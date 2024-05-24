# Docker Swarm 原生集群（三）

> 原文：[`zh.annas-archive.org/md5/9B6C0DB62EFC5AC8A8FAA5F289DFA59D`](https://zh.annas-archive.org/md5/9B6C0DB62EFC5AC8A8FAA5F289DFA59D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：保护 Swarm 集群和 Docker 软件供应链

本章主要讨论 Swarm 集群安全性。特别是，我们将讨论以下主题：

+   使用 Docker 的软件供应链

+   如何保护 Swarm 集群的建议

+   使用 Docker Notary 来保护软件供应链

# 软件供应链

![软件供应链](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_09_001.jpg)

Docker 编排只是更大的软件供应链的一个组成部分。我们基本上从*源代码*作为原材料开始。我们的源代码与*库和依赖包*进行编译和链接。我们使用*构建服务*来持续集成我们的源代码和其依赖项，并最终将它们组装成一个*产品*。然后，我们将产品发布到互联网上，将其存储在其他地方。我们通常称这个仓库为*应用程序存储库*或简称*存储库*。最后，我们将产品发送到客户的环境中，例如云或物理数据中心。

Docker 非常适合这种工作流程。开发人员在本地使用 Docker 来编译和测试应用程序，系统管理员使用 Docker 在构建服务器上部署这些应用程序，并且 Docker 在持续集成的过程中也可能发挥重要作用。

安全性从这里开始。我们需要一种安全的方式在将产品推送到应用程序存储库之前对其进行签名。在我们以 Docker 为中心的世界中，我们将准备好的产品存储在一个称为*Docker Registry*的仓库中。然后，每次在将签名产品部署到我们运行 Docker Swarm 模式集群的生产系统之前，都会对其进行验证。

在本章的其余部分，我们将讨论安全的以下两个方面：

+   如何通过最佳实践来保护生产 Swarm 集群

+   如何通过 Docker Notary 来保护软件供应链

# 保护 Swarm 集群

回想一下来自第四章*创建生产级别的 Swarm*的安全的 Swarm 集群图片；我们将解释 Docker Swarm 模型集群中发现的安全方面。

![保护 Swarm 集群](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_09_002.jpg)

编排器是 Docker Swarm 管理器的主要部分之一。Docker 安全团队成员 Diogo Monica 在 2016 年柏林的编排最低特权演示中提到，编排中的每个组件都必须有其能够做的限制。

+   节点管理：集群操作员可以指示编排器为一组节点执行操作

+   任务分配：编排器还负责为每个节点分配任务

+   集群状态协调：编排器通过将每个状态与期望状态协调来维护集群的状态

+   资源管理：编排器为提交的任务提供和撤销资源

具有最小权限的编排器将使系统更安全，最小权限的编排器是基于这些功能定义的。遵循最小权限原则，管理者以及工作节点必须能够访问“执行给定任务所必需的信息和资源”。

此外，Diogo 提出了可以应用于 Docker 的五种不同攻击模型的列表。它们从最低风险到最高风险列出。

+   外部攻击者：试图破坏集群的防火墙之外的人。

+   内部攻击者：不拥有交换机但可以访问交换机。它可以发送数据包与集群中的节点进行通信。

+   中间人攻击：可以监听网络中的所有内容并进行主动攻击的攻击者。在这种模型中，存在一个 Swarm 集群，并且拦截了工作节点与管理节点的通信。

+   恶意工作节点：工作节点拥有的资源实际上被攻击者拥有。

+   恶意管理节点：管理者是一个攻击者，可以控制完整的编排器并访问所有可用资源。这是最糟糕的情况。如果我们能够实现最小权限，那么恶意管理节点只能攻击与其关联的工作节点。

# 保护 Swarm：最佳实践

我们现在将总结保护 Swarm 集群的检查表。Swarm 团队正在努力实现防止对整个堆栈的攻击的目标，但无论如何，以下规则都适用。

## 认证机构

确保安全性的第一个重要步骤是决定如何使用 CA。当您使用第一个节点形成集群时，它将自动为整个集群创建一个自签名的 CA。在启动后，它创建 CA，签署自己的证书，为管理器添加证书，即自身，并成为准备运行的单节点集群。当新节点加入时，它通过提供正确的令牌来获取证书。每个节点都有自己的身份，经过加密签名。此外，系统为每个规则、工作节点或管理器都有一个证书。角色信息在身份信息中，以告知节点的身份。如果管理器泄露了根 CA，整个集群就会受到威胁。Docker Swarm 模式支持外部 CA 来维护管理器的身份。管理器可以简单地将 CSR 转发给外部 CA，因此不需要维护自己的 CA。请注意，目前仅支持`cfssl`协议。以下命令是使用外部 CA 初始化集群。

```
$ docker swarm init --external-ca \  
    protocol=cfssl,url=https://ca.example.com

```

## 证书和双向 TLS

网络控制平面上的每个端点通信必须具有双向 TLS，并且默认情况下是加密和授权的。这意味着工作节点不能伪装成管理器，也没有外部攻击者可以连接到端点并成功完成 TLS 握手，因为攻击者没有密钥来进行相互认证。这意味着每个节点必须提供有效的 CA 签名证书，其中 OU 字段与集群的每个规则匹配。如果工作节点连接到管理器端点，将被拒绝访问。

Swarm 会自动执行证书轮换。在 SwarmKit 和 Docker Swarm 模式中，证书轮换可以设置为短至一小时。以下是调整证书到期时间的命令。

```
$ docker swarm update --cert-expiry 1h

```

## 加入令牌

每个节点用于加入集群的令牌具有以下四个组件：

+   SWMTKN，Swarm 前缀，用于在令牌泄露时查找或搜索

+   令牌版本，目前为 1

+   CA 根证书的加密哈希值，用于允许引导

+   一个随机生成的秘密。

以下是一个令牌的示例：

`SWMTKN-1-11lo1xx5bau6nmv5jox26rc5mr7l1mj5wi7b84w27v774frtko-e82x3ti068m9eec9w7q2zp9fe`

要访问集群，需要发送一个令牌作为凭证。这就像集群密码。

好消息是，如果令牌被 compromise，令牌可以使用以下命令之一*简单地旋转*。

```
$ docker swarm join-token --rotate worker
$ docker swarm join-token --rotate manager

```

## 使用 Docker Machine 添加 TLS

另一个良好的实践是使用 Docker Machine 为所有管理节点提供额外的 TLS 层，自动设置，以便每个管理节点都可以以安全的方式被远程 Docker 客户端访问。这可以通过以下命令简单地完成，类似于我们在上一章中所做的方式：

```
$ docker-machine create \
      --driver generic \
      --generic-ip-address=<IP> \
    mg0

```

### 在私有网络上形成一个集群

如果形成混合集群不是一个要求，最佳实践之一是我们应该在本地私有网络上形成一个集群，所有节点都在本地私有网络上。这样，覆盖网络的数据就不需要加密，集群的性能会很快。

在形成这种类型的集群时，路由网格允许我们将任何工作节点（不一定是管理节点）暴露给公共网络接口。下图显示了集群配置。您可以看到，通过这种配置和 Docker 服务在入口网络上发布端口 80。路由网格形成了一个星形网格，但我们简化了它，并只显示了从大 W 节点连接到其他节点的一侧。大 W 节点有两个网络接口。其公共接口允许节点充当整个集群的前端节点。通过这种架构，我们可以通过不暴露任何管理节点到公共网络来实现一定级别的安全性。

在私有网络上形成一个集群

# Docker Notary

Docker Content Trust 机制是使用 Docker Notary ([`github.com/docker/notary`](https://github.com/docker/notary)) 实现的，它位于 The Update Framework ([`github.com/theupdateframework/tuf`](https://github.com/theupdateframework/tuf)) 上。TUF 是一个安全的框架，允许我们一次交付一系列受信任的内容。Notary 通过使发布和验证内容变得更容易，允许客户端和服务器形成一个受信任的*集合*。如果我们有一个 Docker 镜像，我们可以使用高度安全的离线密钥对其进行离线签名。然后，当我们发布该镜像时，我们可以将其推送到一个可以用于交付受信任镜像的 Notary 服务器。Notary 是使用 Docker 为企业启用*安全软件供应链*的方法。

我们演示了如何设置我们自己的 Notary 服务器，并在将 Docker 镜像内容推送到 Docker 注册表之前使用它进行签名。先决条件是安装了最新版本的 Docker Compose。

第一步是克隆 Notary（在这个例子中，我们将其版本固定为 0.4.2）：

```
git clone https://github.com/docker/notary.git
cd notary
git checkout v0.4.2
cd notary

```

打开`docker-compose.yml`并添加图像选项以指定签名者和服务器的图像名称和标签。在这个例子中，我使用 Docker Hub 来存储构建图像。所以是`chanwit/server:v042`和`chanwit/signer:v042`。根据您的本地配置进行更改。

![Docker Notary](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_09_004.jpg)

然后开始

```
$ docker-compose up -d

```

我们现在在[`127.0.0.1:4443`](https://127.0.0.1:4443)上运行一个 Notary 服务器。为了使 Docker 客户端能够与 Notary 进行握手，我们需要将 Notary 服务器证书复制为这个受信任地址（`127.0.0.4443`）的 CA。

```
$ mkdir -p ~/.docker/tls/127.0.0.1:4443/
$ cp ./fixtures/notary-server.crt 
    ~/.docker/tls/127.0.0.1:4443/ca.crt

```

之后，我们启用 Docker 内容信任，并将 Docker 内容信任服务器指向我们自己的 Notary，地址为`https://127.0.0.1:4443`。

```
$ export DOCKER_CONTENT_TRUST=1
$ export DOCKER_CONTENT_TRUST_SERVER=https://127.0.0.1:4443

```

然后我们将图像标记为新图像，并在启用 Docker 内容信任的同时推送图像：

```
$ docker tag busybox chanwit/busybox:signed
$ docker push chanwit/busybox:signed

```

如果设置正确完成，我们将看到 Docker 客户端要求新的根密钥和新的存储库密钥。然后它将确认`chanwit/busybox:signed`已成功签名。

```
The push refers to a repository [docker.io/chanwit/busybox]
e88b3f82283b: Layer already exists
signed: digest: 
sha256:29f5d56d12684887bdfa50dcd29fc31eea4aaf4ad3bec43daf19026a7ce69912 size: 527
Signing and pushing trust metadata
You are about to create a new root signing key passphrase. This passphrase
will be used to protect the most sensitive key in your signing system. Please
choose a long, complex passphrase and be careful to keep the password and the
key file itself secure and backed up. It is highly recommended that you use a
password manager to generate the passphrase and keep it safe. There will be no
way to recover this key. You can find the key in your config directory.
Enter passphrase for new root key with ID 1bec0c1:
Repeat passphrase for new root key with ID 1bec0c1:
Enter passphrase for new repository key with ID ee73739 (docker.io/chanwit/busybox):
Repeat passphrase for new repository key with ID ee73739 (docker.io/chanwit/busybox):
Finished initializing "docker.io/chanwit/busybox"
Successfully signed "docker.io/chanwit/busybox":signed

```

现在，我们可以尝试拉取相同的镜像：

```
$ docker pull chanwit/busybox:signed
Pull (1 of 1): chanwit/busybox:signed@sha256:29f5d56d12684887bdfa50dcd29fc31eea4aaf4ad3bec43daf19026a7ce69912
sha256:29f5d56d12684887bdfa50dcd29fc31eea4aaf4ad3bec43daf19026a7ce69912: Pulling from chanwit/busybox
Digest: sha256:29f5d56d12684887bdfa50dcd29fc31eea4aaf4ad3bec43daf19026a7ce69912
Status: Image is up to date for chanwit/busybox@sha256:29f5d56d12684887bdfa50dcd29fc31eea4aaf4ad3bec43daf19026a7ce69912
Tagging chanwit/busybox@sha256:29f5d56d12684887bdfa50dcd29fc31eea4aaf4ad3bec43daf19026a7ce69912 as chanwit/busybox:signed

```

当我们拉取一个未签名的镜像时，这时会显示没有受信任的数据：

```
$ docker pull busybox:latest
Error: remote trust data does not exist for docker.io/library/busybox: 127.0.0.1:4443 does not have trust data for docker.io/library/busybox

```

# 介绍 Docker 秘密

Docker 1.13 在 Swarm 中包含了新的秘密管理概念。

我们知道，我们需要 Swarm 模式来使用秘密。当我们初始化一个 Swarm 时，Swarm 会为我们生成一些秘密：

```
$ docker swarm init

```

Docker 1.13 添加了新的命令`secret`来管理秘密，目的是有效地处理它们。秘密子命令被创建，ls，用于检查和 rm。

让我们创建我们的第一个秘密。`secret create`子命令从标准输入中获取一个秘密。因此，我们需要输入我们的秘密，然后按*Ctrl*+*D*保存内容。小心不要按*Enter*键。例如，我们只需要`1234`而不是`1234\n`作为我们的密码：

```
$ docker secret create password
1234

```

然后按两次*Ctrl*+*D*关闭标准输入。

我们可以检查是否有一个名为 password 的秘密：

```
$ docker secret ls
ID                      NAME                CREATED             UPDATED
16blafexuvrv2hgznrjitj93s  password  25 seconds ago      25 seconds ago
uxep4enknneoevvqatstouec2  test-pass 18 minutes ago      18 minutes ago

```

这是如何工作的？秘密的内容可以通过在创建新服务时传递秘密选项来绑定到服务。秘密将是`/run/secrets/`目录中的一个文件。在我们的情况下，我们将有`/run/secrets/password`包含字符串`1234`。

秘密旨在取代环境变量的滥用。例如，在 MySQL 或 MariaDB 容器的情况下，其根密码应该设置为一个秘密，而不是通过环境变量以明文传递。

我们将展示一个小技巧，使 MariaDB 支持新的 Swarm 秘密，从以下的`entrypoint.sh`开始：

```
$ wget https://raw.githubusercontent.com/docker-
library/mariadb/2538af1bad7f05ac2c23dc6eb35e8cba6356fc43/10.1/docker-entrypoint.sh

```

我们将这行放入这个脚本中，大约在第 56 行之前，然后检查`MYSQL_ROOT_PASSWORD`。

```
# check secret file. if exist, override
if [ -f "/run/secrets/mysql-root-password" ]; then
MYSQL_ROOT_PASSWORD=$(cat /run/secrets/mysql-root-password)
fi

```

此代码检查是否存在`/run/secrets/mysql-root-password`。如果是，则将密钥分配给环境变量`MYSQL_ROOT_PASSWORD`。

之后，我们可以准备一个 Dockerfile 来覆盖 MariaDB 的默认`docker-entrypoint.sh`。

```
FROM mariadb:10.1.19
RUN  unlink /docker-entrypoint.sh
COPY docker-entrypoint.sh /usr/local/bin/
RUN  chmod +x /usr/local/bin/docker-entrypoint.sh
RUN  ln -s usr/local/bin/docker-entrypoint.sh /

```

然后我们构建新的镜像。

```
$ docker build -t chanwit/mariadb:10.1.19 .

```

回想一下，我们有一个名为 password 的秘密，我们有一个允许我们从秘密文件`/run/secrets/mysql-root-password`设置根密码的镜像。因此，该镜像期望在`/run/secrets`下有一个不同的文件名。有了这个，我们可以使用完整选项的秘密（`source=password`，`target=mysql-root-password`）来使 Swarm 服务工作。例如，我们现在可以从这个 MariaDB 镜像启动一个新的`mysql` Swarm 服务：

```
$ docker network create -d overlay dbnet
lsc7prijmvg7sj6412b1jnsot
$ docker service create --name mysql \
--secret source=password,target=mysql-root-password \
--network dbnet \
chanwit/mariadb:10.1.19

```

要查看我们的秘密是否有效，我们可以在相同的覆盖网络上启动一个 PHPMyAdmin 实例。不要忘记通过向`myadmin`服务传递`-e PMA_HOST=mysql`来将这些服务链接在一起。

```
$ docker service create --name myadmin \
--network dbnet --publish 8080:80 \
-e PMA_HOST=mysql \
phpmyadmin/phpmyadmin

```

然后，您可以在浏览器中打开`http://127.0.0.1:8080`，并使用我们通过 Docker 秘密提供的密码`1234`作为 root 登录`PHPMyAdmin`，这样我们就可以使用秘密。

# 摘要

在本章中，我们学习了如何保护 Swarm Mode 和 Docker 软件供应链。我们谈到了一些在生产中如何保护 Docker Swarm 集群的最佳实践。然后我们继续介绍了 Notary，这是一种安全的交付机制，允许 Docker 内容信任。本章以 Docker 1.13 中的一个新功能概述结束：秘密管理。我们展示了如何使用 Docker Secret 来安全地部署 MySQL MariaDB 服务器，而不是通过环境传递根密码。在下一章中，我们将发现如何在一些公共云提供商和 OpenStack 上部署 Swarm。


# 第十章：Swarm 和云

在本书中，我们使用了 Docker Swarm 在一系列不同的底层技术上，到目前为止，我们还没有深入探讨这一含义：我们在 AWS、DigitalOcean 以及我们的本地工作站上运行了 Swarm。对于测试和分期目的，我们运行 Swarm 的平台可能是次要的（*让我们用 Docker Machine 启动一些 AWS 实例并以这种方式工作*），但对于生产环境来说，了解利弊、原因、评估和跟随趋势是必不可少的。

在本章中，我们将审查几种公共和私有云选项和技术以及它们可能的交集。最后，我们将在第十一章中讨论**CaaS**（容器即服务）和**IaaC**（基础设施即代码）这两个全新的热词，*接下来是什么？*

主要我们将关注：

+   Docker for AWS 和 Azure

+   Docker 数据中心

+   在 OpenStack 上的 Swarm

# Docker for AWS 和 Azure

与 Docker For Mac 和 Windows 一样，Docker 团队开始着手开发*新一代*的运维工具集：Docker for AWS 和 Docker for Windows。这些工具旨在为部署 Docker 基础架构提供自动化支持，特别是适用于 Swarm 的基础架构。

目标是提供一种标准的做事方式，将底层基础设施与 Docker 工具集集成，并让人们毫不费力地在他们喜爱的平台上运行最新的软件版本。最终目标实际上是让开发人员将东西从他们的笔记本电脑上移动到云端，使用 Docker for Mac/Windows 和 Docker for AWS/Azure。

## Docker for AWS

用户体验在 Docker 生态系统中一如既往地出色。要求如下：

+   一个 AWS ID

+   导入到 AWS 密钥环中的 SSH 密钥

+   准备好的安全组

基本上，Docker for AWS 是 CloudForms 的可点击模板。CloudForms 是 AWS 的编排系统，允许创建复杂系统的模板，例如，您可以指定由三个 Web 服务器、一个数据库和一个负载均衡器组成的 Web 基础架构。

Docker for AWS 当然具备创建 Docker Swarm（模式）基础架构的能力，它会根据您的指定创建尽可能多的主节点和工作节点，放置一个负载均衡器，并相应地配置所有网络。

这是欢迎界面：

![Docker for AWS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_10_001.jpg)

然后，您可以指定一些基本和高级选项：

![Docker for AWS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_10_002.jpg)

如您所见，您可以选择管理者和工作节点的数量，以及要启动的实例的类型。到目前为止，支持最多 1000 个工作节点。之后，您只需在下一步中点击创建堆栈，并等待几分钟让 CloudForms 启动基础架构。

模板的作用是：

1.  在您的 AWS 帐户中创建一个新的虚拟私有云，包括网络和子网。

1.  创建两个自动扩展组，一个用于管理者，一个用于工作节点。

1.  启动管理者并确保它们与 Raft quorum 达成健康状态。

1.  逐个启动和注册工作节点到 Swarm。

1.  创建**弹性负载均衡器**（**ELBs**）来路由流量。

1.  完成

一旦 CloudFormation 完成，它将提示一个绿色的确认。

![Docker for AWS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_10_003.jpg)

现在，我们准备好进入我们的新 Docker Swarm 基础架构。只需选择一个管理者的公共 IP 并使用在第一步中指定的 SSH 密钥连接到它：

```
 ssh docker@ec2-52-91-75-252.compute-1.amazonaws.com

```

![Docker for AWS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_10_004.jpg)

## Docker for Azure

由于与微软的协议，Azure 也可以作为一键式体验（或几乎是）自动部署 Swarm。

在 Azure 上部署 Swarm 的先决条件是：

+   拥有有效的 Azure 帐户

+   将此帐户 ID 与 Docker for Azure 关联。

+   活动目录主体应用程序 ID

要生成最后一个，您可以方便地使用一个 docker 镜像，并使用以下命令启动它：

```
 docker run -it docker4x/create-sp-azure docker-swarm

```

在过程中，您将需要通过浏览器登录到指定的 URL。最后，将为您提供一对 ID/密钥，供您在 Azure 向导表单中输入。

![Docker for Azure](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_10_005.jpg)

一切就绪后，您只需点击**OK**和**Create**。

![Docker for Azure](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_10_006.jpg)

将创建一组经典虚拟机来运行指定数量的管理者（这里是 1）和工作节点（这里是 4），以及适当的内部网络、负载均衡器和路由器。就像在 Docker for AWS 中一样，您可以通过 SSH 连接到一个管理者的公共 IP 来开始使用部署的 Swarm：

```
 ssh docker@52.169.125.191

```

![Docker for Azure](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_10_007.jpg)

目前 Azure 模板有一个限制，它只支持一个管理者。然而，很快就会有添加新管理者的可能性。

# Docker 数据中心

Docker 数据中心，以前是 Tutum，被 Docker 收购，是 Docker 提供的单击部署解决方案，用于使用 UCP，Universal Control Panel，Docker 的商业和企业产品。

Docker 数据中心包括：

+   **Universal Control Plane**（**UCP**），UI，请参阅[`docs.docker.com/ucp/overview`](https://docs.docker.com/ucp/overview)

+   **Docker Trusted Registry (DTR)**，私有注册表，请参阅[`docs.docker.com/docker-trusted-registry`](https://docs.docker.com/docker-trusted-registry)

在 Dockercon 16 上，团队发布了对在 AWS 和 Azure 上运行 Docker 数据中心的支持（目前处于 Beta 阶段）。要尝试 Docker 数据中心，你需要将许可证与你的公司/项目的 AWS 或 Azure ID 关联起来。

对于 AWS 的数据中心，就像对于 AWS 的 Docker 一样，有一个 CloudFormation 模板，可以立即启动一个 Docker 数据中心。要求是：

+   至少有一个配置了 Route53 的，AWS 的 DNS 服务，请参阅[`docs.aws.amazon.com/Route53/latest/DeveloperGuide/Welcome.html`](http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/Welcome.html)

+   一个 Docker 数据中心许可证

你需要做的就是从你的许可证链接进入创建堆栈页面。在这里，你只需输入**HostedZone** ID 和 Docker 数据中心许可证，然后开始创建堆栈。在内部，Docker 数据中心在私有网络（节点）上放置一些虚拟机，并且一些通过弹性负载均衡器（ELBs，用于控制器）进行负载平衡，上面安装了商业支持的引擎版本。当前版本的 Docker 数据中心虚拟机在内部运行 Swarm 独立和发现机制，以相互连接。我们可以预期数据中心的稳定版本很快就会发布。

Docker 数据中心和 Docker for AWS 之间的主要区别在于前者旨在成为一体化的企业就绪解决方案。而后者是部署 Swarm 集群的最快方式，前者是更完整的解决方案，具有时尚的 UI，Notary 和来自生态系统的可选服务。

# 在 OpenStack 上的 Swarm

说到私有云，最受欢迎的 IaaS 开源解决方案是 OpenStack。OpenStack 是一个由程序（以前称为项目）组成的庞大生态系统，旨在提供所谓的云操作系统。核心 OpenStack 程序包括：

+   **Keystone**：身份和授权系统

+   **Nova**：虚拟机抽象层。Nova 可以与虚拟化模块（如 Libvirt、VMware）进行插接

+   **Neutron**：处理租户网络、实例端口、路由和流量的网络模块

+   **Cinder**：负责处理卷的存储模块

+   **Glance**：镜像存储

一切都由额外的参与者粘合在一起：

+   一个数据库系统，比如 MySQL，保存配置。

+   一个 AMQP 代理，比如 Rabbit，用于排队和传递操作

+   一个代理系统，比如 HAproxy，用来代理 HTTP API 请求

在 OpenStack 中典型的 VM 创建中，发生以下情况：

1.  用户可以从 UI（Horizon）或 CLI 决定生成一个 VM。

1.  他/她点击一个按钮或输入一个命令，比如`nova boot ...`

1.  Keystone 检查用户在他/她的租户中的授权和认证，通过在用户的数据库或 LDAP 中检查（取决于 OpenStack 的配置），并生成一个将在整个会话中使用的令牌：“这是你的令牌：gAAAAABX78ldEiY2”*.*

1.  如果认证成功并且用户被授权生成 VM，Nova 将使用授权令牌调用：“我们正在启动一个 VM，你能找到一个合适的物理主机吗？”

1.  如果这样的主机存在，Nova 从 Glance 获取用户选择的镜像：“Glance，请给我一个 Ubuntu Xenial 可启动的 qcow2 文件”

1.  在物理启动 VM 的计算主机上，一个`nova-compute`进程，它与配置的插件进行通信，例如，对 Libvirt 说：“我们正在这个主机上启动一个 VM”

1.  Neutron 为 VM 分配私有（如果需要还有公共）网络端口：“请在指定的网络上创建这些端口，在这些子网池中”

1.  如果用户愿意，Cinder 会在其调度程序设计的主机上分配卷。也就是说。让我们创建额外的卷，并将它们附加到 VM。

1.  如果使用 KVM，将生成一个包含上述所有信息的适当 XML，并且 Libvirt 在计算主机上启动 VM

1.  当 VM 启动时，通过 cloud-init 注入一些变量，例如，允许无密码 SSH 登录的 SSH 密钥

这（除了 Cinder 上的第 8 步）正是 Docker Machine 的 OpenStack 驱动程序的行为方式：当你使用`-d openstack`在 Machine 上创建一个 Docker 主机时，你必须指定一个现有的 glance 镜像，一个现有的私有（和可选的公共）网络，并且（可选的，否则会自动生成）指定一个存储在 Nova 数据库中的 SSH 镜像。当然，你必须将授权变量传递给你的 OpenStack 环境，或者作为导出的 shell 变量源它们。

在 OpenStack 上创建一个 Docker 主机的 Machine 命令将如下所示：

```
 docker-machine create \
 --driver openstack \
 --openstack-image-id 98011e9a-fc46-45b6-ab2c-cf6c43263a22 \
 --openstack-flavor-id 3 \
 --openstack-floatingip-pool public \
 --openstack-net-id 44ead515-da4b-443b-85cc-a5d13e06ddc85 \
 --openstack-sec-groups machine \
 --openstack-ssh-user ubuntu \
 ubuntu1

```

## OpenStack Nova

因此，在 OpenStack 上进行 Docker Swarm 的经典方式将是开始创建实例，比如从 Ubuntu 16.04 镜像中创建 10 个 VMs，放在一个专用网络中：

+   从 Web UI 中，指定 10 作为实例的数量

+   或者从 CLI 中，使用`nova boot ... --max-count 10 machine-`

+   或者使用 Docker Machine

最后一种方法更有前途，因为 Machine 会自动安装 Docker，而不必在新创建的实例上进行后续的黑客攻击或使用其他工具（例如使用通用驱动程序的 Machine，Belt，Ansible，Salt 或其他脚本）。但在撰写本文时（Machine 0.8.2），Machine 不支持批量主机创建，因此您将不得不使用一些基本的 shell 逻辑循环`docker-machine`命令：

```
 #!/bin/bash
 for i in `seq 0 9`; do
 docker-machine create -d openstack ... openstack-machine-$i
 done

```

这根本不是一个好的用户体验，因为当我们谈论数十个主机时，机器的扩展性仍然非常糟糕。

### （不推荐使用的）nova-docker 驱动程序

曾经，有一个用于 Nova 的驱动程序，可以将 Docker 容器作为 Nova 的最终目的地（而不是创建 KVM 或 VmWare 虚拟机，例如，这些驱动程序允许从 Nova 创建和管理 Docker 容器）。如果对于*旧*的 Swarm 来说使用这样的工具是有意义的（因为一切都被编排为容器），那么对于 Swarm Mode 来说就没有兴趣了，它需要的是 Docker 主机而不是裸露的容器。

## 现实 - OpenStack 友好的方式

幸运的是，OpenStack 是一个非常充满活力的项目，现在它已经发布了**O**（**Ocata**），它通过许多可选模块得到了丰富。从 Docker Swarm 的角度来看，最有趣的是：

+   **Heat:** 这是一个编排系统，可以从模板创建 VMs 配置。

+   **Murano:** 这是一个应用程序目录，可以从由开源社区维护的目录中运行应用程序，包括 Docker 和 Kubernetes 容器。

+   **Magnum:** 这是来自 Rackspace 的容器即服务解决方案。

+   **Kuryr：** 这是网络抽象层。使用 Kuryr，您可以将 Neutron 租户网络和使用 Docker Libnetwork 创建的 Docker 网络（比如 Swarm 网络）连接起来，并将 OpenStack 实例与 Docker 容器连接起来，就好像它们连接到同一个网络一样。

## OpenStack Heat

OpenStack Heat 有点类似于 Docker Compose，允许您通过模板启动系统，但它更加强大：您不仅可以从镜像启动一组实例，比如 Ubuntu 16.04，还可以对它们进行编排，这意味着创建网络，将 VM 接口连接到网络，放置负载均衡器，并在实例上执行后续任务，比如安装 Docker。粗略地说，Heat 相当于 OpenStack 的 Amazon CloudFormation。

在 Heat 中，一切都始于 YAML 模板，借助它，您可以在启动之前对基础架构进行建模，就像您使用 Compose 一样。例如，您可以创建一个这样的模板文件：

```
 ...
 resources:
   dockerhosts_group:
     type: OS::Heat::ResourceGroup
     properties:
       count: 10
       resource_def:
         type: OS::Nova::Server
         properties:
           # create a unique name for each server
           # using its index in the group
           name: docker_host_%index%
           image: Ubuntu 16.04
           flavor: m.large
 ...

```

然后，您可以从中启动一个堆栈（`heat stack-create -f configuration.hot dockerhosts`）。Heat 将调用 Nova、Neutron、Cinder 和所有必要的 OpenStack 服务来编排资源并使其可用。

在这里，我们不会展示如何通过 Heat 启动 Docker Swarm 基础架构，而是会看到 Magnum，它在底层使用 Heat 来操作 OpenStack 对象。

## OpenStack Magnum

Magnum 于 2015 年底宣布，并由 OpenStack 容器团队开发，旨在将**容器编排引擎**（**COEs**）如 Docker Swarm 和**Kubernetes**作为 OpenStack 中的一流资源。在 OpenStack 领域内有许多项目专注于提供容器支持，但 Magnum 走得更远，因为它旨在支持*容器编排*，而不仅仅是裸露的容器管理。

![OpenStack Magnum](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_10_008.jpg)

到目前为止，重点特别放在 Kubernetes 上，但我们在这里谈论**Magnum**，因为它是提供在私有云上运行 CaaS 编排的最有前途的开源技术。在撰写本文时，Magnum 尚不支持最新的 Swarm Mode：这个功能必须得到解决。作者已经在 Launchpad 蓝图上开放了一个问题，可能会在书出版后开始着手处理：[`blueprints.launchpad.net/magnum/+spec/swarm-mode-support`](https://blueprints.launchpad.net/magnum/+spec/swarm-mode-support)。

### 架构和核心概念

Magnum 有两个主要组件，运行在控制节点上：

```
 magnum-api
 magnum-conductor

```

第一个进程`magnum-api`是典型的 OpenStack API 提供者，由 magnum Python 客户端或其他进程调用进行操作，例如创建集群。后者`magnum-conductor`由`magnum-api`（或多或少具有`nova-conductor`的相同功能）通过 AMQP 服务器（如 Rabbit）调用，其目标是与 Kubernetes 或 Docker API 进行接口。实际上，这两个二进制文件一起工作，提供一种编排抽象。

![架构和核心概念](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_10_009.jpg)

在 OpenStack 集群计算节点上，除了`nova-compute`进程外，不需要运行任何特殊的东西：Magnum conductor 直接利用 Heat 创建堆栈，这些堆栈创建网络并在 Nova 中实例化 VM。

Magnum 术语随着项目的发展而不断演变。但这些是主要概念：

+   **容器**是 Docker 容器。

+   **集群**（以前是 Bay）是一组调度工作的节点对象的集合，例如 Swarm 节点。

+   **ClusterTemplate**（以前是 BayModel）是存储有关集群类型信息的模板。例如，ClusterTemplate 定义了*具有 3 个管理节点和 5 个工作节点的 Swarm 集群*。

+   **Pods**是在同一物理或虚拟机上运行的一组容器。

至于高级选项，如存储、新的 COE 支持和扩展，Magnum 是一个非常活跃的项目，我们建议您在[`docs.openstack.org/developer/magnum/`](http://docs.openstack.org/developer/magnum/)上关注其发展。

### 在 Mirantis OpenStack 上安装 HA Magnum

安装 Magnum 并不那么简单，特别是如果您想要保证 OpenStack HA 部署的一些故障转移。互联网上有许多关于如何在 DevStack（开发者的 1 节点暂存设置）中配置 Magnum 的教程，但没有一个显示如何在具有多个控制器的真实生产系统上工作。在这里，我们展示了如何在真实设置中安装 Magnum。

通常，生产 OpenStack 安装会有一些专门用于不同目标的节点。在最小的 HA 部署中，通常有：

+   三个或更多（为了仲裁原因是奇数）**控制节点**，负责托管 OpenStack 程序的 API 和配置服务，如 Rabbit、MySQL 和 HAproxy

+   任意数量的**计算节点**，在这里工作负载在物理上运行（VM 托管的地方）

还可以选择专用存储、监控、数据库、网络和其他节点。

在我们的设置中，基于运行 Newton 的**Mirantis OpenStack**，安装了 Heat，我们有三个控制器和三个计算加存储节点。使用 Pacemaker 配置了 HA，它将 MySQL、Rabbitmq 和 HAproxy 等资源保持高可用性。API 由 HAproxy 代理。这是一个显示配置到 Pacemaker 中的资源的屏幕截图。它们都已启动并正常工作：

![在 Mirantis OpenStack 上安装 HA Magnum](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_10_010.jpg)

集群中的所有节点都运行 Ubuntu 16.04（Xenial），稳定的 Magnum 2.0 软件包存在，因此只需从上游使用它们并使用`apt-get install`进行安装。

然而，在安装 Magnum 之前，有必要准备环境。首先需要一个数据库。只需在任何控制器上输入 MySQL 控制台：

```
 node-1# mysql

```

在 MySQL 中，创建 magnum 数据库和用户，并授予正确的权限：

```
 CREATE DATABASE magnum;
 GRANT ALL PRIVILEGES ON magnum.* TO 'magnum'@'controller' \
   IDENTIFIED BY 'password';
 GRANT ALL PRIVILEGES ON magnum.* TO 'magnum'@'%' \
   IDENTIFIED BY 'password';

```

现在，有必要在 Keystone 中创建服务凭据，首先要定义一个 magnum OpenStack 用户，必须将其添加到服务组中。服务组是一个特殊的组，其中包括在集群中运行的 OpenStack 服务，如 Nova、Neutron 等。

```
 openstack user create --domain default --password-prompt magnum
 openstack role add --project services --user magnum admin

```

之后，必须创建一个新的服务：

```
 openstack service create --name magnum \   --description "OpenStack 
    Container Infrastructure" \   container-infra

```

OpenStack 程序通过其 API 调用并进行通信。API 通过端点访问，这是一个 URL 和端口的配对，在 HA 设置中由 HAproxy 代理。在我们的设置中，HAproxy 在`10.21.22.2`上接收 HTTP 请求，并在控制器 IP 之间进行负载均衡，即`10.21.22.4, 5`和`6`。

![在 Mirantis OpenStack 上安装 HA Magnum](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_10_011.jpg)

我们必须为 Magnum 创建这样的端点，默认情况下监听端口 9511，对于每个区域（公共、内部和管理员）：

```
 openstack endpoint create --region RegionOne \
   container-infra public http://10.21.22.2:9511/v1
 openstack endpoint create --region RegionOne \
   container-infra internal http://10.21.22.2:9511/v1
 openstack endpoint create --region RegionOne \
   container-infra admin http://10.21.22.2:9511/v1

```

此外，Magnum 需要额外的配置来在域内部组织其工作负载，因此必须添加一个专用域和域用户：

```
 openstack domain create --description "Magnum" magnum
 openstack user create --domain magnum --password-prompt 
    magnum_domain_admin
 openstack role add --domain magnum --user magnum_domain_admin admin

```

现在一切就绪，最终运行`apt-get`。在所有三个控制器上运行以下命令，并在 ncurses 界面中，始终选择 No，以不更改环境，或保持默认配置：

```
 apt-get install magnum-api magnum-conductor

```

### 配置 HA Magnum 安装

Magnum 的配置非常简单。使其处于运行状态所需的操作是：

1.  通过`magnum.conf`文件进行配置。

1.  重新启动 magnum 二进制文件。

1.  打开端口`tcp/9511`。

1.  配置 HAproxy 以接受和平衡 magnum APIs。

1.  重新加载 HAproxy。

必须在每个控制器上进行的关键配置如下。首先，在每个控制器上，主机参数应该是管理网络上接口的 IP：

```
 [api]
 host = 10.21.22.6

```

如果未安装**Barbican**（专门用于管理密码等秘密的 OpenStack 项目），则必须由`**x509keypair**`插件处理证书：

```
 [certificates]
 cert_manager_type = x509keypair

```

然后，需要一个数据库连接字符串。在这个 HA 设置中，MySQL 在 VIP`10.21.22.2`上响应：

```
 [database]
 connection=mysql://magnum:password@10.21.22.2/magnum

```

Keystone 身份验证配置如下（选项相当不言自明）：

```
 [keystone_authtoken]
 auth_uri=http://10.21.22.2:5000/
 memcached_servers=10.21.22.4:11211,
    10.21.22.5:11211,10.21.22.6:11211
 auth_type=password
 username=magnum
 project_name=services
 auth_url=http://10.21.22.2:35357/
 password=password
 user_domain_id = default
 project_domain_id = default
 auth_host = 127.0.0.1
 auth_protocol = http
 admin_user = admin
 admin_password =
 admin_tenant_name = admin

```

必须配置 Oslo（消息代理）以进行消息传递：

```
 [oslo_messaging_notifications]
 driver = messaging

```

Rabbitmq 的配置是这样的，指定 Rabbit 集群主机（因为 Rabbit 在控制器上运行，所以所有控制器的管理网络的 IP）：

```
 [oslo_messaging_rabbit]
 rabbit_hosts=10.21.22.6:5673, 10.21.22.4:5673, 10.21.22.5:5673
 rabbit_ha_queues=True
 heartbeat_timeout_threshold=60
 heartbeat_rate=2
 rabbit_userid=magnum
 rabbit_password=A3elbTUIqOcqRihB6XE3MWzN

```

最后，受托人的额外配置如下：

```
 [trust]
 trustee_domain_name = magnum
 trustee_domain_admin_name = magnum_domain_admin
 trustee_domain_admin_password = magnum

```

在进行此重新配置后，必须重新启动 Magnum 服务：

```
 service magnum-api restart
 service magnum-conductor restart

```

Magnum 默认使用端口`tcp/9511`，因此必须在 iptables 中接受到该端口的流量：修改 iptables 以添加此规则：

```
 -A INPUT -s 10.21.22.0/24 -p tcp -m multiport --dports 9511 -m 
    comment --comment "117 magnum-api from 10.21.22.0/24" -j ACCEPT

```

就在其他 OpenStack 服务之后，在`116 openvswitch db`之后。

现在，是时候配置 HAproxy 来接受 magnum 了。在所有控制器的`/etc/haproxy/conf.d`中添加一个`180-magnum.cfg`文件，内容如下：

```
 listen magnum-api
 bind 10.21.22.2:9511
 http-request  set-header X-Forwarded-Proto https if { ssl_fc }
 option  httpchk
 option  httplog
 option  httpclose
 option  http-buffer-request
 timeout  server 600s
 timeout  http-request 10s
 server node-1 10.21.22.6:9511  check inter 10s fastinter 2s 
      downinter 3s rise 3 fall 3
 server node-2 10.21.22.5:9511  check inter 10s fastinter 2s 
      downinter 3s rise 3 fall 3
 server node-3 10.21.22.4:9511  check inter 10s fastinter 2s 
      downinter 3s rise 3 fall 3

```

这将配置 magnum-api 侦听 VIP`10.21.22.2:9511`，支持三个控制器。

紧接着，必须从 Pacemaker 重新启动 HAproxy。从任何控制器上运行：

```
 pcs resource disable p_haproxy

```

等待直到所有控制器上没有运行 HAproxy 进程（您可以使用`ps aux`进行检查），但这应该非常快，不到 1 秒，然后：

```
 pcs resource enable p_haproxy

```

之后，Magnum 将可用并且服务已启动：

```
 source openrc
 magnum service-list

```

![配置 HA Magnum 安装](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_10_012.jpg)

### 在 Magnum 上创建一个 Swarm 集群

创建一个 Swarm 集群，当 COE 被添加到 Magnum 时，将需要执行以下步骤：

1.  创建一个 Swarm 模板。

1.  从模板启动一个集群。

我们不会深入研究尚不存在的东西，但命令可能是这样的：

```
 magnum cluster-template-create \
 --name swarm-mode-cluster-template \
 --image-id ubuntu_xenial \
 --keypair-id fuel \
 --fixed-network private \
 --external-network-id public \
 --dns-nameserver 8.8.8.8 \
 --flavor-id m1.medium \
 --docker-volume-size 5 \
 --coe swarm-mode

```

在这里，定义了一个基于 Ubuntu Xenial 的`m1.medium` flavors 的 swarm-mode 类型的集群模板：VM 将注入 fuel 密钥对，将具有额外的外部公共 IP。基于这样一个模板创建集群的 UX 可能会是：

```
 magnum cluster-create --name swarm-mode-cluster \
       --cluster-template swarm-mode-cluster-template \
       --manager-count 3 \
       --node-count 8

```

在这里，使用三个管理节点和五个工作节点实例化了一个 Swarm 集群。

Magnum 是一个很棒的项目，在 OpenStack 上以最高级别的抽象层次运行容器编排。它在 Rackspace 云上运行，并且通过 Carina 可以供公众使用，参见[`blog.rackspace.com/carina-by-rackspace-simplifies-containers-with-easy-to-use-instant-on-native-container-environment`](http://blog.rackspace.com/carina-by-rackspace-simplifies-containers-with-easy-to-use-instant-on-native-container-environment)。

# 总结

在本章中，我们探讨了可以运行 Docker Swarm 集群的替代平台。我们使用了最新的 Docker 工具--Docker for AWS 和 Docker for Azure--并用它们来演示如何以新的方式安装 Swarm。在介绍了 Docker Datacenter 之后，我们转向了私有云部分。我们在 OpenStack 上工作，展示了如何在其上运行 Docker 主机，如何安装 OpenStack Magnum，以及如何在其上创建 Swarm 对象。我们的旅程即将结束。

下一章也是最后一章将勾勒出 Docker 编排的未来。


# 第十一章：接下来是什么？

Docker 生态系统正在朝着更大的方向发展，其中 Swarm 将是核心组件之一。让我们假设一个路线图。

# 供应的挑战

目前还没有官方工具可以在规模上创建一个大型的 Swarm。目前，运营商使用内部脚本，临时工具（如 Belt），配置管理器（如 Puppet 或 Ansible），或编排模板（如 AWS 的 CloudFormation 或 OpenStack 的 Heat），正如我们在前几章中所看到的。最近，Docker For AWS 和 Azure 成为了替代方案。

但这种用例可能会以软件定义基础设施工具包的统一方式来解决。

# 软件定义基础设施

从容器作为构建模块开始，然后创建系统来设计、编排、扩展、保护和部署不仅仅是应用程序，还有基础设施，长期目标可能是*可编程互联网*。

在 SwarmKit 之后，Docker 于 2016 年 10 月开源了**Infrakit**，这是用于基础设施的工具包。

## Infrakit

虽然 Docker Engine 的重点是容器，Docker Swarm 的重点是编排，但 Infrakit 的重点是*组*作为基元。组意味着任何对象：宠物、牲畜、unikernels 和 Swarm 集群。

Infrakit 是解决在不同基础设施中管理 Docker 的问题的答案。在 Infrakit 之前，这是困难的，而且不可移植。其想法是提供一致的用户体验，从设计数据中心到运行裸容器。Infrakit 是由 Docker 创建可编程基础设施的当前最高级抽象，并且它自己描述为：

> *"InfraKit 是一个用于创建和管理声明式、自愈基础设施的工具包。它将基础设施自动化分解为简单的、可插拔的组件。这些组件共同工作，积极确保基础设施状态与用户的规格说明相匹配。"*

在堆栈中的 Infrakit 靠在容器引擎的侧面。

![Infrakit](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_11_001.jpg)

组织是按组来划分的。有一个用于 Infrakit 自身结构的组，由保持配置的管理器组成。每次只有一个领导者，例如，有两个追随者。每个管理器都包括一些组声明。组可以是牛群、宠物、蜂群、unikernels 等。每个组都用实例（例如容器这样的真实资源）和 flavor（资源类型，例如 Ubuntu Xenial 或 MySQL Docker 镜像）来定义。

Infrakit 是声明性的。它依赖于 JSON 配置，并在内部使用封装和组合的众所周知的模式，以使配置成为处理和使基础设施收敛到特定配置的输入。

Infrakit 的目标是：

+   提供统一的工具包来管理组

+   可插拔

+   提供自我修复

+   发布滚动更新

组抽象了对象的概念。它们可以是任何大小和规模的组，并且可以扩展和缩小，它们可以是具有命名宠物的组、无名牛群、Infrakit 管理器本身和/或所有上述内容的组。目前，在 Infrakit 中只有一个默认的组配置（默认插件），但以后可能会出现新的组定义。默认组是一个接口，公开了诸如观察/取消观察（启动和停止组）、执行/停止更新、更改组大小等操作。

组由实例组成。它们可以是诸如 VM 或容器之类的物理资源，也可以是其他服务的接口，例如 Terraform。

在实例上可以运行 flavor，例如 Zookeeper、MySQL 或 Ubuntu Xenial。

组、实例和 flavor 是可插拔的：它们实际上作为可以用任何语言编写的插件运行。目前，Infrakit 提供了一些 Go 代码，编译后会生成一组二进制文件，例如 cli，可用于控制、检查和执行组、实例和 flavor 的操作，以及插件二进制文件，例如 terraform、swarm 或 zookeeper。

Infrakit 被认为能够管理不一致性，通过持续监控、检测异常并触发操作。这种特性称为自我修复，可以用来创建更健壮的系统。

Infrakit 支持的主要操作之一将是发布滚动更新以更新实例。例如，更新容器中的软件包、更新容器镜像，或者可能通过使用**TUF**（**The Update Framework**）来实现，这是下一节中描述的一个项目。

Infrakit 在撰写时还处于早期和年轻阶段，我们无法展示任何不是 Hello World 的示例。在互联网上，很快就会充满 Infrakit Hello World，Infrakit 团队本身发布了一份逐步教程，以便使用文件或 Terraform 插件。我们可以将其描述为 Docker 生态系统中的架构层，并期望它能够部署甚至是 Swarms，为主机提供服务并相互连接。

预计 Infrakit 将被包含在 Engine 中，可能作为版本 1.14 中的实验性功能。

## TUF - 更新框架

在柏林的 Docker Summit 16 上，还讨论了另一个话题，TUF ([`theupdateframework.github.io/`](https://theupdateframework.github.io/))，这是一个旨在提供安全的更新方式的工具包。

有许多可用的更新工具，可以在实践中进行更新，但 TUF 更多。从项目主页：

> “TUF 帮助开发人员保护新的或现有的软件更新系统，这些系统经常容易受到许多已知攻击的影响。TUF 通过提供一个全面、灵活的安全框架来解决这个普遍问题，开发人员可以将其与任何软件更新系统集成。”

TUF 已经集成到 Docker 中，该工具称为 Notary，正如我们在第九章中看到的，*保护 Swarm 集群和 Docker 软件供应链*，可以使用 Notary。Notary 可用于验证内容并简化密钥管理。使用 Notary，开发人员可以使用密钥离线签署其内容，然后通过将其签名的可信集合推送到 Notary 服务器来使内容可用。

TUF 是否会作为滚动更新机制合并到 Docker Infrakit 中？那将是另一个惊人的进步。

# Docker stacks 和 Compose

另一个可供开发人员使用但仍处于实验阶段的 Docker 功能是 Stacks。我们在第六章中介绍了 Stacks，*在 Swarm 上部署真实应用*。它们将成为在 Swarms 上部署应用程序的默认方法。与启动容器不同，想法是将容器组打包成捆绑包，而不是单独启动。

此外，还可以预期 Compose 与新的 Swarm 之间的新集成。

# CaaS - 容器即服务

在 XaaS 领域，一切都被视为软件，不仅容器是一流公民，编排系统和基础设施也是如此。所有这些抽象将导致以云定义的方式运行这些工具生态系统：容器即服务。

CaaS 的一个例子是 Docker Datacenter。

# Unikernels

SwarmKit 作为一个工具包，不仅可以运行容器集群，还可以运行 unikernels。

unikernels 是什么，为什么它们如此奇妙？

如果你使用 Docker For Mac，你已经在使用 unikernels。它们是这些系统的核心。在 Mac 上，**xhyve**，一个 FreeBSD 虚拟化系统**（bhyve）**的端口，在 unikernel 模式下运行 Docker 主机。

我们都喜欢容器，因为它们小巧快速，但是有一个机制来抽象内核并使其组件（容器）共享系统资源、库、二进制文件的安全隐患确实令人担忧。只需在任何搜索引擎上查找有关容器安全性的 CVE 公告。这是一个严重的问题。

unikernels 承诺对软件架构进行最高级别的重新评估。这里很快解释了这一点。有一种有效的方法来保证最大的安全性，由于它们的性质，它们以非常非常小的尺寸运行。在我们谈论 Terabytes、Petabytes 甚至更大的世界中，你会惊讶地知道，类似 ukvm 的 KVM 的 unikernel 实现可以适应 67Kb（千字节），Web 服务器二进制文件可以达到 300Kb，或者操作系统镜像可以达到几兆字节的数量级。

这是可能的，因为 unikernels 基本上不会将所有系统调用暴露给堆栈，而是将这些调用包含在二进制文件中。一个**ping**二进制文件不需要任何系统调用来访问磁盘，使用加密函数或管理系统进程。那么为什么不切断 ping 的这些调用，并为其提供它所需的最小功能呢？这就是 unikernels 背后的主要思想。ping 命令将与一些网络 I/O、原始套接字一起编译在*内部*，仅此而已。

使用 unikernels 时，内核和用户空间之间没有区别，因为地址表是统一的。这意味着地址表是*连续的*。正如前面解释的那样，这是可能的，因为 unikernel 二进制文件是通过嵌入它们需要的系统功能（如 I/O 操作、内存管理或共享库）在*二进制*内部编译的。在传统的操作系统模型中，应用程序在*运行时*查看和使用系统调用，而使用 unikernels 时，这些系统调用在*编译时*静态链接。

![Unikernels](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_11_002.jpg)

乍一看这可能看起来很奇怪，但这在进程隔离和安全性方面是一项巨大的进步。即使有人能够欺诈性地介入运行 unikernel 内容的某个系统中，她几乎不可能找到任何安全漏洞。攻击面是如此之小，以至于几乎不可能存在任何可利用的未使用的系统调用或功能，除了已经加固的可能正在使用的功能。没有 shell 可调用，没有外部实用程序库或脚本，没有配置或密码文件，没有额外的端口绑定。

那么 unikernels 和 Docker 呢？

在巴塞罗那的 DockerConEU 15 上，一些人跳上舞台展示如何将 Docker 与 unikernels 集成，最终 Docker Inc.收购了该公司，签署了 Docker For Mac 的诞生等其他事项。

在柏林的 Docker Summit 16 上，有人提到 unikernels 可以与 SwarmKit 中的容器一起运行。集成的未来即将到来。

# 为 Docker 做贡献

Docker 中的所有这些创新都是可能的，因为这些项目依赖于一个非常广泛的社区。Docker 是一个非常密集和活跃的项目，分成几个 Github 存储库，其中最值得注意的是：

+   Docker 引擎本身：[www.github.com/docker/docker](https://github.com/docker/docker)

+   Docker 主机实例化工具 Machine：[www.github.com/docker/machine](https://github.com/docker/machine)

+   编排服务 Swarm：[www.github.com/docker/swarmkit](https://github.com/docker/swarmkit)

+   Compose，用于建模微服务的工具：[www.github.com/docker/compose](https://github.com/docker/compose)

+   基础设施管理器 Infrakit：[www.github.com/docker/infrakit](https://github.com/docker/infrakit)

但是，这些项目也无法在没有它们的库的情况下运行，比如 Libcontainer、Libnetwork、Libcompose（等待与 Compose 合并）等等。

所有这些代码都不会存在，没有 Docker 团队和 Docker 社区的承诺。

## Github

鼓励任何公司或个人为项目做出贡献。在[`github.com/docker/docker/blob/master/CONTRIBUTING.md`](https://github.com/docker/docker/blob/master/CONTRIBUTING.md)上有一些指南。

## 文件问题

一个很好的开始是通过在相关项目的 GitHub 空间上开放问题来报告异常、错误或提交想法。

## 代码

另一个受到赞赏的帮助方式是提交拉取请求，修复问题或提出新功能。这些 PR 应遵循并参考记录在 Issues 页面上的一些问题，符合指南。

## Belt 和其他项目

此外，除了这本书，还有许多小的并行项目开始了：

+   Swarm2k 和 Swarm3k，作为社区导向的实验，旨在创建规模化的 Swarm。一些代码、说明和结果可在[www.github.com/swarmzilla](https://github.com/swarmzilla)的相应存储库中找到。

+   Belt 作为 Docker 主机供应商。目前，它只包括 DigitalOcean 驱动程序，但可以进一步扩展。

+   用于 Swarm、Machine 和 Docker 证书的 Ansible 模块，可用于 Ansible play books。

+   容器推送到 Docker Hub 以说明特定组件（如`fsoppelsa/etcd`）或引入新功能（如`fsoppelsa/swarmkit`）。

+   其他次要的拉取请求、黑客和代码部分。

秉承开源精神，上述所有内容都是免费软件，非常感谢任何贡献、改进或批评。

# 总结

最后，简要介绍一下这本书的历史，以及关于 Docker 开发速度的惊人之处。

当编写有关 Docker Swarm 的书籍项目刚起草时，当天只有旧的 Docker Swarm 独立模式，其中 Swarm 容器负责编排容器基础设施，必须依赖外部发现系统，如 Etcd、Consul 或 Zookeeper。

回顾这些时期，就在几个月前，就像在思考史前时期。就在 6 月，当 SwarmKit 作为编排工具开源并被包含到引擎中作为 Swarm Mode 时，Docker 在编排方面迈出了重要的一步。一个完整的、可扩展的、默认安全的、以及本地编排 Docker 的简单方式被发布。然后，结果证明最好的 Docker 编排方式就是 Docker 本身。

但是当 Infrakit 在 2016 年 10 月开源时，基础设施方面迈出了一大步：现在不仅编排和容器组是基本元素，而且其他对象的组，甚至混合在原始 Infrakit 意图中：容器、虚拟机、unikernels，甚至裸金属。

在（不久的）未来，我们可以期待所有这些项目被粘合在一起，Infrakit 作为基础设施管理器，能够提供 Swarm（任何东西），在其中容器或其他对象被编排、互联、存储（完全状态）、滚动更新、通过覆盖网络互联，并得到保护。

Swarm 只是这个大局生态系统的开始。
