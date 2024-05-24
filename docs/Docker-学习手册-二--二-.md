# Docker 学习手册（二）（二）

> 原文：[`zh.annas-archive.org/md5/1FDAAC9AD3D7C9F0A89A69D7710EA482`](https://zh.annas-archive.org/md5/1FDAAC9AD3D7C9F0A89A69D7710EA482)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：运行您的私有 Docker 基础设施

在第四章，*发布图像*中，我们讨论了 Docker 图像，并清楚地了解到 Docker 容器是 Docker 图像的运行时实现。如今，Docker 图像和容器数量众多，因为容器化范式已经席卷了 IT 领域。因此，全球企业有必要将他们的 Docker 图像保存在自己的私有基础设施中以考虑安全性。因此，部署 Docker Hub 到我们自己的基础设施的概念已经出现并发展。 Docker Hub 对于注册和存储不断增长的 Docker 图像至关重要和相关。主要，Docker Hub 专门用于集中和集中管理以下信息：

+   用户帐户

+   图像的校验和

+   公共命名空间

本章重点介绍了为您和 Docker 容器开发者提供所有相关信息，以便在自己的后院设计、填充和运行自己的私有 Docker Hub。本章涵盖了以下重要主题：

+   Docker 注册表和索引

+   Docker 注册表的用例

+   运行您自己的索引和注册表

+   将镜像推送到新创建的注册表

# Docker 注册表和索引

通常，Docker Hub 由 Docker 索引和注册表组成。 Docker 客户端可以通过网络连接和与 Docker Hub 交互。注册表具有以下特征：

+   它存储一组存储库的图像和图形

+   它没有用户帐户数据

+   它没有用户帐户或授权的概念

+   它将认证和授权委托给 Docker Hub 认证服务

+   它支持不同的存储后端（S3、云文件、本地文件系统等）

+   它没有本地数据库

+   它有与之关联的源代码

Docker 注册表的高级功能包括`bugsnag`、`new relic`和`cors`。`bugsnag`功能可检测和诊断应用程序中的崩溃，`new relic`封装了注册表并监视性能，`cors`可以启用以在我们自己的注册表域之外共享资源。建议您使用代理（如 nginx）将注册表部署到生产环境。您还可以直接在 Ubuntu 和基于 Red Hat Linux 的系统上运行 Docker 注册表。

目前，负责开发 Docker 平台的公司已在 GitHub 上发布了 Docker 注册表作为开源服务[`github.com/docker/docker-registry`](https://github.com/docker/docker-registry)。值得注意的是，Docker 索引只是一个建议，在撰写本书时，Docker 尚未发布任何开源项目。在本章中，我们将从 Docker 注册表的用例开始，然后从 GitHub 开始实际部署索引元素和 Docker 注册表。

# Docker 注册表用例

以下是 Docker 注册表的用例：

1.  拉取或下载图像

1.  推送图像

1.  删除图像

现在我们将详细介绍每个用例：

1.  **拉取或下载图像**：用户使用 Docker 客户端从索引请求图像，索引反过来向用户返回注册表详细信息。然后，Docker 客户端将直接请求注册表以获取所需的图像。注册表在内部使用索引对用户进行身份验证。如下图所示，图像拉取是通过客户端、索引和注册表模块的协作完成的：![Docker 注册表用例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_05_01.jpg)

1.  **推送图像**：用户请求推送图像，从索引获取注册表信息，然后直接将图像推送到注册表。注册表使用索引对用户进行身份验证，最后回应用户。控制流程如下图所示：![Docker 注册表用例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_05_02.jpg)

1.  **删除图像**：用户还可以请求从存储库中删除图像。

用户可以选择使用带有或不带有索引的注册表。在不带有索引的情况下使用注册表最适合存储私人图像。

# 运行自己的索引和注册表

在本节中，我们将执行以下步骤来运行自己的索引和注册表，并最终推送图像：

1.  从 GitHub 部署索引组件和注册表。

1.  配置 nginx 与 Docker 注册表。

1.  在 Web 服务器上设置 SSL 以进行安全通信。

## 第 1 步-从 GitHub 部署索引组件和注册表

索引组件包括`apache-utils`和`ngnix`，用于密码验证和 HTTPS 支持的 SSL 功能。用户必须注意，Docker 注册表的当前版本仅支持使用 HTTP 连接到注册表。因此，用户必须部署和使用**安全套接字层**（**SSL**）来保护数据。 SSL 在 Web 服务器和客户端的 Web 浏览器之间创建了加密连接，允许私人数据在没有窃听、数据篡改或消息伪造问题的情况下传输。这是使用广泛接受的 SSL 证书来保护数据的一种经过验证的方法。

Docker 注册表是一个 Python 应用程序，我们可以使用以下命令从[`github.com/docker/docker-registry`](https://github.com/docker/docker-registry)在本地 Ubuntu 机器上安装 Python：

```
$ sudo apt-get -y install build-essential python-dev \
 libevent-dev python-pip liblzma-dev swig libssl-dev

```

现在，安装 Docker 注册表：

```
$ sudo pip install docker-registry

```

这将更新 Python 软件包中的 Docker 注册表，并更新以下路径中的配置文件：

```
$ cd /usr/local/lib/python2.7/dist-packages/config/

```

将`config_sample.yml`文件复制到`config.yml`：

```
$ sudo cp config_sample.yml config.yml

```

默认情况下，Docker 将其数据保存在`/tmp`目录中，这可能会导致问题，因为在许多 Linux 系统上，`/tmp`文件夹在重新启动时会被清除。让我们创建一个永久文件夹来存储我们的数据：

```
$ sudo mkdir /var/docker-registry

```

让我们更新我们之前的`config.yml`文件，以适应以下两个位置的更新路径。第一个位置的更新代码如下：

```
sqlalchemy_index_database:
    _env:SQLALCHEMY_INDEX_DATABASE:sqlite:////var/docker-registry/docker-registry.db
```

以下是第二个位置的代码：

```
local: &local
    storage: local
    storage_path: _env:STORAGE_PATH:/var/docker-registry/registry
```

`config.yml`文件的其他默认配置正常工作。

现在，让我们使用`gunicorn`启动 Docker 注册表。 Gunicorn，也称为 Green Unicorn，是 Linux 系统的 Python **Web 服务器网关接口**（**WSGI**）HTTP 服务器：

```
$ sudo gunicorn --access-logfile - --debug -k gevent -b \
 0.0.0.0:5000 -w 1 docker_registry.wsgi:application
01/Dec/2014:04:59:23 +0000 WARNING: Cache storage disabled!
01/Dec/2014:04:59:23 +0000 WARNING: LRU cache disabled!
01/Dec/2014:04:59:23 +0000 DEBUG: Will return docker-registry.drivers.file.Storage

```

现在，Docker 注册表作为用户本地机器上的一个进程正在运行。

我们可以使用*Ctrl* + *C*来停止这个进程。

我们可以按以下方式启动 Linux 服务：

1.  为`docker-registry`工具创建一个目录：

```
$ sudo mkdir -p /var/log/docker-registry

```

1.  创建并更新 Docker 注册表配置文件：

```
$ sudo vi /etc/init/docker-registry.conf

```

1.  更新文件中的以下内容：

```
description "Docker Registry"
start on runlevel [2345]
stop on runlevel [016]
respawn
respawn limit 10 5
script
exec gunicorn --access-logfile /var/log/docker-registry/access.log --error-logfile /var/log/docker-registry/server.log -k gevent --max-requests 100 --graceful-timeout 3600 -t 3600 -b localhost:5000 -w 8 docker_registry.wsgi:application
end script
```

1.  保存文件后，运行 Docker 注册表服务：

```
$ sudo service docker-registry start
docker-registry start/running, process 25760

```

1.  现在，使用`apache-utils`来保护此注册表，启用密码保护功能，如下所示：

```
$ sudo apt-get -y install nginx apache2-utils

```

1.  用户创建登录 ID 和密码来访问 Docker 注册表：

```
$ sudo htpasswd -c /etc/nginx/docker-registry.htpasswd vinod1

```

1.  在提示时输入新密码。此时，我们有登录 ID 和密码来访问 Docker 注册表。

## 第 2 步 - 配置 nginx 与 Docker 注册表

接下来，我们需要告诉 nginx 使用该认证文件（在上一节的第 6 步和第 7 步中创建）来转发请求到我们的 Docker 注册表。

我们需要创建 nginx 配置文件。为此，我们需要按照以下步骤进行：

1.  通过运行以下命令创建 ngnix 配置文件：

```
$ sudo vi /etc/nginx/sites-available/docker-registry

```

使用以下内容更新文件：

```
upstream docker-registry {
 server localhost:5000;
}
server {
 listen 8080;
 server_name my.docker.registry.com;
 # ssl on;
 # ssl_certificate /etc/ssl/certs/docker-registry;
 # ssl_certificate_key /etc/ssl/private/docker-registry;
 proxy_set_header Host       $http_host;   # required for Docker client sake
 proxy_set_header X-Real-IP  $remote_addr; # pass on real client IP
 client_max_body_size 0; # disable any limits to avoid HTTP 413 for large image uploads
 # required to avoid HTTP 411: see Issue #1486 (https://github.com/dotcloud/docker/issues/1486)
 chunked_transfer_encoding on;
 location / {
     # let Nginx know about our auth file
     auth_basic              "Restricted";
     auth_basic_user_file    docker-registry.htpasswd;
     proxy_pass http://docker-registry;
 } location /_ping {
     auth_basic off;
     proxy_pass http://docker-registry;
 }   location /v1/_ping {
     auth_basic off;
     proxy_pass http://docker-registry;
 }
}
```

1.  创建软链接并重新启动 ngnix 服务：

```
$ sudo ln -s /etc/nginx/sites-available/docker-registry  \
 /etc/nginx/sites-enabled/docker-registry
$ sudo service nginx restart

```

1.  让我们检查一切是否正常工作。运行以下命令，我们应该得到这个输出：

```
$ sudo curl localhost:5000
"\"docker-registry server\""

```

太好了！现在我们的 Docker 注册表正在运行。现在，我们必须检查 nginx 是否按我们的预期工作。要做到这一点，请运行以下命令：

```
$ curl localhost:8080

```

这次，我们会收到一个未经授权的消息：

```
<html>
<head><title>401 Authorization Required</title></head>
<body bgcolor="white">
<center><h1>401 Authorization Required</h1></center>
<hr><center>nginx/1.4.6 (Ubuntu)</center>
</body>
</html>
```

使用之前创建的密码登录：

```
$ curl vinod1:vinod1@localhost:8080
"\"docker-registry server\""ubuntu@ip-172-31-21-44:~$

```

这证实了您的 Docker 注册表受到密码保护。

## 第 3 步 - 在 Web 服务器上设置 SSL 以进行安全通信

这是在本地机器上设置 SSL 的最后一步，该机器托管了用于加密数据的 Web 服务器。我们创建以下文件：

```
$sudo vi /etc/nginx/sites-available/docker-registry

```

使用以下内容更新文件： 

```
server {
 listen 8080;
 server_name mydomain.com;
 ssl on;
 ssl_certificate /etc/ssl/certs/docker-registry;
 ssl_certificate_key /etc/ssl/private/docker-registry;
```

请注意，我的 Ubuntu 机器可以在 Internet 上使用名称`mydomain.com`，并且 SSL 已设置为证书和密钥的路径。

让我们按照以下方式签署证书：

```
$ sudo mkdir ~/certs
$ sudo cd ~/certs

```

使用以下命令生成根密钥：

```
$ sudo openssl genrsa -out devdockerCA.key 2048
Generating RSA private key, 2048 bit long modulus
..........+++
....................+++
e is 65537 (0x10001)

```

现在我们有了根密钥，让我们生成一个根证书（在命令提示符处输入任何你想要的）：

```
$ sudo openssl req -x509 -new -nodes -key devdockerCA.key -days  \
 10000 -out devdockerCA.crt

```

然后，为我们的服务器生成一个密钥：

```
$ sudo openssl genrsa -out dev-docker-registry.com.key 2048

```

现在，我们必须创建一个证书签名请求。一旦我们运行签名命令，请确保“通用名称”是我们的服务器名称。这是强制性的，任何偏差都会导致错误：

```
$ sudo openssl req -new -key dev-docker-registry.com.key -out \
 dev-docker-registry.com.csr

```

在这里，“通用名称”看起来像`mydomain.com`。这是在 AWS 上运行的 Ubuntu VM。

上述命令的输出如下：

```
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:mydomain.com
Email Address []:
Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:

```

“挑战密码”输入为空，并且用户也可以自由填写。然后，我们需要通过运行以下命令签署证书请求：

```
$ sudo openssl x509 -req -in dev-docker-registry.com.csr -CA  \
 devdockerCA.crt -CAkey devdockerCA.key -CAcreateserial -out \
 dev-docker-registry.com.crt -days 10000

```

现在我们已经生成了证书所需的所有文件，我们需要将这些文件复制到正确的位置。

首先，将证书和密钥复制到 nginx 期望它们在的路径：

```
$ sudo cp dev-docker-registry.com.crt /etc/ssl/certs/docker-registry
$ sudo chmod 777 /etc/ssl/certs/docker-registry
$ sudo cp dev-docker-registry.com.key /etc/ssl/private/docker-registry
$ sudo chmod 777 /etc/ssl/private/docker-registry

```

请注意，我们已经创建了自签名证书，并且它们是由任何已知的证书颁发机构签名的，因此我们需要通知注册表这是一个合法的证书：

```
$ sudo mkdir /usr/local/share/ca-certificates/docker-dev-cert
$ sudo cp devdockerCA.crt /usr/local/share/ca-certificates/docker-dev-cert
$ sudo update-ca-certificates
Updating certificates in /etc/ssl/certs... 1 added, 0 removed; done.
Running hooks in /etc/ca-certificates/updated....done.
ubuntu@ip-172-31-21-44:~/certs$

```

让我们重新启动 nginx 以重新加载配置和 SSL 密钥：

```
$ sudo service nginx restart

```

现在，我们将测试 SSL 证书，以检查它是否正常工作。由于`mydomain.com`不是互联网地址，请在`/etc/hosts`文件中添加条目：

```
172.31.24.44 mydomain.com

```

现在运行以下命令：

```
$ sudo curl https://vinod1:vinod1@ mydomain.com:8080
"\"docker-registry server\""ubuntu@ip-172-31-21-44:~$

```

因此，如果一切顺利，您应该会看到类似于这样的内容：

```
"docker-registry server"

```

# 将图像推送到新创建的 Docker 注册表

最后，将图像推送到 Docker 注册表。因此，让我们在本地 Ubuntu 机器上创建一个图像：

```
$ sudo docker run -t -i ubuntu /bin/bash
root@9593c56f9e70:/# echo "TEST" >/mydockerimage
root@9593c56f9e70:/# exit
$ sudo docker commit $(sudo docker ps -lq) vinod-image
e17b685ee6987bb0cd01b89d9edf81a9fc0a7ad565a7e85650c41fc7e5c0cf9e

```

让我们登录到在 Ubuntu 机器上本地创建的 Docker 注册表：

```
$ sudo docker --insecure-registry=mydomain.com:8080 \
 login https://mydomain.com:8080
Username: vinod1
Password:
Email: vinod.puchi@gmail.com
Login Succeeded

```

在将图像推送到注册表之前对其进行标记：

```
$ sudo docker tag vinod-image mydomain.com:8080/vinod-image

```

最后，使用`push`命令上传图像：

```
$ sudo docker push \
mydomain.com:8080/vinod-image
The push refers to a repository [mydomain.com
:8080/vinod-image] (len: 1)
Sending image list
Pushing repository mydomain.com:8080/vi
nod-image (1 tags)
511136ea3c5a: Image successfully pushed
5bc37dc2dfba: Image successfully pushed
----------------------------------------------------
e17b685ee698: Image successfully pushed
Pushing tag for rev [e17b685ee698] on {https://mydomain.com
:8080/v1/repositories/vinod-image/tags/latest}
$

```

现在，从本地磁盘中删除图像，并从 Docker 注册表中`pull`它：

```
$ sudo docker pull mydomain.com:8080/vinod-image
Pulling repository mydomain.com:8080/vi
nod-image
e17b685ee698: Pulling image (latest) from mydomain.com
17b685ee698: Download complete
dc07507cef42: Download complete
86ce37374f40: Download complete
Status: Downloaded newer image for mydomain.com:8080/vinod-image:latest
$

```

# 总结

Docker 引擎允许每个增值软件解决方案被容器化、索引化、注册化和存储化。Docker 正在成为一个系统化开发、发布、部署和在各处运行容器的强大工具。虽然`docker.io`允许您免费将 Docker 创建上传到他们的注册表，但您在那里上传的任何内容都是公开可发现和可访问的。创新者和公司对此并不感兴趣，因此坚持使用私人 Docker Hub。在本章中，我们以易于理解的方式为您解释了所有步骤、语法和语义。我们看到了如何检索图像以生成 Docker 容器，并描述了如何以安全的方式将我们的图像推送到 Docker 注册表，以便经过身份验证的开发人员找到并使用。认证和授权机制作为整个过程的重要部分，已经被详细解释。确切地说，本章被构想和具体化为设置自己的 Docker Hub 的指南。随着世界组织对容器化云表现出示范性兴趣，私人容器中心变得更加重要。

在下一章中，我们将深入探讨容器，这是从图像自然而然的发展。我们将演示在 Docker 容器中运行服务的能力，比如 Web 服务器，并展示它与主机和外部世界的交互。


# 第六章：在容器中运行服务

我们一步步地走到了这一步，为快速发展的 Docker 技术奠定了坚实而令人振奋的基础。我们谈论了高度可用和可重复使用的 Docker 镜像的重要构建模块。此外，您可以阅读如何通过精心设计的存储框架存储和共享 Docker 镜像的易于使用的技术和提示。通常情况下，镜像必须不断经过一系列验证、验证和不断完善，以使它们更加正确和相关，以满足渴望发展的社区的需求。在本章中，我们将通过描述创建一个小型 Web 服务器的步骤，将其运行在容器内，并从外部世界连接到 Web 服务器，将我们的学习提升到一个新的水平。

在本章中，我们将涵盖以下主题：

+   容器网络

+   **容器即服务**（**CaaS**）-构建、运行、暴露和连接到容器服务

+   发布和检索容器端口

+   将容器绑定到特定 IP 地址

+   自动生成 Docker 主机端口

+   使用`EXPOSE`和`-P`选项进行端口绑定

# 容器网络简要概述

与任何计算节点一样，Docker 容器需要进行网络连接，以便其他容器和客户端可以找到并访问它们。在网络中，通常通过 IP 地址来识别任何节点。此外，IP 地址是任何客户端到达任何服务器节点提供的服务的唯一机制。Docker 内部使用 Linux 功能来为容器提供网络连接。在本节中，我们将学习有关容器 IP 地址分配和检索容器 IP 地址的过程。

当容器启动时，Docker 引擎会无需用户干预地选择并分配 IP 地址给容器。您可能会对 Docker 如何为容器选择 IP 地址感到困惑，这个谜团分为两部分来解答，如下所示：

1.  在安装过程中，Docker 在 Docker 主机上创建一个名为`docker0`的虚拟接口。它还选择一个私有 IP 地址范围，并从所选范围中为`docker0`虚拟接口分配一个地址。所选的 IP 地址始终位于 Docker 主机 IP 地址范围之外，以避免 IP 地址冲突。

1.  稍后，当我们启动一个容器时，Docker 引擎会从为`docker0`虚拟接口选择的 IP 地址范围中选择一个未使用的 IP 地址。然后，引擎将这个 IP 地址分配给新启动的容器。

默认情况下，Docker 会选择 IP 地址`172.17.42.1/16`，或者在`172.17.0.0`到`172.17.255.255`范围内的 IP 地址之一。如果与`172.17.x.x`地址直接冲突，Docker 将选择不同的私有 IP 地址范围。也许，老式的`ifconfig`（显示网络接口详细信息的命令）在这里很有用，可以用来找出分配给虚拟接口的 IP 地址。让我们用`docker0`作为参数运行`ifconfig`，如下所示：

```
$ ifconfig docker0

```

输出的第二行将显示分配的 IP 地址及其子网掩码：

```
inet addr:172.17.42.1  Bcast:0.0.0.0  Mask:255.255.0.0

```

显然，从前面的文本中，`172.17.42.1`是分配给`docker0`虚拟接口的 IP 地址。IP 地址`172.17.42.1`是从`172.17.0.0`到`172.17.255.255`的私有 IP 地址范围中的一个地址。

现在迫切需要我们学习如何找到分配给容器的 IP 地址。容器应该使用`-i`选项以交互模式启动。当然，我们可以通过在容器内运行`ifconfig`命令来轻松找到 IP 地址，如下所示：

```
$ sudo docker run -i -t ubuntu:14.04 /bin/bash
root@4b0b567b6019:/# ifconfig

```

`ifconfig`命令将显示 Docker 容器中所有接口的详细信息，如下所示：

```
eth0      Link encap:Ethernet  HWaddr e6:38:dd:23:aa:3f
 inet addr:172.17.0.12  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: fe80::e438:ddff:fe23:aa3f/64 Scope:Link
 UP BROADCAST RUNNING  MTU:1500  Metric:1
 RX packets:6 errors:0 dropped:2 overruns:0 frame:0
 TX packets:7 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:1000
 RX bytes:488 (488.0 B)  TX bytes:578 (578.0 B)

lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

```

显然，`ifconfig`命令的前面输出显示 Docker 引擎为容器虚拟化了两个网络接口，如下所示：

+   第一个是`eth0`（以太网）接口，Docker 引擎分配了 IP 地址`172.17.0.12`。显然，这个地址也在`docker0`虚拟接口的相同 IP 地址范围内。此外，分配给`eth0`接口的地址用于容器内部通信和主机到容器的通信。

+   第二个接口是`lo`（环回）接口，Docker 引擎分配了环回地址`127.0.0.1`。环回接口用于容器内部的本地通信。

简单吧？然而，当使用`docker run`子命令中的`-d`选项以分离模式启动容器时，检索 IP 地址变得复杂起来。分离模式中的这种复杂性的主要原因是没有 shell 提示符来运行`ifconfig`命令。幸运的是，Docker 提供了一个`docker inspect`子命令，它像瑞士军刀一样方便，并允许我们深入了解 Docker 容器或镜像的低级细节。`docker inspect`子命令以 JSON 数组格式生成请求的详细信息。

以下是我们之前启动的交互式容器上`docker inspect`子命令的示例运行。`4b0b567b6019`容器 ID 取自容器的提示符：

```
$ sudo docker inspect 4b0b567b6019

```

该命令生成有关容器的大量信息。在这里，我们展示了从`docker inspect`子命令的输出中提取的容器网络配置的一些摘录：

```
"NetworkSettings": {
 "Bridge": "docker0",
 "Gateway": "172.17.42.1",
 "IPAddress": "172.17.0.12",
 "IPPrefixLen": 16,
 "PortMapping": null,
 "Ports": {}
 },

```

在这里，网络配置列出了以下详细信息：

+   **Bridge**：这是容器绑定的桥接口

+   **Gateway**：这是容器的网关地址，也是桥接口的地址

+   **IPAddress**：这是分配给容器的 IP 地址

+   **IPPrefixLen**：这是 IP 前缀长度，表示子网掩码的另一种方式

+   **PortMapping**：这是端口映射字段，现在已经被弃用，其值始终为 null

+   **Ports**：这是端口字段，将列举所有端口绑定，这将在本章后面介绍

毫无疑问，`docker inspect`子命令对于查找容器或镜像的细节非常方便。然而，浏览令人生畏的细节并找到我们渴望寻找的正确信息是一项繁琐的工作。也许，您可以使用`grep`命令将其缩小到正确的信息。或者更好的是，使用`docker inspect`子命令，它可以帮助您使用`docker inspect`子命令的`--format`选项从 JSON 数组中选择正确的字段。

值得注意的是，在以下示例中，我们使用`docker inspect`子命令的`--format`选项仅检索容器的 IP 地址。IP 地址可以通过 JSON 数组的`.NetworkSettings.IPAddress`字段访问：

```
$ sudo docker inspect \
 --format='{{.NetworkSettings.IPAddress}}' 4b0b567b6019
172.17.0.12

```

# 将容器视为服务

我们为 Docker 技术的基础打下了良好的基础。在本节中，我们将专注于使用 HTTP 服务创建镜像，使用创建的镜像在容器内启动 HTTP 服务，然后演示连接到容器内运行的 HTTP 服务。

## 构建 HTTP 服务器镜像

在本节中，我们将创建一个 Docker 镜像，以在`Ubuntu 14.04`基础镜像上安装`Apache2`，并配置`Apache HTTP Server`以作为可执行文件运行，使用`ENTRYPOINT`指令。

在第三章*构建镜像*中，我们演示了使用 Dockerfile 在`Ubuntu 14.04`基础镜像上创建`Apache2`镜像的概念。在这个例子中，我们将通过设置`Apache`日志路径和使用`ENTRYPOINT`指令将`Apache2`设置为默认执行应用程序来扩展这个 Dockerfile。以下是`Dockerfile`内容的详细解释。

我们将使用`FROM`指令以`ubuntu:14.04`作为基础镜像构建镜像，如`Dockerfile`片段所示：

```
###########################################
# Dockerfile to build an apache2 image
###########################################
# Base image is Ubuntu
FROM ubuntu:14.04
```

使用 MAINTAINER 指令设置作者详细信息

```
# Author: Dr. Peter
MAINTAINER Dr. Peter <peterindia@gmail.com>
```

使用一个`RUN`指令，我们将同步`apt`仓库源列表，安装`apache2`包，然后清理检索到的文件：

```
# Install apache2 package
RUN apt-get update && \
     apt-get install -y apache2 && \
     apt-get clean
```

使用`ENV`指令设置 Apache 日志目录路径：

```
# Set the log directory PATH
ENV APACHE_LOG_DIR /var/log/apache2
```

现在，最后一条指令是使用`ENTRYPOINT`指令启动`apache2`服务器：

```
# Launch apache2 server in the foreground
ENTRYPOINT ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]
```

在上一行中，您可能会惊讶地看到`FOREGROUND`参数。这是传统和容器范式之间的关键区别之一。在传统范式中，服务器应用通常在后台启动，作为服务或守护程序，因为主机系统是通用系统。然而，在容器范式中，必须在前台启动应用程序，因为镜像是为唯一目的而创建的。

在`Dockerfile`中规定了构建镜像的指令后，现在让我们通过使用`docker build`子命令来构建镜像，将镜像命名为`apache2`，如下所示：

```
$ sudo docker build -t apache2 .

```

现在让我们使用`docker images`子命令快速验证镜像：

```
$ sudo docker images

```

正如我们在之前的章节中所看到的，`docker images`命令显示了 Docker 主机中所有镜像的详细信息。然而，为了准确说明使用`docker build`子命令创建的镜像，我们从完整的镜像列表中突出显示了`apache2:latest`（目标镜像）和`ubuntu:14.04`（基础镜像）的详细信息，如下面的输出片段所示：

```
apache2             latest              d5526cd1a645        About a minute ago   232.6 MB
ubuntu              14.04               5506de2b643b        5 days ago           197.8 MB

```

构建了 HTTP 服务器镜像后，现在让我们继续下一节，学习如何运行 HTTP 服务。

## 作为服务运行 HTTP 服务器镜像

在这一节中，我们将使用在上一节中制作的 Apache HTTP 服务器镜像来启动一个容器。在这里，我们使用`docker run`子命令的`-d`选项以分离模式（类似于 UNIX 守护进程）启动容器：

```
$ sudo docker run -d apache2
9d4d3566e55c0b8829086e9be2040751017989a47b5411c9c4f170ab865afcef

```

启动了容器后，让我们运行`docker logs`子命令，看看我们的 Docker 容器是否在其`STDIN`（标准输入）或`STDERR`（标准错误）上生成任何输出：

```
$ sudo docker logs \ 9d4d3566e55c0b8829086e9be2040751017989a47b5411c9c4f170ab865afcef

```

由于我们还没有完全配置 Apache HTTP 服务器，您将会发现以下警告，作为`docker logs`子命令的输出：

```
AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 172.17.0.13\. Set the 'ServerName' directive globally to suppress this message

```

从前面的警告消息中，很明显可以看出分配给这个容器的 IP 地址是`172.17.0.13`。

## 连接到 HTTP 服务

在前面的部分中，从警告消息中，我们发现容器的 IP 地址是`172.17.0.13`。在一个完全配置好的 HTTP 服务器容器上，是没有这样的警告的，所以让我们仍然运行`docker inspect`子命令来使用容器 ID 检索 IP 地址：

```
$ sudo docker inspect \
--format='{{.NetworkSettings.IPAddress}}' \ 9d4d3566e55c0b8829086e9be2040751017989a47b5411c9c4f170ab865afcef
172.17.0.13

```

在 Docker 主机的 shell 提示符下，找到容器的 IP 地址为`172.17.0.13`，让我们快速在这个 IP 地址上运行一个 web 请求，使用`wget`命令。在这里，我们选择使用`-qO-`参数来以安静模式运行`wget`命令，并在屏幕上显示检索到的 HTML 文件：

```
$ wget -qO - 172.17.0.13

```

在这里，我们展示了检索到的 HTML 文件的前五行：

```
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html >
  <!--
    Modified from the Debian original for Ubuntu
    Last updated: 2014-03-19
```

很棒，不是吗？我们在一个容器中运行了我们的第一个服务，并且我们能够从 Docker 主机访问我们的服务。

此外，在普通的 Docker 安装中，一个容器提供的服务可以被 Docker 主机内的任何其他容器访问。您可以继续，在交互模式下启动一个新的 Ubuntu 容器，使用`apt-get`安装`wget`软件包，并运行与我们在 Docker 主机中所做的相同的`wget -qO - 172.17.0.13`命令。当然，您会看到相同的输出。

# 暴露容器服务

到目前为止，我们已经成功启动了一个 HTTP 服务，并从 Docker 主机以及同一 Docker 主机内的另一个容器访问了该服务。此外，正如在第二章的*从容器构建镜像*部分所演示的，容器能够通过在互联网上连接到公共可用的 apt 仓库来成功安装`wget`软件包。然而，默认情况下，外部世界无法访问容器提供的服务。起初，这可能看起来像是 Docker 技术的一个限制。然而，事实是，容器是根据设计与外部世界隔离的。

Docker 通过 IP 地址分配标准实现容器的网络隔离，具体列举如下：

1.  为容器分配一个私有 IP 地址，该地址无法从外部网络访问。

1.  为容器分配一个在主机 IP 网络之外的 IP 地址。

因此，Docker 容器甚至无法从与 Docker 主机相同的 IP 网络连接的系统访问。这种分配方案还可以防止可能会出现的 IP 地址冲突。

现在，您可能想知道如何使服务在容器内运行，并且可以被外部访问，换句话说，暴露容器服务。嗯，Docker 通过在底层利用 Linux `iptables`功能来弥合这种连接差距。

在前端，Docker 为用户提供了两种不同的构建模块来弥合这种连接差距。其中一个构建模块是使用`docker run`子命令的`-p`（将容器的端口发布到主机接口）选项来绑定容器端口。另一种选择是使用`EXPOSE` Dockerfile 指令和`docker run`子命令的`-P`（将所有公开的端口发布到主机接口）选项的组合。

## 发布容器端口-使用-p 选项

Docker 使您能够通过将容器的端口绑定到主机接口来发布容器内提供的服务。`docker run`子命令的`-p`选项使您能够将容器端口绑定到 Docker 主机的用户指定或自动生成的端口。因此，任何发送到 Docker 主机的 IP 地址和端口的通信都将转发到容器的端口。实际上，`-p`选项支持以下四种格式的参数：

+   `<hostPort>:<containerPort>`

+   `<containerPort>`

+   `<ip>:<hostPort>:<containerPort>`

+   `<ip>::<containerPort>`

在这里，`<ip>`是 Docker 主机的 IP 地址，`<hostPort>`是 Docker 主机的端口号，`<containerPort>`是容器的端口号。在本节中，我们向您介绍了`-p <hostPort>:<containerPort>`格式，并在接下来的部分介绍其他格式。

为了更好地理解端口绑定过程，让我们重用之前创建的`apache2` HTTP 服务器镜像，并使用`docker run`子命令的`-p`选项启动一个容器。端口`80`是 HTTP 服务的发布端口，作为默认行为，我们的`apache2` HTTP 服务器也可以在端口`80`上访问。在这里，为了演示这种能力，我们将使用`docker run`子命令的`-p <hostPort>:<containerPort>`选项，将容器的端口`80`绑定到 Docker 主机的端口`80`，如下命令所示：

```
$ sudo docker run -d -p 80:80 apache2
baddba8afa98725ec85ad953557cd0614b4d0254f45436f9cb440f3f9eeae134

```

现在我们已经成功启动了容器，我们可以使用任何外部系统的 Web 浏览器连接到我们的 HTTP 服务器（只要它具有网络连接），以访问我们的 Docker 主机。到目前为止，我们还没有向我们的`apache2` HTTP 服务器镜像添加任何网页。

因此，当我们从 Web 浏览器连接时，我们将得到以下屏幕，这只是随`Ubuntu Apache2`软件包一起提供的默认页面：

![发布容器端口- -p 选项](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_06_01.jpg)

## 容器的网络地址转换

在上一节中，我们看到`-p 80:80`选项是如何起作用的，不是吗？实际上，在幕后，Docker 引擎通过自动配置 Linux `iptables`配置文件中的**网络地址转换**（**NAT**）规则来实现这种无缝连接。

为了说明在 Linux `iptables`中自动配置 NAT 规则，让我们查询 Docker 主机的`iptables`以获取其 NAT 条目，如下所示：

```
$ sudo iptables -t nat -L -n

```

接下来的文本是从 Docker 引擎自动添加的`iptables` NAT 条目中摘录的：

```
Chain DOCKER (2 references)
target     prot opt source               destination
DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80 to:172.17.0.14:80

```

从上面的摘录中，很明显 Docker 引擎有效地添加了一个`DNAT`规则。以下是`DNAT`规则的详细信息：

+   `tcp`关键字表示这个`DNAT`规则仅适用于 TCP 传输协议。

+   第一个`0.0.0.0/0`地址是源地址的元 IP 地址。这个地址表示连接可以来自任何 IP 地址。

+   第二个`0.0.0.0/0`地址是 Docker 主机上目标地址的元 IP 地址。这个地址表示连接可以与 Docker 主机中的任何有效 IP 地址建立。

+   最后，`dpt:80 to:172.17.0.14:80`是用于将 Docker 主机端口`80`上的任何 TCP 活动转发到 IP 地址`172.17.0.17`，即我们容器的 IP 地址和端口`80`的转发指令。

因此，Docker 主机接收到的任何 TCP 数据包都将转发到容器的端口`80`。

## 检索容器端口

Docker 引擎提供至少三种不同的选项来检索容器的端口绑定详细信息。在这里，让我们首先探索选项，然后继续分析检索到的信息。选项如下：

+   `docker ps`子命令始终显示容器的端口绑定详细信息，如下所示：

```
$ sudo docker ps
CONTAINER ID        IMAGE               COMMAND                CREATED             STATUS              PORTS                NAMES
baddba8afa98        apache2:latest      "/usr/sbin/apache2ct   26 seconds ago      Up 25 seconds       0.0.0.0:80->80/tcp   furious_carson

```

+   `docker inspect`子命令是另一种选择；但是，你必须浏览相当多的细节。运行以下命令：

```
$ sudo docker inspect baddba8afa98

```

`docker inspect`子命令以三个 JSON 对象显示与端口绑定相关的信息，如下所示：

+   `ExposedPorts`对象枚举了通过`Dockerfile`中的`EXPOSE`指令暴露的所有端口，以及使用`docker run`子命令中的`-p`选项映射的容器端口。由于我们没有在`Dockerfile`中添加`EXPOSE`指令，我们只有使用`-p80:80`作为`docker run`子命令的参数映射的容器端口：

```
"ExposedPorts": {
 "80/tcp": {}
 },

```

+   `PortBindings`对象是`HostConfig`对象的一部分，该对象列出了通过`docker run`子命令中的`-p`选项进行的所有端口绑定。该对象永远不会列出通过`Dockerfile`中的`EXPOSE`指令暴露的端口：

```
"PortBindings": {
 "80/tcp": [
 {
 "HostIp": "",
 "HostPort": "80"
 }
 ]
 },

```

+   `NetworkSettings`对象的`Ports`对象具有与先前的`PortBindings`对象相同级别的细节。但是，该对象包含通过`Dockerfile`中的`EXPOSE`指令暴露的所有端口，以及使用`docker run`子命令的`-p`选项映射的容器端口：

```
"NetworkSettings": {
 "Bridge": "docker0",
 "Gateway": "172.17.42.1",
 "IPAddress": "172.17.0.14",
 "IPPrefixLen": 16,
 "PortMapping": null,
 "Ports": {
 "80/tcp": [
 {
 "HostIp": "0.0.0.0",
 "HostPort": "80"
 }
 ]
 }
 },

```

当然，可以使用`docker inspect`子命令的`--format`选项来过滤特定的端口字段。

+   `docker port`子命令允许您通过指定容器的端口号来检索 Docker 主机上的端口绑定：

```
$ sudo docker port baddba8afa98 80
0.0.0.0:80

```

显然，在所有先前的输出摘录中，突出显示的信息是 IP 地址`0.0.0.0`和端口号`80`。IP 地址`0.0.0.0`是一个元地址，代表了 Docker 主机上配置的所有 IP 地址。实际上，容器端口`80`绑定到了 Docker 主机上所有有效的 IP 地址。因此，HTTP 服务可以通过 Docker 主机上配置的任何有效 IP 地址访问。

## 将容器绑定到特定的 IP 地址

到目前为止，使用我们学到的方法，容器总是绑定到 Docker 主机上配置的所有 IP 地址。然而，您可能希望在不同的 IP 地址上提供不同的服务。换句话说，特定的 IP 地址和端口将被配置为提供特定的服务。我们可以在 Docker 中使用`docker run`子命令的`-p <ip>:<hostPort>:<containerPort>`选项来实现这一点，如下例所示：

```
$ sudo docker run -d -p 198.51.100.73:80:80 apache2
92f107537bebd48e8917ea4f4788bf3f57064c8c996fc23ea0fd8ea49b4f3335

```

在这里，IP 地址必须是 Docker 主机上的有效 IP 地址。如果指定的 IP 地址不是 Docker 主机上的有效 IP 地址，则容器启动将失败，并显示错误消息，如下所示：

```
2014/11/09 10:22:10 Error response from daemon: Cannot start container 99db8d30b284c0a0826d68044c42c370875d2c3cad0b87001b858ba78e9de53b: Error starting userland proxy: listen tcp 198.51.100.73:80: bind: cannot assign requested address

```

现在，让我们快速回顾一下前面示例的端口映射以及 NAT 条目。

以下文本是`docker ps`子命令的输出摘录，显示了此容器的详细信息：

```
92f107537beb        apache2:latest      "/usr/sbin/apache2ct   About a minute ago   Up About a minute   198.51.100.73:80->80/tcp   boring_ptolemy

```

以下文本是`iptables -n nat -L -n`命令的输出摘录，显示了为此容器创建的`DNAT`条目：

```
DNAT    tcp -- 0.0.0.0/0      198.51.100.73     tcp dpt:80 to:172.17.0.15:80

```

在审查`docker run`子命令的输出和`iptables`的`DNAT`条目之后，您将意识到 Docker 引擎如何优雅地配置了容器在 Docker 主机的 IP 地址`198.51.100.73`和端口`80`上提供的服务。

## 自动生成 Docker 主机端口

Docker 容器天生轻量级，由于其轻量级的特性，您可以在单个 Docker 主机上运行多个相同或不同服务的容器。特别是根据需求在多个容器之间自动扩展相同服务的需求是当今 IT 基础设施的需求。在本节中，您将了解在启动多个具有相同服务的容器时所面临的挑战，以及 Docker 解决这一挑战的方式。

在本章的前面，我们使用`apache2 http server`启动了一个容器，并将其绑定到 Docker 主机的端口`80`。现在，如果我们尝试再启动一个绑定到相同端口`80`的容器，容器将无法启动，并显示错误消息，如下例所示：

```
$ sudo docker run -d -p 80:80 apache2
6f01f485ab3ce81d45dc6369316659aed17eb341e9ad0229f66060a8ba4a2d0e
2014/11/03 23:28:07 Error response from daemon: Cannot start container 6f01f485ab3ce81d45dc6369316659aed17eb341e9ad0229f66060a8ba4a2d0e: Bind for 0.0.0.0:80 failed: port is already allocated

```

显然，在上面的例子中，容器无法启动，因为先前的容器已经映射到`0.0.0.0`（Docker 主机的所有 IP 地址）和端口`80`。在 TCP/IP 通信模型中，IP 地址、端口和传输协议（TCP、UDP 等）的组合必须是唯一的。

我们可以通过手动选择 Docker 主机端口号（例如，`-p 81:80`或`-p 8081:80`）来解决这个问题。虽然这是一个很好的解决方案，但在自动扩展的场景下表现不佳。相反，如果我们把控制权交给 Docker，它会在 Docker 主机上自动生成端口号。通过使用`docker run`子命令的`-p <containerPort>`选项来实现这种端口号生成，如下例所示：

```
$ sudo docker run -d -p 80 apache2
ea3e0d1b18cff40ffcddd2bf077647dc94bceffad967b86c1a343bd33187d7a8

```

成功启动了具有自动生成端口的新容器后，让我们回顾一下上面例子的端口映射以及 NAT 条目：

+   以下文本是`docker ps`子命令的输出摘录，显示了该容器的详细信息：

```
ea3e0d1b18cf        apache2:latest      "/usr/sbin/apache2ct   5 minutes ago       Up 5 minutes        0.0.0.0:49158->80/tcp   nostalgic_morse

```

+   以下文本是`iptables -n nat -L -n`命令的输出摘录，显示了为该容器创建的`DNAT`条目：

```
DNAT    tcp -- 0.0.0.0/0      0.0.0.0/0      tcp dpt:49158 to:172.17.0.18:80

```

在审查了`docker run`子命令的输出和`iptables`的`DNAT`条目之后，引人注目的是端口号`49158`。端口号`49158`是由 Docker 引擎在 Docker 主机上巧妙地自动生成的，借助底层操作系统的帮助。此外，元 IP 地址`0.0.0.0`意味着容器提供的服务可以通过 Docker 主机上配置的任何有效 IP 地址从外部访问。

您可能有一个使用案例，您希望自动生成端口号。但是，如果您仍希望将服务限制在 Docker 主机的特定 IP 地址上，您可以使用`docker run`子命令的`-p <IP>::<containerPort>`选项，如下例所示：

```
$ sudo docker run -d -p 198.51.100.73::80 apache2
6b5de258b3b82da0290f29946436d7ae307c8b72f22239956e453356532ec2a7

```

在前述的两种情况中，Docker 引擎在 Docker 主机上自动生成了端口号并将其暴露给外部世界。网络通信的一般规范是通过预定义的端口号公开任何服务，以便任何人都可以知道 IP 地址，并且端口号可以轻松访问提供的服务。然而，在这里，端口号是自动生成的，因此外部世界无法直接访问提供的服务。因此，容器创建的这种方法的主要目的是实现自动扩展，并且以这种方式创建的容器将与预定义端口上的代理或负载平衡服务进行接口。

## 使用 EXPOSE 和-P 选项进行端口绑定

到目前为止，我们已经讨论了将容器内运行的服务发布到外部世界的四种不同方法。在这四种方法中，端口绑定决策是在容器启动时进行的，并且镜像对于提供服务的端口没有任何信息。到目前为止，这已经运作良好，因为镜像是由我们构建的，我们对提供服务的端口非常清楚。然而，在第三方镜像的情况下，容器内的端口使用必须明确发布。此外，如果我们为第三方使用或甚至为自己使用构建镜像，明确声明容器提供服务的端口是一个良好的做法。也许，镜像构建者可以随镜像一起提供一个自述文件。然而，将端口详细信息嵌入到镜像本身中会更好，这样您可以轻松地从镜像中手动或通过自动化脚本找到端口详细信息。

Docker 技术允许我们使用`Dockerfile`中的`EXPOSE`指令嵌入端口信息，我们在第三章*构建镜像*中介绍过。在这里，让我们编辑之前在本章中使用的构建`apache2` HTTP 服务器镜像的`Dockerfile`，并添加一个`EXPOSE`指令，如下所示。HTTP 服务的默认端口是端口`80`，因此端口`80`被暴露：

```
###########################################
# Dockerfile to build an apache2 image
###########################################
# Base image is Ubuntu
FROM ubuntu:14.04
# Author: Dr. Peter
MAINTAINER Dr. Peter <peterindia@gmail.com>
# Install apache2 package
RUN apt-get update && \
     apt-get install -y apache2 && \
     apt-get clean
# Set the log directory PATH
ENV APACHE_LOG_DIR /var/log/apache2
# Expose port 80
EXPOSE 80
# Launch apache2 server in the foreground
ENTRYPOINT ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]
```

现在我们已经在我们的`Dockerfile`中添加了`EXPOSE`指令，让我们继续使用`docker build`命令构建镜像的下一步。在这里，让我们重用镜像名称`apache2`，如下所示：

```
$ sudo docker build -t apache2 .

```

成功构建了镜像后，让我们检查镜像以验证`EXPOSE`指令对镜像的影响。正如我们之前学到的，我们可以使用`docker inspect`子命令，如下所示：

```
$ sudo docker inspect apache2

```

在仔细审查前面命令生成的输出后，您会意识到 Docker 将暴露的端口信息存储在`Config`对象的`ExposedPorts`字段中。以下是摘录，显示了暴露的端口信息是如何显示的：

```
"ExposedPorts": {
 "80/tcp": {}
 },

```

或者，您可以将格式选项应用于`docker inspect`子命令，以便将输出缩小到非常特定的信息。在这种情况下，`Config`对象的`ExposedPorts`字段在以下示例中显示：

```
$ sudo docker inspect --format='{{.Config.ExposedPorts}}' \
 apache2
map[80/tcp:map[]]

```

继续讨论`EXPOSE`指令，我们现在可以使用我们刚刚创建的`apache2`镜像启动容器。然而，`EXPOSE`指令本身不能在 Docker 主机上创建端口绑定。为了为使用`EXPOSE`指令声明的端口创建端口绑定，Docker 引擎在`docker run`子命令中提供了`-P`选项。

在下面的示例中，从之前重建的`apache2`镜像启动了一个容器。在这里，使用`-d`选项以分离模式启动容器，并使用`-P`选项为 Docker 主机上声明的所有端口创建端口绑定，使用`Dockerfile`中的`EXPOSE`指令：

```
$ sudo docker run -d -P apache2
fdb1c8d68226c384ab4f84882714fec206a73fd8c12ab57981fbd874e3fa9074

```

现在我们已经使用`EXPOSE`指令创建了新容器的镜像，就像之前的容器一样，让我们回顾一下端口映射以及前面示例的 NAT 条目：

+   以下文本摘自`docker ps`子命令的输出，显示了此容器的详细信息：

```
ea3e0d1b18cf        apache2:latest      "/usr/sbin/apache2ct   5 minutes ago       Up 5 minutes        0.0.0.0:49159->80/tcp   nostalgic_morse

```

+   以下文本摘自`iptables -t nat -L -n`命令的输出，显示了为该容器创建的`DNAT`条目：

```
DNAT    tcp -- 0.0.0.0/0      0.0.0.0/0      tcp dpt:49159 to:172.17.0.19:80

```

`docker run`子命令的`-P`选项不接受任何额外的参数，比如 IP 地址或端口号；因此，无法对端口绑定进行精细调整，如`docker run`子命令的`-p`选项。如果对端口绑定的精细调整对您至关重要，您可以随时使用`docker run`子命令的`-p`选项。

# 总结

容器在实质上并不以孤立或独立的方式提供任何东西。它们需要系统地构建，并配备网络接口和端口号。这导致容器在外部世界中的标准化展示，使其他主机或容器能够在任何网络上找到、绑定和利用它们独特的能力。因此，网络可访问性对于容器被注意并以无数种方式被利用至关重要。本章专门展示了容器如何被设计和部署为服务，以及容器网络的方面如何在日益展开的日子里精确而丰富地赋予容器服务的独特世界力量。在接下来的章节中，我们将详细讨论 Docker 容器在软件密集型 IT 环境中的各种能力。


# 第七章：与容器共享数据

一次只做一件事，并且做好，是信息技术（IT）部门长期以来的成功口头禅之一。这个广泛使用的原则也很好地适用于构建和暴露 Docker 容器，并被规定为实现最初设想的 Docker 启发式容器化范式的最佳实践之一。也就是说，将单个应用程序以及其直接依赖项和库放在 Docker 容器中，以确保容器的独立性、自给自足性和可操纵性。让我们看看为什么容器如此重要：

+   容器的临时性质：容器通常存在的时间与应用程序存在的时间一样长。然而，这对应用程序数据有一些负面影响。应用程序自然会经历各种变化，以适应业务和技术变化，甚至在其生产环境中也是如此。还有其他原因，比如应用程序故障、版本更改、应用程序维护等，导致应用程序需要不断更新和升级。在通用计算模型的情况下，即使应用程序因任何原因而死亡，与该应用程序关联的持久数据也会保存在文件系统中。然而，在容器范式的情况下，应用程序升级通常是通过创建一个具有较新版本应用程序的新容器来完成的，然后丢弃旧容器。同样，当应用程序发生故障时，需要启动一个新容器，并丢弃旧容器。总之，容器具有临时性质。

+   企业连续性的需求：在容器环境中，完整的执行环境，包括其数据文件通常被捆绑和封装在容器内。无论出于何种原因，当一个容器被丢弃时，应用程序数据文件也会随着容器一起消失。然而，为了提供无缝的服务，这些应用程序数据文件必须在容器外部保留，并传递给将继续提供服务的容器。一些应用程序数据文件，如日志文件，需要在容器外部进行各种后续分析。Docker 技术通过一个称为数据卷的新构建块非常创新地解决了这个文件持久性问题。

在本章中，我们将涵盖以下主题：

+   数据卷

+   共享主机数据

+   在容器之间共享数据

+   可避免的常见陷阱

# 数据卷

数据卷是 Docker 环境中数据共享的基本构建块。在深入了解数据共享的细节之前，必须对数据卷概念有很好的理解。到目前为止，我们在镜像或容器中创建的所有文件都是联合文件系统的一部分。然而，数据卷是 Docker 主机文件系统的一部分，它只是在容器内部挂载。

数据卷可以使用`Dockerfile`的`VOLUME`指令在 Docker 镜像中进行刻录。此外，可以在启动容器时使用`docker run`子命令的`-v`选项进行指定。在下面的示例中，将详细说明在`Dockerfile`中使用`VOLUME`指令的含义，具体步骤如下：

1.  创建一个非常简单的`Dockerfile`，其中包含基础镜像（`ubuntu:14.04`）和数据卷（`/MountPointDemo`）的指令：

```
FROM ubuntu:14.04
VOLUME /MountPointDemo
```

1.  使用`docker build`子命令构建名称为`mount-point-demo`的镜像：

```
$ sudo docker build -t mount-point-demo .

```

1.  构建完镜像后，让我们使用`docker inspect`子命令快速检查我们的数据卷：

```
$ sudo docker inspect mount-point-demo
[{
 "Architecture": "amd64",
... TRUNCATED OUTPUT ...
 "Volumes": {
 "/MountPointDemo": {}
 },
... TRUNCATED OUTPUT ...

```

显然，在前面的输出中，数据卷是直接刻录在镜像中的。

1.  现在，让我们使用先前创建的镜像启动一个交互式容器，如下命令所示：

```
$ sudo docker run --rm -it mount-point-demo

```

从容器的提示符中，使用`ls -ld`命令检查数据卷的存在：

```
root@8d22f73b5b46:/# ls -ld /MountPointDemo
drwxr-xr-x 2 root root 4096 Nov 18 19:22 /MountPointDemo

```

如前所述，数据卷是 Docker 主机文件系统的一部分，并且会被挂载，如下命令所示：

```
root@8d22f73b5b46:/# mount
... TRUNCATED OUTPUT ...
/dev/disk/by-uuid/721cedbd-57b1-4bbd-9488-ec3930862cf5 on /MountPointDemo type ext3 (rw,noatime,nobarrier,errors=remount-ro,data=ordered)
... TRUNCATED OUTPUT ...

```

1.  在本节中，我们检查了镜像，以了解镜像中的数据卷声明。现在我们已经启动了容器，让我们在另一个终端中使用`docker inspect`子命令和容器 ID 作为参数来检查容器的数据卷。我们之前创建了一些容器，为此，让我们直接从容器的提示符中获取容器 ID`8d22f73b5b46`：

```
$ sudo docker inspect 8d22f73b5b46
... TRUNCATED OUTPUT ...
 "Volumes": {
 "/MountPointDemo": "/var/lib/docker/vfs/dir/737e0355c5d81c96a99d41d1b9f540c2a212000661633ceea46f2c298a45f128"
 },
 "VolumesRW": {
 "/MountPointDemo": true
 }
}

```

显然，在这里，数据卷被映射到 Docker 主机中的一个目录，并且该目录以读写模式挂载。这个目录是由 Docker 引擎在容器启动时自动创建的。

到目前为止，我们已经看到了`Dockerfile`中`VOLUME`指令的含义，以及 Docker 如何管理数据卷。像`Dockerfile`中的`VOLUME`指令一样，我们可以使用`docker run`子命令的`-v <容器挂载点路径>`选项，如下面的命令所示：

```
$ sudo docker run –v /MountPointDemo -it ubuntu:14.04

```

启动容器后，我们鼓励您尝试在新启动的容器中使用`ls -ld /MountPointDemo`和`mount`命令，然后也像前面的步骤 5 中所示那样检查容器。

在这里描述的两种情况中，Docker 引擎会自动在`/var/lib/docker/vfs/`目录下创建目录，并将其挂载到容器中。当使用`docker rm`子命令删除容器时，Docker 引擎不会删除在容器启动时自动创建的目录。这种行为本质上是为了保留存储在目录中的容器应用程序的状态。如果您想删除 Docker 引擎自动创建的目录，可以在删除容器时使用`docker rm`子命令提供`-v`选项来执行，前提是容器已经停止：

```
$ sudo docker rm -v 8d22f73b5b46

```

如果容器仍在运行，则可以通过在上一个命令中添加`-f`选项来删除容器以及自动生成的目录：

```
$ sudo docker rm -fv 8d22f73b5b46

```

我们已经介绍了在 Docker 主机中自动生成目录并将其挂载到容器数据卷的技术和提示。然而，使用`docker run`子命令的`-v`选项可以将用户定义的目录挂载到数据卷。在这种情况下，Docker 引擎不会自动生成任何目录。

### 注意

系统生成的目录存在目录泄漏的问题。换句话说，如果您忘记删除系统生成的目录，可能会遇到一些不必要的问题。有关更多信息，您可以阅读本章节中的*避免常见陷阱*部分。

# 共享主机数据

之前，我们描述了在 Docker 镜像中使用`Dockerfile`中的`VOLUME`指令创建数据卷的步骤。然而，Docker 没有提供任何机制在构建时挂载主机目录或文件，以确保 Docker 镜像的可移植性。Docker 提供的唯一规定是在容器启动时将主机目录或文件挂载到容器的数据卷上。Docker 通过`docker run`子命令的`-v`选项公开主机目录或文件挂载功能。`-v`选项有三种不同的格式，如下所列：

1.  -v <容器挂载路径>

1.  `-v <host path>/<container mount path>`

1.  `-v <host path>/<container mount path>:<read write mode>`

`<host path>`是 Docker 主机上的绝对路径，`<container mount path>`是容器文件系统中的绝对路径，`<read write mode>`可以是只读（`ro`）或读写（`rw`）模式。第一个`-v <container mount path>`格式已经在本章的*数据卷*部分中解释过，作为在容器启动时创建挂载点的方法。第二和第三个选项使我们能够将 Docker 主机上的文件或目录挂载到容器的挂载点。

我们希望通过几个例子深入了解主机数据共享。在第一个例子中，我们将演示如何在 Docker 主机和容器之间共享一个目录，在第二个例子中，我们将演示文件共享。

在第一个例子中，我们将一个目录从 Docker 主机挂载到一个容器中，在容器上执行一些基本的文件操作，并从 Docker 主机验证这些操作，详细步骤如下：

1.  首先，让我们使用`docker run`子命令的`-v`选项启动一个交互式容器，将 Docker 主机目录`/tmp/hostdir`挂载到容器的`/MountPoint`：

```
$ sudo docker run -v /tmp/hostdir:/MountPoint \
 -it ubuntu:14.04

```

### 注意

如果在 Docker 主机上找不到`/tmp/hostdir`，Docker 引擎将自行创建该目录。然而，问题在于系统生成的目录无法使用`docker rm`子命令的`-v`选项删除。

1.  成功启动容器后，我们可以使用`ls`命令检查`/MountPoint`的存在：

```
root@4a018d99c133:/# ls -ld /MountPoint
drwxr-xr-x 2 root root 4096 Nov 23 18:28 /MountPoint

```

1.  现在，我们可以继续使用`mount`命令检查挂载细节：

```
root@4a018d99c133:/# mount
... TRUNCATED OUTPUT ...
/dev/disk/by-uuid/721cedbd-57b1-4bbd-9488-ec3930862cf5 on /MountPoint type ext3 (rw,noatime,nobarrier,errors=remount-ro,data=ordered)
... TRUNCATED OUTPUT ...

```

1.  在这里，我们将验证`/MountPoint`，使用`cd`命令切换到`/MountPoint`目录，使用`touch`命令创建一些文件，并使用`ls`命令列出文件，如下脚本所示：

```
root@4a018d99c133:/# cd /MountPoint/
root@4a018d99c133:/MountPoint# touch {a,b,c}
root@4a018d99c133:/MountPoint# ls -l
total 0
-rw-r--r-- 1 root root 0 Nov 23 18:39 a
-rw-r--r-- 1 root root 0 Nov 23 18:39 b
-rw-r--r-- 1 root root 0 Nov 23 18:39 c

```

1.  可能值得努力使用新终端上的`ls`命令验证`/tmp/hostdir` Docker 主机目录中的文件，因为我们的容器正在现有终端上以交互模式运行：

```
$ sudo  ls -l /tmp/hostdir/
total 0
-rw-r--r-- 1 root root 0 Nov 23 12:39 a
-rw-r--r-- 1 root root 0 Nov 23 12:39 b
-rw-r--r-- 1 root root 0 Nov 23 12:39 c

```

在这里，我们可以看到与第 4 步中相同的一组文件。但是，您可能已经注意到文件的时间戳有所不同。这种时间差异是由于 Docker 主机和容器之间的时区差异造成的。

1.  最后，让我们运行`docker inspect`子命令，以容器 ID`4a018d99c133`作为参数，查看 Docker 主机和容器挂载点之间是否设置了目录映射，如下命令所示：

```
$ sudo docker inspect \
 --format={{.Volumes}} 4a018d99c133
map[/MountPoint:/tmp/hostdir]

```

显然，在`docker inspect`子命令的先前输出中，Docker 主机的`/tmp/hostdir`目录被挂载到容器的`/MountPoint`挂载点上。

对于第二个示例，我们可以将文件从 Docker 主机挂载到容器中，从容器中更新文件，并从 Docker 主机验证这些操作，详细步骤如下：

1.  为了将文件从 Docker 主机挂载到容器中，文件必须在 Docker 主机上预先存在。否则，Docker 引擎将创建一个具有指定名称的新目录，并将其挂载为目录。我们可以通过使用`touch`命令在 Docker 主机上创建一个文件来开始：

```
$ touch /tmp/hostfile.txt

```

1.  使用`docker run`子命令的`-v`选项启动交互式容器，将`/tmp/hostfile.txt` Docker 主机文件挂载到容器上，作为`/tmp/mntfile.txt`：

```
$ sudo docker run -v /tmp/hostfile.txt:/mountedfile.txt \
 -it ubuntu:14.04

```

1.  成功启动容器后，现在让我们使用`ls`命令检查`/mountedfile.txt`的存在：

```
root@d23a15527eeb:/# ls -l /mountedfile.txt
-rw-rw-r-- 1 1000 1000 0 Nov 23 19:33 /mountedfile.txt

```

1.  然后，继续使用`mount`命令检查挂载细节：

```
root@d23a15527eeb:/# mount
... TRUNCATED OUTPUT ...
/dev/disk/by-uuid/721cedbd-57b1-4bbd-9488-ec3930862cf5 on /mountedfile.txt type ext3 (rw,noatime,nobarrier,errors=remount-ro,data=ordered)
... TRUNCATED OUTPUT ...

```

1.  然后，使用`echo`命令更新`/mountedfile.txt`中的一些文本：

```
root@d23a15527eeb:/# echo "Writing from Container" \
 > mountedfile.txt

```

1.  同时，在 Docker 主机中切换到另一个终端，并使用`cat`命令打印`/tmp/hostfile.txt` Docker 主机文件：

```
$ cat /tmp/hostfile.txt
Writing from Container

```

1.  最后，运行`docker inspect`子命令，以容器 ID`d23a15527eeb`作为参数，查看 Docker 主机和容器挂载点之间的文件映射：

```
$ sudo docker inspect \
 --format={{.Volumes}} d23a15527eeb
map[/mountedfile.txt:/tmp/hostfile.txt]

```

从前面的输出可以看出，来自 Docker 主机的`/tmp/hostfile.txt`文件被挂载为容器内的`/mountedfile.txt`。

### 注意

在 Docker 主机和容器之间共享文件的情况下，文件必须在启动容器之前存在。然而，在目录共享的情况下，如果 Docker 主机中不存在该目录，则 Docker 引擎会在 Docker 主机中创建一个新目录，如前面所述。

## 主机数据共享的实用性

在上一章中，我们在 Docker 容器中启动了一个`HTTP`服务。然而，如果你记得正确的话，`HTTP`服务的日志文件仍然在容器内，无法直接从 Docker 主机访问。在这里，在本节中，我们逐步阐述了从 Docker 主机访问日志文件的过程：

1.  让我们开始启动一个 Apache2 HTTP 服务容器，将 Docker 主机的`/var/log/myhttpd`目录挂载到容器的`/var/log/apache2`目录，使用`docker run`子命令的`-v`选项。在这个例子中，我们正在利用我们在上一章中构建的`apache2`镜像，通过调用以下命令：

```
$ sudo docker run -d -p 80:80 \
 -v /var/log/myhttpd:/var/log/apache2 apache2
9c2f0c0b126f21887efaa35a1432ba7092b69e0c6d523ffd50684e27eeab37ac

```

如果你还记得第六章中的`Dockerfile`，*在容器中运行服务*，`APACHE_LOG_DIR`环境变量被设置为`/var/log/apache2`目录，使用`ENV`指令。这将使 Apache2 HTTP 服务将所有日志消息路由到`/var/log/apache2`数据卷。

1.  容器启动后，我们可以在 Docker 主机上切换到`/var/log/myhttpd`目录：

```
$ cd /var/log/myhttpd

```

1.  也许，在这里适当地快速检查`/var/log/myhttpd`目录中存在的文件：

```
$ ls -1
access.log
error.log
other_vhosts_access.log

```

在这里，`access.log`包含了 Apache2 HTTP 服务器处理的所有访问请求。`error.log`是一个非常重要的日志文件，我们的 HTTP 服务器在处理任何 HTTP 请求时记录遇到的错误。`other_vhosts_access.log`文件是虚拟主机日志，在我们的情况下始终为空。

1.  我们可以使用`tail`命令和`-f`选项显示`/var/log/myhttpd`目录中所有日志文件的内容：

```
$ tail -f *.log
==> access.log <==

==> error.log <==
AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 172.17.0.17\. Set the 'ServerName' directive globally to suppress this message
[Thu Nov 20 17:45:35.619648 2014] [mpm_event:notice] [pid 16:tid 140572055459712] AH00489: Apache/2.4.7 (Ubuntu) configured -- resuming normal operations
[Thu Nov 20 17:45:35.619877 2014] [core:notice] [pid 16:tid 140572055459712] AH00094: Command line: '/usr/sbin/apache2 -D FOREGROUND'
==> other_vhosts_access.log <==

```

`tail -f` 命令将持续运行并显示文件的内容，一旦它们被更新。在这里，`access.log` 和 `other_vhosts_access.log` 都是空的，并且 `error.log` 文件上有一些错误消息。显然，这些错误日志是由容器内运行的 HTTP 服务生成的。然后，这些日志被储存在 Docker 主机目录中，在容器启动时被挂载。

1.  当我们继续运行 `tail –f *` 时，让我们从容器内运行的 Web 浏览器连接到 HTTP 服务，并观察日志文件：

```
==> access.log <==
111.111.172.18 - - [20/Nov/2014:17:53:38 +0000] "GET / HTTP/1.1" 200 3594 "-" "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.65 Safari/537.36"
111.111.172.18 - - [20/Nov/2014:17:53:39 +0000] "GET /icons/ubuntu-logo.png HTTP/1.1" 200 3688 "http://111.71.123.110/" "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.65 Safari/537.36"
111.111.172.18 - - [20/Nov/2014:17:54:21 +0000] "GET /favicon.ico HTTP/1.1" 404 504 "-" "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.65 Safari/537.36"

```

HTTP 服务更新 `access.log` 文件，我们可以通过 `docker run` 子命令的 `–v` 选项挂载的主机目录进行操作。

# 在容器之间共享数据

在前面的部分中，我们了解了 Docker 引擎如何在 Docker 主机和容器之间无缝地实现数据共享。尽管这是一个非常有效的解决方案，但它将容器紧密耦合到主机文件系统。这些目录可能会留下不好的印记，因为用户必须在它们的目的达到后手动删除它们。因此，Docker 解决这个问题的建议是创建数据专用容器作为基础容器，然后使用 `docker run` 子命令的 `--volume-from` 选项将该容器的数据卷挂载到其他容器。

## 数据专用容器

数据专用容器的主要责任是保存数据。创建数据专用容器与数据卷部分所示的方法非常相似。此外，容器被明确命名，以便其他容器使用容器的名称挂载数据卷。即使数据专用容器处于停止状态，其他容器也可以访问数据专用容器的数据卷。数据专用容器可以通过以下两种方式创建：

+   在容器启动时通过配置数据卷和容器名称。

+   数据卷也可以在构建镜像时通过 `Dockerfile` 进行编写，然后在容器启动时命名容器。

在以下示例中，我们通过配置 `docker run` 子命令的 `–v` 和 `--name` 选项来启动一个数据专用容器，如下所示：

```
$ sudo docker run --name datavol \
 -v /DataMount \
 busybox:latest /bin/true

```

在这里，容器是从`busybox`镜像启动的，该镜像因其较小的占用空间而被广泛使用。在这里，我们选择执行`/bin/true`命令，因为我们不打算对容器进行任何操作。因此，我们使用`--name`选项命名了容器`datavol`，并使用`docker run`子命令的`-v`选项创建了一个新的`/DataMount`数据卷。`/bin/true`命令立即以退出状态`0`退出，这将停止容器并继续停留在停止状态。

## 从其他容器挂载数据卷

Docker 引擎提供了一个巧妙的接口，可以将一个容器的数据卷挂载（共享）到另一个容器。Docker 通过`docker run`子命令的`--volumes-from`选项提供了这个接口。`--volumes-from`选项以容器名称或容器 ID 作为输入，并自动挂载指定容器上的所有数据卷。Docker 允许您多次使用`--volumes-from`选项来挂载多个容器的数据卷。

这是一个实际的示例，演示了如何从另一个容器挂载数据卷，并逐步展示数据卷挂载过程。

1.  我们首先启动一个交互式 Ubuntu 容器，通过挂载数据专用容器（`datavol`）中的数据卷来进行操作，如前述所述：

```
$ sudo docker run –it \
 --volumes-from datavol \
 ubuntu:latest /bin/bash

```

1.  现在从容器的提示符中，让我们使用`mount`命令验证数据卷挂载：

```
root@e09979cacec8:/# mount
. . . TRUNCATED OUTPUT . . .
/dev/disk/by-uuid/32a56fe0-7053-4901-ae7e-24afe5942e91 on /DataMount type ext3 (rw,noatime,nobarrier,errors=remount-ro,data=ordered)
. . . TRUNCATED OUTPUT . . .

```

在这里，我们成功地从`datavol`数据专用容器中挂载了数据卷。

1.  接下来，我们需要使用`docker inspect`子命令从另一个终端检查该容器的数据卷：

```
$ sudo docker inspect  e09979cacec8
. . . TRUNCATED OUTPUT . . .
 "Volumes": {
 "/DataMount": "/var/lib/docker/vfs/dir/62f5a3314999e5aaf485fc692ae07b3cbfacbca9815d8071f519c1a836c0f01e"
},
 "VolumesRW": {
 "/DataMount": true
 }
}

```

显然，来自`datavol`数据专用容器的数据卷被挂载，就好像它们直接挂载到了这个容器上一样。

我们可以从另一个容器挂载数据卷，并展示挂载点。我们可以通过使用数据卷在容器之间共享数据来使挂载的数据卷工作，如下所示：

1.  让我们重用在上一个示例中启动的容器，并通过向数据卷`/DataMount`写入一些文本来创建一个`/DataMount/testfile`文件，如下所示：

```
root@e09979cacec8:/# echo \
 "Data Sharing between Container" > \
 /DataMount/testfile

```

1.  只需将一个容器分离出来，以显示我们在上一步中编写的文本，使用`cat`命令：

```
$ sudo docker run --rm \
 --volumes-from datavol \
 busybox:latest cat /DataMount/testfile

```

以下是前述命令的典型输出：

```
Data Sharing between Container

```

显然，我们新容器化的`cat`命令的前面输出`容器之间的数据共享`是我们在步骤 1 中写入`/DataMount/testfile`的`datavol`容器中的文本。

很酷，不是吗？您可以通过共享数据卷在容器之间无缝共享数据。在这个例子中，我们使用数据专用容器作为数据共享的基础容器。然而，Docker 允许我们共享任何类型的数据卷，并且可以依次挂载数据卷，如下所示：

```
$ sudo docker run --name vol1 --volumes-from datavol \
 busybox:latest /bin/true
$ sudo docker run --name vol2 --volumes-from vol1 \
 busybox:latest /bin/true

```

在这里，在`vol1`容器中，我们可以挂载来自`datavol`容器的数据卷。然后，在`vol2`容器中，我们挂载了来自`vol1`容器的数据卷，这些数据卷最初来自`datavol`容器。

## 容器之间数据共享的实用性

在本章的前面，我们学习了从 Docker 主机访问 Apache2 HTTP 服务的日志文件的机制。虽然通过将 Docker 主机目录挂载到容器中方便地共享数据，但后来我们意识到可以通过仅使用数据卷在容器之间共享数据。因此，在这里，我们通过在容器之间共享数据来改变 Apache2 HTTP 服务日志处理的方法。为了在容器之间共享日志文件，我们将按照以下步骤启动以下容器：

1.  首先，一个仅用于数据的容器，将向其他容器公开数据卷。

1.  然后，一个利用数据专用容器的数据卷的 Apache2 HTTP 服务容器。

1.  一个用于查看我们 Apache2 HTTP 服务生成的日志文件的容器。

### 注意

注意：如果您在 Docker 主机机器的端口号`80`上运行任何 HTTP 服务，请为以下示例选择任何其他未使用的端口号。如果没有，请先停止 HTTP 服务，然后按照示例进行操作，以避免任何端口冲突。

现在，我们将逐步为您介绍如何制作相应的镜像并启动容器以查看日志文件，如下所示：

1.  在这里，我们首先使用`VOLUME`指令使用`/var/log/apache2`数据卷来制作`Dockerfile`。`/var/log/apache2`数据卷是对`Dockerfile`中第六章中设置的环境变量`APACHE_LOG_DIR`的直接映射，使用`ENV`指令：

```
#######################################################
# Dockerfile to build a LOG Volume for Apache2 Service
#######################################################
# Base image is BusyBox
FROM busybox:latest
# Author: Dr. Peter
MAINTAINER Dr. Peter <peterindia@gmail.com>
# Create a data volume at /var/log/apache2, which is
# same as the log directory PATH set for the apache image
VOLUME /var/log/apache2
# Execute command true
CMD ["/bin/true"]
```

由于这个`Dockerfile`是用来启动数据仅容器的，所以默认的执行命令被设置为`/bin/true`。

1.  我们将继续使用`docker build`从上述`Dockerfile`构建一个名为`apache2log`的 Docker 镜像，如下所示：

```
$ sudo docker build -t apache2log .
Sending build context to Docker daemon  2.56 kB
Sending build context to Docker daemon
Step 0 : FROM busybox:latest
... TRUNCATED OUTPUT ...

```

1.  使用`docker run`子命令从`apache2log`镜像启动一个仅数据的容器，并将生成的容器命名为`log_vol`，使用`--name`选项：

```
$ sudo docker run --name log_vol apache2log

```

根据上述命令，容器将在`/var/log/apache2`中创建一个数据卷并将其移至停止状态。

1.  与此同时，您可以使用`-a`选项运行`docker ps`子命令来验证容器的状态：

```
$ sudo docker ps -a
CONTAINER ID        IMAGE               COMMAND                CREATED             STATUS                      PORTS                NAMES
40332e5fa0ae        apache2log:latest   "/bin/true"            2 minutes ago      Exited (0) 2 minutes ago                        log_vol

```

根据输出，容器以退出值`0`退出。

1.  使用`docker run`子命令启动 Apache2 HTTP 服务。在这里，我们重用了我们在第六章中制作的`apache2`镜像，*在容器中运行服务*。在这个容器中，我们将使用`--volumes-from`选项从我们在第 3 步中启动的数据仅容器`log_vol`挂载`/var/log/apache2`数据卷：

```
$ sudo docker run -d -p 80:80 \
 --volumes-from log_vol \
 apache2
7dfbf87e341c320a12c1baae14bff2840e64afcd082dda3094e7cb0a0023cf42

```

成功启动了从`log_vol`挂载的`/var/log/apache2`数据卷的 Apache2 HTTP 服务后，我们可以使用临时容器访问日志文件。

1.  在这里，我们使用临时容器列出了 Apache2 HTTP 服务存储的文件。这个临时容器是通过从`log_vol`挂载`/var/log/apache2`数据卷而产生的，并且使用`ls`命令列出了`/var/log/apache2`中的文件。此外，`docker run`子命令的`--rm`选项用于在执行完`ls`命令后删除容器：

```
$  sudo docker run --rm \
 --volumes-from log_vol
 busybox:latest ls -l /var/log/apache2
total 4
-rw-r--r--    1 root     root             0 Dec  5 15:27 access.log
-rw-r--r--    1 root     root           461 Dec  5 15:27 error.log
-rw-r--r--    1 root     root             0 Dec  5 15:27 other_vhosts_access.log

```

1.  最后，通过使用`tail`命令访问 Apache2 HTTP 服务生成的错误日志，如下命令所示：

```
$ sudo docker run  --rm  \
 --volumes-from log_vol \
 ubuntu:14.04 \
 tail /var/log/apache2/error.log
AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 172.17.0.24\. Set the 'ServerName' directive globally to suppress this message
[Fri Dec 05 17:28:12.358034 2014] [mpm_event:notice] [pid 18:tid 140689145714560] AH00489: Apache/2.4.7 (Ubuntu) configured -- resuming normal operations
[Fri Dec 05 17:28:12.358306 2014] [core:notice] [pid 18:tid 140689145714560] AH00094: Command line: '/usr/sbin/apache2 -D FOREGROUND'

```

# 避免常见陷阱

到目前为止，我们讨论了如何有效地使用数据卷在 Docker 主机和容器之间以及容器之间共享数据。使用数据卷进行数据共享正在成为 Docker 范式中非常强大和必不可少的工具。然而，它确实存在一些需要仔细识别和消除的缺陷。在本节中，我们尝试列出与数据共享相关的一些常见问题以及克服这些问题的方法和手段。

## 目录泄漏

在数据卷部分，我们了解到 Docker 引擎会根据`Dockerfile`中的`VOLUME`指令以及`docker run`子命令的`-v`选项自动创建目录。我们也明白 Docker 引擎不会自动删除这些自动生成的目录，以保留容器内运行的应用程序的状态。我们可以使用`docker rm`子命令的`-v`选项强制 Docker 删除这些目录。手动删除的过程会带来以下两个主要挑战：

1.  **未删除的目录：** 可能会出现这样的情况，您可能有意或无意地选择不删除生成的目录，而删除容器。

1.  **第三方镜像：** 我们经常利用第三方 Docker 镜像，这些镜像可能已经使用了`VOLUME`指令进行构建。同样，我们可能也有自己的 Docker 镜像，其中包含了`VOLUME`。当我们使用这些 Docker 镜像启动容器时，Docker 引擎将自动生成指定的目录。由于我们不知道数据卷的创建，我们可能不会使用`-v`选项调用`docker rm`子命令来删除自动生成的目录。

在前面提到的情况中，一旦相关的容器被移除，就没有直接的方法来识别那些容器被移除的目录。以下是一些建议，可以避免这种问题：

+   始终使用`docker inspect`子命令检查 Docker 镜像，查看镜像中是否有数据卷。

+   始终使用`docker rm`子命令的`-v`选项来删除为容器创建的任何数据卷（目录）。即使数据卷被多个容器共享，仍然可以安全地使用`docker rm`子命令的`-v`选项，因为只有当共享该数据卷的最后一个容器被移除时，与数据卷关联的目录才会被删除。

+   无论出于何种原因，如果您选择保留自动生成的目录，您必须保留清晰的记录，以便以后可以删除它们。

+   实施一个审计框架，用于审计并找出没有任何容器关联的目录。

## 数据卷的不良影响

如前所述，Docker 允许我们在构建时使用`VOLUME`指令将数据卷刻录到 Docker 镜像中。然而，在构建过程中不应该使用数据卷来存储任何数据，否则会产生不良影响。

在本节中，我们将通过制作一个`Dockerfile`来演示在构建过程中使用数据卷的不良影响，然后通过构建这个`Dockerfile`来展示其影响：

以下是`Dockerfile`的详细信息：

1.  使用`Ubuntu 14.04`作为基础镜像构建镜像：

```
# Use Ubuntu as the base image
FROM ubuntu:14.04
```

1.  使用`VOLUME`指令创建一个`/MountPointDemo`数据卷：

```
VOLUME /MountPointDemo
```

1.  使用`RUN`指令在`/MountPointDemo`数据卷中创建一个文件：

```
RUN date > /MountPointDemo/date.txt
```

1.  使用`RUN`指令显示`/MountPointDemo`数据卷中的文件：

```
RUN cat /MountPointDemo/date.txt
```

继续使用`docker build`子命令从这个`Dockerfile`构建一个镜像，如下所示：

```
$ sudo docker build -t testvol .
Sending build context to Docker daemon  2.56 kB
Sending build context to Docker daemon
Step 0 : FROM ubuntu:14.04
 ---> 9bd07e480c5b
Step 1 : VOLUME /MountPointDemo
 ---> Using cache
 ---> e8b1799d4969
Step 2 : RUN date > /MountPointDemo/date.txt
 ---> Using cache
 ---> 8267e251a984
Step 3 : RUN cat /MountPointDemo/date.txt
 ---> Running in a3e40444de2e
cat: /MountPointDemo/date.txt: No such file or directory
2014/12/07 11:32:36 The command [/bin/sh -c cat /MountPointDemo/date.txt] returned a non-zero code: 1

```

在`docker build`子命令的先前输出中，您会注意到构建在第 3 步失败，因为它找不到在第 2 步创建的文件。显然，在第 3 步时创建的文件在第 2 步时消失了。这种不良影响是由 Docker 构建其镜像的方法造成的。了解 Docker 镜像构建过程将揭开这个谜团。

在构建过程中，对于`Dockerfile`中的每个指令，按照以下步骤进行：

1.  通过将`Dockerfile`指令转换为等效的`docker run`子命令来创建一个新的容器

1.  将新创建的容器提交为镜像

1.  通过将新创建的镜像视为第 1 步的基础镜像，重复执行第 1 步和第 2 步。

当容器被提交时，它保存容器的文件系统，并故意不保存数据卷的文件系统。因此，在此过程中存储在数据卷中的任何数据都将丢失。因此，在构建过程中永远不要使用数据卷作为存储。

# 总结

对于企业规模的分布式应用来说，数据是其运营和产出中最重要的工具和成分。通过 IT 容器化，这个旅程以迅速和明亮的方式开始。通过巧妙利用 Docker 引擎，IT 和业务软件解决方案都被智能地容器化。然而，最初的动机是更快速、无缺陷地实现应用感知的 Docker 容器，因此，数据与容器内的应用紧密耦合。然而，这种紧密性带来了一些真正的风险。如果应用程序崩溃，那么数据也会丢失。此外，多个应用程序可能依赖于相同的数据，因此数据必须进行共享。

在本章中，我们讨论了 Docker 引擎在促进 Docker 主机和容器之间以及容器之间无缝数据共享方面的能力。数据卷被规定为实现不断增长的 Docker 生态系统中各组成部分之间数据共享的基础构件。在下一章中，我们将解释容器编排背后的概念，并看看如何通过一些自动化工具简化这个复杂的方面。编排对于实现复合容器至关重要。


# 第八章：容器编排

在早期的章节中，我们为容器网络的需求奠定了坚实的基础，以及如何在 Docker 容器内运行服务，以及如何通过打开网络端口和其他先决条件来将此服务暴露给外部世界。然而，最近，已经提供了先进的机制，并且一些第三方编排平台进入市场，以明智地建立分布式和不同功能的容器之间的动态和决定性联系，以便为全面但紧凑地包含面向过程、多层和企业级分布式应用程序组合强大的容器。在这个极其多样化但相互连接的世界中，编排的概念不能长期远离其应有的突出地位。本章专门用于解释容器编排的细枝末节，以及它在挑选离散容器并系统地组合成更直接符合不同业务期望和迫切需求的复杂容器方面的直接作用。

在本章中，我们将讨论以下主题的相关细节：

+   链接容器

+   编排容器

+   使用`docker-compose`工具进行容器编排

随着关键任务的应用程序主要是通过松散耦合但高度内聚的组件/服务构建，旨在在地理分布的 IT 基础设施和平台上运行，组合的概念受到了很多关注和吸引力。为了维持良好的容器化旅程，容器的编排被认为是在即时、自适应和智能的 IT 时代中最关键和至关重要的要求之一。有一些经过验证和有前途的方法和符合标准的工具，可以实现神秘的编排目标。

# 链接容器

Docker 技术的一个显著特点之一是链接容器。也就是说，合作容器可以链接在一起，提供复杂和业务感知的服务。链接的容器具有一种源-接收关系，其中源容器链接到接收容器，并且接收容器安全地从源容器接收各种信息。但是，源容器对其链接的接收者一无所知。链接容器的另一个值得注意的特性是，在安全设置中，链接的容器可以使用安全隧道进行通信，而不会将用于设置的端口暴露给外部世界。

Docker 引擎在`docker run`子命令中提供了`--link`选项，以将源容器链接到接收容器。

`--link`选项的格式如下：

```
--link <container>:<alias>

```

在这里，`<container>`是源容器的名称，`<alias>`是接收容器看到的名称。容器的名称在 Docker 主机中必须是唯一的，而别名非常具体且局限于接收容器，因此别名不需要在 Docker 主机上是唯一的。这为在接收容器内部使用固定的源别名名称实现和整合功能提供了很大的灵活性。

当两个容器链接在一起时，Docker 引擎会自动向接收容器导出一些环境变量。这些环境变量具有明确定义的命名约定，其中变量始终以别名名称的大写形式作为前缀。例如，如果`src`是源容器的别名，则导出的环境变量将以`SRC_`开头。Docker 导出三类环境变量，如下所列：

1.  `名称`：这是环境变量的第一类。这个变量采用`<ALIAS>_NAME`的形式，并将接收容器的分层名称作为其值。例如，如果源容器的别名是`src`，接收容器的名称是`rec`，那么环境变量及其值将是`SRC_NAME=/rec/src`。

1.  `ENV`：这是环境变量的第二类。这些变量通过`docker run`子命令的`-e`选项或`Dockerfile`的`ENV`指令在源容器中配置的环境变量。这种类型的环境变量采用`<ALIAS>_ENV_<VAR_NAME>`的形式。例如，如果源容器的别名是`src`，变量名是`SAMPLE`，那么环境变量将是`SRC_ENV_SAMPLE`。

1.  `PORT`：这是最终的第三类环境变量，用于将源容器的连接详细信息导出给接收方。Docker 为源容器通过`docker run`子命令的`-p`选项或`Dockerfile`的`EXPOSE`指令暴露的每个端口创建一组变量。

这些变量采用以下形式：

```
*<ALIAS>_PORT_<port>_<protocol>

```

此形式用于共享源的 IP 地址、端口和协议作为 URL。例如，如果源容器的别名是`src`，暴露的端口是`8080`，协议是`tcp`，IP 地址是`172.17.0.2`，那么环境变量及其值将是`SRC_PORT_8080_TCP=tcp://172.17.0.2:8080`。此 URL 进一步分解为以下三个环境变量：

+   `<ALIAS>_PORT_<port>_<protocol>_ADDR`：此形式包含 URL 的 IP 地址部分（例如：`SRC_PORT_8080_TCP_ADDR= 172.17.0.2`）

+   `<ALIAS>_PORT_<port>_<protocol>_PORT`：此形式包含 URL 的端口部分（例如：`SRC_PORT_8080_TCP_PORT=8080`）

+   `<ALIAS>_PORT_<port>_<protocol>_PROTO`：此形式包含 URL 的协议部分（例如：`SRC_PORT_8080_TCP_PROTO=tcp`）

除了前述的环境变量之外，Docker 引擎还在此类别中导出了一个变量，即`<ALIAS>_PORT`的形式，其值将是源容器暴露的所有端口中最低的 URL。例如，如果源容器的别名是`src`，暴露的端口号是`7070`、`8080`和`80`，协议是`tcp`，IP 地址是`172.17.0.2`，那么环境变量及其值将是`SRC_PORT=tcp://172.17.0.2:80`。

Docker 以良好结构的格式导出这些自动生成的环境变量，以便可以轻松地通过程序发现。因此，接收容器可以很容易地发现有关源容器的信息。此外，Docker 会自动将源 IP 地址及其别名更新为接收容器的`/etc/hosts`文件中的条目。

在本章中，我们将通过一系列实用示例深入介绍 Docker 引擎提供的容器链接功能。

首先，让我们选择一个简单的容器链接示例。在这里，我们将向您展示如何在两个容器之间建立链接，并将一些基本信息从源容器传输到接收容器，如下所示的步骤：

1.  我们首先启动一个交互式容器，可以作为链接的源容器使用，使用以下命令：

```
$ sudo docker run --rm --name example -it busybox:latest

```

容器使用`--name`选项命名为`example`。此外，使用`--rm`选项在退出容器时清理容器。

1.  使用`cat`命令显示源容器的`/etc/hosts`条目：

```
/ # cat /etc/hosts
172.17.0.3      a02895551686
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

```

在这里，`/etc/hosts`文件中的第一个条目是源容器的 IP 地址（`172.17.0.3`）和其主机名（`a02895551686`）。

1.  我们将继续使用`env`命令显示源容器的环境变量：

```
/ # env
HOSTNAME=a02895551686
SHLVL=1
HOME=/root
TERM=xterm
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PWD=/

```

1.  启动源容器后，从相同 Docker 主机的另一个终端，让我们使用`docker run`子命令的`--link`选项启动一个交互式接收容器，将其链接到我们的源容器，如下所示：

```
$ sudo docker run --rm --link example:ex -it busybox:latest

```

在这里，名为`example`的源容器与接收容器链接，其别名为`ex`。

1.  让我们使用`cat`命令显示接收容器的`/etc/hosts`文件的内容：

```
/ # cat /etc/hosts
172.17.0.4      a17e5578b98e
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.17.0.3      ex

```

当然，像往常一样，`/etc/hosts`文件的第一个条目是容器的 IP 地址和其主机名。然而，`/etc/hosts`文件中值得注意的条目是最后一个条目，其中源容器的 IP 地址（`172.17.0.3`）和其别名（`ex`）会自动添加。

1.  我们将继续使用`env`命令显示接收容器的环境变量：

```
/ # env
HOSTNAME=a17e5578b98e
SHLVL=1
HOME=/root
EX_NAME=/berserk_mcclintock/ex
TERM=xterm
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PWD=/

```

显然，一个新的`EX_NAME`环境变量会自动添加到`/berserk_mcclintock/ex`，作为其值。这里`EX`是别名`ex`的大写形式，`berserk_mcclintock`是接收容器的自动生成名称。

1.  最后一步，使用广泛使用的`ping`命令对源容器进行两次 ping，并使用别名作为 ping 地址：

```
/ # ping -c 2 ex
PING ex (172.17.0.3): 56 data bytes
64 bytes from 172.17.0.3: seq=0 ttl=64 time=0.108 ms
64 bytes from 172.17.0.3: seq=1 ttl=64 time=0.079 ms

--- ex ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max = 0.079/0.093/0.108 ms

```

显然，源容器的别名`ex`被解析为 IP 地址`172.17.0.3`，并且接收容器能够成功到达源容器。在安全容器通信的情况下，容器之间是不允许 ping 的。我们在第十一章中对保护容器方面进行了更多详细说明，*保护 Docker 容器*。

在前面的示例中，我们可以将两个容器链接在一起，并且观察到源容器的 IP 地址如何优雅地更新到接收容器的`/etc/hosts`文件中，从而实现容器之间的网络连接。

下一个示例是演示容器链接如何导出源容器的环境变量，这些环境变量是使用`docker run`子命令的`-e`选项或`Dockerfile`的`ENV`指令配置的，然后导入到接收容器中。为此，我们将编写一个带有`ENV`指令的`Dockerfile`，构建一个镜像，使用该镜像启动一个源容器，然后通过链接到源容器来启动一个接收容器：

1.  我们首先编写一个带有`ENV`指令的`Dockerfile`，如下所示：

```
FROM busybox:latest
ENV BOOK="Learning Docker" \
    CHAPTER="Orchestrating Containers"
```

在这里，我们设置了两个环境变量`BOOK`和`CHAPTER`。

1.  继续使用前面的`Dockerfile`从头构建一个名为`envex`的 Docker 镜像：

```
$ sudo docker build -t envex .

```

1.  现在，让我们使用刚刚构建的`envex`镜像启动一个交互式源容器，名称为`example`：

```
$ sudo docker run -it --rm \
 --name example envex

```

1.  从源容器提示符中，通过调用`env`命令显示所有环境变量：

```
/ # env
HOSTNAME=b53bc036725c
SHLVL=1
HOME=/root
TERM=xterm
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
BOOK=Learning Docker
CHAPTER=Orchestrating Containers
PWD=/

```

在所有前述的环境变量中，`BOOK`和`CHAPTER`变量都是使用`Dockerfile`的`ENV`指令配置的。

1.  最后一步，为了说明环境变量的`ENV`类别，启动接收容器并使用`env`命令，如下所示：

```
$ sudo docker run --rm --link example:ex \
 busybox:latest env
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=a5e0c07fd643
TERM=xterm
EX_NAME=/stoic_hawking/ex
EX_ENV_BOOK=Learning Docker
EX_ENV_CHAPTER=Orchestrating Containers
HOME=/root

```

### 注意

该示例也可以在 GitHub 上找到：[`github.com/thedocker/learning-docker/blob/master/chap08/Dockerfile-Env`](https://github.com/thedocker/learning-docker/blob/master/chap08/Dockerfile-Env)。

引人注目的是，在前面的输出中，以`EX_`为前缀的变量是容器链接的结果。感兴趣的环境变量是`EX_ENV_BOOK`和`EX_ENV_CHAPTER`，它们最初是通过`Dockerfile`设置为`BOOK`和`CHAPTER`，但由于容器链接而修改为`EX_ENV_BOOK`和`EX_ENV_CHAPTER`。尽管环境变量名称被翻译，但存储在这些环境变量中的值保持不变。我们在前面的示例中已经讨论了`EX_NAME`变量名。

在前面的示例中，我们可以体验到 Docker 如何优雅而轻松地将源容器中的`ENV`类别变量导出到接收容器中。这些环境变量与源和接收完全解耦，因此一个容器中这些环境变量值的更改不会影响另一个容器。更准确地说，接收容器接收的值是在启动源容器时设置的值。在源容器启动后对这些环境变量值进行的任何更改都不会影响接收容器。接收容器的启动时间并不重要，因为这些值是从 JSON 文件中读取的。

在我们最后的容器链接示例中，我们将向您展示如何利用 Docker 功能来共享两个容器之间的连接详细信息。为了共享容器之间的连接详细信息，Docker 使用环境变量的`PORT`类别。以下是用于创建两个容器并共享它们之间连接详细信息的步骤：

1.  编写一个`Dockerfile`，使用`EXPOSE`指令来公开端口`80`和`8080`，如下所示：

```
FROM busybox:latest
EXPOSE 8080 80
```

1.  继续使用`docker build`子命令从刚刚创建的`Dockerfile`构建 Docker 镜像`portex`，运行以下命令：

```
$ sudo docker build -t portex .

```

1.  现在，让我们使用之前构建的镜像`portex`启动一个名为`example`的交互式源容器：

```
$ sudo docker run -it --rm \
 --name example portex

```

1.  现在我们已经启动了源容器，让我们继续在另一个终端上创建一个接收容器，并将其链接到源容器，然后调用`env`命令来显示所有环境变量，如下所示：

```
$ sudo docker run --rm --link example:ex \
 busybox:latest env
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=c378bb55e69c
TERM=xterm
EX_PORT=tcp://172.17.0.4:80
EX_PORT_80_TCP=tcp://172.17.0.4:80
EX_PORT_80_TCP_ADDR=172.17.0.4
EX_PORT_80_TCP_PORT=80
EX_PORT_80_TCP_PROTO=tcp
EX_PORT_8080_TCP=tcp://172.17.0.4:8080
EX_PORT_8080_TCP_ADDR=172.17.0.4
EX_PORT_8080_TCP_PORT=8080
EX_PORT_8080_TCP_PROTO=tcp
EX_NAME=/prickly_rosalind/ex
HOME=/root

```

### 注意

这个示例也可以在 GitHub 上找到：[`github.com/thedocker/learning-docker/blob/master/chap08/Dockerfile-Expose`](https://github.com/thedocker/learning-docker/blob/master/chap08/Dockerfile-Expose)。

从`env`命令的前面输出可以很明显地看出，Docker 引擎为每个使用`Dockerfile`中的`EXPOSE`指令暴露的端口导出了一组四个`PORT`类别的环境变量。此外，Docker 还导出了另一个`PORT`类别的变量`EX_PORT`。

# 容器的编排

IT 领域中编排的开创性概念已经存在很长时间了。例如，在**服务计算**（**SC**）领域，服务编排的概念以前所未有的方式蓬勃发展，以生产和维护高度健壮和有弹性的服务。离散或原子服务除非按特定顺序组合在一起以获得具有过程感知的复合服务，否则不会起到实质作用。由于编排服务在表达和展示企业独特能力方面更具战略优势，可以以可识别/可发现、可互操作、可用和可组合的服务形式向外界展示；企业对拥有一个易于搜索的服务库（原子和复合）表现出了极大的兴趣。反过来，这个库使企业能够实现大规模的数据和过程密集型应用。很明显，服务的多样性对于组织的增长和发展非常关键。这个日益受到强制要求的需求通过经过验证和有前途的编排能力得到了解决，具有认知能力。

现在，随着我们迅速向容器化的 IT 环境迈进；应用程序和数据容器应该被巧妙地组合起来，以实现一系列新一代软件服务。

然而，要生成高度有效的编排容器，需要精心选择并按正确顺序启动特定目的和不可知目的的容器，以创建编排容器。顺序可以来自过程（控制和数据）流程图。手动完成这一复杂而艰巨的活动引发了一系列怀疑和批评。幸运的是，在 Docker 领域有编排工具可以帮助构建、运行和管理多个容器，以构建企业级服务。Docker 公司负责生产和推广 Docker 启发的容器的生成和组装，推出了一种标准化和简化的编排工具（名为`docker-compose`），以减轻开发人员和系统管理员的工作负担。

服务计算范式的成熟组合技术正在这里复制到激烈的容器化范式中，以实现容器化最初设想的好处，特别是构建功能强大的应用程序感知容器。

微服务架构是一种旨在通过将其功能分解为一组离散服务的架构概念，以解耦软件解决方案的方法。这是通过在架构层面应用标准原则来实现的。微服务架构正在逐渐成为设计和构建大规模 IT 和业务系统的主导方式。它不仅有助于松散和轻量级耦合和软件模块化，而且对于敏捷世界的持续集成和部署也是一个福音。对应用程序的任何更改都意味着必须进行大规模的更改。这一直是持续部署方面的一大障碍。微服务旨在解决这种情况，因此，微服务架构需要轻量级机制、小型、可独立部署的服务，并确保可扩展性和可移植性。这些要求可以通过 Docker 赞助的容器来满足。

微服务是围绕业务能力构建的，并且可以通过完全自动化的部署机制独立部署。每个微服务都可以在不中断其他微服务的情况下部署，容器为这些服务提供了理想的部署和执行环境，以及其他值得注意的设施，如减少部署时间、隔离管理和简单的生命周期。在容器内快速部署新版本的服务非常容易。所有这些因素导致了使用 Docker 提供的功能爆炸般的微服务增长。

正如所解释的，Docker 被提出作为下一代容器化技术，它提供了一种经过验证且潜在有效的机制，以高效和分布式的方式分发应用程序。美妙之处在于开发人员可以在容器内调整应用程序的部分，同时保持容器的整体完整性。这对于当前的趋势有着更大的影响，即公司正在构建更小、自定义、易于管理和离散的服务，以包含在标准化和自动化的容器内，而不是托管在单个物理或虚拟服务器上的大型单片应用程序。简而言之，来自 Docker 的狂热容器化技术已成为即将到来的微服务时代的福音。

Docker 的建立和持续发展是为了实现“运行一次，到处运行”的难以捉摸的目标。Docker 容器通常在进程级别上进行隔离，在 IT 环境中可移植，并且易于重复。单个物理主机可以托管多个容器，因此，每个 IT 环境通常都充斥着各种 Docker 容器。容器的空前增长意味着有效的容器管理存在问题。容器的多样性和相关的异质性被用来大幅增加容器管理的复杂性。因此，编排技术和蓬勃发展的编排工具已成为加速容器化旅程的战略安慰，使其安全地前行。

编排跨越包含微服务的多个容器的应用程序已经成为 Docker 世界的一个重要部分，通过项目，如 Google 的 Kubernetes 或 Flocker。 Decking 是另一个选项，用于促进 Docker 容器的编排。 Docker 在这个领域的新提供是一套三个编排服务，旨在涵盖分布式应用程序的动态生命周期的所有方面，从应用程序开发到部署和维护。 Helios 是另一个 Docker 编排平台，用于在整个舰队中部署和管理容器。起初，`fig`是最受欢迎的容器编排工具。然而，在最近，处于提升 Docker 技术前沿的公司推出了一种先进的容器编排工具（`docker-compose`），以使开发人员在处理 Docker 容器时更加轻松，因为它们通过容器生命周期。

意识到对于下一代、业务关键和容器化工作负载具有容器编排能力的重要性后，Docker 公司收购了最初构想和具体化`fig`工具的公司。然后，Docker 公司适当地将该工具更名为`docker-compose`，并引入了大量增强功能，使该工具更加符合容器开发人员和运营团队的不断变化的期望。

这里是`docker-compose`的要点，它被定位为一种用于定义和运行复杂应用程序的未来和灵活的工具。使用`docker-compose`，您可以在单个文件中定义应用程序的组件（它们的容器、配置、链接、卷等），然后，您可以用一个命令启动所有内容，这样就可以使其运行起来。

这个工具通过提供一组内置工具来简化容器管理，以执行目前手动执行的许多工作。在本节中，我们提供了使用`docker-compose`执行容器编排的所有细节，以便拥有一系列下一代分布式应用程序。

## 使用 docker-compose 编排容器

在本节中，我们将讨论广泛使用的容器编排工具`docker-compose`。`docker-compose`工具是一个非常简单但功能强大的工具，旨在简化运行一组 Docker 容器。换句话说，`docker-compose`是一个编排框架，可以定义和控制多容器服务。

它使您能够创建一个快速和隔离的开发环境，以及在生产环境中编排多个 Docker 容器的能力。`docker-compose`工具在内部利用 Docker 引擎来拉取镜像、构建镜像、按正确顺序启动容器，并根据`docker-compose.yml`文件中给定的定义在容器/服务之间进行正确的连接/链接。

## 安装 docker-compose

在撰写本书时，最新版本的`docker-compose`是 1.2.0，建议您将其与 Docker 1.3 或更高版本一起使用。您可以在 GitHub 位置([`github.com/docker/compose/releases/latest`](https://github.com/docker/compose/releases/latest))找到最新的官方发布的`docker-compose`。

`docker-compose`版本 1.2.0 的 Linux x86-64 二进制文件可在[`github.com/docker/compose/releases/download/1.2.0/docker-compose-Linux-x86_64`](https://github.com/docker/compose/releases/download/1.2.0/docker-compose-Linux-x86_64)下载，您可以直接使用`wget`工具或`curl`工具进行安装，如下所示：

+   使用`wget`工具：

```
$ sudo sh -c 'wget -qO-       https://github.com/docker/compose/releases/download/1.2.0/docker-compose-'uname -s'-'uname -m' >  /usr/local/bin/docker-compose; chmod +x /usr/local/bin/docker-compose'

```

+   使用`curl`工具：

```
$ sudo sh -c 'curl  -sSL  https://github.com/docker/compose/releases/download/1.2.0/docker-compose-'uname -s'-'uname -m' >  /usr/local/bin/docker-compose; chmod +x /usr/local/bin/docker-compose'

```

另外，`docker-compose`也作为一个 Python 包可用，您可以使用`pip`安装程序进行安装，如下所示：

```
$ sudo pip install -U docker-compose

```

### 注意

请注意，如果系统上未安装`pip`，请在安装`docker-compose`之前安装`pip`包。

成功安装`docker-compose`后，您可以检查`docker-compose`的版本，如下所示：

```
$ docker-compose --version
docker-compose 1.2.0

```

## docker-compose.yml 文件

`docker-compose`工具使用`docker-compose.yml`文件编排容器，在其中可以定义需要创建的服务、这些服务之间的关系以及它们的运行时属性。`docker-compose.yml`文件是**YAML Ain't Markup Language**（**YAML**）格式文件，这是一种人类友好的数据序列化格式。默认的`docker-compose`文件是`docker-compose.yml`，可以使用`docker-compose`工具的`-f`选项进行更改。以下是`docker-compose.yml`文件的格式：

```
<service>:
   <key>: <value>
   <key>:
       - <value>
       - <value>
```

在这里，`<service>`是服务的名称。您可以在单个`docker-compose.yml`文件中有多个服务定义。服务名称后面应跟一个或多个键。但是，所有服务必须具有`image`或`build`键，后面可以跟任意数量的可选键。除了`image`和`build`键之外，其余的键可以直接映射到`docker run`子命令中的选项。值可以是单个值或多个值。

以下是`docker-compose`版本 1.2.0 中支持的键列表：

+   `image`：这是标签或镜像 ID

+   `build`：这是包含`Dockerfile`的目录路径

+   `command`：此键覆盖默认命令

+   `links`：此键链接到另一个服务中的容器

+   `external_links`：此键链接到由其他`docker-compose.yml`或其他方式（而不是`docker-compose`）启动的容器

+   `ports`：此键公开端口并指定端口`HOST_port:CONTAINER_port`

+   `expose`：此键公开端口，但不将其发布到主机

+   `volumes`：此键将路径挂载为卷

+   `volumes_from`：此键从另一个容器挂载所有卷

+   `environment`：此键添加环境变量，并使用数组或字典

+   `env_file`：此键将环境变量添加到文件

+   `extends`：这扩展了同一或不同配置文件中定义的另一个服务

+   `net`：这是网络模式，具有与 Docker 客户端`--net`选项相同的值

+   `pid`：这使主机和容器之间共享 PID 空间

+   `dns`：这设置自定义 DNS 服务器

+   `cap_add`：这会向容器添加一个功能

+   `cap_drop`：这会删除容器的某个功能

+   `dns_search`：这设置自定义 DNS 搜索服务器

+   `working_dir`：这会更改容器内的工作目录

+   `entrypoint`：这会覆盖默认的入口点

+   `用户`: 这设置默认用户

+   `主机名`: 这设置了容器的主机名

+   `域名`: 这设置域名

+   `mem_limit`: 这限制内存

+   `特权`: 这给予扩展权限

+   `重启`: 这设置容器的重启策略

+   `stdin_open`: 这启用标准输入设施

+   `tty`: 这启用基于文本的控制，如终端

+   `cpu_shares`: 这设置 CPU 份额(相对权重)

## docker-compose 命令

`docker-compose`工具提供了一些命令的复杂编排功能。所有`docker-compose`命令都使用`docker-compose.yml`文件作为一个或多个服务的编排基础。以下是`docker-compose`命令的语法:

```
docker-compose [<options>] <command> [<args>...]

```

`docker-compose`工具支持以下选项:

+   `--verbose`: 这显示更多输出

+   `--版本`: 这打印版本并退出

+   `-f, --file <file>`: 这指定`docker-compose`的替代文件(默认为`docker-compose.yml`文件)

+   `-p`, `--project-name <name>`: 这指定替代项目名称(默认为目录名称)

`docker-compose`工具支持以下命令:

+   `构建`: 这构建或重建服务

+   `杀死`: 这杀死容器

+   `日志`: 这显示容器的输出

+   `端口`: 这打印端口绑定的公共端口

+   `ps`: 这列出容器

+   `拉取`: 这拉取服务镜像

+   `rm`: 这删除已停止的容器

+   `运行`: 这运行一次性命令

+   `规模`: 这为服务设置容器数量

+   `开始`: 这启动服务

+   `停止`: 这停止服务

+   `启动`: 这创建并启动容器

## 常见用法

在本节中，我们将通过一个示例来体验 Docker-Compose 框架提供的编排功能的威力。为此，我们将构建一个接收您输入的 URL 并以相关响应文本回复的两层 Web 应用程序。该应用程序使用以下两个服务构建，如下所列:

+   `Redis`: 这是一个用于存储键和其关联值的键值数据库

+   `Node.js`: 这是一个用于实现 Web 服务器功能和应用逻辑的 JavaScript 运行环境

这些服务中的每一个都打包在两个不同的容器中，这些容器使用`docker-compose`工具进行组合。以下是服务的架构表示:

![常见用法](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_08_01.jpg)

在这个示例中，我们首先实现了`example.js`模块，这是一个`node.js`文件，用于实现 Web 服务器和键查找功能。接下来，我们将在与`example.js`相同的目录中编写`Dockerfile`，以打包`node.js`运行环境，然后使用与`example.js`相同的目录中的`docker-compose.yml`文件定义服务编排。

以下是`example.js`文件，它是一个简单的请求/响应 Web 应用程序的`node.js`实现。为了便于演示，在这段代码中，我们限制了`build`和`kill docker-compose`命令。为了使代码更加易懂，我们在代码之间添加了注释：

```
// A Simple Request/Response web application

// Load all required libraries
var http = require('http');
var url = require('url');
var redis = require('redis');

// Connect to redis server running
// createClient API is called with
//  -- 6379, a well-known port to which the
//           redis server listens to
//  -- redis, is the link name of the container
//            that runs redis server
var client = redis.createClient(6379, 'redis');

// Set the key value pair in the redis server

// Here all the keys proceeds with "/", because
// URL parser always have "/" as its first character
client.set("/", "Welcome to Docker-Compose helper\nEnter the docker-compose command in the URL for help\n", redis.print);
client.set("/build", "Build or rebuild services", redis.print);
client.set("/kill", "Kill contianers", redis.print);

var server = http.createServer(function (request, response) {
  var href = url.parse(request.url, true).href;
  response.writeHead(200, {"Content-Type": "text/plain"});

  // Pull the response (value) string using the URL
  client.get(href, function (err, reply) {
    if ( reply == null ) response.write("Command: " + href.slice(1) + " not supported\n");
    else response.write(reply + "\n");
    response.end();
  });
});

console.log("Listening on port 80");
server.listen(80);
```

### 注意

该示例也可在[`github.com/thedocker/learning-docker/tree/master/chap08/orchestrate-using-compose`](https://github.com/thedocker/learning-docker/tree/master/chap08/orchestrate-using-compose)找到。

以下文本是`Dockerfile`的内容，该文件打包了`node.js`镜像、`node.js`的`redis`驱动程序和之前定义的`example.js`文件：

```
###############################################
# Dockerfile to build a sample web application
###############################################

# Base image is node.js
FROM node:latest

# Author: Dr. Peter
MAINTAINER Dr. Peter <peterindia@gmail.com>

# Install redis driver for node.js
RUN npm install redis

# Copy the source code to the Docker image
ADD example.js /myapp/example.js
```

### 注意

此代码也可在[`github.com/thedocker/learning-docker/tree/master/chap08/orchestrate-using-compose`](https://github.com/thedocker/learning-docker/tree/master/chap08/orchestrate-using-compose)找到。

以下文本来自`docker-compose.yml`文件，该文件定义了`docker compose`工具要执行的服务编排：

```
web:
  build: .
  command: node /myapp/example.js
  links:
   - redis
  ports:
   - 8080:80
redis:
  image: redis:latest
```

### 注意

该示例也可在[`github.com/thedocker/learning-docker/tree/master/chap08/orchestrate-using-compose`](https://github.com/thedocker/learning-docker/tree/master/chap08/orchestrate-using-compose)找到。

我们在这个`docker-compose.yml`文件中定义了两个服务，这些服务有以下用途：

+   名为`web`的服务是使用当前目录中的`Dockerfile`构建的。同时，它被指示通过运行 node（`node.js`运行时）并以`/myapp/example.js`（web 应用程序实现）作为参数来启动容器。该容器链接到`redis`容器，并且容器端口`80`映射到 Docker 主机的端口`8080`。

+   服务名为`redis`的服务被指示使用`redis:latest`镜像启动一个容器。如果该镜像不在 Docker 主机上，Docker 引擎将从中央仓库或私有仓库中拉取该镜像。

现在，让我们继续我们的示例，使用`docker-compose build`命令构建 Docker 镜像，使用`docker-compose up`命令启动容器，并使用浏览器连接以验证请求/响应功能，如下逐步解释：

1.  `docker-compose`命令必须从存储`docker-compose.yml`文件的目录中执行。`docker-compose`工具将每个`docker-compose.yml`文件视为一个项目，并且它假定项目名称来自`docker-compose.yml`文件的目录。当然，可以使用`-p`选项覆盖此设置。因此，作为第一步，让我们更改存储`docker-compose.yml`文件的目录：

```
$ cd ~/example

```

1.  使用`docker-compose build`命令构建服务：

```
$ sudo docker-compose build

```

1.  按照`docker-compose.yml`文件中指示的服务启动服务，使用`docker-compose up`命令：

```
$ sudo docker-compose up
Creating example_redis_1...
Pulling image redis:latest...
latest: Pulling from redis
21e4345e9035: Pull complete
. . . TRUNCATED OUTPUT . . .
redis:latest: The image you are pulling has been verified.
Important: image verification is a tech preview feature and should not be relied on to provide security.
Digest: sha256:dad98e997480d657b2c00085883640c747b04ca882d6da50760e038fce63e1b5
Status: Downloaded newer image for redis:latest
Creating example_web_1...
Attaching to example_redis_1, example_web_1
. . . TRUNCATED OUTPUT . . .
redis_1 | 1:M 25 Apr 18:12:59.674 * The server is now ready to accept connections on port 6379
web_1  | Listening on port 80
web_1  | Reply: OK
web_1  | Reply: OK
web_1  | Reply: OK

```

由于目录名为`example`，`docker-compose`工具假定项目名称为`example`。

1.  成功使用`docker-compose`工具编排服务后，让我们从不同的终端调用`docker-compose ps`命令，以列出与示例`docker-compose`项目关联的容器：

```
$ sudo docker-compose ps
 Name                   Command             State          Ports
----------------------------------------------------------------------------
example_redis_1   /entrypoint.sh redis-server   Up      6379/tcp
example_web_1     node /myapp/example.js        Up      0.0.0.0:8080->80/tcp

```

显然，两个`example_redis_1`和`example_web_1`容器正在运行。容器名称以`example_`为前缀，这是`docker-compose`项目名称。

1.  在 Docker 主机的不同终端上探索我们自己的请求/响应 Web 应用程序的功能，如下所示：

```
$ curl http://0.0.0.0:8080
Welcome to Docker-Compose helper
Enter the docker-compose command in the URL for help
$ curl http://0.0.0.0:8080/build
Build or rebuild services
$ curl http://0.0.0.0:8080/something
Command: something not supported

```

### 注意

在这里，我们直接使用`http://0.0.0.0:8080`连接到 Web 服务，因为 Web 服务绑定到 Docker 主机的端口`8080`。

很酷，不是吗？凭借极少的努力和`docker-compose.yml`文件的帮助，我们能够将两个不同的服务组合在一起并提供一个复合服务。

# 总结

本章已纳入书中，以提供有关无缝编排多个容器的所有探查和指定细节。我们广泛讨论了容器编排的需求以及使我们能够简化和流畅进行容器编排日益复杂过程的工具。为了证实编排如何在打造企业级容器中方便和有用，并且为了说明编排过程，我们采用了通过一个简单的例子来解释整个范围的广泛做法。我们开发了一个网络应用并将其包含在一个标准容器中。同样，我们使用了一个数据库容器，它是前端网络应用的后端，并且数据库在另一个容器中执行。我们看到如何通过 Docker 引擎的容器链接功能，使用不同的技术使网络应用容器意识到数据库。我们使用了开源工具（`docker-compose`）来实现这一目的。

在下一章中，我们将讨论 Docker 如何促进软件测试，特别是通过一些实用的例子进行集成测试。
