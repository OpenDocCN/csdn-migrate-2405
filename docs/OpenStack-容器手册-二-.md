# OpenStack 容器手册（二）

> 原文：[`zh.annas-archive.org/md5/D8A2C6F8428362E7663D33F30363BDEB`](https://zh.annas-archive.org/md5/D8A2C6F8428362E7663D33F30363BDEB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：Magnum - OpenStack 中的 COE 管理

本章将解释用于管理**容器编排引擎**（**COE**）的 OpenStack 项目 Magnum。Magnum 是用于管理基础架构并在 OpenStack 顶部运行容器的 OpenStack 项目，由不同的技术支持。在本章中，我们将涵盖以下主题：

+   Magnum 介绍

+   概念

+   主要特点

+   组件

+   演练

+   Magnum DevStack 安装

+   管理 COE

# Magnum 介绍

Magnum 是一个 OpenStack 服务，由 OpenStack 容器团队于 2014 年创建，旨在实现**容器编排引擎**（**COE**），提供在 OpenStack 中将容器部署和管理为一流资源的能力。

目前，Magnum 支持 Kubernetes、Apache Mesos 和 Docker Swarm COE。Magnum 使用 Heat 在 OpenStack 提供的 VM 或裸金属上进行这些 COE 的编排。它使用包含运行容器所需工具的 OS 映像。Magnum 提供了与 KeyStone 兼容的 API 和一个完整的多租户解决方案，用于在 OpenStack 集群顶部管理您的 COE。

Magnum 集群是由不同的 OpenStack 服务提供的各种资源集合。它由 Nova 提供的一组 VM、Neutron 创建的连接这些 VM 的网络、Cinder 创建的连接 VM 的卷等组成。Magnum 集群还可以具有一些外部资源，具体取决于创建集群时提供的选项。例如，我们可以通过在集群模板中指定`-master-lb-enabled`选项来为我们的集群创建外部负载均衡器。

Magnum 的一些显着特点是：

+   为 COE 的完整生命周期管理提供标准 API

+   支持多个 COE，如 Kubernetes、Swarm、Mesos 和 DC/OS

+   支持扩展或缩小集群的能力

+   支持容器集群的多租户

+   不同的容器集群部署模型选择：VM 或裸金属

+   提供基于 KeyStone 的多租户安全和认证管理

+   基于 Neutron 的多租户网络控制和隔离

+   支持 Cinder 为容器提供卷

+   与 OpenStack 集成

+   启用安全容器集群访问（**传输层安全**（**TLS**））

+   集群还可以使用外部基础设施，如 DNS、公共网络、公共发现服务、Docker 注册表、负载均衡器等

+   Barbican 提供了用于集群内部的 TLS 证书等秘密的存储

+   基于 Kuryr 的容器级隔离网络

# 概念

Magnum 有几种不同类型的对象构成了 Magnum 系统。在本节中，我们将详细了解每一个对象，以及它们在 Magnum 中的用途。两个重要的对象是集群和集群模板。以下是 Magnum 对象的列表：

# 集群模板

这以前被称为**Baymodel**。集群模板相当于一个 Nova flavor。一个对象存储关于集群的模板信息，比如密钥对、镜像等，这些信息用于一致地创建新的集群。一些参数与集群的基础设施相关，而另一些参数则是针对特定的 COE。不同的 COE 可以存在多个集群模板。

如果一个集群模板被任何集群使用，那么它就不能被更新或删除。

# 集群

这以前被称为**Bay**。它是一个节点对象的集合，用于调度工作。这个节点可以是虚拟机或裸金属。Magnum 根据特定的集群模板中定义的属性以及集群的一些额外参数来部署集群。Magnum 部署由集群驱动程序提供的编排模板，以创建和配置 COE 运行所需的所有基础设施。创建集群后，用户可以使用每个 COE 的本机 CLI 在 OpenStack 上运行他们的应用程序。

# 集群驱动程序

集群驱动程序包含了设置集群所需的所有必要文件。它包含了一个热模板，定义了为任何集群创建的资源，安装和配置集群上的服务的脚本，驱动程序的版本信息，以及模板定义。

# 热堆栈模板

**Heat Stack Template**（**HOT**）是一个定义将形成 COE 集群的资源的模板。每种 COE 类型都有一个不同的模板，取决于其安装步骤。这个模板被 Magnum 传递给 Heat，以建立一个完整的 COE 集群。

# 模板定义

模板定义表示 Magnum 属性和 Heat 模板属性之间的映射。它还有一些被 Magnum 使用的输出。它指示了给定集群将使用哪种集群类型。

# 证书

证书是 Magnum 中代表集群 CA 证书的对象。Magnum 在创建集群时生成服务器和客户端证书，以提供 Magnum 服务和 COE 服务之间的安全通信。CA 证书和密钥存储在 Magnum 中，供用户安全访问集群。用户需要生成客户端证书、客户端密钥和证书签名请求（CSR），然后发送请求给 Magnum 进行签名，并下载签名证书以访问集群。

# 服务

服务是一个存储有关`magnum-conductor`二进制信息的对象。该对象包含有关服务运行的主机、服务是否已禁用、最后一次的详细信息等信息。管理员可以使用这些信息来查看`magnum-conductor`服务的状态。

# 统计

Magnum 还管理每个项目使用情况的统计信息。这些信息对于管理目的很有帮助。统计对象包含有关管理员或用户对租户的当前使用情况的一些指标，甚至对所有活动租户的信息。它们提供信息，例如集群总数、节点总数等。

# 配额

配额是一个存储任何给定项目资源配额的对象。对资源施加配额限制了可以消耗的资源数量，这有助于在创建时保证资源的公平分配。如果特定项目需要更多资源，配额的概念提供了根据需求增加资源计数的能力，前提是不超出系统约束。配额与物理资源密切相关，并且是可计费的实体。

# 关键特性

在前一节中，我们了解到 Magnum 除了管理 COE 基础设施外，还提供了各种功能。在接下来的章节中，我们将讨论 Magnum 中的一些高级功能。

# Kubernetes 的外部负载均衡器

Magnum 默认使用 Flannel 为 Kubernetes 中的资源提供网络。Pod 和服务可以使用这个私有容器网络相互访问和访问外部互联网。然而，这些资源无法从外部网络访问。为了允许外部网络访问，Magnum 提供了为 Kubernetes 集群设置外部负载均衡器的支持。

请参阅[`docs.openstack.org/magnum/latest/user/#steps-for-the-cluster-administrator`](https://docs.openstack.org/magnum/latest/user/#steps-for-the-cluster-administrator)以使用 Magnum 设置 Kubernetes 负载均衡器。

# 传输层安全性

Magnum 允许我们使用 TLS 在集群服务和外部世界之间建立安全通信。Magnum 中的 TLS 通信在三个层面上使用：

+   Magnum 服务与集群 API 端点之间的通信。

+   集群工作节点与主节点之间的通信。

+   终端用户与集群之间的通信。终端用户使用本机客户端库与集群交互，并使用证书在安全网络上进行通信。这适用于 CLI 和使用特定集群客户端的程序。每个客户端都需要有效的证书来进行身份验证并与集群通信。

前两种情况由 Magnum 在内部实现，并创建、存储和配置服务以使用证书进行通信，不向用户公开。最后一种情况涉及用户创建证书、签名并使用它来访问集群。

Magnum 使用 Barbican 存储证书。这提供了另一层证书存储的安全性。Magnum 还支持其他存储证书的方式，例如将它们存储在主节点的本地文件系统中或在 Magnum 数据库中存储。

有关如何配置客户端以访问安全集群的更多详细信息，请参阅[`docs.openstack.org/magnum/latest/user/#interfacing-with-a-secure-cluster`](https://docs.openstack.org/magnum/latest/user/#interfacing-with-a-secure-cluster)。

# 扩展

扩展是 Magnum 的另一个强大功能。Magnum 支持集群的扩展，而容器的扩展不在 Magnum 的范围内。扩展集群可以帮助用户向集群添加或删除节点。在扩展时，Magnum 创建一个虚拟机或裸金属，部署 COE 服务，然后将其注册到集群。在缩减规模时，Magnum 尝试删除工作负载最小的节点。

请参阅*管理 COEs*部分，了解如何扩展集群。

# 存储

Magnum 支持 Cinder 为容器提供块存储，可以是持久的或临时的存储。

# 临时存储

容器文件系统的所有更改都可以存储在本地文件系统或 Cinder 卷中。这是在容器退出后被删除的临时存储。Magnum 提供额外的 Cinder 卷用作容器的临时存储。用户可以在集群模板中使用`docker-volume-size`属性指定卷的大小。此外，用户还可以选择不同的卷类型，例如设备映射器，并使用`docker_volume_type`属性覆盖此选项。

# 持久存储

当容器退出时，可能需要持久保存容器的数据。可以为此目的挂载 Cinder 卷。当容器退出时，卷将被卸载，从而保留数据。

有许多第三方卷驱动程序支持 Cinder 作为后端，例如 Rexray 和 Flocker。Magnum 目前支持 Rexray 作为 Swarm 的卷驱动程序，以及 Mesos 和 Cinder 作为 Kubernetes 的卷驱动程序。

# 通知

Magnum 生成有关使用数据的通知。这些数据对于第三方应用程序用于计费、配额管理、监控等目的非常有用。为了提供通知的标准格式，Magnum 使用**Cloud Auditing Data Federation**（**CADF**）格式。

# 容器监控

Magnum 还支持对容器进行监控。它收集诸如容器 CPU 负载、可用 Inodes 数量、累积接收字节数、内存、节点的 CPU 统计等指标。提供的监控堆栈依赖于 COE 环境中存在的一组容器和服务：

+   cAdvisor

+   节点导出器

+   Prometheus

+   Grafana

用户可以通过在 Magnum 集群模板的定义中指定给定的两个可配置标签来设置此监控堆栈，即`prometheus_monitoring`设置为 True 时，监控将被启用，以及`grafana_admin_password`，这是管理员密码。

# 组件

*Magnum Conductor*部分的图表显示了 Magnum 的架构，其中有两个名为`magnum-api`和`magnum-conductor`的二进制文件构成了 Magnum 系统。Magnum 与 Heat 进行交互进行编排。这意味着 Heat 是与其他项目（如 Nova、Neutron 和 Cinder）交流以为 COE 设置基础设施的 OpenStack 组件，然后在其上安装 COE。我们现在将了解服务的详细功能。

# Magnum API

Magnum API 是一个 WSGI 服务器，用于为用户发送给 Magnum 的 API 请求提供服务。Magnum API 有许多控制器来处理每个资源的请求：

+   Baymodel

+   Bay

+   证书

+   集群

+   集群模板

+   Magnum 服务

+   配额

+   统计

Baymodel 和 Bay 将分别由集群和集群模板替换。每个控制器处理特定资源的请求。它们验证权限请求，验证 OpenStack 资源（例如验证集群模板中传递的镜像是否存在于 Glance 中），为资源创建带有输入数据的数据库对象，并通过 AMQP 服务器将请求传递给`magnum-conductor`。对`magnum-conductor`的调用可以是同步的或异步的，具体取决于每个操作所花费的处理时间。

例如，列表调用可以是同步的，因为它们不耗时，而创建请求可以是异步的。收到来自 conductor 服务的响应后，`magnum-api`服务将响应返回给用户。

# Magnum conductor

Magnum conductor 是为 Magnum 提供协调和数据库查询支持的 RPC 服务器。它是无状态的和水平可扩展的，这意味着可以同时运行多个 conductor 服务实例。`magnum-conductor`服务选择集群驱动程序，然后将模板文件发送到 Heat 服务进行安装，并最终更新数据库以获取对象详细信息。

这是 Magnum 的架构图，显示了 Magnum 中的不同组件，它们与其他 OpenStack 项目的通信，以及为运行任何 COE 而提供的基础设施：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00020.jpeg)

# 演练

在本节中，我们将为您介绍 Magnum 创建 COE 集群的过程。本节涉及 OpenStack 中各个项目的请求流程和组件交互。在 Magnum 中，为集群提供基础设施涉及 OpenStack 内部多个组件之间的交互。

在 Magnum 中为集群提供基础设施的请求流程如下：

1.  用户通过 CLI 或 Horizon 向`magnum-api`发送 REST API 调用以创建集群，并使用从 KeyStone 接收的身份验证令牌。

1.  `magnum-api`接收请求，并将请求发送到 KeyStone 进行令牌验证和访问权限验证。

1.  KeyStone 验证令牌，并发送带有角色和权限的更新身份验证标头。

1.  `magnum-api`然后验证请求的配额。如果配额超过硬限制，将引发异常，指出*资源限制已超出*，并且请求将以`403` HTTP 状态退出。

1.  然后对集群模板中指定的所有 OpenStack 资源进行验证。例如，`magnum-api`会与`nova-api`进行通信，以检查指定的密钥对是否存在。如果验证失败，请求将以`400` HTTP 状态退出。

1.  如果请求中未指定名称，`magnum-api`会为集群生成一个名称。

1.  `magnum-api`然后为集群创建数据库对象。

1.  `magnum-api`向 magnum-conductor 发送 RPC 异步调用请求，以进一步处理请求。

1.  `magnum-conductor`从消息队列中提取请求。

1.  `magnum-conductor`将集群的状态设置为`CREATE_IN_PROGRESS`并将条目存储在数据库中。

1.  `magnum-conductor`为集群创建受托人、信任和证书，并将它们设置为以后使用的集群。

1.  根据集群分布、COE 类型和集群模板中提供的服务器类型，`magnum-conductor`为集群选择驱动程序。

1.  然后，`magnum-conductor`从集群驱动程序中提取模板文件、模板、环境文件和热参数，然后将请求发送到 Heat 以创建堆栈。

1.  然后，Heat 会与多个 OpenStack 服务进行通信，如 Nova、Neutron 和 Cinder，以设置集群并在其上安装 COE。

1.  在 Heat 中创建堆栈后，在 Magnum 数据库中将堆栈 ID 和集群状态设置为`CREATE_COMPLETE`。

Magnum 中有定期任务，会在特定时间间隔内同步 Magnum 数据库中的集群状态。

# Magnum DevStack 安装

为了开发目的安装 Magnum 与 DevStack，请按照以下步骤进行：

1.  如有需要，为 DevStack 创建一个根目录：

```
        $ sudo mkdir -p /opt/stack
        $ sudo chown $USER /opt/stack
        Clone DevStack repo:
        $ git clone https://git.openstack.org/openstack-dev/devstack
        /opt/stack/devstack  
```

1.  我们将使用最小的`local.conf`设置来运行 DevStack，以启用 Magnum、Heat 和 Neutron：

```
    $ cat > /opt/stack/devstack/local.conf << END
    [[local|localrc]]
    DATABASE_PASSWORD=password
    RABBIT_PASSWORD=password
    SERVICE_TOKEN=password
    SERVICE_PASSWORD=password
    ADMIN_PASSWORD=password
    # magnum requires the following to be set correctly
    PUBLIC_INTERFACE=eth1

    # Enable barbican service and use it to store TLS certificates
    enable_plugin barbican 
    https://git.openstack.org/openstack/barbican

    enable_plugin heat 
    https://git.openstack.org/openstack/heat

    # Enable magnum plugin after dependent plugins
    enable_plugin magnum 
    https://git.openstack.org/openstack/magnum

    # Optional:  uncomment to enable the Magnum UI plugin in 
    Horizon
    #enable_plugin magnum-ui 
    https://github.com/openstack/magnum-ui

    VOLUME_BACKING_FILE_SIZE=20G
    END

```

请注意，我们必须在这里使用 Barbican 来存储 Magnum 生成的 TLS 证书。有关详细信息，请参阅*关键特性*部分下的*传输层安全*部分。

还要确保在`local.conf`中使用适当的接口进行设置。

1.  现在，运行 DevStack：

```
        $ cd /opt/stack/devstack
        $ ./stack.sh  
```

1.  您将拥有一个正在运行的 Magnum 设置。要验证安装，请检查正在运行的 Magnum 服务列表：

```
$ magnum service-list
+----+----------+------------------+-------+----------+-----------------+------------------------
-+---------------------------+
| id | host     | binary           | state | disabled | disabled_reason | created_at             
| updated_at                |
+----+----------+------------------+-------+----------+-----------------+------------------------
-+---------------------------+
| 1  | devstack | magnum-conductor | up    | False    | -               | 2017-09
19T11:14:12+00:00 | 2017-09-19T14:06:41+00:00 |
+----+----------+------------------+-------+----------+-----------------+------------------------
-+---------------------------+  
```

# 管理 COE

Magnum 为 OpenStack 集群的生命周期提供无缝管理。当前操作是基本的 CRUD 操作，还有一些高级功能，如集群的扩展、设置外部负载均衡器、使用 TLS 设置安全集群等。在本节中，我们将创建一个 Swarm 集群模板，使用该模板创建一个 Swarm 集群，然后在集群上运行一些工作负载以验证我们的集群状态。

首先，我们将准备我们的会话，以便能够使用各种 OpenStack 客户端，包括 Magnum、Neutron 和 Glance。创建一个新的 shell 并源自 DevStack 的`openrc`脚本：

```
$ source /opt/stack/devstack/openrc admin admin  
```

创建一个用于集群模板的密钥对。这个密钥对将用于 ssh 到集群节点：

```
$ openstack keypair create --public-key ~/.ssh/id_rsa.pub testkey
+-------------+-------------------------------------------------+
| Field       | Value                                           |
+-------------+-------------------------------------------------+
| fingerprint | d2:8d:c8:d2:2a:82:fc:aa:98:17:5f:9b:22:08:8a:f7 |
| name        | testkey                                         |
| user_id     | 4360ea27027a4d9d97e749bba9698915                |
+-------------+-------------------------------------------------+  
```

DevStack 在 Glance 中为 Magnum 的使用创建了一个 Fedora Atomic 微型 OS 镜像。用户还可以在 Glance 中创建其他镜像以供其集群使用。验证在 Glance 中创建的镜像：

```
$ openstack image list
+--------------------------------------+------------------------------------+--------+
| ID                                   | Name                               | Status |
+--------------------------------------+------------------------------------+--------+
| 482bd0b4-883d-4fc5-bf26-a88a98ceddd1 | Fedora-Atomic-26-20170723.0.x86_64 | active |
| 6862d910-a320-499e-a19f-1dbcdc79455f | cirros-0.3.5-x86_64-disk           | active |
+--------------------------------------+------------------------------------+--------+
```

现在，创建一个具有 swarm COE 类型的 Magnum 集群模板。这与 Nova flavor 类似，告诉 Magnum 如何构建集群。集群模板指定了集群中要使用的所有资源，例如 Fedora Atomic 镜像、Nova 密钥对、网络等等：

```
$ magnum cluster-template-create swarm-template --image Fedora-Atomic-26-20170723.0.x86_64 --keypair testkey --external-network public --flavor m1.small --docker-volume-size 5  --dns-nameserver 8.8.8.8 --coe swarm
+-----------------------+--------------------------------------+
| Property              | Value                                |
+-----------------------+--------------------------------------+
| insecure_registry     | -                                    |
| labels                | {}                                   |
| updated_at            | -                                    |
| floating_ip_enabled   | True                                 |
| fixed_subnet          | -                                    |
| master_flavor_id      | -                                    | 
| uuid                  | 0963601a-50aa-4361-9f6f-5f64f0826da8 |
| no_proxy              | -                                    |
| https_proxy           | -                                    |
| tls_disabled          | False                                |
| keypair_id            | testkey                              |
| public                | False                                |
| http_proxy            | -                                    |
| docker_volume_size    | 5                                    |
| server_type           | vm                                   |
| external_network_id   | public                               |
| cluster_distro        | fedora-atomic                        |
| image_id              | Fedora-Atomic-26-20170723.0.x86_64   |
| volume_driver         | -                                    |
| registry_enabled      | False                                |
| docker_storage_driver | devicemapper                         |
| apiserver_port        | -                                    |
| name                  | swarm-template                       |
| created_at            | 2017-09-19T13:06:28+00:00            |
| network_driver        | docker                               |
| fixed_network         | -                                    |
| coe                   | swarm                                |
| flavor_id             | m1.small                             |
| master_lb_enabled     | False                                |
| dns_nameserver        | 8.8.8.8                              |
+-----------------------+--------------------------------------+  
```

使用以下命令验证集群模板的创建：

```
$ magnum cluster-template-list
+--------------------------------------+----------------+
| uuid                                 | name           |
+--------------------------------------+----------------+
| 0963601a-50aa-4361-9f6f-5f64f0826da8 | swarm-template |
+--------------------------------------+----------------+  
```

使用前面的模板创建一个集群。这个集群将导致创建一组安装了 Docker Swarm 的 VM：

```
$ magnum cluster-create swarm --cluster-template swarm-template --node-count 1
Request to create cluster f42f5dfc-a2d0-4f89-9af1-566c666727c3 has been accepted.  
```

集群将初始状态设置为`CREATE_IN_PROGRESS`。当 Magnum 完成创建集群时，将把状态更新为`CREATE_COMPLETE`。

Heat 可以用来查看堆栈或特定集群状态的详细信息。

要检查所有集群堆栈的列表，请使用以下命令：

```
$ openstack stack list
+--------------------------------------+--------------------+----------------------------------+-------------------+----------------------+--------------+
| ID                                   | Stack Name         | Project                          | Stack Status       | Creation Time        | Updated Time |
+--------------------------------------+--------------------+----------------------------------+--------------------+----------------------+--------------+
| 9d39e877-32ff-4904-a349-727274caee68 | swarm-5g5ilw3lak6p | 8c4a19b957904085992dd800621459b6 | CREATE_IN_PROGRESS | 2017-09-19T13:07:52Z | None         |
+--------------------------------------+--------------------+----------------------------------+--------------------+----------------------+--------------+  
```

要查看集群的详细信息，请执行以下操作：

```
$ magnum cluster-show swarm
+---------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Property            | Value                                                                                                                                                                                                                                                                                                                                                                                                |
+---------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| labels              | {}                                                                                                                                                                                                                                                                                                                                                                                                   |
| updated_at          | 2017-09-19T13:16:41+00:00                                                                                                                                                                                                                                                                                                                                                                            |
| keypair             | testkey                                                                                                                                                                                                                                                                                                                                                                                              |
| node_count          | 1                                                                                                                                                                                                                                                                                                                                                                                                    |
| uuid                | f42f5dfc-a2d0-4f89-9af1-566c666727c3                                                                                                                                                                                                                                                                                                                                                                 |
| api_address         | https://172.24.4.4:6443
|
| master_addresses    | ['172.24.4.2']                                                                                                                                                                                                                                                                                                                                                                                       |
| create_timeout      | 60                                                                                                                                                                                                                                                                                                                                                                                                   |
| status              | CREATE_COMPLETE                                                                                                                                                                                                                                                                                                                                                                                        |
| docker_volume_size  | 5                                                                                                                                                                                                                                                                                                                                                                                                    |
| master_count        | 1                                                                                                                                                                                                                                                                                                                                                                                                    |
| node_addresses      | ['172.24.4.3']                                                                                                                                                                                                                                                                                                                                                                                                   |
| status_reason       | Stack CREATE completed successfully                                                                                                                                                                                                                                           |
| coe_version         | 1.2.5                                                                                                                                                                                                                                                                                                                                                                                                |
| cluster_template_id | 0963601a-50aa-4361-9f6f-5f64f0826da8                                                                                                                                                                                                                                                                                                                                                                 |
| name                | swarm                                                                                                                                                                                                                                                                                                                                                                                                |
| stack_id            | 9d39e877-32ff-4904-a349-727274caee68                                                                                                                                                                                                                                                                                                                                                                 |
| created_at          | 2017-09-19T13:07:46+00:00                                                                                                                                                                                                                                                                                                                                                                            |
| discovery_url       | https://discovery.etcd.io/af18b93f0d1b64db0d803a1c76e4d0d0                                                                                                                                                                                                                                                                                                                                           |
| container_version   | 1.12.6                                                                                                                                                                                                                                                                                                                                                                                               |
+---------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+  
```

现在我们需要设置 Docker CLI 以使用我们使用适当凭据创建的 swarm 集群。

创建一个`dir`来存储`certs`和`cd`。`DOCKER_CERT_PATH`环境变量被 Docker 使用，它期望这个目录中有`ca.pem`、`key.pem`和`cert.pem`：

```
$ export DOCKER_CERT_PATH=~/.docker
$ mkdir -p ${DOCKER_CERT_PATH}
$ cd ${DOCKER_CERT_PATH}
```

生成 RSA 密钥：

```
$ openssl genrsa -out key.pem 4096
```

创建`openssl`配置以帮助生成 CSR：

```
$ cat > client.conf << END
[req]
distinguished_name = req_distinguished_name
req_extensions     = req_ext
prompt = no
[req_distinguished_name]
CN = Your Name
[req_ext]
extendedKeyUsage = clientAuth
END 
```

运行`openssl req`命令生成 CSR：

```
$ openssl req -new -days 365 -config client.conf -key key.pem -out client.csr    
```

现在您已经有了客户端 CSR，请使用 Magnum CLI 对其进行签名，并下载签名证书：

```
$ magnum ca-sign --cluster swarm-cluster --csr client.csr > cert.pem
$ magnum ca-show --cluster swarm-cluster > ca.pem  
```

设置 CLI 以使用 TLS。这个`env var`被 Docker 使用：

```
$ export DOCKER_TLS_VERIFY="1" 
```

设置要使用的正确主机，即 Swarm API 服务器端点的公共 IP 地址。

这个`env var`被 Docker 使用：

```
$ export DOCKER_HOST=$(magnum cluster-show swarm-cluster | awk '/
api_address /{print substr($4,7)}')  
```

接下来，我们将在这个 Swarm 集群中创建一个容器。这个容器将四次 ping 地址`8.8.8.8`：

```
$ docker run --rm -it cirros:latest ping -c 4 8.8.8.8  
```

你应该看到类似以下的输出：

```
PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: seq=0 ttl=40 time=25.513 ms
64 bytes from 8.8.8.8: seq=1 ttl=40 time=25.348 ms
64 bytes from 8.8.8.8: seq=2 ttl=40 time=25.226 ms
64 bytes from 8.8.8.8: seq=3 ttl=40 time=25.275 ms

--- 8.8.8.8 ping statistics ---
4 packets transmitted, 4 packets received, 0% packet loss
round-trip min/avg/max = 25.226/25.340/25.513 ms  
```

创建集群后，您可以通过更新`node_count`属性动态地向集群中添加或删除节点。例如，要添加一个节点，执行以下操作：

```
$ magnum cluster-update swarm replace node_count=2  
```

当更新过程继续进行时，集群的状态将为`UPDATE_IN_PROGRESS`。更新完成后，状态将更新为`UPDATE_COMPLETE`。减少`node_count`会删除已删除节点上的所有现有 pod/容器。Magnum 尝试删除工作负载最小的节点。

# 摘要

在本章中，我们详细了解了 OpenStack 容器基础设施管理服务 Magnum。我们研究了 Magnum 中的不同对象。然后，我们了解了 Magnum 的组件和架构。接着，我们提供了 Magnum 中用户请求工作流程的详细概述。

最后，我们看了如何使用 DevStack 安装 Magnum 的开发设置，然后使用 Magnum CLI 进行了实际操作，创建了一个 Docker Swarm COE。

在下一章中，我们将学习 Zun，这是 OpenStack 的一个容器管理服务。


# 第六章：Zun - OpenStack 中的容器管理

在本章中，我们将了解用于管理容器的 OpenStack 项目 Zun。Zun 是 OpenStack 中唯一可用的解决方案，允许用户管理其应用程序容器，支持不同技术，并结合了其他 OpenStack 组件（如 Cinder、Glance 和 Neutron）的优点。Zun 为在 OpenStack IaaS 上运行容器化应用程序提供了强大的平台。

本章将涵盖以下主题：

+   Zun 简介

+   概念

+   关键特性

+   组件

+   演练

+   Zun DevStack 安装

+   管理容器

# Zun 简介

Zun 是在 Mitaka 周期由 Magnum 团队成员开发的 OpenStack 服务。在 2016 年的 OpenStack Austin Summit 上做出了一个决定，创建一个新项目来允许管理容器，并让 Magnum 容器基础设施管理服务仅管理运行容器的基础设施。结果就是 Zun 项目。

Zun 是 OpenStack 的容器管理服务，提供 API 来管理后端使用不同技术抽象的容器。Zun 支持 Docker 作为容器运行时工具。目前，Zun 与许多 OpenStack 服务集成，如用于网络的 Neutron，用于管理容器镜像的 Glance，以及为容器提供卷的 Cinder。

Zun 相比 Docker 有各种附加功能，使其成为容器管理的强大解决方案。以下是 Zun 一些显著特点的列表：

+   为容器的完整生命周期管理提供标准 API

+   提供基于 KeyStone 的多租户安全性和认证管理

+   支持使用 runc 和 clear container 管理容器的 Docker

+   通过将单个容器打包到具有小占地面积的虚拟机中，支持 clear container 提供更高的安全性

+   支持 Cinder 为容器提供卷

+   基于 Kuryr 的容器级隔离网络

+   通过 Heat 支持容器编排

+   容器组合，称为 capsules，允许用户将多个具有相关资源的容器作为单个单元运行

+   支持 SR-IOV 功能，可实现将物理 PCIe 设备跨虚拟机和容器共享

+   支持与容器进行交互式会话

+   Zun 允许用户通过暴露 CPU 集来运行具有专用资源的重型工作负载。

# 概念

在接下来的章节中，我们将看看 Zun 系统中可用的各种对象。

# 容器

在 Zun 中，容器是最重要的资源。Zun 中的容器代表用户运行的任何应用程序容器。容器对象存储信息，如镜像、命令、工作目录、主机等。Zun 是一个可扩展的解决方案；它也可以支持其他容器运行时工具。它为每个工具实现了基于驱动程序的实现。Zun 中的 Docker 驱动程序通过 Docker 管理容器。Zun 中的容器支持许多高级操作，包括 CRUD 操作，如创建、启动、停止、暂停、删除、更新、终止等。

# 镜像

Zun 中的镜像是容器镜像。这些镜像由 Docker Hub 或 Glance 管理。用户可以在创建容器之前下载镜像并将其保存到 Glance 以节省时间。镜像对象存储信息，如镜像名称、标签、大小等。支持的操作包括上传、下载、更新和搜索镜像。

# 服务

Zun 中的服务代表`zun-compute`服务。Zun 可以运行多个`zun-compute`服务实例以支持可伸缩性。该对象用于建立在 Zun 集群中运行的计算服务的状态。服务存储信息，如状态、启用或禁用、上次已知时间等。

# 主机

Zun 中的主机代表计算节点的资源。计算节点是容器运行的物理机器。这用于建立 Zun 中可用资源和已使用资源的列表。Zun 中的主机对象存储有关计算节点的有用信息，如总内存、空闲内存、运行、停止或暂停容器的总数、总 CPU、空闲 CPU 等。

# 胶囊

Zun 中的胶囊代表包含多个容器和其他相关资源的组合单元。胶囊中的容器彼此共享资源，并紧密耦合以作为单个单元一起工作。胶囊对象存储信息，如容器列表、CPU、内存等。

# 容器驱动程序

Zun 旨在成为 OpenStack 顶部容器管理的可扩展解决方案。Zun 支持 Docker 来管理容器。它还旨在未来支持多种其他工具，如 Rocket。为了支持这一点，Zun 有一系列容器驱动程序，可以与许多其他运行时工具实现，并作为 Zun 的解决方案提供。用户可以选择使用他们选择的工具来管理他们的容器。

# 镜像驱动程序

我们已经了解到 Zun 可以支持多个容器运行时工具来管理容器。同样，它支持多个镜像驱动程序来管理容器镜像，如 Glance 驱动程序和 Docker 驱动程序。镜像驱动程序也是可配置的；用户可以根据其用例选择任何可用的解决方案。

# 网络驱动程序

Zun 中的网络驱动程序提供了两个容器之间以及容器与虚拟机之间的通信能力。Zun 有一个 Kuryr 驱动程序来管理所有容器的网络资源。它支持创建和删除网络、连接和断开容器与网络的连接等操作。

# 关键特性

Zun 除了基本的容器管理之外，还具有许多高级功能。在本节中，我们将讨论 Zun 中的一些高级功能。还有许多其他功能正在进行中，例如 SRIOV 网络、PCIe 设备等，这些在 Zun 文档中有所提及。

# Cinder 集成

Zun 支持将持久存储附加到容器中，即使容器退出后仍然存在。这种存储可以用来存储大量数据，超出主机范围，如果主机宕机，这种存储更加可靠。这种支持是通过 Cinder 在 Zun 中实现的。用户可以挂载和卸载 Cinder 卷到他们的容器中。用户首先需要在 Cinder 中创建卷，然后在创建容器时提供卷。

# 容器组合

Zun 支持将多个容器作为单个单元创建。这个单元在 Zun 中被称为 capsule。这个概念与 Kubernetes 中的 pod 非常相似。一个 capsule 包含多个容器和所有相关的资源，如网络和存储，紧密耦合。capsule 中的所有容器都被调度到同一主机上，并共享资源，如 Linux 命名空间、CGroups 等。

# Kuryr 网络

Zun 创建的容器可以与 Nova 创建的虚拟机进行交互。这一功能由`Kuryr-libnetwork`提供。它与 Neutron 进行交互，为容器创建必要的网络资源，并为其他 OpenStack 资源提供通信路径。

# 容器沙盒

Zun 有一系列沙盒容器。沙盒是一个具有与之关联的所有 IaaS 资源的容器，例如端口，IP 地址，卷等。沙盒的目的是将管理这些 IaaS 资源的开销与应用容器分离。沙盒可以管理单个或多个容器，并提供所有所需的资源。

# CPU 集

Zun 允许用户运行具有专用资源的高性能容器。 Zun 向用户公开其主机功能，用户可以在创建容器时指定所需的 CPU。

调度程序会筛选具有可用资源的节点，并在该节点上为容器提供资源。主机信息将在数据库中更新，以反映更新后的资源。

# 组件

* Zun WebSocket 代理 *部分中的图表显示了 Zun 的架构。 Zun 有两个二进制文件：`zun-api`和`zun-compute`。这两个服务共同承载容器管理的整个生命周期。这些服务与其他 OpenStack 服务进行交互，例如 Glance 用于容器图像，Cinder 用于为容器提供卷，Neutron 用于容器与外部世界之间的连接。对容器的请求最终传达给在计算节点上运行的 Docker 服务。然后 Docker 为用户创建容器。

# zun-api

`zun-api`是一个 WSGI 服务器，用于为用户的 API 请求提供服务。对于 Zun 中的每个资源，都有单独的处理程序：

+   容器

+   主机

+   镜像

+   Zun 服务

每个控制器处理特定资源的请求。它们验证权限请求，验证 OpenStack 资源，包括验证图像是否存在于 Docker Hub 或 Glance，并为具有输入数据的资源创建 DB 对象。请求将转发给计算管理器。在从`zun-compute`服务接收到响应后，`zun-api`服务将响应返回给用户。

# Zun 调度程序

Zun 中的调度程序不是 RPC 服务。它是一个简单的 Python 类，对计算节点应用过滤器，并选择适当的节点来处理请求。然后，计算管理器通过 RPC 调用将请求传递给所选的`zun-compute`。对`zun-compute`的调用可以是同步或异步的，具体取决于每个操作所花费的处理时间。例如，列表调用可以是同步的，因为它们不耗时，而创建请求可以是异步的。

# zun-compute

`zun-compute`服务是 Zun 系统的主要组件。它执行大部分后端操作，隐藏了所有复杂性。`zun-compute`为每个请求选择适当的驱动程序，并为容器创建相关资源，如网络资源。然后，它将带有所有必要信息的请求传递给驱动程序。`zun-compute`与多个项目进行交流，获取各种资源，例如从 Glance 获取容器镜像，从 Neutron 获取网络资源。

# Zun WebSocket 代理

Zun 具有用于以交互模式运行容器的 WebSocket 代理服务。该服务与容器建立安全连接，以在其中运行任何命令：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00021.jpeg)

# Walk-through

在本节中，我们将为您介绍在 Zun 中如何创建容器以及用户请求如何从用户传递到创建容器的 Docker。Zun 与其他多个 OpenStack 服务进行交互，以获取容器所需的资源。

在 Zun 中创建容器的请求流程如下：

1.  用户通过 CLI 或 Horizon 向`zun-api`服务发送 REST API 调用以创建集群，并使用从 KeyStone 接收的身份验证令牌。

1.  `zun-api`接收请求，并向 KeyStone 发送令牌和访问权限的验证请求。

1.  KeyStone 验证令牌，并发送带有角色和权限的更新身份验证标头。

1.  `zun-api`然后从请求中解析一些参数，例如安全组、内存和运行时，并对其进行验证。

1.  `zun-api`创建了请求的网络。`zun-api`向 Neutron 发送请求，以确保请求的网络或端口可用。如果不可用，`zun-api`将向 Neutron 发送另一个请求，以搜索可用网络并为容器创建新的 Docker 网络。

1.  `zun-api`然后检查请求的镜像是否可用。如果未找到镜像，则请求将以`400` HTTP 状态失败。

1.  如果请求中未提供容器的名称，`zun-api`会为容器生成一个名称。

1.  然后，`zun-api`为容器创建数据库对象。

1.  `zun-api`将请求发送到计算 API 管理器。计算管理器从调度程序中查找目标计算节点。

1.  然后，`zun-api`将异步调用请求发送到在上一步中选择的`zun-compute`以进一步处理请求。

1.  `zun-compute`从消息队列中获取请求。

1.  `zun-compute`将容器的`task_state`设置为`IMAGE_PULLING`并将条目存储在数据库中。

1.  `zun-compute`调用图像驱动程序下载图像。

1.  成功下载图像后，数据库中的`task_state`现在设置为`CONTAINER_CREATING`。

1.  现在，`zun-compute`声明容器所需的资源，并更新计算节点资源表中的所需信息。

1.  最后，向 Docker 发送请求以使用所有必需的参数创建容器。

1.  Docker 驱动程序创建容器，将状态设置为`CREATED`，`status_reason`设置为`None`，并将容器对象保存在数据库中。

1.  容器成功完成后，`task_state`设置为`None`。

Zun 中有定期任务，在特定时间间隔内同步 Zun 数据库中的容器状态。

# Zun DevStack 安装

我们现在将看看如何使用 DevStack 安装 Zun 的开发设置：

如有需要，创建 DevStack 的根目录：

```
$ sudo mkdir -p /opt/stack
$ sudo chown $USER /opt/stack  
```

要克隆 DevStack 存储库，请执行以下操作：

```
$ git clone https://git.openstack.org/openstack-dev/devstack 
/opt/stack/devstack  
```

现在，创建一个最小的`local.conf`来运行 DevStack 设置。我们将启用以下插件来创建 Zun 设置：

+   `devstack-plugin-container`：此插件安装 Docker

+   `kuryr-libnetwork`：这是使用 Neutron 提供网络服务的 Docker libnetwork 驱动程序

```
$ cat > /opt/stack/devstack/local.conf << END
[[local|localrc]]
HOST_IP=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/')
DATABASE_PASSWORD=password
RABBIT_PASSWORD=password
SERVICE_TOKEN=password
SERVICE_PASSWORD=password
ADMIN_PASSWORD=password
enable_plugin devstack-plugin-container https://git.openstack.org/openstack/devstack-plugin-container
enable_plugin zun https://git.openstack.org/openstack/zun
enable_plugin kuryr-libnetwork https://git.openstack.org/openstack/kuryr-libnetwork

# Optional:  uncomment to enable the Zun UI plugin in Horizon
# enable_plugin zun-ui https://git.openstack.org/openstack/zun-ui
END
```

现在运行 DevStack：

```
$ cd /opt/stack/devstack
$ ./stack.sh  
```

创建一个新的 shell 并源自 DevStack `openrc`脚本以使用 Zun CLI：

```
$ source /opt/stack/devstack/openrc admin admin

```

现在，让我们通过查看服务列表来验证 Zun 的安装：

```
$ zun service-list
+----+--------+-------------+-------+----------+-----------------+---------------------------+--------------------------+
| Id | Host   | Binary      | State | Disabled | Disabled Reason | Created At                | Updated At                |
+----+--------+-------------+-------+----------+-----------------+---------------------------+---------------------------+
| 1  | galvin | zun-compute | up    | False    | None            | 2017-10-10 11:22:50+00:00 | 2017-10-10 11:37:03+00:00 |
+----+--------+-------------+-------+----------+-----------------+---------------------------+---------------------------+  
```

让我们看一下主机列表，其中还显示了在 Zun 中注册供使用的计算节点：

```
$ zun host-list
+--------------------------------------+----------+-----------+------+--------------------+--------+
| uuid                                 | hostname | mem_total | cpus | os                 | labels |
+--------------------------------------+----------+-----------+------+--------------------+--------+
| 08fb3f81-d88e-46a1-93b9-4a2c18ed1f83 | galvin   | 3949      | 1    | Ubuntu 16.04.3 LTS | {}     |
+--------------------------------------+----------+-----------+------+--------------------+--------+  
```

我们可以看到我们有一个计算节点，即主机本身。现在，让我们也看看主机中可用的资源：

```
$ zun host-show galvin
+------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Property         | Value                                                                                                                                                                                               |
+------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| hostname         | galvin                                                                                                                                                                                              |
| uuid             | 08fb3f81-d88e-46a1-93b9-4a2c18ed1f83                                                                                                                                                                |
| links            | ["{u'href': u'http://10.0.2.15/v1/hosts/08fb3f81-d88e-46a1-93b9-4a2c18ed1f83', u'rel': u'self'}", "{u'href': u'http://10.0.2.15/hosts/08fb3f81-d88e-46a1-93b9-4a2c18ed1f83', u'rel': u'bookmark'}"] |
| kernel_version   | 4.10.0-28-generic                                                                                                                                                                                   |
| labels           | {}                                                                                                                                                                                                  |
| cpus             | 1                                                                                                                                                                                                   |
| mem_total        | 3949                                                                                                                                                                                                |
| total_containers | 0                                                                                                                                                                                                  |
| os_type          | linux                                                                                                                                                                                               |
| os               | Ubuntu 16.04.3 LTS                                                                                                                                                                                  |
| architecture     | x86_64                                                                                                                                                                                              |
+------------ ------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+  
```

我们可以看到`zun-compute`服务正在运行。当前设置只安装了一个计算服务；您也可以安装多节点 Zun 设置。请参考[`github.com/openstack/zun/blob/master/doc/source/contributor/quickstart.rst`](https://github.com/openstack/zun/blob/master/doc/source/contributor/quickstart.rst) 获取更多详细信息。

# 管理容器

现在我们有一个运行中的 Zun 设置，我们将在本节尝试对容器进行一些操作。

我们现在将在 Zun 中创建一个容器。但在此之前，让我们检查一下 Docker 的状态：

```
$ sudo docker ps -a
CONTAINER ID        IMAGE                                                 COMMAND                  CREATED              STATUS                          PORTS               NAMES  
```

我们可以看到现在没有容器存在。现在，让我们创建容器：

```
$ zun create --name test cirros ping -c 4 8.8.8.8
+-------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Property          | Value                                                                                                                                                                                                         |
+-------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| addresses         |                                                                                                                                                                                                               |
| links             | ["{u'href': u'http://10.0.2.15/v1/containers/f78e778a-ecbd-42d3-bc77-ac50334c8e57', u'rel': u'self'}", "{u'href': u'http://10.0.2.15/containers/f78e778a-ecbd-42d3-bc77-ac50334c8e57', u'rel': u'bookmark'}"] |
| image             | cirros                                                                                                                                                                                                        |
| labels            | {}                                                                                                                                                                                                            |
| networks          |                                                                                                                                                                                                               |
| security_groups   | None                                                                                                                                                                                                          |
| image_pull_policy | None                                                                                                                                                                                                          |
| uuid              | f78e778a-ecbd-42d3-bc77-ac50334c8e57                                                                                                                                                                          |
| hostname          | None                                                                                                                                                                                                          |
| environment       | {}                                                                                                                                                                                                            |
| memory            | None                                                                                                                                                                                                          |
| status            | Creating                                                                                                                                                                                                      |
| workdir           | None                                                                                                                                                                                                          |
| auto_remove       | False                                                                                                                                                                                                         |
| status_detail     | None                                                                                                                                                                                                          |
| host              | None                                                                                                                                                                                                          |
| image_driver      | None                                                                                                                                                                                                          |
| task_state        | None                                                                                                                                                                                                          |
| status_reason     | None                                                                                                                                                                                                          |
| name              | test                                                                                                                                                                                                          |
| restart_policy    | None                                                                                                                                                                                                          |
| ports             | None                                                                                                                                                                                                          |
| command           | "ping" "-c" "4" "8.8.8.8"                                                                                                                                                                                     |
| runtime           | None                                                                                                                                                                                                          |
| cpu               | None                                                                                                                                                                                                          |
| interactive       | False                                                                                                                                                                                                         |
+-------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+  
```

现在，让我们查看 Zun 列表以检查容器状态：

```
stack@galvin:~/devstack$ zun list
+--------------------------------------+------+--------+----------+---------------+-----------+-------+
| uuid                                 | name | image  | status   | task_state    | addresses | ports |
+--------------------------------------+------+--------+----------+---------------+-----------+-------+
| f78e778a-ecbd-42d3-bc77-ac50334c8e57 | test | cirros | Creating | image_pulling |           | []    |
+--------------------------------------+------+--------+----------+---------------+-----------+-------+
```

我们可以看到容器处于创建状态。让我们也在 Docker 中检查一下容器：

```
$ sudo docker ps -a
CONTAINER ID        IMAGE                                                    COMMAND                  CREATED             STATUS                       PORTS               NAMES
cbd2c94d6273        cirros:latest                                            "ping -c 4 8.8.8.8"      38 seconds ago      Created                                          zun-f78e778a-ecbd-42d3-bc77-ac50334c8e57  
```

现在，让我们启动容器并查看日志：

```
$ zun start test
Request to start container test has been accepted.

$ zun logs test
PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: seq=0 ttl=40 time=25.513 ms
64 bytes from 8.8.8.8: seq=1 ttl=40 time=25.348 ms
64 bytes from 8.8.8.8: seq=2 ttl=40 time=25.226 ms
64 bytes from 8.8.8.8: seq=3 ttl=40 time=25.275 ms

--- 8.8.8.8 ping statistics ---
4 packets transmitted, 4 packets received, 0% packet loss
round-trip min/avg/max = 25.226/25.340/25.513 ms  
```

让我们对容器进行一些高级操作。我们现在将使用 Zun 创建一个交互式容器：

```
$ zun run -i --name new ubuntu /bin/bash
+-------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Property          | Value                                                                                                                                                                                                         |
+-------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| addresses         |                                                                                                                                                                                                               |
| links             | ["{u'href': u'http://10.0.2.15/v1/containers/dd6764ee-7e86-4cf8-bae8-b27d6d1b3225', u'rel': u'self'}", "{u'href': u'http://10.0.2.15/containers/dd6764ee-7e86-4cf8-bae8-b27d6d1b3225', u'rel': u'bookmark'}"] |
| image             | ubuntu                                                                                                                                                                                                        |
| labels            | {}                                                                                                                                                                                                            |
| networks          |                                                                                                                                                                                                               |
| security_groups   | None                                                                                                                                                                                                          |
| image_pull_policy | None                                                                                                                                                                                                          |
| uuid              | dd6764ee-7e86-4cf8-bae8-b27d6d1b3225                                                                                                                                                                          |
| hostname          | None                                                                                                                                                                                                          |
| environment       | {}                                                                                                                                                                                                            |
| memory            | None                                                                                                                                                                                                          |
| status            | Creating                                                                                                                                                                                                      |
| workdir           | None                                                                                                                                                                                                          |
| auto_remove       | False                                                                                                                                                                                                         |
| status_detail     | None                                                                                                                                                                                                          |
| host              | None                                                                                                                                                                                                          |
| image_driver      | None                                                                                                                                                                                                          |
| task_state        | None                                                                                                                                                                                                          |
| status_reason     | None                                                                                                                                                                                                          |
| name              | new                                                                                                                                                                                                           |
| restart_policy    | None                                                                                                                                                                                                          |
| ports             | None                                                                                                                                                                                                          |
| command           | "/bin/bash"                                                                                                                                                                                                   |
| runtime           | None                                                                                                                                                                                                          |
| cpu               | None                                                                                                                                                                                                          |
| interactive       | True                                                                                                                                                                                                          |
+-------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Waiting for container start
Waiting for container start
Waiting for container start
Waiting for container start
Waiting for container start
Waiting for container start
Waiting for container start
Waiting for container start
Waiting for container start
Waiting for container start
connected to dd6764ee-7e86-4cf8-bae8-b27d6d1b3225, press Enter to continue
type ~. to disconnect
root@81142e581b10:/# 
root@81142e581b10:/# ls
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
root@81142e581b10:/# exit
exit  
```

现在，让我们删除容器：

```
$ zun delete test
Request to delete container test has been accepted.

$ zun list
+--------------------------------------+------+--------+---------+------------+--------------------------+-------+
| uuid                                 | name | image  | status  | task_state | addresses                | ports |
+--------------------------------------+------+--------+---------+------------+--------------------------+-------+
| dd6764ee-7e86-4cf8-bae8-b27d6d1b3225 | new  | ubuntu | Stopped | None       | 172.24.4.11, 2001:db8::d | []    |
+--------------------------------------+------+--------+---------+------------+--------------------------+-------+  
```

我们现在将查看一些命令，以了解在 Zun 中如何管理镜像。下载一个 Ubuntu 镜像：

```
$ zun pull ubuntu
+----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Property | Value                                                                                                                                                                                                 |
+----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| uuid     | 9b34875a-50e1-400c-a74b-028b253b35a4                                                                                                                                                                  |
| links    | ["{u'href': u'http://10.0.2.15/v1/images/9b34875a-50e1-400c-a74b-028b253b35a4', u'rel': u'self'}", "{u'href': u'http://10.0.2.15/images/9b34875a-50e1-400c-a74b-028b253b35a4', u'rel': u'bookmark'}"] |
| repo     | ubuntu                                                                                                                                                                                                |
| image_id | None                                                                                                                                                                                                  |
| tag      | latest                                                                                                                                                                                                |
| size     | None                                                                                                                                                                                                  |
+----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+  
```

现在让我们看一下 Zun 中的镜像列表：

```
stack@galvin:~/devstack$ zun image-list
+--------------------------------------+----------+--------+--------+------+
| uuid                                 | image_id | repo   | tag    | size |
+--------------------------------------+----------+--------+--------+------+
| 9b34875a-50e1-400c-a74b-028b253b35a4 | None     | ubuntu | latest | None |
+--------------------------------------+----------+--------+--------+------+  
```

# 总结

在本章中，我们学习了 OpenStack 容器管理服务 Zun。我们深入研究了 Zun 中的不同对象。然后，我们还了解了 Zun 的组件和架构。本章还详细介绍了用户请求在 Zun 中管理容器的工作流程。然后，我们看了如何使用 DevStack 在 Zun 中安装开发设置，并使用 Zun CLI 进行了实际操作，创建了一个容器，并对容器进行了启动和停止等其他操作。在下一章中，我们将学习 Kuryr，它使用 Neutron 为容器提供网络资源。


# 第七章：Kuryr - OpenStack 网络的容器插件

在本章中，我们将学习关于 Kuryr 的内容，这是一个用于容器网络的 OpenStack 项目。本章将涵盖以下主题：

+   介绍 Kuryr

+   Kuryr 架构

+   安装 Kuryr

+   步骤

# 介绍 Kuryr

Kuryr 是捷克语单词，意思是快递员。它是一个 Docker 网络插件，使用 OpenStack Neutron 为 Docker 容器提供网络服务。它将容器网络抽象映射到 OpenStack neutron API。这提供了将虚拟机、容器和裸金属服务器连接到同一虚拟网络的能力，实现无缝的管理体验，并为所有三者提供一致的网络。Kuryr 可以使用 Python 包或 Kolla 容器进行部署。它为使用 neutron 作为提供者的容器提供以下功能：

+   安全组

+   子网池

+   NAT（SNAT/DNAT，浮动 IP）

+   端口安全（ARP 欺骗）

+   服务质量（QoS）

+   配额管理

+   Neutron 可插拔 IPAM

+   通过 neutron 实现良好集成的 COE 负载平衡

+   用于容器的 FWaaS

# Kuryr 架构

在接下来的章节中，我们将看一下 Kuryr 的架构。

# 将 Docker libnetwork 映射到 neutron API

以下图表显示了 Kuryr 的架构，将 Docker libnetwork 网络模型映射到 neutron API。Kuryr 映射**libnetwork** API 并在 neutron 中创建适当的资源，这就解释了为什么**Neutron API**也可以用于容器网络：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00022.jpeg)

# 提供通用的 VIF 绑定基础设施

Kuryr 为各种端口类型提供了通用的 VIF 绑定机制，这些端口类型将从 Docker 命名空间接收并根据其类型附加到网络解决方案基础设施，例如**Linux 桥接口端口**，**Open vSwitch 端口**，**Midonet 端口**等。以下图表表示了这一点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00023.jpeg)

# 提供 neutron 插件的容器化镜像

Kuryr 旨在提供与 Kolla 集成的各种 neutron 插件的容器化镜像。

# 嵌套虚拟机和 Magnum 用例

Kuryr 在容器网络方面解决了 Magnum 项目的用例，并作为 Magnum 或任何其他需要通过 neutron API 利用容器网络的 OpenStack 项目的统一接口。在这方面，Kuryr 利用支持 VM 嵌套容器用例的 neutron 插件，并增强 neutron API 以支持这些用例（例如，OVN）。

# Kuryr 的安装

在本节中，我们将看到如何安装 Kuryr。先决条件如下：

+   KeyStone

+   Neutron

+   DB 管理系统，如 MySQL 或 MariaDB（用于 neutron 和 KeyStone）

+   您选择的供应商的 Neutron 代理

+   如果您选择的 neutron 代理需要，Rabbitmq

+   Docker 1.9+

以下步骤在 Docker 容器内运行 Kuryr：

1.  拉取上游 Kuryr libnetwork Docker 镜像：

```
        $ docker pull kuryr/libnetwork:latest  
```

1.  准备 Docker 以找到 Kuryr 驱动程序：

```
        $ sudo mkdir -p /usr/lib/docker/plugins/kuryr
       $ sudo curl -o /usr/lib/docker/plugins/kuryr/kuryr.spec \ 
                     https://raw.githubusercontent.com/openstack/kuryr-
        libnetwork/master/etc/kuryr.spec
        $ sudo service docker restart  
```

1.  启动 Kuryr 容器：

```
        $ docker run --name kuryr-libnetwork \
        --net=host \
        --cap-add=NET_ADMIN \
        -e SERVICE_USER=admin \;
        -e SERVICE_PROJECT_NAME=admin \
        -e SERVICE_PASSWORD=admin \
        -e SERVICE_DOMAIN_NAME=Default \
        -e USER_DOMAIN_NAME=Default \
        -e IDENTITY_URL=http://127.0.0.1:35357/v3 \
        -v /var/log/kuryr:/var/log/kuryr \
        -v /var/run/openvswitch:/var/run/openvswitch \
                  kuryr/libnetwork  
```

这里：

+   `SERVICE_USER`，`SERVICE_PROJECT_NAME`，`SERVICE_PASSWORD`，`SERVICE_DOMAIN_NAME`和`USER_DOMAIN_NAME`是 OpenStack 凭据

+   `IDENTITY_URL`是指向 OpenStack KeyStone v3 端点的 URL

+   创建卷，以便日志在主机上可用

+   为了在主机命名空间上执行网络操作，例如`ovs-vsctl`，需要给予`NET_ADMIN`权限

# 演练

Kuryr 存在于运行容器并为 libnetwork 远程网络驱动程序提供所需的 API 的每个主机中。

以下是执行创建由 neutron 提供的容器网络的步骤：

1.  用户向 libnetwork 发送请求，以使用 Kuryr 作为网络驱动程序指定符创建 Docker 网络。以下示例创建名为 bar 的 Docker 网络：

```
        $ sudo docker network create --driver=kuryr --ipam-driver=kuryr --
        subnet 10.0.0.0/16 --gateway 10.0.0.1 --ip-range 10.0.0.0/24 bar  
```

1.  libnetwork 调用 Kuryr 插件创建网络

1.  Kuryr 将调用转发给 Neutron，Neutron 使用 Kuryr 提供的输入数据创建网络

1.  收到来自 neutron 的响应后，它准备输出并将其发送到 libnetwork

1.  libnetwork 将响应存储到其键/值数据存储后端

1.  用户可以使用先前创建的网络启动容器：

```
        $ sudo docker run --net=bar -itd --name=nginx-container nginx
```

# 总结

在本章中，我们了解了 Kuryr。我们了解了 Kuryr 是什么，它的架构以及安装过程。我们还看了用户使用 Kuryr 作为网络驱动程序创建 Docker 网络时的整体工作流程。

下一章将重点介绍 Murano 项目。我们将了解 Murano 及其架构，并完成实际操作练习。


# 第八章：Murano - 在 OpenStack 上的容器化应用部署

本章将解释 OpenStack 项目 Murano，它是 OpenStack 的应用程序目录，使应用程序开发人员和云管理员能够发布各种云就绪应用程序在一个可浏览的分类目录中。Murano 大大简化了在 OpenStack 基础设施上的应用程序部署，只需点击一下即可。在本章中，我们将讨论以下主题：

+   Murano 简介

+   Murano 概念

+   主要特点

+   Murano 组件

+   演练

+   Murano DevStack 安装

+   部署容器化应用程序

# Murano 简介

Murano 是 OpenStack 应用程序目录服务，提供各种云就绪应用程序，可以轻松部署在 OpenStack 上，抽象出所有复杂性。它简化了在 OpenStack IaaS 上打包和部署各种应用程序。它是外部应用程序和 OpenStack 的集成点，支持应用程序的完整生命周期管理。Murano 应用程序可以在 Docker 容器或 Kubernetes Pod 中运行。

Murano 是一个强大的解决方案，适用于寻求在 OpenStack 上部署应用程序的最终用户，他们不想担心部署复杂性。

以下是 Murano 提供的功能列表：

+   提供生产就绪的应用程序和动态 UI

+   支持运行容器化应用程序

+   支持在 Windows 和 Linux 系统上部署应用程序

+   使用 Barbican 保护数据

+   支持使用**Heat Orchestration Templates** (**HOT**)运行应用程序包

+   部署多区域应用程序

+   允许将 Cinder 卷附加到应用程序中的 VM，并将包存储在 Glare 中

+   将类似的包打包在一起，比如基于容器的应用程序

+   为计费目的提供与环境和应用程序相关的统计信息

# Murano 概念

在这一部分，我们将讨论 Murano 中使用的不同概念。

# 环境

在 Murano 中，环境表示由单个租户管理的一组应用程序。没有两个租户可以共享环境中的应用程序。另外，一个环境中的应用程序与其他环境是独立的。在一个环境中逻辑相关的多个应用程序可以共同形成一个更复杂的应用程序。

# 打包

Murano 中的软件包是一个 ZIP 存档，其中包含所有安装脚本、类定义、动态 UI 表单、图像列表和应用部署的指令。这个软件包被 Murano 导入并用于部署应用程序。可以将各种软件包上传到 Murano 以用于不同的应用程序。

# 会话

Murano 允许来自不同位置的多个用户对环境进行修改。为了允许多个用户同时进行修改，Murano 使用会话来存储所有用户的本地修改。当将任何应用程序添加到环境时，会创建一个会话，部署开始后，会话将变为无效。会话不能在多个用户之间共享。

# 环境模板

一组应用程序可以形成一个复杂的应用程序。为了定义这样的应用程序，Murano 使用**环境模板**的概念。模板中的每个应用程序由单个租户管理。可以通过将模板转换为环境来部署此模板。

# 部署

部署用于表示安装应用程序的过程。它存储环境状态、事件和任何应用程序部署中的错误等信息。

# 包

在 Murano 中，包代表一组类似的应用程序。包中的应用程序不需要紧密相关。它们根据使用情况进行排序。

一个例子是，创建一个由 MySQL 或 Oracle 应用程序组成的数据库应用程序包。可以直接在 Murano 中导入一个包，这将依次导入包中的所有应用程序。

# 类别

应用程序可以根据其类型分为不同的类别，例如应用程序服务器、大数据和数据库。

# 关键特性

Murano 具有许多先进的功能，使其成为 OpenStack 上应用程序管理的强大解决方案。在本节中，我们将讨论 Murano 中的一些高级功能。

# 生产就绪的应用程序

Murano 有各种云就绪的应用程序，可以在 VM 或裸金属上非常轻松地配置。这不需要任何安装、基础设施管理等知识，使得对于 OpenStack 用户来说，部署复杂应用程序变得非常容易。用户可以选择在 Docker 主机或 Kubernetes Pod 上运行他们的应用程序。

# 应用程序目录 UI

Murano 为最终用户提供了一个界面，可以轻松浏览可用的应用程序。用户只需点击一个按钮即可部署任何复杂的应用程序。该界面是动态的，它在应用程序被部署时提供用户输入的表单。它还允许应用程序标记，提供有关每个应用程序的信息，显示最近的活动等。

# 分发工作负载

Murano 允许用户在部署任何应用程序时选择区域。这样，您的应用程序可以在跨区域进行分布，以实现可伸缩性和高可用性，同时进行任何灾难恢复。

# 应用程序开发

**Murano 编程语言**（**MuranoPL**）可用于定义应用程序。它使用 YAML 和 YAQL 进行应用程序定义。它还具有一些核心库，定义了几个应用程序中使用的常见函数。MuranoPL 还支持垃圾回收，这意味着它会释放应用程序的所有资源。

# Murano 存储库

Murano 支持从不同来源安装包，如文件、URL 和存储库。Murano 可以从自定义存储库导入应用程序包。它会从存储库下载所有依赖的包和镜像（如果已定义）以进行应用程序部署。

请参考[`docs.openstack.org/murano/latest/admin/appdev-guide/muranopackages/repository.html`](https://docs.openstack.org/murano/latest/admin/appdev-guide/muranopackages/repository.html)设置自定义存储库。

# Cinder 卷

Murano 支持将 Cinder 卷附加到应用程序中的虚拟机，并支持从 Cinder 卷引导这些虚拟机。可以附加多个卷到应用程序以用于存储目的。

请参考[`docs.openstack.org/murano/latest/admin/appdev-guide/cinder_volume_supporting.html`](https://docs.openstack.org/murano/latest/admin/appdev-guide/cinder_volume_supporting.html)了解如何在 Murano 中使用 Cinder 卷的详细步骤。

# Barbican 支持

Barbican 是 OpenStack 项目，用于支持诸如密码和证书之类的敏感数据。Murano 确保通过将数据存储在 Barbican 中来保护您的数据。您需要安装 Barbican，并配置 Murano 以使用 Barbican 作为后端存储解决方案。

# HOT 包

Murano 支持从 Heat 模板中组合应用程序包。您可以将任何 Heat 模板添加到 Murano 作为新的部署包。Murano 支持从 Heat 模板自动和手动组合应用程序包的方式。

有关在 Murano 中使用 Heat 模板的详细信息，请参阅[`docs.openstack.org/murano/latest/admin/appdev-guide/hot_packages.html`](https://docs.openstack.org/murano/latest/admin/appdev-guide/hot_packages.html)。

# Murano 组件

*The Murano dashboard*部分的图解释了 Murano 的架构。Murano 具有与其他 OpenStack 组件类似的架构。它也有 API 服务和引擎作为主要组件。还有其他组件，如`murano-agent`，Murano 仪表板和 python 客户端，即`murano-pythonclient`。让我们详细看看每个组件。

# Murano API

Murano API（`murano-api`）是一个 WSGI 服务器，用于为用户提供 API 请求。Murano API 针对每种资源类型都有不同的控制器。每个控制器处理特定资源的请求。它们验证权限的请求，验证请求中提供的数据，并为具有输入数据的资源创建一个 DB 对象。请求被转发到`murano-engine`服务。收到来自`murano-engine`的响应后，`murano-api`服务将响应返回给用户。

# Murano 引擎

Murano 引擎（`murano-engine`）是大部分编排发生的地方。它向 Heat（OpenStack 编排服务）发出一系列调用，以创建部署应用程序所需的基础资源，如 VM 和卷。它还在 VM 内启动一个名为`murano-agent`的代理，以安装外部应用程序。

# Murano 代理

Murano 代理（`murano-agent`）是在部署的虚拟机内运行的服务。它在虚拟机上进行软件配置和安装。VM 镜像是使用此代理构建的。

# Murano 仪表板

Murano 仪表板为用户提供 Web UI，以便轻松浏览访问 Murano 中可用的应用程序。它支持基于角色的访问控制：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00024.jpeg)

# 步骤

在本节中，我们将介绍 Murano 如何部署应用程序。Murano 与多个 OpenStack 服务进行交互，以获取应用程序部署所需的资源。

在 Murano 中部署应用程序的请求流程如下：

1.  用户在收到 KeyStone 的身份验证令牌后，通过 CLI 或 Horizon 向`murano-api`服务发送 REST API 调用以部署环境

1.  `murano-api`服务接收请求，并向 KeyStone 发送验证令牌和访问权限的请求

1.  KeyStone 验证令牌，并发送带有角色和权限的更新身份验证标头

1.  `murano-api`服务检查会话是否有效。如果会话无效或已部署，则请求将以`403` HTTP 状态失败

1.  检查以确定之前是否已删除环境。如果未删除，则在任务表中创建条目以存储此操作的信息

1.  `murano-api`服务通过 RPC 异步调用将请求发送到`murano-engine`服务，JSON 对象包含类类型、应用程序详情和用户数据（如果有的话）

1.  `murano-engine`服务从消息队列中接收请求

1.  它创建一个将与应用程序一起使用的 KeyStone 信任

1.  它下载所需的软件包，并验证所需的类是否可用和可访问

1.  `murano-engine`服务然后创建模型中定义的所有类

1.  然后调用每个应用程序的部署方法。在此阶段，`murano-engine`与 Heat 交互以创建应用程序运行所需的网络、虚拟机和其他资源

1.  实例运行后，将运行一个用户数据脚本来安装和运行 VM 上的`murano-agent`

1.  `murano-agent`服务执行软件配置和安装步骤

1.  安装完成后，`murano-engine`向 API 服务发送关于完成情况的响应

1.  `murano-api`服务然后在数据库中将环境标记为已部署

# Murano DevStack 安装

我们现在将看到如何使用 DevStack 安装 Murano 的开发设置。

1.  如有需要，为 DevStack 创建根目录：

```
        $ sudo mkdir -p /opt/stack
        $ sudo chown $USER /opt/stack  
```

1.  克隆 DevStack 存储库：

```
        $ git clone https://git.openstack.org/openstack-dev/devstack 
        /opt/stack/devstack

```

1.  现在创建一个用于运行 DevStack 设置的最小`local.conf`：

```
        $ cat > /opt/stack/devstack/local.conf << END
        [[local|localrc]]
        HOST_IP=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print
        $2}' | cut -f1  -d'/')
        DATABASE_PASSWORD=password
        RABBIT_PASSWORD=password
        SERVICE_TOKEN=password
        SERVICE_PASSWORD=password
        ADMIN_PASSWORD=password
        enable_plugin murano git://git.openstack.org/openstack/murano
        END 
```

1.  现在运行 DevStack：

```
        $ cd /opt/stack/devstack
        $ ./stack.sh  
```

现在应该已安装 Murano。要验证安装，请运行以下命令：

```
$ sudo systemctl status devstack@murano-*
 devstack@murano-engine.service - Devstack devstack@murano-
engine.service
 Loaded: loaded (/etc/systemd/system/devstack@murano-
engine.service; enabled; vendor preset: enabled)
 Active: active (running) since Thu 2017-11-02 04:32:28 EDT; 2 
weeks 5 days ago
 Main PID: 30790 (murano-engine)
 CGroup: /system.slice/system-devstack.slice/devstack@murano-
engine.service
 ├─30790 /usr/bin/python /usr/local/bin/murano-engine --
config-file /etc/murano/murano.conf
 ├─31016 /usr/bin/python /usr/local/bin/murano-engine --
config-file /etc/murano/murano.conf
 ├─31017 /usr/bin/python /usr/local/bin/murano-engine --
config-file /etc/murano/murano.conf
 ├─31018 /usr/bin/python /usr/local/bin/murano-engine --
config-file /etc/murano/murano.conf
 └─31019 /usr/bin/python /usr/local/bin/murano-engine --
config-file /etc/murano/murano.conf
 devstack@murano-api.service - Devstack devstack@murano-api.service
 Loaded: loaded (/etc/systemd/system/devstack@murano-api.service; 
enabled; vendor preset: enabled)
 Active: active (running) since Thu 2017-11-02 04:32:26 EDT; 2 
weeks 5 days ago
 Main PID: 30031 (uwsgi)
 Status: "uWSGI is ready"
 CGroup: /system.slice/system-devstack.slice/devstack@murano-
api.service
 ├─30031 /usr/local/bin/uwsgi --ini /etc/murano/murano-api-
uwsgi.ini
 ├─30034 /usr/local/bin/uwsgi --ini /etc/murano/murano-api-
uwsgi.ini
 └─30035 /usr/local/bin/uwsgi --ini /etc/murano/murano-api-
uwsgi.ini
```

您可以看到`murano-api`和`murano-engine`服务都已启动并运行。

# 部署容器化应用程序

在前一节中，您学习了如何使用 DevStack 安装 Murano。现在我们将看到如何使用 Murano 来在 OpenStack 上安装应用程序。由于 Murano 提供了可浏览的动态 UI，我们将使用 Horizon 中的应用程序目录选项卡来运行我们的应用程序。

在此示例中，我们将在 Docker 中安装一个 NGINX 容器化应用程序。我们将需要以下软件包来运行此应用程序：

+   Docker 接口库：此库定义了构建 Docker 应用程序的框架。它提供了所有应用程序和由 Docker 支持的主机服务使用的数据结构和常用接口。

+   Docker 独立主机：这是一个常规的 Docker 主机应用程序。所有容器应用程序都在运行使用 Docker 和`murano-agent`构建的映像的专用 VM 内运行。

+   Kubernetes Pod：此应用程序提供了在 OpenStack VM 上使用 Kubernetes 运行容器化应用程序的基础设施。这对于 Docker 独立主机应用程序是可选的。

+   Nginx 应用程序：Nginx 是一个 Web 服务器应用程序，将使用 Docker 独立主机或 Kubernetes Pod 应用程序运行。

所有 Murano 的容器应用程序都可以在[`github.com/openstack/k8s-docker-suite-app-murano`](https://github.com/openstack/k8s-docker-suite-app-murano)找到。

现在让我们开始使用 Murano 仪表板来运行我们的容器应用程序。通过输入您的凭据登录到您的 Horizon 仪表板：

1.  从[`github.com/openstack/k8s-docker-suite-app-murano`](https://github.com/openstack/k8s-docker-suite-app-murano)下载软件包

1.  为上述列出的每个应用程序创建一个`.zip`存档

1.  现在在仪表板上导航到应用程序目录|管理|软件包

1.  点击导入软件包

选择文件作为软件包源，并浏览上传您的应用程序的 ZIP 文件。填写每个应用程序所需的 UI 表单，并单击“单击完成上传软件包”。现在，通过导航到应用程序目录|浏览|本地浏览，您可以浏览可用的应用程序。您将看到这样的页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00025.jpeg)

1.  按照[`github.com/openstack/k8s-docker-suite-app-murano/tree/master/DockerStandaloneHost/elements`](https://github.com/openstack/k8s-docker-suite-app-murano/tree/master/DockerStandaloneHost/elements)中提供的步骤构建 VM 映像

1.  标记要由 Murano 使用的图像。导航到应用程序目录|管理|标记的图像，单击标记图像，并按照以下截图中提供的详细信息填写：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00026.jpeg)

1.  通过单击快速部署来部署应用程序

您可以在下面的截图中看到，我们有两个选择供我们选择作为容器主机：Kubernetes Pod 和 Docker 独立主机。我们将选择后者作为选项：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00027.jpeg)

1.  填写要为我们的应用程序创建的 VM 的详细信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00028.jpeg)

1.  单击创建以创建我们部署的环境

您将被自动重定向到应用程序目录|应用程序|环境中新创建的环境。

1.  单击部署环境以开始安装您的应用程序和所需的基础设施。

您将看到下面的截图，显示它开始创建 VM，Docker 将在其上运行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00029.jpeg)

在前面的部署成功完成后，您将能够看到一个新的虚拟机被创建，如下面的截图所示，并且您的 Nginx 应用程序在 VM 内的 Docker 容器中运行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00030.jpeg)

您可以登录到 VM 并访问 Nginx 应用程序。我们现在已经成功在 OpenStack 上安装了一个容器化的 Nginx 应用程序。

# 摘要

在本章中，您详细了解了 Murano，这是 OpenStack 的应用程序目录服务。我们深入研究了 Murano 中可用的不同概念。然后，您还了解了 Murano 的组件和架构。本章还详细概述了用户请求使用 Murano 部署应用程序的工作流程。然后我们看到如何使用 DevStack 安装 Murano 的开发设置，并且我们在使用 Murano 仪表板创建环境，向其添加应用程序并部署环境时进行了实际操作。

在下一章中，您将了解 Kolla，它提供了用于部署 OpenStack 服务的生产就绪容器和工具。


# 第九章：Kolla - OpenStack 的容器化部署

在本章中，您将了解 Kolla。它为操作 OpenStack 云提供了生产就绪的容器和部署工具。本章的内容如下：

+   Kolla 介绍

+   关键特性

+   架构

+   部署容器化的 OpenStack 服务

# Kolla 介绍

OpenStack 云由多个服务组成，每个服务与其他服务进行交互。OpenStack 没有集成的产品发布。每个项目在每 6 个月后都会遵循一个发布周期。这为运营商提供了更大的灵活性，可以从多个选项中进行选择，并为他们构建自定义的部署解决方案。然而，这也带来了部署和管理 OpenStack 云的复杂性。

这些服务需要可扩展、可升级和随时可用。Kolla 提供了一种在容器内运行这些服务的方式，这使得 OpenStack 云具有快速、可靠、可扩展和可升级的优势。Kolla 打包了 OpenStack 服务及其要求，并在容器镜像中设置了所有配置。

Kolla 使用 Ansible 来运行这些容器镜像，并在裸金属或虚拟机上非常容易地部署或升级 OpenStack 集群。Kolla 容器被配置为将数据存储在持久存储上，然后可以重新挂载到主机操作系统上，并成功恢复以防止任何故障。

为了部署 OpenStack，Kolla 有三个项目如下：

+   **kolla:** 所有 OpenStack 项目的 Docker 容器镜像都在这个项目中维护。Kolla 提供了一个名为 kolla-build 的镜像构建工具，用于为大多数项目构建容器镜像。

+   **kolla-ansible:** 这提供了用于在 Docker 容器内部部署 OpenStack 的 Ansible 剧本。它支持 OpenStack 云的一体化和多节点设置。

+   **kolla-kubernetes:** 这在 Kubernetes 上部署 OpenStack。它旨在利用 Kubernetes 的自愈、健康检查、升级和其他功能，用于管理容器化的 OpenStack 部署。kolla-kubernetes 使用 Ansible 剧本和 Jinja2 模板来生成服务的配置文件。

# 关键特性

在本节中，我们将看到 Kolla 的一些关键特性。

# 高可用部署

OpenStack 生态系统由多个服务组成，它们只运行单个实例，有时会成为任何灾难的单点故障，并且无法扩展到单个实例之外。为了使其可扩展，Kolla 部署了配置了 HA 的 OpenStack 云。因此，即使任何服务失败，也可以在不中断当前操作的情况下进行扩展。这个特性使 Kolla 成为一个理想的解决方案，可以轻松升级和扩展而无需任何停机时间。

# Ceph 支持

Kolla 使用 Ceph 向运行我们的 OpenStack 环境的虚拟机添加持久数据，以便我们可以轻松从任何灾难中恢复，从而使 OpenStack 云更加可靠。Ceph 还用于存储 glance 镜像。

# 图像构建

Kolla 提供了一个名为 kolla-build 的工具，可以在 CentOs、Ubuntu、Debian 和 Oracle Linux 等多个发行版上构建容器镜像。可以一次构建多个依赖组件。

# Docker Hub 支持

您可以直接从 Docker Hub 拉取图像。您可以在[`hub.docker.com/u/kolla/`](https://hub.docker.com/u/kolla/)上查看所有 Kolla 图像。

# 本地注册表支持

Kolla 还支持将图像推送到本地注册表。有关设置本地注册表，请参阅[`docs.openstack.org/kolla-ansible/latest/user/multinode.html#deploy-a-registry`](https://docs.openstack.org/kolla-ansible/latest/user/multinode.html#deploy-a-registry)。

# 多个构建源

Kolla 支持从多个源构建二进制和源代码。二进制是由主机操作系统的软件包管理器安装的软件包，而源代码可以是 URL、本地存储库或 tarball。有关更多详细信息，请参阅[`docs.openstack.org/kolla/latest/admin/image-building.html#build-openstack-from-source`](https://docs.openstack.org/kolla/latest/admin/image-building.html#build-openstack-from-source)。

# Dockerfile 定制

Kolla 支持从 Jinja2 模板构建图像，这为运营商提供了更好的灵活性。运营商可以定制他们的图像构建，包括安装附加软件包、安装插件、更改一些配置设置等。有关如何进行不同定制的更多详细信息，请参阅[`docs.openstack.org/kolla/latest/admin/image-building.html#dockerfile-customisation`](https://docs.openstack.org/kolla/latest/admin/image-building.html#dockerfile-customisation)。

# 架构

在本节中，我们将看到使用 Kolla 的 OpenStack 架构。以下图显示了 Kolla 完成的**高可用**（**HA**）OpenStack 多模式设置。

这里的基础设施工程意味着为基础设施管理编写的代码或应用程序。代码提交到 Gerrit 进行审查，然后 CI 系统审查并检查代码的正确性。一旦代码获得 CI 的批准，CD 系统将构建的输出，即基于 Kolla 的 OpenStack 容器，输入到本地注册表中。

之后，Ansible 联系 Docker，并使用 HA 启动我们的 OpenStack 多节点环境：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00031.jpeg)

# 部署容器化的 OpenStack 服务

在本节中，我们将了解 Kolla 如何使用 kolla-ansible 部署容器化的 OpenStack。在撰写本文时，kolla-kubernetes 正在开发中。

请注意，这不是 Kolla 的完整指南。

Kolla 现在正在发展，因此指南经常进行升级。请参考[`docs.openstack.org/kolla-ansible/latest/`](https://docs.openstack.org/kolla-ansible/latest/)提供的最新文档。我们将尝试解释使用 Kolla 和子项目部署 OpenStack 的一般过程。

使用 Kolla 部署 OpenStack 非常容易。Kolla 在 Docker 或 Kubernetes 上提供全功能和多节点安装。基本上涉及四个步骤：

+   设置本地注册表

+   自动主机引导

+   构建镜像

+   部署镜像

# 设置本地注册表

Kolla 构建的容器镜像需要一个本地注册表进行存储。对于全功能部署来说，这是可选的，可以使用 Docker 缓存。Docker Hub 包含 Kolla 所有主要版本的所有镜像。但是，强烈建议多节点部署确保镜像的单一来源。还建议在生产环境中通过 HTTPS 运行注册表以保护镜像。

有关设置本地注册表的详细步骤，请参考[`docs.openstack.org/kolla-ansible/latest/user/multinode.html#deploy-a-registry`](https://docs.openstack.org/kolla-ansible/latest/user/multinode.html#deploy-a-registry)的指南。

# 自动主机引导

Kolla 安装需要在我们希望运行 OpenStack 的主机上安装一些软件包和工具，例如 Docker、libvirt 和 NTP。这些依赖项可以通过主机引导自动安装和配置。kolla-ansible 提供了用于准备和安装 OpenStack 主机的 bootstrap-servers playbook。

要快速准备主机，请运行此命令：

```
$ kolla-ansible -i <inventory_file> bootstrap-servers  
```

# 构建镜像

在这一步中，我们将为所有 OpenStack 服务构建 Docker 容器镜像。在构建镜像时，我们可以指定镜像的基本发行版、来源和标签。这些镜像将被推送到本地注册表。

在 Kolla 中构建镜像就像运行此命令一样简单：

```
$ kolla-build  
```

此命令默认构建基于 CentOS 的所有镜像。要使用特定的发行版构建镜像，请使用`-b`选项：

```
$ kolla-build -b ubuntu  
```

要为特定项目构建镜像，请将项目名称传递给命令：

```
$ kolla-build nova zun  
```

Kolla 中的一个高级功能是镜像配置文件。配置文件用于定义 OpenStack 中一组相关的项目。Kolla 中定义的一些配置文件如下：

+   **infra**：所有基础设施相关的项目

+   **main**：这些是 OpenStack 的核心项目，如 Nova、Neutron、KeyStone 和 Horizon

+   **aux**：这些是额外的项目，如 Zun 和 Ironic

+   **default**：这是一个准备好的云所需的一组最小项目

也可以在`kolla-build.conf`对象中定义新的配置文件。只需在`.conf`文件的`[profile]`部分下添加一个新的配置文件即可：

```
[profiles]
containers=zun,magnum,heat  
```

在上面的示例中，我们设置了一个名为`containers`的新配置文件，用于表示 OpenStack 中与容器化相关的一组项目。还提到并使用了`heat`项目，因为它是`magnum`所需的。此外，您还可以使用此配置文件为这些项目创建镜像：

```
$ kolla-build -profile containers  
```

还可以使用这些命令将镜像推送到 Docker Hub 或本地注册表：

```
$ kolla-build -push # push to Docker Hub
$ kolla-build -registry <URL> --push # push to local registry  
```

Kolla 还提供了更高级的操作，例如从源代码和 Docker 文件自定义构建镜像。您可以参考[`docs.openstack.org/kolla/latest/admin/image-building.html`](https://docs.openstack.org/kolla/latest/admin/image-building.html) [获取更多详细信息。](https://docs.openstack.org/kolla/latest/admin/image-building.html)

# 部署镜像

现在我们已经准备好部署 OpenStack 所需的所有镜像；kolla-ansible 联系 Docker 并提供这些镜像来运行它们。部署可以是单一节点或多节点。决定是在 kolla-ansible 中可用的 Ansible 清单文件上做出的。此清单文件包含集群中基础设施主机的信息。Kolla 中的部署过程需要环境变量和密码，这些变量和密码在配置文件和清单文件中指定，以配置高可用性的 OpenStack 集群。

用于 OpenStack 部署的所有配置选项和密码分别存储在`/etc/kolla/globals.yml`和`/etc/kolla/passwords.yml`中。手动编辑这些文件以指定您选择的安装，如下所示：

```
kolla_base_distro: "centos"
kolla_install_type: "source"  
```

您可以使用以下命令生成密码：

```
$ kolla-genpwd  
```

您可以在部署目标节点上运行`prechecks`来检查它们是否处于状态：

```
$ kolla-ansible prechecks -i <inventory-file>  
```

现在我们准备好部署 OpenStack。运行以下命令：

```
$ kolla-ansible deploy -i <inventory-file>  
```

要验证安装，请查看`docker`中的容器列表：

```
$ docker ps -a  
```

您应该看到所有运行的 OpenStack 服务容器。现在让我们生成`admin-openrc.sh`文件以使用我们的 OpenStack 集群。生成的文件将存储在`/etc/kolla`目录中：

```
$ kolla-ansible post-deploy  
```

现在安装`python-openstackclient`：

```
$ pip install python-openstackclient  
```

要初始化 neutron 网络和 glance 镜像，请运行此命令：

```
$ . /etc/kolla/admin-openrc.sh
#On centOS
$ /usr/share/kolla-ansible/init-runonce
#ubuntu
$ /usr/local/share/kolla-ansible/init-runonce  
```

成功部署 OpenStack 后，您可以访问 Horizon 仪表板。Horizon 将在`kolla_external_fqdn`或`kolla_internal_fqdn`中指定的 IP 地址或主机名处提供。如果在部署期间未设置这些变量，则它们默认为`kolla_internal_vip_address`。

有关使用 kolla-ansible 部署多节点 OpenStack 云的详细步骤，请参阅[`docs.openstack.org/project-deploy-guide/kolla-ansible/latest/multinode.html`](https://docs.openstack.org/project-deploy-guide/kolla-ansible/latest/multinode.html)，使用 kolla-kubernetes 请参阅[`docs.openstack.org/kolla-kubernetes/latest/deployment-guide.html`](https://docs.openstack.org/kolla-kubernetes/latest/deployment-guide.html)。

# 摘要

在本章中，您了解了 Kolla，它部署了一个容器化的 OpenStack 云。我们看了看 Kolla 中可用的各种项目，并了解了它们的一般功能。然后我们深入了解了 Kolla 的一些关键特性，并讨论了 OpenStack 部署的 Kolla 架构。您还学会了如何使用 Kolla 构建镜像，并最终了解了 Kolla 的部署过程。

在下一章中，我们将探讨保护容器的最佳实践，以及使用不同 OpenStack 项目的优势。


# 第十章：容器和 OpenStack 的最佳实践

在本章中，我们将重点关注在 OpenStack 上运行容器的优势以及在 OpenStack 上部署和保护容器的最佳实践。具体来说，我们将关注以下主题：

+   不同 OpenStack 项目的优势

+   保护和部署容器的最佳实践

# 不同 OpenStack 项目的优势

OpenStack 提供容器平台和应用程序可以使用的资源和服务。它提供了构建可扩展云的标准。它还提供了共享网络、存储和许多其他高级服务。它具有可编程的 API，可用于按需创建基础设施。用户可以使用不同的 OpenStack 服务来处理他们的容器相关工作负载。

用户可以使用 Magnum 来提供和管理他们的 COE。Magnum 提供了多租户的能力，这意味着一个 COE 集群只属于一个租户。这使得容器隔离成为可能，属于不同租户的容器不会被调度到同一台主机上。Magnum 内置支持 Kubernetes、Swarm 和 Mesos。Magnum 还提供 TLS 支持，以确保集群内部服务和外部世界之间的安全通信。

用户可以使用 Zun 直接在 OpenStack 上部署他们的容器工作负载，而不使用 COEs。Zun 提供完整的容器生命周期管理支持。它还通过 Kuryr 提供 Docker 网络支持。这意味着用户可以使用 Neutron 网络来处理他们的容器和虚拟机工作负载，并在其中相互访问。Zun 还为容器提供了 OpenStack Cinder 支持，用于持久存储。Zun 具有内置的多租户能力，并使用 KeyStone 进行身份验证支持。

OpenStack Kolla 提供支持，可以在容器内部部署 OpenStack 服务。这将产生新的、快速的、可靠的、可组合的构建模块。Kolla 通过将每个服务大部分打包为 Docker 容器中的微服务，简化了部署和持续运营。用户可以使用 Kolla 将 OpenStack 服务部署在 Docker 容器或 Kubernetes pod 中。

用户可以使用 Murano 在 OpenStack 上部署他们的容器化应用程序。Murano 将为部署创建基础设施并在其上部署容器化应用程序。

# 保护和部署容器的最佳实践

由于其模块化和在服务器之间的可移植性，容器正在取代虚拟机来运行大部分企业软件。然而，容器也存在一些风险。一个明显的风险与通过克隆分发容器相关。如果基础镜像中存在未修补的漏洞，所有克隆和继承自基础镜像的应用程序也会受到影响。

第二个主要风险是容器系统的默认用户，即 root 用户。如果攻击者获得 root 用户的访问权限，他不仅可以访问其他容器内部，还可以获得主机操作系统中的 root 权限。这可能是毁灭性的！

以下是一些保护和部署容器的最佳实践：

+   用户应始终使用轻量级 Linux 操作系统。轻量级操作系统可以减少攻击的机会。它还使应用更新变得更加容易。

+   用户应保持所有容器镜像更新。保持所有镜像更新可以确保它们没有最新的漏洞。始终将您的镜像保存在集中式存储库中，并对其进行版本控制和标记。

+   用户应自动化所有安全更新。这可以确保补丁快速应用到您的基础设施上。

+   用户应始终扫描其容器镜像以查找潜在缺陷。有许多扫描工具，如 CoreOS 的 Clair，Dockscan 和 Twistlock，它们会将容器清单与已知漏洞列表进行比较，并在检测到任何漏洞时向您发出警报。

+   用户不应在容器中运行多余的面向网络的服务。

+   用户应避免在容器内挂载主机目录，因为这可能会使容器内部的主机敏感数据暴露出来。

+   用户应始终对容器的资源消耗定义限制。这将有助于避免主机上所有资源的消耗，并使其他容器陷入饥饿状态。

+   用户应保护他们的 Docker 主机，并且不应向其他用户提供 root 用户的敏感信息。

+   用户应该使用 TLS 运行他们的 Docker 注册表。只有有效用户才能拉取和推送镜像到注册表。

+   用户应始终监视容器行为以发现异常。

+   用户可以使用清晰的容器或开源 Hyper 来提供更多安全性，因为它们提供更多的隔离。

# 总结

在整本书中，我们遇到了 OpenStack 中几个与容器相关的项目以及它们的关键特性。在本章中，我们总结了本书中所有项目的优势，用于运行容器工作负载。我们还解释了容器中的不同安全问题以及解决这些问题的最佳实践。
