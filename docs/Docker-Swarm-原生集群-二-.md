# Docker Swarm 原生集群（二）

> 原文：[`zh.annas-archive.org/md5/9B6C0DB62EFC5AC8A8FAA5F289DFA59D`](https://zh.annas-archive.org/md5/9B6C0DB62EFC5AC8A8FAA5F289DFA59D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：管理 Swarm 集群

现在我们将看到如何管理运行中的 Swarm 集群。我们将详细讨论诸如扩展集群大小（添加和删除节点）、更新集群和节点信息；处理节点状态（晋升和降级）、故障排除和图形界面（UI）等主题。

在本章中，我们将看一下以下主题：

+   Docker Swarm 独立

+   Docker Swarm 模式

+   集群管理

+   Swarm 健康

+   Swarm 的图形界面

# Docker Swarm 独立

在独立模式下，集群操作需要直接在`swarm`容器内完成。

在本章中，我们不会详细介绍每个选项。Swarm v1 很快将被弃用，因为 Swarm 模式已经被宣布为过时。

![Docker Swarm 独立模式](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_05_001.jpg)

管理 Docker Swarm 独立集群的命令如下：

+   创建（`c`）：正如我们在第一章中所看到的，*欢迎来到 Docker Swarm*，这是我们生成 UUID 令牌的方式，以防令牌机制将被使用。通常，在生产环境中，人们使用 Consul 或 Etcd，因此这个命令对生产环境没有相关性。

+   列表（`l`）：这显示了基于对 Consul 或 Etcd 的迭代的集群节点列表，也就是说，Consul 或 Etcd 必须作为参数传递。

+   加入（`j`）：将运行 swarm 容器的节点加入到集群中。在这里，我们需要在命令行中传递一个发现机制。

+   管理（`m`）：这是独立模式的核心。管理集群涉及更改集群属性，例如过滤器、调度程序、外部 CA URL 和超时。当我们在第六章中使用真实应用程序部署时，我们将更多地讨论这些选项在 Swarm 模式中的应用。

# Docker Swarm 模式

在本节中，我们将继续探索 Swarm 模式命令，以管理集群。

## 手动添加节点

您可以选择创建新的 Swarm 节点，即 Docker 主机，无论您喜欢哪种方式。

如果使用 Docker Machine，它很快就会达到极限。在列出机器时，您将不得不非常耐心地等待几秒钟，直到 Machine 获取并打印整个信息。

手动添加节点的方法是使用通用驱动程序的 Machine；因此，将主机配置（操作系统安装、网络和安全组配置等）委托给其他东西（比如 Ansible），然后利用 Machine 以适当的方式安装 Docker。这就是如何做到的：

1.  手动配置云环境（安全组、网络等）。

1.  使用第三方工具为 Ubuntu 主机提供支持。

1.  在这些主机上使用通用驱动程序运行机器，唯一的目标是正确安装 Docker。

1.  使用第二部分的工具管理主机，甚至其他的。

如果使用 Machine 的通用驱动程序，它将选择最新稳定的 Docker 二进制文件。在撰写本书时，为了使用 Docker 1.12，我们有时通过使用`--engine-install-url`选项，让 Machine 选择获取最新的不稳定版本的 Docker：

```
docker-machine create -d DRIVER --engine-install-url 
    https://test.docker.com mymachine

```

在阅读本书时，对于生产 Swarm（模式），1.12 将是稳定的；因此，除非你需要使用一些最新的 Docker 功能，否则这个技巧将不再必要。

## 管理者

在规划 Swarm 时，必须牢记一些关于管理者数量的考虑，正如我们在第四章中所看到的，*创建生产级 Swarm*。高可用性的理论建议管理者数量必须是奇数，并且等于或大于 3。为了在高可用性中获得法定人数，大多数节点必须同意领导操作的部分。

如果有两个管理者，其中一个宕机然后恢复，可能会导致两者都被视为领导者。这会导致集群组织中的逻辑崩溃，这被称为分裂脑。

你拥有的管理者越多，对故障的抵抗比就越高。看一下下表。

| **管理者数量** | **法定人数（多数）** | **最大可能故障数** |
| --- | --- | --- |
| 3 | 2 | 1 |
| 5 | 3 | 2 |
| 7 | 4 | 3 |
| 9 | 5 | 4 |

此外，在 Swarm 模式下，**ingress**覆盖网络会自动创建，并与节点关联为入口流量。它的目的是与容器一起使用：

![管理者](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_05_002.jpg)

你希望你的容器与内部覆盖（VxLAN meshed）网络关联，以便彼此通信，而不是使用公共或其他外部网络。因此，Swarm 会为您创建这个网络，并且它已经准备好使用。

## 工作者数量

您可以添加任意数量的工作节点。这是 Swarm 的弹性部分。拥有 5、15、200、2300 或 4700 个运行中的工作节点都是完全可以的。这是最容易处理的部分；您可以随时以任何规模添加和删除工作节点。

## 脚本化节点添加

如果您计划不超过 100 个节点，最简单的添加节点的方法是使用基本脚本。

在执行`docker swarm init`时，只需复制粘贴输出的行。

![脚本化节点添加](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_05_003.jpg)

然后，使用循环创建一组特定的工作节点：

```
#!/bin/bash
for i in `seq 0 9`; do
docker-machine create -d amazonec2 --engine-install-url 
    https://test.docker.com --amazonec2-instance-type "t2.large" swarm-
    worker-$i
done

```

之后，只需要浏览机器列表，`ssh`进入它们并`join`节点即可：

```
#!/bin/bash
SWARMWORKER="swarm-worker-"
for machine in `docker-machine ls --format {{.Name}} | grep 
    $SWARMWORKER`;
do
docker-machine ssh $machine sudo docker swarm join --token SWMTKN-
    1-5c3mlb7rqytm0nk795th0z0eocmcmt7i743ybsffad5e04yvxt-
    9m54q8xx8m1wa1g68im8srcme \
172.31.10.250:2377
done

```

此脚本将遍历机器，并对于每个以`s`warm-worker-`开头的名称，它将`ssh`进入并将节点加入现有的 Swarm 和领导管理者，即`172.31.10.250`。

### 注意

有关更多详细信息或下载一行命令，请参阅[`github.com/swarm2k/swarm2k/tree/master/amazonec2`](https://github.com/swarm2k/swarm2k/tree/master/amazonec2)。

## Belt

Belt 是用于大规模配置 Docker Engines 的另一种变体。它基本上是一个 SSH 包装器，需要您在`go`大规模之前准备提供程序特定的映像和配置模板。在本节中，我们将学习如何做到这一点。

您可以通过从 Github 获取其源代码来自行编译 Belt。

```
# Set $GOPATH here
go get https://github.com/chanwit/belt

```

目前，Belt 仅支持 DigitalOcean 驱动程序。我们可以在`config.yml`中准备我们的配置模板。

```
digitalocean:
image: "docker-1.12-rc4"
region: nyc3
ssh_key_fingerprint: "your SSH ID"
ssh_user: root

```

然后，我们可以用几个命令创建数百个节点。

首先，我们创建三个管理主机，每个主机有 16GB 内存，分别是`mg0`，`mg1`和`mg2`。

```
$ belt create 16gb mg[0:2]
NAME      IPv4         MEMORY  REGION         IMAGE           STATUS
mg2   104.236.231.136  16384   nyc3    Ubuntu docker-1.12-rc4  active
mg1   45.55.136.207    16384   nyc3    Ubuntu docker-1.12-rc4  active
mg0   45.55.145.205    16384   nyc3    Ubuntu docker-1.12-rc4  active

```

然后我们可以使用`status`命令等待所有节点都处于活动状态：

```
$ belt status --wait active=3
STATUS  #NODES  NAMES
active      3   mg2, mg1, mg0

```

我们将再次为 10 个工作节点执行此操作：

```
$ belt create 512mb node[1:10]
$ belt status --wait active=13

```

```
STATUS  #NODES  NAMES
active      3   node10, node9, node8, node7

```

## 使用 Ansible

您也可以使用 Ansible（我喜欢，而且它变得非常流行）来使事情更具重复性。我们已经创建了一些 Ansible 模块，可以直接与 Machine 和 Swarm（Mode）一起使用；它还与 Docker 1.12 兼容（[`github.com/fsoppelsa/ansible-swarm`](https://github.com/fsoppelsa/ansible-swarm)）。它们需要 Ansible 2.2+，这是与二进制模块兼容的第一个 Ansible 版本。

您需要编译这些模块（用`go`编写），然后将它们传递给`ansible-playbook -M`参数。

```
git clone https://github.com/fsoppelsa/ansible-swarm
cd ansible-swarm/library
go build docker-machine.go
go build docker_swarm.go
cd ..

```

playbooks 中有一些示例 play。Ansible 的 plays 语法非常容易理解，甚至不需要详细解释。

我使用这个命令将 10 个工作节点加入到**Swarm2k**实验中：

```
    ---    
name: Join the Swarm2k project
hosts: localhost
connection: local
gather_facts: False
#mg0 104.236.18.183
#mg1 104.236.78.154
#mg2 104.236.87.10
tasks:
name: Load shell variables
shell: >
eval $(docker-machine env "{{ machine_name }}")
echo $DOCKER_TLS_VERIFY &&
echo $DOCKER_HOST &&
echo $DOCKER_CERT_PATH &&
echo $DOCKER_MACHINE_NAME
register: worker
name: Set facts
set_fact:
whost: "{{ worker.stdout_lines[0] }}"
wcert: "{{ worker.stdout_lines[1] }}"
name: Join a worker to Swarm2k
docker_swarm:
role: "worker"
operation: "join"
join_url: ["tcp://104.236.78.154:2377"]
secret: "d0cker_swarm_2k"
docker_url: "{{ whost }}"
tls_path: "{{ wcert }}"
register: swarm_result
name: Print final msg
debug: msg="{{ swarm_result.msg }}"

```

基本上，它在加载一些主机信息后调用了`docker_swarm`模块：

+   操作是`join`

+   新节点的角色是`worker`

+   新节点加入了`tcp://104.236.78.154:2377`，这是加入时的领导管理者。这个参数接受一个管理者数组，比如[`tcp://104.236.78.154:2377`, `104.236.18.183:2377`, `tcp://104.236.87.10:2377`]

+   它传递了密码`(secret)`

+   它指定了一些基本的引擎连接事实，模块将使用`tlspath`上的证书连接到`dockerurl`。

在库中编译了`docker_swarm.go`之后，将工作节点加入到 Swarm 就像这样简单：

```
#!/bin/bash
SWARMWORKER="swarm-worker-"
for machine in `docker-machine ls --format {{.Name}} | grep 
    $SWARMWORKER`;
do
ansible-playbook -M library --extra-vars "{machine_name: $machine}" 
    playbook.yaml
done

```

![使用 Ansible](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_05_004.jpg)

# 集群管理

为了更好地说明集群操作，让我们看一个由三个管理者和十个工作节点组成的例子。第一个基本操作是列出节点，使用`docker node ls`命令：

![集群管理](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_05_005.jpg)

你可以通过主机名（**manager1**）或者 ID（**ctv03nq6cjmbkc4v1tc644fsi**）来引用节点。列表中的其他列描述了集群节点的属性。

+   **状态**是节点的物理可达性。如果节点正常，它是就绪的，否则是下线的。

+   **可用性**是节点的可用性。节点状态可以是活动的（参与集群操作）、暂停的（待机，暂停，不接受任务）或者排空的（等待被排空任务）。

+   **管理状态**是管理者的当前状态。如果一个节点不是管理者，这个字段将为空。如果一个节点是管理者，这个字段可以是可达的（保证高可用性的管理者之一）或者领导者（领导所有操作的主机）。![集群管理](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_05_006.jpg)

## 节点操作

`docker node`命令有一些可能的选项。

![节点操作](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_05_007.jpg)

如你所见，你有所有可能的节点管理命令，但没有`create`。我们经常被问到`node`命令何时会添加`create`选项，但目前还没有答案。

到目前为止，创建新节点是一个手动操作，是集群操作员的责任。

## 降级和晋升

工作节点可以晋升为管理节点，而管理节点可以降级为工作节点。

在管理大量管理者和工作者（奇数，大于或等于三）时，始终记住表格以确保高可用性。

使用以下语法将`worker0`和`worker1`提升为管理者：

```
docker node promote worker0
docker node promote worker1

```

幕后没有什么神奇的。只是，Swarm 试图通过即时指令改变节点角色。

![降级和晋升](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_05_008.jpg)

降级是一样的（docker node demote **worker1**）。但要小心，避免意外降级您正在使用的节点，否则您将被锁定。

最后，如果您尝试降级领导管理者会发生什么？在这种情况下，Raft 算法将开始选举，并且新的领导者将在活动管理者中选择。

## 给节点打标签

您可能已经注意到，在前面的屏幕截图中，**worker9**处于**排水**状态。这意味着该节点正在疏散其任务（如果有的话），这些任务将在集群的其他地方重新安排。

您可以通过使用`docker node update`命令来更改节点的可用性状态：

![给节点打标签](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_05_009.jpg)

可用性选项可以是`活动`、`暂停`或`排水`。在这里，我们只是将**worker9**恢复到了活动状态。

+   `活动`状态意味着节点正在运行并准备接受任务

+   `暂停`状态意味着节点正在运行，但不接受任务

+   `排水`状态意味着节点正在运行并且不接受任务，但它目前正在疏散其任务，这些任务正在被重新安排到其他地方。

另一个强大的更新参数是关于标签。有`--label-add`和`--label-rm`，分别允许我们向 Swarm 节点添加标签。

Docker Swarm 标签不影响引擎标签。在启动 Docker 引擎时可以指定标签（`dockerd [...] --label "staging" --label "dev" [...]`）。但 Swarm 无权编辑或更改它们。我们在这里看到的标签只影响 Swarm 的行为。

标签对于对节点进行分类很有用。当您启动服务时，您可以使用标签来过滤和决定在哪里物理生成容器。例如，如果您想要将一堆带有 SSD 的节点专门用于托管 MySQL，您实际上可以：

```
docker node update --label-add type=ssd --label-add type=mysql 
    worker1
docker node update --label-add type=ssd --label-add type=mysql 
    worker2
docker node update --label-add type=ssd --label-add type=mysql 
    worker3

```

稍后，当您使用副本因子启动服务，比如三个，您可以确保它将在`node.type`过滤器上准确地在 worker1、worker2 和 worker3 上启动 MySQL 容器：

```
docker service create --replicas 3 --constraint 'node.type == 
    mysql' --name mysql-service mysql:5.5.

```

## 删除节点

节点移除是一个微妙的操作。这不仅仅是排除 Swarm 中的一个节点，还涉及到它的角色和正在运行的任务。

### 移除工作节点

如果一个工作节点的状态是下线（例如，因为它被物理关闭），那么它目前没有运行任何任务，因此可以安全地移除：

```
docker node rm worker9

```

如果一个工作节点的状态是就绪，那么先前的命令将会引发错误，拒绝移除它。节点的可用性（活跃、暂停或排空）并不重要，因为它仍然可能在运行任务，或者在恢复时运行任务。

因此，在这种情况下，操作员必须手动排空节点。这意味着强制释放节点上的任务，这些任务将被重新调度并移动到其他工作节点：

```
docker node update --availability drain worker9

```

排空后，节点可以关闭，然后在其状态为下线时移除。

### 移除管理者

管理者不能被移除。在移除管理者节点之前，必须将其适当地降级为工作节点，最终排空，然后关闭：

```
docker node demote manager3
docker node update --availability drain manager3
# Node shutdown
docker node rm manager3

```

当必须移除一个管理者时，应该确定另一个工作节点作为新的管理者，并在以后提升，以保持管理者的奇数数量。

### 提示

**使用以下命令移除**：`docker node rm --force`

`--force`标志会移除一个节点，无论如何。这个选项必须非常小心地使用，通常是在节点卡住的情况下才会使用。

# Swarm 健康状况

Swarm 的健康状况基本上取决于集群中节点的可用性以及管理者的可靠性（奇数个、可用、运行中）。

节点可以用通常的方式列出：

```
docker node ls

```

这可以使用`--filter`选项来过滤输出。例如：

```
docker node ls --filter name=manager # prints nodes named *manager*
docker node ls --filter "type=mysql" # prints nodes with a label 
    type tagged "mysql"

```

要获取有关特定节点的详细信息，请使用 inspect 命令，如下所示：

```
docker inspect worker1

```

此外，过滤选项可用于从输出的 JSON 中提取特定数据：

```
docker node inspect --format '{{ .Description.Resources }}' worker2
{1000000000 1044140032}

```

输出核心数量（一个）和分配内存的数量（`1044140032`字节，或 995M）。

# 备份集群配置

管理者的重要数据存储在`/var/lib/docker/swarm`中。这里有：

+   `certificates/`中的证书

+   在`raft/`中的 Raft 状态与 Etcd 日志和快照

+   在`worker/`中的任务数据库

+   其他不太关键的信息，比如当前管理者状态、当前连接套接字等。

最好设置定期备份这些数据，以防需要恢复。

Raft 日志使用的空间取决于集群上生成的任务数量以及它们的状态变化频率。对于 20 万个容器，Raft 日志可以在大约三个小时内增长约 1GB 的磁盘空间。每个任务的日志条目占用约 5KB。因此，Raft 日志目录`/var/lib/docker/swarm/raft`的日志轮换策略应该更或多或少地根据可用磁盘空间进行校准。

# 灾难恢复

如果管理器上的 swarm 目录内容丢失或损坏，则需要立即使用`docker node remove nodeID`命令将该管理器从集群中移除（如果暂时卡住，则使用`--force`）。

集群管理员不应该使用过时的 swarm 目录启动管理器或加入集群。使用过时的 swarm 目录加入集群会导致集群处于不一致的状态，因为在此过程中所有管理器都会尝试同步错误的数据。

在删除具有损坏目录的管理器后，需要删除`/var/lib/docker/swarm/raft/wal`和`/var/lib/docker/swarm/raft/snap`目录。只有在此步骤之后，管理器才能安全地重新加入集群。

# Swarm 的图形界面

在撰写本文时，Swarm 模式还很年轻，现有的 Docker 图形用户界面支持尚未到来或正在进行中。

## Shipyard

**Shipyard** ([`shipyard-project.com/`](https://shipyard-project.com/))，它对 Swarm（v1）操作有很好的支持，现在已更新为使用 Swarm 模式。在撰写本文时（2016 年 8 月），Github 上有一个 1.12 分支，使其可行。

在本书出版时，可能已经有一个稳定的版本可用于自动部署。您可以查看[`shipyard-project.com/docs/deploy/automated/`](https://shipyard-project.com/docs/deploy/automated/)上的说明。

这将类似于通过 SSH 进入领导管理器主机并运行一行命令，例如：

```
curl -sSL https://shipyard-project.com/deploy | bash -s

```

如果我们仍然需要安装特定的非稳定分支，请从 Github 下载到领导管理器主机并安装 Docker Compose。

```
curl -L 
    https://github.com/docker/compose/releases/download/1.8.0/docker-
    compose-`uname -s`-`uname -m` > /usr/local/bin/docker-compose && 
    chmod +x /usr/local/bin/docker-compose

```

最后从`compose`开始：

```
docker-compose up -d < docker-compose.yml

```

此命令将启动多个容器，最终默认公开端口`8080`，以便您可以连接到公共管理器 IP 的端口`8080`以进入 Shipyard UI。

![Shipyard](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_05_010.jpg)

如您在下面的屏幕截图中所见，Docker Swarm 功能已经在 UI 中得到支持（有**服务**、**节点**等），并且我们在本章中概述的操作，如**提升**、**降级**等，对每个节点都是可用的。

![Shipyard](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_05_011.jpg)

## Portainer

支持 Swarm Mode 的另一种 UI，也是我们的首选，是**Portainer**（[`github.com/portainer/portainer/`](https://github.com/portainer/portainer/)）。

将其部署起来就像在领导管理者上启动容器一样简单：

```
docker run -d -p 9000:9000 -v /var/run/:/var/run 
    portainer/portainer

```

![Portainer](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_005_012.jpg)

UI 具有预期的选项，包括一个很好的模板列表，用于快速启动容器，例如 MySQL 或私有注册表，Portainer 在启动时支持 Swarm 服务，使用`-s`选项。

Portainer，在撰写本文时，即将推出 UI 身份验证功能，这是实现完整基于角色的访问控制的第一步，预计将在 2017 年初实现。随后，RBAC 将扩展支持 Microsoft Active Directory 作为目录源。此外，Portainer 还将在 2016 年底之前支持多集群（或多主机）管理。在 2017 年初添加的其他功能包括 Docker Compose（YAML）支持和私有注册表管理。

# 摘要

在这一章中，我们通过了典型的 Swarm 管理程序和选项。在展示了如何向集群添加管理者和工作者之后，我们详细解释了如何更新集群和节点属性，如何检查 Swarm 的健康状况，并遇到了 Shipyard 和 Portainer 作为 UI。在此之后，我们将重点放在基础设施上，现在是时候使用我们的 Swarm 了。在下一章中，我们将启动一些真实的应用程序，通过创建真实的服务和任务来实现。


# 第六章：在 Swarm 上部署真实应用

在 Swarm 基础设施上，我们可以部署各种类型的负载。在本章和下一章中，我们将处理应用程序堆栈。在本章中，我们将：

+   发现 Swarm 的服务和任务

+   部署 Nginx 容器

+   部署一个完整的 WordPress

+   部署一个小规模的 Apache Spark 架构。

# 微服务

IT 行业一直热衷于解耦和重用其创造物，无论是源代码还是应用程序。在架构层面对应用程序进行建模也不例外。模块化早期被称为**面向服务的架构**（**SOA**），并且是基于 XML 的开源协议粘合在一起。然而，随着容器的出现，现在每个人都在谈论微服务。

微服务是小型的、自包含的自治模块，它们共同工作以实现架构目标。

微服务架构的最夸张的例子是 Web 应用程序堆栈，例如 WordPress，其中 Web 服务器可能是一个服务，其他服务包括数据库、缓存引擎和包含应用程序本身的服务。通过 Docker 容器对微服务进行建模可以立即完成，这就是目前行业的发展方向。

![微服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_001.jpg)

使用微服务有许多优势，如下所示：

+   **可重用性**：您只需拉取您想要的服务的镜像（nginx、MySQL），以防需要自定义它们。

+   **异构性**：您可以链接现有的模块，包括不同的技术。如果将来某个时候决定从 MySQL 切换到 MariaDB，您可以拔掉 MySQL 并插入 MariaDB

+   **专注于小规模**：独立模块易于单独进行故障排除

+   **规模**：您可以轻松地将 Web 服务器扩展到 10 个前端，将缓存服务器扩展到 3 个，并在 5 个节点上设计数据库副本，并且可以根据应用程序的负载和需求进行扩展或缩减

+   **弹性**：如果你有三个 memcached 服务器，其中一个失败了，你可以有机制来尝试恢复它，或者直接忘记它并立即启动另一个

# 部署一个复制的 nginx

我们通过一个简单的示例来了解如何在 Swarm 上使用服务：部署和扩展 Nginx。

## 最小的 Swarm

为了使本章自给自足并对正在阅读它的开发人员有用，让我们快速在本地创建一个最小的 Swarm 模式架构，由一个管理者和三个工作者组成：

1.  我们启动了四个 Docker 主机：

```
 for i in seq 3; do docker-machine create -d virtualbox 
      node- $i; done

```

1.  然后我们接管了`node-1`，我们选举它作为我们的静态管理器，并在 Swarm 上初始化它：

```
 eval $(docker-machine env node-1)
 docker swarm init --advertise-addr 192.168.99.100

```

1.  Docker 为我们生成一个令牌，以加入我们的三个工作节点。因此，我们只需复制粘贴该输出以迭代其他三个工作节点，将它们加入节点：

```
 for i in 2 3 4; do
 docker-machine ssh node-$i sudo docker swarm join \
 --token SWMTKN-1-
      4d13l0cf5ipq7e4x5ax2akalds8j1zm6lye8knnb0ba9wftymn-
      9odd9z4gfu4d09z2iu0r2361v \
 192.168.99.100:2377

```

Swarm 模式架构始终通过 Docker Machine-shell 环境变量连接到`node-1`，这些变量由先前的`eval`命令填充。我们需要检查所有节点，包括领导管理器，是否都处于活动状态并成功加入了 Swarm：

![一个最小的 Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_002.jpg)

现在，我们可以使用`docker info`命令来检查这个 Swarm 集群的状态：

![一个最小的 Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_003.jpg)

这里的重要信息是 Swarm 处于活动状态，然后是一些 Raft 的细节。

## Docker 服务

Docker 1.12 中引入的一个新命令是`docker service`，这就是我们现在要看到的。服务是在 Docker Swarm 模式上操作应用程序的主要方式；这是您将创建、销毁、扩展和滚动更新服务的方式。

服务由任务组成。一个 nginx 服务由 nginx 容器任务组成。服务机制在（通常）工作节点上启动任务。因此，当您创建一个服务时，您必须强制指定服务名称和将成为服务基础的容器等选项。

。

![Docker 服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_004.jpg)

创建服务的语法非常直接：只需使用`docker service create`命令，指定选项，如暴露的端口，并选择要使用的容器。在这里我们执行

```
 docker service create -p 80:80 --name swarm-nginx --replicas 3
    fsoppelsa/swarm-nginx

```

![Docker 服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_005.jpg)

这个命令启动了 nginx，将容器的端口`80`暴露给主机的端口`80`，以便可以从外部访问，并指定了三个副本因子。

副本因子是在 Swarm 上扩展容器的方式。如果指定为三个，Swarm 将在三个节点上创建三个 nginx 任务（容器），并尝试保留这个数量，以防其中一个或多个容器死掉，通过在其他可用主机上重新调度 nginx 来实现。

如果没有给出`--replicas`选项，则默认的副本因子是`1`。

一段时间后，Swarm 需要从 hub 或任何本地注册表中将镜像拉到主机并创建适当的容器（并暴露端口）；我们看到三个 nginx 已经在我们的基础设施上就位了，使用命令：

```
 docker service ls

```

![Docker 服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_006.jpg)

这些任务实际上是在三个节点上调度的，如下命令所示：

```
 docker service ps swarm-nginx

```

![Docker 服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_007.jpg)

这里使用的`fsoppelsa/swarm-nginx`容器是对`richarvey/nginx-php-fpm`的微小修改，后者是一个由 PHP 增强的 nginx 镜像。我们使用 PHP 在 Nginx 欢迎页面上输出当前服务器的地址，通过添加一个 PHP 命令来显示负载均衡机制的目的。

```
 <h2>Docker swarm host <?php echo $_SERVER['SERVER_ADDR']; ?></h2>

```

![Docker 服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_008.jpg)

现在，如果你将浏览器指向管理器 IP 并多次重新加载，你会发现负载均衡器有时会将你重定向到不同的容器。

第一个加载的页面将类似于以下截图： 

![Docker 服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_009.jpg)

以下截图显示了另一个加载的页面，由负载均衡器选择了不同的节点，即 10.255.0.9：

![Docker 服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_010.jpg)

以下截图是当负载均衡器重定向到节点 10.255.0.10 时加载的另一个页面：

![Docker 服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_011.jpg)

# 覆盖网络

如果你不仅仅是要复制，而是要连接运行在不同主机上的容器到你的 Swarm 基础设施，你必须使用网络。例如，你需要将你的 web 服务器连接到你的数据库容器，以便它们可以通信。

在 Swarm 模式下，解决这个问题的方法是使用覆盖网络。它们是使用 Docker 的 libnetwork 和 libkv 实现的。这些网络是建立在另一个网络之上的 VxLAN 网络（在标准设置中，是物理主机网络）。

VxLAN 是 VLAN 协议的扩展，旨在增加其可扩展性。连接到 Docker VxLAN 网络的不同主机上的容器可以像它们在同一主机上一样进行通信。

Docker Swarm 模式包括一个路由网格表，通过默认情况下称为**ingress**，实现了这种多主机网络。

## 集成负载均衡

Swarm Mode 1.12 上的负载平衡是如何工作的？路由有两种不同的方式。首先，它通过虚拟 IP 服务公开的端口工作。对端口的任何请求都会分布在承载服务任务的主机之间。其次，服务被赋予一个仅在 Docker 网络内可路由的虚拟 IP 地址。当对此 VIP 地址进行请求时，它们将分布到底层容器。这个虚拟 IP 被注册在 Docker Swarm 中包含的 DNS 服务器中。当对服务名称进行 DNS 查询时（例如 nslookup mysql），将返回虚拟 IP。

# 连接服务：WordPress 示例

启动一堆复制和负载平衡的容器已经是一个不错的开始，但是如何处理由不同相互连接的容器组成的更复杂的应用程序堆栈呢？

在这种情况下，您可以通过名称调用容器进行链接。正如我们刚才看到的，内部 Swarm DNS 服务器将保证可靠的名称解析机制。如果您实例化一个名为`nginx`的服务，您只需将其引用为`nginx`，其他服务将解析为`nginx`虚拟 IP（负载平衡），从而访问分布式容器。

为了以示例演示这一点，我们现在将在 Swarm 上部署经典中的经典：WordPress。您可以将 WordPress 作为容器运行，实际上 Docker Hub 上有一个准备好的镜像，但是它需要一个外部数据库（在本例中是 MySQL）来存储其数据。

因此，首先，我们将在 Swarm 上创建一个名为 WordPress 的新专用覆盖网络，并将一个 MySQL 容器作为 Swarm 服务运行在其上，并将三个负载平衡的 WordPress 容器（Web 容器）也作为 Swarm 服务运行。MySQL 将公开端口 3306，而 WordPress 将公开端口`80`。

让我们首先定义我们的覆盖网络。连接到 Swarm 管理器时，我们发出以下命令：

```
 docker network create --driver overlay wordpress

```

![连接服务：WordPress 示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_012.jpg)

那么，幕后发生了什么？该命令使用 libnetwork 创建了一个覆盖网络，在需要时在 Swarm 节点上可用。如果连接到`node-2`并列出网络，它将始终存在。

我们现在创建一个 MySQL 服务，只由一个容器组成（没有 MySQL 本地副本，也没有 Galera 或其他复制机制），使用以下命令：

```
 docker service create \
 --name mysql \
 --replicas 1 \
 -p 3306:3306 \
 --network wordpress \
 --env MYSQL_ROOT_PASSWORD=dockerswarm \
 mysql:5.6

```

我们想要从 hub 上拉取 MySQL 5.6，调用服务（稍后可以通过解析的名称访问其 VIP）`mysql`，为了清晰起见，将副本设置为 1，暴露端口`3306`，指定专用网络 WordPress，并指定根密码，在我们的情况下是`dockerswarm`：

![连接服务：WordPress 示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_013.jpg)

必须从 hub 上拉取 MySQL 镜像，几秒钟后，我们可以检查并看到在我们的情况下，一个`mysql`容器被下载并放置在`node-1`上（实际上，如果没有另行指定，主节点也可以运行容器），VIP 是`10.255.0.2`，在 WordPress 网络上。我们可以使用以下命令获取此信息：

```
 docker service inspect mysql -f "{{ .Endpoint.VirtualIPs }}"

```

![连接服务：WordPress 示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_014.jpg)

我们现在有一个正在运行的 MySQL，我们只需要启动并将其连接到 WordPress。

## Swarm 调度策略

碰巧我们启动了一个服务，Swarm 将容器调度到`node-1`上运行。Swarm 模式（截至目前，在编写 Docker 1.12 和 1.13-dev 时）只有一种可能的策略：spread。Spread 计算每个主机上的容器数量，并尝试将新创建的容器放置在负载较轻的主机上（即，容器较少的主机）。尽管在当天只有一种可用的 spread 策略，但 Swarm 提供了选项，允许我们以很高的精度过滤将启动任务的主机。

这些选项称为**约束条件**，可以在实例化服务时作为可选参数传递，使用`--constraint`。

现在我们想要启动 WordPress。我们决定要强制在三个工作者上执行三个容器，而不是在主节点上，因此我们指定了一个约束条件。

约束条件的形式为`--constraint``node.KEY == VALUE`或`--constraint``node.KEY != VALUE`，有几种变体。操作员可以按节点 ID、角色和主机名进行过滤。更有趣的是，正如我们在第五章中看到的那样，*管理 Swarm 集群*，可以通过使用`docker node update --label-add`命令将自定义标签添加到节点属性中来指定自定义标签。

| **键** | **含义** | **示例** |
| --- | --- | --- |
| `node.id` | 节点 ID | `node.id == 3tqtddj8wfyd1dl92o1l1bniq` |
| `node.role` | 节点角色（管理器，工作者） | `node.role != manager` |
| `node.hostname` | 节点主机名 | `node.hostname == node-1` |
| `node.labels` | 标签 | `node.labels.type == database` |

## 现在，WordPress

在这里，我们希望在所有工作节点上启动`wordpress`，因此我们说约束条件是`node.role != manager`（或`node.role == worker`）。此外，我们将服务命名为`wordpress`，将副本因子设置为`3`，暴露端口`80`，并告诉 WordPress MySQL 位于主机 mysql 上（这在 Swarm 内部解析并指向 MySQL VIP）：

```
 docker service create \
 --constraint 'node.role != manager' \
 --name wordpress \
 --replicas 3 \
 -p 80:80 \
 --network wordpress \
 --env WORDPRESS_DB_HOST=mysql \
 --env WORDPRESS_DB_USER=root \
 --env WORDPRESS_DB_PASSWORD=dockerswarm \
 wordpress

```

![现在，WordPress](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_015.jpg)

经过一段时间，我们需要将 WordPress 图像下载到工作节点，以便我们可以检查一切是否正常运行。

![现在，WordPress](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_016.jpg)

现在我们通过端口`80`连接到主机之一，并受到 WordPress 安装程序的欢迎。

![现在，WordPress](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_017.jpg)

WordPress 在浏览器中执行一些步骤后就准备好了，比如选择管理员用户名和密码：

![现在，WordPress](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_018.jpg)

# Docker Compose 和 Swarm 模式

许多开发人员喜欢使用 Compose 来模拟他们的应用程序，例如类似 WordPress 的应用程序。我们也这样做，并认为这是描述和管理 Docker 上的微服务的一种绝妙方式。然而，在撰写本书时，Compose 尚未支持 Docker Swarm 模式，所有容器都被安排在当前节点上。要在整个 Swarm 上部署应用程序，我们需要使用堆栈的新捆绑功能。

在撰写本文时，堆栈仅以实验性方式提供，但我们在这里展示它们，只是为了让您体验在（不久的）将来在 Docker 上部署微服务的感觉。

# 介绍 Docker 堆栈

对于 Docker，堆栈将成为打包由多个容器组成的应用程序的标准方式。考虑到庞大的 WordPress 示例：您至少需要一个 Web 服务器和一个数据库。

开发人员通常通过创建一个 YAML 文件来使用 Compose 描述这些应用程序，如下所示：

```
 version: '2'
 services:
   db:
     image: mysql:5.6
     volumes:
       - "./.data/db:/var/lib/mysql"
     restart: always
     environment:
       MYSQL_ROOT_PASSWORD: dockerswarm
       MYSQL_DATABASE: wordpress
       MYSQL_USER: wordpress
       MYSQL_PASSWORD: wordpress
   wordpress:
     depends_on:
       - db
     image: wordpress:latest
     links:
       - db
     ports:
       - "8000:80"
     restart: always
     environment:
       WORDPRESS_DB_HOST: db:3306
       WORDPRESS_DB_PASSWORD: wordpress

```

然后，他们使用类似以下的命令启动此应用：

```
 docker-compose --rm -d --file docker-compose.yml up.

```

在这里，`mysql`和`wordpress`容器被安排、拉取并作为守护进程在开发者连接的主机上启动。从 Docker 1.12 开始（在 1.12 中是实验性的），将有可能将`mysql + wordpress`打包成一个单一文件包，称为**分布式应用程序包**（**DAB**）。

## 分布式应用程序包

因此，您将运行`docker-compose up`命令，而不是：

```
 docker-compose --file docker-compose.yml bundle -o wordpress.dab

```

这个命令将输出另一个名为`wordpress.dab`的 JSON，它将成为通过 Compose 在 Swarm 上描述为 Swarm 服务的服务部署的起点。

对于这个例子，`wordpress.dab`的内容看起来类似于：

```
 {
 "Services": {
 "db": {
 "Env": [
 "MYSQL_ROOT_PASSWORD=dockerswarm",
 "MYSQL_PASSWORD=wordpress",
 "MYSQL_USER=wordpress",
 "MYSQL_DATABASE=wordpress"
 ],
 "Image": 
          "mysql@sha256:e9b0bc4b8f18429479b74b07f4
          d515f2ac14da77c146201a885c5d7619028f4d",
 "Networks": [
 "default"
 ]
 },
 "wordpress": {
 "Env": [
 "WORDPRESS_DB_HOST=db:3306",
 "WORDPRESS_DB_PASSWORD=wordpress"
 ],
 "Image": 
          "wordpress@sha256:10f68e4f1f13655b15a5d0415
          3fe0a454ea5e14bcb38b0695f0b9e3e920a1c97",
 "Networks": [
 "default"
 ],
 "Ports": [
 {
 "Port": 80,
 "Protocol": "tcp"
 }
 ]
 }
 },
 "Version": "0.1"

```

## Docker 部署

从生成的`wordpress.dab`文件开始，当连接到 Swarm 管理器时，开发者可以使用 deploy 命令启动一个堆栈：

```
 docker deploy --file wordpress.dab wordpress1

```

现在你将有两个名为`wordpress1_wordpress`和`wordpress1_db`的服务，传统上遵循 Compose 的语法传统。

![Docker 部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_019.jpg)

这只是一个非常原始的演示。作为一个实验性功能，Compose 中的支持功能仍然没有完全定义，但我们期望它会改变（甚至根本改变）以满足开发者、Swarm 和 Compose 的需求。

# 另一个应用程序：Apache Spark

现在我们已经通过使用服务获得了一些实践经验，我们将迈向下一个级别。我们将在 Swarm 上部署 Apache Spark。Spark 是 Apache 基金会的开源集群计算框架，主要用于数据处理。

Spark 可以用于诸如以下的事情：

+   大数据分析（Spark Core）

+   快速可扩展的数据结构化控制台（Spark SQL）

+   流式分析（Spark Streaming）

+   图形处理（Spark GraphX）

在这里，我们主要关注 Swarm 的基础设施部分。如果你想详细了解如何编程或使用 Spark，可以阅读 Packt 关于 Spark 的图书选择。我们建议从*Fast Data Processing with Spark 2.0 - Third Edition*开始。

Spark 是 Hadoop 的一个整洁而清晰的替代方案，它是 Hadoop 复杂性和规模的更敏捷和高效的替代品。

Spark 的理论拓扑是立即的，可以在一个或多个管理器上计算集群操作，并有一定数量的执行实际任务的工作节点。

对于管理器，Spark 可以使用自己的独立管理器（就像我们在这里做的那样），也可以使用 Hadoop YARN，甚至利用 Mesos 的特性。

然后，Spark 可以将存储委托给内部 HDFS（Hadoop 分布式文件系统）或外部存储服务，如 Amazon S3、OpenStack Swift 或 Cassandra。存储由 Spark 用于获取数据进行处理，然后保存处理后的结果。

## 为什么在 Docker 上使用 Spark

我们将向您展示如何在 Docker Swarm 集群上启动 Spark 集群，作为使用虚拟机启动 Spark 的替代方法。本章中定义的示例可以从容器中获得许多好处：

+   启动容器更快

+   在宠物模型中扩展容器更为直接。

+   您可以获取 Spark 镜像，而无需创建虚拟机，编写自定义脚本，调整 Ansible Playbooks。只需`docker pull`

+   您可以使用 Docker Networking 功能创建专用的覆盖网络，而无需在物理上损害或调用网络团队

## Spark 独立模式无 Swarm

让我们开始定义一个使用经典 Docker 工具构建的小型 Apache Spark 集群，这些工具基本上是 Docker 主机上的 Docker 命令。在了解整体情况之前，我们需要开始熟悉 Swarm 概念和术语。

在本章中，我们将使用`google_container`镜像，特别是 Swarm 版本 1.5.2。2.0 版本中包含了许多改进，但这些镜像被证明非常稳定可靠。因此，我们可以从 Google 仓库中开始拉取它们，用于主节点和工作节点：

```
 docker pull gcr.io/google_containers/spark-master
 docker pull gcr.io/google_containers/spark-worker

```

Spark 可以在 YARN、Mesos 或 Hadoop 的顶部运行。在接下来的示例和章节中，我们将使用它的独立模式，因为这是最简单的，不需要额外的先决条件。在独立的 Spark 集群模式中，Spark 根据核心分配资源。默认情况下，应用程序将占用集群中的所有核心，因此我们将限制专用于工作节点的资源。

我们的架构将非常简单：一个负责管理集群的主节点，以及三个负责运行 Spark 作业的节点。对于我们的目的，主节点必须发布端口`8080`（我们将用于方便的 Web UI），我们将其称为 spark-master。默认情况下，工作节点容器尝试连接到 URL `spark://spark-master:7077`，因此除了将它们链接到主节点外，不需要进一步的定制。

因此，让我们将其传递给实际部分，并使用以下代码初始化 Spark 主节点：

```
 docker run -d \
 -p 8080:8080 \
 --name spark-master \
 -h spark-master \
 gcr.io/google_containers/spark-master

```

这在守护程序模式（`-d`）中运行，从`gcr.io/google_containers/spark-master`镜像中创建一个容器，将名称（`--name`）spark-master 分配给容器，并将其主机名（`-h`）配置为 spark-master。

我们现在可以连接浏览器到 Docker 主机，端口`8080`，以验证 Spark 是否正在运行。

![没有 Swarm 的 Spark 独立运行](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_020.jpg)

它仍然没有活动的工作节点，我们现在要生成。在我们注意到 Spark 主容器的 ID 之前，我们使用以下命令启动工作节点：

```
 docker run -d \
 --link 7ff683727bbf \
 -m 256 \
 -p 8081:8081 \
 --name worker-1 \
 gcr.io/google_containers/spark-worker

```

这将以守护进程模式启动一个容器，将其链接到主节点，将内存使用限制为最大 256M，将端口 8081 暴露给 Web（工作节点）管理，并将其分配给容器名称`worker-1`。类似地，我们启动其他两个工作节点：

```
 docker run -d --link d3409a18fdc0 -m 256 -p 8082:8082 -m 256m -- 
    name worker-2 gcr.io/google_containers/spark-worker
 docker run -d --link d3409a18fdc0 -m 256 -p 8083:8083 -m 256m --
    name worker-3 gcr.io/google_containers/spark-worker

```

我们可以在主节点上检查一切是否连接并运行：

![没有 Swarm 的 Spark 独立运行](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_021.jpg)

## Swarm 上的独立 Spark

到目前为止，我们已经讨论了不那么重要的部分。我们现在将已经讨论的概念转移到 Swarm 架构，所以我们将实例化 Spark 主节点和工作节点作为 Swarm 服务，而不是单个容器。我们将创建一个主节点的副本因子为 1 的架构，以及工作节点的副本因子为 3。

### Spark 拓扑

在这个例子中，我们将创建一个由一个主节点和三个工作节点组成的 Spark 集群。

### 存储

我们将在第七章中定义真实的存储并启动一些真实的 Spark 任务，扩展您的平台。

### 先决条件

我们首先为 Spark 创建一个新的专用覆盖网络：

```
 docker network create --driver overlay spark

```

然后，我们在节点上设置一些标签，以便以后能够过滤。我们希望将 Spark 主节点托管在 Swarm 管理器（`node-1`）上，将 Spark 工作节点托管在 Swarm 工作节点（节点 2、3 和 4）上：

```
 docker node update --label-add type=sparkmaster node-1
 docker node update --label-add type=sparkworker node-2
 docker node update --label-add type=sparkworker node-3
 docker node update --label-add type=sparkworker node-4

```

### 提示

我们在这里添加了“sparkworker”类型标签以确保极端清晰。实际上，只有两种变体，事实上可以写成相同的约束：

**--constraint 'node.labels.type == sparkworker'**

或者：

**--constraint 'node.labels.type != sparkmaster'**

## 在 Swarm 上启动 Spark

现在，我们将在 Swarm 中定义我们的 Spark 服务，类似于我们在前一节为 Wordpress 所做的操作，但这次我们将通过定义在哪里启动 Spark 主节点和 Spark 工作节点来驱动调度策略，以最大程度地精确地进行。

我们从主节点开始，如下所示：

```
 docker service create \
 --container-label spark-master \
 --network spark \
 --constraint 'node.labels.type==sparkmaster' \
 --publish 8080:8080 \
 --publish 7077:7077 \
 --publish 6066:6066 \
 --name spark-master \
 --replicas 1 \
 --limit-memory 1024 \
 gcr.io/google_containers/spark-master

```

Spark 主节点暴露端口`8080`（Web UI），并且可选地，为了示例的清晰度，这里我们还暴露了端口`7077`，Spark 工作节点用于连接到主节点的端口，以及端口 6066，Spark API 端口。此外，我们使用--limit-memory 将内存限制为 1G。一旦 Spark 主节点启动，我们可以创建托管工作节点的服务，sparkworker：

```
 docker service create \
 --constraint 'node.labels.type==sparkworker' \
 --network spark \
 --name spark-worker \
 --publish 8081:8081 \
 --replicas 3 \
 --limit-memory 256 \
 gcr.io/google_containers/spark-worker

```

同样，我们暴露端口`8081`（工作节点的 Web UI），但这是可选的。在这里，所有的 Spark 容器都被调度到了之前我们定义的 spark 工作节点上。将镜像拉到主机上需要一些时间。结果，我们有了最小的 Spark 基础设施：

![在 Swarm 上启动 Spark](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_022.jpg)

Spark 集群正在运行，即使有一点需要补充的地方：

![在 Swarm 上启动 Spark](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_023.jpg)

尽管我们将每个 worker 的内存限制为 256M，但在 UI 中我们仍然看到 Spark 读取了 1024M。这是因为 Spark 内部的默认配置。如果我们连接到任何一个正在运行其中一个 worker 的主机，并使用`docker stats a7a2b5bb3024`命令检查其统计信息，我们会看到容器实际上是受限制的。

![在 Swarm 上启动 Spark](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_06_024.jpg)

# 摘要

在本章中，我们开始在应用程序堆栈上工作，并在 Swarm 上部署真实的东西。我们练习了定义 Swarm 服务，并在专用覆盖网络上启动了一组 nginx，以及一个负载均衡的 WordPress。然后，我们转向了更真实的东西：Apache Spark。我们通过定义自己的调度策略，在 Swarm 上以小规模部署了 Spark。在第七章中，我们将扩展 Swarm 并将其扩展到更大规模，具有更多真实的存储和网络选项。


# 第七章：扩展您的平台

在本章中，我们将扩展我们在第六章中所看到的内容，*在 Swarm 上部署真实应用程序*。我们的目标是在 Swarm 之上部署一个逼真的生产级别的 Spark 集群，增加存储容量，启动一些 Spark 作业，并为基础架构设置监控。

为了做到这一点，本章主要是面向基础架构的。事实上，我们将看到如何将**Libnetwork**、**Flocker**和**Prometheus**与 Swarm 结合起来。

对于网络，我们将使用基本的 Docker 网络覆盖系统，基于 Libnetwork。有一些很棒的网络插件，比如 Weave 和其他插件，但它们要么还不兼容新的 Docker Swarm 模式，要么被 Swarm 集成的路由网格机制所淘汰。

存储方面，情况更加繁荣，因为选择更多（参考[`docs.docker.com/engine/extend/plugins/`](https://docs.docker.com/engine/extend/plugins/)）。我们将选择 Flocker。Flocker 是 Docker 存储的*鼻祖*，可以配置各种各样的存储后端，使其成为生产负载的最佳选择之一。对 Flocker 的复杂性感到害怕吗？这是不必要的：我们将看到如何在几分钟内为任何用途设置多节点 Flocker 集群。

最后，对于监控，我们将介绍 Prometheus。它是目前可用于 Docker 的最有前途的监控系统，其 API 可能很快就会集成到 Docker 引擎中。

因此，我们将在这里涵盖什么：

+   一个准备好运行任何 Spark 作业的 Swarm 上的 Spark 示例

+   自动化安装 Flocker 以适应规模的基础设施

+   演示如何在本地使用 Flocker

+   在 Swarm 模式下使用 Flocker

+   扩展我们的 Spark 应用程序

+   使用 Prometheus 监控这个基础架构的健康状况

# 再次介绍 Spark 示例

我们将重新设计第六章中的示例，*在 Swarm 上部署真实应用程序*，因此我们将在 Swarm 上部署 Spark，但这次是以逼真的网络和存储设置。

Spark 存储后端通常在 Hadoop 上运行，或者在文件系统上运行 NFS。对于不需要存储的作业，Spark 将在工作节点上创建本地数据，但对于存储计算，您将需要在每个节点上使用共享文件系统，这不能通过 Docker 卷插件自动保证（至少目前是这样）。

在 Swarm 上实现这个目标的一种可能性是在每个 Docker 主机上创建 NFS 共享，然后在服务容器内透明地挂载它们。

我们的重点不是说明 Spark 作业的细节和它们的存储组织，而是为 Docker 引入一种主观的存储选项，并提供如何在 Docker Swarm 上组织和扩展一个相当复杂的服务的想法。

# Docker 插件

关于 Docker 插件的详细介绍，我们建议阅读官方文档页面。这是一个起点[`docs.docker.com/engine/extend/`](https://docs.docker.com/engine/extend/)，此外，Docker 可能会发布一个工具，通过一个命令获取插件，请参阅[`docs.docker.com/engine/reference/commandline/plugin_install/`](https://docs.docker.com/engine/reference/commandline/plugin_install/)。

如果您想探索如何将新功能集成到 Docker 中，我们建议您参考 Packt 的*Extending Docker*书籍。该书的重点是 Docker 插件、卷插件、网络插件以及如何创建自己的插件。

对于 Flocker，ClusterHQ 提供了一个自动化部署机制，可以使用 CloudForm 模板在 AWS 上部署 Flocker 集群，您可以使用 Volume Hub 安装。要注册和启动这样一个集群，请访问[`flocker-docs.clusterhq.com/en/latest/docker-integration/cloudformation.html`](https://flocker-docs.clusterhq.com/en/latest/docker-integration/cloudformation.html)。有关详细过程的逐步解释，请参阅*Extending Docker*的第三章，Packt。

在这里，我们将手动进行，因为我们必须集成 Flocker 和 Swarm。

# 实验室

在本教程中，我们将在 AWS 上创建基础架构。理想情况下，对于生产环境，您将设置三个或五个 Swarm 管理器和一些工作节点，并根据负载情况随后添加新的工作节点。

在这里，我们将使用三个 Swarm 管理器、六个 Swarm 工作节点和一个带有 Machine 的 Flocker 控制节点设置一个 Swarm 集群，并不会添加新的工作节点。

安装 Flocker 需要进行几个手动步骤，这些步骤可以自动化（正如我们将看到的）。因此，为了尽可能地减少示例的复杂性，我们将最初按线性顺序运行所有这些命令，而不重复程序以增加系统容量。

如果您不喜欢 Ansible，您可以轻松地将流程调整为您喜欢的工具，无论是 Puppet、Salt、Chef 还是其他工具。

## 一个独特的关键

为简单起见，我们将使用特定生成的 SSH 密钥安装我们的实验室，并将此密钥复制到`authorized_keys`中的主机上安装 Docker Machines。目标是拥有一个唯一的密钥来验证后续使用的 Ansible，我们将使用它来自动化许多我们否则应该手动执行的步骤。

因此，我们首先生成一个`flocker`密钥，并将其放入`keys/`目录：

```
ssh-keygen -t rsa -f keys/flocker

```

## Docker Machine

为了配置我们的 Docker 主机，我们将使用 Docker Machine。这是本教程的系统详细信息：

AWS 实例将被命名为 aws-101 到 aws-110。这种标准化的命名在以后生成和创建 Flocker 节点证书时将非常重要：

+   节点 aws-101、102、103 将成为我们的 Swarm 管理器

+   节点 aws-104 将成为 Flocker 控制节点

+   从 aws-105 到 aws-110 的节点将成为我们的 Swarm 工作节点。

实例类型将是`t2.medium`（2 个 vCPU，4G 内存，EBS 存储）

口味将是 Ubuntu 14.04 Trusty（使用`--amazonec2-ami`参数指定）

安全组将是标准的`docker-machine`（我们将在几秒钟内再次总结要求）

Flocker 版本将是 1.15。

要使用的确切 AMI ID 可以在[`cloud-images.ubuntu.com/locator/ec2/`](https://cloud-images.ubuntu.com/locator/ec2/)上搜索。

AWS 计算器计算出这个设置的成本大约是每月 380 美元，不包括存储使用。

![Docker Machine](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_001.jpg)

因此，我们创建基础设施：

```
for i in `seq 101 110`; do
docker-machine create -d amazonec2 \
--amazonec2-ami ami-c9580bde \
--amazonec2-ssh-keypath keys/flocker \
--amazonec2-instance-type "t2.medium" \
aws-$i;
done

```

并运行。

过一段时间，我们将使其运行起来。

## 安全组

此外，我们还需要在用于此项目的安全组（`docker-machine`）中在 EC2 控制台中打开三个额外的新端口。这些是 Flocker 服务使用的端口：

+   端口`4523/tcp`

+   端口`4524/tcp`

此外，以下是 Swarm 使用的端口：

+   端口`2377/tcp`![安全组](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_003.jpg)

## 网络配置

我们使用标准配置和额外的覆盖网络，称为**Spark**。流量数据将通过 spark 网络传递，这样就可以通过新的主机和工作节点扩展实验室配置，甚至在其他提供商（如**DigitalOcean**或**OpenStack**）上运行。当新的 Swarm 工作节点加入此集群时，此网络将传播到它们，并对 Swarm 服务进行提供。

## 存储配置和架构

正如前面提到的，我们选择了 Flocker（[`clusterhq.com/flocker/introduction/`](https://clusterhq.com/flocker/introduction/)），它是顶级的 Docker 存储项目之一。ClusterHQ 将其描述为：

> *Flocker 是一个为您的 Docker 化应用程序提供容器数据卷管理的开源工具。通过提供数据迁移工具，Flocker 为运维团队提供了在生产环境中运行容器化有状态服务（如数据库）所需的工具。与绑定到单个服务器的 Docker 数据卷不同，称为数据集的 Flocker 数据卷是可移植的，并且可以与集群中的任何容器一起使用。*

Flocker 支持非常广泛的存储选项，从 AWS EBS 到 EMC、NetApp、戴尔、华为解决方案，再到 OpenStack Cinder 和 Ceph 等。

它的设计很简单：Flocker 有一个**控制节点**，它暴露其服务 API 以管理 Flocker 集群和 Flocker 卷，以及一个**Flocker 代理**，与 Docker 插件一起在集群的每个**节点**上运行。

![存储配置和架构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_004.jpg)

要使用 Flocker，在命令行上，您需要运行类似以下的 Docker 命令来读取或写入 Flocker `myvolume`卷上的有状态数据，该卷被挂载为容器内的`/data`：

```
docker run -v myvolume:/data --volume-driver flocker image command

```

此外，您可以使用`docker volume`命令管理卷：

```
docker volume ls
docker volume create -d flocker

```

在本教程架构中，我们将在 aws-104 上安装 Flocker 控制节点，因此将专用，以及在所有节点（包括 node-104）上安装 flocker 代理。

此外，我们将安装 Flocker 客户端，用于与 Flocker 控制节点 API 交互，以管理集群状态和卷。为了方便起见，我们还将从 aws-104 上使用它。

# 安装 Flocker

需要一系列操作才能运行 Flocker 集群：

1.  安装`flocker-ca`实用程序以生成证书。

1.  生成授权证书。

1.  生成控制节点证书。

1.  为每个节点生成节点证书。

1.  生成 flocker 插件证书。

1.  生成客户端证书。

1.  从软件包安装一些软件。

1.  向 Flocker 集群分发证书。

1.  配置安装，添加主配置文件`agent.yml`。

1.  在主机上配置数据包过滤器。

1.  启动和重新启动系统服务。

您可以在小集群上手动执行它们，但它们是重复和乏味的，因此我们将使用一些自解释的 Ansible playbook 来说明该过程，这些 playbook 已发布到[`github.com/fsoppelsa/ansible-flocker`](https://github.com/fsoppelsa/ansible-flocker)。

这些 playbook 可能很简单，可能还不够成熟。还有官方的 ClusterHQ Flocker 角色 playbook（参考[`github.com/ClusterHQ/ansible-role-flocker`](https://github.com/ClusterHQ/ansible-role-flocker)），但为了解释的连贯性，我们将使用第一个存储库，所以让我们克隆它：

```
git clone git@github.com:fsoppelsa/ansible-flocker.git

```

## 生成 Flocker 证书

对于证书生成，需要`flocker-ca`实用程序。有关如何安装它的说明，请访问[`docs.clusterhq.com/en/latest/flocker-standalone/install-client.html`](https://docs.clusterhq.com/en/latest/flocker-standalone/install-client.html)。对于 Linux 发行版，只需安装一个软件包。而在 Mac OS X 上，可以使用 Python 的`pip`实用程序来获取该工具。

**在 Ubuntu 上**：

```
sudo apt-get -y install --force-yes clusterhq-flocker-cli

```

**在 Mac OS X 上**：

```
pip install https://clusterhq-
    archive.s3.amazonaws.com/python/Flocker-1.15.0-py2-none-any.whl

```

一旦拥有此工具，我们生成所需的证书。为了简化事情，我们将创建以下证书结构：

包括所有证书和密钥的目录`certs/`：

+   `cluster.crt`和`.key`是授权证书和密钥

+   `control-service.crt`和`.key`是控制节点证书和密钥

+   `plugin.crt`和`.key`是 Docker Flocker 插件证书和密钥

+   `client.crt`和`.key`是 Flocker 客户端证书和密钥

+   从`node-aws-101.crt`和`.key`到`node-aws-110.crt`和`.key`是节点证书和密钥，每个节点一个

以下是步骤：

1.  生成授权证书：`flocker-ca initialize cluster`

1.  一旦拥有授权证书和密钥，就在同一目录中生成控制节点证书：`flocker-ca create-control-certificate aws-101`

1.  然后生成插件证书：`flocker-ca create-api-certificate plugin`

1.  然后生成客户端证书：`flocker-ca create-api-certificate client`

1.  最后，生成每个节点的证书：`flocker-ca create-node-certificate node-aws-X`

当然，我们必须欺骗并使用`ansible-flocker`存储库中提供的`utility/generate_certs.sh`脚本，它将为我们完成工作：

```
cd utils
./generate_certs.sh

```

在执行此脚本后，我们现在在`certs/`中有所有我们的证书：

![生成 Flocker 证书](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_005.jpg)

## 安装软件

在每个 Flocker 节点上，我们必须执行以下步骤：

1.  将 ClusterHQ Ubuntu 存储库添加到 APT 源列表中。

1.  更新软件包缓存。

1.  安装这些软件包：

+   `clusterhq-python-flocker`

+   `clusterhq-flocker-node`

+   `clusterhq-flocker-docker-plugin`

1.  创建目录`/etc/flocker`。

1.  将 Flocker 配置文件`agent.yml`复制到`/etc/flocker`。

1.  将适用于该节点的证书复制到`/etc/flocker`。

1.  通过启用**ufw**配置安全性，并打开 TCP 端口`2376`、`2377`、`4523`、`4524`。

1.  启动系统服务。

1.  重新启动 docker 守护程序。

再一次，我们喜欢让机器为我们工作，所以让我们在喝咖啡的时候用 Ansible 设置这个。

但是，在此之前，我们必须指定谁将是 Flocker 控制节点，谁将是裸节点，因此我们在`inventory`文件中填写节点的主机 IP。该文件采用`.ini`格式，所需的只是指定节点列表：

![安装软件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_006.jpg)

然后，我们创建一个目录，Ansible 将从中获取文件、证书和配置，然后复制到节点上：

```
mkdir files/

```

现在，我们将之前创建的所有证书从`certs/`目录复制到`files/`中：

```
cp certs/* files/

```

最后，我们在`files/agent.yml`中定义 Flocker 配置文件，内容如下，调整 AWS 区域并修改`hostname`、`access_key_id`和`secret_access_key`：

```
control-service:
hostname: "<Control node IP>"
port: 4524
dataset:
backend: "aws"
region: "us-east-1"
zone: "us-east-1a"
access_key_id: "<AWS-KEY>"
secret_access_key: "<AWS-ACCESS-KEY>"
version: 1

```

这是核心的 Flocker 配置文件，将在每个节点的`/etc/flocker`中。在这里，您可以指定和配置所选后端的凭据。在我们的情况下，我们选择基本的 AWS 选项 EBS，因此我们包括我们的 AWS 凭据。

有了清单、`agent.yml`和所有凭据都准备好在`files/`中，我们可以继续了。

## 安装控制节点

安装控制节点的 playbook 是`flocker_control_install.yml`。此 play 执行软件安装脚本，复制集群证书、控制节点证书和密钥、节点证书和密钥、客户端证书和密钥、插件证书和密钥，配置防火墙打开 SSH、Docker 和 Flocker 端口，并启动这些系统服务：

+   `flocker-control`

+   `flocker-dataset-agent`

+   `flocker-container-agent`

+   `flocker-docker-plugin`

最后，刷新`docker`服务，重新启动它。

让我们运行它：

```
$ export ANSIBLE_HOST_KEY_CHECKING=False
$ ansible-playbook \
-i inventory \
--private-key keys/flocker \
playbooks/flocker_control_install.yml

```

## 安装集群节点

类似地，我们使用另一个 playbook `flocker_nodes_install.yml` 安装其他节点：

```
$ ansible-playbook \
-i inventory \
--private-key keys/flocker \
playbooks/flocker_nodes_install.yml

```

步骤与以前大致相同，只是这个 playbook 不复制一些证书，也不启动`flocker-control`服务。只有 Flocker 代理和 Flocker Docker 插件服务在那里运行。我们等待一段时间直到 Ansible 退出。

![安装集群节点](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_007.jpg)

## 测试一切是否正常运行

为了检查 Flocker 是否正确安装，我们现在登录到控制节点，检查 Flocker 插件是否正在运行（遗憾的是，它有`.sock`文件），然后我们使用`curl`命令安装`flockerctl`实用程序（参考[`docs.clusterhq.com/en/latest/flocker-features/flockerctl.html`](https://docs.clusterhq.com/en/latest/flocker-features/flockerctl.html)）：

```
$ docker-machine ssh aws-104
$ sudo su -
# ls /var/run/docker/plugins/flocker/
flocker.sock  flocker.sock.lock
# curl -sSL https://get.flocker.io |sh

```

现在我们设置一些`flockerctl`使用的环境变量：

```
export FLOCKER_USER=client
export FLOCKER_CONTROL_SERVICE=54.84.176.7
export FLOCKER_CERTS_PATH=/etc/flocker

```

我们现在可以列出节点和卷（当然，我们还没有卷）：

```
flockerctl status
flockerctl list

```

![测试一切是否正常运行](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_008.jpg)

现在，我们可以转到集群的另一个节点，检查 Flocker 集群的连接性（特别是插件和代理是否能够到达并对控制节点进行身份验证），比如`aws-108`，创建一个卷并向其中写入一些数据：

```
$ docker-machine ssh aws-108
$ sudo su -
# docker run -v test:/data --volume-driver flocker \
busybox sh -c "echo example > /data/test.txt"
# docker run -v test:/data --volume-driver flocker \
busybox sh -c "cat /data/test.txt"
example

```

![测试一切是否正常运行](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_009.jpg)

如果我们回到控制节点`aws-104`，我们可以通过使用 docker 和`flockerctl`命令列出它们来验证已创建具有持久数据的卷：

```
docker volume ls
flockerctl list

```

![测试一切是否正常运行](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_010.jpg)

太棒了！现在我们可以删除已退出的容器，从 Flocker 中删除测试卷数据集，然后我们准备安装 Swarm：

```
# docker rm -v ba7884944577
# docker rm -v 7293a156e199
# flockerctl destroy -d 8577ed21-25a0-4c68-bafa-640f664e774e

```

# 安装和配置 Swarm

现在，我们可以使用我们喜欢的方法安装 Swarm，就像前几章中所示。我们将**aws-101**到**aws-103**作为管理者，除了**aws-104**之外的其他节点作为工作节点。这个集群甚至可以进一步扩展。对于实际的事情，我们将保持在 10 个节点的规模。

![安装和配置 Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_011.jpg)

现在我们添加一个专用的`spark`覆盖 VxLAN 网络：

```
docker network create --driver overlay --subnet 10.0.0.0/24 spark

```

## 一个用于 Spark 的卷

现在我们连接到任何 Docker 主机并创建一个`75G`大小的卷，用于保存一些持久的 Spark 数据：

```
docker volume create -d flocker -o size=75G -o profile=bronze --
    name=spark

```

这里讨论的选项是 `profile`。这是一种存储的类型（主要是速度）。如链接 [`docs.clusterhq.com/en/latest/flocker-features/aws-configuration.html#aws-dataset-backend`](https://docs.clusterhq.com/en/latest/flocker-features/aws-configuration.html#aws-dataset-backend) 中所解释的，ClusterHQ 维护了三种可用的 AWS EBS 配置文件：

+   金牌：EBS Provisioned IOPS / API 名称 io1。配置为其大小的最大 IOPS - 30 IOPS/GB，最大为 20,000 IOPS

+   银牌：EBS 通用 SSD / API 名称 gp2

+   青铜：EBS 磁盘 / API 名称标准

我们可以在 Flocker 控制节点上检查这个卷是否已生成，使用 `flockerctl list`。

# 再次部署 Spark

我们选择一个主机来运行 Spark 独立管理器，即 `aws-105`，并将其标记为这样：

```
docker node update --label-add type=sparkmaster aws-105

```

其他节点将托管我们的 Spark 工作节点。

我们在 `aws-105` 上启动 Spark 主节点：

```
$ docker service create \
--container-label spark-master \
--network spark \
--constraint 'node.labels.type == sparkmaster' \
--publish 8080:8080 \
--publish 7077:7077 \
--publish 6066:6066 \
--name spark-master \
--replicas 1 \
--env SPARK_MASTER_IP=0.0.0.0 \
--mount type=volume,target=/data,source=spark,volume-driver=flocker 
    \
fsoppelsa/spark-master

```

首先是镜像。我发现 Google 镜像中包含一些恼人的东西（例如取消设置一些环境变量，因此无法使用 `--env` 开关从外部进行配置）。因此，我创建了一对 Spark 1.6.2 主节点和工作节点镜像。

然后，`--network`。在这里，我们告诉这个容器连接到名为 spark 的用户定义的覆盖网络。

最后，存储：`--mount`，它与 Docker 卷一起使用。我们将其指定为：

+   使用卷：`type=volume`

+   在容器内挂载卷到 `/data`：`target=/data`

+   使用我们之前创建的 `spark` 卷：`source=spark`

+   使用 Flocker 作为 `volume-driver`

当您创建一个服务并挂载某个卷时，如果卷不存在，它将被创建。

### 注意

当前版本的 Flocker 只支持 1 个副本。原因是 iSCSI/块级挂载不能跨多个节点附加。因此，一次只有一个服务可以使用卷，副本因子为 1。这使得 Flocker 更适用于存储和移动数据库数据（这是它的主要用途）。但在这里，我们将用它来展示在 Spark 主节点容器中的持久数据的一个小例子。

因此，根据这个配置，让我们添加三个 Spark 工作节点：

```
$ docker service create \
--constraint 'node.labels.type != sparkmaster' \
--network spark \
--name spark-worker \
--replicas 3 \
--env SPARK\_MASTER\_IP=10.0.0.3 \
--env SPARK\_WORKER\_CORES=1 \
--env SPARK\_WORKER\_MEMORY=1g \
fsoppelsa/spark-worker

```

在这里，我们将一些环境变量传递到容器中，以限制每个容器的资源使用量为 1 核心和 1G 内存。

几分钟后，系统启动，我们连接到 `aws-105`，端口 `8080`，并看到这个页面：

部署 Spark，再次

## 测试 Spark

所以，我们访问 Spark shell 并运行一个 Spark 任务来检查是否一切正常。

我们准备一个带有一些 Spark 实用程序的容器，例如`fsoppelsa/spark-worker`，并运行它来使用 Spark 二进制文件`run-example`计算 Pi 的值：

```
docker run -ti fsoppelsa/spark-worker /spark/bin/run-example 
    SparkPi

```

经过大量输出消息后，Spark 完成计算，给出：

```
...
Pi is roughly 3.14916
...

```

如果我们回到 Spark UI，我们可以看到我们惊人的 Pi 应用程序已成功完成。

![测试 Spark](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_013.jpg)

更有趣的是运行一个连接到主节点执行 Spark 作业的交互式 Scala shell：

```
$ docker run -ti fsoppelsa/spark-worker \
/spark/bin/spark-shell --master spark://<aws-105-IP>:7077

```

![测试 Spark](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_014.jpg)

## 使用 Flocker 存储

仅用于本教程的目的，我们现在使用之前创建的 spark 卷来运行一个示例，从 Spark 中读取和写入一些持久数据。

为了做到这一点，并且由于 Flocker 限制了副本因子，我们终止当前的三个工作节点集，并创建一个只有一个的集合，挂载 spark：

```
$ docker service rm spark-worker
$ docker service create \
--constraint 'node.labels.type == sparkmaster' \
--network spark \
--name spark-worker \
--replicas 1 \
--env SPARK\_MASTER\_IP=10.0.0.3 \
--mount type=volume,target=/data,source=spark,volume-driver=flocker\
fsoppelsa/spark-worker

```

我们现在获得了主机`aws-105`的 Docker 凭据：

```
$ eval $(docker-machine env aws-105)

```

我们可以尝试通过连接到 Spark 主容器在`/data`中写入一些数据。在这个例子中，我们只是将一些文本数据（lorem ipsum 的内容，例如在[`www.loremipsum.net`](http://www.loremipsum.net/)上可用）保存到`/data/file.txt`中。

```
$ docker exec -ti 13ad1e671c8d bash
# echo "the content of lorem ipsum" > /data/file.txt

```

![使用 Flocker 存储](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_015.jpg)

然后，我们连接到 Spark shell 执行一个简单的 Spark 作业：

1.  加载`file.txt`。

1.  将其包含的单词映射到它们出现的次数。

1.  将结果保存在`/data/output`中：

```
$ docker exec -ti 13ad1e671c8d /spark/bin/spark-shell
...
scala> val inFile = sc.textFile("file:/data/file.txt")
scala> val counts = inFile.flatMap(line => line.split(" 
        ")).map(word => (word, 1)).reduceByKey(_ + _)
scala> counts.saveAsTextFile("file:/data/output")
scala> ^D

```

![使用 Flocker 存储](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_016.jpg)

现在，让我们在任何 Spark 节点上启动一个`busybox`容器，并检查`spark`卷的内容，验证输出是否已写入。我们运行以下代码：

```
$ docker run -v spark:/data -ti busybox sh
# ls /data
# ls /data/output/
# cat /data/output/part-00000

```

![使用 Flocker 存储](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_017.jpg)

前面的截图显示了预期的输出。关于 Flocker 卷的有趣之处在于它们甚至可以从一个主机移动到另一个主机。许多操作可以以可靠的方式完成。如果一个人正在寻找 Docker 的良好存储解决方案，那么 Flocker 是一个不错的选择。例如，它被 Swisscom Developer cloud（[`developer.swisscom.com/`](http://developer.swisscom.com/)）在生产中使用，该云平台可以通过 Flocker 技术提供**MongoDB**等数据库。即将推出的 Flocker 版本将致力于精简 Flocker 代码库，并使其更加精简和耐用。内置 HA、快照、证书分发和容器中易于部署的代理等项目是接下来的计划。因此，前景一片光明！

# 扩展 Spark

现在我们来说明 Swarm Mode 最令人惊奇的功能--`scale`命令。我们恢复了在尝试 Flocker 之前的配置，因此我们销毁了`spark-worker`服务，并以副本因子`3`重新创建它：

```
aws-101$ docker service create \
--constraint 'node.labels.type != sparkmaster' \
--network spark \
--name spark-worker \
--replicas 3 \
--env SPARK_MASTER_IP=10.0.0.3 \
--env SPARK\_WORKER\_CORES=1 \
--env SPARK\_WORKER\_MEMORY=1g \
fsoppelsa/spark-worker

```

现在，我们使用以下代码将服务扩展到`30`个 Spark 工作节点：

```
aws-101$ docker service scale spark-worker=30

```

经过几分钟，必要的时间来拉取镜像，我们再次检查：

![扩展 Spark](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_018.jpg)

从 Spark web UI 开始：

![扩展 Spark](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_019.jpg)

`scale`可以用来扩展或缩小副本的大小。到目前为止，仍然没有自动扩展或将负载分配给新添加的节点的自动机制。但可以使用自定义工具来实现，或者甚至可以期待它们很快被集成到 Swarm 中。

# 监控 Swarm 托管的应用程序

我（Fabrizio）在 2016 年 8 月在 Reddit 上关注了一个帖子（[`www.reddit.com/r/docker/comments/4zous1/monitoring_containers_under_112_swarm/`](https://www.reddit.com/r/docker/comments/4zous1/monitoring_containers_under_112_swarm/)），用户抱怨新的 Swarm Mode 更难监控。

如果目前还没有官方的 Swarm 监控解决方案，那么最流行的新兴技术组合之一是：Google 的**cAdvisor**用于收集数据，**Grafana**用于显示图形，**Prometheus**作为数据模型。

## Prometheus

Prometheus 团队将该产品描述为：

> *Prometheus 是一个最初在 SoundCloud 构建的开源系统监控和警报工具包。*

Prometheus 的主要特点包括：

+   多维数据模型

+   灵活的查询语言

+   不依赖分布式存储

+   时间序列收集是通过拉模型进行的

+   通过网关支持推送时间序列

+   支持多种图形和仪表板模式

在[`prometheus.io/docs/introduction/overview/`](https://prometheus.io/docs/introduction/overview/)上有一个很棒的介绍，我们就不在这里重复了。Prometheus 的最大特点，在我们看来，是安装和使用的简单性。Prometheus 本身只包括一个从 Go 代码构建的单个二进制文件，以及一个配置文件。

## 安装监控系统

事情可能很快就会发生变化，所以我们只是勾勒了一种在 Docker 版本 1.12.3 上尝试设置 Swarm 监控系统的方法。

首先，我们创建一个新的覆盖网络，以免干扰`ingress`或`spark`网络，称为`monitoring`：

```
aws-101$ docker network create --driver overlay monitoring

```

然后，我们以`全局`模式启动 cAdvisor 服务，这意味着每个 Swarm 节点上都会运行一个 cAdvisor 容器。我们在容器内挂载一些系统路径，以便 cAdvisor 可以访问它们：

```
aws-101$ docker service create \
--mode global \
--name cadvisor \
--network monitoring \
--mount type=bind,src=/var/lib/docker/,dst=/var/lib/docker \
--mount type=bind,src=/,dst=/rootfs \
--mount type=bind,src=/var/run,dst=/var/run \
--publish 8080 \
google/cadvisor

```

然后我们使用`basi/prometheus-swarm`来设置 Prometheus：

```
aws-101$ docker service create \
--name prometheus \
--network monitoring \
--replicas 1 \
--publish 9090:9090 \
prom/prometheus-swarm

```

然后我们添加`node-exporter`服务（再次`全局`，必须在每个节点上运行）：

```
aws-101$ docker service create \
--mode global \
--name node-exporter \
--network monitoring \
--publish 9100 \
prom/node-exporter

```

最后，我们以一个副本启动**Grafana**：

```
aws-101$ docker service create \
--name grafana \
--network monitoring \
--publish 3000:3000 \
--replicas 1 \
-e "GF_SECURITY_ADMIN_PASSWORD=password" \
-e "PROMETHEUS_ENDPOINT=http://prometheus:9090" \
grafana/grafana

```

## 在 Grafana 中导入 Prometheus

当 Grafana 可用时，为了获得 Swarm 健康状况的令人印象深刻的图表，我们使用这些凭据登录 Grafana 运行的节点，端口为`3000`：

```
"admin":"password"

```

作为管理员，我们点击 Grafana 标志，转到**数据源**，并添加`Prometheus`：

![在 Grafana 中导入 Prometheus](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_020.jpg)

会出现一些选项，但映射已经存在，所以只需**保存并测试**：

![在 Grafana 中导入 Prometheus](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_021.jpg)

现在我们可以返回仪表板，点击**Prometheus**，这样我们就会看到 Grafana 的主面板：

![在 Grafana 中导入 Prometheus](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_07_022.jpg)

我们再次利用了开源社区发布的内容，并用一些简单的命令将不同的技术粘合在一起，以获得期望的结果。监控 Docker Swarm 及其应用程序是一个完全开放的研究领域，因此我们也可以期待那里的惊人进化。

# 总结

在本章中，我们使用 Flocker 为 Swarm 基础架构增加了存储容量，并设置了专用的覆盖网络，使我们的示例应用程序（一个 Spark 集群）能够在其上运行，并通过添加新节点（也可以是在新的提供者，如 DigitalOcean 上）轻松扩展。在使用了我们的 Spark 安装和 Flocker 之后，我们最终引入了 Prometheus 和 Grafana 来监控 Swarm 的健康和状态。在接下来的两章中，我们将看到可以插入 Swarm 的新附加功能，以及如何保护 Swarm 基础架构。


# 第八章：探索 Swarm 的其他功能

在本章中，我们将讨论并加深我们对 Docker 和编排系统的两个非常重要的主题的了解：网络和共识。特别是，我们将看到如何：

+   Libnetwork 的基础。

+   Libnetwork 的基本安全性

+   路由网格

+   覆盖网络

+   网络控制平面

+   Libkv

# Libnetwork

Libnetwork 是从头开始设计的网络堆栈，可以与 Docker 一起使用，无论平台、环境、操作系统还是基础设施如何。Libnetwork 不仅是网络驱动程序的接口。它不仅是一个管理 VLAN 或 VXLAN 网络的库，它做得更多。

Libnetwork 是一个完整的网络堆栈，由三个平面组成，即**管理平面**、**控制平面**和**数据平面**，如下图所示：

![Libnetwork](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_08_001.jpg)

+   **管理平面**允许用户、运营商或工具管理网络基础设施。这些操作包括网络监控。管理平面代表 Docker 网络用户体验，提供 API。它还可以通过管理插件进行扩展，例如 IPAM 插件，例如，允许我们控制如何为每个容器分配 IP 地址。

+   **控制平面**是在-scoped gossip 协议中实现的，直接添加了服务发现、加密密钥分发。

+   简而言之，**数据平面**负责在两个端点之间传输网络数据包。网络插件适用于每个数据平面。默认情况下，有一些内置驱动程序。例如，我们在前几章中遇到的覆盖驱动程序直接使用 Linux 和 Windows 内核中的功能，因此对于这种类型的网络，没有驱动程序代码。这也适用于桥接、IPVLAN 和 MacVLAN 驱动程序。相比之下，其他第三方网络需要以插件的形式进行自己的实现。

遵循通常的 Docker UX，即组件应该在任何环境下都能正常工作，网络堆栈也必须是可移植的。为了使 Docker 的网络堆栈可移植，其设计和实现必须是牢固的。例如，管理平面不能被任何其他组件控制。同样，控制平面也不能被其他组件替换。如果允许这样做，当我们将应用程序环境从一个环境更改为另一个环境时，网络堆栈将会崩溃。

## 网络插件

数据平面设计为可插拔的。事实上，它只能由内置或外部插件管理。例如，MacVLAN 被实现为 Docker 1.12 中的一个插件，而不会影响系统的其他部分。

最值得注意的是，我们可以在同一网络堆栈上拥有多个驱动程序和插件，它们可以在不相互干扰的情况下工作。因此，在 Swarm 中，我们通常可以在同一集群上运行覆盖网络、桥接网络以及主机驱动程序。

## 容器网络模型

Libnetwork 的设计和实现是为了满足 Docker Swarm 运行 Docker 分布式应用程序的要求。也就是说，Libnetwork 实际上是 Docker 网络基础架构。Libnetwork 的基础是一个称为**容器网络模型**（**CNM**）的模型。这是一个明确定义的基本模型，描述了容器如何连接到给定的网络。CNM 由三个组件组成：

+   **沙盒**：这是一个包含容器网络堆栈配置的隔离。

+   **端点**：这是一个仅属于网络和沙盒的连接点。

+   **网络**：这是一组允许彼此自由通信的端点。一个网络由一个或多个端点组成。

驱动程序代表数据平面。每个驱动程序，无论是覆盖、桥接还是 MacVLAN，都以插件的形式存在。每个插件都在特定于其的数据平面上工作。

在系统中，默认情况下有一个内置的 IPAM。这是一个重要问题，因为每个容器必须有一个附加的 IP 地址。因此，有必要内置一个 IPAM 系统，允许每个容器能够像我们以传统方式那样连接到彼此，并且我们需要一个 IP 地址让其他人与容器通信。我们还需要定义子网以及 IP 地址范围。此外，该系统设计为 IPAM 可插拔。这意味着它允许我们拥有自己的 DHCP 驱动程序或允许将系统连接到现有的 DHCP 服务器。

如前所述，Libnetwork 支持开箱即用的多主机网络。值得讨论的多主机网络的组件是其数据平面和控制平面。

Docker 1.12 中的控制平面目前使用八卦机制作为节点的一般发现系统。这种基于八卦协议的网络在 Raft 一致性系统的另一层上同时工作。基本上，我们有两种不同的成员机制同时工作。Libnetwork 允许其他插件的驱动程序共同使用控制平面。

这些是 Libnetwork 控制平面的特点：

+   它是安全和加密的

+   每个数据平面都可以使用它

+   它提供了原生的服务发现和负载均衡功能

Docker 1.12 在 Swarm 中实现了基于 VIP 的服务发现。这项服务通过将容器的虚拟 IP 地址映射到 DNS 记录来工作。然后所有的 DNS 记录都通过八卦进行共享。在 Docker 1.12 中，随着服务概念的引入，这个概念直接适用于发现的概念。

在 Docker 1.11 和之前的版本中，需要使用容器名称和别名来“模拟”服务发现，并进行 DNS 轮询来执行某种原始的负载均衡。

Libnetwork 延续了“电池内置但可拆卸”的原则，这是作为插件系统实现的。在未来，Libnetwork 将逐渐扩展插件系统，以涵盖其他网络部分，例如负载均衡。

# 加密和路由网格

正如之前提到的，Libnetwork 的核心模型是 CNM。在 Swarm 模式下，libnetwork 以集群感知模式构建，并支持多主机网络而无需外部键值存储。覆盖网络自然适应于这种模型。同时引入了数据平面和控制平面加密。通过加密的控制平面，例如 VXLAN 上的路由信息，容器具有哪个 MAC 地址和哪个 IP 地址，将自动得到保护。此外，通过路由网格，CNM 提供了一种分散的机制，允许您从集群的任何 IP 访问服务。当请求来自外部并命中集群的任何节点时，流量将被路由到一个工作容器。

# MacVLAN

1.12 版本中的新驱动程序是 MacVLAN。MacVLAN 是一个高性能的驱动程序，旨在允许 Docker 网络连接到现有的 VLAN，例如公司的一个 VLAN，让一切继续工作。有一种情况是我们将逐渐将工作负载从原始 VLAN 迁移到 Docker，MacVLAN 将帮助将 Docker 集群连接到原始 VLAN。这将使 Docker 网络与底层网络集成，容器将能够在相同的 VLAN 中工作。

我们可以使用 MacVLAN 驱动程序创建一个网络，并将真实子网指定给该网络。我们还可以为容器指定一系列 IP 地址。此外，我们可以使用`--aux-address`排除一些 IP 地址，例如网关，不分配给容器。MacVLAN 驱动程序的父接口是我们希望将该网络连接到的接口。如前所述，MacVLAN 驱动程序的性能最佳。其 Linux 实现非常轻量级。它们只是强制执行网络之间的分离和连接到物理父网络，而不是作为传统的 Linux 桥接实现网络隔离。MacVLAN 驱动程序的使用需要 Linux 内核 3.9-3.19 或 4.x。

## 覆盖网络

由于 Swarm 集群现在是内置在 Docker Engine 中的本机功能，这使得创建覆盖网络非常容易，而无需使用外部键值存储。

管理节点负责管理网络的状态。所有网络状态都保存在 Raft 日志中。Swarm 模式中 Raft 实现与外部键值存储的主要区别在于，嵌入式 Raft 的性能远高于外部存储。我们自己的实验证实，外部键值存储将保持在 100-250 个节点左右，而嵌入式 Raft 帮助我们将系统扩展到了 Swarm3k 事件中的 4,700 个节点。这是因为外部 Raft 存储基本上具有很高的网络延迟。当我们需要就某些状态达成一致时，我们将从网络往返中产生开销，而嵌入式 Raft 存储只是存在于内存中。

过去，当我们想要执行任何与网络相关的操作，例如为容器分配 IP 地址时，由于我们总是与外部存储进行通信，会发生显着的网络延迟。对于嵌入式 Raft，当我们希望就某些值达成共识时，我们可以立即在内存存储中进行。

![覆盖网络](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_08_002.jpg)

当我们使用覆盖驱动程序创建网络时，如下所示：

```
$ docker network create --driver overlay --subnet 10.9.0.0/24 mh_net

```

命令将与分配器交谈。然后将进行子网保留，例如`10.9.0.0/24`，并在分配后立即在管理主机的内存中同意相关值。之后我们想要创建一个服务。然后我们稍后将该服务连接到网络。当我们创建一个服务时，如下所示：

```
$ docker service create --network mh_net nginx

```

编排器为该服务创建了一些任务（容器）。然后为每个创建的任务分配一个 IP 地址。在此分配过程中，分配将再次起作用。

任务创建完成后：

+   任务获得一个 IP 地址

+   其与网络相关的信息将被提交到 Raft 日志存储中

+   在分配完成后，调度程序将任务移动到另一个状态

+   调度程序将每个任务分派给工作节点之一

+   最后，与该任务关联的容器将在 Docker Engine 上运行

如果任务无法分配其网络资源，它将停留在分配状态，并且不会被调度。这是与以前版本的 Docker 不同的重要差异，在 Swarm 模式的网络系统中，分配状态的概念是明显的。通过这种方式，它大大改善了系统的整体分配周期。当我们谈论分配时，我们不仅指 IP 地址的分配，还包括相关的驱动程序工件。对于覆盖网络，需要保留一个 VXLAN 标识符，这是每个 VXLAN 的一组全局标识符。这个标识符的保留是由网络分配器完成的。

将来，要实现相同的分配机制，插件只需实现一些接口，并使状态自动由 Libnetwork 管理并存储到 Raft 日志中。通过这种方式，资源分配是以集中方式进行的，因此我们可以实现一致性和共识。有了共识，我们需要一个高效的共识协议。

# 网络控制平面

网络控制平面是 Libnetwork 的一个子系统，用于管理路由信息，我们需要一个能够快速收敛的协议来完成这项工作。例如，Libnetwork 不使用 BGP 作为协议（尽管 BGP 在支持非常大数量的端点方面非常出色），因为点对点的 BGP 收敛速度不够快，无法在诸如软件容器环境这样高度动态的环境中使用。

在以容器为中心的世界中，网络系统预计会发生非常快速的变化，特别是对于新的 Docker 服务模型，它需要大规模且快速的 IP 分配。我们也希望路由信息在大规模情况下能够非常快速地收敛，例如对于超过 10,000 个容器。在 Swarm2k 和 Swarm3k 的实验中，我们确实一次启动了 10,000 个容器。特别是在 Swarm3k 中，我们在入口负载均衡网络上启动了 4,000 个 NGINX 容器。如果没有良好的实现，这种规模的数量将无法正常工作。

为了解决这个问题，Libnetwork 团队选择在网络控制平面中包含八卦协议。协议的内部算法工作方式如下：它选择 3 个邻居，然后传播相同的信息；在 Libnetwork 的情况下，是路由和其他与网络相关的信息。八卦协议将重复执行此过程，直到每个节点共享相同的信息。通过这种技术，整个集群将在几秒钟内非常快速地接收到信息。

![网络控制平面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_08_003.jpg)

无论如何，整个集群并不需要始终具有相同的信息。集群中的每个节点并不需要知道所有网络的信息。只有特定网络中的节点需要知道自己的网络信息。为了优化 Libnetwork，团队实现了两个范围，*集群范围的八卦通信*和*网络范围的八卦通信*。到目前为止，我们所解释的是集群范围的八卦通信，而网络范围的八卦通信将限制特定网络内的网络信息。当网络扩展以覆盖额外节点时，其八卦范围广播也将覆盖它们。

这项活动是建立在 Docker 的 CNM 之上的，因此依赖于网络抽象。从图中可以看出，左侧网络中有节点**w1**、**w2**和**w3**，右侧网络中也有**w3**、**w4**和**w5**。左侧网络执行八卦，只有**w1**、**w2**、**w3**才会知道其路由信息。您可能会注意到 w3 同时存在于两个网络中。因此，它将接收所有左侧和右侧网络的路由信息。

# Libkv

`libkv`是一个统一的库，用于与不同的键值存储后端进行交互。`libkv`最初是 Docker Swarm v1 的一部分，在最初的开发版本中。后来，所有与键值存储发现服务相关的代码都经过了重构，并移至[www.github.com/docker/libkv](https://github.com/docker/libkv)。

`libkv`允许您执行 CRUD 操作，还可以从不同的后端观察键值条目，因此我们可以使用相同的代码与所有 HA 分布式键值存储一起工作，这些存储包括**Consul**，**Etcd**和**ZooKeeper**，如下图所示。在撰写本文时，libkv 还支持使用**BoltDB**实现的本地存储。

![Libkv](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_08_004.jpg)

## 如何使用 libkv

要开始使用`libkv`，我们首先需要了解如何调用其 API。以下是 Go 中的`libkv Store`接口，适用于每个存储实现：

```
type Store interface {
Put(key string, value []byte, options *WriteOptions) error
Get(key string) (*KVPair, error)
Delete(key string) error
Exists(key string) (bool, error)
Watch(key string, stopCh <-chan struct{}) (<-chan *KVPair, error)
WatchTree(directory string, stopCh <-chan struct{}) (<-chan  
       []*KVPair, 
       error)
NewLock(key string, options *LockOptions) (Locker, error)
List(directory string) ([]*KVPair, error)
DeleteTree(directory string) error
AtomicPut(key string, value []byte, previous *KVPair, options 
       *WriteOptions) (bool, *KVPair, error)
AtomicDelete(key string, previous *KVPair) (bool, error)
Close()
}

```

我们需要知道如何`Put`，`Get`，`Delete`和`Watch`来基本地与存储进行交互。

确保您的计算机上还安装了 Go 和 Git，并且 Git 可执行文件位于您的 PATH 上。然后，我们需要执行一些 go get 来安装我们程序的依赖项：

```
$ go get github.com/docker/libkv
$ go get github.com/davecgh/go-spew/spew
$ go get github.com/hashicorp/consul/api

```

这里我们提供了一个框架。在尝试运行以下程序之前，您需要启动一个单节点的`Consul`：

```
# Delete all keys in Consul
$ curl -X DELETE http://localhost:8500/v1/kv/?recurse
# Compile the program
$ go build main.go
# Run it
$ ./main
# Spew is dumping the result for us in details
([]*store.KVPair) (len=1 cap=2) {
(*store.KVPair)(0x10e00de0)({
Key: (string) (len=27) "docker/nodes/127.0.0.1:2375",
Value: ([]uint8) (len=14 cap=15) {
00000000  31 32 37 2e 30 2e 30 2e  31 3a 32 33 37 35        
      |127.0.0.1:2375|
},
LastIndex: (uint64) 736745
})
}

```

您还可以使用 curl 测试获取您的值。您放置的值应该在那里。我们应该继续使用`libkv`的 API，即`Get`和`Delete`。这留给读者作为练习。

# 总结

本章介绍了 Libnetwork，这是 Docker Swarm 中最重要的部分之一。我们已经讨论了其管理平面，控制平面和数据平面。本章还包括一些关于如何使用`libkv`的技术，这是一个键值抽象，用于实现您自己的服务发现系统。在下一章中，我们将专注于安全性。在下一章中，我们将学习如何保护一个集群。
