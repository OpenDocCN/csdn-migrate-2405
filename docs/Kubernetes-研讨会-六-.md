# Kubernetes 研讨会（六）

> 原文：[`zh.annas-archive.org/md5/DFC15E6DFB274E63E53841C0858DE863`](https://zh.annas-archive.org/md5/DFC15E6DFB274E63E53841C0858DE863)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章： 构建您自己的 HA 集群

概述

在本章中，我们将学习 Kubernetes 如何使我们能够部署具有显著弹性的基础设施，以及如何在 AWS 云中设置一个高可用性的 Kubernetes 集群。本章将帮助您了解是什么使 Kubernetes 能够用于高可用性部署，并帮助您在为您的用例设计生产环境时做出正确的选择。在本章结束时，您将能够在 AWS 上设置一个适当的集群基础设施，以支持您的高可用性（HA）Kubernetes 集群。您还将能够在生产环境中部署应用程序。

# 介绍

在之前的章节中，您了解了应用程序容器化、Kubernetes 的工作原理，以及 Kubernetes 中的一些“专有名词”或“对象”，这些对象允许您创建一种声明式的应用程序架构，Kubernetes 将代表您执行。

软件和硬件的不稳定在所有环境中都是现实。随着应用程序对更高可用性的需求越来越高，基础设施的缺陷变得更加明显。Kubernetes 是专门为帮助解决容器化应用程序的这一挑战而构建的。但是 Kubernetes 本身呢？作为集群操作员，我们是不是要从像鹰一样监视我们的单个服务器，转而监视我们的单个 Kubernetes 控制基础设施呢？

事实证明，这一方面是 Kubernetes 设计考虑的一个方面。Kubernetes 的设计目标之一是能够经受住其自身基础设施的不稳定性。这意味着当正确设置时，Kubernetes 控制平面可以经受相当多的灾难，包括：

+   网络分裂/分区

+   控制平面（主节点）服务器故障

+   etcd 中的数据损坏

+   许多其他影响可用性的不太严重的事件

不仅可以 Kubernetes 帮助您的应用程序容忍故障，而且您可以放心，因为 Kubernetes 也可以容忍其自身控制基础设施的故障。在本章中，我们将建立一个属于我们自己的集群，并确保它具有高可用性。高可用性意味着系统非常可靠，几乎总是可用的。这并不意味着其中的一切总是完美运行；它只意味着每当用户或客户端需要某些东西时，架构规定 API 服务器应该“可用”来完成工作。这意味着我们必须为我们的应用程序设计一个系统，以自动响应并对任何故障采取纠正措施。

在本章中，我们将看看 Kubernetes 如何整合这些措施来容忍其自身控制架构中的故障。然后，您将有机会进一步扩展这个概念，通过设计您的应用程序来利用这种横向可扩展、容错的架构。但首先，让我们看看机器中不同齿轮如何一起转动，使其具有高可用性。

# Kubernetes 组件如何一起实现高可用性

您已经在《第二章》《Kubernetes 概述》中学到了 Kubernetes 的各个部分是如何一起工作，为您的应用程序容器提供运行时的。但我们需要更深入地研究这些组件如何一起实现高可用性。为了做到这一点，我们将从 Kubernetes 的内存库，也就是 etcd 开始。

## etcd

正如您在之前的章节中学到的，etcd 是存储所有 Kubernetes 配置的地方。这使得它可以说是集群中最重要的组件，因为 etcd 中的更改会影响一切的状态。更具体地说，对 etcd 中的键值对的任何更改都会导致 Kubernetes 的其他组件对此更改做出反应，这可能会导致对您的应用程序的中断。为了实现 Kubernetes 的高可用性，最好有多个 etcd 节点。

但是，当您将多个节点添加到像 etcd 这样的最终一致性数据存储中时，会出现更多的挑战。您是否必须向每个节点写入以保持状态的更改？复制是如何工作的？我们是从一个节点读取还是尽可能多地读取？它如何处理网络故障和分区？谁是集群的主节点，领导者选举是如何工作的？简短的答案是，通过设计，etcd 使这些挑战要么不存在，要么易于处理。etcd 使用一种称为**Raft**的共识算法来实现复制和容错，以解决上述许多问题。因此，如果我们正在构建一个 Kubernetes 高可用性集群，我们需要确保正确设置多个节点（最好是奇数，以便更容易进行领导者选举）的 etcd 集群，并且我们可以依靠它。

注意

etcd 中的领导者选举是一个过程，数据库软件的多个实例共同投票，决定哪个主机将成为处理实现数据库一致性所需的任何问题的权威。有关更多详细信息，请参阅此链接：[`raft.github.io/`](https://raft.github.io/)

## 网络和 DNS

许多在 Kubernetes 上运行的应用程序都需要某种形式的网络才能发挥作用。因此，在为您的集群设计拓扑时，网络是一个重要考虑因素。例如，您的网络应该能够支持应用程序使用的所有协议，包括 Kubernetes 使用的协议。Kubernetes 本身在主节点、节点和 etcd 之间的所有通信都使用 TCP，它还使用 UDP 进行内部域名解析，也就是服务发现。您的网络还应该配置为至少具有与您计划在集群中拥有的节点数量一样多的 IP 地址。例如，如果您计划在集群中拥有超过 256 台机器（节点），那么您可能不应该使用/24 或更高的 IP CIDR 地址空间，因为这样只有 255 个或更少的可用 IP 地址。

在本次研讨会的后续部分，我们将讨论作为集群操作员需要做出的安全决策。然而，在本节中，我们不会讨论这些问题，因为它们与 Kubernetes 实现高可用性的能力没有直接关系。我们将在 *第十三章* *Kubernetes 中的运行时和网络安全* 中处理 Kubernetes 的安全性。

最后要考虑的一件事是你的主节点和工作节点所在的网络，即每个主节点都应该能够与每个工作节点通信。这一点很重要，因为每个主节点都要与工作节点上运行的 Kubelet 进程通信，以确定整个集群的状态。

## 节点和主服务器的位置和资源

由于 etcd 的 Raft 算法的设计，它允许 Kubernetes 的键值存储中发生分布式一致性，我们能够运行多个主节点，每个主节点都能够控制整个集群，而不必担心它们会独立行动（换句话说，变得不受控制）。提醒一下，主节点不同步在 Kubernetes 中是一个问题，考虑到你的应用程序的运行时是由 Kubernetes 代表你发出的命令来控制的。如果由于主节点之间的状态同步问题而导致这些命令发生冲突，那么你的应用程序运行时将受到影响。通过引入多个主节点，我们再次提供了对可能危及集群可用性的故障和网络分区的抵抗力。

Kubernetes 实际上能够以“无头”模式运行。这意味着 Kubelets（工作节点）最后从主节点接收的任何指令都将继续执行，直到可以重新与主节点通信。理论上，这意味着部署在 Kubernetes 上的应用程序可以无限期地运行，即使整个控制平面（所有主节点）崩溃，应用程序所在的工作节点上的 Pods 没有发生任何变化。显然，这是集群可用性的最坏情况，但令人放心的是，即使在最坏的情况下，应用程序不一定会遭受停机时间。

当您计划设计和容量高可用性部署 Kubernetes 时，重要的是要了解一些关于您的网络设计的事情，我们之前讨论过。例如，如果您在流行的云提供商中运行集群，它们可能有“可用区”的概念。数据中心环境的类似概念可能是物理隔离的数据中心。如果可能的话，每个可用区应至少有一个主节点和多个工作节点。这很重要，因为在可用区（数据中心）停机的情况下，您的集群仍然能够在剩余的可用区内运行。这在以下图表中有所说明：

![图 11.1：可用区停机前的集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_11_01.jpg)

图 11.1：可用区停机前的集群

假设可用区 C 完全停机，或者至少我们不再能够与其中运行的任何服务器进行通信。现在集群的行为如下：

![图 11.2：可用区停机后的集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_11_02.jpg)

图 11.2：可用区停机后的集群

正如您在图表中所看到的，Kubernetes 仍然可以执行。此外，如果在可用区 C 中运行的节点的丢失导致应用程序不再处于其期望的状态，这是由应用程序的 Kubernetes 清单所决定的，剩余的主节点将工作以在剩余的工作节点上安排中断的工作负载。

注意

根据您的 Kubernetes 集群中工作节点的数量，您可能需要计划额外的资源约束，因为运行连接到多个工作节点的主节点所需的 CPU 功率。您可以使用此链接中的图表来确定应该部署用于控制您的集群的主节点的资源要求：[`kubernetes.io/docs/setup/best-practices/cluster-large/`](https://kubernetes.io/docs/setup/best-practices/cluster-large/)

## 容器网络接口和集群 DNS

关于您的集群，您需要做出的下一个决定是容器本身如何在每个节点之间进行通信。Kubernetes 本身有一个容器网络接口称为**kubenet**，这是我们在本章中将使用的。

对于较小的部署和简单的操作，从容器网络接口（CNI）的角度来看，kubenet 已经超出了这些集群的需求。然而，它并不适用于每种工作负载和网络拓扑。因此，Kubernetes 提供了对几种不同 CNI 的支持。在考虑容器网络接口的高可用性时，您会希望选择性能最佳且稳定的选项。本文介绍 Kubernetes 的范围超出了讨论每种 CNI 提供的内容。

注意

如果您计划使用托管的 Kubernetes 服务提供商或计划拥有更复杂的网络拓扑，比如单个 VPC 内的多个子网，kubenet 将无法满足您的需求。在这种情况下，您将不得不选择更高级的选项。有关选择适合您环境的正确 CNI 的更多信息，请参阅此处：[`chrislovecnm.com/kubernetes/cni/choosing-a-cni-provider/`](https://chrislovecnm.com/kubernetes/cni/choosing-a-cni-provider/)

## 容器运行时接口

您将不得不做出的最终决定之一是您的容器将如何在工作节点上运行。Kubernetes 的默认选择是 Docker 容器运行时接口，最初 Kubernetes 是为了与 Docker 配合而构建的。然而，自那时以来，已经开发了开放标准，其他容器运行时接口现在与 Kubernetes API 兼容。一般来说，集群操作员倾向于坚持使用 Docker，因为它非常成熟。即使您想探索其他选择，也请记住，在设计能够维持工作负载和 Kubernetes 高可用性的拓扑时，您可能会选择更成熟和稳定的选项，比如 Docker。

注意

您可以在此页面找到与 Kubernetes 兼容的其他一些容器运行时接口：[`kubernetes.io/docs/setup/production-environment/container-runtimes/`](https://kubernetes.io/docs/setup/production-environment/container-runtimes/)

## 容器存储接口

最近的 Kubernetes 版本引入了与数据中心和云提供商中可用的持久性工具进行交互的改进方法，例如存储阵列和 blob 存储。最重要的改进是引入和标准化了用于管理 Kubernetes 中的`StorageClass`，`PersistentVolume`和`PersistentVolumeClaim`的容器存储接口。对于高可用集群的考虑，您需要针对每个应用程序做出更具体的存储决策。例如，如果您的应用程序使用亚马逊 EBS 卷，这些卷必须驻留在一个可用区内，那么您将需要确保工作节点具有适当的冗余，以便在发生故障时可以重新安排依赖于该卷的 Pod。有关 CSI 驱动程序和实现的更多信息，请访问：[`kubernetes-csi.github.io/docs/`](https://kubernetes-csi.github.io/docs/)

# 构建一个以高可用性为重点的 Kubernetes 集群

希望通过阅读前面的部分，您开始意识到当您首次接触这个主题时，Kubernetes 并不像看起来那么神奇。它本身是一个非常强大的工具，但当我们充分利用其在高可用配置中运行的能力时，Kubernetes 真正发挥作用。现在我们将看到如何实施它，并实际使用集群生命周期管理工具构建一个集群。但在我们这样做之前，我们需要了解我们可以部署和管理 Kubernetes 集群的不同方式。

## 自管理与供应商管理的 Kubernetes 解决方案

亚马逊网络服务，谷歌云平台，微软 Azure，以及几乎所有其他主要的云服务提供商都提供了托管的 Kubernetes 解决方案。因此，当您决定如何构建和运行您的集群时，您应该考虑一些不同的托管提供商及其战略性的提供，以确定它们是否符合您的业务需求和目标。例如，如果您使用亚马逊网络服务，那么 Amazon EKS 可能是一个可行的解决方案。

选择托管服务提供商而不是开源和自我管理的解决方案存在一些权衡。例如，很多集群组装的繁重工作都已经为您完成，但在这个过程中您放弃了很多控制权。因此，您需要决定您对能够控制 Kubernetes 主平面有多少价值，以及您是否希望能够选择您的容器网络接口或容器运行时接口。出于本教程的目的，我们将使用开源解决方案，因为它可以部署在任何地方，并且还可以帮助我们理解 Kubernetes 的工作原理以及应该如何配置。

注意

请确保您拥有 AWS 账户并能够使用 AWS CLI 访问：[`aws.amazon.com/cli`](https://aws.amazon.com/cli)。

如果您无法访问它，请按照上面的链接中的说明操作。

假设我们现在想要对我们的集群有更多的控制，并且愿意自己管理它，让我们看一些可以用于设置集群的开源工具。

## kops

我们将使用一个更受欢迎的开源安装工具来完成这个过程，这个工具叫做**kops**，它代表**Kubernetes Operations**。它是一个完整的集群生命周期管理工具，并且具有非常易于理解的 API。作为集群创建/更新过程的一部分，kops 可以生成 Terraform 配置文件，因此您可以将基础设施升级过程作为自己流程的一部分运行。它还具有良好的工具支持 Kubernetes 版本之间的升级路径。

注意

Terraform 是一个基础设施生命周期管理工具，我们将在下一章中简要了解。

kops 的一些缺点是它往往落后于 Kubernetes 的两个版本，它并不总是能够像其他工具那样快速响应漏洞公告，并且目前仅限于在 AWS、GCP 和 OpenStack 中创建集群。

我们决定在本章中使用 kops 来管理我们的集群生命周期的原因有四个：

+   我们希望选择一个工具，可以将一些更令人困惑的 Kubernetes 设置抽象化，以便让您更容易进行集群管理。

+   它支持的云平台不仅仅是 AWS，因此如果您选择不使用亚马逊，您不必被锁定在亚马逊上。

+   它支持对 Kubernetes 基础设施进行广泛的定制，例如选择 CNI 提供程序、决定 VPC 网络拓扑和节点实例组定制。

+   它对零停机集群版本升级有一流的支持，并自动处理该过程。

## 其他常用工具

除了 kops 之外，还有其他几种工具可以用来设置 Kubernetes 集群。您可以在此链接找到完整的列表：[`kubernetes.io/docs/setup/#production-environment`](https://kubernetes.io/docs/setup/#production-environment)。

我们在这里提到其中一些，以便您了解有哪些可用的工具：

+   **kubeadm**：这是从 Kubernetes 源代码生成的工具，它将允许对 Kubernetes 的每个组件进行最大程度的控制。它可以部署在任何环境中。

使用 kubeadm 需要对 Kubernetes 有专家级的了解才能发挥作用。它给集群管理员留下了很少的错误空间，并且使用 kubeadm 升级集群是复杂的。

+   **Kubespray**：这使用 Ansible/Vagrant 风格的配置管理，这对许多 IT 专业人士来说是熟悉的。它更适用于基础设施更为静态而非动态的环境（如云）。Kubespray 非常可组合和可配置，从工具的角度来看。它还允许在裸机服务器上部署集群。关键是要注意协调集群组件和硬件和操作系统的软件升级。由于您提供了云提供商所做的许多功能，您必须确保您的升级过程不会破坏运行在集群之上的应用程序。

因为 Kubespray 使用 Ansible 进行配置，您受到了用于配置大型集群并保持其规范性的 Ansible 底层限制的限制。目前，Kubespray 仅限于以下环境：AWS、GCP、Azure、OpenStack、vSphere、Packet、Oracle Cloud Infrastructure 或您自己的裸机安装。

## Kubernetes 中的身份验证和身份

Kubernetes 使用两个概念进行身份验证：ServiceAccounts 用于标识在 Pods 内运行的进程，而 User Accounts 用于标识人类用户。我们将在本章的后续主题中查看 ServiceAccounts，但首先让我们了解 User Accounts。

从一开始，Kubernetes 一直试图对用户帐户的任何形式的身份验证和身份保持非常中立，因为大多数公司都有一种非常特定的用户身份验证方式。有些使用 Microsoft Active Directory 和 Kerberos，有些可能使用 Unix 密码和 UGW 权限集，有些可能使用云提供商或基于软件的 IAM 解决方案。此外，组织可能使用多种不同的身份验证策略。

因此，Kubernetes 没有内置的身份管理或必需的身份验证方式。相反，它有身份验证“策略”的概念。策略本质上是 Kubernetes 将身份验证的验证委托给另一个系统或方法的方式。

在本章中，我们将使用基于 x509 证书的身份验证。X509 证书身份验证基本上利用了 Kubernetes 证书颁发机构和通用名称/组织名称。由于 Kubernetes RBAC 规则使用`用户名`和`组名`将经过身份验证的身份映射到权限集，x509`通用名称`成为 Kubernetes 的`用户名`，而`组织名称`成为 Kubernetes 中的`组名`。kops 会自动为您提供基于 x509 的身份验证证书，因此几乎不用担心；但是当涉及添加自己的用户时，您需要注意这一点。

注意

Kubernetes RBAC 代表基于角色的访问控制，它允许我们根据用户的角色允许或拒绝对某些访问的访问。这将在*第十三章*《Kubernetes 中的运行时和网络安全》中更深入地介绍。

kops 的一个有趣特性是，你可以像使用 kubectl 管理集群资源一样使用它来管理集群资源。kops 处理节点的方式类似于 Kubernetes 处理 Pod 的方式。就像 Kubernetes 有一个名为“Deployment”的资源来管理一组 Pods，kops 有一个名为**InstanceGroup**的资源（也可以用它的简写形式`ig`）来管理一组节点。在 AWS 的情况下，kops InstanceGroup 实际上创建了一个 AWS EC2 自动扩展组。

扩展这个比较，`kops get instancegroups`或`kops get ig`类似于`kubectl get deployments`，`kops edit`的工作方式类似于`kubectl edit`。我们将在本章后面的活动中使用这个功能，但首先，让我们在下面的练习中启动和运行我们的基本 HA 集群基础设施。

注意

在本章中，命令是使用 Zsh shell 运行的。但是，它们与 Bash 完全兼容。

## 练习 11.01：设置我们的 Kubernetes 集群

注意

这个练习将超出 AWS 免费套餐的范围，该套餐通常赠送给新账户持有者的前 12 个月。EC2 的定价信息可以在这里找到：[`aws.amazon.com/ec2/pricing/`](https://aws.amazon.com/ec2/pricing/)

此外，您应该记得在本章结束时删除您的实例，以停止对您消耗的 AWS 资源进行计费。

在这个练习中，我们将准备在 AWS 上运行 Kubernetes 集群的基础设施。选择 AWS 并没有什么特别之处；Kubernetes 是平台无关的，尽管它已经有了允许它与本地 AWS 服务（EBS、EC2 和 IAM）集成的代码，代表集群运营商。这对于 Azure、GCP、IBM Cloud 和许多其他云平台也是如此。

我们将建立一个具有以下规格的集群：

+   三个主节点

+   三个 etcd 节点（为了简单起见，我们将在主节点上运行这些节点）

+   两个工作节点

+   至少两个可用区

一旦我们设置好了我们的集群，我们将在下一个练习中在其上部署一个应用程序。现在按照以下步骤完成这个练习：

1.  确保您已按*前言*中的说明安装了 kops。使用以下命令验证 kops 是否已正确安装和配置：

```
kops version
```

您应该看到以下响应：

```
Version 1.15.0 (git-9992b4055)
```

现在在我们继续以下步骤之前，我们需要在 AWS 中进行一些设置。以下大部分设置都是可配置的，但为了方便起见，我们将为您做出一些决定。

1.  首先，我们将设置一个 AWS IAM 用户，kops 将用它来提供您的基础设施。在您的终端中依次运行以下命令：

```
aws iam create-group --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonRoute53FullAccess --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/IAMFullAccess --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonVPCFullAccess --group-name kops
aws iam create-user --user-name kops
aws iam add-user-to-group --user-name kops --group-name kops
aws iam create-access-key --user-name kops
```

您应该看到类似于这样的输出：

![图 11.3：为 kops 设置 IAM 用户](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_11_03.jpg)

图 11.3：为 kops 设置 IAM 用户

注意突出显示的`AccessKeyID`和`SecretAccessKey`字段，这是您将收到的输出。这是敏感信息，前面截图中的密钥当然将被作者作废。我们将需要突出显示的信息进行下一步操作。

1.  接下来，我们需要将为 kops 创建的凭据导出为环境变量，用于我们的终端会话。使用前一步截图中的突出信息：

```
export AWS_ACCESS_KEY_ID=<AccessKeyId>
export AWS_SECRET_ACCESS_KEY=<SecretAccessKey>
```

1.  接下来，我们需要为 kops 创建一个 S3 存储桶来存储其状态。要创建一个随机的存储桶名称，请运行以下命令：

```
export BUCKET_NAME="kops-$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 13 ; echo)" && echo $BUCKET_NAME
```

第二个命令输出创建的 S3 存储桶的名称，您应该看到类似以下的响应：

```
kops-aptjv0e9o2wet
```

1.  运行以下命令，使用 AWS CLI 创建所需的存储桶：

```
aws s3 mb s3://$BUCKET_NAME --region us-west-2
```

在这里，我们使用`us-west-2`地区。如果您愿意，您可以使用离您更近的地区。对于成功创建存储桶，您应该看到以下响应：

```
make_bucket: kops-aptjv0e9o2wet
```

现在我们有了 S3 存储桶，我们可以开始设置我们的集群。我们可以选择许多选项，但现在我们将使用默认设置。

1.  导出您的集群名称和 kops 将用于存储其状态的 S3 存储桶的名称：

```
export NAME=myfirstcluster.k8s.local
export KOPS_STATE_STORE=s3://$BUCKET_NAME
```

1.  生成所有的配置并将其存储在之前的 S3 存储桶中，使用以下命令创建一个 Kubernetes 集群：

```
kops create cluster --zones us-west-2a,us-west-2b,us-west-2c --master-count=3 --kubernetes-version=1.15.0 --name $NAME
```

通过传递`--zones`参数，我们正在指定我们希望集群跨越的可用区域，并通过指定`master-count=3`参数，我们有效地表示我们要使用一个高可用的 Kubernetes 集群。默认情况下，kops 将创建两个工作节点。

请注意，这实际上并没有创建集群，而是创建了一系列的预检查，以便我们可以在短时间内创建一个集群。它通知我们，为了访问 AWS 实例，我们需要提供一个公钥 - 默认搜索位置是`~/.ssh/id_rsa.pub`。

1.  现在，我们需要创建一个 SSH 密钥，以添加到所有的主节点和工作节点，这样我们就可以用 SSH 登录到它们。使用以下命令：

```
kops create secret --name myfirstcluster.k8s.local sshpublickey admin -i ~/.ssh/id_rsa.pub
```

秘钥类型（`sshpublickey`）是 kops 为此操作保留的特殊关键字。更多信息可以在此链接找到：[`github.com/kubernetes/kops/blob/master/docs/cli/kops_create_secret_sshpublickey.md`](https://github.com/kubernetes/kops/blob/master/docs/cli/kops_create_secret_sshpublickey.md)。

注意

在这里指定的密钥`~/.ssh/id_rsa.pub`将是 kops 要分发到所有主节点和工作节点并可用于从本地计算机到运行服务器进行诊断或维护目的的密钥。

您可以使用以下命令使用密钥以管理员帐户登录：

```
ssh -i ~/.ssh/id_rsa admin@<public_ip_of_instance>
```

虽然这对于这个练习并不是必需的，但你会发现这对以后的章节很有用。

1.  要查看我们的配置，请运行以下命令：

```
kops edit cluster $NAME
```

这将打开您的文本编辑器，并显示我们集群的定义，如下所示：

![图 11.4：检查我们集群的定义](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_11_04.jpg)

图 11.4：检查我们集群的定义

为了简洁起见，我们已经截取了这个屏幕截图。在这一点上，你可以进行任何编辑，但是对于这个练习，我们将继续进行而不进行任何更改。为了简洁起见，我们将不在本研讨会的范围内保留此规范的描述。如果您想了解 kops 的`clusterSpec`中各种元素的更多细节，可以在这里找到更多详细信息：[`github.com/kubernetes/kops/blob/master/docs/cluster_spec.md`](https://github.com/kubernetes/kops/blob/master/docs/cluster_spec.md)。

1.  现在，拿出我们在 S3 中生成并存储的配置，并实际运行命令，以使 AWS 基础设施与我们在配置文件中所说的想要的状态相一致：

```
kops update cluster $NAME --yes
```

注意

默认情况下，kops 中的所有命令都是 dry-run（除了一些验证步骤外，实际上什么都不会发生），除非您指定`--yes`标志。这是一种保护措施，以防止您在生产环境中意外地对集群造成危害。

这将需要很长时间，但完成后，我们将拥有一个可工作的 Kubernetes HA 集群。您应该看到以下响应：

![图 11.5：更新集群以匹配生成的定义](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_11_05.jpg)

图 11.5：更新集群以匹配生成的定义

1.  为了验证我们的集群是否正在运行，让我们运行以下命令。这可能需要 5-10 分钟才能完全运行：

```
kops validate cluster
```

您应该看到以下响应：

![图 11.6：验证我们的集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_11_06.jpg)

图 11.6：验证我们的集群

从这个屏幕截图中，我们可以看到我们有三个 Kubernetes 主节点分布在不同的可用区，并且两个工作节点分布在三个可用区中的两个（使这个集群具有高可用性）。此外，所有节点以及集群似乎都是健康的。

注意

请记住，您的集群资源仍在运行。如果您计划在一段时间后继续进行下一个练习，您可能希望删除此集群以停止对 AWS 资源的计费。要删除此集群，您可以使用以下命令：

`kops delete cluster --name ${NAME} --yes`

## Kubernetes Service Accounts

正如我们之前学到的，Kubernetes ServiceAccount 对象用作 Pod 内部进程的标识标记。虽然 Kubernetes 不管理和验证人类用户的身份，但它管理和验证 ServiceAccount 对象。然后，类似于用户，您可以允许 ServiceAccount 对 Kubernetes 资源进行基于角色的访问。

ServiceAccount 充当使用**JSON Web Token**（**JWT**）样式、基于标头的身份验证方式对集群进行身份验证的一种方式。每个 ServiceAccount 都与一个令牌配对，该令牌存储在由 Kubernetes API 创建的秘密中，然后挂载到与该 ServiceAccount 关联的 Pod 中。每当 Pod 中的任何进程需要发出 API 请求时，它会将令牌与请求一起传递给 API 服务器，Kubernetes 会将该请求映射到 ServiceAccount。基于该身份，Kubernetes 可以确定应该授予该进程对资源/对象（授权）的访问级别。通常，ServiceAccount 只分配给集群内部的 Pod 使用，因为它们只用于内部使用。ServiceAccount 是一个 Kubernetes 命名空间范围的对象。

ServiceAccount 的示例规范如下：

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kube-system
```

我们将在下一个练习中使用这个示例。您可以通过在对象的定义中包含这个字段来将这个 ServiceAccount 附加到一个对象，比如一个 Kubernetes 部署：

```
serviceAccountName: admin-user
```

如果您创建一个 Kubernetes 对象而没有指定服务账户，它将会被创建为`default`服务账户。`default`服务账户是 Kubernetes 为每个命名空间创建的。

在接下来的练习中，我们将在我们的集群上部署 Kubernetes 仪表板。Kubernetes 仪表板可以说是任何 Kubernetes 集群中运行的最有用的工具之一。它对于调试 Kubernetes 中的工作负载配置问题非常有用。

注意

您可以在这里找到更多信息：[`kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/`](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/)。

## 练习 11.02：在我们的 HA 集群上部署应用程序

在这个练习中，我们将使用在上一个练习中部署的相同集群，并部署 Kubernetes 仪表板。如果您已经删除了集群资源，请重新运行上一个练习。kops 将自动将所需的信息添加到本地 Kube 配置文件中以连接到集群，并将该集群设置为默认上下文。

由于 Kubernetes 仪表板是一个帮助我们进行管理任务的应用程序，`default` ServiceAccount 没有足够的权限。在这个练习中，我们将创建一个具有广泛权限的新 ServiceAccount：

1.  首先，我们将应用直接从官方 Kubernetes 存储库获取的 Kubernetes 仪表板清单。这个清单定义了我们应用程序所需的所有对象。运行以下命令：

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.0.0-beta1/aio/deploy/recommended.yaml
```

您应该看到以下响应：

![图 11.7：应用 Kubernetes 仪表板的清单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_11_07.jpg)

图 11.7：应用 Kubernetes 仪表板的清单

1.  接下来，我们需要配置一个 ServiceAccount 来访问仪表板。为此，请创建一个名为`sa.yaml`的文件，并包含以下内容：

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: kube-system
```

注意

我们给这个用户非常宽松的权限，所以请小心处理访问令牌。ClusterRole 和 ClusterRoleBinding 对象是 RBAC 策略的一部分，这在《第十三章》《Kubernetes 中的运行时和网络安全》中有所涵盖。

1.  接下来，运行以下命令：

```
kubectl apply -f sa.yaml
```

您应该看到这个响应：

```
serviceaccount/admin-user created
clusterrolebinding.rbac.authorization.k8s.io/admin-user created
```

1.  现在，让我们通过运行以下命令来确认 ServiceAccount 的详细信息：

```
kubectl describe serviceaccount -n kube-system admin-user
```

您应该看到以下响应：

![图 11.8：检查我们的 ServiceAccount](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_11_08.jpg)

图 11.8：检查我们的 ServiceAccount

当您在 Kubernetes 中创建一个 ServiceAccount 时，它还会在相同的命名空间中创建一个包含用于对 API 服务器进行 API 调用所需的 JWT 内容的 Secret。正如我们从前面的截图中所看到的，这种情况下的 Secret 的名称是`admin-user-token-vx84g`。

1.  让我们检查`secret`对象：

```
kubectl get secret -n kube-system -o yaml admin-user-token-vx84g
```

您应该看到以下输出：

![图 11.9：检查我们的 ServiceAccount 中的令牌](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_11_09.jpg)

图 11.9：检查我们的 ServiceAccount 中的令牌

这是输出的一个截断截图。正如我们所看到的，我们在这个秘密中有一个令牌。请注意，这是 Base64 编码的，我们将在下一步中解码。

1.  现在我们需要账户 Kubernetes 为我们创建的令牌的内容，所以让我们使用这个命令：

```
kubectl -n kube-system get secret $(kubectl -n kube-system get secret | grep admin-user | awk '{print $1}') -o jsonpath='{.data.token}' | base64 --decode
```

让我们分解这个命令。该命令获取名为`admin-user`的密钥，因为我们创建了一个具有该名称的 ServiceAccount。当在 Kubernetes 中创建 ServiceAccount 时，它会放置一个与我们用于对集群进行身份验证的令牌同名的密钥。命令的其余部分是用于将结果解码为有用的形式以便复制和粘贴到仪表板中的语法糖。您应该得到如下截图所示的输出：

![图 11.10：获取与令牌相关的内容与 admin-user ServiceAccount](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_11_10.jpg)

图 11.10：获取与 admin-user ServiceAccount 关联的令牌的内容

复制您收到的输出，但要小心不要复制输出末尾看到的`$`或`%`符号（在 Bash 或 Zsh 中看到）。

1.  默认情况下，Kubernetes 仪表板不会暴露给集群外的公共互联网。因此，为了使用浏览器访问它，我们需要一种允许浏览器与 Kubernetes 容器网络内的 Pod 进行通信的方式。一个有用的方法是使用内置在`kubectl`中的代理：

```
kubectl proxy
```

您应该看到这个响应：

```
Starting to serve on 127.0.0.1:8001
```

1.  打开浏览器并导航到以下 URL：

```
http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/
```

您应该看到以下提示：

![图 11.11：输入令牌以登录 Kubernetes 仪表板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_11_11.jpg)

图 11.11：输入令牌以登录 Kubernetes 仪表板

粘贴从*步骤 4*复制的令牌，然后单击`SIGN IN`按钮。

成功登录后，您应该看到仪表板如下截图所示：

![图 11.12：Kubernetes 仪表板登陆页面](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_11_12.jpg)

图 11.12：Kubernetes 仪表板登陆页面

在这个练习中，我们已经部署了 Kubernetes 仪表板到集群，以便您可以从方便的 GUI 管理您的应用程序。在部署此应用程序的过程中，我们已经看到了如何为我们的集群创建 ServiceAccounts。

在本章中，您已经学会了如何使用 kops 创建云基础架构，以创建一个高可用的 Kubernetes 集群。然后，我们部署了 Kubernetes 仪表板，并在此过程中了解了 ServiceAccounts。现在您已经看到了创建集群并在其上运行应用程序所需的步骤，我们将创建另一个集群，并在接下来的活动中看到其弹性。

## 活动 11.01：测试高可用集群的弹性

在这个活动中，我们将测试我们自己创建的 Kubernetes 集群的弹性。以下是进行此活动的一些指南：

1.  部署 Kubernetes 仪表板。但是这次，将运行应用程序的部署的副本计数设置为高于`1`的值。

Kubernetes Dashboard 应用程序在由名为`kubernetes-dashboard`的部署管理的 Pod 上运行，该部署在名为`kubernetes-dashboard`的命名空间中运行。这是您需要操作的部署。

1.  现在，开始从 AWS 控制台关闭各种节点，以删除节点，删除 Pod，并尽力使底层系统不稳定。

1.  在您尝试关闭集群的每次尝试后，如果控制台仍然可访问，请刷新 Kubernetes 控制台。只要从应用程序获得任何响应，这意味着集群和我们的应用程序（在本例中为 Kubernetes 仪表板）仍然在线。只要应用程序在线，您应该能够访问 Kubernetes 仪表板，如下截图所示：![图 11.13：Kubernetes 仪表板提示输入令牌](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_11_13.jpg)

图 11.13：Kubernetes 仪表板提示输入令牌

此截图仅显示您需要输入令牌的提示，但足以表明我们的应用程序在线。如果您的请求超时，这意味着我们的集群不再可用。

1.  加入另一个节点到这个集群。

为了实现这一点，您需要找到并编辑管理节点的 InstanceGroup 资源。规范包含`maxSize`和`minSize`字段，您可以操纵这些字段来控制节点的数量。当您更新您的集群以匹配修改后的规范时，您应该能够看到三个节点，如下截图所示：

![图 11.14：集群中主节点和工作节点的数量](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_11_14.jpg)

图 11.14：集群中主节点和工作节点的数量

注意

此活动的解决方案可在以下地址找到：[`packt.live/304PEoD`](https://packt.live/304PEoD)。确保在完成活动后删除您的集群。有关如何删除集群的更多详细信息，请参见以下部分（*删除我们的集群*）。

## 删除我们的集群

一旦我们完成了本章中的所有练习和活动，您应该通过运行以下命令来删除集群：

```
kops delete cluster --name ${NAME} --yes
```

您应该看到这个响应：

![图 11.15：删除我们的集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_11_15.jpg)

图 11.15：删除我们的集群

在这一点上，您不应该再从 AWS 那里收到本章中您所创建的 Kubernetes 基础架构的费用。

# 总结

高可用基础架构是实现应用程序高可用性的关键组成部分之一。Kubernetes 是一个设计非常精良的工具，具有许多内置的弹性特性，使其能够经受住重大的网络和计算事件。它致力于防止这些事件影响您的应用程序。在我们探索高可用性系统时，我们调查了 Kubernetes 的一些组件以及它们如何共同实现高可用性。然后，我们使用 kops 集群生命周期管理工具在 AWS 上构建了一个旨在实现高可用性的集群。

在下一章中，我们将看看如何通过利用 Kubernetes 原语来确保高可用性，使我们的应用程序更具弹性。


# 第十二章： 您的应用程序和 HA

概述

在这一章中，我们将通过使用 Terraform 和 Amazon **Elastic Kubernetes Service** (**EKS**)来探索 Kubernetes 集群的生命周期管理。我们还将部署一个应用程序，并学习一些原则，使应用程序更适合 Kubernetes 环境。

本章将指导您如何使用 Terraform 创建一个功能齐全、高可用的 Kubernetes 环境。您将在集群中部署一个应用程序，并修改其功能，使其适用于高可用环境。我们还将学习如何通过使用 Kubernetes 入口资源将来自互联网的流量传输到集群中运行的应用程序。

# 介绍

在上一章中，我们在云环境中设置了我们的第一个多节点 Kubernetes 集群。在本节中，我们将讨论如何为我们的应用程序操作 Kubernetes 集群，即我们将使用集群来运行除了仪表板之外的容器化应用程序。

由于 Kubernetes 的用途与集群操作员所能想象的一样多，因此 Kubernetes 的用例各不相同。因此，我们将对我们为集群操作的应用程序类型做一些假设。我们将优化一个工作流程，用于在基于云的环境中部署具有高可用性要求的具有有状态后端的无状态 Web 应用程序。通过这样做，我们希望能够涵盖人们通常使用 Kubernetes 集群的大部分内容。

Kubernetes 可以用于几乎任何事情。即使我们所涵盖的内容与您对 Kubernetes 的用例不完全匹配，也值得研究，因为这一点很重要。在本章中，我们要做的只是在云中运行一个 Web 应用程序的示例工作流程。一旦您学习了本章中我们将用于运行示例工作流程的原则，您可以在互联网上查找许多其他资源，帮助您发现其他优化工作流程的方式，如果这不符合您的用例。

但在我们继续确保我们将在集群上运行的应用程序的高可用性之前，让我们退一步考虑一下你的云基础设施的高可用性要求。为了在应用程序级别保持高可用性，同样重要的是我们以同样的目标来管理我们的基础设施。这让我们开始讨论基础设施生命周期管理。

# 基础设施生命周期管理概述

简单来说，基础设施生命周期管理是指我们如何在服务器的有用生命周期的每个阶段管理我们的服务器。这涉及到提供、维护和 decommissioning 物理硬件或云资源。由于我们正在利用云基础设施，我们应该利用基础设施生命周期管理工具来以编程方式提供和取消资源。为了理解这一点为什么重要，让我们考虑以下例子。

想象一下，你是一名系统管理员、DevOps 工程师、站点可靠性工程师，或者其他需要处理公司服务器基础设施的角色，而这家公司是数字新闻行业的公司。这意味着，这家公司的员工主要输出的是他们在网站上发布的信息。现在，想象一下，整个网站都在你公司服务器房的一台服务器上运行。服务器上运行的应用程序是一个带有 MySQL 后端的 PHP 博客网站。有一天，一篇文章突然爆红，你突然要处理的流量比前一天多得多。你会怎么做？网站一直崩溃（如果加载的话），你的公司正在因为你试图找到解决方案而损失金钱。

你的解决方案是开始分离关注点并隔离单点故障。你首先要做的是购买更多的硬件并开始配置它，希望能够水平扩展网站。做完这些之后，你运行了五台服务器，其中一台运行着 HAProxy，它负载均衡连接到运行在三台服务器上的 PHP 应用程序和一个数据库服务器上。好吧，现在你觉得你已经控制住了。然而，并非所有的服务器硬件都是一样的——它们运行着不同的 Linux 发行版，每台机器的资源需求也不同，对每台服务器进行补丁、升级和维护变得困难。好巧不巧，又一篇文章突然爆红，你突然面临着比当前硬件能处理的请求量多五倍的情况。现在你该怎么办？继续水平扩展？然而，你只是一个人，所以在配置下一组服务器时很可能会出错。由于这个错误，你以新颖的方式使网站崩溃了，管理层对此并不高兴。你读到这里是不是感到和我写这篇文章时一样紧张？

正是因为配置错误，工程师们开始利用工具和配置编写源代码来定义他们的拓扑结构。这样，如果需要对基础设施状态进行变更，就可以跟踪、控制并以一种使代码负责解决你声明的基础设施状态与实际观察到的状态之间差异的方式进行部署。

基础设施的好坏取决于围绕它的生命周期管理工具和运行在其之上的应用程序。这意味着，如果你的集群构建得很好，但没有工具可以成功地更新集群上的应用程序，那么它就不会为你服务。在本章中，我们将从应用程序级别的视角来看如何利用持续集成构建流水线以零停机、云原生的方式推出新的应用程序更新。

在本章中，我们将为您提供一个测试应用程序进行管理。我们还将使用一个名为**Terraform**的基础设施生命周期管理工具，以更有效地管理 Kubernetes 云基础设施的部署。本章应该能帮助您开发出一套有效的技能，让您能够在 Kubernetes 环境中快速开始创建自己的应用程序交付流水线。

# Terraform

在上一章中，我们使用**kops**从头开始创建了一个 Kubernetes 集群。然而，这个过程可能被视为繁琐且难以复制，这会导致配置错误的高概率，从而在应用程序运行时导致意外事件。幸运的是，有一个非常强大的社区支持的工具，可以很好地解决这个问题，适用于在**亚马逊网络服务**（**AWS**）以及其他几个云平台上运行的 Kubernetes 集群，比如 Azure、**谷歌云平台**（**GCP**）等。

Terraform 是一种通用的基础设施生命周期管理工具；也就是说，Terraform 可以通过代码管理您的基础设施的状态。Terraform 最初创建时的目标是创建一种语言（**HashiCorp 配置语言**（**HCL**））和运行时，可以以可重复的方式创建基础设施，并以与我们控制应用程序源代码变更相同的方式控制对基础设施的变更——通过拉取请求、审查和版本控制。Terraform 自那时以来已经有了相当大的发展，现在是一种通用的配置管理工具。在本章中，我们将使用其最经典的意义上的基础设施生命周期管理的原始功能。

Terraform 文件是用一种叫做 HCL 的语言编写的。HCL 看起来很像 YAML 和 JSON，但有一些不同之处。例如，HCL 支持在其文件中对其他资源的引用进行插值，并能够确定需要创建资源的顺序，以确保依赖于其他资源创建的资源不会以错误的顺序创建。Terraform 文件的文件扩展名是`.tf`。

您可以将 Terraform 文件视为以类似的方式指定整个基础设施的期望状态，例如，Kubernetes YAML 文件将指定部署的期望状态。这允许声明式地管理整个基础设施。因此，我们得到了**基础设施即代码**（**IaC**）的管理思想。

Terraform 分为两个阶段——**计划**和**应用**。这是为了确保您有机会在进行更改之前审查基础设施更改。Terraform 假设它独自负责对基础设施的所有状态更改。因此，如果您使用 Terraform 来管理基础设施，通过任何其他方式进行基础设施更改（例如，通过 AWS 控制台添加资源）是不明智的。这是因为如果您进行更改并且没有确保它在 Terraform 文件中得到更新，那么下次应用 Terraform 文件时，它将删除您一次性的更改。这不是一个错误，这是一个功能，这次是真的。这样做的原因是，当您跟踪基础设施作为代码时，每个更改都可以被跟踪、审查和使用自动化工具进行管理，例如 CI/CD 流水线。因此，如果您的系统状态偏离了书面状态，那么 Terraform 将负责将您观察到的基础设施与您书面记录的内容进行调和。

在本章中，我们将向您介绍 Terraform，因为它在行业中被广泛使用，作为管理基础设施的便捷方式。但是，我们不会深入到使用 Terraform 创建每一个 AWS 资源，以便让我们的讨论集中在 Kubernetes 上。我们只会进行一个快速演示，以确保您理解一些基本原则。

注意

您可以在本书中了解有关在 AWS 中使用 Terraform 的更多信息：[`www.packtpub.com/networking-and-servers/getting-started-terraform-second-edition`](https://www.packtpub.com/networking-and-servers/getting-started-terraform-second-edition)

## 练习 12.01：使用 Terraform 创建 S3 存储桶

在这个练习中，我们将实现一些常用的命令，这些命令在使用 Terraform 时会用到，并向您介绍一个 Terraform 文件，该文件将是我们基础设施的定义。

注意

Terraform 将代表我们在 AWS 上创建资源，这将花费你的钱。

1.  首先，让我们创建一个目录，我们将在其中进行 Terraform 更改，然后我们将导航到该目录：

```
mkdir -p ~/Desktop/eks_terraform_demo
cd Desktop/eks_terraform_demo/
```

1.  现在，我们要创建我们的第一个 Terraform 文件。Terraform 文件的扩展名是`.tf`。创建一个名为`main.tf`的文件（与其他一些语言不同，单词`main`没有特殊意义），内容如下：

```
resource "aws_s3_bucket" "my_bucket" {
  bucket = "<<NAME>>-test-bucket"
  acl    = "private"
}
```

这个块有一个叫做`aws_s3_bucket`的定义，这意味着它将创建一个 Amazon S3 存储桶，其名称在`bucket`字段中指定。`acl="private"`行表示我们不允许公共访问这个存储桶。请确保用您自己的唯一名称替换`<<NAME>>`。

1.  要开始使用 Terraform，我们需要初始化它。因此，让我们用以下命令来做到这一点：

```
terraform init
```

您应该看到以下响应：

![图 12.1：初始化 Terraform](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_01.jpg)

图 12.1：初始化 Terraform

1.  运行以下命令，让 Terraform 确定创建资源的计划，这些资源由我们之前创建的`main.tf`文件定义：

```
terraform plan
```

您将被提示输入一个 AWS 区域。使用离您最近的一个。在下面的屏幕截图中，我们使用的是`us-west-2`：

![图 12.2：计算集群资源所需的更改用于创建 S3 存储桶](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_02.jpg)

图 12.2：计算创建 S3 存储桶所需的集群资源的必要更改

因此，我们可以看到 Terraform 已经使用我们在上一章*练习 11.01，在我们的 Kubernetes 集群中设置 AWS 账户*中设置的访问密钥访问了我们的 AWS 账户，并计算了为使我们的 AWS 环境看起来像我们在 Terraform 文件中定义的那样需要做什么。正如我们在屏幕截图中看到的，它计划为我们添加一个 S3 存储桶，这正是我们想要的。

注意

Terraform 将尝试应用当前工作目录中所有扩展名为`.tf`的文件。

在上一个屏幕截图中，我们可以看到`terraform`命令指示我们没有指定`-out`参数，因此它不会保证精确计划将被应用。这是因为您的 AWS 基础设施中的某些内容可能已经从计划时发生了变化。假设您今天计划了一个计划。然后，稍后，您添加或删除了一些资源。因此，为了实现给定状态所需的修改将是不同的。因此，除非您指定`-out`参数，否则 Terraform 将在应用之前重新计算其计划。

1.  运行以下命令来应用配置并创建我们 Terraform 文件中指定的资源：

```
terraform apply
```

Terraform 将为我们提供一次机会来审查计划并在对 AWS 资源进行更改之前决定我们想要做什么：

![图 12.3：计算更改并确认创建 S3 存储桶的提示](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_03.jpg)

图 12.3：计算更改并确认创建 S3 存储桶的提示

如前所述，即使我们使用`apply`命令，Terraform 也计算了所需的更改。确认 Terraform 显示的操作，然后输入`yes`以执行显示的计划。现在，Terraform 已经为我们创建了一个 S3 存储桶：

![图 12.4：确认后创建 S3 存储桶](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_04.jpg)

图 12.4：确认后创建 S3 存储桶

1.  现在，我们将销毁我们创建的所有资源，以便在进行下一个练习之前进行清理。要销毁它们，请运行以下命令：

```
terraform destroy
```

再次，要确认此操作，您必须在提示时明确允许 Terraform 销毁您的资源，输入`yes`，如以下屏幕截图所示：

![图 12.5：使用 Terraform 销毁资源](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_05.jpg)

图 12.5：使用 Terraform 销毁资源

在这个练习中，我们演示了如何使用 Terraform 创建单个资源（S3 存储桶），以及如何销毁存储桶。这应该让您熟悉了 Terraform 的简单工具，并且我们现在将进一步扩展这些概念。

现在，让我们使用 Terraform 创建一个 Kubernetes 集群。上次，我们构建并管理了自己的集群控制平面。由于几乎每个云提供商都为他们的客户提供此服务，我们将利用由 AWS 提供的 Kubernetes 的托管服务 Amazon 弹性 Kubernetes 服务（EKS）。

当我们使用托管的 Kubernetes 服务时，以下内容由云服务供应商处理：

+   管理和保护 etcd

+   管理和保护用户身份验证

+   管理控制平面组件，如控制器管理器、调度器和 API 服务器

+   在您的网络中运行的 Pod 之间进行 CNI 配置

控制平面通过绑定到您的 VPC 的弹性网络接口暴露给您的节点。您仍然需要管理工作节点，它们作为您帐户中的 EC2 实例运行。因此，使用托管服务允许您专注于使用 Kubernetes 完成的工作，但缺点是对控制平面没有非常精细的控制。

注意

由于 AWS 处理集群的用户身份验证，我们将不得不使用 AWS IAM 凭据来访问我们的 Kubernetes 集群。我们可以在我们的机器上利用 AWS IAM Authenticator 二进制文件来做到这一点。关于这一点，我们将在接下来的章节中详细介绍。

## 练习 12.02：使用 Terraform 创建 EKS 集群

对于这个练习，我们将使用我们已经提供的`main.tf`文件来创建一个生产就绪、高可用的 Kubernetes 集群。

注意

这个 Terraform 文件是从[`github.com/terraform-aws-modules/terraform-aws-eks/tree/master/examples`](https://github.com/terraform-aws-modules/terraform-aws-eks/tree/master/examples)提供的示例进行了调整。

这将使 Terraform 能够创建以下内容：

+   一个具有 IP 地址空间`10.0.0.0/16`的 VPC。它将有三个公共子网，每个子网都有`/24`（`255`）个 IP 地址。

+   路由表和 VPC 的互联网网关需要正常工作。

+   控制平面与节点通信的安全组，以及在允许和必需的端口上接收来自外部世界的流量。

+   EKS 控制平面的 IAM 角色（执行诸如代表您创建服务的**ELB**（弹性负载均衡器）等任务）和节点（处理与 EC2 API 相关的问题）。

+   EKS 控制平面以及与您的 VPC 和节点的所有必要连接的设置。

+   一个用于节点加入集群的**ASG**（自动扩展组）（它将提供两个**m4.large**实例）。

+   生成一个 kubeconfig 文件和一个 ConfigMap，这对于节点加入集群以及与集群通信是必要的。

这是一个相对安全和稳定的方式，可以创建一个能够可靠处理生产工作负载的 Kubernetes 集群。让我们开始练习：

1.  使用以下命令获取我们提供的`main.tf`文件：

```
curl -O https://raw.githubusercontent.com/PacktWorkshops/Kubernetes-Workshop/master/Chapter12/Exercise12.02/main.tf
```

这将替换现有的`main.tf`文件，如果您仍然拥有来自上一个练习的文件。请注意，您的目录中不应该有任何其他 Terraform 文件。

1.  现在，我们需要 Terraform 将在`main.tf`文件中定义的状态应用到您的云基础设施上。为此，请使用以下命令：

```
terraform apply
```

注意

不应该使用我们在上一章生成的用于 kops 的 AWS IAM 用户来执行这些命令，而是应该使用具有 AWS 账户管理员访问权限的用户，以确保没有意外的权限问题。

这可能需要大约 10 分钟才能完成。您应该会看到一个非常长的输出，类似于以下内容：

![图 12.6：为我们的 EKS 集群创建资源](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_06.jpg)

图 12.6：为我们的 EKS 集群创建资源

完成后，将会有两个终端输出——一个用于节点的 ConfigMap，一个用于访问集群的 kubeconfig 文件，如下截图所示：

![图 12.7：获取访问我们的集群所需的信息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_07.jpg)

图 12.7：获取访问我们的集群所需的信息

将 ConfigMap 复制到一个文件中，并将其命名为`configmap.yaml`，然后将 kubeconfig 文件复制并写入计算机上的`~/.kube/config`文件。

1.  现在，我们需要应用更改，以允许我们的工作节点与控制平面通信。这是一个用于将工作节点加入到您的 EKS 集群的 YAML 格式文件；我们已经将其保存为`configmap.yaml`。运行以下命令：

```
kubectl apply -f configmap.yaml
```

注意

要运行此命令，您需要在计算机上安装`aws-iam-authenticator`二进制文件。要执行此操作，请按照此处的说明操作：[`docs.aws.amazon.com/eks/latest/userguide/install-aws-iam-authenticator.html`](https://docs.aws.amazon.com/eks/latest/userguide/install-aws-iam-authenticator.html)。

这将应用允许 Kubernetes 集群与节点通信的 ConfigMap。您应该会看到以下响应：

```
configmap/aws-auth created
```

1.  现在，让我们验证一切是否正常运行。在终端中运行以下命令：

```
kubectl get node
```

您应该会看到以下输出：

![图 12.8：检查我们的节点是否可访问](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_08.jpg)

图 12.8：检查我们的节点是否可访问

在这个阶段，我们使用 EKS 作为控制平面，有两个工作节点的运行中的 Kubernetes 集群。

注意

请记住，您的集群资源将保持在线，直到您删除它们。如果您计划稍后回到以下练习，您可能希望删除您的集群以减少账单。要执行此操作，请运行`terraform destroy`。要重新上线您的集群，请再次运行此练习。

现在我们已经设置好了集群，在接下来的部分，让我们来看一下一个高效灵活的方法，将流量引导到集群上运行的任何应用程序。

# Kubernetes Ingress

在 Kubernetes 项目的早期阶段，Service 对象用于将外部流量传输到运行的 Pod。您只有两种选择来从外部获取流量 - 使用 NodePort 服务或 LoadBalancer 服务。在公共云提供商环境中，后者是首选，因为集群会自动管理设置安全组/防火墙规则，并将 LoadBalancer 指向工作节点上的正确端口。但是，这种方法有一个小问题，特别是对于刚开始使用 Kubernetes 或预算紧张的人。问题是一个 LoadBalancer 只能指向单个 Kubernetes 服务对象。

现在，想象一下您在 Kubernetes 中运行了 100 个微服务，所有这些微服务都需要公开。在 AWS 中，ELB（由 AWS 提供的负载均衡器）的平均成本大约为每月 20 美元。因此，在这种情况下，您每月支付 2000 美元，只是为了有获取流量进入您的集群的选项，并且我们还没有考虑网络的额外成本。

让我们再了解一下 Kubernetes 服务对象和 AWS 负载均衡器之间的一对一关系的另一个限制。假设对于您的项目，您需要将内部 Kubernetes 服务的基于路径的映射到同一负载平衡端点。假设您在`api.example.io`上运行一个 Web 服务，并且希望`api.example.io/users`转到一个微服务，`api.examples.io/weather`转到另一个完全独立的微服务。在 Ingress 到来之前，您需要设置自己的 Kubernetes 服务并对应用进行内部路径解析。

这现在不再是一个问题，因为 Kubernetes Ingress 资源的出现。Kubernetes Ingress 资源旨在与 Ingress 控制器一起运行（这是一个在您的集群中运行的应用程序，监视 Kubernetes API 服务器对 Ingress 资源的更改）。这两个组件一起允许您定义多个 Kubernetes 服务，它们本身不必被外部公开，也可以通过单个负载均衡端点进行路由。让我们看一下以下图表，以更好地理解这一点：

![图 12.9：使用 Ingress 将流量路由到我们的服务](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_09.jpg)

图 12.9：使用 Ingress 将流量路由到我们的服务

在这个例子中，所有请求都是从互联网路由到`api.example.io`。一个请求将转到`api.example.io/a`，另一个将转到`api.example.io/b`，最后一个将转到`api.example.io/c`。这些请求都将发送到一个负载均衡器和一个 Kubernetes 服务，通过 Kubernetes Ingress 资源进行控制。这个 Ingress 资源将流量从单个 Ingress 端点转发到它配置为转发流量的服务。在接下来的章节中，我们将设置`ingress-nginx` Ingress 控制器，这是 Kubernetes 社区中常用的开源工具用于 Ingress。然后，我们将配置 Ingress 以允许流量进入我们的集群，以访问我们的高可用应用程序。

# 在 Kubernetes 上运行的高可用应用程序

现在您有机会启动一个 EKS 集群并了解 Ingress，让我们向您介绍我们的应用程序。我们提供了一个示例应用程序，它有一个缺陷，阻止它成为云原生，并真正能够在 Kubernetes 中进行水平扩展。我们将在接下来的练习中部署这个应用程序并观察其行为。然后，在下一节中，我们将部署这个应用程序的修改版本，并观察它如何更适合实现我们所述的高可用目标。

## 练习 12.03：在 Kubernetes 中部署多副本非高可用应用程序

在这个练习中，我们将部署一个不具备水平扩展能力的应用程序版本。我们将尝试对其进行扩展，并观察阻止其水平扩展的问题：

注意

我们已经在 GitHub 存储库中提供了此应用程序的源代码以供参考。但是，由于我们的重点是 Kubernetes，我们将在此练习中使用命令直接从存储库中获取它。

1.  使用以下命令获取运行应用程序所需的所有对象的清单：

```
curl https://raw.githubusercontent.com/PacktWorkshops/Kubernetes-Workshop/master/Chapter12/Exercise12.03/without_redis.yaml > without_redis.yaml
```

这应该会将清单下载到您当前的目录中：

![图 12.10：下载应用程序清单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_10.jpg)

图 12.10：下载应用程序清单

如果您查看清单，您会发现它包含一个运行单个 Pod 副本的部署和一个 ClusterIP 类型的服务，用于将流量路由到它。

1.  然后，创建一个 Kubernetes 部署和服务对象，以便我们可以运行我们的应用程序：

```
kubectl apply -f without_redis.yaml
```

您应该会看到以下响应：

![图 12.11：创建我们的应用程序资源](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_11.jpg)

图 12.11：为我们的应用程序创建资源

1.  现在，我们需要添加一个 Kubernetes Ingress 资源，以便能够访问这个网站。要开始使用 Kubernetes Ingress，我们需要运行以下命令：

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/nginx-0.30.0/deploy/static/mandatory.yaml 
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/nginx-0.30.0/deploy/static/provider/aws/service-l4.yaml 
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/nginx-0.30.0/deploy/static/provider/aws/patch-configmap-l4.yaml 
```

这三个命令将为 EKS 部署 Nginx Ingress 控制器实现。您应该看到以下响应：

![图 12.12：实现 Ingress 控制器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_12.jpg)

图 12.12：实现 Ingress 控制器

注意

此命令仅适用于 AWS 云提供商。如果您在另一个平台上运行集群，您需要从[`kubernetes.github.io/ingress-nginx/deploy/#aws`](https://kubernetes.github.io/ingress-nginx/deploy/#aws)找到适当的链接。

1.  然后，我们需要为自己创建一个 Ingress。在我们所在的同一文件夹中，让我们创建一个名为`ingress.yaml`的文件，内容如下：

```
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
    - host: counter.com
      http:
        paths:
          - path: /
            backend:
              serviceName: kubernetes-test-ha-application-                without-redis
              servicePort: 80
```

1.  现在，使用以下命令运行 Ingress：

```
kubectl apply -f ingress.yaml
```

您应该看到以下响应：

```
ingress.networking.k8s.io/ingress created
```

1.  现在，我们将配置 Ingress 控制器，使得当请求到达具有`Host:`头部为`counter.com`的负载均衡器时，它应该转发到端口`80`上的`kubernetes-test-ha-application-without-redis`服务。

首先，让我们找到我们需要访问的 URL：

```
kubectl describe svc -n ingress-nginx ingress-nginx
```

您应该看到类似以下的输出：

![图 12.13：检查访问 Ingress 负载均衡器端点的 URL](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_13.jpg)

图 12.13：检查访问 Ingress 负载均衡器端点的 URL

从前面的截图中，注意 Kubernetes 在 AWS 为我们创建的 Ingress 负载均衡器端点如下：

```
a0c805e36932449eab6c966b16b6cf1-13eb0d593e468ded.elb.us-east-1.amazonaws.com
```

您的值可能与前面的值不同，您应该使用您设置的值。

1.  现在，让我们使用`curl`访问端点：

```
curl -H 'Host: counter.com' a0c805e36932449eab6c966b16b6cf1-13eb0d593e468ded.elb.us-east-1.amazonaws.com/get-number
```

您应该得到类似以下的响应：

```
{number: 1}%
```

如果您多次运行它，您会看到每次数字增加 1：

![图 12.14：重复访问我们的应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_14.jpg)

图 12.14：重复访问我们的应用程序

1.  现在，让我们发现应用程序的问题。为了使应用程序具有高可用性，我们需要同时运行多个副本，以便至少允许一个副本不可用。这反过来使应用程序能够容忍故障。为了扩展应用程序，我们将运行以下命令：

```
kubectl scale deployment --replicas=3 kubernetes-test-ha-application-without-redis-deployment
```

您应该看到以下响应：

![图 12.15：扩展应用部署](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_15.jpg)

图 12.15：扩展应用部署

1.  现在，尝试多次访问应用，就像我们在*步骤 7*中所做的那样：

```
curl -H 'Host: counter.com' a3960d10c980e40f99887ea068f41b7b-1447612395.us-east-1.elb.amazonaws.com/get-number
```

您应该看到类似以下的响应：

![图 12.16：重复访问扩展应用以观察行为](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_16.jpg)

图 12.16：重复访问扩展应用以观察行为

注意

这个输出可能对您来说并不完全相同，但如果您看到前几次尝试时数字在增加，请继续访问应用。您将能够在几次尝试后观察到问题行为。

这个输出突出了我们应用的问题——数量并不总是增加。为什么呢？因为负载均衡器可能会将请求传递给任何一个副本，接收请求的副本会根据其本地状态返回响应。

# 处理有状态的应用

前面的练习展示了在分布式环境中处理有状态应用的挑战。简而言之，无状态应用是一种不保存客户端在一个会话中生成的数据以便在下一个会话中使用的应用程序。这意味着一般来说，无状态应用完全依赖于输入来推导其输出。想象一个服务器显示一个静态网页，不需要因任何原因而改变。在现实世界中，无状态应用通常需要与有状态应用结合，以便为客户或应用的消费者创建有用的体验。当然，也有例外。

有状态的应用是一种其输出取决于多个因素的应用，比如用户输入、来自其他应用的输入以及过去保存的事件。这些因素被称为应用的“状态”，它决定了应用的行为。创建具有多个副本的分布式应用最重要的部分之一是，用于生成输出的任何状态都需要在所有副本之间共享。如果您的应用的不同副本使用不同的状态，那么您的应用将会展现基于请求路由到哪个副本的随机行为。这实际上违背了使用副本水平扩展应用的目的。

在前面的练习中，对于每个副本都能以正确的数字进行响应，我们需要将该数字的存储移到每个副本之外。为了做到这一点，我们需要修改应用程序。让我们想一想如何做到这一点。我们能否使用另一个请求在副本之间传递数字？我们能否指定每个副本只能以其分配的数字的倍数进行响应？（如果我们有三个副本，一个只会以`1`、`4`、`7`…进行响应，另一个会以`2`、`5`、`8`…进行响应，最后一个会以`3`、`6`、`9`…进行响应。）或者，我们可以将数字存储在外部状态存储中，比如数据库？无论我们选择什么，前进的道路都将涉及在 Kubernetes 中更新我们正在运行的应用程序。因此，我们需要简要讨论一下如何做到这一点。

## CI/CD 流水线

借助容器化技术和容器镜像标签修订策略的帮助，我们可以相对轻松地对我们的应用程序进行增量更新。就像源代码和基础设施代码一样，我们可以将执行构建和部署流水线步骤的脚本和 Kubernetes 清单版本化，存储在诸如**git**之类的工具中。这使我们能够对我们的集群中的软件更新发生的方式有极大的可见性和灵活性，使用 CI 和 CD 等方法来控制。

对于不熟悉的人来说，**CI/CD**代表**持续集成和持续部署/交付**。CI 方面使用工具，如 Jenkins 或 Concourse CI，将新的更改集成到我们的源代码中，进行可重复的测试和组装我们的代码成最终的构件以进行部署。CI 的目标是多方面的，但以下是一些好处：

+   如果测试充分，软件中的缺陷会在流程的早期被发现。

+   可重复的步骤在部署到环境时会产生可重复的结果。

+   可见性存在是为了与利益相关者沟通功能的状态。

+   它鼓励频繁的软件更新，以使开发人员确信他们的新代码不会破坏现有的功能。

CD 的另一部分是将自动化机制整合到不断向最终用户交付小型更新的过程中，例如在 Kubernetes 中更新部署对象并跟踪部署状态。CI/CD 流水线是当前主流的 DevOps 模型。

理想情况下，CI/CD 流水线应该能够可靠地、可预测地将代码从开发人员的机器带到生产环境，尽量减少手动干预。CI 流水线理想上应该包括编译（必要时）、测试和最终应用程序组装的组件（在 Kubernetes 集群的情况下，这是一个容器）。

CD 流水线应该有一种自动化与基础设施交互的方式，以获取应用程序修订版并部署它，以及任何依赖配置和一次性部署任务，使得所需版本的软件成为软件的运行版本，通过某种策略（比如在 Kubernetes 中使用 Deployment 对象）。它还应该包括遥测工具，以观察部署对周围环境的即时影响。

我们在上一节观察到的问题是，我们的应用程序中的每个副本都是根据其本地状态返回一个数字通过 HTTP。为了解决这个问题，我们建议使用外部状态存储（数据库）来管理应用程序的每个副本之间共享的信息（数字）。我们有几种状态存储的选择。我们选择 Redis，只是因为它很容易上手，而且很容易理解。Redis 是一个高性能的键值数据库，很像 etcd。在我们的示例重构中，我们将通过设置一个名为`num`的键来在副本之间共享状态，值是我们想要返回的递增整数值。在每个请求期间，这个值将被递增并存储回数据库，以便每个副本都可以使用最新的信息。

每家公司和个人都有自己管理部署新代码版本的不同流程。因此，我们将使用简单的命令来执行我们的步骤，可以通过 Bash 和您选择的工具自动化。

## 练习 12.04：使用状态管理部署应用程序

在这个练习中，我们将部署一个修改过的应用程序版本，这是我们在上一个练习中部署的应用程序的修改版本。作为提醒，这个应用程序会计算它被访问的次数，并以 JSON 格式返回给请求者。然而，在上一个练习的结尾，我们观察到在*图 12.16*中，当我们使用多个副本水平扩展这个应用程序时，我们得到的数字并不总是增加的。

注意

我们已经在 GitHub 存储库中提供了这个应用程序的源代码供您参考。然而，由于我们的重点是 Kubernetes，我们将在这个练习中使用命令直接从存储库中获取它。

在这个修改后的应用程序版本中，我们重构了我们的代码，以添加将这个增长计数存储在 Redis 数据库中的功能。这允许我们拥有多个应用程序副本，但每次向端点发出请求时，计数都会增加：

注意

在我们的 Redis 实现中，我们没有使用事务来设置获取后的计数。因此，当我们更新数据库中的值时，有很小的机会获取并处理旧信息，这可能导致意外的结果。

1.  使用以下命令获取此应用程序所需的所有对象的清单：

```
curl https://raw.githubusercontent.com/PacktWorkshops/Kubernetes-Workshop/master/Chapter12/Exercise12.04/with_redis.yaml > with_redis.yaml
```

您应该看到类似以下的响应：

![图 12.17：下载修改后应用程序的清单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_17.jpg)

图 12.17：下载修改后应用程序的清单

如果您打开这个清单，您会看到我们为我们的应用程序运行了三个副本的部署：一个 ClusterIP 服务来暴露它，一个运行一个副本的 Redis 部署，以及另一个 ClusterIP 服务来暴露 Redis。我们还修改了之前创建的 Ingress 对象，指向新的服务。

1.  现在，是时候在 Kubernetes 上部署它了。我们可以运行以下命令：

```
kubectl apply -f with_redis.yaml
```

您应该看到类似以下的响应：

![图 12.18：创建集群所需的资源](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_18.jpg)

图 12.18：创建集群所需的资源

1.  现在，让我们看看这个应用程序通过以下命令给我们带来了什么：

```
curl -H 'Host: counter.com' a3960d10c980e40f99887ea068f41b7b-1447612395.us-east-1.elb.amazonaws.com/get-number
```

重复运行此命令。您应该能够看到一个递增的数字，如下所示：

![图 12.19：具有一致增长数字的可预测输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_19.jpg)

图 12.19：具有一致增长数字的可预测输出

如您在前面的输出中所看到的，程序现在按顺序输出数字，因为我们的 Deployment 的所有副本现在共享一个负责管理应用程序状态（Redis）的单个数据存储。

如果您想创建一个真正高可用、容错的软件系统，还有许多其他范式需要转变，这超出了本书详细探讨的范围。但是，您可以在此链接查看有关分布式系统的更多信息：[`www.packtpub.com/virtualization-and-cloud/hands-microservices-kubernetes`](https://www.packtpub.com/virtualization-and-cloud/hands-microservices-kubernetes)

注意

再次记住，此时您的集群资源仍在运行。如果您希望稍后继续进行活动，请不要忘记使用`terraform destroy`拆除您的集群。

现在，我们已经构建了具有持久性和在不同副本之间共享其状态能力的应用程序，我们将在接下来的活动中进一步扩展它。

## 活动 12.01：扩展我们应用程序的状态管理

目前，我们的应用程序可以利用运行在 Kubernetes 集群内部的共享 Redis 数据库来管理我们在获取时返回给用户的变量计数器。

但是，假设我们暂时不信任 Kubernetes 能够可靠地管理 Redis 容器（因为它是一个易失性的内存数据存储），而是希望使用 AWS ElastiCache 来管理。您在此活动中的目标是使用本章学习的工具修改我们的应用程序，使其与 AWS ElastiCache 配合使用。

您可以使用以下指南完成此活动：

1.  使用 Terraform 来配置 ElastiCache。

您可以在此链接找到为配置 ElastiCache 所需的参数值：[`www.terraform.io/docs/providers/aws/r/elasticache_cluster.html#redis-instance`](https://www.terraform.io/docs/providers/aws/r/elasticache_cluster.html#redis-instance)。

1.  将应用程序更改为连接到 Redis。您需要在 Kubernetes Deployment 中使用环境变量。当您运行`terraform apply`命令时，您可以在`redis_address`字段中找到所需的信息。

1.  将 ElastiCache 端点添加到适当的 Kubernetes 清单环境变量中。

1.  使用任何您想要的工具在 Kubernetes 集群上推出新版本的代码。

到最后，您应该能够观察到应用程序的响应类似于我们在上一个练习中看到的，但这一次，它将使用 ElastiCache 来进行状态管理：

![图 12.20：活动 12.01 的预期输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_12_20.jpg)

图 12.20：活动 12.01 的预期输出

注意

此活动的解决方案可以在以下地址找到：[`packt.live/304PEoD`](https://packt.live/304PEoD)。请记住，您的集群资源将保持在线，直到您删除它们。要删除集群，您需要运行`terraform destroy`。

# 摘要

在本书的早期章节中，我们探讨了 Kubernetes 如何与声明性应用程序管理方法相配合；也就是说，您定义所需的状态，然后让 Kubernetes 来处理其余的事情。在本章中，我们看了一些工具，这些工具可以帮助我们以类似的方式管理我们的云基础设施。我们介绍了 Terraform 作为一种可以帮助我们管理基础设施状态的工具，并介绍了将基础设施视为代码的概念。

然后，我们使用 Terraform 在 Amazon EKS 中创建了一个基本安全、生产就绪的 Kubernetes 集群。我们研究了 Ingress 对象，并了解了使用它的主要动机，以及它提供的各种优势。然后，我们在一个高可用的 Kubernetes 集群上部署了两个应用程序版本，并探讨了一些允许我们改进水平扩展有状态应用程序的概念。这让我们一窥了运行有状态应用程序所面临的挑战，并且我们将在*第十四章*中探讨更多处理这些挑战的方法，*在 Kubernetes 中运行有状态组件*。

在下一章中，我们将继续查看如何通过进一步保护我们的集群来继续准备生产。


# 第十三章： Kubernetes 中的运行时和网络安全

概述

在本章中，我们将看看各种资源，我们可以使用来保护在我们集群中运行的工作负载。我们还将了解一个粗略的威胁模型，并将其应用于设计一个安全的集群，以便我们可以防御我们的集群和应用程序免受各种威胁。到本章结束时，您将能够创建 Role 和 ClusterRole，以及 RoleBinding 和 ClusterRoleBinding 来控制任何进程或用户对 Kubernetes API 服务器和对象的访问。然后，您将学习如何创建 NetworkPolicy 来限制应用程序与数据库之间的通信。您还将学习如何创建 PodSecurityPolicy 来确保应用程序的运行组件符合定义的限制。

# 介绍

在过去的几章中，我们戴上了 DevOps 的帽子，学习了如何在 Kubernetes 中设置集群，以及如何安全地部署新的应用程序版本而不会中断。

现在，是时候稍微转换一下，摘下我们的 DevOps 帽子，戴上我们的安全分析师帽子。首先，我们将看看有人可能攻击我们的 Kubernetes 集群的地方，以及未经授权的用户如何可能在我们的集群中造成严重破坏。之后，我们将介绍 Kubernetes 的一些安全原语以及我们如何对抗最常见的攻击形式。最后，我们将进一步修改我们的应用程序，并演示一些这些安全原语是如何工作的。

但在我们开始任何工作之前，让我们首先简要地看一下现代 Web 应用程序安全的各个关注领域，以及为我们的集群实施有效安全的基本范式。我们将首先检查我们所谓的“云原生安全的 4C”。

# 威胁建模

本章的范围远远超出了充分教授许多必要的安全学科的范围，以便您对现代工作负载安全应该如何实施和编排有严格的理解。然而，我们将简要了解我们应该如何思考。威胁建模是一种学科，我们在其中检查我们的应用程序可能受到攻击或未经授权使用的各个领域。

例如，考虑一个 HTTP Web 服务器。它通常会暴露端口 80 和 443 以提供 Web 流量服务，但它也作为潜在攻击者的入口点。它可能在某个端口上暴露 Web 管理控制台。它可能打开某些其他管理端口和 API 访问，以允许其他软件进行自动化管理。应用程序运行时可能需要定期处理敏感数据。用于创建和交付应用程序的整个端到端流水线可能暴露出各种容易受到攻击的点。应用程序依赖的加密算法可能会因暴力攻击的增加而被破坏或过时。所有这些都代表了我们的应用程序可能受到攻击的各个领域。

组织应用程序的一些攻击向量的简单方法是记住缩写**STRIDE**。它代表以下类型的攻击：

+   **S**欺骗：用户或应用程序伪装成其他人。

+   **T**篡改：未经相关利益相关者同意更改任何数据或提供信息。

+   **R**否认：否认参与行为或无法追踪特定用户的任何行为。

+   **I**信息泄露：窃取你未被授权获取的特权或敏感信息。

+   **D**拒绝服务：向服务器发送虚假请求以使其资源饱和，并拒绝其提供预期目的的能力。

+   **E**特权提升：通过利用漏洞获得对受限资源或特权的访问。

许多黑客发动的攻击都旨在执行上述一项或多项行动，通常是为了危害我们数据的机密性、完整性和可用性。考虑到这一点，我们可以使用一个心智模型来思考我们的系统可能存在威胁的各个部分在现代云原生应用程序堆栈中的位置。这个心智模型被称为“云原生安全的 4C”，我们将使用它来组织我们对 Kubernetes 安全原语的探索。理想情况下，通过利用所有这些原语，这应该能够让您对应用程序在 Kubernetes 环境中对抗类 STRIDE 攻击具有较高的信心。

## 云原生安全的 4C

安全可以并且应该组织成层。这被认为是安全的“深度防御”方法，并且被技术界普遍认为是防止任何单个组件暴露整个系统的最佳方式。当涉及到云原生应用程序时，我们认为安全分为四个层次：保护您的代码、容器、集群和云。以下图表显示了它们是如何组织的。这帮助我们想象，如果在较低层次发生了妥协，它几乎肯定会妥协依赖它的更高层次：

![图 13.1：云原生安全的 4C](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_13_01.jpg)

图 13.1：云原生安全的 4C

由于本书侧重于 Kubernetes，我们将重点关注集群安全，然后开始在我们的示例应用程序中实施一些建议。

注意

有关其他 C 的建议，请查看此链接：[`kubernetes.io/docs/concepts/security/overview/`](https://kubernetes.io/docs/concepts/security/overview/)。

# 集群安全

一种思考 Kubernetes 的方式是将其视为一个巨大的自我编排的计算、网络和存储池。因此，在许多方面，Kubernetes *就像一个云平台*。理解这种等价性很重要，因为这种心理抽象使我们能够以集群操作员与集群开发人员的不同方式进行推理。集群操作员希望确保集群的所有组件都安全，并且针对任何工作负载进行了加固。集群开发人员将关注确保他们为 Kubernetes 定义的工作负载在集群内安全运行。

在这里，您的工作变得有点容易 - 大多数 Kubernetes 的云提供商提供的服务将为您确保 Kubernetes 控制平面的安全。如果由于某种原因，您无法利用云提供商的服务，您将希望在此链接的文档中阅读有关在此链接上保护您的集群的更多信息：[`kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/`](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/)。

即使您使用的是云提供商的服务，仅仅因为他们在保护您的控制平面并不意味着您的 Kubernetes 集群是安全的。您不能依赖于云提供商的安全性的原因是，您的应用程序、其容器或糟糕的策略实施可能会使您的基础设施非常容易受到攻击。因此，现在，我们需要讨论如何在集群内保护工作负载。

注意

Kubernetes 社区正在积极开展工作，以改进安全概念和实施。相关的 Kubernetes 文档应经常重新审视，以确定是否已经进行了改进。

为了加强我们内部集群的安全性，我们需要关注以下三个概念：

+   **Kubernetes RBAC**：这是 Kubernetes 的主要策略引擎。它定义了一套角色和权限系统，以及如何将权限授予这些角色。

+   **网络策略**：这些是（取决于您的容器网络接口插件）在 Pod 之间充当“防火墙”的策略。将它们视为 Kubernetes 感知的网络访问控制列表。

+   **Pod 安全策略**：这些是在特定范围（命名空间、整个集群）定义的，并且作为 Pod 在 Kubernetes 中允许运行的定义。

我们不会涵盖在 etcd 中对 Kubernetes Secrets 进行加密，因为大多数云提供商要么为您处理这个问题，要么实现是特定于该云提供商的（例如 AWS KMS）。

# Kubernetes RBAC

在我们深入研究 RBAC 之前，请回顾一下*第四章*中关于 Kubernetes 如何授权对 API 的请求的内容，我们了解到有三个阶段-认证、授权和准入控制。我们将在*第十六章*中更多地了解准入控制器。

Kubernetes 支持多种不同的集群认证方法，您需要参考您的云提供商的文档，以获取有关其特定实现的更多详细信息。

授权逻辑是通过一种称为**RBAC**的东西处理的。它代表**基于角色的访问控制**，是我们约束某些用户和组只能执行其工作所需的最低权限的基础。这基于软件安全中的一个概念，称为“最小特权原则”。例如，如果你是一家信用卡处理公司的软件工程师，**PCI DSS**合规要求你不应该访问生产集群和客户数据。因此，如果你确实可以访问生产集群，你应该有一个没有特权的角色。

RBAC 是由集群管理员通过四种不同的 API 对象实现的：**Roles**、**RoleBindings**、**ClusterRoles**和**ClusterRoleBindings**。让我们通过检查一个图表来看它们是如何一起工作的：

![图 13.2：不同对象相互作用以实现 RBAC](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_13_02.jpg)

图 13.2：不同对象相互作用以实现 RBAC

在这个图表中，我们可以看到 Kubernetes 的`User`/`Group`和`ServiceAccount`对象通过绑定到`Role`或`ClusterRole`来获得他们的权限。让我们分别了解这些对象。

## 角色

这是一个 Role 的样本规范：

```
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: test-role
rules:
  - verbs:
      - "list"
    apiGroups:
      - ""
    resources:
      - "pods"
```

各种字段定义了 Role 应该具有的权限：

+   `namespace`：Roles 适用于 Kubernetes 命名空间，这在这个字段中定义。这使得 Role 与 ClusterRole 不同，后者的权限适用于集群中的任何命名空间。

+   `动词`：这些描述了我们允许的 Kubernetes 操作。一些常用动词的例子包括`get`、`list`、`watch`、`create`、`update`和`delete`。还有更多，但这些通常对大多数用例来说已经足够了。如果需要复习，请参考*第四章*的*Kubernetes API*部分，*如何与 Kubernetes（API 服务器）通信*。

+   `apiGroups`：这些描述了 Role 将访问的 Kubernetes API 组。这些被指定为`<group>/<version>`（比如`apps/v1`）。如果使用 CustomResourceDefinitions，这些 API 组也可以在这里引用。

注意

Kubernetes 随附的 API 组的完整列表可以在这里找到（截至版本 1.18）：[`kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/`](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/)。

+   `resources`：这些描述了我们正在讨论的 API 对象，并由对象定义的`Kind`字段中的值定义；例如，`deployment`、`secret`、`configmap`、`pod`、`node`等。

## RoleBinding

如前图所示，RoleBinding 将角色绑定或关联到 ServiceAccounts、用户或用户组。以下是 RoleBinding 的示例规范：

```
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: test-role-binding
  namespace: default
roleRef:
  name: test-role
  kind: ClusterRole
  apiGroup: rbac.authorization.k8s.io
subjects:
  - kind: ServiceAccount
    name: test-sa
    namespace: default 
```

此规范定义了应该能够使用角色执行需要在 Kubernetes 中进行授权的操作的主体：

+   `subjects`：这指的是经过身份验证的 ServiceAccount、用户或应该能够使用此角色的组。

+   `roleRef`：这指的是他们可以承担的角色。

## ClusterRole

ClusterRole 在每个方面都与 Role 相同，除了一个方面。它不仅在一个 Kubernetes 命名空间内授予权限，而且在整个集群范围内授予权限。

## ClusterRoleBinding

这与 RoleBinding 相同，只是它必须绑定到 ClusterRole 而不是 Role。您不能将 ClusterRoleBinding 绑定到 Role，也不能将 RoleBinding 绑定到 ClusterRole。

## 有关 RBAC 策略的一些重要说明

+   RBAC 策略文档仅允许。这意味着，默认情况下，主体没有访问权限，只有通过 RoleBinding 或 ClusterRoleBinding 才能具有相应角色或集群角色中规定的特定访问权限。

+   绑定是不可变的。这意味着一旦您将主体绑定到角色或集群角色，就无法更改。这是为了防止特权升级。因此，实体可以被授予修改对象的权限（对于许多用例来说已经足够好），同时防止它提升自己的特权。如果需要修改绑定，只需删除并重新创建。

+   一个可以创建其他 ClusterRoles 和 Roles 的 ClusterRole 或 Role 只能授予最多与其相同的权限。否则，这将是一个明显的特权升级路径。

## 服务账户

在前几章中，当我们学习有关 Minikube 和 Kops 的身份验证时，我们看到 Kubernetes 生成了我们使用的证书。在 EKS 的情况下，使用了 AWS IAM 角色和 AWS IAM Authenticator。

事实证明，Kubernetes 有一个特殊的对象类型，允许集群内的资源与 API 服务器进行身份验证。

我们可以使用 ServiceAccount 资源来允许 Pods 接收 Kubernetes 生成的令牌，它将传递给 API 服务器进行身份验证。所有官方的 Kubernetes 客户端库都支持这种类型的身份验证，因此这是从集群内部进行程序化 Kubernetes 集群访问的首选方法。

当您以集群管理员身份运行时，可以使用`kubectl`使用`--as`参数对特定 ServiceAccount 进行身份验证。对于之前显示的示例 ServiceAccount，这将看起来像这样：

```
kubectl --as=system:serviceaccount:default:test-sa get pods
```

我们将学习这些对象如何一起工作，以便在以下练习中控制访问。

## 练习 13.01：创建 Kubernetes RBAC ClusterRole

在这个练习中，我们将创建一个 ClusterRole 和 ClusterRoleBinding。然后，我们将成为用户并继承他们的权限，如 ClusterRole 所定义的，并演示 Kubernetes 如何基于规则阻止对某些 API 的访问。让我们开始吧：

1.  首先，我们将从我们在*练习 12.02*中使用的 Terraform 文件中重新创建 EKS 集群，*使用 Terraform 创建 EKS 集群*。如果您已经有`main.tf`文件，可以使用它。否则，您可以运行以下命令获取它：

```
curl -O https://raw.githubusercontent.com/PacktWorkshops/Kubernetes-Workshop/master/Chapter12/Exercise12.02/main.tf
```

现在，依次使用以下两个命令，将您的集群资源恢复运行：

```
terraform init
terraform apply
```

注意：

在执行任何这些练习之后，如果您计划在较长时间后继续进行以下练习，最好释放集群资源以停止 AWS 计费。您可以使用`terraform destroy`命令来做到这一点。然后，当您准备进行练习或活动时，可以运行此步骤将所有内容恢复在线。

如果任何练习或活动依赖于在先前练习中创建的对象，您还需要重新创建这些对象。

1.  现在，我们将为我们的 RBAC 资源创建三个 YAML 文件。第一个是一个 ServiceAccount，它允许我们通过集群授予的身份和认证令牌。创建一个名为`sa.yaml`的文件，内容如下：

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: test-sa
  namespace: default
```

1.  接下来，我们将创建一个 ClusterRole 对象并分配一些权限。创建一个名为`cr.yaml`的文件，内容如下：

```
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  namespace: default
  name: test-sa-cluster-role
rules:
  - verbs:
      - "list"
    apiGroups:
      - ""
    resources:
      - "pods"
```

我们正在定义一个`ClusterRole`，它具有列出任何命名空间中所有 Pod 的能力，但其他操作不能执行。

1.  接下来，我们将创建一个`ClusterRoleBinding`对象，将创建的 ServiceAccount 和 ClusterRole 绑定在一起。创建一个名为`crb.yaml`的文件，内容如下：

```
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: test-sa-cluster-role-binding
  namespace: default
roleRef:
  name: test-sa-cluster-role
  kind: ClusterRole
  apiGroup: rbac.authorization.k8s.io
subjects:
  - kind: ServiceAccount
    name: test-sa
    namespace: default
```

在这些文件中，我们定义了三个对象：`ServiceAccount`、`ClusterRole`和`ClusterRoleBinding`。

1.  运行以下命令来创建此 RBAC 策略，以及我们的 ServiceAccount：

```
kubectl apply -f sa.yaml -f cr.yaml -f crb.yaml
```

您应该看到以下响应：

![图 13.3：创建 ServiceAccount、ClusterRole 和 ClusterRoleBinding](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_13_03.jpg)

图 13.3：创建 ServiceAccount、ClusterRole 和 ClusterRoleBinding

1.  在接下来的步骤中，我们将演示使用我们的服务账户的 ClusterRole 将阻止我们描述 Pods。但在那之前，让我们先获取 Pod 的列表，并证明一切仍然正常工作。通过运行以下命令来实现：

```
kubectl get pods --all-namespaces
```

您应该看到以下响应：

![图 13.4：获取 Pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_13_04.jpg)

图 13.4：获取 Pod 列表

1.  现在，让我们描述第一个 Pod。这里第一个 Pod 的名称是`aws-node-fzr6m`。在这种情况下，`describe`命令将如下所示：

```
kubectl describe pod -n kube-system aws-node-fzr6m
```

请使用您集群中的 Pod 名称。您应该看到类似以下的响应：

![图 13.5：描述 aws-node-fzr6m Pod](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_13_05.jpg)

图 13.5：描述 aws-node-fzr6m Pod

上述截图显示了`describe`命令输出的截断版本。

1.  现在，我们将运行与之前相同的命令，但这次假装是使用当前绑定到我们创建的 ClusterRole 和 ClusterRoleBinding 的 ServiceAccount 的用户。我们将使用`kubectl`的`--as`参数来实现这一点。因此，命令将如下所示：

```
kubectl --as=system:serviceaccount:default:test-sa get pods --all-namespaces
```

请注意，我们可以假设 ClusterRole，因为我们是我们创建的集群中的管理员。您应该看到以下响应：

![图 13.6：假设 test-sa ServiceAccount 获取 Pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_13_06.jpg)

图 13.6：假设 test-sa ServiceAccount 获取 Pod 列表

确实，这仍然有效。正如您可能还记得的那样，从*步骤 3*中可以看到，我们提到了`list`作为一个允许的动词，这是用于获取某种类型的所有资源列表的动词。

1.  现在，让我们看看如果具有我们创建的 ClusterRole 的用户尝试描述一个 Pod 会发生什么：

```
kubectl --as=system:serviceaccount:default:test-sa describe pod -n kube-system aws-node-fzr6m
```

您应该看到以下响应：

![图 13.7：禁止错误](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_13_07.jpg)

图 13.7：禁止错误

kubectl `describe`命令使用`get`动词。回想一下*步骤 3*，它不在我们的 ClusterRole 允许的动词列表中。

如果这是一个用户（或黑客）试图使用任何不允许的命令，我们将成功阻止它。Kubernetes 文档网站上有许多实用的 RBAC 示例。在本章中讨论 Kubernetes 中所有 RBAC 的设计模式超出了范围。我们只能说：在可能的情况下，您应该实践“最小特权原则”，以限制对 Kubernetes API 服务器的不必要访问。也就是说，每个人都应该获得完成工作所需的最低访问级别；并非每个人都需要成为集群管理员。

虽然我们无法就公司的安全性做出具体建议，但我们可以说有一些不错的“经验法则”，可以表述如下：

+   在可能的情况下，尝试将集群贡献者/用户放在角色中，而不是 ClusterRole 中。由于角色受到命名空间的限制，这将防止用户未经授权地访问另一个命名空间。

+   只有集群管理员应该访问 ClusterRoles，这应该是有限且临时的。例如，如果您进行值班轮换，工程师负责您的服务的可用性，那么他们在值班期间应该只有管理员 ClusterRole。

# 网络策略

Kubernetes 中的 NetworkPolicy 对象本质上是 Pod 和命名空间级别的网络访问控制列表。它们通过使用标签选择（例如服务）或指示 CIDR IP 地址范围来允许特定端口/协议上的访问。

这对于确保安全非常有帮助，特别是当您在集群上运行多个微服务时。现在，想象一下您有一个为您的公司托管许多应用程序的集群。它托管了一个运行开源库的营销网站，一个包含敏感数据的数据库服务器，以及一个控制对该数据访问的应用服务器。如果营销网站不需要访问数据库，那么它就不应该被允许访问数据库。通过使用 NetworkPolicy，我们可以防止营销网站中的漏洞或错误允许攻击者扩大攻击，以便他们可以通过阻止营销网站 Pod 甚至无法与数据库通信来访问您的业务数据。让我们来看一个示例 NetworkPolicy 文档并解释它：

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sample-network-policy
  namespace: my-namespace
spec:
  podSelector:
    matchLabels:
      role: db
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - ipBlock:
        cidr: 192.18.0.0/16
        except:
        - 192.18.1.0/24
    - namespaceSelector:
        matchLabels:
          project: sample-project
    - podSelector:
        matchLabels:
          role: frontend
    ports:
    - protocol: TCP
      port: 3257
  egress:
  - to:
    - ipBlock:
        cidr: 10.0.0.0/24
    ports:
    - protocol: TCP
      port: 5832
```

让我们来看看这个 NetworkPolicy 的一些字段：

+   它包含了我们在本章前面描述的标准`apiVersion`，`kind`和`metadata`字段。

+   `podSelector`：它应该在命名空间中查找的标签，以应用策略。

+   `policyTypes`：可以是入口、出口或两者。这意味着网络策略适用于被选择的 Pod 中进入的流量、离开被选择的 Pod 的流量，或两者。

+   `Ingress`：这需要一个`from`块，定义了策略中流量可以从哪里发起。这可以是一个命名空间、一个 Pod 选择器或一个 IP 地址块和端口组合。

+   `Egress`：这需要一个`to`块，并定义了网络策略中允许流量去哪里。这可以是一个命名空间、一个 Pod 选择器或一个 IP 地址块和端口组合。

您的 CNI 可能没有成熟的 NetworkPolicies 实现，因此请务必查阅您的云提供商的文档以获取更多信息。在我们使用 EKS 设置的集群中，它使用的是 Amazon CNI。我们可以使用**Calico**，一个开源项目，来增强现有的 EKS CNI，并弥补在执行 NetworkPolicy 声明方面的不足。值得一提的是，Calico 也可以作为 CNI 使用，但我们将只在以下练习中使用其补充功能来执行 NetworkPolicy。

## 练习 13.02：创建 NetworkPolicy

在这个练习中，我们将实现 Calico 来增强 Amazon CNI 在 EKS 中可用的 NetworkPolicy 声明的即插即用执行。让我们开始吧：

1.  运行以下命令安装带有 Calico 的 Amazon CNI：

```
kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/release-1.5/config/v1.5/calico.yaml
```

你应该看到类似于以下的响应：

![图 13.8：安装带有 Calico 的 Amazon CNI](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_13_08.jpg)

图 13.8：安装带有 Calico 的 Amazon CNI

1.  要验证您是否成功部署了与 Calico 对应的 DaemonSet，请使用以下命令：

```
kubectl get daemonset calico-node --namespace kube-system
```

您应该看到`calico-node` DaemonSet，如下所示：

![图 13.9：检查 calico-node DaemonSet](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_13_09.jpg)

图 13.9：检查 calico-node DaemonSet

1.  现在，让我们创建我们的 NetworkPolicy 对象。首先，创建一个名为`net_pol_all_deny.yaml`的文件，内容如下：

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

这个策略是一个非常简单的 NetworkPolicy。它表示不允许流入或流出集群的 Pod 之间的流量。这是我们将继续扩展我们应用程序的安全基础。

1.  让我们使用以下命令应用我们的策略：

```
kubectl apply -f net_pol_all_deny.yaml
```

你应该看到以下响应：

```
networkpolicy.networking.k8s.io/default-deny created
```

现在，我们的集群中没有流量流动。我们可以通过部署我们的应用程序来证明这一点，因为它需要网络来与自身通信。

1.  作为一个测试应用程序，我们将使用与*Exercise 12.04*，*部署应用程序版本更新*中使用的相同应用程序。如果您已经有该 YAML 文件，可以使用它。否则，运行以下命令以在您的工作目录中获取该文件：

```
curl -O https://raw.githubusercontent.com/PacktWorkshops/Kubernetes-Workshop/master/Chapter12/Exercise12.04/with_redis.yaml
```

然后，使用以下命令部署应用程序：

```
kubectl apply -f with_redis.yaml
```

你应该看到以下响应：

![图 13.10：部署我们的应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_13_10.jpg)

图 13.10：部署我们的应用程序

1.  现在，让我们使用以下命令检查我们部署的状态：

```
kubectl describe deployment kubernetes-test-ha-application-with-redis-deployment
```

你应该看到以下响应：

![图 13.11：检查我们应用程序的状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_13_11.jpg)

图 13.11：检查我们应用程序的状态

这是一个截断的截图。正如你所看到的，我们有一个问题，即无法与 Redis 通信。修复这个问题将是*Activity 13.01*，*超越基本操作*的一部分。

1.  现在我们将测试网络访问，因此在一个单独的终端窗口中，让我们启动我们的代理：

```
kubectl proxy
```

你应该看到这个响应：

```
Starting to serve on 127.0.0.1:8001
```

验证 NetworkPolicy 是否阻止流量的另一种方法是使用我们的`curl`命令：

```
curl localhost:8001/api/v1/namespaces/default/services/kubernetes-test-ha-application-with-redis:/proxy/get-number
```

你应该看到类似于这样的响应：

```
Error: 'dial tcp 10.0.0.193:8080: i/o timeout'
Trying to reach: 'http:10.0.0.193:8080/get-number'%
```

正如我们所看到的，我们能够防止 Kubernetes 集群中 Pod 之间的未经授权通信。通过利用 NetworkPolicies，我们可以防止攻击者在能够 compromise 集群、容器或源代码的一些组件后造成进一步的破坏。

# PodSecurityPolicy

到目前为止，我们已经学习并测试了 Kubernetes RBAC 以防止未经授权的 API 服务器访问，并且还应用了 NetworkPolicy 以防止不必要的网络通信。网络之外安全性的下一个最重要领域是应用程序运行时。攻击者需要访问网络来进出，但他们还需要一个容易受攻击的运行时来做更严重的事情。这就是 Kubernetes PodSecurityPolicy 对象帮助防止这种情况发生的地方。

PodSecurityPolicy 对象与特定类型的 AdmissionController 重叠，并允许集群操作员动态定义已被允许在集群上调度的 Pod 的最低运行时要求。

为了确切了解 PodSecurityPolicies 如何有用，让我们考虑以下情景。您是一家大型金融机构的 Kubernetes 集群管理员。您的公司以符合 ITIL 的方式（ITIL 是 IT 服务的标准变更管理框架）使用基于票据的变更管理软件，以确保对环境所做的更改是稳定的。这可以防止开发人员在生产环境中做出灾难性的事情。为了跟上客户要求的市场变化速度，您需要一种程序化的方式来使开发人员能够更自主地进行更改管理。但您还需要以安全和符合某些标准的方式来做到这一点。PodSecurityPolicies 帮助我们做到这一点，因为它们允许管理员在软件中创建策略定义，并在 Pod 被允许进入集群时执行。这意味着开发人员可以更快地移动，而集群管理员仍然可以证明他们的环境完全符合设定的标准。

进一步扩展这种情况，您可能希望阻止用户将其容器以 root 用户身份运行，以防攻击者利用 Docker 中的任何漏洞。通过应用 PodSecurityPolicy，您可以防止用户意外部署不安全的容器。

既然我们已经看到它们如何有用，让我们考虑一个示例 PodSecurityPolicy 并对其进行检查：

```
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: psp-example
  namespace: default
spec:
  privileged: true
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: MustRunAs
    ranges:
      - min: 1
        max: 2500
  runAsUser:
    rule: MustRunAsNonRoot
  fsGroup:
    rule: MustRunAs
    ranges:
      - min: 655
        max: 655
  volumes:
    - '*'
```

让我们在这里检查一些值得注意的字段：

+   `metadata.namespace`: 这将在`default`命名空间中创建 PodSecurityPolicy，并将应用于同一命名空间中的 Pod。

+   `privileged`: 这控制容器是否允许在节点上以特权执行上下文中运行，这实际上授予容器对主机的根级访问权限。您可以在这里找到有关特权容器的更多信息：[`docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities`](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)。

+   `seLinux`: 这定义了任何 SELinux 设置。一些 Kubernetes 集群在 SELinux 环境中运行，这些环境在集群外实现了称为“强制访问控制”的东西。这允许将这些控制投影到集群中。通过声明`RunAsAny`，我们允许任何 SELinux 用户。

+   `supplementalGroups`: 这是策略的一个强制字段。它基本上告诉我们，我们允许任何 Linux 用户组 ID（GID）。在此示例规范中，我们说允许来自 ID 为 1 到 2500 的任何 Linux 用户组的用户。

+   `runAsUser`: 这允许我们指定可以在 Pod 中运行任何进程的特定 Linux 用户。通过声明`MustRunAsNonRoot`，我们说 Pod 中的任何进程都不能以 root 权限运行。

+   `fsGroup`: 这是容器进程必须以其运行的 Linux 组 ID，以便与集群上的某些卷进行交互。因此，即使 Pod 上存在卷，我们也可以限制该 Pod 中的某些进程访问它。在此示例规范中，我们说只有具有 GID 为 655 的`devops`组中的 Linux 用户可以访问该卷。这将适用于 Pod 在集群中的位置或卷的位置。

+   `卷`: 这使我们能够允许可以挂载到该 Pod 的不同类型的卷，例如`configmap`或`persistentVolumeClaim`。在此示例规范中，我们已经指定了`*`（星号），这意味着所有类型的卷都可以被该 Pod 中的进程使用。

现在我们已经了解了规范中不同字段的含义，我们将在以下练习中创建一个 PodSecurityPolicy。

## 练习 13.03：创建和测试 PodSecurityPolicy

在这个练习中，我们将创建一个 PodSecurityPolicy 并将其应用到我们的集群，以演示我们应用后集群中 Pod 必须遵守的功能类型。让我们开始吧：

1.  创建一个名为`pod_security_policy_example.yaml`的文件，内容如下：

```
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: psp-example
  namespace: default
spec:
  privileged: false
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: MustRunAs
    ranges:
      - min: 1
        max: 2500
  runAsUser:
    rule: MustRunAsNonRoot
  fsGroup:
    rule: MustRunAs
    ranges:
      - min: 655
        max: 655
  volumes:
    - '*'
```

1.  要将此应用到集群中，请运行以下命令：

```
kubectl apply -f pod_security_policy_example.yaml
```

您应该会看到以下响应：

```
podsecuritypolicy.policy/psp-example created
```

为了检查我们的策略是否得到执行，让我们尝试创建一个不符合这个策略的 Pod。现在我们有一个名为`MustRunAsNonRoot`的策略，所以我们应该尝试以 root 身份运行一个容器，看看会发生什么。

1.  要创建一个违反这个 PodSecurityPolicy 的 Docker 容器，首先创建一个名为`Dockerfile`的文件，内容如下：

```
FROM debian:latest
USER 0
CMD echo $(whoami)
```

这个`Dockerfile`的第二行切换到 root 用户（由 UID `0`表示），然后`echo`命令应该告诉我们在容器启动时运行的用户是谁。

1.  通过运行以下命令构建 Docker 镜像：

```
docker build -t root .
```

您应该会看到以下响应：

![图 13.12：构建我们的 Docker 镜像](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_13_12.jpg)

图 13.12：构建我们的 Docker 镜像

1.  让我们运行我们的 Docker 容器：

```
docker run root:latest
```

您应该会看到以下响应：

```
root
```

正如我们所看到的，这个容器将以 root 身份运行。

1.  现在，我们需要从这个容器创建一个 Pod。创建一个名为`pod.yaml`的文件，内容如下：

```
apiVersion: v1
kind: Pod
metadata:
  name: rooter
spec:
  containers:
    - name: rooter
      image: packtworkshops/the-kubernetes-workshop:root-tester
```

您可以将自己的镜像推送到 Docker Hub 存储库并替换此链接，或者您可以使用我们已经提供的容器以方便使用。作为一个一般的经验法则，当下载某些应该以 root 访问权限运行的东西时，您应该始终小心。

1.  默认情况下，PodSecurityPolicy 在用户、组或 ServiceAccount 上安装了`use`权限之前不会执行任何操作，这些用户、组或 ServiceAccount 将创建 Pod。为了模仿这一点，我们将快速创建一个 ServiceAccount：

```
kubectl create serviceaccount fake-user
```

您应该会看到以下响应：

```
serviceaccount/fake-user created
```

1.  现在，让我们创建一个将受到这个 PodSecurityPolicy 约束的角色：

```
kubectl create role psp:unprivileged --verb=use --resource=podsecuritypolicy --resource-name=psp-example
```

请注意，这是创建角色的另一种快速方法。在这里，`psp:unprivileged`对应于角色的名称，而标志对应于我们之前学习的字段。我们使用`--resource-name`标志将角色应用到我们特定的 PodSecurityPolicy。您应该会得到以下响应：

```
role.rbac.authorization.k8s.io/psp:unprivileged created
```

1.  让我们使用 RoleBinding 将这个角色绑定到我们的 ServiceAccount：

```
kubectl create rolebinding fake-user:psp:unprivileged --role=psp:unprivileged --serviceaccount=psp-example:fake-user
```

在这里，我们使用了类似于上一步中使用的命令。您应该会看到以下响应：

```
rolebinding.rbac.authorization.k8s.io/fake-user: psp:unprivileged created
```

1.  现在，让我们假扮成这个用户，尝试创建这个 Pod：

```
kubectl --as=system:serviceaccount:psp-example:fake-user apply -f pod.yaml
```

您应该会看到以下响应：

![图 13.13：尝试在假用户 ServiceAccount 的假设下创建一个 Pod](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_13_13.jpg)

图 13.13：尝试在假用户 ServiceAccount 的假设下创建 Pod

在本章的开头，我们探讨了集群安全的 4C，然后在本章的整个过程中，我们看到了 Kubernetes 允许我们以不同的方式加固集群以抵御各种攻击的方法。我们了解到 RBAC 策略允许我们控制对 API 和对象的访问，NetworkPolicy 允许我们加固网络拓扑，而 PodSecurityPolicy 则帮助我们防止受损的运行时。

现在，让我们在以下活动中将这些概念结合起来。

## 活动 13.01：保护我们的应用程序

就目前而言，我们在上一章中的应用程序已经相当安全了。但是，我们需要做的是防止用户部署特权 Pod，并确保我们的应用程序可以与外部世界和其数据存储通信。对于这个应用程序的正确解决方案应该具有以下功能：

+   应用程序应该无缝工作，就像我们在上一章中演示的那样，但现在，它应该阻止任何不必要的网络流量。这里的不必要是指只有与 Redis 服务器通信的 Pod 应用程序，而且该应用程序只能与其他 IP 范围通信。

+   在*Exercise 13.02*，*Creating a NetworkPolicy*中，我们看到由于高度限制性的 NetworkPolicy，我们的应用程序无法工作。然而，在这种情况下，您应该看到应用程序运行并输出类似于以下内容的内容：![图 13.14：活动 13.01 的预期输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_13_14.jpg)

图 13.14：活动 13.01 的预期输出

以下是一些可以帮助您完成此活动的步骤：

1.  确保您拥有集群基础架构和*Exercise 13.01, Creating a Kubernetes RBAC ClusterRole*中的所有对象。

1.  创建名为`pod_security_policy.yaml`的文件（然后应用它）。在创建此文件时，请记住上面第一个要点中描述的功能。您可能需要重新访问*PodSecurityPolicy*部分，在那里我们详细描述了此类文件中使用的每个字段。

1.  创建一个名为`network_policy.yaml`的文件。在创建此文件时，请记住上面第二个要求中列出的内容。您可能需要重新访问*NetworkPolicies*部分，我们在其中详细描述了此类文件中使用的每个字段。确保在创建后应用此策略。

1.  如果您的集群中仍在部署*Exercise 14.02, Creating a NetworkPolicy*中的应用程序，则可以继续下一步。否则，请重新运行该练习中的*步骤 5*和*6*。

1.  现在，测试该应用程序。

注意

此活动的解决方案可在以下地址找到：[`packt.live/304PEoD`](https://packt.live/304PEoD)。

另外，考虑在完成本章后删除 NetworkPolicy 和 PodSecurityPolicy，以避免对后续章节造成干扰。

# 摘要

在我们构建生产就绪的 Kubernetes 环境的过程中，安全性是一个关键方面。考虑到这一点，在本章中，我们研究了威胁建模如何让我们以对抗性的方式思考我们的应用基础架构，以及它如何告诉我们如何防御攻击。然后，我们看了一下云原生安全的 4C，以了解我们的攻击面在哪里，然后看了一下 Kubernetes 如何帮助我们在集群中安全地运行工作负载。

Kubernetes 具有几个安全功能，我们可以利用这些功能来保护我们的集群。我们了解了三个重要的安全措施：RBAC、NetworkPolicies 和 PodSecurityPolicies。我们还了解了它们在保护对集群的访问、保护容器网络和保护容器运行时方面的各种应用。

在下一章中，我们将探讨如何在 Kubernetes 中管理存储对象，并处理具有状态的应用程序。


# 第十四章： 在 Kubernetes 中运行有状态的组件

概述

在本章中，我们将扩展我们的技能，超越无状态应用程序，学习如何处理有状态应用程序。我们将了解 Kubernetes 集群操作员可用的各种状态保留机制，并推导出一个心智模型，以确定在何处可以调用某些选项来有效运行应用程序。我们还将介绍 Helm，这是一个用于部署具有各种 Kubernetes 对象的复杂应用程序的有用工具。

通过本章的学习，您将能够同时使用 StatefulSets 和 PersistentVolumes 来运行需要在 Pod 中断期间保留基于磁盘的状态的应用。您还将能够使用 Helm charts 部署应用程序。

# 介绍

根据您到目前为止学到的一切，您知道 Pod 和其中运行的容器被认为是短暂的。这意味着不能依赖它们的稳定性，因为 Kubernetes 将会干预并将它们移动到集群中的其他位置，以符合集群中各种清单指定的期望状态。但是这里存在一个问题 - 我们该如何处理我们的应用程序的部分，这些部分依赖于从一次交互到下一次交互的状态持久化？如果没有诸如可预测的 Pod 命名和可靠的存储操作等特定保证（我们将在本章后面学习），这样的有状态组件可能会在 Kubernetes 重新启动相关 Pod 或将其移动时失败。然而，在深入讨论上述主题的细节之前，让我们简要谈谈有状态应用程序以及在容器化环境中运行它们的挑战。

# 有状态应用

我们在《第十二章，您的应用程序和 HA》中简要介绍了有状态性的概念。应用程序的有状态组件几乎对世界上所有的信息技术系统都是必需的。它们对于保持账户详细信息、交易记录、HTTP 请求信息以及许多其他用途都是必需的。在生产环境中运行这些应用程序的挑战部分原因几乎总是与网络或持久性机制有关。无论是旋转金属盘、闪存存储、块存储还是其他尚未被发明的工具，持久性在各种形式中都是非常难以处理的。这种困难的部分原因是因为所有这些形式都存在失败的非零概率，一旦你需要在生产环境中拥有数百甚至数千个存储设备，这个概率就会变得非常显著。如今，许多云服务提供商将为客户提供帮助，并提供托管服务来解决这个困难。在 AWS 的情况下，我们有诸如 S3、EBS、RDS、DynamoDB、Elasticache 等工具，这些工具可以帮助开发人员和运营商在没有太多重复工作的情况下顺利运行有状态应用程序（前提是您可以接受供应商锁定）。

一些公司在运行有状态应用和它们所依赖的持久性机制时面临的另一个权衡是，要么培训和维护一大批能够保持这些记录系统在线、健康和最新的员工，要么尝试开发一套工具和程序化强制执行的常见运营场景。这两种方法在组织规模扩大时所需的人力维护工作量上有所不同。

例如，以人为中心的运营方法一开始可以让事情迅速进行，但所有运营成本都会随着应用规模线性增长，最终，官僚主义会导致每次新员工的生产力回报递减。以软件为中心的方法需要更高的前期投资，但成本随着应用规模的对数增长，并且在出现意外错误时有更高的级联故障概率。

这些操作场景的一些例子包括配置和配置、正常操作、扩展输入/输出、备份和异常操作。异常操作的例子包括网络故障、硬盘故障、磁盘数据损坏、安全漏洞和特定应用程序的不规则性。特定应用程序的不规则性的例子可能包括处理特定于 MySQL 的排序问题、处理 S3 最终一致性读取故障、etcd Raft 协议解决错误等。

许多公司发现，他们更容易支付供应商支持费用，使用云托管产品提供，或者重新培训员工，而不是开发编程状态管理流程和软件。

Kubernetes 启用的开发生命周期的一个好处在于工作负载定义方面。公司越是努力地严格定义计算的最小逻辑单元（一个 pod 模板或 PersistentVolume 定义），它们就越能为 Kubernetes 干预不规则操作并适当编排整个应用做好准备。这在很大程度上是因为 Kubernetes 编排是一个经典的动态约束满足问题（CSP）。CSP 求解器可以利用的约束形式的信息越多，工作负载编排就会变得更可预测，因为可行稳态解的数量会减少。因此，以可预测的工作负载编排为最终目标，我们是否可以在 Kubernetes 中运行应用的状态组件？答案是毫无疑问的肯定。在 Kubernetes 中运行有状态的工作负载常常让人犹豫不决。我们从本书的开头就说过，pod 是短暂的，不应该依赖它们的稳定性，因为在节点故障的情况下，它们将被移动和重新启动。因此，在你决定在 Kubernetes 中运行数据库太冒险之前，请考虑一下——世界上最大的搜索引擎公司在一个与 Kubernetes 非常相似的工具中运行数据库。这告诉我们，不仅可能，而且实际上更好的是努力定义工作负载，使它们可以由编排器运行，因为它可能比人类更快地处理应用程序故障。

那么，我们如何实现这一点呢？对这个问题的答案是使用你之前学过的两个 Kubernetes 对象的组合-**PersistentVolumes**和**StatefulSets**。这些在*第 7*和*第 9*章介绍过，所以我们不会在这里详细说明它们的用法，除了说我们将把所有介绍性的主题结合起来，形成一个与*我们的应用*相关的示例。

有效的有状态工作负载编排的关键是模块化和抽象。这些是基本的软件概念，工程师们学习它们以便设计良构架构的软件系统，同样适用于良构架构的基础设施系统。让我们考虑下面的图表，作为在 Kubernetes 中运行数据库时模块化的一个例子：

![图 14.1：Kubernetes 中的模块化有状态组件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_14_01.jpg)

图 14.1：Kubernetes 中的模块化有状态组件

正如你在前面的图表中所看到的，并且在本书中学到的，Kubernetes 由模块化组件组成。因此，通过利用 StatefulSet 资源，我们可以组合使用 PersistentVolumes、PersistentVolumeClaims、StorageClasses、pods 以及围绕它们的生命周期的一些特殊规则，从而更强有力地保证我们应用程序的持久性层的状态。

# 理解 StatefulSets

在*图 14.1*中，我们可以看到 StatefulSet 被调用来管理 pod 的生命周期。StatefulSet（在 Kubernetes 的旧版本中，这被称为 PetSet）的操作方式与部署非常相似，我们提供一个 pod 模板，指定我们要运行的内容以及我们要运行多少个实例。StatefulSet 和部署之间的区别在于以下几点：

+   **一个可以依赖于 DNS 查询的清晰命名方案**：

这意味着在前面的图中，当我们将一个 StatefulSet 命名为`mysql`时，该 StatefulSet 中的第一个 pod 将始终是`mysql-0`。这与传统部署不同，传统部署中 pod 的 ID 是随机分配的。这也意味着，如果你有一个名为`mysql-2`的 pod，它崩溃了，它将在集群中使用完全相同的名称复活。

+   **更新必须进行的明确有序方式**：

根据此 StatefulSet 中的更新策略，每个 pod 将按非常特定的顺序关闭。因此，如果您有一个众所周知的升级路径（例如在 MySQL 的次要软件修订版本的情况下），您应该能够利用 Kubernetes 提供的软件更新策略之一。

+   **可靠的存储操作**：

由于存储是有状态解决方案中最关键的部分，因此 StatefulSet 采取的确定性操作至关重要。默认情况下，为 StatefulSet 配置的任何 PersistentVolume 都将被保留，即使该 StatefulSet 已被删除。虽然此行为旨在防止数据意外删除，但在测试期间可能会导致云提供商产生重大费用，因此您应该密切监视此行为。

+   **必须在 StatefulSet 中定义的 serviceName 字段**：

这个`serviceName`字段必须指向一个称为“无头”的服务，该服务指向这组 pod。这是为了允许使用常见的 Kubernetes DNS 语法单独地寻址这些 pod。例如，如果我的 StatefulSet 正在 default 命名空间中运行，并且名称为`zachstatefulset`，那么第一个 pod 将具有 DNS 条目`zachstatefulset-0.default.svc.cluster.local`。如果此 pod 失败，任何替换 pod 都将使用相同的 DNS 条目。

有关无头服务的更多信息，请访问此链接：[`kubernetes.io/docs/concepts/services-networking/service/#headless-services`](https://kubernetes.io/docs/concepts/services-networking/service/#headless-services)。

## 部署与 StatefulSets

现在您已经以稍微更细粒度的方式介绍了 StatefulSets，那么在选择使用 PersistentVolumeClaim 的 StatefulSet 和部署之间应该根据什么基础进行选择呢？答案取决于您希望编排的内容。

从理论上讲，您可以使用两种类型的 Kubernetes 对象实现类似的行为。两者都创建 pod，都有更新策略，都可以使用 PVC 来创建和管理 PersistentVolume 对象。StatefulSets 的设计目的是为了提供前面列出的保证。通常，在编排数据库、文件服务器和其他形式的敏感持久性依赖应用程序时，您会希望有这些保证。

当我们了解到 StatefulSets 对于可预测地运行应用程序的有状态组件是有用的时，让我们看一个与我们相关的具体例子。正如您从以前的章节中回忆起，我们有一个小型计数器应用程序，我们正在重构以利用尽可能多的云原生原则。在本章中，我们将替换状态持久性机制并尝试一个新的引擎。

# 进一步重构我们的应用程序

我们现在希望将我们的应用程序进一步发展到云原生原则。让我们考虑一下，我们计数器应用程序的产品经理说我们的负载量非常大（您可以通过您的可观察性工具集来确认这一点），有些人并不总是得到一个严格递增的数字；有时，他们会得到相同数字的重复。因此，您与同事商讨后得出结论，为了保证递增的数字，您需要保证数据在应用程序中的访问和持久性。

具体来说，您需要保证针对此数据存储的操作是原子唯一的，在操作之间是一致的，与其他操作是隔离的，并且在故障时是持久的。也就是说，您正在寻找一个符合 ACID 标准的数据库。

注

有关 ACID 合规性的更多信息，请访问此链接：[`database.guide/what-is-acid-in-databases/`](https://database.guide/what-is-acid-in-databases/)。

团队希望能够使用数据库，但他们宁愿不支付 AWS 运行该数据库的费用。如果他们以后在 GCP 或 Azure 上找到更好的交易，他们也宁愿不被锁定在 AWS 上。

因此，在谷歌上简要查看了一些选项后，您的团队决定使用 MySQL。MySQL 是更受欢迎的开源 RDBMS 解决方案之一，因此有很多关于在 Kubernetes 中作为数据库解决方案实施的文档、支持和社区建议。

现在，开始更改您的代码以支持使用 MySQL 支持的事务来递增计数器。因此，为了做到这一点，我们需要改变一些事情：

+   更改我们的应用程序代码，以使用 SQL 而不是 Redis 来访问数据并递增计数器。

+   修改我们的 Kubernetes 集群，以运行 MySQL 而不是 Redis。

+   确保在发生灾难性故障时数据库下面的存储的持久性。

您可能会问自己为什么集群操作员或管理员需要能够理解和重构代码。Kubernetes 的出现加速了软件行业利用 DevOps 工具、实践和文化开始更快、更可预测地为客户提供价值的趋势。这意味着开始使用软件而不是人来扩展我们的操作。我们需要强大的自动化来取代以人为中心的流程，以便能够保证功能和交付速度。因此，基础架构设计师或管理员具有系统级软件工程经验，使他们能够协助重构代码库以利用更多的云原生实践，对他们的职业来说是一个巨大的好处，很快可能会成为所有 DevOps 工程师的工作要求。因此，让我们看看如何重构我们的应用程序以使用 MySQL 进行 StatefulSets 的事务处理。

注意

如果您还不熟悉编程，或者对作者选择的语言的语法（例如本例中的 Golang）不熟悉，您不必担心-所有解决方案都已经被解决并准备好使用。

首先，让我们检查*Exercise 12.04*，*使用状态管理部署应用程序*的代码：

main.go

```
28 if r.Method == "GET" { 
29     val, err := client.Get("num").Result() 
30     if err == redis.Nil { 
31         fmt.Println("num does not exist") 
32         err := client.Set("num", "0", 0).Err() 
33         if err != nil { 
34             panic(err) 
35         } 
36     } else if err != nil { 
37         w.WriteHeader(500) 
38         panic(err) 
39     } else { 
40         fmt.Println("num", val) 
41         num, err := strconv.Atoi(val) 
42         if err != nil { 
43             w.WriteHeader(500) 
44             fmt.Println(err) 
45         } else { 
46             num++ 
47             err := client.Set("num", strconv.Itoa(num), 0).Err() 
48             if err != nil { 
49                 panic(err) 
50             } 
51             fmt.Fprintf(w, "{number: %d}", num) 
52         } 
53 } 
```

此步骤的完整代码可以在[`packt.live/3jSWTHB`](https://packt.live/3jSWTHB)找到。

在上述代码中突出显示了我们访问持久层的两个实例。正如您所看到的，我们不仅没有使用事务，而且在代码中操作了值，因此无法保证这是一个严格递增的计数器。为了做到这一点，我们必须改变我们的策略。

注意

您可以在此链接找到使用 MySQL 容器所需的信息：[`hub.docker.com/_/mysql?tab=description`](https://hub.docker.com/_/mysql?tab=description)。

我们提供了使用 SQL 的重构应用程序。让我们来看看重构应用程序的代码：

main.go

```
38 fmt.Println("Starting HTTP server") 
39 http.HandleFunc("/get-number", func(w http.ResponseWriter, r      *http.Request) { 
40     if r.Method == "GET" { 
41         tx, err := db.Begin() 
42             if err != nil { 
43         panic(err) 
44         } 
45         _, err = tx.Exec(t1) 
46         if err != nil { 
47             tx.Rollback() 
48             fmt.Println(err) 
49         } 
50         err = tx.Commit() 
51         if err != nil { 
52             fmt.Println(err) 
53         } 
54         row := db.QueryRow(t2, 1) 
55         switch err := row.Scan(&num); err { 
56         case sql.ErrNoRows: 
57             fmt.Println("No rows were returned!") 
58         case nil: 
59             fmt.Fprintf(w, "{number: %d}\n", num) 
60         default: 
61             panic(err) 
62         } 
63     } else { 
64         w.WriteHeader(400) 
65         fmt.Fprint(w, "{\"error\": \"Only GET HTTP method is                supported.\"}") 
66     } 
67 }
```

此步骤的完整代码可以在[`packt.live/35ck7nX`](https://packt.live/35ck7nX)找到。

正如您所看到的，它与 Redis 代码大致相同，只是现在我们的值是在事务中设置的。与 Redis 不同，MySQL 不是一种易失性的内存数据存储，因此对数据库的操作必须持久化到磁盘才能成功，并且理想情况下，它们应该持久化到在 pod 中断时不会消失的磁盘上。让我们在下一个练习中设置我们应用程序的其他必需组件。

## 练习 14.01：部署带有 MySQL 后端的计数器应用

在这个练习中，我们将重新配置我们的计数器应用程序，使其与 MySQL 后端一起工作：

1.  首先，我们将从 Terraform 文件中重新创建您的 EKS 集群*练习 12.02*，*使用 Terraform 在 EKS 上创建集群*。如果您已经有`main.tf`文件，可以使用它。否则，您可以运行以下命令获取它：

```
curl -O https://raw.githubusercontent.com/PacktWorkshops/Kubernetes-Workshop/master/Chapter12/Exercise12.02/main.tf
```

现在，依次使用以下两个命令来启动并运行您的集群资源：

```
terraform init
terraform apply
```

注意

在执行任何练习之后，如果您计划在相当长的时间后继续进行以下练习，最好将集群资源分配给您以阻止 AWS 向您收费。您可以使用`terraform destroy`命令来做到这一点。然后，当您准备进行练习或活动时，可以运行此步骤将所有内容恢复在线。

如果任何练习或活动依赖于在先前练习中创建的对象，则您还需要重新创建这些对象。

1.  运行以下命令获取定义所有所需对象的清单文件`with_mysql.yaml`：

```
curl -O https://raw.githubusercontent.com/PacktWorkshops/Kubernetes-Workshop/master/Chapter14/Exercise14.01/with_mysql.yaml
```

打开文件进行检查，以便我们可以检查这个 StatefulSet：

使用 MySQL.yaml

```
44 apiVersion: apps/v1 
45 kind: StatefulSet 
46 metadata: 
47   name: mysql 
48 spec: 
49   selector: 
50    matchLabels: 
51       app: mysql 
52   serviceName: mysql 
53   replicas: 1 
54   template: 
55     metadata: 
56       labels: 
57         app: mysql 
58     spec: 
```

此步骤的完整代码可以在[`packt.live/2R2WN3x`](https://packt.live/2R2WN3x)找到。

注意

在这里，PersistentVolumeClaim 在启动时会自动将 10 GiB 卷从 Amazon EBS 绑定到每个 pod。 Kubernetes 将使用我们在 Terraform 文件中定义的 IAM 角色自动配置 EBS 卷。

当 pod 因任何原因中断时，Kubernetes 将在重新启动时自动将适当的 PersistentVolume 重新绑定到 pod，即使它在不同的工作节点上，只要它在相同的可用区。

1.  让我们通过运行以下命令将其应用到我们的集群：

```
kubectl apply -f with_mysql.yaml
```

您应该看到这个响应：

![图 14.2：部署使用 MySQL 后端的重构应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_14_02.jpg)

图 14.2：部署使用 MySQL 后端的重构应用程序

1.  现在在这个窗口运行`kubectl proxy`，然后让我们打开另一个终端窗口：

```
kubectl proxy
```

你应该看到这个回应：

```
Starting to serve on 127.0.0.1:8001
```

1.  在另一个窗口中，运行以下命令来访问我们的应用程序：

```
curl localhost:8001/api/v1/namespaces/default/services/kubernetes-test-ha-application-with-mysql:/proxy/get-number
```

你应该看到这个回应：

```
{number: 1}
```

您应该看到应用程序按预期运行，就像我们在前几章中看到的那样。就像那样，我们有一个使用 MySQL 持久化数据的工作 StatefulSet 与我们的应用程序。 

正如我们所说的，导致集群操作员不追求 StatefulSets 作为管理数据基础设施的一种方式的原因之一是错误地认为 PersistentVolumes 中的信息和它们绑定的 pod 一样短暂。这是不正确的。由 StatefulSet 创建的 PersistentVolumeClaims 如果删除了 pod 甚至 StatefulSet 也不会被删除。这是为了不惜一切代价保护这些卷中包含的数据。因此，对于清理，我们需要单独删除 PersistentVolume。集群操作员还可以利用其他工具来防止发生这种情况，例如更改 PersistentVolumes（或者创建它的 StorageClass）的回收策略。

## 练习 14.02：测试 PersistentVolumes 中 StatefulSet 数据的弹性

在这个练习中，我们将从上一个练习中离开的地方继续，并通过删除一个资源来测试我们应用程序中的数据的弹性，看看 Kubernetes 如何响应：

1.  现在到了有趣的部分，让我们尝试通过删除 MySQL pod 来测试我们持久性机制的弹性：

```
kubectl delete pod mysql-0
```

你应该看到这个回应：

```
pod "mysql-0" deleted
```

1.  此时应用可能会崩溃，但如果在删除 pod 之前几秒钟后再次尝试前面的`curl`命令，它应该会自动从我们删除 pod 之前的数字继续计数。我们可以通过尝试再次访问应用程序来验证这一点：

```
curl localhost:8001/api/v1/namespaces/default/services/kubernetes-test-ha-application-with-mysql:/proxy/get-number
```

您应该看到类似以下的回应：

```
{number: 2}
```

正如您所看到的，我们不仅从应用程序获得了有效的响应，而且还获得了序列中的下一个数字（`2`），这意味着当我们丢失 MySQL pod 并且 Kubernetes 恢复它时，没有丢失数据。

创建了这个 StatefulSet 之后，清理它并不像运行`kubectl delete -f with_mysql.yaml`那样简单。这是因为 Kubernetes 不会自动销毁由 StatefulSet 创建的 PersistentVolume。

注意

这也意味着，即使我们尝试使用`terraform destroy`删除所有 AWS 资源，我们仍将无限期地支付 AWS 中的孤立 EBS 卷（在这个示例中，我们不希望这样）。

1.  因此，为了清理，我们需要找出哪些 PersistentVolumes 绑定到这个 StatefulSet。让我们列出集群默认命名空间中的 PersistentVolumes：

```
kubectl get pv
```

您应该看到类似于以下的响应：

![图 14.3：获取持久卷列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_14_03.jpg)

图 14.3：获取持久卷列表

1.  看起来我们有一个名为`data-mysql-0`的 PersistentVolume，这是我们想要删除的。首先，我们需要删除创建它的对象。因此，让我们首先删除我们的应用程序及其所有组件：

```
kubectl delete -f with_mysql.yaml
```

您应该看到这个响应：

![图 14.4：删除与 MySQL 关联的持久卷](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_14_04.jpg)

图 14.4：删除与 MySQL 关联的持久卷

1.  让我们检查一下我们试图删除的持久卷：

```
kubectl get pv
```

您应该看到类似于这样的响应：

![图 14.5：获取持久卷列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_14_05.jpg)

图 14.5：获取持久卷列表

从这个图像中，看起来我们的卷还在那里。

1.  我们需要删除创建它的 PersistentVolume 和 PersistentVolumeClaim。为此，让我们首先运行以下命令：

```
kubectl delete pvc data-mysql-0
```

您应该看到这个响应：

```
persistentvolumeclaim "data-mysql-0" deleted
```

一旦我们删除 PersistentVolumeClaim，PersistentVolume 就变为`unbound`，并且受到其回收策略的约束，我们可以在上一步的截图中看到。在这种情况下，策略是删除底层存储卷。

1.  为了验证 PV 是否已删除，让我们运行以下命令：

```
kubectl get pv
```

您应该看到以下响应：

```
No resources found in default namespace.
```

正如在这个截图中所显示的，我们的 PersistentVolume 现在已被删除。

注意

如果您的情况的回收策略不是`Delete`，您还需要手动删除 PersistentVolume。

1.  现在我们已经清理了我们的 PersistentVolumes 和 PersistentVolumeClaims，我们可以继续按照通常的方式进行清理，通过运行以下命令：

```
terraform destroy
```

您应该看到一个以此截图结束的响应：

![图 14.6：清理 Terraform 创建的资源](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_14_06.jpg)

图 14.6：清理 Terraform 创建的资源

在这个练习中，我们已经看到了 Kubernetes 在删除 StatefulSet 时尝试保留 PersistentVolumes。我们还看到了当我们实际想要删除 PersistentVolume 时应该如何进行。

现在我们已经看到了如何设置 StatefulSet 并运行附加到其上的 MySQL 数据库，我们将在接下来的活动中进一步扩展高可用性的原则。不过，在我们这样做之前，我们需要解决 Kubernetes 清单蔓延的问题，因为似乎需要更多的 YAML 清单来实现构建高可用性有状态应用的目标。在接下来的部分中，我们将了解一个工具，它将帮助我们更好地组织和管理应用的清单。

# Helm

在本节中，我们将看一下一个在 Kubernetes 生态系统中非常有帮助的工具，称为 Helm。Helm 是由微软创建的，因为很快就显而易见，对于任何规模的 Kubernetes 部署（例如，涉及 20 个或更多独立组件、可观察性工具、服务和其他对象的部署），需要跟踪大量的 YAML 清单。再加上许多公司运行除了生产环境之外的多个环境，您需要能够使它们彼此保持同步，这样您就开始面临一个难以控制的问题。

Helm 允许您编写 Kubernetes 清单模板，您可以向其提供参数以覆盖任何默认值，然后 Helm 会为您创建适当的 Kubernetes 清单。因此，您可以将 Helm 用作一种软件包管理器，您可以使用 Helm 图表部署整个应用程序，并在安装之前调整一些小参数。使用 Helm 的另一种方式是作为模板引擎。它允许经验丰富的 Kubernetes 操作员仅编写一次良好的模板，然后可以被不熟悉 Kubernetes 清单语法的人成功地创建 Kubernetes 资源。Helm 图表可以通过参数设置任意数量的字段，并且可以根据不同的需求调整基本模板以部署软件或微服务的大不相同的实现。

Helm 软件包称为“图表”，它们具有特定的文件夹结构。您可以使用来自 Git 的共享 Helm 图表存储库，Artifactory 服务器或本地文件系统。在即将进行的练习中，我们将查看一个 Helm 图表并在我们的集群上安装它。

这是一个很好的机会来介绍 Helm，因为如果你一直在学习 Kubernetes，你已经写了相当多的 YAML 并将其应用到了你的集群中。此外，我们所写的很多内容都是我们以前见过的东西的重复。因此，利用 Helm 的模板功能将有助于打包类似的组件并使用 Kubernetes 进行交付。你不一定要利用 Helm 的模板组件来使用它，但这样做会有所帮助，因为你可以重复使用图表来生成不同排列的 Kubernetes 对象。

注意

我们将使用 Helm 3，它与其前身 Helm 2 有很大的不同，并且最近才发布。如果你熟悉 Helm 2 并想了解其中的区别，你可以参考这个链接上的文档：[`v3.helm.sh/docs/faq/#changes-since-helm-2`](https://v3.helm.sh/docs/faq/#changes-since-helm-2)。

Helm 的详细覆盖范围超出了本书的范围，但这里介绍的基本知识是一个很好的起点，也让我们明白了不同的工具和技术如何一起工作，以消除 Kubernetes 中复杂应用编排的几个障碍。

让我们看看如何创建一个图表（这是 Helm 术语中的一个包）并将其应用到一个集群中。然后，我们将了解 Helm 如何从 Helm 图表生成 Kubernetes 清单文件。

让我们通过运行以下命令来创建一个新的 Helm 图表：

```
helm create chart-dev
```

你应该会看到以下的回应：

```
Creating chart-dev
```

当你创建一个新的图表时，Helm 会默认生成一个 NGINX 的图表作为占位符应用。这将为我们创建一个新的文件夹和骨架图表供我们检查。

注意

在接下来的部分中，请确保你已经按照*前言*中的说明安装了`tree`。

让我们使用 Linux 的`tree`命令来看看 Helm 为我们做了什么：

```
tree .
```

你应该会看到类似以下的回应：

![图 14.7：Helm 图表的目录结构](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_14_07.jpg)

图 14.7：Helm 图表的目录结构

注意`templates`文件夹和`values.yaml`文件。Helm 通过使用`values.yaml`文件中的值，并将这些值填充到`templates`文件夹中的文件中相应的占位符中。让我们来看一下`values.yaml`文件的一部分：

values.yaml

```
1  # Default values for chart-dev.
2  # This is a YAML-formatted file.
3  # Declare variables to be passed into your templates.
4  
5  replicaCount: 1
6  
7  image:
8    repository: nginx
9    pullPolicy: IfNotPresent
10   # Overrides the image tag whose default is the chart appVersion.
11   tag: ""
12 
13 imagePullSecrets: []
14 nameOverride: ""
15 fullnameOverride: ""
```

这一步的完整代码可以在[`packt.live/33ej2cO`](https://packt.live/33ej2cO)找到。

正如我们在这里所看到的，这不是一个 Kubernetes 清单，但它看起来有许多相同的字段。在前面的片段中，我们已经突出显示了整个`image`块。这有三个字段（`repository`，`pullPolicy`和`tag`），每个字段都有其相应的值。

另一个值得注意的文件是`Chart.yaml`。此文件中的以下行与我们的讨论相关：

```
appVersion: 1.16.0
```

注意

您可以在此链接找到完整的文件：[`packt.live/2FboR2a`](https://packt.live/2FboR2a)。

文件中的注释对这意味着的描述相当详细：*“这是部署的应用程序的版本号。每次对应用程序进行更改时，应递增此版本号。版本不应遵循语义化版本。它们应反映应用程序正在使用的版本。”*

那么，Helm 是如何将这些组装成我们期望的传统 Kubernetes 清单格式的呢？要了解这一点，让我们检查`templates`文件夹中`deployment.yaml`文件的相应部分：

部署.yaml

```
30  containers:
31    - name: {{ .Chart.Name }}
32      securityContext:
33        {{- toYaml .Values.securityContext | nindent 12 }}
34      image: "{{ .Values.image.repository }}:{{ .Values.image.tag |           default .Chart.AppVersion }}"
35      imagePullPolicy: {{ .Values.image.pullPolicy }}
```

此步骤的完整代码可以在此链接找到：[`packt.live/3k0OGRL`](https://packt.live/3k0OGRL)。

这个文件看起来更像是一个 Kubernetes 清单，其中添加了许多变量。将`deployment.yaml`中的模板占位符与`values.yaml`和`Chart.yaml`中的观察结果进行比较，我们可以推断出以下内容：

+   `{{ .Values.image.repository }}`将被解释为`nginx`。

+   `{{ .Values.image.tag | default .Chart.AppVersion }}`将被解释为`1.16.0`。

因此，我们得到了我们部署规范的结果字段`image: nginx:1.16.0`。

这是我们第一次看到 Helm 模板语言。对于那些熟悉模板引擎（如 Jinja，Go 模板或 Twig）的人来说，这种语法应该看起来很熟悉。如前所述，我们不会深入了解 Helm 的太多细节，但您可以在此链接找到有关 Helm 文档的更多信息：[`helm.sh/docs/chart_template_guide/`](https://helm.sh/docs/chart_template_guide/)。

现在，让我们安装我们生成的示例图表`chart-dev`。这个图表将在我们的 Kubernetes 集群中部署一个示例 NGINX 应用程序。要安装 Helm 图表，命令如下所示：

```
helm install [NAME] [CHART] [flags]
```

我们可以使用`--generate-name`来获取一个随机名称。此外，由于我们已经在`chart-dev`目录中，我们可以直接使用当前工作目录根目录中的`values.yaml`：

```
helm install --generate-name -f values.yaml .
```

您应该看到以下响应：

![图 14.8：安装 Helm 图表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_14_08.jpg)

图 14.8：安装 Helm 图表

请注意，在输出中，您将收到关于接下来要做什么的说明。这些是来自`templates/NOTES.txt`文件的可定制说明。当您制作自己的 Helm 图表时，您可以使用这些来指导使用图表的人。现在，让我们运行这些命令。

注意

此输出中的确切值根据您的特定环境进行了定制，因此您应该从终端输出中复制命令。这适用于以下命令。

第一个命令将 pod 名称设置为名为`POD_NAME`的环境变量：

```
export POD_NAME=$(kubectl get pods --namespace default -l "app.kubernetes.io/name=chart-dev,app.kubernetes.io/instance=chart-1589678730" -o jsonpath="{.items[0].metadata.name}")
```

我们将跳过`echo`命令；它只是告诉您如何访问您的应用程序。存在这个`echo`命令的原因是为了显示终端输出中接下来的命令是什么。

现在在访问我们的应用程序之前，我们需要进行一些端口转发。下一个命令将在您的主机上将端口`8080`映射到 pod 上的端口`80`：

```
kubectl --namespace default port-forward $POD_NAME 8080:80
```

您应该看到这个响应：

```
Forwarding from 127.0.0.1:8080 ->80
Forwarding from [::1]:8080 -> 80
```

现在让我们尝试访问 NGINX。在浏览器中，转到`localhost:8080`。您应该能够看到默认的 NGINX 欢迎页面：

![图 14.9：访问我们的默认 NGINX 测试应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_14_09.jpg)

图 14.9：访问我们的默认 NGINX 测试应用程序

您可以通过删除我们的资源来清理这个。首先，让我们通过获取 Helm 在您的集群中安装的所有发布的列表来获得此发布的生成名称：

```
helm ls
```

您应该看到类似于这样的响应：

![图 14.10：获取 Helm 安装的所有应用程序列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_14_10.jpg)

图 14.10：获取 Helm 安装的所有应用程序列表

现在，我们可以按以下方式删除发布：

```
helm uninstall chart-1589678730
```

使用前面输出中的名称。您应该看到这个响应：

```
release "chart-1589678730" uninstalled
```

就像那样，我们已经编写了我们的第一个图表。所以，让我们继续进行下一个练习，我们将学习 Helm 如何确切地使我们的工作变得更容易。

## 练习 14.03：为我们的基于 Redis 的计数器应用创建图表

在上一节中，我们创建了一个通用的 Helm 图表，但是如果我们想为我们的软件制作自己的图表呢？在这个练习中，我们将创建一个 Helm 图表，该图表将使用 Helm 从*第十二章*“您的应用程序和 HA”中部署我们的 HA 基于 Redis 的解决方案。

1.  如果您在`chart-dev`目录中，导航到父目录：

```
cd ..
```

1.  让我们首先制作一个全新的 Helm 图表：

```
helm create redis-based-counter && cd redis-based-counter
```

您应该看到这个响应：

```
Creating redis-based-counter
```

1.  现在让我们从图表中删除不必要的文件：

```
rm templates/NOTES.txt; \
rm templates/*.yaml; \
rm -r templates/tests/; \
cd templates
```

1.  现在，我们需要进入图表的`templates`文件夹，并从我们的存储库中复制 Redis 计数应用程序的文件：

```
curl -O https://raw.githubusercontent.com/PacktWorkshops/Kubernetes-Workshop/master/Chapter14/Exercise14.03/templates/redis-deployment.yaml; \
curl -O https://raw.githubusercontent.com/PacktWorkshops/Kubernetes-Workshop/master/Chapter14/Exercise14.03/templates/deployment.yaml;\
curl -O https://raw.githubusercontent.com/PacktWorkshops/Kubernetes-Workshop/master/Chapter14/Exercise14.03/templates/redis-service.yaml; \
curl -O https://raw.githubusercontent.com/PacktWorkshops/Kubernetes-Workshop/master/Chapter14/Exercise14.03/templates/service.yaml
```

您可能还记得之前的章节中，我们有多个 Kubernetes 清单共享一个文件，由`---` YAML 文件分隔符字符串分隔。现在我们有了一个管理 Kubernetes 清单的工具，最好将它们保存在单独的文件中，以便我们可以独立管理它们。捆绑的工作现在将由 Helm 来处理。

1.  `templates`文件夹中应该有四个文件。让我们确认一下：

```
tree .
```

您应该会看到以下响应：

![图 14.11：我们应用程序的预期文件结构](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_14_11.jpg)

图 14.11：我们应用程序的预期文件结构

1.  现在我们需要修改`values.yaml`文件。从该文件中删除所有内容，然后只复制以下内容：

```
deployment:
  replicas: 3
redis:
  version: 3
```

1.  现在，为了将它们连接在一起，我们需要编辑`deployment.yaml`和`redis-deployment.yaml`。我们首先要编辑的是`deployment.yaml`。我们应该用模板替换`replicas: 3`，如下清单中的突出显示行所示：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubernetes-test-ha-application-with-redis-deployment
  labels:
    app: kubernetes-test-ha-application-with-redis
spec:
  replicas: {{ .Values.deployment.replicas }}
  selector:
    matchLabels:
      app: kubernetes-test-ha-application-with-redis
  template:
    metadata:
      labels:
        app: kubernetes-test-ha-application-with-redis
    spec:
      containers:
        - name: kubernetes-test-ha-application-with-redis
          image: packtworkshops/the-kubernetes-workshop:demo-app-            with-redis
          imagePullPolicy: Always
          ports:
            - containerPort: 8080
          env:
            - name: REDIS_SVC_ADDR
              value: "redis.default:6379"
```

1.  接下来，编辑`redis-deployment.yaml`文件，并添加一个类似的模板语言块，如下清单中的突出显示行所示：

```
apiVersion: apps/v1 # for versions before 1.9.0 use apps/v1beta2
kind: Deployment
metadata:
  name: redis
  labels:
    app: redis
spec:
  selector:
    matchLabels:
      app: redis
  replicas: 1
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
        - name: master
          image: redis:{{ .Values.redis.version }}
          resources:
            requests:
              cpu: 100m
              memory: 100Mi
          ports:
            - containerPort: 6379
```

1.  现在让我们使用 Helm 安装我们的应用程序：

```
helm install --generate-name -f values.yaml .
```

您应该会看到类似于这样的响应：

![图 14.12：使用自动生成的名称安装我们的 Helm 图表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_14_12.jpg)

图 14.12：使用自动生成的名称安装我们的 Helm 图表

1.  要检查我们的应用程序是否在线，我们可以获取部署列表：

```
kubectl get deployment
```

您应该会看到以下输出：

![图 14.13：获取部署列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_14_13.jpg)

图 14.13：获取部署列表

如您所见，Helm 已部署了我们的应用程序部署，以及为其部署的 Redis 后端。有了这些技能，您很快就会成为 Helm 的船长。

在接下来的活动中，我们将结合本章学到的两件事情——重构我们的应用程序以用于有状态的组件，然后将其部署为 Helm 图表。

## 活动 14.01：将我们的 StatefulSet 部署为图表

现在您已经有了 MySQL、StatefulSets 和 Helm 资源管理的经验，您的任务是将*练习 14.01*、*14.02*和*14.03*中学到的知识结合起来。

对于这个活动，我们将重构我们基于 Redis 的应用程序，使用 StatefulSets 来使用 MySQL 作为后端数据存储，并使用 Helm 进行部署。

遵循这些高级指南完成活动：

1.  按照*Exercise 14.01*的*step 1*中所示设置所需的集群基础设施，部署一个带有 MySQL 后端的计数器应用。

1.  引入一个名为`counter-mysql`的新 Helm 图表。

1.  创建一个使用 MySQL 作为后端的计数器应用的模板。

1.  为我们的 MySQL StatefulSet 创建一个模板。

1.  在适当的地方使用 Kubernetes Service 对象将所有内容连接起来。

1.  配置模板，使`values.yaml`文件能够更改 MySQL 的版本。

1.  测试应用程序。您应该看到与我们在以前的练习中看到的计数器应用程序类似的输出：![图 14.14：活动 14.01 的预期输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_14_14.jpg)

图 14.14：活动 14.01 的预期输出

注意

此活动的解决方案可以在以下地址找到：[`packt.live/304PEoD`](https://packt.live/304PEoD)。

此外，不要忘记使用`terraform destroy`命令清理云资源，以防止 AWS 在活动结束后向您收费。

# 总结

在本章的过程中，我们已经应用了我们的技能，以便能够在我们的示例应用程序中利用 StatefulSets。我们已经看到了如何以编程方式考虑运行软件的有状态部分，以及如何重构应用程序以利用状态持久性的变化。最后，我们学会了如何创建和运行 Kubernetes StatefulSets，这将使我们能够在集群中运行有状态的组件，并对工作负载的运行方式做出保证。

具备管理 Kubernetes 集群上有状态组件所需的技能是能够有效地在许多现实世界的应用中操作的重要一步。

在下一章中，我们将更多地讨论使用 Metrics Server、HorizontalPodAutoscalers 和 ClusterAutoscaler 进行数据驱动的应用编排。我们将学习这些对象如何帮助我们应对运行在 Kubernetes 集群上的应用的需求变化。
