# Kubernetes Windows 实用指南（六）

> 原文：[`zh.annas-archive.org/md5/D85F9AD23476328708B2964790249673`](https://zh.annas-archive.org/md5/D85F9AD23476328708B2964790249673)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十五章：灾难恢复

在每个生产系统中，**灾难恢复**（**DR**）和**业务连续性**（**BC**）是您必须牢记的关键概念，以确保应用工作负载的可用性。您必须在早期阶段考虑它们，以规划您的集群架构。谚语*未能准备，实际上是在准备失败*对于操作 Kubernetes 等分布式系统来说再合适不过了。本章将重点介绍运行 Kubernetes 集群时的灾难恢复。本章的范围不包括多区部署和持久卷的异步复制等 BC 最佳实践。

一般来说，灾难恢复包括一套政策、工具和程序，以使关键技术基础设施和系统在自然或人为灾难后能够恢复或继续运行。您可以在 Google 的一篇优秀文章中了解更多关于灾难恢复规划涉及的概念：[`cloud.google.com/solutions/dr-scenarios-planning-guide`](https://cloud.google.com/solutions/dr-scenarios-planning-guide)。灾难恢复和业务连续性的主要区别在于，灾难恢复侧重于在停机后使基础设施恢复运行，而业务连续性则处理在重大事件期间保持业务场景运行。在 Kubernetes 中，灾难恢复的重要之处在于，您可以基本上专注于对集群的数据和状态进行保护：您需要为有状态的组件制定备份和恢复策略。在 Kubernetes 集群中，最重要的有状态组件是 etcd 集群，它是 Kubernetes API 服务器的存储层。

在本章中，我们将涵盖以下主题：

+   Kubernetes 集群备份策略

+   备份 etcd 集群

+   恢复 etcd 集群备份

+   自动化备份

+   替换失败的 etcd 集群成员

# 技术要求

对于本章，您将需要以下内容：

+   安装了 Windows 10 Pro、企业版或教育版（1903 版或更高版本，64 位）

+   在您的 Windows 机器上安装 SSH 客户端

+   Azure 帐户

+   使用 AKS Engine 或本地集群部署的多主 Windows/Linux Kubernetes 集群（适用于某些场景）

要跟着做，您需要自己的 Azure 账户以创建 Kubernetes 集群的 Azure 资源。如果您之前没有为早期章节创建账户，您可以阅读有关如何获取个人使用的有限免费账户的更多信息[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)。

使用 AKS Engine 部署 Kubernetes 集群已在第八章中进行了介绍，*部署混合 Azure Kubernetes 服务引擎集群*。

您可以从官方 GitHub 存储库[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter15`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter15)下载本章的最新代码示例。

# Kubernetes 集群备份策略

Kubernetes 的灾难恢复基本上涉及创建集群状态备份和恢复策略。让我们首先看看 Kubernetes 中有哪些有状态的组件：

+   Etcd 集群（[`etcd.io/`](https://etcd.io/)）用于持久化 Kubernetes API 服务器资源的状态。

+   Pod 使用的持久卷。

令人惊讶的是（或者*不*），就是这样！对于主节点组件和运行在工作节点上的 pod，您不涉及任何不可恢复的状态；如果您提供了一个新的替换节点，Kubernetes 可以轻松地将工作负载移动到新节点，提供完整的业务连续性。当您的 etcd 集群被恢复时，Kubernetes 将负责协调集群组件的状态。

让我们看看如何备份和恢复持久卷。这完全取决于您的持久卷是如何提供的。您可以依赖于存储在外部的标准文件系统备份，或者在云支持的 PV 的情况下，您可以使用磁盘快照并将其作为云服务的一部分进行管理。还有一个有趣的快照和恢复功能（目前处于 alpha 状态），用于使用 CSI 插件提供的 PV。这将直接在 Kubernetes 集群级别提供更好的备份和恢复集成。

有一个通用的经验法则，尽量使您的集群工作负载尽可能无状态。考虑使用外部托管服务来存储您的数据（例如，Azure blob 存储，Azure Cosmos DB），这些服务的可用性和数据可靠性由 SLA 保证。

对于 etcd 集群，备份和恢复策略取决于两个因素：您如何存储 etcd 数据以及 Kubernetes 主节点的高可用性拓扑是什么。在 etcd 数据存储的情况下，情况类似于持久卷。如果您使用云卷挂载存储，可以依赖云服务提供商的磁盘快照（这是 AKS Engine 的情况），对于自管理磁盘，可以采用标准的文件系统备份策略。在所有情况下，您还有第三个选择：您可以使用 etcd 本身的快照功能。我们稍后将向您展示如何使用`etcdctl`命令执行 etcd 的快照和恢复。

关于 Kubernetes 主节点的高可用性拓扑，如第四章中所述，*Kubernetes 概念和 Windows 支持*，您可以运行**堆叠**拓扑或**外部**拓扑用于 etcd。在堆叠拓扑中，etcd 成员作为 Kubernetes pod 在*每个*主节点上运行。对于外部拓扑，您在 Kubernetes 集群之外运行 etcd 集群。它可能是完全外部的，部署在单独的专用主机上，也可能与主节点共享相同的主机。后者是 AKS Engine 的情况：它运行外部拓扑，但每个主节点都托管一个 etcd 成员作为本机 Linux 服务。对于这两种拓扑，您可以以相同的方式执行备份；唯一的区别在于如何执行恢复。在堆叠拓扑中，通常用于**kubeadm**部署，您需要在新节点上执行`kubeadm init`覆盖本地 etcd 存储。对于外部拓扑，您可以简单地使用`etcdctl`命令。

etcd 集群的外部拓扑具有更多组件，但通常更好地提供业务连续性和灾难恢复。

此外，如果您运行的是 AKS Engine 集群，您可以考虑使用 Azure Cosmos DB（[`azure.microsoft.com/en-us/services/cosmos-db/`](https://azure.microsoft.com/en-us/services/cosmos-db/)）而不是自行管理的 etcd 集群。Cosmos DB 支持暴露 etcd API，并且可以像本地 etcd 集群一样用作 Kubernetes 的后备存储。这样，您可以获得全球分发、高可用性、弹性扩展和 SLA 中定义的数据可靠性。此外，您还可以获得具有地理复制的自动在线备份。您可以在官方文档的 cluster apimodel 中了解更多关于此功能以及如何配置它的信息，网址为[`github.com/Azure/aks-engine/tree/master/examples/cosmos-etcd`](https://github.com/Azure/aks-engine/tree/master/examples/cosmos-etcd)。

现在，让我们来看看如何备份您的 etcd 集群。

# 备份 etcd 集群

备份 etcd 集群的过程很简单，但有多种方法可以完成这项任务：

+   创建 etcd 存储磁盘的备份或快照。这在云场景中尤为重要，您可以轻松地在 Kubernetes 集群之外管理备份。

+   使用`etcdctl`命令手动对 etcd 进行快照。您需要自行管理备份文件：将它们上传到外部存储，并应用保留策略。

+   使用**Velero**（原名 Heptio Ark ([`velero.io/`](https://velero.io/)）），它可以执行快照，管理外部存储中的快照，并在需要时恢复它们。此外，它还可以使用**Restic**集成（[`velero.io/docs/master/restic/`](https://velero.io/docs/master/restic/)）来执行持久卷的备份。

+   使用**etcd-operator**（[`github.com/coreos/etcd-operator`](https://github.com/coreos/etcd-operator)）在 Kubernetes 之上提供 etcd 集群。您可以轻松管理 etcd 集群并执行备份和恢复操作。如果您计划在环境中管理多个 Kubernetes 集群，可以使用这种方法。

我们将演示第二个选项，即手动快照 etcd——在切换到高级自动化（如 Velero）之前，了解底层发生了什么通常是很重要的。为此任务，您将需要一个多主 Kubernetes 集群；您可以使用 AKS Engine 创建一个。与之前的章节一样，您可以使用 Github 存储库中的准备好的 apimodel 定义[https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter15/01_multimaster-aks-engine/kubernetes-windows-template.json]，并使用我们通常的 PowerShell 脚本[https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter15/01_multimaster-aks-engine/CreateAKSEngineClusterWithWindowsNodes.ps1]部署它。此定义将部署三个主节点以及一个 Linux 工作节点和一个 Windows 节点。

请确保您检查在 Azure 上托管五节点 Kubernetes 集群的预估成本。价格将取决于您部署的区域。

当您的集群准备好后，部署一个应用工作负载，例如，之前章节中的投票应用。然后，按照以下步骤创建 etcd 快照：

1.  打开 PowerShell 窗口，并使用以下命令 SSH 到其中一个主节点：

```
ssh azureuser@<dnsPrefix>.<azureLocation>.cloudapp.azure.com
```

1.  检查您的 Kubernetes 集群配置。使用`kubectl cluster-info dump`命令了解更多关于 etcd 设置的信息。您将看到每个主节点都在运行其自己的本地实例（但是外部到集群）的 etcd，并将其作为参数传递给 Kubernetes API 服务器：

```
azureuser@k8s-master-50659983-0:~$ kubectl cluster-info dump
...
 "--etcd-servers=https://127.0.0.1:2379",
...
```

1.  使用`etcdctl`命令获取 etcd 集群的拓扑结构，该集群在主节点上有成员：

```
azureuser@k8s-master-50659983-0:~$ sudo etcdctl cluster-health
member b3a6773c0e93604 is healthy: got healthy result from https://10.255.255.5:2379
member 721d9c3882dbe6f7 is healthy: got healthy result from https://10.255.255.7:2379
member 72b3415f69c52b2a is healthy: got healthy result from https://10.255.255.6:2379
cluster is healthy
```

您可以在 Azure 门户中检查这些是否是主节点的私有 IP 地址。

1.  按顺序执行以下命令以创建 etcd 的快照：

```
sudo mkdir -p /backup
ETCDCTL_API=3 sudo -E etcdctl \
 --endpoints=https://127.0.0.1:2379 \
 --cacert=/etc/kubernetes/certs/ca.crt \
 --cert=/etc/kubernetes/certs/etcdclient.crt \
 --key=/etc/kubernetes/certs/etcdclient.key \
 --debug \
 snapshot save \
 /backup/kubernetes-etcd-snapshot_$(date +"%Y%m%d_%H%M%S").db
```

1.  备份应该在短时间内完成。您可以使用以下命令检查备份的状态：

```
azureuser@k8s-master-50659983-0:~$ ETCDCTL_API=3 sudo -E etcdctl --write-out=table snapshot status /backup/kubernetes-etcd-snapshot_20191208_182555.db
+----------+----------+------------+------------+
|   HASH   | REVISION | TOTAL KEYS | TOTAL SIZE |
+----------+----------+------------+------------+
| b4422ea6 |    28331 |       1034 |     3.2 MB |
+----------+----------+------------+------------+
```

另外，您应该备份用于访问 etcd 集群的证书和密钥。在我们的情况下，这是不需要的，因为我们将恢复相同的主节点机器。但是在一般的灾难恢复场景中，您将需要它们。

备份准备就绪，让我们看看如何将文件上传到 Azure blob 存储。请注意，*不应*直接在生产主节点上执行这些操作，特别是在*快速*安装 Azure CLI 时。我们演示这一点是为了之后创建一个 Kubernetes **CronJob**，它将运行一个 Docker 容器来执行这些操作。请按照以下步骤操作您的开发集群。

1.  在本地计算机上打开一个 PowerShell 窗口，并使用`az login`命令登录到 Azure。

1.  创建一个服务主体，我们将用它来上传备份到 Azure blob 存储容器：

```
PS C:\src> az ad sp create-for-rbac `
 --role="Storage Blob Data Contributor" `
 --scopes="/subscriptions/<azureSubscriptionId>/resourceGroups/<aksEngineResourceGroupName>"

Creating a role assignment under the scope of "/subscriptions/cc9a8166-829e-401e-a004-76d1e3733b8e/resourceGroups/aks-engine-windows-resource-group"
...
{
 "appId": "89694083-0110-4821-9510-a74eedf7a27c",
 "displayName": "azure-cli-2019-12-08-19-15-41",
 "name": "http://azure-cli-2019-12-08-19-15-41",
 "password": "67b1f492-caea-463f-ac28-69177f52fecf",
 "tenant": "86be0945-a0f3-44c2-8868-9b6aa96b0b62"
}
```

复制`appId`、`password`和`tenant`以供进一步使用。

1.  执行以下命令创建一个专用的`aksenginebackups`存储账户来处理备份。选择与您的 AKS Engine 集群相同的 Azure 位置：

```
az storage account create `
 --name aksenginebackups `
 --resource-group <aksEngineResourceGroupName> `
 --location <azureLocation> `
 --sku Standard_ZRS `
 --encryption blob
```

1.  列出新账户的账户密钥，并复制`key1`的值以供进一步使用：

```
az storage account keys list `
 --account-name $aksenginebackups `
 --resource-group <aksEngineResourceGroupName>
```

1.  继续使用上一段的 SSH 会话来操作您的开发 AKS Engine 集群主节点。执行以下命令安装 Azure CLI：

```
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

1.  使用服务主体的`appId`、`password`和`tenant`登录到 Azure：

```
az login --service-principal \
   -u 1775963c-8414-434d-839c-db5d417c4293 \
   -p 276952a9-fa51-44ef-b6c6-905e322dbaed \
   --tenant 86be0945-a0f3-44c2-8868-9b6aa96b0b62
```

1.  为我们的 AKS Engine 集群创建一个新的备份容器。您可以使用任何名称，例如集群的 DNS 前缀：

```
az storage container create \
 --account-name aksenginebackups \
 --account-key "<storageAccountKey>" \
 --name <dnsPrefix>
```

1.  创建一个包含我们在上一段中创建的备份的 blob：

```
sudo az storage blob upload \
 --account-name aksenginebackups \
 --account-key "<storageAccountKey>" \
 --container-name <dnsPrefix> \
 --name kubernetes-etcd-snapshot_20191208_182555.db \
 --file /backup/kubernetes-etcd-snapshot_20191208_182555.db
```

1.  从本地磁盘中删除备份文件：

```
sudo rm /backup/kubernetes-etcd-snapshot_20191208_182555.db
```

为了创建服务主体和存储账户，我们在 GitHub 仓库中提供了一个 PowerShell 脚本，网址为[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter15/02_CreateBlobContainerForBackups.ps1`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter15/02_CreateBlobContainerForBackups.ps1)。

您已成功创建了 etcd 快照并将其上传到 Azure blob 存储。现在，我们将演示如何恢复我们刚刚创建的备份。

# 恢复 etcd 集群备份

为了演示对现有 AKS Engine 集群进行 etcd 恢复的场景，我们首先需要修改一些 Kubernetes 对象，以后证明备份恢复已经生效。请注意，本节中显示的所有命令都假定您正在运行使用外部 etcd 拓扑的 AKS Engine，etcd 成员在托管 Kubernetes 主控组件的相同机器上运行。对于其他集群，比如本地 kubeadm 设置，目录的结构将会有所不同。

首先，让我们介绍一些对集群状态的更改。例如，如果您的投票应用程序正在运行，请使用以下命令删除相关的`Deployment`对象：

```
kubectl delete deployment -n dev-helm voting-application
```

过一段时间，所有的 pod 都将被终止——假设这是我们的**灾难事件**，导致集群无法使用。我们将要恢复之前创建并上传到 Azure Blob 存储的名为`kubernetes-etcd-snapshot_20191208_182555.db`的备份！

如果您已经删除了 SQL Server Deployment 以及 PVCs，那么恢复将不会完全成功。正如我们在前面的章节中提到的，对于 PVs，您需要有一个与 etcd 备份协调的单独的备份策略。然后您可以同时恢复 etcd 快照和相关的 PV 快照。

要执行恢复操作，您需要同时连接到所有三个 Kubernetes 节点。这个操作可以按顺序执行，但是主机上停止和启动 etcd 服务必须同时进行。请按照以下步骤进行：

1.  打开三个 PowerShell 窗口（尽量让它们同时打开并可见，以便更容易地发出命令）。每个窗口将用于一个单独的 Kubernetes 主控。

1.  在 Azure 门户中，找到主控节点的私有 IP。您也可以使用 Azure CLI 来完成这个操作。它们应该遵循这样的约定，即主控`0`是`10.255.255.5`，主控`1`是`10.255.255.6`，主控`2`是`10.255.255.7`。

1.  在第一个 PowerShell 窗口中，执行以下命令连接到一个主控节点（在 Azure 负载均衡器后面），并额外使用端口转发，将本地端口`5500`转发到主控`0`的 SSH 端口，端口`5501`转发到主控`1`的 SSH 端口，端口`5502`转发到主控`2`的 SSH 端口：

```
ssh -L 5500:10.255.255.5:22 `
 -L 5501:10.255.255.6:22 `
 -L 5502:10.255.255.7:22 `
 azureuser@<dnsPrefix>.<azureLocation>.cloudapp.azure.com
```

1.  通过这种方式，您可以从本地机器连接到任何您想要的 Kubernetes 主节点。检查您已经连接到哪个主节点，并在剩余的 PowerShell 窗口中创建 SSH 连接到*其他两个*节点，例如：

```
# Connection to Master 0 already established

# Master 1
ssh azureuser@localhost -p 5501

# Master 2
ssh azureuser@localhost -p 5502
```

1.  现在，您有一组 PowerShell 窗口，可以分别管理每个主节点。第一步是安装 Azure CLI。在*所有主节点*上执行以下命令：

```
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

1.  使用服务主体的`appId`、`password`和`tenant`登录到 Azure，就像之前一样。在*所有主节点*上执行以下命令：

```
az login --service-principal \
   -u 1775963c-8414-434d-839c-db5d417c4293 \
   -p 276952a9-fa51-44ef-b6c6-905e322dbaed \
   --tenant 86be0945-a0f3-44c2-8868-9b6aa96b0b62
```

1.  下载`kubernetes-etcd-snapshot_20191208_182555.db`快照文件。在所有主节点上执行以下命令：

```
az storage blob download \
 --account-name aksenginebackups \
 --account-key "<storageAccountKey>" \
 --container-name <dnsPrefix> \
 --name kubernetes-etcd-snapshot_20191208_182555.db \
 --file snapshot.db
```

1.  所有 etcd 成员必须从相同的快照文件中恢复。这意味着您必须在所有节点上执行类似的操作，只是使用不同的参数。在每个主节点上，确定 etcd 服务的启动参数（对于 AKS Engine，它作为 systemd 服务运行）。执行以下命令以获取每个主节点的参数：

```
cat /etc/default/etcd
```

1.  您需要捕获每个节点的`--name`、`--initial-cluster`、`--initial-cluster-token`和`--initial-advertise-peer-urls`。更确切地说，`--initial-cluster`和`--initial-cluster-token`对于所有主节点都是相同的。我们将使用这些值在每个主节点上初始化一个*新*的 etcd 成员，例如，在我们的集群中，对于主节点`0`，这些参数如下：

```
--name k8s-master-50659983-0
--initial-cluster k8s-master-50659983-0=https://10.255.255.5:2380,k8s-master-50659983-1=https://10.255.255.6:2380,k8s-master-50659983-2=https://10.255.255.7:2380
--initial-cluster-token k8s-etcd-cluster
--initial-advertise-peer-urls https://10.255.255.5:2380
```

1.  我们可以继续为每个 etcd 集群成员恢复数据。此恢复操作仅创建一个新的数据目录。集群当前正在使用的原始数据目录是`/var/lib/etcddisk`（它是从云卷挂载的）。我们将把数据恢复到`/var/lib/etcdisk-restored`，然后交换内容。使用上一步的参数，使用匹配的参数为每个主节点执行此命令：

```
# Master 0
ETCDCTL_API=3 sudo -E etcdctl snapshot restore snapshot.db \
 --name k8s-master-50659983-0 \
 --initial-cluster k8s-master-50659983-0=https://10.255.255.5:2380,k8s-master-50659983-1=https://10.255.255.6:2380,k8s-master-50659983-2=https://10.255.255.7:2380 \
 --initial-cluster-token k8s-etcd-cluster \
 --initial-advertise-peer-urls https://10.255.255.5:2380 \
 --data-dir=/var/lib/etcddisk-restored \
 --debug

# Master 1
ETCDCTL_API=3 sudo -E etcdctl snapshot restore snapshot.db \
 --name k8s-master-50659983-1 \
 --initial-cluster k8s-master-50659983-0=https://10.255.255.5:2380,k8s-master-50659983-1=https://10.255.255.6:2380,k8s-master-50659983-2=https://10.255.255.7:2380 \
 --initial-cluster-token k8s-etcd-cluster \
 --initial-advertise-peer-urls https://10.255.255.6:2380 \
 --data-dir=/var/lib/etcddisk-restored \
 --debug

# Master 2
ETCDCTL_API=3 sudo -E etcdctl snapshot restore snapshot.db \
 --name k8s-master-50659983-2 \
 --initial-cluster k8s-master-50659983-0=https://10.255.255.5:2380,k8s-master-50659983-1=https://10.255.255.6:2380,k8s-master-50659983-2=https://10.255.255.7:2380 \
 --initial-cluster-token k8s-etcd-cluster \
 --initial-advertise-peer-urls https://10.255.255.7:2380 \
 --data-dir=/var/lib/etcddisk-restored \
 --debug
```

1.  快照数据已准备好用于新的 etcd 集群。但首先，我们需要优雅地停止现有的 Kubernetes 主组件；否则，在恢复后，您将处于不一致的状态。

1.  Kubelet 观察`/etc/kubernetes/manifests`目录，其中存储了主组件的清单文件。对这些清单的任何更改都将由 kubelet 应用于集群；这就是在没有 Kubernetes API 服务器的情况下引导 Kubernetes 主节点的方式。要停止主组件，包括 Kubernetes API 服务器，只需将清单文件移动到另一个目录并在所有主节点上执行以下命令：

```
sudo mv /etc/kubernetes/manifests /etc/kubernetes/manifests-stopped
```

几秒钟后，您将看到主组件的 Docker 容器正在停止（使用`docker ps`命令来查看）。

1.  现在，在所有主节点上停止 etcd 服务：

```
sudo service etcd stop
```

1.  在所有主节点上停止 kubelet 服务：

```
sudo service kubelet stop
```

1.  准备好恢复的主节点的最后一步是删除在主节点上运行但未使用`/etc/kubernetes/manifests`目录启动的所有其他 Docker 容器。在所有主节点上执行以下命令：

```
docker stop $(docker ps -q)
```

1.  对 etcd 成员执行实际的数据目录恢复。在所有主节点上执行以下命令。

```
# Backing up old data directory
sudo mkdir /var/lib/etcddisk-old
sudo mv /var/lib/etcddisk/member /var/lib/etcddisk-old/

# Move the contents of the snapshot directory to the target data directory
sudo mv /var/lib/etcddisk-restored/member /var/lib/etcddisk/
sudo chown etcd -R /var/lib/etcddisk
sudo chgrp etcd -R /var/lib/etcddisk
sudo ls -al /var/lib/etcddisk/member/

# Cleanup
sudo rm -rf /var/lib/etcddisk-restored
```

1.  现在我们可以开始使用恢复的快照引导集群。第一步是启动 etcd 集群。在所有主节点上执行以下命令：

```
sudo service etcd start
```

您可以使用`sudo -E etcdctl cluster-health`命令验证 etcd 集群的健康状况。

1.  将停止的清单文件移回到所有主节点的原始位置。一旦 kubelet 启动，它们将被 kubelet 捡起：

```
sudo mv /etc/kubernetes/manifests-stopped /etc/kubernetes/manifests
```

1.  最后，执行最后一步：在所有主节点上启动 kubelet 服务：

```
sudo service kubelet start
```

您可以使用`docker ps`命令快速验证主组件的容器是否正在启动。

1.  您可以在新的 PowerShell 窗口中检查集群是否已经努力协调恢复的状态：

```
PS C:\src> kubectl get pods --all-namespaces
NAMESPACE     NAME                                               READY   STATUS              RESTARTS   AGE
dev-helm      voting-application-8477c76b67-4lkrm                0/1     CrashLoopBackOff    6          9h
dev-helm      voting-application-8477c76b67-7tbmw                0/1     CrashLoopBackOff    6          9h
dev-helm      voting-application-8477c76b67-dls6q                0/1     ContainerCreating   7          9h
dev-helm      voting-application-8477c76b67-dvcqz                0/1     ContainerCreating   7          9h
dev-helm      voting-application-8477c76b67-xttml                0/1     CrashLoopBackOff    9          9h
dev-helm      voting-application-mssql-linux-8548b4dd44-hdrpc    0/1     ContainerCreating   0          9h
kube-system   azure-cni-networkmonitor-6dr8c                     1/1     Running             1          9h
kube-system   azure-cni-networkmonitor-dhgsv                     1/1     Running             0          9h
...
```

我们的投票应用程序部署正在重新创建。这是一个*好消息*：快照恢复已经*成功*。几分钟后，所有的 pod 都将准备就绪，您可以在 Web 浏览器中导航到外部 IP 并再次享受应用程序。

Kubernetes 的**Openshift**发行版实现了本地 etcd 快照恢复功能。您可以在存储库中的脚本中查看详细信息[`github.com/openshift/machine-config-operator/blob/master/templates/master/00-master/_base/files/usr-local-bin-etcd-snapshot-restore-sh.yaml`](https://github.com/openshift/machine-config-operator/blob/master/templates/master/00-master/_base/files/usr-local-bin-etcd-snapshot-restore-sh.yaml)。那里的步骤大致类似于我们在本节中所做的。

正如您所看到的，手动恢复场景有点复杂，并且容易出错。在生产场景中，当其他方法失败时，您应该使用此方法；通常最好使用自动化备份控制器，例如 Velero（[`velero.io/`](https://velero.io/)）。

在下一节中，您将学习如何使用 Kubernetes CronJobs 在 AKS Engine 上自动化备份过程。

# 自动化备份

在本节中，我们将演示如何使用 Kubernetes CronJob 自动化 etcd 集群的备份过程。为此，我们需要一个 Dockerfile，其中安装了`etcdctl`和 Azure CLI，以便为图像创建快照并将其上传到选定的 Azure blob 容器，就像我们在手动步骤中演示的那样。所有配置和服务主体密码将使用环境变量注入，可以使用 Kubernetes secret 设置。

要为 etcd 快照工作程序创建 Docker 镜像，请按照以下步骤进行：

1.  使用 Linux 机器或切换到 Windows 的 Docker 桌面中的 Linux 容器。

1.  打开一个新的 PowerShell 窗口。

1.  为您的源代码创建一个新目录并导航到该目录。

1.  创建一个名为`Dockerfile`的文件，内容如下：

```
FROM ubuntu:18.04

ARG ETCD_VERSION="v3.3.15"

WORKDIR /temp
RUN apt-get update \
 && apt-get install curl -y \
 && curl -L https://github.com/coreos/etcd/releases/download/$ETCD_VERSION/etcd-$ETCD_VERSION-linux-amd64.tar.gz -o etcd-$ETCD_VERSION-linux-amd64.tar.gz \
 && tar xzvf etcd-$ETCD_VERSION-linux-amd64.tar.gz \
 && rm etcd-$ETCD_VERSION-linux-amd64.tar.gz \
 && cd etcd-$ETCD_VERSION-linux-amd64 \
 && cp etcdctl /usr/local/bin/ \
 && rm -rf etcd-$ETCD_VERSION-linux-amd64

RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

WORKDIR /backup-worker
COPY ./docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh

ENTRYPOINT ["/backup-worker/docker-entrypoint.sh"]
```

此 Dockerfile 基于 Ubuntu 18.04 Docker 镜像，并从 etcd 的官方发布中安装`etcdctl`命令。此外，我们安装了 Azure CLI，并将`ENTRYPOINT`设置为一个自定义 shell 脚本，该脚本在容器启动时执行快照操作。

1.  现在，创建一个名为`docker-entrypoint.sh`的文件，内容如下。

```
#!/bin/bash

snapshot_file="kubernetes-etcd-snapshot_$(date +"%Y%m%d_%H%M%S").db"

ETCDCTL_API=3 etcdctl \
   --endpoints=$SNAPSHOT_ETCD_ENDPOINTS \
   --cacert=/etc/kubernetes/certs/ca.crt \
   --cert=/etc/kubernetes/certs/etcdclient.crt \
   --key=/etc/kubernetes/certs/etcdclient.key \
   --debug \
   snapshot save \
   $snapshot_file

ETCDCTL_API=3 etcdctl --write-out=table snapshot status $snapshot_file

az login --service-principal \
   -u $SNAPSHOT_AZURE_PRINCIPAL_APPID \
   -p $SNAPSHOT_AZURE_PRINCIPAL_PASSWORD \
   --tenant $SNAPSHOT_AZURE_PRINCIPAL_TENANT

az storage container create \
   --account-name $SNAPSHOT_AZURE_ACCOUNT_NAME \
   --account-key "$SNAPSHOT_AZURE_ACCOUNT_KEY" \
   --name $SNAPSHOT_AZURE_CONTAINER_NAME

az storage blob upload \
   --account-name $SNAPSHOT_AZURE_ACCOUNT_NAME \
   --account-key "$SNAPSHOT_AZURE_ACCOUNT_KEY" \
   --container-name $SNAPSHOT_AZURE_CONTAINER_NAME \
   --name $snapshot_file \
   --file $snapshot_file

rm -f $snapshot_file

echo "Backup $snapshot_file uploaded successfully!"
```

上述脚本自动化了我们在前几节中提供的步骤。这里的想法是，使用环境变量、证书和密钥注入的所有配置和凭据，用于访问 etcd 集群的主机卷必须挂载到指定位置：`/etc/kubernetes/certs/`。对于 AKS Engine 主节点，此映射将是一对一的。

1.  使用包含您的 Docker ID 的标签构建图像 - 我们将使用`packtpubkubernetesonwindows/aks-engine-etcd-snapshot-azure-blob-job`：

```
docker build -t <dockerId>/aks-engine-etcd-snapshot-azure-blob-job .
```

1.  使用版本`1.0.0`标记图像并将图像与所有标记一起推送到 Docker Hub：

```
docker tag <dockerId>/aks-engine-etcd-snapshot-azure-blob-job:latest <dockerId>/aks-engine-etcd-snapshot-azure-blob-job:1.0.0
docker push <dockerId>/aks-engine-etcd-snapshot-azure-blob-job
```

1.  您可以选择在开发环境中直接在 AKS Engine 主节点上运行 Docker 镜像进行测试。SSH 到节点并执行以下命令：

```
docker run \
 -v /etc/kubernetes/certs:/etc/kubernetes/certs \
 -e SNAPSHOT_ETCD_ENDPOINTS=https://10.255.255.5:2379,https://10.255.255.6:2379,https://10.255.255.7:2379 \
 -e SNAPSHOT_AZURE_PRINCIPAL_APPID=1775963c-8414-434d-839c-db5d417c4293 \
 -e SNAPSHOT_AZURE_PRINCIPAL_PASSWORD=276952a9-fa51-44ef-b6c6-905e322dbaed \
 -e SNAPSHOT_AZURE_PRINCIPAL_TENANT=86be0945-a0f3-44c2-8868-9b6aa96b0b62 \
 -e SNAPSHOT_AZURE_ACCOUNT_NAME=aksenginebackups \
 -e SNAPSHOT_AZURE_ACCOUNT_KEY="<storageAccountKey>" \
 -e SNAPSHOT_AZURE_CONTAINER_NAME=<dnsPrefix> \
 packtpubkubernetesonwindows/aks-engine-etcd-snapshot-azure-blob-job:1.0.0
```

过一段时间后，作业将结束，并且快照将上传到我们之前创建的容器中。

有了 Docker 镜像准备好后，我们可以创建一个专用的 Kubernetes **CronJob**来定期运行此操作。请注意，我们为此工作提供了一个最小的设置；您应该考虑在生产环境中使用专用的服务帐户并设置 RBAC。还建议使用 Helm 图表有效地管理此作业。要创建 CronJob，请按照以下步骤进行：

1.  定义一个*本地*文件`etcd-snapshot-secrets.txt`，该文件将用于为您的 CronJob 定义秘密对象：

```
SNAPSHOT_ETCD_ENDPOINTS=https://10.255.255.5:2379,https://10.255.255.6:2379,https://10.255.255.7:2379
SNAPSHOT_AZURE_PRINCIPAL_APPID=1775963c-8414-434d-839c-db5d417c4293
SNAPSHOT_AZURE_PRINCIPAL_PASSWORD=276952a9-fa51-44ef-b6c6-905e322dbaed
SNAPSHOT_AZURE_PRINCIPAL_TENANT=86be0945-a0f3-44c2-8868-9b6aa96b0b62
SNAPSHOT_AZURE_ACCOUNT_NAME=aksenginebackups
SNAPSHOT_AZURE_ACCOUNT_KEY="<dnsPrefix>"
SNAPSHOT_AZURE_CONTAINER_NAME=<dnsPrefix>
```

1.  使用`etcd-snapshot-secrets.txt`文件创建`etcd-snapshot-azure-blob-job-secrets`秘密对象：

```
kubectl create secret generic `
 -n kube-system `
 etcd-snapshot-azure-blob-job-secrets `
 --from-env-file=etcd-snapshot-secrets.txt
```

1.  现在，为 CronJob 本身创建`etcd-snapshot-cronjob.yaml`清单文件：

```
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: etcd-snapshot-azure-blob-job
  namespace: kube-system
spec:
  schedule: "0 */6 * * *" # (1)
successfulJobsHistoryLimit: 2
  failedJobsHistoryLimit: 2
  jobTemplate:
    spec:
      ttlSecondsAfterFinished: 21600
      activeDeadlineSeconds: 600
      template:
        spec:
          tolerations:
          - key: node-role.kubernetes.io/master  # (2)
 operator: Exists
 effect: NoSchedule
 nodeSelector:
 node-role.kubernetes.io/master: ""
          containers:
          - name: snapshot-worker
            image: packtpubkubernetesonwindows/aks-engine-etcd-snapshot-azure-blob-job:1.0.0  # (3)
            volumeMounts:
            - mountPath: /etc/kubernetes/certs
              name: etcd-certs
            envFrom:
            - secretRef:
                name: etcd-snapshot-azure-blob-job-secrets  # (4)
          volumes:
          - name: etcd-certs
            hostPath:
              path: /etc/kubernetes/certs  # (5)
          restartPolicy: Never
          hostNetwork: true
```

在这个清单文件中，最重要的部分是定义适当的`schedule` **(1)** 的部分。我们使用了`0 */6 * * *` cron 表达式，这将每 6 小时执行一次快照。为了测试目的，您可以将其设置为`* * * * *`，以便将作业安排在*每分钟*执行一次。接下来，我们需要确保 CronJob 的 pod 可以在主节点上调度。我们通过使用`taints`的`tolerations`和`nodeSelector`来实现这一点 **(2)**。这是因为我们需要访问 etcd 证书和密钥，这些必须从主机文件系统中挂载。我们定义 pod 使用我们刚刚创建的`packtpubkubernetesonwindows/aks-engine-etcd-snapshot-azure-blob-job:1.0.0`镜像 **(3)**。为了为容器填充环境变量，我们使用我们的秘密对象`etcd-snapshot-azure-blob-job-secrets`的`secretRef` **(4)**。最后，我们需要将*主机*目录`/etc/kubernetes/certs`挂载到 pod 容器中，以便工作节点可以访问证书和密钥 **(5)**。

1.  使用`kubectl apply -f .\etcd-snapshot-cronjob.yaml`命令应用清单文件。

1.  等待第一次作业执行：

```
PS C:\src> kubectl get cronjob -n kube-system -w
NAME                           SCHEDULE      SUSPEND   ACTIVE   LAST SCHEDULE   AGE
etcd-snapshot-azure-blob-job   0 */6 * * *   False     0        2m              16m
```

1.  当作业完成时，您可以检查相关 pod 的日志，并在 Azure Portal ([`portal.azure.com/`](https://portal.azure.com/))中验证快照是否已上传到您的 Azure blob 容器：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/88207fd0-d5f1-4773-8ce3-bb97fa40063c.png)

当使用多个 etcd 集群（用于多个 Kubernetes 部署）时，您可以使用*etcd-operator* ([`github.com/coreos/etcd-operator`](https://github.com/coreos/etcd-operator)) 来实现类似的结果。对于像本演示中的小集群，使用这样一个复杂的解决方案是没有意义的。

恭喜！您已成功设置了一个自动化的 CronJob，用于创建 etcd 集群快照并自动将它们上传到 Azure blob 容器。现在，我们将演示如何替换失败的 etcd 成员，以恢复 etcd 集群的全部操作。

# 替换失败的 etcd 集群成员

作为一个高可用的数据库，etcd 可以容忍少数故障，这意味着大多数集群成员仍然可用和健康；但是，最好尽快替换失败的成员，以改善整体集群健康状况并最小化多数故障的风险。在生产环境中，始终建议将集群大小保持在两个以上的成员。为了从少数故障中恢复，您需要执行两个步骤：

1.  从集群中删除失败的成员。

1.  添加一个新的替换成员。如果有多个失败的成员，依次替换它们。

etcd 文档提供了运行时配置更改的用例列表，您可以在[`etcd.io/docs/v3.3.12/op-guide/runtime-configuration/`](https://etcd.io/docs/v3.3.12/op-guide/runtime-configuration/)中查看。

创建新成员的方式取决于失败的具体情况。如果是主机上的磁盘故障或数据损坏，您可以考虑重用相同的主机，但使用*不同*磁盘上的数据目录。在主机完全故障的情况下，您可能需要提供一个新的机器并将其用作新的替换成员。我们将演示在 AKS Engine 中*重用*相同主机并创建具有不同数据目录的成员的情况。这是一个非常特定的用例，但在所有情况下，整体流程都是相同的。

首先，让我们模拟 etcd 集群成员的故障。为此，请按照以下步骤进行：

1.  使用 SSH 连接到 Kubernetes 主节点之一：

```
ssh azureuser@<dnsPrefix>.<azureLocation>.cloudapp.azure.com
```

假设我们连接到具有私有 IP`10.255.255.5`的主节点`0`。

1.  验证集群健康状态：

```
azureuser@k8s-master-50659983-0:~$ sudo etcdctl cluster-health
member b3a6773c0e93604 is healthy: got healthy result from https://10.255.255.5:2379
member 721d9c3882dbe6f7 is healthy: got healthy result from https://10.255.255.7:2379
member 72b3415f69c52b2a is healthy: got healthy result from https://10.255.255.6:2379
cluster is healthy
```

1.  使用以下命令在主节点`0`上停止 etcd 服务。这将模拟集群中成员的故障：

```
sudo service etcd stop
```

1.  再次检查集群健康状况，但这次只提供主节点`1`和主节点`2`的端点，它们正常运行：

```
azureuser@k8s-master-50659983-0:~$ sudo etcdctl --endpoints=https://10.255.255.6:2379,https://10.255.255.7:2379 cluster-health
failed to check the health of member b3a6773c0e93604 on https://10.255.255.5:2379: Get https://10.255.255.5:2379/health: dial tcp 10.255.255.5:2379: connect: connection refused
member b3a6773c0e93604 is unreachable: [https://10.255.255.5:2379] are all unreachable
member 721d9c3882dbe6f7 is healthy: got healthy result from https://10.255.255.7:2379
member 72b3415f69c52b2a is healthy: got healthy result from https://10.255.255.6:2379
cluster is degraded
```

1.  记录失败成员的 ID，在我们的案例中是`b3a6773c0e93604`。

现在，让我们演示如何替换失败的成员。请按照以下步骤进行：

1.  确定失败成员的 ID。我们已经从之前的命令中获得了这些信息，但通常您可以使用`sudo etcdctl --endpoints=https://10.255.255.6:2379,https://10.255.255.7:2379 member list`命令。

1.  通过 SSH 登录到具有失败成员的机器。

1.  使用其 ID 从集群中删除失败的成员：

```
azureuser@k8s-master-50659983-0:~$ sudo etcdctl --endpoints=https://10.255.255.6:2379,https://10.255.255.7:2379 member remove b3a6773c0e93604
Removed member b3a6773c0e93604 from cluster
```

1.  向集群添加一个名为`k8s-master-50659983-0-replace-0`的新成员；您可以使用任何名称，但通常最好遵循一致的约定。在我们的情况下，该成员将具有与以前相同的 IP 地址：

```
azureuser@k8s-master-50659983-0:~$ sudo etcdctl --endpoints=https://10.255.255.6:2379,https://10.255.255.7:2379 member add k8s-master-50659983-0-replace-0 https://10.255.255.5:2380
Added member named k8s-master-50659983-0-replace-0 with ID af466a622a247b09 to cluster
```

1.  现在，您需要修改 etcd 服务启动参数，以反映此机器上成员的更改。使用文本编辑器（例如`vim`）以 root 身份打开`/etc/default/etcd`。

1.  将`--name`参数修改为`k8s-master-50659983-0-replace-0`。

1.  将`--initial-cluster`参数修改为`k8s-master-50659983-2=https://10.255.255.7:2380,k8s-master-50659983-1=https://10.255.255.6:2380,k8s-master-50659983-0-replace-0=https://10.255.255.5:2380`。

1.  将`--initial-cluster-state`参数修改为`existing`。

1.  最后，修改数据目录参数`--data-dir`为另一个目录，例如`/var/lib/etcddisk-replace-0`。

1.  保存文件。

1.  创建数据目录，确保其归`etcd`所有：

```
sudo mkdir /var/lib/etcddisk-replace-0
sudo chown etcd /var/lib/etcddisk-replace-0
sudo chgrp etcd /var/lib/etcddisk-replace-0
```

1.  启动 etcd 服务：

```
sudo service etcd start
```

1.  过一段时间后，检查集群健康状态：

```
azureuser@k8s-master-50659983-0:~$ sudo etcdctl --endpoints=https://10.255.255.6:2379,https://10.255.255.7:2379 cluster-health
member 1f5a8b7d5b2a5b68 is healthy: got healthy result from https://10.255.255.5:2379
member 721d9c3882dbe6f7 is healthy: got healthy result from https://10.255.255.7:2379
member 72b3415f69c52b2a is healthy: got healthy result from https://10.255.255.6:2379
cluster is healthy
```

成功！新成员是`健康的`，集群的整体状态也是`健康的`！

如果您需要使用具有*不同*IP 地址的新机器作为 etcd 替换成员，请记得为 Kubernetes API 服务器更改`--etcd-servers`参数，并且如果您在 etcd 前面使用负载均衡器，请不要忘记更新负载均衡器配置。

恭喜！您已成功替换了 etcd 集群中的一个失败成员。即使新成员托管在同一台虚拟机上，它也具有一个新的 ID（`1f5a8b7d5b2a5b68`），并且在集群中被视为一个全新的成员。

# 总结

在本章中，您已经了解了为准备 Kubernetes DR 时应牢记的关键要点。您已经了解了整个 Kubernetes 集群中的有状态组件，以及它们需要使用 etcd 集群和持久卷进行备份和恢复策略的事实。接下来，您将学习如何手动为 Kubernetes etcd 集群执行快照，并将其上传到 Azure blob 容器。然后，我们使用此快照将 Kubernetes 集群恢复到先前的状态，并验证了恢复成功。除此之外，您利用了所有新知识，以创建一个用于创建 etcd 快照（用于 AKS Engine）并将其上传到 Azure blob 容器的 Docker 镜像的快照工作者。我们使用此 Docker 镜像创建了一个 Kubernetes CronJob 来执行备份，每 6 小时执行一次。我们最后讨论的主题是如何替换 AKS Engine 中失败的 etcd 成员。有了这些知识，您应该能够为 Kubernetes 集群创建可靠的灾难恢复计划。

本书的最后一章将重点讨论运行 Kubernetes 的生产考虑。您可以将本章视为一组松散耦合的建议和不同生产场景的最佳实践。

# 问题

1.  灾难恢复（DC）和业务连续性（BC）之间有什么区别，它们之间的关系是什么？

1.  在 Kubernetes 中需要备份哪些组件，以确保能够恢复集群状态的可能性？

1.  什么是 etcd 快照？

1.  Velero 和 etcd-operators 是什么，它们的用例是什么？

1.  恢复 etcd 快照的高级步骤是什么？

1.  Kubernetes CronJob 是什么，您如何使用它来自动化 etcd 集群的备份策略？

1.  替换失败的 etcd 集群成员的高级步骤是什么？

您可以在本书的*评估*中找到这些问题的答案。

# 进一步阅读

+   有关 Kubernetes 功能和灾难恢复的更多信息，请参考以下 Packt 图书：

+   *完整的 Kubernetes 指南* ([`www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide`](https://www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide))。

+   *开始使用 Kubernetes-第三版* ([`www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition`](https://www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition))。

+   *面向开发人员的 Kubernetes* ([`www.packtpub.com/virtualization-and-cloud/kubernetes-developers`](https://www.packtpub.com/virtualization-and-cloud/kubernetes-developers)).

+   如果您对 etcd 本身的细节以及如何处理灾难恢复感兴趣，可以参考官方文档[`etcd.io/docs/v3.4.0/op-guide/recovery/`](https://etcd.io/docs/v3.4.0/op-guide/recovery/)。

+   此外，我们建议观看**Cloud Native Computing Foundation** (**CNCF**)关于使用 Velero 的 Kubernetes 备份策略以及在生产环境中操作 etcd 的优秀网络研讨会：

+   [`www.cncf.io/webinars/kubernetes-backup-and-migration-strategies-using-project-velero/`](https://www.cncf.io/webinars/kubernetes-backup-and-migration-strategies-using-project-velero/)

+   [`www.cncf.io/webinars/kubernetes-in-production-operating-etcd-with-etcdadm/`](https://www.cncf.io/webinars/kubernetes-in-production-operating-etcd-with-etcdadm/)


# 第十六章：运行 Kubernetes 的生产考虑

您已经到达本书的最后一章了——干得好！在这一简短的章节中，我们将为您提供运行 Kubernetes 在生产环境中的各种最佳实践和建议。对于每种软件工程方法或工具，总是有两个世界——您如何在开发中使用它以及您如何在生产中使用它。对于 Kubernetes 来说，在生产中运行需要更多的运维开销，因为您希望以高可用性和可靠性运行您的工作负载，通常规模较大。您必须考虑如何对集群本身进行升级，以及如何对底层操作系统进行补丁，确保业务的连续性。如果您在企业数据中心的隔离网络中运行 Kubernetes，您可能需要在 Docker 和 Kubernetes 的所有组件中进行网络代理配置。

此外，确保使用“基础设施即代码”和“不可变基础设施”方法可再生地配置您的集群非常重要。但这还不是全部——您肯定希望以声明方式管理您的集群工作负载（类似于您的基础设施），为此，您可以采用 GitOps 方法。我们在本章描述的所有概念也可以应用于仅 Linux 集群和混合 Windows/Linux 集群。

本书的最后一章将涵盖以下主题：

+   可再生地配置集群

+   Kubeadm 的限制

+   升级集群

+   操作系统补丁

+   为 Docker 守护程序和 Kubernetes 配置网络代理

# 技术要求

对于本章，您将需要以下内容：

+   已安装 Windows 10 专业版、企业版或教育版（1903 版或更高版本，64 位）

+   Azure 帐户

+   已安装 Helm

+   使用 AKS Engine 或本地集群部署的 Windows/Linux Kubernetes 集群

要跟着做，您需要自己的 Azure 帐户来为 Kubernetes 集群创建 Azure 资源。如果您还没有为之前的章节创建帐户，您可以在这里阅读更多关于如何获得个人使用的有限免费帐户：[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)。

使用 AKS Engine 部署 Kubernetes 集群已在第八章中介绍过，*部署混合 Azure Kubernetes 服务引擎集群*。

您可以从官方 GitHub 存储库下载本章的最新代码示例：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter16`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter16)。

# 可重现地配置集群

首先，让我们看看您如何处理配置您的集群和基础设施以及如何在**持续集成**或**持续部署**（**CI/CD**）管道中作为一部分声明性地管理您的应用程序工作负载。在所有情况下，设置任何*基础设施即代码*方法都比仅使用基础设施更加困难和复杂，但最终会有很大的回报。您可以获得配置一致性，在引入复杂更改时的简单性，可测试/可分析的基础设施更改以及开发工作流程的任何阶段的可重现环境。

# 用于集群的基础设施即代码

**基础设施即代码**（**IaC**）简而言之，是仅使用声明性配置文件管理整个 IT 基础设施的概念。这意味着您的基础设施状态被捕获在配置文件中，并且使用专用工具应用环境更改，而不是使用脚本或交互式工具进行物理硬件配置。对于 Azure，您可以使用**Azure 资源管理器**（**ARM**）模板（[`docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-authoring-templates`](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-authoring-templates)）来描述您的基础设施，或者使用通用的 IaC 工具，如 Terraform（[`www.terraform.io/`](https://www.terraform.io/)）。实际上，在部署 AKS Engine 集群时，您已间接使用了 ARM 模板，您可以将 AKS Engine 工具视为创建复杂 ARM 模板的另一层抽象。

您甚至可以进一步采用 IaC 方法：**不可变基础设施**（**IM**）。在 IM 的情况下，部署后从不修改任何机器上的任何配置。如果需要进行修复，您必须使用修复的基础镜像构建新的机器，并取消配置旧的机器。这听起来可能很极端，但在虚拟机世界和裸机环境中都可以轻松实现。

Packer ([`www.packer.io/`](https://www.packer.io/)) 是帮助您引入这种虚拟和裸机机器范式的最佳工具之一。但是如果您仔细考虑一下，我们在本书中已经大量使用了 IaC 和 IM，但是在不同的、更高的级别上。

Docker 本身就是*不可变基础设施*的体现，您可以将软件作为不可变的操作系统容器映像进行传送，就像它们是 VM 映像一样。Kubernetes 可以被视为管理您的应用程序工作负载的不可变容器基础设施的平台——每当您创建一个新的 Docker 映像并部署新版本的部署时，您只是在创建新的容器并丢弃旧的容器。如果您使用声明性方法来管理您的 Kubernetes 对象（至少使用`kubectl apply -f`），您最终会得到整洁的*基础设施即代码*。

这篇长篇介绍向我们展示了一些可以被视为为 Kubernetes 提供基础设施和部署集群的建议，从最低到最高级别：

+   始终使用*基础设施即代码*或*不可变基础设施*方法为集群提供底层基础设施，使用适合工作的正确工具。Terraform 或 ARM 模板在这两种情况下都非常适合这项任务。AKS Engine ([`github.com/Azure/aks-engine`](https://github.com/Azure/aks-engine)) 是建立在 ARM 模板之上的*不可变基础设施*工具的完美示例。如果您想为集群节点部署新版本的 VM 映像，您需要创建一个新的节点池并使用新映像，然后停用旧的节点池。避免使用最初并非用于此目的的工具，比如 Ansible。

+   在您的基础设施上创建 Kubernetes 集群本身时，请使用“基础设施即代码”概念。诸如 Ansible（[`www.ansible.com/`](https://www.ansible.com/)）、Powershell Desired State Configuration（[`docs.microsoft.com/en-us/powershell/scripting/dsc/overview/overview?view=powershell-6`](https://docs.microsoft.com/en-us/powershell/scripting/dsc/overview/overview?view=powershell-6)）或专用的 kubespray（[`github.com/kubernetes-sigs/kubespray`](https://github.com/kubernetes-sigs/kubespray)）等工具非常适合这项任务。AKS Engine 将基础设施的提供和集群部署完美地结合在一个工具中。如果您需要托管的 Kubernetes 服务，那么再次使用 Terraform 或 ARM 模板。但是不要将它们用于自管理集群来提供软件，即使它们有能力这样做，它们最初也不是为此而设计的。

+   使用 Docker 和 Kubernetes 集群作为应用工作负载的“不可变基础设施”平台。使用专用的声明性工具来管理这个平台，比如 Kustomize（[`kustomize.io/`](https://kustomize.io/)）或 Helm（[`helm.sh/`](https://helm.sh/)）。将 Helm chart 管理提升到一个更高的、也是声明性的水平——使用 Helmfile（[`github.com/roboll/helmfile`](https://github.com/roboll/helmfile)）或 Flux（[`github.com/fluxcd/flux`](https://github.com/fluxcd/flux)）。您将不必再担心运行`helm upgrade`命令！但是再次强调，不要使用那些本来不是为此而设计的工具，比如 Ansible 或 Terraform，即使它们有被宣传为能够管理 Kubernetes 对象或 Helm Charts 的模块或提供者。您会冒着绑定到一个不具备所有 Kubernetes 功能并很快过时的自定义 API 的风险。

如果您想以声明性方式管理多个 Kubernetes 集群，一定要密切关注目前处于 alpha 状态的 Kubernetes Cluster API（[`cluster-api.sigs.k8s.io/introduction.html`](https://cluster-api.sigs.k8s.io/introduction.html)）。这个 Kubernetes 项目将允许您创建一个特殊的 Kubernetes 管理集群，在那里您可以操作集群或机器作为 Kubernetes 自定义资源。

总之，始终使用正确的工具来完成工作！这就是为什么我们现在将看一看 Flux 和 GitOps 方法。

# 应用工作负载的 GitOps

Flux ([`github.com/fluxcd/flux`](https://github.com/fluxcd/flux)) 是一个工具，它可以自动确保 Kubernetes 集群的状态与 Git 中的配置（清单和 Helm 图表）匹配。这种方法符合 GitOps 的理念，GitOps 是一种由 Weaveworks 提出的管理 Kubernetes 集群和应用程序的方式，其中 Git 仓库是声明性基础设施和应用工作负载的唯一真相来源。这种方法完全符合“基础设施即代码”的范式。此外，你可以很好地分离关注点：开发人员对集群状态或应用程序配置进行更改，这些更改存储在 Git 仓库中（通过完整的 CI 流水线），专用的 GitOps 组件负责将配置应用到 Kubernetes 集群。你可以得到清晰的边界，并且始终可以确保仓库中的内容反映了实际的集群状态。

让我们看看如何使用 Flux 来管理运行我们在本书中实施的投票应用程序的集群。为此，您需要一个 AKS Engine 集群，该集群具有能够处理每个节点超过 4 个卷挂载的 Linux 节点 - 您可以使用以下集群 ApiModel：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter16/01_aks-engine-flux/kubernetes-windows-template.json`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter16/01_aks-engine-flux/kubernetes-windows-template.json)。

Flux 中对 Helm 3 的支持目前处于开发状态。您可以在这里跟踪进展：[`github.com/fluxcd/helm-operator/issues/8`](https://github.com/fluxcd/helm-operator/issues/8)。因此，出于这个原因，我们需要为 Flux 组件使用自定义镜像，但在您阅读本文时，支持可能已经处于稳定状态。

首先，让我们创建我们的仓库，作为 Kubernetes 集群的真相来源。请按照以下步骤操作：

1.  创建一个新的 GitHub 仓库。我们将使用 [`github.com/hands-on-kubernetes-on-windows/voting-application-flux`](https://github.com/hands-on-kubernetes-on-windows/voting-application-flux) 进行演示。

1.  在`charts/voting-application`目录中，放置投票应用 Helm 图表。您可以在这里找到最新的版本（在此版本的 Flux 中，`post-install`钩子和等待功能不正确工作，需要进行小的变通）：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter16/02_voting-application-flux/charts/voting-application`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter16/02_voting-application-flux/charts/voting-application)。

1.  在`namespaces`目录中，创建带有命名空间定义的`demo.yaml`文件：

```
apiVersion: v1
kind: Namespace
metadata:
  labels:
    name: demo
  name: demo
```

1.  在`storageclasses`目录中，创建带有`StorageClass`定义的`azure-disk.yaml`文件：

```
kind: StorageClass
apiVersion: storage.k8s.io/v1beta1
metadata:
  name: azure-disk
provisioner: kubernetes.io/azure-disk
parameters:
  storageaccounttype: Standard_LRS
  kind: Managed
```

1.  在`releases`目录中，创建`voting-application.yaml`文件，其中包含我们投票应用的`HelmRelease`自定义资源。这个自定义资源由 Flux Helm Operator 处理：

```
apiVersion: helm.fluxcd.io/v1 
kind: HelmRelease
metadata:
  name: voting-application
  namespace: demo
  annotations:
    fluxcd.io/automated: "true"
spec:
  releaseName: voting-application
  helmVersion: v3
  timeout: 1200
  wait: false
  rollback:
    enable: false
  chart:
    git: ssh://git@github.com/hands-on-kubernetes-on-windows/voting-application-flux
    ref: master
    path: charts/voting-application
```

1.  将更改推送到您的 GitHub 存储库。

Flux 不遵循任何目录约定——如何定义结构取决于您。它所做的就是在存储库中搜索 YAML 文件。

我们已经定义了我们的存储库的真实来源。现在，让我们将 Flux 部署到我们的集群中，它能够处理 Helm 3 图表。执行以下步骤（或者您可以使用 PowerShell 脚本：([`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter16/03_DeployFlux.ps1`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter16/03_DeployFlux.ps1)：

1.  以管理员身份打开一个新的 PowerShell 窗口。

1.  使用 Chocolatey 安装`fluxctl`：

```
choco install fluxctl
```

1.  为 Flux 组件创建一个专用的`fluxcd`命名空间：

```
kubectl create namespace fluxcd
```

1.  添加 Flux Helm 存储库：

```
helm repo add fluxcd https://charts.fluxcd.io
```

1.  安装 Flux Helm 图表。您需要确保所有组件的`nodeSelector`设置为在 Linux 节点上运行。将`git.url`值设置为您的 GitHub 存储库：

```
helm upgrade -i flux fluxcd/flux `
 --namespace fluxcd `
 --set "nodeSelector.`"kubernetes\.io/os`"=linux" `
 --set "memcached.nodeSelector.`"kubernetes\.io/os`"=linux" `
 --set "helmOperator.nodeSelector.`"kubernetes\.io/os`"=linux" `
 --set git.url=git@github.com:hands-on-kubernetes-on-windows/voting-application-flux `
 --debug
```

1.  应用 HelmRelease 自定义资源定义的官方清单（这里我们使用来自`helm-v3-dev`分支的开发清单）：

```
kubectl apply -f https://raw.githubusercontent.com/fluxcd/helm-operator/helm-v3-dev/deploy/flux-helm-release-crd.yaml
```

1.  安装 Flux Helm 操作员的 Helm 图表。这是来自开发分支的操作员版本，支持 Helm 3。记得确保 Linux 的`nodeSelector`：

```
helm upgrade -i helm-operator fluxcd/helm-operator `
 --namespace fluxcd `
 --set git.ssh.secretName=flux-git-deploy `
 --set configureRepositories.enable=true `
 --set configureRepositories.repositories[0].name=stable `
 --set configureRepositories.repositories[0].url=https://kubernetes-charts.storage.googleapis.com `
 --set extraEnvs[0].name=HELM_VERSION `
 --set extraEnvs[0].value=v3 `
 --set image.repository=docker.io/fluxcd/helm-operator-prerelease `
 --set image.tag=helm-v3-dev-ca9c8ba0 `
 --set "nodeSelector.`"kubernetes\.io/os`"=linux" 
```

1.  使用`fluxctl`检索必须添加为部署密钥的公共 SSH 密钥：

```
fluxctl identity --k8s-fwd-ns fluxcd
```

1.  复制密钥并在 Web 浏览器中打开您的 GitHub 存储库。

1.  转到设置和部署密钥。

1.  添加具有写访问权限的密钥。

1.  现在，您可以等待一小段时间，直到 Flux 自动同步存储库，或使用此命令强制同步：

```
fluxctl sync --k8s-fwd-ns fluxcd
```

1.  观察使用`kubectl get all -n demo`命令创建组件。您还可以使用`kubectl logs`命令跟踪 Helm 操作员日志，特别是在安装 Helm 发布过程中出现任何问题时：

```
PS C:\src> kubectl get all -n demo
NAME                                                  READY   STATUS    RESTARTS   AGE
pod/voting-application-5cb4987765-7ht4x               0/1     Running   1          2m
pod/voting-application-5cb4987765-dstml               0/1     Running   1          2m
...
```

在前面的步骤中，我们使用了命令式命令，就像 Flux 的官方指南中一样。当然，您也可以使用声明性清单和带有 Helm 发布值的 YAML 文件。

正如您所看到的，整个过程是完全自动的。您在 Git 存储库中定义状态，Flux 会自动处理将更改应用于集群。现在，让我们测试一下在集群状态中推出更改的工作原理。例如，我们将更改我们在 Voting Application 中使用的图像标记，就好像我们正在推出应用程序的新版本一样：

1.  在您的集群状态存储库中，开始编辑`charts/voting-application/Chart.yaml`。

1.  将`version`更改为`0.4.1`以指示图表版本本身已更改。

1.  将`appVersion`更改为不同的 Voting Application 图像标记。例如，我们可以使用`1.5.0`中的一个先前版本。

1.  保存更改，提交到存储库，并推送到 GitHub。

1.  等待更改自动同步或使用`fluxctl sync --k8s-fwd-ns fluxcd`命令强制同步。

1.  执行`kubectl get pods -n demo`命令以查看资源是否正在重新创建：

```
PS C:\src> kubectl get pods -n demo
NAME                                              READY   STATUS              RESTARTS   AGE
voting-application-55fb99587d-rjvmq               0/1     Running             0          16s
voting-application-55fb99587d-whrwv               1/1     Running             0          79s
voting-application-55fb99587d-x9j8q               0/1     ContainerCreating   0          79s
voting-application-5cb4987765-g2lx8               1/1     Terminating         0          21m
```

1.  描述其中一个新的 pod 以验证它是否使用了所需的 Docker 图像标记创建：

```
PS C:\src> kubectl describe pod -n demo voting-application-55fb99587d-rjvmq
...
Containers:
 voting-application-frontend:
 Container ID: docker://61e207885bcfc3bde670702e342345127dcf0d6e782609bc68127078fc007034
 Image: packtpubkubernetesonwindows/voting-application:1.6.0
```

恭喜！您已成功使用 Flux 设置了 GitOps 管道。在生产环境中，您可以通过向您的 Git 存储库添加与 CI/CD 组件集成来轻松扩展管道，例如，在将每个拉取请求合并到集群状态存储库之前进行验证。您可以在以下文章中了解更复杂的管道：[`www.weave.works/blog/what-is-gitops-really`](https://www.weave.works/blog/what-is-gitops-really)。

在下一节中，我们将看一下 kubeadm 在生产用例中的限制。

# Kubeadm 限制

Kubeadm（[`github.com/kubernetes/kubeadm`](https://github.com/kubernetes/kubeadm)）是一个命令行工具，用于提供 Kubernetes 集群，专注于以用户友好的方式执行必要的操作，使得最小可行的安全集群能够运行起来——我们在第四章《Kubernetes 概念和 Windows 支持》中介绍了这个工具，并在第七章《部署混合本地 Kubernetes 集群》中使用了它。这个工具仅限于特定的机器和 Kubernetes API 通信，因此，它通常被设计为其他管理整个集群的自动化工具的构建块。你会发现，诸如 kubespray 之类的其他复杂自动化工具是建立在 kubeadm 之上的。

从 Kubernetes 1.13 开始，kubeadm 被认为是稳定的，并且可以用于生产环境。但即使当前的核心功能集是稳定的，你也应该考虑一些限制，这些限制可能使 kubeadm 不适合你的生产 Kubernetes 部署：

+   kubeadm 对 Windows 节点仅有初始支持，并且关于此支持的 API 可能会发生变化。这使得混合集群的生产部署变得困难——目前唯一的选择是在 Windows 节点上手动配置 Kubernetes 组件，并将它们加入到现有的 Linux 集群中。当然，如果你在 Azure 上运行，你可以使用 AKS 或 AKS Engine 在生产环境中运行 Windows 容器工作负载。

+   使用 kubeadm 现在可以实现高可用的 Kubernetes 集群设置（具有堆叠和内部 etcd 拓扑），但仍然相对复杂。你可以在官方文档中阅读更多信息：[`kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/`](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/)。此外，目前没有简单的方法使用 kubeadm 之后管理 etcd 集群，这意味着诸如 kubespray 之类的解决方案提供了更多的灵活性。但当然，这是以目前不支持 Windows 为代价的。

+   kubeadm 不能用于加入新节点到已经在没有 kubeadm 的情况下引导的现有集群中。

总的来说，对于混合 Windows/Linux Kubernetes 集群，如果不能使用 AKS 或 AKS Engine，那么没有完美的方式来提供生产就绪的集群。使用 kubeadm 仍然是设置这种集群的唯一半自动化方式。

现在，让我们看看如何将您的 Kubernetes 集群升级到更新的版本。

# 升级集群

在生产环境中运行 Kubernetes 集群肯定需要在某个时候将 Kubernetes 组件升级到更新的版本。您执行升级的方式取决于您用于引导和管理集群的工具。但总的来说，高层次的过程如下：

1.  升级主节点上运行的组件。

1.  升级额外的主节点上运行的组件。

1.  升级工作节点。

有一个重要的规则，您必须遵循以确保安全升级：您只能一次升级集群一个次要版本。这意味着，例如，版本为 1.16 的集群只能升级到 1.17，您不能直接跳到 1.18。这是因为 Kubernetes 主组件的版本差异策略，最多只允许运行一个次要版本的差异。Kubernetes 次要版本发布的预期节奏是三个月一次，这意味着您可能需要经常运行升级过程，特别是考虑到每个次要版本将维护大约九个月。您可以在官方文档中阅读所有组件的政策：[`kubernetes.io/docs/setup/release/version-skew-policy/`](https://kubernetes.io/docs/setup/release/version-skew-policy/)。

根据集群的引导方式，确切的升级步骤会有所不同。例如，对于 kubeadm 集群，升级将在同一台机器上进行。但是，如果您使用的是 AKS 或 AKS Engine，该过程将符合*不可变基础设施*范式：主节点和工作节点将依次替换为运行较新版本 Kubernetes 组件的虚拟机。更详细地说，对于主节点，自动升级过程如下：

1.  将节点标记为不可调度，并排空现有的 Pod。

1.  删除物理虚拟机。现在，控制平面的大小为`N-1`个节点。

1.  创建一个新的虚拟机，安装新版本的 Kubernetes 组件。

1.  将新的虚拟机添加到集群，并应用任何现有的标签、注释或节点污点。现在，数据平面的大小再次为`N`。

对于工作节点，该过程类似，并包括以下步骤：

1.  创建一个新的虚拟机，安装新版本的 Kubernetes 组件。

1.  将新的 VM 添加到集群中。现在，数据平面的大小为 `M+1`。

1.  如果已经有任何 pod 被调度到新节点上，请将它们驱逐出去。

1.  将任何现有的标签、注释或污点应用到新节点上。

1.  `Cordon` 旧节点并排空现有的 pod。

1.  删除旧的 VM。现在，数据平面的大小再次为 `M`。

将工作节点升级为添加额外的节点（而不是首先删除现有节点）的原因是为了确保数据平面工作负载的集群容量不会缩小。这确保了升级对用户来说是完全透明的。您可以在以下链接中阅读有关 AKS 升级程序的更多信息：[`docs.microsoft.com/en-us/azure/aks/upgrade-cluster`](https://docs.microsoft.com/en-us/azure/aks/upgrade-cluster)，以及有关 AKS Engine 的信息：[`github.com/Azure/aks-engine/blob/master/docs/topics/upgrade.md`](https://github.com/Azure/aks-engine/blob/master/docs/topics/upgrade.md)。

您可以使用 AKS 和 AKS Engine 中使用的 *不可变基础设施* 方法进行升级，以执行使用不同工具引导的集群的手动升级，只要工具集允许添加新的主节点和工作节点。

现在让我们执行一个使用 AKS Engine 创建的 Kubernetes 集群（带有 Windows 节点）的升级。在本演示中，我们运行的是一个版本为 1.16.1 的集群，这是我们在之前章节中创建的。您将需要集群 ApiModel，这是您用于初始部署的。要执行升级，请按照以下步骤进行：

1.  打开 PowerShell 窗口。确定可用的 Kubernetes 版本，用于升级带有 Windows 节点的 AKS Engine 集群。运行以下命令：

```
PS C:\src> aks-engine get-versions --version 1.16.1 --windows
Version Upgrades
1.16.1 1.17.0-alpha.1, 1.17.0-alpha.2, 1.17.0-alpha.3, 1.17.0-beta.1
```

1.  让我们将集群升级到最新版本 `1.17.0-beta.1`。如果您没有 AKS Engine 服务主体，您必须生成一个新的，因为不可能检索现有主体的密码。要执行此操作，请使用以下命令：

```
az ad sp create-for-rbac `
 --role="Contributor" `
 --scopes="/subscriptions/<azureSubscriptionId>/resourceGroups/<resourceGroupName>"
```

注意 `appId` 和 `password`，在升级命令中会用到它们。

1.  执行以下命令进行升级。您必须指定生成的集群 ApiModel：

```
aks-engine upgrade `
 --subscription-id <azureSubscriptionId> `
 --api-model .\_output\<dnsPrefix>\apimodel.json `
 --location <azureLocation> `
 --resource-group <resourceGroupName> `
 --upgrade-version "1.17.0-beta.1" `
 --auth-method client_secret `
 --client-id <appId> `
 --client-secret <password>
```

1.  升级可能需要大约 50 分钟（每个节点 10 分钟），具体取决于您的集群大小。如果您的集群中使用单节点控制平面，则在升级期间将无法访问 Kubernetes API 一段时间。升级完成后，运行以下命令验证节点是否运行所需版本的 Kubernetes。

```
PS C:\src> kubectl get nodes
NAME                        STATUS   ROLES    AGE     VERSION
1754k8s010                  Ready    agent    17m     v1.17.0-beta.1
1754k8s012                  Ready    agent    26m     v1.17.0-beta.1
k8s-linuxpool1-17543130-0   Ready    agent    3m44s   v1.17.0-beta.1
k8s-linuxpool1-17543130-2   Ready    agent    9m51s   v1.17.0-beta.1
k8s-master-17543130-0       Ready    master   48m     v1.17.0-beta.1
```

在生产集群中，特别是如果您正在运行带有扩展或专用 VM 镜像的定制集群，则建议在使用完全相同规范创建的单独的分段集群中测试升级。

恭喜，您已成功将 AKS Engine 集群升级到版本`1.17.0-beta.1`。在下一节中，您将学习如何在 Kubernetes 中进行操作系统打补丁。

# OS 打补丁

为了确保集群和基础设施的最佳安全性，您必须确保在节点上运行具有最新补丁的操作系统。幸运的是，Kubernetes 在节点维护方面非常灵活。任何维护的一般方法，包括需要重新启动的 OS 补丁，如下所示：

1.  `Cordon`（标记节点为不可调度）节点并排空现有的 pod。

1.  应用所需的更新并重新启动机器。

1.  `Uncordon`节点以使其再次可调度。

或者，如果您使用*不可变基础设施*方法，则必须通过创建新的打补丁机器并删除旧机器来扩展前面的步骤。例如，在 AKS Engine 中，如果您在节点池中使用自定义 VM 镜像，则此场景可能如下所示：

1.  构建新版本的 VM 镜像。

1.  更新 VMSS 的 VM 镜像（https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-upgrade-scale-set#update-the-os-image-for-your-scale-set），可能直接在 ARM 模板中进行。

1.  对于 VMSS 中的每个 VM，依次执行以下操作：`cordon`和排空节点，将 VM 镜像设置为 VMSS 实例的最新版本，并`uncordon`节点。

如果您有兴趣为 AKS Engine Windows 节点创建自定义 VM 映像，您可以阅读以下构建过程的描述，该过程使用 Packer 和 Azure DevOps：[`github.com/Azure/aks-engine/blob/master/docs/topics/windows-vhd.md`](https://github.com/Azure/aks-engine/blob/master/docs/topics/windows-vhd.md)。

为了维护 Windows 节点的手动程序，请执行以下步骤：

1.  假设我们想要打补丁`1754k8s010` Windows 节点。

1.  使用名称获取`1754k8s010`节点的私有 IP 地址：

```
PS C:\src> az vm show -g <resourceGroupName> -n 1754k8s010 --show-details --query 'privateIps'
"10.240.0.35,10.240.0.36,10.240.0.37,10.240.0.38,10.240.0.39,10.240.0.40,10.240.0.41,10.240.0.42,10.240.0.43,10.240.0.44,10.240.0.45,10.240.0.46,10.240.0.47,10.240.0.48,10.240.0.49,10.240.0.50,10.240.0.51,10.240.0.52,10.240.0.53,10.240.0.54,10.240.0.55,10.240.0.56,10.240.0.57,10.240.0.58,10.240.0.59,10.240.0.60,10.240.0.61,10.240.0.62,10.240.0.63,10.240.0.64,10.240.0.65"
```

1.  使用其中一个私有 IP 从本地`5500`端口通过主节点到 Windows 节点上的端口`3389`（RDP）创建 SSH 隧道：

```
ssh -L 5500:10.240.0.35:3389 azureuser@<dnsPrefix>.<azureLocation>.cloudapp.azure.com
```

1.  在另一个 PowerShell 窗口中，通过隧道启动 RDP 会话：

```
mstsc /v:localhost:5500
```

1.  提供您的 Windows 节点凭据（如 ApiModel）并连接。

1.  等待控制台初始化。

1.  现在，您已经准备好进行维护，但首先，我们需要排空节点（这也会首先使节点`cordons`）。在本地计算机上的新的 PowerShell 窗口中，执行以下命令：

```
PS C:\src> kubectl drain 1754k8s010
node/1754k8s010 cordoned
node/1754k8s010 drained
```

1.  当节点被排空时，您可以开始维护程序。例如，您可以使用控制台中的`sconfig.cmd`实用程序手动应用更新：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/f7f45280-f41d-4029-92d1-c21dc0d7e75d.png)

1.  选择选项`6`并选择要安装的更新：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/85db4f35-ad84-4c6b-a407-d5d69e79f922.png)

1.  等待安装结束并重新启动机器（如果需要）。

1.  当节点完全重新启动后，您可以`uncordon`节点以使其再次可调度：

```
PS C:\src> kubectl uncordon 1754k8s010
node/1754k8s010 uncordoned
```

您的节点现在将在集群中再次完全正常运行。

或者，您可以考虑使用 Azure Update Management 来管理集群中操作系统的更新和打补丁。您可以在官方文档中阅读更多信息：[`docs.microsoft.com/en-us/azure/automation/automation-update-management`](https://docs.microsoft.com/en-us/azure/automation/automation-update-management)。

在最后一节中，我们将展示在 Kubernetes 中哪些组件需要额外配置，如果您的生产集群在 HTTP(S)网络代理后运行。

# 为 Docker 守护程序和 Kubernetes 配置网络代理

在企业环境中，使用 HTTP(S)网络代理连接到外部网络，特别是互联网，是一种常见做法。这需要对所有运行在代理后面的组件进行额外的配置成本-我们将简要概述 Kubernetes 中需要使代理意识到使用外部注册表的 Docker 镜像并将代理设置传播到容器的组件。

假设我们的代理地址如下：

+   `http://proxy.example.com:8080/` 用于 HTTP 代理

+   `http://proxy.example.com:9090/` 用于 HTTPS 代理

其他标准代理的配置，例如 SFTP，可以类似地完成。您可能还需要适当的 no-proxy 变量来排除 Kubernetes 节点和本地网络，否则，您将无法在节点之间通信，或者流量将通过代理额外路由！现在，对于 Linux 节点和主节点（假设是基于 Debian 的发行版，如 Ubuntu），您需要确保配置以下设置：

1.  为默认环境`/etc/environment`定义代理设置。这将使 APT 等工具遵守代理设置：

```
HTTP_PROXY=http://proxy.example.com:8080/
HTTPS_PROXY=http://proxy.example.com:9090/
http_proxy=http://proxy.example.com:8080/
https_proxy=http://proxy.example.com:9090/
```

1.  为 Docker 守护程序环境设置代理。这将确保容器也接收代理变量。您可以使用以下内容定义`/etc/systemd/system/docker.service.d/http-proxy.conf`文件：

```
[Service]
Environment="HTTP_PROXY=http://proxy.example.com:8080/" "HTTPS_PROXY=http://proxy.example.com:9090/" 
```

1.  在代理后面的机器上构建 Docker 镜像时，考虑将代理设置作为参数传递：

```
docker build --build-arg http_proxy=http://proxy.example.com:8080/ \
 --build-arg https_proxy=http://proxy.example.com:9090/ \
 -t someimage .
```

对于 Windows 工作节点，您可以采取以下步骤：

1.  以管理员身份从 PowerShell 定义全局环境变量：

```
[Environment]::SetEnvironmentVariable("HTTP_PROXY", "http://proxy.example.com:8080/", [EnvironmentVariableTarget]::Machine)
[Environment]::SetEnvironmentVariable("HTTPS_PROXY", "http://proxy.example.com:9090/", [EnvironmentVariableTarget]::Machine)
```

1.  另外，确保使用 Web 浏览器引擎的任何流量也遵守代理设置：

```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d proxy.example.com:8080 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f
```

这些配置步骤应该让您拉取 Docker 镜像，引导集群，并在连接到外部网络时使 pod 容器意识到这些设置。

# 总结

在本章中，我们重点介绍了在生产环境中运行 Kubernetes 集群的常见操作最佳实践。首先，我们介绍了为 Kubernetes 提供基础设施和可重复部署集群的方法-我们介绍了*基础设施即代码*和*不可变基础设施*的概念，并展示了它们如何适用于 Kubernetes 领域。此外，我们提供了有关为基础设施和集群部署提供最佳工具的建议。接下来，您将了解 GitOps 是什么，以及如何使用 Flux 和 Git 存储库应用这一理念。我们重点关注了升级和修补底层集群基础设施和 Kubernetes 本身的操作方面。最后，您将学习如何确保您的 Kubernetes 集群可以在企业环境中在 HTTP(S)网络代理后运行。

恭喜！这是一个漫长的旅程，进入（几乎）未知的 Windows Kubernetes 领域-祝您在进一步的 Kubernetes 旅程中好运，并感谢您的阅读。

# 问题

1.  *基础设施即代码*和*不可变基础设施*之间有什么区别？

1.  为什么 Kubernetes 被认为是使用*基础设施即代码*方法的平台？

1.  什么是 GitOps？

1.  在您的 Kubernetes 集群中使用 Flux 的好处是什么？

1.  升级 Kubernetes 集群版本的步骤是什么？

1.  对 Kubernetes 节点执行维护的程序是什么？

您可以在本书的*评估*中找到这些问题的答案。

# 进一步阅读

+   关于 Kubernetes 功能和在生产环境中运行集群的更多信息，请参考以下 Packt 图书：

+   *完整的 Kubernetes 指南*（[`www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide`](https://www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide)）

+   *开始使用 Kubernetes-第三版*（[`www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition`](https://www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition)）

+   如果您有兴趣探索*基础设施即代码*概念，您可以查看以下 Packt 图书：

+   *基础设施即代码（IaC）食谱*（[`www.packtpub.com/virtualization-and-cloud/infrastructure-code-iac-cookbook`](https://www.packtpub.com/virtualization-and-cloud/infrastructure-code-iac-cookbook)）

+   Kubernetes 文档提供了一些更多关于运行集群的最佳实践：[`kubernetes.io/docs/setup/best-practices/`](https://kubernetes.io/docs/setup/best-practices/)。


# 第十七章：评估

# 第一章：创建容器

1.  对象命名空间、进程表、作业对象和 Windows 容器隔离文件系统。此外，在这些低级功能之上，**主机计算服务**（**HCS**）和**主机网络服务**（**HNS**）抽象了运行和管理容器的公共接口。

1.  Windows Server 容器要求主机操作系统版本与容器基础镜像操作系统版本匹配。此外，在 Windows 上，您可以使用 Hyper-V 隔离，这使得可以使用与基础镜像操作系统版本不匹配的容器运行。

1.  在 Hyper-V 隔离中，每个容器都在一个专用的、最小的 Hyper-V 虚拟机中运行。容器不与主机操作系统共享内核；主机操作系统版本与容器基础操作系统版本之间没有兼容性限制。如果需要在非匹配的基础镜像操作系统版本和不受信任的代码执行场景中运行容器，则使用 Hyper-V 隔离。

1.  要在 Docker Desktop（版本 18.02 或更高版本）中启用 LCOW 支持，必须在 Docker 设置|守护程序中启用实验性功能选项。创建一个 LCOW 容器需要为`docker run`命令指定`--platform linux`参数。

1.  `docker logs <containerId>`

1.  对于已安装 Powershell 的 Windows 容器，可以使用以下命令：`docker exec -it <containerId> powershell.exe`。

# 第二章：在容器中管理状态

1.  容器层是每个 Docker 容器文件系统中的可写层的顶层。

1.  绑定挂载提供了一个简单的功能，可以将容器主机中的任何文件或目录挂载到给定的容器中。卷提供了类似的功能，但它们完全由 Docker 管理，因此您不必担心容器主机文件系统中的物理路径。

1.  可写容器层与容器主机耦合在一起，这意味着不可能轻松地将数据移动到不同的主机。层文件系统的性能比直接访问主机文件系统（例如使用卷）差。您不能在不同的容器之间共享可写层。

1.  在 Windows 主机上使用 SMB 全局映射功能，可以将 SMB 共享挂载到容器中可见。然后，您可以将 SMB 共享在容器中作为主机机器上的常规目录挂载。

1.  不行。要持久保存 Hyper-V 容器的存储数据，您必须使用 Docker 卷。如果您需要使用绑定挂载（例如，用于 SMB 全局映射），您必须使用进程隔离。

1.  `docker volume prune`

1.  Docker 中的卷驱动程序可用于管理托管在远程计算机或云服务上的卷。

# 第三章：使用容器映像

1.  Docker 注册表是一个有组织的、分层的系统，用于存储 Docker 映像，提供可伸缩的映像分发。Docker Hub 是由 Docker，Inc.托管和管理的官方公共 Docker 注册表。

1.  标签是存储库中单个图像的版本标签。

1.  `<dockerId>/<repositoryName>:<tag>`

1.  **Azure 容器注册表**（**ACR**）是由 Azure 云提供的完全托管的私有 Docker 注册表。在 ACR 的情况下，您可以使用自己的 Azure 存储帐户存储图像，并且可以使注册表完全私有，以满足您自己的基础设施需求。

1.  `latest`是在拉取或构建图像时使用的默认标签（如果您没有指定显式标签）。一般来说，除了在开发场景中，您不应该使用`latest`标签。在生产环境中，始终为您的 Kubernetes 清单或 Dockerfile 指令指定显式标签。

1.  Semver 建议使用三个数字的以下方案，即主要版本、次要版本和修补版本，用点分隔：`<major>.<minor>.<patch>`，根据需要递增每个数字。

1.  **Docker 内容信任**（**DCT**）提供了一种验证数据数字签名的方法，该数据在 Docker 引擎和 Docker 注册表之间传输。此验证允许发布者对其图像进行签名，并且消费者（Docker 引擎）验证签名以确保图像的完整性和来源。

# 第四章：Kubernetes 概念和 Windows 支持

1.  控制平面（主控）由一组组件组成，负责关于集群的全局决策，例如将应用实例的调度和部署到工作节点以及管理集群事件。数据平面由负责运行主控安排的容器工作负载的工作节点组成。

1.  集群管理使用声明性模型执行，这使得 Kubernetes 非常强大 - 您描述所需的状态，Kubernetes 会完成所有繁重的工作，将集群的当前状态转换为所需的状态。

1.  Kubernetes Pod 由一个或多个共享内核命名空间、IPC、网络堆栈（因此您可以通过相同的集群 IP 地址对其进行寻址，并且它们可以通过本地主机进行通信）和存储的容器组成。换句话说，Pod 可以包含共享某些资源的多个容器。

1.  Deployment API 对象用于声明式管理 ReplicaSet 的部署和扩展。这是确保新版本应用平稳部署的关键 API 对象。

1.  Windows 机器只能作为工作节点加入集群。无法在 Windows 上运行主组件，也没有在混合 Linux/Windows 集群的本地 Kubernetes 开发环境的设置，目前没有标准解决方案，例如 Minikube 或 Docker Desktop for Windows 支持这样的配置。

1.  Minikube 旨在为 Kubernetes 的本地开发提供稳定的环境。它可用于 Windows、Linux 和 macOS，但只能提供 Linux 集群。

1.  **AKS**（**Azure Kubernetes Service**的缩写）是 Azure 提供的完全托管的 Kubernetes 集群。AKS Engine 是 Azure 官方的开源工具，用于在 Azure 上提供自管理的 Kubernetes 集群。在内部，AKS 使用 AKS Engine，但它们不能管理彼此创建的集群。

# 第五章：Kubernetes 网络

1.  运行在节点上的 Pod 必须能够与所有节点上的所有 Pod（包括 Pod 的节点）进行通信，而无需 NAT 和显式端口映射。例如，运行在节点上的所有 Kubernetes 组件，如 kubelet 或系统守护程序/服务，必须能够与该节点上的所有 Pod 进行通信。

1.  您可以在集群节点之间存在二层（L2）连接时，仅使用 host-gw 来使用 Flannel。换句话说，在节点之间不能有任何 L3 路由器。

1.  NodePort 服务是作为 ClusterIP 服务实现的，具有使用任何集群节点 IP 地址和指定端口可达的额外功能。为实现这一点，kube-proxy 在 30000-32767 范围内（可配置）的每个节点上公开相同的端口，并设置转发，以便将对该端口的任何连接转发到 ClusterIP。

1.  降低成本（您只使用一个云负载均衡器来提供传入流量）和 L7 负载均衡功能

1.  容器运行时使用 CNI 插件将容器连接到网络，并在需要时从网络中移除它们。

1.  内部 vSwitch 未连接到容器主机上的网络适配器，而外部 vSwitch 连接并提供与外部网络的连接。

1.  Docker 网络模式（驱动程序）是来自 Docker 的概念，是**容器网络模型**（**CNM**）的一部分。这个规范是 Docker 提出的，旨在以模块化、可插拔的方式解决容器网络设置和管理挑战。CNI 是一个 CNCF 项目，旨在为任何容器运行时和网络实现提供一个简单明了的接口。它们以不同的方式解决了几乎相同的问题。在 Windows 上，Docker 网络模式和 CNI 插件的实现是相同的——它们都是 HNS 的轻量级适配器。

1.  在 Windows 上，覆盖网络模式使用外部 Hyper-V vSwitch 创建一个 VXLAN 覆盖网络。每个覆盖网络都有自己的 IP 子网，由可定制的 IP 前缀确定。

# 第六章：与 Kubernetes 集群交互

1.  kubectl 使用位于`~\.kube\config`的 kubeconfig 文件。这个 YAML 配置文件包含了 kubectl 连接到 Kubernetes API 所需的所有参数。

1.  您可以使用`KUBECONFIG`环境变量或`--kubeconfig`标志来强制 kubectl 在个别命令中使用不同的 kubeconfig。

1.  上下文用于组织和协调对多个 Kubernetes 集群的访问。

1.  `kubectl create`是一个命令，用于创建新的 API 资源，而`kubectl apply`是一个声明性管理命令，用于管理 API 资源。

1.  `kubectl patch`通过合并当前资源状态和仅包含修改属性的补丁来更新资源。补丁的常见用例是在混合 Linux/Windows 集群中需要强制执行现有 DaemonSet 的节点选择器时。

1.  `kubectl logs <podName>`

1.  `kubectl cp <podName>:<sourceRemotePath> <destinationLocalPath>`

# 第七章：部署混合本地 Kubernetes 集群

1.  如果您只计划将集群用于本地开发，请使用内部 NAT Hyper-V vSwitch。任何外部入站通信（除了您的 Hyper-V 主机机器）都需要 NAT。如果您的网络有 DHCP 和 DNS 服务器，您（或网络管理员）可以管理，那么请使用外部 Hyper-V vSwitch。这在大多数生产部署中都是这样的情况。

1.  简而言之，更改操作系统配置，比如禁用交换空间，安装 Docker 容器运行时，安装 Kubernetes 软件包，执行`kubeadm init`。

1.  服务子网是一个虚拟子网（不可路由），用于 Pod 访问服务。虚拟 IP 的可路由地址转换由运行在节点上的 kube-proxy 执行。Pod 子网是集群中所有 Pod 使用的全局子网。

1.  `kubeadm token create --print-join-command`

1.  `kubectl taint nodes --all node-role.kubernetes.io/master-`

1.  Flannel 网络使用 host-gw 后端（在 Windows 节点上使用 win-bridge CNI 插件）：host-gw 后端更可取，因为它处于稳定的功能状态，而 overlay 后端对于 Windows 节点仍处于 alpha 功能状态。

1.  简而言之，下载`sig-windows-tools`脚本，安装 Docker 和 Kubernetes 软件包；为脚本准备 JSON 配置文件；并执行它们。

1.  `kubectl logs <podName>`

# 第八章：部署混合 Azure Kubernetes 服务引擎集群

1.  AKS 是 Azure 提供的一个完全托管的 Kubernetes 集群。AKS Engine 是 Azure 官方的开源工具，用于在 Azure 上为自管理的 Kubernetes 集群进行配置。在内部，AKS 使用 AKS Engine，但它们不能管理彼此创建的集群。

1.  AKS Engine 根据提供的配置文件（集群 apimodel）生成**Azure 资源管理器**（ARM）模板。然后，您可以使用此 ARM 模板在 Azure 基础架构上部署一个完全功能的自管理 Kubernetes 集群。

1.  不可以。即使 AKS 在内部使用 AKS Engine，也不能使用 AKS Engine 来管理 AKS，反之亦然。

1.  Azure CLI，Azure Cloud Shell，kubectl，以及如果您想要使用 SSH 连接到节点，则还需要 Windows 的 SSH 客户端。

1.  AKS Engine 使用 apimodel（或集群定义）JSON 文件生成 ARM 模板，可用于直接部署 Kubernetes 集群到 Azure。

1.  使用 SSH 并执行以下命令：`ssh azureuser@<dnsPrefix>.<azureLocation>.cloudapp.azure.com`。

1.  假设`10.240.0.4`是 Windows 节点的私有 IP，创建一个 SSH 连接到主节点，将 RDP 端口转发到 Windows 节点，使用`ssh -L 5500:10.240.0.4:3389 azureuser@<dnsPrefix>.<azureLocation>.cloudapp.azure.com`命令。在一个新的命令行窗口中，使用`mstsc /v:localhost:5500`命令启动一个 RDP 会话。

# 第九章：部署您的第一个应用程序

1.  命令式方法包括执行命令式的 kubectl 命令，例如`kubectl run`或`kubectl expose`。在声明性方法中，您始终修改对象配置（清单文件），并使用`kubectl apply`命令在集群中创建或更新它们（或者，您可以使用 Kustomization 文件）。

1.  命令式的`kubectl delete`命令优于声明式删除，因为它提供可预测的结果。

1.  `kubectl diff -f <file/directory>`

1.  推荐的做法是使用`nodeSelector`来可预测地调度您的 Pod，无论是 Windows 还是 Linux 容器。

1.  您可以使用`kubectl proxy`访问任何 Service API 对象。`kubectl port-forward`是一个更低级别的命令，您可以使用它来访问单个 Pod 或部署中运行的 Pod 或服务后面的 Pod。

1.  只有当您有能够运行 Ingress Controller Pods 的节点时，才可以使用 Ingress Controller。例如，对于 ingress-nginx，只有 Linux 节点才能部署 Ingress Controller，您将能够为运行在 Windows 节点上的服务创建 Ingress 对象，但所有负载均衡都将在 Linux 节点上执行。

1.  `kubectl scale deployment/<deploymentName> --replicas=<targetNumberOfReplicas>`

# 第十章：部署 Microsoft SQL Server 2019 和 ASP.NET MVC 应用程序

1.  您可以从以下选项中选择：将参数传递给容器命令，为容器定义系统环境变量，将 ConfigMaps 或 Secrets 挂载为容器卷，并可选择使用 PodPresets 将所有内容包装起来。

1.  `LogMonitor.exe`充当应用程序进程的监督者，并将日志打印到标准输出，这些日志是根据配置文件从不同来源收集的。计划进一步扩展此解决方案，以用于侧车容器模式。

1.  您需要确保迁移可以回滚，并且数据库架构与旧版本和新版本的应用程序完全兼容。换句话说，不兼容的更改（例如重命名）必须特别处理，以使各个步骤之间保持向后兼容。

1.  这可以确保在 Pod 终止时数据持久性，并确保 SQL Server 故障转移，即使新的 Pod 被调度到不同的节点上。

1.  您需要使用`ef6.exe`命令来应用迁移。这可以使用 Kubernetes Job 对象执行。

1.  如果您为资源使用低于“限制”值的“请求”值，您可能会进入资源超额分配状态。这使得 Pod 可以临时使用比它们请求的资源更多的资源，并实现了更有效的 Pod 工作负载的装箱。

1.  VS 远程调试器在容器中的`4020` TCP 端口上公开。要连接到它，而不将其公开为服务对象，您需要使用 kubectl 端口转发。

# 第十一章：配置应用程序以使用 Kubernetes 功能

1.  命名空间的一般原则是提供资源配额和对象名称的范围。您将根据集群的大小和团队的大小来组织命名空间。

1.  就绪探针用于确定给定容器是否准备好接受流量。存活探针用于检测容器是否需要重新启动。

1.  这个探针的错误配置可能导致您的服务和容器重新启动循环中的级联故障。

1.  `requests`指定系统提供的给定资源的保证数量。`limits`指定系统提供的给定资源的最大数量。

1.  避免抖动（副本计数频繁波动）。

1.  ConfigMaps 和 Secrets 可以容纳技术上任何类型的由键值对组成的数据。Secrets 的目的是保留访问依赖项的敏感信息，而 ConfigMaps 应该用于一般应用程序配置目的。

1.  `volumeClaimTemplates`用于为此 StatefulSet 中的每个 Pod 副本创建专用的 PersistentVolumeClaim。

1.  为了确保在 Kubernetes 中对部署进行真正的零停机更新，您需要配置适当的探针，特别是就绪探针。这样，用户只有在该副本能够正确响应请求时才会被重定向到副本。

1.  最小权限原则：您的应用程序应仅访问其自己的资源（建议您使用专用服务帐户运行每个应用程序，该帐户可以访问该应用程序的 Secrets 或 ConfigMaps），用户应根据其在项目中的角色拥有受限制的访问权限（例如，QA 工程师可能只需要对集群具有只读访问权限）。

# 第十二章：使用 Kubernetes 进行开发工作流程

1.  Helm 用于为您的 Kubernetes 应用程序创建可再分发的软件包。您可以使用它来部署其他人提供的应用程序，也可以将其用作您自己应用程序的内部软件包和微服务系统的依赖管理器。

1.  Helm 2 需要在 Kubernetes 上部署一个名为 Tiller 的专用服务，它负责与 Kubernetes API 的实际通信。这引起了各种问题，包括安全和 RBAC 问题。从 Helm 3.0.0 开始，不再需要 Tiller，图表管理由客户端完成。

1.  在 Helm 中使用 Kubernetes Job 对象作为安装后钩子。

1.  在 Helm 图表清单或值文件中使用新的 Docker 镜像，并执行 `helm upgrade`。

1.  快照调试器是 Azure 应用程序洞察的一个功能，它监视您的应用程序的异常遥测，包括生产场景。每当出现未处理的异常（顶部抛出），快照调试器都会收集托管内存转储，可以直接在 Azure 门户中进行分析，或者对于更高级的场景，可以使用 Visual Studio 2019 企业版。

1.  您应该更喜欢 Kubernetes 的适当声明式管理。

1.  Azure Dev Spaces 服务为使用 AKS 集群的团队提供了快速迭代的开发体验。

# 第十三章：保护 Kubernetes 集群和应用程序

1.  Kubernetes 本身不提供管理访问集群的普通外部用户的手段。这应该委托给一个可以与 Kubernetes 集成的外部身份验证提供程序，例如，通过认证代理。

1.  为了减少攻击向量，建议的做法是永远不要使用 LoadBalancer 服务公开 Kubernetes 仪表板，并始终使用 kubectl 代理来访问页面。

1.  这将为您的 API 资源和 Secrets 提供额外的安全层，否则它们将以未加密的形式保存在 etcd 中。

1.  不，此功能仅在 Linux 容器中受支持。

1.  NetworkPolicy 对象定义了 Pod 组如何相互通信以及一般网络端点的通信方式 - 将它们视为 OSI 模型第 3 层的网络分割的基本防火墙。要使用网络策略，您需要使用支持网络策略的网络提供程序之一。

1.  在 Windows 上，作为卷挂载到 Pods 的 Kubernetes Secrets 以明文形式写入节点磁盘存储（而不是 RAM）。这是因为 Windows 目前不支持将内存文件系统挂载到 Pod 容器。这可能带来安全风险，并需要额外的操作来保护集群。

1.  当您拥有根权限时，您可以从`/proc/<pid>/environ`枚举出进程的所有环境变量，包括以这种方式注入的 Secrets。对于作为卷挂载的 Secrets，由于使用了`tmpfs`，这是不可能的。

# 第十四章：使用 Prometheus 监控 Kubernetes 应用程序

1.  为您的组件提供可观察性意味着公开有关其内部状态的信息，以便您可以轻松访问数据并推断出组件的实际状态。换句话说，如果某物是可观察的，您就可以理解它。

1.  WMI Exporter 可用于监视 Windows 节点主机操作系统和硬件。要监视 Docker 引擎本身，可以使用引擎公开的实验性指标服务器。

1.  在大规模运行的生产环境中，您可以使用 Prometheus Operator 轻松部署和管理多个不同需求的 Prometheus 集群。

1.  WMI Exporter 和 Docker 引擎指标服务器在每个节点上的专用端口上公开指标。我们需要两个额外的抓取作业来单独处理它们。

1.  将 Telegraf 服务直接托管在您的容器中使用。

1.  为您的应用程序提供额外的仪器和对业务逻辑的洞察。

1.  在您的服务对象清单中，定义一个额外的注释，例如`prometheus.io/secondary-port`。之后，您必须创建一个专用的抓取作业，它将以类似的方式消耗新的注释，就像`prometheus.io/port`一样。

1.  热图是可视化直方图随时间变化的最有效方式，最近 Grafana 已扩展了对 Prometheus 直方图指标的热图本地支持。

# 第十五章：灾难恢复

1.  DR 和 BC 之间的主要区别在于，DR 侧重于在停机后使基础设施恢复运行，而 BC 涵盖了在重大事件期间保持业务场景运行。

1.  `etcd`集群由主节点和持久卷使用。

1.  快照是由 etcd 的 v3 API 提供的备份文件。

1.  Velero 可以执行`etcd`快照，将其管理在外部存储中，并在需要时进行恢复。此外，它还可以用于使用 Restic 集成执行持久卷的备份。Etcd-operator 用于在 Kubernetes 之上提供多个`etcd`集群。您可以轻松管理`etcd`集群并执行备份恢复操作。如果您计划在您的环境中管理多个 Kubernetes 集群，请使用此方法。

1.  访问所有 Kubernetes 主节点，并在所有机器上并行执行相同的步骤：下载目标快照文件，将其恢复到本地目录，停止 Kubernetes 主组件，停止`etcd`服务，停止 kubelet 服务，交换`etcd`数据目录，启动`etcd`服务，最后启动 kubelet 服务。

1.  Kubernetes CronJob 使您能够按固定计划安排 Kubernetes 作业，类似于 Linux 系统中的 cron。

1.  从集群中删除失败的成员，添加新的替代成员，如果有多个失败的成员，则依次替换成员。

# 第十六章：运行 Kubernetes 的生产考虑

1.  在不可变基础设施中，一旦机器被配置，您还不会执行任何修改。如果您需要进行配置更改或热修复，您需要构建新的机器映像并配置新的机器。

1.  Kubernetes 可以被视为管理您的不可变容器基础设施和应用程序工作负载的平台——每当您创建一个新的 Docker 映像并部署新版本时，您只是创建新的容器并丢弃旧的容器。如果您使用声明性方法来管理您的 Kubernetes 对象，您最终会得到整洁的基础设施即代码。

1.  GitOps 是一种由 WeaveWorks 提出的管理 Kubernetes 集群和应用程序的方式，其中 Git 存储库是声明性基础架构和应用程序工作负载的唯一真相来源。这种方法完全符合基础设施即代码范式。

1.  Flux 可以用于轻松实现 GitOps，用于您的 Kubernetes 集群。

1.  升级运行在主主节点上的组件，升级运行在其他主节点上的组件，以及升级工作节点。

1.  将节点标记为不可调度，并排空现有的 Pod，然后应用所需的更新并重新启动机器，然后取消节点标记，使其再次可调度。
