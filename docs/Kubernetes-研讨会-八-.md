# Kubernetes 研讨会（八）

> 原文：[`zh.annas-archive.org/md5/DFC15E6DFB274E63E53841C0858DE863`](https://zh.annas-archive.org/md5/DFC15E6DFB274E63E53841C0858DE863)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十八章： 在没有停机的情况下升级你的集群

概述

在本章中，我们将讨论如何在没有停机的情况下升级你的集群。我们将首先了解保持你的 Kubernetes 集群最新的需求。然后，我们将了解基本的应用部署策略，可以帮助实现 Kubernetes 集群的零停机升级。然后，我们将通过在没有应用停机的情况下对 Kubernetes 集群进行升级来将这些策略付诸实践。

# 介绍

我们在第十一章《构建你自己的 HA 集群》中学习了如何在 AWS 上使用 kops 搭建多节点 Kubernetes 平台。在本章中，你将学习如何将 Kubernetes 平台升级到新版本。我们将通过实际示例为你演示升级 Kubernetes 平台所需的步骤。这些练习还将使你具备维护 Kubernetes 集群所需的技能。

不同的组织以不同的方式设置和维护他们的 Kubernetes 集群。在第十二章《你的应用和 HA》中，你看到了设置集群的多种方式。我们将介绍一个简单的技术来升级你的集群，根据你处理的集群的不同，你需要采取的确切技术和步骤可能会有所不同，尽管我们在这里提到的基本原则和预防措施将适用于你升级集群的方式。

# 升级你的 Kubernetes 集群的需求

建立起你的业务应用并将其推向世界只是游戏的一半。让你的应用能够以安全、可扩展和一致的方式被客户使用是另一半，也是你必须不断努力的一半。为了能够很好地执行这另一半，你需要一个坚固的平台。

在当今竞争激烈的环境中，及时向客户提供最新功能对于让你的业务获得优势至关重要。这个平台不仅必须可靠，还必须提供新的和更新的功能，以满足运行现代应用的需求。Kubernetes 是一个快速发展的平台，非常适合这样一个动态的环境。Kubernetes 的开发和进步速度可以从官方 Kubernetes GitHub 存储库的提交数量中得到证明。让我们来看一下下面的截图：

![图 18.1：2019 年 8 月 25 日至 31 日期间对 Kubernetes 项目的每日提交](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_01.jpg)

图 18.1：2019 年 8 月 25 日至 31 日期间对 Kubernetes 项目的每日提交

橙色条形图代表每周的提交次数，您可以看到平均每周超过 100 次。下面的绿线图显示了 8 月 25 日至 8 月 31 日的提交次数。仅在一个星期的星期二就有超过 50 次提交。

到目前为止，很明显 Kubernetes 正在快速发展，但您可能仍然不确定是否需要更新集群上的 Kubernetes 版本。以下是一些重要原因，说明为什么保持平台更新至关重要：

+   **新功能**：Kubernetes 社区不断添加新功能，以满足现代应用程序的需求。您的软件团队可能会开发一个依赖于较新 Kubernetes 功能的新软件组件。因此，坚持使用较旧版本的 Kubernetes 将阻碍*您*软件的开发。

+   **安全补丁**：Kubernetes 平台中有许多组件在不断变化。不仅需要修补 Kubernetes 二进制文件，还需要修补许多 Linux 功能，如 iptables 和 cgroups。如果 Kubernetes 使用的任何组件存在漏洞，您可能需要修补底层组件，如操作系统本身。以一种一致的方式进行升级对于尽可能保持 Kubernetes 生态系统的安全性非常重要。

例如，在 Kubernetes API 服务器的 1.0–1.12 版本中存在一个漏洞，导致 API 服务器可能因为无效的 YAML 或 JSON 负载而消耗大量资源。您可以在此链接找到有关此漏洞的更多详细信息：[`cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11253`](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11253)

+   **更好地处理现有功能**：Kubernetes 团队不仅添加新功能，还不断改进现有功能以提高稳定性和性能。这些改进可能对您现有的应用程序或自动化脚本有用。因此，从这个角度来看，保持平台更新也是一个好主意。

# Kubernetes 组件 – 复习

到目前为止，您已经了解了 Kubernetes 平台的基本组件。作为一个复习，让我们重新审视一下主要组件：

+   API 服务器负责公开 RESTful Kubernetes API，并且是无状态的。您集群上的所有用户、Kubernetes 主控组件、kubectl 客户端、工作节点，甚至可能是您的应用程序都需要与 API 服务器进行交互。

+   键值存储（etcd 服务器）存储对象并为 API 服务器提供持久后端。

+   调度程序和控制器管理器用于实现集群的状态和存储在 etcd 中的对象。

+   kubelet 是在每个工作节点上运行的程序，类似于代理，按照 Kubernetes 主控组件的指示执行工作。

当我们更新平台时，正如您将在后面的部分中看到的，我们将利用这些组件并将它们作为单独的模块进行升级。

## 警告

Kubernetes 版本标记为 `A.B.C`，遵循语义化版本概念。`A` 是主要版本，`B` 是次要版本，`C` 是补丁发布。根据 Kubernetes 文档，"*在* [*高可用 (HA) 集群*](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/) *中，最新和最旧的 kube-apiserver 实例必须在一个次要版本内。*'

在规划升级时，以下是最安全的方法：

+   始终首先升级到当前次要版本的最新修补版本。例如，如果您使用的是 `1.14.X`，首先升级到 `1.14.X` 发行系列的最新可用版本。这将确保平台已应用了该集群版本的所有可用修复程序。最新的修补程序可能有 bug 修复，这可能为您提供通往下一个次要版本的更顺畅的路径，在我们的示例中将是 `1.15.X`。

+   升级到下一个次要版本。尽量避免跨越多个次要版本，即使可能，因为通常 API 兼容性在一个次要发布版本内。在升级过程中，Kubernetes 平台将同时运行两个不同版本的 API，因为我们一次只升级一个节点。例如，最好从 `1.14` 升级到 `1.15`，而不是升级到 `1.16`。

另一个重要的事情要考虑的是，看看新版本是否需要来自底层 Linux 操作系统的一些更新的库。尽管一般来说，补丁版本不需要任何底层组件的升级，但保持底层操作系统的最新状态也应该是您的首要任务，以为 Kubernetes 平台提供一个安全和一致的环境。

# 升级过程

在这一部分，您将看到升级 Kubernetes 平台所需的步骤。请注意，这里不涵盖升级底层操作系统。为了满足零停机升级的要求，您必须拥有一个具有至少三个主节点和 etcd 服务器的 HA Kubernetes 集群，这样可以实现无摩擦的升级。该过程将使三个节点中的一个脱离集群并进行升级。然后升级后的组件将重新加入集群，然后我们将对第二个节点应用升级过程。由于在任何给定时间，至少有两个服务器保持可用，因此在升级过程中集群将保持可用。

## kops 的一些考虑因素

我们已经在*第十一章*中指导您创建了一个 HA Kubernetes 集群。因此，在本章中，我们将指导您升级相同的集群。

如该章节中所述，部署和管理 Kubernetes 集群有各种方式。我们选择了 kops，它具有用于升级 Kubernetes 组件的内置工具。我们将在本章中利用它们。

kops 的版本设置为与其实现的 Kubernetes 的次要版本类似。例如，kops 版本`1.14.x`实现了 Kubernetes 版本`1.14.x`。有关更多详细信息，请参阅此链接：[`kops.sigs.k8s.io/welcome/releases/`](https://kops.sigs.k8s.io/welcome/releases/)。

注意

在我们在*第十一章*中创建的 HA 集群中，我们部署了三个主节点，这些节点承载了所有 Kubernetes 主平面组件，包括 etcd。

## 升级过程概述

整个升级过程可以用图表总结如下：

![图 18.2：推荐的升级过程](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_02.jpg)

图 18.2：推荐的升级过程

在我们继续实施之前，让我们快速查看每个步骤：

1.  阅读发布说明

这些将指示在升级过程中可能需要的任何特殊注意事项。每个版本的发布说明都可以在 GitHub 的此链接上找到：[`github.com/kubernetes/kubernetes/tree/master/CHANGELOG`](https://github.com/kubernetes/kubernetes/tree/master/CHANGELOG)。

1.  **备份 etcd 数据存储**

正如您之前学到的那样，etcd 存储了集群的整个状态。etcd 的备份可以让您在需要时恢复数据存储的状态。

1.  **备份节点作为可选的故障保护**

如果升级过程不顺利，并且您想要恢复到先前的状态，这可能会派上用场。云供应商（如 AWS、GCP、Azure 等）使您能够对主机进行快照。如果您在私有数据中心运行并为您的机器使用虚拟化技术，您的虚拟化提供商（例如 VMware）可能会提供工具来对节点进行快照。在开始升级 Kubernetes 平台之前，进行快照超出了本书的范围，但尽管如此，这是一个有用的步骤。

1.  如有必要，升级 etcd

用于部署和管理 Kubernetes 集群的工具的更新版本（例如我们的 kops）通常会自动处理这一点。即便如此，这是一个重要的考虑因素，特别是如果您没有使用 kops 等工具。

检查并验证新版本的 Kubernetes 是否需要不同版本的 etcd 存储。这并不总是必要的，但根据您的版本可能需要。例如，Kubernetes 版本`1.13`需要 etcd v3，而较早版本可以使用 etcd v2。

通过阅读发布说明（*步骤 1*）可以确定是否需要升级 etcd。例如，当较早版本的 etcd 在 1.13 版本中被淘汰时，在发布说明中明确提到了这一点：[`github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.13.md#urgent-upgrade-notes`](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.13.md#urgent-upgrade-notes)。

1.  升级主要组件

登录到堡垒主机，并根据期望的 Kubernetes 版本升级 kops 的版本。这个兼容矩阵应该是一个有用的指南：[`kops.sigs.k8s.io/welcome/releases/#compatibility-matrix`](https://kops.sigs.k8s.io/welcome/releases/#compatibility-matrix)。

在第一个主节点上运行升级，验证其是否正确更新，然后对所有其他主节点重复相同的步骤。

1.  升级工作节点组

正如您在*第十一章*，*构建您自己的 HA 集群*中看到的，kops 允许您使用实例组来管理节点，这与 AWS 的自动扩展组相关联。在工作节点的第一个实例组上运行升级。要验证节点是否成功升级，您需要检查节点是否升级到所需版本的 Kubernetes，以及是否在升级后的节点上调度了 pod。对所有其他工作节点的实例组重复相同的步骤。

1.  **验证升级过程是否成功**

检查所有节点是否已升级，并且所有应用程序是否按预期运行。

## 自动化的重要性

从概述中可以看出，升级集群需要几个步骤。考虑到发布和补丁的数量，您可能经常需要这样做。由于该过程有很好的文档记录，强烈建议您考虑使用自动化工具，如 Ansible 或 Puppet，来自动化整个过程。所有前面的步骤都可以完全自动化，您可以重复升级集群的方式。但是，本章不涵盖自动化，因为这超出了本书的范围。

## 备份 etcd 数据存储

etcd 存储整个集群的状态。因此，对 etcd 进行快照可以让我们将整个集群恢复到快照被拍摄时的状态。如果您想将集群恢复到先前的状态，这可能会很有用。

注意

在开始任何练习之前，请确保按照*第十一章*，*构建您自己的 HA 集群*中的说明设置并可用集群，并且您可以通过 SSH 从计算机访问节点。还建议您在开始升级过程之前对节点进行快照。这是特别有益的，因为在本章中，您将对集群进行两次升级-一次在练习期间，一次在活动期间。

现在，在我们进行第一个练习之前，我们需要更多地了解 etcd。它的工作方式是在您的集群中作为一个 pod 在`kube-system`命名空间中运行（正如您在*第二章*，*Kubernetes 概述*中看到的），并公开一个 API，用于向其写入数据。每当 Kubernetes API 服务器想要将任何数据持久化到 etcd 时，它将使用 etcd 的 API 来访问它。

为了备份 etcd，我们还需要访问其 API 并使用内置函数保存快照。为此，我们将使用一个名为`etcdctl`的命令行客户端，它已经存在于 etcd pod 中。对于我们的目的，不需要详细介绍此工具和 etcd API，因此我们不在本书中包含它。您可以在此链接了解更多信息：[`github.com/etcd-io/etcd/tree/master/etcdctl`](https://github.com/etcd-io/etcd/tree/master/etcdctl)。

现在，让我们看看如何在以下练习中使用 etcdctl 来备份 etcd。

## 练习 18.01：对 etcd 数据存储进行快照

在这个练习中，我们将看到如何对 etcd 存储进行快照。如前一节所述，根据您的升级路径，可能不需要手动升级 etcd，但备份 etcd 是必不可少的。对于此操作和所有后续的练习和活动，请使用相同的机器（您的笔记本电脑或台式机），您用来执行*练习 11.01*，*设置我们的 Kubernetes 集群*。

1.  我们已经使用 kops 安装了集群。Kops 使用两个不同的 etcd 集群 - 一个用于 Kubernetes 组件生成的事件，另一个用于其他所有内容。您可以通过发出以下命令来查看这些 pods：

```
kubectl get pods -n kube-system | grep etcd-manager
```

这应该获取 etcd pods 的详细信息。您应该看到类似以下的输出：

![图 18.3：获取 etcd-manager pods 的列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_03.jpg)

图 18.3：获取 etcd-manager pods 的列表

1.  默认情况下，kops 的`etcd-manager`功能每 15 分钟创建一次备份。备份的位置与 kops 工具使用的 S3 存储相同。在*练习 11.01*中，您配置了 S3 存储桶以存储 kops 的状态。让我们查询存储桶，看看那里是否有备份可用：

```
aws s3api list-objects --bucket $BUCKET_NAME | grep backups/etcd/main
```

您应该看到类似这样的响应：

![图 18.4：获取可用备份列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_04.jpg)

图 18.4：获取可用备份列表

您可以看到备份每 15 分钟自动进行，并且备份的时间戳已标记。我们将在下一步中使用在上一张截图中突出显示的最新备份的`Key`。

1.  下一步是从 S3 存储桶获取备份。我们可以使用 AWS CLI 命令来获取我们需要的备份：

```
aws s3api get-object --bucket $BUCKET_NAME --key "myfirstcluster.k8s.local/backups/etcd/main/2020-06-14T02:06:33Z-000001/etcd.backup.gz'  etcd-backup-$(date +%Y-%m-%d_%H:%M:%S_%Z).db
```

请注意，此命令包含存储桶的名称，上一步中文件的`Key`，以及我们在保存文件时要使用的文件名。使用在上一步的输出中获取的`Key`。您应该看到类似于此的响应：

![图 18.5：从我们的 S3 存储桶中保存 etcd 备份](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_05.jpg)

图 18.5：从我们的 S3 存储桶中保存 etcd 备份

请注意，我们使用`date`命令生成文件名。这是系统管理员常用的技术，用于确保不会覆盖任何文件。

请注意

如果您想使用此备份恢复您的 etcd 实例，您可以在此链接找到恢复说明：[`kops.sigs.k8s.io/operations/etcd_backup_restore_encryption/`](https://kops.sigs.k8s.io/operations/etcd_backup_restore_encryption/)。

1.  验证备份文件是否已创建：

```
ls -lrt 
```

您应该看到以下响应：

![图 18.6：确认保存的 etcd 备份](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_06.jpg)

图 18.6：确认保存的 etcd 备份

您应该能够在响应中看到我们创建的快照。

在这个练习中，您已经学会了如何生成 etcd 数据存储的备份。这个备份是 Kubernetes 的状态，不仅在您的升级遇到任何问题时可能有用，而且在任何其他情况下恢复集群也可能有用，比如**灾难恢复**（**DR**）场景。

## 排空节点并使其不可调度

在我们开始升级任何节点（主节点或工作节点）之前，我们需要确保没有任何 pod（包括主要组件的 pod）在此节点上运行。这是准备升级任何节点的重要步骤。此外，该节点需要标记为不可调度。不可调度的节点是调度程序不在此节点调度任何 pod 的标志。

我们可以使用`drain`命令将节点标记为不可调度，并驱逐所有 pod。`drain`命令不会删除任何 DaemonSet pod，除非我们告诉标志这样做。这种行为的原因之一是，DaemonSet pod 不能被调度到任何其他节点上。

请注意，`drain`命令等待优雅终止 pod，并强烈建议在生产环境中等待所有 pod 优雅地终止。让我们在以下练习中看到这一点。

## 练习 18.02：从节点中排空所有的 Pod

在这个练习中，我们将删除在一个节点上运行的所有 pods。一旦所有的 pods 都被移除，我们将把节点改回可调度状态，以便它可以接受新的工作负载。这是当节点已经升级并准备接受新的 pods 时。

1.  获取所有节点的列表：

```
kubectl get nodes
```

您应该看到类似于这样的响应：

![图 18.7：获取节点列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_07.jpg)

图 18.7：获取节点列表

在这个例子中，我们有两个 worker 节点和三个 master 节点。

1.  创建一个名为`upgrade-demo`的新命名空间：

```
kubectl create ns upgrade-demo
```

您应该看到以下响应：

```
namespace/upgrade-demo created
```

1.  运行一堆 pods 来模拟工作负载。创建一个名为`multiple-pods.yaml`的文件，其中包含以下内容：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sleep
spec:
replicas: 4
  selector:
    matchLabels:
      app.kubernetes.io/name: sleep
  template:
    metadata:
      labels:
        app.kubernetes.io/name: sleep
    spec:
      containers:
      - name: sleep
        image: k8s.gcr.io/busybox
        command: [ "/bin/sh', "-c', "while :; do echo 'this is           backend pod'; sleep 5 ; done' ]
        imagePullPolicy: IfNotPresent
```

部署将创建四个 pods 的副本。

1.  现在，使用配置来创建部署：

```
kubectl create -f multiple-pod.yaml -n upgrade-demo
```

您应该看到这个响应：

```
deployment.apps/sleep created
```

1.  验证它们是否在 worker pods 上运行：

```
kubectl get pods -n upgrade-demo -o wide
```

您的输出应该是这样的：

![图 18.8：验证 pods 是否在 worker 节点上运行](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_08.jpg)

图 18.8：验证 pods 是否在 worker 节点上运行

请注意，默认调度程序行为会将 pods 分布在两个 worker 节点之间。

1.  使用`drain`命令从任何节点中驱逐所有的 pods。这个命令也会将节点标记为不可调度：

```
kubectl drain kube-group-1-mdlr --ignore-daemonsets
```

使用您从上一步的输出中获得的节点的名称。注意，我们传递了一个标志来忽略 daemon sets。您应该看到以下响应：

![图 18.9：排水节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_09.jpg)

图 18.9：排水节点

如果我们不设置`--ignore-daemonsets`标志，并且节点上有一些 DaemonSet pods，`drain`将不会在没有这个标志的情况下继续进行。我们建议使用这个标志，因为您的集群可能正在运行一些关键的 pods 作为 DaemonSet - 例如，一个从节点上的所有其他 pods 收集日志并将它们发送到中央日志服务器的 Fluentd pod。您可能希望在最后一刻之前保留这个日志收集 pod 的可用性。

1.  验证所有的 pods 是否已经从该节点排空。为此，获取一个列表的 pods：

```
kubectl get pods -n upgrade-demo -o wide
```

您应该看到以下响应：

![图 18.10：检查 pods 是否已经从排空的节点移开](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_10.jpg)

图 18.10：检查 pods 是否已经从排空的节点移开

在前面的截图中，您可以看到所有的 pod 都在另一个节点上运行。我们的集群中只有两个工作节点，所以所有的 pod 都被调度到了唯一可调度的节点上。如果我们有几个可用的工作节点，调度器会将 pod 分布在它们之间。

1.  让我们描述一下我们的排水节点并做一些重要的观察：

```
kubectl describe node kube-group-1-mdlr
```

使用您在*步骤 6*中排水的节点名称。这将产生一个相当长的输出，但有两个值得观察的部分：

![图 18.11：检查我们排水节点的污点和不可调度状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_11.jpg)

图 18.11：检查我们排水节点的污点和不可调度状态

前面的截图显示我们的节点被标记为不可调度。接下来，在您的输出中找到以下类似的部分：

![图 18.12：检查排水节点上的非终止 pod](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_12.jpg)

图 18.12：检查排水节点上的非终止 pod

这表明我们系统上唯一正在运行的非终止 pod 的名称以`kube-proxy`和`weave-net`开头。第一个 pod 实现了`kube-proxy`，它是管理节点上的 pod 和服务网络规则的组件。第二个 pod 是`weave-net`，它为我们的集群实现了虚拟网络（请注意，您的网络提供程序取决于您选择的网络类型）。由于我们在*步骤 6*中添加了一个排除 DaemonSets 的标志，这些由 DaemonSet 管理的 pod 仍在运行。

1.  一旦您在*步骤 6*中排水了 pod，您就可以升级节点。即使升级不是本练习的一部分，我们只是想让节点再次可调度。为此，请使用以下命令：

```
kubectl uncordon kube-group-1-mdlr
```

您应该看到类似于以下内容的响应：

```
node/kube-group-1-mdlr uncordoned
```

1.  验证节点是否再次可调度。检查以下输出中的“污点”部分：

```
kubectl describe node kube-group-1-mdlr
```

您应该看到类似于以下内容的响应：

![图 18.13：检查我们未封锁节点的污点和不可调度状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_13.jpg)

图 18.13：检查我们未封锁节点的污点和不可调度状态

前面的截图显示节点现在是可调度的，并且我们在*步骤 8*中观察到的污点已经被移除。

在这个练习中，您已经看到如何从节点中删除所有的 pod 并将节点标记为不可调度。这将确保在该节点中不会安排新的 pod，并且我们可以开始升级该节点。我们还学习了如何使节点再次可调度，以便在完成升级后继续使用它。

# 升级 Kubernetes 主要组件

当您以任何重要程度运行 Kubernetes 对您的组织很重要时，您将以 HA 配置运行平台。为了实现这一点，典型的配置至少是三个主要组件的副本，运行在三个不同的节点上。这允许您逐个将单个节点从一个次要版本升级到下一个次要版本，同时在升级后重新加入集群时仍然保持 API 兼容性，因为 Kubernetes 提供了一次次要版本的兼容性。这意味着在逐个升级每个节点时，主要组件可以处于不同的版本。以下表格提供了版本的逻辑流。假设您正在从版本 1.14 升级到 1.15：

![图 18.14：三个主节点的升级计划](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_14.jpg)

图 18.14：三个主节点的升级计划

在接下来的练习中，我们将继续升级 Kubernetes 主要组件。

## 练习 18.03：升级 Kubernetes 主要组件

在这个练习中，您将升级 Kubernetes 主节点上的所有主要组件。此练习假定您仍然登录到集群的堡垒主机。

在这个练习中，我们演示了一个较少数量的节点的过程，以简化操作，但是升级大量节点的过程是相同的。然而，为了实现无缝升级，三个主节点是最少的，并且您的应用程序应该是 HA，并且至少在两个工作节点上运行：

1.  运行 kops 验证器来验证现有的集群：

```
kops validate cluster 
```

您应该看到类似以下的响应：

![图 18.15：验证我们的 kops 集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_15.jpg)

图 18.15：验证我们的 kops 集群

这是输出的截断版本。它显示了集群的主要基础设施组件。

1.  列出集群中的所有节点：

```
kubectl get nodes
```

您应该看到类似这样的响应：

![图 18.16：获取节点列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_16.jpg)

图 18.16：获取节点列表

请注意，我们有三个主节点，它们都在 1.15.7 版本上。

注意

在这个练习中，我们展示了从 Kubernetes 版本 1.15.7 升级到 1.15.10。您可以应用相同的步骤来升级到 kops 在您执行此练习时支持的 Kubernetes 版本。只需记住我们之前的建议，先升级到最新的补丁版本（这就是我们在这里所做的）。

1.  使用`kops upgrade cluster`命令查看可用的更新：

```
kops upgrade cluster ${NAME}
```

请注意，这个命令不会直接运行更新，但它会给出可能的最新更新版本。`NAME`环境变量保存了您的集群名称。您应该看到类似以下的输出：

![图 18.17：检查可用的集群版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_17.jpg)

图 18.17：检查可用的集群版本

您可以从前面的截图中看到，`OLD`版本是`1.15.7`，这是我们当前的版本，`NEW`版本是`1.15.10`，这是我们的目标版本。

1.  一旦您验证了*步骤 4*中的命令的更改，使用`--yes`标志运行相同的命令。这将在 kops 状态存储中标记集群的期望状态：

```
kops upgrade cluster --yes
```

您应该看到类似以下的输出：

![图 18.18：升级 kops 集群配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_18.jpg)

图 18.18：升级 kops 集群配置

这个输出表明了 Kubernetes 集群的期望版本已记录在更新的 kops 配置中。在下一步中，我们将要求 kops 更新云或集群资源以匹配新的规格-即 Kubernetes 版本`1.15.10`。

1.  现在，让我们运行以下命令，以便 kops 更新集群以匹配更新的 kops 配置：

```
kops update cluster ${NAME} --yes
```

这将产生一个长输出，最终会以类似以下的方式结束：

![图 18.19：根据我们集群升级的要求更新我们的集群基础架构我们集群升级的要求](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_19.jpg)

图 18.19：根据我们集群升级的要求更新我们的集群基础架构

这已经更新了集群基础架构，以匹配更新的 kops 配置。接下来，我们需要对运行在这个基础架构上的 Kubernetes 主组件进行升级。

1.  如果您在不同实例组上运行多个主/工作节点实例，那么您可以控制哪个实例组接收更新。为此，让我们首先获取我们实例组的名称。使用以下命令获取名称：

```
kops get instancegroups
```

您应该看到以下响应：

![图 18.20：获取实例组列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_20.jpg)

图 18.20：获取实例组列表

1.  在这一步中，kops 将更新 Kubernetes 集群以匹配 kops 规范。让我们使用滚动更新将第一个主节点升级到新版本：

```
kops rolling-update cluster ${NAME} --instance-group master-australia-southeast1-a --yes
```

请注意，此命令只会在您指定`--yes`标志时应用更改。根据您的节点配置，此命令可能需要一些时间。请耐心等待并观察日志，看是否有任何错误。过一段时间后，您应该看到类似以下截图中的成功消息：

![图 18.21：对我们的第一个实例组应用滚动更新](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_21.jpg)

图 18.21：对我们的第一个实例组应用滚动更新

1.  验证节点是否已升级到目标版本，即`1.15.10`，在我们的情况下：

```
kubectl get nodes
```

这应该给出类似以下的响应：

![图 18.22：检查节点上的主要组件是否已升级](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_22.jpg)

图 18.22：检查节点上的主要组件是否已升级

您可以看到第一个主节点的版本为`1.15.10`。

1.  验证新升级的节点上是否正在运行 pod：

```
kubectl describe node master-australia-southeast1-a-q2pw
```

使用您在之前步骤中升级的节点的名称。这将给出一个很长的输出。查找`Non-terminated Pod`部分，如下截图所示：

![图 18.23：检查我们升级的节点是否正在运行 pod](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_23.jpg)

图 18.23：检查我们升级的节点是否正在运行 pod

注意

重复*步骤 7*至*9*，对所有额外的主节点进行更新和验证，使用相应实例组的适当名称。

1.  验证 kops 是否成功更新了主节点：

```
kops rolling-update cluster ${NAME}
```

您应该看到以下输出：

![图 18.24：检查所有主节点是否已升级](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_24.jpg)

图 18.24：检查所有主节点是否已升级

如前所述，这是一个干跑，输出显示哪些节点需要更新。由于它们都显示`STATUS`为`Ready`，我们知道它们已经更新。相比之下，您可以看到`nodes`（工作节点）返回`NeedsUpdate`，因为我们还没有更新它们。

1.  验证所有主节点是否已升级到所需版本：

```
kubectl get nodes
```

您应该看到类似以下的响应：

![图 18.25：检查所有主节点上 Kubernetes 的版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_25.jpg)

图 18.25：检查所有主节点上 Kubernetes 的版本

如您所见，所有主节点都在运行版本`1.15.10`，这是期望的版本。

在这个练习中，您已经看到了如何在不影响用户的情况下升级 Kubernetes 集群的主节点。逐个节点更新将确保有足够的主服务器可用（至少需要三个才能正常工作），并且在更新期间不会影响用户和集群。

注意

当您对实例组应用滚动更新时，kops 将通过逐个将节点脱机来滚动更新实例组中的节点。除此之外，在这个练习中，我们一次只对一个实例组应用滚动更新。最终，您应该实现的是集群中只有一个节点被逐个脱机。如果您选择自动化这个过程，请记住这一点。

# 升级 Kubernetes 工作节点

尽管 Kubernetes 支持主节点（API 服务器）和工作节点（kubelet）在一个次要版本内的兼容性，但强烈建议您一次性升级主节点和工作节点。使用 kops，升级工作节点类似于升级主节点。由于在一个次要版本内的向后兼容性，如果工作节点与主节点的版本不匹配，工作节点可能仍然可以工作，但强烈不建议在工作节点和主节点上运行不同版本的 Kubernetes，因为这可能会为集群创建问题。

然而，如果您希望在升级过程中保持应用程序在线，以下考虑非常重要：

+   确保您的应用程序配置为高可用。这意味着您应该为每个应用程序至少在不同节点上拥有两个 pod。如果不是这种情况，一旦您从节点中驱逐 pod，您的应用程序可能会出现停机时间。

+   如果您运行有状态的组件，请确保这些组件的状态已备份，或者您的应用程序设计能够承受有状态组件的部分不可用。

例如，假设您正在运行一个具有单个主节点和多个读取副本的数据库。一旦运行数据库主副本的节点驱逐数据库 pod，如果您的应用程序没有正确配置来处理这种情况，它们将遭受停机时间。这与 Kubernetes 集群的升级无关，但重要的是要了解您的应用程序在升级期间的行为，并确保它们被正确配置为容错。

现在我们已经了解了确保应用程序的正常运行时间的要求，让我们看看如何在以下练习中升级工作节点。

## 练习 18.04：升级工作节点

在这个练习中，我们将升级 Kubernetes 集群的所有工作节点。工作节点是您的应用程序的主机。

1.  获取工作节点的实例组列表：

```
kops get instancegroups
```

您应该看到类似以下的响应：

![图 18.26：获取实例组列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_26.jpg)

图 18.26：获取实例组列表

从这个图像中，我们可以看到我们的工作节点实例组的名称是`nodes`。

1.  验证节点是否准备就绪：

```
kubectl get nodes
```

您应该看到类似于这样的响应：

![图 18.27：检查节点状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_27.jpg)

图 18.27：检查节点状态

如果我们有多个实例组，我们将逐个升级每个实例组。然而，我们的任务很简单，因为我们只有一个 - 那就是`nodes`。

1.  运行`kops rolling update`命令，针对`nodes`实例组**不**使用`--yes`标志。这将为您提供使用`kops rolling-update`命令将要更新的摘要：

```
kops rolling-update cluster ${NAME} --node-interval 3m --instance-group nodes --post-drain-delay 3m --logtostderr --v 9
```

请注意，我们已经在前面的命令中更改了详细日志的详细程度。

让我们分解这个命令：

- `node-interval`标志设置不同节点重新启动之间的最小延迟。

- `instance-group`标志指定滚动更新应该应用到哪个实例组。

- `post-drain-delay`标志设置在排空节点之后重新启动之前的延迟。请记住，在本章的前面部分，排空操作将等待 pod 的正常终止。这个延迟将在此之后应用。

`node-interval`和`post-drain-delay`标志提供了控制集群变化速率的选项。这些选项的值部分取决于您正在运行的应用程序类型。例如，如果您在节点上运行一个日志代理 DaemonSet，您可能希望给足够的时间让 pod 将内容刷新到中央日志服务器。

注意

在上一个案例中，我们在执行滚动更新时没有使用这些延迟，因为在那种情况下，实例组中每个只有一个节点。在这里，这个实例组中有三个节点。

- `logtosterr`标志将所有日志输出到**stderr**流，以便我们可以在终端输出中看到它们。

- `v`标志设置我们将看到的日志的详细程度。

此命令将显示以下输出：

![图 18.28：执行滚动更新的干跑](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_28.jpg)

图 18.28：执行滚动更新的干跑

1.  现在，运行升级。使用与上一步相同的命令，并添加`--yes`标志。这告诉 kops 执行升级：

```
kops rolling-update cluster ${NAME} --node-interval 3m --instance-group nodes --post-drain-delay 3m --logtostderr --v 9 --yes
```

Kops 将排空一个节点，等待排空后的延迟时间，然后升级并重新启动节点。这将逐个节点重复进行。您将在终端中看到一个很长的日志，这个过程可能需要长达半个小时才能完成。在您的终端中，您应该开始看到日志，如下所示：

![图 18.29：开始滚动更新过程](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_29.jpg)

图 18.29：开始滚动更新过程

过一会儿，您将看到集群升级已经完成，并显示成功消息，如下所示：

![图 18.30：滚动更新完成消息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_30.jpg)

图 18.30：滚动更新完成消息

细心的读者会注意到，在*图 18.29*中，作者的日志显示，集群升级在大约 3:05 开始，如*图 18.29*所示，大约在 3:25 完成。三个节点的总时间约为 20 分钟。我们在停止每个节点后设置了 3 分钟的延迟，以及在排空所有 pod 后设置了 3 分钟的延迟。因此，每个节点的等待时间加起来为 6 分钟。在实例组中有三个节点，总等待时间为 6×3=18 分钟。

1.  验证工作节点是否已更新到目标版本-即`1.15.10`：

```
kubectl get nodes 
```

您应该看到以下响应：

![图 18.31：检查工作节点上的 Kubernetes 版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_31.jpg)

图 18.31：检查工作节点上 Kubernetes 的版本

1.  验证 pod 是否处于运行状态：

```
kubectl get pods -n upgrade-demo
```

您应该看到所有的 pod 的`STATUS`都设置为`Running`，就像这个截图中一样：

![图 18.32：检查我们的 pod 的状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_32.jpg)

图 18.32：检查我们的 pod 的状态

在这个练习中，您已经看到了通过 kops 升级工作节点是多么容易。但是，我们不建议一次性升级所有生产集群的工作节点，并强烈建议为工作节点创建实例组。以下是一些可用于生产级集群的策略：

+   不要将所有的工作节点都放在一个实例组中。为不同的工作节点集创建多个实例组。默认情况下，kops 只创建一个实例组，但您可以更改此行为，为工作节点创建多个实例组。我们建议为基础设施组件（如监控和日志记录）、入口、关键应用程序、非关键应用程序和静态应用程序创建不同的工作实例组。这将帮助您首先将升级应用于集群中不太关键的部分。这种策略将有助于限制升级过程中的任何问题，并将受影响的节点与集群的其余部分隔离开来。

+   如果您在云中运行集群，可以根据需要提供新节点。因此，创建一个姐妹实例组进行升级可能是一个好主意。这个新的实例组应该运行升级后的 Kubernetes 版本。现在，从旧的实例组中关闭和排空所有的 pod。Kubernetes 调度器将看到新节点可用，并自动将所有 pod 移动到新节点。完成后，您只需删除旧的实例组，升级就完成了。

这种策略需要一些规划，特别是如果您在集群上运行有状态的应用程序。这种策略还假定您能够根据需要提供新节点，因为创建一个姐妹实例组可能需要临时的额外硬件，这对于自建数据中心可能是一个挑战。

请注意，这些都是高级策略，超出了本书的范围。但是，您可以在[`kops.sigs.k8s.io/tutorial/working-with-instancegroups/`](https://kops.sigs.k8s.io/tutorial/working-with-instancegroups/)找到更多信息。

现在您已经看到升级集群所需的所有步骤，您可以在以下活动中将它们整合起来。

## 活动 18.01：将 Kubernetes 平台从版本 1.15.7 升级到 1.15.10

在这个活动中，您将把 Kubernetes 平台从版本`1.15.7`升级到版本`1.15.10`。在这里，我们将整合本章学到的所有内容。以下准则应该帮助您完成这个活动：

注意

在这个活动中，我们展示了从 Kubernetes 版本`1.15.7`升级到`1.15.10`的过程。您可以应用相同的步骤来升级到 kops 在您执行此活动时支持的 Kubernetes 版本。

1.  使用*练习 11.01*，*设置我们的 Kubernetes 集群*，建立一个运行 Kubernetes 版本`1.15.7`的新集群。如果您正在使用云来启动机器，您可以在升级之前对机器进行快照（您的云供应商可能会向您收费），以便快速重新运行升级。

1.  将 kops 升级到您想要在主节点或堡垒节点上升级的版本。对于这个活动，我们需要版本`1.15`。

1.  将其中一个主节点升级到 Kubernetes 版本`1.15.10`。 

1.  验证主节点是否已恢复服务并处于`Ready`状态。

1.  同样，升级所有其他主节点。

1.  验证所有主节点是否已升级到所需版本，如下截图所示：![图 18.33：主节点上的 Kubernetes 升级版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_33.jpg)

图 18.33：主节点上的 Kubernetes 升级版本

1.  现在，升级工作节点。

1.  验证 Pod 是否成功运行在新升级的节点上。最后，您应该能够验证您的 Pod 正在新节点上运行，如下所示：![图 18.34：运行在升级后的工作节点上的 Pod](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_18_34.jpg)

图 18.34：运行在升级后的工作节点上的 Pod

注意

此活动的解决方案可以在以下地址找到：[`packt.live/304PEoD`](https://packt.live/304PEoD)。

# 总结

在本章中，您已经了解到，保持 Kubernetes 平台的最新状态对于提供安全可靠的应用程序运行基础非常重要。在这个快速发展的数字世界中，许多企业依赖于关键应用程序，并保持它们可用，即使升级底层平台也很重要。

您已经看到，如果您一开始就以高可用性配置设置了集群，那么平台的无停机升级是可能的。然而，除非您以容错的方式设计和部署应用程序，否则平台不能保证应用程序的可用性。一个因素是确保您的应用程序有多个实例运行，并且该应用程序被设计为优雅地处理这些实例的终止。

考虑到这一点，我们已经看到了升级集群的重要考虑因素，以确保平台本身不会导致应用程序的停机时间。我们分别研究了主节点和工作节点的升级过程。本章的关键要点是在不同情况下强调的原则，您可以将其应用于不同工具管理的不同类型的 Kubernetes 集群。

正如本章开头提到的，保持平台的最新状态对于跟上 DevOps 的最新发展并使您的应用开发团队能够继续向最终客户提供新功能是很重要的。通过本章获得的技能，您应该能够在升级平台时不会对客户造成中断。

在下一章中，我们将讨论如何使用自定义资源扩展您的 Kubernetes 平台。自定义资源允许您为自己的项目提供 Kubernetes 本机 API 体验。


# 第十九章： Kubernetes 中的自定义资源定义

概述

在本章中，我们将展示如何使用**自定义资源定义**（**CRDs**）来扩展 Kubernetes 并向您的 Kubernetes 集群添加新功能。您还将学习如何定义、配置和实现完整的 CRD。我们还将描述各种示例场景，其中 CRDs 可以非常有帮助。在本章结束时，您将能够定义和配置 CRD 和**自定义资源**（**CR**）。您还将学习如何部署一个基本的自定义控制器来实现集群中 CR 所需的功能。

# 介绍

在之前的章节中，我们学习了不同的 Kubernetes 对象，比如 Pods、Deployments 和 ConfigMaps。这些对象是由 Kubernetes API 定义和管理的（也就是说，对于这些对象，API 服务器管理它们的创建和销毁，以及其他操作）。然而，您可能希望扩展 Kubernetes 提供的功能，以提供一个标准 Kubernetes 中没有的功能，并且不能通过 Kubernetes 提供的内置对象来启用。

为了在 Kubernetes 之上构建这些功能，我们使用**自定义资源**（**CRs**）。**自定义资源定义**（**CRDs**）允许我们通过这种方式向 Kubernetes 服务器添加自定义对象，并像任何其他本机 Kubernetes 对象一样使用这些 CRs。CRD 帮助我们将我们的自定义对象引入 Kubernetes 系统。一旦我们的 CRD 被创建，它就可以像 Kubernetes 服务器中的任何其他对象一样使用。不仅如此，我们还可以使用 Kubernetes API、**基于角色的访问控制**（**RBAC**）策略和其他 Kubernetes 功能来管理我们引入的 CRs。

当您定义一个 CRD 时，它会存储在 Kubernetes 配置数据库（etcd）中。将 CRD 视为自定义对象结构的定义。一旦定义了 CRD，Kubernetes 就会创建符合 CRD 定义的对象。我们称这些对象为 CRs。如果我们将其比作编程语言的类比，CRD 就是类，CR 就是类的实例。简而言之，CRD 定义了自定义对象的模式，CR 定义了您希望实现的对象的期望状态。

CRs 是通过自定义控制器实现的。我们将在本章的第一个主题中更详细地了解自定义控制器。

# 什么是自定义控制器？

CRD 和 CR 可帮助您定义 CR 的期望状态。需要一个组件来确保 Kubernetes 系统的状态与 CR 定义的期望状态相匹配。正如您在前几章中所看到的，执行此操作的 Kubernetes 组件称为控制器。Kubernetes 提供了许多这些控制器，它们的工作是确保期望状态（例如，在部署中定义的 Pod 副本数）等于部署对象中定义的值。总之，控制器是一个通过 Kubernetes API 服务器监视资源状态并尝试将当前状态与期望状态匹配的组件。

标准 Kubernetes 设置中包含的内置控制器旨在与内置对象（如部署）一起使用。对于我们的 CRD 及其 CR，我们需要编写自己的自定义控制器。

## CRD、CR 和控制器之间的关系

CRD 提供了定义 CR 的方法，自定义控制器提供了对 CR 对象进行操作的逻辑。以下图表总结了 CRD、CR 和控制器：

![图 19.1：CRD、CR 和控制器如何相互关联](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_19_01.jpg)

图 19.1：CRD、CR 和控制器如何相互关联

如前图所示，我们有一个 CRD、一个自定义控制器和根据 CRD 定义期望状态的 CR 对象。这里有三件事需要注意：

+   CRD 是定义对象外观的模式。每个资源都有一个定义的模式，告诉 Kubernetes 引擎在定义中期望什么。诸如`PodSpec`之类的核心对象具有内置到 Kubernetes 项目中的模式。

注意

您可以在此链接找到 PodSpec 的源代码：[`github.com/kubernetes/kubernetes/blob/master/pkg/apis/core/types.go#L2627`](https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/core/types.go#L2627)

+   基于模式（CRD）创建的 CR 对象定义了资源的期望状态。

+   自定义控制器是提供功能的应用程序，将当前状态带到期望的状态。

请记住，CRD 是 Kubernetes 允许我们声明性地定义 CR 的模式或定义的一种方式。一旦我们的 CRD（模式）在 Kubernetes 服务器上注册，CR（对象）将根据我们的 CRD 进行定义。

# 标准 Kubernetes API 资源

让我们列出 Kubernetes 集群中所有可用的资源和 API。请记住，我们使用的所有内容都被定义为 API 资源，而 API 是我们与 Kubernetes 服务器通信以处理该资源的网关。

使用以下命令获取当前 Kubernetes 资源的列表：

```
kubectl api-resources
```

您应该看到以下响应：

![图 19.2：标准 Kubernetes API 资源](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_19_02.jpg)

图 19.2：标准 Kubernetes API 资源

在上面的截图中，您可以看到 Kubernetes 中定义的资源具有`APIGroup`属性，该属性定义了负责管理此资源的内部 API。`Kind`列出了资源的名称。正如我们在本主题中之前所看到的，对于标准的 Kubernetes 对象，比如 Pods，Pod 对象的模式或定义内置在 Kubernetes 中。当您定义一个 Pod 规范来运行一个 Pod 时，这可以说类似于 CR。

对于每个资源，都有一些可以针对该资源采取行动的代码。这被定义为一组 API（`APIGroup`）。请注意，可以存在多个 API 组；例如，一个稳定版本和一个实验版本。发出以下命令以查看您的 Kubernetes 集群中有哪些 API 版本可用：

```
kubectl api-versions
```

您应该看到以下响应：

![图 19.3：各种 API 组及其版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_19_03.jpg)

图 19.3：各种 API 组及其版本

在上面的截图中，请注意`apps` API 组有多个可用版本。每个版本可能具有其他组中不可用的不同功能集。

# 为什么我们需要自定义资源？

如前所述，CR 提供了一种方式，通过这种方式我们可以扩展 Kubernetes 平台，以提供特定于某些用例的功能。以下是一些您将遇到 CR 使用的用例。

## 示例用例 1

考虑这样一个用例，您希望自动将业务应用程序或数据库自动部署到 Kubernetes 集群上。抽象掉技术细节，比如配置和部署应用程序，允许团队在不需要深入了解 Kubernetes 的情况下管理它们。例如，您可以创建一个 CR 来抽象数据库的创建。因此，用户只需在 CRD 中定义数据库的名称和大小，控制器就会提供其余部分来创建数据库 Pod。

## 示例用例 2

考虑这样一个情景，您有自助团队。您的 Kubernetes 平台被多个团队使用，您希望团队自行定义工作负载所需的总 CPU 和内存，以及 Pod 的默认限制。您可以创建一个 CRD，团队可以使用命名空间名称和其他参数创建 CR。您的自定义控制器将创建他们需要的资源，并为每个团队关联正确的 RBAC 策略。您还可以添加其他功能，例如限制团队只能使用三个环境。控制器还可以生成审计事件并记录所有活动。

## 示例用例 3

假设您是开发 Kubernetes 集群的管理员，开发人员会在这里测试他们的应用程序。您面临的问题是开发人员留下了正在运行的 Pod，并已转移到新项目。这可能会对您的集群造成资源问题。

在本章中，我们将围绕这种情景构建一个 CRD 和一个自定义控制器。我们可以实现的解决方案是在创建后的一定时间后删除 Pod。让我们称这个时间为`podLiveForThisMinutes`。另一个要求是以可配置的方式为每个命名空间定义`podLiveForThisMinutes`，因为不同的团队可能有不同的优先级和要求。

我们可以为每个命名空间定义一个时间限制，这将为在不同命名空间应用控制提供灵活性。为了实现本示例用例中定义的要求，我们将定义一个 CRD，允许两个字段 - 命名空间名称和允许 Pod 运行的时间量（`podLiveForThisMinutes`）。在本章的其余部分，我们将构建一个 CRD 和一个控制器，使我们能够实现这里提到的功能。

注意

有其他（更好的）方法来实现前面的场景。在现实世界中，如果 Pod 是使用`Deployment`资源创建的，Kubernetes 的`Deployment`对象将重新创建 Pod。我们选择了这个场景，以使示例简单易实现。

# 我们的自定义资源是如何定义的

为了解决前一节中*示例用例 3*的问题，我们决定我们的 CRD 将定义两个字段，如前面的示例中所述。为了实现这一点，我们的 CR 对象将如下所示。

```
apiVersion: "controllers.kube.book.au/v1"
kind: PodLifecycleConfig
metadata:
  name: demo-pod-lifecycle
spec:
  namespaceName: crddemo
  podLiveForThisMinutes: 1
```

上述规范定义了我们的目标对象。正如你所看到的，它看起来就像普通的 Kubernetes 对象，但规范（`spec`部分）根据我们的需求进行了定义。让我们深入了解一下细节。

## apiVersion

这是 Kubernetes 用来对对象进行分组的字段。请注意，我们将版本（`v1`）作为组键的一部分。这种分组技术帮助我们保持对象的多个版本。考虑是否要添加新属性而不影响现有用户。你可以只创建一个带有`v2`的新组，同时存在`v1`和`v2`两个版本的对象定义。因为它们是分开的，所以不同组的不同版本可以以不同的速度发展。

这种方法还有助于我们测试新功能。假设我们想要向同一对象添加一个新字段。然后，我们可以只更改 API 版本并添加新字段。因此，我们可以将稳定版本与新的实验版本分开。

## kind

这个字段提到了由`apiVersion`定义的组中的特定类型对象。把`kind`想象成 CR 对象的名称，比如`Pod`。

注意

不要将其与使用此规范创建的对象的名称混淆，该对象在`metadata`部分中定义。

通过这个，我们可以在一个 API 组下拥有多个对象。想象一下，你要创建一个需要创建多种不同类型对象的功能。你可以在同一个 API 组下使用`Kind`字段创建多个对象。

## spec

这个字段定义了定义对象规范所需的信息。规范包含定义资源期望状态的信息。描述资源特性的所有字段都放在`spec`部分。对于我们的用例，`spec`部分包含我们 CR 所需的两个字段——`podLiveForThisMinutes`和`namespaceName`。

## namespaceName 和 podLiveForThisMinutes

这些是我们想要定义的自定义字段。`namespaceName`将包含目标命名空间的名称，而`podLiveForThisMinutes`将包含我们希望 Pod 活动的时间（以分钟为单位）。

## CRD 的定义

在前面的部分中，我们展示了 CR 的不同组件。然而，在我们定义 CR 之前，我们需要定义一个模式，它规定了 CR 的定义方式。在接下来的练习中，您将为*我们的自定义资源是如何定义的*部分中提到的资源定义模式或 CRD。

考虑这个示例 CRD，在接下来的练习中我们将使用它。让我们通过观察以下定义来理解 CRD 的重要部分：

pod-normaliser-crd.yaml

```
1  apiVersion: apiextensions.k8s.io/v1beta1
2  kind: CustomResourceDefinition
3  metadata:
4    name: podlifecycleconfigs.controllers.kube.book.au
5  spec:
6    group: controllers.kube.book.au
7    version: v1
8    scope: Namespaced
9    names:
10     kind: PodLifecycleConfig
11     plural: podlifecycleconfigs
12     singular: podlifecycleconfig
13  #1.15 preserveUnknownFields: false
14   validation:
15     openAPIV3Schema:
16       type: object
17       properties:
18         spec:
19           type: object
20           properties:
21             namespaceName:
22               type: string
23             podLiveForThisMinutes:
24               type: integer
```

现在，让我们看看这个 CRD 的各个组件：

+   `apiVersion`和`kind`：这些是 CRD 本身的 API 和资源，由 Kubernetes 提供给 CRD 定义。

+   `group`和`version`：将 API 组想象成一组逻辑相关的对象。这两个字段定义了我们 CR 的 API 组和版本，然后将被翻译成我们在前面部分中定义的 CR 的`apiVersion`字段。

+   `kind`：这个字段定义了我们 CR 的`kind`，在*我们的自定义资源是如何定义的*部分中已经定义过。

+   `metadata/name`：名称必须与`spec`字段匹配，格式是两个字段的组合，即`<plural>.<group>`。

+   `scope`：这个字段定义了 CR 是命名空间范围还是集群范围。默认情况下，CR 是集群范围的。我们在这里定义它为命名空间范围。

+   `plurals`：这些是用于 Kubernetes API 服务器 URL 中的复数名称。

+   `openAPIV3Schema`：这是基于 OpenAPI v3 标准定义的模式。它指的是我们 CR 的实际字段/模式。模式定义了我们 CR 中可用的字段、字段的名称和它们的数据类型。它基本上定义了我们 CR 中`spec`字段的结构。我们在 CR 中使用了`namespaceName`和`podLiveForMinutes`字段。你可以在以下练习的*步骤 2*中看到这一点。

有趣的是，API 服务器中服务 CR 的组件被称为`apiextensions-apiserver`。当 kubectl 请求到达 API 服务器时，它首先检查资源是否是标准的 Kubernetes 资源，比如 Pod 或 Deployment。如果资源不是标准资源，那么就会调用`apiextensions-apiserver`。

## 练习 19.01：定义 CRD

在这个练习中，我们将定义一个 CRD，在下一个练习中，我们将为定义的 CRD 创建一个 CR。CRD 的定义存储在 Kubernetes etcd 服务器中。请记住，CRD 和 CR 只是定义，直到您部署与您的 CR 相关联的控制器，CRD/CR 才会有功能附加。通过定义 CRD，您正在向 Kubernetes 集群注册一个新类型的对象。在定义 CRD 之后，它将通过正常的 Kubernetes API 可访问，并且您可以通过 Kubectl 访问它：

1.  创建一个名为`crddemo`的新命名空间：

```
kubectl create ns crddemo
```

这应该得到以下响应：

```
namespace/crddemo created
```

1.  现在，我们需要定义一个 CRD。使用以下内容创建一个名为`pod-normaliser-crd.yaml`的文件：

```
apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  name: podlifecycleconfigs.controllers.kube.book.au
spec:
  group: controllers.kube.book.au
  version: v1
  scope: Namespaced
  names:
    kind: PodLifecycleConfig
    plural: podlifecycleconfigs
    singular: podlifecycleconfig
  #1.15 preserveUnknownFields: false
  validation:
    openAPIV3Schema:
      type: object
      properties:
        spec:
          type: object
          properties:
            namespaceName:
              type: string
            podLiveForThisMinutes:
              type: integer
```

1.  使用上一步的定义，使用以下命令创建 CRD：

```
kubectl create -f pod-normaliser-crd.yaml -n crddemo
```

您应该看到以下响应：

![图 19.4：创建我们的 CRD](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_19_04.jpg)

图 19.4：创建我们的 CRD

1.  使用以下命令验证 CR 是否已在 Kubernetes 中注册：

```
kubectl api-resources | grep podlifecycleconfig
```

您应该看到以下资源列表：

![图 19.5：验证 CR 是否已在 Kubernetes 中注册](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_19_05.jpg)

图 19.5：验证 CR 是否已在 Kubernetes 中注册

1.  使用以下命令验证 Kubernetes API 服务器中是否可用 API：

```
kubectl api-versions | grep controller
```

您应该看到以下响应：

```
controllers.kube.book.au/v1
```

在这个练习中，我们已经定义了一个 CRD，现在，Kubernetes 将能够知道我们的 CR 应该是什么样子的。

现在，在下一个练习中，让我们根据我们定义的 CRD 创建一个资源对象。这个练习将是上一个练习的延伸。但是，我们将它们分开，因为 CRD 对象可以独立存在；您不必将 CR 与 CRD 配对。可能的情况是，CRD 由某些第三方软件供应商提供，并且您只需要创建 CR。例如，供应商提供的数据库控制器可能已经有了 CRD 和控制器。要使用功能，您只需要定义 CR。

让我们继续在下一个练习中将我们的 CRD 制作成一个 CR。

## 练习 19.02：使用 CRD 定义 CR

在这个练习中，我们将根据上一个练习中定义的 CRD 创建一个 CR。CR 将作为一个普通的 Kubernetes 对象存储在 etcd 数据存储中，并由 Kubernetes API 服务器提供服务-也就是说，当您尝试通过 Kubectl 访问它时，它将由 Kubernetes API 服务器处理：

注意

只有在成功完成本章的上一个练习后，您才能执行此练习。

1.  首先，确保`podlifecycleconfigs`类型没有 CR。使用以下命令进行检查：

```
kubectl get podlifecycleconfigs -n crddemo
```

如果没有 CR，您应该会看到以下响应：

```
No resources found.
```

如果已定义资源，可以使用以下命令删除它：

```
kubectl delete podlifecycleconfig <RESOURCE_NAME> -n crddemo
```

1.  现在，我们必须创建一个 CR。使用以下内容创建名为`pod-normaliser.yaml`的文件：

```
apiVersion: "controllers.kube.book.au/v1"
kind: PodLifecycleConfig
metadata:
  name: demo-pod-lifecycle
  # namespace: "crddemo"
spec:
  namespaceName: crddemo
  podLiveForThisMinutes: 1
```

1.  使用以下命令创建来自上一步创建的文件的资源：

```
kubectl create -f pod-normaliser.yaml -n crddemo
```

您应该会看到以下响应：

![图 19.6：创建我们的 CR](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_19_06.jpg)

图 19.6：创建我们的 CR

1.  使用以下命令验证 Kubernetes 是否已注册它：

```
kubectl get podlifecycleconfigs -n crddemo
```

您应该会看到以下响应：

```
NAME                  AGE
demo-pod-lifecycle    48s
```

请注意，我们现在正在使用普通的 kubectl 命令。这是扩展 Kubernetes 平台的一种非常棒的方式。

我们已经定义了自己的 CRD，并已创建了一个 CR。下一步是为我们的 CR 添加所需的功能。

## 编写自定义控制器

现在我们在集群中有一个 CR，我们将继续编写一些代码来*执行*它，以实现我们在*为什么需要自定义资源*部分中设定的场景的目的。

注意

我们不会教授编写控制器 Go 代码的实际编程，因为这超出了本书的范围。但是，我们会为*示例用例 3*提供所需的编程逻辑。

假设我们的自定义控制器代码正在作为一个 Pod 运行。为了响应 CR，它需要做些什么？

1.  首先，控制器必须知道在集群中定义/删除了新的 CR，以获取所需的状态。

1.  其次，代码需要一种与 Kubernetes API 服务器交互的方式，以请求当前状态，然后请求所需的状态。在我们的情况下，我们的控制器必须知道命名空间中所有 Pod 的时间以及 Pod 的创建时间。然后，代码可以要求 Kubernetes 根据 CRD 删除 Pods，如果它们的允许时间已到。请参考*示例用例 3*部分，以刷新您对我们的控制器将要执行的操作的记忆。

我们的代码逻辑可以通过以下图表进行可视化：

![图 19.7：描述自定义控制器逻辑的流程图](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_19_07.jpg)

图 19.7：描述自定义控制器逻辑的流程图

如果我们要将逻辑描述为简单的伪代码，那么它将如下所示：

1.  从 Kubernetes API 服务器获取为我们的自定义 CRD 创建的所有新 CR。

1.  注册回调以便在添加或删除 CR 时触发。每当在我们的 Kubernetes 集群中添加或删除新的 CR 时，都会触发这些回调。

1.  如果将 CR 添加到集群中，回调将创建一个子例程，该子例程将持续获取由 CR 定义的命名空间中的 Pod 列表。如果 Pod 已运行时间超过指定时间，它将被终止。否则，它将休眠几秒钟。

1.  如果删除 CR，回调将停止子例程。

### 自定义控制器的组件

如前所述，详细解释自定义控制器的构建方式超出了本书的范围，我们已经提供了一个完全可用的自定义控制器，以满足*示例用例 3*的需求。我们的重点是确保您可以构建和执行控制器以了解其行为，并且您对所有涉及的组件都感到满意。

自定义控制器是针对 CR 提供功能的组件。为了提供这一点，自定义控制器需要了解 CR 的用途及其不同的参数，或者*结构模式*。为了使我们的控制器了解模式，我们通过代码文件向控制器提供有关我们模式的详细信息。

以下是我们提供的控制器代码的摘录：

types.go

```
12 type PodLifecycleConfig struct {
13
14     // TypeMeta is the metadata for the resource, like kind and           apiversion
15     meta_v1.TypeMeta `json:",inline"`
16
17     // ObjectMeta contains the metadata for the particular           object like labels
18     meta_v1.ObjectMeta `json:"metadata,omitempty"`
19
20     Spec PodLifecycleConfigSpec `json:"spec"`
21 }
22
23 type PodLifecycleConfigSpec struct{
24     NamespaceName   string `json:"namespaceName"`
25     PodLiveForMinutes int `json:"podLiveForThisMinutes"`
26 }
...
32 type PodLifecycleConfigList struct {
33     meta_v1.TypeMeta `json:",inline"`
34     meta_v1.ListMeta `json:"metadata"`
35
36     Items []PodLifecycleConfig `json:"items"`
37 }
```

您可以在此链接找到完整的代码：[`packt.live/3jXky9G`](https://packt.live/3jXky9G)。

正如您所看到的，我们已经根据“自定义资源的定义方式”部分提供的 CR 示例定义了`PodLifecycleConfig`结构。这里重复列出以便更容易参考：

```
apiVersion: "controllers.kube.book.au/v1"
kind: PodLifecycleConfig
metadata:
  name: demo-pod-lifecycle
  # namespace: "crddemo"
spec:
  namespaceName: crddemo
  podLiveForThisMinutes: 1
```

请注意，在`types.go`中，我们已经定义了可以保存此示例规范的完整定义的对象。还要注意在`types.go`中，`namespaceName`被定义为`string`，`podLiveForThisMinuets`被定义为`int`。这是因为我们在 CR 中使用字符串和整数来表示这些字段，正如您所看到的。

控制器的下一个重要功能是监听与 CR 相关的来自 Kubernetes 系统的事件。我们使用**Kubernetes Go**客户端库连接到 Kubernetes API 服务器。该库使连接到 Kubernetes API 服务器（例如，用于身份验证）更容易，并具有预定义的请求和响应类型，以与 Kubernetes API 服务器进行通信。

注意

您可以在此链接找到有关 Kubernetes Go 客户端库的更多详细信息：[`github.com/kubernetes/client-go`](https://github.com/kubernetes/client-go)。

但是，您可以自由地使用任何其他库或任何其他编程语言通过 HTTPS 与 API 服务器通信。

您可以通过查看此链接上的代码来了解我们是如何实现的：[`packt.live/3ieFtVm`](https://packt.live/3ieFtVm)。首先，我们需要连接到 Kubernetes 集群。这段代码正在集群中的一个 Pod 中运行，并且需要连接到 Kubernetes API 服务器。我们需要给予我们的 Pod 足够的权限来连接到主服务器，这将在本章后面的活动中介绍。我们将使用 RBAC 策略来实现这一点。请参考*第十三章*，*Kubernetes 中的运行时和网络安全*，以了解 Kubernetes 如何实现 RBAC 功能的复习。

一旦我们连接上了，我们就使用`SharedInformerFactory`对象来监听控制器的 Kubernetes 事件。将事件视为 Kubernetes 在创建或删除新 CR 时通知我们的一种方式。`SharedInformerFactory`是 Kubernetes Go 客户端库提供的一种方式，用于监听 Kubernetes API 服务器生成的事件。对`SharedInformerFactory`的详细解释超出了本书的范围。

以下代码片段是我们的 Go 代码中创建`SharedInformerFactory`的摘录：

main.go

```
40 // create the kubernetes client configuration
41     config, err := clientcmd.BuildConfigFromFlags("", "")
42     if err != nil {
43         log.Fatal(err)
44     }
45
46     // create the kubernetes client
47     podlifecyelconfgiclient, err := clientset.NewForConfig(config)
48
49
50     // create the shared informer factory and use the client           to connect to kubernetes
51     podlifecycleconfigfactory :=          informers.NewSharedInformerFactoryWithOptions            (podlifecyelconfgiclient, Second*30,
52     informers.WithNamespace(os.Getenv(NAMESPACE_TO_WATCH)))
```

您可以在此链接找到完整的代码：[`packt.live/3lXe3FM`](https://packt.live/3lXe3FM)。

一旦我们连接到 Kubernetes API 服务器，我们需要注册以便在我们的 CR 被创建或删除时得到通知。以下代码执行了这个动作：

main.go

```
62 // fetch the informer for the PodLifecycleConfig
63 podlifecycleconfiginformer :=      podlifecycleconfigfactory.Controllers().V1().     PodLifecycleConfigs().Informer()
64
65 // register with the informer for the events
66 podlifecycleconfiginformer.AddEventHandler(
...
69 //define what to do in case if a new custom resource is created
70         AddFunc: func(obj interface{}) {
...
83 // start the subroutine to check and kill the pods for this namespace
84             go checkAndRemovePodsPeriodically(signal, podclientset, x)
85         },
86
87 //define what to do in case if a  custom resource is removed
88         DeleteFunc: func(obj interface{}) {
```

您可以在此链接找到完整的代码：[`packt.live/2ZjtQoy`](https://packt.live/2ZjtQoy)。

请注意，上述代码是从完整代码中提取的，这里的片段经过了轻微修改，以便在本书中更好地呈现。此代码正在向 Kubernetes 服务器注册回调。请注意，我们已经注册了 `AddFunc` 和 `DeleteFunc`。一旦 CR 被创建或删除，这些函数将被调用，我们可以针对此编写自定义逻辑。您可以看到，对于 `AddFunc`，正在调用 Go 子例程。对于每个新的 CR，我们都有一个单独的子例程来继续监视在命名空间中创建的 Pods。另外，请注意，`AddFunc` 将在日志中打印出 `A Custom Resource has been Added`。您可能还注意到，在 `DeleteFunc` 中，我们已关闭了 `signal` 通道，这将标记 Go 子例程停止自身。

## 活动 19.01：CRD 和自定义控制器的实际应用

在这个活动中，我们将构建和部署自定义控制器、CR 和 CRD。请注意，构建自定义控制器所需的编码超出了本书的范围，并且代码库中提供了现成的代码，以便部署工作控制器。

我们将创建一个新的 CRD，可以接受两个字段 - `podLiveForThisMinutes` 字段，定义了 Pod 在被杀死之前允许运行的时间（以分钟为单位），以及 `namespaceName` 字段，定义了这些规则将应用于哪个命名空间。

我们将根据 CRD 创建一个新的 CR。此外，我们将创建一个新的 Kubernetes 角色，允许从 Kubernetes API 服务器查询此新的 CRD。然后，我们将向您展示如何将新创建的角色与名为 `default` 的 ServiceAccount 关联起来，这是在命名空间 `default` 中运行 Pod 时默认使用的 ServiceAccount。

通常，我们构建一个自定义控制器，提供针对我们创建的 CRD 的逻辑。我们将使用打包为容器的代码，并将其部署为 Pod。控制器将作为普通 Pod 部署。

在活动结束时，为了测试我们的控制器，您将创建一个简单的 Pod，并验证我们的自定义控制器是否能够删除该 Pod。

**活动指南：**

1.  删除现有的 `crddemo` 命名空间，并使用相同的名称创建一个新的命名空间。

1.  使用以下命令获取用于创建控制器的代码和 `Dockerfile`：

```
git clone  https://github.com/PacktWorkshops/Kubernetes-Workshop.git 
cd Chapter19/Activity19.01/controller
```

1.  创建一个具有以下字段的 CRD。

元数据应包含以下内容：

```
name: podlifecycleconfigs.controllers.kube.book.au
```

`OpenAPIV3Schema` 部分应包含以下 `properties` 设置：

```
openAPIV3Schema:
  type: object
  properties:
    spec:
      type: object
      properties:
        namespaceName:
          type: string
        podLiveForThisMinutes:
          type: integer
```

1.  创建一个 CR，允许`crddemo`命名空间中的 Pod 存活 1 分钟。

1.  创建一个角色，为指定的 API 资源允许以下权限：

```
rules:
- apiGroups: ["controllers.kube.book.au"]
  resources: ["podlifecycleconfigs"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""] 
  resources: ["pods"]
  verbs: ["get", "watch", "list", "delete"]
```

1.  使用 RoleBinding 对象，将此新角色与`crddemo`命名空间中的`default` ServiceAccount 关联起来。

1.  使用*步骤 2*中提供的`Dockerfile`构建和部署控制器 Pod。

1.  在`crddemo`命名空间中使用`k8s.gcr.io/busybox`镜像创建一个长时间运行的 Pod。

观察上一步创建的 Pod，并观察我们的控制器是否正在终止它。预期结果是 Pod 应该被创建，然后大约一分钟后应该自动终止，如下面的屏幕截图所示：

![图 19.8：活动 19.01 的预期输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_19_08.jpg)

图 19.8：活动 19.01 的预期输出

注意

此活动的解决方案可以在以下地址找到：[`packt.live/304PEoD`](https://packt.live/304PEoD)。

## 向我们的自定义资源添加数据

在上一个活动中，您创建了 CRD 和 CR。我们之前提到过，一旦定义了我们的 CR，就可以使用标准 kubectl 命令查询它们。例如，如果您想查看已定义的`PodLifecycleConfig`类型的 CR 数量，可以使用以下命令：

```
kubectl get PodLifecycleConfig -n crddemo
```

您将看到以下响应

```
NAME                AGE
demo-pod-lifecycle  8h
```

请注意，它只显示对象的名称和年龄。但是，如果您为本机 Kubernetes 对象发出命令，您将看到更多列。让我们尝试部署：

```
kubectl get deployment -n crddemo
```

您应该看到类似于这样的响应：

```
NAME          READY    UP-TO-DATE   AVAILABLE   AGE
crd-server    1/1      1            1           166m
```

请注意 Kubernetes 添加的附加列，这些列提供了有关对象的更多信息。

如果我们想要添加更多列，以便前面的命令输出显示我们的 CR 的更多细节怎么办？您很幸运，因为 Kubernetes 提供了一种方法来为 CR 添加附加信息列。这对于显示每种自定义对象的关键值非常有用。这可以通过在 CRD 中定义的附加数据来实现。让我们看看我们如何在以下练习中做到这一点。

## 练习 19.03：向 CR 列表命令添加自定义信息

在这个练习中，您将学习如何通过`kubectl get`命令添加自定义信息到 CR 列表中：

注意

只有在成功完成*活动 19.01*，*CRD 和自定义控制器实战*之后，您才能执行此练习。

1.  让我们定义另一个带有附加列的 CRD。创建一个名为`pod-normaliser-crd-adv.yaml`的文件，内容如下：

```
apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  name: podlifecycleconfigsadv.controllers.kube.book.au
spec:
  group: controllers.kube.book.au
  version: v1
  scope: Namespaced
  names:
    kind: PodLifecycleConfigAdv
    plural: podlifecycleconfigsadv
    singular: podlifecycleconfigadv
  #1.15 preserveUnknownFields: false
  validation:
    openAPIV3Schema:
      type: object
      properties:
        spec:
          type: object
          properties:
            namespaceName:
              type: string
            podLiveForThisMinutes:
              type: integer    
  additionalPrinterColumns:
  - name: NamespaceName
    type: string
    description: The name of the namespace this CRD is applied       to.
    JSONPath: .spec.namespaceName
  - name: PodLiveForMinutes
    type: integer
    description: Allowed number of minutes for the Pod to       survive
    JSONPath: .spec.podLiveForThisMinutes
  - name: Age
    type: date
    JSONPath: .metadata.creationTimestamp
```

请注意我们有一个名为`additionalPrinterColumns`的新部分。顾名思义，这定义了资源的附加信息。`additionalPrinterColumns`部分的两个重要字段如下：

- `name`：这定义了要打印的列的名称。

- `JSONPath`：这定义了字段的位置。通过这个路径，从资源中获取信息，并在相应的列中显示。

1.  现在，让我们使用以下命令创建这个新的 CRD：

```
kubectl create -f pod-normaliser-crd-adv.yaml -n crddemo
```

您将看到以下输出：

![图 19.9：创建我们修改后的 CRD](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_19_09.jpg)

图 19.9：创建我们修改后的 CRD

1.  创建了 CRD 后，让我们创建 CRD 的对象。创建一个名为`pod-normaliser-adv.yaml`的文件，内容如下：

```
apiVersion: "controllers.kube.book.au/v1"
kind: PodLifecycleConfigAdv
metadata:
  name: demo-pod-lifecycle-adv
  # namespace: "crddemo"
spec:
  namespaceName: crddemo
  podLiveForThisMinutes: 20
```

现在，`spec`部分中的字段应该在`kubectl get`命令获取的列表中可见，类似于原生 Kubernetes 对象。

1.  使用以下命令创建前一步中定义的 CR：

```
kubectl create -f pod-normaliser-adv.yaml -n crddemo
```

这应该得到以下响应：

![图 19.10：创建我们的 CR](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_19_10.jpg)

图 19.10：创建我们的 CR

1.  现在，让我们发出`kubectl get`命令，看看是否显示了附加字段：

```
kubectl get PodLifecycleConfigAdv -n crddemo
```

您应该看到我们的对象显示了以下信息：

```
NAME                    NAMESPACENAME  PODLIVEFORMINUTES  AGE
demo-pod-lifecycle-adv  crddemo        20                 27m
```

您可以看到附加字段已显示，现在我们对 CR 有了更多信息。

在这个练习中，您已经看到我们可以在通过 Kubernetes API 服务器查询 CR 时关联附加数据。我们可以定义字段名称和字段数据的路径。当您拥有许多相同类型的资源时，这种资源特定信息变得重要，对于运维团队来说，更好地理解定义的资源也很有用。

# 摘要

在本章中，您了解了自定义控制器。根据 Kubernetes 词汇表，控制器实现控制循环，通过 API 服务器监视集群的状态，并进行更改，以尝试将当前状态移向期望的状态。

控制器不仅可以监视和管理用户定义的 CR，还可以对部署或服务等资源进行操作，这些资源通常是 Kubernetes 控制器管理器的一部分。控制器提供了一种编写自己的代码以满足业务需求的方式。

CRD 是 Kubernetes 系统中用于扩展其功能的中心机制。CRD 提供了一种原生方式来实现符合您业务需求的 Kubernetes API 服务器的自定义逻辑。

您已经了解了 CRD 和控制器如何帮助为 Kubernetes 平台提供扩展机制。您还看到了如何配置和部署自定义控制器到 Kubernetes 平台的过程。

当我们接近旅程的尽头时，让我们回顾一下我们取得了什么成就。我们从 Kubernetes 的基本概念开始，了解了其架构以及如何与其交互。我们介绍了 Kubectl，这是与 Kubernetes 交互的命令行工具，然后，我们看到了 Kubernetes API 服务器的工作原理以及如何使用`curl`命令与其通信。

前两章建立了容器化和 Kubernetes 的基础知识。此后，我们学习了 kubectl 的基础知识- Kubernetes 命令中心。在*第四章，如何与 Kubernetes（API 服务器）通信*中，我们看到了 kubectl 和其他 HTTP 客户端如何与 Kubernetes API 服务器通信。我们通过在章节末创建一个部署来巩固我们的学习。

从*第五章*的*Pods*到*第十章*的*ConfigMaps 和 Secrets*，我们深入探讨了理解平台并开始设计在 Kubernetes 上运行应用程序所必不可少的概念。诸如 Pods、Deployments、Services 和 PersistentVolumes 等概念使我们能够利用该平台编写容错应用程序。

在接下来的一系列章节中，从*第十一章*的*构建您自己的 HA 集群*到*第十五章*的*Kubernetes 中的监控和自动缩放*，我们了解了如何在云平台上安装和运行 Kubernetes。这涵盖了在高可用性（HA）配置中安装 Kubernetes 平台以及如何在平台中管理网络安全。在本书的这一部分，您还了解了有状态组件以及应用程序如何使用平台的这些特性。最后，本节讨论了监视您的集群并设置自动缩放。

最后，在这最后一部分，从*第十六章*开始，*Kubernetes 准入控制器*，我们开始学习一些高级概念，比如如何使用准入控制器应用自定义策略。你也已经了解了 Kubernetes 调度器，这是一个决定你的应用程序将在集群中的哪个位置运行的组件。你学会了如何改变调度器的默认行为。你也看到了 CRD 提供了一种扩展 Kubernetes 的方式，这不仅可以用来构建自定义增强功能，也可以作为第三方提供商为 Kubernetes 添加功能的一种方式。

这本书可以作为一个很好的起点，帮助你开始学习 Kubernetes。现在你已经具备了在 Kubernetes 之上设计和构建系统的能力，可以为你的组织带来云原生的体验。虽然这本书到此结束了，但这只是作为一个 Kubernetes 专业人员的旅程的开始。
