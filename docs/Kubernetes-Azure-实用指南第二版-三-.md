# Kubernetes Azure 实用指南第二版（三）

> 原文：[`zh.annas-archive.org/md5/8F91550A7983115FCFE36001051EE26C`](https://zh.annas-archive.org/md5/8F91550A7983115FCFE36001051EE26C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三部分：利用高级 Azure PaaS 服务

在本书的这一部分中，我们已经在 AKS 之上运行了多个应用程序。这些应用程序总是自包含的，这意味着整个应用程序能够完整地在 AKS 之上运行。在 AKS 之上运行完整的应用程序有一定的优势。您可以获得应用程序的可移植性，因为您可以将该应用程序移动到任何其他 Kubernetes 集群而几乎没有摩擦。您还可以完全控制端到端的应用程序。

伴随着更大的控制权而来的是更大的责任。将应用程序的部分内容卸载到 Azure 提供的 PaaS 服务中有一定的优势。例如，通过将数据库卸载到托管的 PaaS 服务，您不再需要关心更新数据库服务，备份会自动为您执行，并且大量的日志记录和监控都是开箱即用的。

在接下来的章节中，我们将介绍多种高级集成和随之而来的优势。阅读完本节后，您应该能够安全地访问其他 Azure 服务，如 Azure SQL 数据库、事件中心和 Azure 函数。

本节包括以下章节：

+   *第八章，将应用程序连接到 Azure 数据库*

+   *第九章，连接到 Azure 事件中心*

+   *第十章，保护您的 AKS 集群*

+   *第十一章，无服务器函数*

我们将从*第八章*开始，*将应用程序连接到 Azure 数据库*，在这一章中，我们将把一个应用程序连接到一个托管的 Azure 数据库。




# 第八章：连接应用程序到 Azure 数据库

在之前的章节中，我们将应用程序的状态存储在我们的集群中，要么在 Redis 集群上，要么在 MariaDB 上。您可能还记得在高可用性方面两者都存在一些问题。本章将带您了解连接到 Azure 托管的 MySQL 数据库的过程。

我们将讨论使用托管数据库与在 Kubernetes 本身上运行 StatefulSets 的好处。为了创建这个托管和管理的数据库，我们将利用 Azure 的 Open Service Broker for Azure（OSBA）。OSBA 是一种从 Kubernetes 集群内部创建 Azure 资源（如托管的 MySQL 数据库）的方式。在本章中，我们将更详细地解释 OSBA 项目，并在我们的集群上设置和配置 OSBA。

然后，我们将利用 OSBA 在 Azure 中创建一个 MySQL 数据库。我们将把这个托管数据库作为 WordPress 应用程序的一部分。这将向您展示如何将应用程序连接到托管数据库。

此外，我们还将向您展示安全性、备份、灾难恢复（DR）、授权和审计日志的方面。还将探讨数据库和集群的独立扩展。我们将把本章的讨论分解为以下主题：

+   OSBA 的设置

+   扩展我们的应用程序以连接到 Azure 数据库

+   探索高级数据库操作

+   审查审计日志

让我们从在我们的集群上设置 OSBA 开始。

## 设置 OSBA

在本节中，我们将在我们的集群上设置 OSBA。OSBA 将允许我们在不离开 Kubernetes 集群的情况下创建一个 MySQL 数据库。我们将从解释使用托管数据库与在 Kubernetes 本身上运行 StatefulSets 的好处开始本节。

### 使用托管数据库服务的好处

到目前为止，我们所讨论的所有示例都是自包含的，也就是说，一切都在 Kubernetes 集群内运行。几乎任何生产应用程序都有状态，通常存储在数据库中。虽然在大部分情况下基本上是云无关的有很大的优势，但在管理数据库等有状态工作负载时却有很大的劣势。

当您在 Kubernetes 集群上运行自己的数据库时，您需要关注可伸缩性、安全性、高可用性、灾难恢复和备份。云提供商提供的托管数据库服务可以减轻您或您的团队执行这些任务的负担。例如，Azure Database for MySQL 具有企业级安全性和合规性、内置高可用性和自动备份。该服务可以在几秒钟内扩展，并且可以非常容易地配置为灾难恢复。

从 Azure 消费生产级数据库要比在 Kubernetes 上设置和管理自己的数据库简单得多。在下一节中，我们将探讨 Kubernetes 如何用于在 Azure 上创建这些数据库的方法。

### 什么是 OSBA？

在本节中，我们将探讨 OSBA 是什么。

与如今大多数应用程序一样，大部分工作已经由开源社区（包括微软员工）为我们完成。微软已经意识到许多用户希望从 Kubernetes 使用其托管服务，并且他们需要一种更容易使用与 Kubernetes 部署相同方法的方式。为了支持这一努力，他们发布了使用这些托管服务作为后端的 Helm 图表 ([`github.com/Azure/helm-charts`](https://github.com/Azure/helm-charts))。

允许您从 Kubernetes 内部创建 Azure 资源的架构的关键部分是 OSBA ([`osba.sh/`](https://osba.sh/))。OSBA 是 Azure 的**开放服务经纪人**（**OSB**）实现。OSB API 是一个规范，定义了云原生应用程序可以使用的平台提供商的通用语言，以管理云服务而无需锁定。

OSB API 本身并不是针对 Azure 或 Kubernetes 的特定。这是一个简化资源供应的行业努力，通过标准化 API 来连接第三方服务。

在使用 Kubernetes 的 OSB API 时，集群上会运行一个名为**服务目录**的扩展。服务目录将监听 Kubernetes API 的请求，并将其转换为 OSB API，以与平台提供商进行接口交互。这意味着当您请求数据库时，Kubernetes API 将该请求发送到服务目录，然后服务目录将使用 OSB API 与平台进行接口交互。*图 8.1*说明了这种逻辑流程：

![用户向 Kubernetes API 请求数据库。然后 Kubernetes API 将此请求转发给服务目录。服务目录然后使用平台上的 OSB API 创建数据库。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.1.jpg)

###### 图 8.1：在 Kubernetes 集群上使用 OSB 请求数据库的逻辑流程

OSBA 是用于多个 Azure 服务的 OSB 实现。它允许用户使用 OSB API 创建 14 种支持的 Azure 服务中的任何一种。其中一个服务是 Azure Database for MySQL。这意味着您可以通过 OSBA 在 Azure 上定义一个 MySQL 数据库，而无需使用 Azure 门户。

在下一节中，我们将专注于如何在我们的集群上安装 OSBA。

### 在集群上安装 OSBA

我们将在我们的集群上安装 OSBA。这个安装有两个元素。首先，我们将在我们的集群上安装服务目录扩展。之后，我们可以在集群上安装 OSBA。

由于我们将在我们的集群上安装多个组件，我们的双节点集群不足以满足这个示例。让我们主动将我们的 AKS 集群扩展到三个节点，这样我们在这个示例中就不会遇到任何问题：

```
az aks scale -n <clustername> -g <cluster resource group> -c 3
```

这个扩展将需要几分钟时间。当集群扩展到三个节点时，我们可以开始部署服务目录到集群上。

**在集群上部署服务目录**

服务目录提供了 OSB 所需的目录服务器。要在集群上部署服务目录，请按照以下步骤进行：

1.  让我们通过运行以下命令来部署服务目录：

```
kubectl create namespace catalog
helm repo add svc-cat https://svc-catalog-charts.storage.googleapis.com
helm install catalog svc-cat/catalog --namespace catalog
```

1.  等待服务目录部署完成。您可以通过运行以下命令来检查：

```
kubectl get all -n catalog
```

1.  验证部署中的两个 Pod 都是`Running`并且完全准备就绪：![输出屏幕表示使用 kubectl get all -n catalog 命令成功部署服务目录。您将看到创建了四种类型的对象，即一个目录 Pod，服务目录，部署目录和复制集目录。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.2.jpg)

###### 图 8.2：成功部署服务目录

1.  要与服务经纪人进行交互，我们需要安装另一个 CLI 工具，即`svcat`。我们可以使用以下命令来完成：

```
curl -sLO https://download.svcat.sh/cli/latest/linux/amd64/svcat
chmod +x ./svcat
./svcat version --client
```

我们现在在我们的集群上配置了一个服务目录。现在，我们可以继续在集群上安装 OSBA。

### 部署 OSBA

在本节中，我们将在我们的集群上部署实际的 OSBA。对于这个设置，我们需要获取订阅 ID、租户 ID、客户 ID 和 OSBA 启动 Azure 服务的凭据：

1.  运行以下命令以获取所需的列表：

```
az account list
```

输出将如*图 8.3*所示：

![屏幕显示所需列表（订阅 ID 和租户 ID），使用 az account list 命令。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.3.jpg)

###### 图 8.3：显示所需列表-订阅 ID 和租户 ID 的输出

1.  复制您的`订阅 ID`以及`租户 ID`并将其保存在环境变量中：

```
export AZURE_SUBSCRIPTION_ID="<SubscriptionId>"
export AZURE_TENANT_ID="<Tenant>"
```

1.  创建一个启用了 RBAC 的服务主体，以便它可以启动 Azure 服务。如果您与其他人共享订阅，请确保服务主体的名称在您的目录中是唯一的：

```
az ad sp create-for-rbac --name osba-quickstart -o table
```

这将生成一个如*图 8.4*所示的输出：

![输出显示服务主体凭据，如 AppID、DisplayName、Name 和密码，使用 az ad sp create-for-rbac --name osba-quickstart -o table 命令。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.4.jpg)

###### 图 8.4：显示服务主体凭据的输出

#### 注意

为了使上一步成功完成，您需要在 Azure 订阅上拥有所有者角色。

1.  将命令输出的值保存在环境变量中：

```
export AZURE_CLIENT_ID="<AppId>"
export AZURE_CLIENT_SECRET="<Password>"
```

1.  现在，我们可以按以下方式部署 OSBA：

```
kubectl create namespace osba
helm repo add azure https://kubernetescharts.blob.core.windows.net/azure
helm install osba azure/open-service-broker-azure \
--namespace osba \
  --set azure.subscriptionId=$AZURE_SUBSCRIPTION_ID \
  --set azure.tenantId=$AZURE_TENANT_ID \
  --set azure.clientId=$AZURE_CLIENT_ID \
  --set azure.clientSecret=$AZURE_CLIENT_SECRET
```

为了验证一切都正确部署了，您可以运行以下命令：

```
kubectl get all -n osba
```

等待直到两个 Pod 都处于`Running`状态。如果其中一个 Pod 处于`Error`状态，您不必担心。OSBA Pods 将自动重新启动并应达到健康状态。在我们的情况下，一个 Pod 重新启动了三次，如*图 8.5*所示：

![输出将显示 OSBA Pods 的状态为 Running，使用 kubectl get all -n osba 命令。在这里，两个 Pod 都处于 Running 状态，其中一个 Pod 重新启动了三次。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.5.jpg)

###### 图 8.5：显示 OSBA Pods 处于 Running 状态的输出

1.  为了验证我们的部署完全成功，我们可以使用我们在上一节中下载的`svcat`实用程序：

```
./svcat get brokers
```

这应该显示您的 Azure 经纪人：

![您可以使用./svcat get brokers 命令查看集群中运行的 Azure 经纪人。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.6.jpg)

###### 图 8.6：显示集群中运行的 Azure 经纪人的输出

1.  您还可以验证通过 OSBA 驱动程序可以部署的所有服务：

```
./svcat get classes
```

这将显示可以使用 OSBA 创建的服务列表，如*图 8.7*所示：

![使用./svcat get classes 命令可以获取（裁剪后的）服务列表。在这里，您可以看到名称以及描述。名称和描述之间的命名空间列为空白。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.7.jpg)

###### 图 8.7：可以使用 OSBA 创建的服务（裁剪后）列表

在本节中，我们在我们的集群上设置了服务目录和 OSBA。这意味着我们现在可以通过 Azure 从我们的集群创建托管服务。在下一节中，当我们使用 Azure 托管的数据库部署 WordPress 时，我们将使用这种能力。

## 部署 WordPress

以下是部署 WordPress 的步骤：

1.  运行以下命令安装 WordPress：

```
kubectl create ns wordpress
helm install wp azure/wordpress --namespace wordpress --set replicaCount=1 --set externalDatabase.azure.location=<your Azure region>
```

1.  要验证 WordPress Pod 的状态，请运行以下命令：

```
kubectl get pods -n wordpress
```

这应该显示单个 WordPress Pod 的状态，如*图 8.8*所示。在我们之前的 WordPress 示例中，我们总是有两个运行的 Pod，但是我们能够在这里将数据库功能卸载到 Azure：

![这张图片显示了 wordpress 部署只创建了一个单独的 pod。您将看到 pod 的名称以及它是否处于 Ready 状态。它还显示了 ContainerCreating 的状态，它重新启动的次数以及获取此状态所花费的时间。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.8.jpg)

###### 图 8.8：仅显示一个 WordPress Pod 和我们集群中没有数据库的输出

1.  在创建 WordPress Pod 时，我们还可以检查数据库的状态。我们可以使用两种工具来获取此状态，要么是`svcat`，要么是`kubectl`：

```
./svcat get instances -n wordpress
```

这将生成如*图 8.9*所示的输出：

![使用./svcat get instances -n wordpress 命令，您可以获取您的 MySQL 实例。您将看到名称，命名空间，类别，计划和状态。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.9.jpg)

###### 图 8.9：显示使用 svcat 获取我们的 MySQL 实例的输出

我们可以使用`kubectl`获得类似的结果：

```
kubectl get serviceinstances -n wordpress
```

这将生成如*图 8.10*所示的输出：

![输出代表使用 svcat 使用 kubectl get serviceinstances -n wordpress 命令获取我们的 MySQL 实例。您将看到名称，类别，计划，状态和年龄。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.10.jpg)

###### 图 8.10：显示使用 kubectl 获取我们的 MySQL 实例的输出

正如您所看到的，每种方法的输出都是相似的。

1.  请给部署几分钟的时间来完成。首先，需要完全配置数据库，然后 WordPress Pod 需要进入“运行”状态。要验证一切是否正常运行，请检查 WordPress Pod 的状态，并确保它处于“运行”状态：

```
kubectl get pods -n wordpress
```

这将生成一个如*图 8.11*所示的输出：

![输出显示了使用 kubectl 获取我们的 MySQL 实例的 kubectl get pods -n wordpress 命令的输出。在一段时间后，您将看到状态更改为 Running。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.11.jpg)

###### 图 8.11：显示 WordPress Pod 的状态的输出

我们现在已经部署了使用 Azure 托管数据库的 WordPress。但是，默认情况下，对我们的数据库的连接是对互联网开放的。我们将在下一节中更改这一点。

### 保护 MySQL

尽管许多步骤都是自动化的，但这并不意味着我们的 MySQL 数据库已经可以投入生产。例如，MySQL 服务器的网络设置具有允许来自任何地方的流量的默认规则。我们将把这个更改为更安全的服务端点规则，也称为**VNet 规则**。

在 Azure 中，服务端点是您用于部署的网络（也称为 VNet）与其连接的服务之间的安全连接。在 AKS 和 MySQL 的情况下，这将在 AKS 部署的 VNet 和 MySQL 服务之间建立安全连接。

在本节中，我们将配置我们的 MySQL 数据库以使用服务端点：

1.  要进行此更改，请在 Azure 搜索栏中搜索`mysql`：![在 Azure 搜索栏中键入 mysql 以找到它。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.12.jpg)

###### 图 8.12：在 Azure 搜索栏中搜索 MySQL

1.  在 MySQL 资源的资源页面中，转到左侧导航中的**连接安全**：![在 MySQL 资源的资源页面中，单击左侧的连接安全选项卡。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.13.jpg)

###### 图 8.13：点击连接安全

1.  有一个默认规则允许从任何 IP 地址连接到数据库。您可以将 AKS VNet 添加到**VNet 规则**部分，并删除**AllowAll 0.0.0.0**规则，如*图 8.14*所示：![在 Azure Database for MySQL 服务器中，单击位于屏幕左侧的连接安全选项卡。这将允许您将 AKS VNet 添加到 VNet 规则部分并删除 AllowAll 规则。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.14.jpg)

###### 图 8.14：将您的 AKS VNet 添加到 VNet 规则部分并删除 AllowAll 规则

通过进行这个简单的改变，我们大大减少了攻击面。现在我们可以连接到我们的 WordPress 网站。

### 连接到 WordPress 网站

您可以通过使用`EXTERNAL_IP`来验证您的博客网站是否可用和运行，该 IP 是通过运行以下命令获得的：

```
kubectl get service -n wordpress
```

这将生成一个如*图 8.15*所示的输出：

![使用 kubectl get service -n wordpress 命令显示服务的外部 IP。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.15.jpg)

###### 图 8.15：显示服务外部 IP 的输出

然后，打开一个网页浏览器，转到`http://<EXTERNAL_IP>/`。您应该会看到您全新的博客：

![屏幕将显示 WordPress 博客的默认外观。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.16.jpg)

###### 图 8.16：WordPress 博客的最终外观

在本节中，我们启动了一个由 Azure 托管的 WordPress 网站，并对其进行了防火墙修改以确保安全。在接下来的部分，我们将介绍让 Azure 管理数据库的优势。

## 探索高级数据库操作

在 Azure 顶层作为托管服务运行数据库有许多优势。在本节中，我们将探讨这些好处。我们将探讨从备份中恢复，如何设置灾难恢复以及如何访问审计日志以验证谁对您的数据库进行了更改。

我们将从备份中恢复我们的数据库开始。

### 从备份恢复

当您在 Kubernetes 集群中运行数据库时，**高可用性**（**HA**）、备份和灾难恢复是您的责任。让我们花点时间来解释这三个概念之间的区别：

+   **HA**：HA 指的是服务的本地冗余，以确保在单个组件故障时服务仍然可用。这意味着设置服务的多个副本并协调它们之间的状态。在数据库上下文中，这意味着设置数据库集群。

Azure Database for MySQL 服务内置了 HA。在撰写本文时，它提供了每月 99.99%的可用性 SLA。

+   **备份**：备份是指对数据进行历史性的复制。当数据发生意外情况时，如意外数据删除或数据被覆盖时，备份是非常有用的。如果您自己运行数据库，您需要设置`cron`作业来进行备份并将其单独存储。

Azure Database for MySQL 会自动处理备份，无需额外配置。该服务每 5 分钟进行一次备份，并使您能够恢复到任何时间点。备份默认保留 7 天，可选配置使备份保留时间延长至 25 天。

+   **DR**：DR 指的是系统从灾难中恢复的能力。这通常指的是从完全区域性停机中恢复的能力。如果您运行自己的数据库，这将涉及在第二区域设置一个辅助数据库，并将数据复制到该数据库。

在 Azure Database for MySQL 的情况下，很容易配置 DR。该服务可以设置一个辅助托管数据库，并将数据从主要区域复制到辅助区域。

#### 注意

您可以参考[`docs.microsoft.com/azure/mysql/concepts-backup`](https://docs.microsoft.com/azure/mysql/concepts-backup)获取有关备份频率、复制和恢复选项的最新信息。

术语 HA、备份和 DR 经常被混淆。使用正确的术语并理解这三个概念之间的区别非常重要。在本节中，我们将重点关注备份，并从我们的 WordPress 数据库执行恢复。为了证明恢复操作将恢复用户数据，我们将首先创建一个博客帖子。

**在 WordPress 上创建博客帖子**

我们将创建一篇博客文章，以证明恢复操作将捕获我们在数据库上生成的新数据。为了能够发布这篇文章，我们需要我们站点的管理员凭据。我们将首先获取这些凭据，然后发布一篇新文章：

1.  要获取管理员凭据，请使用以下命令：

```
echo Password: $(kubectl get secret --namespace wordpress \
  wp-wordpress -o jsonpath="{.data.wordpress-password}" | \
  base64 --decode)
```

这将显示您连接到管理员网站的密码：

![使用 Helm 提供的命令获取 WordPress 管理员用户的密码。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.17.jpg)

###### 图 8.17：获取管理员凭据

1.  现在浏览`http://<EXTERNAL IP>/admin`以打开 WordPress 站点的管理页面。使用用户名`user`和上一步的密码登录。

1.  连接后，选择**撰写您的第一篇博客文章**链接：![在仪表板上，您将看到一个欢迎消息，您将在“下一步”标题下找到“撰写您的第一篇博客文章”的链接。单击此链接。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.18.jpg)

###### 图 8.18：单击链接撰写帖子

1.  创建一篇博客文章。内容并不重要。一旦您满意您的博客文章，选择**发布**按钮保存并发布博客文章：![在博客上输入内容后，转到窗口右侧的发布选项卡。点击该选项卡下的发布按钮来保存并发布。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.19.jpg)

###### 图 8.19：创建一个示例博客文章并点击发布按钮保存

1.  您现在可以连接到`http://<EXTERNAL IP>`来查看您的博客文章：![单击发布按钮后，您将看到一个白屏，上面有一条消息-这篇博客文章将确认备份和恢复。这显示了博客文章的成功状态。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.20.jpg)

###### 图 8.20：显示博客文章成功状态的提示

现在我们已经保存了一篇博客文章，请至少等待 5 分钟。Azure 每 5 分钟对 MySQL 数据库进行一次备份，我们要确保我们的新数据已经备份。一旦过了这 5 分钟，我们就可以继续下一步，执行实际的恢复。

**执行恢复**

现在我们的博客和数据库中都有实际内容。假设在更新过程中，数据库损坏了，所以我们想进行时间点恢复：

1.  要开始恢复操作，请在 Azure 门户中的 MySQL 选项卡上点击**恢复**：![在 Azure Database for MySQL servers 门户中，您会看到屏幕顶部有一个“恢复”按钮。点击它来启动恢复过程。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.21.jpg)

###### 图 8.21：点击恢复按钮来启动恢复过程

1.  然后，您需要选择要执行恢复的时间点。这个时间点可以是当前时间。给恢复的数据库起一个名字，这个名字必须是唯一的，如*图 8.22*所示。最后，点击**确定**。大约 5 到 10 分钟后，MySQL 服务应该会恢复：![单击“恢复”按钮后，将会弹出一个窗口，您需要在其中输入要执行恢复的日期和时间。给恢复的数据库起一个唯一的名字，然后点击确定。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.22.jpg)

###### 图 8.22：选择要恢复的时间点并点击确定按钮

在本节中，我们恢复了我们的 MySQL 数据库。当恢复操作完成后，还有一步需要完成，那就是将 WordPress 连接到恢复的数据库。

**将 WordPress 连接到恢复的数据库**

恢复操作创建了数据库的新实例。为了使我们的 WordPress 安装连接到恢复的数据库，我们需要修改 Kubernetes 部署文件。理想情况下，您将修改 Helm 值文件并执行 Helm 升级；然而，这超出了本书的范围。以下步骤将帮助您将 WordPress 连接到恢复的数据库：

1.  从 Azure 门户中，记下**服务器名称**，如*图 8.23*所示：![屏幕显示了恢复的数据库的详细信息。记下门户右上角给出的服务器名称。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.23.jpg)

###### 图 8.23：显示恢复的数据库的完整名称

1.  还要修改**连接安全性**，就像之前一样，以允许集群与恢复的数据库通信。删除所有规则并向 AKS 集群的网络添加 VNet 规则。结果如*图 8.24*所示：![在 Azure Database for MySQL 服务器中，单击位于屏幕左侧导航窗格上的连接安全选项卡。当您编辑信息时，屏幕将显示“未配置防火墙”的消息。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.24.jpg)

###### 图 8.24：编辑恢复的数据库的连接安全性

1.  接下来，我们需要将我们的 WordPress Pod 连接到新的数据库。让我们指出这是如何发生的。要获取这些信息，请运行以下命令：

```
kubectl describe deploy wp -n wordpress
```

您可以看到连接到数据库的值是从一个 secret 中获取的，如*图 8.25*所示：

![输出显示一系列环境变量，如主机、端口号、数据库名称、数据库用户和密码。连接数据库到 WordPress 的值是从一个 Secret 中获取的。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.25.jpg)

###### 图 8.25：显示 WordPress Pod 的环境变量

在设置 WordPress 时，安装程序将在文件`/bitname/wordpress/wp-config.php`中保存此配置。在接下来的步骤中，我们将首先编辑 secret，然后重新配置`wp-config.php`。

1.  要设置 secrets，我们需要`base64`值。通过运行以下命令获取服务器名称的`base64`值：

```
echo <restored db server name> | base64
```

注意`base64`值。

1.  现在，我们将继续编辑 Secret 中的主机名。为此，我们将使用`edit`命令：

```
kubectl edit secret wp-wordpress-mysql-secret -n wordpress
```

这将打开一个`vi`编辑器。导航到包含`host`的行并按`I`按钮。删除主机的当前值，并粘贴新的`base64`编码值。然后按*Esc*，输入：`wq!`，然后按*Enter*。您的密钥应如*图 8.26*所示：

![打开 vi 编辑器后，导航到主机行。删除主机的当前值，并粘贴 base64 编码的值。这将更改密钥。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.26.jpg)

###### 图 8.26：编辑主机行，包含新服务器名称的 base64 编码值

1.  接下来，我们还需要在`wp-config.php`文件中进行更改。为此，让我们`exec`进入当前的 WordPress 容器并更改该值：

```
kubectl exec -it <wordpress pod name> -n wordpress sh
apt update
apt install vim -y
vim /bitnami/wordpress/wp-config.php
```

这将再次打开`vi`编辑器。导航到包含`DB_HOST`配置行的第 32 行。按`I`进入插入模式，删除当前值，并用*图 8.27*中显示的恢复数据库的名称替换。然后按*Esc*，输入：`wq!`，然后按*Enter*。确保粘贴真实值，而不是`base64`编码的值：

![在 vi 编辑器中，转到包含数据库主机名的第 32 行。将此名称替换为恢复数据库的名称。这将生成一个显示恢复数据库名称的输出屏幕。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.27.jpg)

###### 图 8.27：将数据库名称更改为恢复的数据库

然后，使用以下命令退出 Pod：

```
exit
```

尽管我们现在已重置了密钥值和配置文件，但这并不意味着我们的服务器会自动获取新值。我们现在必须重新启动 Pod，以确保配置再次被读取。

1.  有许多方法可以做到这一点，我们将删除现有的 Pod。一旦删除了这个 Pod，我们的`ReplicaSet`控制器将注意到这一点并创建一个新的 Pod。要删除 Pod，请使用以下命令：

```
kubectl delete pod <wordpress pod name> -n wordpress
```

1.  几秒钟后，您应该看到正在创建一个新的 Pod。新的 Pod 上线需要 5 到 10 分钟。一旦上线，您可以观看该 Pod 的容器日志，并验证您确实连接到了新的数据库：

```
kubectl logs <new wordpress pod> -n wordpress
```

这应该包含如*图 8.28*所示的一行：

![kubectl logs <new wordpress pod> -n wordpress 命令生成一个输出，显示连接到恢复数据库的 WordPress Pod 的日志。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.28.jpg)

###### 图 8.28：显示连接到恢复数据库的 WordPress Pod 的日志

这表明我们现在已连接到我们恢复的数据库。我们可以确认实际内容已经恢复。您可以通过浏览到`http://<EXTERNAL IP>`来连接到 WordPress 网站本身：

![单击连接到 WordPress 网站后，您将看到一个白屏，上面显示着一条消息，确认备份和恢复。这表明博客文章已成功恢复。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.29.jpg)

###### 图 8.29：显示博客文章成功恢复的说明

在本节中，我们探讨了 Azure Database for MySQL 的备份和恢复能力。我们发布了一篇博客文章，并恢复了存储该博客文章的数据库。我们将我们的 WordPress 实例连接到恢复的数据库，并能够验证博客文章已成功恢复。

执行备份只是 Azure Database for MySQL 的能力之一。在下一节中，我们将探讨该服务的灾难恢复能力。

### 灾难恢复（DR）选项

根据您的应用程序要求和灾难恢复需求，您可以向 MySQL 服务器添加副本。副本可以在同一区域创建，以提高读取性能，也可以在辅助区域创建。

如果您正在为灾难恢复场景做准备，您需要在辅助区域设置一个副本。这将保护您免受 Azure 区域性故障的影响。设置这一点时，Azure 将会异步地将数据从主服务器复制到您设置的副本服务器。在复制进行时，副本服务器可以用于读取，但不能用于写入。如果发生灾难，意味着 Azure 区域发生了区域性故障，您需要停止复制，将副本服务器变成一个能够同时提供读取和写入请求的服务器。

在新区域创建副本非常简单。虽然设置和测试复制不在本书的范围内，但我们将展示如何设置。要配置复制，您需要在 MySQL 刀片中打开**复制**选项卡，如*图 8.30*所示：

![要通过 Azure 门户创建副本，请单击导航窗格左侧的 MySQL 刀片中的复制选项卡。副本不显示任何结果。在屏幕右侧输入服务器名称和位置。这将显示每月成本。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.30.jpg)

###### 图 8.30：通过 Azure 门户创建副本

#### 注意

备份、恢复和复制选项的完整列表在[`docs.microsoft.com/azure/mysql/concepts-backup`](https://docs.microsoft.com/azure/mysql/concepts-backup)和[`docs.microsoft.com/azure/mysql/concepts-read-replicas`](https://docs.microsoft.com/azure/mysql/concepts-read-replicas)中有文档记录。

在本节中，我们描述了 Azure Database for MySQL 复制到辅助区域的能力。这个副本可以用来为您的数据库构建 DR 策略。在下一节中，我们将介绍如何使用活动日志来审计谁对您的服务器进行了更改。

### 审查审计日志

数据库包含业务关键数据。您将希望有一个日志记录系统，可以显示谁对您的数据库进行了更改。

当您在 Kubernetes 集群上运行数据库时，如果出现问题，很难获取审计日志。您需要一种强大的动态设置审计级别的方式，具体取决于情况。您还必须确保日志被运送到集群外部。

Azure Database for MySQL 服务通过 Azure 门户提供了强大的审计机制来解决上述问题。该服务有两种不同的日志视图：

+   **活动日志**：活动日志显示发生在数据库 Azure 对象上的所有更改。Azure 记录所有针对 Azure 资源的创建、更新和删除事务，并将这些日志保存 90 天。对于 MySQL 来说，这意味着对大小、备份和复制设置等的所有更改。这些日志对于确定谁对您的数据库进行了更改非常有用。

+   **服务器日志**：服务器日志包括来自数据库中实际数据的日志。MySQL 有多个可配置的日志可用。通常建议打开审计日志以验证谁访问了您的数据库，并打开慢查询监视以跟踪运行缓慢的任何查询。

让我们一起看看这两种日志：

1.  要访问活动日志，请在 Azure 门户中打开 MySQL 数据库刀片。在左侧导航中，寻找**活动日志**。这将打开活动日志视图，如*图 8.31*所示：![单击 Azure 门户左侧窗格中的活动日志选项卡。您将看到针对相应 Azure 数据库执行的操作。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.31.jpg)

###### 图 8.31：Azure 活动日志显示针对 Azure 数据库执行的操作

活动日志提供了非常有价值的信息，可以追溯已执行的活动。您应该在活动日志中找到指向您之前对连接安全设置所做更改的事件。

1.  服务器日志可以通过在左侧导航中查找**服务器日志**来获取。服务器日志默认情况下未打开，如*图 8.32*所示：![如果您在 Azure 门户的导航窗格左侧单击服务器日志选项卡，它将指示默认情况下没有服务器日志。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.32.jpg)

###### 图 8.32：导航显示默认情况下没有服务器日志

1.  让我们打开服务器日志。我们将通过启用`log_slow...`语句和`slow_query_log`来启用审计日志和性能监控，如*图 8.33*所示：![一旦服务器参数页面打开，点击名称为 log_slow...语句和 slow_query_log 的参数。确保它们的值为 ON。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.33.jpg)

###### 图 8.33：启用审计日志和慢查询日志

一旦您打开了这些日志，实际日志将需要几分钟时间才能显示出来。几分钟后，您应该在 Azure 门户中的**服务器日志**选项卡中看到日志，如*图 8.34*所示：

![几分钟后，您可以通过单击 MySQL 刀片左侧导航窗格上的服务器日志选项卡来查看实际日志。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_8.34.jpg)

###### 图 8.34：在 Azure 门户中显示服务器日志

让我们确保在部署后再次清理并将我们的集群缩减到两个节点。缩减到两个节点将确保您在 Azure 订阅上节省成本：

```
helm delete wp -n wordpress
helm delete osba -n osba
helm delete catalog -n catalog
kubectl delete ns wordpress osba catalog
az aks scale -n <clustername> -g <cluster resource group> -c 2
```

在本节中，我们介绍了 Azure 为 MySQL 数据库生成的两种日志类型。我们查看了活动日志，以查看针对 Azure 数据库执行了哪些操作，并打开了服务器日志，以了解数据库内部发生了什么。

## 总结

本章重点介绍了使用 WordPress 示例解决方案，该解决方案利用 MySQL 数据库作为数据存储。我们首先向您展示了如何通过安装 Azure 的 Open Service Broker 来设置集群，以连接 MySQL 数据库。然后，我们向您展示了如何设置 MySQL 数据库，并通过更改默认配置来大大减少数据库的攻击面，从而不允许公共访问数据库。接着，我们讨论了如何从备份中恢复数据库，以及如何利用解决方案进行灾难恢复。最后，我们讨论了如何配置审计日志以进行故障排除。

在下一章中，您将学习如何在 AKS 上实现微服务，包括使用事件中心实现应用程序之间的松耦合集成。


# 第九章：连接到 Azure 事件中心

基于事件的集成是实现微服务的关键模式。微服务架构的理念是将单体应用程序分解为一组较小的服务。事件通常用于协调这些不同的服务之间。当您考虑一个事件时，它可以是许多事物之一。金融交易可以是一个事件，同样的，IoT 传感器数据、网页点击和浏览等也可以是事件。

处理这些类型事件的常用软件是 Apache Kafka（简称 Kafka）。Kafka 最初由 LinkedIn 开发，后来捐赠给 Apache 软件基金会。它是一个流行的开源流平台。流平台具有三个核心能力：发布和订阅消息流（类似于队列），以持久方式存储这些流，并在发生时处理这些流。

Azure 有一个类似于 Apache Kafka 的服务，称为 Azure 事件中心。事件中心是一个提供实时数据摄入的托管服务。它易于设置和使用，并且可以动态扩展。事件中心还与其他 Azure 服务集成，如流分析、函数和 databricks。这些预构建的集成使您更容易构建从事件中心消费事件的应用程序。

事件中心还提供 Kafka 端点。这意味着您可以配置现有的基于 Kafka 的应用程序，并将其指向事件中心。使用事件中心来处理 Kafka 应用程序的好处是您不再需要管理 Kafka 集群，因为您可以将其作为托管服务来使用。

在本章中，您将学习如何在 AKS 上实现微服务，并使用事件中心在应用程序之间实现松耦合集成。您将部署一个使用 Kafka 发送事件的应用程序，并用 Azure 事件中心替换您自己的 Kafka 集群。正如您将在本章中学到的，基于事件的集成是单体和基于微服务的应用程序之间的关键区别之一。

+   部署一组微服务

+   使用 Azure 事件中心

我们将从部署一组构建社交网络的微服务开始本章。

## 部署一组微服务

在本节中，我们将部署一个来自名为社交网络的演示应用程序的一组微服务。该应用程序由两个主要的微服务组成：**用户**和**好友**。用户服务将所有用户存储在自己的数据存储中。用户由 ID、名和姓表示。好友服务存储用户的好友。好友关系链接了两个好友的用户 ID，并且还有自己的 ID。

添加用户/添加好友的事件被发送到消息队列。该应用程序使用 Kafka 作为消息队列，用于存储与用户、好友和推荐相关的事件。

这个队列被一个推荐服务所消费。这个服务由一个**Neo4j**数据库支持，可以用来查询用户之间的关系。Neo4j 是一个流行的图形数据库平台。图形数据库不同于典型的关系数据库，如 MySQL。图形数据库专注于存储不同元素之间的关系。您可以用问题查询图形数据库，比如*给我用户 X 和用户 Y 的共同好友*。

在数据流方面，您可以创建用户和友谊关系。创建用户或友谊关系将在消息队列上生成一条消息，这将导致数据在 Neo4j 数据库中填充。该应用程序没有 Web 界面。您主要将使用命令行与应用程序进行交互，尽管我们可以连接到 Neo4j 数据库以验证数据是否已填充到数据库中。

在接下来的部分，您将学习以下内容：

+   使用 Helm 部署一个示例基于微服务的应用程序。

+   通过发送事件并观察对象的创建和更新来测试服务。

让我们从部署应用程序开始。

### 使用 Helm 部署应用程序

在本节中，我们将使用 Helm 部署演示应用程序。这将使用本地 Kafka 实例部署完整的应用程序。应用程序部署后，我们将生成一个小型社交网络，并验证我们能够创建该社交网络。

1.  这个示例有很多资源需求。为了满足这些需求，将您的集群扩展到四个节点：

```
az aks nodepool scale --node-count 4 -g rg-handsonaks \
  --cluster-name handsonaks --name agentpool
```

1.  这个示例的代码已经包含在本书的 GitHub 存储库中。您可以在`Chapter09`文件夹下的`social-network`文件夹中找到代码。导航到这个文件夹：

```
cd Chapter09/social-network
```

1.  要运行 Kafka，我们还需要运行**ZooKeeper**。ZooKeeper 是 Apache 基金会的另一个开源软件项目。它提供命名、配置管理、同步和分组服务的能力。我们将使用`bitnami`的 Kafka 和 ZooKeeper Helm 图表，因此让我们添加所需的 Helm 存储库：

```
helm repo add bitnami https://charts.bitnami.com
helm repo add incubator https://kubernetes-charts-incubator.storage.googleapis.com
```

这将生成如*图 9.1*所示的输出：

![输出屏幕显示两个 Helm 存储库，bitnami 和 incubator，被添加到您的存储库中。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.1.jpg)

###### 图 9.1：添加 Helm 存储库

1.  让我们更新依赖项以使依赖图表可用：

```
helm dep update deployment/helm/social-network
helm dep update deployment/helm/friend-service
helm dep update deployment/helm/user-service
helm dep update deployment/helm/recommendation-service
```

这将显示类似于*图 9.2*的内容四次：

![为了使依赖图表可用，输出屏幕将显示成功接收来自 svc-cat、incubator、azure、jetstack、bitnami 和 stable 等四个依赖项更新的单独消息。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.2.jpg)

###### 图 9.2：更新依赖项

#### 注意

在此示例中，您可能会看到类似于以下内容的警告：`walk.go:74: found symbolic link in path:`。这是一个可以安全忽略的警告。

1.  接下来，为此应用程序创建一个新的`namespace`：

```
kubectl create namespace social-network
```

这将生成如下输出：

![使用 kubectl create namespace social-network 命令，创建一个新的命名空间。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.3.jpg)

###### 图 9.3：创建一个新的命名空间

1.  现在，继续部署应用程序：

```
helm install social-network --namespace social-network \
  --set fullNameOverride=social-network \
  --set edge-service.service.type=LoadBalancer \
  deployment/helm/social-network
```

1.  使用以下命令检查部署中 Pod 的状态：

```
kubectl get pods -w -n social-network
```

正如您在*图 9.4*中所看到的，大约需要 5 分钟才能使所有的 Pod 都正常运行起来：

![输出显示共有 20 个状态为 Running 的 Pod。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.4.jpg)

###### 图 9.4：显示所有状态为 Running 的 Pod 的输出

1.  应用程序成功部署后，您可以连接到边缘服务。要获取其 IP，请使用以下命令：

```
kubectl get service -n social-network
```

此命令将生成如下输出：

![您可以使用 kubectl get service -n social-network 命令获取 edge-service 的外部 IP。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.5.jpg)

###### 图 9.5：获取边缘服务的外部 IP

1.  您可以进行两个测试来验证应用程序是否正常工作。测试 1 是在浏览器中连接端口`9000`上的边缘服务。*图 9.6*显示了 Whitelabel 错误页面，显示应用程序正在运行：![Whitelabel 错误页面将显示应用程序没有配置错误视图，因此您看到这个作为后备。这表明应用程序正在运行。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.6.jpg)

###### 图 9.6：Whitelabel 错误页面，显示应用程序正在运行

1.  验证应用程序是否运行的第二个测试是实际生成一个小型社交网络。这将验证所有服务是否正常工作。您可以使用以下命令创建这个网络：

```
bash ./deployment/sbin/generate-serial.sh <external-ip>:9000
```

这个命令将生成大量输出。输出将以*图 9.7*中显示的元素开头：

![在创建新的社交网络时，初始输出屏幕将显示名字、姓氏、创建日期和时间、上次修改日期和时间以及一个 ID。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.7.jpg)

###### 图 9.7：创建新的社交网络时的初始输出

1.  生成一个 15 人的网络大约需要一分钟的时间。要验证网络是否已成功创建，请在您的网络浏览器中浏览到[`http://<external-ip>:9000/user/v1/users/1`](http://<external-ip>:9000/user/v1/users/1)。这应该会显示一个代表社交网络中用户的小 JSON 对象，如*图 9.8*所示：![在用户服务中成功创建用户后，访问<external-ip>:9000/user/v1/users/1 的输出屏幕将显示用户的名字和姓氏、创建日期和时间以及上次修改日期和时间。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.8.jpg)

###### 图 9.8：用户服务中成功创建用户

1.  最后，您可以连接到 Neo4j 数据库并可视化您创建的社交网络。要能够连接到 Neo4j，您需要首先将其公开为一个服务。使用社交网络文件夹中的`neo4j-service.yaml`文件来公开它：

```
kubectl create -f neo4j-service.yaml -n social-network
```

然后，获取服务的公共 IP 地址。这可能需要大约一分钟才能使用：

```
kubectl get service neo4j-service -n social-network 
```

上述命令将生成以下输出：

![输出显示了 Neo4j 服务的外部 IP 地址。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.9.jpg)

###### 图 9.9：显示 Neo4j 服务的外部 IP 地址的输出

#### 注意

请注意，Neo4j 服务的外部 IP 可能与边缘服务的外部 IP 不同。

1.  使用浏览器连接到[`http://<external-ip>:7474`](http://<external-ip>:7474)。这将打开一个登录屏幕。使用以下信息登录：

+   **连接 URL**：`bolt://<external-ip>:7678`

+   **用户名**：`neo4j`

+   **密码**：`neo4j`

您的连接信息应该类似于*图 9.10*：

![要登录 Neo4j 服务，用户必须在连接 URL 字段中输入 bolt://<external-ip>:7687，将用户名设置为 neo4j，密码设置为 neo4j。然后他们需要点击密码字段下面的连接选项卡。这将帮助他们登录浏览器。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.10.jpg)

###### 图 9.10：登录到 Neo4j 浏览器

1.  一旦连接到 Neo4j 浏览器，您可以看到实际的社交网络。点击**数据库信息**图标，然后点击**用户**。这将生成一个查询，显示您刚刚创建的社交网络。这将类似于*图 9.11*：![社交网络的输出屏幕分为两部分。屏幕的左侧显示数据库信息，如节点标签、关系类型、属性键和数据库，而屏幕的其余部分显示用户(14)和朋友(149)的名称。输出还包含所创建的社交网络的图形表示。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.11.jpg)

###### 图 9.11：您刚刚创建的社交网络的视图

在当前示例中，我们已经设置了端到端的应用程序，使用在我们的 Kubernetes 集群上运行的 Kafka 作为消息队列。在我们进入下一节之前，让我们删除该示例。要删除本地部署，请使用以下命令：

```
helm delete social-network -n social-network
kubectl delete pvc -n social-network --all
kubectl delete pv --all
```

在下一节中，我们将摆脱在集群中存储事件，并将它们存储在 Azure 事件中心。通过利用 Azure 事件中心上的本机 Kafka 支持，并切换到使用更适合生产的事件存储，我们将看到这个过程是简单的。

## 使用 Azure 事件中心

自己在集群上运行 Kafka 是可能的，但对于生产使用可能很难运行。在本节中，我们将把维护 Kafka 集群的责任转移到 Azure 事件中心。事件中心是一个完全托管的实时数据摄入服务。它原生支持 Kafka 协议，因此，通过轻微修改，我们可以将我们的应用程序从使用本地 Kafka 实例更新为可扩展的 Azure 事件中心实例。

在接下来的几节中，我们将执行以下操作：

+   通过门户创建事件中心并收集连接我们基于微服务的应用程序所需的详细信息

+   修改 Helm 图表以使用新创建的事件中心

让我们开始创建事件中心。

### 创建事件中心

在本节中，我们将创建 Azure 事件中心。稍后我们将使用此事件中心来流式传输新消息。执行以下步骤创建事件中心：

1.  要在 Azure 门户上创建事件中心，请搜索`事件中心`，如*图 9.12*所示：![在搜索栏选项卡中，用户需要输入“事件中心”以在 Azure 门户中创建事件中心。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.12.jpg)

###### 图 9.12：在搜索栏中查找事件中心

1.  点击**事件中心**。

1.  在**事件中心**选项卡上，点击**添加**，如*图 9.13*所示：![要添加新的事件中心，用户需要点击屏幕最左侧的+添加选项卡。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.13.jpg)

###### 图 9.13：添加新的事件中心

1.  填写以下细节：

+   **名称**：此名称应是全局唯一的。考虑在名称中添加您的缩写。

+   **定价层**：选择标准定价层。基本定价层不支持 Kafka。

+   **使此命名空间区域多余**：已禁用。

+   **Azure 订阅**：选择与托管 Kubernetes 集群的订阅相同的订阅。

+   **资源组**：选择我们为集群创建的资源组，在我们的情况下是`rg-handsonaks`。

+   **位置**：选择与您的集群相同的位置。在我们的情况下，这是`West US 2`。

+   **吞吐量单位**：1 个单位足以进行此测试。

+   **自动膨胀**：已禁用。

这应该给您一个类似于*图 9.14*的创建视图：

![有各种需要填写的字段。定价层应设置为标准，使此命名空间区域冗余选项应禁用，吞吐量单位应设置为 1，自动膨胀选项应禁用，并且名称、订阅、资源组和位置字段也需要填写。在这些字段的底部，您将看到创建选项卡。这就是您的事件中心创建的样子。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.14.jpg)

###### 图 9.14：您的事件中心创建应该是这样的

1.  点击向导底部的**创建**按钮来创建您的事件中心。

1.  一旦事件中心创建完成，选择它，如*图 9.15*所示：![一旦事件中心创建完成，您将被引导到一个窗口，在那里您可以在门户上查看事件中心。您需要通过点击事件中心的名称来选择它。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.15.jpg)

###### 图 9.15：一旦创建，点击事件中心名称

1.  点击**共享访问策略**，选择**RootManageSharedAccessKey**，并复制**连接字符串-主密钥**，如*图 9.16*所示：![这个屏幕显示了获取事件中心连接字符串的过程。第一步是在左侧菜单中点击共享访问策略。第二步是选择 RootManageSharedAccessKey 策略，第三步是点击主连接字符串旁边的复制图标。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.16.jpg)

###### 图 9.16：复制主连接字符串

使用 Azure 门户，我们已经创建了一个事件中心，可以存储和处理生成的事件。我们需要收集连接字符串，以便连接我们的基于微服务的应用程序。在下一节中，我们将重新部署我们的社交网络，并配置它连接到事件中心。为了能够部署我们的社交网络，我们将不得不对 Helm 图表进行一些更改，以便将我们的应用程序指向事件中心而不是 Kafka。

### 修改 Helm 文件

我们将把微服务部署从使用本地 Kafka 实例切换到使用 Azure 托管的、与 Kafka 兼容的事件中心实例。为了做出这个改变，我们将修改 Helm 图表，以使用事件中心而不是 Kafka：

1.  修改`values.yaml`文件，以禁用集群中的 Kafka，并包括连接细节到您的事件中心：

```
code deployment/helm/social-network/values.yaml
```

确保更改以下值：

**第 5、18、26 和 34 行**：将其更改为`enabled: false`。

**第 20、28 和 36 行**：将其更改为您的事件中心名称。

**第 21、29 和 37 行**：将其更改为您的事件中心连接字符串：

```
1   nameOverride: social-network
2   fullNameOverride: social-network
3
4   kafka:
5     enabled: true
6     nameOverride: kafka
7     fullnameOverride: kafka
8     persistence:
9       enabled: false
10    resources:
11      requests:
12        memory: 325Mi
13   
14   
15  friend-service:
16    fullnameOverride: friend-service
17    kafka:
18      enabled: true
19    eventhub:
20      name: <event hub name>
21      connection: "<event hub connection string>"
22   
23  recommendation-service:
24    fullnameOverride: recommendation-service
25    kafka:
26      enabled: true
27    eventhub:
28      name: <event hub name>
29      connection: "<event hub connection string>"
30
31  user-service:
32    fullnameOverride: user-service
33    kafka:
34      enabled: true
35    eventhub:
36      name: <event hub name>
37      connection: "<event hub connection string>"
```

#### 注意

对于我们的演示，我们将连接字符串存储在 Helm 值文件中。这不是最佳实践。对于生产用例，您应该将这些值存储为秘密，并在部署中引用它们。我们将在*第十章*，*保护您的 AKS 集群*中探讨这一点。

1.  按照以下方式运行部署：

```
helm install social-network deployment/helm/social-network/ -n social-network --set edge-service.service.type=LoadBalancer
```

1.  等待所有的 Pod 启动。您可以使用以下命令验证所有的 Pod 是否已经启动并正在运行：

```
kubectl get pods -n social-network
```

这将生成以下输出：

![屏幕上显示的 14 个 Pod 显示它们的运行状态为 Running。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.17.jpg)

###### 图 9.17：输出显示所有 Pod 的运行状态

1.  要验证您是否连接到事件中心，而不是本地 Kafka，您可以在门户中检查事件中心，并检查不同的主题。您应该会看到一个 friend 和一个 user 主题，如*图 9.18*所示：![当您在屏幕左侧的菜单中滚动时，您会看到实体选项卡。点击其中的事件中心。您将看到在您的事件中心中创建的两个主题。这些主题的名称应该是 friend 和 user。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.18.jpg)

###### 图 9.18：显示在您的事件中心创建的两个主题

1.  继续观察 Pod。当所有的 Pod 都已启动并正在运行时，获取边缘服务的外部 IP。您可以使用以下命令获取该 IP：

```
kubectl get svc -n social-network
```

1.  然后，运行以下命令验证实际社交网络的创建：

```
bash ./deployment/sbin/generate-serial.sh <external-ip>:9000
```

这将再次创建一个包含 15 个用户的社交网络，但现在将使用事件中心来发送所有与用户、好友和推荐相关的事件。

1.  您可以在 Azure 门户上看到这些活动。Azure 门户为事件中心创建了详细的监控图表。要访问这些图表，请点击**friend**事件中心，如*图 9.19*所示：![在屏幕左侧的导航窗格中，向下滚动到实体部分。点击事件中心。您会看到两个主题：friend 和 user。点击 friend 主题以获取更多指标。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.19.jpg)

###### 图 9.19：点击 friend 主题以获取更多指标

在*图 9.20*中，您可以看到 Azure 门户为您提供了三个图表：请求的数量、消息的数量和总吞吐量：

![Azure 门户显示了主题的三个图表。这些高级图表提供了请求的数量，消息的数量和总吞吐量。这些图表的底部都有一个蓝色图标，表示传入请求，传入消息和传入字节。您还将看到一个橙色图标，表示成功的请求，传出消息和传出字节。图片中的图表显示了上升的尖峰。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.20.jpg)

###### 图 9.20：默认情况下显示高级图表

您可以进一步深入研究各个图表。例如，单击消息图表。这将带您进入 Azure 监视器中的交互式图表编辑器。您可以按分钟查看事件中心的进出消息数量，如*图 9.21*所示：

![单击第二个图表，表示消息数量，您将看到更多详细信息。除了蓝色和橙色图标外，您还将看到靛蓝色和水绿色图标，分别表示捕获的消息和捕获积压（总和）。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.21.jpg)

###### 图 9.21：单击图表以获取更多详细信息

让我们确保清理我们刚刚创建的部署，并将我们的集群缩减回去：

```
helm delete social-network -n social-network
kubectl delete pvc -n social-network --all
kubectl delete pv --all
kubectl delete service neo4j-service -n social-network
az aks nodepool scale --node-count 2 -g rg-handsonaks \
  --cluster-name handsonaks --name agentpool
```

您还可以在 Azure 门户中删除事件中心。要删除事件中心，请转到事件中心的**概述**页面，并选择**删除**按钮，如*图 9.22*所示。系统会要求您重复事件中心的名称，以确保您不会意外删除它：

![单击左侧屏幕上的导航窗格中的概述。您将看到您创建的事件中心的详细信息。要删除此事件中心，请单击工具栏中的删除按钮。此按钮位于刷新按钮的左侧。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_9.22.jpg)

###### 图 9.22：单击删除按钮以删除您的事件中心

本章结束了我们使用 Azure Kubernetes 服务与事件中心的示例。在这个示例中，我们重新配置了一个 Kafka 应用程序，以使用 Azure 事件中心。

## 摘要

在本章中，我们部署了一个基于微服务的应用程序，连接到 Kafka。我们使用 Helm 部署了这个示例应用程序。我们能够通过向本地创建的 Kafka 集群发送事件并观察创建和更新的对象来测试应用程序。

最后，我们介绍了使用 Kafka 支持在 Azure 事件中心存储事件，并且我们能够收集所需的细节来连接我们基于微服务的应用程序并修改 Helm 图表。

下一章将涵盖集群安全性。我们将涵盖 RBAC 安全性、秘钥管理以及使用 Istio 的网络安全。


# 第十章：保护您的 AKS 集群

“泄露机密会导致失败”是一个描述在 Kubernetes 管理的集群中很容易危及安全性的短语（顺便说一句，*Kubernetes*在希腊语中是*舵手*的意思，就像*船*的舵手）。如果您的集群开放了错误的端口或服务，或者在应用程序定义中使用了明文作为秘密，不良行为者可以利用这种疏忽的安全性做几乎任何他们想做的事情。

在本章中，我们将更深入地探讨 Kubernetes 安全性。您将了解 Kubernetes 中的**基于角色的访问控制（RBAC）**的概念。之后，您将学习有关秘密以及如何使用它们的内容。您将首先在 Kubernetes 中创建秘密，然后创建一个 Key Vault 来更安全地存储秘密。最后，您将简要介绍服务网格概念，并且将给出一个实际示例供您参考。

本章将简要介绍以下主题：

+   基于角色的访问控制

+   设置秘密管理

+   在 Key Vault 中使用存储的秘密

+   Istio 服务网格为您服务

#### 注意

要完成有关 RBAC 的示例，您需要访问具有全局管理员权限的 Azure AD 实例。

让我们从 RBAC 开始这一章。

## 基于角色的访问控制

在生产系统中，您需要允许不同用户对某些资源有不同级别的访问权限；这被称为**基于角色的访问控制**（**RBAC**）。本节将带您了解如何在 AKS 中配置 RBAC，以及如何分配不同权限的不同角色。建立 RBAC 的好处在于，它不仅可以防止意外删除关键资源，还是一项重要的安全功能，限制了对集群的完全访问权限。在启用 RBAC 的集群上，用户将能够观察到他们只能修改他们有权限访问的资源。

到目前为止，使用 Cloud Shell，我们一直在扮演*root*，这使我们可以在集群中做任何事情。对于生产用例来说，root 访问是危险的，应尽可能受到限制。通常公认的最佳实践是使用**最小权限原则**（PoLP）登录任何计算机系统。这可以防止对安全数据的访问和通过删除关键资源而造成意外停机。据统计，22%至 29%（[`blog.storagecraft.com/data-loss-statistics-infographic/`](https://blog.storagecraft.com/data-loss-statistics-infographic/)）的数据丢失归因于人为错误。您不希望成为这一统计数字的一部分。

Kubernetes 开发人员意识到这是一个问题，并添加了 RBAC 以及服务角色的概念来控制对集群的访问。Kubernetes RBAC 有三个重要的概念：

+   **角色**：角色包含一组权限。角色默认没有权限，每个权限都需要明确声明。权限的示例包括*get*、*watch*和*list*。角色还包含这些权限所赋予的资源。资源可以是所有 Pod、部署等，也可以是特定对象（如*pod/mypod*）。

+   **主体**：主体可以是分配了角色的 Azure AD 用户或组。

+   **RoleBinding**：RoleBinding 将一个主体与特定命名空间中的角色或者 ClusterRoleBinding 中的整个集群中的角色进行了关联。

一个重要的概念要理解的是，在与 AKS 进行交互时，有两个 RBAC 层次：Azure RBAC 和 Kubernetes RBAC。Azure RBAC 处理分配给人们在 Azure 中进行更改的角色，比如创建、修改和删除集群。Kubernetes RBAC 处理集群中资源的访问权限。两者都是独立的控制平面，但可以使用源自 Azure AD 的相同用户和组。

![一个架构图，显示了 RBAC 的两个层次：Azure RBAC 和 Kubernetes RBAC。在 Azure 中，Azure AD 用户或组被分配 Azure 角色，以允许访问订阅和资源组中的节点。同样，Azure AD 用户或组被分配 Kubernetes 角色，以访问 Kubernetes 中的 Pod、部署和命名空间。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.1.jpg)

###### 图 10.1：两个不同的 RBAC 平面，Azure 和 Kubernetes

Kubernetes 中的 RBAC 是一个可选功能。在 AKS 中，默认情况下是创建启用了 RBAC 的集群。但是，默认情况下，集群未集成到 Azure AD 中。这意味着默认情况下，您无法授予 Kubernetes 权限给 Azure AD 用户。在这个例子中，我们将创建一个与 Azure AD 集成的新集群。让我们通过在 Azure AD 中创建一个新用户和一个新组来开始我们对 RBAC 的探索。

### 创建一个集成了 Azure AD 的新集群

在本节中，我们将创建一个与 Azure AD 集成的新集群。这是必需的，这样我们就可以在接下来的步骤中引用 Azure AD 中的用户。所有这些步骤将在 Cloud Shell 中执行。我们还提供了一个名为`cluster-aad.sh`的文件中的步骤。如果您希望执行该脚本，请更改前四行中的变量以反映您的偏好。让我们继续执行这些步骤：

1.  我们将从缩减当前集群到一个节点开始：

```
az aks nodepool scale --cluster-name handsonaks \
  -g rg-handsonaks --name agentpool--node-count 1
```

1.  然后，我们将设置一些在脚本中将使用的变量：

```
EXISTINGAKSNAME="handsonaks"
NEWAKSNAME="handsonaks-aad"
RGNAME="rg-handsonaks"
LOCATION="westus2"
TENANTID=$(az account show --query tenantId -o tsv)
```

1.  现在，我们将从我们的 AKS 集群中获取现有的服务主体。我们将重用此服务主体，以授予新集群访问我们的 Azure 订阅的权限：

```
# Get SP from existing cluster and create new password
RBACSP=$(azaks show -n $EXISTINGAKSNAME -g $RGNAME \
  --query servicePrincipalProfile.clientId -o tsv)
RBACSPPASSWD=$(openssl rand -base64 32)
az ad sp credential reset --name $RBACSP \
  --password $RBACSPPASSWD --append
```

1.  接下来，我们将创建一个新的 Azure AD 应用程序。这个 Azure AD 应用程序将用于获取用户的 Azure AD 组成员资格：

```
serverApplicationId=$(az ad app create \
    --display-name "${NEWAKSNAME}Server" \
    --identifier-uris "https://${NEWAKSNAME}Server" \
    --query appId -o tsv)
```

1.  在下一步中，我们将更新应用程序，创建服务主体，并从服务主体获取密钥：

```
az ad app update --id $serverApplicationId --set groupMembershipClaims=All
az ad sp create --id $serverApplicationId
serverApplicationSecret=$(az ad sp credential reset \
    --name $serverApplicationId \
    --credential-description "AKSPassword" \
    --query password -o tsv)
```

1.  然后，我们将授予此服务主体访问 Azure AD 中的目录数据的权限：

```
az ad app permission add \
--id $serverApplicationId \
    --api 00000003-0000-0000-c000-000000000000 \
    --api-permissions e1fe6dd8-ba31-4d61-89e7-88639da4683d=Scope \
    06da0dbc-49e2-44d2-8312-53f166ab848a=Scope \
    7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role
az ad app permission grant --id $serverApplicationId\
    --api 00000003-0000-0000-c000-000000000000
```

1.  这里有一个手动步骤，需要我们转到 Azure 门户。我们需要授予应用程序管理员同意。为了实现这一点，在 Azure 搜索栏中查找*Azure Active Directory*：![在 Azure 搜索栏中搜索 Azure Active Directory。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.2.jpg)

###### 图 10.2：在搜索栏中查找 Azure Active Directory

1.  然后，在左侧菜单中选择**应用程序注册**：![在左侧菜单中选择应用程序注册选项卡。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.3.jpg)

###### 图 10.3：选择应用程序注册

1.  在**应用程序注册**中，转到**所有应用程序**，查找*<clustername>Server*，并选择该应用程序：![查找我们之前使用脚本创建的名为 handsonaksaadserver 的应用程序注册。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.4.jpg)

###### 图 10.4：查找我们之前使用脚本创建的应用程序注册

1.  在该应用的视图中，点击**API 权限**，然后点击**为默认目录授予管理员同意**（此名称可能取决于您的 Azure AD 名称）：![转到左侧菜单中的 API 权限，并点击按钮授予管理员特权。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.5.jpg)

###### 图 10.5：授予管理员同意

在接下来的提示中，选择**是**以授予这些权限。

#### 注意

**授予管理员同意**按钮可能需要大约一分钟才能激活。如果还没有激活，请等待一分钟然后重试。您需要在 Azure AD 中拥有管理员权限才能授予此同意。

1.  接下来，我们将创建另一个服务主体并授予其权限。这个服务主体将接受用户的认证请求，并验证他们的凭据和权限：

```
clientApplicationId=$(az ad app create \
    --display-name "${NEWAKSNAME}Client" \
    --native-app \
    --reply-urls "https://${NEWAKSNAME}Client" \
    --query appId -o tsv)
az ad sp create --id $clientApplicationId
oAuthPermissionId=$(az ad app show --id $serverApplicationId\
--query "oauth2Permissions[0].id" -o tsv)
az ad app permission add --id $clientApplicationId \
--api$serverApplicationId --api-permissions \
$oAuthPermissionId=Scope
az ad app permission grant --id $clientApplicationId\
--api $serverApplicationId
```

1.  然后，作为最后一步，我们可以创建新的集群：

```
azaks create \
    --resource-group $RGNAME \
    --name $NEWAKSNAME \
    --location $LOCATION
    --node-count 2 \
    --node-vm-size Standard_D1_v2 \
    --generate-ssh-keys \
    --aad-server-app-id $serverApplicationId \
    --aad-server-app-secret $serverApplicationSecret \
    --aad-client-app-id $clientApplicationId \
    --aad-tenant-id $TENANTID \
    --service-principal $RBACSP \
    --client-secret $RBACSPPASSWD
```

在本节中，我们已经创建了一个集成了 Azure AD 的新 AKS 集群，用于 RBAC。创建一个新集群大约需要 5 到 10 分钟。在新集群正在创建时，您可以继续下一节并在 Azure AD 中创建新用户和组。

### 在 Azure AD 中创建用户和组

在本节中，我们将在 Azure AD 中创建一个新用户和一个新组。我们将在本章后面使用它们来分配权限给我们的 AKS 集群。

#### 注意

您需要在 Azure AD 中拥有用户管理员角色才能创建用户和组。

1.  首先，在 Azure 搜索栏中查找*Azure 活动目录*：![在 Azure 搜索栏中搜索 Azure 活动目录。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.17.jpg)

###### 图 10.6：在搜索栏中查找 Azure 活动目录

1.  点击左侧的**用户**。然后选择**新用户**来创建一个新用户：![导航到左侧菜单中的所有用户选项，然后点击新用户按钮。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.7.jpg)

###### 图 10.7：点击新用户以创建新用户

1.  提供有关用户的信息，包括用户名。确保记下密码，因为这将需要用于登录：![在新用户窗口中，添加所有用户详细信息并确保记下密码。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.8.jpg)

###### 图 10.8：提供用户详细信息（确保记下密码）

1.  创建用户后，返回 Azure AD 刀片并选择**组**。然后点击**新建组**按钮创建一个新组：![在左侧菜单中选择所有组选项卡，然后点击新建组按钮创建一个新组。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.9.jpg)

###### 图 10.9：点击新建组创建新组

1.  创建一个新的安全组。将组命名为`kubernetes-admins`，并将`Tim`添加为组的成员。然后点击底部的**创建**按钮：![在新组窗口中，将组类型设置为安全，添加组名称和组描述，并将我们在上一步中创建的用户添加到该组中。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.10.jpg)

###### 图 10.10：添加组类型、组名称和组描述

1.  我们现在已经创建了一个新用户和一个新组。作为最后一步，我们将使该用户成为 AKS 中的集群所有者，以便他们可以使用 Azure CLI 访问集群。为此，在 Azure 搜索栏中搜索您的集群：![在 Azure 搜索栏中输入集群名称并选择该集群。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.11.jpg)

###### 图 10.11：在 Azure 搜索栏中查找您的集群

1.  在集群刀片中，点击**访问控制（IAM）**，然后点击**添加**按钮添加新的角色分配。选择**Azure Kubernetes Service Cluster User Role**并分配给您刚创建的新用户：![在集群刀片中，选择访问控制（IAM），点击屏幕顶部的添加按钮，选择 Azure Kubernetes Service Cluster User Role，并查找我们之前创建的用户。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.12.jpg)

###### 图 10.12：为新创建的用户分配集群用户角色

1.  由于我们还将为新用户使用 Cloud Shell，因此我们将为他们提供对 Cloud Shell 存储账户的贡献者访问权限。首先，在 Azure 搜索栏中搜索*存储*：![在 Azure 搜索栏中搜索存储账户。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.13.jpg)

###### 图 10.13：在 Azure 搜索栏中搜索存储账户

1.  选择此存储账户所在的资源组：![在存储账户窗口中，选择由 Cloud Shell 创建的存储账户所在的资源组。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.14.jpg)

###### 图 10.14：选择资源组

1.  转到**访问控制（IAM）**，然后单击**添加**按钮。将**Storage Account Contributor**角色授予您新创建的用户：![导航到访问控制（IAM）窗口，然后单击添加按钮。然后，将 Contributor 角色授予我们新创建的用户。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.15.jpg)

###### 图 10.15：给予新创建的用户 Storage Account Contributor 访问权限

这已经完成了创建新用户和组，并给予该用户对 AKS 的访问权限。在下一节中，我们将为该用户和组配置 RBAC。

### 在 AKS 中配置 RBAC

为了演示 AKS 中的 RBAC，我们将创建两个命名空间，并在每个命名空间中部署 Azure Vote 应用程序。我们将给予我们的组对 Pod 的全局只读访问权限，并且我们将给予用户仅在一个命名空间中删除 Pod 的能力。实际上，我们需要在 Kubernetes 中创建以下对象：

+   `ClusterRole`来给予只读访问权限

+   `ClusterRoleBinding`来授予我们的组对该角色的访问权限

+   `Role`来在`delete-access`命名空间中给予删除权限

+   `RoleBinding`来授予我们的用户对该角色的访问权限![我们将要构建的演示的图形表示。我们创建的组将获得 ReadOnlyClusterRole，我们创建的用户在 delete-access 命名空间中获得一个角色，以授予删除 pod 的权限。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.16.jpg)

###### 图 10.16：组获得对整个集群的只读访问权限，用户获得对 delete-access 命名空间的删除权限

让我们在我们的集群上设置不同的角色：

1.  要开始我们的示例，我们需要检索组的 ID。以下命令将检索组 ID：

```
az ad group show -g 'kubernetes-admins' --query objectId -o tsv
```

这将显示您的组 ID。记下来，因为我们在下一步中会需要它：

![az ad group show 命令的输出，显示组 ID。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.17.jpg)

###### 图 10.17：获取组 ID

1.  由于我们为这个示例创建了一个新的集群，我们将获取凭据以登录到这个集群。我们将使用管理员凭据进行初始设置：

```
az aks get-credentials -n handsonaksad -g rg-handsonaks --admin
```

1.  在 Kubernetes 中，我们将为这个示例创建两个命名空间：

```
kubectl create ns no-access
kubectl create ns delete-access
```

1.  我们将在两个命名空间中部署`azure-vote`应用程序：

```
kubectl create -f azure-vote.yaml -n no-access
kubectl create -f azure-vote.yaml -n delete-access
```

1.  接下来，我们将创建`ClusterRole`文件。这在`clusterRole.yaml`文件中提供：

```
1   apiVersion: rbac.authorization.k8s.io/v1
2   kind: ClusterRole
3   metadata:
4     name: readOnly
5   rules:
6   - apiGroups: [""]
7     resources: ["pods"]
8     verbs: ["get", "watch", "list"]
```

让我们仔细看看这个文件：

**第 2 行**：定义了`ClusterRole`的创建

**第 4 行**：为我们的`ClusterRole`命名

**第 6 行**：给予所有 API 组的访问权限

**第 7 行**：给予所有 Pod 的访问权限

第 8 行：允许执行`get`、`watch`和`list`操作

我们将使用以下命令创建这个`ClusterRole`：

```
kubectl create -f clusterRole.yaml
```

1.  下一步是创建一个 ClusterRoleBinding。该绑定将角色链接到用户。这在`clusterRoleBinding.yaml`文件中提供：

```
1   apiVersion: rbac.authorization.k8s.io/v1
2   kind: ClusterRoleBinding
3   metadata:
4     name: readOnlyBinding
5   roleRef:
6     kind: ClusterRole
7     name: readOnly
8     apiGroup: rbac.authorization.k8s.io
9   subjects:
10  - kind: Group
11   apiGroup: rbac.authorization.k8s.io
12   name: "<group-id>"
```

让我们仔细看看这个文件：

第 2 行：定义我们正在创建一个`ClusterRoleBinding`

第 4 行：为我们的`ClusterRoleBinding`命名

第 5-8 行：指的是我们在上一步中创建的`ClusterRole`

第 9-12 行：在 Azure AD 中引用我们的组

我们可以使用以下命令创建这个`ClusterRoleBinding`：

```
kubectl create -f clusterRoleBinding.yaml
```

1.  接下来，我们将创建一个限制在`delete-access`命名空间的`Role`。这在`role.yaml`文件中提供：

```
1   apiVersion: rbac.authorization.k8s.io/v1
2   kind: Role
3   metadata:
4     name: deleteRole
5     namespace: delete-access
6   rules:
7   - apiGroups: [""]
8     resources: ["pods"]
9     verbs: ["delete"]
```

这个文件类似于之前的`ClusterRole`文件。有两个有意义的区别：

第 2 行：定义我们正在创建一个`Role`，而不是`ClusterRole`

第 5 行：定义了在哪个命名空间中创建这个`Role`

我们可以使用以下命令创建这个`Role`：

```
kubectl create -f role.yaml
```

1.  最后，我们将创建将我们的用户链接到命名空间角色的`RoleBinding`。这在`roleBinding.yaml`文件中提供：

```
1   apiVersion: rbac.authorization.k8s.io/v1
2   kind: RoleBinding
3   metadata:
4     name: deleteBinding
5     namespace: delete-access
6   roleRef:
7     kind: Role
8     name: deleteRole
9     apiGroup: rbac.authorization.k8s.io
10  subjects:
11  - kind: User
12    apiGroup: rbac.authorization.k8s.io
13    name: "<user e-mail address>"
```

这个文件类似于之前的 ClusterRoleBinding 文件。有一些有意义的区别：

第 2 行：定义了创建一个`RoleBinding`而不是`ClusterRoleBinding`

第 5 行：定义了在哪个命名空间中创建这个`RoleBinding`

第 7 行：指的是一个普通的`Role`而不是`ClusterRole`

第 11-13 行：定义了我们的用户而不是一个组

我们可以使用以下命令创建这个`RoleBinding`：

```
kubectl create -f roleBinding.yaml
```

这已经满足了 RBAC 的要求。我们已经创建了两个角色并设置了两个 RoleBindings。在下一节中，我们将通过以我们的用户身份登录到集群来探索 RBAC 的影响。

### 验证 RBAC

为了验证 RBAC 是否按预期工作，我们将使用新创建的用户登录到 Azure 门户。在新的浏览器或 InPrivate 窗口中转到[`portal.azure.com`](https://portal.azure.com)，并使用新创建的用户登录。您将立即收到更改密码的提示。这是 Azure AD 中的安全功能，以确保只有该用户知道他们的密码：

![提示更改密码的浏览器窗口。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.18.jpg)

###### 图 10.18：您将被要求更改密码

一旦我们更改了您的密码，我们就可以开始测试不同的 RBAC 角色：

1.  我们将通过为新用户设置 Cloud Shell 来开始我们的实验。启动 Cloud Shell 并选择 Bash：![选择 Bash 选项作为 Cloud Shell。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.19.jpg)

###### 图 10.19：选择 Bash 作为 Cloud Shell

1.  在下一个视图中，选择**显示高级设置**：![在导航到 bash 选项后，选择显示高级设置按钮。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.20.jpg)

###### 图 10.20：选择显示高级设置

1.  然后，将 Cloud Shell 指向现有的存储账户并创建一个新的文件共享：![通过单击创建存储按钮，将 Cloud Shell 指向现有的存储账户以创建新的文件共享。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.21.jpg)

###### 图 10.21：指向现有的存储账户并创建一个新的文件共享

1.  一旦 Cloud Shell 可用，让我们获取连接到我们的 AKS 集群的凭据：

```
az aks get-credentials -n handsonaksaad -g rg-handsonaks
```

1.  然后，我们将尝试在 kubectl 中执行一个命令。让我们尝试获取集群中的节点：

```
kubectl get nodes
```

由于这是针对启用 RBAC 的集群执行的第一个命令，您将被要求重新登录。浏览至[`microsoft.com/devicelogin`](https://microsoft.com/devicelogin)并提供 Cloud Shell 显示给您的代码。确保您在此处使用新用户的凭据登录：

![在提示窗口中输入 Cloud Shell 提供的代码，然后单击下一步按钮。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.22.jpg)

###### 图 10.22：在提示中复制粘贴 Cloud Shell 显示给您的代码

登录后，您应该从 kubectl 收到一个`Forbidden`错误消息，通知您您没有权限查看集群中的节点。这是预期的，因为用户只被配置为可以访问 Pods：

![kubectl 给出错误消息，并声明我们没有权限查看集群中的节点。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.23.jpg)

###### 图 10.23：提示您登录和被禁止的消息

1.  现在我们可以验证我们的用户可以查看所有命名空间中的 Pods，并且用户有权限在`delete-access`命名空间中删除 Pods：

```
kubectl get pods -n no-access
kubectl get pods -n delete-access
```

这应该对两个命名空间都成功。这是由于为用户组配置的`ClusterRole`：

![输出显示我们的用户可以查看两个命名空间中的 Pods。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.24.jpg)

###### 图 10.24：我们的用户可以查看两个命名空间中的 Pods

1.  让我们也验证一下“删除”权限：

```
kubectl delete pod --all -n no-access
kubectl delete pod --all -n delete-access
```

正如预期的那样，在`no-access`命名空间中被拒绝，在`delete-access`命名空间中被允许，如*图 10.25*所示：

![验证删除权限显示在无访问命名空间中被拒绝，在删除访问命名空间中被允许。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.25.jpg)

###### 图 10.25: 在无访问命名空间中被拒绝，在删除访问命名空间中被允许

在本节中，我们已经设置了一个集成了 Azure AD 的新集群，并验证了与 Azure AD 身份的 RBAC 的正确配置。让我们清理本节中创建的资源，获取现有集群的凭据，并将我们的常规集群缩减到两个节点：

```
az aks delete -n handsonaksaad -g rg-handsonaks
az aks get-credentials -n handsonaks -g rg-handsonaks
az aks nodepool scale --cluster-name handsonaks \
  -g rg-handsonaks --name agentpool --node-count 2
```

在下一节中，我们将继续探讨 Kubernetes 安全性的路径，这次是调查 Kubernetes 密码。

## 设置密码管理

所有生产应用程序都需要一些秘密信息才能运行。Kubernetes 具有可插拔的密码后端来管理这些密码。Kubernetes 还提供了多种在部署中使用密码的方式。管理密码并正确使用密码后端的能力将使您的服务能够抵抗攻击。

在之前的章节中，我们在一些部署中使用了密码。大多数情况下，我们将密码作为某种变量的字符串传递，或者 Helm 负责为我们创建密码。在 Kubernetes 中，密码是一种资源，就像 Pods 和 ReplicaSets 一样。密码始终与特定的命名空间相关联。必须在要使用它们的所有命名空间中创建密码。在本节中，我们将学习如何创建、解码和使用我们自己的密码。我们将首先使用 Kubernetes 中的内置密码，最后利用 Azure Key Vault 来存储密码。

### 创建您自己的密码

Kubernetes 提供了三种创建密码的方式，如下所示：

+   从文件创建密码

+   从 YAML 或 JSON 定义创建密码

+   从命令行创建密码

使用上述任何方法，您可以创建三种类型的密码：

+   **通用密码**: 这些可以使用文字值创建。

+   **Docker-registry 凭据**: 用于从私有注册表中拉取镜像。

+   **TLS 证书**: 用于存储 SSL 证书。

我们将从使用文件方法创建密码开始。

**从文件创建密码**

假设您需要存储用于访问 API 的 URL 和秘密令牌。为了实现这一点，您需要按照以下步骤进行操作：

1.  将 URL 存储在`apiurl.txt`中，如下所示：

```
echo https://my-secret-url-location.topsecret.com \
> secreturl.txt
```

1.  将令牌存储在另一个文件中，如下所示：

```
echo 'superSecretToken' > secrettoken.txt
```

1.  让 Kubernetes 从文件中创建密码，如下所示：

```
kubectl create secret generic myapi-url-token \
--from-file=./secreturl.txt --from-file=./secrettoken.txt
```

在这个命令中，我们将秘密类型指定为`generic`。

该命令应返回以下输出：

```
secret/myapi-url-token created
```

1.  我们可以使用`get`命令检查秘密是否与任何其他 Kubernetes 资源以相同的方式创建：

```
kubectl get secrets
```

此命令将返回类似于*图 10.26*的输出：

![kubectl get secrets 命令的输出显示了秘密的名称、类型、数据和年龄。输出中有一个高亮显示，突出显示了名为 myapi-url-token 的秘密，类型为 Opaque。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.26.jpg)

###### 图 10.26：kubectl get secrets 的输出

在这里，您将看到我们刚刚创建的秘密，以及仍然存在于`default`命名空间中的任何其他秘密。我们的秘密是`Opaque`类型，这意味着从 Kubernetes 的角度来看，内容的模式是未知的。它是一个任意的键值对，没有约束，与 Docker 注册表或 TLS 秘密相反，后者具有将被验证为具有所需详细信息的模式。

1.  要了解有关秘密的更多详细信息，您还可以运行`describe`命令：

```
kubectl describe secrets/myapi-url-token
```

您将获得类似于*图 10.27*的输出：

![描述命令的输出显示了有关秘密的其他详细信息。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.27.jpg)

###### 图 10.27：描述秘密的输出

正如您所看到的，前面的命令都没有显示实际的秘密值。

1.  要获取秘密，请运行以下命令：

```
kubectl get -o yaml secrets/myapi-url-token
```

您将获得类似于*图 10.28*的输出：

![通过 kubectl get secret 命令中的-o yaml 开关显示秘密的编码值的输出。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.28.jpg)

###### 图 10.28：在 kubectl get secret 中使用-o yaml 开关可以获取秘密的编码值

数据以键值对的形式存储，文件名作为键，文件的 base64 编码内容作为值。

1.  前面的值是 base64 编码的。Base64 编码并不安全。它会使秘密变得难以被操作员轻松阅读，但任何坏人都可以轻松解码 base64 编码的秘密。要获取实际值，请运行以下命令：

```
echo 'c3VwZXJTZWNyZXRUb2tlbgo=' | base64 -d
```

您将获得最初输入的值：

![获取最初使用 echo <encoded secret> | base64 -d 命令输入的秘密的实际值。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.29.jpg)

###### 图 10.29：Base64 编码的秘密可以轻松解码

1.  同样，对于`url`值，您可以运行以下命令：

```
echo 'aHR0cHM6Ly9teS1zZWNyZXQtdXJsLWxvY2F0aW9uLnRvcHNlY3JldC5jb20K'| base64 -d
```

您将获得最初输入的`url`值，如*图 10.30*所示：

![显示编码的 URL 的输出，这是最初输入的 URL。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.30.jpg)

###### 图 10.30：编码的 URL 也可以很容易地解码

在本节中，我们能够使用文件对 URL 进行编码，并获取实际的秘密值。让我们继续探索第二种方法——从 YAML 或 JSON 定义创建秘密。

**使用 YAML 文件手动创建秘密**

我们将按照以下步骤使用 YAML 文件创建相同的秘密：

1.  首先，我们需要将秘密编码为`base64`，如下所示：

```
echo 'superSecretToken' | base64
```

您将获得以下价值：

```
c3VwZXJTZWNyZXRUb2tlbgo=
```

您可能会注意到，这与我们在上一节中获取秘密的`yaml`定义时存在的值相同。

1.  同样，对于`url`值，我们可以获取 base64 编码的值，如下面的代码块所示：

```
echo 'https://my-secret-url-location.topsecret.com' | base64
```

这将给您`base64`编码的 URL：

```
aHR0cHM6Ly9teS1zZWNyZXQtdXJsLWxvY2F0aW9uLnRvcHNlY3JldC5jb20K
```

1.  现在我们可以手动创建秘密定义；然后保存文件。该文件已在代码包中提供，名称为`myfirstsecret.yaml`：

```
1   apiVersion: v1
2   kind: Secret
3   metadata:
4     name: myapiurltoken-yaml
5   type: Opaque
6   data:
7     url: aHR0cHM6Ly9teS1zZWNyZXQtdXJsLWxvY2F0aW9uLnRvcHNlY3JldC5jb20K
8     token: c3VwZXJTZWNyZXRUb2tlbgo=
```

让我们调查一下这个文件：

**第 2 行**：这指定了我们正在创建一个秘密。

**第 5 行**：这指定了我们正在创建一个`Opaque`秘密，这意味着从 Kubernetes 的角度来看，值是无约束的键值对。

**第 7-8 行**：这些是我们秘密的 base64 编码值。

1.  现在，我们可以像任何其他 Kubernetes 资源一样使用`create`命令创建秘密：

```
kubectl create -f myfirstsecret.yaml
```

1.  我们可以通过以下方式验证我们的秘密是否已成功创建：

```
kubectl get secrets
```

这将显示一个类似于*图 10.31*的输出：

![验证我们的秘密是否已成功使用 kubectl get secrets 命令创建的输出。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.31.jpg)

###### 图 10.31：我们的秘密已成功从 YAML 文件创建

1.  您可以通过在上一节中描述的方式使用`kubectl get -o yaml secrets/myapiurltoken-yaml`来双重检查秘密是否相同。

**使用文字创建通用秘密**

创建秘密的第三种方法是使用`literal`方法，这意味着您可以在命令行上传递值。要做到这一点，请运行以下命令：

```
kubectl create secret generic myapiurltoken-literal \
--from-literal=token='superSecretToken' \
--from-literal=url=https://my-secret-url-location.topsecret.com
```

我们可以通过运行以下命令来验证秘密是否已创建：

```
kubectl get secrets
```

这将给我们一个类似于*图 10.32*的输出：

![运行 kubectl get secrets 命令的输出，验证我们的秘密是否已成功从 CLI 创建。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.32.jpg)

###### 图 10.32：我们的秘密已成功从 CLI 创建

因此，我们已经使用文字值创建了秘密，除了前面两种方法。

### 创建 Docker 注册表密钥

在生产环境中连接到私有 Docker 注册表是必要的。由于这种用例非常常见，Kubernetes 提供了创建连接的机制：

```
kubectl create secret docker-registry <secret-name> \
--docker-server=<your- registry-server> \
--docker-username=<your-name> \
--docker-password=<your-pword> --docker-email=<your-email>
```

第一个参数是秘密类型，即`docker-registry`。然后，您给秘密一个名称；例如，`regcred`。其他参数是 Docker 服务器（[`index.docker.io/v1/`](https://index.docker.io/v1/)用于 Docker Hub），您的用户名，您的密码和您的电子邮件。

您可以使用`kubectl`访问秘密以相同的方式检索秘密。

在 Azure 中，**Azure 容器注册表**（**ACR**）最常用于存储容器映像。集群可以连接到 ACR 的方式有两种。第一种方式是在集群中使用像我们刚刚描述的秘密。第二种方式 - 这是推荐的方式 - 是使用服务主体。我们将在*第十一章，无服务器函数*中介绍集成 AKS 和 ACR。

Kubernetes 中的最终秘密类型是 TLS 秘密。

### 创建 TLS 秘密

TLS 秘密用于存储 TLS 证书。要创建可用于 Ingress 定义的 TLS 秘密，我们使用以下命令：

```
kubectl create secret tls <secret-name> --key <ssl.key> --cert <ssl.crt>
```

第一个参数是`tls`，用于设置秘密类型，然后是`key`值和实际的证书值。这些文件通常来自您的证书注册商。

#### 注意

我们在*第六章*，*管理您的 AKS*，集群中创建了 TLS 秘密，在那里我们使用`cert-manager`代表我们创建了这些秘密。

如果您想生成自己的秘密，可以运行以下命令生成自签名 SSL 证书：

`openssl req -x509 -nodes -days 365 -newkey rsa:2048 - keyout /tmp/ssl.key -out /tmp/ssl.crt -subj "/CN=foo.bar.com"`

在本节中，我们介绍了 Kubernetes 中不同的秘密类型，并看到了如何创建秘密。在下一节中，我们将在我们的应用程序中使用这些秘密。

### 使用您的秘密

秘密一旦创建，就需要与应用程序进行关联。这意味着 Kubernetes 需要以某种方式将秘密的值传递给正在运行的容器。Kubernetes 提供了两种将秘密链接到应用程序的方式：

+   将秘密用作环境变量

+   将秘密挂载为文件

将秘密挂载为文件是在应用程序中使用秘密的最佳方法。在本节中，我们将解释两种方法，并展示为什么最好使用第二种方法。

### 作为环境变量的秘密

在 Pod 定义中引用秘密在`containers`和`env`部分下。我们将使用之前在 Pod 中定义的秘密，并学习如何在应用程序中使用它们：

1.  我们可以配置一个具有环境变量秘密的 Pod，就像在`pod-with-env-secrets.yaml`中提供的定义：

```
1   apiVersion: v1
2   kind: Pod
3   metadata:
4     name: secret-using-env
5   spec:
6     containers:
7     - name: nginx
8       image: nginx
9       env:
10        - name: SECRET_URL
11          valueFrom:
12            secretKeyRef:
13              name: myapi-url-token
14              key: secreturl.txt
15        - name: SECRET_TOKEN
16          valueFrom:
17            secretKeyRef:
18              name: myapi-url-token
19              key: secrettoken.txt
20    restartPolicy: Never
```

让我们检查一下这个文件：

**第 9 行**：在这里，我们设置环境变量。

**第 11-14 行**：在这里，我们引用`myapi-url-token`秘密中的`secreturl.txt`文件。

**第 16-19 行**：在这里，我们引用`myapi-url-token`秘密中的`secrettoken.txt`文件。

1.  现在让我们创建 Pod 并看看它是否真的起作用：

```
kubectl create -f pod-with-env-secrets.yaml
```

1.  检查环境变量是否设置正确：

```
kubectl exec -it secret-using-env sh
echo $SECRET_URL
echo $SECRET_TOKEN
```

这应该显示与*图 10.33*类似的结果：

![通过使用 kubectl exec 在容器中打开 shell 并运行 echo 来验证环境变量是否设置正确，以获取秘密值。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.33.jpg)

###### 图 10.33：我们可以在 Pod 内部获取秘密

任何应用程序都可以通过引用适当的`env`变量来使用秘密值。请注意，应用程序和 Pod 定义都没有硬编码的秘密。

### 将秘密作为文件

让我们看看如何将相同的秘密挂载为文件。我们将使用以下 Pod

定义以演示如何完成此操作。它在`pod-with-env-secrets.yaml`文件中提供：

```
1   apiVersion: v1
2   kind: Pod
3   metadata:
4     name: secret-using-volume
5   spec:
6     containers:
7     - name: nginx
8       image: nginx
9       volumeMounts:
10      - name: secretvolume
11        mountPath: "/etc/secrets"
12        readOnly: true
13    volumes:
14    - name: secretvolume
15      secret:
16        secretName: myapi-url-token
```

让我们仔细看看这个文件：

+   **第 9-12 行**：在这里，我们提供挂载详细信息。我们将`/etc/secrets`目录挂载为只读。

+   **第 13-16 行**：在这里，我们引用秘密。请注意，秘密中的两个值都将挂载到容器中。

请注意，这比`env`定义更简洁，因为您不必为每个秘密定义名称。但是，应用程序需要有特殊的代码来读取文件的内容，以便正确加载它。

让我们看看秘密是否传递了：

1.  使用以下命令创建 Pod：

```
kubectl create -f pod-with-vol-secret.yaml
```

1.  回显挂载卷中文件的内容：

```
kubectl exec -it secret-using-volume bash
cd /etc/secrets/ 
cat secreturl.txt
cat /etc/secrets/secrettoken.txt 
```

如您在*图 10.34*中所见，我们的 Pod 中存在秘密：

![输出显示我们的 Pod 中的秘密可用作文件。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.34.jpg)

###### 图 10.34：我们的 Pod 中的秘密可用作文件

我们已经讨论了将秘密传递给运行中容器的两种方法。在下一节中，我们将解释为什么最好使用文件方法。

### 为什么将秘密作为文件是最佳方法

尽管将秘密作为环境变量是一种常见做法，但将秘密作为文件挂载更安全。Kubernetes 安全地处理秘密作为环境变量，但 Docker 运行时不安全地处理它们。要验证这一点，您可以运行以下命令以在 Docker 运行时看到明文的秘密：

1.  首先使用以下命令获取秘密 Pod 正在运行的实例：

```
kubectl describe pod secret-using-env | grep Node
```

这应该向您显示实例 ID，如*图 10.35*所示：

使用 kubectl describe pod secret-using-env 命令执行以获取实例 ID。

###### 图 10.35：获取实例 ID

1.  接下来，获取正在运行的 Pod 的 Docker ID：

```
kubectl describe pod secret-using-env | grep 'docker://'
```

这应该向您显示 Docker ID：

使用 kubectl describe pod secret-using-env 命令获取 Docker ID。

###### 图 10.36：获取 Docker ID

1.  最后，我们将在运行我们的容器的节点中执行一个命令，以显示我们作为环境变量传递的秘密：

```
INSTANCE=<provide instance number>
DOCKERID=<provide Docker ID>
VMSS=$(az vmss list --query '[].name' -o tsv)
RGNAME=$(az vmss list --query '[].resourceGroup' -o tsv)
az vmss run-command invoke -g $RGNAME -n $VMSS --command-id \
RunShellScript --instance-id $INSTANCE --scripts \
"docker inspect -f '{{ .Config.Env }}' $DOCKERID" \
-o yaml| grep SECRET
```

这将向您显示明文的两个秘密：

输出显示秘密在 Docker 运行时被解码

###### 图 10.37：秘密在 Docker 运行时被解码

如您所见，秘密在 Docker 运行时被解码。这意味着任何有权访问机器的操作者都将能够访问这些秘密。这也意味着大多数日志系统将记录敏感秘密。

#### 注意

RBAC 对于控制秘密也非常重要。拥有对集群的访问权限并具有正确角色的人可以访问存储的秘密。由于秘密只是 base64 编码的，任何具有对秘密的 RBAC 权限的人都可以解码它们。建议谨慎对待对秘密的访问，并非常小心地授予人们使用`kubectl exec`命令获取容器 shell 的访问权限。

让我们确保清理掉我们在这个示例中创建的资源：

```
kubectl delete pod --all
kubectl delete secret myapi-url-token \
myapiurltoken-literal myapiurltoken-yaml
```

现在我们已经使用默认的秘密机制在 Kubernetes 中探索了秘密，让我们继续使用一个更安全的选项，即 Key Vault。

## 使用存储在 Key Vault 中的秘密

在上一节中，我们探讨了存储在 Kubernetes 中的本地秘密。这意味着它们以 base64 编码存储在 Kubernetes API 服务器上（在后台，它们将存储在 etcd 数据库中，但这是微软提供的托管服务的一部分）。我们在上一节中看到，base64 编码的秘密根本不安全。对于高度安全的环境，您将希望使用更好的秘密存储。

Azure 提供了符合行业标准的秘密存储解决方案，称为 Azure 密钥保管库。这是一个托管服务，可以轻松创建、存储和检索秘密，并提供对秘密访问的良好监控。微软维护了一个开源项目，允许您将密钥保管库中的秘密挂载到您的应用程序中。这个解决方案称为密钥保管库 FlexVolume，可以在这里找到：[`github.com/Azure/kubernetes-keyvault-flexvol`](https://github.com/Azure/kubernetes-keyvault-flexvol)。

在本节中，我们将创建一个密钥保管库，并安装密钥保管库 FlexVolume 以挂载存储在密钥保管库中的秘密到 Pod 中。

### 创建密钥保管库

我们将使用 Azure 门户创建密钥保管库：

1.  要开始创建过程，请在 Azure 搜索栏中查找*密钥保管库*：![在 Azure 搜索栏中搜索密钥保管库。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.38.jpg)

###### 图 10.38：在 Azure 搜索栏中查找密钥保管库

1.  点击“添加”按钮开始创建过程：![导航到左上角并点击“添加”按钮开始创建密钥保管库。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.39.jpg)

###### 图 10.39：单击“添加”按钮开始创建密钥保管库

1.  提供创建密钥保管库的详细信息。密钥保管库的名称必须是全局唯一的，因此考虑在名称中添加您的缩写。建议在与您的集群相同的区域创建密钥保管库：![输入订阅、密钥保管库名称和区域等详细信息以创建密钥保管库。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.40.jpg)

###### 图 10.40：提供创建密钥保管库的详细信息

1.  提供详细信息后，点击“审核+创建”按钮以审核并创建您的密钥保管库。点击“创建”按钮完成创建过程。

1.  创建您的密钥保管库需要几秒钟的时间。一旦保管库创建完成，打开它，转到秘密，然后点击**生成/导入**按钮创建一个新的秘密：![导航到左侧导航中的秘密选项卡，并点击生成/导入按钮创建新秘密。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.41.jpg)

###### 图 10.41：创建新秘密

1.  在秘密创建向导中，提供有关您的秘密的详细信息。为了使演示更容易跟进，建议使用名称`k8s-secret-demo`。点击屏幕底部的**创建**按钮来创建秘密：![输入创建新秘密的详细信息。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.42.jpg)

###### 图 10.42：提供新秘密的详细信息

现在我们在密钥保管库中有一个秘密，我们可以继续配置 Key Vault FlexVolume 以在 Kubernetes 中访问此秘密。

### 设置 Key Vault FlexVolume

在本节中，我们将在我们的集群中设置 Key Vault FlexVolume。这将允许我们从 Key Vault 中检索秘密：

1.  使用以下命令创建 Key Vault FlexVolume。`kv-flexvol-installer.yaml`文件已在本章的源代码中提供：

```
kubectl create -f kv-flexvol-installer.yaml
```

#### 注意

我们已经提供了`kv-flexvol-installer.yaml`文件，以确保与本书中的示例一致。对于生产用例，我们建议安装最新版本，可在[`github.com/Azure/kubernetes-keyvault-flexvol`](https://github.com/Azure/kubernetes-keyvault-flexvol)上找到。

1.  FlexVolume 需要凭据才能连接到 Key Vault。在这一步中，我们将创建一个新的服务主体：

```
APPID=$(az ad app create \
    --display-name "flex" \
    --identifier-uris "https://flex" \
    --query appId -o tsv)
az ad sp create --id $APPID
APPPASSWD=$(az ad sp credential reset \
    --name $APPID \
    --credential-description "KeyVault" \
    --query password -o tsv)
```

1.  现在我们将在 Kubernetes 中创建两个秘密来存储服务主体连接：

```
kubectl create secret generic kvcreds \
--from-literal=clientid=$APPID \
--from-literal=clientsecret=$APPPASSWD --type=azure/kv
```

1.  现在我们将为此服务主体授予对密钥保管库中秘密的访问权限：

```
KVNAME=handsonaks-kv
az keyvault set-policy -n $KVNAME --key-permissions \
  get --spn $APPID
az keyvault set-policy -n $KVNAME --secret-permissions \
  get --spn $APPID
az keyvault set-policy -n $KVNAME --certificate-permissions \
  get --spn $APPID
```

您可以在门户中验证这些权限是否已成功设置。在您的密钥保管库中，在**访问策略**部分，您应该看到 flex 应用程序对密钥、秘密和证书具有`获取`权限：

![在访问策略部分，我们可以看到 flex 应用程序对密钥、秘密和证书具有获取权限。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.43.jpg)

###### 图 10.43：flex 应用程序对密钥、秘密和证书具有获取权限

#### 注意

Key Vault FlexVolume 支持多种身份验证选项。我们现在正在使用预创建的服务主体。FlexVolume 还支持使用托管标识，可以使用 Pod 标识或使用托管集群的**虚拟机规模集**（**VMSS**）的标识。本书不会探讨这些其他身份验证选项，但鼓励您在 https://github.com/Azure/kubernetes-keyvault-flexvol 上阅读更多。

这就结束了 Key Vault FlexVolume 的设置。在下一节中，我们将使用 FlexVolume 来访问秘密并将其挂载在 Pod 中。

### 使用 Key Vault FlexVolume 在 Pod 中挂载秘密

在这一部分，我们将把一个来自 Key Vault 的秘密挂载到一个新的 Pod 中。

1.  我们提供了一个名为`pod_secret_flex.yaml`的文件，它将帮助创建一个挂载 Key Vault 秘密的 Pod。您需要对这个文件进行两处更改：

```
1   apiVersion: v1
2   kind: Pod
3   metadata:
4     name: nginx-secret-flex
5   spec:
6     containers:
7     - name: nginx
8       image: nginx
9       volumeMounts:
10      - name: test
11        mountPath: /etc/secret/
12        readOnly: true
13    volumes:
14    - name: test
15      flexVolume:
16        driver: "azure/kv"
17        secretRef:
18          name: kvcreds
19        options:
20          keyvaultname: <keyvault name>
21          keyvaultobjectnames: k8s-secret-demo
22          keyvaultobjecttypes: secret
23          tenantid: "<tenant ID>"
```

让我们调查一下这个文件：

**第 9-12 行**：类似于将秘密作为文件挂载的示例，我们还提供了一个`volumeMount`来将我们的秘密作为文件挂载。

**第 13-23 行**：这是指向 FlexVolume 的卷配置。

**第 17-18 行**：在这里，我们提到了在上一个示例中创建的服务主体凭据。

**第 20-23 行**：您需要更改这些值以代表您的环境。

1.  我们可以使用以下命令创建此 Pod：

```
kubectl create -f pod_secret_flex.yaml
```

1.  一旦 Pod 被创建并运行，我们可以在 Pod 中执行并验证秘密是否存在：

```
kubectl exec -it nginx-secret-flex bash
cd /etc/secret
cat k8s-secret-demo
```

这应该输出我们在 Key Vault 中创建的秘密，如图 10.43 所示：

![显示我们在 Key Vault 中配置的秘密被挂载在 Pod 中作为文件的输出。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.44.jpg)

###### 图 10.44：我们在 Key Vault 中配置的秘密被挂载在 Pod 中作为一个文件

我们已成功使用 Key Vault 存储秘密。秘密不再以 base64 编码的方式存储在我们的集群中，而是安全地存储在集群外的 Key Vault 中。我们仍然可以使用 Key Vault FlexVolume 在集群中访问秘密。

让我们确保清理我们的部署：

```
kubectl delete -f pod_secret_flex.yaml
kubectl delete -f kv-flexvol-installer.yaml
kubectl delete secret kvcreds
```

在这一部分，我们已经看到了创建和挂载秘密的多种方式。我们已经探讨了使用文件、YAML 文件和直接从命令行创建秘密的方法。我们还探讨了秘密可以如何被使用，可以作为环境变量或作为挂载文件。然后，我们研究了一种更安全的使用秘密的方式，即通过 Azure Key Vault。

在下一节中，我们将探讨使用 Istio 服务网格在我们的集群中配置额外的网络安全。

## Istio 服务网格为您服务

我们已经找到了一些保护我们的 Pod 的方法，但我们的网络连接仍然是开放的。集群中的任何 Pod 都可以与同一集群中的任何其他 Pod 通信。作为一个站点可靠性工程师，你会希望强制执行入口和出口规则。此外，你还希望引入流量监控，并希望有更好的流量控制。作为开发人员，你不想被所有这些要求所困扰，因为你不知道你的应用将被部署在哪里，或者什么是允许的。最好的解决方案是一个工具，让我们可以按原样运行应用程序，同时指定网络策略、高级监控和流量控制。

进入服务网格。这被定义为控制服务之间通信的层。服务网格是微服务之间的网络。服务网格被实现为控制和监视不同微服务之间流量的软件。通常，服务网格利用边车来透明地实现功能。如果你记得，Kubernetes 中的 Pod 可以由一个或多个容器组成。边车是添加到现有 Pod 中以实现附加功能的容器；在服务网格的情况下，这个功能就是服务网格的功能。

#### 注意

服务网格控制的远不止网络安全。如果你的集群只需要网络安全，请考虑采用网络策略。

与微服务一样，服务网格的实现并不是免费的午餐。如果你没有数百个微服务在运行，你可能不需要服务网格。如果你决定你真的需要一个，你首先需要选择一个。有四个流行的选项，每个都有自己的优势：

+   Linkerd (https://linkerd.io/)，包括 Conduit (https://conduit.io/)

+   Istio (https://istio.io/)

+   Consul (https://www.consul.io/mesh.html)

你应该根据自己的需求选择一个服务网格，并且放心任何一个解决方案都会适合你。在本节中，你将介绍 Istio 服务网格。我们选择了 Istio 服务网格，因为它很受欢迎。我们使用 GitHub 上的星星和提交作为受欢迎程度的衡量标准。

### 描述 Istio 服务网格

Istio 是由 IBM、Google 和 Lyft 创建的服务网格。该项目于 2017 年 5 月宣布，并于 2018 年 7 月达到稳定的 v1 版本。Istio 是服务网格的控制平面部分。Istio 默认使用`Envoy` sidecar。在本节中，我们将尝试解释什么是服务网格，以及 Istio 服务网格的核心功能是什么。

#### 注意

在本书中，我们只是简要地涉及了服务网格和 Istio。Istio 不仅是一个非常强大的工具，可以保护，还可以管理云原生应用程序的流量。在本书中，我们没有涵盖很多细节和功能。

在功能方面，服务网格（特别是 Istio）具有许多核心功能。其中之一是流量管理。在这种情况下，流量管理一词意味着流量路由的控制。通过实施服务网格，您可以控制流量以实施 A/B 测试或金丝雀发布。没有服务网格，您需要在应用程序的核心代码中实施该逻辑，而有了服务网格，该逻辑是在应用程序之外实施的。

流量管理还带来了 Istio 提供的额外安全性。Istio 可以管理身份验证、授权和服务之间通信的加密。这确保只有经过授权的服务之间进行通信。在加密方面，Istio 可以实施**双向 TLS**（**mTLS**）来加密服务之间的通信。

Istio 还具有实施策略的能力。策略可用于限制某些流量的速率（例如，每分钟只允许 x 个事务），处理对服务的访问的白名单和黑名单，或实施标头重写和重定向。

最后，Istio 为应用程序中不同服务之间的流量提供了巨大的可见性。Istio 可以执行流量跟踪、监控和日志记录服务之间的流量。您可以使用这些信息创建仪表板来展示应用程序性能，并使用这些信息更有效地调试应用程序故障。

在接下来的部分，我们将安装 Istio 并配置 Pod 之间流量的 mTLS 加密。这只是平台的许多功能之一。我们鼓励您走出书本，了解更多关于 Istio 的信息。

### 安装 Istio

安装 Istio 很容易；要这样做，请按照以下步骤操作：

1.  转到您的主目录并下载`istio`软件包，如下所示：

```
cd ~
curl -L https://istio.io/downloadIstio | sh -
```

1.  将`istio`二进制文件添加到您的路径。首先，获取您正在运行的 Istio 版本号：

```
ls | grep istio 
```

这应该显示类似于*图 10.45*的输出：

![运行 ls | grepistio 命令显示正在运行的 Istio 版本号的输出。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.45.jpg)

###### 图 10.45：获取您的 Istio 版本号

记下 Istio 版本，并将其用作以下方式将二进制文件添加到您的路径：

```
export PATH="$PATH:~/istio-<release-number>/bin"
```

1.  使用以下命令检查您的集群是否可以用于运行 Istio：

```
istioctl verify-install
```

1.  使用演示配置文件安装`istio`：

```
istioctl manifest apply --set profile=demo
```

#### 注意

演示配置文件非常适合用于演示 Istio，但不建议用于生产安装。

1.  确保一切都已经启动运行，如下所示：

```
kubectl get svc -n istio-system
```

您应该在`istio-system`命名空间中看到许多服务：

![显示 istio-system 命名空间中所有服务的输出。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.46.jpg)

###### 图 10.46：所有 Istio 服务都已经启动运行

您现在已经安装并运行了 Istio。

### 自动注入 Envoy 作为边车

如本节介绍中所述，服务网格使用边车来实现功能。 Istio 具有使用命名空间中的标签自动安装其使用的`Envoy`边车的能力。我们可以通过以下步骤使其以这种方式运行：

1.  让我们使用适当的标签（即`istio-injection=enabled`）为默认命名空间打标签：

```
kubectl label namespace default istio-injection=enabled
```

1.  让我们启动一个应用程序，看看边车是否确实自动部署（`bookinfo.yaml`文件在本章的源代码中提供）：

```
kubectl create -f bookinfo.yaml
```

获取在默认命名空间上运行的 Pods。Pods 可能需要几秒钟才能显示出来，并且所有 Pods 变为`Running`可能需要几分钟：

```
kubectl get pods
```

1.  在任何一个 Pod 上运行`describe`命令：

```
kubectl describe pods/productpage-v1-<pod-ID>
```

您可以看到边车确实已经应用：

![显示 Istio 自动注入边车代理列出产品页面和 istio-proxy 的详细信息的输出。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.47.jpg)

###### 图 10.47：Istio 自动注入边车代理

请注意，即使没有对基础应用程序进行任何修改，我们也能够部署并附加 Istio 服务网格到容器。

### 强制使用双向 TLS

为了加密所有的服务对服务流量，我们将启用 mTLS。默认情况下，不强制使用双向 TLS。在本节中，我们将逐步强制执行 mTLS 身份验证。

#### 注意

如果您想了解 Istio 中端到端安全框架的更多信息，请阅读 https://istio.io/docs/concepts/security/#authentication-policies。有关双向 TLS 的更多细节，请阅读 https://istio.io/docs/concepts/security/#mutual-tls-authentication。

**部署示例服务**

在这个例子中，您将部署两个服务，`httpbin`和`sleep`，在不同的命名空间下。其中两个命名空间，`foo`和`bar`，将成为服务网格的一部分。这意味着它们将拥有`istio` sidecar 代理。您将在这里学习一种不同的注入 sidecar 的方式。第三个命名空间，`legacy`，将在没有 sidecar 代理的情况下运行相同的服务：

![我们将要构建的演示应用程序的图形表示。图像显示网格中的两个命名空间和网格外的一个命名空间。每个命名空间都有两个 pod，sleep 和 httpbin。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.48.jpg)

###### 图 10.48：三个命名空间中的两个在服务网格中

我们将使用以下命令查看命名空间的服务：

1.  首先，我们创建命名空间（`foo`、`bar`和`legacy`），并在这些命名空间中创建`httpbin`和`sleep`服务：

```
kubectl create ns foo
kubectl apply -f <(istioctl kube-inject \
-f httpbin.yaml) -n foo 
kubectl apply -f <(istioctl kube-inject \
-f sleep.yaml) -n foo
kubectl create ns bar
kubectl apply -f <(istioctl kube-inject \
-f httpbin.yaml) -n bar
kubectl apply -f <(istioctl kube-inject \
-f sleep.yaml) -n bar
kubectl create ns legacy
kubectl apply -f httpbin.yaml -n legacy 
kubectl apply -f sleep.yaml -n legacy
```

正如您所看到的，我们现在正在使用`istioctl`工具来注入 sidecar。它会读取我们的 YAML 文件，并在部署中注入 sidecar。现在我们在`foo`和`bar`命名空间中有一个带有 sidecar 的服务。但是在`legacy`命名空间中没有注入。

1.  让我们检查一下是否一切都部署成功了。为了检查这一点，我们提供了一个脚本，它会从每个命名空间到所有其他命名空间建立连接。该脚本将输出每个连接的 HTTP 状态码。![显示脚本如何使用休眠 pod 测试所有连接，并在每个命名空间中与 httpbin 建立连接的图表。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.49.jpg)

###### 图 10.49：脚本将测试所有连接

1.  使用以下命令运行脚本：

```
bash test_mtls.sh
```

上述命令会迭代所有可达的组合。您应该看到类似以下输出。HTTP 状态码为`200`表示成功：

![bash test_mtls.sh 命令的输出显示 HTTP 状态码为 200，表示所有 pod 都成功，并且证明每个 Pod 都可以与所有其他 Pod 通信。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.50.jpg)

###### 图 10.50：没有任何策略，我们可以成功地从每个命名空间连接到其他命名空间

这向我们表明，在当前配置中，所有 Pod 都可以与所有其他 Pod 通信。

1.  确保除默认策略外没有现有策略，如下所示：

```
kubectl get policies.authentication.istio.io \
--all-namespaces
kubectl get meshpolicies.authentication.istio.io
```

这应该向您展示：

![验证只有两个策略存在。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.51.jpg)

###### 图 10.51：只应存在两个策略

1.  另外，确保没有适用的目标规则：

```
kubectl get destinationrules.networking.istio.io \
--all-namespaces -o yaml | grep "host:"
```

在结果中，不应该有带有`foo`、`bar`、`legacy`或通配符（表示为`*`）的主机。

![确保没有适用的目标规则，并且没有带有 foo、bar、legacy 或*通配符的主机。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.52.jpg)

###### 图 10.52：不应该有带有 foo、bar、legacy 或*通配符的主机

我们已成功部署了示例服务，并且能够确认在默认情况下，所有服务都能够彼此通信。

### 全局启用 mTLS

使用 mTLS 策略，您可以声明所有服务在与其他服务通信时必须使用 mTLS。如果不使用 mTLS，即使恶意用户可以访问集群，即使他们无法访问命名空间，也可以与任何 Pod 通信。如果拥有足够的权限，他们还可以在服务之间充当中间人。在服务之间实施 mTLS 减少了中间人攻击的可能性：

1.  要全局启用双向 TLS，我们将创建以下`MeshPolicy`（在`mtls_policy.yaml`中提供）：

```
1   apiVersion: authentication.istio.io/v1alpha1
2   kind: MeshPolicy
3   metadata:
4     name: default
5   spec:
6     peers:
7     - mtls: {}
```

由于此`MeshPolicy`没有选择器，它将适用于所有工作负载。网格中的所有工作负载只接受使用 TLS 加密的请求。这意味着`MeshPolicy`处理连接的传入部分：

![图形表示显示 MeshPolicy 如何应用于传入连接。图片显示 foo 和 bar 命名空间中的 httpbin 是 MeshPolicy 的一部分。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.53.jpg)

###### 图 10.53：MeshPolicy 适用于传入连接

您可以使用以下命令创建`MeshPolicy`：

```
kubectl apply -f mtls_policy.yaml
```

#### 注意

我们正在粗暴和激进地应用 mTLS。通常，在生产系统中，您会慢慢引入 mTLS。Istio 有一个特殊的 mTLS 强制模式称为`permissive`，可以帮助实现这一点。在`permissive`模式下使用 mTLS，Istio 将尝试在可能的情况下实现 mTLS，并在不可能的情况下记录警告。但是，流量将继续流动。

1.  现在再次运行脚本以测试网络连接：

```
bash test_mtls.sh
```

1.  带有边车的系统在运行此命令时将失败，并将收到`503`状态代码，因为客户端仍在使用纯文本。可能需要几秒钟才能使`MeshPolicy`生效。*图 10.54*显示输出：![bash test_mtls.sh 命令的输出，显示具有边车的 httpbin.foo 和 httpbin.barPods 的流量失败，状态代码为 503。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.54.jpg)

###### 图 10.54：带有边车的 Pod 的流量失败，状态代码为 503

如果在先前的输出中更频繁地看到`200`状态代码，请考虑等待几秒钟，然后重新运行测试。

1.  现在，我们将通过将目标规则设置为使用类似于整个网格的身份验证策略的`*`通配符来允许某些流量。这是配置客户端端的必需操作：

```
1   apiVersion: networking.istio.io/v1alpha3
2   kind: DestinationRule
3   metadata:
4     name: default
5     namespace: istio-system
6   spec:
7     host: "*.local"
8     trafficPolicy:
9       tls:
10        mode: ISTIO_MUTUAL
```

让我们看看这个文件：

+   **第 2 行**：在这里，我们正在创建一个`DestinationRule`，它定义了在路由发生后适用于服务流量的策略。

+   **第 7 行**：任何`.local`中的主机的流量（在我们的情况下是集群中的所有流量）应使用此策略。

+   **第 8-10 行**：在这里，我们定义所有流量都需要 mTLS。

`DestinationRule`适用于连接的传出部分，如*图 10.55*所示：

![图形表示显示 DestinationRule 适用于连接的传出部分。图像显示 foo 和 bar 名称空间中的 sleep 是 DestinationRule 的一部分。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.55.jpg)

###### 图 10.55：DestinationRule 适用于传出流量

我们可以使用以下命令创建这个：

```
kubectl create -f destinationRule.yaml
```

我们可以通过再次运行相同的命令来检查其影响：

```
bash test_mtls.sh
```

这次，返回的代码将如*图 10.56*所示：

![重新运行 bash test_mtls.sh 命令，显示 foo 和 bar 现在可以相互连接，但它们无法再连接到 legacy。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_10.56.jpg)

###### 图 10.56：foo 和 bar 现在可以相互连接，但它们无法再连接到 legacy

让我们考虑一下我们在这种情况下实施了什么。我们实施了：

一个需要 Pod 中传入的 TLS 流量的集群范围策略。

一个需要对外流量进行 mTLS 的集群范围 DestinationRule。

这样做的影响是网格内的服务（也称为具有边车）现在可以使用 mTLS 相互通信，并且完全不在网格内的服务（也称为没有边车）也可以相互通信，只是没有 mTLS。由于我们当前的配置，当流的一部分在网格中时，服务之间的通信会中断。

让我们确保清理我们部署的任何资源：

```
istioctl manifest generate --set profile=demo | kubectl delete -f -
for NS in "foo" "bar" "legacy"
do
kubectl delete -f sleep.yaml -n $NS
kubectl delete -f httpbin.yaml -n $NS
done
kubectl delete -f bookinfo.yaml
```

这结束了 Istio 的演示。

## 总结

在本章中，我们专注于 Kubernetes 中的安全性。我们从使用 Azure AD 中的身份查看了集群 RBAC。之后，我们继续讨论在 Kubernetes 中存储秘密。我们详细介绍了创建、解码和使用秘密。最后，我们安装并注入了 Istio，实现了能够设置系统范围策略而无需开发人员干预或监督的目标。由于黑客喜欢攻击易受攻击的系统，您在本章中学到的技能将有助于使您的设置不太可能成为目标。

在接下来的最后一章中，您将学习如何在 Azure Kubernetes Service（AKS）上部署无服务器函数。
