# Kubernetes Windows 实用指南（五）

> 原文：[`zh.annas-archive.org/md5/D85F9AD23476328708B2964790249673`](https://zh.annas-archive.org/md5/D85F9AD23476328708B2964790249673)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：使用 Kubernetes 的开发工作流程

让我们面对现实吧——Kubernetes 应用程序开发并不简单。在前几章中，我们主要关注了 Kubernetes 的集群供应和运营方面，这本身就有其复杂性。作为在 Windows 上使用 Kubernetes 的软件开发人员，您将面临完全不同的挑战。事实上，您可能需要调整设计方法，采用云优先、云原生、Kubernetes 优先或其他现代方法。您已经看到，Kubernetes 擅长处理从未设计时就意味着要在容器中托管的 Windows 应用程序，但要充分利用 Kubernetes 的功能，您必须扭转这种依赖关系，开始将 Kubernetes 视为设计的中心和开发环境。

在本章中，我们将演示一些流行的工具，您可以在 Windows 上的开发工作流程中使用，从 Visual Studio 2019 和 Visual Studio Code 的基本集成开始，到使用 Azure Application Insights 进行高级快照调试结束。您还将学习如何使用 Helm（版本 3）为您的 Kubernetes 应用程序创建可再分发的软件包。最后，我们将介绍 Azure Dev Spaces，它极大地简化了整个团队的 Kubernetes 开发。

本章将重点讨论以下主题：

+   使用 Kubernetes 的开发工具

+   使用 Helm 打包应用程序

+   使用 Azure Application Insights 调试容器化应用程序

+   使用 Kubernetes 仪表板

+   使用 Azure Dev Spaces 团队中的微服务开发

# 技术要求

对于本章，您将需要以下内容：

+   已安装 Windows 10 Pro、Enterprise 或 Education（1903 版或更高版本；64 位）。

+   Microsoft Visual Studio 2019 Community（或任何其他版本），如果您想编辑应用程序的源代码并对其进行调试。请注意，对于快照调试器功能，您需要企业版。

+   Microsoft Visual Studio Code，如果您想使用图形界面管理 Kubernetes 集群。

+   Windows 的 Chocolatey 软件包管理器（[`chocolatey.org/`](https://chocolatey.org/)）。

+   Azure 账户。

+   使用 Azure Kubernetes Service（AKS）引擎部署的 Windows/Linux Kubernetes 集群，准备部署前几章中的投票应用程序。

使用 Chocolatey 软件包管理器并非强制性，但它可以使安装过程和应用程序版本管理变得更加容易。安装过程在[`chocolatey.org/install`](https://chocolatey.org/install)中有文档记录。

要跟随操作，您需要自己的 Azure 帐户以创建 Kubernetes 集群的 Azure 资源。如果您尚未为之前的章节创建帐户，您可以阅读有关如何获取个人使用的有限免费帐户的更多信息，网址为[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)。

使用 AKS 引擎部署 Kubernetes 集群已在第八章中进行了介绍，*部署混合 Azure Kubernetes 服务引擎集群*。将 Voting 应用程序部署到 Kubernetes 已在第十章中进行了介绍，*部署 Microsoft SQL Server 2019 和 ASP.NET MVC 应用程序*。

您可以从官方*GitHub*存储库中下载本书章节的最新代码示例，网址为[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter12`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter12)。

# 使用 Kubernetes 的开发工具

在 Windows 上日常开发.NET 应用程序时，您很可能会使用 Visual Studio 2019 或 Visual Studio Code。在本节中，我们将向您展示如何安装用于 Kubernetes 的附加扩展，以便为容器编排器引导应用程序。

Visual Studio 2019 和 Visual Studio Code 目前对在 Kubernetes 中管理 Windows 容器的支持非常有限。您将无法使用大多数功能，例如与 Azure Dev Spaces 集成，尽管这可能会在未来发生变化。在.NET Core 的情况下，您可以在 Windows 上开发并依赖于 Linux Docker 镜像。

首先，让我们看看如何在 Visual Studio 2019 中启用 Kubernetes 支持。

# Visual Studio 2019

最新版本的 Visual Studio 带有预定义的 Azure 开发工作负载，您可以直接从 Visual Studio 安装程序应用程序轻松安装。您无需安装任何其他扩展即可在 Visual Studio 中获得 Kubernetes 支持。

如果您之前在 Visual Studio 的早期版本中使用过 Visual Studio Tools for Kubernetes（现已弃用），那么您可以在最新版本的 Visual Studio 的 Azure 开发工作负载中期望类似的功能。

要安装 Azure 开发工作负载，请按照以下步骤操作：

1.  在 Windows 的开始菜单中，搜索 Visual Studio Installer 应用程序。

1.  选择您的 Visual Studio 版本，点击更多，然后选择修改。

1.  选择 Azure 开发并通过点击修改来接受更改：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/3b8a6b8d-896c-4139-a5e6-890ef713949c.png)

1.  等待安装完成并启动 Visual Studio。

现在，您可以为 Kubernetes 的容器应用程序创建新项目，其中包括以下内容：

+   *ASP.NET* Core

+   用于打包的 Helm 图表

+   用于在 AKS 上进行快速迭代开发的 Azure Dev Spaces

也可以为现有的 ASP.NET Core 添加 Kubernetes/Helm 支持：

1.  在解决方案资源管理器中右键单击项目。

1.  导航到添加|容器编排器支持

1.  选择 Kubernetes/Helm。

不幸的是，Visual Studio 2019 目前对于管理 Kubernetes 集群的功能有限。作为替代，您可以使用 Visual Studio Code 来完成这项任务。

# Visual Studio Code

对于 Visual Studio Code，您可以使用微软提供的两个*官方*扩展：

+   **Kubernetes** **(**`ms-kubernetes-tools.vscode-kubernetes-tools`**)**：使您能够在树视图中探索 Kubernetes 集群，管理 Kubernetes 对象，并为编辑清单文件和 Helm 图表提供智能感知。

+   **Azure Dev Spaces (**`azuredevspaces.azds`**)**：启用 Azure Dev Spaces 集成，类似于您在 Visual Studio 2019 中的功能。

要安装这两个扩展，打开 Visual Studio Code 并按照以下步骤操作：

1.  打开扩展面板（*Ctrl*+*Shift*+*X*）。

1.  在 Marketplace 中搜索 Kubernetes。

1.  点击安装。

1.  重复相同步骤以安装 Azure Dev Spaces。

在右侧菜单中，您现在可以使用 Kubernetes 面板，它会自动加载您的 kubeconfig。这个扩展特别适用于处理包含清单文件的工作空间，因为您会得到自动完成、YAML 语法高亮显示和验证。

您可以从树视图或使用命令（*Ctrl*+*Shift*+*P*）来管理您的集群——这可以代替在 PowerShell 中执行`kubectl`命令。例如，您可以查看容器的日志：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/29d93186-f70d-493f-b6f0-14feb40a227f.png)

Visual Studio Code 目前是 Windows 中用于处理 Kubernetes 和 Helm 的最有用和最先进的工具。 在下一节中，我们将展示如何使用 Helm 打包应用程序。

# 使用 Helm 打包应用程序

应用程序需要打包以便轻松重新分发和管理依赖关系。 在 Windows 中，您可以使用 Chocolatey，在 Ubuntu 中，您可以使用**APT**（Advanced Package Tool 的缩写），而对于 Kubernetes，您可以使用 Helm 作为包管理器（[`v3.helm.sh/`](https://v3.helm.sh/)）。 还有一些替代方案，比如 Kustomize（它在`kubectl`中具有本机支持）和 Kapitan，但总的来说，Helm 目前被认为是行业标准，拥有最大的 Helm 图表官方存储库（[`github.com/helm/charts`](https://github.com/helm/charts)）。

Helm 的主要用例如下：

+   将流行软件部署到您的 Kubernetes 集群。 软件包以 Helm 图表的形式分发。

+   共享您自己的应用程序作为 Helm 图表。 这可以包括为最终用户打包产品或将 Helm 用作系统中微服务的内部包和依赖项管理器。

+   确保应用程序获得适当的升级，包括依赖关系管理。

+   为您的需求配置软件部署。 Helm 图表基本上是 Kubernetes 清单的通用**另一种标记语言**（**YAML**）参数化模板。 Helm 使用 Go 模板（[`godoc.org/text/template`](https://godoc.org/text/template)）进行参数化。 如果您熟悉 Go，那么您会感到很亲切； 如果不熟悉，那么您会发现它与其他模板系统非常相似，比如 Mustache。

请注意，Helm 的架构在最近发布的 3.0.0 版本中发生了 drastical 变化。

以前，Helm 需要在 Kubernetes 上部署一个名为 Tiller 的专用服务，负责与 Kubernetes API 的实际通信。 这引发了各种问题，包括安全性和 RBAC（Role-Based Access Control 的缩写）问题。 从 Helm 3.0.0 开始，不再需要 Tiller，图表管理由客户端完成。 您可以在官方 FAQ 中阅读有关旧版 Helm 版本之间的区别的更多信息[`helm.sh/docs/faq/#changes-since-helm-2`](https://helm.sh/docs/faq/#changes-since-helm-2)。

Helm 被分发为一个带有类似 kubectl 的 CLI 的客户端（库）。现在可以使用客户端执行 Helm 中的所有操作。让我们在您的 Windows 机器上安装 Helm。

# 安装 Helm

建议在 Windows 机器上使用 Chocolatey 安装 Helm。要安装 Helm，请按照以下步骤进行：

1.  以管理员身份打开 PowerShell 窗口。

1.  执行以下安装命令：

```
 choco install kubernetes-helm
```

1.  安装完成后，请验证您是否运行版本`3.0.0`或更高版本：

```
PS C:\src> helm version
version.BuildInfo{Version:"v3.0.0", GitCommit:"e29ce2a54e96cd02ccfce88bee4f58bb6e2a28b6", GitTreeState:"clean", GoVersion:"go1.13.4"}
```

1.  检查是否有使用`helm repo list`命令添加的任何存储库。如果没有（在版本 3.0.0 中），添加官方的`stable`存储库并更新：

```
helm repo add stable https://kubernetes-charts.storage.googleapis.com
helm repo update
```

1.  现在，尝试搜索一些 Helm 图表，例如，让我们检查是否有 Microsoft SQL Server 的图表：

```
PS C:\src> helm search hub mssql
URL                                             CHART VERSION   APP VERSION     DESCRIPTION
https://hub.helm.sh/charts/stable/mssql-linux   0.10.1          14.0.3023.8     SQL Server 2017 Linux Helm Chart
```

**Helm Hub** ([`hub.helm.sh/`](https://hub.helm.sh/))提供了一个用户友好的界面，用于浏览官方 Helm 存储库([`github.com/helm/charts`](https://github.com/helm/charts))。

我们找到了一个在 Linux 容器中运行的 SQL Server 的稳定图表。它基于 2017 年的版本，但我们仍然可以将其用于我们的投票应用程序。

# 使用 Helm 部署 Microsoft SQL Server

现在让我们来看看如何将 Microsoft SQL Server 部署到我们的 AKS Engine 集群。每个图表的结构都是相似的：

+   在`root`目录中，您可以找到一个详细的自述文件，其中描述了如何安装图表以及可能的参数是什么([`github.com/helm/charts/tree/master/stable/mssql-linux`](https://github.com/helm/charts/tree/master/stable/mssql-linux))。

+   `Chart.yaml`文件包含图表元数据，包括依赖信息。

+   `templates`目录包含所有用于 Kubernetes 清单的 Go 模板。

+   `values.yaml`文件定义了可以使用 CLI 参数或提供 YAML 文件来覆盖的图表的默认值。

安装 Helm 图表的过程很简单：为您的需求定义正确的值（可能需要分析模板以了解发生了什么），然后运行`helm install`命令。查看 SQL Server 的图表，我们需要指定以下`values.yaml`文件：

```
acceptEula:
  value: "y"

edition:
  value: Developer

sapassword: "S3cur3P@ssw0rd"

service:
  type: LoadBalancer

persistence:
  enabled: true
  storageClass: azure-disk

nodeSelector:
  "kubernetes.io/os": linux
```

使用 Helm 部署 SQL Server，请按照以下步骤进行：

1.  打开 PowerShell 窗口。

1.  将前面的文件保存为`values.yaml`在当前目录中。

1.  创建先决条件。我们需要`dev-helm`命名空间和`azure-disk` StorageClass。创建以下`prereq.yaml`清单文件：

```
---
kind: Namespace
apiVersion: v1
metadata:
  name: dev-helm
  labels:
    name: dev-helm
---
kind: StorageClass
apiVersion: storage.k8s.io/v1beta1
metadata:
  name: azure-disk
provisioner: kubernetes.io/azure-disk
parameters:
  storageaccounttype: Standard_LRS
  kind: Managed
```

1.  使用`kubectl apply -f .\prereq.yaml`命令应用清单文件。

1.  执行 Helm 图表安装的干运行。您将能够看到将应用哪些 Kubernetes 清单文件：

```
helm install demo-mssql stable/mssql-linux `
 --namespace dev-helm `
 --values .\values.yaml `
 --debug `
 --dry-run
```

此命令将执行`stable/mssql-linux`作为`demo-mssql` Helm 发布在`dev-helm`命名空间的安装干运行。

1.  如果您对结果满意，请执行安装：

```
helm install demo-mssql stable/mssql-linux `
 --namespace dev-helm `
 --values .\values.yaml
```

1.  使用以下命令观察 SQL Server 的部署：

```
kubectl get all --all-namespaces -l release=demo-mssql
```

1.  您还可以使用 Helm CLI 检查状态：

```
helm status -n dev-helm demo-mssql
```

1.  使用 SQL Server Management Studio 或 SQL Tools 容器验证 SQL Server 是否正常运行。您可以使用服务的外部 IP 地址——我们已经暴露了一个负载均衡器服务。

管理 Helm 发布的命令与 kubectl 类似，都是命名空间范围的。

正如你所看到的，使用 Helm 在集群中快速引导复杂的应用程序非常高效。现在，让我们为我们的投票应用程序准备一个 Helm 图表。我们将使用一个 SQL Server 图表作为依赖。

# 为我们的投票应用程序创建一个 Helm 图表

为了将我们的投票应用程序打包为 Helm 图表，我们将使用上一章中用于水平 Pod 自动缩放演示的清单文件。您可以在书的 GitHub 存储库中找到基本的清单文件。

为了准备 Helm 图表，我们需要按照以下步骤进行：

1.  收集所有必需的 Kubernetes 清单文件，并确定哪些部分应该被参数化。我们将用这些来创建 Helm 模板文件和“默认值”文件。

1.  为我们的应用程序定义所有的依赖关系，并为它们定义适当的参数值。我们将把这些参数注入到我们父图表的“默认值”文件中。

1.  将 Entity Framework 数据库迁移转换为安装后和升级后的 Helm 钩子。

这里的大部分工作是将原始的 Kubernetes 清单文件转换为 Helm 模板。在接下来的几个步骤中，我们将只展示这个过程的相关部分。为了获得最佳的编码体验，请使用 Visual Studio Code 编辑 Helm 图表。您可以在 Github 存储库[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter12/03_voting-application-helm`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter12/03_voting-application-helm)中找到我们投票应用程序的最终 Helm 图表。

请按照以下步骤创建您的 Helm 图表：

1.  首先，让我们从集群中卸载 SQL Server Helm 发布。我们将自动将此图表作为 Voting 应用程序父图表的依赖项安装：

```
helm uninstall -n dev-helm demo-mssql
```

1.  运行以下命令创建 Helm 图表脚手架：

```
helm create voting-application
```

这将创建一个名为`voting-application`的目录，其中包含 Helm 图表的基本结构和模板。我们将重复使用其中的大部分内容。

1.  使用`cd .\voting-application\`导航到图表目录，并修改`Chart.yaml`文件中的图表元数据：

```
apiVersion: v2
name: voting-application
description: Voting Application (Windows Containers) Helm chart
type: application
version: 0.1.0
appVersion: 1.4.0
dependencies:
  - name: mssql-linux
    version: 0.10.1
    repository: https://kubernetes-charts.storage.googleapis.com
sources:
- https://github.com/hands-on-kubernetes-on-windows/voting-application
```

这里代码的最重要部分涉及定义适当的依赖关系和设置适当的`apiVersion`，这将在模板中用作 Docker 镜像标签。从官方稳定存储库`https://kubernetes-charts.storage.googleapis.com`中添加`mssql-linux`的最新图表版本（`0.10.1`）。

1.  使用`cd .\templates\`命令导航到`templates`目录。我们将在原始形式中使用`reuse _helpers.tpl`（其中包含模板助手函数）、`service.yaml`、`serviceaccount.yaml`和`ingress.yaml`。这些清单模板将产生我们需要的内容，无需任何更改。

1.  下一步是为我们的 Deployment 定义一个清单模板，命名为`deployment.yaml`；您应该检查图表脚手架中的原始`deployment.yaml`文件，因为您可以在我们的模板中使用其中的大部分内容。此模板的最终版本可以在[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter12/03_voting-application-helm/templates/deployment.yaml`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter12/03_voting-application-helm/templates/deployment.yaml)找到。例如，让我们解释一下如何对 Docker 镜像标签进行参数化并注入 SQL Server 密码：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "voting-application.fullname" . }}
  labels:
    {{- include "voting-application.labels" . | nindent 4 }}
spec:
  ...
  template:
    ...
    spec:
      ...
      containers:
        - name: {{ .Chart.Name }}-frontend
          ...
          image: "{{ .Values.image.repository }}:{{ .Chart.AppVersion }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }} 
          env:
          - name: MSSQL_SA_PASSWORD
            valueFrom:
              secretKeyRef:
                name: {{ .Release.Name }}-mssql-linux-secret
                key: sapassword
          - name: CONNECTIONSTRING_VotingApplication
            value: "Data Source={{ .Release.Name }}-mssql-linux;Initial Catalog=VotingApplication;MultipleActiveResultSets=true;User Id=sa;Password=$(MSSQL_SA_PASSWORD);"
```

让我们一步一步地分析。`{{ include "voting-application.fullname" . }}`短语向您展示了如何包含在`_helpers.tpl`中定义的模板，并将其用作部署名称。如果有更高级的模板逻辑，您应该始终使用此文件来定义可重用的模板。

Pod 容器的 Docker 镜像定义为`"{{ .Values.image.repository }}:{{ .Chart.AppVersion }}"`；您可以使用`.Values`来引用在`values.yaml`文件中定义的变量，使用`.Chart`来引用图表元数据。最后，我们使用了`{{ .Release.Name }}-mssql-linux-secret`来引用由依赖的 SQL Server 图表创建的秘密。

您需要了解依赖图表的内部结构，以了解应使用什么值（[`github.com/helm/charts/blob/master/stable/mssql-linux/templates/secret.yaml`](https://github.com/helm/charts/blob/master/stable/mssql-linux/templates/secret.yaml)[)。](https://github.com/helm/charts/blob/master/stable/mssql-linux/templates/secret.yaml)

不幸的是，Helm 没有一个简单的引用过程来从依赖图表中获取这些值，因此您必须要么按照 Helm 使用的约定硬编码名称（我们这样做了），要么在`_helpers.tpl`中定义一个专用模板（这是一种更清晰的方法，但也更复杂）。

1.  定义 RBAC 角色和 RoleBindings，我们创建了两个额外的模板文件，`rolebinding.yaml`和`role.yaml`。您可以在[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter12/03_voting-application-helm/templates`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter12/03_voting-application-helm/templates)中找到内容。为应用程序定义 RBAC 清单可以是有条件的；您可以在官方 Helm 图表中看到这种做法。

1.  我们需要定义的最后一个清单是用于运行 Entity Framework 数据库迁移的 Helm 钩子（[`helm.sh/docs/topics/charts_hooks/`](https://helm.sh/docs/topics/charts_hooks/)）（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter12/03_voting-application-helm/templates/post-install-job.yaml`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter12/03_voting-application-helm/templates/post-install-job.yaml)）。钩子就像任何其他清单模板一样，但它具有额外的注释，确保清单在图表发布的生命周期的某个特定点应用。此外，如果钩子是 Kubernetes 作业，Helm 可以等待作业完成并进行清理。我们希望这个钩子是一个作业，与我们已经用于 EF 迁移的相同类型，并且希望它在安装或升级发布后执行。让我们看看如何在`post-install-job.yaml`文件中定义我们作业的注释：

```
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ .Release.Name }}-ef6-database-migrate
  ...
  annotations:
    "helm.sh/hook": post-install,post-upgrade
    "helm.sh/hook-weight": "-5"
    "helm.sh/hook-delete-policy": hook-succeeded
spec:
  backoffLimit: 10
```

将清单模板转换为钩子的关键注释是`"helm.sh/hook"`。我们使用`post-install`和`post-upgrade`值来确保钩子在安装后和 Helm 发布升级后执行。`"helm.sh/hook-weight"`短语用于确定钩子的顺序，在我们的情况下并不重要，因为我们只有一个钩子。

`"helm.sh/hook-delete-policy"`短语定义了作业实例应在何种情况下自动删除。我们希望仅在成功的钩子执行时删除它们；否则，我们希望保留资源，以便我们可以调试问题。

请注意，我们将作业的`backoffLimit`指定为`10`；在 SQL Server pod 创建时间较长的情况下，我们需要这个值，这种情况下可能需要几分钟；如果我们不这样做，钩子将失败得太快。

1.  最后一步是在图表的根目录中的`values.yaml`文件中提供默认模板值（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter12/03_voting-application-helm/values.yaml`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter12/03_voting-application-helm/values.yaml)）。让我们来看看文件中的一些重要部分：

```
...
image:
  repository: packtpubkubernetesonwindows/voting-application
  pullPolicy: IfNotPresent
...
nodeSelector: 
  "kubernetes.io/os": windows
...
mssql-linux:
  acceptEula:
    value: "y"
  edition:
    value: Developer
  sapassword: "S3cur3P@ssw0rd"
  service:
    type: LoadBalancer
  persistence:
    enabled: true
    storageClass: azure-disk
  nodeSelector:
    "kubernetes.io/os": linux
```

您可以组织值；但是，它们已经方便地排列好了。例如，关于 Docker 镜像的所有内容都被分组到图像节点中，然后您可以在图表中引用图像存储库名称为`{{ .Values.image.repository }}`。要记住的一个非常重要的事情是提供适当的`nodeSelector`，以确保 pod 仅安排在 Windows 节点上。最后，使用其名称为依赖图表定义值。

在这里，我们使用了`mssql-linux`，因为这是我们在`Chart.yaml`文件中引用的图表。您可以在文档中阅读有关管理依赖项和定义值的更多信息[`helm.sh/docs/topics/charts/#chart-dependencies`](https://helm.sh/docs/topics/charts/#chart-dependencies)。

Helm 的许多方面都基于惯例。您可以在文档中找到有关实施图表的最佳实践的更多信息[`helm.sh/docs/topics/chart_best_practices/`](https://helm.sh/docs/topics/chart_best_practices/)。使用`helm lint`命令检查图表是否存在任何问题。

我们的投票应用程序的图表已准备就绪。现在，我们将在`dev-helm`命名空间中将此图表安装到我们的 Kubernetes 集群中：

1.  在图表的`root`目录中打开 PowerShell 窗口。

1.  确保从存储库中获取所有依赖的图表：

```
helm dependency update
```

1.  执行 Helm 图表安装的`dry run`以检查清单文件：

```
helm install voting-application . `
 --namespace dev-helm `
 --debug `
 --dry-run
```

此命令将打印所有解析的清单文件，这些文件将应用于当前目录中图表的安装，使用默认值。

1.  现在，安装图表。我们需要为安装提供扩展的超时，因为我们的 Entity Framework 数据库迁移作业可能需要几分钟才能成功。这取决于 SQL Server 初始化和准备连接的速度。使用以下命令：

```
helm install voting-application . `
 --namespace dev-helm `
 --debug `
 --timeout 900s
```

1.  安装将需要一些时间；您可以在单独的 PowerShell 窗口中观察单个 Kubernetes 对象的部署进度。

```
kubectl get all -n dev-helm
```

1.  安装结束后，使用`kubectl get -n dev-helm svc -w voting-application`获取我们的投票应用程序的 LoadBalancer 服务的外部 IP 地址。在 Web 浏览器中导航到该地址并享受！

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/171f7646-087d-479b-af81-98ec8625ced1.png)

在生产环境中，您应该使用 Helm 图表存储库来管理您的图表。您可以在[`v3.helm.sh/docs/topics/chart_repository/`](https://v3.helm.sh/docs/topics/chart_repository/)了解有关设置存储库的更多信息。此外，为了*声明性*地管理 Helm 图表的发布，类似于`kubectl apply`，您可以考虑使用`Helmfile`（[`github.com/roboll/helmfile`](https://github.com/roboll/helmfile)）。

在下一节中，您将学习如何轻松将 Azure Application Insights 添加到在 Windows 容器中运行的 ASP.NET MVC 应用程序中。我们还将向您展示如何执行刚刚安装的 Helm 发布的升级。

# 使用 Azure Application Insights 调试容器化应用程序

Azure Application Insights 是 Azure Monitor 的一部分，为您的应用程序提供**应用程序性能管理**（**APM**）功能。它是一个庞大的平台，在 Azure 门户中具有丰富的**用户界面**（**UI**）,提供以下功能（以及其他功能）：

+   请求监控和跟踪，包括多个微服务之间的分布式跟踪

+   异常监控和快照调试

+   收集主机机器的性能计数器

+   智能异常检测和警报

+   轻松的日志收集和分析

对我们来说最有趣的功能是快照调试，它可以帮助诊断在不建议使用附加远程调试器的生产部署中的问题。为此，如果您想使用 Visual Studio 分析快照，您将需要 Visual Studio 2019 企业版。或者，您可以在 Azure 门户本身进行分析，该门户具有轻量级的基于 Web 的调试器。

或者，您可以使用 Istio 服务网格提供的带外仪器应用程序监控，在 Azure 上运行的 Kubernetes 应用程序，如[`docs.microsoft.com/en-us/azure/azure-monitor/app/kubernetes`](https://docs.microsoft.com/en-us/azure/azure-monitor/app/kubernetes)中所述。

启用 Azure Application Insights 与快照调试，我们需要按照以下步骤进行：

1.  在 Visual Studio 项目中启用 Azure Application Insights。

1.  安装`Microsoft.ApplicationInsights.SnapshotCollector` NuGet 包。

1.  配置快照调试并修改 Serilog 配置以使用发送日志到`System.Diagnostics.Trace`的接收器。

1.  添加演示异常。

1.  构建一个新的 Docker 镜像并将其推送到 Docker Hub。

1.  升级 Helm 发布。

之后，我们将能够直接在 Azure 门户中分析跟踪图、应用程序日志和异常。请注意，此日志收集解决方案与我们在第八章中演示的不同，*部署混合 Azure Kubernetes 服务引擎集群*，在那里我们使用 Azure Log Analytics 来处理 AKS Engine。它们使用相同的 Azure 服务，但在新解决方案中，我们将仅获取应用程序日志——在 Azure Log Analytics 视图中看不到 Kubernetes 或容器运行时日志。

# 启用 Azure 应用程序洞察

请按照以下步骤在我们的投票应用程序中启用 Azure 应用程序洞察。或者，您可以使用 Github 存储库中提供的现成源代码[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter12/04_voting-application-azure-application-insights-src`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter12/04_voting-application-azure-application-insights-src)。

如果选择这样做，您需要在 Helm 发布升级期间的后续步骤中提供自己的 Azure 应用程序洞察密钥：

1.  在 Visual Studio 2019 中打开`VotingApplication`解决方案。

1.  在解决方案资源管理器中，右键单击`VotingApplication`项目，选择添加，然后选择应用程序洞察遥测...：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/30d776a5-31b6-4ab1-80f8-18b010f920b9.png)

1.  点击开始。

1.  登录 Azure 并提供一个新的资源组和资源名称（或使用默认值）。

1.  点击注册。该操作将需要几分钟的时间。一旦时间过去，将在您的 Azure 订阅中创建一个新的 Azure 应用程序洞察实例，并将适当的 NuGet 包添加到 Visual Studio 项目中。

1.  更新 CodeLens 的资源并启用它来从`System.Diagnostics`中收集跟踪：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/6bc49f59-621a-410b-be48-85af04691aec.png)

1.  我们不希望将仪表键硬编码到 Docker 镜像中。应用程序洞察支持注入`APPINSIGHTS_INSTRUMENTATIONKEY`环境变量的能力。导航到解决方案中的`ApplicationInsights.config`文件，找到以下 XML 节点，记下密钥以供进一步使用，并删除 XML 节点：

```
<InstrumentationKey>4e810bf1-58c4-4af7-a67d-36fcdcf24a2f</InstrumentationKey>
```

1.  搜索解决方案中所有的仪表键的出现。您会在`_Layout.cshtml`中找到另一个；用以下值替换它：

```
instrumentationKey: '@Microsoft.ApplicationInsights.Extensibility.TelemetryConfiguration.Active.InstrumentationKey'
```

1.  在解决方案资源管理器中右键单击`VotingApplication`项目，然后选择`管理 Nuget Packages...`。安装以下 NuGet 包`Microsoft.ApplicationInsights.SnapshotCollectorandSerilog.Sinks.Trace`。

1.  配置快照调试器。在`ApplicationInsights.config`文件中，确保在根节点`ApplicationInsights`中有以下 XML 节点：

```
<TelemetryProcessors>
 <Add Type="Microsoft.ApplicationInsights.SnapshotCollector.SnapshotCollectorTelemetryProcessor, Microsoft.ApplicationInsights.SnapshotCollector">
 <IsEnabled>true</IsEnabled>
 <IsEnabledInDeveloperMode>false</IsEnabledInDeveloperMode>
 <ThresholdForSnapshotting>1</ThresholdForSnapshotting>
 <MaximumSnapshotsRequired>3</MaximumSnapshotsRequired>
 <MaximumCollectionPlanSize>50</MaximumCollectionPlanSize>
 <ReconnectInterval>00:15:00</ReconnectInterval>
 <ProblemCounterResetInterval>1.00:00:00</ProblemCounterResetInterval>
 <SnapshotsPerTenMinutesLimit>3</SnapshotsPerTenMinutesLimit>
 <SnapshotsPerDayLimit>30</SnapshotsPerDayLimit>
 <SnapshotInLowPriorityThread>true</SnapshotInLowPriorityThread>
 <ProvideAnonymousTelemetry>false</ProvideAnonymousTelemetry>
 <FailedRequestLimit>3</FailedRequestLimit>
 </Add>
</TelemetryProcessors>
```

1.  在`NinjectWebCommon.cs`文件的`RegisterServices`方法中注册 Serilog sink。您的日志记录器配置应如下所示：

```
Log.Logger = new LoggerConfiguration()
                 .ReadFrom.AppSettings()
                 .Enrich.FromLogContext()
                 .WriteTo.EventLog(source: "VotingApplication", logName: "VotingApplication", manageEventSource: false)
                 .WriteTo.Trace()
                 .CreateLogger();
```

1.  在`HomeController.cs`文件中，添加一个新的控制器动作`TestException`，我们将用于测试快照调试。它应该只是抛出一个未处理的异常：

```
public ActionResult TestException()
{
    throw new InvalidOperationException("This action always throws an exception!");
}
```

此时，我们的投票应用程序已完全配置为使用 Azure Application Insights。现在可以使用以下步骤升级 Helm 发布：

1.  使用`1.5.0`标签构建一个新的 Docker 镜像，就像我们在之前的章节中所做的那样，并将其推送到 Docker Hub。在我们的情况下，它将被称为`packtpubkubernetesonwindows/voting-application:1.5.0`。

1.  导航到应用程序的 Helm 图表所在的目录。

1.  在`Chart.yaml`文件中，使用`1.5.0`（与 Docker 镜像标签相同）作为`appVersion`。根据我们的最佳实践建议，更改图表的版本，例如使用`0.2.0`。

1.  在`values.yaml`文件中，添加您的仪表键，并将`replicaCount`增加到`5`：

```
azureApplicationInsightsKey: 4e810bf1-58c4-4af7-a67d-36fcdcf24a2f
replicaCount: 5
```

1.  现在，我们需要将仪表键注入到`Voting`应用程序的`Deployment`中的 pod 模板中。修改`templates\deployment.yaml`，以便将`azureApplicationInsightsKey`注入到`APPINSIGHTS_INSTRUMENTATIONKEY`环境变量中：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "voting-application.fullname" . }}
  ...
spec:
  ...
  template:
    ...
    spec:
      ...
      containers:
        - name: {{ .Chart.Name }}-frontend
          ...
          env:
          - name: APPINSIGHTS_INSTRUMENTATIONKEY
            value: {{ .Values.azureApplicationInsightsKey }}
          ...
```

1.  使用图表的新版本执行 Helm 发布的`dry run`。

```
helm upgrade voting-application . `
 --namespace dev-helm `
 --debug `
 --dry-run
```

1.  运行`upgrade`：

```
helm upgrade voting-application . `
 --namespace dev-helm `
 --debug `
 --timeout 900s
```

1.  等待所有副本升级到新版本。

现在，您的应用程序应该正在运行并将所有遥测发送到 Azure Application Insights。您可以从 Azure 门户导航到 Application Insights（[`portal.azure.com/`](https://portal.azure.com/)），或者通过在 Visual Studio 中右键单击`Connected Services`下的`Application Insights`并选择`Open Application Insights Portal`来直接打开它：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/65469ece-eb53-4068-9744-6e3c85d08d35.png)

您可以探索当前配置中提供的多个开箱即用的功能，例如将遥测数据可视化为应用程序地图，显示应用程序中不同组件之间的依赖关系及其当前状态：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/33d80fe8-3a56-446b-9125-dfe93e71be40.png)

如果您对最终用户请求的整体性能感兴趣，可以查看基于 ASP.NET MVC 遥测的专用仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/be8d2e57-0963-4d58-bd84-9408a76d409b.png)

当然，您还可以检查由 Serilog 汇集的应用程序**日志**。此视图中最重要的功能是使用 Kusto 语言（[`docs.microsoft.com/en-us/azure/kusto/query/`](https://docs.microsoft.com/en-us/azure/kusto/query/)）运行复杂查询的可能性，该语言专为分析日志数据而设计：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/e74cf28b-f712-4327-8309-a3eecd6e91db.png)

您可以在官方文档中了解有关 Azure 应用程序洞察功能的更多信息[`docs.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview`](https://docs.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview)。

现在，让我们看看如何使用快照调试器来调试您的容器化应用程序，即使您没有访问远程调试器也可以。

# 快照调试器

Azure 应用程序洞察服务提供了快照调试器，这是一个用于监视应用程序异常遥测的功能，包括生产场景。每当出现未处理的异常（顶部抛出），快照调试器都会收集可以直接在 Azure 门户中分析的托管内存转储，或者针对更高级的场景，使用 Visual Studio 2019 企业版。如果您在安装程序中选择了 ASP.NET 工作负载，则 Visual Studio 将默认安装此功能。

快照调试可以为不使用 ASP.NET MVC 的常规.NET 应用程序进行配置。您可以在文档中了解更多信息[`docs.microsoft.com/en-us/azure/azure-monitor/app/snapshot-debugger-vm#configure-snapshot-collection-for-other-net-applications`](https://docs.microsoft.com/en-us/azure/azure-monitor/app/snapshot-debugger-vm#configure-snapshot-collection-for-other-net-applications)。

在前面的段落中，我们已经通过安装`Microsoft.ApplicationInsights.SnapshotCollector` NuGet 包并提供额外的配置来启用了应用程序中的快照调试。现在，我们可以在我们的投票应用程序中测试此功能：

1.  在您的网络浏览器中，导航到始终引发异常的测试端点：`http://<serviceExternalIp>/Home/TestException`。触发此端点两次；默认情况下，我们必须多次触发相同的异常才能触发快照收集。

1.  您将看到我们投票应用程序的默认错误页面。与此同时，快照已经被收集，对最终用户几乎没有性能影响。

1.  在 Azure 门户中为我们的投票应用程序导航到应用程序洞察。

1.  打开“失败”窗格，并在查看“操作”选项卡时选择“操作”按钮，或在查看“异常”选项卡时选择“异常”按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/f00421e9-9bb6-4d2b-aa14-0d431bea4df8.png)

1.  从右侧选择示例操作窗格并打开异常发生之一。

1.  一开始，您在时间轴上看不到任何快照；您必须首先添加应用程序洞察快照调试器角色。要做到这一点，请单击（看不到快照？排除故障）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/2beb9c1c-48b1-493a-ad2e-b73b14f082aa.png)

1.  单击添加应用程序洞察快照调试器角色：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/47b1975f-5151-46d7-be97-cec1263a1e2e.png)

1.  之后，将执行基本的健康检查。请记住，快照上传需要几分钟的时间，因此，如果您遇到任何健康检查失败，请在几分钟后重试。

1.  现在，在端到端事务详细信息视图中，您将看到代表调试快照的小图标。单击其中一个：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/fa796b3d-87c8-4e5c-8b67-afa9124ecc56.png)

1.  调试快照视图为您提供了轻量级的调试器功能，包括代码反编译。要在 Visual Studio 2019 Enterprise 中分析快照，请单击“下载快照”按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/6fc7d714-5866-483e-8907-6faf0d492e8a.png)

1.  文件下载完成后，双击在 Visual Studio 中打开它。

1.  在 Visual Studio 中，根据您的需求，单击“仅使用托管调试”或“调试托管内存”。当您分析内存泄漏和其他与内存相关的问题时，第二个选项非常有用。

1.  您可能需要选择源代码位置，以便查看源代码视图（[`docs.microsoft.com/en-us/visualstudio/debugger/specify-symbol-dot-pdb-and-source-files-in-the-visual-studio-debugger?view=vs-2019`](https://docs.microsoft.com/en-us/visualstudio/debugger/specify-symbol-dot-pdb-and-source-files-in-the-visual-studio-debugger?view=vs-2019)）。

1.  现在，您可以使用您一直使用的所有调试工具，例如，您可以分析并行堆栈视图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/c5ef3a45-6b7a-4bcd-b478-1198d6e22864.png)

如果在使用快照调试器时遇到任何其他问题，请查看官方的故障排除指南[`docs.microsoft.com/en-us/azure/azure-monitor/app/snapshot-debugger-troubleshoot`](https://docs.microsoft.com/en-us/azure/azure-monitor/app/snapshot-debugger-troubleshoot)。

快照调试器甚至具有更多功能，可以设置实时快照点，以便您可以在不等待异常的情况下创建快照。不幸的是，目前此功能仅适用于在 Linux 容器中运行应用程序的 Azure 应用服务工作负载或托管的 AKS 集群。您可以在文档中找到更多信息[`docs.microsoft.com/en-us/visualstudio/debugger/debug-live-azure-applications?view=vs-2019`](https://docs.microsoft.com/en-us/visualstudio/debugger/debug-live-azure-applications?view=vs-2019)。

在下一节中，我们将介绍 Kubernetes 仪表板。

# 使用 Kubernetes 仪表板

Kubernetes 仪表板（[`github.com/kubernetes/dashboard`](https://github.com/kubernetes/dashboard)）是默认的基于 Web 的用户界面，用于部署、管理和排除运行在 Kubernetes 上的应用程序。通常建议您使用声明性的 kubectl 管理集群，而不是使用仪表板，但它仍然是一个有用的工具，可以查看集群概述，分析日志，并快速执行到 pod 容器中。

要使用仪表板，您必须首先安装它。您有以下选项可以这样做：

+   通过运行`kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.0.0-beta6/aio/deploy/recommended.yaml`来使用官方清单进行部署。您可以在文档中的[`kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/`](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard)中再次检查最新版本。

+   使用`helm install kubernetes-dashboard stable/kubernetes-dashboard`命令安装 Helm 图表。

+   在 AKS Engine 中，使用默认启用的`kubernetes-dashboard`附加组件。

重要的是要知道 Kubernetes API 和 Kubernetes 仪表板有严格的兼容性规则。 您可以在官方发布页面[`github.com/kubernetes/dashboard/releases`](https://github.com/kubernetes/dashboard/releases)上检查矩阵。 目前，AKS Engine 部署了版本`1.10.1`的仪表板，与 Kubernetes API 的最新版本不兼容。 这意味着我们将使用官方清单部署仪表板。 AKS Engine 集群默认为启用 RBAC 的集群，因此我们需要配置 RBAC 以便作为集群管理员使用仪表板。

# 部署 Kubernetes 仪表板

要部署和配置 RBAC，请按照以下步骤进行：

1.  打开 PowerShell 窗口。

1.  使用官方清单部署 Kubernetes 仪表板：

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.0.0-beta6/aio/deploy/recommended.yaml
```

1.  为`admin-user`创建`serviceaccount.yaml`清单文件：

```
apiVersion: v1
kind: ServiceAccount
metadata:
 name: admin-user
 namespace: kubernetes-dashboard
```

1.  使用`kubectl apply -f serviceaccount.yaml`命令应用清单文件。

1.  创建`clusterrolebinding.yaml`清单文件，为此用户授予`cluster-admin`角色：

```
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
  namespace: kubernetes-dashboard
```

1.  使用`kubectl apply -f clusterrolebinding.yaml`命令应用清单文件。

1.  要获取此用户的令牌，请在 PowerShell 中使用以下代码段，并复制`token:`后面的值：

```
kubectl -n kubernetes-dashboard describe secrets ((kubectl -n kubernetes-dashboard get secrets | Select-String "admin-user-token") -Split "\s+")[0]
```

在授予将用于访问仪表板的 ServiceAccount 的`cluster-admin`角色时，您需要了解任何安全影响。 拥有`admin-user` ServiceAccount 令牌的任何人都将能够在您的集群中执行任何操作。 在生产场景中，考虑创建仅公开必要功能的角色。

现在，您可以访问仪表板。 要做到这一点，请按照以下步骤进行：

1.  在 PowerShell 窗口中，使用`kubectl proxy`命令启动连接到 API 的代理。 仪表板未公开为外部服务，这意味着我们必须使用代理。

1.  打开 Web 浏览器，转到`http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/`。

1.  使用令牌选项进行身份验证，并提供我们在前面步骤中检索到的令牌。

1.  您将被重定向到集群的概述：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/b3b0106c-e10f-4eb6-8a4f-c1d177661e02.png)

Kubernetes 仪表板具有多个功能，涵盖了`kubectl`提供的许多功能。在接下来的部分中，我们将探讨如何访问容器日志并执行到 Pod 容器中，因为它们在调试场景中非常有用。

# 访问 Pod 容器日志

Kubernetes 仪表板为您提供了一个方便的界面，可以快速访问 pod 容器日志。要访问我们投票应用程序的一个 pod 的日志，请按照以下步骤进行：

1.  在菜单中，导航到工作负载 | Pod。

1.  找到我们投票应用程序的一个 pod。在右侧，点击三个点按钮，然后选择日志。

1.  您将被重定向到日志视图，在那里您可以实时检查日志，就像使用`kubectl logs`命令一样：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/f1bdcda2-64d6-401e-9035-804a7701cd73.png)

接下来，让我们看看如何`exec`到一个 Pod 容器中。

# 在 Pod 容器中执行命令

与访问日志类似，您可以`exec`到 Pod 容器中以运行临时命令。在调试问题或快速引入开发集群中的配置更改时，这种方法非常有用。执行以下步骤：

1.  在菜单中，导航到工作负载 | Pod。

1.  找到我们投票应用程序的一个 pod。在右侧，点击三个点按钮，然后选择`e``xec`。

1.  几秒钟后，PowerShell 终端将打开。您可以运行任意的 PowerShell 命令并修改容器状态：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/9bcc0f38-0253-4aad-9c48-fc299a9b338d.png)

恭喜！您已成功部署了 Kubernetes 仪表板，现在又多了一个有用的调试工具。在下一节中，您将学习如何使用 Azure Dev Spaces 改进 Kubernetes 的开发环境。

# 在团队中使用 Azure Dev Spaces 进行微服务开发

Azure Dev Spaces（[`docs.microsoft.com/en-us/azure/dev-spaces/`](https://docs.microsoft.com/en-us/azure/dev-spaces/)），也称为**AZDS**（**Azure Dev Spaces**的缩写），是微软提供的增强 Kubernetes 开发体验的最新产品之一。该服务为使用 AKS 集群的团队提供了快速和迭代的开发体验。请注意，目前仅支持托管的 AKS 集群，这意味着您无法为此服务使用 AKS Engine。此外，当前版本不支持开发 Windows 容器应用程序；可以与现有的 Windows pod 进行交互，但它们不会由 AZDS 管理（[`docs.microsoft.com/en-us/azure/dev-spaces/how-to/run-dev-spaces-windows-containers`](https://docs.microsoft.com/en-us/azure/dev-spaces/how-to/run-dev-spaces-windows-containers)）。从这个角度来看，AZDS 对于 Windows 容器应用程序开发并不有用，但由于很可能很快会得到支持，我们将为您概述这一产品。

AZDS 的主要特点如下：

+   您可以最小化本地开发环境设置。您可以在 AKS 中直接调试和测试分布式应用程序的所有组件，而无需替换或模拟依赖关系（开发/生产一致性）。

+   您可以将 Kubernetes 集群组织成共享和私有的 Dev Spaces。

+   它可以独立更新微服务，而不影响 AKS 集群和其他开发人员的其余部分。您可以开发自己的服务版本，在隔离环境中进行测试，并在准备好与其他团队成员共享时更新实例，以便所有人都能看到。

+   它与 Visual Studio Code 和 Visual Studio 2019 完全集成，包括它们的远程调试功能。也可以从 Azure CLI 进行管理。

+   它可以将您的本地计算机连接到 Kubernetes 集群，并测试或调试本地应用程序（带有或不带有容器），并使用所有依赖项（[`docs.microsoft.com/en-us/azure/dev-spaces/how-to/connect`](https://docs.microsoft.com/en-us/azure/dev-spaces/how-to/connect)）。此功能类似于 telepresence。

+   它通过增量代码编译在容器中提供更快的开发循环，每当检测到代码更改时。

要创建 AKS 集群，您可以使用我们在第四章中提供的 Powershell 脚本，*Kubernetes 概念和 Windows 支持*（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter04/05_CreateAKSWithWindowsNodes.ps1`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter04/05_CreateAKSWithWindowsNodes.ps1)）。

该脚本还可以仅创建具有两个节点 Linux 池的集群。 按照以下步骤创建启用了 AZDS 的 AKS 集群：

1.  下载脚本并使用适当的参数执行。 您需要选择支持 AZDS 的 Azure 位置（[`docs.microsoft.com/en-us/azure/dev-spaces/about#supported-regions-and-configurations`](https://docs.microsoft.com/en-us/azure/dev-spaces/about#supported-regions-and-configurations)）并选择该位置可用的 Kubernetes 版本（使用`az aks get-versions --location <azureLocation>`命令）。 在此示例中，我们将在`westeurope`位置创建一个名为`devspaces-demo`的 AKS 集群实例，并选择 Kubernetes 版本`1.15.4`。 请务必选择不包含保留字或商标的集群名称，否则您将无法启用 AZDS：

```
.\05_CreateAKSWithWindowsNodes.ps1 `
 -windowsPassword "S3cur3P@ssw0rd" `
 -azureLocation "westeurope" `
 -kubernetesVersion "1.15.4"
 -aksClusterName "devspaces-demo"
 -skipAddingWindowsNodePool $true
```

1.  集群部署大约需要 15 分钟。 完成后，将添加并设置名为`aks-windows-cluster`的`kubectl`的新上下文为默认值。

1.  使用以下命令为集群启用 AZDS：

```
az aks use-dev-spaces `
 --resource-group "aks-windows-resource-group" `
 --name "devspaces-demo"
```

1.  将安装 AZDS CLI。 在提示时将`default`命名空间用作 Dev Space。

现在 AKS 集群已启用 AZDS，我们可以演示在 Visual Studio 2019 中创建新的 ASP.NET Core 3.0 Kubernetes 应用程序并直接在集群中进行调试有多么容易。 按照以下步骤创建应用程序：

1.  打开 Visual Studio 2019 并选择创建新项目。

1.  找到适用于 Kubernetes 的容器应用程序模板，然后单击“下一步”。

1.  选择项目名称和位置，然后单击“下一步”。

1.  选择 Web 应用程序（模型-视图-控制器）类型，然后单击“创建”。

1.  我们需要对默认配置进行小的更改。 在`charts\azds-demo\values.yaml`文件中，确保使用以下代码启用`ingress`：

```
ingress:
 enabled: true
```

1.  默认情况下，Kestrel 监听端口`5000`。我们需要将端口更改为`80`，以便与 Dockerfile 和 Kubernetes Service 兼容。在`Program.cs`文件中，确保应用程序启动如下所示：

```
public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder
                    .UseUrls("http://0.0.0.0:80")
                    .UseStartup<Startup>();
            });
```

启用了 AZDS 支持的项目具有`azds.yaml`文件，其中定义了 Dev Spaces 配置、Dockerfile 和具有 Helm 图表的`charts`目录，准备好由 AZDS 部署到集群。现在，让我们将应用程序部署到我们的 AKS 集群中的`default` Dev Space 中：

1.  从项目的启动设置中，选择 Azure Dev Spaces：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/c2194bff-518a-4187-8584-4d5809bdd7c0.png)

1.  选择`devspaces demo AKS cluster`和`default space`，并将其标记为公开访问，然后继续点击确定。

1.  AZDS 将构建 Dockerfile，安装 Helm 图表，并附加调试器。在 Web 浏览器中，Ingress 公共端点将自动打开，例如[h](http://default.azds-demo.2dpkt6cj7f.weu.azds.io/)[t](http://default.azds-demo.2dpkt6cj7f.weu.azds.io)[tp:/](http://default.azds-demo.2dpkt6cj7f.weu.azds.io/)[/default.azds-demo.2dpkt6cj7f.weu.azds.io/](http://default.azds-demo.2dpkt6cj7f.weu.azds.io/)。

1.  在`HomeController.cs`文件中，在索引控制器操作中添加断点。刷新浏览器中的网页，您将看到断点被捕获，就像应用程序在本地环境中进行调试一样！

1.  停止调试并在`Index.cshtml`文件中引入更改。例如，将主标题更改为以下内容：

```
<h1 class="display-4">Welcome - Modified</h1>
```

1.  再次使用 Azure Dev Spaces 配置启动应用程序。在输出窗口中，您将看到应用程序被快速重建，并且一段时间后，修改后的主页将再次在 Web 浏览器中打开：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/80e79be7-9d30-4521-8e2b-44251f7bbf39.png)

要了解团队开发中更多的 AZDS 场景，请查看官方文档[`docs.microsoft.com/en-us/azure/dev-spaces/team-development-netcore-visualstudio`](https://docs.microsoft.com/en-us/azure/dev-spaces/team-development-netcore-visualstudio)。

所有这些都发生在 AKS 集群上。正如您所看到的，与在正常的开发循环中构建 Docker 镜像、推送它并部署新的部署相比，开发迭代要快得多。

要删除 AKS 集群，请使用`az group delete --name aks-windows-resource-group --yes`命令。

恭喜！您已成功为您的 AKS 集群设置了 Azure Dev Spaces。

# 总结

本章重点介绍了作为开发人员如何通过 Kubernetes 集群改进开发体验。首先，我们学习了如何为 Visual Studio Code 和 Visual Studio 2019 配置必要的开发扩展。接下来，您学习了如何使用 Helm 打包 Kubernetes 应用程序，首先是通过使用 Microsoft SQL Server 的官方 Helm 图表，然后是通过为我们的投票应用程序创建一个专用图表。

接下来，我们学习了如何将 Azure Application Insights 集成到您的应用程序中，以及如何利用高级功能，如快照调试器，以便在 Windows pod 的生产场景中调试问题。使用我们新的带有 Application Insights 仪表的 Docker 镜像，我们学习了如何执行 Helm 发布升级。我们介绍了 Kubernetes Dashboard，这是最常用的 Kubernetes Web UI。最后，您了解了 Azure Dev Spaces 服务是什么，以及在使用 AKS 集群时如何使用它来增加开发迭代速度。

在下一章中，我们将专注于安全这一重要主题，特别是在 Windows 容器的背景下。

# 问题

1.  Helm 是什么，为什么应该使用它？

1.  Helm 版本二和三之间最大的区别是什么？

1.  如何在 Helm 图表中实现自动的 Entity Framework 数据库迁移？

1.  如何执行安装为 Helm 图表的应用程序的新版本的发布？

1.  快照调试器是什么，如何在生产场景中使用它？

1.  为什么不建议使用 Kubernetes Dashboard 来修改集群中的资源？

1.  使用 Azure Dev Spaces 的优势是什么？

您可以在本书的*评估*部分找到这些问题的答案。

# 进一步阅读

+   有关 Kubernetes 功能以及如何管理应用程序的更多信息，请参考以下 PacktPub 图书：

+   *完整的 Kubernetes 指南*（[`www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide`](https://www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide)）

+   *开始使用 Kubernetes-第三版*（[`www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition`](https://www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition)）

+   开发者的 Kubernetes（[`www.packtpub.com/virtualization-and-cloud/kubernetes-developers`](https://www.packtpub.com/virtualization-and-cloud/kubernetes-developers)）

+   如果您对学习 Azure 应用洞察感兴趣，请参考以下 PacktPub 图书：

+   开发者的 Azure 实践（[`www.packtpub.com/virtualization-and-cloud/hands-azure-developers`](https://www.packtpub.com/virtualization-and-cloud/hands-azure-developers)）

+   Azure 架构师-第二版（[`www.packtpub.com/virtualization-and-cloud/azure-architects-second-edition`](https://www.packtpub.com/virtualization-and-cloud/azure-architects-second-edition)）

+   有关 Helm 的更多信息，您可以查看以下 PacktPub 图书：

+   精通 Kubernetes-第二版（[`www.packtpub.com/application-development/mastering-kubernetes-second-edition`](https://www.packtpub.com/application-development/mastering-kubernetes-second-edition)）


# 第十三章：保护 Kubernetes 集群和应用程序

安全性这个话题值得特别关注——Kubernetes 是一个庞大而复杂的系统，在这个系统中安全性并不明显，潜在的攻击向量也不会立即显现。如果考虑到这个系统可以执行的强大操作以及它与操作系统内部的深度集成，那么在 Kubernetes 中考虑安全性就更加重要了。只是为了让您了解，如果您忽视了配置细节，事情可能会变得很糟糕，可以看一下有关特斯拉因为 Kubernetes Dashboard 的*公共*、*未经身份验证*端点而被加密挖矿的文章[`blog.heptio.com/on-securing-the-kubernetes-dashboard-16b09b1b7aca`](https://blog.heptio.com/on-securing-the-kubernetes-dashboard-16b09b1b7aca)。

在本章中，我们将为您提供保护 Kubernetes 集群的一般最佳实践，包括 Windows 工作负载的视角。Windows 节点有一些限制——例如，只能直接从节点存储（而不是内存）中以明文形式挂载密钥，但它们在不同方面也比 Linux 节点更安全。

本章将涵盖以下主题：

+   保护 Kubernetes 集群

+   保护 Windows 上的容器运行时

+   使用网络策略部署安全应用程序

+   Windows 机器上的 Kubernetes 密钥

# 技术要求

对于本章，您将需要以下内容：

+   已安装的 Windows 10 Pro、企业版或教育版（1903 版本或更高版本，64 位）

+   Azure 账户

+   使用 AKS Engine 部署的 Windows/Linux Kubernetes 集群

要跟着做，您需要自己的 Azure 账户，以便为 Kubernetes 集群创建 Azure 资源。如果您之前没有在前几章创建过账户，您可以阅读更多关于如何获取个人使用的有限免费账户的信息[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)。

使用 AKS Engine 部署 Kubernetes 集群已在第八章中介绍过，*部署混合 Azure Kubernetes 服务引擎集群*。

您可以从官方 GitHub 存储库下载本书章节的最新代码示例[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter13`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter13)。

# 保护 Kubernetes 集群

在本节中，我们将提供一些关于如何保护 Kubernetes 集群的一般指导。此外，我们将探讨在 AKS Engine 集群中使用 Azure Active Directory（AAD）集成进行 API 用户身份验证的主题。本章提供的最佳实践清单并不详尽，因此请始终查阅最新的官方文档，以确保您遵循建议。

现在，让我们逐个讨论以下各小节中的一般建议清单。

# 使用内置 RBAC 进行授权

我们已经在第十一章中介绍了 Kubernetes 提供的基于角色的访问控制（RBAC）用于 API 授权。这种机制允许您配置细粒度的权限集，并将其分配给用户、组和服务帐户。通过这种方式，作为集群管理员，您可以控制集群用户（内部和外部）与 API 服务器的交互方式，他们可以访问哪些 API 资源以及可以执行哪些操作。同时，您应该使用命名空间来创建资源之间的第一个边界。这也使得应用 RBAC 策略更加容易。

对于 RBAC，使用最小特权原则，并倾向于将 RoleBindings 分配给组，而不是单个用户，以减少管理开销。如果使用外部身份验证提供者，您可以轻松地与提供者提供的组集成。在引导集群时，建议您同时使用 Node 和 RBAC 授权器（对 API 服务器使用`--authorization-mode=Node,RBAC`参数），结合 NodeRestriction 准入插件。这是 AKS Engine 初始化集群的默认方式。

# 使用外部身份验证提供者

所有 API 调用都必须经过身份验证。这对外部（普通）用户以及内部 Kubernetes 基础设施的成员（例如 kubelet）都是如此。在基础设施的情况下，这些用户通常使用带有令牌或 X509 客户端证书的 ServiceAccounts，这些证书是在引导集群时创建的。Kubernetes 本身不提供管理访问集群的普通外部用户的手段；这应该委托给一个可以与 Kubernetes 集成的外部身份验证提供者，例如通过认证代理。

您应选择适合您的组织并遵循用户的常见访问模式的身份验证机制。例如，如果您正在运行 AKS 引擎，很可能已经在 Azure 订阅中使用 Azure Active Directory 来管理用户和角色。除此之外，您应考虑使用组来使 RBAC 策略管理更加简单，并与 AAD 更加集成。

除了 AAD 之外，认证代理和认证 webhook 还可以让您有可能与不同的协议集成，例如 LDAP、SAML 或 Kerberos。

在本节的最后，我们将演示如何为您的 AKS 引擎集群启用 AAD 集成。

# 使用 kubeadm 引导集群

如果您手动部署集群，请使用 kubeadm，它可以安全地引导集群。它可以生成一个自签名的 CA 来为集群中的所有组件设置身份，生成用于加入新节点的令牌（TLS 引导），并提供证书管理功能([`kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/`](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/))。初始化一个安全的 Kubernetes 集群是 kubeadm 的首要设计重点([`github.com/kubernetes/kubeadm/blob/master/docs/design/design_v1.10.md`](https://github.com/kubernetes/kubeadm/blob/master/docs/design/design_v1.10.md))。

# 禁用公共 API 访问

对于生产场景，仅使用 RBAC 授权进行 Kubernetes API 的适当用户身份验证可能不足够（从安全角度来看），如果 API 是公开访问的。为了减少 Kubernetes API 的攻击向量，考虑*禁用*公共 API 访问，以及不直接将任何 Kubernetes 节点暴露给互联网。当然，这将需要您使用 VPN 或 jumpbox 主机来访问 API，但这绝对更安全。

AKS 引擎可以通过对集群 apimodel 进行简单更改来为您配置此功能。您可以在官方文档中阅读有关禁用公共 API 访问的更多信息[`github.com/Azure/aks-engine/blob/master/docs/topics/features.md#private-cluster`](https://github.com/Azure/aks-engine/blob/master/docs/topics/features.md#private-cluster)。或者，您可以考虑加固主 VM 的 NAT 入站规则，限制允许通过 HTTPS 和 SSH 连接到机器的 IP 范围。

# 禁用公共仪表板

与 Kubernetes API 类似，您应该禁用公开访问的 Kubernetes 仪表板。在常见的安装中，仪表板可能会暴露为一个 LoadBalancer 服务；在最坏的情况下，这将是一个具有`cluster-admin`角色的 ServiceAccount。推荐的做法是永远不要使用 LoadBalancer 服务公开 Kubernetes 仪表板，并始终使用`kubectl proxy`来访问页面。

此外，Kubernetes 仪表板的 ServiceAccount 应具有足够满足您用例的**最低权限**。您很可能永远不会在生产环境中使用 Kubernetes 仪表板来创建或编辑部署，那么为什么您需要对这些敏感的 API 资源具有写访问权限呢？

# 以非特权模式运行容器

在 Kubernetes 中，可以指定一个 pod 是否具有特权。特权 pod 可能包含以特权模式运行的容器，这基本上意味着容器可以访问主机上的所有设备，这与在主机上以 root（或管理员）权限运行的进程具有类似的权限。

确保您的 pod 容器在操作系统中以非特权模式运行是一个良好的做法；这遵循了最小权限原则。此外，您应该考虑使用 PodSecurityPolicy admission controller 来强制执行一组规则，一个 pod 必须满足才能被调度。一个示例的限制性策略可以在[`raw.githubusercontent.com/kubernetes/website/master/content/en/examples/policy/restricted-psp.yaml`](https://raw.githubusercontent.com/kubernetes/website/master/content/en/examples/policy/restricted-psp.yaml)找到。

请注意，在 Windows 容器的情况下，不支持运行特权容器。此外，对于 Windows 工作负载，请考虑使用**组管理服务帐户**（gMSAs，[`kubernetes.io/docs/tasks/configure-pod-container/configure-gmsa/`](https://kubernetes.io/docs/tasks/configure-pod-container/configure-gmsa/)）。

# 加密数据的静态存储

数据在静止状态下加密被认为是一种普遍的良好做法（有时是法律强制要求）对于所有系统。在 Kubernetes 中，您需要确保 etcd 集群数据被加密。这将为您的 API 资源和秘密提供额外的安全层，否则这些信息将以未加密的形式保存在 etcd 中。在官方 Kubernetes 文档中，有关在静止状态下加密秘密的内容被单独讨论。

对于秘密，您应该始终使用延迟绑定，通过将秘密注入到 pod 中作为卷或环境变量。请注意，在 Linux 上将秘密注入为环境变量是不太安全的；当您拥有 root 权限时，您可以从`/proc/<pid>/environ`枚举出一个进程的所有环境变量。在 Windows 节点上，问题甚至更加复杂：您仍然可以访问进程的环境变量，但卷目前无法使用内存文件系统。这意味着秘密随后直接存储在节点磁盘上。这意味着您应该考虑加密您的 Windows 节点存储，以最小化凭据的暴露。我们将在接下来的章节中讨论这个问题。

# 使用网络策略

网络策略充当您的 pod 之间的防火墙，允许您控制容器化应用程序的网络访问。在 Kubernetes 集群中，默认情况下，pod 之间没有网络通信的限制——基本上，所有的流量都是可能的。使用一种宽松的网络策略模型是一种良好的做法，它默认拒绝所有流量，并只允许连接，如果已经定义了专用的网络策略。

您可以在官方文档中阅读更多关于支持 AKS Engine 上网络策略的网络提供商的信息。请注意，目前这些提供商不支持 Windows pod，除了 Tigera Essentials 订阅服务的企业版本提供的 Calico（https://www.tigera.io/media/pr-calico-for-windows）。

# 保护镜像供应链和扫描镜像

在第三章中，*使用容器镜像*，我们描述了如何使用**Docker Content Trust**（**DCT**）对 Docker 镜像进行签名和验证。您应该在生产中考虑使用这种方法来进行 Docker 镜像流水线。此外，考虑整合开源工具，如**Anchore**（[`github.com/anchore/anchore-engine`](https://github.com/anchore/anchore-engine)）和**Clair**（[`github.com/quay/clair`](https://github.com/quay/clair)），这些工具可以帮助您识别常见的漏洞和曝光（**CVEs**）并加以缓解。

# 旋转基础设施凭据和证书

一般来说，凭据或令牌的有效期越短，攻击者利用这种凭据的难度就越大。利用这一原则为在您的集群中使用的证书和令牌设置较短的生命周期，并在可能的情况下实施**自动轮换**。当您发现自己受到攻击时，这可以成为您的秘密武器；如果您能有效地轮换证书，您可以随时轮换它们，并使任何被截获的凭据无效。

对于 AKS 和 AKS Engine，考虑使用与**Azure Key Vault**集成，这将使您的秘密和证书管理和轮换变得更加容易。您可以在官方文档中阅读更多信息，网址为[`github.com/Azure/kubernetes-keyvault-flexvol`](https://github.com/Azure/kubernetes-keyvault-flexvol)。

此外，考虑集成一个认证提供者，用于发放具有短期有效期的用户令牌。您可以使用这种方法来提供**及时特权访问管理**，这可以大大限制用户拥有资源的*上帝模式*访问的时间。

# 启用审计日志

**审计日志**应始终在生产集群中可用。这将使监视和警报设置对访问异常和意外 API 调用进行监控成为可能。您越早发现任何禁止的 API 响应，就越有可能及时做出反应，防止攻击者获取对集群的访问权限。您可以在官方文档中阅读有关 Kubernetes 审计的更多信息，网址为[`kubernetes.io/docs/tasks/debug-application-cluster/audit/`](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/)。

在设置生产集群时，请确保阅读官方 Kubernetes 指南以保护集群。您可以在[`kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/`](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/)找到更多详细信息。

现在，在我们已经了解了 Kubernetes 集群的最重要的安全最佳实践之后，我们将看看如何在 AKS Engine 集群中启用**Azure Active Directory**（AAD）进行客户端身份验证。

# 集成 AAD 与 AKS Engine

AKS Engine 可以轻松与 AAD 集成，以提供 Kubernetes API 客户端身份验证。与 AAD **组**一起，这种方法可以用于为映射到 AAD 组的用户组创建 RoleBindings 和 ClusterRoleBindings。

让我们看看如何创建一个具有 AAD 集成的 AKS Engine 集群，并为集群管理员创建一个 AAD 组。这种方法可以扩展到管理多个具有不同 RBAC 绑定的 AAD 组。

不支持将 AAD 集成添加到现有的 AKS Engine 集群。因此，您需要在集群部署时做出这个决定。

为服务器和客户端配置 AAD 应用程序的步骤，以及创建管理员 AAD 组的步骤，已经作为 Powershell 脚本提供，方便您使用。您可以使用该脚本或按照以下步骤操作：

1.  打开 PowerShell 窗口，并使用全局唯一的 DNS 前缀定义`$dnsPrefix`变量，稍后将用于 AKS Engine 部署，例如：

```
$dnsPrefix = "handson-aks-engine-win-aad"
```

1.  创建一个将代表 Kubernetes API 服务器的 AAD 服务器应用程序，并将`appId`存储以供进一步使用作为`$serverApplicationId`变量：

```
$serverApplicationId = az ad app create `
 --display-name "${dnsPrefix}Server" `
 --identifier-uris "https://${dnsPrefix}Server" `
 --query appId -o tsv
```

1.  更新此应用程序的组成员资格声明：

```
az ad app update `
 --id $serverApplicationId `
 --set groupMembershipClaims=All
```

1.  创建一个将用于 Azure 平台身份验证的**服务主体**：

```
az ad sp create `
 --id $serverApplicationId
```

1.  获取服务主体的**密钥**并将其存储以供进一步使用作为`$serverApplicationSecret`变量：

```
$serverApplicationSecret = az ad sp credential reset `
 --name $serverApplicationId `
 --credential-description "AKSPassword" `
 --query password -o tsv
```

1.  现在，为服务器应用程序添加权限以读取目录数据、登录和读取用户配置文件：

```
az ad app permission add `
 --id $serverApplicationId `
 --api 00000003-0000-0000-c000-000000000000 `
 --api-permissions e1fe6dd8-ba31-4d61-89e7-88639da4683d=Scope 06da0dbc-49e2-44d2-8312-53f166ab848a=Scope 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role
```

1.  授予权限：

```
az ad app permission grant `
 --id $serverApplicationId `
 --api 00000003-0000-0000-c000-000000000000 
az ad app permission admin-consent `
 --id $serverApplicationId
```

1.  接下来的步骤将类似，但将适用于代表 kubectl 的 AAD **客户端应用程序**。创建该应用程序并将`appId`存储为`$clientApplicationId`变量以供进一步使用：

```
$clientApplicationId = az ad app create `
 --display-name "${dnsPrefix}Client" `
 --native-app `
 --reply-urls "https://${dnsPrefix}Client" `
 --query appId -o tsv
```

根据您的 AAD 租户配置，您可能需要额外的权限来创建服务主体。您可以在官方文档中阅读更多内容[`docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal#required-permissions`](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal#required-permissions)。

1.  为应用程序创建服务主体：

```
az ad sp create `
 --id $clientApplicationId
```

1.  确定服务器应用程序的 OAuth2 ID 并将其存储为`$oauth2PermissionId`：

```
$oauth2PermissionId = az ad app show 
 --id $serverApplicationId `
 --query "oauth2Permissions[0].id" -o tsv
```

1.  使用 OAuth2 ID 允许客户端和服务器应用程序之间的身份验证流程：

```
az ad app permission add `
 --id $clientApplicationId `
 --api $serverApplicationId `
 --api-permissions $oauth2PermissionId=Scope

az ad app permission grant `
 --id $clientApplicationId `
 --api $serverApplicationId
```

1.  为 AKS Engine 管理员创建名为`AksEngineAdmins`的 AAD 组，并将其 ID 存储为`$adminGroupId`变量：

```
$adminGroupId = az ad group create `
 --display-name AksEngineAdmins `
 --mail-nickname AksEngineAdmins `
 --query "objectId" -o tsv
```

1.  我们想要将当前用户添加到这个组。首先，让我们检索用户的`objectId`并将其存储为`$currentUserObjectId`变量：

```
$currentUserObjectId = az ad signed-in-user show `
 --query "objectId" -o tsv
```

1.  将用户添加到 AKS Engine 管理员组：

```
az ad group member add `
 --group AksEngineAdmins `
 --member-id $currentUserObjectId
```

1.  确定当前订阅的 AAD 租户 ID 并将其存储为`$tenantId`变量：

```
$tenantId = az account show `
 --query "tenantId" -o tsv
```

1.  基于前面的变量打印 JSON 对象，该对象将在 AKS Engine apimodel 中使用：

```
echo @"
"aadProfile": {
 "serverAppID": "$serverApplicationId",
 "clientAppID": "$clientApplicationId",
 "tenantID": "$tenantId",
 "adminGroupID": "$adminGroupId"
}
"@
```

我们已经准备好部署带有 AAD 集成的 AKS Engine。为此，我们将使用一个 PowerShell 脚本，几乎与我们在之前章节中使用的方式完全相同([`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter13/02_aks-engine-aad/CreateAKSEngineClusterWithWindowsNodes.ps1`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter13/02_aks-engine-aad/CreateAKSEngineClusterWithWindowsNodes.ps1))，以及 apimodel 模板([`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter13/02_aks-engine-aad/kubernetes-windows-template.json`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter13/02_aks-engine-aad/kubernetes-windows-template.json))。执行 AKS Engine 部署，按照以下步骤进行：

1.  下载 PowerShell 脚本和 apimodel 模板。

1.  在文件位置打开 PowerShell 窗口。

1.  在`kubernetes-windows-template.json`文件中，用前面段落中的自己的值替换`aadProfile`。

1.  使用适当的参数执行脚本：

```
.\CreateAKSEngineClusterWithWindowsNodes.ps1 `
 -azureSubscriptionId <azureSubscriptionId> `
 -dnsPrefix <dnsPrefix> `
 -windowsPassword 'S3cur3P@ssw0rd' `
 -resourceGroupName "aks-engine-aad-windows-resource-group" `
 -azureLocation "westus"
```

1.  几分钟后，脚本将执行`kubectl get pods`命令，并提示您在 Web 浏览器中进行*身份验证*：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/f8a01372-d9c8-4987-9a74-d659c938ff65.png)

1.  导航到 URL，提供代码并登录。之后，您将成功在 Kubernetes API 服务器中进行身份验证，并能够使用 kubectl。

1.  要检查允许您访问的 ClusterRoleBinding 的定义，请执行以下命令：

```
PS C:\src> kubectl describe clusterrolebinding aad-default-admin-group
Name:         aad-default-admin-group
Labels:       addonmanager.kubernetes.io/mode=EnsureExists
 kubernetes.io/cluster-service=true
Annotations:  <none>
Role:
 Kind:  ClusterRole
 Name:  cluster-admin
Subjects:
 Kind   Name                                  Namespace
 ----   ----                                  ---------
 Group  18d047eb-83f9-4740-96be-59555e88138f
```

根据您的需求，您现在可以配置更多的 AAD 组，创建角色并为它们提供适当的 RoleBindings。在下一节中，我们将看看如何确保 Windows 容器运行时安全运行。

# 在 Windows 中保护容器运行时

在保护容器运行时方面，Windows 容器与 Linux 容器有些不同。对于 Windows 容器，操作系统使用一个`Job`对象（不要与 Kubernetes 的`Job`对象混淆！）每个容器一个，具有用于在给定容器中运行的所有进程的系统命名空间过滤器。这提供了与主机机器的逻辑隔离，无法禁用。您可以在第一章中阅读有关 Windows 容器架构的更多信息，*创建容器*。

这一事实有一个后果：在 Windows 中，**特权**容器不可用，尽管在 Linux 中可用。此外，随着 Kubernetes 对 Hyper-V 容器的支持即将到来，您将能够进一步保护容器运行时并强制执行更好的隔离。

对于 Linux 容器，您可以考虑在 Pod 中使用`securityContext`以作为**非特权**用户运行（其 ID 与`0`不同）：

```
apiVersion: v1
kind: Pod
metadata:
  name: secured-pod
spec:
  securityContext:
    runAsUser: 1000
```

此外，您可以强制执行 PodSecurityPolicies，在调度 Pod 之前由准入控制器进行验证。通过这种方式，例如，您可以确保给定命名空间中没有以特权模式运行的 Pod。您必须使用 RBAC 来正确配置策略访问。

AKS Engine 默认启用了 PodSecurityPolicy 准入控制器，并提供了特权和受限策略。

对于 Windows 容器，标准的`securityContext`不适用，因为它是用于 Linux 容器的。Windows 容器在`securityContext`内部有一个专门的对象，名为`windowsOptions`，它可以启用一些目前仍处于**alpha**状态的 Windows 特定功能：

+   使用不同的用户名配置正在运行的 Pod 容器（[`kubernetes.io/docs/tasks/configure-pod-container/configure-runasusername/`](https://kubernetes.io/docs/tasks/configure-pod-container/configure-runasusername/)）。

+   为 Pod 容器配置组管理的服务帐户（gMSA）（[`kubernetes.io/docs/tasks/configure-pod-container/configure-gmsa/`](https://kubernetes.io/docs/tasks/configure-pod-container/configure-gmsa/)）。gMSA 是一种特定类型的 Active Directory 帐户，提供自动密码管理、简化的服务主体名称管理，并且可以将管理委托给多个服务器上的其他管理员。Azure Active Directory 支持 gMSA（[`docs.microsoft.com/en-us/azure/active-directory-domain-services/create-gmsa`](https://docs.microsoft.com/en-us/azure/active-directory-domain-services/create-gmsa)）。

在下一节中，您将了解更多关于网络策略以及它们如何用于在 Kubernetes 上部署更安全的应用程序。

# 使用网络策略部署安全应用程序

在 Kubernetes 中，您可以使用网络策略为应用程序部署提供更好的网络隔离粒度。它们由`NetworkPolicy`对象表示，定义了一组 Pod 如何相互通信以及一般网络端点——可以将它们视为 OSI 模型第 3 层的网络分割的基本防火墙。当然，它们并不是高级防火墙的替代品。

`NetworkPolicy`对象使用标签选择器来识别它们附加到的 Pod。同样，标签选择器和 IP CIDR 用于为这些 Pod 定义入口和出口规则的目标。只有当网络策略具有与给定 Pod 匹配的标签选择器时，才会使用给定的网络策略。如果没有与给定 Pod 匹配的网络策略，它可以接受任何流量。

# 网络策略支持

为了使用网络策略，您需要使用一个支持网络策略的**网络提供商**（用于安装 Pod 网络，如第五章中所述，*Kubernetes 网络*）。最受欢迎的有以下几种：

+   Calico ([`www.projectcalico.org/`](https://www.projectcalico.org/))

+   Cilium ([`cilium.io/`](https://cilium.io/))

+   Kube-router ([`www.kube-router.io/`](https://www.kube-router.io/))

+   Romana ([`romana.io/`](https://romana.io/))

+   Weave Net ([`www.weave.works/docs/net/latest/overview/`](https://www.weave.works/docs/net/latest/overview/))

不幸的是，目前没有*任何*支持 Windows 节点的网络提供商，这意味着您只能在 Linux 集群中使用网络策略。唯一宣布即将支持 Windows 节点和网络策略的网络提供商是 Calico 的企业版本，作为**Tigera Essentials**订阅服务的一部分提供（[`www.tigera.io/media/pr-calico-for-windows`](https://www.tigera.io/media/pr-calico-for-windows)）。您目前可以在私人预览版本中尝试此服务，包括 Windows 节点支持。请注意，如果您使用 AKS 或 AKS Engine，则仅限于与**Azure**或**kubenet**网络 CNI 插件一起使用 Calico 或 Cilium。

有关 AKS Engine 配置网络策略支持的更多详细信息，请参阅官方文档[`github.com/Azure/aks-engine/tree/master/examples/networkpolicy`](https://github.com/Azure/aks-engine/tree/master/examples/networkpolicy)。此外，对于托管的 AKS，您可以考虑使用**高级网络**功能，允许您配置自己的 VNet，定义 Azure 网络安全组，并提供将您的 Pod 连接到 VNet 的自动连接功能-您可以在官方文档中阅读更多[`docs.microsoft.com/en-us/azure/aks/configure-azure-cni`](https://docs.microsoft.com/en-us/azure/aks/configure-azure-cni)。

让我们看看如何使用网络策略来强制执行集群中的 Pod 隔离。

# 配置网络策略

从安全的角度来看，网络策略很重要，因为默认情况下，Kubernetes 允许集群中的**所有对所有**通信。命名空间只提供了简单的隔离，仍然允许 pod 通过 IP 地址相互通信。在较大的集群或多租户场景中，你必须提供更好的网络隔离。尽管 Windows 节点目前还不支持网络策略（但最终***将***支持），我们认为让你了解如何使用原生 Kubernetes 构建来实现网络分割是很重要的。

如果你有一个使用 Calico 网络的 AKS Engine Linux 集群，并且使用 Azure CNI 插件，你可以跟着配置你的 pod 的网络策略。使用这样的配置部署 AKS Engine 只需要对集群 apimodel 进行简单的更改，即在`properties.orchestratorProfile`中添加以下属性：

```
"kubernetesConfig": {
    "networkPolicy": "calico",
    "networkPlugin": "azure"
}
```

现在，我们将创建一个网络策略，*阻止所有*进入`default`命名空间中所有 pod 的流量。这与集群默认情况相反——命名空间中的 pod 将无法相互通信，除非你明确允许。之后，我们将部署一个简单的 Nginx web 服务器，后面是一个负载均衡器服务，并尝试从集群中的不同 pod 内部和 Azure 负载均衡器外部进行通信。然后，我们将创建一个网络策略，作为**白名单规则**，只针对 web 服务器的 TCP 端口 80。请按照以下步骤创建默认拒绝所有规则并部署 Nginx web 服务器：

1.  为`NetworkPolicy`对象在`default`命名空间中拒绝所有进入流量创建一个名为`default-deny-all-ingress.yaml`的清单文件：

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  namespace: default
  name: default-deny-all-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```

这是通过使用空的`podSelector`来实现的，它将选择所有的 pod。

1.  使用`kubectl apply -f .\default-deny-all-ingress.yaml`命令应用清单文件。

1.  如果你想更好地理解任何网络策略的影响，可以使用以下命令：

```
kubectl describe networkpolicy default-deny-all-ingress
```

1.  为 Nginx 部署创建一个名为`nginx-deployment.yaml`的简单清单文件：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: default
  name: nginx-deployment
spec:
  selector:
    matchLabels:
      app: nginx
  replicas: 2
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.7.9
        ports:
        - containerPort: 80
```

1.  使用`kubectl apply -f .\nginx-deployment.yaml`命令应用清单文件。

1.  为部署的负载均衡器服务创建一个名为`nginx-service.yaml`的清单文件：

```
apiVersion: v1
kind: Service
metadata:
  namespace: default
  name: nginx-service
  labels:
    app: nginx
spec:
  type: LoadBalancer
  ports:
  - protocol: TCP
    port: 80
  selector:
    app: nginx
```

1.  使用`kubectl apply -f .\nginx-service.yaml`命令应用清单文件。

在定义非常严格的出口规则时要小心。使用拒绝所有出口规则，您将阻止 pod 访问 Kubernetes DNS 服务。

通过部署我们的 Nginx web 服务器和在`default`命名空间中拒绝所有入口流量到 pod 的默认规则，我们可以测试与 web 服务器的连接。

1.  等待服务的外部 IP 出现，使用`kubectl get svc -w`命令，并在网络浏览器中打开该地址。您会看到连接挂起并最终超时，这是预期的。

1.  让我们使用交互模式中运行 Bourne shell 的`busybox` pod 来检查这一点：

```
kubectl run --generator=run-pod/v1 busybox-debug -i --tty --image=busybox --rm --restart=Never -- sh
```

1.  在 pod 中的 shell 会话中，尝试获取 Nginx 托管的网页。您可以使用服务的 DNS 名称和其中一个 pod 的 IP。在这两种情况下都会失败：

```
wget http://nginx-service:80
wget http://10.240.0.30:80
```

现在，让我们创建一个网络策略，允许 TCP 端口`80`上的入口流量到 Nginx pod。之后，您将能够从集群中的两个 pod 以及 Azure 负载均衡器进行通信。要配置策略，请按照以下步骤进行：

1.  让`busybox`交互会话保持运行，并打开一个新的 PowerShell 窗口。

1.  创建一个名为`default-nginx-allow-ingress.yaml`的清单文件，允许 TCP 端口`80`上的入口流量到所有带有标签`app=nginx`的 pod，来自所有来源：

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  namespace: default
  name: default-nginx-allow-ingress
spec:
  podSelector:
    matchLabels:
      app: nginx
  ingress:
  - from: []
    ports:
    - protocol: TCP
      port: 80
```

1.  使用`kubectl apply -f .\default-nginx-allow-ingress.yaml`命令应用清单文件。

1.  在您的网络浏览器中，再次导航到服务的外部 IP。现在，您应该能够毫无问题地访问网页！

1.  类似地，在`busybox` pod 容器中使用`wget`尝试相同的操作。您也将能够访问网页。

1.  作为练习，为了证明端口过滤正常工作，您可以修改网络策略以使用不同的端口，或者在 TCP 端口上运行不同于`80`的 Nginx。

恭喜！您已成功使用网络策略在 Kubernetes 集群中配置了宽松的网络规则。从*permissive*网络策略模型开始是一个很好的做法，您可以拒绝所有入口流量到您的 pod（有时也是所有出口流量从 pod），并通过特定的网络策略允许连接。请注意，为此，您应该以可预测的方式组织网络策略，使用命名约定。这将使您的网络规则管理变得更加容易。

在接下来的部分中，我们将探讨如何在 Windows 机器上处理 Kubernetes secrets。

# Windows 机器上的 Kubernetes secrets

在第四章中，*Kubernetes 概念和 Windows 支持*，我们提到 Windows 节点支持的限制之一是，挂载到 pod 的 Kubernetes secrets 作为卷写入节点磁盘存储（而不是 RAM 内存）时是明文。原因是 Windows 目前不支持将内存文件系统挂载到 pod 容器。这可能带来安全风险，并需要额外的操作来保护集群。同时，将 secrets 作为环境变量挂载也有其自己的安全风险——如果有系统访问权限，可以枚举进程的环境变量。在可以从内存文件系统挂载 secrets 作为卷之前，除了使用 Azure Key Vault 等第三方提供者，没有完全安全的解决方案来为 Windows 容器注入 secrets。

在 Kubernetes etcd 集群中*at rest*加密 secrets 是一个不同且重要的主题，在官方文档中有介绍：[`kubernetes.io/docs/tasks/administer-cluster/encrypt-data/`](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)。

让我们进行一个小实验，以更好地理解问题和可能的影响。您将需要在前几章中使用的带有 Windows 节点的 AKS 引擎集群。请按照以下步骤进行：

1.  打开 PowerShell 窗口，并创建一个包含用户名`admin`和密码`Password123`的 Base64 编码的`secret-example.yaml`清单文件：

```
apiVersion: v1
kind: Secret
metadata:
  name: secret-example
type: Opaque
data:
  username: YWRtaW4=
  password: UGFzc3dvcmQxMjM=
```

1.  使用`kubectl apply -f .\secret-example.yaml`命令应用清单文件。

1.  创建`windows-example-deployment.yaml`清单文件，用于部署在 Windows 上运行的示例 ASP.NET 应用程序，并在 pod 的`C:\SecretExample`目录中挂载`secret-example` secret：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: windows-example
  labels:
    app: sample
spec:
  replicas: 1
  selector:
    matchLabels:
      app: windows-example
  template:
    metadata:
      name: windows-example
      labels:
        app: windows-example
    spec:
      nodeSelector:
        "beta.kubernetes.io/os": windows
      containers:
      - name: windows-example
        image: mcr.microsoft.com/dotnet/core/samples:aspnetapp-nanoserver-1809
        ports:
          - containerPort: 80
        volumeMounts:
        - name: secret-example-volume
          mountPath: C:\SecretExample
          readOnly: true
      volumes:
      - name: secret-example-volume
        secret:
          secretName: secret-example
```

1.  使用`kubectl apply -f .\windows-example-deployment.yaml`命令应用清单文件。

1.  使用`kubectl get pods -o wide`命令确定运行 pod 的 Windows 节点。在我们的情况下，是`2972k8s011`。

1.  请按照第八章中的*部署混合 Azure Kubernetes 服务引擎集群*的子章节*连接到虚拟机*中的说明，创建到节点`2972k8s011`的远程桌面连接。

1.  当命令行提示初始化时，使用`docker ps`命令来识别运行我们应用程序的 Docker 容器的 ID。接下来，运行`docker inspect -f {{.Mounts}} <containerID>`命令来获取 Docker 卷数据在*主机*磁盘存储上的*物理*位置：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/80d43a8d-4ef0-4490-9a21-8abc4d804b13.png)

1.  现在，只需使用这个路径，检查目录内容，并使用`type <filePath>`命令来显示与我们秘密对象中`password`键对应的文件的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/cfb041d5-5118-4ffd-ab46-4b8bbee2bd2a.png)

正如您所看到的，我们已经毫无问题地检索到了`Password123`的值。在使用内存中的*tmpfs*文件系统将卷挂载到秘密中的 Linux 系统上，这并不容易！

这种当前设计存在明显的安全问题：任何能够访问节点磁盘存储数据的人都可以获取您的秘密（当前使用的）*明文*。这不仅涉及到对机器本身（物理或远程）的访问，还涉及到存储 Docker 卷的磁盘的*备份*。

为了在一定程度上缓解这个问题，您应该为 Windows 节点磁盘使用*磁盘加密*。在内部部署的场景中，您可以考虑使用 BitLocker，在 Windows 服务器操作系统上有原生支持；您可以在官方文档中找到更多详细信息[`docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-how-to-deploy-on-windows-server`](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-how-to-deploy-on-windows-server)。

对于 Azure 部署来说，好消息是 Azure VM 磁盘始终在 Azure 数据中心*静态加密*。如果您的场景要求您在 VM 操作系统级别提供加密，那么对于托管的 AKS 来说，这个功能目前还不支持（[`github.com/Azure/AKS/issues/629`](https://github.com/Azure/AKS/issues/629)），而对于 AKS Engine，节点 VM 默认情况下是没有加密的（您无法在集群 apimodel 中控制它们），但您可以手动启用它。您可以在官方文档中阅读有关 Windows VM 加密方案的更多信息[`docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-windows`](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-windows)。

为了演示如何手动加密 Windows 节点磁盘，让我们为我们集群中的一个节点`2972k8s011`打开加密：

1.  打开 PowerShell 窗口并创建一个名为`AksEngineEncryptionVault`的 Azure 密钥保管库：

```
az keyvault create `
 --resource-group "aks-engine-windows-resource-group" `
 --name "AksEngineEncryptionVault" `
 --location "westeurope"
```

1.  启用密钥保管库用于 Azure VM 的磁盘加密：

```
az keyvault update `
 --resource-group "aks-engine-windows-resource-group" `
 --name "AksEngineEncryptionVault" `
 --enabled-for-disk-encryption "true"
```

1.  为`All`挂载到 VM 的`2972k8s011`节点启用磁盘加密：

```
az vm encryption enable `
 --resource-group "aks-engine-windows-resource-group" `
 --name "2972k8s011" `
 --disk-encryption-keyvault "AksEngineEncryptionVault" `
 --volume-type All
```

1.  加密过程完成后，检查加密功能的当前状态：

```
PS C:\src> az vm encryption show `
>>            --resource-group "aks-engine-windows-resource-group" `
>>            --name "2972k8s011"
{
 "disks": [
 {
 ...
 "name": "2972k8s011_OsDisk_1_1986c424c52c46a39192cdc68c9b9cb9",
 "statuses": [
 {
 "code": "EncryptionState/encrypted",
 "displayStatus": "Encryption is enabled on disk",
 "level": "Info",
 "message": null,
 "time": null
 }
 ]
 }
 ]
}
```

这个过程必须重复进行，对集群中的所有 Windows 节点进行重复，并且在扩展集群时也必须重复进行。

恭喜！您已成功加密了 Windows 节点磁盘，以增加 Kubernetes 密钥安全性。

# 总结

本章主要关注了 Kubernetes 安全性。我们为您提供了 11 条保护 Kubernetes 集群的建议和最佳实践，从使用 RBAC 和集成外部身份验证提供程序，如 Azure Active Directory，到禁用 Kubernetes API 和仪表板的公共访问以及启用审计日志记录。我们演示了如何在 AKS Engine 集群上使用 Azure Active Directory 集成来简化 RBAC 管理和身份验证。接下来，我们讨论了如何在 Kubernetes 中保护容器运行时以及网络策略的作用（目前尚不支持在 Windows 节点上）。

最后，您了解了在 Linux 和 Windows 机器上注入 Kubernetes 密钥的区别，并且看到了，根据当前设计，访问 Windows 机器上的密钥更容易，可能会导致安全问题。为了缓解这一问题，我们向您展示了如何为在集群中用作 Windows 节点的 Azure VM 加密磁盘。

在下一章中，我们将重点讨论如何监视 Kubernetes 集群，特别是运行在 Windows 节点上的.NET 应用程序。

# 问题

1.  为什么应该在 Kubernetes 中使用外部身份验证提供程序，比如 AAD？

1.  禁用对 Kubernetes 仪表板的公共访问为什么重要？

1.  为什么建议对 etcd 数据存储进行加密？

1.  您可以在 Windows 机器上运行特权容器吗？

1.  Kubernetes 中的网络策略是什么，启用它们的先决条件是什么？

1.  Linux 和 Windows 节点在挂载密钥作为卷时的主要区别是什么？

1.  为什么将密钥作为环境变量注入被认为比在 Linux 节点上使用卷不安全？

您可以在本书的*评估*中找到这些问题的答案。

# 进一步阅读

+   有关 Kubernetes 安全性的更多信息，请参考以下 PacktPub 图书：

+   *The Complete Kubernetes Guide*（[`www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide`](https://www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide)）。

+   使用 Kubernetes 入门-第三版（[`www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition`](https://www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition)）。

+   *Kubernetes for Developers*（[`www.packtpub.com/virtualization-and-cloud/kubernetes-developers`](https://www.packtpub.com/virtualization-and-cloud/kubernetes-developers)）。


# 第十四章：使用 Prometheus 监控 Kubernetes 应用程序

作为容器编排器的 Kubernetes 是一个复杂的分布式系统，需要监控和警报才能在规模上正常运行。同时，您需要以相同的方式监控在 Kubernetes 上运行的应用程序——如果没有监控和警报，您就不知道应用程序的行为如何，是否发生任何故障，或者是否应该扩展工作负载。事实上，与监控和警报相关的挑战是企业采用 Kubernetes 时最常报告的阻碍之一。

幸运的是，多年来，市场上涌现出了多种日志聚合、遥测收集、警报甚至专门的**应用性能管理**（**APM**）系统的解决方案。我们可以选择不同的软件即服务（**SaaS**）解决方案或开源系统，这些系统可以在本地托管，专门用于 Kubernetes 集群！

但是另一面是：我们受限于可以支持 Windows 容器和基于 Windows 的 Kubernetes 节点的解决方案。在 Kubernetes 中对 Windows 的生产级支持是非常近期的，没有可以立即使用的一揽子解决方案。因此，本章旨在概述 Kubernetes 的可用监控解决方案，并探讨如何实现支持 Windows 节点的自己的解决方案。

在本章中，我们将涵盖以下主题：

+   可用的监控解决方案

+   提供可观察的 Windows 节点

+   使用 Helm 图表部署 Prometheus

+   Windows 性能计数器

+   使用`prometheus-net`监控.NET 应用程序

+   在 Grafana 中配置仪表板和警报

# 技术要求

本章，您将需要以下内容：

+   安装了 Windows 10 Pro、企业版或教育版（1903 版或更高版本，64 位）

+   Microsoft Visual Studio 2019 Community（或任何其他版本），如果您想编辑应用程序的源代码并进行调试——Visual Studio Code 对经典.NET Framework 的支持有限

+   已安装 Helm

+   Azure 账户

+   使用 AKS Engine 部署的 Windows/Linux Kubernetes 集群，准备部署上一章中的投票应用程序

要跟进，您将需要自己的 Azure 帐户来为 Kubernetes 集群创建 Azure 资源。如果您还没有为之前的章节创建帐户，您可以在此处阅读有关如何获取用于个人使用的有限免费帐户的更多信息：[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)。

使用 AKS Engine 部署 Kubernetes 集群已在第八章中进行了介绍，*部署混合 Azure Kubernetes 服务引擎集群*。将投票应用程序部署到 Kubernetes 已在第十章中进行了介绍，*部署 Microsoft SQL Server 2019 和 ASP.NET MVC 应用程序*。

您可以从官方 GitHub 存储库下载本章的最新代码示例：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter14`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter14)。

# 可用的监控解决方案

单词“监控”通常被用作一个涵盖以下内容的总称：

+   **可观察性：**为您的组件提供可观察性意味着公开有关其内部状态的信息，以便您可以轻松访问数据并对组件的实际状态进行推理。换句话说，如果某物是可观察的，您就可以理解它。提供可观察性的一个众所周知的特性示例是日志记录。您的应用程序生成日志，以便您可以检查应用程序的流程和当前状态。可观察性有三个支柱：日志记录、分布式跟踪和指标。分布式跟踪提供了对请求流经多个服务的洞察，例如使用关联 ID。指标可以是应用程序公开的数字信息，例如计数器或量规。

+   **监控：**这意味着收集组件的可观察数据并存储它，以便进行分析。

+   **分析和警报：**基于收集的监控数据，您可以进行分析，当组件被视为不健康时创建规则，并为您的团队配置警报。更复杂的情况涉及异常检测和机器学习。

在 Kubernetes 中，监控比监控单个应用程序还要复杂。通常，您可以将 Kubernetes 集群的监控划分为以下几个独立的领域：

+   监控 Kubernetes 节点的硬件和操作系统基础设施

+   监控容器运行时

+   监控 Kubernetes 组件和资源本身

+   监控在集群中运行的容器化应用程序

最后，您可以从托管解决方案与 Kubernetes 相关的角度来查看监控系统：

+   **本地监控**：使用自己的云或裸金属基础设施，您可以为运行监控工具提供单独的集群，或者使用与应用程序相同的集群。第二种解决方案更容易，但只能考虑用于小型 Kubernetes 集群。您希望分开应用程序和监控工作负载；您特别不希望监控对应用程序的性能产生负面影响。这种方法的一个示例是部署自己的 Prometheus ([`prometheus.io/`](https://prometheus.io/))实例来收集 Kubernetes 集群中的指标，以及日志分析解决方案，例如**Elasticsearch, Logstash, Kibana** (**ELK**) stack ([`www.elastic.co/what-is/elk-stack`](https://www.elastic.co/what-is/elk-stack))。

+   **内部 SaaS 监控**：如果您在云中运行，可以使用云服务提供商提供的 SaaS 产品，例如在 Azure 上，您可以使用 Azure Monitor ([`azure.microsoft.com/en-us/services/monitor/`](https://azure.microsoft.com/en-us/services/monitor/))。这些解决方案通常很容易与其他托管服务集成，例如 AKS。此外，对于日志监控，您可以利用 Azure Monitor 中的 Log Analytics ([`docs.microsoft.com/en-us/azure/azure-monitor/log-query/get-started-portal`](https://docs.microsoft.com/en-us/azure/azure-monitor/log-query/get-started-portal))。

+   **外部 SaaS 监控**：在这种情况下，您可以使用外部公司提供的专用通用 SaaS 产品来监控在任何云中甚至本地运行的集群。监控平台的市场很大，其中一些知名的例子是 New Relic ([`newrelic.com/platform`](https://newrelic.com/platform))和 Dynatrace ([`www.dynatrace.com/technologies/kubernetes-monitoring/`](https://www.dynatrace.com/technologies/kubernetes-monitoring/))。

通常，使用内部 SaaS 监控比使用外部 SaaS 更便宜，但您面临更多的供应商锁定风险，并增加了对特定云服务提供商的依赖性。使用您自己部署的本地监控是最灵活和最便宜的，但您必须考虑随之而来的管理和运营开销，因为这需要额外的大型应用程序。

关于监控的问题仍然存在。您可以在谷歌的以下在线书籍中了解更多关于四个黄金信号的信息：[`landing.google.com/sre/sre-book/chapters/monitoring-distributed-systems/`](https://landing.google.com/sre/sre-book/chapters/monitoring-distributed-systems/)。在以下文章中了解**USE**（即**Utilization Saturation and Errors**）方法：[`www.brendangregg.com/usemethod.html`](http://www.brendangregg.com/usemethod.html)。

现在，混合 Windows/Linux Kubernetes 集群进入了视野。重要的是要知道，监控 Windows 机器与监控 Linux 机器有很大不同——您不能使用相同的监控代理；它们必须专门针对特定的操作系统。

即使在 Docker 的情况下，它与操作系统的集成方式与 Linux 和 Windows 不同，这也意味着容器运行时监控必须以不同的方式进行。这就是为什么目前在 Kubernetes 中没有用于监控 Windows 节点的即插即用解决方案的原因。提供最接近的是 Azure Monitor 中的容器监控解决方案（[`docs.microsoft.com/en-us/azure/azure-monitor/insights/containers`](https://docs.microsoft.com/en-us/azure/azure-monitor/insights/containers)），它可以为 Windows 容器提供遥测数据，但尚未与混合 AKS 或 AKS Engine 集成。当然，您仍然可以在 AKS Engine 的机器上手动配置它。

那么，我们还有什么其他解决方案吗？作为更通用的解决方案，我们建议部署一个 Prometheus 实例，它将能够默认监控来自 Linux 工作负载的指标，并可以扩展到监控 Windows 节点和容器。

在您的集群中进行分布式跟踪和聚合日志是复杂的监控主题。在本书中，我们只会涵盖度量监控。如果您对 Kubernetes 的日志记录解决方案感兴趣，请查看官方文档：[`kubernetes.io/docs/concepts/cluster-administration/logging/`](https://kubernetes.io/docs/concepts/cluster-administration/logging/)。对于分布式跟踪，请考虑阅读关于 Jaeger 的信息：[`www.jaegertracing.io/`](https://www.jaegertracing.io/)。

让我们看看如何使用 Prometheus 为混合 Kubernetes 集群提供度量监控。

# Prometheus 和监控 Windows 节点

Prometheus ([`prometheus.io/`](https://prometheus.io/)) 是一个用于度量监控的开源系统，使用 PromQL 语言来探索时间序列数据。它利用了“exporters”和 HTTP 拉取模型的概念，其中 exporters 在指定的 HTTP 端点上公开数据，并定期被 Prometheus 服务器抓取。另外，它还可以使用 HTTP 推送模型，通常不建议使用，但有时会很有用。用于公开度量的格式是一个简单的文本格式，其中每一行代表一个度量的值，大致形式如下：

```
http_requests_total{method="post",code="200"} 190
http_requests_total{method="post",code="400"} 5
```

Prometheus 将所有数据存储为时间序列，这些时间序列是同一度量的读数流，覆盖了整个时间范围。exporters 仅公开度量的当前值，而 Prometheus 负责将历史存储为时间序列。在这个例子中，`http_requests_total`是度量的名称，`method`是标签名称，`"post"`是标签值，`190`是当前的度量值。标签用于为您的时间序列数据提供维度，然后可以在 PromQL 中用于各种操作，如过滤和聚合。单个读数的一般格式是`<metric name>{<label name>=<label value>, ...} <metric_value>`。

您可以在官方文档中阅读更多关于这种格式的信息：[`github.com/prometheus/docs/blob/master/content/docs/instrumenting/exposition_formats.md`](https://github.com/prometheus/docs/blob/master/content/docs/instrumenting/exposition_formats.md)。

在 Prometheus 之上，您通常会使用 Alertmanager 来配置警报和 Grafana（[`grafana.com/`](https://grafana.com/)）或 Kibana（[`www.elastic.co/products/kibana`](https://www.elastic.co/products/kibana)）来创建仪表板和可视化。以下图表显示了 Prometheus 在高层次上的架构以及它如何监视在 Kubernetes 中运行的 Linux 工作负载：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/959c13db-97a5-495b-8d3d-26cc3b30e464.png)

用于监视 Kubernetes 上 Linux 容器的常见 Prometheus 架构

除了标准的 Prometheus 组件之外，在集群中每个 Linux 节点上运行着两个关键的导出器：**cAdvisor**，它公开容器运行时指标，以及**Node Exporter**，它负责公开操作系统和硬件指标。对于 Windows，我们可以使用类似的方案，但我们需要使用不同的导出器，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/df756732-0303-496d-8a54-2d0270aef7ec.png)

用于监视 Kubernetes 上 Windows 容器的可能的 Prometheus 架构

在这种情况下，为了公开操作系统和硬件指标，我们使用专门用于 Windows 机器的 WMI Exporter。它还可以公开一些 Docker 指标，但我们还可以打开使用 Docker Engine 本地公开指标的实验性功能，而无需额外的导出器。您可以在文档中阅读更多关于这个 Docker 功能的信息：[`docs.docker.com/config/thirdparty/prometheus/`](https://docs.docker.com/config/thirdparty/prometheus/)。

一般来说，在 Windows 上，部署导出器作为收集操作系统指标的 Kubernetes DaemonSets 更加困难。正如前几章中提到的，在 Windows 上，您无法运行特权容器，因此无法访问容器运行时信息。这就是为什么在 Kubernetes 中监视 Windows 容器比监视 Linux 容器要困难一些的主要原因——我们必须在 Kubernetes 集群之外直接在主机上配置导出器。现在，让我们看看在本地场景和 AKS Engine 中如何实现这一点。

# 提供可观察的 Windows 节点

Prometheus 使用的 HTTP 拉模型与可观察性和监视本身之间的关注点分离完全一致。组件或机器负责暴露适当的数据和指标-它允许被观察-而 Prometheus 定期消耗可用数据，这个过程称为抓取。这意味着如果您有一种方法可以在某个 HTTP 端点以 Prometheus 格式暴露指标，您就可以使用 Prometheus 进行监视！它可以是系统服务暴露的硬件遥测，甚至是您在.NET 应用程序中通过额外的 HTTP 端点访问的自己的指标。

现在，有一个问题，如何在 Windows 操作系统上收集指标数据并将其暴露出来。我们对以下内容感兴趣：

+   与主机机器相关的指标，例如 CPU、内存、网络和 I/O 指标

+   进程和主机操作系统本身的指标以及性能计数器通常

+   容器运行时本身的指标

+   单个容器的指标

+   在裸机上，此外，关于硬件指标的信息，如 CPU 温度和 ECC 内存校正计数。

对于 Prometheus 来说，在 Windows 上支持出口器的支持仍在扩展，但目前，我们已经可以收集大部分前述的指标。总的来说，WMI Exporter（[`github.com/martinlindhe/wmi_exporter`](https://github.com/martinlindhe/wmi_exporter)）是在 Windows 上收集所有与硬件和操作系统相关的指标的推荐出口器。对于 Docker 运行时和容器，我们可以使用 Docker 的一个实验性功能（[`docs.docker.com/config/thirdparty/prometheus/`](https://docs.docker.com/config/thirdparty/prometheus/)）来以 Prometheus 格式暴露指标。此外，当在配置中启用容器收集器时，WMI Exporter 还可以暴露一些有用的 Docker 容器指标。

如果您对任何其他 Windows 性能计数器感兴趣，可以使用 Telegraf（[`www.influxdata.com/time-series-platform/telegraf/`](https://www.influxdata.com/time-series-platform/telegraf/)）将它们暴露为 Prometheus 格式的指标。我们将在接下来的部分中进行这样的操作，因为在主机上监视 Windows 性能计数器以及容器内部都有非常有效的用例。

# 安装 WMI Exporter 并在 Docker 中启用 Metrics Server

现在，我们对如何使 Windows 机器对 Prometheus 可观察以及哪些组件可以满足我们的要求有了一些了解。如果您使用 Chocolatey，WMI Exporter 的安装非常简单：

```
choco install prometheus-wmi-exporter.install
```

此命令将使用默认配置安装导出器，并在端点`http://0.0.0.0:9182`上公开指标，如软件包文档中所述：[`chocolatey.org/packages/prometheus-wmi-exporter.install`](https://chocolatey.org/packages/prometheus-wmi-exporter.install)。对于我们的用例，我们需要启用一些特定的收集器，并且这些信息可以作为参数传递给安装程序。此外，我们应该使安装无人值守，并在机器上安装 Chocolatey（如果缺少）-我们的 PowerShell 脚本将如下所示：

```
if ((Get-Command "choco" -ErrorAction SilentlyContinue) -eq $null) {
 Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')) | Out-Null
}

choco install prometheus-wmi-exporter.install -y --force --params "`"/EnabledCollectors:cpu,cs,container,dns,logical_disk,logon,memory,net,os,process,service,system,tcp`""
```

要在 Docker Engine 中启用 Metrics Server，位于`http://0.0.0.0:9323`，我们可以创建另一个小的 PowerShell 脚本：

```
Set-Content -Value '{ "metrics-addr" : "0.0.0.0:9323", "experimental" : true }' -Path C:\ProgramData\docker\config\daemon.json
Restart-Service Docker -Force
```

现在，您必须考虑如何执行安装。对于本地部署，请考虑以下内容：

+   如果您使用自动化创建 Kubernetes 集群，例如 Ansible，那么您可以添加额外的后配置步骤。

+   如果您在集群中为您的机器使用裸机映像或 VM 映像，您可以将安装步骤嵌入到映像配置过程中。

+   如果您使用 Ansible 或 PowerShell Desired State Configuration 来管理您的机器，您也可以使用这些工具触发安装。

在云部署的情况下，一切取决于您是使用托管还是非托管集群：

+   对于像 AKS 这样的托管部署，您受到服务允许的限制；例如，您可以使用带有自定义脚本扩展的 VMSS。

+   对于非托管部署，您可以使用与本地部署相同的技术，例如提供预安装服务的自定义 VM 映像，或者使用专门针对您的云服务提供商的解决方案。

对于 AKS Engine，您有三个选项：

+   对于开发和测试目的，您可以使用 RDP 或 SSH 连接到 Windows 机器并手动执行安装。

+   您可以为 Windows 节点使用自定义 VM 映像（[`github.com/Azure/aks-engine/blob/master/docs/topics/windows-vhd.md`](https://github.com/Azure/aks-engine/blob/master/docs/topics/windows-vhd.md)）。

+   您可以使用 AKS Engine 扩展([`github.com/Azure/aks-engine/blob/master/docs/topics/extensions.md`](https://github.com/Azure/aks-engine/blob/master/docs/topics/extensions.md))，它们作为部署的一部分运行的自定义脚本扩展。

我们将演示如何使用专用扩展自定义 AKS Engine 集群部署。

# 使用 AKS Engine 的扩展

AKS Engine 扩展是一项功能，它允许在部署的后期步骤中进行额外的自定义步骤。例如，您可以通过扩展存储库执行任何提供的 PowerShell 脚本。存储库可以是遵循目录命名约定的任何 HTTP 服务器，这也包括原始的 GitHub 存储库访问端点。要了解有关扩展如何工作的更多信息，请参阅官方文档：[`github.com/Azure/aks-engine/blob/master/docs/topics/extensions.md`](https://github.com/Azure/aks-engine/blob/master/docs/topics/extensions.md)。您可以使用`winrm`扩展作为了解实现细节的良好基础：[`github.com/Azure/aks-engine/tree/master/extensions/winrm`](https://github.com/Azure/aks-engine/tree/master/extensions/winrm)。

在集群部署期间可以使用扩展。您不能在运行的集群上启用扩展。此外，由于 SQL Server Helm 图表需要在单个节点上挂载四个卷，我们需要为 Linux 节点使用更大的 VM 类型，例如 Standard_D4_v3，该类型支持最多八个卷。您可以在文档中阅读有关每个 VM 挂载的最大卷数：[`docs.microsoft.com/en-us/azure/virtual-machines/windows/sizes-general`](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/sizes-general)。

在本书的 GitHub 存储库中，您可以找到一个安装 WMI Exporter 并在 Windows 上启用 Docker Metrics Server 的扩展：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter14/03_aks-engine-windows-extensions/extensions/prometheus-exporters`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter14/03_aks-engine-windows-extensions/extensions/prometheus-exporters/)。让我们看看扩展是如何构建的，以及如何使用扩展部署新的 AKS Engine 集群：

1.  PowerShell 脚本`v1/installExporters.ps1`执行自定义安装逻辑，并具有以下内容：

```
Param(
    [Parameter()]
    [string]$PackageParameters = "/EnabledCollectors:cpu,cs,container,dns,logical_disk,logon,memory,net,os,process,service,system,tcp"
)

if ((Get-Command "choco" -ErrorAction SilentlyContinue) -eq $null) {
    Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')) | Out-Null
}

choco install prometheus-wmi-exporter.install -y --force --params "`"$PackageParameters`""

Set-Content -Value '{ "metrics-addr" : "0.0.0.0:9323", "experimental" : true }' -Path C:\ProgramData\docker\config\daemon.json
Restart-Service Docker -Force
```

它将使用 Chocolatey 安装 WMI Exporter，为 Docker 启用 Metrics Server，并在之后重新启动 Docker。

1.  `v1/template.json` JSON 文件包含一个 ARM 模板，触发 PowerShell 脚本的关键部分如下：

```
"properties": {
     "publisher": "Microsoft.Compute",
     "type": "CustomScriptExtension",
     "typeHandlerVersion": "1.8",
     "autoUpgradeMinorVersion": true,
     "settings": {
       "fileUris": [
         "[concat(parameters('artifactsLocation'), 'extensions/prometheus-exporters/v1/installExporters.ps1')]"
        ]
     },
     "protectedSettings": {
       "commandToExecute": "[concat('powershell.exe -ExecutionPolicy bypass \"& ./installExporters.ps1 -PackageParameters ', parameters('extensionParameters'), '\"')]"
     }
}
```

这将为自定义脚本扩展配置属性，该扩展将下载安装脚本，并使用您在集群 apimodel 中传递的参数执行它。

1.  `v1/template-link.json`是一个通用文件，其中包含要由 AKS Engine 替换的占位符。这样，您的模板将链接到部署。

1.  现在，创建一个 GitHub 仓库并推送扩展。确保您遵循目录命名约定，例如，存储库中`template.json`的完整路径应为`extensions/prometheus-exporters/v1/template.json`。在示例中，我们将使用以下 GitHub 仓库：[`github.com/ptylenda/aks-engine-windows-extensions`](https://github.com/ptylenda/aks-engine-windows-extensions)。

1.  现在，修改您的 AKS Engine 集群 apimodel，使其为所有 Windows 节点使用扩展（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter14/04_aks-engine-cluster-with-extensions/kubernetes-windows-template.json`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter14/04_aks-engine-cluster-with-extensions/kubernetes-windows-template.json)），并确保您使用`vmSize`用于 Linux 节点池，该节点池能够挂载超过四个卷：

```
{
  "apiVersion": "vlabs",
  "properties": 
    ...
    "agentPoolProfiles": [
      {
        "name": "linuxpool1",
        "vmSize": "Standard_D4_v3"
        ...
      },
      {        
        "name": "windowspool2",
        ...
        "extensions": [
            {
                "name": "prometheus-exporters",
                "singleOrAll": "all"
            }
        ]
      }
    ],
    ...
    "extensionProfiles": [
      {
        "name": "prometheus-exporters",
        "version": "v1",
        "rootURL": "https://raw.githubusercontent.com/ptylenda/aks-engine-windows-extensions/master/",
        "extensionParameters": "'/EnabledCollectors:cpu,cs,container,dns,logical_disk,logon,memory,net,os,process,service,system,tcp'"
      }
    ]
  }
}
```

作为`rootURL`，您需要提供 GitHub 仓库的原始访问的 HTTP 地址，该地址带有扩展。此外，我们将`'/EnabledCollectors:cpu,cs,container,dns,logical_disk,logon,memory,net,os,process,service,system,tcp'`作为参数传递给扩展，这些参数将在执行 PowerShell 脚本时使用。

1.  现在，以与前几章相同的方式部署集群。您也可以使用我们通常的 PowerShell 脚本：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter14/04_aks-engine-cluster-with-extensions/CreateAKSEngineClusterWithWindowsNodes.ps1`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter14/04_aks-engine-cluster-with-extensions/CreateAKSEngineClusterWithWindowsNodes.ps1)。

1.  当部署完成后，使用`kubectl get nodes -o wide`命令来确定其中一个 Windows 节点的私有 IP，例如`10.240.0.65`。

1.  使用`ssh azureuser@<dnsPrefix>.<azureLocation>.cloudapp.azure.com`命令 SSH 到主节点，并检查 Windows 节点是否在端口`9323`和`9182`上导出指标：

```
azureuser@k8s-master-36012248-0:~$ curl http://10.240.0.65:9323/metrics
# HELP builder_builds_failed_total Number of failed image builds
# TYPE builder_builds_failed_total counter
builder_builds_failed_total{reason="build_canceled"} 0
builder_builds_failed_total{reason="build_target_not_reachable_error"} 0
builder_builds_failed_total{reason="command_not_supported_error"} 0
...
azureuser@k8s-master-36012248-0:~$ curl http://10.240.0.65:9182/metrics
# HELP go_gc_duration_seconds A summary of the GC invocation durations.
# TYPE go_gc_duration_seconds summary
go_gc_duration_seconds{quantile="0"} 0
go_gc_duration_seconds{quantile="0.25"} 0
go_gc_duration_seconds{quantile="0.5"} 0
...
```

恭喜！现在您的 AKS Engine 集群中的 Windows 节点正在公开可以被 Prometheus 抓取的指标。在下一节中，我们将在我们的集群中安装 Prometheus，并配置它来监视 Linux 和 Windows 节点。

# 使用 Helm 图表部署 Prometheus

我们的集群基础设施现在是可观察的 - 我们可以部署带有适当配置文件的 Prometheus 并开始监视集群。要部署 Prometheus，我们有几个选项：

+   手动使用多个清单文件部署它。

+   使用`stable/prometheus` Helm 图表（[`github.com/helm/charts/tree/master/stable/prometheus`](https://github.com/helm/charts/tree/master/stable/prometheus)）。该图表提供了 Prometheus、Alertmanager、Pushgateway、Node Exporter（用于 Linux 节点）和 kube-state-metrics。

+   使用`stable/prometheus-operator` Helm 图表（[`github.com/helm/charts/tree/master/stable/prometheus-operator`](https://github.com/helm/charts/tree/master/stable/prometheus-operator)）或`kube-prometheus`（[`github.com/coreos/kube-prometheus`](https://github.com/coreos/kube-prometheus)）。这些解决方案旨在提供一种快速在 Kubernetes 集群中部署多个 Prometheus 集群的方法。

在我们的情况下，最好的选择是使用`stable/prometheus` Helm 图表，因为它需要最少的配置，并且不像通用的 Prometheus Operator 那样复杂。在生产环境中，运行大规模，您应该考虑使用 Prometheus Operator，这样您就可以轻松地为不同的需求部署多个 Prometheus 集群。

# 安装 Helm 图表

要使用 Helm 图表部署 Prometheus，请执行以下步骤：

1.  我们将在名为`monitoring`的单独命名空间中部署我们的监控解决方案。此外，我们需要为 Prometheus 数据持久性定义`StorageClass`。创建名为`prereq.yaml`的清单文件，内容如下：

```
---
kind: Namespace
apiVersion: v1
metadata:
  name: monitoring
  labels:
    name: monitoring
---
kind: StorageClass
apiVersion: storage.k8s.io/v1beta1
metadata:
  name: azure-disk
provisioner: kubernetes.io/azure-disk
parameters:
  storageaccounttype: Standard_LRS
  kind: Managed
```

1.  使用`kubectl apply -f .\prereq.yaml`命令应用清单文件。

1.  现在，我们需要为`stable/prometheus` Helm 图表（[`github.com/prometheus/prometheus`](https://github.com/prometheus/prometheus)）定义值。这个图表是高度可配置的，所以请检查是否需要覆盖任何其他值。创建`helm-values_prometheus.yaml`文件，并开始编辑它，内容如下（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter14/05_helm_prometheus/helm-values_prometheus.yaml`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter14/05_helm_prometheus/helm-values_prometheus.yaml)）：

```
server:
  enabled: true
  global:
 scrape_interval: 50s
 scrape_timeout: 15s
 evaluation_interval: 1m
  service:
    type: LoadBalancer
  nodeSelector:
    "kubernetes.io/os": linux
  persistentVolume:
    storageClass: azure-disk

alertmanager:
  enabled: true
  service:
    type: LoadBalancer
  nodeSelector:
    "kubernetes.io/os": linux
  persistentVolume:
    storageClass: azure-disk

nodeExporter:
  enabled: true
  nodeSelector:
    "kubernetes.io/os": linux

pushgateway:
  enabled: true
  nodeSelector:
    "kubernetes.io/os": linux

kubeStateMetrics:
  enabled: true
  nodeSelector:
    "kubernetes.io/os": linux
```

最重要的部分是确保为所有组件设置适当的`nodeSelector`，以便 Pod 不会意外地被调度到 Windows 机器上。此外，我们需要提供`storageClass`的名称，用于处理 PVC。另一个解决方案可能是在集群中将`azure-disk`设置为默认的`storageClass`。在 Helm 图表配置中，您还可以影响抓取设置，例如您希望多久执行一次抓取作业。最后，我们使用`LoadBalancer`服务公开了 Prometheus 和 Alertmanager——当然，这仅适用于开发和测试目的，以便不使用`kubectl proxy`（这需要对 Grafana 进行额外配置）或使用跳板机。

对于生产场景，请考虑将对 Prometheus 的访问限制在私有网络内，或者在其后面暴露 Ingress，使用 HTTPS，并提供安全的身份验证方法。例如，您可以将 Nginx Ingress 与 Azure Active Directory 集成（[`kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/`](https://kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/)）。

在设置较小的`scrape_interval`值时要小心。太短的抓取间隔可能会导致节点和 Pod 的过载，并导致系统不稳定。您应该始终评估您的导出器在 CPU 使用和 RAM 内存方面的成本。

1.  继续编辑`helm-values_prometheus.yaml`文件，并为 Prometheus 提供抓取配置。我们需要确保我们的 WMI Exporter 和 Docker Engine 指标服务器被 Prometheus 服务器抓取。您只能看到 Docker Engine 指标服务器的以下配置；WMI Exporter 的配置几乎相同，除了端口号：

```
extraScrapeConfigs: |
   - job_name: windows-nodes-docker-metrics-server
     kubernetes_sd_configs:
       - role: node
     scheme: http
     relabel_configs:
     - action: labelmap
       regex: __meta_kubernetes_node_label_(.+)
     - source_labels: [__address__]
       action: replace
       target_label: __address__
       regex: ([^:;]+):(\d+)
       replacement: ${1}:9323
     - source_labels: [kubernetes_io_os]
       action: keep
       regex: windows
     - source_labels: [__meta_kubernetes_node_name]
       regex: (.+)
       target_label: __metrics_path__
       replacement: /metrics
     - source_labels: [__meta_kubernetes_node_name]
       action: replace
       target_label: node
       regex: (.*)
       replacement: ${1}
...
```

Prometheus 抓取配置可能会变得有点复杂；您可以查看官方文档以获取详细说明：[`prometheus.io/docs/prometheus/latest/configuration/configuration/`](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)。基本配置会抓取带有`prometheus.io/scrape: 'true'`注释的 API 资源，因此，例如，如果您希望抓取自己的应用 Pod，您需要使用此注释（以及`prometheus.io/port`）。此外，您可以根据 API 资源直接配置抓取（`kubernetes_sd_configs`），在这种情况下是`node`。之后，我们对节点 API 返回的标签执行各种操作：我们确保`__address__`特殊标签的最终值包含所需的`9323`端口，并且我们将`__metrics_path__`定义为`/metrics`，因此最终，我们将抓取此 HTTP 端点：`http://<nodeAddress>:9323/metrics`。

1.  使用`values`文件安装 Prometheus 的 Helm 图表作为`prometheus`发布：

```
helm install prometheus stable/prometheus -n monitoring --values .\helm-values_prometheus.yaml --debug
```

1.  在安装进行的同时，您可以为`stable/grafana` Helm 图表定义`helm-values_grafana.yaml`值文件，我们将使用它来部署 Prometheus 的 Grafana：

```
nodeSelector:
  "kubernetes.io/os": linux

service:
  type: LoadBalancer

persistence:
  enabled: true
  storageClassName: azure-disk
  size: 20Gi
  accessModes:
   - ReadWriteOnce

adminUser: admin
adminPassword: P@ssword

datasources:
  datasources.yaml:
    apiVersion: 1
    datasources:
    - name: Prometheus
      type: prometheus
      url: http://prometheus-server
      access: proxy
      isDefault: true
```

同样，我们需要确保 Grafana 仅安排在 Linux 节点上。同样，我们使用负载均衡器公开服务-您应该考虑不同的生产部署策略，或者至少为此公共端点提供适当的身份验证。最后一个重要的事情是确保我们的 Prometheus 实例被添加为 Grafana 中的默认数据源。在这里，您应该使用服务名称通过 DNS 名称进行发现。

1.  使用以下命令将`stable/grafana` Helm 图表安装为`grafana`发布：

```
helm install grafana stable/grafana -n monitoring --values .\helm-values_grafana.yaml --debug
```

1.  现在，等待所有 Pod 准备就绪并且服务接收到外部 IP：

```
PS C:\src> kubectl get pod,svc -n monitoring
...
NAME                                    TYPE           CLUSTER-IP     EXTERNAL-IP    PORT(S)        AGE
service/grafana                         LoadBalancer   10.0.28.94     104.40.19.54   80:30836/TCP   2h
service/prometheus-alertmanager         LoadBalancer   10.0.0.229     40.78.81.58    80:30073/TCP   2h
service/prometheus-server               LoadBalancer   10.0.219.93    40.78.42.14    80:32763/TCP   2h
...
```

此时，您有三个可以访问的 Web UI：

+   Prometheus 服务器（在我们的示例中，可在`http://40.78.42.14`访问）

+   Alertmanager（`http://40.78.81.58`）

+   Grafana（`http://104.40.19.54`）

# 验证部署

验证您是否可以访问服务的外部 IP 并执行一些基本操作：

1.  打开您的 Prometheus 服务器的 Web UI。

1.  转到状态并选择目标。

1.  向下滚动到由作业抓取的`windows-nodes-docker-metrics-server`和`windows-nodes-wmi-exporter targets`。它们应该是绿色的，并且在没有错误的情况下执行——如果不是这种情况，您需要验证您的抓取配置。出于调试目的，您可以直接向集群中的适当 ConfigMap 引入更改。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/24f22213-a81b-49db-8c42-c9e19b2b4e1e.png)

1.  在顶部菜单中导航到图形，并在“执行”按钮下方切换到“图形”选项卡。运行一个示例查询，`rate(wmi_net_bytes_total[60s])`，它将根据最后 60 秒的`wmi_net_bytes_total`计数器指标绘制每秒接收和发送到 Windows 节点的平均字节数：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/917ed898-b0d8-43e7-aae8-dde7d2032748.png)

1.  打开 Grafana Web UI，并使用您在 Helm 图表中提供的凭据登录。

1.  在菜单中点击+，选择仪表板，然后选择添加查询。

1.  输入一个示例 PromQL 查询，`wmi_memory_available_bytes / (1024 * 1024 * 1024)`，它将以 GB 为单位绘制 Windows 节点上的可用内存：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/cbee5da2-ea08-45ab-93be-1bed3201b7bd.png)

现在，我们确认我们的监控设置正常工作！您可以在官方文档中深入了解 PromQL：[`prometheus.io/docs/prometheus/latest/querying/basics/`](https://prometheus.io/docs/prometheus/latest/querying/basics/)。这是一种广泛而强大的语言，可以实现大部分您的**服务水平指标**（**SLIs**）来监视您的**服务水平目标**（**SLOs**）。

在下一节中，我们将探讨如何配置使用 Telegraf 导出任何 Windows 性能计数器。

# Windows 性能计数器

Windows 提供了一个名为性能计数器的功能，用于提供有关操作系统、服务、应用程序或驱动程序的性能情况。通常，您使用**Windows 管理工具**（**WMI**）来获取单个指标值，并使用更高级的应用程序（如 Perfmon）来在本地可视化性能数据。对于.NET Framework 应用程序，您可以直接读取运行时提供的多个计数器；您可以在文档中找到计数器的列表：[`docs.microsoft.com/en-us/dotnet/framework/debug-trace-profile/performance-counters`](https://docs.microsoft.com/en-us/dotnet/framework/debug-trace-profile/performance-counters)。有了这些指标，您可以轻松监视异常抛出数量的异常波动（甚至无需分析日志）或分析垃圾回收问题。此外，许多经典的.NET Framework 应用程序还公开了自己的性能计数器。

对于 Kubernetes，除了 WMI Exporter 收集的标准性能计数器（尚不支持自定义查询：[`github.com/martinlindhe/wmi_exporter/issues/87`](https://github.com/martinlindhe/wmi_exporter/issues/87)），还有两种情况可以考虑：

+   收集容器中运行的应用程序的性能计数器

+   收集来自 Windows 主机的更多性能计数器

这两个问题都可以使用 Telegraf（[`github.com/influxdata/telegraf`](https://github.com/influxdata/telegraf)）来解决，它是一个通用的、可扩展的代理，用于收集、处理、聚合和编写指标。它支持的输入插件之一是`win_perf_counter`（[`github.com/influxdata/telegraf/tree/master/plugins/inputs/win_perf_counters`](https://github.com/influxdata/telegraf/tree/master/plugins/inputs/win_perf_counters)），可以收集和转换 Windows 上可用的任何性能计数器。同时，Telegraf 能够使用`prometheus_client`输出插件（[`github.com/influxdata/telegraf/tree/master/plugins/outputs/prometheus_client`](https://github.com/influxdata/telegraf/tree/master/plugins/outputs/prometheus_client)）以 Prometheus 格式公开收集的指标。完整的解决方案需要准备一个配置文件，将 Telegraf 安装为 Windows 服务，并确保 Prometheus 抓取新的端点。

如果您想要从主机机器收集更多性能计数器，在 AKS Engine 上，您可以使用自定义扩展来实现，就像我们为 WMI Exporter 和 Docker 指标服务器所做的那样。我们将演示第一个场景：如何丰富您的 Docker 镜像，以便在 Kubernetes 上运行的容器公开更多 Prometheus 指标。请注意，您必须始终考虑这是否对您来说是一个有效的用例——在集群中的每个容器中嵌入 Telegraf 会增加 CPU 使用率和 RAM 内存占用。一个一般的经验法则是，您应该仅对可能需要调查复杂性能问题的关键组件使用此方法，或者作为调试目的的临时操作。

# 使用 Telegraf 服务扩展 Docker 镜像

Windows 上的 Telegraf 安装过程很简单：需要解压文件，提供适当的配置文件，并将 Telegraf 注册为 Windows 服务。要为投票应用程序构建新版本的 Docker 镜像，该镜像在端口`9273`上公开性能计数器，您可以使用 GitHub 存储库中的源代码([`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter14/06_voting-application-telegraf`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter14/06_voting-application-telegraf))，或者在先前版本的源代码上执行以下步骤：

1.  在根目录中，创建一个名为`telegraf.conf`的新文件，其中包含 Telegraf 配置。您可以在此处找到此文件的内容：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter14/06_voting-application-telegraf/telegraf.conf`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter14/06_voting-application-telegraf/telegraf.conf)。我们只在以下列出了重要部分：

```
...
[[outputs.prometheus_client]]
  listen = "0.0.0.0:9273"
  path = "/metrics"
...
[inputs.win_perf_counters]]
  UseWildcardsExpansion = false
  PrintValid = false

  [[inputs.win_perf_counters.object]]
    # Processor usage, alternative to native, reports on a per core.
    ObjectName = "Processor"
    Instances = ["*"]
    Counters = [
      "% Idle Time",
      "% Interrupt Time",
      "% Privileged Time",
      "% User Time",
      "% Processor Time",
      "% DPC Time",
    ]
    Measurement = "win_cpu"
    # Set to true to include _Total instance when querying for all (*).
    IncludeTotal=true
...
```

我们正在使用`prometheus_client`输出插件和`win_perf_counters`输入插件，它配置了多个性能计数器的收集。

1.  将此文件添加到`votingapplication.csproj`中，以便将其包含在构建输出中。

1.  修改`Dockerfile.production`文件，以便在`runtime`阶段的开头包含安装 Telegraf 的部分：

```
...
FROM mcr.microsoft.com/dotnet/framework/aspnet:4.8-windowsservercore-ltsc2019 AS runtime

WORKDIR /temp
RUN powershell -Command \
    Invoke-WebRequest https://dl.influxdata.com/telegraf/releases/telegraf-1.12.6_windows_amd64.zip -OutFile telegraf.zip \
  ; powershell -Command Expand-Archive -Path telegraf.zip -DestinationPath C:\temp \
  ; Remove-Item -Path telegraf.zip \
  ; mkdir c:\telegraf \
  ; Move-Item -Path c:\temp\telegraf\telegraf.exe -Destination c:\telegraf

WORKDIR /telegraf
RUN powershell -Command \
    mkdir telegraf.d \
  ; .\telegraf.exe --service install --config C:\telegraf\telegraf.conf --config-directory C:\telegraf\telegraf.d
COPY telegraf.conf .
RUN powershell -Command \
    Start-Service telegraf
EXPOSE 9273

...
```

上述命令下载了 Telegraf 的最新版本，将其安装为 Windows 服务，并提供了之前步骤中的配置。

1.  使用标签 1.6.0 构建镜像，并像在之前的章节中一样将其推送到 Docker Hub。在我们的情况下，它将是`packtpubkubernetesonwindows/voting-application:1.6.0`。

Telegraf 配置可以通过将自定义 ConfigMap 挂载到容器中的`C:\telegraf\telegraf.d`目录来在容器运行时进行修改。这是 ConfigMaps 的一个完美用例。

现在，Docker 镜像已准备就绪，可以在投票应用程序的 Helm 图中使用。

# 部署一个可观察的投票应用程序版本

为了能够抓取容器中 Telegraf 公开的性能计数器，我们需要更新 Helm 图以包括 Docker 镜像的新标签，并更新用于抓取的 Pod 注释。您可以在以下位置找到准备好的 Helm 图：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter14/07_voting-application-telegraf-helm`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter14/07_voting-application-telegraf-helm)，或者按照以下步骤使用先前的版本：

1.  在 Helm 图的根目录中打开 PowerShell 窗口。

1.  在`Chart.yaml`文件中，将`appVersion`增加到与 Docker 镜像标签`1.6.0`相等。同时，将图表本身的版本增加到`0.3.0`。

1.  在`templates\service.yaml`文件中，为 Service 添加`annotations`，以便 Prometheus 可以开始在端口`9273`上抓取服务后面的所有 Pod：

```
apiVersion: v1
kind: Service
metadata:
  name: {{ include "voting-application.fullname" . }}
  ...
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "9273"
...
```

1.  更新`templates\deployment.yaml`文件，以便投票应用程序前端 Pod 在`9273`端口上公开 Telegraf 在`/metrics`端点处导出的数据：

```
apiVersion: apps/v1
kind: Deployment
...
spec:
  ...
  template:
    ...
    spec:
    ...
      containers:
        - name: {{ .Chart.Name }}-frontend
          ...
          ports:
            ...
            - name: telegraf
 containerPort: 9273
 protocol: TCP
          ...
```

1.  确保`dev-helm`命名空间存在。创建`dev-helm.yaml`清单文件：

```
kind: Namespace
apiVersion: v1
metadata:
  name: dev-helm
  labels:
    name: dev-helm
```

1.  使用`kubectl apply -f .\dev-helm.yaml`命令应用清单文件。

1.  Helm 图已准备就绪，可以在投票应用程序的 Helm 图的根目录中执行以下命令：

```
helm install voting-application . `
 --namespace dev-helm `
 --debug `
 --timeout 900s
```

或者，如果您已经在集群中安装了此图的先前版本，请使用相同的参数使用`helm upgrade`命令。

1.  等待部署完成；您可以使用`kubectl get pods -n dev-helm -w`命令在另一个 PowerShell 窗口中观察进度。

此时，投票应用程序的新版本已部署到集群中，并且 Prometheus 已经使用`kubernetes-service-endpoints`抓取作业来抓取 Pod。这在默认配置中已经定义。让我们验证一下是否一切正常：

1.  在网络浏览器中导航到投票应用程序的外部 IP，并使用网站创建一些流量，持续几分钟。

1.  在网络浏览器中打开 Prometheus 服务器的外部 IP，在 Graph 面板中打开，并将选项卡切换到 Graph。

1.  Telegraf 配置设置为输出所有带有`win_`前缀的指标。让我们查询其中一个指标，例如`win_aspnet_app_Requests_Failed`，这是 ASP.NET 应用程序中失败请求的计数器。使用`rate(win_aspnet_app_Requests_Failed{app_kubernetes_io_name="voting-application"}[5m])`查询，该查询为每个 Pod 分别提供了过去五分钟内投票应用程序失败请求的平均每秒速率：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/6e13ec99-9e84-49d2-828f-cbe91a6193ff.png)

现在，您可能想知道为什么我们在某个时间点看到失败请求数量突然增加-您很可能会在您的 Prometheus 中看到相同的情况。答案是在部署 Helm 图表后的几分钟内出现了失败的健康检查（就绪探针）。您可能还记得，SQL Server Helm 图表需要最多 10 分钟才能完全部署。这意味着在这段时间内，投票应用程序 Pod 的就绪探针将以 HTTP 500 状态代码失败。

计算`rate`和`irate`需要每个时间序列间隔至少两个数据点。这意味着您应该使用间隔值至少比抓取间隔大两倍。否则，您将在图表中看到缺失的数据。

您可以探索我们为每个 Pod 公开的其他性能计数器-Telegraf 的这种配置获得了大量的计数器，例如.NET CLR 中抛出的异常数量，.NET CLR 中的锁定数量（这对于检测重锁定场景可能非常有用！），.NET CLR 垃圾回收统计信息或 IIS 性能计数器。

在下一节中，我们将添加监控谜题的最后一部分：使用`prometheus-net` NuGet 包直接从.NET Framework 应用程序公开自己的指标。

# 使用 prometheus-net 监控.NET 应用程序

作为监控基础设施的一部分，您需要直接从应用程序中公开自定义指标，这些指标提供了对业务逻辑的额外仪表和见解。最流行的编程语言都有与 Prometheus 集成的绑定，对于 C#，提供与 Prometheus 集成的库之一是`prometheus-net`（[`github.com/prometheus-net/prometheus-net`](https://github.com/prometheus-net/prometheus-net)）。您可以将其用于经典的.NET Framework 和.NET Core，因为它针对的是.NET Standard 2.0。其功能包括以下内容：

+   导出计数器和仪表

+   测量操作持续时间，并创建摘要或直方图

+   跟踪正在进行的操作，并创建具有并发执行代码块数量的仪表

+   异常计数

此外，对于 ASP.NET Core 应用程序，您可以使用专用的中间件包（[`www.nuget.org/packages/prometheus-net.AspNetCore`](https://www.nuget.org/packages/prometheus-net.AspNetCore)）来导出 ASP.NET 指标。不幸的是，对于经典的 ASP.NET MVC，不支持此功能，但可以手动实现类似的功能。

# 安装 NuGet 包并添加指标

该库提供为 NuGet 包（[`www.nuget.org/packages/prometheus-net`](https://www.nuget.org/packages/prometheus-net)）。要在投票应用程序中启用`prometheus-net`，请按照以下步骤操作，或者您可以使用可在以下位置找到的源代码的准备版本：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter14/08_voting-application-prometheus-net`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter14/08_voting-application-prometheus-net)：

1.  在 Visual Studio 2019 中打开投票应用程序解决方案。

1.  右键单击 VotingApplication 项目，然后选择管理 NuGet 包....

1.  找到`prometheus-net`包并安装它。

1.  我们需要启动一个 HTTP 监听器来导出指标。在`Global.asax.cs`文件（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter14/08_voting-application-prometheus-net/Global.asax.cs`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter14/08_voting-application-prometheus-net/Global.asax.cs)）中，在`Application_Start`方法的开头，添加以下行：

```
var server = new MetricServer(port: 9274);
server.Start();
```

这将在所有网络接口的`/metrics`端口`9274`处公开指标。

1.  在运行在 IIS 上的应用程序内部使用自定义 HTTP 监听器需要添加网络 ACL 规则以允许 IIS AppPool 用户使用此端口。因此，我们需要扩展`Dockerfile.production`文件以包括以下命令，例如，在 Telegraf 安装后：

```
RUN "netsh http add urlacl url=http://+:9274/metrics user=\"IIS AppPool\DefaultAppPool\""
EXPOSE 9274
```

现在，该应用程序正在公开非常基本的.NET 性能计数器。我们想要添加一些自定义指标，这些指标将特定于我们的投票应用程序。例如，我们将添加两个指标：

+   **计数器**：这是自应用程序启动以来已添加到数据库的投票数。然后，我们可以使用计数器来，例如，计算每个时间间隔添加的平均投票数。

+   **直方图**：这是用于检索调查结果并对其进行总结的持续时间。

要做到这一点，请按照以下步骤进行：

1.  在`SurveyController`类（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter14/08_voting-application-prometheus-net/Controllers/SurveysController.cs`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter14/08_voting-application-prometheus-net/Controllers/SurveysController.cs)）中，定义两个指标，`DbAddedVotesCount`和`GetSurveyResultOperationDuration`，作为`static readonly`字段：

```
private static readonly Counter DbAddedVotesCount = Metrics.CreateCounter(
    "votingapplication_db_added_votes",
    "Number of votes added to the database.");

private static readonly Histogram GetSurveyResultOperationDuration = Metrics.CreateHistogram(
    "votingapplication_getsurveyresult_duration_seconds",
    "Histogram for duration of GetSurveyResult operation.",
    new HistogramConfiguration { Buckets = Histogram.ExponentialBuckets(0.001, 1.5, 20) });
```

1.  在`Vote`控制器操作中递增`DbAddedVotesCount`计数器，在将每个`Vote`添加到数据库后：

```
...
    this.voteLogManager.Append(vote);
    this.db.Votes.Add(vote);
    DbAddedVotesCount.Inc();
}
...
```

1.  测量获取调查结果的时间以创建直方图。在`Results`控制器操作中，将对`GetSurveyResult`的调用包装到`using`块中，并使用`GetSurveyResultOperationDuration`来测量时间：

```
SurveyResult result;
using (GetSurveyResultOperationDuration.NewTimer())
{
    result = this.GetSurveyResult(survey);
}

return this.View(result);
```

1.  在进行这些更改后，在指标导出端点，您将看到新的指标：

```
# HELP votingapplication_db_added_votes Number of votes added to the database.
# TYPE votingapplication_db_added_votes counter
votingapplication_db_added_votes 3
...
# HELP votingapplication_getsurveyresult_duration_seconds Histogram for duration of GetSurveyResult operation.
# TYPE votingapplication_getsurveyresult_duration_seconds histogram
votingapplication_getsurveyresult_duration_seconds_sum 0.5531466
votingapplication_getsurveyresult_duration_seconds_count 7
votingapplication_getsurveyresult_duration_seconds_bucket{le="0.005"} 0
votingapplication_getsurveyresult_duration_seconds_bucket{le="0.01"} 0
...
```

1.  构建一个新版本的 Docker 镜像，将其标记为`1.7.0`，并推送到 Docker Hub。我们将在下一节中使用`packtpubkubernetesonwindows/voting-application:1.7.0` Docker 镜像。

如您所见，添加导出自定义指标的功能非常简单和自解释——您无需对现有代码库进行重大更改！

现在，让我们部署应用程序的新版本并测试新的指标。

# 部署投票应用程序的新版本

我们必须以与上一节相似的方式修改 Helm 图表。必须更新 Docker 镜像并在服务的注释中注册新的抓取端口-由于 Prometheus 不支持在单个抓取作业中使用多个端口（[`github.com/prometheus/prometheus/issues/3756`](https://github.com/prometheus/prometheus/issues/3756)），我们需要添加第二个作业，该作业将使用新端口。您可以在以下位置找到准备好的 Helm 图表：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter14/09_voting-application-prometheus-net-helm`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter14/09_voting-application-prometheus-net-helm)，或者按照以下步骤使用先前的版本：

1.  在 Helm 图表的根目录中打开 PowerShell 窗口。

1.  在`Chart.yaml`文件中，将`appVersion`增加到与 Docker 镜像标签`1.7.0`相等。还要将图表的`version`增加到`0.4.0`。

1.  在`templates\service.yaml`文件中，为端口`9274`的服务添加一个新的自定义注释`prometheus.io/secondary-port`。我们将在新的抓取作业中使用此注释：

```
apiVersion: v1
kind: Service
metadata:
  name: {{ include "voting-application.fullname" . }}
  ...
  annotations:
    ...
    prometheus.io/secondary-port: "9274"
...
```

1.  更新`templates\deployment.yaml`文件，以便投票应用程序前端 Pod 在应用程序在`/metrics`端点处公开度量数据的端口`9274`。

```
apiVersion: apps/v1
kind: Deployment
...
spec:
  ...
  template:
    ...
    spec:
    ...
      containers:
        - name: {{ .Chart.Name }}-frontend
          ...
          ports:
            ...
            - name: app-metrics
 containerPort: 9274
 protocol: TCP
          ...
```

1.  Helm 图表已准备就绪。可以升级投票应用程序的 Helm 发布-在投票应用程序的 Helm 图表的根目录中执行以下命令：

```
helm upgrade voting-application . `
 --namespace dev-helm `
 --debug `
 --timeout 900s
```

1.  等待部署完成，您可以使用`kubectl get pods -n dev-helm -w`命令在另一个 PowerShell 窗口中观察进度。

最后一步是添加一个 Prometheus 抓取作业，该作业将处理`prometheus.io/secondary-port`注释。将来，使用多个端口进行抓取应该更容易，但目前，您必须为此目的添加多个作业：

1.  在 Prometheus Helm 图表的`helm-values_prometheus.yaml`文件（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter14/10_helm_prometheus-net/helm-values_prometheus.yaml`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter14/10_helm_prometheus-net/helm-values_prometheus.yaml)）中，添加另一个额外的抓取作业。这个作业的定义几乎与默认的`kubernetes-service-endpoints`完全相同，该默认作业位于[`github.com/helm/charts/blob/master/stable/prometheus/values.yaml`](https://github.com/helm/charts/blob/master/stable/prometheus/values.yaml)，但有额外的过滤：

```
   - job_name: kubernetes-service-endpoints-secondary-ports
     kubernetes_sd_configs:
     - role: endpoints
     relabel_configs:
     - action: keep
       regex: true
       source_labels:
       - __meta_kubernetes_service_annotation_prometheus_io_scrape
     - action: keep
 regex: (\d+)
 source_labels:
 - __meta_kubernetes_service_annotation_prometheus_io_secondary_port
     ...
     - action: replace
       regex: ([^:]+)(?::\d+)?;(\d+)
       replacement: $1:$2
       source_labels:
       - __address__
       - __meta_kubernetes_service_annotation_prometheus_io_secondary_port
       target_label: __address__     
```

以下操作将仅保留具有定义的`prometheus.io/secondary-port`注释并使用它来定义用于抓取的最终`__address__`的目标。

1.  升级 Prometheus 的 Helm 发布：

```
helm upgrade prometheus stable/prometheus -n monitoring --values .\helm-values_prometheus.yaml --debug
```

1.  升级完成后，唯一更新的资源是 ConfigMap，`prometheus-server`。在 Prometheus 重新加载配置之前，您需要等待一小段时间。

1.  在 Prometheus web UI 中，导航到状态和目标，并验证新端口的抓取是否正常工作；您应该看到`kubernetes-service-endpoints-secondary-ports`作业的绿色状态：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/62032637-3245-4cb8-b4c3-f7adf67b2af5.png)

1.  打开投票应用的 Web UI，并在几分钟内添加一些投票。

1.  在 Prometheus web UI 的 Graph 选项卡中，运行一个示例查询来验证解决方案是否有效。例如，使用`sum(votingapplication_db_added_votes)`来获取从所有 Pod 添加到数据库的投票总数：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/e3b783f9-ce68-4d56-ab53-40b0287fac5b.png)

我们的解决方案有效！通过这种方式，您可以导出您在应用程序代码中定义的任何指标，并创建更复杂的查询，用于监视和分析目的。

现在，是时候在 Grafana 中配置仪表板并添加一些警报了。

# 在 Grafana 中配置仪表板和警报

Prometheus 服务器的 Web UI 非常有限，在大多数情况下仅用于执行基本的即席查询和检查配置。要在 Prometheus 中创建更高级的数据可视化，可以使用 Grafana（[`grafana.com/`](https://grafana.com/)），这是一个支持多个数据库的开源分析和监控解决方案。在之前的部分中，我们已经使用 Helm 图表部署了 Grafana 和 Prometheus。

Grafana 提供了多种可视化监控数据的方式，从简单的**线**图和仪表到复杂的热图。您可以在官方文档中找到有关如何创建可视化的更多信息：[`grafana.com/docs/grafana/latest/`](https://grafana.com/docs/grafana/latest/)。对于我们的应用程序，我们将演示如何配置一个示例仪表板，其中包括以下可视化：

+   Windows 节点 CPU 使用率的折线图

+   IIS 在过去 5 分钟内处理的平均每秒请求数的仪表

+   显示在过去 5 分钟内添加到数据库的投票数量的折线图

+   用于可视化检索调查结果持续时间的直方图的热图

当然，这些图表将不足以完全监视您的应用程序，但我们想展示如何创建仪表板的一般原则。

# 添加可视化

首先，让我们创建仪表板，并为 Windows 节点的 CPU 使用率添加第一个可视化。请执行以下步骤：

1.  导航到 Grafana Web UI，并使用 Helm 图表发布中提供的凭据登录。默认用户为`admin`，密码为`P@ssword`。

1.  从侧面板中，单击+按钮，然后选择仪表板。

1.  单击“保存仪表板”按钮，并提供`voting application`作为名称。

1.  选择添加查询。

1.  在第一个指标中提供以下查询：`100 - (avg by (instance) (irate(wmi_cpu_time_total{mode="idle"}[2m])) * 100)`。此查询使用总 CPU 空闲时间的计数器计算了过去两分钟的平均 CPU 使用率。

1.  在图例中，提供`{{instance}}`以使用节点主机名作为标签。

1.  从左侧面板中选择可视化。对于 Y 轴，在单位中选择 Misc 并选择百分比（0-100）。

1.  从左侧面板中选择常规。将标题更改为`平均 CPU 使用率`。您的图表应显示 Windows 节点的 CPU 利用率：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/7a23e50d-3c25-4292-89c8-cd57a08a1a88.png)

下一步是创建仪表板，显示 IIS 在过去 5 分钟内处理的平均每秒请求数。按照以下步骤进行：

1.  返回仪表板视图，单击添加面板，然后选择添加查询。

1.  在第一个指标中提供以下查询：`sum((rate(win_aspnet_app_Requests_Total[5m]))) by (app_kubernetes_io_instance)`。此查询计算了每个 Pod 的 5 分钟间隔内请求的每秒速率，并通过 Kubernetes 应用程序全局汇总。

1.  从左侧面板中选择“可视化”。选择仪表板。

1.  在“显示”区域，选择 Calc 为 Last（非空），在“字段”区域，将单位更改为吞吐量 > 请求/秒（reqps）。

1.  从左侧面板中选择“常规”。将“标题”更改为“过去 5 分钟内的平均 IIS 请求次数”。您的仪表正在显示当前每秒的平均请求次数：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/dcb8f239-125b-4324-87c5-0c3f50480ae2.png)

我们将添加第三个可视化，显示过去五分钟内添加到数据库的投票数的折线图。请按照以下步骤操作：

1.  返回仪表板视图，点击“添加面板”，选择“添加查询”。

1.  在第一个指标中提供以下查询：`sum(irate(votingapplication_db_added_votes[5m])) by (app_kubernetes_io_instance) * 300`。该查询计算了每个 Pod 在 5 分钟间隔内投票数量的增加率，并通过 Kubernetes 应用程序全局汇总。我们需要乘以 `300`（5 分钟）因为 `irate` 计算的是每秒的速率。

1.  将图例格式设置为“过去 5 分钟内的投票数”。

1.  从左侧面板中选择“常规”。将“标题”更改为“过去 5 分钟内添加到数据库的投票数”。现在您的图应该如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/3ee5af6b-c88a-4b1b-8079-0569ed13003a.png)

最后，我们将添加最后一个可视化，即用于可视化检索调查结果持续时间直方图的热图。热图是可视化直方图随时间变化的最有效方式，最近，Grafana 扩展了对 Prometheus 直方图指标的热图的本机支持。执行以下步骤创建可视化：

1.  返回仪表板视图，点击“添加面板”，选择“添加查询”。

1.  在第一个指标中提供以下查询：`sum(increase(votingapplication_getsurveyresult_duration_seconds_bucket[2m])) by (le)`。该查询将转换我们的直方图数据——我们确定了最近两分钟内每个桶的绝对增长率，并用标签 `le` 汇总每个桶，这是桶的标识符（`le` 是 **小于或等于** 的缩写—Prometheus 直方图是累积的）。这样，我们就有了整个应用程序全局的桶，而不是单独的 Pod。

1.  将图例格式更改为 `{{le}}`，并将格式设置为 `热图`。

1.  从左侧面板中选择“可视化”。选择“热图”。

1.  在 Y 轴区域，对于单位，选择时间>秒（s），对于格式，选择时间序列桶。将小数设置为`1`以显示整洁的数字。将空间设置为`0`，将舍入设置为`2` - 我们的热图具有相对较多的桶，因此它将使显示更加平滑。

1.  在显示区域，打开显示图例和隐藏零。

1.  从左侧面板中选择常规。将标题更改为`获取调查结果持续时间的热图`。检查您的热图，特别是在多个浏览器选项卡中对主网页进行压力测试后！热图通常在暗色主题下看起来更好（您可以在全局的配置菜单中更改）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/e1008a8e-6d1b-4753-b83d-5429e1945e24.png)

您可以清楚地看到在每分钟约 300 次请求的压力测试期间，此操作的执行情况。

1.  最后，返回仪表板视图，保存所有更改，并按您的意愿重新排列可视化：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/a5bfd5a6-da09-47a0-af08-80ab5f6e7705.png)

在下一小节中，我们将展示如何在 Grafana 中配置电子邮件警报。

# 配置警报

Grafana 除了创建可视化和仪表板外，还能够定义警报规则并向多个渠道发送通知。您可以在官方文档中找到支持的通知渠道列表：[`grafana.com/docs/grafana/latest/alerting/notifications/`](https://grafana.com/docs/grafana/latest/alerting/notifications/)。警报与特定的可视化相关联，因此您首先需要为您的用例创建适当的可视化。我们将演示如何在节点上创建高 CPU 使用率的警报。

首先，我们需要配置一个电子邮件通知渠道，请按照以下步骤操作：

1.  Grafana 需要 SMTP 配置来发送电子邮件。获取您的电子邮件提供商的详细信息，并修改 Grafana Helm 图表值文件`helm-values_grafana.yaml`，以便其中包含节点：

```
grafana.ini:
  smtp:
    enabled: true
    host: <smtpAddressAndPort>  # For Gmail: smtp.gmail.com:587
    user: <smtpUser>
    password: <smtpPassword>
    skip_verify: true  # Needed for Gmail
    from_address: <emailAddress>
    from_name: <name>
```

请注意，如果您想使用 Gmail，如果启用了 2FA，则需要生成应用程序密码。

1.  升级 Grafana 的 Helm 版本：

```
helm upgrade grafana stable/grafana -n monitoring --values .\helm-values_grafana.yaml --debug
```

1.  升级完成后，转到 Grafana Web UI。从左侧面板中打开警报，并选择通知渠道。

1.  单击新通道。

1.  填写名称，选择电子邮件类型，并提供电子邮件地址。

1.  单击“发送测试”以测试您的 SMTP 配置是否正确。如果有任何问题，请检查 Grafana Pod 的日志。几分钟后，您应该会在收件箱中收到测试电子邮件。

当您确认您的通知渠道正常工作时，我们可以继续创建警报本身。我们希望在节点的平均 CPU 使用率超过 80％超过五分钟时收到警报。请按照以下步骤配置此类警报：

1.  打开我们的仪表板，选择平均 CPU 使用率可视化。从可视化菜单中，选择编辑。

1.  从左侧面板打开警报，然后单击创建警报。

1.  按照以下所示配置警报：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/11fe4ac2-3e68-4a9b-ab71-2ebed85a5874.png)

1.  选择您的通知渠道，并可选择自定义通知消息。

1.  保存仪表板。您会注意到仪表板上有一个心形图标，表示警报状态。

现在，我们需要通过创建一些负载来测试我们的规则。我们可以重用在前几章中创建的`StressCpu`操作。按照以下步骤执行测试：

1.  在您的网络浏览器中，导航至`http://<applicationExternalIp>/Home/StressCpu?value=100`，并重复此操作几次，以确保一些 Pod 开始足够地压力节点。

1.  检查仪表板。您会注意到健康状况仍然是绿色的，但指标已经处于红色区域：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/243aeff0-3922-46aa-ace8-69fea39d69cd.png)

1.  等待五分钟，从平均使用率在过去五分钟内超过 80％的时间点开始。您应该通过您的通知渠道收到一封电子邮件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/2c59c431-414c-4afd-95e8-d32fd01c49f7.png)

恭喜！您已成功为 Grafana 中的投票应用程序配置了仪表板，并测试了我们监控系统的警报功能。

# 摘要

在这一长章中，您学会了如何在 Kubernetes 上运行的 Windows 容器中设置监控。首先，我们看了可用的监控解决方案，并确定了哪些适合我们的 Windows 节点的用例——目前最好的选择是使用专用的 Prometheus 实例与 Grafana 一起。接下来，您学会了如何使用 WMI Exporter 和实验性的 Docker Engine 指标服务使 Windows 节点在硬件、操作系统和容器运行时方面可观察。我们已经展示了如何在 AKS Engine 集群上使用扩展安装和配置这些代理。

接下来的步骤是使用 Helm 图表部署 Prometheus 和 Grafana。您需要确保 Prometheus 抓取作业能够在 Windows 节点上发现新的指标端点。之后，我们专注于监控容器内部和 Windows 性能计数器-我们使用 Telegraf 公开了几个计数器，并配置了 Prometheus 对新端点的抓取。此外，您还学会了如何使用`prometheus-net`库直接从应用程序代码向 Prometheus 导出自定义指标。最后，作为锦上添花，我们向您展示了如何为投票应用程序在 Grafana 中配置示例仪表板，以及如何为 Windows 节点上的高 CPU 使用率启用电子邮件警报。

下一章将重点介绍灾难恢复和 Kubernetes 备份策略。

# 问题

1.  为什么可观测性是监控解决方案中的关键概念？

1.  您可以使用哪些组件来使用 Prometheus 监视 Windows 节点？

1.  何时应该使用 Prometheus Operator？

1.  为什么您需要为 Windows 节点在 Prometheus 中配置额外的抓取作业？

1.  如何将 Windows 容器中的任何 Windows 性能计数器导出到 Prometheus？

1.  使用`prometheus-net`库的好处是什么？

1.  如何在 Prometheus 中为单个服务配置多个端口进行抓取？

1.  使用热图可视化 Prometheus 直方图有哪些好处？

您可以在本书的*评估*中找到这些问题的答案。

# 进一步阅读

+   有关 Kubernetes 功能和一般集群监控的更多信息，请参考以下 Packt 图书：

+   *完整的 Kubernetes 指南*（[`www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide`](https://www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide)）。

+   *开始使用 Kubernetes-第三版*（[`www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition`](https://www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition)）。

+   *面向开发人员的 Kubernetes*（[`www.packtpub.com/virtualization-and-cloud/kubernetes-developers`](https://www.packtpub.com/virtualization-and-cloud/kubernetes-developers)）。

+   您可以在以下 Packt 图书中了解更多关于 Prometheus 的信息：

+   《使用 Prometheus 进行实时基础设施监控》（[`www.packtpub.com/virtualization-and-cloud/hands-infrastructure-monitoring-prometheus`](https://www.packtpub.com/virtualization-and-cloud/hands-infrastructure-monitoring-prometheus)）。
