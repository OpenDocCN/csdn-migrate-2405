# Helm 学习手册（四）

> 原文：[`zh.annas-archive.org/md5/AB61831A08B0763334412D2ABCB093BB`](https://zh.annas-archive.org/md5/AB61831A08B0763334412D2ABCB093BB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 Helm 与操作员框架

使用 Helm 的一个优势是能够同步本地和实时状态。使用 Helm，本地状态是通过值文件进行管理的，当使用`install`或`upgrade`命令提供这些值时，将这些值应用于 Kubernetes 集群中的实时状态以进行同步。在之前的章节中，当希望对应用程序进行更改时，通过调用这些命令来执行此操作。

另一种同步这些更改的方法是在集群内创建一个应用程序，定期检查期望状态是否与环境中的当前配置匹配。如果状态不匹配，应用程序可以自动修改环境以匹配期望的状态。这种应用程序被称为 Kubernetes 操作员。在本章中，我们将创建一个基于 Helm 的操作员，以确保本地定义的状态始终与集群的实时状态匹配。如果不匹配，操作员将执行适当的 Helm 命令来更新环境。

本章将涵盖以下主题：

+   理解 Kubernetes 操作员

+   创建一个 Helm 操作员

+   使用 Helm 来管理操作员和自定义资源（CRs）

+   清理您的 Kubernetes 环境

# 技术要求

对于本章，您需要在本地机器上安装以下技术：

+   `minikube`

+   `helm`

+   `kubectl`

除了这些工具之外，您还应该在 GitHub 上找到 Packt 存储库，其中包含与示例相关的资源，网址为[`github.com/PacktPublishing/-Learn-Helm`](https://github.com/PacktPublishing/-Learn-Helm)。本存储库将在本章中被引用。

# 理解 Kubernetes 操作员

自动化是 Kubernetes 平台的核心。正如在*第一章*中所介绍的，*了解 Kubernetes 和 Helm*，Kubernetes 资源可以通过运行`kubectl`命令隐式管理，也可以通过应用 YAML 格式的表示来声明性地管理。一旦使用 Kubernetes 命令行界面（CLI）应用了资源，Kubernetes 的基本原则之一是将集群中资源的当前状态与期望状态匹配，这个过程称为**控制循环**。这种持续的、非终止的监视集群状态的模式是通过控制器实现的。Kubernetes 包括许多本地于平台的控制器，例如拦截对 Kubernetes 应用程序编程接口（API）的请求的准入控制器，以及管理运行的 Pod 副本数量的复制控制器。

随着对 Kubernetes 的兴趣开始增长，提供用户扩展基础平台功能的能力，以及提供更多关于管理应用程序生命周期的智能的组合，导致了几个重要概念的产生，这些概念定义了 Kubernetes 开发的第二波。首先，引入了自定义资源定义（CRD），使用户能够扩展默认的 Kubernetes API，这是与 Kubernetes 平台交互的机制，以创建和注册新类型的资源。注册新的 CRD 会在 Kubernetes API 服务器上创建一个新的 RESTful 资源路径。因此，类似于您可以使用 Kubernetes CLI 执行`kubectl get pods`来检索所有 Pod 对象，例如，为名为**Guestbook**的对象类型注册一个新的 CRD，允许调用`kubectl get guestbook`来查看先前创建的所有 Guestbook 对象。有了这种新的能力，开发人员现在可以创建自己的控制器来监视这些类型的 CR，以管理可以通过 CRD 描述的应用程序的生命周期。

第二个主要趋势是 Kubernetes 部署的应用程序类型的进展。与小型简单的应用程序不同，更复杂和有状态的应用程序被部署得更频繁。这些高级应用程序通常需要更高级的管理和维护水平，例如处理多个组件的部署，以及围绕“第二天”活动的考虑，如备份和恢复。这些任务超出了 Kubernetes 中典型控制器的范围，因为必须嵌入与其管理的应用程序相关的深层知识。使用 CR 来管理应用程序及其组件的这种模式被称为**Operator**模式。由软件公司 CoreOS 在 2016 年首次提出，Operators 旨在捕获人类操作员在管理应用程序生命周期方面的知识。Operators 被打包为普通的容器化应用程序——部署在 pod 中——对 CR 的 API 更改做出反应。

Operators 通常使用称为 Operator Framework 的工具包编写，并基于以下三种不同的技术之一：

+   Go

+   Ansible

+   Helm

基于 Go 的 Operators 利用 Go 编程语言实现控制循环逻辑。基于 Ansible 的 Operators 利用 Ansible CLI 工具和 Ansible playbooks。Ansible 是一种自动化工具，其逻辑是在称为 playbooks 的 YAML 文件中编写的。

在本章中，我们将专注于基于 Helm 的 Operators。Helm Operators 将其控制循环逻辑基于 Helm 图表和 Helm CLI 提供的一部分功能。因此，它们代表了 Helm 用户实现其 Operators 的一种简单方式。

了解了 Operators，让我们使用 Helm 创建自己的 operator。

# 创建一个 Helm operator

在本节中，我们将编写一个基于 Helm 的 operator，用于安装*第五章*中创建的 Guestbook Helm 图表，*构建您的第一个 Helm 图表*。该图表可以在 Pack[t 存储库的`guestbook/`文件夹下找到（https://github.com/PacktPublishing/-Learn-Helm/tree/master/helm-charts/ch](https://github.com/PacktPublishing/-Learn-Helm/tree/master/helm-charts/charts/guestbook)arts/guestbook）。

操作员是作为一个包含控制循环逻辑以维护应用程序的容器镜像构建的。下图演示了访客留言簿操作员部署后的功能：

![图 8.1 - 访客留言簿操作员工作流](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_8.1.jpg)

图 8.1 - 访客留言簿操作员工作流

访客留言簿操作员将不断监视访客留言簿 CR 的更改。当创建访客留言簿 CR 时，访客留言簿操作员将安装您在*第五章*中创建的访客留言簿图表，*构建您的第一个 Helm 图表*。相反，如果删除了访客留言簿 CR，访客留言簿操作员将删除访客留言簿 Helm 图表。

了解访客留言簿操作员的功能后，让我们设置一个可以构建和部署操作员的环境。

## 设置环境

首先，由于操作员将部署到 Kubernetes，您应该通过运行以下命令来启动 Minikube 环境：

```
$ minikube start
```

启动 Minikube 后，创建一个名为`chapter8`的命名空间，如下所示：

```
$ kubectl create ns chapter8
```

由于访客留言簿操作员是作为一个容器镜像构建的，您需要创建一个可以存储它以便以后引用的镜像存储库。为了存储这个镜像，我们将在 Quay（quay.io）中创建一个新的存储库，这是一个公共容器注册表（如果您在其他地方有帐户，那也可以）。我们还将准备一个本地开发环境，其中包含构建操作员镜像所需的必要工具。

让我们从在 Quay 中创建一个新的镜像存储库开始。

### 创建 Quay 存储库

在 Quay 中创建一个新的存储库需要您拥有一个 Quay 帐户。按照以下步骤创建一个 Quay 帐户：[nt:](https://quay.io/signin/)

1.  [在浏览器中导航到 https:/](https://quay.io/signin/)/quay.io/signin/。屏幕会提示您输入 Quay 凭据，如下截图所示：![图 8.2 - 红帽 Quay 登录页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_8.2.jpg)

图 8.2 - 红帽 Quay 登录页面

1.  在页面底部，单击**创建帐户**链接。屏幕会提示您使用一组对话框来创建一个新的 Quay 帐户，如下截图所示：![图 8.3 - 红帽 Quay 创建新帐户页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_8.3.jpg)

图 8.3 - 红帽 Quay**创建新帐户**页面

1.  输入您想要的凭据，然后选择**创建免费帐户**。

1.  您很快将收到一封电子邮件确认。单击确认电子邮件中的链接以验证您的帐户并继续使用新帐户的 Quay。

创建了新的 Quay 帐户后，您可以继续为 operator 图像创建新的图像存储库。

要创建新的图像存储库，请在 Quay 页面右上角选择**+**加号图标，然后选择**新存储库**，如下截图所示：

![图 8.4 - 选择“新存储库”以创建新的图像存储库](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_8.4.jpg)

图 8.4 - 选择“新存储库”以创建新的图像存储库

1.  然后，您将被带到**创建新存储库**页面，在那里您应该输入以下细节：

对于**存储库名称**，输入`guestbook-operator`。

选择**Public**单选按钮，表示对存储库的无身份验证访问。此更改将简化 Kubernetes 访问图像的方式。

其余选项可以保持默认值。完成后，**创建新存储库**页面应该会出现，如下截图所示：

![图 8.5 - Quay 中的“创建新存储库”页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_8.5.jpg)

图 8.5 - Quay 中的“创建新存储库”页面

1.  选择**创建公共存储库**按钮以创建 Quay 存储库。

现在已经创建了一个存储库来存储 Guestbook Operator 图像，让我们准备一个环境，其中包含构建 Helm operator 所需的工具。

### 准备本地开发环境

要创建 Helm operator，您至少需要以下 CLI 工具：

+   `operator-sdk`

+   `docker`，`podman`或`buildah`

`operator-sdk` CLI 是用于帮助开发 Kubernetes Operators 的工具包。它包含简化 operator 开发过程的内在逻辑。在幕后，`operator-sdk`需要一个容器管理工具，它可以用来构建 operator 图像。`operator-sdk` CLI 支持`docker`，`podman`和`buildah`作为底层容器管理工具。

要安装`operator-sdk` CLI，您可以从它们的[GitHub 存储库 https://github.com/operator-framework/](https://github.com/operator-framework/operator-sdk/releases)operator-sdk/releases 下载一个版本。但是，安装`docker`，`podman`或`buildah`的过程可能会因操作系统而异；更不用说，Windows 用户将无法原生地使用`operator-sdk`工具包。

幸运的是，Minikube 虚拟机（VM）可以作为开发人员的工作环境，因为它是一个 Linux VM，并且还包含 Docker CLI，适用于许多不同操作系统。在本节中，我们将在 Minikube VM 上安装`operator-sdk`，并将使用此环境来创建 operator。请注意，虽然提供的步骤旨在在 VM 中运行，但大多数步骤也适用于所有 Linux 和 Mac 机器。

按照以下步骤在 Minikube VM 上安装`operator-sdk`：

1.  通过运行`minikube ssh`命令来访问 VM，如下所示：

```
$ minikube ssh
```

1.  一旦进入 VM，您需要下载`operator-sdk` CLI。这可以通过使用`curl`命令来完成。请注意，写作时使用的`operator-sdk`版本是`0.15.2`版本。

要下载此版本的`operator-sdk` CLI，请运行以下命令：

```
$ cu**rl -o operator-sdk -L https://github.com/operator-framework/operator-sdk/releases/download/v0.15.2/operator-sdk-v0**.15.2-x86_64-linux-gnu 
```

1.  下载后，您需要更改`operator-sdk`二进制文件的权限为用户可执行。运行`chmod`命令进行此修改，如下所示：

```
$ chmod u+x operator-sdk
```

1.  接下来，将`operator-sdk`二进制文件移动到 VM 的`PATH`变量管理的位置，例如`/usr/bin`。因为此操作需要 root 权限，您需要使用`sudo`运行`mv`命令，如下所示：

```
$ sudo mv operator-sdk /usr/bin
```

1.  最后，通过运行`operator-sdk version`命令来验证您的`operator-sdk`安装，如下所示：

```
$ operator-sdk version
operator-sdk version: 'v0.15.2', commit: 'ffaf278993c8fcb00c6f527c9f20091eb8dd3352', go version: 'go1.13.3 linux/amd64'
```

如果此命令执行没有错误，那么您已成功安装了`operator-sdk` CLI。

1.  作为一个额外的步骤，您还应该在 Minikube VM 中克隆 Packt 存储库，因为我们将稍后利用`guestbook` Helm 图表来构建 Helm operator。在 VM 中运行以下命令来克隆存储库：](https://github.com/PacktPublishing/-Learn-Helm.git)

```
$ git clone https://github.com/PacktPub**lishing/-Learn-Helm.git Learn-Helm
```

现在您已经有了 Quay 镜像存储库和从 Minikube VM 创建的本地开发环境，让我们开始编写 Guestbook Operator。请注意，operator 代码的示例位于 Packt 存储库的 https://github.com/PacktPublishing/-Learn-Helm/tree/master/guestbook-operator 位置。

## 搭建 operator 文件结构

与 Helm 图表本身类似，由`operator-sdk` CLI 构建的 Helm Operators 具有必须遵守的特定文件结构。文件结构在下表中进行了解释：

![图 8.6 - 文件结构解释](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_8.6.jpg)

图 8.6 - 文件结构解释

使用`operator-sdk new`命令可以轻松创建操作员文件结构。在您的 Minikube VM 中，执行以下命令来创建 Guestbook Operator 的脚手架：

```
$ operator-sdk new guestbook-operator --type helm --kind Guestbook --helm-chart Learn-Helm/helm-charts/charts/guestbook
INFO[0000] Creating new Helm operator 'guestbook-operator'. 
INFO[0003] Created helm-charts/guestbook       
WARN[0003] Using default RBAC rules: failed to get Kubernetes config: could not locate a kubeconfig 
INFO[0003] Created build/Dockerfile                     
INFO[0003] Created watches.yaml                         
INFO[0003] Created deploy/service_account.yaml          
INFO[0003] Created deploy/role.yaml                     
INFO[0003] Created deploy/role_binding.yaml             
INFO[0003] Created deploy/operator.yaml                 
INFO[0003] Created deploy/crds/charts.helm.k8s.io_v1alpha1_guestbook_cr.yaml 
INFO[0003] Generated CustomResourceDefinition manifests. 
INFO[0003] Project creation complete.
```

`operator-sdk new`命令创建了一个名为`guestbook-operator`的本地目录，其中包含操作员内容。指定应使用`--type`标志创建 Helm 操作员，以及`Guestbook`作为 CR 的名称。

最后，`--helm-chart`标志指示`operator-sdk` CLI 将源 Guestbook 图表复制到操作员目录。

成功创建了 Guestbook 操作员的脚手架，让我们构建操作员并将其推送到您的 Quay 注册表。

## 构建操作员并将其推送到 Quay

`operator-sdk` CLI 提供了一个`operator-sdk build`命令，可以轻松构建操作员图像。此命令旨在针对操作员的顶级目录运行，并将通过引用位于操作员`build/`文件夹下的 Dockerfile 来构建图像。

在您的 Minikube VM 中，运行`operator-sdk build`命令，将您的 Quay 用户名替换为指定位置，如下所示：

```
$ cd guestbook-operator
$ operator-sdk build quay.io/$QUAY_USERNAME/guestbook-operator
```

如果构建成功，您将收到以下消息：

```
INFO[0092] Operator build complete.
```

由于 Minikube VM 安装了 Docker，`operator-sdk` CLI 在后台使用 Docker 构建图像。您可以运行`docker images`命令来验证图像是否已构建，如下所示：

```
$ docker images
```

操作员图像在本地构建后，必须将其推送到图像注册表，以便可以从 Kubernetes 中拉取。为了使用 Docker 将图像推送到注册表，您必须首先对目标注册表进行身份验证。使用`docker login`命令登录到 Quay，如下面的代码片段所示：

```
$ docker login quay.io --username $QUAY_USERNAME --password $QUAY_PASSWORD
```

登录到 Quay 后，使用`docker push`命令将操作员图像推送到 Quay 注册表，就像这样：

```
$ docker push quay.io/$QUAY_USERNAME/guestbook-operator
```

推送完成后，返回到您在*创建 Quay 存储库*部分创建的`guestbook-operator`存储库。您应该能够在**存储库标签**部分看到一个新的标签发布，如下面的屏幕截图所示：

![图 8.7 – 应将新标签推送到您的 Quay 注册表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_8.7.jpg)

图 8.7 – 应将新标签推送到您的 Quay 注册表

现在您的操作员已经推送到容器注册表，让我们继续通过将操作员部署到您的 Kubernetes 环境。

## 部署 Guestbook 操作员

在搭建 Guestbook Operator 时，`operator-sdk` CLI 还创建了一个名为`deploy`的文件夹，并生成了部署操作员所需的文件。

以下是`deploy`文件夹中的内容所示的文件结构：

```
deploy/
  crds/
    charts.helm.k8s.io_guestbooks_crd.yaml
    charts.helm.k8s.io_v1alpha1_guestbook_cr.yaml
  operator.yaml
  role_binding.yaml
  role.yaml
  service_account.yaml
```

`crds/`文件夹包含创建 Guestbook CRD 所需的 YAML 资源（`charts.helm.k8s.io_guestbooks_crd.yaml`）。此文件用于在 Kubernetes 中注册新的 Guestbook API 端点。此外，`crds/`文件夹包含一个示例 Guestbook CR 应用程序（`charts.helm.k8s.io_v1alpha1_guestbook_cr.yaml`）。创建此文件将触发操作员安装 Guestbook Helm 图表。

请查看 CR 的内容，以熟悉所定义属性的类型，如下所示：

```
$ cat guestbook-operator/deploy/crds/charts.helm.k8s.io_v1alpha1_guestbook_cr.yaml
```

以下代码块中提供了输出的片段：

![图 8.8 - Guestbook CR 的片段](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_8.8.jpg)

图 8.8 - Guestbook CR 的片段

`spec`部分中的每个条目都指向 Guestbook 图表的`values.yaml`文件。`operator-sdk`工具自动使用此文件中包含的每个默认值创建了此示例 CR。在应用此 CR 之前，可以添加或修改其他条目，以覆盖 Guestbook 图表的其他值。这些值在运行时由操作员使用，以相应地部署 Guestbook 应用程序。

`deploy/operator.yaml`文件定义了实际的操作员本身，并包含一个简单的部署资源。我们将很快返回到这个文件的内容。

`role_binding.yaml`、`role.yaml`和`service_account.yaml`文件是为了为操作员提供必要的权限，以便监视 Guestbook CR 并将 Guestbook Helm 图表安装到 Kubernetes 中。它通过在`service_account.yaml`文件中定义的服务帐户进行身份验证，然后执行这些操作。一旦经过身份验证，操作员将根据`role.yaml`和`role_binding.yaml`资源获得授权。`role.yaml`文件列出了描述操作员被允许执行的确切资源和操作的精细权限。`role_binding.yaml`文件将角色绑定到操作员的服务帐户。

了解操作员`deploy/`文件夹下创建的每个资源后，请按照以下步骤部署您的 Guestbook 操作员：

1.  不幸的是，Minikube VM 不包含`Kubectl`，所以如果您仍然通过命令行连接到 VM，您必须首先退出到您的本地系统，通过运行以下命令：

```
$ exit
```

1.  早些时候使用`operator-sdk`创建的资源也位于 Packt 存储库的`guestbook-operator/`文件夹下。如果您之前没有克隆过这个存储库，请使用以下命令现在克隆它：

```
$ git clone https://github.com/PacktPublishing/-Learn-Helm.git Learn-Helm
```

作为一个快速的旁注，需要注意的是，Packt 存储库中唯一修改自 Minikube VM 中创建的资源的资源是`role.yaml`文件。`operator-sdk` CLI 基于包含在 guestbook Helm 图表中的模板文件生成了一个简单的`role.yaml`文件。但是，如果您能回忆起来，guestbook 图表包含了一些资源，只有在条件值基础上才会包含这些资源。这些资源是`Job`和`PersistentVolumeClaim`挂钩资源，只有在启用持久存储时才会包含。其中一个示例显示在`PersistentVolumeClaim`模板中，如下面的代码片段所示：

```
{{- if .Values.redis.master.persistence.enabled }}
apiVersion: v1
kind: PersistentVolumeClaim
```

`operator-sdk` CLI 没有自动为`Jobs`和`PersistentVolumeClaims`创建**基于角色的访问控制**（**RBAC**）规则，因为它不知道是否应该包含此模板。

因此，作者已将这些规则添加到位于 https://github.com/PacktPublishing/-Learn-Helm/blob/master/guestbook-operator/deploy/role.yaml#L81-L104 的`role.yaml`文件中。

1.  Guestbook 操作员将依赖于一个新的 API 端点。通过在`guestbook-operator/deploy/crds`文件夹下应用 CRD 来创建此端点，如下所示：

```
$ kubectl apply -f guestbook-operator/deploy/crds/charts.helm.k8s.io_guestbooks_crd.yaml
```

我们将在稍后使用该文件夹下的第二个文件（CR）来部署 Guestbook 应用程序。

1.  接下来，您需要修改`guestbook-operator/deploy/operator.yaml`文件，以指定您之前构建的操作员图像。您会注意到在这个文件中有以下代码行：

```
# Replace this with the built image name
image: REPLACE_IMAGE
```

将`REPLACE_IMAGE`文本替换为您的操作员图像的位置。此值应类似于`quay.io/$QUAY_USERNAME/guestbook-operator`。

1.  一旦您应用了 CRD 并更新了您的`operator.yaml`文件，您可以通过运行以下命令来继续应用`guestbook-operator/deploy/`文件夹中的每个资源：

```
$ kubectl apply -f guestbook-operator/deploy -n chapter8
```

1.  通过对`chapter8`命名空间中的 Pods 运行观察，等待操作员报告`1/1`就绪状态，就像这样：

```
$ kubectl get pods -n chapter8 -w
```

现在 Guestbook operator 已部署，让我们使用它来安装 Guestbook Helm chart。

## 部署 Guestbook 应用程序

当使用 Helm 作为独立的 CLI 工具时，您可以通过运行`helm install`命令来安装 Helm chart。使用 Helm operator，您可以通过创建 CR 来安装 Helm chart。通过创建位于`guestbook-operator/deploy/crds/`文件夹下的提供的 CR 来安装 Guestbook Helm chart，如下面的代码片段所示：

```
$ kubectl apply -f guestbook-operator/deploy/crds/charts.helm.k8s.io_v1alpha1_guestbook_cr.yaml -n chapter8
```

对`chapter8`命名空间中的 Pod 运行另一个`watch`命令，如下面的代码片段所示，您应该能够看到 Guestbook 和 Redis Pods 因 Helm chart 安装而启动：

```
$ kubectl get pods -n chapter8 -w
```

以下代码块描述了每个 Pod 处于`READY`状态：

```
NAME                                  READY   STATUS    RESTARTS
example-guestbook-65bc5fdc55-jvkdz    1/1     Running   0
guestbook-operator-6fddc8d7cb-94mzp   1/1     Running   0
redis-master-0                        1/1     Running   0
redis-slave-0                         1/1     Running   0
redis-slave-1                         1/1     Running   0
```

当您创建 Guestbook CR 时，操作员会执行`helm install`命令来安装 Guestbook chart。您可以通过运行`helm list`来确认已创建的发布，就像这样：

```
$ helm list -n chapter8
NAME             	NAMESPACE	REVISION	UPDATED       
example-guestbook	chapter8 	1       	2020-02-24
```

通过修改`example-guestbook` CR 来执行发布的升级。修改您的`guestbook-operator/deploy/crds/charts.helm.k8s.io_v1alpha1_guestbook_cr.yaml`文件，将副本数从`1`更改为`2`，就像这样：

```
replicaCount: 2
```

在更新了`replicaCount`值之后应用更改，如下所示：

```
$ kubectl apply -f guestbook-operator/deploy/crds/charts.helm.k8s.io_v1alpha1_guestbook_cr.yaml -n chapter8
```

修改 Guestbook CR 将触发针对`example-guestbook`发布的`helm upgrade`命令。正如您可能还记得*第五章*中所述，*构建您的第一个 Helm Chart*，Guestbook Helm chart 的升级钩子将启动对 Redis 数据库的备份。如果您在修改 CR 后对`chapter8`命名空间中的 Pod 运行`watch`，您将注意到一个备份`Job`开始，并且一旦备份完成，您将看到两个 Guestbook Pods 中的一个终止。您还将从以下代码片段中的`helm list`命令中注意到`example-guestbook`发布的修订号已增加到`2`：

```
$ helm list -n chapter8
NAME             	NAMESPACE	REVISION	UPDATED       
example-guestbook	chapter8 	2       	2020-02-24
```

尽管修订号已增加到`2`，但截至撰写本文时，基于 Helm 的 Operators 的一个限制是您无法像使用 CLI 那样发起回滚到先前的修订。如果您尝试对`example-guestbook`发布运行`helm history`，您还将注意到只有第二个修订在发布历史中，如下面的代码片段所示：

```
$ helm history example-guestbook -n chapter8
REVISION	UPDATED                 	STATUS        
2       	Tue Feb 25 04:36:10 2020	deployed
```

这是使用 Helm CLI 和使用基于 Helm 的 operator 之间的重要区别。由于不保留发布历史记录，基于 Helm 的 operator 不允许执行显式回滚。但是，如果升级失败，将运行`helm rollback`命令。在这种情况下，将执行回滚钩子，试图回滚到尝试的升级。

尽管基于 Helm 的 operator 不保留发布历史记录，但它在同步应用程序的期望状态和实际状态方面表现出色。这是因为 operator 不断监视 Kubernetes 环境的状态，并确保应用程序始终配置为与 CR 上指定的配置匹配。换句话说，如果修改了 Guestbook 应用程序的资源之一，operator 将立即恢复更改，使其与 CR 上定义的规范匹配。您可以通过修改 Guestbook 资源之一上的字段来看到这一点。

例如，我们将直接将 Guestbook 部署的副本计数从`2`更改为`3`，并观察 operator 自动将其恢复为`2`个副本，以重新同步 CR 中定义的期望状态。

执行以下`kubectl patch`命令，将 Guestbook 部署的副本计数从`2`更改为`3`：

```
$ kubectl patch deployment example-guestbook -p '{'spec':{'replicas':3}}' -n chapter8
```

通常，这只会添加一个额外的 Guestbook 应用程序副本。但是，因为 Guestbook CR 当前仅定义了`2`个副本，所以 operator 会快速将副本计数更改回`2`，并终止创建的额外 Pod。如果您实际上想将副本计数增加到`3`，则必须更新 Guestbook CR 上的`replicaCount`值。该过程的优势在于确保期望状态与集群的实际状态匹配。

使用基于 Helm 的 operator 卸载 Guestbook 应用程序就像删除 CR 一样简单。删除`example-guestbook` CR 以卸载发布，就像这样：

```
$ kubectl delete -f guestbook-operator/deploy/crds/charts.helm.k8s.io_v1alpha1_guestbook_cr.yaml -n chapter8
```

这将删除`example-guestbook`发布以及所有相关资源。

您还可以删除 Guestbook Operator 及其资源，因为我们在下一节中将不再需要它们。您可以通过运行以下命令来执行此操作：

```
$ kubectl delete -f guestbook-operator/deploy/ -n chapter8
```

一般来说，您应该始终确保在删除运算符之前先删除 CR。当您删除 CR 时，运算符会执行`helm uninstall`命令来删除您的发布。如果您意外地先删除了运算符，您将不得不在命令行上手动运行`helm uninstall`。

在本节中，您创建了一个 Helm 运算符，并学习了如何使用基于运算符的方法部署应用程序。在下一节中，我们将继续讨论运算符，探讨如何使用 Helm 来管理它们。

# 使用 Helm 管理运算符和 CRs

在前一节中，您首先通过创建位于`guestbook-operator/deploy/crds/`文件夹下的 CRD 来安装了 Guestbook 运算符。接下来，您创建了位于`guestbook-operator/deploy/`文件夹下的运算符资源。最后，您创建了 CR 来部署 Guestbook 应用程序。这些任务都是使用 Kubectl CLI 执行的，但也可以使用 Helm 图表来提供更灵活和可重复的解决方案来安装和管理运算符。

Helm 允许您在 Helm 图表中提供一个名为`crds/`的特殊目录，用于在安装图表时创建 CRDs。Helm 会在`templates/`文件夹下定义的任何其他资源之前创建 CRDs，使得安装依赖于 CRDs 存在的应用程序（如运算符）更加简单。

以下文件结构描述了一个 Helm 图表，可用于安装 Guestbook 运算符：

```
guestbook-operator/
  Chart.yaml
  crds/
    charts.helm.k8s.io_guestbooks_crd.yaml
  templates/
    operator.yaml
    role_binding.yaml
    role.yaml
    Service_account.yaml
  values.yaml
```

安装此 Helm 图表时，首先会安装 Guestbook CRD。如果 CRD 已经存在于集群中，它将跳过 CRD 的创建，而只会创建模板资源。请注意，虽然 CRDs 可以方便地包含在 Helm 图表中，但存在一些限制。首先，Helm 图表中的 CRDs 不能包含任何 Go 模板，因此 CRDs 无法像典型资源那样受益于参数化。CRDs 也永远无法升级、回滚或删除。因此，如果需要执行这些操作，用户必须小心地手动修改或删除 CRDs。最后，如前所述安装此类图表将需要集群管理员权限，这是 Kubernetes 中允许的最高权限，因为图表至少包含一个 CRD 资源。

前面描述的 Helm chart 可以被集群管理员使用，以便轻松安装 Guestbook operator。然而，这只是方程的一半，因为最终用户仍然必须创建 CRs 来部署 Guestbook 应用程序。幸运的是，operator 的最终用户也可以利用 Helm，创建一个包装 Guestbook CR 的 Helm chart。

这样的 Helm chart 的示例布局显示在以下文件结构中：

```
guestbook-cr
  Chart.yaml
  templates/
    guestbook.yaml
  values.yaml
```

前面的示例包括一个名为`guestbook.yaml`的模板。这个模板可以包含最初由`operator-sdk` CLI 生成的 Guestbook CR，名称为`charts.helm.k8s.io_v1alpha1_guestbook_cr.yaml`。与 CRDs 不同，`templates/`文件夹下的 CRs 受益于 Go 模板和生命周期管理，就像所有其他资源一样。当 CR 包含基于用户提供的值有条件地包含的复杂字段，或者当同一个发布中必须包含多个不同的 CRs 时，这种方法提供了最大的价值。通过这种方法，您还可以管理 CRs 的生命周期并保持修订历史。

现在您已经了解了如何创建 Helm operator 以及如何使用 Helm 来帮助管理 Operators，可以在下一节中自由地清理您的 Kubernetes 环境。

# 清理您的 Kubernetes 环境

首先，运行以下命令来删除您的 Guestbook CRD：

```
$ kubectl delete crd guestbooks.charts.helm.k8s.io
```

在继续下一个清理步骤之前，请注意，在*问题*部分后面提出的一个问题将挑战您编写自己的 Helm charts 来实现*使用 Helm 管理 Operators 和 CRs*部分讨论的图表设计。您可能希望推迟这些步骤来测试您的实现。

要继续清理工作，请运行以下命令来删除您的`chapter8`命名空间：

```
$ kubectl delete ns chapter8
```

最后，运行`minikube stop`命令来停止您的 Minikube 虚拟机。

# 摘要

operator 对于确保期望状态始终与实际状态匹配非常重要。这样的功能允许用户更轻松地维护资源配置的真实来源。用户可以利用基于 Helm 的 operator 来提供这种类型的资源协调，并且很容易上手，因为它使用 Helm 图表作为部署机制。当创建 CR 时，Helm operator 将安装相关的 Helm 图表以创建新的发布。当修改 CR 时，将执行后续升级，并且在删除 CR 时将卸载发布。

为了管理 operator，集群管理员可以创建一个单独的 Helm 图表，用于创建 operator 的资源和 CRDs。最终用户也可以创建一个单独的 Helm 图表，用于创建 operator 的 CRs，以及其他可能相关的任何资源。

在下一章中，我们将讨论 Helm 生态系统中安全性的最佳实践和主题。

# 进一步阅读

有关 Kubernetes 资源的更多信息，您可以查看以下链接：

+   要发现更多由社区开发的 Operators，请查阅此存储库：[`github.com/operator-framework/awesome-operators`](https://github.com/operator-framework/awesome-operators)。

+   您可以从 Kubernetes 文档中了解有关 Operators 及其起源的更多信息：[`kubernetes.io/docs/concepts/extend-kubernetes/operator/.`](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/. )

# 问题

1.  Kubernetes operator 是如何工作的？

1.  使用 Helm CLI 和使用基于 Helm 的 operator 之间有什么区别？

1.  假设你被要求将现有的 Helm 图表创建为 Helm operator。你会采取哪些步骤来完成这个任务？

1.  在 Helm operator 中，安装、升级、回滚和卸载的生命周期钩子函数是如何工作的？

1.  在 Helm 图表中，`crds/`文件夹的目的是什么？

1.  在“使用 Helm 管理 Operators 和 CRs”部分中，我们介绍了两种不同的 Helm 图表，可以用来帮助管理 Operators 和 CRs。使用该部分提供的图表布局来实现 Helm 图表。这些图表应该用于安装 Guestbook operator 和安装 Guestbook CR。有关创建 Helm 图表的帮助，请参考“第五章”，*构建您的第一个 Helm 图表*。


# 第九章：Helm 安全性考虑

正如你可能在本书中意识到的那样，Helm 是一个强大的工具，为用户提供了许多部署可能性。然而，如果不认识和遵循某些安全范例，这种力量可能会失控。幸运的是，Helm 提供了许多方法来将安全性纳入日常使用中，这些方法简单易行，从下载 Helm CLI 到在 Kubernetes 集群上安装 Helm 图表的整个过程中都可以实现。

在本章中，我们将涵盖以下主题：

+   数据溯源和完整性

+   Helm 图表安全性

+   关于 RBAC、值和图表仓库的额外考虑

# 技术要求

本章将使用以下技术：

+   `minikube`

+   `kubectl`

+   Helm

+   **GNU 隐私保护**（**GPG**）

Minikube、Kubectl 和 Helm 的安装和配置在*第二章*，*准备 Kubernetes 和 Helm 环境*中有介绍。

我们还将利用 Packt 仓库中的`guestbook`图表，位于[`github.com/PacktPublishing/-Learn-Helm`](https://github.com/PacktPublishing/-Learn-Helm)，在本章的后续示例中。如果你还没有克隆这个仓库，请使用以下命令进行克隆。

```
$ git clone https://github.com/PacktPublishing/-Learn-Helm.git Learn-Helm
```

# 数据溯源和完整性

在处理任何类型的数据时，有两个经常被忽视的问题需要考虑：

+   数据是否来自可靠的来源或者你期望的来源？

+   数据是否包含你期望的所有内容？

第一个问题涉及**数据溯源**的主题。数据溯源是关于确定数据的来源。

第二个问题涉及**数据完整性**的主题。数据完整性是关于确定你从远程位置接收到的内容是否代表你期望接收到的内容，并且可以帮助确定数据在传输过程中是否被篡改。数据溯源和数据完整性都可以使用称为**数字签名**的概念进行验证。作者可以基于密码学创建一个唯一的签名来签署数据，而数据的消费者可以使用密码工具来验证该签名的真实性。

如果真实性得到验证，那么消费者就知道数据来自期望的来源，并且在传输过程中没有被篡改。

作者可以通过首先创建一个**Pretty Good Privacy**（**PGP**）密钥对来创建数字签名。在这种情况下，PGP 指的是 OpenPGP，这是一组基于加密的标准。PGP 侧重于建立非对称加密，这是基于使用两个不同密钥——私钥和公钥的。

私钥应保密，而公钥则设计为共享。对于数字签名，私钥用于加密数据，而公钥由消费者用于解密数据。PGP 密钥对通常使用一个名为 GPG 的工具创建，这是一个实现 OpenPGP 标准的开源工具。

创建 PGP 密钥对后，作者可以使用 GPG 对数据进行签名。当数据被签名时，GPG 在后台执行以下步骤：

1.  哈希是基于数据内容计算的。输出是一个称为**消息摘要**的固定长度字符串。

1.  消息摘要使用作者的私钥加密。输出是数字签名。

要验证签名，消费者必须使用作者的公钥来解密它。这种验证也可以使用 GPG 来执行。

数字签名在 Helm 中发挥两种作用：

+   首先，每个 Helm 下载都有一个来自维护者之一的数字签名，可用于验证二进制文件的真实性。签名可用于验证下载的来源以及其完整性。

+   其次，Helm 图表也可以进行数字签名以从相同的验证中受益。图表的作者在打包期间对图表进行签名，图表用户使用作者的公钥验证图表的有效性。

了解数据来源和完整性如何与数字签名相关之后，让我们在本地工作站上创建一个 GPG 密钥对，如果您还没有一个，这将用于详细说明先前描述的许多概念。

## 创建 GPG 密钥对

要创建密钥对，您必须首先在本地计算机上安装 GPG。请使用以下说明作为在本地计算机上安装 GPG 的指南。请注意，在 Linux 系统上，您可能已经安装了 GPG：

+   对于 Windows，您可以使用 Chocolatey 软件包管理器，如下命令所示：

```
> choco install gnupg
```

您还可以从 https://gpg4win.org/download.html 下载 Win 的安装程序。

+   对于 macOS，您可以使用 Homebrew 软件包管理器，使用以下命令：

```
$ brew install gpg
```

您还可以从 https://sourceforge.net/p/gpgosx/docu](https://sourceforge.net/p/gpgosx/docu/Download/)下载基于 macOS 的安装程序。

+   对于基于 Debian 的 Linux 发行版，您可以使用`apt`软件包管理器，如下所示：

```
$ sudo apt install gnupg
```

+   对于基于 RPM 的 Linux 发行版，您可以使用`dnf`软件包管理器，如下所示：

```
$ sudo dnf install gnupg
```

安装了 GPG 之后，您可以创建自己的 GPG 密钥对，我们将在数据来源和完整性讨论中使用它。

配置此密钥对的步骤如下：

1.  运行以下命令创建新的密钥对。此命令可以从任何目录运行：

```
$ gpg --generate-key
```

1.  按照提示输入您的姓名和电子邮件地址。这些将用于标识您作为密钥对的所有者，并且将是接收您的公钥的人看到的名称和电子邮件地址。

1.  按下*O*键继续。

1.  然后将提示您输入私钥密码。输入并确认所需的用于加密和解密操作的密码短语。

一旦您的 GPG 密钥对创建成功，您将看到类似以下的输出：

![图 9.1：成功创建 GPG 密钥对后的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_9.1.jpg)

图 9.1：成功创建 GPG 密钥对后的输出

输出显示有关公共(`pub`)和私有(`sub`)密钥的信息，以及公钥的指纹（输出的第二行）。指纹是用于识别您作为该密钥所有者的唯一标识符。以`uid`开头的第三行显示了您在生成 GPG 密钥对时输入的姓名和电子邮件地址。

现在您的`gpg`密钥对已创建，请继续下一节，了解如何验证 Helm 下载。

## 验证 Helm 下载

如*第二章*中所讨论的，*准备 Kubernetes 和 Helm 环境*，Helm 可以通过从 GitHub 下载存档的方式进行安装。可以从 Helm 的 GitHub 发布页面([`github.com/helm/helm/releases`](https://github.com/helm/helm/releases))安装这些存档，方法是选择以下截图中显示的链接之一：

![图 9.2：Helm 的 GitHub 发布页面中的安装部分](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_9.2.jpg)

图 9.2：Helm 的 GitHub 发布页面中的安装部分

在**安装**部分的底部，您会注意到一个段落解释了发布已经签名。每个 Helm 发布都由 Helm 维护人员签名，并可以根据对应于下载的 Helm 发布的数字签名进行验证。每个数字签名都位于**资产**部分下面。

以下截图显示了这些文件的表示方式：

![图 9.3：Helm 的 GitHub 发布页面上的资产部分](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_9.3.jpg)

图 9.3：Helm 的 GitHub 发布页面上的资产部分

为了验证 Helm 下载的来源和完整性，您还应该下载相应的`.asc`文件。请注意，`.sha256.asc`文件仅用于验证完整性。在本例中，我们将下载相应的`.asc`文件，它将同时验证来源和完整性。

通过以下步骤开始验证 Helm 发布：

1.  在与您的操作系统对应的安装下下载 Helm 存档。虽然 Helm 二进制文件可能已经安装，但您仍然可以下载存档以便按照示例进行操作。完成示例后，您可以从工作站中删除存档。

1.  下载与您的操作系统相对应的`.asc`文件。例如，如果您正在运行基于 AMD64 的 Linux 系统，您将下载`helm-v3.0.0-linux-amd64.tar.gz.asc`文件。

重要提示

文件名中包含的版本对应于您正在下载的实际 Helm 版本。

下载完这两个文件后，您应该在命令行的同一目录中看到两个类似的文件：

```
helm-v3.0.0-linux-amd64.tar.gz
helm-v3.0.0-linux-amd64.tar.gz.asc
```

下一步涉及将 Helm 维护人员的公钥导入到您的本地`gpg`密钥环中。这样可以解密`.asc`文件中包含的数字签名，以验证您下载的内容的来源和完整性。可以通过转到其 keybase 帐户来检索维护人员的公钥。将鼠标悬停在`keybase 帐户`一词上，即可找到该链接。在*图 9.2*的示例中，此位置解析为[`keybase.io/bacongobbler`](https://keybase.io/bacongobbler)。然后，可以通过在末尾添加`/pgp_keys.asc`来下载公钥，生成的链接为[`keybase.io/bacongobbl`](https://keybase.io/bacongobbler/pgp_keys.asc)er/pgp_keys.asc。

请注意，Helm 有多个维护者，因此如果您对不同版本执行验证，则您的链接可能会有所不同。请确保您下载的是与签署发布的密钥对应的正确公钥。

让我们继续验证过程：

1.  使用命令行，下载与 Helm 发布签名对应的公钥：

```
$ curl -o **release_key.asc** https://keybase.io/bacongobbler/pgp_keys.asc
```

1.  下载完成后，您需要将公钥导入到您的 gpg 密钥环中。通过运行以下命令来完成：

```
$ gpg --import release_key.asc
```

如果导入成功，您将看到以下消息：

```
gpg: key 92AA783CBAAE8E3B: public key 'Matthew Fisher <matt.fisher@microsoft.com>' imported
gpg: Total number processed: 1
gpg:               imported: 1
```

1.  现在已经导入了数字签名的公钥，您可以通过利用 GPG 的`--verify`子命令来验证 Helm 安装的发布。这应该针对`helm*.asc`文件运行：

```
$ gpg --verify helm-v3.0.0-linux-amd64.tar.gz.asc
```

该命令将尝试解密`.asc`文件中包含的数字签名。如果成功，这意味着 Helm 下载（以`.tar.gz`结尾的文件）是由您期望的人（本次发布的`Matthew Fisher`）签名的，并且下载没有被修改或以任何方式更改。成功的输出如下：

```
gpg: assuming signed data in 'helm-v3.0.0-linux-amd64.tar.gz'
gpg: Signature made Wed 13 Nov 2019 08:05:01 AM CST
gpg:                using RSA key 967F8AC5E2216F9F4FD270AD92AA783CBAAE8E3B
gpg: Good signature from 'Matthew Fisher <matt.fisher@microsoft.com>' [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: 967F 8AC5 E221 6F9F 4FD2  70AD 92AA 783C BAAE 8E3B
```

在进一步检查此输出时，您可能会注意到“警告”消息，指示该密钥未经认证，这可能会让您对此是否真正成功产生疑问。验证是成功的，但您尚未指示 gpg 维护者的公钥已获得认证，属于他们声称的人。

您可以按照以下步骤执行此认证：

1.  检查输出末尾显示的主密钥指纹的最后 64 位（8 个字符），与 Helm 发布页面显示的 64 位指纹匹配。正如您从*图 9.2*中记得的那样，指纹是这样显示的：

```
This release was signed with 92AA 783C BAAE 8E3B and **can be found** at @bacongobbler's keybase account.
```

1.  从前面的代码中可以看出，Helm 发布页面显示了**主密钥指纹**的最后 64 位，因此我们知道这个公钥确实属于我们期望的人。因此，我们可以安全地认证维护者的公钥。可以通过使用自己的`gpg`密钥对对公钥进行签名来完成此步骤。使用以下命令执行此步骤：

```
$ gpg --sign-key 92AA783CBAAE8E3B # Last 64 bits of fingerprint
```

1.  在“真的要签名吗？”提示中，输入`y`。

现在您已经签署了维护者的公钥，该密钥现在已经获得认证。现在可以在不显示“警告”消息的情况下运行验证：

```
$ gpg --verify helm-v3.0.0-linux-amd64.tar.gz.asc
gpg: assuming signed data in 'helm-v3.0.0-linux-amd64.tar.gz'
gpg: Signature made Wed 13 Nov 2019 08:05:01 AM CST
gpg:                using RSA key 967F8AC5E2216F9F4FD270AD92AA783CBAAE8E3B
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   2  signed:   1  trust: 0-, 0q, 0n, 0m, 0f, 2u
gpg: depth: 1  valid:   1  signed:   0  trust: 1-, 0q, 0n, 0m, 0f, 0u
gpg: next trustdb check due at 2022-03-11
gpg: Good signature from 'Matthew Fisher <matt.fisher@microsoft.com>' [full]
```

数字签名还在验证 Helm 图表的来源和完整性中发挥作用。我们将在下一节中继续讨论这个问题。

# 签署和验证 Helm 图表

类似于 Helm 维护者如何签署发布版，您可以签署自己的 Helm 图表，以便用户可以验证他们安装的图表实际上来自您，并包含了预期的内容。要签署一个图表，您必须首先在本地工作站上拥有一个`gpg`密钥对。

接下来，您可以利用`helm package`命令的某些标志来使用指定的密钥对图表进行签名。

让我们演示如何通过利用 Packt 存储库中的“留言簿”图表来实现这一点。该图表位于`Learn-Helm/helm-charts/charts/guestbook`文件夹中。我们假设您已经在本地工作站上拥有 gpg 密钥对，但如果没有，您可以按照本章的*设置*部分中*数据来源和完整性*部分的说明来配置您的密钥对。

在签署“留言簿”图表之前需要注意的一点是，如果您使用 GPG 版本`2`或更高版本，则必须将您的公钥和秘钥导出为传统格式。之前的 GPG 版本将密钥环存储在`.gpg`文件格式中，这是 Helm 期望您的密钥环所在的格式（在撰写本文时）。较新版本的 GPG 将密钥环存储在`.kbx`文件格式中，目前不受支持。

通过将您的 GPG 公钥和秘钥环转换为`.gpg`文件格式来开始签名过程：

1.  通过运行以下命令来查找您的`gpg`版本：

```
$ gpg --version
gpg (GnuPG) 2.2.9
libgcrypt 1.8.3
Copyright (C) 2018 Free Software Foundation, Inc.
```

1.  如果您的`gpg`版本是`2`或更高版本，请使用以下命令导出您的公钥和秘钥环：

```
$ gpg --export > ~/.gnupg/pubring.gpg
$ gpg --export-secret-keys > ~/.gnupg/secring.gpg
```

一旦您的密钥环被导出，您就可以对 Helm 图表进行签名和打包。`helm package`命令提供了三个关键（双关语）标志，允许您对图表进行签名和打包：

`--sign`：允许您使用 PGP 私钥对图表进行签名

`--key`：签名时要使用的密钥的名称

`--keyring`：包含 PGP 私钥的密钥环的位置

在下一步中，这些标志将与`helm package`命令一起使用，以签署和打包“留言簿”Helm 图表。

1.  运行以下`helm package`命令：

```
$ helm package --sign --key '$KEY_NAME' --keyring ~/.gnupg/secring.gpg guestbook
```

`$KEY_NAME`变量可以指代与所需密钥相关的电子邮件、姓名或指纹。这些细节可以通过利用`gpg --list-keys`命令来发现。

在不签名的情况下使用`helm package`命令，您预计会看到一个文件作为输出——包含 Helm 图表的`tgz`存档。在这种情况下，当签名和打包`guestbook`Helm 图表时，您将看到以下两个文件被创建：

```
guestbook-1.0.0.tgz
guestbook-1.0.0.tgz.prov
```

`guestbook-1.0.0.tgz.prov`文件称为**来源**文件。来源文件包含一个来源记录，显示以下内容：

+   来自`Chart.yaml`文件的图表元数据

+   Helm `guestbook-1.0.0.tgz`文件的 sha256 哈希值

+   `guestbook-1.0.0.tgz`文件的 PGP 数字签名

Helm 图表的用户将利用来源文件来验证图表的数据来源和完整性。将图表推送到图表存储库时，开发人员应确保上传 Helm 图表的`.tgz`存档和`.tgz.prov`来源文件。

一旦您打包并签署了 Helm 图表，您将需要导出与用于加密数字签名的私钥对应的公钥。这将允许用户下载您的公钥并在验证过程中使用。

1.  将您的公钥导出为`ascii-armor`格式，使用以下命令：

```
$ gpg --armor --export $KEY_NAME > pubkey.asc
```

如果您公开发布`guestbook`图表，那么该密钥可以被您的图表用户保存到可下载的位置，例如 Keybase。然后用户可以利用本章节*验证 Helm 发布*部分描述的`gpg --import`命令导入此公钥。

图表用户可以利用`helm verify`命令在安装之前验证图表的数据来源和完整性。该命令旨在针对本地下载的`.tgz`图表存档和`.tgz.prov`来源文件运行。

1.  以下命令提供了针对`guestbook`Helm 图表运行此过程的示例，并假定您的公钥已导入到名为`~/.gnupg/pubring.gpg`的密钥环中：

```
$ helm verify --keyring ~/.gnupg/pubring.gpg guestbook-1.0.0.tgz
```

如果验证成功，将不会显示任何输出。否则，将返回错误消息。验证可能因多种原因失败，包括以下情况：

.tgz 和.tgz.prov 文件不在同一个目录中。

.tgz.prov 文件损坏。

文件哈希值不匹配，表明完整性丢失。

用于解密签名的公钥与最初用于加密的私钥不匹配。

`helm verify`命令旨在在本地下载的图表上运行，因此用户可能会发现最好是利用`helm install --verify`命令，该命令执行验证和安装的单个命令，假设`.tgz`和`.tgz.prov`文件都可以从图表存储库下载。

以下命令描述了如何使用`helm install --verify`命令：

```
$ helm install my-guestbook $CHART_REPO/guestbook --verify --keyring ~/.gnupg/pubring.gpg
```

通过使用本节描述的签名和验证 Helm 图表的方法，您和您的用户都可以确保您安装的图表既属于您自己，又未经修改。

了解数据可靠性和完整性在 Helm 中起到的作用后，让我们继续讨论 Helm 安全性考虑，转而讨论我们下一个主题——与 Helm 图表和 Helm 图表开发相关的安全性。

# 开发安全的 Helm 图表

虽然可靠性和完整性在 Helm 的安全性中起着重要作用，但它们并不是您需要考虑的唯一问题。图表开发人员应确保在开发过程中，他们遵守有关安全性的最佳实践，以防止用户在 Kubernetes 集群中安装图表时引入漏洞。在本节中，我们将讨论与 Helm 图表开发相关的安全性的许多主要问题，以及作为开发人员，您可以做些什么来编写以安全性为优先考虑的 Helm 图表。

我们将首先讨论您的 Helm 图表可能使用的任何容器镜像的安全性。

## 使用安全镜像

由于 Helm（和 Kubernetes）的目标是部署容器镜像，因此镜像本身是一个主要的安全问题。首先，图表开发人员应该意识到镜像标签和镜像摘要之间的区别。

标签是对给定图像的可读引用，并为开发人员和消费者提供了一种确定图像内容的简单方法。然而，标签可能会带来安全问题，因为无法保证给定标签的内容始终保持不变。图像所有者可能会选择使用相同的标签提供更新的图像，例如，以解决安全漏洞，这将导致在运行时执行不同的基础图像，即使标签相同。对相同标签进行这些修改引入了回归的可能性，这可能会对用户造成意外的不利影响。除了使用标签引用图像外，图像也可以通过摘要引用。图像摘要是图像的计算 SHA-256 值，不仅为确切图像提供了不可变标识符，还允许容器运行时验证从远程图像注册表检索到的图像包含了预期的内容。这消除了部署包含对给定标签的意外回归的图像的风险，并且还可以消除中间人攻击的风险，其中标签的内容被恶意修改。

举例来说，可以在图表模板中将图像的引用从`quay.io/bitnami/redis:5.0.9`改为使用摘要引用，如`quay.io/bitnami/redissha256:70b816f2127afb5d4af7ec9d6e8636b2f0f 973a3cd8dda7032f9dcffa38ba11f`。请注意，图像名称后面没有标签，而是明确指定了 SHA-256 摘要。这可以确保图像内容随时间不会改变，即使标签发生变化，从而加强了您的安全性。

随着时间的推移，可以预期与图像相关联的标签或摘要将变得不安全，因为最终可能会针对该图像可能包含的软件包或操作系统版本发布漏洞。有许多不同的方法可以确定与给定图像相关联的漏洞。一种方法是利用图像所属的注册表的本机功能。许多不同的图像注册表包含围绕图像漏洞扫描的功能，可以帮助了解图像何时存在漏洞。

例如，Quay 容器注册表可以自动扫描镜像，以确定镜像包含的漏洞数量。Nexus 和 Artifactory 容器注册表也是具有此功能的容器注册表的例子。除了容器注册表提供的原生扫描功能外，还可以利用其他工具，如 Clair（也是**Quay**的后备扫描技术）、Anchore、Vuls 和 OpenSCAP。当您的镜像注册表或独立扫描工具报告镜像存在漏洞时，如果有新版本可用，您应立即更新图表的镜像，以防止漏洞被引入到用户的 Kubernetes 集群中。

为了简化更新容器镜像的流程，您可以制定一个定期的节奏来检查镜像更新。这有助于防止您的目标镜像包含漏洞，使其不适合部署。许多团队和组织还规定镜像只能来自受信任的注册表，以减少运行包含漏洞的镜像的可能性。此设置在容器运行时级别进行配置，具体位置和配置因运行时而异。

除了镜像漏洞扫描和内容获取之外，您还应避免部署需要提升权限或功能的镜像。功能用于给进程提供一组根权限的子集。一些功能的例子是`NET_ADMIN`，允许进程执行与网络相关的操作，以及`SYS_TIME`，允许进程修改系统的时钟。以 root 身份运行容器会赋予容器所有功能，应尽可能限制。功能列表可以在 Linux 手册页的*CAPABILITIES(7)*页面中找到（http://man7.org/linux/man-pages/man7/capabilities.7.html）。

授予容器功能或允许其以 root 身份运行会使恶意进程更有可能损害底层主机。这不仅影响引入漏洞的容器，还影响在该主机上运行的任何其他容器，可能还影响整个 Kubernetes 集群。如果容器存在漏洞但没有被授予任何功能，攻击向量将小得多，甚至可能完全被阻止。在开发 Helm 图表时，必须考虑图像的漏洞和权限要求，以确保用户和 Kubernetes 集群的其他租户的安全。

除了部署的容器镜像外，图表开发人员还应关注授予应用程序的资源。我们将在下一节中深入探讨这个话题。

设置资源限制

一个 pod 使用属于其底层节点的资源。如果没有适当的默认设置，pod 可能会耗尽`节点资源`，导致诸如 CPU 限制和 pod 驱逐等问题。耗尽底层节点还将阻止其他工作负载在那里被调度。由于资源限制不受控制时可能出现的问题，图表开发人员应该关注在其 Helm 图表或 Kubernetes 集群中设置合理默认值。

许多图表允许将部署的`resources`字段声明为 Helm 值。图表开发人员可以在`values.yaml`文件中默认设置`resources`字段，设置开发人员认为应用程序应该需要的资源量。以下代码显示了一个示例：

```
resources:
  limits:
    cpu: 500m
    memory: 2Gi
```

如果保持默认设置，此示例值将用于将 pod 的 CPU 限制设置为`500m`，内存限制设置为`2Gi`。在`values.yaml`文件中设置此默认值可以防止 pod 耗尽节点资源，同时为所需的应用程序资源量提供建议值。用户可以选择在必要时覆盖资源限制。请注意，图表开发人员还可以为资源请求设置默认值，但这不会阻止 pod 耗尽节点资源。

虽然您应该考虑在`values.yaml`文件中设置默认资源限制，但您也可以在将要安装图表的 Kubernetes 命名空间中设置限制范围和资源配额。这些资源通常不包括在 Helm 图表中，而是在应用部署之前由集群管理员创建。限制范围用于确定容器在命名空间内允许使用的资源数量。限制范围还用于为每个部署到尚未定义资源限制的命名空间的容器设置默认资源限制。以下是由`LimitRange`对象定义的示例限制范围：

```
apiVersion: v1
kind: LimitRange
metadata:
  name: limits-per-container
spec:
  limits:
    - max:
        cpu: 1
        memory: 4Gi
      default:
        cpu: 500m
        memory: 2Gi
      type: Container
```

`LimitRange`在创建`LimitRange`对象的命名空间中强制执行指定的限制。它将允许容器资源的最大数量设置为`1`个`cpu`核心和`4Gi`的`内存`。如果未定义资源限制，它会自动将资源限制设置为`500m`的`cpu`和`2Gi`的`内存`。通过将`type`字段设置为`Pod`，还可以在 Pod 级别应用限制范围。这将确保 Pod 中所有容器的资源利用总和在指定限制之下。除了设置对 CPU 和内存利用的限制，您还可以通过将`type`字段设置为`PersistentVolumeClaim`来设置`LimitRange`对象以默认声明`PersistentVolumeClaim`对象的存储。

这将允许您创建以下资源，以设置单个 PVC 的存储限制：

```
apiVersion: v1
kind: LimitRange
metadata:
  name: limits-per-pvc
spec:
  - max:
      storage: 4Gi
    type: PersistentVolumeClaim
```

当然，您也可以在 Helm 图表的`values.yaml`文件中设置默认存储量。在`values.yaml`文件中设置的默认值反映了您认为默认安装所需的存储量，`LimitRange`对象强制执行用户可以覆盖的绝对最大值。

除了限制范围，您还可以设置资源配额以对命名空间的资源使用添加额外限制。虽然限制范围强制执行每个容器、Pod 或 PVC 级别的资源，资源配额则强制执行每个命名空间级别的资源使用。它们用于定义命名空间可以利用的资源的最大数量。以下是一个资源配额的示例：

```
apiVersion: v1
kind: ResourceQuota
metadata:
  name: pod-and-pvc-quota
spec:
  hard:
    limits.cpu: '4'
    limits.memory: 8Gi
    requests.storage: 20Gi
```

前面的`ResourceQuota`对象在应用于 Kubernetes 命名空间时，将最大 CPU 利用率设置为`4`核，最大内存利用率设置为`8Gi`，并将命名空间中所有工作负载的最大存储请求设置为`20Gi`。资源配额还可以用于设置每个命名空间中`secrets`、`ConfigMaps`和其他 Kubernetes 资源的最大数量。通过使用`资源配额`，您可以防止单个命名空间过度利用集群资源。

通过在 Helm 图表中设置合理的默认资源限制，以及存在`LimitRange`和`ResourceQuota`，您可以确保 Helm 图表的用户不会耗尽集群资源并导致中断或停机。了解如何强制执行资源限制后，让我们继续讨论 Helm 图表安全性周围的下一个主题——处理 Helm 图表中的机密信息。

## 在 Helm 图表中处理机密信息

处理机密信息是在使用 Helm 图表时的常见问题。考虑一下来自*第三章*的 WordPress 应用程序，*安装您的第一个 Helm 图表*，在那里您需要提供一个密码来配置管理员用户。这个密码在`values.yaml`文件中默认没有提供，因为如果您忘记覆盖`password`值，这将使应用程序容易受到攻击。图表开发人员应该养成不为诸如密码之类的机密值提供默认值的习惯，而应该要求用户提供明确的值。这可以通过利用`required`函数轻松实现。Helm 还具有使用`randAlphaNum`函数生成随机字符串的能力。

请注意，此函数每次升级图表时都会生成一个新的随机字符串。因此，开发人员应设计图表，期望用户提供自己的密码或其他机密密钥，并且`required`函数作为确保提供值的门槛。

当用户在图表安装期间提供秘密时，该值应保存在`secret`中，而不是`ConfigMap`中。ConfigMaps 以明文显示值，并且不设计包含凭据或其他秘密值。另一方面，Secrets 通过 Base64 编码其内容提供了混淆。Secrets 还允许您将其内容挂载到 pod 作为`tmpfs`挂载，这意味着内容被挂载到 pod 的易失性内存中，而不是在磁盘上。作为图表开发人员，您应确保由您的 Helm 图表管理的所有凭据和秘密配置都是使用 Kubernetes Secrets 创建的。

图表开发人员应确保使用 Kubernetes Secrets 和`required`函数适当处理密钥，而图表用户应确保诸如凭据之类的密钥安全地提供给 Helm 图表。通常，值是通过`--values`标志提供给 Helm 图表的，额外或覆盖的值在单独的`values`文件中声明，并在安装期间传递给 Helm CLI。这是在处理常规值时的适当方法，但在处理秘密值时应谨慎。用户应确保包含秘密的`values`文件未被检入`git`存储库或其他公共位置，以免泄露这些秘密。用户可以通过利用`--set`标志从本地命令行内联传递秘密来避免泄露秘密。这降低了凭据泄露的风险，但用户应意识到这将在 bash 历史记录中显示凭据。

用户可以通过利用加密工具加密包含秘密的`values`文件来避免泄露秘密。这将继续允许用户应用`--values`标志并将`values`文件推送到远程位置，例如 git 存储库。然后，只有具有适当密钥的用户才能解密`values`文件，并且对于所有其他用户，它将保持加密状态，只允许受信任的成员访问数据。用户可以简单地利用 GPG 加密`values`文件，或者他们可以利用特殊工具如**Sops**。**Sops** (https://github.com/mozilla/sops) 是一个设计用于加密 YAML 或 JSON 文件的值但保留密钥未加密的工具。以下代码显示了来自 Sops 加密文件的秘密键/值对：

```
password:ENC[AES256GCM,data:xhdUx7DVUG8bitGnqjGvPMygpw==,iv:3LR9KcttchCvZNpRKqE5LcXRyWD1I00v2kEAIl1ttco=,tag:9HEwxhT9s1pxo9lg19wyNg==,type:str]
```

请注意`password`键是未加密的，但值是加密的。这样可以让您轻松地查看文件中包含的值的类型，而不会暴露它们的机密信息。

还有其他工具可以加密包含机密的`values`文件。一些例子包括`git-`（https://github.com/AGWA/git-crypt）`crypt`（https://github.com/AGWA/git-crypt）和`blackbox`（https://github.com/StackExchange/blackbox）。此外，诸如 HashiCorp 的`Vault`或 CyberArk Conjur 之类的工具可以用于以键/值存储的形式加密机密。然后，可以通过使用秘密管理系统进行身份验证，然后通过使用`--set`将它们传递给 Helm 来检索机密。

了解安全如何在 Helm 图表开发中发挥作用后，现在让我们讨论如何在 Kubernetes 中应用**基于角色的访问控制**（**RBAC**）以为用户提供更大的安全性。

# 配置 RBAC 规则

在 Kubernetes 中，经过身份验证的用户执行操作的能力是通过一组 RBAC 策略来管理的。正如*第二章*中介绍的*准备 Kubernetes 和 Helm 环境*，策略，也就是角色，可以与用户或服务账户关联，Kubernetes 包含几个可以关联的默认角色。自 Kubernetes 版本`1.6`以来，RBAC 已默认启用。在考虑 Helm 使用中的 Kubernetes RBAC 时，您需要考虑两个因素：

+   安装 Helm 图表的用户

+   与运行工作负载的 pod 关联的服务账户

在大多数情况下，安装 Helm 图表的个人与 Kubernetes 用户关联。但是，Helm 图表也可以通过其他方式安装，例如由与服务账户关联的 Kubernetes 操作员。

在 Kubernetes 集群中，默认情况下，用户和服务账户具有最低权限。通过将权限授予个别命名空间的角色或授予集群级别访问权限的集群角色来获得额外的权限。然后，根据所针对的策略类型，将其与用户或服务账户关联起来，使用角色绑定或集群角色绑定。虽然 Kubernetes 包含了一些可以应用的角色，但应尽可能使用**最低权限访问**的概念。最低权限访问是指只授予用户或应用程序所需的最小权限集以正常运行。例如，我们之前开发的 `guestbook` 图表。假设我们想要添加新功能，可以查询 `guestbook` 应用程序命名空间中的 pods 的元数据。

虽然 Kubernetes 包含一个名为**view**的内置角色，提供了在给定命名空间中读取 pod 清单所需的权限，但它也可以访问其他资源，如 ConfigMaps 和部署。为了最小化授予应用程序的访问级别，可以创建一个自定义策略，以角色或集群角色的形式，仅提供应用程序所需的必要权限。由于 Kubernetes 集群的大多数典型用户无权在集群级别创建资源，让我们创建一个应用于 Helm 图表部署的命名空间的角色。

要创建一个新角色，可以使用 `kubectl create role` 命令。一个基本的角色包含两个关键元素：

+   针对 Kubernetes API 进行的操作类型（动词）

+   要定位的 Kubernetes 资源列表

例如，为了演示如何在 Kubernetes 中配置 RBAC，让我们配置一组 RBAC 规则，允许经过身份验证的用户在命名空间内查看 pods。

重要提示

如果您想在本地工作站上运行此示例，请确保首先运行 `minikube start` 来启动 Minikube。

然后可以通过运行 `kubectl create ns chapter9` 来创建一个名为 `chapter9` 的新命名空间：

1.  使用 `kubectl` CLI 创建一个名为 `guestbook-pod-viewer` 的新角色：

```
$ kubectl create role guestbook-pod-viewer --resource=pods --verb=get,list -n chapter9
```

有了这个新角色，它需要与用户或服务账户关联。由于我们想要将其与在 Kubernetes 中运行的应用程序关联起来，我们将把角色应用到一个服务账户上。当创建一个 pod 时，它会使用一个名为`default`的服务账户。在尝试遵守最小特权访问原则时，建议使用一个单独的服务账户。这是为了确保在与`guestbook`应用程序相同的命名空间中没有部署其他工作负载，因为它也会继承相同的权限。

1.  通过执行以下命令创建一个名为`guestbook`的新服务账户：

```
$ kubectl create sa guestbook -n chapter9
```

1.  接下来，创建一个名为`guestbook-pod-viewers`的角色绑定，将`guestbook-pod-viewer`与`guestbook ServiceAccount`关联起来：

```
$ kubectl create rolebinding guestbook-pod-viewers --role=guestbook-pod-viewer --serviceaccount=chapter9:guestbook -n chapter9
```

最后，要使用新创建的`guestbook` `ServiceAccount`来运行`guestbook`应用程序本身，需要将服务账户的名称应用到部署中。

以下显示了在部署 YAML 中`serviceAccount`配置的外观：

```
serviceAccountName: guestbook
```

您可以通过使用您在*第五章*中创建的图表，或者通过使用[位于 Packt 存储库中的图表](https://github.com/PacktPublishing/-Learn-Helm/tree/master/helm-charts/charts/guestbook)来轻松安装`guestbook`应用程序。该图表公开了一组用于配置部署服务账户的值。

1.  通过运行以下命令安装`guestbook` Helm 图表：

```
$ helm install my-guestbook Learn-Helm/helm-charts/charts/guestbook \
--set serviceAccount.name=guestbook \
--set serviceAccount.create=false \
-n chapter9
```

请注意，在*步骤 4*中，`serviceAccount.create`的值设置为`false`。当您在*第五章*中使用`helm create`命令创建 Helm 图表时，提供了在图表安装时创建服务账户的能力。由于您之前已经使用`kubectl`创建了一个服务账户，这是不需要的。然而，在图表安装期间创建与 RBAC 相关的其他资源的能力并不需要止步于创建服务账户。实际上，如果您的 Helm 图表包含创建角色和角色绑定所需的 YAML 资源，您可以在单个图表安装中执行步骤 1、2 和 3。

1.  此时，`guestbook`应用程序具有列出和获取 pod 所需的权限。为了验证这一假设，`kubectl`有一个命令可以查询用户或服务账户是否有权执行某个操作。执行以下命令来验证`ServiceAccount` guestbook 是否有权限查询`guestbook`命名空间中的所有 pod：

```
$ kubectl auth can-i list pods --as=system:serviceaccount:chapter9:guestbook -n chapter9
```

`--as`标志利用了 Kubernetes 中的用户模拟功能，允许调试授权策略。

1.  该命令的结果应该打印`yes`作为输出。为了确认服务账户不能访问不应该能够访问的资源，比如列出部署，执行以下命令：

```
$ kubectl can-i list deployments --as=system:serviceaccount:guestbook:guestbook -n chapter9
```

1.  可以使用`helm uninstall`命令随意删除您的发布：

```
$ helm uninstall my-guestbook -n chapter9
```

您还可以停止 Minikube 实例，这在本章的其余部分中是不需要的：

```
$ minikube stop
```

从`no`的输出中可以看到，预期的策略已经就位。

当有效使用时，Kubernetes RBAC 有助于为 Helm 图表开发人员提供必要的工具，以强制执行最小特权访问，保护用户和应用程序免受潜在的错误或恶意行为的影响。

接下来，我们将讨论如何保护和访问图表仓库，以增强 Helm 的整体安全性。

# 访问安全的图表仓库

图表仓库提供了在 Kubernetes 集群上发现 Helm 图表并安装它们的能力。仓库在*"**第一章**: Understanding Kubernetes and Helm" on page 305*，*Understanding Kubernetes and Helm*中被介绍为一个包含与仓库中图表相关的元数据的`index.yaml`文件的 HTTP 服务器。在之前的章节中，我们使用了来自各种上游仓库的图表，并且还使用 GitHub Pages 实现了我们自己的仓库。这些仓库都可以自由使用，供任何感兴趣的人使用。然而，Helm 确实支持整合额外的安全措施来保护仓库中存储的内容，包括以下内容：

+   认证

+   **安全套接字层**/**传输层安全**（**SSL**/**TLS**）加密

虽然大多数公共 Helm 存储库不需要任何形式的身份验证，但 Helm 确实允许用户对受保护的图表存储库执行基本和基于证书的身份验证。对于基本身份验证，可以在使用`helm repo add`命令添加存储库时提供用户名和密码，通过使用`--username`和`--password`标志。例如，如果您想访问受基本身份验证保护的存储库，则添加存储库将采取以下形式：

```
$ helm repo add $REPO_URL --username=<username> --password=<password>
```

然后，存储库可以进行交互，而无需重复提供凭据。

对于基于证书的身份验证，`helm repo add`命令提供`--ca-file`，`--cert-file`和`--key-file`标志。`--ca-file`标志用于验证图表存储库的证书颁发机构，而`--cert-file`和`--key-file`标志用于分别指定您的客户端证书和密钥。

在图表存储库本身上启用基本身份验证和证书身份验证取决于所使用的存储库实现。例如，流行的图表存储库 ChartMuseum 提供了`--basic-auth-user`和`--basic-auth-pass`标志，可在启动时用于配置基本身份验证的用户名和密码。它还提供了`--tls-ca-cert`标志来配置证书身份验证的**证书颁发机构**（CA）证书。其他图表存储库实现可能提供其他标志或要求您提供配置文件。

即使有了认证，确保 HTTP 服务器和 Helm 客户端之间的传输是安全的也很重要。这可以通过使用安全套接字层（SSL）/传输层安全性（TLS）加密来实现，以保护 Helm 客户端和 Helm 图表存储库之间的通信。虽然需要证书认证，但需要基本认证（和未经认证的存储库）的存储库仍然可以从加密网络流量中受益，因为这将保护认证尝试以及存储库的内容。与认证一样，配置图表存储库上的 TLS 取决于所使用的存储库实现。ChartMuseum 提供了`--tls-cert`和`--tls-key`标志来提供证书链和密钥文件。更一般的 Web 服务器，如 NGINX，通常需要一个配置文件，提供服务器上证书和密钥文件的位置。像 GitHub Pages 这样的服务已经配置了 TLS。

到目前为止我们使用的每个 Helm 存储库都使用了由公开可用的 CA 签名的证书，这些证书存储在您的 Web 浏览器和底层操作系统中。许多大型组织都有自己的 CA，可以用来生成图表存储库中配置的证书。由于这个证书可能不是来自公开可用的 CA，Helm CLI 可能不信任该证书，添加存储库会导致以下错误：

```
Error: looks like '$REPO_URL' is not a valid chart repository or cannot be reached: Get $REPO_URL/index.yaml: x509: certificate signed by unknown authority
```

为了让 Helm CLI 信任图表存储库的证书，CA 证书或包含多个证书的 CA 捆绑包可以添加到操作系统的信任存储中，或者可以在`helm repo add`命令的`--ca-file`标志中明确指定。这样可以使命令在没有错误的情况下执行。

最后，根据图表存储库的配置，还可以获取额外的指标来执行请求级别的审计和日志记录，以确定谁尝试访问存储库。

通过使用认证和管理传输层的证书，可以实现增强 Helm 存储库的安全性。

# 总结

在本章中，你了解了在使用 Helm 时需要考虑的一些安全主题。首先，你了解了如何证明 Helm 发布和 Helm 图表的数据来源和完整性。接下来，你了解了 Helm 图表安全性以及图表开发人员如何在安全方面采用最佳实践来编写稳定和安全的 Helm 图表。最后，你了解了如何使用 RBAC 来创建基于最小特权访问概念的环境，以及如何保护图表存储库以提供 HTTPS 加密并要求身份验证。现在，有了这些概念，你更有能力创建一个安全的 Helm 架构和工作环境。

# 进一步阅读

+   要了解有关 Helm 图表中数据来源和完整性的更多信息，请访问[`helm.sh/docs/topics/provenance/`](https://helm.sh/docs/topics/provenance/)。

+   要了解更多关于 Kubernetes RBAC 的信息，请查看 Kubernetes 文档中的*使用 RBAC 授权*页面，网址为[`kubernetes.io/docs/reference/access-authn-authz/rbac/`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)。

+   查看 Helm 文档中的图表存储库指南，了解更多关于图表存储库的信息，网址为[`helm.sh/docs/topics/chart_repository/`](https://helm.sh/docs/topics/chart_repository/)。

# 问题

1.  什么是数据来源和完整性？数据来源和数据完整性有什么不同？

1.  想象一下，你想要证明 Helm 下载的数据来源和完整性。除了发布存档之外，用户需要从 Helm 的 GitHub 发布页面下载哪个文件来完成这个任务？

1.  用户可以运行哪些命令来验证 Helm 图表的数据来源和完整性？

1.  作为 Helm 图表开发人员，你可以做些什么来确保部署稳定的容器镜像？

1.  在 Helm 图表上设置资源限制为什么很重要？还有哪些 Kubernetes 资源可以用来配置 Pod 和命名空间的资源限制？

1.  什么是最小特权访问的概念？哪些 Kubernetes 资源允许你配置授权并帮助实现最小特权访问？

1.  可以使用什么命令和一组标志来对图表存储库进行身份验证？


# 第十章：评估

# 第一章：理解 Kubernetes 和 Helm

以下是本章中提出的一些问题的答案：

1.  如果一个应用程序在一个单一应用程序中包含了所有必要的逻辑和功能，那么它就是`单体`的。单体应用程序可以分解成多个不同的应用程序，称为**微服务**。

1.  Kubernetes 是一个容器编排工具。举几个例子，它解决了关于工作负载调度、可用性和可伸缩性的问题。

1.  `创建`、`描述`、`编辑`、`删除`和`应用`

1.  用户必须了解许多不同类型的资源才能部署应用程序。同时，保持本地和实时状态同步、管理应用程序生命周期以及维护样板 YAML 资源文件也是具有挑战性的。

1.  Helm 包括四个生命周期命令，可以让用户轻松管理 Kubernetes 应用程序。用户可以应用这些命令与 Helm 图表进行交互，Helm 图表是部署应用程序所需的 Kubernetes 资源的打包。Helm 抽象了 Kubernetes 资源的复杂性，并为给定应用程序提供了修订历史，允许将应用程序回滚到先前的快照。它还允许动态生成 YAML 资源，并简化了本地和实时状态之间的同步。最后，Helm 按照预定的顺序应用 Kubernetes 资源，并允许自动化的生命周期钩子，可用于执行各种自动化任务。

1.  您可以使用`helm rollback`命令。Helm 为每个应用程序快照分配一个修订版本。当应用程序的一个或多个区域从其先前应用的状态进行修改时，将分配一个新的修订版本。

1.  `安装`、`升级`、`回滚`和`卸载`。

# 第二章：准备 Kubernetes 和 Helm 环境

以下是本章中提出的一些问题的答案：

1.  Windows 和 Mac 用户可以使用 Chocolatey 或 Homebrew 软件包管理器安装 Helm。所有用户（Windows、Mac 和 Linux）也可以从 Helm 的 GitHub 发布页面[`github.com/helm/helm/releases`](https://github.com/helm/helm/releases)安装 Helm。

1.  Helm 使用本地的`kubeconfig`文件进行身份验证。

1.  Kubernetes 角色提供授权。管理员可以通过创建`RoleBinding`来管理这些特权，将角色绑定到用户或组。

1.  helm repo add 命令用于本地配置 Helm 图表存储库。这是安装存储库中包含的图表的要求。

1.  Helm 使用的三个 XDG 环境变量是 XDG_CACHE_HOME、XDG_CONFIG_HOME 和 XDG_DATA_HOME。XDG_CACHE_HOME 用于指定缓存文件的位置（包括从上游图表存储库下载的图表）。XDG_CONFIG_HOME 用于设置 Helm 配置的位置（包括 helm repo add 保存的存储库信息）。XDG_DATA_HOME 用于保存使用 helm plugin install 命令添加的插件信息。

1.  Minikube 允许用户在他们的本地机器上轻松创建单节点 Kubernetes 集群。Minikube 会自动为认证配置 Kubeconfig，并分配给用户 cluster-admin 权限来执行任何所需的操作。

# 第三章：安装您的第一个 Helm 图表

以下是本章提出的问题的一些答案：

1.  Helm Hub 是上游图表存储库的集中位置。用户可以使用 helm search hub 命令与其交互，或者访问 Helm Hub 网站[`hub.helm.sh/`](https://hub.helm.sh/)。

1.  helm get 命令用于获取已安装的 Helm 发布的详细信息，例如应用的值和生成的 Kubernetes 资源。helm show 命令用于显示 Helm 图表的一般信息，例如支持的值列表和图表 README。

1.  --set 标志用于提供内联值，对于提供简单值或包含不应保存到文件的机密的值很有用。--values 标志用于通过使用值文件提供值，对于一次提供大量值并将应用的值保存到源代码控制存储库很有用。

1.  helm history 命令可用于列出发布的修订版本。

1.  如果升级发布而不提供任何值，则默认应用--reuse-values 标志，该标志将重用先前发布中应用的每个值。如果提供了至少一个值，则将应用--reset-values 标志，该标志将将每个值重置为其默认值，然后合并提供的值。

1.  helm history 命令将显示六个发布版本，第六个发布版本表示应用程序已回滚到第 3 个修订版本。

1.  helm list 命令可用于查看部署到命名空间的所有发布。

1.  `helm search repo`命令可用于列出存储库的每个图表。

# 第四章：理解 Helm 图表

以下是本章中提出的一些问题的答案：

1.  YAML 是最常用的格式，尽管也可以使用 JSON。

1.  三个必填字段是`apiVersion`，`name`和`version`。

1.  可以通过在名称等于依赖图表的名称的映射中放置所需的依赖值来引用或覆盖图表依赖的值。还可以使用`import-values`设置导入值，该设置可用于允许使用不同名称引用依赖值。

1.  您可以创建升级钩子以确保在运行`helm upgrade`命令之前进行数据快照。

1.  您可以提供`README.md`文件来为您的图表提供文档。您还可以创建`templates/NOTES.txt`文件，该文件可以在安装时动态生成发布说明。最后，`LICENSE`文件可用于提供法律信息。

1.  `range`操作允许图表开发人员生成重复的 YAML 部分。

1.  `Chart.yaml`文件用于定义有关 Helm 图表的元数据。此文件也称为图表定义。`Chart.lock`文件用于保存图表依赖状态，提供有关所使用的确切依赖版本的元数据，以便可以重新创建`charts/`文件夹。

1.  `helm.sh/hook`注释用于定义钩子资源。

1.  函数和管道允许图表开发人员在模板中执行复杂的处理和数据格式化。常见函数包括`date`，`include`，`indent`，`quote`和`toYaml`。

# 第五章：创建您的第一个 Helm 图表

以下是本章中提出的一些问题的答案：

1.  `helm create`命令可用于创建新的 Helm 图表。

1.  声明 Redis 依赖性使您无需在 Helm 图表中创建 Redis 模板。它允许您部署 Redis 而无需知道所需的正确 Kubernetes 资源配置。

1.  `helm.sh/hook-weight`注释可用于设置执行顺序。按权重升序执行钩子。

1.  `fail`函数用于立即失败渲染，并可用于限制用户输入以符合一组有效设置。`required`函数用于声明必需值，如果未提供该值，则图表模板将失败。

1.  要将 Helm 图表发布到 GitHub Pages 图表存储库，必须首先使用`helm package`命令将 Helm 图表打包为 TGZ 格式。接下来，应使用`helm repo index`命令生成存储库的`index.yaml`文件。最后，存储库内容应推送到 GitHub。

1.  `index.yaml`文件包含有关图表存储库中包含的每个图表的元数据。

# 第六章：测试 Helm 图表

以下是本章提出的一些问题的答案：

1.  `helm template`命令用于在本地生成 Helm 模板。`helm lint`命令用于检查图表结构和图表定义文件中的错误。它还尝试查找会导致安装失败的错误。

1.  在安装之前验证图表模板，可以运行`helm template`命令在本地生成您的 YAML 资源，以确保它们被正确生成。您还可以使用`--verify`标志在不安装资源的情况下与 API 服务器检查您的 YAML 模式是否正确。`helm install --dry-run`命令也可以在安装之前与 API 服务器执行此检查。

1.  可用于检查 YAML 资源样式的工具之一是`yamllint`工具。它可以与`helm template`一起使用来检查生成的资源（例如，`helm template my-test test-chart | yamllint -`）。

1.  创建图表测试是通过创建一个带有`helm.sh/hook: test`注释的图表模板来实现的。图表测试通常是执行脚本或简短命令的 Pod。可以通过运行`helm test`命令来执行它们。

1.  Chart Testing（**ct**）工具允许 Helm 图表维护者更轻松地在 git monorepo 中测试 Helm 图表。它进行彻底的测试，并确保已修改的图表已增加其版本。

1.  `ci/`文件夹用于测试多种不同的 Helm 值组合。

1.  添加`--upgrade`标志将有助于确保对未增加主要版本的图表未发生回归。它将首先安装图表的旧版本，然后升级到新版本。然后，它将删除发布，安装新版本，并尝试对自身进行升级。测试将在每次安装/升级之间进行。

# 第七章：使用 CI/CD 和 GitOps 自动化 Helm 流程

以下是本章提出的一些问题的答案：

1.  CI 是一种自动化的软件开发过程，可以在软件发生变化时重复进行。CD 是一组定义的步骤，用于将软件推进到发布过程中（通常称为管道）。

1.  虽然 CI/CD 描述了软件开发和发布过程，但 GitOps 描述了在 Git 中存储配置的行为。一个例子是将值文件存储在 Git 中，然后应用于将应用程序部署到 Kubernetes。

1.  用于创建和发布 Helm 图表的 CI 管道可以对 Helm 图表进行 lint、安装和测试。Chart 测试工具可以帮助更轻松地执行这些步骤，特别是在维护图表 monorepo 时。管道还应该打包每个 Helm 图表并将图表部署到图表存储库。对于 GitHub Pages 图表存储库，必须生成`index.yaml`文件，并将内容推送到存储库。

1.  CI 允许轻松快速地测试和发布图表。它还可以帮助防止在添加新功能时出现回归。

1.  CD 管道将 Helm 图表部署到每个所需的环境，每个环境都是不同的管道阶段。每次部署后都可以使用`helm test`命令进行烟雾测试。

1.  CD 管道允许用户轻松部署其应用程序，而无需手动调用 Helm CLI 命令。这可以帮助防止在使用 Helm 部署应用程序时出现人为错误的可能性。

1.  为了维护多个环境的配置，可以使用单独的文件夹来按环境分隔值文件。为了减少样板文件，可以保存一个包含每个环境中使用的通用值的文件，并将其应用于每个 Helm 部署。

# 第八章：使用 Operator Framework 的 Helm

以下是本章提出的问题的一些答案：

1.  操作员通过利用自定义控制器和自定义资源来工作。当创建新的自定义资源时，操作员将执行自定义控制器实现的逻辑。对自定义资源的更改也会触发控制器逻辑。操作员通常用于安装和管理应用程序的生命周期。

1.  当使用 Helm CLI 时，您必须从命令行执行`install`、`upgrade`、`rollback`和`uninstall`命令。但是，当使用基于 Helm 的 operator 时，当您`create`、`modify`或`delete`自定义资源时，这些命令将自动执行。当使用基于 Helm 的 operator 时，您不必在本地运行任何 Helm CLI 命令。

关于应用程序生命周期，Helm CLI 允许用户回滚到先前的修订版本，而 Helm operator 不允许这样做，因为它不保留修订版本的历史记录。

1.  您可以首先使用`operator-sdk new`命令来创建一个新的 Helm operator，将该命令指向现有的 Helm 图表，并使用`--helm-chart`标志。接下来，您可以使用`operator-sdk build`命令构建 operator。最后，您可以将 operator 镜像推送到容器注册表。

1.  安装是通过创建新的自定义资源来执行的。升级是通过修改自定义资源来执行的。如果升级失败，回滚将自动执行，但不能显式执行。卸载是通过删除自定义资源来执行的。

1.  `crds/`文件夹允许在创建`templates/`中的内容之前创建**自定义资源定义（CRD）**。它提供了一种轻松的方式来部署依赖于 CRD 的 operator。

1.  答案会有所不同，但已在[`github.com/PacktPublishing/-Learn-Helm/tree/master/ch8-q6-answer`](https://github.com/PacktPublishing/-Learn-Helm/tree/master/ch8-q6-answer)提供了这些图表的示例。该示例创建了一个名为**guestbook-operator**的图表，用于部署 operator 资源（包括 CRD），而另一个图表名为**guestbook-cr**，用于部署自定义资源。

# 第九章：Helm 安全考虑

以下是本章中提出的一些问题的示例答案：

1.  数据溯源是关于确定数据的来源。数据完整性确定您收到的数据是否是您期望的数据。

1.  用户需要下载附带的`.asc`文件，其中包含数字签名。

1.  `helm verify`命令可用于验证本地下载的图表，而`helm install --verify`命令可用于针对存储在上游图表存储库中的图表。

1.  您可以整合常规漏洞扫描。您还可以尝试避免部署需要以 root 或 root 权限子集运行的映像。最后，您可以使用 `sha256` 值引用映像，而不是标签，以确保始终部署预期的映像。

1.  资源限制有助于防止应用程序耗尽底层节点资源。您还可以利用 `LimitRanges` 来设置每个 Pod 或 PVC 的最大资源量，并且可以利用 `ResourceQuotas` 来设置每个命名空间的最大资源量。

1.  最小权限是指仅授予用户或应用程序所需的最小权限集以正常运行。要实现最小权限访问，您可以使用 Kubernetes 的 `Roles` 和 `RoleBindings` 来创建最小权限角色，并将这些角色绑定到用户或组。

1.  `helm repo add` 命令提供了 `--username` 和 `--password` 标志，用于基本身份验证，以及 `--ca-file`、`--cert-file` 和 `--key-file` 标志，用于基于证书的身份验证。`--ca-file` 标志还用于验证图表存储库的证书颁发机构。
