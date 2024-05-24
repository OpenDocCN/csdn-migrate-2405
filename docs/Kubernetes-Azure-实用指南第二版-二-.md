# Kubernetes Azure 实用指南第二版（二）

> 原文：[`zh.annas-archive.org/md5/8F91550A7983115FCFE36001051EE26C`](https://zh.annas-archive.org/md5/8F91550A7983115FCFE36001051EE26C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：在 AKS 中处理常见故障

Kubernetes 是一个具有许多工作部分的分布式系统。AKS 为您抽象了大部分内容，但您仍有责任知道在发生不良情况时应该去哪里寻找以及如何做出响应。Kubernetes 会自动处理大部分故障；然而，您会遇到需要手动干预的情况。

在部署在 AKS 之上的应用程序中，有两个可能出现问题的领域。要么是集群本身出现问题，要么是部署在集群之上的应用程序出现问题。本章专注于集群问题。集群可能出现多种问题。

第一种可能出现的问题是集群中的节点可能变得不可用。这可能是由于 Azure 基础设施故障或虚拟机本身出现问题，例如操作系统崩溃。无论哪种情况，Kubernetes 都会监视集群中的节点故障，并将自动恢复。您将在本章中看到这个过程。

Kubernetes 集群中的第二个常见问题是资源不足的故障。这意味着您尝试部署的工作负载需要的资源超过了集群上可用的资源。您将学习如何监视这些信号以及如何解决这些问题。

另一个常见问题是挂载存储出现问题，这发生在节点变得不可用时。当 Kubernetes 中的节点变得不可用时，Kubernetes 不会分离附加到此失败节点的磁盘。这意味着这些磁盘不能被其他节点上的工作负载使用。您将看到一个实际的例子，并学习如何从这种故障中恢复。

在本章中，我们将深入研究以下故障模式：

+   处理节点故障

+   解决资源不足的故障

+   处理存储挂载问题

在这一章中，您将了解常见的故障场景，以及针对这些场景的解决方案。首先，我们将介绍节点故障。

#### 注意：

参考*Kubernetes the Hard Way*（[`github.com/kelseyhightower/kubernetes-the-hard-way`](https://github.com/kelseyhightower/kubernetes-the-hard-way)），一个优秀的教程，了解 Kubernetes 构建的基础。对于 Azure 版本，请参考*Kubernetes the Hard Way – Azure Translation*（[`github.com/ivanfioravanti/kubernetes-the-hard-way-on-azure`](https://github.com/ivanfioravanti/kubernetes-the-hard-way-on-azure)）。

## 处理节点故障

有意（为了节省成本）或无意中，节点可能会宕机。当这种情况发生时，您不希望在凌晨 3 点接到系统宕机的电话。Kubernetes 可以自动处理节点故障时的工作负载迁移。在这个练习中，我们将部署 guestbook 应用程序，并将在我们的集群中关闭一个节点，看看 Kubernetes 的响应是什么：

1.  确保您的集群至少有两个节点：

```
kubectl get nodes
```

这应该生成一个如*图 5.1*所示的输出：

![执行 kubectl get nodes 命令会显示一个带有两个节点的输出。这两个节点的状态为 Ready。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.1.jpg)

###### 图 5.1：确保您的集群中有两个正在运行的节点

如果您的集群中没有两个节点，请在 Azure 门户中查找您的集群，导航到**节点池**，然后单击**节点计数**。您可以将其扩展到**2**个节点，如*图 5.2*所示：

![单击 Azure 门户左侧的导航窗格中的节点池选项卡。这将显示给您几个选项。转到节点计数选项。单击它以将此计数扩展到两个节点。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.2.jpg)

###### 图 5.2：扩展集群

1.  作为本章的示例应用程序，我们将使用 guestbook 应用程序。部署此应用程序的 YAML 文件已在本章的源代码中提供（`guestbook-all-in-one.yaml`）。要部署 guestbook 应用程序，请使用以下命令：

```
kubectl create -f guestbook-all-in-one.yaml
```

1.  我们将再次为服务提供公共 IP，就像在之前的章节中一样。要开始编辑，请执行以下命令：

```
kubectl edit service frontend
```

1.  这将打开一个`vi`环境。导航到现在显示为`type: ClusterIP`（第 27 行）的行，并将其更改为`type: LoadBalancer`。要进行更改，请按*I*按钮进入插入模式，输入更改，然后按*Esc*按钮，输入`:wq!`，然后按*Enter*保存更改。

1.  更改保存后，您可以观察`service`对象，直到公共 IP 变为可用。要做到这一点，请输入以下内容：

```
kubectl get svc -w
```

1.  这将花费几分钟的时间来显示更新后的 IP。*图 5.3*代表了服务的公共 IP。一旦您看到正确的公共 IP，您可以通过按*Ctrl* + *C*（Mac 上为*command* + *C*）退出 watch 命令：![输出显示前端服务将其外部 IP 从<pending>更改为实际 IP。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.3.jpg)

###### 图 5.3：获取服务的公共 IP

1.  转到`http://<EXTERNAL-IP>`，如*图 5.4*所示：![一旦在浏览器的地址栏中输入公共 IP，它将打开一个带有粗体字“Guestbook”的白屏。这表明您的应用程序现在正在运行。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.4.jpg)

###### 图 5.4：确保应用程序正在运行

1.  让我们看看当前正在运行的 Pods 使用以下代码：

```
kubectl get pods -o wide
```

这将生成如*图 5.5*所示的输出：

![当您执行 kubectl get pods -o wide 命令时，显示的输出将显示 Pods 分布在节点 0 和 1 之间。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.5.jpg)

###### 图 5.5：我们的 Pods 分布在节点 0 和节点 1 之间

这显示我们的工作负载分布在节点 0 和节点 1 之间。

1.  在这个例子中，我们想演示 Kubernetes 如何处理节点故障。为了演示这一点，我们将关闭集群中的一个节点。在这种情况下，我们要造成最大的破坏，所以让我们关闭节点 1（您可以选择任何节点 - 出于说明目的，这并不重要）：

要关闭此节点，请在 Azure 搜索栏中查找我们集群中的`虚拟机规模集`，如*图 5.6*所示：

请在 Azure 搜索栏中键入 vmss 以关闭节点。

###### 图 5.6：查找托管集群的 VMSS

导航到规模集的刀片后，转到**实例**视图，选择要关闭的实例，然后点击**分配**按钮，如*图 5.7*所示：

![单击 Azure 门户中导航窗格中的“实例”选项卡。这将显示实例的数量。选择要关闭的实例。单击出现在地址栏中的取消分配图标。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.7.jpg)

###### 图 5.7：关闭节点 1

这将关闭我们的节点。要查看 Kubernetes 如何与您的 Pods 交互，可以通过以下命令观察集群中的 Pods：

```
kubectl get pods -o wide -w
```

1.  要验证您的应用程序是否可以继续运行，可以选择运行以下命令，每 5 秒钟点击一次 guestbook 前端并获取 HTML。建议在新的 Cloud Shell 窗口中打开此命令：

```
while true; do curl -m 1 http://<EXTERNAl-IP>/ ; sleep 5; done
```

#### 注意

上述命令将一直调用您的应用程序，直到您按下*Ctrl* + *C*（Mac 上的*command* + *C*）。可能会有间歇时间您收不到回复，这是可以预期的，因为 Kubernetes 需要几分钟来重新平衡系统。

添加一些留言板条目，看看当你导致节点关闭时它们会发生什么。这将显示一个如*图 5.8*所示的输出：

![使用留言板应用程序写下几条消息。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.8.jpg)

###### 图 5.8：在留言板中写下几条消息

你所看到的是你所有珍贵的消息都消失了！这显示了在节点故障的情况下拥有**PersistentVolumeClaims**（**PVCs**）对于任何你希望存活的数据的重要性，在我们的应用程序中并非如此。你将在本章的最后一节中看到一个例子。

1.  过一会儿，观察 Pods 的输出应该显示额外的输出，告诉你 Pods 已经在健康的主机上重新调度，如*图 5.9*所示：![这将显示一个输出，显示了从失败节点重新创建的 Pods。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.9.jpg)

###### 图 5.9：从失败节点重新创建的 Pods

你在这里看到的是：

+   一个前端 Pod 在主机 1 上运行时被终止，因为主机变得不健康。

+   一个新的前端 Pod 被创建在主机 0 上。这经历了**Pending**、**ContainerCreating**，然后是**Running**这些阶段。

#### 注意

Kubernetes 在重新调度 Pods 之前察觉到主机不健康。如果你运行`kubectl get nodes`，你会看到节点 1 处于`NotReady`状态。Kubernetes 中有一个叫做 pod-eviction-timeout 的配置，它定义了系统等待在健康主机上重新调度 Pods 的时间。默认值是 5 分钟。

在本节中，你学会了 Kubernetes 如何自动处理节点故障，通过在健康节点上重新创建 Pods。在下一节中，你将学习如何诊断和解决资源耗尽的问题。

## 解决资源耗尽的问题

Kubernetes 集群可能出现的另一个常见问题是集群资源耗尽。当集群没有足够的 CPU 或内存来调度额外的 Pods 时，Pods 将被卡在`Pending`状态。

Kubernetes 使用`requests`来计算某个 Pod 需要多少 CPU 或内存。我们的留言板应用程序为所有部署定义了请求。如果你打开`guestbook-all-in-one.yaml`文件，你会看到`redis-slave`部署的以下内容：

```
...
63  kind: Deployment
64  metadata:
65    name: redis-slave
...
83          resources:
84            requests:
85              cpu: 100m
86              memory: 100Mi
...
```

本节解释了`redis-slave`部署的每个 Pod 都需要`100m`的 CPU 核心（100 毫或 10%）和 100MiB（Mebibyte）的内存。在我们的 1 个 CPU 集群（关闭节点 1），将其扩展到 10 个 Pods 将导致可用资源出现问题。让我们来看看这个：

#### 注意

在 Kubernetes 中，您可以使用二进制前缀表示法或基数 10 表示法来指定内存和存储。二进制前缀表示法意味着使用 KiB（kibibyte）表示 1024 字节，MiB（mebibyte）表示 1024 KiB，Gib（gibibyte）表示 1024 MiB。基数 10 表示法意味着使用 kB（kilobyte）表示 1000 字节，MB（megabyte）表示 1000 kB，GB（gigabyte）表示 1000 MB。

1.  让我们首先将`redis-slave`部署扩展到 10 个 Pods：

```
kubectl scale deployment/redis-slave --replicas=10
```

1.  这将导致创建一对新的 Pod。我们可以使用以下命令来检查我们的 Pods：

```
kubectl get pods
```

这将生成以下输出：

![使用 kubectl get pods 命令，您可以检查您的 Pods。输出将生成一些状态为 Pending 的 Pods。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.10.jpg)

###### 图 5.10：如果集群资源不足，Pods 将进入 Pending 状态

这里突出显示了一个处于`Pending`状态的 Pod。

1.  我们可以使用以下命令获取有关这些待处理 Pods 的更多信息：

```
kubectl describe pod redis-slave-<pod-id>
```

这将显示更多细节。在`describe`命令的底部，您应该看到类似于*图 5.11*中显示的内容：

![输出显示了来自 default-scheduler 的 FailedSchedulingmessage 事件。详细消息显示“0/2 个节点可用：1 个 CPU 不足，1 个节点有 Pod 无法容忍的污点。”](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.11.jpg)

###### 图 5.11：Kubernetes 无法安排此 Pod

它向我们解释了两件事：

+   其中一个节点的 CPU 资源已经用完。

+   其中一个节点有一个 Pod 无法容忍的污点。这意味着`NotReady`的节点无法接受 Pods。

1.  我们可以通过像*图 5.12*中所示的方式启动节点 1 来解决这个容量问题。这可以通过类似于关闭过程的方式完成：![您可以使用与关闭相同的过程来启动节点。单击导航窗格中的实例选项卡。选择要启动的节点。最后，单击工具栏中的“启动”按钮。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.12.jpg)

###### 图 5.12：重新启动节点 1

1.  其他节点再次在 Kubernetes 中变得可用需要几分钟的时间。如果我们重新执行先前 Pod 上的`describe`命令，我们将看到类似于*图 5.13*所示的输出：![描述 Pod 的事件输出显示，经过一段时间，调度程序将 Pod 分配给新节点，并显示拉取图像的过程，以及创建和启动容器的过程。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.13.jpg)

###### 图 5.13：当节点再次可用时，其他 Pod 将在新节点上启动。

这表明在节点 1 再次变得可用后，Kubernetes 将我们的 Pod 调度到该节点，然后启动容器。

在本节中，我们学习了如何诊断资源不足的错误。我们通过向集群添加另一个节点来解决了这个错误。在我们继续进行最终故障模式之前，我们将清理一下 guestbook 部署。

#### 注意

在*第四章*中，*扩展您的应用程序*，我们讨论了集群自动缩放器。集群自动缩放器将监视资源不足的错误，并自动向集群添加新节点。

让我们通过运行以下`delete`命令来清理一下：

```
kubectl delete -f guestbook-all-in-one.yaml
```

到目前为止，我们已经讨论了 Kubernetes 集群中节点的两种故障模式。首先，我们讨论了 Kubernetes 如何处理节点离线以及系统如何将 Pod 重新调度到工作节点上。之后，我们看到了 Kubernetes 如何使用请求来调度节点上的 Pod，以及当集群资源不足时会发生什么。在接下来的部分，我们将讨论 Kubernetes 中的另一种故障模式，即当 Kubernetes 移动带有 PVC 的 Pod 时会发生什么。

## 修复存储挂载问题

在本章的前面，您注意到当 Redis 主节点移动到另一个节点时，guestbook 应用程序丢失了数据。这是因为该示例应用程序没有使用任何持久存储。在本节中，我们将介绍当 Kubernetes 将 Pod 移动到另一个节点时，如何使用 PVC 来防止数据丢失的示例。我们将向您展示 Kubernetes 移动带有 PVC 的 Pod 时会发生的常见错误，并向您展示如何修复此错误。

为此，我们将重用上一章中的 WordPress 示例。在开始之前，让我们确保集群处于干净的状态：

```
kubectl get all
```

这向我们展示了一个 Kubernetes 服务，如*图 5.14*所示：

![执行 kubectl get all 命令会生成一个输出，显示目前只有一个 Kubernetes 服务正在运行。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.14.jpg)

###### 图 5.14：目前您应该只运行 Kubernetes 服务

让我们还确保两个节点都在运行并且处于“就绪”状态：

```
kubectl get nodes
```

这应该显示我们两个节点都处于“就绪”状态，如*图 5.15*所示：

![现在您应该看到两个节点的状态都是 Ready。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.15.jpg)

###### 图 5.15：您的集群中应该有两个可用节点

在前面的示例中，在*处理节点故障*部分，我们看到如果 Pod 重新启动，存储在`redis-master`中的消息将丢失。原因是`redis-master`将所有数据存储在其容器中，每当重新启动时，它都会使用不带数据的干净镜像。为了在重新启动后保留数据，数据必须存储在外部。Kubernetes 使用 PVC 来抽象底层存储提供程序，以提供这种外部存储。

要开始此示例，我们将设置 WordPress 安装。

### 开始 WordPress 安装

让我们从安装 WordPress 开始。我们将演示其工作原理，然后验证在重新启动后存储是否仍然存在：

使用以下命令开始重新安装：

```
helm install wp stable/wordpress 
```

这将花费几分钟的时间来处理。您可以通过执行以下命令来跟踪此安装的状态：

```
kubectl get pods -w
```

几分钟后，这应该显示我们的 Pod 状态为`Running`，并且两个 Pod 的就绪状态为`1/1`，如*图 5.16*所示：

![使用 kubectl get pods -w 命令，您将看到 Pod 从 ContainerCreating 转换为 Running 状态，并且您将看到 Ready pods 的数量从 0/1 变为 1/1。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.16.jpg)

###### 图 5.16：几分钟后，所有 Pod 都将显示为运行状态

在本节中，我们看到了如何安装 WordPress。现在，我们将看到如何使用持久卷来避免数据丢失。

### 使用持久卷来避免数据丢失

**持久卷**（**PV**）是在 Kubernetes 集群中存储持久数据的方法。我们在*第三章*的*在 AKS 上部署应用程序*中更详细地解释了 PV。让我们探索为 WordPress 部署创建的 PV：

1.  在我们的情况下，运行以下`describe nodes`命令：

```
kubectl describe nodes
```

滚动查看输出，直到看到类似于*图 5.17*的部分。在我们的情况下，两个 WordPress Pod 都在节点 0 上运行：

![当您执行 kubectl describe nodes 命令时，您将看到指示两个 Pod 正在节点 0 上运行的信息。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.17.jpg)

###### 图 5.17：在我们的情况下，两个 WordPress Pod 都在节点 0 上运行

您的 Pod 放置可能会有所不同。

1.  我们可以检查的下一件事是我们的 PVC 的状态：

```
kubectl get pvc
```

这将生成一个如*图 5.18*所示的输出：

![输出显示了两个 PVC。除了它们的名称，您还可以看到这些 PVC 的状态、卷、容量和访问模式。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.18.jpg)

###### 图 5.18：WordPress 部署创建了两个 PVC

以下命令显示了绑定到 Pod 的实际 PV：

```
kubectl describe pv
```

这将向您显示两个卷的详细信息。我们将在*图 5.19*中向您展示其中一个：

使用 kubectl describe pvc 命令，您可以详细查看两个 PVC。图片突出显示了默认/data-wp-mariadb-0 的声明，并突出显示了 Azure 中的 diskURI。![使用 kubectl describe pvc 命令，您可以详细查看两个 PVC。图片突出显示了默认/data-wp-mariadb-0 的声明，并突出显示了 Azure 中的 diskURI。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.19.jpg)

###### 图 5.19：一个 PVC 的详细信息

在这里，我们可以看到哪个 Pod 声明了这个卷，以及 Azure 中的**DiskURI**是什么。

1.  验证您的网站是否实际在运行：

```
kubectl get service
```

这将显示我们的 WordPress 网站的公共 IP，如*图 5.20*所示：

![输出屏幕仅显示了 wp-WordPress 服务的 External-IP。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.20.jpg)

###### 图 5.20：获取服务的公共 IP

1.  如果您还记得*第三章*，*AKS 的应用部署*，Helm 向我们显示了获取 WordPress 网站管理员凭据所需的命令。让我们获取这些命令并执行它们以登录到网站，如下所示：

```
helm status wp
echo Username: user
echo Password: $(kubectl get secret --namespace default wp-wordpress -o jsonpath="{.data.wordpress-password}" | base64 -d)
```

这将向您显示`用户名`和`密码`，如*图 5.21*所示：

![输出显示如何通过 Helm 获取用户名和密码。截图中的用户名是 user，密码是 lcsUSJTk8e。在您的情况下，密码将不同。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.21.jpg)

###### 图 5.21：获取 WordPress 应用程序的用户名和密码

#### 注意

您可能会注意到，我们在书中使用的命令与`helm`返回的命令略有不同。`helm`为密码返回的命令对我们不起作用，我们为您提供了有效的命令。

我们可以通过以下地址登录到我们的网站：`http://<external-ip>/admin`。在这里使用前一步骤中的凭据登录。然后，您可以继续添加一篇文章到您的网站。点击**撰写您的第一篇博客文章**按钮，然后创建一篇简短的文章，如*图 5.22*所示：

![您将看到一个欢迎您来到 WordPress 的仪表板。在这里，您将看到一个按钮，上面写着-写下您的第一篇博客文章。单击它开始写作。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.22.jpg)

###### 图 5.22：撰写您的第一篇博客文章

现在输入一些文本，然后单击**发布**按钮，就像*图 5.23*中所示。文本本身并不重要；我们写这个来验证数据确实被保留到磁盘上：

![假设您随机输入了单词“测试”。在写完文字后，单击屏幕右上角的“发布”按钮。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.23.jpg)

###### 图 5.23：发布包含随机文本的文章

如果您现在转到您网站的主页`http://<external-ip>`，您将会看到您的测试文章，就像*图 5.23*中所示。我们将在下一节验证此文章是否经得起重启。

**处理涉及 PVC 的 Pod 故障**

我们将对我们的 PVC 进行的第一个测试是杀死 Pod 并验证数据是否确实被保留。为此，让我们做两件事：

1.  **观察我们应用程序中的 Pod**。为此，我们将使用当前的 Cloud Shell 并执行以下命令：

```
kubectl get pods -w
```

1.  杀死已挂载 PVC 的两个 Pod。为此，我们将通过单击工具栏上显示的图标创建一个新的 Cloud Shell 窗口，如*图 5.24*所示：![单击工具栏左侧花括号图标旁边的图标，单击以打开新的 Cloud Shell。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.24.jpg)

###### 图 24：打开新的 Cloud Shell 实例

一旦您打开一个新的 Cloud Shell，执行以下命令：

```
kubectl delete pod --all
```

如果您使用`watch`命令，您应该会看到类似于*图 5.25*所示的输出：

![运行 kubectl get pods -w 会显示旧的 Pod 被终止并创建新的 Pod。新的 Pod 会从 Pending 状态过渡到 ContainerCreating 再到 Running。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.25.jpg)

###### 图 5.25：删除 Pod 后，Kubernetes 将自动重新创建两个 Pod

正如您所看到的，Kubernetes 迅速开始创建新的 Pod 来从 Pod 故障中恢复。这些 Pod 经历了与原始 Pod 相似的生命周期，从**Pending**到**ContainerCreating**再到**Running**。

1.  如果您转到您的网站，您应该会看到您的演示文章已经被保留。这就是 PVC 如何帮助您防止数据丢失的方式，因为它们保留了容器本身无法保留的数据。

*图 5.26*显示，即使 Pod 被重新创建，博客文章仍然被保留：

![您可以看到您的数据被持久保存，带有“test”字样的博客帖子仍然可用。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.26.jpg)

###### 图 5.26：您的数据被持久保存，您的博客帖子仍然存在

在这里观察的最后一个有趣的数据点是 Kubernetes 事件流。如果运行以下命令，您可以看到与卷相关的事件：

```
kubectl get events | grep -i volume
```

这将生成如*图 5.27*所示的输出。

![输出屏幕将显示一个 FailedAttachVolume 警告。在其下方，它将显示状态现在正常，并带有 SuccessfulAttachVolume 消息。这表明 Kubernetes 最初无法挂载卷，但在下一次尝试时成功挂载了它。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.27.jpg)

###### 图 5.27：Kubernetes 处理了 FailedAttachVolume 错误

这显示了与卷相关的事件。有两条有趣的消息需要详细解释：`FailedAttachVolume`和`SuccessfulAttachVolume`。这向我们展示了 Kubernetes 如何处理具有 read-write-once 配置的卷。由于特性是只能从单个 Pod 中读取和写入，Kubernetes 只会在成功从当前 Pod 卸载卷后，将卷挂载到新的 Pod 上。因此，最初，当新的 Pod 被调度时，它显示了`FailedAttachVolume`消息，因为卷仍然附加到正在删除的 Pod 上。之后，Pod 成功挂载了卷，并通过`SuccessfulAttachVolume`消息显示了这一点。

在本节中，我们已经学习了 PVC 在 Pod 在同一节点上重新创建时可以起到的作用。在下一节中，我们将看到当节点发生故障时 PVC 的使用情况。

**使用 PVC 处理节点故障**

在前面的示例中，我们看到了 Kubernetes 如何处理具有 PV 附加的 Pod 故障。在这个示例中，我们将看看 Kubernetes 在卷附加时如何处理节点故障：

1.  让我们首先检查哪个节点托管了我们的应用程序，使用以下命令：

```
kubectl get pods -o wide
```

我们发现，在我们的集群中，节点 1 托管了 MariaDB，节点 0 托管了 WordPress 网站，如*图 5.28*所示：

![运行 kubectl get pods -o wide 会显示哪个 pod 在哪个节点上运行。在截图中，一个 pod 在每个主机上运行。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.28.jpg)

###### 图 5.28：我们的部署中有两个正在运行的 Pod - 一个在节点 1 上，一个在节点 0 上

1.  我们将引入一个故障，并停止可能会造成最严重损害的节点，即关闭 Azure 门户上的节点 0。我们将以与先前示例相同的方式进行。首先，查找支持我们集群的规模集，如*图 5.29*所示：![在 Azure 门户的搜索栏中键入 vmss 将显示托管您 AKS 集群的 VMSS 的完整名称。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.29.jpg)

###### 图 5.29：查找支持我们集群的规模集

1.  然后按照*图 5.30*中所示关闭节点：![要关闭节点，请在 Azure 门户中导航窗格中的“实例”选项卡上单击。您将看到两个节点。选择第一个节点，然后单击工具栏上的“停用”按钮。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.30.jpg)

###### 图 5.30：关闭节点

1.  完成此操作后，我们将再次观察我们的 Pod，以了解集群中正在发生的情况：

```
kubectl get pods -o wide -w
```

与先前的示例一样，Kubernetes 将在 5 分钟后开始采取行动来应对我们失败的节点。我们可以在*图 5.31*中看到这一情况：

![当您执行 kubectl get pods -o wide -w 命令时，您将看到状态为 Pending 的 Pod 未分配到节点。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.31.jpg)

###### 图 5.31：处于挂起状态的 Pod

1.  我们在这里遇到了一个新问题。我们的新 Pod 处于“挂起”状态，尚未分配到新节点。让我们弄清楚这里发生了什么。首先，我们将“描述”我们的 Pod：

```
kubectl describe pods/wp-wordpress-<pod-id>
```

您将得到一个如*图 5.32*所示的输出：

![您将看到此 Pod 处于挂起状态的原因的详细信息，这是由于 CPU 不足造成的。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.32.jpg)

###### 图 5.32：显示处于挂起状态的 Pod 的输出

1.  这表明我们的集群中没有足够的 CPU 资源来托管新的 Pod。我们可以使用`kubectl edit deploy/...`命令来修复任何不足的 CPU/内存错误。我们将将 CPU 请求从 300 更改为 3，以便我们的示例继续进行：

```
kubectl edit deploy wp-wordpress
```

这将带我们进入一个`vi`环境。我们可以通过输入以下内容快速找到与 CPU 相关的部分：

```
/cpu <enter>
```

一旦到达那里，将光标移动到两个零上，然后按两次`x`键删除零。最后，键入`:wq!`以保存我们的更改，以便我们可以继续我们的示例。

1.  这将导致创建一个新的 ReplicaSet 和一个新的 Pod。我们可以通过输入以下命令来获取新 Pod 的名称：

```
kubectl get pods 
```

查找状态为`ContainerCreating`的 Pod，如下所示：

![输出屏幕显示了四个具有不同状态的 Pod。查找具有 ContainerCreating 状态的 Pod。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.33.jpg)

###### 图 5.33：新的 Pod 被卡在 ContainerCreating 状态

1.  让我们用`describe`命令查看该 Pod 的详细信息：

```
kubectl describe pod wp-wordpress-<pod-id>
```

在这个`describe`输出的“事件”部分，您可以看到以下错误消息：

![在具有 ContainerCreating 状态的 Pod 上执行 kubectl describe 命令会显示一个详细的错误消息，其中包含 FailedMount 的原因。消息表示 Kubernetes 无法挂载卷。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.34.jpg)

###### 图 5.34：新的 Pod 有一个新的错误消息，描述了卷挂载问题

1.  这告诉我们，我们的新 Pod 想要挂载的卷仍然挂载到了被卡在“终止”状态的 Pod 上。我们可以通过手动从我们关闭的节点上分离磁盘并强制删除被卡在“终止”状态的 Pod 来解决这个问题。

#### 注意

处于“终止”状态的 Pod 的行为不是一个错误。这是默认的 Kubernetes 行为。Kubernetes 文档中指出：“Kubernetes（1.5 版本或更新版本）不会仅仅因为节点不可达而删除 Pods。在不可达节点上运行的 Pods 在超时后进入“终止”或“未知”状态。当用户尝试在不可达节点上优雅地删除 Pod 时，Pods 也可能进入这些状态。”您可以在[`kubernetes.io/docs/tasks/run-application/force-delete-stateful-set-pod/`](https://kubernetes.io/docs/tasks/run-application/force-delete-stateful-set-pod/)阅读更多内容。

1.  为此，我们需要规模集的名称和资源组的名称。要找到这些信息，请在门户中查找规模集，如*图 5.35*所示：![在 Azure 搜索栏中键入 vmss 以查找支持您集群的 ScaleSet](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.35.jpg)

###### 图 5.35：查找支持您集群的规模集

1.  在规模集视图中，复制并粘贴规模集名称和资源组。编辑以下命令以从失败的节点分离磁盘，然后在 Cloud Shell 中运行此命令：

```
az vmss disk detach --lun 0 --vmss-name <vmss-name> -g <rgname> --instance-id 0
```

1.  这将从节点 0 中分离磁盘。这里需要的第二步是在 Pod 被卡在终止状态时，强制将其从集群中移除：

```
kubectl delete pod wordpress-wp-<pod-id> --grace-period=0 --force
```

1.  这将使我们的新 Pod 恢复到健康状态。系统需要几分钟来接受更改，然后挂载和调度新的 Pod。让我们再次使用以下命令获取 Pod 的详细信息：

```
kubectl describe pod wp-wordpress-<pod-id>
```

这将生成以下输出：

![输出将显示两个 Pod 的事件类型为 Normal。原因是 SuccessfulAttachVolume 和 Pulled 的第二个 Pod。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.36.jpg)

###### 图 5.36：我们的新 Pod 现在正在挂载卷并拉取容器镜像

1.  这表明新的 Pod 成功挂载了卷，并且容器镜像已被拉取。让我们验证一下 Pod 是否真的在运行：

```
kubectl get pods
```

这将显示 Pod 正在运行，如*图 5.37*所示：

![两个 Pod 的状态为 Running。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.37.jpg)

###### 图 5.37：两个 Pod 都成功运行

这将使您的 WordPress 网站再次可用。

在继续之前，让我们使用以下命令清理我们的部署：

```
helm delete wp
kubectl delete pvc --all
kubectl delete pv --all
```

让我们还重新启动关闭的节点，如*图 5.38*所示：

![要重新启动关闭的节点，请单击导航窗格中的实例选项卡。选择已分配/已停止的节点。单击搜索栏旁边的工具栏中的启动按钮。您的节点现在应该已重新启动。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_5.38.jpg)

###### 图 5.38：重新启动节点 1

在本节中，我们介绍了当 PVC 未挂载到新的 Pod 时，您如何从节点故障中恢复。我们需要手动卸载磁盘，然后强制删除处于`Terminating`状态的 Pod。

## 总结

在本章中，您了解了常见的 Kubernetes 故障模式以及如何从中恢复。我们从一个示例开始，介绍了 Kubernetes 如何自动检测节点故障并启动新的 Pod 来恢复工作负载。之后，您扩展了工作负载，导致集群资源耗尽。您通过重新启动故障节点来为集群添加新资源，从这种情况中恢复了过来。

接下来，您看到了 PV 是如何有用地将数据存储在 Pod 之外的。您关闭了集群上的所有 Pod，并看到 PV 确保应用程序中没有数据丢失。在本章的最后一个示例中，您看到了当 PV 被附加时，您如何从节点故障中恢复。您通过从节点卸载磁盘并强制删除终止的 Pod 来恢复工作负载。这将使您的工作负载恢复到健康状态。

本章已经解释了 Kubernetes 中常见的故障模式。在下一章中，我们将为我们的服务引入 HTTPS 支持，并介绍与 Azure 活动目录的身份验证。


# 第六章：使用 HTTPS 和 Azure AD 保护您的应用程序

HTTPS 已经成为任何面向公众的网站的必需品。它不仅提高了网站的安全性，而且还成为新的浏览器功能的要求。HTTPS 是 HTTP 协议的安全版本。HTTPS 利用**传输层安全**（**TLS**）证书来加密终端用户和服务器之间的流量，或者两个服务器之间的流量。TLS 是**安全套接字层**（**SSL**）的后继者。术语*TLS*和*SSL*经常可以互换使用。

过去，您需要从**证书颁发机构**（**CA**）购买证书，然后在您的 Web 服务器上设置它们，并定期更新它们。虽然今天仍然可能，但 Let's Encrypt 服务和 Kubernetes 中的助手使在集群中设置经过验证的 TLS 证书变得非常容易。Let's Encrypt 是由互联网安全研究组织运营并得到多家公司支持的非营利组织。它是一个提供自动验证 TLS 证书的免费服务。自动化是 Let's Encrypt 服务的一个关键优势。

在 Kubernetes 助手方面，我们将介绍一个名为**Ingress**的新对象，并且我们将使用一个名为**cert-manager**的 Kubernetes 附加组件。Ingress 是 Kubernetes 中管理对服务的外部访问的对象。Ingress 通常用于 HTTP 服务。Ingress 在我们在*第三章，AKS 上的应用部署*中解释的服务对象之上添加了额外的功能。Ingress 可以配置为处理 HTTPS 流量。它还可以根据由用于连接的**域名系统**（**DNS**）分配的主机名配置为将流量路由到不同的后端服务。

`cert-manager`是一个 Kubernetes 附加组件，可帮助自动创建 TLS 证书。它还可以在证书临近到期时帮助进行轮换。`cert-manager`可以与 Let's Encrypt 接口自动请求证书。

在本章中，我们将看到如何设置 Ingress 和`cert-manager`与 Let's Encrypt 接口。

此外，在本章中，我们将探讨为 guestbook 应用程序进行身份验证的不同方法。我们将使用`oauth2_proxy`反向代理来向示例 guest 应用程序添加 Azure Active Directory（AD）的身份验证。`oauth2_proxy`是一个反向代理，将身份验证请求转发到配置身份验证平台。您将学习如何轻松地保护没有内置身份验证的应用程序。身份验证方案可以扩展为使用 GitHub、Google、GitLab、LinkedIn 或 Facebook。

本章将涵盖以下主题：

+   在服务前设置 Ingress

+   为 Ingress 添加 TLS 支持

+   身份验证和常见身份验证提供程序

+   身份验证与授权

+   部署`oauth2_proxy` sidecar

让我们从设置 Ingress 开始。

## HTTPS 支持

传统上，获取 TLS 证书一直是一项昂贵且繁琐的业务。如果您想以低成本完成，可以自行签署证书，但浏览器在打开您的网站时会抱怨并将其标识为不受信任。Let's Encrypt 改变了这一切。Let's Encrypt 是一个免费、自动化和开放的 CA，为公众利益而运行。它为人们提供数字证书，以便免费以最用户友好的方式为网站启用 HTTPS（SSL/TLS）。

#### 注意

尽管本节侧重于使用诸如 Let's Encrypt 之类的自动化服务，您仍然可以选择传统的方式从现有 CA 购买证书并将其导入 Kubernetes。

### 安装 Ingress 控制器

通过 Ingress 对象，Kubernetes 提供了一种安全地公开您的服务的清晰方式。它提供了 SSL 终端点和基于名称的路由，这意味着不同的 DNS 名称可以路由到不同的后端服务。

如果您想在集群中创建 Ingress 对象，首先需要设置 Ingress 控制器。Ingress 控制器将管理您在集群中部署的 Ingresses 的状态。在选择 Ingress 控制器时有多个选项。有关所有选项的完整列表，请参阅[`kubernetes.io/docs/concepts/services-networking/ingress-controllers/`](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/)。在运行 AKS 时，最常见的两个选项要么使用基于 NGINX 的 Ingress 控制器，要么使用基于 Azure 应用程序网关的 Ingress 控制器。在我们的示例中，我们将使用 NGINX 版本。

让我们继续安装 Ingress 控制器的 NGINX 版本，执行以下步骤：

1.  要跟着操作，请在 Cloud Shell 的 Bash 版本中运行此示例。

1.  输入以下命令开始安装：

```
helm repo add stable https://kubernetes-charts.storage.googleapis.com/ 
helm install ingress stable/nginx-ingress
```

这将为我们的集群设置 Ingress 控制器。这还将创建一个我们将用于访问 Ingress 控制器的公共 IP。

1.  让我们连接到 Ingress 控制器。要获取`ingress-controller`服务的公开 IP，请输入此命令：

```
kubectl get service 
```

您应该看到 Ingress 控制器的条目，如*图 6.1*所示：

![您的输出屏幕将显示三个条目。在这三个条目中，Ingress 控制器将显示一个外部 IP。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.1.jpg)

###### 图 6.1：获取 Ingress 控制器的 IP

您可以在浏览器中输入`http://<EXTERNAL-IP>`来浏览网页：

![您的输出屏幕将显示三个条目。在这三个条目中，Ingress 控制器将显示一个外部 IP。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.2.jpg)

###### 图 6.2：显示其默认后端的 Ingress

这向您展示了两件事：

1.  没有后端应用程序，只有一个默认应用程序。

1.  网站通过 HTTP 提供服务，而不是 HTTPS（因此会出现**不安全**警告）。

在接下来的两个部分中，我们将解决这两个问题。我们将首先为我们的留言板应用程序创建一个 Ingress 规则，然后我们将通过 Let's Encrypt 添加 HTTPS 支持。

### 为留言板应用程序添加 Ingress 规则

让我们从重新启动我们的留言板应用程序开始。要启动留言板应用程序，请输入以下命令：

```
kubectl create -f guestbook-all-in-one.yaml
```

这将创建我们信任的留言板应用程序。您应该看到对象被创建，如*图 6.3*所示：

![执行 kubectl create -f guestbook-all-in-one.yaml 命令后，您的输出屏幕将显示所有对象都已创建。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.3.jpg)

###### 图 6.3：创建留言板应用程序

然后，我们可以使用以下 YAML 文件通过 Ingress 公开前端服务。这在本章的源代码中提供为`simple-frontend-ingress.yaml`：

```
1   apiVersion: extensions/v1beta1
2   kind: Ingress
3   metadata:
4     name: simple-frontend-ingress
5   spec:
6     rules:
7     - http:
8         paths:
9         - path: /
10          backend:
11            serviceName: frontend
12            servicePort: 80
```

让我们看看我们在这个 YAML 文件中定义了什么：

+   **第 2 行**：在这里，我们定义了我们正在创建一个 Ingress 对象的事实。

+   **第 5-12 行**：这些行定义了 Ingress 的配置。特别注意：

+   **第 9 行**：在这里，我们定义了此 Ingress 正在侦听的路径。在我们的情况下，这是顶级路径。在更高级的情况下，您可以有不同的路径指向不同的服务。

+   **第 10-12 行**：这些行定义了应将此流量指向的实际服务。

我们可以使用以下命令创建此 Ingress：

```
kubectl apply -f simple-frontend-ingress.yaml 
```

如果您现在转到`https://<EXTERNAL-IP>/`，您应该会得到如*图 6.4*所示的输出：

![当您在浏览器中输入公共 IP 地址时，它将显示一个带有 Guestbook 字样的白屏。这表明通过 Ingress 可以访问 guestbook 应用程序。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.4.jpg)

###### 图 6.4：通过 Ingress 访问 guestbook 应用程序

请注意以下内容：我们不必像在前面的章节中那样公开暴露前端服务。我们已将 Ingress 添加为公开服务，前端服务仍然对集群保密：

![用户可以访问 Ingress，而服务和前端 pod 保持私密。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.5.jpg)

###### 图 6.5：显示可公开访问的 Ingress 的流程图

您可以通过运行以下命令来验证这一点：

```
kubectl get svc
```

这应该只显示一个公共服务：

![运行 kubectl get svc 命令后，您将看到共有六个服务，只有 Ingress 控制器提供了外部 IP。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.6.jpg)

###### 图 6.6：仅显示具有公共 IP 的 Ingress 的输出

在本节中，您已经启动了一个 guestbook 应用程序的实例。您通过创建 Ingress 将其公开。只有 Ingress 是公开访问的。在下一节中，我们将看到如何从 Let's Encrypt 获取证书。

### 从 Let's Encrypt 获取证书

在本节中，我们将为我们的应用程序添加 HTTPS 支持。为此，我们需要一个 TLS 证书。我们将使用`cert-manager` Kubernetes 附加组件从 Let's Encrypt 请求证书。涉及几个步骤。将 HTTPS 添加到我们的应用程序的过程涉及以下步骤：

1.  安装`cert-manager`，它与 Let's Encrypt API 接口，以请求您指定的域名的证书。

1.  将**Azure 完全合格的域名**（**FQDN**）映射到 NGINX Ingress 公共 IP。 FQDN 是服务的完整 DNS 名称，有时称为 DNS 记录，例如`www.google.com`。 为 FQDN 颁发 TLS 证书，这就是为什么我们需要为我们的 Ingress 映射一个 FQDN。

1.  安装证书颁发者，该颁发者将从 Let's Encrypt 获取证书。

1.  为给定的 FQDN 创建 SSL 证书。

1.  通过创建 Ingress 到在*步骤 4*中创建的证书的服务来保护前端服务部分。在我们的示例中，我们不会执行此步骤。但是，我们将重新配置我们的 Ingress 以自动获取在*步骤 4*中创建的证书。

让我们从第一步开始；在我们的集群中安装`cert-manager`。

**安装 cert-manager**

获取 TLS 证书的第一步是在您的集群中安装`cert-manager`。`cert-manager` ([`github.com/jetstack/cert-manager`](https://github.com/jetstack/cert-manager))自动管理和发放来自各种发放源的 TLS 证书。这是由公司**Jetstack**管理的开源解决方案。续订证书和确保它们定期更新都由`cert-manager`管理，这是一个 Kubernetes 附加组件。

以下命令在您的集群中安装`cert-manager`：

```
kubectl create ns cert-manager
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager --namespace cert-manager jetstack/cert-manager
```

这些命令在您的集群中执行了一些操作：

1.  创建一个新的**命名空间**。命名空间在 Kubernetes 中用于隔离彼此的工作负载。

1.  向 Helm 添加一个新的存储库以获取图表。

1.  安装`cert-manager` Helm 图表。

现在您已经安装了`cert-manager`，我们可以继续下一步：将 FQDN 映射到 Ingress。

**将 Azure FQDN 映射到 NGINX Ingress 公共 IP**

获取 TLS 证书过程的下一步是将 FQDN 添加到您的 IP 地址。Let's Encrypt 需要一个公开可用的 DNS 条目来验证 DNS 条目的所有权*之前*发放证书。这确保您不能劫持别人的站点。我们必须将 Azure 给我们的公共域名映射到我们从 Azure 负载均衡器获取的外部 IP，以证明所有权。

以下步骤将帮助我们将 DNS 条目链接到我们的公共 IP：

1.  让我们继续将 DNS 名称链接到我们的公共 IP 地址。首先，请确保从您的 Ingress 服务获取 IP 地址：

```
kubectl get service
```

记下 Ingress 服务的 IP。在 Azure 搜索栏中，现在搜索`public ip`：

![在 Azure 搜索栏中键入公共 IP 并选择“公共 IP 地址”](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.7.jpg)

###### 图 6.7：在 Azure 搜索栏中搜索公共 IP

1.  一旦到达那里，您应该会看到许多公共 IP 地址。要找到我们的公共 IP 地址，您可以在这里显示一个额外的列，该列将显示实际的 IP 地址。点击“编辑列”按钮添加额外的列：![当您从 Azure 门户上的默认目录页面找到您的公共 IP 时，点击页面顶部的“编辑列”按钮。这将打开列选择器。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.8.jpg)

###### 图 6.8：点击“编辑列”以添加额外的列

1.  在列选择器中，选择“IP 地址”，然后点击向右的箭头，如*图 6.9*所示：![要将 IP 地址添加到所选列中，请点击“可用列”导航窗格中的 IP 地址选项卡。接下来，点击位于页面中央的向右的箭头。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.9.jpg)

###### 图 6.9：将 IP 地址添加到所选列

1.  点击“应用”以显示实际的 IP 地址。当您看到您的 IP 地址时，请点击它。在您的 IP 地址的窗格中，进入“配置”视图。然后，输入一个*唯一*的 DNS 名称，然后点击“保存”：![打开您的 IP 地址。点击导航窗格中的“配置”选项卡。输入 DNS 的唯一名称，然后点击搜索栏旁边的保存按钮。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.10.jpg)

###### 图 6.10：添加一个唯一的 DNS 名称标签并保存配置

现在您已经有了与您的公共 IP 地址相关联的 DNS 记录。接下来，您将在集群中安装证书颁发机构。

**安装证书颁发机构**

在本节中，我们将安装 Let's Encrypt 的 staging 证书颁发机构。一个证书可以由多个颁发机构颁发。例如，`letsencrypt-staging`是用于测试目的。由于我们正在构建测试，我们将使用 staging 服务器。证书颁发机构的代码已经在本章的源代码中提供在`certificate-issuer.yaml`文件中。像往常一样，使用`kubectl create -f certificate-issuer.yaml`，其中包含以下内容：

```
1   apiVersion: cert-manager.io/v1alpha2
2   kind: Issuer
3   metadata:
4     name: letsencrypt-staging
5   spec:
6     acme:
7       server: https://acme-staging-v02.api.letsencrypt.org/directory
8       email: <your e-mailaddress>
9       privateKeySecretRef:
10        name: letsencrypt-staging
11      solvers:
12      - http01:
13          ingress:
14            class: nginx
```

现在，让我们看看我们在这里定义了什么：

+   **第 1-2 行**：在这里，我们使用了我们之前安装的**CustomResourceDefinition**（**CRD**）。CRD 是扩展 Kubernetes API 服务器以创建自定义资源的一种方式，比如证书颁发机构。在这种情况下，我们特别指向了我们注入到 Kubernetes API 中的`cert-manager` API CRD，并创建了一个`Issuer`对象。

+   **第 6-10 行**：我们在这些行中提供了 Let's Encrypt 的配置，并指向了 staging 服务器。

+   **第 11-14 行**：这是用于 ACME 客户端认证域名所有权的附加配置。

安装了证书颁发者后，我们现在可以进行下一步：创建 TLS 证书。

**创建 TLS 证书并保护我们的服务**

在本节中，我们将创建一个 TLS 证书。您可以通过两种方式配置`cert-manager`来创建证书。您可以手动创建证书并将其链接到 Ingress 控制器，或者您可以配置 Ingress 控制器，以便`cert-manager`自动创建证书。在本例中，我们将向您展示第二种方法，即通过编辑我们的 Ingress 来使其看起来像以下的 YAML 代码。此文件在 GitHub 上的源代码中存在，名称为`ingress-with-tls.yaml`：

```
1   apiVersion: extensions/v1beta1
2   kind: Ingress
3   metadata:
4     name: simple-frontend-ingress
5     annotations:
6       cert-manager.io/issuer: "letsencrypt-staging"
7   spec:
8     tls:
9     - hosts:
10      - <your DNS prefix>.<your azure region>.cloudapp.azure.com
11      secretName: frontend-tls
12    rules:
13    - host: <your DNS prefix>.<your Azure location>.cloudapp.azure.com
14      http:
15        paths:
16        - path: /
17          backend:
18            serviceName: frontend
19            servicePort: 80
```

我们对原始 Ingress 进行了以下更改：

+   **第 6 行**：我们已经在 Ingress 上添加了一个指向证书颁发者的注释。

+   **第 10 行和第 13 行**：我们在这里添加了 Ingress 的域名。这是必需的，因为 Let's Encrypt 只为域名颁发证书。

+   **第 11 行**：这是将用于存储我们的证书的密钥的名称。

您可以使用以下命令更新我们之前创建的 Ingress：

```
kubectl apply -f ingress-with-tls.yaml
```

`cert-manager`大约需要一分钟来请求证书并配置我们的 Ingress 以使用该证书。在等待期间，让我们来看看`cert-manager`代表我们创建的中间资源。

首先，`cert-manager`为我们创建了一个`certificate`对象。我们可以使用以下命令查看该对象的状态：

```
kubectl get certificate
```

执行此命令将生成一个输出，如*图 6.11*所示：

![当执行 kubectl get certificate 命令时，您应该看到对象的状态为 False。这表示证书尚未准备就绪。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.11.jpg)

###### 图 6.11：显示证书状态的输出

如您所见，我们的证书尚未准备就绪。`cert-manager`创建了另一个对象来实际获取证书。这个对象是`certificaterequest`。我们可以使用以下命令获取其状态：

```
kubectl get certificaterequest
```

这将生成如*图 6.12*所示的输出：

![接下来，当执行 kubectl get certificaterequest 命令时，这也显示对象的状态为 False。这表示证书请求对象尚未准备就绪。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.12.jpg)

###### 图 6.12：输出显示证书请求对象的状态为 False

我们还可以通过针对`certificaterequest`对象发出`describe`命令来获取有关请求的更多详细信息：

```
kubectl describe certificaterequest
```

当我们在等待证书签发时，状态将类似于*图 6.13*：

![使用 kubectl describe certificaterequest 命令，您可以获取有关 certificaterequest 对象的更多详细信息，指示状态为 False。它显示一条消息说“创建了订单资源 default/frontend-tls-<随机 ID>”。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.13.jpg)

###### 图 6.13：提供有关 certificaterequest 对象的更多详细信息的输出

如果我们再给它几秒钟，`describe`命令应该会返回一个成功创建证书的消息，如*图 6.14*所示：

![几秒钟后，您将看到详细信息已更新，状态更改为 True。有一条消息说“成功从签发者获取证书”，这意味着证书现在已签发。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.14.jpg)

###### 图 6.14：显示已签发证书的输出

现在，这应该可以使我们的前端 Ingress 通过 HTTPS 提供服务。让我们在浏览器中尝试一下，浏览到您在映射 FQDN 部分创建的 DNS 名称。这将在浏览器中显示错误，显示证书无效，如*图 6.15*所示。这是可以预期的，因为我们正在使用 Let's Encrypt 临时服务：

![屏幕将显示一条消息，说明您的连接不是私密的。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.15.jpg)

###### 图 6.15：使用 Let's Encrypt 临时服务器，我们的证书默认不受信任

您可以通过单击**高级**并选择**继续**来浏览到您的应用程序。

由于我们能够完成临时证书的测试，现在我们可以转向生产环境。

**从临时切换到生产**

在本节中，我们将从临时证书切换到生产级证书。要做到这一点，您可以通过在集群中创建一个新的签发者来重新执行上一个练习，就像以下所示（在`certificate-issuer-prod.yaml`中提供）。不要忘记在文件中更改您的电子邮件地址：

```
1   apiVersion: cert-manager.io/v1alpha2
2   kind: Issuer
3   metadata:
4     name: letsencrypt-prod
5   spec:
6     acme:
7       server: https://acme-v02.api.letsencrypt.org/directory
8       email: <your e-mail>
9       privateKeySecretRef:
10        name: letsencrypt-staging
11      solvers:
12      - http01:
13          ingress:
14            class: nginx
```

然后将`ingress-with-tls.yaml`文件中对签发者的引用替换为`letsencrypt-prod`，就像这样（在`ingress-with-tls-prod.yaml`文件中提供）：

```
1   apiVersion: extensions/v1beta1
2   kind: Ingress
3   metadata:
4     name: simple-frontend-ingress
5     annotations:
6       cert-manager.io/issuer: "letsencrypt-prod"
7   spec:
8     tls:
9     - hosts:
10      - <your dns prefix>.<your azure region>.cloudapp.azure.com
11      secretName: frontend-tls
12    rules:
13    - host: <your dns prefix>.<your azure region>.cloudapp.azure.com
14      http:
15        paths:
16        - path: /
17          backend:
18            serviceName: frontend
19            servicePort: 80
```

要应用这些更改，请执行以下命令：

```
kubectl create -f certificate-issuer-prod.yaml
kubectl apply -f ingress-with-tls-prod.yaml
```

证书再次生效大约需要一分钟。一旦新证书发放，您可以再次浏览到您的 DNS 名称，并且不应该再看到关于无效证书的警告。如果您单击浏览器中的挂锁项目，您应该会看到您的连接是安全的，并使用有效的证书。

![单击浏览器地址栏上的挂锁图标将告诉您连接是安全的。这个弹出窗口还会让您知道证书是有效的。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.16.jpg)

###### 图 6.16：显示有效证书的网页

在本节中，我们介绍了两个新概念：首先，我们为我们的留言板应用程序添加了一个 Ingress。我们首先在集群上设置了一个 Ingress 控制器，然后为我们的留言板应用程序设置了 Ingress。Ingress 允许在 Kubernetes 之上为应用程序进行高级路由和 HTTPS 卸载。之后，我们为我们的留言板应用程序添加了 HTTPS。我们不需要更改应用程序本身的源代码；通过配置我们的 Ingress，我们能够添加 HTTPS 支持。

在接下来的部分，我们将为我们的应用程序添加另一个安全层。我们将为我们的应用程序添加认证。在深入讨论之前，让我们首先讨论一下关于认证和授权的常见误解。

## 认证与授权

**认证**（**AuthN**）经常与**授权**（**AuthZ**）混淆。认证涉及身份（你是谁？），通常需要一个受信任的身份提供者。存在多个提供者，如 Azure AD、Okta 或 GitHub，甚至社交媒体平台如 Facebook、Google 或 Twitter 也可以用作提供者。授权涉及权限（你想做什么？），在应用程序资源需要受保护方面非常具体。

通常需要多次尝试才能理解两者之间的区别，即使这样，你仍然可能会在两者之间感到困惑。混淆的根源在于，在某些情况下，认证提供者和授权提供者是相同的。例如，在我们的 WordPress 示例中，WordPress 提供认证（它有用户名和密码）和授权（它将用户存储在管理员或用户角色下，例如）。

然而，在大多数情况下，身份验证系统和授权系统是不同的。我们将在*第十章*，*保护您的 AKS 集群*中使用一个实际的例子。在该章节中，我们将使用 Azure AD 作为身份验证源，同时使用 Kubernetes RBAC 作为授权源。

### 身份验证和常见的身份验证提供商

我们的留言板应用对所有人开放，并允许任何拥有公共 IP 的人访问该服务。图像本身没有身份验证。一个常见的问题是希望将附加功能与应用程序实现分开。这可以通过引入一个代理来实现，该代理将提供身份验证流量，而不是在主应用程序中引入身份验证逻辑。

最近的黑客攻击表明，自己建立和维护安全的身份验证系统是困难的。为了帮助客户构建安全的应用程序，许多公司允许您使用他们的身份验证服务来验证用户的身份。这些提供商提供了 OAuth 支持的身份验证服务。以下是一些知名的提供商：

+   **Azure** ([`github.com/pusher/oauth2_proxy#azure-auth-provider`](https://github.com/pusher/oauth2_proxy#azure-auth-provider))

+   **Facebook** ([`github.com/pusher/oauth2_proxy#facebook-auth-provider`](https://github.com/pusher/oauth2_proxy#facebook-auth-provider))

+   **GitHub** (https://github.com/pusher/oauth2_proxy#github-auth-provider)

+   **GitLab** (https://github.com/pusher/oauth2_proxy#gitlab-auth-provider)

+   **Google** (https://github.com/pusher/oauth2_proxy#google-auth-provider)

+   **LinkedIn** ([`github.com/pusher/oauth2_proxy#linkedin-auth-provider`](https://github.com/pusher/oauth2_proxy#linkedin-auth-provider))

在接下来的章节中，我们将使用代理实现`oauth2_proxy`来为我们的留言板示例实现身份验证。

### 部署 oauth2_proxy 代理

让我们从清理之前部署的 Ingress 开始。我们将保留集群中部署的证书颁发机构。我们可以使用以下方式清理 Ingress：

```
kubectl delete -f ingress-with-tls-prod.yaml
```

我们将实现来自 Pusher 的`oauth2_proxy` ([`github.com/pusher/oauth2_proxy`](https://github.com/pusher/oauth2_proxy))。按照以下步骤配置`oauth2_proxy`以使用 Azure AD 作为身份验证系统。

首先，在 Azure AD 中注册一个应用程序。通过在搜索栏中搜索`azure active directory`来打开门户中的 Azure AD 选项卡：

![在搜索栏中输入 Azure 活动目录。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.17.jpg)

###### 图 6.17：在 Azure 搜索栏中搜索 Azure 活动目录

然后，转到**应用注册**并点击**新注册**：

![在 Azure 活动目录的导航窗格中点击应用注册。接下来，点击搜索栏旁边的新注册选项卡。将创建一个新的应用程序注册。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.18.jpg)

###### 图 6.18：创建新的应用程序注册

然后，为应用程序提供名称并点击**创建**：

![为新创建的应用程序输入名称并保存。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.19.jpg)

###### 图 6.19：为应用程序提供名称

接下来，通过以下步骤创建客户端 ID 密钥：

1.  选择**证书和密钥**，然后转到**新的客户端密钥**。为密钥提供描述并点击**添加**：![打开应用程序后，点击左侧屏幕导航窗格中的证书和密钥选项卡。点击新的客户端密钥按钮。将 oauth2_proxy 设置为此应用程序的描述。将到期时间设置为 1 年，然后点击添加按钮。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.20.jpg)

###### 图 6.20：创建新的客户端密钥

1.  点击复制图标并将密钥保存在安全的地方：![要复制并将密钥保存在安全的地方，请点击客户端密钥值旁边的复制图标。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.21.jpg)

###### 图 6.21：复制客户端密钥

1.  接下来，我们需要配置重定向 URL。这是 Azure AD 在用户经过身份验证后将回调的 URL。要进行配置，请转到 Azure AD 的**身份验证**，点击**添加平台**，然后选择**Web**，如*图 6.22*所示：![点击左侧屏幕导航窗格中的身份验证选项卡。接下来，点击平台配置部分中的添加平台按钮。这将打开一个新页面，帮助您配置平台。在 Web 应用程序部分中选择 Web 选项。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.22.jpg)

###### 图 6.22：提供重定向 URL

在那里，您可以输入以下 URL：

`https://<your dns prefix>.<your azure region>.cloudapp.azure.com/oauth2/callback`，然后点击**配置**。

1.  然后，返回**概述**窗格并保存**应用程序**和**目录 ID**：![在左侧屏幕的概述窗格中复制应用程序 ID 和目录 ID 并保存。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_6.23.jpg)

###### 图 6.23：复制应用程序 ID 和目录 ID

在创建客户端 ID 密钥、设置重定向 URL 和复制应用程序和目录 ID 之后，我们需要在 Kubernetes 中创建以下三个对象，以使`oauth2_proxy`在我们的集群上运行，并执行最后一步将 OAuth 链接到我们现有的 Ingress：

1.  首先，我们需要为`oauth2_proxy`创建一个部署。

1.  然后，我们需要将其公开为一个服务。

1.  之后，我们将为`oauth2`创建一个新的 Ingress。

1.  最后，我们将重新配置当前的 Ingress，以便将未经身份验证的请求发送到`oauth2_proxy`。

我们将执行所有三个步骤，并显示 YAML 文件如下：

1.  让我们从第一项开始 - 创建部署。 部署可以在源代码中找到`oauth2_deployment.yaml`文件：

```
1    apiVersion: extensions/v1beta1
2    kind: Deployment
3    metadata:
4      name: oauth2-proxy
5    spec:
6      replicas: 1
7      selector:
8        matchLabels:
9          app: oauth2-proxy
10     template:
11       metadata:
12         labels:
13           app: oauth2-proxy
14       spec:
15         containers:
16         - env:
17             - name: OAUTH2_PROXY_PROVIDER
18               value: azure
19             - name: OAUTH2_PROXY_AZURE_TENANT
20               value: <paste in directory ID>
21             - name: OAUTH2_PROXY_CLIENT_ID
22               value: <paste in application ID>
23             - name: OAUTH2_PROXY_CLIENT_SECRET
24               value: <paste in client secret>
25             - name: OAUTH2_PROXY_COOKIE_SECRET
26               value: somethingveryrandom
27             - name: OAUTH2_PROXY_HTTP_ADDRESS
28               value: "0.0.0.0:4180"
29             - name: OAUTH2_PROXY_UPSTREAM
30               value: "https://<your DNS prefix>.<your azure region>.cloudapp.azure.com/"
31             - name: OAUTH2_PROXY_EMAIL_DOMAINS
32               value: '*'
33           image: quay.io/pusher/oauth2_proxy:latest
34           imagePullPolicy: IfNotPresent
35           name: oauth2-proxy
36           ports:
37           - containerPort: 4180
38             protocol: TCP
```

这个部署有几行有趣的内容需要讨论。 我们在*第三章*的先前示例中讨论了其他行。 我们将在这里重点讨论以下行：

**第 17-18 行**：这些行告诉`oauth2`代理重定向到 Azure AD。

**第 19-32 行**：这是`oauth2`的配置。

**第 33 行**：这行指向正确的容器镜像。 这是我们第一次使用不是托管在 Docker Hub 上的镜像。 **Quay**是由 RedHat 托管的另一个容器存储库。

使用以下命令创建部署：

```
kubectl create -f oauth2_deployment.yaml
```

1.  接下来，`oauth2`需要被公开为一个服务，以便 Ingress 可以与其通信，通过创建以下服务（`oauth2_service.yaml`）：

```
1   apiVersion: v1
2   kind: Service
3   metadata:
4     name: oauth2-proxy
5     namespace: default
6   spec:
7     ports:
8     - name: http
9       port: 4180
10      protocol: TCP
11      targetPort: 4180
12    selector:
13      app: oauth2-proxy
```

使用以下命令创建此服务：

```
kubectl create oauth2_service.yaml
```

1.  接下来，我们将创建一个 Ingress，以便任何访问`handsonaks-ingress-<yourname>.<your azure region>.cloudapp.azure.com/oauth`的 URL 将被重定向到`oauth2-proxy`服务。 这里使用相同的 Let's Encrypt 证书颁发者（本章的源代码中的`oauth2_ingress.yaml`文件）：

```
1   apiVersion: extensions/v1beta1
2   kind: Ingress
3   metadata:
4     name: oauth2-proxy-ingress
5     annotations:
6       kubernetes.io/ingress.class: nginx
7       cert-manager.io/issuer: "letsencrypt-prod"
8   spec:
9     tls:
10     - hosts:
11       - <your DNS prefix>.<your azure region>.cloudapp.azure.com
12       secretName: tls-secret
13     rules:
14     - host: <your DNS prefix>.<your azure region>.cloudapp.azure.com
15       http:
16         paths:
17         - path: /oauth2
18           backend:
19             serviceName: oauth2-proxy
20             servicePort: 4180
```

在这个 Ingress 中有一行很有趣。 **第 17 行**引入了一个新的路径到我们的 Ingress。 正如本章前面提到的，同一个 Ingress 可以将多个路径指向不同的后端服务。 这就是我们在这里配置的内容。

使用以下命令创建此 Ingress：

```
kubectl create -f oauth2_ingress.yaml
```

1.  最后，我们将通过创建 Ingress 将`oauth2`代理链接到前端服务，以配置`nginx`，以便使用`auth-url`和`auth-signin`中的路径进行身份验证检查。如果请求未经身份验证，则流量将发送到`oauth2_proxy`。如果成功经过身份验证，则流量将重定向到后端服务（在我们的案例中是前端服务）。

在 GitHub 存储库中的以下代码执行身份验证成功后的重定向（`frontend-oauth2-ingress.yaml`）：

```
1  apiVersion: extensions/v1beta1
2  kind: Ingress
3  metadata:
4    name: frontend-oauth2-ingress
5    annotations:
6      kubernetes.io/ingress.class: nginx
7      nginx.ingress.kubernetes.io/auth-url: "http://oauth2-proxy.default.svc.cluster.local:4180/oauth2/auth"
8      nginx.ingress.kubernetes.io/auth-signin: "http://<your DNS prefix>.<your azure region>.cloudapp.azure.com/oauth2/start"
9  spec:
10   rules:
11   - host: <your DNS prefix>.<your azure region>.cloudapp.azure.com
12     http:
13       paths:
14       - path: /
15         backend:
16           serviceName: frontend
17           servicePort: 80 
```

在这个 Ingress 配置中有一些有趣的地方要指出。其他行与我们在本章中创建的其他 Ingress 一样普通：

第 5 行：如前所述，Ingress 对象可以由多种技术（如 NGINX 或应用程序网关）支持。 Ingress 对象具有配置基本任务的语法，例如`hosts`和`paths`，但例如没有配置身份验证重定向。注释由多个 Ingress 提供程序使用，以将详细配置数据传递给后端的 Ingress 提供程序。

第 7-8 行：这将配置我们的 Ingress 将非经过身份验证的请求发送到这些 URL。

使用以下命令创建此 Ingress：

```
kubectl create -f frontend-oauth2-ingress.yaml
```

我们现在已经完成了配置。您现在可以使用现有的 Microsoft 帐户登录到`https://handsonaks-ingress-<yourname>.<your azure region>.cloudapp.azure.net/`的服务。为了确保您获得身份验证重定向，请确保使用新的浏览器窗口或私人窗口。您应该会自动重定向到 Azure AD 的登录页面。

#### 注意

`oauth2-proxy`支持多个身份验证提供程序，例如 GitHub 和 Google。只需更改`oauth2-proxy`部署的 YAML 以使用正确的服务更改身份验证提供程序。请参阅 https://github.com/pusher/oauth2_proxy#oauth-provider-configuration 中的相关详细信息。

现在一切都已部署完成，让我们清理一下我们在集群中创建的资源：

```
kubectl delete -f guestbook-all-in-one.yaml
kubectl delete -f frontend-oauth2-ingress.yaml
kubectl delete -f oauth2_ingress.yaml
kubectl delete -f oauth2_deployment.yaml
kubectl delete -f oauth2_service.yaml
kubectl delete ns cert-manager
helm delete ingress
```

在本节中，我们已将 Azure AD 身份验证添加到您的应用程序。我们通过将`oauth2_proxy`添加到我们的集群，然后重新配置现有的 Ingress 以将未经身份验证的请求重定向到`oauth2_proxy`来实现这一点。

## 摘要

在本章中，我们在不实际更改源代码的情况下，为我们的留言板应用程序添加了 HTTPS 安全性和身份控制。我们首先在集群中设置了 Kubernetes Ingress 对象。然后，我们安装了一个证书管理器，该管理器与 Let's Encrypt API 接口，以请求指定的域名的证书。我们利用证书签发者从 Let's Encrypt 获取了证书。然后，我们重新配置了我们的 Ingress，以从集群中的签发者请求证书。

然后，我们深入探讨了身份验证和授权，并向您展示了如何利用 Azure AD 作为留言板应用程序的身份验证提供者。您将学习如何在企业规模上保护您的应用程序。通过与 Azure AD 集成，您可以使任何应用程序连接到组织的 AD。

在下一章中，您将学习如何监视您的部署并设置警报。您还将学习如何在发生错误时快速识别根本原因，并学习如何调试在 AKS 上运行的应用程序。与此同时，您还将学习如何在确定了根本原因后执行正确的修复操作。


# 第七章：监视 AKS 集群和应用程序

现在您已经知道如何在 AKS 集群上部署应用程序，让我们专注于如何确保您的集群和应用程序保持可用。在本章中，您将学习如何监视您的集群以及运行在其中的应用程序。您将探索 Kubernetes 如何通过就绪和存活探针确保您的应用程序可靠运行。

您还将学习如何使用**Azure Monitor**，以及它如何在 Azure 门户中集成，以及如何为 AKS 集群上的关键事件设置警报。您将了解如何使用 Azure Monitor 监视集群本身的状态，集群上的 Pod 以及以规模访问 Pod 的日志。

简而言之，本章将涵盖以下主题：

+   使用`kubectl`监视和调试应用程序

+   审查 Kubernetes 报告的指标

+   审查来自 Azure Monitor 的指标

让我们从回顾一些`kubectl`中的命令开始，您可以使用这些命令来监视您的应用程序。

## 用于监视应用程序的命令

监控部署在 Kubernetes 上的应用程序的健康状况以及 Kubernetes 基础架构本身对于向客户提供可靠的服务至关重要。监控有两个主要用例：

+   持续监控以获取警报，如果某些情况表现不如预期

+   故障排除和调试应用程序错误

在监视运行在 Kubernetes 集群之上的应用程序时，您需要同时检查多个内容，包括容器、Pod、服务以及集群中的节点。对于持续监控，您将需要像 Azure Monitor 或 Prometheus 这样的监控系统。对于故障排除，您将需要与实时集群进行交互。用于故障排除的最常用命令如下：

```
kubectl get <resource type> <resource name>
kubectl describe <resource type> <resource name>
kubectl logs <pod name>
```

我们将在本章中详细描述每个命令。

在开始之前，我们将使用我们的 guestbook 示例进行清洁启动。再次使用以下命令重新创建 guestbook 示例：

```
kubectl create -f guestbook-all-in-one.yaml
```

在`create`命令运行时，我们将在以下章节中观察其进展。

### kubectl get 命令

为了查看部署应用程序的整体情况，`kubectl`提供了`get`命令。`get`命令列出您指定的资源。资源可以是 Pods、ReplicaSets、Ingresses、节点、部署、Secrets 等等。我们已经在前几章中运行了这个命令，以验证我们的应用程序已经准备好使用。执行以下步骤：

1.  运行以下`get`命令，这将获取我们资源及其状态：

```
kubectl get all
```

这将显示您的命名空间中的所有部署、ReplicaSets、Pods 和服务：

![kubectl get all 命令的输出显示资源及其状态，以及命名空间中的部署、ReplicaSets、Pods 和服务。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.1.jpg)

###### 图 7.1：默认命名空间中运行的所有资源

1.  让我们把注意力集中在我们部署中的 Pods 上。我们可以使用以下命令获取 Pods 的状态：

```
kubectl get pods
```

您将看到，现在只显示了 Pods，就像*图 7.2*中所示。让我们详细调查一下：

![使用 kubectl get pods 命令检索我们部署中的 Pod 的状态。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.2.jpg)

###### 图 7.2：您的命名空间中的所有 Pods

第一列表示 Pod 名称，例如`frontend-57d8c9fb45-c6qtm`。第二列表示 Pod 中准备好的容器数量与 Pod 中的总容器数量。通过 Kubernetes 中的就绪探针来定义就绪状态。我们在本章的后面有一个专门的部分叫做*就绪和存活探针*。

第三列表示状态，例如`Pending`或`ContainerCreating`或`Running`等等。第四列表示重启次数，而第五列表示 Pod 被要求创建的时间。

如果您需要更多关于您的 Pod 的信息，您可以通过在命令中添加`-o wide`来添加额外的列到`get`命令的输出中，就像这样：

```
kubectl get pods -o wide
```

这将显示额外的信息，就像*图 7.3*中所示：

![使用 kubectl get pods -o wide 命令获取有关 Pod 的其他信息。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.3.jpg)

###### 图 7.3：添加-o wide 显示了 Pod 的更多细节

额外的列包括 Pod 的 IP 地址、它所在的节点、被提名的节点和就绪门。只有当高优先级的 Pod 抢占低优先级的 Pod 时，才会设置被提名的节点。被提名的节点是高优先级 Pod 在低优先级 Pod 优雅终止后将启动的节点。就绪门是引入外部系统组件作为 Pod 就绪的一种方式。

执行`get pods`命令只显示当前 Pod 的状态。要查看系统中所有资源的事件，请运行以下命令：

```
kubectl get events
```

#### 注意

Kubernetes 默认只保留 1 小时的事件。所有命令只在事件在过去一小时内触发时有效。

如果一切顺利，您应该会得到类似于*图 7.4*的输出：

![显示过去一小时事件的 kubectl get events 命令的输出的缩略列表。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.4.jpg)

###### 图 7.4：获取事件显示过去一小时的所有事件

如您在输出中所见，Pod 的一般状态为`Scheduled` | `Pulling` | `Pulled` | `Created` | `Started`。接下来我们将看到，任何状态都可能失败，我们需要使用`kubectl describe`命令进行深入挖掘。

### kubectl describe 命令

使用`kubectl get events`命令列出整个命名空间的所有事件。如果您只对 Pod 感兴趣，可以使用以下命令：

```
kubectl describe pods
```

上述命令列出了所有与所有 Pod 相关的信息。这通常是典型 shell 无法包含的太多信息。

如果您想要特定 Pod 的信息，可以输入以下内容：

```
kubectl describe pod/<pod-name>
```

#### 注意

您可以在`pod`和`podname`之间使用*斜杠*或*空格*。以下两个命令将产生相同的输出：

`kubectl describe pod/<pod-name>`

`kubectl describe pod <pod-name>`

您将得到类似于*图 7.5*的输出，稍后将对其进行详细解释。

![显示指定 pod 的所有细节的 kubectl describe pod/<pod-name>命令的输出。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.5.jpg)

###### 图 7.5：描述对象显示该对象的详细输出

通过描述，您可以获得 Pod 所在的节点、它运行了多长时间、它的内部 IP 地址、Docker 镜像名称、暴露的端口、`env`变量和事件（在过去一小时内）。

在上面的示例中，Pod 的名称是`frontend-57d8c9fb45-c6qtm`。如*第一章《Docker 和 Kubernetes 简介》*中所述，它采用了“<ReplicaSet 名称>-<随机 5 个字符>”的格式。`replicaset`名称本身是从部署名称`frontend`随机生成的：`<deployment 名称>-<随机 5 个字符>`。

*图 7.6*显示了部署、副本集和 Pod 之间的关系：

![图形化表示部署、副本集和 Pod 之间的关系。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.6.jpg)

###### 图 7.6：部署、副本集和 Pod 之间的关系

Pod 运行的命名空间是`default`。到目前为止，我们一直在使用名为`default`的`default`命名空间。在接下来的章节中，我们将看到命名空间如何帮助我们隔离 Pod。

前面输出中重要的另一部分是节点部分：

```
Node:aks-agentpool-39838025-vmss000005/10.240.0.7
```

节点部分让我们知道 Pod 正在哪个物理节点/虚拟机上运行。如果 Pod 反复重启或出现运行问题，而其他一切似乎正常，可能是节点出现了问题。拥有这些信息对于进行高级调试至关重要。

以下是 Pod 最初被调度的时间：

```
Start Time: Wed, 04 Mar 2020 02:53:55 +0000
```

这并不意味着 Pod 从那时起一直在运行，因此时间在这方面可能会误导。如果发生健康事件（例如，容器崩溃），Pod 将被重新启动。

资源之间的连接是使用“标签”进行的，如下所示：

```
Labels:app=guestbook
pod-template-hash=57d8c9fb45
tier=frontend
```

这就是如何建立`Service` | `Deployment` | `ReplicaSet` | `Pod`等连接的。如果发现流量没有从 Service 路由到 Pod，这是您应该检查的第一件事。如果标签不匹配，资源将无法连接。

以下显示了 Pod 的内部 IP 和其状态：

```
Status:Running
IP:10.244.5.52
```

如前几章所述，构建应用程序时，Pod 可以移动到不同的节点并获得不同的 IP。然而，在调试应用程序问题时，直接获得 Pod 的 IP 可以帮助进行故障排除。您可以直接从一个 Pod 连接到另一个 Pod 以测试连接性，而不是通过 Service 对象连接到应用程序。

在 Pod 中运行的容器和暴露的端口列在以下区块中：

```
Containers: php-redis:
...
Image:gcr.io/google-samples/gb-frontend:v4
...
Port:80/TCP
Host Port:0/TCP
Environment:
GET_HOSTS_FROM:dns
```

在这种情况下，我们从`gcr.io`容器注册表中获取带有`v4`标签的`gb-frontend`容器，仓库名称为`google-samples`。

端口`80`对外部流量开放。由于每个 Pod 都有自己的 IP，即使在同一主机上运行时，相同的端口也可以为同一 Pod 的多个实例开放。例如，如果您在同一节点上运行两个运行 Web 服务器的 Pod，这两个 Pod 都可以使用端口`80`，因为每个 Pod 都有自己的 IP 地址。这是一个巨大的管理优势，因为您不必担心端口冲突。需要配置的端口也是固定的，因此可以简单地编写脚本，而无需考虑为 Pod 分配了哪个端口的逻辑。

在此处显示了上一个小时发生的任何事件：

```
Events:
```

使用`kubectl describe`非常有用，可以获取有关正在运行的资源的更多上下文。在下一节中，我们将专注于调试应用程序。

### 调试应用程序

现在我们对如何监视部署有了基本的了解，我们可以开始看看如何调试部署中的问题。

在本节中，我们将介绍常见错误并确定如何调试和修复它们。

如果您尚未实现 guestbook 应用程序，请运行以下命令：

```
kubectl create -f guestbook-all-in-one.yaml
```

一段时间后，服务应该已经启动并运行。

**图像拉取错误**

在本节中，我们将通过将图像标记值设置为不存在的值来介绍图像拉取错误。当 Kubernetes 无法下载容器所需的图像时，就会发生图像拉取错误。

在 Azure Cloud Shell 上运行以下命令：

```
kubectl edit deployment/frontend
```

接下来，通过执行以下步骤将图像标记从`v4`更改为`v_non_existent`：

1.  键入`/gb-frontend`并按*Enter*按钮，将光标移到图像定义处。

1.  按下*I*键进入插入模式。删除`v4`并输入`v_non_existent`。

1.  现在，首先按下*Esc*键关闭编辑器，然后输入`:wq!`并按*Enter*键。

运行以下命令列出当前命名空间中的所有 Pod：

```
kubectl get pods
```

前面的命令应该指示错误，如*图 7.7*所示：

![kubectl get pods 命令的输出显示有三个 Pod 正在运行，而一个 Pod 出现了 Image pull back off 错误。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.7.jpg)

###### 图 7.7：一个 Pod 的状态为 ImagePullBackOff

运行以下命令以获取完整的错误详细信息：

```
kubectl describe pods/<failed pod name>
```

*图 7.8*显示了一个示例错误输出。关键错误行用红色突出显示：

![使用 kubectl describe pods/<failed pod name>命令显示无法拉取图像的错误详细信息。图像有两个亮点，“无法拉取图像”和“v_non_existent 未找到”。ils on the error](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.8.jpg)

###### 图 7.8：使用 describe 显示错误的更多详细信息

因此，事件清楚地显示图像不存在。将无效凭据传递给私有 Docker 存储库也会在此处显示。

让我们通过将图像标签设置回`v4`来修复错误：

1.  首先，在 Cloud Shell 中键入以下命令以编辑部署：

```
kubectl edit deployment/frontend
```

1.  键入`/gb-frontend`并按`<enter>`将光标移到图像定义处。

1.  按下*I*键进入插入模式。删除`v_non_existent`，然后输入`v4`。

1.  现在，首先按下*Esc*键关闭编辑器，然后输入`:wq!`并按*Enter*键。

部署应该会自动修复。您可以通过再次获取 Pod 的事件来验证它。

#### 注意

由于 Kubernetes 进行了滚动更新，前端一直可用，没有任何停机时间。Kubernetes 识别出新规范存在问题，并停止自动滚动出额外的更改。

图像拉取错误可能发生在图像不可用时。在下一节中，我们将探索应用程序本身的错误。

**应用程序错误**

我们现在将看到如何调试应用程序错误。本节中的错误将是自我引起的，类似于上一节。调试问题的方法与我们用于调试运行应用程序的方法相同。

为了测试我们的失败，我们将使`frontend`服务可以公开访问：

1.  首先，我们将编辑`frontend`服务：

```
kubectl edit service frontend
```

1.  键入`/ClusterIP`并按*Enter*将光标移到类型字段（第 27 行）。

1.  按下*I*键进入插入模式。删除`ClusterIP`，然后输入`LoadBalancer`。

1.  现在，首先按下*Esc*键关闭编辑器，然后输入`:wq!`并按*Enter*。这将为我们的前端服务创建一个公共 IP。

1.  我们可以使用以下命令获取此 IP：

```
kubectl get service
```

1.  让我们通过在浏览器中粘贴其公共 IP 来连接到服务。创建一些条目：![添加了一些条目的留言板应用程序。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.9.jpg)

###### 图 7.9：在留言板应用程序中进行一些条目

#### 注意

大多数错误来自错误配置，可以通过编辑规范来修复。应用程序代码本身的错误需要构建和使用新的映像。

您现在有一个运行中的 guestbook 应用程序实例。为了改善示例的体验，我们将缩减前端，以便只有一个副本在运行。

**缩减前端**

在*第三章*，*在 AKS 上部署应用程序*中，您学习了前端部署的配置为`replicas=3`。这意味着应用程序接收的请求可以由任何一个 Pod 处理。要引入应用程序错误并注意错误，我们需要对所有三个 Pod 进行更改。

为了使这个示例更容易，将`replicas`缩减到`1`，这样您只需要对一个 Pod 进行更改：

```
kubectl scale --replicas=1 deployment/frontend
```

只运行一个副本将使引入错误变得更容易。现在让我们引入这个错误。

**引入应用程序错误**

在这种情况下，我们将使**提交**按钮无法工作。我们需要修改应用程序代码。

#### 注意

不建议使用`kubectl exec`对 Pod 执行命令来对应用程序进行生产更改。如果需要对应用程序进行更改，最好的方法是创建新的容器映像并更新部署。

我们将使用`kubectl exec`命令。此命令允许您在该 Pod 的命令行上运行命令。使用`-it`选项，它会将交互式终端附加到 Pod，并为我们提供一个可以运行命令的 shell。以下命令在 Pod 上启动 Bash 终端：

```
kubectl exec -it <frontend-pod-name> bash
```

一旦您进入容器 shell，运行以下命令：

```
apt update
apt install -y vim
```

上述代码安装了 vim 编辑器，以便我们可以编辑文件引入错误。现在，使用`vim`打开`guestbook.php`文件：

```
vim guestbook.php
```

在第 18 行后添加以下行。记住，在 vim 中插入一行，您按*I*键。编辑完成后，您可以通过按*Esc*退出，然后输入`:wq!`，然后按*Enter*：

```
$host = 'localhost';
if(!defined('STDOUT')) define('STDOUT', fopen('php://stdout', 'w'));
fwrite(STDOUT, "hostname at the beginning of 'set' command "); fwrite(STDOUT, $host);
fwrite(STDOUT, "\n");
```

文件将看起来像*图 7.10*：

![在 vim 编辑器中具有更新代码的 guestbook.php 文件。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.10.jpg)

###### 图 7.10：引入错误和额外日志的更新代码

我们引入了一个错误，即读取消息可以工作，但写入消息却不行。我们通过要求前端连接到不存在的本地主机的 Redis 主服务器来实现这一点。写入应该失败。与此同时，为了使这个演示更加直观，我们在代码的这一部分添加了一些额外的日志记录。

通过浏览其公共 IP 打开您的留言板应用程序，您应该可以看到之前的条目：

![重新打开的留言板应用程序显示之前的条目仍然存在。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.11.jpg)

###### 图 7.11：之前的条目仍然存在

现在，通过输入一条消息并点击**提交**按钮来创建一条新消息：

![向留言板应用程序添加一个“新消息”条目。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.12.jpg)

###### 图 7.12：创建了一条新消息

提交新消息会使其出现在我们的应用程序中。如果我们不知道更好的方法，我们可能会认为该条目已经安全地被写入。然而，如果您刷新浏览器，您会发现消息不再存在。

如果您在浏览器中打开了网络调试工具，您可以捕获服务器的错误响应。

为了验证消息没有被写入数据库，点击浏览器中的**刷新**按钮；您将只看到最初的条目，新条目已经消失：

![点击刷新按钮后，留言板应用程序只显示最初的条目。新消息丢失了。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.13.jpg)

###### 图 7.13：新消息已经消失了

作为应用程序开发人员或操作员，您可能会收到这样的工单：*在新部署后，新条目没有被持久化。修复它。*

### 日志

第一步是获取日志。现在让我们暂时退出前端 Pod 并获取该 Pod 的日志：

```
exit
kubectl logs <frontend-pod-name>
```

您将看到诸如*图 7.14*中所见的条目：

![kubectl logs <frontend-pod-name>命令的输出显示了该 Pod 的日志。图中包含三个突出显示的区域：“在'设置'命令 localhost 之前的主机名”，“cmd=set”，和“new%20message”。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.14.jpg)

###### 图 7.14：新消息显示在应用程序日志中

因此，您知道错误出现在代码的`set`部分写入数据库时。

您将看到这个条目：

```
hostname at the beginning of 'set' command localhost
```

所以我们知道错误发生在这一行和客户端开始之间，所以`$host = 'localhost'`的设置必须是错误的原因。这种错误并不像你想象的那样罕见，正如我们刚才看到的，除非有特定的指示刷新浏览器，否则它很容易通过 QA。对于开发人员来说，它可能完全正常工作，因为他们可能在本地机器上运行着一个 Redis 服务器。

我们现在有两种选项来修复这个错误：我们可以进入 Pod 并进行代码更改，或者我们可以要求 Kubernetes 为我们提供一个健康的新 Pod。不建议对 Pod 进行手动更改，所以我们将使用第二种方法。让我们通过删除有问题的 Pod 来修复这个错误：

```
kubectl delete pod <podname>
```

由于我们有一个控制我们的 Pod 的 ReplicaSet，我们应该立即获得一个已经从正确的镜像启动的新 Pod。尝试再次连接到 guestbook 并验证消息是否再次在浏览器刷新时保留。

以下几点总结了一些常见的错误和修复这些错误的方法：

+   错误可以呈现多种形式。

+   部署团队遇到的大多数错误都是配置问题。

+   日志是你的朋友。

+   在容器上使用`kubectl exec`是一个有用的调试工具。

+   请注意，广泛允许`kubectl exec`是一个严重的安全风险，因为它几乎让 Kubernetes 操作员在他们可以访问的 Pod 中做任何他们想做的事情。

+   任何打印到`stdout`和`stderr`的内容都会显示在日志中（与应用程序/语言/日志框架无关）。

我们在 guestbook 应用程序中引入了一个应用程序错误，并且能够利用 Kubernetes 日志来准确定位代码中的问题。在下一节中，我们将探讨 Kubernetes 中一个强大的机制，称为*就绪和活跃探针*。

## 就绪和活跃探针

我们在上一节中简要提到了就绪探针。在本节中，我们将更深入地探讨它们。

Kubernetes 使用活跃探针和就绪探针来监视应用程序的可用性。每个探针都有不同的目的：

+   **活跃探针**在应用程序运行时监视可用性。如果活跃探针失败，Kubernetes 将重新启动您的 Pod。这对于捕获死锁、无限循环或者只是“卡住”的应用程序可能非常有用。

+   一个**就绪探针**监视应用程序何时变得可用。如果就绪探针失败，Kubernetes 将不会向未准备好的 Pod 发送任何流量。如果您的应用程序在变得可用之前必须经过一些配置，或者如果您的应用程序可能会过载但可以从额外的负载中恢复，这将非常有用。

活跃和就绪探针不需要从应用程序的同一端点提供服务。如果您有一个智能应用程序，该应用程序可以在仍然健康的情况下将自身从轮换中移出（意味着不再向应用程序发送流量）。为了实现这一点，就绪探针将失败，但活跃探针仍然保持活动状态。

让我们通过一个例子来构建这个部署。我们将创建两个 nginx 部署，每个部署都有一个索引页面和一个健康页面。索引页面将作为活跃探针。

### 构建两个 web 容器

在这个例子中，我们将使用一对网页来连接到我们的就绪和活跃探针。让我们首先创建`index1.html`：

```
<!DOCTYPE html>
<html>
<head>
<title>Server 1</title>
</head>
<body>
Server 1
</body>
</html>
```

之后，创建`index2.html`：

```
<!DOCTYPE html>
<html>
<head>
<title>Server 2</title>
</head>
<body>
Server 2
</body>
</html>
```

我们还将创建一个健康页面，`healthy.html`：

```
<!DOCTYPE html>
<html>
<head>
<title>All is fine here</title>
</head>
<body>
OK
</body>
</html>
```

在下一步中，我们将把这些文件挂载到我们的 Kubernetes 部署中。我们将把每个文件都转换成一个`configmap`，然后连接到我们的 Pods。使用以下命令创建 configmap：

```
kubectl create configmap server1 --from-file=index1.html
kubectl create configmap server2 --from-file=index2.html
kubectl create configmap healthy --from-file=healthy.html
```

搞定了这些，我们可以继续创建我们的两个 web 部署。两者将非常相似，只是`configmap`不同。第一个部署文件（`webdeploy1.yaml`）如下所示：

```
1   apiVersion: apps/v1
2   kind: Deployment
...
17     spec:
18       containers:
19         - name: nginx-1
20           image: nginx
21           ports:
22             - containerPort: 80
23           livenessProbe:
24             httpGet:
25               path: /healthy.html
26               port: 80
27             initialDelaySeconds: 3
28             periodSeconds: 3
29           readinessProbe:
30             httpGet:
31               path: /index.html
32               port: 80
33             initialDelaySeconds: 3
34             periodSeconds: 3
35           volumeMounts:
36             - name: html
37               mountPath: /usr/share/nginx/html
38             - name: index
39               mountPath: /tmp/index1.html
40               subPath: index1.html
41             - name: healthy
42               mountPath: /tmp/healthy.html
43               subPath: healthy.html
44           command: ["/bin/sh", "-c"]
45           args: ["cp /tmp/index1.html /usr/share/nginx/html/index.html; cp /tmp/healthy.html /usr/share/nginx/html/healthy.html; nginx; sleep inf"]
46       volumes:
47         - name: index
48           configMap:
49             name: server1
50         - name: healthy
51           configMap:
52             name: healthy
53         - name: html
54           emptyDir: {}
```

在这个部署中有一些要强调的事项：

+   第 23-28 行：这是活跃探针。活跃探针指向健康页面。请记住，如果健康页面失败，容器将被重新启动。

+   第 29-32 行：这是就绪探针。在我们的情况下，就绪探针指向索引页面。如果此页面失败，Pod 将暂时不会收到任何流量，但将继续运行。

+   第 44-45 行：这两行包含一对在容器启动时执行的命令。我们不仅仅运行 nginx 服务器，而是将索引和就绪文件复制到正确的位置，然后启动 nginx，然后使用一个睡眠命令（这样我们的容器就会继续运行）。

您可以使用以下命令创建此部署。您还可以部署类似于服务器 1 的第二个版本，用于服务器 2：

```
kubectl create -f webdeploy1.yaml
kubectl create -f webdeploy2.yaml
```

最后，我们还将创建一个服务，将流量路由到两个部署（`webservice.yaml`）：

```
1   apiVersion: v1
2   kind: Service
3   metadata:
4     name: web
5   spec:
6     selector:
7       app: web-server
8     ports:
9     - protocol: TCP
10     port: 80
11     targetPort: 80
12   type: LoadBalancer
```

我们可以使用以下命令创建该服务：

```
kubectl create -f webservice.yaml
```

我们现在的应用程序已经启动运行。在接下来的部分，我们将引入一些故障来验证活跃性和就绪探针的行为。

### 尝试活跃性和就绪探针

在前一部分中，我们解释了活跃性和就绪探针的功能，并创建了一个示例应用程序。在本节中，我们将在应用程序中引入错误，并验证活跃性和就绪探针的行为。我们将看到就绪探针的失败将导致 Pod 保持运行，但不再接受流量。之后，我们将看到活跃性探针的失败将导致 Pod 被重新启动。

让我们首先尝试使就绪探针失败。

**使就绪探针失败会导致流量暂时停止**

现在我们有一个简单的应用程序正在运行，我们可以尝试活跃性和就绪探针的行为。首先，让我们获取服务的外部 IP 以便使用浏览器连接到我们的 Web 服务器：

```
kubectl get service
```

如果您在浏览器中输入外部 IP，您应该看到一个单行，上面要么写着**服务器 1**，要么写着**服务器 2**：

![浏览器显示外部 IP 和应用程序正在从服务器 2 返回流量。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.15.jpg)

###### 图 7.15：我们的应用程序正在从服务器 2 返回流量

在我们的测试中，我们将使用一个名为`testWeb.sh`的小脚本连接到我们的网页 50 次，这样我们就可以监视服务器 1 和 2 之间结果的良好分布。我们首先需要使该脚本可执行，然后我们可以在我们的部署完全健康的情况下运行该脚本：

```
chmod +x testWeb.sh
./testWeb.sh <external-ip>
```

在健康运行期间，我们可以看到服务器 1 和服务器 2 几乎被同等命中，服务器 1 有 24 次命中，服务器 2 有 26 次命中：

![输出显示服务器 1 和服务器 2 的命中实例分别为 24、48、216 和 26、52、234。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.16.jpg)

###### 图 7.16：当应用程序健康时，流量在服务器 1 和服务器 2 之间进行负载平衡

现在让我们继续并使服务器 1 的就绪探针失败。为此，我们将`exec`进入容器并将索引文件移动到另一个位置：

```
kubectl get pods #note server1 pod name
kubectl exec <server1 pod name> mv /usr/share/nginx/html/index.html /usr/share/nginx/html/index1.html
```

一旦执行了这个，我们可以用以下命令查看 Pod 状态的变化：

```
kubectl get pods -w
```

您应该看到服务器 1 Pod 的就绪状态更改为`0/1`，如*图 7.17*所示：

![使用 kubectl get pods -w 命令的输出显示服务器 1 的就绪状态变为 0/1。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.17.jpg)

###### 图 7.17：失败的就绪探针导致服务器 1 没有任何 READY 容器

这应该不再将流量定向到服务器 1 的 Pod。让我们验证一下：

```
./testWeb.sh <external-ip>
```

在我们的情况下，流量确实被重定向到了服务器 2：

![输出显示所有流量都被定向到服务器 2，服务器 1 的流量为零。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.18.jpg)

###### 图 7.18：现在所有流量都由服务器 2 提供

现在我们可以通过将文件移回到其正确位置来恢复服务器 1 的状态：

```
kubectl exec <server1 pod name> mv /usr/share/nginx/html/index1.html /usr/share/nginx/html/index.html
```

这将使我们的 Pod 恢复到健康状态，并应该再次平均分配流量：

```
./testWeb.sh <external-ip>
```

这将显示类似于*图 7.19*的输出：

![输出显示就绪探针导致流量再次在服务器 1 和服务器 2 之间进行负载均衡。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.19.jpg)

###### 图 7.19：恢复就绪探针会导致流量再次进行负载均衡

失败的就绪探针将导致 Kubernetes 不再向失败的 Pod 发送流量。我们通过使示例应用程序中的就绪探针失败来验证了这一点。在下一节中，我们将探讨失败的活跃探针的影响。

**失败的活跃探针导致容器重新启动**

我们也可以使用活跃探针重复之前的过程。当活跃探针失败时，我们期望 Kubernetes 会继续重启我们的 Pod。让我们尝试通过删除健康文件来实现这一点：

```
kubectl exec <server1 pod name> rm /usr/share/nginx/html/healthy.html
```

让我们看看这对我们的 Pod 有什么影响：

```
kubectl get pods -w
```

我们应该看到 Pod 在几秒钟内重新启动：

![使用 kubectl get pods -w 跟踪 Pod 状态的图像。图像显示服务器 1 通过将重启计数器从 0 增加到 1 来重新启动。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.20.jpg)

###### 图 7.20：失败的活跃探针将导致 Pod 重新启动

正如您在*图 7.20*中所看到的，Pod 已成功重新启动，影响有限。我们可以通过运行`describe`命令来检查 Pod 中发生了什么：

```
kubectl describe pod <server1 pod name>
```

上述命令将给出类似于*图 7.21*的输出：

![使用 kubectl describe pod 命令的输出提供了有关 Pod 的额外细节，并显示了活跃探针的失败情况。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.21.jpg)

###### 图 7.21：有关 Pod 的更多详细信息，显示了活跃探针的失败情况

在`describe`命令中，我们可以清楚地看到 Pod 未通过活跃探针。在四次失败后，容器被终止并重新启动。

这结束了我们对活跃性和就绪性探针的实验。请记住，这两者对您的应用程序都很有用：就绪性探针可用于暂时停止流量到您的 Pod，以便它承受更少的负载。活跃性探针用于在 Pod 出现实际故障时重新启动 Pod。

让我们也确保清理我们刚刚创建的部署：

```
kubectl delete deployment server1 server2
kubectl delete service web
```

活跃性和就绪性探针对确保只有健康的 Pod 会在您的集群中接收流量很有用。在下一节中，我们将探索 Kubernetes 报告的不同指标，您可以使用这些指标来验证应用程序的状态。

## Kubernetes 报告的指标

Kubernetes 报告多个指标。在本节中，我们首先将使用一些 kubectl 命令来获取这些指标。之后，我们将研究 Azure 容器监视器，看看 Azure 如何帮助容器监视。

### 节点状态和消耗

您的 Kubernetes 中的节点是运行应用程序的服务器。Kubernetes 将 Pod 调度到集群中的不同节点。您需要监视节点的状态，以确保节点本身健康，并且节点有足够的资源来运行新应用程序。

运行以下命令以获取有关集群上节点的信息：

```
kubectl get nodes
```

上述命令列出它们的名称、状态和年龄：

![kubectl get nodes 命令的输出，列出节点的名称、状态和年龄。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.22.jpg)

###### 图 7.22：此集群中有两个节点

您可以通过传递`-o` wide 选项来获取更多信息：

```
kubectl get -o wide nodes
```

输出列出了底层的`OS-IMAGE`和`INTERNAL-IP`，以及其他有用的信息，可以在*图 7.23*中查看。

![kubectl get -o wide nodes 命令的输出，显示节点的额外信息，如内部 IP、外部 IP、内核版本和容器运行时。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.23.jpg)

###### 图 7.23：使用-o wide 可以添加关于我们节点的更多细节

您可以使用以下命令找出哪些节点消耗了最多的资源：

```
kubectl top nodes
```

它显示了节点的 CPU 和内存使用情况：

![kubectl top nodes 命令的输出，显示节点的 CPU 和内存利用率。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.24.jpg)

###### 图 7.24：节点的 CPU 和内存利用率

请注意，这是那一时刻的实际消耗，而不是某个节点的请求数。要获取请求数，您可以执行：

```
kubectl describe node <node name>
```

这将向您显示每个 Pod 的请求和限制，以及整个节点的累积量：

![显示特定节点分配的请求和限制数量的输出。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.25.jpg)

###### 图 7.25：描述节点显示有关请求和限制的详细信息

现在您知道在哪里可以找到有关节点利用率的信息。在下一节中，我们将探讨如何获取单个 Pod 的相同指标。

### Pod 消耗

Pods 从 AKS 集群中消耗 CPU 和内存资源。请求和限制用于配置 Pod 可以消耗多少 CPU 和内存。请求用于保留最小数量的 CPU 和内存，而限制用于设置每个 Pod 的最大 CPU 和内存量。

在本节中，我们将探讨如何使用`kubectl`获取有关 Pod 的 CPU 和内存利用率的信息。

让我们首先探索如何查看当前正在运行的 Pod 的请求和限制：

1.  在这个例子中，我们将使用在`kube-system`命名空间中运行的 Pods。获取此命名空间中的所有 Pods：

```
kubectl get pods -n kube-system
```

这应该显示类似于*图 7.26*的内容：

![使用 kubectl get pods -n kube-system 列出 kube-system 命名空间中所有 Pod 的名称、状态、重启次数和年龄。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.26.jpg)

###### 图 7.26：在 kube-system 命名空间中运行的 Pods

1.  让我们获取`coredns` Pods 之一的请求和限制。可以使用`describe`命令来完成：

```
kubectl describe pod coredns-<pod id> -n kube-system
```

在`describe`命令中，应该有一个类似于*图 7.27*的部分：

![显示 CoreDNS Pod 的限制和请求的 describe 命令。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.27.jpg)

###### 图 7.27：CoreDNS Pod 的限制和请求

这向我们显示，此 Pod 的内存限制为`170Mi`，没有 CPU 限制，并且请求了 100m CPU（即 0.1 CPU）和`70Mi`内存。

请求和限制用于在集群中执行容量管理。我们还可以通过运行以下命令获取 Pod 的实际 CPU 和内存消耗：

```
kubectl top pods -n kube-system
```

这应该向您显示类似于*图 7.28*的输出：

![显示 Pod 的 CPU 和内存消耗的 kubectl top pods -n kube-system 命令的输出。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.28.jpg)

###### 图 7.28：查看 Pod 的 CPU 和内存消耗

使用 kubectl top 命令显示了命令运行时的 CPU 和内存消耗。在这种情况下，我们可以看到 coredns Pods 正在使用 2m 和 3m 的 CPU，并且正在使用 21Mi 和 17Mi 的内存。

在本节中，我们一直在使用 kubectl 命令来了解集群中节点和 Pods 的资源利用情况。这是有用的信息，但仅限于特定时间点。在下一节中，我们将使用 Azure Monitor 来获取有关集群和集群上应用程序的更详细信息。

## 来自 Azure Monitor 的报告指标

Azure 门户显示了许多指标，您希望将其与授权结合在一起，因为只有具有门户访问权限的人员才能查看这些指标。

### AKS Insights

AKS 刀片的 Insights 部分提供了您需要了解有关集群的大多数指标。它还具有深入到容器级别的能力。您还可以查看容器的日志。

Kubernetes 提供了可用的指标，但不会存储它们。Azure Monitor 可用于存储这些指标，并使它们随时间可用于查询。为了将相关指标和日志收集到 Insights 中，Azure 连接到 Kubernetes API 来收集指标，然后将其存储在 Azure Monitor 中。

#### 注意

容器的日志可能包含敏感信息。因此，应控制和审计查看日志的权限。

让我们探索 AKS 刀片的 Insights 选项卡。我们将从集群指标开始。

集群指标

Insights 显示集群指标。图 7.29 显示了集群中所有节点的 CPU 利用率和内存利用率：

![Insights 选项卡中的 Cluster 选项卡显示了集群指标。它显示了两个图表：集群中所有节点的 CPU 利用率和内存利用率。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.29.jpg)

###### 图 7.29：Cluster 选项卡显示了集群的 CPU 和内存利用率

集群指标还显示了节点计数和活动 Pods 的数量。节点计数非常重要，因为您可以跟踪是否有节点处于 Not Ready 状态：

![Cluster 选项卡显示两个额外的图表：节点计数和活动 Pods 的数量。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.30.jpg)

###### 图 7.30：Cluster 选项卡显示了节点计数和活动 Pods 的数量

Cluster 选项卡可用于监视集群中节点的状态。接下来，我们将探索 Health 选项卡。

**使用健康选项卡**

在撰写本书时，“健康”选项卡处于预览状态。该选项卡显示了集群健康状况的视图。为了向您显示这一状态，Azure 监视并检查所需的基础设施组件以及节点健康状况：

![健康选项卡的视图显示了集群的整体健康状况。该集群的所有健康指标都标记为绿色。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.31.jpg)

###### 图 7.31：健康选项卡显示了集群的整体健康状况

“健康”选项卡对于跟踪集群的整体健康状况非常有用。我们将要探索的下一个选项卡是“节点”选项卡。

**节点**

“节点”视图向您显示了节点的详细指标。它还向您显示了每个节点上运行的 Pods，正如我们在*图 7.32*中所看到的：

![节点视图窗格显示了每个节点上运行的 Pod 的详细指标。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.32.jpg)

###### 图 7.32：节点视图窗格中节点的详细指标

如果您想要更多细节，您还可以单击并从节点获取 Kubernetes 事件日志：

![右侧窗格中的查看 Kubernetes 事件日志选项允许从集群获取日志。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.33.jpg)

###### 图 7.33：单击“查看 Kubernetes 事件日志”以从集群获取日志

这将打开 Azure Log Analytics，并为您预先创建一个查询，显示节点的日志。在我们的情况下，我们可以看到我们的节点已经重新启动了几次：

![Log Analytics 显示了节点的日志。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.34.jpg)

###### 图 7.34：Log Analytics 显示了节点的日志

**控制器**

“控制器”视图向您显示了集群中所有控制器（即 ReplicaSet、DaemonSet 等）的详细信息以及其中运行的 Pods。这向您展示了一个以控制器为中心的运行容器的视图。例如，您可以找到前端 ReplicaSet 并查看其中运行的所有 Pods 和容器，如*图 7.35*所示：

![在控制器选项卡中显示的具有名称和状态的 ReplicaSet 中运行的所有容器。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.35.jpg)

###### 图 7.35：控制器选项卡向我们显示了 ReplicaSet 中运行的所有容器

接下来的选项卡是“容器”选项卡，它将向我们显示容器的指标、日志和环境变量。

**容器指标、日志和环境变量**

单击“容器”选项卡会列出容器指标、环境变量以及访问其日志，如*图 7.36*所示：

![容器选项卡显示了所有单独的容器。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.36.jpg)

###### 图 7.36：容器选项卡显示了所有单独的容器

#### 注意

您可能会注意到一些容器处于“未知”状态。在我们的情况下，这是可以预料的。在 Azure Monitor 中，我们的时间范围设置为过去 6 小时，在过去 6 小时内，我们创建并删除了许多 Pod。它们不再存在，但 Azure Monitor 知道它们的存在，甚至为它们保留了日志。

我们可以从这个视图中访问我们容器的日志：

![在容器选项卡中访问容器的日志的选项。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.37.jpg)

###### 图 7.37：访问容器的日志

这向我们展示了 Kubernetes 从我们的应用程序中记录的所有日志。我们在本章前面手动访问了这些日志。使用这种方法可能会更加高效，因为我们可以编辑日志查询并在单个视图中关联来自不同 Pod 和应用程序的日志：

![通过日志窗口编辑日志查询并在单个视图中关联来自不同 Pod 和应用程序的日志。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.38.jpg)

###### 图 7.38：日志已被收集并可以查询

除了日志之外，这个视图还显示了为容器设置的环境变量。要查看环境变量，请在此视图的右侧单元格中向下滚动：

![通过在日志视图的右侧单元格中向下滚动来显示为容器设置的环境变量。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_7.39.jpg)

###### 图 7.39：为容器设置的环境变量

以上就是本节的内容。让我们确保清理我们的部署，这样我们就可以在下一章中继续使用一个干净的留言板：

```
kubectl delete -f guestbook-all-in-one.yaml
```

在本节中，我们探讨了在 Kubernetes 上运行的应用程序的监控。我们在 Azure 门户中使用 AKS **Insights**选项卡来详细查看我们的集群和运行在集群上的容器。

## 总结

我们在本章开始时展示了如何使用不同的`kubectl`命令来监视应用程序。然后，我们展示了 Kubernetes 创建的日志如何用于调试该应用程序。日志包含写入`stdout`和`stderr`的所有信息。最后，我们解释了使用 Azure Monitor 来显示 AKS 指标和环境变量，以及使用日志过滤显示日志。我们还展示了如何使用`kubectl`和 Azure Monitor 监控来调试应用程序和集群问题。

在下一章中，我们将学习如何将 AKS 集群连接到 Azure PaaS 服务。我们将重点关注如何将 AKS 集群连接到 Azure 管理的 MySQL 数据库。
