# Kubernetes 开发指南（二）

> 原文：[`zh.annas-archive.org/md5/DCD16B633B67524B76A687C2FBCAAD70`](https://zh.annas-archive.org/md5/DCD16B633B67524B76A687C2FBCAAD70)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：声明式基础设施

Kubernetes 本质上是一个声明性系统。在之前的章节中，我们已经使用诸如`kubectl run`和`kubectl expose`之类的命令探讨了 Kubernetes 及其一些关键概念。这些命令都是命令式的：现在就做这件事。Kubernetes 通过将这些资源作为对象本身来管理这些资源。`kubectl`和 API 服务器将这些请求转换为资源表示，然后存储它们，各种控制器的工作是了解当前状态并按照请求进行操作。

我们可以直接利用声明性结构-所有服务、Pod 和更多内容都可以用 JSON 或 YAML 文件表示。在本章中，我们将转而将您的应用程序定义为声明性基础设施。我们将把现有的简单 Kubernetes Pod 放入您可以与代码一起管理的声明中；存储在源代码控制中并部署以运行您的软件。我们还将介绍 ConfigMaps 和 Secrets，以允许您定义配置以及应用程序结构，并探讨如何使用它们。

本章的部分包括：

+   命令式与声明式

+   声明您的第一个应用程序

+   Kubernetes 资源-注释

+   Kubernetes 资源-ConfigMap

+   Kubernetes 资源-秘密

+   使用 ConfigMap 的 Python 示例

# 命令式与声明式命令

到目前为止，我们的示例主要集中在快速和命令式的命令，例如`kubectl run`来创建一个部署，然后运行我们的软件。这对于一些快速操作很方便，但不容易暴露 API 的全部灵活性。要利用 Kubernetes 提供的所有选项，通常更有效的方法是管理描述您想要的部署的文件。

在使用这些文件时，您可以使用`kubectl create`、`kubectl delete`和`kubectl replace`命令，以及`-f`选项来指定要使用的文件。命令式命令对于简单的设置很容易有效，但您很快就需要一系列重复使用的命令，以充分利用所有功能。您可能会将这些命令集存储在一个备忘单中，但这可能会变得繁琐，而且并不总是清晰明了。

Kubernetes 还提供了一种声明性机制，利用`kubectl apply`命令，该命令接受文件，审查当前状态，并根据需要管理更新-创建、删除等，同时保持更改的简单审计日志。

我建议对于任何比运行单个进程更复杂的事情使用`kubectl apply`命令，这可能是您开发的大多数服务。您在开发中可能不需要审计跟踪。但在暂存/金丝雀环境或生产环境中可能需要，因此熟悉并熟悉它们对于理解它们是有利的。

最重要的是，通过将应用程序的描述放在文件中，您可以将它们包含在源代码控制中，将它们视为代码。这为您提供了一种一致的方式来在团队成员之间共享该应用程序结构，所有这些成员都可以使用它来提供一致的环境。

`kubectl apply`命令有一个`-f`选项，用于指定文件或文件目录，以及一个`-R`选项，如果您正在建立一个复杂的部署，它将递归地遍历目录。

随着我们在本书中的进展，我将使用 YAML 格式（带有注释）的声明性命令和配置来描述和操作 Kubernetes 资源。如果您有强烈的偏好，也可以使用 JSON。

注意：如果您想要一个命令行工具来解析 YAML，那么有一个等价于`jq`用于 JSON 的工具：`yq`。我们的示例不会详细介绍，但如果您想使用该工具，可以在[`yq.readthedocs.io`](https://yq.readthedocs.io)找到更多信息。

# 一堵墙的 YAML

这些配置看起来是什么样子的？其中绝大多数是以 YAML 格式进行管理，选项和配置可能看起来令人不知所措。Kubernetes 中的每个资源都有自己的格式，其中一些格式正在发生变化并处于积极开发中。您会注意到一些 API 和对象结构将积极引用`alpha`或`beta`，以指示项目中这些资源的成熟状态。该项目倾向于以非常保守的方式使用这些术语：

+   `alpha`倾向于意味着这是一个早期实验，数据格式可能会发生变化，但很可能会存在实现最终目标的东西

+   `beta`比纯粹的实验更加可靠，很可能可以用于生产负载，尽管特定的资源格式尚未完全确定，并且可能会在 Kubernetes 发布过程中略微更改

请注意，随着 Kubernetes 的新版本发布，alpha 和 beta API 会不断发展。如果您使用较早版本，它可能会变得不推荐使用，并最终不可用。您需要跟踪这些更新与您正在使用的 Kubernetes 版本。

资源的正式文档、选项和格式托管在[`kubernetes.io`](https://kubernetes.io)的参考文档下。在我写这篇文章时，当前发布的版本是 1.8，该版本的参考文档可在[`kubernetes.io/docs/api-reference/v1.8/`](https://kubernetes.io/docs/api-reference/v1.8/)上找到。该文档是从 Kubernetes 项目源代码生成的，并在每次发布时更新，通常每三个月左右发布一次。

除了浏览参考文档之外，您还可以从现有的 Kubernetes 对象中获取声明。当您使用`kubectl get`命令请求 Kubernetes 资源时，可以添加`-o yaml --export`选项。

如果您更喜欢该格式，`-o yaml`选项可以改为`-o json`。`--export`将剥离一些与 Kubernetes 内部资源的当前状态和身份相关的多余信息，并且不会对您在外部存储时有所帮助。

尽管在 1.8 版本中，这种能力还不完全，但您应该能够要求在一个命名空间中的所有资源，存储这些配置，并使用这些文件来精确地复制它。在实践中，会有一些小问题，因为导出的版本并不总是完全符合您的要求。在这一点上，更好的做法是管理自己的声明文件。

最后，我建议使用 YAML 作为这些声明的格式。您可以使用 JSON，但 YAML 允许您在声明中添加注释，这对于其他人阅读这些文件非常有用——这是 JSON 格式所没有的功能。

# 创建一个简单的部署

让我们首先看看`kubectl run`为我们创建了什么，然后从那里开始。我们使用以下命令创建了之前的简单部署：

```
kubectl run flask --image=quay.io/kubernetes-for-developers/flask:0.1.1 --port=5000
```

在示例中，我们使用`kubectl get deployment flask -o json`命令转储了声明的状态。让我们重复一下，只是使用`-o yaml --export`选项：

```
kubectl get deployment flask -o yaml --export
```

输出应该看起来像下面这样：

```
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
 annotations:
 deployment.kubernetes.io/revision: "1"
 creationTimestamp: null
 generation: 1
 labels:
 run: flask
 name: flask
 selfLink: /apis/extensions/v1beta1/namespaces/default/deployments/flask
spec:
 replicas: 1
 selector:
 matchLabels:
 run: flask
 strategy:
 rollingUpdate:
 maxSurge: 1
 maxUnavailable: 1
 type: RollingUpdate
 template:
 metadata:
 creationTimestamp: null
 labels:
 run: flask
 spec:
 containers:
 - image: quay.io/kubernetes-for-developers/flask:latest
 imagePullPolicy: Always
 name: flask
 ports:
 - containerPort: 5000
 protocol: TCP
 resources: {}
 terminationMessagePath: /dev/termination-log
 terminationMessagePolicy: File
 dnsPolicy: ClusterFirst
 restartPolicy: Always
 schedulerName: default-scheduler
      securityContext: {}
 terminationGracePeriodSeconds: 30
status: {}
```

任何 Kubernetes 资源的一般格式都将具有相同的顶部四个对象：

+   `apiVersion`

+   `kind`

+   `metadata`

+   `spec`

如果您从 Kubernetes 检索信息，您将看到第五个键：`status`。状态不需要由用户定义，并且在检索对象以共享其当前状态时由 Kubernetes 提供。如果您在`kubectl get`命令上错过了`--export`选项，它将包括状态。

您会看到对象中散布着元数据，因为这些对象彼此相关，并在概念上相互构建。尽管它们可能被合并（如前面所示）成单个引用，但元数据被包含在每个资源中。对于我们创建的部署，它使用了部署的声明性引用，它包装了一个 ReplicaSet，该 ReplicaSet 又包装了一个 Pod。

您可以在以下 URL 中查看每个的正式定义：

+   Deployment：[`kubernetes.io/docs/api-reference/v1.8/#deployment-v1beta2-apps`](https://kubernetes.io/docs/api-reference/v1.8/#deployment-v1beta2-apps)

+   ReplicaSet：[`kubernetes.io/docs/api-reference/v1.8/#replicaset-v1beta2-apps`](https://kubernetes.io/docs/api-reference/v1.8/#replicaset-v1beta2-apps)

+   Pod：[`kubernetes.io/docs/api-reference/v1.8/#pod-v1-core`](https://kubernetes.io/docs/api-reference/v1.8/#pod-v1-core)

您可能会注意到 ReplicaSet 和 Deployment 几乎是相同的。部署扩展了 ReplicaSet，并且每个部署实例都至少有一个 ReplicaSet。部署包括声明性选项（以及责任），用于如何在运行软件上执行更新。Kubernetes 建议在部署代码时，使用部署而不是直接使用 ReplicaSet，以便精确指定您希望它在更新时如何反应。

在部署`spec`（[`kubernetes.io/docs/api-reference/v1.8/#deploymentspec-v1beta2-apps`](https://kubernetes.io/docs/api-reference/v1.8/#deploymentspec-v1beta2-apps)）中，所有在模板键下的项目都是从 Pod 模板规范中定义的。您可以在[`kubernetes.io/docs/api-reference/v1.8/#podtemplatespec-v1-core`](https://kubernetes.io/docs/api-reference/v1.8/#podtemplate-v1-core)查看 Pod 模板规范的详细信息。

如果您查看在线文档，您会看到许多我们没有指定的选项。当它们没有被指定时，Kubernetes 仍会使用规范中定义的默认值填充这些值。

您可以根据需要指定完整或轻量级的选项。所需字段的数量非常少。通常只有在您想要不同于默认值的值时，才需要定义可选字段。例如，对于一个部署，必需字段是名称和要部署的镜像。

在为自己的代码创建声明时，我建议保持一组最小的 YAML 声明。这将有助于更容易理解您的资源声明，并且与大量使用注释一起，应该使得生成的文件易于理解。

# 声明您的第一个应用程序

继续选择一个示例并创建一个部署声明，然后尝试使用该声明创建一个。

我建议创建一个名为 `deploy` 的目录，并将您的声明文件放在其中。这是使用 `flask` 示例：

```
flask.yml
```

```
apiVersion: apps/v1beta1
kind: Deployment
metadata:
 name: flask
 labels:
 run: flask
spec:
 template:
 metadata:
 labels:
 app: flask
 spec:
 containers:
 - name: flask
 image: quay.io/kubernetes-for-developers/flask:0.1.1
 ports: 
 - containerPort: 5000
```

在尝试您的文件之前，请删除现有的部署：

```
kubectl delete deployment flask
```

使用 `--validate` 选项是一个很好的做法，可以让 `kubectl` 检查文件，并且您可以将其与 `--dry-run` 一起使用，将文件与 Kubernetes 中的任何现有内容进行比较，以便让您明确知道它将要执行的操作。 YAML 很容易阅读，但不幸的是，由于其使用空格来定义结构，很容易出现格式错误。使用 `--validate` 选项，`kubectl` 将警告您缺少字段或其他问题。如果没有它，`kubectl` 通常会悄悄地失败，只是简单地忽略它不理解的内容：

```
kubectl apply -f deploy/flask.yml --dry-run --validate
```

您应该看到以下结果：

```
deployment "flask" created (dry run)
```

如果您不小心打了错字，您将在输出中看到报告的错误。我在一个键中故意打了错字，`metadata`，结果如下：

```
error: error validating "deploy/flask.yml": error validating data: found invalid field metdata for v1.PodTemplateSpec; if you choose to ignore these errors, turn validation off with --validate=false
```

一旦您确信数据经过验证并且将按预期工作，您可以使用以下命令创建对象：

```
kubectl apply -f deploy/flask.yml
```

即使在尝试运行代码时，仍然很容易犯一些不明显的小错误，但在尝试运行代码时会变得清晰。您可以使用 `kubectl get` 命令来检查特定资源。我建议您还使用 `kubectl describe` 命令来查看有关 Kubernetes 的所有相关事件，而不仅仅是资源的状态：

```
kubectl describe deployment/flask
```

```
 Name: flask
Namespace: default
CreationTimestamp: Sun, 22 Oct 2017 14:03:27 -0700
Labels: run=flask
Annotations: deployment.kubernetes.io/revision=1
 kubectl.kubernetes.io/last-applied-configuration={"apiVersion":"apps/v1beta1","kind":"Deployment","metadata":{"annotations":{},"labels":{"run":"flask"},"name":"flask","namespace":"default"},"spec":{"t...
Selector: app=flask
Replicas: 1 desired | 1 updated | 1 total | 1 available | 0 unavailable
StrategyType: RollingUpdate
MinReadySeconds: 0
RollingUpdateStrategy: 25% max unavailable, 25% max surge
Pod Template:
 Labels: app=flask
 Containers:
 flask:
 Image: quay.io/kubernetes-for-developers/flask:0.1.1
 Port: 5000/TCP
 Environment: <none>
 Mounts: <none>
 Volumes: <none>
Conditions:
 Type Status Reason
 ---- ------ ------
 Available True MinimumReplicasAvailable
 Progressing True NewReplicaSetAvailable
OldReplicaSets: <none>
NewReplicaSet: flask-2003485262 (1/1 replicas created)
Events:
 Type Reason Age From Message
 ---- ------ ---- ---- -------
 Normal ScalingReplicaSet 5s deployment-controller Scaled up replica set flask-2003485262 to 1
```

一旦您对声明的工作原理感到满意，请将其与您的代码一起存储在源代码控制中。本书的示例部分将转移到使用存储的配置，并且本章和以后的章节将更新 Python 和 Node.js 示例。

如果要创建 Kubernetes 资源，然后使用`kubectl apply`命令对其进行管理，应在运行`kubectl run`或`kubectl create`命令时使用`--save-config`选项。这将明确添加`kubectl apply`在运行时期望存在的注释。如果它们不存在，命令仍将正常运行，但会收到警告：

```
Warning: kubectl apply should be used on resource created by either kubectl create --save-config or kubectl apply
```

# ImagePullPolicy

如果在尝试事物时在代码中使用`:latest`标签，您可能已经注意到`imagePullPolicy`的值被设置为`Always`：

```
imagePullPolicy: Always
```

这告诉 Kubernetes 始终尝试从容器存储库加载新的 Docker 镜像。如果使用的标签不是`:latest`，那么默认值(`IfNotPresent`)只会在本地缓存中找不到容器镜像时尝试重新加载它们。

这是一种在频繁更新代码时非常有用的技术。我建议只在独自工作时使用这种技术，因为分享`：latest`的确切含义可能很困难，并且会导致很多混乱。

在任何暂存或生产部署中使用`:latest`标签通常被认为是一种不好的做法，仅仅是因为它引用的内容不确定。

# 审计跟踪

当您使用`kubectl apply`命令时，它会自动在 Kubernetes 资源中的注释中为您维护审计跟踪。如果使用以下命令：

```
kubectl describe deployment flask
```

您将看到类似以下的相当可读的输出：

```
Name: flask
Namespace: default
CreationTimestamp: Sat, 16 Sep 2017 08:31:00 -0700
Labels: run=flask
Annotations: deployment.kubernetes.io/revision=1
kubectl.kubernetes.io/last-applied-configuration={"apiVersion":"apps/v1beta1","kind":"Deployment","metadata":{"annotations":{},"labels":{"run":"flask"},"name":"flask","namespace":"default"},"spec":{"t...
Selector: app=flask
Replicas: 1 desired | 1 updated | 1 total | 1 available | 0 unavailable
StrategyType: RollingUpdate
MinReadySeconds: 0
RollingUpdateStrategy: 25% max unavailable, 25% max surge
Pod Template:
 Labels: app=flask
 Containers:
 flask:
 Image: quay.io/kubernetes-for-developers/flask:0.1.1
 Port: 5000/TCP
 Environment: <none>
 Mounts: <none>
 Volumes: <none>
Conditions:
 Type Status Reason
 ---- ------ ------
 Available True MinimumReplicasAvailable
 Progressing True NewReplicaSetAvailable
OldReplicaSets: <none>
NewReplicaSet: flask-866287979 (1/1 replicas created)
Events:
 FirstSeen LastSeen Count From SubObjectPath Type Reason Message
 --------- -------- ----- ---- ------------- -------- ------ ------
 2d 2d 1 deployment-controller Normal ScalingReplicaSetScaled up replica set flask-866287979 to 1
```

我提到的审计跟踪包含在注释`kubectl.kubernetes.io/last-applied-configuration`中，其中包括最后应用的配置。由于该注释相当长，因此在此输出中对其进行了修剪。如果要转储整个对象，可以查看完整的详细信息，如下所示：

```
kubectl get deployment flask -o json
```

我们感兴趣的信息是`metadata` | `annotations` `kubectl.kubernetes.io/last-applied-configuration`。该注释中的完整细节可能如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/caa72445-4fd3-45c6-82a8-c5b25d63efaa.png)

# Kubernetes 资源-注释

标签和选择器用于对 Kubernetes 资源进行分组和选择，而注释提供了一种添加特定于资源的元数据的方法，这些元数据可以被 Kubernetes 或其运行的容器访问。

正如您刚才看到的，`kubectl apply`在调用时会自动应用一个注释，以跟踪资源的最后应用配置状态。在上一章中，您可能已经注意到部署控制器用于跟踪修订版本的注释`deployment.kubernetes.io/revision`，我们还谈到了`kubernetes.io/change-cause`注释，该注释被`kubectl`用于显示部署发布的更改历史。

注释可以是简单的值或复杂的块（如`kubectl.kubernetes.io/last-applied-configuration`的情况）。到目前为止的示例是 Kubernetes 工具使用注释共享信息，尽管注释也用于在容器中共享信息供应用程序使用。

您可以使用它们来包含诸如添加版本控制修订信息、构建编号、相关的可读联系信息等信息。

与标签一样，注释可以使用命令`kubectl annotate`来添加。一般来说，注释使用与标签相同的键机制，因此任何包含`kubernetes.io`前缀的注释都是来自 Kubernetes 项目的内容。

标签旨在对 Kubernetes 对象（Pod、部署、服务等）进行分组和组织。注释旨在为实例（或一对实例）提供特定的附加信息，通常作为注释本身的附加数据。

# 在 Pod 中公开标签和注释

Kubernetes 可以直接在容器中公开有关 Pod 的数据，通常作为特定文件系统中的文件，您的代码可以读取和使用。标签、注释等可以通过容器规范作为文件在您的容器中提供，并使用 Kubernetes 所谓的`downwardAPI`。

这可以是一种方便的方式，可以在容器中公开注释信息，例如构建时间，源代码引用哈希等，以便您的运行时代码可以读取和引用这些信息。

为了使 Pod 的标签和注释可用，您需要为容器定义一个卷挂载，然后指定`downwardAPI`和卷挂载点中的项目。

更新`flask`部署文件：

```
apiVersion: apps/v1beta1
kind: Deployment
metadata:
 name: flask
 labels:
 run: flask
 annotations:
 example-key: example-data
spec:
 template:
 metadata:
 labels:
 app: flask
 spec:
 containers:
 - name: flask
 image: quay.io/kubernetes-for-developers/flask:0.1.1
 ports:
 - containerPort: 5000
 volumeMounts:
          - name: podinfo
 mountPath: /podinfo
 readOnly: false
 volumes:
 - name: podinfo
 downwardAPI:
 items:
 - path: "labels"
 fieldRef:
 fieldPath: metadata.labels
 - path: "annotations"
 fieldRef:
 fieldPath: metadata.annotations
```

下面部分的细节标识了一个挂载点——将在容器内创建的目录结构。它还指定卷应该使用`downwardAPI`与特定的元数据；在这种情况下，是标签和注释。

当您指定卷挂载位置时，请注意不要指定已经存在并且有文件的位置（例如/等），否则容器可能无法按预期运行。挂载点不会抛出错误-它只是覆盖容器中该位置可能已经存在的任何内容。

您可以使用以下命令应用此更新的声明：

```
kubectl apply -f ./flask.yml
```

现在我们可以打开一个 shell 到正在运行的 Pod，使用以下命令：

```
kubectl exec flask-463137380-d4bfx -it -- sh
```

然后在活动的 shell 中运行以下命令：

```
ls -l /podinfo
```

```
total 0
lrwxrwxrwx    1 root     root            18 Sep 16 18:14 annotations -> ..data/annotations
lrwxrwxrwx    1 root     root            13 Sep 16 18:14 labels -> ..data/labels
```

```
cat /podinfo/annotations
```

```
kubernetes.io/config.seen="2017-09-16T18:14:04.024412807Z"
kubernetes.io/config.source="api"
kubernetes.io/created-by="{\"kind\":\"SerializedReference\",\"apiVersion\":\"v1\",\"reference\":{\"kind\":\"ReplicaSet\",\"namespace\":\"default\",\"name\":\"flask-463137380\",\"uid\":\"d262ca60-9b0a-11e7-884c-0aef48c812e4\",\"apiVersion\":\"extensions\",\"resourceVersion\":\"121204\"}}\n"
```

```
cat /podinfo/labels
```

```
app="flask"
pod-template-hash="463137380"
```

您可以通过以下方式将其与 Pod 本身的注释进行比较：

```
kubectl describe pod flask-463137380-d4bfx
```

```
Name: flask-463137380-d4bfx
Namespace: default
Node: minikube/192.168.64.3
Start Time: Sat, 16 Sep 2017 11:14:04 -0700
Labels: app=flask
pod-template-hash=463137380
Annotations: kubernetes.io/created-by={"kind":"SerializedReference","apiVersion":"v1","reference":{"kind":"ReplicaSet","namespace":"default","name":"flask-463137380","uid":"d262ca60-9b0a-11e7-884c-0aef48c812e4","a...
Status: Running
IP: 172.17.0.5
Created By: ReplicaSet/flask-463137380
Controlled By: ReplicaSet/flask-463137380
```

有关 Pod 的各种数据可以在 Pod 中公开，并且可以通过环境变量将相同的数据公开给 Pod。可以公开的完整数据集在 Kubernetes 文档中有详细说明（[`kubernetes.io/docs/tasks/inject-data-application/downward-api-volume-expose-pod-information/`](https://kubernetes.io/docs/tasks/inject-data-application/downward-api-volume-expose-pod-information/)）。

尽管使用这种机制来提供传递配置数据的方法可能看起来方便和明显，但 Kubernetes 提供了额外的功能，专门用于为容器内的代码提供配置，包括密码、访问令牌和其他机密信息所需的私有配置。

# Kubernetes 资源 - ConfigMap

当您将容器创建为代码的只读实例时，您很快就会需要一种方式来提供标志或配置的小改变。也许更重要的是，您不希望在容器映像中包含诸如 API 密钥、密码或身份验证令牌等私人详细信息。

Kubernetes 支持两种资源来帮助并链接这种类型的信息。第一种是 ConfigMap，可以单独使用或跨 Pod 用于应用部署，为应用程序提供更新和传播配置的单一位置。Kubernetes 还支持 Secret 的概念，这是一种更加严格控制和仅在需要时才公开的配置类型。

例如，一个人可能会使用 ConfigMap 来控制示例 Redis 部署的基本配置，并使用 Secret 来分发敏感的身份验证凭据，以供客户端连接。

# 创建 ConfigMap

您可以使用`kubectl create configmap`命令创建 ConfigMap，其中配置的数据可以在命令行上设置，也可以来自您存储的一个或多个文件。它还支持加载文件目录以方便使用。

从命令行创建单个键/值对非常简单，但可能是管理配置的最不方便的方式。例如，运行以下命令：

```
kubectl create configmap example-config --from-literal=log.level=err
```

这将创建一个名为`example-config`的 ConfigMap，其中包含一个键/值对。您可以使用以下命令查看加载的所有配置列表：

```
kubectl get configmap
```

```
NAME             DATA      AGE
example-config   0         2d
```

并使用以下命令查看 ConfigMap：

```
kubectl describe configmap example-config
```

```
Name: example-config
Namespace: default
Labels: <none>
Annotations: <none>
Data
====
log.level:
----
err
Events: <none>
```

您还可以请求以 YAML 格式获取原始数据：

```
kubectl get configmap example-config -o yaml --export apiVersion: v1
data:
 log.level: err
kind: ConfigMap
metadata:
 creationTimestamp: null
 name: example-config
 selfLink: /api/v1/namespaces/default/configmaps/example-config
```

您还可以请求以 JSON 格式获取原始数据：

```
kubectl get configmap example-config -o json --export {
 "apiVersion": "v1",
 "data": {
 "log.level": "err"
 },
 "kind": "ConfigMap",
 "metadata": {
 "creationTimestamp": null,
 "name": "example-config",
 "selfLink": "/api/v1/namespaces/default/configmaps/example-config"
 }
}
```

从字面值创建的配置的值通常是字符串。

如果您想创建代码可以解析为不同类型（数字、布尔值等）的配置值，则需要将这些配置指定为文件，或者在 YAML 或 JSON 格式的 ConfigMap 对象中定义它们为块。

如果您希望将配置分开存储在不同的文件中，它们可以以简单的`key=value`格式具有多行，每行一个配置。`kubectl create configmap <name> --from-file <filename>`命令将加载这些文件，创建一个基于文件名的`configmap`名称，其中包含来自文件的所有相关数据。如果您已经有要处理的配置文件，可以使用此选项基于这些文件创建 ConfigMaps。

例如，如果您想要一个名为`config.ini`的配置文件加载到 ConfigMap 中：

```
[unusual]
greeting=hello
onoff=true
anumber=3
```

您可以使用以下命令创建一个`iniconfig` ConfigMap：

```
kubectl create configmap iniconfig --from-file config.ini --save-config
```

将数据转储回 ConfigMap：

```
kubectl get configmap iniconfig -o yaml --export
```

应该返回类似以下的内容：

```
apiVersion: v1
data:
 config.ini: |
 [unusual]
 greeting=hello
 onoff=true
 anumber=3
kind: ConfigMap
metadata:
 name: iniconfig
 selfLink: /api/v1/namespaces/default/configmaps/iniconfig
```

YAML 输出中的管道符号（`|`）定义了多行输入。这些类型的配置不会直接作为环境变量可用，因为它们对于该格式是无效的。一旦将它们添加到 Pod 规范中，它们可以作为文件提供。将它们添加到 Pod 规范中与使用向下 API 在 Pod 的容器中公开标签或注释的方式非常相似。

# 管理 ConfigMaps

一旦您创建了一个 ConfigMap，就不能使用`kubectl create`命令用另一个 ConfigMap 覆盖它。您可以删除它并重新创建，尽管更有效的选项是像其他 Kubernetes 资源一样管理配置声明，使用`kubectl apply`命令进行更新。

如果您在尝试一些想法时使用`kubectl create`命令创建了初始的 ConfigMap，您可以开始使用`kubectl apply`命令来管理该配置，方式与我们之前在部署中使用的方式相同：导出 YAML，然后从该文件中使用`kubectl apply`。

例如，要获取并存储我们之前在 deploy 目录中创建的配置，您可以使用以下命令：

```
kubectl get configmap example-config -o yaml --export > deploy/example-config.yml
```

在 Kubernetes 的 1.7 版本中，导出中添加了一些字段，这些字段并不是严格需要的，但如果您将它们留在那里也不会有任何问题。查看文件时，您应该看到类似以下内容：

```
apiVersion: v1
data:
 log.level: err
kind: ConfigMap
metadata:
 creationTimestamp: null
 name: example-config
 selfLink: /api/v1/namespaces/default/configmaps/example-config
```

`data`、`apiVersion`、`kind`和 metadata 的键都是关键的，但 metadata 下的一些子键并不是必需的。例如，您可以删除`metadata.creationTimestamp`和`metadata.selfLink`。

现在您在 Kubernetes 中仍然有 ConfigMap 资源，因此第一次运行`kubectl apply`时，它会警告您正在做一些有点意外的事情：

```
kubectl apply -f deploy/example-config.yml
```

```
Warning: kubectl apply should be used on resource created by either kubectl create --save-config or kubectl apply
configmap "example-config" configured
```

您可以通过在`kubectl create`命令中使用`--save-config`选项来摆脱此警告，这将包括`kubectl apply`期望存在的注释。

此时，`kubectl apply`已应用了其差异并进行了相关更新。如果您现在从 Kubernetes 中检索数据，它将具有`kubectl apply`在更新资源时添加的注释。

```
kubectl get configmap example-config -o yaml --export
```

```
apiVersion: v1
data:
 log.level: err
kind: ConfigMap
metadata:
 annotations:
 kubectl.kubernetes.io/last-applied-configuration: |
 {"apiVersion":"v1","data":{"log.level":"err"},"kind":"ConfigMap","metadata":{"annotations":{},"name":"example-config","namespace":"default"}}
 creationTimestamp: null
 name: example-config
 selfLink: /api/v1/namespaces/default/configmaps/example-config
```

# 将配置暴露到您的容器映像中

有两种主要方法可以将配置数据暴露到您的容器中：

+   将一个或多个 ConfigMaps 的键连接到为您的 Pod 设置的环境变量中

+   Kubernetes 可以将一个或多个 ConfigMaps 中的数据映射到挂载在 Pod 中的卷中。

主要区别在于环境变量通常在调用容器启动时设置一次，并且通常是简单的字符串值，而作为卷中数据挂载的 ConfigMaps 可以更复杂，并且如果更新 ConfigMap 资源，它们将被更新。

请注意，目前不存在明确告知容器 ConfigMap 值已更新的机制。截至 1.9 版本，Kubernetes 不包括任何方式来向 Pod 和容器发出更新的信号。

此外，作为文件挂载公开的配置数据不会立即更新。更新 ConfigMap 资源和在相关 Pod 中看到更改反映之间存在延迟。

# 环境变量

在定义 Pod 规范时，除了强制的名称和镜像键之外，您还可以指定一个 `env` 键。环境键需要一个名称，并且您可以添加一个使用 `valueFrom:` 引用 ConfigMap 中的数据的键。

例如，要将我们的示例配置公开为环境变量，您可以将以下段添加到 Pod 规范中：

```
env:
 - name: LOG_LEVEL_KEY
 valueFrom:
 configMapKeyRef:
 name: example-config
 Key: log.level
```

在 Pod 规范中，您可以包含多个环境变量，并且每个环境变量可以引用不同的 ConfigMap，如果您的配置分成多个部分，以便更容易（或更合理）进行管理。

您还可以将整个 ConfigMap 映射为环境变量作为单个块的所有键/值。

您可以使用 `envFrom` 而不是在 `env` 下使用单独的键，并指定 ConfigMap，例如：

```
envFrom:
 - configMapRef:
 name: example-config
```

使用此设置，每当 Pod 启动时，所有配置数据键/值都将作为环境变量加载。

您可以在 ConfigMap 中创建不适合作为环境变量的键，例如以数字开头的键。在这些情况下，Kubernetes 将加载所有其他键，并在事件日志中记录失败的键，但不会抛出错误。您可以使用 `kubectl get events` 查看失败的消息，其中将显示因为无效而跳过的每个键。

如果您想要使用 ConfigMap 值中的一个作为在容器内运行的命令传递的参数，也可以这样做。当您通过 `env` 和名称指定环境变量时，您可以在 Pod 规范中的其他地方引用该变量使用 `$(ENVIRONMENT_VARIABLE_NAME)`。

例如，以下 `spec` 片段在容器调用中使用了环境变量：

```
spec:
 containers:
 - name: test-container
 image: gcr.io/google_containers/busybox
 command: [ "/bin/sh", "-c", "echo $(LOG_LEVEL_KEY)" ]
 env:
 - name: LOG_LEVEL_KEY
 valueFrom:
 configMapKeyRef:
 name: example-config
 key: log.level
```

# 在容器内部将 ConfigMap 暴露为文件

将 ConfigMap 数据暴露到容器中的文件中，与如何将注释和标签暴露到容器中非常相似。Pod 规范有两个部分。第一部分是为容器定义一个卷，包括名称和应该挂载的位置：

```
 volumeMounts:
 - name: config
 mountPath: /etc/kconfig
 readOnly: true
```

第二部分是一个卷描述，引用了相同的卷名称，并将 ConfigMap 列为属性，指示从哪里获取这些值：

```
 volumes:
 - name: config
 configMap:
 name: example-config
```

一旦应用了该规范，这些值将作为容器内的文件可用：

```
ls -al /etc/kconfig/
```

```
total 12
drwxrwxrwx    3 root     root          4096 Sep 17 00:57 .
drwxr-xr-x    1 root     root          4096 Sep 17 00:57 ..
drwxr-xr-x    2 root     root          4096 Sep 17 00:57 ..9989_17_09_00_57_49.704362876
lrwxrwxrwx    1 root     root            31 Sep 17 00:57 ..data -> ..9989_17_09_00_57_49.704362876
lrwxrwxrwx    1 root     root            16 Sep 17 00:57 log.level -> ..data/log.level
```

```
cat /etc/kconfig/log.level
```

```
Err
```

您可以使用环境变量或配置文件来为应用程序提供配置数据，只需取决于哪种方式更容易或更符合您的需求。我们将更新示例，使用 ConfigMaps 并将 ConfigMaps 添加到部署中，并在示例应用程序的代码中引用这些值。

# 对 ConfigMaps 的依赖

如果您开始在 Pod 规范中引用 ConfigMap，那么您正在为资源创建对该 ConfigMap 的依赖。例如，如果您添加了一些前面的示例来将`example-data`暴露为环境变量，但尚未将`example-config` ConfigMap 添加到 Kubernetes 中，当您尝试部署或更新 Pod 时，它将报告错误。

如果发生这种情况，错误通常会在`kubectl get pods`中报告，或者在事件日志中可见：

```
kubectl get pods
```

```
NAME                     READY     STATUS                                  RESTARTS   AGE
flask-4207440730-xpq8t   0/1       configmaps "example-config" not found   0          2d
```

```
kubectl get events
```

```
LASTSEEN   FIRSTSEEN   COUNT     NAME                     KIND         SUBOBJECT                TYPE      REASON                  SOURCE                  MESSAGE
2d         2d          1         flask-4207440730-30vn0   Pod                                   Normal    Scheduled               default-scheduler       Successfully assigned flask-4207440730-30vn0 to minikube
2d         2d          1         flask-4207440730-30vn0   Pod                                   Normal    SuccessfulMountVolume   kubelet, minikube       MountVolume.SetUp succeeded for volume "podinfo"
2d         2d          1         flask-4207440730-30vn0   Pod                                   Normal    SuccessfulMountVolume   kubelet, minikube       MountVolume.SetUp succeeded for volume "default-token-s40w4"
2d         2d          2         flask-4207440730-30vn0   Pod          spec.containers{flask}   Normal    Pulling                 kubelet, minikube       pulling image "quay.io/kubernetes-for-developers/flask:latest"
2d         2d          2         flask-4207440730-30vn0   Pod          spec.containers{flask}   Normal    Pulled                  kubelet, minikube       Successfully pulled image "quay.io/kubernetes-for-developers/flask:latest"
2d         2d          2         flask-4207440730-30vn0   Pod          spec.containers{flask}   Warning   Failed                  kubelet, minikube       Error: configmaps "example-config" not found
2d         2d          2         flask-4207440730-30vn0   Pod                                   Warning   FailedSync              kubelet, minikube       Error syncing pod
2d         2d          1         flask-4207440730         ReplicaSet                            Normal    SuccessfulCreate        replicaset-controller   Created pod: flask-4207440730-30vn0
2d         2d          1         flask                    Deployment                            Normal    ScalingReplicaSet       deployment-controller   Scaled up replica set flask-4207440730 to 1
```

如果在事后添加 ConfigMap，当 Pod 需要的资源可用时，Pod 将启动。

# Kubernetes 资源 - Secrets

ConfigMaps 非常适用于一般配置，但很容易被看到，这可能不是期望的。对于一些配置，例如密码、授权令牌或 API 密钥，通常希望有一种更受控制的机制来保护这些值。这就是资源 Secrets 旨在解决的问题。

Secrets 通常是单独创建（和管理）的，并且在内部 Kubernetes 使用`base64`编码存储这些数据。

您可以通过首先将值写入一个或多个文件，然后在`create`命令中指定这些文件来在命令行上创建一个 secret。Kubernetes 将负责进行所有相关的`base64`编码并将其存储起来。例如，如果您想要存储数据库用户名和密码，您可以执行以下操作：

```
echo -n “admin” > username.txt
echo -n “sdgp63lkhsgd” > password.txt
kubectl create secret generic database-creds --from-file=username.txt --from-file=password.txt
```

请注意，在命名 secret 的名称时，您可以使用任何字母数字字符，`-`或`.`，但不允许使用下划线。

如果您使用以下命令：

```
kubectl get secrets
```

您可以看到我们刚刚创建的秘密：

```
NAME                  TYPE                                  DATA      AGE
database-creds        Opaque                                2         2d
default-token-s40w4   kubernetes.io/service-account-token   3         5d
```

通过使用以下方式：

```
kubectl describe secret database-creds
```

```
Name: database-creds
Namespace: default
Labels: <none>
Annotations: <none>
Type: Opaque
Data
====
password.txt: 18 bytes
username.txt: 11 bytes
```

您会看到秘密报告为类型`Opaque`，并且与数据关联的字节数。

您仍然可以使用以下方式获取秘密：

```
kubectl get secret database-creds -o yaml --export
```

这将显示`base64`编码的值：

```
apiVersion: v1
data:
  password.txt: 4oCcc2RncDYzbGtoc2dk4oCd
  username.txt: 4oCcYWRtaW7igJ0=
kind: Secret
metadata:
  creationTimestamp: null
  name: database-creds
  selfLink: /api/v1/namespaces/default/secrets/database-creds
type: Opaque
```

如果您`base64`解码该值，您将看到原始版本：

```
echo "4oCcc2RncDYzbGtoc2dk4oCd" | base64 --decode
```

```
“sdgp63lkhsgd”
```

请注意，任何可以访问您的 Kubernetes 集群资源的人都可以检索和查看这些秘密。此外，我不建议您像其他声明一样管理秘密，存储在源代码控制中。这样做会在您的源代码控制系统中暴露这些秘密（以`base64`形式）。

# 将秘密暴露到容器中

我们可以以与暴露 ConfigMaps 非常相似的方式将秘密暴露给 Pod。与 ConfigMaps 一样，您可以选择将秘密作为环境变量或作为卷中的文件暴露，由 Pod 指定。

暴露秘密的格式看起来与暴露 ConfigMap 值的格式相同，只是在规范中使用`secretKeyRef`而不是`configMapRef`。

例如，要将前面的示例秘密密码作为环境变量暴露，您可以在 Pod 规范中使用以下内容：

```
 env:
 - name: DB_PASSWORD
 valueFrom:
 secretKeyRef:
 name: database-creds
 key: password.txt
```

然后在容器内查看，环境变量容器`DB_PASSWORD`：

```
kubectl exec flask-509298146-ql1t9 -it -- sh
```

```
env | grep DB
```

```
DB_PASSWORD=“sdgp63lkhsgd”
```

更好的方法是利用 Kubernetes 包含的将秘密挂载为容器内文件的能力。配置与暴露 ConfigMap 值非常相似，只是在规范中将 Secret 定义为卷属性，而不是 ConfigMap。

在规范中，您需要为容器定义一个`volumeMount`，指示其在容器中的位置：

```
 volumeMounts:
 - name: secrets
 mountPath: "/secrets"
```

然后定义如何从秘密中填充该卷的内容：

```
 volumes:
 - name: secrets
 secret:
 secretName: database-creds
 items:
 - key: password.txt
 path: db_password
```

部署使用此配置后，容器中将有一个`/secrets/db_password`文件，其中包含来自我们秘密的内容：

```
/ # ls -l /secrets/
total 0
lrwxrwxrwx    1 root     root            18 Sep 17 00:49 db_password -> ..data/db_password
```

```
/ # ls -l /secrets/db_password
lrwxrwxrwx    1 root     root            18 Sep 17 00:49 /secrets/db_password -> ..data/db_password
```

```
/ # cat /secrets/db_password
“sdgp63lkhsgd”
```

# 秘密和安全性-秘密有多秘密？

合理地说，但在 Kubernetes 1.8 中至少不是密码学安全的。如果您从安全的角度看待秘密，那么对秘密的约束要比将值留在 ConfigMap 中好，但安全配置文件有显着的限制。

在本质上，密钥的数据以明文（尽管编码文本）存储在 etcd 3.0 中，etcd 3.0 是 Kubernetes 1.8 的基础。它不使用静态密钥来保留（和访问）密钥。如果您正在运行自己的 Kubernetes 集群，请注意，未经保护的 etcd 代表集群整体安全性的一个重大弱点。

对于许多应用程序和用例，这是完全可以接受的，但如果您需要在开发和生产环境中适应更高的安全配置文件，那么您将需要查看与 Kubernetes 配合使用的工具。最常讨论的替代/扩展是 Vault，这是 HashiCorp 的一个开源项目。您可以在[`www.vaultproject.io`](https://www.vaultproject.io)找到有关 Vault 的更多详细信息。

Kubernetes 项目在秘密和秘密管理方面也在不断发展。在 1.7 版本中，Kubernetes 包括**基于角色的访问控制**（**RBAC**），该项目正在根据路线图维护和开发，以改进 Kubernetes 的功能，提高其安全配置文件的能力，并在未来支持更容易与外部秘密管理源（如 Vault）协调。

# 示例-使用 ConfigMap 的 Python/Flask 部署

这个示例建立在我们之前的 Python/Flask 示例之上。此扩展将添加一个使用环境变量和结构化文件的 ConfigMap，以及用于消耗和使用这些值的代码更新。

首先，添加一个包含顶级值和更深层配置的 ConfigMap。顶级值将公开为环境变量，多行 YAML 将公开为容器内的文件：

```
# CONFIGURATION FOR THE FLASK APP
kind: ConfigMap
apiVersion: v1
metadata:
 name: flask-config
data:
 CONFIG_FILE: “/etc/flask-config/feature.flags“
 feature.flags: |
 [features]
 greeting=hello
 debug=true
```

这个 ConfigMap 与部署的 Pod 规范映射，使用`envFrom`键，并作为卷提供文件映射：

```
 spec:
 containers:
 - name: flask
 image: quay.io/kubernetes-for-developers/flask:latest
 ports:
 - containerPort: 5000
 envFrom:
 - configMapRef:
 name: flask-config
 volumeMounts:
 - name: config
 mountPath: /etc/flask-config
 volumes:
 - name: config
 configMap:
 name: flask-config
```

此更新对部署有一个名为`flask-config`的 ConfigMap 的依赖。如果 ConfigMap 没有加载，并且我们尝试加载更新的部署，它将不会更新部署，直到该 ConfigMap 可用。为了避免意外丢失文件的情况，您可以将 ConfigMap 和部署规范放在同一个 YAML 文件中，用新行上的`---`分隔。然后，您可以在使用`kubectl apply`命令时按照指定的顺序部署多个资源。

您还可以将每个资源保存在单独的文件中，如果这样更容易理解或管理，主要取决于您的偏好。`kubectl apply`命令包括选项来引用目录中的所有文件，包括递归地 - 因此，对文件进行排序和结构化；但是，最好自己管理它们。

为了匹配这个示例，[`github.com/kubernetes-for-developers/kfd-flask`](https://github.com/kubernetes-for-developers/kfd-flask)上的代码有一个标签，您可以使用它来一次更新所有文件：

```
git checkout 0.2.0
```

（如果您跳过了之前的示例，您可能需要首先克隆存储库：`git clone https://github.com/kubernetes-for-developers/kfd-flask`）

更新代码后，部署更新：

```
kubectl apply -f deploy/
```

部署后，您可以使用`kubectl exec`在 Pod 中运行交互式 shell，并检查部署和已暴露的内容。

# 侧边栏 - JSONPATH

我们可以使用类似以下命令查找特定的 Pod：

```
kubectl get pods -l app=flask
```

这将仅查找与`app=flask`选择器匹配的 Pod，并打印出类似以下的人类可读输出：

```
NAME                     READY     STATUS    RESTARTS   AGE
flask-2376258259-p1cwb   1/1       Running   0          8m
```

这些相同的数据以结构化形式（JSON、YAML 等）可用，我们可以使用诸如`jq`之类的工具进行解析。Kubectl 包括两个额外的选项，使其成为一个更方便的工具 - 您可以使用`JSONPATH 或 GO_TEMPLATE`来挖掘特定的值。使用内置到`kubectl`客户端的`JSONPATH`，而不是执行前面的两步骤来获取 Pod 名称，您可以直接获取我们想要使用的特定细节，即名称：

```
kubectl get pods -l app=flask -o jsonpath='{.items[*].metadata.name}'
```

这应该返回以下内容：

```
flask-2376258259-p1cwb
```

这可以很容易地嵌入到一个 shell 命令中，使用`$()`来内联执行它。这最终会成为一个更复杂的命令，但它会处理我们询问 Kubernetes 相关 Pod 名称的步骤，这对于许多交互命令来说至关重要。

例如，我们可以使用以下命令在与此部署相关联的 Pod 中打开交互式 shell：

```
kubectl exec $(kubectl get pods -l app=flask \
-o jsonpath='{.items[*].metadata.name}') \
-it -- /bin/sh
```

这获取了 Pod 的名称，并将其嵌入到`kubectl exec`中，以使用`/bin/sh`命令运行交互式会话。

一旦您打开了这个会话，您可以查看已设置的环境变量，如下所示：

```
env
```

这将显示设置的所有环境变量，其中之一应该是以下内容：

```
CONFIG_FILE=/etc/flask-config/feature.flags
```

您可以查看更复杂的配置数据：

```
cat $CONFIG_FILE
[features]
greeting=hello
debug=true
```

我们精心制作了 ConfigMap，根据我们放入部署规范的内容，为该文件的正确位置。如果我们更改部署规范，但不更改 ConfigMap，则嵌入在环境变量`CONFIG_FILE`中的位置将不正确。

使用 Kubernetes 部署、ConfigMap 和服务规范的 YAML，存在许多未抽象出的重复数据。从开发人员的角度来看，这将感到尴尬，违反了常见的不要重复自己的口头禅。有很多重复和小改变的地方，不幸地影响了部署规范。

Kubernetes 项目正在发展与这些文件交互的方式，努力使生成相关配置更加与仍处于早期开发阶段的项目相匹配。随着 Kubernetes 的不断成熟，在定义资源声明时，这应该会演变为更具有代码样式的特质。

# 在 Python/Flask 中使用 ConfigMap

在 Python 中，您可以使用 os.environ 查看环境变量，例如：

```
import os
os.environ.get('CONFIG_FILE’)
```

在代码中使用`os.environ.get`时，您可以设置默认值来处理环境变量未设置的情况：

```
import os
os.environ.get('CONFIG_FILE’,’./feature.flags’)
```

我们在这里设置`CONFIG_FILE`环境变量，以向您展示如何完成此操作，但严格来说，不一定需要读取配置文件-更多是为了方便您在需要时覆盖该值。

Python 还包括一个模块来解析和读取 INI 风格的配置文件，就像我们在 ConfigMap 中添加的那样。继续使用示例：

```
from configparser import SafeConfigParser
from pathlib import Path
# initialize the configuration parser with all the existing environment variables
parser = SafeConfigParser(os.environ)
```

从这里开始，ConfigParser 已加载了名为`DEFAULT`的部分，其中包含所有环境变量，我们可以检索其中的一个：

```
Python 3.6.1 (default, May  2 2017, 15:16:41)
[GCC 6.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> from configparser import SafeConfigParser
>>> from pathlib import Path
>>> # initialize the configuration parser with all the existing environment variables
... parser = SafeConfigParser(os.environ)
>>> parser.get('DEFAULT','CONFIG_FILE')
'/etc/flask-config/feature.flags'
```

我们可以使用基于存储在 ConfigMap 中的 INI 文件的部分来扩展解析器，该文件在文件系统上公开为`/etc/flask-config/feature.flags`，代码如下：

```
# default location of ./feature.flags is used if the environment variable isn’t set
config_file = Path(os.environ.get('CONFIG_FILE','/opt/feature.flags'))
# verify file exists before attempting to read and extend the configuration
if config_file.is_file():
 parser.read(os.environ.get('CONFIG_FILE'))
```

现在解析器将加载来自环境变量的`DEFAULT`部分和来自 ConfigMap 数据的`'features'`部分：

```
>>> parser.sections()
['features']
>>> parser.getboolean('features','debug')
True
```

ConfigParser 还可以使您在代码中包含默认值：

```
>>> parser.getboolean('features','something-else’,fallback=False)
False
```

然后我们使用这种代码来根据 ConfigMap 设置调试启用或禁用：

```
if __name__ == '__main__':
 debug_enable = parser.getboolean('features','debug',fallback=False)
 app.run(debug=debug_enable,host='0.0.0.0')
```

您可以在[`docs.python.org/3/library/configparser.html`](https://docs.python.org/3/library/configparser.html)找到有关如何利用 Python 3 的 ConfigParser 的更多详细信息。

# 摘要

在本章中，我们详细讨论了如何充分利用 Kubernetes 的声明性特性，并通过规范文件来管理我们的应用程序。我们还讨论了 Annotations、ConfigMap 和 Secrets 以及如何创建并在 Pods 内部使用它们。我们在本章中还更新了我们的 Python 和 Node.js 应用程序，以使用 ConfigMaps 来运行我们之前设置的示例代码，并简要介绍了如何利用 kubectl 中内置的`JSONPATH`来使该工具更具即时提供所需特定信息的强大功能。


# 第五章：Pod 和容器的生命周期

由于 Kubernetes 是一个声明性系统，为 Pod 和容器提供的生命周期和钩子是代码可以采取行动的地方。Pod 有一个生命周期，容器也有一个生命周期，Kubernetes 提供了许多地方，您可以向系统提供明确的反馈，以便它按照您的意愿运行。在本章中，我们将深入探讨预期的生命周期，可用的钩子以及如何使用它们的示例。

主题将包括：

+   Pod 生命周期

+   容器生命周期

+   探针

+   容器钩子：post-start 和 pre-stop

+   初始化容器

+   如何处理优雅关闭

# Pod 生命周期

Pod 的生命周期是几个组件的聚合，因为 Pod 有许多移动部分，可以处于各种状态，它的表示是 Kubernetes 如何管理你的代码运行，与各种控制器一起工作的控制和反馈循环。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/ab64835b-8b77-4df5-8e09-b3f564cea9c8.png)

Pod 生命周期的状态有：

+   **挂起**：Pod 已通过 API 创建，并正在被调度，加载并在其中一个节点上运行的过程中

+   **运行**：Pod 完全运行，并且软件在集群中运行

+   **成功（或）失败**：Pod 已完成操作（正常或崩溃）

+   **还有第四种状态**：未知，这是一个相当罕见的情况，通常只在 Kubernetes 内部出现问题时才会出现，它不知道容器的当前状态，或者无法与其底层系统通信以确定该状态。

如果您在容器中运行长时间运行的代码，那么大部分时间将花在运行中。如果您在 Kubernetes 中使用 Job 或 CronJob 运行较短的批处理代码，则最终状态（成功或失败）可能是您感兴趣的。

# 容器生命周期

由于每个 Pod 可以有一个或多个容器，因此容器也有一个由它们单独管理的状态。容器的状态更简单，而且非常直接：

+   等待

+   运行

+   终止

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/f141ab2e-01ec-4e6e-be7c-7e5b0fa7c4e5.png)

容器状态都有与之关联的时间戳，指示集群记录容器处于该状态的时间。如果经过了多个状态的处理，还会有一个最后状态字段。由于容器相当短暂，因此通常会看到先前状态为 Terminated，其中包括容器启动时间、完成时间、退出代码以及有关其终止原因的字符串条目。

以下是在您的 Pod 处理一段时间后容器状态的示例（在此示例中，经过多次更新后）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/99c93667-9d8e-47fa-928a-84350ce562d6.png)

您可以在 `kubectl describe pod` 命令的输出中以人类可读的格式看到额外的详细信息，这通常是快速了解 Pod 内发生的情况最方便的方法。

所有状态都包含额外的信息，以提供正在发生的详细信息。API 中有一个正式的 PodStatus 对象可用。每个状态都有可用的额外详细信息，而且通常状态对象包括一系列常见的条件，这些条件通常在描述或原始 YAML 的输出中是可见的。

使用 `kubectl get pod ... -o yaml` 命令，您可以以机器可解析的形式看到数据，并且可以看到在 `describe` 命令中未公开的额外详细信息。在以下截图中，您可以看到与 Pod 和容器状态相关的输出，包括条件、容器状态和相关时间戳：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/4c10fb77-c0ba-475e-8df0-c79784239f98.png)

随着 Kubernetes 对象经历其生命周期，条件被添加到其状态中。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/487c3b4c-5af2-4f94-88bf-2a6846f910fa.png)

在 Pod 状态 pending 中，通常会添加两个条件：`Initialized` 和 `PodScheduled`。如果集群无法运行请求的 Pod，则可能会看到条件 `Unschedulable` 而不是 `PodScheduled`。当 Pod 处于 Running 状态时，还有一个与之相关的条件 **Ready**，它会影响 Kubernetes 对代码的管理。

# 部署、ReplicaSets 和 Pods

Pods 不是唯一利用和暴露条件的 Kubernetes 资源。部署也使用条件来表示详细信息，例如代码更新的部署进度以及部署的整体可用性。

在使用部署时，您将看到的两个条件是：

+   进展中

+   可用

当底层 Pod 的最小副本数可用时（默认为 1）时，Available 将为 true。当 ReplicaSets 及其相关的 Pods 被创建并且可用时，将设置 Progressing。

Kubernetes 在其内部资源之间的关系上使用了一致的模式。正如我们在前一章中讨论的那样，部署将有关联的副本集，而副本集将有关联的 Pod。您可以将此可视化为一系列对象，其中较高级别负责监视和维护下一级别的状态：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/9306c080-96f0-4c5c-b045-89e063278d7d.png)

我们一直在关注 Pod 的状态及其生命周期，因为那里代表了代码并且实际在运行。在大多数情况下，您将创建一个部署，然后该部署将有自己的状态和条件。这将进而创建一个 ReplicaSet，而 ReplicaSet 将创建 Pod 或 Pods。

当正在创建一个 Pod 时，系统将首先尝试创建 API 资源本身，然后它将尝试在集群中找到一个运行它的位置。当资源已创建时，将向状态添加 Initialized 条件。当集群已确定在哪里运行 Pod 时，将添加 PodScheduled 条件。如果集群无法找到一个可以按照您描述的方式运行 Pod 的位置，则将向状态添加`Unschedulable`条件。

# 获取当前状态的快照

您可以使用`kubectl describe`或`kubectl get`命令查看 Kubernetes 对代码状态的当前快照。如果您只是想要交互式地查看状态，那么`kubectl describe`命令是最有价值的。请记住，Kubernetes 管理与运行代码相关的一系列对象，因此如果您想要查看完整的快照，您将需要查看每个对象的状态：部署、ReplicaSet 和 Pods。实际上，查看部署的状态，然后跳转到 Pods 通常会为您提供所需的任何细节。

您可以通过使用`kubectl get pod`查看 Pod 的原始数据，或者使用`describe`命令来查看 Kubernetes 对您的代码正在做什么。您需要查找`Status`和`Conditions`。例如，当我们之前创建了一个`nodejs`应用程序部署时，创建了一系列对象：

```
kubectl get deploy
NAME   DESIRED CURRENT UP-TO-DATE AVAILABLE AGE
nodejs 1       1       1          1         8h
```

```
kubectl get rs
NAME              DESIRED CURRENT READY AGE
nodejs-6b9b87d48b 1       1       1     8h
```

```
kubectl get pod
NAME                    READY STATUS  RESTARTS AGE
nodejs-6b9b87d48b-ddhjf 1/1   Running 0        8h
```

您可以使用`kubectl describe`命令查看部署的当前状态快照：

```
kubectl describe deploy nodejs
```

这将呈现类似于以下信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/9891c670-bf4d-4b81-99f7-816736917932.png)

您可以使用`kubectl describe`通过查看 ReplicaSet 获取其他详细信息：

```
kubectl describe rs nodejskubectl describe deploy nodejs 
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/28406acd-c028-4c76-9b45-af93951aec4e.png)

最后，再次使用它来查看部署和 ReplicaSet 创建的 Pod：

```
kubectl describe pod nodejs
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/fc6e5004-3a19-4852-b6b1-58dd10ec74cf.png)

从`kubectl describe`输出底部列出的事件将显示与 Pod 相关的发生的顺序。

如果您想在脚本中使用状态，或者以其他方式使用程序解析输出，那么可以使用`kubectl get`命令，指定输出的数据格式，如 YAML。例如，可以使用以下命令检索 YAML 中的相同 Pod 输出：

```
 kubectl get pod nodejs-6b9b87d48b-lcgvd -o yaml
```

输出底部的状态键下将保存状态快照信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/aac29ffc-2486-405a-b053-6fbdb449f2f2.png)

虽然在`kubectl describe`的输出中没有显示，但每个条件都有最后更新时间、上次更改时间、类型和状态。此外，每个容器都列有其自己的状态。

您可以在未来的 Kubernetes 版本中看到的 Pod 条件列表可能会增加，今天包括以下内容：

+   **PodScheduled**：当 Pod 已在节点上调度并且开始将其加载到节点上的过程时转换为 true。

+   已初始化：当 Pod 的所有容器已加载，并且定义的任何初始化容器已运行完成时，将标记为 true。

+   **Ready**：Pod 已根据规范加载和启动。在就绪探测和存活探测成功完成（如果定义了任一或两者），此值不会标记为 true。

+   **Unschedulable**：当 Kubernetes 集群无法将可用资源与 Pod 的需求匹配时，将列出并断言此条件。

有时状态（例如`Succeeded`或`Failed`）还会包括一个`Reason`，其中包括一些文本输出，旨在使理解发生了什么变得更容易。正如您可以从前面的输出中看到的那样，所有状态更改都包括时间戳。由于这是一个时间点的快照，时间戳可以提供线索，以了解发生的顺序以及多久之前发生的。

最后需要注意的是，与 Pod 相关的事件通常会提供有用的描述性注释，说明在启动 Pod 时发生了什么（或者未发生什么）。利用从描述、Pod 状态、条件和事件中提供的所有细节，可以提供最佳的状态更新，这些更新是 Pod 日志之外的外部状态更新。

Pod 的生命周期还包括您可以指定的钩子或反馈机制，以允许您的应用程序提供有关其运行情况的反馈。其中一个机制是`Ready`条件，您之前已经见过。Kubernetes 允许您的应用程序提供特定的反馈，以确定它是否准备好接受流量，以及它的健康状况。这些反馈机制称为**探针**，可以选择在 Pod 规范中定义。

# 探针

Kubernetes 中启用的两种探针是存活探针和就绪探针。它们是互补的，但在意图和用法上有所不同，并且可以为 Pod 中的每个容器定义。

# 存活探针

最基本的探针是存活探针。如果定义了存活探针，它将提供一个命令或 URL，Kubernetes 可以使用它来确定 Pod 是否仍在运行。如果调用成功，Kubernetes 将假定容器是健康的；如果未能响应，则可以根据定义的`restartPolicy`来处理 Pod。结果是二进制的：要么探针成功，Kubernetes 认为您的 Pod 正在运行，要么失败，Kubernetes 认为您的 Pod 不再可用。在后一种情况下，它将根据定义的 RestartPolicy 来选择要执行的操作。

`restartPolicy`的默认值为`Always`，这意味着如果 Pod 中的容器失败，Kubernetes 将始终尝试重新启动它。您可以定义的其他值包括`OnFailure`和`Never`。当容器重新启动时，Kubernetes 将跟踪重新启动发生的频率，并且如果它们在快速连续发生，则会减慢重新启动的频率，最多在重新启动尝试之间间隔五分钟。重新启动次数在`kubectl describe`的输出中作为`restartcount`进行跟踪和可见，并且在`kubectl get`的数据输出中作为`restartCount`键进行跟踪。

如果未明确定义存活探针，则假定探针将成功，并且容器将自动设置为活动状态。如果容器本身崩溃或退出，Kubernetes 将做出反应并根据`restartPolicy`重新启动它，但不会进行其他活动检查。这允许您处理代码已经冻结或死锁并且不再响应的情况，即使进程仍在运行。

可以定义存活探针来通过以下三种方法检查 Pod 的健康状况：

+   `ExecAction`：这在 Pod 内部调用命令以获取响应，并且该命令调用的退出代码的结果用于存活检查。除`0`之外的任何结果都表示失败。

+   `TCPSocketAction`：这尝试打开一个套接字，但除了尝试打开它之外，不会操作或与套接字交互。如果套接字打开，则探针成功，如果失败或在超时后失败，则探针失败。

+   `HTTPGetAction`：类似于套接字选项，这将作为指定的 URI 对您的 Pod 进行 HTTP 连接，并且 HTTP 请求的响应代码用于确定存活探针的成功/失败。

还有许多变量可以配置此探针的具体内容：

+   `activeDeadlineSeconds`（默认情况下未设置）：此值通常与作业一起使用，而不是长时间运行的 Pod，以对作业的最长运行时间设置最大限制。此数字将包括初始化容器所花费的任何时间，稍后在本章中将进一步讨论这一点。

+   `initialDelaySeconds`（默认情况下未设置）：这允许您指定在开始探测检查之前的秒数。默认情况下未设置，因此实际上默认为 0 秒。

+   `timeoutSeconds`（默认为 1）：如果命令或 URL 请求需要很长时间才能返回，这提供了一个超时。如果超时在命令返回之前到期，则假定它已失败。

+   `periodSeconds`（默认为 10）：这定义了 Kubernetes 运行探测的频率——无论是调用命令、检查套接字可用性还是进行 URL 请求。

+   `successThreshold`（默认为 1）：这是探测需要返回成功的次数，以便将容器的状态设置为“活动”。

+   `failureThreshold`（默认为 3）：这是触发将容器标记为不健康的探测的最小连续失败次数。

如果您定义一个 URL 来请求并将其他所有内容保持默认状态，正常模式将需要三个失败响应——超时或非 200 响应代码——然后才会考虑将容器标记为“死亡”并应用`restartPolicy`。默认情况下，每次检查间隔为 10 秒，因此在这些默认情况下，您的容器在系统应用`restartPolicy`之前可能会死亡长达 30 秒。

如果您正在使用基于 HTTP 的探测，可以在进行 HTTP 请求时定义许多其他变量。

+   `host`：默认为 Pod IP 地址。

+   `scheme`：HTTP 或 https。Kubernetes 1.8 默认为 HTTP

+   `path`：URI 请求的路径。

+   `HttpHeaders`：要包含在请求中的任何自定义标头。

+   `port`：进行 HTTP 请求的端口。

# 就绪探测

第二个可用的探测是就绪探测，通常与活跃探测并行使用。就绪探测只有在应用程序准备好并能够处理正常请求时才会做出积极响应。例如，如果您希望等待直到数据库完全可操作，或者预加载一些可能需要几秒钟的缓存，您可能不希望在这些操作完成之前对就绪探测返回积极响应。

与活跃探测一样，如果未定义，则系统会假定一旦您的代码运行，它也准备好接受请求。如果您的代码需要几秒钟才能完全运行，那么定义和利用就绪探测是非常值得的，因为这将与任何服务一起自动更新端点，以便在无法处理流量时不会将流量路由到实例。

配置就绪探针的相同选项可用，其中之一是 `ExecAction`、`TCPSocketAction` 或 `HTTPGetAction`。与存活探针一样，可以使用相同的变量来调整探针请求的频率、超时以及触发状态更改的成功和/或失败次数。如果您修改了存活探针中的值，那么您可能不希望将就绪探针设置为比存活探针更频繁。

作为提醒，当就绪探针失败时，容器不会自动重新启动。如果您需要该功能，您应该使用存活探针。就绪探针专门设置为允许 Pod 指示它尚不能处理流量，但它预计很快就能够。随着探针的更新，Pod 状态将被更新为设置 Ready 为正或负，并且相关的 Ready 条件也将被更新。随着这一过程的发生，使用此 Pod 的任何服务都将收到这些更新的通知，并将根据就绪值更改发送流量（或不发送）。

您可以将就绪探针视为断路器模式的实现，以及负载分担的一种手段。在运行多个 Pod 的情况下，如果一个实例过载或出现一些临时条件，它可以对就绪探针做出负面响应，Kubernetes 中的服务机制将把任何进一步的请求转发到其他 Pod。

# 向我们的 Python 示例添加探针

与以前的示例一样，代码在 GitHub 中可用在 [`github.com/kubernetes-for-developers/kfd-flask`](https://github.com/kubernetes-for-developers/kfd-flask) 项目中。[我不会展示所有更改，但您可以使用此命令从分支 `0.3.0` 检出代码：`git checkout 0.3.0`。从该代码构建的 Docker 镜像同样可以在 `quay.io` 仓库的 `0.3.0` 标签下找到。](https://github.com/kubernetes-for-developers/kfd-flask)

在此更新中，该项目包括了 Redis 的辅助部署，以匹配上一章中的一些概念。部署的规范也已更新，特别添加了存活探针和就绪探针。更新后的部署规范现在如下：

```
apiVersion: apps/v1beta1
kind: Deployment
metadata:
 name: flask
 labels:
 run: flask
spec:
 template:
 metadata:
 labels:
 app: flask
 spec:
 containers:
 - name: flask
 image: quay.io/kubernetes-for-developers/flask:0.3.0
 imagePullPolicy: Always
 ports:
 - containerPort: 5000
 envFrom:
 - configMapRef:
 name: flask-config
 volumeMounts:
 - name: config
 mountPath: /etc/flask-config
 readOnly: true
 livenessProbe:
 httpGet:
 path: /alive
 port: 5000
 initialDelaySeconds: 1
 periodSeconds: 5
 readinessProbe:
 httpGet:
 path: /ready
 port: 5000
 initialDelaySeconds: 5
 periodSeconds: 5
 volumes:
 - name: config
 configMap:
 name: flask-config
```

探针以粗体显示。两个探针都使用与应用程序的其余部分相同的端口（`5000`），以及它们自己各自的端点。就绪探针设置为延迟一秒开始检查，就绪探针设置为延迟五秒开始检查，两者都设置为稍微更紧密的频率，为五秒。

Python 代码也已经更新，主要是为了实现响应于就绪和活动探针的`/alive`和`/ready`方法。

就绪探针是最简单的，只是回复一个静态响应，仅保留底层 flask 代码对 HTTP 请求的响应验证：

```
@app.route('/alive')
def alive():
 return "Yes"
```

就绪探针扩展了这种模式，但在回复肯定之前验证了底层服务（在本例中为 Redis）是否可用和响应。这段代码实际上并不依赖于 Redis，但在您自己的代码中，您可能依赖于远程服务可用，并且有一些方法可以指示该服务是否可用和响应。如前所述，这实际上是断路器模式的一种实现，并且与服务构造一起，允许 Kubernetes 帮助将负载定向到可以响应的实例。

在这种情况下，我们利用了 Python 库中公开的`redis ping()`功能：

```
@app.route('/ready')
def ready():
 if redis_store.ping():
 return "Yes"
 else:
 flask.abort(500)
```

代码中的其他更新初始化了代码中的`redis_store`变量，并将 DNS 条目添加到`configMap`中，以便应用程序代码可以使用它。

# 运行 Python 探针示例

如果您查看`0.3.0`分支，您可以调查此代码并在您自己的 Minikube 实例或另一个 Kubernetes 集群中本地运行它。要查看代码：

```
git clone https://github.com/kubernetes-for-developers/kfd-flask

cd kfd-flask

git checkout 0.3.0

kubectl apply -f deploy/
```

最后一个命令将创建`redis-master`的服务和部署，以及 Python/flask 代码的服务、configmap 和部署。然后，您可以使用`kubectl describe`命令查看定义的探针及其值：

```
kubectl describe deployment flask
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/4c11e8f7-0b0f-4fb9-b60c-0aa2f9aa67a0.png)

您还可以查看正在运行的单个 flask Pod 的日志，并查看正在处理的请求：

```
kubectl log deployment/flask
```

```
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 177-760-948
172.17.0.1 - - [21/Dec/2017 14:57:50] "GET /alive HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:57:53] "GET /ready HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:57:55] "GET /alive HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:57:58] "GET /ready HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:00] "GET /alive HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:03] "GET /ready HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:05] "GET /alive HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:08] "GET /ready HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:10] "GET /alive HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:13] "GET /ready HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:15] "GET /alive HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:18] "GET /ready HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:20] "GET /alive HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:23] "GET /ready HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:25] "GET /alive HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:28] "GET /ready HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:30] "GET /alive HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:33] "GET /ready HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:35] "GET /alive HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:38] "GET /ready HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:40] "GET /alive HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:43] "GET /ready HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:45] "GET /alive HTTP/1.1" 200 -
172.17.0.1 - - [21/Dec/2017 14:58:48] "GET /ready HTTP/1.1" 200 -
...
```

# 向我们的 Node.js 示例添加探针

向基于 Node.js/express 的应用程序添加示例探测与 Python 应用程序完全相同的模式。与 Python 示例一样，此代码和规范可在 GitHub 的[`github.com/kubernetes-for-developers/kfd-nodejs`](https://github.com/kubernetes-for-developers/kfd-nodejs)项目下的分支`0.3.0`中找到。

探测器向 Node.js 部署添加了几乎相同的规范：

```
livenessProbe:
  httpGet:
  path: /probes/alive
  port: 3000
  initialDelaySeconds: 1
  periodSeconds: 5 readinessProbe:   httpGet:
  path: /probes/ready
  port: 3000
  initialDelaySeconds: 5
  periodSeconds: 5
```

在这种情况下，探测器请求与应用程序提供的相同的 HTTP 响应和相同的端口。URI 路径更长，利用了应用程序的结构，该结构使用单个代码段用于特定 URI 下的路由，因此我们能够将就绪性和存活性探测器捆绑到一个新的`probes.js`路由中。

主应用程序已更新以创建一个探测器路由并在应用程序启动时绑定它，然后路由本身的代码提供响应。

`probes.js`的代码如下：

```
var express = require('express');
var router = express.Router();
var util = require('util');
var db = require('../db');

/* GET liveness probe response. */
router.get('/alive', function(req, res, next) {
 res.send('yes');
});

/* GET readiness probe response. */
router.get('/ready', async function(req, res, next) {
 try {
 let pingval = await db.ping()
 if (pingval) {
 res.send('yes');
 } else {
 res.status(500).json({ error: "redis.ping was false" })
 }
 } catch (error) {
 res.status(500).json({ error: error.toString() })
 }
});

module.exports = router;
```

与前面的 Python 示例一样，存活性探测返回静态响应，仅用于验证`express`是否仍然响应 HTTP 请求。就绪性探测更为复杂，它在异步等待/捕获中包装了`db.ping()`并检查其值。如果为负，或发生错误，则返回`500`响应。如果为正，则返回静态的积极结果。

使用`kubectl describe deployment nodejs`将显示配置，其中包含操作探测器，非常类似于 Python 示例，而`kubectl log nodejs-65498dfb6f-5v7nc`将显示来自探测器的请求得到了响应：

```
GET /probes/alive 200 1.379 ms - 3
Thu, 21 Dec 2017 17:43:51 GMT express:router dispatching GET /probes/ready
Thu, 21 Dec 2017 17:43:51 GMT express:router query : /probes/ready
Thu, 21 Dec 2017 17:43:51 GMT express:router expressInit : /probes/ready
Thu, 21 Dec 2017 17:43:51 GMT express:router logger : /probes/ready
Thu, 21 Dec 2017 17:43:51 GMT express:router jsonParser : /probes/ready
Thu, 21 Dec 2017 17:43:51 GMT express:router urlencodedParser : /probes/ready
Thu, 21 Dec 2017 17:43:51 GMT express:router cookieParser : /probes/ready
Thu, 21 Dec 2017 17:43:51 GMT express:router serveStatic : /probes/ready
Thu, 21 Dec 2017 17:43:51 GMT express:router router : /probes/ready
Thu, 21 Dec 2017 17:43:51 GMT express:router dispatching GET /probes/ready
Thu, 21 Dec 2017 17:43:51 GMT express:router trim prefix (/probes) from url /probes/ready
Thu, 21 Dec 2017 17:43:51 GMT express:router router /probes : /probes/ready
Thu, 21 Dec 2017 17:43:51 GMT express:router dispatching GET /ready
GET /probes/ready 200 1.239 ms - 3
Thu, 21 Dec 2017 17:43:54 GMT express:router dispatching GET /probes/alive
Thu, 21 Dec 2017 17:43:54 GMT express:router query : /probes/alive
Thu, 21 Dec 2017 17:43:54 GMT express:router expressInit : /probes/alive
Thu, 21 Dec 2017 17:43:54 GMT express:router logger : /probes/alive
Thu, 21 Dec 2017 17:43:54 GMT express:router jsonParser : /probes/alive
Thu, 21 Dec 2017 17:43:54 GMT express:router urlencodedParser : /probes/alive
Thu, 21 Dec 2017 17:43:54 GMT express:router cookieParser : /probes/alive
Thu, 21 Dec 2017 17:43:54 GMT express:router serveStatic : /probes/alive
Thu, 21 Dec 2017 17:43:54 GMT express:router router : /probes/alive
Thu, 21 Dec 2017 17:43:54 GMT express:router dispatching GET /probes/alive
Thu, 21 Dec 2017 17:43:54 GMT express:router trim prefix (/probes) from url /probes/alive
Thu, 21 Dec 2017 17:43:54 GMT express:router router /probes : /probes/alive
Thu, 21 Dec 2017 17:43:54 GMT express:router dispatching GET /alive
GET /probes/alive 200 1.361 ms - 3
```

我们可以通过终止 Redis 服务来测试就绪性探测的操作。如果我们调用以下命令：

```
kubectl delete deployment redis-master
```

`kubectl get pods`的结果很快就会显示 Pod 是活动的，但不是`ready`的：

```
kubectl get pods
NAME                         READY STATUS      RESTARTS AGE
nodejs-65498dfb6f-5v7nc      0/1   Running     0        8h
redis-master-b6b8774f9-sjl4w 0/1   Terminating 0        10h
```

当`redis-master`部署关闭时，您可以从 Node.js 部署中获取一些有趣的细节。使用`kubectl describe`来显示部署：

```
kubectl describe deploy nodejs
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/da7a3247-b66b-4996-95b3-e1e6d441ec52.png)

并使用`kubectl describe`来查看相关的 Pods：

```
kubectl describe pod nodejs
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/60099d6b-f9f7-45fd-a898-93493110249a.png)

请注意，`Condition Ready`现在是`false`，而 Node.js 容器的状态为`Running`，但`Ready`为`False`。

如果重新创建或恢复 Redis 部署，则服务将像您期望的那样全部恢复在线。

# 容器生命周期钩子

Kubernetes 还提供了一些在每个容器的生命周期中可以在容器的设置和拆卸时间使用的钩子。这些称为容器生命周期钩子，为每个容器定义，而不是为整个 Pod 定义。当您想要为 Pod 中的多个容器配置一些特定于容器的附加功能时，这些钩子非常有用。

每个容器可以定义两个钩子：post-start 和 pre-stop。post-start 和 pre-stop 钩子预期至少被调用一次，但 Kubernetes 不保证这些钩子只会被调用一次。这意味着虽然可能很少见，post-start 或 pre-stop 钩子可能会被调用多次。

这些钩子都不接受参数，并且以与容器运行命令相同的方式定义。当使用时，它们预期是自包含的、相对短暂的命令，总是返回。当这些钩子被调用时，Kubernetes 暂停对容器的管理，直到钩子完成并返回。因此，对于这些钩子调用的可执行文件不要挂起或无限运行至关重要，因为 Kubernetes 没有一种方式来监视这种情况并响应无法完成或返回值的失败。

在 post-start 的情况下，容器状态直到 post-start 钩子完成之前不会转移到运行状态。post-start 钩子也不能保证在容器的主要命令之前或之后被调用。在 pre-stop 的情况下，容器直到 pre-stop 钩子完成并返回后才会被终止。

这两个钩子可以使用 Exec 和 HTTP 两种处理程序之一来调用：Exec 在容器内部以及与容器相同的进程空间中运行特定命令，就像使用`kubectl exec`一样。HTTP 处理程序设置用于针对容器的 HTTP 请求。在任何情况下，如果钩子返回失败代码，容器将被终止。

这些钩子的日志不会在 Pod 事件或日志中公开。如果处理程序失败，它会广播一个事件，可以使用`kubectl describe`命令查看。这两个事件分别是`FailedPostStartHook`和`FailedPreStopHook`。

预停钩子在你想要外部命令被调用来干净地关闭运行中的进程时非常有用，比如调用 `nginx -s quit`。如果你正在使用别人的代码，尤其是它有一个比正确响应 SIGTERM 信号更复杂的关闭过程，这将特别有用。我们将在本章稍后讨论如何优雅地关闭 Kubernetes。

后启动钩子在你想要在容器内创建一个信号文件，或者在容器启动时调用 HTTP 请求时经常有用。更常见的情况是在主代码启动之前进行初始化或前置条件验证，而有另一个选项可用于该功能：初始化容器。

# 初始化容器

初始化容器是可以在你的 Pod 上定义的容器，并且将在定义它们之前的特定顺序中被调用，然后才会启动你的主容器（或容器）。初始化容器在 Kubernetes 1.6 版本中成为 Pod 规范的正常部分。

这些容器可以使用相同的容器镜像并简单地具有替代命令，但它们也可以使用完全不同的镜像，利用 Kubernetes Pod 共享网络和文件系统挂载的保证来进行初始化和设置工作，以便在主容器运行之前进行。这些容器还使用命名空间，因此它们可以获得主容器没有的特定访问权限；因此，它们可以访问主容器无法访问的 Kubernetes Secrets。

初始化容器预期具有可以运行到完成并以成功响应退出的代码。正如之前提到的，这些容器也按顺序调用，并不会并行运行；每个容器都必须在下一个容器启动之前完成。当所有容器都完成时，Kubernetes 初始化 Pod 并运行定义的容器（或容器）。如果初始化容器失败，那么 Pod 被认为已经失败，并且整个套件被终止（或更具体地说，根据 `restartPolicy` 处理）。

初始化容器允许您在运行主进程之前进行各种设置。您可能要做的一些例子包括编写主 Pod 容器需要的配置文件，验证服务在启动主容器之前是否可用和活动，检索和初始化内容，比如从 Git 存储库或文件服务中拉取数据供主容器使用，或者在启动主容器之前强制延迟。

在初始化容器运行时，Pod 状态将显示`Init:`，后面跟着一些初始化容器特定的状态。如果一切顺利，符合预期，它将报告列出的初始化容器数量以及已经完成运行的数量。如果初始化容器失败，那么`Init:`后面将跟着`Error`或`CrashLoopBackOff`。

初始化容器在 Pod 规范中被指定在与主容器相同级别的位置，并且作为一个列表，每个初始化容器都有自己的名称、镜像和要调用的命令。例如，我们可以在 Python flask 规范中添加一个`init`容器，它只会在 Redis 可用时才返回。一个例子可能是以下内容：

```
spec:
 template:
 metadata:
 labels:
 app: flask
 spec:
 containers:
 - name: flask
 image: quay.io/kubernetes-for-developers/flask:0.2.0
 ports:
 - containerPort: 5000
 envFrom:
 - configMapRef:
 name: flask-config
 volumeMounts:
 - name: config
 mountPath: /etc/flask-config
 readOnly: true
 volumes:
 - name: config
 configMap:
 name: flask-config
 initContainers:
      - name: init-myservice
 image: busybox
 command: ['sh', '-c', 'until nslookup redis-master; do echo waiting for redis; sleep 2; done;']
```

在这种情况下，初始化容器的代码只是一个在 shell 中编写的循环，检查是否有对`redis-master`的 DNS 条目的响应，并且会一直运行直到成功。如果在`redis-master`服务建立并具有相关的 DNS 条目之前查看 Pod，您将看到该 Pod 的状态列出为`Init:0/1`。

例如，`kubectl get pods`:

```
NAME                  READY STATUS   RESTARTS AGE
flask-f48f89687-8p8nj 0/1   Init:0/1 0        8h
```

```
kubectl describe deploy/flask
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/7e5adb95-c678-498b-924e-112aba2a69f3.png)

您可能会注意到，这个输出与之前的例子不匹配；在前面的输出中，命令是在寻找对`redis`的 DNS 响应，而我们将服务命名为`redis-service`。

在这种情况下，初始化容器将永远无法完成，Pod 将无限期地保持在`pending`状态。在这种情况下，您需要手动删除部署，或者如果您进行了修改以使其工作，您需要手动删除那些卡在初始化状态的 Pod，否则它们将无法被清理。

一旦初始化容器成功完成，您可以通过 Pod 的`kubectl describe`输出或者再次通过`kubectl get`命令暴露的数据来查看结果。

以下是你将从`kubectl describe`中看到的输出的扩展示例。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/3fd0907c-1d4c-4f56-a14c-20fee8b8ef12.png)

`describe`的输出超出了单个终端页面；你应该继续向下滚动以查看以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/248aa190-9878-410a-a140-baba10022671.png)

# 快速交互式测试

如果你试图创建一个快速的一行初始化容器，尤其是当你使用非常简化的容器比如`busybox`时，交互式地尝试命令通常是很有用的。你想要的命令可能不可用，所以最好快速尝试一下，以验证它是否能按你的期望工作。

要交互式地运行一个`busybox`容器，并在完成后删除它，你可以使用以下命令：

```
kubectl run tempinteractive -it --rm --restart=Never --image=busybox -- /bin/sh
```

然后在容器内尝试这个命令：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/ac15c96e-7170-4b62-bd3d-fe9562463fef.png)

# 处理优雅的关闭

在生命周期钩子中，我们提到了可以定义和启用的 pre-stop 钩子，但如果你正在编写自己的代码，那么尊重 Kubernetes 用于告诉容器关闭的 SIGTERM 信号可能同样容易。

如果你不熟悉 SIGTERM，它是 Linux 内核支持的功能之一——用于向运行中的进程发送中断的一种方式。进程可以监听这些信号，你可以选择它们在接收到时如何响应。有两个信号是你不能“忽略”的，无论你实现了什么，操作系统都会强制执行：SIGKILL 和 SIGSTOP。Kubernetes 在想要关闭容器时使用的信号是 SIGTERM。

你将收到这个信号的事件类型不仅仅是错误或用户触发的删除，还包括当你使用部署所使用的滚动更新机制进行代码更新时。如果你利用了任何自动扩展功能，它也可能发生，这些功能可以动态增加（和减少）`replicaSet`中的副本数量。

当你响应这个信号时，通常会想要保存任何需要的状态，关闭任何连接，然后终止你的应用程序。

如果您正在创建一个其他人也会通过 Kubernetes 使用的服务，那么您可能想要做的第一件事之一是更改一个内部变量，以触发任何就绪探针以响应`false`，然后休眠几秒钟，然后进行任何最终操作和终止。这将允许 Kubernetes 中的服务构造重定向任何进一步的连接，并且所有活动连接都可以完成、排空并礼貌地关闭。

一旦 Kubernetes 发送信号，它就会启动一个计时器。该计时器的默认值为 30 秒，如果您需要或希望更长的值，可以在 Pod 规范中使用`terminateGracePeriodSeconds`的值进行定义。如果容器在计时器到期时尚未退出，Kubernetes 将尝试使用 SIGKILL 信号强制退出。

例如，如果您调用了`kubectl delete deploy nodejs`，然后看到 Pods 保持一段时间处于`Terminating`状态，那就是发生了这种情况。

# Python 中的 SIGTERM

例如，如果您想在 Python 中处理 SIGTERM，那么您可以导入 signal 模块并引用一个处理程序来执行任何您想要的操作。例如，一个简单的立即关闭并退出的代码可能是：

```
import signal
import sys

def sigterm_handler(_signo, _stack_frame):
    sys.exit(0)

signal.signal(signal.SIGTERM, sigterm_handler)
```

信号处理程序的逻辑可以像您的代码要求的那样复杂或简单。

# Node.js 中的 SIGTERM

例如，如果您想在 Node.js 中处理 SIGTERM，那么您可以使用在每个 Node.js 进程中隐式创建的 process 模块来处理信号并退出应用程序。与之前的 Python 示例相匹配，一个简单的关闭立即并退出的代码可能如下所示：

```
/**
 * SIGTERM handler to terminate (semi) gracefully
 */
process.on(process.SIGTERM, function() {
    console.log('Received SIGTERM signal, now shutting down...');
    process.exit(0);
})
```

# 总结

在这一章中，我们首先深入了解了 Pod 的生命周期和状态细节，展示了多种揭示相关细节的方式，并描述了 Kubernetes 在运行软件时的内部操作。然后，我们看了一下您的程序可以通过活跃性和就绪性探针提供的反馈循环，并回顾了在 Python 和 Node.js 中启用这些探针的示例。在探针和代码如何与 Kubernetes 清洁地交互之后，我们看了一下启动和初始化以及优雅关闭的常见情况。

在下一章中，我们将看一下如何使用 Kubernetes 和开源提供应用程序的基本可观察性，特别是监控和日志记录。


# 第六章：Kubernetes 中的后台处理

Kubernetes 包括对一次性（也称为批处理）计算工作的支持，以及支持异步后台工作的常见用例。在本章中，我们将介绍 Kubernetes 的作业概念及其邻居 CronJob。我们还将介绍 Kubernetes 如何处理和支持持久性，以及 Kubernetes 中可用的一些选项。然后，我们将介绍 Kubernetes 如何支持异步后台任务以及 Kubernetes 可以如何表示、操作和跟踪这些任务的方式。我们还将介绍如何设置从消息队列操作的工作代码。

本章涵盖的主题包括：

+   工作

+   CronJob

+   使用 Python 和 Celery 的工作队列示例

+   Kubernetes 中的持久性

+   有状态集

+   **自定义资源定义**（**CRD**）

# 工作

到目前为止，我们所涵盖的大部分内容都集中在持续运行的长期进程上。Kubernetes 还支持较短的、离散的软件运行。Kubernetes 中的作业专注于在一定时间内结束并报告成功或失败的离散运行，并构建在与长期运行软件相同的构造之上，因此它们在其核心使用 pod 规范，并添加了跟踪成功完成数量的概念。

最简单的用例是运行一个单独的 pod，让 Kubernetes 处理由于节点故障或重启而导致的任何故障。您可以在作业中使用的两个可选设置是并行性和完成。如果不指定并行性，默认值为`1`，一次只会安排一个作业。您可以将这两个值都指定为整数，以并行运行多个作业以实现多个完成，并且如果作业是从某种工作队列中工作，则可以不设置完成。

重要的是要知道，完成和并行设置并不是保证 - 因此 Pod 内的代码需要能够容忍多个实例运行。同样，作业需要能够容忍容器在容器失败时重新启动（例如，在使用`restartPolicy OnFailure`时），以及处理任何初始化或设置，如果在重新启动时发现自己在新的 Pod 上运行（这可能发生在节点故障的情况下）。如果作业使用临时文件、锁定或从本地文件进行工作，它应该在启动时验证状态，并且不应该假定文件始终存在，以防在处理过程中发生故障。

当作业运行完成时，系统不会创建更多的 Pod，但也不会删除 Pod。这样可以让您查询成功或失败的 Pod 状态，并查看 Pod 内容器的任何日志。已经完成的 Pod 不会出现在`kubectl get pods`的简单运行中，但如果您使用`-a`选项，它们将会出现。您需要删除已完成的作业，当您使用`kubectl delete`删除作业时，相关的 Pod 也将被删除和清理。

例如，让我们运行一个示例作业来看看它是如何工作的。一个简单的作业，只需打印`hello world`，可以使用以下 YAML 指定：

```
apiVersion: batch/v1 kind: Job metadata:
 name: helloworld spec:
 template: metadata: name: helloworld spec: containers: - name: simple image: busybox command: ["/bin/echo", "'hello world'"] restartPolicy: Never
```

然后，您可以使用`kubectl create`或`kubectl apply`来运行此作业：

```
kubectl apply -f simplejob.yaml
```

预期的`kubectl get jobs`命令将显示存在的作业及其当前状态。由于这个作业非常简单，它可能会在您运行命令查看其当前状态之前完成：

```
kubectl get jobs
```

```
NAME         DESIRED   SUCCESSFUL   AGE helloworld   1         1            3d
```

与 Pod 一样，您可以使用`kubectl describe`命令获取更详细的状态和输出：

```
kubectl describe job helloworld
```

```
Name:           helloworld Namespace:      default Selector:       controller-uid=cdafeb57-e7c4-11e7-89d4-b29f363a60d7 Labels:         controller-uid=cdafeb57-e7c4-11e7-89d4-b29f363a60d7
 job-name=helloworld Annotations:    kubectl.kubernetes.io/last-applied-configuration={"apiVersion":"batch/v1","kind":"Job","metadata":{"annotations":{},"name":"helloworld","namespace":"default"},"spec":{"backoffLimit":4,"template":{"met... Parallelism:    1 Completions:    1 Start Time:     Sat, 23 Dec 2017 01:36:50 -0800 Pods Statuses:  0 Running / 1 Succeeded / 0 Failed Pod Template:
 Labels:  controller-uid=cdafeb57-e7c4-11e7-89d4-b29f363a60d7 job-name=helloworld Containers: simple: Image:  busybox Port:   <none> Command: /bin/echo 'hello world' Environment:  <none> Mounts:       <none> Volumes:        <none> Events:
 Type    Reason            Age   From            Message ----    ------            ----  ----            ------- Normal  SuccessfulCreate  3d    job-controller  Created pod: helloworld-2b2xt
```

如果您运行`kubectl get pods`命令，您将看不到 Pod`helloworld-2b2xt`在 Pod 列表中，但运行`kubectl get pods -a`将显示 Pod，包括仍然存在的已完成或失败的 Pod：

```
NAME                           READY     STATUS      RESTARTS   AGE
```

```
helloworld-2b2xt               0/1       Completed   0          3d
```

如果您只是想亲自查看 Pod 的状态，可以使用`kubectl describe`获取详细信息，以人类可读的形式显示信息：

```
kubectl describe pod helloworld-2b2xt
```

这是一个示例：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/a7c7f878-dbeb-4b92-8ccb-9e4d10436dc8.png)

如果您像在此示例中一样使用 shell 脚本创建一个简单的作业，很容易出错。在这些情况下，默认情况是 Kubernetes 会重试运行 pod，使得 pod 在系统中处于失败状态供您查看。在这种情况下，设置一个退避限制可以限制系统重试作业的次数。如果您不指定此值，它将使用默认值为六次。

一个命令中的简单错误可能看起来像下面这样：

```
kubectl describe job helloworld
```

```
Name:           helloworld Namespace:      default Selector:       controller-uid=6693f83a-e7c7-11e7-89d4-b29f363a60d7 Labels:         controller-uid=6693f83a-e7c7-11e7-89d4-b29f363a60d7
 job-name=helloworld Annotations:    kubectl.kubernetes.io/last-applied-configuration={"apiVersion":"batch/v1","kind":"Job","metadata":{"annotations":{},"name":"helloworld","namespace":"default"},"spec":{"template":{"metadata":{"name":"h... Parallelism:    1 Completions:    1 Start Time:     Sat, 23 Dec 2017 01:55:26 -0800 Pods Statuses:  0 Running / 0 Succeeded / 6 Failed Pod Template:
 Labels:  controller-uid=6693f83a-e7c7-11e7-89d4-b29f363a60d7 job-name=helloworld Containers: simple: Image:  busybox Port:   <none> Command: /bin/sh echo 'hello world' Environment:  <none> Mounts:       <none> Volumes:        <none> Events:
 Type     Reason                Age   From           Message ----     ------                ----  ----            ------- Normal   SuccessfulCreate      3d    job-controller  Created pod: helloworld-sz6zj Normal   SuccessfulCreate      3d    job-controller  Created pod: helloworld-vtzh7 Normal   SuccessfulCreate      3d    job-controller  Created pod: helloworld-2gh74 Normal   SuccessfulCreate      3d    job-controller  Created pod: helloworld-dfggg Normal   SuccessfulCreate      3d    job-controller  Created pod: helloworld-z2llj Normal   SuccessfulCreate      3d    job-controller  Created pod: helloworld-69d4t Warning  BackoffLimitExceeded  3d    job-controller  Job has reach the specified backoff limit
```

并查看`pods`：

```
kubectl get pods -a
```

```
NAME               READY     STATUS    RESTARTS   AGE helloworld-2gh74   0/1       Error     0          3d helloworld-69d4t   0/1       Error     0          3d helloworld-dfggg   0/1       Error     0          3d helloworld-sz6zj   0/1       Error     0          3d helloworld-vtzh7   0/1       Error     0          3d helloworld-z2llj   0/1       Error     0          3d
```

每个 pod 的日志都将可用，因此您可以诊断出了什么问题。

如果您犯了一个错误，那么您可能会想要快速修改作业规范，并使用`kubectl apply`来修复错误。系统认为作业是不可变的，因此如果您尝试快速修复并应用它，将会收到错误。在处理作业时，最好删除作业并创建一个新的。

作业与 Kubernetes 中其他对象的生命周期无关，因此，如果您考虑使用作业来初始化持久性存储中的数据，请记住您需要协调运行该作业。在您希望在服务启动之前每次检查一些逻辑以预加载数据的情况下，最好使用初始化容器，就像我们在上一章中探讨的那样。

一些常见的适合作业的情况包括将备份加载到数据库中、创建备份、进行一些更深入的系统内省或诊断，或者运行超出带宽清理逻辑。在所有这些情况下，您希望知道您编写的函数已经完成，并且成功运行。在失败的情况下，您可能希望重试，或者仅仅通过日志了解发生了什么。

# CronJob

CronJobs 是建立在作业基础上的扩展，允许您指定它们运行的重复计划。该名称源自一个用于调度重复脚本的常见 Linux 实用程序`cron`。CronJobs 在 Kubernetes 版本 1.7 中是 alpha 版本，在版本 1.8 中转为 beta 版本，并且在版本 1.9 中仍然是 beta 版本。请记住，Kubernetes 规范可能会发生变化，但往往相当稳定，并且具有预期的 beta 实用性，因此 CronJobs 的 v1 版本可能会有所不同，但您可以期望它与本文提供的内容非常接近。

规范与作业密切相关，主要区别在于种类是 CronJob，并且有一个必需的字段 schedule，它接受一个表示运行此作业的时间的字符串。

此字符串的格式是五个数字，可以使用通配符。这些字段表示：

+   分钟（0-59）

+   小时（0-23）

+   月份的日期（1-31）

+   月份（1-12）

+   星期几（0-6）

`*`或？字符可以在这些字段中的任何一个中使用，表示任何值都可以接受。字段还可以包括`*/`和一个数字，这表示在一些间隔内定期发生的实例，由相关数字指定。这种格式的一些例子是：

+   `12 * * * *`：每小时在整点后 12 分钟运行

+   `*/5 * * * *`：每 5 分钟运行

+   每周六午夜运行

还有一些特殊的字符串可以用于一些更容易阅读的常见事件：

+   `@yearly`

+   `@monthly`

+   `@weekly`

+   `@daily`

+   ``@hourly``

CronJob 有五个额外的字段，可以指定，但不是必需的。与作业不同，CronJobs 是可变的（就像 pod、部署等一样），因此这些值可以在创建 CronJob 后更改或更新。

第一个是`startingDeadlineSeconds`，如果指定，将限制作业在 Kubernetes 未满足其指定的启动作业时间限制时可以启动的时间。如果时间超过`startingDeadlineSeconds`，该迭代将标记为失败。

第二个是`concurrencyPolicy`，它控制 Kubernetes 是否允许多个相同作业的实例同时运行。默认值为`Allow`，这将允许多个作业同时运行，备用值为`Forbid`和`Replace`。`Forbid`将在第一个作业仍在运行时将以下作业标记为失败，而`Replace`将取消第一个作业并尝试再次运行相同的代码。

第三个字段是`suspended`，默认值为`False`，可以用于暂停计划中作业的任何进一步调用。如果作业已经在运行，并且将`suspend`添加到 CronJob 规范中，那么当前作业将运行到完成，但不会安排任何进一步的作业。

第四和第五个字段是`successfulJobsHistoryLimit`和`failedJobsHistoryLimit`，默认值分别为`3`和`1`。默认情况下，Kubernetes 将清理超出这些值的旧作业，但保留最近的成功和失败，包括日志，以便根据需要进行检查。

创建 CronJob 时，您还需要选择（并在规范中定义）`restartPolicy`。CronJob 不允许`Always`的默认值，因此您需要在`OnFailure`和`Never`之间进行选择。

每分钟打印`hello world`的简单 CronJob 可能如下所示：

```
apiVersion: batch/v1beta1 kind: CronJob metadata:
 name: helloworld spec:
 schedule: "*/1 * * * *" jobTemplate: spec: template: spec: containers: - name: simple image: busybox command: ["/bin/sh", "-c", "echo", "'hello world'"] restartPolicy: OnFailure
```

使用`kubectl apply -f cronjob.yaml`创建此作业后，您可以使用`kubectl get cronjob`查看摘要输出：

```
NAME         SCHEDULE      SUSPEND   ACTIVE    LAST SCHEDULE   AGE helloworld   */1 * * * *   False     1         3d              3d
```

或者，使用`kubectl describe cronjob helloworld`查看更详细的输出：

```
Name:                       helloworld Namespace:                  default Labels:                     <none> Annotations:                kubectl.kubernetes.io/last-applied-configuration={"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"annotations":{},"name":"helloworld","namespace":"default"},"spec":{"jobTemplate":{"spec":{"... Schedule:                   */1 * * * * Concurrency Policy:         Allow Suspend:                    False Starting Deadline Seconds:  <unset> Selector:                   <unset> Parallelism:                <unset> Completions:                <unset> Pod Template:
 Labels:  <none> Containers: simple: Image:  busybox Port:   <none> Command: /bin/sh -c echo 'hello world' Environment:     <none> Mounts:          <none> Volumes:           <none> Last Schedule Time:  Sat, 23 Dec 2017 02:46:00 -0800 Active Jobs:         <none> Events:
 Type    Reason            Age   From                Message ----    ------            ----  ----                ------- Normal  SuccessfulCreate  3d    cronjob-controller  Created job helloworld-1514025900 Normal  SawCompletedJob   3d    cronjob-controller  Saw completed job: helloworld-1514025900 Normal  SuccessfulCreate  3d    cronjob-controller  Created job helloworld-1514025960 Normal  SawCompletedJob   3d    cronjob-controller  Saw completed job: helloworld-1514025960
```

从此输出中，您可能会猜到 CronJob 实际上是根据您定义的时间表和规范中的模板创建作业。每个作业都基于 CronJob 的名称获得自己的名称，并且可以独立查看：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/1b610135-65a4-4cd3-8991-e02851bc1d2a.png)

您可以使用`kubectl get jobs`命令查看从前面的 CronJob 定义的时间表创建的作业：

```
kubectl get jobs
```

```
NAME                    DESIRED   SUCCESSFUL   AGE helloworld-1514025900   1         1            3d helloworld-1514025960   1         1            3d **helloworld-1514026020   1         1            3d** 
```

您还可以使用`kubectl get pods`的`-a`选项查看从这些作业中创建并运行到完成的 Pod：

```
kubectl get pods -a
```

```
NAME                          READY     STATUS      RESTARTS   AGE helloworld-1514025900-5pj4r   0/1       Completed   0          3d helloworld-1514025960-ckshh   0/1       Completed   0          3d helloworld-1514026020-gjrfh   0/1       Completed   0          3d
```

# 使用 Python 和 Celery 的工作队列示例

CronJob 很适合在特定时间表上运行重复任务，但另一个常见的需求是更多或更少地不断处理一系列工作项。作业很适合运行单个任务直到完成，但如果需要处理的事务量足够大，保持不断的处理过程可能更有效。

适应这种工作的常见模式使用消息队列，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/587495c0-7d7c-4060-9796-3c2d5e40607f.png)

通过消息队列，您可以拥有一个 API 前端，用于异步创建要运行的工作，将其移动到队列中，然后有多个工作进程从队列中拉取相关工作。亚马逊有一个支持这种处理模式的基于 Web 的服务，称为**简单队列服务**（**SQS**）。这种模式的巨大好处是将工作人员与请求解耦，因此您可以根据需要独立扩展每个部分。

您可以在 Kubernetes 中做完全相同的事情，将队列作为服务运行，并将连接到该队列的工作程序作为部署。Python 有一个流行的框架 Celery，它可以从消息中进行后台处理，支持多种队列机制。我们将看看如何设置一个示例队列和工作进程，以及如何在 Kubernetes 中利用 Celery 这样的框架。

# Celery worker example

Celery 自 2009 年以来一直在开发和使用，早于 Kubernetes 存在。它是为了部署在多台机器上而编写的。这在我们的示例中可以很好地转化为容器。您可以在[`docs.celeryproject.org/en/latest/`](http://docs.celeryproject.org/en/latest/)获取有关 Celery 的更多详细信息。

在这个例子中，我们将设置一个包含 RabbitMQ 部署和我们自己的容器**celery-worker**的部署，用来处理来自该队列的作业：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/28e529ac-48cc-40f5-9217-60753631314a.png)

此示例的部署和源代码可在 GitHub 上找到[`github.com/kubernetes-for-developers/kfd-celery/`](https://github.com/kubernetes-for-developers/kfd-celery/)。您可以使用以下命令获取此代码：

```
git clone https://github.com/kubernetes-for-developers/kfd-celery -b 0.4.0 cd kfd-celery
```

# RabbitMQ 和配置

此示例使用了一个包含 Bitnami 的 RabbitMQ 的容器。该镜像的源代码可在[`github.com/bitnami/bitnami-docker-rabbitmq`](https://github.com/bitnami/bitnami-docker-rabbitmq)找到，并且容器镜像公开托管在 DockerHub 上[`hub.docker.com/r/bitnami/rabbitmq/`](https://hub.docker.com/r/bitnami/rabbitmq/)。

RabbitMQ 有大量可用的选项，以及多种部署方式，包括集群支持 HA。在这个例子中，我们使用了一个单一的 RabbitMQ 副本在部署中支持名为`message-queue`的服务。我们还设置了一个`ConfigMap`，其中包含一些我们可能想要调整的变量，尽管在这个例子中，这些值与容器内的默认值相同。该部署确实使用了持久卷，以便在发生故障时为队列启用持久性。我们将在本章后面详细介绍持久卷以及如何使用它们。

我们创建的`ConfigMap`将被 RabbitMQ 容器和我们的工作程序部署使用。`ConfigMap`名为`queue-config.yaml`，内容如下：

```
--- apiVersion: v1 kind: ConfigMap metadata:
  name: bitnami-rabbitmq-config data:
  RABBITMQ_USERNAME: "user"
  RABBITMQ_PASSWORD: "bitnami"
  RABBITMQ_VHOST: "/"
  RABBITMQ_NODE_PORT_NUMBER: "5672"
  RABBITMQ_MANAGER_PORT_NUMBER: "15672"
  WORKER_DEBUG_LEVEL: "info"
```

要部署它，您可以使用以下命令：

```
kubectl apply -f deploy/queue-config.yaml
```

```
configmap "bitnami-rabbitmq-config" created
```

`ConfigMap`是基于 Bitnami RabbitMQ 容器的文档创建的，该容器支持通过环境变量设置许多配置项。您可以在 Docker Hub 网页或 GitHub 源中查看容器可以接受的所有细节。在我们的情况下，我们设置了一些最常见的值。

**注意**：您可能希望使用密钥而不是在`ConfigMap`中包含值来更正确地设置用户名和密码。

您可以查看部署的规范：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/acdf2ee8-f989-4935-8ff0-abefc68f18ee.png)

这是如何部署实例的：

```
kubectl apply -f deploy/rabbitmq.yml service "message-queue" created persistentvolumeclaim "rabbitmq-pv-claim" created deployment "rabbitmq" created
```

# Celery worker

为了创建一个 worker，我们制作了一个非常类似于 Flask 容器的自己的容器镜像。Dockerfile 使用 Alpine Linux，并明确将 Python 3 加载到该镜像中，然后从`requirements.txt`文件安装要求，并添加了两个 Python 文件。第一个`celery_conf.py`是直接从 Celery 文档中获取的一些任务的 Python 定义。第二个`submit_tasks.py`是一个简短的示例，旨在交互式运行以创建工作并将其发送到队列中。容器还包括两个 shell 脚本：`run.sh`和`celery_status.sh`。

在所有这些情况下，我们使用了从前面的`ConfigMap`中获取的环境变量来设置 worker 的日志输出，以及与 Kubernetes 内的 RabbitMQ 通信的主机、用户名和密码。

Dockerfile 使用`run.sh`脚本作为其命令，因此我们可以使用此 shell 脚本设置任何环境变量并调用 Celery。因为 Celery 最初是作为一个命令行工具编写的，所以使用 shell 脚本来设置和调用您想要的内容非常方便。以下是对`run.sh`的更详细介绍：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/02e28d34-3a15-4bf3-9030-3533a0120941.png)

该脚本设置了两个 shell 脚本选项，`-e`和`-x`。第一个（`-e`）是为了确保如果我们在脚本中犯了拼写错误或命令返回错误，脚本本身将返回错误。第二个（`-x`）将在`STDOUT`中回显脚本中调用的命令，因此我们可以在容器日志输出中看到它。

下一行中的`DEBUG_LEVEL`使用 shell 查找默认环境变量：`WORKER_DEBUG_LEVEL`。如果设置了，它将使用它，而`WORKER_DEBUG_LEVEL`是早期添加到`ConfigMap`中的。如果值未设置，它将使用默认值`info`，因此如果`ConfigMap`中缺少该值，我们仍将在此处有一个合理的值。

如前所述，Celery 是作为命令行实用程序编写的，并利用 Python 的模块加载来完成其工作。 Python 模块加载包括从当前目录工作，因此我们明确更改为包含 Python 代码的目录。最后，脚本调用命令启动 Celery worker。

我们在脚本`celery_status.sh`中使用类似的结构，该脚本用于提供用于 worker 容器的活动性和可用性探针的 exec 命令，其关键思想是如果命令`celery status`返回而不出现错误，则容器正在有效地与 RabbitMQ 通信，并且应完全能够处理任务。

包含将被调用的逻辑的代码都在`celery_conf.py`中：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/e8492df5-f86d-4f03-8d02-cb9e5a2a3834.png)

您可以看到，我们再次利用环境变量来获取与 RabbitMQ 通信所需的值（主机名、用户名、密码和`vhost`），并从环境变量中组装这些默认值，如果未提供。主机名默认值（`message-queue`）也与我们的服务定义中的服务名称匹配，该服务定义了 RabbitMQ 的前端，为我们提供了一个稳定的默认值。代码的其余部分来自 Celery 文档，提供了两个示例任务，我们也可以分别导入和使用。

您可以使用以下命令部署 worker：

```
kubectl apply -f deploy/celery-worker.yaml
```

这应该报告已创建的部署，例如：

```
deployment "celery-worker" created
```

现在，您应该有两个部署一起运行。您可以使用`kubectl get pods`来验证这一点：

```
NAME                            READY     STATUS    RESTARTS   AGE celery-worker-7c59b58df-qptlc   1/1       Running   0          11m rabbitmq-6c656f667f-rp2zm       1/1       Running   0          14m
```

要更加交互地观察系统，请运行此命令：

```
kubectl log deploy/celery-worker -f
```

这将从`celery-worker`流式传输日志，例如：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/17a0f4de-79ed-45b2-8d96-f703686865a8.png)

这将显示`celery-worker`部署的日志，因为它们发生。打开第二个终端窗口并调用以下命令以运行一个临时 pod 并获得交互式 shell：

```
kubectl run -i --tty \ --image quay.io/kubernetes-for-developers/celery-worker:0.4.0 \ --restart=Never --image-pull-policy=Always --rm testing /bin/sh
```

在 shell 中，您现在可以运行脚本来生成一些任务供 worker 处理：

```
python3 submit_tasks.py
```

这个脚本的一个例子是：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/a99ef267-0e69-4f89-b00e-69f57f3a17b0.png)

这个脚本将无限期地运行，大约每五秒调用一次 worker 中的两个示例任务，在显示日志的窗口中，您应该看到输出更新，显示来自 Celery worker 的记录结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/15f20ba0-d087-4589-8b67-98d7c1aec03b.png)

# Kubernetes 的持久性

到目前为止，我们所有的例子，甚至代码，都基本上是无状态的。在上一章中，我们介绍了使用 Redis 的容器，但没有为它指定任何特殊的东西。默认情况下，Kubernetes 将假定与 pod 关联的任何资源都是临时的，如果节点失败或部署被删除，所有关联的资源都可以并且将被删除。

也就是说，我们所做的几乎所有工作都需要在某个地方存储和维护状态——数据库、对象存储，甚至是持久的内存队列。Kubernetes 包括对持久性的支持，截至目前为止，它仍在快速变化和发展。

# 卷

Kubernetes 最早的支持是卷，可以由集群管理员定义，并且我们已经看到了一些这种构造的变体，配置被暴露到容器中使用 Downward API 在第四章中，*声明式基础设施*。

另一种可以轻松使用的卷是`emptyDir`，您可以在 pod 规范中使用它来创建一个空目录，并将其挂载到一个或多个容器中。这通常在本地节点可用的存储上创建，但包括一个选项来指定*memory*的介质，您可以使用它来创建一个临时的内存支持文件系统。这会占用节点上更多的内存，但为您的 pod 创建一个非常快速的临时文件系统。如果您的代码想要在磁盘上使用一些临时空间，保持定期的检查点，或者加载临时内容，这可能是一个非常好的管理空间的方法。

正如我们在配置中指定的那样，当您使用卷时，您将其指定在卷下，并在`volumeMounts`下进行相关条目，指示您在每个容器上使用它的位置。

我们可以修改我们的 Flask 示例应用程序，使其具有一个内存支持的临时空间：

```
 spec: containers: - name: flask image: quay.io/kubernetes-for-developers/flask:0.3.0 imagePullPolicy: Always ports: - containerPort: 5000 volumeMounts: - name: config mountPath: /etc/flask-config readOnly: true - name: cache-volume mountPath: /opt/cache volumes: - name: config configMap: name: flask-config - name: cache-volume emptyDir: medium: Memory
```

如果我们部署规范的这个版本并在容器中打开一个交互式 shell，你可以看到`/opt/cache`被列为`tmpfs`类型的卷：

```
df -h Filesystem                Size      Used Available Use% Mounted on overlay                  15.3G      1.7G     12.7G  12% / tmpfs                  1000.1M         0   1000.1M   0% /dev tmpfs                  1000.1M         0   1000.1M   0% /sys/fs/cgroup tmpfs                  1000.1M         0   1000.1M   0% /opt/cache /dev/vda1                15.3G      1.7G     12.7G  12% /dev/termination-log /dev/vda1                15.3G      1.7G     12.7G  12% /etc/flask-config /dev/vda1                15.3G      1.7G     12.7G  12% /etc/resolv.conf /dev/vda1                15.3G      1.7G     12.7G  12% /etc/hostname /dev/vda1                15.3G      1.7G     12.7G  12% /etc/hosts shm                      64.0M         0     64.0M   0% /dev/shm tmpfs                  1000.1M     12.0K   1000.1M   0% /run/secrets/kubernetes.io/serviceaccount tmpfs                  1000.1M         0   1000.1M   0% /proc/kcore tmpfs                  1000.1M         0   1000.1M   0% /proc/timer_list tmpfs                  1000.1M         0   1000.1M   0% /proc/timer_stats tmpfs                  1000.1M         0   1000.1M   0% /sys/firmware
```

如果我们没有指定类型为`Memory`的介质，那么该目录将显示在本地磁盘上：

```
df -h Filesystem                Size      Used Available Use% Mounted on overlay                  15.3G      1.7G     12.7G  12% / tmpfs                  1000.1M         0   1000.1M   0% /dev tmpfs                  1000.1M         0   1000.1M   0% /sys/fs/cgroup /dev/vda1                15.3G      1.7G     12.7G  12% /dev/termination-log /dev/vda1                15.3G      1.7G     12.7G  12% /etc/flask-config /dev/vda1                15.3G      1.7G     12.7G  12% /opt/cache /dev/vda1                15.3G      1.7G     12.7G  12% /etc/resolv.conf /dev/vda1                15.3G      1.7G     12.7G  12% /etc/hostname /dev/vda1                15.3G      1.7G     12.7G  12% /etc/hosts shm                      64.0M         0     64.0M   0% /dev/shm tmpfs                  1000.1M     12.0K   1000.1M   0% /run/secrets/kubernetes.io/serviceaccount tmpfs                  1000.1M         0   1000.1M   0% /proc/kcore tmpfs                  1000.1M         0   1000.1M   0% /proc/timer_list tmpfs                  1000.1M         0   1000.1M   0% /proc/timer_stats tmpfs                  1000.1M         0   1000.1M   0% /sys/firmware
```

如果您在云服务提供商上使用卷，那么您可以使用他们的持久卷之一。在这些情况下，您需要在云服务提供商那里创建一个持久磁盘，该磁盘对您的 Kubernetes 集群中的节点是可访问的，但这样可以使数据存在于任何 pod 或节点的生命周期之外。每个云提供商的卷都是特定于该提供商的，例如`awsElasticBlockStore`、`azureDisk`或`gcePersistentDisk`。

还有许多其他类型的卷可用，大多数取决于您的集群是如何设置的以及该设置中可能有什么可用的。您可以从卷的正式文档[`kubernetes.io/docs/concepts/storage/volumes/`](https://kubernetes.io/docs/concepts/storage/volumes/)中了解所有支持的卷。

# 持久卷和持久卷索赔

如果您想要使用持久卷，而不受构建集群的特定位置的限制，您可能想要利用两个较新的 Kubernetes 资源：`PersistentVolume`和`PersistentVolumeClaim`。这些资源将提供卷的具体细节与您期望使用这些卷的方式分开，两者都属于动态卷分配的概念，这意味着当您将代码部署到 Kubernetes 时，系统应该从已经识别的磁盘中提供任何持久卷。Kubernetes 管理员将需要指定至少一个，可能更多的存储类，用于定义可供集群使用的持久卷的一般行为和后备存储。如果您在亚马逊网络服务、谷歌计算引擎或微软的 Azure 上使用 Kubernetes，这些公共服务都预定义了存储类可供使用。您可以在文档[`kubernetes.io/docs/concepts/storage/storage-classes/`](https://kubernetes.io/docs/concepts/storage/storage-classes/)中查看默认的存储类及其定义。如果您在本地使用 Minikube 进行尝试，它也有一个默认的存储类定义，使用的卷类型是`HostPath`。

定义`PersistentVolumeClaim`以与部署中的代码一起使用非常类似于使用`EmptyDir`定义配置卷或缓存，唯一的区别是您需要在引用它之前创建`persistentVolumeClaim`资源。

我们可能用于 Redis 存储的`persistentVolumeClaim`示例可能是：

```
apiVersion: v1 kind: PersistentVolumeClaim metadata:
 name: redis-pv-claim labels: app: redis-master spec:
 accessModes: - ReadWriteOnce resources: requests: storage: 1Gi
```

这将创建一个可供我们容器使用的 1GB 卷。我们可以将其添加到 Redis 容器中，通过名称引用这个`persistentVolumeClaim`来给它提供持久存储：

```
apiVersion: apps/v1beta1 kind: Deployment metadata:
 name: redis-master spec:
 replicas: 1 template: metadata: labels: app: redis role: master tier: backend spec: containers: - name: redis-master image: redis:4 ports: - containerPort: 6379 volumeMounts: - name: redis-persistent-storage mountPath: /data volumes: - name: redis-persistent-storage persistentVolumeClaim: claimName: redis-pv-claim
```

选择`/data`的`mountPath`是为了与 Redis 容器的构建方式相匹配。如果我们查看该容器的文档（来自[`hub.docker.com/_/redis/`](https://hub.docker.com/_/redis/)），我们可以看到内置配置期望所有数据都从`/data`路径使用，因此我们可以用我们自己的`persistentVolumeClaim`覆盖该路径，以便用一些能够在部署的生命周期之外存在的东西来支持该空间。

如果您将这些更改部署到 Minikube，您可以看到集群中反映出的结果资源：

```
kubectl get persistentvolumeclaims NAME             STATUS    VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS   AGE redis-pv-claim   Bound     pvc-f745c6f1-e7d8-11e7-89d4-b29f363a60d7   1Gi        RWO            standard       3d kubectl get persistentvolumes NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS    CLAIM                    STORAGECLASS   REASON    AGE pvc-f745c6f1-e7d8-11e7-89d4-b29f363a60d7   1Gi        RWO            Delete           Bound     default/redis-pv-claim   standard                 3d
```

我们还可以打开一个交互式终端进入 Redis 实例，看看它是如何设置的：

```
kubectl exec -it redis-master-6f944f6c8b-gm2cb -- /bin/sh # df -h Filesystem      Size  Used Avail Use% Mounted on overlay          16G  1.8G   13G  12% / tmpfs          1001M     0 1001M   0% /dev tmpfs          1001M     0 1001M   0% /sys/fs/cgroup /dev/vda1        16G  1.8G   13G  12% /data shm              64M     0   64M   0% /dev/shm tmpfs          1001M   12K 1001M   1% /run/secrets/kubernetes.io/serviceaccount tmpfs          1001M     0 1001M   0% /sys/firmware
```

# 有状态集

在动态配置之后，当您考虑持久性系统时，无论它们是经典数据库、键值数据存储、内存缓存还是基于文档的数据存储，通常希望具有某种冗余和故障转移的方式。 ReplicaSets 和部署在支持某些功能方面走得相当远，特别是对于持久卷，但是将它们更完全地集成到 Kubernetes 中将极大地有利于这些系统，以便我们可以利用 Kubernetes 来处理这些系统的生命周期和协调。这项工作的起点是 Stateful Sets，它们的工作方式类似于部署和 ReplicaSet，因为它们管理一组 pod。

Stateful Sets 与其他系统不同，它们还支持每个 pod 具有稳定的、唯一的标识和特定的有序扩展，无论是向上还是向下。 Stateful Sets 在 Kubernetes 中相对较新，首次出现在 Kubernetes 1.5 中，并在 1.9 版本中进入 beta。 Stateful Sets 还与我们之前提到的特定服务密切合作，即无头服务，需要在 Stateful Set 之前创建，并负责 pod 的网络标识。

作为提醒，无头服务是一种没有特定集群 IP 的服务，而是为与其关联的所有 pods 提供独特的服务标识作为单独的端点。这意味着任何使用该服务的系统都需要知道该服务具有特定标识的端点，并且需要能够与其想要通信的端点进行通信。当创建一个与无头服务相匹配的 Stateful Set 时，pods 将根据 Stateful Set 的名称和序号获得一个标识。例如，如果我们创建了一个名为 datastore 的 Stateful Set 并请求了三个副本，那么 pods 将被创建为 `datastore-0`、`datastore-1` 和 `datastore-2`。Stateful Sets 还有一个 `serviceName` 字段，该字段包含在服务的域名中。以完成这个示例，如果我们将 `serviceName` 设置为 `db`，那么为 pods 创建的关联 DNS 条目将是：

+   `datastore-0.db.[namespace].svc.cluster.local`

+   `datastore-1.db.[namespace].svc.cluster.local`

+   `datastore-2.db.[namespace].svc.cluster.local`

随着副本数量的变化，Stateful Set 也会明确而谨慎地添加和删除 pods。它会按照从最高编号开始顺序终止 pods，并且不会在较低编号的 pods 报告`Ready`和`Running`之前终止较高编号的 pods。从 Kubernetes 1.7 开始，Stateful Sets 引入了一个可选字段 `podManagementPolicy` 来改变这一行为。默认值 `OrderedReady` 的操作如上所述，另一个选项 `Parallel` 则不会按顺序操作，也不需要较低编号的 pods 处于`Running`或`Ready`状态才能终止一个 pod。

滚动更新，类似于部署，对于 Stateful Sets 也略有不同。它由`updateStrategy`可选字段定义，如果未明确设置，则使用`OnDelete`设置。使用此设置，Kubernetes 不会删除旧的 pod，即使在规范更新后，需要您手动删除这些 pod。当您这样做时，系统将根据更新后的规范自动重新创建 pod。另一个值是`RollingUpdate`，它更类似于部署，会自动终止和重新创建 pod，但会明确遵循顺序，并验证 pod 在继续更新下一个 pod 之前是否*准备就绪和运行*。`RollingUpdate`还有一个额外的（可选）字段，`partition`，如果指定了一个数字，将使`RollingUpdate`自动在一部分 pod 上操作。例如，如果分区设置为`3`，并且有`6`个副本，则只有 pod `3`，`4`和`5`会在规范更新时自动更新。Pod `0`，`1`和`2`将被保留，即使它们被手动删除，它们也将以先前的版本重新创建。分区功能可用于分阶段更新或执行分阶段部署。

# 使用 Stateful Set 的 Node.js 示例

应用程序内的代码不需要 Stateful Set 机制，但让我们将其用作易于理解的更新，以展示您可能如何使用 Stateful Set 以及如何观察其运行。

此更新的代码可在 GitHub 上的项目中找到：[`github.com/kubernetes-for-developers/kfd-nodejs`](https://github.com/kubernetes-for-developers/kfd-nodejs)，分支为 0.4.0。该项目的代码没有更改，只是将部署规范更改为 Stateful Set。您可以使用以下命令获取此版本的代码：

```
git clone https://github.com/kubernetes-for-developers/kfd-nodejs -b 0.4.0 cd kfd-nodejs
```

服务定义已更改，删除了`Nodeport`类型，并将`clusterIP`设置为`None`。现在`nodejs-service`的新定义如下：

```
kind: Service apiVersion: v1 metadata:
 name: nodejs-service spec:
 ports: - port: 3000 name: web clusterIP: None selector: app: nodejs
```

这将设置一个无头服务，用于与 Stateful Set 一起使用。从部署到 Stateful Set 的更改同样简单，将类型`Deployment`替换为类型`StatefulSet`，并添加`serviceName`、副本和设置选择器的值。我还添加了一个带有持久卷索赔的数据存储挂载，以展示它如何与您现有的规范集成。现有的`ConfigMap`、`livenessProbe`和`readinessProbe`设置都得到了保留。最终的`StatefulSet`规范现在如下所示：

```
apiVersion: apps/v1beta1 kind: StatefulSet metadata:
 name: nodejs spec:
 serviceName: "nodejs" replicas: 5 selector: matchLabels: app: nodejs template: metadata: labels: app: nodejs spec: containers: - name: nodejs image: quay.io/kubernetes-for-developers/nodejs:0.3.0 imagePullPolicy: Always ports: - containerPort: 3000 name: web envFrom: - configMapRef: name: nodejs-config volumeMounts: - name: config mountPath: /etc/nodejs-config readOnly: true - name: datastore mountPath: /opt/data livenessProbe: httpGet: path: /probes/alive port: 3000 initialDelaySeconds: 1 periodSeconds: 5 readinessProbe: httpGet: path: /probes/ready port: 3000 initialDelaySeconds: 5 periodSeconds: 5 volumes: - name: config configMap: name: nodejs-config updateStrategy: type: RollingUpdate volumeClaimTemplates: - metadata: name: datastore spec: accessModes: [ "ReadWriteOnce" ] resources: requests: storage: 1Gi
```

自上一章中更新了代码以使用带有就绪探针的 Redis 后，我们将希望确保我们的 Redis 已经运行起来，以便这个 Stateful Set 能够继续进行。您可以使用以下命令部署更新后的 Redis 服务定义集：

```
kubectl apply -f deploy/redis.yaml
```

现在，我们可以利用`kubectl get`的观察选项（`-w`）来观察 Kubernetes 如何设置 Stateful Set 并进行仔细的进展。打开一个额外的终端窗口并运行以下命令：

```
kubectl get pods -w -l app=nodejs
```

起初，您不应该看到任何输出，但随着 Kubernetes 在 Stateful Set 中的进展，更新将会出现。

在您原始的终端窗口中，使用以下命令部署我们已更新为`StatefulSet`的规范：

```
kubectl apply -f deploy/nodejs.yaml
```

您应该会看到`service`、`configmap`和`statefulset`对象都已创建的响应：

```
service "nodejs-service" unchanged configmap "nodejs-config" unchanged statefulset "nodejs" created
```

在您观看 pod 的窗口中，当第一个容器上线时，您应该会看到输出开始出现。每当观察触发器发现我们设置的描述符（`-l app=nodejs`）中的一个 pod 有更新时，输出中会出现一行：

```
NAME       READY     STATUS    RESTARTS   AGE nodejs-0   0/1       Pending   0          2h nodejs-0   0/1       Pending   0         2h nodejs-0   0/1       ContainerCreating   0         2h nodejs-0   0/1       Running   0         2h nodejs-0   1/1       Running   0         2h nodejs-1   0/1       Pending   0         2h nodejs-1   0/1       Pending   0         2h nodejs-1   0/1       ContainerCreating   0         2h nodejs-1   0/1       Running   0         2h nodejs-1   1/1       Running   0         2h nodejs-2   0/1       Pending   0         2h nodejs-2   0/1       Pending   0         2h nodejs-2   0/1       ContainerCreating   0         2h nodejs-2   0/1       Running   0         2h nodejs-2   1/1       Running   0         2h nodejs-3   0/1       Pending   0         2h nodejs-3   0/1       Pending   0         2h
```

我们设置的定义有五个副本，因此总共会生成五个 pod。您可以使用以下命令查看该部署的状态：

```
kubectl get sts nodejs
```

```
NAME      DESIRED   CURRENT   AGE nodejs    5         5         2h
```

在上述命令中，`sts`是`statefulset`的缩写。您还可以使用以下命令以人类可读的形式获得当前状态的更详细视图：

```
kubectl describe sts nodejs
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/c12e0f06-ca4c-40e6-af6e-b80d2b8854b0.png)

如果您编辑规范，将副本更改为两个，然后应用更改，您将看到 pod 按照设置的相反顺序被拆除，最高序数号先。以下命令：

```
kubectl apply -f deploy/nodejs.yml
```

应该报告：

```
service "nodejs-service" unchanged configmap "nodejs-config" unchanged statefulset "nodejs" configured
```

在观看 pod 的窗口中，您将看到`nodejs-4`开始终止，并且会一直持续到`nodejs-3`，然后是`nodejs-2`终止。

如果您运行一个临时的`pod`来查看 DNS：

```
kubectl run -i --tty --image busybox dns-test --restart=Never --rm /bin/sh
```

您可以使用`nslookup`命令验证`pods`的 DNS 值：

```
/ # nslookup nodejs-1.nodejs-service
Server: 10.96.0.10
Address 1: 10.96.0.10 kube-dns.kube-system.svc.cluster.local

Name: nodejs-1.nodejs-service
Address 1: 172.17.0.6 nodejs-1.nodejs-service.default.svc.cluster.local

/ # nslookup nodejs-0.nodejs-service
Server: 10.96.0.10
Address 1: 10.96.0.10 kube-dns.kube-system.svc.cluster.local

Name: nodejs-0.nodejs-service
Address 1: 172.17.0.4 nodejs-0.nodejs-service.default.svc.cluster.local
```

# 自定义资源定义

Stateful Sets 并不自动匹配所有可用的持久存储，其中一些甚至对管理应用程序的生命周期有更复杂的逻辑要求。随着 Kubernetes 考虑如何支持扩展其控制器以支持更复杂的逻辑，该项目从 Operators 的概念开始，即可以包含在 Kubernetes 项目中的外部代码，并且截至 Kubernetes 1.8 版本已经发展为更明确地使用`CustomResourceDefinitions`。自定义资源扩展了 Kubernetes API，并允许创建自定义 API 对象，并与自定义控制器匹配，您还可以将其加载到 Kubernetes 中以处理这些对象的生命周期。

自定义资源定义超出了我们在本书中将涵盖的范围，尽管您应该意识到它们的存在。您可以在项目的文档站点上获取有关自定义资源定义以及如何扩展 Kubernetes 的更多详细信息：[`kubernetes.io/docs/concepts/api-extension/custom-resources/.`](https://kubernetes.io/docs/concepts/api-extension/custom-resources/)

有许多通过开源项目提供的 Operators 可利用自定义资源定义来管理 Kubernetes 中特定的应用程序。CoreOS 团队支持用于管理 Prometheus 和`etcd`的 Operators 和自定义资源。还有一个名为 Rook 的开源存储资源和相关技术，它使用自定义资源定义来运行。

截至目前，如何最好地在 Kubernetes 中运行持久存储的广泛集合仍在不断发展。有许多示例可以演示如何在 Kubernetes 中运行您选择的数据库或 NoSQL 数据存储，同时还支持冗余和故障转移。这些系统大多是通过各种机制来支持其管理，其中很少有系统对自动扩展和冗余提供了很多支持。有许多支持各种数据存储的技术可作为示例。一些更复杂的系统使用 Operators 和这些自定义资源定义；其他系统使用一组 Pod 和容器以更简单的复制集来实现其目标。

# 总结

在本章中，我们回顾了 Kubernetes 提供的作业和 CronJobs，以支持批处理和定期批处理处理。我们还通过一个 Python 示例来了解如何使用 RabbitMQ 设置 Celery 工作队列，并配置这两个部署以共同工作。然后，我们看了一下 Kubernetes 如何通过卷、`PersistentVolume`和其自动创建部署所需卷的`PersistentVolumeClaims`的概念来提供持久性。Kubernetes 还支持 Stateful Sets，用于需要稳定标识和持久卷的部署变体，我们看了一个简单的 Node.js 示例，将我们之前的部署示例转换为 Stateful Set。最后，我们通过查看用于扩展 Kubernetes 的自定义资源定义来结束本章。

在下一章中，我们开始研究如何利用 Kubernetes 获取所有这些结构的信息。我们将回顾如何捕获和查看指标，利用 Kubernetes 和其他开源项目，以及从 Kubernetes 鼓励的水平扩展系统中整理日志的示例。
