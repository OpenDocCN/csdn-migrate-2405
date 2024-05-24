# Kubernetes DevOps 手册（三）

> 原文：[`zh.annas-archive.org/md5/55C804BD2C19D0AE8370F4D1F28719E7`](https://zh.annas-archive.org/md5/55C804BD2C19D0AE8370F4D1F28719E7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：集群管理

在之前的章节中，我们学习了 Kubernetes 中大部分基本的 DevOps 技能，从如何将应用程序容器化到通过持续部署将我们的容器化软件无缝部署到 Kubernetes。现在，是时候更深入地了解如何管理 Kubernetes 集群了。

在本章中，我们将学习：

+   如何利用命名空间设置管理边界

+   使用 kubeconfig 在多个集群之间切换

+   Kubernetes 身份验证

+   Kubernetes 授权

虽然 minikube 是一个相当简单的环境，但在本章中，我们将以**Google 容器引擎**（**GKE**）和 AWS 中的自托管集群作为示例，而不是 minikube。有关详细设置，请参阅第九章，*AWS 上的 Kubernetes*，以及第十章，*GCP 上的 Kubernetes*。

# Kubernetes 命名空间

Kubernetes 具有命名空间概念，将物理集群中的资源划分为多个虚拟集群。这样，不同的组可以共享同一个物理集群并实现隔离。每个命名空间提供：

+   一组名称范围；每个命名空间中的对象名称是唯一的

+   确保受信任身份验证的策略

+   设置资源配额以进行资源管理

命名空间非常适合同一公司中的不同团队或项目，因此不同的组可以拥有自己的虚拟集群，这些集群具有资源隔离但共享同一个物理集群。一个命名空间中的资源对其他命名空间是不可见的。可以为不同的命名空间设置不同的资源配额，并提供不同级别的 QoS。请注意，并非所有对象都在命名空间中，例如节点和持久卷，它们属于整个集群。

# 默认命名空间

默认情况下，Kubernetes 有三个命名空间：`default`，`kube-system`和`kube-public`。`default`命名空间包含未指定任何命名空间创建的对象，而`kube-system`包含由 Kubernetes 系统创建的对象，通常由系统组件使用，例如 Kubernetes 仪表板或 Kubernetes DNS。`kube-public`是在 1.6 中新引入的，旨在定位每个人都可以访问的资源。它现在主要关注公共 ConfigMap，如集群信息。

# 创建新的命名空间

让我们看看如何创建一个命名空间。命名空间也是 Kubernetes 对象。我们可以像其他对象一样指定种类为命名空间。下面是创建一个命名空间`project1`的示例：

```
// configuration file of namespace
# cat 8-1-1_ns1.yml
apiVersion: v1
kind: Namespace
metadata:
name: project1

// create namespace for project1
# kubectl create -f 8-1-1_ns1.yml
namespace "project1" created

// list namespace, the abbreviation of namespaces is ns. We could use `kubectl get ns` to list it as well.
# kubectl get namespaces
NAME          STATUS    AGE
default       Active    1d
kube-public   Active    1d
kube-system   Active    1d
project1      Active    11s
```

然后让我们尝试通过`project1`命名空间中的部署启动两个 nginx 容器：

```
// run a nginx deployment in project1 ns
# kubectl run nginx --image=nginx:1.12.0 --replicas=2 --port=80 --namespace=project1 
```

当我们通过`kubectl get pods`列出 pod 时，我们会在我们的集群中看不到任何内容。为什么？因为 Kubernetes 使用当前上下文来决定哪个命名空间是当前的。如果我们在上下文或`kubectl`命令行中不明确指定命名空间，则将使用`default`命名空间：

```
// We'll see the Pods if we explicitly specify --namespace
# kubectl get pods --namespace=project1
NAME                     READY     STATUS    RESTARTS   AGE
nginx-3599227048-gghvw   1/1       Running   0          15s
nginx-3599227048-jz3lg   1/1       Running   0          15s  
```

您可以使用`--namespace <namespace_name>`，`--namespace=<namespace_name>`，`-n <namespace_name>`或`-n=<namespace_name>`来指定命令的命名空间。要列出跨命名空间的资源，请使用`--all-namespaces`参数。

另一种方法是将当前上下文更改为指向所需命名空间，而不是默认命名空间。

# 上下文

**上下文**是集群信息、用于身份验证的用户和命名空间的组合概念。例如，以下是我们在 GKE 中一个集群的上下文信息：

```
- context:
cluster: gke_devops-with-kubernetes_us-central1-b_cluster
user: gke_devops-with-kubernetes_us-central1-b_cluster
name: gke_devops-with-kubernetes_us-central1-b_cluster  
```

我们可以使用`kubectl config current-context`命令查看当前上下文：

```
# kubectl config current-context
gke_devops-with-kubernetes_us-central1-b_cluster
```

要列出所有配置信息，包括上下文，您可以使用`kubectl config view`命令；要检查当前正在使用的上下文，使用`kubectl config get-contexts`命令。

# 创建上下文

下一步是创建上下文。与前面的示例一样，我们需要为上下文设置用户和集群名称。如果我们不指定这些，将设置为空值。创建上下文的命令是：

```
$ kubectl config set-context <context_name> --namespace=<namespace_name> --cluster=<cluster_name> --user=<user_name>  
```

在同一集群中可以创建多个上下文。以下是如何在我的 GKE 集群`gke_devops-with-kubernetes_us-central1-b_cluster`中为`project1`创建上下文的示例：

```
// create a context with my GKE cluster
# kubectl config set-context project1 --namespace=project1 --cluster=gke_devops-with-kubernetes_us-central1-b_cluster --user=gke_devops-with-kubernetes_us-central1-b_cluster
Context "project1" created.  
```

# 切换当前上下文

然后我们可以通过`use-context`子命令切换上下文：

```
# kubectl config use-context project1
Switched to context "project1".  
```

上下文切换后，我们通过`kubectl`调用的每个命令都在`project1`上下文下。我们不需要明确指定命名空间来查看我们的 pod：

```
// list pods
# kubectl get pods
NAME                     READY     STATUS    RESTARTS   AGE
nginx-3599227048-gghvw   1/1       Running   0          3m
nginx-3599227048-jz3lg   1/1       Running   0          3m  
```

# 资源配额

在 Kubernetes 中，默认情况下，pod 是无限制的资源。然后运行的 pod 可能会使用集群中的所有计算或存储资源。ResourceQuota 是一个资源对象，允许我们限制命名空间可以使用的资源消耗。通过设置资源限制，我们可以减少嘈杂的邻居症状。为`project1`工作的团队不会耗尽物理集群中的所有资源。

然后我们可以确保其他项目中工作的团队在共享同一物理集群时的服务质量。Kubernetes 1.7 支持三种资源配额。每种类型包括不同的资源名称（[`kubernetes.io/docs/concepts/policy/resource-quotas`](https://kubernetes.io/docs/concepts/policy/resource-quotas)）。

+   计算资源配额（CPU，内存）

+   存储资源配额（请求的存储、持久卷索赔）

+   对象计数配额（pod、RCs、ConfigMaps、services、LoadBalancers）

创建的资源不会受到新创建的资源配额的影响。如果资源创建请求超过指定的 ResourceQuota，资源将无法启动。

# 为命名空间创建资源配额

现在，让我们学习`ResourceQuota`的语法。以下是一个例子：

```
# cat 8-1-2_resource_quota.yml
apiVersion: v1
kind: ResourceQuota
metadata:
 name: project1-resource-quota
spec:
 hard:# the limits of the sum of memory request
 requests.cpu: "1"               # the limits of the sum   
   of requested CPU
   requests.memory: 1Gi            # the limits of the sum  
   of requested memory 
   limits.cpu: "2"           # the limits of total CPU  
   limits
   limits.memory: 2Gi        # the limits of total memory 
   limit 
   requests.storage: 64Gi    # the limits of sum of 
   storage requests across PV claims
   pods: "4"                 # the limits of pod number   
```

模板与其他对象一样，只是这种类型变成了`ResourceQuota`。我们指定的配额适用于处于成功或失败状态的 pod（即非终端状态）。支持几种资源约束。在前面的例子中，我们演示了如何设置计算 ResourceQuota、存储 ResourceQuota 和对象 CountQuota。随时，我们仍然可以使用`kubectl`命令来检查我们设置的配额：`kubectl describe resourcequota <resource_quota_name>`。

现在让我们通过命令`kubectl edit deployment nginx`修改我们现有的 nginx 部署，将副本从`2`更改为`4`并保存。现在让我们列出状态。

```
# kubectl describe deployment nginx
Replicas:         4 desired | 2 updated | 2 total | 2 available | 2 unavailable
Conditions:
 Type                  Status      Reason
 ----                  ------      ------
 Available             False MinimumReplicasUnavailable
 ReplicaFailure  True  FailedCreate  
```

它指示一些 pod 在创建时失败。如果我们检查相应的 ReplicaSet，我们可以找出原因：

```
# kubectl describe rs nginx-3599227048
...
Error creating: pods "nginx-3599227048-" is **forbidden**: failed quota: project1-resource-quota: must specify limits.cpu,limits.memory,requests.cpu,requests.memory  
```

由于我们已经在内存和 CPU 上指定了请求限制，Kubernetes 不知道新期望的三个 pod 的默认请求限制。我们可以看到原来的两个 pod 仍在运行，因为资源配额不适用于现有资源。然后我们使用`kubectl edit deployment nginx`来修改容器规范如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00116.jpeg)

在这里，我们在 pod 规范中指定了 CPU 和内存的请求和限制。这表明 pod 不能超过指定的配额，否则将无法启动：

```
// check the deployment state
# kubectl get deployment
NAME      DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
nginx     4         3         2            3           2d  
```

可用的 pod 变成了四个，而不是两个，但仍然不等于我们期望的四个。出了什么问题？如果我们退一步检查我们的资源配额，我们会发现我们已经使用了所有的 pod 配额。由于部署默认使用滚动更新部署机制，它将需要大于四的 pod 数量，这正是我们之前设置的对象限制：

```
# kubectl describe resourcequota project1-resource-quota
Name:             project1-resource-quota
Namespace:        project1
Resource          Used  Hard
--------          ----  ----
limits.cpu        900m  4
limits.memory     900Mi 4Gi
pods              4     4
requests.cpu      300m  4
requests.memory   450Mi 16Gi
requests.storage  0     64Gi  
```

通过`kubectl edit resourcequota project1-resource-quota`命令将 pod 配额从`4`修改为`8`后，部署有足够的资源来启动 pod。一旦`Used`配额超过`Hard`配额，请求将被资源配额准入控制器拒绝，否则，资源配额使用将被更新以确保足够的资源分配。

由于资源配额不会影响已创建的资源，有时我们可能需要调整失败的资源，比如删除一个 RS 的空更改集或者扩展和缩小部署，以便让 Kubernetes 创建新的 pod 或 RS，这将吸收最新的配额限制。

# 请求具有默认计算资源限制的 pod

我们还可以为命名空间指定默认的资源请求和限制。如果在创建 pod 时不指定请求和限制，将使用默认设置。关键是使用`LimitRange`资源对象。`LimitRange`对象包含一组`defaultRequest`（请求）和`default`（限制）。

LimitRange 由 LimitRanger 准入控制器插件控制。如果启动自托管解决方案，请确保启用它。有关更多信息，请查看本章的准入控制器部分。

下面是一个示例，我们将`cpu.request`设置为`250m`，`limits`设置为`500m`，`memory.request`设置为`256Mi`，`limits`设置为`512Mi`：

```
# cat 8-1-3_limit_range.yml
apiVersion: v1
kind: LimitRange
metadata:
 name: project1-limit-range
spec:
 limits:
 - default:
 cpu: 0.5
 memory: 512Mi
 defaultRequest:
 cpu: 0.25
 memory: 256Mi
 type: Container

// create limit range
# kubectl create -f 8-1-3_limit_range.yml
limitrange "project1-limit-range" created  
```

当我们在此命名空间内启动 pod 时，即使在 ResourceQuota 中设置了总限制，我们也不需要随时指定`cpu`和`memory`请求和`limits`。

CPU 的单位是核心，这是一个绝对数量。它可以是 AWS vCPU，GCP 核心或者装备了超线程处理器的机器上的超线程。内存的单位是字节。Kubernetes 使用字母或二的幂的等价物。例如，256M 可以写成 256,000,000，256 M 或 244 Mi。

此外，我们可以在 LimitRange 中为 pod 设置最小和最大的 CPU 和内存值。它与默认值的作用不同。默认值仅在 pod 规范不包含任何请求和限制时使用。最小和最大约束用于验证 pod 是否请求了太多的资源。语法是`spec.limits[].min`和`spec.limits[].max`。如果请求超过了最小和最大值，服务器将抛出 forbidden 错误。

```
limits: 
   - max: 
      cpu: 1 
      memory: 1Gi 
     min: 
      cpu: 0.25 
      memory: 128Mi 
    type: Container 
```

Pod 的服务质量：Kubernetes 中的 pod 有三个 QoS 类别：Guaranteed、Burstable 和 BestEffort。它与我们上面学到的命名空间和资源管理概念密切相关。我们还在第四章中学习了 QoS，*使用存储和资源*。请参考第四章中的最后一节*使用存储和资源*进行复习。

# 删除一个命名空间

与其他资源一样，删除一个命名空间是`kubectl delete namespace <namespace_name>`。请注意，如果删除一个命名空间，与该命名空间关联的所有资源都将被清除。

# Kubeconfig

Kubeconfig 是一个文件，您可以使用它来通过切换上下文来切换多个集群。我们可以使用`kubectl config view`来查看设置。以下是`kubeconfig`文件中 minikube 集群的示例。

```
# kubectl config view
apiVersion: v1
clusters:  
- cluster:
 certificate-authority: /Users/k8s/.minikube/ca.crt
 server: https://192.168.99.100:8443
 name: minikube
contexts:
- context:
 cluster: minikube
 user: minikube
 name: minikube
current-context: minikube
kind: Config
preferences: {}
users:
- name: minikube
 user:
 client-certificate: /Users/k8s/.minikube/apiserver.crt
 client-key: /Users/k8s/.minikube/apiserver.key
```

就像我们之前学到的一样。我们可以使用`kubectl config use-context`来切换要操作的集群。我们还可以使用`kubectl config --kubeconfig=<config file name>`来指定要使用的`kubeconfig`文件。只有指定的文件将被使用。我们还可以通过环境变量`$KUBECONFIG`指定`kubeconfig`文件。这样，配置文件可以被合并。例如，以下命令将合并`kubeconfig-file1`和`kubeconfig-file2`：

```
# export KUBECONFIG=$KUBECONFIG: kubeconfig-file1: kubeconfig-file2  
```

您可能会发现我们之前没有进行任何特定的设置。那么`kubectl config view`的输出来自哪里呢？默认情况下，它存在于`$HOME/.kube/config`下。如果没有设置前面的任何一个，将加载此文件。

# 服务账户

与普通用户不同，**服务账户**是由 pod 内的进程用来联系 Kubernetes API 服务器的。默认情况下，Kubernetes 集群为不同的目的创建不同的服务账户。在 GKE 中，已经创建了大量的服务账户：

```
// list service account across all namespaces
# kubectl get serviceaccount --all-namespaces
NAMESPACE     NAME                         SECRETS   AGE
default       default                      1         5d
kube-public   default                      1         5d
kube-system   namespace-controller         1         5d
kube-system   resourcequota-controller     1         5d
kube-system   service-account-controller   1         5d
kube-system   service-controller           1         5d
project1      default                      1         2h
...  
```

Kubernetes 将在每个命名空间中创建一个默认的服务账户，如果在创建 pod 时未指定服务账户，则将使用该默认服务账户。让我们看看默认服务账户在我们的`project1`命名空间中是如何工作的：

```
# kubectl describe serviceaccount/default
Name:       default
Namespace:  project1
Labels:           <none>
Annotations:      <none>
Image pull secrets:     <none>
Mountable secrets:      default-token-nsqls
Tokens:                 default-token-nsqls  
```

我们可以看到，服务账户基本上是使用可挂载的密钥作为令牌。让我们深入了解令牌中包含的内容：

```
// describe the secret, the name is default-token-nsqls here
# kubectl describe secret default-token-nsqls
Name:       default-token-nsqls
Namespace:  project1
Annotations:  kubernetes.io/service-account.name=default
              kubernetes.io/service-account.uid=5e46cc5e- 
              8b52-11e7-a832-42010af00267
Type: kubernetes.io/service-account-token
Data
====
ca.crt:     # the public CA of api server. Base64 encoded.
namespace:  # the name space associated with this service account. Base64 encoded
token:      # bearer token. Base64 encoded
```

密钥将自动挂载到目录`/var/run/secrets/kubernetes.io/serviceaccount`。当 pod 访问 API 服务器时，API 服务器将检查证书和令牌进行认证。服务账户的概念将在接下来的部分中与我们同在。

# 认证和授权

从 DevOps 的角度来看，认证和授权非常重要。认证验证用户并检查用户是否真的是他们所代表的身份。另一方面，授权检查用户拥有哪些权限级别。Kubernetes 支持不同的认证和授权模块。

以下是一个示例，展示了当 Kubernetes API 服务器收到请求时如何处理访问控制。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00117.jpeg)API 服务器中的访问控制

当请求发送到 API 服务器时，首先，它通过使用 API 服务器中的**证书颁发机构**（**CA**）验证客户端的证书来建立 TLS 连接。API 服务器中的 CA 通常位于`/etc/kubernetes/`，客户端的证书通常位于`$HOME/.kube/config`。握手完成后，进入身份验证阶段。在 Kubernetes 中，身份验证模块是基于链的。我们可以使用多个身份验证和授权模块。当请求到来时，Kubernetes 将依次尝试所有的身份验证器，直到成功。如果请求在所有身份验证模块上失败，将被拒绝为 HTTP 401 未经授权。否则，其中一个身份验证器验证用户的身份并对请求进行身份验证。然后 Kubernetes 授权模块将发挥作用。它将验证用户是否有权限执行他们请求的操作，通过一组策略。授权模块也是基于链的。它将不断尝试每个模块，直到成功。如果请求在所有模块上失败，将得到 HTTP 403 禁止的响应。准入控制是 API 服务器中一组可配置的插件，用于确定请求是否被允许或拒绝。在这个阶段，如果请求没有通过其中一个插件，那么请求将立即被拒绝。

# 身份验证

默认情况下，服务账户是基于令牌的。当您创建一个服务账户或一个带有默认服务账户的命名空间时，Kubernetes 会创建令牌并将其存储为一个由 base64 编码的秘密，并将该秘密作为卷挂载到 pod 中。然后 pod 内的进程有能力与集群通信。另一方面，用户账户代表一个普通用户，可能使用`kubectl`直接操作资源。

# 服务账户身份验证

当我们创建一个服务账户时，Kubernetes 服务账户准入控制器插件会自动创建一个签名的令牌。

在第七章，*持续交付*中，在我们演示了如何部署`my-app`的示例中，我们创建了一个名为`cd`的命名空间，并且我们使用了脚本`get-sa-token.sh`（[`github.com/DevOps-with-Kubernetes/examples/blob/master/chapter7/get-sa-token.sh`](https://github.com/DevOps-with-Kubernetes/examples/blob/master/chapter7/get-sa-token.sh)）来为我们导出令牌。然后我们通过`kubectl config set-credentials <user> --token=$TOKEN`命令创建了一个名为`mysa`的用户：

```
# kubectl config set-credentials mysa --token=${CI_ENV_K8S_SA_TOKEN}  
```

接下来，我们将上下文设置为与用户和命名空间绑定：

```
# kubectl config set-context myctxt --cluster=mycluster --user=mysa  
```

最后，我们将把我们的上下文`myctxt`设置为默认上下文：

```
# kubectl config use-context myctxt  
```

当服务账户发送请求时，API 服务器将验证令牌，以检查请求者是否有资格以及它所声称的身份是否属实。

# 用户账户认证

有几种用户账户认证的实现方式。从客户端证书、持有者令牌、静态文件到 OpenID 连接令牌。您可以选择多种身份验证链。在这里，我们将演示客户端证书的工作原理。

在第七章，*持续交付*中，我们学习了如何为服务账户导出证书和令牌。现在，让我们学习如何为用户做这件事。假设我们仍然在`project1`命名空间中，并且我们想为我们的新 DevOps 成员琳达创建一个用户，她将帮助我们为`my-app`进行部署。

首先，我们将通过 OpenSSL（[`www.openssl.org`](https://www.openssl.org)）生成一个私钥：

```
// generate a private key for Linda
# openssl genrsa -out linda.key 2048  
```

接下来，我们将为琳达创建一个证书签名请求（`.csr`）：

```
// making CN as your username
# openssl req -new -key linda.key -out linda.csr -subj "/CN=linda"  
```

现在，`linda.key`和`linda.csr`应该位于当前文件夹中。为了批准签名请求，我们需要找到我们 Kubernetes 集群的 CA。

在 minikube 中，它位于`~/.minikube/`。对于其他自托管解决方案，通常位于`/etc/kubernetes/`下。如果您使用 kops 部署集群，则位置位于`/srv/kubernetes`下，您可以在`/etc/kubernetes/manifests/kube-apiserver.manifest`文件中找到路径。

假设我们在当前文件夹下有`ca.crt`和`ca.key`，我们可以通过我们的签名请求生成证书。使用`-days`参数，我们可以定义过期日期：

```
// generate the cert for Linda, this cert is only valid for 30 days.
# openssl x509 -req -in linda.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out linda.crt -days 30
Signature ok
subject=/CN=linda
Getting CA Private Key  
```

在我们的集群中有证书签名后，我们可以在集群中设置一个用户。

```
# kubectl config set-credentials linda --client-certificate=linda.crt --client-key=linda.key
User "linda" set.  
```

记住上下文的概念：它是集群信息、用于认证的用户和命名空间的组合。现在，我们将在`kubeconfig`中设置一个上下文条目。请记住从以下示例中替换您的集群名称、命名空间和用户：

```
# kubectl config set-context devops-context --cluster=k8s-devops.net --namespace=project1 --user=linda
Context "devops-context" modified.  
```

现在，琳达应该没有任何权限：

```
// test for getting a pod 
# kubectl --context=devops-context get pods
Error from server (Forbidden): User "linda" cannot list pods in the namespace "project1". (get pods)  
```

琳达现在通过了认证阶段，而 Kubernetes 知道她是琳达。但是，为了让琳达有权限进行部署，我们需要在授权模块中设置策略。

# 授权

Kubernetes 支持多个授权模块。在撰写本文时，它支持：

+   ABAC

+   RBAC

+   节点授权

+   Webhook

+   自定义模块

**基于属性的访问控制**（**ABAC**）是在**基于角色的访问控制**（**RBAC**）引入之前的主要授权模式。节点授权被 kubelet 用于向 API 服务器发出请求。Kubernetes 支持 webhook 授权模式，以与外部 RESTful 服务建立 HTTP 回调。每当面临授权决定时，它都会进行 POST。另一种常见的方式是按照预定义的授权接口实现自己的内部模块。有关更多实现信息，请参阅[`kubernetes.io/docs/admin/authorization/#custom-modules`](https://kubernetes.io/docs/admin/authorization/#custom-modules)。在本节中，我们将更详细地描述 ABAC 和 RBAC。

# 基于属性的访问控制（ABAC）

ABAC 允许管理员将一组用户授权策略定义为每行一个 JSON 格式的文件。ABAC 模式的主要缺点是策略文件在启动 API 服务器时必须存在。文件中的任何更改都需要使用`--authorization-policy-file=<policy_file_name>`命令重新启动 API 服务器。自 Kubernetes 1.6 以来引入了另一种授权方法 RBAC，它更灵活，不需要重新启动 API 服务器。RBAC 现在已成为最常见的授权模式。

以下是 ABAC 工作原理的示例。策略文件的格式是每行一个 JSON 对象。策略的配置文件类似于我们的其他配置文件。只是在规范中有不同的语法。ABAC 有四个主要属性：

| **属性类型** | **支持的值** |
| --- | --- |
| 主题匹配 | 用户，组 |
| 资源匹配 | `apiGroup`，命名空间和资源 |
| 非资源匹配 | 用于非资源类型请求，如`/version`，`/apis`，`/cluster` |
| 只读 | true 或 false |

以下是一些示例：

```
{"apiVersion": "abac.authorization.kubernetes.io/v1beta1", "kind": "Policy", "spec": {"user":"admin", "namespace": "*", "resource": "*", "apiGroup": "*"}} 
{"apiVersion": "abac.authorization.kubernetes.io/v1beta1", "kind": "Policy", "spec": {"user":"linda", "namespace": "project1", "resource": "deployments", "apiGroup": "*", "readonly": true}} 
{"apiVersion": "abac.authorization.kubernetes.io/v1beta1", "kind": "Policy", "spec": {"user":"linda", "namespace": "project1", "resource": "replicasets", "apiGroup": "*", "readonly": true}} 
```

在前面的例子中，我们有一个名为 admin 的用户，可以访问所有内容。另一个名为`linda`的用户只能在命名空间`project1`中读取部署和副本集。

# 基于角色的访问控制（RBAC）

RBAC 在 Kubernetes 1.6 中处于 beta 阶段，默认情况下是启用的。在 RBAC 中，管理员创建了几个`Roles`或`ClusterRoles`，这些角色定义了细粒度的权限，指定了一组资源和操作（动词），角色可以访问和操作这些资源。之后，管理员通过`RoleBinding`或`ClusterRoleBindings`向用户授予`Role`权限。

如果你正在运行 minikube，在执行`minikube start`时添加`--extra-config=apiserver.Authorization.Mode=RBAC`。如果你通过 kops 在 AWS 上运行自托管集群，则在启动集群时添加`--authorization=rbac`。Kops 会将 API 服务器作为一个 pod 启动；使用`kops edit cluster`命令可以修改容器的规范。

# 角色和集群角色

在 Kubernetes 中，`Role`绑定在命名空间内，而`ClusterRole`是全局的。以下是一个`Role`的示例，可以对部署、副本集和 pod 资源执行所有操作，包括`get`、`watch`、`list`、`create`、`update`、`delete`、`patch`。

```
# cat 8-5-2_role.yml
kind: Role
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
 namespace: project1
 name: devops-role
rules:
- apiGroups: ["", "extensions", "apps"]
 resources:
 - "deployments"
 - "replicasets"
 - "pods"
 verbs: ["*"]
```

在我们写这本书的时候，`apiVersion`仍然是`v1beta1`。如果 API 版本发生变化，Kubernetes 会抛出错误并提醒您进行更改。在`apiGroups`中，空字符串表示核心 API 组。API 组是 RESTful API 调用的一部分。核心表示原始 API 调用路径，例如`/api/v1`。新的 REST 路径中包含组名和 API 版本，例如`/apis/$GROUP_NAME/$VERSION`；要查找您想要使用的 API 组，请查看[`kubernetes.io/docs/reference`](https://kubernetes.io/docs/reference)中的 API 参考。在资源下，您可以添加您想要授予访问权限的资源，在动词下列出了此角色可以执行的操作数组。让我们来看一个更高级的`ClusterRoles`示例，我们在上一章中使用了持续交付角色：

```
# cat cd-clusterrole.yml
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRole
metadata:
 name: cd-role
rules:
- apiGroups: ["extensions", "apps"]
 resources:
 - deployments
 - replicasets
 - ingresses
 verbs: ["*"]
 - apiGroups: [""]
 resources:
 - namespaces
 - events
 verbs: ["get", "list", "watch"]
 - apiGroups: [""]
 resources:
 - pods
 - services
 - secrets
 - replicationcontrollers
 - persistentvolumeclaims
 - jobs
 - cronjobs
 verbs: ["*"]
```

`ClusterRole`是集群范围的。一些资源不属于任何命名空间，比如节点，只能由`ClusterRole`控制。它可以访问的命名空间取决于它关联的`ClusterRoleBinding`中的`namespaces`字段。我们可以看到，我们授予了该角色读取和写入 Deployments、ReplicaSets 和 ingresses 的权限，它们分别属于 extensions 和 apps 组。在核心 API 组中，我们只授予了对命名空间和事件的访问权限，以及对其他资源（如 pods 和 services）的所有权限。

# RoleBinding 和 ClusterRoleBinding

`RoleBinding`用于将`Role`或`ClusterRole`绑定到一组用户或服务账户。如果`ClusterRole`与`RoleBinding`绑定而不是`ClusterRoleBinding`，它将只被授予`RoleBinding`指定的命名空间内的权限。以下是`RoleBinding`规范的示例：

```
# cat 8-5-2_rolebinding_user.yml  
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
 name: devops-role-binding
 namespace: project1
subjects:
- kind: User
 name: linda
 apiGroup: [""]
roleRef:
 kind: Role
 name: devops-role
 apiGroup: [""]
```

在这个例子中，我们通过`roleRef`将`Role`与用户绑定。Kubernetes 支持不同类型的`roleRef`；我们可以在这里将`Role`的类型替换为`ClusterRole`：

```
roleRef:
kind: ClusterRole
name: cd-role
apiGroup: rbac.authorization.k8s.io 
```

然后`cd-role`只能访问`project1`命名空间中的资源。

另一方面，`ClusterRoleBinding`用于在所有命名空间中授予权限。让我们回顾一下我们在第七章中所做的事情，*持续交付*。我们首先创建了一个名为`cd-agent`的服务账户，然后创建了一个名为`cd-role`的`ClusterRole`。最后，我们为`cd-agent`和`cd-role`创建了一个`ClusterRoleBinding`。然后我们使用`cd-agent`代表我们进行部署：

```
# cat cd-clusterrolebinding.yml
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
 name: cd-agent
roleRef:
 apiGroup: rbac.authorization.k8s.io
 kind: ClusterRole
 name: cd-role
subjects:
- apiGroup: rbac.authorization.k8s.io
 kind: User
 name: system:serviceaccount:cd:cd-agent  
```

`cd-agent`通过`ClusterRoleBinding`与`ClusterRole`绑定，因此它可以跨命名空间拥有`cd-role`中指定的权限。由于服务账户是在命名空间中创建的，我们需要指定其完整名称，包括命名空间：

```
system:serviceaccount:<namespace>:<serviceaccountname> 
```

让我们通过`8-5-2_role.yml`和`8-5-2_rolebinding_user.yml`启动`Role`和`RoleBinding`：

```
# kubectl create -f 8-5-2_role.yml
role "devops-role" created
# kubectl create -f 8-5-2_rolebinding_user.yml
rolebinding "devops-role-binding" created  
```

现在，我们不再被禁止了：

```
# kubectl --context=devops-context get pods
No resources found.
```

如果 Linda 想要列出命名空间，允许吗？：

```
# kubectl --context=devops-context get namespaces
Error from server (Forbidden): User "linda" cannot list namespaces at the cluster scope. (get namespaces)  
```

答案是否定的，因为 Linda 没有被授予列出命名空间的权限。

# 准入控制

准入控制发生在 Kubernetes 处理请求之前，经过身份验证和授权之后。在启动 API 服务器时，通过添加`--admission-control`参数来启用它。如果集群版本>=1.6.0，Kubernetes 建议在集群中使用以下插件。

```
--admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,PersistentVolumeLabel,DefaultStorageClass,DefaultTolerationSeconds,ResourceQuota  
```

以下介绍了这些插件的用法，以及为什么我们需要它们。有关支持的准入控制插件的更多最新信息，请访问官方文档[`kubernetes.io/docs/admin/admission-controllers`](https://kubernetes.io/docs/admin/admission-controllers)。

# 命名空间生命周期

正如我们之前所了解的，当命名空间被删除时，该命名空间中的所有对象也将被驱逐。此插件确保在终止或不存在的命名空间中无法发出新的对象创建请求。它还防止了 Kubernetes 本机命名空间的删除。

# 限制范围

此插件确保`LimitRange`可以正常工作。使用`LimitRange`，我们可以在命名空间中设置默认请求和限制，在启动未指定请求和限制的 Pod 时将使用这些设置。

# 服务帐户

如果使用服务帐户对象，则必须添加服务帐户插件。有关服务帐户的更多信息，请再次查看本章中的服务帐户部分。

# PersistentVolumeLabel

`PersistentVolumeLabel`根据底层云提供商提供的标签，为新创建的 PV 添加标签。此准入控制器已从 1.8 版本中弃用。

# 默认存储类

如果在持久卷索赔中未设置`StorageClass`，此插件确保默认存储类可以按预期工作。不同的云提供商使用不同的供应工具来利用`DefaultStorageClass`（例如 GKE 使用 Google Cloud 持久磁盘）。请确保您已启用此功能。

# 资源配额

就像`LimitRange`一样，如果您正在使用`ResourceQuota`对象来管理不同级别的 QoS，则必须启用此插件。资源配额应始终放在准入控制插件列表的末尾。正如我们在资源配额部分提到的，如果使用的配额少于硬配额，资源配额使用将被更新，以确保集群具有足够的资源来接受请求。将其放在准入控制器列表的末尾可以防止请求在被以下控制器拒绝之前过早增加配额使用。

# 默认容忍秒

在介绍此插件之前，我们必须了解**污点**和**容忍**是什么。

# 污点和容忍

污点和忍受度用于阻止一组 Pod 在某些节点上调度运行。污点应用于节点，而忍受度则指定给 Pod。污点的值可以是`NoSchedule`或`NoExecute`。如果在运行一个带有污点的节点上的 Pod 时没有匹配的忍受度，那么这些 Pod 将被驱逐。

假设我们有两个节点：

```
# kubectl get nodes
NAME                            STATUS    AGE       VERSION  
ip-172-20-56-91.ec2.internal Ready 6h v1.7.2
ip-172-20-68-10.ec2.internal Ready 29m v1.7.2
```

现在通过`kubectl run nginx --image=nginx:1.12.0 --replicas=1 --port=80`命令运行一个 nginx Pod。

该 Pod 正在第一个节点`ip-172-20-56-91.ec2.internal`上运行：

```
# kubectl describe pods nginx-4217019353-s9xrn
Name:       nginx-4217019353-s9xrn
Node:       ip-172-20-56-91.ec2.internal/172.20.56.91
Tolerations:    node.alpha.kubernetes.io/notReady:NoExecute for 300s
node.alpha.kubernetes.io/unreachable:NoExecute for 300s  
```

通过 Pod 描述，我们可以看到有两个默认的忍受度附加到 Pod 上。这意味着如果节点尚未准备好或不可达，那么在 Pod 从节点中被驱逐之前等待 300 秒。这两个忍受度由 DefaultTolerationSeconds 准入控制器插件应用。我们稍后会谈论这个。接下来，我们将在第一个节点上设置一个 taint：

```
# kubectl taint nodes ip-172-20-56-91.ec2.internal experimental=true:NoExecute
node "ip-172-20-56-91.ec2.internal" tainted  
```

由于我们将操作设置为`NoExecute`，并且`experimental=true`与我们的 Pod 上的任何忍受度不匹配，因此 Pod 将立即从节点中删除并重新调度。可以将多个 taints 应用于一个节点。Pod 必须匹配所有忍受度才能在该节点上运行。以下是一个可以通过的带污染节点的示例：

```
# cat 8-6_pod_tolerations.yml
apiVersion: v1
kind: Pod
metadata:
 name: pod-with-tolerations
spec:
 containers:
 - name: web
 image: nginx
 tolerations:
 - key: "experimental"
 value: "true"
 operator: "Equal"
 effect: "NoExecute"  
```

除了`Equal`运算符，我们也可以使用`Exists`。在这种情况下，我们不需要指定值。只要键存在并且效果匹配，那么 Pod 就有资格在带污染的节点上运行。

`DefaultTolerationSeconds`插件用于设置那些没有设置任何忍受度的 Pod。然后将应用于`taints`的默认忍受度`notready:NoExecute`和`unreachable:NoExecute`，持续 300 秒。如果您不希望在集群中发生此行为，禁用此插件可能有效。

# PodNodeSelector

此插件用于将`node-selector`注释设置为命名空间。当启用插件时，使用以下格式通过`--admission-control-config-file`命令传递配置文件：

```
podNodeSelectorPluginConfig:
 clusterDefaultNodeSelector: <default-node-selectors-  
  labels>
 namespace1: <namespace-node-selectors-labels-1>
 namespace2: <namespace-node-selectors-labels-2>
```

然后`node-selector`注释将应用于命名空间。然后该命名空间上的 Pod 将在这些匹配的节点上运行。

# AlwaysAdmit

这总是允许所有请求，可能仅用于测试。

# AlwaysPullImages

拉取策略定义了 kubelet 拉取镜像时的行为。默认的拉取策略是`IfNotPresent`，也就是说，如果本地不存在镜像，它将拉取镜像。如果启用了这个插件，那么默认的拉取策略将变为`Always`，也就是说，总是拉取最新的镜像。这个插件还带来了另一个好处，如果你的集群被不同的团队共享。每当一个 pod 被调度，它都会拉取最新的镜像，无论本地是否存在该镜像。这样我们就可以确保 pod 创建请求始终通过对镜像的授权检查。

# AlwaysDeny

这总是拒绝所有请求。它只能用于测试。

# DenyEscalatingExec

这个插件拒绝任何`kubectl exec`和`kubectl attach`命令升级特权模式。具有特权模式的 pod 具有主机命名空间的访问权限，这可能会带来安全风险。

# 其他准入控制器插件

还有许多其他的准入控制器插件可以使用，比如 NodeRestriciton 来限制 kubelet 的权限，ImagePolicyWebhook 来建立一个控制对镜像访问的 webhook，SecurityContextDeny 来控制 pod 或容器的权限。请参考官方文档([`kubernetes.io/docs/admin/admission-controllers)`](https://kubernetes.io/docs/admin/admission-controllers/))以了解其他插件。

# 总结

在本章中，我们学习了命名空间和上下文是什么以及它们是如何工作的，如何通过设置上下文在物理集群和虚拟集群之间切换。然后我们了解了重要的对象——服务账户，它用于识别在 pod 内运行的进程。然后我们了解了如何在 Kubernetes 中控制访问流程。我们了解了认证和授权之间的区别，以及它们在 Kubernetes 中的工作方式。我们还学习了如何利用 RBAC 为用户提供细粒度的权限。最后，我们学习了一些准入控制器插件，它们是访问控制流程中的最后一道防线。

AWS 是公共 IaaS 提供商中最重要的参与者。在本章中，我们在自托管集群示例中经常使用它。在下一章第九章，*在 AWS 上使用 Kubernetes*，我们将最终学习如何在 AWS 上部署集群以及在使用 AWS 时的基本概念。


# 第九章：在 AWS 上的 Kubernetes

在公共云上使用 Kubernetes 对您的应用程序来说是灵活和可扩展的。AWS 是公共云行业中受欢迎的服务之一。在本章中，您将了解 AWS 是什么，以及如何在 AWS 上设置 Kubernetes，以及以下主题：

+   了解公共云

+   使用和理解 AWS 组件

+   kops 进行 Kubernetes 设置和管理

+   Kubernetes 云提供商

# AWS 简介

当您在公共网络上运行应用程序时，您需要像网络、虚拟机和存储这样的基础设施。显然，公司会借用或建立自己的数据中心来准备这些基础设施，然后雇佣数据中心工程师和运营商来监视和管理这些资源。

然而，购买和维护这些资产需要大量的资本支出；您还需要为数据中心工程师/运营商支付运营费用。您还需要一段时间来完全设置这些基础设施，比如购买服务器，安装到数据中心机架上，连接网络，然后进行操作系统的初始配置/安装等。

因此，快速分配具有适当资源容量的基础设施是决定您业务成功的重要因素之一。

为了使基础设施管理更加简单和快速，数据中心有许多技术可以帮助。例如，对于虚拟化、软件定义网络（SDN）、存储区域网络（SAN）等。但是将这些技术结合起来会有一些敏感的兼容性问题，并且很难稳定；因此需要雇佣这个行业的专家，最终使运营成本更高。

# 公共云

有一些公司提供了在线基础设施服务。AWS 是一个著名的提供在线基础设施的服务，被称为云或公共云。早在 2006 年，AWS 正式推出了虚拟机服务，称为弹性计算云（EC2），在线对象存储服务，称为简单存储服务（S3），以及在线消息队列服务，称为简单队列服务（SQS）。

这些服务足够简单，但从数据中心管理的角度来看，它们减轻了基础设施的预分配并减少了读取时间，因为它们采用按使用量付费的定价模型（按小时或年度向 AWS 支付）。因此，AWS 变得如此受欢迎，以至于许多公司已经从自己的数据中心转向了公共云。

与公共云相反，你自己的数据中心被称为**本地**。

# API 和基础设施即代码

使用公共云而不是本地数据中心的独特好处之一是公共云提供了一个 API 来控制基础设施。AWS 提供了命令行工具（**AWS CLI**）来控制 AWS 基础设施。例如，注册 AWS（[`aws.amazon.com/free/`](https://aws.amazon.com/free/)）后，安装 AWS CLI（[`docs.aws.amazon.com/cli/latest/userguide/installing.html`](http://docs.aws.amazon.com/cli/latest/userguide/installing.html)），然后如果你想启动一个虚拟机（EC2 实例），可以使用 AWS CLI 如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00118.jpeg)

如你所见，注册 AWS 后，只需几分钟就可以访问你的虚拟机。另一方面，如果你从零开始设置自己的本地数据中心会怎样呢？以下图表是对比使用本地数据中心和使用公共云的高层次比较：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00119.jpeg)

如你所见，公共云太简单和快速了；这就是为什么公共云不仅对新兴的使用方便，而且对永久的使用也很方便。

# AWS 组件

AWS 有一些组件来配置网络和存储。了解公共云的工作原理以及如何配置 Kubernetes 是很重要的。

# VPC 和子网

在 AWS 上，首先你需要创建自己的网络；这被称为**虚拟私有云**（**VPC**）并使用 SDN 技术。AWS 允许你在 AWS 上创建一个或多个 VPC。每个 VPC 可以根据需要连接在一起。当你创建一个 VPC 时，只需定义一个网络 CIDR 块和 AWS 区域。例如，在`us-east-1`上的 CIDR `10.0.0.0/16`。无论你是否有访问公共网络，你都可以定义任何网络地址范围（在/16 到/28 的掩码范围内）。VPC 的创建非常快速，一旦创建了 VPC，然后你需要在 VPC 内创建一个或多个子网。

在下面的例子中，通过 AWS 命令行创建了一个 VPC：

```
//specify CIDR block as 10.0.0.0/16
//the result, it returns VPC ID as "vpc-66eda61f"
$ aws ec2 create-vpc --cidr-block 10.0.0.0/16
{
 "Vpc": {
 "VpcId": "vpc-66eda61f", 
   "InstanceTenancy": "default", 
   "Tags": [], 
   "State": "pending", 
   "DhcpOptionsId": "dopt-3d901958", 
   "CidrBlock": "10.0.0.0/16"
  }
}
```

子网是一个逻辑网络块。它必须属于一个 VPC，并且另外属于一个可用区域。例如，VPC `vpc-66eda61f`和`us-east-1b`。然后网络 CIDR 必须在 VPC 的 CIDR 内。例如，如果 VPC CIDR 是`10.0.0.0/16`（`10.0.0.0` - `10.0.255.255`），那么一个子网 CIDR 可以是`10.0.1.0/24`（`10.0.1.0` - `10.0.1.255`）。

在下面的示例中，创建了两个子网（`us-east-1a`和`us-east-1b`）到`vpc-66eda61f`：

```
//1^(st) subnet 10.0."1".0/24 on us-east-1"a" availability zone
$ aws ec2 create-subnet --vpc-id vpc-66eda61f --cidr-block 10.0.1.0/24 --availability-zone us-east-1a
{
 "Subnet": {
    "VpcId": "vpc-66eda61f", 
    "CidrBlock": "10.0.1.0/24", 
    "State": "pending", 
    "AvailabilityZone": "us-east-1a", 
    "SubnetId": "subnet-d83a4b82", 
    "AvailableIpAddressCount": 251
  }
} 

//2^(nd) subnet 10.0."2".0/24 on us-east-1"b"
$ aws ec2 create-subnet --vpc-id vpc-66eda61f --cidr-block 10.0.2.0/24 --availability-zone us-east-1b
{
   "Subnet": {
    "VpcId": "vpc-66eda61f", 
    "CidrBlock": "10.0.2.0/24", 
    "State": "pending", 
    "AvailabilityZone": "us-east-1b", 
    "SubnetId": "subnet-62758c06", 
    "AvailableIpAddressCount": 251
   }
}
```

让我们将第一个子网设置为面向公众的子网，将第二个子网设置为私有子网。这意味着面向公众的子网可以从互联网访问，从而允许它拥有公共 IP 地址。另一方面，私有子网不能拥有公共 IP 地址。为此，您需要设置网关和路由表。

为了使公共网络和私有网络具有高可用性，建议至少创建四个子网（两个公共和两个私有位于不同的可用区域）。

但为了简化易于理解的示例，这些示例创建了一个公共子网和一个私有子网。

# 互联网网关和 NAT-GW

在大多数情况下，您的 VPC 需要与公共互联网连接。在这种情况下，您需要创建一个**IGW**（**互联网网关**）并附加到您的 VPC。

在下面的示例中，创建了一个 IGW 并附加到`vpc-66eda61f`：

```
//create IGW, it returns IGW id as igw-c3a695a5
$ aws ec2 create-internet-gateway 
{
   "InternetGateway": {
      "Tags": [], 
      "InternetGatewayId": "igw-c3a695a5", 
      "Attachments": []
   }
}

//attach igw-c3a695a5 to vpc-66eda61f
$ aws ec2 attach-internet-gateway --vpc-id vpc-66eda61f --internet-gateway-id igw-c3a695a5  
```

一旦附加了 IGW，然后为指向 IGW 的子网设置一个路由表（默认网关）。如果默认网关指向 IGW，则该子网可以拥有公共 IP 地址并从/到互联网访问。因此，如果默认网关不指向 IGW，则被确定为私有子网，这意味着没有公共访问。

在下面的示例中，创建了一个指向 IGW 并设置为第一个子网的路由表：

```
//create route table within vpc-66eda61f
//it returns route table id as rtb-fb41a280
$ aws ec2 create-route-table --vpc-id vpc-66eda61f
{
 "RouteTable": {
 "Associations": [], 
 "RouteTableId": "rtb-fb41a280", 
 "VpcId": "vpc-66eda61f", 
 "PropagatingVgws": [], 
 "Tags": [], 
 "Routes": [
 {
 "GatewayId": "local", 
 "DestinationCidrBlock": "10.0.0.0/16", 
 "State": "active", 
 "Origin": "CreateRouteTable"
 }
 ]
 }
}

//then set default route (0.0.0.0/0) as igw-c3a695a5
$ aws ec2 create-route --route-table-id rtb-fb41a280 --gateway-id igw-c3a695a5 --destination-cidr-block 0.0.0.0/0
{
 "Return": true
}

//finally, update 1^(st) subnet (subnet-d83a4b82) to use this route table
$ aws ec2 associate-route-table --route-table-id rtb-fb41a280 --subnet-id subnet-d83a4b82
{
 "AssociationId": "rtbassoc-bf832dc5"
}

//because 1^(st) subnet is public, assign public IP when launch EC2
$ aws ec2 modify-subnet-attribute --subnet-id subnet-d83a4b82 --map-public-ip-on-launch  
```

另一方面，尽管第二个子网是一个私有子网，但不需要公共 IP 地址，但是私有子网有时需要访问互联网。例如，下载一些软件包和访问 AWS 服务。在这种情况下，我们仍然有一个连接到互联网的选项。它被称为**网络地址转换网关**（**NAT-GW**）。

NAT-GW 允许私有子网通过 NAT-GW 访问公共互联网。因此，NAT-GW 必须位于公共子网上，并且私有子网的路由表将 NAT-GW 指定为默认网关。请注意，为了在公共网络上访问 NAT-GW，需要将**弹性 IP**（**EIP**）附加到 NAT-GW。

在以下示例中，创建了一个 NAT-GW：

```
//allocate EIP, it returns allocation id as eipalloc-56683465
$ aws ec2 allocate-address 
{
 "PublicIp": "34.233.6.60", 
 "Domain": "vpc", 
 "AllocationId": "eipalloc-56683465"
}

//create NAT-GW on 1^(st) public subnet (subnet-d83a4b82
//also assign EIP eipalloc-56683465
$ aws ec2 create-nat-gateway --subnet-id subnet-d83a4b82 --allocation-id eipalloc-56683465
{
 "NatGateway": {
 "NatGatewayAddresses": [
 {
 "AllocationId": "eipalloc-56683465"
 }
 ], 
 "VpcId": "vpc-66eda61f", 
 "State": "pending", 
 "NatGatewayId": "nat-084ff8ba1edd54bf4", 
 "SubnetId": "subnet-d83a4b82", 
 "CreateTime": "2017-08-13T21:07:34.000Z"
 }
}  
```

与 IGW 不同，AWS 会对弹性 IP 和 NAT-GW 收取额外的每小时费用。因此，如果希望节省成本，只有在访问互联网时才启动 NAT-GW。

创建 NAT-GW 需要几分钟，一旦 NAT-GW 创建完成，更新指向 NAT-GW 的私有子网路由表，然后任何 EC2 实例都能访问互联网，但由于私有子网上没有公共 IP 地址，因此无法从公共互联网访问私有子网的 EC2 实例。

在以下示例中，更新第二个子网的路由表，将 NAT-GW 指定为默认网关：

```
//as same as public route, need to create a route table first
$ aws ec2 create-route-table --vpc-id vpc-66eda61f
{
 "RouteTable": {
 "Associations": [], 
 "RouteTableId": "rtb-cc4cafb7", 
 "VpcId": "vpc-66eda61f", 
 "PropagatingVgws": [], 
 "Tags": [], 
 "Routes": [
 {
 "GatewayId": "local", 
 "DestinationCidrBlock": "10.0.0.0/16", 
 "State": "active", 
 "Origin": "CreateRouteTable"
 }
 ]
 }
}

//then assign default gateway as NAT-GW
$ aws ec2 create-route --route-table-id rtb-cc4cafb7 --nat-gateway-id nat-084ff8ba1edd54bf4 --destination-cidr-block 0.0.0.0/0
{
 "Return": true
}

//finally update 2^(nd) subnet that use this routing table
$ aws ec2 associate-route-table --route-table-id rtb-cc4cafb7 --subnet-id subnet-62758c06
{
 "AssociationId": "rtbassoc-2760ce5d"
}
```

总的来说，已经配置了两个子网，一个是公共子网，一个是私有子网。每个子网都有一个默认路由，使用 IGW 和 NAT-GW，如下所示。请注意，ID 会有所不同，因为 AWS 会分配唯一标识符：

| **子网类型** | **CIDR 块** | **子网 ID** | **路由表 ID** | **默认网关** | **EC2 启动时分配公共 IP** |
| --- | --- | --- | --- | --- | --- |
| 公共 | 10.0.1.0/24 | `subnet-d83a4b82` | `rtb-fb41a280` | `igw-c3a695a5` (IGW) | 是 |
| 私有 | 10.0.2.0/24 | `subnet-62758c06` | `rtb-cc4cafb7` | `nat-084ff8ba1edd54bf4` (NAT-GW) | 否（默认） |

从技术上讲，您仍然可以为私有子网的 EC2 实例分配公共 IP，但是没有通往互联网的默认网关（IGW）。因此，公共 IP 将被浪费，绝对无法从互联网获得连接。

现在，如果在公共子网上启动 EC2 实例，它将成为公共面向的，因此可以从该子网提供应用程序。

另一方面，如果在私有子网上启动 EC2 实例，它仍然可以通过 NAT-GW 访问互联网，但无法从互联网访问。但是，它仍然可以从公共子网的 EC2 实例访问。因此，您可以部署诸如数据库、中间件和监控工具之类的内部服务。

# 安全组

一旦 VPC 和相关的网关/路由子网准备就绪，您可以创建 EC2 实例。然而，至少需要事先创建一个访问控制，这就是所谓的**安全组**。它可以定义一个防火墙规则，即入站（传入网络访问）和出站（传出网络访问）。

在下面的例子中，创建了一个安全组和一个规则，允许来自您机器的 IP 地址的公共子网主机的 ssh，以及全球范围内开放 HTTP（80/tcp）：

当您为公共子网定义安全组时，强烈建议由安全专家审查。因为一旦您将 EC2 实例部署到公共子网上，它就有了一个公共 IP 地址，然后包括黑客和机器人在内的所有人都能直接访问您的实例。

```

//create one security group for public subnet host on vpc-66eda61f
$ aws ec2 create-security-group --vpc-id vpc-66eda61f --group-name public --description "public facing host"
{
 "GroupId": "sg-7d429f0d"
}

//check your machine's public IP (if not sure, use 0.0.0.0/0 as temporary)
$ curl ifconfig.co
107.196.102.199

//public facing machine allows ssh only from your machine
$ aws ec2 authorize-security-group-ingress --group-id sg-7d429f0d --protocol tcp --port 22 --cidr 107.196.102.199/32

//public facing machine allow HTTP access from any host (0.0.0.0/0)
$ aws ec2 authorize-security-group-ingress --group-id sg-d173aea1 --protocol tcp --port 80 --cidr 0.0.0.0/0  
```

接下来，为私有子网主机创建一个安全组，允许来自公共子网主机的 ssh。在这种情况下，指定公共子网安全组 ID（`sg-7d429f0d`）而不是 CIDR 块是方便的：

```
//create security group for private subnet
$ aws ec2 create-security-group --vpc-id vpc-66eda61f --group-name private --description "private subnet host"
{
 "GroupId": "sg-d173aea1"
}

//private subnet allows ssh only from ssh bastion host security group
//it also allows HTTP (80/TCP) from public subnet security group
$ aws ec2 authorize-security-group-ingress --group-id sg-d173aea1 --protocol tcp --port 22 --source-group sg-7d429f0d

//private subnet allows HTTP access from public subnet security group too
$ aws ec2 authorize-security-group-ingress --group-id sg-d173aea1 --protocol tcp --port 80 --source-group sg-7d429f0d
```

总的来说，以下是已创建的两个安全组：

| **名称** | **安全组 ID** | **允许 ssh（22/TCP）** | **允许 HTTP（80/TCP）** |
| --- | --- | --- | --- |
| 公共 | `sg-7d429f0d` | 您的机器（`107.196.102.199`） | `0.0.0.0/0` |
| 私有 | `sg-d173aea1` | 公共 sg（`sg-7d429f0d`） | 公共 sg（`sg-7d429f0d`） |

# EC2 和 EBS

EC2 是 AWS 中的一个重要服务，您可以在您的 VPC 上启动一个 VM。根据硬件规格（CPU、内存和网络），AWS 上有几种类型的 EC2 实例可用。当您启动一个 EC2 实例时，您需要指定 VPC、子网、安全组和 ssh 密钥对。因此，所有这些都必须事先创建。

由于之前的例子，唯一的最后一步是 ssh 密钥对。让我们创建一个 ssh 密钥对：

```
//create keypair (internal_rsa, internal_rsa.pub)
$ ssh-keygen 
Generating public/private rsa key pair.
Enter file in which to save the key (/Users/saito/.ssh/id_rsa): /tmp/internal_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /tmp/internal_rsa.
Your public key has been saved in /tmp/internal_rsa.pub.

//register internal_rsa.pub key to AWS
$ aws ec2 import-key-pair --key-name=internal --public-key-material "`cat /tmp/internal_rsa.pub`"
{
 "KeyName": "internal", 
   "KeyFingerprint":  
 "18:e7:86:d7:89:15:5d:3b:bc:bd:5f:b4:d5:1c:83:81"
} 

//launch public facing host, using Amazon Linux on us-east-1 (ami-a4c7edb2)
$ aws ec2 run-instances --image-id ami-a4c7edb2 --instance-type t2.nano --key-name internal --security-group-ids sg-7d429f0d --subnet-id subnet-d83a4b82

//launch private subnet host
$ aws ec2 run-instances --image-id ami-a4c7edb2 --instance-type t2.nano --key-name internal --security-group-ids sg-d173aea1 --subnet-id subnet-62758c06  
```

几分钟后，在 AWS Web 控制台上检查 EC2 实例的状态；它显示一个具有公共 IP 地址的公共子网主机。另一方面，私有子网主机没有公共 IP 地址：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00120.jpeg)

```
//add private keys to ssh-agent
$ ssh-add -K /tmp/internal_rsa
Identity added: /tmp/internal_rsa (/tmp/internal_rsa)
$ ssh-add -l
2048 SHA256:AMkdBxkVZxPz0gBTzLPCwEtaDqou4XyiRzTTG4vtqTo /tmp/internal_rsa (RSA)

//ssh to the public subnet host with -A (forward ssh-agent) option
$ ssh -A ec2-user@54.227.197.56
The authenticity of host '54.227.197.56 (54.227.197.56)' can't be established.
ECDSA key fingerprint is SHA256:ocI7Q60RB+k2qbU90H09Or0FhvBEydVI2wXIDzOacaE.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '54.227.197.56' (ECDSA) to the list of known hosts.

           __|  __|_  )
           _|  (     /   Amazon Linux AMI
          ___|\___|___|

    https://aws.amazon.com/amazon-linux-ami/2017.03-release-notes/
    2 package(s) needed for security, out of 6 available
    Run "sudo yum update" to apply all updates.
```

现在您位于公共子网主机（`54.227.197.56`），但是这台主机也有一个内部（私有）IP 地址，因为这台主机部署在 10.0.1.0/24 子网（`subnet-d83a4b82`）中，因此私有地址范围必须是`10.0.1.1` - `10.0.1.254`：

```
$ ifconfig eth0
eth0      Link encap:Ethernet  HWaddr 0E:8D:38:BE:52:34 
          inet addr:10.0.1.24  Bcast:10.0.1.255      
          Mask:255.255.255.0
```

让我们在公共主机上安装 nginx web 服务器如下：

```
$ sudo yum -y -q install nginx
$ sudo /etc/init.d/nginx start
Starting nginx:                                            [  OK  ]
```

然后，回到您的机器上，检查`54.227.197.56`的网站：

```
$ exit
logout
Connection to 52.227.197.56 closed.

//from your machine, access to nginx
$ curl -I 54.227.197.56
HTTP/1.1 200 OK
Server: nginx/1.10.3
...
Accept-Ranges: bytes  
```

此外，在同一个 VPC 内，其他可用区域也是可达的，因此您可以从这个主机 ssh 到私有子网主机（`10.0.2.98`）。请注意，我们使用了`ssh -A`选项，它转发了一个 ssh-agent，因此不需要创建`~/.ssh/id_rsa`文件：

```
[ec2-user@ip-10-0-1-24 ~]$ ssh 10.0.2.98
The authenticity of host '10.0.2.98 (10.0.2.98)' can't be established.
ECDSA key fingerprint is 1a:37:c3:c1:e3:8f:24:56:6f:90:8f:4a:ff:5e:79:0b.
Are you sure you want to continue connecting (yes/no)? yes
    Warning: Permanently added '10.0.2.98' (ECDSA) to the list of known hosts.

           __|  __|_  )
           _|  (     /   Amazon Linux AMI
          ___|\___|___|

https://aws.amazon.com/amazon-linux-ami/2017.03-release-notes/
2 package(s) needed for security, out of 6 available
Run "sudo yum update" to apply all updates.
[ec2-user@ip-10-0-2-98 ~]$ 
```

除了 EC2，还有一个重要的功能，即磁盘管理。AWS 提供了一个灵活的磁盘管理服务，称为**弹性块存储**（**EBS**）。您可以创建一个或多个持久数据存储，可以附加到 EC2 实例上。从 EC2 的角度来看，EBS 是 HDD/SSD 之一。一旦终止（删除）了 EC2 实例，EBS 及其内容可能会保留，然后重新附加到另一个 EC2 实例上。

在下面的例子中，创建了一个具有 40GB 容量的卷，并附加到一个公共子网主机（实例 ID`i-0db344916c90fae61`）：

```
//create 40GB disk at us-east-1a (as same as EC2 host instance)
$ aws ec2 create-volume --availability-zone us-east-1a --size 40 --volume-type standard
{
    "AvailabilityZone": "us-east-1a", 
    "Encrypted": false, 
    "VolumeType": "standard", 
    "VolumeId": "vol-005032342495918d6", 
    "State": "creating", 
    "SnapshotId": "", 
    "CreateTime": "2017-08-16T05:41:53.271Z", 
    "Size": 40
}

//attach to public subnet host as /dev/xvdh
$ aws ec2 attach-volume --device xvdh --instance-id i-0db344916c90fae61 --volume-id vol-005032342495918d6
{
    "AttachTime": "2017-08-16T05:47:07.598Z", 
    "InstanceId": "i-0db344916c90fae61", 
    "VolumeId": "vol-005032342495918d6", 
    "State": "attaching", 
    "Device": "xvdh"
}
```

将 EBS 卷附加到 EC2 实例后，Linux 内核会识别`/dev/xvdh`，然后您需要对该设备进行分区，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00121.jpeg)

在这个例子中，我们将一个分区命名为`/dev/xvdh1`，所以你可以在`/dev/xvdh1`上创建一个`ext4`格式的文件系统，然后可以挂载到 EC2 实例上使用这个设备：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00122.jpeg)

卸载卷后，您可以随时分离该卷，然后在需要时重新附加它：

```
//detach volume
$ aws ec2 detach-volume --volume-id vol-005032342495918d6
{
    "AttachTime": "2017-08-16T06:03:45.000Z", 
    "InstanceId": "i-0db344916c90fae61", 
    "VolumeId": "vol-005032342495918d6", 
    "State": "detaching", 
    "Device": "xvdh"
}
```

# Route 53

AWS 还提供了一个托管 DNS 服务，称为**Route 53**。Route 53 允许您管理自己的域名和关联的 FQDN 到 IP 地址。例如，如果您想要一个域名`k8s-devops.net`，您可以通过 Route 53 订购注册您的 DNS 域名。

以下屏幕截图显示订购域名`k8s-devops.net`；可能需要几个小时才能完成注册：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00123.jpeg)

注册完成后，您可能会收到来自 AWS 的通知电子邮件，然后您可以通过 AWS 命令行或 Web 控制台控制这个域名。让我们添加一个记录（FQDN 到 IP 地址），将`public.k8s-devops.net`与公共面向的 EC2 主机公共 IP 地址`54.227.197.56`关联起来。为此，获取托管区域 ID 如下：

```
$ aws route53 list-hosted-zones | grep Id
"Id": "/hostedzone/Z1CTVYM9SLEAN8",   
```

现在您得到了一个托管区域 ID，即`/hostedzone/Z1CTVYM9SLEAN8`，所以让我们准备一个 JSON 文件来更新 DNS 记录如下：

```
//create JSON file
$ cat /tmp/add-record.json 
{
 "Comment": "add public subnet host",
  "Changes": [
   {
     "Action": "UPSERT",
     "ResourceRecordSet": {
       "Name": "public.k8s-devops.net",
       "Type": "A",
       "TTL": 300,
       "ResourceRecords": [
         {
          "Value": "54.227.197.56"
         }
       ]
     }
   }
  ]
}

//submit to Route53
$ aws route53 change-resource-record-sets --hosted-zone-id /hostedzone/Z1CTVYM9SLEAN8 --change-batch file:///tmp/add-record.json 

//a few minutes later, check whether A record is created or not
$ dig public.k8s-devops.net

; <<>> DiG 9.8.3-P1 <<>> public.k8s-devops.net
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18609
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;public.k8s-devops.net.       IN    A

;; ANSWER SECTION:
public.k8s-devops.net.  300   IN    A     54.227.197.56  
```

看起来不错，现在通过 DNS 名称`public.k8s-devops.net`访问 nginx：

```
$ curl -I public.k8s-devops.net
HTTP/1.1 200 OK
Server: nginx/1.10.3
...  
```

# ELB

AWS 提供了一个强大的基于软件的负载均衡器，称为**弹性负载均衡器**（**ELB**）。它允许您将网络流量负载均衡到一个或多个 EC2 实例。此外，ELB 可以卸载 SSL/TLS 加密/解密，并且还支持多可用区。

在以下示例中，创建了一个 ELB，并将其与公共子网主机 nginx（80/TCP）关联。因为 ELB 还需要一个安全组，所以首先为 ELB 创建一个新的安全组：

```
$ aws ec2 create-security-group --vpc-id vpc-66eda61f --group-name elb --description "elb sg"
{
  "GroupId": "sg-51d77921"
} 
$ aws ec2 authorize-security-group-ingress --group-id sg-51d77921 --protocol tcp --port 80 --cidr 0.0.0.0/0

$ aws elb create-load-balancer --load-balancer-name public-elb --listeners Protocol=HTTP,LoadBalancerPort=80,InstanceProtocol=HTTP,InstancePort=80 --subnets subnet-d83a4b82 --security-groups sg-51d77921
{
   "DNSName": "public-elb-1779693260.us-east- 
    1.elb.amazonaws.com"
}

$ aws elb register-instances-with-load-balancer --load-balancer-name public-elb --instances i-0db344916c90fae61

$ curl -I public-elb-1779693260.us-east-1.elb.amazonaws.com
HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Length: 3770
Content-Type: text/html
...  
```

让我们更新 Route 53 DNS 记录`public.k8s-devops.net`，指向 ELB。在这种情况下，ELB 已经有一个`A`记录，因此使用指向 ELB FQDN 的`CNAME`（别名）：

```
$ cat change-to-elb.json 
{
 "Comment": "use CNAME to pointing to ELB",
  "Changes": [
    {
      "Action": "DELETE",
      "ResourceRecordSet": {
        "Name": "public.k8s-devops.net",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [
          {
           "Value": "52.86.166.223"
          }
        ]
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "public.k8s-devops.net",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [
          {
           "Value": "public-elb-1779693260.us-east-           
1.elb.amazonaws.com"
          }
        ]
      }
 }
 ]
}

$ dig public.k8s-devops.net

; <<>> DiG 9.8.3-P1 <<>> public.k8s-devops.net
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10278
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;public.k8s-devops.net.       IN    A

;; ANSWER SECTION:
public.k8s-devops.net.  300   IN    CNAME public-elb-1779693260.us-east-1.elb.amazonaws.com.
public-elb-1779693260.us-east-1.elb.amazonaws.com. 60 IN A 52.200.46.81
public-elb-1779693260.us-east-1.elb.amazonaws.com. 60 IN A 52.73.172.171

;; Query time: 77 msec
;; SERVER: 10.0.0.1#53(10.0.0.1)
;; WHEN: Wed Aug 16 22:21:33 2017
;; MSG SIZE  rcvd: 134

$ curl -I public.k8s-devops.net
HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Length: 3770
Content-Type: text/html
...  
```

# S3

AWS 提供了一个有用的对象数据存储服务，称为**简单存储服务**（**S3**）。它不像 EBS，没有 EC2 实例可以挂载为文件系统。相反，使用 AWS API 将文件传输到 S3。因此，AWS 可以实现可用性（99.999999999%），并且多个实例可以同时访问它。它适合存储非吞吐量和随机访问敏感的文件，如配置文件、日志文件和数据文件。

在以下示例中，从您的计算机上传文件到 AWS S3：

```
//create S3 bucket "k8s-devops"
$ aws s3 mb s3://k8s-devops
make_bucket: k8s-devops

//copy files to S3 bucket
$ aws s3 cp add-record.json s3://k8s-devops/
upload: ./add-record.json to s3://k8s-devops/add-record.json 
$ aws s3 cp change-to-elb.json s3://k8s-devops/
upload: ./change-to-elb.json to s3://k8s-devops/change-to-elb.json 

//check files on S3 bucket
$ aws s3 ls s3://k8s-devops/
2017-08-17 20:00:21        319 add-record.json
2017-08-17 20:00:28        623 change-to-elb.json  
```

总的来说，我们已经讨论了如何配置围绕 VPC 的 AWS 组件。以下图表显示了一个主要组件和关系：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00124.jpeg)

# 在 AWS 上设置 Kubernetes

我们已经讨论了一些 AWS 组件，这些组件非常容易设置网络、虚拟机和存储。因此，在 AWS 上设置 Kubernetes 有多种方式，例如 kubeadm（[`github.com/kubernetes/kubeadm`](https://github.com/kubernetes/kubeadm)）、kops（[`github.com/kubernetes/kops`](https://github.com/kubernetes/kops)）和 kubespray（[`github.com/kubernetes-incubator/kubespray`](https://github.com/kubernetes-incubator/kubespray)）。在 AWS 上配置 Kubernetes 的推荐方式之一是使用 kops，这是一个生产级的设置工具，并支持大量配置。在本章中，我们将使用 kops 在 AWS 上配置 Kubernetes。请注意，kops 代表 Kubernetes 操作。

# 安装 kops

首先，您需要将 kops 安装到您的机器上。Linux 和 macOS 都受支持。Kops 是一个单一的二进制文件，所以只需将`kops`命令复制到`/usr/local/bin`中，如推荐的那样。之后，为 kops 创建一个处理 kops 操作的 IAM 用户和角色。有关详细信息，请参阅官方文档（[`github.com/kubernetes/kops/blob/master/docs/aws.md`](https://github.com/kubernetes/kops/blob/master/docs/aws.md)）。

# 运行 kops

Kops 需要一个存储配置和状态的 S3 存储桶。此外，使用 Route 53 来注册 Kubernetes API 服务器名称和 etcd 服务器名称到域名系统。因此，在前一节中创建的 S3 存储桶和 Route 53。

Kops 支持各种配置，例如部署到公共子网、私有子网，使用不同类型和数量的 EC2 实例，高可用性和叠加网络。让我们使用与前一节中网络类似的配置来配置 Kubernetes，如下所示：

Kops 有一个选项可以重用现有的 VPC 和子网。但是，它的行为很棘手，可能会根据设置遇到一些问题；建议使用 kops 创建一个新的 VPC。有关详细信息，您可以在[`github.com/kubernetes/kops/blob/master/docs/run_in_existing_vpc.md`](https://github.com/kubernetes/kops/blob/master/docs/run_in_existing_vpc.md)找到一份文档。

| **参数** | **值** | **意义** |
| --- | --- | --- |
| - `--name` | `my-cluster.k8s-devops.net` | 在`k8s-devops.net`域下设置`my-cluster` |
| - `--state` | `s3://k8s-devops` | 使用 k8s-devops S3 存储桶 |
| - `--zones` | `us-east-1a` | 部署在`us-east-1a`可用区 |
| - `--cloud` | `aws` | 使用 AWS 作为云提供商 |
| - `--network-cidr` | `10.0.0.0/16` | 使用 CIDR 10.0.0.0/16 创建新的 VPC |
| - `--master-size` | `t2.large` | 为主节点使用 EC2 `t2.large`实例 |
| - `--node-size` | `t2.medium` | 为节点使用 EC2 `t2.medium`实例 |
| - `--node-count` | `2` | 设置两个节点 |
| - `--networking` | `calico` | 使用 Calico 进行叠加网络 |
| - `--topology` | `private` | 设置公共和私有子网，并将主节点和节点部署到私有子网 |
| - `--ssh-puglic-key` | `/tmp/internal_rsa.pub` | 为堡垒主机使用`/tmp/internal_rsa.pub` |
| - `--bastion` |  | 在公共子网上创建 ssh 堡垒服务器 |
| - `--yes` |  | 立即执行 |

因此，运行以下命令来运行 kops：

```
$ kops create cluster --name my-cluster.k8s-devops.net --state=s3://k8s-devops --zones us-east-1a --cloud aws --network-cidr 10.0.0.0/16 --master-size t2.large --node-size t2.medium --node-count 2 --networking calico --topology private --ssh-public-key /tmp/internal_rsa.pub --bastion --yes

I0818 20:43:15.022735   11372 create_cluster.go:845] Using SSH public key: /tmp/internal_rsa.pub
...
I0818 20:45:32.585246   11372 executor.go:91] Tasks: 78 done / 78 total; 0 can run
I0818 20:45:32.587067   11372 dns.go:152] Pre-creating DNS records
I0818 20:45:35.266425   11372 update_cluster.go:247] Exporting kubecfg for cluster
Kops has set your kubectl context to my-cluster.k8s-devops.net

Cluster is starting.  It should be ready in a few minutes.  
```

在看到上述消息后，完全完成可能需要大约 5 到 10 分钟。这是因为它需要我们创建 VPC、子网和 NAT-GW，启动 EC2，然后安装 Kubernetes 主节点和节点，启动 ELB，然后更新 Route 53 如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00125.jpeg)

完成后，`kops`会更新您机器上的`~/.kube/config`，指向您的 Kubernetes API 服务器。Kops 会创建一个 ELB，并在 Route 53 上设置相应的 FQDN 记录为`https://api.<your-cluster-name>.<your-domain-name>/`，因此，您可以直接从您的机器上运行`kubectl`命令来查看节点列表，如下所示：

```
$ kubectl get nodes
NAME                          STATUS         AGE       VERSION
ip-10-0-36-157.ec2.internal   Ready,master   8m        v1.7.0
ip-10-0-42-97.ec2.internal    Ready,node     6m        v1.7.0
ip-10-0-42-170.ec2.internal   Ready,node     6m        v1.7.0

```

太棒了！从头开始在 AWS 上设置 AWS 基础设施和 Kubernetes 只花了几分钟。现在您可以通过`kubectl`命令部署 pod。但是您可能想要 ssh 到 master/node 上查看发生了什么。

然而，出于安全原因，如果您指定了`--topology private`，您只能 ssh 到堡垒主机。然后使用私有 IP 地址 ssh 到 master/node 主机。这类似于前一节中 ssh 到公共子网主机，然后使用 ssh-agent（`-A`选项）ssh 到私有子网主机。

在以下示例中，我们 ssh 到堡垒主机（kops 创建 Route 53 条目为`bastion.my-cluster.k8s-devops.net`），然后 ssh 到 master（`10.0.36.157`）：

>![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00126.jpeg)

# Kubernetes 云服务提供商

在使用 kops 设置 Kubernetes 时，它还将 Kubernetes 云服务提供商配置为 AWS。这意味着当您使用 LoadBalancer 的 Kubernetes 服务时，它将使用 ELB。它还将**弹性块存储**（**EBS**）作为其`StorageClass`。

# L4 负载均衡器

当您将 Kubernetes 服务公开到外部世界时，使用 ELB 更有意义。将服务类型设置为 LoadBalancer 将调用 ELB 创建并将其与节点关联：

```
$ cat grafana.yml 
apiVersion: apps/v1beta1
kind: Deployment
metadata:
 name: grafana
spec:
 replicas: 1
 template:
 metadata:
 labels:
 run: grafana
 spec:
 containers:
 - image: grafana/grafana
 name: grafana
 ports:
 - containerPort: 3000
---
apiVersion: v1
kind: Service
metadata:
 name: grafana
spec:
 ports:
 - port: 80
 targetPort: 3000
 type: LoadBalancer
 selector:
 run: grafana

$ kubectl create -f grafana.yml 
deployment "grafana" created
service "grafana" created

$ kubectl get service
NAME         CLUSTER-IP       EXTERNAL-IP        PORT(S)        AGE
grafana      100.65.232.120   a5d97c8ef8575...   80:32111/TCP   11s
kubernetes   100.64.0.1       <none>             443/TCP        13m

$ aws elb describe-load-balancers | grep a5d97c8ef8575 | grep DNSName
 "DNSName": "a5d97c8ef857511e7a6100edf846f38a-1490901085.us-east-1.elb.amazonaws.com",  
```

如您所见，ELB 已经自动创建，DNS 为`a5d97c8ef857511e7a6100edf846f38a-1490901085.us-east-1.elb.amazonaws.com`，因此现在您可以在`http://a5d97c8ef857511e7a6100edf846f38a-1490901085.us-east-1.elb.amazonaws.com`访问 Grafana。

您可以使用`awscli`来更新 Route 53，分配一个`CNAME`，比如`grafana.k8s-devops.net`。另外，Kubernetes 的孵化项目`external-dns`（[`github.com/kubernetes-incubator/external-dns)`](https://github.com/kubernetes-incubator/external-dns)）可以自动更新 Route 53 在这种情况下。![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00127.jpeg)

# L7 负载均衡器（入口）

截至 kops 版本 1.7.0，它尚未默认设置 ingress 控制器。然而，kops 提供了一些插件（[`github.com/kubernetes/kops/tree/master/addons`](https://github.com/kubernetes/kops/tree/master/addons)）来扩展 Kubernetes 的功能。其中一个插件 ingress-nginx（[`github.com/kubernetes/kops/tree/master/addons/ingress-nginx`](https://github.com/kubernetes/kops/tree/master/addons/ingress-nginx)）使用 AWS ELB 和 nginx 的组合来实现 Kubernetes 的 ingress 控制器。

为了安装`ingress-nginx`插件，输入以下命令来设置 ingress 控制器：

```
$ kubectl create -f https://raw.githubusercontent.com/kubernetes/kops/master/addons/ingress-nginx/v1.6.0.yaml
namespace "kube-ingress" created
serviceaccount "nginx-ingress-controller" created
clusterrole "nginx-ingress-controller" created
role "nginx-ingress-controller" created
clusterrolebinding "nginx-ingress-controller" created
rolebinding "nginx-ingress-controller" created
service "nginx-default-backend" created
deployment "nginx-default-backend" created
configmap "ingress-nginx" created
service "ingress-nginx" created
deployment "ingress-nginx" created
```

之后，使用 NodePort 服务部署 nginx 和 echoserver 如下：

```
$ kubectl run nginx --image=nginx --port=80
deployment "nginx" created
$ 
$ kubectl expose deployment nginx --target-port=80 --type=NodePort
service "nginx" exposed
$ 
$ kubectl run echoserver --image=gcr.io/google_containers/echoserver:1.4 --port=8080
deployment "echoserver" created
$ 
$ kubectl expose deployment echoserver --target-port=8080 --type=NodePort
service "echoserver" exposed

// URL "/" point to nginx, "/echo" to echoserver
$ cat nginx-echoserver-ingress.yaml 
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
 name: nginx-echoserver-ingress
spec:
 rules:
 - http:
 paths:
 - path: /
 backend:
 serviceName: nginx
 servicePort: 80
 - path: /echo
 backend:
 serviceName: echoserver
 servicePort: 8080

//check ingress
$ kubectl get ing -o wide
NAME                       HOSTS     ADDRESS                                                                 PORTS     AGE
nginx-echoserver-ingress   *         a1705ab488dfa11e7a89e0eb0952587e-28724883.us-east-1.elb.amazonaws.com   80        1m 
```

几分钟后，ingress 控制器将 nginx 服务和 echoserver 服务与 ELB 关联起来。当您使用 URI "`/`"访问 ELB 服务器时，它会显示 nginx 屏幕如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00128.jpeg)

另一方面，如果你访问相同的 ELB，但使用 URI "`/echo`"，它会显示 echoserver 如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00129.jpeg)

与标准的 Kubernetes 负载均衡器服务相比，一个负载均衡器服务会消耗一个 ELB。另一方面，使用 nginx-ingress 插件，它可以将多个 Kubernetes NodePort 服务整合到单个 ELB 上。这将有助于更轻松地构建您的 RESTful 服务。

# StorageClass

正如我们在第四章中讨论的那样，有一个`StorageClass`可以动态分配持久卷。Kops 将 provisioner 设置为`aws-ebs`，使用 EBS：

```
$ kubectl get storageclass
NAME            TYPE
default         kubernetes.io/aws-ebs 
gp2 (default)   kubernetes.io/aws-ebs 

$ cat pvc-aws.yml 
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
 name: pvc-aws-1
spec:
 storageClassName: "default"
 accessModes:
 - ReadWriteOnce
 resources:
 requests:
 storage: 10Gi

$ kubectl create -f pvc-aws.yml 
persistentvolumeclaim "pvc-aws-1" created

$ kubectl get pv
NAME                                       CAPACITY   ACCESSMODES   RECLAIMPOLICY   STATUS    CLAIM               STORAGECLASS   REASON    AGE
pvc-94957090-84a8-11e7-9974-0ea8dc53a244   10Gi       RWO           Delete          Bound     default/pvc-aws-1   default                  3s  
```

这将自动创建 EBS 卷如下：

```
$ aws ec2 describe-volumes --filter Name=tag-value,Values="pvc-51cdf520-8576-11e7-a610-0edf846f38a6"
{
 "Volumes": [
    {
      "AvailabilityZone": "us-east-1a", 
    "Attachments": [], 
      "Tags": [
       {
...
     ], 
    "Encrypted": false, 
    "VolumeType": "gp2", 
    "VolumeId": "vol-052621c39546f8096", 
    "State": "available", 
    "Iops": 100, 
    "SnapshotId": "", 
    "CreateTime": "2017-08-20T07:08:08.773Z", 
       "Size": 10
       }
     ]
   }
```

总的来说，AWS 的 Kubernetes 云提供程序被用来将 ELB 映射到 Kubernetes 服务，还有将 EBS 映射到 Kubernetes 持久卷。对于 Kubernetes 来说，使用 AWS 是一个很大的好处，因为不需要预先分配或购买物理负载均衡器或存储，只需按需付费；这为您的业务创造了灵活性和可扩展性。

# 通过 kops 维护 Kubernetes 集群

当您需要更改 Kubernetes 配置，比如节点数量甚至 EC2 实例类型，kops 可以支持这种用例。例如，如果您想将 Kubernetes 节点实例类型从`t2.medium`更改为`t2.micro`，并且由于成本节约而将数量从 2 减少到 1，您需要修改 kops 节点实例组（`ig`）设置如下：

```
$ kops edit ig nodes --name my-cluster.k8s-devops.net --state=s3://k8s-devops   
```

它启动了 vi 编辑器，您可以更改 kops 节点实例组的设置如下：

```
apiVersion: kops/v1alpha2
kind: InstanceGroup
metadata:
 creationTimestamp: 2017-08-20T06:43:45Z
 labels:
 kops.k8s.io/cluster: my-cluster.k8s-devops.net
 name: nodes
spec:
 image: kope.io/k8s-1.6-debian-jessie-amd64-hvm-ebs-2017- 
 05-02
 machineType: t2.medium
 maxSize: 2
 minSize: 2
 role: Node
 subnets:
 - us-east-1a  
```

在这种情况下，将`machineType`更改为`t2.small`，将`maxSize`/`minSize`更改为`1`，然后保存。之后，运行`kops update`命令应用设置：

```
$ kops update cluster --name my-cluster.k8s-devops.net --state=s3://k8s-devops --yes 

I0820 00:57:17.900874    2837 executor.go:91] Tasks: 0 done / 94 total; 38 can run
I0820 00:57:19.064626    2837 executor.go:91] Tasks: 38 done / 94 total; 20 can run
...
Kops has set your kubectl context to my-cluster.k8s-devops.net
Cluster changes have been applied to the cloud.

Changes may require instances to restart: kops rolling-update cluster  
```

正如您在前面的消息中看到的，您需要运行`kops rolling-update cluster`命令来反映现有实例。将现有实例替换为新实例可能需要几分钟：

```
$ kops rolling-update cluster --name my-cluster.k8s-devops.net --state=s3://k8s-devops --yes
NAME              STATUS     NEEDUPDATE  READY MIN   MAX   NODES
bastions          Ready       0           1     1     1     0
master-us-east-1a Ready       0           1     1     1     1
nodes             NeedsUpdate 1           0     1     1     1
I0820 01:00:01.086564    2844 instancegroups.go:350] Stopping instance "i-07e55394ef3a09064", node "ip-10-0-40-170.ec2.internal", in AWS ASG "nodes.my-cluster.k8s-devops.net".  
```

现在，Kubernetes 节点实例已从`2`减少到`1`，如下所示：

```
$ kubectl get nodes
NAME                          STATUS         AGE       VERSION
ip-10-0-36-157.ec2.internal   Ready,master   1h        v1.7.0
ip-10-0-58-135.ec2.internal   Ready,node     34s       v1.7.0  
```

# 总结

在本章中，我们已经讨论了公共云。AWS 是最流行的公共云服务，它提供 API 以编程方式控制 AWS 基础设施。我们可以轻松实现自动化和基础架构即代码。特别是，kops 使我们能够从头开始快速设置 AWS 和 Kubernetes。Kubernetes 和 kops 的开发都非常活跃。请继续监视这些项目，它们将在不久的将来具有更多功能和配置。

下一章将介绍**Google Cloud Platform**（**GCP**），这是另一个流行的公共云服务。**Google Container Engine**（**GKE**）是托管的 Kubernetes 服务，使使用 Kubernetes 变得更加容易。


# 第十章：GCP 上的 Kubernetes

Google Cloud Platform（GCP）在公共云行业中越来越受欢迎，由 Google 提供。GCP 与 AWS 具有类似的概念，如 VPC、计算引擎、持久磁盘、负载均衡和一些托管服务。在本章中，您将了解 GCP 以及如何通过以下主题在 GCP 上设置 Kubernetes：

+   理解 GCP

+   使用和理解 GCP 组件

+   使用 Google Container Engine（GKE），托管的 Kubernetes 服务

# GCP 简介

GCP 于 2011 年正式推出。但与 AWS 不同的是，GCP 最初提供了 PaaS（平台即服务）。因此，您可以直接部署您的应用程序，而不是启动虚拟机。之后，不断增强功能，支持各种服务。

对于 Kubernetes 用户来说，最重要的服务是 GKE，这是一个托管的 Kubernetes 服务。因此，您可以从 Kubernetes 的安装、升级和管理中得到一些缓解。它采用按使用 Kubernetes 集群的方式付费。GKE 也是一个非常活跃的服务，不断及时提供新版本的 Kubernetes，并为 Kubernetes 提供新功能和管理工具。

让我们看看 GCP 提供了什么样的基础设施和服务，然后探索 GKE。

# GCP 组件

GCP 提供了 Web 控制台和命令行界面（CLI）。两者都很容易直接地控制 GCP 基础设施，但需要 Google 账户（如 Gmail）。一旦您拥有了 Google 账户，就可以转到 GCP 注册页面（[`cloud.google.com/free/`](https://cloud.google.com/free/)）来创建您的 GCP 账户。

如果您想通过 CLI 进行控制，您需要安装 Cloud SDK（[`cloud.google.com/sdk/gcloud/`](https://cloud.google.com/sdk/gcloud/)），这类似于 AWS CLI，您可以使用它来列出、创建、更新和删除 GCP 资源。安装 Cloud SDK 后，您需要使用以下命令将其配置到 GCP 账户：

```
$ gcloud init
```

# VPC

与 AWS 相比，GCP 中的 VPC 政策有很大不同。首先，您不需要为 VPC 设置 CIDR 前缀，换句话说，您不能为 VPC 设置 CIDR。相反，您只需向 VPC 添加一个或多个子网。因为子网总是带有特定的 CIDR 块，因此 GCP VPC 被识别为一组逻辑子网，VPC 内的子网可以相互通信。

请注意，GCP VPC 有两种模式，即**自动**或**自定义**。如果您选择自动模式，它将在每个区域创建一些具有预定义 CIDR 块的子网。例如，如果您输入以下命令：

```
$ gcloud compute networks create my-auto-network --mode auto
```

它将创建 11 个子网，如下面的屏幕截图所示（因为截至 2017 年 8 月，GCP 有 11 个区域）：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00130.jpeg)

自动模式 VPC 可能是一个很好的起点。但是，在自动模式下，您无法指定 CIDR 前缀，而且来自所有区域的 11 个子网可能无法满足您的用例。例如，如果您想通过 VPN 集成到您的本地数据中心，或者只想从特定区域创建子网。

在这种情况下，选择自定义模式 VPC，然后可以手动创建具有所需 CIDR 前缀的子网。输入以下命令以创建自定义模式 VPC：

```
//create custom mode VPC which is named my-custom-network
$ gcloud compute networks create my-custom-network --mode custom  
```

因为自定义模式 VPC 不会像下面的屏幕截图所示创建任何子网，让我们在这个自定义模式 VPC 上添加子网：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00131.jpeg)

# 子网

在 GCP 中，子网始终跨越区域内的多个区域（可用区）。换句话说，您无法像 AWS 一样在单个区域创建子网。创建子网时，您总是需要指定整个区域。

此外，与 AWS 不同（结合路由和 Internet 网关或 NAT 网关确定为公共或私有子网的重要概念），GCP 没有明显的公共和私有子网概念。这是因为 GCP 中的所有子网都有指向 Internet 网关的路由。

GCP 使用**网络标签**而不是子网级别的访问控制，以确保网络安全。这将在下一节中进行更详细的描述。

这可能会让网络管理员感到紧张，但是 GCP 最佳实践为您带来了更简化和可扩展的 VPC 管理，因为您可以随时添加子网以扩展整个网络块。

从技术上讲，您可以启动 VM 实例设置为 NAT 网关或 HTTP 代理，然后为指向 NAT/代理实例的私有子网创建自定义优先级路由，以实现类似 AWS 的私有子网。

有关详细信息，请参阅以下在线文档：

[`cloud.google.com/compute/docs/vpc/special-configurations`](https://cloud.google.com/compute/docs/vpc/special-configurations)

还有一件事，GCP VPC 的一个有趣且独特的概念是，您可以将不同的 CIDR 前缀网络块添加到单个 VPC 中。例如，如果您有自定义模式 VPC，然后添加以下三个子网：

+   `subnet-a` (`10.0.1.0/24`) 来自 `us-west1`

+   `subnet-b` (`172.16.1.0/24`) 来自 `us-east1`

+   `subnet-c` (`192.168.1.0/24`) 来自 `asia-northeast1`

以下命令将从三个不同的区域创建三个具有不同 CIDR 前缀的子网：

```
$ gcloud compute networks subnets create subnet-a --network=my-custom-network --range=10.0.1.0/24 --region=us-west1
$ gcloud compute networks subnets create subnet-b --network=my-custom-network --range=172.16.1.0/24 --region=us-east1
$ gcloud compute networks subnets create subnet-c --network=my-custom-network --range=192.168.1.0/24 --region=asia-northeast1  
```

结果将是以下 Web 控制台。如果您熟悉 AWS VPC，您将不相信这些 CIDR 前缀的组合在单个 VPC 中！这意味着，每当您需要扩展网络时，您可以随意分配另一个 CIDR 前缀以添加到 VPC 中。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00132.jpeg)

# 防火墙规则

正如之前提到的，GCP 防火墙规则对于实现网络安全非常重要。但是 GCP 防火墙比 AWS 的安全组（SG）更简单和灵活。例如，在 AWS 中，当您启动一个 EC2 实例时，您必须至少分配一个与 EC2 和 SG 紧密耦合的 SG。另一方面，在 GCP 中，您不能直接分配任何防火墙规则。相反，防火墙规则和 VM 实例是通过网络标签松散耦合的。因此，防火墙规则和 VM 实例之间没有直接关联。以下图表是 AWS 安全组和 GCP 防火墙规则之间的比较。EC2 需要安全组，另一方面，GCP VM 实例只需设置一个标签。这与相应的防火墙是否具有相同的标签无关。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00133.jpeg)

例如，根据以下命令为公共主机（使用网络标签`public`）和私有主机（使用网络标签`private`）创建防火墙规则：

```
//create ssh access for public host
$ gcloud compute firewall-rules create public-ssh --network=my-custom-network --allow="tcp:22" --source-ranges="0.0.0.0/0" --target-tags="public"

//create http access (80/tcp for public host)
$ gcloud compute firewall-rules create public-http --network=my-custom-network --allow="tcp:80" --source-ranges="0.0.0.0/0" --target-tags="public"

//create ssh access for private host (allow from host which has "public" tag)
$ gcloud compute firewall-rules create private-ssh --network=my-custom-network --allow="tcp:22" --source-tags="public" --target-tags="private"

//create icmp access for internal each other (allow from host which has either "public" or "private")
$ gcloud compute firewall-rules create internal-icmp --network=my-custom-network --allow="icmp" --source-tags="public,private"
```

它创建了四个防火墙规则，如下图所示。让我们创建 VM 实例，以使用`public`或`private`网络标签，看看它是如何工作的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00134.jpeg)

# VM 实例

GCP 中的 VM 实例与 AWS EC2 非常相似。您可以选择各种具有不同硬件配置的机器（实例）类型。以及 Linux 或基于 Windows 的 OS 镜像或您定制的 OS，您可以选择。

如在讨论防火墙规则时提到的，您可以指定零个或多个网络标签。标签不一定要事先创建。这意味着您可以首先使用网络标签启动 VM 实例，即使没有创建防火墙规则。这仍然是有效的，但在这种情况下不会应用防火墙规则。然后创建一个防火墙规则来具有网络标签。最终，防火墙规则将应用于 VM 实例。这就是为什么 VM 实例和防火墙规则松散耦合的原因，这为用户提供了灵活性。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00135.jpeg)

在启动 VM 实例之前，您需要首先创建一个 ssh 公钥，与 AWS EC2 相同。这样做的最简单方法是运行以下命令来创建和注册一个新密钥：

```
//this command create new ssh key pair
$ gcloud compute config-ssh

//key will be stored as ~/.ssh/google_compute_engine(.pub)
$ cd ~/.ssh
$ ls -l google_compute_engine*
-rw-------  1 saito  admin  1766 Aug 23 22:58 google_compute_engine
-rw-r--r--  1 saito  admin   417 Aug 23 22:58 google_compute_engine.pub  
```

现在让我们开始在 GCP 上启动一个 VM 实例。

在`subnet-a`和`subnet-b`上部署两个实例作为公共实例（使用`public`网络标签），然后在`subnet-a`上启动另一个实例作为私有实例（使用`private`网络标签）：

```
//create public instance ("public" tag) on subnet-a
$ gcloud compute instances create public-on-subnet-a --machine-type=f1-micro --network=my-custom-network --subnet=subnet-a --zone=us-west1-a --tags=public

//create public instance ("public" tag) on subnet-b
$ gcloud compute instances create public-on-subnet-b --machine-type=f1-micro --network=my-custom-network --subnet=subnet-b --zone=us-east1-c --tags=public

//create private instance ("private" tag) on subnet-a with larger size (g1-small)
$ gcloud compute instances create private-on-subnet-a --machine-type=g1-small --network=my-custom-network --subnet=subnet-a --zone=us-west1-a --tags=private

//Overall, there are 3 VM instances has been created in this example as below
$ gcloud compute instances list
NAME                                           ZONE           MACHINE_TYPE  PREEMPTIBLE  INTERNAL_IP  EXTERNAL_IP      STATUS
public-on-subnet-b                             us-east1-c     f1-micro                   172.16.1.2   35.196.228.40    RUNNING
private-on-subnet-a                            us-west1-a     g1-small                   10.0.1.2     104.199.121.234  RUNNING
public-on-subnet-a                             us-west1-a     f1-micro                   10.0.1.3     35.199.171.31    RUNNING  
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00136.jpeg)

您可以登录到这些机器上检查防火墙规则是否按预期工作。首先，您需要将 ssh 密钥添加到您的机器上的 ssh-agent 中：

```
$ ssh-add ~/.ssh/google_compute_engine
Enter passphrase for /Users/saito/.ssh/google_compute_engine: 
Identity added: /Users/saito/.ssh/google_compute_engine (/Users/saito/.ssh/google_compute_engine)  
```

然后检查 ICMP 防火墙规则是否可以拒绝来自外部的请求，因为 ICMP 只允许公共或私有标记的主机，因此不应允许来自您的机器的 ping，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00137.jpeg)

另一方面，公共主机允许来自您的机器的 ssh，因为 public-ssh 规则允许任何（`0.0.0.0/0`）。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00138.jpeg)

当然，这台主机可以通过私有 IP 地址在`subnet-a`（`10.0.1.2`）上 ping 和 ssh 到私有主机，因为有`internal-icmp`规则和`private-ssh`规则。

让我们通过 ssh 连接到私有主机，然后安装`tomcat8`和`tomcat8-examples`包（它将在 Tomcat 中安装`/examples/`应用程序）。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00139.jpeg)

请记住，`subnet-a`是`10.0.1.0/24`的 CIDR 前缀，但`subnet-b`是`172.16.1.0/24`的 CIDR 前缀。但在同一个 VPC 中，它们之间是可以互相连接的。这是使用 GCP 的一个巨大优势，您可以根据需要扩展网络地址块。

现在，在公共主机（`public-on-subnet-a`和`public-on-subnet-b`）上安装 nginx：

```
//logout from VM instance, then back to your machine
$ exit

//install nginx from your machine via ssh
$ ssh 35.196.228.40 "sudo apt-get -y install nginx"
$ ssh 35.199.171.31 "sudo apt-get -y install nginx"

//check whether firewall rule (public-http) work or not
$ curl -I http://35.196.228.40/
HTTP/1.1 200 OK
Server: nginx/1.10.3
Date: Sun, 27 Aug 2017 07:07:01 GMT
Content-Type: text/html
Content-Length: 612
Last-Modified: Fri, 25 Aug 2017 05:48:28 GMT
Connection: keep-alive
ETag: "599fba2c-264"
Accept-Ranges: bytes  
```

然而，此时，您无法访问私有主机上的 Tomcat。即使它有一个公共 IP 地址。这是因为私有主机还没有任何允许 8080/tcp 的防火墙规则：

```
$ curl http://104.199.121.234:8080/examples/
curl: (7) Failed to connect to 104.199.121.234 port 8080: Operation timed out  
```

继续前进，不仅为 Tomcat 创建防火墙规则，还将设置一个负载均衡器，以配置 nginx 和 Tomcat 从单个负载均衡器访问。

# 负载均衡

GCP 提供以下几种类型的负载均衡器：

+   第 4 层 TCP 负载均衡器

+   第 4 层 UDP 负载均衡器

+   第 7 层 HTTP(S)负载均衡器

第 4 层，无论是 TCP 还是 UDP，负载均衡器都类似于 AWS 经典 ELB。另一方面，第 7 层 HTTP(S)负载均衡器具有基于内容（上下文）的路由。例如，URL /img 将转发到实例 a，其他所有内容将转发到实例 b。因此，它更像是一个应用级别的负载均衡器。

AWS 还提供了**应用负载均衡器**（**ALB**或**ELBv2**），它与 GCP 第 7 层 HTTP(S)负载均衡器非常相似。有关详细信息，请访问[`aws.amazon.com/blogs/aws/new-aws-application-load-balancer/`](https://aws.amazon.com/blogs/aws/new-aws-application-load-balancer/)。

为了设置负载均衡器，与 AWS ELB 不同，需要在配置一些项目之前进行几个步骤：

| **配置项** | **目的** |
| --- | --- |
| 实例组 | 确定 VM 实例或 VM 模板（OS 镜像）的组。 |
| 健康检查 | 设置健康阈值（间隔、超时等）以确定实例组的健康状态。 |
| 后端服务 | 设置负载阈值（最大 CPU 或每秒请求）和会话亲和性（粘性会话）到实例组，并关联到健康检查。 |
| url-maps（负载均衡器） | 这是一个实际的占位符，用于表示关联后端服务和目标 HTTP(S)代理的 L7 负载均衡器 |
| 目标 HTTP(S)代理 | 这是一个连接器，它建立了前端转发规则与负载均衡器之间的关系 |
| 前端转发规则 | 将 IP 地址（临时或静态）、端口号与目标 HTTP 代理关联起来 |
| 外部 IP（静态） | （可选）为负载均衡器分配静态外部 IP 地址 |

以下图表显示了构建 L7 负载均衡器的所有前述组件的关联：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00140.jpeg)

首先设置一个实例组。在这个例子中，有三个要创建的实例组。一个用于私有主机 Tomcat 实例（8080/tcp），另外两个实例组用于每个区域的公共 HTTP 实例。

为此，执行以下命令将它们三个分组：

```
//create instance groups for HTTP instances and tomcat instance
$ gcloud compute instance-groups unmanaged create http-ig-us-west --zone us-west1-a
$ gcloud compute instance-groups unmanaged create http-ig-us-east --zone us-east1-c
$ gcloud compute instance-groups unmanaged create tomcat-ig-us-west --zone us-west1-a

//because tomcat uses 8080/tcp, create a new named port as tomcat:8080
$ gcloud compute instance-groups unmanaged set-named-ports tomcat-ig-us-west --zone us-west1-a --named-ports tomcat:8080

//register an existing VM instance to correspond instance group
$ gcloud compute instance-groups unmanaged add-instances http-ig-us-west --instances public-on-subnet-a --zone us-west1-a
$ gcloud compute instance-groups unmanaged add-instances http-ig-us-east --instances public-on-subnet-b --zone us-east1-c
$ gcloud compute instance-groups unmanaged add-instances tomcat-ig-us-west --instances private-on-subnet-a --zone us-west1-a  
```

# 健康检查

通过执行以下命令设置标准设置：

```
//create health check for http (80/tcp) for "/"
$ gcloud compute health-checks create http my-http-health-check --check-interval 5 --healthy-threshold 2 --unhealthy-threshold 3 --timeout 5 --port 80 --request-path /

//create health check for Tomcat (8080/tcp) for "/examples/"
$ gcloud compute health-checks create http my-tomcat-health-check --check-interval 5 --healthy-threshold 2 --unhealthy-threshold 3 --timeout 5 --port 8080 --request-path /examples/  
```

# 后端服务

首先，我们需要创建一个指定健康检查的后端服务。然后为每个实例组添加阈值，CPU 利用率最高为 80%，HTTP 和 Tomcat 的最大容量均为 100%：

```
//create backend service for http (default) and named port tomcat (8080/tcp)
$ gcloud compute backend-services create my-http-backend-service --health-checks my-http-health-check --protocol HTTP --global
$ gcloud compute backend-services create my-tomcat-backend-service --health-checks my-tomcat-health-check --protocol HTTP --port-name tomcat --global

//add http instance groups (both us-west1 and us-east1) to http backend service
$ gcloud compute backend-services add-backend my-http-backend-service --instance-group http-ig-us-west --instance-group-zone us-west1-a --balancing-mode UTILIZATION --max-utilization 0.8 --capacity-scaler 1 --global
$ gcloud compute backend-services add-backend my-http-backend-service --instance-group http-ig-us-east --instance-group-zone us-east1-c --balancing-mode UTILIZATION --max-utilization 0.8 --capacity-scaler 1 --global

//also add tomcat instance group to tomcat backend service
$ gcloud compute backend-services add-backend my-tomcat-backend-service --instance-group tomcat-ig-us-west --instance-group-zone us-west1-a --balancing-mode UTILIZATION --max-utilization 0.8 --capacity-scaler 1 --global  
```

# 创建负载均衡器

负载均衡器需要绑定`my-http-backend-service`和`my-tomcat-backend-service`。在这种情况下，只有`/examples`和`/examples/*`将被转发到`my-tomcat-backend-service`。除此之外，每个 URI 都将转发流量到`my-http-backend-service`：

```
//create load balancer(url-map) to associate my-http-backend-service as default
$ gcloud compute url-maps create my-loadbalancer --default-service my-http-backend-service

//add /examples and /examples/* mapping to my-tomcat-backend-service
$ gcloud compute url-maps add-path-matcher my-loadbalancer --default-service my-http-backend-service --path-matcher-name tomcat-map --path-rules /examples=my-tomcat-backend-service,/examples/*=my-tomcat-backend-service

//create target-http-proxy that associate to load balancer(url-map)
$ gcloud compute target-http-proxies create my-target-http-proxy --url-map=my-loadbalancer

//allocate static global ip address and check assigned address
$ gcloud compute addresses create my-loadbalancer-ip --global
$ gcloud compute addresses describe my-loadbalancer-ip --global
address: 35.186.192.6

//create forwarding rule that associate static IP to target-http-proxy
$ gcloud compute forwarding-rules create my-frontend-rule --global --target-http-proxy my-target-http-proxy --address 35.186.192.6 --ports 80
```

如果您不指定`--address`选项，它将创建并分配一个临时的外部 IP 地址。

最后，负载均衡器已经创建。但是，还有一个缺失的配置。私有主机没有任何防火墙规则来允许 Tomcat 流量（8080/tcp）。这就是为什么当您查看负载均衡器状态时，`my-tomcat-backend-service`的健康状态保持为下线（0）。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00141.jpeg)

在这种情况下，您需要添加一个允许从负载均衡器到私有子网的连接的防火墙规则（使用`private`网络标记）。根据 GCP 文档（[`cloud.google.com/compute/docs/load-balancing/health-checks#https_ssl_proxy_tcp_proxy_and_internal_load_balancing`](https://cloud.google.com/compute/docs/load-balancing/health-checks#https_ssl_proxy_tcp_proxy_and_internal_load_balancing)），健康检查心跳将来自地址范围`130.211.0.0/22`和`35.191.0.0/16`：

```
//add one more Firewall Rule that allow Load Balancer to Tomcat (8080/tcp)
$ gcloud compute firewall-rules create private-tomcat --network=my-custom-network --source-ranges 130.211.0.0/22,35.191.0.0/16 --target-tags private --allow tcp:8080  
```

几分钟后，`my-tomcat-backend-service`的健康状态将变为正常（`1`）；现在您可以从 Web 浏览器访问负载均衡器。当访问`/`时，它应该路由到`my-http-backend-service`，该服务在公共主机上有 nginx 应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00142.jpeg)

另一方面，如果您使用相同的负载均衡器 IP 地址访问`/examples/` URL，它将路由到`my-tomcat-backend-service`，该服务是私有主机上的 Tomcat 应用程序，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00143.jpeg)

总的来说，需要执行一些步骤来设置负载均衡器，但将不同的 HTTP 应用集成到单个负载均衡器上，以最小的资源高效地提供服务是很有用的。

# 持久磁盘

GCE 还有一个名为**持久磁盘**（**PD**）的存储服务，它与 AWS EBS 非常相似。您可以在每个区域分配所需的大小和类型（标准或 SSD），并随时附加/分离到 VM 实例。

让我们创建一个 PD，然后将其附加到 VM 实例。请注意，将 PD 附加到 VM 实例时，两者必须位于相同的区域。这个限制与 AWS EBS 相同。因此，在创建 PD 之前，再次检查 VM 实例的位置：

```
$ gcloud compute instances list
NAME                                           ZONE           MACHINE_TYPE  PREEMPTIBLE  INTERNAL_IP  EXTERNAL_IP      STATUS
public-on-subnet-b                             us-east1-c     f1-micro                   172.16.1.2   35.196.228.40    RUNNING
private-on-subnet-a                            us-west1-a     g1-small                   10.0.1.2     104.199.121.234  RUNNING
public-on-subnet-a                             us-west1-a     f1-micro                   10.0.1.3     35.199.171.31    RUNNING  
```

让我们选择`us-west1-a`，然后将其附加到`public-on-subnet-a`：

```
//create 20GB PD on us-west1-a with standard type
$ gcloud compute disks create my-disk-us-west1-a --zone us-west1-a --type pd-standard --size 20

//after a few seconds, check status, you can see existing boot disks as well
$ gcloud compute disks list
NAME                                           ZONE           SIZE_GB  TYPE         STATUS
public-on-subnet-b                             us-east1-c     10       pd-standard  READY
my-disk-us-west1-a                             us-west1-a     20       pd-standard  READY
private-on-subnet-a                            us-west1-a     10       pd-standard  READY
public-on-subnet-a                             us-west1-a     10       pd-standard  READY

//attach PD(my-disk-us-west1-a) to the VM instance(public-on-subnet-a)
$ gcloud compute instances attach-disk public-on-subnet-a --disk my-disk-us-west1-a --zone us-west1-a

//login to public-on-subnet-a to see the status
$ ssh 35.199.171.31
Linux public-on-subnet-a 4.9.0-3-amd64 #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Aug 25 03:53:24 2017 from 107.196.102.199
saito@public-on-subnet-a**:**~**$ sudo su
root@public-on-subnet-a:/home/saito# dmesg | tail
[ 7377.421190] systemd[1]: apt-daily-upgrade.timer: Adding 25min 4.773609s random time.
[ 7379.202172] systemd[1]: apt-daily-upgrade.timer: Adding 6min 37.770637s random time.
[243070.866384] scsi 0:0:2:0: Direct-Access     Google   PersistentDisk   1    PQ: 0 ANSI: 6
[243070.875665] sd 0:0:2:0: [sdb] 41943040 512-byte logical blocks: (21.5 GB/20.0 GiB)
[243070.883461] sd 0:0:2:0: [sdb] 4096-byte physical blocks
[243070.889914] sd 0:0:2:0: Attached scsi generic sg1 type 0
[243070.900603] sd 0:0:2:0: [sdb] Write Protect is off
[243070.905834] sd 0:0:2:0: [sdb] Mode Sense: 1f 00 00 08
[243070.905938] sd 0:0:2:0: [sdb] Write cache: enabled, read cache: enabled, doesn't support DPO or FUA
[243070.925713] sd 0:0:2:0: [sdb] Attached SCSI disk  
```

您可能会看到 PD 已经附加到`/dev/sdb`。与 AWS EBS 类似，您必须格式化此磁盘。因为这是一个 Linux 操作系统操作，步骤与第九章中描述的完全相同，*在 AWS 上的 Kubernetes*。

# Google 容器引擎（GKE）

总的来说，一些 GCP 组件已经在前几节中介绍过。现在，您可以开始在 GCP VM 实例上使用这些组件设置 Kubernetes。您甚至可以使用在第九章中介绍的 kops，*在 AWS 上的 Kubernetes*也是如此。

然而，GCP 有一个名为 GKE 的托管 Kubernetes 服务。在底层，它使用了一些 GCP 组件，如 VPC、VM 实例、PD、防火墙规则和负载均衡器。

当然，像往常一样，您可以使用`kubectl`命令来控制 GKE 上的 Kubernetes 集群，该命令包含在 Cloud SDK 中。如果您尚未在您的机器上安装`kubectl`命令，请输入以下命令通过 Cloud SDK 安装`kubectl`：

```
//install kubectl command
$ gcloud components install kubectl  
```

# 在 GKE 上设置您的第一个 Kubernetes 集群

您可以使用`gcloud`命令在 GKE 上设置 Kubernetes 集群。它需要指定几个参数来确定一些配置。其中一个重要的参数是网络。您必须指定将部署到哪个 VPC 和子网。虽然 GKE 支持多个区域进行部署，但您需要至少指定一个区域用于 Kubernetes 主节点。这次，它使用以下参数来启动 GKE 集群：

| **参数** | **描述** | **值** |
| --- | --- | --- |
| `--cluster-version` | 指定 Kubernetes 版本 | `1.6.7` |
| `--machine-type` | Kubernetes 节点的 VM 实例类型 | `f1-micro` |
| `--num-nodes` | Kubernetes 节点的初始数量 | `3` |
| `--network` | 指定 GCP VPC | `my-custom-network` |
| `--subnetwork` | 如果 VPC 是自定义模式，则指定 GCP 子网 | `subnet-c` |
| `--zone` | 指定单个区域 | `asia-northeast1-a` |
| `--tags` | 将分配给 Kubernetes 节点的网络标签 | `private` |

在这种情况下，您需要键入以下命令在 GCP 上启动 Kubernetes 集群。这可能需要几分钟才能完成，因为在幕后，它将启动多个 VM 实例并设置 Kubernetes 主节点和节点。请注意，Kubernetes 主节点和 etcd 将由 GCP 完全管理。这意味着主节点和 etcd 不会占用您的 VM 实例：

```
$ gcloud container clusters create my-k8s-cluster --cluster-version 1.6.7 --machine-type f1-micro --num-nodes 3 --network my-custom-network --subnetwork subnet-c --zone asia-northeast1-a --tags private

Creating cluster my-k8s-cluster...done. 
Created [https://container.googleapis.com/v1/projects/devops-with-kubernetes/zones/asia-northeast1-a/clusters/my-k8s-cluster].
kubeconfig entry generated for my-k8s-cluster.
NAME            ZONE               MASTER_VERSION  MASTER_IP      MACHINE_TYPE  NODE_VERSION  NUM_NODES  STATUS
my-k8s-cluster  asia-northeast1-a  1.6.7           35.189.135.13  f1-micro      1.6.7         3          RUNNING

//check node status
$ kubectl get nodes
NAME                                            STATUS    AGE       VERSION
gke-my-k8s-cluster-default-pool-ae180f53-47h5   Ready     1m        v1.6.7
gke-my-k8s-cluster-default-pool-ae180f53-6prb   Ready     1m        v1.6.7
gke-my-k8s-cluster-default-pool-ae180f53-z6l1   Ready     1m        v1.6.7  
```

请注意，我们指定了`--tags private`选项，因此 Kubernetes 节点 VM 实例具有`private`网络标记。因此，它的行为与具有`private`标记的其他常规 VM 实例相同。因此，您无法从公共互联网进行 ssh，也无法从互联网进行 HTTP。但是，您可以从具有`public`网络标记的另一个 VM 实例进行 ping 和 ssh。

一旦所有节点准备就绪，让我们访问默认安装的 Kubernetes UI。为此，使用`kubectl proxy`命令作为代理连接到您的计算机。然后通过代理访问 UI：

```
//run kubectl proxy on your machine, that will bind to 127.0.0.1:8001
$ kubectl proxy
Starting to serve on 127.0.0.1:8001

//use Web browser on your machine to access to 127.0.0.1:8001/ui/
http://127.0.0.1:8001/ui/
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00144.jpeg)

# 节点池

在启动 Kubernetes 集群时，您可以使用`--num-nodes`选项指定节点的数量。GKE 将 Kubernetes 节点管理为节点池。这意味着您可以管理一个或多个附加到您的 Kubernetes 集群的节点池。

如果您需要添加更多节点或删除一些节点怎么办？GKE 提供了一个功能，可以通过以下命令将 Kubernetes 节点从 3 更改为 5 来调整节点池的大小：

```
//run resize command to change number of nodes to 5
$ gcloud container clusters resize my-k8s-cluster --size 5 --zone asia-northeast1-a

//after a few minutes later, you may see additional nodes
$ kubectl get nodes
NAME                                            STATUS    AGE       VERSION
gke-my-k8s-cluster-default-pool-ae180f53-47h5   Ready     5m        v1.6.7
gke-my-k8s-cluster-default-pool-ae180f53-6prb   Ready     5m        v1.6.7
gke-my-k8s-cluster-default-pool-ae180f53-f8ps   Ready     30s       v1.6.7
gke-my-k8s-cluster-default-pool-ae180f53-qzxz   Ready     30s       v1.6.7
gke-my-k8s-cluster-default-pool-ae180f53-z6l1   Ready     5m        v1.6.7  
```

增加节点数量将有助于扩展节点容量。但是，在这种情况下，它仍然使用最小的实例类型（`f1-micro`，仅具有 0.6 GB 内存）。如果单个容器需要超过 0.6 GB 内存，则可能无法帮助。在这种情况下，您需要进行扩展，这意味着您需要添加更大尺寸的 VM 实例类型。

在这种情况下，您必须将另一组节点池添加到您的集群中。因为在同一个节点池中，所有 VM 实例都配置相同。因此，您无法在同一个节点池中更改实例类型。

因此，添加一个新的节点池，该节点池具有两组新的`g1-small`（1.7 GB 内存）VM 实例类型到集群中。然后，您可以扩展具有不同硬件配置的 Kubernetes 节点。

默认情况下，您可以在一个区域内创建 VM 实例数量的一些配额限制（例如，在`us-west1`最多八个 CPU 核心）。如果您希望增加此配额，您必须将您的帐户更改为付费帐户。然后向 GCP 请求配额更改。有关更多详细信息，请阅读来自[`cloud.google.com/compute/quotas`](https://cloud.google.com/compute/quotas)和[`cloud.google.com/free/docs/frequently-asked-questions#how-to-upgrade`](https://cloud.google.com/free/docs/frequently-asked-questions#how-to-upgrade)的在线文档。

运行以下命令，添加一个具有两个`g1-small`实例的额外节点池：

```
//create and add node pool which is named "large-mem-pool"
$ gcloud container node-pools create large-mem-pool --cluster my-k8s-cluster --machine-type g1-small --num-nodes 2 --tags private --zone asia-northeast1-a

//after a few minustes, large-mem-pool instances has been added
$ kubectl get nodes
NAME                                              STATUS    AGE       VERSION
gke-my-k8s-cluster-default-pool-ae180f53-47h5     Ready     13m       v1.6.7
gke-my-k8s-cluster-default-pool-ae180f53-6prb     Ready     13m       v1.6.7
gke-my-k8s-cluster-default-pool-ae180f53-f8ps     Ready     8m        v1.6.7
gke-my-k8s-cluster-default-pool-ae180f53-qzxz     Ready     8m        v1.6.7
gke-my-k8s-cluster-default-pool-ae180f53-z6l1     Ready     13m       v1.6.7
gke-my-k8s-cluster-large-mem-pool-f87dd00d-9v5t   Ready     5m        v1.6.7
gke-my-k8s-cluster-large-mem-pool-f87dd00d-fhpn   Ready     5m        v1.6.7  
```

现在您的集群中总共有七个 CPU 核心和 6.4GB 内存的容量更大。然而，由于更大的硬件类型，Kubernetes 调度器可能会首先分配部署 pod 到`large-mem-pool`，因为它有足够的内存容量。

但是，您可能希望保留`large-mem-pool`节点，以防一个大型应用程序需要大的堆内存大小（例如，Java 应用程序）。因此，您可能希望区分`default-pool`和`large-mem-pool`。

在这种情况下，Kubernetes 标签`beta.kubernetes.io/instance-type`有助于区分节点的实例类型。因此，使用`nodeSelector`来指定 pod 的所需节点。例如，以下`nodeSelector`参数将强制使用`f1-micro`节点进行 nginx 应用程序：

```
//nodeSelector specifies f1-micro
$ cat nginx-pod-selector.yml 
apiVersion: v1
kind: Pod
metadata:
 name: nginx
spec:
 containers:
 - name: nginx
 image: nginx
 nodeSelector:
 beta.kubernetes.io/instance-type: f1-micro

//deploy pod
$ kubectl create -f nginx-pod-selector.yml 
pod "nginx" created

//it uses default pool
$ kubectl get pods nginx -o wide
NAME      READY     STATUS    RESTARTS   AGE       IP           NODE
nginx     1/1       Running   0          7s        10.56.1.13   gke-my-k8s-cluster-default-pool-ae180f53-6prb
```

如果您想指定一个特定的标签而不是`beta.kubernetes.io/instance-type`，请使用`--node-labels`选项创建一个节点池。这将为节点池分配您所需的标签。

有关更多详细信息，请阅读以下在线文档：

[`cloud.google.com/sdk/gcloud/reference/container/node-pools/create`](https://cloud.google.com/sdk/gcloud/reference/container/node-pools/create)。

当然，如果您不再需要它，可以随时删除一个节点池。要做到这一点，请运行以下命令删除`default-pool`（`f1-micro` x 5 个实例）。如果在`default-pool`上有一些正在运行的 pod，此操作将自动涉及 pod 迁移（终止`default-pool`上的 pod 并重新在`large-mem-pool`上启动）：

```
//list Node Pool
$ gcloud container node-pools list --cluster my-k8s-cluster --zone asia-northeast1-a
NAME            MACHINE_TYPE  DISK_SIZE_GB  NODE_VERSION
default-pool    f1-micro      100           1.6.7
large-mem-pool  g1-small      100           1.6.7

//delete default-pool
$ gcloud container node-pools delete default-pool --cluster my-k8s-cluster --zone asia-northeast1-a

//after a few minutes, default-pool nodes x 5 has been deleted
$ kubectl get nodes
NAME                                              STATUS    AGE       VERSION
gke-my-k8s-cluster-large-mem-pool-f87dd00d-9v5t   Ready     16m       v1.6.7
gke-my-k8s-cluster-large-mem-pool-f87dd00d-fhpn   Ready     16m       v1.6.7  
```

您可能已经注意到，所有前面的操作都发生在一个单一区域（`asia-northeast1-a`）中。因此，如果`asia-northeast1-a`区域发生故障，您的集群将会宕机。为了避免区域故障，您可以考虑设置一个多区域集群。

# 多区域集群

GKE 支持多区域集群，允许您在多个区域上启动 Kubernetes 节点，但限制在同一地区内。在之前的示例中，它只在`asia-northeast1-a`上进行了配置，因此让我们重新配置一个集群，其中包括`asia-northeast1-a`，`asia-northeast1-b`和`asia-northeast1-c`，总共三个区域。

非常简单；在创建新集群时，只需添加一个`--additional-zones`参数。

截至 2017 年 8 月，有一个测试功能支持将现有集群从单个区域升级到多个区域。使用以下测试命令：

`$ gcloud beta container clusters update my-k8s-cluster --additional-zones=asia-northeast1-b,asia-northeast1-c`。

要将现有集群更改为多区域，可能需要安装额外的 SDK 工具，但不在 SLA 范围内。

让我们删除之前的集群，并使用`--additional-zones`选项创建一个新的集群：

```
//delete cluster first
$ gcloud container clusters delete my-k8s-cluster --zone asia-northeast1-a

//create a new cluster with --additional-zones option but 2 nodes only
$ gcloud container clusters create my-k8s-cluster --cluster-version 1.6.7 --machine-type f1-micro --num-nodes 2 --network my-custom-network --subnetwork subnet-c --zone asia-northeast1-a --tags private --additional-zones asia-northeast1-b,asia-northeast1-c  
```

在此示例中，它将在每个区域（`asia-northeast1-a`，`b`和`c`）创建两个节点；因此，总共将添加六个节点：

```
$ kubectl get nodes
NAME                                            STATUS    AGE       VERSION
gke-my-k8s-cluster-default-pool-0c4fcdf3-3n6d   Ready     44s       v1.6.7
gke-my-k8s-cluster-default-pool-0c4fcdf3-dtjj   Ready     48s       v1.6.7
gke-my-k8s-cluster-default-pool-2407af06-5d28   Ready     41s       v1.6.7
gke-my-k8s-cluster-default-pool-2407af06-tnpj   Ready     45s       v1.6.7
gke-my-k8s-cluster-default-pool-4c20ec6b-395h   Ready     49s       v1.6.7
gke-my-k8s-cluster-default-pool-4c20ec6b-rrvz   Ready     49s       v1.6.7  
```

您还可以通过 Kubernetes 标签`failure-domain.beta.kubernetes.io/zone`区分节点区域，以便指定要部署 Pod 的所需区域。

# 集群升级

一旦开始管理 Kubernetes，您可能会在升级 Kubernetes 集群时遇到一些困难。因为 Kubernetes 项目非常积极，大约每三个月就会有一个新版本发布，例如 1.6.0（2017 年 3 月 28 日发布）到 1.7.0（2017 年 6 月 29 日发布）。

GKE 还会及时添加新版本支持。它允许我们通过`gcloud`命令升级主节点和节点。您可以运行以下命令查看 GKE 支持的 Kubernetes 版本：

```
$ gcloud container get-server-config

Fetching server config for us-east4-b
defaultClusterVersion: 1.6.7
defaultImageType: COS
validImageTypes:
- CONTAINER_VM
- COS
- UBUNTU
validMasterVersions:
- 1.7.3
- 1.6.8
- 1.6.7
validNodeVersions:
- 1.7.3
- 1.7.2
- 1.7.1
- 1.6.8
- 1.6.7
- 1.6.6
- 1.6.4
- 1.5.7
- 1.4.9  
```

因此，您可能会看到此时主节点和节点上支持的最新版本都是 1.7.3。由于之前的示例安装的是 1.6.7 版本，让我们升级到 1.7.3。首先，您需要先升级主节点：

```
//upgrade master using --master option
$ gcloud container clusters upgrade my-k8s-cluster --zone asia-northeast1-a --cluster-version 1.7.3 --master
Master of cluster [my-k8s-cluster] will be upgraded from version 
[1.6.7] to version [1.7.3]. This operation is long-running and will 
block other operations on the cluster (including delete) until it has 
run to completion.

Do you want to continue (Y/n)?  y

Upgrading my-k8s-cluster...done. 
Updated [https://container.googleapis.com/v1/projects/devops-with-kubernetes/zones/asia-northeast1-a/clusters/my-k8s-cluster].  
```

根据环境，大约需要 10 分钟，之后您可以通过以下命令进行验证：

```
//master upgrade has been successfully to done
$ gcloud container clusters list --zone asia-northeast1-a
NAME            ZONE               MASTER_VERSION  MASTER_IP       MACHINE_TYPE  NODE_VERSION  NUM_NODES  STATUS
my-k8s-cluster  asia-northeast1-a  1.7.3           35.189.141.251  f1-micro      1.6.7 *       6          RUNNING  
```

现在您可以将所有节点升级到 1.7.3 版本。因为 GKE 尝试执行滚动升级，它将按照以下步骤逐个节点执行：

1.  从集群中注销目标节点。

1.  删除旧的 VM 实例。

1.  提供一个新的 VM 实例。

1.  设置节点为 1.7.3 版本。

1.  注册到主节点。

因此，它比主节点升级需要更长的时间：

```
//node upgrade (not specify --master)
$ gcloud container clusters upgrade my-k8s-cluster --zone asia-northeast1-a --cluster-version 1.7.3 
All nodes (6 nodes) of cluster [my-k8s-cluster] will be upgraded from 
version [1.6.7] to version [1.7.3]. This operation is long-running and will block other operations on the cluster (including delete) until it has run to completion.

Do you want to continue (Y/n)?  y  
```

在滚动升级期间，您可以看到节点状态如下，并显示滚动更新的中间过程（两个节点已升级到 1.7.3，一个节点正在升级，三个节点处于挂起状态）：

```
NAME                                            STATUS                        AGE       VERSION
gke-my-k8s-cluster-default-pool-0c4fcdf3-3n6d   Ready                         37m       v1.6.7
gke-my-k8s-cluster-default-pool-0c4fcdf3-dtjj   Ready                         37m       v1.6.7
gke-my-k8s-cluster-default-pool-2407af06-5d28   NotReady,SchedulingDisabled   37m       v1.6.7
gke-my-k8s-cluster-default-pool-2407af06-tnpj   Ready                         37m       v1.6.7
gke-my-k8s-cluster-default-pool-4c20ec6b-395h   Ready                         5m        v1.7.3
gke-my-k8s-cluster-default-pool-4c20ec6b-rrvz   Ready                         1m        v1.7.3  
```

# Kubernetes 云提供商

GKE 还集成了 Kubernetes 云提供商，可以深度整合到 GCP 基础设施；例如通过 VPC 路由的覆盖网络，通过持久磁盘的 StorageClass，以及通过 L4 负载均衡器的服务。最好的部分是通过 L7 负载均衡器的入口。让我们看看它是如何工作的。

# StorageClass

与 AWS 上的 kops 一样，GKE 也默认设置了 StorageClass，使用持久磁盘：

```
$ kubectl get storageclass
NAME                 TYPE
standard (default)   kubernetes.io/gce-pd 

$ kubectl describe storageclass standard
Name:       standard
IsDefaultClass:   Yes
Annotations:      storageclass.beta.kubernetes.io/is-default-class=true
Provisioner:      kubernetes.io/gce-pd
Parameters: type=pd-standard
Events:           <none>  
```

因此，在创建持久卷索赔时，它将自动将 GCP 持久磁盘分配为 Kubernetes 持久卷。关于持久卷索赔和动态配置，请参阅第四章，*使用存储和资源*：

```
$ cat pvc-gke.yml 
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
 name: pvc-gke-1
spec:
 storageClassName: "standard"
 accessModes:
 - ReadWriteOnce
 resources:
 requests:
 storage: 10Gi

//create Persistent Volume Claim
$ kubectl create -f pvc-gke.yml 
persistentvolumeclaim "pvc-gke-1" created

//check Persistent Volume
$ kubectl get pv
NAME                                       CAPACITY   ACCESSMODES   RECLAIMPOLICY   STATUS    CLAIM               STORAGECLASS   REASON    AGE
pvc-bc04e717-8c82-11e7-968d-42010a920fc3   10Gi       RWO           Delete          Bound     default/pvc-gke-1   standard                 2s

//check via gcloud command
$ gcloud compute disks list 
NAME                                                             ZONE               SIZE_GB  TYPE         STATUS
gke-my-k8s-cluster-d2e-pvc-bc04e717-8c82-11e7-968d-42010a920fc3  asia-northeast1-a  10       pd-standard  READY  
```

# L4 负载均衡器

与 AWS 云提供商类似，GKE 还支持使用 L4 负载均衡器来为 Kubernetes 服务提供支持。只需将`Service.spec.type`指定为 LoadBalancer，然后 GKE 将自动设置和配置 L4 负载均衡器。

请注意，L4 负载均衡器到 Kubernetes 节点之间的相应防火墙规则可以由云提供商自动创建。如果您想快速将应用程序暴露给互联网，这种方法简单但足够强大：

```
$ cat grafana.yml 
apiVersion: apps/v1beta1
kind: Deployment
metadata:
 name: grafana
spec:
 replicas: 1
 template:
 metadata:
 labels:
 run: grafana
 spec:
 containers:
 - image: grafana/grafana
 name: grafana
 ports:
 - containerPort: 3000
---
apiVersion: v1
kind: Service
metadata:
 name: grafana
spec:
 ports:
 - port: 80
 targetPort: 3000
 type: LoadBalancer
 selector:
 run: grafana

//deploy grafana with Load Balancer service
$ kubectl create -f grafana.yml 
deployment "grafana" created
service "grafana" created

//check L4 Load balancer IP address
$ kubectl get svc grafana
NAME      CLUSTER-IP     EXTERNAL-IP     PORT(S)        AGE
grafana   10.59.249.34   35.189.128.32   80:30584/TCP   5m

//can reach via GCP L4 Load Balancer
$ curl -I 35.189.128.32
HTTP/1.1 302 Found
Location: /login
Set-Cookie: grafana_sess=f92407d7b266aab8; Path=/; HttpOnly
Set-Cookie: redirect_to=%252F; Path=/
Date: Wed, 30 Aug 2017 07:05:20 GMT
Content-Type: text/plain; charset=utf-8  
```

# L7 负载均衡器（入口）

GKE 还支持 Kubernetes 入口，可以设置 GCP L7 负载均衡器，根据 URL 将 HTTP 请求分发到目标服务。您只需要设置一个或多个 NodePort 服务，然后创建入口规则指向服务。在幕后，Kubernetes 会自动创建和配置防火墙规则、健康检查、后端服务、转发规则和 URL 映射。

首先，让我们创建相同的示例，使用 nginx 和 Tomcat 部署到 Kubernetes 集群。这些示例使用绑定到 NodePort 而不是 LoadBalancer 的 Kubernetes 服务：

**![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00145.jpeg)**

此时，您无法访问服务，因为还没有防火墙规则允许从互联网访问 Kubernetes 节点。因此，让我们创建指向这些服务的 Kubernetes 入口。

您可以使用`kubectl port-forward <pod name> <your machine available port><: service port number>`通过 Kubernetes API 服务器访问。对于前面的情况，请使用`kubectl port-forward tomcat-670632475-l6h8q 10080:8080.`。

之后，打开您的 Web 浏览器到`http://localhost:10080/`，然后您可以直接访问 Tomcat pod。

Kubernetes Ingress 定义与 GCP 后端服务定义非常相似，因为它需要指定 URL 路径、Kubernetes 服务名称和服务端口号的组合。因此，在这种情况下，URL `/` 和 `/*` 指向 nginx 服务，URL `/examples` 和 `/examples/*` 指向 Tomcat 服务，如下所示：

```
$ cat nginx-tomcat-ingress.yaml 
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
 name: nginx-tomcat-ingress
spec:
 rules:
 - http:
 paths:
 - path: /
 backend:
 serviceName: nginx
 servicePort: 80
 - path: /examples
 backend:
 serviceName: tomcat
 servicePort: 8080
 - path: /examples/*
 backend:
 serviceName: tomcat
 servicePort: 8080

$ kubectl create -f nginx-tomcat-ingress.yaml 
ingress "nginx-tomcat-ingress" created  
```

大约需要 10 分钟来完全配置 GCP 组件，如健康检查、转发规则、后端服务和 URL 映射：

```
$ kubectl get ing
NAME                   HOSTS     ADDRESS           PORTS     AGE
nginx-tomcat-ingress   *         107.178.253.174   80        1m  
```

您还可以通过 Web 控制台检查状态，如下所示：

！[](../images/00146.jpeg)

完成 L7 负载均衡器的设置后，您可以访问负载均衡器的公共 IP 地址（`http://107.178.253.174/`）来查看 nginx 页面。以及访问`http://107.178.253.174/examples/`，然后您可以看到`tomcat 示例`页面。

在前面的步骤中，我们为 L7 负载均衡器创建并分配了临时 IP 地址。然而，使用 L7 负载均衡器的最佳实践是分配静态 IP 地址，因为您还可以将 DNS（FQDN）关联到静态 IP 地址。

为此，更新 Ingress 设置以添加注释`kubernetes.io/ingress.global-static-ip-name`，以关联 GCP 静态 IP 地址名称，如下所示：

```
//allocate static IP as my-nginx-tomcat
$ gcloud compute addresses create my-nginx-tomcat --global

//check assigned IP address
$ gcloud compute addresses list 
NAME             REGION  ADDRESS         STATUS
my-nginx-tomcat          35.186.227.252  IN_USE

//add annotations definition
$ cat nginx-tomcat-static-ip-ingress.yaml 
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
 name: nginx-tomcat-ingress
 annotations:
 kubernetes.io/ingress.global-static-ip-name: my-nginx- 
tomcat
spec:
 rules:
 - http:
 paths:
 - path: /
 backend:
 serviceName: nginx
 servicePort: 80
 - path: /examples
 backend:
 serviceName: tomcat
 servicePort: 8080
 - path: /examples/*
 backend:
 serviceName: tomcat
 servicePort: 8080

//apply command to update Ingress
$ kubectl apply -f nginx-tomcat-static-ip-ingress.yaml 

//check Ingress address that associate to static IP
$ kubectl get ing
NAME                   HOSTS     ADDRESS          PORTS     AGE
nginx-tomcat-ingress   *         35.186.227.252   80        48m  
```

所以，现在您可以通过静态 IP 地址访问入口，如`http://35.186.227.252/`（nginx）和`http://35.186.227.252/examples/`（Tomcat）。

# 摘要

在本章中，我们讨论了 Google Cloud Platform。基本概念类似于 AWS，但一些政策和概念是不同的。特别是 Google Container Engine，作为一个非常强大的服务，可以将 Kubernetes 用作生产级别。Kubernetes 集群和节点管理非常容易，不仅安装，还有升级。云提供商也完全集成到 GCP 中，特别是 Ingress，因为它可以通过一个命令配置 L7 负载均衡器。因此，如果您计划在公共云上使用 Kubernetes，强烈建议尝试 GKE。

下一章将提供一些新功能和替代服务的预览，以对抗 Kubernetes。
