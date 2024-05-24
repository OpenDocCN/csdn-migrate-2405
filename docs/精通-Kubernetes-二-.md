# 精通 Kubernetes（二）

> 原文：[`zh.annas-archive.org/md5/0FB6BD53079686F120215D277D8C163C`](https://zh.annas-archive.org/md5/0FB6BD53079686F120215D277D8C163C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：高可用性和可靠性

在上一章中，我们讨论了监视您的 Kubernetes 集群，在节点级别检测问题，识别和纠正性能问题以及一般故障排除。

在本章中，我们将深入探讨高度可用的集群主题。这是一个复杂的主题。Kubernetes 项目和社区尚未就实现高可用性的真正方式达成一致。高度可用的 Kubernetes 集群有许多方面，例如确保控制平面在面对故障时能够继续运行，保护`etcd`中的集群状态，保护系统的数据，并快速恢复容量和/或性能。不同的系统将有不同的可靠性和可用性要求。如何设计和实现高度可用的 Kubernetes 集群将取决于这些要求。

通过本章的学习，您将了解与高可用性相关的各种概念，并熟悉 Kubernetes 高可用性最佳实践以及何时使用它们。您将能够使用不同的策略和技术升级实时集群，并能够根据性能、成本和可用性之间的权衡选择多种可能的解决方案。

# 高可用性概念

在这一部分，我们将通过探索可靠和高可用系统的概念和构建模块来开始我们的高可用性之旅。百万（万亿？）美元的问题是，我们如何从不可靠的组件构建可靠和高可用的系统？组件会失败，你可以把它带到银行；硬件会失败；网络会失败；配置会出错；软件会有 bug；人会犯错误。接受这一点，我们需要设计一个系统，即使组件失败，也能可靠和高可用。这个想法是从冗余开始，检测组件故障，并快速替换坏组件。

# 冗余

**冗余**是可靠和高可用系统在硬件和数据级别的基础。如果关键组件失败并且您希望系统继续运行，您必须准备好另一个相同的组件。Kubernetes 本身通过复制控制器和副本集来管理无状态的 pod。然而，您的`etcd`中的集群状态和主要组件本身需要冗余以在某些组件失败时继续运行。此外，如果您的系统的重要组件没有受到冗余存储的支持（例如在云平台上），那么您需要添加冗余以防止数据丢失。

# 热插拔

**热插拔**是指在不关闭系统的情况下替换失败的组件的概念，对用户的中断最小（理想情况下为零）。如果组件是无状态的（或其状态存储在单独的冗余存储中），那么热插拔新组件来替换它就很容易，只需要将所有客户端重定向到新组件。然而，如果它存储本地状态，包括内存中的状态，那么热插拔就很重要。有以下两个主要选项：

+   放弃在飞行中的交易

+   保持热备份同步

第一个解决方案要简单得多。大多数系统都足够弹性，可以应对故障。客户端可以重试失败的请求，而热插拔的组件将为它们提供服务。

第二个解决方案更加复杂和脆弱，并且会产生性能开销，因为每次交互都必须复制到两个副本（并得到确认）。对于系统的某些部分可能是必要的。

# 领导者选举

领导者或主选举是分布式系统中常见的模式。您经常有多个相同的组件协作和共享负载，但其中一个组件被选为领导者，并且某些操作通过领导者进行序列化。您可以将具有领导者选举的分布式系统视为冗余和热插拔的组合。这些组件都是冗余的，当当前领导者失败或不可用时，将选举出一个新的领导者并进行热插拔。

# 智能负载平衡

负载平衡是指在多个组件之间分配服务传入请求的工作负载。当一些组件失败时，负载平衡器必须首先停止向失败或不可达的组件发送请求。第二步是提供新的组件来恢复容量并更新负载平衡器。Kubernetes 通过服务、端点和标签提供了支持这一点的很好的设施。

# 幂等性

许多类型的故障都可能是暂时的。这在网络问题或过于严格的超时情况下最常见。不响应健康检查的组件将被视为不可达，另一个组件将取而代之。原本计划发送到可能失败的组件的工作可能被发送到另一个组件，但原始组件可能仍在工作并完成相同的工作。最终结果是相同的工作可能会执行两次。很难避免这种情况。为了支持精确一次语义，您需要付出沉重的代价，包括开销、性能、延迟和复杂性。因此，大多数系统选择支持至少一次语义，这意味着可以多次执行相同的工作而不违反系统的数据完整性。这种属性被称为幂等性。幂等系统在多次执行操作时保持其状态。

# 自愈

当动态系统中发生组件故障时，通常希望系统能够自我修复。Kubernetes 复制控制器和副本集是自愈系统的很好例子，但故障可能远不止于 Pod。在上一章中，我们讨论了资源监控和节点问题检测。补救控制器是自愈概念的一个很好的例子。自愈始于自动检测问题，然后是自动解决。配额和限制有助于创建检查和平衡，以确保自动自愈不会因不可预测的情况（如 DDOS 攻击）而失控。

在本节中，我们考虑了创建可靠和高可用系统涉及的各种概念。在下一节中，我们将应用它们，并展示部署在 Kubernetes 集群上的系统的最佳实践。

# 高可用性最佳实践

构建可靠和高可用的分布式系统是一项重要的工作。在本节中，我们将检查一些最佳实践，使基于 Kubernetes 的系统能够可靠地运行，并在面对各种故障类别时可用。

# 创建高可用集群

要创建一个高可用的 Kubernetes 集群，主要组件必须是冗余的。这意味着`etcd`必须部署为一个集群（通常跨三个或五个节点），Kubernetes API 服务器必须是冗余的。辅助集群管理服务，如 Heapster 的存储，如果必要的话也可以部署为冗余。以下图表描述了一个典型的可靠和高可用的 Kubernetes 集群。有几个负载均衡的主节点，每个节点都包含整个主要组件以及一个`etcd`组件：

！[](Images/9a4726b1-7f50-4611-bed4-91d7663833b8.png)

这不是配置高可用集群的唯一方式。例如，您可能更喜欢部署一个独立的`etcd`集群，以优化机器的工作负载，或者如果您的`etcd`集群需要比其他主节点更多的冗余。

自托管的 Kubernetes，其中控制平面组件部署为集群中的 pod 和有状态集，是简化控制平面组件的健壮性、灾难恢复和自愈的一个很好的方法，通过将 Kubernetes 应用于 Kubernetes。

# 使您的节点可靠

节点会失败，或者一些组件会失败，但许多故障是暂时的。基本的保证是确保 Docker 守护程序（或任何 CRI 实现）和 Kubelet 在发生故障时能够自动重启。

如果您运行 CoreOS，一个现代的基于 Debian 的操作系统（包括 Ubuntu >= 16.04），或者任何其他使用`systemd`作为其`init`机制的操作系统，那么很容易将`Docker`和`kubelet`部署为自启动守护程序：

```
systemctl enable docker 
systemctl enable kublet 
```

对于其他操作系统，Kubernetes 项目选择了 monit 作为高可用示例，但您可以使用任何您喜欢的进程监视器。

# 保护您的集群状态

Kubernetes 集群状态存储在`etcd`中。`etcd`集群被设计为超级可靠，并分布在多个节点上。利用这些功能对于一个可靠和高可用的 Kubernetes 集群非常重要。

# 集群化 etcd

您的 etcd 集群中应该至少有三个节点。如果您需要更可靠和冗余性，可以增加到五个、七个或任何其他奇数节点。节点数量必须是奇数，以便在网络分裂的情况下有明确的多数。

为了创建一个集群，`etcd`节点应该能够发现彼此。有几种方法可以实现这一点。我建议使用 CoreOS 的优秀的`etcd-operator`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/9f1020a1-9e4e-4d18-af97-d17c4af9f0dd.png)

操作员负责处理 etcd 操作的许多复杂方面，例如：

+   创建和销毁

+   调整大小

+   故障转移

+   滚动升级

+   备份和恢复

# 安装 etcd 操作员

安装`etcd-operator`的最简单方法是使用 Helm-Kubernetes 包管理器。如果您尚未安装 Helm，请按照[`github.com/kubernetes/helm#install`](https://github.com/kubernetes/helm#install)中给出的说明进行操作。

然后，初始化`helm`：

```
> helm init 
Creating /Users/gigi.sayfan/.helm 
Creating /Users/gigi.sayfan/.helm/repository 
Creating /Users/gigi.sayfan/.helm/repository/cache 
Creating /Users/gigi.sayfan/.helm/repository/local 
Creating /Users/gigi.sayfan/.helm/plugins 
Creating /Users/gigi.sayfan/.helm/starters 
Creating /Users/gigi.sayfan/.helm/cache/archive 
Creating /Users/gigi.sayfan/.helm/repository/repositories.yaml 
Adding stable repo with URL: https://kubernetes-charts.storage.googleapis.com 
Adding local repo with URL: http://127.0.0.1:8879/charts 
$HELM_HOME has been configured at /Users/gigi.sayfan/.helm. 

Tiller (the Helm server-side component) has been installed into your Kubernetes Cluster. 
Happy Helming! 
```

我们将在第十三章中深入探讨 Helm，*处理 Kubernetes 包管理器*。目前，我们只是用它来安装`etcd`操作员。在支持 Kubernetes 1.8 的 Minikube 0.24.1 上（尽管 Kubernetes 1.10 已经发布），默认情况下存在一些权限问题。为了克服这些问题，我们需要创建一些角色和角色绑定。以下是`rbac.yaml`文件：

```
# Wide open access to the cluster (mostly for kubelet) 
kind: ClusterRole 
apiVersion: rbac.authorization.k8s.io/v1beta1 
metadata: 
  name: cluster-writer 
rules: 
  - apiGroups: ["*"] 
    resources: ["*"] 
    verbs: ["*"] 
  - nonResourceURLs: ["*"] 
    verbs: ["*"] 

--- 

# Full read access to the api and resources 
kind: ClusterRole 
apiVersion: rbac.authorization.k8s.io/v1beta1metadata: 
  name: cluster-reader 
rules: 
  - apiGroups: ["*"] 
    resources: ["*"] 
    verbs: ["get", "list", "watch"] 
  - nonResourceURLs: ["*"] 
    verbs: ["*"] 
--- 
# Give admin, kubelet, kube-system, kube-proxy god access 
kind: ClusterRoleBinding 
apiVersion: rbac.authorization.k8s.io/v1beta1metadata: 
  name: cluster-write 
subjects: 
  - kind: User 
    name: admin 
  - kind: User 
    name: kubelet 
  - kind: ServiceAccount 
    name: default 
    namespace: kube-system 
  - kind: User 
    name: kube-proxy 
roleRef: 
  kind: ClusterRole 
  name: cluster-writer 
  apiGroup: rbac.authorization.k8s.io 
```

您可以像应用其他 Kubernetes 清单一样应用它：

```
kubectl apply -f rbac.yaml.  
```

现在，我们终于可以安装`etcd-operator`了。我使用`x`作为一个简短的发布名称，以使输出更简洁。您可能希望使用更有意义的名称：

```
> helm install stable/etcd-operator --name x 
NAME:   x 
LAST DEPLOYED: Sun Jan  7 19:29:17 2018 
NAMESPACE: default 
STATUS: DEPLOYED 

RESOURCES: 
==> v1beta1/ClusterRole 
NAME                           AGE 
x-etcd-operator-etcd-operator  1s 

==> v1beta1/ClusterRoleBinding 
NAME                                   AGE 
x-etcd-operator-etcd-backup-operator   1s 
x-etcd-operator-etcd-operator          1s 
x-etcd-operator-etcd-restore-operator  1s 

==> v1/Service 
NAME                   TYPE       CLUSTER-IP    EXTERNAL-IP  PORT(S)    AGE 
etcd-restore-operator  ClusterIP  10.96.236.40  <none>       19999/TCP  1s 

==> v1beta1/Deployment 
NAME                                   DESIRED  CURRENT  UP-TO-DATE  AVAILABLE  AGE 
x-etcd-operator-etcd-backup-operator   1        1        1         0          1s 
x-etcd-operator-etcd-operator          1        1        1         0          1s 
x-etcd-operator-etcd-restore-operator  1        1        1         0          1s 

==> v1/ServiceAccount 
NAME                                   SECRETS  AGE 
x-etcd-operator-etcd-backup-operator   1        1s 
x-etcd-operator-etcd-operator          1        1s 
x-etcd-operator-etcd-restore-operator  1        1s 

NOTES: 
1\. etcd-operator deployed. 
  If you would like to deploy an etcd-cluster set cluster.enabled to true in values.yaml 
  Check the etcd-operator logs 
    export POD=$(kubectl get pods -l app=x-etcd-operator-etcd-operator --namespace default --output name) 
    kubectl logs $POD --namespace=default 
```

# 创建 etcd 集群

将以下内容保存到`etcd-cluster.yaml`中：

```
apiVersion: "etcd.database.coreos.com/v1beta2" 
kind: "EtcdCluster" 
metadata: 
  name: "etcd-cluster" 
spec: 
  size: 3 
  version: "3.2.13" 
```

要创建集群类型：

```
> k create -f etcd-cluster.yaml
etcdcluster "etcd-cluster" created

Let's verify the cluster pods were created properly:
> k get pods | grep etcd-cluster
etcd-cluster-0000                         1/1       Running   0          4m
etcd-cluster-0001                         1/1       Running   0          4m
etcd-cluster-0002                         1/1       Running   0          4m

```

# 验证 etcd 集群

一旦`etcd`集群正常运行，您可以访问`etcdctl`工具来检查集群状态和健康状况。Kubernetes 允许您通过`exec`命令（类似于 Docker exec）直接在 pod 或容器内执行命令。

以下是如何检查集群是否健康：

```
> k exec etcd-cluster-0000 etcdctl cluster-health
member 898a228a043c6ef0 is healthy: got healthy result from http://etcd-cluster-0001.etcd-cluster.default.svc:2379
member 89e2f85069640541 is healthy: got healthy result from http://etcd-cluster-0002.etcd-cluster.default.svc:2379
member 963265fbd20597c6 is healthy: got healthy result from http://etcd-cluster-0000.etcd-cluster.default.svc:2379
cluster is healthy  
```

以下是如何设置和获取键值对：

```
> k exec etcd-cluster-0000 etcdctl set test "Yeah, it works"
Yeah, it works
> k exec etcd-cluster-0000 etcdctl get test  
```

是的，它有效！

# 保护您的数据

保护集群状态和配置非常重要，但更重要的是保护您自己的数据。如果一些方式集群状态被损坏，您可以始终从头开始重建集群（尽管在重建期间集群将不可用）。但如果您自己的数据被损坏或丢失，您将陷入深深的麻烦。相同的规则适用；冗余是王道。然而，尽管 Kubernetes 集群状态非常动态，但您的许多数据可能不太动态。例如，许多历史数据通常很重要，可以进行备份和恢复。实时数据可能会丢失，但整个系统可以恢复到较早的快照，并且只会遭受暂时的损害。

# 运行冗余的 API 服务器

API 服务器是无状态的，可以从`etcd`集群中动态获取所有必要的数据。这意味着您可以轻松地运行多个 API 服务器，而无需在它们之间进行协调。一旦有多个 API 服务器运行，您可以在它们前面放置一个负载均衡器，使客户端对此毫无察觉。

# 在 Kubernetes 中运行领导者选举

一些主要组件，如调度程序和控制器管理器，不能同时处于活动状态。这将是一片混乱，因为多个调度程序尝试将相同的 pod 调度到多个节点或多次调度到同一节点。拥有高度可扩展的 Kubernetes 集群的正确方法是使这些组件以领导者选举模式运行。这意味着多个实例正在运行，但一次只有一个实例处于活动状态，如果它失败，另一个实例将被选为领导者并接替其位置。

Kubernetes 通过`leader-elect`标志支持这种模式。调度程序和控制器管理器可以通过将它们各自的清单复制到`/etc/kubernetes/manifests`来部署为 pod。

以下是调度程序清单中显示标志使用的片段：

```
command:
- /bin/sh
- -c
- /usr/local/bin/kube-scheduler --master=127.0.0.1:8080 --v=2 --leader-elect=true 1>>/var/log/kube-scheduler.log
2>&1
```

以下是控制器管理器清单中显示标志使用的片段：

```
- command:
- /bin/sh
- -c
- /usr/local/bin/kube-controller-manager --master=127.0.0.1:8080 --cluster-name=e2e-test-bburns
--cluster-cidr=10.245.0.0/16 --allocate-node-cidrs=true --cloud-provider=gce  --service-account-private-key-file=/srv/kubernetes/server.key
--v=2 --leader-elect=true 1>>/var/log/kube-controller-manager.log 2>&1
image: gcr.io/google_containers/kube-controller-manager:fda24638d51a48baa13c35337fcd4793 
```

请注意，这些组件无法像其他 pod 一样由 Kubernetes 自动重新启动，因为它们正是负责重新启动失败的 pod 的 Kubernetes 组件，因此如果它们失败，它们无法重新启动自己。必须已经有一个准备就绪的替代品正在运行。

# 应用程序的领导者选举

领导者选举对你的应用也可能非常有用，但实现起来非常困难。幸运的是，Kubernetes 来拯救了。有一个经过记录的程序，可以通过 Google 的`leader-elector`容器来支持你的应用进行领导者选举。基本概念是使用 Kubernetes 端点结合`ResourceVersion`和`Annotations`。当你将这个容器作为你的应用 pod 的 sidecar 时，你可以以非常简化的方式获得领导者选举的能力。

让我们使用三个 pod 运行`leader-elector`容器，并进行名为 election 的选举：

```
> kubectl run leader-elector --image=gcr.io/google_containers/leader-elector:0.5 --replicas=3 -- --election=election -http=0.0.0.0:4040
```

过一段时间，你会在你的集群中看到三个名为`leader-elector-xxx`的新 pod。

```
> kubectl get pods | grep elect
leader-elector-57746fd798-7s886                1/1       Running   0          39s
leader-elector-57746fd798-d94zx                1/1       Running   0          39s
leader-elector-57746fd798-xcljl                1/1       Running   0          39s 
```

好了。但是谁是主人？让我们查询选举端点：

```
    > kubectl get endpoints election -o json
    {
        "apiVersion": "v1",
        "kind": "Endpoints",
        "metadata": {
            "annotations": {
                "control-plane.alpha.kubernetes.io/leader": "{\"holderIdentity\":\"leader-elector-57746fd798-xcljl\",\"leaseDurationSeconds\":10,\"acquireTime\":\"2018-01-08T04:16:40Z\",\"renewTime\":\"2018-01-08T04:18:26Z\",\"leaderTransitions\":0}"
            },
            "creationTimestamp": "2018-01-08T04:16:40Z",
            "name": "election",
            "namespace": "default",
            "resourceVersion": "1090942",
            "selfLink": "/api/v1/namespaces/default/endpoints/election",
            "uid": "ba42f436-f42a-11e7-abf8-080027c94384"
        },
        "subsets": null
    }  
```

如果你仔细查看，你可以在`metadata.annotations`中找到它。为了方便检测，我推荐使用神奇的`jq`程序来切割和解析 JSON（[`stedolan.github.io/jq/`](https://stedolan.github.io/jq/)）。它非常有用，可以解析 Kubernetes API 或`kubectl`的输出：

```
> kubectl get endpoints election -o json | jq -r .metadata.annotations[] | jq .holderIdentity
"leader-elector-57746fd798-xcljl"
```

为了证明领导者选举有效，让我们杀死领导者，看看是否选举出了新的领导者：

```
> kubectl delete pod leader-elector-916043122-10wjj
pod "leader-elector-57746fd798-xcljl" deleted 
```

我们有了一个新的领导者：

```
> kubectl get endpoints election -o json | jq -r .metadata.annotations[] | jq .holderIdentity
"leader-elector-57746fd798-d94zx"  
```

你也可以通过 HTTP 找到领导者，因为每个`leader-elector`容器都通过一个本地 web 服务器（运行在端口`4040`上）来暴露领导者，尽管一个代理：

```
> kubectl proxy 
In a separate console:

> curl http://localhost:8001/api/v1/proxy/namespaces/default/pods/leader-elector-57746fd798-d94zx:4040/ | jq .name
"leader-elector-57746fd798-d94zx"  
```

本地 web 服务器允许 leader-elector 容器作为同一个 pod 中主应用容器的 sidecar 容器运行。你的应用容器与`leader-elector`容器共享同一个本地网络，因此它可以访问`http://localhost:4040`并获取当前领导者的名称。只有与当选领导者共享 pod 的应用容器才会运行应用程序；其他 pod 中的应用容器将处于休眠状态。如果它们收到请求，它们将把请求转发给领导者，或者可以通过一些巧妙的负载均衡技巧自动将所有请求发送到当前的领导者。

# 使你的暂存环境高度可用

高可用性的设置很重要。如果您费心设置高可用性，这意味着存在高可用性系统的业务案例。因此，您希望在部署到生产环境之前测试可靠且高可用的集群（除非您是 Netflix，在那里您在生产环境中进行测试）。此外，理论上，对集群的任何更改都可能破坏高可用性，而不会影响其他集群功能。关键点是，就像其他任何事物一样，如果您不进行测试，就假设它不起作用。

我们已经确定您需要测试可靠性和高可用性。最好的方法是创建一个尽可能接近生产环境的分阶段环境。这可能会很昂贵。有几种方法可以管理成本：

+   **临时高可用性（HA）分阶段环境**：仅在 HA 测试期间创建一个大型 HA 集群

+   **压缩时间**：提前创建有趣的事件流和场景，输入并快速模拟情况

+   **将 HA 测试与性能和压力测试相结合**：在性能和压力测试结束时，超载系统，看可靠性和高可用性配置如何处理负载

# 测试高可用性

测试高可用性需要计划和对系统的深入了解。每项测试的目标是揭示系统设计和/或实施中的缺陷，并提供足够的覆盖范围，如果测试通过，您将对系统的行为感到满意。

在可靠性和高可用性领域，这意味着您需要找出破坏系统并观察其自我修复的方法。

这需要几个部分，如下：

+   可能故障的全面列表（包括合理的组合）

+   对于每种可能的故障，系统应该如何做出清晰的响应

+   诱发故障的方法

+   观察系统反应的方法

这些部分都不是微不足道的。根据我的经验，最好的方法是逐步进行，并尝试提出相对较少的通用故障类别和通用响应，而不是详尽且不断变化的低级故障列表。

例如，一个通用的故障类别是节点无响应；通用的响应可能是重启节点。诱发故障的方法可以是停止节点的虚拟机（如果是虚拟机），观察应该是，尽管节点宕机，系统仍然根据标准验收测试正常运行。节点最终恢复正常，系统恢复正常。您可能还想测试许多其他事情，比如问题是否已记录，相关警报是否已发送给正确的人，以及各种统计数据和报告是否已更新。

请注意，有时故障无法在单一响应中解决。例如，在我们的节点无响应案例中，如果是硬件故障，那么重启是无济于事的。在这种情况下，第二种响应方式就会发挥作用，也许会启动、配置并连接到节点的新虚拟机。在这种情况下，您不能太通用，可能需要为节点上的特定类型的 pod/角色创建测试（etcd、master、worker、数据库和监控）。

如果您有高质量的要求，那么准备花费比生产环境更多的时间来设置适当的测试环境和测试。

最后，一个重要的观点是尽量不要侵入。这意味着，理想情况下，您的生产系统不会具有允许关闭部分系统或导致其配置为以减少容量运行进行测试的测试功能。原因是这会增加系统的攻击面，并且可能会因配置错误而意外触发。理想情况下，您可以在不修改将部署在生产环境中的代码或配置的情况下控制测试环境。使用 Kubernetes，通常很容易向暂存环境中的 pod 和容器注入自定义测试功能，这些功能可以与系统组件交互，但永远不会部署在生产环境中。

在本节中，我们看了一下实际上拥有可靠和高可用的集群所需的条件，包括 etcd、API 服务器、调度器和控制器管理器。我们考虑了保护集群本身以及您的数据的最佳实践，并特别关注了启动环境和测试的问题。

# 实时集群升级

在运行 Kubernetes 集群中涉及的最复杂和风险最高的任务之一是实时升级。不同版本系统的不同部分之间的交互通常很难预测，但在许多情况下是必需的。具有许多用户的大型集群无法承担维护期间的离线状态。攻击复杂性的最佳方法是分而治之。微服务架构在这里非常有帮助。您永远不会升级整个系统。您只是不断升级几组相关的微服务，如果 API 已更改，那么也会升级它们的客户端。一个经过良好设计的升级将至少保留向后兼容性，直到所有客户端都已升级，然后在几个版本中弃用旧的 API。

在本节中，我们将讨论如何使用各种策略升级您的集群，例如滚动升级和蓝绿升级。我们还将讨论何时适合引入破坏性升级与向后兼容升级。然后，我们将进入关键的模式和数据迁移主题。

# 滚动升级

滚动升级是逐渐将组件从当前版本升级到下一个版本的升级。这意味着您的集群将同时运行当前版本和新版本的组件。这里有两种情况需要考虑：

+   新组件向后兼容

+   新组件不向后兼容

如果新组件向后兼容，那么升级应该非常容易。在 Kubernetes 的早期版本中，您必须非常小心地使用标签管理滚动升级，并逐渐改变旧版本和新版本的副本数量（尽管`kubectl`滚动更新是复制控制器的便捷快捷方式）。但是，在 Kubernetes 1.2 中引入的部署资源使其变得更加容易，并支持副本集。它具有以下内置功能：

+   运行服务器端（如果您的机器断开连接，它将继续运行）

+   版本控制

+   多个并发部署

+   更新部署

+   汇总所有 pod 的状态

+   回滚

+   金丝雀部署

+   多种升级策略（滚动升级是默认值）

这是一个部署三个 NGINX pod 的部署示例清单：

```
apiVersion: extensions/v1beta1 
kind: Deployment 
metadata: 
  name: nginx-deployment 
spec: 
  replicas: 3 
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

资源种类是部署，它的名称是`nginx-deployment`，您可以在以后引用此部署（例如，用于更新或回滚）。最重要的部分当然是规范，其中包含一个 pod 模板。副本确定集群中将有多少个 pod，并且模板规范包含每个容器的配置：在这种情况下，只有一个容器。

要开始滚动更新，您需要创建部署资源：

```
$ kubectl create -f nginx-deployment.yaml --record  
```

您可以稍后使用以下命令查看部署的状态：

```
$ kubectl rollout status deployment/nginx-deployment  
```

# 复杂的部署

当您只想升级一个 pod 时，部署资源非常有用，但您经常需要升级多个 pod，并且这些 pod 有时存在版本相互依赖关系。在这种情况下，有时您必须放弃滚动更新或引入临时兼容层。例如，假设服务 A 依赖于服务 B。服务 B 现在有一个破坏性的变化。服务 A 的 v1 pod 无法与服务 B 的 v2 pod 进行交互操作。从可靠性和变更管理的角度来看，让服务 B 的 v2 pod 支持旧的和新的 API 是不可取的。在这种情况下，解决方案可能是引入一个适配器服务，该服务实现了 B 服务的 v1 API。该服务将位于 A 和 B 之间，并将跨版本转换请求和响应。这增加了部署过程的复杂性，并需要多个步骤，但好处是 A 和 B 服务本身很简单。您可以在不兼容版本之间进行滚动更新，一旦所有人升级到 v2（所有 A pod 和所有 B pod），所有间接性都将消失。

# 蓝绿升级

滚动更新对可用性来说非常好，但有时管理正确的滚动更新涉及的复杂性被认为太高，或者它增加了大量工作，推迟了更重要的项目。在这些情况下，蓝绿升级提供了一个很好的替代方案。使用蓝绿发布，您准备了一个完整的生产环境的副本，其中包含新版本。现在你有两个副本，旧的（蓝色）和新的（绿色）。蓝色和绿色哪个是哪个并不重要。重要的是你有两个完全独立的生产环境。目前，蓝色是活动的并处理所有请求。您可以在绿色上运行所有测试。一旦满意，您可以切换绿色变为活动状态。如果出现问题，回滚同样容易；只需从绿色切换回蓝色。我在这里优雅地忽略了存储和内存状态。这种立即切换假设蓝色和绿色只由无状态组件组成，并共享一个公共持久层。

如果存储发生了变化或对外部客户端可访问的 API 发生了破坏性变化，则需要采取额外的步骤。例如，如果蓝色和绿色有自己的存储，那么所有传入的请求可能需要同时发送到蓝色和绿色，并且绿色可能需要从蓝色那里摄取历史数据以在切换之前同步。

# 管理数据合同变更

数据合同描述数据的组织方式。这是结构元数据的一个总称。数据库模式是最典型的例子。最常见的例子是关系数据库模式。其他例子包括网络负载、文件格式，甚至字符串参数或响应的内容。如果有配置文件，那么这个配置文件既有文件格式（JSON、YAML、TOML、XML、INI 和自定义格式），也有一些内部结构，描述了什么样的层次结构、键、值和数据类型是有效的。有时，数据合同是显式的，有时是隐式的。无论哪种方式，您都需要小心管理它，否则当读取、解析或验证数据时遇到不熟悉的结构时，就会出现运行时错误。

# 迁移数据

数据迁移是一件大事。如今，许多系统管理着以 TB、PB 或更多为单位的数据。在可预见的未来，收集和管理的数据量将继续增加。数据收集的速度超过了硬件创新的速度。关键点是，如果您有大量数据需要迁移，这可能需要一段时间。在以前的一家公司，我负责一个项目，将近 100TB 的数据从一个传统系统的 Cassandra 集群迁移到另一个 Cassandra 集群。

第二个 Cassandra 集群具有不同的架构，并且由 Kubernetes 集群全天候访问。该项目非常复杂，因此在紧急问题出现时，它一直被推迟。传统系统仍然与新一代系统并存，远远超出了最初的估计时间。

有很多机制可以将数据分割并发送到两个集群，但是我们遇到了新系统的可扩展性问题，我们必须在继续之前解决这些问题。历史数据很重要，但不必以与最近的热数据相同的服务水平访问。因此，我们着手进行了另一个项目，将历史数据发送到更便宜的存储中。当然，这意味着客户库或前端服务必须知道如何查询两个存储并合并结果。当您处理大量数据时，您不能认为任何事情都是理所当然的。您会遇到工具、基础设施、第三方依赖和流程的可扩展性问题。大规模不仅仅是数量的变化，通常也是质量的变化。不要指望一切都会顺利进行。这远不止是从 A 复制一些文件到 B。

# 弃用 API

API 的弃用有两种情况：内部和外部。内部 API 是由您和您的团队或组织完全控制的组件使用的 API。您可以确保所有 API 用户将在短时间内升级到新的 API。外部 API 是由您直接影响范围之外的用户或服务使用的。有一些灰色地带的情况，您在一个庞大的组织（比如谷歌）工作，甚至内部 API 可能需要被视为外部 API。如果您很幸运，所有外部 API 都由自更新的应用程序或通过您控制的 Web 界面使用。在这些情况下，API 实际上是隐藏的，您甚至不需要发布它。

如果您有很多用户（或者一些非常重要的用户）使用您的 API，您应该非常谨慎地考虑弃用。弃用 API 意味着您强迫用户更改其应用程序以与您合作，或者保持与早期版本的锁定。

有几种方法可以减轻痛苦：

+   不要弃用。扩展现有 API 或保持以前的 API 活动。尽管这有时很简单，但会增加测试负担。

+   为您的目标受众提供所有相关编程语言的客户端库。这总是一个很好的做法。它允许您对底层 API 进行许多更改，而不会干扰用户（只要您保持编程语言接口稳定）。

+   如果必须弃用，请解释原因，为用户提供充足的升级时间，并尽可能提供支持（例如，带有示例的升级指南）。您的用户会感激的。

# 大型集群的性能、成本和设计权衡

在前一节中，我们看了现场集群升级。我们探讨了各种技术以及 Kubernetes 如何支持它们。我们还讨论了一些困难的问题，比如破坏性变化、数据合同变化、数据迁移和 API 弃用。在本节中，我们将考虑大型集群的各种选项和配置，具有不同的可靠性和高可用性属性。当您设计您的集群时，您需要了解您的选项，并根据您组织的需求进行明智的选择。

在本节中，我们将涵盖各种可用性要求，从尽力而为一直到零停机的圣杯，对于每个可用性类别，我们将考虑从性能和成本的角度来看它意味着什么。

# 可用性要求

不同的系统对可靠性和可用性有非常不同的要求。此外，不同的子系统有非常不同的要求。例如，计费系统总是高优先级，因为如果计费系统停机，您就无法赚钱。然而，即使在计费系统内部，如果有时无法争议费用，从业务角度来看可能也可以接受。

# 快速恢复

快速恢复是高可用集群的另一个重要方面。某些时候会出现问题。您的不可用时钟开始运行。您能多快恢复正常？

有时候，这不取决于你。例如，如果你的云服务提供商出现故障（而且你没有实施联合集群，我们稍后会讨论），那么你只能坐下来等待他们解决问题。但最有可能的罪魁祸首是最近部署的问题。当然，还有与时间相关的问题，甚至与日历相关的问题。你还记得 2012 年 2 月 29 日使微软 Azure 崩溃的闰年错误吗？

快速恢复的典范当然是蓝绿部署-如果在发现问题时保持之前的版本运行。

另一方面，滚动更新意味着如果问题早期被发现，那么大多数你的 pod 仍在运行之前的版本。

数据相关的问题可能需要很长时间才能解决，即使你的备份是最新的，而且你的恢复程序实际上是有效的（一定要定期测试）。

像 Heptio Ark 这样的工具在某些情况下可以帮助，它可以创建集群的快照备份，以防出现问题并且你不确定如何解决。

# 尽力而为

尽力而为意味着，反直觉地，根本没有任何保证。如果有效，太好了！如果不起作用-哦，好吧。你打算怎么办？这种可靠性和可用性水平可能适用于经常更改的内部组件，而使它们健壮的努力不值得。这也可能适用于作为测试版发布到公众的服务。

尽力而为对开发人员来说是很好的。开发人员可以快速移动并破坏事物。他们不担心后果，也不必经历严格测试和批准的考验。尽力而为服务的性能可能比更健壮的服务更好，因为它通常可以跳过昂贵的步骤，比如验证请求、持久化中间结果和复制数据。然而，另一方面，更健壮的服务通常经过了大量优化，其支持硬件也经过了对其工作负载的精细调整。尽力而为服务的成本通常较低，因为它们不需要使用冗余，除非运营商忽视了基本的容量规划，只是不必要地过度配置。

在 Kubernetes 的背景下，一个重要问题是集群提供的所有服务是否都是尽力而为的。如果是这种情况，那么集群本身就不需要高可用性。你可能只需要一个单一的主节点和一个单一的`etcd`实例，而 Heapster 或其他监控解决方案可能不需要部署。

# 维护窗口

在有维护窗口的系统中，专门的时间用于执行各种维护活动，如应用安全补丁、升级软件、修剪日志文件和数据库清理。在维护窗口期间，系统（或子系统）将不可用。这是计划中的非工作时间，并且通常会通知用户。维护窗口的好处是你不必担心维护操作会如何与系统中的实时请求交互。这可以极大地简化操作。系统管理员和开发人员一样喜欢维护窗口和尽力而为的系统。

当然，缺点是系统在维护期间会停机。这可能只适用于用户活动受限于特定时间（美国办公时间或仅工作日）的系统。

使用 Kubernetes，你可以通过将所有传入的请求重定向到负载均衡器上的网页（或 JSON 响应）来进行维护窗口。

但在大多数情况下，Kubernetes 的灵活性应该允许你进行在线维护。在极端情况下，比如升级 Kubernetes 版本，或从 etcd v2 切换到 etcd v3，你可能需要使用维护窗口。蓝绿部署是另一种选择。但集群越大，蓝绿部署的成本就越高，因为你必须复制整个生产集群，这既昂贵又可能导致你遇到配额不足的问题。

# 零停机

最后，我们来到了零停机系统。没有所谓的零停机系统。所有系统都会失败，所有软件系统肯定会失败。有时，故障严重到足以使系统或其某些服务宕机。把零停机看作是最佳努力的分布式系统设计。你设计零停机是指你提供了大量的冗余和机制来解决预期的故障，而不会使系统宕机。一如既往，要记住，即使有零停机的商业案例，也不意味着每个组件都必须是。

零停机计划如下：

+   **每个级别都要有冗余**：这是一个必要的条件。你的设计中不能有单一的故障点，因为一旦它失败，你的系统就会宕机。

+   **自动热插拔故障组件**：冗余只有在冗余组件能够在原始组件失败后立即启动时才有效。一些组件可以共享负载（例如无状态的 Web 服务器），因此不需要明确的操作。在其他情况下，比如 Kubernetes 调度器和控制器管理器，你需要进行领导者选举，以确保集群保持运行。

+   **大量的监控和警报以及早发现问题**：即使设计再谨慎，你可能会漏掉一些东西，或者一些隐含的假设可能会使你的设计失效。通常这样微妙的问题会悄悄地出现在你身上，如果足够关注，你可能会在它变成全面系统故障之前发现它。例如，假设当磁盘空间超过 90%时有一个清理旧日志文件的机制，但出于某种原因它不起作用。如果你设置一个警报，当磁盘空间超过 95%时，那么你就能发现并防止系统故障。

+   **部署到生产环境之前的顽强测试**：全面的测试已被证明是提高质量的可靠方法。为一个运行庞大的分布式系统的大型 Kubernetes 集群做全面测试是一项艰苦的工作，但你需要这样做。你应该测试什么？一切。没错，为了实现零停机，你需要同时测试应用程序和基础设施。你的 100%通过的单元测试是一个很好的开始，但它们并不能提供足够的信心，即当你在生产 Kubernetes 集群上部署应用程序时，它仍然会按预期运行。最好的测试当然是在蓝绿部署或相同集群后的生产集群上进行。如果没有完全相同的集群，可以考虑一个尽可能与生产环境相符的暂存环境。以下是你应该运行的测试列表。每个测试都应该全面，因为如果你留下一些未经测试的东西，它可能是有问题的：

+   +   单元测试

+   验收测试

+   性能测试

+   压力测试

+   回滚测试

+   数据恢复测试

+   渗透测试

听起来疯狂吗？很好。零停机的大规模系统很难。微软、谷歌、亚马逊、Facebook 和其他大公司有数以万计的软件工程师（合计）专门负责基础设施、运营，并确保系统正常运行。

+   **保留原始数据**：对于许多系统来说，数据是最关键的资产。如果保留原始数据，可以从后续发生的任何数据损坏和处理数据丢失中恢复。这并不能真正帮助实现零停机，因为重新处理原始数据可能需要一段时间，但它可以帮助实现零数据丢失，这通常更为重要。这种方法的缺点是，与处理后的数据相比，原始数据通常要大得多。一个好的选择可能是将原始数据存储在比处理数据更便宜的存储设备中。

+   **感知到的正常运行时间作为最后的手段**：好吧，系统的某个部分出现了问题。你可能仍然能够保持一定水平的服务。在许多情况下，你可能可以访问略旧的数据版本，或者让用户访问系统的其他部分。这并不是一个很好的用户体验，但从技术上讲，系统仍然可用。

# 性能和数据一致性

当你开发或操作分布式系统时，CAP 定理应该时刻放在脑后。CAP 代表一致性（Consistency）、可用性（Availability）和分区容忍性（Partition Tolerance）。该定理表示你最多只能拥有其中的两个。由于任何分布式系统在实践中都可能遭受网络分区，你可以在 CP 和 AP 之间做出选择。CP 意味着为了保持一致性，系统在网络分区发生时将不可用。AP 意味着系统将始终可用，但可能不一致。例如，来自不同分区的读取可能返回不同的结果，因为其中一个分区没有接收到写入。在本节中，我们将专注于高可用系统，即 AP。为了实现高可用性，我们必须牺牲一致性，但这并不意味着我们的系统将具有损坏或任意数据。关键词是最终一致性。我们的系统可能会落后一点，并提供对略微陈旧数据的访问，但最终你会得到你期望的结果。当你开始考虑最终一致性时，这将为潜在的性能改进打开大门。

举例来说，如果某个重要数值频繁更新（例如，每秒一次），但你只每分钟发送一次数值，那么你已经将网络流量减少了 60 倍，平均只落后实时更新 30 秒。这非常重要，非常巨大。你刚刚让系统能够处理 60 倍的用户或请求。

# 总结

在本章中，我们看了可靠且高可用的大规模 Kubernetes 集群。这可以说是 Kubernetes 的甜蜜点。虽然能够编排运行少量容器的小集群很有用，但并非必需，但在大规模情况下，你必须有一个编排解决方案，可以信任其与系统一起扩展，并提供工具和最佳实践来实现这一点。

你现在对分布式系统中可靠性和高可用性的概念有了扎实的理解。你已经深入了解了运行可靠且高可用的 Kubernetes 集群的最佳实践。你已经探讨了活动 Kubernetes 集群升级的微妙之处，并且可以在可靠性和可用性水平以及其性能和成本方面做出明智的设计选择。

在下一章中，我们将讨论 Kubernetes 中重要的安全主题。我们还将讨论保护 Kubernetes 的挑战和涉及的风险。您将学习有关命名空间、服务账户、准入控制、身份验证、授权和加密的所有内容。


# 第五章：配置 Kubernetes 安全性、限制和账户

在第四章中，*高可用性和可靠性*，我们讨论了可靠且高可用的 Kubernetes 集群，基本概念，最佳实践，如何进行实时集群升级，以及关于性能和成本的许多设计权衡。

在本章中，我们将探讨安全这一重要主题。Kubernetes 集群是由多个层次的相互作用组件组成的复杂系统。在运行关键应用程序时，不同层的隔离和分隔非常重要。为了保护系统并确保对资源、能力和数据的适当访问，我们必须首先了解 Kubernetes 作为一个运行未知工作负载的通用编排平台所面临的独特挑战。然后，我们可以利用各种安全、隔离和访问控制机制，确保集群和运行在其上的应用程序以及数据都是安全的。我们将讨论各种最佳实践以及何时适合使用每种机制。

在本章的结尾，您将对 Kubernetes 安全挑战有很好的理解。您将获得如何加固 Kubernetes 以抵御各种潜在攻击的实际知识，建立深度防御，并且甚至能够安全地运行多租户集群，同时为不同用户提供完全隔离以及对他们在集群中的部分拥有完全控制的能力。

# 理解 Kubernetes 安全挑战

Kubernetes 是一个非常灵活的系统，以通用方式管理非常低级别的资源。Kubernetes 本身可以部署在许多操作系统和硬件或虚拟机解决方案上，可以部署在本地或云端。Kubernetes 运行由运行时实现的工作负载，通过定义良好的运行时接口与之交互，但不了解它们是如何实现的。Kubernetes 操作关键资源，如网络、DNS 和资源分配，代表或为了应用程序服务，而对这些应用程序一无所知。这意味着 Kubernetes 面临着提供良好的安全机制和能力的艰巨任务，以便应用程序管理员可以使用，同时保护自身和应用程序管理员免受常见错误的影响。

在本节中，我们将讨论 Kubernetes 集群的几个层次或组件的安全挑战：节点、网络、镜像、Pod 和容器。深度防御是一个重要的安全概念，要求系统在每个层面都保护自己，既要减轻渗透其他层的攻击，也要限制入侵的范围和损害。认识到每个层面的挑战是向深度防御迈出的第一步。

# 节点挑战

节点是运行时引擎的主机。如果攻击者能够访问节点，这是一个严重的威胁。它至少可以控制主机本身和运行在其上的所有工作负载。但情况会变得更糟。节点上运行着一个与 API 服务器通信的 kubelet。一个复杂的攻击者可以用修改过的版本替换 kubelet，并通过与 Kubernetes API 服务器正常通信来有效地逃避检测，而不是运行预定的工作负载，收集有关整个集群的信息，并通过发送恶意消息来破坏 API 服务器和集群的其余部分。节点将可以访问共享资源和秘密，这可能使其渗透得更深。节点入侵非常严重，既因为可能造成的损害，也因为事后很难检测到它。

节点也可能在物理级别上受到损害。这在裸机上更相关，您可以知道哪些硬件分配给了 Kubernetes 集群。

另一个攻击向量是资源耗尽。想象一下，您的节点成为了一个与您的 Kubernetes 集群无关的机器人网络的一部分，它只运行自己的工作负载并耗尽 CPU 和内存。这里的危险在于 Kubernetes 和您的基础设施可能会自动扩展并分配更多资源。

另一个问题是安装调试和故障排除工具，或者在自动部署之外修改配置。这些通常是未经测试的，如果被遗留并激活，它们至少会导致性能下降，但也可能引起更严重的问题。至少会增加攻击面。

在涉及安全性的地方，这是一个数字游戏。您希望了解系统的攻击面以及您的脆弱性。让我们列出所有的节点挑战：

+   攻击者控制主机

+   攻击者替换 kubelet

+   攻击者控制运行主要组件（API 服务器、调度器和控制器管理器）的节点

+   攻击者获得对节点的物理访问权限

+   攻击者耗尽与 Kubernetes 集群无关的资源

+   通过安装调试和故障排除工具或更改配置造成自我伤害

任何重要的 Kubernetes 集群至少跨越一个网络。与网络相关的挑战很多。您需要非常详细地了解系统组件是如何连接的。哪些组件应该相互通信？它们使用什么网络协议？使用什么端口？它们交换什么数据？您的集群如何与外部世界连接？

暴露端口和服务的复杂链路：

+   容器到主机

+   主机到内部网络中的主机

+   主机到世界

使用覆盖网络（将在第十章中更多讨论，*高级 Kubernetes 网络*）可以帮助进行深度防御，即使攻击者获得对 Docker 容器的访问权限，它们也会被隔离，无法逃脱到底层网络基础设施。

发现组件也是一个很大的挑战。这里有几个选项，比如 DNS、专用发现服务和负载均衡器。每种方法都有一套利弊，需要仔细规划和洞察力才能在您的情况下得到正确的解决方案。

确保两个容器能够找到彼此并交换信息非常重要。

您需要决定哪些资源和端点应该是公开访问的。然后，您需要想出一个适当的方法来对用户和服务进行身份验证，并授权它们对资源进行操作。

敏感数据必须在进入和离开集群时进行加密，有时也需要在静态状态下进行加密。这意味着密钥管理和安全密钥交换，这是安全领域中最难解决的问题之一。

如果您的集群与其他 Kubernetes 集群或非 Kubernetes 进程共享网络基础设施，那么您必须对隔离和分离非常谨慎。

这些要素包括网络策略、防火墙规则和软件定义网络（SDN）。这个方案通常是定制的。这在本地和裸机集群中尤其具有挑战性。让我们回顾一下：

+   制定连接计划

+   选择组件、协议和端口

+   找出动态发现

+   公共与私有访问

+   身份验证和授权

+   设计防火墙规则

+   决定网络策略

+   密钥管理和交换

在网络层面，容器、用户和服务之间相互找到并交流变得更加容易，与此同时，也需要限制访问并防止网络攻击或对网络本身的攻击之间保持不断的紧张关系。

这些挑战中许多并非特定于 Kubernetes。然而，Kubernetes 是一个管理关键基础设施并处理低级网络的通用平台，这使得有必要考虑动态和灵活的解决方案，可以将系统特定要求整合到 Kubernetes 中。

# 图像挑战

Kubernetes 运行符合其运行时引擎之一的容器。它不知道这些容器在做什么（除了收集指标）。您可以通过配额对容器施加一定的限制。您还可以通过网络策略限制它们对网络其他部分的访问。然而，最终，容器确实需要访问主机资源、网络中的其他主机、分布式存储和外部服务。图像决定了容器的行为。图像存在两类问题：

+   恶意图像

+   易受攻击的图像

恶意图像是包含由攻击者设计的代码或配置的图像，用于造成一些伤害或收集信息。恶意代码可以被注入到您的图像准备流水线中，包括您使用的任何图像存储库。或者，您可能安装了被攻击的第三方图像，这些图像现在可能包含恶意代码。

易受攻击的图像是您设计的图像（或您安装的第三方图像），恰好包含一些漏洞，允许攻击者控制正在运行的容器或造成其他伤害，包括以后注入他们自己的代码。

很难说哪一类更糟。在极端情况下，它们是等价的，因为它们允许完全控制容器。其他防御措施已经就位（记得深度防御吗？），并且对容器施加的限制将决定它可以造成多大的破坏。减少恶意镜像的危险非常具有挑战性。使用微服务的快速移动公司可能每天生成许多镜像。验证镜像也不是一件容易的事。例如，考虑 Docker 镜像由多层组成。包含操作系统的基础镜像可能在发现新漏洞时随时变得容易受攻击。此外，如果您依赖他人准备的基础镜像（非常常见），那么恶意代码可能会进入这些您无法控制并且绝对信任的基础镜像中。

总结镜像挑战：

+   Kubernetes 不知道镜像在做什么

+   Kubernetes 必须为指定功能提供对敏感资源的访问

+   保护镜像准备和交付管道（包括镜像仓库）是困难的

+   快速开发和部署新镜像的速度可能与仔细审查更改的冲突

+   包含操作系统的基础镜像很容易过时并变得容易受攻击

+   基础镜像通常不受您控制，更容易受到恶意代码的注入

+   集成静态镜像分析器，如 CoreOS Clair，可以帮助很多。

# 配置和部署的挑战

Kubernetes 集群是远程管理的。各种清单和策略确定了集群在每个时间点的状态。如果攻击者能够访问具有对集群的管理控制的机器，他们可以造成严重破坏，比如收集信息、注入恶意镜像、削弱安全性和篡改日志。通常情况下，错误和失误可能同样有害，影响重要的安全措施，并使集群容易受到攻击。如今，拥有对集群的管理访问权限的员工经常在家或咖啡店远程工作，并随身携带笔记本电脑，他们离打开防护门只有一个 `kubectl` 命令的距离。

让我们重申挑战：

+   Kubernetes 是远程管理的

+   具有远程管理访问权限的攻击者可以完全控制集群

+   配置和部署通常比代码更难测试

+   远程或外出办公的员工面临延长的暴露风险，使攻击者能够以管理员权限访问他们的笔记本电脑或手机

# Pod 和容器方面的挑战

在 Kubernetes 中，pod 是工作单位，包含一个或多个容器。Pod 只是一个分组和部署构造，但在实践中，部署在同一个 pod 中的容器通常通过直接机制进行交互。所有容器共享相同的本地主机网络，并经常共享来自主机的挂载卷。同一 pod 中容器之间的轻松集成可能导致主机的部分暴露给所有容器。这可能允许一个恶意或易受攻击的恶意容器打开对其他容器的升级攻击的途径，然后接管节点本身。主要附加组件通常与主要组件共同存在，并呈现出这种危险，特别是因为它们中的许多是实验性的。对于在每个节点上运行 pod 的守护程序集也是如此。

多容器 pod 的挑战包括以下内容：

+   相同的 pod 容器共享本地主机网络

+   相同的 pod 容器有时会共享主机文件系统上的挂载卷

+   恶意容器可能会影响 pod 中的其他容器

+   如果与访问关键节点资源的其他容器共同存在，恶意容器更容易攻击节点

+   实验性的附加组件与主要组件共同存在时，可能是实验性的并且安全性较低

# 组织、文化和流程方面的挑战

安全性通常与生产力相矛盾。这是一种正常的权衡，无需担心。传统上，当开发人员和运营是分开的时，这种冲突是在组织层面上管理的。开发人员推动更多的生产力，并将安全要求视为业务成本。运营控制生产环境，并负责访问和安全程序。DevOps 运动打破了开发人员和运营之间的壁垒。现在，开发速度往往占据主导地位。诸如持续部署-在没有人为干预的情况下每天部署多次-这样的概念在大多数组织中是闻所未闻的。Kubernetes 是为这种新型云原生应用程序的世界而设计的。然而，它是基于谷歌的经验开发的。谷歌有大量时间和熟练的专家来开发平衡快速部署和安全性的适当流程和工具。对于较小的组织，这种平衡可能非常具有挑战性，安全性可能会受到影响。

采用 Kubernetes 的组织面临的挑战如下：

+   控制 Kubernetes 操作的开发人员可能不太关注安全性

+   开发速度可能被认为比安全性更重要

+   持续部署可能会使难以在达到生产之前检测到某些安全问题

+   较小的组织可能没有足够的知识和专业技能来正确管理 Kubernetes 集群的安全性

在本节中，我们回顾了在尝试构建安全的 Kubernetes 集群时所面临的许多挑战。这些挑战大多数并非特定于 Kubernetes，但使用 Kubernetes 意味着系统的大部分是通用的，并且不知道系统正在做什么。在试图锁定系统时，这可能会带来问题。这些挑战分布在不同的层次上：

+   节点挑战

+   网络挑战

+   镜像挑战

+   配置和部署挑战

+   Pod 和容器挑战

+   组织和流程挑战

在下一节中，我们将看一下 Kubernetes 提供的设施，以解决其中一些挑战。许多挑战需要在更大的系统级别上找到解决方案。重要的是要意识到仅仅使用所有 Kubernetes 安全功能是不够的。

# 加固 Kubernetes

前一节列出了开发人员和管理员在部署和维护 Kubernetes 集群时面临的各种安全挑战。在本节中，我们将专注于 Kubernetes 提供的设计方面、机制和功能，以解决其中一些挑战。通过审慎使用功能，如服务账户、网络策略、身份验证、授权、准入控制、AppArmor 和秘密，您可以达到一个相当良好的安全状态。

记住，Kubernetes 集群是一个更大系统的一部分，包括其他软件系统、人员和流程。Kubernetes 不能解决所有问题。您应始终牢记一般安全原则，如深度防御、需要知道的基础和最小特权原则。此外，记录您认为在攻击事件中可能有用的所有内容，并设置警报，以便在系统偏离其状态时进行早期检测。这可能只是一个错误，也可能是一次攻击。无论哪种情况，您都希望了解并做出响应。

# 了解 Kubernetes 中的服务账户

Kubernetes 在集群外部管理常规用户，用于连接到集群的人员（例如，通过`kubectl`命令），并且它还有服务账户。

常规用户是全局的，可以访问集群中的多个命名空间。服务账户受限于一个命名空间。这很重要。它确保了命名空间的隔离，因为每当 API 服务器从一个 pod 接收到请求时，其凭据只适用于其自己的命名空间。

Kubernetes 代表 pod 管理服务账户。每当 Kubernetes 实例化一个 pod 时，它会为 pod 分配一个服务账户。当 pod 进程与 API 服务器交互时，服务账户将标识所有的 pod 进程。每个服务账户都有一组凭据挂载在一个秘密卷中。每个命名空间都有一个名为`default`的默认服务账户。当您创建一个 pod 时，它会自动分配默认服务账户，除非您指定其他服务账户。

您可以创建额外的服务账户。创建一个名为`custom-service-account.yaml`的文件，其中包含以下内容：

```
apiVersion: v1 
kind: ServiceAccount 
metadata: 
  name: custom-service-account 
Now type the following: 
kubectl create -f custom-service-account.yaml 
That will result in the following output: 
serviceaccount "custom-service-account" created 
Here is the service account listed alongside the default service account: 
> kubectl get serviceAccounts 
NAME                     SECRETS   AGE 
custom-service-account   1         3m 
default                  1         29d 
```

请注意，为您的新服务账户自动创建了一个秘密。

要获取更多详细信息，请输入以下内容：

```
> kubectl get serviceAccounts/custom-service-account -o yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  creationTimestamp: 2018-01-15T18:24:40Z
  name: custom-service-account
  namespace: default
  resourceVersion: "1974321"
  selfLink: /api/v1/namespaces/default/serviceaccounts/custom-service-account
  uid: 59bc3515-fa21-11e7-beab-080027c94384
  secrets:
  - name: custom-service-account-token-w2v7v  
```

您可以通过输入以下内容查看秘密本身，其中包括一个`ca.crt`文件和一个令牌：

```
kubectl get secrets/custom-service-account-token-w2v7v -o yaml  
```

# Kubernetes 如何管理服务账户？

API 服务器有一个名为服务账户准入控制器的专用组件。它负责在 pod 创建时检查是否有自定义服务账户，如果有，则确保自定义服务账户存在。如果没有指定服务账户，则分配默认服务账户。

它还确保 pod 具有`ImagePullSecrets`，当需要从远程镜像注册表中拉取镜像时是必要的。如果 pod 规范没有任何密钥，它将使用服务账户的`ImagePullSecrets`。

最后，它添加了一个包含 API 访问令牌的卷和一个`volumeSource`挂载在`/var/run/secrets/kubernetes.io/serviceaccount`上。

API 令牌是由另一个名为**令牌控制器**的组件创建并添加到密钥中，每当创建服务账户时。令牌控制器还监视密钥，并在密钥被添加或从服务账户中删除时添加或删除令牌。

服务账户控制器确保每个命名空间都存在默认的服务账户。

# 访问 API 服务器

访问 API 需要一系列步骤，包括身份验证、授权和准入控制。在每个阶段，请求可能会被拒绝。每个阶段由多个链接在一起的插件组成。以下图表说明了这一点：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/d1531a41-3d47-4fc0-8bbe-f435cc592581.png)

# 用户身份验证

当您首次创建集群时，会为您创建一个客户端证书和密钥。`Kubectl`使用它们在端口`443`上通过 TLS 与 API 服务器进行身份验证，反之亦然（加密的 HTTPS 连接）。您可以通过检查您的`.kube/config`文件找到您的客户端密钥和证书：

```
> cat ~/.kube/config | grep client

client-certificate: /Users/gigi.sayfan/.minikube/client.crt
client-key: /Users/gigi.sayfan/.minikube/client.key  
```

请注意，如果多个用户需要访问集群，创建者应以安全的方式向其他用户提供客户端证书和密钥。

这只是与 Kubernetes API 服务器本身建立基本的信任。您还没有进行身份验证。各种身份验证模块可能会查看请求并检查各种额外的客户端证书、密码、持有者令牌和 JWT 令牌（用于服务账户）。大多数请求需要经过身份验证的用户（常规用户或服务账户），尽管也有一些匿名请求。如果请求未能通过所有身份验证器进行身份验证，它将被拒绝，并返回 401 HTTP 状态码（未经授权，这有点名不副实）。

集群管理员通过向 API 服务器提供各种命令行参数来确定要使用的认证策略：

+   --client-ca-file=<filename>（用于文件中指定的 x509 客户端证书）

+   --token-auth-file=<filename>（用于文件中指定的持有者令牌）

+   --basic-auth-file=<filename>（用于文件中指定的用户/密码对）

+   --experimental-bootstrap-token-auth（用于`kubeadm`使用的引导令牌）

服务账户使用自动加载的认证插件。管理员可以提供两个可选标志：

+   --service-account-key-file=<filename>（用于签署持有者令牌的 PEM 编码密钥。如果未指定，将使用 API 服务器的 TLS 私钥。）

+   --service-account-lookup（如果启用，从 API 中删除的令牌将被撤销。）

还有其他几种方法，例如开放 ID 连接，Web 钩子，Keystone（OpenStack 身份服务）和认证代理。主题是认证阶段是可扩展的，并且可以支持任何认证机制。

各种认证插件将检查请求，并根据提供的凭据，将关联以下属性：

+   **用户名**（用户友好的名称）

+   **uid**（唯一标识符，比用户名更一致）

+   **组**（用户所属的一组组名）

+   **额外字段**（将字符串键映射到字符串值）

认证器完全不知道特定用户被允许做什么。他们只是将一组凭据映射到一组身份。授权者的工作是弄清楚请求对经过身份验证的用户是否有效。任何认证器接受凭据时，认证成功。认证器运行的顺序是未定义的。

# 模拟

用户可以模拟不同的用户（经过适当授权）。例如，管理员可能希望以权限较低的不同用户身份解决一些问题。这需要将模拟头传递给 API 请求。这些头是：

+   `模拟用户`：要扮演的用户名。

+   `模拟组`：这是要扮演的组名，可以多次提供以设置多个组。这是可选的，需要`模拟用户`。

+   `模拟额外-(额外名称)`：这是用于将额外字段与用户关联的动态标头。这是可选的，需要`模拟用户`。

使用`kubectl`，您可以传递`--as`和`--as-group`参数。

# 授权请求

一旦用户经过身份验证，授权就开始了。Kubernetes 具有通用的授权语义。一组授权模块接收请求，其中包括经过身份验证的用户名和请求的动词（`list`，`get`，`watch`，`create`等）。与身份验证不同，所有授权插件都将有机会处理任何请求。如果单个授权插件拒绝请求或没有插件发表意见，则将以`403` HTTP 状态码（禁止）拒绝请求。只有在至少有一个插件被接受且没有其他插件拒绝时，请求才会继续。

集群管理员通过指定`--authorization-mode`命令行标志来确定要使用哪些授权插件，这是一个逗号分隔的插件名称列表。

支持以下模式：

+   `--authorization-mode=AlwaysDeny`拒绝所有请求；在测试期间很有用。

+   `-authorization-mode=AlwaysAllow`允许所有请求；如果不需要授权，则使用。

+   `--authorization-mode=ABAC`允许使用简单的、基于本地文件的、用户配置的授权策略。**ABAC**代表**基于属性的访问控制**。

+   `--authorization-mode=RBAC`是一种基于角色的机制，授权策略存储在并由 Kubernetes API 驱动。**RBAC**代表**基于角色的访问控制**。

+   `--authorization-mode=Node`是一种特殊模式，用于授权 kubelet 发出的 API 请求。

+   `--authorization-mode=Webhook`允许授权由使用 REST 的远程服务驱动。

您可以通过实现以下简单的 Go 接口来添加自定义授权插件：

```
type Authorizer interface {
  Authorize(a Attributes) (authorized bool, reason string, err error)
    } 
```

`Attributes`输入参数也是一个接口，提供了您需要做出授权决定的所有信息：

```
type Attributes interface {
  GetUser() user.Info
  GetVerb() string
  IsReadOnly() bool
  GetNamespace() string
  GetResource() string
  GetSubresource() string
  GetName() string
  GetAPIGroup() string
  GetAPIVersion() string
  IsResourceRequest() bool
  GetPath() string
} 
```

# 使用准入控制插件

好的。请求已经经过身份验证和授权，但在执行之前还有一步。请求必须通过一系列的准入控制插件。与授权者类似，如果单个准入控制器拒绝请求，则请求将被拒绝。

准入控制器是一个很好的概念。其思想是可能存在全局集群关注点，这可能是拒绝请求的理由。没有准入控制器，所有授权者都必须意识到这些问题并拒绝请求。但是，有了准入控制器，这个逻辑可以执行一次。此外，准入控制器可以修改请求。准入控制器以验证模式或变异模式运行。通常情况下，集群管理员通过提供名为`admission-control`的命令行参数来决定运行哪些准入控制插件。该值是一个逗号分隔的有序插件列表。以下是 Kubernetes >= 1.9 的推荐插件列表（顺序很重要）：

```
--admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,PersistentVolumeLabel,DefaultStorageClass,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota,DefaultTolerationSeconds  
```

让我们看一些可用的插件（随时添加更多）：

+   `AlwaysAdmit`: 透传（我不确定为什么需要它）。

+   `AlwaysDeny`: 这拒绝一切（用于测试很有用）。

+   `AlwaysPullImages`: 这将新的 Pod 镜像拉取策略设置为 Always（在多租户集群中很有用，以确保没有凭据拉取私有镜像的 Pod 不使用它们）。

+   `DefaultStorageClass`: 这为未指定存储类的`PersistentVolumeClaim`创建请求添加了一个默认存储类。

+   `DefaultTollerationSeconds`: 这设置了 Pod 对污点的默认容忍时间（如果尚未设置）：`notready:NoExecute` 和 `notreachable:NoExecute`。

+   `DenyEscalatingExec`: 这拒绝对以提升的特权运行并允许主机访问的 Pod 执行和附加命令。这包括以特权运行、具有主机 IPC 命名空间访问权限和具有主机 PID 命名空间访问权限的 Pod。

+   `EventRateLimit`: 这限制了 API 服务器的事件洪水（Kubernetes 1.9 中的新功能）。

+   `ExtendedResourceToleration`: 这将节点上的污点与 GPU 和 FPGA 等特殊资源结合起来，与请求这些资源的 Pod 的容忍结合起来。最终结果是具有额外资源的节点将专门用于具有适当容忍的 Pod。

+   `ImagePolicyWebhook`: 这个复杂的插件连接到外部后端，根据镜像决定是否拒绝请求。

+   `Initializers`: 这通过修改要创建的资源的元数据来设置挂起的初始化器（基于`InitializerConfiguration`）。

+   `InitialResources`（实验性的）：如果未指定，这将根据历史使用情况分配计算资源和限制。

+   `LimitPodHardAntiAffinity`：拒绝定义了除 `kubernetes.io`/`hostname` 之外的反亲和拓扑键的任何 Pod 在 `requiredDuringSchedulingRequiredDuringExecution` 中。

+   `LimitRanger`：拒绝违反资源限制的请求。

+   `MutatingAdmissionWebhook`：按顺序调用已注册的能够修改目标对象的变异 Webhook。请注意，由于其他变异 Webhook 的潜在更改，不能保证更改会生效。

+   `NamespaceLifecycle`：拒绝在正在终止或不存在的命名空间中创建对象。

+   `ResourceQuota`：拒绝违反命名空间资源配额的请求。

+   `ServiceAccount`：这是服务账户的自动化。

+   `ValidatingAdmissionWebhook`：此准入控制器调用与请求匹配的任何验证 Webhook。匹配的 Webhook 会并行调用；如果其中任何一个拒绝请求，请求将失败。

正如您所看到的，准入控制插件具有多样的功能。它们支持命名空间范围的策略，并主要从资源管理的角度执行请求的有效性。这使授权插件可以专注于有效的操作。`ImagePolicyWebHook` 是验证镜像的入口，这是一个很大的挑战。`Initializers` 是动态准入控制的入口，您可以在其中部署自己的准入控制器，而无需将其编译到 Kubernetes 中。还有外部准入 Webhook，适用于诸如资源的语义验证（所有 Pod 是否具有标准的标签集？）等任务。

通过身份验证、授权和准入的各个阶段分别负责验证传入请求的责任划分，每个阶段都有自己的插件，使得复杂的过程变得更容易理解和使用。

# 保护 Pod

Pod 安全是一个主要关注点，因为 Kubernetes 调度 Pod 并让它们运行。为了保护 Pod 和容器，有几种独立的机制。这些机制一起支持深度防御，即使攻击者（或错误）绕过一个机制，也会被另一个机制阻止。

# 使用私有镜像仓库

这种方法让您非常有信心，您的集群只会拉取您之前审查过的镜像，并且您可以更好地管理升级。您可以在每个节点上配置`$HOME/.dockercfg`或`$HOME/.docker/config.json`。但是，在许多云提供商上，您无法这样做，因为节点是自动为您配置的。

# ImagePullSecrets

这种方法适用于云提供商上的集群。其思想是，注册表的凭据将由 pod 提供，因此无论它被安排在哪个节点上运行都无所谓。这避开了节点级别的`.dockercfg`问题。

首先，您需要为凭据创建一个`secret`对象：

```
> kubectl create secret the-registry-secret 
  --docker-server=<docker registry server> 
  --docker-username=<username> 
  --docker-password=<password> 
  --docker-email=<email>
secret "docker-registry-secret" created.  
```

如果需要，您可以为多个注册表（或同一注册表的多个用户）创建 secret。kubelet 将合并所有`ImagePullSecrets`。

然而，因为 pod 只能在其自己的命名空间中访问 secret，所以您必须在希望 pod 运行的每个命名空间中创建一个 secret。

一旦定义了 secret，您可以将其添加到 pod 规范中，并在集群上运行一些 pod。pod 将使用 secret 中的凭据从目标镜像注册表中拉取镜像：

```
apiVersion: v1 
kind: Pod 
metadata: 
  name: cool-pod 
  namespace: the-namespace 
spec: 
  containers: 
    - name: cool-container 
      image: cool/app:v1 
  imagePullSecrets: 
    - name: the-registry-secret 
```

# 指定安全上下文

安全上下文是一组操作系统级别的安全设置，例如 UID、gid、功能和 SELinux 角色。这些设置应用于容器级别作为容器安全内容。您可以指定将应用于 pod 中所有容器的 pod 安全上下文。pod 安全上下文还可以将其安全设置（特别是`fsGroup`和`seLinuxOptions`）应用于卷。

以下是一个示例 pod 安全上下文：

```
apiVersion: v1 
kind: Pod 
metadata: 
  name: hello-world 
spec: 
  containers: 
    ... 
  securityContext: 
    fsGroup: 1234 
    supplementalGroups: [5678] 
    seLinuxOptions: 
      level: "s0:c123,c456" 
```

容器安全上下文应用于每个容器，并覆盖了 pod 安全上下文。它嵌入在 pod 清单的容器部分中。容器上下文设置不能应用于卷，卷保持在 pod 级别。

以下是一个示例容器安全内容：

```
apiVersion: v1 
kind: Pod 
metadata: 
  name: hello-world 
spec: 
  containers: 
    - name: hello-world-container 
      # The container definition 
      # ... 
      securityContext: 
        privileged: true 
        seLinuxOptions: 
          level: "s0:c123,c456" 
```

# 使用 AppArmor 保护您的集群

`AppArmor`是一个 Linux 内核安全模块。使用`AppArmor`，您可以限制在容器中运行的进程对一组有限的资源的访问，例如网络访问、Linux 功能和文件权限。您可以通过配置`AppArmor`来配置配置文件。

# 要求

在 Kubernetes 1.4 中，AppArmor 支持作为 beta 版本添加。它并不适用于每个操作系统，因此您必须选择一个受支持的操作系统发行版才能利用它。Ubuntu 和 SUSE Linux 支持 AppArmor，并默认启用。其他发行版则具有可选的支持。要检查 AppArmor 是否已启用，请输入以下代码：

```
cat /sys/module/apparmor/parameters/enabled
 Y 
```

如果结果是`Y`，则已启用。

配置文件必须加载到内核中。请检查以下文件：

```
/sys/kernel/security/apparmor/profiles  
```

此时，只有 Docker 运行时支持`AppArmor`。

# 使用 AppArmor 保护 Pod

由于`AppArmor`仍处于 beta 阶段，因此您需要将元数据指定为注释，而不是`bonafide`字段；当它退出 beta 阶段时，这将发生变化。

要将配置文件应用于容器，请添加以下注释：

```
container.apparmor.security.beta.kubernetes.io/<container-name>: <profile-ref>
```

配置文件引用可以是默认配置文件，`runtime`/`default`，或者主机`localhost/<profile-name>`上的配置文件。

以下是一个防止写入文件的示例配置文件：

```
#include <tunables/global> 

profile k8s-apparmor-example-deny-write flags=(attach_disconnected) { 
  #include <abstractions/base> 

  file, 

  # Deny all file writes. 
  deny /** w, 
} 
```

AppArmor 不是 Kubernetes 资源，因此其格式不是您熟悉的 YAML 或 JSON。

要验证配置文件是否正确附加，请检查进程`1`的属性：

```
kubectl exec <pod-name> cat /proc/1/attr/current  
```

默认情况下，Pod 可以在集群中的任何节点上调度。这意味着配置文件应该加载到每个节点中。这是 DaemonSet 的一个经典用例。

# 编写 AppArmor 配置文件

手动编写`AppArmor`配置文件很重要。有一些工具可以帮助：`aa-genprof`和`aa-logprof`可以为您生成配置文件，并通过在应用程序中使用`AppArmor`的 complain 模式来帮助微调它。这些工具会跟踪应用程序的活动和`AppArmor`警告，并创建相应的配置文件。这种方法有效，但感觉有些笨拙。

我的最爱工具是 bane（[`github.com/jessfraz/bane`](https://github.com/jessfraz/bane)），它可以根据 TOML 语法生成`AppArmor`配置文件。Bane 配置文件非常易读且易于理解。以下是一个 bane 配置文件的片段：

```
    Name = "nginx-sample"
    [Filesystem]
    # read only paths for the container
    ReadOnlyPaths = [
      "/bin/**",
      "/boot/**",
      "/dev/**",
    ]

    # paths where you want to log on write
    LogOnWritePaths = [
      "/**"
    ]

    # allowed capabilities
    [Capabilities]
    Allow = [
      "chown",
      "setuid",
    ]

    [Network]
    Raw = false
    Packet = false
    Protocols = [
      "tcp",
      "udp",
      "icmp"
    ] 
```

生成的`AppArmor`配置文件相当复杂。

# Pod 安全策略

**Pod 安全策略**（**PSP**）自 Kubernetes 1.4 以来就作为 Beta 版本可用。必须启用它，并且还必须启用 PSP 准入控制来使用它们。PSP 在集群级别定义，并为 Pod 定义安全上下文。使用 PSP 和直接在 Pod 清单中指定安全内容之间有一些区别，就像我们之前所做的那样：

+   将相同的策略应用于多个 Pod 或容器

+   让管理员控制 Pod 的创建，以便用户不会创建具有不适当安全上下文的 Pod

+   通过准入控制器为 Pod 动态生成不同的安全内容

PSPs 真的扩展了安全上下文的概念。通常，与 Pod（或者说，Pod 模板）的数量相比，您将拥有相对较少的安全策略。这意味着许多 Pod 模板和容器将具有相同的安全策略。没有 PSP，您必须为每个 Pod 清单单独管理它。

这是一个允许一切的示例 PSP：

```
    {
      "kind": "PodSecurityPolicy",
      "apiVersion":"policy/v1beta1",
      "metadata": {
        "name": "permissive"
      },
      "spec": {
          "seLinux": {
              "rule": "RunAsAny"
          },
          "supplementalGroups": {
              "rule": "RunAsAny"
          },
          "runAsUser": {
              "rule": "RunAsAny"
          },
          "fsGroup": {
              "rule": "RunAsAny"
          },
          "volumes": ["*"]
      }
    }
```

# 通过 RBAC 授权 Pod 安全策略

这是启用策略使用的推荐方法。让我们创建`clusterRole`（`Role`也可以）来授予使用目标策略的访问权限。它应该是这样的：

```
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
 name: <role name>
rules:
- apiGroups: ['policy']
 resources: ['podsecuritypolicies']
 verbs: ['use']
 resourceNames:
 - <list of policies to authorize>
```

然后，我们需要将集群角色绑定到授权用户：

```
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
 name: <binding name>
roleRef:
 kind: ClusterRole
 name: <role name>
 apiGroup: rbac.authorization.k8s.io
subjects:
# Authorize specific service accounts:
- kind: ServiceAccount
 name: <authorized service account name>
 namespace: <authorized pod namespace>
# Authorize specific users (not recommended):
- kind: User
 apiGroup: rbac.authorization.k8s.io
 name: <authorized user name>
```

如果使用角色绑定而不是集群角色，则它将仅适用于与绑定相同命名空间中的 Pod。这可以与系统组配对，以授予对在命名空间中运行的所有 Pod 的访问权限：

```
# Authorize all service accounts in a namespace:
- kind: Group
 apiGroup: rbac.authorization.k8s.io
 name: system:serviceaccounts
# Or equivalently, all authenticated users in a namespace:
- kind: Group
 apiGroup: rbac.authorization.k8s.io
 name: system:authenticated
```

# 管理网络策略

节点、Pod 和容器的安全性至关重要，但这还不够。网络分割对于设计安全的 Kubernetes 集群至关重要，它允许多租户使用，并且可以最小化安全漏洞的影响。深度防御要求您对不需要相互通信的系统部分进行分隔，并允许您仔细管理流量的方向、协议和端口。

网络策略可以让您对集群的命名空间和通过标签选择的 Pod 进行细粒度控制和适当的网络分割。在其核心，网络策略是一组防火墙规则，应用于一组由标签选择的命名空间和 Pod。这非常灵活，因为标签可以定义虚拟网络段，并且可以作为 Kubernetes 资源进行管理。

# 选择支持的网络解决方案

一些网络后端不支持网络策略。例如，流行的 Flannel 无法应用于策略。

这是一个支持的网络后端列表：

+   Calico

+   WeaveNet

+   Canal

+   Cillium

+   Kube-Router

+   Romana

# 定义网络策略

您可以使用标准的 YAML 清单来定义网络策略。

这是一个示例策略：

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
 name: the-network-policy
 namespace: default
spec:
 podSelector:
 matchLabels:
 role: db
 ingress:
 - from:
 - namespaceSelector:
 matchLabels:
 project: cool-project
 - podSelector:
 matchLabels:
 role: frontend
 ports:
 - protocol: tcp
 port: 6379
```

`spec`部分有两个重要部分——`podSelector`和`ingress`。`podSelector`管理此网络策略适用于哪些 pod。`ingress`管理哪些命名空间和 pod 可以访问这些 pod，以及它们可以使用哪些协议和端口。

在示例网络策略中，`pod`选择器指定了网络策略的目标，即所有标记为`role: db`的 pod。`ingress`部分有一个`from`子部分，其中包括一个`namespace`选择器和一个`pod`选择器。集群中所有标记为`project: cool-project`的命名空间，以及这些命名空间中所有标记为`role: frontend`的 pod，都可以访问标记为`role: db`的目标 pod。`ports`部分定义了一对对（协议和端口），进一步限制了允许的协议和端口。在这种情况下，协议是`tcp`，端口是`6379`（Redis 标准端口）。

请注意，网络策略是集群范围的，因此集群中多个命名空间的 pod 可以访问目标命名空间。当前命名空间始终包括在内，因此即使它没有`project: cool`标签，带有`role: frontend`的`pods`仍然可以访问。

网络策略以白名单方式运行很重要。默认情况下，所有访问都被禁止，网络策略可以打开某些协议和端口，以匹配标签的某些 pod。这意味着，如果您的网络解决方案不支持网络策略，所有访问将被拒绝。

白名单性质的另一个含义是，如果存在多个网络策略，则所有规则的并集都适用。如果一个策略允许访问端口`1234`，另一个策略允许访问端口`5678`，那么一个 pod 可能访问端口`1234`或`5678`。

# 限制对外部网络的出口

Kubernetes 1.8 添加了出口网络策略支持，因此您也可以控制出站流量。以下是一个示例，阻止访问外部 IP`1.2.3.4`。`order: 999`确保在其他策略之前应用该策略：

```
apiVersion: v1
kind: policy
metadata:
 name: default-deny-egress
spec:
 order: 999
 egress:
 - action: deny
 destination:
 net: 1.2.3.4
 source: {}
```

# 跨命名空间策略

如果将集群划分为多个命名空间，有时如果 pod 跨命名空间通信，这可能会很方便。您可以在网络策略中指定`ingress.namespaceSelector`字段，以允许从多个命名空间访问。例如，如果您有生产和暂存命名空间，并且定期使用生产数据的快照填充暂存环境。

# 使用秘密

秘密在安全系统中至关重要。它们可以是凭据，如用户名和密码、访问令牌、API 密钥或加密密钥。秘密通常很小。如果您有大量要保护的数据，您应该对其进行加密，并将加密/解密密钥保留为秘密。

# 在 Kubernetes 中存储秘密

Kubernetes 默认将秘密以明文存储在`etcd`中。这意味着对`etcd`的直接访问是有限的并且受到仔细保护。从 Kubernetes 1.7 开始，您现在可以在休息时加密您的秘密（当它们由`etcd`存储时）。

秘密是在命名空间级别管理的。Pod 可以通过秘密卷将秘密挂载为文件，也可以将其作为环境变量。从安全的角度来看，这意味着可以创建命名空间中的任何用户或服务都可以访问为该命名空间管理的任何秘密。如果要限制对秘密的访问，请将其放在一组有限用户或服务可访问的命名空间中。

当秘密挂载到一个 pod 上时，它永远不会被写入磁盘。它存储在`tmpfs`中。当 kubelet 与 API 服务器通信时，通常使用 TLS，因此秘密在传输过程中受到保护。

# 配置休息时的加密

启动 API 服务器时，您需要传递此参数：

```
--experimental-encryption-provider-config <encryption config file>   
```

以下是一个样本加密配置：

```
kind: EncryptionConfig
apiVersion: v1
resources:
 - resources:
 - secrets
 providers:
 - identity: {}
 - aesgcm:
 keys:
 - name: key1
 secret: c2VjcmV0IGlzIHNlY3VyZQ==
 - name: key2
 secret: dGhpcyBpcyBwYXNzd29yZA==
 - aescbc:
 keys:
 - name: key1
 secret: c2VjcmV0IGlzIHNlY3VyZQ==
 - name: key2
 secret: dGhpcyBpcyBwYXNzd29yZA==
 - secretbox:
 keys:
 - name: key1
 secret: YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
```

# 创建秘密

在尝试创建需要它们的 pod 之前，必须先创建秘密。秘密必须存在；否则，pod 创建将失败。

您可以使用以下命令创建秘密：

```
kubectl create secret. 
```

在这里，我创建了一个名为`hush-hash`的通用秘密，其中包含两个键—用户名和密码：

```
> kubectl create secret generic hush-hush --from-literal=username=tobias --from-literal=password=cutoffs 
```

生成的秘密是`Opaque`：

```
> kubectl describe secrets/hush-hush
Name:           hush-hush
Namespace:      default
Labels:         <none>
Annotations:    <none>

Type:   Opaque

Data
====
password:       7 bytes
username:       6 bytes
```

您可以使用`--from-file`而不是`--from-literal`从文件创建秘密，并且如果将秘密值编码为`base64`，还可以手动创建秘密。

秘密中的键名必须遵循 DNS 子域的规则（不包括前导点）。

# 解码秘密

要获取秘密的内容，可以使用`kubectl get secret`：

```
> kubectl get secrets/hush-hush -o yaml
apiVersion: v1
data:
 password: Y3V0b2Zmcw==
 username: dG9iaWFz
kind: Secret
metadata:
 creationTimestamp: 2018-01-15T23:43:50Z
 name: hush-hush
 namespace: default
 resourceVersion: "2030851"
 selfLink: /api/v1/namespaces/default/secrets/hush-hush
 uid: f04641ef-fa4d-11e7-beab-080027c94384
type: Opaque
The values are base64-encoded. You need to decode them yourself:
> echo "Y3V0b2Zmcw==" | base64 --decode
cutoofs
```

这些值是`base64`编码的。您需要自己解码它们：

```
> echo "Y3V0b2Zmcw==" | base64 --decode
cutoofs 
```

# 在容器中使用秘密

容器可以通过从 pod 中挂载卷来将秘密作为文件访问。另一种方法是将秘密作为环境变量访问。最后，容器（如果其服务账户具有权限）可以直接访问 Kubernetes API 或使用 kubectl get secret。

要使用作为卷挂载的秘密，pod 清单应声明卷，并且应在容器的规范中挂载：

```
{ 
 "apiVersion": "v1", 
 "kind": "Pod", 
  "metadata": { 
    "name": "pod-with-secret", 
    "namespace": "default" 
  }, 
  "spec": { 
    "containers": [{ 
      "name": "the-container", 
      "image": "redis", 
      "volumeMounts": [{ 
        "name": "secret-volume", 
        "mountPath": "/mnt/secret-volume", 
        "readOnly": true 
      }] 
    }], 
    "volumes": [{ 
      "name": "secret-volume", 
      "secret": { 
        "secretName": "hush-hush" 
      } 
    }] 
  } 
} 
```

卷名称（`secret-volume`）将 pod 卷绑定到容器中的挂载点。多个容器可以挂载相同的卷。

当此 pod 运行时，用户名和密码将作为文件出现在`/etc/secret-volume`下：

```
> kubectl exec pod-with-secret cat /mnt/secret-volume/username
tobias

> kubectl exec pod-with-secret cat /mnt/secret-volume/password
cutoffs  
```

# 运行多用户集群

在本节中，我们将简要讨论使用单个集群来托管多个用户或多个用户社区的系统的选项。这个想法是这些用户是完全隔离的，甚至可能不知道他们与其他用户共享集群。每个用户社区都将拥有自己的资源，并且它们之间不会有通信（除非通过公共端点）。Kubernetes 命名空间概念是这个想法的最终表达。

# 多用户集群的情况

为什么要为多个隔离的用户或部署运行单个集群？每个用户都有一个专用的集群不是更简单吗？主要有两个原因：成本和运营复杂性。如果您有许多相对较小的部署，并且希望为每个部署创建一个专用的集群，那么您将需要为每个部署单独的主节点，可能还需要一个三节点的`etcd`集群。这可能会增加成本。运营复杂性也非常重要。管理数十甚至数百个独立的集群并不容易。每次升级和每次补丁都需要应用到每个集群。运营可能会失败，您将不得不管理一群集群，其中一些集群的状态可能与其他集群略有不同。跨所有集群的元操作可能更加困难。您将不得不聚合并编写您的工具来执行操作并从所有集群收集数据。

让我们看一些多个隔离社区或部署的用例和要求：

+   作为`<Blank>-`服务的平台或服务提供商

+   管理单独的测试、暂存和生产环境

+   将责任委托给社区/部署管理员

+   对每个社区强制执行资源配额和限制

+   用户只能看到他们社区中的资源

# 使用命名空间进行安全的多租户管理

Kubernetes 命名空间是安全的多租户集群的完美解决方案。这并不奇怪，因为这是命名空间的设计目标之一。

您可以轻松地创建除内置 kube 系统和默认之外的命名空间。以下是一个将创建一个名为`custom-namespace`的新命名空间的 YAML 文件。它只有一个名为`name`的元数据项。没有比这更简单的了：

```
apiVersion: v1 
kind: Namespace 
metadata: 
  name: custom-namespace 
```

让我们创建命名空间：

```
> Kubectl create -f custom-namespace.yaml
namespace "custom-namespace" created

> kubectl get namesapces
NAME               STATUS    AGE
custom-namespace   Active    39s
default            Active    32d
kube-system        Active    32d
```

状态字段可以是`active`或`terminating`。当您删除一个命名空间时，它将进入 terminating 状态。当命名空间处于此状态时，您将无法在此命名空间中创建新资源。这简化了命名空间资源的清理，并确保命名空间真正被删除。如果没有它，当现有 pod 被删除时，复制控制器可能会创建新的 pod。

要使用命名空间，您需要在`kubectl`命令中添加`--namespace`参数：

```
> kubectl create -f some-pod.yaml --namespace=custom-namespace
pod "some-pod" created
```

在自定义命名空间中列出 pod 只返回我们刚刚创建的 pod：

```
> kubectl get pods --namespace=custom-namespace
NAME       READY     STATUS    RESTARTS   AGE
some-pod   1/1       Running   0          6m 
```

在不带命名空间的情况下列出 pod 会返回默认命名空间中的 pod：

```
> Kubectl get pods
NAME                           READY     STATUS    RESTARTS   AGE
echo-3580479493-n66n4          1/1       Running   16         32d
leader-elector-191609294-lt95t 1/1       Running   4          9d
leader-elector-191609294-m6fb6 1/1       Running   4          9d
leader-elector-191609294-piu8p 1/1       Running   4          9d pod-with-secret                1/1       Running   1          1h
```

# 避免命名空间陷阱

命名空间很棒，但可能会增加一些摩擦。当您只使用默认命名空间时，可以简单地省略命名空间。当使用多个命名空间时，必须使用命名空间限定所有内容。这可能是一个负担，但不会带来任何危险。但是，如果一些用户（例如，集群管理员）可以访问多个命名空间，那么您就有可能意外修改或查询错误的命名空间。避免这种情况的最佳方法是将命名空间密封起来，并要求为每个命名空间使用不同的用户和凭据。

此外，工具可以帮助清楚地显示您正在操作的命名空间（例如，如果从命令行工作，则是 shell 提示，或者在 Web 界面中突出显示命名空间）。

确保可以在专用命名空间上操作的用户不能访问默认命名空间。否则，每当他们忘记指定命名空间时，他们将在默认命名空间上悄悄操作。

# 总结

在本章中，我们介绍了开发人员和管理员在 Kubernetes 集群上构建系统和部署应用程序时面临的许多安全挑战。但我们也探讨了许多安全功能和灵活的基于插件的安全模型，提供了许多限制、控制和管理容器、pod 和节点的方法。Kubernetes 已经为大多数安全挑战提供了多功能解决方案，随着诸如 AppArmor 和各种插件从 alpha/beta 状态转移到一般可用状态，它将变得更加完善。最后，我们考虑了如何使用命名空间来支持同一 Kubernetes 集群中的多个用户社区或部署。

在下一章中，我们将深入研究许多 Kubernetes 资源和概念，以及如何有效地使用它们并将它们组合起来。Kubernetes 对象模型是建立在一小部分通用概念（如资源、清单和元数据）的坚实基础之上的。这使得一个可扩展的、但令人惊讶地一致的对象模型能够为开发人员和管理员提供非常多样化的能力集。


# 第六章：使用关键的 Kubernetes 资源

在本章中，我们将设计一个挑战 Kubernetes 能力和可伸缩性的大规模平台。Hue 平台的目标是创建一个无所不知、无所不能的数字助手。Hue 是你的数字延伸。它将帮助你做任何事情，找到任何东西，并且在许多情况下，将代表你做很多事情。它显然需要存储大量信息，与许多外部服务集成，响应通知和事件，并且在与你的互动方面非常智能。

在本章中，我们将有机会更好地了解 Kubectl 和其他相关工具，并将详细探讨我们之前见过的资源，如 pod，以及新资源，如**jobs**。在本章结束时，你将清楚地了解 Kubernetes 有多么令人印象深刻，以及它如何可以作为极其复杂系统的基础。

# 设计 Hue 平台

在本节中，我们将为惊人的 Hue 平台设定舞台并定义范围。Hue 不是老大哥，Hue 是小弟！Hue 将做任何你允许它做的事情。它可以做很多事情，但有些人可能会担心，所以你可以选择 Hue 可以帮助你多少。准备好进行一次疯狂的旅行！

# 定义 Hue 的范围

Hue 将管理你的数字人格。它将比你自己更了解你。以下是 Hue 可以管理并帮助你的一些服务列表：

+   搜索和内容聚合

+   医疗

+   智能家居

+   金融-银行、储蓄、退休、投资

+   办公室

+   社交

+   旅行

+   健康

+   家庭

+   智能提醒和通知：让我们想想可能性。Hue 将了解你，也了解你的朋友和所有领域的其他用户的总和。Hue 将实时更新其模型。它不会被陈旧的数据所困扰。它将代表你采取行动，提供相关信息，并持续学习你的偏好。它可以推荐你可能喜欢的新节目或书籍，根据你的日程安排和家人或朋友的情况预订餐厅，并控制你的家庭自动化。

+   安全、身份和隐私：Hue 是您在线的代理。有人窃取您的 Hue 身份，甚至只是窃听您的 Hue 互动的后果是灾难性的。潜在用户甚至可能不愿意信任 Hue 组织他们的身份。让我们设计一个非信任系统，让用户随时有权终止 Hue。以下是一些朝着正确方向的想法：

+   通过专用设备和多因素授权实现强大的身份验证，包括多种生物识别原因

+   频繁更换凭证

+   快速服务暂停和所有外部服务的身份重新验证（将需要向每个提供者提供原始身份证明）

+   Hue 后端将通过短暂的令牌与所有外部服务进行交互

+   将 Hue 构建为一组松散耦合的微服务的架构。

Hue 的架构将需要支持巨大的变化和灵活性。它还需要非常可扩展，其中现有的功能和外部服务不断升级，并且新的功能和外部服务集成到平台中。这种规模需要微服务，其中每个功能或服务都与其他服务完全独立，除了通过标准和/或可发现的 API 进行定义的接口。

# Hue 组件

在着手进行微服务之旅之前，让我们回顾一下我们需要为 Hue 构建的组件类型。

+   用户资料：

用户资料是一个重要组成部分，有很多子组件。它是用户的本质，他们的偏好，跨各个领域的历史，以及 Hue 对他们了解的一切。

+   用户图：

用户图组件模拟了用户在多个领域之间的互动网络。每个用户参与多个网络：社交网络（如 Facebook 和 Twitter）、专业网络、爱好网络和志愿者社区。其中一些网络是临时的，Hue 将能够对其进行结构化以使用户受益。Hue 可以利用其对用户连接的丰富资料，即使不暴露私人信息，也能改善互动。

+   身份：

身份管理是至关重要的，正如前面提到的，因此它值得一个单独的组件。用户可能更喜欢管理具有独立身份的多个互斥配置文件。例如，也许用户不愿意将他们的健康配置文件与社交配置文件混合在一起，因为这样做可能会意外地向朋友透露个人健康信息的风险。

+   **授权者**：

授权者是一个关键组件，用户明确授权 Hue 代表其执行某些操作或收集各种数据。这包括访问物理设备、外部服务的帐户和主动程度。

+   **外部服务**：

Hue 是外部服务的聚合器。它并非旨在取代您的银行、健康提供者或社交网络。它将保留大量关于您活动的元数据，但内容将保留在您的外部服务中。每个外部服务都需要一个专用组件来与外部服务的 API 和政策进行交互。当没有 API 可用时，Hue 通过自动化浏览器或原生应用程序来模拟用户。

+   **通用传感器**：

Hue 价值主张的一个重要部分是代表用户行事。为了有效地做到这一点，Hue 需要意识到各种事件。例如，如果 Hue 为您预订了假期，但它感觉到有更便宜的航班可用，它可以自动更改您的航班或要求您确认。有无限多件事情可以感知。为了控制感知，需要一个通用传感器。通用传感器将是可扩展的，但提供一个通用接口，供 Hue 的其他部分统一使用，即使添加了越来越多的传感器。

+   **通用执行器**：

这是通用传感器的对应物。Hue 需要代表您执行操作，比如预订航班。为了做到这一点，Hue 需要一个通用执行器，可以扩展以支持特定功能，但可以以统一的方式与其他组件交互，比如身份管理器和授权者。

+   **用户学习者**：

这是 Hue 的大脑。它将不断监视您所有的互动（经您授权的），并更新对您的模型。这将使 Hue 随着时间变得越来越有用，预测您的需求和兴趣，提供更好的选择，在合适的时候提供更相关的信息，并避免让人讨厌和压抑。

# Hue 微服务

每个组件的复杂性都非常巨大。一些组件，比如外部服务、通用传感器和通用执行器，需要跨越数百、数千甚至更多不断变化的外部服务进行操作，而这些服务是在 Hue 的控制范围之外的。甚至用户学习器也需要学习用户在许多领域和领域的偏好。微服务通过允许 Hue 逐渐演变并增加更多的隔离能力来满足这种需求，而不会在自身的复杂性下崩溃。每个微服务通过标准接口与通用 Hue 基础设施服务进行交互，并且可以通过明确定义和版本化的接口与其他一些服务进行交互。每个微服务的表面积是可管理的，微服务之间的编排基于标准最佳实践：

+   **插件**：

插件是扩展 Hue 而不会产生大量接口的关键。关于插件的一件事是，通常需要跨越多个抽象层的插件链。例如，如果我们想要为 Hue 添加与 YouTube 的新集成，那么你可以收集大量特定于 YouTube 的信息：你的频道、喜欢的视频、推荐以及你观看过的视频。为了向用户显示这些信息并允许他们对其进行操作，你需要跨越多个组件并最终在用户界面中使用插件。智能设计将通过聚合各种操作类别，如推荐、选择和延迟通知，来帮助许多不同的服务。

插件的好处在于任何人都可以开发。最初，Hue 开发团队将不得不开发插件，但随着 Hue 变得更加流行，外部服务将希望与 Hue 集成并构建 Hue 插件以启用其服务。

当然，这将导致插件注册、批准和策划的整个生态系统。

+   **数据存储**：

Hue 将需要多种类型的数据存储和每种类型的多个实例来管理其数据和元数据：

+   +   关系数据库

+   图数据库

+   时间序列数据库

+   内存缓存

由于 Hue 的范围，每个数据库都将需要进行集群化和分布式处理。

+   **无状态微服务**：

微服务应该大部分是无状态的。这将允许特定实例被快速启动和关闭，并根据需要在基础设施之间迁移。状态将由存储管理，并由短暂的访问令牌访问微服务。

+   **基于队列的交互**：

所有这些微服务需要相互通信。用户将要求 Hue 代表他们执行任务。外部服务将通知 Hue 各种事件。与无状态微服务相结合的队列提供了完美的解决方案。每个微服务的多个实例将监听各种队列，并在从队列中弹出相关事件或请求时做出响应。这种安排非常健壮且易于扩展。每个组件都可以是冗余的并且高度可用。虽然每个组件都可能出现故障，但系统非常容错。

队列可以用于异步的 RPC 或请求-响应式的交互，其中调用实例提供一个私有队列名称，被调用者将响应发布到私有队列。

# 规划工作流程

Hue 经常需要支持工作流程。典型的工作流程将得到一个高层任务，比如预约牙医；它将提取用户的牙医详情和日程安排，与用户的日程安排匹配，在多个选项之间进行选择，可能与用户确认，预约，并设置提醒。我们可以将工作流程分类为完全自动和涉及人类的人工工作流程。然后还有涉及花钱的工作流程。

# 自动工作流程

自动工作流程不需要人为干预。Hue 有完全的权限来执行从开始到结束的所有步骤。用户分配给 Hue 的自主权越多，它的效果就会越好。用户应该能够查看和审计所有的工作流程，无论是过去还是现在。

# 人工工作流程

人工工作流程需要与人的交互。最常见的情况是用户需要从多个选项中进行选择或批准某项操作，但也可能涉及到另一个服务上的人员。例如，要预约牙医，您可能需要从秘书那里获取可用时间的列表。

# 预算意识工作流程

有些工作流程，比如支付账单或购买礼物，需要花钱。虽然从理论上讲，Hue 可以被授予对用户银行账户的无限访问权限，但大多数用户可能更愿意为不同的工作流程设置预算，或者只是将花钱作为经过人工批准的活动。

# 使用 Kubernetes 构建 Hue 平台

在本节中，我们将看看各种 Kubernetes 资源以及它们如何帮助我们构建 Hue。首先，我们将更好地了解多才多艺的 Kubectl，然后我们将看看在 Kubernetes 中运行长时间运行的进程，内部和外部暴露服务，使用命名空间限制访问，启动临时作业以及混合非集群组件。显然，Hue 是一个庞大的项目，所以我们将在本地 Minikube 集群上演示这些想法，而不是实际构建一个真正的 Hue Kubernetes 集群。

# 有效使用 Kubectl

Kubectl 是您的瑞士军刀。它几乎可以做任何与集群相关的事情。在幕后，Kubectl 通过 API 连接到您的集群。它读取您的`.kube/config`文件，其中包含连接到您的集群或集群所需的信息。命令分为多个类别：

+   **通用命令**：以通用方式处理资源：`create`，`get`，`delete`，`run`，`apply`，`patch`，`replace`等等

+   **集群管理命令**：处理节点和整个集群：`cluster-info`，`certificate`，`drain`等等

+   **故障排除命令**：`describe`，`logs`，`attach`，`exec`等等

+   **部署命令**：处理部署和扩展：`rollout`，`scale`，`auto-scale`等等

+   **设置命令**：处理标签和注释：`label`，`annotate`等等

```
Misc commands: help, config, and version 
```

您可以使用 Kubernetes `config view`查看配置。

这是 Minikube 集群的配置：

```
~/.minikube > k config view 
apiVersion: v1 
clusters: 
- cluster: 
    certificate-authority: /Users/gigi.sayfan/.minikube/ca.crt 
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
    client-certificate: /Users/gigi.sayfan/.minikube/client.crt 
    client-key: /Users/gigi.sayfan/.minikube/client.key 
```

# 理解 Kubectl 资源配置文件

许多 Kubectl 操作，比如`create`，需要复杂的分层输出（因为 API 需要这种输出）。Kubectl 使用 YAML 或 JSON 配置文件。这是一个用于创建 pod 的 JSON 配置文件：

```
apiVersion: v1
kind: Pod
metadata:
  name: ""
  labels:
    name: ""
  namespace: ""
  annotations: []
  generateName: ""
spec:
     ...  
```

+   `apiVersion`：非常重要的 Kubernetes API 不断发展，并且可以通过 API 的不同版本支持相同资源的不同版本。

+   `kind`：`kind`告诉 Kubernetes 它正在处理的资源类型，在本例中是`pod`。这是必需的。

+   `metadata`：这是描述 pod 及其操作位置的大量信息：

+   `名称`：在其命名空间中唯一标识 pod

+   `标签`：可以应用多个标签

+   `命名空间`：pod 所属的命名空间

+   `注释`：可查询的注释列表

+   `规范`：`规范`是一个包含启动 pod 所需的所有信息的 pod 模板。它可能非常复杂，所以我们将在多个部分中探讨它：

```
"spec": {
  "containers": [
  ],
  "restartPolicy": "",
  "volumes": [
  ]
}  
```

+   `容器规范`：pod 规范的容器是容器规范的列表。每个容器规范都有以下结构：

```
        {
          "name": "",
          "image": "",
          "command": [
            ""
          ],
          "args": [
            ""
          ],
          "env": [
            {
              "name": "",
              "value": ""
            }
          ],
          "imagePullPolicy": "",
          "ports": [
            {
              "containerPort": 0,
              "name": "",
              "protocol": ""
            }
          ],
          "resources": {
            "cpu": ""
            "memory": ""
          }
        }
```

每个容器都有一个镜像，一个命令，如果指定了，会替换 Docker 镜像命令。它还有参数和环境变量。然后，当然还有镜像拉取策略、端口和资源限制。我们在前几章中已经涵盖了这些。

# 在 pod 中部署长时间运行的微服务

长时间运行的微服务应该在 pod 中运行，并且是无状态的。让我们看看如何为 Hue 的一个微服务创建 pod。稍后，我们将提高抽象级别并使用部署。

# 创建 pod

让我们从一个常规的 pod 配置文件开始，为创建 Hue 学习者内部服务。这个服务不需要暴露为公共服务，它将监听一个队列以获取通知，并将其见解存储在一些持久存储中。

我们需要一个简单的容器来运行 pod。这可能是有史以来最简单的 Docker 文件，它将模拟 Hue 学习者：

```
FROM busybox
CMD ash -c "echo 'Started...'; while true ; do sleep 10 ; done"  
```

它使用`busybox`基础镜像，打印到标准输出`Started...`，然后进入一个无限循环，这显然是长时间运行的。

我构建了两个标记为`g1g1/hue-learn:v3.0`和`g1g1/hue-learn:v4.0`的 Docker 镜像，并将它们推送到 Docker Hub 注册表（`g1g1`是我的用户名）。

```
docker build . -t g1g1/hue-learn:v3.0
docker build . -t g1g1/hue-learn:v4.0
docker push g1g1/hue-learn:v3.0
docker push g1g1/hue-learn:v4.0  
```

现在，这些镜像可以被拉入 Hue 的 pod 中的容器。

我们将在这里使用 YAML，因为它更简洁和易读。这里是样板和`元数据`标签：

```
apiVersion: v1
kind: Pod
metadata:
  name: hue-learner
  labels:
    app: hue 
    runtime-environment: production
    tier: internal-service 
  annotations:
    version: "3.0"
```

我使用注释而不是标签的原因是，标签用于标识部署中的一组 pod。不允许修改标签。

接下来是重要的`容器`规范，为每个容器定义了强制的`名称`和`镜像`：

```
spec:
  containers:
  - name: hue-learner
    image: g1g1/hue-learn:v3.0  
```

资源部分告诉 Kubernetes 容器的资源需求，这允许更高效和紧凑的调度和分配。在这里，容器请求`200`毫 CPU 单位（0.2 核心）和`256` MiB：

```
resources:
  requests:
    cpu: 200m
    memory: 256Mi 
```

环境部分允许集群管理员提供将可用于容器的环境变量。这里告诉它通过`dns`发现队列和存储。在测试环境中，可能会使用不同的发现方法：

```
env:
- name: DISCOVER_QUEUE
  value: dns
- name: DISCOVER_STORE
  value: dns 
```

# 用标签装饰 pod

明智地为 pod 贴上标签对于灵活的操作至关重要。它让您可以实时演变您的集群，将微服务组织成可以统一操作的组，并以自发的方式深入观察不同的子集。

例如，我们的 Hue 学习者 pod 具有以下标签：

+   **运行环境**：生产

+   **层级**：内部服务

版本注释可用于支持同时运行多个版本。如果需要同时运行版本 2 和版本 3，无论是为了提供向后兼容性还是在从`v2`迁移到`v3`期间暂时运行，那么具有版本注释或标签允许独立扩展不同版本的 pod 并独立公开服务。`runtime-environment`标签允许对属于特定环境的所有 pod 执行全局操作。`tier`标签可用于查询属于特定层的所有 pod。这只是例子；在这里，您的想象力是限制。

# 使用部署部署长时间运行的进程

在大型系统中，pod 不应该只是创建并放任不管。如果由于任何原因 pod 意外死亡，您希望另一个 pod 替换它以保持整体容量。您可以自己创建复制控制器或副本集，但这也会留下错误的可能性以及部分故障的可能性。在启动 pod 时指定要创建多少副本更有意义。

让我们使用 Kubernetes 部署资源部署我们的 Hue 学习者微服务的三个实例。请注意，部署对象在 Kubernetes 1.9 时变得稳定：

```
apiVersion: apps/v1 (use apps/v1beta2 before 1.9)
 kind: Deployment
 metadata:
 name: hue-learn
 labels:
 app: hue
 spec:
 replicas: 3
 selector:
 matchLabels:
 app: hue
 template:
 metadata:
 labels:
 app: hue
 spec:
 <same spec as in the pod template>
```

`pod spec`与我们之前使用的 pod 配置文件中的`spec`部分相同。

让我们创建部署并检查其状态：

```
> kubectl create -f .\deployment.yaml
deployment "hue-learn" created
> kubectl get deployment hue-learn
NAME        DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
hue-learn   3          3           3             3        4m

> kubectl get pods | grep hue-learn
NAME                        READY     STATUS    RESTARTS   AGE
hue-learn-237202748-d770r   1/1       Running   0          2m
hue-learn-237202748-fwv2t   1/1       Running   0          2m
hue-learn-237202748-tpr4s   1/1       Running   0          2m  
```

您可以使用`kubectl describe`命令获取有关部署的更多信息。

# 更新部署

Hue 平台是一个庞大且不断发展的系统。您需要不断升级。部署可以更新以无痛的方式推出更新。您可以更改 pod 模板以触发由 Kubernetes 完全管理的滚动更新。

目前，所有的 pod 都在运行版本 3.0：

```
> kubectl get pods -o json | jq .items[0].spec.containers[0].image
"3.0"  
```

让我们更新部署以升级到版本 4.0。修改部署文件中的镜像版本。不要修改标签；这会导致错误。通常，您会修改镜像和一些相关的元数据在注释中。然后我们可以使用`apply`命令来升级版本：

```
> kubectl apply -f hue-learn-deployment.yaml
deployment "hue-learn" updated
> kubectl get pods -o json | jq .items[0].spec.containers[0].image
"4.0"  
```

# 分离内部和外部服务

内部服务是只有其他服务或集群中的作业（或登录并运行临时工具的管理员）直接访问的服务。在某些情况下，内部服务根本不被访问，只是执行其功能并将结果存储在其他服务以解耦方式访问的持久存储中。

但是一些服务需要向用户或外部程序公开。让我们看一个虚假的 Hue 服务，它管理用户的提醒列表。它实际上并不做任何事情，但我们将用它来说明如何公开服务。我将一个虚假的`hue-reminders`镜像（与`hue-learn`相同）推送到 Docker Hub：

```
docker push g1g1/hue-reminders:v2.2  
```

# 部署内部服务

这是部署，它与 Hue-learner 部署非常相似，只是我删除了`annotations`、`env`和`resources`部分，只保留了一个标签以节省空间，并在容器中添加了一个`ports`部分。这是至关重要的，因为服务必须通过一个端口公开，其他服务才能访问它：

```
apiVersion: apps/v1a1
kind: Deployment
metadata:
 name: hue-reminders
spec:
 replicas: 2 
 template:
 metadata:
 name: hue-reminders
 labels:
 app: hue-reminders
 spec: 
 containers:
 - name: hue-reminders
 image: g1g1/hue-reminders:v2.2 
 ports:
 - containerPort: 80 
```

当我们运行部署时，两个 Hue `reminders` pod 被添加到集群中：

```
> kubectl create -f hue-reminders-deployment.yaml
> kubectl get pods
NAME                           READY   STATUS    RESTARTS   AGE
hue-learn-56886758d8-h7vm7      1/1    Running       0      49m
hue-learn-56886758d8-lqptj      1/1    Running       0      49m
hue-learn-56886758d8-zwkqt      1/1    Running       0      49m
hue-reminders-75c88cdfcf-5xqtp  1/1    Running       0      50s
hue-reminders-75c88cdfcf-r6jsx  1/1    Running       0      50s 
```

好的，pod 正在运行。理论上，其他服务可以查找或配置其内部 IP 地址，并直接访问它们，因为它们都在同一个网络空间中。但这并不具有可扩展性。每当一个 reminders pod 死掉并被新的 pod 替换，或者当我们只是扩展 pod 的数量时，所有访问这些 pod 的服务都必须知道这一点。服务通过提供所有 pod 的单一访问点来解决这个问题。服务如下：

```
apiVersion: v1
kind: Service
metadata:
 name: hue-reminders
 labels:
 app: hue-reminders 
spec:
 ports:
 - port: 80
 protocol: TCP
 selector:
 app: hue-reminders
```

该服务具有一个选择器，选择所有具有与其匹配的标签的 pod。它还公开一个端口，其他服务将使用该端口来访问它（它不必与容器的端口相同）。

# 创建 hue-reminders 服务

让我们创建服务并稍微探索一下：

```
> kubectl create -f hue-reminders-service.yaml
service "hue-reminders" created
> kubectl describe svc hue-reminders
Name:              hue-reminders
Namespace:         default
Labels:            app=hue-reminders
Annotations:       <none>
Selector:          app=hue-reminders
Type:              ClusterIP
IP:                10.108.163.209
Port:              <unset>  80/TCP
TargetPort:        80/TCP
Endpoints:         172.17.0.4:80,172.17.0.6:80
Session Affinity:  None
Events:            <none>  
```

服务正在运行。其他 pod 可以通过环境变量或 DNS 找到它。所有服务的环境变量都是在 pod 创建时设置的。这意味着如果在创建服务时已经有一个 pod 在运行，您将不得不将其终止，并让 Kubernetes 使用环境变量重新创建它（您通过部署创建 pod，对吧？）：

```
> kubectl exec hue-learn-56886758d8-fjzdd -- printenv | grep HUE_REMINDERS_SERVICE

HUE_REMINDERS_SERVICE_PORT=80
HUE_REMINDERS_SERVICE_HOST=10.108.163.209  
```

但是使用 DNS 要简单得多。您的服务 DNS 名称是：

```
<service name>.<namespace>.svc.cluster.local
> kubectl exec hue-learn-56886758d8-fjzdd -- nslookup hue-reminders
Server:    10.96.0.10
Address 1: 10.96.0.10 kube-dns.kube-system.svc.cluster.local 
Name:      hue-reminders
Address 1: 10.108.163.209 hue-reminders.default.svc.cluster.local  
```

# 将服务暴露给外部

该服务在集群内可访问。如果您想将其暴露给外部世界，Kubernetes 提供了两种方法：

+   为直接访问配置`NodePort`

+   如果在云环境中运行，请配置云负载均衡器

在为外部访问配置服务之前，您应该确保其安全。Kubernetes 文档中有一个涵盖所有细节的很好的示例：

[`github.com/kubernetes/examples/blob/master/staging/https-nginx/README.md`](https://github.com/kubernetes/examples/blob/master/staging/https-nginx/README.md)。

我们已经在第五章中介绍了原则，“配置 Kubernetes 安全性、限制和账户”。

以下是通过`NodePort`向外界暴露 Hue-reminders 服务的`spec`部分：

```
spec:
  type: NodePort
  ports:
  - port: 8080
    targetPort: 80
    protocol: TCP
    name: http
 - port: 443
   protocol: TCP
   name: https
 selector:
   app: hue-reminders
```

# Ingress

`Ingress`是 Kubernetes 的一个配置对象，它可以让您将服务暴露给外部世界，并处理许多细节。它可以执行以下操作：

+   为您的服务提供外部可见的 URL

+   负载均衡流量

+   终止 SSL

+   提供基于名称的虚拟主机

要使用`Ingress`，您必须在集群中运行一个`Ingress`控制器。请注意，Ingress 仍处于测试阶段，并且有许多限制。如果您在 GKE 上运行集群，那么可能没问题。否则，请谨慎操作。`Ingress`控制器目前的一个限制是它不适用于扩展。因此，它还不是 Hue 平台的一个好选择。我们将在第十章“高级 Kubernetes 网络”中更详细地介绍`Ingress`控制器。

以下是`Ingress`资源的外观：

```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
 name: test
spec:
 rules:
 - host: foo.bar.com
 http:
 paths:
 - path: /foo
 backend:
 serviceName: fooSvc
 servicePort: 80
 - host: bar.baz.com
 http:
 paths:
 - path: /bar
 backend:
 serviceName: barSvc
 servicePort: 80
```

Nginx `Ingress`控制器将解释此`Ingress`请求，并为 Nginx Web 服务器创建相应的配置文件：

```
http { 
  server { 
    listen 80; 
    server_name foo.bar.com; 

    location /foo { 
      proxy_pass http://fooSvc; 
    } 
  } 
  server { 
    listen 80; 
    server_name bar.baz.com; 

    location /bar { 
      proxy_pass http://barSvc; 
    } 
  } 
} 
```

可以创建其他控制器。

# 使用命名空间限制访问

Hue 项目进展顺利，我们有几百个微服务和大约 100 名开发人员和 DevOps 工程师在其中工作。相关微服务组出现，并且您会注意到许多这些组是相当自治的。它们完全不知道其他组。此外，还有一些敏感领域，如健康和财务，您将希望更有效地控制对其的访问。输入命名空间。

让我们创建一个新的服务，Hue-finance，并将其放在一个名为`restricted`的新命名空间中。

这是新的`restricted`命名空间的 YAML 文件：

```
kind: Namespace 
 apiVersion: v1
 metadata:
     name: restricted
     labels:
       name: restricted

> kubectl create -f restricted-namespace.yaml
namespace "restricted" created  
```

创建命名空间后，我们需要为命名空间配置上下文。这将允许限制访问仅限于此命名空间：

```
> kubectl config set-context restricted --namespace=restricted --cluster=minikube --user=minikube
Context "restricted" set.

> kubectl config use-context restricted
Switched to context "restricted". 
```

让我们检查我们的`cluster`配置：

```
> kubectl config view
apiVersion: v1
clusters:
- cluster:
 certificate-authority: /Users/gigi.sayfan/.minikube/ca.crt
 server: https://192.168.99.100:8443
 name: minikube
contexts:
- context:
 cluster: minikube
 user: minikube
 name: minikube
- context:
 cluster: minikube
 namespace: restricted
 user: minikube
 name: restricted
current-context: restricted
kind: Config
preferences: {}
users:
- name: minikube
 user:
 client-certificate: /Users/gigi.sayfan/.minikube/client.crt
 client-key: /Users/gigi.sayfan/.minikube/client.key
```

如您所见，当前上下文是`restricted`。

现在，在这个空的命名空间中，我们可以创建我们的`hue-finance`服务，它将独立存在：

```
> kubectl create -f hue-finance-deployment.yaml
deployment "hue-finance" created

> kubectl get pods
NAME                           READY     STATUS    RESTARTS   AGE
hue-finance-7d4b84cc8d-gcjnz   1/1       Running   0          6s
hue-finance-7d4b84cc8d-tqvr9   1/1       Running   0          6s
hue-finance-7d4b84cc8d-zthdr   1/1       Running   0          6s  
```

不需要切换上下文。您还可以使用`--namespace=<namespace>`和`--all-namespaces`命令行开关。

# 启动作业

Hue 部署了许多长时间运行的微服务进程，但也有许多运行、完成某个目标并退出的任务。Kubernetes 通过作业资源支持此功能。Kubernetes 作业管理一个或多个 pod，并确保它们运行直到成功。如果作业管理的 pod 中的一个失败或被删除，那么作业将运行一个新的 pod 直到成功。

这是一个运行 Python 进程计算 5 的阶乘的作业（提示：它是 120）：

```
apiVersion: batch/v1
kind: Job
metadata:
  name: factorial5
spec:
  template:
    metadata:
      name: factorial5
    spec:
      containers:
      - name: factorial5
        image: python:3.6
        command: ["python", 
                  "-c", 
                  "import math; print(math.factorial(5))"]
      restartPolicy: Never      
```

请注意，`restartPolicy`必须是`Never`或`OnFailure`。默认的`Always`值是无效的，因为作业在成功完成后不应重新启动。

让我们启动作业并检查其状态：

```
> kubectl create -f .\job.yaml
job "factorial5" created

> kubectl get jobs
NAME         DESIRED   SUCCESSFUL   AGE
factorial5   1         1            25s  
```

默认情况下不显示已完成任务的 pod。您必须使用`--show-all`选项：

```
> kubectl get pods --show-all
NAME                           READY     STATUS      RESTARTS   AGE
factorial5-ntp22               0/1       Completed   0          2m
hue-finance-7d4b84cc8d-gcjnz   1/1       Running     0          9m
hue-finance-7d4b84cc8d-tqvr9   1/1       Running     0          8m
hue-finance-7d4b84cc8d-zthdr   1/1       Running     0          9m  
```

`factorial5` pod 的状态为`Completed`。让我们查看它的输出：

```
> kubectl logs factorial5-ntp22
120  
```

# 并行运行作业

您还可以使用并行运行作业。规范中有两个字段，称为`completions`和`parallelism`。`completions`默认设置为`1`。如果您需要多个成功完成，则增加此值。`parallelism`确定要启动多少个 pod。作业不会启动比成功完成所需的更多的 pod，即使并行数更大。

让我们运行另一个只睡眠`20`秒直到完成三次成功的作业。我们将使用`parallelism`因子为`6`，但只会启动三个 pod：

```
apiVersion: batch/v1
kind: Job
metadata:
 name: sleep20
spec:
 completions: 3
 parallelism: 6 
 template:
 metadata:
 name: sleep20
 spec:
 containers:
 - name: sleep20
 image: python:3.6
 command: ["python", 
 "-c", 
 "import time; print('started...'); 
 time.sleep(20); print('done.')"]
 restartPolicy: Never 

> Kubectl get pods 
NAME              READY  STATUS   RESTARTS  AGE
sleep20-1t8sd      1/1   Running    0       10s
sleep20-sdjb4      1/1   Running    0       10s
sleep20-wv4jc      1/1   Running    0       10s
```

# 清理已完成的作业

当作业完成时，它会保留下来 - 它的 pod 也是如此。这是有意设计的，这样您就可以查看日志或连接到 pod 并进行探索。但通常，当作业成功完成后，它就不再需要了。清理已完成的作业及其 pod 是您的责任。最简单的方法是简单地删除`job`对象，这将同时删除所有的 pod：

```
> kubectl delete jobs/factroial5
job "factorial5" deleted
> kubectl delete jobs/sleep20
job "sleep20" deleted  
```

# 安排 cron 作业

Kubernetes cron 作业是在指定时间内运行一次或多次的作业。它们的行为类似于常规的 Unix cron 作业，指定在`/etc/crontab`文件中。

在 Kubernetes 1.4 中，它们被称为`ScheduledJob`。但是，在 Kubernetes 1.5 中，名称更改为`CronJob`。从 Kubernetes 1.8 开始，默认情况下在 API 服务器中启用了`CronJob`资源，不再需要传递`--runtime-config`标志，但它仍处于`beta`阶段。以下是启动一个每分钟提醒您伸展的 cron 作业的配置。在计划中，您可以用`?`替换`*`：

```
apiVersion: batch/v1beta1
kind: CronJob
metadata:
 name: stretch
spec:
 schedule: "*/1 * * * *"
 jobTemplate:
 spec:
 template:
 metadata:
 labels:
 name: stretch 
 spec:
 containers:
 - name: stretch
 image: python
 args:
 - python
 - -c
 - from datetime import datetime; print('[{}] Stretch'.format(datetime.now()))
 restartPolicy: OnFailure
```

在 pod 规范中，在作业模板下，我添加了一个名为`name`的标签。原因是 Kubernetes 会为 cron 作业及其 pod 分配带有随机前缀的名称。该标签允许您轻松发现特定 cron 作业的所有 pod。请参阅以下命令行：

```
> kubectl get pods
NAME                       READY     STATUS              RESTARTS   AGE
stretch-1482165720-qm5bj   0/1       ImagePullBackOff    0          1m
stretch-1482165780-bkqjd   0/1       ContainerCreating   0          6s  
```

请注意，每次调用 cron 作业都会启动一个新的`job`对象和一个新的 pod：

```
> kubectl get jobs
NAME                 DESIRED   SUCCESSFUL   AGE
stretch-1482165300   1         1            11m
stretch-1482165360   1         1            10m
stretch-1482165420   1         1            9m
stretch-1482165480   1         1            8m 
```

当 cron 作业调用完成时，它的 pod 进入`Completed`状态，并且不会在没有`-show-all`或`-a`标志的情况下可见：

```
> Kubectl get pods --show-all
NAME                       READY     STATUS      RESTARTS   AGE
stretch-1482165300-g5ps6   0/1       Completed   0          15m
stretch-1482165360-cln08   0/1       Completed   0          14m
stretch-1482165420-n8nzd   0/1       Completed   0          13m
stretch-1482165480-0jq31   0/1       Completed   0          12m  
```

通常情况下，您可以使用`logs`命令来检查已完成的 cron 作业的 pod 的输出：

```
> kubectl logs stretch-1482165300-g5ps6
[2016-12-19 16:35:15.325283] Stretch 
```

当您删除一个 cron 作业时，它将停止安排新的作业，并删除所有现有的作业对象以及它创建的所有 pod。

您可以使用指定的标签（在本例中名称等于`STRETCH`）来定位由 cron 作业启动的所有作业对象。您还可以暂停 cron 作业，以便它不会创建更多的作业，而无需删除已完成的作业和 pod。您还可以通过设置在 spec 历史限制中管理以前的作业：`spec.successfulJobsHistoryLimit`和`.spec.failedJobsHistoryLimit`。

# 混合非集群组件

Kubernetes 集群中的大多数实时系统组件将与集群外的组件进行通信。这些可能是完全外部的第三方服务，可以通过某些 API 访问，但也可能是在同一本地网络中运行的内部服务，由于各种原因，这些服务不是 Kubernetes 集群的一部分。

这里有两个类别：网络内部和网络外部。为什么这种区别很重要？

# 集群外网络组件

这些组件无法直接访问集群。它们只能通过 API、外部可见的 URL 和公开的服务来访问。这些组件被视为任何外部用户一样。通常，集群组件将只使用外部服务，这不会造成安全问题。例如，在我以前的工作中，我们有一个将异常报告给第三方服务的 Kubernetes 集群（[`sentry.io/welcome/`](https://sentry.io/welcome/)）。这是从 Kubernetes 集群到第三方服务的单向通信。

# 网络内部组件

这些是在网络内部运行但不受 Kubernetes 管理的组件。有许多原因可以运行这些组件。它们可能是尚未 Kubernetized 的传统应用程序，或者是一些不容易在 Kubernetes 内部运行的分布式数据存储。将这些组件运行在网络内部的原因是为了性能，并且与外部世界隔离，以便这些组件和 pod 之间的流量更加安全。作为相同网络的一部分确保低延迟，并且减少了身份验证的需求既方便又可以避免身份验证开销。

# 使用 Kubernetes 管理 Hue 平台

在这一部分，我们将看一下 Kubernetes 如何帮助操作像 Hue 这样的大型平台。Kubernetes 本身提供了许多功能来编排 Pod 和管理配额和限制，检测和从某些类型的通用故障（硬件故障、进程崩溃和无法访问的服务）中恢复。但是，在 Hue 这样一个复杂的系统中，Pod 和服务可能正在运行，但处于无效状态或等待其他依赖项以执行其职责。这很棘手，因为如果一个服务或 Pod 还没有准备好，但已经收到请求，那么你需要以某种方式管理它：失败（将责任放在调用者身上），重试（*多少次？* *多长时间？* *多频繁？*），并排队等待以后（*谁来管理这个队列？*）。

如果整个系统能够意识到不同组件的就绪状态，或者只有当组件真正就绪时才可见，通常会更好。Kubernetes 并不了解 Hue，但它提供了几种机制，如活跃性探针、就绪性探针和 Init Containers，来支持你的集群的应用程序特定管理。

# 使用活跃性探针来确保你的容器是活着的

Kubectl 监视着你的容器。如果容器进程崩溃，Kubelet 会根据重启策略来处理它。但这并不总是足够的。你的进程可能不会崩溃，而是陷入无限循环或死锁。重启策略可能不够微妙。通过活跃性探针，你可以决定何时认为容器是活着的。这里有一个 Hue 音乐服务的 Pod 模板。它有一个`livenessProbe`部分，使用了`httpGet`探针。HTTP 探针需要一个方案（HTTP 或 HTTPS，默认为 HTTP），一个主机（默认为`PodIp`），一个`path`和一个`port`。如果 HTTP 状态码在`200`到`399`之间，探针被认为是成功的。你的容器可能需要一些时间来初始化，所以你可以指定一个`initialDelayInSeconds`。在这段时间内，Kubelet 不会进行活跃性检查：

```
apiVersion: v1
kind: Pod
metadata:
 labels:
 app: hue-music
 name: hue-music
spec:
 containers:
 image: the_g1g1/hue-music
 livenessProbe:
 httpGet:
 path: /pulse
 port: 8888
 httpHeaders:
 - name: X-Custom-Header
 value: ItsAlive
 initialDelaySeconds: 30
 timeoutSeconds: 1
 name: hue-music
```

如果任何容器的活跃性探针失败，那么 Pod 的重启策略就会生效。确保你的重启策略不是*Never*，因为那会使探针变得无用。

有两种其他类型的探针：

+   `TcpSocket`：只需检查端口是否打开

+   `Exec`：运行一个返回`0`表示成功的命令

# 使用就绪性探针来管理依赖关系

就绪探针用于不同的目的。您的容器可能已经启动运行，但可能依赖于此刻不可用的其他服务。例如，Hue-music 可能依赖于访问包含您听歌历史记录的数据服务。如果没有访问权限，它将无法执行其职责。在这种情况下，其他服务或外部客户端不应该向 Hue 音乐服务发送请求，但没有必要重新启动它。就绪探针解决了这种情况。当一个容器的就绪探针失败时，该容器的 pod 将从其注册的任何服务端点中移除。这确保请求不会涌入无法处理它们的服务。请注意，您还可以使用就绪探针暂时移除过载的 pod，直到它们排空一些内部队列。

这是一个示例就绪探针。我在这里使用 exec 探针来执行一个 `custom` 命令。如果命令退出时的退出代码为非零，容器将被关闭：

```
readinessProbe:
 exec:
 command: 
 - /usr/local/bin/checker
 - --full-check
 - --data-service=hue-multimedia-service
 initialDelaySeconds: 60
 timeoutSeconds: 5
```

在同一个容器上同时拥有就绪探针和存活探针是可以的，因为它们有不同的用途。

# 使用初始化容器进行有序的 pod 启动

存活和就绪探针非常好用。它们认识到，在启动时，可能会有一个容器尚未准备好的时间段，但不应被视为失败。为了适应这一点，有一个 `initialDelayInSeconds` 设置，容器在这段时间内不会被视为失败。但是，如果这个初始延迟可能非常长呢？也许，在大多数情况下，一个容器在几秒钟后就准备好处理请求了，但是因为初始延迟设置为五分钟以防万一，当容器处于空闲状态时，我们会浪费很多时间。如果容器是高流量服务的一部分，那么在每次升级后，许多实例都可能在五分钟后处于空闲状态，几乎使服务不可用。

初始化容器解决了这个问题。一个 pod 可能有一组初始化容器，在其他容器启动之前完成运行。初始化容器可以处理所有非确定性的初始化，并让应用容器通过它们的就绪探针尽量减少延迟。

初始化容器在 Kubernetes 1.6 中退出了 beta 版。您可以在 pod 规范中指定它们，作为 `initContainers` 字段，这与 `containers` 字段非常相似。以下是一个示例：

```
apiVersion: v1
kind: Pod
metadata:
 name: hue-fitness
spec:
 containers: 
 name: hue-fitness
 Image: hue-fitness:v4.4
 InitContainers:
 name: install
 Image: busybox
 command: /support/safe_init
 volumeMounts:
 - name: workdir
 mountPath: /workdir   
```

# 与 DaemonSet pods 共享

`DaemonSet` pods 是自动部署的 pod，每个节点一个（或指定节点的子集）。它们通常用于监视节点并确保它们正常运行。这是一个非常重要的功能，我们在第三章“监控、日志记录和故障排除”中讨论了节点问题检测器。但它们可以用于更多的功能。默认的 Kubernetes 调度程序的特性是根据资源可用性和请求来调度 pod。如果有很多不需要大量资源的 pod，许多 pod 将被调度到同一个节点上。让我们考虑一个执行小任务的 pod，然后，每秒钟，将其所有活动的摘要发送到远程服务。想象一下，平均每秒钟会有 50 个这样的 pod 被调度到同一个节点上。这意味着，每秒钟，50 个 pod 会进行 50 次几乎没有数据的网络请求。我们能不能将它减少 50 倍，只进行一次网络请求？使用`DaemonSet` pod，其他 50 个 pod 可以与其通信，而不是直接与远程服务通信。`DaemonSet` pod 将收集来自 50 个 pod 的所有数据，并且每秒钟将其汇总报告给远程服务。当然，这需要远程服务 API 支持汇总报告。好处是 pod 本身不需要修改；它们只需配置为与`DaemonSet` pod 在本地主机上通信，而不是与远程服务通信。`DaemonSet` pod 充当聚合代理。

这个配置文件的有趣之处在于，`hostNetwork`、`hostPID`和`hostIPC`选项都设置为`true`。这使得 pod 能够有效地与代理通信，利用它们在同一物理主机上运行的事实。

```
apiVersion: apps/v1
kind: DaemonSet
metadata:
 name: hue-collect-proxy
 labels:
 tier: stats
 app: hue-collect-proxy
spec:
 template:
 metadata:
 labels:
 hue-collect-proxy
 spec:
 hostPID: true
 hostIPC: true
 hostNetwork: true
 containers:
 image: the_g1g1/hue-collect-proxy
 name: hue-collect-proxy
```

# 使用 Kubernetes 发展 Hue 平台

在本节中，我们将讨论扩展 Hue 平台和服务其他市场和社区的其他方法。问题始终是，“我们可以使用哪些 Kubernetes 功能和能力来解决新的挑战或要求？”

# 在企业中利用 Hue

企业通常无法在云中运行，要么是因为安全和合规性原因，要么是因为性能原因，因为系统必须处理数据和传统系统，这些系统不适合迁移到云上。无论哪种情况，企业的 Hue 必须支持本地集群和/或裸金属集群。

虽然 Kubernetes 最常部署在云上，甚至有一个特殊的云提供商接口，但它并不依赖于云，可以在任何地方部署。它需要更多的专业知识，但已经在自己的数据中心上运行系统的企业组织拥有这方面的专业知识。

CoreOS 提供了大量关于在裸机集群上部署 Kubernetes 集群的材料。

# 用 Hue 推动科学的进步

Hue 在整合来自多个来源的信息方面非常出色，这对科学界将是一个福音。想象一下 Hue 如何帮助来自不同领域的科学家进行多学科合作。

科学社区的网络可能需要在多个地理分布的集群上部署。这就是集群联邦。Kubernetes 考虑到了这种用例，并不断发展其支持。我们将在后面的章节中详细讨论这个问题。

# 用 Hue 教育未来的孩子

Hue 可以用于教育，并为在线教育系统提供许多服务。但隐私问题可能会阻止将 Hue 作为单一的集中系统用于儿童。一个可能的选择是建立一个单一的集群，为不同学校设立命名空间。另一个部署选项是每个学校或县都有自己的 Hue Kubernetes 集群。在第二种情况下，Hue 教育必须非常易于操作，以满足没有太多技术专长的学校。Kubernetes 可以通过提供自愈和自动扩展功能来帮助 Hue，使其尽可能接近零管理。

# 总结

在本章中，我们设计和规划了 Hue 平台的开发、部署和管理——一个想象中的全知全能的服务，建立在微服务架构上。当然，我们使用 Kubernetes 作为底层编排平台，并深入探讨了许多它的概念和资源。特别是，我们专注于为长期运行的服务部署 pod，而不是为启动短期或定期作业部署作业，探讨了内部服务与外部服务，还使用命名空间来分割 Kubernetes 集群。然后，我们研究了像活跃性和就绪性探针、初始化容器和守护进程集这样的大型系统的管理。

现在，您应该能够设计由微服务组成的 Web 规模系统，并了解如何在 Kubernetes 集群中部署和管理它们。

在下一章中，我们将深入研究存储这个非常重要的领域。数据为王，但通常是系统中最不灵活的元素。Kubernetes 提供了一个存储模型，并提供了许多与各种存储解决方案集成的选项。
