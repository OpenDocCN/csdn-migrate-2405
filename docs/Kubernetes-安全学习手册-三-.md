# Kubernetes 安全学习手册（三）

> 原文：[`zh.annas-archive.org/md5/389AEFE03E8149C2BB9C34B66276B16C`](https://zh.annas-archive.org/md5/389AEFE03E8149C2BB9C34B66276B16C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：深度防御

深度防御是一种在网络安全中应用多层安全控制来保护有价值资产的方法。在传统或单片式 IT 环境中，我们可以列举出许多：认证、加密、授权、日志记录、入侵检测、防病毒、**虚拟私人网络**（**VPN**）、防火墙等等。您可能会发现这些安全控制也存在于 Kubernetes 集群中（而且应该存在）。

在之前的章节中，我们已经讨论了认证、授权、准入控制器、保护 Kubernetes 组件、保护配置、加固镜像和 Kubernetes 工作负载等主题。所有这些都构建了不同的安全控制层，以保护您的 Kubernetes 集群。在本章中，我们将讨论构建额外安全控制层的主题，这些主题与 Kubernetes 集群中的运行时防御最相关。以下是本章将要解决的问题：您的集群是否暴露了任何敏感数据？如果 Kubernetes 集群发生攻击，您能否检测到攻击？您的 Kubernetes 集群能够承受攻击吗？您如何应对攻击？

在本章中，我们将讨论 Kubernetes 审计，然后介绍高可用性的概念，并讨论如何在 Kubernetes 集群中应用高可用性。接下来，我们将介绍 Vault，这是一个方便的秘密管理产品，适用于 Kubernetes 集群。然后，我们将讨论如何使用 Falco 来检测 Kubernetes 集群中的异常活动。最后但同样重要的是，我们将介绍 Sysdig Inspect 和**用户空间的检查点和资源**（也称为**CRIU**）用于取证。

本章将涵盖以下主题：

+   介绍 Kubernetes 审计

+   在 Kubernetes 集群中启用高可用性

+   使用 Vault 管理秘密

+   使用 Falco 检测异常

+   使用 Sysdig Inspect 和 CRIU 进行取证

# 介绍 Kubernetes 审计

Kubernetes 审计是在 1.11 版本中引入的。Kubernetes 审计记录事件，例如创建部署，修补 pod，删除命名空间等，按照时间顺序进行记录。通过审计，Kubernetes 集群管理员能够回答以下问题：

+   发生了什么？（创建了一个 pod，是什么类型的 pod）

+   谁做的？（来自用户/管理员）

+   发生在什么时候？（事件的时间戳）

+   它发生在哪里？（Pod 是在哪个命名空间中创建的？）

从安全的角度来看，审计使 DevOps 团队和安全团队能够通过跟踪 Kubernetes 集群内发生的事件来更好地检测和预防异常。

在 Kubernetes 集群中，是`kube-apiserver`进行审计。当请求（例如，创建一个命名空间）发送到`kube-apiserver`时，请求可能会经过多个阶段。每个阶段将生成一个事件。已知的阶段如下：

+   `RequestReceived`：在审计处理程序接收请求而不处理它时生成事件。

+   `RequestStarted`：在发送响应头并发送响应正文之间生成事件，仅适用于长时间运行的请求，如`watch`。

+   `RequestComplete`：在发送响应正文时生成事件。

+   `Panic`：当发生紧急情况时生成事件。

在本节中，我们将首先介绍 Kubernetes 审计策略，然后向您展示如何启用 Kubernetes 审计以及持久化审计记录的几种方法。

## Kubernetes 审计策略

由于记录 Kubernetes 集群内发生的一切事情并不现实，审计策略允许用户定义关于应记录何种事件以及应记录事件的多少细节的规则。当`kube-apiserver`处理事件时，它将按顺序比较审计策略中的规则列表。第一个匹配的规则还决定了事件的审计级别。让我们看看审计策略是什么样子。以下是一个示例：

```
apiVersion: audit.k8s.io/v1 # This is required.
kind: Policy
# Skip generating audit events for all requests in RequestReceived stage. This can be either set at the policy level or rule level.
omitStages:
  - "RequestReceived"
rules:
  # Log pod changes at RequestResponse level
  - level: RequestResponse
    verbs: ["create", "update"]
    namespace: ["ns1", "ns2", "ns3"]
    resources:
    - group: ""
# Only check access to resource "pods", not the sub-resource of pods which is consistent with the RBAC policy.
      resources: ["pods"]
# Log "pods/log", "pods/status" at Metadata level
  - level: Metadata
    resources:
    - group: ""
      resources: ["pods/log", "pods/status"]
# Don't log authenticated requests to certain non-resource URL paths.
  - level: None
    userGroups: ["system:authenticated"]
    nonResourceURLs: ["/api*", "/version"]
# Log configmap and secret changes in all other namespaces at the Metadata level.
  - level: Metadata
    resources:
    - group: "" # core API group
      resources: ["secrets", "configmaps"]
```

您可以在审计策略中配置多个审计规则。每个审计规则将由以下字段配置：

+   `level`：定义审计事件详细程度的审计级别。

+   `resources`：审计的 Kubernetes 对象。资源可以通过**应用程序编程接口**（**API**）组和对象类型来指定。

+   `nonResourcesURL`：与审计的任何资源不相关的非资源**统一资源定位符**（**URL**）路径。

+   `namespace`：决定哪个命名空间中的 Kubernetes 对象将接受审计。空字符串将用于选择非命名空间对象，空列表意味着每个命名空间。

+   `verb`：决定将接受审计的 Kubernetes 对象的具体操作，例如`create`，`update`或`delete`。

+   `users`：决定审计规则适用于的经过身份验证的用户

+   `userGroups`：决定认证用户组适用于的审计规则。

+   `omitStages`：跳过在给定阶段生成事件。这也可以在策略级别设置。

审计策略允许您通过指定`verb`、`namespace`、`resources`等在细粒度级别上配置策略。规则的审计级别定义了应记录事件的详细程度。有四个审计级别，如下所述：

+   `None`：不记录与审计规则匹配的事件。

+   `Metadata`：当事件匹配审计规则时，记录请求到`kube-apiserver`的元数据（如`user`、`timestamp`、`resource`、`verb`等）。

+   `Request`：当事件匹配审计规则时，记录元数据以及请求正文。这不适用于非资源 URL。

+   `RequestResponse`：当事件匹配审计规则时，记录元数据、请求和响应正文。这不适用于非资源请求。

请求级别的事件比元数据级别的事件更详细，而`RequestResponse`级别的事件比请求级别的事件更详细。高详细度需要更多的输入/输出（I/O）吞吐量和存储。了解审计级别之间的差异非常必要，这样您就可以正确定义审计规则，既可以节约资源又可以保障安全。成功配置审计策略后，让我们看看审计事件是什么样子的。以下是一个元数据级别的审计事件：

```
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Metadata",
  "auditID": "05698e93-6ad7-4f4e-8ae9-046694bee469",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/ns1/pods",
  "verb": "create",
  "user": {
    "username": "admin",
    "uid": "admin",
    "groups": [
      "system:masters",
      "system:authenticated"
    ]
  },
  "sourceIPs": [
    "98.207.36.92"
  ],
  "userAgent": "kubectl/v1.17.4 (darwin/amd64) kubernetes/8d8aa39",
  "objectRef": {
    "resource": "pods",
    "namespace": "ns1",
    "name": "pod-1",
    "apiVersion": "v1"
  },
  "responseStatus": {
    "metadata": {},
    "code": 201
  },
  "requestReceivedTimestamp": "2020-04-09T07:10:52.471720Z",
  "stageTimestamp": "2020-04-09T07:10:52.485551Z",
  "annotations": {
    "authorization.k8s.io/decision": "allow",
    "authorization.k8s.io/reason": ""
  }
}
```

前面的审计事件显示了`user`、`timestamp`、被访问的对象、授权决定等。请求级别的审计事件在审计事件中的`requestObject`字段中提供了额外的信息。您将在`requestObject`字段中找到工作负载的规范，如下所示：

```
  "requestObject": {
    "kind": "Pod",
    "apiVersion": "v1",
    "metadata": {
      "name": "pod-2",
      "namespace": "ns2",
      "creationTimestamp": null,
      ...
    },
    "spec": {
      "containers": [
        {
          "name": "echo",
          "image": "busybox",
          "command": [
            "sh",
            "-c",
            "echo 'this is echo' && sleep 1h"
          ],
          ...
          "imagePullPolicy": "Always"
        }
      ],
      ...
      "securityContext": {},
    },
```

`RequestResponse`级别的审计事件是最详细的。事件中的`responseObject`实例几乎与`requestObject`相同，但包含了额外的信息，如资源版本和创建时间戳，如下面的代码块所示：

```
{
  "responseObject": {
      ...
      "selfLink": "/api/v1/namespaces/ns3/pods/pod-3",
      "uid": "3fd18de1-7a31-11ea-9e8d-0a39f00d8287",
      "resourceVersion": "217243",
      "creationTimestamp": "2020-04-09T07:10:53Z",
      "tolerations": [
        {
          "key": "node.kubernetes.io/not-ready",
          "operator": "Exists",
          "effect": "NoExecute",
          "tolerationSeconds": 300
        },
        {
          "key": "node.kubernetes.io/unreachable",
          "operator": "Exists",
          "effect": "NoExecute",
          "tolerationSeconds": 300
        }
      ],
      ...
    },
 }
```

请务必正确选择审计级别。更详细的日志提供了对正在进行的活动更深入的洞察。然而，存储和处理审计事件的时间成本更高。值得一提的是，如果在 Kubernetes 秘密对象上设置了请求或`RequestResponse`审计级别，秘密内容将被记录在审计事件中。如果将审计级别设置为比包含敏感数据的 Kubernetes 对象的元数据更详细，您应该使用敏感数据遮蔽机制，以避免秘密被记录在审计事件中。

Kubernetes 审计功能通过对象类型、命名空间、操作、用户等提供了对 Kubernetes 对象的审计灵活性。由于 Kubernetes 审计默认情况下未启用，接下来，让我们看看如何启用 Kubernetes 审计并存储审计记录。

## 配置审计后端

为了启用 Kubernetes 审计，您需要在启动`kube-apiserver`时传递`--audit-policy-file`标志和您的审计策略文件。可以配置两种类型的审计后端来处理审计事件：日志后端和 webhook 后端。让我们来看看它们。

### 日志后端

日志后端将审计事件写入主节点上的文件。以下标志用于在`kube-apiserver`中配置日志后端：

+   `--log-audit-path`：指定主节点上的日志路径。这是打开或关闭日志后端的标志。

+   `--audit-log-maxage`：指定保留审计记录的最大天数。

+   `--audit-log-maxbackup`：指定主节点上要保留的审计文件的最大数量。

+   `--audit-log-maxsize`：指定在日志文件被轮换之前的最大兆字节大小。

让我们来看看 webhook 后端。

### webhook 后端

webhook 后端将审计事件写入注册到`kube-apiserver`的远程 webhook。要启用 webhook 后端，您需要使用 webhook 配置文件设置`--audit-webhook-config-file`标志。此标志也在启动`kube-apiserver`时指定。以下是一个用于为稍后将更详细介绍的 Falco 服务注册 webhook 后端的 webhook 配置的示例：

```
apiVersion: v1
kind: Config
clusters:
- name: falco
  cluster:
    server: http://$FALCO_SERVICE_CLUSTERIP:8765/k8s_audit
contexts:
- context:
    cluster: falco
    user: ""
  name: default-context
current-context: default-context
preferences: {}
users: []
```

`server`字段中指定的 URL（`http://$FALCO_SERVICE_CLUSTERIP:8765/k8s_audit`）是审计事件将要发送到的远程端点。自 Kubernetes 1.13 版本以来，可以通过`AuditSink`对象动态配置 webhook 后端，该对象仍处于 alpha 阶段。

在本节中，我们介绍了 Kubernetes 审计，介绍了审计策略和审计后端。在下一节中，我们将讨论 Kubernetes 集群中的高可用性。

# 在 Kubernetes 集群中启用高可用性

可用性指的是用户访问服务或系统的能力。系统的高可用性确保了系统的约定的正常运行时间。例如，如果只有一个实例来提供服务，而该实例宕机，用户将无法再访问该服务。具有高可用性的服务由多个实例提供。当一个实例宕机时，备用实例仍然可以提供服务。以下图表描述了具有和不具有高可用性的服务：

![图 11.1 - 具有和不具有高可用性的服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_11_001.jpg)

图 11.1 - 具有和不具有高可用性的服务

在 Kubernetes 集群中，通常会有多个工作节点。集群的高可用性得到了保证，即使一个工作节点宕机，仍然有其他工作节点来承载工作负载。然而，高可用性不仅仅是在集群中运行多个节点。在本节中，我们将从三个层面来看 Kubernetes 集群中的高可用性：工作负载、Kubernetes 组件和云基础设施。

## 启用 Kubernetes 工作负载的高可用性

对于 Kubernetes 工作负载，比如部署和 StatefulSet，您可以在规范中指定`replicas`字段，用于指定微服务运行多少个复制的 pod，并且控制器将确保在集群中的不同工作节点上有`x`个 pod 运行，如`replicas`字段中指定的那样。DaemonSet 是一种特殊的工作负载；控制器将确保在集群中的每个节点上都有一个 pod 运行，假设您的 Kubernetes 集群有多个节点。因此，在部署或 StatefulSet 中指定多个副本，或者使用 DaemonSet，将确保您的工作负载具有高可用性。为了确保工作负载的高可用性，还需要确保 Kubernetes 组件的高可用性。

## 启用 Kubernetes 组件的高可用性

高可用性也适用于 Kubernetes 组件。让我们来回顾一下几个关键的 Kubernetes 组件，如下所示：

+   `kube-apiserver`：Kubernetes API 服务器（`kube-apiserver`）是一个控制平面组件，用于验证和配置诸如 pod、服务和控制器之类的对象的数据。它使用**REepresentational State Transfer**（**REST**）请求与对象进行交互。

+   `etcd`：`etcd`是一个高可用性的键值存储，用于存储配置、状态和元数据等数据。其`watch`功能使 Kubernetes 能够监听配置的更新并相应地进行更改。

+   `kube-scheduler`：`kube-scheduler`是 Kubernetes 的默认调度程序。它会观察新创建的 pod 并将 pod 分配给节点。

+   `kube-controller-manager`：Kubernetes 控制器管理器是观察状态更新并相应地对集群进行更改的核心控制器的组合。

如果`kube-apiserver`宕机，那么基本上您的集群也会宕机，因为用户或其他 Kubernetes 组件依赖于与`kube-apiserver`通信来执行其任务。如果`etcd`宕机，那么集群和对象的状态将无法被消费。`kube-scheduler`和`kube-controller-manager`也很重要，以确保工作负载在集群中正常运行。所有这些组件都在主节点上运行，以确保组件的高可用性。一个简单的方法是为您的 Kubernetes 集群启动多个主节点，可以通过`kops`或`kubeadm`来实现。您会发现类似以下的内容：

```
$ kubectl get pods -n kube-system
...
etcd-manager-events-ip-172-20-109-109.ec2.internal       1/1     Running   0          4h15m
etcd-manager-events-ip-172-20-43-65.ec2.internal         1/1     Running   0          4h16m
etcd-manager-events-ip-172-20-67-151.ec2.internal        1/1     Running   0          4h16m
etcd-manager-main-ip-172-20-109-109.ec2.internal         1/1     Running   0          4h15m
etcd-manager-main-ip-172-20-43-65.ec2.internal           1/1     Running   0          4h15m
etcd-manager-main-ip-172-20-67-151.ec2.internal          1/1     Running   0          4h16m
kube-apiserver-ip-172-20-109-109.ec2.internal            1/1     Running   3          4h15m
kube-apiserver-ip-172-20-43-65.ec2.internal              1/1     Running   4          4h16m
kube-apiserver-ip-172-20-67-151.ec2.internal             1/1     Running   4          4h15m
kube-controller-manager-ip-172-20-109-109.ec2.internal   1/1     Running   0          4h15m
kube-controller-manager-ip-172-20-43-65.ec2.internal     1/1     Running   0          4h16m
kube-controller-manager-ip-172-20-67-151.ec2.internal    1/1     Running   0          4h15m
kube-scheduler-ip-172-20-109-109.ec2.internal            1/1     Running   0          4h15m
kube-scheduler-ip-172-20-43-65.ec2.internal              1/1     Running   0          4h15m
kube-scheduler-ip-172-20-67-151.ec2.internal             1/1     Running   0          4h16m
```

现在您有多个`kube-apiserver` pod、`etcd` pod、`kube-controller-manager` pod 和`kube-scheduler` pod 在`kube-system`命名空间中运行，并且它们在不同的主节点上运行。还有一些其他组件，如`kubelet`和`kube-proxy`，它们在每个节点上运行，因此它们的可用性由节点的可用性保证，并且`kube-dns`默认情况下会启动多个 pod，因此它们的高可用性是得到保证的。无论您的 Kubernetes 集群是在公共云上运行还是在私有数据中心中运行——基础设施都是支持 Kubernetes 集群可用性的支柱。接下来，我们将讨论云基础设施的高可用性，并以云提供商为例。

## 启用云基础设施的高可用性

云提供商通过位于不同地区的多个数据中心提供全球范围的云服务。云用户可以选择在哪个地区和区域（实际数据中心）托管他们的服务。区域和区域提供了对大多数类型的物理基础设施和基础设施软件服务故障的隔离。请注意，云基础设施的可用性也会影响托管在云中的 Kubernetes 集群上运行的服务。您应该利用云的高可用性，并最终确保在 Kubernetes 集群上运行的服务的高可用性。以下代码块提供了使用`kops`指定区域的示例，以利用云基础设施的高可用性：

```
export NODE_SIZE=${NODE_SIZE:-t2.large}
export MASTER_SIZE=${MASTER_SIZE:-t2.medium}
export ZONES=${ZONES:-"us-east-1a,us-east-1b,us-east-1c"}
export KOPS_STATE_STORE="s3://my-k8s-state-store2/"
kops create cluster k8s-clusters.k8s-demo-zone.com \
  --cloud aws \
  --node-count 3 \
  --zones $ZONES \
  --node-size $NODE_SIZE \
  --master-size $MASTER_SIZE \
  --master-zones $ZONES \
  --networking calico \
  --kubernetes-version 1.14.3 \
  --yes \
```

Kubernetes 集群的节点如下所示：

```
$ kops validate cluster
...
INSTANCE GROUPS
NAME			ROLE	MACHINETYPE	MIN	MAX	SUBNETS
master-us-east-1a	Master	t2.medium	1	1	us-east-1a
master-us-east-1b	Master	t2.medium	1	1	us-east-1b
master-us-east-1c	Master	t2.medium	1	1	us-east-1c
nodes			Node	t2.large	3	3	us-east-1a,us-east-1b,us-east-1c
```

前面的代码块显示了分别在`us-east-1a`、`us-east-1b`和`us-east-1c`可用区运行的三个主节点。因此，作为工作节点，即使其中一个数据中心宕机或正在维护，主节点和工作节点仍然可以在其他数据中心中运行。

在本节中，我们已经讨论了 Kubernetes 工作负载、Kubernetes 组件和云基础设施的高可用性。让我们使用以下图表来总结 Kubernetes 集群的高可用性：

![图 11.2-云中 Kubernetes 集群的高可用性](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_11_002.jpg)

图 11.2-云中 Kubernetes 集群的高可用性

现在，让我们转到下一个关于在 Kubernetes 集群中管理秘密的主题。

# 使用 Vault 管理秘密

秘密管理是一个重要的话题，许多开源和专有解决方案已经被开发出来，以帮助解决不同平台上的秘密管理问题。因此，在 Kubernetes 中，它的内置`Secret`对象用于存储秘密数据，并且实际数据与其他 Kubernetes 对象一起存储在`etcd`中。默认情况下，秘密数据以明文（编码格式）存储在`etcd`中。`etcd`可以配置为在静止状态下加密秘密。同样，如果`etcd`未配置为使用**传输层安全性**（**TLS**）加密通信，则秘密数据也以明文传输。除非安全要求非常低，否则建议在 Kubernetes 集群中使用第三方解决方案来管理秘密。

在本节中，我们将介绍 Vault，这是一个**Cloud Native Computing Foundation**（**CNCF**）秘密管理项目。Vault 支持安全存储秘密、动态秘密生成、数据加密、密钥吊销等。在本节中，我们将重点介绍如何在 Kubernetes 集群中为应用程序存储和提供秘密。现在，让我们看看如何为 Kubernetes 集群设置 Vault。

## 设置 Vault

您可以使用`helm`在 Kubernetes 集群中部署 Vault，如下所示：

```
helm install vault --set='server.dev.enabled=true' https://github.com/hashicorp/vault-helm/archive/v0.4.0.tar.gz
```

请注意，设置了`server.dev.enabled=true`。这对开发环境很好，但不建议在生产环境中设置。您应该看到有两个正在运行的 pod，如下所示：

```
$ kubectl get pods
NAME                                    READY   STATUS    RESTARTS   AGE
vault-0                                 1/1     Running   0          80s
vault-agent-injector-7fd6b9588b-fgsnj   1/1     Running   0          80s
```

`vault-0` pod 是用于管理和存储秘密的 pod，而`vault-agent-injector-7fd6b9588b-fgsnj` pod 负责将秘密注入带有特殊 vault 注释的 pod 中，我们将在*提供和轮换秘密*部分中更详细地展示。接下来，让我们为`postgres`数据库连接创建一个示例秘密，如下所示：

```
vault kv put secret/postgres username=alice password=pass
```

请注意，前面的命令需要在`vault-0` pod 内执行。由于您希望限制 Kubernetes 集群中仅有相关应用程序可以访问秘钥，您可能希望定义一个策略来实现，如下所示：

```
cat <<EOF > /home/vault/app-policy.hcl
path "secret*" {
  capabilities = ["read"]
}
EOF
vault policy write app /home/vault/app-policy.hcl
```

现在，您有一个定义了在`secret`路径下读取秘密权限的策略，比如`secret`/`postgres`。接下来，您希望将策略与允许的实体关联，比如 Kubernetes 中的服务账户。这可以通过执行以下命令来完成：

```
vault auth enable kubernetes
vault write auth/kubernetes/config \
   token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
   kubernetes_host=https://${KUBERNETES_PORT_443_TCP_ADDR}:443 \
   kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
vault write auth/kubernetes/role/myapp \
   bound_service_account_names=app \
   bound_service_account_namespaces=demo \
   policies=app \
   ttl=24h
```

Vault 可以利用 Kubernetes 的天真认证，然后将秘密访问策略绑定到服务账户。现在，命名空间 demo 中的服务账户 app 可以访问`postgres`秘密。现在，让我们在`vault-app.yaml`文件中部署一个演示应用程序，如下所示：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  labels:
    app: vault-agent-demo
spec:
  selector:
    matchLabels:
      app: vault-agent-demo
  replicas: 1
  template:
    metadata:
      annotations:
      labels:
        app: vault-agent-demo
    spec:
      serviceAccountName: app
      containers:
      - name: app
        image: jweissig/app:0.0.1
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app
  labels:
    app: vault-agent-demo
```

请注意，在上述的`.yaml`文件中，尚未添加注释，因此在创建应用程序时，秘密不会被注入，也不会添加 sidecar 容器。代码可以在以下片段中看到：

```
$ kubectl get pods
NAME                                    READY   STATUS    RESTARTS   AGE
app-668b8bcdb9-js9mm                    1/1     Running   0          3m23s
```

接下来，我们将展示秘密注入的工作原理。

## 提供和轮换秘密

我们在部署应用程序时不展示秘密注入的原因是，我们想向您展示在注入到演示应用程序 pod 之前和之后的详细差异。现在，让我们使用以下 Vault 注释来补丁部署：

```
$ cat patch-template-annotation.yaml
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/agent-inject-status: "update"
        vault.hashicorp.com/agent-inject-secret-postgres: "secret/postgres"
        vault.hashicorp.com/agent-inject-template-postgres: |
          {{- with secret "secret/postgres" -}}
          postgresql://{{ .Data.data.username }}:{{ .Data.data.password }}@postgres:5432/wizard
          {{- end }}
        vault.hashicorp.com/role: "myapp"
```

上述注释规定了将注入哪个秘密，以及以什么格式和使用哪个角色。一旦我们更新了演示应用程序的部署，我们将发现秘密已经被注入，如下所示：

```
$ kubectl get pods
NAME                                    READY   STATUS    RESTARTS   AGE
app-68d47bb844-2hlrb                    2/2     Running   0          13s
$ kubectl -n demo exec -it app-68d47bb844-2hlrb -c app -- cat /vault/secrets/postgres
postgresql://alice:pass@postgres:5432/wizard
```

让我们来看一下 pod 的规范（而不是补丁后的部署）-与补丁后的部署规范相比，您会发现以下内容（用粗体标记）已经添加：

```
  containers:
  - image: jweissig/app:0.0.1
    ...
    volumeMounts:
    - mountPath: /vault/secrets
      name: vault-secrets
  - args:
    - echo ${VAULT_CONFIG?} | base64 -d > /tmp/config.json && vault agent -config=/tmp/config.json
    command:
    - /bin/sh
    - -ec
    image: vault:1.3.2
    name: vault-agent
    volumeMounts:
    - mountPath: /vault/secrets
      name: vault-secrets
 initContainers:
  - args:
    - echo ${VAULT_CONFIG?} | base64 -d > /tmp/config.json && vault agent -config=/tmp/config.json
    command:
    - /bin/sh
    - -ec
    image: vault:1.3.2
    name: vault-agent-init
    volumeMounts:
    - mountPath: /vault/secrets
      name: vault-secrets
  volumes:
   - emptyDir:
      medium: Memory
    name: vault-secrets
```

在上述列出的变化中值得一提的几件事情：注入了一个名为`vault-agent-init`的`init`容器和一个名为`vault-agent`的 sidecar 容器，以及一个名为`vault-secrets`的`emptyDir`类型卷。这就是为什么在补丁之后，你会看到演示应用程序 pod 中运行了两个容器。此外，`vault-secrets`卷被挂载在`init`容器、`sidecar`容器和`app`容器的`/vault/secrets/`目录中。秘密存储在`vault-secrets`卷中。通过预定义的变异 webhook 配置（通过`helm`安装）来完成 pod 规范的修改，如下所示：

```
apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingWebhookConfiguration
metadata:
  ...
  name: vault-agent-injector-cfg
webhooks:
- admissionReviewVersions:
  - v1beta1
  clientConfig:
    caBundle: <CA_BUNDLE>
    service:
      name: vault-agent-injector-svc
      namespace: demo
      path: /mutate
  failurePolicy: Ignore
  name: vault.hashicorp.com
  namespaceSelector: {}
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - v1
    operations:
    - CREATE
    - UPDATE
    resources:
    - pods
    scope: '*'
```

注册到`kube-apiserver`的变异 webhook 配置基本上告诉`kube-apiserver`将任何 pod 的创建或更新请求重定向到`demo`命名空间中的`vault-agent-injector-svc`服务。服务的后面是`vault-agent-injector` pod。然后，`vault-agent-injector` pod 将查找相关的注释，并根据请求将`init`容器和`sidecar`容器以及存储秘密的卷注入到 pod 的规范中。为什么我们需要一个`init`容器和一个`sidecar`容器？`init`容器是为了预先填充我们的秘密，而`sidecar`容器是为了在整个应用程序生命周期中保持秘密数据同步。

现在，让我们运行以下代码来更新秘密，并看看会发生什么：

```
vault kv put secret/postgres username=alice password=changeme
```

现在，密码已从`pass`更新为`changeme`在`vault` pod 中。并且，在`demo`应用程序方面，我们可以看到在等待几秒钟后，它也已经更新了：

```
$ kubectl -n demo exec -it app-68d47bb844-2hlrb -c app -- cat /vault/secrets/postgres
postgresql://alice:changeme@postgres:5432/wizard
```

Vault 是一个强大的秘密管理解决方案，它的许多功能无法在单个部分中涵盖。我鼓励你阅读文档并尝试使用它来更好地了解 Vault。接下来，让我们谈谈在 Kubernetes 中使用 Falco 进行运行时威胁检测。

# 使用 Falco 检测异常

Falco 是一个 CNCF 开源项目，用于检测云原生环境中的异常行为或运行时威胁，比如 Kubernetes 集群。它是一个基于规则的运行时检测引擎，具有约 100 个现成的检测规则。在本节中，我们将首先概述 Falco，然后向您展示如何编写 Falco 规则，以便您可以构建自己的 Falco 规则来保护您的 Kubernetes 集群。

## Falco 概述

Falco 被广泛用于检测云原生环境中的异常行为，特别是在 Kubernetes 集群中。那么，什么是异常检测？基本上，它使用行为信号来检测安全异常，比如泄露的凭据或异常活动，行为信号可以从你对实体的了解中得出正常行为是什么。

### 面临的挑战

要确定 Kubernetes 集群中的正常行为并不容易。从运行应用程序的角度来看，我们可以将它们分为三类，如下所示：

+   **Kubernetes 组件**：`kube-apiserver`、`kube-proxy`、`kubelet`、**容器运行时接口**（**CRI**）插件、**容器网络接口**（**CNI**）插件等

+   **自托管应用程序**：Java、Node.js、Golang、Python 等

+   **供应商服务**：Cassandra、Redis、MySQL、NGINX、Tomcat 等

或者，从系统的角度来看，我们有以下类型的活动：

+   文件活动，如打开、读取和写入

+   进程活动，如`execve`和`clone`系统调用

+   网络活动，如接受、连接和发送

或者，从 Kubernetes 对象的角度来看：`pod`、`secret`、`deployment`、`namespace`、`serviceaccount`、`configmap`等

为了覆盖 Kubernetes 集群中发生的所有这些活动或行为，我们将需要丰富的信息来源。接下来，让我们谈谈 Falco 依赖的事件来源，以进行异常检测，以及这些来源如何涵盖前述的活动和行为。

### 异常检测的事件来源

Falco 依赖两个事件来源进行异常检测。一个是系统调用，另一个是 Kubernetes 审计事件。对于系统调用事件，Falco 使用内核模块来监听机器上的系统调用流，并将这些系统调用传递到用户空间（最近也支持了`ebpf`）。在用户空间，Falco 还会丰富原始系统调用事件的上下文，如进程名称、容器 ID、容器名称、镜像名称等。对于 Kubernetes 审计事件，用户需要启用 Kubernetes 审计策略，并将 Kubernetes 审计 webhook 后端注册到 Falco 服务端点。然后，Falco 引擎检查引擎中加载的任何 Falco 规则匹配的任何系统调用事件或 Kubernetes 审计事件。

讨论使用系统调用和 Kubernetes 审计事件作为事件源进行异常检测的原因也很重要。系统调用是应用程序与操作系统交互以访问文件、设备、网络等资源的编程方式。考虑到容器是一组具有自己专用命名空间的进程，并且它们共享节点上相同的操作系统，系统调用是可以用来监视容器活动的统一事件源。应用程序使用什么编程语言并不重要；最终，所有函数都将被转换为系统调用以与操作系统交互。看一下下面的图表：

![图 11.3 - 容器和系统调用](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_11_003.jpg)

图 11.3 - 容器和系统调用

在上图中，有四个运行不同应用程序的容器。这些应用程序可能使用不同的编程语言编写，并且它们都调用一个函数来以不同的函数名打开文件（例如，`fopen`、`open`和`os.Open`）。然而，从操作系统的角度来看，所有这些应用程序都调用相同的系统调用`open`，但可能使用不同的参数。Falco 能够从系统调用中检索事件，因此无论应用程序是什么类型或使用什么编程语言都不重要。

另一方面，借助 Kubernetes 审计事件，Falco 可以完全了解 Kubernetes 对象的生命周期。这对于异常检测也很重要。例如，在生产环境中，以特权方式启动一个带有`busybox`镜像的 pod 可能是异常的。

总的来说，两个事件源——系统调用和 Kubernetes 审计事件——足以覆盖 Kubernetes 集群中发生的所有重要活动。现在，通过对 Falco 事件源的理解，让我们用一个高级架构图总结一下 Falco 的概述。

### 高级架构

Falco 主要由几个组件组成，如下：

+   **Falco 规则**：定义用于检测事件是否异常的规则。

+   **Falco 引擎**：使用 Falco 规则评估传入事件，并在事件匹配任何规则时产生输出。

+   **内核模块/Sysdig 库**：在发送到 Falco 引擎进行评估之前，标记系统调用事件并丰富它们。

+   Web 服务器：监听 Kubernetes 审计事件并传递给 Falco 引擎进行评估。

以下图表显示了 Falco 的内部架构：

图 11.4 - Falco 的内部架构

](image/B15566_11_004.jpg)

图 11.4 - Falco 的内部架构

现在，我们已经总结了 Falco 的概述。接下来，让我们尝试创建一些 Falco 规则并检测任何异常行为。

## 创建 Falco 规则以检测异常

在我们深入研究 Falco 规则之前，请确保已通过以下命令安装了 Falco：

```
helm install --name falco stable/falco
```

Falco DaemonSet 应该在您的 Kubernetes 集群中运行，如下面的代码块所示：

```
$ kubectl get pods
NAME          READY   STATUS    RESTARTS   AGE
falco-9h8tg   1/1     Running   10         62m
falco-cnt47   1/1     Running   5          3m45s
falco-mz6jg   1/1     Running   0          6s
falco-t4cpw   1/1     Running   0          10s
```

要启用 Kubernetes 审计并将 Falco 注册为 webhook 后端，请按照 Falco 存储库中的说明进行操作（[`github.com/falcosecurity/evolution/tree/master/examples/k8s_audit_config`](https://github.com/falcosecurity/evolution/tree/master/examples/k8s_audit_config)）。

Falco 规则中有三种类型的元素，如下所示：

+   规则：触发警报的条件。规则具有以下属性：规则名称、描述、条件、优先级、来源、标签和输出。当事件匹配任何规则的条件时，根据规则的输出定义生成警报。

+   宏：可以被其他规则或宏重复使用的规则条件片段。

+   列表：可以被宏和规则使用的项目集合。

为了方便 Falco 用户构建自己的规则，Falco 提供了一些默认列表和宏。

### 创建系统调用规则

Falco 系统调用规则评估系统调用事件 - 更准确地说是增强的系统调用。系统调用事件字段由内核模块提供，并且与 Sysdig（Sysdig 公司构建的开源工具）过滤字段相同。策略引擎使用 Sysdig 的过滤器从系统调用事件中提取信息，如进程名称、容器映像和文件路径，并使用 Falco 规则进行评估。

以下是可以用于构建 Falco 规则的最常见的 Sysdig 过滤字段：

+   proc.name：进程名称

+   fd.name：写入或读取的文件名

+   container.id：容器 ID

+   container.image.repository：不带标签的容器映像名称

+   fd.sip 和 fd.sport：服务器**Internet Protocol**（**IP**）地址和服务器端口

+   fd.cip 和 fd.cport：客户端 IP 和客户端端口

+   **evt.type**: 系统调用事件（`open`、`connect`、`accept`、`execve`等）

让我们尝试构建一个简单的 Falco 规则。假设您有一个`nginx` pod，仅从`/usr/share/nginx/html/`目录提供静态文件。因此，您可以创建一个 Falco 规则来检测任何异常的文件读取活动，如下所示：

```
    - rule: Anomalous read in nginx pod
      desc: Detect any anomalous file read activities in Nginx pod.
      condition: (open_read and container and container.image.repository="kaizheh/insecure-nginx" and fd.directory != "/usr/share/nginx/html")
      output: Anomalous file read activity in Nginx pod (user=%user.name process=%proc.name file=%fd.name container_id=%container.id image=%container.image.repository)
      priority: WARNING
```

前面的规则使用了两个默认宏：`open_read`和`container`。`open_read`宏检查系统调用事件是否仅以读模式打开，而`container`宏检查系统调用事件是否发生在容器内。然后，该规则仅适用于运行`kaizheh/insecure-nginx`镜像的容器，并且`fd.directory`过滤器从系统调用事件中检索文件目录信息。在此规则中，它检查是否有任何文件读取超出`/usr/share/nginx/html/`目录。那么，如果`nginx`的配置错误导致文件路径遍历（在任意目录下读取文件）会怎么样？以下代码块显示了一个示例：

```
# curl insecure-nginx.insecure-nginx.svc.cluster.local/files../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/bin/false
```

与此同时，Falco 检测到超出指定目录的文件访问，输出如下：

```
08:22:19.484698397: Warning Anomalous file read activity in Nginx pod (user=<NA> process=nginx file=/etc/passwd container_id=439e2e739868 image=kaizheh/insecure-nginx) k8s.ns=insecure-nginx k8s.pod=insecure-nginx-7c99fdf44b-gffp4 container=439e2e739868 k8s.ns=insecure-nginx k8s.pod=insecure-nginx-7c99fdf44b-gffp4 container=439e2e739868
```

接下来，让我们看看如何使用 K8s 审计规则。

### 创建 K8s 审计规则

K8s 审计规则评估 Kubernetes 审计事件。在本章的前面部分，我们已经展示了 Kubernetes 审计事件记录的样子。与 Sysdig 过滤器类似，有两种方法可以从 Kubernetes 审计事件中检索信息。一种是使用**JavaScript 对象表示法**（**JSON**）指针；另一种是使用 Falco 内置过滤器。以下是用于检索 Kubernetes 审计事件信息的一些常用 Falco 内置过滤器：

+   `ka.verb`: Kubernetes 审计事件的动词字段。`jevt.value[/verb]`是其对应的 JSON 指针。

+   `ka.target.resource`: Kubernetes 审计事件的资源字段。`jevt.value[/objectRef/resource]`是其对应的 JSON 指针。

+   `ka.user.name`: Kubernetes 审计事件的用户名字段。`jevt.value[/user/username]`是其对应的 JSON 指针。

+   `ka.uri`: Kubernetes 审计事件的`requestURI`字段。`jet.value[/requestURI]`是其对应的 JSON 指针。

让我们尝试构建一个简单的 K8s 审计规则。假设您不希望在`kube-system`命名空间中部署除了一些受信任的服务镜像（如`kube-apiserver`、`etcd-manager`等）之外的镜像。因此，您可以创建一个 Falco 规则，如下所示：

```
- list: trusted_images
  items: [calico/node, kopeio/etcd-manager, k8s.gcr.io/kube-apiserver, k8s.gcr.io/kube-controller-manager, k8s.gcr.io/kube-proxy, k8s.gcr.io/kube-scheduler]
- rule: Untrusted Image Deployed in kube-system Namespace
  desc: >
    Detect an untrusted image deployed in kube-system namespace
  condition: >
    kevt and pod
    and kcreate
    and ka.target.namespace=kube-system
    and not ka.req.pod.containers.image.repository in (trusted_images)
  output: Untrusted image deployed in kube-system namespace (user=%ka.user.name image=%ka.req.pod.containers.image.repository resource=%ka.target.name)
  priority: WARNING
  source: k8s_audit
  tags: [k8s]
```

首先，我们定义了一个受信任的镜像列表，这些镜像将被允许部署到`kube-system`命名空间中。在规则中，我们使用了两个默认宏：`pod`和`kcreate`。 `pod`宏检查目标资源是否为 Pod，而`kcreate`检查动词是否为`create`。我们还检查目标命名空间是否为`kube-system`，并且部署的镜像不在`trusted_images`列表中。规则的`source`字段中的`k8s_audit`值表示此规则评估 Kubernetes 审计事件。然后，如果我们尝试在`kube-system`命名空间中部署`busybox`镜像的 Pod，我们将从 Falco 看到以下警报：

```
21:47:15.063915008: Warning Untrusted image deployed in kube-system namespace (user=admin image=busybox resource=pod-1)
```

请注意，为了使此规则起作用，需要将 Pod 创建的审计级别至少设置为“请求”级别，其中审计事件包括 Pod 的规范信息，例如镜像。

在本节中，我们介绍了 Falco，并向您展示了如何从系统调用和 Kubernetes 审计事件两个事件源创建 Falco 规则。这两个规则都用于基于工作负载或集群已知良性活动来检测异常活动。接下来，让我们谈谈如何在 Kubernetes 集群中进行取证工作。

# 使用 Sysdig Inspect 和 CRIU 进行取证。

在网络安全中，取证意味着收集、处理和分析信息，以支持漏洞缓解和/或欺诈、反情报或执法调查。您可以保存的数据越多，对收集的数据进行的分析越快，您就越能追踪攻击并更好地应对事件。在本节中，我们将向您展示如何使用 CRIU 和 Sysdig 开源工具来收集数据，然后介绍 Sysdig Inspect，这是一个用于分析 Sysdig 收集的数据的开源工具。

## 使用 CRIU 收集数据

**CRIU**是**Checkpoint and Restore In Userspace**的缩写。它是一个可以冻结运行中的容器并在磁盘上捕获容器状态的工具。稍后，可以将磁盘上保存的容器和应用程序数据恢复到冻结时的状态。它对于容器快照、迁移和远程调试非常有用。从安全的角度来看，它特别有用于捕获容器中正在进行的恶意活动（以便您可以在检查点后立即终止容器），然后在沙盒环境中恢复状态以进行进一步分析。

CRIU 作为 Docker 插件工作，仍处于实验阶段，已知问题是 CRIU 在最近的几个版本中无法正常工作（[`github.com/moby/moby/issues/37344`](https://github.com/moby/moby/issues/37344)）。出于演示目的，我使用了较旧的 Docker 版本（Docker CE 17.03），并将展示如何使用 CRIU 对运行中的容器进行检查点，并将状态恢复为新容器。

要启用 CRIU，您需要在 Docker 守护程序中启用`experimental`模式，如下所示：

```
echo "{\"experimental\":true}" >> /etc/docker/daemon.json
```

然后，在重新启动 Docker 守护程序后，您应该能够成功执行`docker checkpoint`命令，就像这样：

```
# docker checkpoint
Usage:	docker checkpoint COMMAND
Manage checkpoints
Options:
      --help   Print usage
Commands:
  create      Create a checkpoint from a running container
  ls          List checkpoints for a container
  rm          Remove a checkpoint
```

然后，按照说明安装 CRIU（[`criu.org/Installation`](https://criu.org/Installation)）。接下来，让我们看一个简单的示例，展示 CRIU 的强大之处。我有一个简单的`busybox`容器在运行，每秒增加`1`，如下面的代码片段所示：

```
# docker run -d --name looper --security-opt seccomp:unconfined busybox /bin/sh -c 'i=0; while true; do echo $i; i=$(expr $i + 1); sleep 1; done'
91d68fafec8fcf11e7699539dec0b037220b1fcc856fb7050c58ab90ae8cbd13
```

睡了几秒钟后，我看到计数器的输出在增加，如下所示：

```
# sleep 5
# docker logs looper
0
1
2
3
4
5
```

接下来，我想对容器进行检查点，并将状态存储到本地文件系统，就像这样：

```
# docker checkpoint create --checkpoint-dir=/tmp looper checkpoint
checkpoint
```

现在，`checkpoint`状态已保存在`/tmp`目录下。请注意，除非在创建检查点时指定了`--leave-running`标志，否则容器 looper 将在检查点后被杀死。

然后，创建一个镜像容器，但不运行它，就像这样：

```
# docker create --name looper-clone --security-opt seccomp:unconfined busybox /bin/sh -c 'i=0; while true; do echo $i; i=$(expr $i + 1); sleep 1; done'
49b9ade200e7da6bbb07057da02570347ad6fefbfc1499652ed286b874b59f2b
```

现在，我们可以启动具有存储状态的新`looper-clone`容器。让我们再等几秒钟，看看会发生什么。结果可以在下面的代码片段中看到：

```
# docker start --checkpoint-dir=/tmp --checkpoint=checkpoint looper-clone
# sleep 5
# docker logs looper-clone
6
7
8
9
10
```

新的`looper-clone`容器从`6`开始计数，这意味着状态（计数器为`5`）已成功恢复并使用。

CRIU 对容器取证非常有用，特别是当容器中发生可疑活动时。您可以对容器进行检查点（假设在集群中有多个副本运行），让 CRIU 杀死可疑容器，然后在沙盒环境中恢复容器的可疑状态以进行进一步分析。接下来，让我们谈谈另一种获取取证数据的方法。

## 使用 Sysdig 和 Sysdig Inspect

Sysdig 是一个用于 Linux 系统探索和故障排除的开源工具，支持容器。Sysdig 还可以用于通过在 Linux 内核中进行仪器化和捕获系统调用和其他操作系统事件来创建系统活动的跟踪文件。捕获功能使其成为容器化环境中的一种出色的取证工具。为了支持在 Kubernetes 集群中捕获系统调用，Sysdig 提供了一个`kubectl`插件，`kubectl-capture`，它使您可以像使用其他`kubectl`命令一样简单地捕获目标 pod 的系统调用。捕获完成后，可以使用强大的开源工具 Sysdig Inspect 进行故障排除和安全调查。

让我们继续以`insecure-nginx`为例，因为我们收到了 Falco 警报，如下面的代码片段所示：

```
08:22:19.484698397: Warning Anomalous file read activity in Nginx pod (user=<NA> process=nginx file=/etc/passwd container_id=439e2e739868 image=kaizheh/insecure-nginx) k8s.ns=insecure-nginx k8s.pod=insecure-nginx-7c99fdf44b-gffp4 container=439e2e739868 k8s.ns=insecure-nginx k8s.pod=insecure-nginx-7c99fdf44b-gffp4 container=439e2e739868
```

在触发警报时，`nginx` pod 仍然可能正在遭受攻击。您可以采取一些措施来应对。启动捕获，然后分析 Falco 警报的更多上下文是其中之一。

要触发捕获，请从[`github.com/sysdiglabs/kubectl-capture`](https://github.com/sysdiglabs/kubectl-capture)下载`kubectl-capture`并将其放置在其他`kubectl`插件中，就像这样：

```
$ kubectl plugin list
The following compatible plugins are available:
/Users/kaizhehuang/.krew/bin/kubectl-advise_psp
/Users/kaizhehuang/.krew/bin/kubectl-capture
/Users/kaizhehuang/.krew/bin/kubectl-ctx
/Users/kaizhehuang/.krew/bin/kubectl-krew
/Users/kaizhehuang/.krew/bin/kubectl-ns
/Users/kaizhehuang/.krew/bin/kubectl-sniff
```

然后，像这样在`nginx` pod 上启动捕获：

```
$ kubectl capture insecure-nginx-7c99fdf44b-4fl5s -ns insecure-nginx
Sysdig is starting to capture system calls:
Node: ip-172-20-42-49.ec2.internal
Pod: insecure-nginx-7c99fdf44b-4fl5s
Duration: 120 seconds
Parameters for Sysdig: -S -M 120 -pk -z -w /capture-insecure-nginx-7c99fdf44b-4fl5s-1587337260.scap.gz
The capture has been downloaded to your hard disk at:
/Users/kaizhehuang/demo/chapter11/sysdig/capture-insecure-nginx-7c99fdf44b-4fl5s-1587337260.scap.gz
```

在幕后，`kubectl-capture`在运行疑似受害者 pod 的主机上启动一个新的 pod 进行捕获，持续时间为`120`秒，这样我们就可以看到主机上正在发生的一切以及接下来`120`秒内的情况。捕获完成后，压缩的捕获文件将在当前工作目录中创建。您可以将 Sysdig Inspect 作为 Docker 容器引入，以开始安全调查，就像这样：

```
$ docker run -d -v /Users/kaizhehuang/demo/chapter11/sysdig:/captures -p3000:3000 sysdig/sysdig-inspect:latest
17533f98a947668814ac6189908ff003475b10f340d8f3239cd3627fa9747769
```

现在，登录到`http://localhost:3000`，您应该看到登录**用户界面**（**UI**）。记得解压`scap`文件，这样您就可以看到捕获文件的概述页面，如下所示：

![图 11.5 - Sysdig Inspect 概述](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_11_005.jpg)

图 11.5 - Sysdig Inspect 概述

Sysdig Inspect 从以下角度提供了对容器内发生活动的全面洞察：

+   执行的命令

+   文件访问

+   网络连接

+   系统调用

让我们不仅仅限于 Falco 警报进行更深入的挖掘。根据警报，我们可能怀疑这是一个文件路径遍历问题，因为是`nginx`进程访问`/etc/passwd`文件，我们知道这个 pod 只提供静态文件服务，所以`nginx`进程不应该访问`/usr/share/nginx/html/`目录之外的任何文件。现在，让我们看一下以下截图，看看发送给`nginx` pod 的网络请求是什么：

![图 11.6 – Sysdig Inspect 调查连接到 nginx 的网络连接](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_11_006.jpg)

图 11.6 – Sysdig Inspect 调查连接到 nginx 的网络连接

在查看连接后，我们发现请求来自单个 IP，`100.123.226.66`，看起来像是一个 pod IP。它可能来自同一个集群吗？在左侧面板上点击**Containers**视图，并在过滤器中指定`fd.cip=100.123.226.66`。然后，你会发现它来自`anchore-cli`容器，如下截图所示：

![图 11.7 – Sysdig Inspect 调查一个容器向 nginx 发送请求](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_11_007.jpg)

图 11.7 – Sysdig Inspect 调查一个容器向 nginx 发送请求

事实上，`anchore-cli` pod 碰巧运行在与`nginx` pod 相同的节点上，如下面的代码块所示：

```
$ kubectl get pods -o wide
NAME          READY   STATUS    RESTARTS   AGE   IP               NODE                           NOMINATED NODE   READINESS GATES
anchore-cli   1/1     Running   1          77m   100.123.226.66   ip-172-20-42-49.ec2.internal   <none>           <none>
$ kubectl get pods -n insecure-nginx -o wide
NAME                              READY   STATUS    RESTARTS   AGE   IP               NODE                           NOMINATED NODE   READINESS GATES
insecure-nginx-7c99fdf44b-4fl5s   1/1     Running   0          78m   100.123.226.65   ip-172-20-42-49.ec2.internal   <none>           <none>
```

现在我们知道可能有一些文件路径遍历攻击是从`anchore-cli` pod 发起的，让我们看看这是什么（只需在前面的**Sysdig Inspect**页面中双击条目），如下所示：

![图 11.8 – Sysdig Inspect 调查路径遍历攻击命令](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_11_008.jpg)

图 11.8 – Sysdig Inspect 调查路径遍历攻击命令

我们发现在`anchore-cli` pod 中执行了一系列文件路径遍历命令，详细如下：

+   使用 curl 命令访问 100.71.138.95 上的文件../etc/

+   使用 curl 命令访问 100.71.138.95 上的文件../

+   使用 curl 命令访问 100.71.138.95 上的文件../etc/passwd

+   使用 curl 命令访问 100.71.138.95 上的文件../etc/shadow

我们现在能够更接近攻击者了，下一步是尝试更深入地调查攻击者是如何进入`anchore-cli` pod 的。

CRIU 和 Sysdig 都是在容器化环境中进行取证的强大工具。希望 CRIU 问题能够很快得到解决。请注意，CRIU 还需要 Docker 守护程序以`experimental`模式运行，而 Sysdig 和 Sysdig Inspect 更多地在 Kubernetes 级别工作。Sysdig Inspect 提供了一个漂亮的用户界面，帮助浏览发生在 Pod 和容器中的不同活动。

# 总结

在这一长章中，我们涵盖了 Kubernetes 审计、Kubernetes 集群的高可用性、使用 Vault 管理秘密、使用 Falco 检测异常活动以及使用 CRIU 和 Sysdig 进行取证。虽然您可能会发现需要花费相当长的时间来熟悉所有的实践和工具，但深度防御是一个庞大的主题，值得深入研究安全性，这样您就可以为 Kubernetes 集群建立更强大的防护。

我们谈到的大多数工具都很容易安装和部署。我鼓励您尝试它们：添加自己的 Kubernetes 审计规则，使用 Vault 在 Kubernetes 集群中管理秘密，编写自己的 Falco 规则来检测异常行为，因为您比任何其他人都更了解您的集群，并使用 Sysdig 收集所有取证数据。一旦您熟悉了所有这些工具，您应该会对自己的 Kubernetes 集群更有信心。

在下一章中，我们将讨论一些已知的攻击，比如针对 Kubernetes 集群的加密挖矿攻击，看看我们如何利用本书中学到的技术来减轻这些攻击。

# 问题

1.  为什么我们不应该将审计级别设置为`Request`或`RequestResponse`用于秘密对象？

1.  在`kops`中用什么标志设置多个主节点？

1.  当 Vault 中的秘密更新时，侧车容器会做什么？

1.  Falco 使用哪些事件源？

1.  Falco 使用哪个过滤器从系统调用事件中检索进程名称？

1.  CRIU 对正在运行的容器有什么作用？

1.  您可以用 Sysdig Inspect 做什么？

# 更多参考资料

+   Kubernetes 审计：[`kubernetes.io/docs/tasks/debug-application-cluster/audit/`](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/)

+   使用`kubeadm`实现高可用性：[`kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/`](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/)

+   Vault：[`www.vaultproject.io/docs/internals/architecture`](https://www.vaultproject.io/docs/internals/architecture)

+   Falco：https://falco.org/docs/

+   Sysdig 过滤：[`github.com/draios/sysdig/wiki/Sysdig-User-Guide#user-content-filtering`](https://github.com/draios/sysdig/wiki/Sysdig-User-Guide#user-content-filtering)

+   CRIU：[`criu.org/Docker`](https://criu.org/Docker)

+   Sysdig `kubectl-capture`：[`sysdig.com/blog/tracing-in-kubernetes-kubectl-capture-plugin/`](https://sysdig.com/blog/tracing-in-kubernetes-kubectl-capture-plugin/)

+   Sysdig Inspect：[`github.com/draios/sysdig-inspect`](https://github.com/draios/sysdig-inspect)

+   Sysdig：[`github.com/draios/sysdig`](https://github.com/draios/sysdig)


# 第三部分：从错误和陷阱中学习

在本节中，您将了解涉及 Kubernetes 集群的一些攻击场景，从已知攻击和 CVE 到缓解和预防策略。

本节包括以下章节：

+   *第十二章*, *分析和检测加密货币挖矿攻击*

+   *第十三章*, *从 Kubernetes CVEs 中学习*


# 第十二章：分析和检测加密挖矿攻击

随着区块链和加密货币的日益普及，加密挖矿攻击变得越来越引人注目。加密货币是通过在区块链上利用计算资源进行去中心化交易的交易费而获得的。使用计算资源验证交易以赚取加密货币的过程称为加密挖矿，由一个名为加密挖矿软件的软件进行。安全研究人员发现与各种加密挖矿二进制文件相关的黑客事件在受害者的基础设施内运行。Kubernetes 集群的默认开放性以及用于挖矿所需的大量计算能力的可用性使得 Kubernetes 集群成为加密挖矿攻击的完美目标。Kubernetes 集群的复杂性也使得加密挖矿活动难以检测。

由于我们已经介绍了不同的 Kubernetes 内置安全机制和开源工具来保护 Kubernetes 集群，现在我们将看看如何在具体场景中使用它们。在本章中，我们将首先分析几种已知的加密挖矿攻击，然后我们将讨论如何使用开源工具检测加密挖矿攻击的检测机制。最后但同样重要的是，我们将回顾我们在之前章节中讨论的主题，并看看它们应该如何应用来保护我们的环境免受一般攻击。

本章将涵盖以下主题：

+   分析加密挖矿攻击

+   检测挖矿攻击

+   防御攻击

# 分析加密挖矿攻击

在本节中，我们将首先简要介绍加密挖矿攻击，然后分析一些公开披露的加密挖矿攻击。我们希望您了解加密挖矿攻击模式以及使攻击可能的缺陷。

## 加密挖矿攻击简介

区块链构成了加密货币的基础。简而言之，区块链是由表示为区块的数字资产链组成的。这些区块包含有关交易的信息以及谁参与了交易的数字签名。每种加密货币都与一个区块链相关联。验证交易记录的过程称为挖矿。挖矿将历史记录添加到区块链中，以确保区块在未来无法修改。挖矿旨在消耗大量资源，以确保区块链的去中心化属性。通过成功挖矿区块，矿工可以获得与交易相关的交易费。因此，如果你有一台笔记本电脑或个人电脑，你也可以用它来挖矿；但很可能你需要一些专用的 GPU 或专门的硬件，比如**现场可编程门阵列**（**FPGA**）和**专用集成电路**（**ASIC**）来做好挖矿工作。Kubernetes 集群中的资源可用性使它们成为攻击者赚取加密货币的理想目标。

加密挖矿攻击就像在 Wi-Fi 上免费搭车一样。就像你的网络带宽会被免费搭车者分享一样，你的 CPU 或计算资源的一部分（或大部分）将在没有你的同意的情况下被挖矿进程占用。影响也是类似的。如果 Wi-Fi 上的免费搭车者正在使用你的 Wi-Fi 网络通过 BitTorrent 下载电影，你在观看 Netflix 时可能会有不好的体验。当有挖矿进程运行时，同一节点中运行的其他应用程序也会受到严重影响，因为挖矿进程可能会大部分时间占用 CPU。

加密挖矿攻击已经成为黑客最吸引人的攻击之一，因为这几乎是一种确保能够从成功入侵中获益的方式。小偷只来偷或破坏。如果破坏不是入侵的目的，加密挖矿攻击可能是黑客的主要选择之一。

黑客发动加密挖矿攻击的至少两种方式已经被报道。一种是通过应用程序漏洞，比如跨站脚本，SQL 注入，远程代码执行等，使黑客能够访问系统，然后下载并执行挖矿程序。另一种方式是通过恶意容器镜像。当从包含挖矿程序的镜像创建容器时，挖矿过程就会开始。

尽管互联网上有不同类型的加密挖矿二进制文件，但总的来说，矿业过程是计算密集型的，占用大量 CPU 周期。矿业过程有时会加入矿业池，以便以合作的方式进行挖矿。

接下来，让我们看看发生在现实世界中的一些加密挖矿攻击。我们将讨论使攻击可能的漏洞，并研究攻击模式。

## 特斯拉的 Kubernetes 集群上的加密挖矿攻击

2018 年，特斯拉的 Kubernetes 集群遭受了一次加密挖矿攻击，并由 RedLock 报告。尽管这次攻击发生了相当长时间，但我们至少可以从中学到两件事情——使攻击可能的漏洞和攻击模式。

### 漏洞

黑客渗透了没有密码保护的 Kubernetes 仪表板。从仪表板上，黑客获得了一些重要的秘密来访问 Amazon S3 存储桶。

### 攻击模式

黑客们做了相当不错的工作，隐藏了他们的足迹，以避免被发现。以下是一些值得一提的模式：

+   矿业过程没有占用太多 CPU 周期，因此 pod 的 CPU 使用率并不太高。

+   与大多数加密挖矿案例不同，矿业过程没有加入任何知名的矿业池。相反，它有自己的矿业服务器，位于 Cloudflare 后面，这是一个内容交付网络（CDN）服务。

+   矿业过程与矿业服务器之间的通信是加密的。

通过前面的操作，黑客故意试图隐藏加密挖矿模式，以便逃避检测。

## Graboid——一次加密蠕虫攻击

这次加密蠕虫攻击是由 Palo Alto Network Unit42 研究团队在 2019 年底发现的。尽管这次攻击并不是针对 Kubernetes 集群，但它是针对 Docker 守护程序的，这是 Kubernetes 集群中的基石之一。在攻击的一个步骤中，工具包从 Docker Hub 下载包含加密挖矿二进制文件的镜像并启动。这一步也可以应用于 Kubernetes 集群。

### 漏洞

Docker 引擎暴露在互联网上，而且没有进行身份验证和授权配置。攻击者可以轻松地完全控制 Docker 引擎。

### 攻击模式

一旦黑客控制了 Docker 引擎，他们就开始下载一个恶意镜像并启动一个容器。以下是关于恶意容器值得一提的一些模式：

+   恶意容器联系了命令和控制服务器，以下载一些恶意脚本。

+   恶意容器包含了一个 Docker 客户端二进制文件，用于控制其他不安全的 Docker 引擎。

+   恶意容器通过 Docker 客户端向其他不安全的 Docker 引擎发出命令，以下载和启动另一个包含加密挖矿二进制文件的镜像。

根据 Shodan 的数据，超过 2000 个 Docker 引擎暴露在互联网上。前述步骤被重复执行，以便加密挖矿蠕虫传播。

## 吸取的教训

回顾一下我们讨论过的两种已知的加密挖矿攻击，配置错误是使黑客轻松入侵的主要问题之一。加密挖矿具有一些典型的模式，例如，挖矿过程将与挖矿池通信，而挖矿过程通常会占用大量的 CPU 周期。然而，黑客可能会故意伪装他们的挖矿行为以逃避检测。一旦黑客进入 pod，他们可以开始联系命令和控制服务器来下载和执行挖矿二进制文件；另一方面，他们也可以开始侦察。如果您的 Kubernetes 集群中的安全域没有得到适当配置，他们很容易进行横向移动。接下来，让我们使用我们在之前章节介绍的开源工具来检测 Kubernetes 集群中典型的加密挖矿活动。

# 检测加密挖矿攻击

在这一部分，我们将讨论如何使用我们在前几章介绍的一些开源工具来检测 Kubernetes 集群中的加密挖矿活动。我们基于已知的加密挖矿模式来检测加密挖矿活动：高 CPU 使用率，与挖矿池的通信，矿工的执行命令行以及二进制签名。请注意，每个单独的措施都有其自身的局限性。将它们结合起来可以提高检测的效率。然而，仍然存在一些高级的加密挖矿攻击，比如攻击特斯拉的那种。因此，有必要与安全团队合作，为您的 Kubernetes 集群应用全面的检测策略，以覆盖各种入侵。

为了演示每个工具检测加密挖矿，我们模拟一个受害者`nginx` pod：

```
$ kubectl get pods -n insecure-nginx
NAME                              READY   STATUS    RESTARTS   AGE
insecure-nginx-8455b6d49c-z6wb9   1/1     Running   0          163m
```

在`nginx` pod 内部，有一个矿工二进制文件位于`/tmp`目录中：

```
root@insecure-nginx-8455b6d49c-z6wb9:/# ls /tmp
minerd2  perg
```

`minerd2`是挖矿二进制文件。我们可以假设`minerd2`要么被种子化在镜像中，要么从命令和控制服务器下载。首先，让我们看看监控 CPU 使用率如何帮助检测加密挖矿活动。

注意

不建议在生产服务器上运行加密挖矿二进制文件。这仅供教育目的。 

## 监控 CPU 利用率

正如我们在*第十章*中讨论的那样，*Kubernetes 集群的实时监控和资源管理*，资源管理和资源监控对于维护服务的可用性至关重要。加密挖矿通常占用大量 CPU 周期，导致容器或 pod 的 CPU 使用率显着提高。让我们通过比较加密挖矿发生前后`nginx` pod 的 CPU 使用情况来看一个例子：

![图 12.1 - 挖矿前 nginx pod 的 CPU 使用情况在 Grafana 指标中](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_12_01.jpg)

图 12.1 - 挖矿前 nginx pod 的 CPU 使用情况在 Grafana 指标中

前面的截图显示了由 Prometheus 和 Grafana 监控的`insecure-nginx` pod 的 CPU 使用情况。一般来说，最大的 CPU 使用率小于`0.1`。当执行加密挖矿二进制文件时，你会发现 CPU 使用率急剧上升：

![图 12.2 - 挖矿后 nginx pod 的 CPU 使用情况](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_12_02.jpg)

图 12.2 - 挖矿后 nginx pod 的 CPU 使用情况

CPU 使用率从平均率`0.07`上升到约`2.4`。无论在幕后发生了什么，这样巨大的 CPU 使用率上升都应立即引起您的注意。很明显，即使有这样的 CPU 激增，也不意味着 pod 内运行着加密挖矿二进制文件。CPU 激增也可能是由其他原因引起的。

另一方面，如果黑客故意限制加密挖矿攻击的进展，就像对特斯拉的攻击一样，CPU 可能只会有一点点上升，很难注意到。接下来，让我们看看 Falco 如何帮助检测加密挖矿活动。

## 检测到矿池的网络流量

典型的加密挖矿进程行为是挖矿进程与同一挖矿池内的其他挖矿进程协作，以便高效地进行挖矿。挖矿进程在挖矿期间与挖矿池服务器进行通信。

在 Falco 的默认规则中，有一个规则用于检测对已知矿工池的出站连接。让我们更仔细地看看这个规则。首先，有一个用于挖矿端口和挖矿域的预定义列表([`github.com/falcosecurity/falco/blob/master/rules/falco_rules.yaml#L2590`](https://github.com/falcosecurity/falco/blob/master/rules/falco_rules.yaml#L2590))：

```
- list: miner_ports
  items: [
        25, 3333, 3334, 3335, 3336, 3357, 4444,
        5555, 5556, 5588, 5730, 6099, 6666, 7777,
        7778, 8000, 8001, 8008, 8080, 8118, 8333,
        8888, 8899, 9332, 9999, 14433, 14444,
        45560, 45700
    ]
- list: miner_domains
  items: [
      "Asia1.ethpool.org","ca.minexmr.com", "monero.crypto-pool.fr",
      ...
      "xmr-jp1.nanopool.org","xmr-us-east1.nanopool.org",
      "xmr-us-west1.nanopool.org","xmr.crypto-pool.fr",
      "xmr.pool.minergate.com"
      ]
```

然后，有一个预定义的网络连接宏用于前述矿工端口和矿工域：

```
- macro: minerpool_other
  condition: (fd.sport in (miner_ports) and fd.sip.name in (miner_domains))
```

除了`minerpool_other`宏之外，还有两个分别用于 HTTP 和 HTTPS 连接的其他宏—`minerpool_http`和`minerpool_https`—它们都结合起来得到主要的检测逻辑：

```
- macro: net_miner_pool
  condition: (evt.type in (sendto, sendmsg) and evt.dir=< and (fd.net != "127.0.0.0/8" and not fd.snet in (rfc_1918_addresses)) and ((minerpool_http) or (minerpool_https) or (minerpool_other)))
```

然后，`net_miner_pool`宏由`检测出站连接到常见矿工池端口`规则使用，以检测出站连接到矿工域：

```
# The rule is disabled by default.
# Note: Falco will send DNS requests to resolve miner pool domains which may trigger alerts in your environment.
- rule: Detect outbound connections to common miner pool ports
  desc: Miners typically connect to miner pools on common ports.
  condition: net_miner_pool and not trusted_images_query_miner_domain_dns
  enabled: true
  output: Outbound connection to IP/Port flagged by cryptoioc.ch (command=%proc.cmdline port=%fd.rport ip=%fd.rip container=%container.info image=%container.image.repository)
  priority: CRITICAL
  tags: [network, mitre_execution]
```

如果有一个正在运行并与列表中定义的矿工域进行通信的加密挖矿进程，警报将被触发，如下所示：

```
19:46:37.939287649: Critical Outbound connection to IP/Port flagged by cryptoioc.ch (command=minerd2 -a cryptonight -o stratum+tcp://monero.crypto-pool.fr:3333 -u 49TfoHGd6apXxNQTSHrMBq891vH6JiHmZHbz5Vx36nLRbz6WgcJunTtgcxno G6snKFeGhAJB5LjyAEnvhBgCs5MtEgML3LU -p x port=37110 ip=100.97.244.198 container=k8s.ns=insecure-nginx k8s.pod=insecure-nginx-8455b6d49c-z6wb9 container=07dce07d5100 image=kaizheh/victim) k8s.ns=insecure-nginx k8s.pod=insecure-nginx-8455b6d49c-z6wb9 container=07dce07d5100 k8s.ns=insecure-nginx k8s.pod=insecure-nginx-8455b6d49c-z6wb9 container=07dce07d5100
```

`检测出站连接到常见矿工池端口`规则很简单。如果这个规则生成了一个警报，你应该把它作为高优先级处理。规则的限制也很明显；您将不得不保持挖矿域和挖矿端口的更新。如果有新的挖矿域可用或者使用了新的挖矿服务器端口，并且它们没有添加到 Falco 列表中，那么规则将无法检测到加密挖矿活动。请注意，该规则默认情况下是禁用的。由于 Falco 需要发送 DNS 请求来解析矿工池域名，这些 DNS 请求将被一些云提供商警报。一个副作用是，像 Cilium 的 Hubble 这样的开源工具可以帮助监控网络流量。

另一种方法是使用白名单方法。如果您知道微服务的出站连接中的目标端口或 IP 块，您可以创建 Falco 规则来警报不在白名单上的任何出站连接的目标 IP 或端口。以下是一个例子：

```
- list: trusted_server_addresses
  items: [...]
- list: trusted_server_ports
  items: [...]
- rule: Detect anomalous outbound connections 
  desc: Detect anomalous outbound connections
  condition: (evt.type in (sendto, sendmsg) and container and evt.dir=< and (fd.net != "127.0.0.0/8" and not fd.snet in (trusted_server_addresses) or not fd.sport in (trusted_server_ports))) 
  output: Outbound connection to anomalous IP/Port(command=%proc.cmdline port=%fd.rport ip=%fd.rip container=%container.info image=%container.image.repository)
  priority: CRITICAL
```

上述规则将警报任何对`trusted_server_ports`或`trusted_server_addresses`之外的 IP 地址或端口的出站连接。鉴于攻击发生在特斯拉，Falco 将警报存在异常连接，即使 IP 地址看起来正常。接下来，让我们看另一个 Falco 规则，根据命令行中的模式来检测潜在的加密挖矿活动。

## 检测已启动的加密挖矿进程

Stratum 挖矿协议是与挖矿服务器进行通信的挖矿过程中最常见的协议。一些挖矿二进制文件允许用户在执行时指定与挖矿池服务器通信的协议。

在 Falco 的默认规则中，有一个规则是基于命令行中的关键字来检测加密二进制文件的执行：

```
- rule: Detect crypto miners using the Stratum protocol
  desc: Miners typically specify the mining pool to connect to with a URI that begins with 'stratum+tcp'
  condition: spawned_process and proc.cmdline contains "stratum+tcp"
  output: Possible miner running (command=%proc.cmdline container=%container.info image=%container.image.repository)
  priority: CRITICAL
  tags: [process, mitre_execution]
```

如果 Falco 检测到任何使用`stratum+tcp`启动的进程并且在进程的命令行中指定了，那么`检测使用 Stratum 协议的加密矿工`规则将引发警报。输出如下：

```
19:46:37.779784798: Critical Possible miner running (command=minerd2 -a cryptonight -o stratum+tcp://monero.crypto-pool.fr:3333 -u 49TfoHGd6apXxNQTSHrMBq891vH6JiHmZHbz5Vx36 nLRbz6WgcJunTtgcxnoG6snKFeGhAJB5LjyAEnvhBgCs5MtEgML3LU -p x container=k8s.ns=insecure-nginx k8s.pod=insecure-nginx-8455b6d49c-z6wb9 container=07dce07d5100 image=kaizheh/victim) k8s.ns=insecure-nginx k8s.pod=insecure-nginx-8455b6d49c-z6wb9 container=07dce07d5100 k8s.ns=insecure-nginx k8s.pod=insecure-nginx-8455b6d49c-z6wb9 container=07dce07d5100
```

执行的`minerd2 -a cryptonight -o stratum+tcp://monero.crypto-pool.fr:3333 -u 49TfoHGd6apXxNQTSHrMBq891vH6JiHmZHbz5Vx36nLRbz6Wgc JunTtgcxnoG6snKFeGhAJB5LjyAEnvhBgCs5MtEgML3LU -p x`命令行包含了`stratum+tcp`关键字。这就是为什么会触发警报。

与其他基于名称的检测规则一样，该规则的限制是显而易见的。如果加密二进制执行文件不包含`stratum+tcp`，则该规则将不会被触发。

上述规则使用了黑名单方法。另一种方法是使用白名单方法，如果您知道将在微服务中运行的进程。您可以定义一个 Falco 规则，当启动任何不在信任列表上的进程时引发警报。以下是一个示例：

```
- list: trusted_nginx_processes
  items: ["nginx"]
- rule: Detect Anomalous Process Launched in Nginx Container
  desc: Anomalous process launched inside container.
  condition: spawned_process and container and not proc.name in (trusted_nginx_processes) and image.repository.name="nginx"
  output: Anomalous process running in Nginx container (command=%proc.cmdline container=%container.info image=%container.image.repository)
  priority: CRITICAL
  tags: [process]
```

上述规则将警报任何在`nginx`容器中启动的异常进程，其中包括加密挖矿进程。最后，让我们看看图像扫描工具如何通过与恶意软件源集成来帮助检测加密挖矿二进制文件的存在。

## 检查二进制签名

加密挖矿二进制文件有时可以被识别为恶意软件。与传统的反病毒软件一样，我们也可以检查运行中的二进制文件的哈希值与恶意软件源的匹配情况。借助图像扫描工具，比如 Anchore，我们可以获取文件的哈希值：

```
root@anchore-cli:/# anchore-cli --json image content kaizheh/victim:nginx files | jq '.content | .[] | select(.filename=="/tmp/minerd2")'
{
  "filename": "/tmp/minerd2",
  "gid": 0,
  "linkdest": null,
  "mode": "00755",
  "sha256": "e86db6abf96f5851ee476eeb8c847cd73aebd0bd903827a362 c07389d71bc728",
  "size": 183048,
  "type": "file",
  "uid": 0
}
```

`/tmp/minerd2`文件的哈希值为`e86db6abf96f5851ee476eeb8c847cd73aebd0bd903827a362c07389d71bc728`。然后，我们可以将哈希值与 VirusTotal 进行比对，VirusTotal 提供恶意软件信息源服务：

```
$ curl -H "Content-Type: application/json" "https://www.virustotal.com/vtapi/v2/file/report?apikey=$VIRUS_FEEDS_API_KEY&resource=e86db6abf96f5851ee476eeb8c847cd73aebd0bd903827a 362c07389d71bc728" | jq .
```

`$VIRUS_FEEDS_API_KEY`是您访问 VirusTotal API 服务的 API 密钥，然后提供以下报告：

```
{
  "scans": {
    "Fortinet": {
      "detected": true,
      "version": "6.2.142.0",
      "result": "Riskware/CoinMiner",
      "update": "20200413"
    },
    ...
    "Antiy-AVL": {
      "detected": true,
      "version": "3.0.0.1",
      "result": "RiskWare[RiskTool]/Linux.BitCoinMiner.a",
      "update": "20200413"
    },
  },
  ...
  "resource": "e86db6abf96f5851ee476eeb8c847cd73aebd0bd903827a362c07389d71bc 728",
  "scan_date": "2020-04-13 18:22:56",
  "total": 60,
  "positives": 25,
  "sha256": "e86db6abf96f5851ee476eeb8c847cd73aebd0bd903827a362c07389d71bc 728",
 }
```

VirusTotal 报告显示，`/tmp/minerd2`已被 25 个不同的信息源报告为恶意软件，如 Fortinet 和 Antiy AVL。通过在 CI/CD 流水线中集成图像扫描工具和恶意软件信息源服务，您可以帮助在开发生命周期的早期阶段检测恶意软件。然而，这种单一方法的缺点是，如果挖矿二进制文件从命令和控制服务器下载到运行的 Pod 中，您将错过加密挖矿攻击。另一个限制是，如果信息源服务器没有关于加密二进制文件的任何信息，您肯定会错过它。

我们已经讨论了四种不同的方法来检测加密挖矿攻击。每种方法都有其自身的优点和局限性；将一些这些方法结合起来以提高其检测能力和检测效果将是理想的。

接下来，让我们回顾一下我们在本书中讨论的内容，并全面运用这些知识来预防一般性的攻击。

# 防御攻击

在前一节中，我们讨论了几种检测加密挖矿活动的方法。在本节中，我们将讨论通过保护 Kubernetes 集群来防御攻击。因此，这不仅涉及防御特定攻击，还涉及防御各种攻击。四个主要的防御领域是 Kubernetes 集群供应、构建、部署和运行时。首先，让我们谈谈保护 Kubernetes 集群供应。

## 保护 Kubernetes 集群供应

有多种方法可以配置 Kubernetes 集群，比如`kops`和`kubeadm`。无论您使用哪种工具来配置集群，每个 Kubernetes 组件都需要进行安全配置。使用`kube-bench`来对您的 Kubernetes 集群进行基准测试，并改进安全配置。确保启用了 RBAC，禁用了`--anonymous-auth`标志，网络连接进行了加密等等。以下是我们在*第六章*中涵盖的关键领域，*保护集群组件*，以及*第七章*，*身份验证、授权和准入控制*：

+   为 Kubernetes 控制平面、`kubelet`等正确配置身份验证和授权

+   保护 Kubernetes 组件之间的通信，例如`kube-apiserver`、`kubelet`、`kube-apiserver`和`etcd`之间的通信

+   为`etcd`启用静态数据加密

+   确保不启动不必要的组件，比如仪表板

+   确保所有必要的准入控制器都已启用，而已弃用的控制器已禁用

通过安全配置 Kubernetes 集群，可以减少黑客轻易入侵您的 Kubernetes 集群的机会，就像特斯拉的集群一样（其中仪表板不需要身份验证）。接下来，让我们谈谈如何保护构建。

## 保护构建

保护 Kubernetes 集群还包括保护微服务。保护微服务必须从 CI/CD 流水线的开始进行。以下是一些关键的对策，如*第八章*中讨论的，*保护 Kubernetes Pod*，以及*第九章*，*DevOps 流水线中的图像扫描*，以在构建阶段保护微服务：

+   妥善处理图像扫描工具发现的微服务漏洞，以减少通过利用应用程序漏洞成功入侵的可能性。

+   对 Dockerfile 进行基准测试，以改进镜像的安全配置。确保镜像中没有存储敏感数据，所有依赖包都已更新等等。

+   扫描镜像中的可执行文件，确保没有恶意软件植入镜像。

+   为工作负载正确配置 Kubernetes 安全上下文。遵循最小特权原则，限制对系统资源的访问，比如使用主机级别的命名空间、主机路径等，并移除不必要的 Linux 能力，只授予必需的能力。

+   不要启用自动挂载服务账户。如果工作负载不需要服务账户，就不要为其创建服务账户。

+   遵循最小特权原则，尝试了解工作负载正在执行的任务，并只授予服务账户所需的特权。

+   遵循最小特权原则，尝试估计工作负载的资源使用情况，并为工作负载应用适当的资源请求和限制。

当然，保护构建也可以扩展到保护整个 CI/CD 流水线，比如源代码管理和 CI/CD 组件。然而，这超出了本书的范围。我们只会建议我们认为最相关的保护 Kubernetes 集群的选项。接下来，让我们谈谈保护部署。

## 保护部署

我们已经在 Kubernetes 集群中的*第七章*、*认证、授权和准入控制*，以及*第八章*、*保护 Kubernetes Pods*中讨论了不同类型的准入控制器，以及正确使用它们的必要性，例如一个镜像扫描准入控制器的示例（*第九章*、*DevOps 流水线中的镜像扫描*）。使用准入控制器和其他内置机制作为工作负载的重要安全门卫。以下是一些关键的对策：

+   为命名空间和工作负载应用网络策略。这可以是限制对工作负载的访问（入站网络策略），也可以是实施最小特权原则（出站网络策略）。当给定一个工作负载时，如果你知道出站连接的目标 IP 块，你应该为该工作负载创建一个网络策略来限制其出站连接。出站网络策略应该阻止任何超出白名单 IP 块的目的地流量，比如从命令和控制服务器下载加密挖矿二进制文件。

+   使用**Open Policy Agent**（**OPA**）来确保只有来自受信任的镜像仓库的镜像被允许在集群中运行。有了这个策略，OPA 应该阻止来自不受信任来源的镜像运行。例如，可能存在包含加密挖矿二进制文件的恶意镜像在 Docker Hub 中，因此您不应该将 Docker Hub 视为受信任的镜像仓库。

+   使用镜像扫描准入控制器来确保只有符合扫描策略的镜像被允许在集群中运行。我们已经在[*第九章*]（B15566_09_Final_ASB_ePub.xhtml#_idTextAnchor277）中谈到了这一点，*DevOps 流水线中的镜像扫描*。可能会发现新的漏洞，并且在部署工作负载时漏洞数据库将会更新。在部署之前进行扫描是必要的。

+   使用 OPA 或 Pod 安全策略来确保具有受限 Linux 功能和对主机级命名空间、主机路径等受限访问权限的工作负载。

+   最好在工作节点上启用 AppArmor，并为部署的每个镜像应用一个 AppArmor 配置文件。当工作负载部署时，会限制 AppArmor 配置文件，尽管实际的保护是在运行时发生的。一个很好的用例是构建一个 AppArmor 配置文件，以允许白名单内的进程运行，当您知道容器内运行的进程时，这样其他进程，比如加密挖矿进程，将被 AppArmor 阻止。

利用准入控制器的力量，为您的工作负载部署构建一个门卫。接下来，让我们谈谈在运行时保护工作负载。

## 保护运行时

很可能，您的 Kubernetes 集群是与黑客作战的前线。尽管我们讨论了不同的策略来保护构建和部署，但所有这些策略最终都旨在减少 Kubernetes 集群中的攻击面。您不能简单地闭上眼睛，假设您的 Kubernetes 集群一切都会好起来。这就是为什么我们在[*第十章*]（B15566_10_Final_ASB_ePub.xhtml#_idTextAnchor305）中谈论资源监控，*Kubernetes 集群的实时监控和资源管理*，以及审计、秘钥管理、检测和取证在[*第十一章*]（B15566_11_Final_ASB_ePub.xhtml#_idTextAnchor324）中，*深度防御*。总结一下在这两章中涵盖的内容，以下是保护运行时的关键对策：

+   部署像 Prometheus 和 Grafana 这样的良好的监控工具，以监控 Kubernetes 集群中的资源使用情况。这对于确保服务的可用性至关重要，而且像加密货币挖矿这样的攻击可能会引发 CPU 使用率的激增。

+   启用 Kubernetes 的审计策略以记录 Kubernetes 事件和活动。

+   确保基础设施、Kubernetes 组件和工作负载的高可用性。

+   使用像 Vault 这样的良好的秘密管理工具来管理和提供微服务的秘密。

+   部署像 Falco 这样的良好的检测工具，以侦测 Kubernetes 集群中的可疑活动。

+   最好有取证工具来收集和分析可疑事件。

你可能注意到保护微服务间通信并未被提及。服务网格是一个热门话题，可以帮助保障微服务及其间通信，但出于两个原因，本书未涵盖服务网格：

+   服务网格会给工作负载和 Kubernetes 集群带来性能开销，因此它们还不是保障服务间通信的完美解决方案。

+   从应用安全的角度来看，可以轻松地强制应用程序在 443 端口上监听，并使用 CA 签名证书进行加密通信。如果微服务还执行身份验证和授权，那么只有受信任的微服务才能访问授权资源。服务网格并非保障服务间通信的不可替代解决方案。

为了防御针对 Kubernetes 集群的攻击，我们需要从头到尾保护 Kubernetes 集群的供应、构建、部署和运行。它们都应被视为同等重要，因为你的防御力取决于最薄弱的环节。

# 总结

在本章中，我们回顾了过去两年发生的一些加密货币挖矿攻击，这引起了对保护容器化环境需求的广泛关注。然后，我们向你展示了如何使用不同的开源工具来检测加密货币挖矿攻击。最后但同样重要的是，我们讨论了如何通过总结前几章的内容来保护你的 Kubernetes 集群免受攻击。

我们希望你理解保护 Kubernetes 集群的核心概念，这意味着保护集群的供应、构建、部署和运行阶段。你也应该对开始使用 Anchore、Prometheus、Grafana 和 Falco 感到满意。

众所周知，Kubernetes 仍在不断发展，并不完美。在下一章中，我们将讨论一些已知的 Kubernetes**常见漏洞和曝光**（**CVEs**）以及一些可以保护您的集群免受未知变体影响的缓解措施。以下一章的目的是为了让您能够应对未来发现的任何 Kubernetes CVEs。

# 问题

+   是什么缺陷导致了特斯拉的 Kubernetes 集群中发生了加密挖矿攻击？

+   如果您是特斯拉的 DevOps，您会采取什么措施来防止加密挖矿攻击？

+   当您在一个容器中看到 CPU 使用率激增时，您能否得出结论说发生了加密挖矿攻击？

+   您能想到一种可以绕过“使用 Stratum 协议检测加密挖矿程序”的 Falco 规则的加密挖矿过程吗？

+   为了保护您的 Kubernetes 集群，您需要保护哪四个领域？

# 进一步阅读

有关本章涵盖的主题的更多信息，请参考以下链接：

+   特斯拉加密挖矿攻击：[`redlock.io/blog/cryptojacking-tesla`](https://redlock.io/blog/cryptojacking-tesla)

+   加密蠕虫攻击：[`unit42.paloaltonetworks.com/graboid-first-ever-cryptojacking-worm-found-in-images-on-docker-hub/`](https://unit42.paloaltonetworks.com/graboid-first-ever-cryptojacking-worm-found-in-images-on-docker-hub/)

+   普罗米修斯：[`prometheus.io/docs/introduction/overview/`](https://prometheus.io/docs/introduction/overview/)

+   Falco：[`falco.org/docs/`](https://falco.org/docs/)

+   VirusTotal API：[`developers.virustotal.com/v3.0/reference`](https://developers.virustotal.com/v3.0/reference)

+   加密挖矿攻击分析：[`kromtech.com/blog/security-center/cryptojacking-invades-cloud-how-modern-containerization-trend-is-exploited-by-attackers`](https://kromtech.com/blog/security-center/cryptojacking-invades-cloud-how-modern-containerization-trend-is-exploited-by-attackers)

+   哈勃：[`github.com/cilium/hubble`](https://github.com/cilium/hubble)


# 第十三章：从 Kubernetes CVEs 中学习

**通用漏洞和暴露**（**CVEs**）是对广为人知的安全漏洞和暴露的标识，这些漏洞和暴露存在于流行的应用程序中。CVE ID 由`CVE`字符串后跟漏洞的年份和 ID 号组成。CVE 数据库是公开可用的，并由 MITRE 公司维护。CVE 条目包括每个问题的简要描述，有助于了解问题的根本原因和严重程度。这些条目不包括问题的技术细节。CVE 对于 IT 专业人员协调和优先更新是有用的。每个 CVE 都有与之相关的严重性。MITRE 使用**通用漏洞评分系统**（**CVSS**）为 CVE 分配严重性评级。建议立即修补高严重性的 CVE。让我们看一个在[cve.mitre.org](http://cve.mitre.org)上的 CVE 条目的例子。

如下截图所示，CVE 条目包括 ID、简要描述、参考文献、**CVE 编号管理机构**（**CNA**）的名称以及条目创建日期：

![图 13.1 - CVE-2018-18264 的 MITRE 条目](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_13_001.jpg)

图 13.1 - CVE-2018-18264 的 MITRE 条目

对于安全研究人员和攻击者来说，CVE 条目最有趣的部分是**参考文献**部分。CVE 的参考文献是指研究人员发布的博客链接，涵盖了问题的技术细节，以及问题描述和拉取请求的链接。安全研究人员研究这些参考文献，以了解漏洞并开发类似问题的缓解措施，或者针对尚未修复的已知问题。另一方面，攻击者研究这些参考文献，以找到未修补的问题变体。

在本章中，我们将讨论 Kubernetes 的四个公开已知安全漏洞。首先，我们将看一下路径遍历问题-CVE-2019-11246。这个问题允许攻击者修改客户端的内容，这可能导致数据泄露或在集群管理员的机器上执行代码。接下来，我们将讨论 CVE-2019-1002100，它允许用户对 API 服务器进行**拒绝服务**（DoS）攻击。然后，我们将讨论 CVE-2019-11253，它允许未经身份验证的用户对`kube-apiserver`进行 DoS 攻击。最后，我们将讨论 CVE-2019-11247，它允许具有命名空间权限的用户修改集群范围的资源。我们将讨论每个 CVE 的缓解策略。升级到 Kubernetes 和`kubectl`的最新版本，以修补漏洞，应该是您的首要任务。Kubernetes 的最新稳定版本可以在[`github.com/kubernetes/kubernetes/releases`](https://github.com/kubernetes/kubernetes/releases)找到。我们将讨论的缓解策略将有助于加强您的集群对类似性质的攻击。最后，我们将介绍`kube-hunter`，它可以用于扫描已知安全漏洞的 Kubernetes 集群。

在本章中，我们将涵盖以下主题：

+   kubectl cp 中的路径遍历问题-CVE-2019-11246

+   JSON 解析中的 DoS 问题-CVE-2019-1002100

+   YAML 解析中的 DoS 问题-CVE-2019-11253

+   角色解析中的特权升级问题-CVE-2019-11247

+   使用 kube-hunter 扫描已知漏洞

# kubectl cp 中的路径遍历问题-CVE-2019-11246

开发人员经常为调试目的将文件复制到或从 Pod 中的容器中。 `kubectl cp`允许开发人员从 Pod 中的容器复制文件，或者将文件复制到 Pod 中的容器（默认情况下，这是在 Pod 中的第一个容器中完成的）。

要将文件复制到 Pod，您可以使用以下方法：

```
kubectl cp /tmp/test <pod>:/tmp/bar
```

要从 Pod 复制文件，您可以使用以下方法：

```
kubectl cp <some-pod>:/tmp/foo /tmp/bar
```

当文件从一个 pod 中复制时，Kubernetes 首先创建文件内部的文件的 TAR 归档。然后将 TAR 归档复制到客户端，最后为客户端解压 TAR 归档。2018 年，研究人员发现了一种方法，可以使用`kubectl cp`来覆盖客户端主机上的文件。如果攻击者可以访问一个 pod，这个漏洞可以被用来用恶意文件替换 TAR 归档。当畸形的 TAR 文件被复制到主机时，它可以在解压时覆盖主机上的文件。这可能导致数据泄露和主机上的代码执行。

让我们看一个例子，攻击者修改 TAR 归档，使其包含两个文件：`regular.txt`和`foo/../../../../bin/ps`。在这个归档中，`regular.txt`是用户期望的文件，`ps`是一个恶意二进制文件。如果这个归档被复制到`/home/user/admin`，恶意二进制文件将覆盖`bin`文件夹中的众所周知的`ps`二进制文件。这个问题的第一个补丁是不完整的，攻击者找到了一种利用符号链接的方法来利用相同的问题。研究人员找到了一种绕过符号链接修复的方法，最终在 1.12.9、1.13.6 和 1.14.2 版本中解决了这个问题，并被分配了 CVE-2019-11246。

## 缓解策略

您可以使用以下策略来加固您的集群，以防止这个问题和类似于 CVE-2019-11246 的问题：

+   **始终使用更新版本的 kubectl**：您可以使用以下命令找到`kubectl`二进制文件的最新版本：

```
$ curl https://storage.googleapis.com/kubernetes-release/release/stable.txt
v1.18.3
```

+   **使用准入控制器限制 kubectl cp 的使用**：正如我们在*第七章*中讨论的那样，*身份验证、授权和准入控制*，Open Policy Agent 可以用作准入控制器。让我们看一个拒绝调用`kubectl cp`的策略：

```
deny[reason] {
  input.request.kind.kind == "PodExecOptions"
  input.request.resource.resource == "pods"
  input.request.subResource == "exec"
  input.request.object.command[0] == "tar"
  reason = sprintf("kubectl cp was detected on %v/%v by user: %v", [
    input.request.namespace,
    input.request.object.container,
    input.request.userInfo.username])
}
```

这个策略拒绝了 pod 中 TAR 二进制文件的执行，从而禁用了所有用户的`kubectl cp`。您可以更新此策略，以允许特定用户或组的`kubectl cp`。

+   为客户端应用适当的访问控制：如果您是生产集群的管理员，您的工作机器上有许多攻击者可能想要访问的机密信息。理想情况下，构建机器不应该是您的工作笔记本电脑。管理员可以`ssh`到的专用硬件来访问 Kubernetes 集群是一个良好的做法。您还应确保构建机器上的任何敏感数据都具有适当的访问控制。

+   为所有 pod 设置安全上下文：如*第八章*中所讨论的，*保护 Kubernetes Pod*，确保 pod 具有`readOnlyRootFilesystem`，这将防止攻击者在文件系统中篡改文件（例如，覆盖`/bin/tar`二进制文件）。

```
spec:
    securityContext:
        readOnlyRootFilesystem: true
```

+   使用 Falco 规则检测文件修改：我们在*第十一章*中讨论了 Falco，*深度防御*。Falco 规则（可以在[`github.com/falcosecurity/falco/blob/master/rules/falco_rules.yaml`](https://github.com/falcosecurity/falco/blob/master/rules/falco_rules.yaml)找到）可以设置为执行以下操作：

检测 pod 中二进制文件的修改：使用默认的 Falco 规则中的`Write below monitored dir`来检测对 TAR 二进制文件的更改：

```
- rule: Write below monitored dir
  desc: an attempt to write to any file below a set of binary directories
  condition: >
    evt.dir = < and open_write and monitored_dir
    and not package_mgmt_procs
    and not coreos_write_ssh_dir
    and not exe_running_docker_save
    and not python_running_get_pip
    and not python_running_ms_oms
    and not google_accounts_daemon_writing_ssh
    and not cloud_init_writing_ssh
    and not user_known_write_monitored_dir_conditions
  output: >
    File below a monitored directory opened for writing (user=%user.name
    command=%proc.cmdline file=%fd.name parent=%proc.pname pcmdline=%proc.pcmdline gparent=%proc.aname[2] container_id=%container.id image=%container.image.repository)
  priority: ERROR
  tags: [filesystem, mitre_persistence]
```

检测使用易受攻击的 kubectl 实例：`kubectl`版本 1.12.9、1.13.6 和 1.14.2 已修复了此问题。使用早于此版本的任何版本都将触发以下规则：

```
- macro: safe_kubectl_version
  condition: (jevt.value[/userAgent] startswith "kubectl/v1.15" or
              jevt.value[/userAgent] startswith "kubectl/v1.14.3" or
              jevt.value[/userAgent] startswith "kubectl/v1.14.2" or
              jevt.value[/userAgent] startswith "kubectl/v1.13.7" or
              jevt.value[/userAgent] startswith "kubectl/v1.13.6" or
              jevt.value[/userAgent] startswith "kubectl/v1.12.9")
# CVE-2019-1002101
# Run kubectl version --client and if it does not say client version 1.12.9,
1.13.6, or 1.14.2 or newer,  you are running a vulnerable version.
- rule: K8s Vulnerable Kubectl Copy
  desc: Detect any attempt vulnerable kubectl copy in pod
  condition: kevt_started and pod_subresource and kcreate and
             ka.target.subresource = "exec" and ka.uri.param[command] = "tar" and
             not safe_kubectl_version
  output: Vulnerable kubectl copy detected (user=%ka.user.name pod=%ka.target.name ns=%ka.target.namespace action=%ka.target.subresource command=%ka.uri.param[command] userAgent=%jevt.value[/userAgent])
  priority: WARNING
  source: k8s_audit
  tags: [k8s]
```

CVE-2019-11246 是为什么您需要跟踪安全公告并阅读技术细节以添加减轻策略到您的集群以确保如果发现问题的任何变化，您的集群是安全的一个很好的例子。接下来，我们将看看 CVE-2019-1002100，它可以用于在`kube-apiserver`上引起 DoS 问题。

# JSON 解析中的 DoS 问题-CVE-2019-1002100

修补是一种常用的技术，用于在运行时更新 API 对象。开发人员使用`kubectl patch`在运行时更新 API 对象。一个简单的例子是向 pod 添加一个容器：

```
spec:
  template:
    spec:
      containers:
      - name: db
        image: redis
```

前面的补丁文件允许一个 pod 被更新以拥有一个新的 Redis 容器。`kubectl patch`允许补丁以 JSON 格式。问题出现在`kube-apiserver`的 JSON 解析代码中，这允许攻击者发送一个格式错误的`json-patch`实例来对 API 服务器进行 DoS 攻击。在*第十章*中，*Kubernetes 集群的实时监控和资源管理*，我们讨论了 Kubernetes 集群中服务可用性的重要性。这个问题的根本原因是`kube-apiserver`对`patch`请求的未经检查的错误条件和无限制的内存分配。

## 缓解策略

你可以使用以下策略来加固你的集群，以防止这个问题和类似 CVE-2019-100210 的问题：

+   **在 Kubernetes 集群中使用资源监控工具**：如*第十章*中所讨论的，*Kubernetes 集群的实时监控和资源管理*，资源监控工具如 Prometheus 和 Grafana 可以帮助识别主节点内存消耗过高的问题。在 Prometheus 指标图表中，高数值可能如下所示：

```
container_memory_max_usage_bytes{pod_ name="kube-apiserver-xxx" }
sum(rate(container_cpu_usage_seconds_total{pod_name="kube-apiserver-xxx"}[5m]))
sum(rate(container_network_receive_bytes_total{pod_name="kube-apiserver-xxx"}[5m]))
```

这些资源图表显示了`kube-apiserver`在 5 分钟间隔内的最大内存、CPU 和网络使用情况。这些使用模式中的任何异常都是`kube-apiserver`受到攻击的迹象。

+   **建立高可用性的 Kubernetes 主节点**：我们在*第十一章*中学习了高可用性集群，*深度防御*。高可用性集群有多个 Kubernetes 组件的实例。如果一个组件的负载很高，其他实例可以被使用，直到负载减少或第一个实例重新启动。

使用`kops`，你可以使用`--master-zones={zone1, zone2}`来拥有多个主节点：

```
kops create cluster k8s-clusters.k8s-demo-zone.com \
  --cloud aws \
  --node-count 3 \
  --zones $ZONES \
  --node-size $NODE_SIZE \
  --master-size $MASTER_SIZE \
  --master-zones $ZONES \
  --networking calico \
  --kubernetes-version 1.14.3 \
  --yes \
kube-apiserver-ip-172-20-43-65.ec2.internal              1/1     Running   4          4h16m
kube-apiserver-ip-172-20-67-151.ec2.internal             1/1     Running   4          4h15m
```

正如您所看到的，这个集群中有多个`kube-apiserver` pods 在运行。

+   **使用 RBAC 限制用户权限**：用户的权限也应该遵循最小权限原则，这在*第四章*中已经讨论过，*在 Kubernetes 中应用最小权限原则*。如果用户不需要访问任何资源的`PATCH`权限，角色应该被更新以便他们没有访问权限。

+   **在暂存环境中测试您的补丁**：暂存环境应设置为生产环境的副本。开发人员并不完美，因此开发人员可能会创建格式不正确的补丁。如果在暂存环境中测试集群的补丁或更新，就可以在不影响生产服务的情况下发现补丁中的错误。

DoS 通常被认为是低严重性问题，但如果发生在集群的核心组件上，您应该认真对待。对`kube-apiserver`的 DoS 攻击可能会破坏整个集群的可用性。接下来，我们将看看针对 API 服务器的另一种 DoS 攻击。未经身份验证的用户可以执行此攻击，使其比 CVE-2019-1002100 更严重。

# YAML 解析中的 DoS 问题 - CVE-2019-11253

XML 炸弹或十亿笑攻击在任何 XML 解析代码中都很受欢迎。与 XML 解析问题类似，这是发送到`kube-apiserver`的 YAML 文件中的解析问题。如果发送到服务器的 YAML 文件具有递归引用，它会触发`kube-apiserver`消耗 CPU 资源，从而导致 API 服务器的可用性问题。在大多数情况下，由`kube-apiserver`解析的请求受限于经过身份验证的用户，因此未经身份验证的用户不应该能够触发此问题。在 Kubernetes 版本 1.14 之前的版本中有一个例外，允许未经身份验证的用户使用`kubectl auth can-i`来检查他们是否能执行操作。

这个问题类似于 CVE-2019-1002100，但更严重，因为未经身份验证的用户也可以触发此问题。

## 缓解策略

您可以使用以下策略来加固您的集群，以防止此问题和类似于 CVE-2019-11253 的尚未发现的问题：

+   **在 Kubernetes 集群中使用资源监控工具**：类似于 CVE-2019-1002100，资源监控工具（如 Prometheus 和 Grafana）可以帮助识别主节点内存消耗过高的问题，我们在*第十章*中讨论了*实时监控和资源管理的 Kubernetes 集群*。

+   **启用 RBAC**：漏洞是由`kube-apiserver`在 YAML 文件中对递归实体的处理不当以及未经身份验证的用户与`kube-apiserver`交互的能力引起的。我们在*第七章*中讨论了 RBAC，*身份验证、授权和准入控制*。RBAC 在当前版本的 Kubernetes 中默认启用。您也可以通过将`--authorization-mode=RBAC`传递给`kube-apiserver`来启用它。在这种情况下，未经身份验证的用户不应被允许与`kube-apiserver`交互。对于经过身份验证的用户，应遵循最小特权原则。

+   **为未经身份验证的用户禁用 auth can-i（对于 v1.14.x）**：不应允许未经身份验证的用户与`kube-apiserver`交互。在 Kubernetes v1.14.x 中，您可以使用[`github.com/kubernetes/kubernetes/files/3735508/rbac.yaml.txt`](https://github.com/kubernetes/kubernetes/files/3735508/rbac.yaml.txt)中的 RBAC 文件禁用未经身份验证的服务器的`auth can-i`：

```
kubectl auth reconcile -f rbac.yaml --remove-extra-subjects --remove-extra-permissions
kubectl annotate --overwrite clusterrolebinding/system:basic-user rbac.authorization.kubernetes.io/autoupdate=false 
```

第二个命令禁用了`clusterrolebinding`的自动更新，这将确保在重新启动时不会覆盖更改。

+   **kube-apiserver 不应暴露在互联网上**：允许来自受信任实体的 API 服务器访问使用防火墙或 VPC 是一个良好的做法。

+   **禁用匿名身份验证**：我们在*第六章*中讨论了`anonymous-auth`作为一个应该在可能的情况下禁用的选项，*保护集群组件*。匿名身份验证在 Kubernetes 1.16+中默认启用以用于传统策略规则。如果您没有使用任何传统规则，建议默认禁用`anonymous-auth`，方法是将`--anonymous-auth=false`传递给 API 服务器。

正如我们之前讨论的，对`kube-apiserver`的 DoS 攻击可能会导致整个集群的服务中断。除了使用包含此问题补丁的最新版本的 Kubernetes 之外，重要的是遵循这些缓解策略，以避免集群中出现类似问题。接下来，我们将讨论授权模块中触发经过身份验证用户特权升级的问题。

# 角色解析中的特权升级问题 – CVE-2019-11247

我们在*第七章*中详细讨论了 RBAC，*认证、授权和准入控制*。角色和角色绑定允许用户获得执行某些操作的特权。这些特权是有命名空间的。如果用户需要集群范围的特权，则使用集群角色和集群角色绑定。这个问题允许用户进行集群范围的修改，即使他们的特权是有命名空间的。准入控制器的配置，比如 Open Policy Access，可以被具有命名空间角色的用户修改。

## 缓解策略

您可以使用以下策略来加固您的集群，以防止这个问题和类似 CVE-2019-11247 的问题：

+   **避免在角色和角色绑定中使用通配符**：角色和集群角色应该特定于资源名称、动词和 API 组。在 `roles` 中添加 `*` 可以允许用户访问他们本不应该访问的资源。这符合我们在*第四章*中讨论的最小特权原则，*在 Kubernetes 中应用最小特权原则*。

+   **启用 Kubernetes 审计**：我们在*第十一章*中讨论了 Kubernetes 的审计和审计策略，*深度防御*。Kubernetes 的审计可以帮助识别集群中的任何意外操作。在大多数情况下，这样的漏洞会被用来修改和删除集群中的任何额外控制。您可以使用以下策略来识别这类利用的实例：

```
  apiVersion: audit.k8s.io/v1 # This is required.
      kind: Policy
      rules:
      - level: RequestResponse
        verbs: ["patch", "update", "delete"]
        resources:
        - group: ""
          resources: ["pods"]
          namespaces: ["kube-system", "monitoring"]
```

此策略记录了在 `kube-system` 或 `monitoring` 命名空间中删除或修改 pod 的任何实例。

这个问题确实很有趣，因为它突显了 Kubernetes 提供的安全功能如果配置错误也可能会带来危害。接下来，我们将讨论 `kube-hunter`，这是一个开源工具，用于查找集群中已知的安全问题。

# 使用 kube-hunter 扫描已知的漏洞

Kubernetes 发布的安全公告和公告（[`kubernetes.io/docs/reference/issues-security/security/`](https://kubernetes.io/docs/reference/issues-security/security/)）是跟踪 Kubernetes 中发现的新安全漏洞的最佳方式。这些公告和咨询电子邮件可能会有点压倒性，很可能会错过重要的漏洞。为了避免这些情况，定期检查集群中是否存在已知 CVE 的工具就派上用场了。`kube-hunter`是一个由 Aqua 开发和维护的开源工具，可帮助识别您的 Kubernetes 集群中已知的安全问题。

设置`kube-hunter`的步骤如下：

1.  克隆存储库：

```
$git clone https://github.com/aquasecurity/kube-hunter
```

1.  在您的集群中运行`kube-hunter` pod：

```
$ ./kubectl create -f job.yaml
```

1.  查看日志以查找集群中的任何问题：

```
$ ./kubectl get pods
NAME                READY   STATUS              RESTARTS   AGE
kube-hunter-7hsfc   0/1     ContainerCreating   0          12s
```

以下输出显示了 Kubernetes v1.13.0 中已知的漏洞列表：

![图 13.2 - kube-hunter 的结果](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_13_002.jpg)

图 13.2 - kube-hunter 的结果

这个截图突出显示了`kube-hunter`在 Kubernetes v1.13.0 集群中发现的一些问题。`kube-hunter`发现的问题应该被视为关键，并应立即解决。

# 摘要

在本章中，我们讨论了 CVE 的重要性。这些公开已知的标识对于集群管理员、安全研究人员和攻击者都很重要。我们讨论了由 MITRE 维护的 CVE 条目的重要方面。然后我们看了四个知名的 CVE，并讨论了每个 CVE 的问题和缓解策略。作为集群管理员，升级`kubectl`客户端和 Kubernetes 版本应该始终是您的首要任务。然而，添加缓解策略以检测和防止由未公开报告的类似问题引起的利用同样重要。最后，我们讨论了一个开源工具`kube-hunter`，它可以定期识别您的 Kubernetes 集群中的问题。这消除了集群管理员密切关注 Kubernetes 的安全公告和公告的额外负担。

现在，您应该能够理解公开披露的漏洞的重要性，以及这些公告如何帮助加强您的 Kubernetes 集群的整体安全姿态。阅读这些公告将帮助您识别集群中的任何问题，并有助于加固您的集群。

# 问题

1.  CVE 条目对集群管理员、安全研究人员和攻击者来说最重要的部分是什么？

1.  为什么客户端安全问题，如 CVE-2019-11246 对 Kubernetes 集群很重要？

1.  为什么 kube-apiserver 中的 DoS 问题被视为高严重性问题？

1.  比较 API 服务器中经过身份验证与未经身份验证的 DoS 问题。

1.  讨论`kube-hunter`的重要性。

# 更多参考资料

+   CVE 列表：[`cve.mitre.org/cve/search_cve_list.html`](https://cve.mitre.org/cve/search_cve_list.html)

+   使用 Falco 检测 CVE-2019-11246：[`sysdig.com/blog/how-to-detect-kubernetes-vulnerability-cve-2019-11246-using-falco/`](https://sysdig.com/blog/how-to-detect-kubernetes-vulnerability-cve-2019-11246-using-falco/)

+   使用 OPA 防止 CVE-2019-11246：[`blog.styra.com/blog/investigate-and-correct-cves-with-the-k8s-api`](https://blog.styra.com/blog/investigate-and-correct-cves-with-the-k8s-api)

+   CVE-2019-1002100 的 GitHub 问题：[`github.com/kubernetes/kubernetes/issues/74534`](https://github.com/kubernetes/kubernetes/issues/74534)

+   CVE-2019-11253 的 GitHub 问题：[`github.com/kubernetes/kubernetes/issues/83253`](https://github.com/kubernetes/kubernetes/issues/83253)

+   CVE-2019-11247 的 GitHub 问题：[`github.com/kubernetes/kubernetes/issues/80983`](https://github.com/kubernetes/kubernetes/issues/80983)

+   `kube-hunter`：[`github.com/aquasecurity/kube-hunter`](https://github.com/aquasecurity/kube-hunter)

+   CVE 2020-8555 的 GitHub 问题：[`github.com/kubernetes/kubernetes/issues/91542`](https://github.com/kubernetes/kubernetes/issues/91542)

+   CVE 2020-8555 的 GitHub 问题：[`github.com/kubernetes/kubernetes/issues/91507`](https://github.com/kubernetes/kubernetes/issues/91507)


# 第十四章：评估

# 第一章

1.  扩展、运营成本和更长的发布周期。

1.  主要组件运行在主节点上。这些组件负责管理工作节点。主要组件包括`kube-apiserver`、`etcd`、`kube-scheduler`、`kube-controller-manager`、`cloud-controller-manager`和`dns-server`。

1.  Kubernetes 部署帮助根据标签和选择器扩展/缩小 Pod。部署封装了副本集和 Pod。部署的 YAML 规范包括 Pod 的实例数量和`template`，它与 Pod 规范相同。

1.  OpenShift、K3S 和 Minikube。

1.  Kubernetes 环境具有高度可配置性，并由众多组件组成。可配置性和复杂性与不安全的默认设置是一个令人担忧的原因。此外，集群中主要组件的 compromis 是引起违规的最简单方式。

# 第二章

1.  Pod。

1.  网络命名空间和 IPC 命名空间。

1.  用于保存其他容器的网络命名空间的占位符。

1.  ClusterIP、NodePort、LoadBalancer 和 ExternalName。

1.  Ingress 支持第 7 层路由，并且不需要来自云提供商的额外负载均衡器，而 LoadBalancer 服务需要每个服务一个负载均衡器。

# 第三章

1.  威胁建模是一个迭代的过程，从设计阶段开始。

1.  最终用户、内部攻击者和特权攻击者。

1.  存储在`etcd`中的未加密数据。

1.  Kubernetes 环境的复杂性增加了在 Kubernetes 环境中使用威胁建模应用程序的难度。

1.  Kubernetes 引入了与应用程序的额外资产和交互。这增加了 Kubernetes 中应用程序的复杂性，增加了攻击面。

# 第四章

1.  `Role`对象包含由动词和资源组成的规则，指示命名空间中资源的操作特权。

1.  `RoleBinding`对象将命名空间中的`Role`对象与一组主体（例如`User`和`ServiceAccount`）链接起来。它用于将 Role 对象中定义的特权授予主体。

1.  `RoleBinding`表示主体拥有的特权在`RoleBinding`对象的命名空间中有效。`ClusterRoleBinding`表示主体拥有的特权在整个集群中有效。

1.  `hostPID`、`hostNetwork`和`hostIPC`。

1.  为具有出口规则的 Pod 创建网络策略。

# 第五章

1.  主要组件、工作组件和 Kubernetes 对象。

1.  Pod、service/Ingress、`api-server`、节点和命名空间。

1.  RBAC 和网络策略。

1.  Pod 中的进程可以访问主机 PID 命名空间，查看工作节点上运行的所有进程。

```
kind: NetworkPolicy
metadata:
  name: allow-good
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          from: <allowed_label>
```

# 第六章

1.  基于令牌的身份验证使静态令牌能够用于识别集群中请求的来源。静态令牌无法在不重新启动 API 服务器的情况下进行更新，因此不应使用。

1.  `NodeRestriction`准入控制器确保 kubelet 只能修改其正在运行的节点的节点和 Pod 对象。

1.  将`--encryption-provider-config`传递给 API 服务器，以确保在`etcd`中对数据进行加密。

1.  `dnsmasq`中的安全漏洞，SkyDNS 中的性能问题，以及使用单个容器而不是三个容器来提供相同功能的`kube-dns`。

1.  您可以在 EKS 集群上使用`kube-bench`如下：

**$ git clone :** https://github.com/aquasecurity/kube-bench** $ kubectl apply -f job-eks.yaml**

# 第七章

1.  在生产集群中不应使用静态令牌和基本身份验证。这些模块使用静态凭据，需要重新启动 API 服务器才能更新。

1.  集群管理员可以使用用户模拟特权来测试授予新用户的权限。使用`kubectl`，集群管理员可以使用`--as --as-group`标志以不同的用户身份运行请求。

1.  Kubernetes 中默认启用了 Node 和 RBAC。应该使用这些。如果集群使用远程 API 进行授权，则应改用 Webhook 模式。

1.  `EventRateLimit`准入控制器指定 API 服务器可以处理的请求的最大限制。另一方面，LimitRanger 确保 Kubernetes 对象遵守`LimitRange`对象指定的资源限制。

1.  拒绝使用`rego`策略创建具有`test.example`端点的 Ingress 如下：

```
package kubernetes.admission
import data.kubernetes.namespaces
operations = {"CREATE", "UPDATE"}
deny[msg] {
    input.request.kind.kind == "Ingress"
    operations[input.request.operation]
    host := input.request.object.spec.rules[_].host
    host == "test.example"
    msg := sprintf("invalid ingress host %q", [host])
}
```

# 第八章

1.  定义一个命令，要求 Docker 引擎定期检查容器的健康状态。

1.  `COPY`指令只能将文件从构建机器复制到镜像的文件系统，而`ADD`指令不仅可以从本地主机复制文件，还可以从远程 URL 检索文件到镜像的文件系统。使用`ADD`可能会引入从互联网添加恶意文件的风险。

1.  `CAP_NET_BIND_SERVICE`。

1.  将`runAsNonRoot`设置为`true`，kubelet 将阻止以 root 用户身份运行容器。

1.  创建具有特权的角色，使用`PodSecurityPolicy`对象，并创建`rolebinding`对象将角色分配给工作负载使用的服务账户。

# 第九章

1.  `Docker history <image name>`.

1.  7-8.9.

1.  `anchore-cli image add <image name>`.

1.  `anchore-cli image vuln <image name> all`.

1.  `anchore-cli evaluate check <image digets> --tag <image full tag>`.

1.  它有助于识别具有最新已知漏洞的图像。

# 第十章

1.  资源请求指定 Kubernetes 对象保证获得的资源，而限制指定 Kubernetes 对象可以使用的最大资源。

1.  限制内存为 500 mi 的资源配额如下：

```
apiVersion: v1
kind: ResourceQuota
metadata:
    name: pods-medium
spec:
    hard:
      memory: 500Mi
```

1.  LimitRanger 是一个实施 LimitRanges 的准入控制器。LimitRange 定义了 Kubernetes 资源的约束。限制范围可以应用于 Pod、容器或`persistantvolumeclaim`。命名空间资源配额类似于`LimitRange`，但对整个命名空间进行强制执行。

1.  服务账户令牌。

1.  Prometheus 和 Grafana。

# 第十一章

1.  秘密数据将记录在 Kubernetes 审计日志中。

1.  `--master-zones`.

1.  将更新的秘密同步到 Pod 的挂载卷。

1.  系统调用和 Kubernetes 审计事件。

1.  `proc.name`.

1.  检查运行中的容器，稍后可以在隔离环境中恢复。

1.  故障排除和安全调查。

# 第十二章

1.  仪表板在未启用身份验证的情况下使用。

1.  不要运行仪表板，或者为仪表板启用身份验证。

1.  不。这可能是加密挖矿攻击，但也可能是由其他原因引起的，比如应用程序错误。

1.  加密挖矿二进制文件使用 HTTP 或 HTTPS 协议连接到挖矿池服务器，而不是 stratum。

1.  Kubernetes 集群的配置、构建、部署和运行时。

# 第十三章

1.  集群管理员跟踪 CVE ID，以确保 Kubernetes 集群不容易受到已知的公开问题的影响。安全研究人员研究参考部分，以了解问题的技术细节，以开发 CVE 的缓解措施。最后，攻击者研究参考部分，以找到未修补的变体或使用类似技术来发现代码其他部分的问题。

1.  客户端问题经常导致数据外泄或客户端上的代码执行。构建机器或集群管理员的机器通常包含敏感数据，对这些机器的攻击可能会对组织产生重大经济影响。

1.  `api-server`上的 DoS 问题可能导致整个集群的可用性中断。

1.  未经身份验证的 DoS 问题比经过身份验证的 DoS 问题更严重。理想情况下，未经身份验证的用户不应该能够与`api-server`通信。如果未经身份验证的用户能够发送请求并导致`api-server`的 DoS 问题，那比经过身份验证的用户更糟糕。经过身份验证的 DoS 请求也非常严重，因为集群中的配置错误可能允许未经身份验证的用户提升权限并成为经过身份验证的用户。

1.  Kubernetes 的安全公告和通知是了解任何新公开已知漏洞的好方法。这些公告和通知相当嘈杂，管理员很容易忽略重要问题。定期运行`kube-hunter`有助于集群管理员识别管理员可能忽略的任何已知问题。
