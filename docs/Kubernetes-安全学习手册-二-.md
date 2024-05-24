# Kubernetes 安全学习手册（二）

> 原文：[`zh.annas-archive.org/md5/389AEFE03E8149C2BB9C34B66276B16C`](https://zh.annas-archive.org/md5/389AEFE03E8149C2BB9C34B66276B16C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：身份验证、授权和准入控制

身份验证和授权在保护应用程序中起着非常重要的作用。这两个术语经常被交替使用，但它们是非常不同的。身份验证验证用户的身份。一旦身份得到验证，授权就用来检查用户是否有执行所需操作的特权。身份验证使用用户知道的东西来验证他们的身份；在最简单的形式中，这是用户名和密码。一旦应用程序验证了用户的身份，它会检查用户可以访问哪些资源。在大多数情况下，这是访问控制列表的一个变体。用户的访问控制列表与请求属性进行比较，以允许或拒绝操作。

在本章中，我们将讨论请求在被`kube-apiserver`处理之前如何经过身份验证、授权模块和准入控制器的处理。我们将详细介绍不同模块和准入控制器的细节，并强调推荐的安全配置。

最后，我们将介绍**Open Policy Agent**（**OPA**），这是一个开源工具，可用于在微服务中实现授权。在 Kubernetes 中，我们将看看它如何作为一个验证准入控制器。许多集群需要比 Kubernetes 已提供的更细粒度的授权。使用 OPA，开发人员可以定义可以在运行时更新的自定义授权策略。有几个利用 OPA 的开源工具，比如 Istio。

在本章中，我们将讨论以下主题：

+   在 Kubernetes 中请求工作流

+   Kubernetes 身份验证

+   Kubernetes 授权

+   准入控制器

+   介绍 OPA

# 在 Kubernetes 中请求工作流

在 Kubernetes 中，`kube-apiserver`处理所有修改集群状态的请求。`kube-apiserver`首先验证请求的来源。它可以使用一个或多个身份验证模块，包括客户端证书、密码或令牌。请求依次从一个模块传递到另一个模块。如果请求没有被所有模块拒绝，它将被标记为匿名请求。API 服务器可以配置为允许匿名请求。

一旦请求的来源得到验证，它将通过授权模块，检查请求的来源是否被允许执行操作。授权模块允许请求，如果策略允许用户执行操作。Kubernetes 支持多个授权模块，如基于属性的访问控制（ABAC）、基于角色的访问控制（RBAC）和 webhooks。与认证模块类似，集群可以使用多个授权：

![图 7.1 - 在 kube-apiserver 处理之前进行请求解析](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_07_001.jpg)

图 7.1 - 在 kube-apiserver 处理之前进行请求解析

经过授权和认证模块后，准入控制器修改或拒绝请求。准入控制器拦截创建、更新或删除对象的请求。准入控制器分为两类：变异或验证。变异准入控制器首先运行；它们修改它们承认的请求。接下来运行验证准入控制器。这些控制器不能修改对象。如果任何准入控制器拒绝请求，将向用户返回错误，并且请求将不会被 API 服务器处理。

# Kubernetes 认证

Kubernetes 中的所有请求都来自外部用户、服务账户或 Kubernetes 组件。如果请求的来源未知，则被视为匿名请求。根据组件的配置，认证模块可以允许或拒绝匿名请求。在 v1.6+中，匿名访问被允许以支持匿名和未经认证的用户，用于 RBAC 和 ABAC 授权模式。可以通过向 API 服务器配置传递`--anonymous-auth=false`标志来明确禁用匿名访问：

```
$ps aux | grep api
root      3701  6.1  8.7 497408 346244 ?       Ssl  21:06   0:16 kube-apiserver --advertise-address=192.168.99.111 --allow-privileged=true --anonymous-auth=false
```

Kubernetes 使用一个或多个这些认证策略。让我们逐一讨论它们。

## 客户端证书

在 Kubernetes 中，使用 X509 证书颁发机构（CA）证书是最常见的认证策略。可以通过向服务器传递`--client-ca-file=file_path`来启用它。传递给 API 服务器的文件包含 CA 的列表，用于在集群中创建和验证客户端证书。证书中的“通用名称”属性通常用作请求的用户名，“组织”属性用于标识用户的组：

```
kube-apiserver --advertise-address=192.168.99.104 --allow-privileged=true --authorization-mode=Node,RBAC --client-ca-file=/var/lib/minikube/certs/ca.crt
```

要创建新证书，需要执行以下步骤：

1.  生成私钥。可以使用`openssl`、`easyrsa`或`cfssl`生成私钥：

```
openssl genrsa -out priv.key 4096
```

1.  生成**证书签名请求**（**CSR**）。使用私钥和类似以下的配置文件生成 CSR。此 CSR 是为`test`用户生成的，该用户将成为`dev`组的一部分：

```
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
[ dn ]
CN = test
O = dev
[ v3_ext ]
authorityKeyIdentifier=keyid,issuer:always basicConstraints=CA:FALSE
keyUsage=keyEncipherment,dataEncipherment extendedKeyUsage=serverAuth,clientAuth
```

您可以使用`openssl`生成 CSR：

```
openssl req -config ./csr.cnf -new -key priv.key -nodes -out new.csr
```

1.  签署 CSR。使用以下 YAML 文件创建一个 Kubernetes`CertificateSigningRequest`请求：

```
apiVersion: certificates.k8s.io/v1beta1
kind: CertificateSigningRequest
metadata:
 name: mycsr
spec:
 groups:
 - system:authenticated
 request: ${BASE64_CSR}
 usages:
 - digital signature
 - key encipherment
 - server auth
 - client auth
```

之前生成的证书签名请求与前面的 YAML 规范一起使用，生成一个新的 Kubernetes 证书签名请求：

```
$ export BASE64_CSR=$(cat ./new.csr | base64 | tr -d '\n')
$ cat csr.yaml | envsubst | kubectl apply -f -
```

创建此请求后，需要由集群管理员批准以生成证书：

```
kubectl certificate approve mycsr
```

1.  导出 CRT。可以使用`kubectl`导出证书：

```
kubectl get csr mycsr -o jsonpath='{.status.certificate}' \
 | base64 --decode > new.crt
```

接下来，我们将看一下静态令牌，这是开发和调试环境中常用的身份验证模式，但不应在生产集群中使用。

## 静态令牌

API 服务器使用静态文件来读取令牌。将此静态文件传递给 API 服务器使用`--token-auth-file=<path>`。令牌文件是一个逗号分隔的文件，包括`secret`、`user`、`uid`、`group1`和`group2`。

令牌作为 HTTP 标头传递在请求中：

```
Authorization: Bearer 66e6a781-09cb-4e7e-8e13-34d78cb0dab6
```

令牌会持久存在，API 服务器需要重新启动以更新令牌。这*不*是一种推荐的身份验证策略。如果攻击者能够在集群中生成恶意 Pod，这些令牌很容易被破坏。一旦被破坏，生成新令牌的唯一方法是重新启动 API 服务器。

接下来，我们将看一下基本身份验证，这是静态令牌的一种变体，多年来一直作为 Web 服务的身份验证方法。

## 基本身份验证

与静态令牌类似，Kubernetes 还支持基本身份验证。可以通过使用`basic-auth-file=<path>`来启用。认证凭据存储在 CSV 文件中，包括`password`、`user`、`uid`、`group1`和`group2`。

用户名和密码作为认证标头传递在请求中：

```
Authentication: Basic base64(user:password)
```

与静态令牌类似，基本身份验证密码无法在不重新启动 API 服务器的情况下更改。不应在生产集群中使用基本身份验证。

## 引导令牌

引导令牌是静态令牌的一种改进。引导令牌是 Kubernetes 中默认使用的身份验证方法。它们是动态管理的，并存储为`kube-system`中的秘密。要启用引导令牌，请执行以下操作：

1.  在 API 服务器中使用`--enable-bootstrap-token-auth`来启用引导令牌验证器：

```
$ps aux | grep api
root      3701  3.8  8.8 497920 347140 ?       Ssl  21:06   4:58 kube-apiserver --advertise-address=192.168.99.111 --allow-privileged=true --anonymous-auth=true --authorization-mode=Node,RBAC --client-ca-file=/var/lib/minikube/certs/ca.crt --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,NodeRestriction,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota --enable-bootstrap-token-auth=true
```

1.  使用`controller`标志在控制器管理器中启用`tokencleaner`：

```
$ ps aux | grep controller
root      3693  1.4  2.3 211196 94396 ?        Ssl  21:06   1:55 kube-controller-manager --authentication-kubeconfig=/etc/kubernetes/controller-manager.conf --authorization-kubeconfig=/etc/kubernetes/controller-manager.conf --bind-address=127.0.0.1 --client-ca-file=/var/lib/minikube/certs/ca.crt --cluster-name=mk --cluster-signing-cert-file=/var/lib/minikube/certs/ca.crt --cluster-signing-key-file=/var/lib/minikube/certs/ca.key --controllers=*,bootstrapsigner,tokencleaner
```

1.  与令牌身份验证类似，引导令牌作为请求中的 HTTP 头传递：

```
Authorization: Bearer 123456.aa1234fdeffeeedf
```

令牌的第一部分是`TokenId`值，第二部分是`TokenSecret`值。`TokenController`确保从系统秘密中删除过期的令牌。

## 服务账户令牌

服务账户验证器会自动启用。它验证签名的持有者令牌。签名密钥是使用`--service-account-key-file`指定的。如果未指定此值，则将使用 Kube API 服务器的私钥：

```
$ps aux | grep api
root      3711 27.1 14.9 426728 296552 ?       Ssl  04:22   0:04 kube-apiserver --advertise-address=192.168.99.104 ... --secure-port=8443 --service-account-key-file=/var/lib/minikube/certs/sa.pub --service-cluster-ip-range=10.96.0.0/12 --tls-cert-file=/var/lib/minikube/certs/apiserver.crt --tls-private-key-file=/var/lib/minikube/certs/apiserver.key
docker    4496  0.0  0.0  11408   544 pts/0    S+   04:22   0:00 grep api
```

服务账户由`kube-apiserver`创建，并与 pod 关联。这类似于 AWS 中的实例配置文件。如果未指定服务账户，则默认服务账户将与 pod 关联。

要创建一个名为 test 的服务账户，您可以使用以下命令：

```
kubectl create serviceaccount test 
```

服务账户有关联的秘密，其中包括 API 服务器的 CA 和签名令牌：

```
$ kubectl get serviceaccounts test -o yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  creationTimestamp: "2020-03-29T04:35:58Z"
  name: test
  namespace: default
  resourceVersion: "954754"
  selfLink: /api/v1/namespaces/default/serviceaccounts/test
  uid: 026466f3-e2e8-4b26-994d-ee473b2f36cd
secrets:
- name: test-token-sdq2d
```

如果我们列举细节，我们可以看到证书和令牌：

```
$ kubectl get secret test-token-sdq2d -o yaml
apiVersion: v1
data:
  ca.crt: base64(crt)
  namespace: ZGVmYXVsdA==
  token: base64(token)
kind: Secret
```

接下来，我们将讨论 webhook 令牌。一些企业拥有远程身份验证和授权服务器，通常在所有服务中使用。在 Kubernetes 中，开发人员可以使用 webhook 令牌来利用远程服务进行身份验证。

## Webhook 令牌

在 webhook 模式下，Kubernetes 会调用集群外的 REST API 来确定用户的身份。可以通过向 API 服务器传递`--authorization-webhook-config-file=<path>`来启用身份验证的 webhook 模式。

以下是 webhook 配置的示例。在此示例中，[authn.example.com/authenticate](http://authn.example.com/authenticate)用作 Kubernetes 集群的身份验证端点：

```
clusters:
  - name: name-of-remote-authn-service
    cluster:
      certificate-authority: /path/to/ca.pem
      server: https://authn.example.com/authenticate
```

让我们看看另一种远程服务可以用于身份验证的方式。

## 身份验证代理

`kube-apiserver`可以配置为使用`X-Remote`请求头标识用户。您可以通过向 API 服务器添加以下参数来启用此方法：

```
--requestheader-username-headers=X-Remote-User
--requestheader-group-headers=X-Remote-Group
--requestheader-extra-headers-prefix=X-Remote-Extra-
```

每个请求都有以下标头来识别它们：

```
GET / HTTP/1.1
X-Remote-User: foo
X-Remote-Group: bar
X-Remote-Extra-Scopes: profile
```

API 代理使用 CA 验证请求。

## 用户冒充

集群管理员和开发人员可以使用用户冒充来调试新用户的身份验证和授权策略。要使用用户冒充，用户必须被授予冒充特权。API 服务器使用以下标头来冒充用户：

+   `冒充-用户`

+   `冒充-组`

+   `冒充-额外-*`

一旦 API 服务器接收到冒充标头，API 服务器会验证用户是否经过身份验证并具有冒充特权。如果是，则请求将以冒充用户的身份执行。`kubectl`可以使用`--as`和`--as-group`标志来冒充用户：

```
kubectl apply -f pod.yaml --as=dev-user --as-group=system:dev
```

一旦身份验证模块验证了用户的身份，它们会解析请求以检查用户是否被允许访问或修改请求。

# Kubernetes 授权

授权确定请求是否允许或拒绝。一旦确定请求的来源，活动授权模块会评估请求的属性与用户的授权策略，以允许或拒绝请求。每个请求依次通过授权模块，如果任何模块提供允许或拒绝的决定，它将自动被接受或拒绝。

## 请求属性

授权模块解析请求中的一组属性，以确定请求是否应该被解析、允许或拒绝：

+   **用户**：请求的发起者。这在身份验证期间进行验证。

+   **组**：用户所属的组。这是在身份验证层中提供的。

+   **API**：请求的目的地。

+   **请求动词**：请求的类型，可以是`GET`、`CREATE`、`PATCH`、`DELETE`等。

+   **资源**：正在访问的资源的 ID 或名称。

+   **命名空间**：正在访问的资源的命名空间。

+   **请求路径**：如果请求是针对非资源端点的，则使用路径来检查用户是否被允许访问端点。这对于`api`和`healthz`端点是正确的。

现在，让我们看看使用这些请求属性来确定请求发起者是否被允许发起请求的不同授权模式。

## 授权模式

现在，让我们看看 Kubernetes 中可用的不同授权模式。

## 节点

节点授权模式授予 kubelet 访问节点的服务、端点、节点、Pod、秘密和持久卷的权限。kubelet 被识别为`system:nodes`组的一部分，用户名为`system:node:<name>`，由节点授权者授权。这种模式在 Kubernetes 中默认启用。

`NodeRestriction`准入控制器与节点授权者一起使用，我们将在本章后面学习，以确保 kubelet 只能修改其正在运行的节点上的对象。API 服务器使用`--authorization-mode=Node`标志来使用节点授权模块：

```
$ps aux | grep api
root      3701  6.1  8.7 497408 346244 ?       Ssl  21:06   0:16 kube-apiserver --advertise-address=192.168.99.111 --allow-privileged=true --anonymous-auth=true --authorization-mode=Node,RBAC --client-ca-file=/var/lib/minikube/certs/ca.crt --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,NodeRestriction,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota
```

节点授权与 ABAC 或 RBAC 一起使用，接下来我们将看一下。

## ABAC

使用 ABAC，通过验证请求的属性来允许请求。可以通过在 API 服务器中使用`--authorization-policy-file=<path>`和`--authorization-mode=ABAC`来启用 ABAC 授权模式。

策略包括每行一个 JSON 对象。每个策略包括以下内容：

+   **版本**：策略格式的 API 版本。

+   **种类**：`Policy`字符串用于策略。

+   **规范**：包括用户、组和资源属性，如`apiGroup`、`namespace`和`nonResourcePath`（如`/version`、`/apis`、`readonly`），以允许不修改资源的请求。

一个示例策略如下：

```
{"apiVersion": "abac.authorization.kubernetes.io/v1beta1", "kind": "Policy", "spec": {"user": "kubelet", "namespace": "*", "resource": "pods", "readonly": true}} 
```

此策略允许 kubelet 读取任何 Pod。ABAC 难以配置和维护。不建议在生产环境中使用 ABAC。

## RBAC

使用 RBAC，通过分配给用户的角色来规范对资源的访问。自 v1.8 以来，RBAC 在许多集群中默认启用。要启用 RBAC，请使用`--authorization-mode=RBAC`启动 API 服务器：

```
$ ps aux | grep api
root     14632  9.2 17.0 495148 338780 ?       Ssl  06:11   0:09 kube-apiserver --advertise-address=192.168.99.104 --allow-privileged=true --authorization-mode=Node,RBAC ...
```

RBAC 使用 Role，这是一组权限，以及 RoleBinding，它向用户授予权限。Role 和 RoleBinding 受到命名空间的限制。如果角色需要跨命名空间，则可以使用 ClusterRole 和 ClusterRoleBinding 来向用户授予权限。

以下是允许用户在默认命名空间中创建和修改 Pod 的`Role`属性示例：

```
kind: Role
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  namespace: default
  name: deployment-manager
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
```

相应的`RoleBinding`可以与`Role`一起使用，向用户授予权限：

```
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: binding
  namespace: default
subjects:
- kind: User
  name: employee
  apiGroup: ""
roleRef:
  kind: Role
  name: deployment-manager
  apiGroup: ""
```

一旦应用了`RoleBinding`，您可以切换上下文查看是否工作正常：

```
$ kubectl --context=employee-context get pods
NAME                          READY   STATUS    RESTARTS   AGE
hello-node-677b9cfc6b-xks5f   1/1     Running   0          12m
```

但是，如果尝试查看部署，将导致错误：

```
$ kubectl --context=employee-context get deployments
Error from server (Forbidden): deployments.apps is forbidden: User "employee" cannot list resource "deployments" in API group "apps" in the namespace "default"
```

由于角色和角色绑定受限于默认命名空间，访问不同命名空间中的 Pod 将导致错误：

```
$ kubectl --context=employee-context get pods -n test
Error from server (Forbidden): pods is forbidden: User "test" cannot list resource "pods" in API group "" in the namespace "test"
$ kubectl --context=employee-context get pods -n kube-system
Error from server (Forbidden): pods is forbidden: User "test" cannot list resource "pods" in API group "" in the namespace "kube-system"
```

接下来，我们将讨论 webhooks，它为企业提供了使用远程服务器进行授权的能力。

## Webhooks

类似于用于身份验证的 webhook 模式，用于授权的 webhook 模式使用远程 API 服务器来检查用户权限。可以通过使用`--authorization-webhook-config-file=<path>`来启用 webhook 模式。

让我们看一个示例 webhook 配置文件，将[`authz.remote`](https://authz.remote)设置为 Kubernetes 集群的远程授权端点：

```
clusters:
  - name: authz_service
    cluster:
      certificate-authority: ca.pem
      server: https://authz.remote/
```

一旦请求通过了认证和授权模块，准入控制器就会处理请求。让我们详细讨论准入控制器。

# 准入控制器

准入控制器是在请求经过认证和授权后拦截 API 服务器的模块。控制器在修改集群中对象的状态之前验证和改变请求。控制器可以是改变和验证的。如果任何控制器拒绝请求，请求将立即被丢弃，并向用户返回错误，以便请求不会被处理。

可以通过使用`--enable-admission-plugins`标志来启用准入控制器：

```
$ps aux | grep api
root      3460 17.0  8.6 496896 339432 ?       Ssl  06:53   0:09 kube-apiserver --advertise-address=192.168.99.106 --allow-privileged=true --authorization-mode=Node,RBAC --client-ca-file=/var/lib/minikube/certs/ca.crt --enable-admission-plugins=PodSecurityPolicy,NamespaceLifecycle,LimitRanger --enable-bootstrap-token-auth=true
```

可以使用`--disable-admission-plugins`标志来禁用默认的准入控制器。

在接下来的章节中，我们将看一些重要的准入控制器。

### AlwaysAdmit

此准入控制器允许所有的 Pod 存在于集群中。自 1.13 版本以来，该控制器已被弃用，不应在任何集群中使用。使用此控制器，集群的行为就好像集群中不存在任何控制器一样。

## AlwaysPullImages

该控制器确保新的 Pod 始终强制拉取镜像。这有助于确保 Pod 使用更新的镜像。它还确保只有有权限访问的用户才能使用私有镜像，因为没有访问权限的用户在启动新的 Pod 时无法拉取镜像。应该在您的集群中启用此控制器。

## 事件速率限制

拒绝服务攻击在基础设施中很常见。行为不端的对象也可能导致资源的高消耗，如 CPU 或网络，从而导致成本增加或可用性降低。`EventRateLimit`用于防止这些情况发生。

限制是使用配置文件指定的，可以通过向 API 服务器添加 `--admission-control-config-file` 标志来指定。

集群可以有四种类型的限制：`Namespace`、`Server`、`User` 和 `SourceAndObject`。对于每个限制，用户可以拥有 **每秒查询** (**QPS**)、突发和缓存大小的最大限制。

让我们看一个配置文件的例子：

```
limits:
- type: Namespace
  qps: 50
  burst: 100
  cacheSize: 200
- type: Server
  qps: 10
  burst: 50
  cacheSize: 200
```

这将为所有 API 服务器和命名空间添加 `qps`、`burst` 和 `cacheSize` 限制。

接下来，我们将讨论 LimitRanger，它可以防止集群中可用资源的过度利用。

## LimitRanger

这个准入控制器观察传入的请求，并确保它不违反 `LimitRange` 对象中指定的任何限制。

一个 `LimitRange` 对象的例子如下：

```
apiVersion: "v1"
kind: "LimitRange"
metadata:
  name: "pod-example" 
spec:
  limits:
    - type: "Pod"
      max:
        memory: "128Mi"
```

有了这个限制范围对象，任何请求内存超过 128 Mi 的 pod 都将失败：

```
pods "range-demo" is forbidden maximum memory usage per Pod is 128Mi, but limit is 1073741824
```

在使用 LimitRanger 时，恶意的 pod 无法消耗过多的资源。

## NodeRestriction

这个准入控制器限制了 kubelet 可以修改的 pod 和节点。有了这个准入控制器，kubelet 以 `system:node:<name>` 格式获得一个用户名，并且只能修改自己节点上运行的节点对象和 pod。

## PersistentVolumeClaimResize

这个准入控制器为 `PersistentVolumeClaimResize` 请求添加了验证。

## PodSecurityPolicy

这个准入控制器在创建或修改 pod 时运行，以确定是否应该基于 pod 的安全敏感配置来运行 pod。策略中的一组条件将与工作负载配置进行检查，以验证是否应该允许工作负载创建请求。PodSecurityPolicy 可以检查诸如 `privileged`、`allowHostPaths`、`defaultAddCapabilities` 等字段。您将在下一章中了解更多关于 PodSecurityPolicy 的内容。

## SecurityContextDeny

如果未启用 PodSecurityPolicy，则建议使用此准入控制器。它限制了安全敏感字段的设置，这可能会导致特权升级，例如运行特权 pod 或向容器添加 Linux 功能：

```
$ ps aux | grep api
root      3763  6.7  8.7 497344 345404 ?       Ssl  23:28   0:14 kube-apiserver --advertise-address=192.168.99.112 --allow-privileged=true --authorization-mode=Node,RBAC --client-ca-file=/var/lib/minikube/certs/ca.crt --enable-admission-plugins=SecurityContextDeny
```

建议默认情况下在集群中启用 PodSecurityPolicy。但是，由于管理开销，可以在为集群配置 PodSecurityPolicy 之前使用 `SecurityContextDeny`。

## ServiceAccount

`ServiceAccount`是 pod 的身份。这个准入控制器实现了`ServiceAccount`；如果集群使用服务账户，应该使用它。

## MutatingAdmissionWebhook 和 ValidatingAdmissionWebhook

类似于用于身份验证和授权的 webhook 配置，webhook 可以用作准入控制器。MutatingAdmissionWebhook 修改工作负载的规范。这些钩子按顺序执行。ValidatingAdmissionWebhook 解析传入的请求以验证其是否正确。验证钩子同时执行。

现在，我们已经了解了 Kubernetes 中资源的身份验证、授权和准入控制。让我们看看开发人员如何在他们的集群中实现细粒度的访问控制。在下一节中，我们将讨论 OPA，这是一个在生产集群中广泛使用的开源工具。

# OPA 简介

**OPA**是一个开源的策略引擎，允许在 Kubernetes 中执行策略。许多开源项目，如 Istio，利用 OPA 提供更精细的控制。OPA 是由**Cloud Native Computing Foundation** (**CNCF**)托管的孵化项目。

OPA 部署为与其他服务一起的服务。为了做出授权决策，微服务调用 OPA 来决定请求是否应该被允许或拒绝。授权决策被卸载到 OPA，但这种执行需要由服务本身实现。在 Kubernetes 环境中，它经常被用作验证 webhook：

![图 7.2 - 开放策略代理](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_07_002.jpg)

图 7.2 - 开放策略代理

为了做出策略决策，OPA 需要以下内容：

+   **集群信息**：集群的状态。集群中可用的对象和资源对于 OPA 来说是重要的，以便决定是否应该允许请求。

+   **输入查询**：策略代理分析请求的参数，以允许或拒绝请求。

+   **策略**：策略定义了解析集群信息和输入查询以返回决策的逻辑。OPA 的策略是用一种称为 Rego 的自定义语言定义的。

让我们看一个例子，说明如何利用 OPA 来拒绝创建带有`busybox`镜像的 pod。您可以使用官方的 OPA 文档([`www.openpolicyagent.org/docs/latest/kubernetes-tutorial/`](https://www.openpolicyagent.org/docs/latest/kubernetes-tutorial/))在您的集群上安装 OPA。

以下是限制使用`busybox`镜像创建和更新 pod 的策略：

```
$ cat pod-blacklist.rego
package kubernetes.admission
import data.kubernetes.namespaces
operations = {"CREATE", "UPDATE"}
deny[msg] {
	input.request.kind.kind == "Pod"
	operations[input.request.operation]
	image := input.request.object.spec.containers[_].image
	image == "busybox"
	msg := sprintf("image not allowed %q", [image])
}
```

要应用此策略，您可以使用以下内容：

```
kubectl create configmap pod —from-file=pod-blacklist.rego
```

一旦创建了`configmap`，`kube-mgmt`会从`configmap`中加载这些策略，在`opa`容器中，`kube-mgmt`和`opa`容器都在`opa` pod 中。现在，如果您尝试使用`busybox`镜像创建一个 pod，您将得到以下结果：

```
$ cat busybox.yaml
apiVersion: v1
kind: Pod
metadata:
  name: busybox
spec:
  containers:
  - name: sec-ctx-demo
    image: busybox
    command: [ "sh", "-c", "sleep 1h" ]
```

该策略检查对`busybox`镜像名称的请求，并拒绝使用`busybox`镜像创建带有`image not allowed`错误的 pod：

```
admission webhook "validating-webhook.openpolicyagent.org" denied the request: image not allowed "busybox"
```

类似于我们之前讨论过的准入控制器，可以使用 OPA 在 Kubernetes 集群中创建进一步细粒度的准入控制器。

# 总结

在本章中，我们讨论了在 Kubernetes 中进行身份验证和授权的重要性。我们讨论了可用于身份验证和授权的不同模块，并详细讨论了这些模块，以及详细介绍了每个模块的使用示例。在讨论身份验证时，我们讨论了用户模拟，这可以由集群管理员或开发人员用来测试权限。接下来，我们谈到了准入控制器，它可以用于在身份验证和授权之后验证或改变请求。我们还详细讨论了一些准入控制器。最后，我们看了一下 OPA，它可以在 Kubernetes 集群中执行更细粒度的授权。

现在，您应该能够为您的集群制定适当的身份验证和授权策略。您应该能够确定哪些准入控制器适用于您的环境。在许多情况下，您将需要更细粒度的授权控制，这可以通过使用 OPA 来实现。

在下一章中，我们将深入探讨保护 pod。本章将更详细地涵盖我们在本章中涵盖的一些主题，如 PodSecurityPolicy。保护 pod 对于保护 Kubernetes 中的应用部署至关重要。

# 问题

1.  哪些授权模块不应该在集群中使用？

1.  集群管理员如何测试对新用户授予的权限？

1.  哪些授权模式适合生产集群？

1.  `EventRateLimit`和`LimitRange`准入控制器之间有什么区别？

1.  您能否编写一个 Rego 策略来拒绝创建带有`test.example`端点的 ingress？

# 进一步阅读

您可以参考以下链接获取更多信息：

+   准入控制器: [`kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#what-does-each-admission-controller-do`](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#what-does-each-admission-controller-do)

+   OPA: [`www.openpolicyagent.org/docs/latest/`](https://www.openpolicyagent.org/docs/latest/)

+   Kubernetes RBAC: [`rbac.dev/`](https://rbac.dev/)

+   audit2RBAC: [`github.com/liggitt/audit2rbac`](https://github.com/liggitt/audit2rbac)

+   KubiScan: [`github.com/cyberark/KubiScan`](https://github.com/cyberark/KubiScan)


# 第八章：保护 Kubernetes Pods

尽管 pod 是作为运行微服务的最细粒度单位，保护 Kubernetes pods 是一个广泛的主题，因为它应该涵盖整个 DevOps 流程：构建、部署和运行。

在本章中，我们选择将焦点缩小到构建和运行阶段。为了在构建阶段保护 Kubernetes pods，我们将讨论如何加固容器镜像并配置 pod（或 pod 模板）的安全属性，以减少攻击面。虽然一些工作负载的安全属性，如 AppArmor 和 SELinux 标签，会在运行阶段生效，但安全控制已经为工作负载定义好了。为了进一步澄清问题，我们试图通过在构建阶段配置运行效果的安全属性来保护 Kubernetes 工作负载。为了在运行阶段保护 Kubernetes pods，我们将介绍一个带有示例的 PodSecurityPolicy 以及辅助工具`kube-psp-advisor`。

后续章节将更详细地讨论运行时安全和响应。还要注意，应用程序的利用可能导致 pod 被 compromise。但是，我们不打算在本章中涵盖应用程序。

在本章中，我们将涵盖以下主题：

+   容器镜像的加固

+   配置 pod 的安全属性

+   PodSecurityPolicy 的威力

# 容器镜像的加固

容器镜像的加固意味着遵循安全最佳实践或基线，以配置容器镜像，以减少攻击面。镜像扫描工具只关注在镜像内捆绑的应用程序中找到的公开披露的问题。但是，在构建镜像时遵循最佳实践以及安全配置，可以确保应用程序具有最小的攻击面。

在我们开始讨论安全配置基线之前，让我们看看容器镜像是什么，以及 Dockerfile 是什么，以及它是如何用来构建镜像的。

## 容器镜像和 Dockerfile

一个**容器镜像**是一个文件，它捆绑了微服务二进制文件、它的依赖项和微服务的配置等。一个容器是镜像的运行实例。如今，应用程序开发人员不仅编写代码来构建微服务；他们还需要构建 Dockerfile 来将微服务容器化。为了帮助构建容器镜像，Docker 提供了一种标准化的方法，称为 Dockerfile。一个**Dockerfile**包含一系列的指令，比如复制文件、配置环境变量、配置开放端口和容器入口点，这些指令可以被 Docker 守护进程理解以构建镜像文件。然后，镜像文件将被推送到镜像注册表，然后从那里部署到 Kubernetes 集群中。每个 Dockerfile 指令都会在镜像中创建一个文件层。

在我们看一个 Dockerfile 的例子之前，让我们先了解一些基本的 Dockerfile 指令：

+   **FROM**：从基础镜像或父镜像初始化一个新的构建阶段。两者都意味着你正在捆绑自己的镜像的基础或文件层。

+   **RUN**：执行命令并将结果提交到上一个文件层之上。

+   **ENV**：为运行的容器设置环境变量。

+   **CMD**：指定容器将运行的默认命令。

+   **COPY/ADD**：这两个命令都是将文件或目录从本地（或远程）URL 复制到镜像的文件系统中。

+   **EXPOSE**：指定微服务在容器运行时将监听的端口。

+   **ENTRYPOINT**：类似于`CMD`，唯一的区别是`ENTRYPOINT`会使容器作为可执行文件运行。

+   **WORKDIR**：为接下来的指令设置工作目录。

+   **USER**：为容器的`CMD`/`ENTRYPOINT`设置用户和组 ID。

现在，让我们来看一个 Dockerfile 的例子：

```
FROM ubuntu
# install dependencies
RUN apt-get install -y software-properties-common python
RUN add-apt-repository ppa:chris-lea/node.js
RUN echo "deb http://us.archive.ubuntu.com/ubuntu/ precise universe" >> /etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y nodejs
# make directory
RUN mkdir /var/www
# copy app.js
ADD app.js /var/www/app.js
# set the default command to run
CMD ["/usr/bin/node", "/var/www/app.js"]
```

从上面的 Dockerfile 中，我们可以看出这个镜像是基于`ubuntu`构建的。然后，它运行了一系列的`apt-get`命令来安装依赖，并创建了一个名为`/var/www`的目录。接下来，将`app.js`文件从当前目录复制到镜像文件系统中的`/var/www/app.js`。最后，配置默认命令来运行这个`Node.js`应用程序。我相信当你开始构建镜像时，你会看到 Dockerfile 是多么简单和强大。

下一个问题是安全问题，因为看起来您可以构建任何类型的图像。接下来，让我们谈谈 CIS Docker 基准。

## CIS Docker 基准

互联网安全中心（CIS）制定了有关 Docker 容器管理和管理的指南。现在，让我们来看看 CIS Docker 基准关于容器图像的安全建议：

+   为容器图像创建一个用户来运行微服务：以非 root 用户运行容器是一个好的做法。虽然用户命名空间映射是可用的，但默认情况下未启用。以 root 身份运行意味着如果攻击者成功逃离容器，他们将获得对主机的 root 访问权限。在 Dockerfile 中使用`USER`指令创建一个用户。

+   使用受信任的基础图像构建您自己的图像：从公共存储库下载的图像不能完全信任。众所周知，来自公共存储库的图像可能包含恶意软件或加密货币挖矿程序。因此，建议您从头开始构建图像或使用最小的受信任图像，如 Alpine。此外，在构建图像后执行图像扫描。图像扫描将在下一章节中介绍。

+   不要在图像中安装不必要的软件包：安装不必要的软件包会增加攻击面。建议保持图像的精简。在构建图像的过程中，您可能需要安装一些工具。请记住在 Dockerfile 的末尾将它们删除。

+   扫描并重建图像以应用安全补丁：很可能会在基础图像或图像中安装的软件包中发现新的漏洞。经常扫描图像是一个好的做法。一旦发现任何漏洞，尝试通过重建图像来修补安全漏洞。图像扫描是在构建阶段识别漏洞的关键机制。我们将在下一章节详细介绍图像扫描。

+   为 Docker 启用内容信任：内容信任使用数字签名确保客户端和 Docker 注册表之间的数据完整性。它确保容器图像的来源。但默认情况下未启用。您可以通过将环境变量`DOCKER_CONTENT_TRUST`设置为`1`来启用它。

+   **向容器图像添加 HEALTHCHECK 指令**：`HEALTHCHECK`指令定义了一个命令，要求 Docker 引擎定期检查容器的健康状态。根据健康状态检查结果，Docker 引擎然后退出不健康的容器并启动一个新的容器。

+   **确保 Dockerfile 中的更新不被缓存**：根据您选择的基础镜像，您可能需要在安装新软件包之前更新软件包存储库。但是，如果您在 Dockerfile 中的单行中指定`RUN apt-get update``(Debian)`，Docker 引擎将缓存此文件层，因此，当您再次构建图像时，它仍将使用缓存的旧软件包存储库信息。这将阻止您在图像中使用最新的软件包。因此，要么在单个 Dockerfile 指令中同时使用`update`和`install`，要么在 Docker`build`命令中使用`--no-cache`标志。

+   **从图像中删除 setuid 和 setgid 权限**：`setuid`和`setgid`权限可用于特权升级，因为具有这些权限的文件允许以所有者特权而不是启动器特权执行。您应该仔细审查具有`setuid`和`setgid`权限的文件，并删除不需要此类权限的文件。

+   **在 Dockerfile 中使用 COPY 而不是 ADD**：`COPY`指令只能将文件从本地计算机复制到图像的文件系统，而`ADD`指令不仅可以从本地计算机复制文件，还可以从远程 URL 检索文件到图像的文件系统。使用`ADD`可能会引入从互联网添加恶意文件的风险。

+   **不要在 Dockerfile 中存储机密信息**：有许多工具可以提取图像文件层。如果图像中存储了任何机密信息，那么这些机密信息就不再是机密信息。在 Dockerfile 中存储机密信息会使容器有潜在的可利用性。一个常见的错误是使用`ENV`指令将机密信息存储在环境变量中。

+   **仅安装经过验证的软件包**：这类似于仅使用受信任的基础镜像。在安装图像内的软件包时要小心，确保它们来自受信任的软件包存储库。

如果您遵循前述 CIS Docker 基准的安全建议，您将成功地加固容器镜像。这是在构建阶段保护 pod 的第一步。现在，让我们看看我们需要注意的安全属性，以确保 pod 的安全。

# 配置 pod 的安全属性

正如我们在前一章中提到的，应用程序开发人员应该知道微服务必须具有哪些特权才能执行任务。理想情况下，应用程序开发人员和安全工程师应该共同努力，通过配置 Kubernetes 提供的安全上下文来加固 pod 和容器级别的微服务。

我们将主要的安全属性分为四类：

+   为 pod 设置主机命名空间

+   容器级别的安全上下文

+   Pod 级别的安全上下文

+   AppArmor 配置文件

通过采用这种分类方式，您会发现它们易于管理。

## 为 pod 设置主机级别的命名空间

在 pod 规范中使用以下属性来配置主机命名空间的使用：

+   **hostPID**：默认情况下为`false`。将其设置为`true`允许 pod 在工作节点上看到所有进程。

+   **hostNetwork**：默认情况下为`false`。将其设置为`true`允许 pod 在工作节点上看到所有网络堆栈。

+   **hostIPC**：默认情况下为`false`。将其设置为`true`允许 pod 在工作节点上看到所有 IPC 资源。

以下是如何在`ubuntu-1` pod 的`YAML`文件中配置在 pod 级别使用主机命名空间的示例：

```
apiVersion: v1
kind: Pod
metadata:
  name: ubuntu-1
  labels:
    app: util
spec:
  containers:
  - name: ubuntu
    image: ubuntu
    imagePullPolicy: Always
  hostPID: true
  hostNetwork: true
  hostIPC: true
```

前面的工作负载 YAML 配置了`ubuntu-1` pod 以使用主机级 PID 命名空间、网络命名空间和 IPC 命名空间。请记住，除非必要，否则不应将这些属性设置为`true`。将这些属性设置为`true`还会解除同一工作节点上其他工作负载的安全边界，正如在*第五章*中已经提到的，*配置 Kubernetes 安全边界*。

## 容器的安全上下文

多个容器可以被分组放置在同一个 Pod 中。每个容器可以拥有自己的安全上下文，定义特权和访问控制。在容器级别设计安全上下文为 Kubernetes 工作负载提供了更精细的安全控制。例如，您可能有三个容器在同一个 Pod 中运行，其中一个必须以特权模式运行，而其他的以非特权模式运行。这可以通过为各个容器配置安全上下文来实现。

以下是容器安全上下文的主要属性：

+   **privileged**: 默认情况下为`false`。将其设置为`true`实质上使容器内的进程等同于工作节点上的 root 用户。

+   **能力**: 容器运行时默认授予容器的一组能力。默认授予的能力包括：`CAP_SETPCAP`、`CAP_MKNOD`、`CAP_AUDIT_WRITE`、`CAP_CHOWN`、`CAP_NET_RAW`、`CAP_DAC_OVERRIDE`、`CAP_FOWNER`、`CAP_FSETID`、`CAP_KILL`、`CAP_SETGID`、`CAP_SETUID`、`CAP_NET_BIND_SERVICE`、`CAP_SYS_CHROOT`和`CAP_SETFCAP`。

您可以通过配置此属性添加额外的能力或删除一些默认的能力。诸如`CAP_SYS_ADMIN`和`CAP_NETWORK_ADMIN`之类的能力应谨慎添加。对于默认的能力，您还应该删除那些不必要的能力。

+   **allowPrivilegeEscalation**: 默认情况下为`true`。直接设置此属性可以控制`no_new_privs`标志，该标志将设置为容器中的进程。基本上，此属性控制进程是否可以获得比其父进程更多的特权。请注意，如果容器以特权模式运行，或者添加了`CAP_SYS_ADMN`能力，此属性将自动设置为`true`。最好将其设置为`false`。

+   **readOnlyRootFilesystem**: 默认情况下为`false`。将其设置为`true`会使容器的根文件系统变为只读，这意味着库文件、配置文件等都是只读的，不能被篡改。将其设置为`true`是一个良好的安全实践。

+   runAsNonRoot：默认情况下为`false`。将其设置为`true`可以启用验证，以确保容器中的进程不能以 root 用户（UID=0）身份运行。验证由`kubelet`执行。将`runAsNonRoot`设置为`true`后，如果以 root 用户身份运行，`kubelet`将阻止容器启动。将其设置为`true`是一个良好的安全实践。这个属性也可以在`PodSecurityContext`中使用，在 Pod 级别生效。如果在`SecurityContext`和`PodSecurityContext`中都设置了这个属性，那么在容器级别指定的值优先。

+   runAsUser：这是用来指定容器镜像入口进程运行的 UID。默认设置是镜像元数据中指定的用户（例如，Dockerfile 中的`USER`指令）。这个属性也可以在`PodSecurityContext`中使用，在 Pod 级别生效。如果在`SecurityContext`和`PodSecurityContext`中都设置了这个属性，那么在容器级别指定的值优先。

+   runAsGroup：类似于`runAsUser`，这是用来指定容器入口进程运行的**Group ID**或**GID**。这个属性也可以在`PodSecurityContext`中使用，在 Pod 级别生效。如果在`SecurityContext`和`PodSecurityContext`中都设置了这个属性，那么在容器级别指定的值优先。

+   seLinuxOptions：这是用来指定容器的 SELinux 上下文的。默认情况下，如果未指定，容器运行时将为容器分配一个随机的 SELinux 上下文。这个属性也可以在`PodSecurityContex`中使用，在 Pod 级别生效。如果在`SecurityContext`和`PodSecurityContext`中都设置了这个属性，那么在容器级别指定的值优先。

既然你现在了解了这些安全属性是什么，你可以根据自己的业务需求提出自己的加固策略。一般来说，安全最佳实践如下：

+   除非必要，不要以特权模式运行。

+   除非必要，不要添加额外的能力。

+   丢弃未使用的默认能力。

+   以非 root 用户身份运行容器。

+   启用`runAsNonRoot`检查。

+   将容器根文件系统设置为只读。

现在，让我们看一个为容器配置`SecurityContext`的示例：

```
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
  labels:
    app: web
spec:
  hostNetwork: false
  hostIPC: false
  hostPID: false
  containers:
  - name: nginx
    image: kaizheh/nginx 
    securityContext:
      privileged: false
      capabilities:
        add:
        - NETWORK_ADMIN
      readOnlyRootFilesystem: true 
      runAsUser: 100
      runAsGroup: 1000
```

nginx-pod 内的`nginx`容器以 UID 为`100`和 GID 为`1000`的用户身份运行。除此之外，`nginx`容器还获得了额外的`NETWORK_ADMIN`权限，并且根文件系统被设置为只读。这里的 YAML 文件只是展示了如何配置安全上下文的示例。请注意，在生产环境中运行的容器中不建议添加`NETWORK_ADMIN`。

## Pod 的安全上下文

安全上下文是在 pod 级别使用的，这意味着安全属性将应用于 pod 内的所有容器。

以下是 pod 级别的主要安全属性列表：

+   **fsGroup**：这是一个应用于所有容器的特殊辅助组。这个属性的有效性取决于卷类型。基本上，它允许`kubelet`将挂载卷的所有权设置为具有辅助 GID 的 pod。

+   **sysctls**：`sysctls`用于在运行时配置内核参数。在这样的上下文中，`sysctls`和内核参数是可以互换使用的。这些`sysctls`命令是命名空间内的内核参数，适用于 pod。以下`sysctls`命令已知是命名空间内的：`kernel.shm*`、`kernel.msg*`、`kernel.sem`和`kernel.mqueue.*`。不安全的`sysctls`默认情况下是禁用的，不应在生产环境中启用。

+   **runAsUser**：这是用来指定容器镜像的入口进程运行的 UID 的。默认设置是镜像元数据中指定的用户（例如，Dockerfile 中的`USER`指令）。这个属性也可以在`SecurityContext`中使用，它在容器级别生效。如果在`SecurityContext`和`PodSecurityContext`中都设置了这个属性，那么在容器级别指定的值会优先生效。

+   **runAsGroup**：类似于`runAsUser`，这是用来指定容器的入口进程运行的 GID 的。这个属性也可以在`SecurityContext`中使用，它在容器级别生效。如果在`SecurityContext`和`PodSecurityContext`中都设置了这个属性，那么在容器级别指定的值会优先生效。

+   **runAsNonRoot**：默认情况下设置为`false`，将其设置为`true`可以启用验证，即容器中的进程不能以 root 用户（UID=0）身份运行。验证由`kubelet`执行。将其设置为`true`，`kubelet`将阻止以 root 用户身份运行的容器启动。将其设置为`true`是一个很好的安全实践。此属性也可在`SecurityContext`中使用，其在容器级别生效。如果在`SecurityContext`和`PodSecurityContext`中都设置了此属性，则以容器级别指定的值优先。

+   **seLinuxOptions**：这是用来指定容器的 SELinux 上下文的。如果未指定，默认情况下，容器运行时会为容器分配一个随机的 SELinux 上下文。此属性也可在`SecurityContext`中使用，其在容器级别生效。如果在`SecurityContext`和`PodSecurityContext`中都设置了此属性，则以容器级别指定的值优先。

请注意，`runAsUser`、`runAsGroup`、`runAsNonRoot`和`seLinuxOptions`属性在容器级别的`SecurityContext`和 pod 级别的`PodSecurityContext`中都可用。这为用户提供了灵活性和极其重要的安全控制。`fsGroup`和`sysctls`不像其他属性那样常用，所以只有在必要时才使用它们。

## AppArmor 配置文件

AppArmor 配置文件通常定义了进程拥有的 Linux 功能，容器可以访问的网络资源和文件等。为了使用 AppArmor 配置文件保护 pod 或容器，您需要更新 pod 的注释。让我们看一个例子，假设您有一个 AppArmor 配置文件来阻止任何文件写入活动。

```
#include <tunables/global>
profile k8s-apparmor-example-deny-write flags=(attach_disconnected) {
  #include <abstractions/base>
  file,
  # Deny all file writes.
  deny /** w,
}
```

请注意，AppArmor 不是 Kubernetes 对象，如 pod、部署等。它不能通过`kubectl`操作。您需要 SSH 到每个节点，并将 AppArmor 配置文件加载到内核中，以便 pod 可以使用它。

以下是加载 AppArmor 配置文件的命令：

```
cat /etc/apparmor.d/profile.name | sudo apparmor_parser -a
```

然后，将配置文件放入`enforce`模式：

```
sudo aa-enforce /etc/apparmor.d/profile.name
```

一旦加载了 AppArmor 配置文件，您可以更新 pod 的注释，以使用 AppArmor 配置文件保护您的容器。以下是将 AppArmor 配置文件应用于容器的示例：

```
apiVersion: v1
kind: Pod
metadata:
  name: hello-apparmor
  annotations:
    # Tell Kubernetes to apply the AppArmor profile 
    # "k8s-apparmor-example-deny-write".
    container.apparmor.security.beta.kubernetes.io/hello: 
      localhost/k8s-apparmor-example-deny-write
spec:
  containers:
  - name: hello
    image: busybox
    command: [ "sh", "-c", "echo 'Hello AppArmor!' && sleep 1h" ]
```

`hello-apparmor`内的容器除了在回显“Hello AppArmor！”消息后进入睡眠状态外，什么也不做。当它运行时，如果您从容器中启动一个 shell 并写入任何文件，AppArmor 将会阻止。尽管编写健壮的 AppArmor 配置文件并不容易，但您仍然可以创建一些基本的限制，比如拒绝写入到某些目录，拒绝接受原始数据包，并使某些文件只读。此外，在将配置应用到生产集群之前，先测试配置文件。开源工具如 bane 可以帮助为容器创建 AppArmor 配置文件。

我们不打算在本书中深入讨论 seccomp 配置文件，因为为微服务编写 seccomp 配置文件并不容易。即使是应用程序开发人员也不知道他们开发的微服务有哪些系统调用是合法的。尽管您可以打开审计模式以避免破坏微服务的功能，但构建健壮的 seccomp 配置文件仍然任重道远。另一个原因是，这个功能在版本 1.17 之前仍处于 alpha 阶段。根据 Kubernetes 的官方文档，alpha 表示默认情况下禁用，可能存在错误，并且只建议在短期测试集群中运行。当 seccomp 有任何新的更新时，我们可能会在以后更详细地介绍 seccomp。

我们已经介绍了如何在构建时保护 Kubernetes Pod。接下来，让我们看看如何在运行时保护 Kubernetes Pod。

# PodSecurityPolicy 的力量

Kubernetes PodSecurityPolicy 是一个集群级资源，通过它可以控制 pod 规范的安全敏感方面，从而限制 Kubernetes pod 的访问权限。作为一名 DevOps 工程师，您可能希望使用 PodSecurityPolicy 来限制大部分工作负载以受限访问权限运行，同时只允许少数工作负载以额外权限运行。

在本节中，我们将首先仔细研究 PodSecurityPolicy，然后介绍一个名为 `kube-psp-advisor` 的开源工具，它可以帮助为运行中的 Kubernetes 集群构建一个自适应的 PodSecurityPolicy。

## 理解 PodSecurityPolicy

您可以将 PodSecurityPolicy 视为评估 Pod 规范中定义的安全属性的策略。只有那些安全属性符合 PodSecurityPolicy 要求的 Pod 才会被允许进入集群。例如，PodSecurityPolicy 可以用于阻止启动大多数特权 Pod，同时只允许那些必要或受限制的 Pod 访问主机文件系统。

以下是由 PodSecurityPolicy 控制的主要安全属性：

+   **privileged**: 确定 Pod 是否可以以特权模式运行。

+   **hostPID**: 确定 Pod 是否可以使用主机 PID 命名空间。

+   **hostNetwork**: 确定 Pod 是否可以使用主机网络命名空间。

+   **hostIPC**: 确定 Pod 是否可以使用主机 IPC 命名空间。默认设置为`true`。

+   **allowedCapabilities**: 指定可以添加到容器中的功能列表。默认设置为空。

+   **defaultAddCapabilities**: 指定默认情况下将添加到容器中的功能列表。默认设置为空。

+   **requiredDropCapabilities**: 指定将从容器中删除的功能列表。请注意，功能不能同时在`allowedCapabilities`和`requiredDropCapabilities`字段中指定。默认设置为空。

+   **readOnlyRootFilesystem**: 当设置为`true`时，PodSecurityPolicy 将强制容器以只读根文件系统运行。如果容器的安全上下文中明确将属性设置为`false`，则将拒绝 Pod 运行。默认设置为`false`。

+   **runAsUser**: 指定可以在 Pod 和容器的安全上下文中设置的允许用户 ID 列表。默认设置允许所有。

+   **runAsGroup**: 指定可以在 Pod 和容器的安全上下文中设置的允许组 ID 列表。默认设置允许所有。

+   **allowPrivilegeEscalation**: 确定 Pod 是否可以提交请求以允许特权升级。默认设置为`true`。

+   **allowedHostPaths**: 指定 Pod 可以挂载的主机路径列表。默认设置允许所有。

+   **卷**: 指定可以由 Pod 挂载的卷类型列表。例如，`secret`、`configmap`和`hostpath`是有效的卷类型。默认设置允许所有。

+   **seLinux**: 指定可以在 Pod 和容器的安全上下文中设置的允许`seLinux`标签列表。默认设置允许所有。

+   **allowedUnsafeSysctl**：允许运行不安全的`sysctls`。默认设置不允许任何。

现在，让我们来看一个 PodSecurityPolicy 的例子：

```
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
    name: example
spec:
  allowedCapabilities:
  - NET_ADMIN
  - IPC_LOCK
  allowedHostPaths:
  - pathPrefix: /dev
  - pathPrefix: /run
  - pathPrefix: /
  fsGroup:
    rule: RunAsAny
  hostNetwork: true
  privileged: true
  runAsUser:
    rule: RunAsAny
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  volumes:
  - hostPath
  - secret
```

这个 PodSecurityPolicy 允许`NET_ADMIN`和`IPC_LOCK`的权限，从主机和 Kubernetes 的秘密卷挂载`/`，`/dev`和`/run`。它不强制执行任何文件系统组 ID 或辅助组，也允许容器以任何用户身份运行，访问主机网络命名空间，并以特权容器运行。策略中没有强制执行 SELinux 策略。

要启用此 Pod 安全策略，您可以运行以下命令：

```
$ kubectl apply -f example-psp.yaml
```

现在，让我们验证 Pod 安全策略是否已成功创建：

```
$ kubectl get psp
```

输出将如下所示：

```
NAME      PRIV     CAPS                           SELINUX    RUNASUSER   FSGROUP    SUPGROUP   READONLYROOTFS   VOLUMES
example   true     NET_ADMIN, IPC_LOCK            RunAsAny   RunAsAny    RunAsAny   RunAsAny   false            hostPath,secret
```

创建了 Pod 安全策略后，还需要另一步来强制执行它。您将需要授予用户、组或服务帐户使用`PodSecurityPolicy`对象的特权。通过这样做，Pod 安全策略有权根据关联的服务帐户评估工作负载。以下是如何强制执行 PodSecurityPolicy 的示例。首先，您需要创建一个使用 PodSecurityPolicy 的集群角色：

```
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: use-example-psp
rules:
- apiGroups: ['policy']
  resources: ['podsecuritypolicies']
  verbs:     ['use']
  resourceNames:
  - example
```

然后，创建一个`RoleBinding`或`ClusterRoleBinding`对象，将之前创建的`ClusterRole`对象与服务帐户、用户或组关联起来：

```
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: use-example-psp-binding
roleRef:
  kind: ClusterRole
  name: use-example-psp
  apiGroup: rbac.authorization.k8s.io
subjects:
# Authorize specific service accounts:
- kind: ServiceAccount
  name: test-sa
  namespace: psp-test
```

之前创建的`use-example-pspbinding.yaml`文件创建了一个`RoleBinding`对象，将`use-example-psp`集群角色与`psp-test`命名空间中的`test-sa`服务帐户关联起来。通过所有这些设置，`psp-test`命名空间中其服务帐户为`test-sa`的任何工作负载将通过 PodSecurityPolicy 示例的评估。只有符合要求的工作负载才能被允许进入集群。

从上面的例子中，想象一下在您的 Kubernetes 集群中运行不同类型的工作负载，每个工作负载可能需要不同的特权来访问不同类型的资源。为不同的工作负载创建和管理 Pod 安全策略将是一个挑战。现在，让我们来看看`kube-psp-advisor`，看看它如何帮助您创建 Pod 安全策略。

## Kubernetes PodSecurityPolicy Advisor

Kubernetes PodSecurityPolicy Advisor（也称为`kube-psp-advisor`）是来自 Sysdig 的开源工具。它扫描集群中运行的工作负载的安全属性，然后基于此推荐您的集群或工作负载的 Pod 安全策略。

首先，让我们将`kube-psp-advisor`作为`kubectl`插件进行安装。如果您还没有安装`krew`，请按照说明（https://github.com/kubernetes-sigs/krew#installation）安装它。然后，使用`krew`安装`kube-psp-advisor`如下：

```
$ kubectl krew install advise-psp
```

然后，您应该能够运行以下命令来验证安装：

```
$ kubectl advise-psp
A way to generate K8s PodSecurityPolicy objects from a live K8s environment or individual K8s objects containing pod specifications
Usage:
  kube-psp-advisor [command]
Available Commands:
  convert     Generate a PodSecurityPolicy from a single K8s Yaml file
  help        Help about any command
  inspect     Inspect a live K8s Environment to generate a PodSecurityPolicy
Flags:
  -h, --help           help for kube-psp-advisor
      --level string   Log level (default "info")
```

要为命名空间中的工作负载生成 Pod 安全策略，可以运行以下命令：

```
$ kubectl advise-psp inspect --grant --namespace psp-test
```

上述命令为在`psp-test`命名空间内运行的工作负载生成了 Pod 安全策略。如果工作负载使用默认服务账户，则不会为其生成 PodSecurityPolicy。这是因为默认服务账户将被分配给没有专用服务账户关联的工作负载。当然，您肯定不希望默认服务账户能够使用特权工作负载的 PodSecurityPolicy。

以下是`kube-psp-advisor`为`psp-test`命名空间中的工作负载生成的输出示例，包括 Role、RoleBinding 和 PodSecurityPolicy 在一个单独的 YAML 文件中，其中包含多个 Pod 安全策略。让我们来看一个推荐的 PodSecurityPolicy：

```
# Pod security policies will be created for service account 'sa-1' in namespace 'psp-test' with following workloads:
#	Kind: ReplicaSet, Name: busy-rs, Image: busybox
#	Kind: Pod, Name: busy-pod, Image: busybox
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  creationTimestamp: null
  name: psp-for-psp-test-sa-1
spec:
  allowedCapabilities:
  - SYS_ADMIN
  allowedHostPaths:
  - pathPrefix: /usr/bin
    readOnly: true
  fsGroup:
    rule: RunAsAny
  hostIPC: true
  hostNetwork: true
  hostPID: true
  runAsUser:
    rule: RunAsAny
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  volumes:
  - configMap
  - secret
  - hostPath
```

以下是由`kube-psp-advisor`生成的 Role：

```
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  creationTimestamp: null
  name: use-psp-by-psp-test:sa-1
  namespace: psp-test
rules:
- apiGroups:
  - policy
  resourceNames:
  - psp-for-psp-test-sa-1
  resources:
  - podsecuritypolicies
  verbs:
  - use
---
```

以下是由`kube-psp-advisor`生成的 RoleBinding：

```
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: null
  name: use-psp-by-psp-test:sa-1-binding
  namespace: psp-test
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: use-psp-by-psp-test:sa-1
subjects:
- kind: ServiceAccount
  name: sa-1
  namespace: psp-test
---
```

前面的部分是推荐的 PodSecurityPolicy，`psp-for-psp-test-sa-1`，适用于`busy-rs`和`busy-pod`工作负载，因为这两个工作负载共享相同的服务账户`sa-1`。因此，分别创建了`Role`和`RoleBinding`来使用 Pod 安全策略`psp-for-psp-test-sa-1`。PodSecurityPolicy 是基于使用`sa-1`服务账户的工作负载的安全属性的聚合生成的：

```
---
# Pod security policies will NOT be created for service account 'default' in namespace 'psp-test' with following workdloads:
#	Kind: ReplicationController, Name: busy-rc, Image: busybox
---
```

前面的部分提到`busy-rc`工作负载使用`default`服务账户，因此不会为其创建 Pod 安全策略。这是一个提醒，如果要为工作负载生成 Pod 安全策略，请不要使用默认服务账户。

构建 Kubernetes PodSecurityPolicy 并不是一件简单的事情，尽管如果一个受限的 PodSecurityPolicy 适用于整个集群，并且所有工作负载都符合它将是理想的。DevOps 工程师需要有创造力，以便构建受限的 Pod 安全策略，同时不破坏工作负载的功能。`kube-psp-advisor`使得实施 Kubernetes Pod 安全策略变得简单，适应您的应用程序要求，并且特别为每个应用程序提供了细粒度的权限，只允许最少访问权限的特权。

# 总结

在本章中，我们介绍了如何使用 CIS Docker 基准来加固容器镜像，然后详细介绍了 Kubernetes 工作负载的安全属性。接下来，我们详细介绍了 PodSecurityPolicy，并介绍了`kube-psp-advisor`开源工具，该工具有助于建立 Pod 安全策略。

保护 Kubernetes 工作负载不是一蹴而就的事情。安全控制需要从构建、部署和运行阶段应用。它始于加固容器镜像，然后以安全的方式配置 Kubernetes 工作负载的安全属性。这发生在构建阶段。为不同的 Kubernetes 工作负载构建自适应的 Pod 安全策略也很重要。目标是限制大多数工作负载以受限权限运行，同时只允许少数工作负载以额外权限运行，而不会破坏工作负载的可用性。这发生在运行时阶段。`kube-psp-advisor`能够帮助构建自适应的 Pod 安全策略。

在下一章中，我们将讨论图像扫描。在 DevOps 工作流程中，这对于帮助保护 Kubernetes 工作负载至关重要。

# 问题

1.  在 Dockerfile 中，`HEALTHCHECK`是做什么的？

1.  为什么在 Dockerfile 中使用`COPY`而不是`ADD`？

1.  如果您的应用程序不监听任何端口，可以丢弃哪些默认功能？

1.  `runAsNonRoot`属性控制什么？

1.  当您创建一个`PodSecurityPolicy`对象时，为了强制执行该 Pod 安全策略，您还需要做什么？

# 进一步阅读

您可以参考以下链接，了解本章涵盖的主题的更多信息：

+   要了解有关`kube-psp-advisor`的更多信息，请访问以下链接：[`github.com/sysdiglabs/kube-psp-advisor`](https://github.com/sysdiglabs/kube-psp-advisor)

+   要了解有关 AppArmor 的更多信息，请访问以下链接：[`gitlab.com/apparmor/apparmor/-/wikis/Documentation`](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)

+   要了解有关 bane 的更多信息，请访问以下链接：[`github.com/genuinetools/bane`](https://github.com/genuinetools/bane)


# 第九章：DevOps 流水线中的图像扫描

在开发生命周期的早期阶段发现缺陷和漏洞是一个好的做法。在早期阶段识别问题并加以修复有助于提高应用程序的稳健性和稳定性。它还有助于减少生产环境中的攻击面。保护 Kubernetes 集群必须覆盖整个 DevOps 流程。与加固容器图像和在工作负载清单中限制强大的安全属性类似，图像扫描可以帮助改善开发方面的安全姿态。但是，图像扫描绝对可以做得更多。

在本章中，首先，我们将介绍图像扫描和漏洞的概念，然后我们将讨论一个名为 Anchore Engine 的流行开源图像扫描工具，并向您展示如何使用它进行图像扫描。最后但同样重要的是，我们将向您展示如何将图像扫描集成到 CI/CD 流水线中。

在本章之后，您应该熟悉图像扫描的概念，并且可以放心地使用 Anchore Engine 进行图像扫描。更重要的是，如果您还没有这样做，您需要开始考虑将图像扫描集成到您的 CI/CD 流水线中的策略。

在本章中，我们将涵盖以下主题：

+   介绍容器图像和漏洞

+   使用 Anchore Engine 扫描图像

+   将图像扫描集成到 CI/CD 流水线中

# 介绍容器图像和漏洞

图像扫描可用于识别图像内部的漏洞或违反最佳实践（取决于图像扫描器的能力）。漏洞可能来自图像内的应用程序库或工具。在我们开始图像扫描之前，最好先了解一些关于容器图像和漏洞的知识。

## 容器图像

容器镜像是一个文件，其中包含了微服务二进制文件、其依赖项、微服务的配置等。如今，应用程序开发人员不仅编写代码来构建微服务，还需要构建一个镜像来容器化应用程序。有时，应用程序开发人员可能不遵循安全最佳实践来编写代码，或者从未经认证的来源下载库。这意味着您自己的应用程序或应用程序依赖的包可能存在漏洞。但不要忘记您使用的基础镜像，其中可能包含另一组脆弱的二进制文件和软件包。因此，首先让我们看一下镜像的样子：

```
$ docker history kaizheh/anchore-cli
IMAGE               CREATED             CREATED BY                                      SIZE                COMMENT
76b8613d39bc        8 hours ago         /bin/sh -c #(nop) COPY file:92b27c0a57eddb63…   678B                
38ea9049199d        10 hours ago        /bin/sh -c #(nop)  ENV PATH=/.local/bin/:/us…   0B                  
525287c1340a        10 hours ago        /bin/sh -c pip install anchorecli               5.74MB              
f0cbce9c40f4        10 hours ago        /bin/sh -c apt-get update && apt-get install…   423MB               
a2a15febcdf3        7 months ago        /bin/sh -c #(nop)  CMD ["/bin/bash"]            0B                  
<missing>           7 months ago        /bin/sh -c mkdir -p /run/systemd && echo 'do…   7B                  
<missing>           7 months ago        /bin/sh -c set -xe   && echo '#!/bin/sh' > /…   745B                
<missing>           7 months ago        /bin/sh -c [ -z "$(apt-get indextargets)" ]     987kB               
<missing>           7 months ago        /bin/sh -c #(nop) ADD file:c477cb0e95c56b51e…   63.2MB       
```

上面的输出显示了镜像`kaizheh/anchore-cli`的文件层（使用`--no-trunc`标志显示完整命令）。您可能注意到每个文件层都有一个创建它的相应命令。每个命令之后都会创建一个新的文件层，这意味着镜像的内容已经逐层更新（基本上，Docker 是按写时复制工作的），您仍然可以看到每个文件层的大小。这很容易理解：当您安装新的软件包或向基础添加文件时，镜像的大小会增加。`missing`镜像 ID 是一个已知的问题，因为 Docker Hub 只存储叶层的摘要，而不是父镜像中的中间层。然而，上述镜像历史确实说明了镜像在 Dockerfile 中的情况，如下所示：

```
FROM ubuntu
RUN apt-get update && apt-get install -y python-pip jq vim
RUN pip install anchorecli
ENV PATH="$HOME/.local/bin/:$PATH"
COPY ./demo.sh /demo.sh
```

上述 Dockerfile 的工作原理描述如下：

1.  构建`kaizheh/anchore-cli`镜像时，我选择从`ubuntu`构建。

1.  然后，我安装了`python-pip`，`jq`和`vim`软件包。

1.  接下来，我使用`pip`安装了`anchore-cli`，这是我在上一步中安装的。

1.  然后我配置了环境变量路径。

1.  最后，我将一个名为`demo.sh`的 shell 脚本复制到了镜像中。

下图显示了镜像文件层映射到 Dockerfile 指令：

![图 9.1 - Dockerfile 指令映射到镜像文件层](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_09_001.jpg)

图 9.1 - Dockerfile 指令映射到镜像文件层

你不必记住每一层添加了什么。最终，容器镜像是一个压缩文件，其中包含了应用程序所需的所有二进制文件和软件包。当从镜像创建容器时，容器运行时会提取镜像，然后为镜像的提取内容创建一个目录，然后在启动之前为镜像中的入口应用程序配置 chroot、cgroup、Linux 命名空间、Linux 权限等。

现在你知道了容器运行时启动容器的魔法。但你仍然不确定你的镜像是否存在漏洞，以至于可以轻易被黑客攻击。让我们看看镜像扫描到底是做什么。

## 检测已知漏洞

人们会犯错误，开发人员也一样。如果应用程序中的缺陷是可以利用的，这些缺陷就会成为安全漏洞。漏洞有两种类型，一种是已经被发现的，而另一种则是未知的。安全研究人员、渗透测试人员等都在努力寻找安全漏洞，以减少潜在的妥协。一旦安全漏洞被修补，开发人员会将补丁作为应用程序的更新。如果这些更新没有及时应用，应用程序就有被攻击的风险。如果这些已知的安全问题被恶意人员利用，将给公司造成巨大损失。

在这一部分，我们不会讨论如何寻找安全漏洞。让安全研究人员和道德黑客去做他们的工作。相反，我们将讨论如何通过执行漏洞管理来发现和管理那些由镜像扫描工具发现的已知漏洞。此外，我们还需要了解漏洞是如何在社区中跟踪和共享的。因此，让我们谈谈 CVE 和 NVD。

### 漏洞数据库简介

CVE 代表通用漏洞和暴露。当发现漏洞时，会为其分配一个唯一的 ID，并附有描述和公共参考。通常，描述中会包含受影响的版本信息。这就是一个 CVE 条目。每天都会发现数百个漏洞，并由 MITRE 分配唯一的 CVE ID。

NVD 代表国家漏洞数据库。它同步 CVE 列表。一旦 CVE 列表有新的更新，新的 CVE 将立即显示在 NVD 中。除了 NVD，还有一些其他的漏洞数据库可用，比如 Synk。

简单来说，图像扫描工具的魔法是：图像扫描工具提取图像文件，然后查找图像中所有可用的软件包和库，并在漏洞数据库中查找它们的版本。如果有任何软件包的版本与漏洞数据库中的任何 CVE 描述匹配，图像扫描工具将报告图像中存在漏洞。如果在容器图像中发现漏洞，您不应感到惊讶。那么，您打算怎么处理呢？您需要做的第一件事是保持冷静，不要惊慌。

### 漏洞管理

当您有漏洞管理策略时，就不会惊慌。一般来说，每个漏洞管理策略都将从理解漏洞的可利用性和影响开始，这是基于 CVE 详细信息的。NVD 提供了一个漏洞评分系统，也被称为通用漏洞评分系统（CVSS），以帮助您更好地了解漏洞的严重程度。

根据您对漏洞的理解，需要提供以下信息来计算漏洞分数：

+   攻击向量：利用程序是网络攻击、本地攻击还是物理攻击

+   攻击复杂性：利用漏洞的难度有多大

+   所需权限：利用程序是否需要任何权限，如 root 或非 root

+   用户交互：利用程序是否需要任何用户交互

+   范围：利用程序是否会导致跨安全域

+   机密性影响：利用程序对软件机密性的影响程度

+   完整性影响：利用程序对软件完整性的影响程度

+   可用性影响：利用程序对软件可用性的影响程度

CVSS 计算器可在[`nvd.nist.gov/vuln-metrics/cvss/v3-calculator`](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)找到：

![图 9.2 - CVSS 计算器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_09_002.jpg)

图 9.2 - CVSS 计算器

尽管前面截图中的输入字段只涵盖了基本分数指标，但它们作为决定漏洞严重程度的基本因素。还有另外两个指标可以用来评估漏洞的严重程度，但我们不打算在本节中涵盖它们。根据 CVSS（第 3 版），分数有四个范围：

+   **低**: 0.1-3.9

+   **中等**: 4-6.9

+   **高**: 7-8.9

+   **关键**: 9-10

通常，图像扫描工具在报告图像中的任何漏洞时会提供 CVSS 分数。在采取任何响应措施之前，漏洞分析至少还有一步。你需要知道漏洞的严重程度也可能受到你自己环境的影响。让我举几个例子：

+   漏洞只能在 Windows 中被利用，但基本操作系统镜像不是 Windows。

+   漏洞可以从网络访问中被利用，但图像中的进程只发送出站请求，从不接受入站请求。

上述情景展示了 CVSS 分数并不是唯一重要的因素。你应该专注于那些既关键又相关的漏洞。然而，我们的建议仍然是明智地优先处理漏洞，并尽快修复它们。

如果在图像中发现漏洞，最好及早修复。如果在开发阶段发现漏洞，那么你应该有足够的时间来做出响应。如果在运行生产集群中发现漏洞，应该在补丁可用时立即修补图像并重新部署。如果没有补丁可用，那么有一套缓解策略可以防止集群受到损害。

这就是为什么图像扫描工具对你的 CI/CD 流水线至关重要。在一节中涵盖漏洞管理并不现实，但我认为对漏洞管理的基本理解将帮助你充分利用任何图像扫描工具。有一些流行的开源图像扫描工具可用，比如 Anchore、Clair、Trivvy 等等。让我们看一个这样的图像扫描工具和例子。

# 使用 Anchore Engine 扫描图像

Anchore Engine 是一个开源的图像扫描工具。它不仅分析 Docker 图像，还允许用户定义接受图像扫描策略。在本节中，我们将首先对 Anchore Engine 进行高层介绍，然后我们将展示如何使用 Anchore 自己的 CLI 工具`anchore-cli`部署 Anchore Engine 和 Anchore Engine 的基本图像扫描用例。

## Anchore Engine 简介

当图像提交给 Anchore Engine 进行分析时，Anchore Engine 将首先从图像注册表中检索图像元数据，然后下载图像并将图像排队进行分析。以下是 Anchore Engine 将要分析的项目：

+   图像元数据

+   图像层

+   操作系统软件包，如`deb`、`rpm`、`apkg`等

+   文件数据

+   应用程序依赖包：

- Ruby 宝石

- Node.js NPMs

- Java 存档

- Python 软件包

+   文件内容

要在 Kubernetes 集群中使用 Helm 部署 Anchore Engine——CNCF 项目，这是 Kubernetes 集群的软件包管理工具，请运行以下命令：

```
$ helm install anchore-demo stable/anchore-engine
```

Anchore Engine 由几个微服务组成。在 Kubernetes 集群中部署时，您会发现以下工作负载正在运行：

```
$ kubectl get deploy
NAME                                      READY   UP-TO-DATE   AVAILABLE   AGE
anchore-demo-anchore-engine-analyzer      1/1     1            1           3m37s
anchore-demo-anchore-engine-api           1/1     1            1           3m37s
anchore-demo-anchore-engine-catalog       1/1     1            1           3m37s
anchore-demo-anchore-engine-policy        1/1     1            1           3m37s
anchore-demo-anchore-engine-simplequeue   1/1     1            1           3m37s
anchore-demo-postgresql                   1/1     1            1           3m37s
```

Anchore Engine 将图像扫描服务解耦为前面日志中显示的微服务：

+   **API**：接受图像扫描请求

+   **目录**：维护图像扫描作业的状态

+   **策略**：加载图像分析结果并执行策略评估

+   **Analyzer**：从图像注册表中拉取图像并执行分析

+   **Simplequeue**：排队图像扫描任务

+   **PostgreSQL**：存储图像分析结果和状态

现在 Anchore Engine 已成功部署在 Kubernetes 集群中，让我们看看如何使用`anchore-cli`进行图像扫描。

## 使用 anchore-cli 扫描图像

Anchore Engine 支持从 RESTful API 和`anchore-cli`访问。`anchore-cli`在迭代使用时非常方便。`anchore-cli`不需要在 Kubernetes 集群中运行。您需要配置以下环境变量以启用对 Anchore Engine 的 CLI 访问：

+   `ANCHORE_CLI_URL`：Anchore Engine API 端点

+   `ANCHORE_CLI_USER`：访问 Anchore Engine 的用户名

+   `ANCHORE_CLI_PASS`：访问 Anchore Engine 的密码

一旦您成功配置了环境变量，您可以使用以下命令验证与 Anchore Engine 的连接：

```
root@anchore-cli:/# anchore-cli system status
```

输出应该如下所示：

```
Service analyzer (anchore-demo-anchore-engine-analyzer-5fd777cfb5-jtqp2, http://anchore-demo-anchore-engine-analyzer:8084): up
Service apiext (anchore-demo-anchore-engine-api-6dd475cf-n24xb, http://anchore-demo-anchore-engine-api:8228): up
Service policy_engine (anchore-demo-anchore-engine-policy-7b8f68fbc-q2dm2, http://anchore-demo-anchore-engine-policy:8087): up
Service simplequeue (anchore-demo-anchore-engine-simplequeue-6d4567c7f4-7sll5, http://anchore-demo-anchore-engine-simplequeue:8083): up
Service catalog (anchore-demo-anchore-engine-catalog-949bc68c9-np2pc, http://anchore-demo-anchore-engine-catalog:8082): up
Engine DB Version: 0.0.12
Engine Code Version: 0.6.1
```

`anchore-cli` 能够与 Kubernetes 集群中的 Anchore Engine 进行通信。现在让我们使用以下命令扫描一个镜像：

```
root@anchore-cli:/# anchore-cli image add kaizheh/nginx-docker
```

输出应该如下所示：

```
Image Digest: sha256:416b695b09a79995b3f25501bf0c9b9620e82984132060bf7d66d877 6c1554b7
Parent Digest: sha256:416b695b09a79995b3f25501bf0c9b9620e82984132060bf7d66d877 6c1554b7
Analysis Status: analyzed
Image Type: docker
Analyzed At: 2020-03-22T05:48:14Z
Image ID: bcf644d78ccd89f36f5cce91d205643a47c8a5277742c5b311c9d9 6699a3af82
Dockerfile Mode: Guessed
Distro: debian
Distro Version: 10
Size: 1172316160
Architecture: amd64
Layer Count: 16
Full Tag: docker.io/kaizheh/nginx-docker:latest
Tag Detected At: 2020-03-22T05:44:38Z
```

您将从镜像中获得镜像摘要、完整标签等信息。根据镜像大小，Anchore Engine 分析镜像可能需要一些时间。一旦分析完成，您将看到 `Analysis Status` 字段已更新为 `analyzed`。使用以下命令检查镜像扫描状态：

```
root@anchore-cli:/# anchore-cli image get kaizheh/nginx-docker
```

输出应该如下所示：

```
Image Digest: sha256:416b695b09a79995b3f25501bf0c9b9620e82984132060bf7d66d877 6c1554b7
Parent Digest: sha256:416b695b09a79995b3f25501bf0c9b9620e82984132060bf7d66d877 6c1554b7
Analysis Status: analyzed
Image Type: docker
Analyzed At: 2020-03-22T05:48:14Z
Image ID: bcf644d78ccd89f36f5cce91d205643a47c8a5277742c5b311c9d96699a3a f82
Dockerfile Mode: Guessed
Distro: debian
Distro Version: 10
Size: 1172316160
Architecture: amd64
Layer Count: 16
Full Tag: docker.io/kaizheh/nginx-docker:latest
Tag Detected At: 2020-03-22T05:44:38Z
```

我们之前简要提到了 Anchore Engine 策略；Anchore Engine 策略允许您根据漏洞的严重程度不同定义规则来处理漏洞。在默认的 Anchore Engine 策略中，您将在默认策略中找到以下两条规则。第一条规则如下：

```
{
	"action": "WARN",
	"gate": "vulnerabilities",
	"id": "6063fdde-b1c5-46af-973a-915739451ac4",
	"params": [{
			"name": "package_type",
			"value": "all"
		},
		{
			"name": "severity_comparison",
			"value": "="
		},
		{
			"name": "severity",
			"value": "medium"
		}
	],
	"trigger": "package"
},
```

第一条规则定义了任何具有中等级漏洞的软件包仍将将策略评估结果设置为通过。第二条规则如下：

```
 {
 	"action": "STOP",
 	"gate": "vulnerabilities",
 	"id": "b30e8abc-444f-45b1-8a37-55be1b8c8bb5",
 	"params": [{
 			"name": "package_type",
 			"value": "all"
 		},
 		{
 			"name": "severity_comparison",
 			"value": ">"
 		},
 		{
 			"name": "severity",
 			"value": "medium"
 		}
 	],
 	"trigger": "package"
 },
```

第二条规则定义了任何具有高或关键漏洞的软件包将会将策略评估结果设置为失败。镜像分析完成后，使用以下命令检查策略：

```
root@anchore-cli:/# anchore-cli --json evaluate check sha256:416b695b09a79995b3f25501bf0c9b9620e82984132060bf7d66d877 6c1554b7 --tag docker.io/kaizheh/nginx-docker:latest
```

输出应该如下所示：

```
[
    {
        "sha256:416b695b09a79995b3f25501bf0c9b9620e82984132060 bf7d66d8776c1554b7": {
            "docker.io/kaizheh/nginx-docker:latest": [
                {
                    "detail": {},
                    "last_evaluation": "2020-03-22T06:19:44Z",
                    "policyId": "2c53a13c-1765-11e8-82ef-235277 61d060",
                    "status": "fail"
                }
            ]
        }
    }
]
```

因此，镜像 `docker.io/kaizheh/nginx-docker:latest` 未通过默认策略评估。这意味着必须存在一些高或关键级别的漏洞。使用以下命令列出镜像中的所有漏洞：

```
root@anchore-cli:/# anchore-cli image vuln docker.io/kaizheh/nginx-docker:latest all
```

输出应该如下所示：

```
Vulnerability ID        Package                                                Severity          Fix                              CVE Refs                Vulnerability URL
CVE-2019-9636           Python-2.7.16                                          Critical          None                             CVE-2019-9636           https://nvd.nist.gov/vuln/detail/CVE-2019-9636
CVE-2020-7598           minimist-0.0.8                                         Critical          None                             CVE-2020-7598           https://nvd.nist.gov/vuln/detail/CVE-2020-7598
CVE-2020-7598           minimist-1.2.0                                         Critical          None                             CVE-2020-7598           https://nvd.nist.gov/vuln/detail/CVE-2020-7598
CVE-2020-8116           dot-prop-4.2.0                                         Critical          None                             CVE-2020-8116           https://nvd.nist.gov/vuln/detail/CVE-2020-8116
CVE-2013-1753           Python-2.7.16                                          High              None                             CVE-2013-1753           https://nvd.nist.gov/vuln/detail/CVE-2013-1753
CVE-2015-5652           Python-2.7.16                                          High              None                             CVE-2015-5652           https://nvd.nist.gov/vuln/detail/CVE-2015-5652
CVE-2019-13404          Python-2.7.16                                          High              None                             CVE-2019-13404          https://nvd.nist.gov/vuln/detail/CVE-2019-13404
CVE-2016-8660           linux-compiler-gcc-8-x86-4.19.67-2+deb10u1             Low               None                             CVE-2016-8660           https://security-tracker.debian.org/tracker/CVE-2016-8660
CVE-2016-8660           linux-headers-4.19.0-6-amd64-4.19.67-2+deb10u1         Low               None                             CVE-2016-8660           https://security-tracker.debian.org/tracker/CVE-2016-8660
```

上述列表显示了镜像中的所有漏洞，包括 CVE ID、软件包名称、严重程度、是否有修复可用以及参考信息。Anchore Engine 策略基本上帮助您过滤掉较不严重的漏洞，以便您可以专注于更严重的漏洞。然后，您可以开始与安全团队进行漏洞分析。

注意

有时，如果一个软件包或库中的高级或关键级别漏洞没有修复可用，您应该寻找替代方案，而不是继续使用有漏洞的软件包。

在接下来的部分，我们将讨论如何将镜像扫描集成到 CI/CD 流水线中。

# 将镜像扫描集成到 CI/CD 流水线中

镜像扫描可以在 DevOps 流水线的多个阶段触发，我们已经讨论了在流水线早期阶段扫描镜像的优势。然而，新的漏洞将被发现，您的漏洞数据库应该不断更新。这表明，即使在构建阶段通过了镜像扫描，也不意味着在运行时阶段会通过，如果发现了新的关键漏洞，并且该漏洞也存在于镜像中。当发生这种情况时，您应该停止工作负载部署，并相应地应用缓解策略。在深入集成之前，让我们看一下适用于镜像扫描的 DevOps 阶段的大致定义:

+   **构建**: 当镜像在 CI/CD 流水线中构建时

+   **部署**: 当镜像即将部署到 Kubernetes 集群时

+   **运行时**: 在镜像部署到 Kubernetes 集群并且容器正在运行时

虽然有许多不同的 CI/CD 流水线和许多不同的镜像扫描工具供您选择，但整合镜像扫描到 CI/CD 流水线中的概念是确保 Kubernetes 工作负载和 Kubernetes 集群的安全。

## 构建阶段的扫描

有许多 CI/CD 工具，例如 Jenkins、Spinnaker 和 Screwdriver，供您使用。在本节中，我们将展示如何将镜像扫描集成到 GitHub 工作流程中。GitHub 中的工作流程是一个可配置的自动化流程，包含多个作业。这类似于 Jenkins 流水线的概念，但是以 YAML 格式定义。具有镜像扫描的简单工作流程就像定义触发器。通常在拉取请求或提交推送时完成，设置构建环境，例如 Ubuntu。

然后在工作流程中定义步骤:

1.  检出 PR 分支。

1.  从分支构建镜像。

1.  将镜像推送到注册表-这是可选的。当本地构建镜像时，应该能够启动镜像扫描器来扫描镜像。

1.  扫描新构建或推送的镜像。

1.  如果违反策略，则失败工作流。

以下是 GitHub 中定义的示例工作流程:

```
name: CI
...
  build:
    runs-on: ubuntu-latest
    steps:
    # Checks-out your repository under $GITHUB_WORKSPACE, so your job can access it
    - uses: actions/checkout@v2
    # Runs a set of commands using the runners shell
    - name: Build and Push
      env:
        DOCKER_SECRET: ${{ secrets.DOCKER_SECRET }} 
      run: |
        cd master/chapter9 && echo "Build Docker Image"
        docker login -u kaizheh -p ${DOCKER_SECRET}
        docker build -t kaizheh/anchore-cli . && docker push kaizheh/anchore-cli
    - name: Scan
      env:
        ANCHORE_CLI_URL: ${{ secrets.ANCHORE_CLI_URL }} 
        ANCHORE_CLI_USER:  ${{ secrets.ANCHORE_CLI_USER }}
        ANCHORE_CLI_PASS:  ${{ secrets.ANCHORE_CLI_PASS }}
      run: |      
        pip install anchorecli            # install anchore-cli
        export PATH="$HOME/.local/bin/:$PATH"       
        img="kaizheh/anchore-cli"
        anchore-cli image add $img        # add image
        sha=$(anchore-cli --json --api-version=0.2.4 image get $img | jq .[0].imageDigest -r)                   # get sha value
        anchore-cli image wait $img       # wait for image analyzed
        anchore-cli --json evaluate check $sha --tag $img # evaluate       
    - name: Post Scan
      run: |
        # Slack to notify developers scan result or invite new reviewer if failed
        exit 1  # purposely ends here
```

在构建流水线的第一步中，我使用了`checkout` GitHub 操作来检出分支。GitHub 操作对于工作流程就像编程语言中的函数一样。它封装了您不需要知道的细节，但为您执行任务。它可以接受输入参数并返回结果。在第二步中，我们运行了一些命令来构建图像`kaizheh/anchore-cli`并将图像推送到注册表。在第三步中，我们使用`anchore-cli`来扫描图像（是的，我们使用 Anchore Engine 来扫描我们自己的`anchore-cli`图像）。

请注意，我配置了 GitHub secrets 来存储诸如 Docker Hub 访问令牌、Anchore 用户名和密码等敏感信息。在最后一步，我们故意失败以进行演示。但通常，最后一步会随着评论建议的图像扫描结果而带来通知和响应。您将在 GitHub 中找到工作流程的结果详细信息，如下所示：

![图 9.3 – GitHub 图像扫描工作流程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_09_003.jpg)

图 9.3 – GitHub 图像扫描工作流程

前面的屏幕截图显示了工作流程中每个步骤的状态，当您点击进入时，您将找到每个步骤的详细信息。Anchore 还提供了一个名为 Anchore Container Scan 的图像扫描 GitHub 操作。它在新构建的图像上启动 Anchore Engine 扫描程序，并返回漏洞、清单和可以用于失败构建的通过/失败策略评估。

## 在部署阶段进行扫描

尽管部署是一个无缝的过程，但我想在一个单独的部分提出关于在部署阶段进行图像扫描的两个原因：

+   将应用程序部署到 Kubernetes 集群时，可能会发现新的漏洞，即使它们在构建时通过了图像扫描检查。最好在它们在 Kubernetes 集群中运行时发现漏洞之前阻止它们。

+   图像扫描可以成为 Kubernetes 中验证准入过程的一部分。

我们已经在*第七章*中介绍了`ValidatingAdmissionWebhook`的概念，*身份验证、授权和准入控制*。现在，让我们看看图像扫描如何帮助通过在 Kubernetes 集群中运行之前扫描其图像来验证工作负载。图像扫描准入控制器是来自 Sysdig 的开源项目。它扫描即将部署的工作负载中的图像。如果图像未通过图像扫描策略，工作负载将被拒绝。以下是工作流程图：

![图 9.4 - 图像扫描准入工作流](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_09_004.jpg)

图 9.4 - 图像扫描准入工作流

前面的图表显示了基于图像扫描验证的工作负载准入过程：

1.  有一个工作负载创建请求发送到`kube-apiserver`。

1.  `kube-apiserver`根据验证 webhook 配置将请求转发到注册的验证 webhook 服务器。

1.  验证 webhook 服务器从工作负载的规范中提取图像信息，并将其发送到 Anchore Engine API 服务器。

1.  根据图像扫描策略，Anchore Engine 将验证决定作为验证决定返回给服务器。

1.  验证 webhook 服务器将验证决定转发给`kube-apiserver`。

1.  `kube-apiserver`根据来自图像扫描策略评估结果的验证决定，要么允许要么拒绝工作负载。

要部署图像扫描准入控制器，首先要检出 GitHub 存储库（[`github.com/sysdiglabs/image-scanning-admission-controller`](https://github.com/sysdiglabs/image-scanning-admission-controller)），然后运行以下命令：

```
$ make deploy
```

然后你应该找到 webhook 服务器和服务已经创建：

```
NAME                                              READY   STATUS    RESTARTS   AGE
pod/image-scan-k8s-webhook-controller-manager-0   1/1     Running   1          16s
NAME                                                        TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)   AGE
service/image-scan-k8s-webhook-controller-manager-service   ClusterIP   100.69.225.172   <none>        443/TCP   16s
service/webhook-server-service                              ClusterIP   100.68.111.117   <none>        443/TCP   8s
NAME                                                         READY   AGE
statefulset.apps/image-scan-k8s-webhook-controller-manager   1/1     16s
```

除了 webhook 服务器部署，该脚本还创建了一个`ValidatingWebhookConfiguration`对象来注册图像扫描准入 webhook 服务器，该对象在`generic-validatingewebhookconfig.yaml`中定义到`kube-apiserver`：

```
apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingWebhookConfiguration
metadata:
  name: validating-webhook-configuration
webhooks:
- name: validating-create-pods.k8s.io
  clientConfig:
    service:
      namespace: image-scan-k8s-webhook-system
      name: webhook-server-service
      path: /validating-create-pods
    caBundle: {{CA_BUNDLE}}
  rules:
  - operations:
    - CREATE
    apiGroups:
    - ""
    apiVersions:
    - "v1"
    resources:
    - pods
  failurePolicy: Fail
```

验证 webhook 配置对象基本上告诉`kube-apiserver`将任何 pod 创建请求转发到`image-scan-webhook-system`命名空间中的`webhook-server-service`，并使用`/validating-create-pod` URL 路径。

您可以使用图像扫描准入控制器提供的测试用例来验证您的设置，如下所示：

```
$ make test
```

在测试中，将在 Kubernetes 集群中部署三个不同的 pod。其中一个存在关键漏洞，违反了图像扫描策略。因此，具有关键漏洞的工作负载将被拒绝。

```
+ kubectl run --image=bitnami/nginx --restart=Never nginx
pod/nginx created
+ kubectl run --image=kaizheh/apache-struts2-cve-2017-5638 --restart=Never apache-struts2
Error from server (Image failed policy check: kaizheh/apache-struts2-cve-2017-5638): admission webhook "validating-create-pods.k8s.io" denied the request: Image failed policy check: kaizheh/apache-struts2-cve-2017-5638
+ kubectl run --image=alpine:3.2 --restart=Never alpine
pod/alpine created
```

前面的输出显示，带有图像`kaizheh/apache-struts2-cve-2017-5638`的工作负载被拒绝了。该图像运行 Apache Struts 2 服务，其中包含一个 CVSS 评分为 10 的关键漏洞（[`nvd.nist.gov/vuln/detail/CVE-2017-5638`](https://nvd.nist.gov/vuln/detail/CVE-2017-5638)）。尽管测试中的 CVE 是旧的，但您应该能够在早期发现它。然而，新的漏洞将被发现，漏洞数据库将不断更新。为即将部署在 Kubernetes 集群中的任何工作负载设置一个门卫是至关重要的。图像扫描作为验证入场是 Kubernetes 部署的一个良好安全实践。现在，让我们谈谈在 Kubernetes 集群中运行时阶段的图像扫描。

## 运行时阶段的扫描

干得好！工作负载的图像在构建和部署阶段通过了图像扫描策略评估。但这并不意味着图像没有漏洞。请记住，新的漏洞将被发现。通常，图像扫描器使用的漏洞数据库将每隔几个小时更新一次。一旦漏洞数据库更新，您应该触发图像扫描器扫描在 Kubernetes 集群中正在运行的图像。有几种方法可以做到这一点：

+   直接在每个工作节点上扫描拉取的图像。要在工作节点上扫描图像，您可以使用诸如 Sysdig 的`secure-inline-scan`工具（[`github.com/sysdiglabs/secure-inline-scan`](https://github.com/sysdiglabs/secure-inline-scan)）。

+   定期在注册表中扫描图像，直接在漏洞数据库更新后进行扫描。

再次强调，一旦发现正在使用的图像中存在重大漏洞，您应该修补易受攻击的图像并重新部署，以减少攻击面。

# 总结

在本章中，我们首先简要讨论了容器图像和漏洞。然后，我们介绍了一个开源图像扫描工具 Anchore Engine，并展示了如何使用`anchore-cli`进行图像扫描。最后但同样重要的是，我们讨论了如何将图像扫描集成到 CI/CD 流水线的三个不同阶段：构建、部署和运行时。图像扫描在保护 DevOps 流程方面表现出了巨大的价值。一个安全的 Kubernetes 集群需要保护整个 DevOps 流程。

现在，您应该可以轻松部署 Anchore Engine 并使用`anchore-cli`来触发图像扫描。一旦您在图像中发现任何漏洞，请使用 Anchore Engine 策略将其过滤掉，并了解其真正影响。我知道这需要时间，但在您的 CI/CD 流水线中设置图像扫描是必要且很棒的。通过这样做，您将使您的 Kubernetes 集群更加安全。

在下一章中，我们将讨论 Kubernetes 集群中的资源管理和实时监控。

# 问题

让我们使用一些问题来帮助您更好地理解本章内容：

1.  哪个 Docker 命令可以用来列出图像文件层？

1.  根据 CVSS3 标准，哪个漏洞评分范围被认为是高风险的？

1.  `anchore-cli`命令是什么，用于开始扫描图像？

1.  `anchore-cli`命令是什么，用于列出图像的漏洞？

1.  `anchore-cli`命令是什么，用于评估符合 Anchore Engine 策略的图像？

1.  为什么将图像扫描集成到 CI/CD 流水线中如此重要？

# 进一步参考

+   要了解更多关于 Anchore Engine 的信息，请阅读：[`docs.anchore.com/current/docs/engine/general/`](https://docs.anchore.com/current/docs/engine/general/)

+   要了解更多关于 Anchore 扫描操作的信息：[`github.com/marketplace/actions/anchore-container-scan`](https://github.com/marketplace/actions/anchore-container-scan)

+   要了解更多关于 Sysdig 的图像扫描准入控制器的信息：[`github.com/sysdiglabs/image-scanning-admission-controller`](https://github.com/sysdiglabs/image-scanning-admission-controller)

+   要了解更多关于 GitHub actions 的信息：[`help.github.com/en/actions`](https://help.github.com/en/actions)


# 第十章：Kubernetes 集群的实时监控和资源管理

服务的可用性是**机密性、完整性和可用性**（**CIA**）三要素中的关键组成部分之一。曾经有许多恶意攻击者使用不同的技术来破坏用户服务的可用性。一些对关键基础设施的攻击，如电力网络和银行，导致了经济上的重大损失。其中最显著的攻击之一是对亚马逊 AWS Route 53 基础设施的攻击，导致全球核心 IT 服务中断。为了避免这样的问题，基础设施工程师实时监控资源使用和应用程序健康状况，以确保组织提供的服务的可用性。实时监控通常与警报系统相结合，当观察到服务中断的症状时通知利益相关者。

在本章中，我们将讨论如何确保 Kubernetes 集群中的服务始终正常运行。我们将首先讨论单体环境中的监控和资源管理。接下来，我们将讨论资源请求和资源限制，这是 Kubernetes 资源管理的核心概念。然后，我们将看看 Kubernetes 提供的诸如`LimitRanger`之类的工具，用于资源管理，然后将重点转移到资源监控。我们将研究内置监视器，如 Kubernetes 仪表板和 Metrics Server。最后，我们将研究一些开源工具，如 Prometheus 和 Grafana，用于监视 Kubernetes 集群的状态。

在本章中，我们将讨论以下内容：

+   在单体环境中进行实时监控和管理

+   在 Kubernetes 中管理资源

+   在 Kubernetes 中监控资源

# 在单体环境中进行实时监控和管理

资源管理和监控在单体环境中同样很重要。在单体环境中，基础设施工程师经常将 Linux 工具（如`top`、`ntop`和`htop`）的输出导入数据可视化工具，以监视虚拟机的状态。在托管环境中，内置工具如 Amazon CloudWatch 和 Azure 资源管理器有助于监视资源使用情况。

除了资源监控之外，基础设施工程师还会主动为进程和其他实体分配最低资源需求和使用限制。这确保了服务有足够的资源可用。此外，资源管理还确保不良行为或恶意进程不会占用资源并阻止其他进程工作。对于单体部署，诸如 CPU、内存和生成的进程等资源会被限制在不同的进程中。在 Linux 上，可以使用`prlimit`来限制进程的限制：

```
$prlimit --nproc=2 --pid=18065
```

这个命令设置了父进程可以生成的子进程的限制为`2`。设置了这个限制后，如果一个 PID 为`18065`的进程尝试生成超过`2`个子进程，它将被拒绝。

与单体环境类似，Kubernetes 集群运行多个 pod、部署和服务。如果攻击者能够生成 Kubernetes 对象，比如 pod 或部署，攻击者可以通过耗尽 Kubernetes 集群中可用的资源来发动拒绝服务攻击。如果没有足够的资源监控和资源管理，集群中运行的服务不可用可能会对组织造成经济影响。

# 在 Kubernetes 中管理资源

Kubernetes 提供了主动分配和限制 Kubernetes 对象可用资源的能力。在本节中，我们将讨论资源请求和限制，这构成了 Kubernetes 中资源管理的基础。接下来，我们将探讨命名空间资源配额和限制范围。使用这两个功能，集群管理员可以限制不同 Kubernetes 对象可用的计算和存储资源。

## 资源请求和限制

正如我们在*第一章*中讨论的那样，*Kubernetes 架构*中，默认的调度程序是`kube-scheduler`，它运行在主节点上。`kube-scheduler`会找到最适合的节点来运行未调度的 pod。它通过根据 pod 请求的存储和计算资源来过滤节点来实现这一点。如果调度程序无法为 pod 找到节点，pod 将保持在挂起状态。此外，如果节点的所有资源都被 pod 利用，节点上的`kubelet`将清理死掉的 pod - 未使用的镜像。如果清理不能减轻压力，`kubelet`将开始驱逐那些消耗更多资源的 pod。

资源请求指定了 Kubernetes 对象保证获得的资源。不同的 Kubernetes 变体或云提供商对资源请求有不同的默认值。可以在工作负载的规范中指定 Kubernetes 对象的自定义资源请求。资源请求可以针对 CPU、内存和 HugePages 进行指定。让我们看一个资源请求的例子。

让我们创建一个没有在 `yaml` 规范中指定资源请求的 Pod，如下所示：

```
apiVersion: v1
kind: Pod
metadata:
  name: demo
spec:
  containers:
  - name: demo
```

Pod 将使用部署的默认资源请求：

```
$kubectl get pod demo —output=yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{},"name":"demo","namespace":"default"},"spec":{"containers":[{"image":"nginx","name":"demo"}]}}
    kubernetes.io/limit-ranger: 'LimitRanger plugin set: cpu request for container
      demo'
  creationTimestamp: "2020-05-07T21:54:47Z"
  name: demo
  namespace: default
  resourceVersion: "3455"
  selfLink: /api/v1/namespaces/default/pods/demo
  uid: 5e783495-90ad-11ea-ae75-42010a800074
spec:
  containers:
  - image: nginx
    imagePullPolicy: Always
    name: demo
    resources:
      requests:
        cpu: 100m
```

对于前面的例子，Pod 的默认资源请求是 0.1 CPU 核心。现在让我们向 `.yaml` 规范中添加一个资源请求并看看会发生什么：

```
apiVersion: v1
kind: Pod
metadata:
  name: demo
spec:
  containers:
  - name: demo
    image: nginx
    resources:
      limits:
          hugepages-2Mi: 100Mi
      requests:
        cpu: 500m         memory: 300Mi         hugepages-2Mi: 100Mi 
```

这个规范创建了一个具有 0.5 CPU 核心、300 MB 和 `hugepages-2Mi` 的 100 MB 的资源请求的 Pod。您可以使用以下命令检查 Pod 的资源请求：

```
$kubectl get pod demo —output=yaml
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: "2020-05-07T22:02:16Z"
  name: demo-1
  namespace: default
  resourceVersion: "5030"
  selfLink: /api/v1/namespaces/default/pods/demo-1
  uid: 6a276dd2-90ae-11ea-ae75-42010a800074
spec:
  containers:
  - image: nginx
    imagePullPolicy: Always
    name: demo
    resources:
      limits:
        hugepages-2Mi: 100Mi
      requests:
        cpu: 500m
        hugepages-2Mi: 100Mi
        memory: 300Mi
```

从输出中可以看出，Pod 使用了 0.5 CPU 核心、300 MB `内存` 和 100 MB 2 MB `hugepages` 的自定义资源请求，而不是默认的 1 MB。

另一方面，限制是 Pod 可以使用的资源的硬限制。限制指定了 Pod 应该被允许使用的最大资源。如果需要的资源超过了限制中指定的资源，Pod 将受到限制。与资源请求类似，您可以为 CPU、内存和 HugePages 指定限制。让我们看一个限制的例子：

```
$ cat stress.yaml
apiVersion: v1
kind: Pod
metadata:
  name: demo
spec:
  containers:
  - name: demo
    image: polinux/stress
    command: ["stress"]
    args: ["--vm", "1", "--vm-bytes", "150M", "--vm-hang", "1"]
```

这个 Pod 启动一个尝试在启动时分配 `150M` 内存的压力进程。如果 `.yaml` 规范中没有指定限制，Pod 将可以正常运行：

```
$ kubectl create -f stress.yaml pod/demo created
$ kubectl get pods NAME         READY   STATUS             RESTARTS   AGE demo         1/1     Running            0          3h
```

限制被添加到 Pod 的 `yaml` 规范的容器部分：

```
containers:
  - name: demo
    image: polinux/stress
    resources:
      limits:
        memory: "150Mi"
    command: ["stress"]
args: ["--vm", "1", "--vm-bytes", "150M", "--vm-hang", "1"]
```

压力进程无法运行，Pod 进入 `CrashLoopBackOff` 状态：

```
$ kubectl get pods
NAME     READY   STATUS             RESTARTS   AGE
demo     1/1     Running            0          44s
demo-1   0/1     CrashLoopBackOff   1          5s
```

当您描述 Pod 时，可以看到 Pod 被终止并出现 `OOMKilled` 错误：

```
$ kubectl describe pods demo
Name:         demo
Namespace:    default
...
Containers:
  demo:
    Container ID:  docker://a43de56a456342f7d53fa9752aa4fa7366 cd4b8c395b658d1fc607f2703750c2
    Image:         polinux/stress
    Image ID:      docker-pullable://polinux/stress@sha256:b61 44f84f9c15dac80deb48d3a646b55c7043ab1d83ea0a697c09097aaad21aa
...
    Command:
      stress
    Args:
      --vm
      1
      --vm-bytes
      150M
      --vm-hang
      1
    State:          Waiting
      Reason:       CrashLoopBackOff
    Last State:     Terminated
      Reason:       OOMKilled
      Exit Code:    1
      Started:      Mon, 04 May 2020 10:48:14 -0700
      Finished:     Mon, 04 May 2020 10:48:14 -0700
```

资源请求和限制被转换、映射到 `docker` 参数——`—cpu-shares` 和 `—memory` 标志——并传递给容器运行时。

我们看了资源请求和限制如何为 Pod 工作的例子，但是相同的例子也适用于 DaemonSet、Deployments 和 StatefulSets。接下来，我们将看一下命名空间资源配额如何帮助设置命名空间可以使用的资源的上限。

## 命名空间资源配额

命名空间的资源配额有助于定义命名空间内所有对象可用的资源请求和限制。使用资源配额，您可以限制以下内容：

+   `request.cpu`：命名空间中所有对象的 CPU 的最大资源请求。

+   `request.memory`：命名空间中所有对象的内存的最大资源请求。

+   `limit.cpu`：命名空间中所有对象的 CPU 的最大资源限制。

+   `limit.memory`：命名空间中所有对象的内存的最大资源限制。

+   `requests.storage`：命名空间中存储请求的总和不能超过这个值。

+   `count`：资源配额也可以用来限制集群中不同 Kubernetes 对象的数量，包括 pod、服务、PersistentVolumeClaims 和 ConfigMaps。

默认情况下，云提供商或不同的变体对命名空间应用了标准限制。在**Google Kubernetes Engine**（**GKE**）上，`cpu`请求被设置为 0.1 CPU 核心：

```
$ kubectl describe namespace default
Name:         default
Labels:       <none>
Annotations:  <none>
Status:       Active
Resource Quotas
 Name:                       gke-resource-quotas
 Resource                    Used  Hard
 --------                    ---   ---
 count/ingresses.extensions  0     100
 count/jobs.batch            0     5k
 pods                        2     1500
 services                    1     500
Resource Limits
 Type       Resource  Min  Max  Default Request  Default Limit  Max Limit/Request Ratio
 ----       --------  ---  ---  ---------------  -------------  -----------------------
 Container  cpu       -    -    100m             -              -
```

让我们看一个例子，当资源配额应用到一个命名空间时会发生什么：

1.  创建一个命名空间演示：

```
$ kubectl create namespace demo
namespace/demo created
```

1.  定义一个资源配额。在这个例子中，配额将 CPU 的资源请求限制为`1` CPU：

```
$ cat quota.yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-resources
spec:
  hard:
    requests.cpu: "1"
```

1.  通过以下命令将配额应用到命名空间：

```
$ kubectl apply -f quota.yaml --namespace demo
resourcequota/compute-resources created
```

1.  您可以通过执行以下命令来检查资源配额是否成功应用到命名空间：

```
$ kubectl describe namespace demo
Name:         demo
Labels:       <none>
Annotations:  <none>
Status:       Active
Resource Quotas
 Name:         compute-resources
 Resource      Used  Hard
 --------      ---   ---
 requests.cpu  0     1
 Name:                       gke-resource-quotas
 Resource                    Used  Hard
 --------                    ---   ---
 count/ingresses.extensions  0     100
 count/jobs.batch            0     5k
 pods                        0     1500
 services                    0     500
```

1.  现在，如果我们尝试创建使用`1` CPU 的两个 pod，第二个请求将失败，并显示以下错误：

```
$ kubectl apply -f nginx-cpu-1.yaml --namespace demo
Error from server (Forbidden): error when creating "nginx-cpu-1.yaml": pods "demo-1" is forbidden: exceeded quota: compute-resources, requested: requests.cpu=1, used: requests.cpu=1, limited: requests.cpu=1
```

资源配额确保了命名空间中 Kubernetes 对象的服务质量。

## LimitRanger

我们在*第七章*中讨论了`LimitRanger`准入控制器，*身份验证、授权和准入控制*。集群管理员可以利用限制范围来确保行为不端的 pod、容器或`PersistentVolumeClaims`不会消耗所有可用资源。

要使用限制范围，启用`LimitRanger`准入控制器：

```
$ ps aux | grep kube-api
root      3708  6.7  8.7 497216 345256 ?       Ssl  01:44   0:10 kube-apiserver --advertise-address=192.168.99.116 --allow-privileged=true --authorization-mode=Node,RBAC --client-ca-file=/var/lib/minikube/certs/ca.crt --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,NodeRestriction,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota
```

使用 LimitRanger，我们可以对存储和计算资源强制执行`default`、`min`和`max`限制。集群管理员为诸如 pod、容器和 PersistentVolumeClaims 等对象创建一个限制范围。对于任何对象创建或更新的请求，LimitRanger 准入控制器会验证请求是否违反了任何限制范围。如果请求违反了任何限制范围，将发送 403 Forbidden 响应。

让我们看一个简单限制范围的例子：

1.  创建一个将应用限制范围的命名空间：

```
$kubectl create namespace demo
```

1.  为命名空间定义一个`LimitRange`：

```
$ cat limit_range.yaml
apiVersion: "v1"
kind: "LimitRange"
metadata:
  name: limit1
  namespace: demo
spec:
  limits:
  - type: "Container"
    max:
      memory: 512Mi
      cpu: 500m
    min:
      memory: 50Mi
      cpu: 50m
```

1.  验证`limitrange`是否被应用：

```
$ kubectl get limitrange -n demo
NAME     CREATED AT
limit1   2020-04-30T02:06:18Z
```

1.  创建一个违反限制范围的 pod：

```
$cat nginx-bad.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-bad
spec:
  containers:
  - name: nginx-bad
    image: nginx-bad
    resources:
      limits:
        memory: "800Mi"
        cpu: "500m"
```

这个请求将被拒绝：

```
$ kubectl apply -f nginx-bad.yaml -n demo
Error from server (Forbidden): error when creating "nginx-bad.yaml": pods "nginx-bad" is forbidden: maximum memory usage per Container is 512Mi, but limit is 800M
```

如果 LimitRanger 指定了 CPU 或内存，所有的 pod 和容器都应该有 CPU 或内存的请求或限制。LimitRanger 在 API 服务器接收到创建或更新对象的请求时起作用，但在运行时不起作用。如果一个 pod 在限制被应用之前就违反了限制，它将继续运行。理想情况下，限制应该在命名空间创建时应用。

现在我们已经看了一些可以用于积极资源管理的功能，我们转而看一些可以帮助我们监控集群并在事态恶化之前通知我们的工具。

# 监控 Kubernetes 资源

正如我们之前讨论的，资源监控是确保集群中服务可用性的重要步骤。资源监控可以发现集群中服务不可用的早期迹象或症状。资源监控通常与警报管理相结合，以确保利益相关者在观察到集群中出现任何问题或与任何问题相关的症状时尽快收到通知。

在这一部分，我们首先看一些由 Kubernetes 提供的内置监视器，包括 Kubernetes Dashboard 和 Metrics Server。我们将看看如何设置它，并讨论如何有效地使用这些工具。接下来，我们将看一些可以插入到您的 Kubernetes 集群中并提供比内置工具更深入的洞察力的开源工具。

## 内置监视器

让我们来看一些由 Kubernetes 提供的用于监控 Kubernetes 资源和对象的工具 - Metrics Server 和 Kubernetes Dashboard。

### Kubernetes Dashboard

Kubernetes Dashboard 为集群管理员提供了一个 Web UI，用于创建、管理和监控集群对象和资源。集群管理员还可以使用仪表板创建 pod、服务和 DaemonSets。仪表板显示了集群的状态和集群中的任何错误。

Kubernetes 仪表板提供了集群管理员在集群中管理资源和对象所需的所有功能。鉴于仪表板的功能，应该将对仪表板的访问限制在集群管理员范围内。从 v1.7.0 版本开始，仪表板具有登录功能。2018 年，仪表板中发现了一个特权升级漏洞（CVE-2018-18264），允许未经身份验证的用户登录到仪表板。对于这个问题，尚无已知的野外利用，但这个简单的漏洞可能会对许多 Kubernetes 发行版造成严重破坏。

当前的登录功能允许使用服务账户和 `kubeconfig` 登录。建议使用服务账户令牌来访问 Kubernetes 仪表板：

![图 10.1 – Kubernetes 仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_10_001.jpg)

图 10.1 – Kubernetes 仪表板

为了允许服务账户使用 Kubernetes 仪表板，您需要将 `cluster-admin` 角色添加到服务账户中。让我们看一个示例，说明如何使用服务账户来访问 Kubernetes 仪表板：

1.  在默认命名空间中创建一个服务账户：

```
$kubectl create serviceaccount dashboard-admin-sa
```

1.  将 `cluster-admin` 角色与服务账户关联：

```
$kubectl create clusterrolebinding dashboard-admin-sa --clusterrole=cluster-admin --serviceaccount=default:dashboard-admin-sa
```

1.  获取服务账户的令牌：

```
$ kubectl describe serviceaccount dashboard-admin-sa
Name:                dashboard-admin-sa
Namespace:           default
Labels:              <none>
Annotations:         <none>
Image pull secrets:  <none>
Mountable secrets:   dashboard-admin-sa-token-5zwpw
Tokens:              dashboard-admin-sa-token-5zwpw
Events:              <none>
```

1.  使用以下命令获取服务账户的令牌：

```
$ kubectl describe secrets dashboard-admin-sa-token-5zwpw
Name:         dashboard-admin-sa-token-5zwpw
Namespace:    default
Labels:       <none>
Annotations:  kubernetes.io/service-account.name: dashboard-admin-sa
              kubernetes.io/service-account.uid: 83218a92-915c-11ea-b763-42010a800022
Type:  kubernetes.io/service-account-token
Data
====
ca.crt:     1119 bytes
namespace:  7 bytes
token:      <token>
```

1.  使用服务账户令牌登录到仪表板：

![图 10.2 – Kubernetes 仪表板登录](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_10_002.jpg)

图 10.2 – Kubernetes 仪表板登录

使用 Kubernetes 仪表板，管理员可以了解资源可用性、资源分配、Kubernetes 对象和事件日志：

![图 10.3 – Kubernetes 仪表板 – 资源分配](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_10_003.jpg)

图 10.3 – Kubernetes 仪表板 – 资源分配

上述截图显示了节点上资源请求和限制的资源分配情况。以下截图突出显示了 Kubernetes 仪表板上节点的事件：

![图 10.4 – Kubernetes 仪表板 – 事件日志](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_10_004.jpg)

图 10.4 – Kubernetes 仪表板 – 事件日志

Kubernetes 仪表板作为一个容器在主节点上运行。您可以通过枚举主节点上的 Docker 容器来查看这一点：

```
$ docker ps | grep dashboard
a963e6e6a54b        3b08661dc379           "/metrics-sidecar"       4 minutes ago       Up 4 minutes                            k8s_dashboard-metrics-scraper_dashboard-metrics-scraper-84bfdf55ff-wfxdm_kubernetes-dashboard_5a7ef2a8-b3b4-4e4c-ae85-11cc8b61c1c1_0
c28f0e2799c1        cdc71b5a8a0e           "/dashboard --insecu…"   4 minutes ago       Up 4 minutes                            k8s_kubernetes-dashboard_kubernetes-dashboard-bc446cc64-czmn8_kubernetes-dashboard_40630c71-3c6a-447b-ae68-e23603686ede_0
10f0b024a13f        k8s.gcr.io/pause:3.2   "/pause"                 4 minutes ago       Up 4 minutes                            k8s_POD_dashboard-metrics-scraper-84bfdf55ff-wfxdm_kubernetes-dashboard_5a7ef2a8-b3b4-4e4c-ae85-11cc8b61c1c1_0
f9c1e82174d8        k8s.gcr.io/pause:3.2   "/pause"                 4 minutes ago       Up 4 minutes                            k8s_POD_kubernetes-dashboard-bc446cc64-czmn8_kubernetes-dashboard_40630c71-3c6a-447b-ae68-e23603686ede_0
```

仪表板进程在主节点上以一组参数运行：

```
$ ps aux | grep dashboard
dbus     10727  0.9  1.1 136752 46240 ?        Ssl  05:46   0:02 /dashboard --insecure-bind-address=0.0.0.0 --bind-address=0.0.0.0 --namespace=kubernetes-dashboard --enable-skip-login --disable-settings-authorizer
docker   11889  0.0  0.0  11408   556 pts/0    S+   05:51   0:00 grep dashboard
```

确保仪表板容器使用以下参数运行：

+   **禁用不安全端口**：`--insecure-port`允许 Kubernetes 仪表板接收 HTTP 请求。确保在生产环境中禁用它。

+   **禁用不安全的地址**：应禁用`--insecure-bind-address`，以避免 Kubernetes 仪表板可以通过 HTTP 访问的情况。

+   **将地址绑定到本地主机**：`--bind-address`应设置为`127.0.0.1`，以防止主机通过互联网连接。

+   **启用 TLS**：使用`tls-cert-file`和`tls-key-file`来通过安全通道访问仪表板。

+   **确保启用令牌身份验证模式**：可以使用`--authentication-mode`标志指定身份验证模式。默认情况下，它设置为`token`。确保仪表板不使用基本身份验证。

+   **禁用不安全登录**：当仪表板可以通过 HTTP 访问时，会使用不安全登录。这应该默认禁用。

+   **禁用跳过登录**：跳过登录允许未经身份验证的用户访问 Kubernetes 仪表板。`--enable-skip-login`启用跳过登录；这在生产环境中不应存在。

+   **禁用设置授权器**：`--disable-settings-authorizer`允许未经身份验证的用户访问设置页面。在生产环境中应禁用此功能。

### Metrics Server

Metrics Server 使用每个节点上的`kubelet`公开的摘要 API 聚合集群使用数据。它使用`kube-aggregator`在`kube-apiserver`上注册。Metrics Server 通过 Metrics API 公开收集的指标，这些指标被水平 Pod 自动缩放器和垂直 Pod 自动缩放器使用。用于调试集群的`kubectl top`也使用 Metrics API。Metrics Server 特别设计用于自动缩放。

在某些 Kubernetes 发行版上，默认情况下启用了 Metrics Server。您可以使用以下命令在`minikube`上启用它：

```
$ minikube addons enable metrics-server
```

您可以使用以下命令检查 Metrics Server 是否已启用：

```
$ kubectl get apiservices | grep metrics
v1beta1.metrics.k8s.io                 kube-system/metrics-server   True        7m17s
```

启用 Metrics Server 后，需要一些时间来查询摘要 API 并关联数据。您可以使用`kubectl top node`来查看当前的指标：

```
$ kubectl top node
NAME       CPU(cores)   CPU%   MEMORY(bytes)   MEMORY%
minikube   156m         7%     1140Mi          30%
$ kubectl top pod
NAME         CPU(cores)   MEMORY(bytes)
nginx-good   0m           2Mi
```

与其他服务和组件类似，Metrics Server 也有配置参数。在生产集群中，请确保 Metrics Server 不使用`--kubelet-insecure-tls`标志，该标志允许 Metrics Server 跳过 CA 对证书的验证。

## 第三方监控工具

第三方监控工具集成到 Kubernetes 中，提供了更多功能和对 Kubernetes 资源健康的洞察。在本节中，我们将讨论 Prometheus 和 Grafana，它们是开源社区中最流行的监控工具。

## Prometheus 和 Grafana

Prometheus 是由 SoundCloud 开发并被 CNCF 采用的开源仪表和数据收集框架。Prometheus 可以用来查看不同数据点的时间序列数据。Prometheus 使用拉取系统。它发送一个称为抓取的 HTTP 请求，从系统组件（包括 API 服务器、`node-exporter`和`kubelet`）获取数据。抓取的响应和指标存储在 Prometheus 服务器上的自定义数据库中。

让我们看看如何设置 Prometheus 来监视 Kubernetes 中的一个命名空间：

1.  创建一个命名空间：

```
$kubectl create namespace monitoring
```

1.  定义一个集群角色来读取 Kubernetes 对象，如 pods、nodes 和 services，并将角色绑定到一个服务账户。在这个例子中，我们使用默认的服务账户：

```
$ cat prometheus-role.yaml
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRole
metadata:
  name: prometheus
rules:
- apiGroups: [""]
  resources:
  - nodes
  - nodes/proxy
  - services
  - endpoints
  - pods
  verbs: ["get", "list", "watch"]
- apiGroups:
  - extensions
  resources:
  - ingresses
  verbs: ["get", "list", "watch"]
- nonResourceURLs: ["/metrics"]
  verbs: ["get"]
$ kubectl create -f prometheus-role.yaml
clusterrole.rbac.authorization.k8s.io/prometheus created
```

现在，我们创建一个角色绑定，将角色与默认服务账户关联起来：

```
$ cat prometheus-rolebinding.yaml
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: prometheus
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: prometheus
subjects:
- kind: ServiceAccount
  name: default
  namespace: monitoring
```

1.  Prometheus 使用 ConfigMap 来指定抓取规则。以下规则抓取`kube-apiserver`。可以定义多个抓取来获取指标：

```
$ cat config_prometheus.yaml apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-server-conf
  labels:
    name: prometheus-server-conf
  namespace: monitoring
data:
  prometheus.yml: |-
    global:
      scrape_interval: 5s
      evaluation_interval: 5s
  scrape_configs:    - job_name: 'kubernetes-apiservers'
      kubernetes_sd_configs:
      - role: endpoints
      scheme: https
      tls_config:
        ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
      bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
      relabel_configs:
      - source_labels: [__meta_kubernetes_namespace, __meta_kubernetes_service_name, __meta_kubernetes_endpoint_port_name]
        action: keep
        regex: default;kubernetes;https
```

1.  为 Prometheus 创建一个部署：

```
spec:
      containers:
        - name: prometheus
          image: prom/prometheus:v2.12.0
          args:
            - "--config.file=/etc/prometheus/prometheus.yml"
            - "--storage.tsdb.path=/prometheus/"
          ports:
            - containerPort: 9090
          volumeMounts:
            - name: prometheus-config-volume
              mountPath: /etc/prometheus/
            - name: prometheus-storage-volume
              mountPath: /prometheus/
      volumes:
        - name: prometheus-config-volume
          configMap:
            defaultMode: 420
            name: prometheus-server-conf
        - name: prometheus-storage-volume
          emptyDir: {}
```

1.  部署成功后，可以使用端口转发或 Kubernetes 服务来访问仪表板：

```
$ kubectl port-forward <prometheus-pod> 8080:9090 -n monitoring
```

这样可以为 Prometheus pod 启用端口转发。现在，您可以使用端口`8080`上的集群 IP 来访问它：

![图 10.5 – Prometheus 仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_10_005.jpg)

图 10.5 – Prometheus 仪表板

查询可以输入为表达式，并查看结果为**图形**或**控制台**消息。使用 Prometheus 查询，集群管理员可以查看由 Prometheus 监视的集群、节点和服务的状态。

让我们看一些对集群管理员有帮助的 Prometheus 查询的例子：

+   Kubernetes CPU 使用率：

```
sum(rate(container_cpu_usage_seconds_total{container_name!="POD",pod_name!=""}[5m]))
```

+   Kubernetes 命名空间的 CPU 使用率：

```
sum(rate(container_cpu_usage_seconds_total{container_name!="POD",namespace!=""}[5m])) by (namespace)
```

+   按 pod 的 CPU 请求：

```
sum(kube_pod_container_resource_requests_cpu_cores) by (pod)
```

让我们看一下演示集群的命名空间的 CPU 使用率：

![图 10.6 – 命名空间的 CPU 使用率](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_10_006.jpg)

图 10.6 – 命名空间的 CPU 使用率

Prometheus 还允许集群管理员使用 ConfigMaps 设置警报：

```
prometheus.rules: |-
    groups:
    - name: Demo Alert
      rules:
      - alert: High Pod Memory
        expr: sum(container_memory_usage_bytes{pod!=""})  by (pod) > 1000000000
        for: 1m
        labels:
          severity: high
        annotations:
          summary: High Memory Usage
```

当容器内存使用大于`1000` MB 并持续`1`分钟时，此警报将触发一个带有`high`严重性标签的警报：

![图 10.7 – Prometheus 警报](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_10_007_New.jpg)

图 10.7 – Prometheus 警报

使用`Alertmanager`与 Prometheus 有助于对来自诸如 Prometheus 的应用程序的警报进行去重、分组和路由，并将其路由到集成客户端，包括电子邮件、OpsGenie 和 PagerDuty。

Prometheus 与其他增强数据可视化和警报管理的第三方工具很好地集成。Grafana 就是这样的工具。Grafana 允许对从 Prometheus 检索的数据进行可视化、查询和警报。

现在让我们看看如何使用 Prometheus 设置 Grafana：

1.  Grafana 需要一个数据源进行摄入；在本例中，它是 Prometheus。数据源可以使用 UI 添加，也可以使用 ConfigMap 指定：

```
$ cat grafana-data.yaml                                   apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-datasources
  namespace: monitoring
data:
  prometheus.yaml: |-
    {
        "apiVersion": 1,
        "datasources": [
            {
               "access":"proxy",
                "editable": true,
                "name": "prometheus",
                "orgId": 1,
                "type": "prometheus",
                "url": "http://192.168.99.128:30000",
                "version": 1
            }
        ]
    }
```

1.  为 Grafana 创建一个部署：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: grafana
  template:
    metadata:
      name: grafana
      labels:
        app: grafana
    spec:
      containers:
      - name: grafana
        image: grafana/grafana:latest
        ports:
        - name: grafana
          containerPort: 3000
        volumeMounts:
          - mountPath: /var/lib/grafana
            name: grafana-storage
          - mountPath: /etc/grafana/provisioning/datasources
            name: grafana-datasources
            readOnly: false
      volumes:
        - name: grafana-storage
          emptyDir: {}
        - name: grafana-datasources
          configMap:
              name: grafana-datasources
```

1.  然后可以使用端口转发或 Kubernetes 服务来访问仪表板：

```
apiVersion: v1
kind: Service
metadata:
  name: grafana
  namespace: monitoring
  annotations:
      prometheus.io/scrape: 'true'
      prometheus.io/port:   '3000'
spec:
  selector:
    app: grafana
  type: NodePort
  ports:
    - port: 3000
      targetPort: 3000
      nodePort: 32000
```

1.  默认情况下，仪表板的用户名和密码为`admin`。登录后，您可以设置一个新的仪表板，或者从 Grafana 导入一个仪表板。要导入一个仪表板，您可以点击**+ > 导入**，然后会出现以下屏幕。在第一个文本框中输入`315`，以从 Grafana 导入仪表板 315：![图 10.8 – 在 Grafana 中导入仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_10_009.jpg)

图 10.8 – 在 Grafana 中导入仪表板

1.  这个仪表板是由 Instrumentisto 团队创建的。导入时，下一个屏幕上的所有字段将自动填充：![图 10.9 – Grafana 仪表板 – 315](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_10_010.jpg)

图 10.9 – Grafana 仪表板 – 315

1.  也可以使用自定义的 Prometheus 查询创建一个新的仪表板：![图 10.10 – 自定义仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_10_011.jpg)

图 10.10 – 自定义仪表板

1.  与 Prometheus 类似，您可以在每个仪表板上设置警报：

![图 10.11 – Grafana 中的新警报](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_10_012.jpg)

图 10.11 – Grafana 中的新警报

还有其他与 Prometheus 集成的工具，使其成为 DevOps 和集群管理员的宝贵工具。

# 总结

在本章中，我们讨论了可用性作为 CIA 三要素的重要组成部分。我们从安全的角度讨论了资源管理和实时资源监控的重要性。然后，我们介绍了资源请求和限制，这是 Kubernetes 资源管理的核心概念。接下来，我们讨论了资源管理以及集群管理员如何积极确保 Kubernetes 对象不会表现不端。

我们深入研究了命名空间资源配额和限制范围的细节，并看了如何设置它的示例。然后我们转向资源监控。我们看了一些作为 Kubernetes 一部分提供的内置监视器，包括 Dashboard 和 Metrics Server。最后，我们看了一些第三方工具 - Prometheus 和 Grafana - 这些工具更强大，大多数集群管理员和 DevOps 工程师更喜欢使用。

通过资源管理，集群管理员可以确保 Kubernetes 集群中的服务有足够的资源可用于运行，并且恶意或行为不端的实体不会独占所有资源。另一方面，资源监控有助于实时识别问题和症状。与资源监控一起使用的警报管理可以在发生问题时通知利益相关者，例如磁盘空间不足或内存消耗过高，从而确保停机时间最小化。

在下一章中，我们将详细讨论深度防御。我们将看看集群管理员和 DevOps 工程师如何通过分层安全配置、资源管理和资源监控来增强安全性。深度防御将引入更多的工具包，以确保在生产环境中可以轻松检测和减轻攻击。

# 问题

1.  资源请求和限制之间有什么区别？

1.  定义一个将内存限制限制为 500 mi 的资源配额。

1.  限制范围与资源配额有何不同？

1.  Kubernetes Dashboard 的推荐认证方法是什么？

1.  哪个是最广泛推荐的资源监控工具？

# 更多参考资料

您可以参考以下链接，了解本章涵盖的主题的更多信息：

+   电力系统的拒绝服务攻击：[`www.cnbc.com/2019/05/02/ddos-attack-caused-interruptions-in-power-system-operations-doe.html`](https://www.cnbc.com/2019/05/02/ddos-attack-caused-interruptions-in-power-system-operations-doe.html)

+   亚马逊 Route53 DDoS：[`www.cpomagazine.com/cyber-security/ddos-attack-on-amazon-web-services-raises-cloud-safety-concerns/`](https://www.cpomagazine.com/cyber-security/ddos-attack-on-amazon-web-services-raises-cloud-safety-concerns/)

+   Limit Ranger 设计文档: [`github.com/kubernetes/community/blob/master/contributors/design-proposals/resource-management/admission_control_limit_range.md`](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/resource-management/admission_control_limit_range.md)

+   Kubernetes Dashboard: [`github.com/kubernetes/dashboard/blob/master/docs/README.md`](https://github.com/kubernetes/dashboard/blob/master/docs/README.md)

+   使用 Kubernetes Dashboard 进行特权升级: [`sysdig.com/blog/privilege-escalation-kubernetes-dashboard/`](https://sysdig.com/blog/privilege-escalation-kubernetes-dashboard/)

+   Metrics Server: [`github.com/kubernetes-sigs/metrics-server`](https://github.com/kubernetes-sigs/metrics-server)

+   聚合 API 服务器: [`github.com/kubernetes/community/blob/master/contributors/design-proposals/api-machinery/aggregated-api-servers.md`](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/api-machinery/aggregated-api-servers.md)

+   Prometheus 查询: [`prometheus.io/docs/prometheus/latest/querying/examples/`](https://prometheus.io/docs/prometheus/latest/querying/examples/)

+   Grafana 文档: [`grafana.com/docs/grafana/latest/`](https://grafana.com/docs/grafana/latest/)
