# Kubernetes 云原生指南（四）

> 原文：[`zh.annas-archive.org/md5/58DD843CC49B42503E619A37722EEB6C`](https://zh.annas-archive.org/md5/58DD843CC49B42503E619A37722EEB6C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：Kubernetes 安全性和合规性

在本章中，您将了解一些关键的 Kubernetes 安全性要点。我们将讨论一些最近的 Kubernetes 安全问题，以及对 Kubernetes 进行的最近审计的发现。然后，我们将从我们集群的每个级别开始实施安全性，从 Kubernetes 资源及其配置的安全性开始，然后是容器安全，最后是入侵检测的运行时安全。首先，我们将讨论一些与 Kubernetes 相关的关键安全概念。

在本章中，我们将涵盖以下主题：

+   了解 Kubernetes 上的安全性

+   审查 Kubernetes 的 CVE 和安全审计

+   实施集群配置和容器安全的工具

+   处理 Kubernetes 上的入侵检测、运行时安全性和合规性

# 技术要求

为了运行本章详细介绍的命令，您需要一台支持`kubectl`命令行工具的计算机，以及一个正常运行的 Kubernetes 集群。请参阅*第一章*，*与 Kubernetes 通信*，了解快速启动 Kubernetes 的几种方法，以及如何安装`kubectl`工具的说明。

此外，您还需要一台支持 Helm CLI 工具的机器，通常具有与`kubectl`相同的先决条件-有关详细信息，请查看 Helm 文档[`helm.sh/docs/intro/install/`](https://helm.sh/docs/intro/install/)。

本章中使用的代码可以在书籍的 GitHub 存储库中找到[`github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter12`](https://github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter12)。

# 了解 Kubernetes 上的安全性

在讨论 Kubernetes 上的安全性时，非常重要的是要注意安全边界和共享责任。*共享责任模型*是一个常用术语，用于描述公共云服务中的安全处理方式。它指出客户对其应用程序的安全性以及公共云组件和服务的配置的安全性负责。另一方面，公共云提供商负责服务本身的安全性以及其运行的基础设施，一直到数据中心和物理层。

同样，Kubernetes 的安全性是共享的。尽管上游 Kubernetes 不是商业产品，但成千上万的 Kubernetes 贡献者和来自大型科技公司的重要组织力量确保了 Kubernetes 组件的安全性得到维护。此外，大量的个人贡献者和使用该技术的公司构成了庞大的生态系统，确保了在 CVE 报告和处理时的改进。不幸的是，正如我们将在下一节讨论的那样，Kubernetes 的复杂性意味着存在许多可能的攻击向量。

因此，作为开发人员，根据共享责任模型，你需要负责配置 Kubernetes 组件的安全性，你在 Kubernetes 上运行的应用程序的安全性，以及集群配置中的访问级别安全性。虽然你的应用程序和容器本身的安全性不在本书的范围内，但它们对 Kubernetes 的安全性绝对重要。我们将花大部分时间讨论配置级别的安全性，访问安全性和运行时安全性。

Kubernetes 本身或 Kubernetes 生态系统提供了工具、库和完整的产品来处理这些级别的安全性 - 我们将在本章中审查其中一些选项。

现在，在我们讨论这些解决方案之前，最好先从为什么可能需要它们的基本理解开始。让我们继续下一节，我们将详细介绍 Kubernetes 在安全领域遇到的一些问题。

# 审查 Kubernetes 的 CVE 和安全审计

Kubernetes 在其悠久历史中遇到了几个**通用漏洞和暴露**（**CVEs**）。在撰写本文时，MITRE CVE 数据库在搜索`kubernetes`时列出了 2015 年至 2020 年间的 73 个 CVE 公告。其中每一个要么直接与 Kubernetes 相关，要么与在 Kubernetes 上运行的常见开源解决方案相关（例如 NGINX 入口控制器）。

其中一些攻击向量足够严重，需要对 Kubernetes 源代码进行热修复，因此它们在 CVE 描述中列出了受影响的版本。关于 Kubernetes 相关的所有 CVE 的完整列表可以在[`cve.mitre.org/cgi-bin/cvekey.cgi?keyword=kubernetes`](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=kubernetes)找到。为了让你了解一些已经发现的问题，让我们按时间顺序回顾一些这些 CVE。

## 了解 CVE-2016-1905 – 不正确的准入控制

这个 CVE 是生产 Kubernetes 中的第一个重大安全问题。国家漏洞数据库（NIST 网站）给出了这个问题的基础评分为 7.7，将其归类为高影响类别。

通过这个问题，Kubernetes 准入控制器不会确保`kubectl patch`命令遵循准入规则，允许用户完全绕过准入控制器 - 在多租户场景中是一场噩梦。

## 了解 CVE-2018-1002105 – 连接升级到后端

这个 CVE 很可能是迄今为止 Kubernetes 项目中最关键的。事实上，NVD 给出了它 9.8 的严重性评分！在这个 CVE 中，发现在某些版本的 Kubernetes 中，可以利用 Kubernetes API 服务器的错误响应进行连接升级。一旦连接升级，就可以向集群中的任何后端服务器发送经过身份验证的请求。这允许恶意用户在没有适当凭据的情况下模拟完全经过身份验证的 TLS 请求。

除了这些 CVE（很可能部分受它们驱动），CNCF 在 2019 年赞助了 Kubernetes 的第三方安全审计。审计的结果是开源的，公开可用，值得一看。

## 了解 2019 年安全审计结果

正如我们在前一节中提到的，2019 年 Kubernetes 安全审计是由第三方进行的，审计结果完全是开源的。所有部分的完整审计报告可以在[`www.cncf.io/blog/2019/08/06/open-sourcing-the-kubernetes-security-audit/`](https://www.cncf.io/blog/2019/08/06/open-sourcing-the-kubernetes-security-audit/)找到。

总的来说，这次审计关注了以下 Kubernetes 功能的部分：

+   `kube-apiserver`

+   `etcd`

+   `kube-scheduler`

+   `kube-controller-manager`

+   `cloud-controller-manager`

+   `kubelet`

+   `kube-proxy`

+   容器运行时

意图是在涉及安全性时专注于 Kubernetes 最重要和相关的部分。审计的结果不仅包括完整的安全报告，还包括威胁模型和渗透测试，以及白皮书。

深入了解审计结果不在本书的范围内，但有一些重要的收获是对许多最大的 Kubernetes 安全问题的核心有很好的了解。

简而言之，审计发现，由于 Kubernetes 是一个复杂的、高度网络化的系统，具有许多不同的设置，因此有许多可能的配置，经验不足的工程师可能会执行，并在这样做的过程中，打开他们的集群给外部攻击者。

Kubernetes 的这个想法足够复杂，以至于不安全的配置很容易发生，这一点很重要，需要注意和牢记。

整个审计值得一读-对于那些具有重要的网络安全和容器知识的人来说，这是对 Kubernetes 作为平台开发过程中所做的一些安全决策的极好的视角。

现在我们已经讨论了 Kubernetes 安全问题的发现位置，我们可以开始研究如何增加集群的安全姿态。让我们从一些默认的 Kubernetes 安全功能开始。

# 实施集群配置和容器安全的工具

Kubernetes 为我们提供了许多内置选项，用于集群配置和容器权限的安全性。由于我们已经讨论了 RBAC、TLS Ingress 和加密的 Kubernetes Secrets，让我们讨论一些我们还没有时间审查的概念：准入控制器、Pod 安全策略和网络策略。

## 使用准入控制器

准入控制器经常被忽视，但它是一个极其重要的 Kubernetes 功能。许多 Kubernetes 的高级功能都在幕后使用准入控制器。此外，您可以创建新的准入控制器规则，以添加自定义功能到您的集群中。

有两种一般类型的准入控制器：

+   变异准入控制器

+   验证准入控制器

变异准入控制器接受 Kubernetes 资源规范并返回更新后的资源规范。它们还执行副作用计算或进行外部调用（在自定义准入控制器的情况下）。

另一方面，验证准入控制器只是接受或拒绝 Kubernetes 资源 API 请求。重要的是要知道，这两种类型的控制器只对创建、更新、删除或代理请求进行操作。这些控制器不能改变或更改列出资源的请求。

当这些类型的请求进入 Kubernetes API 服务器时，它将首先通过所有相关的变异准入控制器运行请求。然后，输出（可能已经变异）将通过验证准入控制器，最后在 API 服务器中被执行（或者如果被准入控制器拒绝，则不会被执行）。

在结构上，Kubernetes 提供的准入控制器是作为 Kubernetes API 服务器的一部分运行的函数或“插件”。它们依赖于两个 webhook 控制器（它们本身就是准入控制器，只是特殊的准入控制器）：**MutatingAdmissionWebhook** 和 **ValidatingAdmissionWebhook**。所有其他准入控制器在底层都使用这两个 webhook 中的一个，具体取决于它们的类型。此外，您编写的任何自定义准入控制器都可以附加到这两个 webhook 中的任一个。

在我们看创建自定义准入控制器的过程之前，让我们回顾一下 Kubernetes 提供的一些默认准入控制器。有关完整列表，请查看 Kubernetes 官方文档 [`kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#what-does-each-admission-controller-do`](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#what-does-each-admission-controller-do)。

### 理解默认准入控制器

在典型的 Kubernetes 设置中有许多默认的准入控制器，其中许多对一些非常重要的基本功能是必需的。以下是一些默认准入控制器的示例。

#### **NamespaceExists** 准入控制器

**NamespaceExists** 准入控制器检查任何传入的 Kubernetes 资源（除了命名空间本身）。这是为了检查资源所附加的命名空间是否存在。如果不存在，它将在准入控制器级别拒绝资源请求。

#### PodSecurityPolicy 准入控制器

**PodSecurityPolicy** 准入控制器支持 Kubernetes Pod 安全策略，我们马上就会了解到。该控制器阻止不符合 Pod 安全策略的资源被创建。

除了默认准入控制器之外，我们还可以创建自定义准入控制器。

### 创建自定义准入控制器

可以使用两个 webhook 控制器之一动态地创建自定义准入控制器。其工作方式如下：

1.  您必须编写自己的服务器或脚本，以独立于 Kubernetes API 服务器运行。

1.  然后，您可以配置前面提到的两个 webhook 触发器之一，向您的自定义服务器控制器发送带有资源数据的请求。

1.  基于结果，webhook 控制器将告诉 API 服务器是否继续。

让我们从第一步开始：编写一个快速的准入服务器。

### 编写自定义准入控制器的服务器

为了创建我们的自定义准入控制器服务器（它将接受来自 Kubernetes 控制平面的 webhook），我们可以使用任何编程语言。与大多数对 Kubernetes 的扩展一样，Go 语言具有最好的支持和库，使编写自定义准入控制器更容易。现在，我们将使用一些伪代码。

我们的服务器的控制流将看起来像这样：

Admission-controller-server.pseudo

```
// This function is called when a request hits the
// "/mutate" endpoint
function acceptAdmissionWebhookRequest(req)
{
  // First, we need to validate the incoming req
  // This function will check if the request is formatted properly
  // and will add a "valid" attribute If so
  // The webhook will be a POST request from Kubernetes in the
  // "AdmissionReviewRequest" schema
  req = validateRequest(req);
  // If the request isn't valid, return an Error
  if(!req.valid) return Error; 
  // Next, we need to decide whether to accept or deny the Admission
  // Request. This function will add the "accepted" attribute
  req = decideAcceptOrDeny(req);
  if(!req.accepted) return Error;
  // Now that we know we want to allow this resource, we need to
  // decide if any "patches" or changes are necessary
  patch = patchResourceFromWebhook(req);
  // Finally, we create an AdmissionReviewResponse and pass it back
  // to Kubernetes in the response
  // This AdmissionReviewResponse includes the patches and
  // whether the resource is accepted.
  admitReviewResp = createAdmitReviewResp(req, patch);
  return admitReviewResp;
}
```

现在我们有了一个简单的服务器用于我们的自定义准入控制器，我们可以配置一个 Kubernetes 准入 webhook 来调用它。

### 配置 Kubernetes 调用自定义准入控制器服务器

为了告诉 Kubernetes 调用我们的自定义准入服务器，它需要一个地方来调用。我们可以在任何地方运行我们的自定义准入控制器 - 它不需要在 Kubernetes 上。

也就是说，出于本章的目的，在 Kubernetes 上运行它很容易。我们不会详细介绍清单，但让我们假设我们有一个 Service 和一个 Deployment 指向它，运行着我们的服务器的容器。Service 看起来会像这样：

Service-webhook.yaml

```
apiVersion: v1
kind: Service
metadata:
  name: my-custom-webhook-server
spec:
  selector:
    app: my-custom-webhook-server
  ports:
    - port: 443
      targetPort: 8443
```

重要的是要注意，我们的服务器需要使用 HTTPS，以便 Kubernetes 接受 webhook 响应。有许多配置的方法，我们不会在本书中详细介绍。证书可以是自签名的，但证书的通用名称和 CA 需要与设置 Kubernetes 集群时使用的名称匹配。

现在我们的服务器正在运行并接受 HTTPS 请求，让我们告诉 Kubernetes 在哪里找到它。为此，我们使用`MutatingWebhookConfiguration`。

下面的代码块显示了`MutatingWebhookConfiguration`的一个示例：

Mutating-webhook-config-service.yaml

```
apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingWebhookConfiguration
metadata:
  name: my-service-webhook
webhooks:
  - name: my-custom-webhook-server.default.svc
    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods", "deployments", "configmaps"]
    clientConfig:
      service:
        name: my-custom-webhook-server
        namespace: default
        path: "/mutate"
      caBundle: ${CA_PEM_B64}
```

让我们分解一下我们的`MutatingWebhookConfiguration`的 YAML。正如你所看到的，我们可以在这个配置中配置多个 webhook - 尽管在这个示例中我们只做了一个。

对于每个 webhook，我们设置`name`，`rules`和`configuration`。`name`只是 webhook 的标识符。`rules`允许我们精确配置 Kubernetes 应该在哪些情况下向我们的准入控制器发出请求。在这种情况下，我们已经配置了我们的 webhook，每当发生`pods`、`deployments`和`configmaps`类型资源的`CREATE`事件时触发。

最后，我们有`clientConfig`，在其中我们指定 Kubernetes 应该如何在哪里进行 webhook 请求。由于我们在 Kubernetes 上运行我们的自定义服务器，我们指定了服务名称，以及在我们的服务器上要命中的路径（`"/mutate"`在这里是最佳实践），以及要与 HTTPS 终止证书进行比较的集群 CA。如果您的自定义准入服务器在其他地方运行，还有其他可能的配置字段-如果需要，可以查看文档（[`kubernetes.io/docs/reference/access-authn-authz/admission-controllers/`](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)）。

一旦我们在 Kubernetes 中创建了`MutatingWebhookConfiguration`，就很容易测试验证。我们所需要做的就是像平常一样创建一个 Pod、Deployment 或 ConfigMap，并检查我们的请求是否根据服务器中的逻辑被拒绝或修补。

假设我们的服务器目前设置为拒绝任何包含字符串`deny-me`的 Pod。它还设置了在`AdmissionReviewResponse`中添加错误响应。

让我们使用以下的 Pod 规范：

To-deny-pod.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: my-pod-to-deny
spec:
  containers:
  - name: nginx
    image: nginx
```

现在，我们可以创建我们的 Pod 来检查准入控制器。我们可以使用以下命令：

```
kubectl create -f to-deny-pod.yaml
```

这导致以下输出：

```
Error from server (InternalError): error when creating "to-deny-pod.yaml": Internal error occurred: admission webhook "my-custom-webhook-server.default.svc" denied the request: Pod name contains "to-deny"!
```

就是这样！我们的自定义准入控制器成功拒绝了一个不符合我们在服务器中指定条件的 Pod。对于被修补（而不是被拒绝但被更改）的资源，`kubectl`不会显示任何特殊响应。您需要获取相关资源以查看修补的效果。

现在我们已经探讨了自定义准入控制器，让我们看看另一种实施集群安全实践的方法- Pod 安全策略。

## 启用 Pod 安全策略

Pod 安全策略的基本原则是允许集群管理员创建规则，Pod 必须遵循这些规则才能被调度到节点上。从技术上讲，Pod 安全策略只是另一种准入控制器。然而，这个功能得到了 Kubernetes 的官方支持，并值得深入讨论，因为有许多选项可用。

Pod 安全策略可用于防止 Pod 以 root 身份运行，限制端口和卷的使用，限制特权升级等等。我们现在将回顾一部分 Pod 安全策略的功能，但要查看完整的 Pod 安全策略配置类型列表，请查阅官方 PSP 文档[https://kubernetes.io/docs/concepts/policy/pod-security-policy/]。

最后，Kubernetes 还支持用于控制容器权限的低级原语 - 即*AppArmor*，*SELinux*和*Seccomp*。这些配置超出了本书的范围，但对于高度安全的环境可能会有用。

### 创建 Pod 安全策略的步骤

实施 Pod 安全策略有几个步骤：

1.  首先，必须启用 Pod 安全策略准入控制器。

1.  这将阻止在您的集群中创建所有 Pod，因为它需要匹配的 Pod 安全策略和角色才能创建 Pod。出于这个原因，您可能希望在启用准入控制器之前创建您的 Pod 安全策略和角色。

1.  启用准入控制器后，必须创建策略本身。

1.  然后，必须创建具有对 Pod 安全策略访问权限的`Role`或`ClusterRole`对象。

1.  最后，该角色可以与**ClusterRoleBinding**或**RoleBinding**绑定到用户或服务`accountService`帐户，允许使用该服务帐户创建的 Pod 使用 Pod 安全策略可用的权限。

在某些情况下，您的集群可能默认未启用 Pod 安全策略准入控制器。让我们看看如何启用它。

### 启用 Pod 安全策略准入控制器

为了启用 PSP 准入控制器，`kube-apiserver`必须使用指定准入控制器的标志启动。在托管的 Kubernetes（EKS、AKS 等）上，PSP 准入控制器可能会默认启用，并且为初始管理员用户创建一个特权 Pod 安全策略。这可以防止 PSP 在新集群中创建 Pod 时出现任何问题。

如果您正在自行管理 Kubernetes，并且尚未启用 PSP 准入控制器，您可以通过使用以下标志重新启动`kube-apiserver`组件来启用它：

```
kube-apiserver --enable-admission-plugins=PodSecurityPolicy,ServiceAccount…<all other desired admission controllers>
```

如果您的 Kubernetes API 服务器是使用`systemd`文件运行的（如果遵循*Kubernetes：困难的方式*，它将是这样），则应该在那里更新标志。通常，`systemd`文件放置在`/etc/systemd/system/`文件夹中。

为了找出已经启用了哪些准入插件，您可以运行以下命令：

```
kube-apiserver -h | grep enable-admission-plugins
```

此命令将显示已启用的准入插件的长列表。例如，您将在输出中看到以下准入插件：

```
NamespaceLifecycle, LimitRanger, ServiceAccount…
```

现在我们确定了 PSP 准入控制器已启用，我们实际上可以创建 PSP 了。

### 创建 PSP 资源

Pod 安全策略本身可以使用典型的 Kubernetes 资源 YAML 创建。以下是一个特权 Pod 安全策略的 YAML 文件：

Privileged-psp.yaml

```
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged-psp
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  privileged: true
  allowedCapabilities:
  - '*'
  volumes:
  - '*'
  hostNetwork: true
  hostPorts:
  - min: 2000
    max: 65535
  hostIPC: true
  hostPID: true
  allowPrivilegeEscalation: true
  runAsUser:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```

此 Pod 安全策略允许用户或服务账户（通过**RoleBinding**或**ClusterRoleBinding**）创建具有特权功能的 Pod。例如，使用此`PodSecurityPolicy`的 Pod 将能够绑定到主机网络的端口`2000`-`65535`，以任何用户身份运行，并绑定到任何卷类型。此外，我们还有一个关于`allowedProfileNames`的`seccomp`限制的注释-这可以让您了解`Seccomp`和`AppArmor`注释与`PodSecurityPolicies`的工作原理。

正如我们之前提到的，仅仅创建 PSP 是没有任何作用的。对于将创建特权 Pod 的任何服务账户或用户，我们需要通过**Role**和**RoleBinding**（或`ClusterRole`和`ClusterRoleBinding`）为他们提供对 Pod 安全策略的访问权限。

为了创建具有对此 PSP 访问权限的`ClusterRole`，我们可以使用以下 YAML：

Privileged-clusterrole.yaml

```
apiVersion: rbac.authorization.k8s.io
kind: ClusterRole
metadata:
  name: privileged-role
rules:
- apiGroups: ['policy']
  resources: ['podsecuritypolicies']
  verbs:     ['use']
  resourceNames:
  - privileged-psp
```

现在，我们可以将新创建的`ClusterRole`绑定到我们打算创建特权 Pod 的用户或服务账户上。让我们使用`ClusterRoleBinding`来做到这一点：

Privileged-clusterrolebinding.yaml

```
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: privileged-crb
roleRef:
  kind: ClusterRole
  name: privileged-role
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: Group
  apiGroup: rbac.authorization.k8s.io
  name: system:authenticated
```

在我们的情况下，我们希望让集群上的每个经过身份验证的用户都能创建特权 Pod，因此我们绑定到`system:authenticated`组。

现在，我们可能不希望所有用户或 Pod 都具有特权。一个更现实的 Pod 安全策略会限制 Pod 的能力。

让我们看一下具有这些限制的 PSP 的一些示例 YAML：

unprivileged-psp.yaml

```
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: unprivileged-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  readOnlyRootFilesystem: false
```

正如您所看到的，这个 Pod 安全策略在其对创建的 Pod 施加的限制方面大不相同。在此策略下，不允许任何 Pod 以 root 身份运行或升级为 root。它们还对它们可以绑定的卷的类型有限制（在前面的代码片段中已经突出显示了这一部分）-它们不能使用主机网络或直接绑定到主机端口。

在这个 YAML 中，`runAsUser`和`supplementalGroups`部分都控制可以运行或由容器添加的 Linux 用户 ID 和组 ID，而`fsGroup`键控制容器可以使用的文件系统组。

除了使用诸如`MustRunAsNonRoot`之类的规则，还可以直接指定容器可以使用的用户 ID - 任何未在其规范中明确使用该 ID 运行的 Pod 将无法调度到节点上。

要查看限制用户特定 ID 的示例 PSP，请查看以下 YAML：

Specific-user-id-psp.yaml

```
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: specific-user-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 3000
  readOnlyRootFilesystem: false
```

应用此 Pod 安全策略后，将阻止任何以用户 ID`0`或`3001`或更高的身份运行的 Pod。为了创建一个满足这个条件的 Pod，我们在 Pod 规范的`securityContext`中使用`runAs`选项。

这是一个满足这一约束的示例 Pod，即使有了这个 Pod 安全策略，它也可以成功调度：

Specific-user-pod.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: specific-user-pod
spec:
  securityContext:
    runAsUser: 1000
  containers:
  - name: test
    image: busybox
    securityContext:
      allowPrivilegeEscalation: false
```

正如您在这个 YAML 中看到的，我们为我们的 Pod 指定了一个特定的用户 ID`1000`来运行。我们还禁止我们的 Pod 升级为 root。即使`specific-user-psp`已经生效，这个 Pod 规范也可以成功调度。

现在我们已经讨论了 Pod 安全策略如何通过对 Pod 运行方式施加限制来保护 Kubernetes，我们可以转向网络策略，我们可以限制 Pod 的网络。

## 使用网络策略

Kubernetes 中的网络策略类似于防火墙规则或路由表。它们允许用户通过选择器指定一组 Pod，然后确定这些 Pod 可以如何以及在哪里进行通信。

为了使网络策略工作，您选择的 Kubernetes 网络插件（如*Weave*、*Flannel*或*Calico*）必须支持网络策略规范。网络策略可以像其他 Kubernetes 资源一样通过一个 YAML 文件创建。让我们从一个非常简单的网络策略开始。

这是一个限制访问具有标签`app=server`的 Pod 的网络策略规范。

Label-restriction-policy.yaml

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-network-policy
spec:
  podSelector:
    matchLabels:
      app: server
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 80
```

现在，让我们逐步解析这个网络策略的 YAML，因为这将帮助我们解释随着我们的进展一些更复杂的网络策略。

首先，在我们的规范中，我们有一个`podSelector`，它在功能上类似于节点选择器。在这里，我们使用`matchLabels`来指定这个网络策略只会影响具有标签`app=server`的 Pod。

接下来，我们为我们的网络策略指定一个策略类型。有两种策略类型：`ingress`和`egress`。一个网络策略可以指定一个或两种类型。`ingress`指的是制定适用于连接到匹配的 Pod 的网络规则，而`egress`指的是制定适用于离开匹配的 Pod 的连接的网络规则。

在这个特定的网络策略中，我们只是规定了一个单一的`ingress`规则：只有来自具有标签`app=server`的 Pod 的流量才会被接受，这些流量是源自具有标签`app:frontend`的 Pod。此外，唯一接受具有标签`app=server`的 Pod 上的流量的端口是`80`。

在`ingress`策略集中可以有多个`from`块对应多个流量规则。同样，在`egress`中也可以有多个`to`块。

重要的是要注意，网络策略是按命名空间工作的。默认情况下，如果在命名空间中没有单个网络策略，那么在该命名空间中的 Pod 之间的通信就没有任何限制。然而，一旦一个特定的 Pod 被单个网络策略选中，所有到该 Pod 的流量和从该 Pod 出去的流量都必须明确匹配一个网络策略规则。如果不匹配规则，它将被阻止。

有了这个想法，我们可以轻松地创建强制执行广泛限制的 Pod 网络策略。让我们来看看以下网络策略：

Full-restriction-policy.yaml

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: full-restriction-policy
  namespace: development
spec:
  policyTypes:
  - Ingress
  - Egress
  podSelector: {}
```

在这个`NetworkPolicy`中，我们指定我们将包括`Ingress`和`Egress`策略，但我们没有为它们写一个块。这样做的效果是自动拒绝任何`Egress`和`Ingress`的流量，因为没有规则可以匹配流量。

另外，我们的`{}` Pod 选择器值对应于选择命名空间中的每个 Pod。这条规则的最终结果是，`development`命名空间中的每个 Pod 将无法接受入口流量或发送出口流量。

重要提示

还需要注意的是，网络策略是通过结合影响 Pod 的所有单独的网络策略，然后将所有这些规则的组合应用于 Pod 流量来解释的。

这意味着，即使在我们先前的示例中限制了`development`命名空间中的所有入口和出口流量，我们仍然可以通过添加另一个网络策略来为特定的 Pod 启用它。

假设现在我们的`development`命名空间对 Pod 有完全的流量限制，我们希望允许一部分 Pod 在端口`443`上接收网络流量，并在端口`6379`上向数据库 Pod 发送流量。为了做到这一点，我们只需要创建一个新的网络策略，通过策略的叠加性质，允许这种流量。

这就是网络策略的样子：

覆盖限制网络策略.yaml

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: override-restriction-policy
  namespace: development
spec:
  podSelector:
    matchLabels:
      app: server
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 443
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 6379
```

在这个网络策略中，我们允许`development`命名空间中的服务器 Pod 在端口`443`上接收来自前端 Pod 的流量，并在端口`6379`上向数据库 Pod 发送流量。

如果我们想要打开所有 Pod 之间的通信而没有任何限制，同时实际上还要制定网络策略，我们可以使用以下 YAML 来实现：

全开放网络策略.yaml

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-egress
spec:
  podSelector: {}
  egress:
  - {}
  ingress:
  - {}
  policyTypes:
  - Egress
  - Ingress
```

现在我们已经讨论了如何使用网络策略来设置 Pod 之间的流量规则。然而，也可以将网络策略用作外部防火墙。为了做到这一点，我们创建基于外部 IP 而不是 Pod 作为源或目的地的网络策略规则。

让我们看一个限制与特定 IP 范围作为目标的 Pod 之间通信的网络策略的示例：

外部 IP 网络策略.yaml

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: specific-ip-policy
spec:
  podSelector:
    matchLabels:
      app: worker
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - ipBlock:
        cidr: 157.10.0.0/16
        except:
        - 157.10.1.0/24
  egress:
  - to:
    - ipBlock:
        cidr: 157.10.0.0/16
        except:
        - 157.10.1.0/24
```

在这个网络策略中，我们指定了一个`Ingress`规则和一个`Egress`规则。每个规则根据网络请求的源 IP 而不是来自哪个 Pod 来接受或拒绝流量。

在我们的情况下，我们已经为我们的`Ingress`和`Egress`规则选择了一个`/16`子网掩码范围（带有指定的`/24` CIDR 异常）。这会产生一个副作用，即阻止集群内部的任何流量到达这些 Pod，因为我们的 Pod IP 都不会匹配默认集群网络设置中的规则。

然而，在指定的子网掩码中来自集群外部的流量（并且不在异常范围内）将能够向`worker`Pod 发送流量，并且还能够接受来自`worker`Pod 的流量。

随着我们讨论网络策略的结束，我们可以转向安全堆栈的一个完全不同的层面 - 运行时安全和入侵检测。

# 处理 Kubernetes 上的入侵检测、运行时安全和合规性

一旦您设置了 Pod 安全策略和网络策略，并且通常确保您的配置尽可能牢固 - Kubernetes 仍然存在许多可能的攻击向量。在本节中，我们将重点关注来自 Kubernetes 集群内部的攻击。即使在具有高度特定的 Pod 安全策略的情况下（这确实有所帮助，需要明确），您的集群中运行的容器和应用程序仍可能执行意外或恶意操作。

为了解决这个问题，许多专业人士寻求运行时安全工具，这些工具允许对应用程序进程进行持续监控和警报。对于 Kubernetes 来说，一个流行的开源工具就是*Falco*。

## 安装 Falco

Falco 自称为 Kubernetes 上进程的*行为活动监视器*。它可以监视在 Kubernetes 上运行的容器化应用程序以及 Kubernetes 组件本身。

Falco 是如何工作的？在实时中，Falco 解析来自 Linux 内核的系统调用。然后，它通过规则过滤这些系统调用 - 这些规则是可以应用于 Falco 引擎的一组配置。每当系统调用违反规则时，Falco 就会触发警报。就是这么简单！

Falco 附带了一套广泛的默认规则，可以在内核级别增加显著的可观察性。当然，Falco 支持自定义规则 - 我们将向您展示如何编写这些规则。

但首先，我们需要在我们的集群上安装 Falco！幸运的是，Falco 可以使用 Helm 进行安装。但是，非常重要的是要注意，有几种不同的安装 Falco 的方式，在事件发生时它们在有效性上有很大的不同。

我们将使用 Helm 图表安装 Falco，这对于托管的 Kubernetes 集群或者您可能无法直接访问工作节点的任何情况都非常简单且有效。

然而，为了获得最佳的安全姿态，Falco 应该直接安装到 Kubernetes 节点的 Linux 级别。使用 DaemonSet 的 Helm 图表非常易于使用，但本质上不如直接安装 Falco 安全。要直接将 Falco 安装到您的节点上，请查看[`falco.org/docs/installation/`](https://falco.org/docs/installation)上的安装说明。

有了这个警告，我们可以使用 Helm 安装 Falco：

1.  首先，我们需要将`falcosecurity`存储库添加到我们本地的 Helm 中：

```
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

接下来，我们可以继续使用 Helm 实际安装 Falco。

重要提示

Falco Helm 图表有许多可能可以在 values 文件中更改的变量-要全面审查这些变量，您可以在官方 Helm 图表存储库[`github.com/falcosecurity/charts/tree/master/falco`](https://github.com/falcosecurity/charts/tree/master/falco)上查看。

1.  要安装 Falco，请运行以下命令：

```
helm install falco falcosecurity/falco
```

此命令将使用默认值安装 Falco，您可以在[`github.com/falcosecurity/charts/blob/master/falco/values.yaml`](https://github.com/falcosecurity/charts/blob/master/falco/values.yaml)上查看默认值。

接下来，让我们深入了解 Falco 为安全意识的 Kubernetes 管理员提供了什么。

## 了解 Falco 的功能

如前所述，Falco 附带一组默认规则，但我们可以使用新的 YAML 文件轻松添加更多规则。由于我们使用的是 Helm 版本的 Falco，因此将自定义规则传递给 Falco 就像创建一个新的 values 文件或编辑具有自定义规则的默认文件一样简单。

添加自定义规则看起来像这样：

Custom-falco.yaml

```
customRules:
  my-rules.yaml: |-
    Rule1
    Rule2
    etc...
```

现在是讨论 Falco 规则结构的好时机。为了说明，让我们借用一些来自随 Falco Helm 图表一起提供的`Default` Falco 规则集的规则。

在 YAML 中指定 Falco 配置时，我们可以使用三种不同类型的键来帮助组成我们的规则。这些是宏、列表和规则本身。

在这个例子中，我们正在查看的具体规则称为`启动特权容器`。这个规则将检测特权容器何时被启动，并记录一些关于容器的信息到`STDOUT`。规则在处理警报时可以做各种事情，但记录到`STDOUT`是在发生高风险事件时增加可观察性的好方法。

首先，让我们看一下规则条目本身。这个规则使用了一些辅助条目，几个宏和列表 - 但我们将在稍后讨论这些：

```
- rule: Launch Privileged Container
  desc: Detect the initial process started in a privileged container. Exceptions are made for known trusted images.
  condition: >
    container_started and container
    and container.privileged=true
    and not falco_privileged_containers
    and not user_privileged_containers
  output: Privileged container started (user=%user.name command=%proc.cmdline %container.info image=%container.image.repository:%container.image.tag)
  priority: INFO
  tags: [container, cis, mitre_privilege_escalation, mitre_lateral_movement]
```

正如您所看到的，Falco 规则有几个部分。首先，我们有规则名称和描述。然后，我们指定规则的触发条件 - 这充当 Linux 系统调用的过滤器。如果系统调用匹配`condition`块中的所有逻辑过滤器，规则就会被触发。

当触发规则时，`output`键允许我们设置输出文本的格式。`priority`键让我们分配一个优先级，可以是`emergency`、`alert`、`critical`、`error`、`warning`、`notice`、`informational`和`debug`中的一个。

最后，`tags`键将标签应用于相关的规则，使得更容易对规则进行分类。当使用不仅仅是简单文本`STDOUT`条目的警报时，这一点尤为重要。

这里`condition`的语法特别重要，我们将重点关注过滤系统的工作原理。

首先，由于过滤器本质上是逻辑语句，您将看到一些熟悉的语法（如果您曾经编程或编写伪代码） - `and`、`and not`、`and so on`。这种语法很容易学习，可以在[`github.com/draios/sysdig/wiki/sysdig-user-guide#filtering`](https://github.com/draios/sysdig/wiki/sysdig-user-guide#filtering)找到关于它的全面讨论 - *Sysdig*过滤器语法。

需要注意的是，Falco 开源项目最初是由*Sysdig*创建的，这就是为什么它使用常见的*Sysdig*过滤器语法。

接下来，您将看到对`container_started`和`container`的引用，以及`falco_privileged_containers`和`user_privileged_containers`的引用。这些不是简单的字符串，而是宏的使用 - 引用 YAML 中其他块的引用，指定了额外的功能，并且通常使得编写规则变得更加容易，而不需要重复大量的配置。

为了了解这个规则是如何真正工作的，让我们看一下在前面规则中引用的所有宏的完整参考：

```
- macro: container
  condition: (container.id != host)
- macro: container_started
  condition: >
    ((evt.type = container or
     (evt.type=execve and evt.dir=< and proc.vpid=1)) and
     container.image.repository != incomplete)
- macro: user_sensitive_mount_containers
  condition: (container.image.repository = docker.io/sysdig/agent)
- macro: falco_privileged_containers
  condition: (openshift_image or
              user_trusted_containers or
              container.image.repository in (trusted_images) or
              container.image.repository in (falco_privileged_images) or
              container.image.repository startswith istio/proxy_ or
              container.image.repository startswith quay.io/sysdig)
- macro: user_privileged_containers
  condition: (container.image.repository endswith sysdig/agent)
```

您将在前面的 YAML 中看到，每个宏实际上只是一块可重用的`Sysdig`过滤器语法块，通常使用其他宏来完成规则功能。列表在这里没有显示，它们类似于宏，但不描述过滤逻辑。相反，它们包括一个字符串值列表，可以作为使用过滤器语法的比较的一部分。

例如，在`falco_privileged_containers`宏中的`(``trusted_images)`引用了一个名为`trusted_images`的列表。以下是该列表的来源：

```
- list: trusted_images
  items: []
```

正如您所看到的，在默认规则中，这个特定列表是空的，但自定义规则集可以在这个列表中使用一组受信任的镜像，然后这些受信任的镜像将自动被所有使用`trusted_image`列表作为其过滤规则一部分的其他宏和规则所使用。

正如之前提到的，除了跟踪 Linux 系统调用之外，Falco 在版本 v0.13.0 中还可以跟踪 Kubernetes 控制平面事件。

### 了解 Falco 中的 Kubernetes 审计事件规则

在结构上，这些 Kubernetes 审计事件规则的工作方式与 Falco 的 Linux 系统调用规则相同。以下是 Falco 中默认 Kubernetes 规则的示例：

```
- rule: Create Disallowed Pod
  desc: >
    Detect an attempt to start a pod with a container image outside of a list of allowed images.
  condition: kevt and pod and kcreate and not allowed_k8s_containers
  output: Pod started with container not in allowed list (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image)
  priority: WARNING
  source: k8s_audit
  tags: [k8s]
```

这个规则在 Falco 中针对 Kubernetes 审计事件（基本上是控制平面事件），在创建不在`allowed_k8s_containers`列表中的 Pod 时发出警报。默认的`k8s`审计规则包含许多类似的规则，大多数在触发时输出格式化日志。

现在，我们在本章的前面谈到了一些 Pod 安全策略，你可能会发现 PSPs 和 Falco Kubernetes 审计事件规则之间有一些相似之处。例如，看看默认的 Kubernetes Falco 规则中的这个条目：

```
- rule: Create HostNetwork Pod
  desc: Detect an attempt to start a pod using the host network.
  condition: kevt and pod and kcreate and ka.req.pod.host_network intersects (true) and not ka.req.pod.containers.image.repository in (falco_hostnetwork_images)
  output: Pod started using host network (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image)
  priority: WARNING
  source: k8s_audit
  tags: [k8s]
```

这个规则在尝试使用主机网络启动 Pod 时触发，直接映射到主机网络 PSP 设置。

Falco 利用这种相似性，让我们可以使用 Falco 作为一种`试验`新的 Pod 安全策略的方式，而不会在整个集群中应用它们并导致运行中的 Pod 出现问题。

为此，`falcoctl`（Falco 命令行工具）带有`convert psp`命令。该命令接受一个 Pod 安全策略定义，并将其转换为一组 Falco 规则。这些 Falco 规则在触发时只会将日志输出到`STDOUT`（而不会像 PSP 不匹配那样导致 Pod 调度失败），这样就可以更轻松地在现有集群中测试新的 Pod 安全策略。

要了解如何使用`falcoctl`转换工具，请查看官方 Falco 文档[`falco.org/docs/psp-support/`](https://falco.org/docs/psp-support/)。

现在我们对 Falco 工具有了很好的基础，让我们讨论一下它如何用于实施合规性控制和运行时安全。

## 将 Falco 映射到合规性和运行时安全用例

由于其可扩展性和审计低级别的 Linux 系统调用的能力，Falco 是持续合规性和运行时安全的绝佳工具。

在合规性方面，可以利用 Falco 规则集，这些规则集专门映射到合规性标准的要求-例如 PCI 或 HIPAA。这使用户能够快速检测并采取行动，处理不符合相关标准的任何进程。有几个标准的开源和闭源 Falco 规则集。

同样地，对于运行时安全，Falco 公开了一个警报/事件系统，这意味着任何触发警报的运行时事件也可以触发自动干预和补救过程。这对安全性和合规性都适用。例如，如果一个 Pod 触发了 Falco 的不合规警报，一个进程可以立即处理该警报并删除有问题的 Pod。

# 总结

在本章中，我们了解了 Kubernetes 上下文中的安全性。首先，我们回顾了 Kubernetes 上的安全性基础知识-安全堆栈的哪些层对我们的集群相关，以及如何管理这种复杂性的一些基本概念。接下来，我们了解了 Kubernetes 遇到的一些主要安全问题，以及讨论了 2019 年安全审计的结果。

然后，我们在 Kubernetes 的两个不同级别实施了安全性-首先是使用 Pod 安全策略和网络策略进行配置，最后是使用 Falco 进行运行时安全。

在下一章中，我们将学习如何通过构建自定义资源使 Kubernetes 成为您自己的。这将允许您为集群添加重要的新功能。

# 问题

1.  自定义准入控制器可以使用哪两个 Webhook 控制器的名称？

1.  空的`NetworkPolicy`对入口有什么影响？

1.  为了防止攻击者更改 Pod 功能，哪种类型的 Kubernetes 控制平面事件对于跟踪是有价值的？

# 进一步阅读

+   Kubernetes CVE 数据库：[`cve.mitre.org/cgi-bin/cvekey.cgi?keyword=kubernetes`](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=kubernetes)


# 第四部分：扩展 Kubernetes

在这一部分，您将把在前几节中学到的知识应用到 Kubernetes 上的高级模式中。我们将使用自定义资源定义来扩展默认的 Kubernetes 功能，实现服务网格和无服务器模式在您的集群上，并运行一些有状态的工作负载。

本书的这一部分包括以下章节：

+   *第十三章*, *使用 CRD 扩展 Kubernetes*

+   *第十四章*, *服务网格和无服务器*

+   *第十五章*, *Kubernetes 上的有状态工作负载*


# 第十三章：使用 CRD 扩展 Kubernetes

本章解释了扩展 Kubernetes 功能的许多可能性。它从讨论**自定义资源定义**（**CRD**）开始，这是一种 Kubernetes 本地的方式，用于指定可以通过熟悉的`kubectl`命令（如`get`、`create`、`describe`和`apply`）对其进行操作的自定义资源。接下来是对运算符模式的讨论，这是 CRD 的扩展。然后详细介绍了云提供商附加到其 Kubernetes 实现的一些钩子，并以对更大的云原生生态系统的简要介绍结束。使用本章学到的概念，您将能够设计和开发对 Kubernetes 集群的扩展，解锁高级使用模式。

本章的案例研究将包括创建两个简单的 CRD 来支持一个示例应用程序。我们将从 CRD 开始，这将让您对扩展如何构建在 Kubernetes API 上有一个良好的基础理解。

在本章中，我们将涵盖以下主题：

+   如何使用**自定义资源定义**（**CRD**）扩展 Kubernetes

+   使用 Kubernetes 运算符进行自管理功能

+   使用特定于云的 Kubernetes 扩展

+   与生态系统集成

# 技术要求

为了运行本章中详细介绍的命令，您需要一台支持`kubectl`命令行工具的计算机，以及一个正常运行的 Kubernetes 集群。请参阅*第一章*，*与 Kubernetes 通信*，了解快速启动和运行 Kubernetes 的几种方法，以及如何安装`kubectl`工具。

本章中使用的代码可以在书籍的 GitHub 存储库中找到，网址为[`github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter13`](https://github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter13)。

# 如何使用自定义资源定义扩展 Kubernetes

让我们从基础知识开始。什么是 CRD？我们知道 Kubernetes 有一个 API 模型，我们可以对资源执行操作。一些 Kubernetes 资源的例子（现在你应该对它们非常熟悉）是 Pods、PersistentVolumes、Secrets 等。

现在，如果我们想在集群中实现一些自定义功能，编写我们自己的控制器，并将控制器的状态存储在某个地方，我们可以，当然，将我们自定义功能的状态存储在 Kubernetes 或其他地方运行的 SQL 或 NoSQL 数据库中（这实际上是扩展 Kubernetes 的策略之一）-但是如果我们的自定义功能更像是 Kubernetes 功能的扩展，而不是完全独立的应用程序呢？

在这种情况下，我们有两个选择：

+   自定义资源定义

+   API 聚合

API 聚合允许高级用户在 Kubernetes API 服务器之外构建自己的资源 API，并使用自己的存储，然后在 API 层聚合这些资源，以便可以使用 Kubernetes API 进行查询。这显然是非常可扩展的，实质上只是使用 Kubernetes API 作为代理来使用您自己的自定义功能，这可能实际上与 Kubernetes 集成，也可能不会。

另一个选择是 CRDs，我们可以使用 Kubernetes API 和底层数据存储（`etcd`）而不是构建我们自己的。我们可以使用我们知道的`kubectl`和`kube api`方法与我们自己的自定义功能进行交互。

在这本书中，我们不会讨论 API 聚合。虽然比 CRDs 更灵活，但这是一个高级主题，需要对 Kubernetes API 有深入的了解，并仔细阅读 Kubernetes 文档以正确实施。您可以在 Kubernetes 文档中了解更多关于 API 聚合的信息[`kubernetes.io/docs/concepts/extend-kubernetes/api-extension/apiserver-aggregation/`](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/apiserver-aggregation/)。

所以，现在我们知道我们正在使用 Kubernetes 控制平面作为我们自己的有状态存储来存储我们的新自定义功能，我们需要一个模式。类似于 Kubernetes 中 Pod 资源规范期望特定字段和配置，我们可以告诉 Kubernetes 我们对新的自定义资源期望什么。现在让我们来看一下 CRD 的规范。

## 编写自定义资源定义

对于 CRDs，Kubernetes 使用 OpenAPI V3 规范。有关 OpenAPI V3 的更多信息，您可以查看官方文档[`github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.0.md`](https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.0.md)，但我们很快将看到这如何转化为 Kubernetes CRD 定义。

让我们来看一个 CRD 规范的示例。现在让我们明确一点，这不是任何特定记录的 YAML 的样子。相反，这只是我们在 Kubernetes 内部定义 CRD 的要求的地方。一旦创建，Kubernetes 将接受与规范匹配的资源，我们就可以开始制作我们自己的这种类型的记录。

这里有一个 CRD 规范的示例 YAML，我们称之为`delayedjob`。这个非常简单的 CRD 旨在延迟启动容器镜像作业，这样用户就不必为他们的容器编写延迟启动的脚本。这个 CRD 非常脆弱，我们不建议任何人真正使用它，但它确实很好地突出了构建 CRD 的过程。让我们从一个完整的 CRD 规范 YAML 开始，然后分解它：

自定义资源定义-1.yaml

```
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: delayedjobs.delayedresources.mydomain.com
spec:
  group: delayedresources.mydomain.com
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                delaySeconds:
                  type: integer
                image:
                  type: string
  scope: Namespaced
  conversion:
    strategy: None
  names:
    plural: delayedjobs
    singular: delayedjob
    kind: DelayedJob
    shortNames:
    - dj
```

让我们来审视一下这个文件的部分。乍一看，它看起来像是您典型的 Kubernetes YAML 规范 - 因为它就是！在`apiVersion`字段中，我们有`apiextensions.k8s.io/v1`，这是自 Kubernetes `1.16`以来的标准（在那之前是`apiextensions.k8s.io/v1beta1`）。我们的`kind`将始终是`CustomResourceDefinition`。

`metadata`字段是当事情开始变得特定于我们的资源时。我们需要将`name`元数据字段结构化为我们资源的`复数`形式，然后是一个句号，然后是它的组。让我们从我们的 YAML 文件中快速偏离一下，讨论一下 Kubernetes API 中组的工作原理。

### 理解 Kubernetes API 组

组是 Kubernetes 在其 API 中分割资源的一种方式。每个组对应于 Kubernetes API 服务器的不同子路径。

默认情况下，有一个名为核心组的遗留组 - 它对应于在 Kubernetes REST API 的`/api/v1`端点上访问的资源。因此，这些遗留组资源在其 YAML 规范中具有`apiVersion: v1`。核心组中资源的一个例子是 Pod。

接下来，有一组命名的组 - 这些组对应于可以在`REST` URL 上访问的资源，形式为`/apis/<GROUP NAME>/<VERSION>`。这些命名的组构成了 Kubernetes 资源的大部分。然而，最古老和最基本的资源，如 Pod、Service、Secret 和 Volume，都在核心组中。一个在命名组中的资源的例子是`StorageClass`资源，它在`storage.k8s.io`组中。

重要说明

要查看哪个资源属于哪个组，您可以查看您正在使用的 Kubernetes 版本的官方 Kubernetes API 文档。例如，版本`1.18`的文档将位于[`kubernetes.io/docs/reference/generated/kubernetes-api/v1.18`](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18)。

CRD 可以指定自己的命名组，这意味着特定的 CRD 将在 Kubernetes API 服务器可以监听的`REST`端点上可用。考虑到这一点，让我们回到我们的 YAML 文件，这样我们就可以讨论 CRD 的主要部分-版本规范。

### 理解自定义资源定义版本

正如您所看到的，我们选择了组`delayedresources.mydomain.com`。该组理论上将包含任何其他延迟类型的 CRD-例如，`DelayedDaemonSet`或`DelayedDeployment`。

接下来，我们有我们的 CRD 的主要部分。在`versions`下，我们可以定义一个或多个 CRD 版本（在`name`字段中），以及该 CRD 版本的 API 规范。然后，当您创建 CRD 的实例时，您可以在 YAML 文件的`apiVersion`键的版本参数中定义您将使用的版本-例如，`apps/v1`，或在这种情况下，`delayedresources.mydomain.com/v1`。

每个版本项还有一个`served`属性，这实质上是一种定义给定版本是否启用或禁用的方式。如果`served`为`false`，则该版本将不会被 Kubernetes API 创建，并且该版本的 API 请求（或`kubectl`命令）将失败。

此外，还可以在特定版本上定义一个`deprecated`键，这将导致 Kubernetes 在使用弃用版本进行 API 请求时返回警告消息。这就是带有弃用版本的 CRD 的`yaml`文件的样子-我们已删除了一些规范，以使 YAML 文件简短：

自定义资源定义-2.yaml

```
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: delayedjob.delayedresources.mydomain.com
spec:
  group: delayedresources.mydomain.com
  versions:
    - name: v1
      served: true
      storage: false
      deprecated: true
      deprecationWarning: "DelayedJob v1 is deprecated!"
      schema:
        openAPIV3Schema:
		…
    - name: v2
      served: true
      storage: true
      schema:
        openAPIV3Schema:
		...
  scope: Namespaced
  conversion:
    strategy: None
  names:
    plural: delayedjobs
    singular: delayedjob
    kind: DelayedJob
    shortNames:
    - dj
```

正如您所看到的，我们已将`v1`标记为已弃用，并且还包括一个弃用警告，以便 Kubernetes 作为响应发送。如果我们不包括弃用警告，将使用默认消息。

进一步向下移动，我们有`storage`键，它与`served`键交互。这是必要的原因是，虽然 Kubernetes 支持同时拥有多个活动（也就是`served`）版本的资源，但是只能有一个版本存储在控制平面中。然而，`served`属性意味着 API 可以提供多个版本的资源。那么这是如何工作的呢？

答案是，Kubernetes 将把 CRD 对象从存储的版本转换为您要求的版本（或者反过来，在创建资源时）。

这种转换是如何处理的？让我们跳过其余的版本属性，看看`conversion`键是如何工作的。

`conversion`键允许您指定 Kubernetes 将如何在您的服务版本和存储版本之间转换 CRD 对象的策略。如果两个版本相同-例如，如果您请求一个`v1`资源，而存储的版本是`v1`，那么不会发生转换。

截至 Kubernetes 1.13 的默认值是`none`。使用`none`设置，Kubernetes 不会在字段之间进行任何转换。它只会包括应该出现在`served`（或存储，如果创建资源）版本上的字段。

另一个可能的转换策略是`Webhook`，它允许您定义一个自定义 Webhook，该 Webhook 将接收一个版本并对其进行适当的转换为您想要的版本。这里有一个使用`Webhook`转换策略的 CRD 示例-为了简洁起见，我们省略了一些版本模式：

Custom-resource-definition-3.yaml

```
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: delayedjob.delayedresources.mydomain.com
spec:
  group: delayedresources.mydomain.com
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
		...
  scope: Namespaced
  conversion:
    strategy: Webhook
    webhook:
      clientConfig:
        url: "https://webhook-conversion.com/delayedjob"
  names:
    plural: delayedjobs
    singular: delayedjob
    kind: DelayedJob
    shortNames:
    - dj
```

正如您所看到的，`Webhook`策略让我们定义一个 URL，请求将发送到该 URL，其中包含有关传入资源对象、其当前版本和需要转换为的版本的信息。

想法是我们的`Webhook`服务器将处理转换并传回修正后的 Kubernetes 资源对象。`Webhook`策略是复杂的，可以有许多可能的配置，我们在本书中不会深入讨论。

重要提示

要了解如何配置转换 Webhooks，请查看官方 Kubernetes 文档[`kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/`](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/)。

现在，回到我们在 YAML 中的`version`条目！在`served`和`storage`键下，我们看到`schema`对象，其中包含我们资源的实际规范。如前所述，这遵循 OpenAPI Spec v3 模式。

`schema`对象，由于空间原因已从前面的代码块中删除，如下所示：

自定义资源定义-3.yaml（续）

```
     schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                delaySeconds:
                  type: integer
                image:
                  type: string
```

正如您所看到的，我们支持`delaySeconds`字段，它将是一个整数，以及`image`，它是一个与我们的容器映像相对应的字符串。如果我们真的想要使`DelayedJob`达到生产就绪状态，我们会希望包括各种其他选项，使其更接近原始的 Kubernetes Job 资源 - 但这不是我们的意图。

在原始代码块中进一步向后移动，超出版本列表，我们看到一些其他属性。首先是`scope`属性，可以是`Cluster`或`Namespaced`。这告诉 Kubernetes 是否将 CRD 对象的实例视为特定于命名空间的资源（例如 Pods，Deployments 等），还是作为集群范围的资源 - 就像命名空间本身一样，因为在命名空间中获取命名空间对象是没有意义的！

最后，我们有`names`块，它允许您定义资源名称的复数和单数形式，以在各种情况下使用（例如，`kubectl get pods`和`kubectl get pod`都可以工作）。

`names`块还允许您定义驼峰命名的`kind`值，在资源 YAML 中将使用该值，以及一个或多个`shortNames`，可以用来在 API 或`kubectl`中引用该资源 - 例如，`kubectl get po`。

解释了我们的 CRD 规范 YAML 后，让我们来看一下我们 CRD 的一个实例 - 正如我们刚刚审查的规范所定义的，YAML 将如下所示：

Delayed-job.yaml

```
apiVersion: delayedresources.mydomain.com/v1
kind: DelayedJob
metadata:
  name: my-instance-of-delayed-job
spec:
  delaySeconds: 6000
  image: "busybox"
```

正如您所看到的，这就像我们的 CRD 定义了这个对象。现在，所有的部分都就位了，让我们测试一下我们的 CRD！

### 测试自定义资源定义

让我们继续在 Kubernetes 上测试我们的 CRD 概念：

1.  首先，让我们在 Kubernetes 中创建 CRD 规范 - 就像我们创建任何其他对象一样：

```
kubectl apply -f delayedjob-crd-spec.yaml
```

这将导致以下输出：

```
customresourcedefinition "delayedjob.delayedresources.mydomain.com" has been created
```

1.  现在，Kubernetes 将接受对我们的`DelayedJob`资源的请求。我们可以通过最终使用前面的资源 YAML 创建一个来测试这一点：

```
kubectl apply -f my-delayed-job.yaml
```

如果我们正确定义了我们的 CRD，我们将看到以下输出：

```
delayedjob "my-instance-of-delayed-job" has been created
```

正如您所看到的，Kubernetes API 服务器已成功创建了我们的`DelayedJob`实例！

现在，您可能会问一个非常相关的问题 - 现在怎么办？这是一个很好的问题，因为事实上，到目前为止，我们实际上什么也没有做，只是向 Kubernetes API 数据库添加了一个新的`表`。

仅仅因为我们给我们的`DelayedJob`资源一个应用程序镜像和一个`delaySeconds`字段，并不意味着我们打算的任何功能实际上会发生。通过创建我们的`DelayedJob`实例，我们只是向那个`表`添加了一个条目。我们可以使用 Kubernetes API 或`kubectl`命令获取它，编辑它或删除它，但没有实现任何应用功能。

为了让我们的`DelayedJob`资源真正做些什么，我们需要一个自定义控制器，它将获取我们的`DelayedJob`实例并对其进行操作。最终，我们仍然需要使用官方 Kubernetes 资源（如 Pods 等）来实现实际的容器功能。

这就是我们现在要讨论的。有许多构建 Kubernetes 自定义控制器的方法，但流行的方法是**运算符模式**。让我们继续下一节，看看我们如何让我们的`DelayedJob`资源拥有自己的生命。

# 使用 Kubernetes 运算符自管理功能

在没有首先讨论**Operator Framework**之前，不可能讨论 Kubernetes 运算符。一个常见的误解是，运算符是通过 Operator Framework 专门构建的。Operator Framework 是一个开源框架，最初由 Red Hat 创建，旨在简化编写 Kubernetes 运算符。

实际上，运算符只是一个与 Kubernetes 接口并对资源进行操作的自定义控制器。Operator Framework 是一种使 Kubernetes 运算符的一种偏见方式，但还有许多其他开源框架可以使用 - 或者，您可以从头开始制作一个！

使用框架构建运算符时，最流行的两个选项是前面提到的**Operator Framework**和**Kubebuilder**。

这两个项目有很多共同之处。它们都使用`controller-tools`和`controller-runtime`，这是两个由 Kubernetes 项目官方支持的构建 Kubernetes 控制器的库。如果您从头开始构建运算符，使用这些官方支持的控制器库将使事情变得更容易。

与 Operator Framework 不同，Kubebuilder 是 Kubernetes 项目的官方部分，就像`controller-tools`和`controller-runtime`库一样 - 但这两个项目都有其优缺点。重要的是，这两个选项以及一般的 Operator 模式都是在集群上运行控制器。这似乎是最好的选择，但你也可以在集群外运行控制器，并且它可以正常工作。要开始使用 Operator Framework，请查看官方 GitHub 网站[`github.com/operator-framework`](https://github.com/operator-framework)。对于 Kubebuilder，你可以查看[`github.com/kubernetes-sigs/kubebuilder`](https://github.com/kubernetes-sigs/kubebuilder)。

大多数操作员，无论使用哪种框架，都遵循控制循环范式 - 让我们看看这个想法是如何工作的。

## 映射操作员控制循环

控制循环是系统设计和编程中的控制方案，由一系列逻辑过程组成的永无止境的循环。通常，控制循环实现了一种测量-分析-调整的方法，它测量系统的当前状态，分析需要做出哪些改变使其与预期状态一致，然后调整系统组件使其与预期状态一致（或至少更接近预期状态）。

在 Kubernetes 的操作员或控制器中，这个操作通常是这样工作的：

1.  首先是一个“监视”步骤 - 也就是监视 Kubernetes API 中预期状态的变化，这些状态存储在`etcd`中。

1.  然后是一个“分析”步骤 - 控制器决定如何使集群状态与预期状态一致。

1.  最后是一个“更新”步骤 - 更新集群状态以实现集群变化的意图。

为了帮助理解控制循环，这里有一个图表显示了这些部分是如何组合在一起的：

![图 13.1 - 测量分析更新循环](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_13_01.jpg)

图 13.1 - 测量分析更新循环

让我们使用 Kubernetes 调度器来说明这一点 - 它本身就是一个控制循环过程：

1.  让我们从一个假设的集群开始，处于稳定状态：所有的 Pod 都已经调度，节点也健康，一切都在正常运行。

1.  然后，用户创建了一个新的 Pod。

我们之前讨论过 kubelet 是基于`pull`的工作方式。这意味着当 kubelet 在其节点上创建一个 Pod 时，该 Pod 已经通过调度器分配给了该节点。然而，当通过`kubectl create`或`kubectl apply`命令首次创建 Pod 时，该 Pod 尚未被调度或分配到任何地方。这就是我们的调度器控制循环开始的地方：

1.  第一步是**测量**，调度器从 Kubernetes API 读取状态。当从 API 列出 Pod 时，它发现其中一个 Pod 未分配给任何节点。现在它转移到下一步。

1.  接下来，调度器对集群状态和 Pod 需求进行分析，以决定将 Pod 分配给哪个节点。正如我们在前几章中讨论的那样，这涉及到 Pod 资源限制和请求、节点状态、放置控制等等，这使得它成为一个相当复杂的过程。一旦处理完成，更新步骤就可以开始了。

1.  最后，**更新** - 调度器通过将 Pod 分配给从*步骤 2*分析中获得的节点来更新集群状态。此时，kubelet 接管自己的控制循环，并为其节点上的 Pod 创建相关的容器。

接下来，让我们将从调度器控制循环中学到的内容应用到我们自己的`DelayedJob`资源上。

## 为自定义资源定义设计运算符

实际上，为我们的`DelayedJob` CRD 编写运算符超出了我们书的范围，因为这需要对编程语言有所了解。如果您选择使用 Go 构建运算符，它提供了与 Kubernetes SDK、**controller-tools**和**controller-runtime**最多的互操作性，但任何可以编写 HTTP 请求的编程语言都可以使用，因为这是所有 SDK 的基础。

然而，我们仍将逐步实现`DelayedJob` CRD 的运算符步骤，使用一些伪代码。让我们一步一步来。

### 步骤 1：测量

首先是**测量**步骤，我们将在我们的伪代码中实现为一个永远运行的`while`循环。在生产实现中，会有去抖动、错误处理和一堆其他问题，但是对于这个说明性的例子，我们会保持简单。

看一下这个循环的伪代码，这实际上是我们应用程序的主要功能：

Main-function.pseudo

```
// The main function of our controller
function main() {
  // While loop which runs forever
  while() {
     // fetch the full list of delayed job objects from the cluster
	var currentDelayedJobs = kubeAPIConnector.list("delayedjobs");
     // Call the Analysis step function on the list
     var jobsToSchedule = analyzeDelayedJobs(currentDelayedJobs);
     // Schedule our Jobs with added delay
     scheduleDelayedJobs(jobsToSchedule);
     wait(5000);
  }
}
```

正如您所看到的，在我们的`main`函数中的循环调用 Kubernetes API 来查找存储在`etcd`中的`delayedjobs` CRD 列表。这是`measure`步骤。然后调用分析步骤，并根据其结果调用更新步骤来安排需要安排的任何`DelayedJobs`。

重要说明

请记住，在这个例子中，Kubernetes 调度程序仍然会执行实际的容器调度 - 但是我们首先需要将我们的`DelayedJob`简化为官方的 Kubernetes 资源。

在更新步骤之后，我们的循环在执行循环之前等待完整的 5 秒。这确定了控制循环的节奏。接下来，让我们继续进行分析步骤。

### 步骤 2：分析

接下来，让我们来审查我们操作员的**Analysis**步骤，这是我们控制器伪代码中的`analyzeDelayedJobs`函数：

分析函数伪代码

```
// The analysis function
function analyzeDelayedJobs(listOfDelayedJobs) {
  var listOfJobsToSchedule = [];
  foreach(dj in listOfDelayedJobs) {
    // Check if dj has been scheduled, if not, add a Job object with
    // added delay command to the to schedule array
    if(dj.annotations["is-scheduled"] != "true") {
      listOfJobsToSchedule.push({
        Image: dj.image,
        Command: "sleep " + dj.delaySeconds + "s",
        originalDjName: dj.name
      });
    }
  }
  return listOfJobsToSchedule;  
}
```

正如您所看到的，前面的函数循环遍历了从**Measure**循环传递的集群中的`DelayedJob`对象列表。然后，它检查`DelayedJob`是否已经通过检查对象的注释之一的值来进行了调度。如果尚未安排，它将向名为`listOfJobsToSchedule`的数组添加一个对象，该数组包含`DelayedJob`对象中指定的图像，一个命令以睡眠指定的秒数，以及`DelayedJob`的原始名称，我们将在**Update**步骤中用来标记为已调度。

最后，在**Analyze**步骤中，`analyzeDelayedJobs`函数将我们新创建的`listOfJobsToSchedule`数组返回给主函数。让我们用最终的更新步骤来结束我们的操作员设计，这是我们主循环中的`scheduleDelayedJobs`函数。

### 步骤 3：更新

最后，我们的控制循环的**Update**部分将从我们的分析中获取输出，并根据需要更新集群以创建预期的状态。以下是伪代码：

更新函数伪代码

```
// The update function
function scheduleDelayedJobs(listOfJobs) {
  foreach(job in listOfDelayedJobs) {
    // First, go ahead and schedule a regular Kubernetes Job
    // which the Kube scheduler can pick up on.
    // The delay seconds have already been added to the job spec
    // in the analysis step
    kubeAPIConnector.create("job", job.image, job.command);
    // Finally, mark our original DelayedJob with a "scheduled"
    // attribute so our controller doesn't try to schedule it again
    kubeAPIConnector.update("delayedjob", job.originalDjName,
    annotations: {
      "is-scheduled": "true"
    });
  } 
}
```

在这种情况下，我们正在使用从我们的`DelayedJob`对象派生的常规 Kubernetes 对象，并在 Kubernetes 中创建它，以便`Kube`调度程序可以找到它，创建相关的 Pod 并管理它。一旦我们使用延迟创建了常规作业对象，我们还会使用注释更新我们的`DelayedJob` CRD 实例，将`is-scheduled`注释设置为`true`，以防止它被重新调度。

这完成了我们的控制循环 - 从这一点开始，`Kube`调度器接管并且我们的 CRD 被赋予生命作为一个 Kubernetes Job 对象，它控制一个 Pod，最终分配给一个 Node，并且一个容器被调度来运行我们的代码！

当然，这个例子是高度简化的，但你会惊讶地发现有多少 Kubernetes 操作员执行一个简单的控制循环来协调 CRD 并将其简化为基本的 Kubernetes 资源。操作员可以变得非常复杂，并执行特定于应用程序的功能，例如备份数据库、清空持久卷等，但这种功能通常与被控制的内容紧密耦合。

现在我们已经讨论了 Kubernetes 控制器中的操作员模式，我们可以谈谈一些特定于云的 Kubernetes 控制器的开源选项。

# 使用特定于云的 Kubernetes 扩展

通常情况下，在托管的 Kubernetes 服务（如 Amazon EKS、Azure AKS 和 Google Cloud 的 GKE）中默认可用，特定于云的 Kubernetes 扩展和控制器可以与相关的云平台紧密集成，并且可以轻松地从 Kubernetes 控制其他云资源。

即使不添加任何额外的第三方组件，许多这些特定于云的功能都可以通过**云控制器管理器**（**CCM**）组件在上游 Kubernetes 中使用，该组件包含许多与主要云提供商集成的选项。这通常是在每个公共云上的托管 Kubernetes 服务中默认启用的功能，但它们可以与在特定云平台上运行的任何集群集成，无论是托管还是非托管。

在本节中，我们将回顾一些常见的云扩展到 Kubernetes 中，包括**云控制器管理器（CCM）**和需要安装其他控制器的功能，例如**external-dns**和**cluster-autoscaler**。让我们从一些常用的 CCM 功能开始。

## 了解云控制器管理器组件

正如在*第一章*中所述，*与 Kubernetes 通信*，CCM 是一个官方支持的 Kubernetes 控制器，提供了对几个公共云服务功能的钩子。为了正常运行，CCM 组件需要以访问特定云服务的权限启动，例如在 AWS 中的 IAM 角色。

对于官方支持的云，如 AWS、Azure 和 Google Cloud，CCM 可以简单地作为集群中的 DaemonSet 运行。我们使用 DaemonSet，因为 CCM 可以执行诸如在云提供商中创建持久存储等任务，并且需要能够将存储附加到特定的节点。如果您使用的是官方不支持的云，您可以为该特定云运行 CCM，并且应该遵循该项目中的具体说明。这些替代类型的 CCM 通常是开源的，可以在 GitHub 上找到。关于安装 CCM 的具体信息，让我们继续下一节。

## 安装 cloud-controller-manager

通常，在创建集群时配置 CCM。如前一节所述，托管服务，如 EKS、AKS 和 GKE，将已经启用此组件，但即使 Kops 和 Kubeadm 也将 CCM 组件作为安装过程中的一个标志暴露出来。

假设您尚未以其他方式安装 CCM 并计划使用上游版本的官方支持的公共云之一，您可以将 CCM 安装为 DaemonSet。

首先，您需要一个`ServiceAccount`：

Service-account.yaml

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cloud-controller-manager
  namespace: kube-system
```

这个`ServiceAccount`将被用来给予 CCM 必要的访问权限。

接下来，我们需要一个`ClusterRoleBinding`：

Clusterrolebinding.yaml

```
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:cloud-controller-manager
subjects:
- kind: ServiceAccount
  name: cloud-controller-manager
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
```

如您所见，我们需要给`cluster-admin`角色访问我们的 CCM 服务账户。CCM 将需要能够编辑节点，以及其他一些操作。

最后，我们可以部署 CCM 的`DaemonSet`本身。您需要使用适合您特定云提供商的正确设置填写此 YAML 文件-查看您云提供商关于 Kubernetes 的文档以获取这些信息。

`DaemonSet`规范非常长，因此我们将分两部分进行审查。首先，我们有`DaemonSet`的模板，其中包含所需的标签和名称：

Daemonset.yaml

```
apiVersion: apps/v1
kind: DaemonSet
metadata:
  labels:
    k8s-app: cloud-controller-manager
  name: cloud-controller-manager
  namespace: kube-system
spec:
  selector:
    matchLabels:
      k8s-app: cloud-controller-manager
  template:
    metadata:
      labels:
        k8s-app: cloud-controller-manager
```

正如您所看到的，为了匹配我们的`ServiceAccount`，我们在`kube-system`命名空间中运行 CCM。我们还使用`k8s-app`标签对`DaemonSet`进行标记，以将其区分为 Kubernetes 控制平面组件。

接下来，我们有`DaemonSet`的规范：

Daemonset.yaml（续）

```
    spec:
      serviceAccountName: cloud-controller-manager
      containers:
      - name: cloud-controller-manager
        image: k8s.gcr.io/cloud-controller-manager:<current ccm version for your version of k8s>
        command:
        - /usr/local/bin/cloud-controller-manager
        - --cloud-provider=<cloud provider name>
        - --leader-elect=true
        - --use-service-account-credentials
        - --allocate-node-cidrs=true
        - --configure-cloud-routes=true
        - --cluster-cidr=<CIDR of the cluster based on Cloud Provider>
      tolerations:
      - key: node.cloudprovider.kubernetes.io/uninitialized
        value: "true"
        effect: NoSchedule
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      nodeSelector:
        node-role.kubernetes.io/master: ""
```

正如您所看到的，此规范中有一些地方需要查看您选择的云提供商的文档或集群网络设置，以找到正确的值。特别是在网络标志中，例如`--cluster-cidr`和`--configure-cloud-routes`，这些值可能会根据您如何设置集群而改变，即使在单个云提供商上也是如此。

既然我们在集群中以某种方式运行 CCM，让我们深入了解它提供的一些功能。

## 了解云控制器管理器的功能

默认的 CCM 在一些关键领域提供了功能。首先，CCM 包含了节点、路由和服务的子控制器。让我们依次审查每个，看看它为我们提供了什么，从节点/节点生命周期控制器开始。

### CCM 节点/节点生命周期控制器

CCM 节点控制器确保集群状态，就是集群中的节点与云提供商系统中的节点是等价的。一个简单的例子是 AWS 中的自动扩展组。在使用 AWS EKS（或者只是在 AWS EC2 上使用 Kubernetes，尽管这需要额外的配置）时，可以配置 AWS 自动扩展组中的工作节点组，根据节点的 CPU 或内存使用情况进行扩展或缩减。当这些节点由云提供商添加和初始化时，CCM 节点控制器将确保集群对于云提供商呈现的每个节点都有一个节点资源。

接下来，让我们转向路由控制器。

### CCM 路由控制器

CCM 路由控制器负责以支持 Kubernetes 集群的方式配置云提供商的网络设置。这可能包括分配 IP 和在节点之间设置路由。服务控制器也处理网络 - 但是外部方面。

### CCM 服务控制器

CCM 服务控制器提供了在公共云提供商上运行 Kubernetes 的“魔力”。我们在*第五章*中审查的一个方面是`LoadBalancer`服务，*服务和入口 - 与外部世界通信*，例如，在配置了 AWS CCM 的集群上，类型为`LoadBalancer`的服务将自动配置匹配的 AWS 负载均衡器资源，为您提供了一种在集群中公开服务的简单方法，而无需处理`NodePort`设置甚至 Ingress。

现在我们了解了 CCM 提供的内容，我们可以进一步探讨一下在公共云上运行 Kubernetes 时经常使用的一些其他云提供商扩展。首先，让我们看看`external-dns`。

## 使用 Kubernetes 的 external-dns

`external-dns`库是一个官方支持的 Kubernetes 插件，允许集群配置外部 DNS 提供程序以自动化方式为服务和 Ingress 提供 DNS 解析。`external-dns`插件支持广泛的云提供商，如 AWS 和 Azure，以及其他 DNS 服务，如 Cloudflare。

重要说明

要安装`external-dns`，您可以在[`github.com/kubernetes-sigs/external-dns`](https://github.com/kubernetes-sigs/external-dns)上查看官方 GitHub 存储库。

一旦在您的集群上实施了`external-dns`，就可以简单地以自动化的方式创建新的 DNS 记录。要测试`external-dns`与服务的配合，我们只需要在 Kubernetes 中创建一个带有适当注释的服务。

让我们看看这是什么样子：

service.yaml

```
apiVersion: v1
kind: Service
metadata:
  name: my-service-with-dns
  annotations:
    external-dns.alpha.kubernetes.io/hostname: myapp.mydomain.com
spec:
  type: LoadBalancer
  ports:
  - port: 80
    name: http
    targetPort: 80
  selector:
    app: my-app
```

正如您所看到的，我们只需要为`external-dns`控制器添加一个注释，以便检查要在 DNS 中创建的域记录。当然，域和托管区必须可以被您的`external-dns`控制器访问 - 例如，在 AWS Route 53 或 Azure DNS 上。请查看`external-dns` GitHub 存储库上的具体文档。

一旦服务启动运行，`external-dns`将获取注释并创建一个新的 DNS 记录。这种模式非常适合多租户或每个版本部署，因为像 Helm 图表这样的东西可以使用变量来根据应用程序的部署版本或分支来更改域 - 例如，`v1.myapp.mydomain.com`。

对于 Ingress，这甚至更容易 - 您只需要在 Ingress 记录中指定一个主机，就像这样：

ingress.yaml

```
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: my-domain-ingress
  annotations:
    kubernetes.io/ingress.class: "nginx".
spec:
  rules:
  - host: myapp.mydomain.com
    http:
      paths:
      - backend:
          serviceName: my-app-service
          servicePort: 80
```

此主机值将自动创建一个 DNS 记录，指向 Ingress 正在使用的任何方法 - 例如，在 AWS 上的负载均衡器。

接下来，让我们谈谈**cluster-autoscaler**库的工作原理。

## 使用 cluster-autoscaler 插件

与`external-dns`类似，`cluster-autoscaler`是 Kubernetes 的一个官方支持的附加组件，支持一些主要的云提供商具有特定功能。 `cluster-autoscaler`的目的是触发集群中节点数量的扩展。它通过控制云提供商自己的扩展资源（例如 AWS 自动缩放组）来执行此过程。

集群自动缩放器将在任何单个 Pod 由于节点上的资源限制而无法调度时执行向上缩放操作，但仅当现有节点大小（例如，在 AWS 中为`t3.medium`大小的节点）可以允许 Pod 被调度时才会执行。

类似地，集群自动缩放器将在任何节点可以在不会对其他节点造成内存或 CPU 压力的情况下清空 Pod 时执行向下缩放操作。

要安装`cluster-autoscaler`，只需按照您的云提供商的正确说明，为集群类型和预期的`cluster-autoscaler`版本进行操作。例如，EKS 上的 AWS`cluster-autoscaler`的安装说明可在[`aws.amazon.com/premiumsupport/knowledge-center/eks-cluster-autoscaler-setup/`](https://aws.amazon.com/premiumsupport/knowledge-center/eks-cluster-autoscaler-setup/)找到。

接下来，让我们看看如何通过检查 Kubernetes 生态系统来找到开源和闭源的扩展。

# 与生态系统集成

Kubernetes（以及更一般地说，云原生）生态系统是庞大的，包括数百个流行的开源软件库，以及成千上万个新兴的软件库。这可能很难导航，因为每个月都会有新的技术需要审查，而收购、合并和公司倒闭可能会将您最喜欢的开源库变成一个未维护的混乱。

幸运的是，这个生态系统中有一些结构，了解它是值得的，以帮助导航云原生开源选项的匮乏。这其中的第一个重要结构组件是**云原生计算基金会**或**CNCF**。

## 介绍云原生计算基金会

CNCF 是 Linux 基金会的一个子基金会，它是一个主持开源项目并协调不断变化的公司列表的非营利实体，这些公司为和使用开源软件做出贡献。

CNCF 几乎完全是为了引导 Kubernetes 项目的未来而成立的。它是在 Kubernetes 1.0 发布时宣布的，并且此后已经发展到涵盖了云原生空间中的数百个项目 - 从 Prometheus 到 Envoy 到 Helm，以及更多。

了解 CNCF 组成项目的最佳方法是查看 CNCF Cloud Native Landscape，网址为[`landscape.cncf.io/`](https://landscape.cncf.io/)。

如果你对你在 Kubernetes 或云原生中遇到的问题感兴趣，CNCF Landscape 是一个很好的起点。对于每个类别（监控、日志记录、无服务器、服务网格等），都有几个开源选项供您选择。

当前云原生技术生态系统的优势和劣势。有大量的选择可用，这使得正确的路径通常不明确，但也意味着你可能会找到一个接近你确切需求的解决方案。

CNCF 还经营着一个官方的 Kubernetes 论坛，可以从 Kubernetes 官方网站[kubernetes.io](http://kubernetes.io)加入。Kubernetes 论坛的网址是[`discuss.kubernetes.io/`](https://discuss.kubernetes.io/)。

最后，值得一提的是*KubeCon*/*CloudNativeCon*，这是由 CNCF 主办的一个大型会议，涵盖了 Kubernetes 本身和许多生态项目等主题。*KubeCon*每年都在扩大规模，2019 年*KubeCon* *North America*有近 12,000 名与会者。

# 总结

在本章中，我们学习了如何扩展 Kubernetes。首先，我们讨论了 CRDs - 它们是什么，一些相关的用例，以及如何在集群中实现它们。接下来，我们回顾了 Kubernetes 中操作员的概念，并讨论了如何使用操作员或自定义控制器来赋予 CRD 生命。

然后，我们讨论了针对 Kubernetes 的特定于云供应商的扩展，包括`cloud-controller-manager`、`external-dns`和`cluster-autoscaler`。最后，我们介绍了大型云原生开源生态系统以及发现适合你使用情况的项目的一些好方法。

本章中使用的技能将帮助您扩展 Kubernetes 集群，以便与您的云提供商以及您自己的自定义功能进行接口。

在下一章中，我们将讨论作为应用于 Kubernetes 的两种新兴架构模式 - 无服务器和服务网格。

# 问题

1.  什么是 CRD 的服务版本和存储版本之间的区别？

1.  自定义控制器或操作员控制循环的三个典型部分是什么？

1.  `cluster-autoscaler`如何与现有的云提供商扩展解决方案（如 AWS 自动扩展组）交互？

# 进一步阅读

+   CNCF 景观：[`landscape.cncf.io/`](https://landscape.cncf.io/)

+   官方 Kubernetes 论坛：[`discuss.kubernetes.io/`](https://discuss.kubernetes.io/)


# 第十四章：服务网格和无服务器

本章讨论了高级 Kubernetes 模式。首先，它详细介绍了时髦的服务网格模式，其中通过 sidecar 代理处理可观察性和服务到服务的发现，以及设置流行的服务网格 Istio 的指南。最后，它描述了无服务器模式以及如何在 Kubernetes 中应用它。本章的主要案例研究将包括为示例应用程序和服务发现设置 Istio，以及 Istio 入口网关。

让我们从讨论 sidecar 代理开始，它为服务网格的服务到服务连接性奠定了基础。

在本章中，我们将涵盖以下主题：

+   使用 sidecar 代理

+   向 Kubernetes 添加服务网格

+   在 Kubernetes 上实现无服务器

# 技术要求

为了运行本章中详细介绍的命令，您需要一台支持`kubectl`命令行工具的计算机，以及一个可用的 Kubernetes 集群。请参阅*第一章*，*与 Kubernetes 通信*，了解快速启动和运行 Kubernetes 的几种方法，以及如何安装`kubectl`工具的说明。

本章中使用的代码可以在书的 GitHub 存储库中找到，网址为[`github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter14`](https://github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter14)。

# 使用 sidecar 代理

正如我们在本书中早些时候提到的，sidecar 是一种模式，其中一个 Pod 包含另一个容器，除了要运行的实际应用程序容器。这个额外的“额外”容器就是 sidecar。Sidecar 可以用于许多不同的原因。一些最常用的 sidecar 用途是监控、日志记录和代理。

对于日志记录，一个 sidecar 容器可以从应用容器中获取应用程序日志（因为它们可以共享卷并在本地通信），然后将日志发送到集中式日志堆栈，或者解析它们以进行警报。监控也是类似的情况，sidecar Pod 可以跟踪并发送有关应用程序 Pod 的指标。

使用侧车代理时，当请求进入 Pod 时，它们首先进入代理容器，然后路由请求（在记录或执行其他过滤之后）到应用程序容器。同样，当请求离开应用程序容器时，它们首先进入代理，代理可以提供 Pod 的路由。

通常，诸如 NGINX 之类的代理侧车只为进入 Pod 的请求提供代理。然而，在服务网格模式中，进入和离开 Pod 的请求都通过代理，这为服务网格模式本身提供了基础。

请参考以下图表，了解侧车代理如何与应用程序容器交互：

![图 14.1 - 代理侧车](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_14_001.jpg)

图 14.1 - 代理侧车

正如您所看到的，侧车代理负责将请求路由到 Pod 中的应用程序容器，并允许功能，如服务路由、记录和过滤。

侧车代理模式是一种替代基于 DaemonSet 的代理，其中每个节点上的代理 Pod 处理对该节点上其他 Pod 的代理。Kubernetes 代理本身类似于 DaemonSet 模式。使用侧车代理可以提供比使用 DaemonSet 代理更灵活的灵活性，但性能效率会有所降低，因为需要运行许多额外的容器。

一些用于 Kubernetes 的流行代理选项包括以下内容：

+   *NGINX*

+   *HAProxy*

+   *Envoy*

虽然 NGINX 和 HAProxy 是更传统的代理，但 Envoy 是专门为分布式、云原生环境构建的。因此，Envoy 构成了流行的服务网格和为 Kubernetes 构建的 API 网关的核心。

在我们讨论 Envoy 之前，让我们讨论安装其他代理作为侧车的方法。

## 使用 NGINX 作为侧车反向代理

在我们指定 NGINX 如何作为侧车代理之前，值得注意的是，在即将发布的 Kubernetes 版本中，侧车将成为一个 Kubernetes 资源类型，它将允许轻松地向大量 Pod 注入侧车容器。然而，目前侧车容器必须在 Pod 或控制器（ReplicaSet、Deployment 等）级别指定。

让我们看看如何使用以下部署 YAML 配置 NGINX 作为侧车，我们暂时不会创建。这个过程比使用 NGINX Ingress Controller 要手动一些。

出于空间原因，我们将 YAML 分成两部分，并删除了一些冗余内容，但您可以在代码存储库中完整地看到它。让我们从部署的容器规范开始：

Nginx-sidecar.yaml：

```
   spec:
     containers:
     - name: myapp
       image: ravirdv/http-responder:latest
       imagePullPolicy: IfNotPresent
     - name: nginx-sidecar
       image: nginx
       imagePullPolicy: IfNotPresent
       volumeMounts:
         - name: secrets
           mountPath: /app/cert
         - name: config
           mountPath: /etc/nginx/nginx.conf
           subPath: nginx.conf
```

正如您所看到的，我们指定了两个容器，即我们的主应用程序容器`myapp`和`nginx` sidecar，我们通过卷挂载注入了一些配置，以及一些 TLS 证书。

接下来，让我们看看同一文件中的`volumes`规范，我们在其中注入了一些证书（来自一个密钥）和`config`（来自`ConfigMap`）：

```
    volumes:
     - name: secrets
       secret:
         secretName: nginx-certificates
         items:
           - key: server-cert
             path: server.pem
           - key: server-key
             path: server-key.pem
     - name: config
       configMap:
         name: nginx-configuration
```

正如您所看到的，我们需要一个证书和一个密钥。

接下来，我们需要使用`ConfigMap`创建 NGINX 配置。NGINX 配置如下：

nginx.conf：

```
http {
    sendfile        on;
    include       mime.types;
    default_type  application/octet-stream;
    keepalive_timeout  80;
    server {
       ssl_certificate      /app/cert/server.pem;
      ssl_certificate_key  /app/cert/server-key.pem;
      ssl_protocols TLSv1.2;
      ssl_ciphers EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:!EECDH+3DES:!RSA+3DES:!MD5;
      ssl_prefer_server_ciphers on;
      listen       443 ssl;
      server_name  localhost;
      location / {
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_pass http://127.0.0.1:5000/;
      }
    }
}
worker_processes  1;
events {
    worker_connections  1024;
}
```

正如您所看到的，我们有一些基本的 NGINX 配置。重要的是，我们有`proxy_pass`字段，它将请求代理到`127.0.0.1`上的端口，或者本地主机。由于 Pod 中的容器可以共享本地主机端口，这充当了我们的 sidecar 代理。出于本书的目的，我们不会审查所有其他行，但是请查看 NGINX 文档，了解每行的更多信息（[`nginx.org/en/docs/`](https://nginx.org/en/docs/)）。

现在，让我们从这个文件创建`ConfigMap`。使用以下命令来命令式地创建`ConfigMap`：

```
kubectl create cm nginx-configuration --from-file=nginx.conf=./nginx.conf
```

这将导致以下输出：

```
Configmap "nginx-configuration" created
```

接下来，让我们为 NGINX 创建 TLS 证书，并将它们嵌入到 Kubernetes 密钥中。您需要安装 CFSSL（CloudFlare 的 PKI/TLS 开源工具包）库才能按照这些说明进行操作，但您也可以使用任何其他方法来创建您的证书。

首先，我们需要创建**证书颁发机构**（**CA**）。从 CA 的 JSON 配置开始：

nginxca.json：

```
{
   "CN": "mydomain.com",
   "hosts": [
       "mydomain.com",
       "www.mydomain.com"
   ],
   "key": {
       "algo": "rsa",
       "size": 2048
   },
   "names": [
       {
           "C": "US",
           "ST": "MD",
           "L": "United States"
       }
   ]
}
```

现在，使用 CFSSL 创建 CA 证书：

```
cfssl gencert -initca nginxca.json | cfssljson -bare nginxca
```

接下来，我们需要 CA 配置：

Nginxca-config.json：

```
{
  "signing": {
      "default": {
          "expiry": "20000h"
      },
      "profiles": {
          "client": {
              "expiry": "43800h",
              "usages": [
                  "signing",
                  "key encipherment",
                  "client auth"
              ]
          },
          "server": {
              "expiry": "20000h",
              "usages": [
                  "signing",
                  "key encipherment",
                  "server auth",
                  "client auth"
              ]
          }
      }
  }
}
```

我们还需要一个证书请求配置：

Nginxcarequest.json：

```
{
  "CN": "server",
  "hosts": [
    ""
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  }
}
```

现在，我们实际上可以创建我们的证书了！使用以下命令：

```
cfssl gencert -ca=nginxca.pem -ca-key=nginxca-key.pem -config=nginxca-config.json -profile=server -hostname="127.0.0.1" nginxcarequest.json | cfssljson -bare server
```

作为证书密钥的最后一步，通过最后一个`cfssl`命令从证书文件的输出创建 Kubernetes 密钥：

```
kubectl create secret generic nginx-certs --from-file=server-cert=./server.pem --from-file=server-key=./server-key.pem
```

现在，我们终于可以创建我们的部署了：

```
kubectl apply -f nginx-sidecar.yaml 
```

这将产生以下输出：

```
deployment "myapp" created
```

为了检查 NGINX 代理功能，让我们创建一个服务来指向我们的部署：

Nginx-sidecar-service.yaml：

```
apiVersion: v1
kind: Service
metadata:
 name:myapp
 labels:
   app: myapp
spec:
 selector:
   app: myapp
 type: NodePort
 ports:
 - port: 443
   targetPort: 443
   protocol: TCP
   name: https
```

现在，使用`https`访问集群中的任何节点应该会导致一个正常工作的 HTTPS 连接！但是，由于我们的证书是自签名的，浏览器将显示一个*不安全*的消息。

现在您已经看到了 NGINX 如何与 Kubernetes 一起作为边车代理使用，让我们转向更现代的、云原生的代理边车 - Envoy。

## 使用 Envoy 作为边车代理

Envoy 是为云原生环境构建的现代代理。在我们稍后将审查的 Istio 服务网格中，Envoy 充当反向和正向代理。然而，在我们进入 Istio 之前，让我们尝试部署 Envoy 作为代理。

我们将告诉 Envoy 在哪里路由各种请求，使用路由、监听器、集群和端点。这个功能是 Istio 的核心，我们将在本章后面进行审查。

让我们逐个查看 Envoy 配置的每个部分，看看它是如何工作的。

### Envoy 监听器

Envoy 允许配置一个或多个监听器。对于每个监听器，我们指定 Envoy 要监听的端口，以及我们想要应用到监听器的任何过滤器。

过滤器可以提供复杂的功能，包括缓存、授权、**跨源资源共享**（**CORS**）配置等。Envoy 支持将多个过滤器链接在一起。

### Envoy 路由

某些过滤器具有路由配置，指定应接受请求的域、路由匹配和转发规则。

### Envoy 集群

Envoy 中的集群表示可以根据监听器中的路由将请求路由到的逻辑服务。在云原生环境中，集群可能包含多个可能的 IP 地址，因此它支持负载均衡配置，如*轮询*。

### Envoy 端点

最后，在集群中指定端点作为服务的一个逻辑实例。Envoy 支持从 API 获取端点列表（这基本上是 Istio 服务网格中发生的事情），并在它们之间进行负载均衡。

在 Kubernetes 上的生产 Envoy 部署中，很可能会使用某种形式的动态、API 驱动的 Envoy 配置。Envoy 的这个特性称为 xDS，并被 Istio 使用。此外，还有其他开源产品和解决方案使用 Envoy 与 xDS，包括 Ambassador API 网关。

在本书中，我们将查看一些静态（非动态）的 Envoy 配置；这样，我们可以分解配置的每个部分，当我们审查 Istio 时，您将对一切是如何工作有一个很好的理解。

现在让我们深入研究一个 Envoy 配置，用于设置一个单个 Pod 需要能够将请求路由到两个服务，*Service 1*和*Service 2*。设置如下：

![图 14.2-出站 envoy 代理](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_14_002.jpg)

图 14.2-出站 envoy 代理

如您所见，我们应用 Pod 中的 Envoy sidecar 将配置为路由到两个上游服务，*Service 1*和*Service 2*。两个服务都有两个可能的端点。

在 Envoy xDS 的动态设置中，端点的 Pod IPs 将从 API 中加载，但是为了我们的审查目的，我们将在端点中显示静态的 Pod IPs。我们将完全忽略 Kubernetes 服务，而是直接访问 Pod IPs 以进行轮询配置。在服务网格场景中，Envoy 也将部署在所有目标 Pod 上，但现在我们将保持简单。

现在，让我们看看如何在 Envoy 配置 YAML 中配置这个网络映射（您可以在代码存储库中找到完整的配置）。这当然与 Kubernetes 资源 YAML 非常不同-我们将在稍后讨论这一部分。整个配置涉及大量的 YAML，所以让我们一点一点地来。

### 理解 Envoy 配置文件

首先，让我们看看我们配置的前几行-关于我们的 Envoy 设置的一些基本信息。

Envoy-configuration.yaml:

```
admin:
  access_log_path: "/dev/null"
  address:
    socket_address:
      address: 0.0.0.0
      port_value: 8001
```

如您所见，我们为 Envoy 的`admin`指定了一个端口和地址。与以下配置一样，我们将 Envoy 作为一个 sidecar 运行，因此地址将始终是本地的- `0.0.0.0`。接下来，我们用一个 HTTPS 监听器开始我们的监听器列表：

```
static_resources:
  listeners:
   - address:
      socket_address:
        address: 0.0.0.0
        port_value: 8443
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.config.filter.network.http_connection_manager.v2.HttpConnectionManager
          stat_prefix: ingress_https
          codec_type: auto
          route_config:
            name: local_route
            virtual_hosts:
            - name: backend
              domains:
              - "*"
              routes:
              - match:
                  prefix: "/service/1"
                route:
                  cluster: service1
              - match:
                  prefix: "/service/2"
                route:
                  cluster: service2
          http_filters:
          - name: envoy.filters.http.router
            typed_config: {}
```

如您所见，对于每个 Envoy 监听器，我们有一个本地地址和端口（此监听器是一个 HTTPS 监听器）。然后，我们有一个过滤器列表-尽管在这种情况下，我们只有一个。每个 envoy 过滤器类型的配置略有不同，我们不会逐行审查它（请查看 Envoy 文档以获取更多信息[`www.envoyproxy.io/docs`](https://www.envoyproxy.io/docs)），但这个特定的过滤器匹配两个路由，`/service/1`和`/service/2`，并将它们路由到两个 envoy 集群。在我们的 YAML 的第一个 HTTPS 监听器部分下，我们有 TLS 配置，包括证书：

```
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_certificates:
              certificate_chain:
                inline_string: |
                   <INLINE CERT FILE>
              private_key:
                inline_string: |
                  <INLINE PRIVATE KEY FILE>
```

如您所见，此配置传递了`private_key`和`certificate_chain`。接下来，我们有第二个也是最后一个监听器，一个 HTTP 监听器：

```
  - address:
      socket_address:
        address: 0.0.0.0
        port_value: 8080
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.config.filter.network.http_connection_manager.v2.HttpConnectionManager
          codec_type: auto
          stat_prefix: ingress_http
          route_config:
            name: local_route
            virtual_hosts:
            - name: backend
              domains:
              - "*"
              routes:
              - match:
                  prefix: "/service1"
                route:
                  cluster: service1
              - match:
                  prefix: "/service2"
                route:
                  cluster: service2
          http_filters:
          - name: envoy.filters.http.router
            typed_config: {}
```

如您所见，这个配置与我们的 HTTPS 监听器的配置非常相似，只是它监听不同的端口，并且不包括证书信息。接下来，我们进入我们的集群配置。在我们的情况下，我们有两个集群，一个用于`service1`，一个用于`service2`。首先是`service1`：

```
  clusters:
  - name: service1
    connect_timeout: 0.25s
    type: strict_dns
    lb_policy: round_robin
    http2_protocol_options: {}
    load_assignment:
      cluster_name: service1
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: service1
                port_value: 5000
```

接下来，`Service 2`：

```
  - name: service2
    connect_timeout: 0.25s
    type: strict_dns
    lb_policy: round_robin
    http2_protocol_options: {}
    load_assignment:
      cluster_name: service2
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: service2
                port_value: 5000
```

对于这些集群中的每一个，我们指定请求应该路由到哪里，以及到哪个端口。例如，对于我们的第一个集群，请求被路由到`http://service1:5000`。我们还指定了负载均衡策略（在这种情况下是轮询）和连接的超时时间。现在我们有了我们的 Envoy 配置，我们可以继续创建我们的 Kubernetes Pod，并注入我们的 sidecar 以及 envoy 配置。我们还将把这个文件分成两部分，因为它有点太大了，以至于难以理解：

Envoy-sidecar-deployment.yaml：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-service
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: my-service
    spec:
      containers:
      - name: envoy
        image: envoyproxy/envoy:latest
        ports:
          - containerPort: 9901
            protocol: TCP
            name: envoy-admin
          - containerPort: 8786
            protocol: TCP
            name: envoy-web
```

如您所见，这是一个典型的部署 YAML。在这种情况下，我们实际上有两个容器。首先是 Envoy 代理容器（或边车）。它监听两个端口。接下来，继续向下移动 YAML，我们为第一个容器进行了卷挂载（用于保存 Envoy 配置），以及一个启动命令和参数：

```
        volumeMounts:
          - name: envoy-config-volume
            mountPath: /etc/envoy-config/
        command: ["/usr/local/bin/envoy"]
        args: ["-c", "/etc/envoy-config/config.yaml", "--v2-config-only", "-l", "info","--service-cluster","myservice","--service-node","myservice", "--log-format", "[METADATA][%Y-%m-%d %T.%e][%t][%l][%n] %v"]
```

最后，我们有我们 Pod 中的第二个容器，这是一个应用容器：

```
- name: my-service
        image: ravirdv/http-responder:latest
        ports:
        - containerPort: 5000
          name: svc-port
          protocol: TCP
      volumes:
        - name: envoy-config-volume
          configMap:
            name: envoy-config
            items:
              - key: envoy-config
                path: config.yaml
```

如您所见，这个应用在端口`5000`上响应。最后，我们还有我们的 Pod 级别卷定义，以匹配 Envoy 容器中挂载的 Envoy 配置卷。在创建部署之前，我们需要创建一个带有我们的 Envoy 配置的`ConfigMap`。我们可以使用以下命令来做到这一点：

```
kubectl create cm envoy-config 
--from-file=config.yaml=./envoy-config.yaml
```

这将导致以下输出：

```
Configmap "envoy-config" created
```

现在我们可以使用以下命令创建我们的部署：

```
kubectl apply -f deployment.yaml
```

这将导致以下输出：

```
Deployment "my-service" created
```

最后，我们需要我们的下游服务，`service1`和`service2`。为此，我们将继续使用`http-responder`开源容器映像，在端口`5000`上进行响应。部署和服务规范可以在代码存储库中找到，并且我们可以使用以下命令创建它们：

```
kubectl create -f service1-deployment.yaml
kubectl create -f service1-service.yaml
kubectl create -f service2-deployment.yaml
kubectl create -f service2-service.yaml
```

现在，我们可以测试我们的 Envoy 配置！从我们的`my-service`容器中，我们可以向端口`8080`的本地主机发出请求，路径为`/service1`。这应该会指向我们的`service1` Pod IP 之一。为了发出这个请求，我们使用以下命令：

```
Kubectl exec <my-service-pod-name> -it -- curl localhost:8080/service1
```

我们已经设置了我们的服务来在`curl`请求上回显它们的名称。看一下我们`curl`命令的以下输出：

```
Service 1 Reached!
```

现在我们已经看过了 Envoy 如何与静态配置一起工作，让我们转向基于 Envoy 的动态服务网格 - Istio。

# 在 Kubernetes 中添加服务网格

*服务网格*模式是侧车代理的逻辑扩展。通过将侧车代理附加到每个 Pod，服务网格可以控制服务之间的功能，如高级路由规则、重试和超时。此外，通过让每个请求通过代理，服务网格可以实现服务之间的相互 TLS 加密，以增加安全性，并且可以让管理员对集群中的请求有非常好的可观察性。

有几个支持 Kubernetes 的服务网格项目。最流行的如下：

+   Istio

+   Linkerd

+   *Kuma*

+   Consul

这些服务网格中的每一个对服务网格模式有不同的看法。*Istio*可能是最流行和最全面的解决方案，但也非常复杂。*Linkerd*也是一个成熟的项目，但更容易配置（尽管它使用自己的代理而不是 Envoy）。*Consul*是一个支持 Envoy 以及其他提供者的选项，不仅仅在 Kubernetes 上。最后，*Kuma*是一个基于 Envoy 的选项，也在不断增长。

探索所有选项超出了本书的范围，因此我们将坚持使用 Istio，因为它通常被认为是默认解决方案。也就是说，所有这些网格都有优势和劣势，在计划采用服务网格时值得看看每一个。

## 在 Kubernetes 上设置 Istio

虽然 Istio 可以使用 Helm 安装，但 Helm 安装选项不再是官方支持的安装方法。

相反，我们使用`Istioctl` CLI 工具将 Istio 与配置安装到我们的集群上。这个配置可以完全定制，但是为了本书的目的，我们将只使用"demo"配置：

1.  在集群上安装 Istio 的第一步是安装 Istio CLI 工具。我们可以使用以下命令来完成这个操作，这将安装最新版本的 CLI 工具：

```
curl -L https://istio.io/downloadIstio | sh -
```

1.  接下来，我们将希望将 CLI 工具添加到我们的路径中，以便使用：

```
cd istio-<VERSION>
export PATH=$PWD/bin:$PATH
```

1.  现在，让我们安装 Istio！Istio 的配置被称为*配置文件*，如前所述，它们可以使用 YAML 文件进行完全定制。

对于这个演示，我们将使用内置的`demo`配置文件与 Istio 一起使用，这提供了一些基本设置。使用以下命令安装配置文件：

```
istioctl install --set profile=demo
```

这将导致以下输出：

![图 14.3 - Istioctl 配置文件安装输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_14_003.jpg)

图 14.3 - Istioctl 配置文件安装输出

1.  由于截至 Kubernetes 1.19，sidecar 资源尚未发布，因此 Istio 本身将在任何打上`istio-injection=enabled`标签的命名空间中注入 Envoy 代理。

要为任何命名空间打上标签，请运行以下命令：

```
kubectl label namespace my-namespace istio-injection=enabled
```

1.  为了方便测试，使用前面的`label`命令为`default`命名空间打上标签。一旦 Istio 组件启动，该命名空间中的任何 Pod 将自动注入 Envoy sidecar，就像我们在上一节中手动创建的那样。

要从集群中删除 Istio，请运行以下命令：

```
istioctl x uninstall --purge
```

这应该会出现一个确认消息，告诉您 Istio 已被移除。

1.  现在，让我们部署一些东西来测试我们的新网格！我们将部署三种不同的应用服务，每个都有一个部署和一个服务资源：

a. 服务前端

b. 服务后端 A

c. 服务后端 B

这是*服务前端*的部署：

Istio-service-deployment.yaml：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: service-frontend
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: service-frontend
        version: v2
    spec:
      containers:
      - name: service-frontend
        image: ravirdv/http-responder:latest
        ports:
        - containerPort: 5000
          name: svc-port
          protocol: TCP
```

这是*服务前端*的服务：

Istio-service-service.yaml：

```
apiVersion: v1
kind: Service
metadata:
  name: service-frontend
spec:
  selector:
    name: service-frontend
  ports:
    - protocol: TCP
      port: 80
      targetPort: 5000
```

服务后端 A 和 B 的 YAML 与*服务前端*相同，除了交换名称、镜像名称和选择器标签。

1.  现在我们有了一些要路由到（和之间）的服务，让我们开始设置一些 Istio 资源！

首先，我们需要一个`Gateway`资源。在这种情况下，我们不使用 NGINX Ingress Controller，但这没关系，因为 Istio 提供了一个可以用于入口和出口的`Gateway`资源。以下是 Istio`Gateway`定义的样子：

Istio-gateway.yaml：

```
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: myapplication-gateway
spec:
  selector:
    istio: ingressgateway
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - "*"
```

这些`Gateway`定义看起来与入口记录非常相似。我们有`name`和`selector`，Istio 用它们来决定使用哪个 Istio Ingress Controller。接下来，我们有一个或多个服务器，它们实质上是我们网关上的入口点。在这种情况下，我们不限制主机，并且接受端口`80`上的请求。

1.  现在我们有了一个用于将请求发送到我们的集群的网关，我们可以开始设置一些路由。我们在 Istio 中使用`VirtualService`来做到这一点。Istio 中的`VirtualService`是一组应该遵循的路由，当对特定主机名的请求时。此外，我们可以使用通配符主机来为网格中的任何地方的请求制定全局规则。让我们看一个示例`VirtualService`配置：

Istio-virtual-service-1.yaml：

```
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: myapplication
spec:
  hosts:
  - "*"
  gateways:
  - myapplication-gateway
  http:
  - match:
    - uri:
        prefix: /app
    - uri:
        prefix: /frontend
    route:
    - destination:
        host: service-frontend
        subset: v1
```

在这个`VirtualService`中，如果匹配我们的`uri`前缀，我们将请求路由到任何主机到我们的入口点*Service Frontend*。在这种情况下，我们匹配前缀，但你也可以在 URI 匹配器中使用精确匹配，将`prefix`替换为`exact`。

1.  所以，现在我们有一个设置，与我们预期的 NGINX Ingress 非常相似，入口进入集群由路由匹配决定。

然而，在我们的路由中，`v1`是什么？这实际上代表了我们*Frontend Service*的一个版本。让我们继续使用一个新的资源类型 - Istio `DestinationRule`来指定这个版本。这是一个`DestinationRule`配置的样子：

Istio-destination-rule-1.yaml:

```
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: service-frontend
spec:
  host: service-frontend
  subsets:
  - name: v1
    labels:
      version: v1
  - name: v2
    labels:
      version: v2
```

正如你所看到的，我们在 Istio 中指定了我们前端服务的两个不同版本，每个版本都查看一个标签选择器。从我们之前的部署和服务中，你可以看到我们当前的前端服务版本是`v2`，但我们也可以并行运行两者！通过在入口虚拟服务中指定我们的`v2`版本，我们告诉 Istio 将所有请求路由到服务的`v2`。此外，我们还配置了我们的`v1`版本，它在之前的`VirtualService`中被引用。这个硬规则只是在 Istio 中将请求路由到不同子集的一种可能的方式。

现在，我们已经成功通过网关将流量路由到我们的集群，并基于目标规则路由到虚拟服务子集。在这一点上，我们实际上已经“在”我们的服务网格中！

1.  现在，从我们的*Service Frontend*，我们希望能够路由到*Service Backend A*和*Service Backend B*。我们该怎么做？更多的虚拟服务就是答案！让我们来看看*Backend Service A*的虚拟服务：

Istio-virtual-service-2.yaml:

```
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: myapplication-a
spec:
  hosts:
  - service-a
  http:
    route:
    - destination:
        host: service-backend-a
        subset: v1
```

正如你所看到的，这个`VirtualService`路由到我们服务的`v1`子集，`service-backend-a`。我们还需要另一个`VirtualService`用于`service-backend-b`，我们不会完全包含（但看起来几乎相同）。要查看完整的 YAML，请检查`istio-virtual-service-3.yaml`的代码存储库。

1.  一旦我们的虚拟服务准备好了，我们需要一些目标规则！*Backend Service A*的`DestinationRule`如下：

Istio-destination-rule-2.yaml:

```
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: service-backend-a
spec:
  host: service-backend-a
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
  subsets:
  - name: v1
    labels:
      version: v1
```

*Backend Service B*的`DestinationRule`类似，只是有不同的子集。我们不会包含代码，但是在代码存储库中检查`istio-destination-rule-3.yaml`以获取确切的规格。

这些目标规则和虚拟服务相加，形成了以下路由图：

![图 14.4 - Istio 路由图](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_14_004.jpg)

图 14.4 - Istio 路由图

正如您所看到的，来自“前端服务”Pod 的请求可以路由到“后端服务 A 版本 1”或“后端服务 B 版本 3”，每个后端服务也可以相互路由。对后端服务 A 或 B 的这些请求还额外利用了 Istio 的最有价值的功能之一 - 双向 TLS。在这种设置中，网格中的任何两点之间都会自动保持 TLS 安全。

接下来，让我们看看如何在 Kubernetes 上使用无服务器模式。

# 在 Kubernetes 上实现无服务器

云提供商上的无服务器模式迅速变得越来越受欢迎。无服务器架构由可以自动扩展的计算组成，甚至可以扩展到零（即没有使用计算容量来提供函数或其他应用）。函数即服务（FaaS）是无服务器模式的扩展，其中函数代码是唯一的输入，无服务器系统负责根据需要路由请求到计算资源并进行扩展。AWS Lambda、Azure Functions 和 Google Cloud Run 是一些更受欢迎的 FaaS/无服务器选项，它们得到了云提供商的官方支持。Kubernetes 还有许多不同的无服务器框架和库，可以用于在 Kubernetes 上运行无服务器、扩展到零的工作负载以及 FaaS。其中一些最受欢迎的如下：

+   Knative

+   Kubeless

+   OpenFaaS

+   Fission

关于 Kubernetes 上所有无服务器选项的全面讨论超出了本书的范围，因此我们将专注于两种不同的选项，它们旨在满足两种完全不同的用例：OpenFaaS 和 Knative。

虽然 Knative 非常可扩展和可定制，但它使用了多个耦合的组件，增加了复杂性。这意味着需要一些额外的配置才能开始使用 FaaS 解决方案，因为函数只是 Knative 支持的许多其他模式之一。另一方面，OpenFaaS 使得在 Kubernetes 上轻松启动和运行无服务器和 FaaS 变得非常容易。这两种技术出于不同的原因都是有价值的。

在本章的教程中，我们将看看 Knative，这是最流行的无服务器框架之一，也支持通过其事件功能的 FaaS。

## 在 Kubernetes 上使用 Knative 进行 FaaS

如前所述，Knative 是用于 Kubernetes 上无服务器模式的模块化构建块。因此，在我们实际使用函数之前，它需要一些配置。Knative 也可以与 Istio 一起安装，它用作路由和扩展无服务器应用程序的基础。还有其他非 Istio 路由选项可用。

使用 Knative 进行 FaaS，我们需要安装*Knative Serving*和*Knative Eventing*。Knative Serving 将允许我们运行无服务器工作负载，而 Knative Eventing 将提供通道来向这些规模为零的工作负载发出 FaaS 请求。让我们按照以下步骤来完成这个过程：

1.  首先，让我们安装 Knative Serving 组件。我们将从安装 CRDs 开始：

```
kubectl apply --filename https://github.com/knative/serving/releases/download/v0.18.0/serving-crds.yaml
```

1.  接下来，我们可以安装服务组件本身：

```
kubectl apply --filename https://github.com/knative/serving/releases/download/v0.18.0/serving-core.yaml
```

1.  此时，我们需要安装一个网络/路由层供 Knative 使用。让我们使用 Istio：

```
kubectl apply --filename https://github.com/knative/net-istio/releases/download/v0.18.0/release.yaml
```

1.  我们需要从 Istio 获取网关 IP 地址。根据您运行的位置（换句话说，是在 AWS 还是本地），此值可能会有所不同。使用以下命令获取它：

```
Kubectl get service -n istio-system istio-ingressgateway
```

1.  Knative 需要特定的 DNS 设置来启用服务组件。在云设置中最简单的方法是使用`xip.io`的“Magic DNS”，尽管这对基于 Minikube 的集群不起作用。如果您正在运行其中之一（或者只是想查看所有可用选项），请查看[Knative 文档](https://knative.dev/docs/install/any-kubernetes-cluster/)。

要设置 Magic DNS，请使用以下命令：

```
kubectl apply --filename https://github.com/knative/serving/releases/download/v0.18.0/serving-default-domain.yaml
```

1.  现在我们已经安装了 Knative Serving，让我们安装 Knative Eventing 来处理我们的 FaaS 请求。首先，我们需要更多的 CRDs。使用以下命令安装它们：

```
kubectl apply --filename https://github.com/knative/eventing/releases/download/v0.18.0/eventing-crds.yaml
```

1.  现在，安装事件组件，就像我们安装服务一样：

```
kubectl apply --filename https://github.com/knative/eventing/releases/download/v0.18.0/eventing-core.yaml
```

在这一点上，我们需要为我们的事件系统添加一个队列/消息层来使用。我们是否提到 Knative 支持许多模块化组件？

重要提示

为了简化事情，让我们只使用基本的内存消息层，但了解所有可用选项对您也是有好处的。关于消息通道的模块化选项，请查看[`knative.dev/docs/eventing/channels/channels-crds/`](https://knative.dev/docs/eventing/channels/channels-crds/)上的文档。对于事件源选项，您可以查看[`knative.dev/docs/eventing/sources/`](https://knative.dev/docs/eventing/sources/)。

1.  安装`in-memory`消息层，请使用以下命令：

```
kubectl apply --filename https://github.com/knative/eventing/releases/download/v0.18.0/in-memory-channel.yaml
```

1.  以为我们已经完成了？不！还有最后一件事。我们需要安装一个 broker，它将从消息层获取事件并将它们处理到正确的位置。让我们使用默认的 broker 层，MT-Channel broker 层。您可以使用以下命令安装它：

```
kubectl apply --filename https://github.com/knative/eventing/releases/download/v0.18.0/mt-channel-broker.yaml
```

到此为止，我们终于完成了。我们通过 Knative 安装了一个端到端的 FaaS 实现。正如你所看到的，这并不是一项容易的任务。Knative 令人惊奇的地方与令人头疼的地方是一样的——它提供了许多不同的模块选项和配置，即使在每个步骤选择了最基本的选项，我们仍然花了很多时间来解释安装过程。还有其他可用的选项，比如 OpenFaaS，它们更容易上手，我们将在下一节中进行探讨！然而，在 Knative 方面，现在我们的设置终于准备好了，我们可以添加我们的 FaaS。

### 在 Knative 中实现 FaaS 模式

现在我们已经设置好了 Knative，我们可以使用它来实现一个 FaaS 模式，其中事件将通过触发器触发在 Knative 中运行的一些代码。要设置一个简单的 FaaS，我们将需要三样东西：

+   一个从入口点路由我们的事件的 broker

+   一个消费者服务来实际处理我们的事件

+   一个指定何时将事件路由到消费者进行处理的触发器定义

首先，我们需要创建我们的 broker。这很简单，类似于创建入口记录或网关。我们的`broker` YAML 如下所示：

Knative-broker.yaml：

```
apiVersion: eventing.knative.dev/v1
kind: broker
metadata:
 name: my-broker
 namespace: default
```

接下来，我们可以创建一个消费者服务。这个组件实际上就是我们的应用程序，它将处理事件——我们的函数本身！我们不打算向你展示比你已经看到的更多的 YAML，让我们假设我们的消费者服务只是一个名为`service-consumer`的普通的 Kubernetes 服务，它路由到一个运行我们应用程序的四个副本的 Pod 部署。

最后，我们需要一个触发器。这决定了如何以及哪些事件将从 broker 路由。触发器的 YAML 如下所示：

Knative-trigger.yaml：

```
apiVersion: eventing.knative.dev/v1
kind: Trigger
metadata:
  name: my-trigger
spec:
  broker: my-broker
  filter:
    attributes:
      type: myeventtype
  subscriber:
    ref:
     apiVersion: v1
     kind: Service
     name: service-consumer
```

在这个 YAML 中，我们创建了一个 `Trigger` 规则，任何通过我们的经纪人 `my-broker` 并且类型为 `myeventtype` 的事件将自动路由到我们的消费者 `service-consumer`。有关 Knative 中触发器过滤器的完整文档，请查看 [`knative.dev/development/eventing/triggers/`](https://knative.dev/development/eventing/triggers/) 上的文档。

那么，我们如何创建一些事件呢？首先，使用以下命令检查经纪人 URL：

```
kubectl get broker
```

这应该会产生以下输出：

```
NAME      READY   REASON   URL                                                                                 AGE
my-broker   True             http://broker-ingress.knative-eventing.svc.cluster.local/default/my-broker     1m
```

现在我们终于可以测试我们的 FaaS 解决方案了。让我们快速启动一个 Pod，从中我们可以向我们的触发器发出请求：

```
kubectl run -i --tty --rm debug --image=radial/busyboxplus:curl --restart=Never -- sh
```

现在，从这个 Pod 内部，我们可以继续测试我们的触发器，使用 `curl`。我们需要发出的请求需要有一个等于 `myeventtype` 的 `Ce-Type` 标头，因为这是我们触发器所需的。Knative 使用形式为 `Ce-Id`、`Ce-Type` 的标头，如下面的代码块所示，来进行路由。

`curl` 请求将如下所示：

```
curl -v "http://broker-ingress.knative-eventing.svc.cluster.local/default/my-broker" \
  -X POST \
  -H "Ce-Id: anyid" \
  -H "Ce-Specversion: 1.0" \
  -H "Ce-Type: myeventtype" \
  -H "Ce-Source: any" \
  -H "Content-Type: application/json" \
  -d '{"payload":"Does this work?"}'
```

正如您所看到的，我们正在向经纪人 URL 发送 `curl` `http` 请求。此外，我们还在 HTTP 请求中传递了一些特殊的标头。重要的是，我们传递了 `type=myeventtype`，这是我们触发器上的过滤器所需的，以便发送请求进行处理。

在这个例子中，我们的消费者服务会回显请求的 JSON 主体的 payload 键，以及一个 `200` 的 HTTP 响应，因此运行这个 `curl` 请求会给我们以下结果：

```
> HTTP/1.1 200 OK
> Content-Type: application/json
{
  "Output": "Does this work?"
}
```

成功！我们已经测试了我们的 FaaS，并且它返回了我们期望的结果。从这里开始，我们的解决方案将根据事件的数量进行零扩展和缩减，与 Knative 的所有内容一样，还有许多自定义和配置选项，可以精确地调整我们的解决方案以满足我们的需求。

接下来，我们将使用 OpenFaaS 而不是 Knative 来查看相同的模式，以突出两种方法之间的区别。

## 在 Kubernetes 上使用 OpenFaaS 进行 FaaS

现在我们已经讨论了如何开始使用 Knative，让我们用 OpenFaaS 做同样的事情。首先，要安装 OpenFaaS 本身，我们将使用来自 `faas-netes` 仓库的 Helm 图表，该仓库位于 [`github.com/openfaas/faas-netes`](https://github.com/openfaas/faas-netes)。

### 使用 Helm 安装 OpenFaaS 组件

首先，我们将创建两个命名空间来保存我们的 OpenFaaS 组件：

+   `openfaas` 用于保存 OpenFaas 的实际服务组件

+   `openfaas-fn` 用于保存我们部署的函数

我们可以使用以下命令使用`faas-netes`存储库中的一个巧妙的 YAML 文件来添加这两个命名空间：

```
kubectl apply -f https://raw.githubusercontent.com/openfaas/faas-netes/master/namespaces.yml
```

接下来，我们需要使用以下 Helm 命令添加`faas-netes` `Helm` `存储库`：

```
helm repo add openfaas https://openfaas.github.io/faas-netes/
helm repo update
```

最后，我们实际部署 OpenFaaS！

在前面的`faas-netes`存储库中的 OpenFaaS 的 Helm 图表有几个可能的变量，但我们将使用以下配置来确保创建一组初始的身份验证凭据，并部署入口记录：

```
helm install openfaas openfaas/openfaas \
    --namespace openfaas  \
    --set functionNamespace=openfaas-fn \
    --set ingress.enabled=true \
    --set generateBasicAuth=true 
```

现在，我们的 OpenFaaS 基础设施已经部署到我们的集群中，我们将希望获取作为 Helm 安装的一部分生成的凭据。Helm 图表将作为钩子的一部分创建这些凭据，并将它们存储在一个秘密中，因此我们可以通过运行以下命令来获取它们：

```
OPENFAASPWD=$(kubectl get secret basic-auth -n openfaas -o jsonpath="{.data.basic-auth-password}" | base64 --decode)
```

这就是我们需要的所有 Kubernetes 设置！

接下来，让我们安装 OpenFaas CLI，这将使管理 OpenFaas 函数变得非常容易。

### 安装 OpenFaaS CLI 和部署函数

要安装 OpenFaaS CLI，我们可以使用以下命令（对于 Windows，请查看前面的 OpenFaaS 文档）：

```
curl -sL https://cli.openfaas.com | sudo sh
```

现在，我们可以开始构建和部署一些函数。这最容易通过 CLI 来完成。

在构建和部署 OpenFaaS 的函数时，OpenFaaS CLI 提供了一种简单的方法来生成样板，并为特定语言构建和部署函数。它通过“模板”来实现这一点，并支持各种类型的 Node、Python 等。有关模板类型的完整列表，请查看[`github.com/openfaas/templates`](https://github.com/openfaas/templates)上的模板存储库。

使用 OpenFaaS CLI 创建的模板类似于您从 AWS Lambda 等托管无服务器平台期望的内容。让我们使用以下命令创建一个全新的 Node.js 函数：

```
faas-cli new my-function –lang node
```

这将产生以下输出：

```
Folder: my-function created.
Function created in folder: my-function
Stack file written: my-function.yml
```

正如你所看到的，`new`命令生成一个文件夹，在其中有一些函数代码本身的样板，以及一个 OpenFaaS YAML 文件。

OpenFaaS YAML 文件将如下所示：

My-function.yml:

```
provider:
  name: openfaas
  gateway: http://localhost:8080
functions:
  my-function:
    lang: node
    handler: ./my-function
    image: my-function
```

实际的函数代码（在`my-function`文件夹中）包括一个函数文件`handler.js`和一个依赖清单`package.json`。对于其他语言，这些文件将是不同的，我们不会深入讨论 Node 中的具体依赖。但是，我们将编辑`handler.js`文件以返回一些文本。编辑后的文件如下所示：

Handler.js:

```
"use strict"
module.exports = (context, callback) => {
    callback(undefined, {output: "my function succeeded!"});
}
```

这段 JavaScript 代码将返回一个包含我们文本的 JSON 响应。

现在我们有了我们的函数和处理程序，我们可以继续构建和部署我们的函数。OpenFaaS CLI 使构建函数变得简单，我们可以使用以下命令来完成：

```
faas-cli build -f /path/to/my-function.yml 
```

该命令的输出很长，但当完成时，我们将在本地构建一个新的容器映像，其中包含我们的函数处理程序和依赖项！

接下来，我们将像对待任何其他容器一样，将我们的容器映像推送到容器存储库。OpenFaaS CLI 具有一个很好的包装命令，可以将映像推送到 Docker Hub 或其他容器映像存储库：

```
faas-cli push -f my-function.yml 
```

现在，我们可以将我们的函数部署到 OpenFaaS。再次，这由 CLI 轻松完成。使用以下命令进行部署：

```
faas-cli deploy -f my-function.yml
```

现在，一切都已准备好让我们测试在 OpenFaaS 上部署的函数了！我们在部署 OpenFaaS 时使用了一个入口设置，以便请求可以通过该入口。但是，我们新函数生成的 YAML 文件设置为在开发目的地对`localhost:8080`进行请求。我们可以编辑该文件以将请求发送到我们入口网关的正确`URL`（请参阅[`docs.openfaas.com/deployment/kubernetes/`](https://docs.openfaas.com/deployment/kubernetes/)中的文档），但相反，让我们通过快捷方式在本地主机上打开 OpenFaaS。

让我们使用`kubectl port-forward`命令在本地主机端口`8080`上打开我们的 OpenFaaS 服务。我们可以按照以下方式进行：

```
export OPENFAAS_URL=http://127.0.0.1:8080
kubectl port-forward -n openfaas svc/gateway 8080:8080
```

现在，让我们按照以下方式将先前生成的 auth 凭据添加到 OpenFaaS CLI 中：

```
echo -n $OPENFAASPWD | faas-cli login -g $OPENFAAS_URL -u admin --password-stdin
```

最后，为了测试我们的函数，我们只需运行以下命令：

```
faas-cli invoke -f my-function.yml my-function
```

这将产生以下输出：

```
Reading from STDIN - hit (Control + D) to stop.
This is my message
{ output: "my function succeeded!"});}
```

如您所见，我们成功收到了我们预期的响应！

最后，如果我们想要删除这个特定的函数，我们可以使用以下命令，类似于我们使用`kubectl delete -f`的方式：

```
faas-cli rm -f my-function.yml 
```

就是这样！我们的函数已被删除。

# 总结

在本章中，我们学习了关于 Kubernetes 上的服务网格和无服务器模式。为了为这些做好准备，我们首先讨论了在 Kubernetes 上运行边车代理，特别是使用 Envoy 代理。

然后，我们转向服务网格，并学习了如何安装和配置 Istio 服务网格，以实现服务到服务的互相 TLS 路由。

最后，我们转向了在 Kubernetes 上的无服务器模式，您将学习如何配置和安装 Knative，以及另一种选择 OpenFaaS，用于 Kubernetes 上的无服务器事件和 FaaS。

本章中使用的技能将帮助您在 Kubernetes 上构建服务网格和无服务器模式，为您提供完全自动化的服务发现和 FaaS 事件。

在下一章（也是最后一章）中，我们将讨论在 Kubernetes 上运行有状态应用程序。

# 问题

1.  静态和动态 Envoy 配置有什么区别？

1.  Envoy 配置的四个主要部分是什么？

1.  Knative 的一些缺点是什么，OpenFaaS 又如何比较？

# 进一步阅读

+   CNCF 景观：[`landscape.cncf.io/`](https://landscape.cncf.io/)

+   官方 Kubernetes 论坛：[`discuss.kubernetes.io/`](https://discuss.kubernetes.io/)
