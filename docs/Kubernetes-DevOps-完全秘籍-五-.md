# Kubernetes DevOps 完全秘籍（五）

> 原文：[`zh.annas-archive.org/md5/2D2322071D8188F9AA9E93F3DAEEBABE`](https://zh.annas-archive.org/md5/2D2322071D8188F9AA9E93F3DAEEBABE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：Kubernetes 上的可观测性和监控

在本章中，我们将讨论内置的 Kubernetes 工具和流行的第三方监控选项，适用于您的容器化 DevOps 环境。您将学习如何监视性能分析的指标，以及如何监视和管理 Kubernetes 资源的实时成本。

到本章结束时，您应该掌握以下知识：

+   在 Kubernetes 中进行监控

+   检查容器

+   使用 Amazon CloudWatch 进行监控

+   使用 Google Stackdriver 进行监控

+   使用 Azure Monitor 进行监控

+   使用 Prometheus 和 Grafana 监控 Kubernetes

+   使用 Sysdig 进行监控和性能分析

+   使用 Kubecost 管理资源成本

# 技术要求

本章中的配方假定您已经部署了一个功能齐全的 Kubernetes 集群，遵循第一章中描述的推荐方法之一，*构建生产就绪的 Kubernetes 集群*。

Kubernetes 的命令行工具`kubectl`将用于本章中其余的配方，因为它是针对 Kubernetes 集群运行命令的主要命令行界面。我们还将使用 Helm，在 Helm 图表可用的情况下部署解决方案。

# 在 Kubernetes 中进行监控

在本节中，我们将配置我们的 Kubernetes 集群以获取核心指标，如 CPU 和内存。您将学习如何使用内置的 Kubernetes 工具在 CLI 和 UI 中监视 Kubernetes 指标。

## 做好准备

确保您已准备好 Kubernetes 集群，并配置`kubectl`以管理集群资源。

将`k8sdevopscookbook/src`存储库克隆到您的工作站，以使用`chapter8`目录中的清单文件：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd /src/chapter8
```

*使用 Kubernetes 仪表板监视指标*配方需要 Kubernetes 仪表板 v2.0.0 或更高版本才能正常运行。如果您想要向仪表板添加指标功能，请确保您已按照第一章中的*部署 Kubernetes 仪表板*配方中的说明安装了 Kubernetes 仪表板，*构建生产就绪的 Kubernetes 集群*。

## 如何做…

本节进一步分为以下子节，以使流程更加简单：

+   使用 Kubernetes Metrics Server 添加指标

+   使用 CLI 监控指标

+   使用 Kubernetes 仪表板监视指标

+   监控节点健康

### 使用 Kubernetes Metrics Server 添加指标

获取核心系统指标，如 CPU 和内存，不仅提供有用的信息，而且还是扩展 Kubernetes 功能所必需的，比如我们在第七章中提到的*扩展和升级应用*中的水平 Pod 自动缩放：

1.  通过运行以下命令将 Metrics Server 存储库克隆到您的客户端：

```
$ git clone https://github.com/kubernetes-incubator/metrics-        server.git
```

1.  通过运行以下命令，在`metrics-server/deploy/1.8+`目录中应用清单来部署 Metrics Server：

```
$ kubectl apply -f metrics-server/deploy/1.8+
```

此命令将在`kube-space`命名空间中创建所需的资源。

### 使用 CLI 监控指标

作为 Metrics Server 的一部分，资源指标 API 提供对 Pod 和节点的 CPU 和内存资源指标的访问。让我们使用资源指标 API 从 CLI 访问指标数据：

1.  首先，让我们显示节点资源利用率：

```
$ kubectl top nodes
NAME                          CPU(cores) CPU% MEMORY(bytes) MEMORY%
ip-172-20-32-169.ec2.internal 259m       12%  1492Mi        19%
ip-172-20-37-106.ec2.internal 190m       9%   1450Mi        18%
ip-172-20-48-49.ec2.internal  262m       13%  2166Mi        27%
ip-172-20-58-155.ec2.internal 745m       37%  1130Mi        14%
```

该命令将返回所有 Kubernetes 节点上已使用的 CPU 和内存。

有几种使用指标信息的方法。首先，在任何给定时间，CPU 和内存的使用量都应低于您的期望阈值，否则需要向集群添加新节点以平稳处理服务。平衡利用也很重要，这意味着如果内存使用的百分比高于 CPU 使用的平均百分比，您可能需要考虑更改云实例类型以使用更平衡的 VM 实例。

1.  在任何命名空间中显示 Pod 资源利用率。在此示例中，我们正在列出`openebs`命名空间中的 Pod：

```
$ kubectl top pods -n openebs
NAME                                         CPU(cores) MEMORY(bytes)
maya-apiserver-6ff5bc7bdd-l5gmt              2m         10Mi
openebs-admission-server-76dbdf97d9-swjw9    0m         3Mi
openebs-localpv-provisioner-6777f78966-f6lzp 2m         8Mi
openebs-ndm-operator-797495544c-hblxv        5m         12Mi
openebs-ndm-prvcr                            1m         6Mi
openebs-ndm-qmr66                            1m         6Mi
openebs-ndm-xbc2q                            1m         6Mi
openebs-provisioner-58bbbb8575-jzch2         3m         7Mi
openebs-snapshot-operator-6d7545dc69-b2zr7   4m         15Mi
```

该命令应返回所有 Pod 的已使用 CPU 和内存。Kubernetes 功能，如水平 Pod 缩放器，可以利用此信息来调整您的 Pod。

### 使用 Kubernetes 仪表板监控指标

默认情况下，除非安装了 Kubernetes Metrics Server 并且`kubernetes-metrics-scraper`辅助容器正在运行，否则 Kubernetes 仪表板不会显示详细的指标。

首先验证所有必要的组件是否正在运行，然后我们将看到如何从 Kubernetes 仪表板访问指标数据：

1.  验证`kubernetes-metrics-scraper` Pod 是否正在运行。如果没有，请按照第一章*，构建生产就绪的 Kubernetes 集群*中的*部署 Kubernetes 仪表板*配方中的说明安装 Kubernetes 仪表板：

```
$ kubectl get pods -n kubernetes-dashboard
NAME                                       READY STATUS  RESTARTS AGE
dashboard-metrics-scraper-69fcc6d9df-hhkkw 1/1   Running 0        177m
kubernetes-dashboard-566c79c67d-xqc6h      1/1   Running 0        177m
```

1.  在 Kubernetes 仪表板上，选择命名空间，然后单击“概述”菜单。此视图显示该命名空间中的 Pod 及其 CPU 和内存利用率：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/aa6b9895-ed40-4158-a8d2-1f1658e952a9.png)

1.  在 Kubernetes 仪表板上，选择一个命名空间，然后在“概述”菜单中单击 Pods。此视图显示所选命名空间中工作负载的整体 CPU 和内存利用率：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/7dd1d037-341d-490c-b402-32f4cd607cae.png)

1.  在集群菜单下选择节点。此视图显示集群中的节点以及 CPU 和内存的利用率：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/a7514a43-71a6-4a60-8b0e-ed2a8b3ba896.png)

如果请求和限制设置得非常高，那么它们可能会占用集群超出预期的份额。

### 监控节点健康

在本教程中，我们将学习如何在 Kubernetes 集群中创建一个 DaemonSet 来监视节点健康。节点问题检测器将从守护程序收集节点问题，并将其报告给 API 服务器作为 NodeCondition 和 Event：

1.  首先，从`/src/chapter8`文件夹中检查`node-problem-detector.yaml`文件的内容，并创建 DaemonSet 来运行节点问题检测器：

```
$ cat debug/node-problem-detector.yaml
$ kubectl apply -f debug/node-problem-detector.yaml
```

1.  获取集群中节点的列表。此命令将返回工作节点和主节点：

```
$ kubectl get nodes
NAME                          STATUS ROLES  AGE   VERSION
ip-172-20-32-169.ec2.internal Ready  node   6d23h v1.14.6
ip-172-20-37-106.ec2.internal Ready  node   6d23h v1.14.6
ip-172-20-48-49.ec2.internal  Ready  master 6d23h v1.14.6
ip-172-20-58-155.ec2.internal Ready  node   6d23h v1.14.6
```

1.  通过将以下命令中的节点名称替换为您的节点名称并运行它来描述节点的状态。在输出中，检查`Conditions`部分是否有错误消息。以下是输出的示例：

```
$ kubectl describe node ip-172-20-32-169.ec2.internal | grep -i condition -A 20 | grep Ready -B 20
Conditions:
 Type Status LastHeartbeatTime LastTransitionTime Reason Message
 ---- ------ ----------------- ------------------ ------ -------
 NetworkUnavailable False Sat, 12 Oct 2019 00:06:46 +0000 Sat, 12 Oct 2019 00:06:46 +0000 RouteCreated RouteController created a route
 MemoryPressure False Fri, 18 Oct 2019 23:43:37 +0000 Sat, 12 Oct 2019 00:06:37 +0000 KubeletHasSufficientMemory kubelet has sufficient memory available
 DiskPressure False Fri, 18 Oct 2019 23:43:37 +0000 Sat, 12 Oct 2019 00:06:37 +0000 KubeletHasNoDiskPressure kubelet has no disk pressure
 PIDPressure False Fri, 18 Oct 2019 23:43:37 +0000 Sat, 12 Oct 2019 00:06:37 +0000 KubeletHasSufficientPID kubelet has sufficient PID available
 Ready True Fri, 18 Oct 2019 23:43:37 +0000 Sat, 12 Oct 2019 00:06:37 +0000 KubeletReady kubelet is posting ready status
```

1.  此外，您可以通过将命令的最后一部分替换为其中一个条件来检查`KernelDeadlock`、`MemoryPressure`和`DiskPressure`条件。以下是`KernelDeadlock`的示例：

```
$ kubectl get node ip-172-20-32-169.ec2.internal -o yaml | grep -B5 KernelDeadlock
 - lastHeartbeatTime: "2019-10-18T23:58:53Z"
 lastTransitionTime: "2019-10-18T23:49:46Z"
 message: kernel has no deadlock
 reason: KernelHasNoDeadlock
 status: "False"
 type: KernelDeadlock
```

节点问题检测器可以检测无响应的运行时守护程序；硬件问题，如坏的 CPU、内存或磁盘；内核问题，包括内核死锁条件；损坏的文件系统；无响应的运行时守护程序；以及基础设施守护程序问题，如 NTP 服务中断。

## 另请参阅

+   Kubernetes Metrics Server 设计文档：[`github.com/kubernetes/community/blob/master/contributors/design-proposals/instrumentation/metrics-server.md`](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/instrumentation/metrics-server.md)

+   在 OpenShift 容器平台中配置和使用监控堆栈：[`access.redhat.com/documentation/en-us/openshift_container_platform/4.2/html/monitoring/index`](https://access.redhat.com/documentation/en-us/openshift_container_platform/4.2/html/monitoring/index)

+   Krex，一个 Kubernetes 资源浏览器：[`github.com/kris-nova/krex`](https://github.com/kris-nova/krex)

# 检查容器

在本节中，我们将解决与 pod 卡在 Pending、ImagePullBackOff 或 CrashLoopBackOff 状态相关的问题。您将学习如何检查和调试在 Kubernetes 中遇到部署问题的 pod。

## 准备工作

确保您已准备好一个 Kubernetes 集群，并配置了`kubectl`以管理集群资源。

## 如何操作…

该部分进一步分为以下子部分，以使过程更加简单：

+   检查处于 Pending 状态的 pod

+   检查处于 ImagePullBackOff 状态的 pod

+   检查处于 CrashLoopBackOff 状态的 pod

### 检查处于 Pending 状态的 pod

当您在 Kubernetes 上部署应用程序时，不可避免地会需要获取有关应用程序的更多信息。在这个示例中，我们将学习检查常见的 pod 问题，即 pod 卡在 Pending 状态：

1.  在`/src/chapter8`文件夹中，检查`mongo-sc.yaml`文件的内容，并运行以下命令部署它。部署清单包括具有三个副本的 MongoDB Statefulset，Service，并且由于参数错误而卡在 Pending 状态，我们将对其进行检查以找到问题的根源：

```
$ cat debug/mongo-sc.yaml
$ kubectl apply -f debug/mongo-sc.yaml
```

1.  通过运行以下命令列出 pod。您会注意到`mongo-0` pod 的状态是`Pending`：

```
$ kubectl get pods
NAME    READY STATUS  RESTARTS AGE
mongo-0 0/2   Pending 0        3m
```

1.  使用`kubectl describe pod`命令获取有关 pod 的其他信息，并查找`Events`部分。在这种情况下，`Warning`指向未绑定的`PersistentVolumeClaim`：

```
$ kubectl describe pod mongo-0
...
Events:
 Type    Reason           Age    From          Message
 ----    ------           ----   ----          -------
 Warning FailedScheduling 2m34s (x34 over 48m) default-scheduler pod has unbound immediate PersistentVolumeClaims (repeated 3 times)

```

1.  现在我们知道需要查看 PVC 状态，这要归功于上一步的结果，让我们获取 PVC 列表以检查问题。您会看到 PVC 也处于`Pending`状态：

```
$ kubectl get pvc
NAME              STATUS  VOLUME CAPACITY ACCESS MODES STORAGECLASS AGE
mongo-pvc-mongo-0 Pending                              storageclass 53m
```

1.  使用`kubectl describe pvc`命令获取有关 PVC 的其他信息，并查看事件的描述位置。在这种情况下，`Warning`指向一个名为`storageclass`的缺失存储类：

```
$ kubectl describe pvc mongo-pvc-mongo-0
...
Events:
 Type    Reason             Age  From           Message
 ----    ------             ---- ----           -------
 Warning ProvisioningFailed 70s  (x33 over 58m) persistentvolume-controller storageclass.storage.k8s.io "storageclass" not found

```

1.  列出存储类。您会注意到没有名为`storageclass`的存储类：

```
$ kubectl get sc
NAME                            PROVISIONER AGE
default                         kubernetes.io/aws-ebs 16d
gp2                             kubernetes.io/aws-ebs 16d
openebs-cstor-default (default) openebs.io/provisioner-iscsi 8d
openebs-device                  openebs.io/local 15d
openebs-hostpath                openebs.io/local 15d
openebs-jiva-default            openebs.io/provisioner-iscsi 15d
openebs-snapshot-promoter       volumesnapshot.external-storage.k8s.io/snapshot-promoter 15d
```

1.  现在我们知道我们在*步骤 1*中应用的清单文件使用了一个不存在的存储类。在这种情况下，您可以创建缺失的存储类，或者编辑清单以包含现有的存储类来解决问题。

让我们创建一个缺失的存储类，从现有的默认存储类中创建，就像下面的示例中所示`gp2`：

```
$ kubectl create -f sc-gp2.yaml
```

1.  通过运行以下命令列出 pod。您会注意到在*步骤 2*中先前处于`Pending`状态的所有 pod 现在的状态为`Running`：

```
$ kubectl get pods
NAME    READY STATUS  RESTARTS AGE
mongo-0 2/2   Running 0        2m18s
mongo-1 2/2   Running 0        88s
mongo-2 2/2   Running 0        50s
```

您已成功学会了如何检查为什么 pod 处于挂起状态并修复它。

### 检查处于 ImagePullBackOff 状态的 pod

有时您的清单文件可能会在图像名称中出现拼写错误，或者图像位置可能已更改。因此，当您部署应用程序时，容器图像将无法找到，并且部署将被卡住。在这个教程中，我们将学习如何检查处于`ImagePullBackOff`状态的 pod 的常见问题：

1.  在`/src/chapter8`文件夹中，检查`mongo-image.yaml`文件的内容，并通过运行以下命令部署它。部署清单包括具有三个副本的 MongoDB Statefulset，Service，并且由于容器图像名称中的拼写错误而被卡住在 ImagePullBackOff 状态，我们将对其进行检查以找到源：

```
$ cat debug/mongo-image.yaml
$ kubectl apply -f debug/mongo-image.yaml
```

1.  通过运行以下命令列出 pod。您会注意到`mongo-0` pod 的状态为`ImagePullBackOff`：

```
$ kubectl get pods
NAME    READY STATUS           RESTARTS AGE
mongo-0 0/2   ImagePullBackOff 0        32s
```

1.  使用`kubectl describe pod`命令获取有关 pod 的其他信息，并查找`Events`部分。在这种情况下，`Warning`指向未能拉取`mongi`图像的失败：

```
$ kubectl describe pod mongo-0
...
Events:
 Type    Reason           Age    From          Message
 ----    ------           ----   ----          -------
 Warning Failed 25s (x3 over 68s) kubelet, ip-172-20-32-169.ec2.internal Error: ErrImagePull
 Warning Failed 25s (x3 over 68s) kubelet, ip-172-20-32-169.ec2.internal Failed to pull image "mongi": rpc error: code = Unknown desc = Error response from daemon: pull access denied for mongi, repository does not exist or may require 'docker login'
 Normal Pulling 25s (x3 over 68s) kubelet, ip-172-20-32-169.ec2.internal Pulling image "mongi"
 Normal BackOff 14s (x4 over 67s) kubelet, ip-172-20-32-169.ec2.internal Back-off pulling image "mongi"
 Warning Failed 14s (x4 over 67s) kubelet, ip-172-20-32-169.ec2.internal Error: ImagePullBackOff
```

1.  现在我们知道需要确认容器图像名称。正确的名称应该是`mongo`。让我们编辑清单文件`mongo-image.yaml`，并将图像名称更改为`mongo`，如下所示：

```
... 
spec:
 terminationGracePeriodSeconds: 10
 containers:
 - name: mongo
 image: mongo
 command:
...
```

1.  通过运行以下命令删除并重新部署资源：

```
$ kubectl delete -f mongo-image.yaml
$ kubectl apply -f mongo-image.yaml
```

1.  通过运行以下命令列出 pod。您会注意到在*步骤 2*中先前处于`ImagePullBackOff`状态的所有 pod 现在的状态为`Running`：

```
$ kubectl get pods
NAME    READY STATUS  RESTARTS AGE
mongo-0 2/2   Running 0        4m55s
mongo-1 2/2   Running 0        4m55s
mongo-2 2/2   Running 0        4m55s
```

您已成功学会了检查状态为`ImagePullBackOff`的 pod 并进行故障排除。

### 检查处于 CrashLoopBackOff 状态的 pod

检查处于`CrashLoopBackOff`状态的 Pod 与检查处于挂起状态的 Pod 基本类似，但可能还需要更多关于您正在创建的容器工作负载的知识。当容器内的应用程序不断崩溃、Pod 的参数配置不正确、存活探针失败或在 Kubernetes 上部署时发生错误时，就会发生`CrashLoopBackOff`。

在这个教程中，我们将学习如何检查 Pod 陷入`CrashLoopBackOff`状态的常见问题：

1.  在`/src/chapter8`文件夹中，检查`mongo-config.yaml`文件的内容，并运行以下命令部署它。部署清单包括一个具有三个副本的 MongoDB 有状态集，Service，并由于缺少配置文件而陷入`CrashLoopBackOff`状态，我们将对其进行检查以找到源：

```
$ cat debug/mongo-config.yaml
$ kubectl apply -f debug/mongo-config.yaml
```

1.  通过运行以下命令列出 Pod。您会注意到`mongo-0` Pod 的状态为`CrashLoopBackOff`或`Error`：

```
$ kubectl get pods
NAME READY STATUS RESTARTS AGE
mongo-0 1/2 CrashLoopBackOff 3 58s
```

1.  使用`kubectl describe pod`命令获取有关 Pod 的附加信息，并查找`Events`部分。在这种情况下，`Warning`显示容器已重新启动，但没有指向任何有用的信息：

```
$ kubectl describe pod mongo-0
...
Events:
 Type    Reason           Age    From          Message
 ----    ------           ----   ----          -------
...
 Normal Pulled 44s (x4 over 89s) kubelet, ip-172-20-32-169.ec2.internal Successfully pulled image "mongo"
 Warning BackOff 43s (x5 over 87s) kubelet, ip-172-20-32-169.ec2.internal Back-off restarting failed container

```

1.  当来自 Pod 的事件不够用时，您可以使用`kubectl logs`命令从 Pod 获取附加信息。使用以下命令检查 Pod 日志中的消息。日志消息指向一个丢失的文件；需要进一步检查清单：

```
$ kubectl logs mongo-0 mongo
/bin/sh: 1: cannot open : No such file
```

1.  检查并仔细查看应用程序清单文件`mongo-config.yaml`，您会发现在这种情况下缺少环境变量`MYFILE`：

```
...
 spec:
 terminationGracePeriodSeconds: 10
 containers:
 - name: mongo
 image: mongo
 command: ["/bin/sh"]
 args: ["-c", "sed \"s/foo/bar/\" < $MYFILE"]
...
```

1.  要解决此问题，您可以向部署中添加`ConfigMap`。编辑`mongo-config.yaml`文件，并通过在文件开头添加`MYFILE`参数与`ConfigMap`资源来添加缺失的文件，类似于以下内容：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
 name: app-env
data:
 MYFILE: "/etc/profile"
EOF
```

1.  通过运行以下命令删除并重新部署资源：

```
$ kubectl delete -f mongo-image.yaml
$ kubectl apply -f mongo-image.yaml
```

1.  通过运行以下命令列出 Pod。您会注意到之前处于 CrashLoopBackOff 状态的所有 Pod 现在状态为`Running`。

```
$ kubectl get pods
NAME    READY STATUS  RESTARTS AGE
mongo-0 2/2   Running 0        4m15s
mongo-1 2/2   Running 0        4m15s
mongo-2 2/2   Running 0        4m15s
```

您已成功学会了如何检查 Pod 的 CrashLoopBackOff 问题并修复它。

## 另请参阅

+   调试 init 容器：[`kubernetes.io/docs/tasks/debug-application-cluster/debug-init-containers/`](https://kubernetes.io/docs/tasks/debug-application-cluster/debug-init-containers/)

+   调试 pods 和 ReplicationControllers [`kubernetes.io/docs/tasks/debug-application-cluster/debug-pod-replication-controller/`](https://kubernetes.io/docs/tasks/debug-application-cluster/debug-pod-replication-controller/)

+   调试 statefulset：[`kubernetes.io/docs/tasks/debug-application-cluster/debug-stateful-set/`](https://kubernetes.io/docs/tasks/debug-application-cluster/debug-stateful-set/)

+   确定 pod 失败的原因：[`kubernetes.io/docs/tasks/debug-application-cluster/determine-reason-pod-failure/`](https://kubernetes.io/docs/tasks/debug-application-cluster/determine-reason-pod-failure/)

+   Squash，用于微服务的调试器：[`github.com/solo-io/squash`](https://github.com/solo-io/squash)

# 使用 Amazon CloudWatch 进行监控

在本节中，我们将使用 Amazon CloudWatch Container Insights 来监视、隔离和诊断您的容器化应用程序和微服务环境。作为一名 DevOps 或系统工程师，您将学习如何使用 Amazon ECS CloudWatch 指标来监视服务健康状态和当前警报，使用自动化仪表板总结您的 Amazon EKS 集群的性能和健康状态，包括 pod、节点、命名空间和服务。

## 准备工作

将`k8sdevopscookbook/src`存储库克隆到您的工作站，以使用`chapter8`目录中的清单文件：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd src/chapter8/
```

确保您有一个准备好的 Amazon EKS Kubernetes 集群，并且已配置`kubectl`来管理集群资源。如果您还没有，可以按照第一章中的说明*构建生产就绪的 Kubernetes 集群*在*在 Amazon Web Services 上配置 Kubernetes 集群*部分。

## 如何做…

本节进一步分为以下小节，以使流程更加简单：

+   启用 Webhook 授权模式

+   为 Amazon EKS 安装 Container Insights 代理程序

+   查看 Container Insights 指标

### 启用 Webhook 授权模式

如果您使用`kops`选项在 AWS EC2 实例上部署了 Kubernetes 集群，而不是使用 Amazon EKS，则您的 kubelet 需要启用 Webhook 授权模式。

让我们按照以下步骤进行：

1.  使用以下两个标志启用`webhook`授权模式。第一个标志允许使用 ServiceAccount 令牌对 kubelet 进行身份验证。第二个标志允许 kubelet 执行 RBAC 请求并决定请求资源（在本例中为 Amazon CloudWatch）是否被允许访问资源端点：

```
--authentication-token-webhook=true 
--authorization-mode=Webhook 
```

1.  您还需要为 Kubernetes 工作节点的 IAM 角色添加必要的策略。在[`console.aws.amazon.com/ec2/`](https://console.aws.amazon.com/ec2/)上打开 Amazon EC2 控制台。

1.  在资源下，点击“运行实例”：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/1cacb071-9928-4b6f-b6fc-952920da2a89.png)

1.  从列表中选择一个工作节点实例，并在“描述”选项卡上选择 IAM 角色。在我们的示例中，eksctl-adorable-rainbow-157155665-NodeInstanceRole-MOT7WBCOOOHE 是 IAM 角色：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/74adf21c-9ea7-4bed-9207-f2f8506cfe99.png)

1.  在“权限”选项卡上，点击“附加策略”按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/264d1165-f3c8-4354-a85a-f240d6d6da84.png)

1.  在搜索框中，键入`CloudWatchAgentServerPolicy`并选择该策略：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/34d276bc-65d1-4a11-9067-58a07d98e4e0.png)

1.  点击“附加策略”按钮将策略附加到您的 IAM 角色：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/72c1f9fc-5738-488a-89b1-926b8ac65dd7.png)

现在，您已成功启用了 Webhook 授权模式并向 IAM 角色添加了所需的策略。

### 为 Amazon EKS 安装容器洞察代理

在这个教程中，我们将启用 CloudWatch 代理来收集我们的 EKS Kubernetes 集群的集群指标：

1.  使用以下命令在您的集群上创建名为`amazon-cloudwatch`的命名空间：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
 name: amazon-cloudwatch
 labels:
 name: amazon-cloudwatch
EOF
```

1.  为您在*步骤 1*中创建的`amazon-cloudwatch`命名空间创建 CloudWatch 代理的服务帐户。以下命令还将创建`cloudwatch-agent-role` ClusterRole 和 ClusterRoleBinding：

```
$ kubectl apply -f cloudwatch/cwagent-serviceaccount.yaml
```

1.  使用`eksctl`命令或从 Amazon 容器服务仪表板获取您的 EKS 集群名称。在这里，我们将使用`eksctl`获取集群名称。在我们的示例中，集群名称是`adorable-rainbow-1571556654`：

```
$ eksctl get cluster
NAME                        REGION
adorable-rainbow-1571556654 us-west-2
```

1.  为 CloudWatch 代理创建 ConfigMap。在运行以下命令之前，请用您在*步骤 3*中的集群名称替换`"cluster_name": "adorable-rainbow-1571556654"`：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
 name: cwagentconfig
 namespace: amazon-cloudwatch
data:
 cwagentconfig.json: |
 {
 "logs": {
 "metrics_collected": {
 "kubernetes": {
 "cluster_name": "{{cluster_name}}",
 "metrics_collection_interval": 60
 }
 },
 "force_flush_interval": 5
 }
 }
EOF
```

1.  部署 CloudWatch 代理作为 DaemonSet。上述命令将使用 StatsD，这是一个监听通过 UDP 或 TCP 发送的统计信息（如计数器和计时器）的网络守护程序，并将聚合发送到 CloudWatch，如果可用还会使用可插拔的后端服务：

```
$ kubectl apply -f cloudwatch/cwagent.yaml
```

1.  通过运行以下命令来验证 CloudWatch 代理 Pod 是否已创建。由于代理作为 DaemonSets 运行，您应该能够看到每个工作节点列出的一个 Pod。在我们的示例中，我们有两个工作节点和两个代理 Pod 正在运行：

```
$ kubectl get pods -n amazon-cloudwatch
NAME                   READY STATUS  RESTARTS AGE
cloudwatch-agent-dtpxt 1/1   Running 0        67s
cloudwatch-agent-j7frt 1/1   Running 0        67s
```

完成后，CloudWatch 代理将开始向 CloudWatch 容器洞察服务发送性能日志事件。

### 查看容器洞察指标

在这个教程中，我们将学习如何使用 CloudWatch 来监视我们的 Kubernetes 集群中的节点和 Pod 指标：

1.  在[`console.aws.amazon.com/cloudwatch/`](https://console.aws.amazon.com/cloudwatch/)上打开 CloudWatch 控制台：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/8591ca4c-f964-4ece-8072-b6fc04769301.png)

1.  单击“概览”选项旁边的向下箭头按钮，然后从列表中选择“容器洞察”：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/6de4bede-d420-4133-b405-c8afe47b9d67.png)

1.  要查看 EKS 节点的健康状况和统计信息，请在左上角切换到 EKS 节点。新视图上的图表将显示资源利用率、集群故障和节点数量，类似于以下截图的历史视图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/e0d639f6-1f3b-49f3-b60f-7de5cac9248c.png)

1.  要查看容器性能统计信息，请在左上角切换到 EKS Pod。新视图上的图表将显示 Pod 的总资源利用率，并列出 Pod 的各自 CPU 和内存消耗百分比，类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/424be416-0fbf-4206-bdf2-3c28653322d5.png)

1.  要查看任何资源的详细日志或 AWS X-Ray 跟踪，请从列表中选择资源名称，然后单击“操作”按钮。从下拉菜单中，您可以选择要查看的日志。选择后，日志将在新窗口中打开：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/c0cd7c15-5b63-4291-bd71-20a96ea33b4b.png)

现在您已经学会了如何使用容器洞察来监视您的 Kubernetes 集群中的节点和 Pod 指标。 

## 另请参阅

+   使用容器洞察[`docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html`](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html)

+   使用 CloudWatch 异常检测 [`docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Anomaly_Detection.html`](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Anomaly_Detection.html)

+   Container Insights 收集的指标列表：[`docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-metrics-EKS.html`](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-metrics-EKS.html)

# 使用 Google Stackdriver 进行监控

在本节中，我们将使用 Google Stackdriver Kubernetes Engine 监控来监视、隔离和诊断您的容器化应用程序和微服务环境。您将学习如何使用 Stackdriver Kubernetes Engine 监控来聚合来自**Google Kubernetes Engine**（**GKE**）的 Kubernetes 环境的日志、事件和指标，以帮助您了解您的应用在生产环境中的行为。

## 准备工作

确保您已准备好一个 GKE 集群，并配置了`kubectl`来管理集群资源。如果您还没有，请按照第一章，*构建生产就绪的 Kubernetes 集群*中的*在 Google 云平台上配置 Kubernetes 集群*的说明进行操作。

## 如何做…

本节进一步分为以下子节，以使流程更加简单：

+   安装 GKE 的 Stackdriver Kubernetes Engine 监控支持

+   在 Stackdriver 上配置工作空间

+   使用 Stackdriver 监控 GKE 指标

### 安装 GKE 的 Stackdriver Kubernetes Engine 监控支持

安装 Stackdriver 监控支持可以让您轻松监控 GKE 集群，调试日志，并使用高级分析和跟踪功能分析您的集群性能。在这个示例中，我们将启用 Stackdriver Kubernetes Engine 监控支持，以从我们的 GKE 集群中收集集群指标：

1.  在[`console.cloud.google.com/kubernetes`](https://console.cloud.google.com/kubernetes)上打开 Google Kubernetes Engine 控制台。在这个控制台上，您将看到您的 GKE 集群列表。在我们的示例中，我们只有一个集群，它被称为 k8s-devops-cookbook-1：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/c30d840b-0424-421d-aa84-182e82ef6d5d.png)

1.  单击集群旁边的小笔形编辑图标：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/14e028fa-1b95-41c2-9cf4-383bf033a67b.png)

1.  在集群配置页面上，确保“传统 Stackdriver 日志记录”和“传统 Stackdriver 监控”已禁用，并且“Stackdriver Kubernetes Engine 监控”选项已设置为启用：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/775f7514-c629-4e0a-bcb6-a38388106a25.png)

1.  单击保存按钮以应用对集群的更改。

### 在 Stackdriver 上配置工作区

Stackdriver 监控帮助您更深入地了解您的公共云。Stackdriver 的监控功能包括监控、日志记录、跟踪、错误报告和警报，以收集您的公共云服务的性能和诊断数据。Kubernetes 监控是完整解决方案的一小部分。在本教程中，您将学习如何在首次访问后配置 Stackdriver 工作区：

1.  在[`app.google.stackdriver.com`](https://app.google.stackdriver.com)上打开 Stackdriver 控制台。第一次访问控制台时，您需要将工作区添加到控制台，否则您将看到一个空的仪表板，类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/9fb46066-4580-4aaa-8251-3eadf2523ffd.png)

1.  单击“添加工作区”按钮以包括您现有的工作区。您将被要求输入您的 Google Cloud Platform 项目名称。单击空的“选择项目”字段，并从列表中选择您的项目。在我们的示例中，它是 DevOpsCookBook。选择项目后，单击“创建工作区”按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/183db9a1-b5fa-4572-97d1-1386f608f675.png)

1.  Stackdriver 还允许您监控 AWS 账户。对于本教程，我们将跳过此选项。单击“跳过 AWS 设置”以进行下一步：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/23ac9fb9-7880-409d-ae33-afbf822f0207.png)

1.  在“安装 Stackdriver 代理”窗口中，单击“继续”按钮。

1.  在“通过电子邮件获取报告”窗口中，选择要通过电子邮件发送报告的频率。选择每周报告。请注意，您始终可以选择不发送报告，并稍后启用此功能：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/a8fba332-b774-40ec-908e-00876c324f93.png)

1.  最后，单击“启动监控”按钮以访问 Stackdriver 控制台：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/3e254f3f-0a00-49d6-ba23-9e4cba3f96de.png)

现在您已经配置了 Stackdriver 工作区，以收集来自您的公共云服务的诊断数据。

### 使用 Stackdriver 监控 GKE 指标

安装 Stackdriver 监控支持可以让您轻松监视 GKE 集群，调试日志，并使用高级分析和跟踪功能分析集群性能。在本示例中，我们将启用 Stackdriver Kubernetes Engine 监控支持，以从我们的 GKE 集群收集集群指标：

1.  在按照*在 Stackdriver 上配置工作空间*的步骤后，打开 Stackdriver 控制台[`app.google.stackdriver.com`](https://app.google.stackdriver.com)：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/b6f26a4c-35ad-4a59-aba0-36c13140c69e.png)

1.  从资源菜单中，点击“Kubernetes Engine”选项：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/68af781b-54af-4e3d-8f77-8d4e7a9dadbd.png)

1.  Kubernetes Engine 视图将显示启用了 Stackdriver Kubernetes Engine 监控的集群列表。在我们的示例中，您可以看到我们有一个可用的集群：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/2ac01aa4-5e4d-47bd-a35f-c57c40452dab.png)

1.  在基础设施选项卡上，点击集群名称旁边的展开图标。Stackdriver 将展开列表，显示各个工作节点。在“就绪”列中，您可以看到每个节点上部署并处于就绪状态的 pod 数量。在“CPU 利用率”列中，左侧的值显示总可用 CPU 数，右侧的值显示当前利用率百分比。类似地，在“内存利用率”列中，左侧的值显示总可用内存（GiB），右侧的值显示当前利用率百分比：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/178051c8-51f7-447e-90a6-e7a4d7452c46.png)

1.  点击节点名称旁边的展开图标，列表将展开以显示部署在该特定节点上的 pod：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/1049ab7b-a3cb-425d-a7ed-5db45bd1dbc5.png)

1.  点击集群中的一个 pod。Stackdriver 将显示 pod 指标的详细视图，包括 pod 重启、CPU、内存、存储和网络利用率。在我们的示例中，我们可以看到 Prometheus pod 的指标：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/03f65bd5-6cf9-4543-a92f-2e11b2ed5086.png)

1.  点击“日志”选项卡切换到日志摘要视图。此视图将只显示最近的日志：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/77e036ee-938a-41af-9fd7-268da8a01c7c.png)

1.  点击“转到控制台”按钮，打开详细的日志视图，您可以在其中查看旧日志并使用过滤器创建指标：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/1966c05e-4835-490b-9964-6c4b83a88e75.png)

现在您知道如何使用 Stackdriver 来监视 GKE 集群和部署在 GKE 集群上的资源的健康状况、性能指标和日志。

## 另请参阅

+   Google Stackdriver 文档：[`cloud.google.com/stackdriver/docs/`](https://cloud.google.com/stackdriver/docs/)

+   使用 Prometheus 与 Stackdriver Kubernetes Engine 监控：[`cloud.google.com/monitoring/kubernetes-engine/prometheus`](https://cloud.google.com/monitoring/kubernetes-engine/prometheus)

+   Stackdriver Prometheus sidecar: [`github.com/Stackdriver/stackdriver-prometheus-sidecar`](https://github.com/Stackdriver/stackdriver-prometheus-sidecar)

+   GCP 倡导者在 Stackdriver 上发布的技术文章集合：[`medium.com/google-cloud/tagged/stackdriver`](https://medium.com/google-cloud/tagged/stackdriver)

# 使用 Azure Monitor 进行监控

在本节中，我们将使用 Azure Monitor 来监视、隔离和诊断您的容器化应用程序和微服务环境。您将学习如何使用 Azure Monitor 来聚合来自**Azure Kubernetes Service**（**AKS**）上的 Kubernetes 环境的日志、事件和指标，以帮助您了解应用程序在生产环境中的行为。

## 做好准备

确保您已经准备好一个 AKS 集群，并且已经配置好`kubectl`来管理集群资源。如果您还没有，您可以按照《第一章》中的说明进行操作，即《构建生产就绪的 Kubernetes 集群》，在《在 Google Cloud Platform 上配置 Kubernetes 集群》的教程中。

## 如何做…

本节进一步分为以下子节，以使流程更加简单：

+   使用 CLI 为 AKS 集群启用 Azure Monitor 支持

+   使用 Azure Monitor 监控 AKS 性能指标

+   使用 Azure Monitor 查看实时日志

### 使用 CLI 为 AKS 启用 Azure Monitor 支持

启用 Azure Monitor 以便从控制器、节点和容器中收集内存和处理器指标，这些指标通过 Kubernetes Metrics API 在 Kubernetes 中可用。

在这个教程中，我们将启用从 AKS Kubernetes 集群收集指标和日志的监控，通过 Log Analytics 代理的容器化版本：

1.  如果您按照第一章中的*在 AKS 上部署托管的 Kubernetes 集群*配方部署了您的 AKS 集群，您可以使用以下命令为您的集群启用 Azure Monitor。在运行以下命令之前，将名称`AKSCluster`替换为您的 AKS 集群名称，并将资源组`k8sdevopscookbook`替换为您在创建集群时使用的 Azure 资源组名称：

```
$ az aks enable-addons -a monitoring \
--name AKSCluster --resource-group k8sdevopscookbook
```

如果您正在部署新的集群，可以在 CLI 命令中添加`--enable-addons monitoring`参数，以在集群创建期间为您的 AKS 集群启用 Azure Monitor 功能，如下所示：**`$ az aks create --resource-group k8sdevopscookbook \`**

**`--name AKSCluster \`**

**`--node-count 3 \`**

**`--service-principal <appId> \`**

**`--client-secret <password> \`**

**`--enable-addons monitoring  \`**

**`--generate-ssh-keys`**

完成后，此命令将为您的 AKS 集群启用 Azure Monitor 和日志记录。

### 使用 Azure Monitor 监视 AKS 性能指标

可以直接从 AKS 集群管理仪表板和 Azure Monitor 仪表板查看 AKS 集群的性能指标。在此配方中，我们将通过 Azure Monitor 监视 AKS 性能指标：

1.  按照*使用 CLI 为 AKS 启用 Azure Monitor 支持*的配方后，打开 Azure 门户网站[`portal.azure.com`](https://portal.azure.com)，单击“Kubernetes 服务”按钮，转到 AKS 管理仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/3e90313c-78a7-42b3-8b63-b8c334e67c8b.png)

1.  在 Kubernetes 服务视图中，单击您的集群名称。在我们的示例中，它是 AKSCluster：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/fcde7e75-32cc-480f-8135-ea1a3c635655.png)

1.  单击“监视容器”菜单，打开您的 AKS 集群的 Azure Monitor Insights 视图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/c6b1e871-02ae-4646-9699-0913fcb0432d.png)

1.  有关您的 AKS 集群的监视信息分为五个类别：集群、节点、控制器、容器和部署。在此视图中，在集群选项卡上，您将能够查看节点 CPU 和内存利用率、AKS 节点计数和活动 pod 计数，就像这样：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/a217da74-4918-4284-95eb-00184ecebf4c.png)

1.  单击“节点”选项卡，切换到节点性能指标视图。默认情况下，CPU 使用数据显示为过去 6 小时的 95th 百分位数。可以使用页面上的下拉菜单调整这些选项：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/cfd57746-c26c-484e-be08-698d6fa652eb.png)

1.  单击节点名称旁边的展开图标，列表将展开显示部署在该特定节点上的 Pod 和容器。在此视图中，可以查看每个资源的 CPU 利用率和正常运行时间：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/7214bf0f-c795-4278-b34e-42a9f1505a7e.png)

现在你知道如何通过 Azure Monitor insights 监视 AKS 性能指标了。

### 使用 Azure Monitor 查看实时日志

除了性能指标，Azure Monitor 还可以帮助查看 AKS 集群资源的日志。在本教程中，我们将学习如何使用 Azure Monitor 访问事件和日志：

1.  在你的集群中，要显示 Pod 事件和实时指标，你需要应用`ClusterRoleBinding`。通过在你的 AKS 集群上运行以下命令来创建`ClusterRole`：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1 
kind: ClusterRole 
metadata: 
 name: containerHealth-log-reader 
rules: 
 - apiGroups: [""] 
 resources: ["pods/log", "events"] 
 verbs: ["get", "list"] 
EOF
```

1.  通过在你的 AKS 集群上运行以下命令来创建`ClusterRoleBinding`：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1 
kind: ClusterRoleBinding 
metadata: 
 name: containerHealth-read-logs-global 
roleRef: 
 kind: ClusterRole 
 name: containerHealth-log-reader 
 apiGroup: rbac.authorization.k8s.io 
subjects: 
 - kind: User 
 name: clusterUser 
 apiGroup: rbac.authorization.k8s.io
EOF
```

1.  单击“监视容器”菜单，打开你的 AKS 集群的 Azure Monitor insights 视图。

1.  单击节点名称旁边的展开图标，列表将展开显示部署在该特定节点上的 Pod 和容器：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/7214bf0f-c795-4278-b34e-42a9f1505a7e.png)

1.  单击你的集群中的一个 Pod。Insights 将在右侧面板上显示 Pod 指标的详细视图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/2e752e4c-bd3d-4615-9d7d-9b9729f976ae.png)

1.  在右侧窗格中，单击“查看实时数据”按钮。此选项将展开视图，显示来自 Pod 的实时事件和实时指标，如下图所示。事件可用于排除本章“检查容器”部分中讨论的 Pod 问题：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/73a98dc7-3ed0-4eb1-9dca-a10f22b81e55.png)

1.  你在视图中看到的日志和事件消息取决于所选的资源类型。单击“在分析中查看”按钮以切换到 Kubernetes 事件日志：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/87f51ad2-f794-4613-b1d6-80a76ca2e171.png)

1.  在此视图中，您将能够查看和过滤 Pod 事件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/32fd7845-c1bb-4b2a-bec6-123d24d5f853.png)

1.  这次，单击 Pod 内的一个容器。Insights 将在右侧面板中显示容器信息和性能指标的详细视图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/d3669927-aa96-4e52-9acd-bf799584f3c7.png)

1.  在右侧窗格中，单击“在分析中查看”按钮以切换到“查看容器日志”：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/a0e6d41b-54b4-4bfd-afee-78aa85777c4d.png)

1.  在此视图中，您将能够查看和过滤容器日志：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/8b2613e1-6422-47c9-b8a5-867981db4cc5.png)

现在您知道如何使用 Azure 监视来监视 AKS 集群的健康状况、性能指标和日志，以及在 AKS 集群上部署的资源。

## 另请参阅

+   Azure 容器监视文档：[`docs.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-overview`](https://docs.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-overview)

+   使用 Azure 监视与 Prometheus：[`azure.microsoft.com/en-us/blog/azure-monitor-for-containers-with-prometheus-now-in-preview/`](https://azure.microsoft.com/en-us/blog/azure-monitor-for-containers-with-prometheus-now-in-preview/)

# 使用 Prometheus 和 Grafana 监视 Kubernetes

在本节中，我们将在 Kubernetes 集群上部署 Prometheus 和 Grafana。您将学习如何使用 Prometheus 监视 Kubernetes 服务，并使用 Grafana 仪表板可视化集群和应用程序指标。

## 准备就绪

将`k8sdevopscookbook/src`存储库克隆到您的工作站，以便在`chapter8`目录中使用清单文件：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd /src/chapter8
```

确保您已准备好 Kubernetes 集群，并配置了`kubectl`以管理集群资源。

## 如何做…

本节进一步分为以下子节，以使流程更加简单：

+   使用 Helm 图表部署 Prometheus Operator

+   使用 Grafana 仪表板监视指标

+   将 Grafana 仪表板添加到监视应用程序

### 使用 Helm 图表部署 Prometheus

Prometheus 是一个流行的开源解决方案，用于事件监视和警报。Prometheus 记录实时指标在时间序列数据库中，它是 Kubernetes 集群中最受欢迎的组件之一。几乎所有新的托管 Kubernetes 解决方案都会在集群部署的某种方式上安装 Prometheus。在本教程中，您将学习如何使用 Helm 图表在 Kubernetes 集群上部署 Prometheus：

1.  更新 Helm 存储库。此命令将从公共图表存储库本地获取最新的图表：

```
$ helm repo update
```

1.  使用`helm install`命令在`monitoring`命名空间中部署 Prometheus Operator。此命令将部署 Prometheus 以及 Alertmanager、Grafana、node-exporter 和 kube-state-metrics 附加组件；基本上，这是一组在 Kubernetes 集群上使用 Prometheus 所需的组件：

```
$ helm install stable/prometheus-operator --name prometheus \
 --namespace monitoring
```

1.  验证在监视命名空间中部署的 Pod 的状态：

```
$ kubectl get pods -n monitoring
NAME READY STATUS RESTARTS AGE
alertmanager-prometheus-prometheus-oper-alertmanager-0 2/2 Running 0 88s
prometheus-grafana-6c6f7586b6-f9jbr 2/2 Running 0 98s
prometheus-kube-state-metrics-57d6c55b56-wf4mc 1/1 Running 0 98s
prometheus-prometheus-node-exporter-8drg7 1/1 Running 0 98s
prometheus-prometheus-node-exporter-lb7l5 1/1 Running 0 98s
prometheus-prometheus-node-exporter-vx7w2 1/1 Running 0 98s
prometheus-prometheus-oper-operator-86c9c956dd-88p82 2/2 Running 0 98s
prometheus-prometheus-prometheus-oper-prometheus-0 3/3 Running 1 78s
```

现在您已经安装了 Prometheus，并且具备在 Kubernetes 环境中操作所需的组件包。

### 使用 Grafana 仪表板监视指标

Grafana 是一个开源的分析和监控解决方案。默认情况下，Grafana 用于查询 Prometheus。按照以下说明来公开包含的 Grafana 服务实例并通过 Web 浏览器访问它：

1.  获取`monitoring`命名空间中的服务列表：

```
$ kubectl get svc -n monitoring
NAME                                    TYPE      CLUSTER-IP   EXTERNAL-IP PORT(S)                    AGE
alertmanager-operated                   ClusterIP None         <none>      9093/TCP,9094/TCP,9094/UDP 33m
prometheus-grafana                      ClusterIP 10.0.1.132   <none>      80/TCP                     33m
prometheus-kube-state-metrics           ClusterIP 10.0.69.144  <none>      8080/TCP                   33m
prometheus-operated                     ClusterIP None         <none>      9090/TCP                   33m
prometheus-prometheus-node-exporter     ClusterIP 10.0.100.183 <none>      9100/TCP                   33m
prometheus-prometheus-oper-alertmanager ClusterIP 10.0.202.140 <none>      9093/TCP                   33m
prometheus-prometheus-oper-operator     ClusterIP 10.0.174.214 <none>      8080/TCP,443/TCP           33m
prometheus-prometheus-oper-prometheus   ClusterIP 10.0.243.177 <none>      9090/TCP                   33m
```

1.  创建端口转发以使用`kubectl port-forward`命令访问 Grafana UI。此命令将本地端口`8000`转发到运行中的 Grafana pod 的端口`3000`：

```
$ kubectl port-forward -n monitoring prometheus-grafana 8000:80
```

作为替代方案，您可以使用`kubectl edit svc prometheus-grafana -n monitoring`命令来修补`prometheus-grafana`服务，并将服务类型`ClusterIP`更改为`LoadBalancer`，以使用云负载均衡器在外部公开服务。

1.  在 Web 浏览器中转到`http://localhost:8000`（或者如果使用 LoadBalancer，则是外部 IP）。您应该看到 Grafana 登录页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/2e980b93-4bf2-4ad2-b6d7-df69e189d97d.png)

1.  使用`admin`作为用户名和`prom-operator`作为密码登录：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/35e3b8b9-90a3-49ae-9909-98a5d82de501.png)

1.  单击仪表板左上角的主页按钮，列出可用的内置仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/9a9312e4-26ce-4e7f-8f1c-ffeb80641161.png)

1.  例如，从列表中选择`Nodes`仪表板以显示 Kubernetes 节点指标。在此视图中，您将看到节点资源的图形表示，包括 CPU、内存、磁盘和网络利用率：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/df28d7ef-d7c6-4aae-b221-a4086743c484.png)

现在您知道如何在 Grafana 中浏览仪表板。您可以使用 Grafana 来可视化 Kubernetes 指标和其他为 Prometheus 提供指标的工作负载指标，方法是按照下一个步骤。

### 添加 Grafana 仪表板以监视应用程序

Grafana 用于可视化存储在 Prometheus 上的指标。它提供具有模板变量的动态和可重用的仪表板。在本教程中，我们将学习如何从预构建的仪表板库中添加一个新的仪表板，以监视部署在 Kubernetes 上的应用程序：

1.  每个应用程序都有不同的与应用程序的连续性相关的指标。首先，应用程序需要向 Prometheus 公开指标（有关编写 Prometheus 导出器的其他信息，请参阅“另请参阅”部分），并且必须将 Prometheus 添加为 Grafana 的数据源。对于此示例，我们将使用我们在第三章“构建 CI/CD 流水线”中部署的 Jenkins，在“在 Jenkins X 中设置 CI/CD 流水线”食谱中。

1.  单击仪表板左上角的“主页”按钮，然后单击“在 Grafana.com 上查找仪表板”：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/7be64ba6-bf4a-48a2-9094-9f2e4eae5384.png)

1.  在搜索字段中，键入`Jenkins`。您将看到一些特定于 Jenkins 的仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/0adfecca-dbdc-4902-9acf-4ee493e9ad49.png)

1.  单击“Jenkins：性能和健康概述”，并将 ID 复制到剪贴板。此时，仪表板 ID 306 是您添加此预构建仪表板到 Grafana 实例所需的全部内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/2b55ebc7-9cb5-4ef1-a636-56ea5a81ad73.png)

1.  如果未启用仪表板，请按照“概述”部分中的说明操作。

1.  在 Grafana 界面中，单击导入仪表板。将仪表板 ID 306 粘贴到 Grafana.com 仪表板字段中。Grafana 将自动检测仪表板并显示详细信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/691e380e-e9de-4d34-a8c1-d844425b1e51.png)

1.  选择 Prometheus 作为数据源名称，然后单击导入：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/15ac1933-d044-49ff-a2be-ff0d9008a7bf.png)

1.  单击“主页”按钮以再次列出仪表板，您将在最近的仪表板列表中找到新的仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/cfe18365-2ee8-4595-a167-d0f496ddbca8.png)

同样，您可以在 Grafana 上找到预构建的仪表板，用于我们在之前章节中使用的应用程序，例如云提供商服务监控（AWS、GCP、Azure、阿里巴巴）、GitLab CI、Minio、OpenEBS 以及许多其他 Kubernetes 集群指标。

## 另请参阅

+   Prometheus 文档：[`prometheus.io/docs/introduction/overview/`](https://prometheus.io/docs/introduction/overview/)

+   编写 Prometheus 导出器：[`prometheus.io/docs/instrumenting/writing_exporters/`](https://prometheus.io/docs/instrumenting/writing_exporters/)

+   Prometheus-Operator 的 GitHub 存储库：[`github.com/coreos/prometheus-operator`](https://github.com/coreos/prometheus-operator)

+   Grafana 文档：[`grafana.com/docs/`](https://grafana.com/docs/)

+   Grafana 社区仪表板：[`grafana.com/grafana/dashboards`](https://grafana.com/grafana/dashboards)

+   Grafana 插件：[`grafana.com/grafana/plugins`](https://grafana.com/grafana/plugins)

+   启用 Jenkins Prometheus 插件：[`wiki.jenkins.io/display/JENKINS/Prometheus+Plugin`](https://wiki.jenkins.io/display/JENKINS/Prometheus+Plugin)

+   将 Stackdriver 添加为数据源：[`grafana.com/grafana/plugins/stackdriver`](https://grafana.com/grafana/plugins/stackdriver)

+   将 Azure Monitor 添加为数据源：[`grafana.com/grafana/plugins/grafana-azure-monitor-datasource`](https://grafana.com/grafana/plugins/grafana-azure-monitor-datasource)

+   Prometheus 替代方案：

+   DataDog：[`www.datadoghq.com`](https://www.datadoghq.com)

+   New Relic：[`newrelic.com`](https://newrelic.com)

+   Open Falcon：[`open-falcon.org`](http://open-falcon.org)

# 使用 Sysdig 进行监控和性能分析

在这一部分，我们将使用 Sysdig Monitor 来监控和简化 Kubernetes 故障排除。您将学习如何安装 Sysdig Monitor 并扩展 Prometheus 功能，以满足更高级的企业需求。

## 准备工作

这里提到的所有操作都需要一个 Sysdig 账户。如果您还没有账户，请转到[`sysdig.com/sign-up/`](https://sysdig.com/sign-up/)并创建一个试用或完整账户。

对于这个教程，我们需要准备好一个 Kubernetes 集群，并安装 Kubernetes 命令行工具`kubectl`和`helm`来管理集群资源。

## 如何做…

这一部分进一步分为以下子部分，以使流程更加简单：

+   安装 Sysdig 代理

+   分析应用程序性能

### 安装 Sysdig 代理

Sysdig Monitor 是一种用于监视和故障排除应用程序的工具，作为 Sysdig Cloud Native Visibility and Security Platform 的一部分。在这个教程中，您将学习如何部署 Sysdig Monitor 并利用 Prometheus 指标：

1.  如果您还没有准备好您的 Sysdig Monitor 访问密钥，请转到[`app.sysdigcloud.com/#/settings/agentInstallation`](https://app.sysdigcloud.com/#/settings/agentInstallation)的账户设置，并检索您的访问密钥：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/32c5535e-065c-4b79-9b23-f5ea7fbd414f.png)

1.  使用 Helm 图表安装 Sysdig 代理，将以下命令中的`YourAccessKey`替换为*步骤 1*中的 Sysdig Monitor 访问密钥。此命令将在集群中的所有 Kubernetes 工作节点上安装 Sysdig Monitor 和 Sysdig Secure 所需的 Sysdig 代理作为 DaemonSet：

```
$ helm install --name sysdig-agent --set sysdig.accessKey=YourAccessKey, \ sysdig.settings.tags='linux:ubuntu, dept:dev,local:ca' \
--set sysdig.settings.k8s_cluster_name='my_cluster' stable/sysdig
```

1.  安装 Sysdig 代理后，节点将被 Sysdig Monitor 检测到。在这个视图中，所有节点都应该被检测到。在我们的示例中，我们检测到了四个节点。单击“转到下一步”按钮继续：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/de244830-51e2-4271-91a3-a818cb866345.png)

1.  Sysdig Monitor 与 AWS 深度集成。如果您的 Kubernetes 集群部署在 AWS 上，您可以选择输入 AWS 访问密钥 ID 和密钥来启用集成；否则，单击“跳过”按钮跳过 AWS 集成：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/2c7877d2-4b1d-4f0f-b201-82fa0b22efd7.png)

1.  单击“让我们开始”来探索 Sysdig Monitor：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/d6f58dc0-18cf-4693-b538-60c94ad211de.png)

现在你知道如何部署 Sysdig Monitor 并利用 Prometheus 指标了。

### 分析应用程序性能

延迟、流量、错误和饱和度被谷歌 SRE 团队视为黄金信号。

让我们按照这些说明来学习如何在 Kubernetes 上的应用程序中导航 Sysdig Monitor 界面以找到黄金信号：

1.  登录到您的 Sysdig 云原生可见性和安全平台仪表板，网址为[`app.sysdigcloud.com`](https://app.sysdigcloud.com)：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/c7426a65-1d78-4f74-a875-c3cbfc7bd9f1.png)

1.  资源会自动分组到主机和容器组中。单击组下拉菜单，然后选择部署和 pod：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/b184c906-1d1a-45fb-8193-98f03de12259.png)

1.  单击仪表板和指标下拉菜单，然后在默认仪表板 | 应用程序下选择 HTTP 仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/c5eb72b9-1df6-4418-b18c-71092bc0c82d.png)

1.  Sysdig 可以识别和解码诸如 HTTP 之类的应用程序协议，并为您提供详细的指标。在这个视图中，您可以看到请求的数量，最常请求的 URL 或端点，最慢的 URL，以及整个基础架构的 HTTP 响应代码和请求类型：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/3d50d433-cec7-40fe-b638-146b2c4e0ad8.png)

1.  作为性能故障排除的示例，将鼠标移动到*最慢的 URL*图表上，以识别问题和响应时间慢的应用程序。在我们的示例中，我们看到我们之前部署的 Kubecost Prometheus 服务器的响应时间慢，为 48 毫秒：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/06993da6-8804-404e-bafb-579e1be078ab.png)

现在您已经对如何浏览 Sysdig 仪表板有了基本了解。Sysdig 提供了深度跟踪功能，可在监视多个容器时使用。我们将在第九章中了解更多关于 Sysdig 的安全功能和异常检测用法。您可以在*另请参阅*部分的*Sysdig 示例*链接中找到其他用例。

## 另请参阅

+   Sysdig Falco - 行为活动监控工具：[`github.com/draios/oss-falco`](https://github.com/draios/oss-falco)

+   Sysdig Inspect - 容器故障排除和安全调查工具：[`github.com/draios/sysdig-inspect`](https://github.com/draios/sysdig-inspect)

+   监控分布式系统（Golden Signals）：[`landing.google.com/sre/sre-book/chapters/monitoring-distributed-systems/`](https://landing.google.com/sre/sre-book/chapters/monitoring-distributed-systems/)

+   Sysdig 示例：[`github.com/draios/sysdig/wiki/sysdig-examples`](https://github.com/draios/sysdig/wiki/sysdig-examples)

# 使用 Kubecost 管理资源成本

在本节中，我们将安装和配置开源 Kubecost 项目，该项目可以让您了解 Kubernetes 资源的成本相关可见性。您将学习如何监视资源成本以减少支出，并可能防止基于资源的停机。

## 准备就绪

此配方需要在 AWS 或 GCP 上部署的功能性 Kubernetes 集群。目前，不支持其他云提供商。

在执行以下配方中的命令之前，您需要安装`kubectl`和`helm`。您可以在第二章的*在 Kubernetes 上操作应用程序*中找到安装 Helm 的说明，*使用 Helm 图表部署工作负载*部分。

## 如何做…

本节进一步分为以下小节，以便简化流程：

+   安装 Kubecost

+   访问 Kubecost 仪表板

+   监控 Kubernetes 资源成本分配

### 安装 Kubecost

Kubecost 创建了当前和历史 Kubernetes 支出的 Kubernetes 资源粒度模型。这些模型可用于在支持多个应用程序、团队和部门的 Kubernetes 环境中提供资源分配和成本透明度的监控。在本教程中，我们将看一下使 Kubecost 运行起来的基本步骤：

1.  将 Kubecost 图表存储库添加到本地 Helm 图表存储库列表中：

```
$ helm repo add kubecost https://kubecost.github.io/cost-analyzer/
```

1.  使用`Helm install`命令将 Kubecost 安装到`kubecost`命名空间中：

```
$ helm install kubecost/cost-analyzer --namespace kubecost --name kubecost --set kubecostToken="dGVzdEB0ZXN0LmNvbQ==xm343yadf98"
```

1.  验证所有的 pod 都在运行。正如您所看到的，该项目还部署了自己的 Prometheus 和 Grafana 实例：

```
$ kubectl get pods -nkubecost
NAME READY STATUS RESTARTS AGE
cost-analyzer-checks-1571781600-6mhwh 0/1 Completed 0 7m1s
kubecost-cost-analyzer-54bc969689-8rznl 3/3 Running 0 9m7s
kubecost-grafana-844d4b9844-dkdvn 3/3 Running 0 9m7s
kubecost-prometheus-alertmanager-85bbbd6b7b-fpmqr 2/2 Running 0 9m7s
kubecost-prometheus-kube-state-metrics-857c5d4b4f-gxmgj 1/1 Running 0 9m7s
kubecost-prometheus-node-exporter-6bsp2 1/1 Running 0 9m7s
kubecost-prometheus-node-exporter-jtw2h 1/1 Running 0 9m7s
kubecost-prometheus-node-exporter-k69fh 1/1 Running 0 9m7s
kubecost-prometheus-pushgateway-7689458dc9-rx5jj 1/1 Running 0 9m7s
kubecost-prometheus-server-7b8b759d74-vww8c 2/2 Running 0 9m7s
```

如果您有现有的 Prometheus 部署，`node-exporter` pod 可能会卡在 Pending 模式。在这种情况下，您需要使用不同的端口来部署 Kubecost；否则，pod 将无法获取所请求的 pod 端口。

现在您已经安装了 Kubecost 成本分析器，并且具有在 Kubernetes 环境中操作所需的一系列组件。

### 访问 Kubecost 仪表板

让我们按照这些说明来访问 Kubecost 仪表板，在那里您可以实时监视您的 Kubernetes 资源及其成本：

1.  获取`kubecost`命名空间中服务的列表：

```
$ kubectl get svc -nkubecost
NAME TYPE CLUSTER-IP EXTERNAL-IP PORT(S) AGE
kubecost-cost-analyzer ClusterIP 100.65.53.41 <none> 9001/TCP,9003/TCP,9090/TCP 13m
kubecost-grafana ClusterIP 100.69.52.23 <none> 80/TCP 13m
kubecost-prometheus-alertmanager ClusterIP 100.71.217.248 <none> 80/TCP 13m
kubecost-prometheus-kube-state-metrics ClusterIP None <none> 80/TCP 13m
kubecost-prometheus-node-exporter ClusterIP None <none> 9100/TCP 13m
kubecost-prometheus-pushgateway ClusterIP 100.69.137.163 <none> 9091/TCP 13m
kubecost-prometheus-server ClusterIP 100.64.7.82 <none> 80/TCP 13m
```

1.  创建一个端口转发以使用`kubectl port-forward`命令访问 Kubecost UI。该命令将本地端口`9090`转发到 Kubecost 成本分析器 pod：

```
$ kubectl port-forward --namespace kubecost deployment/kubecost-cost-analyzer 9090
```

作为替代方案，您可以使用`kubectl edit svc kubecost-cost-analyzer -nkubecost`命令对`kubecost-cost-analyzer`服务进行修补，并将服务类型`ClusterIP`更改为`LoadBalancer`，以使用云负载均衡器在外部公开服务。

1.  在您的 Web 浏览器中打开地址`http://localhost:9090`（或者如果使用 LoadBalancer，则是外部 IP）。您应该看到 Kubecost 登录页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/b70a21da-4594-4d5c-85f7-b6d3c3302ddb.png)

1.  通过将额外的 Kubecost 端点添加到一个中并用于监视单个仪表板上的多个集群来扩展仪表板。如果您有多个集群，请单击添加新集群图标，并添加来自其他集群的端点 URL：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/2fe36cb1-7c6b-487c-a5ac-6c4eaf92d788.png)

### 监控 Kubernetes 资源成本分配

让我们按照这些说明来学习如何使用 Kubecost 监视与 Kubernetes 相关的云支出，并找到可能的节省建议：

1.  通过按照前面的步骤“访问 Kubecost 仪表板”访问您的 Kubecost 仪表板。在仪表板上点击您的集群名称以访问详细摘要。此视图将显示月度成本和闲置资源的集群效率：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/c2342587-22dc-4e24-86da-1f1a4da0a660.png)

1.  点击“实时资产”按钮。此视图显示与当前云提供商相关的实时成本。在我们的示例中，有一个主节点，三个使用`kops`在 AWS 集群上部署的工作节点 Kubernetes 集群，自创建以来每个节点的账单大约为 60 美元：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/21ce2025-eef5-459f-8c13-92979fed7254.png)

1.  点击“分配”菜单。此视图显示当前命名空间中的累积成本。您可以应用范围过滤器，以获取所选命名空间中资源的每日、每周、每月或自定义范围成本：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/a3c40f99-8b8b-4fcc-ae0e-e3db77f3f0e1.png)

1.  点击“节省”菜单。此菜单中的信息非常重要，并指向您可以采取的可能的优化步骤。例如，以下视图显示我们有两个利用率不足的节点（利用率低于 60%），如果我们缩减集群，可以节省成本。在这种情况下，我们可以排空节点并缩减集群。点击每个节省类别，了解如何采取行动以实现此处显示的节省率：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/5dfbbb6f-9ff7-4a36-8d9f-08def74d837e.png)

1.  点击“健康”菜单。此视图显示可靠性评估和集群健康风险：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/ccff73d9-7b28-491e-93ca-a74e0fe9f92a.png)

1.  禁用“显示全部”选项以列出需要您关注的问题。在我们的示例中，我们看到一个高优先级指向 Crash looping pods。您可以按照本章节中“检查容器”部分的说明进一步识别问题：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/065355fd-c651-420b-b50a-d58bb056c728.png)

1.  点击“通知”菜单。从此菜单，您可以指定如何处理通知。如果您有 Slack 频道，可以在此处点击“添加”按钮将通知转发到该频道；否则，电子邮件通知可作为选项：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/27ea1986-351c-457b-9c0e-9bd59921c888.png)

现在您已经了解如何监控项目成本，并更好地了解了如何采取行动来增加 DevOps 环境的投资回报。

## 另请参阅

+   Kubecost 文档：[`docs.kubecost.com/`](http://docs.kubecost.com/)

+   将 Kubecost 部署为一个 pod：[`github.com/kubecost/cost-model/blob/master/deploying-as-a-pod.md`](https://github.com/kubecost/cost-model/blob/master/deploying-as-a-pod.md)


# 第九章：保护应用程序和集群

00000000000000 在本章中，我们将讨论在从测试到生产的过程中，减少攻击面和保护 Kubernetes 集群的基本步骤。我们将讨论安全审计，将 DevSecOps 构建到 CI/CD 流水线中，检测性能分析的指标，以及如何安全地管理秘密和凭据。

在本章中，我们将介绍以下配方：

+   使用 RBAC 加固集群安全

+   配置 Pod 安全策略

+   使用 Kubernetes CIS 基准进行安全审计

+   将 DevSecOps 构建到流水线中，使用 Aqua Security

+   使用 Falco 监视可疑的应用程序活动

+   使用 HashiCorp Vault 安全保护凭据

# 技术要求

本章中的配方要求您通过遵循第一章中描述的建议方法之一部署了功能齐全的 Kubernetes 集群，*构建生产就绪的 Kubernetes 集群*。

Kubernetes 命令行工具`kubectl`将用于本章中其余的配方，因为它是针对 Kubernetes 集群运行命令的主要命令行界面。我们还将使用`helm`，在那里 Helm 图表可用于部署解决方案。

# 使用 RBAC 加固集群安全

在诸如 Kubernetes 之类的复杂系统中，授权机制用于设置谁被允许对集群资源进行何种更改并操纵它们。**基于角色的访问控制**（**RBAC**）是一种高度集成到 Kubernetes 中的机制，它授予用户和应用程序对 Kubernetes API 的细粒度访问权限。

作为良好的实践，您应该与`NodeRestriction`准入插件一起使用 Node 和 RBAC 授权器。

在本节中，我们将介绍如何启用 RBAC 并创建角色和角色绑定，以授予应用程序和用户对集群资源的访问权限。

## 准备工作

确保您已准备好启用 RBAC 的 Kubernetes 集群（自 Kubernetes 1.6 以来，默认情况下已启用 RBAC），并且已配置`kubectl`和`helm`，以便您可以管理集群资源。在尝试为用户创建密钥之前，还需要确保您拥有`openssl`工具来创建私钥。

将`k8sdevopscookbook/src`存储库克隆到您的工作站，以便在`chapter9`目录中使用清单文件，如下所示：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd src/chapter9/rbac
```

RBAC 从 Kubernetes 1.6 版本开始默认启用。如果由于任何原因禁用了 RBAC，请使用`--authorization-mode=RBAC`启动 API 服务器以启用 RBAC。

## 如何做…

本节进一步分为以下子节，以使此过程更容易：

+   查看默认角色

+   创建用户帐户

+   创建角色和角色绑定

+   测试 RBAC 规则

### 查看默认角色

RBAC 是 Kubernetes 集群的核心组件，允许我们创建和授予对象角色，并控制对集群内资源的访问。这个步骤将帮助您了解角色和角色绑定的内容。

让我们执行以下步骤来查看我们集群中的默认角色和角色绑定：

1.  使用以下命令查看默认的集群角色。您将看到一个长长的混合列表，其中包括`system:`、`system:controller:`和一些其他带有前缀的角色。`system:*`角色由基础设施使用，`system:controller`角色由 Kubernetes 控制器管理器使用，它是一个监视集群共享状态的控制循环。一般来说，当您需要解决权限问题时，了解它们都是很好的，但我们不会经常使用它们：

```
$ kubectl get clusterroles
$ kubectl get clusterrolebindings
```

1.  查看由 Kubernetes 拥有的系统角色之一，以了解它们的目的和限制。在下面的示例中，我们正在查看`system:node`，它定义了 kubelet 的权限。在规则的输出中，`apiGroups:`表示核心 API 组，`resources`表示 Kubernetes 资源类型，`verbs`表示角色上允许的 API 操作：

```
$ kubectl get clusterroles system:node -oyaml
```

1.  让我们查看默认的用户角色，因为它们是我们更感兴趣的角色。没有`system:`前缀的角色是面向用户的角色。以下命令将仅列出非`system:`前缀的角色。通过 RoleBindings 在特定命名空间中授予的主要角色是`admin`、`edit`和`view`角色：

```
$ kubectl get clusterroles | grep -v '^system'
NAME AGE
admin 8d #gives read-write access
 to all resources
cluster-admin 8d #super-user, gives read-write access
 to all resources
edit 8d #allows create/update/delete on resources except RBAC permissions
kops:dns-controller 8d
kube-dns-autoscaler 8d
view 8d #read-only access to resources
```

1.  现在，使用以下命令查看默认的集群绑定，即`cluster-admin`。您将看到此绑定使用`cluster-admin`角色为`system:masters`组提供了集群范围的超级用户权限：

```
$ kubectl get clusterrolebindings/cluster-admin -o yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
...
roleRef:
 apiGroup: rbac.authorization.k8s.io
 kind: ClusterRole
 name: cluster-admin
subjects:
- apiGroup: rbac.authorization.k8s.io
 kind: Group
 name: system:masters
```

自 Kubernetes 1.6 版本发布以来，默认情况下启用了 RBAC，并且新用户可以创建并在管理员用户将权限分配给特定资源之前不具备任何权限。现在，您已经了解了可用的默认角色。

在接下来的教程中，您将学习如何创建新的角色和角色绑定，并授予帐户所需的权限。

### 创建用户帐户

正如 Kubernetes 文档中所解释的，Kubernetes 没有用于表示普通用户帐户的对象。因此，它们需要在外部进行管理（查看*参见*部分的*Kubernetes 身份验证*文档，以获取更多详细信息）。本教程将向您展示如何使用私钥创建和管理用户帐户。

让我们执行以下步骤来创建一个用户帐户：

1.  为示例用户创建一个私钥。在我们的示例中，密钥文件是`user3445.key`：

```
$ openssl genrsa -out user3445.key 2048
```

1.  创建一个名为`user3445.csr`的**证书签名请求**（**CSR**），使用我们在*步骤 1*中创建的私钥。在`-subj`参数中设置用户名（`/CN`）和组名（`/O`）。在以下示例中，用户名是`john.geek`，而组名是`development`：

```
$ openssl req -new -key user3445.key \
-out user3445.csr \
-subj "/CN=john.geek/O=development"
```

1.  要使用内置签名者，您需要定位集群的集群签名证书。默认情况下，`ca.crt`和`ca.key`文件应位于`/etc/kubernetes/pki/`目录中。如果您正在使用 kops 进行部署，您可以从`s3://$BUCKET_NAME/$KOPS_CLUSTER_NAME/pki/private/ca/*.key`和`s3://$BUCKET_NAME/$KOPS_CLUSTER_NAME/pki/issued/ca/*.crt`下载集群签名密钥。一旦您找到了密钥，将以下代码中提到的`CERT_LOCATION`更改为文件的当前位置，并生成最终签名证书：

```
$ openssl x509 -req -in user3445.csr \
-CA CERT_LOCATION/ca.crt \
-CAkey CERT_LOCATION/ca.key \
-CAcreateserial -out user3445.crt \
-days 500
```

1.  如果所有文件都已找到，*步骤 3*中的命令应返回类似以下的输出：

```
Signature ok
subject=CN = john.geek, O = development
Getting CA Private Key
```

在我们继续之前，请确保将签名密钥存储在安全的目录中。作为行业最佳实践，建议使用秘密引擎或 Vault 存储。您将在本章后面的*使用 HashiCorp Vault 保护凭据*中了解有关 Vault 存储的更多信息。

1.  使用新用户凭据创建一个新的上下文：

```
$ kubectl config set-credentials user3445 --client-certificate=user3445.crt --client-key=user3445.key
$ kubectl config set-context user3445-context --cluster=local --namespace=secureapp --user=user3445
```

1.  使用以下命令列出现有上下文。您将看到已创建新的`user3445-context`：

```
$ kubectl config get-contexts
CURRENT NAME                    CLUSTER AUTHINFO NAMESPACE
*       service-account-context local   kubecfg
 user3445-context        local   user3445 secureapp
```

1.  现在，尝试使用新用户上下文列出 pod。由于新用户没有任何角色，并且新用户默认情况下没有分配任何角色，因此您将收到访问被拒绝的错误：

```
$ kubectl --context=user3445-context get pods
Error from server (Forbidden): pods is forbidden: User "john.geek" cannot list resource "pods" in API group "" in the namespace "secureapps"
```

1.  可选地，您可以使用`openssl base64 -in <infile> -out <outfile>`命令对所有三个文件（`user3445.crt`，`user3445.csr`和`user3445.key`）进行`base64`编码，并将填充的`config-user3445.yml`文件分发给您的开发人员。示例文件可以在本书的 GitHub 存储库的`src/chapter9/rbac`目录中找到。有许多方法可以分发用户凭据。使用文本编辑器查看示例：

```
$ cat config-user3445.yaml
```

通过这样，您已经学会了如何创建新用户。接下来，您将创建角色并将其分配给用户。

### 创建角色和 RoleBindings

角色和 RoleBindings 始终在定义的命名空间中使用，这意味着权限只能授予与角色和 RoleBindings 本身相同命名空间中的资源，而不是用于授予集群范围资源（如节点）权限的 ClusterRoles 和 ClusterRoleBindings。

让我们执行以下步骤在我们的集群中创建一个示例角色和 RoleBinding：

1.  首先，创建一个我们将创建角色和 RoleBinding 的命名空间。在我们的示例中，命名空间是`secureapp`：

```
$ kubectl create ns secureapp
```

1.  使用以下规则创建一个角色。该角色基本上允许在我们在*步骤 1.*中创建的`secureapp`命名空间中对部署、副本集和 Pod 执行所有操作。请注意，授予的任何权限都只是增量的，没有拒绝规则：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
 namespace: secureapp
 name: deployer
rules:
- apiGroups: ["", "extensions", "apps"]
 resources: ["deployments", "replicasets", "pods"]
 verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
EOF
```

1.  使用`deployer`角色为用户名`john.geek`在`secureapp`命名空间中创建一个 RoleBinding。我们这样做是因为 RoleBinding 只能引用同一命名空间中存在的角色：

```
$ cat <<EOF | kubectl apply -f -
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
 name: deployer-binding
 namespace: secureapp
subjects:
- kind: User
 name: john.geek
 apiGroup: ""
roleRef:
 kind: Role
 name: deployer
 apiGroup: ""
EOF
```

通过这样，您已经学会了如何创建一个新的角色，并使用 RoleBindings 授予用户权限。

### 测试 RBAC 规则

让我们执行以下步骤来测试我们之前创建的角色和 RoleBinding：

1.  在用户有权限访问的`secureapp`命名空间中部署一个测试 Pod：

```
$ cat <<EOF | kubectl --context=user3445-context apply -f -
apiVersion: v1
kind: Pod
metadata:
 name: busybox
 namespace: secureapp
spec:
 containers:
 - image: busybox
 command:
 - sleep
 - "3600"
 imagePullPolicy: IfNotPresent
 name: busybox
 restartPolicy: Always
EOF
```

列出新用户上下文中的 Pod。在*创建用户帐户*中失败的相同命令在*步骤 7*中现在应该能够成功执行：

```
$ kubectl --context=user3445-context get pods 
NAME    READY STATUS  RESTARTS AGE
busybox 1/1   Running 1        2m
```

如果您尝试在不同的命名空间中创建相同的 Pod，您将看到该命令将无法执行。

## 工作原理...

这个示例向您展示了如何在 Kubernetes 中创建新用户，并快速创建角色和 RoleBindings 以授予用户帐户对 Kubernetes 的权限。

Kubernetes 集群有两种类型的用户：

+   **用户帐户**：用户帐户是外部管理的普通用户。

+   **服务账户**：服务账户是与 Kubernetes 服务相关联并由 Kubernetes API 管理其自己资源的用户。

您可以通过查看*另请参阅*部分中的*管理服务账户*链接来了解更多关于服务账户的信息。

在*创建角色和 RoleBindings*配方中，在*步骤 1*中，我们创建了一个名为`deployer`的角色。然后，在*步骤 2*中，我们将与 deployer 角色关联的规则授予了用户账户`john.geek`。

RBAC 使用`rbac.authorization.k8s.io` API 来做出授权决策。这允许管理员使用 Kubernetes API 动态配置策略。如果您想要使用现有的角色并给予某人集群范围的超级用户权限，您可以使用`cluster-admin` ClusterRole 和 ClusterRoleBinding。ClusterRoles 没有命名空间限制，并且可以在任何命名空间中执行具有授予的权限的命令。总的来说，在分配`cluster-admin` ClusterRole 给用户时应该小心。ClusterRoles 也可以像 Roles 一样限制到命名空间，如果它们与 RoleBindings 一起使用来授予权限。

## 另请参阅

+   Kubernetes 中的 RBAC 授权文档：[`kubernetes.io/docs/reference/access-authn-authz/rbac/#rolebinding-and-clusterrolebinding`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#rolebinding-and-clusterrolebinding)

+   有关默认角色和角色绑定的更多信息：[`kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings)

+   基于 Kubernetes 审计日志自动生成 RBAC 策略：[`github.com/liggitt/audit2rbac`](https://github.com/liggitt/audit2rbac)

+   Kubernetes 认证：[`kubernetes.io/docs/reference/access-authn-authz/authentication/`](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)

+   管理服务账户：[`kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/`](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)

+   kubectl-bindrole 工具用于查找绑定到指定 ServiceAccount 的 Kubernetes 角色：[`github.com/Ladicle/kubectl-bindrole`](https://github.com/Ladicle/kubectl-bindrole)

# 配置 Pod 安全策略

Pod 安全策略（PSP）在 Kubernetes 集群上用于启用对 Pod 创建的细粒度授权，并控制 Pod 的安全方面。PodSecurityPolicy 对象定义了接受 Pod 进入集群并按预期运行的条件。

在本节中，我们将介绍在 Kubernetes 上重新创建和配置 PSP。

## 准备工作

确保您已准备好启用 RBAC 的 Kubernetes 集群（自 Kubernetes 1.6 以来，RBAC 默认已启用），并配置`kubectl`和`helm`来管理集群资源。

将`k8sdevopscookbook/src`存储库克隆到您的工作站，以便使用`chapter9`目录中的清单文件，如下所示：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd src/chapter9/psp
```

通过运行`kubectl get psp`命令来验证集群是否需要启用 PodSecurityPolicy。如果收到消息说明`服务器没有资源类型"podSecurityPolicies"。`，则需要在集群上启用 PSP。

## 操作步骤：

本节进一步分为以下子节，以使此过程更加简单：

+   在 EKS 上启用 PSP

+   在 GKE 上启用 PSP

+   在 AKS 上启用 PSP

+   创建受限制的 PSP

### 在 EKS 上启用 PSP

作为最佳实践，在创建自己的策略之前，不应该启用 PSP。本文将带您了解如何在 Amazon EKS 上启用 PSP 以及如何审查默认策略。

让我们执行以下步骤：

1.  部署 Kubernetes 版本 1.13 或更高版本。PSP 将默认启用。默认配置带有一个名为`eks.privileged`的非破坏性策略，没有限制。使用以下命令查看默认策略：

```
$ kubectl get psp eks.privileged
NAME           PRIV CAPS SELINUX  RUNASUSER FSGROUP  SUPGROUP READONLYROOTFS VOLUMES
eks.privileged true *    RunAsAny RunAsAny  RunAsAny RunAsAny false          *
```

1.  描述策略以查看其完整详情，如下所示：

```
$ kubectl describe psp eks.privileged
```

1.  要审查、恢复或删除默认 PSP，请使用示例存储库中`src/chapter9/psp`目录中名为`eks-privileged-psp.yaml`的 YAML 清单。

### 在 GKE 上启用 PSP

作为最佳实践，在创建自己的策略之前，不应该启用 PSP。本文将带您了解如何在 Google Kubernetes Engine（GKE）上启用 PSP 以及如何审查默认策略。

让我们执行以下步骤：

1.  您可以通过运行以下命令在部署的集群上启用 PSP，按照第一章中的说明，*构建生产就绪的 Kubernetes 集群*，在*在 GKE 上配置托管的 Kubernetes 集群*中。将`k8s-devops-cookbook-1`替换为您自己的集群名称：

```
$ gcloud beta container clusters update k8s-devops-cookbook-1 --enable-pod-security-policy
```

1.  默认配置带有一个名为`gce.privileged`的非破坏性策略，没有限制，还有其他几个策略。使用以下命令查看默认策略：

```
$ kubectl get psp
NAME                         PRIV  CAPS SELINUX  RUNASUSER FSGROUP  SUPGROUP READONLYROOTFS VOLUMES
gce.event-exporter           false      RunAsAny RunAsAny  RunAsAny RunAsAny false          hostPath,secret
gce.fluentd-gcp              false      RunAsAny RunAsAny  RunAsAny RunAsAny false          configMap,hostPath,secret
gce.persistent-volume-binder false      RunAsAny RunAsAny  RunAsAny RunAsAny false          nfs,secret,projected
gce.privileged               true  *    RunAsAny RunAsAny  RunAsAny RunAsAny false          *
gce.unprivileged-addon       false SETPCAP,MKNOD,AUDIT_WRITE,CHOWN,NET_RAW,DAC_OVERRIDE,FOWNER,FSETID,KILL,SETGID,SETUID,NET_BIND_SERVICE,SYS_CHROOT,SETFCAP RunAsAny RunAsAny RunAsAny RunAsAny false emptyDir,configMap,secret,projected
```

1.  描述策略以查看其完整详情，如下所示：

```
$ kubectl describe psp gce.privileged
```

1.  要查看、恢复或删除默认 PSP，请使用示例存储库中的 YAML 清单，在`src/chapter9/psp`中命名为`gce-privileged-psp.yaml`。

### 在 AKS 上启用 PodSecurityPolicy

作为最佳实践，在创建自己的策略之前，不应启用 PodSecurityPolicy。本教程将带您了解如何在**Azure Kubernetes Service**（**AKS**）上启用 PSP 以及如何查看默认策略。

让我们执行以下步骤：

1.  您可以按照第一章 *构建生产就绪的 Kubernetes 集群*中给出的说明，在*在 AKS 上配置托管的 Kubernetes 集群*教程中运行以下命令来在部署的集群上启用 PSP。将`k8sdevopscookbook`替换为您自己的资源组，将`AKSCluster`替换为您的集群名称：

```
$ az aks create --resource-group k8sdevopscookbook \
--name AKSCluster \
--enable-pod-security-policy
```

1.  默认配置带有一个名为`privileged`的非破坏性策略，没有限制。使用以下命令查看默认策略：

```
$ kubectl get psp
NAME PRIV CAPS SELINUX RUNASUSER FSGROUP SUPGROUP READONLYROOTFS VOLUMES
privileged true * RunAsAny RunAsAny RunAsAny RunAsAny false * configMap,emptyDir,projected,secret,downwardAPI,persistentVolumeClaim
```

1.  描述策略以查看其完整详情，如下所示：

```
$ kubectl describe psp privileged
```

1.  要查看、恢复或删除默认 PSP，请使用示例存储库中的 YAML 清单，在`src/chapter9/psp`中命名为`aks-privileged-psp.yaml`。

### 创建受限的 PSPs

作为安全最佳实践，建议限制容器在 Pod 中以 root 用户特权运行，以限制任何可能的风险。在特权模式下运行时，容器内运行的进程具有与容器外进程相同的特权和访问权限，这可能会增加攻击者访问一些管理能力的风险。

让我们执行以下步骤来创建一个受限的 PodSecurityPolicy：

1.  部署一个新的受限`PodSecurityPolicy`：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: extensions/v1beta1
kind: PodSecurityPolicy
metadata:
 name: restricted-psp
spec:
 privileged: false
 runAsUser:
 rule: MustRunAsNonRoot
 seLinux:
 rule: RunAsAny
 fsGroup:
 rule: RunAsAny
 supplementalGroups:
 rule: RunAsAny
 volumes:
 - '*'
EOF
```

1.  确认策略已创建。您会注意到`RUNASUSER`列显示`MustRunAsNonRoot`，这表示不允许使用 root 权限：

```
$ kubectl get psp restricted-psp
NAME           PRIV  CAPS     SELINUX  RUNASUSER        FSGROUP   SUPGROUP READONLYROOTFS VOLUMES
restricted-psp false          RunAsAny MustRunAsNonRoot RunAsAny  RunAsAny false          *
```

1.  通过运行需要 root 访问权限的 pod 来验证 PSP。部署将失败，并显示一条消息，指出`container has runAsNonRoot and image will run as root`，如下代码所示：

```
$ kubectl run --image=mariadb:10.4.8 mariadb --port=3306 --env="MYSQL_ROOT_PASSWORD=my-secret-pw"
$ kubectl get pods
NAME                     READY STATUS                                                RESTARTS AGE
mariadb-5584b4f9d8-q6whd 0/1   container has runAsNonRoot and image will run as root 0        46s
```

通过这样，您已经学会了如何创建一个受限的 PodSecurityPolicy。

## 还有更多...

此部分进一步分为以下子部分，以使此过程更加简单：

+   限制 Pod 访问特定卷类型

+   使用 Kubernetes PSPs 顾问

### 限制 Pod 访问特定卷类型

作为 PodSecurityPolicy 规则的一部分，您可能希望限制使用特定类型的卷。在本教程中，您将学习如何限制容器访问卷类型。

让我们执行以下步骤来创建 PodSecurityPolicy：

1.  创建新的受限`PodSecurityPolicy`。此策略仅限制卷类型为`nfs`：

```
$ cat <<EOF | kubectl apply -f -
kind: PodSecurityPolicy
metadata:
 name: restricted-vol-psp
spec:
 privileged: false
 runAsUser:
 rule: RunAsAny
 seLinux:
 rule: RunAsAny
 fsGroup:
 rule: RunAsAny
 supplementalGroups:
 rule: RunAsAny
 volumes:
 - 'nfs'
EOF
```

1.  通过部署需要持久存储的应用程序来验证策略。在这里，我们将使用前几章的 MinIO 示例。部署应该失败，并显示消息“不允许使用 persistentVolumeClaim 卷”。

```
$ kubectl create -f \
https://raw.githubusercontent.com/k8sdevopscookbook/src/master/chapter6/minio/minio.yaml
```

1.  删除 PSP 和部署：

```
$ kubectl delete psp restricted-vol-psp
$ kubectl delete -f \
https://raw.githubusercontent.com/k8sdevopscookbook/src/master/chapter6/minio/minio.yaml
```

1.  新 PSP 允许的卷集包括`configMap`、`downwardAPI`、`emptyDir`、`persistentVolumeClaim`、`secret`和`projected`。您可以通过转到*支持的卷类型*链接在*另请参阅*部分找到卷类型的完整列表。使用以下内容创建新的受限 PodSecurityPolicy。此策略仅限制卷类型为`persistentVolumeClaim`：

```
$ cat <<EOF | kubectl apply -f -
kind: PodSecurityPolicy
metadata:
 name: permit-pvc-psp
spec:
 privileged: false
 runAsUser:
 rule: RunAsAny
 seLinux:
 rule: RunAsAny
 fsGroup:
 rule: RunAsAny
 supplementalGroups:
 rule: RunAsAny
 volumes:
 - 'persistentVolumeClaim'
EOF
```

1.  重复*步骤 2*以部署应用程序。这次，将允许创建`persistentVolumeClaim`，并将创建 Pod 请求的 PVC。

### 使用 Kubernetes PodSecurityPolicy 顾问

Kubernetes PodSecurityPolicy Advisor 是 Sysdig 的一个简单工具，用于强制执行 Kubernetes 中的最佳安全实践。`kube-psp-advisor`扫描 Kubernetes 资源的现有安全上下文，并为集群中的资源生成 PSP，以删除不必要的特权。

让我们执行以下步骤在我们的集群上启用`kube-psp-advisor`：

1.  克隆存储库并使用以下命令构建项目：

```
$ git clone https://github.com/sysdiglabs/kube-psp-advisor
$ cd kube-psp-advisor && make build
```

1.  通过执行二进制文件运行扫描过程。如果要将扫描限制为命名空间，可以通过向命令添加`--namespace=`参数来指定，类似于以下代码中所示。如果不这样做，它将扫描整个集群。这样做后，将生成一个`PodSecurityPolicy`：

```
$ ./kube-psp-advisor --namespace=secureapp > psp-advisor.yaml
```

1.  审查`psp-advisor.yaml`文件的内容，并应用生成的 PSP：

```
$ cat psp-advisor.yaml
$ kubectl apply -f psp-advisor.yaml
```

通过这样，您已经学会了如何以更简单的方式生成 PSP，以减少可能增加攻击面的不必要权限。

## 另请参阅

+   Kubernetes 文档-PodSecurityPolicy：[`kubernetes.io/docs/concepts/policy/pod-security-policy/`](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)

+   支持的卷类型：[`kubernetes.io/docs/concepts/storage/volumes/#types-of-volumes`](https://kubernetes.io/docs/concepts/storage/volumes/#types-of-volumes)

# 使用 Kubernetes CIS 基准进行安全审计

Kubernetes CIS 基准是业界专家接受的安全配置最佳实践。CIS 基准指南可以从**互联网安全中心**（**CIS**）网站[`www.cisecurity.org/`](https://www.cisecurity.org/)下载为 PDF 文件。`kube-bench`是一个自动化记录检查的应用程序。

在本节中，我们将介绍安装和使用开源的`kube-bench`工具，以运行 Kubernetes CIS 基准，对 Kubernetes 集群进行安全审计。

## 做好准备

对于这个配方，我们需要准备好一个 Kubernetes 集群，并安装 Kubernetes 命令行工具`kubectl`。

将`k8sdevopscookbook/src`存储库克隆到您的工作站，以使用`chapter9`目录中的清单文件，如下所示：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd src/chapter9/cis
```

一些测试针对 Kubernetes 节点，只能在完全自我管理的集群上执行，您可以控制主节点。因此，托管集群（如 EKS、GKE、AKS 等）将无法执行所有测试，并需要不同的作业描述或参数来执行测试。在必要时会提到这些。

## 如何操作…

本节进一步分为以下子节，以使此过程更加简单：

+   在 Kubernetes 上运行 kube-bench

+   在托管的 Kubernetes 服务上运行 kube-bench

+   在 OpenShift 上运行 kube-bench

+   运行 kube-hunter

### 在 Kubernetes 上运行 kube-bench

CIS 基准对主节点和工作节点都有测试。因此，只有在您可以控制主节点的自我管理集群上才能完成测试的全部范围。在这个配方中，您将学习如何直接在主节点和工作节点上运行 kube-bench。

让我们执行以下步骤来运行 CIS 推荐的测试：

1.  下载并安装`kube-bench`命令行界面到您的一个主节点和一个工作节点：

```
$ curl --silent --location "https://github.com/aquasecurity/kube-bench/releases/download/v0.1.0/kube-bench_0.1.0_linux_amd64.tar.gz" | tar xz -C /tmp
$ sudo mv /tmp/kube-bench /usr/local/bin
```

1.  SSH 登录到您的 Kubernetes 主节点并运行以下命令。它将快速返回测试结果，并附有解释和建议在之后运行的其他手动测试的列表。在这里，您可以看到`31`个检查通过，`36`个测试失败：

```
$ kube-bench master
...
== Summary ==
31 checks PASS
36 checks FAIL
24 checks WARN
1 checks INFO
```

1.  要保存结果，请使用以下命令。测试完成后，将`kube-bench-master.txt`文件移动到本地主机进行进一步审查：

```
$ kube-bench master > kube-bench-master.txt
```

1.  审查`kube-bench-master.txt`文件的内容。您将看到与以下类似的内容，这是来自 Kubernetes 指南的 CIS 基准检查的状态：

```
[INFO] 1 Master Node Security Configuration
[INFO] 1.1 API Server
[PASS] 1.1.1 Ensure that the --anonymous-auth argument is set to false (Not Scored)
[FAIL] 1.1.2 Ensure that the --basic-auth-file argument is not set (Scored)
[PASS] 1.1.3 Ensure that the --insecure-allow-any-token argument is not set (Not Scored)
[PASS] 1.1.4 Ensure that the --kubelet-https argument is set to true (Scored)
[FAIL] 1.1.5 Ensure that the --insecure-bind-address argument is not set (Scored)
[FAIL] 1.1.6 Ensure that the --insecure-port argument is set to 0 (Scored)
[PASS] 1.1.7 Ensure that the --secure-port argument is not set to 0 (Scored)
[FAIL] 1.1.8 Ensure that the --profiling argument is set to false (Scored)
[FAIL] 1.1.9 Ensure that the --repair-malformed-updates argument is set to false (Scored)
[PASS] 1.1.10 Ensure that the admission control plugin AlwaysAdmit is not set (Scored)
...
```

测试被分成了几个类别，这些类别是根据 CIS 基准指南中建议的，比如 API 服务器、调度器、控制器管理器、配置管理器、etcd、一般安全原语和 PodSecurityPolicies。

1.  按照报告中*修复*部分建议的方法来修复失败的问题，并重新运行测试以确认已进行修正。您可以在先前报告中建议的一些修复措施如下：

```
== Remediations ==
1.1.2 Follow the documentation and configure alternate mechanisms for authentication. Then,
edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.manifest
on the master node and remove the --basic-auth-file=<filename>
parameter.

1.1.5 Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.manife$
on the master node and remove the --insecure-bind-address
parameter.

1.1.6 Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.manife$
apiserver.yaml on the master node and set the below parameter.
--insecure-port=0

1.1.8 Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.manife$
on the master node and set the below parameter.
--profiling=false

1.2.1 Edit the Scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.manifest
file on the master node and set the below parameter.
--profiling=false
...
```

1.  让我们从先前的列表中选取一个问题。`1.2.1`建议我们禁用分析 API 端点。原因是通过分析数据可以揭示高度敏感的系统信息，并且通过对集群进行分析可能会产生大量数据和负载，从而使该功能使集群无法服务（拒绝服务攻击）。编辑`kube-scheduler.manifest`文件，并在`kube-schedule`命令之后添加`--profiling=false`，如下所示：

```
...
spec:
 containers:
 - command:
 - /bin/sh
 - -c
 - mkfifo /tmp/pipe; (tee -a /var/log/kube-scheduler.log < /tmp/pipe & ) ; exec
 /usr/local/bin/kube-scheduler --profiling=False --kubeconfig=/var/lib/kube-scheduler/kubeconfig
 --leader-elect=true --v=2 > /tmp/pipe 2>&1
...
```

1.  再次运行测试并确认`1.2.1`上的问题已经得到纠正。在这里，您可以看到通过的测试数量从`31`增加到`32`。还有一个检查已经通过：

```
$ kube-bench master
...
== Summary ==
32 checks PASS
35 checks FAIL
24 checks WARN
1 checks INFO
```

1.  在工作节点上运行以下命令进行测试：

```
$ kube-bench node
...
== Summary ==
9 checks PASS
12 checks FAIL
2 checks WARN
1 checks INFO
```

1.  要保存结果，请使用以下命令。测试完成后，将`kube-bench-worker.txt`文件移动到本地主机进行进一步审查：

```
$ kube-bench node > kube-bench-worker.txt
```

1.  审查`kube-bench-worker.txt`文件的内容。您将看到与以下类似的内容，这是来自 Kubernetes 指南的 CIS 基准检查的状态：

```
[INFO] 2 Worker Node Security Configuration
[INFO] 2.1 Kubelet
[PASS] 2.1.1 Ensure that the --anonymous-auth argument is set to false (Scored)
[FAIL] 2.1.2 Ensure that the --authorization-mode argument is not set to AlwaysAllow (Scored)
[PASS] 2.1.3 Ensure that the --client-ca-file argument is set as appropriate (Scored)
...
```

同样，按照所有的修复措施，直到您清除了主节点和工作节点上的所有失败测试。

### 在托管的 Kubernetes 服务上运行 kube-bench

托管的 Kubernetes 服务（如 EKS、GKE、AKS 等）与您无法在主节点上运行检查的区别在于，您要么只能遵循上一个教程中的工作节点检查，要么运行一个 Kubernetes 作业来验证您的环境。在本教程中，您将学习如何在托管的 Kubernetes 服务节点上运行 kube-bench，以及在您没有直接 SSH 访问节点的情况下运行 kube-bench 的情况。

让我们执行以下步骤来运行 CIS 推荐的测试：

1.  对于本教程，我们将使用 EKS 作为我们的 Kubernetes 服务，但如果您愿意，您可以将 Kubernetes 和容器注册服务更改为其他云提供商。首先，创建一个 ECR 存储库，我们将在其中托管 kube-bench 镜像：

```
$ aws ecr create-repository --repository-name k8sdevopscookbook/kube-bench --image-tag-mutability MUTABLE
```

1.  将`kube-bench`存储库克隆到本地主机：

```
$ git clone https://github.com/aquasecurity/kube-bench.git
```

1.  登录到您的**弹性容器注册表**（**ECR**）帐户。在将图像推送到注册表之前，您需要进行身份验证：

```
$ $(aws ecr get-login --no-include-email --region us-west-2)
```

1.  通过运行以下命令构建 kube-bench 镜像：

```
$ docker build -t k8sdevopscookbook/kube-bench 
```

1.  用您的 AWS 帐户号替换`<AWS_ACCT_NUMBER>`并执行它以将其推送到 ECR 存储库。第一个命令将创建一个标签，而第二个命令将推送图像：

```
$ docker tag k8sdevopscookbook/kube-bench:latest <AWS_ACCT_NUMBER>.dkr.ecr.us-west-2.amazonaws.com/k8s/kube-bench:latest
# docker push <AWS_ACCT_NUMBER>.dkr.ecr.us-west-2.amazonaws.com/k8s/kube-bench:latest
```

1.  编辑`job-eks.yaml`文件，并将第 12 行的图像名称替换为您在*步骤 5*中推送的图像的 URI。它应该看起来类似于以下内容，除了您应该在图像 URI 中使用您的 AWS 帐户号：

```
apiVersion: batch/v1
kind: Job
metadata:
 name: kube-bench
spec:
 template:
 spec:
 hostPID: true
 containers:
 - name: kube-bench
 # Push the image to your ECR and then refer to it here
 image: 316621595343.dkr.ecr.us-west-2.amazonaws.com/k8sdevopscookbook/kube-bench:latest
...
```

1.  使用以下命令运行作业。它将很快被执行和完成：

```
$ kubectl apply -f job-eks.yaml
```

1.  列出在您的集群中创建的 kube-bench pod。它应该显示`Completed`作为状态，类似于以下示例：

```
$ kubectl get pods |grep kube-bench
kube-bench-7lxzn 0/1 Completed 0 5m
```

1.  用上一个命令的输出替换 pod 名称，并查看 pod 日志以检索`kube-bench`的结果。在我们的示例中，pod 名称是`kube-bench-7lxzn`：

```
$ kubectl logs kube-bench-7lxzn
```

现在，您可以在任何托管的 Kubernetes 集群上运行 kube-bench。获取日志后，按照所有的修复建议，直到清除工作节点上的失败测试。

### 在 OpenShift 上运行 kube-bench

OpenShift 有不同的命令行工具，因此，如果我们运行默认的测试作业，我们将无法在我们的集群上收集所需的信息，除非另有说明。在本教程中，您将学习如何在 OpenShift 上运行`kube-bench`。

让我们执行以下步骤来运行 CIS 推荐的测试：

1.  SSH 进入您的 OpenShift 主节点，并使用`--version ocp-3.10`或`ocp-3.11`运行以下命令，根据您的 OpenShift 版本。目前，只支持 3.10 和 3.11：

```
$ kube-bench master --version ocp-3.11
```

1.  要保存结果，请使用以下命令。测试完成后，将`kube-bench-master.txt`文件移动到本地主机以进行进一步审查：

```
$ kube-bench master --version ocp-3.11 > kube-bench-master.txt
```

1.  SSH 进入您的 OpenShift 工作节点，并重复此配方的前两步，但这次使用您正在运行的 OpenShift 版本的`node`参数。在我们的示例中，这是 OCP 3.11：

```
$ kube-bench node --version ocp-3.11 > kube-bench-node.txt
```

按照*在 Kubernetes 上运行 kube-bench*的配方说明来修补建议的安全问题。

## 它是如何工作的...

这个配方向您展示了如何快速在您的集群上使用 kube-bench 运行 CIS Kubernetes 基准。

在*在 Kubernetes 上运行 kube-bench*的配方中，在*步骤 1*中，执行完检查后，kube-bench 访问了保存在以下目录中的配置文件：`/var/lib/etcd`、`/var/lib/kubelet`、`/etc/systemd`、`/etc/kubernetes`和`/usr/bin`。因此，运行检查的用户需要为所有配置文件提供 root/sudo 访问权限。

如果配置文件无法在其默认目录中找到，则检查将失败。最常见的问题是在`/usr/bin`目录中缺少`kubectl`二进制文件。kubectl 用于检测 Kubernetes 版本。您可以通过在命令的一部分中使用`--version`来跳过此目录，从而指定 Kubernetes 版本，类似于以下内容：

```
$ kube-bench master --version 1.14
```

*步骤 1*将返回四种不同的状态。`PASS`和`FAIL`状态是不言自明的，因为它们指示测试是否成功运行或失败。`WARN`表示测试需要手动验证，这意味着需要注意。最后，`INFO`表示不需要进一步操作。

## 另请参阅

+   CIS Kubernetes 基准：[`www.cisecurity.org/benchmark/kubernetes/`](https://www.cisecurity.org/benchmark/kubernetes/)

+   kube-bench 存储库：[`github.com/aquasecurity/kube-bench`](https://github.com/aquasecurity/kube-bench)

+   如何自定义默认配置：[`github.com/aquasecurity/kube-bench/blob/master/docs/README.md#configuration-and-variables`](https://github.com/aquasecurity/kube-bench/blob/master/docs/README.md#configuration-and-variables)

+   为基于 Kubernetes 的应用程序自动执行合规性检查：[`github.com/cds-snc/security-goals`](https://github.com/cds-snc/security-goals)

+   从头开始加固 Kubernetes：[`github.com/hardening-kubernetes/from-scratch`](https://github.com/hardening-kubernetes/from-scratch)

+   CNCF 博客上的 9 个 Kubernetes 安全最佳实践：[`www.cncf.io/blog/2019/01/14/9-kubernetes-security-best-practices-everyone-must-follow/`](https://www.cncf.io/blog/2019/01/14/9-kubernetes-security-best-practices-everyone-must-follow/)

+   Rancher 的加固指南[`rancher.com/docs/rancher/v2.x/en/security/hardening-2.2/`](https://rancher.com/docs/rancher/v2.x/en/security/hardening-2.2/)

+   必备的 Kubernetes 安全审计工具：

+   Kube-bench: [`github.com/aquasecurity/kube-bench`](https://github.com/aquasecurity/kube-bench)

+   Kube-hunter: [`kube-hunter.aquasec.com/`](https://kube-hunter.aquasec.com/)

+   Kubeaudit: [`github.com/Shopify/kubeaudit`](https://github.com/Shopify/kubeaudit)

+   Kubesec: [`github.com/controlplaneio/kubesec`](https://github.com/controlplaneio/kubesec)

+   Open Policy Agent: [`www.openpolicyagent.org/`](https://www.openpolicyagent.org/)

+   K8Guard: [`k8guard.github.io/`](https://k8guard.github.io/)

# 将 DevSecOps 构建到流水线中，使用 Aqua Security

“左移”方法逐渐变得越来越受欢迎，这意味着安全必须内置到流程和流水线中。缩短流水线的最大问题之一是它们通常留下很少的空间进行适当的安全检查。因此，另一种称为“尽快部署更改”的方法被引入，这对 DevOps 的成功至关重要。

在本节中，我们将介绍使用 Aqua Security 自动化容器镜像中的漏洞检查，以减少应用程序的攻击面。

## 准备工作

确保您已经使用您喜欢的 CI/CD 工具配置了现有的 CI/CD 流水线。如果没有，请按照第三章中的说明，*构建 CI/CD 流水线*，配置 GitLab 或 CircleCI。

将`k8sdevopscookbook/src`存储库克隆到您的工作站，以便使用`chapter9`目录中的清单文件，方法如下：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd src/chapter9
```

确保您有一个准备好的 Kubernetes 集群，并配置`kubectl`来管理集群资源。

## 操作步骤

本节将向您展示如何将 Aqua 集成到您的 CI/CD 平台。本节进一步分为以下子节，以使此过程更加简单：

+   使用 Aqua Security Trivy 扫描镜像

+   将漏洞扫描构建到 GitLab 中

+   将漏洞扫描构建到 CircleCI 中

### 使用 Trivy 扫描镜像

Trivy 是一个用于识别容器漏洞的开源容器扫描工具。它是市场上最简单和最准确的扫描工具之一。在这个示例中，我们将学习如何安装和扫描使用 Trivy 的容器映像。

让我们执行以下步骤来运行 Trivy：

1.  获取最新的 Trivy 发布号并将其保存在一个变量中：

```
$ VERSION=$(curl --silent "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | \
grep '"tag_name":' | \
sed -E 's/.*"v([^"]+)".*/\1/')
```

下载并安装`trivy`命令行界面：

```
$ curl --silent --location "https://github.com/aquasecurity/trivy/releases/download/v${VERSION}/trivy_${VERSION}_Linux-64bit.tar.gz" | tar xz -C /tmp
$ sudo mv /trivy /usr/local/bin
```

1.  通过运行以下命令验证`trivy`是否正常工作。它将返回其当前版本：

```
$ trivy --version
trivy version 0.1.7
```

1.  通过用目标映像替换容器映像名称来执行`trivy`检查。在我们的示例中，我们扫描了来自 Docker Hub 存储库的`postgres:12.0`映像：

```
$ trivy postgres:12.0
2019-11-12T04:08:02.013Z INFO Updating vulnerability database...
2019-11-12T04:08:07.088Z INFO Detecting Debian vulnerabilities...

postgres:12.0 (debian 10.1)
===========================
Total: 164 (UNKNOWN: 1, LOW: 26, MEDIUM: 122, HIGH: 14, CRITICAL: 1)
...
```

1.  测试摘要将显示已检测到的漏洞数量，并将包括漏洞的详细列表，以及它们的 ID 和每个漏洞的解释：

```
+-----------+---------------+----------+----------+-----------+------+
| LIBRARY   | V ID          | SEVERITY | INST VER | FIXED VER | TITLE|
+-----------+------------------+-------+----------+-----------+------+
| apt       | CVE-2011-3374 | LOW      | 1.8.2    |           |      |
+-----------+---------------+          +----------+-----------+------+
| bash      | TEMP-0841856  |          | 5.0-4    |           |      |
+-----------+---------------+          +----------+-----------+------+
| coreutils | CVE-2016-2781 |          | 8.30-3   |           |      |
+           +---------------+          +          +-----------+------+
|           | CVE-2017-18018|          |          |           |      |
+-----------+---------------+----------+----------+-----------+------+
| file      | CVE-2019-18218| HIGH     | 1:5.35-4 | 1:5.35-4+d| file:|
...
```

通过这样，您已经学会了如何快速扫描您的容器映像。Trivy 支持各种容器基础映像（CentOS，Ubuntu，Alpine，Distorless 等），并原生支持 Docker Hub、Amazon ECR 和 Google Container Registry GCR 等容器注册表。Trivy 完全适用于 CI。在接下来的两个示例中，您将学习如何将 Trivy 添加到 CI 流水线中。

### 将漏洞扫描构建到 GitLab 中

使用 GitLab Auto DevOps，容器扫描作业使用 CoreOS Clair 来分析 Docker 映像的漏洞。然而，它并不是针对基于 Alpine 的映像的所有安全问题的完整数据库。Aqua Trivy 几乎有两倍的漏洞数量，更适合于 CI。有关详细比较，请参阅*Trivy Comparison*链接中的*另请参阅*部分。本示例将带您完成在 GitLab CI 流水线中添加测试阶段的过程。

让我们执行以下步骤来在 GitLab 中添加 Trivy 漏洞检查：

1.  编辑项目中的 CI/CD 流水线配置`.gitlab-ci.yml`文件：

```
$ vim .gitlab-ci.yml
```

1.  在您的流水线中添加一个新的阶段并定义该阶段。您可以在`src/chapter9/devsecops`目录中找到一个示例。在我们的示例中，我们使用了`vulTest`阶段名称：

```
stages:
 - build
 - vulTest
 - staging
 - production
#Add the Step 3 here
```

1.  添加新的阶段，即`vulTest`。当您定义一个新的阶段时，您需要指定一个阶段名称父键。在我们的示例中，父键是`trivy`。`before_script`部分的命令将下载`trivy`二进制文件：

```
trivy:
 stage: vulTest
 image: docker:stable-git
 before_script:
 - docker build -t trivy-ci-test:${CI_COMMIT_REF_NAME} .
 - export VERSION=$(curl --silent "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
 - wget https://github.com/aquasecurity/trivy/releases/download/v${VERSION}/trivy_${VERSION}_Linux-64bit.tar.gz
 - tar zxvf trivy_${VERSION}_Linux-64bit.tar.gz
 variables:
 DOCKER_DRIVER: overlay2
 allow_failure: true
 services:
 - docker:stable-dind
#Add the Step 4 here
```

1.  最后，审查并添加 Trivy 扫描脚本，并完成`vulTest`阶段。以下脚本将对关键严重性漏洞返回`--exit-code 1`，如下所示：

```
 script:
 - ./trivy --exit-code 0 --severity HIGH --no-progress --auto-refresh trivy-ci-test:${CI_COMMIT_REF_NAME}
 - ./trivy --exit-code 1 --severity CRITICAL --no-progress --auto-refresh trivy-ci-test:${CI_COMMIT_REF_NAME}
 cache:
 directories:
 - $HOME/.cache/trivy
```

现在，您可以运行您的流水线，新阶段将包含在您的流水线中。如果检测到关键漏洞，流水线将失败。如果您不希望该阶段使您的流水线失败，您还可以为关键漏洞指定`--exit-code 0`。

### 将漏洞扫描构建到 CircleCI 中

CircleCI 使用 Orbs 来包装预定义的示例，以加快项目配置的速度。目前，Trivy 没有 CircleCI Orb，但是仍然很容易使用 CircleCI 配置 Trivy。本示例将带您完成向 CircleCI 流水线添加测试阶段的过程。

让我们执行以下步骤来在 CircleCI 中添加 Trivy 漏洞检查：

1.  编辑位于我们项目存储库中的`.circleci/config.yml`的 CircleCI 配置文件。您可以在`src/chapter9/devsecops`目录中找到我们的示例：

```
$ vim .circleci/config.yml
```

1.  首先添加作业和镜像。在这个示例中，作业名称是`build`：

```
jobs:
 build:
 docker:
 - image: docker:18.09-git
#Add the Step 3 here
```

1.  开始添加构建图像的步骤。`checkout`步骤将从其代码存储库中检出项目。由于我们的作业将需要 docker 命令，因此添加`setup_remote_docker`。执行此步骤时，将创建远程环境，并且将适当地配置您当前的主要容器：

```
 steps:
 - checkout
 - setup_remote_docker
 - restore_cache:
 key: vulnerability-db
 - run:
 name: Build image
 command: docker build -t trivy-ci-test:${CIRCLE_SHA1} .
#Add the Step 4 here
```

1.  添加必要的步骤来安装 Trivy：

```
 - run:
 name: Install trivy
 command: |
 apk add --update curl
 VERSION=$(
 curl --silent "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | \
 grep '"tag_name":' | \
 sed -E 's/.*"v([^"]+)".*/\1/'
 )

 wget https://github.com/aquasecurity/trivy/releases/download/v${VERSION}/trivy_${VERSION}_Linux-64bit.tar.gz
 tar zxvf trivy_${VERSION}_Linux-64bit.tar.gz
 mv trivy /usr/local/bin
#Add the Step 5 here
```

1.  添加使用 Trivy 扫描本地镜像的步骤。根据需要修改`trivy`参数和首选退出代码。在这里，`trivy`仅检查关键漏洞（`--severity CRITICAL`），如果发现漏洞，则失败（`--exit-code 1`）。它抑制进度条（`--no-progress`），并在更新版本时自动刷新数据库（`--auto-refresh`）：

```
 - run:
 name: Scan the local image with trivy
 command: trivy --exit-code 1 --severity CRITICAL --no-progress --auto-refresh trivy-ci-test:${CIRCLE_SHA1}
 - save_cache:
 key: vulnerability-db
 paths:
 - $HOME/.cache/trivy
#Add the Step 6 here
```

1.  最后，更新工作流以触发漏洞扫描：

```
workflows:
 version: 2
 release:
 jobs:
 - build
```

现在，您可以在 CircleCI 中运行您的流水线，新阶段将包含在您的流水线中。

## 请参阅

+   Aqua Security Trivy 比较：[`github.com/aquasecurity/trivy#comparison-with-other-scanners`](https://github.com/aquasecurity/trivy#comparison-with-other-scanners)

+   Aqua Security Trivy CI 示例：[`github.com/aquasecurity/trivy#comparison-with-other-scanners`](https://github.com/aquasecurity/trivy#comparison-with-other-scanners)

+   Aqua Security Trivy 替代品用于图像漏洞测试：

+   Aqua Security Microscanner: [`github.com/aquasecurity/microscanner`](https://github.com/aquasecurity/microscanner)

+   Clair: [`github.com/coreos/clair`](https://github.com/coreos/clair)

+   Docker Hub: [`beta.docs.docker.com/v17.12/docker-cloud/builds/image-scan/`](https://beta.docs.docker.com/v17.12/docker-cloud/builds/image-scan/)

+   GCR: [`cloud.google.com/container-registry/docs/container-analysis`](https://cloud.google.com/container-registry/docs/container-analysis)

+   Layered Insight: [`layeredinsight.com/`](https://layeredinsight.com/)

+   NeuVector: [`neuvector.com/vulnerability-scanning/`](https://neuvector.com/vulnerability-scanning/)

+   Sysdig Secure: [`sysdig.com/products/secure/`](https://sysdig.com/products/secure/)

+   Quay: [`coreos.com/quay-enterprise/docs/latest/security-scanning.html`](https://coreos.com/quay-enterprise/docs/latest/security-scanning.html)

+   Twistlock: [`www.twistlock.com/platform/vulnerability-management-tools/`](https://www.twistlock.com/platform/vulnerability-management-tools/)

# 使用 Falco 监视可疑的应用程序活动

Falco 是一个云原生的运行时安全工具集。Falco 通过其运行时规则引擎深入了解系统行为。它用于检测应用程序、容器、主机和 Kubernetes 编排器中的入侵和异常。

在本节中，我们将介绍在 Kubernetes 上安装和基本使用 Falco。

## 准备工作

将`k8sdevopscookbook/src`存储库克隆到您的工作站，以使用`chapter9`目录中的清单文件，如下所示：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd src/chapter9
```

确保您已准备好一个 Kubernetes 集群，并配置好`kubectl`和`helm`来管理集群资源。

## 如何做…

本节将向您展示如何配置和运行 Falco。本节进一步分为以下子节，以使此过程更加简单：

+   在 Kubernetes 上安装 Falco

+   使用 Falco 检测异常

+   定义自定义规则

### 在 Kubernetes 上安装 Falco

Falco 可以通过多种方式安装，包括直接在 Linux 主机上部署 Falco 作为 DaemonSet，或者使用 Helm。本教程将向您展示如何将 Falco 安装为 DaemonSet。

让我们执行以下步骤，在我们的集群上部署 Falco：

1.  将 Falco 存储库克隆到您当前的工作目录：

```
$ git clone https://github.com/falcosecurity/falco.git
$ cd falco/integrations/k8s-using-daemonset/k8s-with-rbac
```

1.  为 Falco 创建一个服务账户。以下命令还将为其创建 ClusterRole 和 ClusterRoleBinding：

```
$ kubectl create -f falco-account.yaml
```

1.  使用从克隆存储库位置的以下命令创建一个服务：

```
$ kubectl create -f falco-service.yaml
```

1.  创建一个`config`目录并将部署配置文件和规则文件复制到`config`目录中。稍后我们需要编辑这些文件：

```
$ mkdir config
$ cp ../../../falco.yaml config/
$ cp ../../../rules/falco_rules.* config/
$ cp ../../../rules/k8s_audit_rules.yaml config/
```

1.  使用`config/`目录中的配置文件创建一个 ConfigMap。稍后，DaemonSet 将使用 ConfigMap 使配置对 Falco pods 可用：

```
$ kubectl create configmap falco-config --from-file=config
```

1.  最后，使用以下命令部署 Falco：

```
$ kubectl create -f falco-daemonset-configmap.yaml
```

1.  验证 DaemonSet pods 已成功创建。您应该在集群上的每个可调度的工作节点上看到一个 pod。在我们的示例中，我们使用了一个具有四个工作节点的 Kubernetes 集群：

```
$ kubectl get pods | grep falco-daemonset
falco-daemonset-94p8w 1/1 Running 0 2m34s
falco-daemonset-c49v5 1/1 Running 0 2m34s
falco-daemonset-htrxw 1/1 Running 0 2m34s
falco-daemonset-kwms5 1/1 Running 0 2m34s
```

有了这个，Falco 已经部署并开始监视行为活动，以检测我们节点上应用程序中的异常活动。

### 使用 Falco 检测异常

Falco 检测到各种可疑行为。在这个教程中，我们将产生一些在正常生产集群中可能会引起怀疑的活动。

让我们执行以下步骤来产生可能触发系统调用事件丢弃的活动：

1.  首先，我们需要在测试一些行为之前审查完整的规则。Falco 有两个规则文件。默认规则位于`/etc/falco/falco_rules.yaml`，而本地规则文件位于`/etc/falco/falco_rules.local.yaml`。您的自定义规则和修改应该在`falco_rules.local.yaml`文件中：

```
$ cat config/falco_rules.yaml
$ cat config/falco_rules.local.yaml
```

1.  您将看到一长串的默认规则和宏。其中一些如下所示：

```
- rule: Disallowed SSH Connection
- rule: Launch Disallowed Container
- rule: Contact K8S API Server From Container
- rule: Unexpected K8s NodePort Connection
- rule: Launch Suspicious Network Tool in Container
- rule: Create Symlink Over Sensitive Files
- rule: Detect crypto miners using the Stratum protocol
```

1.  通过获取一个 bash shell 进入其中一个 Falco pods 并查看日志来测试 Falco 是否正常工作。列出 Falco pods：

```
$ kubectl get pods | grep falco-daemonset
falco-daemonset-94p8w 1/1 Running 0 2m34s
falco-daemonset-c49v5 1/1 Running 0 2m34s
falco-daemonset-htrxw 1/1 Running 0 2m34s
falco-daemonset-kwms5 1/1 Running 0 2m34s
```

1.  从上述命令的输出中获取对一个 Falco pod 的 bash shell 访问并查看日志：

```
$ kubectl exec -it falco-daemonset-94p8w bash
$ kubectl logs falco-daemonset-94p8w  
```

1.  在日志中，您将看到 Falco 检测到我们对 pods 的 shell 访问：

```
{"output":"00:58:23.798345403: Notice A shell was spawned in a container with an attached terminal (user=root k8s.ns=default k8s.pod=falco-daemonset-94p8w container=0fcbc74d1b4c shell=bash parent=docker-runc cmdline=bash terminal=34816 container_id=0fcbc74d1b4c image=falcosecurity/falco) k8s.ns=default k8s.pod=falco-daemonset-94p8w container=0fcbc74d1b4c k8s.ns=default k8s.pod=falco-daemonset-94p8w container=0fcbc74d1b4c","priority":"Notice","rule":"Terminal shell in container","time":"2019-11-13T00:58:23.798345403Z", "output_fields": {"container.id":"0fcbc74d1b4c","container.image.repository":"falcosecurity/falco","evt.time":1573606703798345403,"k8s.ns.name":"default","k8s.pod.name":"falco-daemonset-94p8w","proc.cmdline":"bash","proc.name":"bash","proc.pname":"docker-runc","proc.tty":34816,"user.name":"root"}}
```

通过这样，您已经学会了如何使用 Falco 来检测异常和可疑行为。

### 定义自定义规则

Falco 规则可以通过添加我们自己的规则来扩展。在这个教程中，我们将部署一个简单的应用程序，并创建一个新规则来检测恶意应用程序访问我们的数据库。

执行以下步骤来创建一个应用程序并为 Falco 定义自定义规则：

1.  切换到`src/chapter9/falco`目录，这是我们示例所在的位置：

```
$ cd src/chapter9/falco
```

1.  创建一个新的`falcotest`命名空间：

```
$ kubectl create ns falcotest
```

1.  审查 YAML 清单并使用以下命令部署它们。这些命令将创建一个 MySQL pod，Web 应用程序，我们将用来 ping 应用程序的客户端，以及它的服务：

```
$ kubectl create -f mysql.yaml
$ kubectl create -f ping.yaml
$ kubectl create -f client.yaml
```

1.  现在，使用默认凭据`bob/foobar`的客户端 pod 发送 ping 到我们的应用程序。预期地，我们将能够进行身份验证并成功完成任务：

```
$ kubectl exec client -n falcotest -- curl -F "s=OK" -F "user=bob" -F "passwd=foobar" -F "ipaddr=localhost" -X POST http://ping/ping.php
```

1.  编辑`falco_rules.local.yaml`文件：

```
$ vim config/falco_rules.local.yaml
```

1.  将以下规则添加到文件末尾并保存：

```
 - rule: Unauthorized process
 desc: There is a running process not described in the base template
 condition: spawned_process and container and k8s.ns.name=falcotest and k8s.deployment.name=ping and not proc.name in (apache2, sh, ping)
 output: Unauthorized process (%proc.cmdline) running in (%container.id)
 priority: ERROR
 tags: [process]
```

1.  更新用于 DaemonSet 的 ConfigMap 并通过运行以下命令删除 pod 以获得新的配置：

```
$ kubectl delete -f falco-daemonset-configmap.yaml
$ kubectl create configmap falco-config --from-file=config --dry-run --save-config -o yaml | kubectl apply -f -
$ kubectl apply -f falco-daemonset-configmap.yaml
```

1.  我们将执行 SQL 注入攻击并访问存储我们的 MySQL 凭据的文件。我们的新自定义规则应该能够检测到它：

```
$ kubectl exec client -n falcotest -- curl -F "s=OK" -F "user=bad" -F "passwd=wrongpasswd' OR 'a'='a" -F "ipaddr=localhost; cat /var/www/html/ping.php" -X POST http://ping/ping.php
```

1.  上述命令将返回 PHP 文件的内容。您将能够在那里找到 MySQL 凭据：

```
3 packets transmitted, 3 received, 0% packet loss, time 2044ms
rtt min/avg/max/mdev = 0.028/0.035/0.045/0.007 ms
<?php
$link = mysqli_connect("mysql", "root", "foobar", "employees");
?>
```

1.  列出 Falco pod：

```
$ kubectl get pods | grep falco-daemonset
falco-daemonset-5785b 1/1 Running 0 9m52s
falco-daemonset-brjs7 1/1 Running 0 9m52s
falco-daemonset-mqcjq 1/1 Running 0 9m52s
falco-daemonset-pdx45 1/1 Running 0 9m52s
```

1.  查看来自 Falco pod 的日志：

```
$ kubectl exec -it falco-daemonset-94p8w bash
**$ kubectl logs falco-daemonset-94p8w** 
```

1.  在日志中，您将看到 Falco 检测到我们对 pod 的 shell 访问：

```
05:41:59.9275580001: Error Unauthorized process (cat /var/www/html/ping.php) running in (5f1b6d304f99) k8s.ns=falcotest k8s.pod=ping-74dbb488b6-6hwp6 container=5f1b6d304f99
```

有了这个，您就知道如何使用 Kubernetes 元数据（如`k8s.ns.name`和`k8s.deployment.name`）添加自定义规则。您还可以使用其他过滤器。这在*参见*部分的*支持的过滤器*链接中有更详细的描述。

## 工作原理...

本教程向您展示了如何在 Kubernetes 上运行应用程序时，基于预定义和自定义规则来检测异常。

在*Kubernetes 上安装 Falco*的步骤中，在*第 5 步*，我们创建了一个 ConfigMap 供 Falco pod 使用。Falco 有两种类型的规则文件。

在第 6 步中，当我们创建了 DaemonSet 时，所有默认规则都是通过 ConfigMap 中的`falco_rules.yaml`文件提供的。这些放置在 pod 内的`/etc/falco/falco_rules.yaml`中，而本地规则文件`falco_rules.local.yaml`可以在`/etc/falco/falco_rules.local.yaml`中找到。

默认规则文件包含许多常见异常和威胁的规则。所有定制的部分都必须添加到`falco_rules.local.yaml`文件中，我们在*定义自定义规则*教程中已经做到了。

在*定义自定义规则*教程中，在*第 6 步*，我们创建了一个包含`rules`元素的自定义规则文件。Falco 规则文件是一个使用三种元素的 YAML 文件：`rules`，`macros`和`lists`。

规则定义了发送有关特定条件的警报。规则是一个包含至少以下键的文件：

+   `rule`：规则的名称

+   `condition`：应用于事件的表达式，用于检查它们是否匹配规则

+   `desc`：规则用途的详细描述

+   `output`：显示给用户的消息

+   `priority`：紧急、警报、关键、错误、警告、通知、信息或调试

您可以通过转到“了解 Falco 规则”链接来了解更多关于这些规则的信息，该链接提供在“另请参阅”部分中。

## 另请参阅

+   Falco 文档：[`falco.org/docs/`](https://falco.org/docs/)

+   Falco 存储库和集成示例：[`github.com/falcosecurity/falco`](https://github.com/falcosecurity/falco)

+   了解 Falco 规则：[`falco.org/dochttps://falco.org/docs/rules/s/rules/`](https://falco.org/dochttps://falco.org/docs/rules/s/rules/)

+   将 Falco 与其他工具进行比较：[`sysdig.com/blog/selinux-seccomp-falco-technical-discussion/`](https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/)

+   支持的过滤器：[`github.com/draios/sysdig/wiki/Sysdig-User-Guide#all-supported-filters`](https://github.com/draios/sysdig/wiki/Sysdig-User-Guide#all-supported-filters)

# 使用 HashiCorp Vault 保护凭据

HashiCorp Vault 是一个流行的工具，用于安全存储和访问诸如凭据、API 密钥和证书之类的秘密。 Vault 提供安全的秘密存储，按需动态秘密，数据加密以及支持秘密吊销。

在本节中，我们将介绍访问和存储 Kubernetes 秘密的安装和基本用例。

## 准备就绪

将`k8sdevopscookbook/src`存储库克隆到您的工作站，以便在`chapter9`目录中使用清单文件，方法如下：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd src/chapter9
```

确保您已准备好 Kubernetes 集群，并配置了`kubectl`和`helm`以管理集群资源。

## 操作步骤…

本节进一步分为以下小节，以使此过程更加简单：

+   在 Kubernetes 上安装 Vault

+   访问 Vault UI

+   在 Vault 上存储凭据

### 在 Kubernetes 上安装 Vault

此教程将向您展示如何在 Kubernetes 上获取 Vault 服务。 让我们执行以下步骤，使用 Helm 图表安装 Vault：

1.  克隆图表存储库：

```
$ git clone https://github.com/hashicorp/vault-helm.git
$ cd vault-helm
```

1.  检查最新的稳定版本：

```
$ git checkout v$(curl --silent "https://api.github.com/repos/hashicorp/vault-helm/releases/latest" | \
grep '"tag_name":' | \
sed -E 's/.*"v([^"]+)".*/\1/')
```

1.  如果您想要安装高可用的 Vault，请跳至*步骤 4*；否则，请使用此处显示的 Helm 图表参数安装独立版本：

```
$ helm install --name vault --namespace vault ./
```

1.  要部署使用 HA 存储后端（如 Consul）的高可用版本，请使用以下 Helm 图表参数。 这将使用具有三个副本的 StatefulSet 部署 Vault：

```
$ helm install --name vault --namespace vault --set='server.ha.enabled=true' ./
```

1.  验证 pod 的状态。您会注意到 pod 尚未准备就绪，因为就绪探针要求首先初始化 Vault：

```
$ $ kubectl get pods -nvault
NAME                                  READY STATUS  RESTARTS AGE
vault-0                               0/1   Running 0        83s
vault-agent-injector-5fb898d6cd-rct82 1/1   Running 0        84s
```

1.  检查初始化状态。它应该是`false`：

```
$ kubectl exec -it vault-0 -nvault -- vault status
Key             Value
---             -----
Seal Type       shamir
Initialized     false
Sealed          true
Total Shares    0
Threshold       0
Unseal Progress 0/0
Unseal Nonce    n/a
Version         n/a
HA Enabled      false
```

1.  初始化 Vault 实例。以下命令将返回一个解封密钥和根令牌：

```
$ kubectl exec -it vault-0 -nvault -- vault operator init -n 1 -t 1

Unseal Key 1: lhLeU6SRdUNQgfpWAqWknwSxns1tfWP57iZQbbYtFSE=
Initial Root Token: s.CzcefEkOYmCt70fGSbHgSZl4
Vault initialized with 1 key shares and a key threshold of 1\. Please securely
distribute the key shares printed above. When the Vault is re-sealed,
restarted, or stopped, you must supply at least 1 of these keys to unseal it
before it can start servicing requests.
```

1.  使用以下命令的输出中的解封密钥解封 Vault：

```
$ kubectl exec -it vault-0 -nvault -- vault operator unseal lhLeU6SRdUNQgfpWAqWknwSxns1tfWP57iZQbbYtFSE=
Key          Value
---          -----
Seal Type    shamir
Initialized  true
Sealed       false
Total Shares 1
Threshold    1
Version      1.3.1
Cluster Name vault-cluster-6970c528
Cluster ID   dd88cca8-20bb-326c-acb3-2d924bb1805c
HA Enabled   false
```

1.  验证 pod 的状态。您将看到就绪探针已经验证，并且 pod 已准备就绪：

```
$ kubectl get pods -nvault
NAME                                  READY STATUS  RESTARTS AGE
vault-0                               1/1   Running 0        6m29s
vault-agent-injector-5fb898d6cd-rct82 1/1   Running 0        6m30s
```

Vault 在初始化后即可使用。现在，您知道如何在 Kubernetes 上运行 Vault 了。

### 访问 Vault UI

默认情况下，在使用 Helm 图表安装时，启用 Vault UI。让我们执行以下步骤来访问 Vault UI：

1.  由于访问 Vault 是一个安全问题，不建议使用服务暴露它。使用端口转发来访问 Vault UI，使用以下命令：

```
$ kubectl port-forward vault-0 -nvault 8200:8200
```

1.  一旦转发完成，您可以在`http://localhost:8200`上访问 UI：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/1b504490-441c-4b87-9a8f-a44ab9159dc2.png)

现在，您可以访问 Web UI。参加 Vault Web UI 之旅，熟悉其功能。

### 在 Vault 中存储凭据

此教程将向您展示如何在 Kubernetes 中使用 Vault，并从 Vault 中检索秘密。

让我们执行以下步骤来在 Vault 中启用 Kubernetes 认证方法：

1.  使用您的令牌登录 Vault：

```
$ vault login <root-token-here>
```

1.  向 Vault 写入一个秘密：

```
$ vault write secret/foo value=bar
Success! Data written to: secret/foo
$ vault read secret/foo
Key              Value
---              -----
refresh_interval 768h
value            bar
```

1.  让我们配置 Vault 的 Kubernetes 认证后端。首先，创建一个 ServiceAccount：

```
$ kubectl -n vault create serviceaccount vault-k8s
```

1.  为`vault-k8s` ServiceAccount 创建一个 RoleBinding：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
 name: role-tokenreview-binding
 namespace: default
roleRef:
 apiGroup: rbac.authorization.k8s.io
 kind: ClusterRole
 name: system:auth-delegator
subjects:
- kind: ServiceAccount
 name: vault-k8s
 namespace: default
EOF
```

1.  获取令牌：

```
$ SECRET_NAME=$(kubectl -n vault get serviceaccount vault-k8s -o jsonpath={.secrets[0].name})
$ ACCOUNT_TOKEN=$(kubectl -n vault get secret ${SECRET_NAME} -o jsonpath={.data.token} | base64 --decode; echo)
$ export VAULT_SA_NAME=$(kubectl get sa -n vault vault-k8s -o jsonpath=”{.secrets[*].name}”)
$ export SA_CA_CRT=$(kubectl get secret $VAULT_SA_NAME -n vault -o jsonpath={.data.'ca\.crt'} | base64 --decode; echo)
```

1.  在 vault 中启用 Kubernetes 认证后端：

```
$ vault auth enable kubernetes
$ vault write auth/kubernetes/config kubernetes_host=”https://MASTER_IP:6443" kubernetes_ca_cert=”$SA_CA_CRT” token_reviewer_jwt=$TR_ACCOUNT_TOKEN
```

1.  使用`policy.hcl`文件从示例存储库创建一个名为`vault-policy`的新策略：

```
$ vault write sys/policy/vault-policy policy=@policy.hcl
```

1.  接下来，为 ServiceAccount 创建一个角色：

```
$ vault write auth/kubernetes/role/demo-role \
 bound_service_account_names=vault-coreos-test \
 bound_service_account_namespaces=default \
 policies=demo-policy \
 ttl=1h
```

1.  通过运行以下命令使用角色进行身份验证：

```
$ DEFAULT_ACCOUNT_TOKEN=$(kubectl get secret $VAULT_SA_NAME -n vault -o jsonpath={.data.token} | base64 — decode; echo )
```

1.  通过运行以下命令使用令牌登录 Vault：

```
$ vault write auth/kubernetes/login role=demo-role jwt=${DEFAULT_ACCOUNT_TOKEN}
```

1.  在`secret/demo`路径下创建一个秘密：

```
$ vault write secret/demo/foo value=bar
```

通过这样，您已经学会了如何在 Vault 中创建 Kubernetes 认证后端，并使用 Vault 存储 Kubernetes 秘密。

## 另请参阅

+   Hashicorp Vault 文档：[`www.vaultproject.io/docs/`](https://www.vaultproject.io/docs/)

+   Hashicorp Vault 存储库：[`github.com/hashicorp/vault-helm`](https://github.com/hashicorp/vault-helm)

+   在 Kubernetes 上使用 Vault 的实践：[`github.com/hashicorp/hands-on-with-vault-on-kubernetes`](https://github.com/hashicorp/hands-on-with-vault-on-kubernetes)
