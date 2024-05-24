# 精通 Kubernetes（三）

> 原文：[`zh.annas-archive.org/md5/0FB6BD53079686F120215D277D8C163C`](https://zh.annas-archive.org/md5/0FB6BD53079686F120215D277D8C163C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：处理 Kubernetes 存储

在本章中，我们将看一下 Kubernetes 如何管理存储。存储与计算非常不同，但在高层次上它们都是资源。作为一个通用平台，Kubernetes 采取了在编程模型和一组存储提供者插件后面抽象存储的方法。首先，我们将详细介绍存储的概念模型以及如何将存储提供给集群中的容器。然后，我们将介绍常见的云平台存储提供者，如 AWS、GCE 和 Azure。然后我们将看一下著名的开源存储提供者（来自红帽的 GlusterFS），它提供了一个分布式文件系统。我们还将研究一种替代方案——Flocker——它将您的数据作为 Kubernetes 集群的一部分进行管理。最后，我们将看看 Kubernetes 如何支持现有企业存储解决方案的集成。

在本章结束时，您将对 Kubernetes 中存储的表示有扎实的了解，了解每个部署环境（本地测试、公共云和企业）中的各种存储选项，并了解如何为您的用例选择最佳选项。

# 持久卷演练

在这一部分，我们将看一下 Kubernetes 存储的概念模型，并了解如何将持久存储映射到容器中，以便它们可以读写。让我们先来看看存储的问题。容器和 Pod 是短暂的。当容器死亡时，容器写入自己文件系统的任何内容都会被清除。容器也可以挂载宿主节点的目录并进行读写。这样可以在容器重新启动时保留，但节点本身并不是不朽的。

还有其他问题，比如当容器死亡时，挂载的宿主目录的所有权。想象一下，一堆容器将重要数据写入它们的宿主机上的各个数据目录，然后离开，留下所有这些数据散落在节点上，没有直接的方法告诉哪个容器写入了哪些数据。您可以尝试记录这些信息，但您会在哪里记录呢？很明显，对于大规模系统，您需要从任何节点访问持久存储以可靠地管理数据。

# 卷

基本的 Kubernetes 存储抽象是卷。容器挂载绑定到其 Pod 的卷，并访问存储，无论它在哪里，都好像它在它们的本地文件系统中一样。这并不新鲜，但很棒，因为作为一个需要访问数据的应用程序开发人员，您不必担心数据存储在何处以及如何存储。

# 使用 emptyDir 进行 Pod 内通信

使用共享卷在同一 Pod 中的容器之间共享数据非常简单。容器 1 和容器 2 只需挂载相同的卷，就可以通过读写到这个共享空间进行通信。最基本的卷是`emptyDir`。`emptyDir`卷是主机上的`empty`目录。请注意，它不是持久的，因为当 Pod 从节点中移除时，内容会被擦除。如果容器崩溃，Pod 将继续存在，稍后可以访问它。另一个非常有趣的选项是使用 RAM 磁盘，通过指定介质为`Memory`。现在，您的容器通过共享内存进行通信，这样做速度更快，但当然更易失。如果节点重新启动，`emptyDir`卷的内容将丢失。

这是一个`pod`配置文件，其中有两个容器挂载名为`shared-volume`的相同卷。这些容器在不同的路径上挂载它，但当`hue-global-listener`容器将文件写入`/notifications`时，`hue-job-scheduler`将在`/incoming`下看到该文件。

```
apiVersion: v1
kind: Pod
metadata:
  name: hue-scheduler
spec:
  containers:
  - image: the_g1g1/hue-global-listener
    name: hue-global-listener
    volumeMounts:
    - mountPath: /notifications
      name: shared-volume
  - image: the_g1g1/hue-job-scheduler
    name: hue-job-scheduler
    volumeMounts:
    - mountPath: /incoming
      name: shared-volume
  volumes:
  - name: shared-volume
    emptyDir: {}
```

要使用共享内存选项，我们只需要在`emptyDir`部分添加`medium`:`Memory`：

```
volumes:
- name: shared-volume
  emptyDir:
   medium: Memory 
```

# 使用 HostPath 进行节点内通信

有时，您希望您的 Pod 可以访问一些主机信息（例如 Docker 守护程序），或者您希望同一节点上的 Pod 可以相互通信。如果 Pod 知道它们在同一主机上，这将非常有用。由于 Kubernetes 根据可用资源调度 Pod，Pod 通常不知道它们与哪些其他 Pod 共享节点。有两种情况下，Pod 可以依赖于其他 Pod 与其一起在同一节点上调度：

+   在单节点集群中，所有 Pod 显然共享同一节点

+   DaemonSet Pod 始终与与其选择器匹配的任何其他 Pod 共享节点

例如，在第六章中，*使用关键的 Kubernetes 资源*，我们讨论了一个作为聚合代理的 DaemonSet pod 到其他 pod 的。实现此行为的另一种方法是让 pod 将其数据简单地写入绑定到`host`目录的挂载卷，然后 DaemonSet pod 可以直接读取并对其进行操作。

在决定使用 HostPath 卷之前，请确保您了解限制：

+   具有相同配置的 pod 的行为可能会有所不同，如果它们是数据驱动的，并且它们主机上的文件不同

+   它可能会违反基于资源的调度（即将推出到 Kubernetes），因为 Kubernetes 无法监视 HostPath 资源

+   访问主机目录的容器必须具有`privileged`设置为`true`的安全上下文，或者在主机端，您需要更改权限以允许写入

这是一个配置文件，将`/coupons`目录挂载到`hue-coupon-hunter`容器中，该容器映射到主机的`/etc/hue/data/coupons`目录：

```
apiVersion: v1
kind: Pod
metadata:
  name: hue-coupon-hunter
spec:
  containers:
  - image: the_g1g1/hue-coupon-hunter
    name: hue-coupon-hunter
    volumeMounts:
    - mountPath: /coupons
      name: coupons-volume 
  volumes:
  - name: coupons-volume
    host-path: 
        path: /etc/hue/data/coupons
```

由于 pod 没有`privileged`安全上下文，它将无法写入`host`目录。让我们改变容器规范以通过添加安全上下文来启用它：

```
- image: the_g1g1/hue-coupon-hunter
   name: hue-coupon-hunter
   volumeMounts:
   - mountPath: /coupons
     name: coupons-volume
   securityContext:
          privileged: true
```

在下图中，您可以看到每个容器都有自己的本地存储区，其他容器或 pod 无法访问，并且主机的`/data`目录被挂载为卷到容器 1 和容器 2：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/51e8d5df-c170-469b-8284-f1c2e952e87a.png)

# 使用本地卷进行持久节点存储

本地卷类似于 HostPath，但它们在 pod 重新启动和节点重新启动时保持不变。在这种意义上，它们被视为持久卷。它们在 Kubernetes 1.7 中添加。截至 Kubernetes 1.10 需要启用功能门。本地卷的目的是支持 StatefulSet，其中特定的 pod 需要被调度到包含特定存储卷的节点上。本地卷具有节点亲和性注释，简化了将 pod 绑定到它们需要访问的存储的过程：

```
apiVersion: v1
kind: PersistentVolume
metadata:
  name: example-pv
  annotations:
        "volume.alpha.kubernetes.io/node-affinity": '{
            "requiredDuringSchedulingIgnoredDuringExecution": {
                "nodeSelectorTerms": [
                    { "matchExpressions": [
                        { "key": "kubernetes.io/hostname",
                          "operator": "In",
                          "values": ["example-node"]
                        }
                    ]}
                 ]}
              }'
spec:
    capacity:
      storage: 100Gi
    accessModes:
    - ReadWriteOnce
    persistentVolumeReclaimPolicy: Delete
    storageClassName: local-storage
    local:
      path: /mnt/disks/ssd1
```

# 提供持久卷

`emptyDir` 卷可以被挂载和容器使用，但它们不是持久的，也不需要任何特殊的配置，因为它们使用节点上的现有存储。`HostPath` 卷在原始节点上持久存在，但如果 pod 在不同的节点上重新启动，它无法访问先前节点上的 `HostPath` 卷。`Local` 卷在节点上持久存在，可以在 pod 重新启动、重新调度甚至节点重新启动时幸存下来。真正的持久卷使用提前由管理员配置的外部存储（不是物理连接到节点的磁盘）。在云环境中，配置可能非常简化，但仍然是必需的，作为 Kubernetes 集群管理员，您至少要确保您的存储配额是充足的，并且要认真监控使用情况与配额的对比。

请记住，持久卷是 Kubernetes 集群类似于节点使用的资源。因此，它们不受 Kubernetes API 服务器的管理。您可以静态或动态地配置资源。

+   **静态配置持久卷**：静态配置很简单。集群管理员提前创建由某些存储介质支持的持久卷，这些持久卷可以被容器声明。

+   **动态配置持久卷**：当持久卷声明与静态配置的持久卷不匹配时，动态配置可能会发生。如果声明指定了存储类，并且管理员为该类配置了动态配置，那么持久卷可能会被即时配置。当我们讨论持久卷声明和存储类时，我们将在后面看到示例。

+   **外部配置持久卷**：最近的一个趋势是将存储配置器从 Kubernetes 核心移出到卷插件（也称为 out-of-tree）。外部配置器的工作方式与 in-tree 动态配置器相同，但可以独立部署和更新。越来越多的 in-tree 存储配置器迁移到 out-of-tree。查看这个 Kubernetes 孵化器项目：[`github.com/kubernetes-incubator/external-storage`](https://github.com/kubernetes-incubator/external-storage)。

# 创建持久卷

以下是 NFS 持久卷的配置文件：

```
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-1
  labels:
     release: stable
     capacity: 100Gi 
spec:
  capacity:
    storage: 100Gi
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce
   - ReadOnlyMany
  persistentVolumeReclaimPolicy: Recycle
  storageClassName: normal
  nfs:
    path: /tmp
    server: 172.17.0.8
```

持久卷具有包括名称在内的规范和元数据。让我们在这里关注规范。有几个部分：容量、卷模式、访问模式、回收策略、存储类和卷类型（例如示例中的`nfs`）。

# 容量

每个卷都有指定的存储量。存储索赔可以由至少具有该存储量的持久卷满足。例如，持久卷的容量为`100` Gibibytes（2³⁰字节）。在分配静态持久卷时，了解存储请求模式非常重要。例如，如果您配置了 100 GiB 容量的 20 个持久卷，并且容器索赔了 150 GiB 的持久卷，则即使总体容量足够，该索赔也不会得到满足：

```
capacity:
    storage: 100Gi 
```

# 卷模式

可选的卷模式在 Kubernetes 1.9 中作为静态配置的 Alpha 功能添加（即使您在规范中指定它作为字段，而不是在注释中）。它允许您指定是否需要文件系统（`"Filesystem"`）或原始存储（`"Block"`）。如果不指定卷模式，则默认值是`"Filesystem"`，就像在 1.9 之前一样。

# 访问模式

有三种访问模式：

+   `ReadOnlyMany`：可以由多个节点挂载为只读

+   `ReadWriteOnce`：可以由单个节点挂载为读写

+   `ReadWriteMany`：可以由多个节点挂载为读写

存储被挂载到节点，所以即使使用`ReadWriteOnce`，同一节点上的多个容器也可以挂载该卷并对其进行写入。如果这造成问题，您需要通过其他机制来处理（例如，您可以只在您知道每个节点只有一个的 DaemonSet pods 中索赔该卷）。

不同的存储提供程序支持这些模式的一些子集。当您配置持久卷时，可以指定它将支持哪些模式。例如，NFS 支持所有模式，但在示例中，只启用了这些模式：

```
accessModes:
    - ReadWriteMany
   - ReadOnlyMany
```

# 回收策略

回收策略确定持久卷索赔被删除时会发生什么。有三种不同的策略：

+   `Retain`：需要手动回收卷

+   `Delete`：关联的存储资产，如 AWS EBS、GCE PD、Azure 磁盘或 OpenStack Cinder 卷，将被删除

+   `Recycle`：仅删除内容（`rm -rf /volume/*`）

`Retain`和`Delete`策略意味着持久卷将不再对未来索赔可用。`recycle`策略允许再次索赔该卷。

目前，只有 NFS 和 HostPath 支持回收。AWS EBS、GCE PD、Azure 磁盘和 Cinder 卷支持删除。动态配置的卷总是被删除。

# 存储类

您可以使用规范的可选`storageClassName`字段指定存储类。如果这样做，那么只有指定相同存储类的持久卷要求才能绑定到持久卷。如果不指定存储类，则只有不指定存储类的持久卷要求才能绑定到它。

# 卷类型

卷类型在规范中通过名称指定。没有`volumeType`部分。

在前面的示例中，`nfs`是卷类型：

```
nfs:
    path: /tmp
    server: 172.17.0.8 
```

每种卷类型可能有自己的一组参数。在这种情况下，它是一个`path`

和`server`。

我们将在本章后面讨论各种卷类型。

# 提出持久卷要求

当容器需要访问某些持久存储时，它们会提出要求（或者说，开发人员和集群管理员会协调必要的存储资源

要求）。以下是一个与上一节中的持久卷匹配的示例要求：

```
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: storage-claim
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 80Gi
  storageClassName: "normal"
  selector:
    matchLabels:
      release: "stable"
    matchExpressions:
      - {key: capacity, operator: In, values: [80Gi, 100Gi]}
```

名称`storage-claim`在将要将要求挂载到容器中时将变得重要。

规范中的访问模式为`ReadWriteOnce`，这意味着如果要求得到满足，则不能满足其他具有`ReadWriteOnce`访问模式的要求，但仍然可以满足`ReadOnlyMany`的要求。

资源部分请求 80 GiB。这可以通过我们的持久卷满足，它的容量为 100 GiB。但这有点浪费，因为 20 GiB 将不会被使用。

存储类名称为`"normal"`。如前所述，它必须与持久卷的类名匹配。但是，对于**持久卷要求**（**PVC**），空类名（`""`）和没有类名之间存在差异。前者（空类名）与没有存储类名的持久卷匹配。后者（没有类名）只有在关闭`DefaultStorageClass`准入插件或者打开并且使用默认存储类时才能绑定到持久卷。

`Selector`部分允许您进一步过滤可用的卷。例如，在这里，卷必须匹配标签`release: "stable"`，并且还必须具有标签`capacity: 80 Gi`或`capacity: 100 Gi`。假设我们还有其他几个容量为 200 Gi 和 500 Gi 的卷。当我们只需要 80 Gi 时，我们不希望索赔 500 Gi 的卷。

Kubernetes 始终尝试匹配可以满足索赔的最小卷，但如果没有 80 Gi 或 100 Gi 的卷，那么标签将阻止分配 200 Gi 或 500 Gi 的卷，并使用动态配置。

重要的是要意识到索赔不会按名称提及卷。匹配是由基于存储类、容量和标签的 Kubernetes 完成的。

最后，持久卷索赔属于命名空间。将持久卷绑定到索赔是排他的。这意味着持久卷将绑定到一个命名空间。即使访问模式是`ReadOnlyMany`或`ReadWriteMany`，所有挂载持久卷索赔的 Pod 必须来自该索赔的命名空间。

# 将索赔作为卷

好的。我们已经配置了一个卷并对其进行了索赔。现在是时候在容器中使用索赔的存储了。这其实非常简单。首先，持久卷索赔必须在 Pod 中用作卷，然后 Pod 中的容器可以像任何其他卷一样挂载它。这是一个`pod`配置文件，指定了我们之前创建的持久卷索赔（绑定到我们配置的 NFS 持久卷）。

```
kind: Pod
apiVersion: v1
metadata:
  name: the-pod
spec:
  containers:
    - name: the-container
      image: some-image
      volumeMounts:
      - mountPath: "/mnt/data"
        name: persistent-volume
  volumes:
    - name: persistent-volume
      persistentVolumeClaim:
        claimName: storage-claim
```

关键在`volumes`下的`persistentVolumeClaim`部分。索赔名称（这里是`storage-claim`）在当前命名空间内唯一标识特定索赔，并使其作为卷命名为`persistent-volume`。然后，容器可以通过名称引用它，并将其挂载到`/mnt/data`。

# 原始块卷

Kubernetes 1.9 将此功能作为 alpha 功能添加。您必须使用功能门控来启用它：`--feature-gates=BlockVolume=true`。

原始块卷提供对底层存储的直接访问，不经过文件系统抽象。这对需要高存储性能的应用程序非常有用，比如数据库，或者需要一致的 I/O 性能和低延迟。光纤通道、iSCSI 和本地 SSD 都适用于用作原始块存储。目前（Kubernetes 1.10），只有`Local Volume`和`FiberChannel`存储提供程序支持原始块卷。以下是如何定义原始块卷：

```
apiVersion: v1
kind: PersistentVolume
metadata:
  name: block-pv
spec:
  capacity:
    storage: 10Gi
  accessModes:
    - ReadWriteOnce
  volumeMode: Block
  persistentVolumeReclaimPolicy: Retain
  fc:
    targetWWNs: ["50060e801049cfd1"]
    lun: 0
    readOnly: false
```

匹配的 PVC 必须指定`volumeMode: Block`。这是它的样子：

```
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: block-pvc
spec:
  accessModes:
    - ReadWriteOnce
  volumeMode: Block
  resources:
    requests:
      storage: 10Gi
```

Pods 将原始块卷作为`/dev`下的设备而不是挂载的文件系统来消耗。容器可以访问这个设备并对其进行读/写。实际上，这意味着对块存储的 I/O 请求直接传递到底层块存储，而不经过文件系统驱动程序。理论上这更快，但实际上如果您的应用程序受益于文件系统缓冲，它实际上可能会降低性能。

这是一个带有容器的 Pod，它将`block-pvc`与原始块存储绑定为名为`/dev/xdva`的设备：

```
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-block-volume
spec:
  containers:
    - name: fc-container
      image: fedora:26
      command: ["/bin/sh", "-c"]
      args: [ "tail -f /dev/null" ]
      volumeDevices:
        - name: data
          devicePath: /dev/xvda
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: block-pvc
```

# 存储类

存储类允许管理员使用自定义持久存储配置集群（只要有适当的插件支持）。存储类在`metadata`中有一个`name`，一个`provisioner`和`parameters`：

```
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: standard
provisioner: kubernetes.io/aws-ebs
parameters:
  type: gp2
```

您可以为同一个提供程序创建多个存储类，每个提供程序都有自己的参数。

目前支持的卷类型如下：

+   `AwsElasticBlockStore`

+   `AzureFile`

+   `AzureDisk`

+   `CephFS`

+   `Cinder`

+   `FC`

+   `FlexVolume`

+   `Flocker`

+   `GcePersistentDisk`

+   `GlusterFS`

+   `ISCSI`

+   `PhotonPersistentDisk`

+   `Quobyte`

+   `NFS`

+   `RBD`

+   `VsphereVolume`

+   `PortworxVolume`

+   `ScaleIO`

+   `StorageOS`

+   `Local`

这个列表不包含其他卷类型，比如`gitRepo`或`secret`，这些类型不是由典型的网络存储支持的。Kubernetes 的这个领域仍然在变化中，将来它会进一步解耦，设计会更清晰，插件将不再是 Kubernetes 本身的一部分。智能地利用卷类型是架构和管理集群的重要部分。

# 默认存储类

集群管理员还可以分配一个默认的`storage`类。当分配了默认的存储类并且打开了`DefaultStorageClass`准入插件时，那么没有存储类的声明将使用默认的`storage`类进行动态配置。如果默认的`storage`类没有定义或者准入插件没有打开，那么没有存储类的声明只能匹配没有`storage`类的卷。

# 演示持久卷存储的端到端

为了说明所有的概念，让我们进行一个小型演示，创建一个 HostPath 卷，声明它，挂载它，并让容器写入它。

让我们首先创建一个`hostPath`卷。将以下内容保存在`persistent-volume.yaml`中：

```
kind: PersistentVolume
apiVersion: v1
metadata:
 name: persistent-volume-1
spec:
 StorageClassName: dir
 capacity:
 storage: 1Gi
 accessModes:
 - ReadWriteOnce
 hostPath:
 path: "/tmp/data"

> kubectl create -f persistent-volume.yaml
persistentvolume "persistent-volume-1" created
```

要查看可用的卷，可以使用`persistentvolumes`资源类型，或者简称为`pv`：

```
> kubectl get pv
NAME:             persistent-volume-1 
CAPACITY:         1Gi
ACCESS MODES:     RWO 
RECLAIM POLICY:   Retain 
STATUS:           Available 
CLAIM: 
STORAGECLASS:    dir
REASON: 
AGE:             17s 
```

我稍微编辑了一下输出，以便更容易看到。容量为 1 GiB，符合要求。回收策略是`Retain`，因为`HostPath`卷是保留的。状态为`Available`，因为卷尚未被声明。访问模式被指定为`RWX`，表示`ReadWriteMany`。所有访问模式都有一个简写版本：

+   `RWO`：`ReadWriteOnce`

+   `ROX`：`ReadOnlyMany`

+   `RWX`：`ReadWriteMany`

我们有一个持久卷。让我们创建一个声明。将以下内容保存到`persistent-volume-claim.yaml`中：

```
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
 name: persistent-volume-claim
spec:
 accessModes:
 - ReadWriteOnce
 resources:
 requests:
 storage: 1Gi
```

然后，运行以下命令：

```
> kubectl create -f  persistent-volume-claim.yaml
persistentvolumeclaim "persistent-volume-claim" created  
```

让我们检查一下`claim`和`volume`：

```
> kubectl get pvc
NAME                                  STATUS  VOLUME                     CAPACITY   ACCESSMODES   AGE
persistent-volume-claim   Bound     persistent-volume-1   1Gi        RWO            dir            1m

> kubectl get pv
NAME:                 persistent-volume-1
CAPACITY:             1Gi
ACCESS MODES:         RWO 
RECLAIM POLICY:       Retain
STATUS:               Bound 
CLAIM:               default/persistent-volume-claim 
STORAGECLASS:        dir
REASON: 
AGE:                 3m  
```

如您所见，`claim`和`volume`已经绑定在一起。最后一步是创建一个`pod`并将`claim`分配为`volume`。将以下内容保存到`shell-pod.yaml`中：

```
kind: Pod
apiVersion: v1
metadata:
 name: just-a-shell
 labels:
 name: just-a-shell
spec:
 containers:
 - name: a-shell
 image: ubuntu
 command: ["/bin/bash", "-c", "while true ; do sleep 10 ; done"]
 volumeMounts:
 - mountPath: "/data"
 name: pv
 - name: another-shell
 image: ubuntu
 command: ["/bin/bash", "-c", "while true ; do sleep 10 ; done"]
 volumeMounts:
 - mountPath: "/data"
 name: pv
 volumes:
 - name: pv
 persistentVolumeClaim:
 claimName: persistent-volume-claim
```

这个 pod 有两个容器，它们使用 Ubuntu 镜像，并且都运行一个`shell`命令，只是在无限循环中睡眠。这样做的目的是让容器保持运行，这样我们以后可以连接到它们并检查它们的文件系统。该 pod 将我们的持久卷声明挂载为`pv`的卷名。两个容器都将其挂载到它们的`/data`目录中。

让我们创建`pod`并验证两个容器都在运行：

```
> kubectl create -f shell-pod.yaml
pod "just-a-shell" created

> kubectl get pods
NAME           READY     STATUS    RESTARTS   AGE
just-a-shell   2/2       Running   0           1m 
```

然后，`ssh`到节点。这是主机，其`/tmp/data`是 pod 的卷，挂载为每个正在运行的容器的`/data`：

```
> minikube ssh
$
```

在节点内部，我们可以使用 Docker 命令与容器进行通信。让我们看一下最后两个正在运行的容器：

```
$ docker ps -n 2 --format '{{.ID}}\t{{.Image}}\t{{.Command}}'
820fc954fb96     ubuntu    "/bin/bash -c 'whi..."
cf4502f14be5     ubuntu    "/bin/bash -c 'whi..."
```

然后，在主机的`/tmp/data`目录中创建一个文件。它应该通过挂载的卷对两个容器都可见：

```
$ sudo touch /tmp/data/1.txt
```

让我们在其中一个容器上执行一个`shell`，验证文件`1.txt`确实可见，并创建另一个文件`2.txt`：

```
$ docker exec -it 820fc954fb96  /bin/bash
root@just-a-shell:/# ls /data
1.txt
root@just-a-shell:/# touch /data/2.txt
root@just-a-shell:/# exit
Finally, we can run a shell on the other container and verify that both 1.txt and 2.txt are visible:
docker@minikube:~$ docker exec -it cf4502f14be5 /bin/bash
root@just-a-shell:/# ls /data
1.txt  2.txt
```

# 公共存储卷类型 - GCE，AWS 和 Azure

在本节中，我们将介绍一些主要公共云平台中可用的常见卷类型。在规模上管理存储是一项困难的任务，最终涉及物理资源，类似于节点。如果您选择在公共云平台上运行您的 Kubernetes 集群，您可以让您的云提供商处理所有这些挑战，并专注于您的系统。但重要的是要了解每种卷类型的各种选项、约束和限制。

# AWS 弹性块存储（EBS）

AWS 为 EC2 实例提供 EBS 作为持久存储。AWS Kubernetes 集群可以使用 AWS EBS 作为持久存储，但有以下限制：

+   pod 必须在 AWS EC2 实例上作为节点运行

+   Pod 只能访问其可用区中配置的 EBS 卷

+   EBS 卷可以挂载到单个 EC2 实例

这些是严重的限制。单个可用区的限制，虽然对性能有很大帮助，但消除了在规模或地理分布系统中共享存储的能力，除非进行自定义复制和同步。单个 EBS 卷限制为单个 EC2 实例意味着即使在同一可用区内，pod 也无法共享存储（甚至是读取），除非您确保它们在同一节点上运行。

在解释所有免责声明之后，让我们看看如何挂载 EBS 卷：

```
apiVersion: v1
kind: Pod
metadata:
 name: some-pod
spec:
 containers:
 - image: some-container
 name: some-container
 volumeMounts:
 - mountPath: /ebs
 name: some-volume
 volumes:
 - name: some-volume
 awsElasticBlockStore:
 volumeID: <volume-id>
 fsType: ext4
```

您必须在 AWS 中创建 EBS 卷，然后将其挂载到 pod 中。不需要声明或存储类，因为您通过 ID 直接挂载卷。`awsElasticBlockStore`卷类型为 Kubernetes 所知。

# AWS 弹性文件系统

AWS 最近推出了一项名为**弹性文件系统**（**EFS**）的新服务。这实际上是一个托管的 NFS 服务。它使用 NFS 4.1 协议，并且与 EBS 相比有许多优点：

+   多个 EC2 实例可以跨多个可用区（但在同一区域内）访问相同的文件

+   容量根据实际使用情况自动扩展和缩减

+   您只支付您使用的部分

+   您可以通过 VPN 将本地服务器连接到 EFS

+   EFS 运行在自动在可用区之间复制的 SSD 驱动器上

话虽如此，即使考虑到自动复制到多个可用区（假设您充分利用了 EBS 卷），EFS 比 EBS 更加广泛。它正在使用外部供应商，部署起来并不是微不足道的。请按照这里的说明进行操作：

[`github.com/kubernetes-incubator/external-storage/tree/master/aws/efs`](https://github.com/kubernetes-incubator/external-storage/tree/master/aws/efs)

一旦一切都设置好了，并且您已经定义了存储类，并且持久卷存在，您可以创建一个声明，并将其以`ReadWriteMany`模式挂载到尽可能多的`pod`中。这是持久声明：

```
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
 name: efs
 annotations:
 volume.beta.kubernetes.io/storage-class: "aws-efs"
spec:
 accessModes:
 - ReadWriteMany
 resources:
 requests:
 storage: 1Mi
```

这是一个使用它的`pod`：

```
kind: Pod
apiVersion: v1
metadata:
 name: test-pod
spec:
 containers:
 - name: test-pod
 image: gcr.io/google_containers/busybox:1.24
 command:
 - "/bin/sh"
 args:
 - "-c"
 - "touch /mnt/SUCCESS exit 0 || exit 1"
 volumeMounts:
 - name: efs-pvc
 mountPath: "/mnt"
 restartPolicy: "Never"
 volumes:
 - name: efs-pvc
 persistentVolumeClaim:
 claimName: efs

```

# GCE 持久磁盘

`gcePersistentDisk`卷类型与`awsElasticBlockStore`非常相似。您必须提前规划磁盘。它只能被同一项目和区域中的 GCE 实例使用。但是同一卷可以在多个实例上以只读方式使用。这意味着它支持`ReadWriteOnce`和`ReadOnlyMany`。您可以使用 GCE 持久磁盘在同一区域的多个`pod`之间共享数据。

使用`ReadWriteOnce`模式中的持久磁盘的`pod`必须由复制控制器、副本集或具有`0`或`1`个副本计数的部署控制。尝试扩展到`1`之外的数量将因明显原因而失败：

```
apiVersion: v1
kind: Pod
metadata:
 name: some-pod
spec:
 containers:
 - image: some-container
 name: some-container
 volumeMounts:
 - mountPath: /pd
 name: some-volume
 volumes:
 - name: some-volume
 gcePersistentDisk:
 pdName: <persistent disk name>
 fsType: ext4 
```

# Azure 数据磁盘

Azure 数据磁盘是存储在 Azure 存储中的虚拟硬盘。它的功能类似于 AWS EBS。这是一个示例`pod`配置文件：

```
apiVersion: v1
kind: Pod
metadata:
 name: some-pod
spec:
 containers:
 - image: some-container
 name: some-container
 volumeMounts:
 - name: some-volume
 mountPath: /azure
 volumes:
 - name: some-volume
 azureDisk:
 diskName: test.vhd
 diskURI: https://someaccount.blob.microsoft.net/vhds/test.vhd 
```

除了强制的`diskName`和`diskURI`参数之外，它还有一些可选参数：

+   `cachingMode`：磁盘缓存模式。必须是`None`、`ReadOnly`或`ReadWrite`之一。默认值为`None`。

+   `fsType`：文件系统类型设置为`mount`。默认值为`ext4`。

+   `readOnly`：文件系统是否以`readOnly`模式使用。默认值为`false`。

Azure 数据磁盘的限制为 1,023 GB。每个 Azure VM 最多可以有 16 个数据磁盘。您可以将 Azure 数据磁盘附加到单个 Azure VM 上。

# Azure 文件存储

除了数据磁盘，Azure 还有一个类似于 AWS EFS 的共享文件系统。但是，Azure 文件存储使用 SMB/CIFS 协议（支持 SMB 2.1 和 SMB 3.0）。它基于 Azure 存储平台，具有与 Azure Blob、Table 或 Queue 相同的可用性、耐用性、可扩展性和地理冗余能力。

为了使用 Azure 文件存储，您需要在每个客户端 VM 上安装`cifs-utils`软件包。您还需要创建一个`secret`，这是一个必需的参数：

```
apiVersion: v1
kind: Secret
metadata:
 name: azure-file-secret
type: Opaque
data:
 azurestorageaccountname: <base64 encoded account name>
 azurestorageaccountkey: <base64 encoded account key>
```

这是一个 Azure 文件存储的配置文件：

```
apiVersion: v1
kind: Pod
metadata:
 name: some-pod
spec:
 containers:
  - image: some-container
    name: some-container
    volumeMounts:
      - name: some-volume
        mountPath: /azure
 volumes:
      - name: some-volume
        azureFile:
          secretName: azure-file-secret
         shareName: azure-share
          readOnly: false
```

Azure 文件存储支持在同一地区内共享以及连接本地客户端。以下是说明工作流程的图表：

# Kubernetes 中的 GlusterFS 和 Ceph 卷

GlusterFS 和 Ceph 是两个分布式持久存储系统。GlusterFS 在其核心是一个网络文件系统。Ceph 在核心是一个对象存储。两者都公开块、对象和文件系统接口。两者都在底层使用`xfs`文件系统来存储数据和元数据作为`xattr`属性。您可能希望在 Kubernetes 集群中使用 GlusterFS 或 Ceph 作为持久卷的几个原因：

+   您可能有很多数据和应用程序访问 GlusterFS 或 Ceph 中的数据

+   您具有管理和操作 GlusterFS 的专业知识

或 Ceph

+   您在云中运行，但云平台持久存储的限制是一个非起点。

# 使用 GlusterFS

GlusterFS 故意简单，将底层目录公开，并留给客户端（或中间件）处理高可用性、复制和分发。GlusterFS 将数据组织成逻辑卷，其中包括包含文件的多个节点（机器）的砖块。文件根据 DHT（分布式哈希表）分配给砖块。如果文件被重命名或 GlusterFS 集群被扩展或重新平衡，文件可能会在砖块之间移动。以下图表显示了 GlusterFS 的构建模块：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/2cce08b3-be8d-480f-a250-4fa10b656553.png)

要将 GlusterFS 集群用作 Kubernetes 的持久存储（假设您已经运行了 GlusterFS 集群），您需要遵循几个步骤。特别是，GlusterFS 节点由插件作为 Kubernetes 服务进行管理（尽管作为应用程序开发人员，这与您无关）。

# 创建端点

这是一个端点资源的示例，您可以使用`kubectl create`创建为普通的 Kubernetes 资源：

```
{
  "kind": "Endpoints",
  "apiVersion": "v1",
  "metadata": {
    "name": "glusterfs-cluster"
  },
  "subsets": [
    {
      "addresses": [
        {
          "ip": "10.240.106.152"
        }
      ],
      "ports": [
        {
          "port": 1
        }
      ]
    },
    {
      "addresses": [
        {
          "ip": "10.240.79.157"
        }
      ],
      "ports": [
        {
          "port": 1
        }
      ]
    }
  ]
}
```

# 添加 GlusterFS Kubernetes 服务

为了使端点持久，您可以使用一个没有选择器的 Kubernetes 服务来指示端点是手动管理的：

```
{
  "kind": "Service",
  "apiVersion": "v1",
  "metadata": {
    "name": "glusterfs-cluster"
  },
  "spec": {
    "ports": [
      {"port": 1}
    ]
  }
}
```

# 创建 Pods

最后，在 pod 规范的`volumes`部分中，提供以下信息：

```
"volumes": [
            {
                "name": "glusterfsvol",
                "glusterfs": {
                    "endpoints": "glusterfs-cluster",
                    "path": "kube_vol",
                    "readOnly": true
                }
            }
        ] 
```

然后容器可以按名称挂载`glusterfsvol`。

`endpoints`告诉 GlusterFS 卷插件如何找到 GlusterFS 集群的存储节点。

# 使用 Ceph

Ceph 的对象存储可以使用多个接口访问。Kubernetes 支持**RBD**（块）和**CEPHFS**（文件系统）接口。以下图表显示了 RADOS - 底层对象存储 - 如何在多天内访问。与 GlusterFS 不同，Ceph 会自动完成大量工作。它自行进行分发、复制和自我修复：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/04ef7c1d-6584-455b-b84a-8d5cd92a0375.png)

# 使用 RBD 连接到 Ceph

Kubernetes 通过**Rados****Block****Device**（**RBD**）接口支持 Ceph。您必须在 Kubernetes 集群中的每个节点上安装`ceph-common`。一旦您的 Ceph 集群正常运行，您需要在`pod`配置文件中提供 Ceph RBD 卷插件所需的一些信息：

+   `monitors`：Ceph 监视器。

+   `pool`：RADOS 池的名称。如果未提供，则使用默认的 RBD 池。

+   `image`：RBD 创建的镜像名称。

+   `user`：RADOS 用户名。如果未提供，则使用默认的`admin`。

+   `keyring`：`keyring`文件的路径。如果未提供，则使用默认的`/etc/ceph/keyring`。

+   `*` `secretName`：认证密钥的名称。如果提供了一个，则`secretName`会覆盖`keyring`。注意：请参阅下一段关于如何创建`secret`的内容。

+   `fsType`：在其上格式化的文件系统类型（`ext4`、`xfs`等）。

设备。

+   `readOnly`：文件系统是否以`readOnly`方式使用。

如果使用了 Ceph 认证`secret`，则需要创建一个`secret`对象：

```
apiVersion: v1
kind: Secret
metadata:
  name: ceph-secret
type: "kubernetes.io/rbd" 
data:
  key: QVFCMTZWMVZvRjVtRXhBQTVrQ1FzN2JCajhWVUxSdzI2Qzg0SEE9PQ==
```

`secret`类型为`kubernetes.io/rbd`。

pod 规范的`volumes`部分看起来与此相同：

```
"volumes": [
    {
        "name": "rbdpd",
        "rbd": {
            "monitors": [
          "10.16.154.78:6789",
      "10.16.154.82:6789",
          "10.16.154.83:6789"
        ],
            "pool": "kube",
            "image": "foo",
            "user": "admin",
            "secretRef": {
      "name": "ceph-secret"
      },
            "fsType": "ext4",
            "readOnly": true
        }
    }
]
```

Ceph RBD 支持`ReadWriteOnce`和`ReadOnlyMany`访问模式。

# 使用 CephFS 连接到 Ceph

如果您的 Ceph 集群已经配置了 CephFS，则可以非常轻松地将其分配给 pod。此外，CephFS 支持`ReadWriteMany`访问模式。

配置类似于 Ceph RBD，只是没有池、镜像或文件系统类型。密钥可以是对 Kubernetes `secret`对象的引用（首选）或`secret`文件：

```
apiVersion: v1
kind: Pod
metadata:
  name: cephfs
spec:
  containers:
  - name: cephfs-rw
    image: kubernetes/pause
    volumeMounts:
    - mountPath: "/mnt/cephfs"
      name: cephfs
  volumes:
  - name: cephfs
    cephfs:
      monitors:
      - 10.16.154.78:6789
      - 10.16.154.82:6789
      - 10.16.154.83:6789
      user: admin
      secretFile: "/etc/ceph/admin.secret"
      readOnly: true
```

您还可以在`cephfs`系统中提供路径作为参数。默认为`/`。

内置的 RBD 供应程序在外部存储 Kubernetes 孵化器项目中有一个独立的副本。

# Flocker 作为集群容器数据卷管理器

到目前为止，我们已经讨论了将数据存储在 Kubernetes 集群之外的存储解决方案（除了`emptyDir`和 HostPath，它们不是持久的）。Flocker 有点不同。它是 Docker 感知的。它旨在让 Docker 数据卷在容器在节点之间移动时一起传输。如果你正在将基于 Docker 的系统从不同的编排平台（如 Docker compose 或 Mesos）迁移到 Kubernetes，并且你使用 Flocker 来编排存储，你可能想使用 Flocker 卷插件。就个人而言，我觉得 Flocker 所做的事情和 Kubernetes 为抽象存储所做的事情之间存在很多重复。

Flocker 有一个控制服务和每个节点上的代理。它的架构与 Kubernetes 非常相似，其 API 服务器和每个节点上运行的 Kubelet。Flocker 控制服务公开了一个 REST API，并管理着整个集群的状态配置。代理负责确保其节点的状态与当前配置匹配。例如，如果一个数据集需要在节点 X 上，那么节点 X 上的 Flocker 代理将创建它。

以下图表展示了 Flocker 架构：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/795d9283-b014-4464-a7b0-4732d4d83736.png)

为了在 Kubernetes 中使用 Flocker 作为持久卷，你首先必须有一个正确配置的 Flocker 集群。Flocker 可以与许多后备存储一起工作（再次，与 Kubernetes 持久卷非常相似）。

然后你需要创建 Flocker 数据集，这时你就可以将其连接为持久卷了。经过你的辛勤工作，这部分很容易，你只需要指定 Flocker 数据集的名称：

```
apiVersion: v1
kind: Pod
metadata:
  name: some-pod
spec:
  containers:
    - name: some-container
      image: kubernetes/pause
      volumeMounts:
          # name must match the volume name below
          - name: flocker-volume
            mountPath: "/flocker"
  volumes:
    - name: flocker-volume
      flocker:
        datasetName: some-flocker-dataset
```

# 将企业存储集成到 Kubernetes 中

如果你有一个通过 iSCSI 接口公开的现有**存储区域网络**（**SAN**），Kubernetes 为你提供了一个卷插件。它遵循了我们之前看到的其他共享持久存储插件的相同模型。你必须配置 iSCSI 启动器，但你不必提供任何启动器信息。你只需要提供以下内容：

+   iSCSI 目标的 IP 地址和端口（如果不是默认的`3260`）

+   目标的`iqn`（iSCSI 合格名称）—通常是反向域名

+   **LUN**—逻辑单元号

+   文件系统类型

+   `readonly`布尔标志

iSCSI 插件支持`ReadWriteOnce`和`ReadonlyMany`。请注意，目前无法对设备进行分区。以下是卷规范：

```
volumes:
  - name: iscsi-volume
    iscsi:
      targetPortal: 10.0.2.34:3260
      iqn: iqn.2001-04.com.example:storage.kube.sys1.xyz
      lun: 0
      fsType: ext4
      readOnly: true  
```

# 投影卷

可以将多个卷投影到单个目录中，使其显示为单个卷。支持的卷类型有：`secret`，`downwardAPI`和`configMap`。如果您想将多个配置源挂载到一个 pod 中，这将非常有用。您可以将它们全部捆绑到一个投影卷中，而不必为每个源创建单独的卷。这是一个例子：

```
apiVersion: v1
kind: Pod
metadata:
  name: the-pod
spec:
  containers:
  - name: the-container
    image: busybox
    volumeMounts:
    - name: all-in-one
      mountPath: "/projected-volume"
      readOnly: true
  volumes:
  - name: all-in-one
    projected:
      sources:
      - secret:
          name: the-secret
          items:
            - key: username
              path: the-group/the-user
      - downwardAPI:
          items:
            - path: "labels"
              fieldRef:
                fieldPath: metadata.labels
            - path: "cpu_limit"
              resourceFieldRef:
                containerName: the-container
                resource: limits.cpu
      - configMap:
          name: the-configmap
          items:
            - key: config
              path: the-group/the-config
```

# 使用 FlexVolume 的外部卷插件

FlexVolume 在 Kubernetes 1.8 中已经普遍可用。它允许您通过统一 API 消耗外部存储。存储提供商编写一个驱动程序，您可以在所有节点上安装。FlexVolume 插件可以动态发现现有的驱动程序。以下是使用 FlexVolume 绑定到外部 NFS 卷的示例：

```
apiVersion: v1
kind: Pod
metadata:
  name: nginx-nfs
  namespace: default
spec:
  containers:
  - name: nginx-nfs
    image: nginx
    volumeMounts:
    - name: test
      mountPath: /data
    ports:
    - containerPort: 80
  volumes:
  - name: test
    flexVolume:
      driver: "k8s/nfs"
      fsType: "nfs"
      options:
        server: "172.16.0.25"
        share: "dws_nas_scratch"
```

# 容器存储接口

**容器存储接口**（**CSI**）是标准化容器编排器和存储提供商之间交互的一个倡议。它由 Kubernetes、Docker、Mesos 和 Cloud Foundry 推动。其想法是存储提供商只需要实现一个插件，容器编排器只需要支持 CSI。这相当于存储的 CNI。与 FlexVolume 相比，有几个优点：

+   CSI 是一个行业标准

+   FlexVolume 插件需要访问节点和主节点根文件系统来部署驱动程序

+   FlexVolume 存储驱动程序通常需要许多外部依赖项

+   FlexVolume 的 EXEC 风格接口很笨拙

Kubernetes 1.9 中添加了一个 CSI 卷插件作为 alpha 功能，并在 Kubernetes 1.10 中已经升级为 beta 状态。FlexVolume 将保持向后兼容，至少一段时间。但随着 CSI 的发展和更多存储提供商实现 CSI 卷驱动程序，我确实可以看到 Kubernetes 只提供内部 CSI 卷插件，并通过 CSI 驱动程序与任何存储提供商进行通信。

这是一个演示 CSI 在 Kubernetes 中如何工作的图表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/a2dc5686-d962-4436-b8f5-b89c4d503f95.png)

# 总结

在本章中，我们深入研究了 Kubernetes 中的存储。我们看了基于卷、声明和存储类的通用概念模型，以及卷插件的实现。Kubernetes 最终将所有存储系统映射到容器中的挂载文件系统或原始块存储中。这种直接的模型允许管理员配置和连接任何存储系统，从本地的`host`目录到基于云的共享存储，再到企业存储系统。存储供应商从内部到外部的过渡对存储生态系统是一个好兆头。现在，您应该清楚地了解了存储在 Kubernetes 中的建模和实现，并能够在您的 Kubernetes 集群中做出明智的存储实现选择。

在第八章中，《使用 Kubernetes 运行有状态应用程序》，我们将看到 Kubernetes 如何提高抽象级别，并在存储之上，利用 StatefulSets 等概念来开发、部署和操作有状态的应用程序。


# 第八章：使用 Kubernetes 运行有状态应用

在这一章中，我们将探讨在 Kubernetes 上运行有状态应用所需的条件。Kubernetes 通过根据复杂的要求和配置（如命名空间、限制和配额）自动在集群节点上启动和重新启动 pod，从而减少了我们的工作量。但是，当 pod 运行存储感知软件（如数据库和队列）时，重新定位一个 pod 可能会导致系统崩溃。首先，我们将了解有状态 pod 的本质，以及它们在 Kubernetes 中管理起来更加复杂的原因。我们将探讨一些管理复杂性的方法，比如共享环境变量和 DNS 记录。在某些情况下，冗余的内存状态、DaemonSet 或持久存储声明可以解决问题。Kubernetes 为有状态 pod 推广的主要解决方案是 StatefulSet（以前称为 PetSet）资源，它允许我们管理具有稳定属性的索引集合的 pod。最后，我们将深入探讨在 Kubernetes 上运行 Cassandra 集群的一个完整示例。

# Kubernetes 中有状态与无状态应用

在 Kubernetes 中，无状态应用是指不在 Kubernetes 集群中管理其状态的应用。所有状态都存储在集群外，集群容器以某种方式访问它。在本节中，我们将了解为什么状态管理对于分布式系统的设计至关重要，以及在 Kubernetes 集群内管理状态的好处。

# 理解分布式数据密集型应用的性质

让我们从基础知识开始。分布式应用程序是在多台计算机上运行的一组进程，处理输入，操作数据，公开 API，并可能具有其他副作用。每个进程是其程序、运行时环境和输入输出的组合。你在学校写的程序会作为命令行参数获取输入，也许它们会读取文件或访问数据库，然后将结果写入屏幕、文件或数据库。一些程序在内存中保持状态，并可以通过网络提供请求。简单的程序在单台计算机上运行，可以将所有状态保存在内存中或从文件中读取。它们的运行时环境是它们的操作系统。如果它们崩溃，用户必须手动重新启动它们。它们与它们的计算机绑定在一起。分布式应用程序是一个不同的动物。单台计算机不足以处理所有数据或足够快地提供所有请求。单台计算机无法容纳所有数据。需要处理的数据如此之大，以至于无法以成本效益的方式下载到每个处理机器中。机器可能会出现故障，需要被替换。需要在所有处理机器上执行升级。用户可能分布在全球各地。

考虑所有这些问题后，很明显传统方法行不通。限制因素变成了数据。用户/客户端必须只接收摘要或处理过的数据。所有大规模数据处理必须在数据附近进行，因为传输数据的速度慢且昂贵。相反，大部分处理代码必须在相同的数据中心和网络环境中运行。

# 共享环境变量与 DNS 记录用于发现

Kubernetes 为集群中的全局发现提供了几种机制。如果您的存储集群不是由 Kubernetes 管理，您仍然需要告诉 Kubernetes pod 如何找到它并访问它。主要有两种方法：

+   DNS

+   环境变量

在某些情况下，您可能希望同时使用环境变量和 DNS，其中环境变量可以覆盖 DNS。

# 为什么要在 Kubernetes 中管理状态？

在 Kubernetes 中管理状态的主要原因是，与在单独的集群中管理相比，Kubernetes 已经提供了许多监视、扩展、分配、安全和操作存储集群所需的基础设施。运行并行存储集群将导致大量重复的工作。

# 为什么要在 Kubernetes 之外管理状态？

让我们不排除其他选择。在某些情况下，将状态管理在一个单独的非 Kubernetes 集群中可能更好，只要它与相同的内部网络共享（数据接近性胜过一切）。

一些有效的原因如下：

+   您已经有一个单独的存储集群，不想引起麻烦

+   您的存储集群被其他非 Kubernetes 应用程序使用

+   Kubernetes 对您的存储集群的支持还不够稳定或成熟

您可能希望逐步在 Kubernetes 中处理有状态的应用程序，首先从一个单独的存储集群开始，然后再与 Kubernetes 更紧密地集成。

# 通过 DNS 访问外部数据存储

DNS 方法简单直接。假设您的外部存储集群是负载均衡的，并且可以提供稳定的端点，那么 pod 可以直接命中该端点并连接到外部集群。

# 通过环境变量访问外部数据存储

另一种简单的方法是使用环境变量传递连接信息到外部存储集群。Kubernetes 提供`ConfigMap`资源作为一种将配置与容器镜像分开的方式。配置是一组键值对。配置信息可以作为环境变量暴露在容器内部以及卷中。您可能更喜欢使用秘密来存储敏感的连接信息。

# 创建 ConfigMap

以下配置文件将创建一个保留地址列表的配置文件：

```
apiVersion: v1 
kind: ConfigMap 
metadata: 
  name: db-config 
  namespace: default 
data: 
  db-ip-addresses: 1.2.3.4,5.6.7.8 

> kubectl create -f .\configmap.yamlconfigmap
 "db-config" created
```

`data`部分包含所有的键值对，这种情况下，只有一个键名为`db-ip-addresses`的键值对。在后面消耗`configmap`时将会很重要。您可以检查内容以确保它是正确的：

```
> kubectl get configmap db-config -o yaml
apiVersion: v1
data:
  db-ip-addresses: 1.2.3.4,5.6.7.8
kind: ConfigMap
metadata:
 creationTimestamp: 2017-01-09T03:14:07Z
 name: db-config
 namespace: default
 resourceVersion: "551258"
 selfLink: /api/v1/namespaces/default/configmaps/db-config
 uid: aebcc007-d619-11e6-91f1-3a7ae2a25c7d  
```

还有其他创建`ConfigMap`的方法。您可以直接使用`--from-value`或`--from-file`命令行参数来创建它们。

# 将 ConfigMap 作为环境变量消耗

当您创建一个 pod 时，可以指定一个`ConfigMap`并以多种方式使用其值。以下是如何将我们的配置映射为环境变量：

```
apiVersion: v1 
kind: Pod 
metadata: 
  name: some-pod 
spec: 
  containers: 
    - name: some-container 
      image: busybox 
      command: [ "/bin/sh", "-c", "env" ] 
      env: 
        - name: DB_IP_ADDRESSES 
          valueFrom: 
            configMapKeyRef: 
              name: db-config 
              key: db-ip-addresses         
  restartPolicy: Never 
```

这个 pod 运行`busybox`最小容器，并执行`env bash`命令，然后立即退出。`db-config`映射中的`db-ip-addresses`键被映射到`DB_IP_ADDRESSES`环境变量，并反映在输出中：

```
> kubectl logs some-pod
HUE_REMINDERS_SERVICE_PORT=80
HUE_REMINDERS_PORT=tcp://10.0.0.238:80
KUBERNETES_PORT=tcp://10.0.0.1:443
KUBERNETES_SERVICE_PORT=443
HOSTNAME=some-pod
SHLVL=1
HOME=/root
HUE_REMINDERS_PORT_80_TCP_ADDR=10.0.0.238
HUE_REMINDERS_PORT_80_TCP_PORT=80
HUE_REMINDERS_PORT_80_TCP_PROTO=tcp
DB_IP_ADDRESSES=1.2.3.4,5.6.7.8
HUE_REMINDERS_PORT_80_TCP=tcp://10.0.0.238:80
KUBERNETES_PORT_443_TCP_ADDR=10.0.0.1
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
KUBERNETES_PORT_443_TCP_PORT=443
KUBERNETES_PORT_443_TCP_PROTO=tcp
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_PORT_443_TCP=tcp://10.0.0.1:443
HUE_REMINDERS_SERVICE_HOST=10.0.0.238
PWD=/
KUBERNETES_SERVICE_HOST=10.0.0.1 
```

# 使用冗余的内存状态

在某些情况下，您可能希望在内存中保留瞬态状态。分布式缓存是一个常见情况。时间敏感的信息是另一个情况。对于这些用例，不需要持久存储，通过服务访问多个 Pod 可能是正确的解决方案。我们可以使用标签等标准 Kubernetes 技术来识别属于存储冗余副本的 Pod，并通过服务公开它。如果一个 Pod 死掉，Kubernetes 将创建一个新的 Pod，并且在它赶上之前，其他 Pod 将服务于该状态。我们甚至可以使用 Pod 的反亲和性 alpha 功能来确保维护相同状态的冗余副本的 Pod 不被调度到同一节点。

# 使用 DaemonSet 进行冗余持久存储

一些有状态的应用程序，如分布式数据库或队列，会冗余地管理它们的状态并自动同步它们的节点（我们稍后将深入研究 Cassandra）。在这些情况下，重要的是将 Pod 调度到单独的节点。同样重要的是，Pod 应该被调度到具有特定硬件配置的节点，甚至专门用于有状态应用程序。DaemonSet 功能非常适合这种用例。我们可以为一组节点打上标签，并确保有状态的 Pod 被逐个地调度到所选的节点组。

# 应用持久卷索赔

如果有状态的应用程序可以有效地使用共享的持久存储，那么在每个 Pod 中使用持久卷索赔是正确的方法，就像我们在第七章中演示的那样，*处理 Kubernetes 存储*。有状态的应用程序将被呈现为一个看起来就像本地文件系统的挂载卷。

# 利用 StatefulSet

StatefulSet 控制器是 Kubernetes 的一个相对较新的添加（在 Kubernetes 1.3 中作为 PetSets 引入，然后在 Kubernetes 1.5 中更名为 StatefulSet）。它专门设计用于支持分布式有状态应用程序，其中成员的身份很重要，如果一个 Pod 被重新启动，它必须保留在集合中的身份。它提供有序的部署和扩展。与常规 Pod 不同，StatefulSet 的 Pod 与持久存储相关联。

# 何时使用 StatefulSet

StatefulSet 非常适合需要以下一项或多项功能的应用程序：

+   稳定、独特的网络标识符

+   稳定的持久存储

+   有序、优雅的部署和扩展

+   有序、优雅的删除和终止

# StatefulSet 的组件

有几个部分需要正确配置，才能使 StatefulSet 正常工作：

+   一个负责管理 StatefulSet pod 的网络标识的无头服务

+   具有多个副本的 StatefulSet 本身

+   动态或由管理员持久存储提供

这是一个名为`nginx`的服务的示例，将用于 StatefulSet：

```
apiVersion: v1 
kind: Service 
metadata: 
  name: nginx 
  labels: 
    app: nginx 
spec: 
  ports: 
  - port: 80 
    name: web 
  clusterIP: None 
  selector: 
    app: nginx 
```

现在，`StatefulSet`配置文件将引用该服务：

```
apiVersion: apps/v1 
kind: StatefulSet 
metadata: 
  name: web 
spec: 
  serviceName: "nginx" 
  replicas: 3 
  template: 
    metadata: 
      labels: 
        app: nginx 
```

接下来是包含名为`www`的挂载卷的 pod 模板：

```
spec: 
  terminationGracePeriodSeconds: 10 
  containers: 
  - name: nginx 
    image: gcr.io/google_containers/nginx-slim:0.8 
    ports: 
    - containerPort: 80 
      name: web 
      volumeMounts: 
    - name: www 
      mountPath: /usr/share/nginx/html 
```

最后，`volumeClaimTemplates`使用名为`www`的声明匹配挂载的卷。声明请求`1Gib`的`存储`，具有`ReadWriteOnce`访问权限：

```
volumeClaimTemplates: 
- metadata: 
    name: www 
  spec: 
    accessModes: [ "ReadWriteOnce" ] 
    resources: 
      requests: 
        storage: 1Gib 
```

# 在 Kubernetes 中运行 Cassandra 集群

在本节中，我们将详细探讨配置 Cassandra 集群在 Kubernetes 集群上运行的一个非常大的示例。完整的示例可以在这里访问：

[`github.com/kubernetes/kubernetes/tree/master/examples/storage/cassandra`](https://github.com/kubernetes/kubernetes/tree/master/examples/storage/cassandra)

首先，我们将学习一些关于 Cassandra 及其特殊性的知识，然后按照逐步的步骤来使其运行，使用我们在前一节中介绍的几种技术和策略。

# Cassandra 的简要介绍

Cassandra 是一个分布式列式数据存储。它从一开始就为大数据而设计。Cassandra 快速、健壮（没有单点故障）、高可用性和线性可扩展。它还支持多数据中心。它通过专注于并精心打造支持的功能，以及同样重要的是不支持的功能，来实现所有这些。在以前的公司中，我运行了一个使用 Cassandra 作为传感器数据主要数据存储的 Kubernetes 集群（约 100 TB）。Cassandra 根据**分布式哈希表**（**DHT**）算法将数据分配给一组节点（节点环）。集群节点通过八卦协议相互通信，并迅速了解集群的整体状态（哪些节点加入，哪些节点离开或不可用）。Cassandra 不断压缩数据并平衡集群。数据通常被复制多次以实现冗余、健壮性和高可用性。从开发者的角度来看，Cassandra 非常适合时间序列数据，并提供了一个灵活的模型，可以在每个查询中指定一致性级别。它还是幂等的（对于分布式数据库来说非常重要的特性），这意味着允许重复插入或更新。

这是一个图表，显示了 Cassandra 集群的组织方式，以及客户端如何访问任何节点，请求将如何自动转发到具有所请求数据的节点：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/3176a1dd-f524-4deb-8638-1b04872ec14d.png)

# Cassandra Docker 镜像

在 Kubernetes 上部署 Cassandra 与独立的 Cassandra 集群部署相反，需要一个特殊的 Docker 镜像。这是一个重要的步骤，因为这意味着我们可以使用 Kubernetes 来跟踪我们的 Cassandra pod。该镜像在这里可用：

[`github.com/kubernetes/kubernetes/tree/master/examples/storage/cassandra/image`](https://github.com/kubernetes/kubernetes/tree/master/examples/storage/cassandra/image)

以下是 Docker 文件的基本部分。该镜像基于 Ubuntu Slim：

```
FROM gcr.io/google_containers/ubuntu-slim:0.9  
```

添加和复制必要的文件（`Cassandra.jar`，各种配置文件，运行脚本和读取探测脚本），创建一个`data`目录供 Cassandra 存储其 SSTable，并挂载它：

```
ADD files / 

RUN set -e && echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections \
  && apt-get update && apt-get -qq -y --force-yes install --no-install-recommends \  
    openjdk-8-jre-headless \
    libjemalloc1 \ 
    localepurge  \
    wget && \
  mirror_url=$( wget -q -O - http://www.apache.org/dyn/closer.cgi/cassandra/ \
        | sed -n 's#.*href="\(http://.*/cassandra\/[^"]*\)".*#\1#p' \
        | head -n 1 \
    ) \
    && wget -q -O - ${mirror_url}/${CASSANDRA_VERSION}/apache-cassandra-${CASSANDRA_VERSION}-bin.tar.gz \
        | tar -xzf - -C /usr/local \
    && wget -q -O - https://github.com/Yelp/dumb-init/releases/download/v${DI_VERSION}/dumb-init_${DI_VERSION}_amd64 > /sbin/dumb-init \
    && echo "$DI_SHA  /sbin/dumb-init" | sha256sum -c - \
    && chmod +x /sbin/dumb-init \
    && chmod +x /ready-probe.sh \
    && mkdir -p /cassandra_data/data \
    && mkdir -p /etc/cassandra \
    && mv /logback.xml /cassandra.yaml /jvm.options /etc/cassandra/ \ 
    && mv /usr/local/apache-cassandra-${CASSANDRA_VERSION}/conf/cassandra-env.sh /etc/cassandra/ \
    && adduser --disabled-password --no-create-home --gecos '' --disabled-login cassandra \
    && chown cassandra: /ready-probe.sh \ 

VOLUME ["/$CASSANDRA_DATA"] 
```

暴露访问 Cassandra 的重要端口，并让 Cassandra 节点相互通信：

```
# 7000: intra-node communication 
# 7001: TLS intra-node communication 
# 7199: JMX 
# 9042: CQL 
# 9160: thrift service 

EXPOSE 7000 7001 7199 9042 9160 
```

最后，使用`dumb-init`命令运行`run.sh`脚本，这是一个来自 yelp 的简单容器`init`系统：

```
CMD ["/sbin/dumb-init", "/bin/bash", "/run.sh"] 
```

# 探索`run.sh`脚本

`run.sh`脚本需要一些 shell 技能，但这是值得的。由于 Docker 只允许运行一个命令，对于非平凡的应用程序来说，有一个设置环境并为实际应用程序做准备的启动脚本是非常常见的。在这种情况下，镜像支持几种部署选项（有状态集、复制控制器、DaemonSet），我们稍后会介绍，而运行脚本通过环境变量非常可配置。

首先，为`/etc/cassandra/cassandra.yaml`中的 Cassandra 配置文件设置了一些本地变量。`CASSANDRA_CFG`变量将在脚本的其余部分中使用：

```
set -e 
CASSANDRA_CONF_DIR=/etc/cassandra 
CASSANDRA_CFG=$CASSANDRA_CONF_DIR/cassandra.yaml 
```

如果没有指定`CASSANDRA_SEEDS`，那么设置`HOSTNAME`，它在 StatefulSet 解决方案中使用：

```
# we are doing StatefulSet or just setting our seeds 
if [ -z "$CASSANDRA_SEEDS" ]; then 
  HOSTNAME=$(hostname -f) 
Fi 
```

然后是一长串带有默认值的环境变量。语法`${VAR_NAME:-<default>}`使用`VAR_NAME`环境变量，如果定义了的话，或者使用默认值。

类似的语法`${VAR_NAME:=<default}`也可以做同样的事情，但同时也赋值

如果未定义环境变量，则将默认值分配给它。

这里都用到了两种变体：

```
CASSANDRA_RPC_ADDRESS="${CASSANDRA_RPC_ADDRESS:-0.0.0.0}" 
CASSANDRA_NUM_TOKENS="${CASSANDRA_NUM_TOKENS:-32}" 
CASSANDRA_CLUSTER_NAME="${CASSANDRA_CLUSTER_NAME:='Test Cluster'}" 
CASSANDRA_LISTEN_ADDRESS=${POD_IP:-$HOSTNAME} 
CASSANDRA_BROADCAST_ADDRESS=${POD_IP:-$HOSTNAME} 
CASSANDRA_BROADCAST_RPC_ADDRESS=${POD_IP:-$HOSTNAME} 
CASSANDRA_DISK_OPTIMIZATION_STRATEGY="${CASSANDRA_DISK_OPTIMIZATION_STRATEGY:-ssd}" 
CASSANDRA_MIGRATION_WAIT="${CASSANDRA_MIGRATION_WAIT:-1}" 
CASSANDRA_ENDPOINT_SNITCH="${CASSANDRA_ENDPOINT_SNITCH:-SimpleSnitch}" 
CASSANDRA_DC="${CASSANDRA_DC}" 
CASSANDRA_RACK="${CASSANDRA_RACK}" 
CASSANDRA_RING_DELAY="${CASSANDRA_RING_DELAY:-30000}" 
CASSANDRA_AUTO_BOOTSTRAP="${CASSANDRA_AUTO_BOOTSTRAP:-true}" 
CASSANDRA_SEEDS="${CASSANDRA_SEEDS:false}" 
CASSANDRA_SEED_PROVIDER="${CASSANDRA_SEED_PROVIDER:-org.apache.cassandra.locator.SimpleSeedProvider}" 
CASSANDRA_AUTO_BOOTSTRAP="${CASSANDRA_AUTO_BOOTSTRAP:false}" 

# Turn off JMX auth 
CASSANDRA_OPEN_JMX="${CASSANDRA_OPEN_JMX:-false}" 
# send GC to STDOUT 
CASSANDRA_GC_STDOUT="${CASSANDRA_GC_STDOUT:-false}" 
```

然后是一个部分，其中所有变量都打印到屏幕上。让我们跳过大部分内容：

```
echo Starting Cassandra on ${CASSANDRA_LISTEN_ADDRESS}
echo CASSANDRA_CONF_DIR ${CASSANDRA_CONF_DIR}
...
```

接下来的部分非常重要。默认情况下，Cassandra 使用简单的 snitch，不知道机架和数据中心。当集群跨多个数据中心和机架时，这并不是最佳选择。

Cassandra 是机架和数据中心感知的，可以优化冗余性和高可用性，同时适当地限制跨数据中心的通信：

```
# if DC and RACK are set, use GossipingPropertyFileSnitch 
if [[ $CASSANDRA_DC && $CASSANDRA_RACK ]]; then 
  echo "dc=$CASSANDRA_DC" > $CASSANDRA_CONF_DIR/cassandra-rackdc.properties 
  echo "rack=$CASSANDRA_RACK" >> $CASSANDRA_CONF_DIR/cassandra-rackdc.properties 
  CASSANDRA_ENDPOINT_SNITCH="GossipingPropertyFileSnitch" 
fi 
```

内存管理很重要，您可以控制最大堆大小，以确保 Cassandra 不会开始抖动并开始与磁盘交换：

```
if [ -n "$CASSANDRA_MAX_HEAP" ]; then 
  sed -ri "s/^(#)?-Xmx[0-9]+.*/-Xmx$CASSANDRA_MAX_HEAP/" "$CASSANDRA_CONF_DIR/jvm.options" 
  sed -ri "s/^(#)?-Xms[0-9]+.*/-Xms$CASSANDRA_MAX_HEAP/" "$CASSANDRA_CONF_DIR/jvm.options" 
fi 

if [ -n "$CASSANDRA_REPLACE_NODE" ]; then 
   echo "-Dcassandra.replace_address=$CASSANDRA_REPLACE_NODE/" >> "$CASSANDRA_CONF_DIR/jvm.options" 
fi 
```

机架和数据中心信息存储在一个简单的 Java `properties`文件中：

```
for rackdc in dc rack; do 
  var="CASSANDRA_${rackdc^^}" 
  val="${!var}" 
  if [ "$val" ]; then 
  sed -ri 's/^('"$rackdc"'=).*/1 '"$val"'/' "$CASSANDRA_CONF_DIR/cassandra-rackdc.properties" 
  fi 
done 
```

接下来的部分循环遍历之前定义的所有变量，在`Cassandra.yaml`配置文件中找到相应的键，并进行覆盖。这确保了每个配置文件在启动 Cassandra 本身之前都是动态定制的：

```
for yaml in \  
  broadcast_address \ 
  broadcast_rpc_address \ 
  cluster_name \ 
  disk_optimization_strategy \ 
  endpoint_snitch \ 
  listen_address \ 
  num_tokens \  
  rpc_address \ 
  start_rpc \  
  key_cache_size_in_mb \ 
  concurrent_reads \ 
  concurrent_writes \ 
  memtable_cleanup_threshold \  
  memtable_allocation_type \ 
  memtable_flush_writers \ 
  concurrent_compactors \  
  compaction_throughput_mb_per_sec \ 
  counter_cache_size_in_mb \ 
  internode_compression \ 
  endpoint_snitch \ 
  gc_warn_threshold_in_ms \  
  listen_interface  \
  rpc_interface  \
  ; do 
  var="CASSANDRA_${yaml^^}" 
  val="${!var}" 
  if [ "$val" ]; then 
    sed -ri 's/^(# )?('"$yaml"':).*/\2 '"$val"'/' "$CASSANDRA_CFG" 
  fi 
done 

echo "auto_bootstrap: ${CASSANDRA_AUTO_BOOTSTRAP}" >> $CASSANDRA_CFG 
```

接下来的部分都是关于根据部署解决方案（StatefulSet 或其他）设置种子或种子提供程序。对于第一个 pod 来说，有一个小技巧可以作为自己的种子引导：

```
# set the seed to itself.  This is only for the first pod, otherwise 
# it will be able to get seeds from the seed provider 
if [[ $CASSANDRA_SEEDS == 'false' ]]; then 
  sed -ri 's/- seeds:.*/- seeds: "'"$POD_IP"'"/' $CASSANDRA_CFG 
else # if we have seeds set them.  Probably StatefulSet 
  sed -ri 's/- seeds:.*/- seeds: "'"$CASSANDRA_SEEDS"'"/' $CASSANDRA_CFG 
fi 

sed -ri 's/- class_name: SEED_PROVIDER/- class_name: '"$CASSANDRA_SEED_PROVIDER"'/' $CASSANDRA_CFG 
```

以下部分设置了远程管理和 JMX 监控的各种选项。在复杂的分布式系统中，拥有适当的管理工具至关重要。Cassandra 对普遍的**Java 管理扩展**（**JMX**）标准有深入的支持：

```
# send gc to stdout 
if [[ $CASSANDRA_GC_STDOUT == 'true' ]]; then 
  sed -ri 's/ -Xloggc:\/var\/log\/cassandra\/gc\.log//' $CASSANDRA_CONF_DIR/cassandra-env.sh 
fi 

# enable RMI and JMX to work on one port 
echo "JVM_OPTS=\"\$JVM_OPTS -Djava.rmi.server.hostname=$POD_IP\"" >> $CASSANDRA_CONF_DIR/cassandra-env.sh 

# getting WARNING messages with Migration Service 
echo "-Dcassandra.migration_task_wait_in_seconds=${CASSANDRA_MIGRATION_WAIT}" >> $CASSANDRA_CONF_DIR/jvm.options 
echo "-Dcassandra.ring_delay_ms=${CASSANDRA_RING_DELAY}" >> $CASSANDRA_CONF_DIR/jvm.options 

if [[ $CASSANDRA_OPEN_JMX == 'true' ]]; then 
  export LOCAL_JMX=no 
  sed -ri 's/ -Dcom\.sun\.management\.jmxremote\.authenticate=true/ -Dcom\.sun\.management\.jmxremote\.authenticate=false/' $CASSANDRA_CONF_DIR/cassandra-env.sh 
  sed -ri 's/ -Dcom\.sun\.management\.jmxremote\.password\.file=\/etc\/cassandra\/jmxremote\.password//' $CASSANDRA_CONF_DIR/cassandra-env.sh 
fi 
```

最后，`CLASSPATH`设置为`Cassandra` JAR 文件，并将 Cassandra 作为 Cassandra 用户在前台（非守护进程）启动：

```
export CLASSPATH=/kubernetes-cassandra.jar

su cassandra -c "$CASSANDRA_HOME/bin/cassandra -f"  
```

# 连接 Kubernetes 和 Cassandra

连接 Kubernetes 和 Cassandra 需要一些工作，因为 Cassandra 被设计为非常自给自足，但我们希望让它在适当的时候连接 Kubernetes 以提供功能，例如自动重新启动失败的节点、监视、分配 Cassandra pods，并在其他 pods 旁边提供 Cassandra pods 的统一视图。Cassandra 是一个复杂的系统，有许多控制选项。它带有一个`Cassandra.yaml`配置文件，您可以使用环境变量覆盖所有选项。

# 深入了解 Cassandra 配置

有两个特别相关的设置：seed 提供程序和 snitch。seed 提供程序负责发布集群中节点的 IP 地址（seeds）列表。每个启动的节点都连接到 seeds（通常至少有三个），如果成功到达其中一个，它们立即交换有关集群中所有节点的信息。随着节点之间的 gossip，这些信息会不断更新每个节点。

`Cassandra.yaml`中配置的默认 seed 提供程序只是一个静态的 IP 地址列表，在这种情况下只有环回接口：

```
seed_provider: 
    - class_name: SEED_PROVIDER 
      parameters: 
          # seeds is actually a comma-delimited list of addresses. 
          # Ex: "<ip1>,<ip2>,<ip3>" 
          - seeds: "127.0.0.1"  
```

另一个重要的设置是 snitch。它有两个角色：

+   它教会 Cassandra 足够了解您的网络拓扑以有效地路由请求。

+   它允许 Cassandra 在集群中分散副本以避免相关故障。它通过将机器分组到数据中心和机架来实现这一点。Cassandra 会尽量避免在同一机架上拥有多个副本（这实际上可能不是一个物理位置）。

Cassandra 预装了几个 snitch 类，但它们都不了解 Kubernetes。默认是`SimpleSnitch`，但可以被覆盖。

```
# You can use a custom Snitch by setting this to the full class  
# name of the snitch, which will be assumed to be on your classpath. 
endpoint_snitch: SimpleSnitch 
```

# 自定义 seed 提供程序

在 Kubernetes 中将 Cassandra 节点作为 pod 运行时，Kubernetes 可能会移动 pod，包括 seeds。为了适应这一点，Cassandra seed 提供程序需要与 Kubernetes API 服务器进行交互。

这是自定义的`KubernetesSeedProvider` Java 类的一个简短片段，它实现了 Cassandra 的`SeedProvider` API：

```
public class KubernetesSeedProvider implements SeedProvider { 
   ... 
    /** 
     * Call kubernetes API to collect a list of seed providers 
     * @return list of seed providers 
     */ 
    public List<InetAddress> getSeeds() { 
        String host = getEnvOrDefault("KUBERNETES_PORT_443_TCP_ADDR", "kubernetes.default.svc.cluster.local"); 
        String port = getEnvOrDefault("KUBERNETES_PORT_443_TCP_PORT", "443"); 
        String serviceName = getEnvOrDefault("CASSANDRA_SERVICE", "cassandra"); 
        String podNamespace = getEnvOrDefault("POD_NAMESPACE", "default"); 
        String path = String.format("/api/v1/namespaces/%s/endpoints/", podNamespace); 
        String seedSizeVar = getEnvOrDefault("CASSANDRA_SERVICE_NUM_SEEDS", "8"); 
        Integer seedSize = Integer.valueOf(seedSizeVar); 
        String accountToken = getEnvOrDefault("K8S_ACCOUNT_TOKEN", "/var/run/secrets/kubernetes.io/serviceaccount/token"); 

        List<InetAddress> seeds = new ArrayList<InetAddress>(); 
        try { 
            String token = getServiceAccountToken(accountToken); 

            SSLContext ctx = SSLContext.getInstance("SSL"); 
            ctx.init(null, trustAll, new SecureRandom()); 

            String PROTO = "https://"; 
            URL url = new URL(PROTO + host + ":" + port + path + serviceName); 
            logger.info("Getting endpoints from " + url); 
            HttpsURLConnection conn = (HttpsURLConnection)url.openConnection(); 

            conn.setSSLSocketFactory(ctx.getSocketFactory()); 
            conn.addRequestProperty("Authorization", "Bearer " + token); 
            ObjectMapper mapper = new ObjectMapper(); 
            Endpoints endpoints = mapper.readValue(conn.getInputStream(), Endpoints.class);    }    
            ... 
        } 
        ... 

    return Collections.unmodifiableList(seeds);    
} 
```

# 创建一个 Cassandra 无头服务

无头服务的作用是允许 Kubernetes 集群中的客户端通过标准的 Kubernetes 服务连接到 Cassandra 集群，而不是跟踪节点的网络标识或在所有节点前面放置专用的负载均衡器。Kubernetes 通过其服务提供了所有这些功能。

这是配置文件：

```
apiVersion: v1 
kind: Service 
metadata: 
  labels: 
    app: cassandra 
  name: cassandra 
spec: 
  clusterIP: None 
  ports: 
    - port: 9042 
  selector: 
    app: Cassandra 
```

`app: Cassandra`标签将把所有参与服务的 pod 分组。Kubernetes 将创建端点记录，DNS 将返回一个用于发现的记录。`clusterIP`是`None`，这意味着服务是无头的，Kubernetes 不会进行任何负载平衡或代理。这很重要，因为 Cassandra 节点直接进行通信。

`9042`端口被 Cassandra 用于提供 CQL 请求。这些可以是查询、插入/更新（Cassandra 总是使用 upsert），或者删除。

# 使用 StatefulSet 创建 Cassandra 集群

声明 StatefulSet 并不是一件简单的事情。可以说它是最复杂的 Kubernetes 资源。它有很多组成部分：标准元数据，StatefulSet 规范，Pod 模板（通常本身就相当复杂），以及卷索赔模板。

# 解析 StatefulSet 配置文件

让我们按部就班地查看声明一个三节点 Cassandra 集群的示例 StatefulSet 配置文件。

这是基本的元数据。请注意，`apiVersion`字符串是`apps/v1`（StatefulSet 从 Kubernetes 1.9 开始普遍可用）：

```
apiVersion: "apps/v1" 
kind: StatefulSet 
metadata: 
  name: cassandra 
```

StatefulSet 的`spec`定义了无头服务的名称，StatefulSet 中有多少个 pod，以及 pod 模板（稍后解释）。`replicas`字段指定了 StatefulSet 中有多少个 pod：

```
spec: 
  serviceName: cassandra 
  replicas: 3  
  template: ... 
```

对于 pod 来说，术语`replicas`是一个不幸的选择，因为这些 pod 并不是彼此的副本。它们共享相同的 pod 模板，但它们有独特的身份，它们负责一般状态的不同子集。在 Cassandra 的情况下，这更加令人困惑，因为它使用相同的术语`replicas`来指代冗余复制一些状态的节点组（但它们并不相同，因为每个节点也可以管理额外的状态）。我向 Kubernetes 项目提出了一个 GitHub 问题，要求将术语从`replicas`更改为`members`：

[`github.com/kubernetes/kubernetes.github.io/issues/2103`](https://github.com/kubernetes/kubernetes.github.io/issues/2103)

Pod 模板包含一个基于自定义 Cassandra 镜像的单个容器。以下是带有`app: cassandra`标签的 Pod 模板：

```
template: 
  metadata: 
    labels: 
      app: cassandra 
  spec: 
    containers: ...   
```

容器规范有多个重要部分。它以`name`和我们之前查看的`image`开始：

```
containers: 
   - name: cassandra 
      image: gcr.io/google-samples/cassandra:v12 
      imagePullPolicy: Always 
```

然后，它定义了 Cassandra 节点需要的多个容器端口，用于外部和内部通信：

```
ports: 
- containerPort: 7000 
  name: intra-node 
- containerPort: 7001 
  name: tls-intra-node 
- containerPort: 7199 
  name: jmx 
- containerPort: 9042 
  name: cql 
```

资源部分指定容器所需的 CPU 和内存。这很关键，因为存储管理层不应因`cpu`或`memory`而成为性能瓶颈。

```
resources: 
  limits: 
    cpu: "500m" 
    memory: 1Gi 
  requests: 
    cpu: "500m" 
    memory: 1Gi 
```

Cassandra 需要访问`IPC`，容器通过安全内容的功能请求它：

```
securityContext: 
capabilities: 
  add: 
       - IPC_LOCK 
```

`env`部分指定容器内可用的环境变量。以下是必要变量的部分列表。`CASSANDRA_SEEDS`变量设置为无头服务，因此 Cassandra 节点可以在启动时与 seeds 通信并发现整个集群。请注意，在此配置中，我们不使用特殊的 Kubernetes 种子提供程序。`POD_IP`很有趣，因为它利用向`status.podIP`的字段引用通过 Downward API 填充其值：

```
 env: 
   - name: MAX_HEAP_SIZE 
     value: 512M 
   - name: CASSANDRA_SEEDS 
     value: "cassandra-0.cassandra.default.svc.cluster.local" 
  - name: POD_IP 
    valueFrom: 
      fieldRef: 
        fieldPath: status.podIP 
```

容器还有一个就绪探针，以确保 Cassandra 节点在完全在线之前不会收到请求：

```
readinessProbe: 
  exec: 
    command: 
    - /bin/bash 
    - -c 
    - /ready-probe.sh 
  initialDelaySeconds: 15 
  timeoutSeconds: 5 
```

当然，Cassandra 需要读写数据。`cassandra-data`卷挂载就是这样的：

```
volumeMounts: 
- name: cassandra-data 
  mountPath: /cassandra_data 
```

容器规范就是这样。最后一部分是卷索赔模板。在这种情况下，使用了动态配置。强烈建议为 Cassandra 存储使用 SSD 驱动器，特别是其日志。在这个例子中，请求的存储空间是`1 Gi`。通过实验，我发现单个 Cassandra 节点的理想存储空间是 1-2 TB。原因是 Cassandra 在后台进行大量的数据重排、压缩和数据再平衡。如果一个节点离开集群或一个新节点加入集群，你必须等到数据被正确再平衡，然后才能重新分布来自离开节点的数据或者填充新节点。请注意，Cassandra 需要大量的磁盘空间来进行所有这些操作。建议保留 50%的空闲磁盘空间。当考虑到你还需要复制（通常是 3 倍）时，所需的存储空间可能是你的数据大小的 6 倍。如果你愿意冒险，也许根据你的用例，你可以用 30%的空闲空间，甚至只使用 2 倍的复制。但是，即使是在单个节点上，也不要低于 10%的空闲磁盘空间。我以艰难的方式得知，Cassandra 会简单地卡住，无法在没有极端措施的情况下进行压缩和再平衡这样的节点。

访问模式当然是`ReadWriteOnce`：

```
volumeClaimTemplates: 
- metadata: 
  name: cassandra-data 
  annotations: 
    volume.beta.kubernetes.io/storage-class: fast 
spec: 
  accessModes: [ "ReadWriteOnce" ] 
  resources: 
    requests: 
      storage: 1Gi 
```

在部署有状态集时，Kubernetes 根据索引号按顺序创建 pod。当扩展或缩减规模时，也是按顺序进行的。对于 Cassandra 来说，这并不重要，因为它可以处理节点以任何顺序加入或离开集群。当销毁一个 Cassandra pod 时，持久卷仍然存在。如果以后创建了具有相同索引的 pod，原始的持久卷将被挂载到其中。这种稳定的连接使得 Cassandra 能够正确管理状态。

# 使用复制控制器来分发 Cassandra

StatefulSet 非常好，但是如前所述，Cassandra 已经是一个复杂的分布式数据库。它有很多机制可以自动分发、平衡和复制集群中的数据。这些机制并不是为了与网络持久存储一起工作而进行优化的。Cassandra 被设计为与直接存储在节点上的数据一起工作。当一个节点死机时，Cassandra 可以通过在其他节点上存储冗余数据来进行恢复。让我们来看看在 Kubernetes 集群上部署 Cassandra 的另一种方式，这种方式更符合 Cassandra 的语义。这种方法的另一个好处是，如果您已经有一个现有的 Kubernetes 集群，您不必将其升级到最新版本，只是为了使用一个有状态的集。

我们仍将使用无头服务，但是我们将使用常规的复制控制器，而不是有状态集。有一些重要的区别：

+   复制控制器而不是有状态集

+   节点上安排运行的 pod 的存储

+   使用了自定义的 Kubernetes 种子提供程序类

# 解剖复制控制器配置文件

元数据非常简单，只有一个名称（标签不是必需的）：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
  name: cassandra 
  # The labels will be applied automatically 
  # from the labels in the pod template, if not set 
  # labels: 
    # app: Cassandra 
```

`spec`指定了`replicas`的数量：

```
spec: 
  replicas: 3 
  # The selector will be applied automatically 
  # from the labels in the pod template, if not set. 
  # selector: 
      # app: Cassandra 
```

pod 模板的元数据是指定`app: Cassandra`标签的地方。复制控制器将跟踪并确保具有该标签的 pod 恰好有三个：

```
template: 
    metadata: 
      labels: 
        app: Cassandra 
```

pod 模板的`spec`描述了容器的列表。在这种情况下，只有一个容器。它使用相同的名为`cassandra`的 Cassandra Docker 镜像，并运行`run.sh`脚本：

```
spec: 
  containers: 
    - command: 
        - /run.sh 
      image: gcr.io/google-samples/cassandra:v11 
      name: cassandra 
```

在这个例子中，资源部分只需要`0.5`个 CPU 单位：

```
 resources: 
            limits: 
              cpu: 0.5 
```

环境部分有点不同。`CASSANDRA_SEED_PROVDIER`指定了我们之前检查过的自定义 Kubernetes 种子提供程序类。这里的另一个新添加是`POD_NAMESPACE`，它再次使用 Downward API 从元数据中获取值：

```
 env: 
    - name: MAX_HEAP_SIZE 
      value: 512M 
    - name: HEAP_NEWSIZE 
      value: 100M 
    - name: CASSANDRA_SEED_PROVIDER 
      value: "io.k8s.cassandra.KubernetesSeedProvider" 
    - name: POD_NAMESPACE 
      valueFrom: 
         fieldRef: 
           fieldPath: metadata.namespace 
    - name: POD_IP 
      valueFrom: 
         fieldRef: 
           fieldPath: status.podIP 
```

`ports`部分是相同的，暴露节点内通信端口（`7000`和`7001`），`7199` JMX 端口用于外部工具（如 Cassandra OpsCenter）与 Cassandra 集群通信，当然还有`9042` CQL 端口，通过它客户端与集群通信：

```
 ports: 
    - containerPort: 7000 
      name: intra-node 
    - containerPort: 7001 
      name: tls-intra-node 
    - containerPort: 7199 
      name: jmx 
    - containerPort: 9042 
      name: cql 
```

一次又一次，卷被挂载到`/cassandra_data`中。这很重要，因为同样配置正确的 Cassandra 镜像只期望其`data`目录位于特定路径。Cassandra 不关心后备存储（尽管作为集群管理员，你应该关心）。Cassandra 只会使用文件系统调用进行读写。

```
volumeMounts: 
  - mountPath: /cassandra_data 
    name: data 
```

卷部分是与有状态集解决方案最大的不同之处。有状态集使用持久存储索赔将特定的 pod 与特定的持久卷连接起来，以便具有稳定身份。复制控制器解决方案只是在托管节点上使用`emptyDir`。

```
volumes: 
  - name: data 
    emptyDir: {} 
```

这有许多影响。你必须为每个节点提供足够的存储空间。如果 Cassandra pod 死掉，它的存储空间也会消失。即使 pod 在同一台物理（或虚拟）机器上重新启动，磁盘上的数据也会丢失，因为`emptyDir`一旦其 pod 被删除就会被删除。请注意，容器重新启动是可以的，因为`emptyDir`可以在容器崩溃时幸存下来。那么，当 pod 死掉时会发生什么呢？复制控制器将启动一个带有空数据的新 pod。Cassandra 将检测到集群中添加了一个新节点，为其分配一些数据，并通过从其他节点移动数据来自动开始重新平衡。这就是 Cassandra 的亮点所在。它不断地压缩、重新平衡和均匀地分布数据到整个集群中。它会自动弄清楚该为你做什么。

# 为节点分配 pod

复制控制器方法的主要问题是多个 pod 可以被调度到同一 Kubernetes 节点上。如果你的复制因子是三，负责某个键空间范围的所有三个 pod 都被调度到同一个 Kubernetes 节点上会怎么样？首先，所有对该键范围的读取或写入请求都将发送到同一个节点，增加了更多的压力。但更糟糕的是，我们刚刚失去了冗余性。我们有一个**单点故障**（**SPOF**）。如果该节点死掉，复制控制器将愉快地在其他 Kubernetes 节点上启动三个新的 pod，但它们都不会有数据，而且集群中的其他 Cassandra 节点（其他 pod）也没有数据可供复制。

这可以通过使用 Kubernetes 调度概念中的反亲和性来解决。在将 pod 分配给节点时，可以对 pod 进行注释，以便调度程序不会将其调度到已经具有特定标签集的节点上。将此添加到 pod 的`spec`中，以确保最多只有一个 Cassandra pod 被分配给一个节点：

```
spec: 
  affinity: 
    podAntiAffinity: 
      requiredDuringSchedulingIgnoredDuringExecution: 
      - labelSelector: 
          matchExpressions: 
          - key: app 
            operator: In 
            values: 
            - cassandra 
          topologyKey: kubernetes.io/hostname 
```

# 使用 DaemonSet 来分发 Cassandra

解决将 Cassandra pod 分配给不同节点的问题的更好方法是使用 DaemonSet。DaemonSet 具有类似于复制控制器的 pod 模板。但是 DaemonSet 有一个节点选择器，用于确定在哪些节点上调度其 pod。它没有特定数量的副本，它只是在与其选择器匹配的每个节点上调度一个 pod。最简单的情况是在 Kubernetes 集群中的每个节点上调度一个 pod。但是节点选择器也可以使用标签的匹配表达式来部署到特定的节点子集。让我们为在 Kubernetes 集群上部署我们的 Cassandra 集群创建一个 DaemonSet：

```
apiVersion: apps/v1 
kind: DaemonSet 
metadata: 
  name: cassandra-daemonset 
```

DaemonSet 的`spec`包含一个常规的 pod 模板。`nodeSelector`部分是魔术发生的地方，它确保每个带有`app: Cassandra`标签的节点上始终会被调度一个且仅有一个 pod：

```
spec: 
  template: 
    metadata: 
      labels: 
        app: cassandra 
    spec: 
      # Filter only nodes with the label "app: cassandra": 
      nodeSelector: 
        app: cassandra 
      containers: 
```

其余部分与复制控制器相同。请注意，预计`nodeSelector`将被弃用，而亲和性将被取代。这将在何时发生，目前尚不清楚。

# 总结

在本章中，我们涵盖了有关有状态应用程序以及如何将其与 Kubernetes 集成的主题。我们发现有状态应用程序很复杂，并考虑了几种发现机制，例如 DNS 和环境变量。我们还讨论了几种状态管理解决方案，例如内存冗余存储和持久存储。本章的大部分内容围绕在 Kubernetes 集群内部部署 Cassandra 集群，使用了几种选项，例如有状态集、复制控制器和 DaemonSet。每种方法都有其优缺点。在这一点上，您应该对有状态应用程序有深入的了解，以及如何在基于 Kubernetes 的系统中应用它们。您已经掌握了多种用例的多种方法，也许甚至学到了一些关于 Cassandra 的知识。

在下一章中，我们将继续我们的旅程，探讨可扩展性的重要主题，特别是自动扩展性，以及在集群动态增长时如何部署和进行实时升级和更新。这些问题非常复杂，特别是当集群上运行有状态应用程序时。
