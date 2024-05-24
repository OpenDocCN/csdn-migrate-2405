# Kubernetes DevOps 完全秘籍（四）

> 原文：[`zh.annas-archive.org/md5/2D2322071D8188F9AA9E93F3DAEEBABE`](https://zh.annas-archive.org/md5/2D2322071D8188F9AA9E93F3DAEEBABE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：灾难恢复和备份

在本章中，我们将专注于备份和灾难恢复方案，以保持生产中的应用程序高度可用，并允许它们在云提供商或基本 Kubernetes 节点故障期间快速恢复服务。在本章中遵循配方后，您将掌握用于**灾难恢复**（**DR**）的工具，并能够在集群和云之间实时迁移应用程序。

本章中，我们将涵盖以下配方：

+   使用 MinIO 配置和管理 S3 对象存储

+   管理 Kubernetes 卷快照和恢复

+   使用 Velero 进行应用程序备份和恢复

+   使用 Kasten 进行应用程序备份和恢复

+   跨云应用程序迁移

# 技术要求

本章的配方假定您已通过第一章中描述的推荐方法之一部署了功能性 Kubernetes 集群，*构建生产就绪的 Kubernetes 集群*。

Kubernetes 操作工具`kubectl`将在本章的其余配方中使用，因为它是针对 Kubernetes 集群运行命令的主要命令行界面。如果您正在使用 Red Hat OpenShift 集群，可以用`oc`替换`kubectl`。所有命令都预计以类似的方式运行。

# 使用 MinIO 配置和管理 S3 对象存储

在本节中，我们将使用 MinIO 创建 S3 对象存储，以存储 Kubernetes 中您的应用程序创建的工件或配置文件。您将学习如何创建部署清单文件，部署 S3 服务，并为其他应用程序或用户提供外部 IP 地址以使用该服务。

## 准备工作

将`k8sdevopscookbook/src`存储库克隆到您的工作站，以便在`chapter6`目录下使用清单文件，如下所示：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd src/chapter6
```

确保您已准备好一个 Kubernetes 集群，并配置了`kubectl`，以便您可以管理集群资源。

## 如何做…

本节进一步分为以下子节，以使此过程更容易：

+   创建部署 YAML 清单

+   创建 MinIO S3 服务

+   访问 MinIO Web 用户界面

### 创建部署 YAML 清单

所有 Kubernetes 资源都是通过使用 YAML 清单文件以声明方式创建的。让我们执行以下步骤来创建一个示例文件，稍后我们将在 Kubernetes 中部署应用程序时使用它：

1.  对于这个配方，我们将使用 MinIO 创建一些资源，以便我们可以了解文件格式，并在以后帮助我们部署完全功能的应用程序。通过访问[`min.io/download#/kubernetes`](https://min.io/download#/kubernetes)打开 MinIO 下载网站。

1.  在 MinIO 网站上，从可用下载选项列表中，单击 Kubernetes 按钮，然后选择 Kubernetes CLI 选项卡。此页面将帮助我们根据我们的偏好生成 MinIO 应用程序所需的 YAML 内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/f6c098f2-e477-4d54-9dcb-c06d82636bbe.png)

1.  输入您的访问密钥和秘密密钥对。在我们的示例中，我们使用了`minio`/`minio123`。当您访问 MinIO 服务时，这将代替用户名和密码。选择分布式作为部署模型，并输入`4`作为节点数。此选项将创建一个具有四个副本的 StatefulSet。输入`10`GB 作为大小。在我们的示例中，我们将使用以下配置屏幕上显示的值：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/ac4ca547-45a4-49e1-8abb-850c0d5f480c.png)

1.  单击“生成”按钮并检查文件内容。您将注意到存储在 YAML 清单中的三种不同资源，包括服务、StatefulSet 和第二个服务，它将创建一个云负载均衡器来将第一个服务端口暴露给外部访问。

1.  复制内容，并将其保存为`minio.yaml`在您的工作站上。

### 创建 MinIO S3 服务

让我们执行以下步骤来创建必要的资源，以使用 MinIO 获得功能齐全的 S3 服务：

1.  使用您在*创建部署 YAML 清单*配方中创建的 YAML 清单部署 MinIO：

```
$ kubectl apply -f minio.yaml
```

作为替代方法，您可以使用示例存储库中`/src/chapter6/minio`目录下保存的示例 YAML 文件，使用`$ kubectl apply -f minio/minio.yaml`命令。

1.  验证 StatefulSet。您应该看到 4 个 4 个副本部署，类似于以下输出。请注意，如果您以独立方式部署，您将没有 StatefulSets：

```
$ kubectl get statefulsets
NAME  READY AGE
minio 4/4   2m17s
```

现在，您已经部署了一个 MinIO 应用程序。在下一个配方中，我们将学习如何发现其外部地址以访问该服务。

### 访问 MinIO Web 用户界面

作为部署过程的一部分，我们让 MinIO 创建一个云负载均衡器来将服务暴露给外部访问。在这个配方中，我们将学习如何访问 MinIO 界面，以上传和下载文件到 S3 后端。为此，我们将执行以下步骤：

1.  使用以下命令获取`minio-service` LoadBalancer 的外部 IP。您将在`EXTERNAL-IP`列下看到公开的服务地址，类似于以下输出：

```
$ kubectl get service
NAME          TYPE         CLUSTER-IP EXTERNAL-IP                     PORT(S)  AGE
minio         ClusterIP    None       <none>                          9000/TCP 2m49s
minio-service LoadBalancer 10.3.0.4   abc.us-west-2.elb.amazonaws.com 9000:30345/TCP 2m49s
```

1.  正如您所看到的，输出服务是通过端口`9000`公开的。要访问该服务，我们还需要将端口`9000`添加到地址的末尾（`http://[externalIP]:9000`），并在浏览器中打开 MinIO 服务的公共地址。

1.  您需要有权限访问仪表板。使用我们之前创建的默认用户名`minio`和默认密码`minio123`登录到 Minio 部署。登录后，您将能够访问 MinIO 浏览器，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/b5a51dc2-c1e4-4258-9fce-11333ec2342f.png)

MinIO 与亚马逊 S3 云存储服务兼容，最适合存储照片、日志文件和备份等非结构化数据。现在您可以访问 MinIO 用户界面，创建 buckets，上传文件，并通过 S3 API 访问它们，类似于访问标准的亚马逊 S3 服务来存储您的备份。您可以通过转到*另请参阅*部分中的*MinIO 文档*链接来了解更多关于 MinIO 的信息。

## 工作原理...

这个配方向您展示了如何在 Kubernetes 上部署 MinIO 来提供完全兼容 Amazon S3 API 的服务。此服务将在以后用于灾难恢复和备份在 Kubernetes 上运行的应用程序。

在*创建 MinIO S3 服务*配方中，在*步骤 1*中，当我们部署 MinIO 时，它会在端口`9000`创建一个 LoadBalancer 服务。由于我们将节点数设置为`4`，将创建一个具有四个副本的 StatefulSet。每个副本将使用`volumeClaimTemplates`部分设置的信息来创建 PVC。如果未明确定义`storageClassName`，则将使用默认存储类。结果，您将在集群上看到创建了四个**PersistentVolumesClaim**（PVC）实例，以提供高可用的 MinIO 服务。

## 另请参阅

+   MinIO 文档网址：[`docs.min.io/docs/minio-quickstart-guide.html`](https://docs.min.io/docs/minio-quickstart-guide.html)

+   Kubernetes 的 MinIO Operator 网址：[`github.com/minio/minio-operator`](https://github.com/minio/minio-operator)

+   MinIO Erasure Code QuickStart Guide 网址：[`docs.min.io/docs/minio-erasure-code-quickstart-guide`](https://docs.min.io/docs/minio-erasure-code-quickstart-guide)

+   使用 MinIO 客户端，网址：[`docs.min.io/docs/minio-client-quickstart-guide`](https://docs.min.io/docs/minio-client-quickstart-guide)

# 管理 Kubernetes 卷快照和恢复

在本节中，我们将在 Kubernetes 中从我们的持久卷创建卷快照。通过按照这个步骤，您将学习如何启用卷快照功能，创建快照存储类，并从现有的卷快照中恢复。

## 准备工作

确保您有一个准备好的 Kubernetes 集群，并配置`kubectl`来管理集群资源。

将`k8sdevopscookbook/src`存储库克隆到您的工作站，以便使用`chapter6`目录下的清单文件，如下所示：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd src/chapter6
```

确保您首选存储供应商的**容器存储接口**（**CSI**）驱动程序已安装在您的 Kubernetes 集群上，并且已实现了快照功能。我们在第五章中介绍了 AWS EBS、GCP PD、Azure Disk、Rook 和 OpenEBS CSI 驱动程序的安装，*为有状态的工作负载做准备*。

本节中的说明与其他支持通过 CSI 进行快照的供应商类似。您可以在 Kubernetes CSI 文档网站上找到这些额外的驱动程序：[`kubernetes-csi.github.io/docs/drivers.html`](https://kubernetes-csi.github.io/docs/drivers.html)。

## 如何做…

本节进一步分为以下子节，以使这个过程更容易：

+   启用功能门

+   通过 CSI 创建卷快照

+   通过 CSI 从快照还原卷

+   通过 CSI 克隆卷

### 启用功能门

这里将讨论的一些功能目前可能处于不同的阶段（alpha、beta 或 GA）。如果遇到问题，请执行以下步骤：

1.  为`kube-apiserver`和`kubelet`设置以下`feature-gates`标志为`true`：

```
- --feature-gates=VolumeSnapshotDataSource=true
- --feature-gates=KubeletPluginsWatcher=true
- --feature-gates=CSINodeInfo=true
- --feature-gates=CSIDriverRegistry=true
- --feature-gates=BlockVolume=true
- --feature-gates=CSIBlockVolume=true
```

您可以通过转到*参见*部分中的*Kubernetes 功能门*链接，找到功能及其状态的最新状态。

### 通过 CSI 创建卷快照

卷快照是从 Kubernetes 集群中的 PVC 中获取的状态的副本。它是一个有用的资源，可以使用现有数据启动有状态的应用程序。让我们按照以下步骤使用 CSI 创建卷快照：

1.  创建 PVC 或选择现有的 PVC。在我们的食谱中，我们将使用 AWS EBS CSI 驱动程序和我们在第五章中创建的`aws-csi-ebs`存储类，*为有状态的工作负载做准备*，在*安装 EBS CSI 驱动程序来管理 EBS 卷*食谱中：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
 name: csi-ebs-pvc
spec:
 accessModes:
 - ReadWriteOnce
 storageClassName: aws-csi-ebs
 resources:
 requests:
 storage: 4Gi
EOF
```

1.  创建一个 pod，它将写入**PersistentVolume**（**PV**）内的`/data/out.txt`文件：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
 name: app
spec:
 containers:
 - name: app
 image: centos
 command: ["/bin/sh"]
 args: ["-c", "while true; do echo $(date -u) >> /data/out.txt; sleep 5; done"]
 volumeMounts:
 - name: persistent-storage
 mountPath: /data
 volumes:
 - name: persistent-storage
 persistentVolumeClaim:
 claimName: csi-ebs-pvc
EOF
```

1.  创建`VolumeSnapshotClass`。确保快照提供程序设置为您的 CSI 驱动程序名称。在这个食谱中，这是`ebs.csi.aws.com`：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: snapshot.storage.k8s.io/v1alpha1
kind: VolumeSnapshotClass
metadata:
 name: csi-ebs-vsc
snapshotter: ebs.csi.aws.com
EOF
```

1.  必须使用存储供应商的 CSI 驱动程序创建 PVC。在我们的食谱中，我们将使用我们在*安装 EBS CSI 驱动程序来管理 EBS 卷*食谱中创建的 PVC。现在，使用我们在*步骤 1*中设置的 PVC 名称（`csi-ebs-pvc`）创建`VolumeSnapshot`：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: snapshot.storage.k8s.io/v1alpha1
kind: VolumeSnapshot
metadata:
 name: ebs-volume-snapshot
spec:
 snapshotClassName: csi-ebs-vsc
 source:
 name: csi-ebs-pvc
 kind: PersistentVolumeClaim
EOF
```

1.  列出卷快照：

```
$ kubectl get volumesnapshot
NAME AGE
ebs-volume-snapshot 18s
```

1.  在检查以下命令的输出时，验证状态是否为`Ready To Use: true`：

```
$ kubectl describe volumesnapshot ebs-volume-snapshot
```

### 通过 CSI 从快照还原卷

我们可以创建快照以尝试还原其他快照。让我们执行以下步骤来还原我们在上一个食谱中创建的快照：

1.  使用以下命令从快照中还原卷，并使用 PVC。如您所见，将基于`ebs-volume-snapshot`快照创建一个名为`csi-ebs-pvc-restored`的新 PVC：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
 name: csi-ebs-pvc-restored
spec:
 accessModes:
 - ReadWriteOnce
 storageClassName: aws-csi-ebs
 resources:
 requests:
 storage: 4Gi
 dataSource:
 name: ebs-volume-snapshot
 kind: VolumeSnapshot
 apiGroup: snapshot.storage.k8s.io
EOF
```

1.  创建另一个 pod，它将继续写入 PV 内的`/data/out.txt`文件。此步骤将确保卷在创建后仍然可以访问：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
 name: newapp
spec:
 containers:
 - name: app
 image: centos
 command: ["/bin/sh"]
 args: ["-c", "while true; do echo $(date -u) >> /data/out.txt; sleep 5; done"]
 volumeMounts:
 - name: persistent-storage
 mountPath: /data
 volumes:
 - name: persistent-storage
 persistentVolumeClaim:
 claimName: csi-ebs-pvc-restored
EOF
```

1.  确认`newapp` pod 包含恢复的数据和*创建卷快照*食谱中的时间戳：

```
$ kubectl exec -it newapp cat /data/out.txt
```

通过这个，您已经学会了如何从现有快照中提供持久卷。这是 CI/CD 流水线中非常有用的一步，这样您就可以节省时间来排查失败的流水线。

### 通过 CSI 克隆卷

虽然快照是 PV 的某个状态的副本，但这并不是创建数据副本的唯一方法。CSI 还允许从现有卷创建新卷。在这个食谱中，我们将执行以下步骤，使用现有 PVC 创建一个 PVC：

1.  获取 PVC 列表。您可能有多个 PVC。在这个例子中，我们将使用我们在*创建卷快照*食谱中创建的 PVC。只要已经使用支持`VolumePVCDataSource` API 的 CSI 驱动程序创建了另一个 PVC，您就可以使用另一个 PVC：

```
$ kubectl get pvc
NAME STATUS VOLUME CAPACITY ACCESS MODES STORAGECLASS AGE
csi-ebs-pvc Bound pvc-574ed379-71e1-4548-b736-7137ab9cfd9d 4Gi RWO aws-csi-ebs 23h
```

1.  使用现有的 PVC（在本示例中为`csi-ebs-pvc`）作为`dataSource`创建 PVC。数据源可以是`VolumeSnapshot`或 PVC。在本例中，我们使用`PersistentVolumeClaim`来克隆数据：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
 name: clone-of-csi-ebs-pvc
spec:
 accessModes:
 - ReadWriteOnce
 resources:
 requests:
 storage: 4Gi
 dataSource:
 kind: PersistentVolumeClaim
 name: csi-ebs-pvc
EOF
```

通过这个，您已经学会了从现有数据源克隆持久数据的简单方法。

## 工作原理...

本示例向您展示了如何创建快照，从快照中恢复数据，以及如何在 Kubernetes 上立即克隆持久卷。

在*通过 CSI 从快照还原卷*和*通过 CSI 克隆卷*的示例中，我们向 PVC 添加了`dataSource`，引用了现有的 PVC，以便创建一个完全独立的新 PVC。生成的 PVC 可以独立附加、克隆、快照或删除，即使源被删除。主要区别在于，在为 PVC 进行供应之后，后端设备会提供指定卷的精确副本，而不是空 PV。

重要的是要注意，对于已经实现了这一功能的 CSI 驱动程序，动态供应商可以使用本地克隆支持。CSI 项目正在不断发展和成熟，因此并非每个存储供应商都提供完整的 CSI 功能。

## 另请参阅

+   Kubernetes CSI 驱动程序列表，请参见[`kubernetes-csi.github.io/docs/drivers.html`](https://kubernetes-csi.github.io/docs/drivers.html)

+   **容器存储接口**（**CSI**）文档，请参见[`kubernetes-csi.github.io`](https://kubernetes-csi.github.io)

+   CSI 规范，请参见[`github.com/container-storage-interface/spec`](https://github.com/container-storage-interface/spec)

+   Kubernetes 功能门，参见[`kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/`](https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/)

+   Kubernetes 卷克隆文档，请参见[`kubernetes.io/docs/concepts/storage/volume-pvc-datasource/`](https://kubernetes.io/docs/concepts/storage/volume-pvc-datasource/)

+   Kubernetes 卷快照文档，请参见[`kubernetes.io/docs/concepts/storage/volume-snapshots/`](https://kubernetes.io/docs/concepts/storage/volume-snapshots/)

# 使用 Velero 进行应用程序备份和恢复

在本节中，我们将使用 VMware Velero（前身为 Heptio Ark）在 Kubernetes 中创建灾难恢复备份，并迁移 Kubernetes 应用程序及其持久卷。

您将学习如何安装 Velero，创建标准和计划备份，并将它们恢复到 Kubernetes 集群中的 S3 目标。

## 准备工作

确保您有一个准备好的 Kubernetes 集群，并且`kubectl`配置为管理集群资源。

克隆`k8sdevopscookbook/src`存储库到您的工作站，以便在`chapter6`目录下使用清单文件，如下所示：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd src/chapter6
```

这个配方需要一个具有可呈现数据的现有有状态工作负载，以便我们可以模拟灾难，然后恢复数据。为此，我们将使用在第五章的*安装 EBS CSI 驱动程序来管理 EBS 卷*配方中创建的`mytestapp`应用程序，*为有状态的工作负载做准备*。

Velero 还需要 S3 兼容的对象存储来存储备份。在这个配方中，我们将使用在*使用 Minio 配置和管理 S3 对象存储*配方中部署的 MinIO S3 目标来存储我们的备份。

## 如何做…

这一部分进一步分为以下子部分，以使这个过程更容易：

+   安装 Velero

+   备份应用程序

+   恢复应用程序

+   创建计划备份

+   备份整个命名空间

+   使用 MinIO 查看备份

+   删除备份和计划

### 安装 Velero

Velero 是一个开源项目，用于备份、执行灾难恢复、恢复和迁移 Kubernetes 资源和持久卷。在这个配方中，我们将学习如何通过以下步骤在我们的 Kubernetes 集群中部署 Velero：

1.  下载 Velero 的最新版本：

```
$ wget https://github.com/vmware-tanzu/velero/releases/download/v1.1.0/velero-v1.1.0-linux-amd64.tar.gz
```

在撰写本书时，Velero 的最新版本是 v1.1.0。检查 Velero 存储库[`github.com/vmware-tanzu/velero/releases`](https://github.com/vmware-tanzu/velero/releases)，如果自本书发布以来已更改，请使用最新的下载链接更新链接。

1.  提取 tarball：

```
$ tar -xvzf velero-v1.1.0-linux-amd64.tar.gz
$ sudo mv velero-v1.1.0-linux-amd64/velero /usr/local/bin/ 
```

1.  确认`velero`命令可执行：

```
$ velero version
Client:
 Version: v1.1.0
 Git commit: a357f21aec6b39a8244dd23e469cc4519f1fe608
<error getting server version: the server could not find the requested resource (post serverstatusrequests.velero.io)>
```

1.  创建`credentials-velero`文件，其中包含您在*使用 Minio 配置和管理 S3 对象存储*配方中使用的访问密钥和秘钥：

```
$ cat > credentials-velero <<EOF
[default]
aws_access_key_id = minio
aws_secret_access_key = minio123
EOF
```

1.  使用 MinIO 服务的外部 IP 更新`s3Url`并安装 Velero 服务器：

```
$ velero install \
 --provider aws \
 --bucket velero \
 --secret-file ./credentials-velero \
 --use-restic \
 --backup-location-config region=minio,s3ForcePathStyle="true",s3Url=http://ac76d4a1ac72c496299b17573ac4cf2d-512600720.us-west-2.elb.amazonaws.com:9000
```

1.  确认部署成功：

```
$ kubectl get deployments -l component=velero --namespace=velero
NAME READY UP-TO-DATE AVAILABLE AGE
velero 1/1 1 1 62s
```

有了这个，Velero 已经在您的 Kubernetes 集群上使用 MinIO 作为备份目标进行配置。

### 备份应用程序

让我们执行以下步骤，使用 Velero 备份应用程序及其卷。我们在这里创建的所有 YAML 清单文件都可以在`/src/chapter6/velero`目录下找到：

1.  如果您已经为要备份的应用程序和卷打上标签，可以跳到*步骤 5*。否则，使用以下命令创建一个命名空间和一个 PVC：

```
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
 name: backup-example
 labels:
 app: app2backup
EOF
```

1.  在`backup-example`命名空间中使用您首选的`storageClass`创建一个 PVC。在我们的示例中，这是`aws-csi-ebs`：

```
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
 name: pvc2backup
 namespace: backup-example
 labels:
 app: app2backup
spec:
 accessModes:
 - ReadWriteOnce
 storageClassName: aws-csi-ebs
 resources:
 requests:
 storage: 4Gi
EOF
```

1.  在`src/chapter6/velero`目录中查看`myapp.yaml`文件，并使用它创建一个将使用 PVC 并写入`/data/out.txt`文件的 pod：

```
$ kubectl apply -f myapp.yaml
```

1.  验证我们的`myapp` pod 是否将数据写入卷：

```
$ kubectl exec -it myapp cat /data/out.txt -nbackup-example
Thu Sep 12 23:18:08 UTC 2019
```

1.  为所有具有`app=app2backup`标签的对象创建备份：

```
$ velero backup create myapp-backup --selector app=app2backup
```

1.  确认备份阶段已经完成：

```
$ velero backup describe myapp-backup
Name: myapp-backup
Namespace: velero
Labels: velero.io/storage-location=default
Annotations: <none>
Phase: Completed
...
```

1.  列出所有可用的备份：

```
$ velero backup get
NAME         STATUS    CREATED                       EXPIRES STORAGE LOCATION SELECTOR
myapp-backup Completed 2019-09-13 05:55:08 +0000 UTC 29d     default app=app2backup
```

通过这样，您已经学会了如何使用标签创建应用程序的备份。

### 恢复应用程序

让我们执行以下步骤来从备份中恢复应用程序：

1.  删除应用程序及其 PVC 以模拟数据丢失的情况：

```
$ kubectl delete pvc pvc2backup -nbackup-example
$ kubectl delete pod myapp -nbackup-example
```

1.  从名为`myapp-backup`的先前备份中恢复您的应用程序：

```
$ velero restore create --from-backup myapp-backup
```

1.  确认您的应用程序正在运行：

```
$ kubectl get pod -nbackup-example
NAME  READY STATUS  RESTARTS AGE
myapp 1/1   Running 0        10m
```

1.  确认我们的`myapp` pod 将数据写入卷：

```
$ kubectl exec -it myapp cat /data/out.txt -nbackup-example
```

通过这样，您已经学会了如何使用 Velero 从备份中恢复应用程序及其卷。

### 创建定期备份

Velero 支持 cron 表达式来安排备份任务。让我们执行以下步骤来为我们的应用程序安排备份：

1.  创建一个定期的每日备份：

```
$ velero schedule create myapp-daily --schedule="0 0 1 * * ?" --selector app=app2backup
```

如果您不熟悉 cron 表达式，可以使用*另请参阅*部分中的*Cron 表达式生成器*链接创建不同的计划。

请注意，前面的计划使用了 cron 表达式。作为替代，您可以使用简写表达式，如`--schedule="@daily"`，或者使用在线 cron 生成器创建 cron 表达式。

1.  获取当前已安排的备份作业列表：

```
$ velero schedule get
 NAME        STATUS  CREATED                       SCHEDULE    BACKUP TTL LAST BACKUP SELECTOR
 myapp-daily Enabled 2019-09-13 21:38:36 +0000 UTC 0 0 1 * * ? 720h0m0s   2m ago      app=app2backup
```

1.  确认已经通过定期备份作业创建了备份：

```
$ velero backup get
NAME                       STATUS    CREATED                       EXPIRES STORAGE LOCATION SELECTOR
myapp-daily-20190913205123 Completed 2019-09-13 20:51:24 +0000 UTC 29d     default app=app2backup
```

通过这样，您已经学会了如何使用 Velero 创建应用程序的定期备份。

### 备份整个命名空间

在进行备份时，您可以使用不同类型的选择器，甚至可以在所选命名空间中使用完整的资源。在本教程中，我们将通过以下步骤包括命名空间中的资源：

1.  使用以下命令对整个命名空间进行备份。此示例包括`backup-example`命名空间。如果需要，请替换此命名空间。在执行以下命令之前，命名空间和资源应该存在：

```
$ velero backup create fullnamespace --include-namespaces backup-example
```

1.  如果需要从备份中排除特定资源，请向它们添加`backup: "false"`标签，并运行以下命令：

```
$ velero backup create fullnamespace --selector 'backup notin (false)'
```

通过这个，你学会了如何使用 Velero 在给定命名空间中创建资源备份。

### 使用 MinIO 查看备份

让我们执行以下步骤来查看 MinIO 界面上备份的内容：

1.  按照*访问 MinIO Web 用户界面*食谱中的说明，访问 MinIO 浏览器。

1.  点击`velero`桶：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/efb51d77-7b1f-4a87-9833-cbf0d54a88a1.png)

1.  打开`backups`目录以查找 Velero 备份列表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/06f1ed3a-b4c3-4dba-b7dd-ce13aa9cfdad.png)

1.  点击备份名称以访问备份的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/69115a8e-713f-4681-8e96-cb338c9e438c.png)

通过这个，你学会了如何定位和查看 Velero 备份的内容。

### 删除备份和计划

如果没有正确维护，Velero 备份的大小会迅速增长。让我们执行以下步骤来删除现有的备份资源和清理定期备份：

1.  删除名为`myapp-backup`的现有备份：

```
$ velero backup delete myapp-backup
```

1.  删除所有现有备份：

```
$ velero backup delete --all
```

1.  删除名为`myapp-daily`的定期备份作业：

```
$ velero schedule delete myapp-daily
```

## 它是如何工作的...

这个食谱向你展示了如何创建灾难恢复备份，从 S3 目标还原你的应用程序及其数据，以及如何在 Kubernetes 上创建定期备份作业。

在*备份应用程序*食谱中，在*步骤 4*中，当你运行`velero backup create myapp-backup --selector app=app2backup`时，Velero 客户端会调用 Kubernetes API 服务器并创建一个备份对象。

你可以通过运行`kubectl get crds |grep velero`命令来获取 Velero 创建的**自定义资源定义**（**CRD**）列表。

Velero 的 BackupController 会监视新对象，一旦检测到，它会执行标准验证并处理备份。Velero 的 BackupController 通过向 API 服务器请求资源来收集备份信息。然后，它会调用默认存储提供程序并上传备份文件。

## 另请参阅

+   Velero 项目存储库位于[`github.com/vmware-tanzu/velero/`](https://github.com/vmware-tanzu/velero/)

+   Velero 文档，网址为[`velero.io/docs/master/index.html`](https://velero.io/docs/master/index.html)

+   Velero 支持矩阵，网址为[`velero.io/docs/master/supported-providers/`](https://velero.io/docs/master/supported-providers/)

+   Velero 播客和社区文章，网址为[`velero.io/resources/`](https://velero.io/resources/)

+   Cron 表达式生成器，网址为[`www.freeformatter.com/cron-expression-generator-quartz.html`](https://www.freeformatter.com/cron-expression-generator-quartz.html)

# **使用 Kasten 进行应用程序备份和恢复**

在本节中，我们将使用 Kasten（K10）创建灾难恢复备份，并在 Kubernetes 中迁移 Kubernetes 应用程序及其持久卷。

您将学习如何安装和使用 K10，创建标准和定期备份到 S3 目标的应用程序，并将它们恢复到 Kubernetes 集群中。

## 准备工作

确保您已准备好一个 Kubernetes 集群，并配置了`kubectl`和`helm`，以便您可以管理集群资源。在这个教程中，我们将在 AWS 上使用一个三节点的 Kubernetes 集群。

这个教程需要一个现有的有状态工作负载，具有可呈现的数据来模拟灾难。为了恢复数据，我们将使用在第五章的*安装 EBS CSI 驱动程序来管理 EBS 卷*教程中创建的`mytestapp`应用程序。

克隆`k8sdevopscookbook/src`存储库到您的工作站，以使用`chapter6`目录下的清单文件，如下所示：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd src/chapter6
```

K10 默认配备了 Starter Edition 许可证，允许您在最多三个工作节点的集群上免费使用该软件。K10 需要配置备份目标。

## 如何做…

这一部分进一步分为以下小节，以使这个过程更容易：

+   安装 Kasten

+   访问 Kasten 仪表板

+   备份应用程序

+   恢复应用程序

### 安装 Kasten

让我们执行以下步骤，在我们的 Kubernetes 集群中安装 Kasten 作为备份解决方案：

1.  添加 K10 helm 存储库：

```
$ helm repo add kasten https://charts.kasten.io/
```

1.  在开始之前，让我们验证环境。以下脚本将执行一些预安装测试，以验证您的集群：

```
$ curl https://docs.kasten.io/tools/k10_preflight.sh | bash
Checking for tools
 --> Found kubectl --> Found helm
Checking access to the Kubernetes context kubernetes-admin@net39dvo58
 --> Able to access the default Kubernetes namespace
Checking for required Kubernetes version (>= v1.10.0)
 --> Kubernetes version (v1.15.3) meets minimum requirements
Checking if Kubernetes RBAC is enabled
 --> Kubernetes RBAC is enabled
Checking if the Aggregated Layer is enabled
 --> The Kubernetes Aggregated Layer is enabled
Checking if the Kasten Helm repo is present
 --> The Kasten Helm repo was found
Checking for required Helm Tiller version (>= v2.11.0)
 --> Tiller version (v2.14.3) meets minimum requirements
All pre-flight checks succeeded!
```

1.  确保您的首选存储类设置为默认；否则，通过向以下命令添加`-set persistence.storageClass`参数来定义它。在我们的示例中，我们正在使用`openebs-cstor-default`存储类。还要添加您的 AWS 访问密钥和秘钥并安装 K10：

```
$ helm install kasten/k10 --name=k10 --namespace=kasten-io \
 --set persistence.storageClass=openebs-cstor-default \
 --set persistence.size=20Gi \
 --set secrets.awsAccessKeyId="AWS_ACCESS_KEY_ID" \
 --set secrets.awsSecretAccessKey="AWS_SECRET_ACCESS_KEY"
```

1.  使用以下`helm`命令确认部署状态为`DEPLOYED`：

```
$ helm ls
NAME REVISION UPDATED                  STATUS   CHART      APP    VERSION NAMESPACE
k10  1        Tue Oct 29 07:36:19 2019 DEPLOYED k10-1.1.56 1.1.56         kasten-io
```

在此步骤后，所有的 pod 应该在大约一分钟内部署完成，因为 Kasten 基于 Kubernetes CRDs 提供了一个 API。您可以使用带有新 CRDs 的`kubectl`（参考*相关链接*部分中的*Kasten CLI 命令*链接），或者按照下一个步骤，即*访问 Kasten 仪表板*的步骤，使用 Kasten 仪表板。

### 访问 Kasten 仪表板

让我们执行以下步骤来访问 Kasten 仪表板。这是我们将进行应用程序备份和恢复的地方：

1.  使用以下命令创建端口转发。这一步将 Kasten 仪表板服务的端口`8000`转发到本地工作站的端口`8080`：

```
$ export KASTENDASH_POD=$(kubectl get pods --namespace kasten-io -l "service=gateway" -o jsonpath="{.items[0].metadata.name}")
$ kubectl port-forward --namespace kasten-io $KASTENDASH_POD 8080:8000 >> /dev/null &
```

1.  在您的工作站上，使用浏览器打开`http://127.0.0.1:8080/k10/#`：

```
$ firefox http://127.0.0.1:8080/k10/#
```

1.  阅读并接受最终用户许可协议：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/d9d57128-8bd7-4866-b89c-783f526ba6e0.png)

通过这样，您已经访问了 Kasten 仪表板。您可以通过单击主菜单并参考*相关链接*部分中的*Kasten 文档*链接来熟悉它，以获取额外的设置（如果需要）。

### 备份应用程序

让我们执行以下步骤来备份我们的应用程序：

1.  如果您已经有一个应用程序和与备份相关的持久卷，您可以跳过*步骤 5*。否则，使用以下示例代码创建一个命名空间和 PVC：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
 name: backup-example
 labels:
 app: app2backup
EOF
```

1.  在`backup-example`命名空间中创建一个 PVC：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
 name: pvc2backup
 namespace: backup-example
 labels:
 app: app2backup
spec:
 accessModes:
 - ReadWriteOnce
 storageClassName: openebs-cstor-default
 resources:
 requests:
 storage: 4Gi
EOF
```

1.  创建一个将使用 PVC 并在`src/chapter6/kasten`目录下的示例`myapp.yaml`清单中写入`/data/out.txt`文件的 pod：

```
$ kubectl apply -f - kasten/myapp.yaml
```

1.  验证我们的`myapp` pod 是否将数据写入卷：

```
$ kubectl exec -it myapp cat /data/out.txt -nbackup-example
Thu Sep 12 23:18:08 UTC 2019
```

1.  在 Kasten 仪表板上，点击未管理的应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/c5898a07-a42d-4519-882f-3b8df68b52fa.png)

1.  在`backup-example`命名空间中，点击创建策略：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/9a3b4e0b-e693-4c44-a086-9008ce33fae5.png)

1.  输入名称并选择快照操作：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/361d0974-208f-40dd-b864-f1ad16f92c2f.png)

1.  选择每日作为操作频率：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/e3748fc4-ecf5-4ffc-9c0d-c015fc813595.png)

1.  点击创建策略：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/005f07e8-82a9-43fc-ba5c-939c8ba0cfbc.png)

按照这些步骤，您将使用策略创建第一个备份，以及以下备份作业的时间表。

### 恢复应用程序

让我们执行以下步骤来从现有备份中恢复应用程序：

1.  在应用程序下，从符合应用程序的列表中，单击`backup-example`旁边的箭头图标，然后选择还原应用程序。如果应用程序已被删除，则需要选择“已删除”选项：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/6622c618-54a4-4a76-a590-c6712d3fb734.png)

1.  选择要恢复的还原点：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/96080433-08be-439f-8f64-7e5339a41259.png)

1.  选择`backup-example`，然后单击还原：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/ff4d400e-a230-4881-bd0b-ada3983bc960.png)

1.  确认您希望进行还原：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/03d1059c-9b06-4377-b123-798fe2c3654a.png)

通过这样，您已经学会了如何使用 Kasten 从备份中还原应用程序及其卷。

## 它是如何工作的...

本教程向您展示了如何创建灾难恢复备份，从 S3 目标还原应用程序及其数据，并在 Kubernetes 上创建定期备份。

在*备份应用程序*教程中，在*步骤 2*中，我们创建了一个使用 OpenEBS 作为存储供应商的 pod。在这种情况下，Kasten 使用一种通用备份方法，该方法需要一个能够挂载应用程序数据卷的 sidecar 到您的应用程序。以下是一个示例，您可以在使用非标准存储选项时添加到您的 pod 和部署中：

```
- name: kanister-sidecar
  image: kanisterio/kanister-tools:0.20.0
  command: ["bash", "-c"]
  args:
  - "tail -f /dev/null"
  volumeMounts:
  - name: data
    mountPath: /data
```

## 另请参阅

+   Kasten 文档，网址为[`docs.kasten.io/`](https://docs.kasten.io/)

+   Kasten CLI 命令，网址为[`docs.kasten.io/api/cli.html`](https://docs.kasten.io/api/cli.html)

+   有关使用 Kanister 进行通用备份和还原的更多信息，请访问[`docs.kasten.io/kanister/generic.html#generic-kanister`](https://docs.kasten.io/kanister/generic.html#generic-kanister)

# 跨云应用程序迁移

在云上运行应用程序时，重要的是要有一个计划，以防云供应商服务中断发生，以及避免可能的云锁定，通过使用类似于 OpenEBS 管理层的云原生存储解决方案来抽象存储层，该解决方案允许您管理对每个云或数据中心的暴露。在本节中，我们将从一个 Kubernetes 集群迁移一个云原生应用程序到另一个在不同云供应商上运行的集群，以模拟迁移场景。您将学习如何使用 Kasten 和 OpenEBS Director 来使用备份来迁移应用程序。

## 准备就绪

确保您有两个准备好的 Kubernetes 集群，并且已配置`kubectl`以管理集群资源。

在本教程中，我们将使用由 D2iQ `Konvoy`部署和管理的 AWS 集群以及使用`kops`部署的集群。例如，我们将迁移一个现有的`minio`应用程序。

这里提供的说明需要一个 AWS 账户和一个具有使用相关服务权限的 AWS 用户策略。如果您没有，请访问[`aws.amazon.com/account/`](https://aws.amazon.com/account/)并创建一个。

## 如何做…

该部分进一步分为以下子部分，以使该过程更加简单：

+   在 Kasten 中创建导出配置文件

+   在 Kasten 中导出还原点

+   在 Kasten 中创建导入配置文件

+   在 Kasten 中迁移应用程序

+   在 OpenEBS Director 中导入集群

+   在 OpenEBS Director 中迁移应用程序

### 在 Kasten 中创建导出配置文件

首先，我们将使用 Kasten 创建一个导出配置文件，以存储迁移场景中要使用的示例应用程序的远程副本。要做到这一点，请按照以下步骤操作：

1.  在设置下，选择移动性选项卡，然后单击新配置文件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/cdd97ec7-a6f5-4a3d-a36b-1262632e6a9c.png)

1.  要创建目标配置文件，请选择导出，勾选启用数据可移植性框，选择 Amazon S3，并输入您的用户凭据。

1.  单击验证并保存：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/b581e6be-bde1-4f00-aa14-8b4076f1eb8c.png)

我们在本教程中创建的导出配置文件将在以后用于将数据移动到另一个集群。

### 在 Kasten 中导出还原点

让我们执行以下步骤来创建应用程序还原点：

1.  在应用程序下，从符合应用程序的列表中，单击 minio 旁边的箭头图标，并选择导出应用程序。

1.  选择要导出的还原点：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/3468839f-77dd-457a-8c9e-14bf94a24125.png)

1.  选择您的导出配置文件，然后点击导出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/3678bee2-6415-4002-82ef-458056c586e1.png)

1.  确认还原。

1.  将文本块复制到剪贴板中。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/28bee252-28bc-4e74-9466-0d484c8fc8a6.png)

### 在 Kasten 中创建一个导入配置文件

让我们在我们想要迁移应用程序的第二个集群上执行以下步骤：

1.  在设置下，选择移动性选项卡，然后点击新配置文件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/cdd97ec7-a6f5-4a3d-a36b-1262632e6a9c.png)

1.  要创建目标配置文件，选择导入，选择 Amazon S3，并输入您的用户凭据。

1.  使用您在源集群上为导出配置文件创建的存储桶名称。

1.  点击验证并保存：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/45b04dbd-3d44-4082-ada0-2cf2de272c04.png)

我们在这个教程中创建的导入配置文件将在以后用于从另一个集群导入数据。

### 在 Kasten 中迁移应用程序

最后，让我们执行以下步骤来使用导入配置文件并从另一个集群迁移应用程序：

1.  在策略下，点击新策略：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/f677f96a-db96-4ea1-91c3-b4e6781a06c2.png)

1.  选择导入并勾选导入后恢复框。

1.  选择每日作为操作频率，并粘贴来自*导出还原点*教程的配置数据文本块。

1.  选择您在*创建导入配置文件*教程中创建的导入配置文件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/d1ed6e91-6514-4442-ade2-c957aad5d211.png)

1.  点击创建策略按钮。

完成此步骤后，Kasten 将从还原点中恢复应用程序及其数据到新集群中。

### 将集群导入 OpenEBS Director

OpenEBS Director Online 是一个免费使用的**SaaS（软件即服务）**解决方案（企业用户可用 OnPrem 选项）用于管理 Kubernetes 中的有状态应用程序。除了其日志记录和监控功能外，它还提供**数据迁移即服务**（**DMaaS**）。在这个教程中，我们将学习如何将现有的集群添加到平台，然后在下一个教程中执行 DMaaS：

1.  转到[www.mayadata.io](http://www.mayadata.io)登录到您的 OpenEBS 企业平台[`portal.mayadata.io/home`](https://portal.mayadata.io/home)：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/7093385d-3d37-4b90-b9f9-dd24f2b32231.png)

1.  点击连接您的集群按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/5e7893ef-d6d6-43d4-beaf-35082cda9d66.png)

1.  命名您的项目。在这里，我们使用了名称`GKECluster`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/94b19b9e-61be-4208-9714-10974dad61f3.png)

1.  选择您的 Kubernetes 集群位置。在这里，我们使用了`GKE`上的一个集群：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/d7724b3a-c711-4007-b16b-67d6d2feef3d.png)

1.  在您的第一个集群上复制并执行该命令：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/5f7b4124-5ce5-4881-a11d-83724a277151.png)

1.  从左侧菜单中，点击“集群”：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/a221c7bb-1686-4715-acc2-ee1ed179c406.png)

1.  在“集群”视图中，点击“连接新集群”，然后为第二个集群重复*步骤 4*和*步骤 5*：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/d644a1cf-abc7-4c0f-84d4-045a43c33ed9.png)

1.  完成后，您将在平台上看到两个集群。

### 在 OpenEBS Director 中迁移应用程序

让我们按照以下步骤执行数据迁移（DMaaS）：

1.  在“集群”视图中，点击订阅列下的“免费”，并开始为两个集群进行高级计划评估：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/d187fb83-83e1-4ee4-a682-8c3ae95d2e01.png)

1.  在源集群的概述页面上，点击您想要迁移的工作负载。在这个示例中，我们将迁移 MinIO 工作负载：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/a95bcc41-65d4-4b85-8814-c5f77804a451.png)

1.  在应用程序视图中，选择 DMaaS 选项卡，然后点击“新建计划”按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/570b09c3-d9ed-4780-956f-979ff6bb4ed1.png)

1.  在“新计划”视图中，选择 AWS 作为 S3 提供商，并选择您的凭据和地区。最后，选择备份间隔为每天，然后点击“立即计划”按钮创建备份。作为替代，您也可以使用 GCP 或 MinIO 作为 S3 目标：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/8954c3ca-0aff-46f4-8a7d-57179332ae2c.png)

1.  从左侧菜单中，选择 DMaaS，然后点击您创建的计划旁边的“恢复”按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/f338c82a-6c2c-4c34-b141-eb0cd12fce7a.png)

1.  从托管集群列表中选择目标集群，然后点击“开始恢复”：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/ef0ee5f3-bc54-4107-a064-f3f64d09fd2f.png)

您的工作负载将被恢复到第二个集群。

## 另请参阅

+   OpenEBS Director 文档，请访问[`help.mayadata.io/hc/en-us`](https://help.mayadata.io/hc/en-us)

+   在 Auto DevOps 用例中使用 OpenEBS Director，请访问[`youtu.be/AOSUZxUs5BE?t=1210`](https://youtu.be/AOSUZxUs5BE?t=1210)

+   连接到 OpenEBS Director Online，请访问[`docs.openebs.io/docs/next/directoronline.html`](https://docs.openebs.io/docs/next/directoronline.html)


# 第七章：扩展和升级应用程序

在本章中，我们将讨论可以使用的方法和策略，以动态地扩展在 Kubernetes 上运行的容器化服务，以处理我们服务的不断变化的流量需求。在本章的配方中，您将掌握创建负载均衡器以将流量分发到多个工作节点并增加带宽所需的技能。您还将了解如何在生产环境中处理升级以最小化停机时间。

在本章中，我们将涵盖以下配方：

+   在 Kubernetes 上扩展应用程序

+   为节点分配应用程序的优先级

+   创建外部负载均衡器

+   使用 Istio 创建入口服务和服务网格

+   使用 Linkerd 创建入口服务和服务网格

+   在 Kubernetes 中自动修复 Pod

+   通过蓝/绿部署管理升级

# 技术要求

本章的配方假定您已通过第一章中描述的推荐方法之一部署了一个功能齐全的 Kubernetes 集群，*构建生产就绪的 Kubernetes 集群*。

Kubernetes 命令行工具`kubectl`将在本章的其余部分中用于配方，因为它是针对 Kubernetes 集群运行命令的主要命令行界面。我们还将在 Helm 图表可用的情况下使用 helm 来部署解决方案。

# 在 Kubernetes 上扩展应用程序

在本节中，我们将执行应用程序和集群扩展任务。您将学习如何在 Kubernetes 中手动和自动地扩展服务容量，以支持动态流量。

## 准备工作

将`k8sdevopscookbook/src`存储库克隆到您的工作站，以便使用`chapter7`目录中的清单文件，如下所示：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd /src/chapter7/
```

确保您已准备好一个 Kubernetes 集群，并配置了`kubectl`和`helm`来管理集群资源。

## 操作步骤：

此部分进一步分为以下子部分，以使此过程更加简单：

+   验证 Metrics Server 的安装

+   手动扩展应用程序

+   使用水平 Pod 自动缩放器自动缩放应用程序

### 验证 Metrics Server 的安装

本节中的*使用水平 Pod 自动缩放器自动缩放应用程序*配方还需要在您的集群上安装 Metrics Server。Metrics Server 是用于核心资源使用数据的集群范围聚合器。按照以下步骤验证 Metrics Server 的安装：

1.  通过运行以下命令确认是否需要安装 Metrics Server：

```
$ kubectl top node
error: metrics not available yet
```

1.  如果安装正确，您应该看到以下节点指标：

```
$ kubectl top nodes
NAME                          CPU(cores) CPU% MEMORY(bytes) MEMORY%
ip-172-20-32-169.ec2.internal 259m       12%  1492Mi        19%
ip-172-20-37-106.ec2.internal 190m       9%   1450Mi        18%
ip-172-20-48-49.ec2.internal  262m       13%  2166Mi        27%
ip-172-20-58-155.ec2.internal 745m       37%  1130Mi        14%
```

如果收到错误消息，指出`尚未提供指标`，则需要按照*使用 Kubernetes Metrics Server 添加指标*配方中提供的步骤安装 Metrics Server。

### 手动扩展应用程序

当您的应用程序的使用量增加时，有必要将应用程序扩展。Kubernetes 被设计用来处理高规模工作负载的编排。

让我们执行以下步骤，了解如何手动扩展应用程序：

1.  更改目录到`/src/chapter7/charts/node`，这是您在*准备就绪*部分创建的示例存储库的本地克隆所在的位置：

```
$ cd /charts/node/
```

1.  使用以下命令安装待办事项应用程序示例。这个 Helm 图表将部署两个 pod，包括一个 Node.js 服务和一个 MongoDB 服务：

```
$ helm install . --name my-ch7-app
```

1.  获取`my-ch7-app-node`的服务 IP 以连接到应用程序。以下命令将返回应用程序的外部地址：

```
$ export SERVICE_IP=$(kubectl get svc --namespace default my-ch7-app-node --template "{{ range (index .status.loadBalancer.ingress 0) }}{{.}}{{ end }}")
$ echo http://$SERVICE_IP/
http://mytodoapp.us-east-1.elb.amazonaws.com/
```

1.  在 Web 浏览器中打开*步骤 3*中的地址。您将获得一个完全功能的待办事项应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/1e02a226-7f1d-4804-98f7-6176144d9845.png)

1.  使用`helm status`检查应用程序的状态。您将看到已部署的 pod 数量在`Available`列中：

```
$ helm status my-ch7-app
LAST DEPLOYED: Thu Oct 3 00:13:10 2019
NAMESPACE: default
STATUS: DEPLOYED
RESOURCES:
==> v1/Deployment
NAME               READY UP-TO-DATE AVAILABLE AGE
my-ch7-app-mongodb 1/1   1          1         9m9s
my-ch7-app-node    1/1   1          1         9m9s
...
```

1.  将节点 pod 的规模从当前的单个副本扩展到`3`个副本：

```
$ kubectl scale --replicas 3 deployment/my-ch7-app-node
deployment.extensions/my-ch7-app-node scaled
```

1.  再次检查应用程序的状态，并确认，这次可用副本的数量为`3`，`v1/Pod`部分中的`my-ch7-app-node` pod 数量已增加到`3`：

```
$ helm status my-ch7-app
...
RESOURCES:
==> v1/Deployment
NAME READY UP-TO-DATE AVAILABLE AGE
my-ch7-app-mongodb 1/1 1 1 26m
my-ch7-app-node 3/3 3 3 26m
...
==> v1/Pod(related)
NAME READY STATUS RESTARTS AGE
my-ch7-app-mongodb-5499c954b8-lcw27 1/1 Running 0 26m
my-ch7-app-node-d8b94964f-94dsb 1/1 Running 0 91s
my-ch7-app-node-d8b94964f-h9w4l 1/1 Running 3 26m
my-ch7-app-node-d8b94964f-qpm77 1/1 Running 0 91s
```

1.  要缩小应用程序的规模，请重复*步骤 5*，但这次使用`2`个副本：

```
$ kubectl scale --replicas 2 deployment/my-ch7-app-node
deployment.extensions/my-ch7-app-node scaled
```

有了这个，您学会了如何在需要时扩展您的应用程序。当然，您的 Kubernetes 集群资源也应该能够支持不断增长的工作负载能力。

下一个配方将向您展示如何根据实际资源消耗而不是手动步骤来自动缩放工作负载。

### 使用水平 Pod 自动缩放器自动缩放应用程序

在本教程中，您将学习如何创建**水平 Pod 自动缩放器**（**HPA**）来自动化我们在上一个教程中创建的应用程序的扩展过程。我们还将使用负载生成器测试 HPA，模拟增加流量击中我们的服务的情景。请按照以下步骤操作：

1.  首先，确保您已经部署了*手动扩展应用程序*中的示例待办事项应用程序。当您运行以下命令时，您应该会看到 MongoDB 和 Node pods 的列表：

```
$ kubectl get pods | grep my-ch7-app
my-ch7-app-mongodb-5499c954b8-lcw27 1/1 Running 0 4h41m
my-ch7-app-node-d8b94964f-94dsb     1/1 Running 0 4h16m
my-ch7-app-node-d8b94964f-h9w4l     1/1 Running 3 4h41m
```

1.  使用以下命令声明性地创建 HPA。这将自动化在达到`targetCPUUtilizationPercentage`阈值时在`1`到`5`个副本之间扩展应用程序的过程。在我们的示例中，pod 的 CPU 利用率目标的平均值设置为`50`％。当利用率超过此阈值时，您的副本将增加：

```
cat <<EOF | kubectl apply -f -
apiVersion: autoscaling/v1
kind: HorizontalPodAutoscaler
metadata:
 name: my-ch7-app-autoscaler
 namespace: default
spec:
 scaleTargetRef:
 apiVersion: apps/v1
 kind: Deployment
 name: my-ch7-app-node
 minReplicas: 1
 maxReplicas: 5
 targetCPUUtilizationPercentage: 50
EOF
```

尽管结果大多数情况下可能是相同的，但声明性配置需要理解 Kubernetes 对象配置规范和文件格式。作为替代方案，`kubectl`可以用于对 Kubernetes 对象进行命令式管理。

请注意，您必须在部署中设置 CPU 请求才能使用自动缩放。如果您的部署中没有 CPU 请求，HPA 将部署但不会正常工作。

您还可以通过运行`$ kubectl autoscale deployment my-ch7-app-node --cpu-percent=50 --min=1 --max=5`命令来命令式地创建相同的`HorizontalPodAutoscaler`。

1.  确认当前副本的数量和 HPA 的状态。当您运行以下命令时，副本的数量应为`1`：

```
$ kubectl get hpa
NAME                  REFERENCE                  TARGETS       MINPODS MAXPODS REPLICAS AGE
my-ch7-app-autoscaler Deployment/my-ch7-app-node 0%/50%        1       5       1        40s
```

1.  获取`my-ch7-app-node`的服务 IP，以便在下一步中使用：

```
$ export SERVICE_IP=$(kubectl get svc --namespace default my-ch7-app-node --template "{{ range (index .status.loadBalancer.ingress 0) }}{{.}}{{ end }}")
$ echo http://$SERVICE_IP/
http://mytodoapp.us-east-1.elb.amazonaws.com/
```

1.  打开一个新的终端窗口并创建一个负载生成器来测试 HPA。确保您在以下代码中用实际服务 IP 替换`YOUR_SERVICE_IP`。此命令将向您的待办事项应用程序生成流量：

```
$ kubectl run -i --tty load-generator --image=busybox /bin/sh

while true; do wget -q -O- YOUR_SERVICE_IP; done
```

1.  等待几分钟，使自动缩放器对不断增加的流量做出响应。在一个终端上运行负载生成器的同时，在另一个终端窗口上运行以下命令，以监视增加的 CPU 利用率。在我们的示例中，这被设置为`210％`：

```
$ kubectl get hpa
NAME                  REFERENCE                  TARGETS       MINPODS MAXPODS REPLICAS AGE
my-ch7-app-autoscaler Deployment/my-ch7-app-node 210%/50%      1       5       1        23m
```

1.  现在，检查部署大小并确认部署已调整为`5`个副本，以应对工作负载的增加：

```
$ kubectl get deployment my-ch7-app-node
NAME            READY UP-TO-DATE AVAILABLE AGE
my-ch7-app-node 5/5   5          5         5h23m
```

1.  在运行负载生成器的终端屏幕上，按下*Ctrl* + *C*来终止负载生成器。这将停止发送到您的应用程序的流量。

1.  等待几分钟，让自动缩放器进行调整，然后通过运行以下命令来验证 HPA 状态。当前的 CPU 利用率应该更低。在我们的示例中，它显示下降到`0%`：

```
$ kubectl get hpa
NAME                  REFERENCE                  TARGETS MINPODS MAXPODS REPLICAS AGE
my-ch7-app-autoscaler Deployment/my-ch7-app-node 0%/50%  1       5       1        34m
```

1.  检查部署大小，并确认部署已经因停止流量生成器而缩减到`1`个副本：

```
$ kubectl get deployment my-ch7-app-node
NAME            READY UP-TO-DATE AVAILABLE AGE
my-ch7-app-node 1/1   1          1         5h35m
```

在这个教程中，您学会了如何根据不断变化的指标动态地自动化应用程序的扩展。当应用程序被扩展时，它们会动态地调度到现有的工作节点上。

## 工作原理...

这个教程向您展示了如何根据 Kubernetes 指标动态地手动和自动地扩展部署中的 Pod 数量。

在这个教程中，在*步骤 2*中，我们创建了一个自动缩放器，它会在`minReplicas: 1`和`maxReplicas: 5`之间调整副本的数量。如下例所示，调整标准由`targetCPUUtilizationPercentage: 50`指标触发：

```
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: my-ch7-app-node
  minReplicas: 1
  maxReplicas: 5
  targetCPUUtilizationPercentage: 50
```

`targetCPUUtilizationPercentage`是与`autoscaling/v1`API 一起使用的。您很快将看到`targetCPUUtilizationPercentage`将被一个名为 metrics 的数组所取代。

要了解新的指标和自定义指标，运行以下命令。这将返回我们使用 V1 API 创建的清单到使用 V2 API 的新清单：

```
$ kubectl get hpa.v2beta2.autoscaling my-ch7-app-node -o yaml
```

这使您能够指定额外的资源指标。默认情况下，CPU 和内存是唯一支持的资源指标。除了这些资源指标，v2 API 还支持另外两种类型的指标，这两种指标都被视为自定义指标：每个 Pod 的自定义指标和对象指标。您可以通过转到*参见*部分中提到的*Kubernetes HPA 文档*链接来了解更多信息。

## 参见

+   使用自定义指标的 Kubernetes Pod 自动缩放器：[`sysdig.com/blog/kubernetes-autoscaler/`](https://sysdig.com/blog/kubernetes-autoscaler/)

+   Kubernetes HPA 文档：[`kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/`](https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/)

+   使用配置文件声明式管理 Kubernetes 对象：[`kubernetes.io/docs/tasks/manage-kubernetes-objects/declarative-config/`](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/declarative-config/)

+   使用配置文件命令式管理 Kubernetes 对象：[`kubernetes.io/docs/tasks/manage-kubernetes-objects/imperative-config/`](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/imperative-config/)

# 将应用程序分配给节点

在本节中，我们将确保 pod 不会被调度到不合适的节点上。您将学习如何使用节点选择器、污点、容忍和设置优先级将 pod 调度到 Kubernetes 节点上。

## 准备工作

确保您已准备好一个 Kubernetes 集群，并配置了`kubectl`和`helm`来管理集群资源。

## 如何做…

此部分进一步分为以下子部分，以使此过程更容易：

+   给节点贴标签

+   使用 nodeSelector 将 pod 分配给节点

+   使用节点和 pod 亲和性将 pod 分配给节点

### 给节点贴标签

Kubernetes 标签用于指定资源的重要属性，这些属性可用于将组织结构应用到系统对象上。在这个配方中，我们将学习用于 Kubernetes 节点的常见标签，并应用一个自定义标签，以便在调度 pod 到节点时使用。

让我们执行以下步骤，列出已分配给您的节点的一些默认标签：

1.  列出已分配给您的节点的标签。在我们的示例中，我们将使用部署在 AWS EC2 上的 kops 集群，因此您还将看到相关的 AWS 标签，例如可用区：

```
$ kubectl get nodes --show-labels
NAME                          STATUS ROLES AGE VERSION LABELS
ip-172-20-49-12.ec2.internal  Ready   node  23h v1.14.6 
kubernetes.io/arch=amd64,kubernetes.io/instance-type=t3.large,
kubernetes.io/os=linux,failure-domain.beta.kubernetes.io/region=us-east-1,
failure-domain.beta.kubernetes.io/zone=us-east-1a,
kops.k8s.io/instancegroup=nodes,kubernetes.io/hostname=ip-172-20-49-12.ec2.internal,
kubernetes.io/role=node,node-role.kubernetes.io/node=
...
```

1.  获取您的集群中的节点列表。我们将使用节点名称在下一步中分配标签：

```
$ kubectl get nodes
NAME                           STATUS ROLES  AGE VERSION
ip-172-20-49-12.ec2.internal   Ready  node   23h v1.14.6
ip-172-20-50-171.ec2.internal  Ready  node   23h v1.14.6
ip-172-20-58-83.ec2.internal   Ready  node   23h v1.14.6
ip-172-20-59-8.ec2.internal    Ready  master 23h v1.14.6
```

1.  将两个节点标记为`production`和`development`。使用*步骤 2*的输出中的工作节点名称运行以下命令：

```
$ kubectl label nodes ip-172-20-49-12.ec2.internal environment=production
$ kubectl label nodes ip-172-20-50-171.ec2.internal environment=production
$ kubectl label nodes ip-172-20-58-83.ec2.internal environment=development
```

1.  验证新标签是否已分配给节点。这次，除了标记为`role=master`的节点外，您应该在所有节点上看到`environment`标签：

```
$ kubectl get nodes --show-labels
```

建议为将使用您的集群的其他人记录标签。虽然它们不直接暗示核心系统的语义，但确保它们对所有用户仍然有意义和相关。

### 使用 nodeSelector 将 pod 分配给节点

在这个配方中，我们将学习如何使用 nodeSelector 原语将 pod 调度到选定的节点：

1.  在名为`todo-dev`的新目录中创建我们在*手动扩展应用程序*配方中使用的 Helm 图表的副本。稍后我们将编辑模板，以指定`nodeSelector`：

```
$ cd src/chapter7/charts
$ mkdir todo-dev
$ cp -a node/* todo-dev/
$ cd todo-dev
```

1.  编辑`templates`目录中的`deployment.yaml`文件：

```
$ vi templates/deployment.yaml
```

1.  在`containers:`参数之前添加`nodeSelector:`和`environment: "{{ .Values.environment }}"`。这应该如下所示：

```
...
          mountPath: {{ .Values.persistence.path }}
      {{- end }}
# Start of the addition
      nodeSelector:
        environment: "{{ .Values.environment }}"
# End of the addition
      containers:
      - name: {{ template "node.fullname" . }}

...
```

Helm 安装使用模板生成配置文件。如前面的示例所示，为了简化您自定义提供的值的方式，使用`{{expr}}`，这些值来自`values.yaml`文件名称。`values.yaml`文件包含图表的默认值。

尽管在大型集群上可能不太实用，但是除了使用`nodeSelector`和标签之外，您还可以使用`nodeName`设置在一个特定的节点上安排 Pod。在这种情况下，您可以将`nodeName: yournodename`添加到部署清单中，而不是`nodeSelector`设置。

1.  现在我们已经添加了变量，编辑`values.yaml`文件。这是我们将环境设置为`development`标签的地方：

```
$ vi values.yaml
```

1.  在文件末尾添加`environment: development`行。它应该如下所示：

```
...
## Affinity for pod assignment
## Ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/#affinity-and-anti-affinity
##
affinity: {}
environment: development
```

1.  编辑`Chart.yaml`文件，并将图表名称更改为其文件夹名称。在这个配方中，它被称为`todo-dev`。在这些更改之后，前两行应该如下所示：

```
apiVersion: v1
name: todo-dev
...
```

1.  更新 Helm 依赖项并构建它们。以下命令将拉取所有依赖项并构建 Helm 图表：

```
$ helm dep update & helm dep build
```

1.  检查图表是否存在问题。如果图表文件有任何问题，linting 过程将提出问题；否则，不应该发现任何失败：

```
$ helm lint .
==> Linting .
Lint OK
1 chart(s) linted, no failures
```

1.  使用以下命令安装示例待办应用程序。这个 Helm 图表将部署两个 Pod，包括一个 Node.js 服务和一个 MongoDB 服务，但这次节点被标记为`environment: development`：

```
$ helm install . --name my-app7-dev --set serviceType=LoadBalancer
```

1.  使用以下命令检查所有的 Pod 是否已经安排在开发节点上。您会发现`my-app7-dev-todo-dev` Pod 正在带有`environment: development`标签的节点上运行：

```
$ for n in $(kubectl get nodes -l environment=development --no-headers | cut -d " " -f1); do kubectl get pods --all-namespaces --no-headers --field-selector spec.nodeName=${n} ; done
```

有了这个，您已经学会了如何使用`nodeSelector`原语将工作负载 Pod 安排到选定的节点上。

### 使用节点和 Pod 之间的亲和性将 Pod 分配给节点

在这个配方中，我们将学习如何扩展我们在上一个配方中表达的约束，即使用亲和性和反亲和性特性将 Pod 分配给带标签的节点。

让我们使用基于场景的方法来简化不同的亲和性选择器选项的配方。我们将采用前面的示例，但这次是具有复杂要求：

+   `todo-prod`必须安排在带有`environment:production`标签的节点上，并且如果无法安排，则应该失败。

+   `todo-prod`应该在一个被标记为`failure-domain.beta.kubernetes.io/zone=us-east-1a`或`us-east-1b`的节点上运行，但如果标签要求不满足，可以在任何地方运行。

+   `todo-prod`必须在与`mongodb`相同的区域运行，但不应在`todo-dev`运行的区域运行。

这里列出的要求只是为了代表一些亲和性定义功能的使用示例。这不是配置这个特定应用程序的理想方式。在您的环境中，标签可能完全不同。

上述情景将涵盖节点亲和性选项（`requiredDuringSchedulingIgnoredDuringExecution`和`preferredDuringSchedulingIgnoredDuringExecution`）的两种类型。您将在我们的示例中稍后看到这些选项。让我们开始吧：

1.  将我们在*手动扩展应用程序*配方中使用的 Helm 图表复制到一个名为`todo-prod`的新目录中。我们稍后将编辑模板，以指定`nodeAffinity`规则：

```
$ cd src/chapter7/charts
$ mkdir todo-prod
$ cp -a node/* todo-prod/
$ cd todo-prod
```

1.  编辑`values.yaml`文件。要访问它，请使用以下命令：

```
$ vi values.yaml
```

1.  用以下代码替换最后一行`affinity: {}`。这个改变将满足我们之前定义的第一个要求，意味着一个 pod 只能放置在一个带有`environment`标签且其值为`production`的节点上：

```
## Affinity for pod assignment
## Ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/#affinity-and-anti-affinity
# affinity: {}
# Start of the affinity addition #1
affinity:
 nodeAffinity:
 requiredDuringSchedulingIgnoredDuringExecution:
 nodeSelectorTerms:
 - matchExpressions:
 - key: environment
 operator: In
 values:
 - production
# End of the affinity addition #1
```

您还可以在`nodeSelectorTerms`下指定多个`matchExpressions`。在这种情况下，pod 只能被调度到所有`matchExpressions`都满足的节点上，这可能会限制您成功调度的机会。

虽然在大型集群上可能不太实用，但是除了使用`nodeSelector`和标签之外，您还可以使用`nodeName`设置在特定节点上调度一个 pod。在这种情况下，将`nodeName: yournodename`添加到您的部署清单中，而不是`nodeSelector`设置。

1.  现在，在上述代码添加的下面添加以下行。这个添加将满足我们之前定义的第二个要求，意味着带有`failure-domain.beta.kubernetes.io/zone`标签且其值为`us-east-1a`或`us-east-1b`的节点将被优先选择：

```
          - production
# End of the affinity addition #1
# Start of the affinity addition #2
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 1
      preference:
        matchExpressions:
        - key: failure-domain.beta.kubernetes.io/zone
          operator: In
          values:
          - us-east-1a
          - us-east-1b
# End of the affinity addition #2
```

1.  对于第三个要求，我们将使用 pod 之间的亲和性和反亲和性功能。它们允许我们基于节点上已经运行的 pod 的标签来限制我们的 pod 有资格被调度到哪些节点，而不是根据节点上的标签进行调度。以下 podAffinity `requiredDuringSchedulingIgnoredDuringExecution`规则将寻找存在`app: mongodb`的节点，并使用`failure-domain.beta.kubernetes.io/zone`作为拓扑键来显示我们的 pod 允许被调度到哪里：

```
          - us-east-1b
# End of the affinity addition #2
# Start of the affinity addition #3a
  podAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector:
        matchExpressions:
        - key: app
          operator: In
          values:
          - mongodb
      topologyKey: failure-domain.beta.kubernetes.io/zone
# End of the affinity addition #3a
```

1.  添加以下行以满足要求。这次，`podAntiAffinity preferredDuringSchedulingIgnoredDuringExecution`规则将寻找存在`app: todo-dev`的节点，并使用`failure-domain.beta.kubernetes.io/zone`作为拓扑键：

```
      topologyKey: failure-domain.beta.kubernetes.io/zone
# End of the affinity addition #3a
# Start of the affinity addition #3b
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app
            operator: In
            values:
            - todo-dev
        topologyKey: failure-domain.beta.kubernetes.io/zone
# End of the affinity addition #3b
```

1.  编辑`Chart.yaml`文件，并将图表名称更改为其文件夹名称。在这个示例中，它被称为`todo-prod`。做出这些更改后，前两行应如下所示：

```
apiVersion: v1
name: todo-prod
...
```

1.  更新 Helm 依赖项并构建它们。以下命令将拉取所有依赖项并构建 Helm 图表：

```
$ helm dep update & helm dep build
```

1.  检查图表是否存在问题。如果图表文件有任何问题，linting 过程将指出；否则，不应该发现任何失败：

```
$ helm lint .
==> Linting .
Lint OK
1 chart(s) linted, no failures
```

1.  使用以下命令安装待办事项应用示例。这个 Helm 图表将部署两个 pod，包括一个 Node.js 服务和一个 MongoDB 服务，这次遵循我们在本示例开始时定义的详细要求：

```
$ helm install . --name my-app7-prod --set serviceType=LoadBalancer
```

1.  使用以下命令检查已经在节点上调度的所有 pod 是否标记为`environment: production`。您将发现`my-app7-dev-todo-dev` pod 正在节点上运行：

```
$ for n in $(kubectl get nodes -l environment=production --no-headers | cut -d " " -f1); do kubectl get pods --all-namespaces --no-headers --field-selector spec.nodeName=${n} ; done
```

在本示例中，您学习了在 Kubernetes 中使用一些原语时如何进行高级 pod 调度实践，包括`nodeSelector`、节点亲和性和 pod 之间的亲和性。现在，您将能够配置一组应用程序，这些应用程序位于相同的定义拓扑中或在不同的区域中进行调度，以便您拥有更好的**服务级别协议**（**SLA**）时间。

## 工作原理...

本节中的示例向您展示了如何根据复杂的要求在首选位置上调度 pod。

在*节点标记*示例中，在*步骤 1*中，您可以看到一些标准标签已经应用到您的节点上。这里是它们的简要解释以及它们的用途：

+   `kubernetes.io/arch`：这来自`runtime.GOARCH`参数，并应用于节点以识别在不同架构容器映像（如 x86、arm、arm64、ppc64le 和 s390x）上运行的位置混合架构集群。

+   `kubernetes.io/instance-type`：只有在集群部署在云提供商上时才有用。实例类型告诉我们很多关于平台的信息，特别是对于需要在具有 GPU 或更快存储选项的实例上运行一些 Pod 的 AI 和机器学习工作负载。

+   `kubernetes.io/os`：这适用于节点，并来自`runtime.GOOS`。除非您在同一集群中有 Linux 和 Windows 节点，否则可能不太有用。

+   `failure-domain.beta.kubernetes.io/region`和`/zone`：如果您的集群部署在云提供商上或您的基础设施跨不同的故障域，这也更有用。在数据中心，它可以用于定义机架解决方案，以便您可以将 Pod 安排在不同的机架上，以提高可用性。

+   `kops.k8s.io/instancegroup=nodes`：这是设置为实例组名称的节点标签。仅在使用 kops 集群时使用。

+   `kubernetes.io/hostname`：显示工作节点的主机名。

+   `kubernetes.io/role`：显示工作节点在集群中的角色。一些常见的值包括`node`（表示工作节点）和`master`（表示节点是主节点，并且默认情况下被标记为不可调度的工作负载）。

在*使用节点和跨 Pod 亲和力将 Pod 分配给节点*配方中，在*步骤 3*中，节点亲和力规则表示 Pod 只能放置在具有键为`environment`且值为`production`的标签的节点上。

在*步骤 4*中，首选`affinity key: value`要求（`preferredDuringSchedulingIgnoredDuringExecution`）。这里的`weight`字段可以是`1`到`100`之间的值。满足这些要求的每个节点，Kubernetes 调度程序都会计算一个总和。总分最高的节点是首选的。

这里使用的另一个细节是`In`参数。节点亲和力支持以下运算符：`In`、`NotIn`、`Exists`、`DoesNotExist`、`Gt`和`Lt`。您可以通过查看“通过示例查看调度亲和力”链接来了解更多关于这些运算符的信息，该链接在*另请参阅*部分中提到。

如果选择器和亲和力规则规划不当，很容易阻止 pod 在节点上调度。请记住，如果同时指定了`nodeSelector`和`nodeAffinity`规则，则必须同时满足这两个要求，才能将 pod 调度到可用节点上。

在*步骤 5*中，使用`podAffinity`来满足 PodSpec 中的要求。在这个示例中，`podAffinity`是`requiredDuringSchedulingIgnoredDuringExecution`。在这里，`matchExpressions`表示一个 pod 只能在`failure-domain.beta.kubernetes.io/zone`与其他带有`app: mongodb`标签的 pod 所在的节点匹配的节点上运行。

在*步骤 6*中，使用`podAntiAffinity`和`preferredDuringSchedulingIgnoredDuringExecution`满足了要求。在这里，`matchExpressions`表示一个 pod 不能在`failure-domain.beta.kubernetes.io/zone`与其他带有`app: todo-dev`标签的 pod 所在的节点匹配的节点上运行。通过将权重设置为`100`来增加权重。

## 另请参阅

+   已知标签、注释和污点列表：[`kubernetes.io/docs/reference/kubernetes-api/labels-annotations-taints/`](https://kubernetes.io/docs/reference/kubernetes-api/labels-annotations-taints/)

+   将 Pod 分配给 Kubernetes 文档中的节点：[`kubernetes.io/docs/tasks/configure-pod-container/assign-pods-nodes/`](https://kubernetes.io/docs/tasks/configure-pod-container/assign-pods-nodes/)

+   有关 Kubernetes 文档中标签和选择器的更多信息：[`kubernetes.io/docs/concepts/overview/working-with-objects/labels/`](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)

+   通过示例了解调度器亲和力：[`banzaicloud.com/blog/k8s-affinities/`](https://banzaicloud.com/blog/k8s-affinities/)

+   节点亲和力和 NodeSelector 设计文档：[`github.com/kubernetes/community/blob/master/contributors/design-proposals/scheduling/nodeaffinity.md`](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/scheduling/nodeaffinity.md)

+   Pod 间拓扑亲和力和反亲和力设计文档：[`github.com/kubernetes/community/blob/master/contributors/design-proposals/scheduling/podaffinity.md`](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/scheduling/podaffinity.md)

# 创建外部负载均衡器

负载均衡器服务类型是一种相对简单的服务替代方案，用于使用基于云的外部负载均衡器而不是入口。外部负载均衡器服务类型的支持仅限于特定的云提供商，但受到大多数流行的云提供商的支持，包括 AWS、GCP、Azure、阿里云和 OpenStack。

在本节中，我们将使用负载均衡器来公开我们的工作负载端口。我们将学习如何为公共云上的集群创建外部 GCE/AWS 负载均衡器，以及如何使用`inlet-operator`为您的私有集群创建外部负载均衡器。

## 准备工作

确保您已经准备好一个 Kubernetes 集群，并且`kubectl`和`helm`已配置好以管理集群资源。在本教程中，我们使用了在 AWS 上使用`kops`部署的集群，如第一章中所述，*构建生产就绪的 Kubernetes 集群*，在*亚马逊网络服务*的示例中。相同的说明也适用于所有主要的云提供商。

要访问示例文件，请将`k8sdevopscookbook/src`存储库克隆到您的工作站，以便在`src/chapter7/lb`目录中使用配置文件，方法如下：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd src/chapter7/lb/
```

在您克隆了示例存储库之后，您可以继续进行操作。

## 操作步骤

本节进一步分为以下小节，以使这个过程更容易：

+   创建外部云负载均衡器

+   查找服务的外部地址

### 创建外部云负载均衡器

当您创建一个应用程序并将其公开为 Kubernetes 服务时，通常需要使服务可以通过 IP 地址或 URL 从外部访问。在本教程中，您将学习如何创建一个负载均衡器，也称为云负载均衡器。

在前几章中，我们已经看到了一些示例，这些示例使用了负载均衡器服务类型来公开 IP 地址，包括上一章中的*使用 MinIO 配置和管理 S3 对象存储*和*使用 Kasten 进行应用程序备份和恢复*，以及本章中提供的 To-Do 应用程序在*将应用程序分配给节点*的示例中。

让我们使用 MinIO 应用程序来学习如何创建负载均衡器。按照以下步骤创建一个服务，并使用外部负载均衡器服务公开它：

1.  查看`src/chapter7/lb`目录中`minio.yaml`文件的内容，并使用以下命令部署它。这将创建一个 StatefulSet 和一个服务，其中 MinIO 端口通过端口号`9000`在集群内部公开。你可以选择应用相同的步骤并为你自己的应用程序创建一个负载均衡器。在这种情况下，跳到*步骤 2*：

```
$ kubectl apply -f minio.yaml
```

1.  列出 Kubernetes 上可用的服务。你会看到 MinIO 服务的服务类型为`ClusterIP`，`EXTERNAL-IP`字段下为`none`：

```
$ kubectl get svc
NAME       TYPE      CLUSTER-IP EXTERNAL-IP PORT(S)  AGE
kubernetes ClusterIP 100.64.0.1 <none>      443/TCP  5d
minio      ClusterIP None       <none>      9000/TCP 4m
```

1.  创建一个`TYPE`设置为`LoadBalancer`的新服务。以下命令将使用`TCP`协议将我们的 MinIO 应用程序的`port: 9000`暴露到`targetPort: 9000`，如下所示：

```
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
 name: minio-service
spec:
 type: LoadBalancer
 ports:
 - port: 9000
 targetPort: 9000
 protocol: TCP
 selector:
 app: minio
EOF
```

上述命令将立即创建`Service`对象，但在云服务提供商端实际的负载均衡器可能需要 30 秒到 1 分钟才能完全初始化。尽管对象将声明它已准备就绪，但在负载均衡器初始化之前它将无法正常工作。这是云负载均衡器与入口控制器相比的一个缺点，我们将在下一个教程中看到，*使用 Istio 创建入口服务和服务网格*。

作为*步骤 3*的替代方案，你也可以使用以下命令创建负载均衡器：

```
$ kubectl expose rc example --port=9000 --target-port=9000 --name=minio-service --type=LoadBalancer
```

### 查找服务的外部地址

让我们执行以下步骤来获取服务的外部可达地址：

1.  列出使用`LoadBalancer`类型的服务。`EXTERNAL-IP`列将显示云供应商提供的地址：

```
$ kubectl get svc |grep LoadBalancer
NAME          TYPE         CLUSTER-IP    EXTERNAL-IP                                  PORT(S)        AGE
minio-service LoadBalancer 100.69.15.120 containerized.me.us-east-1.elb.amazonaws.com 9000:30705/TCP 4h39m
```

1.  如果你在 AWS 等云服务提供商上运行，你也可以使用以下命令获取确切的地址。你可以复制并粘贴到网页浏览器中：

```
$ SERVICE_IP=http://$(kubectl get svc minio-service \
-o jsonpath='{.status.loadBalancer.ingress[0].hostname}:{.spec.ports[].targetPort}')
$ echo $SERVICE_IP
```

1.  如果你在裸机服务器上运行，那么你可能不会有`hostname`条目。例如，如果你正在运行 MetalLB ([`metallb.universe.tf/`](https://metallb.universe.tf/))，一个用于裸机 Kubernetes 集群的负载均衡器，或者 SeeSaw ([`github.com/google/seesaw`](https://github.com/google/seesaw))，一个基于**Linux 虚拟服务器**（**LVS**）的负载均衡平台，你需要查找`ip`条目：

```
$ SERVICE_IP=http://$(kubectl get svc minio-service \
-o jsonpath='{.status.loadBalancer.ingress[0].ip}:{.spec.ports[].targetPort}')
$ echo $SERVICE_IP
```

上述命令将返回一个类似于`https://containerized.me.us-east-1.elb.amazonaws.com:9000`的链接。

## 它是如何工作的...

这个教程向你展示了如何快速创建一个云负载均衡器，以便使用外部地址暴露你的服务。

在*创建云负载均衡器*示例中，在*第 3 步*中，当在 Kubernetes 中创建负载均衡器服务时，将代表您创建一个云提供商负载均衡器，而无需单独通过云服务提供商 API。这个功能可以帮助您轻松地管理负载均衡器的创建，但同时需要一些时间来完成，并且需要为每个服务单独创建一个独立的负载均衡器，因此可能成本高且不太灵活。

为了使负载均衡器更加灵活并增加更多的应用级功能，您可以使用 Ingress 控制器。使用 Ingress，流量路由可以由 Ingress 资源中定义的规则来控制。您将在接下来的两个示例中了解更多关于流行的 Ingress 网关，*使用 Istio 创建 Ingress 服务和服务网格*和*使用 Linkerd 创建 Ingress 服务和服务网格*。

## 另请参阅

+   Kubernetes 关于负载均衡器服务类型的文档：[`kubernetes.io/docs/concepts/services-networking/service/#loadbalancer`](https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer)

+   在 Amazon EKS 上使用负载均衡器：[`docs.aws.amazon.com/eks/latest/userguide/load-balancing.html`](https://docs.aws.amazon.com/eks/latest/userguide/load-balancing.html)

+   在 AKS 上使用负载均衡器：[`docs.microsoft.com/en-us/azure/aks/load-balancer-standard`](https://docs.microsoft.com/en-us/azure/aks/load-balancer-standard)

+   在阿里云上使用负载均衡器：[`www.alibabacloud.com/help/doc-detail/53759.htm`](https://www.alibabacloud.com/help/doc-detail/53759.htm)

+   私有 Kubernetes 集群的负载均衡器：[`blog.alexellis.io/ingress-for-your-local-kubernetes-cluster/`](https://blog.alexellis.io/ingress-for-your-local-kubernetes-cluster/)

# 使用 Istio 创建 Ingress 服务和服务网格

Istio 是一个流行的开源服务网格。在本节中，我们将启动并运行基本的 Istio 服务网格功能。您将学习如何创建一个服务网格来保护、连接和监控微服务。

服务网格是一个非常详细的概念，我们不打算解释任何详细的用例。相反，我们将专注于启动和运行我们的服务。

## 准备工作

确保您已经准备好一个 Kubernetes 集群，并且已经配置好`kubectl`和`helm`来管理集群资源。

将`https://github.com/istio/istio`存储库克隆到您的工作站，如下所示：

```
$ git clone https://github.com/istio/istio.git 
$ cd istio
```

我们将使用前面的存储库中的示例，在我们的 Kubernetes 集群上安装 Istio。

## 如何做…

这一部分进一步分为以下小节，以使这个过程更容易：

+   使用 Helm 安装 Istio

+   验证安装

+   创建入口网关

### 使用 Helm 安装 Istio

让我们执行以下步骤来安装 Istio：

1.  在部署 Istio 之前，创建所需的 Istio CRD：

```
$ helm install install/kubernetes/helm/istio-init --name istio-init \
--namespace istio-system
```

1.  使用默认配置安装 Istio。这将部署 Istio 核心组件，即`istio-citadel`、`istio-galley`、`istio-ingressgateway`、`istio-pilot`、`istio-policy`、`istio-sidecar-injector`和`istio-telemetry`：

```
$ helm install install/kubernetes/helm/istio --name istio \
--namespace istio-system
```

1.  通过为将运行应用程序的命名空间添加标签来启用自动 sidecar 注入。在本示例中，我们将使用`default`命名空间：

```
$ kubectl label namespace default istio-injection=enabled
```

为了使您的应用程序能够获得 Istio 功能，pod 需要运行一个 Istio sidecar 代理。上面的命令将自动注入 Istio sidecar。作为替代方案，您可以在*安装 Istio sidecar 说明*链接中找到使用`istioctl`命令手动向您的 pod 添加 Istio sidecar 的说明。

### 验证安装

让我们执行以下步骤来确认 Istio 已成功安装：

1.  检查已创建的 Istio CRD 的数量。以下命令应返回`23`，这是 Istio 创建的 CRD 的数量：

```
$ kubectl get crds | grep 'istio.io' | wc -l
23
```

1.  运行以下命令并确认已创建 Istio 核心组件服务的列表：

```
$ kubectl get svc -n istio-system
NAME                   TYPE         CLUSTER-IP     EXTERNAL-IP PORT(S)             AGE
istio-citadel          ClusterIP    100.66.235.211 <none>      8060/TCP,...        2m10s
istio-galley           ClusterIP    100.69.206.64  <none>      443/TCP,...         2m11s
istio-ingressgateway   LoadBalancer 100.67.29.143  domain.com  15020:31452/TCP,... 2m11s
istio-pilot            ClusterIP    100.70.130.148 <none>      15010/TCP,...       2m11s
istio-policy           ClusterIP    100.64.243.176 <none>      9091/TCP,...        2m11s
istio-sidecar-injector ClusterIP    100.69.244.156 <none>      443/TCP,...         2m10s
istio-telemetry        ClusterIP    100.68.146.30  <none>      9091/TCP,...        2m11s
prometheus             ClusterIP    100.71.172.191 <none>      9090/TCP            2m11s
```

1.  确保列出的所有 pod 都处于`Running`状态：

```
$ kubectl get pods -n istio-system
```

1.  确认启用了 Istio 注入的命名空间。您应该只在`default`命名空间中看到`istio-injection`：

```
$ kubectl get namespace -L istio-injection
NAME            STATUS AGE  ISTIO-INJECTION
default         Active 5d8h enabled
istio-system    Active 40m
kube-node-lease Active 5d8h
kube-public     Active 5d8h
kube-system     Active 5d8h
```

您可以通过为命名空间添加`istio-injection=enabled`标签来始终启用其他命名空间的注入。

### 创建入口网关

Istio 使用网关而不是控制器来负载均衡流量。让我们执行以下步骤来为我们的示例应用程序创建一个 Istio 入口网关：

1.  在`src/chapter7/lb`目录中的示例目录中查看`minio.yaml`文件的内容，并使用以下命令部署它。这将创建一个 StatefulSet 和一个服务，其中 MinIO 端口通过端口号`9000`在集群内部公开。您也可以选择应用相同的步骤并为您自己的应用程序创建一个入口网关。在这种情况下，跳到*步骤 2*：

```
$ kubectl apply -f minio.yaml
```

1.  获取入口 IP 和端口：

```
$ export INGRESS_HOST=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
$ export INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].port}')
$ export SECURE_INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="https")].port}')
```

1.  创建一个新的 Istio 网关：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
 name: minio-gateway
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
EOF
```

1.  创建一个新的`VirtualService`来通过网关转发请求到 MinIO 实例。这有助于为网关指定路由并将网关绑定到`VirtualService`：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
 name: minio
spec:
 hosts:
 - "*"
 gateways:
 - minio-gateway.default
 http:
 - match:
 - uri:
 prefix: /
 route:
 - destination:
 port:
 number: 9000
 host: minio
EOF
```

这个配置将使用 Istio 将您的服务暴露给外部访问，并且您将对规则有更多的控制。

## 工作原理...

这个教程向您展示了如何快速配置 Istio 服务网格，并使用自定义的 Istio 资源，如入口网关来向外部开放服务。

为了使服务网格正常运行，网格中的每个 pod 都需要运行一个 Envoy sidecar。在*使用 Helm 安装 Istio*的步骤 3 中，我们启用了对`default`命名空间中的 pod 的自动注入，以便在该命名空间中部署的 pod 将运行 Envoy sidecar。

入口控制器是在 Kubernetes 集群中运行并配置路由规则的反向代理。在*创建入口网关*的步骤 2 中，与传统的 Kubernetes 入口对象不同，我们使用了 Istio CRD，如 Gateway、VirtualService 和 DestinationRule 来创建入口。

我们使用`istio: ingressgateway`选择器为入口网关创建了一个网关规则，以便在端口号`80`上接受 HTTP 流量。

在*步骤 4*中，我们为我们想要暴露的 MinIO 服务创建了一个 VirtualService。由于网关可能在不同的命名空间中，我们使用`minio-gateway.default`来设置网关名称。

通过这样，我们已经使用 HTTP 暴露了我们的服务。您可以通过查看*另请参阅*部分中的链接来了解如何使用 HTTPS 协议暴露服务。

## 还有更多...

尽管它非常受欢迎，但 Istio 并不是最简单的入口处理方式。我们强烈建议您查看所有适用于您的用例的选项，并考虑替代方案。因此，了解如何删除 Istio 是很有用的。

### 删除 Istio

您可以使用以下命令删除 Istio：

```
$ helm delete istio
$ helm delete istio-init
```

如果您想要完全删除 Helm 记录中的已删除发布记录，并释放发布名称以供以后使用，可以在前面的命令中添加`--purge`参数。

## 另请参阅

+   Istio 文档：[`istio.io/docs/`](https://istio.io/docs/)

+   Istio 示例：[`istio.io/docs/examples/bookinfo/`](https://istio.io/docs/examples/bookinfo/)

+   安装 Istio sidecar：[`istio.io/docs/setup/additional-setup/sidecar-injection/`](https://istio.io/docs/setup/additional-setup/sidecar-injection/)

+   来自 Kelsey Hightower 的 Istio 入口教程：[`github.com/kelseyhightower/istio-ingress-tutorial`](https://github.com/kelseyhightower/istio-ingress-tutorial)

+   使用 Istio 进行流量管理：[`istio.io/docs/tasks/traffic-management/`](https://istio.io/docs/tasks/traffic-management/)

+   使用 Istio 进行安全：[`istio.io/docs/tasks/security/`](https://istio.io/docs/tasks/security/)

+   使用 Istio 进行策略强制：[`istio.io/docs/tasks/policy-enforcement/`](https://istio.io/docs/tasks/policy-enforcement/)

+   使用 Istio 收集遥测信息：[`istio.io/docs/tasks/telemetry/`](https://istio.io/docs/tasks/telemetry/)

+   使用 Cert-Manager 创建 Kubernetes 入口：[`istio.io/docs/tasks/traffic-management/ingress/ingress-certmgr/`](https://istio.io/docs/tasks/traffic-management/ingress/ingress-certmgr/)

# 使用 Linkerd 创建入口服务和服务网格

在本节中，我们将启动基本的 Linkerd 服务网格。您将学习如何创建一个服务网格来保护、连接和监视微服务。

服务网格本身是一个非常详细的概念，我们不打算在这里解释任何详细的用例。相反，我们将专注于启动和运行我们的服务。

## 准备工作

确保您已准备好 Kubernetes 集群，并配置了`kubectl`和`helm`来管理集群资源。

要访问此示例的文件，请将`k8sdevopscookbook/src`存储库克隆到您的工作站，以使用`src/chapter7/linkerd`目录中的配置文件，如下所示：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
$ cd src/chapter7/linkerd/
```

在克隆了上述存储库之后，您可以开始使用这些示例。

## 如何做…

为了使这个过程更容易，本节进一步分为以下小节：

+   安装 Linkerd CLI

+   安装 Linkerd

+   验证 Linkerd 部署

+   查看 Linkerd 指标

### 安装 Linkerd CLI

要与 Linkerd 交互，您需要安装`linkerd` CLI。按照以下步骤进行：

1.  通过运行以下命令安装`linkerd` CLI：

```
$ curl -sL https://run.linkerd.io/install | sh
```

1.  将`linkerd` CLI 添加到您的路径：

```
$ export PATH=$PATH:$HOME/.linkerd2/bin
```

1.  通过运行以下命令验证`linkerd` CLI 是否已安装。由于我们尚未安装，它应显示服务器不可用：

```
$ linkerd version
Client version: stable-2.5.0
Server version: unavailable
```

1.  验证`linkerd`是否可以安装。此命令将检查集群并指出存在的问题：

```
$ linkerd check --pre
Status check results are √
```

如果状态检查看起来不错，您可以继续下一个示例。

### 安装 Linkerd

与其他选择相比，Linkerd 更容易入门和管理，因此它是我首选的服务网格。

使用 Linkerd CLI 安装 Linkerd 控制平面。此命令将使用默认选项并在`linkerd`命名空间中安装 linkerd 组件：

```
$ linkerd install | kubectl apply -f -
```

拉取所有容器镜像可能需要一分钟左右。之后，您可以通过以下步骤验证组件的健康状况，*验证 Linkerd 部署*。

### 验证 Linkerd 部署

验证 Linkerd 的部署与安装过程一样简单。

运行以下命令验证安装。这将显示控制平面组件和 API 的长摘要，并确保您正在运行最新版本：

```
$ linkerd check
...

control-plane-version
---------------------
√ control plane is up-to-date
√ control plane and cli versions match

Status check results are √
```

如果状态检查良好，您可以准备使用示例应用程序测试 Linkerd。

### 将 Linkerd 添加到服务

按照以下步骤将 Linkerd 添加到我们的演示应用程序中：

1.  切换到`linkerd`文件夹：

```
$ cd /src/chapter7/linkerd
```

1.  部署使用 gRPC 和 HTTP 调用混合为用户提供投票应用程序的演示应用程序：

```
$ kubectl apply -f emojivoto.yml
```

1.  获取演示应用程序的服务 IP。以下命令将返回应用程序的外部可访问地址：

```
$ SERVICE_IP=http://$(kubectl get svc web-svc -n emojivoto \
-o jsonpath='{.status.loadBalancer.ingress[0].hostname}:{.spec.ports[].targetPort}')
$ echo $SERVICE_IP
```

1.  在 Web 浏览器中打开*步骤 3*中的外部地址，并确认应用程序是否正常运行：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/d32ad784-1d4e-49cb-a1d3-90a8e88004d6.png)

1.  通过为将运行应用程序的命名空间打标签来启用自动注入 sidecar。在这个示例中，我们使用了`emojivoto`命名空间：

```
$ kubectl label namespace emojivoto linkerd.io/inject=enabled
```

您还可以通过在运行应用程序的 pod 上手动注入`linkerd` sidecar 来手动注入：

`kubectl get -n emojivoto deploy -o yaml | linkerd inject - | kubectl apply -f -` 命令。在这个示例中，使用了`emojivoto`命名空间。

## 还有更多...

本节进一步分为以下子节，以使该过程更容易：

+   访问仪表板

+   删除 Linkerd

### 访问仪表板

我们可以使用端口转发或使用入口来访问仪表板。让我们从简单的方法开始，也就是通过端口转发到您的本地系统：

1.  通过运行以下命令查看 Linkerd 仪表板：

```
$ linkerd dashboard &
```

1.  在浏览器中访问以下链接以查看仪表板：

```
http://127.0.0.1:50750
```

上述命令将从您的本地系统设置端口转发到`linkerd-web` pod。

如果您想从外部 IP 访问仪表板，请按照以下步骤操作：

1.  下载示例的入口定义：

```
$ wget https://raw.githubusercontent.com/k8sdevopscookbook/src/master/chapter7/linkerd/ingress-nginx.yaml
```

1.  在`src/chapter7/linkerd`目录中的`ingress-nginx.yaml`文件中编辑入口配置，并将第 27 行的`- host`: `dashboard.example.com`更改为您希望暴露仪表板的 URL。使用以下命令应用配置：

```
$ kubectl apply -f ingress-nginx.yaml
```

上述示例文件使用`linkerddashboard.containerized.me`作为仪表板地址。它还使用`admin/admin`凭据对访问进行保护。强烈建议您通过更改配置中`auth`部分中定义的 base64 编码的密钥对来使用自己的凭据，格式为`username:password`。

### 删除 Linkerd

要删除 Linkerd 控制平面，请运行以下命令：

```
$ linkerd install --ignore-cluster | kubectl delete -f -
```

此命令将拉取 Linkerd 控制平面的所有配置文件列表，包括命名空间、服务账户和 CRD，并将它们删除。

## 另请参阅

+   Linkerd 文档：[`linkerd.io/2/overview/`](https://linkerd.io/2/overview/)

+   使用 Linkerd 的常见任务：[`linkerd.io/2/tasks/`](https://linkerd.io/2/tasks/)

+   Linkerd 常见问题和答案：[`linkerd.io/2/faq/`](https://linkerd.io/2/faq/)

# Kubernetes 中的自动修复 Pods

Kubernetes 在集群级别具有自愈能力。它在容器失败时重新启动容器，在节点死机时重新调度 Pod，甚至杀死不响应用户定义的健康检查的容器。

在本节中，我们将执行应用程序和集群扩展任务。您将学习如何使用存活探针和就绪探针来监视容器健康，并在失败时触发重新启动操作。

## 准备工作

确保您有一个准备好的 Kubernetes 集群，并配置`kubectl`和`helm`来管理集群资源。

## 操作步骤：

本节进一步分为以下子节，以使此过程更加简单：

+   测试自愈 Pod

+   向 Pod 添加存活探针

### 测试自愈 Pod

在这个示例中，我们将手动删除部署中的 Pod，以展示 Kubernetes 如何替换它们。稍后，我们将学习如何使用用户定义的健康检查来自动化这个过程。现在，让我们测试 Kubernetes 对被销毁的 Pod 的自愈能力：

1.  创建具有两个或更多副本的部署或 StatefulSet。例如，我们将使用在上一章中使用的 MinIO 应用程序，在*配置和管理 S3 对象存储使用 MinIO*示例中。此示例有四个副本：

```
$ cd src/chapter7/autoheal/minio
$ kubectl apply -f minio.yaml
```

1.  列出作为 StatefulSet 的一部分部署的 MinIO pods。您会看到四个 pods：

```
$ kubectl get pods |grep minio
minio-0 1/1 Running 0 4m38ms
minio-1 1/1 Running 0 4m25s
minio-2 1/1 Running 0 4m12s
minio-3 1/1 Running 0 3m48s
```

1.  删除一个 pod 来测试 Kubernetes 的自愈功能，然后立即再次列出 pods。您会看到被终止的 pod 将被快速重新调度和部署：

```
$ kubectl delete pod minio-0
pod "minio-0" deleted
$ kubectl get pods |grep miniominio-0
minio-0 0/1 ContainerCreating 0 2s
minio-1 1/1 Running           0 8m9s
minio-2 1/1 Running           0 7m56s
minio-3 1/1 Running           0 7m32s
```

通过手动销毁一个正在运行的 pod 来测试 Kubernetes 的自愈功能。现在，我们将学习如何向 pods 添加健康状态检查，以便 Kubernetes 自动杀死无响应的 pods，然后重新启动它们。

### 向 pods 添加活跃性探测

Kubernetes 使用活跃性探测来确定何时重新启动容器。可以通过在容器内运行活跃性探测命令并验证它通过 TCP 套接字活跃性探测返回`0`，或者通过向指定路径发送 HTTP 请求来检查活跃性。在这种情况下，如果路径返回成功代码，那么 kubelet 将认为容器是健康的。在本示例中，我们将学习如何向示例应用程序发送 HTTP 请求方法。让我们执行以下步骤来添加活跃性探测：

1.  编辑`src/chapter7/autoheal/minio`目录中的`minio.yaml`文件，并在`volumeMounts`部分下面添加以下`livenessProbe`部分，然后再添加`volumeClaimTemplates`。您的 YAML 清单应该类似于以下内容。这将每`20`秒向`/minio/health/live`位置发送 HTTP 请求以验证其健康状况：

```
...
        volumeMounts:
        - name: data
          mountPath: /data
#### Starts here 
        livenessProbe:
          httpGet:
            path: /minio/health/live
            port: 9000
          initialDelaySeconds: 120
          periodSeconds: 20
#### Ends here 
  # These are converted to volume claims by the controller
  # and mounted at the paths mentioned above.
  volumeClaimTemplates:
```

对于使用 HTTP 请求进行活跃性探测的应用程序，需要公开未经身份验证的健康检查端点。在我们的示例中，MinIO 通过`/minio/health/live`端点提供此功能。如果您的工作负载没有类似的端点，您可能希望在 pod 内部使用活跃性命令来验证其健康状况。

1.  部署应用程序。它将创建四个 pods：

```
$ kubectl apply -f minio.yaml
```

1.  通过描述其中一个 pods 来确认活跃性探测。您将看到类似以下的`Liveness`描述：

```
$ kubectl describe pod minio-0
...
 Liveness: http-get http://:9000/minio/health/live delay=120s timeout=1s period=20s #success=1 #failure=3
...
```

1.  为了测试活动探测，我们需要再次编辑`minio.yaml`文件。这次，将`livenessProbe`端口设置为`8000`，这是应用程序无法响应 HTTP 请求的地方。重复*步骤 2*和*3*，重新部署应用程序，并检查 pod 描述中的事件。您将在事件中看到一个`minio failed liveness probe, will be restarted`消息：

```
$ kubectl describe pod minio-0
```

1.  您可以通过列出 pod 来确认重启。您会看到每个 MinIO pod 由于具有失败的活动状态而多次重新启动：

```
$ kubectl get pods
NAME    READY STATUS  RESTARTS AGE
minio-0 1/1   Running 4        12m
minio-1 1/1   Running 4        12m
minio-2 1/1   Running 3        11m
minio-3 1/1   Running 3        11m
```

在这个教程中，您学会了如何为在 Kubernetes 集群中运行的应用程序实现自动修复功能。

## 工作原理...

这个教程向您展示了如何在 Kubernetes 上运行的应用程序中使用活动探测。

在*向 pod 添加活动探测*教程中，在*步骤 1*中，我们添加了基于 HTTP 请求的健康检查。

通过添加 StatefulSet 路径和端口，我们让 kubelet 探测定义的端点。在这里，`initialDelaySeconds`字段告诉 kubelet 在第一次探测之前应该等待`120`秒。如果您的应用程序需要一段时间才能准备好端点，那么请确保在第一次探测之前允许足够的时间；否则，您的 pod 将在端点能够响应请求之前重新启动。

在*步骤 3*中，`periodSeconds`字段指定 kubelet 应每`20`秒执行一次活动探测。同样，根据应用程序的预期可用性，您应该设置适合您的应用程序的周期。

## 另请参阅

+   配置活动探测和就绪探测：[`kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/`](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)

+   Kubernetes 最佳实践：设置健康检查：[`cloud.google.com/blog/products/gcp/kubernetes-best-practices-setting-up-health-checks-with-readiness-and-liveness-probes`](https://cloud.google.com/blog/products/gcp/kubernetes-best-practices-setting-up-health-checks-with-readiness-and-liveness-probes)

# 通过蓝/绿部署管理升级

蓝绿部署架构是一种方法，用于通过运行两个可以在需要时切换的相同的生产环境来减少停机时间。这两个环境被标识为蓝色和绿色。在本节中，我们将执行滚动应用程序升级。您将学习如何使用 Kubernetes 中的蓝绿部署来滚动应用程序的新版本并使用持久存储。

## 准备工作

确保您已准备好一个 Kubernetes 集群，并配置了`kubectl`和`helm`来管理集群资源。

对于这个步骤，我们将需要一个持久存储提供程序，以从应用程序的一个版本中获取快照，并使用另一个版本的应用程序的克隆来保持持久卷内容。我们将使用 OpenEBS 作为持久存储提供程序，但您也可以使用任何兼容 CSI 的存储提供程序。

确保 OpenEBS 已经配置了 cStor 存储引擎，方法是按照第五章中的说明进行操作，即*准备有状态工作负载*，在*使用 OpenEBS 进行持久存储*的步骤中。

## 如何做…

本节进一步分为以下子节，以使此过程更容易：

+   创建蓝色部署

+   创建绿色部署

+   从蓝色切换到绿色的流量

### 创建蓝色部署

有许多传统工作负载无法与 Kubernetes 的滚动更新方式配合使用。如果您的工作负载需要部署新版本并立即切换到新版本，则可能需要执行蓝绿部署。使用蓝绿部署方法，我们将标记当前生产环境为蓝色。在下一个步骤中，我们将创建一个名为绿色的相同生产环境，然后将服务重定向到绿色。

让我们执行以下步骤来创建第一个应用程序，我们将其称为蓝色：

1.  切换到此步骤示例所在的目录：

```
$ cd /src/chapter7/bluegreen
```

1.  查看`blue-percona.yaml`文件的内容，并使用它来创建应用程序的蓝色版本：

```
$ kubectl create -f blue-percona.yaml
pod "blue" created
persistentvolumeclaim "demo-vol1-claim" created
```

1.  查看`percona-svc.yaml`文件的内容，并使用它来创建服务。您将看到服务中的`selector`设置为`app: blue`。此服务将所有 MySQL 流量转发到蓝色 pod：

```
$ kubectl create -f percona-svc.yaml
```

1.  获取`percona`的服务 IP。在我们的示例中，集群 IP 为`10.3.0.75`：

```
$ kubectl get svc percona
NAME TYPE CLUSTER-IP EXTERNAL-IP PORT(S) AGE
percona ClusterIP 10.3.0.75 <none> 3306/TCP 1m
```

1.  编辑`sql-loadgen.yaml`文件，并将目标 IP 地址替换为您的 percona 服务 IP。在我们的示例中，它是`10.3.0.75`：

```
      containers:
      - name: sql-loadgen
        image: openebs/tests-mysql-client
        command: ["/bin/bash"]
        args: ["-c", "timelimit -t 300 sh MySQLLoadGenerate.sh 10.3.0.75 > /dev/null 2>&1; exit 0"]
        tty: true
```

1.  通过运行`sql-loadgen.yaml`作业来启动负载生成器：

```
$ kubectl create -f sql-loadgen.yaml
```

此作业将生成针对 Percona 工作负载（当前为蓝色）转发的服务的 IP 的 MySQL 负载。

### 创建绿色部署

让我们执行以下步骤来部署应用程序的新版本作为我们的绿色部署。我们将把服务切换到绿色，对蓝色的持久卷进行快照，并在新的 pod 中部署绿色工作负载：

1.  让我们创建蓝色应用程序 PVC 的数据快照，并使用它来部署绿色应用程序：

```
$ kubectl create -f snapshot.yaml
volumesnapshot.volumesnapshot.external-storage.k8s.io "snapshot-blue" created
```

1.  审查`green-percona.yaml`文件的内容，并使用它来创建应用的绿色版本：

```
$ kubectl create -f green-percona.yaml
pod "green" created
persistentvolumeclaim "demo-snap-vol-claim" created
```

这个 pod 将使用蓝色应用程序的 PVC 的快照作为其原始 PVC。

### 从蓝色切换到绿色的流量

让我们执行以下步骤，将流量从蓝色切换到新的绿色部署：

使用以下命令编辑服务，并将`blue`替换为`green`。服务流量将被转发到标记为`green`的 pod：

```
$ kubectl edit svc percona
```

在这个示例中，您已经学会了如何使用蓝/绿部署策略升级具有有状态工作负载的应用程序。

## 另请参阅

+   在 Kubernetes 中使用 Jenkins 进行零停机部署：[`kubernetes.io/blog/2018/04/30/zero-downtime-deployment-kubernetes-jenkins/`](https://kubernetes.io/blog/2018/04/30/zero-downtime-deployment-kubernetes-jenkins/)

+   蓝/绿部署的简单指南：[`codefresh.io/kubernetes-tutorial/blue-green-deploy/`](https://codefresh.io/kubernetes-tutorial/blue-green-deploy/)

+   Kubernetes 蓝绿部署示例：[`github.com/ContainerSolutions/k8s-deployment-strategies/tree/master/blue-green`](https://github.com/ContainerSolutions/k8s-deployment-strategies/tree/master/blue-green)
