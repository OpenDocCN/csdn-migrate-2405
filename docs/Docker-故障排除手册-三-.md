# Docker 故障排除手册（三）

> 原文：[`zh.annas-archive.org/md5/26C3652580332746A9E26A30363AEFD3`](https://zh.annas-archive.org/md5/26C3652580332746A9E26A30363AEFD3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 Kubernetes 管理 Docker 容器

在上一章中，我们学习了 Docker 网络和如何解决网络问题。在本章中，我们将介绍 Kubernetes。

Kubernetes 是一个容器集群管理工具。目前，它支持 Docker 和 Rocket。这是谷歌的一个开源项目，于 2014 年 6 月在 Google I/O 上发布。它支持在各种云提供商上部署，如 GCE、Azure、AWS、vSphere 和裸机。Kubernetes 管理器是精简的、可移植的、可扩展的和自愈的。

在本章中，我们将涵盖以下内容：

+   Kubernetes 简介

+   在裸机上部署 Kubernetes

+   在 Minikube 上部署 Kubernetes

+   在 AWS 和 vSphere 上部署 Kubernetes

+   部署一个 pod

+   在生产环境中部署 Kubernetes

+   调试 Kubernetes 问题

Kubernetes 有各种重要组件，如下：

+   **节点**：这是 Kubernetes 集群的一部分的物理或虚拟机，运行 Kubernetes 和 Docker 服务，可以在其上调度 pod。

+   **主节点**：这个节点维护 Kubernetes 服务器运行时的运行状态。这是所有客户端调用配置和管理 Kubernetes 组件的入口点。

+   **Kubectl**：这是用于与 Kubernetes 集群交互以提供对 Kubernetes API 的主访问权限的命令行工具。通过它，用户可以部署、删除和列出 pod。

+   **Pod**：这是 Kubernetes 中最小的调度单元。它是一组共享卷并且没有端口冲突的 Docker 容器集合。可以通过定义一个简单的 JSON 文件来创建它。

+   **复制控制器**：这个控制 pod 的生命周期，并确保在任何给定时间运行指定数量的 pod，通过根据需要创建或销毁 pod。

+   **标签**：标签用于基于键值对标识和组织 pod 和服务：![使用 Kubernetes 管理 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_08_001.jpg)

Kubernetes 主/从流程

# 在裸机上部署 Kubernetes

Kubernetes 可以部署在裸机 Fedora 或 Ubuntu 机器上。甚至 Fedora 和 Ubuntu 虚拟机可以部署在 vSphere、工作站或 VirtualBox 上。在以下教程中，我们将介绍在单个 Fedora 24 机器上部署 Kubernetes，该机器将充当主节点，以及部署`k8s` pod 的节点：

1.  启用 Kubernetes 测试 YUM 仓库：

```
 yum -y install --enablerepo=updates-testing kubernetes

```

1.  安装`etcd`和`iptables-services`：

```
 yum -y install etcd iptables-services

```

1.  在`/etcd/hosts`中，设置 Fedora 主节点和 Fedora 节点：

```
 echo "192.168.121.9  fed-master 
        192.168.121.65  fed-node" >> /etc/hosts

```

1.  禁用防火墙和`iptables-services`：

```
 systemctl disable iptables-services firewalld 
        systemctl stop iptables-services firewalld

```

1.  编辑`/etcd/kubernetes/config`文件：

```
 # Comma separated list of nodes in the etcd cluster
        KUBE_MASTER="--master=http://fed-master:8080"
        # logging to stderr means we get it in the systemd journal
        KUBE_LOGTOSTDERR="--logtostderr=true"
        # journal message level, 0 is debug
        KUBE_LOG_LEVEL="--v=0"
        # Should this cluster be allowed to run privileged docker 
        containers
        KUBE_ALLOW_PRIV="--allow-privileged=false"

```

1.  编辑`/etc/kubernetes/apiserver`文件的内容：

```
 # The address on the local server to listen to. 
        KUBE_API_ADDRESS="--address=0.0.0.0" 

        # Comma separated list of nodes in the etcd cluster 
        KUBE_ETCD_SERVERS="--etcd-servers=http://127.0.0.1:2379" 

        # Address range to use for services         
        KUBE_SERVICE_ADDRESSES="--service-cluster-ip-
        range=10.254.0.0/16" 

        # Add your own! 
        KUBE_API_ARGS=""

```

1.  `/etc/etcd/etcd.conf`文件应该取消注释以下行，以便在端口`2379`上进行监听，因为 Fedora 24 使用 etcd 2.0：

```
 ETCD_LISTEN_CLIENT_URLS="http://0.0.0.0:2379"

```

1.  **Kubernetes 节点设置可以在单独的主机上完成，但我们将在当前机器上设置它们，以便在同一台机器上配置 Kubernetes 主节点和节点：**

1.  **编辑`/etcd/kubernetes/kubelet`文件如下：**

```
 ### 
        # Kubernetes kubelet (node) config 

        # The address for the info server to serve on (set to 0.0.0.0 
        or "" for 
        all interfaces) 
        KUBELET_ADDRESS="--address=0.0.0.0" 

        # You may leave this blank to use the actual hostname 
        KUBELET_HOSTNAME="--hostname-override=fed-node" 

        # location of the api-server 
        KUBELET_API_SERVER="--api-servers=http://fed-master:8080" 

        # Add your own! 
        #KUBELET_ARGS=""

```

1.  创建一个 shell 脚本在同一台机器上启动所有 Kubernetes 主节点和节点服务：

```
 $ nano start-k8s.sh 
        for SERVICES in etcd kube-apiserver kube-controller-manager 
        kube-scheduler 
        kube-proxy kubelet docker; do  
            systemctl restart $SERVICES 
            systemctl enable $SERVICES 
            systemctl status $SERVICES  
        done

```

1.  在 Kubernetes 机器上创建一个`node.json`文件来配置它：

```
        { 
            "apiVersion": "v1", 
            "kind": "Node", 
            "metadata": { 
                "name": "fed-node", 
                "labels":{ "name": "fed-node-label"} 
            }, 
            "spec": { 
                "externalID": "fed-node" 
            } 
        } 

```

1.  使用以下命令创建一个节点对象：

```
 $ kubectl create -f ./node.json 

        $ kubectl get nodes 
        NAME               LABELS                  STATUS 
        fed-node           name=fed-node-label     Unknown

```

1.  一段时间后，节点应该准备好部署 pod：

```
 kubectl get nodes 
        NAME                LABELS                  STATUS 
        fed-node            name=fed-node-label     Ready

```

# 故障排除 Kubernetes Fedora 手动设置

如果 kube-apiserver 启动失败，可能是由于服务账户准入控制，需要在允许调度 pod 之前提供服务账户和令牌。它会被控制器自动生成。默认情况下，API 服务器使用 TLS 服务密钥，但由于我们不是通过 HTTPS 发送数据，也没有 TLS 服务器密钥，我们可以提供相同的密钥文件给 API 服务器，以便 API 服务器验证生成的服务账户令牌。

使用以下内容生成密钥并将其添加到`k8s`集群中：

```
 openssl genrsa -out /tmp/serviceaccount.key 2048

```

要启动 API 服务器，在`/etc/kubernetes/apiserver`文件的末尾添加以下选项：

```
 KUBE_API_ARGS="--
         service_account_key_file=/tmp/serviceaccount.key"

```

在`/etc/kubernetes/kube-controller-manager`文件的末尾添加以下选项：

```
 KUBE_CONTROLLER_MANAGER_ARGS=" -
 service_account_private_key_file
        =/tmp/serviceaccount.key"

```

使用`start_k8s.sh` shell 脚本重新启动集群。

# 使用 Minikube 部署 Kubernetes

Minikube 仍在开发中；它是一个工具，可以方便地在本地运行 Kubernetes，针对底层操作系统进行了优化（MAC/Linux）。它在虚拟机内运行单节点 Kubernetes 集群。Minikube 帮助开发人员学习 Kubernetes，并轻松进行日常开发和测试。

以下设置将涵盖 Mac OS X 上的 Minikube 设置，因为很少有指南可以部署 Kubernetes 在 Mac 上：

1.  下载 Minikube 二进制文件：

```
 $ curl -Lo minikube
 https://storage.googleapis.com/minikube/releases/v0.12.2/minikube-darwin-amd64
 % Total % Received % Xferd Average Speed Time Time Time Current
 Dload Upload Total Spent Left Speed
 100 79.7M 100 79.7M 0 0 1857k 0 0:00:43 0:00:43 --:--:-- 1863k

```

1.  授予二进制文件执行权限：

```
 $ chmod +x minikube

```

1.  将 Minikube 二进制文件移动到`/usr/local/bin`，以便将其添加到路径并可以直接在终端上执行：

```
 $ sudo mv minikube /usr/local/bin

```

1.  之后，我们将需要`kubectl`客户端二进制文件来针对 Mac OS X 运行命令单节点 Kubernetes 集群：

```
 $ curl -Lo kubectl https://storage.googleapis.com/kubernetes-release/release/v1.3.0/bin/darwin/amd64/kubectl && chmod +x kubectl && sudo mv kubectl /usr/local/bin/

        https://storage.googleapis.com/kubernetes-release/release/v1.3.0/bin/darwin/amd64/kubectl && chmod +x kubectl && sudo mv kubectl /usr/local/bin/
          % Total % Received % Xferd Average Speed Time Time Time Current
                                     Dload Upload Total Spent Left Speed
        100 53.2M 100 53.2M 0 0 709k 0 0:01:16 0:01:16 --:--:-- 1723k

```

现在已配置 kubectl 以与集群一起使用。

1.  设置 Minikube 以在本地部署 VM 并配置 Kubernetes 集群：

```
 $ minikube start

        Starting local Kubernetes cluster...

        Downloading Minikube ISO

        36.00 MB / 36.00 MB

		[==============================================] 
        100.00% 0s

```

1.  我们可以设置 kubectl 以使用 Minikube 上下文，并在需要时进行切换：

```
 $ kubectl config use-context minikube 
        switched to context "minikube".

```

1.  我们将能够列出 Kubernetes 集群的节点：

```
 $ kubectl get nodes

        NAME       STATUS    AGE
        minikube   Ready     39m

```

1.  创建`hello-minikube` pod 并将其公开为服务：

```
 $ kubectl run hello-minikube --
          image=gcr.io/google_containers/echoserver:1.4 --port=8080

        deployment "hello-minikube" created

        $ kubectl expose deployment hello-minikube --type=NodePort

        service "hello-minikube" exposed

```

1.  我们可以使用以下命令获取`hello-minikube` pod 的状态：

```
 $  kubectl get pod
     NAME                           READY   STATUS    RESTARTS   AGE          hello-minikube-3015430129-otr7u   1/1    running       0          36s
        vkohli-m01:~ vkohli$ curl $(minikube service hello-minikube --url)
        CLIENT VALUES:
        client_address=172.17.0.1
        command=GET
        real path=/
        query=nil
        request_version=1.1
        request_uri=http://192.168.99.100:8080/

        SERVER VALUES:
        server_version=nginx: 1.10.0 - lua: 10001

        HEADERS RECEIVED:
        accept=*/*
        host=192.168.99.100:30167
        user-agent=curl/7.43.0

```

1.  我们可以使用以下命令打开 Kubernetes 仪表板并查看部署的 pod 的详细信息：

```
 $ minikube dashboard

        Opening kubernetes dashboard in default browser...

```

![使用 Minikube 部署 Kubernetes](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_08_002.jpg)

展示 hello-minikube pod 的 Kubernetes UI

# 在 AWS 上部署 Kubernetes

让我们开始在 AWS 上部署 Kubernetes 集群，可以使用 Kubernetes 代码库中已经存在的配置文件来完成。

1.  登录到 AWS 控制台（[`aws.amazon.com/console/`](http://aws.amazon.com/console/)）

1.  打开 IAM 控制台（[`console.aws.amazon.com/iam/home?#home`](https://console.aws.amazon.com/iam/home?))

1.  选择 IAM 用户名，选择**安全凭据**选项卡，然后单击**创建访问密钥**选项。

1.  创建密钥后，下载并保存在安全的位置。下载的 CSV 文件将包含访问密钥 ID 和秘密访问密钥，这将用于配置 AWS CLI。

1.  安装和配置 AWS 命令行界面。在本例中，我们使用以下命令在 Linux 上安装了 AWS CLI：

```
 $ sudo pip install awscli

```

1.  为了配置 AWS-CLI，请使用以下命令：

```
 $ aws configure
 AWS Access Key ID [None]: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
 AWS Secret Access Key [None]: YYYYYYYYYYYYYYYYYYYYYYYYYYYY
 Default region name [None]: us-east-1
 Default output format [None]: text

```

1.  配置 AWS CLI 后，我们将创建一个配置文件，并附加一个具有对 S3 和 EC2 的完全访问权限的角色。

```
 $ aws iam create-instance-profile --instance-profile-name Kube

```

1.  角色可以附加到上述配置文件，该配置文件将具有完全的 EC2 和 S3 访问权限，如下面的屏幕截图所示。可以使用控制台或 AWS CLI 单独创建角色，并使用 JSON 文件定义角色可以具有的权限：

```
 $ aws iam create-role --role-name Test-Role --assume-role-policy-
          document /root/kubernetes/Test-Role-Trust-Policy.json

```

![在 AWS 上部署 Kubernetes](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_08_003.jpg)

在 Kubernetes 部署期间在 AWS 中附加策略

1.  创建角色后，可以使用以下命令将其附加到策略：

```
 $ aws iam add-role-to-instance-profile --role-name Test-Role --
          instance-profile-name Kube

```

1.  脚本使用默认配置文件；我们可以按以下方式更改它：

```
 $ export AWS_DEFAULT_PROFILE=Kube

```

1.  Kubernetes 集群可以使用一个命令轻松部署，如下所示；

```
 $ export KUBERNETES_PROVIDER=aws; wget -q -O - https://get.k8s.io | bash
 Downloading kubernetes release v1.1.1 to /home/vkohli/kubernetes.tar.gz
 --2015-11-22 10:39:18--  https://storage.googleapis.com/kubernetes-
        release/release/v1.1.1/kubernetes.tar.gz
 Resolving storage.googleapis.com (storage.googleapis.com)... 
        216.58.220.48, 2404:6800:4007:805::2010
 Connecting to storage.googleapis.com 
        (storage.googleapis.com)|216.58.220.48|:443... connected.
 HTTP request sent, awaiting response... 200 OK
 Length: 191385739 (183M) [application/x-tar]
 Saving to: 'kubernetes.tar.gz'
 100%[======================================>] 191,385,739 1002KB/s   
        in 3m 7s
 2015-11-22 10:42:25 (1002 KB/s) - 'kubernetes.tar.gz' saved 
        [191385739/191385739]
 Unpacking kubernetes release v1.1.1
 Creating a kubernetes on aws...
 ... Starting cluster using provider: aws
 ... calling verify-prereqs
 ... calling kube-up
 Starting cluster using os distro: vivid
 Uploading to Amazon S3
 Creating kubernetes-staging-e458a611546dc9dc0f2a2ff2322e724a
 make_bucket: s3://kubernetes-staging-e458a611546dc9dc0f2a2ff2322e724a/
 +++ Staging server tars to S3 Storage: kubernetes-staging-
        e458a611546dc9dc0f2a2ff2322e724a/devel
 upload: ../../../tmp/kubernetes.6B8Fmm/s3/kubernetes-salt.tar.gz to 
        s3://kubernetes-staging-e458a611546dc9dc0f2a2ff2322e724a/devel/kubernetes-
        salt.tar.gz
 Completed 1 of 19 part(s) with 1 file(s) remaining

```

1.  上述命令将调用`kube-up.sh`，然后使用`config-default.sh`脚本调用`utils.sh`，该脚本包含具有四个节点的`k8s`集群的基本配置，如下所示：

```
 ZONE=${KUBE_AWS_ZONE:-us-west-2a}
 MASTER_SIZE=${MASTER_SIZE:-t2.micro}
 MINION_SIZE=${MINION_SIZE:-t2.micro}
 NUM_MINIONS=${NUM_MINIONS:-4}
 AWS_S3_REGION=${AWS_S3_REGION:-us-east-1}

```

1.  这些实例是在 Ubuntu 上运行的“t2.micro”。该过程需要五到十分钟，之后主节点和从节点的 IP 地址将被列出，并可用于访问 Kubernetes 集群。

# 在 vSphere 上部署 Kubernetes

可以使用`govc`（基于 govmomi 构建的 vSphere CLI）在 vSphere 上安装 Kubernetes：

1.  在开始设置之前，我们需要在 Linux 机器上安装 golang，可以按以下方式进行：

```
 $ wget https://storage.googleapis.com/golang/go1.7.3.linux-
 amd64.tar.gz

        $ tar -C /usr/local -xzf go1.7.3.linux-amd64.tar.gz

        $ go

        Go is a tool for managing Go source code.
        Usage:
          go command [arguments]

```

1.  设置 go 路径：

```
 $ export GOPATH=/usr/local/go
 $ export PATH=$PATH:$GOPATH/bin

```

1.  下载预构建的 Debian VMDK，该 VMDK 将用于在 vSphere 上创建 Kubernetes 集群：

```
         $ curl --remote-name-all https://storage.googleapis.com/
        govmomi/vmdk/2016-01-08/kube.vmdk.gz{,.md5}
 % Total    % Received % Xferd  Average Speed   Time    Time     Time  
        Current
 Dload  Upload   Total   Spent    Left  
        Speed
         100  663M  100  663M   0   0  14.4M      0  0:00:45  0:00:45 --:--:-- 
        17.4M
         100    47  100    47   0   0     70      0 --:--:-- --:--:-- --:--:--   
        0
         $ md5sum -c kube.vmdk.gz.md5
         kube.vmdk.gz: OK
         $ gzip -d kube.vmdk.gz

```

# Kubernetes 设置故障排除

我们需要设置适当的环境变量以远程连接到 ESX 服务器以部署 Kubernetes 集群。为了在 vSphere 上进行 Kubernetes 设置，应设置以下环境变量：

```
 export GOVC_URL='https://[USERNAME]:[PASSWORD]@[ESXI-HOSTNAME-IP]/sdk'
 export GOVC_DATASTORE='[DATASTORE-NAME]'
 export GOVC_DATACENTER='[DATACENTER-NAME]'
 #username & password used to login to the deployed kube VM
 export GOVC_RESOURCE_POOL='*/Resources'
 export GOVC_GUEST_LOGIN='kube:kube'
 export GOVC_INSECURE=true

```

### 注意

本教程使用 ESX 和 vSphere 版本 v5.5。

将`kube.vmdk`上传到 ESX 数据存储。VMDK 将存储在由以下命令创建的`kube`目录中：

```
 $ govc datastore.import kube.vmdk kube

```

将 Kubernetes 提供程序设置为 vSphere，同时在 ESX 上部署 Kubernetes 集群。这将包含一个 Kubernetes 主节点和四个 Kubernetes 从节点，这些从节点是从上传到数据存储中的扩展的`kube.vmdk`派生出来的：

```
 $ cd kubernetes
 $ KUBERNETES_PROVIDER=vsphere cluster/kube-up.sh

```

这将显示四个 VM 的 IP 地址列表。如果您目前正在开发 Kubernetes，可以使用此集群部署机制以以下方式测试新代码：

```
 $ cd kubernetes
 $ make release
 $ KUBERNETES_PROVIDER=vsphere cluster/kube-up.sh

```

可以使用以下命令关闭集群：

```
 $ cluster/kube-down.sh

```

![Kubernetes 设置故障排除](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_08_004.jpg)

在 vSphere 上部署的 Kubernetes 主节点/从节点

# Kubernetes pod 部署

现在，在以下示例中，我们将部署两个 NGINX 复制 pod（rc-pod）并通过服务公开它们。要了解 Kubernetes 网络，请参考以下图表以获取更多详细信息。在这里，应用程序可以通过虚拟 IP 地址公开，并且服务会代理请求，负载均衡到 pod 的副本：

![Kubernetes pod deployment](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_08_005.jpg)

使用 OVS 桥的 Kubernetes 网络

1.  在 Kubernetes 主节点上，创建一个新文件夹：

```
 $ mkdir nginx_kube_example
 $ cd nginx_kube_example

```

1.  在您选择的编辑器中创建 YAML 文件，该文件将用于部署 NGINX pod：

```
 $ vi nginx_pod.yaml
 apiVersion: v1
 kind: ReplicationController
 metadata:
 name: nginx
 spec:
 replicas: 2
 selector:
 app: nginx
 template:
 metadata:
 name: nginx
 labels:
 app: nginx
 spec:
 containers:
 - name: nginx
 image: nginx
 ports:
 - containerPort: 80

```

1.  使用`kubectl`创建 NGINX pod：

```
 $ kubectl create -f nginx_pod.yaml

```

1.  在前面的 pod 创建过程中，我们创建了两个 NGINX pod 的副本，其详细信息如下所示：

```
 $ kubectl get pods
 NAME          READY     REASON    RESTARTS   AGE
 nginx-karne   1/1       Running   0          14s
 nginx-mo5ug   1/1       Running   0          14s
 $ kubectl get rc
 CONTROLLER   CONTAINER(S)   IMAGE(S)   SELECTOR    REPLICAS
 nginx        nginx          nginx      app=nginx   2

```

1.  可以列出部署的 minion 上的容器如下：

```
         $ docker ps
         CONTAINER ID        IMAGE                                   COMMAND
        CREATED             STATUS              PORTS               NAMES
         1d3f9cedff1d        nginx:latest                            "nginx -g 
        'daemon of   41 seconds ago      Up 40 seconds
        k8s_nginx.6171169d_nginx-karne_default_5d5bc813-3166-11e5-8256-
        ecf4bb2bbd90_886ddf56
         0b2b03b05a8d        nginx:latest                            "nginx -g 
        'daemon of   41 seconds ago      Up 40 seconds

```

1.  使用 YAML 文件部署 NGINX 服务，以便在主机端口`82`上暴露 NGINX pod：

```
 $ vi nginx_service.yaml
 apiVersion: v1
 kind: Service
 metadata:
 labels:
 name: nginxservice
 name: nginxservice
 spec:
 ports:
 # The port that this service should serve on.
 - port: 82
 # Label keys and values that must match in order to receive traffic for 
        this service.
 selector:
 app: nginx
 type: LoadBalancer

```

1.  使用`kubectl`创建 NGINX 服务：

```
 $kubectl create -f nginx_service.yaml
 services/nginxservice

```

1.  可以列出 NGINX 服务如下：

```
         $ kubectl get services
         NAME           LABELS                                   SELECTOR    IP(S)
        PORT(S)
         kubernetes     component=apiserver,provider=kubernetes  <none>      
        192.168.3.1    443/TCP
         nginxservice   name=nginxservice                        app=nginx   
        192.168.3.43   82/TCP

```

1.  现在可以通过以下 URL 访问通过服务访问的 NGINX 服务器测试页面：`http://192.168.3.43:82`

# 在生产环境中部署 Kubernetes

在本节中，我们将介绍一些可以用于在生产环境中部署 Kubernetes 的重要要点和概念。

+   **暴露 Kubernetes 服务**：一旦我们部署了 Kubernetes pod，我们就使用服务来暴露它们。Kubernetes 服务是一个抽象，它定义了一组 pod 和一种将它们作为微服务暴露的策略。服务有自己的 IP 地址，但问题是这个地址只存在于 Kubernetes 集群内，这意味着服务不会暴露到互联网上。可以直接在主机机器端口上暴露服务，但一旦在主机机器上暴露服务，就会出现端口冲突。这也会使 Kubernetes 的优势失效，并且使部署的服务难以扩展：![在生产环境中部署 Kubernetes](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_08_006.jpg)

Kubernetes 服务通过外部负载均衡器暴露

一个解决方案是添加外部负载均衡器，如 HAProxy 或 NGINX。这是为每个 Kubernetes 服务配置一个后端，并将流量代理到各个 pod。类似于 AWS 部署，可以在 VPN 内部部署 Kubernetes 集群，并使用 AWS 外部负载均衡器来暴露每个 Kubernetes 服务：

+   **支持 Kubernetes 中的升级场景**：在升级场景中，我们需要实现零停机。Kubernetes 的外部负载均衡器有助于在通过 Kubernetes 部署服务的情况下实现这种功能。我们可以启动一个运行新版本服务的副本集群，旧的集群版本将为实时请求提供服务。一旦新服务准备就绪，负载均衡器可以配置为将负载切换到新版本。通过使用这种方法，我们可以支持企业产品的零运行时升级场景：![在生产环境中部署 Kubernetes](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_08_007.jpg)

Kubernetes 部署中支持的升级场景

+   **使基于 Kubernetes 的应用部署自动化**：借助部署工具，我们可以自动化测试和在生产环境中部署 Docker 容器的过程。为此，我们需要构建流水线和部署工具，在成功构建后将 Docker 镜像推送到 Docker Hub 这样的注册表。然后，部署工具将负责部署测试环境并调用测试脚本。在成功测试后，部署工具还可以负责在 Kubernetes 生产环境中部署服务。

Kubernetes 应用部署流水线

+   **了解资源约束**：在启动 Kubernetes 集群时了解资源约束，配置每个 pod 的资源请求和 CPU/内存限制。大多数容器在生产环境中崩溃是由于资源不足或内存不足。容器应经过充分测试，并在生产环境中为 pod 分配适当的资源，以成功部署微服务。

+   **监控 Kubernetes 集群**：应该通过日志持续监控 Kubernetes 集群。应使用诸如 Graylog、Logcheck 或 Logwatch 等日志工具与 Apache Kafka 这样的消息系统一起收集容器的日志并将其传送到日志工具中。借助 Kafka，可以轻松索引日志，并处理大量流。Kubernetes 副本运行无误。如果任何 pod 崩溃，Kubernetes 服务会重新启动它们，并根据配置始终保持副本数量正常运行。用户想要了解的一个方面是失败背后的真正原因。Kubernetes 指标和应用指标可以发布到诸如 InfluxDB 这样的时间序列存储中，用于跟踪应用程序错误，并测量负载、吞吐量和其他统计数据，以进行失败后分析。

+   **Kubernetes 中的持久存储**：Kubernetes 具有卷的概念来处理持久数据。在 Kubernetes 的生产部署中，我们希望有持久存储，因为容器在重新启动时会丢失数据。卷由各种实现支持，例如主机机器、NFS 或使用云提供商的卷服务。Kubernetes 还提供了两个 API 来处理持久存储。

+   **持久卷（PV）**：这是在集群中预配的资源，其行为就像节点是集群资源一样。pod 根据需要从持久卷请求资源（CPU 和内存）。通常由管理员进行预配。

+   **持久卷索赔（PVC）**：PVC 消耗 PV 资源。这是用户对存储的请求，类似于 pod。pod 可以根据需要请求资源（CPU 和内存）的级别。

# 调试 Kubernetes 问题

在本节中，我们将讨论一些 Kubernetes 故障排除方面的问题：

1.  调试 Kubernetes 集群的第一步是列出节点的数量，使用以下命令：

```
 $ kubetl get nodes

```

还要验证所有节点是否处于就绪状态。

1.  查看日志以找出部署的 Kubernetes 集群中的问题

```
 master:
 var/log/kube-apiserver.log - API Server, responsible for serving the API
        /var/log/kube-scheduler.log - Scheduler, responsible for making scheduling 
    decisions
        /var/log/kube-controller-manager.log - Controller that manages replication 
    controllers
 Worker nodes:
 /var/log/kubelet.log - Kubelet, responsible for running containers on the 
    node
        /var/log/kube-proxy.log - Kube Proxy, responsible for service load 
    balancing

```

1.  如果 pod 保持在挂起状态，请使用以下命令：

```
 $ cluster/kubectl.sh describe pod podname

```

这将列出事件，并可能描述发生在 pod 上的最后一件事情。

1.  要查看所有集群事件，请使用以下命令：

```
 $ cluster/kubectl.sh get events

```

如果`kubectl`命令行无法到达`apiserver`进程，请确保`Kubernetes_master`或`Kube_Master_IP`已设置。确保`apiserver`进程在主节点上运行，并检查其日志：

+   如果您能够创建复制控制器但看不到 pod：如果复制控制器没有创建 pod，请检查控制器是否正在运行，并查看日志。

+   如果`kubectl`永远挂起或 pod 处于等待状态：

+   检查主机是否被分配给了 pod，如果没有，那么它们目前正在为某些任务进行调度。

+   检查 kubelet 是否指向`etcd`中 pod 的正确位置，`apiserver`是否使用相同的名称或 minion 的 IP。

+   如果出现问题，请检查 Docker 守护程序是否正在运行。还要检查 Docker 日志，并确保防火墙没有阻止从 Docker Hub 获取镜像。

+   `apiserver`进程报告：

+   错误同步容器：`Get http://:10250/podInfo?podID=foo: dial tcp :10250:`**连接被拒绝**：

+   这意味着 pod 尚未被调度

+   检查调度器日志，看看它是否正常运行

+   无法连接到容器

+   尝试 Telnet 到服务端口或 pod 的 IP 地址的 minion

+   使用以下命令检查 Docker 中是否创建了容器：

```
 $ sudo docker ps -a

```

+   如果您看不到容器，则问题可能出在 pod 配置、镜像、Docker 或 kubelet 上。如果您看到容器每 10 秒创建一次，则问题可能出在容器的创建或容器的进程失败。

+   X.509 证书已过期或尚未生效。

检查当前时间是否与客户端和服务器上的时间匹配。使用`ntpdate`进行一次性时钟同步。

# 总结

在本章中，我们学习了如何借助 Kubernetes 管理 Docker 容器。Kubernetes 在 Docker 编排工具中有不同的视角，其中每个 pod 将获得一个唯一的 IP 地址，并且可以借助服务进行 pod 之间的通信。我们涵盖了许多部署场景，以及在裸机、AWS、vSphere 或使用 Minikube 部署 Kubernetes 时的故障排除问题。我们还研究了有效部署 Kubernetes pods 和调试 Kubernetes 问题。最后一部分介绍了在生产环境中部署 Kubernetes 所需的负载均衡器、Kubernetes 服务、监控工具和持久存储。在下一章中，我们将介绍 Docker 卷以及如何在生产环境中有效使用它们。


# 第九章：挂载卷行李

本章介绍了数据卷和存储驱动程序的概念，在 Docker 中被广泛用于管理持久或共享数据。我们还将深入研究 Docker 支持的各种存储驱动程序，以及与其相关的基本命令进行管理。Docker 数据卷的三个主要用例如下：

+   在容器被删除后保持数据持久

+   在主机和 Docker 容器之间共享数据

+   用于在 Docker 容器之间共享数据

为了理解 Docker 卷，我们需要了解 Docker 文件系统的工作原理。Docker 镜像存储为一系列只读层。当容器启动时，只读镜像在顶部添加一个读写层。如果需要修改当前文件，则将其从只读层复制到读写层，然后应用更改。读写层中的文件版本隐藏了底层文件，但并未销毁它。因此，当删除 Docker 容器时，重新启动镜像将启动一个带有全新读写层的全新容器，并且所有更改都将丢失。位于只读层之上的读写层的组合称为**联合文件系统**（**UFS**）。为了持久保存数据并能够与主机和其他容器共享，Docker 提出了卷的概念。基本上，卷是存在于 UFS 之外的目录，并在主机文件系统上表现为普通目录或文件。

Docker 卷的一些重要特性如下：

+   在创建容器时可以初始化卷

+   数据卷可以被重用并在其他数据容器之间共享

+   数据卷即使容器被删除也可以保留数据

+   数据卷的更改是直接进行的，绕过了 UFS

在本章中，我们将涵盖以下内容：

+   仅数据容器

+   托管由共享存储支持的映射卷

+   Docker 存储驱动程序性能

# 通过理解 Docker 卷来避免故障排除

在本节中，我们将探讨处理数据和 Docker 容器的四种方法，这将帮助我们理解并实现前面提到的 Docker 卷的用例。

# 默认情况下将数据存储在 Docker 容器内部

在这种情况下，数据只能在 Docker 容器内部可见，而不是来自主机系统。如果容器关闭或 Docker 主机死机，数据将丢失。这种情况主要适用于打包在 Docker 容器中的服务，并且在它们返回时不依赖于持久数据：

```
$ docker run -it ubuntu:14.04 
root@358b511effb0:/# cd /tmp/ 
root@358b511effb0:/tmp# cat > hello.txt 
hii 
root@358b511effb0:/tmp# ls 
hello.txt 

```

如前面的例子所示，`hello.txt`文件只存在于容器内部，一旦容器关闭，它将不会被保存。

![默认情况下将数据存储在 Docker 容器内部](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_09_001.jpg)

存储在 Docker 容器内部的数据

# 数据专用容器

数据可以存储在 Docker UFS 之外的数据专用容器中。数据将在数据专用容器的挂载命名空间内可见。由于数据持久保存在容器之外，即使容器被删除，数据仍然存在。如果任何其他容器想要连接到这个数据专用容器，只需使用`--volumes-from`选项来获取容器并将其应用到当前容器。让我们尝试使用数据卷容器：

![数据专用容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_09_002.jpg)

使用数据专用容器

## 创建数据专用容器

```
$ docker create -v /tmp --name ubuntuvolume Ubuntu:14.04 

```

在前面的命令中，我们创建了一个 Ubuntu 容器并附加了`/tmp`。它是基于 Ubuntu 镜像的数据专用容器，并存在于`/tmp`目录中。如果新的 Ubuntu 容器需要向我们的数据专用容器的`/tmp`目录写入一些数据，可以通过`--volumes-from`选项实现。现在，我们在新容器的`/tmp`目录中写入的任何内容都将保存在 Ubuntu 数据容器的`/tmp`卷中：

```
$ docker create -v /tmp --name ubuntuvolume ubuntu:14.04 
d694752455f7351e95d1563ed921257654a1867c467a2813ae25e7d99c067234 

```

在容器-1 中使用数据卷容器：

```
$ docker run -t -i --volumes-from ubuntuvolume ubuntu:14.04 /bin/bash 
root@127eba0504cd:/# echo "testing data container" > /tmp/hello 
root@127eba0504cd:/# exit 
exit 

```

在容器-2 中使用数据卷容器来获取容器-1 共享的数据：

```
$ docker run -t -i --volumes-from ubuntuvolume ubuntu:14.04 /bin/bash 
root@5dd8152155de:/# cd tmp/ 
root@5dd8152155de:/tmp# ls 
hello 
root@5dd8152155de:/tmp# cat hello 
testing data container 

```

正如我们所看到的，容器-2 获得了容器-1 在`/tmp`空间中写入的数据。这些示例演示了数据专用容器的基本用法。

## 在主机和 Docker 容器之间共享数据

这是一个常见的用例，需要在主机和 Docker 容器之间共享文件。在这种情况下，我们不需要创建一个数据专用容器；我们可以简单地运行任何 Docker 镜像的容器，并简单地用主机系统目录的内容覆盖其中一个目录。

让我们考虑一个例子，我们想要从主机系统访问 Docker NGINX 的日志。目前，它们在主机外部不可用，但可以通过简单地将容器内的`/var/log/nginx`映射到主机系统上的一个目录来实现。在这种情况下，我们将使用来自主机系统的共享卷运行 NGINX 镜像的副本，如下所示：

![在主机和 Docker 容器之间共享数据](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_09_003.jpg)

在主机和 Docker 容器之间共享数据

在主机系统中创建一个`serverlogs`目录：

```
$ mkdir /home/serverlogs 

```

运行 NGINX 容器，并将`/home/serverlogs`映射到 Docker 容器内的`/var/log/nginx`目录：

```
$ docker run -d -v /home/serverlogs:/var/log/nginx -p 5000:80 nginx 
Unable to find image 'nginx:latest' locally 
latest: Pulling from library/nginx 
5040bd298390: Pull complete 
... 

```

从主机系统访问`http://localhost:5000`，之后将生成日志，并且可以在主机系统中的`/home/serverlogs`目录中访问这些日志，该目录映射到 Docker 容器内的`/var/log/nginx`，如下所示：

```
$ cd serverlogs/ 
$ ls 
access.log  error.log 
$ cat access.log  
172.17.42.1 - - [20/Jan/2017:14:57:41 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:50.0) Gecko/20100101 Firefox/50.0" "-" 

```

# 由共享存储支持的主机映射卷

Docker 卷插件允许我们挂载共享存储后端。这样做的主要优势是用户在主机故障的情况下不会遭受数据丢失，因为它由共享存储支持。在先前的方法中，如果我们迁移容器，卷不会被迁移。可以借助外部 Docker 卷插件实现这一点，例如**Flocker**和**Convy**，它们使卷可移植，并有助于轻松迁移带有卷的容器，同时保护数据，因为它不依赖于主机文件系统。

## Flocker

Flocker 被广泛用于运行容器化的有状态服务和需要持久存储的应用程序。Docker 提供了卷管理的基本视图，但 Flocker 通过提供卷的耐久性、故障转移和高可用性来增强它。Flocker 可以手动部署到 Docker Swarm 和 compose 中，或者可以借助 CloudFormation 模板在 AWS 上轻松设置，如果备份存储必须在生产设置中使用。

Flocker 可以通过以下步骤轻松部署到 AWS 上：

1.  登录到您的 AWS 帐户并在 Amazon EC2 中创建一个密钥对。

1.  从 AWS 的主页中选择**CloudFormation**。

1.  Flocker 云形成堆栈可以使用 AWS S3 存储中的模板启动，链接如下：`https://s3.amazonaws.com/installer.downloads.clusterhq.com/flocker-cluster.cloudformation.json`

1.  选择创建堆栈；然后选择第二个选项并指定 Amazon S3 模板 URL：![Flocker](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_09_004.jpg)

1.  在下一个屏幕上，指定**堆栈名称**，**AmazonAccessKeyID**和**AmazonSecretAccessKey**：![Flocker](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_09_005.jpg)

1.  提供键值对以标记此 Flocker 堆栈，并在必要时提供此堆栈的**IAM 角色**：![Flocker](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_09_006.jpg)

1.  审查详细信息并启动 Flocker 云形成堆栈：![Flocker](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_09_007.jpg)

1.  一旦从输出选项卡完成堆栈部署，获取客户端节点和控制节点的 IP 地址。使用在 Flocker 堆栈部署开始时生成的键值对 SSH 进入客户端节点。

设置以下参数：

```
$ export FLOCKER_CERTS_PATH=/etc/flocker 
$ export FLOCKER_USER=user1 
$ export FLOCKER_CONTROL_SERVICE=<ControlNodeIP> # not ClientNodeIP! 
$ export DOCKER_TLS_VERIFY=1 
$ export DOCKER_HOST=tcp://<ControlNodeIP>:2376 
$ flockerctl status # should list two servers (nodes) running 
$ flockerctl ls # should display no datasets yet 
$ docker info |grep Nodes # should output "Nodes: 2" 

```

如果 Flocker 的`status`和`ls`命令成功运行，这意味着 Docker Swarm 和 Flocker 已成功在 AWS 上设置。

Flocker 卷可以轻松设置，并允许您创建一个将超出容器或容器主机生命周期的容器：

```
$ docker run --volume-driver flocker -v flocker-volume:/cont-dir --name=testing-container 

```

将创建并挂载外部存储块到我们的主机上，并将容器目录绑定到它。如果容器被删除或主机崩溃，数据仍然受到保护。可以使用相同的命令在第二个主机上启动备用容器，并且我们将能够访问我们的共享存储。前面的教程是为了在 AWS 上为生产用例设置 Flocker，但我们也可以通过 Docker Swarm 设置在本地测试 Flocker。让我们考虑一个使用情况，您有两个 Docker Swarm 节点和一个 Flocker 客户端节点。

## 在 Flocker 客户端节点

创建一个`docker-compose.yml`文件，并定义容器`redis`和`clusterhq/flask`。提供相应的配置 Docker 镜像、名称、端口和数据卷：

```
$ nano docker-compose.yml 
web: 
  image: clusterhq/flask 
  links: 
   - "redis:redis" 
  ports: 
   - "80:80" 
redis: 
  image: redis:latest 
  ports: 
   - "6379:6379" 
  volumes: ["/data"] 

```

创建一个名为`flocker-deploy.yml`的文件，在其中我们将定义将部署在相同节点`node-1`上的两个容器；暂时将`node-2`留空作为 Swarm 集群的一部分：

```
$ nano flocker-deploy.yml 
"version": 1 
"nodes": 
  "node-1": ["web", "redis"] 
  "node-2": [] 

```

使用前述的`.yml`文件部署容器；我们只需要运行以下命令即可：

```
$ flocker-deploy control-service flocker-deploy.yml docker-compose.yml 

```

集群配置已更新。可能需要一段时间才能生效，特别是如果需要拉取 Docker 镜像。

两个容器都可以在`node-1`上运行。一旦设置完成，我们可以在`http://node-1`上访问应用程序。它将显示此网页的访问计数：

```
"Hello... I have been seen 8 times" 

```

重新创建部署文件以将容器移动到`node-2`：

```
$ nano flocker-deply-alt.yml 
"version": 1\. 
"nodes": 
  "node-1": ["web"] 
  "node-2": ["redis"] 

```

现在，我们将把容器从`node-1`迁移到`node-2`，我们将看到 Flocker 将自动处理卷管理。当 Redis 容器在`node-2`上启动时，它将连接到现有的卷：

```
$ flocker-deploy control-service flocker-deploy-alt.yml docker-compose.yml 

```

集群配置已更新。这可能需要一段时间才能生效，特别是如果需要拉取 Docker 镜像。

我们可以 SSH 进入`node-2`并列出正在运行的 Redis 容器。尝试访问`http://node2`上的应用程序；我们将能够看到计数仍然保持在`node-1`中，并且当从`node-2`访问应用程序时，计数会增加`1`：

```
"Hello... I have been seen 9 times" 

```

这个例子演示了我们如何在 Flocker 集群中轻松地将容器及其数据卷从一个节点迁移到另一个节点。

## Convoy Docker 卷插件

Convoy 是另一个广泛使用的 Docker 卷插件，用于提供存储后端。它是用 Go 语言编写的，其主要优势是可以以独立模式部署。Convoy 将作为 Docker 卷扩展运行，并且会像一个中间容器一样运行。Convoy 的初始实现利用 Linux 设备，并为卷提供以下四个 Docker 存储功能：

+   薄配置卷

+   在主机之间恢复卷

+   对卷进行快照

+   将卷备份到外部对象存储，如**Amazon EBS**，**虚拟文件系统**（**VFS**）和**网络文件系统**（**NFS**）：![Convoy Docker 卷插件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_09_008.jpg)

使用 Convoy 卷插件

在下面的例子中，我们将运行一个本地的 Convoy 设备映射驱动程序，并展示在两个容器之间使用 Convoy 卷插件共享数据的用法：

1.  验证 Docker 版本是否高于 1.8。

1.  通过本地下载插件 tar 文件并解压缩来安装 Convoy 插件：

```
$ wget https://github.com/rancher/convoy/releases/download
        /v0.5.0/convoy.tar.gz 
        $ tar xvf convoy.tar.gz 
        convoy/ 
        convoy/convoy-pdata_tools 
        convoy/convoy 
        convoy/SHA1SUMS 
        $ sudo cp convoy/convoy convoy/convoy-pdata_tools /usr/local/bin/ 
        $ sudo mkdir -p /etc/docker/plugins/ 
        $ sudo bash -c 'echo "unix:///var/run/convoy/convoy.sock" > 
        /etc/docker/plugins/convoy.spec' 

```

1.  我们可以继续使用文件支持的环回设备，它充当伪设备，并使文件可在块设备中访问，以演示 Convoy 设备映射驱动程序：

```
$ truncate -s 100G data.vol 
        $ truncate -s 1G metadata.vol 
        $ sudo losetup /dev/loop5 data.vol 
        $ sudo losetup /dev/loop6 metadata.vol 

```

1.  一旦数据和元数据设备设置好，启动 Convoy 插件守护程序：

```
sudo convoy daemon --drivers devicemapper --driver-opts 
        dm.datadev=/dev/loop5 --driver-opts dm.metadatadev=/dev/loop6 

```

1.  在前面的终端中，Convoy 守护程序将开始运行；打开下一个终端实例并创建一个使用 Convoy 卷`test_volume`挂载到容器内`/sample`目录的`busybox` Docker 容器：

```
$ sudo docker run -it -v test_volume:/sample --volume-driver=convoy 
        busybox 
        Unable to find image 'busybox:latest' locally 
        latest: Pulling from library/busybox 
        4b0bc1c4050b: Pull complete   
        Digest: sha256:817a12c32a39bbe394944ba49de563e085f1d3c5266eb8
        e9723256bc4448680e 
        Status: Downloaded newer image for busybox:latest 

```

1.  在挂载的目录中创建一个示例文件：

```
/ # cd sample/ 
        / # cat > test 
        testing 
        /sample # exit 

```

1.  使用 Convoy 作为卷驱动程序启动不同的容器，并挂载相同的 Convoy 卷：

```
$ sudo docker run -it -v test_volume:/sample --volume-driver=convoy --
        name=new-container busybox 

```

1.  当我们执行`ls`时，我们将能够看到在先前容器中创建的文件：

```
/ # cd sample/ 
        /sample # ls 
        lost+found  test 
        /sample # exit 

```

因此，前面的例子显示了 Convoy 如何允许在同一主机或不同主机上的容器之间共享卷。

基本上，卷驱动程序应该用于持久数据，例如 WordPress MySQL DB：

```
$ docker run --name wordpressdb --volume-driver=convoy -v test_volume:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=password -e MYSQL_DATABASE=wordpress -d mysql:5.7 
1e7908c60ceb3b286c8fe6a183765c1b81d8132ddda24a6ba8f182f55afa2167 

$ docker run -e WORDPRESS_DB_PASSWORD=password -d --name wordpress --link wordpressdb:mysql  wordpress 
0ef9a9bdad448a6068f33a8d88391b6f30688ec4d3341201b1ddc9c2e641f263 

```

在前面的例子中，我们使用 Convoy 卷驱动程序启动了 MySQL DB，以便在主机故障时提供持久性。然后我们将 MySQL 数据库链接到 WordPress Docker 容器中。

# Docker 存储驱动程序性能

在本节中，我们将研究 Docker 支持的文件系统的性能方面和比较。可插拔的存储驱动程序架构和灵活性插入卷是容器化环境和生产用例的最佳方法。Docker 支持 aufs、btrfs、devicemapper、vfs、zfs 和 overlayfs 文件系统。

## UFS 基础知识

如前所述，Docker 使用 UFS 以实现只读的分层方法。

Docker 使用 UFS 将多个这样的层合并为单个镜像。本节将深入探讨 UFS 的基础知识以及 Docker 支持的存储驱动程序。

UFS 递归地将多个目录合并为单个虚拟视图。UFS 的基本愿望是拥有一个只读文件系统和一些可写的覆盖层。这会产生一个假象，即文件系统具有读写访问权限，即使它是只读的。UFS 使用写时复制来支持此功能。此外，UFS 操作的是目录而不是驱动器。

底层文件系统并不重要。UFS 可以合并来自不同底层文件系统的目录。由于 UFS 拦截了与这些文件系统绑定的操作，因此可以合并不同的底层文件系统。下图显示了 UFS 位于用户应用程序和文件系统之间。UFS 的示例包括 Union FS、Another Union FS（AUFS）等：

![UFS 基础知识](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/B04534_09_9.jpg)

UFS 和分支的底层文件系统

### UFS - 术语

UFS 中的分支是合并的文件系统。分支可以具有不同的访问权限，例如只读、读写等。UFS 是可堆叠的文件系统。分支还可以被分配偏好，确定对文件系统执行操作的顺序。如果在多个分支中存在具有相同文件名的目录，则 UFS 中的目录内容似乎被合并，但对这些目录中的文件的操作会被重定向到各自的文件系统。

UFS 允许我们在只读文件系统上创建可写层，并创建新文件/目录。它还允许更新现有文件。通过将文件复制到可写层，然后进行更改来更新现有文件。只读文件系统中的文件保持不变，但 UFS 创建的虚拟视图将显示更新后的文件。将文件复制到可写层以更新它的现象称为复制上升。

使用复制上升后，删除文件变得复杂。在尝试删除文件时，我们必须从底部到顶部删除所有副本。这可能导致只读层上的错误，无法删除文件。在这种情况下，文件会从可写层中删除，但仍然存在于下面的只读层中。

### UFS - 问题

UFS 最明显的问题是对底层文件系统的支持。由于 UFS 包装了必要的分支及其文件系统，因此必须在 UFS 源代码中添加文件系统支持。底层文件系统不会改变，但 UFS 必须为每个文件系统添加支持。

删除文件后创建的白出也会造成很多问题。首先，它们会污染文件系统命名空间。可以通过在单个子目录中添加白出来减少这种情况，但这需要特殊处理。此外，由于白出，`rmdir`的性能会下降。即使一个目录看起来是空的，它可能包含很多白出，因此`rmdir`无法删除该目录。

在 UFS 中，复制上升是一个很好的功能，但它也有缺点。它会降低第一次更新的性能，因为它必须将完整的文件和目录层次结构复制到可写层。此外，需要决定目录复制的时间。有两种选择：在更新时复制整个目录层次结构，或者在打开目录时进行复制。这两种技术都有各自的权衡。

#### AuFS

AuFS 是另一种 UFS。AuFS 是从 UFS 文件系统分叉出来的。这引起了开发者的注意，并且现在远远领先于 UFS。事实上，UFS 现在在遵循开发 AuFS 时所做的一些设计决策。像任何 UFS 一样，AuFS 使现有的文件系统和叠加在其上形成一个统一的视图。

AuFS 支持前几节中提到的所有 UFS 功能。您需要在 Ubuntu 上安装`aufs-tools`软件包才能使用 AuFS 命令。有关 AuFS 及其命令的更多信息，请参阅 AuFS 手册页。

#### 设备映射器

**设备映射器**是 Linux 内核组件；它提供了将物理块设备映射到虚拟块设备的机制。这些映射设备可以用作逻辑卷。设备映射器提供了创建这种映射的通用方法。

设备映射器维护一个表，该表定义了设备映射。该表指定了如何映射设备的每个逻辑扇区范围。该表包含以下参数的行：

+   `起始`

+   `长度`

+   `映射`

+   `映射参数`

第一行的`起始`值始终为零。对于其他行，起始加上前一行的长度应等于当前行的`起始`值。设备映射器的大小始终以 512 字节扇区指定。有不同类型的映射目标，例如线性、条带、镜像、快照、快照原点等。

## Docker 如何使用设备映射器

Docker 使用设备映射器的薄配置和快照功能。这些功能允许许多虚拟设备存储在同一数据卷上。数据和元数据使用两个单独的设备。数据设备用于池本身，元数据设备包含有关卷、快照、存储池中的块以及每个快照的块之间的映射的信息。因此，Docker 创建了一个单个的大块设备，然后在其上创建了一个薄池。然后创建一个基本块设备。每个镜像和容器都是从此基本设备的快照中形成的。

### BTRFS

**BTRFS**是一个 Linux 文件系统，有潜力取代当前默认的 Linux 文件系统 EXT3/EXT4。BTRFS（也称为**butter FS**）基本上是一个写时复制文件系统。**写时复制**（**CoW**）意味着它永远不会更新数据。相反，它会创建数据的新副本，该副本存储在磁盘的其他位置，保留旧部分不变。任何具有良好文件系统知识的人都会理解，写时复制需要更多的空间，因为它也存储了旧数据的副本。此外，它还存在碎片化的问题。那么，写时复制文件系统如何成为默认的 Linux 文件系统呢？这不会降低性能吗？更不用说存储空间的问题了。让我们深入了解 BTRFS，了解为什么它变得如此受欢迎。

BTRFS 的主要设计目标是开发一种通用文件系统，可以在任何用例和工作负载下表现良好。大多数文件系统对于特定的文件系统基准测试表现良好，但在其他情况下性能并不那么好。除此之外，BTRFS 还支持快照、克隆和 RAID（0 级、1 级、5 级、6 级、10 级）。这比以往任何人从文件系统中得到的都要多。人们可以理解设计的复杂性，因为 Linux 文件系统部署在各种设备上，从计算机和智能手机到小型嵌入式设备。BTRFS 布局用 B 树表示，更像是一片 B 树的森林。这些是适合写时复制的 B 树。由于写时复制文件系统通常需要更多的磁盘空间，总的来说，BTRFS 具有非常复杂的空间回收机制。它有一个垃圾收集器，利用引用计数来回收未使用的磁盘空间。为了数据完整性，BTRFS 使用校验和。

存储驱动程序可以通过将`--storage-driver`选项传递给`dockerd`命令行，或在`/etc/default/docker`文件中设置`DOCKER_OPTS`选项来选择：

```
$ dockerd --storage-driver=devicemapper & 

```

我们已经考虑了前面三种广泛使用的文件系统与 Docker，以便使用微基准测试工具对以下 Docker 命令进行性能分析；`fio`是用于分析文件系统详细信息的工具，比如随机写入：

+   `commit`：这用于从运行的容器创建 Docker 镜像：![BTRFS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_09_010.jpg)

图表描述了提交包含单个大文件的大型容器所需的时间

+   `build`：用于使用包含一系列步骤的 Dockerfile 构建镜像的命令，以便从头开始创建包含单个大文件的镜像：![BTRFS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_09_011.jpg)

图表描述了在不同文件系统上构建容器所需的时间

+   `rm`：用于删除已停止的容器的命令：![BTRFS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_09_012.jpg)

图表描述了使用 rm 命令删除包含成千上万文件的容器所需的时间。

+   `rmi`：用于删除镜像的命令：![BTRFS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_09_013.jpg)

图表描述了使用 rmi 命令删除包含单个大文件的大型容器所需的时间

从前面的测试中，我们可以清楚地看到，AuFS 和 BTRFS 在 Docker 命令方面表现非常出色，但是 BTRFS 容器执行许多小写操作会导致 BTRFS 块的使用不佳。这最终可能导致 Docker 主机的空间不足并停止工作。使用 BTRFS 存储驱动程序可以密切监视 BTRFS 文件系统上的可用空间。此外，由于 BTRFS 日志技术，顺序写入受到影响，可能会减半性能。

设备映射器的性能不佳，因为每次容器更新现有数据时，存储驱动程序执行一次 CoW 操作。复制是从镜像快照到容器的快照，可能会对容器性能产生明显影响。

AuFS 看起来是 PaaS 和其他类似用例的不错选择，其中容器密度起着重要作用。AuFS 在运行时有效地共享镜像，实现快速容器启动时间和最小磁盘空间使用。它还非常有效地使用系统页面缓存。OverlayFS 是一种类似于 AuFS 的现代文件系统，但设计更简单，可能更快。但目前，OverlayFS 还不够成熟，无法在生产环境中使用。它可能会在不久的将来成为 AuFS 的继任者。没有单一的驱动程序适用于每种用例。用户应根据用例选择存储驱动程序，并考虑应用程序所需的稳定性，或者使用发行版 Docker 软件包安装的默认驱动程序。如果主机系统是 RHEL 或其变体，则 Device Mapper 是默认的存储驱动程序。对于 Ubuntu，AuFS 是默认驱动程序。

# 摘要

在本章中，我们深入探讨了与 Docker 相关的数据卷和存储驱动器概念。我们讨论了使用四种方法来排除数据卷故障，以及它们的优缺点。将数据存储在 Docker 容器内的第一种情况是最基本的情况，但在生产环境中无法灵活管理和处理数据。第二种和第三种情况是关于使用仅数据容器或直接在主机上存储数据。这些情况有助于提供可靠性，但仍然依赖于主机的可用性。第四种情况是关于使用第三方卷插件，如 Flocker 或 Convoy，通过将数据存储在单独的块中解决了所有先前的问题，并在容器从一个主机转移到另一个主机或容器死亡时提供了数据的可靠性。在最后一节中，我们讨论了 Docker 存储驱动程序和 Docker 提供的插件架构，以使用所需的文件系统，如 AuFS、BTRFS、Device Mapper、vfs、zfs 和 OverlayFS。我们深入研究了 AuFS、BTRFS 和 Device Mapper，这些是广泛使用的文件系统。通过使用基本的 Docker 命令进行的各种测试表明，AuFS 和 BTRFS 比 Device Mapper 提供更好的性能。用户应根据其应用用例和 Docker 守护程序主机系统选择 Docker 存储驱动程序。

在下一章中，我们将讨论 Docker 在公共云 AWS 和 Azure 中的部署以及故障排除。


# 第十章：在公共云中部署 Docker - AWS 和 Azure

在本章中，我们将在公共云 AWS 和 Azure 上进行 Docker 部署。 AWS 在 2014 年底推出了**弹性计算云**（**EC2**）容器服务。当它推出时，该公司强调了基于过去发布的亚马逊服务的高级 API 调用的容器集群管理任务。 AWS 最近发布了 Docker for AWS Beta，允许用户快速在 AWS 和 Azure 上设置和配置 Docker 1.13 swarm 模式。借助这项新服务，我们可以获得以下功能：

+   它确保团队可以无缝地将应用程序从开发人员的笔记本电脑移动到基于 Docker 的暂存和生产环境

+   它有助于与底层 AWS 和 Azure 基础设施深度集成，利用主机环境，并向使用公共云的管理员公开熟悉的接口

+   它部署平台并在各种平台之间轻松迁移，其中 Docker 化的应用程序可以简单高效地移动

+   它确保应用程序在所选平台、硬件、基础设施和操作系统上以最新和最优秀的 Docker 版本完美运行

在本章的后半部分，我们将涵盖 Azure 容器服务，它可以简单地创建、配置和管理提供支持运行容器化应用程序的虚拟机集群。它允许我们在 Microsoft Azure 上部署和管理容器化应用程序。它还支持各种 Docker 编排工具，如 DC/OS、Docker Swarm 或 Kubernetes，根据用户选择。

在本章中，我们将涵盖以下主题：

+   Amazon EC2 容器服务的架构

+   故障排除 AWS ECS 部署

+   更新 ECS 集群中的 Docker 容器

+   Microsoft Azure 容器服务的架构

+   Microsoft Azure 容器服务的故障排除

+   AWS 和 Azure 的 Docker Beta

# Amazon ECS 的架构

亚马逊 ECS 的核心架构是集群管理器，这是一个后端服务，负责集群协调和状态管理的任务。在集群管理器的顶部是调度程序管理器。它们彼此解耦，允许客户构建自己的调度程序。资源池包括 Amazon EC2 实例的 CPU、内存和网络资源，这些资源由容器分区。 Amazon ECS 通过在每个 EC2 实例上运行的开源 Amazon ECS 容器代理来协调集群，并根据调度程序的要求启动、停止和监视容器。为了管理单一真相：EC2 实例、运行在它们上面的任务以及使用的容器和资源。我们需要将状态存储在某个地方，这是在集群管理器键/值存储中完成的。为了实现这个键/值存储的并发控制，维护了一个基于事务日志的数据存储，以记录对每个条目的更改。亚马逊 ECS 集群管理器已经开放了一组 API，允许用户访问存储在键/值存储中的所有集群状态信息。通过`list`命令，客户可以检索管理的集群、运行的任务和 EC2 实例。`describe`命令可以帮助检索特定 EC2 实例的详细信息以及可用的资源。亚马逊 ECS 架构提供了一个高度可扩展、可用和低延迟的容器管理解决方案。它是完全托管的，并提供运营效率，允许客户构建和部署应用程序，而不必考虑要管理或扩展的集群：

![Amazon ECS 架构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/4534_10_1-1.jpg)

亚马逊 ECS 架构

# 故障排除 - AWS ECS 部署

EC2 实例可以手动部署，并且可以在其上配置 Docker，但 ECS 是由 ECS 管理的一组 EC2 实例。 ECS 将负责在集群中的各个主机上部署 Docker 容器，并与其他 AWS 基础设施服务集成。

在本节中，我们将介绍在 AWS 上设置 ECS 的一些基本步骤，这将有助于解决和绕过基本配置错误：

+   创建 ECS 集群

+   创建 ELB 负载均衡器

+   在 ECS 集群中运行 Docker 容器

+   更新 ECS 集群中的 Docker 容器

1.  从 AWS 控制台中的**计算**下列出的**EC2 容器服务**启动：![故障排除 - AWS ECS 部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_002.jpg)

1.  单击**开始**按钮：![故障排除 - AWS ECS 部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_003.jpg)

1.  在下一个屏幕上，选择两个选项：部署示例应用程序，创建和管理私有仓库。为 EC2 服务创建了一个私有仓库，并由 AWS 进行了安全保护。需要 AWS 登录才能推送镜像：![故障排除 - AWS ECS 部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_004.jpg)

1.  提供仓库名称，我们将能够看到生成需要推送容器镜像的仓库地址：![故障排除 - AWS ECS 部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_005.jpg)

1.  下一个屏幕显示了一些基本的 Docker 和 AWS CLI 命令，用于将容器镜像推送到私有仓库，如下所示：

使用`pip`软件包管理器安装 AWS CLI：

```
 $ pip install awscl

```

使用`aws configure`命令并提供 AWS 访问密钥 ID 和 AWS 秘密访问密钥进行登录：

```
 $ aws configure 
        AWS Access Key ID [None]:  
        AWS Secret Access Key [None]: 
        Default region name [None]:  
        Default output format [None]:

```

获取`docker login`命令，以便将本地 Docker 客户端认证到私有 AWS 注册表：

```
 $ aws ecr get-login --region us-east-1 
        docker login -u AWS -p 
        Key...

```

使用生成的链接作为前述命令的输出，该链接将配置 Docker 客户端以便与部署在 AWS 中的私有仓库一起工作：

```
 $ docker login -u AWS -p Key... 
        Flag --email has been deprecated, will be removed in 1.13\. 
        Login Succeeded

```

现在我们将使用 AWS 私有仓库名称标记 nginx 基本容器镜像，以便将其推送到私有仓库：

```
 $ docker images 
        REPOSITORY  TAG     IMAGE ID      CREATED     SIZE 
        nginx       latest  19146d5729dc  6 days ago  181.6 MB 

        $ docker tag nginx:latest private-repo.amazonaws.com/sample:latest 

        $ docker push private-repo.amazonaws.com/sample:latest 
        The push refers to a repository [private-repo.amazonaws.com/sample] 
        e03d01018b72: Pushed  
        ee3b1534c826: Pushing [==>] 2.674 MB/58.56 MB 
        b6ca02dfe5e6: Pushing [>] 1.064 MB/123.1 MB  
        ... Image successfully pushed

```

1.  将镜像推送到私有 Docker 仓库后，我们将创建一个任务定义，定义以下内容：

+   要运行的 Docker 镜像

+   要分配的资源（CPU、内存等）

+   要挂载的卷

+   要链接在一起的 Docker 容器

+   启动时应运行的命令容器

+   要为容器设置的环境变量

+   任务应使用的 IAM 角色

+   特权 Docker 容器与否

+   要给 Docker 容器的标签

+   要用于容器的端口映射和网络，以及要用于容器的 Docker 网络模式：![故障排除 - AWS ECS 部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_006.jpg)

1.  高级容器配置给我们提供了声明**CPU 单位**、**入口点**、特权容器与否等选项：![故障排除 - AWS ECS 部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_007.jpg)

1.  在下一步中，我们将声明对于运行持续的任务（如 Web 服务）有用的服务。

这使我们能够在 ECS 集群中同时运行和维护指定数量（期望数量）的任务定义。如果任何任务失败，Amazon ECS 服务调度程序将启动另一个实例，并保持服务中所需数量的任务。

我们可以选择在负载均衡器后面的服务中运行所需数量的任务。Amazon ECS 允许我们配置弹性负载均衡，以在服务中定义的任务之间分发流量。负载均衡器可以配置为应用负载均衡器，它可以将请求路由到一个或多个端口，并在应用层（HTTP/HTTPS）做出决策。经典负载均衡器在传输层（TCP/SSL）或应用层（HTTP/HTTPS）做出决策。它需要负载均衡器端口和容器实例端口之间的固定关系：

![故障排除 - AWS ECS 部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_008.jpg)

1.  在下一步中，配置集群，这是 EC2 实例的逻辑分组。默认情况下，我们将把`t2.micro`定义为 EC2 实例类型，并将当前实例数定义为`1`：![故障排除 - AWS ECS 部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_009.jpg)

1.  审查配置并部署 ECS 集群。创建集群后，单击**查看服务**按钮以查看有关服务的详细信息：![故障排除 - AWS ECS 部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_010.jpg)

1.  单击 EC2 容器负载均衡器，以获取公开访问的服务 URL：![故障排除 - AWS ECS 部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_011.jpg)

1.  在负载均衡器的描述中，DNS 名称是从互联网访问服务的 URL：![故障排除 - AWS ECS 部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_012.jpg)

1.  当我们访问负载均衡器的公共 URL 时，可以看到欢迎使用 nginx 页面：![故障排除 - AWS ECS 部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_013.jpg)

# 更新 ECS 集群中的 Docker 容器

我们在 ECS 集群中运行 Docker 容器，现在，让我们走一遍这样一个情景，即容器和服务都需要更新。通常，这发生在持续交付模型中，我们有两个生产环境；蓝色环境是服务的旧版本，目前正在运行，以处理用户的请求。新版本环境被称为绿色环境，它处于最后阶段，并将处理未来用户的请求，因为我们从旧版本切换到新版本。

蓝绿部署有助于快速回滚。如果我们在最新的绿色环境中遇到任何问题，我们可以将路由器切换到蓝色环境。现在，由于绿色环境正在运行并处理所有请求，蓝色环境可以用作下一个部署的最终测试步骤的暂存环境。这种情况可以很容易地通过 ECS 中的任务定义来实现：

![在 ECS 集群中更新 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_014.jpg)

蓝绿部署环境

1.  通过选择创建的 ECS 任务并单击**创建新任务定义**按钮，可以创建新的修订版本：![在 ECS 集群中更新 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_015.jpg)

1.  在任务的新定义中，我们可以附加一个新容器或单击容器定义并进行更新。*高级容器配置*也可以用于设置*环境变量*：![在 ECS 集群中更新 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_016.jpg)

1.  创建最新任务后，单击**操作**，然后单击**更新服务**：![在 ECS 集群中更新 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_017.jpg)

1.  **console-sample-app-static:2**将更新**console-sample-app-static:1**，并在下一个屏幕上提供了包括任务数量和自动缩放选项在内的各种选项：![在 ECS 集群中更新 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_018.jpg)

自动缩放组将启动，包括 AMI、实例类型、安全组和用于启动 ECS 实例的所有其他细节。使用缩放策略，我们可以扩展集群实例和服务，并在需求减少时安全地缩小它们。可用区感知的 ECS 调度程序管理、分发和扩展集群，从而使架构具有高可用性。

# Microsoft Azure 容器服务架构

Azure 是当今市场上增长最快的基础设施服务之一。它支持按需扩展和创建混合环境的能力，并借助 Azure 云服务支持大数据。Azure 容器服务提供了开源容器集群和编排解决方案的部署。借助 Azure 容器服务，我们可以部署基于 DC/OS（Marathon）、Kubernetes 和 Swarm 的容器集群。Azure 门户提供了简单的 UI 和 CLI 支持来实现这种部署。

Microsoft Azure 正式成为第一个支持主流容器编排引擎的公共云。即使 Azure 容器服务引擎也在 GitHub 上开源（[`github.com/Azure/acs-engine`](https://github.com/Azure/acs-engine)）。

这一步使开发人员能够理解架构并直接在 vSphere Hypervisor、KVM 或 HyperV 上运行多个编排引擎。 **Azure 资源管理器**（**ARM**）模板为通过 ACS API 部署的集群提供了基础。ACS 引擎是用 Go 构建的，这使用户能够组合不同的配置部件并构建最终模板，用于部署集群。

Azure 容器引擎具有以下功能：

+   您选择的编排器，如 DC/OS，Kubernetes 或 Swarm

+   多个代理池（可用性集和虚拟机集）

+   Docker 集群大小最多可达 1,200 个：

+   支持自定义 vNET

Azure 容器服务主要是以 DC/OS 作为关键组件之一构建的，并且在 Microsoft Azure 上进行了优化以便轻松创建和使用。ACS 架构有三个基本组件：Azure Compute 用于管理 VM 健康，Mesos 用于容器健康管理，Swarm 用于 Docker API 管理：

![Microsoft Azure 容器服务架构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_019.jpg)

Microsoft Azure 容器架构

# 故障排除-微软 Azure 容器服务

在本节中，我们将看看如何在 Microsoft Azure 中部署 Docker Swarm 集群，并提供编排器配置详细信息：

1.  我们需要创建一个 RSA 密钥，在部署步骤中将被请求。该密钥将需要用于登录到安装后的部署机器：

```
 $ ssh-keygen

```

一旦生成，密钥可以在`~/root/id_rsa`中找到

1.  在 Azure 账户门户中单击**新建**按钮：![故障排除-微软 Azure 容器服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_022.jpg)

1.  搜索**Azure 容器服务**并选择它：![故障排除-微软 Azure 容器服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_023.jpg)

1.  完成此步骤后，选择**资源管理器**作为部署模型，然后单击**创建**按钮：![故障排除-微软 Azure 容器服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_024.jpg)

1.  配置基本设置页面，需要以下细节：**用户名**，将作为部署在 Docker Swarm 集群中的虚拟机的管理员；第二个字段是提供我们在步骤 1 中创建的**SSH 公钥**；并通过在**资源组**字段中指定名称来创建一个新的资源组：![故障排除 - Microsoft Azure 容器服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_025.jpg)

1.  根据需要选择**编排器配置**为**Swarm**，**DC/OS**或**Kubernetes**：![故障排除 - Microsoft Azure 容器服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_026.jpg)

1.  在下一步中，为此部署提供编排器配置、**代理计数**和**主服务器计数**。还可以根据需要提供 DNS 前缀，如`dockerswarm`：![故障排除 - Microsoft Azure 容器服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_027.jpg)

1.  检查**摘要**，一旦验证通过，点击**确定**。在下一个屏幕上，点击**购买**按钮继续部署：![故障排除 - Microsoft Azure 容器服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_028.jpg)

1.  一旦部署开始，可以在 Azure 主要**仪表板**上看到状态：![故障排除 - Microsoft Azure 容器服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_029.jpg)

1.  创建 Docker Swarm 集群后，点击仪表板上显示的 Docker Swarm 资源中的 swarm-master：![故障排除 - Microsoft Azure 容器服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_030.jpg)

1.  在 swarm-master 的**基本信息**部分，您将能够找到 DNS 条目，如下面的截图所示：![故障排除 - Microsoft Azure 容器服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_031.jpg)

以下是连接到 swarm-master 的 SSH 命令：

```
 ssh <DNS_FROM_FIELD> -A -p 2200 -i <PUB_FILE_LOCATION>

```

一旦连接到主服务器，可以执行基本的 Docker Swarm 命令，并且可以在部署在 Microsoft Azure 上的 Swarm 集群上部署容器。

# AWS 和 Azure 的 Docker Beta

随着这项服务的最新发布，Docker 已经简化了通过与两个云平台的基础设施服务紧密集成，在 AWS 和 Azure 上部署 Docker 引擎的过程。这使开发人员能够将他们的代码捆绑并部署到生产机器中，而不管环境如何。目前，该服务处于 Beta 版本，但我们已经介绍了 AWS 的 Docker 部署的基本教程。该服务还允许您在这些环境中轻松升级 Docker 版本。甚至这些服务中还启用了 Swarm 模式，为单个 Docker 引擎提供了自愈和自组织的 Swarm 模式。它们还分布在可用性区域中。

与先前的方法相比，Docker Beta for AWS and Azure 提供了以下改进：

+   使用 SSH 密钥进行 IaaS 帐户的访问控制

+   轻松配置基础设施负载平衡和动态更新，因为应用程序在系统中被配置

+   可以使用安全组和虚拟网络来进行安全的 Docker 设置

Docker for AWS 使用*CloudFormation*模板并创建以下对象：

+   启用自动缩放的 EC2 实例

+   IAM 配置文件

+   DynamoDB 表

+   VPC、子网和安全组

+   ELB

需要部署和访问部署实例的 AWS 区域的 SSH 密钥。安装也可以使用 AWS CLI 使用 CloudFormation 模板完成，但在本教程中，我们将介绍基于 AWS 控制台的方法：

1.  登录控制台，选择 CloudFormation，然后单击**创建堆栈**。

1.  指定 Amazon S3 模板 URL 为`https://docker-for-aws.s3.amazonaws.com/aws/beta/aws-v1.13.0-rc4-beta14.json`，如下所示：![Docker Beta for AWS and Azure](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_032.jpg)

1.  在下一个屏幕上，指定堆栈详细信息，说明需要部署的 Swarm 管理器和节点的数量。还可以指定要使用的 AWS 生成的 SSH 密钥：![Docker Beta for AWS and Azure](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_033.jpg)

1.  在下一个屏幕上，我们将有提供标签以及 IAM 权限角色的选项：![Docker Beta for AWS and Azure](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_034.jpg)

1.  审查详细信息并启动堆栈：![Docker Beta for AWS and Azure](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_035.jpg)

1.  堆栈将显示为状态**CREATE_IN_PROGRESS**。等待堆栈完全部署：![Docker Beta for AWS and Azure](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_036.jpg)

1.  部署后，堆栈将具有状态**CREATE_COMPLETE**。单击它，部署的环境详细信息将被列出：![Docker Beta for AWS and Azure](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_10_037.jpg)

AWS 生成的 SSH 密钥可用于 SSH 到管理节点并管理部署的 Docker Swarm 实例：

```
 $ ssh -i <path-to-ssh-key> docker@<ssh-host> 
Welcome to Docker!

```

`docker info`命令将提供有关 Swarm 集群的信息。可以使用以下命令列出 Swarm 节点：

```
 $ docker info  
Containers: 5 
 Running: 4 
 Paused: 0 
 Stopped: 1 
Images: 5 
Server Version: 1.13.0-rc4 
Storage Driver: overlay2 
 Backing Filesystem: extfs 

$ docker node ls 
ID                           HOSTNAME                       STATUS  AVAILABILITY  MANAGER STATUS 
koewopxooyp5ftf6tn5wypjtd    ip-172-31-37-122.ec2.internal  Ready   Active         
qs9swn3uv67v4vhahxrp4q24g    ip-172-31-2-43.ec2.internal    Ready   Active         
ubkzv527rlr08fjjgvweu0k6t *  ip-172-31-1-137.ec2.internal   Ready   Active        Leader

```

SSH 连接也可以直接连接到领导节点，并部署基本的 Docker 容器：

```
 $ ssh docker@ip-172-31-37-122.ec2.internal 

$ docker run hello-world 
Unable to find image 'hello-world:latest' locally 
latest: Pulling from library/hello-world 
c04b14da8d14: Pull complete  
Digest: sha256:0256e8a36e2070f7bf2d0b0763dbabdd67798512411de4cdcf9431a1feb60fd9 
Status: Downloaded newer image for hello-world:latest 

Hello from Docker!

```

服务可以按照以下方式为先前部署的容器创建：

```
 $ docker service create --replicas 1 --name helloworld alpine ping docker.com
 xo7byk0wyx5gim9y7etn3o6kz
 $ docker service ls
 ID            NAME        MODE        REPLICAS   IMAGE
 xo7byk0wyx5g  helloworld  replicated  1/1        alpine:latest
 $ docker service inspect --pretty helloworld
 ID:           xo7byk0wyx5gim9y7etn3o6kz
 Name:         helloworld
 Service Mode: Replicated

```

可以按照以下方式在 Swarm 集群中扩展和移除服务：

```
 $ docker service scale helloworld=5 
helloworld scaled to 5 

$ docker service ps helloworld 
ID            NAME          IMAGE          NODE                           DESIRED STATE  CURRENT STATE               ERROR  PORTS 
9qu8q4equobn  helloworld.1  alpine:latest  ip-172-31-37-122.ec2.internal  Running        Running about a minute ago          
tus2snjwqmxm  helloworld.2  alpine:latest  ip-172-31-37-122.ec2.internal  Running        Running 6 seconds ago               
cxnilnwa09tl  helloworld.3  alpine:latest  ip-172-31-2-43.ec2.internal    Running        Running 6 seconds ago               
cegnn648i6b2  helloworld.4  alpine:latest  ip-172-31-1-137.ec2.internal   Running        Running 6 seconds ago               
sisoxrpxxbx5  helloworld.5  alpine:latest  ip-172-31-1-137.ec2.internal   Running        Running 6 seconds ago               

$ docker service rm helloworld 
helloworld

```

# 摘要

在本章中，我们已经介绍了在公共云 Microsoft Azure 和 AWS 上部署 Docker。两家云服务提供商为客户提供了有竞争力的容器服务。本章帮助解释了 AWS EC2 和 Microsoft Azure 容器服务架构的详细架构。它还涵盖了容器集群的所有部署步骤的安装和故障排除。本章还涵盖了蓝绿部署场景以及它在 AWS EC2 中的支持情况，这在现代 SaaS 应用程序的情况下通常是必要的。最后，我们介绍了最近推出的 Docker Beta，适用于 AWS 和 Azure，它提供了容器从开发环境迁移到生产环境的简便方法，因为它们是相同的。基于容器的应用程序可以很容易地使用 Docker Beta 进行部署和扩展，因为这项服务与云服务提供商的 IaaS 非常紧密地结合在一起。
