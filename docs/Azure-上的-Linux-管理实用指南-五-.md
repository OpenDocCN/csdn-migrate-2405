# Azure 上的 Linux 管理实用指南（五）

> 原文：[`zh.annas-archive.org/md5/0EE39A6B040A18FF64595B6B3C82179F`](https://zh.annas-archive.org/md5/0EE39A6B040A18FF64595B6B3C82179F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：使用 Azure Kubernetes 服务。

在上一章中，我们探索了容器虚拟化的世界，特别是 Docker 容器。本章是关于使用**Azure Kubernetes 服务**（**AKS**）管理容器化工作负载的。

本章与本书中的所有其他章节都不同。到目前为止，每一章都是关于基础设施和提供平台：经典的云系统管理员。甚至*第九章*，*Azure 中的容器虚拟化*，也包含诸如“我们如何安装 Docker？”和“我们如何让容器运行起来？”的问题。本章将回答以下问题：

+   我们在开发阶段和之后如何部署和管理我们的工作负载？

+   我们如何进行扩展/缩减？

+   可用性选项是什么？

Kubernetes 为所有这些问题提供了重要的答案。它是一个解决方案，用于自动化重要任务，如部署、管理、扩展、网络和容器化应用程序的可用性管理。

Kubernetes 最初是由 Google 设计的，现在由 Cloud Native Computing Foundation（[`www.cncf.io`](https://www.cncf.io)）维护。微软是这个基金会的重要合作伙伴，并且在金钱和代码方面是 Kubernetes 项目的重要贡献者。实际上，Kubernetes 的联合创始人之一 Brendan Burns 就在微软工作，并领导着在微软内部从事容器编排工作的团队。此外，微软还启动了几个针对 Kubernetes 的开源项目，提供了额外的工具。

由于微软在 Kubernetes 中的重要参与，它能够在 Azure 中实现一个完全与上游兼容的 Kubernetes 版本。这对开发人员也很重要，因此他们可以使用本地 Kubernetes 安装来开发软件，当开发完成后，将其发布到 Azure 云。

AKS 为 Kubernetes 提供了一个完全托管的容器即服务解决方案。这意味着您不必考虑 Kubernetes 软件的配置、管理和升级。控制平面由 Azure 管理。

AKS 使得在 Azure 中部署和管理 Kubernetes 变得容易：它可以处理从供应到保持应用程序最新和根据您的需求进行扩展的完整维护过程。

甚至在不中断的情况下升级 Kubernetes 集群的过程也可以通过 AKS 完成。

最后但同样重要的是，监控对于 Kubernetes 集群的每个部分都是可用的。

在本章结束时，您将能够：

+   解释 Kubernetes 和 AKS 是什么。

+   使用 AKS 来部署和管理您的集群。

+   在 AKS 中维护应用程序的完整生命周期。

因此，在我们实际开始使用 AKS 之前，让我们首先了解技术要求是什么。

## 技术要求

正如本章介绍中所述，本章与所有其他章节都不同，这影响了技术要求。到目前为止，技术要求很简单：你只需要一堆虚拟机。

本章需要一个 DevOps 环境，在这个环境中，开发人员和运维人员在同一个团队中紧密合作，还有一个人既做开发又做运维相关的任务。

还必须做出选择：我们在哪里开发？本地还是在 Azure 云中？两者都可以，而且不应该有任何区别！从成本的角度来看，最好在工作站上进行。在本章中，假设您是在本地进行开发。因此，您需要一个工作站（或虚拟机）。我们需要以下内容：

+   Azure CLI。

+   Docker 和构建工具。

+   Kubernetes。

+   一些基本的开发人员工具，比如 Git。

+   一些其他工具，比如稍后介绍的 Helm。

+   一个很好的**集成开发环境**（**IDE**）。我们推荐使用 Microsoft **Visual Studio**（**VS**）Code 以及 Docker 和 Kubernetes 的 Microsoft 扩展（仅当有图形界面时；否则使用 Nano 编辑器）。

+   可选地，可以使用诸如 Ansible 之类的编排工具。请查看 Ansible `azure_rm_aks`和`8ks_raw`模块。

### 使用 WSL 和 VS Code

您可以使用**Windows 子系统**（**WSL**）和 VS Code 以及 VS Code 远程 WSL 扩展，在 Windows 桌面或笔记本电脑上获得 Linux 开发环境，而无需使用虚拟机。这将使您能够从 PowerShell 或 CMD 访问 Linux 文件，并从 Bash 访问 Windows 文件。VS Code 是一个可以在各种平台上运行并支持许多语言的源代码编辑器。您可以使用 WSL 和 VS Code 从您喜欢的 Windows 平台开发、运行和调试基于 Linux 的应用程序。可以使用 PowerShell 启用 WSL 功能，并从 Microsoft Store 安装 Linux。VS Code 适用于 Windows 和 Linux，并可从[`code.visualstudio.com/`](https://code.visualstudio.com/)下载。由于 VS Code 的配置设置在 Windows 和 Linux 平台上都是保持一致的，因此您可以轻松地在 Windows 和 Linux 之间切换。

您可以在[`docs.microsoft.com/en-us/learn/modules/get-started-with-windows-subsystem-for-linux/`](https://docs.microsoft.com/en-us/learn/modules/get-started-with-windows-subsystem-for-linux/)找到 WSL 的逐步教程，并在[`docs.microsoft.com/en-us/windows/wsl/install-win10`](https://docs.microsoft.com/en-us/windows/wsl/install-win10)找到详细的安装指南。在 Windows 上运行时，您可以配置默认 shell 并在 PowerShell 和 WSL 之间进行选择，在 Linux 上可以选择 Zsh 或 Bash。

### 安装依赖项

我们将使用 Ubuntu 18.04 LTS 桌面版。但是您也可以在 Azure 虚拟机中使用 Ubuntu 18.04 LTS 服务器。有了其他章节中获得的所有知识，很容易将我们将要做的事情转移到其他 Linux 发行版、macOS 甚至 Windows 上：

1.  首先，升级 Ubuntu：

```
sudo apt update &&sudo apt upgrade
```

1.  安装开发人员工具，包括其他一些依赖项和`openssh`：

```
sudo apt install build-essential git curl openssh-server \
ebtablesethtoolsocat
```

1.  首先，我们将安装 Azure CLI。

您可以通过运行单个命令安装 Azure CLI：

```
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash 
```

或者，您可以使用以下说明进行手动安装。

获取所需的软件包：

```
sudo apt-get install ca-certificates curl apt-transport-https lsb-release gnupg
```

获取并安装签名密钥：

```
curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | 
sudo tee /etc/apt/trusted.gpg.d/microsoft.asc.gpg> /dev/null
sudo apt-add-repository \
  https://packages.microsoft.com/repos/azure-cli
curl -L https://packages.microsoft.com/keys/microsoft.asc \
  | sudo apt-key add -
sudo apt update 
sudo apt install azure-cli
```

1.  要安装 PowerShell 和 VS Code，我们使用的是 snaps，这是类似于 Windows 上的便携式应用程序的通用软件包：

```
sudo snap install --classic powershell
sudo snap install --classic vscode
```

或者，您可以使用以下命令安装 PowerShell Core：

```
curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
curl https://packages.microsoft.com/config/ubuntu/18.04/prod.list | sudo tee /etc/apt/sources.list.d/microsoft.list
sudo apt update
sudo apt install -y powershell
```

1.  键入`pwsh`以启动 PowerShell Core：

```
admin123@kubes:~$ pwsh
```

如果 PowerShell Core 成功启动，您将获得以下输出：

![使用 pwsh 命令启动 PowerShell Core](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_01.jpg)

###### 图 10.1：启动 PowerShell Core

1.  安装 Azure 的 Azure cmdlet：

```
sudo pwsh -Command "Install-Module PowerShellGet -Force"
sudo pwsh -Command "Install-Module -Name AzureRM.Netcore \
 -AllowClobber"
sudo chown -R $USER ~/.local/
```

1.  安装 Docker：

```
curl -sSL https://get.docker.com/ | sudo sh
sudo usermod -aG docker $USER
```

您将获得 Docker 版本详细信息如下：

![获取 Docker 版本详细信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_02.jpg)

###### 图 10.2：Docker 版本详细信息

1.  暂时停止 Docker：

```
Sudo systemctl stop docker.service
```

### kubectl 安装

kubectl 是一个命令行界面，可用于管理 Kubernetes 集群。它可用于许多操作。例如，使用`kubectl create`创建一个或多个文件，并使用`kubectl delete`从文件中删除资源。我们将使用 Azure CLI 来安装`kubectl`，并以 root 身份执行以下命令以授予所需的权限：

```
sudo -i
az login
az aks install-cli
```

首先，您需要使用以下命令下载最新版本：

```
curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.16.3/bin/linux/amd64/kubectl
```

接下来，使其可执行：

```
chmod +x ./kubectl
```

现在，将其移动到您的`PATH`：

```
Sudo mv ./kubectl /usr/local/bin/kubectl
```

通过请求版本信息来验证安装：

```
kubectl version
```

要启用自动补全，可以为 Bash 和 Zsh 在`kubectl`中执行以下命令：

```
kubectl completion bash > ~/.kube/completion.bash.inc
printf"
 # Kubectl shell completion
 source '$HOME/.kube/completion.bash.inc'
">> $HOME/.bash_profile
source $HOME/.bash_profile
```

对于 Zsh，请执行以下命令：

```
sudo -i
kubectl completion zsh>"${fpath[1]}/_kubectl"
exit
source <(kubectl completion zsh)
```

到目前为止，我们已经使用`curl`命令在 Linux 上安装了最新版本的 kubectl 二进制文件，并启用了 kubectl 的 shell 自动补全。现在我们准备使用 AKS 了。

#### 注意

如果你使用 kubectl 时收到类似`Error from server (NotAcceptable): unknown (get nodes)`的错误消息，使用`https://dl.k8s.io/v1.10.6/kubernetes-client-linux-amd64.tar.gz`降级你的客户端。

尽管这完全超出了本书的范围，但我们个人喜欢使用 Zsh shell，并使用一个名为 Spaceship 的漂亮定制。提示符可以让你更清楚地了解你在哪里以及在处理 AKS 时在做什么。

这是快速安装： 

```
sudo apt install zshnpm fonts-powerline
zsh # and create a .zshrc file with option 0 
npm install spaceship-prompt
chsh -s /bin/zsh
```

## 开始使用 AKS

Azure AKS 使得部署和管理容器应用变得容易。你可以快速定义、部署和调试 Kubernetes 应用程序，还可以使用 Azure AKS 自动将应用程序容器化。你可以自动化监控、升级、修复和扩展，从而减少手动基础设施维护。安装了 kubectl 后，现在是时候在 Azure 中设置和探索 Kubernetes 环境了：

1.  创建一个集群。

1.  查找有关集群的信息。

1.  部署一个简单的工作负载。

### 使用 Azure CLI 创建一个集群

在 Kubernetes 中，我们将使用集群。一个集群包含一个主节点或控制平面，它控制着一切，以及一个或多个工作节点。在 Azure 中，我们不需要关心主节点，只需要关心节点。

为了本章的目的，最好为其创建一个新的资源组：

```
az group create --location eastus--name MyKubernetes
```

在这个资源组中，我们将部署我们的集群：

```
az aks create --resource-group MyKubernetes \
  --name Cluster01 \
  --node-count 1 --generate-ssh-keys 
```

这个命令可能需要长达 10 分钟的时间。一旦你收到提示，用以下方法验证一下：

```
az aks list
```

在输出中，你会找到很多信息，比如完全合格的域名，集群的名称等等：

![获取已部署集群的详细信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_03.jpg)

###### 图 10.3：部署集群的详细信息

有一个名为 Kubernetes Dashboard 的 Web 界面可供使用，你可以用它来访问集群。要使其可用，执行以下操作：

```
az aks browse --name Cluster01 --resource-group MyKubernetes
```

将你的浏览器指向`http://127.0.0.1:8001`：

![Kubernetes Dashboard 显示有关集群和资源组的详细信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_04.jpg)

###### 图 10.4：Kubernetes Dashboard

`az`实用程序正在将门户隧道传输到你的本地主机。按*Ctrl* + *C*退出隧道。

为了能够使用`kubectl`实用程序，我们需要将配置合并到本地配置文件中：

```
az aks get-credentials --resource-group MyKubernetes \
 --name Cluster01
```

上述命令的输出如下：

![使用 az aks get-credentials 命令将配置合并到本地配置文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_05.jpg)

###### 图 10.5：将配置合并到本地配置文件

由于我们时髦的命令提示符，你可以看到我们从本地 Kubernetes 集群切换到了 Azure 中的集群。要查看可用的集群，执行以下操作：

```
kubectl config get-contexts
```

上述命令的输出如下：

![使用 kubectl config get-contexts 命令查看可用的集群](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_06.jpg)

###### 图 10.6：查看可用的集群

你可以使用`kubectl config use-context <cluster>`切换到另一个集群。

你也可以使用`kubectl`找到有关你的集群的信息：

```
kubectl cluster-info
```

上述命令的输出如下：

![使用 kubectl cluster-info 命令获取有关集群的详细信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_07.jpg)

###### 图 10.7：有关集群的信息

我们在这里创建了一个名为`Cluster01`的 Kubernetes 集群，使用了`az aks create`命令。现在让我们列出节点，这些节点是 Kubernetes 的工作机器，并由主节点管理：

```
kubectl get nodes
```

上述命令的输出如下：

![使用 kubectl get nodes 命令列出节点](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_08.jpg)

###### 图 10.8：列出节点

### 在 AKS 中的第一个部署

AKS 允许您构建和部署应用程序到托管的 Kubernetes 集群中，该集群管理容器化应用程序的连接和可用性。您可以使用简单的 `kubectl create` 命令在 AKS 中部署 Docker 容器：

```
Kubectl createnginx --image=nginx --port=80
```

几秒钟内，会出现消息：`deployment.apps/nginx created`。

使用以下命令验证部署：

```
kubectl get deployment
```

上述命令的输出如下：

![使用 kubectl get deployment 命令验证部署](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_09.jpg)

###### 图 10.9：验证镜像部署

当我们执行 `run` 命令时，Docker 容器被部署到了集群中。更具体地说，一个 pod 被创建，并在其中运行容器。一个 pod 是一组共享资源的容器，比如存储和网络资源，它还包含了如何运行容器的规范。要查看创建的 pod，请执行以下命令：

```
kubectl get pods
```

上述命令的输出返回了 pod 名称、pod 状态（运行中、挂起、成功、失败或未知）、重启次数和正常运行时间，如下所示：

![使用 kubectl get pods 命令获取 pod 的详细信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_10.jpg)

###### 图 10.10：pod 的详细信息

Pods 来来去去；它们是动态创建的，可以在扩展上/下进行。使用 `explain` 命令，您可以找到有关 pod 的各种信息：

```
kubectl explain pods/nginx-57867cc648-dkv28
```

让我们删除 pod：

```
kubectl delete pod nginx-57867cc648-dkv28 
```

再次执行 `kubectl get pods` 命令；您应该会看到一个新的 pod 可用。

### 创建服务

但实际上，您不应该关心 pod：服务才是重要的。服务是使应用程序对外界可访问的对象。在服务的背后，有一个或多个 pod。服务跟踪 pod 及其 IP 地址，并且它是一组逻辑 pod 及其策略的抽象。您可以使用以下命令列出命名空间中的所有服务：

```
kubectl get services
```

上述命令的输出如下：

![使用 get services 命令列出命名空间中的所有服务](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_11.jpg)

###### 图 10.11：列出命名空间中的所有服务

只找到一个服务，`CLUSTER-IP`。可以使用以下命令找到更多详细信息：

```
kubectl describe services/kubernetes
```

![获取 Kubernetes 中服务的描述](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_12.jpg)

###### 图 10.12：获取 Kubernetes 服务的描述

让我们摆脱我们的第一个部署：

```
kubectl delete deployment nginx
```

![使用 kubectl delete deployment nginx 命令删除第一个部署](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_13.jpg)

###### 图 10.13：删除第一个部署

让我们创建一个新的：

```
kubectl run nginx --image=nginx
```

![为 nginx 创建一个新镜像](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_14.jpg)

###### 图 10.14：创建一个新的 nginx 镜像

请注意，我们没有暴露端口。让我们使用 `kubectl get pods` 命令列出 pod。为了使资源可访问，我们添加了一个 `LoadBalancer` 类型的服务：

```
kubectl expose pod <pod name> --port=80 --target-port=80 \
  --type=LoadBalancer
```

输出应该类似于以下内容：

![列出 pod 并添加 LoadBalancer 类型的服务](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_15.jpg)

###### 图 10.15：列出 pod 并添加 LoadBalancer 类型的服务

在浏览器中使用 `EXTERNAL-IP` 地址。它会显示 `nginx` 的欢迎页面。

### 多容器 pod

一个 pod 也是 Kubernetes 用来维护容器的抽象层。有许多用例和真实场景需要在单个 pod 中有多个容器，以支持微服务容器应用程序之间的通信，如下图所示。此图中的持久存储显示了每个容器在 pod 的生命周期中进行读写操作的通信方式，当您删除 pod 时，共享的持久存储数据会丢失：

![一个块图表描述多容器 pod 的架构](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_16.jpg)

###### 图 10.16：多容器 pod 的架构

但是有一些用例是基于 pod 为 pod 内的容器提供共享资源的事实，比如：

+   带有辅助应用程序（如日志记录和监控）的容器

+   反向代理

到目前为止，我们使用`—image`参数创建了一个简单的 pod。对于更复杂的 pod，我们需要以 YAML 格式进行规范。创建一个名为`myweb.yaml`的文件，内容如下：

```
apiVersion: v1
kind: Pod
metadata:
  name: myweb
spec:
restartPolicy: Never
  volumes:
  - name: logger
emptyDir: {}
  containers:
  - name: nginx
    image: nginx
volumeMounts:
    - name: logger
mountPath: /var/log/nginx
readOnly: false
  - name: logmachine
    image: ubuntu
volumeMounts:
    - name: logger
mountPath: /var/log/nginxmachine
```

在这个文件中，创建了一个名为`journal`的共享卷。`emptydir`指令确保在创建 pod 时创建卷。

验证，执行以下命令：

```
kubectl exec myweb -c nginxfindmnt | grep logger
```

这个命令在`myweb` pod 中的`nginx`容器上执行`findmnt`命令。我们已经创建了容器、pod 和共享存储。现在让我们把注意力转移到 Helm 上，它是 Kubernetes 的包管理器。

#### 注意

前面的选项不能作为集群解决方案使用，您可能需要使用`mountOptions`标志将其中一个容器的文件系统挂载为只读。

## 使用 Helm 工作

Helm ([`helm.sh`](https://helm.sh)和[`github.com/helm`](https://github.com/helm))是 Kubernetes 的应用程序包管理器。您可以将其与 Linux 的`apt`和`yum`进行比较。它帮助使用图表管理 Kubernetes，这些图表定义、安装和升级您想要部署在 Kubernetes 上的应用程序。

Helm 的 GitHub 仓库和 Microsoft 提供了许多图表，Microsoft 是该项目最大的贡献者之一。

### 安装 Helm

如果您使用 Ubuntu 系统，有两种选择——您可以使用`snap`包安装 Helm，或者只需从[`github.com/kubernetes/helm/releases`](https://github.com/kubernetes/helm/releases)下载二进制文件。使用二进制文件适用于每个 Linux 发行版，而`snap`存储库并不总是有 Helm 的最新版本。因此，让我们使用[`github.com/helm/helm/releases`](https://github.com/helm/helm/releases)找到 Helm 的最新版本，并相应更改`helm-vx.x.x-linux-amd64.taz.gz`文件名中的`x`：

```
cd /tmp
wget https://storage.googleapis.com/kubernetes-helm/\
  helm-v2.9.1-linux-amd64.tar.gz
sudo tar xf helm-v2.9.1-linux-amd64.tar.gz --strip=1 -C \
  /usr/local/bin linux-amd64/helm
```

始终在网站上检查最新版本，并相应更改命令。

macOS 用户可以使用 Brew ([`brew.sh/`](https://brew.sh/))：

```
brew install kubernetes-helm
```

客户端已安装，有了这个客户端，我们可以将服务器部分 Tiller 部署到我们的 Kubernetes 集群中：

```
helm init
```

![使用 helm init 命令将 Tiller 部署到 Kubernetes 集群中](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_17.jpg)

###### 图 10.17：将 Tiller 部署到 Kubernetes 集群中

验证版本：

```
helm version
```

输出应该类似于以下内容：

![验证 Helm 版本](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_18.jpg)

###### 图 10.18：验证 Helm 版本

为了让 Helm 能够访问 Kubernetes 集群，必须创建一个带有相应角色的服务账户：

```
kubectl create serviceaccount \
  --namespace kube-system tiller
```

如下截图所示，我们使用`kubectl create`命令在`kube-system`命名空间中创建了 Tiller 服务账户：

![在 kube-system 命名空间中创建 Tiller 服务账户](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_19.jpg)

###### 图 10.19：在 kube-system 命名空间中创建 Tiller 服务账户

授予 Kubernetes 资源的集群管理员访问权限以执行管理任务：

```
kubectl create clusterrolebinding tiller-cluster-rule \
  --clusterrole=cluster-admin \
  --serviceaccount=kube-system:tiller
```

如下截图所示，您可以根据自己的需求创建自定义角色：

![使用 kubectl create clusterrolebinding 命令创建基于自定义角色](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_20.jpg)

###### 图 10.20：创建自定义角色

Helm 是安装在本地计算机上的客户端，Tiller 是安装在 Kubernetes 上的服务器。要重新配置 Helm，即确保 Tiller 的版本与本地 Helm 匹配，执行：

```
helm init --service-account tiller --upgrade
```

### Helm 仓库管理

Helm 仓库是一个 HTTP 服务器，可以提供 YAML 文件，并包含托管在同一服务器上的打包图表和`index.yml`。在安装期间添加了两个仓库：

+   [`kubernetes-charts.storage.googleapis.com/`](https://kubernetes-charts.storage.googleapis.com/)

+   http://127.0.0.1:8879/charts

让我们从 Microsoft 添加仓库：

```
helm repo add azure \
  https://kubernetescharts.blob.core.windows.net/azure
```

![添加来自 Microsoft 的仓库](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_21.jpg)

###### 图 10.21：从 Microsoft 添加存储库

检查可用的存储库：

```
helm repo list
```

输出应类似于以下内容：

![使用 helm repo list 命令检查可用的存储库](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_22.jpg)

###### 图 10.22：检查可用的存储库

要更新存储库信息，请执行以下操作：

```
helm repo update
```

您还可以使用`remove`参数删除存储库。

### 使用 Helm 安装应用程序

让我们看看存储库中有什么可用的内容：

```
helm search wordpress
```

前面命令的输出如下：

![关于 wordpress 的搜索结果，提供有关聊天版本、应用程序版本、描述等详细信息。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_23.jpg)

###### 图 10.23：搜索 wordpress 存储库

如果您想要有关图表的信息，如如何使用它、可用参数等，可以使用`helm inspect`命令。现在，我们只是要部署它：

```
helm install stable/wordpress
```

前面命令的安装输出日志包含访问`WordPress`实例所需的必要详细信息。

使用以下命令验证集群中 Helm 图表的状态：

```
helm ls
```

前面命令的输出返回修订名称、更新时间戳、状态、图表及其命名空间等信息：

![使用 helm ls 命令验证 Helm 图表的状态](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_24.jpg)

###### 图 10.24：验证 Helm 图表的状态

审查安装过程的先前输出：

```
helm status contrasting-chicken
```

该命令返回部署时间戳、命名空间和状态，以及资源详细信息，如`v1/PersistentVolumeClaim`、`v1/Service`、`extensions/Deployment`、`v1/Secret`以及数据库服务器的`connection`详细信息：

![使用 helm status 命令审查 helm 状态](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_25.jpg)

###### 图 10.25：审查 helm 状态

当然，`kubectl`也会向您显示以下结果：

![使用 kubectl 获取部署详细信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_26.jpg)

###### 图 10.26：使用 kubectl 获取部署详细信息

以下截图显示了`kubectl get service`命令的输出：

![kubectl get service 命令的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_27.jpg)

###### 图 10.27：kubectl get service 命令的输出

让我们删除我们的部署（名称可以使用`helm ls`找到）：

```
helm delete <NAME>
```

![使用 helm delete 命令删除部署](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_28.jpg)

###### 图 10.28：使用 helm delete 命令删除部署

要自定义应用程序，请执行以下操作：

```
helm inspect stable/wordpress
```

然后，搜索 WordPress 设置：

![搜索 WordPress 设置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_29.jpg)

###### 图 10.29：搜索 WordPress 设置

创建一个 YAML 文件，例如`custom.yaml`，其中包含以下内容：

```
image:
  registry: docker.io
  repository: bitnami/wordpress
  tag: 4-ol-7
wordpressUsername: linuxstar01
wordpressEmail: linuxstar01@example.com
wordpressFirstName: Kamesh
wordpressLastName: Ganesan
wordpressBlogName: Linux on Azure – 2nd Edition!
```

然后，部署 WordPress 应用程序：

```
helm install stable/wordpress -f custom.yaml
```

您可以使用`kubectl`命令验证结果。首先，获取 Pod 的名称：

```
kubectl get pod
```

![使用 kubectl get pod 命令验证 WordPress 应用程序的部署](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_30.jpg)

###### 图 10.30：验证 WordPress 应用程序的部署

之后，执行以下操作：

```
kubectl describe pod <podname>
```

![使用 kubectl describe pod 命令获取 pod 的描述](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_31.jpg)

###### 图 10.31：获取 pod 描述

例如，在“事件”部分，您会看到拉取了`docker.io/bitnami/wordpress:4-ol-7`镜像。

清理一切：

```
helm delete stable/wordpress
kubectl scale sts --all --replicas=0
kubectl delete pod --all
kubectl delete sts --all --cascade=false
```

不要担心有状态的集合（`sts`）；它们是由该应用程序创建的，用于有序部署和共享持久存储。

### 创建 Helm 图表

Helm 图表类似于 Linux 发行版中使用的软件包，您可以使用 Helm 客户端浏览软件包存储库（图表）目录结构。有许多为您创建的图表，也可以创建自己的图表。

首先，创建一个工作目录，并准备好使用：

```
helm create myhelm
cd myhelm
```

前面的命令应该给出类似的输出：

![创建一个工作目录，并通过首先运行 cd myhelm 然后执行 ls -al 命令使其准备好使用](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_32.jpg)

###### 图 10.32：创建工作目录

创建了一些文件和目录：

+   `Chart.yaml`文件：该文件包含有关图表的基本信息。

+   `values.yaml`文件：默认配置值。

+   `charts`目录：依赖图表。

+   `templates`目录：用于为 Kubernetes 创建清单文件

此外，您还可以添加一个`LICENSE`文件，一个`README.md`文件和一个带有要求的文件，`requirements.yaml`。

让我们稍微修改`Chart.yaml`：

```
apiVersion: v1
appVersion: 1.15.2
description: My First Nginx Helm
name: myhelm
version: 0.1.0
maintainers:
- name: Kamesh Ganesan
    email: kameshg@example.com
    url: http://packtpub.com
```

该文件或多或少是自解释的：维护者是可选的。`appVersion`是指，在这个例子中，nginx 的版本。

使用以下命令验证配置：

```
helm lint
```

花些时间来调查`templates`目录和`value.yaml`文件中的文件。当然，我们之所以使用 nginx 作为示例，是因为`helm create`创建的文件也使用 nginx 作为示例。

首先，执行干运行：

```
helm install --dry-run --debug ../myhelm
```

这样，您就可以看到将用于部署应用程序的清单。之后，您就可以安装它了：

```
helm install ../myhelm
```

安装后，我们意识到在干运行时，有一些不对劲：nginx 的版本是`nginx: stable`，即版本 1.14.0。打开`values.yaml`文件，将`tag: stable`更改为`tag: 1.15.2`。

使用`helm ls`查找名称并更新它：

```
helm upgrade <name> ../myhelm
```

将创建一个新的 pod；旧的将被删除：

![通过将新的 pod 替换为旧的 pod 来查找 pod 的名称并更新它的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_33.jpg)

###### 图 10.33：更新 pod 版本

甚至有一个`rollback`选项，如果您想恢复到旧版本：

```
helm rollback <RELEASE> <REVISION>
```

您只需要指定要恢复的发布和修订版本。

## 使用草稿

作为开发人员，您通常会使用 Helm，用于准备就绪的应用程序，并且应该进行维护。您很可能还将代码托管在 GitHub 等版本控制系统上。

这就是草稿（[`github.com/Azure/draft`](https://github.com/Azure/draft)）的用武之地。它试图简化流程，从您的代码开始，在 Kubernetes 集群中进行。

该工具正在大力开发中。草稿变得越来越受欢迎和稳定，定期添加新的语言和功能。

如果开发阶段变成了似乎可用的东西，您仍然可以使用草稿，但更有可能的是您也会转向 Helm。

要了解草稿支持哪些编程语言，您可以在安装后执行以下命令：

```
draft pack list
Available Packs:
  github.com/Azure/draft/clojure
  github.com/Azure/draft/csharp
  github.com/Azure/draft/erlang
  github.com/Azure/draft/go
  github.com/Azure/draft/gradle
  github.com/Azure/draft/java
  github.com/Azure/draft/javascript
  github.com/Azure/draft/php
  github.com/Azure/draft/python
  github.com/Azure/draft/ruby
  github.com/Azure/draft/rust
  github.com/Azure/draft/swift
```

### 安装草稿

要使用草稿，必须安装和配置 Helm。

从[`github.com/Azure/draft/releases`](https://github.com/Azure/draft/releases)获取您的副本：

```
cd /tmp
wget https://azuredraft.blob.core.windows.net/draft/\
  draft-v0.15.0-linux-amd64.tar.gz
sudo tar xf draft-v0.15.0-linux-amd64.tar.gz --strip=1 \
  -C /usr/local/bin linux-amd64/draft
```

始终在网站上检查最新版本，并相应更改命令。

macOS 用户可以使用 Brew 安装它：

```
brew tap azure/draft && brew install draft
```

您可以看到，使用 Helm 的开发人员也参与了 Draft 的开发。在这两种情况下，其中许多人是微软的开发人员。与 Helm 类似，在安装客户端后，您必须初始化草稿：

```
draft init
```

这将安装一些默认插件并设置您可以在草稿中使用的存储库。

使用以下命令检查版本：

```
draft version
```

在撰写本文时，其版本为 0.16.0：

![输出显示草稿版本为 0.16.0](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_34.jpg)

###### 图 10.34：检查草稿版本

最后一步涉及配置 Docker 存储库、Docker Hub 或 Azure。在本书的目的中，我们使用的是 Azure。

创建**Azure 容器注册表**（**ACR**）：

```
az acr create --resource-group MyKubernetes --name LinuxStarACR --sku Basic
```

登录到`LinuxStarACR`：

```
az acr login --name LinuxStarACR
```

![使用 az acr login --name LinuxStarACR 命令登录到 LinuxStarACR](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_35.jpg)

###### 图 10.35：登录到 LinuxStarACR

配置存储库：

```
draft config set registry LinuxStarACR
```

登录到注册表：

```
az acr login --name LinuxStarACR
```

在草稿和 ACR 之间创建信任：

```
export AKS_SP_ID=$(azaks show \
 --resource-group <resource group> \
 --name <Kubernetes Cluster>
 --query "servicePrincipalProfile.clientId" -o tsv)
export ACR_RESOURCE_ID=$(azacr show \
 --resource-group <resource group>\
 --name <ACR Name> --query "id" -o tsv)
az role assignment create --assignee $AKS_SP_ID --scope $ACR_RESOURCE_ID --role contributor 
```

我们已成功安装了 Draft v0.16.0 并创建了 ACR。最后，我们在 Draft 和 ACR 之间创建了信任。现在是时候继续开始使用草稿了。

### 使用草稿

让我们开发一些简单的 Draft 代码。为此，我们将创建一个名为`mynode`的目录。在这个目录中，我们将创建一个名为`mynode.js`的文件，其中包含以下代码：

```
var http = require('http');
var server = http.createServer(function(req, res) {
res.writeHead(200);
res.end('Hello World!');
});
server.listen(8080);
```

这是一个简单的 Web 服务器，提供一个显示`Hello World!`的页面。我们处于开发过程的早期阶段。要创建一个`package.json`文件，请执行以下操作：

```
npminit
```

填写信息：

```
name: (mynode)
version: (1.0.0) 0.0.1
description: My first Node App
entry point: (mynode.js)
test command: node mynode.js
git repository:
keywords: webapp
author: Kamesh Ganesan
license: (ISC)
```

现在我们准备执行 Draft：

```
draft create
```

![使用 draft create 命令创建 Dockerfile](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_36.jpg)

###### 图 10.36：使用 draft create 命令创建 Dockerfile

这将创建一个 Dockerfile 和所有 Helm 的信息。

输出的最后一行“准备启航”实际上意味着你已经准备好执行：

```
draft up
```

上述命令生成以下输出：

![使用 draft up 命令构建和推送 Docker 镜像](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_37.jpg)

###### 图 10.37：构建和推送 Docker 镜像

这将构建镜像并发布应用程序。

执行`helm ls`将显示`mynode`应用程序：

![显示 mynode 应用程序的详细信息的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_38.jpg)

###### 图 10.38：获取 mynode 应用程序的详细信息

使用`kubectl get services`来显示服务：

![使用 kubectl get services 命令显示服务](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_39.jpg)

###### 图 10.39：使用 kubectl get services 显示服务

这里一切似乎都很正常，但`kubectl get pod`告诉我们情况并非如此：

![使用 kubectl get pod 命令检查 pod 的状态](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_40.jpg)

###### 图 10.40：检查 pod 的状态

`draft logs`命令没有显示任何错误。因此，让我们看看 Kubernetes 认为什么：

```
kubectl logs <Pod Name>
```

它声明`npm ERR! missing script: start`。故意在`package.json`文件中制造了一个错误。根据以下示例修改内容，修改值：

```
{
"name": "mynode",
"version": "0.0.2",
"description": "My first Node App",
"main": "mynode.js",
"scripts": {
"start": "node mynode.js",
"test": "echo \"Error: no test specified\"& exit 1"
  },
"keywords": [
"webapp"
  ],
"author": "Kamesh Ganesan",
"license": "ISC"
}
```

通过再次执行以下操作来更新应用程序：

```
draft update
```

连接到应用程序：

```
draft connect
```

![使用 draft connect 命令连接应用程序](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_41.jpg)

###### 图 10.41：连接到应用程序

打开另一个终端：

```
curl localhost:39053
```

输出必须是`Hello World!`。

在终端中按下*Ctrl* + *C*，运行`draft connect`，并删除部署：

```
draft delete
```

使用`kubectl get all`检查集群资源，并根据需要进行清理。

## 管理 Kubernetes

我们已经创建了一个 Kubernetes 集群，并且学习了`kubectl`实用程序以及一些可用于开发和维护 Kubernetes 集群中应用程序的工具。

因此，如果回顾一下本章开头的三个问题，我们已经回答了第一个问题。在本节中，我们将回答另外两个问题，并介绍如何更新 Kubernetes 版本。

### 更新应用程序

早些时候，我们使用 Helm 和 Draft 来管理我们的应用程序，这意味着所有的辛苦工作都已经为我们完成。但是你也可以借助`kubectl`来更新工作负载。

通常情况下，我们的集群现在应该是空的，所以让我们快速再次部署我们的`nginx` pod：

```
kubectl run nginx --image=nginx
```

仔细查看部署：

![显示 nginx pod 部署成功的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_42.jpg)

###### 图 10.42：部署 nginx pod

这实际上告诉我们，我们想要一个实例，有一个正在运行，它是最新的（已更新以匹配所需容量的实例数），并且它是可用的。运行的 nginx 版本不是最新的，所以我们想要将其更新到版本 1.17.5。执行以下操作：

```
kubectl edit deployment/nginx
```

将镜像更改为`nginx:1.17.5`：

![将镜像更改为 nginx:1.17.5](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_43.jpg)

###### 图 10.43：将镜像更改为 nginx:1.17.5

**kubectl rollout**命令可用于管理资源部署。一些有效的 rollout 选项包括 status、history、pause、restart、resume 和 undo。**kubectl rollout status**显示部署的当前状态，而**kubectl rollout history**列出以前的修订和配置。

```
kubectl rollout status deployment nginx
kubectl rollout history deployment nginx
```

或者，更好的是，您可以使用`describe`命令，它为您提供比前两个命令结合起来更详细的输出：

```
kubectl describe deployment nginx
```

使用 kubectl describe deployment 命令获取 nginx 部署的更详细输出

###### 图 10.44：nginx 部署的详细信息

更新部署的另一种方法是使用`set image`命令，通过更新映像来部署更新的 nginx 容器，新版本为 1.17.5，如下所示：

```
kubectl set image deployment/nginxnginx=nginx:1.17.5 --record
```

如前面的屏幕截图所示，nginx 容器映像已成功升级为版本 1.17.5。

### 扩展应用程序

目前有一个正在运行的 pod，但为了处理所有传入的负载，您可能需要更多实例并且需要负载平衡传入的流量。为此，您需要副本来定义任何给定时间运行的指定数量的 pod 副本。

让我们回到`kubectl`并获取当前的部署：

获取当前部署的状态

###### 图 10.45：获取当前部署的状态

此刻的期望（配置）状态是`1`。当前情况是`1`，有`1`个可用。

要扩展到三个实例，请执行以下操作：

```
kubectl scale deployment nginx --replicas=3
```

再次运行`kubectl get deployments`；然后查看可用的 pod：

```
kubectl get pods -o wide
```

显示扩展后可用 pod 的状态的输出

###### 图 10.46：扩展后检查可用的 pod

创建负载均衡器服务：

```
kubectl expose deployment nginx --type=LoadBalancer \
 --name=nginx-lb --port 80
kubectl get services
```

显示创建负载均衡器服务的输出

###### 图 10.47：创建负载均衡器服务

现在每个 HTTP 请求都由负载均衡器处理，并且流量分布在实例之间。

您还可以使用自动缩放。首先，安装 Metrics Server：

```
git clone https://github.com/kubernetes-incubator/metrics-server.git 
kubectl create -f metrics-server/deploy/1.8+/
```

配置自动缩放：如果负载超过`50`％，则会创建额外的实例，最多为`10`：

```
kubectl autoscale deployment nginx --cpu-percent=50 --min=3 --max=10
```

当然，在这种情况下，至少有两个节点在您的集群中是有意义的：

```
azaks scale --name Cluster01 \
  --resource-group MyKubernetes \
  --node-count 2
kubectl get nodes
```

请注意，此过程大约需要 10 分钟。要查看自动缩放的状态，请执行以下操作：

```
kubectl get hpa
```

使用 kubectl get hpa 命令查看自动缩放的状态

###### 图 10.48：列出自动缩放器

### 升级 Kubernetes

与任何软件或应用程序一样，您需要定期升级 Kubernetes 集群以使其保持最新状态。升级非常重要，可以获得最新的错误修复和所有关键的安全功能，以及最新的 Kubernetes 功能。如果要在不间断的情况下升级 Kubernetes 控制平面，则还需要有多个可用节点。以下步骤将向您展示如何快速升级 Kubernetes 集群。

首先查看当前版本：

```
az aks list --query "[].kubernetesVersion"
```

显示当前 Kubernetes 版本为 1.13.12 的输出

###### 图 10.49：查看当前 Kubernetes 版本

询问您位置的可用版本：

```
az aks get-versions --location eastus --output table | egrep "¹.13.12"
```

获取 East US 位置可用版本的输出

###### 图 10.50：East US 位置的可用版本

我们可以升级到版本 1.14.8：

```
az aks upgrade --resource-group MyKubernetes
  --name Cluster01 \
  --kubernetes-version 1.14.8 --yes --no-wait
```

添加`--no-wait`参数的效果是您几乎立即就能恢复提示符。

这样，大约 3 分钟后，您可以开始使用`kubectl`来获取节点和 pod 的状态（使用`-owide`参数，例如`kubectl get pods -o wide`），并了解已创建具有最新版本的新节点。工作负载在该节点上重新创建，并更新了另一个节点。之后，最后一个剩下的节点被清空并升级。

## 持久存储

在上一章中，我们提到了在容器中使用持久存储的多种方法，并且在本章中也提到了这一点。

Kubernetes 可以配置持久存储，但您必须提供它，例如通过 NFS 容器或通过实施 StorSimple iSCSI 虚拟阵列（如果您需要从多个容器进行读/写访问，这将特别有用）。即使您使用 Azure 存储，也有许多选择要做。您想使用磁盘还是 Azure 存储？您想动态创建它们还是使用现有的（静态）？大多数这些问题都是基于成本和对复制、备份和快照等服务需求来回答的。

在本节中，我们想要涵盖动态选项；在编排方面，这是一个更好的选择，因为您可以在 Kubernetes 内部完成所有操作（或使用其周围的工具）。

无论您使用 Azure 存储还是磁盘，您都需要在与 Kubernetes 相同的资源组中拥有一个存储账户：

```
az storage account create --resource-group MyKubernetes \
 --name mystorageest1 –sku Standard_LRS
```

请查看*第二章*，*开始使用 Azure 云*，以获取上述命令的语法。请记住，名称必须是唯一的。

### Kubernetes 的 Azure 磁盘

您可以动态或静态地为在 AKS 集群中的一个或多个 Kubernetes pod 使用的持久卷提供存储类。有两种存储类：标准 Azure 磁盘（默认）和高级 Azure 磁盘，这是一种托管的高级存储类：

1.  首先，创建一个 YAML 文件来创建存储类。这样可以自动提供存储：

```
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: storageforapp
provisioner: kubernetes.io/azure-disk
parameters:
storageaccounttype: Standard_LRS
 location: eastus
 kind: shared
```

1.  使用以下内容应用它：

```
kubectlapply -f storageclass.yaml
```

用刚创建的文件名替换文件名。

1.  还需要另一个 YAML 文件来索赔持久卷，或者换句话说，创建它：

```
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: claim-storage-for-app
  annotations:
volume.beta.kubernetes.io/storage-class: storageforapp
spec:
accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
```

1.  请注意，匹配是在注释中完成的。也要应用这个文件：

```
kubectlapply -f persistentvolume.yaml
```

1.  使用以下内容验证结果：

```
kubectl get sc
```

![执行 kubectl get sc 命令以验证存储类的创建](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_51.jpg)

###### 图 10.51：验证存储类的创建

1.  要在 pod 中使用存储，可以像以下示例一样使用它：

```
kind: Pod
apiVersion: v1
metadata:
  name: my-web
spec:
  containers:
    - name: nginx
      image: nginx
volumeMounts:
      - mountPath: "/var/www/html"
        name: volume
  volumes:
    - name: volume
persistentVolumeClaim:
claimName: claim-storage-for-app
```

### Kubernetes 的 Azure 文件

当您以`ReadWriteOnce`访问模式类型挂载 Azure 磁盘时，它将仅对 AKS 中的单个 pod 可用。因此，您需要使用 Azure 文件来在多个 pod 之间共享持久卷。Azure 文件的配置与 Azure 磁盘并没有太大不同，如前一节所述。创建存储类的 YAML 文件如下：

```
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: azurefile
provisioner: kubernetes.io/azure-file
mountOptions:
  - dir_mode=0888
  - file_mode=0888
  - uid=1000
  - gid=1000
  - mfsymlinks
  - nobrl
  - cache=none
parameters:
skuName: Standard_LRS
```

通过执行以下 YAML 文件使用持久卷索赔来提供 Azure 文件共享：

```
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: azurefile
spec:
accessModes:
    - ReadWriteMany
storageClassName: azurefile
  resources:
    requests:
      storage: 5Gi
```

按以下方式应用这两个 YAML 文件：

。

![使用持久卷索赔创建 Azure 文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_52.jpg)

###### 图 10.52：使用持久卷索赔创建 Azure 文件

执行 Azure 文件存储创建 YAML 和存储卷索赔 YAML 的结果如下：

![验证 Azure 文件和 Azure 磁盘的创建](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_10_53.jpg)

###### 图 10.53：验证 Azure 文件和 Azure 磁盘的创建

如您所见，pod 中的规范保持不变。通过这些逐步实施，我们成功地为持久存储需求创建了 Azure 磁盘和 Azure 文件。

## 总结

本章主要讨论了 Kubernetes。我们从描述开发人员可能的工作环境开始，即具有工具启动本地开发的良好工作站，即使在本地安装了 Kubernetes。我们以 Ubuntu Desktop 为例，但实际上，只要您对开发环境满意，就没有关系。

一切就绪后，我们使用 Azure CLI 和 PowerShell 覆盖了在 Azure 中配置 Kubernetes 集群。

在 Azure 中部署工作负载可以简单地执行`kubectl run`，但也探讨了更复杂的场景，如多容器应用程序。

作为开发人员，有两种工具可帮助简化您的开发流程：Draft 和 Helm。Draft 用于初始开发阶段，Helm 用于安装和维护应用程序之后。

Kubernetes 是一个管理容器的工具，使得部署、维护和更新工作负载变得容易。可伸缩性是使用 Kubernetes 的优势之一；甚至可以根据所需的 CPU 和内存资源自动扩展。

本章的最后一节涵盖了在 Kubernetes 中使用持久存储，实际上为您提供了比在容器中存储数据或直接将存储附加到容器中更好的方式。

在下一章中，我们将回到 DevOps 的 Ops 部分——即故障排除和监视您的工作负载，而工作负载指的是安装了 Linux 的虚拟机、容器和 AKS。

## 问题

1.  什么是 Pod？

1.  创建多容器 Pod 的一个好理由是什么？

1.  您可以使用哪些方法在 Kubernetes 中部署应用程序？

1.  您可以使用哪些方法来更新 Kubernetes 中的应用程序？

1.  如果您想要升级控制平面，是否需要在 Kubernetes 中创建额外的节点？

1.  您能想到为什么要使用 iSCSI 解决方案的原因吗？

1.  作为练习，重新创建使用持久存储的多容器 Pod。

## 进一步阅读

本章的目标是提供一个实用的方法，让您的工作负载在 Azure 云中运行。我们希望这是您进入 Kubernetes 世界的开始。还有很多东西等待您去发现！

Nigel Poulton 是一位已经写过关于 Docker 的优秀书籍的作者，他还写了一本关于 Kubernetes 的书籍*The Kubernetes Book*。如果您对 Kubernetes 真的很新，这是一个很好的起点。Gigi Sayfan 写了*Mastering Kubernetes*。确保购买第二版！不仅因为第一版不太好，而且因为它是必备的，并提供比第一版更多的信息。

作为开发人员，您应该尝试*Kubernetes for Developers*：Joseph Heck 可以告诉您更多关于使用 Kubernetes 的开发生命周期，使用 Node.js 和 Python 的示例。在他的书的最后一章中，他提到了 Helm 和 Brigade 等新兴项目。我们希望这将在以后的版本中更详细地探讨，甚至可能在另一本书中。

谈到 Brigade，[`brigade.sh`](https://brigade.sh)在其官方网站上被描述为“*在云中运行可编写脚本的自动化任务的工具——作为您的 Kubernetes 集群的一部分*。”这远远超出了本书的范围，而且它基本上还处于早期开发阶段。作为开发人员，您应该花一些时间阅读更多关于它并尝试它。

最后但同样重要的是，另一个值得一提的重要资源是 Azure 的开放服务经纪人（OSBA：[`osba.sh`](https://osba.sh)）。它没有出现在本章中，因为在撰写本文时它还不完全具备生产能力。OSBA 是与外部服务（如数据库和存储）通信的开放标准。这是另一种为容器提供数据和存储数据的解决方案。


# 第十一章：故障排除和监视工作负载

故障排除和日志记录非常相关；当您遇到问题时，您开始分析事件、服务和系统日志。

在云环境中解决问题和修复问题可能与在更经典的部署中进行故障排除不同。本章解释了在 Azure 环境中故障排除 Linux 工作负载的差异、挑战和新可能性。

在本章结束时，您将能够：

+   使用不同工具在 Linux 系统中进行性能分析。

+   监视 CPU、内存、存储和网络等指标的详细信息。

+   使用 Azure 工具识别和解决问题。

+   使用 Linux 工具识别和解决问题。

## 技术要求

对于本章，您需要运行 Linux 发行版的一个或两个 VM。如果您愿意，可以使用最小的大小。必须安装`audit`守护程序，并且为了具有要分析和理解的审计系统日志，最好安装 Apache 和 MySQL/MariaDB 服务器。

以下是 CentOS 的一个示例：

```
sudo yum groups install ''Basic Web Server''
sudo yum install mariadbmariadb-server
sudo yum install setroubleshoot
sudosystemctl enable --now apache2
sudosystemctl enable --now mariadb
```

`auditd`通过使用可以根据您的需求进行修改的审计规则，提供关于服务器性能和活动的深入详细信息。要安装`audit`守护程序，请使用以下命令：

```
sudo yum list audit audit-libs
```

执行上述命令后，您将获得以下输出：

![安装审计守护程序](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_01.jpg)

###### 图 11.1：安装审计守护程序

如果您可以看到如前所示的已安装的审计软件包列表，则已经安装了；如果没有，则运行以下命令：

```
sudo yum install audit audit-libs
```

成功安装`auditd`后，您需要启动`auditd`服务以开始收集审计日志，然后存储日志：

```
sudo systemctl start auditd
```

如果您想在启动时启动`auditd`，那么您必须使用以下命令：

```
sudo systemctl enable auditd
```

现在让我们验证`auditd`是否已成功安装并开始使用以下命令收集日志：

```
tail -f /var/log/audit/audit.log
```

![验证 auditd 的安装和日志收集](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_02.jpg)

###### 图 11.2：验证成功安装 auditd 并收集日志

在本章中，我们将涵盖一般的 Azure 管理和 Azure Monitor。Linux 的 Log Analytics 代理，用于从 VM 收集信息，不受每个 Linux 发行版的支持；在决定要在本章中使用哪个发行版之前，请访问[`docs.microsoft.com/en-us/azure/virtual-machines/extensions/oms-linux`](https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/oms-linux)。

#### 注意

**运营管理套件**（**OMS**）通常已停用，并过渡到 Azure，名称“OMS”不再在任何地方使用，除了一些变量名称。现在它被称为 Azure Monitor。有关命名和术语更改的更多信息，请参阅[`docs.microsoft.com/en-gb/azure/azure-monitor/terminology`](https://docs.microsoft.com/en-gb/azure/azure-monitor/terminology)，或者您也可以在[`docs.microsoft.com/en-us/azure/azure-monitor/platform/oms-portal-transition`](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/oms-portal-transition)获取有关过渡的详细信息。

## 访问您的系统

学会排除工作负载将有助于您的日常工作。在 Azure 中进行故障排除与在其他环境中进行故障排除并无不同。在本节中，我们将看到一些技巧和窍门，这些将有助于您的日常工作。

### 无远程访问

当您无法通过 SSH 访问 Azure VM 时，可以通过 Azure 门户运行命令。

要在 Azure 门户上的 Azure VM 上运行命令，请登录到 Azure 门户，导航到您的 VM 并选择**运行命令**：

![导航到 Azure 门户中的 VM 部分的命令列表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_03.jpg)

###### 图 11.3：导航到 Azure 门户中的 VM 部分

或者，您可以使用命令行，如下所示：

```
az vm run-command invoke --name <vm name> \
  --command-id RunShellScript \
  --scripts hostnamectl \
  --resource-group <resource group>
```

`az vm run`命令可用于在 VM 中运行 shell 脚本，用于一般机器或应用程序管理以及诊断问题。

无论是通过命令行还是通过 Azure 门户，只有在 Microsoft Azure Linux 代理仍在运行并可访问时，`az vm`命令才能正常工作。

#### 注意

您可以在[`github.com/Azure/azure-powershell`](https://github.com/Azure/azure-powershell)获取最新的 Microsoft Azure PowerShell 存储库，其中包含安装步骤及其用法。`az`正在取代 AzureRM，所有新的 Azure PowerShell 功能将只在`az`中提供。

根据安全最佳实践，您需要通过登录到 Azure 帐户并使用`az vm user`来重置密码来更改密码如下：

```
az vm user update \
  --resource-group myResourceGroup \
  --name myVM \
  --username linuxstar \
  --password myP@88w@rd
```

只有当您配置了具有密码的用户时才有效。如果您使用 SSH 密钥部署了 VM，那么您很幸运：同一部分中的**重置密码**选项将完成工作。

此选项使用 VMAccess 扩展（[`github.com/Azure/azure-linux-extensions/tree/master/VMAccess`](https://github.com/Azure/azure-linux-extensions/tree/master/VMAccess)）。与前面讨论的**运行命令**选项一样，它需要 Azure VM 代理。

### 处理端口

您无法远程访问的原因可能与网络有关。在*第五章*，*高级 Linux 管理*中，`ip`命令在*网络*部分中被简要介绍。您可以使用此命令验证 IP 地址和路由表。

在 Azure 站点上，必须检查网络和网络安全组，如*第三章*，*基本 Linux 管理*中所述。在 VM 中，您可以使用`ss`命令，例如`ip`，它是`iproute2`软件包的一部分，用于列出处于监听状态的 UPD（`-u`）和 TCP（`p`）端口，以及打开端口的进程 ID（`-p`）：

![使用 ss -tulpn 命令检查端口详细信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_04.jpg)

###### 图 11.4：使用 ss -tulpn 命令检查端口

可以使用`firewall-cmd --list-all --zone=public`快速检查防火墙规则；如果有多个区域和接口，您需要为每个区域执行此操作。要包括 Azure Service Fabric 创建的规则，可以使用`iptables-save`：

![使用 iptables-save 命令包括 Azure Service Fabric 创建的规则](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_05.jpg)

###### 图 11.5：包括 Azure Service Fabric 创建的规则

不幸的是，在`systemd`单元级别没有可用的注释来查看所有访问规则的配置。不要忘记验证它们，如*第六章*，*管理 Linux 安全和身份*中所讨论的那样。

### 使用 nftables

`nftables`比`iptables`更容易使用，并且它将整个`iptables`框架与简单的语法结合在一起。`nftables`建立在一个内核`netfilter`子系统上，可用于创建分组的复杂过滤规则。nftables 比`iptables`具有许多优点。例如，它允许您使用单个规则执行多个操作。它使用`nft`命令行工具，也可以使用`nft -i`命令以交互模式使用：

1.  使用以下命令安装`nftables`：

```
sudo apt install nftables
```

1.  然后安装`compat`，加载与`nftables`内核子系统的兼容性：

```
apt install iptables-nftables-compat
```

1.  最后，使用以下命令启用`nftables`服务：

```
sudo systemctl enable nftables.service
```

1.  您可以使用以下命令查看当前的`nft`配置：

```
nft list ruleset
```

1.  此外，您可以使用以下命令登录到`nft`交互模式：

```
nft –i
```

1.  现在，您可以使用以下`list`命令列出现有的规则集：

```
nft> list ruleset
```

1.  让我们创建一个新表，`rule_table1`：

```
nft>add table inet rule_table1
```

1.  现在，我们需要添加接受入站/出站流量的链命令如下：

```
nft>add chain inet rule_table1 input { type filter hook input priority 0 ; policy accept; }
nft>add chain inet rule_table1 output { type filter hook input priority 0 ; policy accept; }
```

1.  您可以使用以下命令添加规则以接受 TCP（传输控制协议）端口：

```
nft>add rule inet rule_table1 input tcpdport { ssh, telnet, https, http } accept
nft>add rule inet rule_table1 output tcpdport { https, http } accept
```

1.  这是我们新的`nftables`配置的输出：

```
nft> list ruleset
table inet rule_table1 {
        chain input {
                type filter hook input priority 0; policy accept;
tcpdport { ssh, telnet, http, https } accept
        }
        chain output {
                type filter hook input priority 0; policy accept;
tcpdport { http, https } accept
        }
}
```

### 引导诊断

假设您已经创建了您的 VM，可能是经过编排的，并且很可能是您自己的 VM，但它无法启动。

在启用 VM 的引导诊断之前，您需要一个存储账户来存储数据。您可以使用 `az storage account list` 列出已经可用的存储账户，如果需要，可以使用 `az storage account create` 命令创建一个存储账户。

现在让我们通过在 Azure CLI 中输入以下命令来启用引导诊断：

```
az vm boot-diagnostics enable --name <vm name>\
  --resource-group <resource group> \
  --storage <url>
```

区别在于您不需要存储账户的名称，而是需要存储 blob 的名称，可以通过 `az storage account list` 命令作为存储账户的属性找到。

在 Azure CLI 中执行以下命令以接收引导日志：

```
az vm boot-diagnostics get-boot-log \
--name <virtual machine> \
  --resource-group <resource group>
```

输出也会自动存储在一个文件中；在 Azure CLI 中，最好通过 `less` 进行管道处理或将其重定向到文件中。

### Linux 日志

典型的 Linux 系统上运行着许多进程、服务和应用程序，它们产生不同的日志，如应用程序、事件、服务和系统日志，可用于审计和故障排除。在早期的章节中，我们遇到了 `journalctl` 命令，用于查询和显示日志。在本章中，我们将更详细地讨论这个命令，并看看如何使用 `journalctl` 实用程序来切割和处理日志。

在使用 systemd 作为其 `init` 系统的 Linux 发行版中，如 RHEL/CentOS、Debian、Ubuntu 和 SUSE 的最新版本中，使用 `systemd-journald` 守护程序进行日志记录。该守护程序收集单元的标准输出、syslog 消息，并且（如果应用程序支持）将应用程序的消息传递给 systemd。

日志被收集在一个数据库中，可以使用 `journalctl` 进行查询。

**使用 journalctl**

如果您执行 `systemctl status <unit>`，您可以看到日志的最后条目。要查看完整的日志，`journalctl` 是您需要的工具。与 `systemctl` 不同的是：您可以使用 `-H` 参数在其他主机上查看状态。您不能使用 `journalctl` 连接到其他主机。这两个实用程序都有 `–M` 参数，用于连接到 `systemd-nspawn` 和 `Rkt` 容器。

要查看日志数据库中的条目，请执行以下操作：

```
Sudo journalctl --unit <unit>
```

![使用 journalctl --unit <unit> 命令查看日志数据库中的条目](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_06.jpg)

###### 图 11.6：查看日志数据库中的条目

默认情况下，日志使用 `less` 进行分页。如果您想要另一个分页器，比如 `more`，那么您可以通过 `/etc/environment` 文件进行配置。添加以下行：

```
SYSTEMD_PAGER=/usr/bin/more
```

以下是输出的示例：

![使用 journalctl 命令获取进程的日志条目](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_07.jpg)

###### 图 11.7：使用 journalctl 命令获取进程的日志条目

让我们来看一下输出：

+   第一列是时间戳。在数据库中，它是以 EPOCH 时间定义的，因此如果您更改时区，没有问题：它会被转换。

+   第二列是主机名，由 `hostnamectl` 命令显示。

+   第三列包含标识符和进程 ID。

+   第四列是消息。

您可以添加以下参数来过滤日志：

+   `--dmesg`：内核消息，替代了旧的 `dmesg` 命令

+   `--identifier`：标识符字符串

+   `--boot`：当前引导过程中的消息；如果数据库在重启后是持久的，还可以选择以前的引导

**过滤器**

当然，您可以在标准输出上使用 `grep`，但 `journalctl` 有一些参数，可以帮助您过滤出所需的信息：

+   `--priority`：按 `alert`、`crit`、`debug`、`emerg`、`err`、`info`、`notice` 和 `warning` 进行过滤。这些优先级的分类与 syslog 协议规范中的相同。

+   `--since` 和 `--until`：按时间戳过滤。参考 `man systemd.time` 查看所有可能性。

+   `--lines`：行数，类似于 `tail`。

+   `--follow`：类似于 `tail -f` 的行为。

+   `--reverse`：将最后一行放在第一行。

+   `--output`：将输出格式更改为 JSON 等格式，或者向输出添加更多详细信息。

+   `--catalog`：如果有消息的解释，则添加消息的解释。

所有过滤器都可以组合，就像这里一样：

```
sudo journalctl -u sshd --since yesterday --until 10:00 \
  --priority err
```

![使用 journalctl 使用多个参数过滤日志条目](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_08.jpg)

###### 图 11.8：使用 journalctl 使用多个过滤器过滤日志条目

**基于字段的过滤**

我们还可以根据字段进行过滤。键入此命令：

```
sudojournactl _
```

现在按两次*Ctrl* + *I*；您将看到所有可用字段。这些过滤器也适用于相同的原则；也就是说，您可以将它们组合起来：

```
sudo journalctl _UID=1000 _PID=1850
```

您甚至可以将它们与普通过滤器组合使用：

```
sudo journalctl _KERNEL_DEVICE=+scsi:5:0:0:0 -o verbose
```

**数据库持久性**

现在，您可能需要出于合规原因或审计要求存储日志一段时间。因此，您可以使用 Azure Log Analytics 代理从不同来源收集日志。默认情况下，日志数据库不是持久的。为了使其持久化，出于审计或合规原因（尽管最佳做法不是将日志存储在本地主机），您必须编辑配置文件`/etc/systemd/journald.conf`。

将`#Storage=auto`行更改为此：

```
Storage=persistent
```

使用`force`重新启动`systemd-journald`守护程序：

```
sudo systemctl force-reload systemd-journald
```

使用此查看记录的引导：

```
sudo journalctl --list-boots
```

![使用--list-boots 命令查看记录的引导](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_09.jpg)

###### 图 11.9：查看记录的引导

您可以使用`--boot`参数将引导 ID 作为过滤器添加：

```
journalctl --priority err --boot <boot id>
```

通过这种方式，`hostnamectl`的输出显示当前的引导 ID。

日志数据库不依赖于守护程序。您可以使用`--directory`和`--file`参数查看它。

**Syslog 协议**

在实施 syslog 协议期间，Linux 和 Unix 家族的其他成员启用了日志记录。它仍然用于将日志发送到远程服务。

重要的是要理解该协议使用设施和严重性。这两者在 RFC 5424（[`tools.ietf.org/html/rfc5424`](https://tools.ietf.org/html/rfc5424)）中标准化。在这里，设施指定记录消息的程序类型；例如，内核或 cron。严重性标签用于描述影响，例如信息或关键。

程序员的 syslog 手册（`journald`能够获取有关程序输出的所有内容。

**添加日志条目**

您可以手动向日志添加条目。对于 syslog，`logger`命令可用：

```
logger -p <facility.severity> "Message"
```

对于`journald`，有`systemd-cat`：

```
systemd-cat --identifier <identifier> --priority <severity><command>
```

让我们看一个例子：

```
systemd-cat --identifier CHANGE --priority info \
  echo "Start Configuration Change"
```

作为标识符，您可以使用自由字符串或 syslog 设施。`logger`和`systemd-cat`都可以用于在日志中生成条目。如果应用程序不支持 syslog，则可以使用此功能；例如，在 Apache 配置中，您可以使用此指令：

```
errorlog  "tee -a /var/log/www/error/log  | logger -p local6.info"
```

您还可以将其作为变更管理的一部分使用。

**将 journald 与 RSYSLOG 集成**

为了为您自己的监控服务收集数据，您的监控服务需要 syslog 支持。这些监控服务的良好示例作为 Azure 中的现成 VM 提供：**Splunk**和**Elastic Stack**。

RSYSLOG 是当今最常用的 syslog 协议实现。它已经默认安装在 Ubuntu、SUSE 和 Red Hat 等发行版中。

RSYSLOG 可以使用`imjournal`模块与日志数据库很好地配合。在 SUSE 和 Red Hat 等发行版中，这已经配置好；在 Ubuntu 中，您必须对`/etc/rsyslog.conf`文件进行修改：

```
# module(load="imuxsock")
module(load="imjournal")
```

修改后，重新启动 RSYSLOG：

```
sudo systemctl restart rsyslog
```

使用`/etc/rsyslog.d/50-default.conf`中的设置，它记录到纯文本文件中。

要将来自本地 syslog 的所有内容发送到远程 syslog 服务器，您必须将以下内容添加到此文件中：

```
*. *  @<remote server>:514
```

#### 注意

这是 Ubuntu 中的文件名。在其他发行版中，请使用`/etc/rsyslog.conf`。

如果要使用 TCP 协议而不是 UDP 协议，请使用`@@`。

**其他日志文件**

您可以在`/var/log`目录结构中找到不支持 syslog 或`systemd-journald`的应用程序的日志文件。要注意的一个重要文件是`/var/log/waagent.log`文件，其中包含来自 Azure Linux VM 代理的日志记录。还有`/var/log/azure`目录，其中包含来自其他 Azure 代理（如 Azure Monitor）和 VM 扩展的日志记录。

## Azure Log Analytics

Azure Log Analytics 是 Azure Monitor 的一部分，它收集和分析日志数据并采取适当的操作。它是 Azure 中的一个服务，可以从多个系统中收集日志数据并将其存储在一个中心位置的单个数据存储中。它由两个重要组件组成：

+   Azure Log Analytics 门户，具有警报、报告和分析功能

+   需要在 VM 上安装的 Azure Monitor 代理

还有一个移动应用程序（在 iOS 和 Android 商店中，您可以在*Microsoft Azure*下找到它），如果您想在外出时查看工作负载的状态。

### 配置 Log Analytics 服务

在 Azure 门户中，从左侧栏选择**所有服务**，并搜索**Log Analytics**。选择**添加**并创建新的 Log Analytics 工作区。在撰写本文时，它并不是在所有地区都可用。使用该服务并不受地区限制；如果 VM 位于另一个地区，您仍然可以监视它。

#### 注意

此服务没有预付费用，您按使用量付费！阅读[`aka.ms/PricingTierWarning`](http://aka.ms/PricingTierWarning)获取更多详细信息。

另一种创建服务的方法是使用 Azure CLI：

```
az extension add -n application-insights
```

创建服务后，会弹出一个窗口，允许您导航到新创建的资源。或者，您可以在**所有服务**中再次搜索。

请注意，在资源窗格的右上角，Azure Monitor 和工作区 ID；您以后会需要这些信息。转到**高级设置**以找到工作区密钥。

在 Azure CLI 中，您可以使用以下命令收集此信息：

```
az monitor app-insights component create --app myapp
   --location westus1
   --resource-group my-resource-grp
```

要列出 Azure 订阅的所有工作区，可以使用以下 Azure CLI 命令：

```
az ml workspace list
```

您可以使用以下 Azure CLI 命令以 JSON 格式获取有关工作区的详细信息：

```
az ml workspace show -w my-workspace -g my-resource-grp
```

### 安装 Azure Log Analytics 代理

在安装 Azure Monitor 代理之前，请确保已安装`audit`包（在`auditd`中）。

要在 Linux VM 中安装 Azure Monitor 代理，您有两种可能性：启用 VM 扩展`OMSAgentforLinux`，或在 Linux 中下载并安装 Log Analytics 代理。

首先，设置一些变量以使脚本编写更容易：

```
$rg = "<resource group>"
$loc = "<vm location>"
$omsName = "<OMS Name>"
$vm = "<vm name">
```

您需要工作区 ID 和密钥。`Set-AzureVMExtension` cmdlet 需要以 JSON 格式的密钥，因此需要进行转换：

```
$omsID = $(Get-AzOperationalInsightsWorkspace '
 -ResourceGroupName $rg -Name $omsName.CustomerId) 
$omsKey = $(Get-AzOperationalInsightsWorkspaceSharedKeys '
 -ResourceGroupName $rg -Name $omsName).PrimarySharedKey
$PublicSettings = New-Object psobject | Add-Member '
 -PassThruNotePropertyworkspaceId $omsId | ConvertTo-Json
$PrivateSettings = New-Object psobject | Add-Member '
 -PassThruNotePropertyworkspaceKey $omsKey | ConvertTo-Json
```

现在您可以将扩展添加到虚拟机：

```
Set-AzureVMExtension -ExtensionName "OMS" '
  -ResourceGroupName $rg -VMName $vm '
  -Publisher "Microsoft.EnterpriseCloud.Monitoring" 
  -ExtensionType "OmsAgentForLinux" -TypeHandlerVersion 1.0 '
  -SettingString $PublicSettings
  -ProtectedSettingString $PrivateSettings -Location $loc
```

上述过程相当复杂并且需要一段时间。下载方法更简单，但您必须以访客身份通过 SSH 登录到 VM。当然，这两种方法都可以自动化/编排：

```
cd /tmp
wget \
https://github.com/microsoft/OMS-Agent-for-Linux \
/blob/master/installer/scripts/onboard_agent.sh
sudo -s 
sh onboard_agent.sh -w <OMS id> -s <OMS key> -d \
  opinsights.azure.com
```

如果在安装代理时遇到问题，请查看`/var/log/waagent.log`和`/var/log/azure/Microsoft.EnterpriseCloud.Monitoring.OmsAgentForLinux/*/extension.log`配置文件。

扩展的安装还会创建一个配置文件`rsyslog,/etc/rsyslogd.d/95-omsagent.conf`：

```
kern.warning @127.0.0.1:25224
user.warning @127.0.0.1:25224
daemon.warning @127.0.0.1:25224
auth.warning @127.0.0.1:25224
syslog.warning @127.0.0.1:25224
uucp.warning @127.0.0.1:25224
authpriv.warning @127.0.0.1:25224
ftp.warning @127.0.0.1:25224
cron.warning @127.0.0.1:25224
local0.warning @127.0.0.1:25224
local1.warning @127.0.0.1:25224
local2.warning @127.0.0.1:25224
local3.warning @127.0.0.1:25224
local4.warning @127.0.0.1:25224
local5.warning @127.0.0.1:25224
local6.warning @127.0.0.1:25224
local7.warning @127.0.0.1:25224
```

基本上意味着 syslog 消息（`facility.priority`）被发送到 Azure Monitor 代理。

在新资源的底部窗格中，有一个名为**开始使用 Log Analytics**的部分：

![在 Azure 门户中开始使用 Log Analytics 部分](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_10.jpg)

###### 图 11.10：在 Azure 门户中开始使用 Log Analytics 部分

单击**Azure 虚拟机（VMs）**。您将看到此工作区中可用的虚拟机：

![工作区中可用的虚拟机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_11.jpg)

###### 图 11.11：工作区中可用的虚拟机

上述屏幕截图表示工作区中可用的虚拟机。它还显示我们已连接到数据源。

### 获取数据

在此资源的**高级设置**部分，您可以添加性能和 syslog 数据源。您可以使用特殊的查询语言通过日志搜索访问所有数据。如果您对这种语言不熟悉，您应该访问[`docs.loganalytics.io/docs/Learn/Getting-Started/Getting-started-with-queries`](https://docs.loganalytics.io/docs/Learn/Getting-Started/Getting-started-with-queries)和[`docs.loganalytics.io/index`](https://docs.loganalytics.io/index)。

现在，只需执行此查询：

```
search *
```

为了查看是否有可用的数据，将搜索限制为一个 VM：

```
search * | where Computer == "centos01"
```

或者，为了获取所有的 syslog 消息，作为一个测试，您可以重新启动您的 VM，或者尝试这个：

```
logger -t <facility>. <priority> "message"
```

在 syslog 中执行以下查询以查看结果：

```
Syslog | sort 
```

如果您点击**保存的搜索**按钮，还有许多示例可用。

监控解决方案提供了一个非常有趣的附加功能，使这个过程变得更加容易。在**资源**窗格中，点击**查看解决方案**：

![导航到 VM 中的查看解决方案选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_12.jpg)

###### 图 11.12：导航到监控解决方案选项

选择所需的选项，然后点击**添加**：

![日志分析中的管理解决方案](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_13.jpg)

###### 图 11.13：日志分析中的管理解决方案

**服务地图**是一个重要的服务。它为您的资源提供了很好的概述，并提供了一个易于使用的界面，用于日志、性能计数器等。安装**服务地图**后，您必须在 Linux 机器上安装代理，或者您可以登录到门户并导航到 VM，它将自动为您安装代理：

```
cd /tmp
wget --content-disposition https://aka.ms/dependencyagentlinux \
-O InstallDependencyAgent-Linux64.bin
sudo sh InstallDependencyAgent-Linux64.bin -s
```

安装后，选择**虚拟机** > **监视** > **洞察** > **服务地图**。

现在，点击**摘要**：

![服务地图中的摘要部分](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_14.jpg)

###### 图 11.14：服务地图摘要部分

您可以监视您的应用程序，查看日志文件等：

![检查日志文件以监视应用程序](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_15.jpg)

###### 图 11.15：服务地图概述

### 日志分析和 Kubernetes

为了管理您的容器，您需要对 CPU、内存、存储和网络使用情况以及性能信息有详细的了解。Azure 监视可以用于查看 Kubernetes 日志、事件和指标，允许从一个位置监视容器。您可以使用 Azure CLI、Azure PowerShell、Azure 门户或 Terraform 为您的新或现有的 AKS 部署启用 Azure 监视。

创建一个新的`az aks create`命令：

```
az aks create --resource-group MyKubernetes --name myAKS --node-count 1 --enable-addons monitoring --generate-ssh-keys
```

要为现有的 AKS 集群启用 Azure 监视，使用`az aks`命令进行修改：

```
az aks enable-addons -a monitoring -n myAKS -g MyKubernetes
```

您可以从 Azure 门户为您的 AKS 集群启用监视，选择**监视**，然后选择**容器**。在这里，选择**未监视的集群**，然后选择容器，点击**启用**：

![从 Azure 门户监视 AKS 集群](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_16.jpg)

###### 图 11.16：从 Azure 门户监视 AKS 集群

### 您网络的日志分析

Azure Log Analytics 中的另一个解决方案是 Traffic Analytics。它可视化工作负载的网络流量，包括开放端口。它能够为安全威胁生成警报，例如，如果应用程序尝试访问其不允许访问的网络。此外，它提供了具有日志导出选项的详细监控选项。

如果您想使用 Traffic Analytics，首先您必须为您想要分析的每个区域创建一个网络监视器：

```
New-AzNetworkWatcher -Name <name> '
 -ResourceGroupName<resource group> -Location <location>
```

之后，您必须重新注册网络提供程序并添加 Microsoft Insights，以便网络监视器可以连接到它：

```
Register-AzResourceProvider -ProviderNamespace '
 "Microsoft.Network"
Register-AzResourceProvider -ProviderNamespaceMicrosoft.Insights
```

不能使用这个解决方案与其他提供商，如`Microsoft.ClassicNetwork`。

下一步涉及使用“网络安全组（NSG）”，它通过允许或拒绝传入流量来控制日志流量的流动。在撰写本文时，这只能在 Azure 门户中实现。在 Azure 门户的左侧栏中，选择“监视”>“网络观察程序”，然后选择“NSG 流日志”。现在你可以选择要为其启用“NSG 流日志”的 NSG。

启用它，选择一个存储账户，并选择你的 Log Analytics 工作空间。

信息收集需要一些时间。大约 30 分钟后，第一批信息应该可见。在 Azure 门户的左侧栏中选择“监视”，转到“网络观察程序”，然后选择“Traffic Analytics”。或者，从你的 Log Analytics 工作空间开始：

![从 Azure 门户检查 Traffic Analytics 选项，查看网络流量分布](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_17.jpg)

###### 图 11.17：使用 Traffic Analytics 查看网络流量分布

## 性能监控

在 Azure Monitor 中，有许多可用于监控的选项。例如，性能计数器可以让你深入了解你的工作负载。还有一些特定于应用程序的选项。

即使你不使用 Azure Monitor，Azure 也可以为每个 VM 提供各种指标，但不在一个中心位置。只需导航到你的 VM。在“概述”窗格中，你可以查看 CPU、内存和存储的性能数据。详细信息可在“监视”下的“指标”部分中找到。各种数据都可以获得，如 CPU、存储和网络数据：

![使用 Azure 门户的概述窗格查看 VM 的性能数据](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_18.jpg)

###### 图 11.18：查看 VM 的性能数据

许多解决方案的问题在于它们是特定于应用程序的，或者你只是看到了最终结果，却不知道原因是什么。如果你需要了解虚拟机所使用资源的一般性能信息，可以使用 Azure 提供的信息。如果你需要了解你正在运行的 Web 服务器或数据库的信息，可以看看是否有 Azure 解决方案。但在许多情况下，如果你也能在 VM 中进行性能故障排除，那将非常有帮助。在某种程度上，我们将从第三章《基本 Linux 管理》中的“进程管理”部分开始。

在我们开始之前，有多种方法和方式可以进行性能故障排除。这本书能提供你唯一应该使用的方法，或者告诉你唯一需要的工具吗？不，不幸的是！但它可以让你意识到可用的工具，并至少涵盖它们的基本用法。对于更具体的需求，你总是可以深入研究 man 页面。在这一部分，我们特别关注负载是什么，以及是什么导致了负载。

最后一点：这一部分被称为“性能监控”，但这可能不是完美的标题。它是平衡监控、故障排除和分析。然而，在每个系统工程师的日常生活中，这种情况经常发生，不是吗？

并非所有提到的工具都默认在 Red Hat/CentOS 存储库中可用。你需要配置`epel`存储库：`yum install epel-release`。

### 使用 top 显示 Linux 进程

如果你研究性能监控和 Linux 等主题，`top`总是被提到。它是用来快速了解系统上正在运行的内容的头号命令。

你可以用`top`显示很多东西，它带有一个很好的 man 页面，解释了所有的选项。让我们从屏幕顶部开始关注最重要的部分：

![使用 top 命令显示 Linux 进程](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_19.jpg)

###### 图 11.19：使用 top 命令显示资源使用情况

让我们看看前面截图中提到的选项：

+   `wa`): 如果此值持续超过 10%，这意味着底层存储正在减慢服务器。此参数显示 CPU 等待 I/O 进程的时间。Azure VM 使用 HDD 而不是 SSD，使用多个 HDD 在 RAID 配置中可能有所帮助，但最好迁移到 SSD。如果这还不够，也有高级 SSD 解决方案可用。

+   `us`): 应用程序的 CPU 利用率；请注意，CPU 利用率是跨所有 CPU 总计的。

+   `sy`): CPU 在内核任务上花费的时间。

+   **Swap**：由于应用程序没有足够的内存而导致的内存分页。大部分时间应该为零。

`top` 屏幕底部还有一些有趣的列：

![从 top 命令获取的输出的底部条目](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_20.jpg)

###### 图 11.20：从 top 命令获取的输出的底部条目

就个人而言，我们不建议现在担心优先级和 nice 值。对性能的影响很小。第一个有趣的字段是 `VIRT`（虚拟内存）。这指的是程序目前可以访问的内存量。它包括与其他应用程序共享的内存、视频内存、应用程序读入内存的文件等。它还包括空闲内存、交换内存和常驻内存。常驻内存是此进程实际使用的内存。`SHR` 是应用程序之间共享的内存量。这些信息可以让您对系统上应配置多少`swap`有一个概念：取前五个进程，加上 `VIRT`，然后减去 `RES` 和 `SHR`。这并不完美，但是是一个很好的指标。

在前面截图中的 **S** 列是机器的状态：

+   `D` 是不可中断的睡眠，大多数情况是由于等待存储或网络 I/O。

+   `R` 正在运行—消耗 CPU。

+   `S` 正在休眠—等待 I/O，没有 CPU 使用。等待用户或其他进程触发。

+   `T` 被作业控制信号停止，大多数情况是因为用户按下 *Ctrl* + *Z*。

+   `Z` 是僵尸—父进程已经死亡。在内核忙于清理时，它被内核标记为僵尸。在物理机器上，这也可能是 CPU 故障的迹象（由温度或糟糕的 BIOS 引起）；在这种情况下，您可能会看到许多僵尸。在 Azure 中，这不会发生。僵尸不会造成伤害，所以不要杀死它们；内核会处理它们。

### top 替代方案

有许多类似于 `top` 的实用程序，例如 `htop`，它看起来更漂亮，更容易配置。

非常相似但更有趣的是 `atop`。它包含所有进程及其资源使用情况，甚至包括在 `atop` 屏幕更新之间死亡的进程。这种全面的记账对于理解个别短暂进程的问题非常有帮助。`atop` 还能够收集有关运行容器、网络和存储的信息。

另一个是 `nmon`，它类似于 `atop`，但更专注于统计数据，并提供更详细的信息，特别是内存和存储方面的信息：

![使用 nmon 命令获取内存、CPU 和存储性能详细信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_21.jpg)

###### 图 11.21：内存、CPU 和存储性能详细信息

`nmon` 也可以用来收集数据：

```
nmon -f -s 60 -c 30
```

上述命令每分钟收集 30 轮信息，以逗号分隔的文件格式，易于在电子表格中解析。在 IBM 的开发者网站 [`nmon.sourceforge.net/pmwiki.php?n=Site.Nmon-Analyser`](http://nmon.sourceforge.net/pmwiki.php?n=Site.Nmon-Analyser) 上，您可以找到一个 Excel 电子表格，使这变得非常容易。它甚至提供了一些额外的数据分析选项。

`glances` 最近也变得非常受欢迎。它基于 Python，并提供有关系统、正常运行时间、CPU、内存、交换、网络和存储（磁盘 I/O 和文件）的当前信息：

![使用 glances 实用程序查看性能](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_22.jpg)

###### 图 11.22：使用 glances 实用程序查看性能

`glances`是`top`的最先进的替代品。它提供了所有替代品的功能，而且，您还可以远程使用它。您需要提供服务器的用户名和密码来启动`glances`：

```
glances --username <username> --password <password> --server 
```

在客户端上也执行以下操作：

```
glances --client @<ip address>
```

默认情况下，使用端口`61209`。如果使用`--webserver`参数而不是`--server`，甚至不需要客户端。端口`61208`上提供完整的 Web 界面！

`glances`能够以多种格式导出日志，并且可以使用 API 进行查询。对**SNMP**（简单网络管理协议）协议的实验性支持也正在进行中。

### Sysstat-一组性能监控工具

`sysstat`软件包包含性能监控实用程序。在 Azure 中最重要的是`sar`、`iostat`和`pidstat`。如果还使用 Azure Files，`cifsiostat`也很方便。

`sar`是主要实用程序。主要语法是：

```
sar -<resource> interval count
```

例如，使用以下命令报告 CPU 统计信息 5 次，间隔为 1 秒：

```
sar -u 1 5
```

要监视核心`1`和`2`，请使用此命令：

```
sar -P 1 2 1 5
```

（如果要单独监视所有核心，可以使用`ALL`关键字。）

以下是一些其他重要资源：

+   `-r`：内存

+   `-S`：交换

+   `-d`：磁盘

+   `-n <type>`：网络类型，例如：

`DEV`：显示网络设备统计

`EDEV`：显示网络设备故障（错误）统计

`NFS`：显示`SOCK`：显示 IPv4 中正在使用的套接字

`IP`：显示 IPv4 网络流量

`TCP`：显示 TCPv4 网络流量

`UDP`：显示 UDPv4 网络流量

`ALL`：显示所有前述信息

`pidstat`可以通过其进程 ID 从特定进程收集 CPU 数据。在下一个截图中，您可以看到每 5 秒显示 2 个样本。`pidstat`也可以对内存和磁盘执行相同的操作：

![使用 pidstat 命令获取特定进程的 CPU 数据性能](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_23.jpg)

###### 图 11.23：使用 pidstat 显示 CPU 统计信息

`iostat`是一个实用程序，顾名思义，它可以测量 I/O，但也可以创建 CPU 使用情况报告：

![使用 iostat 命令获取 I/O 性能统计](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_24.jpg)

###### 图 11.24：使用 iostat 获取 CPU 和设备报告和统计信息

`tps`表示每秒向设备发出的传输次数。`kb_read/s`和`kB_wrtn/s`是在 1 秒内测得的千字节数；前面截图中的`avg-cpu`列是自 Linux 系统启动以来的统计总数。

在安装`sysstat`软件包时，在`/etc/cron.d/sysstat`文件中安装了一个 cron 作业。

#### 注意

在现代 Linux 系统中，`systemd-timers`和使用`cron`的旧方法都可用。`sysstat`仍然使用`cron`。要检查`cron`是否可用并正在运行，请转到`systemctl | grep cron`。

`cron`每 10 分钟运行一次`sa1`命令。它收集系统活动并将其存储在二进制数据库中。每天一次，执行`sa2`命令生成报告。数据存储在`/var/log/sa`目录中。您可以使用`sadf`查询该数据库：

![使用 sadf 命令查询系统活动的数据库](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_25.jpg)

###### 图 11.25：使用 sadf 查询系统活动的数据库

此截图显示了 11 月 6 日`09:00:00`至`10:10:00`之间的数据。默认情况下，它显示 CPU 统计信息，但您可以使用与`sar`相同的参数进行自定义：

```
sadf /var/log/sa/sa03 -- -n DEV
```

这显示了 11 月 6 日每个网络接口的网络统计信息。

### dstat

`sysstat`用于历史报告，而`dstat`用于实时报告。虽然`top`是`ps`的监视版本，但`dstat`是`sar`的监视版本：

![使用 dstat 命令获取实时报告](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_26.jpg)

###### 图 11.26：使用 dstat 获取实时报告

如果您不想一次看到所有内容，可以使用以下参数：

+   `c`：CPU

+   `d`：磁盘

+   `n`：网络

+   `g`：分页

+   `s`：交换

+   `m`：内存

### 使用 iproute2 进行网络统计

在本章的前面，我们谈到了`ip`。这个命令还提供了一个选项，用于获取网络接口的统计信息：

```
ip -s link show dev eth0
```

![使用 ip -s link show dev eth0 命令获取网络接口的统计信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_27.jpg)

###### 图 11.27：获取网络接口的统计信息

它解析来自`/proc/net`目录的信息。另一个可以解析此信息的实用程序是`ss`。可以使用以下命令请求简单摘要：

```
ss -s
```

使用`-t`参数不仅可以显示处于监听状态的端口，还可以显示特定接口上的传入和传出流量。

如果您需要更多详细信息，`iproute2`软件包提供了另一个实用程序：`nstat`。使用`-d`参数，甚至可以在间隔模式下运行它：

![使用 nstat 实用程序获取处于监听状态的端口的详细报告](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_28.jpg)

###### 图 11.28：获取有关处于监听状态的端口的详细报告

这已经比`ss`的简单摘要要多得多。但是`iproute2`软件包还有更多提供：`lnstat`。

这是提供网络统计信息的命令，如路由缓存统计：

```
lnstat––d
```

![使用 lnstat-d 命令获取网络统计信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_29.jpg)

###### 图 11.29：使用 lnstat -d 获取网络统计信息

这显示了它可以显示或监视的所有内容。这相当低级，但我们使用`lnstat -f/proc/net/stat/nf_conntrack`解决了一些与防火墙性能相关的问题，同时监视`drops`计数器。

### 使用 IPTraf-NG 进行网络监控

您可以从`nmon`等工具获取网络详细信息，但如果您想要更多详细信息，那么 IPTraf-NG 是一个非常好的实时基于控制台的网络监控解决方案。它是一个基于控制台的网络监控实用程序，可以收集所有网络 IP、TCP、UDP 和 ICMP 数据，并能够根据 TCP/UDP 的大小来分解信息。还包括一些基本过滤器。

一切都在一个菜单驱动的界面中，所以没有必须记住的参数：

![IPTraf-NG 的菜单窗口](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_11_30.jpg)

###### 图 11.30：IPTraf-NG 的菜单窗口

### tcpdump

当然，`tcpdump`不是性能监控解决方案。这个实用程序是监视、捕获和分析网络流量的好工具。

要查看所有网络接口上的网络流量，请执行以下操作：

```
tcpdump -i any 
```

对于特定接口，请尝试这个：

```
tcpdump -i eth0 
```

一般来说，最好不要解析主机名：

```
tcpdump -n -i eth0
```

通过重复`v`参数，可以添加不同级别的详细程度，最大详细程度为三：

```
tcpdump -n -i eth0 -vvv
```

您可以基于主机筛选流量：

```
tcpdump host <ip address> -n -i eth0 
```

或者，您可以基于源或目标 IP 进行筛选：

```
tcpdump src <source ip address> -n -i eth0 
tcpdump dst <destination ip address> -n -i eth0
```

还可以根据特定端口进行筛选：

```
tcpdump port 22 
tcpdumpsrc port 22
tcpdump not port 22
```

所有参数都可以组合使用：

```
tcpdump -n dst net <subnet> and not port ssh -c 5
```

添加了`-c`参数，因此只捕获了五个数据包。您可以将捕获的数据保存到文件中：

```
tcpdump -v -x -XX -w /tmp/capture.log       
```

添加了两个参数，以增加与其他可以读取`tcpdump`格式的分析器的兼容性：

+   `-XX`：以十六进制和 ASCII 格式打印每个数据包的数据

+   `-x`：为每个数据包添加标题

要以人类可读的完整时间戳格式读取数据，请使用此命令：

```
tcpdump -tttt -r /tmp/capture.log
```

#### 注意

另一个很棒的网络分析器是 Wireshark。这是一个图形工具，适用于许多操作系统。该分析器可以导入从`tcpdump`捕获的数据。它配备了一个很棒的搜索过滤器和分析工具，适用于许多不同的网络协议和服务。

在虚拟机中进行捕获并将其下载到工作站以便在 Wireshark 中进一步分析数据是有意义的。

我们相信您现在可以使用不同的工具在 Linux 系统中实现良好的性能分析，以监视 CPU、内存、存储和网络详细信息。

## 摘要

在本章中，我们涵盖了有关故障排除、日志记录、监控甚至分析的几个主题。从获取对虚拟机的访问开始，我们研究了在 Linux 中本地和远程进行日志记录。

性能监控和性能故障排除之间有一条细微的界限。有许多不同的实用工具可用于找出性能问题的原因。每个工具都有不同的目标，但也有很多重叠之处。我们已经介绍了 Linux 中最流行的实用工具以及一些可用的选项。

在第一章中，我们看到 Azure 是一个非常开放源代码友好的环境，微软已经付出了很大的努力，使 Azure 成为一个开放的、标准的云解决方案，并考虑了互操作性。在本章中，我们看到微软不仅在部署应用程序时支持 Linux，而且在 Azure Monitor 中也支持它。

## 问题

1.  为什么在虚拟机中至少应该有一个带密码的用户？

1.  `systemd-journald`守护进程的目的是什么？

1.  syslog 设施是什么？

1.  syslog 中有哪些可用的优先级？

1.  你如何向日志添加条目，以及为什么要这样做？

1.  在 Azure 中有哪些服务可用于查看指标？

1.  为什么`top`只能用于初步查看与性能相关的问题，以及哪个实用工具可以解决这个问题？

1.  `sysstat`和`dstat`实用程序之间有什么区别？

1.  为什么应该在工作站上安装 Wireshark？

## 进一步阅读

一个重要的信息来源是 Brendan D Gregg 的网站（[`www.brendangregg.com`](http://www.brendangregg.com)），他在那里分享了一份令人难以置信的长长的 Linux 性能文档、幻灯片、视频等清单。除此之外，还有一些不错的实用工具！他是 2015 年教会我的人，正确识别问题是很重要的。

+   是什么让你觉得有问题？

+   曾经有没有出现过问题？

+   最近有什么变化吗？

+   尝试寻找技术描述，比如延迟、运行时错误等。

+   只有应用程序受影响，还是其他资源也受到影响？

+   提出一个关于环境的确切描述。

你还需要考虑以下几点：

+   是什么导致负载（哪个进程、IP 地址等）？

+   为什么称之为负载？

+   负载使用了哪些资源？

+   负载是否发生变化？如果是，它是如何随时间变化的？

最后但同样重要的是，本书作者是 Benjamin Cane 的《Red Hat Enterprise Linux 故障排除指南》。我知道，这本书的一些部分已经过时，因为它是在 2015 年印刷的。当然，我希望有第二版，但是，特别是如果你是 Linux 的新手，买这本书。
