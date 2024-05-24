# Kubernetes 秘籍（四）

> 原文：[`zh.annas-archive.org/md5/6F444487B7AC74DB6092F54D9EA36B7A`](https://zh.annas-archive.org/md5/6F444487B7AC74DB6092F54D9EA36B7A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：在 GCP 上构建 Kubernetes

在本章中，我们将在以下食谱中使用**Google Cloud Platform**（**GCP**）：

+   玩转 GCP

+   通过**Google Kubernetes Engine**（**GKE**）设置托管的 Kubernetes

+   探索 GKE 上的 Kubernetes CloudProvider

+   在 GKE 上管理 Kubernetes 集群

# 玩转 GCP

GCP 在公共云行业变得越来越受欢迎。它有类似于 AWS 的概念，如 VPC、计算引擎、持久性磁盘、负载均衡和几个托管服务。最有趣的服务是 GKE，这是托管的 Kubernetes 集群。我们将探索如何使用 GCP 和 GKE。

# 准备工作

要使用 GCP，您需要拥有一个谷歌账号，比如 Gmail（[`mail.google.com/mail/`](https://mail.google.com/mail/)），很多人已经有了。然后按照以下步骤使用您的谷歌账号注册 GCP：

1.  转到[`cloud.google.com`](https://cloud.google.com)网站，然后点击“免费试用”按钮

1.  使用您的谷歌账号登录谷歌

1.  注册 GCP 并输入个人信息和结算信息

就是这样！

注册完成后，您将看到 GCP Web 控制台页面。一开始，它可能会要求您创建一个项目；默认名称可能是“My First Project”。您可以保留它，但在本章中我们将创建另一个项目，以帮助您更好地理解。

GCP Web 控制台作为第一步就足够了。但是不建议继续使用 Web 控制台进行 DevOps，因为人工手动输入总会导致人为错误，而且 Google 可能会在将来更改 Web 控制台的设计。

因此，我们将使用 CLI。GCP 提供了一个名为 Cloud SDK 的 CLI 工具（[`cloud.google.com/sdk/`](https://cloud.google.com/sdk/)）。因此，让我们创建一个新的 GCP 项目，然后在您的计算机上安装 Cloud SDK。

# 创建一个 GCP 项目

我们将通过以下步骤从头开始创建一个新项目。这将帮助您了解 GCP 项目的工作原理：

1.  点击“My First Project”链接转到项目页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/a34389e9-cb29-4c1b-8f1f-4df4957081e7.png)导航到项目链接

1.  您可能会看到您自己的项目可供选择，但这次请点击“+”按钮创建一个新项目：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/47198482-4866-4daa-9443-182e99c7c608.png)创建一个新项目

1.  将项目名称输入为`Kubernetes Cookbook`。然后 GCP 将生成并分配一个项目 ID，如 kubernetes-cookbook-12345。请记住这个项目 ID。

您可能会注意到您的项目 ID 不是 kubernetes-cookbook，就像屏幕截图中显示的 kubernetes-cookbook-194302 一样。即使您尝试点击“编辑”来尝试将其更改为 kubernetes-cookbook，也不允许，因为项目 ID 是所有 GCP 用户的唯一字符串。而我们已经使用了 kubernetes-cookbook 项目 ID。![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/0fd87e3a-8715-4e46-a992-f368a6bf95e4.png)项目名称和项目 ID

1.  几分钟后，您的项目就准备好使用了。返回顶部横幅上的项目选择页面，然后选择您的 Kubernetes Cookbook 项目：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/93685e0e-2de7-4b92-bc57-d8240fcb7af6.png)选择 Kubernetes Cookbook 项目

完成！您随时可以切换到您的项目和 Kubernetes Cookbook 项目。这是一个隔离的环境；任何 VPC、VM、IAM 用户甚至计费方法都是独立的。

# 安装 Cloud SDK

接下来，在您的计算机上安装 Cloud SDK。它支持 Windows、Mac 和 Linux 平台。所有这些都需要 Python 解释器版本 2.7，但大多数 macOS 和 Linux 安装都使用默认设置。

另一方面，Windows 默认情况下没有 Python 解释器。但是，在 Windows 的 Cloud SDK 安装程序中，可以安装 Python。让我们逐步在 Windows 和 macOS 上安装 Cloud SDK。

# 在 Windows 上安装 Cloud SDK

Cloud SDK 为 Windows 提供了一个安装程序。它还包括 Windows 的 Python 解释器。请按照以下步骤在您的 Windows 计算机上安装：

1.  在 Windows 上下载 Cloud SDK 安装程序 ([`dl.google.com/dl/cloudsdk/channels/rapid/GoogleCloudSDKInstaller.exe`](https://dl.google.com/dl/cloudsdk/channels/rapid/GoogleCloudSDKInstaller.exe))。

1.  运行 Cloud SDK 安装程序。

如果您从未在 Windows 计算机上安装过 Python 解释器，您必须选择“捆绑的 Python”选项：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/f28b2426-efed-4bf7-8cd6-5c7dd9758275.png)Windows 的 Cloud SDK 安装程序

1.  除此之外，使用默认选项继续安装。

1.  安装完成后，您可以在 Google Cloud SDK 程序组中找到 Google Cloud SDK Shell。单击它以启动 Google Cloud SDK Shell：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/1232e920-4d5f-44d9-91c5-52a00344d03e.png)Google Cloud SDK 程序组中的 Google Cloud SDK Shell

1.  键入 `gcloud info` 以检查您是否可以查看 Cloud SDK 版本：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/443c01fd-9b87-450e-a00e-1f2351558d22.png)在 Windows 上运行 gcloud 命令

# 在 Linux 和 macOS 上安装 Cloud SDK

在 Linux 和 macOS 上安装 Cloud SDK 遵循这里列出的步骤。让我们在您的主目录下安装 Cloud SDK：

1.  打开终端。

1.  输入以下命令以下载并运行 Cloud SDK 安装程序：

```
$ curl https://sdk.cloud.google.com | bash
```

1.  它会询问您期望的安装目录。默认情况下，它位于您的主目录下。因此，输入`return`：

```
Installation directory (this will create a google-cloud-sdk subdirectory) (/Users/saito):
```

1.  它会询问是否发送用户使用数据；当它崩溃时，它会发送一些信息。根据您的隐私政策，如果不希望向 Google 发送任何数据，请选择`n`。否则选择`Y`以提高它们的质量：

```
Do you want to help improve the Google Cloud SDK (Y/n)? n
```

1.  它会询问是否通过将`gcloud`命令添加到您的命令搜索路径来更新`.bash_profile`；输入`y`继续：

```
Modify profile to update your $PATH and enable shell command
completion?
Do you want to continue (Y/n)?  y
The Google Cloud SDK installer will now prompt you to update an rc
file to bring the Google Cloud CLIs into your environment.
Enter a path to an rc file to update, or leave blank to use
[/Users/saito/.bash_profile]:
```

1.  打开另一个终端或输入`exec -l $SHELL`以刷新您的命令搜索路径：

```
//reload .bash_profile
$ exec -l $SHELL

//check gcloud command is in your search path
$ which gcloud
/Users/saito/google-cloud-sdk/bin/gcloud
```

1.  输入`gcloud info`以检查是否可以看到 Cloud SDK 版本：

```
$ gcloud info
Google Cloud SDK [187.0.0]
Platform: [Mac OS X, x86_64] ('Darwin', 'Hideto-Saito-no-MacBook.local', '17.4.0', 'Darwin Kernel Version 17.4.0: Sun Dec 17 09:19:54 PST 2017; root:xnu-4570.41.2~1/RELEASE_X86_64', 'x86_64', 'i386')
Python Version: [2.7.14 (default, Jan 21 2018, 12:22:04)  [GCC 4.2.1 Compatible Apple LLVM 9.0.0 (clang-900.0.38)]]
Python Location: [/usr/local/Cellar/python/2.7.14_2/Frameworks/Python.framework/Versions/2.7/Resources/Python.app/Contents/MacOS/Python]
```

现在您可以开始配置 Cloud SDK 了！

# 配置 Cloud SDK

您可以通过以下步骤配置 Windows 和 Linux/macOS 的 Cloud SDK：

1.  启动 Google Cloud SDK Shell（Windows）或打开终端（Linux/macOS）。

1.  输入`gcloud init`；它会要求您登录您的 Google 帐户。输入`y`并按回车键：

```
You must log in to continue. Would you like to log in (Y/n)? y
```

1.  它将打开一个网页浏览器，导航到 Google 登录页面；继续使用您的 Google 帐户和 GCP 帐户登录。

1.  它会询问您是否 Cloud SDK 可以访问您的 Google 帐户信息。点击“允许”按钮。

1.  回到终端-它会询问您要使用哪个项目。让我们选择您创建的“Kubernetes Cookbook”项目：

```
Pick cloud project to use:
 [1] my-first-project-194302
 [2] kubernetes-cookbook
 [3] Create a new project
Please enter numeric choice or text value (must exactly match list item):  2
```

1.  它会询问您是否要配置`Compute Engine`。这次让我们输入`n`跳过它：

```
Do you want to configure Google Compute Engine
(https://cloud.google.com/compute) settings (Y/n)?  n
```

现在您可以开始使用 Cloud SDK 来控制 GCP。让我们创建 VPC、子网和防火墙规则，然后启动一个 VM 实例来设置我们自己的 GCP 基础设施。

如果您选择了错误的项目或者想要重试，您可以随时通过`gcloud init`命令重新配置您的设置。

# 如何做...

我们将通过使用`gcloud`命令，了解 GCP 的基本功能，以在“Kubernetes Cookbook”项目下设置基础设施。我们将创建这些组件：

+   一个新的 VPC

+   VPC 中的两个子网（`us-central1`和`us-east1`）

+   三个防火墙规则（`public-ssh`，`public-http`和`private-ssh`）

+   我们将把您的 ssh 公钥添加到项目范围的元数据

总体而言，您的基础设施将如下所示。让我们逐个配置组件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/e360bc7c-6a8d-4dc1-83db-41c845ded19b.png)目标基础设施

# 创建一个 VPC

GCP 中的 VPC 类似于 AWS，但无需绑定特定区域，也无需设置 CIDR 地址范围。这意味着您可以创建一个覆盖所有区域的 VPC。默认情况下，您的 Kubernetes Cookbook 项目具有一个默认 VPC。

但是，为了更好地理解，让我们按照以下步骤创建一个新的 VPC：

1.  运行`gcloud compute networks`命令来创建一个新的 VPC。名称为`chap7`，子网模式为`custom`，这意味着子网不会自动创建。因此，我们将在下一步手动添加它：

```
$ gcloud compute networks create chap7 --subnet-mode=custom
```

1.  检查 VPC 列表；您应该有两个 VPC，`default` VPC 和`chap7` VPC：

```
$ gcloud compute networks list
NAME     SUBNET_MODE  BGP_ROUTING_MODE  IPV4_RANGE  GATEWAY_IPV4 **chap7    CUSTOM       REGIONAL** default  AUTO         REGIONAL
```

# 创建子网

让我们按照以下步骤在`chap7` VPC（网络）下创建两个子网：

1.  为了创建一个子网，您必须选择区域。通过输入`gcloud compute regions list`，您将知道哪些区域对您可用：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/9a46d42e-477c-436b-9b2c-fbef497e1ab9.png)显示 GCP 区域列表

1.  让我们选择`us-central1`和`us-east1`，按照以下配置在`chap7` VPC 下创建两个子网：

| **子网名称** | **VPC** | **CIDR 范围** | **区域** |
| --- | --- | --- | --- |
| `chap7-us-central1` | `chap7` | `192.168.1.0/24` | `us-central1` |
| `chap7-us-east1` | `chap7` | `192.168.2.0/24` | `us-east1` |

```
$ gcloud compute networks subnets create chap7-us-central1 --network=chap7 --range=192.168.1.0/24 --region us-central1

$ gcloud compute networks subnets create chap7-us-east1 --network=chap7 --range=192.168.2.0/24 --region us-east1
```

1.  检查以下命令，以查看子网是否正确配置：

```
$ gcloud compute networks subnets list --network=chap7
NAME               REGION       NETWORK  RANGE chap7-us-east1     us-east1     chap7    192.168.2.0/24 chap7-us-central1  us-central1  chap7    192.168.1.0/24
```

# 创建防火墙规则

防火墙规则类似于 AWS 安全组，您可以定义传入和传出的数据包过滤器。它们使用网络标记来区分防火墙规则和 VM 实例。因此，VM 实例可以指定零个或一些网络标记，然后防火墙规则将应用于具有相同网络标记的 VM。

因此，在创建防火墙规则时，我们需要设置一个目标网络标记。总的来说，我们将创建三个具有这些配置的防火墙规则：

| **防火墙规则名称** | **目标 VPC** | **允许端口** | **允许来自** | **目标网络标记** |
| --- | --- | --- | --- | --- |
| `public-ssh` | `chap7` | `ssh` (22/tcp) | 所有 (`0.0.0.0/0`) | public |
| `public-http` | `chap7` | `http` (80/tcp) | 所有 (`0.0.0.0/0`) | public |
| `private-ssh` | `chap7` | `ssh` (22/tcp) | 具有公共网络标记的主机 | private |

1.  创建一个`public-ssh`规则：

```
$ gcloud compute firewall-rules create public-ssh --network=chap7 --allow="tcp:22" --source-ranges="0.0.0.0/0" --target-tags="public"
```

1.  创建一个`public-http`规则：

```
$ gcloud compute firewall-rules create public-http --network=chap7 --allow="tcp:80" --source-ranges="0.0.0.0/0" --target-tags="public"
```

1.  创建一个`private-ssh`规则：

```
$ gcloud compute firewall-rules create private-ssh --network=chap7 --allow="tcp:22" --source-tags="public" --target-tags="private"
```

1.  检查所有防火墙规则：

```
$ gcloud compute firewall-rules list --filter='NETWORK=chap7'
NAME         NETWORK  DIRECTION  PRIORITY  ALLOW   DENY private-ssh  chap7    INGRESS    1000      tcp:22 public-http  chap7    INGRESS    1000      tcp:80 public-ssh   chap7    INGRESS    1000      tcp:22
```

# 将您的 ssh 公钥添加到 GCP

在启动 VM 实例之前，您需要上传您的 ssh 公钥以便登录到 VM。如果您没有任何 ssh 密钥，您必须运行`ssh-keygen`命令生成一对密钥（公钥和私钥）。假设您有一个名为`~/.ssh/id_rsa.pub`的公钥和一个名为`~/.ssh/id_rsa`的私钥

1.  使用`whoami`命令检查您的登录用户名，然后使用`gcloud compute config-ssh`通过以下命令上传您的密钥：

```
$ whoami
saito

$ gcloud compute config-ssh --ssh-key-file=~/.ssh/id_rsa
```

1.  检查您的 ssh 公钥是否注册为元数据：

```
$ gcloud compute project-info describe --format=json
{
 "commonInstanceMetadata": { "fingerprint": "fAqDGp0oSMs=", "items":  { "key": "**ssh-keys**", "value": "**saito**:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAr1cHrrONuaPgN20sXCPH8uT2lOjWRB3zEncOTxOI2lCW6DM6Mr31boboDe0kAtUMdoDU43yyMe4r734SmtMuh... 
```

就是这样。这些是启动 VM 实例的最小配置。因此，让我们在这个基础设施上启动一些 VM 实例。

# 它是如何工作的...

现在您拥有自己的 VPC、子网和防火墙规则。这个基础设施将被计算引擎（VM 实例）、Kubernetes 引擎和一些其他 GCP 产品使用。让我们在您的 VPC 上部署两个 VM 实例，如下图所示，看看它是如何工作的：

![最终状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/061df439-c2c1-48b2-9aeb-9645e75b1deb.png)

# 启动 VM 实例

我们将使用以下配置在`us-central1`和`us-east1`上启动两个 VM 实例：

| **VM 实例名称** | **目标 VPC** | **区域（参见以下步骤）** | **目标子网** | **分配网络标签** |
| --- | --- | --- | --- | --- |
| `chap7-public` | `chap7` | `us-central1-a` | `chap7-us-central1` | public |
| `chap7-private` | `chap7` | `us-east1-b` | `chap7-us-east1` | private |

1.  使用以下命令检查`us-central1`和`us-east1`中可用的区域：

```
$ gcloud compute zones list --filter='name:(us-east1,us-central1)'
NAME           REGION       STATUS  NEXT_MAINTENANCE  TURNDOWN_DATE 
**us-east1-b**     us-east1     UP us-east1-c     us-east1     UP us-east1-d     us-east1     UP 
us-central1-c  us-central1  UP **us-central1-a**  us-central1  UP us-central1-f  us-central1  UP us-central1-b  us-central1  UP
```

因此，让我们选择`us-central1-a`作为`chap7-public`，选择`us-east1-b`作为`chap7-private`：

1.  输入以下命令创建两个 VM 实例：

```
$ gcloud compute instances create chap7-public --network=chap7 --subnet=chap7-us-central1 --zone=us-central1-a --tags=public --machine-type=f1-micro
$ gcloud compute instances create chap7-private --network=chap7 --subnet=chap7-us-east1 --zone=us-east1-b --tags=private --machine-type=f1-micro
```

1.  通过以下命令检查 VM 实例的外部 IP 地址：

```
$ gcloud compute instances list
NAME           ZONE           MACHINE_TYPE  PREEMPTIBLE  INTERNAL_IP  EXTERNAL_IP    STATUS 
chap7-public   us-central1-a  f1-micro                   192.168.1.2  **35.224.14.45**   RUNNING 
chap7-private  us-east1-b     f1-micro                   **192.168.2.2**  35.229.95.179  RUNNING
```

1.  运行`ssh-agent`以记住您的 ssh 密钥：

```$
 ssh-add ~/.ssh/id_rsa
 ```

1.  从您的机器通过`-A`选项（转发身份验证）和使用外部 IP 地址 ssh 到`chap7-public`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/01c661b0-0fb2-4541-a527-1d97a51994cd.png)

ssh 到公共 VM 实例

1.  通过内部 IP 地址从`chap7-public`到`chap7-private`进行 ssh：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/0bdef6f5-f918-4d9f-ab06-2dfdf413ecc4.png)ssh 到私有 VM 实例

1.  输入`exit`命令返回到`chap7-public`主机，然后使用`apt-get`命令安装`nginx`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/c932a618-0356-4c6b-aefc-c96873cd71b8.png)在公共 VM 实例上安装 nginx

1.  使用以下命令启动`nginx`：

```
$ sudo systemctl start nginx
```

1.  使用您的 Web 浏览器访问`chap7-public`（通过外部 IP）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/e140b946-9757-4ec3-96a3-650eddc6f7ab.png)访问公共 VM 实例上的 nginx web 服务器

恭喜！您已经完成了设置 GCP VPC、子网和防火墙规则，并启动了 VM 实例！这些都是 Google Compute Engine 的非常基本和常见的用法。您可以登录并在这些机器上安装软件，甚至可以从头开始构建一个 Kubernetes 集群。但是，GCP 还有一个名为 Kubernetes Engine 的托管 Kubernetes 产品。我们将在本章中探讨它。

# 玩转 Google Kubernetes Engine

Kubernetes 是由谷歌设计的，并在谷歌内部广泛使用多年。Google Cloud Platform 提供托管的 GKE。使用 GKE，我们不需要从头开始构建集群。相反，集群可以按需启动和关闭。

# 准备就绪

我们可以使用 GCP 控制台中的 Kubernetes Engine 仪表板或 gcloud CLI 来启动和配置集群。使用控制台非常直观和直观。但是，使用 CLI 是使操作可重复或与现有管道集成的更灵活的方式。在这个教程中，我们将介绍如何使用 gcloud 启动和设置 Kubernetes 集群，以及 GCP 中的一些重要概念。

在 GCP 中，一切都与项目相关联。GCP 项目是使用 GCP 服务、计费和权限控制的基本单位。首先，我们需要从 GCP 控制台创建一个项目[`console.cloud.google.com`](https://console.cloud.google.com)。

在 GCP 中，项目 ID 是全局唯一的。项目正确创建后，我们将看到分配了一个唯一的项目编号。在主页仪表板上，我们将清楚地看到我们使用了多少资源。我们可以从这里设置权限、存储、网络、计费和其他资源。在我们继续之前，我们需要安装 gcloud。gcloud 是 Google Cloud SDK 的一部分。除了 gcloud 可以在 GCP 中执行大多数常见操作之外，Google Cloud SDK 还包括其他常见的 GCP 工具，例如 gsutil（用于管理 Cloud Storage）、bq（用于 BigQuery 的命令行工具）和 core（Cloud SDK 库）。这些工具可以在 Google Cloud SDK 下载页面上找到：[`cloud.google.com/sdk/docs/#install_the_latest_cloud_tools_version_cloudsdk_current_version`](https://cloud.google.com/sdk/docs/#install_the_latest_cloud_tools_version_cloudsdk_current_version)。

安装 gcloud 后，运行 gcloud init 以登录并设置您的身份与 gcloud 并创建一个名为**k8s-cookbook-2e**的项目。我们可以使用 gcloud 来操作 Google Cloud 中的几乎所有服务；主要的命令组是：

```
gcloud container [builds|clusters|images|node-pools|operations] | $COMMAND $FLAG…
```

gcloud 容器命令行集用于管理我们在 Google Kubernetes Engine 中的容器和集群。对于启动集群，最重要的参数是网络设置。让我们花一些时间在这里了解 GCP 中的网络术语。就像 AWS 一样，GCP 也有 VPC 概念。这是一种私有和更安全的方式，可以将您的计算、存储和云资源与公共互联网隔离开来。它可以在项目之间进行对等连接，或者与本地数据中心建立 VPN，创建混合云环境：

```
// create GCP VPC, it might take few minutes.
# gcloud compute networks create k8s-network
Created [https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/global/networks/k8s-network].
NAME         SUBNET_MODE  BGP_ROUTING_MODE  IPV4_RANGE  GATEWAY_IPV4
k8s-network  AUTO         REGIONAL
```

在此网络上的实例在创建防火墙规则之前将无法访问。例如，您可以通过运行以下命令允许实例之间的所有内部流量以及 SSH、RDP 和 ICMP：

```
$ gcloud compute firewall-rules create <FIREWALL_NAME> --network k8s-network --allow tcp,udp,icmp --source-ranges <IP_RANGE>
$ gcloud compute firewall-rules create <FIREWALL_NAME> --network k8s-network --allow tcp:22,tcp:3389,icmp
```

默认情况下，VPC 以自动模式创建，这将在每个区域创建一个子网。我们可以通过子命令`describe`观察到这一点：

```
// gcloud compute networks describe <VPC name>
# gcloud compute networks describe k8s-network
autoCreateSubnetworks: true
creationTimestamp: '2018-02-25T13:54:28.867-08:00'
id: '1580862590680993403'
kind: compute#network
name: k8s-network
routingConfig:
  routingMode: REGIONAL
selfLink: https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/global/networks/k8s-network
subnetworks:
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/australia-southeast1/subnetworks/k8s-network
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/europe-west4/subnetworks/k8s-network
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/northamerica-northeast1/subnetworks/k8s-network
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/europe-west1/subnetworks/k8s-network
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/southamerica-east1/subnetworks/k8s-network
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/us-central1/subnetworks/k8s-network
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/us-east1/subnetworks/k8s-network
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/asia-east1/subnetworks/k8s-network
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/us-west1/subnetworks/k8s-network
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/europe-west3/subnetworks/k8s-network
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/asia-southeast1/subnetworks/k8s-network
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/us-east4/subnetworks/k8s-network
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/europe-west2/subnetworks/k8s-network
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/asia-northeast1/subnetworks/k8s-network
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/asia-south1/subnetworks/k8s-network
x_gcloud_bgp_routing_mode: REGIONAL
x_gcloud_subnet_mode: AUTO
```

在 GCP 中，每个子网都跨越一个区域。区域是一个区域中的隔离位置，这与 AWS 中的可用区概念类似。

或者，您可以通过添加参数`--subnet-mode=custom`以自定义模式创建网络，这允许您定义所需的 IP 范围、区域和所有路由规则。有关更多详细信息，请参阅前一节。

自动模式还可以帮助您设置所有默认的路由规则。路由用于定义某些 IP 范围的目的地。例如，此路由将将数据包定向到虚拟网络`10.158.0.0/20`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/7fe25562-f068-439c-9e86-1e0873de39b4.png)默认路由示例

有一个用于将数据包定向到外部世界的路由。此路由的下一跳是默认的互联网网关，类似于 AWS 中的 igw。但是，在 GCP 中，您不需要显式创建互联网网关：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/532e9bd0-5148-40f5-a51d-a02176ae9ee1.png)用于互联网访问的默认路由

GCP 网络中的另一个重要概念是防火墙规则，用于控制实例的入站和出站。在 GCP 中，防火墙规则与 VM 实例之间的关联是通过网络标签实现的。

防火墙规则也可以分配给网络中的所有实例或一组具有特定服务帐户的实例（仅入口）。服务帐户是 GCP 中 VM 实例的身份。一个或多个角色可以分配给一个服务帐户，因此它可以访问其他 GCP 资源。这类似于 AWS 实例配置文件。

一个 VM 实例可以有多个网络标签，这意味着可以应用多个网络路由。这张图表展示了标签的工作原理。在下面的图表中，第一个防火墙规则应用于 VM1 和 VM2，而 VM2 有两个与之相关联的防火墙规则：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/69c75148-13f4-4596-a4d4-dd6b32705650.png)AWS 安全组和 GCP 防火墙规则的示意图

在**AWS**中，一个或多个入口/出口规则被定义在一个**安全组**中，一个或多个安全组可以分配给一个**EC2**实例。而在**GCP**中，一个或多个防火墙规则被定义，并且与一个或多个标签相关联。一个实例可以分配一个或多个标签。通过映射网络标签，防火墙规则可以控制和限制实例的出入访问。

# 如何做…

我们已经学习了 GCP 中的基本网络概念。让我们启动我们的第一个 GKE 集群：

| **参数** | **描述** | **示例中的值** |
| --- | --- | --- |
| `--cluster-version` | 支持的集群版本（参考[`cloud.google.com/kubernetes-engine/release-notes`](https://cloud.google.com/kubernetes-engine/release-notes)） | `1.9.2-gke.1` |
| `--machine-type` | 节点的实例类型（参考[`cloud.google.com/compute/docs/machine-types`](https://cloud.google.com/compute/docs/machine-types)） | `f1-micro` |
| `--num-nodes` | 集群中节点的数量 | `3` |
| `--network` | 目标 VPC 网络 | `k8s-network`（我们刚刚创建的网络） |
| `--zone` | 目标区域 | `us-central1-a`（您可以自由选择任何区域） |
| `--tags` | 要附加到节点的网络标签 | private |
| `--service-account &#124; --scopes` | 节点身份（参考[`cloud.google.com/sdk/gcloud/reference/container/clusters/create`](https://cloud.google.com/sdk/gcloud/reference/container/clusters/create)获取更多范围值） | `storage-rw`,`compute-ro` |

通过引用前面的参数，让我们使用`gcloud`命令启动一个三节点集群：

```
// create GKE cluster
$ gcloud container clusters create my-k8s-cluster --cluster-version 1.9.2-gke.1 --machine-type f1-micro --num-nodes 3 --network k8s-network --zone us-central1-a --tags private --scopes=storage-rw,compute-ro
WARNING: The behavior of --scopes will change in a future gcloud release: service-control and service-management scopes will no longer be added to what is specified in --scopes. To use these scopes, add them explicitly to --scopes. To use the new behavior, set container/new_scopes_behavior property (gcloud config set container/new_scopes_behavior true).
WARNING: Starting in Kubernetes v1.10, new clusters will no longer get compute-rw and storage-ro scopes added to what is specified in --scopes (though the latter will remain included in the default --scopes). To use these scopes, add them explicitly to --scopes. To use the new behavior, set container/new_scopes_behavior property (gcloud config set container/new_scopes_behavior true).
Creating cluster my-k8s-cluster...done.
Created [https://container.googleapis.com/v1/projects/kubernetes-cookbook/zones/us-central1-a/clusters/my-k8s-cluster].
To inspect the contents of your cluster, go to: https://console.cloud.google.com/kubernetes/workload_/gcloud/us-central1-a/my-k8s-cluster?project=kubernetes-cookbook
kubeconfig entry generated for my-k8s-cluster.
NAME            LOCATION       MASTER_VERSION  MASTER_IP    MACHINE_TYPE  NODE_VERSION  NUM_NODES  STATUS
my-k8s-cluster  us-central1-a  1.9.2-gke.1     35.225.24.4  f1-micro      1.9.2-gke.1   3          RUNNING
```

在集群运行起来后，我们可以通过配置`kubectl`开始连接到集群：

```
# gcloud container clusters get-credentials my-k8s-cluster --zone us-central1-a --project kubernetes-cookbook
Fetching cluster endpoint and auth data.
kubeconfig entry generated for my-k8s-cluster.
```

让我们看看集群是否健康：

```
// list cluster components
# kubectl get componentstatuses
NAME                 STATUS    MESSAGE              ERROR
controller-manager   Healthy   ok
scheduler            Healthy   ok
etcd-0               Healthy   {"health": "true"}
etcd-1               Healthy   {"health": "true"}
```

我们可以检查集群中的节点：

```
// list the nodes in cluster
# kubectl get nodes
NAME                                            STATUS    ROLES     AGE       VERSION
gke-my-k8s-cluster-default-pool-7d0359ed-0rl8   Ready     <none>    21m       v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-7d0359ed-1s2v   Ready     <none>    21m       v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-7d0359ed-61px   Ready     <none>    21m       v1.9.2-gke.1
```

我们还可以使用`kubectl`来检查集群信息：

```
// list cluster info
# kubectl cluster-info
Kubernetes master is running at https://35.225.24.4
GLBCDefaultBackend is running at https://35.225.24.4/api/v1/namespaces/kube-system/services/default-http-backend:http/proxy
Heapster is running at https://35.225.24.4/api/v1/namespaces/kube-system/services/heapster/proxy
KubeDNS is running at https://35.225.24.4/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy
kubernetes-dashboard is running at https://35.225.24.4/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy
Metrics-server is running at https://35.225.24.4/api/v1/namespaces/kube-system/services/https:metrics-server:/proxy
```

# 它是如何工作的...

在幕后，gcloud 创建了一个具有三个节点的 Kubernetes 集群，以及一个控制器管理器，调度程序和具有两个成员的 etcd 集群。我们还可以看到主节点启动了一些服务，包括控制器使用的默认后端，用于监视的 heapster，集群中的 DNS 服务的 KubeDNS，用于 Kubernetes UI 的仪表板，以及用于资源使用度量的 metrics-server。

我们看到`Kubernetes-dashboard`有一个 URL；让我们尝试访问它：

！[](assets/4e58c86e-2d4e-4495-a79f-3bdc37c3da1b.png)禁止访问 Kubernetes 仪表板

我们得到了`HTTP 403 Forbidden`。我们从哪里获取访问和凭据呢？一种方法是通过`kubectl proxy`命令运行代理。它将主 IP 绑定到本地`127.0.0.1:8001`：

```
# kubectl proxy
Starting to serve on 127.0.0.1:8001
```

之后，当我们访问`http://127.0.0.1:8001/ui`时，它将被重定向到`http://127.0.0.1:8001/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy`。

自 Kubernetes 1.7 以来，仪表板已支持基于持有者令牌或`Kubeconfig`文件的用户身份验证：

！[](assets/fd85ef71-b10b-40b8-af0e-31ba8d287dee.png)登录到 Kubernetes 仪表板

您可以创建一个用户并将其绑定到当前上下文（请参阅第八章“高级集群管理”中的*身份验证和授权*配方）。只是为了方便起见，我们可以检查是否有任何现有用户。首先，我们需要知道我们当前的上下文名称。上下文包括集群信息，用于身份验证的用户和一个命名空间：

```
// check our current context name
# kubectl config current-context
gke_kubernetes-cookbook_us-central1-a_my-k8s-cluster
```

知道上下文名称后，我们可以通过`kubectl`配置视图`$CONTEXT_NAME`来描述它：

```
// kubectl config view $CONTEXT_NAME
# kubectl config view gke_kubernetes-cookbook_us-central1-a_my-k8s-cluster
current-context: gke_kubernetes-cookbook_us-central1-a_my-k8s-cluster
kind: Config
preferences: {}
users:
- name: gke_kubernetes-cookbook_us-central1-a_my-k8s-cluster
  user:
    auth-provider:
      config:
        access-token: $ACCESS_TOKEN
        cmd-args: config config-helper --format=json
        cmd-path: /Users/chloelee/Downloads/google-cloud-sdk-2/bin/gcloud
        expiry: 2018-02-27T03:46:57Z
        expiry-key: '{.credential.token_expiry}'
        token-key: '{.credential.access_token}'
      name: gcp
```

我们可能会发现我们的集群中存在一个默认用户；使用其`$ACCESS_TOKEN`，您可以一窥 Kubernetes 控制台。

！[](assets/6825b49d-6934-41d2-83a8-cb3a098d2675.png)Kubernetes 仪表板概述

我们在 GKE 中的集群已经运行起来了！让我们尝试看看是否可以在上面运行一个简单的部署：

```
# kubectl run nginx --image nginx --replicas=2
deployment "nginx" created
# kubectl get pods
NAME                   READY     STATUS    RESTARTS   AGE
nginx-8586cf59-x27bj   1/1       Running   0          12s
nginx-8586cf59-zkl8j   1/1       Running   0          12s
```

让我们检查一下我们的 Kubernetes 仪表板：

！[](assets/8a069c1f-b7cb-4441-8f32-90576dcdab69.png)Kubernetes 仪表板中的工作负载

万岁！部署已创建，结果是安排和创建了两个 pod。

# 另请参阅

+   在第八章“高级集群管理”中的* kubeconfig 高级设置*

+   在第八章“高级集群管理”中设置节点资源

+   在第八章中*高级集群管理*中*使用 Web UI*。

+   在第八章中*高级集群管理*中*在 Kubernetes 集群中设置 DNS 服务器*。

+   在第八章中*高级集群管理*中*身份验证和授权*。

# 在 GKE 上探索 CloudProvider

GKE 作为本地 Kubernetes 云提供商运行，与 Kubernetes 中的资源无缝集成，并允许您按需进行配置，例如，为网络配置 VPC 路由，为 StorageClass 配置**持久磁盘**（PD），为服务配置 L4 负载均衡器，为入口配置 L4 负载均衡器。

# 准备就绪

默认情况下，在 Google Cloud Platform 中创建网络并启动 Kubernetes 集群时，具有适当路由的容器可以在不设置显式网络的情况下相互通信。除了前面列出的资源，我们在大多数情况下不需要显式设置任何设置。GKE 会自动运行。

# 如何操作…

让我们看看 GKE 提供的存储、网络等功能有多方便。

# StorageClass

在第二章中*深入了解 Kubernetes 概念*中，我们学习了如何声明`PersistentVolume`和`PersistentVolumeClaim`。通过动态配置，您可以定义一组具有不同物理存储后端的`StorageClass`，并在`PersistentVolume`或`PersistentVolumeClaim`中使用它们。让我们看看它是如何工作的。

要检查当前默认的`StorageClass`，请使用`kubectl get storageclasses`命令：

```
# kubectl get storageclasses
NAME                 PROVISIONER            AGE
standard (default)   kubernetes.io/gce-pd   1h
```

我们可以看到我们有一个名为 standard 的默认存储类，其提供程序是 GCE PD。

让我们创建一个`PersistentVolumeClaim`请求，并使用标准的`StorageClass`作为后端：

```
# cat gke-pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
    name: pvc-example-pv
spec:
  storageClassName: standard
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi

// create resources
# kubectl create -f gke-pvc.yaml
persistentvolumeclaim "pvc-example-pv" created
```

`storageClassName`是放置`StorageClass`名称的地方。如果放入不存在的内容，PVC 将不会被创建，因为没有适当映射的`StorageClass`可用：

```
// check pvc status
# kubectl get pvc
NAME              STATUS    VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS   AGE
pvc-example-pv    Bound     pvc-1491b08e-1cfc-11e8-8589-42010a800360   10Gi       RWO            standard       12m

// describe the details of created PVC
# kubectl describe pvc pvc-example-pv
Name:          pvc-example-pv
Namespace:     default
StorageClass:  standard
Status:        Bound
Volume:        pvc-1491b08e-1cfc-11e8-8589-42010a800360
Labels:        <none>
Annotations:   pv.kubernetes.io/bind-completed=yes
               pv.kubernetes.io/bound-by-controller=yes
               volume.beta.kubernetes.io/storage-provisioner=kubernetes.io/gce-pd
Finalizers:    []
Capacity:      10Gi
Access Modes:  RWO
Events:
  Type    Reason                 Age   From                         Message
  ----    ------                 ----  ----                         -------
  Normal  ProvisioningSucceeded  12m   persistentvolume-controller  Successfully provisioned volume pvc-1491b08e-1cfc-11e8-8589-42010a800360 using kubernetes.io/gce-pd
```

我们可以看到卷`pvc-1491b08e-1cfc-11e8-8589-42010a800360`已经被创建并绑定。如果我们列出 GCP 磁盘，我们会发现已经创建了一个持久磁盘；磁盘名称的后缀表示 Kubernetes 中的卷名称。这就是动态卷配置的魔力：

```
# gcloud compute disks list
NAME                                                             ZONE           SIZE_GB  TYPE         STATUS
gke-my-k8s-cluster-5ef-pvc-1491b08e-1cfc-11e8-8589-42010a800360  us-central1-a  10       pd-standard  READY
```

除了默认的`StorageClass`，您还可以创建自己的。在第二章中进行了回顾，*深入了解 Kubernetes 概念*。

# 服务（负载均衡器）

`LoadBalancer`服务类型仅在支持外部负载均衡器的云环境中起作用。这允许外部流量路由到目标 Pod。在 GCP 中，`LoadBalancer`服务类型将创建一个 TCP 负载均衡器：

1.  用于允许负载均衡器和节点之间流量的防火墙规则将自动创建：

```
// leveraging LoadBalancer service
# cat gke-service.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      run: nginx
  template:
    metadata:
      labels:
        run: nginx
    spec:
      containers:
        - image: nginx
          name: nginx
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: nginx
spec:
  ports:
    - port: 80
      targetPort: 80
  type: LoadBalancer
  selector:
    run: nginx

// create resources
# kubectl create -f gke-service.yaml
deployment "nginx" created
service "nginx" created
```

1.  让我们来检查服务。如果负载均衡器仍在进行配置，`EXTERNAL-IP`将显示`<pending>`。等一会儿，负载均衡器 IP 最终会显示出来：

```
# kubectl get svc nginx
NAME      TYPE           CLUSTER-IP      EXTERNAL-IP      PORT(S)        AGE
nginx     LoadBalancer   10.35.250.183   35.225.223.151   80:30383/TCP   11m
```

1.  让我们使用`$EXTERNAL-IP:80`进行 curl，看看它是否正常工作：

```
# curl -I 35.225.223.151
HTTP/1.1 200 OK
Server: nginx/1.13.9
Date: Thu, 01 Mar 2018 03:57:05 GMT
Content-Type: text/html
Content-Length: 612
Last-Modified: Tue, 20 Feb 2018 12:21:20 GMT
Connection: keep-alive
ETag: "5a8c12c0-264"
Accept-Ranges: bytes
```

1.  如果我们在 GCP 中检查转发规则，我们可以找到一个定义了外部 IP 到目标池的流量如何走的规则：

```
# gcloud compute forwarding-rules list
NAME                              REGION       IP_ADDRESS      IP_PROTOCOL  TARGET
ae1f2ad0c1d0211e8858942010a80036  us-central1  35.225.223.151  TCP          us-central1/targetPools/ae1f2ad0c1d0211e8858942010a80036
```

1.  目标池是一组实例，它们接收来自转发规则的流量。我们也可以使用 gcloud 命令来检查目标池：

```
// list target pools
# gcloud compute target-pools list
NAME                              REGION       SESSION_AFFINITY  BACKUP  HEALTH_CHECKS
ae1f2ad0c1d0211e8858942010a80036  us-central1  NONE                      k8s-1a4c86537c370d21-node

// check target pools info, replace $GCP_REGION as your default region.
# gcloud compute target-pools describe ae1f2ad0c1d0211e8858942010a80036 --region=$GCP_REGION
creationTimestamp: '2018-02-28T19:45:46.052-08:00'
description: '{"kubernetes.io/service-name":"default/nginx"}'
healthChecks:
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/global/httpHealthChecks/k8s-1a4c86537c370d21-node
id: '3515096241941432709'
instances:
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/zones/us-central1-a/instances/gke-my-k8s-cluster-default-pool-36121894-71wg
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/zones/us-central1-a/instances/gke-my-k8s-cluster-default-pool-36121894-04rv
- https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/zones/us-central1-a/instances/gke-my-k8s-cluster-default-pool-36121894-3mxm
kind: compute#targetPool
name: ae1f2ad0c1d0211e8858942010a80036
region: https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/us-central1
selfLink: https://www.googleapis.com/compute/v1/projects/kubernetes-cookbook/regions/us-central1/targetPools/ae1f2ad0c1d0211e8858942010a80036
sessionAffinity: NONE
```

我们可以看到目标池内有三个节点。这些节点与我们的 Kubernetes 集群中的三个节点相同。负载均衡器将根据源/定义 IP 和端口的哈希将流量分发到节点上。`LoadBalancer`类型的服务看起来很方便；然而，它无法进行基于路径的路由。现在是 Ingress 发挥作用的时候了。Ingress 支持虚拟主机、基于路径的路由和 TLS 终止，这是对您的 Web 服务更灵活的方法。

# Ingress

在第五章中，*构建持续交付流水线*，我们学习了关于 Ingress 的概念，以及何时以及如何使用它。Ingress 定义了一组规则，允许入站连接访问 Kubernetes 集群服务。它在 L7 级别将流量路由到集群，并且控制器将流量带到节点。当 GCP 是云提供商时，如果创建了 Ingress，将创建一个 L7 负载均衡器，以及相关的防火墙规则、健康检查、后端服务、转发规则和 URL 映射。在 GCP 中，URL 映射是一个包含一组规则并将请求转发到相应后端服务的机制。

在这个示例中，我们将重用第五章中的示例，*构建持续交付流水线*，`Nodeport-deployment.yaml`和`echoserver.yaml`。接下来是这两个服务如何工作的示例，来自第五章，*构建持续交付流水线*：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/9396e211-b955-4cd9-bb43-1154a5cc13ae.jpg)Ingress 示例

我们将为 nginx 和 echoserver 创建一个 Ingress，路由到不同的服务。当流量进入时，pod Ingress 控制器将决定路由到哪个服务。

这是一个 Ingress 的示例。请注意，如果您希望底层服务始终从特定主机名访问，可能需要在规则部分内添加主机名：

```
# cat INGRESS.yaml
apiVersion: extensions/v1beta1
kind: INGRESS
metadata:
  name: my-INGRESS
  annotations:
    INGRESS.kubernetes.io/rewrite-target: /
spec:
  rules:
    - http:
        paths:
          - path: /
            # default backend
            backend:
              serviceName: nodeport-svc
              servicePort: 8080
          - path: /nginx
            # nginx service
            backend:
              serviceName: nodeport-svc
              servicePort: 8080
          - path: /echoserver
            # echoserver service
            backend:
              serviceName: echoserver-svc
              servicePort: 8080

// create nodeport-svc (nginx) service
# kubectl create -f nodeport-deployment.yaml
deployment "nodeport-deploy" created
service "nodeport-svc" created

// create echoserver-svc (echoserver) service
# kubectl create -f echoserver.yaml
deployment "echoserver-deploy" created
service "echoserver-svc" created

// create INGRESS
# kubectl create -f INGRESS.yaml
INGRESS "my-INGRESS" created
```

请仔细检查底层服务是否配置为`NodePort`类型。否则，您可能会遇到诸如`googleapi: Error 400: Invalid value for field 'namedPorts[1].port': '0'. Must be greater than or equal to 1, invalid error`的错误，来自`loadbalancer-controller`。

几分钟后，L7 负载均衡器将被创建，您可以从 GCP 控制台或使用 gcloud 命令来查看它。让我们使用`kubectl`来检查 INGRESS 中的后端服务是否健康：

```
// kubectl describe INGRESS $INGRESS_name
# kubectl describe INGRESS my-INGRESS

curl Name:             my-INGRESS
Namespace:        default
Address:          35.190.46.137
Default backend:  default-http-backend:80 (10.32.2.3:8080)
Rules:
  Host  Path  Backends
  ----  ----  --------
  *
        /             nodeport-svc:8080 (<none>)
        /nginx        nodeport-svc:8080 (<none>)
        /echoserver   echoserver-svc:8080 (<none>)
Annotations:
  backends:         {"k8s-be-31513--91cf30ccf285becb":"HEALTHY","k8s-be-31780--91cf30ccf285becb":"HEALTHY","k8s-be-32691--91cf30ccf285becb":"HEALTHY"}
  forwarding-rule:  k8s-fw-default-my-INGRESS--91cf30ccf285becb
  rewrite-target:   /
  target-proxy:     k8s-tp-default-my-INGRESS--91cf30ccf285becb
  url-map:          k8s-um-default-my-INGRESS--91cf30ccf285becb
Events:
  Type    Reason   Age               From                     Message
  ----    ------   ----              ----                     -------
  Normal  Service  2m (x11 over 1h)  loadbalancer-controller  no user specified default backend, using system default
```

我们可以看到三个后端服务都是健康的，并且相关的转发规则、目标代理和 URL 映射都已创建。我们可以通过访问 GCP 控制台中的 GKE 中的发现和负载均衡或网络服务中的负载均衡选项卡来全面了解情况：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/c1509f93-dc69-4e09-b6c6-0c80c63776cc.png)发现和负载均衡

后端服务如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/69386610-e730-4510-94ff-cda84aa27e43.png)后端服务

您的 Ingress 资源可能会不时遇到更新。当您重新部署它时，不能保证 GCP 会为您的负载均衡器分配相同的 IP 地址。当 IP 地址与 DNS 名称关联时，这可能会引入问题。每次 IP 更改时，目标 IP 地址都需要更新。这可以通过静态外部 IP 地址加上`kubernetes.io/INGRESS.global-static-ip-name`注释来解决：

```
// allocate static IP as my-external-ip
# gcloud compute addresses create my-external-ip –global

// check external-ip
# gcloud compute addresses list
NAME            REGION  ADDRESS        STATUS
my-external-ip          130.211.37.61  RESERVED
After external IP is prepared, we could start launching our INGRESS now.
# cat INGRESS-static-ip.yaml
apiVersion: extensions/v1beta1
kind: INGRESS
metadata:
  name: my-INGRESS-static-ip
  annotations:
    INGRESS.kubernetes.io/rewrite-target: /
    kubernetes.io/INGRESS.global-static-ip-name: my-external-ip
spec:
  rules:
    - http:
        paths:
          - path: /
            # default backend
            backend:
              serviceName: nodeport-svc
              servicePort: 8080
          - path: /nginx
            # nginx service
            backend:
              serviceName: nodeport-svc
              servicePort: 8080
          - path: /echoserver
            # echoserver service
            backend:
              serviceName: echoserver-svc
              servicePort: 8080

# kubectl create -f INGRESS-static-ip.yaml
INGRESS "my-INGRESS-stati-ip" created
```

让我们描述`my-INGRESS`，看看它是否正确绑定了我们创建的外部 IP：

```
# kubectl describe INGRESS my-INGRESS
Name:             my-INGRESS
Namespace:        default
Address:          130.211.37.61
Default backend:  default-http-backend:80 (10.32.2.3:8080)
Rules:
  Host  Path  Backends
  ----  ----  --------
  *        /             nodeport-svc:8080 (<none>)
        /nginx        nodeport-svc:8080 (<none>)        /echoserver   echoserver-svc:8080 (<none>)Annotations:
  backends:         {"k8s-be-31108--91cf30ccf285becb":"HEALTHY","k8s-be-31250--91cf30ccf285becb":"HEALTHY","k8s-be-32691--91cf30ccf285becb":"HEALTHY"}  forwarding-rule:  k8s-fw-default-my-INGRESS--91cf30ccf285becb  rewrite-target:   /  target-proxy:     k8s-tp-default-my-INGRESS--91cf30ccf285becb  url-map:          k8s-um-default-my-INGRESS--91cf30ccf285becbEvents:  Type    Reason   Age               From                     Message  ----    ------   ----              ----                     -------  Normal  ADD      27m               loadbalancer-controller  default/my-INGRESS  Normal  CREATE   25m               loadbalancer-controller  ip: 130.211.37.61
  Normal  Service  4m (x6 over 25m)  loadbalancer-controller  no user specified default backend, using system default
```

我们已经准备就绪。`Nginx`和`echoserver`可以通过外部静态 IP`130.211.37.61`访问，并且我们可以通过在 GCP 中使用云 DNS 服务来将 DNS 名称与其关联。

# 还有更多...

在 Kubernetes v.1.9 中，Kubernetes 云控制器管理器被提升为 alpha 版。云控制器管理器旨在通过其自身的发布周期支持云提供商的发布功能，这可以独立于 Kubernetes 的发布周期。然后它可以独立于 Kubernetes 核心发布周期。它提供了每个云提供商都可以实现的通用接口，与 Kubernetes 核心逻辑解耦。在不久的将来，我们将看到来自不同云提供商的更全面的支持！

# 另请参阅

+   *在第二章中使用服务*，*深入了解 Kubernetes 概念*

+   *在第二章中使用卷*，*深入了解 Kubernetes 概念*

+   *在第三章中转发容器端口*，*玩转容器*

# 在 GKE 上管理 Kubernetes 集群

Google Kubernetes Engines 为我们提供了运行 Kubernetes 的无缝体验；它还使 Kubernetes 管理变得如此简单。根据预期的高峰时间，我们可能希望扩展或缩小 Kubernetes 节点。或者，我们可以使用自动缩放器来对节点进行自动缩放。Kubernetes 是一个不断发展的平台。发布速度很快。我们可能需要不时地升级集群版本，这非常容易做到。我们还可以使用 Autoupgrade 功能通过在 GKE 中启用自动调度功能来升级集群。让我们看看如何做到这一点。

# 准备工作

在设置 GCP 提供的管理功能之前，我们必须有一个正在运行的集群。我们将在本章中重复使用我们在“玩转 Google Kubernetes Engine”示例中创建的集群。

# 如何做…

在这个示例中，我们将介绍如何根据使用情况和要求来管理节点数量。此外，我们还将学习如何处理集群升级。最后，我们将看到如何在 GKE 中提供多区域集群，以防止物理区域的故障。

# 节点池

节点池是 GCP 中共享相同配置的一组实例。当我们从`gcloud`命令启动集群时，我们传递`--num-node=3`和其余参数。然后将在同一池内启动三个实例，共享相同的配置，使用相同的方法：

```
# gcloud compute instance-groups list NAME LOCATION SCOPE NETWORK MANAGED INSTANCES gke-my-k8s-cluster-default-pool-36121894-grp us-central1-a zone k8s-network Yes 3 
```

假设您的服务预计会出现高峰时间。作为 Kubernetes 管理员，您可能希望调整集群内的节点池大小。

```
# gcloud container clusters resize my-k8s-cluster --size 5 --zone us-central1-a --node-pool default-pool
Pool [default-pool] for [my-k8s-cluster] will be resized to 5.
Do you want to continue (Y/n)?  y
Resizing my-k8s-cluster...done.
Updated [https://container.googleapis.com/v1/projects/kubernetes-cookbook/zones/us-central1-a/clusters/my-k8s-cluster].
# kubectl get nodes
NAME                                               STATUS    ROLES     AGE       VERSION
gke-my-k8s-cluster-default-pool-36121894-04rv      Ready     <none>    6h        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-36121894-71wg      Ready     <none>    6h        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-36121894-8km3      Ready     <none>    39s       v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-36121894-9j9p      Ready     <none>    31m       v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-36121894-9jmv      Ready     <none>    36s       v1.9.2-gke.1
```

调整大小命令可以帮助您扩展和缩小。如果调整大小后的节点数少于之前，调度器将迁移 pod 以在可用节点上运行。

您可以为规范中的每个容器设置计算资源边界。您可以为 pod 容器设置请求和限制。假设我们有一个需要 1024 MB 内存的超级 nginx：

```
# cat super-nginx.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: super-nginx
  labels:
    app: nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx
        resources:
          requests:
            memory: 1024Mi 

// create super nginx deployment
# kubectl create -f super-nginx.yaml
deployment "super-nginx" created

# kubectl get pods
NAME                           READY     STATUS    RESTARTS   AGE
super-nginx-df79db98-5vfmv      0/1       Pending   0          10s
# kubectl describe po super-nginx-779494d88f-74xjp
Name:           super-nginx-df79db98-5vfmv
Namespace:      default
Node:           <none>
Labels:         app=nginx
                pod-template-hash=89358654
Annotations:    kubernetes.io/limit-ranger=LimitRanger plugin set: cpu request for container nginx
Status:         PendingIP:
Controlled By:  ReplicaSet/super-nginx-df79db98
...
Events:
  Type     Reason            Age                From               Message
  ----     ------            ----               ----               -------
  Warning  FailedScheduling  11s (x5 over 18s)  default-scheduler  0/5 nodes are available: 5 Insufficient memory.
```

我们创建的节点大小是`f1-miro`，每个节点只有 0.6 GB 内存。这意味着调度器永远无法找到具有足够内存来运行`super-nginx`的节点。在这种情况下，我们可以通过创建另一个节点池向集群中添加具有更高内存的更多节点。我们将使用`g1-small`作为示例，其中包含 1.7 GB 内存：

```
// create a node pool named larger-mem-pool with n1-standard-1 instance type
# gcloud container node-pools create larger-mem-pool --cluster my-k8s-cluster --machine-type n1-standard-1 --num-nodes 2 --tags private --zone us-central1-a --scopes=storage-rw,compute-ro
...
Creating node pool larger-mem-pool...done.
Created [https://container.googleapis.com/v1/projects/kubernetes-cookbook/zones/us-central1-a/clusters/my-k8s-cluster/nodePools/larger-mem-pool].
NAME             MACHINE_TYPE   DISK_SIZE_GB  NODE_VERSION
larger-mem-pool  n1-standard-1  100           1.9.2-gke.1

// check node pools
# gcloud container node-pools list --cluster my-k8s-cluster --zone us-central1-a
NAME             MACHINE_TYPE   DISK_SIZE_GB  NODE_VERSION
default-pool     f1-micro       100           1.9.2-gke.1
larger-mem-pool  n1-standard-1  100           1.9.2-gke.1

// check current nodes
# kubectl get nodes
NAME                                               STATUS    ROLES     AGE       VERSION
gke-my-k8s-cluster-default-pool-36121894-04rv      Ready     <none>    7h        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-36121894-71wg      Ready     <none>    7h        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-36121894-8km3      Ready     <none>    9m        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-36121894-9j9p      Ready     <none>    40m       v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-36121894-9jmv      Ready     <none>    9m        v1.9.2-gke.1
gke-my-k8s-cluster-larger-mem-pool-a51c8da3-f1tb   Ready     <none>    1m        v1.9.2-gke.1
gke-my-k8s-cluster-larger-mem-pool-a51c8da3-scw1   Ready     <none>    1m        v1.9.2-gke.1
```

看起来我们有两个更强大的节点。让我们来看看我们超级 nginx 的状态：

```
# kubectl get pods
NAME                         READY     STATUS    RESTARTS   AGE
super-nginx-df79db98-5vfmv   1/1       Running   0          23m
```

它正在运行！Kubernetes 调度器将始终尝试找到足够的资源来调度 pod。在这种情况下，集群中添加了两个新节点，可以满足资源需求，因此 pod 被调度并运行：

```
// check the event of super nginx
# kubectl describe pods super-nginx-df79db98-5vfmv
...
Events:
  Warning  FailedScheduling       3m (x7 over 4m)     default-scheduler                                          0/5 nodes are available: 5 Insufficient memory.
  Normal   Scheduled              1m                  default-scheduler                                          Successfully assigned super-nginx-df79db98-5vfmv to gke-my-k8s-cluster-larger-mem-pool-a51c8da3-scw1
  Normal   SuccessfulMountVolume  1m                  kubelet, gke-my-k8s-cluster-larger-mem-pool-a51c8da3-scw1  MountVolume.SetUp succeeded for volume "default-token-bk8p2"
  Normal   Pulling                1m                  kubelet, gke-my-k8s-cluster-larger-mem-pool-a51c8da3-scw1  pulling image "nginx"
  Normal   Pulled                 1m                  kubelet, gke-my-k8s-cluster-larger-mem-pool-a51c8da3-scw1  Successfully pulled image "nginx"
  Normal   Created                1m                  kubelet, gke-my-k8s-cluster-larger-mem-pool-a51c8da3-scw1  Created container
  Normal   Started                1m                  kubelet, gke-my-k8s-cluster-larger-mem-pool-a51c8da3-scw1  Started container
```

从 pod 的事件中，我们知道它经过了哪些路径。最初，它找不到具有足够资源的节点，最终被调度到名为`gke-my-k8s-cluster-larger-mem-pool-a51c8da3-scw1`的新节点上。

为了使用户对在特定节点上调度 pod 的偏好，引入了`nodeSelector`。您可以在 pod 规范中使用内置的节点标签，例如`beta.kubernetes.io/instance-type: n1-standard-1`，或使用自定义标签来实现。有关更多信息，请参阅[`kubernetes.io/docs/concepts/configuration/assign-pod-node`](https://kubernetes.io/docs/concepts/configuration/assign-pod-node)。

Kubernetes 还支持**集群自动缩放**，根据容量自动调整集群大小，如果所有节点都没有足够的资源来运行请求的 pod。为此，我们在创建新节点池时添加`–enable-autoscaling`并指定最大和最小节点数：

```
# cloud container node-pools create larger-mem-pool --cluster my-k8s-cluster --machine-type n1-standard-1 --tags private --zone us-central1-a --scopes=storage-rw,compute-ro --enable-autoscaling --min-nodes 1 --max-nodes 5
...
Creating node pool larger-mem-pool...done.
Created [https://container.googleapis.com/v1/projects/kubernetes-cookbook/zones/us-central1-a/clusters/my-k8s-cluster/nodePools/larger-mem-pool].
NAME             MACHINE_TYPE   DISK_SIZE_GB  NODE_VERSION
larger-mem-pool  n1-standard-1  100           1.9.2-gke.1
```

几分钟后，我们可以看到我们的集群中有一个新节点：

```
#  kubectl get nodes
NAME                                               STATUS    ROLES     AGE       VERSION
gke-my-k8s-cluster-default-pool-36121894-04rv      Ready     <none>    8h        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-36121894-71wg      Ready     <none>    8h        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-36121894-8km3      Ready     <none>    1h        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-36121894-9j9p      Ready     <none>    1h        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-36121894-9jmv      Ready     <none>    1h        v1.9.2-gke.1
gke-my-k8s-cluster-larger-mem-pool-a51c8da3-s6s6   Ready     <none>    15m       v1.9.2-gke.1
```

现在，让我们通过使用`kubectl`编辑或创建新的部署，将我们的超级 nginx 的副本从 1 更改为 4：

```
// check current pods
# kubectl get pods
NAME                         READY     STATUS    RESTARTS   AGE
super-nginx-df79db98-5q9mj   0/1       Pending   0          3m
super-nginx-df79db98-72fcz   1/1       Running   0          3m
super-nginx-df79db98-78lbr   0/1       Pending   0          3m
super-nginx-df79db98-fngp2   1/1       Running   0          3m
```

我们发现有两个处于挂起状态的 pod：

```
// check nodes status
# kubectl get nodes
NAME                                               STATUS     ROLES     AGE       VERSION
gke-my-k8s-cluster-default-pool-36121894-04rv      Ready   <none>    8h        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-36121894-71wg      Ready      <none>    8h        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-36121894-9j9p      Ready      <none>    2h        v1.9.2-gke.1
gke-my-k8s-cluster-larger-mem-pool-a51c8da3-d766   Ready      <none>    4m        v1.9.2-gke.1
gke-my-k8s-cluster-larger-mem-pool-a51c8da3-gtsn   Ready      <none>    3m        v1.9.2-gke.1
gke-my-k8s-cluster-larger-mem-pool-a51c8da3-s6s6   Ready      <none>    25m       v1.9.2-gke.1
```

几分钟后，我们看到我们的大内存池中有新成员，并且所有我们的 pod 都可以运行：

```
// check pods status
# kubectl get pods
NAME                         READY     STATUS    RESTARTS   AGE
super-nginx-df79db98-5q9mj   1/1       Running   0          3m
super-nginx-df79db98-72fcz   1/1       Running   0          3m
super-nginx-df79db98-78lbr   1/1       Running   0          3m
super-nginx-df79db98-fngp2   1/1       Running   0          3m
```

集群自动缩放非常方便且具有成本效益。当节点过度配置时，节点池中的额外节点将被自动终止。

# 多区域和区域性集群

我们的`my-k8s-cluster`目前部署在`us-central1-a`区域。虽然区域是一个区域内的物理隔离位置，但它可能会发生故障。Google Kubernetes Engine 支持多区域和区域部署。多区域集群在一个区域中创建一个主节点，并在多个区域中提供节点；另一方面，区域集群在三个区域中创建多个主节点，并在多个区域中提供节点。

# 多区域集群

启用多区域集群，创建集群时在命令中添加`--additional-zones $zone2, $zone3, …`。

就像 AWS 一样，GCP 也有服务配额限制。如果需要，您可以使用`gcloud compute project-info describe –project $PROJECT_NAME`来检查配额，并从 GCP 控制台请求增加。

让我们首先启动每个区域的两个节点集群：

```
// launch a multi-zone cluster with 2 nodes per zone.
# gcloud container clusters create my-k8s-cluster --cluster-version 1.9.2-gke.1 --machine-type f1-micro --num-nodes 2 --network k8s-network --tags private --scopes=storage-rw,compute-ro --zone us-central1-a --additional-zones us-central1-b,us-central1-c
Creating cluster my-k8s-cluster...done.
Created [https://container.googleapis.com/v1/projects/kubernetes-cookbook/zones/us-central1-a/clusters/my-k8s-cluster].
To inspect the contents of your cluster, go to: https://console.cloud.google.com/kubernetes/workload_/gcloud/us-central1-a/my-k8s-cluster?project=kubernetes-cookbook
kubeconfig entry generated for my-k8s-cluster.
NAME            LOCATION       MASTER_VERSION  MASTER_IP      MACHINE_TYPE  NODE_VERSION  NUM_NODES  STATUS
my-k8s-cluster  us-central1-a  1.9.2-gke.1     35.226.67.179  f1-micro      1.9.2-gke.1   6          RUNNING
```

我们发现现在有六个节点：

```
# kubectl get nodes
NAME                                            STATUS    ROLES     AGE       VERSION
gke-my-k8s-cluster-default-pool-068d31a2-q909   Ready     <none>    8m        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-068d31a2-rqzw   Ready     <none>    8m        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-64a6ead8-qf6z   Ready     <none>    8m        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-64a6ead8-x8cc   Ready     <none>    8m        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-798c4248-2r4p   Ready     <none>    8m        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-798c4248-skdn   Ready     <none>    8m        v1.9.2-gke.1
```

让我们检查一下节点是否分布在我们指定的三个区域中：

```
# gcloud compute instance-groups list NAME LOCATION SCOPE NETWORK MANAGED INSTANCES gke-my-k8s-cluster-default-pool-068d31a2-grp us-central1-a zone k8s-network Yes 2 gke-my-k8s-cluster-default-pool-64a6ead8-grp us-central1-c zone k8s-network Yes 2 gke-my-k8s-cluster-default-pool-798c4248-grp us-central1-b zone k8s-network Yes 2 
```

# 区域集群

区域集群仍处于测试阶段。要使用这些，我们需要启用 gcloud beta 命令。我们可以通过以下命令启用它：

```
# export CLOUDSDK_CONTAINER_USE_V1_API_CLIENT=false # gcloud config set container/use_v1_api false 
Updated property [container/use_v1_api].
```

然后我们应该能够使用`gcloud v1beta`命令启动区域集群：

```
# gcloud beta container clusters create my-k8s-cluster --cluster-version 1.9.2-gke.1 --machine-type f1-micro --num-nodes 2 --network k8s-network --tags private --scopes=storage-rw,compute-ro --region us-central1 

Creating cluster my-k8s-cluster...done. Created [https://container.googleapis.com/v1beta1/projects/kubernetes-cookbook/zones/us-central1/clusters/my-k8s-cluster]. To inspect the contents of your cluster, go to: https://console.cloud.google.com/kubernetes/workload_/gcloud/us-central1/my-k8s-cluster?project=kubernetes-cookbook 

kubeconfig entry generated for my-k8s-cluster. NAME LOCATION MASTER_VERSION MASTER_IP MACHINE_TYPE NODE_VERSION NUM_NODES STATUS my-k8s-cluster us-central1 1.9.2-gke.1 35.225.71.127 f1-micro 1.9.2-gke.1 6 RUNNING
```

该命令与创建集群的命令非常相似，只有两个不同之处：在组名 container 之前添加了一个 beta 标志，表示这是一个`v1beta`命令。第二个不同之处是将`--zone`更改为`--region`：

```
// list instance groups
# gcloud compute instance-groups list
NAME                                          LOCATION       SCOPE  NETWORK      MANAGED  INSTANCES
gke-my-k8s-cluster-default-pool-074ab64e-grp  us-central1-a  zone   k8s-network  Yes      2
gke-my-k8s-cluster-default-pool-11492dfc-grp  us-central1-c  zone   k8s-network  Yes      2
gke-my-k8s-cluster-default-pool-f2c90100-grp  us-central1-b  zone   k8s-network  Yes      2
```

# 集群升级

Kubernetes 是一个快速发布的项目。GKE 也不断支持新版本。一个月内有多个次要版本更新并不罕见。检查 GKE 控制台：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/7474190c-b187-407f-aac8-f92c7e3c9ec3.png)GCP 控制台中的可升级信息

我们看到有一个可用的升级。截图中的 1.9.3-gke.1 刚刚发布，我们的集群可以升级：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/bd70a627-254a-4882-b45a-7f1c15f9b782.png)可升级至 1.9.3-gke.0

我们可以通过 GKE 控制台或使用 gcloud 命令升级集群。我们将使用单区域（`us-central1-a`）集群来演示如何在下一个示例中进行升级。在升级集群时，主节点始终是首先进行升级的节点。期望的节点版本不能大于当前主节点版本。

```
# gcloud container clusters upgrade my-k8s-cluster --zone us-central1-a --cluster-version 1.9.3-gke.0 –master
Master of cluster [my-k8s-cluster] will be upgraded from version
[1.9.2-gke.1] to version [1.9.3-gke.0]. This operation is long-running
 and will block other operations on the cluster (including delete)
until it has run to completion.
Do you want to continue (Y/n)?  y
Upgrading my-k8s-cluster...done.
Updated [https://container.googleapis.com/v1/projects/kubernetes-cookbook/zones/us-central1-a/clusters/my-k8s-cluster].
```

让我们检查一下主节点的版本：

```
# kubectl version
...
Server Version: version.Info{Major:"1", Minor:"9+", GitVersion:"v1.9.3-gke.0", GitCommit:"a7b719f7d3463eb5431cf8a3caf5d485827b4210", GitTreeState:"clean", BuildDate:"2018-02-16T18:26:01Z", GoVersion:"go1.9.2b4", Compiler:"gc", Platform:"linux/amd64"}
```

看起来不错。主节点已升级到`v1.9.3-gke.0`，但我们的节点还没有升级：

```
# kubectl get nodes
NAME                                            STATUS    ROLES     AGE       VERSION
gke-my-k8s-cluster-default-pool-978ca614-3jxx   Ready     <none>    8m        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-978ca614-njrs   Ready     <none>    8m        v1.9.2-gke.1
gke-my-k8s-cluster-default-pool-978ca614-xmlw   Ready     <none>    8m        v1.9.2-gke.1
```

对于节点升级，GKE 不会一次性升级所有节点，而是执行滚动升级。它将首先从节点池中排空和注销一个节点，删除旧实例，然后使用所需版本重新创建一个新实例，然后将其添加回集群中：

```
// perform node upgrades.
# gcloud container clusters upgrade my-k8s-cluster --zone us-central1-a --cluster-version 1.9.3-gke.0
All nodes (3 nodes) of cluster [my-k8s-cluster] will be upgraded from
version [1.9.2-gke.1] to version [1.9.3-gke.0]. This operation is
long-running and will block other operations on the cluster (including
 delete) until it has run to completion.
Do you want to continue (Y/n)?  y
Upgrading my-k8s-cluster...done.
Updated [https://container.googleapis.com/v1/projects/kubernetes-cookbook/zones/us-central1-a/clusters/my-k8s-cluster].
```

节点池可以通过在集群创建期间使用`--enable-autoupgrade`标志进行自动升级，或者使用 gcloud 容器`node-pools`更新命令来更新现有节点池。有关更多信息，请参阅[`cloud.google.com/kubernetes-engine/docs/concepts/node-auto-upgrades`](https://cloud.google.com/kubernetes-engine/docs/concepts/node-auto-upgrades)。

这将需要超过 10 分钟。之后，集群中的所有节点都将升级到`1.9.3-gke.0`。

# 另请参阅

+   *在第八章中 kubeconfig 的高级设置*，*高级集群管理*

+   *在第八章中设置节点资源*，*高级集群管理*


# 第八章：高级集群管理

在本章中，我们将涵盖以下内容：

+   kubeconfig 中的高级设置

+   在节点中设置资源

+   使用 WebUI 玩耍

+   使用 RESTful API 工作

+   使用 Kubernetes DNS 工作

+   认证和授权

# 介绍

在本章中，我们将介绍一些高级管理主题。首先，您将学习如何使用 kubeconfig 来管理不同的集群。然后，我们将在节点中处理计算资源。Kubernetes 提供了友好的用户界面，用于展示资源的当前状态，例如部署、节点和 Pod。您将学习如何构建和管理它。

接下来，您将学习如何使用 Kubernetes 公开的 RESTful API。这将是与其他系统集成的便捷方式。最后，我们希望构建一个安全的集群；最后一节将介绍如何在 Kubernetes 中设置认证和授权。

# kubeconfig 中的高级设置

**kubeconfig**是一个配置文件，在客户端上管理 Kubernetes 中的集群、上下文和认证设置。使用`kubeconfig`文件，我们可以设置不同的集群凭据、用户和命名空间，以在集群之间或集群内的上下文之间切换。它可以通过使用`kubectl config`子命令来配置命令行，也可以通过直接更新配置文件来配置。在本节中，我们将描述如何使用`kubectl config`来操作 kubeconfig 以及如何直接输入 kubeconfig 文件。

如果您已经阅读了第二章中的*使用命名空间*，即*走进 Kubernetes 概念*，那里我们首次提到了 kubeconfig，您将了解其基本概念。让我们回顾一些关键点：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/e705eb01-9990-424f-8967-f63d4de49904.png)kubeconfig 包含三个参数：用户、集群和上下文

从上图可以注意到以下内容：

+   **kubeconfig 中有三个参数**：用户、集群和上下文—用户有自己的认证，而集群确定了具有专用计算资源的特定 API 服务器。上下文既是*用户*又是集群。

+   **为各种设置组合构建多个上下文**：用户和集群可以在不同的上下文中共享。

+   **命名空间可以在一个上下文中对齐**：命名空间的当前上下文设置了规则。任何请求都应遵循当前上下文中的用户和集群映射。

# 做好准备

请运行两个 Kubernetes 集群，并为它们指定主机名。您可以在主节点上更新 hostfile（`/etc/hosts`）。一个在本地主机上，API 服务器端点为`http://localhost:8080`，另一个在远程端点，端点为`http://$REMOTE_MASTER_NODE:8080`。我们将使用这两个集群进行演示。这里的 API 服务器端点是不安全的通道。这是一个简单的 API 服务器配置，用于虚拟访问权限。

**在 kubeadm 上启用 API 服务器的不安全端点**

在运行`kubeadm init`时，我们必须传递额外的参数给 API 服务器。在这种情况下，应用标志`--config`指示的自定义配置文件：

```
// you can also get this file through code bundle $ cat additional-kubeadm-config apiVersion: kubeadm.k8s.io/v1alpha1 kind: MasterConfiguration apiServerExtraArgs:
 insecure-bind-address: "0.0.0.0" insecure-port: "8080" // start cluster with additional system settings $ sudo kubeadm init --config ./additional-kubeadm-config
```

在启动了两个具有不安全访问 API 服务器端点的集群之后，确保您可以在本地主机集群上访问它们：

```
// on localhost cluster, the following commands should be successful
$ curl http://localhost:8080
$ curl http://$REMOTE_MASTER_NODE:8080
```

请注意，不安全的地址配置只是为了我们即将进行的教程。用户应该小心在实际系统中正确设置它。

在开始之前，我们应该检查默认的 kubeconfig，以便观察任何更新后的更改。执行命令`kubectl config view`来查看您的初始 kubeconfig：

```
// the settings created by kubeadm
$ kubectl config view
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: REDACTED
    server: https://192.168.122.101:6443
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kubernetes-admin
  name: kubernetes-admin@kubernetes
current-context: kubernetes-admin@kubernetes kind: Config
preferences: {}
users:
- name: kubernetes-admin
  user:
    client-certificate-data: REDACTED
    client-key-data: REDACTED
```

根据您的安装方法，可能会有一些不同的设置。但是我们也可以发现工具已经初始化了一个基本上下文，即`kubeadm`中的`kubernetes-admin@kubernetes`。继续复制物理的`kubeconfig`文件作为以后更新的基础，并在练习后恢复我们的原始环境。

```
// in default, the kubeconfig used by client is the one under $HOME
$ cp ~/.kube/config ~/original-kubeconfig
```

# 如何做...

在这个教程中，我们将使用本地主机集群作为主控制台，通过上下文更改来切换集群。首先，在两个集群中运行不同数量的`nginx`，并确保所有的 pod 都在运行：

```
// in the terminal of localhost cluster
$ kubectl run local-nginx --image=nginx --replicas=2 --port=80
deployment "local-nginx" created
// check the running pods
$ kubectl get pod
NAME                           READY     STATUS    RESTARTS   AGE
local-nginx-6484bbb57d-xpjp2   1/1       Running   0          1m
local-nginx-6484bbb57d-z4qgp   1/1       Running   0          1m
// in the terminal of remote cluster
$ kubectl run remote-nginx --image=nginx --replicas=4 --port=80
deployment "remote-nginx" created
$ kubectl get pod
NAME                            READY     STATUS    RESTARTS   AGE
remote-nginx-5dd7b9cb7d-fxr9m   1/1       Running   0          29s
remote-nginx-5dd7b9cb7d-gj2ft   1/1       Running   0          29s
remote-nginx-5dd7b9cb7d-h7lmj   1/1       Running   0          29s
remote-nginx-5dd7b9cb7d-hz766   1/1       Running   0          29s
```

# 设置新的凭据

接下来，我们将为每个集群设置两个凭据。使用子命令`set-credentials`，如`kubectl config set-credentials <CREDENTIAL_NAME>`，将凭据添加到 kubeconfig 中。Kubernetes 支持不同的身份验证方法。我们可以使用密码、客户端证书或令牌。在这个例子中，我们将使用 HTTP 基本身份验证来简化场景。Kubernetes 还支持客户端证书和令牌身份验证。有关更多信息，请使用标志`-h`执行`set-credentials`命令，以详细介绍其功能：

```
// check the details of setting up credentials
$ kubectl config set-credentials -h
// in localhost cluster, copy the based file into a new one
$ cp ~/original-kubeconfig ~/new-kubeconfig
// add a user "user-local" with credential named "myself@localhost" in kubeconfig "new-kubeconfig"
$ kubectl config set-credentials myself@localhost --username=user-local --password=passwordlocal --kubeconfig="new-kubeconfig"
User "myself@local" set.
```

通过上述步骤，我们成功在`"new-kubeconfig"` kubeconfig 文件中添加了新的凭据。kubeconfig 文件将默认格式化为 YAML-您可以通过文本编辑器检查文件。通过这种方法，我们能够定制新的配置而不干扰当前的设置。另一方面，如果没有`--kubeconfig`标志，更新将直接附加到`live kubeconfig`上：

```
// renew live kubeconfig file with previous update
$ cp ~/new-kubeconfig ~/.kube/config
// add another credential in localhost cluster, this time, let's update current settings directly
$ kubectl config set-credentials myself@remote --username=user-remote --password=passwordremote
User "myself@remote" set.
```

此时，请检查您的 live kubeconfig 设置，并找出新的凭据：

```
$ kubectl config view
...
users:
- name: myself@local
  user:
    password: passwordlocal
    username: user-local
- name: myself@remote
  user:
    password: passwordremote
    username: user-remote
```

# 设置新的集群

要设置一个新的集群，我们使用命令`kubectl config set-cluster <CLUSTER_NAME>`。需要额外的`--server`标志来指示访问集群。其他标志用于定义安全级别，例如`--insecure-skip-tls-verify`标志，它可以绕过对服务器证书的检查。如果您正在设置一个带有 HTTPS 的受信任服务器，您将需要使用`--certificate-authority=$PATH_OF_CERT --embed-certs=true`代替。要获取更多信息，请使用`-h`标志执行命令以获取更多信息。在接下来的命令中，我们在本地主机环境中设置了两个集群配置：

```
// in localhost cluster, create a cluster information pointing to itself
 $ kubectl config set-cluster local-cluster --insecure-skip-tls-verify=true --server=http://localhost:8080
 Cluster "local-cluster" set.
 // another cluster information is about the remote one
 $ kubectl config set-cluster remote-cluster --insecure-skip-tls-verify=true --server=http://$REMOTE_MASTER_NODE:8080
 Cluster "remote-cluster" set.
 // check kubeconfig in localhost cluster, in this example, the remote master node has the hostname "node01"
 $ kubectl config view
 apiVersion: v1
 clusters:
 ...
 - cluster:
     insecure-skip-tls-verify: true
     server: http://localhost:8080
   name: local-cluster
 - cluster:
     insecure-skip-tls-verify: true
     server: http://node01:8080
   name: remote-cluster
 ...
```

我们尚未将任何内容与**用户**和**集群**关联起来。我们将在下一节通过**上下文**将它们关联起来。

# 设置上下文并更改当前上下文

一个上下文包含一个集群、命名空间和用户。根据当前上下文，客户端将使用指定的*用户*信息和命名空间向集群发送请求。要设置上下文，我们将使用`kubectl config set-context <CONTEXT_NAME> --user=<CREDENTIAL_NAME> --namespace=<NAMESPACE> --cluster=<CLUSTER_NAME>`命令来创建或更新它：

```
// in localhost cluster, create a context for accessing local cluster's default namespace
$ kubectl config set-context default/local/myself --user=myself@local --namespace=default --cluster=local-cluster
Context "default/local/myself" created.
// furthermore, create another context for remote cluster
$ kubectl config set-context default/remote/myself --user=myself@remote --namespace=default --cluster=remote-cluster
Context "default/remote/myself" created.
```

让我们检查当前的 kubeconfig。我们可以找到两个新的上下文：

```
$ kubectl config view
...
contexts:
- context:
    cluster: local-cluster
    namespace: default
    user: myself@local
  name: default/local/myself
- context:
    cluster: remote-cluster
    namespace: default
    user: myself@remote
  name: default/remote/myself
...
```

创建上下文后，我们可以切换上下文以管理不同的集群。在这里，我们将使用`kubectl config use-context <CONTEXT_NAME>`命令：

```
// check current context
$ kubectl config current-context
kubernetes-admin@kubernetes

// use the new local context instead
$ kubectl config use-context default/local/myself
Switched to context "default/local/myself".
// check resource for the status of context
$ kubectl get pod
NAME                           READY     STATUS    RESTARTS   AGE
local-nginx-6484bbb57d-xpjp2   1/1       Running   0          2h
local-nginx-6484bbb57d-z4qgp   1/1       Running   0          2h
```

是的，看起来不错。如果我们切换到具有远程集群设置的上下文呢？

```
// switch to the context of remote cluster
$ kubectl config use-context default/remote/myself
Switched to context "default/remote/myself".
// check the pods
$ kubectl get pod
NAME                            READY     STATUS    RESTARTS   AGE
remote-nginx-5dd7b9cb7d-fxr9m   1/1       Running   0          2h
remote-nginx-5dd7b9cb7d-gj2ft   1/1       Running   0          2h
remote-nginx-5dd7b9cb7d-h7lmj   1/1       Running   0          2h
remote-nginx-5dd7b9cb7d-hz766   1/1       Running   0          2h
```

我们所做的所有操作都是在本地主机集群中进行的。kubeconfig 使得在多个集群上以多个用户的身份工作变得更加容易。

# 清理 kubeconfig

我们仍然可以利用`kubectl config`来删除 kubeconfig 中的配置。对于集群和上下文，您可以使用子命令`delete-cluster`和`delete-context`来删除被忽略的配置。或者，对于这三个类别，`unset`子命令可以完成删除：

```
// delete the customized local context
$ kubectl config delete-cluster local-cluster
deleted cluster local-cluster from $HOME/.kube/config

// unset the local user // to remove cluster, using property clusters.CLUSTER_NAME; to remove contexts, using property contexts.CONTEXT_NAME $ kubectl config unset users.myself@local
Property "users.myself@local" unset.
```

尽管前面的命令会立即应用于实时 kubeconfig，但更新另一个 kubeconfig 文件以进行替换的方式更快、更可靠。kubeconfig 文件是文本文件`new-kubeconfig`，我们刚刚更新的文件，或者我们从初始语句中复制的文件`original-kubeconfig`：

```
// remove all of our practices
$ cp ~/original-kubeconfig ~/.kube/config
// check your kubeconfig to make sure it has been cleaned
$ kubectl config view
```

# 还有更多...

正如我们在前一节中提到的，凭据和权限的实际用例不能被忽视，就像在我们的演示中穿越不安全的端点一样。为了避免安全问题，您可以在授予用户权限时查看官方文档（位于[`kubernetes.io/docs/admin/authentication/`](https://kubernetes.io/docs/admin/authentication/)）。

# 另请参阅

kubeconfig 管理集群、凭据和命名空间设置。查看以下完整概念的配方：

+   在第二章中的*使用秘密*配方，*深入了解 Kubernetes 概念*

+   在第二章中的*使用命名空间*配方，*深入了解 Kubernetes 概念*

# 在节点中设置资源

在任何基础设施中，计算资源管理都非常重要。我们应该很好地了解我们的应用程序，并保留足够的 CPU 和内存容量，以避免资源耗尽。在本节中，我们将介绍如何管理 Kubernetes 节点中的节点容量。此外，我们还将描述如何管理 Pod 计算资源。

Kubernetes 具有资源**服务质量**（**QoS**）的概念。它允许管理员优先考虑分配资源。根据 Pod 的设置，Kubernetes 将每个 Pod 分类为以下之一：

+   保证的 Pod

+   可突发的 Pod

+   最佳努力的 Pod

优先级为保证 > 可突发 > 最佳努力。例如，如果在同一 Kubernetes 节点中存在一个最佳努力的 Pod 和一个保证的 Pod，并且该节点遇到 CPU 问题或内存耗尽，Kubernetes 主节点将首先终止最佳努力的 Pod。让我们看看它是如何工作的。

# 准备就绪

有两种设置资源 QoS 的方法：pod 配置或命名空间配置。如果将资源 QoS 设置为命名空间，它将应用于属于同一命名空间的所有 pod。如果将资源 QoS 设置为 pod，它将仅应用于该 pod。此外，如果同时将其设置为命名空间和 pod，它将首先从命名空间配置中获取一个值，然后用 pod 配置覆盖它。因此，我们将设置两个命名空间，一个具有资源 QoS，另一个没有资源 QoS，以查看它们之间的不同：

1.  使用`kubectl`命令创建两个命名空间：

```
$ kubectl create namespace chap8-no-qos
namespace "chap8-no-qos" created

$ kubectl create namespace chap8-qos
namespace "chap8-qos" created
```

1.  准备一个 YAML 文件，设置`spec.limits.defaultRequest.cpu: 0.1`如下：

```
$ cat resource-request-cpu.yml
apiVersion: v1
kind: LimitRange
metadata:
  name: resource-request-cpu
spec:
  limits:
  - defaultRequest:
 cpu: 0.1
    type: Container
```

1.  通过输入`kubectl`命令，使其仅适用于`chap8-qos`命名空间：

```
$ kubectl create -f resource-request-cpu.yml --namespace=chap8-qos
limitrange "resource-request-cpu" created
```

1.  使用`kubectl`命令检查`chap8-qos`和`chap8-no-qos`上的资源限制：

```
//chap8-no-qos doesn't have any resource limits value
$ kubectl describe namespaces chap8-no-qos
Name:         chap8-no-qos
Labels:       <none>
Annotations:  <none>
Status:       Active
No resource quota.
No resource limits.

//chap8-qos namespace has a resource limits value
$ kubectl describe namespaces chap8-qos
Name:         chap8-qos
Labels:       <none>
Annotations:  <none>
Status:       Active
No resource quota.
Resource Limits
 Type       Resource  Min  Max  Default Request  Default Limit  Max Limit/Request Ratio
 ----       --------  ---  ---  ---------------  -------------  -----------------------
 Container  cpu       -    -    100m             -              -
```

# 如何做...

让我们逐步配置一个 BestEffort pod，一个 Guaranteed pod，然后是一个 Burstable pod。

# 配置一个 BestEffort pod

BestEffort pod 在资源 QoS 类中具有最低的优先级。因此，在资源短缺的情况下，Kubernetes 调度程序将终止此 BestEffort pod，然后将 CPU 和内存资源让给其他优先级更高的 pod。

为了将 pod 配置为 BestEffort，您需要将资源限制设置为`0`（显式），或者不指定资源限制（隐式）。

1.  准备一个 pod 配置，明确将`spec.containers.resources.limits`设置为`0`：

```
$ cat besteffort-explicit.yml
apiVersion: v1
kind: Pod
metadata:
  name: besteffort
spec:
  containers:
  - name: nginx
    image: nginx
    resources:
      limits:
 cpu: 0
 memory: 0
```

1.  在`chap8-qos`和`chap8-no-qos`命名空间上创建 pod：

```
$ kubectl create -f besteffort-explicit.yml --namespace=chap8-qos
pod "besteffort" created

$ kubectl create -f besteffort-explicit.yml --namespace=chap8-no-qos
pod "besteffort" created
```

1.  检查`QoS`类；两个 pod 都有`BestEffort`类：

```
$ kubectl describe pods besteffort --namespace=chap8-qos | grep QoS
QoS Class:       BestEffort

$ kubectl describe pods besteffort --namespace=chap8-no-qos | grep QoS
QoS Class:       BestEffort
```

有一个陷阱：如果在 pod 配置中没有设置任何资源设置，pod 将从命名空间的默认设置中获取一个值。因此，如果创建一个没有资源设置的 pod，在`chap8-qos`和`chap8-no-qos`之间的结果将会不同。以下示例演示了命名空间设置如何影响结果：

1.  从`chap8-qos`和`chap8-no-qos`命名空间中删除之前的 pod：

```
$ kubectl delete pod --all --namespace=chap8-qos
pod "besteffort" deleted

$ kubectl delete pod --all --namespace=chap8-no-qos
pod "besteffort" deleted
```

1.  准备一个没有资源设置的 pod 配置：

```
$ cat besteffort-implicit.yml
apiVersion: v1
kind: Pod
metadata:
  name: besteffort
spec:
  containers:
  - name: nginx
    image: nginx
```

1.  在两个命名空间上创建 pod：

```
$ kubectl create -f besteffort-implicit.yml --namespace=chap8-qos
pod "besteffort" created

$ kubectl create -f besteffort-implicit.yml --namespace=chap8-no-qos
pod "besteffort" created
```

1.  `QoS`类的结果是不同的：

```
$ kubectl describe pods besteffort --namespace=chap8-no-qos |grep QoS
QoS Class:       BestEffort

$ kubectl describe pods besteffort --namespace=chap8-qos |grep QoS
QoS Class:       Burstable
```

因为`chap8-qos`命名空间具有默认设置`request.cpu: 0.1`，这导致 pod 配置为`Burstable`类。因此，我们将使用`chap8-no-qos`命名空间，避免这种意外结果。

# 配置一个 Guaranteed pod

保证类具有资源`QoS`类的最高优先级。在资源短缺的情况下，Kubernetes 调度程序将尽量保留保证的 pod。

为了将 pod 配置为具有`保证`类，明确设置资源限制和资源请求为相同的值，或者只设置资源限制：

1.  准备一个 pod 配置，`resources.limit`和`resources.request`具有相同的值：

```
$ cat guaranteed.yml
apiVersion: v1
kind: Pod
metadata:
  name: guaranteed-pod
spec:
  containers:
  - name: nginx
    image: nginx
    resources:
      limits:
 cpu: 0.3
 memory: 350Mi
 requests:
 cpu: 0.3
 memory: 350Mi
```

1.  在`chap8-no-qos`命名空间上创建 pod：

```
$ kubectl create -f guaranteed.yml --namespace=chap8-no-qos
pod "guaranteed-pod" created
```

1.  检查`QoS`类；它有`保证`类：

```
$ kubectl describe pods guaranteed-pod --namespace=chap8-no-qos |grep QoS
QoS Class:       Guaranteed
```

# 配置一个可突发的 pod

可突发的 pod 的优先级高于 BestEffort，但低于 Guaranteed。为了将 pod 配置为可突发 Pod，您需要设置`resources.request`。`resources.limit`是可选的，但`resources.request`和`resources.limit`的值不能相等：

1.  准备一个只有`resources.request`的 pod 配置：

```
$ cat burstable.yml
apiVersion: v1
kind: Pod
metadata:
  name: burstable-pod
spec:
  containers:
  - name: nginx
    image: nginx
    resources:
      requests:
 cpu: 0.1
 memory: 10Mi
 limits:
 cpu: 0.5
 memory: 300Mi
```

1.  创建 pod：

```
$ kubectl create -f burstable.yml --namespace=chap8-no-qos
pod "burstable-pod" created
```

1.  检查`QoS`类；它是`可突发`：

```
$ kubectl describe pods burstable-pod --namespace=chap8-no-qos |grep QoS
QoS Class:       Burstable
```

# 工作原理...

让我们看看资源请求/限制如何影响资源管理。先前的可突发的 YAML 配置通过不同的阈值声明了请求和限制：

| **资源定义类型** | **资源名称** | **值** | **描述** |
| --- | --- | --- | --- |
| **请求** | CPU | 0.1 | 至少占用 1 个 CPU 核心的 10% |
| 内存 | 10Mi | 至少 10 兆字节的内存 |
| **限制** | CPU | 0.5 | 最大 1 个 CPU 核心的 50% |
| 内存 | 300Mi | 最大 300 兆字节的内存 |

对于 CPU 资源，可接受的值表达式要么是核心（0.1、0.2...1.0、2.0），要么是毫核（100 m、200 m...1000 m、2000 m）。1000 m 相当于 1.0 个核心。例如，如果 Kubernetes 节点有 2 个核心 CPU（或者 1 个带超线程的核心），则总共有 2.0 个核心或 2000 毫核，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/8ce2f36e-be54-4b02-8fa7-48e38ba68343.png)代表 2.0 个 CPU 资源

通过输入`kubectl describe node <node name>`，您可以检查节点上有哪些资源：

```
//Find a node name
$ kubectl get nodes
NAME       STATUS    ROLES     AGE       VERSION
minikube   Ready     <none>    22h       v1.9.0

//Specify node name 'minikube' 
$ kubectl describe nodes minikube
Name:               minikube
Roles:              <none>
Labels:             beta.kubernetes.io/arch=amd64
...
...
Allocatable:
 cpu:     2 memory:  1945652Ki pods:    110
```

这显示了节点`minikube`，它有 2.0 个 CPU 和大约 1945 MB 的内存。如果运行 nginx 示例（`requests.cpu: 0.1`），它至少占用 0.1 个核心，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/6dbfa34c-d9ef-4cd8-9d73-4026023fd281.png)请求 0.1 个 CPU 资源

只要 CPU 有足够的空间，它可以占用高达 0.5 个核心（`limits.cpu: 0.5`），如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/e4e58894-3e05-489c-903f-ebac4cb546de.png)它可能占用高达 0.5 个 CPU 资源

因此，如果将`requests.cpu`设置为大于 2.0，则该 pod 将不会分配给此节点，因为可分配的 CPU 为 2.0，而 nginx pod 已经占用了至少 0.1 个 CPU。

# 另请参阅

在本节中，您学会了如何通过设置资源请求和限制来配置资源 QoS。命名空间的默认值会影响生成的 pod 配置，因此您应该明确指定资源请求和限制。

请回顾以下章节，以复习如何配置命名空间：

+   *在第二章中的*使用命名空间*，*深入了解 Kubernetes 概念*

# 玩转 WebUI

Kubernetes 有一个 WebUI，可以可视化资源和机器的状态，并且还可以作为管理应用程序的附加界面，无需使用命令行。在这个示例中，我们将介绍 Kubernetes 仪表板。

# 准备就绪

Kubernetes 仪表板（[`github.com/kubernetes/dashboard`](https://github.com/kubernetes/dashboard)）就像一个服务器端应用程序。首先确保您有一个正常运行的 Kubernetes 集群，我们将在接下来的页面中进行安装和相关设置。由于仪表板将被浏览器访问，我们可以使用通过 minikube 引导的笔记本电脑运行的 Kubernetes 系统，并减少转发网络端口或设置防火墙规则的程序。

对于通过 minikube 引导的 Kubernetes 系统，请检查 minikube 和系统本身是否正常工作：

```
// check if minikube runs well
$ minikube status
minikube: Running
cluster: Running
kubectl: Correctly Configured: pointing to minikube-vm at 192.168.99.100
// check the Kubernetes system by components
$ kubectl get cs
NAME                 STATUS    MESSAGE              ERROR
scheduler            Healthy   ok
controller-manager   Healthy   ok
etcd-0               Healthy   {"health": "true"}
```

# 如何做...

在使用 minikube 引导 Kubernetes 系统时，默认情况下会创建仪表板。因此，我们将分别讨论这两种情况。

# 依赖于 minikube 创建的仪表板

因为 Kubernetes 仪表板已经启动，我们所要做的就是使用特定的 URL 打开 Web UI。这很方便；您只需在终端上输入一个命令：

```
$ minikube dashboard
Opening kubernetes dashboard in default browser...
```

然后，您将看到您喜爱的浏览器打开一个新的网页，就像我们在第一章中介绍的那样，*构建您自己的 Kubernetes 集群*。其 URL 将类似于[`MINIKUBE_VM_IP:30000/#!/overview?namespace=default`](http://MINIKUBE_VM_IP:30000/#!/overview?namespace=default)。最重要的是，我们绕过了预期的网络代理和身份验证程序。

# 手动在系统上使用其他引导工具创建仪表板

要运行 Kubernetes 仪表板，我们只需执行一个命令来应用一个配置文件，然后每个资源将自动创建：

```
$ kubectl create -f
https://raw.githubusercontent.com/kubernetes/dashboard/master/src/deploy/recommended/kubernetes-dashboard.yaml
secret "kubernetes-dashboard-certs" created
serviceaccount "kubernetes-dashboard" created
role "kubernetes-dashboard-minimal" created
rolebinding "kubernetes-dashboard-minimal" created
deployment "kubernetes-dashboard" created
service "kubernetes-dashboard" created
```

接下来，让我们使用命令`kubectl proxy`打开一个连接本地主机和 API 服务器的网关。然后，我们就可以通过浏览器访问仪表板了：

```
$ kubectl proxy
Starting to serve on 127.0.0.1:8001
```

一旦您看到类似于上述代码的停止结果，您现在可以通过 URL 访问仪表板：[`localhost:8001/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/`](http://localhost:8001/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/)。在那里，您将在浏览器中看到以下屏幕：

！[](assets/1b64d4fc-7349-4385-bf46-7877f2e3fc06.png)Kubernetes 仪表板的登录门户

为了快速进入我们的演示，我们将使用现有服务帐户的令牌进行登录。无论您使用什么引导工具，都可以在任何情况下利用仪表板创建的工具：

```
// check the service account in your system
$ kubectl get secret -n kube-system
NAME                               TYPE                                  DATA      AGE
default-token-7jfmd                kubernetes.io/service-account-token   3         51d
kubernetes-dashboard-certs         Opaque                                0         2d
kubernetes-dashboard-key-holder    Opaque                                2         51d
kubernetes-dashboard-token-jw42n   kubernetes.io/service-account-token   3         2d
// grabbing token by checking the detail information of the service account with prefix "kubernetes-dashboard-token-"
$ kubectl describe secret kubernetes-dashboard-token-jw42n -n kube-system
Name:         kubernetes-dashboard-token-jw42n
Namespace:    kube-system
Labels:       <none>
Annotations:  kubernetes.io/service-account.name=kubernetes-dashboard
              kubernetes.io/service-account.uid=253a1a8f-210b-11e8-b301-8230b6ac4959
Type:  kubernetes.io/service-account-token
Data
====
ca.crt:     1066 bytes
namespace:  11 bytes
token:     
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Ii....
```

复制令牌并粘贴到浏览器控制台中，然后点击“登录”：

！[](assets/fe682158-1db8-4f8a-8f62-041683a327a0.png)使用服务帐户的令牌进行身份验证

欢迎来到仪表板主页：

！[](assets/9319f189-19d4-40e2-a573-e10dd4ec8e91.png)Kubernetes 仪表板的主页

# 它是如何工作的...

Kubernetes 仪表板有两个主要功能：检查资源的状态和部署资源。它可以覆盖我们在客户端终端使用`kubectl`命令的大部分工作，但是图形界面更加友好。

# 通过仪表板浏览您的资源

我们可以在仪表板上检查硬件和软件资源。例如，要查看集群中的节点，请在左侧菜单的“集群”部分下点击“节点”；当前集群中的每个节点将显示在页面上，并附有一些基本信息：

！[](assets/9d2d70c8-65d3-4df0-aebb-133b8dda5fb4.png)仪表板上 Kubernetes 节点的状态

您屏幕上的结果可能与上述截图不同，因为它将基于您的环境。继续点击一个节点的名称；甚至会显示更多详细信息。其中一些以美丽的图表呈现：

！[](assets/b21650a8-65fe-4a70-91b4-40202faef84a.png)计算节点资源状态

展示软件资源，让我们来看看持有这个仪表板的资源。在左侧菜单中，将 Namespace 更改为 kube-system，并单击概述，这将汇总该 Namespace 下的所有资源。通过在单个页面上将资源放在一起并使用清晰的图表，很容易找出任何问题：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/11aa609b-d4d3-4783-87b8-57b89b183d4c.png)kube-system 命名空间的资源概述

还有更多；单击 kubernetes-dashboard 的部署，然后单击副本集中唯一 pod 右侧的小文本文件图标。您可以查看容器的日志：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/7a0b7ba5-205e-4995-b015-6208a8201d26.png)kubernetes-dashboard 的部署信息![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/19522040-4c1e-4172-8d41-472b089eb917.png)仪表板应用程序的日志

现在，我们已经看到 Kubernetes 仪表板提供了一个出色的界面，用于显示资源状态，包括节点、Kubernetes 工作负载和控制器，以及应用程序日志。

# 通过仪表板部署资源

在这里，我们将准备一个 YAML 配置文件，用于在新的 Namespace 下创建 Kubernetes 部署和相关服务。它将用于通过仪表板构建资源：

```
// the configuration file for creating Deployment and Service on new Namespace: dashboard-test
$ cat my-nginx.yaml
apiVersion: apps/v1beta2
kind: Deployment
metadata:
  name: my-nginx
  namespace: dashboard-test
spec:
  replicas: 3
  selector:
    matchLabels:
      run: demo
  template:
    metadata:
      labels:
        run: demo
    spec:
      containers:
      - name: my-container
        image: nginx
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: my-nginx
  namespace: dashboard-test
spec:
  ports:
    - protocol: TCP
      port: 80
  type: NodePort
  selector:
    run: demo
```

首先，单击网页右上角的 CREATE 按钮。

部署有三种方法。让我们选择第二种方法并上传先前介绍的配置文件。单击 UPLOAD 按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/68c65a6f-4f65-4b33-938f-092e0f640ffb.png)通过配置文件创建资源

不幸的是，发生了错误：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/e78630f7-bc05-4fae-a611-b9fe02e43992.png)由于错误部署而导致的问题的错误消息

仪表板根据左侧菜单上*用户*选择的 Namespace 显示资源。此错误消息弹出并告诉用户，文件中提到的 Namespace 与仪表板中的不匹配。我们需要做的是创建一个新的 Namespace 并切换到它。

这一次，我们将使用纯文本创建一个 Namespace。再次单击 CREATE 按钮，并选择从文本输入方法创建。将以下行粘贴到网页上以创建一个新的 Namespace：

```
apiVersion: v1
kind: Namespace
metadata:
  name: dashboard-test
```

现在，我们有一个新的 Namespace，`dashboard-test`。在仪表板上选择它作为主 Namespace，并再次提交`my-nginx.yaml`文件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/f458157c-6ead-44c7-b3e5-deaaf4022df2.png)在提交配置文件之前选择正确的 Namespace

现在您可以查看此部署的概述！黄色圆圈表示挂起状态。一旦 pod 准备就绪，它们将变为绿色，或者如果失败，它们将变为红色，但是如果您按照以下步骤操作，您将看不到红色的圆圈：

创建资源的状态图

# 通过仪表板删除资源

我们还可以通过仪表板删除 Kubernetes 资源。尝试自己找到我们刚刚创建的 Service `my-nginx`！执行以下操作：

+   在左侧菜单上更改 Namespace 为 dashboard-test

+   单击左侧菜单中的 Discovery and load balancing 部分下的 Services

+   单击超链接名称上的 Service my-nginx

+   单击页面右上角的 DELETE，位于 CREATE 按钮下方

就是这样！一旦您看到屏幕上弹出确认消息，只需单击即可。最后，您不仅创建了一个资源，还从 Kubernetes 仪表板中删除了它。

# 另请参阅

本教程介绍了如何启动一个 Web 界面，以便轻松地探索和管理 Kubernetes 实例，如 pod、部署和服务，而无需使用`kubectl`命令。请参考第二章中的以下教程，了解如何通过`kubectl`命令获取详细信息。

+   在第二章中的*使用 Pod*、*部署 API*和*使用服务*教程，深入了解 Kubernetes 概念

# 使用 RESTful API 进行操作

用户可以通过`kubectl`命令控制 Kubernetes 集群；它支持本地和远程执行。但是，一些管理员或操作员可能需要集成一个程序来控制 Kubernetes 集群。

Kubernetes 具有一个 RESTful API，通过 API 控制 Kubernetes 集群，类似于`kubectl`命令。让我们学习如何通过提交 API 请求来管理 Kubernetes 资源。

# 准备工作

在本教程中，为了绕过额外的网络设置和验证权限，我们将演示使用*minikube-*创建的集群与 Kubernetes 代理：在主机上轻松创建 Kubernetes 集群，并使用代理条目启用对 API 服务器的本地接近。

首先，运行代理以快速转发 API 请求：

```
//curl by API endpoint
$ kubectl proxy
Starting to serve on 127.0.0.1:8001
```

在使用 Kubernetes 代理工作一段时间后，您可能会发现`kubectl proxy`命令会在终端上停止，迫使您为后续命令打开一个新的通道，这有点让人讨厌。为了避免这种情况，只需在命令的最后一个参数中添加`&`。在 shell 中，这个`&`符号将使您的命令在后台运行：

```
$ kubectl proxy &
[1] 6372
Starting to serve on 127.0.0.1:8001
```

请注意，如果您不使用代理，应手动终止此进程：

```
$ kill -j9 6372
```

然后，尝试使用简单的路径`/api`来测试终端点：

```
$ curl http://127.0.0.1:8001/api
{
  "kind": "APIVersions",
  "versions": [
    "v1"
  ],
  "serverAddressByClientCIDRs": [
    {
      "clientCIDR": "0.0.0.0/0",
      "serverAddress": "10.0.2.15:8443"
    }
  ]
}
```

一旦您看到一些基本的 API 服务器信息显示在前面的代码中，恭喜！您现在可以使用 Kubernetes 的 Kubernetes RESTful API 进行操作。

**访问 Kubernetes API 服务器的安全方式**

但是，如果您考虑访问更安全的 API 服务器，比如 kubeadm 集群，则应注意以下事项：

+   API 服务器的终端点

+   用于身份验证的令牌

我们可以通过以下命令获取所需的信息。然后，您可以成功地请求版本的 API：

```
$ APISERVER=$(kubectl config view | grep server | cut -f 2- -d ":" | tr -d " ")
// get the token of default service account
$ TOKEN=$(kubectl get secret --field-selector type=kubernetes.io/service-account-token -o name | grep default-token- | head -n 1 | xargs kubectl get -o 'jsonpath={.data.token}' | base64 -d)
$ curl $APISERVER/api -H "Authorization: Bearer $TOKEN" --insecure
```

另一方面，当在 kubeadm 中访问资源时，您可能会看到显示“权限被拒绝”的消息。如果是这样，解决方案是将默认服务账户绑定到管理员角色，即 kubeadm 系统中的`cluster-admin`。我们在代码包中提供了配置文件`rbac.yaml`，如果需要，请查看：

```
$ curl $APISERVER/api/v1/namespaces/default/services -H "Authorization: Bearer $TOKEN" --insecure
...
 "status": "Failure",
 "message": "services is forbidden: User \"system:serviceaccount:default:default\" cannot list services in the namespace \"default\"",
 "reason": "Forbidden",
...
$ kubectl create -f rbac.yaml
clusterrolebinding "fabric8-rbac" created
// now the API request is successful
$ curl $APISERVER/api/v1/namespaces/default/services -H "Authorization: Bearer $TOKEN" --insecure
{
   "kind": "ServiceList",
   "apiVersion": "v1",
   "metadata": {
      "selfLink": "/api/v1/namespaces/default/services",
      "resourceVersion": "291954"
    },
...
```

小心使用`--insecure`标志，因为终端点使用 HTTPS 协议，而`-H`则添加带有令牌的标头。这些是与我们的天真演示设置相比的额外设置。

# 如何做到...

在本节中，我们将向您展示如何通过 RESTful API 管理资源。通常，`curl`的命令行模式将涵盖以下想法：

+   **操作**：`curl`没有指定操作将默认触发`GET`。要指定操作，请添加`X`标志。

+   **主体数据**：就像使用`kubectl`创建 Kubernetes 资源一样，我们使用`d`标志应用资源配置。带有`@`符号的值可以附加一个文件。此外，`h`标志有助于添加请求标头；在这里，我们需要以 JSON 格式添加内容类型。

+   **URL**：在终端点之后有各种路径，基于不同的功能。

让我们使用以下 JSON 配置文件创建一个部署：

```
$ cat nginx-deployment.json
{
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "metadata": {
    "name": "my-nginx"
  },
  "spec": {
    "replicas": 2,
       "selector": {
      "matchLabels": {
        "app": "nginx"
      }
    },
    "template": {
      "metadata": {
        "labels": {
          "app": "nginx"
        }
      },
      "spec": {
        "containers": [
          {
            "image": "nginx",
            "name": "my-nginx"
          }
        ]
      }
    }
  }
}
```

我们可以在 API 参考页面中找到每个功能（[`kubernetes.io/docs/reference/generated/kubernetes-api/v1.10/`](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.10/)）。这类似于在编写配置文件时搜索资源的配置。要提交 API 请求，您应该知道要处理哪种资源，以及要在其上执行什么操作。执行以下步骤在参考网页上找到相应的信息：

1.  选择一个资源。

1.  选择一个操作，例如读取或写入。

1.  选择操作的详细信息，例如创建或删除。

1.  信息将显示在网页的中间面板上。一个可选的步骤是在控制台右上角将`kubectl`切换到`curl`。更多细节，比如命令标志，将显示在右侧面板上。

要检查创建部署的信息，您的 Web 控制台可能看起来像这个屏幕截图一样：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/27576170-067f-4473-ad48-66beacb359aa.png)使用 API 创建部署的路径查找步骤

根据参考页面，我们可以组合一个指定的`curl`命令并立即发出请求：

```
$ curl -X POST -H "Content-type: application/json" -d @nginx-deployment.json http://localhost:8001/apis/apps/v1/namespaces/default/deployments
{
  "kind": "Deployment",
  "apiVersion": "apps/v1",
  "metadata": {
    "name": "my-nginx",
    "namespace": "default",
    "selfLink": "/apis/apps/v1/namespaces/default/deployments/my-nginx",
    "uid": "6eca324e-2cc8-11e8-806a-080027b04dc6",
    "resourceVersion": "209",
    "generation": 1,
    "creationTimestamp": "2018-03-21T05:26:39Z",
    "labels": {
      "app": "nginx"
    }
  },
...
```

对于成功的请求，服务器将返回资源的状态。继续检查是否可以通过`kubectl`命令找到新的部署：

```
$ kubectl get deployment
NAME       DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
my-nginx   2         2         2            2           1m
```

当然，也可以通过 RESTful API 进行检查：

```
// the operation "-X GET" can be ignored, since
$ curl -X GET http://localhost:8001/apis/apps/v1/namespaces/default/deployments
```

接下来，尝试删除这个新的 Deployment，`my-nginx`，这也是一种`写`操作：

```
$ curl -X DELETE http://localhost:8001/apis/apps/v1/namespaces/default/deployments/my-nginx
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {
  },
  "status": "Success",
  "details": {
    "name": "my-nginx",
    "group": "apps",
    "kind": "deployments",
    "uid": "386a3aaa-2d2d-11e8-9843-080027b04dc6"
  }
}
```

# 它是如何工作的...

RESTful API 允许 CRUD（创建、读取、更新和删除）操作，这是每个现代 Web 应用程序背后的相同概念。有关更多详细信息，请参阅[`en.wikipedia.org/wiki/Create,_read,_update_and_delete`](https://en.wikipedia.org/wiki/Create,_read,_update_and_delete)。

根据 CRUD 结构，Kubernetes RESTful API 具有以下基本方法：

| **操作** | **HTTP 方法** | **示例** |
| --- | --- | --- |
| 创建 | `POST` | `POST /api/v1/namespaces/default/pods` |
| 读取 | `GET` | `GET /api/v1/componentstatuses` |
| 更新 | `PUT` | `PUT /apis/apps/v1/namespaces/default/deployments/my-nginx` |
| 删除 | `DELETE` | `DELETE /api/v1/namespaces/default/services/nginx-service` |

正如我们在第三章的*使用配置文件*配方中提到的，Kubernetes 使用*swagger*（[`swagger.io/`](https://swagger.io)）和 OpenAPI（[`www.openapis.org`](https://www.openapis.org)）构建 RESTful API。我们可以打开集群的 swagger UI 控制台来检查 API 功能。然而，建议您通过官方网站进行检查，就像我们在上一节中演示的那样。网站上的描述更加详细和用户友好。

# 还有更多...

更加程序化的利用 Kubernetes API 的方法是使用客户端库（[`kubernetes.io/docs/reference/client-libraries/`](https://kubernetes.io/docs/reference/client-libraries/)）。充分利用这些客户端工具不仅可以节省资源管理时间，还可以产生稳健可靠的 CI/CD 环境。在这里，我们想介绍 Python 的 Kubernetes 客户端库：[`github.com/kubernetes-client/python`](https://github.com/kubernetes-client/python)。首先，您应该安装 Kubernetes 的 Python 库：

```
$ pip install kubernetes
```

然后，请将以下 Python 文件放在与 JSON 配置文件`nginx-deployment.json`相同的位置，其中在系统上运行`kubectl`有效：

```
$ cat create_deployment.py
from kubernetes import client, config
import json
config.load_kube_config()
resource_config = json.load(open("./nginx-deployment.json"))
api_instance = client.AppsV1Api()
response = api_instance.create_namespaced_deployment(body=resource_config, namespace="default")
print("success, status={}".format(response.status))
```

现在甚至不需要启用 Kubernetes 代理；继续直接运行此脚本，看看会发生什么：

```
$ python create_deployment.py
```

# 另请参阅

本文介绍了如何通过程序使用 Kubernetes RESTful API。将其与远程自动化程序集成非常重要。有关详细参数和安全增强，请参考以下配方：

+   第三章中的*使用配置文件*配方，*与容器一起玩*

+   第七章中的*身份验证和授权*配方，*在 GCP 上构建 Kubernetes*

# 使用 Kubernetes DNS

当您将许多 Pod 部署到 Kubernetes 集群时，服务发现是最重要的功能之一，因为 Pod 可能依赖于其他 Pod，但是当 Pod 重新启动时，其 IP 地址将发生变化。您需要一种灵活的方式来将 Pod 的 IP 地址传达给其他 Pod。Kubernetes 有一个名为`kube-dns`的附加功能，可以帮助解决这种情况。它可以为 Pod 和 Kubernetes 服务注册和查找 IP 地址。

在本节中，我们将探讨如何使用`kube-dns`，它为您提供了一种灵活的方式来配置 Kubernetes 集群中的 DNS。

# 准备工作

自 Kubernetes 版本 1.3 以来，`kube-dns`已经随 Kubernetes 一起提供，并且默认情况下已启用。要检查`kube-dns`是否工作，请使用以下命令检查`kube-system`命名空间：

```
$ kubectl get deploy kube-dns --namespace=kube-system NAME       DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE kube-dns   1         1         1            1           1d
```

如果您正在使用 minikube，请输入以下命令来查看插件的状态：

```
$ minikube addons list |grep kube-dns
- kube-dns: enabled
```

如果显示为禁用状态，则需要使用以下命令启用它：

```
$ minikube addons enable kube-dns
```

此外，准备两个命名空间`chap8-domain1`和`chap8-domain2`，以演示`kube-dns`如何分配域名：

```
$ kubectl create namespace chap8-domain1 namespace "chap8-domain1" created $ kubectl create namespace chap8-domain2 namespace "chap8-domain2" created //check chap8-domain1 and chap8-domain2 $ kubectl get namespaces NAME            STATUS    AGE chap8-domain1 Active    16s chap8-domain2 **Active    14s** default         Active    4h kube-public     Active    4h kube-system     Active    4h  
```

# 如何做...

`kube-dns`为 pod 和 Kubernetes 服务分配**完全** **限定域名**（**FQDN**）。让我们看看一些不同之处。

# pod 的 DNS

Kubernetes 为 pod 分配的域名为`<IP 地址>.<命名空间名称>.pod.cluster.local`。因为它使用了 pod 的 IP 地址，所以 FQDN 不能保证永久存在，但如果应用程序需要 FQDN，那么拥有它是很好的。

让我们在`chap8-domain1`和`chap8-domain2`上部署 apache2（`httpd`），如下所示：

```
$ kubectl run my-apache --image=httpd --namespace chap8-domain1 deployment "my-apache" created $ kubectl run my-apache --image=httpd --namespace chap8-domain2 deployment "my-apache" created
```

键入`kubectl get pod -o wide`以捕获这些 pod 的 IP 地址：

```
$ kubectl get pods -o wide --namespace=chap8-domain**1** NAME                         READY     STATUS    RESTARTS   AGE       IP           NODE my-apache-55fb679f49-qw58f   1/1       Running   0          27s        **172.17.0.4**   minikube   $ kubectl get pods -o wide --namespace=chap8-domain**2** NAME                         READY     STATUS    RESTARTS   AGE       IP           NODE my-apache-55fb679f49-z9gsr   1/1       Running   0          26s        **172.17.0.5**   minikube
```

这显示了`chap8-domain1`上的`my-apache-55fb679f49-qw58f`使用`172.17.0.4`。另一方面，`chap8-domain2`上的`my-apache-55fb679f49-z9gsr`使用`172.17.0.5`。

在这种情况下，FQDN 将是：

+   `172-17-0-4.chap8-domain1.pod.cluster.local` (`chap8-domain1`)

+   `172-17-0-5.chap8-domain2.pod.cluster.local` (`chap8-domain2`)

请注意，IP 地址中的点（`.`）被更改为连字符（`-`）。这是因为点是用来确定子域的分隔符。

要检查名称解析是否有效，请在前台启动`busybox` pod（使用`-it`选项）。然后使用`nslookup`命令来解析 FQDN 到 IP 地址，如下面的步骤所示：

1.  使用`-it`选项运行`busybox`：

```
$ kubectl run -it busybox --restart=Never --image=busybox
```

1.  在 busybox pod 中，键入`nslookup`来解析`chap8-domain1`上 apache 的 FQDN：

```
# nslookup 172-17-0-4.chap8-domain1.pod.cluster.local Server: 10.96.0.10 Address 1: 10.96.0.10 kube-dns.kube-system.svc.cluster.local Name: 172-17-0-4.chap8-domain1.pod.cluster.local Address 1: 172.17.0.4
```

1.  还要输入`nslookup`来解析`chap8-domain`2 上 apache 的 FQDN：

```
# nslookup 172-17-0-5.chap8-domain2.pod.cluster.local Server: 10.96.0.10 Address 1: 10.96.0.10 kube-dns.kube-system.svc.cluster.local Name: 172-17-0-5.chap8-domain2.pod.cluster.local Address 1: 172.17.0.5
```

1.  退出 busybox pod，然后删除它以释放资源：

```
# exit $ kubectl delete pod busybox pod "busybox" deleted
```

# Kubernetes 服务的 DNS

首先，从服务发现的角度来看，Kubernetes 服务的 DNS 是最重要的。这是因为应用程序通常连接到 Kubernetes 服务，而不是连接到 pod。这就是为什么应用程序更经常查找 Kubernetes 服务的 DNS 条目，而不是查找 pod 的原因。

其次，Kubernetes 服务的 DNS 条目将使用 Kubernetes 服务的名称而不是 IP 地址。例如，它看起来像这样：`<服务名称>.<命名空间名称>.svc.cluster.local`。

最后，Kubernetes 服务对 DNS 有两种不同的行为；普通服务或无头服务。普通服务有自己的 IP 地址，而无头服务使用 pod 的 IP 地址。让我们先了解普通服务。

普通服务是默认的 Kubernetes 服务。它将分配一个 IP 地址。执行以下步骤来创建一个普通服务并检查 DNS 的工作原理：

1.  为`chap8-domain1`和`chap8-domain2`上的 apache 创建一个普通服务：

```
$ kubectl expose deploy my-apache --namespace=chap8-domain1 --name=my-apache-svc --port=80 --type=ClusterIP service "my-apache-svc" exposed $ kubectl expose deploy my-apache --namespace=chap8-domain2 --name=my-apache-svc --port=80 --type=ClusterIP service "my-apache-svc" exposed
```

1.  通过运行以下命令检查这两个服务的 IP 地址：

```
$ kubectl get svc my-apache-svc --namespace=chap8-domain1 NAME            TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE my-apache-svc   ClusterIP   **10.96.117.206**   <none>        80/TCP    32s $ kubectl get svc my-apache-svc --namespace=chap8-domain2 NAME            TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)   AGE my-apache-svc   ClusterIP   **10.105.27.49**   <none>        80/TCP    49s
```

1.  为了进行名称解析，在前台使用 busybox pod：

```
$ kubectl run -it busybox --restart=Never --image=busybox 
```

1.  在 busybox pod 中，使用`nslookup`命令查询这两个服务的 IP 地址：

```
//query Normal Service on chap8-domain1
# nslookup my-apache-svc.chap8-domain1.svc.cluster.local Server: 10.96.0.10 Address 1: 10.96.0.10 kube-dns.kube-system.svc.cluster.local  Name: my-apache-svc.chap8-domain1.svc.cluster.local Address 1: 10.96.117.206 my-apache-svc.chap8-domain1.svc.cluster.local

//query Normal Service on chap8-domain2 # nslookup my-apache-svc.chap8-domain2.svc.cluster.local Server: 10.96.0.10 Address 1: 10.96.0.10 kube-dns.kube-system.svc.cluster.local  Name: my-apache-svc.chap8-domain2.svc.cluster.local Address 1: 10.105.27.49 my-apache-svc.chap8-domain2.svc.cluster.local
```

1.  访问 apache 服务以查看流量是否可以分发到后端 apache pod：

```
# wget -q -O - my-apache-svc.chap8-domain1.svc.cluster.local <html><body><h1>It works!</h1></body></html> # wget -q -O - my-apache-svc.chap8-domain2.svc.cluster.local <html><body><h1>It works!</h1></body></html>
```

1.  退出`busybox` pod 并删除它：

```
# exit  $ kubectl delete pod busybox pod "busybox" deleted
```

DNS 对于普通服务的行为类似于代理；流量会先到达普通服务，然后再分发到 pod。那么无头服务呢？这将在*它是如何工作的...*部分进行讨论。

# StatefulSet 的 DNS

StatefulSet 在第三章中有描述，*与容器一起玩耍*。它为 pod 名称分配一个序列号，例如，`my-nginx-0`，`my-nginx-1`，`my-nginx-2`。StatefulSet 还使用这些 pod 名称来分配 DNS 条目，而不是 IP 地址。因为它使用 Kubernetes 服务，FQDN 看起来如下：`<StatefulSet 名称>-<序列号>.<服务名称>.<命名空间名称>.svc.cluster.local`。

让我们创建 StatefulSet 来检查 StatefulSet 中 DNS 是如何工作的：

1.  准备 StatefulSet 和普通服务的 YAML 配置如下：

```
$ cat nginx-sts.yaml apiVersion: v1 kind: Service metadata:
 name: nginx-sts-svc labels: app: nginx-sts spec:
 ports: - port: 80 selector: app: nginx-sts ---
apiVersion: apps/v1beta1 kind: StatefulSet metadata:
 name: nginx-sts spec:
 serviceName: "nginx-sts-svc" replicas: 3 template: metadata: labels: app: nginx-sts spec: containers: - name: nginx-sts image: nginx ports: - containerPort: 80 restartPolicy: Always
```

1.  在`chap8-domain2`上创建 StatefulSet：

```
$ kubectl create -f nginx-sts.yaml --namespace=chap8-domain2 service "nginx-sts-svc" created
statefulset "nginx-sts" created
```

1.  使用`kubectl`命令检查 pod 和服务创建的状态：

```
//check StatefulSet (in short sts)
$ kubectl get sts --namespace=chap8-domain2 NAME        DESIRED   CURRENT   AGE nginx-sts   3         3         46s  //check Service (in short svc) $ kubectl get svc nginx-sts-svc --namespace=chap8-domain2 NAME            TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE nginx-sts-svc   ClusterIP   **10.104.63.124**   <none>        80/TCP    8m  //check Pod with "-o wide" to show an IP address
$ kubectl get pods --namespace=chap8-domain2 -o wide NAME                         READY     STATUS    RESTARTS   AGE       IP            NODE my-apache-55fb679f49-z9gsr   1/1       Running   1          22h       172.17.0.4    minikube nginx-sts-0                  1/1       Running   0          2m        **172.17.0.2**    minikube nginx-sts-1                  1/1       Running   0          2m        **172.17.0.9**    minikube nginx-sts-2                  1/1       Running   0          1m        **172.17.0.10**   minikube
```

1.  在前台启动`busybox` pod：

```
$ kubectl run -it busybox --restart=Never --image=busybox 
```

1.  使用`nslookup`命令查询服务的 IP 地址：

```
# nslookup nginx-sts-svc.chap8-domain2.svc.cluster.local Server:    10.96.0.10 Address 1: 10.96.0.10 kube-dns.kube-system.svc.cluster.local  Name:      nginx-sts-svc.chap8-domain2.svc.cluster.local Address 1: **10.104.63.124** nginx-sts-svc.chap8-domain2.svc.cluster.local
```

1.  使用`nslookup`命令查询单个 pod 的 IP 地址：

```
# nslookup nginx-sts-0.nginx-sts-svc.chap8-domain2.svc.cluster.local Server:    10.96.0.10 Address 1: 10.96.0.10 kube-dns.kube-system.svc.cluster.local Name:      nginx-sts-0.nginx-sts-svc.chap8-domain2.svc.cluster.local Address 1: **172.17.0.2** nginx-sts-0.nginx-sts-svc.chap8-domain2.svc.cluster.local # nslookup nginx-sts-1.nginx-sts-svc.chap8-domain2.svc.cluster.local Server:    10.96.0.10 Address 1: 10.96.0.10 kube-dns.kube-system.svc.cluster.local Name:      nginx-sts-1.nginx-sts-svc.chap8-domain2.svc.cluster.local Address 1: **172.17.0.9** nginx-sts-1.nginx-sts-svc.chap8-domain2.svc.cluster.local # nslookup nginx-sts-2.nginx-sts-svc.chap8-domain2.svc.cluster.local Server:    10.96.0.10 Address 1: 10.96.0.10 kube-dns.kube-system.svc.cluster.local Name:      nginx-sts-2.nginx-sts-svc.chap8-domain2.svc.cluster.local Address 1: **172.17.0.10** nginx-sts-2.nginx-sts-svc.chap8-domain2.svc.cluster.local
```

1.  清理`busybox` pod：

```
# exit $ kubectl delete pod busybox pod "busybox" deleted
```

# 它是如何工作的...

我们已经设置了几个组件来查看最初如何创建 DNS 条目。Kubernetes 服务名称对于确定 DNS 的名称尤为重要。

然而，Kubernetes 服务有两种模式，即普通服务或无头服务。普通服务已在前一节中描述过；它有自己的 IP 地址。另一方面，无头服务没有 IP 地址。

让我们看看如何创建一个无头服务以及名称解析是如何工作的：

1.  为`chap8-domain1`和`chap8-domain2`上的 apache 创建一个无头服务（指定`--cluster-ip=None`）：

```
$ kubectl expose deploy my-apache --namespace=chap8-domain1 --name=my-apache-svc-hl --port=80 --type=ClusterIP **--cluster-ip=None** service "my-apache-svc-hl" exposed $ kubectl expose deploy my-apache --namespace=chap8-domain2 --name=my-apache-svc-hl --port=80 --type=ClusterIP **--cluster-ip=None** service "my-apache-svc-hl" exposed
```

1.  使用以下命令检查这两个无头服务是否没有 IP 地址：

```
$ kubectl get svc my-apache-svc-hl --namespace=chap8-domain1 NAME               TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE my-apache-svc-hl   ClusterIP   **None**         <none>        80/TCP    13m $ kubectl get svc my-apache-svc-hl --namespace=chap8-domain2 NAME               TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE my-apache-svc-hl   ClusterIP   **None**         <none>        80/TCP    13m
```

1.  在前台启动`busybox` pod：

```
$ kubectl run -it busybox --restart=Never --image=busybox 
```

1.  在`busybox` pod 中，查询这两个服务。它必须显示地址作为 pod 的地址（`172.168.0.4`和`172.168.0.5`）：

```
# nslookup my-apache-svc-hl.chap8-domain1.svc.cluster.local Server: 10.96.0.10 Address 1: 10.96.0.10 kube-dns.kube-system.svc.cluster.local Name: my-apache-svc-hl.chap8-domain1.svc.cluster.local Address 1: 172.17.0.4 # nslookup my-apache-svc-hl.chap8-domain2.svc.cluster.local Server: 10.96.0.10 Address 1: 10.96.0.10 kube-dns.kube-system.svc.cluster.local  Name: my-apache-svc-hl.chap8-domain2.svc.cluster.local Address 1: 172.17.0.5 
```

1.  退出`busybox` pod 并删除它：

```
# exit $ kubectl delete pod busybox pod "busybox" deleted
```

# 无头服务在 pod 扩展时

前面的示例只显示一个 IP 地址，因为我们只设置了一个 Pod。如果使用`kubectl scale`命令增加一个实例会发生什么？

让我们将`chap8-domain1`上的 Apache 实例数量从 1 增加到 3，然后看看无头服务 DNS 是如何工作的：

```
//specify --replicas=3 
$ kubectl scale deploy my-apache --namespace=chap8-domain1 --replicas=3 deployment "my-apache" scaled  //Now there are 3 Apache Pods $ kubectl get pods --namespace=chap8-domain1 -o wide NAME                         READY     STATUS    RESTARTS   AGE       IP           NODE my-apache-55fb679f49-c8wg7   1/1       Running   0          1m        **172.17.0.7**   minikube my-apache-55fb679f49-cgnj8   1/1       Running   0          1m        **172.17.0.8**   minikube my-apache-55fb679f49-qw58f   1/1       Running   0          8h       **172.17.0.4**   minikube

//launch busybox to run nslookup command $ kubectl run -it busybox --restart=Never --image=busybox  //query Headless service name # nslookup my-apache-svc-hl.chap8-domain1.svc.cluster.local Server: 10.96.0.10 Address 1: 10.96.0.10 kube-dns.kube-system.svc.cluster.local Name: my-apache-svc-hl.chap8-domain1.svc.cluster.local Address 1: **172.17.0.4** Address 2: **172.17.0.7** Address 3: **172.17.0.8**  //quit busybox and release it
# exit $ kubectl delete pod busybox  pod "busybox" deleted
```

结果很简单：一个 DNS 条目，`my-apache-svc-hl.chap8-domain1.svc.cluster.local`返回 3 个 IP 地址。因此，当您的 HTTP 客户端尝试访问 Kubernetes 服务`my-apache-svc-hl.chap8-domain1.svc.cluster.local`时，它会从`kube-dns`获取这 3 个 IP 地址，然后直接访问其中一个，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/f93148d8-eea0-4c05-bc39-49c50ef4edcf.png)访问无头服务和 pod 的顺序

因此，Kubernetes 无头服务不进行任何流量分发。这就是为什么它被称为无头的。

# 另请参阅

本节描述了`kube-dns`如何在 DNS 中为 pod 和服务命名。了解普通服务和无头服务之间的区别对于理解如何连接到您的应用程序非常重要。下一节还描述了 StatefulSet 的用例：

+   *在第三章中*，*确保容器的灵活使用*，*玩转容器*

# 身份验证和授权

对于 Kubernetes 这样的平台，身份验证和授权都至关重要。身份验证确保用户是他们声称的那个人。授权验证用户是否有足够的权限执行某些操作。Kubernetes 支持各种身份验证和授权插件。

# 准备就绪

当请求到达 API 服务器时，首先通过验证客户端的证书与 API 服务器中的**证书颁发机构**（**CA**）建立 TLS 连接。API 服务器中的 CA 通常位于`/etc/kubernetes/`，客户端的证书通常位于`$HOME/.kube/config`。握手完成后，进入认证阶段。在 Kubernetes 中，认证模块是基于链的。我们可以使用多个认证模块。当请求到来时，Kubernetes 将依次尝试所有认证器，直到成功。如果请求在所有认证模块上失败，将被拒绝为 HTTP 401 未经授权。否则，其中一个认证器将验证用户的身份，并对请求进行认证。然后，Kubernetes 授权模块开始发挥作用。它们验证*用户*是否有权限执行他们请求的操作，使用一组策略。授权模块逐一检查。就像认证模块一样，如果所有模块都失败，请求将被拒绝。如果用户有资格发出请求，请求将通过认证和授权模块，并进入准入控制模块。请求将逐一通过各种准入控制器进行检查。如果任何准入控制器拒绝请求，请求将立即被拒绝。

以下图表演示了这个顺序：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/34ebdbc5-c58c-44cb-af44-76c75ee70733.png)通过 Kubernetes API 服务器传递的请求

# 如何做...

在 Kubernetes 中，有两种类型的账户；服务账户和用户账户。它们之间的主要区别在于用户账户不存储和管理在 Kubernetes 本身。它们不能通过 API 调用添加。以下表格是一个简单的比较：

|  | **服务账户** | **用户账户** |
| --- | --- | --- |
| **范围** | 命名空间 | 全局 |
| **被使用** | 进程 | 普通用户 |
| **由谁创建** | API 服务器或通过 API 调用 | 管理员，不能通过 API 调用添加 |
| **由谁管理** | API 服务器 | 集群外部 |

服务账户用于 Pod 内的进程与 API 服务器联系。Kubernetes 默认会创建一个名为**default**的服务账户。如果一个 Pod 没有与服务账户关联，它将被分配给默认服务账户：

```
// check default service accoun
# kubectl describe serviceaccount default
Name:                default
Namespace:           default
Labels:              <none>
Annotations:         <none>
Image pull secrets:  <none>
Mountable secrets:   default-token-q4qdh
Tokens:              default-token-q4qdh
Events:              <none>
```

我们可能会发现与此服务帐户关联的一个 Secret。这由令牌控制器管理。当创建新的服务帐户时，控制器将创建一个令牌，并使用`kubernetes.io/service-account.name`注释将其与服务帐户关联，从而允许 API 访问。在 Kubernetes 中，令牌以 Secret 格式存在。拥有 Secret 查看权限的任何人都可以看到令牌。以下是创建服务帐户的示例：

```
// configuration file of a ServiceAccount named chapter8-serviceaccount
# cat serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: chapter8-serviceaccount
// create service account
# kubectl create -f serviceaccount.yaml
serviceaccount "chapter8-serviceaccount" created
// describe the service account we just created
# kubectl describe serviceaccount chapter8-serviceaccount
Name:                chapter8-serviceaccount
Namespace:           default
Labels:              <none>
Annotations:         <none>
Image pull secrets:  <none>
Mountable secrets:   chapter8-serviceaccount-token-nxh47
Tokens:              chapter8-serviceaccount-token-nxh47
Events:              <none>
```

# 认证

Kuberentes 支持几种帐户认证策略，从客户端证书、持有者令牌和静态文件到 OpenID 连接令牌。可以选择多个选项，并与其他认证链组合使用。在本教程中，我们将介绍如何使用令牌、客户端证书和 OpenID 连接令牌进行认证。

# 服务帐户令牌认证

在上一节中，我们创建了一个服务帐户；现在，让我们看看如何使用服务帐户令牌进行认证。我们首先需要检索令牌：

```
// check the details of the secret
# kubectl get secret chapter8-serviceaccount-token-nxh47 -o yaml
apiVersion: v1
data:
  ca.crt: <base64 encoded>
  namespace: ZGVmYXVsdA==
  token: <bearer token, base64 encoded>
kind: Secret
metadata:
  annotations:
    kubernetes.io/service-account.name: chapter8-serviceaccount
    name: chapter8-serviceaccount-token-nxh47
  namespace: default
  ...
type: kubernetes.io/service-account-token
```

我们可以看到数据下的三个项目都是 base64 编码的。我们可以在 Linux 中使用`echo "encoded content" | base64 --decode`命令轻松解码它们。例如，我们可以解码编码的命名空间内容：

```
# echo "ZGVmYXVsdA==" | base64 --decode 
default 
```

使用相同的命令，我们可以获取令牌并在请求中使用它。API 服务器期望在请求中使用`Authorization: Bearer $TOKEN`的 HTTP 头。以下是如何使用令牌进行身份验证并直接向 API 服务器发出请求的示例。

首先，我们需要获取我们解码后的令牌：

```
// get the decoded token from secret chapter8-serviceaccount-token-nxh47 
# TOKEN=`echo "<bearer token, base64 encoded>" | base64 --decode` 
```

其次，我们还需要解码`ca.crt`：

```
// get the decoded ca.crt from secret chapter8-serviceaccount-token-nxh47 
# echo "<ca.crt, base64 encoded>" | base64 --decode > cert 
```

接下来，我们需要知道 API 服务器是什么。使用`kubectl config view`命令，我们可以得到服务器列表：

```
# kubectl config view
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: REDACTED
    server: https://api.demo-k8s.net
  name: demo-k8s.net
- cluster:
    certificate-authority: /Users/chloelee/.minikube/ca.crt
    server: https://192.168.99.100:8443
  name: minikube
...
```

找到您当前正在使用的。在这个例子中，我们正在使用 minikube。服务器位于`https://192.168.99.100:8443`。

您可以使用`kubectl config current-context`命令找到当前上下文。

然后我们应该可以开始了！我们将通过`https://$APISERVER/api`直接请求 API 端点，使用`--cacert`和`--header`。

```
# curl --cacert cert https://192.168.99.100:8443/api --header "Authorization: Bearer $TOKEN"
{
  "kind": "APIVersions",
  "versions": [
    "v1"
  ],
  "serverAddressByClientCIDRs": [
    {
      "clientCIDR": "0.0.0.0/0",
      "serverAddress": "10.0.2.15:8443"
    }
  ]
}
```

我们可以看到可用版本是`v1`。让我们看看在`/api/v1`端点中有什么：

```
# curl --cacert cert https://192.168.99.100:8443/api/v1 --header "Authorization: Bearer $TOKEN"
{
  "kind": "APIResourceList",
  "groupVersion": "v1",
  "resources": [
   ...
   {
      "name": "configmaps",
      "singularName": "",
      "namespaced": true,
      "kind": "ConfigMap",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],      
      "shortNames": ["cm"]
    }
  ],  ...
}
```

它将列出我们请求的所有端点和动词。让我们以`configmaps`为例，并使用`grep`命令查找名称：

```
# curl --cacert cert https://192.168.99.100:8443/api/v1/configmaps --header "Authorization: Bearer $TOKEN" |grep \"name\"
        "name": "extension-apiserver-authentication",
        "name": "ingress-controller-leader-nginx",
        "name": "kube-dns",
        "name": "nginx-load-balancer-conf",
```

在这个例子中，我的集群中列出了四个默认的 configmaps。我们可以使用`kubectl`来验证这一点。结果应该与我们之前得到的相匹配：

```
# kubectl get configmaps --all-namespaces
NAMESPACE     NAME                                 DATA      AGE
kube-system   extension-apiserver-authentication   6         6d
kube-system   ingress-controller-leader-nginx      0         6d
kube-system   kube-dns                             0         6d
kube-system   nginx-load-balancer-conf             1         6d
```

# X509 客户端证书

用户帐户的常见身份验证策略是使用客户端证书。在下面的示例中，我们将创建一个名为琳达的用户，并为她生成一个客户端证书：

```
// generate a private key for Linda
# openssl genrsa -out linda.key 2048
Generating RSA private key, 2048 bit long modulus
..............+++
..............+++
e is 65537 (0x10001)
// generate a certificate sign request (.csr) for Linda. Make sure /CN is equal to the username.
# openssl req -new -key linda.key -out linda.csr -subj "/CN=linda"
```

接下来，我们将通过私钥和签名请求文件为琳达生成一个证书，以及我们集群的 CA 和私钥：

在 minikube 中，它位于`~/.minikube/`。对于其他自托管解决方案，通常位于`/etc/kubernetes/`下。如果您使用`kops`部署集群，则位置位于`/srv/kubernetes`下，您可以在`/etc/kubernetes/manifests/kube-apiserver.manifest`文件中找到路径。

```
// generate a cert
# openssl x509 -req -in linda.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out linda.crt -days 30
Signature ok
subject=/CN=linda
Getting CA Private Key
```

我们已经用我们集群证书签署了琳达；现在我们可以将其设置到我们的`kubeconfig`文件中：

```
# kubectl config set-credentials linda --client-certificate=linda.crt --client-key=linda.key 
User "linda" set. 
```

我们可以使用`kubectl config view`来验证用户是否已设置：

```
# kubectl config view
current-context: minikube
kind: Config
users:
  - name: linda
  user:
    client-certificate: /k8s-cookbooks-2e/ch8/linda.crt
    client-key: /k8s-cookbooks-2e/ch8/linda.key
...
```

创建用户后，我们可以创建一个上下文，将命名空间和集群与该用户关联起来：

```
# kubectl config set-context linda-context --cluster=minikube --user=linda
```

之后，Kubernetes 应该能够识别琳达并将其传递到授权阶段。

# OpenID 连接令牌

另一种流行的身份验证策略是 OpenID 连接令牌。将身份验证委托给 OAuth2 提供程序是管理用户的一种便利方式。要启用该功能，必须将两个必需的标志设置为 API 服务器：`--oidc-issuer-url`，它指示发行者 URL，允许 API 服务器发现公共签名密钥，以及`--oidc-client-id`，它是要与发行者关联的应用程序的客户端 ID。有关完整信息，请参阅官方文档[`kubernetes.io/docs/admin/authentication/#configuring-the-api-server`](https://kubernetes.io/docs/admin/authentication/#configuring-the-api-server)。以下是我们如何在 minikube 集群中设置 Google OpenID 身份验证的示例。以下步骤可以轻松地用于身份验证用途。

首先，我们将不得不从 Google 请求一组由客户端 ID、客户端密钥和重定向 URL 组成的集合。以下是从 Google 请求和下载密钥的步骤：

1.  在 GCP 控制台中，转到 API 和服务|凭据|创建凭据|OAuth 客户端 ID。

1.  在应用程序类型中选择其他，然后单击创建。

1.  下载 JSON 文件。

之后，凭据已成功创建。我们可以查看 JSON 文件。以下是我们从示例项目 kubernetes-cookbook 中获得的文件：

```
# cat client_secret_140285873781-f9h7d7bmi6ec1qa0892mk52t3o874j5d.apps.googleusercontent.com.json
{
    "installed":{
        "client_id":"140285873781
f9h7d7bmi6ec1qa0892mk52t3o874j5d.apps.googleusercontent.com",
        "project_id":"kubernetes-cookbook",
        "auth_uri":"https://accounts.google.com/o/oauth2/auth",
        "token_uri":"https://accounts.google.com/o/oauth2/token",
        "auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs",
        "client_secret":"Ez0m1L7436mlJQErhalp3Gda",
        "redirect_uris":[
            "urn:ietf:wg:oauth:2.0:oob",
            "http://localhost"
        ]
    }
}
```

现在，我们应该能够启动我们的集群。不要忘记必须传递 OIDC 标志。在 minikube 中，可以通过`--extra-config`参数来完成：

```
// start minikube cluster and passing oidc parameters. 
# minikube start --extra-config=apiserver.Authorization.Mode=RBAC --extra-config=apiserver.Authentication.OIDC.IssuerURL=https://accounts.google.com --extra-config=apiserver.Authentication.OIDC.UsernameClaim=email --extra-config=apiserver.Authentication.OIDC.ClientID="140285873781-f9h7d7bmi6ec1qa0892mk52t3o874j5d.apps.googleusercontent.com" 
```

集群启动后，用户必须登录到身份提供者以获取`access_token`、`id_token`和`refresh_token`。在 Google 中，登录后您将获得一个代码，然后将代码与请求一起传递以获取令牌。然后，我们通过 kubectl 将令牌传递给 API 服务器的请求。以下是此过程的顺序图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/d0012bfc-9d77-400a-9ba7-1ff5acc5f21c.png)Google OpenID 连接身份验证的时间图

要请求代码，您的应用程序应以以下格式发送 HTTP 请求：

```
// https://accounts.google.com/o/oauth2/v2/auth?client_id=<client_id>&response_type=code&scope=openid%20email&redirect_uri=urn:ietf:wg:oauth:2.0:oob
# https://accounts.google.com/o/oauth2/v2/auth?client_id=140285873781-f9h7d7bmi6ec1qa0892mk52t3o874j5d.apps.googleusercontent.com&response_type=code&scope=openid%20email&redirect_uri=urn:ietf:wg:oauth:2.0:oob
```

然后，一个浏览器窗口将弹出要求登录到 Google。登录后，代码将显示在控制台中：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cb-2e/img/d7a66cd3-ece7-4f59-b157-7f5c33543105.png)

接下来，我们传递请求令牌的代码到`https://www.googleapis.com/oauth2/v4/token`。然后，我们应该能够从响应中获取`access_token`、`refresh_token`和`id_token`：

```
// curl -d "grant_type=authorization_code&client_id=<client_id>&client_secret=<client_secret>&redirect_uri=urn:ietf:wg:oauth:2.0:oob&code=<code>" -X POST https://www.googleapis.com/oauth2/v4/token
# curl -d "grant_type=authorization_code&client_id=140285873781-f9h7d7bmi6ec1qa0892mk52t3o874j5d.apps.googleusercontent.com&client_secret=Ez0m1L7436mlJQErhalp3Gda&redirect_uri=urn:ietf:wg:oauth:2.0:oob&code=4/AAAd5nqWFkpKmxo0b_HZGlcAh57zbJzggKmoOG0BH9gJhfgvQK0iu9w" -X POST https://www.googleapis.com/oauth2/v4/token
{
 "access_token": "ya29.GluJBQIhJy34vqJl7V6lPF9YSXmKauvvctjUJHwx72gKDDJikiKzQed9iUnmqEv8gLYg43H6zTSYn1qohkNce1Q3fMl6wbrGMCuXfRlipTcPtZnFt1jNalqMMTCm",
 "token_type": "Bearer",
 "expires_in": 3600,
 "refresh_token": "1/72xFflvdTRdqhjn70Bcar3qyWDiFw-8KoNm6LdFPorQ",
 "id_token": "eyJhbGc...mapQ"
}
```

假设我们将用户`chloe-k8scookbook@gmail.com`与此 Google 帐户关联。让我们在我们的集群中创建它。我们可以将用户信息附加到我们的 kubeconfig 中。文件的默认位置是`$HOME/.kube/config`：

```
// append to kubeconfig file.
- name: chloe-k8scookbook@gmail.com
  user:
    auth-provider:
      config:
        client-id: 140285873781-f9h7d7bmi6ec1qa0892mk52t3o874j5d.apps.googleusercontent.com
        client-secret: Ez0m1L7436mlJQErhalp3Gda
        id-token: eyJhbGc...mapQ
        idp-issuer-url: https://accounts.google.com
        refresh-token: 1/72xFflvdTRdqhjn70Bcar3qyWDiFw-8KoNm6LdFPorQ
      name: oidc
```

之后，让我们使用用户列出节点并查看是否可以通过身份验证：

```
# kubectl --user=chloe-k8scookbook@gmail.com get nodes 
Error from server (Forbidden): nodes is forbidden: User "chloe-k8scookbook@gmail.com" cannot list nodes at the cluster scope 
```

我们遇到了授权错误！在验证身份后，下一步将是检查用户是否有足够的权限来执行请求。

# 授权

经过身份验证阶段后，授权者开始工作。在我们继续讨论授权策略之前，让我们先谈谈`Role`和`RoleBinding`。

# Role 和 RoleBinding

Kubernetes 中的`Role`包含一组规则。规则通过指定`apiGroups`、`resources`和`verbs`来定义某些操作和资源的权限集。例如，以下角色定义了对`configmaps`的只读规则：

```
# cat role.yaml
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: configmap-ro
rules:
  - apiGroups: ["*"]
    resources: ["configmaps"]
    verbs: ["watch", "get", "list"]
```

`RoleBinding`用于将角色与帐户列表关联。以下示例显示我们将`configmap-ro`角色分配给一组主体。在这种情况下，只有用户`linda`：

```
# cat rolebinding.yaml
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: devops-role-binding
subjects:
- apiGroup: ""
  kind: User
  name: linda
roleRef:
  apiGroup: ""
  kind: Role
  name: configmap-ro
```

`Role`和`RoleBinding`是有命名空间的。它们的范围仅限于单个命名空间。要访问`整个集群`资源，我们需要`ClusterRole`和`ClusterRoleBinding`。

要将命名空间添加到`Role`或`RoleBinding`中，只需在配置文件的元数据中添加一个命名空间字段。

# ClusterRole 和 ClusterRoleBinding

`ClusterRole`和`ClusterRoleBinding`基本上类似于`Role`和`RoleBinding`。与`Role`和`RoleBinding`仅限于单个命名空间的方式不同，`ClusterRole`和`ClusterRoleBinding`用于授予整个集群范围的资源。因此，可以将对所有命名空间、非命名空间资源和非资源端点的访问授予`ClusterRole`，并且我们可以使用`ClusterRoleBinding`将用户和角色绑定。

我们还可以将服务账户与`ClusterRole`绑定。由于服务账户是有命名空间的，我们必须指定其完整名称，其中包括它所在的命名空间：

```
system:serviceaccount:<namespace>:<serviceaccountname>
```

以下是`ClusterRole`和`ClusterRoleBinding`的示例。在此角色中，我们授予了许多资源的所有操作权限，例如`deployments`、`replicasets`、`ingresses`、`pods`和`services`，并且我们将命名空间和事件的权限限制为只读：

```
# cat serviceaccount_clusterrole.yaml
apiVersion: rbac.authorization.k8s.io/v1
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
  verbs: ["*"]---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cd-role-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cd-role
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: system:serviceaccount:default:chapter8-serviceaccount
```

在`apiGroup`中的[`""`]表示 Kubernetes 中的核心组。要查看资源和动词的完整列表，请查看 Kubernetes API 参考站点：[`kubernetes.io/docs/reference/`](https://kubernetes.io/docs/reference/)。

在这种情况下，我们创建了一个`cd-role`，这是执行持续部署的角色。此外，我们创建了一个`ClusterRoleBinding`，将服务账户`chapter8-serviceaccount`与`cd-role`关联起来。

# 基于角色的访问控制（RBAC）

基于角色的访问控制的概念围绕着`Role`、`ClusterRole`、`RoleBinding`和`ClusterRoleBinding`。通过`role.yaml`和`rolebinding.yaml`，正如我们之前展示的，Linda 应该对`configmaps`资源获得只读访问权限。要将授权规则应用于`chloe-k8scookbook@gmail.com`，只需将`ClusterRole`和`ClusteRoleBinding`与其关联即可：

```
# cat oidc_clusterrole.yaml
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: oidc-admin-role
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: admin-binding
subjects:
  - kind: User
    name: chloe-k8scookbook@gmail.com
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: oidc-admin-role
  apiGroup: rbac.authorization.k8s.io
```

然后，我们应该能够看到我们是否可以使用`chloe-k8scookbook@gmail.com`用户获取节点：

```
# kubectl --user=chloe-k8scookbook@gmail.com get nodes 
NAME STATUS ROLES AGE VERSION minikube Ready <none> 6d v1.9.4 
```

它的运行效果很好。我们不再遇到 Forbidden 错误。

在 RBAC 之前，Kubernetes 提供了**基于属性的访问控制**（**ABAC**），允许集群管理员将一组用户授权策略定义为一个 JSON 格式的文件。然而，该文件必须在启动 API 服务器时存在，这使得它在现实世界中无法使用。在 Kubernetes 1.6 中引入 RBAC 之后，ABAC 变得过时并被弃用。

# 准入控制

准入控制模块在 Kubernetes 验证谁发出请求以及请求者是否具有足够的权限执行它们之后开始发挥作用。与身份验证和授权不同，准入控制可以查看请求的内容，甚至有能力对其进行验证或修改。如果请求未经过准入控制器之一，请求将立即被拒绝。要在 Kubernetes 中启用准入控制器，只需在启动 API 服务器时传递`--admission-control（版本<1.10）--enable-admission-plugins（版本>=1.10）`参数。

根据集群的配置方式，传递`--enable-admission-plugin`参数的方法可能会有所不同。在 minikube 中，添加`--extra-config=apiserver.Admission.PluginNames=$ADMISSION_CONTROLLERS`并用逗号分隔不同的控制器应该就可以了。

不同的准入控制器设计用于不同的目的。在接下来的教程中，我们将介绍一些重要的准入控制器以及 Kubernetes 官方建议用户拥有的准入控制器。版本>=1.6.0 的推荐列表如下：`NamespaceLifecycle`、`LimitRanger`、`ServiceAccount`、`PersistentVolumeLabel`、`DefaultStorageClass`、`DefaultTolerationSeconds`、`ResourceQuota`。

请注意，准入控制器的顺序很重要，因为请求会依次通过（这对于 1.10 版本之前使用`--admission-control`选项的情况是正确的；在 v1.10 中，该参数被`--enable-admission-plugins`替换，顺序就不再重要）。我们不希望首先进行`ResourceQuota`检查，然后在检查了一长串准入控制器后发现资源信息已过时。

如果版本是>=1.9.0，则`MutatingAdmissionWebhook`和`ValidatingAdmissionWebhook`将在`ResourceQuota`之前添加。有关`MutatingAdmissionWebhook`和`ValidatingAdmissionWebhook`的更多信息，请参阅本教程中的*更多内容*部分。

# NamespaceLifecycle

当命名空间被删除时，该命名空间中的所有对象也将被清除。此插件确保在终止或不存在的命名空间中无法进行新对象的创建请求。它还可以防止 Kubernetes 本机命名空间被删除。

# LimitRanger

此插件确保 `LimitRange` 可以正常工作。使用 `LimitRange`，我们可以在命名空间中设置默认请求和限制，在启动 pod 时使用，而无需指定请求和限制。

# ServiceAccount

如果您打算在用例中利用 ServiceAccount 对象，则必须添加 ServiceAccount 插件。有关 ServiceAccount 的更多信息，请重新查看本教程中学到的 ServiceAccount 部分。

# PersistentVolumeLabel（从 v1.8 版本开始已弃用）

`PersistentVolumeLabel` 根据底层云提供商提供的标签，为新创建的 PV 添加标签。从 1.8 版本开始，此准入控制器已被弃用。此控制器的功能现在由云控制器管理器负责，它定义了特定于云的控制逻辑并作为守护程序运行。

# 默认存储类

此插件确保默认存储类在未在 `PersistentVolumeClaim` 中设置 `StorageClass` 的情况下可以正常工作。不同的云提供商使用不同的供应工具来利用 `DefaultStorageClass`（例如 GKE 使用 Google Cloud Persistent Disk）。请确保您已启用此功能。

# 默认容忍时间

污点和容忍度用于阻止一组 pod 在某些节点上调度运行。污点应用于节点，而容忍度则针对 pod 进行指定。污点的值可以是 `NoSchedule` 或 `NoExecute`。如果在一个带有污点的节点上运行的 pod 没有匹配的容忍度，那么这些 pod 将被驱逐。

`DefaultTolerationSeconds` 插件用于设置那些没有设置容忍度的 pod。然后，它将为 `notready:NoExecute` 和 `unreachable:NoExecute` 的默认容忍度申请 300 秒。如果节点不可用或不可达，等待 300 秒后再将 pod 从节点中驱逐。

# ResourceQuota

就像 `LimitRange` 一样，如果您正在使用 `ResourceQuota` 对象来管理不同级别的 QoS，则必须启用此插件。`ResourceQuota` 应始终放在准入控制插件列表的末尾。正如我们在 `ResourceQuota` 部分提到的，如果使用的配额少于硬配额，资源配额使用将被更新，以确保集群有足够的资源来接受请求。将其放在 ServiceAccount 准入控制器列表的末尾可以防止请求在被后续控制器拒绝之前过早增加配额使用。

# DenyEscalatingExec

这个插件拒绝了任何 kubectl exec 和 kubectl attach 命令的提升特权模式。具有特权模式的 pod 可以访问主机命名空间，这可能会带来安全风险。

# AlwaysPullImages

拉取策略定义了 kubelet 拉取镜像时的行为。默认的拉取策略是 `IfNotPresent`，也就是说，如果本地不存在镜像，它会拉取镜像。如果启用了这个插件，那么默认的拉取策略将变为 Always，也就是说，总是拉取最新的镜像。这个插件还提供了另一个好处，如果你的集群被不同的团队共享。每当一个 pod 被调度，它都会拉取最新的镜像，无论本地是否存在该镜像。这样我们就可以确保 pod 创建请求始终通过镜像的授权检查。

有关准入控制器的完整列表，请访问官方网站（[`kubernetes.io/docs/admin/admission-controllers`](https://kubernetes.io/docs/admin/admission-controllers)）获取更多信息。

# 还有更多...

在 Kubernetes 1.7 之前，准入控制器需要与 API 服务器一起编译，并在 API 服务器启动之前进行配置。**动态准入控制**旨在打破这些限制。由于我们撰写本书时，动态准入控制的两个主要组件都还不是 GA，除了将它们添加到准入控制链中，还需要在 API 服务器中进行额外的运行时配置：`--runtime-config=admissionregistration.k8s.io/v1alpha1`。

在 minikube 中，ServiceAccount 运行时配置设置为 `api/all`，因此默认情况下已启用。

# Initializers（alpha）

Initializers 是对象初始化阶段的一组任务。它们可以是一组检查或变更，用于执行强制策略或注入默认值。例如，你可以实现一个 Initializer 来向 pod 注入一个 sidecar 容器或包含测试数据的卷。Initializers 在对象的 `metadata.initializers.pending` 中进行配置。在相应的 Initializer 控制器（通过名称标识）执行任务后，它将从元数据中删除其名称。如果由于某些原因某个 Initializer 不起作用，所有具有该 Initializer 的对象将被卡在未初始化阶段，并且在 API 中不可见。请谨慎使用。

# Webhook 准入控制器（v1.9 中的 beta 版本）

截至 v1.10，有两种类型的 webhook 准入控制器：

+   `ValidatingAdmissionWebhook`：它可以进行额外的自定义验证来拒绝请求

+   `MutatingAdmissionWebhooks`：它可以改变对象以强制执行默认策略

有关更多实施信息，请参考官方文档：

[`kubernetes.io/docs/admin/extensible-admission-controllers/`](https://kubernetes.io/docs/admin/extensible-admission-controllers/)

# 参见

以下食谱与本节相关：

+   *在第二章中的*使用命名空间*

+   *在第五章*中的*设置持续交付流水线*，构建持续交付流水线*

+   *在第八章*中的*kubeconfig 的高级设置*，高级集群管理*

+   *在第八章*中的*使用 ServiceAccount RESTful API*，高级集群管理*
