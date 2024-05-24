# Docker 快速启动指南（一）

> 原文：[`zh.annas-archive.org/md5/23ECB0A103B038BBAFCFDE067D60BC3D`](https://zh.annas-archive.org/md5/23ECB0A103B038BBAFCFDE067D60BC3D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

通常，当我提到 Docker 或这本书时，我得到的第一个问题是*Docker 是什么？*所以，我们也可以现在回答这个问题，把它解决掉…

在我交往的朋友圈里，我会回答这个问题，说*Docker 是一种软件解决方案，用于构建、发布和在任何地方运行容器*。但如果你不是计算机专业人士，那么这个答案对你来说几乎毫无意义。所以，让我们再试一次，以一种值得快速入门指南的方式回答*什么是 Docker？*。

Docker 是一种工具，允许软件开发人员轻松创建应用程序，并将这些应用程序打包成一个称为**容器**的特殊包。正确使用时，作为容器打包的应用程序可以非常高效、非常安全地运行。由于容器包含应用程序运行所需的一切，它还允许开发人员在几乎任何地方分享他们的应用程序，而无需重新创建或重新打包。

这意味着，通过使用 Docker，开发人员可以在自己的笔记本电脑上创建、运行和测试他们的应用容器，然后与同行分享完全相同的容器，以便他们也可以运行和测试。然后，他们可以与质量保证团队分享相同的容器，以进一步验证质量，最终，完全相同的容器可以在生产环境中运行和使用。

使用 Docker，软件开发人员可以创建比以往更好、更安全的软件，可以比以往更快地进行测试和部署。

在这本书的页面中，您将找到所有您需要了解 Docker 是什么以及 Docker 提供了什么好处的信息。使用详细但易于理解的描述和示例，这本快速入门指南将教会您如何设置自己的 Docker 开发环境，以及如何创建利用 Docker 提供的所有重要功能的企业级 Docker 镜像。这本快速入门指南将教会您如何使用 Docker 网络和 Docker 的存储功能。您还将学习如何创建和部署多容器应用程序，以及如何使用 Docker Swarm 设置 Docker 集群。完成快速入门指南时，您将能够构建和共享自己的 Docker 镜像，并在 Docker 容器中运行最重要的应用程序。这本快速入门指南将充分准备您在未来的所有项目中使用 Docker。如果您准备好开始，请翻页...

# 这本书适合谁

这本快速入门指南适用于任何想了解 Docker 是什么以及为什么有这么多人对使用它感到兴奋的人。它适用于希望立即开始使用 Docker 并且没有时间翻阅完整的《精通 Docker》书籍或参加为期一周的培训课程的开发人员。这本指南适用于任何需要快速决定是否在下一个项目中使用 Docker 并立即开始的人。

# 为了充分利用这本书

您应该有一台开发者工作站，可以在上面安装 Docker 并用于测试本书中包含的示例。您应该通过实际尝试每个示例来学习，而不仅仅是阅读它们。此外，您应该至少有一台其他服务器，最好是两台或三台其他服务器，用于配置为 Docker 集群。这些服务器可以是 AWS 中的 EC2 实例；或者是 VMware Workstation 或 Fusion 上的虚拟机；或者在 VirtualBox 中的虚拟机，最坏的情况下。本书中使用的所有软件都是免费或开源的，因此您应该能够尝试您在这里学到的一切。大多数示例无论您使用的操作系统如何都能很好地工作，我已经尝试在适当的地方指出了差异。您应该在[`hub.docker.com`](https://hub.docker.com)上创建一个帐户，并在[`github.com`](https://github.com)上创建一个帐户。所有的代码示例都经过了我的测试，以及几位审阅者的测试，所以如果您无法使它们工作，请仔细检查代码并重试，或者从 Packt 下载代码并将其剪切粘贴到您的系统中，然后再试一次。您会掌握的。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保您使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Docker-Quick-Start-Guide`](https://github.com/PacktPublishing/Docker-Quick-Start-Guide)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快去看看吧！

# 实际代码

访问以下链接查看代码运行的视频：[`bit.ly/2Q1DbPq`](http://bit.ly/2Q1DbPq)

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。以下是一个例子：“在网络密钥部分，我们正在指示 Docker 创建两个网络，一个名为`frontend`，一个名为`backend`。”

任何命令行输入或输出都以以下方式编写：

```
# Enable autolock on your swarm cluster
docker swarm update --autolock=true
# Adjust certificate expiry to 30 days
docker swarm update --cert-expiry 720h
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。以下是一个例子：“一旦配置已保存，让我们通过单击“立即构建”链接来测试作业。”

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。

# 保持联系


# 第一章：设置 Docker 开发环境

“突然间我想到：如果我的拖车可以被简单地吊起并放在船上，而不触及其中的货物，那不是很好吗？” - Malcolm McLean，美国卡车企业家

在本章中，我们将为我们的工作站设置 Docker 开发环境。我们将学习如何在 Linux、Windows 和 OS X 工作站上设置 Docker 开发环境。然后，我们将处理每个操作系统的一些后安装步骤。最后，我们将了解在每个操作系统上使用 Docker 的区别以及在它们之间需要注意的事项。

到本章结束时，您将了解以下内容：

+   如何设置您的 Docker 开发环境，无论您的工作站运行在以下哪种操作系统上：

+   CentOS

+   Ubuntu

+   Windows

+   OS X

+   在不同操作系统上使用 Docker 时需要注意的差异

# 技术要求

您需要使用您选择的操作系统（包括 Linux、Windows 或 OS X）的开发工作站。您需要在工作站上拥有 sudo 或管理员访问权限。由于您将安装从互联网上拉取的 Docker 软件，因此您需要工作站上的基本互联网连接。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter01`](https://github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter01)

查看以下视频以查看代码的运行情况：[`bit.ly/2rbGXqy`](http://bit.ly/2rbGXqy)

# 设置您的 Docker 开发环境

现在是时候动手了。让我们开始设置我们的工作站。无论您的首选操作系统是什么，都有相应的 Docker。使用以下内容作为指南，我们将带您完成在工作站上设置 Docker 的过程。我们可以从设置 Linux 工作站开始，然后解决 Windows 系统的问题，最后完成可能是最常见的开发者选项，即 OS X 工作站。虽然 OS X 可能是最受欢迎的开发者选项，但我建议您考虑将 Linux 发行版作为您的首选工作站。稍后在*在 OS X 工作站上安装 Docker*部分中，我们将更多地讨论我为什么做出这样的建议。但现在，如果您被说服在 Linux 上开发，请在 Linux 安装讨论期间仔细关注。

一般来说，有两种 Docker 可供选择：Docker 企业版或 Docker EE，以及 Docker 社区版或 Docker CE。通常，在企业中，你会选择企业版，特别是对于生产环境。它适用于业务关键的用例，Docker EE 正如其名，是经过认证、安全且在企业级别得到支持的。这是一个商业解决方案，由 Docker 提供支持并购买。

另一种类型，Docker CE，是一个社区支持的产品。CE 是免费提供的，通常是小型企业的生产环境和开发人员工作站的选择。Docker CE 是一个完全有能力的解决方案，允许开发人员创建可以与团队成员共享、用于 CI/CD 的自动构建工具，并且如果需要，可以与 Docker 社区大规模共享的容器。因此，它是开发人员工作站的理想选择。值得注意的是，Docker CE 有两种发布路径：稳定版和测试版。在本章的所有安装示例中，我们将使用 Docker CE 的稳定发布路径。

我们将从 CentOS Linux 开始安装讨论，但如果你赶时间，可以直接跳到 Ubuntu、Windows 或 Mac 部分。

# 在 Linux 工作站上安装 Docker

我们将执行 Docker 的 Linux 安装步骤，分别针对基于 RPM 的工作站（使用 CentOS）和基于 DEB 的工作站（使用 Ubuntu），这样你就会得到最符合你当前使用的 Linux 发行版或将来打算使用的指导。我们将从 CentOS 开始我们的安装之旅。

你可以在*参考*部分找到所有操作系统安装中使用的下载链接。

# 在 CentOS 工作站上安装 Docker

CentOS 上的 Docker CE 需要一个维护的 CentOS 7 版本。虽然安装可能在存档版本上运行，但它们既没有经过测试也没有得到支持。

在 CentOS 上安装 Docker CE 有三种方法：

+   通过 Docker 仓库

+   下载并手动安装 RPM 包

+   运行 Docker 的便利脚本

最常用的方法是通过 Docker 仓库，所以让我们从那里开始。

# 通过 Docker 仓库安装 Docker CE

首先，我们需要安装一些必需的软件包。打开终端窗口，输入以下命令：

```
# installing required packages sudo yum install -y yum-utils \
 device-mapper-persistent-data \
 lvm2
```

这将确保我们在系统上安装了`yum-config-manager`实用程序和设备映射器存储驱动程序。如下截图所示：

请注意，你的 CentOS 7 安装可能已经安装了这些，并且在这种情况下，`yum install`命令将报告没有需要安装的内容。![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/bbfeed5a-dfc3-4cdb-800d-8f2b7d425e18.png)

接下来，我们将为 Docker CE 设置 CentOS 稳定存储库。

值得注意的是，即使你想安装边缘版本，你仍然需要设置稳定的存储库。

输入以下命令设置稳定的存储库：

```
# adding the docker-ce repo sudo yum-config-manager \
 --add-repo \
 https://download.docker.com/linux/centos/docker-ce.repo
```

如果你想使用边缘版本，可以使用以下命令启用它：

```
# enable edge releases sudo yum-config-manager --enable docker-ce-edge
```

同样，你可以使用这个命令禁用对边缘版本的访问：

```
# disable edge releases sudo yum-config-manager --disable docker-ce-edge
```

现在开始有趣的部分...我们将安装 Docker CE。要这样做，请输入以下命令：

```
# install docker sudo yum -y install docker-ce 
```

如果出现关于需要安装`container-selinux`的错误，请使用以下命令进行安装，然后重试：

```
# install container-selinux sudo yum -y --enablerepo=rhui-REGION-rhel-server-extras \
   install container-selinux

sudo yum -y install docker-ce
```

就是这样！安装 Docker CE 比你想象的要容易得多，对吧？

让我们使用最基本的方法来确认安装成功，通过发出版本命令。

这个命令验证了我们安装了 Docker CE，并显示了刚刚安装的 Docker 的版本。输入以下命令：

```
# validate install with version command docker --version
```

在撰写本文时，最新版本的 Docker CE 是 18.03.1：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/93abb062-6714-4a13-83d1-a131bb53546f.png)

我们还有一个关键的步骤。虽然 Docker CE 已安装，但 Docker 守护程序尚未启动。要启动它，我们需要发出以下命令：

```
# start docker deamon sudo systemctl start docker
```

它应该悄悄地启动，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/24b47ec6-3c2d-4073-8ccd-c2ce213ba130.png)

我们看到了如何使用版本命令验证 Docker 的安装。这是一个很好的快速测试，但有一种简单的方法来确认不仅安装，而且一切都按预期启动和工作，那就是运行我们的第一个 Docker 容器。

让我们发出以下命令来运行 hello-world 容器：

```
# run a test container sudo docker run hello-world
```

如果一切顺利，你会看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/154e15a3-d7a5-430c-b866-1864ba153fa9.png)

我们在我们的 CentOS 工作站上安装了 Docker CE，并且它已经在运行容器。我们有了一个很好的开始。现在我们知道如何使用 Docker 存储库进行安装，让我们看看如何手动使用下载的 RPM 进行安装。

# 使用下载的 RPM 手动安装 Docker CE

安装 Docker CE 的另一种方法是使用下载的 RPM。这种方法涉及下载您希望安装的版本的 Docker CE RPM。您需要浏览 Docker CE 稳定版 RPM 下载站点。其 URL 为[`download.docker.com/linux/centos/7/x86_64/stable/Packages`](https://download.docker.com/linux/centos/7/x86_64/stable/Packages)：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/70e0eff2-2b78-4c29-836e-8528b8afb3d9.png)

单击要下载的 Docker CE 版本，并在提示时告诉浏览器保存文件。接下来，发出`yum install`命令，提供已下载的 RPM 文件的路径和文件名。您的命令应该类似于这样：

```
# install the docker rpm sudo yum install ~/Downloads/docker-ce-18.03.1.ce-1.el7.centos.x86_64.rpm
```

您需要启动 Docker 守护程序。您将在存储库部分使用前面的命令：

```
# start docker sudo systemctl start docker
```

而且，正如我们之前学到的，您可以使用以下命令验证安装的功能：

```
# validate the install and functionality docker --version
sudo docker run hello-world
```

虽然这种方法可能看起来更简单、更容易执行，但它不太理想，因为它更多地是一个手动过程，特别是在更新 Docker CE 版本时。您必须再次浏览下载页面，找到更新版本，下载它，然后执行`yum install`。使用之前描述的 Docker 存储库方法，升级只需发出`yum upgrade`命令。现在让我们再看一种在您的 CentOS 工作站上安装 Docker CE 的方法。

# 通过运行便利脚本安装 Docker CE

安装 Docker 的第三种方法是使用 Docker 提供的便利脚本。这些脚本允许您安装 Docker 的最新边缘版本或最新测试版本。不建议在生产环境中使用其中任何一个，但它们确实在测试和开发最新的 Docker 版本时起到作用。这些脚本在某种程度上受限，因为它们不允许您在安装过程中自定义任何选项。相同的脚本可以用于各种 Linux 发行版，因为它们确定您正在运行的基本发行版，然后根据该确定进行安装。该过程很简单。

使用`curl`下载所需的脚本，然后使用 sudo 运行脚本。

运行最新的边缘版本的命令如下：

```
# download and run the install script curl -fsSL get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

执行脚本将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/a09ba16c-6262-4ae3-b391-a43c0c768ff5.png)

docker 组已经由脚本为您创建，但由于 CentOS 是以 RPM 为中心，您仍需要自己启动 Docker 服务：

```
# start docker sudo systemctl start docker
```

如果这是一个基于 Debian 的系统，Docker 服务将会被脚本自动启动。

现在我们已经检查了在 CentOS 工作站上安装 Docker 的三种方法，现在是时候讨论一些推荐的后续安装设置。

# 您可能要考虑的后续安装步骤

所有三种安装方法都会自动为您创建一个 docker 组，但如果您希望能够在不使用`root`或 sudo 的情况下运行 Docker 命令，则需要将用户添加到 docker 组中。

请注意，许多 Docker 命令需要完整的管理员访问权限才能执行，因此将用户添加到 docker 组相当于授予他们 root 访问权限，应考虑安全影响。如果用户已经在其工作站上具有 root 访问权限，则将其添加到 docker 组只是为其提供方便。

通过以下命令轻松将当前用户添加到 docker 组：

```
# add the current user to the docker group sudo usermod -aG docker $USER
```

您需要注销并重新登录以更新您帐户的组成员资格，但一旦您这样做了，您应该可以执行任何 Docker 命令而不使用 sudo。

可以通过在不使用 sudo 的情况下运行 hello-world 容器来验证：

```
# test that sudo is not needed docker run hello-world
```

接下来，您将希望配置系统在系统启动时启动 Docker 服务：

```
# configure docker to start on boot sudo systemctl enable docker
```

您可能要考虑的另一个后续安装步骤是安装 docker-compose。

这个工具可以成为您的 Docker 工具箱的重要补充，我们将在第七章中讨论其用途，*Docker Stacks*。安装 docker-compose 的命令是：

```
# install docker compose
sudo curl -L \
 https://github.com/docker/compose/releases/download/1.21.2/docker-compose-$(uname -s)-$(uname -m) \
 -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

恭喜，您的 CentOS 工作站现在已准备好开始开发您的 Docker 镜像并部署您的 Docker 容器。接下来，我们将学习如何在 Ubuntu 工作站上使用 DEB-based 系统安装 Docker。如果您准备好了，请继续阅读。

# 在 Ubuntu 工作站上安装 Docker

与在 CentOS 工作站上一样，我们将在 Ubuntu 工作站上安装 Docker CE。在 Ubuntu 上安装 Docker CE 的要求是您必须运行 64 位的最新 LTS 版本，例如 Bionic、Xenial 或 Trusty。您可以在 Artful 版本的 Ubuntu 上安装 Docker CE 的边缘版本。

在 Ubuntu 上安装 Docker CE 有三种方法：

+   通过 Docker 仓库

+   下载并手动安装 DEB 软件包

+   运行方便脚本

最常用的方法是通过 Docker 存储库，所以让我们从那里开始。

# 通过 Docker 存储库安装 Docker CE

我们首先需要设置 Docker 存储库，然后我们可以进行安装，所以让我们现在处理存储库。

第一步是更新 apt 软件包索引。使用以下命令来执行：

```
# update apt-get libraries sudo apt-get update
```

现在我们需要安装一些支持软件包：

```
# install required packages sudo apt-get install \
 apt-transport-https \
 ca-certificates \
 curl \
 software-properties-common
```

接下来，我们需要获取 Docker 的 GPG 密钥：

```
# get the GPG key for docker curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
   sudo apt-key add -
```

您可以确认已成功添加了 Docker 的 GPG 密钥；它将具有`9DC8 5822 9FC7 DD38 854A E2D8 8D81 803C 0EBF CD88`的指纹。

您可以通过使用以下命令检查最后八个字符是否与`0EBFCD88`匹配来验证密钥：

```
# validating the docker GPG key is installed sudo apt-key fingerprint 0EBFCD88
```

最后，我们需要实际设置存储库。我们将专注于我们的示例中的稳定存储库。

如果要安装 Docker CE 的边缘或测试版本，请确保在以下命令中的`stable`单词后添加`edge`或`test`（不要替换`stable`单词）：

```
# adding the docker repository sudo add-apt-repository \
 "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
 $(lsb_release -cs) \
 stable"
```

现在我们的系统已经设置了正确的存储库来安装 Docker CE，让我们来安装它。

首先确保所有软件包都是最新的，通过发出`apt-get update`命令：

```
# update apt-get libraries again sudo apt-get update
```

现在我们将实际安装 Docker CE：

```
# install docker sudo apt-get install docker-ce
```

Docker 已安装。安装后，您可以检查 Docker 版本以确认安装成功：

```
# validate install with version command docker --version
```

版本命令应该类似于这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/51eddd17-1070-4a6e-891c-16df43cb1920.png)

现在，让我们验证 Docker 安装是否按预期工作。为此，我们将使用以下命令运行 hello-world Docker 镜像：

```
# validating functionality by running a container
sudo docker run hello-world
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/4abbab91-b0ea-4fc9-bf7c-6928739f5e36.png)

您注意到了一些有趣的事情吗？

在安装后，我们不需要像在 CentOS 安装中那样启动 Docker。这是因为在基于 DEB 的 Linux 系统上，安装过程也会为我们启动 Docker。此外，Ubuntu 工作站已配置为在启动时启动 Docker。因此，在安装过程中，这两个 Docker 启动步骤都已为您处理。太棒了！您的 Ubuntu 工作站现在已安装了 Docker，并且我们已经验证它正在按预期工作。

虽然使用 Docker 存储库是在工作站上安装 Docker 的最佳方法，但让我们快速看一下在 Ubuntu 工作站上手动安装 Docker CE 的另一种方法，即通过使用 DEB 软件包手动安装它。

# 使用 DEB 软件包手动安装 Docker CE

现在我们将向您展示如何下载和安装 Docker CE DEB 软件包。如果由于某种原因，软件库对您的工作站不可用，您应该考虑使用此方法。

您需要下载 Docker CE 软件包，所以首先打开浏览器，访问 Ubuntu Docker CE 软件包下载站点[`download.docker.com/linux/ubuntu/dists/.`](https://download.docker.com/linux/ubuntu/dists/)

在那里，您将找到列出的 Ubuntu 版本文件夹的列表，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/22e51e24-f5fb-4fec-986b-3ba7eed038b9.png)

您需要选择与工作站上安装的 Ubuntu 版本相匹配的文件夹，对我来说是`xenial`文件夹。

继续浏览到`/pool/stable/`，然后转到与您的工作站硬件相匹配的处理器文件夹。对我来说，那是 amd64，看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/2b78a600-e4fb-47a6-95d5-0332af65eebf.png)

现在单击要下载和安装的 Docker CE 版本。

在单击“确定”之前，请务必选择“保存文件”选项。

一旦软件包已下载到您的工作站，只需使用`dpkg`命令手动安装软件包即可安装它。

您将下载的 Docker CE 软件包的路径和文件名作为参数提供给`dpkg`。以下是我用于刚刚下载的软件包的命令：

```
# installing docker package
sudo dpkg -i ~/Downloads/docker-ce_18.03.1~ce-0~ubuntu_amd64.deb
```

执行该命令如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/d1bfd0e2-c566-4b4e-ac1a-6e904bec3ff5.png)

现在 Docker 已安装，让我们使用版本命令来确认成功安装，然后运行 hello-world 容器来验证 Docker 是否按预期工作：

```
# validating the install and functionality
docker --version
sudo docker run hello-world
```

这很好。就像仓库安装一样，您的 docker 组已创建，并且在手动软件包安装中，这两个启动步骤都已为您处理。您不必启动 Docker，也不必配置 Docker 在启动时启动。因此，您已准备好开始创建 Docker 镜像和运行 Docker 容器。

然而，在我们开始创建和运行之前，还有一种在 Ubuntu 工作站上安装 Docker 的方法，我们将介绍。您可以使用 Docker 的便利脚本来安装 Docker CE 的最新边缘或测试版本。现在让我们看看如何做到这一点。

# 通过运行便利脚本安装 Docker CE

安装 Docker 的另一种方法是使用 Docker 提供的便利脚本。这些脚本允许您安装最新的边缘版本或最新的测试版本的 Docker。不建议在生产环境中使用其中任何一个，但它们确实在测试和开发最新的 Docker 版本时起到作用。这些脚本有一定的局限性，因为它们不允许您在安装中自定义任何选项。相同的脚本可以用于各种 Linux 发行版，因为它们确定您正在运行的基本发行版，然后根据该确定进行安装。这个过程很简单。使用`curl`拉取所需的脚本，然后使用 sudo 运行脚本。运行最新的边缘版本的命令如下。

使用以下命令安装 curl：

```
# install curl sudo apt-get install curl
```

现在获取脚本并运行 docker 脚本进行安装：

```
# download and run the docker install script curl -fsSL get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

执行脚本将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/ab1d1aed-aa83-49e9-978f-f71095f9d532.png)

脚本已为您创建了 docker 组。 Docker 服务已启动，并且工作站已配置为在启动时运行 Docker。因此，您又一次准备好开始使用 Docker。

我们已经研究了在 Ubuntu 工作站上安装 Docker 的三种方法，现在是讨论建议的后安装设置的好时机。

# 您可能要考虑的后安装步骤

这三种安装方法都会自动为您创建一个 docker 组，但如果您想要能够在不使用`root`或 sudo 的情况下运行 Docker 命令，您将需要将您的用户添加到 docker 组中。

请注意，许多 Docker 命令需要完全的管理员访问权限才能执行，因此将用户添加到 docker 组相当于授予他们 root 访问权限，应考虑安全性影响。如果用户已经在他们的工作站上具有 root 访问权限，则将他们添加到 docker 组只是为他们提供方便。

将当前用户添加到 docker 组中很容易通过以下命令完成：

```
# add the current user to the docker group sudo usermod -aG docker $USER
```

您需要注销并重新登录以更新您帐户的组成员资格，但一旦您这样做了，您就可以执行任何 Docker 命令而不使用 sudo。

这可以通过 hello-world 容器进行验证：

```
# validate that sudo is no longer needed docker run hello-world
```

您应该考虑的另一个后安装步骤是安装 docker-compose。

这个工具可以成为您的 Docker 工具箱的重要补充，我们将在第七章《Docker Stacks》中讨论其用途。安装 docker-compose 的命令是：

```
# install docker-compose
sudo curl -L https://github.com/docker/compose/releases/download/1.21.2/docker-compose-$(uname -s)-$(uname -m) -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

恭喜，您的 Ubuntu 工作站现在已准备好开始开发 Docker 镜像并部署 Docker 容器。接下来，我们将学习如何在基于 Windows 的工作站上安装 Docker。如果您准备好了，请继续阅读。

# 在 Windows 工作站上安装 Docker

Docker CE 的 Windows 版本与 Windows 10 专业版或企业版兼容。Windows 上的 Docker CE 通过与 Windows Hyper-V 虚拟化和网络集成，提供了完整的 Docker 开发解决方案。Windows 上的 Docker CE 支持创建和运行 Windows 和 Linux 容器。Windows 上的 Docker CE 可以从 Docker 商店下载：[`store.docker.com/editions/community/docker-ce-desktop-windows`](https://store.docker.com/editions/community/docker-ce-desktop-windows)。

您需要登录 Docker 商店以下载 Docker CE for Windows 安装程序，因此，如果您还没有帐户，请立即创建一个然后登录。

请务必安全地保存您的 Docker 凭据，因为您将在将来经常使用它们。

登录后，您应该会看到“获取 Docker”下载按钮。单击下载按钮，允许安装程序下载到您的工作站。一旦安装程序下载完成，您可以单击“运行”按钮开始安装。如果出现安全检查，请确认您要运行安装程序可执行文件，然后单击“运行”按钮。如果您的工作站启用了 UAC，您可能会看到用户账户控制警告，询问您是否要允许 Docker CE 安装程序对设备进行更改。您必须选择“是”才能继续，所以请立即单击。

Docker CE 安装程序将运行，并开始下载 Docker。一旦 Docker 安装文件成功下载，安装程序将要求您确认所需的配置。这里的选项很少。我建议您将快捷方式添加到桌面，并且不要选择使用 Windows 容器而不是 Linux 容器的选项：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/5b9ae48a-1a9d-4633-a64a-c799e62d9895.png)

安装程序将解压 Docker CE 文件。当文件解压缩后，您将收到安装成功的通知。根据当前的文档，安装程序将在安装结束时为您运行 Docker。根据我的经验，这并不总是发生。请耐心等待，但如果第一次它没有启动，您可能需要手动运行 Docker。

如果您选择了将 Docker 添加到桌面的快捷方式配置选项，现在您可以双击该快捷方式图标，第一次启动 Docker。

Docker 将运行，并且您将看到一个欢迎屏幕，告诉您 Docker 已经启动。建议您在此时提供您的 Docker 凭据并登录。

每当 Docker 运行时，您将在任务栏通知区域看到一个鲸鱼图标。如果您将鼠标悬停在该图标上，您可以获取 Docker 进程的状态。您将看到诸如 Docker 正在启动和 Docker 正在运行等状态。您可以右键单击该图标以打开 Docker for Windows 菜单：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/705619cd-d82e-4c3a-a00a-1b846bd3e499.png)

一旦您在 Windows 工作站上运行 Docker，您可以打开 Windows PowerShell 命令窗口并开始使用 Docker。要验证安装是否成功，请打开 PowerShell 窗口并输入版本命令。为了确认 Docker 是否按预期工作，请运行 hello-world Docker 容器：

```
# validate install and functionality docker --version
docker run hello-world
```

您的 Windows 10 工作站现在已设置好，可以创建 Docker 镜像并运行 Docker 容器。Docker 也应该配置为在启动时启动，这样当您需要重新启动工作站时，它将自动启动。

请注意，在 Windows 工作站上使用 Docker CE 并不完全像在 Linux 工作站上使用 Docker CE 那样。在幕后隐藏着一个额外的虚拟化层。Docker 在 Hyper-V 中运行一个小型的 Linux 虚拟机，并且您所有的 Docker 交互都会通过这个 Linux 虚拟机进行。对于大多数用例，这永远不会出现任何问题，但它确实会影响性能。我们将在*发现操作系统之间需要注意的差异*部分详细讨论这一点。

我们还想看一下另一个设置，所以如果您准备好了，就直接进入下一节。

# 您可能想考虑的安装后步骤

以下是我建议您在 Docker Windows 工作站上进行的一些安装后步骤。

# 安装 Kitematic

Docker CE 的 Windows 安装集成了一个名为 Kitematic 的图形用户界面工具。如果您是图形界面类型的人（并且由于您正在使用 Windows 进行 Docker，我猜您是），您会想要安装此工具。

在任务栏通知区域找到`Docker`图标，右键单击它以打开 Windows 菜单。单击 Kitematic 菜单选项。Kitematic 不是默认安装的。您必须下载包含应用程序的存档。当您第一次单击 Kitematic 菜单选项时，将提示您下载它。单击下载按钮，并将存档文件保存到您的工作站。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/b4ee253f-bc5c-4952-b206-a2dab0761e12.png)

您需要解压 Kitematic 存档才能使用它。未压缩的 Kitematic 文件夹需要位于`C:\Program Files\Docker`文件夹中，并且文件夹名称为`Kitematic`，以便 Docker 子菜单集成能够正常工作。一旦您在 Windows 工作站的正确路径上安装了 Kitematic，您可以右键单击任务栏通知区域中的`Docker`图标，然后再次选择 Kitematic 选项。

您将被提示再次输入您的 Docker 凭据以连接到 Docker Hub。您可以跳过此步骤，但我建议您现在就登录。一旦您登录（或跳过登录步骤），您将看到 Kitematic 用户界面。它允许您在工作站上下载和运行 Docker 容器。尝试一个，比如*hello-world-nginx*容器，或者如果您想玩游戏，可以尝试 Minecraft 容器。

您现在可以在 Windows 10 工作站上创建 Docker 镜像并运行 Docker 容器，但我们还有一个工作站操作系统需要学习如何在其上安装 Docker CE。让我们看看如何在 OS X 工作站上安装它。

# 为 PowerShell 设置 DockerCompletion

如果您曾经使用过命令行完成，您可能会考虑为 PowerShell 安装 DockerCompletion。此工具为 Docker 命令提供了命令行完成。它相当容易安装。您需要设置系统以允许执行已下载的模块。为此，请以管理员身份打开 PowerShell 命令窗口，并发出以下命令：

```
# allow remote signed scripts to run
Set-ExecutionPolicy RemoteSigned
```

您现在可以关闭管理员命令窗口，并打开普通用户 PowerShell 命令窗口。要安装`DockerCompletion`模块，请发出以下命令：

```
# install Docker completion
Install-Module DockerCompletion -Scope CurrentUser
```

最后，在当前的 PowerShell 窗口中激活模块，请使用以下命令：

```
# enable Docker completion
Import-Module DockerCompletion
```

现在您可以为所有 Docker 命令使用命令完成功能。这是一个很好的节省按键的功能！

请注意，Import-Module 命令仅在当前的 PowerShell 命令窗口中有效。如果您希望在所有未来的 PowerShell 会话中都可用，您需要将`Import-Module DockerCompletion`添加到您的 PowerShell 配置文件中。

您可以使用以下命令轻松编辑您的 PowerShell 配置文件（如果尚未创建，则创建一个新的）：

```
# update your user profile to enable docker completion for every PowerShell command prompt
notepad $PROFILE
```

输入`Import-Module DockerCompletion`命令并保存配置文件。现在您的 Docker 命令行完成功能将在所有未来的 PowerShell 会话中激活。

# 在 OS X 工作站上安装 Docker

近年来，Mac 上的 Docker 故事有了很大进展，现在它是 Mac 工作站的一个真正可用的开发解决方案。Docker CE for Mac 需要 OS X El Capitan 10.11 或更新的 macOS 版本。Docker CE 应用程序与 OS X 中内置的 hypervisor、网络和文件系统集成。安装过程很简单：下载 Docker 安装程序镜像并启动它。您可以从 Docker 商店下载安装程序镜像。您必须登录 Docker 商店才能下载安装镜像，因此，如果尚未拥有帐户，请在那里创建一个。

请务必安全地保存您的凭据，因为以后会需要它们。

浏览到 Docker CE for Mac 的 Docker 商店页面[`store.docker.com/editions/community/docker-ce-desktop-mac`](https://store.docker.com/editions/community/docker-ce-desktop-mac)。请记住，您必须登录 Docker 商店才能下载安装程序镜像。

一旦登录到 Docker 商店，Get Docker 按钮将可供单击。继续单击它开始下载。Docker CE for Mac 安装镜像可能需要一些时间来下载。下载完成后，双击`Docker.dmg`镜像文件以挂载和打开它：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/b5757407-1b67-4886-96a8-7857bf6cd463.png)

一旦 Docker CE for Mac 镜像已挂载并打开，点击`Docker`图标并将其拖放到`应用程序`图标上以完成安装。将启动复制`Docker`到`应用程序`的操作。当复制过程完成时，Docker 应用程序将可以从您的`应用程序`文件夹中运行。双击您的`Docker`图标来启动它。第一次启动 Docker 时，会警告您正在运行从互联网下载的应用程序，以确保您真的想要打开它。当 Docker 应用程序打开时，您将收到友好的欢迎消息。

在欢迎消息上点击下一步，会警告您 Docker 需要提升的权限才能运行，并告知您必须提供凭据来安装 Docker 的网络和应用链接。输入您的用户名和密码。Docker 应用程序将启动，将鲸鱼图标添加到菜单通知区域。

您还将被提示输入 Docker 商店凭据，以允许 Docker for Mac 登录商店。输入您的凭据，然后点击“登录”按钮。您将收到确认消息，显示您当前已登录。

为了验证我们的安装成功并确认我们的安装功能，我们将发出版本命令，然后运行 Docker 的 hello-world 容器：

```
# validate install and functionality docker --version
docker run hello-world
```

您的 macOS 工作站现在已设置好，可以创建 Docker 镜像和运行 Docker 容器。您已经准备好将应用程序容器化了！您可以轻松使用终端窗口进行所有 Docker 工作，但您可能对 Mac 上可用的图形 UI 工具**Kitematic**感兴趣。让我们接下来安装 Kitematic。

# 安装后你可能想考虑的步骤

以下是我建议您的 Docker OS X 工作站的一些安装后步骤。

# 安装 Kitematic

虽然您可以在 OS X 终端窗口中使用 Docker CLI，并且可能会在大部分 Docker 开发工作中使用它，但您也可以选择使用名为 Kitematic 的图形 UI 工具。要安装 Kitematic，请右键单击 OS X 菜单通知区域中的鲸鱼图标以打开 Docker for Mac 菜单。单击 Kitematic 菜单选项以下载（以及后来运行）Kitematic 应用程序。如果您尚未安装 Kitematic，当您单击 Docker for Mac 菜单时，将显示包含下载链接的消息。该消息还提醒您必须将 Kitematic 安装到您的`Applications`文件夹中以启用 Docker 菜单集成。单击此处链接下载 Kitematic 应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/dbf3a805-51e9-448a-9656-e50c242ad008.png)

下载完成后，将下载的应用程序移动到您的`Applications`文件夹中，如之前所述。然后，使用 Docker for Mac 菜单，再次单击 Kitematic 菜单选项。这次它将运行 Kitematic 应用程序。第一次运行应用程序时，您将收到标准警告，询问您是否真的要打开它。单击“打开”按钮以打开。

一旦在您的 Mac 工作站上安装了 Kitematic，您可以单击菜单栏通知区域中的 Docker 鲸鱼图标，然后再选择 Kitematic 选项。

您将被提示输入您的 Docker 凭据以将 Kitematic 连接到 Docker Hub。您可以跳过此步骤，但我建议您现在登录。一旦您登录（或跳过登录步骤），您将看到 Kitematic 用户界面。这允许您在您的工作站上下载和运行 Docker 容器。尝试一个，比如*hello-world-nginx*容器，或者如果您想玩游戏，可以尝试 Minecraft 容器。

恭喜！您现在已经设置好了使用 Docker CLI 和 Kitematic 图形用户界面来运行 Docker 容器和管理 Docker 镜像。但是，您将使用 OS X 终端和您喜欢的代码编辑器来创建 Docker 镜像。

# 安装 Docker 命令行完成

安装 Homebrew。您的 Mac 上可能已经安装了 Homebrew，但如果没有，现在应该安装它。以下是安装它的命令：

```
# install homebrew
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

接下来，使用 Homebrew 安装`bash-completion`。以下是命令：

```
# use homebrew to install bash completion 
brew install bash-completion
```

安装`bash-completion`会指导你将以下行添加到你的`~/.bash_profile`文件中：

```
# update the bash profile to enable bash completion for every terminal session 
[ -f /usr/local/etc/bash_completion ] && . /usr/local/etc/bash_completion
```

现在，创建必要的链接以启用 Docker 命令行补全功能。每个 Docker 工具集都有一个链接。以下是 bash 的链接命令（如果你使用`zsh`，请查看下一个代码块中的链接命令）：

```
# create links for bash shell
ln -s /Applications/Docker.app/Contents/Resources/etc/docker.bash-completion $(brew --prefix)/etc/bash_completion.d/docker
ln -s /Applications/Docker.app/Contents/Resources/etc/docker-machine.bash-completion $(brew --prefix)/etc/bash_completion.d/docker-machine
ln -s /Applications/Docker.app/Contents/Resources/etc/docker-compose.bash-completion $(brew --prefix)/etc/bash_completion.d/docker-compose
```

请注意，如果你使用的是`zsh`而不是 bash，链接命令是不同的。以下是`zsh`的链接命令：

```
# create links for zsh shell
ln -s /Applications/Docker.app/Contents/Resources/etc/docker.zsh-completion /usr/local/share/zsh/site-functions/_docker
ln -s /Applications/Docker.app/Contents/Resources/etc/docker-machine.zsh-completion /usr/local/share/zsh/site-functions/_docker-machine
ln -s /Applications/Docker.app/Contents/Resources/etc/docker-compose.zsh-completion /usr/local/share/zsh/site-functions/_docker-compose
```

最后，重新启动你的终端会话——现在你可以使用 Docker 命令补全了！尝试输入`docker`并按两次*Tab*键。

# 参考

+   Docker 企业版数据：[`www.docker.com/enterprise-edition`](https://www.docker.com/enterprise-edition)

+   Docker 社区版数据：[`www.docker.com/community-edition`](https://www.docker.com/community-edition)

+   下载 CentOS 版的 Docker CE：[`store.docker.com/editions/community/docker-ce-server-centos`](https://store.docker.com/editions/community/docker-ce-server-centos)

+   下载 Ubuntu 版的 Docker CE：[`store.docker.com/editions/community/docker-ce-server-ubuntu`](https://store.docker.com/editions/community/docker-ce-server-ubuntu)

+   下载 Windows 版的 Docker CE：[`store.docker.com/editions/community/docker-ce-desktop-windows`](https://store.docker.com/editions/community/docker-ce-desktop-windows)

+   下载 Mac 版的 Docker CE：[`store.docker.com/editions/community/docker-ce-desktop-mac`](https://store.docker.com/editions/community/docker-ce-desktop-mac)

+   CentOS 版 Docker CE 稳定版 RPM 下载站点：[`download.docker.com/linux/centos/7/x86_64/stable/Packages`](https://download.docker.com/linux/centos/7/x86_64/stable/Packages)

+   Docker 安装 Repo：[`github.com/docker/docker-install`](https://github.com/docker/docker-install)

+   Ubuntu 版 Docker CE DEB 包下载站点：[`download.docker.com/linux/ubuntu/dists/`](https://download.docker.com/linux/ubuntu/dists/)

+   在 Windows 上运行 Windows Docker 容器：[`blog.docker.com/2016/09/build-your-first-docker-windows-server-container/`](https://blog.docker.com/2016/09/build-your-first-docker-windows-server-container/)

+   PowerShell 的 DockerCompletion：[`github.com/matt9ucci/DockerCompletion`](https://github.com/matt9ucci/DockerCompletion)

+   Mac 版的 Docker CE：[`store.docker.com/editions/community/docker-ce-desktop-mac`](https://store.docker.com/editions/community/docker-ce-desktop-mac)

+   Mac 的命令行完成：[`docs.docker.com/docker-for-mac/#install-shell-completion`](https://docs.docker.com/docker-for-mac/#install-shell-completion)

+   在您的 Mac 上安装 Homebrew：[`brew.sh/`](https://brew.sh/)

# 操作系统之间需要注意的差异

Docker 镜像是自包含的软件包，包括运行它们所设计的应用程序所需的一切。Docker 的一个巨大优势是，Docker 镜像可以在几乎任何操作系统上运行。也就是说，在不同的操作系统上运行 Docker 镜像的体验会有一些差异。Docker 是在 Linux 上创建的，并且与一些关键的 Linux 构造深度集成。因此，当您在 Linux 上运行 Docker 时，一切都会直接无缝地与操作系统集成。Docker 原生地利用 Linux 内核和文件系统。

不幸的是，当您在 Windows 或 Mac 上运行 Docker 时，Docker 无法利用与 Linux 上原生支持的相同构造，因为这些构造在这些其他操作系统上不存在。Docker 通过在非 Linux 操作系统中的虚拟机中创建一个小型、高效的 Linux VM 来处理这个问题。在 Windows 上，这个 Linux VM 是在 Hyper-V 中创建的。在 macOS 上，这个 VM 是在一个名为**hyperkit**的自定义虚拟机中创建的。

正如您所期望的，辅助虚拟机会带来性能开销。然而，如果您确实使用 Windows 或 OS X 作为开发工作站，您会高兴地知道，Docker 在这两个平台上都取得了很多积极的进展，减少了开销，并且随着每个新的主要版本的发布，性能得到了显著改善。有很多关于 OS X 上 hyperkit 虚拟机高 CPU 利用率的报告，但我个人没有遇到这个问题。我相信，使用当前稳定版本的 Docker CE，Windows 和 OS X 都可以成功用于 Docker 开发。

除了处理性能之外，还有其他一些差异需要考虑。有两个你应该知道的：文件挂载和端点。

在 Linux 操作系统上，Docker CE 能够直接使用文件系统来进行运行容器中的文件挂载，从而提供本地磁盘性能水平。您还可以更改文件系统驱动程序以实现不同级别的性能。这在 Windows 或 Mac 上不可用。对于 Windows 和 OS X，还有一个额外的文件系统工具来处理文件挂载。在 Windows 上，您将使用 Windows 共享文件，在 OS X 上则使用 osxfs。不幸的是，对于 Windows 和 OS X 用户来说，文件挂载的性能损失是显著的。尽管 Docker 在改进 Windows 和 OS X 的文件挂载故事方面取得了长足进步，但与在 Linux 操作系统上本地运行相比，两者仍然明显较慢。特别是对于 Windows，文件挂载选项非常受限制。如果您正在开发一个对磁盘利用率很高的应用程序，这种差异可能足以让您立即考虑切换到 Linux 开发工作站。

Linux 上的 Docker 和 Windows 或 Mac 上的 Docker 之间的另一个区别是端口的利用。例如，在 Windows 上使用 Docker 时，无法使用 localhost 从主机访问容器的端点。这是一个已知的 bug，但唯一的解决方法是从与运行它们的主机不同的主机访问容器的端点。在 Mac 上使用 Docker 时，还存在其他端点限制，比如无法 ping 容器（因为 Docker for Mac 无法将 ping 流量路由到容器内部），也无法使用每个容器的 IP 地址（因为 Docker 桥接网络无法从 macOS 访问）。

这些任何限制可能足以让您考虑将开发工作站切换到 Ubuntu 或 CentOS 操作系统。对我来说是这样，您会发现本书中大多数示例都是在我的 Ubuntu 工作站上执行的。我会尽量指出如果您使用 Windows 或 OS X 可能会有显著不同的地方。

# 总结

哇！我们在这第一章涵盖了很多内容。现在，您应该能够在您的工作站上安装 Docker，无论它运行的是哪种操作系统。您应该能够使用三种不同的方法在 Linux 工作站上安装 Docker，并了解在基于 RPM 的系统和基于 DEB 的系统上安装之间的一些区别。

我们还介绍了一些非常重要的原因，为什么您可能会考虑使用 Linux 工作站进行开发，而不是使用 Windows 或 macOS 工作站。到目前为止，您应该能够通过检查安装的 Docker 版本轻松验证 Docker 的成功安装。

您应该能够通过运行一个 hello-world 容器轻松确认 Docker 是否按预期工作。对于你的第一章来说还不错，对吧？好了，有了这个基础和你新准备好的 Docker 工作站，让我们直接进入第二章 *学习 Docker 命令*，在那里我们将学习许多你每天都会使用的 Docker 命令。

# 参考资料

+   Docker for Windows 限制：[`docs.docker.com/docker-for-windows/troubleshoot/#limitations-of-windows-containers-for-localhost-and-published-ports`](https://docs.docker.com/docker-for-windows/troubleshoot/#limitations-of-windows-containers-for-localhost-and-published-ports)

+   Docker for Mac 限制：[`docs.docker.com/v17.09/docker-for-mac/networking/#known-limitations-use-cases-and-workarounds`](https://docs.docker.com/v17.09/docker-for-mac/networking/#known-limitations-use-cases-and-workarounds)


# 第二章：学习 Docker 命令

在本章中，我们将学习一些基本的 Docker 命令。虽然我们将重点关注最重要的命令之一，即`container run`命令，但我们也将涵盖许多其他您每天都会使用的命令。这些命令包括列出容器命令、停止容器命令和删除容器命令。在学习过程中，我们还将了解其他容器命令，如日志、检查、统计、附加、执行和提交。我认为您会发现本章对 Docker 教育是一个很好的基础。

BIC：国际集装箱局成立于 1933 年，是一个中立的、非营利性的国际组织，其使命是促进集装箱化和联运交通的安全、安全和可持续发展。

在本章结束时，您将了解以下内容：

+   当前和以前的命令行语法

+   使用版本命令的两种方式

+   如何使用`container run`命令及其许多可选参数

+   如何启动和停止容器、查看容器信息、与运行中的容器交互，以及如何保存和重用对容器所做的更改

# 技术要求

您将从 Docker 的公共仓库中拉取 Docker 镜像，并安装 jq 软件包，因此需要基本的互联网访问权限来执行本章中的示例。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter02`](https://github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter02)

查看以下视频以查看代码的实际操作：[`bit.ly/2P43WNT`](http://bit.ly/2P43WNT)

# 命令语法信息

在我们深入学习 Docker 命令及其众多选项之前，我想通知您的是 Docker CLI 在 2017 年 1 月发生了变化。

随着每个新版本的发布，Docker 命令和相关选项的数量都在增加。Docker 决定需要解决这种复杂性。因此，随着 Docker 版本 1.13 的发布（Docker 还在 2017 年更改了版本编号方案），CLI 命令已被划分为管理功能组。例如，现在有一个容器管理组的命令，以及一个镜像管理组的命令。这改变了您运行 Docker 命令的方式。以下是旧和新`run`命令的使用示例：

```
# the new command syntax...
docker container run hello-world
# the old command syntax...
docker run hello-world
```

这个变化提供了更好的命令组织，但也增加了命令行的冗长。这是一个权衡。就我所知，目前为止，旧的命令语法仍然适用于所有 Docker 命令，但在本书的其余示例中，我打算使用新的语法。至少我会尝试，因为旧习惯难改。

我想在这里提一点，大多数命令选项都有短格式和长格式。我会尝试在我的示例中至少分享一次长格式，这样你就会知道短版本代表什么。如果你安装了 Docker 命令行完成，它将是一个有用的资源，可以记住新的基于 Docker 管理的命令和可以与之一起使用的参数。这是容器命令的顶级命令完成帮助的样子：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/f5fa4bbe-0891-4883-8c95-ddb910ca7e9a.png)

该命令列表让我们提前了解了一些我们将在本章中审查的命令，所以让我们开始学习 Docker 命令。在第一章中，*设置 Docker 开发环境*，我们使用了两个非常常见的 Docker 命令：`version`命令和`run`命令。虽然你认为你已经了解了`version`命令的所有内容，但你可能会惊讶地发现它还有另一个技巧。Docker 的 version 命令还有另一个版本。

# version 命令

你已经使用了`docker --version`命令作为一个快速测试来确认 Docker 是否已安装。现在尝试一下没有破折号的命令：

```
docker version
```

这个版本的命令可以更详细地了解安装在系统上的 Docker 的版本。值得注意的是，docker-compose 命令，我们稍后会谈到，也有两个版本的 version 命令——一个带有破折号提供单行响应，另一个没有破折号，提供更多细节。

请记住，所有 Docker 命令都有一个丰富的帮助系统。尝试输入 Docker 命令的任何部分并使用`--help`参数来查看。例如，`docker container run --help`。

# Docker run 命令

由于我们将经常使用`run`命令，我们现在应该看一下。你已经以其最基本的形式使用了`run`命令：

```
# new syntax
# Usage: docker container run [OPTIONS] IMAGE [COMMAND] [ARG...]
docker container run hello-world

# old syntax
docker run hello-world
```

这个命令告诉 Docker，您想要基于描述为 hello-world 的镜像运行一个容器。您可能会问自己，当我安装 Docker 时，hello-world 容器镜像是否已安装？答案是否定的。`docker run`命令将查看本地容器镜像缓存，以查看是否有与所请求容器描述匹配的容器镜像。如果有，Docker 将从缓存的镜像中运行容器。如果在缓存中找不到所需的容器镜像，Docker 将访问 Docker 注册表，尝试下载容器镜像，并在此过程中将其存储在本地缓存中。然后 Docker 将从缓存中运行新下载的容器。

Docker 注册表只是一个集中存储和检索 Docker 镜像的地方。我们稍后会更多地讨论注册表和 Docker 注册表。现在，只需了解有本地镜像缓存和远程镜像存储这一点。当我们在第一章中运行 hello-world 容器时，您看到了本地未找到容器的过程，*设置 Docker 开发环境。*当 Docker 在本地缓存中找不到容器镜像并且必须从注册表中下载时，情况是这样的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/8d336a4c-94d9-4a62-832f-c6a370eb84de.png)

您可以使用 docker `pull`命令预先填充本地 docker 缓存，以便运行您计划运行的容器镜像；例如：

```
# new syntax
# Usage: docker image pull [OPTIONS] NAME[:TAG|@DIGEST]
docker image pull hello-world

# old syntax
docker pull hello-world
```

如果您使用`pull`命令预取容器镜像，当您执行 docker `run`命令时，它将在本地缓存中找到镜像，而无需再次下载。

您可能已经注意到在前面的屏幕截图中，您请求了 hello-world 容器镜像，Docker 未能在本地缓存中找到，然后从存储库中下载了`hello-world:latest`容器镜像。每个容器镜像描述由三个部分组成：

+   Docker 注册表主机名

+   斜杠分隔的名称

+   标签名称

第一部分，注册表主机名，我们还没有看到或使用过，但它是通过公共 Docker 注册表的默认值包含的。每当您不指定注册表主机名时，Docker 将隐式使用公共 Docker 注册表。此注册表主机名是`docker.io`。Docker 注册表的内容可以在[`hub.docker.com/explore`](https://hub.docker.com/explore)上浏览。这是 Docker 镜像的主要公共存储库。可以设置和使用其他公共或私有镜像注册表，并且许多公司将这样做，建立自己的私有 Docker 镜像注册表。我们将在第八章“Docker 和 Jenkins”中再谈一些相关内容。现在，只需了解 Docker 镜像描述的第一部分是托管容器镜像的注册表主机名。值得注意的是，注册表主机名可以包括端口号。这可以用于配置为在非默认端口值上提供数据的注册表。

容器镜像描述的第二部分是斜杠分隔的名称。这部分就像是容器镜像的路径和名称。有一些官方容器镜像不需要指定路径。对于这些镜像，您可以简单地指定斜杠分隔名称的名称部分。在我们的示例中，这是描述的 hello-world 部分。

容器镜像描述的第三部分是标签名称。这部分被认为是镜像的版本标签，但它不需要仅由数字组成。标签名称可以是任何一组 ASCII 字符，包括大写和小写字母，数字，破折号，下划线或句点。关于标签名称的唯一限制是它们不能以句点或破折号开头，并且必须少于 128 个字符。标签名称与斜杠分隔的名称之间用冒号分隔。这让我们回到之前看到的`hello-world:latest`镜像描述。与注册表主机名一样，标签名称有一个默认值。默认值是`latest`。在我们的示例中，使用的标签名称是默认值，并且在搜索和下载中显示为`hello-world:latest`。您可以在以下示例中看到所有这些内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/8e50f5e2-4ba1-4a13-962d-84665c6b3369.png)

我们确认了我们的本地镜像缓存是空的，使用`docker images`命令，然后拉取了完全限定的 hello-world 镜像以预取到我们的本地缓存中。然后我们使用了与之前所有的 hello-world 示例中相同的简短描述，Docker 运行容器而不再次下载，显示使用了默认值并且它们与完全限定的值匹配。

好的，现在我们已经了解了 Docker `run`命令的所有基础知识，让我们深入一点，检查一些你可以与`run`命令一起使用的可选参数。如果你查看完整的`run`命令语法，你会看到这样的内容：

```
# Usage:  docker container run [OPTIONS] IMAGE [COMMAND] [ARG...]
```

请注意命令的最后部分是`[COMMAND] [ARG...]`。这告诉我们`container run`命令有一个可选的命令参数，也可以包括自己的可选参数。Docker 容器镜像是使用默认命令构建的，当你基于该镜像运行容器时，会执行该默认命令。对于 hello-world 容器，默认命令是`/hello`。对于完整的 Ubuntu OS 容器，默认命令是`bash`。每当你运行一个 Ubuntu 容器并且没有指定在容器中运行的命令时，将使用默认命令。如果现在这些还不太清楚，不要担心——我们将在本章的*回到 Docker 运行命令*部分稍后讨论默认命令和在运行时覆盖它。现在，知道当你运行一个容器时，它将执行一个命令，要么是默认命令，要么是提供给`container run`命令的覆盖命令来在运行的容器中执行。最后一点注意：当运行容器的命令（默认或覆盖）终止时，容器将退出。在我们使用 hello-world 容器的示例中，一旦容器内的`/hello`命令终止，hello-world 容器就会退出。一会儿，你将了解更多关于运行中容器和已退出容器之间的区别。

现在，我们将继续讨论`run`命令的一个我最喜欢的可选参数，即`--rm`参数。这里需要一些背景信息。您可能还记得来自第一章的*设置 Docker 开发环境*，Docker 镜像由多个层组成。每当您运行一个 Docker 容器时，实际上只是使用本地缓存的 Docker 镜像（这是一堆层），并在其顶部创建一个新的读/写层。在容器运行期间发生的所有执行和更改都存储在其自己的读/写层中。

# 列出容器的命令

可以使用以下命令显示运行中的容器：

```
# Usage: docker container ls [OPTIONS]
docker container ls
```

这是列出容器的命令，如果没有任何额外的参数，它将列出当前正在运行的容器。我所说的当前运行是什么意思？容器是在系统上运行的特殊进程，就像系统上的其他进程一样，容器可以停止或退出。然而，与系统上其他类型的进程不同，容器的默认行为是在停止时保留其读/写层。这是因为如果需要，您可以重新启动容器，保持其退出时的状态数据。举个例子，假设您运行一个作为操作系统的容器，比如 Ubuntu，在该容器中安装了`wget`。容器退出后，您可以重新启动它，它仍然安装了`wget`。请记住，每个运行的容器都有自己的读/写层，因此，如果您运行一个 Ubuntu 容器并安装了`wget`，然后运行另一个 Ubuntu 容器，它将不会有`wget`。读/写层在容器之间不共享。但是，如果重新启动安装了`wget`的容器，它仍然会安装。

因此，运行中的容器和停止的容器之间的区别在于进程是正在运行还是已退出，留下了自己的读/写层。有一个参数可以让您列出所有容器，包括正在运行和已退出的容器。您可能已经猜到了，它是`--all`参数，它看起来像这样：

```
# short form of the parameter is -a
docker container ls -a
# long form is --all
docker container ls --all

# old syntax
docker ps -a
```

现在，让我们回到我最喜欢的可选运行命令参数之一，即`--rm`参数：

```
# there is no short form of the --rm parameter
docker container run --rm hello-world
```

此参数指示 Docker 在容器退出时自动删除容器的读/写层。当您运行一个 docker 容器而没有`--rm`参数时，容器数据在容器退出时会被留下，以便稍后可以重新启动容器。然而，如果在运行容器时包括`--rm`参数，那么在容器退出时所有容器的读/写数据都会被删除。这个参数提供了一个在`exit`时进行简单清理的功能，这在很多情况下都会非常有用。让我们通过一个快速示例来看一下，使用我们刚刚讨论过的 run 和`container ls`命令：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/537bbccb-96a6-49ac-8ed4-f80ef15988f7.png)

首先，我们确认我们的本地缓存中有 hello-world 镜像。接下来，我们列出了系统上所有的容器，包括正在运行和已退出的。请注意镜像和容器之间的区别。如果您熟悉 VMware，类似于模板和虚拟机的类比。接下来，我们使用`--rm`参数运行了 hello-world 容器。hello-world 容器打印其消息，然后立即退出（我们将输出重定向到`/dev/null`，以使示例输出变短）。接下来，我们再次列出了容器，因为我们看到 hello-world 容器的读/写数据在容器退出时被自动删除了。之后，我们再次运行了 hello-world 容器，但这次没有使用`--rm`参数。当我们这次列出容器时，我们看到了（已退出）容器的指示。通常，您会运行一个容器，知道您以后永远不需要重新启动它，并使用`--rm`参数自动清理它非常方便。但如果您不使用`--rm`参数会怎么样呢？您会被困在一个不断增长的容器列表中吗？当然不会。Docker 有一个命令来处理这个问题。那就是`container rm`命令。

# 删除容器命令

删除容器命令看起来像这样：

```
# the new syntax
# Usage: docker container rm [OPTIONS] CONTAINER [CONTAINER...]
docker container rm cd828234194a

# the old syntax
docker rm cd828234194a
```

该命令需要一个唯一标识容器的值；在本例中，我使用了刚刚运行的 hello-world 容器的完整容器 ID。您可以使用容器 ID 的前几个字符，只要它在系统上提供了唯一标识符。另一种唯一标识容器的方法是通过分配给它的`name`。当您运行容器时，Docker 将为其提供一个唯一的随机生成的名称。在上面的示例中，分配的随机名称是`competent_payne`。因此，我们可以像这样使用删除命令： 

```
# using the randomly generated name docker container rm competent_payne
```

虽然 Docker 提供的随机生成的名称比其分配的容器 ID 更易读，但它们可能仍然不如您希望的那样相关。这就是为什么 Docker 为`run`命令提供了一个可选参数来为您的容器命名。以下是使用`--name`参数的示例：

```
# using our own name docker container run --name hi-earl hello-world
```

现在，当我们列出所有容器时，我们可以看到我们的容器名称为`hi-earl`。当然，您可能希望使用更好的容器名称，也许是描述容器执行功能的名称，例如`db-for-earls-app`。

注意：与容器 ID 一样，容器名称在主机上必须是唯一的。您不能有两个具有相同名称的容器（即使其中一个已退出）。如果将有多个运行相同镜像的容器，例如 Web 服务器镜像，请为它们分配唯一的名称，例如 web01 和 web02。![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/9d9bae7d-2569-4d62-b104-0f77cef7e52c.png)

您可以通过在命令行上提供每个容器的唯一标识符来同时删除多个容器：

```
# removing more than one docker container rm hi-earl hi-earl2
```

通常，您只会在容器退出后删除容器，例如我们一直在使用的 hello-world 容器。但是，有时您可能希望删除当前正在运行的容器。您可以使用`--force`参数来处理这种情况。以下是使用 force 参数删除运行中容器的示例：

```
# removing even if it is running docker container rm --force web-server
```

以下是它的样子：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/e6d64ba5-07f6-4495-a2d1-b8e9b6964384.png)

请注意，在第一个`container ls`命令中，我们没有使用`--all`参数。这提醒我们 Web 服务器容器正在运行。当我们尝试删除它时，我们被告知容器仍在运行，不会被删除。这是一个很好的保障，有助于防止删除运行中的容器。接下来，我们使用了强制命令，运行中的容器被删除而没有任何警告。最后，我们进行了另一个`container ls`命令，包括`--all`参数，以显示这次实际上删除了我们容器的读/写数据。

如果您已经设置了 Docker 命令完成，您可以输入命令，直到需要输入容器的唯一标识符，然后使用*Tab*键获取容器列表，切换到您想要删除的容器。一旦您突出显示要删除的容器，使用空格键或*Enter*键进行选择。您可以再次按*Tab*键选择另一个要一次删除多个容器。选择所有容器后，按*Enter*执行命令。请记住，除非包括强制参数`rm -f`，否则在为`rm`命令切换时，您只会看到已停止的容器。

有时，您可能希望删除系统上的所有容器，无论是否正在运行。有一种有用的方法来处理这种情况。您可以结合`container ls`命令和容器删除命令来完成任务。您将使用`container ls`命令的新参数来完成这个任务——`--quiet`参数。此命令指示 Docker 仅返回容器 ID，而不是带有标题的完整列表。以下是命令：

```
# list just the container IDs docker container ls --all --quiet
```

现在我们可以将`container ls`命令返回的值作为输入参数提供给容器删除命令。它看起来像这样：

```
# using full parameter names
docker container rm --force $(docker container ls --all --quiet)
# using short parameter names
docker container rm -f $(docker container ls -aq)

# using the old syntax
docker rm -f $(docker ps -aq)
```

这将从您的系统中删除*所有*容器*运行和退出*，所以要小心！

您可能经常使用这个快捷方式，所以为它创建一个系统别名非常方便。

您可以将以下内容添加到您的`~/.bash_profile`或`~/zshrc`文件中：`alias RMAC='docker container rm --force $(docker container ls --all --quiet)'。

许多容器被设计为运行并立即退出，例如我们已经多次使用的 hello-world 示例。其他容器的镜像被创建为，当您使用它运行容器时，容器将继续运行，提供一些持续有用的功能，例如提供网页服务。当您运行一个持久的容器时，它将保持前台进程直到退出，并附加到进程：标准输入、标准输出和标准错误。这对于一些测试和开发用例来说是可以的，但通常情况下，这不适用于生产容器。相反，最好将`container run`作为后台进程运行，一旦启动就将控制权交还给您的终端会话。当然，有一个参数可以实现这一点。那就是`--detach`参数。使用该参数的效果如下：

```
# using the full form of the parameter
docker container run --detach --name web-server --rm nginx
# using the short form of the parameter
docker container run -d --name web-server --rm nginx
```

使用此参数将进程从前台会话中分离，并在容器启动后立即将控制权返回给您。您可能的下一个问题是，如何停止一个分离的容器？好吧，我很高兴您问了。您可以使用`container stop`命令。

# 停止容器命令

停止命令很容易使用。以下是命令的语法和示例：

```
# Usage: docker container stop [OPTIONS] CONTAINER [CONTAINER...]
docker container stop web-server
```

在我们的情况下，运行容器时我们使用了`--rm`参数，因此一旦容器停止，读/写层将被自动删除。与许多 Docker 命令一样，您可以提供多个唯一的容器标识符作为参数，以一条命令停止多个容器。

现在您可能会想知道，如果我使用`--detach`参数，我如何查看容器的运行情况？有几种方法可以从容器中获取信息。让我们在继续运行参数探索之前先看看其中一些。

# 容器日志命令

当您在前台运行容器时，容器发送到标准输出和标准错误的所有输出都会显示在运行容器的会话控制台中。然而，当您使用`--detach`参数时，容器一旦启动，会立即返回会话控制，因此您看不到发送到`stdout`和`stderr`的数据。如果您想查看这些数据，可以使用`container logs`命令。该命令如下：

```
# the long form of the command
# Usage: docker container logs [OPTIONS] CONTAINER
docker container logs --follow --timestamps web-server
# the short form of the command
docker container logs -f -t web-server

# get just the last 5 lines (there is no short form for the "--tail" parameter)
docker container logs --tail 5 web-server

# the old syntax
docker logs web-server
```

`--details`、`--follow`、`--timestamps`和`--tail`参数都是可选的，但我在这里包括了它们以供参考。当您使用`container logs`命令而没有可选参数时，它将只是将容器日志的所有内容转储到控制台。您可以使用`--tail`参数加上一个数字来仅转储最后几行。您可以组合这些参数（除了`--tail`和`--follow`）以获得您想要的结果。`--follow`参数就像在查看不断写入的日志时使用`tail -f`命令，并将每行写入日志时显示出来。您可以使用*Ctrl *+ *C* 退出正在跟踪的日志。`--timestamps`参数非常适合评估写入容器日志的频率。

# 容器顶部命令

您可能并不总是只想查看容器的日志；有时您想知道容器内运行着哪些进程。这就是`container top`命令的用处。理想情况下，每个容器都运行一个进程，但世界并不总是理想的，因此您可以使用这样的命令来查看目标容器中运行的所有进程：

```
# using the new syntax
# Usage: docker container top CONTAINER [ps OPTIONS]
docker container top web-server

# using the old syntax
docker top web-server
```

正如您可能期望的那样，`container top`命令只用于一次查看单个容器的进程。

# 容器检查命令

当您运行容器时，会有大量与容器关联的元数据。有许多时候您会想要查看那些元数据。用于执行此操作的命令是：

```
# using the new syntax
# Usage: docker container inspect [OPTIONS] CONTAINER [CONTAINER...]
docker container inspect web-server

# using the old syntax
docker inspect web-server
```

如前所述，此命令返回大量数据。您可能只对元数据的子集感兴趣。您可以使用`--format`参数来缩小返回的数据。查看这些示例：

+   获取一些状态数据：

```
# if you want to see the state of a container you can use this command
docker container inspect --format '{{json .State}}' web-server1 | jq

# if you want to narrow the state data to just when the container started, use this command
docker container inspect --format '{{json .State}}' web-server1 | jq '.StartedAt'
```

+   获取一些`NetworkSettings`数据：

```
# if you are interested in the container's network settings, use this command
docker container inspect --format '{{json .NetworkSettings}}' web-server1 | jq

# or maybe you just want to see the ports used by the container, here is a command for that
docker container inspect --format '{{json .NetworkSettings}}' web-server1 | jq '.Ports'

# maybe you just want the IP address used by the container, this is the command you could use.
docker container inspect -f '{{json .NetworkSettings}}' web-server1 | jq '.IPAddress'
```

+   使用单个命令获取多个容器的数据：

```
# maybe you want the IP Addresses for a couple containers
docker container inspect -f '{{json .NetworkSettings}}' web-server1 web-server2 | jq '.IPAddress'

# since the output for each container is a single line, this one can be done without using jq
docker container inspect -f '{{ .NetworkSettings.IPAddress }}' web-server1 web-server2 web-server3
```

这些示例大多使用 json 处理器`jq`。如果您尚未在系统上安装它，现在是一个很好的时机。以下是在本书中使用的每个操作系统上安装`jq`的命令：

```
# install jq on Mac OS
brew install jq

# install jq on ubuntu
sudo apt-get install jq

# install jq on RHEL/CentOS
yum install -y epel-release
yum install -y jq

# install jq on Windows using Chocolatey NuGet package manager
chocolatey install jq
```

inspect 命令的`--format`参数使用 go 模板。您可以在 Docker 文档页面上找到有关它们的更多信息，用于格式化输出：[`docs.docker.com/config/formatting`](https://docs.docker.com/config/formatting)。

# 容器统计命令

另一个非常有用的 Docker 命令是 stats 命令。它为一个或多个正在运行的容器提供实时、持续更新的使用统计信息。这有点像使用 Linux 的`top`命令。您可以不带参数运行该命令，以查看所有正在运行的容器的统计信息，或者您可以提供一个或多个唯一的容器标识符，以查看一个或多个容器的特定容器的统计信息。以下是使用该命令的一些示例：

```
# using the new syntax, view the stats for all running containers
# Usage: docker container stats [OPTIONS] [CONTAINER...]
docker container stats

# view the stats for just two web server containers
docker container stats web-server1 web-server2

# using the old syntax, view stats for all running containers
docker stats
```

当您查看了足够的统计信息后，您可以使用 C*trl* + *C*退出视图。

回到`run`命令参数，接下来，我们将讨论通常一起使用的`run`命令的两个参数。有时候你运行一个容器，你想与它进行交互式会话。例如，您可能运行一个在更多或更少完整的操作系统（如 Ubuntu）内执行某些应用程序的容器，并且您希望在该容器内部进行访问以更改配置或调试一些问题，类似于使用 SSH 连接到服务器。与大多数 Docker 相关的事情一样，有多种方法可以实现这一点。一种常见的方法是使用`run`命令的两个可选参数：`--interactive`和`--tty`。现在让我们看看它是如何工作的。您已经看到我们如何使用`--detach`参数启动与我们正在运行的容器断开连接：

```
# running detached docker container run --detach --name web-server1 nginx
```

当我们运行此命令启动我们的 nginx web 服务器并浏览`http://localhost`时，我们发现它没有提供我们期望的欢迎页面。因此，我们决定进行一些调试，而不是从容器中分离出来，我们决定使用两个`--interactive`和`--tty`参数进行交互式运行。现在，由于这是一个 nginx 容器，它在容器启动时执行一个默认命令。该命令是`nginx -g 'daemon off;'`。由于这是默认命令，与容器进行交互对我们没有任何好处。因此，我们将通过在运行命令中提供一个参数来覆盖默认命令。它看起来会像这样：

```
# using the long form of the parameters
docker container run --interactive --tty --name web-server2 nginx bash

# using the short form of the parameters (joined as one), which is much more common usage
docker container run -it --name web-server2 nginx bash
```

这个命令将像以前一样运行容器，但是不会执行默认命令，而是执行`bash`命令。它还会打开一个与容器交互的终端会话。根据需要，我们可以以`root`用户的身份在容器内执行命令。我们可以查看文件夹和文件，编辑配置设置，安装软件包等等。我们甚至可以运行镜像的默认命令，以查看是否解决了任何问题。这里有一个有点牵强的例子：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/5355ddb7-ef52-4406-9397-c7839cf8de8f.png)

您可能已经注意到了`-p 80:80`参数。这是发布参数的简写形式，我们将在*回到 Docker 运行命令*部分讨论。使用`container ls`命令，您可以看到使用默认命令运行容器与使用覆盖命令运行容器之间的区别：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/339ffd7a-c93b-466f-b9f1-e389a763598b.png)

Web 服务器运行使用了默认的 CMD，而 web-server2 使用了覆盖的 CMD `bash`。这是一个牵强的例子，帮助您理解这些概念。一个真实的例子可能是当您想要与基于操作系统的容器进行交互连接时，比如 Ubuntu。您可能还记得在第一章的开头，*设置 Docker 开发环境*中提到，默认在 Ubuntu 容器中运行的命令是`bash`。既然如此，您就不必提供一个命令来覆盖默认值。您可以使用这样的运行命令：

```
# running interactively with default CMD docker container run -it --name earls-dev ubuntu
```

使用这个`container run`命令，您可以连接到正在运行的 Ubuntu 容器的交互式终端会话。您可以做几乎任何您通常在连接到 Ubuntu 服务器时会做的事情。您可以使用`apt-get`安装软件，查看运行中的进程，执行`top`命令等等。可能会像这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/9fafd0d2-f070-4432-bea9-b6d2a7a141ba.png)

还有一些其他容器命令可以帮助您与已经运行并分离的容器进行交互。现在让我们快速看一下这些命令。

# 容器附加命令

假设您有一个正在运行的容器。它当前与您的终端会话分离。您可以使用`container attach`命令将该容器的执行进程带到您的终端会话的前台进程。让我们使用之前使用过的 web 服务器示例：

```
# run a container detached
docker container run --detach -it --name web-server1 -p 80:80 nginx

# show that the container is running
docker container ps

# attach to the container
# Usage: docker container attach [OPTIONS] CONTAINER
docker container attach web-server1

# issue a *Ctrl* + *PQ* keystroke to detach (except for Docker on Mac, see below for special Mac instructions)

# again, show that the container is running detached.
docker container ps
```

当你附加到运行的容器时，它的执行命令将成为你的终端会话的前台进程。要从容器中分离，你需要发出*Ctrl* + *PQ*按键。如果你发出*Ctrl* + *C*按键，容器的执行进程将接收到 sig-term 信号并终止，这将导致容器退出。这通常是不希望的。所以记住要使用*Ctrl* + *PQ*按键来分离。

然而，在 macOS 上存在一个已知问题：对于 Mac 上的 Docker，*Ctrl* + *PQ*按键组合不起作用，除非你在`attach`命令上使用另一个参数，`--sig-proxy=false`参数，否则你将无法在不使用*Ctrl *+ *C*按键的情况下从容器中分离出来：

```
# when you are using Docker for Mac, remember to always add the "--sig-proxy=false" parameter
docker attach --sig-proxy=false web-server1
```

当你向`attach`命令提供`--sig-proxy=false`参数时，你可以向附加的容器发出*Ctrl *+ *C*按键，它将分离而不向容器进程发送 sig-term 信号，从而使容器再次以分离状态运行，脱离你的终端会话：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/fcf8b70a-0e46-4ad1-a260-d783fadf9ca6.png)

# 容器 exec 命令

有时，当你有一个以分离状态运行的容器时，你可能想要访问它，但不想附加到执行命令。你可以通过使用容器 exec 命令来实现这一点。这个命令允许你在运行的容器中执行另一个命令，而不附加或干扰已经运行的命令。这个命令经常用于创建与已经运行的容器的交互会话，或者在容器内执行单个命令。命令看起来像这样：

```
# start an nginx container detached
docker container run --detach --name web-server1 -p 80:80 nginx

# see that the container is currently running
docker container ls

# execute other commands in the running container
# Usage: docker container exec [OPTIONS] CONTAINER COMMAND [ARG...] docker container exec -it web-server1 bash
docker container exec web-server1 cat /etc/debian_version

# confirm that the container is still running 
docker container ls
```

当`exec`命令完成时，你退出 bash shell，或者文件内容已经被替换，然后它会退出到终端会话，让容器以分离状态运行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/fb344e4d-5ba7-440f-af71-9b42c8c4ccce.png)

让我们在继续讨论许多可选的`container run`参数之前，先看看另一个 Docker 命令。

# 容器 commit 命令

重要的是要知道，当您连接到正在运行的容器并对其进行更改，比如安装新的软件包或更改配置文件时，这些更改只适用于该正在运行的容器。例如，如果您使用 Ubuntu 镜像运行一个容器，然后在该容器中安装`curl`，那么这个更改不会应用到您从中运行容器的镜像，例如 Ubuntu。如果您要从相同的 Ubuntu 镜像启动另一个容器，您需要再次安装`curl`。但是，如果您希望在运行新容器时保留并使用在运行容器内进行的更改，您可以使用`container commit`命令。`container commit`命令允许您保存容器的当前读/写层以及原始镜像的层，从而创建一个全新的镜像。当您使用新镜像运行容器时，它将包括您使用`container commit`命令保存的更改。`container commit`命令的样子如下：

```
# Usage: docker container commit [OPTIONS] CONTAINER [REPOSITORY[:TAG]]
docker container commit ubuntu new-ubuntu
```

这里有一个使用`container commit`命令将`curl`安装到正在运行的容器中，并创建一个包含安装的`curl`命令的新容器的示例：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/47f18f01-68e7-42e5-80de-4dacdf2aad16.png)

有了这个例子，我现在可以从`ubuntu-curl`镜像运行新的容器，它们都将已经安装了`curl`命令。

# 回到 Docker 运行命令

现在，让我们回到讨论`container run`命令。之前，您看到了使用`run`命令和`--publish`参数的示例。使用可选的发布参数允许您指定与运行容器相关的将要打开的端口。`--publish`参数包括用冒号分隔的端口号对。例如：

```
# create an nginx web-server that redirects host traffic from port 8080 to port 80 in the container
docker container run --detach --name web-server1 --publish 8080:80 nginx
```

第一个端口号与运行容器的主机相关联。在 nginx 示例中，`8080`在主机上暴露；在我们的情况下，那将是`http://localhost:8080`。第二个端口号是运行容器上打开的端口。在这种情况下，它将是`80`。描述`--publish 8080:80`参数时，您可以说类似于，发送到主机上端口`8080`的流量被重定向到运行容器上的端口`80`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/3309bf24-df9f-47bf-b97c-9bc3112928fb.png)

重要的区别在于主机端口和容器端口。我可以在同一系统上运行多个暴露端口`80`的容器，但是每个端口在主机上只能有一个容器的流量。看下面的例子更好地理解：

```
# all of these can be running at the same time
docker container run --detach --name web-server1 --publish 80:80 nginx
docker container run --detach --name web-server2 --publish 8000:80 nginx
docker container run --detach --name web-server3 --publish 8080:80 nginx
docker container run --detach --name web-server4 --publish 8888:80 nginx # however if you tried to run this one too, it would fail to run 
# because the host already has port 80 assigned to web-server1
docker container run --detach --name web-server5 --publish 80:80 nginx
```

要知道这是网络的一般限制，而不是 Docker 或容器的限制。在这里我们可以看到这些命令及其输出。注意端口和名称，以及已经使用的端口作为端点的使用失败：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/60594bf1-705f-48cf-9ecd-60d4691320be.png)

这是关于`container run`命令的各种选项参数的大量数据。这并不是所有的选项参数，但应该足够让你有一个很好的开始。如果你想了解更多我们探讨的可选参数，或者找出我们没有涵盖的内容，一定要访问 docker 文档页面上的`container run`命令，网址是[`docs.docker.com/engine/reference/run/`](https://docs.docker.com/engine/reference/run/)。

# 总结

在本章中，我们学习了关于 Docker 镜像描述和 Docker 注册表的知识。然后我们看到了版本命令的另一种形式。之后，我们探索了许多 Docker 容器命令，包括`run`、`stop`、`ls`、`logs`、`top`、`stats`、`attach`、`exec`和`commit`命令。最后，我们了解了如何通过从主机到容器打开端口来暴露您的容器。你应该对 Docker 已经能做的事情感到很满意，但是请稍等，在第三章 *创建 Docker 镜像*中，我们将向您展示如何使用`Dockerfile`和镜像构建命令创建自己的 Docker 镜像。如果你准备好了，翻页吧。

# 参考

+   Docker 注册表：[`hub.docker.com/explore/`](https://hub.docker.com/explore/)

+   所有`container run`命令的参数：[`docs.docker.com/engine/reference/run/`](https://docs.docker.com/engine/reference/run/)

+   使用`--format`参数与容器检查命令：[`docs.docker.com/config/formatting`](https://docs.docker.com/config/formatting)

+   json jq 解析器：[`stedolan.github.io/jq/`](https://stedolan.github.io/jq/)

+   Chocolatey Windows 软件包管理器：[`chocolatey.org/`](https://chocolatey.org/)


# 第三章：创建 Docker 镜像

在本章中，我们将学习如何创建企业级的 Docker 镜像。我们将首先学习 Docker 镜像的主要构建块，具体来说是 Dockerfile。然后，我们将探索 Dockerfile 中可用的所有指令。有一些指令在表面上看起来非常相似。我们将揭示`COPY`和`ADD`指令之间的区别，`ENV`和`ARG`指令之间的区别，以及最重要的是`CMD`和`ENTRYPOINT`指令之间的区别。接下来，我们将了解构建上下文是什么以及为什么它很重要。最后，我们将介绍实际的镜像构建命令。

如果得到良好维护，普通的集装箱的平均寿命约为 20 年，而 Docker 容器的平均寿命为 2.5 天。- [`www.tintri.com/blog/2017/03/tintri-supports-containers-advanced-storage-features`](https://www.tintri.com/blog/2017/03/tintri-supports-containers-advanced-storage-features)

在本章中，我们将涵盖以下主题：

+   什么是 Dockerfile？

+   Dockerfile 中可以使用的所有指令

+   何时使用`COPY`或`ADD`指令

+   `ENV`和`ARG`变量之间的区别

+   为什么要使用`CMD`和`ENTRYPOINT`指令

+   构建上下文的重要性

+   使用 Dockerfile 构建 Docker 镜像

# 技术要求

您将从 Docker 的公共存储库中拉取 Docker 镜像，因此需要基本的互联网访问权限来执行本章中的示例。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter03`](https://github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter03)

查看以下视频以查看代码的实际操作：[`bit.ly/2rbHvwC`](http://bit.ly/2rbHvwC)

# 什么是 Dockerfile？

您在第二章中学到，您可以运行 Docker 容器，对正在运行的容器进行修改，然后使用`docker commit`命令保存这些更改，从而有效地创建一个新的 Docker 镜像。尽管这种方法有效，但不是创建 Docker 容器的首选方式。创建 Docker 镜像的最佳方式是使用具有描述所需镜像的 Dockerfile 的 Docker 镜像构建命令。

Dockerfile（是的，正确的拼写是一个词，首字母大写*D*）是一个文本文件，其中包含 Docker 守护程序用来创建 Docker 镜像的指令。指令使用一种键值对语法进行定义。每个指令都在 Dockerfile 中占据一行。虽然 Dockerfile 指令不区分大小写，但有一个常用的约定，即指令单词始终大写。

Dockerfile 中指令的顺序很重要。指令按顺序评估，从 Dockerfile 的顶部开始，直到文件的底部结束。如果您还记得第一章中的内容，Docker 镜像由层组成。Dockerfile 中的所有指令都会导致生成一个新的层，因此在构建 Docker 镜像时，但是，某些指令只会向创建的镜像添加一个大小为零的元数据层。由于最佳实践是尽可能保持 Docker 镜像尽可能小，因此您将希望尽可能高效地使用创建非零字节大小层的指令。在接下来的部分中，我们将注意到使用指令创建非零字节大小层的地方，以及如何最好地使用该指令来最小化层数量和大小。另一个重要的考虑因素是指令的顺序。某些指令必须在其他指令之前使用，但除了这些例外情况，您可以按任何顺序放置其他指令。最佳实践是在 Dockerfile 的早期使用变化最小的指令，在 Dockerfile 的后期使用变化更频繁的指令。原因是当您需要重新构建镜像时，只有在 Dockerfile 中第一行更改的位置或之后的层才会被重新构建。如果您还不理解这一点，不用担心，一旦我们看到一些例子，它就会更有意义。

我们将在本节末尾回顾构建命令，但我们将从 Dockerfile 可用的指令开始，首先是必须是 Dockerfile 中的第一个指令的指令：`FROM`指令。

# FROM 指令

每个 Dockerfile 必须有一个`FROM`指令，并且它必须是文件中的第一个指令。（实际上，`FROM`指令之前可以使用 ARG 指令，但这不是必需的指令。我们将在 ARG 指令部分更多地讨论这个。）

`FROM`指令设置正在创建的镜像的基础，并指示 Docker 守护程序新镜像的基础应该是指定为参数的现有 Docker 镜像。指定的镜像可以使用与我们在第二章中看到的 Docker `container run`命令相同的语法来描述。在这里，它是一个`FROM`指令，指定使用官方的`nginx`镜像，版本为 1.15.2：

```
# Dockerfile
FROM nginx:1.15.2
```

请注意，在这个例子中，没有指定指示指定的镜像是官方 nginx 镜像的存储库。如果没有指定标签，将假定为`latest`标签。

`FROM`指令将创建我们新镜像中的第一层。该层将是指令参数中指定的镜像大小，因此最好指定满足新镜像所需条件的最小镜像。一个特定于应用程序的镜像，比如`nginx`，会比一个操作系统镜像，比如 ubuntu，要小。而`alpine`的操作系统镜像会比其他操作系统的镜像，比如 Ubuntu、CentOS 或 RHEL，要小得多。`FROM`指令可以使用一个特殊的关键字作为参数。它是`scratch`。Scratch 不是一个可以拉取或运行的镜像，它只是向 Docker 守护程序发出信号，表明你想要构建一个带有空基础镜像层的镜像。`FROM scratch`指令被用作许多其他基础镜像的基础层，或者用于专门的应用程序特定镜像。你已经看到了这样一个专门的应用程序镜像的例子：hello-world。hello-world 镜像的完整 Dockerfile 如下：

```
# hello-world Dockerfile
FROM scratch
COPY hello /
CMD ["/hello"]
```

我们将很快讨论`COPY`和`CMD`指令，但是你应该根据它的 Dockerfile 来感受一下 hello-world 镜像有多小。在 Docker 镜像的世界中，越小越好。参考一下一些镜像的大小：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/3e91115f-6c8d-4634-8638-b0c8e051a85b.png)

# 标签指令

LABEL 指令是向 Docker 镜像添加元数据的一种方法。当创建镜像时，此指令会向镜像添加嵌入式键值对。一个镜像可以有多个 LABEL，并且每个 LABEL 指令可以提供一个或多个标签。LABEL 指令最常见的用途是提供有关镜像维护者的信息。这些数据以前有自己的指令。请参阅有关现在已弃用的 MAINTAINER 指令的下面提示框。以下是一些有效的 LABEL 指令示例：

```
# LABEL instruction syntax
# LABEL <key>=<value> <key>=<value> <key>=<value> ...
LABEL maintainer="Earl Waud <earlwaud@mycompany.com>"
LABEL "description"="My development Ubuntu image"
LABEL version="1.0"
LABEL label1="value1" \
 label2="value2" \
 lable3="value3"
LABEL my-multi-line-label="Labels can span \
more than one line in a Dockerfile."
LABEL support-email="support@mycompany.com" support-phone="(123) 456-7890"
```

LABEL 指令是 Dockerfile 中可以多次使用的指令之一。你将会在后面学到，一些可以多次使用的指令只会保留最后一次使用的内容，忽略之前的所有使用。但是 LABEL 指令不同。每次使用 LABEL 指令都会向生成的镜像添加一个额外的标签。然而，如果两次或更多次使用 LABEL 具有相同的键，标签将获得最后一个匹配的 LABEL 指令中提供的值。就像这样：

```
# earlier in the Dockerfile
LABEL version="1.0"
# later in the Dockerfile...
LABEL version="2.0"
# The Docker image metadata will show version="2.0"
```

重要的是要知道，在你的 FROM 指令中指定的基础镜像可能包含使用 LABEL 指令创建的标签，并且它们将自动包含在你正在构建的镜像的元数据中。如果你的 Dockerfile 中的 LABEL 指令使用与 FROM 镜像的 Dockerfile 中使用的 LABEL 指令相同的键，你（后来的）值将覆盖 FROM 镜像中的值。你可以使用 inspect 命令查看镜像的所有标签：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/c01d1aab-1110-46c5-9623-cad509812cc6.png)

MAINTAINER 指令有一个专门用于提供有关镜像维护者信息的 Dockerfile 指令，但是这个指令已经被弃用。不过，你可能会在某个时候看到它在 Dockerfile 中被使用。语法如下：`"maintainer": "Earl Waud <earlwaud@mycompany.com>"`。

# COPY 指令

你已经在“FROM 指令”部分的 hello-world Dockerfile 中看到了使用 COPY 指令的示例。COPY 指令用于将文件和文件夹复制到正在构建的 Docker 镜像中。COPY 指令的语法如下：

```
# COPY instruction syntax
COPY [--chown=<user>:<group>] <src>... <dest>
# Use double quotes for paths containing whitespace)
COPY [--chown=<user>:<group>] ["<src>",... "<dest>"]
```

请注意，--chown 参数仅适用于基于 Linux 的容器。如果没有--chown 参数，所有者 ID 和组 ID 都将设置为 0。

`<src>`或源是文件名或文件夹路径，并且被解释为相对于构建的上下文。我们稍后会在本章中更多地讨论构建上下文，但现在，将其视为构建命令运行的位置。源可能包括通配符。

`<dest>`或目标是正在创建的图像中的文件名或路径。目标是相对于图像文件系统的根目录，除非有一个前置的`WORKDIR`指令。我们稍后会讨论`WORKDIR`指令，但现在，只需将其视为设置当前工作目录的一种方式。当`COPY`命令在 Dockerfile 中的`WORKDIR`指令之后出现时，复制到图像中的文件或文件夹将被放置在相对于当前工作目录的目标中。如果目标包括一个或多个文件夹的路径，如果它们不存在，所有文件夹都将被创建。

在我们之前的 hello-world Dockerfile 示例中，您看到了一个`COPY`指令，它将一个名为`hello`的可执行文件复制到图像的文件系统根位置。它看起来像这样：`COPY hello /`。这是一个基本的`COPY`指令。以下是一些其他示例：

```
# COPY instruction Dockerfile for Docker Quick Start
FROM alpine:latest
LABEL maintainer="Earl Waud <earlwaud@mycompany.com>"
LABEL version=1.0
# copy multiple files, creating the path "/theqsg/files" in the process
COPY file* theqsg/files/
# copy all of the contents of folder "folder1" to "/theqsg/" 
# (but not the folder "folder1" itself)
COPY folder1 theqsg/
# change the current working directory in the image to "/theqsg"
WORKDIR theqsg
# copy the file special1 into "/theqsg/special-files/"
COPY --chown=35:35 special1 special-files/
# return the current working directory to "/"
WORKDIR /
CMD ["sh"]
```

通过从图像运行容器并执行`ls`命令，我们可以看到使用前面的 Dockerfile 得到的图像文件系统会是什么样子：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/442d213e-eea8-4ca6-bee4-253d64e84aa5.png)

您可以看到在目标路径中指定的文件夹在复制期间被创建。您还会注意到提供`--chown`参数会设置目标文件的所有者和组。一个重要的区别是当源是一个文件夹时，文件夹的内容会被复制，但文件夹本身不会被复制。请注意，使用`WORKDIR`指令会更改图像文件系统中的路径，并且随后的`COPY`指令现在将相对于新的当前工作目录。在这个例子中，我们将当前工作目录返回到`/`，以便在容器中执行的命令将相对于`/`运行。

# ADD 指令

`ADD`指令用于将文件和文件夹复制到正在构建的 Docker 图像中。`ADD`指令的语法如下：

```
# ADD instruction syntax
ADD [--chown=<user>:<group>] <src>... <dest>
# Use double quotes for paths containing whitespace)
ADD [--chown=<user>:<group>] ["<src>",... "<dest>"]
```

现在，您可能会认为`ADD`指令似乎就像我们刚刚审查的`COPY`指令一样。嗯，你没错。基本上，我们看到`COPY`指令所做的所有事情，`ADD`指令也可以做。它使用与`COPY`指令相同的语法，两者之间的`WORKDIR`指令的效果也是相同的。那么，为什么我们有两个执行相同操作的命令呢？

# COPY 和 ADD 之间的区别

答案是`ADD`指令实际上可以比`COPY`指令做更多。更多取决于用于源输入的值。使用`COPY`指令时，源可以是文件或文件夹。然而，使用`ADD`指令时，源可以是文件、文件夹、本地`.tar`文件或 URL。

当`ADD`指令的源值是`.tar`文件时，该 TAR 文件的内容将被提取到镜像中的相应文件夹中。

当您在`ADD`指令中使用`.tar`文件作为源并包括`--chown`参数时，您可能期望在从存档中提取的文件上设置图像中的所有者和组。目前情况并非如此。不幸的是，尽管使用了`--chown`参数，提取内容的所有者、组和权限将与存档中包含的内容相匹配。当您使用`.tar`文件时，您可能希望在 ADD 之后包含`RUN chown -R X:X`。

如前所述，`ADD`指令可以使用 URL 作为源值。以下是一个包含使用 URL 的`ADD`指令的示例 Dockerfile：

```
# ADD instruction Dockerfile for Docker Quick Start
FROM alpine
LABEL maintainer="Earl Waud <earlwaud@mycompany.com>"
LABEL version=3.0
ADD https://github.com/docker-library/hello-world/raw/master/amd64/hello-world/hello /
RUN chmod +x /hello
CMD ["/hello"]
```

在`ADD`指令中使用 URL 是有效的，将文件下载到镜像中，但是这个功能并不被 Docker 推荐。以下是 Docker 文档对使用`ADD`的建议：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/f457493e-9d04-4f9f-8892-4eb6466b159d.png)

因此，一般来说，每当您可以使用`COPY`指令将所需内容放入镜像时，您应该选择使用`COPY`而不是`ADD`。

# ENV 指令

正如您可能猜到的那样，`ENV`指令用于定义将在从正在构建的镜像创建的运行容器中设置的环境变量。使用典型的键值对定义变量。Dockerfile 可以有一个或多个`ENV`指令。以下是`ENV`指令的语法：

```
# ENV instruction syntax
# This is the form to create a single environment variable per instruction
# Everything after the space following the <key> becomes the value
ENV <key> <value>
# This is the form to use when you want to create more than one variable per instruction
ENV <key>=<value> ...
```

每个`ENV`指令将创建一个或多个环境变量（除非键名重复）。让我们看一下 Dockerfile 中的一些`ENV`指令：

```
# ENV instruction Dockerfile for Docker Quick Start
FROM alpine
LABEL maintainer="Earl Waud <earlwaud@mycompany.com>"
ENV appDescription This app is a sample of using ENV instructions
ENV appName=env-demo
ENV note1="The First Note First" note2=The\ Second\ Note\ Second \
note3="The Third Note Third"
ENV changeMe="Old Value"
CMD ["sh"]
```

使用此 Dockerfile 构建镜像后，您可以检查镜像元数据，并查看已创建的环境变量：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/e98f6d2e-906f-4c99-8a98-7fd5aceb10fc.png)

环境变量可以在运行容器时使用`--env`参数进行设置（或覆盖）。在这里，我们看到了这个功能的实际应用：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/572af022-9c53-496a-96e1-7e1c23a14b24.png)

重要的是要知道，使用`ENV`指令会在生成的镜像中创建一个大小为零字节的额外层。如果要向镜像添加多个环境变量，并且可以使用支持一次设置多个变量的指令形式，那么只会创建一个额外的镜像层，因此这是一个好方法。

# ARG 指令

有时在构建 Docker 镜像时，您可能需要使用变量数据来自定义构建。`ARG`指令是处理这种情况的工具。要使用它，您需要将`ARG`指令添加到 Dockerfile 中，然后在执行构建命令时，通过`--build-arg`参数传入变量数据。`--build-arg`参数使用现在熟悉的键值对格式：

```
# The ARG instruction syntax
ARG <varname>[=<default value>]

# The build-arg parameter syntax
docker image build --build-arg <varname>[=<value>] ...
```

您可以在 Dockerfile 中使用多个`ARG`指令，并在 docker image build 命令上使用相应的`--build-arg`参数。对于每个`--build-arg`参数的使用，都必须包括一个`ARG`指令。如果没有`ARG`指令，则在构建过程中`--build-arg`参数将不会被设置，并且您将收到警告消息。如果您没有提供`--build-arg`参数，或者没有为现有的`ARG`指令提供`--build-arg`参数的值部分，并且该`ARG`指令包括默认值，那么变量将被分配默认值。

请注意，在镜像构建过程中，即使`--build-arg`被包括为 docker image build 命令的参数，相应的变量也不会在 Dockerfile 中的`ARG`指令到达之前设置。换句话说，`--build-arg`参数的键值对的值在其对应的`ARG`行之后才会被设置。

在 `ARG` 指令中定义的参数不会持续到从创建的镜像运行的容器中，但是 ARG 指令会在生成的镜像中创建新的零字节大小的层。以下是使用 `ARG` 指令的教育示例：

```
# ARG instruction Dockerfile for Docker Quick Start
FROM alpine
LABEL maintainer="Earl Waud <earlwaud@mycompany.com>"

ENV key1="ENV is stronger than an ARG"
RUN echo ${key1}
ARG key1="not going to matter"
RUN echo ${key1}

RUN echo ${key2}
ARG key2="defaultValue"
RUN echo ${key2}
ENV key2="ENV value takes over"
RUN echo ${key2}
CMD ["sh"]
```

创建一个包含上述代码块中显示的内容的 Dockerfile，并运行以下构建命令，以查看 `ENV` 和 `ARG` 指令的范围如何发挥作用：

```
# Build the image and look at the output from the echo commands
 docker image build --rm \
 --build-arg key1="buildTimeValue" \
 --build-arg key2="good till env instruction" \
 --tag arg-demo:2.0 .
```

第一个 `echo ${key1}` 会让你看到，即使有一个 `--build-arg` 参数用于 `key1`，它也不会被存储为 `key1`，因为有一个相同键名的 `ENV` 指令。这对于第二个 `echo ${key1}` 仍然成立，这是在 ARG `key1` 指令之后。当 `ARG` 和 `EVN` 指令具有相同的键名时，ENV 变量值总是获胜。

然后，你会看到第一个 `echo ${key2}` 是空的，即使有一个 `--build-arg` 参数。这是因为我们还没有达到 `ARG key2` 指令。第二个 `echo ${key2}` 将包含相应 `--build-arg` 参数的值，即使在 `ARG key2` 指令中提供了默认值。最终的 `echo ${key2}` 将显示在 `ENV key2` 指令中提供的值，尽管在 `ARG` 中有默认值，并且通过 `--build-arg` 参数传递了一个值。同样，这是因为 `ENV` 总是胜过 ARG。

# ENV 和 ARG 之间的区别

这是一对具有类似功能的指令。它们都可以在构建镜像时使用，设置参数以便在其他 Dockerfile 指令中使用。可以使用这些参数的其他 Dockerfile 指令包括 `FROM`、`LABEL`、`COPY`、`ADD`、`ENV`、`USER`、`WORKDIR`、`RUN`、`VOLUME`、`EXPOSE`、`STOPSIGNAL` 和 `ONBUILD`。以下是在其他 Docker 命令中使用 `ARG` 和 `ENV` 变量的示例：

```
# ENV vs ARG instruction Dockerfile for Docker Quick Start
FROM alpine
LABEL maintainer="Earl Waud <earlwaud@mycompany.com>"
ENV lifecycle="production"
RUN echo ${lifecycle}
ARG username="35"
RUN echo ${username}
ARG appdir
RUN echo ${appdir}
ADD hello /${appdir}/
RUN chown -R ${username}:${username} ${appdir}
WORKDIR ${appdir}
USER ${username}
CMD ["./hello"]
```

使用这个 Dockerfile，你会想为 `appdir` `ARG` 指令提供 `--build-arg` 参数，并且在构建命令中提供用户名（如果你想要覆盖默认值）。你也可以在运行时提供一个 `--env` 参数来覆盖生命周期变量。以下是可能使用的构建和运行命令：

```
# Build the arg3 demo image
docker image build --rm \
 --build-arg appdir="/opt/hello" \
 --tag arg-demo:3.0 .

# Run the arg3 demo container
docker container run --rm --env lifecycle="test" arg-demo:3.0
```

虽然 `ENV` 和 `ARG` 指令可能看起来相似，但它们实际上是非常不同的。以下是记住 `ENV` 和 `ARG` 指令创建的参数之间的关键区别：

+   ENV 持续存在于运行中的容器中，ARG 不会。

+   ARG 使用相应的构建参数，ENV 不使用。

+   `ENV`指令必须包括键和值，`ARG`指令有一个键，但（默认）值是可选的。

+   ENV 比 ARG 更重要。

永远不要使用`ENV`或`ARG`指令向构建命令或生成的容器提供秘密数据，因为这些值对于运行 docker history 命令的任何用户都是明文可见的。

# USER 指令

USER 指令允许您为 Dockerfile 中接下来的所有指令和从构建图像运行的容器设置当前用户（和组）。`USER`指令的语法如下：

```
# User instruction syntax
USER <user>[:<group>] or
USER <UID>[:<GID>]
```

如果将命名用户（或组）作为`USER`指令的参数提供，则该用户（和组）必须已经存在于系统的 passwd 文件（或组文件）中，否则将发生构建错误。如果将`UID`（或`GID`）作为`USER`命令的参数提供，则不会执行检查用户（或组）是否存在。考虑以下 Dockerfile：

```
# USER instruction Dockerfile for Docker Quick Start 
FROM alpine
LABEL maintainer="Earl Waud <earl@mycompany.com>"
RUN id
USER games:games
run id
CMD ["sh"]
```

当图像构建开始时，当前用户是 root 或`UID=0` `GID=0`。然后，执行`USER`指令将当前用户和组设置为`games:games`。由于这是 Dockerfile 中`USER`指令的最后一次使用，所有使用构建图像运行的容器将具有当前用户（和组）设置为 games。构建和运行如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/0aca2a20-ee07-4b3b-ba94-bc58b78b8deb.png)

请注意，步骤 3/6 的 RUN id 的输出显示当前用户为 root，然后在步骤 5/6（在`USER`指令之后）中显示当前用户为 games。最后，请注意，从图像运行的容器具有当前用户 games。`USER`指令在图像中创建了一个大小为零字节的层。

# WORKDIR 指令

我们已经在一些示例中看到了`WORKDIR`指令的使用，用于演示其他指令。它有点像 Linux 的`cd`和`mkdir`命令的组合。`WORKDIR`指令将把图像中的当前工作目录更改为指令中提供的值。如果参数中路径的任何部分尚不存在，则将作为执行指令的一部分创建它。`WORKDIR`指令的语法如下：

```
# WORKDIR instruction syntax
WORKDIR instruction syntax
WORKDIR /path/to/workdir
```

`WORKDIR`指令可以使用`ENV`或`ARG`参数值作为其参数的全部或部分。Dockerfile 可以有多个`WORKDIR`指令，每个后续的`WORKDIR`指令将相对于前一个（如果使用相对路径）。以下是演示此可能性的示例：

```
# WORKDIR instruction Dockerfile for Docker Quick Start
FROM alpine
# Absolute path...
WORKDIR /
# relative path, relative to previous WORKDIR instruction
# creates new folder
WORKDIR sub-folder-level-1
RUN touch file1.txt
# relative path, relative to previous WORKDIR instruction
# creates new folder
WORKDIR sub-folder-level-2
RUN touch file2.txt
# relative path, relative to previous WORKDIR instruction
# creates new folder
WORKDIR sub-folder-level-3
RUN touch file3.txt
# Absolute path, creates three sub folders...
WORKDIR /l1/l2/l3
CMD ["sh"]
```

从这个 Dockerfile 构建镜像将导致镜像具有三层嵌套的文件夹。从镜像运行容器并列出文件和文件夹将如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/c1c550ed-5793-45d4-a4d7-a9f8c4c60f81.png)

`WORKDIR`指令将在生成的镜像中创建一个大小为零字节的层。

# VOLUME 指令

您应该记住，Docker 镜像由一系列相互叠加的只读层组成，当您从 Docker 镜像运行容器时，它会创建一个新的读写层，您可以将其视为位于只读层之上。所有对容器的更改都应用于读写层。如果对只读层中的文件进行更改，将会创建该文件的副本并将其添加到读写层。然后，所有更改都将应用于该副本。该副本隐藏了只读层中找到的版本，因此从运行的容器的角度来看，文件只有一个版本，即已更改的版本。这大致是统一文件系统的工作原理。

这实际上是一件好事。但是，它也带来了一个挑战，即当运行的容器退出并被删除时，所有更改也将被删除。这通常是可以接受的，直到您希望在容器的生命周期之后保留一些数据，或者希望在容器之间共享数据时。Docker 有一条指令可以帮助您解决这个问题，那就是`VOLUME`指令。

`VOLUME`指令将创建一个存储位置，该位置位于美国文件系统之外，并且通过这样做，允许存储在容器的生命周期之外持久存在。以下是`VOLUME`指令的语法：

```
# VOLUME instruction syntax
VOLUME ["/data"]
# or for creating multiple volumes with a single instruction
VOLUME /var/log /var/db /moreData
```

创建卷的其他方法是向 docker `container run`命令添加卷参数，或者使用 docker volume create 命令。我们将在第四章 *Docker Volumes*中详细介绍这些方法。

这是一个简单的示例 Dockerfile。它在`/myvol`创建了一个卷，其中将有一个名为`greeting`的文件：

```
# VOLUME instruction Dockerfile for Docker Quick Start
FROM alpine
RUN mkdir /myvol
RUN echo "hello world" > /myvol/greeting
VOLUME /myvol
CMD ["sh"]
```

基于从此 Dockerfile 创建的镜像运行容器将在主机系统上创建一个挂载点，最初包含`greeting`文件。当容器退出时，挂载点将保留。在运行具有要持久保存的挂载点的容器时，使用`--rm`参数要小心。使用`--rm`，没有其他卷参数，将导致容器退出时清理挂载点。看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/b5f7a39c-bbc2-4ed6-96a3-96327e0839af.png)

我们开始时没有卷。然后，我们以分离模式运行了一个基于前面的 Dockerfile 创建的镜像的容器。我们再次检查卷，看到了通过运行容器创建的卷。然后，我们停止容器并再次检查卷，现在卷已经消失了。通常，使用`VOLUME`指令的目的是在容器消失后保留挂载点中的数据。因此，如果您要在运行容器时使用`--rm`，您应该包括`--mount`运行参数，我们将在第四章 *Docker Volumes*中详细介绍。

您可以使用卷的挂载点与主机上的数据进行交互。以下是一个演示这一点的示例：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/bd92fd61-ea21-4375-850c-4e759713d89e.png)

在这个演示中，我们运行了一个基于前面的 Dockerfile 创建的镜像的容器。然后，我们列出了卷，并查看了 myvolsrc 卷（我们已经知道了名称，因为我们在运行命令中提供了它，但您可以使用`ls`命令来查找您可能不知道的卷名称）。使用卷的名称，我们检查卷以找到它在主机上的挂载点。为了验证容器中卷的内容，我们使用 exec 命令来列出文件夹。接下来，使用挂载点路径，我们使用 touch 命令创建一个新文件。最后，我们使用相同的 exec 命令，并看到容器内的卷已经改变（来自容器外的操作）。同样，如果容器更改卷的内容，这些更改将立即反映在主机挂载点上。

前面的示例在 OS X 上直接显示不起作用。它需要一些额外的工作。不过不要惊慌！我们将向您展示如何处理 OS X 所需的额外工作，在第四章 *Docker Volumes*中。

使用`VOLUME`指令既强大又危险。它之所以强大，是因为它让您拥有超出容器生命周期的数据。它之所以危险，是因为数据会立即从容器传递到主机，如果容器被攻击，可能会带来麻烦。出于安全考虑，最佳实践是*不*在 Dockerfile 中包含基于主机的 VOLUME 挂载。我们将在第四章中介绍一些更安全的替代方法，*Docker Volumes*。

`VOLUME`指令将在生成的 Docker 镜像中添加一个大小为零字节的层。

# EXPOSE 指令

`EXPOSE`指令是记录镜像期望在使用 Dockerfile 构建的镜像运行容器时打开的网络端口的一种方式。`EXPOSE`指令的语法如下：

```
# EXPOSE instruction syntax
EXPOSE <port> [<port>/<protocol>...]
```

重要的是要理解，在 Dockerfile 中包含`EXPOSE`指令实际上并不会在容器中打开网络端口。当从具有`EXPOSE`指令的 Dockerfile 中的镜像运行容器时，仍然需要包括`-p`或`-P`参数来实际打开网络端口到容器。

根据需要在 Dockerfile 中包含多个`EXPOSE`指令。在运行时包括`-P`参数是一种快捷方式，可以自动打开 Dockerfile 中包含的所有`EXPOSE`指令的端口。在运行命令时使用`-P`参数时，相应的主机端口将被随机分配。

将`EXPOSE`指令视为镜像开发者向您传达的信息，告诉您在运行容器时，镜像中的应用程序期望您打开指定的端口。`EXPOSE`指令在生成的镜像中创建一个大小为零字节的层。

# RUN 指令

`RUN`指令是 Dockerfile 的真正工作马。这是您对生成的 Docker 镜像产生最大变化的工具。基本上，它允许您在镜像中执行任何命令。`RUN`指令有两种形式。以下是语法：

```
# RUN instruction syntax
# Shell form to run the command in a shell
# For Linux the default is "/bin/sh -c"
# For Windows the default is "cmd /S /C"
RUN <command>

# Exec form
RUN ["executable", "param1", "param2"]
```

每个`RUN`指令在镜像中创建一个新的层，随后的每个指令的层都将建立在`RUN`指令的层的结果之上。除非使用`SHELL`指令覆盖，默认情况下，shell 形式的指令将使用默认 shell。如果您正在构建一个不包含 shell 的容器，您将需要使用`RUN`指令的 exec 形式。您还可以使用 exec 形式的指令来使用不同的 shell。例如，要使用 bash shell 运行命令，您可以添加一个`RUN`指令，如下所示：

```
# Exec form of RUN instruction using bash
RUN ["/bin/bash", "-c", "echo hello world > /myvol/greeting"]
```

`RUN`命令的用途仅受想象力的限制，因此提供`RUN`指令示例的详尽列表是不可能的，但以下是一些使用两种形式的指令的示例，只是为了给您一些想法：

```
# RUN instruction Dockerfile for Docker Quick Start
FROM ubuntu
RUN useradd --create-home -m -s /bin/bash dev
RUN mkdir /myvol
RUN echo "hello DQS Guide" > /myvol/greeting
RUN ["chmod", "664", "/myvol/greeting"]
RUN ["chown", "dev:dev", "/myvol/greeting"]
VOLUME /myvol
USER dev
CMD ["/bin/bash"]
```

当您知道您的镜像将包含 bash 时，可以添加一个有趣且有用的`RUN`指令。这个想法是我在 Dockercon 16 上得知的，由我的同事*Marcello de Sales*与我分享。您可以使用以下代码在 shell 进入容器时创建自定义提示。如果您不喜欢鲸鱼图形，可以更改并使用任何您喜欢的东西。我包括了一些我喜欢的选项。以下是代码：

```
# RUN instruction Dockerfile for Docker Quick Start
FROM ubuntu
RUN useradd --create-home -m -s /bin/bash dev
# Add a fun prompt for dev user of my-app
# whale: "\xF0\x9F\x90\xB3"
# alien:"\xF0\x9F\x91\xBD"
# fish:"\xF0\x9F\x90\xA0"
# elephant:"\xF0\x9F\x91\xBD"
# moneybag:"\xF0\x9F\x92\xB0"
RUN echo 'PS1="\[$(tput bold)$(tput setaf 4)\]my-app $(echo -e "\xF0\x9F\x90\xB3") \[$(tput sgr0)\] [\\u@\\h]:\\W \\$ "' >> /home/dev/.bashrc && \
 echo 'alias ls="ls --color=auto"' >> /home/dev/.bashrc
USER dev
CMD ["/bin/bash"]
```

生成的提示如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/2d0c1502-1539-4012-9e25-d472c87bea18.png)

# `CMD`指令

`CMD`指令用于定义从使用其 Dockerfile 构建的镜像运行容器时采取的默认操作。虽然在 Dockerfile 中可以包含多个`CMD`指令，但只有最后一个才会有意义。基本上，最后一个`CMD`指令为镜像提供了默认操作。这允许您在 Dockerfile 的`FROM`指令中覆盖或使用镜像中的`CMD`。以下是一个示例，其中一个微不足道的 Dockerfile 不包含`CMD`指令，并依赖于在`FROM`指令中使用的 ubuntu 镜像中找到的指令：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/2c1f6b2e-a069-432c-a891-fb4eb69f7bab.png)

您可以从 history 命令的输出中看到，ubuntu 镜像包括`CMD ["/bin/bash"]`指令。您还会看到我们的 Dockerfile 没有自己的`CMD`指令。当我们运行容器时，默认操作是运行`"/bin/bash"`。

`CMD`指令有三种形式。第一种是 shell 形式。第二种是 exec 形式，这是最佳实践形式。第三种是特殊的 exec 形式，它有两个参数，并且与`ENTRYPOINT`指令一起使用，我们将在*ENTRYPOINT 指令*部分讨论它。以下是`CMD`指令的语法。

```
# CMD instruction syntax
CMD command param1 param2 (shell form)
CMD ["executable","param1","param2"] (exec form)
CMD ["param1","param2"] (as default parameters to ENTRYPOINT)
```

以下是一些`CMD`指令的示例供您参考：

```
# CMD instruction examples
CMD ["/bin/bash"]
CMD while true; do echo 'DQS Expose Demo' | nc -l -p 80; done
CMD echo "How many words are in this echo command" | wc -
CMD tail -f /dev/null
CMD ["-latr", "/var/opt"]
```

与`RUN`指令一样，`CMD`指令的 shell 形式默认使用`["/bin/sh", "-c"]` shell 命令（或`["cmd", "/S", "/C"]`用于 Windows），除非它被`SHELL`指令覆盖。然而，与`RUN`指令不同，`CMD`指令在构建镜像时不执行任何操作，而是在从镜像构建的容器运行时执行。如果正在构建的容器镜像没有 shell，则可以使用指令的 exec 形式，因为它不会调用 shell。`CMD`指令向镜像添加了一个大小为零字节的层。

# ENTRYPOINT 指令

`ENTRYPOINT`指令用于配置 docker 镜像以像应用程序或命令一样运行。例如，我们可以使用`ENTRYPOINT`指令制作一个显示`curl`命令帮助信息的镜像。考虑这个 Dockerfile：

```
# ENTRYPOINT instruction Dockerfile for Docker Quick Start
FROM alpine
RUN apk add curl
ENTRYPOINT ["curl"]
CMD ["--help"]
```

我们可以运行容器镜像，不覆盖`CMD`参数，它将显示`curl`命令的帮助信息。然而，当我们用`CMD`覆盖参数运行容器时，在这种情况下是一个 URL，响应将是`curl`该 URL。看一下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/71810ef5-9fe0-439d-963f-7a03c6b758df.png)

当为具有`ENTRYPOINT`指令的 exec 形式的容器提供运行参数时，这些参数将附加到`ENTRYPOINT`指令，覆盖`CMD`指令中提供的任何内容。在这个例子中，`--help`被`google.com`运行参数覆盖，所以结果指令是`curl google.com`。以下是`ENTRYPOINT`指令的实际语法：

```
# ENTRYPOINT instruction syntax
ENTRYPOINT command param1 param2 (shell form)
ENTRYPOINT ["executable", "param1", "param2"] (exec form, best practice)
```

与`CMD`指令一样，只有最后一个`ENTRYPOINT`指令是重要的。同样，这允许您在使用`FROM`镜像时使用或覆盖`ENTRYPOINT`指令。与`RUN`和`CMD`指令一样，使用 shell 形式将调用`["/bin/sh", "-c"]`（或在 Windows 上为`["cmd", "/S", "/C"]`）。当使用指令的 exec 形式时，情况并非如此。这对于没有 shell 或 shell 不可用于活动用户上下文的镜像非常重要。但是，您将不会获得 shell 处理，因此在使用指令的 exec 形式时，任何 shell 环境变量都不会被替换。通常最好尽可能使用`ENTRYPOINT`指令的 exec 形式。

# CMD 和 ENTRYPOINT 之间的区别

在这里，我们再次有两个表面上看起来非常相似的指令。事实上，它们之间确实有一些功能重叠。这两个指令都提供了一种定义在运行容器时执行的默认应用程序的方法。然而，它们各自有其独特的目的，并且在某些情况下共同工作，以提供比任何一条指令单独提供的更大的功能。

最佳实践是在希望容器作为应用程序执行、提供特定（开发者）定义的功能时使用`ENTRYPOINT`指令，并在希望为用户提供更多灵活性以确定容器将提供的功能时使用`CMD`。

这两个指令都有两种形式：shell 形式和 exec 形式。最佳实践是尽可能使用任何一种的 exec 形式。原因是，shell 形式将运行`["/bin/sh", "-c"]`（或在 Windows 上为`["cmd", "/S", "/C"]`）来启动指令参数中的应用程序。由于这个原因，运行在容器中的主要进程不是应用程序，而是 shell。这会影响容器的退出方式，影响信号的处理方式，并且可能会对不包括`"/bin/sh"`的镜像造成问题。您可能需要使用 shell 形式的一个用例是如果您需要 shell 环境变量替换。

在 Dockerfile 中还有一个使用两个指令的用例。当您同时使用两者时，可以定义在运行容器时执行的特定应用程序，并允许用户轻松提供与定义的应用程序一起使用的参数。在这种情况下，您将使用`ENTRYPOINT`指令设置要执行的应用程序，并使用`CMD`指令为应用程序提供一组默认参数。通过这种配置，容器的用户可以从`CMD`指令中提供的默认参数中受益，或者他们可以通过在`container run`命令中提供参数作为参数轻松覆盖应用程序中使用的这些参数。强烈建议在同时使用两个指令时使用它们的 exec 形式。

# `HEALTHCHECK`指令

`HEALTHCHECK`指令是 Dockerfile 中相对较新的添加，用于定义在容器内运行的命令，以测试容器的应用程序健康状况。当容器具有`HEALTHCHECK`时，它会获得一个特殊的状态变量。最初，该变量将被设置为`starting`。每当成功执行`HEALTHCHECK`时，状态将被设置为`healthy`。当执行`HEALTHCHECK`并失败时，失败计数值将被递增，然后与重试值进行比较。如果失败计数等于或超过重试值，则状态将被设置为`unhealthy`。`HEALTHCHECK`指令的语法如下：

```
# HEALTHCHECK instruction syntax
HEALTHCHECK [OPTIONS] CMD command (check container health by running a command inside the container)
HEALTHCHECK NONE (disable any HEALTHCHECK inherited from the base image)
```

在设置`HEALTHCHECK`时有四个选项可用，这些选项如下：

```
# HEALTHCHECK CMD options
--interval=DURATION (default: 30s)
--timeout=DURATION (default: 30s)
--start-period=DURATION (default: 0s)
--retries=N (default: 3)
```

`--interval`选项允许您定义`HEALTHCHECK`测试之间的时间间隔。`--timeout`选项允许您定义被视为`HEALTHCHECK`测试时间过长的时间量。如果超过超时时间，测试将自动视为失败。`--start-period`选项允许在容器启动期间定义一个无失败时间段。最后，`--retries`选项允许您定义多少连续失败才能将`HEALTHCHECK`状态更新为`unhealthy`。

`HEALTHCHECK`指令的`CMD`部分遵循与`CMD`指令相同的规则。有关`CMD`指令的完整详情，请参阅前面的部分。使用的`CMD`在退出时将提供一个状态，该状态要么是成功的 0，要么是失败的 1。以下是使用`HEALTHCHECK`指令的 Dockerfile 示例：

```
# HEALTHCHECK instruction Dockerfile for Docker Quick Start
FROM alpine
RUN apk add curl
EXPOSE 80/tcp
HEALTHCHECK --interval=30s --timeout=3s \
 CMD curl -f http://localhost/ || exit 1
CMD while true; do echo 'DQS Expose Demo' | nc -l -p 80; done
```

使用上述 Dockerfile 构建的镜像运行容器如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/5a4d6561-c20e-4f21-94d0-0de027616a41.png)

您可以看到`HEALTHCHECK`最初报告状态为`starting`，但一旦`HEALTHCHECK` `CMD`报告成功，状态就会更新为`healthy`。

# ONBUILD 指令

`ONBUILD`指令是在创建将成为另一个 Dockerfile 中`FROM`指令参数的镜像时使用的工具。`ONBUILD`指令只是向您的镜像添加元数据，具体来说是存储在镜像中而不被其他方式使用的触发器。然而，当您的镜像作为另一个 Dockerfile 中`FROM`命令的参数提供时，该元数据触发器会被使用。以下是`ONBUILD`指令的语法：

```
# ONBUILD instruction syntax
ONBUILD [INSTRUCTION]
```

`ONBUILD`指令有点像 Docker 时间机器，用于将指令发送到未来。（如果您知道我刚刚输入*Doctor time machine*多少次，您可能会笑！）让我们用一个简单的例子来演示`ONBUILD`指令的使用。首先，我们将使用以下 Dockerfile 构建一个名为`my-base`的镜像：

```
# my-base Dockerfile
FROM alpine
LABEL maintainer="Earl Waud <earlwaud@mycompany.com>"
ONBUILD LABEL version="1.0"
ONBUILD LABEL support-email="support@mycompany.com" support-phone="(123) 456-7890"
CMD ["sh"]
```

接下来，让我们构建一个名为`my-app`的镜像，该镜像是从`my-base`镜像构建的，如下所示：

```
# my-app Dockerfile
FROM my-base:1.0
CMD ["sh"]
```

检查生成的`my-app`镜像，我们可以看到`ONBUILD`指令中提供的 LABEL 命令被发送到未来，到达`my-app`镜像：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/a1594a9a-5813-48bd-ae3e-0c40d9ed65b3.png)

如果您对`my-base`镜像进行类似的检查，您会发现它*不*包含版本和支持标签。还要注意，`ONBUILD`指令是一次性使用的时间机器。如果您使用`FROM`指令中的`my-app`构建一个新的镜像，新的镜像将*不*获得`my-base`镜像的 ONBUILD 指令中提供的标签。

# STOPSIGNAL 指令

`STOPSIGNAL`指令用于设置系统调用信号，该信号将被发送到容器，告诉它退出。指令中使用的参数可以是无符号数字，等于内核系统调用表中的位置，也可以是大写的实际信号名称。以下是该指令的语法：

```
# STOPSIGNAL instruction syntax
STOPSIGNAL signal
```

`STOPSIGNAL`指令的示例包括以下内容：

```
# Sample STOPSIGNAL instruction using a position number in the syscall table
STOPSIGNAL 9
# or using a signal name
STOPSIGNAL SIGQUIT
```

`STOPSIGNAL`指令提供的参数在发出`docker container stop`命令时使用。请记住，使用`ENTRYPOINT`和/或`CMD`指令的执行形式非常重要，以便应用程序成为 PID 1，并直接接收信号。以下是有关在 Docker 中使用信号的出色博客文章链接：[`medium.com/@gchudnov/trapping-signals-in-docker-containers-7a57fdda7d86`](https://medium.com/@gchudnov/trapping-signals-in-docker-containers-7a57fdda7d86)。该文章提供了使用 node.js 应用程序处理信号的出色示例，包括代码和 Dockerfile。

# `SHELL`指令

正如您在本章的许多部分中所阅读的，有几个指令有两种形式，即执行形式或 shell 形式。如前所述，所有 shell 形式默认使用`["/bin/sh", "-c"]`用于 Linux 容器，以及`["cmd", "/S", "/C"]`用于 Windows 容器。`SHELL`指令允许您更改该默认设置。以下是`SHELL`指令的语法：

```
# SHELL instruction syntax
SHELL ["executable", "parameters"]
```

`SHELL`指令可以在 Dockerfile 中使用多次。所有使用 shell 的指令，并且在`SHELL`指令之后，将使用新的 shell。因此，根据需要可以在单个 Dockerfile 中多次更改 shell。在创建 Windows 容器时，这可能特别有用，因为它允许您在`cmd.exe`和`powershell.exe`之间来回切换。

# Docker 镜像构建命令

好的，镜像构建命令不是 Dockerfile 指令。相反，它是用于将 Dockerfile 转换为 docker 镜像的 docker 命令。Docker 镜像构建命令将 docker 构建上下文，包括 Dockerfile，发送到 docker 守护程序，它解析 Dockerfile 并逐层构建镜像。我们将很快讨论构建上下文，但现在可以将其视为根据 Dockerfile 中的内容构建 Docker 镜像所需的一切。构建命令的语法如下：

```
# Docker image build command syntax
Usage: docker image build [OPTIONS] PATH | URL | -
```

图像构建命令有许多选项。我们现在不会涵盖所有选项，但让我们看一下一些最常见的选项：

```
# Common options used with the image build command
--rm         Remove intermediate containers after a successful build
--build-arg  Set build-time variables
--tag        Name and optionally a tag in the 'name:tag' format
--file       Name of the Dockerfile (Default is 'PATH/Dockerfile')
```

Docker 守护程序通过从 Dockerfile 中的每个命令创建新的图像来构建图像。每个新图像都是在前一个图像的基础上构建的。使用可选的`--rm`参数将指示守护程序在构建成功完成时删除所有中间图像。当重新构建成功构建的图像时，使用此选项将减慢构建过程，但会保持本地图像缓存的清洁。

当我们讨论`ARG`指令时，我们已经谈到了构建参数。请记住，`--build-arg`选项是您如何为 Dockerfile 中的`ARG`指令提供值。

`--tag`选项允许您为图像指定一个更易读的名称和版本。我们在之前的几个示例中也看到了这个选项的使用。

`--file`选项允许您使用文件名而不是 Dockerfile，并将 Dockerfile 保留在构建上下文文件夹之外的路径中。

以下是一些图像构建命令供参考：

```
# build command samples
docker image build --rm --build-arg username=35 --tag arg-demo:2.0 .
docker image build --rm --tag user-demo:1.0 .
docker image build --rm --tag workdir-demo:1.0 .
```

您会注意到前面每个示例中都有一个尾随的`。`。这个句号表示当前工作目录是图像构建的构建上下文的根目录。

# 解析指令

解析指令是 Dockerfile 中可选注释行的一个特殊子集。任何解析指令必须出现在第一个正常注释行之前。它们还必须出现在任何空行或其他构建指令之前，包括`FROM`指令。基本上，所有解析指令必须位于 Dockerfile 的顶部。顺便说一句，如果你还没有弄清楚，你可以通过以`#`字符开头来创建一个普通的注释行。解析指令的语法如下：

```
# directive=value
# The line above shows the syntax for a parser directive
```

那么，您可以使用解析器指令做什么呢？目前，唯一支持的是`escape`。`escape`解析器指令用于更改用于指示下一个字符在指令中被视为字符而不是表示的特殊字符的字符。如果不使用解析器指令，则默认值为`\`。在本章的几个示例中，您已经看到了它用于转义换行符，允许在 Dockerfile 中将指令继续到下一行。如果需要使用不同的`escape`字符，可以使用`escape`解析器指令来处理。您可以将`escape`字符设置为两种选择之一：

```
# escape=\ (backslash)
Or
# escape=` (backtick)
```

一个例子是当您在 Windows 系统上创建 Dockerfile 时可能需要更改用作`escape`字符的字符。如您所知，`\`用于区分路径字符串中的文件夹级别，例如`c:\windows\system32`。

\drivers`。切换到使用`escape`字符的反引号将避免需要转义此类字符串，例如：`c:\\windows\\system32\\drivers`。

# 构建上下文

构建上下文是在使用构建镜像命令时发送到 Docker 守护程序的所有内容。这包括 Dockerfile 和发出构建命令时当前工作目录的内容，包括当前工作目录可能包含的所有子目录。可以使用`-f`或`--file`选项将 Dockerfile 放在当前工作目录以外的目录中，但 Dockerfile 仍然会随构建上下文一起发送。使用`.dockerignore`文件，可以在发送到 Docker 守护程序的构建上下文中排除文件和文件夹。

构建 Docker 镜像时，非常重要的是尽可能保持构建上下文的大小。这是因为整个构建上下文都会发送到 Docker 守护程序以构建镜像。如果构建上下文中有不必要的文件和文件夹，那么它将减慢构建过程，并且根据 Dockerfile 的内容，可能会导致膨胀的镜像。这是一个如此重要的考虑因素，以至于每个镜像构建命令都会在命令输出的第一行显示构建上下文的大小。它看起来像这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/b0300473-f75d-45ad-8bb7-c37fd77987bf.png)

构建上下文成为 Dockerfile 中命令的文件系统根。例如，考虑使用以下`COPY`指令：

```
# build context Dockerfile for Docker Quick Start guide
FROM scratch
COPY hello /
CMD ["/hello"]
```

这告诉 Docker 守护程序将`hello`文件从构建上下文的根目录复制到容器镜像的根目录。

如果命令成功完成，将显示镜像 ID，如果提供了`--tag`选项，则还将显示新的标签和版本：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/a22a41a4-e7bb-47ec-8112-2e22153de989.png)

保持构建上下文小的关键之一是使用`.dockerignore`文件。

# .dockerignore 文件

如果您熟悉使用`.gitignore`文件，那么您已经基本了解了`.dockerignore`文件的目的。`.dockerignore`文件用于排除在 docker 镜像构建过程中不想包含在构建上下文中的文件。使用它有助于防止敏感和其他不需要的文件被包含在构建上下文中，可能最终出现在 docker 镜像中。这是一个帮助保持 Docker 镜像小的绝佳工具。

`.dockerignore`文件需要位于构建上下文的根文件夹中。与`.gitignore`文件类似，它使用一个以换行符分隔的模式列表。`.dockerignore`文件中的注释以`#`作为行的第一个字符。您可以通过包含一个例外行来覆盖模式。例外行以`!`作为行的第一个字符。所有其他行都被视为用于排除文件和/或文件夹的模式。

`.dockerignore`文件中的行顺序很重要。文件后面的匹配模式将覆盖文件前面的匹配模式。如果您添加一个与`.dockerignore`文件或 Dockerfile 文件匹配的模式，它们仍将与构建上下文一起发送到 docker 守护程序，但它们将不可用于任何`ADD`或`COPY`指令，因此不能出现在生成的镜像中。这是一个例子：

```
# Example of a .dockerignore file
# Exclude unwanted files
/*~
/*.log
/.DS_Store
```

# 总结

好了！那是一次冒险。现在您应该能够构建任何类型的 Docker 镜像。您知道何时使用`COPY`而不是`ADD`，何时使用`ENV`而不是`ARG`，也许最重要的是何时使用`CMD`而不是`ENTERYPOINT`。您甚至学会了如何穿越时间！这些信息对于开始使用 Docker 来说真的是一个很好的基础，并且在您开发更复杂的 Docker 镜像时将作为一个很好的参考。

希望你从这一章学到了很多，但我们还有更多要学习，所以让我们把注意力转向下一个主题。在第四章 *Docker Volumes*中，我们将学习更多关于 Docker 卷的知识。翻页，让我们继续我们的快速入门之旅。

# 参考资料

查看以下链接，获取本章讨论的主题信息：

+   hello-world GitHub 存储库：[`github.com/docker-library/hello-world`](https://github.com/docker-library/hello-world)

+   Docker 卷：[`docs.docker.com/storage/volumes/`](https://docs.docker.com/storage/volumes/)

+   使用 Docker 的信号：[`medium.com/@gchudnov/trapping-signals-in-docker-containers-7a57fdda7d86`](https://medium.com/@gchudnov/trapping-signals-in-docker-containers-7a57fdda7d86)

+   `.dockerignore`参考文档：[`docs.docker.com/engine/reference/builder/#dockerignore-file`](https://docs.docker.com/engine/reference/builder/#dockerignore-file)

+   Dockerfile 的最佳实践：[`docs.docker.com/v17.09/engine/userguide/eng-image/dockerfile_best-practices/`](https://docs.docker.com/v17.09/engine/userguide/eng-image/dockerfile_best-practices/)
