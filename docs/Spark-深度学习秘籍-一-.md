# Spark 深度学习秘籍（一）

> 原文：[`zh.annas-archive.org/md5/D22F0E873CEFD5D61BC00E51F025B8FB`](https://zh.annas-archive.org/md5/D22F0E873CEFD5D61BC00E51F025B8FB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

随着深度学习在现代工业中迅速被广泛采用，组织机构正在寻找将流行的大数据工具与高效的深度学习库结合起来的方法。这将有助于深度学习模型以更高的效率和速度进行训练。

借助*Apache Spark 深度学习食谱*，您将通过具体的配方来生成深度学习算法的结果，而不会陷入理论中。从为深度学习设置 Apache Spark 到实现各种类型的神经网络，本书解决了常见和不太常见的问题，以便在分布式环境中进行深度学习。除此之外，您还将获得在 Spark 中可以重复使用以解决类似问题或微调以解决稍有不同问题的深度学习代码。您还将学习如何使用 Spark 进行数据流处理和聚类。一旦掌握了基础知识，您将探索如何使用流行的库（如 TensorFlow 和 Keras）在 Spark 中实现和部署 CNN、RNN 和 LSTM 等深度学习模型。最终，这是一本旨在教授如何在 Spark 上实际应用模型的食谱，因此我们不会深入探讨理论和数学。

在本章中使用的模型背后的原理，尽管我们会引用额外的

可以获取每个模型的信息。

通过本书，您将掌握在 Apache Spark 上训练和部署高效深度学习模型的专业知识。

# 本书适合对象

本书适用于具有基本机器学习和大数据概念的人，希望通过自顶向下的方法扩展他们的理解。本书以即插即用的方式提供了深度学习和机器学习算法。任何没有编程经验的人，特别是对 Python 不熟悉的人，都可以按照逐步指示轻松实现本书中的算法。本书中大部分代码都是不言自明的。每个代码块执行一个特定的功能，或者在挖掘、操作、转换和拟合数据到深度学习模型方面执行一个动作。

本书旨在通过有趣的项目（如股价预测）为读者提供实践经验，同时更加扎实地理解深度学习和机器学习概念。这是通过书中每一章节提供的大量在线资源链接（如发表的论文、教程和指南）来实现的。

# 本书涵盖内容

第一章，*为深度学习设置 Spark*，涵盖了您需要的一切，以便在虚拟 Ubuntu 桌面环境中开始使用 Spark 进行开发。

第二章，*使用 Spark 创建神经网络*，解释了在不使用 TensorFlow 或 Keras 等深度学习库的情况下，从头开始开发神经网络的过程。

第三章，*卷积神经网络的痛点*，介绍了在图像识别的卷积神经网络上工作时出现的一些痛点，以及如何克服这些问题。

第四章，*循环神经网络的痛点*，介绍了前馈神经网络和循环神经网络，并描述了循环神经网络出现的一些痛点，以及如何利用 LSTM 来解决这些问题。

第五章，*使用 Spark ML 预测消防部门呼叫*，介绍了使用 Spark 机器学习为旧金山市的消防部门呼叫开发分类模型的过程。

第六章，*在生成网络中使用 LSTMs*，提供了使用小说或大型文本语料库作为输入数据来定义和训练 LSTM 模型的实际方法，同时还使用训练好的模型生成自己的输出序列。

第七章，*使用 TF-IDF 进行自然语言处理*，介绍了对聊天机器人对话数据进行升级分类的步骤。

第八章，*使用 XGBoost 进行房地产价值预测*，专注于使用 Kings County 房屋销售数据集训练一个简单的线性模型，并用它来预测房价，然后深入研究一个稍微复杂的模型来提高预测准确性。

第九章，*使用 LSTM 预测苹果股票市场成本*，专注于使用 Keras 上的 LSTM 创建深度学习模型，以预测 AAPL 股票的股市价格。

第十章，*使用深度卷积网络进行人脸识别*，利用 MIT-CBCL 数据集中 10 个不同主题的面部图像来训练和测试深度卷积神经网络模型。

第十一章，*使用 Word2Vec 创建和可视化词向量*，专注于机器学习中向量的重要性，并指导用户如何利用 Google 的 Word2Vec 模型训练不同的模型并可视化从小说中生成的词向量。

第十二章，*使用 Keras 创建电影推荐引擎*，专注于使用深度学习库 Keras 为用户构建电影推荐引擎。

第十三章，*在 Spark 上使用 TensorFlow 进行图像分类*，专注于利用迁移学习识别世界上两位顶级足球运动员：克里斯蒂亚诺·罗纳尔多和利昂内尔·梅西。

# 为了充分利用本书

1.  利用提供的所有链接，更好地理解本书中使用的一些术语。

1.  互联网是当今世界上最大的大学。使用 YouTube、Udemy、edX、Lynda 和 Coursera 等网站的视频，了解各种深度学习和机器学习概念。

1.  不要只是读这本书然后忘记它。在阅读本书时，实际实施每一步。建议您在阅读每个配方时打开您的 Jupyter Notebook，这样您可以在阅读书籍的同时处理每个配方，并同时检查您获得的每个步骤的输出。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便将文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压缩文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Apache-Spark-Deep-Learning-Cookbook`](https://github.com/PacktPublishing/Apache-Spark-Deep-Learning-Cookbook)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富的图书和视频目录的其他代码包，可在 **[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)** 上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子："保存在工作目录内的 `trained` 文件夹下。"

代码块设置如下：

```scala
print('Total Rows')
df.count()
print('Rows without Null values')
df.dropna().count()
print('Row with Null Values')
df.count()-df.dropna().count()
```

任何命令行输入或输出都以以下方式编写：

```scala
nltk.download("punkt")
nltk.download("stopwords")
```

**粗体**：表示一个新术语、一个重要词或屏幕上看到的词。例如，菜单或对话框中的单词会出现在文本中。这是一个例子："右键单击页面，然后单击“另存为”…"

警告或重要说明会出现在这样。

提示和技巧会出现在这样。

# 部分

在本书中，您会经常看到几个标题（*准备工作*、*如何做*、*它是如何工作的*、*还有更多*和*另请参阅*）。

清晰地说明如何完成食谱，使用以下部分：

# 准备工作

本节告诉您在食谱中可以期望什么，并描述如何设置食谱所需的任何软件或任何初步设置。

# 如何做…

本节包含遵循食谱所需的步骤。

# 它是如何工作的…

本节通常包括对前一节中发生的事情的详细解释。

# 还有更多…

本节包含有关食谱的其他信息，以使您对食谱更加了解。

# 另请参阅

本节提供了指向食谱的其他有用信息的链接。


# 第一章：为深度学习开发设置 Spark

在本章中，将涵盖以下内容：

+   下载 Ubuntu 桌面镜像

+   在 macOS 上使用 VMWare Fusion 安装和配置 Ubuntu

+   在 Windows 上使用 Oracle VirtualBox 安装和配置 Ubuntu

+   在 Google Cloud Platform 上安装和配置 Ubuntu 桌面

+   在 Ubuntu 桌面上安装和配置 Spark 和先决条件

+   将 Jupyter 笔记本与 Spark 集成

+   启动和配置 Spark 集群

+   停止 Spark 集群

# 介绍

深度学习是机器学习算法的专注研究，其主要学习方法是使用神经网络。深度学习在过去几年内迅速发展。微软、谷歌、Facebook、亚马逊、苹果、特斯拉等许多公司都在其应用程序、网站和产品中使用深度学习模型。与此同时，作为运行在大数据源之上的内存计算引擎，Spark 已经使处理大量信息变得更加容易和快速。事实上，Spark 现在已成为数据工程师、机器学习工程师和数据科学家的主要大数据开发工具。

由于深度学习模型在处理更多数据时表现更好，Spark 和深度学习之间的协同作用实现了完美的结合。几乎与用于执行深度学习算法的代码一样重要的是能够实现最佳开发的工作环境。许多才华横溢的人渴望开发神经网络，以帮助回答他们研究中的重要问题。不幸的是，深度学习模型开发的最大障碍之一是获得学习大数据所需的技术资源。本章的目的是为 Spark 上的深度学习创建一个理想的虚拟开发环境。

# 下载 Ubuntu 桌面镜像

Spark 可以为各种操作系统设置，无论是在本地还是在云中。对于我们的目的，Spark 将安装在以 Ubuntu 为操作系统的基于 Linux 的虚拟机上。使用 Ubuntu 作为首选虚拟机有几个优势，其中最重要的是成本。由于它们基于开源软件，Ubuntu 操作系统是免费使用的，不需要许可证。成本始终是一个考虑因素，本出版物的主要目标之一是尽量减少在 Spark 框架上开始深度学习所需的财务开支。

# 准备就绪

下载镜像文件需要满足一些最低要求：

+   至少 2GHz 双核处理器

+   至少 2GB 的系统内存

+   至少 25GB 的免费硬盘空间

# 操作步骤...

按照配方中的步骤下载 Ubuntu 桌面镜像：

1.  要创建 Ubuntu 桌面的虚拟机，首先需要从官方网站下载文件：[`www.ubuntu.com/download/desktop.`](https://www.ubuntu.com/download/desktop)

1.  截至目前，Ubuntu 桌面 16.04.3 是可供下载的最新版本。

1.  一旦下载完成，以.iso 格式访问以下文件：

`ubuntu-16.04.3-desktop-amd64.iso`

# 工作原理...

虚拟环境通过隔离与物理或主机机器的关系，提供了一个最佳的开发工作空间。开发人员可能会使用各种类型的主机环境，如运行 macOS 的 MacBook，运行 Windows 的 Microsoft Surface，甚至在 Microsoft Azure 或 AWS 云上的虚拟机；然而，为了确保代码执行的一致性，将部署一个 Ubuntu 桌面内的虚拟环境，可以在各种主机平台上使用和共享。

# 还有更多...

根据主机环境的不同，桌面虚拟化软件有几种选择。在使用 macOS 时，有两种常见的虚拟化软件应用：

+   VMWare Fusion

+   Parallels

# 另请参阅

要了解有关 Ubuntu 桌面的更多信息，请访问[`www.ubuntu.com/desktop`](https://www.ubuntu.com/desktop)。

# 在 macOS 上使用 VMWare Fusion 安装和配置 Ubuntu

本节将重点介绍使用 Ubuntu 操作系统构建虚拟机的过程，使用**VMWare Fusion**。

# 准备就绪

您的系统需要先安装 VMWare Fusion。如果您目前没有安装，可以从以下网站下载试用版本：

[`www.vmware.com/products/fusion/fusion-evaluation.html`](https://www.vmware.com/products/fusion/fusion-evaluation.html)

# 如何操作...

按照本文步骤配置在 macOS 上使用 VMWare Fusion 的 Ubuntu：

1.  一旦 VMWare Fusion 启动并运行，点击左上角的*+*按钮开始配置过程，并选择 New...，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00005.jpeg)

1.  选择后，选择从磁盘或镜像安装的选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00006.jpeg)

1.  选择从 Ubuntu 桌面网站下载的操作系统的`iso`文件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00007.jpeg)

1.  下一步将询问是否要选择 Linux Easy Install。建议这样做，并为 Ubuntu 环境设置显示名称/密码组合，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00008.jpeg)

1.  配置过程几乎完成了。显示虚拟机摘要，可以选择自定义设置以增加内存和硬盘，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00009.jpeg)

1.  虚拟机需要 20 到 40 GB 的硬盘空间就足够了；但是，将内存增加到 2 GB 甚至 4 GB 将有助于虚拟机在执行后续章节中的 Spark 代码时的性能。通过在虚拟机的设置下选择处理器和内存，并将内存增加到所需的数量来更新内存，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00010.jpeg)

# 工作原理...

设置允许手动配置必要的设置，以便在 VMWare Fusion 上成功运行 Ubuntu 桌面。根据主机机器的需求和可用性，可以增加或减少内存和硬盘存储。

# 还有更多...

现在剩下的就是第一次启动虚拟机，这将启动系统安装到虚拟机的过程。一旦所有设置完成并且用户已登录，Ubuntu 虚拟机应该可以用于开发，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00011.jpeg)

# 另请参阅

除了 VMWare Fusion 外，在 Mac 上还有另一款提供类似功能的产品。它被称为 Parallels Desktop for Mac。要了解有关 VMWare 和 Parallels 的更多信息，并决定哪个程序更适合您的开发，请访问以下网站：

+   [`www.vmware.com/products/fusion.html`](https://www.vmware.com/products/fusion.html) 下载并安装 Mac 上的 VMWare Fusion

+   [`parallels.com`](https://parallels.com) 下载并安装 Parallels Desktop for Mac

# 在 Windows 上使用 Oracle VirtualBox 安装和配置 Ubuntu

与 macOS 不同，在 Windows 中有几种虚拟化系统的选项。这主要是因为在 Windows 上虚拟化非常常见，因为大多数开发人员都在使用 Windows 作为他们的主机环境，并且需要虚拟环境进行测试，而不会影响依赖于 Windows 的任何依赖项。

# 准备就绪

Oracle 的 VirtualBox 是一款常见的虚拟化产品，可以免费使用。Oracle VirtualBox 提供了一个简单的过程，在 Windows 环境中运行 Ubuntu 桌面虚拟机。

# 如何操作...

按照本配方中的步骤，在 Windows 上使用**VirtualBox**配置 Ubuntu：

1.  启动 Oracle VM VirtualBox Manager。接下来，通过选择新建图标并指定机器的名称、类型和版本来创建一个新的虚拟机，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00012.jpeg)

1.  选择“专家模式”，因为一些配置步骤将被合并，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00013.jpeg)

理想的内存大小应至少设置为`2048`MB，或者更好的是`4096`MB，具体取决于主机机器上的资源。

1.  此外，为在 Ubuntu 虚拟机上执行深度学习算法设置一个最佳硬盘大小至少为 20GB，如果可能的话更大，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00014.jpeg)

1.  将虚拟机管理器指向 Ubuntu `iso`文件下载的启动磁盘位置，然后开始创建过程，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00015.jpeg)

1.  在安装一段时间后，选择启动图标以完成虚拟机，并准备好进行开发，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00016.jpeg)

# 工作原理...

该设置允许手动配置必要的设置，以便在 Oracle VirtualBox 上成功运行 Ubuntu 桌面。与 VMWare Fusion 一样，内存和硬盘存储可以根据主机机器的需求和可用性进行增加或减少。

# 还有更多...

请注意，一些运行 Microsoft Windows 的机器默认情况下未设置为虚拟化，并且用户可能会收到初始错误，指示 VT-x 未启用。这可以在重新启动时在 BIOS 中进行反转，并且可以启用虚拟化。

# 另请参阅

要了解更多关于 Oracle VirtualBox 并决定是否适合您，请访问以下网站并选择 Windows 主机开始下载过程：[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)。

# 安装和配置 Ubuntu 桌面以在 Google Cloud Platform 上运行

之前，我们看到了如何在 VMWare Fusion 上本地设置 Ubuntu 桌面。在本节中，我们将学习如何在**Google Cloud Platform**上进行相同的设置。

# 准备工作

唯一的要求是一个 Google 账户用户名。首先使用您的 Google 账户登录到 Google Cloud Platform。Google 提供一个免费的 12 个月订阅，账户中有 300 美元的信用额度。设置将要求您的银行详细信息；但是，Google 不会在未明确告知您的情况下向您收费。继续验证您的银行账户，然后您就可以开始了。

# 操作方法...

按照配方中的步骤配置 Ubuntu 桌面以在 Google Cloud Platform 上运行：

1.  一旦登录到您的 Google Cloud Platform，访问一个看起来像下面截图的仪表板：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00017.jpeg)

Google Cloud Platform 仪表板

1.  首先，点击屏幕左上角的产品服务按钮。在下拉菜单中，在计算下，点击 VM 实例，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00018.jpeg)

1.  创建一个新实例并命名它。在我们的案例中，我们将其命名为`ubuntuvm1`。在启动实例时，Google Cloud 会自动创建一个项目，并且实例将在项目 ID 下启动。如果需要，可以重命名项目。

1.  点击**创建实例**后，选择您所在的区域。

1.  在启动磁盘下选择**Ubuntu 16.04LTS**，因为这是将在云中安装的操作系统。请注意，LTS 代表版本，并且将获得来自 Ubuntu 开发人员的长期支持。

1.  接下来，在启动磁盘选项下，选择 SSD 持久磁盘，并将大小增加到 50GB，以增加实例的存储空间，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00019.jpeg)

1.  接下来，将访问范围设置为**允许对所有云 API 进行完全访问**。

1.  在防火墙下，请检查**允许 HTTP 流量**和**允许 HTTPS 流量**，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00020.jpeg)

选择选项允许 HTTP 流量和 HTTPS 流量

1.  一旦实例配置如本节所示，点击“创建”按钮创建实例。

点击“创建”按钮后，您会注意到实例已经创建，并且具有唯一的内部和外部 IP 地址。我们将在后期需要这个。SSH 是安全外壳隧道的缩写，基本上是在客户端-服务器架构中进行加密通信的一种方式。可以将其视为数据通过加密隧道从您的笔记本电脑到谷歌的云服务器，以及从谷歌的云服务器到您的笔记本电脑的方式。

1.  点击新创建的实例。从下拉菜单中，点击**在浏览器窗口中打开**，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00021.jpeg)

1.  您会看到谷歌在一个新窗口中打开了一个 shell/终端，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00022.jpeg)

1.  一旦 shell 打开，您应该看到一个如下图所示的窗口：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00023.jpeg)

1.  在 Google 云 shell 中输入以下命令：

```scala
$ sudo apt-get update
$ sudo apt-get upgrade
$ sudo apt-get install gnome-shell
$ sudo apt-get install ubuntu-gnome-desktop
$ sudo apt-get install autocutsel
$ sudo apt-get install gnome-core
$ sudo apt-get install gnome-panel
$ sudo apt-get install gnome-themes-standard
```

1.  当提示是否继续时，输入`y`并选择 ENTER，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00024.jpeg)

1.  完成上述步骤后，输入以下命令设置`vncserver`并允许连接到本地 shell：

```scala
$ sudo apt-get install tightvncserver
$ touch ~/.Xresources
```

1.  接下来，通过输入以下命令启动服务器：

```scala
$ tightvncserver
```

1.  这将提示您输入密码，稍后将用于登录到 Ubuntu 桌面虚拟机。此密码限制为八个字符，需要设置和验证，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00025.jpeg)

1.  外壳自动生成了一个启动脚本，如下图所示。可以通过复制并粘贴其`PATH`来访问和编辑此启动脚本：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00026.jpeg)

1.  在我们的情况下，查看和编辑脚本的命令是：

```scala
:~$ vim /home/amrith2kmeanmachine/.vnc/xstartup
```

这个`PATH`在每种情况下可能会有所不同。确保设置正确的`PATH`。`vim`命令会在 Mac 上的文本编辑器中打开脚本。

本地 shell 生成了一个启动脚本以及一个日志文件。启动脚本需要在文本编辑器中打开和编辑，接下来将讨论这一点。

1.  输入`vim`命令后，启动脚本的屏幕应该看起来像下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00027.jpeg)

1.  输入`i`进入`INSERT`模式。接下来，删除启动脚本中的所有文本。然后它应该看起来像下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00028.jpeg)

1.  将以下代码复制粘贴到启动脚本中：

```scala
#!/bin/sh
autocutsel -fork
xrdb $HOME/.Xresources
xsetroot -solid grey
export XKL_XMODMAP_DISABLE=1
export XDG_CURRENT_DESKTOP="GNOME-Flashback:Unity"
export XDG_MENU_PREFIX="gnome-flashback-"
unset DBUS_SESSION_BUS_ADDRESS
gnome-session --session=gnome-flashback-metacity --disable-acceleration-check --debug &
```

1.  脚本应该出现在编辑器中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00029.jpeg)

1.  按 Esc 退出`INSERT`模式，然后输入`:wq`以写入并退出文件。

1.  启动脚本配置完成后，在 Google shell 中输入以下命令关闭服务器并保存更改：

```scala
$ vncserver -kill :1
```

1.  此命令应该生成一个类似下图中的进程 ID：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00030.jpeg)

1.  通过输入以下命令重新启动服务器：

```scala
$ vncserver -geometry 1024x640
```

接下来的一系列步骤将专注于从本地主机安全地进入 Google Cloud 实例的外壳隧道。在本地 shell/终端上输入任何内容之前，请确保已安装 Google Cloud。如果尚未安装，请按照位于以下网站的快速入门指南中的说明进行安装：

[`cloud.google.com/sdk/docs/quickstart-mac-os-x`](https://cloud.google.com/sdk/docs/quickstart-mac-os-x)

1.  安装完 Google Cloud 后，在您的机器上打开终端，并输入以下命令连接到 Google Cloud 计算实例：

```scala
$ gcloud compute ssh \
YOUR INSTANCE NAME HERE \
--project YOUR PROJECT NAME HERE \
--zone YOUR TIMEZONE HERE \
--ssh-flag "-L 5901:localhost:5901"
```

1.  确保在上述命令中正确指定实例名称、项目 ID 和区域。按下 ENTER 后，本地 shell 的输出会变成下图所示的样子：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00031.jpeg)

1.  一旦您看到实例名称后跟着`":~$"`，这意味着本地主机/笔记本电脑和 Google Cloud 实例之间已成功建立了连接。成功通过 SSH 进入实例后，我们需要一个名为**VNC Viewer**的软件来查看和与已在 Google Cloud Compute 引擎上成功设置的 Ubuntu 桌面进行交互。接下来的几个步骤将讨论如何实现这一点。

1.  可以使用以下链接下载 VNC Viewer：

[`www.realvnc.com/en/connect/download/viewer/`](https://www.realvnc.com/en/connect/download/viewer/)

1.  安装完成后，点击打开 VNC Viewer，并在搜索栏中输入`localhost::5901`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00032.jpeg)

1.  接下来，在提示以下屏幕时点击**continue**：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00033.jpeg)

1.  这将提示您输入虚拟机的密码。输入您在第一次启动`tightvncserver`命令时设置的密码，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00034.jpeg)

1.  您将最终被带入到您在 Google Cloud Compute 上的 Ubuntu 虚拟机的桌面。当在 VNC Viewer 上查看时，您的 Ubuntu 桌面屏幕现在应该看起来像以下截图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00035.jpeg)

# 工作原理...

您现在已成功为与 Ubuntu 虚拟机/桌面交互设置了 VNC Viewer。建议在 Google Cloud 实例不使用时暂停或关闭实例，以避免产生额外费用。云方法对于可能无法访问高内存和存储资源的开发人员来说是最佳的。

# 还有更多...

虽然我们讨论了 Google Cloud 作为 Spark 的云选项，但也可以在以下云平台上利用 Spark：

+   Microsoft Azure

+   Amazon Web Services

# 另请参阅

要了解更多关于 Google Cloud Platform 并注册免费订阅，请访问以下网站：

[`cloud.google.com/`](https://cloud.google.com/)

# 在 Ubuntu 桌面上安装和配置 Spark 及其先决条件

在 Spark 可以运行之前，需要在新创建的 Ubuntu 桌面上安装一些必要的先决条件。本节将重点介绍在 Ubuntu 桌面上安装和配置以下内容：

+   Java 8 或更高版本

+   Anaconda

+   Spark

# 准备工作

本节的唯一要求是具有在 Ubuntu 桌面上安装应用程序的管理权限。

# 操作步骤...

本节将逐步介绍在 Ubuntu 桌面上安装 Python 3、Anaconda 和 Spark 的步骤：

1.  通过终端应用程序在 Ubuntu 上安装 Java，可以通过搜索该应用程序并将其锁定到左侧的启动器上找到，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00036.jpeg)

1.  通过在终端执行以下命令，在虚拟机上进行 Java 的初始测试：

```scala
java -version
```

1.  在终端执行以下四个命令来安装 Java：

```scala
sudo apt-get install software-properties-common 
$ sudo add-apt-repository ppa:webupd8team/java
$ sudo apt-get update
$ sudo apt-get install oracle-java8-installer
```

1.  接受 Oracle 的必要许可协议后，在终端再次执行`java -version`进行 Java 的二次测试。成功安装 Java 将在终端显示以下结果：

```scala
$ java -version
java version "1.8.0_144"
Java(TM) SE Runtime Environment (build 1.8.0_144-b01)
Java HotSpot(TM) 64-Bit Server VM (build 25.144-b01, mixed mode)
```

1.  接下来，安装最新版本的 Anaconda。当前版本的 Ubuntu 桌面预装了 Python。虽然 Ubuntu 预装 Python 很方便，但安装的版本是 Python 2.7，如下输出所示：

```scala
$ python --version
Python 2.7.12
```

1.  当前版本的 Anaconda 是 v4.4，Python 3 的当前版本是 v3.6。下载后，通过以下命令访问`Downloads`文件夹查看 Anaconda 安装文件：

```scala
$ cd Downloads/
~/Downloads$ ls
Anaconda3-4.4.0-Linux-x86_64.sh
```

1.  进入`Downloads`文件夹后，通过执行以下命令启动 Anaconda 的安装：

```scala
~/Downloads$ bash Anaconda3-4.4.0-Linux-x86_64.sh 
Welcome to Anaconda3 4.4.0 (by Continuum Analytics, Inc.)
In order to continue the installation process, please review the license agreement.
Please, press ENTER to continue
```

请注意，Anaconda 的版本以及其他安装的软件的版本可能会有所不同，因为新的更新版本会发布给公众。本章和本书中使用的 Anaconda 版本可以从[`repo.continuum.io/archive/Anaconda3-4.4.0-Linux-x86.sh`](https://repo.continuum.io/archive/Anaconda3-4.4.0-Linux-x86.sh)下载

1.  安装完成 Anaconda 后，重新启动终端应用程序，通过在终端中执行`python --version`来确认 Python 3 现在是 Anaconda 的默认 Python 环境：

```scala
$ python --version
Python 3.6.1 :: Anaconda 4.4.0 (64-bit)
```

1.  Linux 仍然提供 Python 2 版本，但在执行脚本时需要显式调用，如下命令所示：

```scala
~$ python2 --version
Python 2.7.12
```

1.  访问以下网站开始 Spark 下载和安装过程：

[`spark.apache.org/downloads.html`](https://spark.apache.org/downloads.html)

1.  选择下载链接。以下文件将下载到 Ubuntu 的**下载**文件夹中：

`spark-2.2.0-bin-hadoop2.7.tgz`

1.  通过执行以下命令在终端级别查看文件：

```scala
$ cd Downloads/
~/Downloads$ ls
spark-2.2.0-bin-hadoop2.7.tgz
```

1.  通过执行以下命令提取`tgz`文件：

```scala
~/Downloads$ tar -zxvf spark-2.2.0-bin-hadoop2.7.tgz
```

1.  使用`ls`查看**下载**目录，显示`tgz`文件和提取的文件夹：

```scala
~/Downloads$ ls
spark-2.2.0-bin-hadoop2.7 spark-2.2.0-bin-hadoop2.7.tgz
```

1.  通过执行以下命令，将提取的文件夹从**下载**文件夹移动到**主目录**文件夹：

```scala
~/Downloads$ mv spark-2.2.0-bin-hadoop2.7 ~/
~/Downloads$ ls
spark-2.2.0-bin-hadoop2.7.tgz
~/Downloads$ cd
~$ ls
anaconda3 Downloads Pictures Templates
Desktop examples.desktop Public Videos
Documents Music spark-2.2.0-bin-hadoop2.7
```

1.  现在，`spark-2.2.0-bin-hadoop2.7`文件夹已移动到**主目录**文件夹中，在左侧工具栏上选择**文件**图标时可以查看，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00037.jpeg)

1.  Spark 现在已安装。通过在终端级别执行以下脚本来启动 Spark：

```scala
~$ cd ~/spark-2.2.0-bin-hadoop2.7/
~/spark-2.2.0-bin-hadoop2.7$ ./bin/pyspark
```

1.  执行最终测试，以确保 Spark 在终端上运行，通过执行以下命令来确保`SparkContext`在本地环境中驱动集群：

```scala
>>> sc
<SparkContext master=local[*] appName=PySparkShell>
```

# 工作原理...

本节解释了 Python、Anaconda 和 Spark 的安装过程背后的原因。

1.  Spark 在**Java 虚拟机**（**JVM**）上运行，Java **软件开发工具包**（**SDK**）是 Spark 在 Ubuntu 虚拟机上运行的先决条件安装。

为了使 Spark 在本地机器或集群上运行，安装需要最低版本的 Java 6。

1.  Ubuntu 建议使用`sudo apt install`方法安装 Java，因为这样可以确保下载的软件包是最新的。

1.  请注意，如果尚未安装 Java，则终端中的输出将显示以下消息：

```scala
The program 'java' can be found in the following packages:
* default-jre
* gcj-5-jre-headless
* openjdk-8-jre-headless
* gcj-4.8-jre-headless
* gcj-4.9-jre-headless
* openjdk-9-jre-headless
Try: sudo apt install <selected package>
```

1.  虽然 Python 2 也可以，但被视为传统 Python。 Python 2 将于 2020 年面临终止生命周期日期；因此，建议所有新的 Python 开发都使用 Python 3，就像本出版物中的情况一样。直到最近，Spark 只能与 Python 2 一起使用。现在不再是这种情况。Spark 可以与 Python 2 和 3 一起使用。通过 Anaconda 是安装 Python 3 以及许多依赖项和库的便捷方式。Anaconda 是 Python 和 R 的免费开源发行版。Anaconda 管理 Python 中用于数据科学相关任务的许多常用软件包的安装和维护。

1.  在安装 Anaconda 过程中，重要的是确认以下条件：

+   Anaconda 安装在`/home/username/Anaconda3`位置

+   Anaconda 安装程序将 Anaconda3 安装位置前置到`/home/username/.bashrc`中的`PATH`中

1.  安装 Anaconda 后，下载 Spark。与 Python 不同，Spark 不会预先安装在 Ubuntu 上，因此需要下载和安装。

1.  为了进行深度学习开发，将选择以下 Spark 的偏好设置：

+   **Spark 版本**：**2.2.0** (2017 年 7 月 11 日)

+   **软件包类型**：预构建的 Apache Hadoop 2.7 及更高版本

+   **下载类型**：直接下载

1.  一旦 Spark 安装成功，通过在命令行执行 Spark 的输出应该看起来类似于以下截图：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00038.jpeg)

1.  初始化 Spark 时需要注意的两个重要特性是，它是在`Python 3.6.1` | `Anaconda 4.4.0 (64 位)` | 框架下，并且 Spark 标志的版本是 2.2.0。

1.  恭喜！Spark 已成功安装在本地 Ubuntu 虚拟机上。但是，还没有完成所有工作。当 Spark 代码可以在 Jupyter 笔记本中执行时，Spark 开发效果最佳，特别是用于深度学习。幸运的是，Jupyter 已经在本节前面执行的 Anaconda 分发中安装了。

# 还有更多...

也许你会问为什么我们不直接使用`pip install pyspark`在 Python 中使用 Spark。之前的 Spark 版本需要按照我们在本节中所做的安装过程。从 2.2.0 开始的未来版本的 Spark 将开始允许通过`pip`方法直接安装。我们在本节中使用完整的安装方法，以确保您能够在使用早期版本的 Spark 时安装和完全集成 Spark。

# 另请参阅

要了解更多关于 Jupyter 笔记本及其与 Python 的集成，请访问以下网站：

[`jupyter.org`](http://jupyter.org)

要了解有关 Anaconda 的更多信息并下载 Linux 版本，请访问以下网站：

[`www.anaconda.com/download/`](https://www.anaconda.com/download/)

# 将 Jupyter 笔记本与 Spark 集成

初学 Python 时，使用 Jupyter 笔记本作为交互式开发环境（IDE）非常有用。这也是 Anaconda 如此强大的主要原因之一。它完全整合了 Python 和 Jupyter 笔记本之间的所有依赖关系。PySpark 和 Jupyter 笔记本也可以做到同样的事情。虽然 Spark 是用 Scala 编写的，但 PySpark 允许在 Python 中进行代码转换。

# 做好准备

本节大部分工作只需要从终端访问`.bashrc`脚本。

# 如何操作...

PySpark 默认情况下未配置为在 Jupyter 笔记本中工作，但稍微调整`.bashrc`脚本即可解决此问题。我们将在本节中逐步介绍这些步骤：

1.  通过执行以下命令访问`.bashrc`脚本：

```scala
$ nano .bashrc
```

1.  滚动到脚本的最后应该会显示最后修改的命令，这应该是在上一节安装过程中由 Anaconda 设置的`PATH`。`PATH`应该如下所示：

```scala
# added by Anaconda3 4.4.0 installer
export PATH="/home/asherif844/anaconda3/bin:$PATH"
```

1.  在 Anaconda 安装程序添加的`PATH`下，可以包括一个自定义函数，帮助将 Spark 安装与 Anaconda3 中的 Jupyter 笔记本安装进行通信。在本章和后续章节中，我们将把该函数命名为`sparknotebook`。配置应该如下所示：`sparknotebook()`

```scala
function sparknotebook()
{
export SPARK_HOME=/home/asherif844/spark-2.2.0-bin-hadoop2.7
export PYSPARK_PYTHON=python3
export PYSPARK_DRIVER_PYTHON=jupyter
export PYSPARK_DRIVER_PYTHON_OPTS="notebook"
$SPARK_HOME/bin/pyspark
}
```

1.  更新后的`.bashrc`脚本应该保存后如下所示：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00039.jpeg)

1.  保存并退出`.bashrc`文件。建议通过执行以下命令并重新启动终端应用程序来确认`.bashrc`文件已更新：

```scala
$ source .bashrc
```

# 它是如何工作的...

本节的目标是将 Spark 直接集成到 Jupyter 笔记本中，以便我们不是在终端上进行开发，而是利用在笔记本中开发的好处。本节解释了在 Jupyter 笔记本中进行 Spark 集成的过程。

1.  我们将创建一个名为`sparknotebook`的命令函数，我们可以从终端调用它，通过 Anaconda 安装打开一个 Spark 会话的 Jupyter 笔记本。这需要在`.bashrc`文件中设置两个设置：

1.  PySpark Python 设置为 python 3

1.  将 PySpark 驱动程序设置为 Jupyter 的 Python

1.  现在可以直接从终端访问`sparknotebook`函数，方法是执行以下命令：

```scala
$ sparknotebook
```

1.  然后，该函数应通过默认的 Web 浏览器启动全新的 Jupyter 笔记本会话。可以通过单击右侧的“新建”按钮并在“笔记本”下选择“Python 3”来创建 Jupyter 笔记本中的新 Python 脚本，其扩展名为`.ipynb`，如下截图所示:![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00040.jpeg)

1.  再次，就像在终端级别为 Spark 做的那样，将在笔记本中执行`sc`的简单脚本，以确认 Spark 是否通过 Jupyter 正常运行:![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00041.jpeg)

1.  理想情况下，版本、主节点和应用名称应与在终端执行`sc`时的输出相同。如果是这种情况，那么 PySpark 已成功安装和配置为与 Jupyter 笔记本一起工作。

# 还有更多...

重要的是要注意，如果我们通过终端调用 Jupyter 笔记本而没有指定`sparknotebook`，我们的 Spark 会话将永远不会启动，并且在执行`SparkContext`脚本时会收到错误。

我们可以通过在终端执行以下内容来访问传统的 Jupyter 笔记本：

```scala
jupyter-notebook
```

一旦我们启动笔记本，我们可以尝试执行与之前相同的`sc.master`脚本，但这次我们将收到以下错误：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00042.jpeg)

# 另请参阅

在线提供了许多公司提供 Spark 的托管服务，通过笔记本界面，Spark 的安装和配置已经为您管理。以下是：

+   Hortonworks ([`hortonworks.com/`](https://hortonworks.com/))

+   Cloudera ([`www.cloudera.com/`](https://www.cloudera.com/))

+   MapR ([`mapr.com/`](https://mapr.com/))

+   DataBricks ([`databricks.com/`](https://mapr.com/))

# 启动和配置 Spark 集群

对于大多数章节，我们将要做的第一件事是初始化和配置我们的 Spark 集群。

# 准备就绪

在初始化集群之前导入以下内容。

+   `from pyspark.sql import SparkSession`

# 如何做...

本节介绍了初始化和配置 Spark 集群的步骤。

1.  使用以下脚本导入`SparkSession`：

```scala
from pyspark.sql import SparkSession
```

1.  使用以下脚本配置名为`spark`的`SparkSession`：

```scala
spark = SparkSession.builder \
    .master("local[*]") \
    .appName("GenericAppName") \
    .config("spark.executor.memory", "6gb") \
.getOrCreate()
```

# 它是如何工作的...

本节解释了`SparkSession`作为在 Spark 中开发的入口点的工作原理。

1.  从 Spark 2.0 开始，不再需要创建`SparkConf`和`SparkContext`来开始在 Spark 中进行开发。导入`SparkSession`将处理初始化集群。此外，重要的是要注意，`SparkSession`是`pyspark`的`sql`模块的一部分。

1.  我们可以为我们的`SparkSession`分配属性：

1.  `master`：将 Spark 主 URL 分配给在我们的`local`机器上运行，并使用最大可用的核心数。

1.  `appName`：为应用程序分配一个名称

1.  `config`：将`spark.executor.memory`分配为`6gb`

1.  `getOrCreate`：确保如果没有可用的`SparkSession`，则创建一个，并在可用时检索现有的`SparkSession`

# 还有更多...

出于开发目的，当我们在较小的数据集上构建应用程序时，我们可以只使用`master("local")`。如果我们要在生产环境中部署，我们将希望指定`master("local[*]")`，以确保我们使用最大可用的核心并获得最佳性能。

# 另请参阅

要了解有关`SparkSession.builder`的更多信息，请访问以下网站：

[`spark.apache.org/docs/2.2.0/api/java/org/apache/spark/sql/SparkSession.Builder.html`](https://spark.apache.org/docs/2.2.0/api/java/org/apache/spark/sql/SparkSession.Builder.html)

# 停止 Spark 集群

一旦我们在集群上开发完成，最好关闭它并保留资源。

# 如何做...

本节介绍了停止`SparkSession`的步骤。

1.  执行以下脚本：

`spark.stop()`

1.  通过执行以下脚本来确认会话是否已关闭：

`sc.master`

# 它是如何工作的...

本节将解释如何确认 Spark 集群已关闭。

1.  如果集群已关闭，当在笔记本中执行另一个 Spark 命令时，将会收到以下截图中看到的错误消息：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00043.jpeg)

# 还有更多...

在本地环境中工作时，关闭 Spark 集群可能并不那么重要；然而，在 Spark 部署在计算成本需要付费的云环境中，关闭集群将会很昂贵。


# 第二章：在 Spark 中创建神经网络

在本章中，将涵盖以下内容：

+   在 PySpark 中创建数据框

+   在 PySpark 数据框中操作列

+   将 PySpark dataframe 转换为数组

+   在散点图中可视化数组

+   设置权重和偏差以输入神经网络

+   对神经网络的输入数据进行归一化

+   验证数组以获得最佳神经网络性能

+   使用 Sigmoid 设置激活函数

+   创建 Sigmoid 导数函数

+   在神经网络中计算成本函数

+   基于身高和体重预测性别

+   可视化预测分数

# 介绍

本书的大部分内容将集中在使用 Python 中的库构建深度学习算法，例如 TensorFlow 和 Keras。虽然这些库有助于构建深度神经网络，而无需深入研究深度学习的微积分和线性代数，但本章将深入探讨在 PySpark 中构建一个简单的神经网络，以基于身高和体重进行性别预测。理解神经网络的基础之一是从头开始构建模型，而不使用任何流行的深度学习库。一旦建立了神经网络框架的基础，理解和利用一些更流行的深度神经网络库将变得更简单。

# 在 PySpark 中创建数据框

数据框将作为构建深度学习模型中使用的所有数据的框架。与 Python 中的`pandas`库类似，PySpark 具有内置功能来创建数据框。

# 准备工作

在 Spark 中创建数据框有几种方法。一种常见的方法是通过导入`.txt`、`.csv`或`.json`文件。另一种方法是手动输入字段和数据行到 PySpark 数据框中，虽然这个过程可能有点繁琐，但在处理小数据集时特别有帮助。本章将在 PySpark 中手动构建一个数据框，以身高和体重为基础预测性别。使用的数据集如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00044.jpeg)

虽然本章将手动将数据集添加到 PySpark 中，但数据集也可以从以下链接查看和下载：

[`github.com/asherif844/ApacheSparkDeepLearningCookbook/blob/master/CH02/data/HeightAndWeight.txt`](https://github.com/asherif844/ApacheSparkDeepLearningCookbook/blob/master/CH02/data/HeightAndWeight.txt)

最后，我们将通过使用以下终端命令在第一章中创建的 Jupyter 笔记本配置的 Spark 环境开始本章和未来的章节：

```scala
sparknotebook
```

# 如何做...

在使用 PySpark 时，必须首先导入和初始化`SparkSession`，然后才能创建任何数据框：

1.  使用以下脚本导入`SparkSession`：

```scala
from pyspark.sql import SparkSession

```

1.  配置`SparkSession`：

```scala
spark = SparkSession.builder \
         .master("local") \
         .appName("Neural Network Model") \
         .config("spark.executor.memory", "6gb") \
         .getOrCreate()
sc = spark.sparkContext
```

1.  在这种情况下，`SparkSession`的`appName`已命名为`Neural Network Model`，并且`6gb`已分配给会话内存。

# 它是如何工作的...

本节解释了如何创建我们的 Spark 集群并配置我们的第一个数据框。

1.  在 Spark 中，我们使用`.master()`来指定我们是在分布式集群上运行作业还是在本地运行。在本章和其余章节中，我们将使用`.master('local')`在本地执行 Spark，并指定一个工作线程。这对于测试和开发目的是可以的，但如果部署到生产环境可能会遇到性能问题。在生产环境中，建议使用`.master('local[*]')`来设置 Spark 在本地可用的尽可能多的工作节点上运行。如果我们的机器上有 3 个核心，并且我们想要设置我们的节点数与之匹配，那么我们将指定`.master('local[3]')`。

1.  `数据框`变量`df`首先通过插入每列的行值，然后使用以下脚本插入列标题名称来创建：

```scala
df = spark.createDataFrame([('Male', 67, 150), # insert column values
                            ('Female', 65, 135),
                            ('Female', 68, 130),
                            ('Male', 70, 160),
                            ('Female', 70, 130),
                            ('Male', 69, 174),
                            ('Female', 65, 126),
                            ('Male', 74, 188),
                            ('Female', 60, 110),
                            ('Female', 63, 125),
                            ('Male', 70, 173),
                            ('Male', 70, 145),
                            ('Male', 68, 175),
                            ('Female', 65, 123),
                            ('Male', 71, 145),
                            ('Male', 74, 160),
                            ('Female', 64, 135),
                            ('Male', 71, 175),
                            ('Male', 67, 145),
                            ('Female', 67, 130),
                            ('Male', 70, 162),
                            ('Female', 64, 107),
                            ('Male', 70, 175),
                            ('Female', 64, 130),
                            ('Male', 66, 163),
                            ('Female', 63, 137),
                            ('Male', 65, 165),
                            ('Female', 65, 130),
                            ('Female', 64, 109)], 
                           ['gender', 'height','weight']) # insert header values
```

1.  在 PySpark 中，`show()`函数可以预览前 20 行，如使用上述脚本时所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00045.jpeg)

# 还有更多...

如果没有明确说明，`.show()`功能默认显示 20 行。如果我们只想显示数据框的前 5 行，我们需要明确说明，如下脚本所示：`df.show(5)`。

# 另请参阅

要了解有关 SparkSQL、数据框、函数和 PySpark 中数据集的更多信息，请访问以下网站：

[`spark.apache.org/docs/latest/sql-programming-guide.html`](https://spark.apache.org/docs/latest/sql-programming-guide.html)

# 在 PySpark 数据框中操作列

数据框几乎完成了；但在构建神经网络之前，有一个需要解决的问题。与其将`gender`值保留为字符串，不如将该值转换为数值整数以进行计算，随着本章的进行，这一点将变得更加明显。

# 准备工作

这一部分需要导入以下内容：

+   `from pyspark.sql import functions`

# 如何做...

本节将介绍将数据框中的字符串转换为数值的步骤：

+   Female --> 0

+   Male --> 1

1.  在数据框中转换列值需要导入`functions`：

```scala
from pyspark.sql import functions
```

1.  接下来，使用以下脚本将`gender`列修改为数值：

```scala
df = df.withColumn('gender',functions.when(df['gender']=='Female',0).otherwise(1))
```

1.  最后，使用以下脚本重新排列列，使`gender`成为数据框中的最后一列：

```scala
df = df.select('height', 'weight', 'gender')
```

# 它是如何工作的...

本节解释了如何应用对数据框的操作。

1.  `pyspark.sql`中的`functions`具有几个有用的逻辑应用，可用于在 Spark 数据框中对列应用 if-then 转换。在我们的情况下，我们将`Female`转换为 0，`Male`转换为 1。

1.  使用`.withColumn()`转换将数值应用于 Spark 数据框。

1.  对于 Spark 数据框，`.select()`功能类似于传统 SQL，按照请求的顺序和方式选择列。

1.  最终预览数据框将显示更新后的数据集，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00046.jpeg)

# 还有更多...

除了数据框的`withColumn()`方法外，还有`withColumnRenamed()`方法，用于重命名数据框中的列。

# 将 PySpark 数据框转换为数组

为了构建神经网络的基本组件，PySpark 数据框必须转换为数组。Python 有一个非常强大的库`numpy`，使得处理数组变得简单。

# 准备工作

`numpy`库应该已经随着`anaconda3` Python 包的安装而可用。但是，如果由于某种原因`numpy`库不可用，可以使用终端上的以下命令进行安装：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00047.jpeg)

`pip install`或`sudo pip install`将通过使用请求的库来确认是否已满足要求：

```scala
import numpy as np
```

# 如何做...

本节将介绍将数据框转换为数组的步骤：

1.  使用以下脚本查看从数据框中收集的数据：

```scala
df.select("height", "weight", "gender").collect()
```

1.  使用以下脚本将收集的值存储到名为`data_array`的数组中：

```scala
data_array =  np.array(df.select("height", "weight", "gender").collect())
```

1.  执行以下脚本以访问数组的第一行：

```scala
data_array[0]
```

1.  同样，执行以下脚本以访问数组的最后一行：

```scala
data_array[28]
```

# 它是如何工作的...

本节解释了如何将数据框转换为数组：

1.  我们的数据框的输出可以使用`collect()`收集，并如下截图所示查看：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00048.jpeg)

1.  数据框转换为数组，并且可以在以下截图中看到该脚本的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00049.jpeg)

1.  可以通过引用数组的索引来访问任何一组`height`，`weight`和`gender`值。数组的形状为(29,3)，长度为 29 个元素，每个元素由三个项目组成。虽然长度为 29，但索引从`[0]`开始到`[28]`结束。可以在以下截图中看到数组形状以及数组的第一行和最后一行的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00050.jpeg)

1.  可以将数组的第一个和最后一个值与原始数据框进行比较，以确认转换的结果没有改变值和顺序。

# 还有更多...

除了查看数组中的数据点外，还可以检索数组中每个特征的最小和最大点：

1.  检索`height`，`weight`和`gender`的最小和最大值，可以使用以下脚本：

```scala
print(data_array.max(axis=0))
print(data_array.min(axis=0))
```

1.  脚本的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00051.jpeg)

最大`height`为`74`英寸，最小`height`为`60`英寸。最大重量为`188`磅，最小重量为`107`磅。性别的最小和最大值并不那么重要，因为我们已经为它们分配了`0`和`1`的数值。

# 另请参阅

要了解更多关于 numpy 的信息，请访问以下网站：

[www.numpy.org](http://www.numpy.org)

# 在散点图中可视化数组

本章将开发的神经网络的目标是在已知`height`和`weight`的情况下预测个体的性别。了解`height`，`weight`和`gender`之间的关系的一个强大方法是通过可视化数据点来喂养神经网络。这可以通过流行的 Python 可视化库`matplotlib`来实现。

# 准备工作

与`numpy`一样，`matplotlib`应该在安装 anaconda3 Python 包时可用。但是，如果由于某种原因`matplotlib`不可用，可以在终端使用以下命令进行安装：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00052.jpeg)

`pip install`或`sudo pip install`将通过使用所需的库来确认要求已经满足。

# 如何做到...

本节将介绍通过散点图可视化数组的步骤。

1.  导入`matplotlib`库并使用以下脚本配置库以在 Jupyter 笔记本中可视化绘图：

```scala
 import matplotlib.pyplot as plt
 %matplotlib inline
```

1.  接下来，使用`numpy`的`min()`和`max()`函数确定散点图的*x*和 y 轴的最小和最大值，如下脚本所示：

```scala
min_x = data_array.min(axis=0)[0]-10
max_x = data_array.max(axis=0)[0]+10
min_y = data_array.min(axis=0)[1]-10
max_y = data_array.max(axis=0)[1]+10
```

1.  执行以下脚本来绘制每个`gender`的`height`和`weight`：

```scala
# formatting the plot grid, scales, and figure size
plt.figure(figsize=(9, 4), dpi= 75)
plt.axis([min_x,max_x,min_y,max_y])
plt.grid()
for i in range(len(data_array)):
    value = data_array[i]
    # assign labels values to specific matrix elements
    gender = value[2]
    height = value[0]
    weight = value[1]

    # filter data points by gender
    a = plt.scatter(height[gender==0],weight[gender==0], marker 
      = 'x', c= 'b', label = 'Female')
    b = plt.scatter(height[gender==1],weight[gender==1], marker 
      = 'o', c= 'b', label = 'Male')

   # plot values, title, legend, x and y axis
   plt.title('Weight vs Height by Gender')
   plt.xlabel('Height (in)')
   plt.ylabel('Weight (lbs)')
   plt.legend(handles=[a,b])
```

# 它是如何工作的...

本节将解释如何将数组绘制为散点图：

1.  将`matplotlib`库导入到 Jupyter 笔记本中，并配置`matplotlib`库以在 Jupyter 笔记本的单元格中内联绘制可视化

1.  确定 x 和 y 轴的最小和最大值以调整我们的绘图，并给出一个最佳的外观图形。脚本的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00053.jpeg)

1.  每个轴都添加了`10`个像素的缓冲区，以确保捕获所有数据点而不被切断。

1.  创建一个循环来迭代每一行的值，并绘制`weight`与`height`。

1.  此外，`Female gender`分配了不同的样式点`x`，而`Male gender`分配了`o`。

1.  可以在以下截图中看到绘制 Weight vs Height by Gender 的脚本的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00054.jpeg)

# 还有更多...

散点图快速而简单地解释了数据的情况。散点图的右上象限和左下象限之间存在明显的分割。所有超过 140 磅的数据点表示`Male gender`，而所有低于该值的数据点属于`Female gender`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00055.jpeg)

这个散点图将有助于确认当在本章后面创建神经网络时，选择随机身高和体重来预测性别的结果是什么。

# 另请参阅

要了解更多关于`matplotlib`的信息，请访问以下网站：

[www.matplotlib.org](http://www.matplotlib.org/)

# 为输入神经网络设置权重和偏差。

PySpark 框架和数据现在已经完成。是时候转向构建神经网络了。无论神经网络的复杂性如何，开发都遵循类似的路径：

1.  输入数据

1.  添加权重和偏差

1.  求和数据和权重的乘积

1.  应用激活函数

1.  评估输出并将其与期望结果进行比较

本节将重点放在设置权重上，这些权重创建了输入，输入进入激活函数。

# 准备工作

简单了解神经网络的基本构建模块对于理解本节和本章的其余部分是有帮助的。每个神经网络都有输入和输出。在我们的案例中，输入是个体的身高和体重，输出是性别。为了得到输出，输入与值（也称为权重：w1 和 w2）相乘，然后加上偏差（b）。这个方程被称为求和函数 z，并给出以下方程式：

z = (输入 1) x (w1) + (输入 2) x (w2) + b

权重和偏差最初只是随机生成的值，可以使用`numpy`执行。权重将通过增加或减少对输出的影响来为输入增加权重。偏差将在一定程度上起到不同的作用，它将根据需要将求和（z）的基线向上或向下移动。然后，z 的每个值通过激活函数转换为 0 到 1 之间的预测值。激活函数是一个转换器，它给我们一个可以转换为二进制输出（男/女）的值。然后将预测输出与实际输出进行比较。最初，预测和实际输出之间的差异将很大，因为在刚开始时权重是随机的。然而，使用一种称为反向传播的过程来最小化实际和预测之间的差异，使用梯度下降的技术。一旦我们在实际和预测之间达成可忽略的差异，我们就会存储神经网络的 w1、w2 和 b 的值。

# 如何做...

本节将逐步介绍设置神经网络的权重和偏差的步骤。

1.  使用以下脚本设置值生成器的随机性：

```scala
np.random.seed(12345)
```

1.  使用以下脚本设置权重和偏差：

```scala
w1 = np.random.randn()
w2 = np.random.randn()
b= np.random.randn()
```

# 工作原理...

本节解释了如何初始化权重和偏差，以便在本章的后续部分中使用：

1.  权重是使用`numpy`随机生成的，并设置了随机种子以确保每次生成相同的随机数

1.  权重将被分配一个通用变量`w1`和`w2`

1.  偏差也是使用`numpy`随机生成的，并设置了随机种子以确保每次生成相同的随机数

1.  偏差将被分配一个通用变量`b`

1.  这些值被插入到一个求和函数`z`中，它生成一个初始分数，将输入到另一个函数中，即激活函数，稍后在本章中讨论

1.  目前，所有三个变量都是完全随机的。`w1`、`w2`和`b`的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00056.jpeg)

# 还有更多...

最终目标是获得一个预测输出，与实际输出相匹配。对权重和值进行求和的过程有助于实现这一过程的一部分。因此，随机输入的`0.5`和`0.5`将产生以下求和输出：

```scala
z = 0.5 * w1 + 0.5 * w2 + b 
```

或者，使用我们当前随机值`w1`和`w2`，将得到以下输出：

```scala
z = 0.5 * (-0.2047) + 0.5 * (0.47894) + (-0.51943) = -7.557
```

变量`z`被分配为权重与数据点的乘积总和。目前，权重和偏差是完全随机的。然而，正如本节前面提到的，通过一个称为反向传播的过程，使用梯度下降，权重将被调整，直到确定出更理想的结果。梯度下降只是识别出我们的权重的最佳值的过程，这将给我们最好的预测输出，并且具有最小的误差。确定最佳值的过程涉及识别函数的局部最小值。梯度下降将在本章后面讨论。

# 另请参阅

要了解更多关于人工神经网络中权重和偏差的知识，请访问以下网站：

[`en.wikipedia.org/wiki/Artificial_neuron`](https://en.wikipedia.org/wiki/Artificial_neuron)

# 为神经网络标准化输入数据

当输入被标准化时，神经网络的工作效率更高。这最小化了特定输入的幅度对其他可能具有较低幅度值的输入的整体结果的影响。本节将标准化当前个体的`身高`和`体重`输入。

# 准备好

输入值的标准化需要获取这些值的平均值和标准差进行最终计算。

# 如何做...

本节将介绍标准化身高和体重的步骤。

1.  使用以下脚本将数组切片为输入和输出：

```scala
X = data_array[:,:2]
y = data_array[:,2]
```

1.  可以使用以下脚本计算 29 个个体的平均值和标准差：

```scala
x_mean = X.mean(axis=0)
x_std = X.std(axis=0)

```

1.  创建一个标准化函数，使用以下脚本对`X`进行标准化：

```scala
 def normalize(X):
     x_mean = X.mean(axis=0)
     x_std = X.std(axis=0)
     X = (X - X.mean(axis=0))/X.std(axis=0)
     return X
```

# 它是如何工作的...

本节将解释身高和体重是如何被标准化的。

1.  `data_array`矩阵分为两个矩阵：

1.  `X`由身高和体重组成

1.  `y`由性别组成

1.  两个数组的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00057.jpeg)

1.  `X`组件是输入，是唯一会经历标准化过程的部分。*y*组件，或性别，暂时将被忽略。标准化过程涉及提取所有 29 个个体的输入的平均值和标准差。身高和体重的平均值和标准差的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00058.jpeg)

1.  身高的平均值约为 67 英寸，标准差约为 3.4 英寸。体重的平均值约为 145 磅，标准差约为 22 磅。

1.  一旦它们被提取，使用以下方程对输入进行标准化：`X_norm = (X - X_mean)/X_std`。

1.  使用 Python 函数`normalize()`对`X`数组进行标准化，现在`X`数组被分配到新创建的标准化集的值，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00059.jpeg)

# 另请参阅

要了解更多关于统计标准化的知识，请访问以下网站：

[`en.wikipedia.org/wiki/Normalization_(statistics)`](https://en.wikipedia.org/wiki/Normalization_(statistics))

# 验证数组以获得最佳神经网络性能

在确保我们的数组在即将到来的神经网络中获得最佳性能的过程中，一点验证工作可以走很长的路。

# 准备好

这一部分需要使用`numpy.stack()`函数进行一些`numpy`魔术。

# 如何做...

以下步骤将验证我们的数组是否已被标准化。

1.  执行以下步骤以打印数组输入的平均值和标准差：

```scala
print('standard deviation')
print(round(X[:,0].std(axis=0),0))
print('mean')
print(round(X[:,0].mean(axis=0),0))
```

1.  执行以下脚本将身高、体重和性别组合成一个数组`data_array`：

```scala
data_array = np.column_stack((X[:,0], X[:,1],y))
```

# 它是如何工作的...

本节解释了数组如何被验证和构建，以便在神经网络中实现最佳的未来使用。

1.  身高的新`mean`应为 0，`standard deviation`应为 1。这可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00060.jpeg)

1.  这是归一化数据集的确认，因为它包括平均值为 0 和标准差为 1。

1.  原始的`data_array`对于神经网络不再有用，因为它包含了`height`、`weight`和`gender`的原始、非归一化的输入值。

1.  然而，通过一点点`numpy`魔法，`data_array`可以被重组，包括归一化的`height`和`weight`，以及`gender`。这是通过`numpy.stack()`完成的。新数组`data_array`的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00061.jpeg)

# 还有更多...

我们的数组现在已经准备就绪。我们的身高和体重的输入已经归一化，我们的性别输出标记为 0 或 1。

# 另请参阅

要了解有关`numpy.stack()`的更多信息，请访问以下网站：

[`docs.scipy.org/doc/numpy/reference/generated/numpy.stack.html`](https://docs.scipy.org/doc/numpy/reference/generated/numpy.stack.html)

# 使用`sigmoid`设置激活函数

激活函数在神经网络中用于帮助确定输出，无论是是或否，真或假，或者在我们的情况下是 0 或 1（男/女）。此时，输入已经被归一化，并且已经与权重和偏差`w1`、`w2`和`b`相加。然而，权重和偏差目前完全是随机的，并且没有被优化以产生与实际输出匹配的预测输出。构建预测结果的缺失环节在于激活或`sigmoid`函数，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00062.jpeg)

如果总和产生的数字非常小，它将产生激活为 0。同样，如果总和产生的数字相当大，它将产生激活为 1。这个函数很有用，因为它将输出限制为二进制结果，这对于分类非常有用。这些输出的后果将在本章的其余部分中讨论和澄清。

# 准备工作

`sigmoid`函数类似于逻辑回归函数，因为它计算出 0 到 1 之间的概率结果。此外，它给出了介于两者之间的范围。因此，可以设置条件，将大于 0.5 的任何值关联到 1，小于 0.5 的值关联到 0。

# 如何做到...

本节将逐步介绍使用样本数据创建和绘制`sigmoid`函数的步骤。

1.  使用 Python 函数创建`sigmoid`函数，如下脚本所示：

```scala
def sigmoid(input):
  return 1/(1+np.exp(-input))
```

1.  使用以下脚本为`sigmoid`曲线创建样本`x`值：

```scala
X = np.arange(-10,10,1)
```

1.  此外，使用以下脚本为`sigmoid`曲线创建样本`y`值：

```scala
Y = sigmoid(X)
```

1.  使用以下脚本绘制这些点的`x`和`y`值：

```scala
plt.figure(figsize=(6, 4), dpi= 75)
plt.axis([-10,10,-0.25,1.2])
plt.grid()
plt.plot(X,Y)
plt.title('Sigmoid Function')
plt.show()
```

# 它是如何工作的...

本节介绍了 S 型函数背后的数学原理。

1.  `sigmoid`函数是逻辑回归的专门版本，用于分类。逻辑回归的计算用以下公式表示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00063.jpeg)

1.  逻辑回归函数的变量代表以下含义：

+   *L*代表函数的最大值

+   *k*代表曲线的陡峭程度

+   *x[midpoint]*代表函数的中点值

1.  由于`sigmoid`函数的陡度值为 1，中点为 0，最大值为 1，它产生以下函数：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00064.jpeg)

1.  我们可以绘制一个通用的`sigmoid`函数，其 x 值范围从-5 到 5，y 值范围从 0 到 1，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00065.jpeg)

1.  我们使用 Python 创建了自己的`sigmoid`函数，并使用样本数据在`-10`和`10`之间绘制了它。我们的绘图看起来与之前的通用`sigmoid`绘图非常相似。我们的`sigmoid`函数的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00066.jpeg)

# 另请参阅

要了解更多关于`sigmoid`函数起源的信息，请访问以下网站：

[`en.wikipedia.org/wiki/Sigmoid_function`](https://en.wikipedia.org/wiki/Sigmoid_function)

# 创建 Sigmoid 导数函数

Sigmoid 函数是一个独特的函数，其中 Sigmoid 函数的导数值包括 Sigmoid 函数的值。也许你会问这有什么了不起。然而，由于 Sigmoid 函数已经计算，这使得在执行多层反向传播时处理更简单、更高效。此外，在计算中使用 Sigmoid 函数的导数来得出最佳的`w1`、`w2`和`b`值，以得出最准确的预测输出。

# 准备工作

对微积分中的导数有一定的了解将有助于理解 Sigmoid 导数函数。

# 如何做...

本节将介绍创建 Sigmoid 导数函数的步骤。

1.  就像`sigmoid`函数一样，使用以下脚本可以使用 Python 创建`sigmoid`函数的导数：

```scala
def sigmoid_derivative(x):
    return sigmoid(x) * (1-sigmoid(x))
```

1.  使用以下脚本绘制`sigmoid`函数的导数与原始`sigmoid`函数：

```scala
plt.figure(figsize=(6, 4), dpi= 75)
plt.axis([-10,10,-0.25,1.2])
plt.grid()
X = np.arange(-10,10,1)
Y = sigmoid(X)
Y_Prime = sigmoid_derivative(X)
c=plt.plot(X, Y, label="Sigmoid",c='b')
d=plt.plot(X, Y_Prime, marker=".", label="Sigmoid Derivative", c='b')
plt.title('Sigmoid vs Sigmoid Derivative')
plt.xlabel('X')
plt.ylabel('Y')
plt.legend()
plt.show()
```

# 工作原理...

本节将解释 Sigmoid 函数的导数背后的数学原理，以及使用 Python 创建 Sigmoid 函数的导数的逻辑。

1.  神经网络将需要`sigmoid`函数的导数来预测`gender`的准确输出。`sigmoid`函数的导数使用以下公式计算：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00067.jpeg)

1.  然后，我们可以使用 Python 中的原始 Sigmoid 函数`sigmoid()`创建 Sigmoid 函数的导数`sigmoid_derivate()`。我们可以在以下截图中将两个函数并排绘制：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00068.jpeg)

1.  Sigmoid 导数跟踪原始 Sigmoid 函数的斜率。在绘图的早期阶段，当 Sigmoid 的斜率完全水平时，Sigmoid 导数也是 0.0。当 Sigmoid 的值接近 1 时，斜率也几乎完全水平。Sigmoid 的斜率的峰值在 x 轴的中点。因此，这也是 Sigmoid 导数的峰值。

# 另请参阅

要深入了解导数，请访问以下网站：

[`www.khanacademy.org/math/calculus-home/taking-derivatives-calc`](https://www.khanacademy.org/math/calculus-home/taking-derivatives-calc)

# 在神经网络中计算成本函数

此时，是时候将本章前面强调的所有部分汇总起来，计算成本函数了，神经网络将使用该函数来确定预测结果与原始或实际结果的匹配程度，给定当前可用的 29 个个体数据点。成本函数的目的是确定实际值和预测值之间的差异。然后使用梯度下降来增加或减少`w1`、`w2`和`b`的值，以减少成本函数的值，最终实现我们的目标，得出与实际值匹配的预测值。

# 准备工作

成本函数的公式如下：

成本(x)=(预测-实际)²

如果成本函数看起来很熟悉，那是因为这实际上只是最小化实际输出和预测之间的平方差的另一种方式。神经网络中梯度下降或反向传播的目的是将成本函数最小化，直到该值接近 0。在那一点上，权重和偏差（`w1`、`w2`和`b`）将不再是由`numpy`生成的随机无关紧要的值，而是对神经网络模型有实际贡献的实际重要权重。

# 如何做...

本节将介绍计算成本函数的步骤。

1.  设置学习率值为`0.1`，逐步改变权重和偏差，直到使用以下脚本选择最终输出：

```scala
learningRate = 0.1
```

1.  使用以下脚本初始化一个名为`allCosts`的 Python 列表。

```scala
allCosts = []
```

1.  创建一个`for`循环，使用以下脚本迭代 100,000 个场景：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00069.jpeg)

1.  使用以下脚本绘制 100,000 次迭代中收集的成本值：

```scala
plt.plot(all_costs)
plt.title('Cost Value over 100,000 iterations')
plt.xlabel('Iteration')
plt.ylabel('Cost Value')
plt.show()
```

1.  可以使用以下脚本查看权重和偏差的最终值：

```scala
print('The final values of w1, w2, and b')
print('---------------------------------')
print('w1 = {}'.format(w1))
print('w2 = {}'.format(w2))
print('b = {}'.format(b))
```

# 它是如何工作的...

本节解释了如何使用成本函数生成权重和偏差。

1.  将实施一个`for`循环，该循环将对权重和偏差执行梯度下降，以调整值，直到成本函数接近 0。

1.  循环将迭代 100,000 次成本函数。每次从 29 个个体中随机选择`height`和`weight`的值。

1.  从随机的`height`和`weight`计算出总和值`z`，并使用输入计算出`sigmoid`函数的`predictedGender`分数。

1.  计算成本函数，并将其添加到跟踪 100,000 次迭代中的所有成本函数的列表`allCosts`中。

1.  计算了一系列关于总和值（`z`）以及成本函数（`cost`）的偏导数。

1.  这些计算最终用于根据成本函数更新权重和偏差，直到它们（`w1`、`w2`和`b`）在 100,000 次迭代中返回接近 0 的值。

1.  最终，目标是使成本函数的值随着迭代次数的增加而减少。成本函数在 100,000 次迭代中的输出可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00070.jpeg)

1.  在迭代过程中，成本值从约 0.45 下降到约 0.01。

1.  此外，我们可以查看产生成本函数最低值的`w1`、`w2`和`b`的最终输出，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00071.jpeg)

# 还有更多...

现在可以测试权重和偏差的最终值，以计算成本函数的工作效果以及预测值与实际分数的比较。

以下脚本将通过每个个体创建一个循环，并基于权重（`w1`、`w2`）和偏差（`b`）计算预测的性别分数：

```scala
for i in range(len(data_array)):
    random_individual = data_array[i]
    height = random_individual[0]
    weight = random_individual[1]
    z = height*w1 + weight*w2 + b
    predictedGender=sigmoid(z)
    print("Individual #{} actual score: {} predicted score:                           {}".format(i+1,random_individual[2],predictedGender))
```

可以在下面的截图中看到脚本的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00072.jpeg)

29 个实际分数大约与预测分数相匹配。虽然这对于确认模型在训练数据上产生匹配结果是有好处的，但最终的测试将是确定模型是否能够对引入的新个体进行准确的性别预测。

# 另请参阅

要了解更多关于使用梯度下降来最小化成本函数或平方（差）误差函数的信息，请访问以下网站：

[`en.wikipedia.org/wiki/Gradient_descent`](https://en.wikipedia.org/wiki/Gradient_descent)

# 根据身高和体重预测性别

只有当预测模型实际上可以根据新信息进行预测时，它才有用。这适用于简单的逻辑或线性回归，或更复杂的神经网络模型。

# 准备好了

这就是乐趣开始的地方。本节的唯一要求是为男性和女性个体提取样本数据点，并使用其身高和体重值来衡量前一节中创建的模型的准确性。

# 如何做...

本节介绍了如何根据身高和体重预测性别的步骤。

1.  创建一个名为`input_normalize`的 Python 函数，用于输入`height`和`weight`的新值，并输出归一化的身高和体重，如下脚本所示：

```scala
def input_normalize(height, weight):
    inputHeight = (height - x_mean[0])/x_std[0]
    inputWeight = (weight - x_mean[1])/x_std[1]
    return inputHeight, inputWeight
```

1.  为`height`设置值为`70`英寸，为`weight`设置值为`180`磅，并将其分配给名为`score`的变量，如下脚本所示：

```scala
score = input_normalize(70, 180)
```

1.  创建另一个 Python 函数，名为`predict_gender`，输出一个概率分数`gender_score`，介于 0 和 1 之间，以及一个性别描述，通过应用与`w1`、`w2`和`b`的求和以及`sigmoid`函数，如下脚本所示：

```scala
def predict_gender(raw_score):
    gender_summation = raw_score[0]*w1 + raw_score[1]*w2 + b
    gender_score = sigmoid(gender_summation)
    if gender_score <= 0.5:
        gender = 'Female'
    else:
        gender = 'Male'
    return gender, gender_score
```

# 工作原理...

本节解释了如何使用身高和体重的新输入来生成性别的预测分数。

1.  创建一个函数来输入新的身高和体重值，并将实际值转换为规范化的身高和体重值，称为`inputHeight`和`inputWeight`。

1.  使用一个变量`score`来存储规范化的值，并创建另一个函数`predictGender`来输入分数值，并根据前一节中创建的`w1`、`w2`和`b`的值输出性别分数和描述。这些值已经经过梯度下降进行了预调整，以微调这些值并最小化`cost`函数。

1.  将`score`值应用到`predict_gender`函数中，应该显示性别描述和分数，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00073.jpeg)

1.  似乎`70`英寸的`height`和`180`磅的`weight`的规格是男性的高预测器（99.999%）。

1.  对于`50`英寸的`height`和`150`磅的`weight`的另一个测试可能会显示不同的性别，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00074.jpeg)

1.  同样，这个输入从`sigmoid`函数中产生了一个非常低的分数（0.00000000839），表明这些特征与`Female`性别密切相关。

# 另请参阅

要了解更多关于测试、训练和验证数据集的信息，请访问以下网站：

[`en.wikipedia.org/wiki/Training,_test,_and_validation_sets`](https://en.wikipedia.org/wiki/Training,_test,_and_validation_sets)

# 可视化预测分数

虽然我们可以根据特定身高和体重的个体单独预测性别，但整个数据集可以通过使用每个数据点来绘制和评分，以确定输出是女性还是男性。

# 准备工作

本节不需要任何依赖项。

# 如何做...

本节将通过步骤来可视化图表中的所有预测点。

1.  使用以下脚本计算图表的最小和最大点：

```scala
x_min = min(data_array[:,0])-0.1
x_max = max(data_array[:,0])+0.1
y_min = min(data_array[:,1])-0.1
y_max = max(data_array[:,1])+0.1
increment= 0.05

print(x_min, x_max, y_min, y_max)
```

1.  生成*x*和*y*值，增量为 0.05 单位，然后创建一个名为`xy_data`的数组，如下脚本所示：

```scala
x_data= np.arange(x_min, x_max, increment)
y_data= np.arange(y_min, y_max, increment)
xy_data = [[x_all, y_all] for x_all in x_data for y_all in y_data]
```

1.  最后，使用本章前面使用过的类似脚本来生成性别分数并填充图表，如下脚本所示：

```scala
for i in range(len(xy_data)):
    data = (xy_data[i])
    height = data[0]
    weight = data[1] 
    z_new = height*w1 + weight*w2 + b
    predictedGender_new=sigmoid(z_new)
    # print(height, weight, predictedGender_new)
    ax = plt.scatter(height[predictedGender_new<=0.5],
            weight[predictedGender_new<=0.5],     
            marker = 'o', c= 'r', label = 'Female')    
    bx = plt.scatter(height[predictedGender_new > 0.5],
            weight[predictedGender_new>0.5], 
            marker = 'o', c= 'b', label = 'Male') 
    # plot values, title, legend, x and y axis
    plt.title('Weight vs Height by Gender')
    plt.xlabel('Height (in)')
    plt.ylabel('Weight (lbs)')
    plt.legend(handles=[ax,bx])
```

# 工作原理...

本节解释了如何创建数据点以生成将被绘制的预测值。

1.  根据数组值计算图表的最小和最大值。脚本的输出可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00075.jpeg)

1.  我们为每个数据点生成 x 和 y 值，在 0.05 的增量内的最小和最大值，并将每个（x，y）点运行到预测分数中以绘制这些值。女性性别分数分配为红色，男性性别分数分配为蓝色，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00076.jpeg)

1.  图表显示了根据所选的`height`和`weight`之间的性别分数的分界线。


# 第三章：卷积神经网络的痛点

在本章中，将介绍以下内容：

+   痛点＃1：导入 MNIST 图像

+   痛点＃2：可视化 MNIST 图像

+   痛点＃3：将 MNIST 图像导出为文件

+   痛点＃4：增强 MNIST 图像

+   痛点＃5：利用训练图像的替代来源

+   痛点＃6：优先考虑用于 CNN 的高级库

# 介绍

**卷积神经网络**（**CNN**）在过去几年中一直备受关注。在图像识别方面取得了巨大成功。随着现代智能手机的出现，任何人现在都有能力拍摄大量物体的照片并将其发布在社交媒体网站上，这在当今时代非常相关。正是由于这种现象，卷积神经网络如今需求量很大。

有几个特性使 CNN 能够最佳地执行。它们需要以下特性：

+   大量的训练数据

+   视觉和空间数据

+   强调过滤（池化）、激活和卷积，而不是传统神经网络中更明显的全连接层

虽然 CNN 已经广受欢迎，但由于其计算需求以及需要大量训练数据来获得性能良好的模型，它们在使用中存在一些局限性。我们将专注于可以应用于数据的技术，这些技术最终将有助于开发卷积神经网络，并解决这些局限性。在后面的章节中，当我们为图像分类开发模型时，我们将应用其中一些技术。

# 痛点＃1：导入 MNIST 图像

用于图像分类的最常见数据集之一是`MNIST`数据集，它由成千上万个手写数字样本组成。根据 Yann LeCun、Corinna Cortes 和 Christopher J.C. Burges 的说法，**修改后的国家标准与技术研究所**（**MNIST**）有以下用途：

这是一个适合想要尝试在真实世界数据上学习技术和模式识别方法的人的良好数据库，同时在预处理和格式化上花费最少的精力。

在我们的 Jupyter 笔记本中导入 MNIST 图像有几种方法。在本章中，我们将介绍以下两种方法：

1.  直接通过 TensorFlow 库

1.  通过 MNIST 网站手动操作

需要注意的一点是，我们将主要使用 MNIST 图像作为我们如何改进卷积神经网络性能的示例。所有这些将应用于 MNIST 图像的技术都可以应用于用于训练 CNN 的任何图像。

# 准备工作

唯一需要的要求是安装`TensorFlow`。它可能不会预先安装在 anaconda3 软件包中；因此，简单的`pip`安装将确认`TensorFlow`的可用性，或者如果当前不可用，则安装它。`TensorFlow`可以在终端中轻松安装，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00077.jpeg)

# 如何做...

`TensorFlow`库中有一个方便的内置示例集，可以直接使用。其中一个示例数据集就是`MNIST`。本节将介绍访问这些图像的步骤。

1.  使用以下脚本将`TensorFlow`导入库，并使用别名`tf`：

```scala
import tensorflow as tf
```

1.  使用以下脚本从库中下载和提取图像，并保存到本地文件夹：

```scala
from tensorflow.examples.tutorials.mnist import input_data
data = input_data.read_data_sets('MNIST/', one_hot=True)
```

1.  使用以下脚本检索将用于评估图像分类准确性的训练和测试数据集的最终计数：

```scala
print('Image Inventory')
print('----------')
print('Training: ' + str(len(data.train.labels)))
print('Testing: '+ str(len(data.test.labels)))
print('----------')
```

# 工作原理...

本节解释了访问 MNIST 数据集的过程：

1.  一旦我们收到确认`TensorFlow`库已正确安装，就将其导入笔记本。

1.  我们可以确认`TensorFlow`的版本，并将图像提取到我们的`MNIST/`本地文件夹中。提取过程可在笔记本的输出中看到，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00078.jpeg)

1.  提取的四个文件分别命名为：

1.  `t10k-images-idx3-ubyte.gz`

1.  `t10k-labels-idx1-ubyte.gz`

1.  `train-images-idx3-ubyte.gz`

1.  `train-labels-idx1-ubyte.gz`

1.  它们已经下载到`MNIST/`子文件夹中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00079.jpeg)

1.  此外，可以在我们的笔记本中查看这四个文件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00080.jpeg)

1.  这四个文件是测试和训练图像以及相应的测试和训练标签，用于识别测试和训练数据集中的每个图像。此外，明确定义了`one_hot = True`特性。这表明标签使用 one-hot 编码，有助于模型中的特征选择，因为每列的值将是 0 或 1。 

1.  还导入了库的一个子类，它将 MNIST 的手写图像存储到指定的本地文件夹中。包含所有图像的文件夹应该大约为 12MB，包括 55,000 张训练图像和 10,000 张测试图像，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00081.jpeg)

1.  这 10,000 张图像将用于测试我们将在 55,000 张图像上训练的模型的准确性。

# 还有更多...

在尝试通过`TensorFlow`直接访问 MNIST 数据集时，有时可能会出现错误或警告。就像在本节前面看到的那样，当导入 MNIST 时，我们收到了以下警告：

警告：从<ipython-input-3-ceaef6f48460>:2 读取数据集（来自 tensorflow.contrib.learn.python.learn.datasets.mnist）已被弃用，并将在将来的版本中删除。

更新说明：

请使用替代方案，例如来自 tensorflow/models 的 official/mnist/dataset.py。

数据集可能会在未来的`TensorFlow`版本中被弃用，因此不再直接可访问。有时，当通过`TensorFlow`提取 MNIST 图像时，我们可能会遇到典型的*HTTP 403 错误*。这可能是因为网站暂时不可用。无论哪种情况，都有一种手动方法可以使用以下链接下载这四个`.gz`文件：

[`yann.lecun.com/exdb/mnist/`](http://yann.lecun.com/exdb/mnist/)

这些文件位于网站上，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00082.jpeg)

下载这些文件并将它们保存到一个可访问的本地文件夹，类似于直接从`TensorFlow`获取的文件所做的操作。

# 另请参阅

要了解更多关于`MNIST`手写数字数据库的信息，请访问以下网站：[`yann.lecun.com/exdb/mnist/`](http://yann.lecun.com/exdb/mnist/)。

要了解更多关于 one-hot 编码的信息，请访问以下网站：[`hackernoon.com/what-is-one-hot-encoding-why-and-when-do-you-have-to-use-it-e3c6186d008f.`](https://hackernoon.com/what-is-one-hot-encoding-why-and-when-do-you-have-to-use-it-e3c6186d008f)

# 痛点＃2：可视化 MNIST 图像

在 Jupyter 笔记本中处理图形时，绘制图像通常是一个主要的痛点。显示训练数据集中的手写图像至关重要，特别是当比较与手写图像相关联的标签的实际值时。

# 准备工作

用于可视化手写图像的唯一 Python 库是`numpy`和`matplotlib`。这两个库应该已经通过 Anaconda 中的软件包可用。如果由于某种原因它们不可用，可以在终端使用以下命令进行`pip`安装：

+   `pip install matplotlib`

+   `pip install numpy`

# 如何做...

本节将介绍在 Jupyter 笔记本中可视化 MNIST 手写图像的步骤：

1.  导入以下库，`numpy`和`matplotlib`，并使用以下脚本配置`matplotlib`以进行`inline`绘图：

```scala
import numpy as np
import matplotlib.pyplot as plt
%matplotlib inline
```

1.  使用以下脚本绘制前两个样本图像：

```scala
for i in range(2):
    image = data.train.images[i]
    image = np.array(image, dtype='float')
    label = data.train.labels[i]
    pixels = image.reshape((28, 28))
    plt.imshow(pixels, cmap='gray')
    print('-----------------')
    print(label)
    plt.show()
```

# 它是如何工作的...

本节将介绍在 Jupyter 笔记本中查看 MNIST 手写图像的过程：

1.  在 Python 中生成一个循环，从训练数据集中取样两幅图像。

1.  最初，图像只是存储在`numpy`数组中的 0 到 1 之间的浮点格式的一系列值。数组的值是一个名为`image`的标记图像。然后将`image`数组重塑为一个名为`pixels`的 28 x 28 矩阵，其中 0 处为黑色，非 0 处为灰色。值越高，灰色越浅。例如，可以在以下截图中看到数字 8 的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00083.jpeg)

1.  循环的输出产生了数字 7 和 3 的两幅手写图像以及它们的标签，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00084.jpeg)

1.  除了绘制图像外，还会在图像上方打印训练数据集的标签。标签是一个长度为 10 的数组，对于所有 10 个数字，只有 0 或 1 的值。对于数字 7，数组中的第 8 个元素的值为 1，对于数字 3，数组中的第 4 个元素的值为 1。所有其他值都为 0。

# 还有更多...

图像的数值可能不会立即显而易见。虽然大多数人能够确定第一幅图像是 7，第二幅图像是 3，但从标签数组中获得确认会更有帮助。

数组中有 10 个元素，每个元素引用数字 0 到 9 的标签值。由于第一个数组在第 8 个位置有一个正值或 1，这表明图像的值是 7，因为 7 在数组的第 8 个索引中。所有其他值应为 0。此外，第二幅图像在第 4 个位置有一个值为 1，表示 3 的正值。

# 另请参阅

Leun、Cortes 和 Burges 在以下声明中讨论了为什么图像像素设置为 28 x 28：

NIST 的原始黑白（双色）图像被尺寸标准化以适应 20x20 像素的框，同时保持其纵横比。由于标准化算法使用的抗锯齿技术，生成的图像包含灰度级。通过计算像素的质心，并将图像平移到使该点位于 28x28 区域的中心，将图像置于 28x28 图像中心。

--来自[`yann.lecun.com/exdb/mnist/.`](http://yann.lecun.com/exdb/mnist/)的 Leun、Cortes 和 Burges

# 痛点＃3：将 MNIST 图像导出为文件

我们经常需要直接在图像中工作，而不是作为数组向量。本节将指导我们将数组转换为`.png`图像。

# 准备工作

将向图像导出向量需要导入以下库：

+   `从 matplotlib 导入图像`

# 如何做...

本节将介绍将 MNIST 数组样本转换为本地文件的步骤。

1.  创建一个子文件夹，将我们的图像保存到我们的主文件夹`MNIST/`中，使用以下脚本：

```scala
if not os.path.exists('MNIST/images'):
   os.makedirs('MNIST/images/')
os.chdir('MNIST/images/')
```

1.  循环遍历 MNIST 数组的前 10 个样本，并使用以下脚本将它们转换为`.png`文件：

```scala
from matplotlib import image
for i in range(1,10):
     png = data.train.images[i]
     png = np.array(png, dtype='float')
     pixels = png.reshape((28, 28))
     image.imsave('image_no_{}.png'.format(i), pixels, cmap = 'gray')
```

1.  执行以下脚本以查看从`image_no_1.png`到`image_no_9.png`的图像列表：

```scala
print(os.listdir())
```

# 它是如何工作的...

本节解释了如何将 MNIST 数组转换为图像并保存到本地文件夹中。

1.  我们创建一个名为`MNIST/images`的子文件夹，以帮助我们存储临时的`.png`图像，并将它们与 MNIST 数组和标签分开。

1.  再次循环遍历`data.train`图像，并获得可以用于取样的九个数组。然后将图像保存为`.png`文件到我们的本地目录，格式如下：`'image_no_{}.png'.format(i), pixels, cmap = 'gray'`

1.  可以在本地目录中看到九个图像的输出，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00085.jpeg)

# 还有更多...

除了查看目录中的图像列表外，我们还可以在 Linux 中查看目录中的图像，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00086.jpeg)

# 另请参阅

要了解有关`matplotlib`中`image.imsave`的更多信息，请访问以下网站：

[`matplotlib.org/api/_as-gen/matplotlib.pyplot.imsave.html`](https://matplotlib.org/api/_as-gen/matplotlib.pyplot.imsave.html)

# 痛点＃4：增强 MNIST 图像

在处理图像识别时的主要缺点之一是某些图像的变化不够多样化。这可能导致卷积神经网络的运行不如我们希望的那样理想，并且由于训练数据的缺乏多样性而返回不理想的结果。有一些技术可用于规避这一缺点，我们将在本节中讨论其中一种。

# 准备工作

再次，我们已经为我们做了大部分繁重的工作。我们将使用一个流行的 Python 包`augmentor`，它经常与机器学习和深度学习建模一起使用，以生成现有图像的额外版本，经过扭曲和增强以获得更多的变化。

首先必须使用以下脚本进行`pip`安装：`pip install augmentor`

然后我们应该得到确认该包已安装，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00087.jpeg)

然后我们需要从 augmentor 中导入 pipeline 类：

+   `from Augmentor import Pipeline`

# 操作步骤...

本节介绍了增加我们九个样本图像的频率和增强的步骤。

1.  使用以下脚本初始化`augmentor`函数：

```scala
from Augmentor import Pipeline
augmentor = Pipeline('/home/asherif844/sparkNotebooks/Ch03/MNIST/images')
```

1.  执行以下脚本，以便`augmentor`函数可以根据以下规格`旋转`我们的图像：

```scala
augmentor.rotate(probability=0.9, max_left_rotation=25, max_right_rotation=25)
```

1.  执行以下脚本，使每个图像通过两次迭代，每次迭代 10 次增强：

```scala
for i in range(1,3):
     augmentor.sample(10)
```

# 工作原理...

本节解释了如何使用我们的九个图像创建额外的扭曲图像。

1.  我们需要为图像变换创建一个`Pipeline`并指定将要使用的图像的位置。这确保了以下内容：

1.  图像的源位置

1.  将要转换的图像数量

1.  图像的目标位置

1.  我们可以看到我们的目标位置已创建一个名为`/output/`的子文件夹，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00088.jpeg)

1.  `augmentor`函数被配置为将每个图像向右旋转 25 度或向左旋转 25 度，概率为 90%。基本上，概率配置确定增强发生的频率。

1.  创建一个循环，对每个图像进行两次遍历，并对每个图像应用两次变换；但是，由于我们对每个变换都添加了概率，因此有些图像可能不会被转换，而其他图像可能会被转换超过两次。变换完成后，我们应该收到一条消息，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00089.jpeg)

1.  一旦我们完成增强，我们可以访问`/output/`子目录，并查看每个数字如何略有改变，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00090.jpeg)

1.  我们可以看到我们有几个数字 3、1、8、0 和 9 的变化，都有不同程度的旋转。现在我们已经将样本数据集增加了三倍，并且增加了更多的变化，而不必去提取更多的图像进行训练和测试。

# 还有更多...

我们只应用了`rotate`变换；但是，还有几种变换和增强功能可用于图像：

+   透视扭曲

+   弹性变形

+   剪切

+   裁剪

+   镜像

当寻求增加训练数据集的频率和多样性时，并非所有这些转换都是必要的，但使用一些特征的组合并评估模型性能可能是有益的。

# 另请参阅

要了解更多关于`augmentor`的信息，请访问以下网站：

[`augmentor.readthedocs.io/en/master/`](https://augmentor.readthedocs.io/en/master/)

# 痛点＃5：利用训练图像的替代来源

有时，没有足够的资源来执行卷积神经网络。这些资源可能来自计算的角度或数据收集的角度。在这种情况下，我们依赖其他来源来帮助我们对图像进行分类。

# 准备工作

利用预训练模型作为其他数据集上测试结果的来源的技术称为迁移学习。这里的优势在于，用于训练图像的大部分 CPU 资源被外包给了预训练模型。迁移学习最近已成为深度学习的常见扩展。

# 如何做...

本节解释了迁移学习的工作过程。

1.  收集一系列数据集或图像，您有兴趣对其进行分类，就像您对传统机器学习或深度学习一样。

1.  将数据集分割为训练和测试集，例如 75/25 或 80/20。

1.  确定将用于识别图像模式和识别您希望分类的图像的预训练模型。

1.  构建一个深度学习管道，将训练数据连接到预训练模型，并开发识别测试数据所需的权重和参数。

1.  最后，在测试数据上评估模型性能。

# 它是如何工作的...

本节解释了将迁移学习应用于 MNIST 数据集的过程。

1.  我们在使用迁移学习时确实采取了一种捷径的方法，因为我们要么在资源、时间或两者方面受到限制，我们正在利用已经完成的先前工作，并希望它能帮助我们解决一些新问题。

1.  由于我们正在处理图像分类问题，因此应使用曾经用于分类常见图像的预训练模型。有许多常见的模型，但其中两个突出的是：

1.  由微软开发的 ResNet 模型。

1.  谷歌开发的 Inception 模型。

1.  由于微软和谷歌都拥有广泛的图像库，因此两种模型都对图像分类非常有用，可以在更详细的层面提取特征。

1.  在 Spark 中，有能力构建深度学习管道，并调用一个名为`DeepImageFeaturizer`的类，并将`InceptionV3`模型应用于从训练数据中收集的一组特征。然后使用某种二元或多分类评估器在测试数据上评估训练数据集。

1.  深度学习或机器学习中的管道只是用于从数据收集的初始环境到应用模型对收集的数据进行最终评估或分类的工作流程过程。

# 还有更多...

与一切一样，使用迁移学习有利有弊。正如我们在本节前面讨论的那样，当您在资源有限时，对大型数据集进行自己的建模时，迁移学习是理想的选择。手头的源数据可能不具备预训练模型中的许多独特特征，导致模型性能不佳。可以随时切换到另一个预训练模型并评估模型性能。再次强调，迁移学习是一种快速失败的方法，当其他选择不可用时可以采取。

# 另请参阅

要了解有关微软 ResNet 的更多信息，请访问以下网站：

[`resnet.microsoft.com/`](https://resnet.microsoft.com/)

要了解有关谷歌 Inception 的更多信息，请访问以下网站：

[`www.tensorflow.org/tutorials/image_recognition`](https://www.tensorflow.org/tutorials/image_recognition)

要了解更多关于 InceptionV3 的信息，您可以阅读康奈尔大学的题为《重新思考计算机视觉的 Inception 架构》的论文：

[`arxiv.org/abs/1512.00567`](https://arxiv.org/abs/1512.00567)

# 痛点＃6：优先考虑用于 CNN 的高级库

有许多库可用于执行卷积神经网络。其中一些被认为是低级的，比如 TensorFlow，其中许多配置和设置需要大量编码。这对于经验不足的开发人员来说可能是一个主要痛点。还有其他库，比如 Keras，它是建立在诸如 TensorFlow 之类的库之上的高级框架。这些库需要更少的代码来构建卷积神经网络。通常，刚开始构建神经网络的开发人员会尝试使用 TensorFlow 来实现模型，并在途中遇到几个问题。本节将首先建议使用 Keras 构建卷积神经网络，而不是使用 TensorFlow 来预测 MNIST 数据集中的手写图像。

# 准备工作

在本节中，我们将使用 Keras 训练一个模型，以识别 MNIST 中的手写图像。您可以通过在终端执行以下命令来安装 Keras：

```scala
pip install keras
```

# 如何做...

本节将介绍构建一个模型来识别 MNIST 中手写图像的步骤。

1.  使用以下脚本基于以下变量创建测试和训练图像和标签：

```scala
xtrain = data.train.images
ytrain = np.asarray(data.train.labels)
xtest = data.test.images 
ytest = np.asarray(data.test.labels)
```

1.  使用以下脚本重塑测试和训练数组：

```scala
xtrain = xtrain.reshape( xtrain.shape[0],28,28,1)
xtest = xtest.reshape(xtest.shape[0],28,28,1)
ytest= ytest.reshape(ytest.shape[0],10)
ytrain = ytrain.reshape(ytrain.shape[0],10)
```

1.  从`keras`导入以下内容以构建卷积神经网络模型：

```scala
import keras
import keras.backend as K
from keras.models import Sequential
from keras.layers import Dense, Flatten, Conv2D
```

1.  使用以下脚本设置图像排序：

```scala
K.set_image_dim_ordering('th')
```

1.  使用以下脚本初始化`Sequential` `model`：

```scala
model = Sequential()
```

1.  使用以下脚本向`model`添加层：

```scala
model.add(Conv2D(32, kernel_size=(3, 3),activation='relu', 
            input_shape=(1,28,28)))
model.add(Flatten())
model.add(Dense(128, activation='relu'))
model.add(Dense(10, activation='sigmoid'))
```

1.  使用以下脚本编译`model`：

```scala
model.compile(optimizer='adam',loss='binary_crossentropy', 
              metrics=['accuracy'])
```

1.  使用以下脚本训练`model`：

```scala
model.fit(xtrain,ytrain,batch_size=512,epochs=5,
            validation_data=(xtest, ytest))
```

1.  使用以下脚本测试`model`的性能：

```scala
stats = model.evaluate(xtest, ytest)
print('The accuracy rate is {}%'.format(round(stats[1],3)*100))
print('The loss rate is {}%'.format(round(stats[0],3)*100))
```

# 它是如何工作的...

本节解释了如何在 Keras 上构建卷积神经网络以识别 MNIST 中的手写图像。

1.  对于任何模型开发，我们需要确定我们的测试和训练数据集以及特征和标签。在我们的情况下，这相当简单，因为来自 TensorFlow 的 MNIST 数据已经被分解为`data.train.images`用于特征和`data.train.labels`用于标签。此外，我们希望将标签转换为数组，因此我们利用`np.asarray()`来处理`ytest`和`ytrain`。

1.  `xtrain`、`xtest`、`ytrain`和`ytest`的数组目前不是用于 Keras 中的卷积神经网络的正确形状。正如我们在本章早期确定的那样，MNIST 图像的特征表示为 28 x 28 像素图像，标签表示 0 到 9 之间的十个值中的一个。x-arrays 将被重塑为(,28,28,1)，y-arrays 将被重塑为(,10)。新数组的`shape`如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00091.jpeg)

1.  如前所述，Keras 是一个高级库；因此，它不会执行张量或卷积操作，而没有低级库（如 TensorFlow）的帮助。为了配置这些操作，我们将`backend`设置为`K`，`Keras`的图像维度排序`image_dim_ordering`设置为`tf`，表示 TensorFlow。

请注意，后端也可以设置为其他低级库，如`Theano`。我们将维度排序设置为`th`。此外，我们需要重构特征的形状。然而，在过去的几年中，`Theano`并没有像`TensorFlow`那样获得同样的采用率。

1.  一旦我们导入构建 CNN 模型所需的必要库，我们就可以开始构建模型的序列或层，`Sequential()`。为了演示目的，我们将保持这个模型尽可能简单，只有 4 层，以证明我们仍然可以在最小的复杂性下获得高准确性。每一层都是使用`.add()`方法添加的。

1.  第一层被设置为构建一个二维（`Conv2D`）卷积层，这对于空间图像如 MNIST 数据是常见的。由于这是第一层，我们必须明确定义传入数据的`input_shape`。此外，我们指定一个`kernel_size`，用于设置用于卷积的窗口滤波器的高度和宽度。通常，这是 32 个滤波器的 3x3 窗口或 5x5 窗口。此外，我们必须为这一层设置一个激活函数，对于效率目的，特别是在神经网络的早期阶段，`relu`是一个不错的选择。

1.  接下来，第二层将第一层的输入展平，以获取一个分类，我们可以用来确定图像是否是可能的 10 个数字之一。

1.  第三，我们将第二层的输出传递到具有 128 个隐藏层的另一个具有`relu`激活函数的`dense`层。密集连接层中的函数包括`input_shape`和`kernel_size`以及偏差，以创建每个 128 个隐藏层的输出。

1.  最后一层是输出层，将决定 MNIST 图像的预测值是什么。我们添加另一个具有`sigmoid`函数的`dense`层，以输出我们的 MNIST 图像可能的 10 种情况的概率。Sigmoid 函数对于二元或多类分类结果很有用。

1.  下一步是使用`adam`作为`optimizer`编译模型，并评估`accuracy`作为`metrics`。`adam`优化器对于 CNN 模型很常见，当处理 10 种可能结果的多类分类场景时，使用`categorical_crossentropy`作为损失函数也很常见，这也是我们的情况。

1.  我们使用`batch_size`为`512`的图像进行`5`次运行或`epochs`来训练模型。每个 epoch 的损失和准确性都被捕获，并可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00092.jpeg)

1.  我们通过在测试数据集上评估训练模型来计算准确性和损失率，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00093.jpeg)

1.  我们的模型似乎表现良好，准确率为 98.6%，损失率为 5%。

1.  我们在 Keras 中使用了五行代码来构建一个简单的卷积神经网络模型。Keras 是一个快速上手的模型设计工具。一旦您准备好转向更复杂的模型开发和控制，可能更有意义的是在 TensorFlow 中构建卷积神经网络。

# 还有更多...

除了获取模型的准确性，我们还可以通过执行以下脚本来产生 CNN 建模过程中每一层的形状：

```scala
model.summary()
```

`model.summary()`的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00094.jpeg)

我们看到第一层的输出形状（None, 24, 24, 32）通过在第二层中乘以 24 x 24 x 32 而展平为形状（None, 18432）。此外，我们看到我们的第三和第四层具有我们使用 Dense 层函数分配给它们的形状。

# 另请参阅

要了解更多关于 Keras 中 2D 卷积层开发的信息，请访问以下网站：

[`keras.io/layers/convolutional/#conv2d`](https://keras.io/layers/convolutional/#conv2d)

要了解如何在 TensorFlow 中使用 MNIST 图像构建卷积神经网络，请访问以下网站：

[`www.tensorflow.org/versions/r1.4/get_started/mnist/pros`](https://www.tensorflow.org/versions/r1.4/get_started/mnist/pros)
