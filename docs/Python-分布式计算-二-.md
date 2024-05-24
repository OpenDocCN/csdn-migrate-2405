# Python 分布式计算（二）



# 五、云平台部署 Python （Distributed Computing with Python）



上一章介绍了创建 Python 分布式应用的 Celery 和其它工具。我们学习了不同的分布式计算架构：分布任务队列和分布对象。然而，还有一个课题没有涉及。这就时在多台机器上部署完成的应用。本章就来学习。

这里，我们来学习 Amazon Web Services (AWS)，它是市场领先的云服务产品，以在上面部署分布式应用。云平台不是部署应用的唯一方式，下一章，我们会学习另一种部署方式，HPC 集群。部署到 AWS 或它的竞品是一个相对廉价的方式。

## 云计算和 AWS

AWS 是云计算的领先提供商，它的产品是基于互联网的按需计算和存储服务，通常是按需定价。

通过接入庞大的算力资源池（虚拟或现实的）和云平台存储，可以让应用方便的进行水平扩展（添加更多机器）或垂直扩展（使用性能更高的硬件）。在非常短的时间内，通过动态添加或减少资源（减少花费），就可以让用户下载应用。配置资源的简易化、使用庞大的云平台资源、云平台的高可用性、低廉的价格，都是进行云平台部署的优点，尤其是对小公司和个人。

云平台的两种主要服务是计算机节点和存储。也会提供其它服务，包括可扩展的数据库服务器（关系型和非关系型数据库）、网络应用缓存、特殊计算框架（例如 Hadoop/MapReduce），以及应用服务（比如消息队列或电子邮件服务）。所有这些服务都可以进行动态扩展，以适应使用量的增加，当使用量减小时，再缩小规模。

AWS 提供前面所有的服务，然而这章只关注一些主要服务：计算机节点 Amazon Elastic Compute Cloud (EC2)，计算机节点虚拟硬盘存储 Amazon Elastic Block Store (EBS)，存储应用数据 AmazonSimple Storage Server(S3)，应用部署 Amazon Elastic Beanstalk。

## 创建 AWS 账户

为了使用 AWS，需要创建一个账户。使用一定量资源的首年是免费的，之后按照标准价格收费。

要创建账户，打开页面[https://aws.amazon.com](https://link.jianshu.com?t=https://aws.amazon.com/)，点击 Create a Free Account，如下面截屏所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/ada696526bd3dcf958e98b5098949c0e.jpg)

注册需要基本的联系信息，支付手段（必须要用信用卡注册），和一些其它信息。

一旦账户激活，就可以登录管理页面，如下面截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/a4b24f7a134634112a796f7e3f0a4347.jpg)

控制台页面功能繁杂，有许多图标，对应着 50 多项服务。本章会讲如何使用 EC2、Elastic Beanstalk，S3 和 Identity and Access Management 服务，它们的图标在下图中标出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/6e018edaae8da24275b83ce15043d75b.jpg)

在创建虚拟运行应用和用存储仓保存数据之前，我们需要创建至少一个用户和一个用户组。要这么做，点击第二栏的 Identity and Access Management，或打开网页[https://console.aws.amazon.com/iam/](https://link.jianshu.com?t=https://console.aws.amazon.com/iam/)。点击左边栏的 Groups，然后点击 Create New Group 按钮。

然后会让你输入新用户组的名字。我通常使用`Wheel`作为管理组的名字。填入用户组名字之后，点击 Next Step 按钮。

然后，我们需要选择这个用户组的预定义规则。在这个页面，我们可以选择 AdministratorAccess。然后点击 Next Step 按钮。

在下一页检查之前的选项，如果没有问题，可以点击 Create Group。Group 页面就会列出新创建的用户组了，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/ad9d313e05397bcdd8df8053e7ceeb64.jpg)

点击用户组的名字（Wheel），然后在 Permissions 栏就会显示这个组的规则，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/7523ba6b72cd4363b76c6bc2e6ace340.jpg)

现在，创建至少一个用户，即登录虚拟机的账户。左侧栏点击 Users，然后点击页面上方的 Create New Users，在打开的页面中，一次最多可以创建五个用户。

现在来创建一个用户。在第一个空格（数字 1 旁边）输入用户名，确保勾选了选项框 Generate an access key for each user，然后点击 Create 按钮，如下图所示（我选的用户名是 bookuser）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/48a41c358889f470a3c160af8e015f77.jpg)

下面的一页很重要，呈现在我们面前的是一个用户创建流程的概括，可以在这里下载用户整数。一定要点击 Download Credentials 按钮。如果没有做，或将证书（一个 csv 文件）放错了位置，你可以创建一个新用户，再下载一个证书。

现在，我们需要将创建的用户添加到用户组。要这么做，返回 Groups 页面（点击左侧栏的 Groups），选择之前创建的管理组（Wheel），点击页面上方的 Group Actions，在弹出的页面点击 Add Users to Group。如果这个条目不能使用，确保勾选了组名旁边的选择框。

来到一个列出所有用户的新页面。点击刚刚创建的用户旁边的勾选框，然后点击页面底部的 Add Users。在下一页，点击组名，然后在 Users 栏会显示刚刚添加的用户，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/4ac72b87a0ef839accb378f5efb46e47.jpg)

现在，创建密码。返回 Users 页面（点击左侧导航栏的 Users），点击用户名，在打开的页面点击 Security Credentials 栏。会看到类似下图的页面：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/8c39f13d50581e2e376693066f6c06df.jpg)

这里，在 Sign-In-Credentials 下面的 Manage Password 根据提示设置密码，我们可以让 AWS 为我们设置密码，或自定义一个密码。

快完成了。剩下的是为用户创建 SSH 密钥，以让用户能不用密码就登录 EC2 实例。这也可以用管理台来做。

登出管理台，用刚才创建的用户再次登录。为了这么做，使用刚才页面的 URL，[https://console.aws.amazon.com/iam](https://link.jianshu.com?t=https://console.aws.amazon.com/iam)，它的形式是`https://<ACCOUNT NUMBER>.signin.aws.amazon.com/console/`。

现在，在管理台页面，点击 EC2 图标，然后在左上方的弹出框选择实例的地理位置（我选择的是 Ireland）。Amazon EC2 虚拟机有多个区域，涵盖美国、欧洲、亚洲和南美。SSH 密钥是和区域有关的，也就是说，要使用两个不同区域的机器，我们要为每个区域创建两个不同的 SSH 密钥对。

选择完区域之后，点击 Key Pairs，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/4346832d4300db837e8c827b0980c74d.jpg)

点击 Create Key Pair，给其命名（我起的名字是 bookuser-ireland-key），然后点击 Create 按钮。新创建的私钥会自动下载到你的电脑，格式是`pem`（有事下载的文件的后缀名是`.pem.txt`，可以将其重命名为`.pem`）。

确保将其安全的存放，进行备份，因为不会再次下载。如果放的位置不对，你需要使用 AWS 控制台新建一个，以删除这个密钥对。

我把密钥保存在`$HOME`的`.ssh`目录。我通常将密钥复制到这里，重命名它的后缀为`.pem`，并且只有我才能访问（即 chmod 400 ~/.ssh/bookuser-ireland-key.pem）。

## 创建一个 EC2 实例

做完了所有的配置，现在可以创建第一个虚拟机了。从我们选择的地理区域开始（记得为每个创建密钥），然后登陆运行的实例。我们现在只是用网页控制台来做。

如果你不在控制台，使用创建的用户登陆（可以使用 URL：`https://<ACCOUNTNUMBER>.signin.aws.amazon.com/console/`），然后点击 EC2 图标。

打开的 EC2 控制台如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/759771f3fe5930f6311934cb2eb64dd6.jpg)

点击页面中间的蓝色按妞 Launch Instance。接下来创建虚拟机。首先，选择 Amazon Machine Image (AMI)，它是底层的操作系统，和默认的虚拟机软件包集合。

可选的配置有很多。我们选择一个免费的 AMI。我喜欢 64 位的 Ubuntu 服务器镜像，从上往下数的第四个（你也可以选其它的）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/f1884f1368f8cddf385304eb55b27e81.jpg)

然后，要选择虚拟硬件。Amazon 提供多种配置，取决于用户的需求。例如，如果我们想运行深度学习代码，我们就要选择 GPU 强大的实例。在我们的例子中，我们选择 Free tier eligible t2.micro，下面截图中的第一个：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/74e96918aadf9471ad9c2c56b8f8f332.jpg)

点击 Next: Configure Instance Details 会打开一个新页面，在上面可以配置将要创建的实例的一些特性。现在，只使用其默认值，但要关注一下 Purchasing option。我们现在使用的是 Spot instance，意味着如果使用了更高级的实例需要硬件资源，就会关闭之前的虚拟机。

我们现在不需要对这一项进行设置，但是要知道 Spot instance 是一种可以降低花费的手段。点击 Next: Add Storage。

这里，我们可以配置存储选项。现在，还是使用默认值，只是看一下选项的内容。Delete on Termination 是默认勾选的，它的作用是当结束实例时，和其相关的数据也会被删除。因为在默认情况下，实例是暂停而非终止，这么设置就可以。然后点击 Next: Tag Instance。我们现在不创建任何 tag，所以继续点击 Next: Configure Security Group。

这个打开的页面很重要，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/bebd3aae2138876952dff7dfe95658a7.jpg)

在这一页上，我们来配置实例的服务（网络端口）和登录 VM 的 IP 地址。现在，我们只是改变 SSH 的规则，以允许从 My IP 的连接（在弹出菜单的 Source 标题，SSH 行）。

例如，向 Anywhere 打开 TCP 的 80 端口，以运行一个网络服务器，或是 5672 端口（使用 RabbitMQ 的 Celery 的端口），供 Celery 应用的 IP 使用。

现在不建立任何规则，使用默认的 SSH 访问规则。设置页面如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/c22e8b40ed322a4851fa9c47a43bb82f.jpg)

最后，点击 Review and Launch，如果没有问题的话，再点击 Launch。确保可以访问正确的`.pem`文件，以访问 EC2 实例，然后点击 Launch Instances。

Amazon 现在会启动实例，需要几分钟时间。通过点击页面底部的 View Instances，可以看到实例的运行或准备状态：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/6aca926cab42ed905060cbff455009d9.jpg)

一旦 VM 运行了，就可以用 SSH 连接它。通过终端进行连接，使用实例 OS 的正确 Unix 用户名（即，Amazon Linux 是`ec2-user`，Ubuntu 是`ubuntu`，SUSE 是`root`或`ec2-user`，Fedora Linux 是`fedora`或`ec2-user`）。

在我们的例子中，登录窗口如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/f20bacff5fb484991a84ac316daf1837.jpg)

VM 中包含了一些预先安装的软件，包括 Python 2.7 和 3.4。为了实用，这个 VM 是一台 Linux 服务器。试验结束之后，可以在 Actions 弹出窗中点击 Stop 结束实例，选中实例的名字，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/b3d8a828dd6c85bdc45fbaa939a0c7bf.jpg)

关于 EC2 实例，特别要注意虚拟的存储和虚拟机在重启、停止、关闭时，存储设备的行为。因为，无论停止还是关闭虚拟机，它的 IP 地址都会失效，下次启动时会分配新的 IP 地址。

我们创建的实例（`t2.micro`）使用存储在 EBS 的虚拟硬盘，它是 EC2 实例的高性能和高可靠性的存储。

默认情况下，当对应的实例关闭时，存储在 EBS 的虚拟硬盘会被删除（除非 Add Storage 页面的 Delete on Termination 选项没有勾选），但实例停止时，存储不会删除。停止实例会导致存储费用，而关闭实例不会。

重启一个关闭的实例是不可能的，必须要从头新建一个实例，这比重启暂停的 VM 要花费更长的时间。因为这个原因，如果想重新使用实例，最好停止而不是关闭。然而，保持 EBS 存储是一笔可观的花费，所以应该使用时间不长的实例应该关闭。

重启、关闭状态下，使应用数据保存在 EBS 的方法之一是新建一个 EBS 卷，当相关的 EC2 实例运行时，将新的卷分配给这个实例。这是通过点击 EC2 Dashboard 页面的 Volumes 链接，然而根据提示操作。要记住，初次使用一个卷时，需要进行格式化，这可以通过在运行 EC2 实例内使用专门的工具，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/3a061aa695c28ef5d13daa77dc59ce29.jpg)

Linux 内核重新映射了 EBS 卷的设备名字，`/dev/sdf to /dev/xvdf`。

分配一个卷就像将硬盘链接电脑，它们的数据在重启之后也会保存，并可以从一个实例移动到另一个实例。要记住，每创建一个卷都要花钱，无论是否使用。

另一种（花费较低的）存储应用数据的方法是使用 S3，接下来讨论它。

## 使用 Amazon S3 存储数据

Amazon Simple Storage Service，S3，是一个存储、读取数据的网络服务。各种文件都可以存储到 S3，上到 5TB 的数据，或是源代码。

S3 远比 EBS 便宜，但是它不提供文件层，而是一个 REST API。另一个不同点是，EBS 卷一次只能分配一个运行的实例，S3 对象可以在多个实例间共享，取决于许可协议，可以网络各处访问。

使用 S3 很简单，你需要在某个地理区域（为了降低访问时间）创建一些桶（即 S3 的容器），然后添加数据。过程如下：登录 AWS 管理台，点击 Storage & Content Delivery 下面的 S3 图标，点击 Create Bucket 按钮，给桶起名字，然后给它选择区域。

对于这个例子，我们起的名气是 book-123-456，区域是爱尔兰，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/3e49681783a8bd72e906552fb4c00398.jpg)

点击 Create 按钮。因为桶的名字实在 S3 用户间分享的，像 book 这样的名字都被使用过了。因此，起的名字最好加上一些识别符。

下一页显示了创建的 S3 桶列表，见下图（点击桶名字左侧的图标，以显示桶的属性）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/e239f312e9fe3f65f0007251624bcd2e.jpg)

从这页开始，在桶页面上就可以查看桶的内容、上传数据、重命名、或删除，见下面截图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/ff643a577fae0440ee28e2068fe3fa08.jpg)

Amazon S3 有一个复杂的许可协议，可以根据每个对象、每个桶执行访问。现在，向桶传一些文件，并修改访问权限。

创建一个文本文件夹，并存储一些文本文件。在我的例子中，我创建了一个文件`index.html`，内容是"Hi there!"。使用 Upload，上传到 S3.

我们可以检查这个文件的属性（包括访问权），通过选择文件，并点击右上角的 Properties。从下页可以看到，默认情况下，刚刚上传的文件只能被我们访问到：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/d535d929dd00d30589c8e020cf0615ad.jpg)

我们可以从终端师徒访问文件（使用文件名属性下方的 URL），但是会有错误 Access Denied。我们可以添加一个许可，让任何人可以对这个文件进行读写，如下图所示（记得 Save 访问规则）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/c9b2a7e4ed8709289c953001ff0658dc.jpg)

创建这个许可之后，刚上传的文件就是面向公众可读的了，例如，作为网页的静态文件。在 S3 上存储文件相对便宜，但不是完全免费。

## Amazon elastic beanstalk

Amazon Elastic Beanstalk (EB) 是将应用部署到 AWS 的简便方法，不必分别处理 EC2 和 S3.Amazon EB 功能完备，支持 Python。

最好在 Python 虚拟环境中，用命令行（使用 awsebcli 包）使用 EB。要点是，你需要创建一个 Python 应用的虚拟环境，以部署到 AWS。应用本身保存在一个文件夹内，用来打包。

使用`eb`命令，就可以创建一个初始化部署配置（`eb init`），通过写额外的配置文件（文件夹`.ebextensions`）来进行自定义，配置选项，例如需要的环境变量，或需要进行的推迟安装。

应用在本地测试完毕之后，就可以使用`eb create`部署到 AWS，使用`eb terminate`命令进行销毁。

AWS 网站有关于部署的教程，例如，一个稍显复杂的 Django 网页应用（[http://docs.aws.amazon.com/elasticbeanstalk/latest/dg/create-deploy-python-django.html#python-django-configure-for-eb](https://link.jianshu.com?t=http://docs.aws.amazon.com/elasticbeanstalk/latest/dg/create-deploy-python-django.html#python-django-configure-for-eb)），可以让你学习更多的 EB。

尽管 EB 文档大部分都是关于网页应用的，它的应用不局限于 HTTP 服务器和 WSGI 应用。

## 创建私有云平台

AWS 对大多数个人和公司都是一个不错的选择。但是，使用 AWS 也会增加成本。或者，公司的政策，或从数据的隐私性考虑，不能使用云平台。

这就需要搭建一个内部的私有云平台。使用现有的硬件，运行虚拟机（EC2）和数据存储中间件（类似于 S3），再加上其它服务，比如负载均衡、数据库等等。

这样的免费开源工具很多，比如**OpenStack**([http://www.openstack.org](https://link.jianshu.com?t=http://www.openstack.org/))， **CloudStack**([https://cloudstack.apache.org](https://link.jianshu.com?t=https://cloudstack.apache.org/))，和 **Eucalyptus**([http://www.eucalyptus.com](https://link.jianshu.com?t=http://www.eucalyptus.com/))。

Eucalyptus 可以和 AWS（EC2 和 S3）交互。使用它可以构建类似 AWS 的 API。这样，就可以扩展私有云平台，或是迁移到 EC2 和 S3，而不用重新创建虚拟机镜像、工具和管理脚本文件。

另外，Python 的与 AWS 交互的 boto 工具包（`pip install boto`）是与 Eucalyptus 兼容的。

## 总结

通过 AWS，我们学习了利用云平台进行计算和存储，用户按需支付，只需要给使用的资源付款。

这些平台在开发阶段和运行阶段，都可以用于我们的分布式应用。特别是进行伸缩性测试，让我们自己一下提供许多台机器是不现实的。更不用说，还可以使用海量的云平台资源，以及可靠性保障。

同时，云平台服务是收费。而且，通常定价不菲。另外，从时间和精力，云平台限制颇多，我们不能管理资源、不能安装软件，也不能学习某个软件工具和它的特性。从一个云平台迁移到另一个，还往往很费事。

知道了这些，就可以更好的让云平台适合我们的总体设计、开发、测试、部署。

例如，一个简单的策略是将分布式应用部署到自建的平台上，只在流量增加时使用云平台。所以，要时刻更新 VM 镜像，并引入到 Amazon EC2.

下一章，我们会学习研究者和实验室/大学人员的场景，在大型的高性能计算机（HPC）群上运行 Python。



# 六、超级计算机群使用 Python （Distributed Computing with Python）



本章，我们学习另一种部署分布式 Python 应用的的方法。即使用高性能计算机（HPC）群（也叫作超级计算机），它们通常价值数百万美元（或欧元），占地庞大。

真正的 HPC 群往往位于大学和国家实验室，创业公司和小公司因为资金难以运作。它们都是系统巨大，有上万颗 CPU、数千台机器。

经常超算中心的集群规模通常取决于电量供应。使用几兆瓦的 HPC 系统很常见。例如，我使用过有 160000 核、7000 节点的机群，它的功率是 4 兆瓦！

想在 HPC 群运行 Python 的开发者和科学家可以在本章学到有用的东西。不使用 HPC 群的读者，也可以学到一些有用的工具。

## 典型的 HPC 群

HPC 系统有多种形式和规模，然而，它们有一些相同点。它们是匀质的，大量相同的、装在架子上的计算机，处于同一个房间内，通过高速网络相连。有时，在升级的时候，HPC 群会被分成两个运行体系。此时，要特别注意规划代码，以应对两个部分的性能差异。

集群中的大部分机器（称作节点），运行着相同的系统和相同的软件包，只运行计算任务。用户不能直接使用这些机器。

少部分节点的算力不如计算节强大，但是允许用户登录。它们称作服务节点（或登录节点或头节点），只运行用户脚本、编译文件、任务管理软件。用户通常登录这些节点，以访问机群。

另一些节点，介于服务节点和计算节点之间，它们运行着全套计算节点的操作系统，但是由多个用户共享，而纯粹的计算节点的每个核只运行一个线程。

这些节点是用来运行小型的序列化任务，而不需要计算节点的全部资源（安装应用和清理）。例如在 Cray 系统上，这些节点称作 Multiple Application, Multiple User (MAMU)节点。

下图是 NASA 的 2004 Columbia 超级计算机，它有 10240 个处理器，具有一定代表性：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/6e975e968c000cb35298339e1e79ddc3.jpg)

如何在 HPC 群上运行代码呢？通常是在服务节点登录，使用任务规划器（job scheduler）。任务规划器是一个中间件，给它一些代码，它就可以寻找一些计算节点运行代码。

如果此时没有可用的硬件资源，代码就会在一个队列中等待，直到有可用的资源。等待时间可能很长，对于短代码，等待时间可能比运行时间还长。

HPC 系统使用任务规划器，视为了确保各部门和项目可以公平使用，最大化利用机群。

商用和开源的规划器有很多。最常用的是 PBS 和它的衍生品（例如 Torque 和 PBS Pro），HTCondor，LoadLeveler，SLURM、Grid Engine 和 LSF。这里，我们简短介绍下其中两个：HTCondor 和 PBS Pro。

## 任务规划器

如前所述，你不能直接在 HPC 群上运行代码，你必须将任务请求提交给任务规划器。任务规划器会分配算力资源，在分配的节点上运行应用。

这种间接的方法会造成额外的开销，但可以保证每个用户都能公平的分享使用计算机群，同时任务是有优先级的，大多数处理器都处于忙碌状态。

下图展示了任务规划器的基本组件，和任务提交到执行的事件顺序：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/22bd53e4e0f6cb0e5931a9e551da7220.jpg)

首先，先来看一些定义：

*   任务：这是应用的元数据，例如它的可执行文件、输入和输出、它的硬件和软件需求，它的执行环境，等等；
*   机器：这是最小的任务执行硬件。取决于集群的配置，它可能是一部分节点（例如，一台多核电脑的一个核心）和整个节点。

从概念层面，任务规划器的主要部分有：

*   资源管理器
*   一个或多个任务队列
*   协调器

为了提交一个任务请求到任务规划器，需要编写元数据对象，它描述了我们想运行的内容，运行的方式和位置。它往往是一个特殊格式的文本文件，后面有一个例子。

然后，用户使用命令行或库提交任务描述文件（上图中的步骤 1）到任务规划器。这些任务先被分配到一个或多个队列（例如，一个队列负责高优先级任务，一个负责低优先级任务，一个负责小任务）。

同时，资源管理器保持监督（步骤 2）所有计算节点，以确定哪台空闲哪台繁忙。它还监督着正在运行的任务的优先级，在必要时可以释放一些空间给高优先级的任务。另外，它还监督着每台机器的性能指标，能运行什么样的任务（例如，有的机器只能让特定用户使用）。

另外一个守护进程，萧条期，持续监督着任务队列的闲置任务（步骤 2），并将它们分配给何时的机器（步骤 3），其间要考虑用户的优先级、任务优先级、任务需求和偏好、和机器的性能和偏好。如果在这一步（称作协调循环）没有可用的资源来运行任务，任务就保存在队列中。

一旦指派了运行任务的资源，规划器会在分配的机器上运行可执行文件（步骤 4）。有的规划器（例如 HTCondor）会复制可执行文件，向执行机器发送文件。如果不是这样，就必须让代码和数据是在共享式文件系统，或是复制到机器上。

规划器（通常使用监督进程）监督所有的运行任务，如果任务失败则重启任务。如果需要的话，还可以发送任务成功或失败的 email 通知邮件。

大多数系统支持任务间依赖，只有达到一定条件时（比如，新的卷），任务才能执行。

## 使用 HTCondor 运行 Python 任务

这部分设定是用 HTCondor 任务规划器，接入机群。安装 HTCondor 不难（参考管理文档[https://research.cs.wisc.edu/htcondor/manual/](https://link.jianshu.com?t=https://research.cs.wisc.edu/htcondor/manual/)），这里就不介绍了。

HTCondor 有一套命令行工具，可以用来向机群提交任务（`condor_submit`），查看提交任务的状态（`condor_q`），销毁一个任务（`condor_rm`），查看所有机器的状态（`condor_status`）。还有许多其它工具，总数超过 60。但是，我们这里只关注主要的四个。

另一种与 HTCondor 机群交互的方法是使用 Distributed Resource Management Application API (DRMAA)，它内置于多数 HTCondor 安装包，被打包成一个共享库（例如，Linux 上的`libdrmma.so`）。

DRMAA 有任务规划器的大部分功能，所以原则上，相同的代码还可以用来提交、监督和控制机群和规划器的任务。Python 的`drmaa`模块（通过`pip install drmaa`安装），提供了 DRMAA 的功能，包括 HTCondor 和 PBS 的功能。

我们关注的是命令行工具，如何用命令行工具运行代码。我们先创建一个文本文件（称作任务文件或提交文件），描述任务的内容。

打开文本编辑器，创建一个新文件。任务文件的名字不重要。我们现在要做的是在机群上运行下面的代码：

```py
$ python3.5 –c "print('Hello, HTCondor!')" 
```

任务文件（`htcondor/simple/simple.job`）的代码如下：

```py
# Simple Condor job file
# There is no requirement or standard on job file extensions.
# Format is key = value
# keys and values are case insensitive, with the exception of
# paths and file names (depending on the file system).
# Usage: shell> condor_submit simple.job
# Universe is the execution environment for our jobs
# vanilla is the one for shell scripts etc.
Universe = vanilla
# Executable is the path to the executable to run
Executable = /usr/local/bin/python3.5
# The arguments string is passed to the Executable
# The entire string is enclosed in double-quotes
# Arguments with spaces are in single quotes
# Single & double quotes are escaped by repeating them
Arguments = "-c 'print(''Hello, HTCondor!'')'"
# Output is the file where STDOUT will be redirected to
Output = simple_stdout.txt
# Error is the file where STDERR will be redirected to
Error = simple_stderr.txt
# Log is the HTCondor log, not the log for our app
Log = simple.log
# Queue tells HTCondor to enqueue our job
Queue 
```

这段代码很简单。

让人疑惑的可能是`Output`指令，它指向文件进行`STDOUT`重定向，而不是执行代码的结果输出。

另一个会让人疑惑的是`Log`指令，它不知想应用的日志文件，而是任务专门的 HTCondor 日志。指令`Arguments`句法特殊，也要注意下。

我们可以用`condor_submit`提交任务，如下图所示，提交任务之后，立即用`condor_q`查看状态：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/9a9dc1efeb11fe2b419aa8b330aaf796.jpg)

HTCondor 给任务分配了一个数字识别符，形式是`cluster id.process id`（这里，进程 ID 专属于 HTCondor，与 Unix 进程 ID 不完全相同）。因为可以向一个任务文件提交多个任务（可以通过`Queue`命令，例如`Queue 5000`，可以启动 5000 个任务的实例），HTCondor 会将其当做集群处理。

每个集群都有一个唯一的识别符，集群中的每个进程都有一个 0 到 N-1 之间的识别符，N 是集群的总进程数（任务实例的数量）。我们的例子中，只提交一个任务，它的识别符是 60.0。

> 注意：严格的讲，前面的任务识别符只是在任务队列/提交奇迹中是唯一的，在整个集群不是唯一的。唯一的是`GlobalJobId`，它是一连串事件的 ID，包括主机名、集群 ID、进程 ID 和任务提交的时间戳。可以用`condor_q -log`显示`GlobalJobId`，和其它内部参数。

取决于 HTCondor 的配置，以及机群的繁忙程度，任务可以立即运行，或是在队列中等待。我们可以用`condor_q`查询状态，`idle`（状态 I），`running`（状态 R），`suspended`（状态 H），`killed`（状态 X）。最近添加了两个新的状态：`in the process of transferring data to the execute node`（<）和`transferring data back to the submit host`（>）。

如果一切正常，任务会在队列中等待一段时间，然后状态变为运行，最后退出（成功或出现错误），从队列消失。

一旦任务完成，查看当前目录，我们可以看到三个新文件：`simple.log`，`simple_stderr.txt`和`simple_stdout.txt`。它们是任务的日志文件，任务的标准错误，和标准输出流。

日志文件有许多有用的信息，包括任务提交的时间和从哪台机器提交的，在队列中等待的时间，运行的时间和机器，退出代码和利用的资源。

我们的 Python 任务退出状态是 0（意味成功），在`STDERR`上没有输出（即`simple_stderr.txt`是空的），然后向`STDOUT`写入`Hello，HTCondor！`（即`simple_stdout.txt`）。如果不是这样，就要进行调试。

现在提交一个简单的 Python 文件。新的任务文件很相似，我们只需更改`Executable`和`Arguments`。我们还要传递一些环境变量给任务，提交 100 个实例。

创建一个新任务文件（`htcondor/script/script.job`），代码如下：

```py
# Simple Condor job file
# There is no requirement or standard on job file extensions.
# Format is key = value
# keys and values are case insensitive, with the exception of
# paths and file names (depending on the file system).
# Usage: shell> condor_submit script.job

# Universe is the execution environment for our jobs
# vanilla is the one for shell scripts etc.
Universe = vanilla
# Executable is the path to the executable to run
Executable = test.py
# The arguments string is passed to the Executable
# The entire string is enclosed in double-quotes
# Arguments with spaces are in single quotes
# Single & double quotes are escaped by repeating them
Arguments = "--clusterid=$(Cluster) --processid=$(Process)"
# We can specify environment variables for our jobs as
# by default jobs execute in a very restricted environment
Environment = "MYVAR1=foo MYVAR2=bar"
# We can also pass our entire environment to the job
# By default this is not the case (i.e. GetEnv is False)
GetEnv = True
# Output is the file where STDOUT will be redirected to
# We will have one file per process otherwise each
# process will overwrite the same file.
Output = script_stdout.$(Cluster).$(Process).txt
# Error is the file where STDERR will be redirected to
Error = script_stderr.$(Cluster).$(Process).txt
# Log is the HTCondor log, not the log for our app
Log = script.log
# Queue tells HTCondor to enqueue our job
Queue 100 
```

接下来写要运行的 Python 文件。创建一个新文件（`htcondor/script/test.py`），代码如下：

```py
#!/usr/bin/env python3.5
import argparse
import getpass
import os
import socket
import sys
ENV_VARS = ('MYVAR1', 'MYVAR2')

parser = argparse.ArgumentParser()
parser.add_argument('--clusterid', type=int)
parser.add_argument('--processid', type=int)
args = parser.parse_args()

cid = args.clusterid
pid = args.processid

print('I am process {} of cluster {}'
      .format(pid, cid))
print('Running on {}'
      .format(socket.gethostname()))
print('$CWD = {}'
      .format(os.getcwd()))
print('$USER = {}'
      .format(getpass.getuser()))

undefined = False
for v in ENV_VARS:
    if v in os.environ:
        print('{} = {}'
              .format(v, os.environ[v]))
    else:
        print('Error: {} undefined'
              .format(v))
        undefined = True
if undefined:
    sys.exit(1)
sys.exit(0) 
```

这段简单的代码很适合初次使用 HPC 机群。它可以清晰的显示任务在哪里运行，和运行的账户。

这是在写 Python 任务时需要知道的重要信息。某些机群有在所有计算节点上都有常规账户，在机群上分享用户的主文件夹。对于我们的例子，用户在登录节点上提交之后就会运行。
在其他机群上，任务都运行在低级用户下（例如，`nobody`用户）。这时，特别要注意许可和任务执行环境。

> 注意：HTCondor 可以在提交主机和执行节点之间高效复制数据文件和/或可执行文件。可以是按需复制，或是总是复制的模式。感兴趣的读者可以查看指令`should_transfer_files`，`transfer_executable`，`transfer_input_files`，和`transfer_output_files`。

前面的任务文件（`htcondor/script/script.job`）有一些地方值得注意。首先，要保证运行任务的用户可以找到 Python 3.5，它的位置可能和不同。我们可以让 HTCondor 向运行的任务传递完整的环境（通过指令`GetEnv = True`）。

我们还提交了 100 个实例（`Queue 100`）。这是数据并行应用的常用方式，数据代码彼此独立运行。

我们需要自定义文件的每个实例。我们可以在任务文件的等号右边用两个变量，$(Process)和$(Cluster)。在提交任务的时候，对于每个进程，HTCondor 用响应的集群 ID 和进程 ID 取代了这两个变量。

像之前一样，提交这个任务：

```py
$ condor_submit script.job 
```

任务提交的结果显示在下图中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/8f3d6493d9482ef577646e70b0a0111e.jpg)

当所有的任务都完成之后，在当前目录，我们会有 100 个`STDOUT`文件和 100 个`STDERR`文件，还有一个 HTCondor 生成的日志文件。

如果一切正常，所有的`STDERR`文件都会是空的，所有的`STDOUT`文件都有以下的文字：

```py
I am process 9 of cluster 61
Running on somehost
$CWD = /tmp/book/htcondor/script
$USER = bookuser
MYVAR1 = foo
MYVAR2 = bar 
```

留给读者一个有趣的练习，向`test.py`文件插入条件化的错误。如下所示：

```py
if pid == 13:
    raise Exception('Booo!')
else:
    sys.exit(0) 
```

或者：

```py
if pid == 13:
    sys.exit(2)
else:
    sys.exit(0) 
```

然后，观察任务集群的变化。

如果做这个试验，会看到在第一种情况下（抛出一个异常），响应的`STDERR`文件不是空的。第二种情况的错误难以察觉。错误是静默的，只是出现在`script.log`文件，如下所示：

```py
005 (034.013.000) 01/09 12:25:13 Job terminated.
    (1) Normal termination (return value 2)
        Usr 0 00:00:00, Sys 0 00:00:00  -  Run Remote Usage
        Usr 0 00:00:00, Sys 0 00:00:00  -  Run Local Usage
        Usr 0 00:00:00, Sys 0 00:00:00  -  Total Remote Usage
        Usr 0 00:00:00, Sys 0 00:00:00  -  Total Local Usage
    0  -  Run Bytes Sent By Job
    0  -  Run Bytes Received By Job
    0  -  Total Bytes Sent By Job
    0  -  Total Bytes Received By Job
    Partitionable Resources :    Usage  Request Allocated
       Cpus                 :                 1         1
       Disk (KB)            :        1        1  12743407
       Memory (MB)          :        0        1      2048 
```

注意到`Normal termination (return value 2)`此行，它说明发生了错误。

习惯上，我们希望发生错误时，会有这样的指示。要这样的话，我们在提交文件中使用下面的指令：

```py
Notification = Error
Notify_User = email@example.com 
```

这样，如果发生错误，HTCondor 就会向`email@example.com`发送报错的电子邮件。通知的可能的值有`Complete`（即，无论退出代码，当任务完成时，发送 email），`Error`（即，退出代码为非零值时，发送 email），和默认值`Never`。

另一个留给读者的练习是指出我们的任务需要哪台机器，任务偏好的机器又是哪台。这两个独立的请求是分别通过指令`Requirements`和`Rank`。`Requirements`是一个布尔表达式，`Rank`是一个浮点表达式。二者在每个协调循环都被评估，以找到一批机器以运行任务。

对于所有`Requirements`被评为`True`的机器，被选中的机器都有最高的`Rank`值。

> 笔记：当然，机器也可以对任务定义`Requirements`和`Rank`（由系统管理员来做）。因此，一个任务只在两个`Requirements`是`True`的机器上运行，二者`Rank`值结合起来一定是最高的。

如果不定义任务文件的`Rank`，它就默认为`0.0.Requirements`。默认会请求相同架构和 OS 作为请求节点，和族都的硬盘保存可执行文件。

例如，我们可以进行一些试验，我们请求运行 64 位 Linux、大于 64GB 内存的机器，倾向于快速机器：

```py
Requirements = (Target.Memory > 64) && (Target.Arch == "X86_64") && (Target.OpSys == "LINUX")
Rank = Target.KFlops 
```

> 笔记：对于`Requirements`和`Rank`的可能的值，你可以查看附录 A 中的 Machine ClassAd Atributes。最可能用到的是`Target.Memory`，`Target.Arch`，`Target.OpSys`，`Target.Disk`，`Target.Subnet`和`Target.KFlops`。

最后，实践中另一个强大的功能是，为不同的任务定义依赖。往往，我们的应用可以分解成一系列步骤，其中一些可以并行执行，其余的不能（可能由于需要等待中间结果）。当只有独立的步骤时，我们可以将它们组织成几个任务集合，就像前面的例子。

HTCondor DAGMan（无回路有向图管理器 Directed Acyclic Graph Manager 的缩写）是一个元规划器，是一个提交任务、监督任务的工具，当任务完成时，它会检查哪个其它的任务准备好了，并提交它。

为了在 DAG 中组织任务，我们需要为每一个任务写一个提交文件。另外，我们需要另写一个文本文件，描述任务的依赖规则。

假设我们有四个任务（单进程或多进程集合）。称为 A、B、C、D，它们的提交文件是`a.job`，`b.job`，`c.job`，`d.job`。比如，我们想染 A 第一个运行，当 A 完成时，同时运行 B 和 C，当 B 和 C 都完成时，再运行 D。

下图，显示了流程：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/7c3d466e72e90a8dbf4d7e24844b08b2.jpg)

DAG 文件（`htcondor/dag/simple.dag`）的代码如下所示：

```py
# Simple Condor DAG file
# There is no requirement or standard on DAG file extensions.
# Usage: shell> condor_submit_dag simple.dag

# Define the nodes in the DAG
JOB A a.job
JOB B b.job
JOB C c.job
JOB D d.job

# Define the relationship between nodes
PARENT A CHILD B C
PARENT B C CHILD D 
```

四个提交文件没有那么重要。我们可以使用下面的内容（例如，任务 A 和其它三个都可以使用）：

```py
Universe = vanilla
Executable = /bin/echo
Arguments = "I am job A"
Output = a_stdout.txt
Log = a.log
Queue 
```

提交完整的 DAG，是使用`condor_submit_dag`命令：

```py
$ condor_submit_dag simple.dag 
```

这条命令创建了一个特殊提交文件（`simple.dag.condor.sub`）到`condor_dagman`可执行文件，它的作用是监督运行的任务，在恰当的时间规划任务。

DAGMan 元规划器有还有许多这里没写的功能，包括类似 Makefile 的功能，可以继续运行由于错误停止的任务。

关于性能，你还需要注意几点。DAG 中的每个节点，当被提交时，都要经过一个协调循环，就像一个通常的 HTCondor 任务。这些一系列的循环会导致损耗，损耗与节点的数量成正比。通常，协调循环会与计算重叠，所以在实践中很少看到损耗。

另一点，`condor_dagman`的效率非常高，DAGs 有百万级别甚至更多的节点都很常见。

> 笔记：推荐感兴趣的读者阅读 HTCondor 一章的 DAGMan Applications。

短短一章放不下更多关于 HTCondor 的内容，它的完整手册超过 1000 页！这里介绍的覆盖了日常使用。我们会在本章的末尾介绍调试的方法。接下来，介绍另一个流行的任务规划器：PBS。

## 使用 PBS 运行 Python 任务

Portable Batch System (PBS)是 90 年代初，NASA 开发的。它现在有三个变体：OpenPBS，Torque 和 PBS Pro。这三个都是原先代码的分叉，从用户的角度，它们三个的外观和使用感受十分相似。

这里我们学习 PBS Pro（它是 Altair Engineering 的商用产品，[http://www.pbsworks.com](https://link.jianshu.com?t=http://www.pbsworks.com/)），它的特点和指令在 Torque 和 OpenPBS 上也可以使用，只是有一点不同。另外，为了简洁，我们主要关注 HTCondor 和 PBS 的不同。

从概念上，PBS 和 HTCondor 很像。二者有相似的架构，一个主节点（`pbs_server`），一个协调器和规划器（`pbs_sched`），执行节点的任务监督器（`pbs_mom`）。

用户将任务提交到队列。通常，对不同类型的任务（例如，序列 vsMPI 并行）和不同优先级的任务有多个队列。相反的，HTCondor 对每个提交主机只有一个队列。用户可用命令行工具、DRMAA 和 Python 的 drmaa 模块（`pip install drmaa`）与 PBS 交互。

PBS 任务文件就是一般的可以本地运行的文件（例如，Shell 或 Python 文件）。它们一般都有专门的内嵌的 PBS 指令，作为文件的注释。这些指令的 Windows 批处理脚本形式是#PBS <directive> 或 REM PBS <directive>（例如，`#PBS -q serial or REM PBS –q serial`）。

使用`qsub`命令（类似`condor_submit`），将任务提交到合适的任务队列。一旦成功提交一个任务，`qsub`会打印出任务 ID（形式是`integer.server_hostname`），然后退出。任务 ID 也可以作为任务的环境变量`$PBS_JOBID`。

资源需求和任务特性，可以在`qsub`中指出，或在文件中用指令标明。推荐在文件中用指令标明，而不用`qsub`命令，因为可以增加文件的可读性，也是种记录。

例如，提交我们之前讨论过的`simple.job`，你可以简单的写一个最小化的 shell 文件（`pbs/simple/simple.sh`）：

```py
#!/bin/bash
/usr/local/bin/python3.5 -c "print('Hello, HTCondor!')" 
```

我们看到，没有使用 PBS 指令（它适用于没有需求的简单任务）。我们可以如下提交文件：

```py
$ qsub simple.sh 
```

因为没必要为这样的一个简单任务写 Shell 文件，`qsub`用行内参数就可以了：

```py
$ qsub -- /usr/local/bin/python3.5 -c "print('Hello, HTCondor!')" 
```

但是，不是所有的 PBS 都有这个特性。

在有多个任务队列/规划器的安装版本上，我们可以指定队列和规划器，可以用命令行（即`qsub –q queue@scheduler_name`）或用文件中的指令（即，`#PBS –q queue@scheduler_name`）。

前面的两个示例任务显示了 PBS 和 HTCondor 在提交任务时的不同。使用 HTCondor，我们需要写一个任务提交文件，来处理运行什么以及在哪里运行。使用 PBS，可以直接提交任务。

> 笔记：从 8.0 版本开始，HTCondor 提供了一个命令行工具，`condor_qsub`，像是`qsub`的简化版，非常适合从 PBS 向 HTCondor 转移。

提交成功后，`qsub`会打印出任务 ID，它的形式是`integer.servername`（例如`8682293.pbshead`）。PBS 将任务标准流重新转到`scriptname.oInteger`（给`STDOUT`）和`scriptname.eInteger`（给`STDERR`），`Integer`是任务 ID 的整数部分（例如，我们例子中的 simple.sh.e8682293 和 script.sh.o8682293）。

任务通常（在执行节点）运行在提交账户之下，在一个 PBS 创建的临时目录，之后会自动删除。目录的路径是环境变量`$PBS_TMPDIR`。

通常，PBS 定义定义了许多环境变量，用于运行的任务。一些设定了提交任务的账户的环境，它们的名字通常是`PBS_0`开头（例如，`$PBS_O_HOME`或`$PBS_O_PATH`）。其它是专门用于任务的，如`$PBS_TMPDIR`。

> 笔记：现在，PBS Pro 定义了 30 个任务环境变量。可以在 PBS Professional Reference Guide 的 PBS Environment Variables 一章查到完整列表。

使用指令`#PBS –J start-end[:step]`提交任务数组（命令行或在文件中使用指令）。为了获得提交者的环境，可以使用`-V`指令，或者传递一个自定义环境到任务，使用`#PBS -v "ENV1=VAL1, ENV2=VAL2, …"`。

例如，前面例子的任务数组，可以这样写（`pbs/script/test.py`）：

```py
#!/usr/bin/env python3.5
#PBS -J 0-99
#PBS -V
import argparse
import getpass
import os
import socket
import sys

ENV_VARS = ('MYVAR1', 'MYVAR2')

if 'PBS_ENVIRONMENT' in os.environ:
    # raw_cid has the form integer[].server
    raw_cid = os.environ['PBS_ARRAY_ID']
    cid = int(raw_cid.split('[')[0])
    pid = int(os.environ['PBS_ARRAY_INDEX'])
else:
    parser = argparse.ArgumentParser()
    parser.add_argument('--clusterid', type=int)
    parser.add_argument('--processid', type=int)
    args = parser.parse_args()

    cid = args.clusterid
    pid = args.processid

print('I am process {} of cluster {}'
      .format(pid, cid))
print('Running on {}'
      .format(socket.gethostname()))
print('$CWD = {}'
      .format(os.getcwd()))
print('$USER = {}'
      .format(getpass.getuser()))

undefined = False
for v in ENV_VARS:
    if v in os.environ:
        print('{} = {}'
              .format(v, os.environ[v]))
    else:
        print('Error: {} undefined'
              .format(v))
        undefined = True
if undefined:
    sys.exit(1)
sys.exit(0) 
```

我们完全不需要提交文件。用`qsub`提交，如下所示：

```py
$ MYVAR1=foo MYVAR2=bar qsub test.py 
```

分配的任务 ID 的形式是`integer[].server`（例如`8688459[].pbshead`），它可以指示提交了任务数组，而不是一个简单的任务。这是 HTCondor 和 PBS 的另一不同之处：在 HTCondor 中，一个简单任务是一个任务集合（即，任务数组），只有一个进程。另一不同点是，PBS 任务访问集合 ID 和进程 ID 的唯一方式是通过环境变量，因为没有任务提交文件（提交任务时可以提交变量）。

使用 PBS，我们还需要做一些简单解析以从`$PBS_ARRAY_ID`提取任务数组 ID。但是，我们可以通过检测是否定义了`$PBS_ENVIRONMENT`，来判断代码是否运行。

使用指令`-l`指明资源需求。例如，下面的指令要求 20 台机器，每台机器有 32 核和 16GB 内存：

```py
#PBS –l select=20:ncpus=32:mem=16gb 
```

也可以指定任务的内部依赖，但不如 HTCondor 简单：依赖的规则需要任务 ID，只有在提交任务之后才会显示出来。之前的 DAG`diamond`可以用如下的方法执行（`pbs/dag/dag.sh`）：

```py
#!/bin/bash
A=`qsub -N A job.sh`
echo "Submitted job A as $A"

B=`qsub -N B -W depend=afterok:$A job.sh`
C=`qsub -N C -W depend=afterok:$A job.sh`
echo "Submitted jobs B & C as $B, $C"

D=`qsub -N D -W depend=afterok:$B:$C job.sh`
echo "Submitted job D as $D" 
```

这里，任务文件是：

```py
#!/bin/bash
echo "I am job $PBS_JOBNAME" 
```

这个例子中，使用了`$PBS_JOBNAME`获取任务名，并使用指令`-W depend=`强制了任务执行顺序。

一旦提交了任务，我们可以用命令`qstat`监控，它等同于`condor_q`。销毁一个任务（或在运行之前，将队伍从队列移除），是通过`qdel`（等价于`condor_rm`）。

PBS Pro 和 HTCondor 一样，是一个复杂的系统，功能很多。这里介绍的只是它的表层，但是作为想要在 PBS HPC 机群上操作的人，作为入门足够了。

一些人觉得用 Python 和 Shell 文件提交到 PBS 而不用任务文件非常有吸引力。其他人则喜欢 HTCondor 和 DAGMan 的工具处理任务内依赖。二者都是运行在 HPC 机群的强大系统。

## 调试

一切正常是再好不过，但是，运气不会总是都好。分布式应用，即使是远程运行的简单任务，都很难调试。很难知道任务运行在哪个账户之下，运行的环境是什么，在哪里运行，使用任务规划器，很难预测何时运行。

当发生错误时，通过几种方法，可以知道发生了什么当使用任务规划器时，首先要做的是查看任务提交工具返回错误信息（即，`condor_submit`，`condor_submit_dag`，`or qsub`）。然后要看任务`STDOUT`，`STDERR`和日志文件。

通常，任务规划器本身就有诊断错误任务的工具。例如，HTCondor 提供了`condor_q -better-analyze`，检查为什么任务会在队列中等待过长时间。

通常，任务规划器导致的问题可以分成以下几类：

*   权限不足
*   环境错误
*   受限的网络通讯
*   代码依赖问题
*   任务需求
*   共享 vs 本地文件系统

头三类很容易检测，只需提交一个测试任务，打印出完整的环境、用户名等等，剩下的很难检测到，尤其是在大集群上。

对于这些情况，可以关注任务是在哪台机器运行的，然后启动一个交互 session（即 `qsub –I`、`condor_submit – interactive`或`condor_ssh_to_job`），然后一步一步再运行代码。

如果任务需求的资源不足（例如，需要一个特定版本的 OS 或软件包，或其它特别的硬件）或资源过多，任务规划器就需要大量时间找到合适的资源。

任务规划期通常提供工具以检查哪个资源符合任务的需求（例如，`condor_status –constrain`）。如果任务分配给计算节点的时间不够快，就需要进行检测。

另一个产生问题的来源是提交主机的文件系统的代码、数据不能适用于全部的计算节点。这种情况下，推荐使用数据转移功能（HTCondor 提供），数据阶段的预处理文件。

Python 代码的常用方法是使用虚拟环境，在虚拟环境里先安装好所有的依赖（按照指定的安装版本）。完成之后，再传递给任务规划器。

在有些应用中，传输的数据量十分大，要用许多时间。这种情况下，最好是给数据分配进程。如果不能的话，应该像普通任务一样规划数据的移动，并使用任务依赖，保证数据准备好之后再开始计算。

## 总结

我们在本章学习了如何用任务规划器，在 HPC 机群上运行 Python 代码。

但是由于篇幅的限制，还有许多内容没有涉及。也许，最重要的就是 MPI（Message Passing Interface），它是 HPC 任务的进程间通讯标准库。Python 有 MPI 模块，最常使用的是 mpi4py， [http://pythonhosted.org/mpi4py/](https://link.jianshu.com?t=http://pythonhosted.org/mpi4py/)，和 Python 包目录[https://pypi.python.org/pypi/mpi4py/](https://link.jianshu.com?t=https://pypi.python.org/pypi/mpi4py/)。

另一个没涉及的是在 HPC 机群运行分布式任务队列。对于这种应用，可以提交一系列的任务到机群，一个任务作为消息代理，其它任务启动 worker，最后一个任务启动应用。特别需要注意连接 worker 和应用到消息代理，提交任务的时候不能确定代理是在哪一台机器。与 Pyro 类似的一个策略是使用 nameserver，解决这个问题。

然而，计算节点上有持续的进程是不推荐的，因为不符合任务规划器的原则。大多数系统都会在几个小时之后退出长时间运行的进程。对于长时间运行的应用，最好先咨询机群的管理者。

任务规划器（包括 MPI）是效率非常高的工具，在 HPC 之外也有用途。其中许多都是开源的，并且有活跃的社区，值得一看。

下一章会讲分布式应用发生错误时该怎么做。



# 七、测试和调试分布式应用 （Distributed Computing with Python）



无论大小的分布式应用，测试和调试的难度都非常大。因为是分布在网络中的，各台机器可能十分不同，地理位置也可能不同。

进一步的，使用的电脑可能有不同的用户账户、不同的硬盘、不同的软件包、不同的硬件、不同的性能。还可能在不同的时区。对于错误，分布式应用的开发者需要考虑所有这些。查错的人需要面对所有的这些挑战。

目前为止，本书没有花多少时间处理错误，而是关注于开发和部署应用的工具。

在本章，我们会学习开发者可能会碰到的错误。我们还会学习一些解决方案和工具。

## 概述

测试和调试一个单体应用并不简单，但是有许多工具可以使其变得简单，包括 pdb 调试器，各种分析工具（有 cProfile 和 line_profile），纠错器（linter），静态代码分析工具，和许多测试框架，其中许多都包括于 Python 3.3 及更高版本的标准库。

调试分布式应用的困难是，单进程应用调试的工具处理多进程时就失去了一部分功能，特别是当进程运行在不同的机器上时。

调试、分析用 C、C++、Fortran 语言写成的分布式应用可以用工具，例如 Intel VTune、Allinea MAP 和 DDT。但是 Python 开发者可用的工具极少，甚至没有。

编写小型和中型的分布式应用并不难。与单线程应用相比，写多线程应用的难点是后者有许多依赖间组件，组件通常运行在不同的硬件上，必须要协调网络。这就是为什么监控和调试分布代码如此困难。

幸运的是，还是可以在 Python 分布式应用上使用熟悉的调试工具和代码分析工具。但是，这些工具的作用有限，我们必须使用登录和打印语句，以搞清错误在哪里。

## 常见错误——时钟和时间

时间是一个易用的变量。例如，当将不同的数据流整合、数据库排序、重建事件的时间线，使用时间戳是非常自然的。另外，一些工具（比如`GMU make`）单纯的依赖文件修改的时间，很容易被不同机器的错误时间搞混。

因为这些原因，在所有的机器进行时间同步是非常重要的。如果机器位于不同的时区，不仅要同步时间，还要根据 UTC 时间进行校准。当不能将时间调整为 UTC 时间时，建议代码内部都是按照 UTC 来运行，只是在屏幕显示的时候再转化为本地时间。

通常，在分布式系统中进行时间同步是一个复杂的课题，超出了本书的范畴。大多数读者，可以使用网络时间协议（NTP），这是一个完美的同步解决方案。大多数操作系统都支持 NTP。

关于时间，另一个需要考虑的是周期动作的计时，例如轮询循环和定时任务。许多应用需要每隔一段时间就产生进程或进行动作（例如，发送 email 确认或检查新的数据是否可用）。

常用的方法是使用定时器（使用代码或使用 OS 工具），在某一时刻让所有定时器启动，通常是在某刻和一定时间段之后。这种方法的危险之处是，进程同一时刻开始工作，可能使系统过载。

一个常见的例子是启动许多进程，这些进程都需要从一个共享硬盘读取配置或数据。这种情况下，所有一切正常，知道进程的数量变得太大，以至于共享硬盘无法处理数据传输，就会导致应用变慢。

常见的解决方法是把计时器延迟，让计时器分布在一个范围之内。通常，因为我们不总是控制所有使用的代码，让计时器随机延迟几分钟是可行的。

另一个例子是图片处理服务，需要给隔一段时间就检测新的数据。当发现新的图片，就复制这些图片、重命名、缩放、并转换成常见的格式，最后存档。如果不小心，同一时间上传过多图片，就会很容易使系统过载。

更好的方法是限制应用（使用队列架构），只加载合理数量的图片，而不使系统过载。

## 常见错误——软件环境

另一个常见的问题是所有机器上安装的软件是一致的，升级也是一致的。

不过，往往用几小时调试一个分布式系统，最后发现因为一些未知的原因，一些电脑上的代码或软件是旧版的。有时，还会发现该有的代码反而没有。

软件存在差异的原因很多：可能是加载失败，或部署过程中的错误，或者仅仅是人为的错误。

HPC 中常用的解决方法是，在启动应用之前，将代码安装在虚拟环境里。一些项目倾向于静态的依赖链接，以免从动态库加载出现错误。

当和安装完整环境、软件依赖和应用本身相比，这种方法适用于运行时较长的应用。实际意义不大。

幸好，Python 可以创建虚拟环境。可以使用两个工具`pyvenv`（Python 3.5 以上的标准库支持）和`virtualenv`（PyPI 支持）。另外，使用`pip`命令，可以指定包的版本。联合使用这些工具，就可以控制执行环境。

但是，错误往往在细节，不同的节点可能有相同的虚拟环境，但是有不兼容的第三方库。

对于这些问题，可以使用容器技术，例如 Docker，或有版本控制的虚拟环境。

如果不能使用容器技术，就想到了 HPC 机群，最好的方法不是依赖系统软件，而是自己管理环境和软件栈。

## 常见问题——许可和环境

不同的电脑可能是在不同的用户账户下运行我们的代码，我们的应用可能想在一个特定的目录下读取文件或写入数据，然后碰到了一个许可错误。即使我们的代码使用的账户都是相同的，它们的环境可能是不同的。因此，设定的环境变量的值可能是错误的。

当我们的代码使用特殊的低级用户账号运行时，这种问题就很常见。防御性的代码，尤其是访问环境碰到未定义值时，能返回默认设置是十分必要的。

一个常见的方法是，只在特定的用户账号下运行，这个账号由自己控制，指定环境变量，和应用启动文件（它的版本也是受控的）。

但是，一些系统不仅是在极度受限的账户下运行任务，而且还是限制在沙盒内。大多数时候，连接外网也是禁止的。此时，唯一的办法就是本地设置完整环境，并复制到共享硬盘。其它的数据可以来自用户搭建的，运行小任务的服务器。

通常来说，许可错误和用户环境问题与软件环境问题类似，应该协同处理。开发者往往想让代码尽可能独立于环境，用虚拟环境装下代码和环境变量。

## 常见问题——硬件资源可用性

在给定的时间，我们的应用需要的硬件资源可能，也可能不可用。即使可用，也不能保证在相当长的时间内都可用。当网络出现故障时，就容易碰到这个问题，并且很常见（尤其是对于移动 app）。在实际中，很难将这种错误和机器或应用崩溃进行区分。

使用分布式框架和任务规划器的应用经常需要依靠框架处理常见的错误。当发生错误或机器不可用时，一些任务规划器还会重新提交任务。

但是，复杂的应用需要特别的策略应对硬件问题。有时，最好的方法是当资源可用时，再次运行应用。

其它时候，重启的代价很大。此时，常用的方法是从检查点重启。也就是说，应用会周期的记录状态，所以可以从检查点重启。

如果从检查点重启，你需要平衡从中途重启和记录状态造成的性能损失。另一个要考虑的是，增加了代码的复杂性，尤其是使用多个进程或线程读写状态信息。

好的方法是，可以快速重新创建的数据和结果不要写入检查点。或者，一些进程需要花费大量时间，此时使用检查点非常合适。

例如，气象模拟可能运行数周或数月。此时，每隔几个小时就写入检查点是非常重要的，因为从头开始成本太高。另外，上传图片和创建缩略图的进程，它的运行特别快，就不需要检查点。

安全起见，状态的写入和更新应该是不可分割的（例如，写入临时文件，只有在写入完全的时候才能取代原先的文件）。

与 HPC 和 AWS 竞价实例很相似，进程中的一部分会被从运行的机器驱赶出来。当这种情况发生时，通常会发送一个警告（信号`SIGQUIT`），几秒之后，这些进程就会被销毁（信号`SIGKILL`）。对于 AWS 竞价实例，可以通过实例元数据的服务确定销毁的时间。无论哪种情况，我们的应用都有时间来记录状态。

Python 有强大的功能捕获和处理信号（参考`signal`模块）。例如，下面的示例代码展示了一个检查点策略：

```py
#!/usr/bin/env python3.5
"""
Simple example showing how to catch signals in Python
"""
import json
import os
import signal
import sys

# Path to the file we use to store state. Note that we assume
# $HOME to be defined, which is far from being an obvious
# assumption!
STATE_FILE = os.path.join(os.environ['HOME'],
                               '.checkpoint.json')

class Checkpointer:
    def __init__(self, state_path=STATE_FILE):
        """
        Read the state file, if present, and initialize from that.
        """
        self.state = {}
        self.state_path = state_path
        if os.path.exists(self.state_path):
            with open(self.state_path) as f:
                self.state.update(json.load(f))
        return

    def save(self):
        print('Saving state: {}'.format(self.state))
        with open(self.state_path, 'w') as f:
            json.dump(self.state, f)
        return

    def eviction_handler(self, signum, frame):
        """
        This is the function that gets called when a signal is trapped.
        """
        self.save()

        # Of course, using sys.exit is a bit brutal. We can do better.
        print('Quitting')
        sys.exit(0)
        return

if __name__ == '__main__':
    import time

    print('This is process {}'.format(os.getpid()))

    ckp = Checkpointer()
    print('Initial state: {}'.format(ckp.state))

    # Catch SIGQUIT
    signal.signal(signal.SIGQUIT, ckp.eviction_handler)
    # Get a value from the state.
    i = ckp.state.get('i', 0)
    try:
        while True:
            i += 1
            ckp.state['i'] = i
            print('Updated in-memory state: {}'.format(ckp.state))
            time.sleep(1)
    except KeyboardInterrupt:
        ckp.save() 
```

我们可以在一个终端运行这段代码，然后在另一个终端，我们发送一个信号`SIGQUIT`（例如，`-s SIGQUIT <process id>`）。如果这么做的话，我们可以看到检查点的动作，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/2b170c04d55dee9720ffabbc54567484.jpg)

> 笔记：使用分布式应用通常需要在性能不同、硬件不同、软件不同的机器上运行。

即使有任务规划器，帮助我们廁何时的软件和硬件环境，我们必须记录各台机器的环境和性能。在高级的架构中，这些性能指标可以提高任务规划的效率。

例如，PBS Pro，再次执行提交任务时就考虑了历史性能。HTCondor 持续给每台机器打分，用于选择节点和排名。

最让人没有办法的情况是网络问题或服务器过载，网络请求的时间太长，就会导致代码超时。这可能会导致我们认为服务使不可用的。这些暂时性的问题，是很难调试的。

## 困难——开发环境

另一个分布式系统常见的困难是搭建一个有代表性的开发和测试环境，尤其是对于个人小型团队。开发环境最好能代表最糟糕的开发环境，可以让开发者测试常见的错误，例如硬盘溢出、网络延迟、间歇性网络断开，硬件、软件失效等实际中会发生的故障。

大型团队拥有开发和测试集群的资源，他们总是有专门的软件质量团队对我们的代码进行压力测试。

不幸的是，小团队常常被迫在笔记本电脑上编写代码，并使用非常简单（最好的情况！）的由两台或三台虚拟机组成环境，它们运行在笔记本电脑上以模拟真实系统。

这种务实的方案是可行的，绝对比什么都没有要好。然而，我们应该记住，虚拟机运行在同一主机上表现出不切实际的高可用性和较低的网络延迟。此外，没有人会意外升级它们，而不通知我们或使用错误的操作系统。这个环境太易于控制和稳定，不够真实。

更接近现实的设置是创建一个小型开发集群，比如 AWS，使用相同的 VM 镜像，使用生产环境中相同的软件栈和用户帐户。

简而言之，很难找到替代品。对于基于云平台的应用，我们至少应该在部署版本的小型版本上测试我们的代码。对于 HPC 应用程序，我们应该使用测试集群、或集群的一部分，用于测试和开发。

理想情况下，我们最好在操作系统的一个克隆版本上进行开发。但是，考虑成本和简易性，我们还是会使用虚拟机：因为它够简单，基本上是免费的，不用网络连接，这一点很重要。

然而，我们应该记住分布式应用并不是很难编写的，只是它们的故障模式比单机模式多的多。其中一些故障（特别是与数据访问相关的），所以需要仔细地选择架构。

在开发阶段后期，纠正由错误假设所导致的架构选择代价高昂。说服管理者尽早给我们提供所需的硬件资源通常是困难的。最后，这是一种微妙的平衡。

## 有效策略——日志

通常情况下，日志就像备份或吃蔬菜，我们都知道应该这样做，但大多数人都忘记了。在分布式应用程序中，我们没有其他选择，日志是必不可少的。不仅如此，记录一切都是必要的。

由于有许多不同的进程在远程资源上运行，理解发生了什么的唯一方法是获得日志信息并使其随时可用，并且以易于检索的格式/系统存储。

在最低限度，我们应该记录进程的启动和退出时间、退出代码和异常（如果有的话），所有的输入参数，输出，完整执行环境、执行主机名和 IP，当前工作目录，用户帐户以及完整应用配置，和所有的软件版本。

如果出了问题，我们应该能够使用这些信息登录到同一台机器（如果仍然可用），转到同一目录，并复制我们的代码，重新运行。当然，完全复制执行环境可能做不到（通常是因为需要管理员权限）。

然而，我们应该始终努力模拟实际环境。这是任务规划器的优点所在，它允许我们选择指定的机器，并指定完整的任务环境，这使得复制错误更少。

记录软件版本（不仅是 Python 版本，还有使用的所有包的版本）可以诊断远程机器上过时的软件栈。Python 包管理器，`pip`，可以容易的获取安装的包：`import pip; pip.main(['list'])`。`import sys; print(sys.executable, sys.version_info)`可以显示 Python 的位置和版本。

创建一个系统，使所有的类和函数调用发出具有相同等级的日志，而且是在对象生命周期的同一位置。常见的方法包括使用装饰器、元类。这正是 Python 模块`autologging` （PyPI 上有）的作用。

一旦日志就位，我们面临的问题是在哪里存储这些日志，对于大型应用，传输日志占用资源很多。简单的应用可以将日志写入硬盘的文本文件。更复杂的应用程序可能需要在数据库中存储这些信息（可以通过创建一个 Python 日志模块的自定义处理程序完成）或专门的日志聚合器，如 Sentry（[https://getsentry.com](https://link.jianshu.com?t=https://getsentry.com/)）。

与日志密切相关的是监督。分布式应用程序可以有许多可移动组件，并且需要知道哪些机器处于繁忙状态，以及哪些进程或任务当前正在运行、等待，或处于错误状态。知道哪些进程比平时花费更长的时间，往往是一个重要的警告信号，表明可能有错误。

Python 有一些监督方案（经常与日志系统集成）。比如 Celery，推荐使用 flower（[http://flower.readthedocs.org](https://link.jianshu.com?t=http://flower.readthedocs.org/)）作为监督和控制。另外，HPC 任务规划器，往往缺少通用的监督方案。

在潜在问题变严重之前，最好就监测出来。实际上，监视资源（如可用硬盘空间和触发器动作），甚至是简单的 email 警告，当它们低于阈值时，监督是有用的。许多部门监督硬件性能和硬盘智能数据，以发现潜在问题。

这些问题更可能是运营而不是开发者感兴趣的，但最好记住。监督也可以集成在我们的应用程序以执行适当的策略，来处理性能下降的问题。

## 有效策略——模拟组件

一个好的，虽然可能耗费时间和精力，测试策略是模拟系统的一些或全部组件。原因是很多：一方面，模拟软件组件使我们能够更直接地测试接口。此时，mock 测试库，如`unittest.mock`（Python 3.5 的标准库），是非常有用的。

另一个模拟软件组件的原因是，使组件发生错误以观察应用的响应。例如，我们可以将增加 REST API 或数据库的服务的响应时间，看看会发生什么。有时，超时会让应用误以为服务器崩溃。

特别是在设计和开发复杂分布式应用的早期阶段，人们可能对网络可用性、性能或服务响应时间（如数据库或服务器）做出过于乐观的假设。因此，使一个服务完全失效或修改它的功能，可以检测出代码中的错误。

**Netflix Chaos Monkey** ([https://github.com/Netflix/SimianArmy](https://link.jianshu.com?t=https://github.com/Netflix/SimianArmy))可以随机使系统中的组件失效，用于测试应用的反应。

## 总结

用 Python 编写或运行小型或中型分布式应用程序并不困难。我们可以利用许多高质量框架，例如，Celery、Pyro、各种任务规划期，Twisted、，MPI 绑定（本书中没有讨论），或标准库的模块`multiprocessing`。

然而，真正的困难在于监视和调试应用，特别是因为大部分代码并行运行在许多不同的、通常是远程的计算机上。

潜藏最深的 bug 是那些最终产生错误结果的 bug（例如，由于数据在过程中被污染），而不是引发一个异常，大多数框架都能捕获并抛出。

遗憾的是，Python 的监视和调试工具不像用来开发相同代码的框架和库那么功能完备。其结果是，大型团队可以使用自己开发的、通常是非常专业的分布式调试系统，小团队主要依赖日志和打印语句。

分布式应用和动态语言（尤其是 Python）需要更多的关于调试方面的工作。



# 八、继续学习 （Distributed Computing with Python）

* * *

[序言](https://www.jianshu.com/p/ad10480c89d9)
[第 1 章 并行和分布式计算介绍](https://www.jianshu.com/p/a8ec42f6cb4e)
[第 2 章 异步编程](https://www.jianshu.com/p/02893376bfe8)
[第 3 章 Python 的并行计算](https://www.jianshu.com/p/66f47049cc5a)
[第 4 章 Celery 分布式应用](https://www.jianshu.com/p/ee14ed9e4989)
[第 5 章 云平台部署 Python](https://www.jianshu.com/p/84dde3009782)
[第 6 章 超级计算机群使用 Python](https://www.jianshu.com/p/59471509d3d9)
[第 7 章 测试和调试分布式应用](https://www.jianshu.com/p/c92721ff5f3c)
第 8 章 继续学习

* * *

这本书是一个简短但有趣的用 Python 编写并行和分布式应用的旅程。这本书真正要做的是让读者相信使用 Python 编写一个小型或中型分布式应用不仅是大多数开发者都能做的，而且也是非常简单的。

即使是一个简单的分布式应用也有许多组件，远多于单体应用。也有更多的错误方式，不同的机器上同一时间发生的事情也更多。

但是，幸好可以使用高质量的 Python 库和框架，来搭建分布式系统，使用起来也比多数人想象的简单。

另外，并行和分布式计算正逐渐变为主流，随着多核 CPU 的发展，如果还继续遵守摩尔定律，编写并行代码是必须的。

Celery、Python-RQ、Pyro 等工具，只需要极少的精力，就可以获得性能极大地提高。

但是，必须要知道，分布式应用缺少强大的调试器和分析器，这个问题不局限于 Python。监督和日志可以检测性能的瓶颈，进而查找到错误。现在这种缺少调试工具的状况，需要改善。

本章剩下的部分回顾了前面的所学，还给感兴趣的读者提了继续学习哪些工具和课题的建议。

## 前两章

本书的最初章节讲解了一些并行和分布式计算的基本理论。引入了一些重要的概念，如共享内存和分布式内存架构以及它们之间的差异。

这两章还用阿姆达尔定律研究了并行加速的基本算法。讨论的收获是，投入并行计算的收益是递减的。另外，绕过阿姆达尔定律的方法之一是增加的问题的规模，使并行代码所占的份额更大（古斯塔夫森定律）。

另一个收获是，尽量保持进程间通讯越小越好。最好让各个进程都是独立的。进程之间的通讯越少，代码越简单，损耗越少。

大多数实际场景都需要一系列扇出和扇入同步/还原步骤，大多数框架都能合理有效地处理这些步骤。然而，并行步骤中的数据依赖或大量消息传递通常会成为严重的问题。

提到的另一种架构是数据列车或数据并行。这是一种处理方式，其中一个启动大量的 worker 进程，超过可用硬件资源的数量。正如所看到的，数据并行的主要优点是很好的伸缩性和更简单的代码。此外，大多数操作系统和任务规划器在交错 I/O 和计算方面会做得很好，从而掩盖系统延迟。

我们还研究了两种完全不同的编程范式：同步和异步编程。我们看到 Python 对 futures、回调、协程的支持很好，这是异步编程的核心。

正如我们所讨论的，异步代码具有避免，或者减少了竞争条件，因为只有一段代码可以在给定的时间点运行。这意味着，数据访问模式被大大简化了，但代码和调试变复杂了；当使用回调和协程，很难跟踪执行路径。

在本书中，我们看到了使用线程、多进程、协程的并行代码的性能。对于 I/O 操作，我们看到这三个并发策略可以实现显着的加速。然而，由于 Python 全局锁，CPU 操作并没有获得加速，除非使用多个进程。

同步和异步编程都有其优点。使用的越多，越会发现线程和系统编程的 C 和 C++很像。协程的优点之一就是避免竞争条件。多个进程，虽然在一台机器上相当笨重，但为更一般的分布式计算架构铺平了道路。使用哪种风格取决于个人喜好和必须使用的特定库。

## 工具

在第 3 章中，我们学习了 Python 的标准库模块，来编写并行应用。我们使用了`threading`和`multiprocessing`模块，还使用了更为高级的`concurrent.futures`模块。

我们看到 Python 为分布式并行应用构建了一个坚固的基础。前面的是哪个模块都是 Python 安装包自带的，没有外部依赖，因此很受欢迎。

我们在第 4 章学习了一些第三方 Python 模块，包括 Celery、Python-RQ 和 Pyro。我们学习了怎么使用它们，并看到它们都很容易使用。

它们都需要一些内部组件，比如消息代理、数据库或 nameserver，它们可能不适用于所有情况。同时，它们都可以让开发者轻易地开发小型和中型的分布应用。它们都有活跃的社区给予支持。

关于代码的性能，最重要的是分析哪些代码是值得优化的。如果使用更快的解释器，比如 pypy，不能使性能提高，就要考虑更优化的库，比如对数值代码使用 Numpy，或使用 C 或 Cython，它们都可以使性能提高。

如果这些方法不成，还可以考虑并发、并行和分布式结算，但会提高复杂性。

一个简单的办法是使用数据并行（例如，对不同的数据启用多个代码实例）。可以使用任务规划器，比如 HTCondor。

稍微复杂一点的办法是使用`concurrent.futures`或 Celery，使代码并行化。高级用户，特别是 HP 用户，还可以考虑使用 MPI 作为进程间通讯框架。

但是，并非所有的分布式应用都要用到 Celery、Python-RQ 和 Pyro。特别是当应用需要复杂、高性能、分布式图片处理，使用 Celery 就不好。

此时，开发者可以使用工作流管理系统，例如**Luigi** ([https://github.com/spotify/luigi](https://link.jianshu.com?t=https://github.com/spotify/luigi))，或流处理，比如 Apache Spark 或 Storm。对于专门的 Python 工具，可以参考[https://spark.apache.org/docs/0.9.1/python-programming-guide.html](https://link.jianshu.com?t=https://spark.apache.org/docs/0.9.1/python-programming-guide.html) and[https://github.com/Parsely/streamparse](https://link.jianshu.com?t=https://github.com/Parsely/streamparse)。

## 云平台和 HPC

第 5 章简要介绍了云计算和 AWS。这是现在的热点，原因很简单：只要很少的投入，几乎不需要等待，就可以租用一些虚拟机，还可以租数据库和数据存储。如果需要更多的性能，可以方便地进行扩展。

Things, unfortunately, are never as simple as vendor brochures like to depict, especially when outsourcing a critical piece of infrastructure to a third party whose interests might not be perfectly aligned with ours.

[](https://link.jianshu.com?t=http://fanyi.baidu.com/translate?aldtype=16047&query=Large+teams+have+the+resources+to+set+up+development+and+test+clusters%2C+and+they+almost+always+have+dedicated+software+quality+teams+stress+testing+our+code.&keyfrom=baidu&smartresult=dict&lang=auto2zh###)

不过，事情不像销售商手册描述的那样简单，特别是当把一个重要的工作外包给一个可能与我们的利益不完全一致的第三方的时候。

我的建议是总是设想最坏的情况，并在本地自动备份整个应用及其软件栈（至少在单独的个体上）。理想情况下（但实际上并不是这样），人们会在一个完全独立的云平台上运行一个缩减的、但最新的完整应用的拷贝，作为发生错误的保险。

使用第三方服务时，进行本地备份是非常重要的。用户虚拟机和数据被删除，不可找回，这种错误绝不要发生。还要考虑过度依赖某个服务商，当应用过大时，迁移到另一个服务商几乎是不可能的。

只使用最小公分母（例如，只使用 EC2 和 AWS）既有吸引力，也可能让人沮丧，只能使用 AWS 提供的功能。

总之，云平台是一把双刃剑。对于小团队和小应用来说，它无疑是方便和低成本的。对于大型应用程序或处理大量数据的应用来说，它可能是相当昂贵的，因为带宽往往非常贵。

此外，学术界、政府部门或政府机构的团队可能很难获得支付云平台所需的资金。事实上，在这些部门，通常更容易获得资金购买设施自建而不是服务。

另一个关于严重限制了云计算在许多情况下的适用性问题，就是数据隐私和数据托管问题。例如，大公司往往不愿意在别人的机器上存放他们私有的，通常是机密的数据。

医疗数据，这类与客户或患者唯一相关的数据，对它应该存储在哪里以及如何使用有它自己的一套法律限制。最近美国有关国家监管部门要求欧洲公司使用云平台时，加大对其数据的隐私权和法律管辖权管理。

HPC 使用的工具，在这几十年来还是只限于自身的范围，没怎么用到其他领域。

虽然有若干原因导致了这个问题，还是要学习下任务规划器，如 HTCondor，和如何使用它。HTCondor 可以在许多不同的环境中使用。它是一个强大的分布式计算中间件，适用于小型和大型应用。

现在的任务规划器提供了大量的功能，它们在容错、工作流管理和数据移动规划等领域尤其强大。它们都支持运行任何可执行文件，这意味着它们可以轻易的规划和运行 Python 代码。

让人感兴趣的可能是用云平台虚拟机动态扩展 HPC 系统。有些任务规划器自身支持使用适配器，如 Eucalyptus。

高级 HPC 用户可能希望将其应用指定运行在机群的某些机器上。事实上，事实上，HPC 系统中的网络结构是按层次结构组织的：高速网络连接同一级上的节点。下一个性能层连接同一个机柜中或一组机柜。InfiniBand 等级连接剩下的机柜租，最后，较慢的以太网连接机群，彼此连接和连接外部。

结果是，应用程序需要大量的进程间通信和/或数据迁移，使用较少数量的位于同一级的处理器，而不是多个等级的处理器，就可以使性能大幅提高。类似的方法也适用于所使用的网络文件系统，以及是否为元文件的大量操作付出性能的代价。

当然这些优化，缺点是它们是不可移植的，这是由于 HPC 系统的声明周期只有几年，因此需要尽量使用最高性能的代码（这是 HPC 集群存在的理由）。

## 调试和监控

第 7 章中介绍少的日志、监控、分析和吊事分布式系统，即使放在现在，也是困难的工作，尤其是使用的语言不是 C、C++或 Fortran。这里没有什么要说的了，除了有一个重要的空白要填补。

多数的中大型团队使用日志聚合器如 Sentry ([https://getsentry.com](https://link.jianshu.com?t=https://getsentry.com/))，和监控方案如 Ganglia ([http://ganglia.sourceforge.net](https://link.jianshu.com?t=http://ganglia.sourceforge.net/))。

对于 Python 应用，可以使用 IO 监控工具，如 Darshan ([http://www.mcs.anl.gov/research/projects/darshan/](https://link.jianshu.com?t=http://www.mcs.anl.gov/research/projects/darshan/))，和分布式分析工具 MAP ([http://www.allinea.com/products/map](https://link.jianshu.com?t=http://www.allinea.com/products/map))。

## 继续学习

正如我们所看到的，用 Python 中构建小型、中型分布式应用并不是特别困难。一旦分布式系统发展到更大的规模，所需的设计和开发工作量也将以超线性方式增长。

在这种情况下，就需要更牢固的分布式系统理论。在线和离线都有许多可用的资源。许多大学都开设有关这个课程，其中一些是在线免费的。

一个例子就是 ETH 的《分布式计算原理》([http://dcg.ethz.ch/lectures/podc_allstars/index.html](https://link.jianshu.com?t=http://dcg.ethz.ch/lectures/podc_allstars/index.html))，它包含了一些基本原理，包括同步、一致性和最终一致性（包括著名的 CAP 定理）。

最后要说，初学者应该感到鼓舞。用几行代码的一个简单框架，如 Python-RQ，就可以让代码性能大幅提升！

* * *

[序言](https://www.jianshu.com/p/ad10480c89d9)
[第 1 章 并行和分布式计算介绍](https://www.jianshu.com/p/a8ec42f6cb4e)
[第 2 章 异步编程](https://www.jianshu.com/p/02893376bfe8)
[第 3 章 Python 的并行计算](https://www.jianshu.com/p/66f47049cc5a)
[第 4 章 Celery 分布式应用](https://www.jianshu.com/p/ee14ed9e4989)
[第 5 章 云平台部署 Python](https://www.jianshu.com/p/84dde3009782)
[第 6 章 超级计算机群使用 Python](https://www.jianshu.com/p/59471509d3d9)
[第 7 章 测试和调试分布式应用](https://www.jianshu.com/p/c92721ff5f3c)
第 8 章 继续学习

* * *