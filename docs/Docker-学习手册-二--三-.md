# Docker 学习手册（二）（三）

> 原文：[`zh.annas-archive.org/md5/1FDAAC9AD3D7C9F0A89A69D7710EA482`](https://zh.annas-archive.org/md5/1FDAAC9AD3D7C9F0A89A69D7710EA482)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：使用 Docker 进行测试

毫无疑问，测试的特征一直处于软件工程学科的前沿。人们普遍认为，如今软件已经深入并决定性地渗透到我们日常环境中的各种有形物体中，以便拥有大量智能、连接和数字化的资产。此外，随着对分布式和同步软件的高度关注，软件设计、开发、测试和调试、部署以及交付的复杂性不断攀升。正在发现手段和机制来简化和优化软件构建的必要自动化，以及对软件可靠性、弹性和可持续性的认证。Docker 正成为测试各种软件应用的极其灵活的工具。在本章中，我们将讨论如何有效地利用值得注意的 Docker 进展进行软件测试，以及它在加速和增强测试自动化方面的独特优势。

本章讨论以下主题：

+   测试驱动开发（TDD）的简要概述

+   在 Docker 中测试您的代码

+   将 Docker 测试过程集成到 Jenkins 中

新兴情况是，Docker 容器被利用来创建开发和测试环境，这些环境与生产环境完全相同。与虚拟机相比，容器需要更少的开销，虚拟机一直是开发、分级和部署环境的主要环境。让我们从下一代软件的测试驱动开发概述开始，以及 Docker 启发的容器化如何简化 TDD 过程。

# 测试驱动开发的简要概述

软件开发的漫长而艰难的旅程在过去的几十年里经历了许多转折，而其中一种突出的软件工程技术无疑是 TDD。关于 TDD 的更多细节和文档请参见[`agiledata.org/essays/tdd.html`](http://agiledata.org/essays/tdd.html)。

简而言之，测试驱动开发，也被称为 TDD，是一种软件开发实践，其中开发周期始于编写一个会失败的测试用例，然后编写实际的软件使测试通过，并继续重构和重复这个周期，直到软件达到可接受的水平。这个过程在下面的图表中描述了：

![测试驱动开发的简要概述](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_09_01.jpg)

# 在 Docker 中测试您的代码

在本节中，我们将带您进行一次旅程，向您展示如何使用存根进行 TDD，并且 Docker 如何在开发软件中变得方便。为此，我们以一个具有跟踪每个用户访问次数功能的 Web 应用程序用例为例。在这个例子中，我们使用 Python 作为实现语言，`redis`作为键值对数据库来存储用户的点击次数。此外，为展示 Docker 的测试能力，我们将我们的实现限制在只有两个功能：`hit`和`getHit`。

### 注意

注意：本章中的所有示例都使用`python3`作为运行环境。`ubuntu 14.04`安装默认带有`python3`。如果您的系统上没有安装`python3`，请参考相应的手册安装`python3`。

根据 TDD 实践，我们首先为`hit`和`getHit`功能添加单元测试用例，如下面的代码片段所示。在这里，测试文件的名称为`test_hitcount.py`：

```
import unittest
import hitcount

class HitCountTest (unittest.TestCase):
     def testOneHit(self):
         # increase the hit count for user user1
         hitcount.hit("user1")
         # ensure that the hit count for user1 is just 1
         self.assertEqual(b'1', hitcount.getHit("user1"))

if __name__ == '__main__':
    unittest.main()
```

### 注意

此示例也可在[`github.com/thedocker/testing/tree/master/src`](https://github.com/thedocker/testing/tree/master/src)找到。

在第一行中，我们导入了提供运行单元测试并生成详细报告的必要框架和功能的`unittest` Python 模块。在第二行中，我们导入了`hitcount` Python 模块，我们将在其中实现点击计数功能。然后，我们将继续添加测试代码，测试`hitcount`模块的功能。

现在，使用 Python 的单元测试框架运行测试套件，如下所示：

```
$ python3 -m unittest 

```

以下是单元测试框架生成的输出：

```
E 
====================================================================== 
ERROR: test_hitcount (unittest.loader.ModuleImportFailure) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
...OUTPUT TRUNCATED ... 
ImportError: No module named 'hitcount' 

---------------------------------------------------------------------- 
Ran 1 test in 0.001s 

FAILED (errors=1) 

```

如预期的那样，测试失败并显示错误消息`ImportError: No module named 'hitcount'`，因为我们甚至还没有创建文件，因此无法导入`hitcount`模块。

现在，在与`test_hitcount.py`相同的目录中创建一个名为`hitcount.py`的文件：

```
$ touch hitcount.py 

```

继续运行单元测试套件：

```
$ python3 -m unittest 

```

以下是单元测试框架生成的输出：

```
E 
====================================================================== 
ERROR: testOneHit (test_hitcount.HitCountTest) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/home/user/test_hitcount.py", line 10, in testOneHit 
 hitcount.hit("peter") 
AttributeError: 'module' object has no attribute 'hit' 

---------------------------------------------------------------------- 
Ran 1 test in 0.001s 

FAILED (errors=1) 

```

再次，测试套件失败，就像之前一样，但是出现了不同的错误消息`AttributeError: 'module' object has no attribute 'hit'`。我们之所以会得到这个错误，是因为我们还没有实现`hit`函数。

让我们继续在`hitcount.py`中实现`hit`和`getHit`函数，如下所示：

```
import redis
# connect to redis server
r = redis.StrictRedis(host='0.0.0.0', port=6379, db=0)

# increase the hit count for the usr
def hit(usr):
    r.incr(usr)

# get the hit count for the usr
   def getHit(usr):
    return (r.get(usr))
```

### 注意

此示例也可在 GitHub 上找到[`github.com/thedocker/testing/tree/master/src`](https://github.com/thedocker/testing/tree/master/src)。

注意：要继续进行此示例，您必须具有与`pip3`兼容的`python3`版本的软件包安装程序。

以下命令用于安装`pip3`：

```
$ wget -qO- https://bootstrap.pypa.io/get-pip.py | sudo python3 - 

```

在此程序的第一行中，我们导入了`redis`驱动程序，这是`redis`数据库的连接驱动程序。在接下来的一行中，我们将连接到`redis`数据库，然后我们将继续实现`hit`和`getHit`函数。

`redis`驱动程序是一个可选的 Python 模块，因此让我们继续使用 pip 安装程序安装`redis`驱动程序，如下所示：

```
$ sudo pip3 install redis 

```

即使安装了`redis`驱动程序，我们的`unittest`仍然会失败，因为我们尚未运行`redis`数据库服务器。因此，我们可以运行`redis`数据库服务器以成功完成我们的单元测试，或者采用传统的 TDD 方法来模拟`redis`驱动程序。模拟是一种测试方法，其中复杂的行为被预定义或模拟的行为替代。在我们的示例中，为了模拟 redis 驱动程序，我们将利用一个名为 mockredis 的第三方 Python 包。这个模拟包可以在[`github.com/locationlabs/mockredis`](https://github.com/locationlabs/mockredis)找到，`pip`安装程序的名称是`mockredispy`。让我们使用 pip 安装这个模拟：

```
$ sudo pip3 install mockredispy 

```

安装了`mockredispy`，`redis`模拟器之后，让我们重构我们之前编写的测试代码`test_hitcount.py`，以使用`mockredis`模块提供的模拟`redis`功能。这是通过`unittest.mock`模拟框架提供的 patch 方法来实现的，如下面的代码所示：

```
import unittest
from unittest.mock import patch

# Mock for redis
import mockredis
import hitcount

class HitCountTest(unittest.TestCase):

    @patch('hitcount.r',mockredis.mock_strict_redis_client(host='0.0.0.0', port=6379, db=0))
    def testOneHit(self):
        # increase the hit count for user user1
        hitcount.hit("user1")
        # ensure that the hit count for user1 is just 1
        self.assertEqual(b'1', hitcount.getHit("user1"))

if __name__ == '__main__':
    unittest.main()
```

### 注意

此示例也可在 GitHub 上找到[`github.com/thedocker/testing/tree/master/src`](https://github.com/thedocker/testing/tree/master/src)。

现在，再次运行测试套件：

```
$ python3 -m unittest 
. 
---------------------------------------------------------------------- 
Ran 1 test in 0.000s 

OK 

```

最后，正如我们在前面的输出中所看到的，我们通过测试、代码和重构周期成功实现了访客计数功能。

## 在容器内运行测试

在上一节中，我们向您介绍了 TDD 的完整周期，其中我们安装了额外的 Python 包来完成我们的开发。然而，在现实世界中，一个人可能会在多个可能具有冲突库的项目上工作，因此需要对运行时环境进行隔离。在 Docker 技术出现之前，Python 社区通常使用`virtualenv`工具来隔离 Python 运行时环境。Docker 通过打包操作系统、Python 工具链和运行时环境将这种隔离推向了更高级别。这种类型的隔离为开发社区提供了很大的灵活性，可以根据项目需求使用适当的软件版本和库。

以下是将上一节的测试和访客计数实现打包到 Docker 容器中并在容器内执行测试的逐步过程：

1.  创建一个`Dockerfile`来构建一个带有`python3`运行时、`redis`和`mockredispy`包、`test_hitcount.py`测试文件和访客计数实现`hitcount.py`的镜像，最后启动单元测试：

```
#############################################
# Dockerfile to build the unittest container
#############################################

# Base image is python
FROM python:latest

# Author: Dr. Peter
MAINTAINER Dr. Peter <peterindia@gmail.com>

# Install redis driver for python and the redis mock
RUN pip install redis && pip install mockredispy

# Copy the test and source to the Docker image
ADD src/ /src/

# Change the working directory to /src/
WORKDIR /src/

# Make unittest as the default execution
ENTRYPOINT python3 -m unittest
```

### 注意

此示例也可在 GitHub 上找到：[`github.com/thedocker/testing/tree/master/src`](https://github.com/thedocker/testing/tree/master/src)。

1.  现在在我们制作`Dockerfile`的目录中创建一个名为`src`的目录。将`test_hitcount.py`和`hitcount.py`文件移动到新创建的`src`目录中。

1.  使用`docker build`子命令构建`hit_unittest` Docker 镜像：

```
$ sudo docker build -t hit_unittest . 
Sending build context to Docker daemon 11.78 kB 
Sending build context to Docker daemon 
Step 0 : FROM python:latest 
 ---> 32b9d937b993 
Step 1 : MAINTAINER Dr. Peter <peterindia@gmail.com> 
 ---> Using cache 
 ---> bf40ee5f5563 
Step 2 : RUN pip install redis && pip install mockredispy 
 ---> Using cache 
 ---> a55f3bdb62b3 
Step 3 : ADD src/ /src/ 
 ---> 526e13dbf4c3 
Removing intermediate container a6d89cbce053 
Step 4 : WORKDIR /src/ 
 ---> Running in 5c180e180a93 
 ---> 53d3f4e68f6b 
Removing intermediate container 5c180e180a93 
Step 5 : ENTRYPOINT python3 -m unittest 
 ---> Running in 74d81f4fe817 
 ---> 063bfe92eae0 
Removing intermediate container 74d81f4fe817 
Successfully built 063bfe92eae0 

```

1.  现在我们已经成功构建了镜像，让我们使用`docker run`子命令启动我们的容器，并使用单元测试包，如下所示：

```
$ sudo docker run --rm -it hit_unittest . 
---------------------------------------------------------------------- 
Ran 1 test in 0.001s 

OK 

```

显然，单元测试成功运行且无错误，因为我们已经打包了被测试的代码。

在这种方法中，对于每次更改，都会构建 Docker 镜像，然后启动容器来完成测试。

## 使用 Docker 容器作为运行时环境

在上一节中，我们构建了一个 Docker 镜像来执行测试。特别是在 TDD 实践中，单元测试用例和代码经历多次更改。因此，需要反复构建 Docker 镜像，这是一项艰巨的工作。在本节中，我们将看到一种替代方法，即使用运行时环境构建 Docker 容器，将开发目录挂载为卷，并在容器内执行测试。

在 TDD 周期中，如果需要额外的库或更新现有库，那么容器将被更新为所需的库，并更新的容器将被提交为新的镜像。这种方法提供了任何开发人员梦寐以求的隔离和灵活性，因为运行时及其依赖项都存在于容器中，任何配置错误的运行时环境都可以被丢弃，并且可以从先前工作的镜像构建新的运行时环境。这也有助于保持 Docker 主机的清醒状态，避免安装和卸载库。

以下示例是关于如何将 Docker 容器用作非污染但非常强大的运行时环境的逐步说明：

1.  我们开始启动 Python 运行时交互式容器，使用`docker run`子命令：

```
$ sudo docker run -it \ 
 -v /home/peter/src/hitcount:/src \ 
 python:latest /bin/bash 

```

在这个例子中，`/home/peter/src/hitcount` Docker 主机目录被标记为源代码和测试文件的占位符。该目录在容器中被挂载为`/src`。

1.  现在，在 Docker 主机的另一个终端上，将`test_hitcount.py`测试文件和访客计数实现`hitcount.py`复制到`/home/peter/src/hitcount`目录中。

1.  切换到 Python 运行时交互式容器终端，将当前工作目录更改为`/src`，并运行单元测试：

```
root@a8219ac7ed8e:~# cd /src 
root@a8219ac7ed8e:/src# python3 -m unittest 
E 
====================================================================== 
ERROR: test_hitcount (unittest.loader.ModuleImportFailure) 
. . . TRUNCATED OUTPUT . . . 
 File "/src/test_hitcount.py", line 4, in <module> 
 import mockredis 
ImportError: No module named 'mockredis' 

----------------------------------------------------------------- 
Ran 1 test in 0.001s 

FAILED (errors=1) 

```

显然，测试失败是因为找不到`mockredis` Python 库。

1.  继续安装`mockredispy pip`包，因为前一步失败了，无法在运行时环境中找到`mockredis`库：

```
root@a8219ac7ed8e:/src# pip install mockredispy 

```

1.  重新运行 Python 单元测试：

```
root@a8219ac7ed8e:/src# python3 -m unittest 
E 
================================================================= 
ERROR: test_hitcount (unittest.loader.ModuleImportFailure) 
. . . TRUNCATED OUTPUT . . . 
 File "/src/hitcount.py", line 1, in <module> 
 import redis 
ImportError: No module named 'redis' 

Ran 1 test in 0.001s 

FAILED (errors=1) 

```

再次，测试失败，因为尚未安装`redis`驱动程序。

1.  继续使用 pip 安装程序安装`redis`驱动程序，如下所示：

```
root@a8219ac7ed8e:/src# pip install redis 

```

1.  成功安装了`redis`驱动程序后，让我们再次运行单元测试：

```
root@a8219ac7ed8e:/src# python3 -m unittest 
. 
----------------------------------------------------------------- 
Ran 1 test in 0.000s 

OK 

```

显然，这次单元测试通过了，没有警告或错误消息。

1.  现在我们有一个足够好的运行时环境来运行我们的测试用例。最好将这些更改提交到 Docker 镜像以便重用，使用`docker commit`子命令：

```
$ sudo docker commit a8219ac7ed8e python_rediswithmock 
fcf27247ff5bb240a935ec4ba1bddbd8c90cd79cba66e52b21e1b48f984c7db2 

```

从现在开始，我们可以使用`python_rediswithmock`镜像来启动新的容器进行 TDD。

在本节中，我们生动地阐述了如何将 Docker 容器作为测试环境的方法，同时通过在容器内隔离和限制运行时依赖项，保持 Docker 主机的完整性和纯洁性。

# 将 Docker 测试集成到 Jenkins 中

在上一节中，我们阐述了关于软件测试的激动人心的基础，如何利用 Docker 技术进行软件测试，以及在测试阶段容器技术的独特优势。在本节中，我们将介绍为了使用 Docker 准备 Jenkins 环境所需的步骤，然后演示如何扩展 Jenkins 以集成和自动化使用 Docker 进行测试，使用众所周知的点击计数用例。

## 准备 Jenkins 环境

在本节中，我们将带您完成安装`jenkins`、Jenkins 的 GitHub 插件和`git`以及修订控制工具的步骤。这些步骤如下：

1.  我们首先要添加 Jenkins 的受信任的 PGP 公钥：

```
$ wget -q -O - \ 
 https://jenkins-ci.org/debian/jenkins-ci.org.key | \ 
 sudo apt-key add - 

```

在这里，我们使用`wget`来下载 PGP 公钥，然后使用 apt-key 工具将其添加到受信任密钥列表中。由于 Ubuntu 和 Debian 共享相同的软件打包，Jenkins 为两者提供了一个通用的软件包。

1.  将 Debian 软件包位置添加到`apt`软件包源列表中，如下所示：

```
$ sudo sh -c \ 
 'echo deb http://pkg.jenkins-ci.org/debian binary/ > \ 
 /etc/apt/sources.list.d/jenkins.list' 

```

1.  添加了软件包源后，继续运行`apt-get`命令更新选项，以重新同步来自源的软件包索引：

```
$ sudo apt-get update 

```

1.  现在，使用`apt-get`命令安装选项来安装`jenkins`，如下所示：

```
$ sudo apt-get install jenkins 

```

1.  最后，使用`service`命令激活`jenkins`服务：

```
$ sudo service jenkins start 

```

1.  `jenkins`服务可以通过任何 Web 浏览器访问，只需指定安装了 Jenkins 的系统的 IP 地址（`10.1.1.13`）。Jenkins 的默认端口号是`8080`。以下截图是**Jenkins**的入口页面或**仪表板**：![准备 Jenkins 环境](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_09_02.jpg)

1.  在本例中，我们将使用 GitHub 作为源代码存储库。Jenkins 默认不支持 GitHub，因此需要安装 GitHub 插件。在安装过程中，有时 Jenkins 不会填充插件可用性列表，因此您必须强制它下载可用插件列表。您可以通过执行以下步骤来实现：

1.  在屏幕左侧选择**管理 Jenkins**，这将带我们到**管理 Jenkins**页面，如下面的屏幕截图所示：![准备 Jenkins 环境](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_09_03.jpg)

1.  在**管理 Jenkins**页面上，选择**管理插件**，这将带我们到**插件管理器**页面，如下面的屏幕截图所示：![准备 Jenkins 环境](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_09_04.jpg)

1.  在**插件管理器**页面上，选择**高级**选项卡，转到页面底部，您将在页面右下角找到**立即检查**按钮。单击**立即检查**按钮开始插件更新。或者，您可以通过导航到`http://<jenkins-server>:8080/pluginManager/advanced`直接转到**高级**页面上的**立即检查**按钮，其中`<jenkins-server>`是安装 Jenkins 的系统的 IP 地址。

### 注意

注意：如果 Jenkins 没有更新可用的插件列表，很可能是镜像站点的问题，因此使用有效的镜像 URL 修改**更新站点**字段。

1.  更新了可用插件列表后，让我们继续安装 GitHub 插件，如下面的子步骤所示：

1.  在**插件管理器**页面中选择**可用**选项卡，其中将列出所有可用的插件。

1.  输入`GitHub 插件`作为过滤器，这将只列出 GitHub 插件，如下面的屏幕截图所示：![准备 Jenkins 环境](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_09_05.jpg)

1.  选择复选框，然后单击**立即下载并在重启后安装**。您将进入一个屏幕，显示插件安装的进度：![准备 Jenkins 环境](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_09_06.jpg)

1.  在所有插件成功下载后，继续使用`http://< jenkins-server >:8080/restart`重新启动 Jenkins，其中`<jenkins-server>`是安装 Jenkins 的系统的 IP 地址。

1.  确保安装了`git`软件包，否则使用`apt-get`命令安装`git`软件包：

```
$ sudo apt-get install git 

```

1.  到目前为止，我们一直在使用`sudo`命令运行 Docker 客户端，但不幸的是，我们无法在 Jenkins 中调用`sudo`，因为有时它会提示输入密码。为了克服`sudo`密码提示问题，我们可以利用 Docker 组，任何属于 Docker 组的用户都可以在不使用`sudo`命令的情况下调用 Docker 客户端。Jenkins 安装总是设置一个名为`jenkins`的用户和组，并使用该用户和组运行 Jenkins 服务器。因此，我们只需要将`jenkins`用户添加到 Docker 组，即可使 Docker 客户端在不使用`sudo`命令的情况下工作：

```
$ sudo gpasswd -a jenkins docker 
Adding user jenkins to group docker 

```

1.  重新启动`jenkins`服务，以使组更改生效，使用以下命令：

```
$ sudo service jenkins restart 
 * Restarting Jenkins Continuous Integration Server jenkins              [ OK ] 

```

我们已经设置了一个 Jenkins 环境，现在能够自动从[`github.com`](http://github.com)存储库中拉取最新的源代码，将其打包为 Docker 镜像，并执行规定的测试场景。

## 自动化 Docker 测试流程

在本节中，我们将探讨如何使用 Jenkins 和 Docker 自动化测试。如前所述，我们将使用 GitHub 作为我们的存储库。我们已经将我们之前示例的`Dockerfile`、`test_hitcount.py`和`hitcount.py`文件上传到 GitHub 上的[`github.com/thedocker/testing`](https://github.com/thedocker/testing)，我们将在接下来的示例中使用它们。但是，我们强烈建议您在[`github.com`](http://github.com)上设置自己的存储库，使用您可以在[`github.com/thedocker/testing`](https://github.com/thedocker/testing)找到的分支选项，并在接下来的示例中替换此地址。

以下是自动化 Docker 测试的详细步骤：

1.  配置 Jenkins 在 GitHub 存储库中的文件修改时触发构建，如下面的子步骤所示：

1.  再次连接到 Jenkins 服务器。

1.  选择**新项目**或**创建新作业**：![自动化 Docker 测试流程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_09_07.jpg)

1.  在下一个截图中，为项目命名（例如`Docker-Testing`），并选择**自由风格项目**单选按钮：![自动化 Docker 测试流程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_09_08.jpg)

1.  在下一个截图中，在**源代码管理**下选择**Git**单选按钮，并在**存储库 URL**文本字段中指定 GitHub 存储库 URL：![自动化 Docker 测试流程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_09_09.jpg)

1.  在**构建触发器**下选择**轮询 SCM**，以便每`15`分钟间隔进行 GitHub 轮询。在**计划**文本框中输入以下代码`H/15 * * * *`，如下面的屏幕截图所示。为了测试目的，您可以缩短轮询间隔：![自动化 Docker 测试流程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_09_10.jpg)

1.  向下滚动屏幕，然后在**构建**下选择**添加构建步骤**按钮。在下拉列表中，选择**执行 shell**并输入以下文本，如下面的屏幕截图所示：![自动化 Docker 测试流程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_09_11.jpg)

1.  最后，通过点击**保存**按钮保存配置。

1.  返回 Jenkins 仪表板，您可以在仪表板上找到您的测试：![自动化 Docker 测试流程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_09_12.jpg)

1.  您可以等待 Jenkins 计划启动构建，也可以点击屏幕右侧的时钟图标立即启动构建。一旦构建完成，仪表板将更新构建状态为成功或失败，并显示构建编号：![自动化 Docker 测试流程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_09_13.jpg)

1.  如果将鼠标悬停在构建编号附近，将会出现一个下拉按钮，其中包括**更改**、**控制台输出**等选项，如下面的屏幕截图所示：![自动化 Docker 测试流程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_09_14.jpg)

1.  **控制台输出**选项将显示构建的详细信息，如下所示：

```
Started by user anonymous 
Building in workspace /var/lib/jenkins/jobs/Docker-Testing/workspace 
Cloning the remote Git repository 
Cloning repository https://github.com/thedocker/testing/ 
. . . OUTPUT TRUNCATED . . . 
+ docker build -t docker_testing_using_jenkins . 
Sending build context to Docker daemon 121.9 kB 

Sending build context to Docker daemon 
Step 0 : FROM python:latest 
. . . OUTPUT TRUNCATED . . . 
Successfully built ad4be4b451e6 
+ docker run --rm docker_testing_using_jenkins 
. 
---------------------------------------------------------------------- 
Ran 1 test in 0.000s 

OK 
Finished: SUCCESS 

```

1.  显然，测试失败是因为错误的模块名**error_hitcount**，这是我们故意引入的。现在，让我们故意在**test_hitcount.py**中引入一个错误，观察对 Jenkins 构建的影响。由于我们已经配置了 Jenkins，它会忠实地轮询 GitHub 并启动构建：![自动化 Docker 测试流程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_09_15.jpg)

显然，构建失败了，正如我们预期的那样。

1.  最后一步，打开失败构建的**控制台输出**：

```
Started by an SCM change 
Building in workspace /var/lib/jenkins/jobs/Docker-Testing/workspace 
. . . OUTPUT TRUNCATED . . . 
ImportError: No module named 'error_hitcount' 

---------------------------------------------------------------------- 
Ran 1 test in 0.001s 

FAILED (errors=1) 
Build step 'Execute shell' marked build as failure 
Finished: FAILURE 

```

显然，测试失败是因为我们故意引入的错误模块名`error_hitcount`。

酷，不是吗？我们使用 Jenkins 和 Docker 自动化了我们的测试。此外，我们能够体验使用 Jenkins 和 Docker 进行测试自动化的力量。在大型项目中，Jenkins 和 Docker 可以结合在一起，自动化完成完整的单元测试需求，从而自动捕捉任何开发人员引入的缺陷和不足。

# 总结

集装箱化的潜在好处正在软件工程的广度和长度上被发现。以前，测试复杂的软件系统涉及许多昂贵且难以管理的服务器模块和集群。考虑到涉及的成本和复杂性，大多数软件测试是通过模拟程序和存根来完成的。随着 Docker 技术的成熟，所有这些都将永远结束。Docker 的开放性和灵活性使其能够与其他技术无缝地配合，从而大大减少测试时间和复杂性。

长期以来，测试软件系统的主要方法包括模拟、依赖注入等。通常，这些方法需要在代码中创建许多复杂的抽象。目前的做法是针对应用程序开发和运行测试用例实际上是在存根上进行，而不是在完整的应用程序上进行。也就是说，通过容器化工作流，很可能对具有所有依赖关系的真实应用程序容器进行测试。因此，Docker 范式的贡献，特别是对测试现象和阶段的贡献，近来正在被认真阐述和记录。确切地说，软件工程领域正在朝着 Docker 空间的所有创新迈进，迎来智能和更加晴朗的日子。

在本章中，我们清楚地阐述和解释了使用受 Docker 启发的容器化范式的集成应用程序的强大测试框架。对于敏捷世界来说，经过验证的 TDD 方法被坚持为高效的软件构建和维护方法。本章利用 Python 单元测试框架来说明 TDD 方法是软件工程的开创性工具。单元测试框架被调整为高效、优雅的容器化，并且 Docker 容器与 Jenkins 无缝集成，后者是持续交付的现代部署工具，并且是敏捷编程世界的重要组成部分，正如本章所描述的。Docker 容器源代码在进入 GitHub 代码存储库之前经过预检。Jenkins 工具从 GitHub 下载代码并在容器内运行测试。在下一章中，我们将深入探讨并描述容器技术和各种调试工具和技术的理论方面。


# 第十章：调试容器

调试一直是软件工程领域的艺术组成部分。各种软件构建模块个别以及集体都需要经过软件开发和测试专业人员深入而决定性的调查流程，以确保最终软件应用程序的安全性和安全性。由于 Docker 容器被认为是下一代关键运行时环境，用于使命关键的软件工作负载，因此对于容器、制作者和作曲家来说，进行容器的系统和明智的验证和验证是相关和至关重要的。

本章专门为技术人员撰写，旨在为他们提供所有正确和相关的信息，以便精心调试在容器内运行的应用程序和容器本身。在本章中，我们将从理论角度探讨作为容器运行的进程的进程隔离方面。Docker 容器在主机上以用户级进程运行，通常具有与操作系统提供的隔离级别相同的隔离级别。随着 Docker 1.5 的发布，许多调试工具可供使用，可以有效地用于调试应用程序。我们还将介绍主要的 Docker 调试工具，如 Docker `exec`、`stats`、`ps`、`top`、`events`和`logs`。最后，我们将介绍`nsenter`工具，以便登录到容器而无需运行**Secure Shell**（**SSH**）守护程序。

本章将涵盖的主题列表如下：

+   Docker 容器的进程级隔离

+   调试容器化应用程序

+   安装和使用`nsenter`

# Docker 容器的进程级隔离

在虚拟化范式中，hypervisor 模拟计算资源并提供一个虚拟化环境，称为 VM，用于在其上安装操作系统和应用程序。而在容器范式的情况下，单个系统（裸机或虚拟机）被有效地分区，以便同时运行多个服务而互不干扰。为了防止它们相互干扰，这些服务必须相互隔离，以防止它们占用对方的资源或产生依赖冲突（也称为依赖地狱）。Docker 容器技术基本上通过利用 Linux 内核构造（如命名空间和 cgroups，特别是命名空间）实现了进程级别的隔离。Linux 内核提供了以下五个强大的命名空间，用于将全局系统资源相互隔离。这些是用于隔离进程间通信资源的**进程间通信**（**IPC**）命名空间：

+   网络命名空间用于隔离网络资源，如网络设备、网络堆栈、端口号等

+   挂载命名空间隔离文件系统挂载点

+   PID 命名空间隔离进程标识号

+   用户命名空间用于隔离用户 ID 和组 ID

+   UTS 命名空间用于隔离主机名和 NIS 域名

当我们必须调试容器内运行的服务时，这些命名空间会增加额外的复杂性，我们将在下一章节中更详细地学习。

在本节中，我们将讨论 Docker 引擎如何通过一系列实际示例利用 Linux 命名空间提供进程隔离，其中之一列在此处：

1.  首先，通过使用`docker run`子命令以交互模式启动一个`ubuntu`容器，如下所示：

```
$ sudo docker run -it --rm ubuntu /bin/bash
root@93f5d72c2f21:/#

```

1.  继续在不同的终端中使用`docker inspect`子命令查找前面容器`93f5d72c2f21`的进程 ID：

```
$ sudo docker inspect \
 --format "{{ .State.Pid }}" 93f5d72c2f21
2543

```

显然，从前面的输出中，容器`93f5d72c2f21`的进程 ID 是`2543`。

1.  得到容器的进程 ID 后，让我们继续看看与容器关联的进程在 Docker 主机中的情况，使用`ps`命令：

```
$ ps -fp 2543
UID        PID  PPID  C STIME TTY          TIME CMD
root      2543  6810  0 13:46 pts/7    00:00:00 /bin/bash

```

很神奇，不是吗？我们启动了一个带有`/bin/bash`作为其命令的容器，我们在 Docker 主机中也有`/bin/bash`进程。

1.  让我们再进一步，使用`cat`命令在 Docker 主机中显示`/proc/2543/environ`文件：

```
$ sudo cat -v /proc/2543/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin^@HOSTNAME=93f5d72c2f21^@TERM=xterm^@HOME=/root^@$

```

在前面的输出中，`HOSTNAME=93f5d72c2f21`从其他环境变量中脱颖而出，因为`93f5d72c2f21`是容器的 ID，也是我们之前启动的容器的主机名。

1.  现在，让我们回到终端，我们正在运行交互式容器`93f5d72c2f21`，并使用`ps`命令列出该容器内运行的所有进程：

```
root@93f5d72c2f21:/# ps -ef
UID    PID PPID C STIME TTY     TIME CMD
root     1   0 0 18:46 ?    00:00:00 /bin/bash
root    15   1 0 19:30 ?    00:00:00 ps -ef

```

令人惊讶，不是吗？在容器内，`bin/bash`进程的进程 ID 为`1`，而在容器外，即 Docker 主机中，进程 ID 为`2543`。此外，**父进程 ID**（**PPID**）为`0`（零）。

在 Linux 世界中，每个系统只有一个 PID 为 1 且 PPID 为 0 的根进程，这是该系统完整进程树的根。Docker 框架巧妙地利用 Linux PID 命名空间来生成一个全新的进程树；因此，容器内运行的进程无法访问 Docker 主机的父进程。然而，Docker 主机可以完全查看 Docker 引擎生成的子 PID 命名空间。

网络命名空间确保所有容器在主机上拥有独立的网络接口。此外，每个容器都有自己的回环接口。每个容器使用自己的网络接口与外部世界通信。您会惊讶地知道，该命名空间不仅有自己的路由表，还有自己的 iptables、链和规则。本章的作者在他的主机上运行了三个容器。在这里，自然期望每个容器有三个网络接口。让我们运行`docker ps`命令：

```
$ sudo docker ps
41668be6e513        docker-apache2:latest   "/bin/sh -c 'apachec
069e73d4f63c        nginx:latest            "nginx -g '
871da6a6cf43        ubuntu:14.04            "/bin/bash"

```

所以这里有三个接口，每个容器一个。让我们通过运行以下命令来获取它们的详细信息：

```
$ ifconfig
veth2d99bd3 Link encap:Ethernet  HWaddr 42:b2:cc:a5:d8:f3
 inet6 addr: fe80::40b2:ccff:fea5:d8f3/64 Scope:Link
 UP BROADCAST RUNNING  MTU:9001  Metric:1
veth422c684 Link encap:Ethernet  HWaddr 02:84:ab:68:42:bf
 inet6 addr: fe80::84:abff:fe68:42bf/64 Scope:Link
 UP BROADCAST RUNNING  MTU:9001  Metric:1
vethc359aec Link encap:Ethernet  HWaddr 06:be:35:47:0a:c4
 inet6 addr: fe80::4be:35ff:fe47:ac4/64 Scope:Link
 UP BROADCAST RUNNING  MTU:9001  Metric:1

```

挂载命名空间确保挂载的文件系统只能被同一命名空间内的进程访问。容器 A 无法看到容器 B 的挂载点。如果您想要检查您的挂载点，您需要首先使用`exec`命令（在下一节中描述），然后转到`/proc/mounts`：

```
root@871da6a6cf43:/# cat /proc/mounts
rootfs / rootfs rw 0 0/dev/mapper/docker-202:1-149807 871da6a6cf4320f625d5c96cc24f657b7b231fe89774e09fc771b3684bf405fb / ext4 rw,relatime,discard,stripe=16,data=ordered 0 0 proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0

```

让我们运行一个带有挂载点的容器，作为**存储区域网络**（**SAN**）或**网络附加存储**（**NAS**）设备，并通过登录到容器来访问它。这是给您的一个练习。我在工作中的一个项目中实现了这一点。

这些容器/进程可以被隔离到其他命名空间中，包括用户、IPC 和 UTS。用户命名空间允许您在命名空间内拥有根权限，而不会将该特定访问权限授予命名空间外的进程。使用 IPC 命名空间隔离进程会为其提供自己的进程间通信资源，例如 System V IPC 和 POSIX 消息。UTS 命名空间隔离系统的*主机名*。

Docker 使用`clone`系统调用实现了这个命名空间。在主机上，您可以检查 Docker 为容器创建的命名空间（带有`pid 3728`）：

```
$ sudo ls /proc/3728/ns/
ipc  mnt  net  pid  user  uts

```

在大多数 Docker 的工业部署中，人们广泛使用经过修补的 Linux 内核来满足特定需求。此外，一些公司已经修补了他们的内核，以将任意进程附加到现有的命名空间，因为他们认为这是部署、控制和编排容器最方便和可靠的方式。

## 控制组

Linux 容器依赖于控制组（cgroups），它们不仅跟踪进程组，还公开 CPU、内存和块 I/O 使用情况的指标。您还可以访问这些指标，并获取网络使用情况指标。控制组是 Linux 容器的另一个重要组件。控制组已经存在一段时间，并最初是在 Linux 内核代码 2.6.24 中合并的。它们确保每个 Docker 容器都将获得固定数量的内存、CPU 和磁盘 I/O，以便任何容器都无法在任何情况下使主机机器崩溃。控制组不会阻止访问一个容器，但它们对抵御一些**拒绝服务**（**DoS**）攻击至关重要。

在 Ubuntu 14.04 上，`cgroup`实现在`/sys/fs/cgroup`路径中。Docker 的内存信息可在`/sys/fs/cgroup/memory/docker/`路径下找到。

类似地，CPU 详细信息可以在`/sys/fs/cgroup/cpu/docker/`路径中找到。

让我们找出容器（`41668be6e513e845150abd2dd95dd574591912a7fda947f6744a0bfdb5cd9a85`）可以消耗的最大内存限制。

为此，您可以转到`cgroup`内存路径，并检查`memory.max.usage`文件：

```
/sys/fs/cgroup/memory/docker/41668be6e513e845150abd2dd95dd574591912a7fda947f6744a0bfdb5cd9a85
$ cat memory.max_usage_in_bytes
13824000

```

因此，默认情况下，任何容器只能使用最多 13.18 MB 的内存。

类似地，CPU 参数可以在以下路径中找到：

```
/sys/fs/cgroup/cpu/docker/41668be6e513e845150abd2dd95dd574591912a7fda947f6744a0bfdb5cd9a85

```

传统上，Docker 在容器内部只运行一个进程。因此，通常情况下，您会看到人们为 PHP、nginx 和 MySQL 分别运行三个容器。然而，这是一个谬论。您可以在单个容器内运行所有三个进程。

Docker 在不具备 root 权限的情况下，隔离了容器中运行的应用程序与底层主机的许多方面。然而，这种分离并不像虚拟机那样强大，虚拟机在 hypervisor 之上独立运行独立的操作系统实例，而不与底层操作系统共享内核。在同一主机上以容器化应用程序的形式运行具有不同安全配置文件的应用程序并不是一个好主意，但将不同的应用程序封装到容器化应用程序中具有安全性的好处，否则这些应用程序将直接在同一主机上运行。

# 调试容器化应用程序

计算机程序（软件）有时无法按预期行为。这是由于错误的代码或由于开发、测试和部署系统之间的环境变化。Docker 容器技术通过将所有应用程序依赖项容器化，尽可能消除开发、测试和部署之间的环境问题。尽管如此，由于错误的代码或内核行为的变化，仍可能出现异常，需要进行调试。调试是软件工程世界中最复杂的过程之一，在容器范式中变得更加复杂，因为涉及到隔离技术。在本节中，我们将学习使用 Docker 本机工具以及外部提供的工具来调试容器化应用程序的一些技巧和窍门。

最初，Docker 社区中的许多人单独开发了自己的调试工具，但后来 Docker 开始支持本机工具，如`exec`、`top`、`logs`、`events`等。在本节中，我们将深入探讨以下 Docker 工具：

+   `exec`

+   `ps`

+   `top`

+   `stats`

+   `events`

+   `logs`

## Docker exec 命令

`docker exec`命令为部署自己的 Web 服务器或在后台运行的其他应用程序的用户提供了非常需要的帮助。现在，不需要登录到容器中运行 SSH 守护程序。

首先，运行`docker ps -a`命令以获取容器 ID：

```
$ sudo docker ps -a
b34019e5b5ee        nsinit:latest             "make local"
a245253db38b        training/webapp:latest    "python app.py"

```

然后，运行`docker exec`命令以登录到容器中。

```
$ sudo docker exec -it a245253db38b bash
root@a245253db38b:/opt/webapp#

```

需要注意的是，`docker exec` 命令只能访问正在运行的容器，因此如果容器停止运行，则需要重新启动已停止的容器才能继续。`docker exec` 命令使用 Docker API 和 CLI 在目标容器中生成一个新进程。因此，如果你在目标容器内运行 `pe -aef` 命令，结果如下：

```
# ps -aef
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 Mar22 ?        00:00:53 python app.py
root        45     0  0 18:11 ?        00:00:00 bash
root        53    45  0 18:11 ?        00:00:00 ps -aef

```

这里，`python app.y` 是已在目标容器中运行的应用程序，`docker exec` 命令已在容器内添加了 `bash` 进程。如果你运行 `kill -9 pid(45)`，你将自动退出容器。

如果你是一名热情的开发者，并且想增强 `exec` 功能，你可以参考 [`github.com/chris-rock/docker-exec`](https://github.com/chris-rock/docker-exec)。

建议仅将 `docker exec` 命令用于监视和诊断目的，我个人认为一个容器一个进程的概念是最佳实践之一。

## Docker ps 命令

`docker ps` 命令可在容器内部使用，用于查看进程的状态。这类似于 Linux 环境中的标准 `ps` 命令，*不*是我们在 Docker 主机上运行的 `docker ps` 命令。

此命令在 Docker 容器内运行：

```
root@5562f2f29417:/# ps –s
 UID   PID   PENDING   BLOCKED   IGNORED    CAUGHT STAT TTY        TIME COMMAND
 0     1  00000000  00010000  00380004  4b817efb Ss   ?          0:00 /bin/bash
 0    33  00000000  00000000  00000000  73d3fef9 R+   ?          0:00 ps -s
root@5562f2f29417:/# ps -l
F S   UID   PID  PPID  C PRI  NI ADDR SZ WCHAN  TTY          TIME CMD
4 S     0     1     0  0  80   0 -  4541 wait   ?        00:00:00 bash
0 R     0    34     1  0  80   0 -  1783 -      ?        00:00:00 ps
root@5562f2f29417:/# ps -t
 PID TTY      STAT   TIME COMMAND
 1 ?        Ss     0:00 /bin/bash
 35 ?        R+     0:00 ps -t
root@5562f2f29417:/# ps -m
 PID TTY          TIME CMD
 1 ?        00:00:00 bash
 - -        00:00:00 -
 36 ?        00:00:00 ps
 - -        00:00:00 -
root@5562f2f29417:/# ps -a
 PID TTY          TIME CMD
 37 ?        00:00:00 ps

```

使用 `ps --help <simple|list|output|threads|misc|all>` 或 `ps --help <s|l|o|t|m|a>` 获取额外的帮助文本。

## Docker top 命令

你可以使用以下命令从 Docker 主机机器上运行 `top` 命令：

```
docker top [OPTIONS] CONTAINER [ps OPTIONS]

```

这将列出容器的运行进程，而无需登录到容器中，如下所示：

```
$ sudo docker top  a245253db38b
UID                 PID                 PPID                C
STIME               TTY                 TIME                CMD
root                5232                3585                0
Mar22               ?                   00:00:53            python app.py
$ sudo docker top  a245253db38b  -aef
UID                 PID                 PPID                C
STIME               TTY                 TIME                CMD
root                5232                3585                0
Mar22               ?                   00:00:53            python app.py

```

Docker `top` 命令提供有关 CPU、内存和交换使用情况的信息，如果你在 Docker 容器内运行它：

```
root@a245253db38b:/opt/webapp# top
top - 19:35:03 up 25 days, 15:50,  0 users,  load average: 0.00, 0.01, 0.05
Tasks:   3 total,   1 running,   2 sleeping,   0 stopped,   0 zombie
Cpu(s):  0.0%us,  0.0%sy,  0.0%ni, 99.9%id,  0.0%wa,  0.0%hi,  0.0%si,  0.0%st
Mem:   1016292k total,   789812k used,   226480k free,    83280k buffers
Swap:        0k total,        0k used,        0k free,   521972k cached
 PID USER      PR  NI  VIRT  RES  SHR S %CPU %MEM    TIME+  COMMAND
 1 root      20   0 44780  10m 1280 S  0.0  1.1   0:53.69 python
 62 root      20   0 18040 1944 1492 S  0.0  0.2   0:00.01 bash
 77 root      20   0 17208 1164  948 R  0.0  0.1   0:00.00 top

```

如果在容器内运行 `top` 命令时出现 `error - TERM environment variable not set` 错误，请执行以下步骤解决：

运行 `echo $TERM` 命令。你会得到 `dumb` 作为结果。然后运行以下命令：

```
$ export TERM=dumb

```

这将解决错误。

## Docker stats 命令

Docker `stats` 命令使你能够从 Docker 主机机器上查看容器的内存、CPU 和网络使用情况，如下所示：

```
$ sudo docker stats a245253db38b
CONTAINER           CPU %               MEM USAGE/LIMIT       MEM %
 NET I/O
a245253db38b        0.02%               16.37 MiB/992.5 MiB   1.65%
 3.818 KiB/2.43 KiB

```

你也可以运行 `stats` 命令来查看多个容器的使用情况：

```
$ sudo docker stats a245253db38b f71b26cee2f1

```

在最新的 Docker 1.5 版本中，Docker 为您提供了对容器统计信息的*只读*访问权限。这将简化容器的 CPU、内存、网络 IO 和块 IO。这有助于您选择资源限制，以及进行性能分析。Docker stats 实用程序仅为正在运行的容器提供这些资源使用详细信息。您可以使用端点 API 在[`docs.docker.com/reference/api/docker_remote_api_v1.17/#inspect-a-container`](https://docs.docker.com/reference/api/docker_remote_api_v1.17/#inspect-a-container)获取详细信息。

Docker stats 最初是从 Michael Crosby 的代码贡献中获取的，可以在[`github.com/crosbymichael`](https://github.com/crosbymichael)上访问。

## Docker 事件命令

Docker 容器将报告以下实时事件：`create`、`destroy`、`die`、`export`、`kill`、`omm`、`pause`、`restart`、`start`、`stop`和`unpause`。以下是一些示例，说明如何使用这些命令：

```
$ sudo docker pause  a245253db38b
a245253db38b
$ sudo docker ps -a
a245253db38b        training/webapp:latest    "python app.py"        4 days ago         Up 4 days (Paused)       0.0.0.0:5000->5000/tcp   sad_sammet
$ sudo docker unpause  a245253db38b
a245253db38b
$ sudo docker ps -a
a245253db38b        training/webapp:latest    "python app.py"        4 days ago    Up 4 days        0.0.0.0:5000->5000/tcp   sad_sammet

```

Docker 镜像还将报告取消标记和删除事件。

使用多个过滤器将被视为`AND`操作；例如，`--filter container= a245253db38b --filter event=start`将显示容器`a245253db38b`的事件和事件类型为 start 的事件。

目前，支持的过滤器有 container、event 和 image。

## Docker 日志命令

此命令获取容器的日志，而无需登录到容器中。它批量检索执行时存在的日志。这些日志是`STDOUT`和`STDERR`的输出。通用用法显示在`docker logs [OPTIONS] CONTAINER`中。

`–follow`选项将继续提供输出直到结束，`-t`将提供时间戳，`--tail= <number of lines>`将显示容器日志消息的行数：

```
$ sudo docker logs a245253db38b
 * Running on http://0.0.0.0:5000/
172.17.42.1 - - [22/Mar/2015 06:04:23] "GET / HTTP/1.1" 200 -
172.17.42.1 - - [24/Mar/2015 13:43:32] "GET / HTTP/1.1" 200 -
$
$ sudo docker logs -t a245253db38b
2015-03-22T05:03:16.866547111Z  * Running on http://0.0.0.0:5000/
2015-03-22T06:04:23.349691099Z 172.17.42.1 - - [22/Mar/2015 06:04:23] "GET / HTTP/1.1" 200 -
2015-03-24T13:43:32.754295010Z 172.17.42.1 - - [24/Mar/2015 13:43:32] "GET / HTTP/1.1" 200 -

```

我们还在第二章和第六章中使用了`docker logs`实用程序，以查看我们的容器的日志。

# 安装和使用 nsenter

在任何商业 Docker 部署中，您可能会使用各种容器，如 Web 应用程序、数据库等。但是，您需要访问这些容器以修改配置或调试/排除故障。这个问题的一个简单解决方案是在每个容器中运行一个 SSH 服务器。这不是一个访问机器的好方法，因为会带来意想不到的安全影响。然而，如果您在 IBM、戴尔、惠普等世界一流的 IT 公司工作，您的安全合规人员绝不会允许您使用 SSH 连接到机器。

所以，这就是解决方案。`nsenter`工具为您提供了登录到容器的访问权限。请注意，`nsenter`将首先作为 Docker 容器部署。使用部署的`nsenter`，您可以访问您的容器。按照以下步骤进行：

1.  让我们运行一个简单的 Web 应用程序作为一个容器：

```
$ sudo docker run -d -p 5000:5000 training/webapp python app.py
------------------------
a245253db38b626b8ac4a05575aa704374d0a3c25a392e0f4f562df92bb98d74

```

1.  测试 Web 容器：

```
$ curl localhost:5000
Hello world!

```

1.  安装`nsenter`并将其作为一个容器运行：

```
$ sudo docker run -v /usr/local/bin:/target jpetazzo/nsenter

```

现在，`nsenter`作为一个容器正在运行。

1.  使用 nsenter 容器登录到我们在步骤 1 中创建的容器（`a245253db38b`）。

运行以下命令以获取`PID`值：

```
$ PID=$(sudo docker inspect --format {{.State.Pid}} a245253db38b)

```

1.  现在，访问 Web 容器：

```
$ sudo nsenter --target $PID --mount --uts --ipc --net --pid
root@a245253db38b:/#

```

然后，您可以登录并开始访问您的容器。以这种方式访问您的容器将使您的安全和合规专业人员感到满意，他们会感到放松。

自 Docker 1.3 以来，Docker exec 是一个支持的工具，用于登录到容器中。

`nsenter`工具不进入 cgroups，因此规避了资源限制。这样做的潜在好处是调试和外部审计，但对于远程访问，`docker exec`是当前推荐的方法。

`nsenter`工具仅在 Intel 64 位平台上进行测试。您不能在要访问的容器内运行`nsenter`，因此只能在主机上运行`nsenter`。通过在主机上运行`nsenter`，您可以访问该主机上的所有容器。此外，您不能使用在特定主机 A 上运行的`nsenter`来访问主机 B 上的容器。

# 总结

Docker 利用 Linux 容器技术（如 LXC 和现在的`libcontainer`）为您提供容器的隔离。Libcontainer 是 Docker 在 Go 编程语言中的自己的实现，用于访问内核命名空间和控制组。这个命名空间用于进程级别的隔离，而控制组用于限制运行容器的资源使用。由于容器作为独立进程直接在 Linux 内核上运行，因此**通常可用**（**GA**）的调试工具不足以在容器内部工作以调试容器化的进程。Docker 现在为您提供了丰富的工具集，以有效地调试容器，以及容器内部的进程。Docker `exec` 将允许您登录到容器，而无需在容器中运行 SSH 守护程序。

Docker `stats` 提供有关容器内存和 CPU 使用情况的信息。Docker `events` 报告事件，比如创建、销毁、杀死等。同样，Docker `logs` 从容器中获取日志，而无需登录到容器中。

调试是可以用来制定其他安全漏洞和漏洞的基础。因此，下一章将详细阐述 Docker 容器的可能安全威胁，以及如何通过各种安全方法、自动化工具、最佳实践、关键指南和指标来抑制这些威胁。


# 第十一章：保护 Docker 容器

到目前为止，我们在本书中已经谈了很多关于快速兴起的 Docker 技术。如果不详细阐述 Docker 特定的安全问题和解决方法，这本书就不会有一个完美的结局。因此，本章是专门为了向您详细解释 Docker 启发的容器的不断增长的安全挑战而精心制作和纳入本书的。我们还希望更多地阐明，通过一系列开创性技术、高质量算法、启用工具和最佳实践，如何解决悬而未决的安全问题。

在本章中，我们将详细讨论以下主题：

+   Docker 容器安全吗？

+   容器的安全特性

+   新兴的安全方法

+   容器安全的最佳实践

确保任何 IT 系统和业务服务的不可破坏和无法渗透的安全性，是 IT 领域数十年来的主要需求和主要挑战之一。聪明的头脑可以识别和利用在系统构思和具体化阶段被漫不经心和无意识引入的各种安全漏洞和缺陷。这个漏洞最终在 IT 服务交付过程中带来无数的违规和破坏。另一方面，安全专家和工程师尝试各种技巧和技术，以阻止黑客的邪恶行程。然而，到目前为止，这并不是一场彻底的胜利。在各个地方，都有一些来自未知来源的引人注目的入侵，导致高度令人不安的 IT 减速，有时甚至崩溃。因此，全球各个组织和政府正在大力投资于安全研究工作，以完全消灭所有与安全和安全相关的事件和事故。

为了最大程度地减少安全威胁和漏洞对 IT 系统造成的不可挽回和难以描述的后果，有大量专门的安全产品供应商和托管安全服务提供商。确切地说，对于任何现有和新兴的技术来说，安全性都是最关键和最重要的方面，不能轻视。

Docker 是 IT 领域快速成熟的容器化技术，最近，安全方面被赋予了首要重要性，考虑到 Docker 容器的采用和适应性不断上升。此外，一系列特定目的和通用容器正在进入生产环境，因此安全难题具有特殊意义。毫无疑问，未来 Docker 平台发布将会有很多关注安全参数的内容，因为这个开源 Docker 倡议的市场份额和思想份额一直在上升。

# Docker 容器安全吗？

随着 Docker 容器在生产 IT 环境中受到精心评估，不同领域对容器的安全漏洞提出了质疑。因此，有人呼吁研究人员和安全专家大力加强容器安全，以提高服务提供商和消费者的信心。在本节中，我们将描述 Docker 容器在安全方面的立场。由于容器正在与虚拟机同步进行密切审查，我们将从几个与虚拟机和容器相关的安全要点开始。

## 安全方面 - 虚拟机与 Docker 容器

让我们从理解虚拟机与容器的区别开始。通常，虚拟机是笨重的，因此臃肿，而容器是轻量级的，因此苗条而时尚。

以下表格概括了虚拟机和容器的著名特性：

| 虚拟机 | 容器 |
| --- | --- |
| 几个虚拟机可以在单个物理机上运行（低密度）。 | 几十个容器可以在单个物理或虚拟机上运行（高密度）。 |
| 这确保了虚拟机的完全隔离以确保安全。 | 这使得在进程级别进行隔离，并使用命名空间和 cgroups 等功能提供额外的隔离。 |
| 每个虚拟机都有自己的操作系统，物理资源由底层的 hypervisor 管理。 | 容器与其 Docker 主机共享相同的内核。 |
| 对于网络，虚拟机可以连接到虚拟或物理交换机。Hypervisors 具有用于 I/O 性能改进的缓冲区，NIC 绑定等。容器利用标准的 IPC 机制，如信号，管道，套接字等进行网络连接。每个容器都有自己的网络堆栈。 |

下图清楚地说明了成熟的虚拟化范式和快速发展的容器化理念之间的结构差异。

安全方面-虚拟机与 Docker 容器

关于 VM 和容器安全方面的辩论正在加剧。有人支持其中一种，也有人反对。前面的图表帮助我们可视化、比较和对比了两种范式中的安全影响。

在虚拟化范式中，hypervisors 是虚拟机的集中和核心控制器。对于新提供的虚拟机的任何访问都需要通过这个 hypervisor 解决方案，它是任何未经身份验证、未经授权和不道德目的的坚实墙。因此，与容器相比，虚拟机的攻击面更小。必须破解或攻破 hypervisor 才能影响其他虚拟机。

与虚拟化范式相比，容器直接放置在主机系统的内核之上。这种精简高效的架构大大提高了效率，因为它完全消除了 hypervisor 的仿真层，并且提供了更高的容器密度。然而，与虚拟机范式不同，容器范式没有太多的层，因此如果任何一个容器受到损害，就可以轻松地访问主机和其他容器。因此，与虚拟机相比，容器的攻击面更大。

然而，Docker 平台的设计者已经充分考虑了这种安全风险，并设计了系统来阻止大多数安全风险。在接下来的部分中，我们将讨论系统中固有设计的安全性，所提出的大幅增强容器安全性的解决方案，以及最佳实践和指南。

## 容器的安全特性

Linux 容器，特别是 Docker 容器，具有一些有趣的固有安全功能。因此，容器化运动在安全方面是受到了良好的保护。在本节中，我们将详细讨论这些与安全相关的功能。

Docker 平台提倡分层安全方法，以为容器带来更果断和灵巧的安全性，如下图所示：

![容器的安全功能](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_11_02.jpg)

讨论中，Docker 使用了一系列安全屏障来阻止入侵。也就是说，如果一个安全机制被破坏，其他机制会迅速阻止容器被黑客攻击。在评估 Docker 容器的安全影响时，有一些关键领域需要进行检查。

### 资源隔离

众所周知，容器被定位为微服务架构时代的产物。也就是说，在单个系统中，可以有多个通用的、以及特定目的的服务，它们动态地相互协作，实现易于维护的分布式应用程序。随着物理系统中服务的多样性和异构性不断增加，安全复杂性必然会上升。因此，资源需要明确定界并隔离，以避免任何危险的安全漏洞。被广泛接受的安全方法是利用命名空间的内核特性。

内核命名空间为 Linux 容器提供了必要的隔离功能。Docker 项目为 Docker 容器添加了一些额外的命名空间，容器的每个独立方面都在自己的命名空间中运行，因此无法在外部访问。以下是 Docker 使用的命名空间列表：

+   **PID 命名空间**：用于一系列操作，以实现进程级别的隔离

+   **网络命名空间**：用于对网络接口进行执行控制

+   **IPC 命名空间**：用于控制对 IPC 资源的访问

+   **挂载命名空间**：用于管理挂载点

+   **UTS 命名空间**：用于隔离内核和版本标识符

内核命名空间提供了首要的隔离形式。在一个容器中运行的进程不会影响在另一个容器或主机系统中运行的进程。网络命名空间确保每个容器都有自己的网络堆栈，从而限制对其他容器接口的访问。从网络架构的角度来看，给定 Docker 主机上的所有容器都位于桥接接口上。这意味着它们就像连接到共同以太网交换机的物理机器一样。

### 资源会计和控制

容器消耗不同的物理资源以提供其独特的功能。然而，资源消耗必须受到纪律、有序和严格的监管。一旦出现偏差，容器执行其分配的任务的可能性就会更大。例如，如果资源使用没有系统地同步，就会导致**拒绝服务**（DoS）攻击。

Linux 容器利用控制组（cgroups）来实现资源会计和审计，以便以无摩擦的方式运行应用程序。众所周知，有多种资源有助于成功运行容器。它们提供了许多有用的指标，并确保每个容器都能公平地分享内存、CPU 和磁盘 I/O。

此外，它们保证单个容器不能通过耗尽任何一个资源来使系统崩溃。这个特性有助于抵御一些 DoS 攻击。这个特性有助于在云环境中以多租户身份运行容器，以确保它们的正常运行和性能。任何其他容器的任何利用都会被及时识别和制止，以避免任何不良事件的发生。

## 根权限-影响和最佳实践

Docker 引擎通过利用最近提到的资源隔离和控制技术有效地保护容器免受任何恶意活动的影响。尽管如此，Docker 暴露了一些潜在的安全威胁，因为 Docker 守护程序以根权限运行。在这一部分，我们列出了一些安全风险和减轻它们的最佳实践。

### 受信任的用户控制

由于 Docker 守护程序以根权限运行，它有能力将 Docker 主机的任何目录挂载到容器中，而不限制任何访问权限。也就是说，您可以启动一个容器，其中`/host`目录将是主机上的`/`目录，容器将能够在没有任何限制的情况下修改您的主机文件系统。这只是恶意用途中的一个例子。考虑到这些活动，Docker 的后续版本限制了通过 Unix 套接字访问 Docker 守护程序的权限。如果您明确决定这样做，Docker 可以配置为通过 HTTP 上的 REST API 访问守护程序。但是，您应该确保它只能从受信任的网络或 VPN 访问，或者用 stunnel 和客户端 SSL 证书保护。您还可以使用 HTTPS 和证书来保护它们。

### 非根容器

如前所述，Docker 容器默认情况下以根权限运行，容器内运行的应用程序也是如此。从安全的角度来看，这是另一个重要问题，因为黑客可以通过入侵容器内运行的应用程序来获得对 Docker 主机的根访问权限。不要绝望，Docker 提供了一个简单而强大的解决方案，可以将容器的权限更改为非根用户，从而阻止对 Docker 主机的恶意根访问。可以使用`docker run`子命令的`-u`或`--user`选项，或者在`Dockerfile`中使用`USER`指令来实现将用户更改为非根用户。

在本节中，我们将通过展示 Docker 容器的默认根权限来演示这个概念，然后继续使用`Dockerfile`中的`USER`指令将根权限修改为非根用户。

首先，我们通过在`docker run`子命令中运行简单的`id`命令来演示 Docker 容器的默认根权限，如下所示：

```
$ sudo docker run --rm ubuntu:14.04 id
uid=0(root) gid=0(root) groups=0(root)

```

现在，让我们执行以下步骤：

1.  制作一个`Dockerfile`，创建一个非根权限用户，并将默认的根用户修改为新创建的非根权限用户，如下所示：

```
#######################################################
# Dockerfile to change from root to non-root privilege
#######################################################

# Base image is Ubuntu
FROM ubuntu:14.04

# Add a new user "peter" with user id 7373
RUN useradd -u 7373  peter

# Change to non-root privilege
USER peter
uid=0(root) gid=0(root) groups=0(root)
```

1.  继续使用`docker build`子命令构建 Docker 镜像，如下所示：

```
$ sudo docker build –t nonrootimage .

```

1.  最后，让我们使用`docker run`子命令中的`id`命令来验证容器的当前用户：

```
$ sudo docker run --rm nonrootimage id
uid=7373(peter) gid=7373(peter) groups=7373(peter)

```

显然，容器的用户、组和组现在已更改为非根用户。

将默认的根特权修改为非根特权是遏制恶意渗透进入 Docker 主机内核的一种非常有效的方法。

### 加载 Docker 镜像和安全影响

Docker 通常从网络中拉取镜像，这些镜像通常在源头进行筛选和验证。然而，为了备份和恢复，Docker 镜像可以使用`docker save`子命令保存，并使用`docker load`子命令加载回来。这种机制也可以用于通过非常规手段加载第三方镜像。不幸的是，在这种做法中，Docker 引擎无法验证源头，因此这些镜像可能携带恶意代码。因此，作为第一道安全屏障，Docker 在特权分离的 chrooted 子进程中提取镜像。即使 Docker 确保了特权分离，也不建议加载任意镜像。

### 新兴的安全方法

到目前为止，我们已经讨论了与安全相关的内核特性和能力。通过理解和应用这些内核能力，大多数安全漏洞可以得到关闭。安全专家和倡导者考虑到了容器化理念在生产环境中更快更广泛的采用，提出了一些额外的安全解决方案，我们将详细描述这些安全方法。在开发、部署和交付企业级容器时，开发人员和系统管理员需要极为重视这些安全方法，以消除任何内部或外部的安全攻击。

# 用于容器安全的安全增强型 Linux

安全增强型 Linux（SELinux）是清理 Linux 容器中的安全漏洞的一次勇敢尝试，它是 Linux 内核中强制访问控制（MAC）机制、多级安全（MLS）和多类别安全（MCS）的实现。一个名为 Virtproject 的新的协作倡议正在基于 SELinux 构建，并且正在与 Libvirt 集成，为虚拟机和容器提供一个可适应的 MAC 框架。这种新的架构为容器提供了一个安全的隔离和安全网，因为它主要阻止容器内的根进程与容器外运行的其他进程进行接口和干扰。Docker 容器会自动分配到 SELinux 策略中指定的 SELinux 上下文中。

在完全检查**自由裁量访问控制**（**DAC**）之后，SELinux 始终检查所有允许的操作。SELinux 可以根据定义的策略在 Linux 系统中的文件和进程以及它们的操作上建立和强制执行规则。根据 SELinux 规范，文件（包括目录和设备）被称为对象。同样，进程，比如运行命令的用户，被称为主体。大多数操作系统使用 DAC 系统来控制主体如何与对象和彼此交互。在操作系统上使用 DAC，用户可以控制自己对象的权限。例如，在 Linux 操作系统上，用户可以使他们的主目录可读，从而给用户和主体窃取潜在敏感信息的机会。然而，单独使用 DAC 并不是一个绝对安全的方法，DAC 访问决策仅基于用户身份和所有权。通常，DAC 简单地忽略其他安全启用参数，如用户的角色、功能、程序的可信度以及数据的敏感性和完整性。

由于每个用户通常对其文件拥有完全自由裁量权，确保系统范围的安全策略是困难的。此外，用户运行的每个程序都只是继承了用户被授予的所有权限，用户可以自由更改对他/她的文件的访问权限。所有这些都导致对恶意软件的最小保护。许多系统服务和特权程序以粗粒度权限运行，因此这些程序中的任何缺陷都可以轻松利用并扩展以获得对系统的灾难性访问。

正如在开头提到的，SELinux 将**强制访问控制**（**MAC**）添加到 Linux 内核中。这意味着对象的所有者对对象的访问没有控制或自由裁量权。内核强制执行 MAC，这是一种通用的 MAC 机制，它需要能够对系统中的所有进程和文件强制执行管理设置的安全策略。这些文件和进程将用于基于包含各种安全信息的标签做出决策。MAC 具有足够保护系统的固有能力。此外，MAC 确保应用程序安全，防止任何恶意入侵和篡改。MAC 还提供了强大的应用程序隔离，以便任何受攻击和受损的应用程序都可以独立运行。

接下来是**多类别安全**（**MCS**）。MCS 主要用于保护容器免受其他容器的影响。也就是说，任何受影响的容器都无法使同一 Docker 主机中的其他容器崩溃。MCS 基于多级安全（MLS）功能，并独特地利用 SELinux 标签的最后一个组件，*MLS 字段*。一般来说，当容器启动时，Docker 守护程序会选择一个随机的 MCS 标签。Docker 守护程序会使用该 MCS 标签为容器中的所有内容打上标签。

当守护程序启动容器进程时，它告诉内核使用相同的 MCS 标签为进程打标签。只要进程的 MCS 标签与文件系统内容的 MCS 标签匹配，内核就只允许容器进程读取/写入自己的内容。内核会阻止容器进程读取/写入使用不同 MCS 标签标记的内容。这样，被黑客入侵的容器进程就无法攻击其他容器。Docker 守护程序负责确保没有容器使用相同的 MCS 标签。通过巧妙地使用 MCS，禁止了容器之间的错误级联。

## 受 SELinux 启发的好处

SELinux 被定位为将绝对安全带给 Docker 容器的主要改进之一。很明显，SELinux 具有几个与安全相关的优势。由于 Docker 容器原生运行在 Linux 系统上，通过优雅的 SELinux 方法在 Linux 系统中进行的核心和关键改进也可以轻松地复制到 Docker 容器中。所有进程和文件都被标记为一种类型。一种类型能够定义和区分进程的域和文件的不同域。通过在它们自己的域中运行它们，进程彼此之间完全分离，对其他进程的任何侵入都受到严格监控并在萌芽阶段被制止。SELinux 赋予我们建立和执行策略规则的权力，以定义进程如何与文件和彼此交互。例如，只有在有明确阐述的 SELinux 策略允许所需和划定的访问时，才允许任何访问。确切地说，SELinux 在强制执行数据保密性和完整性方面非常方便。SELinux 还有助于保护进程免受不受信任的输入。它具有以下好处：

+   细粒度访问控制：SELinux 访问决策是基于考虑各种安全影响信息，比如 SELinux 用户、角色、类型和级别。SELinux 策略可以在系统级别进行管理定义、执行和实施。通过全面利用 SELinux 升级，用户在放宽和减轻安全和访问策略方面的自由裁量权完全被消除。

+   减少特权升级攻击的漏洞性：这些进程通常在域中运行，因此彼此之间干净地分离。SELinux 策略规则定义了进程如何访问文件和其他进程。也就是说，如果一个进程被有意或无意地破坏，攻击者只能访问该进程的标准功能和该进程被配置为访问的文件。例如，如果一个 Web 服务器被关闭，攻击者不能使用该进程来读取其他文件，除非特定的 SELinux 策略规则被纳入以允许这样的访问。

+   SELinux 中的进程分离：这些进程被安排在自己的域中运行，防止进程访问其他进程使用的文件，同时也防止进程访问其他进程。例如，在运行 SELinux 时，攻击者无法破坏服务器模块（例如 Samba 服务器），然后利用它作为攻击向量来读写其他进程使用的文件，比如后端数据库。SELinux 在大大限制了由不当配置错误造成的损害方面非常有用。域名系统（DNS）服务器经常在彼此之间复制信息，这被称为区域传输。攻击者可以使用区域传输来向 DNS 服务器更新虚假信息。SELinux 防止区域文件被任何黑客滥用。我们对 Docker 容器使用两种类型的 SELinux 执行。

+   类型强制：这保护主机免受容器内部的进程的影响。运行 Docker 容器的默认类型是`svirt_lxc_net_t`。所有容器进程都以这种类型运行，容器内的所有内容都标记有`svirt_sandbox_file_t`类型。`svirt_lxc_net_t`默认类型被允许管理任何标记为`svirt_sandbox_file_t`的内容。此外，`svirt_lxc_net_t`还能够读取/执行主机上`/usr`目录下的大多数标签。

+   **安全问题**：如果所有容器进程都以`svirt_lxc_net_t`运行，并且所有内容都标记为`svirt_sandbox_file_t`，则容器进程可能被允许攻击运行在其他容器中的进程和其他容器拥有的内容。这就是多类别安全（MCS）执行变得很有用的地方。

+   **多类别安全（MCS）**：这是对 SELinux 的一个实质性增强，允许用户为文件打上类别标签。这些类别实际上用于进一步限制**自主访问控制**（**DAC**）和**类型强制**（**TE**）逻辑。一个类别的例子是*公司机密*。只有有权访问该类别的用户才能访问带有该类别标签的文件，假设现有的 DAC 和 TE 规则也允许访问。术语*类别*指的是**多级安全**（**MLS**）中使用的非层次化类别。在 MLS 下，对象和主体被标记有安全级别。这些安全级别包括一个分层敏感值，比如*绝密*，以及零个或多个非层次化类别，比如*加密*。类别提供了敏感级别内的隔间，并强制实施需要知道的安全原则。MCS 是对 MLS 的一种改编，代表了一种政策变化。除了访问控制，MCS 还可以用于在打印页面的顶部和底部显示 MCS 类别。这可能还包括一张封面，以指示文件处理程序。

+   **AppArmor**：这是一个有效且易于使用的 Linux 应用程序安全系统。AppArmor 通过强制执行良好的行为并防止甚至未知的应用程序缺陷被利用，主动保护操作系统和应用程序免受任何外部或内部威胁，甚至零日攻击。AppArmor 安全策略完全定义了个别应用程序可以访问的系统资源以及权限。AppArmor 包含了许多默认策略，并且使用高级静态分析和基于学习的工具的组合，即使是非常复杂的应用程序，也可以在几小时内成功部署 AppArmor 策略。AppArmor 适用于支持它的系统上的 Docker 容器。AppArmor 提供企业级主机入侵防范，并保护操作系统和应用程序免受内部或外部攻击、恶意应用程序和病毒的有害影响。因此，企业可以保护关键数据，降低系统管理成本，并确保符合政府法规。全面的企业范围网络应用程序安全需要关注用户和应用程序。这是一个突出的选择，可为 Docker 容器和容器内的应用程序带来无法渗透的安全性。策略正在成为确保容器安全的强大机制。策略制定和自动执行策略在保证容器安全方面起着重要作用。

# 容器安全的最佳实践

有强大而有韧性的安全解决方案，可以增强服务提供者和用户对容器化旅程的信心，以及对其有清晰和敏捷的态度。在本节中，我们提供了许多提示、最佳实践和关键指南，这些来自不同来源，旨在使安全管理员和顾问能够严密地保护 Docker 容器。基本上，如果容器在多租户系统中运行，并且您没有使用经过验证的安全实践，那么安全前方肯定存在着明显的危险。如前所述，安全漏洞可能发生在不同的服务级别，因此安全架构师需要弄清楚可能出现的问题，并规定经过验证和开创性的安全保护方法。安全领域的先驱和权威建议采用以下易于理解和遵循的做法，以实现最初设想的容器益处：

+   摒弃特权访问

+   尽量以非 root 用户身份运行您的容器和服务

首要建议是不要在系统上运行随机和未经测试的 Docker 镜像。制定策略，利用受信任的 Docker 镜像和容器存储库来订阅和使用应用程序和数据容器，用于应用程序开发、打包、装运、部署和交付。从过去的经验来看，从公共领域下载的任何不受信任的容器可能会导致恶意和混乱的情况。Linux 发行版，如**Red Hat Enterprise Linux**（**RHEL**），已经采取了以下机制，以帮助管理员确保最高的安全性：

+   一个可信赖的软件存储库可供下载和使用

+   安全更新和补丁来修复漏洞

+   一个安全响应团队来查找和管理漏洞

+   一个工程团队来管理/维护软件包并致力于安全增强

+   常见标准认证来检查操作系统的安全性

如前所述，最大的问题是并非所有 Linux 都有命名空间。目前，Docker 使用五个命名空间来改变进程对系统的视图——进程、网络、挂载、主机名和共享内存。虽然这些给用户一定程度的安全性，但绝不像 KVM 那样全面。在 KVM 环境中，虚拟机中的进程不直接与主机内核通信。它们无法访问内核文件系统。设备节点可以与虚拟机内核通信，但不能与主机通信。因此，为了从虚拟机中提升权限，进程必须破坏虚拟机内核，找到超级监视器中的漏洞，突破 SELinux 控制（sVirt），并攻击主机内核。在容器环境中，方法是保护主机免受容器内进程的影响，并保护容器免受其他容器的影响。这就是将多个安全控制组合或聚合在一起，以保护容器及其内容。

基本上，我们希望尽可能设置多个安全屏障，以防止任何形式的突破。如果特权进程能够突破一个封闭机制，那么就要用层次结构中的下一个屏障来阻止它们。使用 Docker，可以尽可能利用 Linux 的多个安全机制。

以下是可能采取的安全措施：

+   文件系统保护：为了避免任何未经授权的写入，文件系统需要是只读的。也就是说，特权容器进程不能向其写入，也不会影响主机系统。一般来说，大多数应用程序不需要向其文件系统写入任何内容。有几个 Linux 发行版使用只读文件系统。因此，可以阻止特权容器进程重新挂载文件系统为读写模式。这就是阻止容器内挂载任何文件系统的能力。

+   **写时复制文件系统**：Docker 一直在使用**高级多层统一文件系统**（**AuFS**）作为容器的文件系统。AuFS 是一个分层文件系统，可以透明地覆盖一个或多个现有的文件系统。当一个进程需要修改一个文件时，AuFS 首先创建该文件的副本，并能够将多个层合并成一个文件系统的单一表示。这个过程称为写时复制，这可以防止一个容器看到另一个容器的更改，即使它们写入相同的文件系统镜像。一个容器不能改变镜像内容以影响另一个容器中的进程。

+   **功能的选择**：通常有两种方法来执行权限检查：特权进程和非特权进程。特权进程可以绕过所有类型的内核权限检查，而非特权进程则根据进程的凭据进行完整的权限检查。最近的 Linux 内核将传统上与超级用户相关联的特权划分为称为功能的不同单元，这些功能可以独立启用和禁用。功能是每个线程的属性。删除功能可以在 Docker 容器中带来几个积极的变化。无论如何，功能决定了 Docker 的功能、可访问性、可用性、安全性等等。因此，在增加或删除功能的过程中需要仔细考虑。

+   **保持系统和数据的安全**：在企业和服务提供商在生产环境中使用容器之前，需要解决一些安全问题。出于以下三个原因，容器化最终将使得更容易保护应用程序：

+   较小的有效负载减少了安全漏洞的表面积

+   可以更新操作系统而不是逐步打补丁

+   通过允许明确的关注分离，容器有助于 IT 和应用团队有目的地合作。

IT 部门负责基础设施相关的安全漏洞。应用团队修复容器内部的缺陷，也负责运行时依赖关系。缓解 IT 和应用开发团队之间的紧张关系有助于平稳过渡到混合云模型。每个团队的责任都清晰地划分，以确保容器及其运行时基础设施的安全。通过这样清晰的分工，积极地识别任何可见和不可见的危害安全的事件，并及时消除，制定和执行策略，精确和完美的配置，利用适当的安全发现和缓解工具等，都在系统地完成。

+   **利用 Linux 内核功能**：一个普通的服务器（裸机或虚拟机）需要以 root 身份运行一堆进程。这些通常包括`ssh`、`cron`、`syslogd`、硬件管理工具（例如加载模块）、网络配置工具（例如处理 DHCP、WPA 或 VPN）等。容器非常不同，因为几乎所有这些任务都由容器所托管和运行的基础设施处理。安全专家撰写的各种博客上有一些最有趣和鼓舞人心的安全相关细节的最佳实践、关键指南、技术知识等。您可以在[`docs.docker.com/articles/security/`](https://docs.docker.com/articles/security/)找到一些最有趣和鼓舞人心的安全相关细节。

# 数字签名验证

Docker，这家知名的开源容器公司，宣布已将数字签名验证添加到 Docker 镜像中。这将确保当您从官方 Docker 仓库下载一个容器化应用时，您得到的是真实版本。此时，Docker 引擎会自动使用数字签名检查官方仓库中所有镜像的来源和完整性。数字签名为 Docker 镜像带来了额外的信任。也就是说，特定的 Docker 镜像没有被篡改或扭曲，因此可以放心和清晰地完全使用。

这种新添加的加密验证用于为用户提供额外的安全保证。将来，将会有一些功能，比如发布者认证、镜像完整性和授权、公钥基础设施（PKI）管理等，供镜像发布者和消费者使用。如果官方镜像被损坏或篡改，Docker 将立即发出警告。目前，Docker 引擎不会阻止任何受影响的镜像运行，非官方镜像也不会被验证。随着 Docker 社区加固代码并解决不可避免的可用性问题，未来版本将会改变这一点。

在开发应用程序时，有时需要在其运行时查看它。最近出现了一些工具，如`nsinit`和`nsenter`，以帮助开发人员调试其容器化的应用程序。一些用户已经开始运行一个 init 进程，以在他们的应用程序中生成`sshd`，以允许他们访问，这会带来风险和开销。

## Docker 的安全部署指南

Docker 容器越来越多地托管在生产环境中，可以被公开发现和被许多人使用。特别是随着云技术的更快采用，全球组织和机构的 IT 环境正在被系统地优化和转变，以灵活和果断地托管更多种类的虚拟机和容器。有一些新的改进和功能，比如 Flocker 和 Clocker，可以加快将容器部署到云环境（私有、公共、混合和社区）的过程。在部署容器时必须遵循一些建议。众所周知，容器通过允许开发人员和系统管理员无缝部署应用程序和服务，显著减少了开销。然而，由于 Docker 利用与主机系统相同的内核来减少资源需求，如果配置不足，容器可能面临重大安全风险。在部署容器时，开发人员和系统管理员必须严格遵循一些仔细注释的指南。例如，[`github.com/GDSSecurity/Docker-Secure-Deployment-Guidelines`](https://github.com/GDSSecurity/Docker-Secure-Deployment-Guidelines)以表格形式详细阐述了所有正确的细节。

毫无疑问，分布式和复杂应用程序中的软件缺陷为智能攻击者和黑客打开了入侵托管关键、机密和客户数据的系统的大门。因此，安全解决方案被坚持并融入到 IT 堆栈的所有层中，因此在不同级别和层次上出现了许多类型的安全漏洞。例如，周界安全只解决了部分问题，因为不断变化的要求要求允许员工、客户和合作伙伴访问网络。同样，还有防火墙、入侵检测和预防系统、应用交付控制器（ADC）、访问控制、多因素身份验证和授权、打补丁等。然后，为了在传输、持久性和应用程序使用数据时保护数据，有加密、隐写术和混合安全模型。所有这些都是反应性和现实的机制，但趋势增长的是虚拟业务坚持采用积极主动的安全方法。随着 IT 趋向和趋势向着备受期待的虚拟 IT 世界发展，安全问题和影响正在受到安全专家的额外重视。

## 未来

在未来的日子里，容器化领域将会有更多值得注意的即兴创新、转型和颠覆。通过一系列创新和整合，Docker 平台正在被定位为加强容器化旅程的领先平台。以下是通过巧妙利用 Docker 技术取得的主要成就：

+   **加强分布式范式**：随着计算越来越分布和联合，微服务架构（MSA）将在 IT 中发挥非常决定性和更深层次的作用。Docker 容器正日益成为托管和交付日益增长的微服务数组的最有效方式。随着容器编排技术和工具获得更广泛的认可，微服务（特定的和通用的）被识别、匹配、编排和编排，形成业务感知的复合服务。

+   **赋能云范式**：云理念正在牢牢抓住 IT 世界，以实现迫切需要的 IT 基础设施合理化、简化、标准化、自动化和优化。抽象和虚拟化概念是云范式取得空前成功的关键，正在渗透到各种 IT 模块中。最初，它始于服务器虚拟化，现在已经涉及存储和网络虚拟化。随着我们周围所有技术的进步，人们普遍渴望实现软件定义基础设施（软件定义计算、存储和网络）。Docker 引擎，作为 Docker 平台的核心和关键部分，已经得到充分巩固，以使容器在软件定义环境中无障碍地运行。

+   **实现 IT 弹性、可移植性、敏捷性和适应性**：容器正逐渐成为灵活和未来化的 IT 构建模块，为实现更强韧性、多功能性、优雅和柔韧性做出贡献。更快速地提供 IT 资源以确保更高的可用性和实时可伸缩性，轻松消除开发和运营团队之间的各种摩擦，保证 IT 的原生性能，实现组织化和优化的 IT 以提高 IT 生产力等，这些都是对 Docker 容器的一些典型设想，以实现更智能的 IT。

### 注意

容器将成为虚拟机（VM）和裸金属服务器的战略补充，以实现更深层次的 IT 自动化、加速和增强，从而实现备受炒作和期望的业务敏捷性、自主性和可负担性。

# 摘要

安全性绝对是一个挑战，也是一个重要的方面，不容忽视。如果一个容器被 compromise，那么让容器主机垮掉就不是一件困难的事情。因此，确保容器和主机的安全对于容器化概念的蓬勃发展至关重要，特别是在 IT 系统的集中化和联邦化日益增长的情况下。在本章中，我们特别关注了 Docker 容器的令人作呕和毁灭性的安全问题，并解释了为容纳动态、企业级和关键任务应用程序的容器提供无懈可击的安全解决方案的方法和手段。在未来的日子里，将会有新的安全方法和解决方案，以确保 Docker 容器和主机的安全无法被渗透和破坏，因为容器及其内容的安全对于服务提供商和消费者来说至关重要。
