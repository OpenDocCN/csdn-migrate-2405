# 精通 Python 网络编程第二版（二）

> 原文：[`zh.annas-archive.org/md5/dda7e4d1dd78bc5577547014ce9b53d1`](https://zh.annas-archive.org/md5/dda7e4d1dd78bc5577547014ce9b53d1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：Python 自动化框架- Ansible 基础知识

前两章逐步介绍了与网络设备交互的不同方式。在第二章中，*低级网络设备交互*，我们讨论了管理交互会话以控制交互的 Pexpect 和 Paramiko 库。在第三章中，*API 和意图驱动的网络*，我们开始从 API 和意图的角度思考我们的网络。我们看了各种包含明确定义的命令结构并提供了一种结构化方式从设备获取反馈的 API。当我们从第二章 *低级网络设备交互*转移到第三章 *API 和意图驱动的网络*时，我们开始思考我们对网络的意图，并逐渐以代码的形式表达我们的网络。

让我们更深入地探讨将我们的意图转化为网络需求的想法。如果你曾经从事过网络设计，那么最具挑战性的部分往往不是网络设备的不同部分，而是资格和将业务需求转化为实际网络设计。你的网络设计需要解决业务问题。例如，你可能在一个更大的基础设施团队中工作，需要适应一个繁荣的在线电子商务网站，在高峰时段经历网站响应速度缓慢。你如何确定网络是否存在问题？如果网站的响应速度确实是由于网络拥塞造成的，那么你应该升级网络的哪一部分？其他系统能否利用更大的速度和吞吐量？以下图表是一个简单的过程的示意图，当我们试图将我们的业务需求转化为网络设计时，我们可能会经历的步骤：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/864b0e75-a6f0-4e3b-9115-d969d38f5605.png)业务逻辑到网络部署

在我看来，网络自动化不仅仅是更快的配置。它还应该解决业务问题，并准确可靠地将我们的意图转化为设备行为。这些是我们在网络自动化旅程中应该牢记的目标。在本章中，我们将开始研究一个名为**Ansible**的基于 Python 的框架，它允许我们声明我们对网络的意图，并从 API 和 CLI 中抽象出更多。

# 一个更具声明性的框架

有一天早上，你从一个关于潜在网络安全漏洞的噩梦中惊醒。你意识到你的网络包含有价值的数字资产，应该受到保护。作为网络管理员，你一直在做好工作，所以它相当安全，但你想在网络设备周围增加更多的安全措施，以确保安全。

首先，你将目标分解为两个可行的项目：

+   升级设备到最新版本的软件，这需要：

1.  将镜像上传到设备。

1.  指示设备从新镜像启动。

1.  继续重新启动设备。

1.  验证设备是否正在运行新软件镜像。

+   在网络设备上配置适当的访问控制列表，包括以下内容：

1.  在设备上构建访问列表。

1.  在接口上配置访问列表，在大多数情况下是在接口配置部分，以便可以应用到接口上。

作为一个以自动化为重点的网络工程师，您希望编写脚本来可靠地配置设备并从操作中获得反馈。您开始研究每个步骤所需的命令和 API，在实验室中验证它们，最终在生产环境中部署它们。在为 OS 升级和 ACL 部署做了大量工作之后，您希望这些脚本可以转移到下一代设备上。如果有一个工具可以缩短这个设计-开发-部署周期，那不是很好吗？

在本章和第五章《Python 自动化框架-超越基础》中，我们将使用一个名为 Ansible 的开源自动化工具。它是一个可以简化从业务逻辑到网络命令的过程的框架。它可以配置系统，部署软件，并协调一系列任务。Ansible 是用 Python 编写的，并已成为受网络设备供应商支持的领先自动化工具之一。

在本章中，我们将讨论以下主题：

+   一个快速的 Ansible 示例

+   Ansible 的优势

+   Ansible 架构

+   Ansible Cisco 模块和示例

+   Ansible Juniper 模块和示例

+   Ansible Arista 模块和示例

在撰写本书时，Ansible 2.5 版本兼容 Python 2.6 和 2.7，最近才从技术审查中获得了对 Python 3 的支持。与 Python 一样，Ansible 的许多有用功能来自社区驱动的扩展模块。即使 Ansible 核心模块支持 Python 3，许多扩展模块和生产部署仍处于 Python 2 模式。需要一些时间将所有扩展模块从 Python 2 升级到 Python 3。因此，在本书的其余部分，我们将使用 Python 2.7 和 Ansible 2.2。

为什么选择 Ansible 2.2？Ansible 2.5 于 2018 年 3 月发布，提供了许多新的网络模块功能，具有新的连接方法、语法和最佳实践。鉴于其相对较新的功能，大多数生产部署仍处于 2.5 版本之前。然而，在本章中，您还将找到专门用于 Ansible 2.5 示例的部分，供那些想要利用新语法和功能的人使用。

有关 Ansible Python 3 支持的最新信息，请访问[`docs.ansible.com/ansible/python_3_support.html`](http://docs.ansible.com/ansible/python_3_support.html)。

从前面的章节可以看出，我是一个学习示例的信徒。就像 Ansible 的底层 Python 代码一样，即使您以前没有使用过 Ansible，Ansible 构造的语法也很容易理解。如果您有一些关于 YAML 或 Jinja2 的经验，您将很快找到语法和预期过程之间的关联。让我们先看一个例子。

# 一个快速的 Ansible 示例

与其他自动化工具一样，Ansible 最初是用来管理服务器的，然后扩展到管理网络设备的能力。在很大程度上，服务器模块和网络模块以及 Ansible 所称的 playbook 之间是相似的，只是有细微的差别。在本章中，我们将首先看一个服务器任务示例，然后再与网络模块进行比较。

# 控制节点安装

首先，让我们澄清一下在 Ansible 环境中使用的术语。我们将把安装了 Ansible 的虚拟机称为控制机，被管理的机器称为目标机器或被管理节点。Ansible 可以安装在大多数 Unix 系统上，唯一的依赖是 Python 2.6 或 2.7。目前，Windows 操作系统并不被官方支持作为控制机。Windows 主机仍然可以被 Ansible 管理，只是不被支持作为控制机。

随着 Windows 10 开始采用 Windows 子系统，Ansible 可能很快也准备好在 Windows 上运行。有关更多信息，请查看 Windows 的 Ansible 文档（[`docs.ansible.com/ansible/2.4/intro_windows.html`](https://docs.ansible.com/ansible/2.4/intro_windows.html)）。

在受控节点要求中，您可能会注意到一些文档提到 Python 2.4 或更高版本是一个要求。这对于管理诸如 Linux 之类的操作系统的目标节点是正确的，但显然并非所有网络设备都支持 Python。我们将看到如何通过在控制节点上本地执行来绕过网络模块的此要求。

对于 Windows，Ansible 模块是用 PowerShell 实现的。如果您想查看核心和额外存储库中的 Windows 模块，可以在 Windows/subdirectory 中找到。

我们将在我们的 Ubuntu 虚拟机上安装 Ansible。有关其他操作系统的安装说明，请查看安装文档（[`docs.ansible.com/ansible/intro_installation.html`](http://docs.ansible.com/ansible/intro_installation.html)）。在以下代码块中，您将看到安装软件包的步骤：

```py
$ sudo apt-get install software-properties-common
$ sudo apt-add-repository ppa:ansible/ansible
$ sudo apt-get update
$ sudo apt-get install ansible
```

我们也可以使用`pip`来安装 Ansible：`pip install ansible`。我个人更喜欢使用操作系统的软件包管理系统，比如 Ubuntu 上的 Apt。

现在我们可以进行快速验证如下：

```py
$ ansible --version
ansible 2.6.1
  config file = /etc/ansible/ansible.cfg 
```

现在，让我们看看如何在同一控制节点上运行不同版本的 Ansible。如果您想尝试最新的开发功能而不进行永久安装，这是一个有用的功能。如果我们打算在没有根权限的控制节点上运行 Ansible，我们也可以使用这种方法。

从输出中我们可以看到，写作本书时，最新版本是 2.6.1。请随意使用此版本，但考虑到相对较新的发布，我们将在本书中专注于 Ansible 版本 2.2。

# 从源代码运行不同版本的 Ansible

您可以从源代码检出运行 Ansible（我们将在第十一章中查看 Git 作为版本控制机制）：

```py
$ git clone https://github.com/ansible/ansible.git --recursive
$ cd ansible/
$ source ./hacking/env-setup
...
Setting up Ansible to run out of checkout...
$ ansible --version
ansible 2.7.0.dev0 (devel cde3a03b32) last updated 2018/07/11 08:39:39 (GMT -700)
 config file = /etc/ansible/ansible.cfg
...
```

要运行不同版本，我们可以简单地使用`git checkout`切换到不同的分支或标签，并重新执行环境设置：

```py
$ git branch -a
$ git tag --list 
$ git checkout v2.5.6
...
HEAD is now at 0c985fe... New release v2.5.6
$ source ./hacking/env-setup
$ ansible --version
ansible 2.5.6 (detached HEAD 0c985fee8a) last updated 2018/07/11 08:48:20 (GMT -700)
 config file = /etc/ansible/ansible.cfg
```

如果 Git 命令对您来说有点奇怪，我们将在第十一章中更详细地介绍 Git。

一旦我们到达您需要的版本，比如 Ansible 2.2，我们可以为该版本运行核心模块的更新：

```py
$ ansible --version
ansible 2.2.3.0 (detached HEAD f5be18f409) last updated 2018/07/14 07:40:09 (GMT -700)
...
$ git submodule update --init --recursive
Submodule 'lib/ansible/modules/core' (https://github.com/ansible/ansible-modules-core) registered for path 'lib/ansible/modules/core'
```

让我们来看看我们将在本章和第五章中使用的实验室拓扑，*Python 自动化框架-超越基础知识*。

# 实验室设置

在本章和第五章中，我们的实验室将有一个安装了 Ansible 的 Ubuntu 16.04 控制节点机器。这个控制机器将能够访问我们的 VIRL 设备的管理网络，这些设备包括 IOSv 和 NX-OSv 设备。当目标机器是主机时，我们还将有一个单独的 Ubuntu 虚拟机用于我们的 playbook 示例。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/9f1dbd4a-6866-43af-ab4c-ef765483d7c4.png)实验室拓扑

现在，我们准备看我们的第一个 Ansible playbook 示例。

# 您的第一个 Ansible playbook

我们的第一个 playbook 将在控制节点和远程 Ubuntu 主机之间使用。我们将采取以下步骤：

1.  确保控制节点可以使用基于密钥的授权。

1.  创建清单文件。

1.  创建一个 playbook。

1.  执行并测试它。

# 公钥授权

首先要做的是将您的 SSH 公钥从控制机器复制到目标机器。完整的公钥基础设施教程超出了本书的范围，但在控制节点上有一个快速演练：

```py
$ ssh-keygen -t rsa <<<< generates public-private key pair on the host machine if you have not done so already
$ cat ~/.ssh/id_rsa.pub <<<< copy the content of the output and paste it to the ~/.ssh/authorized_keys file on the target host
```

你可以在[`en.wikipedia.org/wiki/Public_key_infrastructure`](https://en.wikipedia.org/wiki/Public_key_infrastructure)了解更多关于 PKI 的信息。

因为我们使用基于密钥的身份验证，我们可以在远程节点上关闭基于密码的身份验证，使其更加安全。现在，你可以使用私钥从控制节点到远程节点进行`ssh`连接，而无需输入密码。

你能自动复制初始公钥吗？这是可能的，但高度依赖于你的用例、规定和环境。这类似于网络设备的初始控制台设置以建立初始 IP 可达性。你会自动化这个过程吗？为什么或者为什么不？

# 库存文件

如果没有远程目标需要管理，我们就不需要 Ansible，对吧？一切都始于我们需要在远程主机上执行一些任务。在 Ansible 中，我们指定潜在远程目标的方式是使用一个库存文件。我们可以将这个库存文件作为`/etc/ansible/hosts`文件，或者在 playbook 运行时使用`-i`选项指定文件。我个人更喜欢将这个文件放在与我的 playbook 相同的目录中，并使用`-i`选项。

从技术上讲，只要它是有效的格式，这个文件可以被命名为任何你喜欢的名字。然而，按照惯例，将这个文件命名为`hosts`。遵循这个惯例，你可以在未来避免一些麻烦。

库存文件是一个简单的纯文本 INI 风格([`en.wikipedia.org/wiki/INI_file`](https://en.wikipedia.org/wiki/INI_file))文件，用于说明你的目标。默认情况下，目标可以是 DNS FQDN 或 IP 地址：

```py
$ cat hosts
192.168.199.170
```

我们现在可以使用命令行选项来测试 Ansible 和`hosts`文件：

```py
$ ansible -i hosts 192.168.199.170 -m ping
192.168.199.170 | SUCCESS => {
 "changed": false,
 "ping": "pong"
}
```

默认情况下，Ansible 假设执行 playbook 的用户在远程主机上存在。例如，我在本地以`echou`的身份执行 playbook；相同的用户也存在于我的远程主机上。如果你想以不同的用户执行，可以在执行时使用`-u`选项，即`-u REMOTE_USER`。

示例中的上一行将主机文件读入库存文件，并在名为`192.168.199.170`的主机上执行`ping`模块。Ping ([`docs.ansible.com/ansible/ping_module.html`](http://docs.ansible.com/ansible/ping_module.html))是一个简单的测试模块，连接到远程主机，验证可用的 Python 安装，并在成功时返回输出`pong`。

如果你对已经与 Ansible 一起提供的现有模块的使用有任何疑问，可以查看不断扩展的模块列表([`docs.ansible.com/ansible/list_of_all_modules.html`](http://docs.ansible.com/ansible/list_of_all_modules.html))。

如果你遇到主机密钥错误，通常是因为主机密钥不在`known_hosts`文件中，通常位于`~/.ssh/known_hosts`下。你可以通过 SSH 到主机并在添加主机时回答`yes`，或者通过检查`/etc/ansible/ansible.cfg`或`~/.ansible.cfg`来禁用这个功能，使用以下代码：

```py
[defaults]
host_key_checking = False
```

现在我们已经验证了库存文件和 Ansible 包，我们可以制作我们的第一个 playbook。

# 我们的第一个 playbook

Playbooks 是 Ansible 描述使用模块对主机执行的操作的蓝图。这是我们在使用 Ansible 时作为操作员将要花费大部分时间的地方。如果你正在建造一个树屋，playbook 将是你的手册，模块将是你的工具，而库存将是你在使用工具时要处理的组件。

playbook 旨在人类可读，并且采用 YAML 格式。我们将在 Ansible 架构部分看到常用的语法。现在，我们的重点是运行一个示例 playbook，以了解 Ansible 的外观和感觉。

最初，YAML 被说成是另一种标记语言，但现在，[`yaml.org/`](http://yaml.org/)已经重新定义这个首字母缩写为 YAML 不是标记语言。

让我们看看这个简单的 6 行 playbook，`df_playbook.yml`：

```py
---
- hosts: 192.168.199.170

 tasks:
 - name: check disk usage
 shell: df > df_temp.txt
```

在 playbook 中，可以有一个或多个 plays。在这种情况下，我们有一个 play（第二到第六行）。在任何 play 中，我们可以有一个或多个任务。在我们的示例 play 中，我们只有一个任务（第四到第六行）。`name`字段以人类可读的格式指定任务的目的，使用了`shell`模块。该模块接受一个`df`参数。`shell`模块读取参数中的命令并在远程主机上执行它。在这种情况下，我们执行`df`命令来检查磁盘使用情况，并将输出复制到名为`df_temp.txt`的文件中。

我们可以通过以下代码执行 playbook：

```py
$ ansible-playbook -i hosts df_playbook.yml
PLAY [192.168.199.170] *********************************************************

TASK [setup] *******************************************************************
ok: [192.168.199.170]

TASK [check disk usage] ************************************************
changed: [192.168.199.170]

PLAY RECAP *********************************************************************
192.168.199.170 : ok=2 changed=1 unreachable=0 failed=0
```

如果您登录到受管主机（对我来说是`192.168.199.170`），您会看到`df_temp.txt`文件包含`df`命令的输出。很整洁，对吧？

您可能已经注意到，我们的输出实际上执行了两个任务，尽管我们在 playbook 中只指定了一个任务；设置模块是默认自动添加的。它由 Ansible 执行，以收集有关远程主机的信息，这些信息可以在 playbook 中稍后使用。例如，设置模块收集的事实之一是操作系统。收集有关远程目标的事实的目的是什么？您可以将此信息用作同一 playbook 中其他任务的条件。例如，playbook 可以包含额外的任务来安装软件包。它可以具体使用`apt`来为基于 Debian 的主机安装软件包，使用`yum`来为基于 Red Hat 的主机安装软件包，这是基于在设置模块中收集的操作系统事实。

如果您对设置模块的输出感到好奇，您可以通过`$ ansible -i hosts <host> -m setup`找出 Ansible 收集的信息。

在幕后，我们的简单任务实际上发生了一些事情。控制节点将 Python 模块复制到远程主机，执行模块，将模块输出复制到临时文件，然后捕获输出并删除临时文件。目前，我们可能可以安全地忽略这些底层细节，直到我们需要它们。

重要的是，我们充分理解我们刚刚经历的简单过程，因为我们将在本章后面再次提到这些元素。我特意选择了一个服务器示例来呈现在这里，因为当我们需要偏离它们时（记住我们提到 Python 解释器很可能不在网络设备上），这将更有意义。

恭喜您执行了您的第一个 Ansible playbook！我们将更深入地了解 Ansible 架构，但现在让我们看看为什么 Ansible 非常适合网络管理。记住 Ansible 模块是用 Python 编写的吗？这对于 Python 网络工程师来说是一个优势，对吧？

# Ansible 的优势

除了 Ansible 之外，还有许多基础设施自动化框架，包括 Chef、Puppet 和 SaltStack。每个框架都提供其独特的功能和模型；没有一个框架适合所有组织。在本节中，我想列出 Ansible 相对于其他框架的一些优势，以及为什么我认为这是网络自动化的好工具。

我正在列出 Ansible 的优势，而不是将它们与其他框架进行比较。其他框架可能采用与 Ansible 相同的某些理念或某些方面，但很少包含我将要提到的所有功能。我相信正是所有以下功能和理念的结合使得 Ansible 成为网络自动化的理想选择。

# 无需代理

与一些同行不同，Ansible 不需要严格的主从模型。客户端不需要安装软件或代理来与服务器通信。除了许多平台默认具有的 Python 解释器外，不需要额外的软件。

对于网络自动化模块，Ansible 使用 SSH 或 API 调用将所需的更改推送到远程主机，而不是依赖远程主机代理。这进一步减少了对 Python 解释器的需求。对于网络设备管理来说，这对于网络设备管理来说是非常重要的，因为网络供应商通常不愿意在其平台上安装第三方软件。另一方面，SSH 已经存在于网络设备上。这种心态在过去几年里有所改变，但总体上，SSH 是所有网络设备的共同点，而配置管理代理支持则不是。正如您从第二章“低级网络设备交互”中所记得的那样，更新的网络设备还提供 API 层，这也可以被 Ansible 利用。

由于远程主机上没有代理，Ansible 使用推送模型将更改推送到设备，而不是拉模型，其中代理从主服务器拉取信息。在我看来，推送模型更具确定性，因为一切都起源于控制机器。在拉模型中，“拉”的时间可能因客户端而异，因此导致更改时间的差异。

再次强调与现有网络设备一起工作时无代理的重要性是不言而喻的。这通常是网络运营商和供应商接受 Ansible 的主要原因之一。

# 幂等性

根据维基百科的定义，幂等性是数学和计算机科学中某些操作的属性，可以多次应用而不会改变初始应用后的结果（https://en.wikipedia.org/wiki/Idempotence）。更常见的说法是，这意味着反复运行相同的过程不会改变系统。Ansible 旨在具有幂等性，这对于需要一定操作顺序的网络操作是有益的。

幂等性的优势最好与我们编写的 Pexpect 和 Paramiko 脚本进行比较。请记住，这些脚本是为了像工程师坐在终端上一样推送命令而编写的。如果您执行该脚本 10 次，该脚本将进行 10 次更改。如果我们通过 Ansible playbook 编写相同的任务，将首先检查现有设备配置，只有在更改不存在时才会执行 playbook。如果我们执行 playbook 10 次，更改只会在第一次运行时应用，接下来的 9 次运行将抑制配置更改。

幂等性意味着我们可以重复执行 playbook，而不必担心会有不必要的更改。这很重要，因为我们需要自动检查状态的一致性，而不会有任何额外的开销。

# 简单且可扩展

Ansible 是用 Python 编写的，并使用 YAML 作为 playbook 语言，这两者都被认为相对容易学习。还记得 Cisco IOS 的语法吗？这是一种特定领域的语言，只适用于管理 Cisco IOS 设备或其他类似结构的设备；它不是一个通用的语言，超出了其有限的范围。幸运的是，与一些其他自动化工具不同，Ansible 没有额外的特定领域语言或 DSL 需要学习，因为 YAML 和 Python 都被广泛用作通用目的语言。

从上面的例子中可以看出，即使您以前没有见过 YAML，也很容易准确猜出 playbook 的意图。Ansible 还使用 Jinja2 作为模板引擎，这是 Python web 框架（如 Django 和 Flask）常用的工具，因此知识是可转移的。

我无法强调 Ansible 的可扩展性。正如前面的例子所示，Ansible 最初是为了自动化服务器（主要是 Linux）工作负载而设计的。然后它开始用 PowerShell 管理 Windows 机器。随着越来越多的行业人员开始采用 Ansible，网络成为一个开始受到更多关注的话题。Ansible 聘请了合适的人员和团队，网络专业人员开始参与，客户开始要求供应商提供支持。从 Ansible 2.0 开始，网络自动化已成为与服务器管理并驾齐驱的一等公民。生态系统活跃而健康，每个版本都在不断改进。

就像 Python 社区一样，Ansible 社区也很友好，对新成员和新想法持包容态度。我亲身经历过成为新手，试图理解贡献程序并希望编写模块以合并到上游的过程。我可以证明，我始终感到受到欢迎和尊重我的意见。

简单性和可扩展性确实为未来的保护做出了很好的表述。技术世界发展迅速，我们不断努力适应。学习一项技术并继续使用它，而不受最新趋势的影响，这不是很好吗？显然，没有人有水晶球能够准确预测未来，但 Ansible 的记录为未来技术的适应性做出了很好的表述。

# 网络供应商支持

让我们面对现实，我们不是生活在真空中。行业中有一个流行的笑话，即 OSI 层应该包括第 8 层（金钱）和第 9 层（政治）。每天，我们需要使用各种供应商制造的网络设备。

以 API 集成为例。我们在前几章中看到了 Pexpect 和 API 方法之间的差异。在网络自动化方面，API 显然具有优势。然而，API 接口并不便宜。每个供应商都需要投入时间、金钱和工程资源来实现集成。供应商支持技术的意愿在我们的世界中非常重要。幸运的是，所有主要供应商都支持 Ansible，这清楚地表明了越来越多的网络模块可用（[`docs.ansible.com/ansible/list_of_network_modules.html`](http://docs.ansible.com/ansible/list_of_network_modules.html)）。

为什么供应商支持 Ansible 比其他自动化工具更多？无代理的特性肯定有所帮助，因为只有 SSH 作为唯一的依赖大大降低了进入门槛。在供应商一侧工作过的工程师知道，功能请求过程通常需要数月时间，需要克服许多障碍。每次添加新功能，都意味着需要花更多时间进行回归测试、兼容性检查、集成审查等。降低进入门槛通常是获得供应商支持的第一步。

Ansible 基于 Python 这一事实，这是许多网络专业人员喜欢的语言，也是供应商支持的另一个重要推动力。对于已经在 PyEZ 和 Pyeapi 上进行投资的 Juniper 和 Arista 等供应商，他们可以轻松利用现有的 Python 模块，并快速将其功能集成到 Ansible 中。正如我们将在第五章《Python 自动化框架-超越基础知识》中看到的，我们可以利用现有的 Python 知识轻松编写自己的模块。

在 Ansible 专注于网络之前，它已经拥有大量由社区驱动的模块。贡献过程在某种程度上已经成熟和建立，或者说已经成熟，就像一个开源项目可以成熟一样。Ansible 核心团队熟悉与社区合作进行提交和贡献。

增加网络供应商支持的另一个原因也与 Ansible 能够让供应商在模块上表达自己的优势有关。我们将在接下来的部分中看到，除了 SSH，Ansible 模块还可以在本地执行，并通过 API 与这些设备通信。这确保供应商可以在他们通过 API 提供最新和最好的功能时立即表达出来。对于网络专业人员来说，这意味着您可以在使用 Ansible 作为自动化平台时，使用最前沿的功能来选择供应商。

我们花了相当大的篇幅讨论供应商支持，因为我觉得这经常被忽视在 Ansible 故事中。有供应商愿意支持这个工具意味着您，网络工程师，可以放心地睡觉，知道下一个网络中的重大事件将有很高的机会得到 Ansible 的支持，您不会被锁定在当前供应商上，因为您的网络需要增长。

# Ansible 架构

Ansible 架构由 playbooks、plays 和 tasks 组成。看一下我们之前使用的`df_playbook.yml`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/5d5fb374-caea-4662-ad0b-27dffe364640.png)Ansible playbook

整个文件称为 playbook，其中包含一个或多个 plays。每个 play 可以包含一个或多个 tasks。在我们的简单示例中，我们只有一个 play，其中包含一个单独的 task。在本节中，我们将看一下以下内容：

+   **YAML**：这种格式在 Ansible 中被广泛用于表达 playbooks 和变量。

+   **清单**：清单是您可以在其中指定和分组基础设施中的主机的地方。您还可以在清单文件中可选地指定主机和组变量。

+   **变量**：每个网络设备都不同。它有不同的主机名、IP、邻居关系等。变量允许使用标准的 plays，同时还能适应这些差异。

+   **模板**：模板在网络中并不新鲜。事实上，您可能在不经意间使用了一个模板。当我们需要配置新设备或替换 RMA（退货授权）时，我们通常会复制旧配置并替换主机名和环回 IP 地址等差异。Ansible 使用 Jinja2 标准化模板格式，我们稍后将深入探讨。

在第五章中，《Python 自动化框架-超越基础知识》，我们将涵盖一些更高级的主题，如条件、循环、块、处理程序、playbook 角色以及它们如何与网络管理一起使用。

# YAML

YAML 是 Ansible playbooks 和一些其他文件使用的语法。官方的 YAML 文档包含了语法的完整规范。以下是与 Ansible 最常见用法相关的简洁版本：

+   YAML 文件以三个破折号(`---`)开头

+   空格缩进用于表示结构，就像 Python 一样

+   注释以井号(`#`)开头

+   列表成员以前导连字符(`-`)表示，每行一个成员

+   列表也可以用方括号(`[]`)表示，元素之间用逗号(`,`)分隔

+   字典由 key: value 对表示，用冒号分隔

+   字典可以用花括号表示，元素之间用逗号分隔

+   字符串可以不用引号，但也可以用双引号或单引号括起来

正如您所看到的，YAML 很好地映射到 JSON 和 Python 数据类型。如果我要将`df_playbook.yml`重写为`df_playbook.json`，它将如下所示：

```py
        [
          {
            "hosts": "192.168.199.170",
            "tasks": [
            "name": "check disk usage",
            "shell": "df > df_temp.txt"
           ]
          }
        ]
```

这显然不是一个有效的 playbook，但可以帮助理解 YAML 格式，同时使用 JSON 格式进行比较。大多数情况下，playbook 中会看到注释(`#`)、列表(`-`)和字典(key: value)。

# 清单

默认情况下，Ansible 会查看`/etc/ansible/hosts`文件中在 playbook 中指定的主机。如前所述，我发现通过`-i`选项指定主机文件更具表现力。这是我们到目前为止一直在做的。为了扩展我们之前的例子，我们可以将我们的清单主机文件写成如下形式：

```py
[ubuntu]
192.168.199.170

[nexus]
192.168.199.148
192.168.199.149

[nexus:vars]
username=cisco
password=cisco

[nexus_by_name]
switch1 ansible_host=192.168.199.148
switch2 ansible_host=192.168.199.149
```

你可能已经猜到，方括号标题指定了组名，所以在 playbook 中我们可以指向这个组。例如，在`cisco_1.yml`和`cisco_2.yml`中，我可以对`nexus`组下指定的所有主机进行操作，将它们指向`nexus`组名：

```py
---
- name: Configure SNMP Contact
hosts: "nexus"
gather_facts: false
connection: local
<skip>
```

一个主机可以存在于多个组中。组也可以作为`children`进行嵌套：

```py
[cisco]
router1
router2

[arista]
switch1
switch2

[datacenter:children]
cisco
arista
```

在上一个例子中，数据中心组包括`cisco`和`arista`成员。

我们将在下一节讨论变量。但是，您也可以选择在清单文件中指定属于主机和组的变量。在我们的第一个清单文件示例中，[`nexus:vars`]指定了整个 nexus 组的变量。`ansible_host`变量在同一行上为每个主机声明变量。

有关清单文件的更多信息，请查看官方文档（[`docs.ansible.com/ansible/intro_inventory.html`](http://docs.ansible.com/ansible/intro_inventory.html)）。

# 变量

我们在上一节中稍微讨论了变量。由于我们的受管节点并不完全相同，我们需要通过变量来适应这些差异。变量名应该是字母、数字和下划线，并且应该以字母开头。变量通常在三个位置定义：

+   playbook

+   清单文件

+   将要包含在文件和角色中的单独文件

让我们看一个在 playbook 中定义变量的例子，`cisco_1.yml`：

```py
---
- name: Configure SNMP Contact
hosts: "nexus"
gather_facts: false
connection: local

vars:
cli:
host: "{{ inventory_hostname }}"
username: cisco
password: cisco
transport: cli

tasks:
- name: configure snmp contact
nxos_snmp_contact:
contact: TEST_1
state: present
provider: "{{ cli }}"

register: output

- name: show output
debug:
var: output
```

在`vars`部分下可以看到`cli`变量的声明，该变量在`nxos_snmp_contact`任务中被使用。

有关`nxso_snmp_contact`模块的更多信息，请查看在线文档（[`docs.ansible.com/ansible/nxos_snmp_contact_module.html`](http://docs.ansible.com/ansible/nxos_snmp_contact_module.html)）。

要引用一个变量，可以使用 Jinja2 模板系统的双花括号约定。除非您以它开头，否则不需要在花括号周围加引号。我通常发现更容易记住并在变量值周围加上引号。

你可能也注意到了`{{ inventory_hostname }}`的引用，在 playbook 中没有声明。这是 Ansible 自动为您提供的默认变量之一，有时被称为魔术变量。

没有太多的魔术变量，你可以在文档中找到列表（[`docs.ansible.com/ansible/playbooks_variables.html#magic-variables-and-how-to-access-information-about-other-hosts`](http://docs.ansible.com/ansible/playbooks_variables.html#magic-variables-and-how-to-access-information-about-other-hosts)）。

我们在上一节的清单文件中声明了变量：

```py
[nexus:vars]
username=cisco
password=cisco

[nexus_by_name]
switch1 ansible_host=192.168.199.148
switch2 ansible_host=192.168.199.149
```

为了在清单文件中使用变量而不是在 playbook 中声明它们，让我们在主机文件中为`[nexus_by_name]`添加组变量：

```py
[nexus_by_name]
switch1 ansible_host=192.168.199.148
switch2 ansible_host=192.168.199.149

[nexus_by_name:vars]
username=cisco
password=cisco
```

然后，修改 playbook 以匹配我们在`cisco_2.yml`中看到的内容，以引用变量：

```py
---
- name: Configure SNMP Contact
hosts: "nexus_by_name"
gather_facts: false
connection: local

vars:
  cli:
     host: "{{ ansible_host }}"
     username: "{{ username }}"
     password: "{{ password }}"
     transport: cli

tasks:
  - name: configure snmp contact
  nxos_snmp_contact:
    contact: TEST_1
    state: present
    provider: "{{ cli }}"

  register: output

- name: show output
  debug:
    var: output
```

请注意，在这个例子中，我们在清单文件中引用了`nexus_by_name`组，`ansible_host`主机变量和`username`和`password`组变量。这是一个很好的方法，可以将用户名和密码隐藏在受保护的文件中，并发布 playbook 而不担心暴露敏感数据。

要查看更多变量示例，请查看 Ansible 文档（[`docs.ansible.com/ansible/playbooks_variables.html`](http://docs.ansible.com/ansible/playbooks_variables.html)）。

要访问提供在嵌套数据结构中的复杂变量数据，您可以使用两种不同的表示法。在`nxos_snmp_contact`任务中，我们在一个变量中注册了输出，并使用 debug 模块显示它。在 playbook 执行期间，您将看到类似以下的内容：

```py
 TASK [show output] 
 *************************************************************
 ok: [switch1] => {
 "output": {
 "changed": false,
 "end_state": {
 "contact": "TEST_1"
 },
 "existing": {
 "contact": "TEST_1"
 },
 "proposed": {
 "contact": "TEST_1"
 },
 "updates": []
 }
 }
```

为了访问嵌套数据，我们可以使用`cisco_3.yml`中指定的以下表示法：

```py
msg: '{{ output["end_state"]["contact"] }}'
msg: '{{ output.end_state.contact }}'
```

您将只收到指定的值：

```py
TASK [show output in output["end_state"]["contact"]] 
***************************
ok: [switch1] => {
 "msg": "TEST_1"
}
ok: [switch2] => {
 "msg": "TEST_1"
}

TASK [show output in output.end_state.contact] 
*********************************
ok: [switch1] => {
 "msg": "TEST_1"
}
ok: [switch2] => {
 "msg": "TEST_1"
}
```

最后，我们提到变量也可以存储在单独的文件中。为了了解如何在角色或包含的文件中使用变量，我们应该再多举几个例子，因为它们起步有点复杂。我们将在第五章中看到更多角色的例子，《Python 自动化框架-进阶》。

# Jinja2 模板

在前面的部分中，我们使用了 Jinja2 语法`{{ variable }}`的变量。虽然您可以在 Jinja2 中做很多复杂的事情，但幸运的是，我们只需要一些基本的东西来开始。

Jinja2 ([`jinja.pocoo.org/`](http://jinja.pocoo.org/))是一个功能齐全、强大的模板引擎，起源于 Python 社区。它在 Python web 框架中广泛使用，如 Django 和 Flask。

目前，只需记住 Ansible 使用 Jinja2 作为模板引擎即可。根据情况，我们将重新讨论 Jinja2 过滤器、测试和查找。您可以在这里找到有关 Ansible Jinja2 模板的更多信息：[`docs.ansible.com/ansible/playbooks_templating.html`](http://docs.ansible.com/ansible/playbooks_templating.html)。

# Ansible 网络模块

Ansible 最初是用于管理完整操作系统的节点，如 Linux 和 Windows，然后扩展到支持网络设备。您可能已经注意到我们迄今为止为网络设备使用的 playbook 中微妙的差异，比如`gather_facts: false`和`connection: local`；我们将在接下来的章节中更仔细地研究这些差异。

# 本地连接和事实

Ansible 模块是默认在远程主机上执行的 Python 代码。由于大多数网络设备通常不直接暴露 Python，或者它们根本不包含 Python，我们几乎总是在本地执行 playbook。这意味着 playbook 首先在本地解释，然后根据需要推送命令或配置。

请记住，远程主机的事实是通过默认添加的 setup 模块收集的。由于我们正在本地执行 playbook，因此 setup 模块将在本地主机而不是远程主机上收集事实。这显然是不需要的，因此当连接设置为本地时，我们可以通过将事实收集设置为 false 来减少这个不必要的步骤。

因为网络模块是在本地执行的，对于那些提供备份选项的模块，文件也会在控制节点上本地备份。

Ansible 2.5 中最重要的变化之一是引入了不同的通信协议（[`docs.ansible.com/ansible/latest/network/getting_started/network_differences.html#multiple-communication-protocols`](https://docs.ansible.com/ansible/latest/network/getting_started/network_differences.html#multiple-communication-protocols)）。连接方法现在包括`network_cli`、`netconf`、`httpapi`和`local`。如果网络设备使用 SSH 的 CLI，您可以在其中一个设备变量中将连接方法指定为`network_cli`。然而，由于这是一个相对较新的更改，您可能仍然会在许多现有的 playbook 中看到连接状态为本地。

# 提供者参数

正如我们从第二章和第三章中所看到的，*低级网络设备交互*和*API 和意图驱动的网络*，网络设备可以通过 SSH 或 API 连接，这取决于平台和软件版本。所有核心网络模块都实现了`provider`参数，这是一组用于定义如何连接到网络设备的参数。一些模块只支持`cli`，而一些支持其他值，例如 Arista EAPI 和 Cisco NXAPI。这就是 Ansible“让供应商发光”的理念所体现的地方。模块将有关于它们支持哪种传输方法的文档。

从 Ansible 2.5 开始，指定传输方法的推荐方式是使用`connection`变量。您将开始看到提供程序参数逐渐在未来的 Ansible 版本中被淘汰。例如，使用`ios_command`模块作为示例，[`docs.ansible.com/ansible/latest/modules/ios_command_module.html#ios-command-module`](https://docs.ansible.com/ansible/latest/modules/ios_command_module.html#ios-command-module)，提供程序参数仍然有效，但被标记为已弃用。我们将在本章后面看到一个例子。

`provider`传输支持的一些基本参数如下：

+   `host`：定义远程主机

+   `port`：定义连接的端口

+   `username`：要进行身份验证的用户名

+   `password`：要进行身份验证的密码

+   `transport`：连接的传输类型

+   `authorize`：这允许特权升级，适用于需要特权的设备

+   `auth_pass`：定义特权升级密码

正如您所看到的，并非所有参数都需要指定。例如，对于我们之前的 playbook，我们的用户在登录时始终处于管理员特权，因此我们不需要指定`authorize`或`auth_pass`参数。

这些参数只是变量，因此它们遵循相同的变量优先规则。例如，如果我将`cisco_3.yml`更改为`cisco_4.yml`并观察以下优先顺序：

```py
    ---
    - name: Configure SNMP Contact
      hosts: "nexus_by_name"
      gather_facts: false
      connection: local

      vars:
        cli:
          host: "{{ ansible_host }}"
          username: "{{ username }}"
          password: "{{ password }}"
          transport: cli

      tasks:
        - name: configure snmp contact
          nxos_snmp_contact:
            contact: TEST_1
            state: present
            username: cisco123
            password: cisco123
            provider: "{{ cli }}"

          register: output

        - name: show output in output["end_state"]["contact"]
          debug:
            msg: '{{ output["end_state"]["contact"] }}'

        - name: show output in output.end_state.contact
          debug:
            msg: '{{ output.end_state.contact }}'
```

在任务级别定义的用户名和密码将覆盖 playbook 级别的用户名和密码。当尝试连接时，如果用户在设备上不存在，我将收到以下错误：

```py
PLAY [Configure SNMP Contact] 
**************************************************

TASK [configure snmp contact] 
**************************************************
fatal: [switch2]: FAILED! => {"changed": false, "failed": true, 
"msg": "failed to connect to 192.168.199.149:22"}
fatal: [switch1]: FAILED! => {"changed": false, "failed": true, 
"msg": "failed to connect to 192.168.199.148:22"}
to retry, use: --limit 
@/home/echou/Master_Python_Networking/Chapter4/cisco_4.retry

PLAY RECAP 
*********************************************************************
switch1 : ok=0 changed=0 unreachable=0 failed=1
switch2 : ok=0 changed=0 unreachable=0 failed=1
```

# Ansible Cisco 示例

Ansible 中的 Cisco 支持按操作系统 IOS、IOS-XR 和 NX-OS 进行分类。我们已经看到了许多 NX-OS 的例子，所以在这一部分让我们尝试管理基于 IOS 的设备。

我们的主机文件将包括两个主机，`R1`和`R2`：

```py
[ios_devices]
R1 ansible_host=192.168.24.250
R2 ansible_host=192.168.24.251

[ios_devices:vars]
username=cisco
password=cisco
```

我们的 playbook，`cisco_5.yml`，将使用`ios_command`模块来执行任意的`show commands`：

```py
    ---
    - name: IOS Show Commands
      hosts: "ios_devices"
      gather_facts: false
      connection: local

      vars:
        cli:
          host: "{{ ansible_host }}"
          username: "{{ username }}"
          password: "{{ password }}"
          transport: cli

      tasks:
        - name: ios show commands
          ios_command:
            commands:
              - show version | i IOS
              - show run | i hostname
            provider: "{{ cli }}"

          register: output

        - name: show output in output["end_state"]["contact"]
          debug:
            var: output
```

结果是我们期望的`show version`和`show run`输出：

```py
 $ ansible-playbook -i ios_hosts cisco_5.yml

 PLAY [IOS Show Commands] 
 *******************************************************

 TASK [ios show commands] 
 *******************************************************
 ok: [R1]
 ok: [R2]

 TASK [show output in output["end_state"]["contact"]] 
 ***************************
 ok: [R1] => {
 "output": {
 "changed": false,
 "stdout": [
 "Cisco IOS Software, 7200 Software (C7200-A3JK9S-M), Version 
 12.4(25g), RELEASE SOFTWARE (fc1)",
 "hostname R1"
 ],
 "stdout_lines": [
 [
 "Cisco IOS Software, 7200 Software (C7200-A3JK9S-M), Version 
 12.4(25g), RELEASE SOFTWARE (fc1)"
 ],
 [
 "hostname R1"
 ]
 ]
 }
 }
 ok: [R2] => {
 "output": {
 "changed": false,
 "stdout": [
 "Cisco IOS Software, 7200 Software (C7200-A3JK9S-M), Version 
 12.4(25g), RELEASE SOFTWARE (fc1)",
 "hostname R2"
 ],
 "stdout_lines": [
 [
 "Cisco IOS Software, 7200 Software (C7200-A3JK9S-M), Version 
 12.4(25g), RELEASE SOFTWARE (fc1)"
 ],
 [
 "hostname R2"
 ]
 ]
 }
 }

 PLAY RECAP 
 *********************************************************************
 R1 : ok=2 changed=0 unreachable=0 failed=0
 R2 : ok=2 changed=0 unreachable=0 failed=0
```

我想指出这个例子所说明的一些事情：

+   NXOS 和 IOS 之间的 playbook 基本相同

+   `nxos_snmp_contact`和`ios_command`模块的语法遵循相同的模式，唯一的区别是模块的参数

+   设备的 IOS 版本非常古老，不理解 API，但模块仍然具有相同的外观和感觉

正如您从前面的例子中所看到的，一旦我们掌握了 playbook 的基本语法，微妙的差异在于我们想要执行的任务的不同模块。

# Ansible 2.5 连接示例

我们简要讨论了 Ansible playbook 中网络连接更改的添加，从版本 2.5 开始。随着这些变化，Ansible 还发布了一个网络最佳实践文档。让我们根据最佳实践指南构建一个例子。对于我们的拓扑，我们将重用第二章中的拓扑，其中有两个 IOSv 设备。由于这个例子涉及多个文件，这些文件被分组到一个名为`ansible_2-5_example`的子目录中。

我们的清单文件减少到组和主机的名称：

```py
$ cat hosts
[ios-devices]
iosv-1
iosv-2
```

我们创建了一个`host_vars`目录，其中包含两个文件。每个文件对应清单文件中指定的名称：

```py
$ ls -a host_vars/
. .. iosv-1 iosv-2
```

主机的变量文件包含了之前包含在 CLI 变量中的内容。`ansible_connection`的额外变量指定了`network_cli`作为传输方式：

```py
$ cat host_vars/iosv-1
---
ansible_host: 172.16.1.20
ansible_user: cisco
ansible_ssh_pass: cisco
***ansible_connection: network_cli***
ansible_network_os: ios
ansbile_become: yes
ansible_become_method: enable
ansible_become_pass: cisco

$ cat host_vars/iosv-2
---
ansible_host: 172.16.1.21
ansible_user: cisco
ansible_ssh_pass: cisco
***ansible_connection: network_cli***
ansible_network_os: ios
ansbile_become: yes
ansible_become_method: enable
ansible_become_pass: cisco
```

我们的 playbook 将使用`ios_config`模块，并启用`backup`选项。请注意，在这个例子中使用了`when`条件，以便如果有其他操作系统的主机，这个任务将不会被应用：

```py
$ cat my_playbook.yml
---
- name: Chapter 4 Ansible 2.5 Best Practice Demonstration
 ***connection: network_cli***
 gather_facts: false
 hosts: all
 tasks:
 - name: backup
 ios_config:
 backup: yes
 register: backup_ios_location
 ***when: ansible_network_os == 'ios'***
```

当 playbook 运行时，将为每个主机创建一个新的备份文件夹，其中包含备份的配置：

```py
$ ansible-playbook -i hosts my_playbook.yml

PLAY [Chapter 4 Ansible 2.5 Best Practice Demonstration] ***********************

TASK [backup] ******************************************************************
ok: [iosv-2]
ok: [iosv-1]

PLAY RECAP *********************************************************************
iosv-1 : ok=1 changed=0 unreachable=0 failed=0
iosv-2 : ok=1 changed=0 unreachable=0 failed=0

$ ls -l backup/
total 8
-rw-rw-r-- 1 echou echou 3996 Jul 11 19:01 iosv-1_config.2018-07-11@19:01:55
-rw-rw-r-- 1 echou echou 3996 Jul 11 19:01 iosv-2_config.2018-07-11@19:01:55

$ cat backup/iosv-1_config.2018-07-11@19\:01\:55
Building configuration...

Current configuration : 3927 bytes
!
! Last configuration change at 01:46:00 UTC Thu Jul 12 2018 by cisco
!
version 15.6
service timestamps debug datetime msec
service timestamps log datetime msec
...
```

这个例子说明了`network_connection`变量和基于网络最佳实践的推荐结构。我们将在第五章中将变量转移到`host_vars`目录中，并使用条件语句。这种结构也可以用于本章中的 Juniper 和 Arista 示例。对于不同的设备，我们只需为`network_connection`使用不同的值。

# Ansible Juniper 示例

Ansible Juniper 模块需要 Juniper PyEZ 包和 NETCONF。如果你一直在关注第三章中的 API 示例，你就可以开始了。如果没有，请参考该部分以获取安装说明，以及一些测试脚本来确保 PyEZ 正常工作。还需要 Python 包`jxmlease`：

```py
$ sudo pip install jxmlease
```

在主机文件中，我们将指定设备和连接变量：

```py
[junos_devices]
J1 ansible_host=192.168.24.252

[junos_devices:vars]
username=juniper
password=juniper!
```

在我们的 Juniper playbook 中，我们将使用`junos_facts`模块来收集设备的基本信息。这个模块相当于 setup 模块，如果我们需要根据返回的值采取行动，它会很方便。请注意这里的传输和端口的不同值：

```py
    ---
    - name: Get Juniper Device Facts
      hosts: "junos_devices"
      gather_facts: false
      connection: local

      vars:
        netconf:
          host: "{{ ansible_host }}"
          username: "{{ username }}"
          password: "{{ password }}"
          port: 830
          transport: netconf

      tasks:
        - name: collect default set of facts
          junos_facts:
            provider: "{{ netconf }}"

          register: output

        - name: show output
          debug:
            var: output
```

执行时，你会从`Juniper`设备收到这个输出：

```py
PLAY [Get Juniper Device Facts] 
************************************************

TASK [collect default set of facts] 
********************************************
ok: [J1]

TASK [show output] 
*************************************************************
ok: [J1] => {
"output": {
"ansible_facts": {
"HOME": "/var/home/juniper",
"domain": "python",
"fqdn": "master.python",
"has_2RE": false,
"hostname": "master",
"ifd_style": "CLASSIC",
"model": "olive",
"personality": "UNKNOWN",
"serialnumber": "",
"switch_style": "NONE",
"vc_capable": false,
"version": "12.1R1.9",
"version_info": {
"build": 9,
"major": [
12,
1
],
"minor": "1",
"type": "R"
}
},
"changed": false
 }
}

PLAY RECAP 
*********************************************************************
J1 : ok=2 changed=0 unreachable=0 failed=0
```

# Ansible Arista 示例

我们将看一下最终的 playbook 示例，即 Arista 命令模块。此时，我们对 playbook 的语法和结构已经非常熟悉。Arista 设备可以配置为使用`cli`或`eapi`进行传输，因此在这个例子中，我们将使用`cli`。

这是主机文件：

```py
[eos_devices]
A1 ansible_host=192.168.199.158
```

playbook 也与我们之前看到的类似：

```py
    ---
 - name: EOS Show Commands
 hosts: "eos_devices"
 gather_facts: false
 connection: local

 vars:
 cli:
 host: "{{ ansible_host }}"
 username: "arista"
 password: "arista"
 authorize: true
 transport: cli

 tasks:
 - name: eos show commands
 eos_command:
 commands:
 - show version | i Arista
 provider: "{{ cli }}"
 register: output

 - name: show output
 debug:
 var: output
```

输出将显示标准输出，就像我们从命令行预期的那样：

```py
 PLAY [EOS Show Commands] 
 *******************************************************

 TASK [eos show commands] 
 *******************************************************
 ok: [A1]

 TASK [show output] 
 *************************************************************
 ok: [A1] => {
 "output": {
 "changed": false,
 "stdout": [
 "Arista DCS-7050QX-32-F"
 ],
 "stdout_lines": [
 [
 "Arista DCS-7050QX-32-F"
 ]
 ],
 "warnings": []
 }
 }

 PLAY RECAP 
 *********************************************************************
 A1 : ok=2 changed=0 unreachable=0 failed=0
```

# 总结

在本章中，我们对开源自动化框架 Ansible 进行了全面介绍。与基于 Pexpect 和 API 驱动的网络自动化脚本不同，Ansible 提供了一个更高层的抽象，称为 playbook，用于自动化我们的网络设备。

Ansible 最初是用来管理服务器的，后来扩展到网络设备；因此我们看了一个服务器的例子。然后，我们比较和对比了网络管理 playbook 的不同之处。之后，我们看了 Cisco IOS、Juniper JUNOS 和 Arista EOS 设备的示例 playbook。我们还看了 Ansible 推荐的最佳实践，如果你使用的是 Ansible 2.5 及更高版本。

在[第五章]（96b9ad57-2f08-4f0d-9b94-1abec5c55770.xhtml）中，《Python 自动化框架-超越基础知识》，我们将利用本章所学的知识，开始了解 Ansible 的一些更高级的特性。


# 第五章：Python 自动化框架-超越基础

在第一章中，*TCP/IP 协议套件和 Python 回顾*，我们看了一些基本结构，以使 Ansible 运行起来。我们使用 Ansible 清单文件、变量和 playbook。我们还看了一些使用 Cisco、Juniper 和 Arista 设备的网络模块的示例。

在本章中，我们将进一步建立在之前章节所学到的知识基础上，并深入探讨 Ansible 的更高级主题。关于 Ansible 已经写了很多书，而且 Ansible 的内容远不止我们可以在两章中涵盖的。这里的目标是介绍我认为作为网络工程师您需要的大部分 Ansible 功能和功能，并尽可能地缩短学习曲线。

需要指出的是，如果您对第四章中提出的一些观点不清楚，现在是回顾它们的好时机，因为它们是本章的先决条件。

在本章中，我们将研究以下主题：

+   Ansible 条件

+   Ansible 循环

+   模板

+   组和主机变量

+   Ansible Vault

+   Ansible 角色

+   编写自己的模块

我们有很多内容要涵盖，所以让我们开始吧！

# Ansible 条件

Ansible 条件类似于编程语言中的条件语句。在第一章中，*TCP/IP 协议套件和 Python 回顾*，我们看到 Python 使用条件语句只执行代码的一部分，使用`if.. then`或`while`语句。在 Ansible 中，它使用条件关键字只有在条件满足时才运行任务。在许多情况下，play 或任务的执行可能取决于事实、变量或上一个任务的结果。例如，如果您有一个升级路由器镜像的 play，您希望包括一步来确保新的路由器镜像在移动到下一个重启路由器的 play 之前已经在设备上。

在本节中，我们将讨论`when`子句，它支持所有模块，以及在 Ansible 网络命令模块中支持的独特条件状态。一些条件如下：

+   等于（`eq`）

+   不等于（`neq`）

+   大于（`gt`）

+   大于或等于（`ge`）

+   小于（`lt`）

+   小于或等于（`le`）

+   包含

# when 子句

`when`子句在您需要检查变量或 play 执行结果的输出并相应地采取行动时非常有用。我们在第四章中看到了`when`子句的一个快速示例，*Python 自动化框架- Ansible 基础*，当我们查看 Ansible 2.5 最佳实践结构时。如果您还记得，只有当设备的网络操作系统是 Cisco IOS 时，任务才会运行。让我们在`chapter5_1.yml`中看另一个使用它的例子：

```py
    ---
    - name: IOS Command Output
      hosts: "iosv-devices"
      gather_facts: false
      connection: local
      vars:
        cli:
          host: "{{ ansible_host }}"
          username: "{{ username }}"
          password: "{{ password }}"
          transport: cli
      tasks:
        - name: show hostname
          ios_command:
            commands:
              - show run | i hostname
                provider: "{{ cli }}"
            register: output
        - name: show output
          when: '"iosv-2" in "{{ output.stdout }}"'
          debug:
            msg: '{{ output }}'
```

我们在这个 playbook 中看到了之前在第四章中的所有元素，*Python 自动化框架- Ansible 基础**，直到第一个任务结束。在 play 的第二个任务中，我们使用`when`子句来检查输出是否包含`iosv-2`关键字。如果是，我们将继续执行任务，该任务使用 debug 模块来显示输出。当 playbook 运行时，我们将看到以下输出：

```py
    <skip>
    TASK [show output]  
    *************************************************************
    skipping: [ios-r1]
 ok: [ios-r2] => {
 "msg": {
 "changed": false,
 "stdout": [
 "hostname iosv-2"
 ],
 "stdout_lines": [
 [
 "hostname iosv-2"
 ]
 ],
 "warnings": []
 }
 }
    <skip>
```

我们可以看到`iosv-r1`设备被跳过了，因为条件没有通过。我们可以在`chapter5_2.yml`中进一步扩展这个例子，只有当条件满足时才应用某些配置更改：

```py
    <skip> 
    tasks:
      - name: show hostname
        ios_command:
          commands:
            - show run | i hostname
          provider: "{{ cli }}"
        register: output
      - name: config example
        when: '"iosv-2" in "{{ output.stdout }}"'
        ios_config:
          lines:
            - logging buffered 30000
          provider: "{{ cli }}"
```

我们可以在这里看到执行输出：

```py
 TASK [config example] 
 **********************************************************
 skipping: [ios-r1]
 changed: [ios-r2] 
 PLAY RECAP 
 ***********************************************************
 ios-r1 : ok=1 changed=0 unreachable=0 failed=0
 ios-r2 : ok=2 changed=1 unreachable=0 failed=0
```

再次注意执行输出中`ios-r2`是唯一应用的更改，而`ios-r1`被跳过。在这种情况下，日志缓冲区大小只在`ios-r2`上更改。

`when`子句在使用设置或事实模块时也非常有用-您可以根据最初收集的一些`事实`来采取行动。例如，以下语句将确保只有主要版本为`16`的 Ubuntu 主机将受到条件语句的影响：

```py
when: ansible_os_family == "Debian" and ansible_lsb.major_release|int >= 16
```

有关更多条件，请查看 Ansible 条件文档([`docs.ansible.com/ansible/playbooks_conditionals.html`](http://docs.ansible.com/ansible/playbooks_conditionals.html))。

# Ansible 网络事实

在 2.5 之前，Ansible 网络配送了许多特定于网络的事实模块。网络事实模块存在，但供应商之间的命名和使用方式不同。从 2.5 版本开始，Ansible 开始标准化其网络事实模块的使用。Ansible 网络事实模块从系统中收集信息，并将结果存储在以`ansible_net_`为前缀的事实中。这些模块收集的数据在模块文档中有记录的*返回值*中。这对于 Ansible 网络模块来说是一个相当重要的里程碑，因为它默认情况下可以为您抽象出事实收集过程的大部分繁重工作。

让我们使用在第四章中看到的相同结构，*Python 自动化框架- Ansible 基础*，Ansible 2.5 最佳实践，但扩展它以查看`ios_facts`模块如何用于收集事实。回顾一下，我们的清单文件包含两个 iOS 主机，主机变量驻留在`host_vars`目录中：

```py
$ cat hosts
[ios-devices]
iosv-1
iosv-2

$ cat host_vars/iosv-1
---
ansible_host: 172.16.1.20
ansible_user: cisco
ansible_ssh_pass: cisco
ansible_connection: network_cli
ansible_network_os: ios
ansbile_become: yes
ansible_become_method: enable
ansible_become_pass: cisco
```

我们的 playbook 将有三个任务。第一个任务将使用`ios_facts`模块为我们的两个网络设备收集事实。第二个任务将显示为每个设备收集和存储的某些事实。您将看到我们显示的事实是默认的`ansible_net`事实，而不是来自第一个任务的已注册变量。第三个任务将显示我们为`iosv-1`主机收集的所有事实：

```py
$ cat my_playbook.yml
---
- name: Chapter 5 Ansible 2.5 network facts
 connection: network_cli
 gather_facts: false
 hosts: all
 tasks:
 - name: Gathering facts via ios_facts module
 ios_facts:
 when: ansible_network_os == 'ios'

 - name: Display certain facts
 debug:
 msg: "The hostname is {{ ansible_net_hostname }} running {{ ansible_net_version }}"

 - name: Display all facts for a host
 debug:
 var: hostvars['iosv-1']
```

当我们运行 playbook 时，您会看到前两个任务的结果是我们预期的：

```py
$ ansible-playbook -i hosts my_playbook.yml

PLAY [Chapter 5 Ansible 2.5 network facts] *************************************

TASK [Gathering facts via ios_facts module] ************************************
ok: [iosv-2]
ok: [iosv-1]

TASK [Display certain facts] ***************************************************
ok: [iosv-2] => {
 "msg": "The hostname is iosv-2 running 15.6(3)M2"
}
ok: [iosv-1] => {
 "msg": "The hostname is iosv-1 running 15.6(3)M2"
}
```

第三个任务将显示为 iOS 设备收集的所有网络设备事实。已经收集了大量有关 iOS 设备的信息，可以帮助您进行网络自动化需求：

```py
TASK [Display all facts for a host] ********************************************
ok: [iosv-1] => {
 "hostvars['iosv-1']": {
 "ansbile_become": true,
 "ansible_become_method": "enable",
 "ansible_become_pass": "cisco",
 "ansible_check_mode": false,
 "ansible_connection": "network_cli",
 "ansible_diff_mode": false,
 "ansible_facts": {
 "net_all_ipv4_addresses": [
 "10.0.0.5",
 "172.16.1.20",
 "192.168.0.1"
 ],
 "net_all_ipv6_addresses": [],
 "net_filesystems": [
 "flash0:"
 ],
 "net_gather_subset": [
 "hardware",
 "default",
 "interfaces"
 ],
 "net_hostname": "iosv-1",
 "net_image": "flash0:/vios-adventerprisek9-m",
 "net_interfaces": {
 "GigabitEthernet0/0": {
 "bandwidth": 1000000,
 "description": "OOB Management",
 "duplex": "Full",
 "ipv4": [
 {
 "address": "172.16.1.20",
 "subnet": "24"
 }
[skip]
```

Ansible 2.5 中的网络事实模块是简化工作流程的重要一步，并使其与其他服务器模块齐头并进。

# 网络模块条件

让我们通过使用我们在本章开头看到的比较关键字来查看另一个网络设备条件示例。我们可以利用 IOSv 和 Arista EOS 都以 JSON 格式提供`show`命令的输出这一事实。例如，我们可以检查接口的状态：

```py
 arista1#sh interfaces ethernet 1/3 | json
 {
 "interfaces": {
 "Ethernet1/3": {
 "interfaceStatistics": {
 <skip>
 "outPktsRate": 0.0
 },
 "name": "Ethernet1/3",
 "interfaceStatus": "disabled",
 "autoNegotiate": "off",
 <skip>
 }
 arista1#
```

如果我们有一个操作要执行，并且它取决于`Ethernet1/3`被禁用以确保没有用户影响，比如确保没有用户连接到`Ethernet1/3`，我们可以在`chapter5_3.yml`剧本中使用以下任务。它使用`eos_command`模块来收集接口状态输出，并在继续下一个任务之前使用`waitfor`和`eq`关键字来检查接口状态：

```py
    <skip>
     tasks:
       - name: "sh int ethernet 1/3 | json"
         eos_command:
           commands:
             - "show interface ethernet 1/3 | json"
           provider: "{{ cli }}"
           waitfor:
             - "result[0].interfaces.Ethernet1/3.interfaceStatus eq 
    disabled"
         register: output
       - name: show output
         debug:
           msg: "Interface Disabled, Safe to Proceed"
```

在满足条件后，将执行第二个任务：

```py
 TASK [sh int ethernet 1/3 | json] 
 **********************************************
 ok: [arista1]

 TASK [show output] 
 *************************************************************
 ok: [arista1] => {
 "msg": "Interface Disabled, Safe to Proceed"
 }
```

如果接口处于活动状态，则将在第一个任务后给出错误如下：

```py
 TASK [sh int ethernet 1/3 | json] 
 **********************************************
 fatal: [arista1]: FAILED! => {"changed": false, "commands": ["show 
 interface ethernet 1/3 | json | json"], "failed": true, "msg": 
 "matched error in response: show interface ethernet 1/3 | json | 
 jsonrn% Invalid input (privileged mode required)rn********1>"}
 to retry, use: --limit 
 @/home/echou/Master_Python_Networking/Chapter5/chapter5_3.retry

 PLAY RECAP 
 ******************************************************************
 arista1 : ok=0 changed=0 unreachable=0 failed=1
```

查看其他条件，如`包含`，`大于`和`小于`，因为它们符合您的情况。

# Ansible 循环

Ansible 在 playbook 中提供了许多循环，例如标准循环，循环文件，子元素，do-until 等等。在本节中，我们将看两种最常用的循环形式：标准循环和循环哈希值。

# 标准循环

playbook 中的标准循环经常用于轻松多次执行类似任务。标准循环的语法非常简单：`{{ item }}`变量是在`with_items`列表上循环的占位符。例如，看一下`chapter5_4.yml` playbook 中的以下部分：

```py
      tasks:
        - name: echo loop items
          command: echo {{ item }}
          with_items: ['r1', 'r2', 'r3', 'r4', 'r5']   
```

它将使用相同的`echo`命令循环遍历五个列表项：

```py
TASK [echo loop items] *********************************************************
changed: [192.168.199.185] => (item=r1)
changed: [192.168.199.185] => (item=r2)
changed: [192.168.199.185] => (item=r3)
changed: [192.168.199.185] => (item=r4)
changed: [192.168.199.185] => (item=r5)
```

我们将在`chapter5_5.yml` playbook 中将标准循环与网络命令模块相结合，以向设备添加多个 VLAN：

```py
 tasks:
   - name: add vlans
     eos_config:
       lines:
           - vlan {{ item }}
       provider: "{{ cli }}"
     with_items:
         - 100
         - 200
         - 300
```

`with_items`列表也可以从变量中读取，这样可以更灵活地构建 playbook 的结构：

```py
vars:
  vlan_numbers: [100, 200, 300]
<skip>
tasks:
  - name: add vlans
    eos_config:
      lines:
          - vlan {{ item }}
      provider: "{{ cli }}"
    with_items: "{{ vlan_numbers }}"
```

标准循环在执行 playbook 中的冗余任务时是一个很好的时间节省器。它还通过减少任务所需的行数使 playbook 更易读。

在下一节中，我们将看看如何循环遍历字典。

# 循环遍历字典

循环遍历一个简单的列表很好。然而，我们经常有一个带有多个属性的实体。如果您考虑上一节中的`vlan`示例，每个`vlan`都会有一些独特的属性，比如`vlan`描述，网关 IP 地址，可能还有其他属性。通常，我们可以使用字典来表示实体，以将多个属性合并到其中。

让我们在上一节中的`vlan`示例中扩展为`chapter5_6.yml`中的字典示例。我们为三个`vlan`定义了字典值，每个值都有一个嵌套字典，用于描述和 IP 地址：

```py
    <skip> 
    vars:
       cli:
         host: "{{ ansible_host }}"
         username: "{{ username }}"
         password: "{{ password }}"
         transport: cli
       vlans: {
           "100": {"description": "floor_1", "ip": "192.168.10.1"},
           "200": {"description": "floor_2", "ip": "192.168.20.1"}
           "300": {"description": "floor_3", "ip": "192.168.30.1"}
       }
```

我们可以通过使用每个项目的键作为`vlan`号来配置第一个任务`add vlans`：

```py
     tasks:
       - name: add vlans
         nxos_config:
           lines:
             - vlan {{ item.key }}
           provider: "{{ cli }}"
         with_dict: "{{ vlans }}"
```

我们可以继续配置`vlan`接口。请注意，我们使用`parents`参数来唯一标识应该针对哪个部分检查命令。这是因为描述和 IP 地址都是在配置中的`interface vlan <number>`子部分下配置的：

```py
  - name: configure vlans
    nxos_config:
       lines:
         - description {{ item.value.name }}
         - ip address {{ item.value.ip }}/24
       provider: "{{ cli }}"
       parents: interface vlan {{ item.key }}
    with_dict: "{{ vlans }}"
```

执行时，您将看到字典被循环遍历：

```py
TASK [configure vlans] *********************************************************
changed: [nxos-r1] => (item={'key': u'300', 'value': {u'ip': u'192.168.30.1', u'name': u'floor_3'}})
changed: [nxos-r1] => (item={'key': u'200', 'value': {u'ip': u'192.168.20.1', u'name': u'floor_2'}})
changed: [nxos-r1] => (item={'key': u'100', 'value': {u'ip': u'192.168.10.1', u'name': u'floor_1'}})
```

让我们检查所需的配置是否应用到设备上：

```py
nx-osv-1# sh run | i vlan
<skip>
vlan 1,10,100,200,300
nx-osv-1#
```

```py
nx-osv-1# sh run | section "interface Vlan100"
interface Vlan100
 description floor_1
 ip address 192.168.10.1/24
nx-osv-1#
```

有关 Ansible 的更多循环类型，请随时查看文档（[`docs.ansible.com/ansible/playbooks_loops.html`](http://docs.ansible.com/ansible/playbooks_loops.html)）。

循环遍历字典在第一次使用时需要一些练习。但就像标准循环一样，循环遍历字典将成为您工具箱中的一个宝贵工具。

# 模板

就我所记，作为一名网络工程师，我一直在使用一种网络模板。根据我的经验，许多网络设备的网络配置部分是相同的，特别是如果这些设备在网络中担任相同的角色。

大多数情况下，当我们需要为新设备进行配置时，我们使用相同的模板形式的配置，替换必要的字段，并将文件复制到新设备上。使用 Ansible，您可以使用模板模块（[`docs.ansible.com/ansible/template_module.html`](http://docs.ansible.com/ansible/template_module.html)）自动化所有工作。

我们正在使用的基本模板文件利用了 Jinja2 模板语言（[`jinja.pocoo.org/docs/`](http://jinja.pocoo.org/docs/)）。我们在第四章中简要讨论了 Jinja2 模板语言，*Python 自动化框架- Ansible 基础*，我们将在这里更多地了解它。就像 Ansible 一样，Jinja2 有自己的语法和循环和条件的方法；幸运的是，我们只需要了解它的基础知识就足够了。Ansible 模板是我们日常任务中将要使用的重要工具，我们将在本节中更多地探索它。我们将通过逐渐从简单到更复杂地构建我们的 playbook 来学习语法。

模板使用的基本语法非常简单；你只需要指定源文件和要复制到的目标位置。

现在我们将创建一个空文件：

```py
$ touch file1
```

然后，我们将使用以下 playbook 将`file1`复制到`file2`。请注意，playbook 仅在控制机上执行。接下来，我们将为`template`模块的参数指定源文件和目标文件的路径：

```py
---
- name: Template Basic
  hosts: localhost

  tasks:
    - name: copy one file to another
      template:
        src=./file1
        dest=./file2
```

在 playbook 执行期间，我们不需要指定主机文件，因为默认情况下 localhost 是可用的。但是，你会收到一个警告：

```py
$ ansible-playbook chapter5_7.yml
 [WARNING]: provided hosts list is empty, only localhost is available
<skip>
TASK [copy one file to another] ************************************************

changed: [localhost]
<skip>
```

源文件可以有任何扩展名，但由于它们是通过 Jinja2 模板引擎处理的，让我们创建一个名为`nxos.j2`的文本文件作为模板源。模板将遵循 Jinja2 的惯例，使用双大括号来指定变量：

```py
    hostname {{ item.value.hostname }}
    feature telnet
    feature ospf
    feature bgp
    feature interface-vlan

    username {{ item.value.username }} password {{ item.value.password 
    }} role network-operator
```

# Jinja2 模板

让我们也相应地修改 playbook。在`chapter5_8.yml`中，我们将进行以下更改：

1.  将源文件更改为`nxos.j2`

1.  将目标文件更改为一个变量

1.  提供作为字典的变量值，我们将在模板中进行替换：

```py
    ---
    - name: Template Looping
      hosts: localhost

      vars:
        nexus_devices: {
          "nx-osv-1": {"hostname": "nx-osv-1", "username": "cisco", 
    "password": "cisco"}
        }

      tasks:
        - name: create router configuration files
          template:
            src=./nxos.j2
            dest=./{{ item.key }}.conf
          with_dict: "{{ nexus_devices }}"
```

运行 playbook 后，你会发现名为`nx-osv-1.conf`的目标文件已经填充好，可以使用了：

```py
$ cat nx-osv-1.conf
hostname nx-osv-1

feature telnet
feature ospf
feature bgp
feature interface-vlan

username cisco password cisco role network-operator
```

# Jinja2 循环

我们还可以在 Jinja2 中循环遍历列表和字典。我们将在`nxos.j2`中使用这两种循环：

```py
    {% for vlan_num in item.value.vlans %}
    vlan {{ vlan_num }}
    {% endfor %}

    {% for vlan_interface in item.value.vlan_interfaces %}
    interface {{ vlan_interface.int_num }}
      ip address {{ vlan_interface.ip }}/24
    {% endfor %}
```

在`chapter5_8.yml` playbook 中提供额外的列表和字典变量：

```py
   vars:
     nexus_devices: {
       "nx-osv-1": {
       "hostname": "nx-osv-1",
       "username": "cisco",
       "password": "cisco",
       "vlans": [100, 200, 300],
       "vlan_interfaces": [
          {"int_num": "100", "ip": "192.168.10.1"},
          {"int_num": "200", "ip": "192.168.20.1"},
          {"int_num": "300", "ip": "192.168.30.1"}
        ]
       }
     }
```

运行 playbook，你会看到路由器配置中`vlan`和`vlan_interfaces`的配置都已填写好。

# Jinja2 条件

Jinja2 还支持`if`条件检查。让我们在某些设备上打开 netflow 功能的字段中添加这个条件。我们将在`nxos.j2`模板中添加以下内容：

```py
    {% if item.value.netflow_enable %}
    feature netflow
    {% endif %}
```

我们将列出 playbook 中的差异：

```py
    vars:
      nexus_devices: {
      <skip>
             "netflow_enable": True
      <skip>
     }
```

我们将采取的最后一步是通过将`nxos.j2`放置在`true-false`条件检查中，使其更具可扩展性。在现实世界中，我们往往会有多个设备了解`vlan`信息，但只有一个设备作为客户端主机的网关：

```py
    {% if item.value.l3_vlan_interfaces %}
    {% for vlan_interface in item.value.vlan_interfaces %}
    interface {{ vlan_interface.int_num }}
     ip address {{ vlan_interface.ip }}/24
    {% endfor %}
    {% endif %}
```

我们还将在 playbook 中添加第二个设备，名为`nx-osv-2`：

```py
     vars:
       nexus_devices: {
       <skip>
         "nx-osv-2": {
           "hostname": "nx-osv-2",
           "username": "cisco",
           "password": "cisco",
           "vlans": [100, 200, 300],
           "l3_vlan_interfaces": False,
           "netflow_enable": False
         }
        <skip>
     }
```

我们现在准备运行我们的 playbook：

```py
$ ansible-playbook chapter5_8.yml
 [WARNING]: provided hosts list is empty, only localhost is available. Note
that the implicit localhost does not match 'all'

PLAY [Template Looping] ********************************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [create router configuration files] ***************************************
ok: [localhost] => (item={'value': {u'username': u'cisco', u'password': u'cisco', u'hostname': u'nx-osv-2', u'netflow_enable': False, u'vlans': [100, 200, 300], u'l3_vlan_interfaces': False}, 'key': u'nx-osv-2'})
ok: [localhost] => (item={'value': {u'username': u'cisco', u'password': u'cisco', u'hostname': u'nx-osv-1', u'vlan_interfaces': [{u'int_num': u'100', u'ip': u'192.168.10.1'}, {u'int_num': u'200', u'ip': u'192.168.20.1'}, {u'int_num': u'300', u'ip': u'192.168.30.1'}], u'netflow_enable': True, u'vlans': [100, 200, 300], u'l3_vlan_interfaces': True}, 'key': u'nx-osv-1'})

PLAY RECAP *********************************************************************
localhost : ok=2 changed=0 unreachable=0 failed=0
```

让我们检查两个配置文件的差异，以确保条件性的更改正在发生：

```py
$ cat nx-osv-1.conf
hostname nx-osv-1

feature telnet
feature ospf
feature bgp
feature interface-vlan

feature netflow

username cisco password cisco role network-operator

vlan 100
vlan 200
vlan 300

interface 100
 ip address 192.168.10.1/24
interface 200
 ip address 192.168.20.1/24
interface 300
 ip address 192.168.30.1/24

$ cat nx-osv-2.conf
hostname nx-osv-2

feature telnet
feature ospf
feature bgp
feature interface-vlan

username cisco password cisco role network-operator

vlan 100
vlan 200
vlan 300
```

很整洁，对吧？这肯定可以为我们节省大量时间，以前需要重复复制和粘贴。对我来说，模板模块是一个重大的改变。几年前，这个模块就足以激励我学习和使用 Ansible。

我们的 playbook 变得有点长了。在下一节中，我们将看到如何通过将变量文件转移到组和目录中来优化 playbook。

# 组和主机变量

请注意，在之前的 playbook`chapter5_8.yml`中，我们在`nexus_devices`变量下的两个设备的用户名和密码变量中重复了自己：

```py
    vars:
      nexus_devices: {
        "nx-osv-1": {
          "hostname": "nx-osv-1",
          "username": "cisco",
          "password": "cisco",
          "vlans": [100, 200, 300],
        <skip>
        "nx-osv-2": {
          "hostname": "nx-osv-2",
          "username": "cisco",
          "password": "cisco",
          "vlans": [100, 200, 300],
        <skip>
```

这并不理想。如果我们需要更新用户名和密码的值，我们需要记住在两个位置更新。这增加了管理负担，也增加了出错的机会。作为最佳实践，Ansible 建议我们使用`group_vars`和`host_vars`目录来分离变量。

有关更多 Ansible 最佳实践，请查看[`docs.ansible.com/ansible/playbooks_best_practices.html`](http://docs.ansible.com/ansible/playbooks_best_practices.html)。

# 组变量

默认情况下，Ansible 将在与 playbook 同一目录中寻找组变量，称为`group_vars`，用于应用于组的变量。默认情况下，它将在清单文件中匹配组名的文件名。例如，如果我们在清单文件中有一个名为`[nexus-devices]`的组，我们可以在`group_vars`下有一个名为`nexus-devices`的文件，其中包含可以应用于该组的所有变量。

我们还可以使用名为`all`的特殊文件来包含应用于所有组的变量。

我们将利用此功能来处理我们的用户名和密码变量。首先，我们将创建`group_vars`目录：

```py
$ mkdir group_vars
```

然后，我们可以创建一个名为`all`的 YAML 文件来包含用户名和密码：

```py
$ cat group_vars/all
---
username: cisco
password: cisco
```

然后我们可以在 playbook 中使用变量：

```py
    vars:
      nexus_devices: {
       "nx-osv-1": {
          "hostname": "nx-osv-1",
          "username": "{{ username }}",
          "password": "{{ password }}",
          "vlans": [100, 200, 300],
        <skip>
         "nx-osv-2": {
          "hostname": "nx-osv-2",
          "username": "{{ username }}",
          "password": "{{ password }}",
          "vlans": [100, 200, 300],
        <skip>
```

# 主机变量

我们可以进一步以与组变量相同的格式分离主机变量。这就是我们能够在第四章中应用变量的 Ansible 2.5 playbook 示例以及本章前面部分的方法：

```py
$ mkdir host_vars
```

在我们的情况下，我们在本地主机上执行命令，因此`host_vars`下的文件应该相应地命名，例如`host_vars/localhost`。在我们的`host_vars/localhost`文件中，我们还可以保留在`group_vars`中声明的变量：

```py
$ cat host_vars/localhost
---
"nexus_devices":
 "nx-osv-1":
 "hostname": "nx-osv-1"
 "username": "{{ username }}"
 "password": "{{ password }}"
 "vlans": [100, 200, 300]
 "l3_vlan_interfaces": True
 "vlan_interfaces": [
 {"int_num": "100", "ip": "192.168.10.1"},
 {"int_num": "200", "ip": "192.168.20.1"},
 {"int_num": "300", "ip": "192.168.30.1"}
 ]
 "netflow_enable": True

 "nx-osv-2":
 "hostname": "nx-osv-2"
 "username": "{{ username }}"
 "password": "{{ password }}"
 "vlans": [100, 200, 300]
 "l3_vlan_interfaces": False
 "netflow_enable": False
```

在我们分离变量之后，playbook 现在变得非常轻量，只包含我们操作的逻辑：

```py
 $ cat chapter5_9.yml
 ---
 - name: Ansible Group and Host Variables
 hosts: localhost

 tasks:
 - name: create router configuration files
 template:
 src=./nxos.j2
 dest=./{{ item.key }}.conf
 with_dict: "{{ nexus_devices }}"
```

`group_vars`和`host_vars`目录不仅减少了我们的操作开销，还可以通过允许我们使用 Ansible Vault 加密敏感信息来帮助保护文件，接下来我们将看一下。

# Ansible Vault

从前一节中可以看出，在大多数情况下，Ansible 变量提供敏感信息，如用户名和密码。最好在变量周围采取一些安全措施，以便我们可以对其进行保护。Ansible Vault（[`docs.ansible.com/ansible/2.5/user_guide/vault.html`](https://docs.ansible.com/ansible/2.5/user_guide/vault.html)）为文件提供加密，使其呈现为明文。

所有 Ansible Vault 函数都以`ansible-vault`命令开头。您可以通过 create 选项手动创建加密文件。系统会要求您输入密码。如果您尝试查看文件，您会发现文件不是明文。如果您已经下载了本书的示例，我使用的密码只是单词*password*：

```py
$ ansible-vault create secret.yml
Vault password: <password>

$ cat secret.yml
$ANSIBLE_VAULT;1.1;AES256
336564626462373962326635326361323639323635353630646665656430353261383737623<skip>653537333837383863636530356464623032333432386139303335663262
3962
```

编辑或查看加密文件，我们将使用`edit`选项编辑或通过`view`选项查看文件：

```py
$ ansible-vault edit secret.yml 
Vault password:

$ ansible-vault view secret.yml 
Vault password:
```

让我们加密`group_vars/all`和`host_vars/localhost`变量文件：

```py
$ ansible-vault encrypt group_vars/all host_vars/localhost
Vault password:
Encryption successful
```

现在，当我们运行 playbook 时，我们将收到解密失败的错误消息：

```py
ERROR! Decryption failed on /home/echou/Master_Python_Networking/Chapter5/Vaults/group_vars/all
```

当我们运行 playbook 时，我们需要使用`--ask-vault-pass`选项：

```py
$ ansible-playbook chapter5_10.yml --ask-vault-pass
Vault password:
```

对于任何访问的 Vault 加密文件，解密将在内存中进行。

在 Ansible 2.4 之前，Ansible Vault 要求所有文件都使用相同的密码进行加密。自 Ansible 2.4 及以后版本，您可以使用 vault ID 来提供不同的密码文件（[`docs.ansible.com/ansible/2.5/user_guide/vault.html#multiple-vault-passwords`](https://docs.ansible.com/ansible/2.5/user_guide/vault.html#multiple-vault-passwords)）。

我们还可以将密码保存在文件中，并确保特定文件具有受限权限：

```py
$ chmod 400 ~/.vault_password.txt
$ ls -lia ~/.vault_password.txt 
809496 -r-------- 1 echou echou 9 Feb 18 12:17 /home/echou/.vault_password.txt
```

然后，我们可以使用`--vault-password-file`选项执行 playbook：

```py
$ ansible-playbook chapter5_10.yml --vault-password-file ~/.vault_password.txt
```

我们还可以仅加密一个字符串，并使用`encrypt_string`选项将加密的字符串嵌入到 playbook 中（[`docs.ansible.com/ansible/2.5/user_guide/vault.html#use-encrypt-string-to-create-encrypted-variables-to-embed-in-yaml`](https://docs.ansible.com/ansible/2.5/user_guide/vault.html#use-encrypt-string-to-create-encrypted-variables-to-embed-in-yaml)）：

```py
$ ansible-vault encrypt_string
New Vault password:
Confirm New Vault password:
Reading plaintext input from stdin. (ctrl-d to end input)
new_user_password
!vault |
 $ANSIBLE_VAULT;1.1;AES256
 616364386438393262623139623561613539656664383834643338323966623836343737373361326134663232623861313338383534613865303864616364380a626365393665316133616462643831653332663263643734363863666632636464636563616265303665626364636562316635636462323135663163663331320a62356361326639333165393962663962306630303761656435633966633437613030326633336438366264626464366138323666376239656633623233353832

Encryption successful
```

然后可以将字符串放置在 playbook 文件中作为变量。在下一节中，我们将使用`include`和`roles`进一步优化我们的 playbook。

# Ansible 包括和角色

处理复杂任务的最佳方法是将它们分解成更小的部分。当然，这种方法在 Python 和网络工程中都很常见。在 Python 中，我们将复杂的代码分解成函数、类、模块和包。在网络中，我们也将大型网络分成机架、行、集群和数据中心等部分。在 Ansible 中，我们可以使用`roles`和`includes`将大型 playbook 分割和组织成多个文件。拆分大型 Ansible playbook 简化了结构，因为每个文件都专注于较少的任务。它还允许 playbook 的各个部分被重复使用。

# Ansible 包含语句

随着 playbook 的规模不断增长，最终会显而易见，许多任务和操作可以在不同的 playbook 之间共享。Ansible`include`语句类似于许多 Linux 配置文件，只是告诉机器扩展文件的方式与直接编写文件的方式相同。我们可以在 playbook 和任务中使用 include 语句。在这里，我们将看一个扩展我们任务的简单示例。

假设我们想要显示两个不同 playbook 的输出。我们可以制作一个名为`show_output.yml`的单独的 YAML 文件作为附加任务：

```py
    ---
    - name: show output
        debug:
          var: output
```

然后，我们可以在多个 playbook 中重用此任务，例如在`chapter5_11_1.yml`中，它与上一个 playbook 几乎相同，只是在最后注册输出和包含语句方面有所不同：

```py
    ---
    - name: Ansible Group and Host Varibles
      hosts: localhost

      tasks:
        - name: create router configuration files
          template:
            src=./nxos.j2
            dest=./{{ item.key }}.conf
          with_dict: "{{ nexus_devices }}"
          register: output

        - include: show_output.yml
```

另一个 playbook，`chapter5_11_2.yml`，可以以相同的方式重用`show_output.yml`：

```py
    ---
    - name: show users
      hosts: localhost

      tasks:
        - name: show local users
          command: who
          register: output

        - include: show_output.yml
```

请注意，两个 playbook 使用相同的变量名`output`，因为在`show_output.yml`中，我们为简单起见硬编码了变量名。您还可以将变量传递到包含的文件中。

# Ansible 角色

Ansible 角色将逻辑功能与物理主机分开，以更好地适应您的网络。例如，您可以构建角色，如 spines、leafs、core，以及 Cisco、Juniper 和 Arista。同一物理主机可以属于多个角色；例如，设备可以同时属于 Juniper 和核心。这种灵活性使我们能够执行操作，例如升级所有 Juniper 设备，而不必担心设备在网络层中的位置。

Ansible 角色可以根据已知的文件基础结构自动加载某些变量、任务和处理程序。关键是这是一个已知的文件结构，我们会自动包含。实际上，您可以将角色视为 Ansible 预先制作的`include`语句。

Ansible playbook 角色文档（[`docs.ansible.com/ansible/playbooks_roles.html#roles`](http://docs.ansible.com/ansible/playbooks_roles.html#roles)）描述了我们可以配置的角色目录列表。我们不需要使用所有这些目录。在我们的示例中，我们只会修改“tasks 和 vars”文件夹。但是，了解 Ansible 角色目录结构中所有可用选项是很好的。

以下是我们将用作角色示例的内容：

```py
├── chapter5_12.yml
├── chapter5_13.yml
├── hosts
└── roles
 ├── cisco_nexus
 │   ├── defaults
 │   ├── files
 │   ├── handlers
 │   ├── meta
 │   ├── tasks
 │   │   └── main.yml
 │   ├── templates
 │   └── vars
 │       └── main.yml
 └── spines
 ├── defaults
 ├── files
 ├── handlers
 ├── tasks
 │   └── main.yml
 ├── templates
 └── vars
 └── main.yml
```

您可以看到，在顶层，我们有主机文件以及 playbooks。我们还有一个名为`roles`的文件夹。在文件夹内，我们定义了两个角色：`cisco_nexus`和`spines`。大多数角色下的子文件夹都是空的，除了“tasks 和 vars”文件夹。每个文件夹内都有一个名为`main.yml`的文件。这是默认行为：main.yml 文件是您在 playbook 中指定角色时自动包含的入口点。如果您需要拆分其他文件，可以在 main.yml 文件中使用 include 语句。

这是我们的情景：

+   我们有两个 Cisco Nexus 设备，`nxos-r1`和`nxos-r2`。我们将为它们所有配置日志服务器以及日志链路状态，利用`cisco_nexus`角色。

+   此外，nxos-r1 也是一个脊柱设备，我们将希望配置更详细的日志记录，也许是因为脊柱在我们的网络中处于更关键的位置。

对于我们的`cisco_nexus`角色，我们在`roles/cisco_nexus/vars/main.yml`中有以下变量：

```py
---
cli:
  host: "{{ ansible_host }}"
  username: cisco
  password: cisco
  transport: cli
```

我们在`roles/cisco_nexus/tasks/main.yml`中有以下配置任务：

```py
---
- name: configure logging parameters
  nxos_config:
    lines:
      - logging server 191.168.1.100
      - logging event link-status default
    provider: "{{ cli }}"
```

我们的 playbook 非常简单，因为它只需要指定我们想要根据`cisco_nexus`角色配置的主机：

```py
---
- name: playbook for cisco_nexus role
  hosts: "cisco_nexus"
  gather_facts: false
  connection: local

  roles:
    - cisco_nexus
```

当您运行 playbook 时，playbook 将包括在`cisco_nexus`角色中定义的任务和变量，并相应地配置设备。

对于我们的`spine`角色，我们将在`roles/spines/tasks/mail.yml`中有一个额外的更详细的日志记录任务：

```py
---
- name: change logging level
  nxos_config:
    lines:
      - logging level local7 7
    provider: "{{ cli }}"
```

在我们的 playbook 中，我们可以指定它包含`cisco_nexus`角色和`spines`角色：

```py
---
- name: playbook for spine role
  hosts: "spines"
  gather_facts: false
  connection: local

  roles:
    - cisco_nexus
    - spines
```

当我们按照这个顺序包括这两个角色时，`cisco_nexus`角色任务将被执行，然后是 spines 角色：

```py
TASK [cisco_nexus : configure logging parameters] ******************************
changed: [nxos-r1]

TASK [spines : change logging level] *******************************************
ok: [nxos-r1]
```

Ansible 角色是灵活和可扩展的，就像 Python 函数和类一样。一旦您的代码增长到一定程度，将其分解成更小的部分以便维护几乎总是一个好主意。

您可以在 Ansible 示例 Git 存储库中找到更多角色的示例，网址为[`github.com/ansible/ansible-examples`](https://github.com/ansible/ansible-examples)。

**Ansible Galaxy** ([`docs.ansible.com/ansible/latest/reference_appendices/galaxy.html`](https://docs.ansible.com/ansible/latest/reference_appendices/galaxy.html))是一个免费的社区网站，用于查找、共享和协作角色。您可以在 Ansible Galaxy 上查看由 Juniper 网络提供的 Ansible 角色的示例：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/6809eca8-e5b1-4f7c-8fc6-f690fc747597.png)JUNOS Role on Ansible Galaxy ( [`galaxy.ansible.com/Juniper/junos`](https://galaxy.ansible.com/Juniper/junos))

在下一节中，我们将看一下如何编写我们自己的自定义 Ansible 模块。

# 编写您自己的自定义模块

到目前为止，您可能会感到 Ansible 中的网络管理在很大程度上取决于找到适合您任务的正确模块。这种逻辑中肯定有很多道理。模块提供了一种抽象管理主机和控制机之间交互的方式；它们允许我们专注于我们操作的逻辑。到目前为止，我们已经看到主要供应商为 Cisco、Juniper 和 Arista 提供了各种模块。

以 Cisco Nexus 模块为例，除了特定任务，如管理 BGP 邻居(`nxos_bgp`)和 aaa 服务器(`nxos_aaa_server`)。大多数供应商还提供了运行任意 show(`nxos_config`)和配置命令(`nxos_config`)的方法。这通常涵盖了我们大部分的用例。

从 Ansible 2.5 开始，还有网络事实模块的简化命名和用法。

如果您使用的设备当前没有您正在寻找的任务的模块怎么办？在本节中，我们将看一下几种方法，通过编写我们自己的自定义模块来解决这种情况。

# 第一个自定义模块

编写自定义模块并不需要复杂；实际上，它甚至不需要用 Python 编写。但是由于我们已经熟悉 Python，我们将使用 Python 来编写我们的自定义模块。我们假设该模块是我们自己和我们的团队将使用的，而不需要提交给 Ansible，因此我们将暂时忽略一些文档和格式。

如果您有兴趣开发可以提交到 Ansible 的模块，请参阅 Ansible 的模块开发指南([`docs.ansible.com/ansible/latest/dev_guide/developing_modules.html`](https://docs.ansible.com/ansible/latest/dev_guide/developing_modules.html))。

默认情况下，如果我们在与 playbook 相同的目录中创建一个名为`library`的文件夹，Ansible 将包括该目录在模块搜索路径中。因此，我们可以将我们的自定义模块放在该目录中，并且我们将能够在我们的 playbook 中使用它。自定义模块的要求非常简单：模块只需要返回 JSON 输出给 playbook。

回想一下，在第三章 *API 和意图驱动的网络*中，我们使用以下 NXAPI Python 脚本与 NX-OS 设备进行通信：

```py
    import requests
    import json

    url='http://172.16.1.142/ins'
    switchuser='cisco'
    switchpassword='cisco'

    myheaders={'content-type':'application/json-rpc'}
    payload=[
     {
       "jsonrpc": "2.0",
       "method": "cli",
       "params": {
         "cmd": "show version",
         "version": 1.2
       },
       "id": 1
     }
    ]
    response = requests.post(url,data=json.dumps(payload),   
    headers=myheaders,auth=(switchuser,switchpassword)).json()

    print(response['result']['body']['sys_ver_str'])
```

当我们执行它时，我们只是收到了系统版本。我们可以简单地修改最后一行为 JSON 输出，如下面的代码所示：

```py
    version = response['result']['body']['sys_ver_str']
    print json.dumps({"version": version})
```

我们将把这个文件放在`library`文件夹下：

```py
$ ls -a library/
. .. custom_module_1.py
```

在我们的剧本中，我们可以使用动作插件([`docs.ansible.com/ansible/dev_guide/developing_plugins.html`](https://docs.ansible.com/ansible/dev_guide/developing_plugins.html)) `chapter5_14.yml`来调用这个自定义模块：

```py
    ---
    - name: Your First Custom Module
      hosts: localhost
      gather_facts: false
      connection: local

      tasks:
        - name: Show Version
          action: custom_module_1
          register: output

        - debug:
            var: output
```

请注意，就像`ssh`连接一样，我们正在本地执行模块，并且模块正在进行 API 调用。当你执行这个剧本时，你将得到以下输出：

```py
$ ansible-playbook chapter5_14.yml
 [WARNING]: provided hosts list is empty, only localhost is available

PLAY [Your First Custom Module] ************************************************

TASK [Show Version] ************************************************************
ok: [localhost]

TASK [debug] *******************************************************************
ok: [localhost] => {
 "output": {
 "changed": false,
 "version": "7.3(0)D1(1)"
 }
}

PLAY RECAP *********************************************************************
localhost : ok=2 changed=0 unreachable=0 failed=0
```

正如你所看到的，你可以编写任何受 API 支持的模块，Ansible 将乐意接受任何返回的 JSON 输出。

# 第二个自定义模块

在上一个模块的基础上，让我们利用 Ansible 中的常见模块样板，该样板在模块开发文档中有说明([`docs.ansible.com/ansible/dev_guide/developing_modules_general.html`](http://docs.ansible.com/ansible/dev_guide/developing_modules_general.html))。我们将修改最后一个自定义模块，并创建`custom_module_2.py`来接收剧本中的输入。

首先，我们将从`ansible.module_utils.basic`导入样板代码：

```py
    from ansible.module_utils.basic import AnsibleModule

    if __name__ == '__main__':
        main()
```

然后，我们可以定义主要函数，我们将在其中放置我们的代码。`AnsibleModule`，我们已经导入了，提供了处理返回和解析参数的常见代码。在下面的示例中，我们将解析`host`、`username`和`password`三个参数，并将它们作为必填字段：

```py
    def main():
        module = AnsibleModule(
          argument_spec = dict(
          host = dict(required=True),
          username = dict(required=True),
          password = dict(required=True)
      )
    )
```

然后，可以检索这些值并在我们的代码中使用：

```py
     device = module.params.get('host')
     username = module.params.get('username')
     password = module.params.get('password')

     url='http://' + host + '/ins'
     switchuser=username
     switchpassword=password
```

最后，我们将跟踪退出代码并返回值：

```py
    module.exit_json(changed=False, msg=str(data))
```

我们的新剧本`chapter5_15.yml`将与上一个剧本相同，只是现在我们可以在剧本中为不同的设备传递值：

```py
     tasks:
       - name: Show Version
         *action: custom_module_1 host="172.16.1.142" username="cisco"* 
 *password="cisco"*
         register: output
```

当执行时，这个剧本将产生与上一个剧本完全相同的输出。但是，因为我们在自定义模块中使用了参数，所以现在可以将自定义模块传递给其他人使用，而不需要他们了解我们模块的细节。他们可以在剧本中写入自己的用户名、密码和主机 IP。

当然，这是一个功能齐全但不完整的模块。首先，我们没有进行任何错误检查，也没有为使用提供任何文档。但是，这是一个很好的演示，展示了构建自定义模块有多么容易。额外的好处是，我们看到了如何使用我们已经制作的现有脚本，并将其转换为自定义的 Ansible 模块。

# 总结

在本章中，我们涵盖了很多内容。基于我们之前对 Ansible 的了解，我们扩展到了更高级的主题，如条件、循环和模板。我们看了如何通过主机变量、组变量、包含语句和角色使我们的剧本更具可扩展性。我们还看了如何使用 Ansible Vault 保护我们的剧本。最后，我们使用 Python 制作了自己的自定义模块。

Ansible 是一个非常灵活的 Python 框架，可以用于网络自动化。它提供了另一个抽象层，与 Pexpect 和基于 API 的脚本分开。它在性质上是声明式的，更具表达性，符合我们的意图。根据你的需求和网络环境，它可能是你可以用来节省时间和精力的理想框架。

在第六章 *使用 Python 进行网络安全*中，我们将使用 Python 进行网络安全。
