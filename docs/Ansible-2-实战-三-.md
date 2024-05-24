# Ansible 2 实战（三）

> 原文：[`zh.annas-archive.org/md5/B93AA180F347B680872C5A7851966C2F`](https://zh.annas-archive.org/md5/B93AA180F347B680872C5A7851966C2F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二部分：扩展 Ansible 的功能

在本节中，我们将介绍 Ansible 插件和模块的重要概念。我们将介绍它们的有效使用以及如何通过编写自己的插件和模块来扩展 Ansible 的功能。我们甚至会看一下提交您的模块和插件到官方 Ansible 项目的要求。我们还将介绍编码最佳实践，以及一些高级的 Ansible 技术，使您能够在使用集群环境时安全地自动化您的基础设施。

本节包括以下章节：

+   第五章，*消费和创建模块*

+   第六章，*消费和创建插件*

+   第七章，*编码最佳实践*

+   第八章，*高级 Ansible 主题*


# 第五章：使用和创建模块

在整本书中，我们几乎不断地提到并使用 Ansible 模块。我们把这些模块视为“黑匣子”——也就是说，我们只是接受它们的存在，并且它们将以某种记录的方式工作。然而，关于 Ansible 的许多伟大之处之一是它是一个开源产品，因此，您不仅可以查看和修改其源代码，还可以编写自己的补充。迄今为止，已经有成千上万的模块可用于 Ansible，处理从简单的命令，如复制文件和安装软件包，到配置高度复杂和定制的网络设备。这一大量的模块已经源于使用 Ansible 解决问题的真正需求，每次发布 Ansible 时，包含的模块数量都在增加。

迟早，您会遇到一个特定的功能，它在当前的 Ansible 模块中不存在。当然，您可以尝试填补这个功能上的空白，要么编写自己的模块，要么为现有模块的增强功能做出贡献，以便其他人也能从 Ansible 项目中受益。在本章中，您将学习创建自己模块的基础知识，以及如果愿意，如何将您的代码贡献回上游的 Ansible 项目。

具体来说，在本章中，您将涵盖以下主题：

+   使用命令行执行多个模块

+   审查模块索引

+   从命令行访问模块文档

+   模块返回值

+   开发自定义模块

让我们开始吧！

# 技术要求

本章假定您已经按照第一章 *开始使用 Ansible*中详细介绍的方式设置了您的控制主机，并且正在使用最新版本——本章的示例是使用 Ansible 2.9 进行测试的。本章还假定您至少有一个额外的主机进行测试。理想情况下，这应该是基于 Linux 的。尽管本章中将给出主机名的具体示例，但您可以自由地用您自己的主机名和/或 IP 地址替换它们。如何做到这一点的详细信息将在适当的地方提供。

本章涵盖的模块开发工作假定您的计算机上存在 Python 2 或 Python 3 开发环境，并且您正在运行 Linux、FreeBSD 或 macOS。需要额外的 Python 模块时，它们的安装将被记录。构建模块文档的任务在 Python 3.5 或更高版本周围有一些非常具体的要求，因此如果您希望尝试这个任务，您将需要安装一个合适的 Python 环境。

本章的代码包在这里可用：[`github.com/PacktPublishing/Ansible-2-Cookbook/tree/master/Chapter%205`](https://github.com/PacktPublishing/Ansible-2-Cookbook/tree/master/Chapter%205)。

# 使用命令行执行多个模块

由于本章主要讨论模块以及如何创建它们，让我们回顾一下如何使用模块。我们在整本书中都做过这个，但我们并没有特别关注它们工作的一些具体细节。我们没有讨论的关键事情之一是 Ansible 引擎如何与其模块进行通信，反之亦然，所以让我们现在来探讨一下。

与以往一样，当使用 Ansible 命令时，我们需要一个清单来运行我们的命令。在本章中，由于我们的重点是模块本身，我们将使用一个非常简单和小的清单，如下所示：

```
[frontends]
frt01.example.com

[appservers]
app01.example.com
```

现在，让我们回顾的第一部分，您可以通过一个临时命令轻松运行一个模块，并使用`-m`开关告诉 Ansible 您想要运行哪个模块。因此，您可以运行的最简单的命令之一是 Ansible 的`ping`命令，如下所示：

```
$ ansible -i hosts appservers -m ping 
```

现在，我们之前没有看过的一件事是 Ansible 和它的模块之间的通信；然而，让我们来检查一下前面命令的输出：

```
$ ansible -i hosts appservers -m ping
app01.example.com | SUCCESS => {
 "ansible_facts": {
 "discovered_interpreter_python": "/usr/bin/python"
 },
 "changed": false,
 "ping": "pong"
}
```

你注意到输出的结构了吗 - 大括号、冒号和逗号？是的，Ansible 使用 JSON 格式的数据与它的模块进行通信，模块也将它们的数据以 JSON 格式返回给 Ansible。前面的输出实际上是`ping`模块通过 JSON 格式的数据结构向 Ansible 引擎返回的一个子集。

当然，我们在使用模块时不必担心这一点，可以在命令行上使用`key=value`对或在 playbooks 和 roles 中使用 YAML。因此，JSON 对我们来说是屏蔽的，但这是一个重要的事实，当我们在本章后面进入模块开发的世界时要牢记在心。

Ansible 模块就像高级编程语言中的函数一样，它们接受一组明确定义的参数作为输入，执行它们的功能，然后提供一组输出数据，这些数据也是明确定义和有文档记录的。我们稍后会更详细地看一下这一点。当然，前面的命令没有包括任何参数，所以这是通过 Ansible 最简单的模块调用。

现在，让我们运行另一个带有参数的命令，并将数据传递给模块：

```
$ ansible -i hosts appservers -m command -a "/bin/echo 'hello modules'"
```

在这种情况下，我们向命令模块提供了一个字符串作为参数，然后 Ansible 将其转换为 JSON 并传递给命令模块。当你运行这个临时命令时，你会看到类似以下的输出：

```
$  ansible -i hosts appservers -m command -a "/bin/echo 'hello modules'"
app01.example.com | CHANGED | rc=0 >>
hello modules
```

在这种情况下，输出数据似乎不是 JSON 格式的；然而，当你运行一个模块时，Ansible 打印到终端的内容只是每个模块返回的数据的一个子集 - 例如，我们命令的`CHANGED`状态和`rc=0`退出代码都以 JSON 格式的数据结构传递回 Ansible - 这只是对我们隐藏了。

这一点不需要过多强调，但设置一个上下文是很重要的。正是这个上下文将贯穿本章的始终，所以只需记住这些关键点：

+   Ansible 和它的模块之间的通信是通过 JSON 格式的数据结构完成的。

+   模块接受控制它们功能的输入数据（参数）。

+   模块总是返回数据 - 至少是模块执行的状态（例如`changed`、`ok`或`failed`）。

当然，在开始编写自己的模块之前，检查是否已经存在可以执行所有（或部分）所需功能的模块是有意义的。我们将在下一节中探讨这一点。

# 审查模块索引

正如前面的部分所讨论的，Ansible 提供了成千上万的模块，使得快速轻松地开发 playbooks 并在多个主机上运行它们。然而，当有这么多模块时，你该如何找到合适的模块呢？幸运的是，Ansible 文档提供了一个组织良好、分类清晰的模块列表，你可以查阅以找到你需要的模块 - 可以在这里找到：[`docs.ansible.com/ansible/latest/modules/modules_by_category.html`](https://docs.ansible.com/ansible/latest/modules/modules_by_category.html)。

假设你想要查看是否有一个原生的 Ansible 模块可以帮助你配置和管理你的亚马逊网络服务 S3 存储桶。这是一个相当明确、明确定义的需求，所以让我们以一种逻辑的方式来处理：

1.  首先，像之前讨论的那样，在你的网络浏览器中打开分类的模块索引：

```
https://docs.ansible.com/ansible/latest/modules/modules_by_category.html
```

1.  现在，我们知道亚马逊网络服务几乎肯定会出现在`Cloud`模块类别中，所以让我们在浏览器中打开它。

1.  在这个页面上仍然列出了数百，甚至数千个模块！所以，让我们在浏览器中使用查找功能（*Ctrl* + *F*）来查看`s3`关键字是否出现在任何地方：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/prac-asb/img/dfa7f773-fcca-4f39-ae84-a0ecd968e7e9.png)

我们很幸运-确实如此，并且页面下方还有几个更多的列表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/prac-asb/img/f0611a81-5115-4749-9a37-ff80186fc8d1.png)

现在我们有了一个要使用的模块的简短列表-当然，有几个，所以我们仍然需要弄清楚我们的 playbook 需要哪一个（或哪些）。正如前面的简短描述所示，这将取决于您的预期任务是什么。

1.  简短的描述应该足以给您一些关于模块是否适合您的需求的线索。一旦您有了想法，您可以单击适当的文档链接查看有关模块以及如何使用它的更多详细信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/prac-asb/img/cff1ffb2-7801-4c9f-ae0d-605181e91ae3.png)

正如您所看到的，每个模块的文档页面都提供了大量的信息，包括更长的描述。如果您向下滚动页面，您将看到可以向模块提供的可能参数列表，一些如何使用它们的实际示例，以及有关模块输出的一些详细信息。还要注意前面截图中的要求部分-一些模块，特别是与云相关的模块，在运行之前需要在 Python 2.6 或更高版本上安装额外的 Python 模块，如果您尝试在没有在 Python 2.6 或更高版本上安装`boto`，`boto3`和`botocore`模块的情况下从 playbook 运行`aws_s3`模块，您将只会收到一个错误。

所有模块必须在被接受为 Ansible 项目的一部分之前创建这样的文档，因此，如果您打算提交自己的模块，您必须牢记这一点。这也是 Ansible 流行的原因之一-具有易于维护和有良好文档的标准，它是自动化的完美社区平台。官方的 Ansible 网站并不是您可以获取文档的唯一地方，因为它甚至可以在命令行上使用。我们将在下一节中看看如何通过这种方式检索文档。

# 从命令行访问模块文档

正如前一节所讨论的，Ansible 项目以其文档为傲，并且使这些文档易于访问是项目本身的重要部分。现在，假设您正在进行 Ansible 任务（在 playbook、角色或甚至是临时命令中），并且您在只能访问您正在工作的机器的 shell 的数据中心环境中。您将如何访问 Ansible 文档？

幸运的是，我们还没有讨论的 Ansible 安装的一部分是`ansible-doc`工具，它与熟悉的`ansible`和`ansible-playbook`可执行文件一起作为标准安装。`ansible-doc`命令包括一个完整（基于文本的）文档库，其中包含您安装的 Ansible 版本附带的所有模块的文档。这意味着您需要的模块信息就在您的指尖，即使您在数据中心中并且没有工作的互联网连接！

以下是一些示例，向您展示如何与`ansible-doc`工具进行交互：

+   您可以通过简单地发出以下命令在您的 Ansible 控制机上列出所有有文档的模块：

```
**$ ansible-doc -l** 
```

您应该看到一个类似以下的输出：

```
fortios_router_community_list          Configure community lists in Fortinet's FortiOS ...
azure_rm_devtestlab_info               Get Azure DevTest Lab facts
ecs_taskdefinition                     register a task definition in ecs
avi_alertscriptconfig                  Module for setup of AlertScriptConfig Avi RESTfu...
tower_receive                          Receive assets from Ansible Tower
netapp_e_iscsi_target                  NetApp E-Series manage iSCSI target configuratio...
azure_rm_acs                           Manage an Azure Container Service(ACS) instance
fortios_log_syslogd2_filter            Filters for remote system server in Fortinet's F...
junos_rpc                              Runs an arbitrary RPC over NetConf on an Juniper...
na_elementsw_vlan                      NetApp Element Software Manage VLAN
pn_ospf                                CLI command to add/remove ospf protocol to a vRo...
pn_snmp_vacm                           CLI command to create/modify/delete snmp-vacm
cp_mgmt_service_sctp                   Manages service-sctp objects on Check Point over...
onyx_ospf                              Manage OSPF protocol on Mellanox ONYX network de.
```

有许多页面的输出，这只是向您展示有多少模块！实际上，您可以计数它们：

```
$ ansible-doc -l | wc -l
3387
```

没错- Ansible 2.9.6 附带了 3,387 个模块！

+   与以前一样，您可以使用您喜欢的 shell 工具来处理索引来搜索特定的模块；例如，您可以使用`grep`来查找所有与 S3 相关的模块，就像我们在上一节的 Web 浏览器中交互式地做的那样：

```
$ ansible-doc -l | grep s3
s3_bucket_notification                    Creates, upda...
purefb_s3user                             Create or del...
purefb_s3acc                              Create or del...
aws_s3_cors                               Manage CORS f...
s3_sync                                   Efficiently u...
s3_logging                                Manage loggin...
s3_website                                Configure an ...
s3_bucket                                 Manage S3 buc...
s3_lifecycle                              Manage s3 buc...
aws_s3_bucket_info                        Lists S3 buck...
aws_s3                                    manage object...

```

+   现在，我们可以轻松查找我们感兴趣的模块的具体文档。假设我们想了解更多关于`aws_s3`模块的信息-就像我们在网站上所做的那样，只需运行以下命令：

```
$ ansible-doc aws_s3
```

这应该产生一个类似以下的输出：

```
$ ansible-doc aws_s3 > AWS_S3 (/usr/lib/python2.7/site-packages/ansible/modules/cloud/amazon/aws_s

 This module allows the user to manage S3 buckets and the
 objects within them. Includes support for creating and
 deleting both objects and buckets, retrieving objects as files
 or strings and generating download links. This module has a
 dependency on boto3 and botocore.

 * This module is maintained by The Ansible Core Team
 * note: This module has a corresponding action plugin.

OPTIONS (= is mandatory):

- aws_access_key
 AWS access key id. If not set then the value of the
 AWS_ACCESS_KEY environment variable is used.
 (Aliases: ec2_access_key, access_key)[Default: (null)]
 type: str
....
```

虽然格式有些不同，`ansible-doc`告诉我们关于该模块的信息，提供了我们可以传递的所有参数（`OPTIONS`）的列表，当我们向下滚动时，甚至给出了一些工作示例和可能的返回值。我们将在下一节中探讨返回值的主题，因为它们对于理解非常重要，特别是当我们接近开发自己的模块的主题时。

# 模块返回值

正如我们在本章前面讨论的那样，Ansible 模块将它们的结果作为结构化数据返回，以 JSON 格式在后台格式化。在前面的例子中，你遇到了这些返回数据，既以退出代码的形式，也在我们使用`register`关键字来捕获任务结果的 Ansible 变量中。在本节中，我们将探讨如何发现 Ansible 模块的返回值，以便我们以后在 playbook 中使用它们，例如，进行条件处理（见第四章，*Playbooks and Roles*）。

由于空间有限，当涉及到返回值时，我们将选择可能是最简单的 Ansible 模块之一——`ping`模块。

话不多说，让我们使用我们在上一节学到的`ansible-doc`工具，看看它对于这个模块的返回值有什么说：

```
$ ansible-doc ping
```

如果你滚动到前面命令的输出底部，你应该会看到类似这样的内容：

```
$ ansible-doc ping
...

RETURN VALUES:

ping:
 description: value provided with the data parameter
 returned: success
 type: str
 sample: pong
```

因此，我们可以看到`ping`模块只会返回一个值，那就是`ping`。`description`告诉我们我们应该期望这个特定的返回值包含什么，而`returned`字段告诉我们它只会在`success`时返回（如果它会在其他条件下返回，这些将在这里列出）。`type`返回值是一个字符串（用`str`表示），虽然你可以通过提供给`ping`模块的参数来改变值，但默认返回值（因此`sample`）是`pong`。

现在，让我们看看实际情况。例如，这些返回值中没有任何内容告诉我们模块是否成功运行以及是否有任何更改；然而，我们知道这些是关于每个模块运行的基本信息。

让我们把一个非常简单的 playbook 放在一起。我们将使用`ping`模块而不带任何参数运行，使用`register`关键字捕获返回值，然后使用`debug`模块将返回值转储到终端上：

```
---
- name: Simple play to demonstrate a return value
  hosts: localhost

  tasks:
    - name: Perform a simple module based task
      ping:
      register: pingresult

    - name: Display the result
      debug:
        var: pingresult
```

现在，让我们看看当我们运行这个 playbook 时会发生什么：

```
$ ansible-playbook retval.yml
[WARNING]: provided hosts list is empty, only localhost is available. Note that
the implicit localhost does not match 'all'

PLAY [Simple play to demonstrate a return value] *******************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [Perform a simple module based task] **************************************
ok: [localhost]

TASK [Display the result] ******************************************************
ok: [localhost] => {
 "pingresult": {
 "changed": false,
 "failed": false,
 "ping": "pong"
 }
}

PLAY RECAP *********************************************************************
localhost : ok=3 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

注意，`ping`模块确实返回一个名为`ping`的值，其中包含`pong`字符串（因为 ping 成功了）。然而，你可以看到实际上有两个额外的返回值，这些在 Ansible 文档中没有列出。这些伴随着每个任务运行，因此是隐式的 - 也就是说，你可以假设它们将是从每个模块返回的数据中的一部分。如果模块运行导致目标主机上的更改，`changed`返回值将被设置为`true`，而如果模块运行因某种原因失败，`failed`返回值将被设置为`true`。

使用`debug`模块打印模块运行的输出是一个非常有用的技巧，如果你想收集关于模块、它的工作方式以及返回的数据类型的更多信息。在这一点上，我们已经涵盖了几乎所有关于模块工作的基础知识，所以下一节，我们将开始开发我们自己的（简单）模块。

# 开发自定义模块

现在我们熟悉了模块，如何调用它们，如何解释它们的结果以及如何找到它们的文档，我们可以开始编写我们自己的简单模块。虽然这不包括许多与 Ansible 一起提供的模块的深入和复杂的功能，但希望这将为您提供足够的信息，以便在构建您自己的更复杂的模块时能够自信地继续。

一个重要的要点是，Ansible 是用 Python 编写的，因此它的模块也是用 Python 编写的。因此，您需要用 Python 编写您的模块，并且要开始开发自己的模块，您需要确保已安装 Python 和一些必要的工具。如果您已经在开发机器上运行 Ansible，您可能已经安装了所需的软件包，但如果您从头开始，您需要安装 Python、Python 软件包管理器（`pip`）和可能一些其他开发软件包。确切的过程会因操作系统而异，但以下是一些示例，供您开始：

+   在 Fedora 上，您将运行以下命令来安装所需的软件包：

```
$ sudo dnf install python python-devel
```

+   同样，在 CentOS 上，您将运行以下命令来安装所需的软件包：

```
$ sudo yum install python python-devel
```

+   在 Ubuntu 上，您将运行以下命令来安装所需的软件包：

```
$ sudo apt-get update
$ sudo apt-get install python-pip python-dev build-essential 
```

+   如果您正在 macOS 上使用 Homebrew 包管理系统，以下命令将安装您需要的软件包：

```
$ sudo brew install python
```

安装所需的软件包后，您需要将 Ansible Git 存储库克隆到本地机器，因为其中有一些有价值的脚本，我们在模块开发过程中将需要。使用以下命令将 Ansible 存储库克隆到开发机器上的当前目录：

```
$ git clone https://github.com/ansible/ansible.git
```

最后（尽管是可选的），在虚拟环境（`venv`）中开发您的 Ansible 模块是一个很好的做法，因为这意味着您需要安装的任何 Python 软件包都在这里，而不是与全局系统 Python 模块一起。以不受控制的方式为整个系统安装模块有时可能会导致兼容性问题，甚至破坏本地工具，因此虽然这不是必需的步骤，但强烈建议这样做。

为您的 Python 模块开发工作创建虚拟环境的确切命令将取决于您正在运行的操作系统以及您使用的 Python 版本。您应该参考您的 Linux 发行版的文档以获取更多信息；但是，以下命令在默认 Python 2.7.5 的 CentOS 7.7 上进行了测试，以在您刚刚从 GitHub 克隆的 Ansible 源代码目录中创建一个名为`moduledev`的虚拟环境：

```
$ cd ansible
$  python -m virtualenv moduledev
New python executable in /home/james/ansible/moduledev/bin/python
Installing setuptools, pip, wheel...done.
```

有了我们的开发环境设置好了，让我们开始编写我们的第一个模块。这个模块将非常简单，因为本书的范围超出了如何编写大量 Python 代码的深入讨论。但是，我们将编写一些可以使用 Python 库中的函数在目标机器上本地复制文件的代码。

显然，这与现有模块功能有很大的重叠，但它将作为一个很好的简洁示例，演示如何编写一个简单的 Python 程序，以便 Ansible 可以使用它作为模块。现在，让我们开始编写我们的第一个模块：

1.  在您喜欢的编辑器中，创建一个名为（例如）`remote_filecopy.py`的新文件：

```
$ vi remote_filecopy.py
```

1.  从一个 shebang 开始，表示这个模块应该用 Python 执行：

```
#!/usr/bin/python
```

1.  虽然不是强制性的，但在新模块的头部添加版权信息以及您的详细信息是一个好习惯。通过这样做，任何使用它的人都会了解他们可以使用、修改或重新分发的条款。这里给出的文本仅仅是一个例子；您应该自行调查各种适当的许可证，并确定哪种对您的模块最合适：

```
# Copyright: (c) 2018, Jesse Keating <jesse.keating@example.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
```

1.  在版权部分之后立即添加包含`metadata_version`、`status`和`supported_by`信息的 Ansible 元数据部分也是一个好习惯。请注意，`metadata_version`字段代表 Ansible 元数据版本（在撰写本文时应为`1.1`），与您的模块版本或您使用的 Ansible 版本无关。以下代码中建议的值对于刚开始使用是可以的，但如果您的模块被接受到官方的 Ansible 源代码中，它们可能会改变：

```
ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}
```

1.  记住`ansible-doc`和 Ansible 文档网站上提供的优秀文档？所有这些都会自动生成，从你添加到这个文件的特殊部分。让我们开始通过向我们的模块添加以下代码来添加：

```
DOCUMENTATION = '''
---
module: remote_filecopy
version_added: "2.9"
short_description: Copy a file on the remote host
description:
  - The remote_copy module copies a file on the remote host from a given source to a provided destination.
options:
  source:
    description:
      - Path to a file on the source file on the remote host
    required: True
  dest:
    description:
      - Path to the destination on the remote host for the copy
    required: True
author:
- Jesse Keating (@omgjlk)
'''
```

特别注意`author`字典 - 为了通过官方 Ansible 代码库的语法检查，作者的名字应该在括号中附上他们的 GitHub ID。如果不这样做，你的模块仍然可以工作，但它将无法通过我们稍后进行的测试。

注意文档是用 YAML 格式编写的，用三个单引号括起来？列出的字段应该适用于几乎所有模块，但自然地，如果你的模块接受不同的选项，你应该指定这些选项以使其与你的模块匹配。

1.  文档中的示例也是从这个文件生成的 - 它们在`DOCUMENTATION`后面有自己特殊的文档部分，并应该提供如何使用你的模块创建任务的实际示例，如下例所示：

```
EXAMPLES = '''
   # Example from Ansible Playbooks
   - name: backup a config file
     remote_copy:
       source: /etc/herp/derp.conf
       dest: /root/herp-derp.conf.bak
'''
```

1.  你的模块返回给 Ansible 的数据也应该在自己的部分中进行文档化。我们的示例模块将返回以下值：

```
RETURN = '''
source:
  description: source file used for the copy
  returned: success
  type: str
  sample: "/path/to/file.name"
dest:
  description: destination of the copy
  returned: success
  type: str
  sample: "/path/to/destination.file"
gid:
  description: group ID of destination target
  returned: success
  type: int
  sample: 502
group:
  description: group name of destination target
  returned: success
  type: str
  sample: "users"
uid:
  description: owner ID of destination target
  returned: success
  type: int
  sample: 502
owner:
  description: owner name of destination target
  returned: success
  type: str
  sample: "fred"
mode:
  description: permissions of the destination target
  returned: success
  type: int
  sample: 0644
size:
  description: size of destination target
  returned: success
  type: int
  sample: 20
state:
  description: state of destination target
  returned: success
  type: str
  sample: "file"
'''
```

1.  我们完成文档部分后，应立即导入我们要使用的任何 Python 模块。在这里，我们将包括`shutil`模块，该模块将用于执行文件复制：

```
import shutil
```

1.  现在我们已经建立了模块头和文档，我们可以开始编写代码了。现在，你可以看到为每个单独的 Ansible 模块编写文档需要付出多少努力！我们的模块应该从定义一个`main`函数开始，在这个函数中，我们将创建一个`AnsibleModule`类型的对象，并使用一个`argument_spec`字典来获取模块调用时的选项：

```
 def main():
       module = AnsibleModule(
           argument_spec = dict(
               source=dict(required=True, type='str'),
               dest=dict(required=True, type='str')
           ) 
       )
```

1.  在这个阶段，我们已经拥有了编写模块功能代码所需的一切 - 甚至包括它被调用时的选项。因此，我们可以使用 Python 的`shutil`模块来执行本地文件复制，基于提供的参数：

```
       shutil.copy(module.params['source'],
                   module.params['dest'])
```

1.  在这一点上，我们已经执行了我们的模块旨在完成的任务。然而，可以说我们还没有完成 - 我们需要清理地退出模块，并向 Ansible 提供我们的返回值。通常，在这一点上，你会编写一些条件逻辑来检测模块是否成功以及它是否实际上对目标主机进行了更改。然而，为简单起见，我们将简单地每次以`changed`状态退出 - 扩展这个逻辑并使返回状态更有意义留给你作为练习：

```
      module.exit_json(changed=True)
```

`module.exit_json`方法来自我们之前创建的`AnsibleModule` - 记住，我们说过重要的是知道数据是如何使用 JSON 来回传递的！

1.  在我们接近模块代码的结尾时，我们现在必须告诉 Python 它可以从哪里导入`AnsibleModule`对象。可以通过以下代码行来完成：

```
   from ansible.module_utils.basic import *
```

1.  现在是模块的最后两行代码 - 这是我们告诉模块在启动时应该运行`main`函数的地方：

```
   if __name__ == '__main__':
       main()
```

就是这样 - 通过一系列良好记录的步骤，你可以用 Python 编写自己的 Ansible 模块。下一步当然是测试它，在我们实际在 Ansible 中测试之前，让我们看看是否可以在 shell 中手动运行它。当然，为了让模块认为它是在 Ansible 中运行，我们必须以 JSON 格式生成一些参数。创建一个文件，包含以下内容以提供参数：

```
{
 "ANSIBLE_MODULE_ARGS": {
 "source": "/tmp/foo",
        "dest": "/tmp/bar"
    }
} 
```

有了这个小小的 JSON 片段，你可以直接用 Python 执行你的模块。如果你还没有这样做，你需要按照以下方式设置你的 Ansible 开发环境。请注意，我们还手动创建了源文件`/tmp/foo`，这样我们的模块就可以真正执行文件复制了：

```
$ touch /tmp/foo
$ . moduledev/bin/activate
(moduledev) $ . hacking/env-setup
running egg_info
creating lib/ansible_base.egg-info
writing requirements to lib/ansible_base.egg-info/requires.txt
writing lib/ansible_base.egg-info/PKG-INFO
writing top-level names to lib/ansible_base.egg-info/top_level.txt
writing dependency_links to lib/ansible_base.egg-info/dependency_links.txt
writing manifest file 'lib/ansible_base.egg-info/SOURCES.txt'
reading manifest file 'lib/ansible_base.egg-info/SOURCES.txt'
reading manifest template 'MANIFEST.in'
warning: no files found matching 'SYMLINK_CACHE.json'
warning: no previously-included files found matching 'docs/docsite/rst_warnings'
warning: no previously-included files matching '*' found under directory 'docs/docsite/_build'
warning: no previously-included files matching '*.pyc' found under directory 'docs/docsite/_extensions'
warning: no previously-included files matching '*.pyo' found under directory 'docs/docsite/_extensions'
warning: no files found matching '*.ps1' under directory 'lib/ansible/modules/windows'
warning: no files found matching '*.psm1' under directory 'test/support'
writing manifest file 'lib/ansible_base.egg-info/SOURCES.txt'

Setting up Ansible to run out of checkout...

PATH=/home/james/ansible/bin:/home/james/ansible/moduledev/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/home/james/bin
PYTHONPATH=/home/james/ansible/lib
MANPATH=/home/james/ansible/docs/man:/usr/local/share/man:/usr/share/man

Remember, you may wish to specify your host file with -i

Done!
```

现在，你终于可以第一次运行你的模块了。你可以按照以下步骤进行：

```
(moduledev) $ python remote_filecopy.py args.json
{"invocation": {"module_args": {"dest": "/tmp/bar", "source": "/tmp/foo"}}, "changed": true}

(moduledev) $ ls -l /tmp/bar
-rw-r--r-- 1 root root 0 Apr 16 16:24 /tmp/bar
```

成功！你的模块有效 - 它既接收又生成 JSON 数据，正如我们在本章前面讨论的那样。当然，你还有很多东西要添加到你的模块 - 我们还没有处理模块的`failed`或`ok`返回，也不支持检查模式。然而，我们已经有了一个良好的开端，如果你想了解更多关于 Ansible 模块和丰富功能的内容，你可以在这里找到更多详细信息：[`docs.ansible.com/ansible/latest/dev_guide/developing_modules_general.html`](https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_general.html)。

当涉及测试你的模块时，创建一个 JSON 文件中的参数并不直观，尽管，正如我们所见，它确实运行良好。幸运的是，我们可以很容易地在 playbook 中运行我们的 Ansible 模块！默认情况下，Ansible 将检查 playbook 目录是否有一个名为`library/`的子目录，并将从这里运行引用的模块。因此，我们可以创建以下内容：

```
$ cd ~
$ mkdir testplaybook
$ cd testplaybook
$ mkdir library
$ cp ~/ansible/moduledev/remote_filecopy.py library/
```

现在，在这个 playbook 目录中创建一个简单的清单文件，就像我们之前做的那样，并添加一个带有以下内容的 playbook：

```
---
- name: Playbook to test custom module
  hosts: all

  tasks:
    - name: Test the custom module
      remote_filecopy:
        source: /tmp/foo
        dest: /tmp/bar
      register: testresult

    - name: Print the test result data
      debug:
        var: testresult
```

为了清晰起见，你的最终目录结构应该如下所示：

```
testplaybook
├── hosts
├── library
│   └── remote_filecopy.py
└── testplaybook.yml
```

现在，尝试以通常的方式运行 playbook，看看会发生什么：

```
$ ansible-playbook -i hosts testplaybook.yml

PLAY [Playbook to test custom module] ******************************************

TASK [Gathering Facts] *********************************************************
ok: [frt01.example.com]
ok: [app01.example.com]

TASK [Test the custom module] **************************************************
changed: [app01.example.com]
changed: [frt01.example.com]

TASK [Print the test result data] **********************************************
ok: [app01.example.com] => {
 "testresult": {
 "changed": true,
 "failed": false
 }
}
ok: [frt01.example.com] => {
 "testresult": {
 "changed": true,
 "failed": false
 }
}

PLAY RECAP *********************************************************************
app01.example.com : ok=3 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt01.example.com : ok=3 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

成功！你不仅在本地测试了你的 Python 代码，而且还成功地在 Ansible playbook 中的两台远程服务器上运行了它。这真的很容易，这证明了扩展你的 Ansible 模块以满足你自己的定制需求是多么简单。

尽管成功运行了这段代码，但我们还没有检查文档，也没有从 Ansible 中测试它的操作。在我们更详细地解决这些问题之前，在下一节中，我们将看看模块开发的一些常见陷阱以及如何避免它们。

# 避免常见陷阱

你的模块必须经过深思熟虑，并且要优雅地处理错误条件 - 有一天人们将依赖于你的模块来自动化可能在成千上万台服务器上执行的任务，所以他们最不想做的就是花费大量时间调试错误，尤其是那些本来可以被捕获或优雅处理的琐碎错误。在本节中，我们将具体看看错误处理和如何做到这一点，以便 playbook 仍然可以正常运行并优雅退出。

在我们开始之前，一个总体的指导是，就像文档在 Ansible 中受到高度关注一样，你的错误消息也应该如此。它们应该是有意义的，易于解释，你应该避免无意义的字符串，比如`Error!`。

所以，现在，如果我们删除我们试图复制的源文件，然后用相同的参数重新运行我们的模块，我认为你会同意输出既不漂亮也不有意义，除非你碰巧是一个经验丰富的 Python 开发者：

```
(moduledev) $ rm -f /tmp/foo
(moduledev) $ python remote_filecopy.py args.json
Traceback (most recent call last):
 File "remote_filecopy.py", line 99, in <module>
 main()
 File "remote_filecopy.py", line 93, in main
 module.params['dest'])
 File "/usr/lib64/python2.7/shutil.py", line 119, in copy
 copyfile(src, dst)
 File "/usr/lib64/python2.7/shutil.py", line 82, in copyfile
 with open(src, 'rb') as fsrc:
IOError: [Errno 2] No such file or directory: '/tmp/foo'
```

我们毫无疑问可以做得更好。让我们复制一份我们的模块，并向其中添加一些代码。首先，用以下代码替换`shutil.copy`行：

```
    try:
       shutil.copy(module.params['source'], module.params['dest'])
    except:
       module.fail_json(msg="Failed to copy file")
```

这是 Python 中一些非常基本的异常处理，但它允许代码尝试`shutil.copy`任务。但是，如果这失败并引发了异常，我们不会使用回溯退出，而是使用`module.fail_json`调用干净地退出。这将告诉 Ansible 模块失败，并干净地发送 JSON 格式的错误消息回去。当然，我们可以做很多事情来改进错误消息；例如，我们可以从`shutil`模块获取确切的错误消息并将其传递回 Ansible，但是这又留给您来完成。

现在，当我们尝试使用不存在的源文件运行模块时，我们将看到以下清晰格式的 JSON 输出：

```
(moduledev) $ rm -f /tmp/foo
(moduledev) $ python better_remote_filecopy.py args.json

{"msg": "Failed to copy file", "failed": true, "invocation": {"module_args": {"dest": "/tmp/bar", "source": "/tmp/foo"}}}
```

然而，如果复制成功，模块仍然以与以前相同的方式工作：

```
(moduledev) $ touch /tmp/foo
(moduledev) $ python better_remote_filecopy.py args.json

{"invocation": {"module_args": {"dest": "/tmp/bar", "source": "/tmp/foo"}}, "changed": true}
```

通过对我们的代码进行这个简单的更改，我们现在可以干净而优雅地处理文件复制操作的失败，并向用户报告一些更有意义的内容，而不是使用回溯。在您的模块中进行异常处理和处理的一些建议如下：

+   快速失败-在出现错误后不要尝试继续处理。

+   使用各种模块 JSON 返回函数返回最有意义的可能错误消息。

+   如果有任何方法可以避免返回回溯，请不要返回回溯。

+   尝试使错误在模块和其功能的上下文中更有意义（例如，对于我们的模块，`文件复制错误`比`文件错误`更有意义-我认为您很容易想出更好的错误消息）。

+   不要用错误轰炸用户；相反，尝试专注于报告最有意义的错误，特别是当您的模块代码很复杂时。

这完成了我们对 Ansible 模块中错误处理的简要而实用的介绍。在下一节中，我们将回到我们在模块中包含的文档，包括如何将其构建为 HTML 文档，以便它可以放在 Ansible 网站上（如果您的模块被接受为 Ansible 源代码的一部分，这正是 Web 文档将如何生成）。

# 测试和记录您的模块

我们已经在本章前面讨论过，已经为我们的模块做了大量的文档工作。但是，我们如何查看它，以及如何检查它是否正确编译为 HTML，如果它被接受为 Ansible 源代码的一部分，它将放在 Ansible 网站上？

在我们实际查看文档之前，我们应该使用一个名为`ansible-test`的工具，这个工具是在 2.9 版本中新增的。这个工具可以对我们的模块代码进行健全性检查，以确保我们的文档符合 Ansible 项目团队所需的所有标准，并且代码结构正确（例如，Python 的`import`语句应该始终放在文档块之后）。让我们开始吧：

1.  要运行健全性测试，假设您已经克隆了官方存储库，请切换到此目录并设置您的环境。请注意，如果您的标准 Python 二进制文件不是 Python 3，`ansible-test`工具将无法运行，因此您应确保已安装 Python 3，并在必要时设置虚拟环境以确保您正在使用 Python 3。可以按照以下步骤完成：

```
$ cd ansible$ python 3 -m venv venv
$ . venv/bin/activate
(venv) $ source hacking/env-setup
running egg_info
creating lib/ansible.egg-info
writing lib/ansible.egg-info/PKG-INFO
writing dependency_links to lib/ansible.egg-info/dependency_links.txt
writing requirements to lib/ansible.egg-info/requires.txt
writing top-level names to lib/ansible.egg-info/top_level.txt
writing manifest file 'lib/ansible.egg-info/SOURCES.txt'
reading manifest file 'lib/ansible.egg-info/SOURCES.txt'
reading manifest template 'MANIFEST.in'
warning: no files found matching 'SYMLINK_CACHE.json'
writing manifest file 'lib/ansible.egg-info/SOURCES.txt'

Setting up Ansible to run out of checkout...

PATH=/home/james/ansible/bin:/home/james/ansible/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/home/james/bin
PYTHONPATH=/home/james/ansible/lib
MANPATH=/home/james/ansible/docs/man:/usr/local/share/man:/usr/share/man

Remember, you may wish to specify your host file with -i

Done!
```

1.  接下来，使用`pip`安装 Python 要求，以便您可以运行`ansible-test`工具：

```
(venv) $ pip install -r test/runner/requirements/sanity.txt
```

1.  现在，只要您已将模块代码复制到源树中的适当位置（此处显示了一个示例复制命令），您可以按以下方式运行健全性测试：

```
(venv) $ cp ~/moduledev/remote_filecopy.py ./lib/ansible/modules/files/
(venv) $ ansible-test sanity --test validate-modules remote_filecopy
Sanity check using validate-modules
WARNING: Cannot perform module comparison against the base branch. Base branch not detected when running locally.
WARNING: Reviewing previous 1 warning(s):
WARNING: Cannot perform module comparison against the base branch. Base branch not detected when running locally.
```

从前面的输出中，您可以看到除了一个警告与我们没有基本分支进行比较之外，我们在本章前面开发的模块代码已经通过了所有测试。如果您对文档有问题（例如，作者名称格式不正确），这将被视为错误。

现在我们已经通过了`ansible-test`的检查，让我们看看使用`ansible-doc`命令文档是否正确。这很容易做到。首先，退出你的虚拟环境，如果你还在其中，然后切换到你之前从 GitHub 克隆的 Ansible 源代码目录。现在，你可以手动告诉`ansible-doc`在哪里查找模块，而不是默认路径。这意味着你可以运行以下命令：

```
$ cd ~/ansible
$ ansible-doc -M moduledev/ remote_filecopy
```

你应该看到我们之前创建的文档的文本呈现 - 这里显示了第一页的示例，以便让你了解它应该是什么样子：

```
> REMOTE_FILECOPY (/home/james/ansible/moduledev/remote_filecopy.py)

 The remote_copy module copies a file on the remote host from a
 given source to a provided destination.

 * This module is maintained by The Ansible Community
OPTIONS (= is mandatory):

= dest
 Path to the destination on the remote host for the copy

= source
 Path to a file on the source file on the remote host

```

太好了！所以，我们已经可以使用`ansible-doc`访问我们的模块文档，并确保它在文本模式下呈现正确。但是，我们如何构建 HTML 版本呢？幸运的是，这方面有一个明确定义的过程，我们将在这里概述：

1.  在`lib/ansible/modules/`下，你会发现一系列分类的目录，模块被放置在其中 - 我们的最适合放在`files`类别下，所以将其复制到这个位置，为即将到来的构建过程做准备：

```
$ cp moduledev/remote_filecopy.py lib/ansible/modules/files/
```

1.  作为文档创建过程的下一步，切换到`docs/docsite/`目录：

```
$ cd docs/docsite/
```

1.  构建一个基于文档的 Python 文件。使用以下命令来完成：

```
$ MODULES=hello_module make webdocs
```

现在，理论上，制作 Ansible 文档应该是这么简单的；然而，不幸的是，在写作时，Ansible v2.9.6 的源代码拒绝构建`webdocs`。随着时间的推移，这无疑会得到修复，因为在写作时，文档构建脚本正在迁移到 Python 3。为了让`make webdocs`命令运行，我不得不将 Ansible v2.8.10 的源代码克隆为起点。

即使在这个环境中，在 CentOS 7 上，`make webdocs`命令也会失败，除非你有一些非常特定的 Python 3 要求。这些要求没有很好地记录，但从测试中，我可以告诉你，Sphinx v2.4.4 可以工作。CentOS 7 提供的版本太旧并且失败，而 Python 模块仓库提供的最新版本（写作时为 v3.0.1）与构建过程不兼容并且失败。

一旦我从 Ansible v2.8.10 源代码树开始工作，我必须确保我已经从我的 Python 3 环境中删除了任何现有的`sphinx`模块（你需要 Python 3.5 或更高版本才能在本地构建文档 - 如果你的节点上没有安装这个，请在继续之前安装）然后运行以下命令：

```
$ pip3 uninstall sphinx
$ pip3 install sphinx==2.4.4
$ pip3 install sphinx-notfound-page
```

有了这个，你就可以成功地运行`make webdocs`来构建你的文档。你会看到很多输出。一个成功的运行应该以类似于这里显示的输出结束：

```
generating indices... genindex py-modindexdone
writing additional pages... search/home/james/ansible/docs/docsite/_themes/sphinx_rtd_theme/search.html:21: RemovedInSphinx30Warning: To modify script_files in the theme is deprecated. Please insert a <script> tag directly in your theme instead.
 {% endblock %}
 opensearchdone
copying images... [100%] dev_guide/style_guide/images/thenvsthan.jpg
copying downloadable files... [ 50%] network/getting_started/sample_files/first_copying downloadable files... [100%] network/getting_started/sample_files/first_playbook_ext.yml
copying static files... ... done
copying extra files... done
dumping search index in English (code: en)... done
dumping object inventory... done
build succeeded, 35 warnings.

The HTML pages are in _build/html.
make[1]: Leaving directory `/home/james/ansible/docs/docsite'
```

现在，请注意，在这个过程结束时，`make`命令告诉我们在哪里查找编译好的文档。如果你在这里查找，你会找到以下内容：

```
$ find /home/james/ansible/docs/docsite -name remote_filecopy*
/home/james/ansible/docs/docsite/rst/modules/remote_filecopy_module.rst
/home/james/ansible/docs/docsite/_build/html/modules/remote_filecopy_module.html
/home/james/ansible/docs/docsite/_build/doctrees/modules/remote_filecopy_module.doctree
```

尝试在你的网页浏览器中打开 HTML 文件 - 你应该看到页面的呈现就像官方 Ansible 项目文档中的一个页面！这使你能够检查你的文档是否构建正确，并且在将要查看的上下文中看起来和读起来都很好。这也让你有信心，当你提交你的代码到 Ansible 项目时（如果你这样做的话），你提交的是符合 Ansible 文档质量标准的东西。

有关在本地构建文档的更多信息，请参阅这里：[`docs.ansible.com/ansible/latest/community/documentation_contributions.html#building-the-documentation-locally`](https://docs.ansible.com/ansible/latest/community/documentation_contributions.html#building-the-documentation-locally)。虽然这是一个很好的文档，但它目前并没有反映出围绕 Sphinx 的兼容性问题，也没有反映出关于 Ansible 2.9 的构建问题。然而，希望它会给你所有其他你需要开始你的文档的指针。

目前构建文档的过程在支持的环境方面有些麻烦；但是，希望这是一些将来会解决的问题。与此同时，本节中概述的过程已经为您提供了一个经过测试和可行的起点。

# 模块清单

除了我们迄今为止涵盖的指针和良好的实践之外，在您的模块代码中还有一些事项，您应该遵循，以便产生一个被认为是符合 Ansible 潜在包含标准的东西。以下清单并不详尽，但会给您一个关于您作为模块开发人员应该遵循的实践的良好想法：

+   尽可能多地测试您的模块，无论是在成功的情况下还是在导致错误的情况下。您可以使用 JSON 数据进行测试，就像我们在本章中所做的那样，或者在测试 playbook 中使用它们。

+   尽量将您的 Python 要求保持在最低限度。有时，可能无法避免需要额外的 Python 依赖（例如 AWS 特定模块的`boto`要求），但一般来说，您使用的越少越好。

+   不要为您的模块缓存数据 - Ansible 在不同主机上的执行策略意味着您不太可能从中获得良好的结果。期望在每次运行时收集您需要的所有数据。

+   模块应该是一个单独的 Python 文件 - 它们不应该分布在多个文件中。

+   确保在提交模块代码时调查并运行 Ansible 集成测试。有关这些测试的更多信息，请参阅：[`docs.ansible.com/ansible/latest/dev_guide/testing_integration.html`](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html)。

+   确保在模块代码的适当位置包含异常处理，就像我们在本章中所做的那样，以防止出现问题。

+   在 Windows 模块中不要使用`PSCustomObjects`，除非您绝对无法避免它。

凭借您从本章中获得的信息，您应该有开始创建自己的模块所需的一切。您可能决定不将它们提交到 Ansible 项目，并且确实没有这样的要求。但是，即使您不这样做，遵循本章中概述的实践将确保您构建一个高质量的模块，无论其预期的受众是谁。最后，基于您确实希望将源代码提交到 Ansible 项目的前提，在接下来的部分中，我们将看看如何通过向 Ansible 项目提交拉取请求来实现这一点。

# 向上游贡献 - 提交 GitHub 拉取请求

当您努力工作在您的模块上并彻底测试和记录它之后，您可能会觉得是时候将其提交到 Ansible 项目以供包含了。这意味着在官方的 Ansible 存储库上创建一个拉取请求。虽然在 GitHub 上的操作细节超出了本书的范围，但我们将为您提供一个基本程序的实际焦点概述。

遵循此处概述的过程将在 GitHub 上为 Ansible 项目生成一个真实的请求，以便您提交的代码可以与他们的代码合并。*除非*您真的有一个准备提交到 Ansible 代码库的新模块，否则*不要*遵循此过程。

要将您的模块作为 Ansible 存储库的拉取请求提交，您需要 fork 官方 Ansible 存储库的`devel`分支。要做到这一点，请从您的 Web 浏览器登录到您的 GitHub 帐户（或者如果您还没有帐户，则创建一个帐户），然后导航到以下截图中显示的 URL。点击右上角的 Fork。作为提醒，官方 Ansible 源代码存储库的 URL 是[`github.com/ansible/ansible.git`](https://github.com/ansible/ansible.git)：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/prac-asb/img/0779e17d-e64b-4699-8632-6bede2ca8db0.png)

现在您已经将存储库分叉到您自己的账户，我们将演示您需要运行的命令，以将您的模块代码添加到其中。然后，我们将向您展示如何创建所需的**拉取请求**（也称为**PRs**），以便您可以将您的新模块与上游的 Ansible 项目合并：

1.  克隆您刚刚分叉到本地机器的`devel`分支。使用类似以下的命令，但确保用与您自己 GitHub 账户匹配的 URL 替换它：

```
$ git clone https://github.com/danieloh30/ansible.git
```

1.  将您的模块代码复制到适当的模块目录中-以下代码中给出的`copy`命令只是一个示例，让您知道该怎么做，但实际上，您应该选择适当的类别子目录来放置您的模块，因为它不一定适合`files`类别。添加完 Python 文件后，执行`git add`使 Git 知道新文件，然后用有意义的提交消息提交它。一些示例命令如下：

```
$ cd ansible
$ cp ~/ansible-development/moduledev/remote_filecopy.py ./lib/ansible/modules/files/
$ git add lib/ansible/modules/files/remote_filecopy.py
$ git commit -m 'Added tested version of remote_filecopy.py for pull request creation'
```

1.  现在，确保使用以下命令将代码推送到您分叉的存储库：

```
$ git push
```

1.  返回到 GitHub 网页浏览器，并导航到拉取请求页面，如下所示。点击“New pull request”按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/prac-asb/img/2b2235ef-6a3a-4f76-9d4b-f035cb98cbdb.png)

按照 GitHub 网站的指导，跟随拉取请求创建过程。一旦您成功提交了拉取请求，您应该能够导航到官方 Ansible 源代码存储库的拉取请求列表，并在那里找到您的拉取请求。拉取请求列表的示例如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/prac-asb/img/6148a8a0-6da2-4a93-882c-2b86faa880ce.png)

当截图被拍摄时，几乎有 31,000 个关闭的拉取请求和将近 1,700 个待审核的！当您阅读本书时，肯定会有更多，这表明 Ansible 在持续发展和增长中非常依赖开源社区。想一想-你也可以成为其中的一部分！如果您的拉取请求被审查需要很长时间，不要惊慌-这只是因为有很多拉取请求需要审查和处理。您可以像我们之前演示的那样，将模块代码添加到本地的`library/`目录中，以便您的拉取请求被处理的速度不会妨碍您使用 Ansible 的工作。有关在本地工作时放置插件代码的更多详细信息可以在这里找到：[`docs.ansible.com/ansible/latest/dev_guide/developing_locally.html`](https://docs.ansible.com/ansible/latest/dev_guide/developing_locally.html)。

除了为自定义模块创建拉取请求之外，还有许多其他贡献到 Ansible 项目的方式。以下是一些其他贡献项目的示例：

+   审查 Ansible 文档并报告您发现的任何错误（在第四章的创建中已经提交了一个）

+   创建一个本地的 Ansible MeetUp 来传播关于 Ansible 的知识。如果你的地区已经有了这样的聚会，考虑定期参加。

+   通过社交媒体传播关于 Ansible 的知识和意识，使用适当的账户引用和标签；例如，`@ansible`，`#ansible`等。

这完成了我们学习如何创建模块的旅程，从最初研究模块操作的理论步骤，一直到将您的新模块代码贡献给 GitHub 上官方的 Ansible 项目。我们希望您发现这段旅程有益和有价值，并且增强了您使用 Ansible 并在需要时扩展其功能的能力。

# 总结

模块是 Ansible 的生命线——没有它们，Ansible 无法在各种系统上执行如此复杂和多样的任务。由于是开源项目，通过一点 Python 知识，您可以轻松扩展 Ansible 的功能。在本章中，我们探讨了如何从头开始编写自定义模块。截至目前，Ansible 非常丰富多功能，但这种易于定制和扩展的特性使得 Ansible 在潜力方面几乎没有限制，尤其是考虑到 Python 作为一种编程语言的强大和流行。

在本章中，我们从回顾如何使用命令行执行多个模块开始。然后，我们探讨了询问当前模块索引的过程，以及如何获取模块文档来评估其是否适合我们的需求，无论我们是否有活动的互联网连接。然后，我们探讨了模块数据及其 JSON 格式，最后通过一个简单的自定义模块的编码过程，带您进行了一次旅程。这为您提供了在未来创建自己的模块的基础，如果您愿意的话。

在下一章中，我们将探讨使用和创建另一个核心的 Ansible 功能，即插件的过程。

# 发现插件类型

Ansible 的代码一直被设计为模块化的——这是它的核心优势之一。无论是通过使用模块执行任务还是通过插件（我们将很快看到），Ansible 的模块化设计使其能够像本书中展示的那样多才多艺和强大。与模块一样，Ansible 插件都是用 Python 编写的，并且期望以一定的格式摄取和返回数据（稍后会详细介绍）。Ansible 的插件在功能上通常是不可见的，因为您在命令或 playbook 中很少直接调用它们，但它们负责提供 Ansible 提供的一些最重要的功能，包括 SSH 连接、解析清单文件（INI 格式、YAML 或其他格式）以及在数据上运行`jinja2`过滤器的能力。

像往常一样，在继续之前，让我们验证一下您的测试机上是否安装了合适的 Ansible 版本：

```
$  ansible-doc --version
ansible-doc 2.9.6
 config file = /etc/ansible/ansible.cfg
 configured module search path = [u'/root/.ansible/plugins/modules', u'/usr/share/ansible/plugins/modules']
 ansible python module location = /usr/lib/python2.7/site-packages/ansible
 executable location = /usr/bin/ansible-doc
 python version = 2.7.5 (default, Aug 7 2019, 00:51:29) [GCC 4.8.5 20150623 (Red Hat 4.8.5-39)]
```

插件的文档工作与模块的文档工作一样多，您会很高兴地知道，有一个插件索引可在[`docs.ansible.com/ansible/latest/plugins/plugins.html`](https://docs.ansible.com/ansible/latest/plugins/plugins.html)上找到。

您也可以像之前一样使用`ansible-doc`命令，只是您需要添加`-t`开关。插件总是放在适当的类别中，因为它们在类别之间的功能差异很大。如果您没有使用`-t`开关，您最终会指定`ansible-doc -t`模块，它会返回可用模块的列表。

截至目前，Ansible 中可以找到以下插件类别：

+   `become`: 负责使 Ansible 能够获得超级用户访问权限（例如，通过`sudo`）

+   `cache`: 负责缓存从后端系统检索的事实，以提高自动化性能

+   `callback`: 允许您在响应事件时添加新的行为，例如更改 Ansible playbook 运行输出中数据的格式

+   `cliconf`: 提供了对各种网络设备命令行界面的抽象，为 Ansible 提供了一个标准的操作接口

+   `connection`: 提供了从 Ansible 到远程系统的连接（例如，通过 SSH、WinRM、Docker 等）

+   `httpapi`: 告诉 Ansible 如何与远程系统的 API 交互（例如，用于 Fortinet 防火墙）

+   `inventory`: 提供了解析各种静态和动态清单格式的能力

+   `lookup`：允许 Ansible 从外部来源查找数据（例如，通过读取一个平面文本文件）

+   `netconf`：为 Ansible 提供抽象，使其能够与启用 NETCONF 的网络设备一起工作

+   `shell`：提供 Ansible 在不同系统上使用各种 shell 的能力（例如，在 Windows 上使用`powershell`，在 Linux 上使用`sh`）

+   `strategy`：为 Ansible 提供不同的执行策略插件（例如，我们在第四章中看到的调试策略，*Playbooks and Roles*）

+   `vars`：提供 Ansible 从某些来源获取变量的能力，例如我们在第三章中探讨的`host_vars`和`group_vars`目录，*定义您的清单*）

我们将把在 Ansible 网站上探索插件文档作为您完成的练习留给您。但是，如果您想使用`ansible-doc`工具来探索各种插件，您需要运行以下命令：

1.  要使用`ansible-doc`命令列出给定类别中可用的所有插件，可以运行以下命令：

```
$ ansible-doc -t connection -l
```

这将返回连接插件的文本索引，类似于我们在查看模块文档时看到的内容。索引输出的前几行如下所示：

```
kubectl           Execute tasks in pods running on Kubernetes
napalm            Provides persistent connection using NAPALM
qubes             Interact with an existing QubesOS AppVM
libvirt_lxc       Run tasks in lxc containers via libvirt
funcd             Use funcd to connect to target
chroot            Interact with local chroot
psrp              Run tasks over Microsoft PowerShell Remoting Protocol
zone              Run tasks in a zone instance
winrm             Run tasks over Microsoft's WinRM
paramiko_ssh      Run tasks via python ssh (paramiko)
```

1.  然后，您可以探索给定插件的文档。例如，如果我们想了解`paramiko_ssh`插件，我们可以发出以下命令：

```
**$ ansible-doc -t connection paramiko_ssh**
```

您会发现插件文档采用非常熟悉的格式，与我们在第五章中看到的模块的格式类似。

```
> PARAMIKO (/usr/lib/python2.7/site-packages/ansible/plugins/connection/param

 Use the python ssh implementation (Paramiko) to connect to
 targets The paramiko transport is provided because many
 distributions, in particular EL6 and before do not support
 ControlPersist in their SSH implementations. This is needed on
 the Ansible control machine to be reasonably efficient with
 connections. Thus paramiko is faster for most users on these
 platforms. Users with ControlPersist capability can consider
 using -c ssh or configuring the transport in the configuration
 file. This plugin also borrows a lot of settings from the ssh
 plugin as they both cover the same protocol.

 * This module is maintained by The Ansible Community
OPTIONS (= is mandatory):

- host_key_auto_add
 TODO: write it
 [Default: (null)]
 set_via:
 env:
 - name: ANSIBLE_PARAMIKO_HOST_KEY_AUTO_ADD
 ini:
 - key: host_key_auto_add
```

由于 Ansible 各个领域的所有工作和努力，您可以轻松地了解包含在 Ansible 中的插件以及如何使用它们。到目前为止，我们已经看到，插件的文档与模块的文档一样完整。在本章的下一节中，我们将更深入地了解如何找到与您的 Ansible 发行版配套的插件代码。

# 问题

1.  哪个命令行可以作为参数传递给模块？

A) `ansible dbservers -m command "/bin/echo 'hello modules'"`

B) `ansible dbservers -m command -d "/bin/echo 'hello modules'"`

C) `ansible dbservers -z command -a "/bin/echo 'hello modules'"`

D) `ansible dbservers -m command -a "/bin/echo 'hello modules'"`

E) `ansible dbservers -a "/bin/echo 'hello modules'"`

1.  在创建自定义模块并处理异常时，以下哪种做法是不推荐的？

A) 设计一个简单的自定义模块，如果可以避免的话，不要向用户提供回溯。

B) 快速失败您的模块代码，并验证您是否提供了有用和可理解的异常消息。

C) 仅显示与最相关的异常相关的错误消息，而不是所有可能的错误。

D) 确保您的模块文档是相关的并且易于理解。

E) 删除导致错误的 playbook，然后从头开始重新创建它们。

1.  正确或错误：要为 Ansible 上游项目做出贡献，您需要将代码提交到`devel`分支。

A) True

B) False

# 进一步阅读

+   有关 Ansible 模块的常见返回值的文档可以在这里找到：[`docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html#common`](https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html#common)。

+   查看以下文档，了解您可以在 Windows 机器上使用的所有现有模块：[`docs.ansible.com/ansible/latest/modules/list_of_windows_modules.html#windows-modules`](https://docs.ansible.com/ansible/latest/modules/list_of_windows_modules.html#windows-modules)。

+   一些主要的模块索引以及它们的分类可以在以下链接找到：

+   云模块: [`docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html`](https://docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html)

+   集群模块: [`docs.ansible.com/ansible/latest/modules/list_of_clustering_modules.html`](https://docs.ansible.com/ansible/latest/modules/list_of_clustering_modules.html)

+   命令模块: [`docs.ansible.com/ansible/latest/modules/list_of_commands_modules.html`](https://docs.ansible.com/ansible/latest/modules/list_of_commands_modules.html)

+   加密模块: [`docs.ansible.com/ansible/latest/modules/list_of_crypto_modules.html`](https://docs.ansible.com/ansible/latest/modules/list_of_crypto_modules.html)

+   数据库模块: [`docs.ansible.com/ansible/latest/modules/list_of_database_modules.html`](https://docs.ansible.com/ansible/latest/modules/list_of_database_modules.html)

+   身份模块: [`docs.ansible.com/ansible/latest/modules/list_of_identity_modules.html`](https://docs.ansible.com/ansible/latest/modules/list_of_identity_modules.html)

+   所有模块: [`docs.ansible.com/ansible/latest/modules/list_of_all_modules.html`](https://docs.ansible.com/ansible/latest/modules/list_of_all_modules.html)


# 第六章：使用和创建插件

到目前为止，模块一直是我们在 Ansible 中旅程中非常明显和关键的一部分。它们用于执行明确定义的任务，可以用于一次性命令（使用临时命令）或作为更大的 playbook 的一部分。插件对于 Ansible 同样重要，迄今为止我们一直在使用它们，甚至没有意识到！虽然模块始终用于在 Ansible 中创建某种任务，但插件的使用方式取决于它们的用例。有许多不同类型的插件；我们将在本章中向您介绍它们，并让您了解它们的目的。但是，作为一个引子，您是否意识到当 Ansible 使用 SSH 连接到远程服务器时，连接插件提供了功能？这展示了插件发挥的重要作用。

在本章中，我们将为您提供对插件的深入介绍，并向您展示如何探索 Ansible 附带的各种插件。然后，我们将扩展这一点，演示如何创建自己的插件并在 Ansible 项目中使用它们，这与我们在上一章中使用自定义模块的方式非常相似。这将有助于您理解诸如 Ansible 等开源软件提供的无限可能性。

在本章中，我们将涵盖以下主题：

+   发现插件类型

+   查找包含的插件

+   创建自定义插件

# 技术要求

本章假设您已经按照第一章中详细介绍的方式设置了 Ansible 的控制主机，并且您正在使用最新版本。本章中的示例是使用 Ansible 2.9 进行测试的。本章还假设您至少有一个额外的主机进行测试；最好是基于 Linux 的主机。

尽管本章将给出主机名的具体示例，但您可以自由地用您自己的主机名和/或 IP 地址替换它们，如何做到这一点的详细信息将在适当的位置提供。本章涵盖的插件开发工作假设您的计算机上有 Python 2 或 Python 3 开发环境，并且您正在运行 Linux、FreeBSD 或 macOS。需要额外的 Python 模块时，它们的安装将有文档记录。构建模块文档的任务在 Python 3.5 或更高版本中有一些非常具体的要求，因此假设您可以安装一个合适的 Python 环境，如果您希望尝试这样做。

本章的代码包可以在[`github.com/PacktPublishing/Ansible-2-Cookbook/tree/master/Chapter%206`](https://github.com/PacktPublishing/Ansible-2-Cookbook/tree/master/Chapter%206)上找到。

# 查找包含的插件

正如我们在前一节中讨论的，插件在 Ansible 中并不像它们的模块对应物那样明显，然而迄今为止我们在每个单个 Ansible 命令中都在幕后使用它们！让我们在前一节的工作基础上继续，我们查看了插件文档，看看我们可以在哪里找到插件的源代码。这反过来将作为我们自己构建一个简单插件的前提。

如果您在 Linux 系统上使用软件包管理器（即通过 RPM 或 DEB 软件包）安装了 Ansible，则您的插件位置将取决于您的操作系统。例如，在我安装了来自官方 RPM 软件包的 Ansible 的测试 CentOS 7 系统上，我可以看到安装的插件在这里：

```
$ ls /usr/lib/python2.7/site-packages/ansible/plugins/
action    cliconf       httpapi        inventory    lookup     terminal
become    connection    __init__.py    loader.py    netconf    test
cache     doc_fragments __init__.pyc   loader.pyc   shell      vars
callback  filter        __init__.pyo   loader.pyo   strategy
```

注意插件是如何分成子目录的，所有子目录都以它们的类别命名。如果我们想查找我们在前一节中审查过文档的`paramiko_ssh`插件，我们可以在`connection/`子目录中查找：

```
$ ls -l /usr/lib/python2.7/site-packages/ansible/plugins/connection/paramiko_ssh.py
-rw-r--r-- 1 root root 23544 Mar 5 05:39 /usr/lib/python2.7/site-packages/ansible/plugins/connection/paramiko_ssh.py
```

但是，总的来说，我不建议您编辑或更改从软件包安装的文件，因为在升级软件包时很容易覆盖它们。由于本章的目标之一是编写我们自己的简单自定义插件，让我们看看如何在官方 Ansible 源代码中找到插件：

1.  从 GitHub 克隆官方 Ansible 存储库，就像我们之前做的那样，并将目录更改为克隆的位置：

```
$ git clone https://github.com/ansible/ansible.git
$ cd ansible
```

1.  在官方源代码目录结构中，您会发现所有插件都包含在`lib/ansible/plugins/`下（同样，以分类的子目录形式）：

```
$ cd lib/ansible/plugins
```

1.  我们可以通过查看`connection`目录来探索基于连接的插件：

```
$ ls -al connection/
```

此目录的确切内容将取决于您克隆的 Ansible 源代码的版本。在撰写本文时，它看起来如下，每个插件都有一个 Python 文件（类似于我们在第五章中看到的每个模块都有一个 Python 文件）：

```
$ ls -al connection/
total 176
drwxr-xr-x 2 root root 109 Apr 15 17:24 .
drwxr-xr-x 19 root root 297 Apr 15 17:24 ..
-rw-r--r-- 1 root root 16411 Apr 15 17:24 __init__.py
-rw-r--r-- 1 root root 6855 Apr 15 17:24 local.py
-rw-r--r-- 1 root root 23525 Apr 15 17:24 paramiko_ssh.py
-rw-r--r-- 1 root root 32839 Apr 15 17:24 psrp.py
-rw-r--r-- 1 root root 55367 Apr 15 17:24 ssh.py
-rw-r--r-- 1 root root 31277 Apr 15 17:24 winrm.py
```

1.  您可以查看每个插件的内容，以了解它们的工作原理，这也是开源软件的美妙之处的一部分：

```
$ less connection/paramiko_ssh.py
```

以下代码块显示了此文件开头的示例，以便让您了解如果此命令运行正确，您应该看到的输出类型：

```
# (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
# (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
 author: Ansible Core Team
 connection: paramiko
 short_description: Run tasks via python ssh (paramiko)
 description:
 - Use the python ssh implementation (Paramiko) to connect to targets
 - The paramiko transport is provided because many distributions, in particular EL6 and before do not support ControlPersist
 in their SSH implementations.
....
```

请注意`DOCUMENTATION`块，它与我们在处理模块源代码时看到的非常相似。如果您探索每个插件的源代码，您会发现其结构与模块代码结构有些相似。但是，下一节，让我们开始构建我们自己的自定义插件，通过一个实际的例子来学习它们是如何组合在一起的，而不是简单地接受这种说法。

# 创建自定义插件

在本节中，我们将带您完成创建自己插件的实际指南。这个例子必然会很简单。但是，希望它能很好地指导您了解插件开发的原则和最佳实践，并为您构建自己更复杂的插件奠定坚实的基础。我们甚至会向您展示如何将这些与您自己的 playbooks 集成，并在准备就绪时将它们提交给官方 Ansible 项目以供包含。

正如我们在构建自己的模块时所指出的，Ansible 是用 Python 编写的，它的插件也不例外。因此，您需要用 Python 编写您的插件；因此，要开始开发自己的插件，您需要确保已安装 Python 和一些基本工具。如果您的开发机器上已经运行了 Ansible，您可能已经安装了所需的软件包。但是，如果您从头开始，您需要安装 Python、Python 软件包管理器（`pip`）和可能一些其他开发软件包。具体的过程在不同的操作系统之间会有很大的不同，但是这里有一些示例供您参考：

+   在 Fedora 上，您可以运行以下命令来安装所需的软件包：

```
$ sudo dnf install python python-devel
```

+   同样，在 CentOS 上，您可以运行以下命令来安装所需的软件包：

```
$ sudo yum install python python-devel
```

+   在 Ubuntu 上，您可以运行以下命令来安装您需要的软件包：

```
$ sudo apt-get update
$ sudo apt-get install python-pip python-dev build-essential 
```

+   如果您正在使用 Homebrew 包装系统的 macOS，以下命令将安装您需要的软件包：

```
$ sudo brew install python
```

安装所需的软件包后，您需要将 Ansible Git 存储库克隆到本地计算机，因为其中有一些有价值的脚本，我们在模块开发过程中将需要。使用以下命令将 Ansible 存储库克隆到开发机器上的当前目录：

```
$ git clone https://github.com/ansible/ansible.git
$ cd ansible
```

有了所有这些先决条件，让我们开始创建您自己的插件。虽然编写模块和插件之间有许多相似之处，但也有根本的不同之处。实际上，Ansible 可以使用的不同类型的插件实际上是稍微不同编码的，并且有不同的建议。遗憾的是，我们在本书中没有空间来逐一介绍每一种插件，但您可以从官方 Ansible 文档中了解每种插件类型的要求。

对于我们的简单示例，我们将创建一个过滤器插件，用另一个字符串替换给定的字符串。如果您参考前面的文档链接，过滤器插件可能是一些最容易编码的插件，因为与模块一样，对文档没有严格的要求。但是，如果我们要创建一个`lookup`插件，我们将期望创建与我们在第五章中创建的`DOCUMENTATION`、`EXAMPLES`和`RETURN`文档部分相同的文档。我们还需要以相同的方式测试和构建我们的 web 文档。

我们已经涵盖了这一点，因此在本章中不需要重复整个过程。相反，我们将首先专注于创建一个过滤器插件。与其他 Ansible 插件和模块不同，您实际上可以在单个 Python 插件文件中定义多个过滤器。过滤器本质上是相当紧凑的代码。它们也是众多的，因此每个过滤器一个文件的方式不太适用。但是，如果您想编写其他类型的插件（如`lookup`插件），*您将*需要为每个插件创建一个 Python 文件。

让我们开始创建我们的简单过滤器插件。由于我们只创建一个，它将存在于自己的单独的 Python 文件中。如果您想将代码提交回 Ansible 项目，可以提出修改 Ansible 核心过滤器 Python 文件的建议；但现在，我们将把这个作为一个项目留给您自己完成。我们的过滤器文件将被称为`custom_filter.py`，它将存在于一个名为`filter_plugins`的目录中，该目录必须与您的 playbook 目录位于同一目录中。

执行以下步骤来创建和测试您的插件代码：

1.  在插件文件中以标题开始，以便人们知道谁编写了插件以及它发布的许可证。当然，您应该更新版权和许可字段，以适合您的插件的值，但以下文本作为一个示例供您开始使用：

```
# (c) 2020, James Freeman <james.freeman@example.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
```

1.  接下来，我们将添加一个非常简单的 Python 函数——您的函数可以像您想要的那样复杂，但对于我们来说，我们将简单地使用 Python 的`.replace`函数来替换`string`变量中的一个字符串为另一个字符串。以下示例查找`Puppet`的实例，并将其替换为`Ansible`：

```
def improve_automation(a):
 return a.replace("Puppet", "Ansible")
```

1.  接下来，我们需要创建`FilterModule`类的对象，这是 Ansible 将知道这个 Python 文件包含一个过滤器的方法。在这个对象中，我们可以创建一个`filters`定义，并将我们之前定义的过滤器函数的值返回给 Ansible：

```
class FilterModule(object):
       '''improve_automation filters'''
       def filters(self):
           return {'improve_automation': improve_automation}
```

1.  正如您所看到的，这段代码非常简单，我们可以使用内置的 Python 函数，比如`replace`，来操作字符串。在 Ansible 中没有特定的插件测试工具，因此我们将通过编写一个简单的 playbook 来测试我们的插件代码。以下 playbook 代码定义了一个包含单词`Puppet`的简单字符串，并使用`debug`模块将其打印到控制台，应用我们新定义的过滤器到字符串：

```
---
- name: Play to demonstrate our custom filter
  hosts: frontends
  gather_facts: false
  vars:
    statement: "Puppet is an excellent automation tool!"

  tasks:
    - name: make a statement
      debug:
        msg: "{{ statement | improve_automation }}"
```

现在，在我们尝试运行之前，让我们回顾一下目录结构应该是什么样子的。就像我们能够利用我们在第五章中创建的自定义模块一样，通过创建一个`library/`子目录来存放我们的模块，我们也可以为我们的插件创建一个`filter_plugins/`子目录。当你完成了前面代码块中各个文件的编码细节后，你的目录树结构应该是这样的：

```
.
├── filter_plugins
│   ├── custom_filter.py
├── hosts
├── myplugin.yml
```

现在让我们运行一下我们的小测试 playbook，看看我们得到了什么输出。如果一切顺利，它应该看起来像下面这样：

```
$ ansible-playbook -i hosts myplugin.yml

PLAY [Play to demonstrate our custom filter] ***********************************

TASK [make a statement] ********************************************************
ok: [frt01.example.com] => {
 "msg": "Ansible is an excellent automation tool!"
}

PLAY RECAP *********************************************************************
frt01.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

正如你所看到的，我们的新过滤器插件将我们变量的内容中的`Puppet`字符串替换为`Ansible`字符串。当然，这只是一个愚蠢的测试，不太可能被贡献回 Ansible 项目。然而，它展示了如何在只有六行代码和一点点 Python 知识的情况下，我们创建了自己的过滤器插件来操作一个字符串。我相信你可以想出更复杂和有用的东西！

其他插件类型需要比这更多的工作；虽然我们不会在这里详细介绍创建过滤器插件的过程，但你会发现编写过滤器插件更类似于编写模块，因为你需要做以下工作：

+   包括`DOCUMENTATION`、`EXAMPLES`和`RETURN`部分的适当文档。

+   确保你在插件中加入了适当和充分的错误处理。

+   彻底测试它，包括失败和成功的情况。

举个例子，让我们重复前面的过程，但是创建一个`lookup`插件。这个插件将基于一个简化版本的`lookup`插件文件。然而，我们希望调整我们的版本，只返回文件的第一个字符。你可以根据需要调整这个示例，也许从文件中读取头文件，或者你可以添加参数到插件中，允许你使用字符索引提取子字符串。我们将把这个增强活动留给你自己去完成。让我们开始吧！我们的新 lookup 插件将被称为`firstchar`，而`lookup`插件与它们的 Python 文件是一对一的映射，插件文件将被称为`firstchar.py`。（事实上，Ansible 将使用这个文件名作为插件的名称——你在代码中找不到对它的引用！）。如果你打算像之前执行的那样从 playbook 中测试这个插件，你应该在一个名为`lookup_plugins/`的目录中创建它：

1.  首先，像之前一样在插件文件中添加一个头部，以便维护者和版权细节清晰可见。我们从原始的`file.py` `lookup`插件代码中借用了大部分内容，因此我们需要包含相关的来源信息：

```
# (c) 2020, James Freeman <james.freeman@example.com>
# (c) 2012, Daniel Hokka Zakrisson <daniel@hozac.com>
# (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
```

1.  接下来，添加 Python 3 的头文件——如果你打算通过**Pull Request**（**PR**）提交你的插件到 Ansible 项目，这是绝对必需的。

```
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
```

1.  接下来，在你的插件中添加一个`DOCUMENTATION`块，以便其他用户能够理解如何与它交互：

```
DOCUMENTATION = """
    lookup: firstchar
    author: James Freeman <james.freeman@example.com>
    version_added: "2.9"
    short_description: read the first character of file contents
    description:
        - This lookup returns the first character of the contents from a file on the Ansible controller's file system.
    options:
      _terms:
        description: path(s) of files to read
        required: True
    notes:
      - if read in variable context, the file can be interpreted as YAML if the content is valid to the parser.
      - this lookup does not understand 'globing', use the fileglob lookup instead.
"""
```

1.  添加相关的`EXAMPLES`块，展示如何使用你的插件，就像我们为模块做的那样：

```
EXAMPLES = """
- debug: msg="the first character in foo.txt is {{lookup('firstchar', '/etc/foo.txt') }}"

"""
```

1.  还要确保你记录了插件的`RETURN`值：

```
RETURN = """
  _raw:
    description:
      - first character of content of file(s)
"""
```

1.  文档完成后，我们现在可以开始编写我们的 Python 代码了。我们将首先导入所有需要使我们的模块工作的 Python 模块。我们还将设置`display`对象，它用于详细输出和调试。如果你需要显示`debug`输出，应该在插件代码中使用这个对象，而不是`print`语句：

```
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

display = Display()
```

1.  我们现在将创建一个`LookupModule`类的对象。在其中定义一个名为`run`的默认函数（这是 Ansible `lookup`插件框架所期望的），并初始化一个空数组作为我们的返回数据：

```
class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):

        ret = []
```

1.  有了这个，我们将开始一个循环，遍历每个术语（在我们的简单插件中，这将是传递给插件的文件名）。虽然我们只会在简单的用例上测试这个，但查找插件的使用方式意味着它们需要支持操作的`terms`列表。在这个循环中，我们显示有价值的调试信息，并且最重要的是，定义一个包含我们将要打开的每个文件的详细信息的对象，称为`lookupfile`：

```
      for term in terms:
            display.debug("File lookup term: %s" % term)

   lookupfile = self.find_file_in_search_path(variables, 'files', term)

      display.vvvv(u"File lookup using %s as file" % lookupfile)
```

1.  现在，我们将读取文件内容。这可能只需要一行 Python 代码，但我们从第五章中对模块的工作中知道，我们不应该认为我们会得到一个实际可以读取的文件。因此，我们将把读取文件内容的语句放入一个`try`块中，并实现异常处理，以确保插件的行为是合理的，即使在错误情况下，也能传递易于理解的错误消息给用户，而不是 Python 的回溯信息：

```
            try:
                if lookupfile:
               contents, show_data = self._loader._get_file_contents(lookupfile)
                    ret.append(contents.rstrip()[0])
                else:
                    raise AnsibleParserError()
            except AnsibleParserError:
                raise AnsibleError("could not locate file in lookup: %s" % term)
```

请注意，在其中，我们将文件内容的第一个字符（用`[0]`索引表示）附加到我们的空数组中。我们还使用`rstrip`删除任何尾随空格。

1.  最后，我们使用`return`语句将从文件中收集到的字符返回给 Ansible：

```
        return ret
```

1.  再次，我们可以创建一个简单的测试 playbook 来测试我们新创建的插件：

```
---
- name: Play to demonstrate our custom lookup plugin
  hosts: frontends
  gather_facts: false

  tasks:
    - name: make a statement
      debug:
        msg: "{{ lookup('firstchar', 'testdoc.txt')}}"
```

同样，我们使用 debug 模块将输出打印到控制台，并引用我们的`lookup`插件来获取输出。

1.  创建前面代码块中提到的文本文件，名为`testdoc.txt`。它可以包含任何你喜欢的内容——我的包含以下简单文本：

```
Hello
```

为了清晰起见，你的最终目录结构应该如下所示：

```
.
├── hosts
├── lookup_plugins
│   └── firstchar.py
├── myplugin2.yml
└── testdoc.txt
```

1.  现在，当我们运行我们的新 playbook 时，我们应该看到类似以下的输出：

```
$ ansible-playbook -i hosts myplugin2.yml

PLAY [Play to demonstrate our custom lookup plugin] ****************************

TASK [make a statement] ********************************************************
ok: [frt01.example.com] => {
 "msg": "H"
}

PLAY RECAP *********************************************************************
frt01.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

如果一切顺利，你的 playbook 应该返回你创建的文本文件的第一个字符。当然，我们可以做很多事情来增强这段代码，但这是一个很好的简单示例，可以让你开始。

有了这个基础，你现在应该对如何开始编写自己的 Ansible 插件有一个合理的想法。我们下一个逻辑步骤是更深入地了解如何测试我们新编写的插件，我们将在下一节中进行。

# 学习将自定义插件与 Ansible 源代码集成

到目前为止，我们只是以独立的方式测试了我们的插件。这一切都很好，但如果你真的想要将它添加到你自己的 Ansible 源代码分支，或者更好的是，提交给 Ansible 项目以便包含在 PR 中，那该怎么办呢？幸运的是，这个过程与我们在第五章中介绍的非常相似，只是文件夹结构略有不同。

与以前一样，你的第一个任务将是获取官方 Ansible 项目源代码的副本——例如，通过将 GitHub 存储库克隆到你的本地机器上：

```
$ git clone https://github.com/ansible/ansible.git
$ cd ansible
```

接下来，你需要将你的插件代码复制到一个适当的插件目录中。

1.  例如，我们的示例过滤器将被复制到你刚刚克隆的源代码中的以下目录中：

```
$ cp ~/custom_filter.py ./lib/ansible/plugins/filter/
```

1.  类似地，我们的自定义`lookup`插件将放在`lookup`插件的目录中，使用如下命令：

```
$ cp ~/firstchar.py ./lib/ansible/plugins/lookup/
```

将代码复制到位后，你需要像以前一样测试文档（即你的插件是否包含它）。你可以像我们在第五章中那样构建`webdocs`文档，所以我们不会在这里重复。不过，作为一个提醒，我们可以快速检查文档是否正确渲染，使用`ansible-doc`命令，如下所示：

```
$ . hacking/env-setup
running egg_info
creating lib/ansible.egg-info
writing requirements to lib/ansible.egg-info/requires.txt
writing lib/ansible.egg-info/PKG-INFO
writing top-level names to lib/ansible.egg-info/top_level.txt
writing dependency_links to lib/ansible.egg-info/dependency_links.txt
writing manifest file 'lib/ansible.egg-info/SOURCES.txt'
reading manifest file 'lib/ansible.egg-info/SOURCES.txt'
reading manifest template 'MANIFEST.in'
warning: no files found matching 'SYMLINK_CACHE.json'
writing manifest file 'lib/ansible.egg-info/SOURCES.txt'

Setting up Ansible to run out of checkout...

PATH=/home/james/ansible/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin
PYTHONPATH=/home/james/ansible/lib
MANPATH=/home/james/ansible/docs/man:/usr/local/share/man:/usr/share/man

Remember, you may wish to specify your host file with -i

Done!

$ ansible-doc -t lookup firstchar
> FIRSTCHAR (/home/james/ansible/lib/ansible/plugins/lookup/firstchar.py)

 This lookup returns the first character of the contents from a
 file on the Ansible controller's file system.

 * This module is maintained by The Ansible Community
OPTIONS (= is mandatory):

= _terms
 path(s) of files to read
```

到目前为止，您已经看到在 Ansible 中插件开发和模块开发之间有很多重叠。特别重要的是要注意异常处理和生成高质量、易于理解的错误消息，并遵守和维护 Ansible 的高标准文档。我们在这里没有涵盖的一个额外的项目是插件输出。所有插件必须返回 Unicode 字符串；这确保它们可以正确通过`jinja2`过滤器运行。更多指导信息可以在官方 Ansible 文档中找到：[`docs.ansible.com/ansible/latest/dev_guide/developing_plugins.html`](https://docs.ansible.com/ansible/latest/dev_guide/developing_plugins.html)。

有了这些知识，现在您应该可以开始自己的插件开发工作，甚至可以将您的代码提交回社区，如果您愿意的话。我们将在下一节简要回顾一下这一点。

# 与社区分享插件

您可能希望将您的新插件提交到 Ansible 项目，就像我们在第五章中考虑我们的自定义模块一样，*使用和创建模块*。这个过程与模块的过程几乎完全相同，这一部分将对此进行回顾。

使用以下流程将向 GitHub 上的 Ansible 项目提交一个真实的请求，将您提交的代码与他们的代码合并。除非您真的有一个准备提交到 Ansible 代码库的新模块，否则*不要*按照这个流程进行。

为了将您的插件作为 Ansible 存储库的 PR 提交，您首先需要 fork 官方 Ansible 存储库的`devel`分支。要做到这一点，在您的网络浏览器上登录 GitHub 账户（或者如果您还没有账户，创建一个），然后导航到[`github.com/ansible/ansible.git`](https://github.com/ansible/ansible.git)。点击页面右上角的 Fork：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/prac-asb/img/e7b8c847-4112-4e50-bc4e-3fb49b62e8ef.png)

一旦您将存储库 fork 到您自己的账户，我们将指导您运行所需的命令，将您的模块代码添加到其中，然后创建必需的 PRs，以便将您的新模块与上游 Ansible 项目合并：

1.  克隆您刚刚 fork 到本地计算机的`devel`分支。使用类似以下命令的命令，但一定要用符合您自己 GitHub 账户的 URL 替换它：

```
$ git clone https://github.com/<your GitHub account>/ansible.git
```

1.  将您的模块代码复制到适当的`plugins/`目录中。以下代码块中使用的`copy`命令只是一个示例，让您了解要做什么——实际上，您应该选择适当的类别子目录来放置您的插件，因为它不一定适合`lookup`类别。一旦您添加了 Python 文件，执行`git add`命令使 Git 知道新文件，然后用有意义的`commit`消息提交它。这里显示了一些示例命令：

```
$ cd ansible
$ cp ~/ansible-development/plugindev/firstchar.py ./lib/ansible/plugins/lookup
$ git add lib/ansible/plugins/lookup/firstchar.py
$ git commit -m 'Added tested version of firstchar.py for pull request creation'
```

1.  现在，请确保使用以下命令将代码推送到您 fork 的存储库：

```
$ git push
```

1.  在您的网络浏览器中返回 GitHub，并导航到 Pull Requests 页面，如下面的屏幕截图所示。点击 New pull request 按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/prac-asb/img/25997bfa-230e-4627-9bef-042c675fb503.png)

按照 GitHub 网站的指导，完成 PR 创建过程。一旦您成功提交了您的 PR，您应该能够导航到官方 Ansible 源代码存储库的 PR 列表，并在那里找到您的 PR。以下是一个 PR 列表的示例截图，供您参考：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/prac-asb/img/c2be2eb5-8243-4e21-8d26-96e2769181b6.png)

如前所述，如果您的 PR 需要很长时间才能得到审查，不要感到惊慌 - 这仅仅是因为有很多 PR 需要审查和处理。您始终可以通过将插件代码添加到本地`*_plugins/`目录中来在本地使用您的插件代码，就像我们之前演示的那样，这样您的 PR 的处理速度不会妨碍您使用 Ansible。有关在本地工作时放置插件代码的更多详细信息，请参阅[`docs.ansible.com/ansible/latest/dev_guide/developing_locally.html`](https://docs.ansible.com/ansible/latest/dev_guide/developing_locally.html)。

我们完成了对插件创建的探讨，包括两个可工作的示例。希望您发现这段旅程是有益和有价值的，并且增强了您使用 Ansible 并在需要时扩展其功能的能力。

# 总结

Ansible 插件是 Ansible 功能的核心部分，在本章中，我们发现在整本书中一直在使用它们，甚至没有意识到！Ansible 的模块化设计使得无论您是使用模块还是当前支持的各种类型的插件，都可以轻松扩展和添加功能。无论是添加用于字符串处理的新过滤器，还是查找数据的新方法（或者甚至是连接到新技术的新连接机制），Ansible 插件提供了一个完整的框架，可以将 Ansible 的功能远远扩展到其已经广泛的能力之外。

在本章中，我们了解了 Ansible 支持的各种类型的插件，然后更详细地探讨了它们，并了解了如何获取现有插件的文档和信息。然后，我们完成了两个实际示例，为 Ansible 创建了两种不同类型的插件，同时探讨了插件开发的最佳实践以及这如何与模块开发重叠。最后，我们回顾了如何将我们的新插件代码作为 PR 提交回 Ansible 项目。

在下一章中，我们将探讨编写 Ansible playbook 时应遵循的最佳实践，以确保您生成可管理、高质量的自动化代码。

# 问题

1.  您可以使用以下哪个`ansible-doc`命令来列出所有缓存插件的名称？

A) `ansible-doc -a cache -l`

B) `ansible-doc cache -l`

C) `ansible-doc -a cache`

D) `ansible-doc -t cache -l`

E) `ansible-doc cache`

1.  您需要将哪个类添加到您的`lookup`插件代码中，以包括大部分插件代码，包括`run()`、`items`循环、`try`和`except`？

A) `LookupModule`

B) `RunModule`

C) `StartModule`

D) `InitModule`

E) `LoadModule`

1.  真或假 - 为了使用 Python 创建自定义插件，您需要在您的操作系统上安装带有相关依赖项的 Python：

A) True

B) False

# 进一步阅读

您可以通过直接访问 Ansible 存储库来找到所有插件，网址为[`github.com/ansible/ansible/tree/devel/lib/ansible/plugins`](https://github.com/ansible/ansible/tree/devel/lib/ansible/plugins)。


# 第七章：编码最佳实践

Ansible 可以帮助您自动化几乎所有日常 IT 任务，从单调的任务，如应用补丁或部署配置文件，到部署全新的基础设施作为代码。随着越来越多的人意识到其强大和简单，Ansible 的使用和参与每年都在增长。您会在互联网上找到许多示例 Ansible playbook、角色、博客文章等，再加上本书这样的资源，您将能够熟练地编写自己的 Ansible playbook。

然而，您如何知道在 Ansible 中编写自动化代码的最佳方法是什么？您如何判断在互联网上找到的示例是否实际上是一种好的做事方式？在本章中，我们将带您了解 Ansible 最佳实践的实际指南，向您展示目前被认为是关于目录结构和 playbook 布局的良好实践，如何有效地使用清单（特别是在云上），以及如何最好地区分您的环境。通过本章的学习，您应该能够自信地编写从小型单任务 playbook 到复杂环境的大规模 playbook。

在本章中，我们将涵盖以下主题：

+   首选的目录布局

+   云清单的最佳方法

+   区分不同的环境类型

+   定义组和主机变量的正确方法

+   使用顶级 playbook

+   利用版本控制工具

+   设置操作系统和分发差异

+   Ansible 版本之间的移植

# 技术要求

本章假设您已经按照第一章 *开始使用 Ansible*中的方式设置了 Ansible 的控制主机，并且您正在使用最新版本；本章的示例是在 Ansible 2.9 上测试的。本章还假设您至少有一个额外的主机进行测试；理想情况下，这应该是基于 Linux 的。尽管本章将给出主机名的具体示例，但欢迎您用自己的主机名和/或 IP 地址替换它们，如何做到这一点的详细信息将在适当的地方提供。

本章中使用的代码包可以在[`github.com/PacktPublishing/Ansible-2-Cookbook/tree/master/Chapter%207`](https://github.com/PacktPublishing/Ansible-2-Cookbook/tree/master/Chapter%207)找到。

# 首选的目录布局

正如我们在本书中探讨了 Ansible 一样，我们多次表明，随着 playbook 的规模和规模的增长，您越有可能希望将其分成多个文件和目录。这方面的一个很好的例子是角色，在第四章 *Playbooks and Roles*中，我们定义了角色，不仅使我们能够重用常见的自动化代码，还使我们能够将潜在的庞大的单个 playbook 分成更小、逻辑上组织得更好、更易管理的部分。我们还在第三章 *Defining Your Inventory*中，探讨了定义清单文件的过程，以及如何将其分成多个文件和目录。然而，我们还没有探讨如何将所有这些放在一起。所有这些都在官方 Ansible 文档中有记录，网址是[`docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html#content-organization`](https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html#content-organization)。

然而，在本章中，让我们从一个实际的例子开始，向您展示一个设置简单基于角色的 playbook 的目录结构的好方法，其中有两个不同的清单——一个用于开发环境，一个用于生产环境（在任何真实的用例中，您都希望将它们分开，尽管理想情况下，您应该能够在两者上执行相同的操作以保持一致性和测试目的）。

让我们开始构建目录结构：

1.  使用以下命令为您的开发清单创建目录树：

```
$ mkdir -p inventories/development/group_vars
$ mkdir -p inventories/development/host_vars
```

1.  接下来，我们将为我们的开发清单定义一个 INI 格式的清单文件——在我们的示例中，我们将保持非常简单，只有两台服务器。要创建的文件是`inventories/development/hosts`：

```
[app]
app01.dev.example.com
app02.dev.example.com
```

1.  为了进一步说明，我们将为我们的 app 组添加一个组变量。如第三章中所讨论的，创建一个名为`app.yml`的文件，放在我们在上一步中创建的`group_vars`目录中：

```
---
http_port: 8080
```

1.  接下来，使用相同的方法创建一个`production`目录结构：

```
$ mkdir -p inventories/production/group_vars
$ mkdir -p inventories/production/host_vars
```

1.  在新创建的`production`目录中创建名为`hosts`的清单文件，并包含以下内容：

```
[app]
app01.prod.example.com
app02.prod.example.com
```

1.  现在，我们将为我们的生产清单的`http_port`组变量定义一个不同的值。将以下内容添加到`inventories/production/group_vars/app.yml`中：

```
---
http_port: 80
```

这完成了我们的清单定义。接下来，我们将添加任何我们可能发现对我们的 playbook 有用的自定义模块或插件。假设我们想要使用我们在第五章中创建的`remote_filecopy.py`模块。就像我们在本章中讨论的那样，我们首先为这个模块创建目录：

```
$ mkdir library
```

然后，将`remote_filecopy.py`模块添加到此库中。我们不会在这里重新列出代码以节省空间，但您可以从第五章中名为*开发自定义模块*的部分复制它，或者利用本书在 GitHub 上附带的示例代码。

插件也可以做同样的事情；如果我们还想使用我们在第六章中创建的`filter`插件，我们将创建一个适当命名的目录：

```
$ mkdir filter_plugins
```

然后，将`filter`插件代码复制到此目录中。

最后，我们将创建一个角色来在我们的新 playbook 结构中使用。当然，您会有很多角色，但我们将创建一个作为示例，然后您可以为每个角色重复这个过程。我们将称我们的角色为`installapp`，并使用`ansible-galaxy`命令（在第四章中介绍）为我们创建目录结构：

```
$ mkdir roles
$ ansible-galaxy role init --init-path roles/ installapp
- Role installapp was created successfully
```

然后，在我们的`roles/installapp/tasks/main.yml`文件中，我们将添加以下内容：

```
---
- name: Display http_port variable contents
  debug:
    var: http_port

- name: Create /tmp/foo
  file:
    path: /tmp/foo
    state: file

- name: Use custom module to copy /tmp/foo
  remote_filecopy:
    source: /tmp/foo
    dest: /tmp/bar

- name: Define a fact about automation
  set_fact:
    about_automation: "Puppet is an excellent automation tool"

- name: Tell us about automation with a custom filter applied
  debug:
    msg: "{{ about_automation | improve_automation }}"
```

在上述代码中，我们重用了本书前几章的许多示例。您还可以像之前讨论的那样为角色定义处理程序、变量、默认值等，但对于我们的示例来说，这就足够了。

创建我们最佳实践目录结构的最后阶段是添加一个顶层 playbook 来运行。按照惯例，这将被称为`site.yml`，并且它将具有以下简单内容（请注意，我们构建的目录结构处理了许多事情，使得顶层 playbook 非常简单）：

```
---
- name: Play using best practise directory structure
  hosts: all

  roles:
    - installapp
```

为了清晰起见，您的最终目录结构应如下所示：

```
.
├── filter_plugins
│   ├── custom_filter.py
│   └── custom_filter.pyc
├── inventories
│   ├── development
│   │   ├── group_vars
│   │   │   └── app.yml
│   │   ├── hosts
│   │   └── host_vars
│   └── production
│   ├── group_vars
│   │   └── app.yml
│   ├── hosts
│   └── host_vars
├── library
│   └── remote_filecopy.py
├── roles
│   └── installapp
│   ├── defaults
│   │   └── main.yml
│   ├── files
│   ├── handlers
│   │   └── main.yml
│   ├── meta
│   │   └── main.yml
│   ├── README.md
│   ├── tasks
│   │   └── main.yml
│   ├── templates
│   ├── tests
│   │   ├── inventory
│   │   └── test.yml
│   └── vars
│   └── main.yml
└── site.yml
```

现在，我们可以以正常方式运行我们的 playbook。例如，要在开发清单上运行它，请执行以下操作：

```
$ ansible-playbook -i inventories/development/hosts site.yml

PLAY [Play using best practise directory structure] ****************************

TASK [Gathering Facts] *********************************************************
ok: [app02.dev.example.com]
ok: [app01.dev.example.com]

TASK [installapp : Display http_port variable contents] ************************
ok: [app01.dev.example.com] => {
 "http_port": 8080
}
ok: [app02.dev.example.com] => {
 "http_port": 8080
}

TASK [installapp : Create /tmp/foo] ********************************************
changed: [app02.dev.example.com]
changed: [app01.dev.example.com]

TASK [installapp : Use custom module to copy /tmp/foo] *************************
changed: [app02.dev.example.com]
changed: [app01.dev.example.com]

TASK [installapp : Define a fact about automation] *****************************
ok: [app01.dev.example.com]
ok: [app02.dev.example.com]

TASK [installapp : Tell us about automation with a custom filter applied] ******
ok: [app01.dev.example.com] => {
 "msg": "Ansible is an excellent automation tool"
}
ok: [app02.dev.example.com] => {
 "msg": "Ansible is an excellent automation tool"
}

PLAY RECAP *********************************************************************
app01.dev.example.com : ok=6 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
app02.dev.example.com : ok=6 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

同样，对生产清单运行以下命令：

```
$ ansible-playbook -i inventories/production/hosts site.yml

PLAY [Play using best practise directory structure] ****************************

TASK [Gathering Facts] *********************************************************
ok: [app02.prod.example.com]
ok: [app01.prod.example.com]

TASK [installapp : Display http_port variable contents] ************************
ok: [app01.prod.example.com] => {
 "http_port": 80
}
ok: [app02.prod.example.com] => {
 "http_port": 80
}

TASK [installapp : Create /tmp/foo] ********************************************
changed: [app01.prod.example.com]
changed: [app02.prod.example.com]

TASK [installapp : Use custom module to copy /tmp/foo] *************************
changed: [app02.prod.example.com]
changed: [app01.prod.example.com]

TASK [installapp : Define a fact about automation] *****************************
ok: [app01.prod.example.com]
ok: [app02.prod.example.com]

TASK [installapp : Tell us about automation with a custom filter applied] ******
ok: [app01.prod.example.com] => {
 "msg": "Ansible is an excellent automation tool"
}
ok: [app02.prod.example.com] => {
 "msg": "Ansible is an excellent automation tool"
}

PLAY RECAP *********************************************************************
app01.prod.example.com : ok=6 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
app02.prod.example.com : ok=6 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

注意适当的主机和相关变量是如何被每个清单捕捉到的，以及我们的目录结构是多么整洁和有条理。这是你布置 playbooks 的理想方式，将确保它们可以按需扩展到任何你需要的规模，而不会变得笨重和难以管理或排查故障。在本章的下一节中，我们将探讨处理云清单的最佳方法。

# 云清单的最佳方法

在第三章《定义清单》中，我们看了一个简单的例子，介绍了如何使用动态清单，并通过使用 Cobbler provisioning 系统的实际示例为你提供了指导。然而，当涉及到使用云清单（它们只是动态清单的一种形式，但专门针对云）时，一开始可能会感到有些困惑，你可能会发现很难让它们运行起来。如果你按照本节概述的高级程序，这将成为一个简单而直接的任务。

由于这是一本实践性的书，我们将选择一个示例进行讨论。遗憾的是，我们没有空间为所有云提供商提供实际示例，但如果你按照我们将为亚马逊 EC2 概述的高级流程，并将其应用到你所需的云提供商（例如，Microsoft Azure 或 Google Cloud Platform），你会发现上手和运行的过程实际上非常简单。

然而，在开始之前需要注意的一点是，在包括 2.8.x 版本在内的 Ansible 版本中，动态清单脚本是 Ansible 源代码的一部分，并且可以从我们在本书中之前检查和克隆的主要 Ansible 存储库中获取。随着 Ansible 不断增长和扩展的性质，已经有必要在 2.9.x 版本（以及以后的版本）中将动态清单脚本分离到一个称为 Ansible 集合的新分发机制中，这将成为 2.10 版本的主流（在撰写本文时尚未发布）。你可以在[`www.ansible.com/blog/getting-started-with-ansible-collections`](https://www.ansible.com/blog/getting-started-with-ansible-collections)了解更多关于 Ansible 集合及其内容。

然而，随着 Ansible 2.10 版本的发布，你下载和使用动态清单脚本的方式可能会发生根本性的变化，然而，遗憾的是，在撰写本文时，关于这将是什么样子，目前还没有透露太多。因此，我们将指导你下载当前 2.9 版本所需的动态清单提供商脚本，并建议你在 2.10 版本发布时查阅 Ansible 文档，以获取相关脚本的下载位置。一旦你下载了它们，我相信你将能够按照本章概述的方式继续使用它们。

如果你正在使用 Ansible 2.9 版本，你可以在 GitHub 的 stable-2.9 分支上找到并下载所有最新的动态清单脚本，网址为[`github.com/ansible/ansible/tree/stable-2.9/contrib/inventory`](https://github.com/ansible/ansible/tree/stable-2.9/contrib/inventory)。

尽管官方的 Ansible 文档已经更新，但互联网上的大多数指南仍然引用这些脚本的旧 GitHub 位置，你会发现它们已经不再起作用。在使用动态清单时，请记住这一点！现在让我们继续讨论使用云提供商的动态清单脚本的过程；我们将以亚马逊 EC2 动态清单脚本作为工作示例，但我们在这里应用的原则同样适用于任何其他云清单脚本：

1.  在确定我们要使用 Amazon EC2 之后，我们的第一个任务是获取动态清单脚本及其相关的配置文件。由于云技术发展迅速，最安全的做法可能是直接从 GitHub 上的官方 Ansible 项目下载这些文件的最新版本。以下三个命令将下载动态清单脚本并使其可执行，以及下载模板配置文件：

```
$ wget https://raw.githubusercontent.com/ansible/ansible/stable-2.9/contrib/inventory/ec2.py
$ chmod +x ec2.py
$ wget https://raw.githubusercontent.com/ansible/ansible/stable-2.9/contrib/inventory/ec2.ini
```

1.  成功下载文件后，让我们来看看它们的内容。不幸的是，Ansible 动态清单没有与我们在模块和插件中看到的那样整洁的文档系统。然而，对我们来说幸运的是，这些动态清单脚本的作者在这些文件的顶部放置了许多有用的注释，以帮助我们入门。让我们来看看`ec2.py`的内容：

```
#!/usr/bin/env python

'''
EC2 external inventory script
=================================

Generates inventory that Ansible can understand by making API request to
AWS EC2 using the Boto library.

NOTE: This script assumes Ansible is being executed where the environment
variables needed for Boto have already been set:
    export AWS_ACCESS_KEY_ID='AK123'
    export AWS_SECRET_ACCESS_KEY='abc123'

Optional region environment variable if region is 'auto'

This script also assumes that there is an ec2.ini file alongside it. To specify
 a
different path to ec2.ini, define the EC2_INI_PATH environment variable:

    export EC2_INI_PATH=/path/to/my_ec2.ini
```

有很多文档需要阅读，但其中一些最相关的信息包含在那些开头几行中。首先，我们需要确保`Boto`库已安装。其次，我们需要为`Boto`设置 AWS 访问参数。本文档的作者已经给了我们最快的入门方式（确实，他们的工作不是复制`Boto`文档）。

但是，如果您参考`Boto`的官方文档，您会发现有很多配置 AWS 凭据的方法——设置环境变量只是其中之一。您可以在[`boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html`](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html)上阅读有关配置`Boto`身份验证的更多信息。

1.  在继续安装`Boto`之前，让我们来看看示例`ec2.ini`文件：

```
# Ansible EC2 external inventory script settings
#

[ec2]

# to talk to a private eucalyptus instance uncomment these lines
# and edit edit eucalyptus_host to be the host name of your cloud controller
#eucalyptus = True
#eucalyptus_host = clc.cloud.domain.org

# AWS regions to make calls to. Set this to 'all' to make request to all regions
# in AWS and merge the results together. Alternatively, set this to a comma
# separated list of regions. E.g. 'us-east-1,us-west-1,us-west-2' and do not
# provide the 'regions_exclude' option. If this is set to 'auto', AWS_REGION or
# AWS_DEFAULT_REGION environment variable will be read to determine the region.
regions = all
regions_exclude = us-gov-west-1, cn-north-1
```

同样，您可以在此文件中看到大量经过良好记录的选项，并且如果您滚动到底部，甚至会发现您可以在此文件中指定您的凭据，作为先前讨论的方法的替代。然而，默认设置对于您只是想开始使用的情况已经足够了。

1.  让我们现在确保`Boto`库已安装；确切的安装方法将取决于您选择的操作系统和 Python 版本。您可能可以通过软件包安装它；在 CentOS 7 上，您可以按照以下步骤执行此操作：

```
$ sudo yum -y install python-boto python-boto3
```

或者，您可以使用`pip`来实现这一目的。例如，要将其安装为 Python 3 环境的一部分，您可以运行以下命令：

```
$ sudo pip3 install boto3
```

1.  安装了`Boto`之后，让我们继续使用前面文档中建议给我们的环境变量来设置我们的 AWS 凭据：

```
$ export AWS_ACCESS_KEY_ID='<YOUR_DATA>'
$ export AWS_SECRET_ACCESS_KEY='<YOUR_DATA>'
```

1.  完成这些步骤后，您现在可以像往常一样使用动态清单脚本——只需使用`-i`参数引用可执行的清单脚本，就像您在静态清单中所做的那样。例如，如果您想对在 Amazon EC2 上运行的所有主机运行 Ansible `ping`模块作为临时命令，您需要运行以下命令。确保用`-u`开关指定的用户帐户替换连接到 EC2 实例的用户帐户。还要引用您的私有 SSH 密钥文件：

```
$ ansible -i ec2.py -u ec2-user --private-key /home/james/my-ec2-id_rsa -m ping all
```

就是这样——如果您以同样的系统方法处理所有动态清单脚本，那么您将毫无问题地使它们运行起来。只需记住，文档通常嵌入在脚本文件和其附带的配置文件中，请确保在尝试使用脚本之前阅读两者。

需要注意的一点是，许多动态清单脚本，包括`ec2.py`，会缓存其对云提供商的 API 调用结果，以加快重复运行的速度并避免过多的 API 调用。然而，在快速发展的开发环境中，你可能会发现云基础设施的更改没有被及时捕捉到。对于大多数脚本，有两种解决方法——大多数特性缓存配置参数在其配置文件中，比如`ec2.ini`中的`cache_path`和`cache_max_age`参数。如果你不想为每次运行都设置这些参数，你也可以通过直接调用动态清单脚本并使用特殊开关来手动刷新缓存，例如在`ec2.py`中：

```
$ ./ec2.py --refresh-cache
```

这就结束了我们对云清单脚本的实际介绍。正如我们讨论过的，只要你查阅文档（包括互联网上的文档和每个动态清单脚本中嵌入的文档），并遵循我们描述的简单方法，你应该不会遇到问题，并且应该能够在几分钟内开始使用动态清单。在下一节中，我们将回到静态清单，并探讨区分各种技术环境的最佳方法。

# 区分不同的环境类型

在几乎每个企业中，你都需要按类型划分你的技术环境。例如，你几乎肯定会有一个开发环境，在这里进行所有的测试和开发工作，并且有一个生产环境，在这里运行所有稳定的测试代码。这些环境（在最理想的情况下）应该使用相同的 Ansible playbooks——毕竟，逻辑是，如果你能够在开发环境成功部署和测试一个应用程序，那么你应该能够以同样的方式在生产环境中部署它，并且它能够正常运行。然而，这两个环境之间总是存在差异，不仅仅是在主机名上，有时还包括参数、负载均衡器名称、端口号等等——这个列表似乎是无穷无尽的。

在本章的*首选目录布局*部分，我们介绍了使用两个单独的清单目录树来区分开发和生产环境的方法。当涉及到区分这些环境时，你应该按照这种方式进行；因此，显然，我们不会重复这些例子，但重要的是要注意，当处理多个环境时，你的目标应该是：

+   尽量重用相同的 playbooks 来运行相同代码的所有环境。例如，如果你在开发环境部署了一个 web 应用程序，你应该有信心你的 playbooks 也能在生产环境（以及你的**质量保证**（**QA**）环境，以及其他可能需要部署的环境）中部署相同的应用程序。

+   这意味着你不仅在测试应用程序部署和代码，还在测试 Ansible 的 playbooks 和 roles 作为整个测试过程的一部分。

+   每个环境的清单应该保存在单独的目录树中（就像本章的*首选目录布局*部分所示），但所有的 roles、playbooks、插件和模块（如果有的话）都应该在相同的目录结构中（这对于两个环境来说应该是一样的）。

+   不同的环境通常需要不同的身份验证凭据；你应该将这些凭据分开保存，不仅是为了安全，还为了确保 playbooks 不会意外地在错误的环境中运行。

+   你的 playbooks 应该在你的版本控制系统中，就像你的代码一样。这样可以让你随着时间跟踪变化，并确保每个人都在使用相同的自动化代码副本。

如果您注意这些简单的指针，您会发现您的自动化工作流程成为您业务的真正资产，并确保在所有部署中可靠性和一致性。相反，不遵循这些指针会使您面临在开发中运行正常但在生产中运行失败的可怕情况，这经常困扰着技术行业。现在，让我们在下一节中继续讨论，看看在处理主机和组变量时的最佳实践，正如我们在*首选目录布局*部分中所看到的，您需要应用这些实践，特别是在处理多个环境时。

# 定义组和主机变量的正确方法

在处理组和主机变量时，您可以使用我们在*首选目录布局*部分中使用的基于目录的方法进行拆分。但是，有一些额外的指针可以帮助您管理这一点。首先，您应该始终注意变量的优先级。变量优先级顺序的详细列表可以在[`docs.ansible.com/ansible/latest/user_guide/playbooks_variables.html#variable-precedence-where-should-i-put-a-variable`](https://docs.ansible.com/ansible/latest/user_guide/playbooks_variables.html#variable-precedence-where-should-i-put-a-variable)找到。但是，处理多个环境的关键要点如下：

+   主机变量始终比组变量的优先级高；因此，您可以使用主机变量覆盖任何组变量。如果您以受控的方式利用此行为，这种行为是有用的，但如果您不了解它，可能会产生意想不到的结果。

+   有一个名为`all`的特殊组变量定义，适用于所有清单组。这比特定定义的组变量的优先级低。

+   如果您在两个组中定义相同的变量会发生什么？如果发生这种情况，两个组具有相同的优先级，那么谁会获胜？为了演示这一点（以及我们之前的例子），我们将为您创建一个简单的实际示例。

要开始，让我们为我们的清单创建一个目录结构。为了尽可能简洁，我们只会创建一个开发环境的例子。但是，您可以通过在本章的*首选目录布局*部分构建更完整的示例来扩展这些概念：

1.  使用以下命令创建一个清单目录结构：

```
$ mkdir -p inventories/development/group_vars
$ mkdir -p inventories/development/host_vars
```

1.  在`inventories/development/hosts`文件中创建一个包含两个主机的单个组的简单清单文件；内容应如下所示：

```
[app]
app01.dev.example.com
app02.dev.example.com
```

1.  现在，让我们为清单中的所有组创建一个特殊的组变量文件；这个文件将被称为`inventories/development/group_vars/all.yml`，应包含以下内容：

```
---
http_port: 8080
```

1.  最后，让我们创建一个名为`site.yml`的简单 playbook，以查询和打印我们刚刚创建的变量的值：

```
---
- name: Play using best practise directory structure
  hosts: all

  tasks:
    - name: Display the value of our inventory variable
      debug:
        var: http_port
```

1.  现在，如果我们运行这个 playbook，我们会看到变量（我们只在一个地方定义）取得了我们期望的值：

```
$ ansible-playbook -i inventories/development/hosts site.yml

PLAY [Play using best practise directory structure] ****************************

TASK [Gathering Facts] *********************************************************
ok: [app01.dev.example.com]
ok: [app02.dev.example.com]

TASK [Display the value of our inventory variable] *****************************
ok: [app01.dev.example.com] => {
 "http_port": 8080
}
ok: [app02.dev.example.com] => {
 "http_port": 8080
}

PLAY RECAP *********************************************************************
app01.dev.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
app02.dev.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

1.  到目前为止，一切顺利！现在，让我们向我们的清单目录结构添加一个新文件，`all.yml`文件保持不变。我们还将创建一个位于`inventories/development/group_vars/app.yml`的新文件，其中将包含以下内容：

```
---
http_port: 8081
```

1.  我们现在在一个名为`all`的特殊组和`app`组中定义了相同的变量（我们的开发清单中的两个服务器都属于这个组）。那么，如果我们现在运行我们的 playbook 会发生什么？输出应如下所示：

```
$ ansible-playbook -i inventories/development/hosts site.yml

PLAY [Play using best practise directory structure] ****************************

TASK [Gathering Facts] *********************************************************
ok: [app02.dev.example.com]
ok: [app01.dev.example.com]

TASK [Display the value of our inventory variable] *****************************
ok: [app01.dev.example.com] => {
 "http_port": 8081
}
ok: [app02.dev.example.com] => {
 "http_port": 8081
}

PLAY RECAP *********************************************************************
app01.dev.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
app02.dev.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

1.  如预期的那样，在特定组中的变量定义获胜，这符合 Ansible 文档中记录的优先顺序。现在，让我们看看如果我们在两个特定命名的组中定义相同的变量会发生什么。为了完成这个示例，我们将创建一个子组，称为`centos`，以及另一个可能包含按照新的构建标准构建的主机的组，称为`newcentos`，这两个应用服务器都将是其成员。这意味着修改`inventories/development/hosts`，使其看起来如下：

```
[app]
app01.dev.example.com
app02.dev.example.com

[centos:children]
app

[newcentos:children]
app
```

1.  现在，让我们通过创建一个名为`inventories/development/group_vars/centos.yml`的文件来重新定义`centos`组的`http_port`变量，其中包含以下内容：

```
---
http_port: 8082
```

1.  为了增加混乱，让我们也在`inventories/development/group_vars/newcentos.yml`中为`newcentos`组定义这个变量，其中包含以下内容：

```
---
http_port: 8083
```

1.  我们现在在组级别定义了相同的变量四次！让我们重新运行我们的 playbook，看看哪个值会通过：

```
$ ansible-playbook -i inventories/development/hosts site.yml

PLAY [Play using best practise directory structure] ****************************

TASK [Gathering Facts] *********************************************************
ok: [app01.dev.example.com]
ok: [app02.dev.example.com]

TASK [Display the value of our inventory variable] *****************************
ok: [app01.dev.example.com] => {
 "http_port": 8083
}
ok: [app02.dev.example.com] => {
 "http_port": 8083
}

PLAY RECAP *********************************************************************
app01.dev.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
app02.dev.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

我们在`newcentos.yml`中输入的值赢了-但为什么？Ansible 文档规定，在清单中（唯一可以这样做的地方）在组级别定义相同的变量时，最后加载的组中的变量获胜。组按字母顺序处理，`newcentos`是字母表中最后一个字母开头的组-因此，它的`http_port`值是获胜的值。

1.  为了完整起见，我们可以通过不触及`group_vars`目录，但添加一个名为`inventories/development/host_vars/app01.dev.example.com.yml`的文件来覆盖所有这些，其中包含以下内容：

```
---
http_port: 9090
```

1.  现在，如果我们最后再次运行我们的 playbook，我们会看到我们在主机级别定义的值完全覆盖了我们为`app01.dev.example.com`设置的任何值。`app02.dev.example.com`不受影响，因为我们没有为它定义主机变量，所以优先级的下一个最高级别是`newcentos`组的组变量：

```
$ ansible-playbook -i inventories/development/hosts site.yml

PLAY [Play using best practise directory structure] ****************************

TASK [Gathering Facts] *********************************************************
ok: [app01.dev.example.com]
ok: [app02.dev.example.com]

TASK [Display the value of our inventory variable] *****************************
ok: [app01.dev.example.com] => {
 "http_port": 9090
}
ok: [app02.dev.example.com] => {
 "http_port": 8083
}

PLAY RECAP *********************************************************************
app01.dev.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
app02.dev.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

有了这些知识，你现在可以做出关于如何在清单中结构化你的变量以确保在主机和组级别都能达到期望结果的高级决策。了解变量优先级顺序是很重要的，因为这些示例已经证明了这一点，但遵循文档中的顺序也将使你能够创建功能强大、灵活的 playbook 清单，可以在多个环境中很好地工作。现在，你可能已经注意到，在本章中，我们在我们的目录结构中使用了一个名为`site.yml`的顶层 playbook。我们将在下一节更详细地讨论这个 playbook。

# 使用顶层 playbooks

到目前为止的所有示例中，我们都是使用 Ansible 推荐的最佳实践目录结构构建的，并且不断地引用顶层 playbook，通常称为`site.yml`。这个 playbook 的理念，实际上，是在我们所有的目录结构中都有一个共同的名字，这样它就可以在整个服务器环境中使用-也就是说，你的**site**。

当然，这并不是说你必须在基础设施的每台服务器或每个功能上使用相同的 playbook 集合；相反，这意味着只有你才能做出最适合你环境的最佳决定。然而，Ansible 自动化的整个目标是所创建的解决方案简单易于运行和操作。想象一下，将一个包含 100 个不同 playbook 的 playbook 目录结构交给一个新的系统管理员-他们怎么知道应该在什么情况下运行哪些 playbook？培训某人使用 playbook 的任务将是巨大的，只会将复杂性从一个领域转移到另一个领域。

在另一端，您可以利用`when`子句与事实和清单分组，以便您的 playbook 确切地知道在每种可能的情况下在每台服务器上运行什么。当然，这是不太可能发生的，事实是您的自动化解决方案最终会处于中间位置。

最重要的是，当收到新的 playbook 目录结构时，新操作员至少知道运行 playbook 和理解代码的起点在哪里。如果他们遇到的顶级 playbook 总是`site.yml`，那么至少每个人都知道从哪里开始。通过巧妙地使用角色和`import_*`和`include_*`语句，您可以将 playbook 分割成可重用代码的逻辑部分，正如我们之前讨论的那样，所有这些都来自一个 playbook 文件。

现在您已经了解了顶级 playbook 的重要性，让我们在下一节中看看如何利用版本控制工具来确保在集中和维护自动化代码时遵循良好的实践。

# 利用版本控制工具

正如我们在本章前面讨论的那样，对于您的 Ansible 自动化代码，版本控制和测试不仅仅是您的代码，还包括清单（或动态清单脚本）、任何自定义模块、插件、角色和 playbook 代码都至关重要。这是因为 Ansible 自动化的最终目标很可能是使用 playbook（或一组 playbook）部署整个环境。这甚至可能涉及部署基础设施作为代码，特别是如果您要部署到云环境中。

对 Ansible 代码的任何更改可能意味着对您的环境的重大更改，甚至可能意味着重要的生产服务是否正常工作。因此，非常重要的是您保持 Ansible 代码的版本历史，并且每个人都使用相同的版本。您可以自由选择最适合您的版本控制系统；大多数公司环境已经有某种版本控制系统。但是，如果您以前没有使用过版本控制系统，我们建议您在 GitHub 或 GitLab 等地方注册免费帐户，这两者都提供免费的版本控制存储库，以及更高级的付费计划。

关于 Git 的版本控制的完整讨论超出了本书的范围；事实上，整本书都致力于这个主题。但是，我们将带您了解最简单的用例。在以下示例中，假定您正在使用 GitHub 上的免费帐户，但如果您使用不同的提供商，只需更改 URL 以匹配您的版本控制存储库主机给您的 URL。

除此之外，您还需要在 Linux 主机上安装命令行 Git 工具。在 CentOS 上，您可以按照以下方式安装这些工具：

```
$ sudo yum install git
```

在 Ubuntu 上，这个过程同样简单：

```
$ sudo apt-get update
$ sudo apt-get install git
```

工具安装完成并且您的帐户设置好之后，您的下一个任务是将 Git 存储库克隆到您的计算机。如果您想开始使用自己的存储库进行工作，您需要与提供商一起设置这一点——GitHub 和 GitLab 都提供了出色的文档，您应该按照这些文档设置您的第一个存储库。

一旦设置和初始化，您可以克隆一个副本到您的本地计算机以对代码进行更改。这个本地副本称为工作副本，您可以按照以下步骤进行克隆和更改的过程（请注意，这些纯属假设性的例子，只是为了让您了解需要运行的命令；您应该根据自己的用例进行调整）：

1.  使用以下命令将您的`git`存储库克隆到本地计算机以创建一个工作副本：

```
$ git clone https://github.com/<YOUR_GIT_ACCOUNT>/<GIT_REPO>.git
Cloning into '<GIT_REPO>'...
remote: Enumerating objects: 7, done.
remote: Total 7 (delta 0), reused 0 (delta 0), pack-reused 7
Unpacking objects: 100% (7/7), done. 
```

1.  切换到您克隆的代码目录（工作副本）并进行任何需要的代码更改：

```
$ cd <GIT_REPO>
$ vim myplaybook.yml
```

1.  确保测试您的代码，并且当您对其满意时，添加已准备提交新版本的更改文件，使用以下命令：

```
$ git add myplaybook.yml
```

1.  接下来要做的是提交您所做的更改。提交基本上是存储库中的新代码版本，因此应该附有有意义的`commit`消息（在`-m`开关后面用引号指定），如下所示：

```
$ git commit -m 'Added new spongle-widget deployment to myplaybook.yml'
[master ed14138] Added new spongle-widget deployment to myplaybook.yml
 Committer: Daniel Oh <doh@danieloh.redhat.com>
Your name and email address were configured automatically based
on your username and hostname. Please check that they are accurate.
You can suppress this message by setting them explicitly. Run the
following command and follow the instructions in your editor to edit
your configuration file:

    git config --global --edit

After doing this, you may fix the identity used for this commit with:

    git commit --amend --reset-author

 1 file changed, 1 insertion(+), 1 deletion(-) 
```

1.  现在，所有这些更改都仅存在于您本地计算机上的工作副本中。这本身就很好，但如果代码可以供所有需要在版本控制系统上查看它的人使用，那将更好。要将更新的提交推送回（例如）GitHub，运行以下命令：

```
$ git push
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 8 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 297 bytes | 297.00 KiB/s, done.
Total 3 (delta 2), reused 0 (delta 0)
remote: Resolving deltas: 100% (2/2), completed with 2 local objects.
To https://github.com/<YOUR_GIT_ACCOUNT>/<GIT_REPO>.git
   0d00263..ed14138 master -> master 
```

就是这样！

1.  现在，其他合作者可以克隆您的代码，就像我们在*步骤 1*中所做的那样。或者，如果他们已经有您的存储库的工作副本，他们可以使用以下命令更新他们的工作副本（如果您想要更新您的工作副本以查看其他人所做的更改，也可以这样做）：

```
$ git pull
```

Git 还有一些非常高级的主题和用例超出了本书的范围。但是，您会发现大约 80%的时间，前面的命令就是您需要的所有 Git 命令行知识。还有许多图形界面的 Git 前端，以及与 Git 存储库集成的代码编辑器和**集成开发环境**（**IDEs**），可以帮助您更好地利用它们。完成这些后，让我们看看如何确保您可以在多个主机上使用相同的 playbook（或 role），即使它们可能具有不同的操作系统和版本。

# 设置 OS 和分发差异

如前所述，我们的目标是尽可能广泛地使用相同的自动化代码。然而，尽管我们努力标准化我们的技术环境，变体总是会出现。例如，不可能同时对所有服务器进行主要升级，因此当出现主要的新操作系统版本时，例如**Red Hat Enterprise Linux**（**RHEL**）8 或 Ubuntu Server 20.04，一些机器将保持在旧版本上，而其他机器将进行升级。同样，一个环境可能标准化为 Ubuntu，但随后引入了一个只在 CentOS 上获得认证的应用程序。简而言之，尽管标准化很重要，但变体总是会出现。

在编写 Ansible playbook 时，特别是 role 时，您的目标应该是使它们尽可能广泛地适用于您的环境。其中一个经典例子是软件包管理——假设您正在编写一个安装 Apache 2 Web 服务器的 role。如果您必须使用此 role 支持 Ubuntu 和 CentOS，不仅要处理不同的软件包管理器（`yum`和`apt`），还要处理不同的软件包名称（`httpd`和`apache2`）。

在第四章中，*Playbooks and Roles*，我们看了如何使用`when`子句将条件应用于任务，以及 Ansible 收集的事实，如`ansible_distribution`。然而，还有另一种在特定主机上运行任务的方法，我们还没有看过。在同一章中，我们还看了如何在一个 playbook 中定义多个 play 的概念——有一个特殊的模块可以根据 Ansible 事实为我们创建清单组，我们可以利用这一点以及多个 play 来创建一个 playbook，根据主机的类型在每个主机上运行适当的任务。最好通过一个实际的例子来解释这一点，所以让我们开始吧。

假设我们在此示例中使用以下简单的清单文件，其中有两个主机在一个名为`app`的单个组中：

```
[app]
app01.dev.example.com
app02.dev.example.com
```

现在让我们构建一个简单的 playbook，演示如何使用 Ansible 事实对不同的 play 进行分组，以便操作系统分发确定 playbook 中运行哪个 play。按照以下步骤创建此 playbook 并观察其运行：

1.  首先创建一个新的 playbook——我们将其称为`osvariants.yml`——包含以下`Play`定义。它还将包含一个单独的任务，如下所示：

```
---
- name: Play to demonstrate group_by module
  hosts: all

  tasks:
    - name: Create inventory groups based on host facts
      group_by:
        key: os_{{ ansible_facts['distribution'] }}
```

到目前为止，playbook 结构对您来说应该已经非常熟悉了。但是，使用`group_by`模块是新的。它根据我们指定的键动态创建新的清单组——在本例中，我们根据从`Gathering Facts`阶段获取的 OS 发行版事实创建组。原始清单组结构保留不变，但所有主机也根据其事实添加到新创建的组中。

因此，我们简单清单中的两台服务器仍然在`app`组中，但如果它们基于 Ubuntu，它们将被添加到一个名为`os_Ubuntu`的新创建的清单组中。同样，如果它们基于 CentOS，它们将被添加到一个名为`os_CentOS`的组中。

1.  有了这些信息，我们可以继续根据新创建的组创建额外的 play。让我们将以下`Play`定义添加到同一个 playbook 文件中，以在 CentOS 上安装 Apache：

```
- name: Play to install Apache on CentOS
  hosts: os_CentOS
  become: true

  tasks:
    - name: Install Apache on CentOS
      yum:
        name: httpd
        state: present
```

这是一个完全正常的`Play`定义，它使用`yum`模块来安装`httpd`包（在 CentOS 上需要）。唯一与我们之前工作不同的是 play 顶部的`hosts`定义。这使用了第一个 play 中由`group_by`模块创建的新创建的清单组。

1.  同样，我们可以添加第三个`Play`定义，这次是使用`apt`模块在 Ubuntu 上安装`apache2`包：

```
- name: Play to install Apache on Ubuntu
  hosts: os_Ubuntu
  become: true

  tasks:
    - name: Install Apache on Ubuntu
      apt:
        name: apache2
        state: present
```

1.  如果我们的环境是基于 CentOS 服务器并运行此 playbook，则结果如下：

```
$ ansible-playbook -i hosts osvariants.yml

PLAY [Play to demonstrate group_by module] *************************************

TASK [Gathering Facts] *********************************************************
ok: [app02.dev.example.com]
ok: [app01.dev.example.com]

TASK [Create inventory groups based on host facts] *****************************
ok: [app01.dev.example.com]
ok: [app02.dev.example.com]

PLAY [Play to install Apache on CentOS] ****************************************

TASK [Gathering Facts] *********************************************************
ok: [app01.dev.example.com]
ok: [app02.dev.example.com]

TASK [Install Apache on CentOS] ************************************************
changed: [app02.dev.example.com]
changed: [app01.dev.example.com]
[WARNING]: Could not match supplied host pattern, ignoring: os_Ubuntu

PLAY [Play to install Apache on Ubuntu] ****************************************
skipping: no hosts matched

PLAY RECAP *********************************************************************
app01.dev.example.com : ok=4 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
app02.dev.example.com : ok=4 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

请注意安装 CentOS 上的 Apache 的任务是如何运行的。它是这样运行的，因为`group_by`模块创建了一个名为`os_CentOS`的组，而我们的第二个 play 仅在名为`os_CentOS`的组中运行。由于清单中没有运行 Ubuntu 的服务器，因此`os_Ubuntu`组从未被创建，因此第三个 play 不会运行。我们会收到有关没有与`os_Ubuntu`匹配的主机模式的警告，但 playbook 不会失败——它只是跳过了这个 play。

我们提供了这个例子，以展示另一种管理自动化编码中不可避免的 OS 类型差异的方式。归根结底，选择最适合您的编码风格取决于您。您可以使用`group_by`模块，如此处所述，或者将任务编写成块，并向块添加`when`子句，以便仅在满足某个基于事实的条件时运行（例如，OS 发行版是 CentOS）——或者甚至两者的组合。选择最终取决于您，这些不同的示例旨在为您提供多种选择，以便您在其中选择最佳解决方案。

最后，让我们通过查看在 Ansible 版本之间移植自动化代码来结束本章。

# 在 Ansible 版本之间移植

Ansible 是一个快速发展的项目，随着发布和新功能的添加，新模块（和模块增强）被发布，软件中不可避免的错误也得到修复。毫无疑问，您最终会写出针对 Ansible 的一个版本的代码，然后在某个时候需要再次在更新的版本上运行它。举例来说，当我们开始写这本书时，当前的 Ansible 版本是 2.7。当我们编辑这本书准备出版时，版本 2.9.6 是当前的稳定版本。

通常情况下，当你升级时，你会发现你的早期版本的代码“差不多能用”，但这并不总是确定的。有时模块会被弃用（尽管通常不会没有警告地弃用），功能也会发生变化。预计 Ansible 2.10 发布时会有一些重大变更。因此，问题是——当你更新你的 Ansible 安装时，如何确保你的剧本、角色、模块和插件仍然能够正常工作？

回答的第一部分是确定你从哪个版本的 Ansible 开始。例如，假设你正在准备升级到 Ansible 2.10。如果你查询已安装的 Ansible 版本，看到类似以下的内容，那么你就知道你是从 Ansible 2.9 版本开始的：

```
$ ansible --version
ansible 2.9.6
 config file = /etc/ansible/ansible.cfg
 configured module search path = [u'/home/james/.ansible/plugins/modules', u'/usr/share/ansible/plugins/modules']
 ansible python module location = /usr/lib/python2.7/site-packages/ansible
 executable location = /usr/bin/ansible
 python version = 2.7.5 (default, Aug 7 2019, 00:51:29) [GCC 4.8.5 20150623 (Red Hat 4.8.5-39)]
```

因此，你首先需要查看 Ansible 2.10 版本的迁移指南；通常每个主要版本（比如 2.8、2.9 等）都会有一个迁移指南。2.10 版本的指南可以在 [`docs.ansible.com/ansible/devel/porting_guides/porting_guide_2.10.html`](https://docs.ansible.com/ansible/devel/porting_guides/porting_guide_2.10.html) 找到。

如果我们查看这份文档，我们会发现即将有一些变更——这些变更对你是否重要取决于你正在运行的代码。例如，如果我们查看指南中的 *Modules Removed* 部分，我们会发现 `letsencrypt` 模块已被移除，并建议你使用 `acme_certificate` 模块代替。如果你在 Ansible 中使用 `letsencrypt` 模块生成免费的 SSL 证书，那么你肯定需要更新你的剧本和角色以适应这一变更。

正如你在前面的链接中看到的，Ansible 2.9 和 2.10 版本之间有大量的变更。因此，重要的是要注意，迁移指南是从升级前一个主要版本的角度编写的。也就是说，如果你查询你的 Ansible 版本并返回以下内容，那么你是从 Ansible 2.8 迁移过来的：

```
$ ansible --version
ansible 2.8.4
 config file = /etc/ansible/ansible.cfg
 configured module search path = [u'/home/james/.ansible/plugins/modules', u'/usr/share/ansible/plugins/modules']
 ansible python module location = /usr/lib/python2.7/site-packages/ansible
 executable location = /usr/bin/ansible
 python version = 2.7.5 (default, Aug 7 2019, 00:51:29) [GCC 4.8.5 20150623 (Red Hat 4.8.5-39)]
```

如果你直接升级到 Ansible 2.10，那么你需要查看 2.9（涵盖了从 2.8 到 2.9 的代码变更）和 2.10（涵盖了从 2.9 到 2.10 的升级所需的变更）的迁移指南。所有迁移指南的索引可以在官方 Ansible 网站上找到，网址是 [`docs.ansible.com/ansible/devel/porting_guides/porting_guides.html`](https://docs.ansible.com/ansible/devel/porting_guides/porting_guides.html)。

另一个获取信息的好途径，尤其是更精细的信息，是变更日志。这些日志会在每个次要版本发布时发布和更新，目前可以在官方 Ansible GitHub 仓库的`stable`分支上找到，用于你想查询的版本。例如，如果你想查看 Ansible 2.9 的所有变更日志，你需要前往 [`github.com/ansible/ansible/blob/stable-2.9/changelogs/CHANGELOG-v2.9.rst`](https://github.com/ansible/ansible/blob/stable-2.9/changelogs/CHANGELOG-v2.9.rst)。

将代码从 Ansible 版本迁移到另一个版本（如果你愿意这么称呼的话）的诀窍就是阅读 Ansible 项目团队发布的优秀文档。大量的工作投入到了创建这些文档中，因此建议你充分利用。这就结束了我们对使用 Ansible 的最佳实践的介绍。希望你觉得这一章很有价值。

# 总结

Ansible 自动化项目通常从小规模开始，但随着人们意识到 Ansible 的强大和简单，代码和清单往往呈指数增长（至少在我的经验中是这样）。在推动更大规模自动化的过程中，重要的是 Ansible 自动化代码和基础设施本身不会成为另一个头疼事。通过在早期嵌入一些良好的实践并在整个使用 Ansible 进行自动化的过程中始终如一地应用它们，您会发现管理 Ansible 自动化是简单易行的，并且对您的技术基础设施是真正有益的。

在本章中，您了解了应该为 playbook 采用的目录布局的最佳实践，以及在使用云清单时应采用的步骤。然后，您学习了通过 OS 类型区分环境的新方法，以及有关变量优先级以及在处理主机和组变量时如何利用它的更多信息。然后，您探索了顶级 playbook 的重要性，然后看了如何利用版本控制工具来管理您的自动化代码。最后，您探讨了创建单个 playbook 的新技术，该 playbook 将管理不同 OS 版本和发行版的服务器，最后看了将代码移植到新的 Ansible 版本的重要主题。

在下一章中，我们将探讨您可以使用 Ansible 来处理在自动化过程中可能出现的一些特殊情况的一些更高级的方法。

# 问题

1.  什么是一种安全且简单的方式来持续管理（即修改、修复和创建）代码更改并与他人共享？

A）Playbook 修订

B）任务历史

C）临时创建

D）使用 Git 存储库

E）日志管理

1.  Ansible Galaxy 支持从中央、社区支持的存储库与其他用户共享角色。 

A）真

B）假

1.  真或假- Ansible 模块保证在将来的所有版本中都可用。

A）真

B）假

# 进一步阅读

通过创建分支和标签来管理多个存储库、版本或任务，以有效地控制多个版本。有关更多详细信息，请参考以下链接：

+   如何使用 Git 标记：[`git-scm.com/book/en/v2/Git-Basics-Tagging`](https://git-scm.com/book/en/v2/Git-Basics-Tagging)

+   如何使用 Git 分支：[`git-scm.com/docs/git-branch`](https://git-scm.com/docs/git-branch)
