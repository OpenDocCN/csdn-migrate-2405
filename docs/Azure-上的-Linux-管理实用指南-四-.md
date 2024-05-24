# Azure 上的 Linux 管理实用指南（四）

> 原文：[`zh.annas-archive.org/md5/0EE39A6B040A18FF64595B6B3C82179F`](https://zh.annas-archive.org/md5/0EE39A6B040A18FF64595B6B3C82179F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：探索持续配置自动化

到目前为止，我们一直在使用单个 VM，手动部署和配置它们。这对实验室和非常小的环境很好，但是如果您必须管理更大的环境，这是一项非常耗时甚至令人厌倦的工作。犯错误和遗漏事项也非常容易，例如 VM 之间的细微差异，更不用说相关的稳定性和安全风险了。例如，在部署过程中选择错误的版本将导致一致性问题，以后进行升级是一个繁琐的过程。

自动化部署和配置管理是缓解这项乏味任务的理想方式。然而，过一段时间，您可能会注意到这种方法存在一些问题。存在许多原因导致问题，以下是一些失败的原因：

+   脚本失败是因为有些东西发生了变化，例如软件更新引起的。

+   有一个稍有不同的基础镜像的新版本。

+   脚本可能很难阅读，难以维护。

+   脚本依赖于其他组件；例如，操作系统、脚本语言和可用的内部和外部命令。

+   总有那么一个同事——脚本对你有效，但是，由于某种原因，当他们执行时总是失败。

当然，随着时间的推移，事情已经有所改善：

+   许多脚本语言现在是多平台的，例如 Bash、Python 和 PowerShell。它们在 Windows、macOS 和 Linux 上都可用。

+   在`systemd`中，带有`-H`参数的`systemctl`实用程序可以远程执行命令，即使远程主机是另一个 Linux 发行版也可以执行。更新的`systemd`版本具有更多功能。

+   `firewalld`和`systemd`使用易于部署的配置文件和覆盖。

自动化很可能不是您部署、安装、配置和管理工作负载的答案。幸运的是，还有另一种方法：编排。

从音乐角度来看，编排是研究如何为管弦乐队谱写音乐的学问。您必须了解每种乐器，并知道它们可以发出什么声音。然后，您可以开始谱写音乐；为此，您必须了解乐器如何共同发声。大多数情况下，您从单个乐器开始，例如钢琴。之后，您可以扩展到包括其他乐器。希望结果将是一部杰作，管弦乐队的成员将能够开始演奏。成员如何开始并不重要，但最终指挥确保结果重要。

在计算中有许多与编排相似的地方。在开始之前，您必须了解所有组件的工作原理，它们如何配合以及组件的功能，以便完成工作。之后，您可以开始编写代码以实现最终目标：一个可管理的环境。

云环境最大的优势之一是环境的每个组件都是以软件编写的。是的，我们知道，在最后一行，仍然有许多硬件组件的数据中心，但作为云用户，您不必关心这一点。您需要的一切都是以软件编写的，并且具有 API 进行通信。因此，不仅可以自动化部署 Linux 工作负载，还可以自动化和编排 Linux 操作系统的配置以及应用程序的安装和配置，并保持一切更新。您还可以使用编排工具配置 Azure 资源，甚至可以使用这些工具创建 Linux VM。

在编排中，有两种不同的方法：

+   **命令式**：告诉编排工具如何达到这个目标

+   **声明性**：告诉编排工具您要实现的目标是什么

一些编排工具可以同时执行这两种方法，但总的来说，在云环境中，声明性方法是更好的方法，因为您有很多选项可以配置，并且可以声明每个选项并实现确切的目标。好消息是，如果这种方法变得太复杂，例如，当编排工具无法理解目标时，您总是可以使用一点命令方法来扩展这种方法，使用脚本。

本章的重点是 Ansible，但我们还将涵盖 PowerShell **期望状态配置**（**DSC**）和 Terraform 作为声明性实现的示例。本章的重点是理解编排并了解足够的知识以开始。当然，我们还将讨论与 Azure 的集成。

本章的主要要点是：

+   了解诸如 Ansible 和 Terraform 等第三方自动化工具以及它们在 Azure 中的使用方式。

+   使用 Azure 的本地自动化和 PowerShell DSC 来实现机器的期望状态。

+   如何在 Linux 虚拟机中实现 Azure 策略客户端配置并审计设置。

+   概述市场上其他可用的自动化部署和配置解决方案。

### 技术要求

在实践中，您至少需要一个虚拟机作为控制机，或者您可以使用运行 Linux 或 **Windows 子系统**（**WSL**）的工作站。除此之外，我们还需要一个节点，该节点需要是 Azure 虚拟机。但是，为了提供更好的解释，我们部署了三个节点。如果您的 Azure 订阅受到预算限制，请随时继续使用一个节点。您使用的 Linux 发行版并不重要。本节中的示例用于编排节点，是针对 Ubuntu 节点的，但很容易将其转换为其他发行版。

在本章中，将探讨多种编排工具。对于每个工具，您需要一个干净的环境。因此，在本章中完成 Ansible 部分后，进入 Terraform 之前，请删除虚拟机并部署新的虚拟机。

## 理解配置管理

在本章的介绍中，您可能已经读到了术语*配置管理*。让我们更深入地了解一下。配置管理是指您希望如何配置虚拟机。例如，您希望在 Linux 虚拟机中配置 Apache Web 服务器以托管网站；因此，虚拟机的配置部分涉及：

+   安装 Apache 软件包和依赖项

+   为 HTTP 流量或 HTTPS 流量打开防火墙端口（如果使用 SSL（安全套接字层）证书）

+   启用服务并引导它，以便 Apache 服务在启动时启动

这个例子是一个非常简单的 Web 服务器。想象一下一个复杂的场景，您有一个前端 Web 服务器和后端数据库，因此涉及的配置非常复杂。到目前为止，我们一直在谈论单个虚拟机；如果您想要具有相同配置的多个虚拟机怎么办？我们又回到了起点，您必须多次重复配置，这是一项耗时且乏味的任务。这就是编排的作用，正如我们在介绍中讨论的那样。我们可以利用编排工具部署我们想要的虚拟机状态。这些工具将负责配置。此外，在 Azure 中，我们有 Azure 策略客户端配置，可用于审计设置。使用此策略，我们可以定义虚拟机应该处于的条件。如果评估失败或条件未满足，Azure 将标记此计算机为不符合规定。

本章的重点是 Ansible，但我们还将涵盖 PowerShell DSC 和 Terraform 作为声明性实现的示例。本章的重点是理解编排并学习足够的知识以开始。当然，我们还将讨论与 Azure 的集成。

## 使用 Ansible

Ansible 在本质上是最小的，几乎没有依赖性，并且不会向节点部署代理。对于 Ansible，只需要 OpenSSH 和 Python。它也非常可靠：可以多次应用更改而不会改变初始应用的结果，并且不应该对系统的其余部分产生任何副作用（除非您编写了非常糟糕的代码）。它非常注重代码的重用，这使得它更加可靠。

Ansible 的学习曲线并不是很陡峭。您可以从几行代码开始，然后逐渐扩展，而不会破坏任何东西。在我们看来，如果您想尝试一个编排工具，可以从 Ansible 开始，如果您想尝试另一个编排工具，学习曲线会陡峭得多。

### 安装 Ansible

在 Azure Marketplace 中，有一个可用于 Ansible 的即用型 VM。目前 Azure Marketplace 中有三个版本的 Ansible：Ansible 实例、Ansible Tower 和 AWX，这是 Ansible Tower 的社区版。在本书中，我们将集中讨论这个免费提供的社区项目；这已经足够学习和开始使用 Ansible 了。之后，您可以转到 Ansible 网站，探索差异，下载企业版的试用版 Ansible，并决定是否需要企业版。

安装 Ansible 有多种方法：

+   使用您的发行版存储库

+   使用[`releases.ansible.com/ansible`](https://releases.ansible.com/ansible)上可用的最新版本

+   使用 GitHub：[`github.com/ansible`](https://github.com/ansible)

+   使用首选方法 Python 安装程序，该方法适用于每个操作系统：

```
pip install ansible[azure]
```

Red Hat 和 CentOS 的标准存储库中没有 Python 的`pip`可用于安装。您必须使用额外的 EPEL 存储库：

```
sudo yum install epel-release
sudo yum install python-pip
```

安装完 Ansible 后，检查版本：

```
ansible --version
```

如果您不想安装 Ansible，则无需安装：Azure Cloud Shell 中预安装了 Ansible。在撰写本书时，Cloud Shell 支持 Ansible 版本 2.9.0。但是，为了介绍安装过程，我们将选择在 VM 上本地安装 Ansible。要与 Azure 集成，您还需要安装 Azure CLI 以获取您需要提供给 Ansible 的信息。

### SSH 配置

您安装 Ansible 的机器现在被称为 ansible-master，换句话说，它只是一个带有 Ansible、Ansible 配置文件和编排指令的虚拟机。与节点的通信使用通信协议进行。对于 Linux，SSH 被用作通信协议。为了使 Ansible 能够以安全的方式与节点通信，使用基于密钥的身份验证。如果尚未完成此操作，请生成一个 SSH 密钥对并将密钥复制到要编排的虚拟机。

要生成 SSH 密钥，请使用此命令：

```
ssh-keygen
```

一旦生成密钥，默认情况下，它将保存在用户的主目录中的`.ssh`目录中。要显示密钥，请使用此命令：

```
cat ~/.ssh/id_rsa.pub
```

一旦我们有了密钥，我们必须将该值复制到节点服务器。按照以下步骤复制密钥：

1.  复制`id_rsa.pub`文件的内容。

1.  SSH 到您的节点服务器。

1.  使用`sudo`命令切换到超级用户。

1.  编辑`~/.ssh/`中的`authorized_keys`文件。

1.  粘贴我们从 Ansible 服务器复制的密钥。

1.  保存并关闭文件。

要验证过程是否成功，请返回到安装了 Ansible 的机器（从现在开始，我们将称其为 ansible-master）并`ssh`到节点。如果在生成密钥时使用了密码，它将要求输入密码。自动复制密钥的另一种方法是使用`ssh-copy-id`命令。

### 最低限度的配置

配置 Ansible，您将需要一个`ansible.cfg`文件。有不同的位置可以存储这个配置文件，Ansible 按以下顺序搜索：

```
ANSIBLE_CONFIG (environment variable if set)
ansible.cfg (in the current directory)
~/.ansible.cfg (in the home directory)
/etc/ansible/ansible.cfg
```

Ansible 将处理前面的列表，并使用找到的第一个文件；其他所有文件都将被忽略。

如果不存在，请在`/etc`中创建`ansible`目录，并添加一个名为`ansible.cfg`的文件。这是我们将保存配置的地方：

```
[defaults]
inventory = /etc/ansible/hosts
```

让我们试试以下：

```
ansible all -a "systemctl status sshd"
```

这个命令，称为临时命令，对`/etc/ansiblehosts`中定义的所有主机执行`systemctl status sshd`。如果每个主机有多个用户名，你也可以在以下 ansible 主机文件中指定这些节点的用户名：

```
<ip address>   ansible_ssh_user='<ansible user>'
```

因此，如果需要，你可以像以下截图中所示将用户添加到清单文件行项目，并且对于三个节点，文件将如下所示：

![代码将用户添加到清单文件行项目](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_01.jpg)

###### 图 8.1：将用户添加到清单文件行项目

再试一次。使用远程用户而不是本地用户名。现在你可以登录并执行命令了。

### 清单文件

Ansible 清单文件定义了主机和主机组。基于此，你可以调用主机或组（一组主机）并运行特定的 playbook 或执行命令。

在这里，我们将调用我们的组`nodepool`并添加我们节点的 IP。由于我们所有的 VM 都在同一个 Azure VNet 中，我们使用私有 IP。如果它们在不同的网络中，你可以添加公共 IP。在这里，我们使用三个 VM 来帮助解释。如果你只有一个节点，只需输入那一个。

你也可以使用 VM 的 DNS 名称，但它们应该添加到你的`/etc/hosts`文件中以进行解析：

```
[nodepool] 
10.0.0.5 
10.0.0.6
10.0.0.7
```

另一个有用的参数是`ansible_ssh_user`。你可以使用它来指定用于登录节点的用户名。如果你在 VMs 上使用多个用户名，这种情况就会出现。

在我们的示例中，不要使用`all`，你可以使用一个名为`ansible-nodes`的组名。还可以使用通用变量，这些变量对每个主机都有效，并且可以针对每个服务器进行覆盖；例如：

```
[all:vars]
ansible_ssh_user='student'
[nodepool]
<ip address> ansible_ssh_user='other user'
```

有时，你需要特权来执行命令：

```
ansible nodepool-a "systemctl restart sshd"
```

这会得到以下错误消息：

```
Failed to restart sshd.service: Interactive authentication required.
See system logs and 'systemctl status sshd.service' for details.non-zero return code.
```

对于临时命令，只需将`-b`选项作为 Ansible 参数添加，以启用特权升级。它将默认使用`sudo`方法。在 Azure 镜像中，如果你使用`sudo`，就不需要提供 root 密码。这就是为什么`-b`选项可以无问题地工作。如果你配置了`sudo`来提示输入密码，使用`-K`。

我们建议运行其他命令，比如`netstat`和`ping`，以了解这些命令在这些机器上是如何执行的。运行`netstat`并使用`sshd`进行 grep 将会得到类似于这样的输出：

![netstat 和 grep ssh 命令的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_02.jpg)

###### 图 8.2：运行 netstat 并使用 sshd 进行 grep

#### 注意

当运行`ansible all`命令时，你可能会收到弃用警告。为了抑制这个警告，在`ansible.cfg`中使用`deprecation_warnings=False`。

### Ansible Playbooks 和 Modules

使用临时命令是一种命令方法，不比只使用 SSH 客户端远程执行命令更好。

有两个组件，你需要将其变成真正的命令编排：一个 playbook 和一个模块。Playbook 是部署、配置和维护系统的基础。它可以编排一切，甚至在主机之间！Playbook 用于描述你想要达到的状态。Playbook 是用 YAML 编写的，可以用`ansible-playbook`命令执行：

```
ansible-playbook <filename>
```

第二个组件是模块。描述模块的最佳方式是：执行任务以达到期望的状态。它们也被称为任务插件或库插件。

所有可用的模块都有文档；你可以在网上和你的系统上找到文档。

要列出所有可用的插件文档，请执行以下命令：

```
ansible-doc -l
```

这会花一些时间。我们建议你将结果重定向到一个文件。这样，它会花费更少的时间，而且更容易搜索模块。

例如，让我们尝试创建一个 playbook，如果用户尚不存在，则使用**user**模块创建用户。换句话说，期望的状态是存在特定用户。

首先阅读文档：

```
ansible-doc user
```

在 Ansible 目录中创建一个文件，例如`playbook1.yaml`，内容如下。验证用户文档中的参数：

```
---
- hosts: all
  tasks:
  - name: Add user Jane Roe
    become: yes
    become_method: sudo
    user:
      state: present
      name: jane
      create_home: yes
      comment: Jane Roe
      generate_ssh_key: yes
      group: users
      groups:
        - sudo
        - adm
      shell: /bin/bash
      skeleton: /etc/skel
```

从输出中，您可以看到所有主机返回了`OK`，并且用户已创建：

![创建的 ansible 文件的参数](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_03.jpg)

###### 图 8.3：运行 Ansible playbook

为了确保用户已创建，我们将检查所有主机上的`/etc/passwd`文件。从输出中，我们可以看到用户已经被创建：

![检查主机的密码文件以验证用户创建](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_04.jpg)

###### 图 8.4：使用/etc/passwd 验证用户创建

确保缩进正确，因为 YAML 在缩进和空格方面非常严格。使用支持 YAML 的编辑器，如 vi、Emacs 或 Visual Studio Code，确实有很大帮助。

如果需要运行命令特权提升，可以使用`become`和`become_method`或`-b`。

要检查 Ansible 语法，请使用以下命令：

```
ansible-playbook --syntax-check Ansible/example1.yaml
```

让我们继续看看如何在 Azure 进行身份验证并开始部署。

### 身份验证到 Microsoft Azure

要将 Ansible 与 Microsoft Azure 集成，您需要创建一个配置文件，为 Ansible 提供 Azure 的凭据。

凭据必须存储在您的主目录中的`~/.azure/credentials`文件中。首先，我们必须使用 Azure CLI 收集必要的信息。如下身份验证到 Azure：

```
az login
```

如果您成功登录，您将获得类似以下的输出：

![用户凭据指示成功的 Azure 登录](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_05.jpg)

###### 图 8.5：使用 az 登录命令登录到 Azure

这已经是您需要的信息的一部分。如果您已经登录，请执行以下命令：

```
az account list
```

创建服务主体：

```
az ad sp create-for-rbac --name <principal> --password <password>
```

应用 ID 是您的`client_id`，密码是您的`secret`，将在我们即将创建的凭据文件中引用。

创建`~/.azure/credentials`文件，内容如下：

```
[default]
subscription_id=xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx 
client_id=xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx 
secret=xxxxxxxxxxxxxxxxx 
tenant=xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx 
```

使用`ansible-doc -l | grep azure`查找可用于 Azure 的 Ansible 模块。将内容重定向到文件以供参考。

### 资源组

让我们检查一切是否如预期那样工作。创建一个名为`resourcegroup.yaml`的新 playbook，内容如下：

```
---
- hosts: localhost
  tasks:
  - name: Create a resource group
    azure_rm_resourcegroup:
      name: Ansible-Group
      location: westus
```

请注意，主机指令是 localhost！执行 playbook 并验证资源组是否已创建：

```
az group show --name Ansible-Group
```

输出应该与以下非常相似：

```
{
 "id": "/subscriptions/xxxx/resourceGroups/Ansible-Group",
 "location": "westus",
 "managedBy": null,
 "name": "Ansible-Group",
 "properties": {
 "provisioningState": "Succeeded"
 },
 "tags": null
 }
```

### 虚拟机

让我们使用 Ansible 在 Azure 中创建一个虚拟机。为此，请创建一个`virtualmachine.yaml`文件，内容如下。检查每个块的`name`字段，以了解代码的作用：

```
- hosts: localhost
  tasks:
  - name: Create Storage Account
    azure_rm_storageaccount:
      resource_group: Ansible-Group
      name: ansiblegroupsa
      account_type: Standard_LRS
	 .
	 .
	 .	  - name: Create a CentOS VM
    azure_rm_virtualmachine:
      resource_group: Ansible-Group
      name: ansible-vm
      vm_size: Standard_DS1_v2
      admin_username: student
  admin_password:welk0mITG!
      image:
        offer: CentOS
        publisher: OpenLogic
        sku: '7.5'
        version: latest
```

考虑到代码的长度，我们只在这里展示了一小部分。您可以从本书的 GitHub 存储库中的`chapter 8`文件夹中下载整个`virtualmachine.yaml`文件。

在下面的截图中，您可以看到 Ansible 创建了 VM 所需的所有资源：

![使用 Ansible 创建 VM 所需的所有资源](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_06.jpg)

###### 图 8.6：使用 Ansible 创建 VM 所需的所有资源

您可以在 Ansible 的 Microsoft Azure 指南中找到使用 Ansible 部署 Azure VM 的完整示例（[`docs.ansible.com/ansible/latest/scenario_guides/guide_azure.html`](https://docs.ansible.com/ansible/latest/scenario_guides/guide_azure.html)）。

### Ansible 中的 Azure 清单管理

我们已经学会了两种在 Azure 中使用 Ansible 的方法：

+   在清单文件中使用 Ansible 连接到 Linux 机器。实际上，无论是在 Azure 中还是在其他地方运行都无关紧要。

+   使用 Ansible 管理 Azure 资源。

在本节中，我们将进一步进行。我们将使用动态清单脚本询问 Azure 在您的环境中运行了什么，而不是使用静态清单。

第一步是下载 Azure 的动态清单脚本。如果您不是 root 用户，请使用`sudo`执行：

```
cd /etc/ansible
wget https://raw.githubusercontent.com/ansible/ansible/devel/contrib/inventory/azure_rm.py
chmod +x /etc/ansible/azure_rm.py
```

编辑`/etc/ansible/ansible.cfg`文件并删除`inventory=/etc/ansible/hosts`行。

让我们进行第一步：

```
ansible -i /etc/ansible/azure_rm.py azure -m ping
```

它可能会因为身份验证问题而失败：

![由于身份验证问题导致主机连接失败](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_07.jpg)

###### 图 8.7：由于身份验证问题导致主机连接失败

如果您对不同的 VM 有不同的登录，您可以始终在每个任务中使用用户指令。在这里，我们使用`azure`，这意味着所有 VM。您始终可以使用 VM 名称查询机器。例如，您可以使用用户凭据 ping`ansible-node3` VM：

![使用用户凭据 ping ansible-node3 VM](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_08.jpg)

###### 图 8.8：查询 ansible-node3 VM

理想情况下，Ansible 希望您使用 SSH 密钥而不是密码。如果您想使用密码，可以使用`–extra-vars`并传递密码。请注意，为此您需要安装一个名为`sshpass`的应用程序。要通过 Ansible ping 使用密码的 Azure VM，请执行以下命令：

```
ansible -i azure_rm.py ansible-vm -m ping \
--extra-vars "ansible_user=<username> ansible_password=<password>"
```

让我们以前一个示例中使用 Ansible 创建的 VM 实例为例，其中用户名是`student`，密码是`welk0mITG!`。从屏幕截图中，您可以看到 ping 成功。您可能会看到一些警告，但可以安全地忽略它们。但是，如果 ping 失败，则需要进一步调查：

![屏幕截图表明对用户的 ping 成功](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_09.jpg)

###### 图 8.9：发送 ping 给用户名 student

通过在与`azure_rm.py`目录相同的目录中创建一个`azure_rm.ini`文件，您可以修改清单脚本的行为。以下是一个示例`ini`文件：

```
[azure]
include_powerstate=yes
group_by_resource_group=yes
group_by_location=yes
group_by_security_group=yes
group_by_tag=yes
```

它的工作方式与`hosts`文件非常相似。`[azure]`部分表示所有 VM。您还可以为以下内容提供部分：

+   位置名称

+   资源组名称

+   安全组名称

+   标记键

+   标记键值

选择一个或多个 VM 的另一种方法是使用标记。要能够给 VM 打标记，您需要 ID：

```
az vm list --output tsv
```

现在，您可以给 VM 打标记：

```
az resource tag --resource-group <resource group> \
  --tags webserver --id </subscriptions/...>
```

您还可以在 Azure 门户中给 VM 打标记：

![在 Azure 门户中给 VM 打标记](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_10.jpg)

###### 图 8.10：在 Azure 门户中给 VM 打标记

单击**更改**并添加一个标记，带有或不带有值（您也可以使用该值来过滤该值）。要验证，请使用标记名称主机：

```
ansible -i /etc/ansible/azure_rm.py webserver -m ping
```

只有标记的 VM 被 ping。让我们为这个标记的 VM 创建一个 playbook，例如`/etc/ansible/example9.yaml`。标记再次在`hosts`指令中使用：

```
---
- hosts: webserver
  tasks:
  - name: Install Apache Web Server
    become: yes
    become_method: sudo
    apt:
      name: apache2
      install_recommends: yes
      state: present
      update-cache: yes
    when:
      - ansible_distribution == "Ubuntu"
      - ansible_distribution_version == "18.04"
```

执行 playbook：

```
ansible-playbook -i /etc/ansible/azure_rm.py /etc/ansible/example9.yaml
```

一旦 playbook 运行完毕，如果您检查 VM，您会看到 Apache 已安装。

如前所述，Ansible 并不是唯一的工具。还有另一个流行的工具叫做 Terraform。在下一节中，我们将讨论 Azure 上的 Terraform。

## 使用 Terraform

Terraform 是由 HashiCorp 开发的另一个**基础设施即代码**（**IaC**）工具。您可能想知道为什么它被称为 IaC 工具。原因是您可以使用代码定义基础设施的需求，而 Terraform 将帮助您部署它。Terraform 使用**HashiCorp 配置语言**（**HCL**）；但是，您也可以使用 JSON。Terraform 在 macOS、Linux 和 Windows 中都受支持。

Terraform 支持各种 Azure 资源，如网络、子网、存储、标记和 VM。如果您回忆一下，我们讨论了编写代码的命令式和声明式方式。Terraform 是声明式的，它可以维护基础设施的状态。一旦部署，Terraform 会记住基础设施的当前状态。

与每个部分一样，过程的第一部分涉及安装 Terraform。让我们继续进行 Terraform 的 Linux 安装。

### 安装

Terraform 的核心可执行文件可以从[`www.terraform.io/downloads.html`](https://www.terraform.io/downloads.html)下载，并且可以复制到添加到您的`$PATH`变量的目录之一。您还可以使用`wget`命令来下载核心可执行文件。要做到这一点，首先您必须从上述链接中找出 Terraform 的最新版本。在撰写本文时，最新版本为 0.12.16

现在我们已经有了版本，我们将使用以下命令使用`wget`下载可执行文件：

```
wget https://releases.hashicorp.com/terraform/0.12.17/terraform_0.12.17_linux_amd64.zip
```

ZIP 文件将被下载到当前工作目录。现在我们将使用解压工具来提取可执行文件：

```
unzip terraform_0.12.16_linux_amd64.zip
```

#### 注意

`unzip`可能不是默认安装的。如果它抛出错误，请使用`apt`或`yum`根据您使用的发行版进行安装`unzip`。

提取过程将为您获取 Terraform 可执行文件，您可以将其复制到`$PATH`中的任何位置。

要验证安装是否成功，您可以执行：

```
terraform --version
```

现在我们已经确认了 Terraform 已经安装，让我们继续设置 Azure 的身份验证。

### 连接到 Azure

有多种方法可以用来对 Azure 进行身份验证。您可以使用 Azure CLI、使用客户端证书的服务主体、服务主体和客户端密钥，以及许多其他方法。对于测试目的，使用`az`登录命令的 Azure CLI 是正确的选择。然而，如果我们想要自动化部署，这并不是一个理想的方法。我们应该选择服务主体和客户端密钥，就像我们在 Ansible 中所做的那样。

让我们从为 Terraform 创建一个服务主体开始。如果您已经为上一节创建了服务主体，请随意使用。要从 Azure CLI 创建一个新的服务主体，请使用以下命令：

```
az ad sp create-for-rbac -n terraform
```

此时，您可能已经熟悉了输出，其中包含`appID`、密码和租户 ID。

记下输出中的值，我们将创建变量来存储这个值：

```
export ARM_CLIENT_ID="<appID>"
export ARM_CLIENT_SECRET="<password>"
export ARM_SUBSCRIPTION_ID="<subscription ID>"
export ARM_TENANT_ID="<tenant ID>"
```

因此，我们已经将所有的值存储到变量中，这些值将被 Terraform 用于身份验证。由于我们已经处理了身份验证，让我们用 HCL 编写代码，以便在 Azure 中部署资源。

### 部署到 Azure

您可以使用任何代码编辑器来完成这个任务。由于我们已经在 Linux 机器上，您可以使用 vi 或 nano。如果您愿意，您也可以使用 Visual Studio Code，它具有 Terraform 和 Azure 的扩展，可以为您提供智能感知和语法高亮显示。

让我们创建一个 terraform 目录来存储我们所有的代码，在`terraform`目录中，我们将根据我们要部署的内容创建进一步的目录。在我们的第一个示例中，我们将使用 Terraform 在 Azure 中创建一个资源组。稍后，我们将讨论如何在这个资源组中部署一个 VM。

因此，要创建一个`terraform`目录，并在此目录中创建一个`resource-group`子文件夹，请执行以下命令：

```
mkdir terraform
cd terraform && mkdir resource-group
cd resource-group
```

接下来，创建一个包含以下内容的 main.tf 文件：

```
provider "azurerm" {
    version = "~>1.33"
}
resource "azurerm_resource_group" "rg" {
    name     = "TerraformOnAzure"
    location = "eastus"
}
```

代码非常简单。让我们仔细看看每个项目。

提供者指令显示我们想要使用`azurerm`提供者的 1.33 版本。换句话说，我们指示我们将使用 Terraform Azure 资源管理器提供者的 1.33 版本，这是 Terraform 可用的插件之一。

`resource`指令表示我们将部署一个`azurerm_resource_group`类型的 Azure 资源，具有`name`和`location`两个参数。

`rg`代表资源配置。每个模块中的资源名称必须是唯一的。例如，如果您想在同一个模板中创建另一个资源组，您不能再次使用`rg`，因为您已经使用过了；而是，您可以选择除`rg`之外的任何其他名称，比如`rg2`。

在使用模板开始部署之前，我们首先需要初始化项目目录，即我们的`resource-group`文件夹。要初始化 Terraform，请执行以下操作：

```
terraform init
```

在初始化期间，Terraform 将从其存储库下载`azurerm`提供程序，并显示类似以下的输出：

![Terraform 从其存储库下载 azurerm 提供程序](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_11.jpg)

###### 图 8.11：初始化 Terraform 以下载 azurerm 提供程序

由于我们已经将服务主体详细信息导出到变量中，因此可以使用此命令进行部署：

```
terraform apply
```

此命令将连接 Terraform 到您的 Azure 订阅，并检查资源是否存在。如果 Terraform 发现资源不存在，它将继续创建一个执行计划以部署。您将获得以下截图中显示的输出。要继续部署，请键入`yes`：

![使用 terraform apply 连接 terraform 到 Azure 订阅](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_12.jpg)

###### 图 8.12：连接 Terraform 到 Azure 订阅

一旦您提供了输入，Terraform 将开始创建资源。创建后，Terraform 将向您显示创建的所有内容的摘要以及添加和销毁的资源数量，如下所示：

![使用 terraform apply 命令创建的资源摘要](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_13.jpg)

###### 图 8.13：创建的资源摘要

在我们初始化 Terraform 的项目目录中将生成一个名为`terraform.tfstate`的状态文件。该文件将包含状态信息，还将包含我们部署到 Azure 的资源列表。

我们已成功创建了资源组；在下一节中，我们将讨论如何使用 Terraform 创建 Linux VM。

### 部署虚拟机

在前面的示例中，我们创建了资源组，我们使用`azurerm_resource_group`作为要创建的资源。对于每个资源，都会有一个指令，例如对于 VM，它将是`azurerm_virtual_machine`。

此外，我们使用`terraform apply`命令创建了资源组。但是 Terraform 还提供了一种使用执行计划的方法。因此，我们可以先创建一个计划，看看将会做出什么更改，然后再部署。

首先，您可以返回到`terraform`目录并创建一个名为`vm`的新目录。为不同的项目单独创建目录总是一个好主意：

```
mkdir ../vm
cd ../vm
```

一旦您进入目录，您可以创建一个名为`main.tf`的新文件，其中包含以下代码块中显示的内容。使用添加的注释查看每个块的目的。考虑到代码的长度，我们显示了代码块的截断版本。您可以在本书的 GitHub 存储库的`第八章`文件夹中找到`main.tf`代码文件：

```
provider "azurerm" {
    version = "~>1.33"
}
#Create resource group
resource "azurerm_resource_group" "rg" {
    name     = "TFonAzure"
    location = "eastus"
}
.
.
.
#Create virtual machine, combining all the components we created so far
resource "azurerm_virtual_machine" "myterraformvm" {
    name                  = "tf-VM"
    location              = "eastus"
    resource_group_name   = azurerm_resource_group.rg.name
    network_interface_ids = [azurerm_network_interface.nic.id]
    vm_size               = "Standard_DS1_v2"
    storage_os_disk {
        name              = "tfOsDisk"
        caching           = "ReadWrite"
        create_option     = "FromImage"
        managed_disk_type = "Standard_LRS"
    }
    storage_image_reference {
        publisher = "Canonical"
        offer     = "UbuntuServer"
        sku       = "16.04.0-LTS"
        version   = "latest"
    }
    os_profile {
        computer_name  = "tfvm"
        admin_username = "adminuser"
        admin_password = "Pa55w0rD!@1234"
    }

    os_profile_linux_config {
    disable_password_authentication = false
  }
}
```

如果您查看`azurerm_virtual_network`部分，您会发现，我们没有写下资源名称，而是以`type.resource_configuration.parameter`的格式给出了一个引用。在这种情况下，我们没有写下资源组名称，而是给出了`azurerm_resource_group.rg.name`的引用。同样，在整个代码中，我们都采用了引用以使部署变得更加容易。

在开始部署规划之前，我们必须使用以下内容初始化项目：

```
terraform init
```

如前所述，我们将使用执行计划。要创建执行计划并将其保存到`vm-plan.plan`文件中，请执行：

```
terraform plan -out vm-plan.plan
```

您将收到很多警告；它们可以安全地忽略。确保代码没有显示任何错误。如果成功创建了执行计划，它将显示执行计划的下一步操作，如下所示：

![成功创建执行计划](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_14.jpg)

###### 图 8.14：显示执行计划

如输出所建议的，我们将执行：

```
terraform apply "vm-plan.plan"
```

现在，部署将开始，并显示正在部署的资源，已经经过了多少时间等等，如输出所示：

![部署资源的详细信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_15.jpg)

###### 图 8.15：资源部署详细信息

最后，Terraform 将提供部署的资源数量的摘要：

![部署资源的摘要](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_16.jpg)

###### 图 8.16：部署的资源数量摘要

还有另一个命令，就是`show`命令。这将显示部署的完整状态，如下截图所示：

![检查部署的完整状态](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_17.jpg)

###### 图 8.17：显示部署的完整状态

我们编写了一小段代码，可以在 Azure 中部署一个 VM。但是，可以通过向代码添加许多参数来进行高级状态配置。所有参数的完整列表都可以在 Terraform 文档（[`www.terraform.io/docs/providers/azurerm/r/virtual_machine.html`](https://www.terraform.io/docs/providers/azurerm/r/virtual_machine.html)）和微软文档（[`docs.microsoft.com/en-us/azure/virtual-machines/linux/terraform-create-complete-vm`](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/terraform-create-complete-vm)）中找到。

由于这些模板有点高级，它们将使用变量而不是重复的值。然而，一旦您习惯了这一点，您就会了解 Terraform 有多强大。

最后，您可以通过执行以下命令销毁整个部署或项目：

```
terraform destroy
```

这将删除项目的`main.tf`文件中提到的所有资源。如果您有多个项目，您必须导航到项目目录并执行`destroy`命令。执行此命令时，系统将要求您确认删除；一旦您说“是”，资源将被删除：

![使用 terraform destroy 命令销毁整个部署](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_18.jpg)

###### 图 8.18：使用 terraform destroy 命令删除所有资源

最后，您将得到一个摘要，如下所示：

![被销毁资源的摘要](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_19.jpg)

###### 图 8.19：被销毁资源的摘要

现在我们熟悉了在 Azure 上使用 Terraform 和部署简单的 VM。如今，由于 DevOps 的可用性和采用率，Terraform 正变得越来越受欢迎。 Terraform 使评估基础架构并重新构建它变得轻松无忧。

## 使用 PowerShell DSC

与 Bash 一样，PowerShell 是一个具有强大脚本功能的 shell。我们可能会认为 PowerShell 更像是一种脚本语言，可以用来执行简单的操作或创建资源，就像我们迄今为止所做的那样。但是，PowerShell 的功能远不止于此，还延伸到自动化和配置。

DSC 是 PowerShell 的一个重要但鲜为人知的部分，它不是用 PowerShell 语言自动化脚本，而是提供了 PowerShell 中的声明性编排。

如果将其与 Ansible 进行比较，对 Linux 的支持非常有限。但它非常适用于常见的管理任务，缺少的功能可以通过 PowerShell 脚本来补偿。微软非常专注于使其与 Windows Server 保持一致。一旦发生这种情况，它将被 PowerShell DSC Core 取代，这与他们以前使用 PowerShell | PowerShell Core 所做的非常相似。这将在 2019 年底完成。

另一个重要的注意事项是，由于某种原因，随 DSC 提供的 Python 脚本偶尔无法正常工作，有时会出现 401 错误甚至未定义的错误。首先确保您拥有最新版本的 OMI 服务器和 DSC，然后再试一次；有时，您可能需要尝试两到三次。

### Azure Automation DSC

使用 DSC 的一种方法是使用 Azure Automation DSC。这样，您就不必使用单独的机器作为控制节点。要使用 Azure Automation DSC，您需要一个 Azure Automation 帐户。

**自动化帐户**

在 Azure 门户中，选择左侧栏中的**所有服务**，导航到**管理+治理**，然后选择**自动化帐户**。创建一个自动化帐户，并确保选择**Run As Account**。

再次导航到**所有服务**，**管理工具**，然后选择**刚创建的帐户**：

![选择新创建的自动化帐户](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_20.jpg)

###### 图 8.20：在 Azure 门户中创建自动化帐户

在这里，您可以管理您的节点、配置等等。

请注意，此服务并非完全免费。流程自动化按作业执行分钟计费，而配置管理按受管节点计费。

要使用此帐户，您需要**Run As Account**的注册 URL 和相应的密钥。这两个值都可以在**帐户**和**密钥设置**下找到。

或者，在 PowerShell 中，执行以下命令：

```
Get-AzAutomationRegistrationInfo ' 
  -ResourceGroup <resource group> '
  -AutomationAccountName <automation account name>
```

Linux 有一个可用的 VM 扩展；这样，您可以部署 VM，包括它们的配置，完全编排。

有关更多信息，请访问[`github.com/Azure/azure-linux-extensions/tree/master/DSC`](https://github.com/Azure/azure-linux-extensions/tree/master/DSC)和[`docs.microsoft.com/en-us/azure/virtual-machines/extensions/dsc-linux`](https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/dsc-linux)。

因为我们要使用 Linux 和 DSC，我们需要一个名为`nx`的 DSC 模块。该模块包含了 Linux 的 DSC 资源。在自动化帐户的设置中，选择`nx`并导入该模块。

### 在 Linux 上安装 PowerShell DSC

要在 Linux 上使用 PowerShell DSC，您需要 Open Management Infrastructure Service。支持的 Linux 发行版版本如下：

+   Ubuntu 12.04 LTS，14.04 LTS 和 16.04 LTS。目前不支持 Ubuntu 18.04。

+   RHEL/CentOS 6.5 及更高版本。

+   openSUSE 13.1 及更高版本。

+   SUSE Linux Enterprise Server 11 SP3 及更高版本。

该软件可在[`github.com/Microsoft/omi`](https://github.com/Microsoft/omi)下载。

在基于 Red Hat 的发行版上的安装如下：

```
sudo yum install \
  https://github.com/Microsoft/omi/releases/download/\
  v1.4.2-3/omi-1.4.2-3.ssl_100.ulinux.x64.rpm
```

对于 Ubuntu，您可以使用`wget`从 GitHub 存储库下载`deb`文件，并使用`dpkg`进行安装：

```
dpkg –i ./omi-1.6.0-0.ssl_110.ulinux.x64.deb 
```

#### 注意

确保下载与您的 SSL 版本匹配的文件。您可以使用`openssl version`命令来检查您的 SSL 版本。

安装后，服务会自动启动。使用以下命令检查服务的状态：

```
sudo systemctl status omid.service
```

要显示产品和版本信息，包括使用的配置目录，请使用以下命令：

```
/opt/omi/bin/omicli id
```

![带有配置目录列表的产品信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_21.jpg)

###### 图 8.21：显示产品和版本信息

### 创建期望状态

PowerShell DSC 不仅仅是一个带有参数的脚本或代码，就像在 Ansible 中一样。要开始使用 PowerShell DSC，您需要一个必须编译成**管理对象格式**（**MOF**）文件的配置文件。

但是，首先要做的是。让我们创建一个名为`example1.ps1`的文件，内容如下：

```
Configuration webserver {
Import-DscResource -ModuleName PSDesiredStateConfiguration,nx
Node "ubuntu01"{
    nxPackage apache2
    {
        Name = "apache2"
        Ensure = "Present"
        PackageManager = "apt"
    }
 }
}
webserver
```

让我们调查一下这个配置。正如所述，它与函数声明非常相似。配置得到一个标签，并在脚本末尾执行。必要的模块被导入，VM 的主机名被声明，配置开始。

### PowerShell DSC 资源

在这个配置文件中，使用了一个名为`nxPackage`的资源。有几个内置资源：

+   `nxArchive`：提供在特定路径解压归档（`.tar`，`.zip`）文件的机制。

+   `nxEnvironment`：管理环境变量。

+   `nxFile`：管理文件和目录。

+   `nxFileLine`：管理 Linux 文件中的行。

+   `nxGroup`：管理本地 Linux 组。

+   `nxPackage`：管理 Linux 节点上的软件包。

+   `nxScript`：运行脚本。大多数情况下，这是用来暂时切换到更命令式的编排方法。

+   `nxService`：管理 Linux 服务（守护进程）。

+   `nxUser`：管理 Linux 用户。

您还可以使用 MOF 语言、C#、Python 或 C/C++编写自己的资源。

您可以访问[`docs.microsoft.com/en-us/powershell/dsc/lnxbuiltinresources`](https://docs.microsoft.com/en-us/powershell/dsc/lnxbuiltinresources)来使用官方文档。

保存脚本并执行如下：

```
pwsh -file example1.ps
```

脚本的结果是创建一个与配置名称相同的目录。其中，有一个以 MOF 格式的 localhost 文件。这是用于描述 CIM 类的语言（**CIM**代表**通用信息模型**）。CIM 是用于管理完整环境（包括硬件）的开放标准。

我们认为这个描述足以理解为什么微软选择了这个模型和相应的编排语言文件！

您还可以将配置文件上传到 Azure，在**DSC Configurations**下。按下**Compile**按钮在 Azure 中生成 MOF 文件。

**在 Azure 中应用资源**

如果需要，您可以使用`/opt/microsoft/dsc/Scripts`中的脚本在本地应用所需的状态，但在我们看来，这并不像应该那样容易。而且，因为本章是关于 Azure 中的编排，我们将直接转向 Azure。

注册虚拟机：

```
sudo /opt/microsoft/dsc/Scripts/Register.py \
  --RegistrationKey <automation account key> \
  --ConfigurationMode ApplyOnly \
  --RefreshMode Push --ServerURL <automation account url>
```

再次检查配置：

```
sudo /opt/microsoft/dsc/Scripts/GetDscLocalConfigurationManager.py
```

现在，节点在**Automation Account**设置下的**DSC Nodes**窗格中可见。现在，您可以链接上传和编译的 DSC 配置。配置已应用！

另一种方法是使用**Add Node**选项，然后选择 DSC 配置。

总之，PowerShell DSC 的主要用例场景是编写、管理和编译 DSC 配置，以及导入和分配这些配置到云中的目标节点。在使用任何工具之前，您需要了解用例场景以及它们如何适用于您的环境以实现目标。到目前为止，我们一直在配置虚拟机；接下来的部分将介绍如何使用 Azure 策略来审计 Linux 虚拟机内部的设置。

## Azure 策略客户端配置

策略主要用于资源的治理。Azure 策略是 Azure 中的一个服务，您可以在其中创建、管理和分配策略。这些策略可用于审计和合规性。例如，如果您在东部美国位置托管一个安全的应用程序，并且希望仅限制在东部美国的部署，可以使用 Azure 策略来实现这一点。

假设您不希望在订阅中部署 SQL 服务器。在 Azure 策略中，您可以创建一个策略并指定允许的服务，只有它们可以在该订阅中部署。请注意，如果您将策略分配给已经存在资源的订阅，Azure 策略只能对分配后创建的资源进行操作。但是，如果任何现有资源在分配前不符合策略，它们将被标记为“不合规”，因此管理员可以在必要时进行更正。此外，Azure 策略只会在部署的验证阶段生效。

一些内置策略包括：

+   允许的位置：使用此功能，您可以强制执行地理合规性。

+   允许的虚拟机 SKU：定义一组虚拟机 SKU。

+   向资源添加标签：向资源添加标签。如果没有传递值，它将采用默认的标签值。

+   强制执行标签及其值：用于强制执行对资源所需的标签及其值。

+   不允许的资源类型：防止部署选定的资源。

+   允许的存储帐户 SKU：我们在上一章中讨论了可用于存储帐户的不同 SKU，如 LRS、GRS、ZRS 和 RA-GRS。您可以指定允许的 SKU，其余的将被拒绝部署。

+   允许的资源类型：正如我们在示例中提到的，您可以指定订阅中允许的资源。例如，如果您只想要 VM 和网络，您可以接受**Microsoft.Compute**和**Microsoft.Network**资源提供程序；所有其他提供程序都不允许部署。

到目前为止，我们已经讨论了 Azure Policy 如何用于审计 Azure 资源，但它也可以用于审计 VM 内部的设置。Azure Policy 通过使用 Guest Configuration 扩展和客户端来完成这项任务。扩展和客户端共同确认了客户操作系统的配置、应用程序的存在、状态以及客户操作系统的环境设置。

Azure Policy Guest Configuration 只能帮助您审计客户 VM。在撰写本文时，不支持应用配置。

### Linux 的 Guest Configuration 扩展

客户策略配置由 Guest Configuration 扩展和代理完成。VM 上的 Guest Configuration 代理通过使用 Linux 的 Guest Configuration 扩展进行配置。正如前面讨论的，它们共同工作，允许用户在 VM 上运行客户策略，从而帮助用户审计 VM 上的策略。Chef InSpec ([`www.inspec.io/docs/`](https://www.inspec.io/docs/))是 Linux 的客户策略。让我们看看如何将扩展部署到 VM 并使用扩展支持的命令。

**部署到虚拟机**

要做到这一点，您需要有一个 Linux VM。我们将通过执行以下操作将 Guest Configuration 扩展部署到 VM。

```
az vm extension set --resource-group <resource-group> \
--vm-name <vm-name> \
--name ConfigurationForLinux \
--publisher Microsoft.GuestConfiguration \
--version 1.9.0
```

您将获得类似于此的输出：

![将 Guest Configuration 扩展部署到 VM](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_22.jpg)

###### 图 8.22：将 Guest Configuration 扩展部署到 VM

### 命令

Guest Configuration 扩展支持`install`、`uninstall`、`enable`、`disable`和`update`命令。要执行这些命令，您需要切换当前工作目录到`/var/lib/waagent/Microsoft.GuestConfiguration.ConfigurationForLinux-1.9.0/bin`。之后，您可以使用`guest-configuration-shim`脚本链接可用的命令。

#### 注意

检查文件是否启用了执行位。如果没有，使用`chmod +x guest-configuration-shim`来设置执行权限。

执行任何命令的一般语法是`./guest-configuration-shim <command name>`。

例如，如果您想要安装 Guest Configuration 扩展，可以使用`install`命令。当扩展已安装时，将调用`enable`，这将提取代理程序包，安装并启用代理程序。

类似地，`update`将更新代理服务到新代理，`disable`禁用代理，最后，`uninstall`将卸载代理。

代理程序下载到路径，例如`/var/lib/waagent/Microsoft.GuestConfiguration.ConfigurationForLinux-<version>/GCAgent/DSC`，并且`agent`输出保存在此目录中的`stdout`和`stderr`文件中。如果遇到任何问题，请验证这些文件的内容。尝试理解错误，然后进行故障排除。

日志保存在`/var/log/azure/Microsoft.GuestConfiguration.ConfigurationForLinux`。您可以使用这些日志来调试问题。

目前，Azure Policy Guest Configuration 支持以下操作系统版本：

![Azure Policy Guest Configuration 支持的操作系统版本](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_08_23.jpg)

###### 图 8.23：Azure Policy Guest Configuration 支持的操作系统版本

Azure 策略以 JSON 清单的形式编写。编写策略不是本书的一部分；您可以参考 Microsoft 共享的示例策略（[`github.com/MicrosoftDocs/azure-docs/blob/master/articles/governance/policy/samples/guest-configuration-applications-installed-linux.md`](https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/governance/policy/samples/guest-configuration-applications-installed-linux.md)）。此示例用于审计 Linux VM 中是否安装了特定应用程序。

如果您调查示例，您将了解组件是什么，以及如何在您的上下文中使用参数。

## 其他解决方案

编排市场中的另一个重要参与者是 Puppet。直到最近，Puppet 在 Azure 中的支持非常有限，但这种情况正在迅速改变。Puppet 模块`puppetlabs/azure_arm`仍然处于起步阶段，但`puppetlabs/azure`为您提供了所需的一切。这两个模块都需要 Azure CLI 才能工作。将 Azure CLI 集成到其商业 Puppet Enterprise 产品中的工作非常出色。Azure 有一个 VM 扩展，可用于将成为 Puppet 节点的 VM。

更多信息请访问[`puppet.com/products/managed-technology/microsoft-windows-azure`](https://puppet.com/products/managed-technology/microsoft-windows-azure)。

您还可以选择 Chef 软件，它提供了一个自动化和编排平台，已经存在很长时间了。它的开发始于 2009 年！用户编写“食谱”，描述 Chef 如何使用诸如刀具之类的工具管理“厨房”。在 Chef 中，许多术语都来自厨房。Chef 与 Azure 集成非常好，特别是如果您从 Azure Marketplace 使用 Chef Automate。还有一个 VM 扩展可用。Chef 适用于大型环境，学习曲线相对陡峭，但至少值得一试。

更多信息请访问[`www.chef.io/partners/azure/`](https://www.chef.io/partners/azure/)。

## 总结

我们从简要介绍编排、使用编排的原因以及不同的方法：命令式与声明式开始了本章。

之后，我们介绍了 Ansible、Terraform 和 PowerShell DSC 平台。关于以下内容涵盖了许多细节：

+   如何安装平台

+   在操作系统级别处理资源

+   与 Azure 集成

Ansible 是迄今为止最完整的解决方案，也可能是学习曲线最平缓的解决方案。但是，所有解决方案都非常强大，总是有办法克服它们的局限性。对于所有编排平台来说，未来在功能和能力方面都是充满希望的。

在 Azure 中创建 Linux VM 并不是在 Azure 中创建工作负载的唯一方法；您还可以使用容器虚拟化来部署应用程序的平台。在下一章中，我们将介绍容器技术。

## 问题

在本章中，让我们跳过常规问题。启动一些 VM 并选择您选择的编排平台。配置网络安全组以允许 HTTP 流量。

尝试使用 Ansible、Terraform 或 PowerShell DSC 配置以下资源：

1.  创建用户并将其设置为`wheel`组（基于 RH 的发行版）或`sudo`（Ubuntu）的成员。

1.  安装 Apache Web 服务器，从`/wwwdata`提供内容，使用 AppArmor（Ubuntu）或 SELinux（基于 RHEL 的发行版）进行安全保护，并在此 Web 服务器上提供一个漂亮的`index.html`页面。

1.  将 SSH 限制为您的 IP 地址。HTTP 端口必须对整个世界开放。您可以通过提供覆盖文件或 FirewallD 来使用 systemd 方法。

1.  部署一个新的 VM，选择您喜欢的发行版和版本。

1.  使用变量创建新的`/etc/hosts`文件。如果您使用 PowerShell DSC，您还需要 PowerShell 来完成此任务。对于专家：使用资源组中其他计算机的主机名和 IP 地址。

## 进一步阅读

我们真的希望你喜欢这个对编排平台的介绍。这只是一个简短的介绍，让你对更多的学习产生好奇。本章提到的编排工具的所有网站都是很好的资源，阅读起来很愉快。

还有一些额外的资源需要提到，包括以下内容：

+   詹姆斯·波格兰的《学习 PowerShell DSC-第二版》。

+   Ansible：我们确实认为 Russ McKendrick 的《学习 Ansible》以及同一作者关于 Ansible 的其他书籍都值得赞扬。如果你懒得读这本书，那么你可以参考 Ansible 的文档开始学习。如果你想要一些实践教程，你可以使用这个 GitHub 仓库：[`github.com/leucos/ansible-tuto`](https://github.com/leucos/ansible-tuto)。

+   Terraform：**在 Microsoft Azure 上使用 Terraform-第一部分：介绍**是由微软高级软件工程师 Julien Corioland 撰写的博客系列。该博客包括一系列讨论 Azure 上 Terraform 的主题。值得一读并尝试这些任务。博客地址为[`blog.jcorioland.io/archives/2019/09/04/terraform-microsoft-azure-introduction.html`](https://blog.jcorioland.io/archives/2019/09/04/terraform-microsoft-azure-introduction.html)。

+   Mayank Joshi 的《精通 Chef》

+   Jussi Heinonen 的《学习 Puppet》


# 第九章：Azure 中的容器虚拟化

在*第二章*“开始使用 Azure 云”中，我们开始了在 Azure 中的旅程，首先在 Azure 中部署了我们的第一个工作负载：Linux 虚拟机的部署。之后，我们涵盖了 Linux 操作系统的许多方面。

在*第七章*“部署您的虚拟机”中，我们探讨了部署虚拟机的几种选项，而*第八章*“探索持续配置自动化”则是关于使用编排工具进行配置管理之后要做的事情。

编排是 DevOps 运动的一个不断增长的部分。DevOps 是打破组织中经典隔离的一部分。参与开发、测试和部署产品的不同团队必须进行沟通和合作。DevOps 是文化哲学、实践和工具的结合。DevOps 是一种使部署增量、频繁和常规事件的方式，同时限制失败影响的方法。

虚拟机不是部署工作负载的唯一方式：您还可以在容器中部署工作负载。它使得与编排一起，可以满足 DevOps 的要求。

因此，在我们实际学习和在 Azure 中实现容器之前，让我们快速看一下本章提供了什么。在本章结束时，您将：

+   了解容器的历史，并了解容器化的早期采用情况。

+   熟悉诸如`systemd-nspawn`和 Docker 之类的容器工具。

+   能够使用 Docker Machine 和 Docker Compose。

+   能够使用 Azure 容器实例和 Azure 容器注册表。

+   了解新一代容器工具，如 Buildah、Podman 和 Skopeo。

现在，我们首先要了解容器是什么，以及它是如何发展的。

## 容器技术简介

在*第一章*“探索 Azure 云”中，我们简要介绍了容器。因此，让我们继续更详细地介绍容器。我们知道虚拟机是在 hypervisor 上运行的，并且在大多数情况下，您必须为每个目的创建一个单独的虚拟机来隔离环境。虚拟机将有一个类似 Linux 的客户操作系统，然后我们将安装所需的软件。在某些情况下，您必须部署大量的虚拟机进行测试。如果您正在使用运行 Hyper-V 的本地基础设施，您必须考虑资源利用率，即每个虚拟机将使用多少内存、CPU 等。如果您在 Azure 中部署，您还必须考虑成本。您可能只需要一些虚拟机来测试某些东西，但这些虚拟机的占用空间很大；它们实际上是在虚拟运行的完整计算机。另一个问题是兼容性问题。假设您有一个应用程序需要一个依赖包，比如 Python 2.2。现在想象一下在同一个虚拟机中运行另一个应用程序，它与 Python 2.2 存在兼容性问题，只能使用 Python 2.1。您最终将不得不为第二个应用程序创建一个新的虚拟机，其中安装了 Python 2.1。为了克服这个问题，引入了容器。以下是容器与虚拟机有何不同的图示表示：

![VMs 与容器的图示表示不同](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_01.jpg)

###### 图 9.1：虚拟机和容器的表示

与虚拟机一样，容器允许您将应用程序与所有依赖项和库打包在一起。它们像虚拟机一样是隔离的环境，可以用于测试和运行应用程序，而无需创建多个虚拟机。容器也很轻量级。

与虚拟机不同，容器是在操作系统级别进行虚拟化的，而不是每个硬件组件都进行虚拟化。这意味着容器的占用空间比虚拟机小。例如，Ubuntu ISO 镜像的大小接近 2.4 GB；另一方面，Ubuntu 容器镜像小于 200 MB。考虑之前的例子，我们在 Python 2.2 上有依赖问题，最终创建了两个虚拟机。使用容器，我们可以有两个占用空间比两个虚拟机小得多的容器。此外，主机操作系统的成本和资源利用远远低于两个虚拟机。容器使用容器运行时部署；有不同的运行时可用。在本章中，我们将看一下流行的容器运行时。

容器不是圣杯。它不能解决您所有的问题。但是，您可以考虑以下情景，如果它们中的任何一个符合您的要求，您可能希望将应用程序容器化：

+   应用程序经常需要更新新功能，最好无需停机，这是由业务需求驱动的。

+   系统工程师和开发人员可以共同解决业务需求，并对彼此的领域有足够的理解和知识（而不必成为两者的专家），并且具有持续实验和学习的文化。

+   为了使应用程序更好，需要有失败的空间。

+   应用程序不是单点故障。

+   应用程序在可用性和安全性方面不是关键应用程序。

还有一件小事：如果您有许多不同类型的应用程序，并且这些应用程序之间几乎没有共享的代码，容器技术仍然是一个选择，但在这种情况下，虚拟机可能是更好的解决方案。

我们将简要介绍容器技术的历史，以便让您更好地了解其来源。我们将探讨当今提供的一些解决方案：systemd-nspawn 和 Docker。甚至有更多的容器虚拟化实现可用，甚至一些最早的实现，比如 LXC。实际上，无论您使用哪种容器化工具：如果您了解容器背后的思想和概念，就很容易使用其他工具实现相同的思想和概念。唯一改变的是命令；所有这些工具的基本概念都是相同的。

### 容器的历史

容器现在非常流行。但它们并不新；它们不是突然出现的。很难指出它们开始的确切时间。我们不想给您历史课，但历史可以让您了解技术，甚至可以让您了解为什么或何时应该在组织中使用容器。

因此，我们不会专注于确切的时间轴，我们只会涵盖重要的步骤：实施如果您想了解当今容器技术的重要技术。

### **chroot 环境**

在 Linux 中，有一个根文件系统，如*第五章* *高级 Linux 管理*中所述，一切都挂载到该文件系统上，这将对当前运行的进程及其子进程可见。

在`chroot`中运行的进程有自己的根文件系统，与系统范围的根完全分离，称为`fs.chroot`。它经常用于开发，因为在`chroot`中运行的程序无法访问其根文件系统之外的文件或命令。要从目录启动 chroot 监狱，请执行以下操作：

```
chroot /<directory>
```

1979 年，在 Unix 的第 7 版中引入了`chroot`系统调用，并在 1982 年引入了 BSD Unix。Linux 自其存在的早期就实现了这个系统调用。

### **OpenVZ**

2005 年，几乎与 Solaris 启动其容器技术同时，一家名为 Virtuozzo 的公司启动了 OpenVZ 项目。

他们采用了 chroot 环境的原则，并将其应用于其他资源。chroot 进程将具有以下内容：

+   根文件系统

+   用户和组

+   设备

+   一个进程树

+   一个网络

+   进程间通信对象

当时，OpenVZ 被视为基于 hypervisor 的虚拟化的轻量级替代方案，也被视为开发人员的坚实平台。它仍然存在，并且您可以在任何 Linux 操作系统上使用它，无论是在云中还是不在云中。

使用 OpenVZ 类似于使用虚拟机：您可以创建一个带有您喜欢的发行版基本安装的映像，之后您可以使用编排来安装应用程序并维护一切。

### **LXC**

2006 年，Google 的工程师开始在 Linux 内核中开发一个名为**cgroups**（**控制组**）的功能，以便对进程集合（资源组）上的 CPU、内存、磁盘 I/O 和网络等资源进行资源控制。

Linux 内核的一个相关特性是`cgroups`的概念成为了一个命名空间。

2008 年，`cgroups`被合并到 Linux 内核中，并引入了一个新的命名空间，即`user`命名空间。然后，这两种技术为容器的新步骤——LXC 启用了。

其他可用的命名空间包括`pid`、`mount`、`network`、`uts`（自己的域名）和`ipc`。

不再需要跟踪 Linux 内核的开发情况：每个所需的组件都可用，并且资源管理更加出色。

最近，Canonical 开发了一个名为 LXD 的新容器管理器，它在其后端使用 LXC，并旨在提供改进的用户体验来管理容器。从技术上讲，LXD 使用 LXC 通过 liblxc 和其 Go 绑定来实现这一目标。以下列出了 LXD 的一些优点：

+   安全

+   高度可扩展

+   简化资源共享

## systemd-nspawn

systemd 带有一个容器解决方案。它起初是一个实验，然后 Lennart Poettering 认为它已经准备好投入生产。实际上，它是另一个解决方案 Rkt 的基础。在撰写本书时，Rkt 的开发已经停止。但是，您仍然可以访问 Rkt GitHub 存储库（[`github.com/rkt/rkt`](https://github.com/rkt/rkt)）。

systemd-nspawn 并不是很出名，但它是一种强大的解决方案，可在每个现代 Linux 系统上使用。它建立在内核命名空间和 systemd 之上进行管理。这是一种类似于增强版的 chroot。

如果您想了解更多关于容器底层技术的知识，systemd-nspawn 是一个很好的起点。在这里，每个组件都是可见的，如果您愿意，可以手动配置。systemd-nspawn 的缺点是您必须自己完成所有工作，从创建映像到编排再到高可用性：这一切都是可能的，但您必须自己构建。

容器也可以使用诸如`yum`之类的软件包管理器创建，并通过提取原始云映像（几个发行版提供此类映像，例如[`cloud.centos.org/centos/7/images`](https://cloud.centos.org/centos/7/images)和[`cloud-images.ubuntu.com/`](https://cloud-images.ubuntu.com/)）。您甚至可以使用 Docker 映像！

如前所述，有多种方法可以创建容器。例如，我们将介绍其中的两种：`debootstrap`和`yum`。

### 使用 debootstrap 创建容器

`debootstrap`实用程序是一个工具，可以将基于 Debian 或 Ubuntu 的系统安装到已安装系统的子目录中。它在 SUSE、Debian 和 Ubuntu 的存储库中可用；在 CentOS 或其他基于 Red Hat 的发行版上，您需要从**企业 Linux 的额外软件包**（**EPEL**）存储库中获取它。

例如，让我们在 CentOS 机器上引导 Debian，以创建我们的 systemd 容器的模板。

在本章中，如果您正在运行 CentOS，您必须更改 systemd-nspawn 的安全标签：

```
semanage fcontext -a -t virtd_lxc_exec_t /usr/bin/systemd-nspawn
 restorecon -v /usr/bin/systemd-nspawn
```

首先，安装 debootstrap：

```
sudo yum install epel-release
sudo yum install debootstrap
```

创建一个子目录：

```
sudo mkdir -p /var/lib/machines/releases/stretch
sudo -s
cd /var/lib/machines/releases
```

例如，从 Debian 的美国镜像引导：

```
debootstrap --arch amd64 stretch stretch \
  http://ftp.us.debian.org/debian
```

### 使用 yum 创建容器

`yum`实用程序在每个存储库中都可用，并且可用于创建具有基于 Red Hat 的发行版的容器。

让我们来看看创建 CentOS 7 容器的步骤：

1.  创建一个目录，我们将在其中安装 CentOS，并将其用作我们的模板：

```
sudo mkdir -p /var/lib/machines/releases/centos7
sudo -s
cd /var/lib/machines/releases/centos7
```

首先，您必须在[`mirror.centos.org/centos-7/7/os/x86_64/Packages/`](http://mirror.centos.org/centos-7/7/os/x86_64/Packages/)下载`centos-release rpm`软件包。

1.  初始化`rpm`数据库并安装此软件包：

```
rpm --rebuilddb --root=/var/lib/machines/releases/centos7
rpm --root=/var/lib/machines/releases/centos7 \
  -ivh --nodeps centos-release*rpm
```

1.  现在您已经准备好至少安装最低限度的内容了：

```
yum --installroot=/var/lib/machines/releases/centos7 \
  groups install  'Minimal Install'
```

安装软件包后，将可用完整的根文件系统，提供启动容器所需的一切。您还可以使用此根文件系统作为模板；在这种情况下，您需要修改模板以确保每个容器都是唯一的。

### systemd-firstboot

systemd-firstboot 是在首次启动容器时配置一些内容的好方法。您可以配置以下参数：

+   系统区域设置（`--locale=`）

+   系统键盘映射（`--keymap=`）

+   系统时区（`--timezone=`）

+   系统主机名（`--hostname=`）

+   系统的机器 ID（`--machine-id=`）

+   Root 用户的密码（`--root-password=`）

您还可以使用`-prompt`参数在首次启动时请求这些参数。

在以下示例中，我们将修改`systemd-firstboot`单元，以传递在首次运行容器时将执行的配置。

在容器目录中执行`chroot`。让我们以我们的 CentOS 镜像为例：

```
chroot /var/lib/containers/releases/centos7
passwd root
```

启动镜像：

```
systemd-nspawn --boot -D centos7
```

打开`systemd-firstboot`单元，`/usr/lib/systemd/system/systemd-firstboot.service`，并对其进行修改：

```
[Unit]
Description=First Boot Wizard
Documentation=man:systemd-firstboot(1)
DefaultDependencies=no
Conflicts=shutdown.target
After=systemd-readahead-collect.service systemd-readahead-replay.service systemd-remount-fs.service
Before=systemd-sysusers.service sysinit.target shutdown.target
ConditionPathIsReadWrite=/etc
ConditionFirstBoot=yes
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/systemd-firstboot --locale=en_US-utf8 --root-password=welk0mITG! --timezone=Europe/Amsterdam 
StandardOutput=tty
StandardInput=tty
StandardError=tty
```

启用服务：

```
systemctl enable systemd-firstboot
```

清理设置：

```
 rm /etc/\
  {machine-id,localtime,hostname,shadow,locale.conf,securetty}
```

使用*Ctrl* + *D*退出 chroot 环境。

### 部署第一个容器

如果您正在使用 BTRFS 文件系统模板目录作为子卷，可以使用`systemd-nspawn`的`--template`参数。否则，它将创建一个新的子卷：

```
cd /var/lib/machines/releases
cp -rf centos7/ /var/lib/machines/centos01
```

是时候启动我们的第一个容器了：

```
systemd-nspawn --boot -D centos01
```

尝试登录并使用*Ctrl* + *]]]*杀死它。

从现在开始，您可以使用`machinectl`命令管理容器：

```
machinectl start <machine name>
```

使用以下登录：

```
machinectl login <machine name>
```

`machinectl`还有许多其他参数值得研究！如果收到权限被拒绝的消息，请考虑 SELinux 故障排除！此外，`journalctl`有一个`-M`参数，用于查看容器内的日志，或者使用以下命令：

```
journalctl _PID=<pid of container> -a
```

如果您在容器中执行`hostnamectl`，您将看到类似以下内容：

![hostnamectl 命令的详细输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_02.jpg)

###### 图 9.2：hostnamectl 命令的输出

内核是主机的内核！

### 在启动时启用容器

要使容器在启动时可用，请启用目标`machines.target`：

```
sudo systemctl enable machines.target
```

现在为我们的容器创建一个`nspawn`文件：`/etc/systemd/nspawn/centos01.nspawn`。文件名必须与容器相同：

```
[Exec]
PrivateUsers=pick
[Network]
Zone=web
Port=tcp:80
[Files]
PrivateUsersChown=yes
```

`[Network]`还设置了从容器的 TCP 端口`80`到主机的端口`80`的端口转发。您必须在容器中的网络接口上配置 IP 地址，并在子网中的虚拟以太网接口上配置主机上的 IP 地址，以使其正常工作。

现在启用 VM：

```
sudo machinectl enable centos01
```

现在您知道如何使用`systemd-nspawn`并部署您的容器，让我们继续讨论最流行的容器化工具：Docker。您可能已经听说过很多关于 Docker 的事情，所以让我们开始吧！

## Docker

2010 年 3 月，Solomon Hykes 开始开发 Docker。它在法国作为内部 dotCloud 开始。由于 2013 年在一次大型 Python 会议上的公开发布以及 Red Hat 的兴趣，Docker 真正起飞。在同年的最后一个季度，公司的名称更改为 Docker Inc。

Docker 最初是建立在 LXC 之上的，但过了一段时间，LXC 被他们自己的`libcontainer`库所取代。

Docker 的架构非常复杂：它由客户端、Docker 和守护进程`dockerd`组成。另一个守护进程`containerd`是操作系统和正在使用的容器技术类型的抽象层。您可以使用`docker-containerd-ctr`工具与`containerd`进行交互。`containerd`守护进程负责以下内容：

+   注册表（您可以存储镜像的地方）

+   镜像（构建、元数据等）

+   网络

+   卷（用于存储持久数据）

+   签名（内容的信任）

`containerd`与 RunC 通信，RunC 负责以下内容：

+   生命周期管理

+   运行时信息

+   在容器内运行命令

+   生成规格（镜像 ID、标签等）

Docker 有两个版本可用——**Docker 社区版**（**CE**）和**Docker 企业版**（**EE**）。Docker EE 于 2019 年 11 月由 Docker Inc 出售给 Mirantis；然而，Docker CE 仍由 Docker Inc 处理。Docker EE 增加了 Docker 支持，还有集成的安全框架，认证插件，对 Docker Swarm（类似于 Kubernetes 的容器编排解决方案）的支持，以及对 RBAC/AD/LDAP 的支持。然而，所有这些都是需要付费的。如果您觉得您的环境需要这些额外的优势，那么值得付费。另一方面，Docker CE 是开源软件，可以免费使用。

### Docker 安装

在 Azure 中有多种安装和使用 Docker CE 的方法。您可以安装您选择的 Linux 发行版，并在其上安装 Docker。Azure Marketplace 中提供了几个 VM，如 RancherOS，这是一个非常精简的 Linux 发行版，专门用于运行 Docker。最后但同样重要的是，还有 Docker for Azure 模板，由 Docker 提供，网址为[`docs.docker.com/docker-for-azure`](https://docs.docker.com/docker-for-azure)和[`docs.docker.com/docker-for-azure`](https://docs.docker.com/docker-for-azure)。

对于本章的目的，Ubuntu 服务器 VM 上的 Docker 绝对不是一个坏主意；它可以节省很多工作！但是有几个原因不使用这个 VM：

+   如果您自己配置一切，确实可以帮助更好地理解事物。

+   使用的软件相对较旧。

+   用于创建 VM 的 Docker VM 扩展已被弃用，不再处于活跃开发状态。

Docker for Azure 模板还安装并配置了 Docker Swarm，这是一个 Docker 本地的集群系统。

Docker 网站提供了关于如何手动安装 Docker 的优秀文档。如果您想使用`apt`或`yum`进行安装而不是按照脚本，可以按照官方 Docker 文档进行操作（[`docs.docker.com/v17.09/engine/installation/#supported-platforms`](https://docs.docker.com/v17.09/engine/installation/#supported-platforms)）。如果您按照这个方法操作，可以跳过`cloud-init`脚本。

在这里，我们将按照我们的脚本进行安装。请注意，这个脚本对实验环境很方便，但不适用于生产环境。

它从 Edge 渠道安装最新版本的 Docker，而不是从 Stable 渠道。理论上，这可能会有点不稳定。

然而，对于本章的目的，这是一个很好的开始方式。为了快速启动和运行，让我们使用*第七章，部署您的虚拟机*中学到的 cloud-init 技术。

首先创建一个新的资源组，例如`Docker_LOA`：

```
az group create --name Docker_LOA --location westus
```

创建一个 cloud-init 配置文件；在我的示例中，文件名为`docker.yml`，内容如下：

```
#cloud-config
package_upgrade: true
write_files:
- content: |
    [Service]
    ExecStart=
    ExecStart=/usr/bin/dockerd
  path: /etc/systemd/system/docker.service.d/docker.conf
- content: |
    {
      "hosts": ["fd://","tcp://127.0.0.1:2375"]
    }
  path: /etc/docker/daemon.json
runcmd:
 - curl -sSL https://get.docker.com/ | sh
 - usermod -aG docker <ssh user>
```

不要忘记用您用于执行`az`命令的帐户的登录名替换`<ssh user>`。

你可能已经注意到我们在脚本中添加了 `ExecStart` 两次。ExecStart 允许你指定在启动单元时需要运行的命令。通过设置 `ExecStart=` 并在第二行指定实际命令，可以清除它是一个好习惯。原因是当 Docker 安装时，它将最初具有 `ExecStart` 值，当我们提供另一个值时，将导致冲突。这种冲突将阻止服务启动。让我们继续使用我们创建的 cloud-init 文件创建一个安装了 Docker 的虚拟机：

1.  创建一个安装了你选择的发行版的虚拟机：

```
az vm create --name UbuntuDocker --resource-group Docker_LOA \
  --image UbuntuLTS --generate-ssh-keys --admin-username <ssh-user> \ 
  --custom-data docker.yml
```

1.  当虚拟机准备就绪后，登录并执行以下操作：

```
sudo systemctl status docker.service
```

#### 注意

如果你收到一条消息说 "`Warning: docker.service changed on disk, run systemctl daemon-reload to reload docker.service`"，请耐心等待，cloud-init 仍在忙碌。另外，如果你看到 `docker.service` 未找到，请等待一段时间让 cloud-init 完成安装。你可以通过执行 `dpkg -l | grep docker` 来验证 Docker CE 是否已安装。

1.  执行以下命令以获取有关 Docker 守护程序的更多信息：

```
docker info
```

1.  是时候下载我们的第一个容器并运行它了：

```
docker run hello-world
```

在下面的截图中，你可以看到容器成功运行，并收到了 `Hello from Docker!` 消息：

![使用 docker run hello-world 命令成功执行容器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_03.jpg)

###### 图 9.3：成功执行容器

Docker 容器是一个执行的镜像。要列出系统中可用的镜像，请执行以下操作：

```
docker image ls
```

在上一个例子中，我们运行了 `docker run hello-world`。因此，镜像已经被拉取，并且当我们使用 `docker image ls` 命令时，你可以看到 `hello-world` 镜像被列出来了：

![使用 docker image 列出 hello-world 镜像](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_04.jpg)

ls 命令](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_04.jpg)

###### 图 9.4：列出 Docker 镜像

如果你再次执行 `docker run hello-world`，这次镜像将不会被下载。相反，它将使用在上一次运行期间已经存储或下载的镜像。

让我们下载另一个镜像：

```
docker run ubuntu
```

之后，我们将列出所有容器，即使那些未运行的：

```
docker ps -a
```

所有容器都具有 `exited` 状态。如果你想保持容器运行，你必须在运行命令中添加 `-dt` 参数；`-d` 表示分离运行：

```
docker run -dt ubuntu bash
```

如果你想要一个交互式 shell 到 Ubuntu 容器（就像你 SSH 到一个虚拟机一样），你可以添加 `-i` 参数：

```
   docker run -it ubuntu
```

通过再次查看进程列表来验证它是否正在运行：

```
docker ps
```

使用容器的 ID 或名称，你可以在容器中执行命令，并在终端中接收标准输出：

```
docker exec <id/name> <command>
```

例如，你可以执行以下命令来查看容器镜像的操作系统版本：

```
docker exec <id/name> cat /etc/os-release
```

附加到容器以验证内容是否符合预期：

```
docker attach <id/name>
```

并使用 *Ctrl* + *P* 和 *Ctrl* + *Q* 分离，这意味着你将退出交互式 shell，容器将在后台运行。

总之，如果你一直在跟着做，到目前为止，你将能够运行容器，将它们作为分离运行，从主机机器执行容器命令，以及获取容器的交互式 shell。到目前为止，我们已经使用了 Docker Hub 中已经可用的镜像。在下一节中，我们将学习如何从基础镜像构建自己的 Docker 镜像。

### 构建 Docker 镜像

Docker 镜像包含层。对于你运行的每个命令来向容器添加组件，都会添加一个层。每个容器都是一个具有只读层和可写层的镜像。第一层是引导文件系统，第二层称为基础层；它包含操作系统。你可以从 Docker Registry 拉取镜像（稍后你将了解更多关于 Registry 的信息），或者自己构建镜像。

如果您想自己构建一个，可以以类似的方式进行，就像我们之前看到的那样，使用 systemd-nspawn 容器，例如，通过使用 debootstrap。大多数命令需要 root 用户访问权限，因此请按以下方式提升您的权限：

```
sudo -i
```

让我们以 Debian 作为基本镜像。这将帮助您了解`docker import`命令。下载并提取 Debian Stretch：

```
debootstrap --arch amd64 stretch stretch \
  http://ftp.us.debian.org/debian
```

创建一个 tarball 并将其直接导入 Docker：

```
tar -C stretch -c . | docker import - stretch
```

使用以下命令进行验证：

```
docker images
```

Docker 还提供了一个名为`scratch`的非常小的基本镜像。

Docker 镜像是从 Dockerfile 构建的。让我们创建一个工作目录来保存 Dockerfile：

```
mkdir ~/my-image && cd ~/my-image
```

由于`stretch`镜像已经在 Docker Hub 中可用，因此最好使用新名称标记您的镜像，以便 Docker 不会尝试拉取镜像，而是选择本地镜像。要标记镜像，请使用以下命令：

```
docker tag stretch:latest apache_custom:v1 
```

然后，通过执行`vi Dockerfile`（您可以使用任何文本编辑器）创建一个 Dockerfile。此文件中的第一行将基本镜像添加为一个层：

```
FROM apache_custom:v1 
```

第二层包含 Debian 更新：

```
RUN apt-get --yes update
```

第三层包含 Apache 安装：

```
RUN apt-get --yes install apache2
```

添加最新的层并在这个读/写层中运行 Apache。`CMD`用于指定执行容器的默认值：

```
CMD /usr/sbin/apachectl -e info -DFOREGROUND
```

打开端口`80`：

```
EXPOSE 80
```

保存文件，您的文件条目将如下截图所示。添加注释是一个好习惯；但是，这是可选的：

![使用 cat Dockerfile 创建 Docker 镜像](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_05.jpg)

###### 图 9.5：创建 Docker 镜像

构建容器：

```
docker build -t apache_image .
```

如果一切顺利，输出应该显示类似于以下内容：

![表示成功构建 Docker 镜像的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_06.jpg)

###### 图 9.6：成功构建 Docker 镜像

您可以测试容器：

```
docker run -d apache_image 
```

查看构建历史：

```
docker history <ID/name>
```

如下截图所示，您将能够查看容器的构建历史：

![显示构建容器的详细输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_07.jpg)

###### 图 9.7：审查构建的容器历史

执行`docker ps`以获取容器的 ID，并使用该 ID 收集有关容器的信息：

```
docker inspect <ID/name> | grep IPAddress
```

在输出中，您可以找到容器的 IP 地址：

![容器的 IP 地址输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_08.jpg)

###### 图 9.8：获取 Docker 的 IP 地址

使用`curl`查看 Web 服务器是否真的在运行：

```
curl <ip address>
```

您将能够在此处看到著名的 HTML“它起作用”页面：

![使用 curl 命令测试 Web 服务器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_09.jpg)

###### 图 9.9：使用 curl 命令测试 Web 服务器

现在，我们将使用以下命令停止容器：

```
docker stop <ID>
```

现在再次运行它：

```
docker run -d <ID> -p 8080:80
```

这将使网站在本地主机端口`8080`上可用。

您还可以使用**acbuild**来构建 Docker 容器。

### Docker Machine

还有另一种创建 Docker 容器的方法：Docker Machine。这是一个创建将托管 Docker 的 VM 的工具。这是您应该在开发机器上运行的东西，无论是物理的还是虚拟的，您都应该远程执行所有操作。

请注意，Docker Machine 可以安装在 macOS、Linux 和 Windows 机器上。请参考 Docker Machine 文档（[`docs.docker.com/machine/install-machine/`](https://docs.docker.com/machine/install-machine/)）以获取 macOS 和 Windows 安装信息，因为我们只关注 Linux 安装。

切换回安装了 Docker 的 Ubuntu 机器。安装以下依赖项：

```
sudo apt install sshfs
```

接下来，您需要下载 Docker Machine，然后将其提取到您的`PATH`中：

```
base=https://github.com/docker/machine/releases/download/v0.16.0 \
&& curl -L $base/docker-machine-$(uname -s)-$(uname -m) \
>/tmp/docker-machine && \
sudo mv /tmp/docker-machine /usr/local/bin/docker-machine \
&& chmod +x /usr/local/bin/docker-machine
```

自动补全可能非常有用，还要确保以 root 身份运行以下脚本，因为脚本将写入`/etc/`目录：

```
base=https://raw.githubusercontent.com/docker/machine/v0.16.0
for i in docker-machine-prompt.bash docker-machine-wrapper.bash \
docker-machine.bash
do
  sudo wget "$base/contrib/completion/bash/${i}" -P \ /etc/bash_completion.d
source /etc/bash_completion.d/$i
done
```

注销并重新登录。为了验证`bash-completion`是否有效，您可以点击 tab 按钮查看`docker-machine`的可用命令，如下截图所示：

![使用 docker-machine 命令验证 bash-completion](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_10.jpg)

###### 图 9.10：验证 bash-completion 是否成功

验证版本：

```
docker-machine version
```

使用 Azure 作为驱动程序，现在可以部署 VM：

```
docker-machine create -d azure \
  --azure-subscription-id <subscription id> \
  --azure-ssh-user <username> \
  --azure-open-port 80 \
  --azure-size <size> <vm name>
```

还有其他选项，例如公共 IP 和资源组名称，可以在部署期间传递。 您可以在 Docker 文档中查看这些选项的完整列表和默认值（[`docs.docker.com/machine/drivers/azure/`](https://docs.docker.com/machine/drivers/azure/)）。 如果我们没有为特定选项指定值，Docker 将采用默认值。 还要记住的一件事是，VM 名称应仅包含小写字母数字字符或必要时连字符； 否则，您将收到错误。

在下面的屏幕截图中，您可以看到名称为`docker-machine-2`的 VM 的部署成功，并且 Docker 正在该机器上运行。 为了简单起见，我们已将订阅 ID 保存到变量`$SUB_ID`中，这样我们就不必每次都检查它； 如果需要，您也可以这样做。 由于我们之前已经进行了身份验证，因此驱动程序不会要求我们再次登录。 驱动程序会记住您的凭据长达两周，这意味着您不必每次部署时都登录。 您还可以查看部署了哪些资源：

![代表 docker-machine-2 VM 成功部署的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_11.jpg)

###### 图 9.11：部署 docker-machine-2 VM

要告诉 Docker 使用远程环境而不是在本地运行容器，请执行以下操作：

```
docker-machine env <vm name>
eval $(docker-machine env <vm name>)
```

要验证是否正在使用远程环境，请使用`info`命令：

```
docker info
```

在其他信息中，输出显示您正在使用在 Azure 中运行的特定 VM：

![使用 dockor info 命令详细了解 Docker 的信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_12.jpg)

###### 图 9.12：获取 docker 信息

对于 Docker Machine，执行以下命令：

```
docker-machine ls
```

输出应类似于以下内容：

![列出 Docker 机器的各种详细信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_13.jpg)

###### 图 9.13：列出 docker-machine

让我们创建一个 nginx 容器，将主机端口`80`映射到容器端口`80`。 这意味着所有发送到主机 VM 端口`80`的流量将被定向到容器的端口`80`。 这是使用`-p`参数给出的。 执行以下命令创建 nginx 容器：

```
docker run -d -p 80:80 --restart=always nginx
```

查找 VM 的 IP 地址：

```
docker-machine ip <vm name>
```

在浏览器中使用该 IP 地址验证 nginx 是否正在运行。

Docker Machine 还允许我们使用`scp`参数将文件复制到 VM 中，甚至可以在本地挂载文件：

```
mkdir -m 777 /mnt/test
docker-machine mount <vm name>:/home/<username> /mnt/test
```

使用`docker ps`查找正在运行的实例，停止它们并删除它们，以便它们为下一个实用程序做好准备。

### Docker Compose

Docker Compose 是用于创建多容器应用程序的工具，例如，需要 Web 服务器和数据库的 Web 应用程序。

您可以在[`github.com/docker/compose/releases`](https://github.com/docker/compose/releases)上检查 Docker Compose 的最新或稳定版本，并安装它，将命令中的版本号替换为最新版本：

```
sudo curl -L "https://github.com/docker/compose/releases/download/1.24.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
```

现在，将可执行权限应用于我们下载的二进制文件：

```
sudo chmod +x /usr/local/bin/docker-compose
```

接下来，验证安装：

```
docker-compose version
```

如果安装成功，您将能够看到安装的 Docker Compose 的版本：

![验证 Dockor Compose 信息的版本](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_14.jpg)

###### 图 9.14：验证 Docker compose 安装

#### 注意

安装后，如果前面的命令失败，请检查您的路径，否则在`/usr/bin`或您的路径中的任何其他目录中创建符号链接。 要找出您的`PATH`中有哪些目录，请在 shell 中执行`$PATH`。 要创建符号链接，请执行`sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose`。

创建名为`docker-compose.yml`的文件，并包含以下内容：

```
wordpress:
  image: wordpress
  links:
    - db:mysql
  ports:
    - 80:80
db:
  image: mariadb
  environment:
    MYSQL_ROOT_PASSWORD: <password>
```

将`<password>`替换为您选择的密码。 在仍然连接到 Azure 环境的情况下，使用 Docker Machine 执行以下操作：

```
docker-compose up -d
```

如果构建成功，将运行两个容器，您可以使用`docker ps`进行验证，并使用正确的 IP 地址（`docker-machine ip <vm name>`）在浏览器中打开 WordPress 安装程序。

### Docker 注册表

每次执行`docker run`或`docker pull`（仅下载）时，都会从互联网获取镜像。它们来自哪里？运行此命令：

```
docker info | grep Registry
```

上述命令的输出给出了答案：[`index.docker.io/v1/`](https://index.docker.io/v1/)。此 URL 是官方的 Docker Hub。Docker Hub，或 Docker Store，还有一个可通过[`hub.docker.com`](https://hub.docker.com)访问的漂亮的 Web 界面，是私有和公开可用的 Docker 镜像的在线存储库。

`docker search`命令可用于搜索此存储库。要限制此命令的输出，可以添加过滤器：

```
docker search --filter "is-official=true" nginx --no-trunc
```

以下是`docker search`命令的输出：

![docker search 命令的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_15.jpg)

###### 图 9.15：docker search 命令的输出

可选地，添加`--no-trunc`参数以查看镜像的完整描述。输出中还有一个星级评分，可以帮助我们选择最佳可用镜像。

如果您在 Docker Hub 网站上创建自己的帐户，可以使用`docker push`将您的镜像上传到注册表。这是免费的！

使用以下信息登录：

```
docker login -u <username> -p <password>
```

构建镜像：

```
docker build -t <accountname>/<image>:versiontag .
```

您还可以在之后为镜像打标签：

```
docker tag <tag id> <accountname>/<image>:versiontag
```

对于版本控制，建议使用诸如`v1.11.1.2019`之类的字符串，表示第一个版本于 2019 年 11 月 1 日发布。如果不添加版本，它将被标记为最新版本。

您无法使用`docker search`命令查看标签。您需要使用 Web 界面或使用`curl`（用于在服务器和客户端之间传输数据的工具）和`jq`（一种类似于`sed`但专门用于 JSON 数据的工具）来查询 Docker API：

```
wget -q https://registry.hub.docker.com/v1/repositories/<image>/tags -O - | jq 
```

#### 注意

默认情况下未安装 jq。您必须使用`apt install jq`进行安装。

此输出将以 JSON 格式呈现。您可以使用`jq`进一步查询并根据需要优化输出。如果您不想使用 jq 格式化 JSON，可以使用本机的`sed`、`tr`和`cut`命令来格式化输出并获得更清晰的内容：

```
wget -q https://registry.hub.docker.com/v1/repositories/<image name>/tags -O -  | sed -e 's/[][]//g' -e 's/"//g' -e 's/ //g' | tr '}' '\n' | cut -d ":" -f3
```

如果您想获取 nginx 的所有标签，可以将`<image name>`替换为`nginx`。

我们已经讨论了 Docker Hub 以及如何检查可用镜像。类似地，Azure 提供了 Azure 容器注册表，您可以在其中存储私有镜像，并在需要时拉取它们。在开始使用 Azure 容器注册表之前，我们需要了解 Azure 容器实例，借助它，您可以在不必管理主机机器的情况下运行容器。让我们继续学习更多。

## Azure 容器实例

现在我们能够在虚拟机中运行容器，我们可以更进一步：我们可以使用 Azure 容器实例服务来运行它，而无需管理服务器。

您可以在 Azure 门户中执行此操作。在左侧导航栏中，选择**所有服务**并搜索**容器实例**。一旦进入**容器实例**，点击**添加**以创建新的容器实例，门户将重定向到以下窗口：

![在 Azure 容器实例门户上创建新的容器实例](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_16.jpg)

###### 图 9.16：创建 Docker 容器实例

您可以创建一个资源组或使用现有的资源组。将容器名称设置为`nginx`，设置`Public`，因为我们将要拉取一个公共镜像，将镜像名称设置为`nginx:latest`，设置`Linux`，并选择容器的所需资源要求。点击**下一步**，在**网络**部分，我们将公开**端口 80**以进行 HTTP 流量，如下截图所示。此外，如果需要，您可以添加**DNS 标签**并选择公共 IP 地址：

![为容器实例添加网络详细信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_17.jpg)

###### 图 9.17：为容器实例添加网络详细信息

这已足够验证和创建实例。您可以跳过下一节，转到**审阅+创建**。但是，Azure 在**高级**选项卡中提供了高级选项。这些选项可用于添加环境变量，设置重启策略选项，并使用命令覆盖以包括在容器初始化时需要执行的一组命令。如果您愿意，也可以配置这些选项。

您还可以使用 Azure CLI 命令行创建容器：

```
az container create --resource-group <resource group> --name nginx --image nginx:latest --dns-name-label nginx-loa --ports 80
```

您也可以使用 PowerShell：

```
New-AzContainerGroup -ResourceGroupName <resource group> '
  -Name nginx -Image nginx:latest r -OsType Linux '
  -DnsNameLabel nginx-loa2
```

请注意，DNS 标签在您的区域必须是唯一的。

在命令的输出中，实例的 IP 地址是可见的：

![使用 PowerShell 创建容器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_18.jpg)

###### 图 9.18：使用 PowerShell 创建容器

您应该能够访问 FQDN 和 IP 地址上的 Web 服务器。如屏幕截图所示，您可以将浏览器指向 DNS 标签或 IP 地址，然后您可以看到**欢迎使用 nginx！**页面：

![当浏览器指向 DNS 标签时，Web 页面的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_19.jpg)

###### 图 9.19：当浏览器指向 DNS 标签时，Web 服务器的输出

要获取容器实例的列表，请执行以下操作：

```
az container list
```

或者，执行以下操作：

```
Get-AzContainerGroup | Format-List
```

到目前为止，我们一直依赖 Docker Registry 来保存、拉取和推送图像。Azure 提供了一个私有图像注册表，您可以在其中存储图像，以便在需要时使用。这项服务称为 Azure 容器注册表。让我们了解一下。

## Azure 容器注册表

如前所述，您可以使用私有 Azure 容器注册表，而不是 Docker 注册表。这项服务是收费的！使用此 Azure 服务的优势在于，您拥有 Blob 存储的所有功能（可靠性、可用性、复制等），并且可以将所有流量保持在 Azure 内部，这使得该注册表在功能、性能和成本方面成为一个有趣的选择。

### 使用 Azure 门户

创建注册表的最简单方法是使用 Azure 门户。在左侧导航栏中，选择**所有服务**，然后搜索**容器注册表**。单击**添加**，您应该会看到以下屏幕。不要忘记启用**管理员用户**选项；这样做可以让您使用用户名作为注册表名称和访问密钥作为密码登录到容器注册表：

![使用 Azure 门户创建容器注册表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_20.jpg)

###### 图 9.20：使用 Azure 门户创建容器注册表

如果注册表准备就绪，将会弹出一个弹窗，显示作业已完成，并且您将能够看到资源。如果导航到**访问密钥刀片窗格**，您将找到登录服务器和您的用户名，该用户名与注册表名称相同，并且一组密码：

![访问密钥刀片窗格的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_21.jpg)

###### 图 9.21：访问密钥刀片窗格

使用此信息登录存储库，方式与您在 Docker Hub 上登录相同。

推送图像后，它将在存储库中可用。从那里，您可以将其部署到 Azure 容器实例服务并运行它。

### 使用 Azure CLI

我们已经通过 Azure 门户创建了一个 Azure 容器注册表实例。也可以使用 Azure CLI 和 PowerShell 执行相同的任务。我们将遵循 Azure CLI 步骤，并鼓励您尝试使用 PowerShell 自行完成此过程。

首先，我们需要一个已安装 Docker 和 Azure CLI 的 Linux VM。

让我们首先创建一个资源组，或者您可以使用在门户示例中使用的相同资源组。只是为了回忆我们在* Docker 安装*部分学习的命令，我们将继续使用一个新的资源组：

```
az group create --name az-acr-cli --location eastus
```

一旦收到成功消息，请继续使用以下命令创建容器注册表：

```
az acr create --resource-group az-acr-cli --name azacrcliregistry --sku Basic --admin-enabled true
```

在这里，我们使用基本 SKU 创建容器注册表。还有其他可用的 SKU，提供更多的存储选项和吞吐量。SKU 指向容器注册表的不同定价层。访问 Microsoft Azure 定价页面（[`azure.microsoft.com/en-in/pricing/details/container-registry/`](https://azure.microsoft.com/en-in/pricing/details/container-registry/)）查看每个 SKU 的定价。由于这是一个演示，并且为了保持成本最低，我们将选择基本 SKU。

部署 Azure 容器注册表实例后，我们将登录到注册表。但是要登录，我们需要密码。我们已经知道用户名，即注册表的名称，所以让我们找到注册表的密码：

```
az acr credential show --name azacrcliregistry --resource-group az-acr-cli
```

输出将显示用户名和密码。请记下它们。您可以使用密码 1 或密码 2。既然我们确定了凭据，我们将通过执行以下操作登录到 Azure 容器注册表实例：

```
az acr login --name azacrcliregistry --username azacrcliregistry --password <password>
```

如果登录成功，您应该收到以下截图中显示的输出：

![显示 Azure 容器注册表成功登录的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_22.jpg)

###### 图 9.22：Azure 容器注册表登录成功

让我们继续推送一个镜像到注册表。为了推送一个镜像，首先我们需要有一个镜像。如果您正在使用在先前示例中使用的相同 VM，您可能已经拉取了一些镜像。如果镜像不存在，您可以使用`docker pull <image name>`来获取镜像。您可以使用`docker images`命令来验证可用镜像的列表。由于我们已经有了一个 nginx 镜像，我们不打算从 Docker Hub 拉取它。

现在我们有了镜像，让我们给它打标签。标记将帮助您知道您正在使用哪个镜像。例如，如果您有一个标记为`v1`的镜像，并对其进行了一些更改，您可以将其标记为`v2`。标记有助于您根据发布日期、版本号或任何其他标识符对镜像进行逻辑组织。我们需要以`<AcrLoginName>/<image name>:<version tag>`格式对镜像进行标记，其中`acr-name`是 Azure 容器注册表实例的 FQDN。要获取 Azure 容器注册表实例的 FQDN，请执行以下操作：

```
az acr show -n azacrcliregistry -g az-acr-cli | grep loginServer
```

对于 nginx 镜像，我们将其标记为`nginx:v1`：

```
docker tag nginx azacrcliregistry.azurecr.io/ngnix:v1
```

让我们使用`docker push`命令将标记的镜像推送到 Azure 容器注册表：

```
docker push azacrcliregistry.azurecr.io/ngnix:v1
```

所有层都应该被推送，就像截图中显示的那样：

![将标记的镜像推送到 Azure 容器注册表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_23.jpg)

###### 图 9.23：将标记的镜像推送到容器注册表

假设您已经将多个镜像推送到 Azure 容器注册表，并希望获取所有镜像的列表。然后，您可以使用`az acr repository list`命令。要列出我们创建的 Azure 容器注册表实例中的所有镜像，请使用此命令：

```
az acr repository list --name azacrcliregistry -o table
```

您可以使用`docker run`命令来运行容器。但是请务必确保镜像名称的格式为`<AcrLoginName>/<image>`。Docker 时代即将结束，最终将被无守护进程的下一代工具所取代。

接下来的部分都是关于这些工具以及如何使用 Docker 创建类比进行平稳过渡的。

## Buildah、Podman 和 Skopeo

在前面的部分中，我们讨论了 Docker 的工作原理以及如何使用它来部署容器。如前所述，Docker 使用 Docker 守护程序，这有助于我们实现所有这些。如果我们说人们已经开始向 Docker 告别，会怎么样？是的，随着下一代容器管理工具的推出，Docker 正在逐渐消失。我们并不是说 Docker 完全退出了舞台，但是它将被无根或无守护进程的 Linux 容器工具所取代。您没听错：这些工具没有守护进程在运行，使用单块守护进程的方法即将结束。难怪人们已经开始称使用这些工具部署的容器为“无 Docker 容器”。

### 历史

您可能会想知道这一切是什么时候发生的。早在 2015 年，Docker Inc.和 CoreOS 以及其他一些组织提出了“开放容器倡议”（OCI）的想法。这背后的意图是标准化容器运行时和图像格式规范。OCI 图像格式得到了大多数容器图像存储库的支持，例如 Docker Hub 和 Azure 容器注册表。现在大多数可用的容器运行时要么兼容 OCI，要么正在进行 OCI。这只是开始。

早些时候，Docker 是 Kubernetes 唯一可用的容器运行时。显然，其他供应商希望在 Kubernetes 中支持他们特定的运行时。由于这个困境和对其他供应商的支持不足，Kubernetes 在 2017 年创建了 CRI。CRI 代表容器运行时接口。您可以使用其他运行时，例如 CRI-O、containerd 或 frakti。由于 Kubernetes 的蓬勃发展以及对多个运行时的支持，Docker 的垄断地位开始动摇。在很短的时间内，Docker 的垄断地位发生了变化，并成为 Kubernetes 中支持的运行时之一。这种变化产生的涟漪实际上孕育了无守护进程工具的想法，并推翻了使用需要超级用户访问权限的单块守护进程的方法。

让我们尝试理解流行的术语，而不是使用通用术语。Buildah 用于构建容器，Podman 用于运行容器，Skopeo 允许您对存储图像的图像和存储库执行各种操作。让我们更仔细地看看这些工具。有些人建议在使用这些工具之前删除 Docker，但我们建议保留 Docker，以便您可以不断地将这些工具与其进行比较。如果您已经按照之前关于 Docker 的部分进行了操作，您将能够创建一个类比。

### 安装

安装这些工具非常简单。您可以在 Ubuntu 中使用 apt 或在 RHEL 中使用 yum 来安装这些工具。由于我们正在使用相同的 VM，我们将遵循这些软件包在 Ubuntu 上的安装。要安装 Buildah，请执行以下操作：

```
sudo apt update 
sudo apt install -y software-properties-common
sudo add-apt-repository -y ppa:projectatomic/ppa
sudo apt update 
sudo apt install -y buildah
```

由于在安装 Buildah 时已经添加了 PPA 存储库，我们可以直接使用`apt install`来部署 Podman。要安装 Podman，请执行以下操作：

```
sudo apt -y install podman
```

为了安装 Skopeo，我们需要在 Ubuntu VM 上安装`snap`。如果您使用的是 Ubuntu 16.04 LTS 或更高版本，则`snap`将默认安装。否则，您必须使用`apt install snapd`手动安装它。

让我们使用 snap 安装 Skopeo：

```
sudo snap install skopeo --edge
```

#### 注意

如果您收到错误消息，指出“修订版不适用于生产”，您可以使用“--devmode”参数进行安装；这将跳过此错误并完成安装。

现在我们准备探索这些工具。

### Buildah

在上一节中，我们讨论了 Dockerfile。这里有一个有趣的部分：Buildah 完全支持 Dockerfile。您所需要做的就是编写 Dockerfile 并使用`bud`命令，该命令代表使用 Docker 进行构建。让我们使用在 Dockerfile 部分中使用的相同示例。通过执行`vi Dockerfile`（您可以使用任何文本编辑器），添加以下行来创建一个 Dockerfile：

```
FROM nginx 
RUN apt-get --yes update
RUN apt-get --yes install apache2
CMD /usr/sbin/apachectl -e info -DFOREGROUND
EXPOSE 80
```

保存文件。

在构建之前，我们还需要处理其他事情。Buildah 会在`/etc/containers/registries.conf`文件中查找注册表列表。如果此文件不存在，我们需要创建一个，添加以下代码，并保存文件：

```
[registries.search]
registries = ['docker.io']
```

通过这样做，我们指示搜索 Docker Hub 的镜像。如果需要，您还可以将 Azure 容器注册表实例添加到列表中。

让我们继续构建镜像；确保您在 Dockerfile 所在的目录中。使用以下命令开始构建过程：

```
buildah bud -t ngnix-buildah .
```

我们创建了一个名为`nginx-buildah`的镜像。要查看镜像列表，可以使用`buildah images`命令。是的，我们知道它看起来与您在 Docker 中列出镜像的方式非常相似。我们需要牢记这个类比，它将帮助您学习。

输出将类似于此：

使用 buildah images 命令列出图像的输出

###### 图 9.24：使用 buildah 命令列出图像

您可以看到 Buildah 列出了我们从 Docker Hub 拉取的图像，还列出了存储在本地主机存储库中的图像。

要从图像构建容器，我们可以使用以下命令：

```
buildah from <image>
```

这将创建一个名为`<image>-working-container`的容器。如果要构建一个 nginx 容器，请执行此操作：

```
buildah from nginx
```

您将获得类似于此的输出：

使用"buildah from nginx"命令构建 nginx 容器

###### 图 9.25：构建 nginx 容器

就像使用`docker ps`列出所有容器一样，我们将运行`buildah ps`，我们将能够看到我们刚刚创建的`nginx-working-container`：

使用 buildah ps 命令列出容器

###### 图 9.26：使用 buildah ps 命令列出容器

此外，我们可以使用`buildah run`命令直接在容器中执行命令。语法如下：

```
buildah run <container name> <command>
```

让我们尝试打印我们创建的 nginx 容器的`/etc/os-release`文件的内容。命令如下：

```
buildah run nginx-working-container cat /etc/os-release
```

输出将类似于此：

使用 buildah run nginx-working-container cat /etc/os-release 命令打印 nginx 容器的内容

###### 图 9.27：打印 nginx 容器的内容

与 Docker 一样，Buildah 支持`push`、`pull`、`tag`和`inspect`等命令。

### Podman

我们通过 Buildah 构建的图像遵循 OCI 兼容性，并且可以与 Podman 一起使用。在 Podman 中，类比一直在继续；我们所要做的就是用 Podman 命令替换所有 Docker 命令。我们必须牢记的一个关键事项是，在 Podman 中，非 root 用户无法为容器进行端口绑定。如果您的容器需要端口映射，那么您必须以 root 身份运行 Podman。由于我们已经介绍了 Docker，您已经熟悉了 Docker 命令，我们将尝试运行一个容器并进行验证。让我们创建一个端口映射到`8080`的 nginx 容器。由于我们需要映射一个端口，我们将以`sudo`身份运行该命令：

```
sudo podman run -d -p 8080:80 --name webserver nginx
```

由于我们使用`sudo`命令创建了容器，因此它将归属于 root 用户。如果使用`sudo`创建容器，请确保您对与该容器相关的所有操作都链接了 sudo。

要列出容器，请使用`podman ps`，我们可以看到容器正在主机的`0.0.0.0:8080`上监听，并映射到容器的端口：

使用 podman ps 命令列出容器

###### 图 9.28：使用 podman ps 命令列出容器

让我们进行一次`curl`调用，确认 Web 服务器是否在端口`8080`上运行：

```
curl localhost:8080
```

如果一切正常，您将能够看到 nginx 欢迎页面：

验证 Web 服务器 curl 命令的端口身份验证的输出

###### 图 9.29：验证 Web 服务器端口身份验证

是的，容器正在无守护进程运行！

我们在这里不会覆盖所有 Podman 命令，一旦您熟悉了 Docker，您只需在命令行中用`podman`替换`docker`。

### Skopeo

如果您还记得，我们之前尝试使用 Docker 获取图像的标签。使用 Skopeo，您可以检查存储库、复制图像和删除图像。首先，我们将使用`skopeo inspect`命令在 Docker Hub 中获取图像的标签而不拉取它：

```
skopeo inspect docker://nginx:latest
```

运行此命令将触发一些警告。您可以忽略它们。如果您检查输出，您会看到它正在提供标签、层、操作系统类型等信息。

您可以使用`skopeo copy`命令在多个存储库之间复制容器图像。此外，您还可以将 Skopeo 与 Azure 容器注册表一起使用。

我们不会覆盖所有这些。但是，您可以访问这些工具的 GitHub 存储库：

+   Buildah：[`github.com/containers/buildah`](https://github.com/containers/buildah)

+   Podman：[`github.com/containers/libpod`](https://github.com/containers/libpod)

+   Skopeo：[`github.com/containers/skopeo`](https://github.com/containers/skopeo)

## 容器和存储

本节旨在为您提供有关容器和存储的基本概念。每个可以创建镜像的构建工具都提供了向容器添加数据的选项。

您应该仅使用此功能来提供配置文件。尽可能将应用程序数据托管在容器之外。如果您想快速更新/删除/替换/扩展容器，如果数据在容器内，这几乎是不可能的。

当我们创建一个容器时，存储被附加到容器上。然而，容器是短暂的，这意味着当您销毁容器时存储也会被销毁。假设您为测试创建了一个 Ubuntu 容器，并且保存了一些在容器上测试并希望以后可以使用的脚本。现在，如果您意外删除了这个容器，那么您测试并保存以供以后使用的所有脚本都将消失。

您的应用程序数据很重要，您希望即使容器的生命周期结束后也能保留它。因此，我们希望将数据与容器的生命周期分离。通过这样做，您的数据不会被销毁，并且可以在需要时重复使用。在 Docker 中，可以通过使用卷来实现这一点。

Docker 支持各种持久卷的选项，包括 Azure Files。换句话说，您可以将 Azure 文件共享与 Docker 容器绑定为持久卷。为了演示这一点，我们将使用主机卷，其中一个位置将被挂载为容器的卷。这些步骤的目的是展示即使容器从主机中删除后数据仍然可以保存。

在创建容器时，卷信息通过`-v`参数传递给`docker run`命令。一般的语法如下：

```
docker run -v /some-directory/on host:/some-directory/in container
```

假设您有一个应用程序，将在容器中的`/var/log`目录中创建一个文件，并且我们需要使其持久化。在下一个命令中，我们将一个主机目录映射到容器的`/var/log`目录。

要完成这个练习，您需要在运行 Docker 的 Linux VM 上创建一个`~/myfiles`目录，该目录将映射到容器：

```
mkdir ~/myfiles
```

让我们创建一个带有交互式 shell 的 Ubuntu 容器，其中传递了`-v`参数以挂载卷：

```
docker run -it -v ~/myfile:/var/log ubuntu
```

如果容器成功创建，您将以 root 用户登录到容器中：

![创建 Ubuntu 容器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_30.jpg)

###### 图 9.30：创建 Ubuntu 容器

我们将转到容器的`/var/log`目录，并使用此命令创建 10 个空文件：

```
touch file{1..10}
```

列出目录的内容将显示我们刚刚创建的 10 个文件：

![获取/var/log 目录中最近创建的 10 个文件的列表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_31.jpg)

###### 图 9.31：列出/var/log 目录的内容

使用*Ctrl* + *D*退出交互式 shell，现在我们回到主机机器。现在我们将删除容器：

```
docker rm <id/name of the container>
```

`id/name`可以从`docker ps --all`命令的输出中获取。

现在容器已被删除，我们将转到主机机器的`~/myfiles`目录以验证内容。

在下面的屏幕截图中，您可以看到容器已成功删除；但是，`~/myfiles`目录仍然保存着我们在容器内创建的文件：

![列出~/myfiles 目录中的文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_09_32.jpg)

###### 图 9.32：列出~/myfiles 目录中的文件

现在我们知道如何使我们的卷持久化。对于 Docker，有一些解决方案，比如[`github.com/ContainX/docker-volume-netshare`](https://github.com/ContainX/docker-volume-netshare)。

如果你正在使用 Docker 并想使用 Azure 文件，你可以使用 Cloudstor，这是一个可用的插件，网址是[`docs.docker.com/docker-for-azure/persistent-data-volumes`](https://docs.docker.com/docker-for-azure/persistent-data-volumes)。

使用 Azure 文件存储可能不是最便宜的解决方案，但这样你可以获得所有你需要的可用性和备份选项。

如果你要使用 Kubernetes，那就是另一回事了。我们将在下一章中讨论这个问题。

## 总结

在本章中，我们讨论了在 Azure 中部署工作负载的另一种方式。在介绍容器虚拟化的历史、思想和概念之后，我们探讨了一些可用的选项。除了较旧的实现，如 LXC，我们还讨论了其他出色且稳定的容器托管实现：systemd-nspawn 和 Docker。

我们不仅看到了如何运行从仓库中拉取的现有镜像，还学会了如何创建我们自己的镜像。也许最大的好消息是，有一个名为 Buildah 的工具，它能够使用开放容器倡议（OCI）标准创建镜像，并且可以用于 Docker。

本章的大部分内容都是关于 Docker 的。迄今为止，这是最广泛实施的容器解决方案。而且，谈到实施，有许多实现/部署 Docker 的方法：

+   在虚拟机中手动部署它

+   从市场上部署一个准备好的虚拟机

+   Docker Machine

+   Azure 容器实例

还讨论了与 Docker Hub 和 Azure 容器注册表一起工作。

最后，我们讨论了 Buildah、Podman 和 Skopeo 等新的容器技术。

我们以几句话结束了本章关于容器和存储的讨论。如果容器被销毁，附加到容器的存储会发生什么，或者如何使存储持久化，你将在下一章*第十章*“使用 Azure Kubernetes 服务”中了解到。此外，我们还将讨论著名的容器编排工具 Kubernetes。

## 问题

1.  使用容器的原因是什么？

1.  容器不是你需要的解决方案的时候是什么情况？

1.  如果你需要像虚拟私有服务器这样的东西，你想要一个虚拟机，还是有一个可用的容器虚拟化解决方案可能是个好主意？

1.  为什么从一个解决方案（比如 Docker）迁移到另一个解决方案（比如 Buildah）不应该很困难？

1.  开发机器用于什么？

1.  为什么使用 Buildah 是一个好主意，即使它还在积极开发中？

1.  为什么不应该将应用程序数据存储在容器中？

## 进一步阅读

在容器虚拟化领域进行进一步阅读并不是一件很容易的事情。对于`systemd-nspawn`来说，阅读起来相对容易：man 页面很容易理解。让我们提一个建议，这对于`systemd-nspawn`甚至 Docker 都是相关的：Red Hat 在他们的网站上提供了一份名为资源管理指南的文档（[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/resource_management_guide/`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/resource_management_guide/)），其中包含了关于 cgroups 的良好信息。

以下是有关 Docker 的一些参考资料：

+   *编排 Docker*，作者 Shrikrishna Holla，你可以了解如何管理和部署 Docker 服务

+   *掌握 Docker 企业：敏捷容器采用的伴侣指南*，作者 Mark Panthofer，你可以探索 Docker EE 的附加服务以及它们的使用方式
