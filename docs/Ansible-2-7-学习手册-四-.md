# Ansible 2.7 学习手册（四）

> 原文：[`zh.annas-archive.org/md5/89BF78DDE1DEE382F084F8254DF8B8DD`](https://zh.annas-archive.org/md5/89BF78DDE1DEE382F084F8254DF8B8DD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四部分：使用 Ansible 部署应用

本节解释了如何从 Ansible 管理 Windows 节点以及如何利用 Ansible Galaxy 和 Ansible Tower 来最大化您的生产力。

本节包含以下章节：

+   第十章，*为企业介绍 Ansible*

+   第十一章，*开始使用 AWX*

+   第十二章，*与 AWX 用户、权限和组织合作*


# 第十二章：为企业介绍 Ansible

在前一章中，我们看到了 Ansible 的工作原理以及如何利用它。到目前为止，我们一直在假定我们的目标是 Unix 机器，我们将自己编写所有 playbook，并且 Ansible CLI 是我们要寻找的。现在我们将摆脱这些假设，看看如何超越典型的 Ansible 用法。

在本章中，我们将探讨以下主题：

+   Windows 上的 Ansible

+   Ansible Galaxy

+   Ansible Tower

# 技术要求

除了 Ansible 本身之外，为了能够在您的机器上按本章示例操作，您需要一个 Windows 机器。

# Windows 上的 Ansible

Ansible 版本 1.7 开始能够通过一些基本模块管理 Windows 机器。在 Ansible 被 Red Hat 收购后，Microsoft 和许多其他公司以及个人都为此付出了大量努力。到 2.1 版本发布之时，Ansible 管理 Windows 机器的能力已接近完整。一些模块已扩展以在 Unix 和 Windows 上无缝工作，而在其他情况下，Windows 逻辑与 Unix 有很大差异，因此需要创建新的模块。

在撰写本文时，尚不支持将 Windows 作为控制机器，尽管某些用户已调整了代码和环境使其能够运行。

从控制机器到 Windows 机器的连接不是通过 SSH 进行的；而是通过**Windows 远程管理**（**WinRM**）进行的。您可以访问微软的网站以获取详细解释和实施方法：[`msdn.microsoft.com/en-us/library/aa384426(v=vs.85).aspx`](https://docs.microsoft.com/en-in/windows/desktop/WinRM/portal)。

在控制机器上，一旦安装了 Ansible，重要的是安装 WinRM。您可以通过以下命令使用 `pip` 安装：

```
pip install "pywinrm>=0.3.0"  
```

您可能需要使用 `sudo` 或 `root` 帐户来执行此命令。

在每台远程 Windows 机器上，您需要安装 PowerShell 版本 3.0 或更高。Ansible 提供了一些有用的脚本来设置它：

+   WinRM ([`github.com/ansible/ansible/blob/devel/examples/scripts/ConfigureRemotingForAnsible.ps1`](https://github.com/ansible/ansible/blob/devel/examples/scripts/ConfigureRemotingForAnsible.ps1))

+   PowerShell 3.0 升级 ([`github.com/cchurch/ansible/blob/devel/examples/scripts/upgrade_to_ps3.ps1`](https://github.com/cchurch/ansible/blob/devel/examples/scripts/upgrade_to_ps3.ps1))

您还需要通过防火墙允许端口`5986`，因为这是默认的 WinRM 连接端口，并确保它可以从命令中心访问。

为确保可以远程访问服务，请运行 `curl` 命令：

```
curl -vk -d `` -u "$USER:$PASSWORD" "https://<IP>:5986/wsman".  
```

如果基本身份验证可用，则可以开始运行命令。设置完成后，您就可以开始运行 Ansible！让我们通过运行 `win_ping` 来运行 Ansible 中 Windows 版本的 `Hello, world!` 程序的等效程序。为此，让我们设置我们的凭据文件。

可以使用 `ansible-vault` 完成此操作，如下所示：

```
$ ansible-vault create group_vars/windows.yml  
```

正如我们已经看到的，`ansible-vault` 会要求您设置 `password`：

```
Vault password:
Confirm Vault password:  
```

此时，我们可以添加我们需要的变量：

```
ansible_ssh_user: Administrator 
ansible_ssh_pass: <password> 
ansible_ssh_port: 5986 
ansible_connection: winrm 
```

让我们设置我们的 `inventory` 文件，如下所示：

```
[windows] 
174.129.181.242 
```

在此之后，让我们运行 `win_ping`：

```
ansible windows -i inventory -m win_ping --ask-vault-pass  
```

Ansible 将要求我们输入 `Vault 密码`，然后打印运行结果，如下所示：

```
Vault password: 
174.129.181.242 | success >> { 
    "changed": false, 
    "ping": "pong" 
} 
```

我们已经看到了如何连接到远程计算机。现在，您可以以与管理 Unix 计算机相同的方式管理 Windows 计算机。需要注意的是，由于 Windows 操作系统和 Unix 系统之间存在巨大差异，不是每个 Ansible 模块都能正常工作。因此，许多 Unix 模块已经被从头开始重写，以具有与 Unix 模块相似的行为，但具有完全不同的实现方式。这些模块的列表可以在 [`docs.ansible.com/ansible/latest/modules/list_of_windows_modules.html`](https://docs.ansible.com/ansible/latest/modules/list_of_windows_modules.html) 找到。

# Ansible Galaxy

Ansible Galaxy 是一个免费网站，您可以在该网站上下载由社区开发的 Ansible 角色，并在几分钟内启动自动化。您可以分享或审查社区角色，以便其他人可以轻松找到 Ansible Galaxy 上最值得信赖的角色。您可以通过简单地注册 Twitter、Google 和 GitHub 等社交媒体应用程序，或者在 Ansible Galaxy 网站 [`galaxy.ansible.com/`](https://galaxy.ansible.com/) 上创建新帐户，并使用 `ansible-galaxy` 命令下载所需的角色，该命令随 Ansible 版本 1.4.2 及更高版本一起提供。

如果您想要托管自己的本地 Ansible Galaxy 实例，可以通过从 [`github.com/ansible/galaxy`](https://github.com/ansible/galaxy) 获取代码来实现。

要从 Ansible Galaxy 下载 Ansible 角色，请使用以下命令：

```
ansible-galaxy install username.rolename  
```

您也可以按照以下步骤指定版本：

```
ansible-galaxy install username.rolename[,version]  
```

如果您不指定版本，则 `ansible-galaxy` 命令将下载最新可用的版本。您可以通过以下两种方式安装多个角色；首先，通过将多个角色名称用空格分隔，如下所示：

```
ansible-galaxy install username.rolename[,version] username.rolename[,version]  
```

其次，您可以通过在文件中指定角色名称，并将该文件名传递给 `-r/--role-file` 选项来完成此操作。例如，您可以创建以下内容的 `requirements.txt` 文件：

```
user1.rolename,v1.0.0 
user2.rolename,v1.1.0 
user3.rolename,v1.2.1 
```

您可以通过将文件名传递给 `ansible-galaxy` 命令来安装角色，如下所示：

```
ansible-galaxy install -r requirements.txt  
```

让我们看看如何使用 `ansible-galaxy` 下载 Apache HTTPd 的角色：

```
ansible-galaxy install geerlingguy.apache  
```

您将看到类似以下内容的输出：

```
- downloading role 'apache', owned by geerlingguy
- downloading role from https://github.com/geerlingguy/ansible-role-apache/archive/3.0.3.tar.gz
- extracting geerlingguy.apache to /home/fale/.ansible/roles/geerlingguy.apache
- geerlingguy.apache (3.0.3) was installed successfully
```

前述的 `ansible-galaxy` 命令将把 Apache HTTPd 角色下载到 `~/.ansible/roles` 目录中。您现在可以直接在您的 playbook 中使用前述的角色，并创建 `playbooks/galaxy.yaml` 文件，并填写以下内容：

```
- hosts: web 
  user: vagrant 
  become: True 
  roles: 
    - geerlingguy.apache 
```

如您所见，我们创建了一个带有 `geerlingguy.apache` 角色的简单 playbook。现在我们可以测试它：

```
ansible-playbook -i inventory playbooks/galaxy.yaml 
```

这应该给我们以下输出：

```
PLAY [web] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws01.fale.io]

TASK [geerlingguy.apache : Include OS-specific variables.] ***********
ok: [ws01.fale.io]

TASK [geerlingguy.apache : Include variables for Amazon Linux.] ******
skipping: [ws01.fale.io]

TASK [geerlingguy.apache : Define apache_packages.] ******************
ok: [ws01.fale.io]

TASK [geerlingguy.apache : include_tasks] ****************************
included: /home/fale/.ansible/roles/geerlingguy.apache/tasks/setup-RedHat.yml for ws01.fale.io

TASK [geerlingguy.apache : Ensure Apache is installed on RHEL.] ******
changed: [ws01.fale.io]

TASK [geerlingguy.apache : Get installed version of Apache.] *********
ok: [ws01.fale.io]

...
```

正如您可能已经注意到的，由于该角色设计用于在许多不同的 Linux 发行版上工作，因此跳过了许多步骤。

现在您知道如何利用 Ansible Galaxy 角色，您可以花更少的时间重写其他人已经写过的代码，并花更多的时间编写对您的架构特定且给您带来更多价值的部分。

# 将角色推送到 Ansible Galaxy

由于 Ansible Galaxy 是社区驱动的工作，您还可以将自己的角色添加到其中。在我们可以开始发布它的流程之前，我们需要对其进行准备。

Ansible 为我们提供了一个工具，可以从模板中引导一个新的 Galaxy 角色。为了利用它，我们可以运行以下命令：

```
ansible-galaxy init ansible-role-test
```

这将创建 `ansible-role-test` 文件夹，以及通常具有的所有文件夹的 Ansible 角色。

唯一对您新的文件将是 `meta/main.yaml`，即使没有 Ansible Galaxy 也可以使用，但包含了很多关于角色的信息，这些信息可被 Ansible Galaxy 读取。

可用于设置的主要信息在该文件中都可以找到，以满足您的需求，如下所示：

+   `author`：您的名字。

+   `description`：在此处放置角色的描述。

+   `company`：在此处放置您所工作公司的名称（或删除该行）。

+   `license`：设置您的模块将具有的许可证。一些建议的许可证包括 BSD（也是默认的），MIT，GPLv2，GPLv3，Apache 和 CC-BY。

+   `min_ansible_version`：设置您已测试过角色的最低 Ansible 版本。

+   `galaxy_tags`：在此部分中，放置您的模块适用的平台和版本。

+   `dependencies`：列出执行您的角色所需的角色。

要进行发布，您需要使用 GitHub 账户登录 Galaxy，然后您可以转到“我的内容”开始添加内容。

按下“添加内容”后，将会出现一个窗口，其中显示您可以选择的存储库，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb-27/img/f3ddb72c-f36a-4ced-b4e3-5786e4c73e33.png)

在选择正确的存储库后，然后点击“确定”按钮，Ansible Galaxy 将开始导入给定的角色。

如果您在执行此操作几分钟后返回到“我的内容”页面，您将看到您的角色及其状态，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb-27/img/42d74864-d05d-4170-a2a9-c41880b7b8bc.png)

您现在可以像其他人一样使用该角色。记得在需要更改时更新它！

# Ansible Tower 和 AWX

Ansible Tower 是由 Red Hat 开发的基于 Web 的 GUI。Ansible Tower 提供了一个易于使用的仪表板，您可以在其中管理节点和基于角色的身份验证以控制对 Ansible Tower 仪表板的访问。Ansible Tower 的主要特点如下：

+   **LDAP/AD 集成**：您可以基于 Ansible Tower 对 LDAP/AD 服务器执行的查询结果导入（并授予权限给）用户。

+   **基于角色的访问控制**：它限制用户只能运行他们被授权运行的 Playbook，并/或者仅针对有限数量的主机。

+   **REST API**：所有 Ansible Tower 的功能都通过 REST API 暴露出来。

+   **作业调度**：Ansible Tower 允许我们调度作业（Playbook 执行）。

+   **图形化清单管理**：Ansible Tower 对清单的管理方式比 Ansible 更加动态。

+   **仪表盘**：Ansible Tower 允许我们查看所有当前和之前作业执行的情况。

+   **日志记录**：Ansible Tower 记录每次作业执行的所有结果，以便在需要时进行查看。

在 Red Hat 收购 Ansible Inc. 期间，承诺过将使 Ansible Tower 成为开源项目。2017 年，这一承诺得以实现，并且以 AWX 的名字回归。

AWX 和 Ansible Tower 在企业版中经常被使用，因为它为 Ansible 生态系统提供了非常方便的功能。我们将在接下来的章节中更详细地讨论这些功能。

# 概要

在本章中，我们已经了解了如何通过查看如何控制 Windows 主机将 Ansible 移出 Unix 世界。然后我们转向 Ansible Galaxy，在那里您可以找到许多其他人编写的角色，您可以简单地重用。最后，我们提到了 Ansible Tower，它是 AWX 的开源化身。在接下来的章节中，我们将更多地讨论关于 AWX 的内容，从安装过程到运行您的第一个作业。


# 第十三章：开始使用 AWX

正如我们在前面的章节中所看到的，Ansible 是一个非常强大的工具。但这还不足以使其无处不在。事实上，要使一个工具无处不在，它需要在任何用户级别上都易于使用，并且易于以各种方式与现有环境集成。

Ansible 公司认识到了这一点，并创建了一个名为 Ansible Tower 的工具，它基本上是围绕 Ansible 构建的 Web UI 和 API 集。 Ansible Tower 是一个闭源工具，也是该公司的主要收入来源。 当红帽公司宣布收购 Ansible 时，其管理层也承诺将 Ansible Tower 开源化。 几年后，红帽公司开源了 Ansible Tower，创建了 AWX 项目，它现在是 Ansible Tower 的上游项目，就像 Fedora 是 Red Hat Enterprise Linux 的上游项目一样。

在 AWX 之前，开源社区中还开发了其他 Web UI 和 API 集，例如 Semaphore。 AWX 和 Ansible Tower 并不是今天 Ansible 的唯一 Web UI 和 API 集，但它们是更活跃的解决方案。

在本章中，我们将看到如何设置 AWX 并学习如何使用它。 更具体地说，我们将讨论以下内容：

+   设置 AWX

+   理解 AWX 项目是什么以及如何利用它

+   理解 AWX 清单是什么以及与 Ansible 清单的区别

+   理解 AWX 作业模板是什么以及如何创建一个

+   理解 AWX 作业是什么以及如何执行您的第一个作业

# 技术要求

对于本章，您需要一台可以运行 `ansible` 和 `docker` 并且已安装 `docker-py` 的机器。

# 设置 AWX

与 Ansible 不同，安装 AWX 不仅涉及一个单一命令，但仍然相当快速和简单。

首先，您需要安装 `ansible`、`docker` 和 `docker-py`。之后，您需要给所需用户运行 Docker 的权限。最后，您需要下载 AWX Git 仓库并执行一个 `ansible` playbook。

# 在 Fedora 中安装 Ansible、Docker 和 Docker-py

让我们从在 Fedora 中安装 `docker`、`ansible` 和 `docker-py` 包开始：

```
sudo dnf install ansible docker python-docker-py
```

要启动并启用 Docker 服务，请使用以下命令：

```
sudo systemctl start docker
sudo systemctl enable docker
```

现在我们已经安装了 `ansible`、`docker` 和 `docker-py`，让我们继续授予用户访问 Docker 的权限。

# 在 Fedora 中给当前用户授权使用 Docker

为确保当前用户可以使用 Docker（默认情况下，Fedora 仅允许 root 使用它），您需要创建一个新的 Docker 组，将当前用户分配到其中，并重新启动 Docker：

```
sudo groupadd docker && sudo gpasswd -a ${USER} docker && sudo systemctl restart docker
```

由于组只在会话开始时分配，所以您需要重新启动您的会话，但我们可以通过执行以下命令来强制 Linux 将新组添加到当前会话中：

```
newgrp docker
```

现在我们已经准备好了所有的先决条件，我们可以开始真正的 AWX 安装了。

# 安装 AWX

我们首先需要做的是通过执行以下命令来检出 `git` 代码库：

```
git clone https://github.com/ansible/awx.git
```

一旦 Git 完成了它的任务，我们就可以将目录更改为包含安装程序的目录并运行它：

```
cd awx/installer/
ansible-playbook -i inventory install.yml
```

这将在 Docker 容器和默认配置中安装 AWX。您可以通过更改相同文件夹中的`inventory`文件来调整配置（在运行最后一个命令之前）。

安装过程完成后，您可以打开浏览器，并指向`https://localhost`，然后使用`admin`用户名和`password`密码登录。

登录后，您应该会看到类似以下的页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb-27/img/0e4ea5a6-e787-40d6-8c22-bc548d9693bf.png)

设置了 AWX 后，您现在将能够执行 Ansible playbooks 而不再使用 Ansible CLI。要开始这个过程，我们首先需要一个项目，所以让我们看看如何设置它。

# 创建新的 AWX 项目

AWX 假设您已经将您的 playbooks 保存在某个地方，为了能够在 AWX 中使用它们，我们需要创建一个项目。

项目基本上是包含 Ansible 资源（角色和 playbooks）的存储库的 AWX 占位符。

当您进入项目部分时，在左侧菜单栏中，您将看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb-27/img/43d1f1ec-f54e-4d38-b918-bc59a206129f.png)

如您所见，演示项目已经就位（安装程序为我们创建了它！）并且由一个 Git 存储库支持。

项目名称的左侧有一个白色圆圈，表示该特定项目尚未被拉取。如果有一个绿色圆圈，意味着项目已成功拉取。脉动的绿色圆圈表示拉取正在进行中，而红色停止标志表示出现了问题。

在项目的同一行，有三个按钮：

+   **获取 SCM 最新修订版本**：获取代码的当前最新版本

+   **复制**：创建项目的副本

+   **删除**：删除项目

在卡片的右上角，您可以看到一个绿色的加号按钮。这是一个允许我们添加更多项目的按钮。

通过选择它，一个新的**新项目**卡片将出现在**项目**卡片的顶部，您可以在其中添加新项目。

**新项目**卡片将如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb-27/img/d2e61be9-d1c9-4660-9f76-e145fe46429e.png)

它正在请求有关您要创建的项目的信息：

+   名称：这是您项目的显示名称。这是为了人类使用，所以要做到人性化！

+   描述：一个额外的显示（仍然是给人看的），以理解项目目标。

+   组织：将拥有该项目的组织。这将在下一章中介绍。现在，让我们保持默认设置。

+   SCM 类型：您的代码所包含的 SCM 类型。在撰写本文时，受支持的选项有：手动、Git、Mercurial、Subversion 和 Red Hat Insights。

+   根据您选择的 SCM 类型，将出现更多字段，例如 SCM URL 和 SCM 分支。

当您填写完所有必填字段后，您可以保存并看到已添加一个新项目。

# 使用 AWX 清单

AWX 清单是 AWX 世界中 Ansible 清单的等价物。由于 AWX 是一个图形工具，清单不像 Ansible 中那样存储为文件（如在 Ansible 中所做），而是可通过 AWX 用户界面进行管理。不绑定到文件还使 AWX 清单相对于 Ansible 清单具有更多的灵活性。

AWX 有不同的方式来管理清单。

您可以通过点击左侧菜单上的 Inventories 项目来查看，您将找到类似于此的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb-27/img/8c479b7f-f596-44a3-afea-49ea888b23d2.png)

至于项目，AWX 自带演示清单。

从左到右看，我们可以找到以下列：

+   云符号 - 用于清单同步状态

+   显示状态（正常或失败）的常规圆圈

+   清单名称

+   清单类型

+   拥有清单的组织

+   编辑符号

+   复制符号

+   删除符号

与之前一样，绿色 + 按钮将允许您创建新项目。点击它，它会询问您想要创建清单还是智能清单。

我们现在可以选择 Inventories 选项，它将允许您添加名称和组织（仅两个强制选项）以及其他非强制选项。一旦保存，您将能够添加主机、组和权限。

如果您不愿手工指定主机、组、变量等，还有一个 Sources 标签可供您使用。

点击 Sources 标签上的 +，您将能够从可用类型列表或使用自定义脚本添加来源。

撰写时可用的来源类型如下：

+   **从项目中获取**：基本上，它将从存储库导入一个 Ansible 核心清单文件。

+   **亚马逊 EC2**：它将使用 AWS API 来发现在您的环境中运行的所有 EC2 机器及其特性。

+   **谷歌计算引擎（GCE）**：它将使用 Google API 来发现您环境中运行的所有 GCE 机器及其特性。

+   **Microsoft Azure 资源管理器**：它将使用 Azure API 来发现在您的环境中运行的所有机器及其特性。

+   **VMWare vCenter**：它将使用 VMWare API 来发现由您的 vCenter 管理的所有机器及其特性。

+   **红帽 Satellite 6**：它将使用卫星 API 来发现由您的卫星管理的所有机器及其特性。

+   **红帽 CloudForms**：它将使用 CloudForms API 来发现由其管理的所有机器及其特性。

+   **OpenStack**：它将使用 OpenStack API 来发现在您的 OpenStack 环境中运行的所有机器及其特性。

+   **红帽虚拟化**：它将使用 RHEV API 来发现所有正在运行的机器及其特性。

+   **Ansible Tower**：它将使用另一个 Ansible Tower/AWX 安装 API 来发现其管理的所有机器及其特性。

+   **自定义脚本**：它将使用您在*清单脚本*部分上传的脚本。

我们现在已经看到如何设置 AWX 清单，这将在下一部分中需要：设置 AWX 作业模板。

# 理解 AWX 作业模板

在 AWX 中，我们有一个作业模板的概念，它基本上是对 playbook 的封装。

要管理作业模板，您必须转到左侧菜单中的“模板”部分，然后会发现类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb-27/img/f17c3464-51a2-4a32-82ea-51888f89b563.png)

查看包含作业模板的表格，我们会找到以下内容：

+   作业模板名称

+   模板类型（AWX 还支持工作流模板，这是一组作业模板的模板）

+   火箭按钮

+   复制按钮

+   删除按钮

通过点击火箭按钮，我们可以执行它。这样做会自动将您带入到不同的视图中，在下一节中我们会发现。

# 使用 AWX 作业

AWX 作业是 AWX 作业模板的执行，就像 Ansible 运行是 Ansible playbooks 的执行一样。

当您启动一个作业时，您会看到一个窗口，就像下面这个：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb-27/img/e7d34166-9649-45fb-9c3a-de4dc0956bed.png)

这是在命令行上运行 Ansible 时的 AWX 版本的输出。

几秒钟后，在右侧的灰色框中，一个非常熟悉的输出将开始弹出，因为它完全相同于 Ansible 的`stdout`，只是重定向到那里。

如果稍后您在左侧菜单栏上点击“作业”，您会发现自己处于一个不同的屏幕上，列出了所有先前运行的作业：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb-27/img/a1c73c44-3175-4b24-bc2b-f7d7773e834d.png)

正如您所注意到的，我们有两个已经执行的作业，而我们只执行了演示作业模板。这是因为在演示作业模板执行之前已经拉取了演示项目。这使得操作员始终可以放心地运行作业，知道它将始终是 SCM 中可用的最新版本要执行的作业。

# 摘要

在本章中，您已经学会了如何在 Fedora 上设置 AWX，并学会了使用 AWX 项目、清单、作业模板和作业。正如您可以想象的那样，由于 AWX 中存在的选项、标志和项目数量，这只是冰山一角，并不打算对其进行完整的解释，因为需要一个专门的书籍来解释。

在接下来的章节中，我们将稍微讨论一下 AWX 用户、用户权限和组织。


# 第十四章：与 AWX 用户、权限和组织一起工作

在阅读上一章节时，您可能会对 AWX 的安全性产生疑问。

AWX 非常强大，并且要如此强大，它需要对目标机器有很多访问权限，这意味着它可能成为安全链中的一个潜在弱点。

在本章中，我们将讨论一些 AWX 用户、权限和组织的问题；具体来说，我们将涵盖以下主题：

+   AWX 用户和权限

+   AWX 组织

# 技术要求

为了完成本章，我们只需要 AWX，这是我们在上一章中设置的。

# AWX 用户和权限

首先，如果您还记得第一次打开 AWX 时，您将记得您必须输入用户名和密码。

当然你可以想象，那些是默认凭据，但您可以创建组织所需的所有用户。

为此，您可以转到左侧菜单中的用户部分，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb-27/img/7822cc10-cb41-4c6e-85f8-2cdbb396510d.png)

正如您可能期望的那样，管理员用户已存在，并且是唯一存在的用户。

我们可以通过点击带有+ 符号绿色按钮来创建其他用户。

当我们创建新用户时，需要填写以下字段：

+   **名字**：这是用户的名字。

+   **姓氏**：用户的姓氏。

+   **组织**：用户所属的组织（我们稍后将在本章更多地讨论这个问题）。

+   **电子邮件**：这是用户的电子邮件。

+   **用户名**：这是用户的用户名。将用于登录，并将在用户界面中弹出。

+   **密码**：这是用户的密码。

+   **确认密码**：重新输入密码以确保没有拼写错误。

+   **用户类型**：用户可以是普通用户、系统审计员或系统管理员。默认情况下，普通用户无法访问任何内容，除非明确授予权限。系统审计员可以以只读模式查看整个系统中的所有内容。系统管理员可以完全读写访问整个系统。

创建了一个普通用户后，您可以转至模板。如果您进入`演示作业模板`的编辑模式，您会注意到一个权限部分，您可以在其中查看和设置能够查看和操作此作业模板的用户。您应该看到以下屏幕截图中显示的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb-27/img/e3c5dc3e-7ca2-4c72-a811-e11f3ed7061c.png)

通过点击带有+ 符号绿色按钮，将会出现一个模态框，您可以在其中选择（或搜索）要启用的用户，并选择访问级别，如下所示的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb-27/img/3f453db8-f42e-4cfd-a2fb-624915b4ff7f.png)

AWX 允许您在三种不同的访问级别之间进行选择：

+   **管理员**：这种类型的用户能够查看作业模板和以前使用它创建的作业，执行将来的作业模板，以及编辑作业模板。

+   **执行**：这种用户可以看到作业模板和以前使用它创建的作业，并在未来执行作业模板，但不能编辑作业模板。

+   **读取**：这种用户可以看到作业模板和以前使用它创建的作业，但不能执行它也不能更改它。

类似于作业模板可以被用户看到、使用和管理，AWX 中的所有其他对象都可以有权限。

如您所想象的那样，如果您开始有数十个作业和数十个用户，您将花费大量时间来管理权限。为了帮助您，AWX 提供了团队的概念。

团队可以在左侧菜单中的团队项中进行管理，基本上只是用户的分组，因此您可以从**自主访问控制**（**DAC**）方法转变为**基于角色的访问控制**（**RBAC**）方法，这样在组织变化和需求方面更快地跟上。

通过使用用户、团队和权限，您将能够以非常精细的级别决定谁能够做什么。

# AWX 组织

在更复杂的组织中，经常出现很多来自非常不同团队和业务单元的人共享同一个 AWX 安装的情况。

在这些情况下，建立不同的 AWX 组织是有意义的。这可以更轻松地管理权限，并将一些权限管理委托给核心系统管理员团队之外的组织管理员。此外，组织允许垂直权限于组织资源，比如清单管理员（即，拥有该组织所有清单的自动管理员）或项目管理员（即，拥有该组织所有项目的自动管理员），除了组织范围的角色（比如组织管理员和组织审核员）。

如果您在一个有多个网站的公司，您可以决定将所有网站集群到同一个 AWX 组织中（如果它们是由同一批人管理的，比如，“web group”），或者您可以决定将它们分成多个 AWX 组织，每个网站一个。

这些组织带来的优势如下：

+   更简单的权限管理

+   团队经理（即，“web group” 管理员或单个网站管理员）能够随着时间推移招聘和解雇成员

+   更容易和更快的审核，因为只需要审核与特定组织相关的权限，而不是 Tower 中的所有权限

凭借这些优势，我总是建议您考虑如何在 AWX 中使用 AWX 组织。

此外，根据我的经验，我始终注意到 AWX 组织结构与公司结构越相似，用户体验越好，因为对所有用户来说都会感觉自然。另一方面，如果你试图强行将 AWX 组织结构与公司结构完全不同，这将感觉陌生，会减慢 AWX 的采用速度，并且在某些情况下甚至可能导致平台失败。

# 总结

在这本书中，我们从一些非常基本的自动化概念开始，通过将 Ansible 与其他常见选项如手动流程、bash 脚本、Puppet 和 Chef 进行比较。然后，我们看了如何编写 YAML 文件，因为这是 Ansible 使用的格式，以及如何安装 Ansible。然后，我们进行了第一个由 Ansible 驱动的安装（基本的一对 HTTP 服务器，支持数据库服务器）。然后，我们添加了利用 Ansible 特性的功能，例如变量、模板和任务委派。接着，我们看到了 Ansible 如何在 AWS、Digital Ocean 和 Azure 等云环境中帮助您。然后，我们继续分析 Ansible 如何用于触发通知，以及在各种部署场景中的应用。最后，我们总结了官方 Ansible 图形界面的概述：AWX/Ansible Tower。

通过这个内容，现在你应该能够自动化你在使用 Ansible 过程中遇到的所有可能情景。
