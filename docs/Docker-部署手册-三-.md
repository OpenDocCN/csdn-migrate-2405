# Docker 部署手册（三）

> 原文：[`zh.annas-archive.org/md5/0E809A4AEE99AC7378E63C4191A037CF`](https://zh.annas-archive.org/md5/0E809A4AEE99AC7378E63C4191A037CF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：构建我们自己的平台

在之前的章节中，我们花了很多时间在基础设施的各个部分上建立了一些孤立的小部分，但在本章中，我们将尝试将尽可能多的概念结合在一起，构建一个最小可行的平台即服务（PaaS）。在接下来的章节中，我们将涵盖以下主题：

+   配置管理（CM）工具

+   亚马逊网络服务（AWS）部署

+   持续集成/持续交付（CI/CD）

在构建我们的服务核心时，我们将看到将一个小服务部署到真正的云中需要做些什么。

需要注意的一点是，本章仅作为云中实际部署的快速入门和基本示例，因为创建一个带有所有功能的 PaaS 基础设施通常是非常复杂的，需要大型团队花费数月甚至数年的时间来解决所有问题。更为复杂的是，解决方案通常非常具体地针对运行在其上的服务和编排工具的选择，因此，请将本章中看到的内容视为您自己部署中可使用的当前生态系统的样本，但其他工具可能更适合您的特定需求。

# 配置管理

对于每个依赖大量类似配置的机器的系统（无论是物理还是虚拟的），总会出现对简单易用的重建工具的需求，以帮助自动化大部分过去需要手动完成的任务。在 PaaS 集群的情况下，理想情况下，所有基础设施的部分都能够在最小用户干预的情况下被重建为所需的确切状态。对于裸金属 PaaS 服务器节点来说，这是至关重要的，因为任何需要手动操作的操作都会随着节点数量的增加而增加，因此优化这个过程对于任何生产就绪的集群基础设施来说都是至关重要的。

现在你可能会问自己，“为什么我们要关心 CM 工具？”事实上，如果您在容器基础设施周围没有适当的 CM，您将确保自己在各种问题上会在非工作时间接到紧急电话，例如：节点永远无法加入集群，配置不匹配，未应用的更改，版本不兼容，以及许多其他问题，这些问题会让您抓狂。因此，为了防止这一系列情况发生在您身上，我们将深入研究这个支持软件生态系统。

解释清楚并且了解清楚之后，我们可以看到一些可供选择的 CM 工具：

+   Ansible ([`www.ansible.com`](https://www.ansible.com))

+   Puppet ([`puppet.com`](https://puppet.com))

+   Chef ([`www.chef.io/chef/`](https://www.chef.io/chef/))

+   SaltStack ([`saltstack.com`](https://saltstack.com))

+   还有一些其他工具在功能和稳定性方面大多较弱。

由于 Puppet 和 Chef 都需要基于代理的部署，而 SaltStack 在 Ansible 的流行度方面落后很多，因此在我们的工作中，我们将 Cover Ansible 作为首选的 CM 工具，但是您的需求可能会有所不同。根据自己的需求选择最合适的工具。

作为一个相关的侧面说明，从我与 DevOps 在线社区的互动中，似乎在撰写本材料时，Ansible 正在成为 CM 工具的事实标准，但它并非没有缺陷。虽然我很愿意推荐它的使用，因为它有许多出色的功能，但请预期更大模块的复杂边缘情况可能不太可靠，并且请记住，您可能会发现的大多数错误可能已经通过 GitHub 上的未合并的拉取请求进行了修复，您可能需要根据需要在本地应用。警告！选择配置管理工具不应该轻率对待，您应该在承诺使用某个工具之前权衡利弊，因为一旦您管理了一些机器，这个工具是最难更换的！虽然许多 IT 和 DevOps 专业人员几乎将这个选择视为一种生活方式（类似于`vim`和`emacs`用户之间的极化），但请确保您仔细和理性地评估您的选择，因为在未来更换到不同的工具的成本很高。我个人从未听说过一家公司在使用某种工具一段时间后更换配置管理工具，尽管我相信有一些公司这样做了。

# Ansible

如果您以前没有使用过 Ansible，它具有以下好处：

+   它相对容易使用（基于 YAML/Ninja2）

+   它只需要一个 SSH 连接到目标

+   它包含大量可插拔模块，以扩展其功能（[`docs.ansible.com/ansible/latest/modules_by_category.html`](https://docs.ansible.com/ansible/latest/modules_by_category.html)），其中许多在基本安装中，因此通常不必担心依赖关系

如果这个列表听起来不够好，整个 Ansible 架构是可扩展的，因此如果没有满足您要求的可用模块，它们相对容易编写和集成，因此 Ansible 能够适应您可能拥有或想要构建的几乎任何基础设施。在底层，Ansible 使用 Python 和 SSH 直接在目标主机上运行命令，但使用了一个更高级的**领域特定语言**（**DSL**），使得对比直接通过类似 Bash 的方式编写 SSH 命令，编写服务器配置对某人来说非常容易和快速。

当前的 Ubuntu LTS 版本（16.04）带有 Ansible 2.0.0.2，这对大多数情况来说应该是足够的，但通常建议使用更接近上游版本的版本，既可以修复错误，也可以添加新的模块。如果选择后者，请确保固定版本以确保一致的工作部署。

# 安装

要在大多数基于 Debian 的发行版上安装 Ansible，通常过程非常简单：

```
$ # Make sure we have an accurate view of repositories
$ sudo apt-get update 
<snip>
Fetched 3,971 kB in 22s (176 kB/s) 
Reading package lists... Done

$ # Install the package
$ sudo apt-get install ansible 
Reading package lists... Done
Building dependency tree 
Reading state information... Done
The following NEW packages will be installed:
 ansible
0 upgraded, 1 newly installed, 0 to remove and 30 not upgraded.
<snip>
Setting up ansible (2.0.0.2-2ubuntu1) ...

$ # Sanity check
$ ansible --version 
ansible 2.0.0.2
 config file = /home/user/checkout/eos-administration/ansible/ansible.cfg
 configured module search path = /usr/share/ansible
```

# 基础知识

项目的标准布局通常分为定义功能切片的角色，其余的配置基本上只是支持这些角色。Ansible 项目的基本文件结构看起来像这样（尽管通常需要更复杂的设置）：

```
.
├── group_vars
│   └── all
├── hosts
├── named-role-1-server.yml
└── roles
 ├── named-role-1
 │   ├── tasks
 │   │   └── main.yml
 │   ├── files
 │   │   └── ...
 │   ├── templates
 │   │   └── ...
 │   └── vars
 │       └── main.yml
 ...
```

让我们分解一下这个文件系统树的基本结构，并看看每个部分在更大的图景中是如何使用的：

+   `group_vars/all`：这个文件用于定义所有 playbooks 中使用的变量。这些变量可以在 playbooks 和模板中使用变量扩展（`"{{ variable_name }}"`）。

+   `hosts/`：这个文件或目录列出了您想要管理的主机和组，以及任何特定的连接细节，比如协议、用户名、SSH 密钥等。在文档中，这个文件通常被称为清单文件。

+   `roles/`：这里列出了可以以分层和分层方式应用于目标机器的角色定义列表。通常，它进一步细分为`tasks/`、`files/`、`vars/`和每个角色内的其他布局敏感结构：

+   `<role_name>/tasks/main.yml`：一个 YAML 文件，列出了作为角色一部分执行的主要步骤。

+   `<role_name>/files/...`：在这里，您将添加静态文件，这些文件将被复制到目标机器上，不需要任何预处理。

+   `<role_name>/templates/...`：在这个目录中，您将为与角色相关的任务添加模板文件。这些通常包含将带有变量替换的模板复制到目标机器上。

+   `<role_name>/vars/main.yml`：就像父目录暗示的那样，这个 YAML 文件保存了特定于角色的变量定义。

+   `playbooks/`：在这个目录中，您将添加所有顶层的辅助 playbooks，这些 playbooks 在角色定义中无法很好地适应。

# 用法

现在我们已经了解了 Ansible 的外观和操作方式，是时候用它做一些实际的事情了。我们现在要做的是创建一个 Ansible 部署配置，应用我们在上一章中介绍的一些系统调整，并在运行 playbook 后让 Docker 在机器上为我们准备好。

这个例子相对简单，但它应该很好地展示了一个体面的配置管理工具的易用性和强大性。Ansible 也是一个庞大的主题，像这样的一个小节无法覆盖我想要的那么详细，但文档相对不错，你可以在[`docs.ansible.com/ansible/latest/index.html`](https://docs.ansible.com/ansible/latest/index.html)找到它。如果你想跳过手工输入，可以在[`github.com/sgnn7/deploying_with_docker/tree/master/chapter_8/ansible_deployment`](https://github.com/sgnn7/deploying_with_docker/tree/master/chapter_8/ansible_deployment)找到这个例子（和其他例子）；然而，这可能是一个很好的练习，做一次以熟悉 Ansible 的 YAML 文件结构。

首先，我们需要为保存文件创建我们的文件结构。我们将称我们的主要角色为`swarm_node`，由于我们整个机器只是一个 swarm 节点，我们将把我们的顶层部署 playbook 命名为相同的名称：

```
$ # First we create our deployment source folder and move there
$ mkdir ~/ansible_deployment
$ cd ~/ansible_deployment/

$ # Next we create the directories we will need
$ mkdir -p roles/swarm_node/files roles/swarm_node/tasks

$ # Make a few placeholder files
$ touch roles/swarm_node/tasks/main.yml \
        swarm_node.yml \
        hosts

$ # Let's see what we have so far
$ tree
.
├── hosts
├── roles
│   └── swarm_node
│       ├── files
│       └── tasks
│           └── main.yml
└── swarm_node.yml
4 directories, 3 files
```

现在让我们将以下内容添加到顶层的`swarm_node.yml`。这将是 Ansible 的主入口点，它基本上只定义了目标主机和我们想要在它们上运行的角色：

```
---
- name: Swarm node setup
 hosts: all

 become: True

 roles:
 - swarm_node
```

YAML 文件是以空格结构化的，所以在编辑这个文件时要确保不要省略任何空格。一般来说，所有的嵌套级别都比父级多两个空格，键/值用冒号定义，列表用`-`（减号）前缀列出。有关 YAML 结构的更多信息，请访问[`en.wikipedia.org/wiki/YAML#Syntax`](https://en.wikipedia.org/wiki/YAML#Syntax)。

我们在这里做的大部分都是显而易见的：

+   `主机：所有`：在清单文件中定义的所有服务器上运行此命令。通常，这只是一个 DNS 名称，但由于我们只有一个单一的机器目标，`all`应该没问题。

+   `become: True`: 由于我们使用 SSH 在目标上运行命令，而 SSH 用户通常不是 root，我们需要告诉 Ansible 需要使用`sudo`提升权限来运行命令。如果用户需要密码来使用`sudo`，可以在调用 playbook 时使用`ansible-playbook -K`标志指定密码，但在本章后面我们将使用不需要密码的 AWS 实例。

+   `roles: swarm_mode`: 这是我们要应用于目标的角色列表，目前只有一个叫做`swarm_node`的角色。这个名称*必须*与`roles/`中的文件夹名称匹配。

接下来要定义的是我们在上一章中涵盖的系统调整配置文件，用于增加文件描述符最大值、ulimits 等。将以下文件及其相应内容添加到`roles/swarm_node/files/`文件夹中：

+   `conntrack.conf`:

```
net.netfilter.nf_conntrack_tcp_timeout_established = 43200
net.netfilter.nf_conntrack_max = 524288
```

+   `file-descriptor-increase.conf`:

```
fs.file-max = 1000000
```

+   `socket-buffers.conf`:

```
net.core.optmem_max = 40960
net.core.rmem_default = 16777216
net.core.rmem_max = 16777216
net.core.wmem_default = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 87380 16777216
```

+   `ulimit-open-files-increase.conf`:

```
root soft nofile 65536
root hard nofile 65536
* soft nofile 65536
* hard nofile 65536
```

添加这些文件后，我们的目录结构应该看起来更像这样：

```
.
├── hosts
├── roles
│   └── swarm_node
│       ├── files
│       │   ├── conntrack.conf
│       │   ├── file-descriptor-increase.conf
│       │   ├── socket-buffers.conf
│       │   └── ulimit-open-files-increase.conf
│       └── tasks
│           └── main.yml
└── swarm_node.yml
```

大部分文件已经就位，现在我们终于可以转向主配置文件--`roles/swarm_mode/tasks/main.yml`。在其中，我们将使用 Ansible 的模块和 DSL 逐步列出我们的配置步骤：

+   `apt-get dist-upgrade` 更新镜像以提高安全性

+   对机器配置文件进行各种改进，以便更好地作为 Docker 主机运行

+   安装 Docker

为了简化理解以下的 Ansible 配置代码，也可以记住这个结构，因为它是我们将使用的每个离散步骤的基础，并且在看到几次后很容易理解：

```
- name: A descriptive step name that shows in output
 module_name:
 module_arg1: arg_value
 module_arg2: arg2_value
 module_array_arg3:
 - arg3_item1
 ...
 ...
```

您可以在主 Ansible 网站上找到我们在 playbook 中使用的所有模块文档([`docs.ansible.com/ansible/latest/list_of_all_modules.html`](https://docs.ansible.com/ansible/latest/list_of_all_modules.html))。由于信息量巨大，我们将避免在此处深入研究模块文档，因为这通常会分散本节的目的。

您还可以在这里找到我们使用的特定模块的文档：

- [`docs.ansible.com/ansible/latest/apt_module.html`](https://docs.ansible.com/ansible/latest/apt_module.html)

- [`docs.ansible.com/ansible/latest/copy_module.html`](https://docs.ansible.com/ansible/latest/copy_module.html)

- [`docs.ansible.com/ansible/latest/lineinfile_module.html`](https://docs.ansible.com/ansible/latest/lineinfile_module.html)

- [`docs.ansible.com/ansible/latest/command_module.html`](https://docs.ansible.com/ansible/latest/command_module.html)

- [`docs.ansible.com/ansible/latest/apt_key_module.html`](https://docs.ansible.com/ansible/latest/apt_key_module.html)

- [`docs.ansible.com/ansible/latest/apt_repository_module.html`](https://docs.ansible.com/ansible/latest/apt_repository_module.html)

让我们看看主安装 playbook（`roles/swarm_mode/tasks/main.yml`）应该是什么样子的：

```
---
- name: Dist-upgrading the image
 apt:
 upgrade: dist
 force: yes
 update_cache: yes
 cache_valid_time: 3600

- name: Fixing ulimit through limits.d
 copy:
 src: "{{ item }}.conf"
 dest: /etc/security/limits.d/90-{{ item }}.conf
 with_items:
 - ulimit-open-files-increase

- name: Fixing ulimits through pam_limits
 lineinfile:
 dest: /etc/pam.d/common-session
 state: present
 line: "session required pam_limits.so"

- name: Ensuring server-like kernel settings are set
 copy:
 src: "{{ item }}.conf"
 dest: /etc/sysctl.d/10-{{ item }}.conf
 with_items:
 - socket-buffers
 - file-descriptor-increase
 - conntrack

# Bug: https://github.com/systemd/systemd/issues/1113
- name: Working around netfilter loading order
 lineinfile:
 dest: /etc/modules
 state: present
 line: "{{ item }}"
 with_items:
 - nf_conntrack_ipv4
 - nf_conntrack_ipv6

- name: Increasing max connection buckets
 command: echo '131072' > /sys/module/nf_conntrack/parameters/hashsize

# Install Docker
- name: Fetching Docker's GPG key
 apt_key:
 keyserver: hkp://pool.sks-keyservers.net
 id: 58118E89F3A912897C070ADBF76221572C52609D

- name: Adding Docker apt repository
 apt_repository:
 repo: 'deb https://apt.dockerproject.org/repo {{ ansible_distribution | lower }}-{{ ansible_distribution_release | lower }} main'
 state: present

- name: Installing Docker
 apt:
 name: docker-engine
 state: installed
 update_cache: yes
 cache_valid_time: 3600
```

警告！这个配置对于放在互联网上运行没有进行*任何*加固，所以在进行真正的部署之前，请小心并在这个 playbook 中添加任何您需要的安全步骤和工具。至少我建议安装`fail2ban`软件包，但您可能有其他策略（例如 seccomp、grsecurity、AppArmor 等）。

在这个文件中，我们按顺序一步一步地配置了机器，从基本配置到完全能够运行 Docker 容器的系统，使用了一些核心的 Ansible 模块和我们之前创建的配置文件。可能不太明显的一点是我们使用了`{{ ansible_distribution | lower }}`类型的变量，但在这些变量中，我们使用了有关我们正在运行的系统的 Ansible 事实（[`docs.ansible.com/ansible/latest/playbooks_variables.html`](https://docs.ansible.com/ansible/latest/playbooks_variables.html)），并通过 Ninja2 的`lower()`过滤器传递它们，以确保变量是小写的。通过对存储库端点执行此操作，我们可以在几乎任何基于 deb 的服务器目标上使用相同的配置而不会遇到太多麻烦，因为变量将被替换为适当的值。

在这一点上，我们需要做的唯一一件事就是将我们的服务器 IP/DNS 添加到`hosts`文件中，并使用`ansible-playbook <options> swarm_node.yml`运行 playbook。但由于我们想在亚马逊基础设施上运行这个，我们将在这里停下来，看看我们如何可以采取这些配置步骤，并从中创建一个**亚马逊机器映像**（**AMI**），在这个映像上我们可以启动任意数量的**弹性计算云**（**EC2**）实例，这些实例是相同的，并且已经完全配置好了。

# 亚马逊网络服务设置

要继续进行我们的 Amazon Machine Image (AMI)构建部分，我们必须先拥有一个可用的 AWS 账户和一个关联的 API 密钥，然后才能继续。为避免歧义，请注意几乎所有 AWS 服务都需要付费使用，您使用 API 可能会为您产生费用，即使是您可能没有预期的事情（如带宽使用、AMI 快照存储等），所以请谨慎使用。

AWS 是一个非常复杂的机器，比 Ansible 复杂得多，覆盖关于它的所有内容是不可能在本书的范围内完成的。但我们会在这里尽量为您提供足够相关的指导，让您有一个起点。如果您决定想了解更多关于 AWS 的信息，他们的文档通常非常好，您可以在[`aws.amazon.com/documentation/`](https://aws.amazon.com/documentation/)找到。

# 创建一个账户

虽然这个过程非常简单，但它已经在很多重要的方面发生了一些变化，因此在这里详细介绍整个过程并无法更新，这对您来说是一种伤害，所以为了创建账户，我将引导您到具有最新信息的链接，该链接是[`aws.amazon.com/premiumsupport/knowledge-center/create-and-activate-aws-account/`](https://aws.amazon.com/premiumsupport/knowledge-center/create-and-activate-aws-account/)。一般来说，这个过程的开始是在[`aws.amazon.com/`](https://aws.amazon.com/)，您可以通过单击屏幕右上角的黄色注册或创建 AWS 账户按钮并按照说明进行操作：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/ee360b0d-e6ef-4cf5-a704-a3c19f28462d.png)

# 获取 API 密钥

创建了 AWS 账户后，我们现在需要获取 API 密钥，以便通过我们想要使用的各种工具访问和使用资源：

1.  通过转到`https://<account_id or alias>.signin.aws.amazon.com/console`登录您的控制台。请注意，您可能需要最初以根账户身份登录（如下截图所示，在登录按钮下方有一个小蓝色链接），如果您注册账户时没有创建用户：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/96e3d45c-e762-42df-8171-8ab7a21c4019.png)

1.  转到 IAM 页面[`console.aws.amazon.com/iam/`](https://console.aws.amazon.com/iam/)，并单击屏幕左侧的用户链接。

1.  单击“添加用户”以开始用户创建过程。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/3e2af10f-fe45-4a06-9abe-37a6f98ca761.png)注意！确保选中“程序化访问”复选框，否则您的 AWS API 密钥将无法用于我们的示例。

1.  对于权限，我们将为该用户提供完整的管理员访问权限。对于生产服务，您将希望将其限制为所需的访问级别：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/b06d52c2-375d-47c6-b148-efebf348b7e0.png)

1.  按照向导的其余部分，并记录密钥 ID 和密钥秘钥，因为这些将是您的 AWS API 凭据：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/11fc7117-065e-4978-afc3-a37968ccbbcc.png)

# 使用 API 密钥

为了以最简单的方式使用 API 密钥，您可以在 shell 中导出变量，这些变量将被工具接收；但是，您需要在使用 AWS API 的每个终端上执行此操作：

```
$ export AWS_ACCESS_KEY_ID="AKIABCDEFABCDEF"
$ export AWS_SECRET_ACCESS_KEY="123456789ABCDEF123456789ABCDEF"
$ export AWS_REGION="us-west-1"
```

或者，如果您已安装`awscli`工具（`sudo apt-get install awscli`），您可以直接运行`aws configure`：

```
$ aws configure
AWS Access Key ID [None]: AKIABCDEFABCEF
AWS Secret Access Key [None]: 123456789ABCDEF123456789ABCDEF
Default region name [None]: us-west-1
Default output format [None]: json
```

还有许多其他设置凭据的方法，例如通过配置文件，但这确实取决于您的预期使用情况。有关这些选项的更多信息，您可以参考官方文档[`docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html`](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html)。

有了可用并配置为 CLI 使用的密钥，我们现在可以继续使用 Packer 构建自定义 AMI 镜像。

# HashiCorp Packer

正如我们之前所暗示的，如果我们必须在每次将新机器添加到集群或云基础架构中时运行 CM 脚本，那么我们的 CM 脚本实际上并不那么理想。虽然我们可以这样做，但我们真的不应该这样做，因为在理想的情况下，集群节点应该是一个灵活的群组，可以根据使用情况生成和销毁实例，最大程度地减少用户干预，因此要求手动设置每台新机器甚至在最小的集群规模下都是不可行的。通过 AMI 镜像创建，我们可以在制作镜像时预先制作一个带有 Ansible 的模板基本系统镜像。通过这样做，我们可以使用相同的镜像启动任何新机器，并且我们与运行中的系统的交互将被保持在最低限度，因为理想情况下一切都应该已经配置好。

为了创建这些机器映像，HashiCorp Packer ([`www.packer.io/`](https://www.packer.io/)) 允许我们通过应用我们选择的 CM 工具（Ansible）的配置运行，并为任何大型云提供商输出一个可供使用的映像。通过这样做，您可以将集群节点（或任何其他服务器配置）的期望状态永久地记录在映像中，对于集群的任何节点添加需求，您只需要基于相同的 Packer 映像生成更多的 VM 实例。

# 安装

由于 Packer 是用 Go 编程语言编写的，要安装 Packer，您只需要从他们的网站[`www.packer.io/downloads.html`](https://www.packer.io/downloads.html)下载二进制文件。通常可以通过以下方式快速安装：

```
$ # Get the archive
$ wget -q --show-progress https://releases.hashicorp.com/packer/1.1.1/packer_<release>.zip
packer_<release>.zip 100%[==============================================>] 15.80M 316KB/s in 40s

$ # Extract our binary
$ unzip packer_<release>.zip
Archive: packer_<release>.zip
 inflating: packer

$ # Place the binary somewhere in your path
$ sudo mv packer /usr/local/bin/

$ packer --version
1.1.1
```

注意！Packer 二进制文件仅为其运行程序提供 TLS 身份验证，而没有任何形式的签名检查，因此，与 Docker 使用的 GPG 签名的`apt`存储库相比，程序由 HashiCorp 自己发布的保证要低得多；因此，在以这种方式获取它或从源代码构建时，请格外小心（[`github.com/hashicorp/packer`](https://github.com/hashicorp/packer)）。

# 用法

在大多数情况下，使用 Packer 实际上相当容易，因为您只需要 Ansible 设置代码和一个相对较小的`packer.json`文件。将此内容添加到我们在早期部分的 Ansible 部署配置中的`packer.json`中：

```
{
  "builders": [
    {
      "ami_description": "Cluster Node Image",
      "ami_name": "cluster-node",
      "associate_public_ip_address": true,
      "force_delete_snapshot": true,
      "force_deregister": true,
      "instance_type": "m3.medium",
      "region": "us-west-1",
      "source_ami": "ami-1c1d217c",
      "ssh_username": "ubuntu",
      "type": "amazon-ebs"
    }
  ],
  "provisioners": [
    {
      "inline": "sudo apt-get update && sudo apt-get install -y ansible",
      "type": "shell"
    },
    {
      "playbook_dir": ".",
      "playbook_file": "swarm_node.yml",
      "type": "ansible-local"
    }
  ]
}
```

如果不明显，我们在此配置文件中有`provisioners`和`builders`部分，它们通常对应于 Packer 的输入和输出。在我们之前的示例中，我们首先通过`shell` provisioner 安装 Ansible，因为下一步需要它，然后使用`ansible-local` provisioner 在基本 AMI 上运行我们当前目录中的`main.yml` playbook。应用所有更改后，我们将结果保存为新的**弹性块存储**（**EBS**）优化的 AMI 映像。

AWS **弹性块存储**（**EBS**）是一项为 EC2 实例提供块设备存储的服务（这些实例基本上只是虚拟机）。对于机器来说，这些看起来像是常规的硬盘，可以格式化为任何你想要的文件系统，并用于在亚马逊云中以永久方式持久化数据。它们具有可配置的大小和性能级别；然而，正如你可能期望的那样，随着这两个设置的增加，价格也会上涨。唯一需要记住的另一件事是，虽然你可以像移动物理磁盘一样在 EC2 实例之间移动驱动器，但你不能跨可用性区域移动 EBS 卷。一个简单的解决方法是复制数据。"AMI 镜像"短语扩展为"Amazon Machine Image image"，这是一个非常古怪的表达方式，但就像姐妹短语"PIN number"一样，在本节中使用这种方式会更流畅。如果你对英语语言的这种特殊性感到好奇，你可以查阅 RAS 综合症的维基页面[`en.wikipedia.org/wiki/RAS_syndrome`](https://en.wikipedia.org/wiki/RAS_syndrome)。

对于构建器部分，更详细地解释一些参数将会很有帮助，因为它们可能并不明显，无法从 JSON 文件中直接看出来：

```
- type: What type of image are we building (EBS-optimized one in our case).
- region: What region will this AMI build in.
- source_ami: What is our base AMI? See section below for more info on this.
- instance_type: Type of instance to use when building the AMI - bigger machine == faster builds.
- ami_name: Name of the AMI that will appear in the UI.
- ami_description: Description for the AMI.
- ssh_username: What username to use to connect to base AMI. For Ubuntu, this is usually "ubuntu".
- associate_public_ip_address: Do we want this builder to have an external IP. Usually this needs to be true.
- force_delete_snapshot: Do we want to delete the old block device snapshot if same AMI is rebuilt?
- force_deregister: Do we want to replace the old AMI when rebuilding?
```

您可以在[`www.packer.io/docs/builders/amazon-ebs.html`](https://www.packer.io/docs/builders/amazon-ebs.html)找到有关此特定构建器类型及其可用选项的更多信息。

# 选择正确的 AMI 基础镜像

与我们在早期章节中介绍的选择要扩展的基础 Docker 镜像不同，选择正确的 AMI 来在 Packer 上使用是一个不简单的任务。一些发行版经常更新，因此 ID 会发生变化。ID 也是每个 AWS 区域独一无二的，您可能需要硬件或半虚拟化（`HVM` vs `PV`）。除此之外，您还需要根据您的存储需求选择正确的存储类型（在撰写本书时为`instance-store`、`ebs`和`ebs-ssd`），这创建了一个绝对不直观的选项矩阵。

如果您没有使用过 Amazon **弹性计算云**（**EC2**）和 EBS，存储选项对新手来说可能有点令人困惑，但它们的含义如下：

+   `instance-store`：这种存储类型是本地的 EC2 VM，空间取决于 VM 类型（尽管通常很少），并且在 VM 终止时完全丢弃（停止或重新启动的 VM 保留其状态）。实例存储非常适合不需要保留任何状态的节点，但不应该用于希望保留数据的机器；但是，如果您想要持久存储并且利用无状态存储，您可以独立地将单独的 EBS 驱动器挂载到实例存储 VM 上。

+   `ebs`：每当使用特定镜像启动 EC2 实例时，此存储类型将创建并关联由旧的磁性旋转硬盘支持的 EBS 卷，因此数据始终保留。如果您想要持久保存数据或`instance-store`卷不够大，这个选项很好。不过，截至今天，这个选项正在被积极弃用，因此很可能在未来会消失。

+   `ebs-ssd`：这个选项基本上与前面的选项相同，但使用**固态设备**（SSD），速度更快，但每 GB 分配的成本更高。

我们需要选择的另一件事是虚拟化类型：

+   半虚拟化/`pv`：这种虚拟化比较老，使用软件来链式加载您的镜像，因此能够在更多样化的硬件上运行。虽然很久以前它比较快，但今天通常比硬件虚拟化慢。

+   硬件虚拟化/`hvm`：这种虚拟化使用 CPU 级指令在完全隔离的环境中运行您的镜像，类似于直接在裸机硬件上运行镜像。虽然它取决于特定的英特尔 VT CPU 技术实现，但通常比`pv`虚拟化性能更好，因此在大多数情况下，您应该优先使用它而不是其他选项，特别是如果您不确定选择哪个选项。

有了我们对可用选项的新知识，我们现在可以确定我们将使用哪个镜像作为基础。对于我们指定的操作系统版本（Ubuntu LTS），您可以使用辅助页面在[`cloud-images.ubuntu.com/locator/ec2/`](https://cloud-images.ubuntu.com/locator/ec2/)找到合适的镜像：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/c078e660-0b39-4cfc-a458-246a2aed150e.png)

对于我们的测试构建，我们将使用`us-west-1`地区，Ubuntu 16.04 LTS 版本（`xenial`），64 位架构（`amd64`），`hvm`虚拟化和`ebs-ssd`存储，以便我们可以使用页面底部的过滤器来缩小范围：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/a4fe9542-6e35-4fd1-a9f5-5aa1cfc6dd6d.png)

正如您所看到的，列表收缩到一个选择，在我们的`packer.json`中，我们将使用`ami-1c1d217c`。

由于此列表更新了具有更新的安全补丁的 AMI，很可能在您阅读本节时，AMI ID 在您的端上将是其他值。因此，如果您看到我们在这里找到的值与您在阅读本章时可用的值之间存在差异，请不要感到惊讶。

# 构建 AMI

警告！运行此 Packer 构建肯定会在您的 AWS 帐户上产生一些（尽管在撰写本书时可能只有几美元）费用，因为使用了非免费实例类型、快照使用和 AMI 使用，有可能是一些重复的费用。请参考 AWS 的定价文档来估算您将被收取的金额。另外，清理掉您在 AWS 对象上完成工作后不会保留的一切，也是一个良好的做法，因为这将确保您在使用此代码后不会产生额外的费用。有了`packer.json`，我们现在可以构建我们的镜像。我们将首先安装先决条件（`python-boto`和`awscli`），然后检查访问权限，最后构建我们的 AMI：

```
$ # Install python-boto as it is a prerequisite for Amazon builders
$ # Also get awscli to check if credentials have been set correctly
$ sudo apt-get update && sudo apt-get install -y python-boto awscli
<snip>

$ # Check that AWS API credentials are properly set. 
$ # If you see errors, consult the previous section on how to do this
$ aws ec2 describe-volumes 
{
 "Volumes": [
 ]
}

$ # Go to the proper directory if we are not in it
$ cd ~/ansible_deployment

$ # Build our AMI and use standardized output format
$ packer build -machine-readable packer.json 
<snip>
1509439711,,ui,say,==> amazon-ebs: Provisioning with shell script: /tmp/packer-shell105349087
<snip>
1509439739,,ui,message, amazon-ebs: Setting up ansible (2.0.0.2-2ubuntu1) ...
1509439741,,ui,message, amazon-ebs: Setting up python-selinux (2.4-3build2) ...
1509439744,,ui,say,==> amazon-ebs: Provisioning with Ansible...
1509439744,,ui,message, amazon-ebs: Uploading Playbook directory to Ansible staging directory...
<snip>
1509439836,,ui,message, amazon-ebs: TASK [swarm_node : Installing Docker] ****************************************
1509439855,,ui,message, amazon-ebs: [0;33mchanged: [127.0.0.1]0m
1509439855,,ui,message, amazon-ebs:
1509439855,,ui,message, amazon-ebs: PLAY RECAP *******************************************************************
1509439855,,ui,message, amazon-ebs: [0;33m127.0.0.1[0m : [0;32mok[0m[0;32m=[0m[0;32m10[0m [0;33mchanged[0m[0;33m=[0m[0;33m9[0m unreachable=0 failed=0
1509439855,,ui,message, amazon-ebs:
1509439855,,ui,say,==> amazon-ebs: Stopping the source instance...
<snip>
1509439970,,ui,say,Build 'amazon-ebs' finished.
1509439970,,ui,say,--> amazon-ebs: AMIs were created:\nus-west-1: ami-a694a8c6\n
```

成功！通过这个新的镜像 ID（您可以在输出的末尾看到`ami-a694a8c6`），我们现在可以在 EC2 中使用这个 AMI 启动实例，并且它们将具有我们应用的所有调整以及预安装的 Docker！

# 部署到 AWS

只有裸露的镜像，没有虚拟机来运行它们，我们之前的 Packer 工作还没有完全实现自动化工作状态。为了真正实现这一点，我们现在需要用更多的 Ansible 粘合剂将所有东西联系在一起，以完成部署。不同阶段的封装层次应该在概念上看起来像这样：

![

从图表中可以看出，我们将采取分层的方法进行部署：

+   在最内层，我们有 Ansible 脚本，将裸机、虚拟机或 AMI 转换为我们想要的配置状态。

+   Packer 封装了该过程，并生成了静态 AMI 镜像，这些镜像可以进一步在 Amazon EC2 云服务上使用。

+   然后，Ansible 最终通过部署使用那些静态的、由 Packer 创建的镜像来封装之前提到的一切。

# 自动化基础设施部署的道路

现在我们知道我们想要什么，我们该如何做呢？幸运的是，如前面的列表所示，Ansible 可以为我们完成这部分工作；我们只需要编写一些配置文件。但是，由于 AWS 在这里非常复杂，所以它不会像只启动一个实例那样简单，因为我们想要一个隔离的 VPC 环境。但是，由于我们只管理一个服务器，我们对 VPC 之间的网络连接并不是很在意，所以这会让事情变得简单一些。

首先，我们需要考虑所有所需的步骤。其中一些对大多数人来说可能非常陌生，因为 AWS 相当复杂，大多数开发人员通常不会在网络上工作，但这些是必需的步骤，以便在不破坏帐户的默认设置的情况下拥有一个隔离的 VPC：

+   为特定虚拟网络设置 VPC。

+   创建并将子网绑定到它。如果没有这个，我们的机器将无法在上面使用网络。

+   设置虚拟互联网网关并将其附加到 VPC，以便使用路由表解析地址。如果我们不这样做，机器将无法使用互联网。

+   设置一个安全组（防火墙）白名单，列出我们希望能够访问我们服务器的端口（SSH 和 HTTP 端口）。默认情况下，所有端口都被阻止，因此这可以确保启动的实例是可访问的。

+   最后，使用配置的 VPC 进行网络设置来提供 VM 实例。

要拆除所有内容，我们需要做同样的事情，只是相反。

首先，我们需要一些变量，这些变量将在部署和拆除 playbooks 之间共享。在与本章中我们一直在使用的大型 Ansible 示例相同的目录中创建一个`group_vars/all`文件：

```
# Region that will accompany all AWS-related module usages
aws_region: us-west-1

# ID of our Packer-built AMI
cluster_node_ami: ami-a694a8c6

# Key name that will be used to manage the instances. Do not
# worry about what this is right now - we will create it in a bit
ssh_key_name: swarm_key

# Define the internal IP network for the VPC
swarm_vpc_cidr: "172.31.0.0/16"
```

现在我们可以在与`packer.json`相同的目录中编写我们的`deploy.yml`，并使用其中一些变量：

这种部署的困难程度从我们之前的示例中显著增加，并且没有很好的方法来涵盖分散在数十个 AWS、网络和 Ansible 主题之间的所有信息，以简洁的方式描述它，但是这里有一些我们将使用的模块的链接，如果可能的话，您应该在继续之前阅读：

- [`docs.ansible.com/ansible/latest/ec2_vpc_net_module.html`](https://docs.ansible.com/ansible/latest/ec2_vpc_net_module.html)

- [`docs.ansible.com/ansible/latest/set_fact_module.html`](https://docs.ansible.com/ansible/latest/set_fact_module.html)

- [`docs.ansible.com/ansible/latest/ec2_vpc_subnet_module.html`](https://docs.ansible.com/ansible/latest/ec2_vpc_subnet_module.html)

- [`docs.ansible.com/ansible/latest/ec2_vpc_igw_module.html`](https://docs.ansible.com/ansible/latest/ec2_vpc_igw_module.html)

- [`docs.ansible.com/ansible/latest/ec2_vpc_route_table_module.html`](https://docs.ansible.com/ansible/latest/ec2_vpc_route_table_module.html)

- [`docs.ansible.com/ansible/latest/ec2_group_module.html`](https://docs.ansible.com/ansible/latest/ec2_group_module.html)

- [`docs.ansible.com/ansible/latest/ec2_module.html`](https://docs.ansible.com/ansible/latest/ec2_module.html)

```
- hosts: localhost
 connection: local
 gather_facts: False

 tasks:
 - name: Setting up VPC
 ec2_vpc_net:
 region: "{{ aws_region }}"
 name: "Swarm VPC"
 cidr_block: "{{ swarm_vpc_cidr }}"
 register: swarm_vpc

 - set_fact:
 vpc: "{{ swarm_vpc.vpc }}"

 - name: Setting up the subnet tied to the VPC
 ec2_vpc_subnet:
 region: "{{ aws_region }}"
 vpc_id: "{{ vpc.id }}"
 cidr: "{{ swarm_vpc_cidr }}"
 resource_tags:
 Name: "Swarm subnet"
 register: swarm_subnet

 - name: Setting up the gateway for the VPC
 ec2_vpc_igw:
 region: "{{ aws_region }}"
 vpc_id: "{{ vpc.id }}"
 register: swarm_gateway

 - name: Setting up routing table for the VPC network
 ec2_vpc_route_table:
 region: "{{ aws_region }}"
 vpc_id: "{{ vpc.id }}"
 lookup: tag
 tags:
 Name: "Swarm Routing Table"
 subnets:
 - "{{ swarm_subnet.subnet.id }}"
 routes:
 - dest: 0.0.0.0/0
 gateway_id: "{{ swarm_gateway.gateway_id }}"

 - name: Setting up security group / firewall
 ec2_group:
 region: "{{ aws_region }}"
 name: "Swarm SG"
 description: "Security group for the swarm"
 vpc_id: "{{ vpc.id }}"
 rules:
 - cidr_ip: 0.0.0.0/0
 proto: tcp
 from_port: 22
 to_port: 22
 - cidr_ip: 0.0.0.0/0
 proto: tcp
 from_port: 80
 to_port: 80
 rules_egress:
 - cidr_ip: 0.0.0.0/0
 proto: all
 register: swarm_sg

 - name: Provisioning cluster node
 ec2:
 region: "{{ aws_region }}"
 image: "{{ cluster_node_ami }}"
 key_name: "{{ ssh_key_name }}"
 instance_type: "t2.medium"
 group_id: "{{ swarm_sg.group_id }}"
 vpc_subnet_id: "{{ swarm_subnet.subnet.id }}"
 source_dest_check: no
 assign_public_ip: yes
 monitoring: no
 instance_tags:
 Name: cluster-node
 wait: yes
 wait_timeout: 500
```

我们在这里所做的与我们之前的计划非常相似，但现在我们有具体的部署代码与之匹配：

1.  我们使用`ec2_vpc_net`模块设置 VPC。

1.  我们使用`ec2_vpc_subnet`模块创建子网并将其关联到 VPC。

1.  为我们的云创建 Internet 虚拟网关使用`ec2_vpc_igw`。

1.  然后创建 Internet 网关以解析不在同一网络中的任何地址。

1.  使用`ec2_group`模块启用入站和出站网络，但只允许端口`22`（SSH）和端口`80`（HTTP）。

1.  最后，我们的 EC2 实例是在新配置的 VPC 中使用`ec2`模块创建的。

正如我们之前提到的，拆除应该非常类似，但是相反，并包含更多的`state: absent`参数。让我们把以下内容放在同一个文件夹中的`destroy.yml`中：

```
- hosts: localhost
 connection: local
 gather_facts: False

 tasks:
 - name: Finding VMs to delete
 ec2_remote_facts:
 region: "{{ aws_region }}"
 filters:
 "tag:Name": "cluster-node"
 register: deletable_instances

 - name: Deleting instances
 ec2:
 region: "{{ aws_region }}"
 instance_ids: "{{ item.id }}"
 state: absent
 wait: yes
 wait_timeout: 600
 with_items: "{{ deletable_instances.instances }}"
 when: deletable_instances is defined

 # v2.0.0.2 doesn't have ec2_vpc_net_facts so we have to fake it to get VPC info
 - name: Finding route table info
 ec2_vpc_route_table_facts:
 region: "{{ aws_region }}"
 filters:
 "tag:Name": "Swarm Routing Table"
 register: swarm_route_table

 - set_fact:
 vpc: "{{ swarm_route_table.route_tables[0].vpc_id }}"
 when: swarm_route_table.route_tables | length > 0

 - name: Removing security group
 ec2_group:
 region: "{{ aws_region }}"
 name: "Swarm SG"
 state: absent
 description: ""
 vpc_id: "{{ vpc }}"
 when: vpc is defined

 - name: Deleting gateway
 ec2_vpc_igw:
 region: "{{ aws_region }}"
 vpc_id: "{{ vpc }}"
 state: absent
 when: vpc is defined

 - name: Deleting subnet
 ec2_vpc_subnet:
 region: "{{ aws_region }}"
 vpc_id: "{{ vpc }}"
 cidr: "{{ swarm_vpc_cidr }}"
 state: absent
 when: vpc is defined

 - name: Deleting route table
 ec2_vpc_route_table:
 region: "{{ aws_region }}"
 vpc_id: "{{ vpc }}"
 state: absent
 lookup: tag
 tags:
 Name: "Swarm Routing Table"
 when: vpc is defined

 - name: Deleting VPC
 ec2_vpc_net:
 region: "{{ aws_region }}"
 name: "Swarm VPC"
 cidr_block: "{{ swarm_vpc_cidr }}"
 state: absent
```

如果部署 playbook 可读，则该 playbook 应该很容易理解，正如我们所提到的，它只是以相反的方式运行相同的步骤，删除我们已经创建的任何基础设施部分。

# 运行部署和拆除 playbooks

如果您还记得，在我们的`group_vars`定义中，我们有一个关键变量（`ssh_key_name: swarm_key`），在这一点上变得相对重要，因为没有工作密钥，我们既不能部署也不能启动我们的 VM，所以现在让我们这样做。我们将使用`awscli`和`jq`--一个 JSON 解析工具，它将减少我们的工作量，但也可以通过 GUI 控制台完成。

```
$ # Create the key with AWS API and save the private key to ~/.ssh directory
$ aws ec2 create-key-pair --region us-west-1 \
 --key-name swarm_key | jq -r '.KeyMaterial' > ~/.ssh/ec2_swarm_key

$ # Check that its not empty by checking the header
$ head -1 ~/.ssh/ec2_swarm_key 
-----BEGIN RSA PRIVATE KEY-----

$ # Make sure that the permissions are correct on it
$ chmod 600 ~/.ssh/ec2_swarm_key

$ # Do a sanity check that it has the right size and permissions
$ ls -la ~/.ssh/ec2_swarm_key
-rw------- 1 sg sg 1671 Oct 31 16:52 /home/sg/.ssh/ec2_swarm_key
```

将密钥放置后，我们终于可以运行我们的部署脚本：

```
$ ansible-playbook deploy.yml 
 [WARNING]: provided hosts list is empty, only localhost is available

PLAY *************************************************************************

TASK [Setting up VPC] ********************************************************
ok: [localhost]

TASK [set_fact] **************************************************************
ok: [localhost]

TASK [Setting up the subnet] *************************************************
ok: [localhost]

TASK [Setting up the gateway] ************************************************
ok: [localhost]

TASK [Setting up routing table] **********************************************
ok: [localhost]

TASK [Setting up security group] *********************************************
ok: [localhost]

TASK [Provisioning cluster node] *********************************************
changed: [localhost]

PLAY RECAP *******************************************************************
localhost : ok=7 changed=1 unreachable=0 failed=0 

$ # Great! It looks like it deployed the machine! 
$ # Let's see what we have. First we need to figure out what the external IP is
$ aws ec2 describe-instances --region us-west-1 \
 --filters Name=instance-state-name,Values=running \
 --query 'Reservations[*].Instances[*].PublicIpAddress'
[
 [
 "52.53.240.17"
 ]
]

$ # Now let's try connecting to it
ssh -i ~/.ssh/ec2_swarm_key ubuntu@52.53.240.17 
<snip>
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '52.53.240.17' (ECDSA) to the list of known hosts.
<snip>

ubuntu@ip-172-31-182-20:~$ # Yay! Do we have Docker?
ubuntu@ip-172-31-182-20:~$ sudo docker ps
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES

ubuntu@ip-172-31-182-20:~$ # Create our single-server swarm
ubuntu@ip-172-31-182-20:~$ sudo docker swarm init
Swarm initialized: current node (n2yc2tedm607rvnjs72fjgl1l) is now a manager.
<snip>

ubuntu@ip-172-31-182-20:~$ # Here we can now do anything else that's needed
ubuntu@ip-172-31-182-20:~$ # Though you would normally automate everything
```

如果您看到类似于`"没有处理程序准备好进行身份验证。已检查 1 个处理程序。['HmacAuthV4Handler']检查您的凭据"`的错误，请确保您已正确设置 AWS 凭据。

看起来一切都在运行！在这一点上，如果我们愿意，我们可以部署我们之前构建的三层应用程序。由于我们已经完成了我们的示例，并且我们的迷你 PaaS 正在运行，我们可以返回并通过运行`destroy.yml` playbook 来清理事务：

```
ubuntu@ip-172-31-182-20:~$ # Get out of our remote machine
ubuntu@ip-172-31-182-20:~$ exit
logout
Connection to 52.53.240.17 closed.

$ # Let's run the cleanup script
ansible-playbook destroy.yml 
 [WARNING]: provided hosts list is empty, only localhost is available

PLAY *************************************************************************

TASK [Finding VMs to delete] *************************************************
ok: [localhost]

TASK [Deleting instances] ****************************************************
changed: [localhost] => <snip>

TASK [Finding route table info] **********************************************
ok: [localhost]

TASK [set_fact] **************************************************************
ok: [localhost]

TASK [Removing security group] ***********************************************
changed: [localhost]

TASK [Deleting gateway] ******************************************************
changed: [localhost]

TASK [Deleting subnet] *******************************************************
changed: [localhost]

TASK [Deleting route table] **************************************************
changed: [localhost]

TASK [Deleting VPC] **********************************************************
changed: [localhost]

PLAY RECAP *******************************************************************
localhost : ok=9 changed=6 unreachable=0 failed=0 

```

有了这个，我们可以使用单个命令自动部署和拆除我们的基础架构。虽然这个例子的范围相当有限，但它应该能给你一些关于如何通过自动扩展组、编排管理 AMI、注册表部署和数据持久化来扩展的想法。

# 持续集成/持续交付

随着您创建更多的服务，您会注意到来自源代码控制和构建的手动部署需要更多的时间，因为需要弄清楚哪些图像依赖关系属于哪里，哪个图像实际上需要重建（如果您运行的是单一存储库），服务是否发生了任何变化，以及许多其他辅助问题。为了简化和优化我们的部署过程，我们需要找到一种方法，使整个系统完全自动化，以便部署新版本的服务所需的唯一事情是提交代码存储库分支的更改。

截至今天，名为 Jenkins 的最流行的自动化服务器通常用于进行构建自动化和 Docker 镜像和基础架构的部署，但其他工具如 Drone、Buildbot、Concoure 等也在非常有能力的软件 CI/CD 工具排行榜上迅速上升，但迄今为止还没有达到行业的同等接受水平。由于 Jenkins 相对容易使用，我们可以快速演示其功能，虽然这个例子有点简单，但它应该很明显地表明了它可以用于更多的用途。

由于 Jenkins 将需要`awscli`、Ansible 和`python-boto`，我们必须基于 Docker Hub 上可用的 Jenkins 创建一个新的 Docker 镜像。创建一个新文件夹，并在其中添加一个`Dockerfile`，内容如下：

```
FROM jenkins

USER root
RUN apt-get update && \
 apt-get install -y ansible \
 awscli \
 python-boto

USER jenkins
```

现在我们构建并运行我们的服务器：

```
$ # Let's build our image
$ docker build -t jenkins_with_ansible 
Sending build context to Docker daemon 2.048kB
Step 1/4 : FROM jenkins
<snip>
Successfully tagged jenkins_with_ansible:latest

$ # Run Jenkins with a local volume for the configuration
$ mkdir jenkins_files
$ docker run -p 8080:8080 \
 -v $(pwd)/jenkins_files:/var/jenkins_home \
 jenkins_with_ansible

Running from: /usr/share/jenkins/jenkins.war
<snip>
Jenkins initial setup is required. An admin user has been created and a password generated.
Please use the following password to proceed to installation:

3af5d45c2bf04fffb88e97ec3e92127a

This may also be found at: /var/jenkins_home/secrets/initialAdminPassword
<snip>
INFO: Jenkins is fully up and running
```

在它仍在运行时，让我们转到主页并输入我们在镜像启动期间收到警告的安装密码。转到`http://localhost:8080`并输入日志中的密码：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/b92e7df8-9270-444e-ad56-3042aa188d7a.png)

在下一个窗口上点击“安装建议的插件”，然后在相关下载完成后，选择最后一个安装程序页面上的“以管理员身份继续”，这应该会带您到主要的登陆页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/e82e77e8-f006-4cb2-ba62-bdcaee9d5aa5.png)

点击“创建新作业”，命名为`redeploy_infrastructure`，并将其设置为自由风格项目。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/f90a1571-c515-4365-9c1d-80bdf33d8857.png)

接下来，我们将使用我们的 Git 存储库端点配置作业，以便在主分支上的任何提交上构建：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/6bb0475d-efd1-41d3-b071-a4f835c45f7a.png)

作为我们的构建步骤，当存储库触发器激活时，我们将销毁并部署基础设施，有效地用新版本替换它。添加一个新的**执行 Shell**类型的构建步骤，并添加以下内容：

```
# Export needed AWS credentials
export AWS_DEFAULT_REGION="us-west-1"
export AWS_ACCESS_KEY_ID="AKIABCDEFABCDEF"
export AWS_SECRET_ACCESS_KEY="123456789ABCDEF123456789ABCDEF"

# Change to relevant directory
cd chapter_8/aws_deployment

# Redeploy the service by cleaning up the old deployment
# and deploying a new one
ansible-playbook destroy.yml
ansible-playbook deploy.yml
```

工作应该看起来与这个相似：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/c56d4689-5abb-4777-b187-a2dc96a5b7fb.png)

保存更改并点击“保存”，这应该会带您到构建的主页。在这里，点击“立即构建”按钮，一旦构建出现在左侧构建列表中，点击其进度条或名称旁边的下拉菜单，并选择“查看日志”：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/f8092593-3a14-4fea-97d5-6050e1ba03a5.png)

成功！正如您所看到的，通过 Jenkins 和一些小的配置，我们刚刚实现了我们简单基础设施的自动部署。虽然粗糙但有效，通常情况下，您不希望重新部署所有内容，而只是更改了的部分，并且 Jenkins 生活在集群中，但这些都是一些更复杂的努力，将留给读者作为可能的改进点。

# 资源考虑

由于 Jenkins 在 Java 虚拟机上运行，它会以惊人的速度消耗可用的 RAM，并且通常是使用量最大的，也是我经验最丰富的**内存不足**（**OOM**）罪魁祸首。即使在最轻量的使用情况下，计划为 Jenkins 工作节点分配至少 1GB 的 RAM，否则可能在构建流水线的最不合时宜的阶段出现各种故障。一般规则是，目前大多数 Jenkins 安装将不会在分配给它们 2GB 的 RAM 时出现太多问题，但由于 VM 实例中 RAM 的价格，您可以尝试缩减规模，直到达到可接受的性能水平。

另外需要注意的最后一件事是，相对而言，Jenkins 镜像也是一个庞大的镜像，重达约 800 MB，因此请记住，移动这个容器并不像我们之前使用的一些其他工具那样容易或快速。

# 首次部署的循环依赖

在集群中使用 Jenkins 作为 Docker 化服务来链接构建所有其他镜像时，我需要提到一个常见的陷阱，即您将不可避免地在新部署中遇到问题，因为 Jenkins 最初不可用，因为在集群初始化阶段，注册表中通常没有镜像可用，并且默认的 Jenkins Docker 镜像没有进行任何配置。除此之外，由于您经常需要一个已运行的 Jenkins 实例来构建更新的 Jenkins 镜像，您将陷入经典的进退两难的境地。您可能会有一种本能去手动构建 Jenkins 作为后续部署步骤，但如果您真的想要拥有大部分无需干预的基础设施，您必须抵制这种冲动。

解决这个问题的一般方法通常是在干净的集群上引导 Jenkins，通常是如下图所示的方式：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/b5ffcb96-c3ad-4d99-ac8f-840034f3ea73.png)

首先进行集群部署，以确保我们有一种构建引导映像的方法，然后使用 Docker Registry 存储构建后的映像。随后，在任何可用的 Docker Engine 节点上构建 Jenkins 映像，并将其推送到注册表，以便服务将具有正确的映像来启动。如果需要，然后使用相同的配置管理工具（如 Ansible）或编排工具启动所述服务，并等待自动启动作业，该作业将构建所有其他剩余的映像，这些映像应填充注册表以运行完整的集群所需的所有其他映像。这里的基本思想是通过 CM 工具进行初始引导，然后让 Jenkins 服务重新构建所有其他映像并（重新）启动任务。

在大规模部署中，还可以使用集群编排来安排和处理此引导过程，而不是使用 CM 工具，但由于每个编排引擎之间存在巨大差异，这些步骤可能在它们之间大相径庭。

# 进一步的通用 CI/CD 用途

像 Jenkins 这样的良好的 CI 工具可以做的事情远不止我们在这里介绍的内容；它们都需要大量的时间和精力来使其正常工作，但如果您能够实施它们，其好处是非常显著的：

+   自构建：如前所述，当配置更改时，您可以让 Jenkins 构建自己的映像，并重新部署自己。

+   仅部署已更改的 Docker 映像：如果使用 Docker 缓存，您可以检查新构建是否创建了不同的映像哈希，并且仅在确实创建了不同的映像时部署。这样做将防止无谓的工作，并使您的基础设施始终运行最新的代码。

+   定时 Docker 清理：您可以在 Jenkins 上运行清理作业（或类似于`cron`的任何其他作业），以释放或管理您的 Docker 节点，以避免手动交互。

此列表还可以包括：自动发布、故障通知、构建跟踪，以及许多其他可以获得的东西，但可以说，您确实希望在任何非平凡的部署中都有一个可工作的 CI 流水线。

一个经验法则是，如果您需要手动完成某些可以通过一些定时器和 shell 脚本自动化的工作，大多数 CI 工具（如 Jenkins）都可以帮助您，所以不要害怕尝试不同和创造性的用法。通过本章中涵盖的一整套选项和其他工具，您可以放心地入睡，知道您的集群在一段时间内都不需要不断地看护。

# 摘要

在本章中，我们更多地介绍了如何真正部署 PaaS 基础架构以及为此所需的以下主题：使用 Ansible 进行配置管理工具化、使用 HashiCorp Packer 进行云镜像管理以及使用 Jenkins 进行持续集成。通过在这里获得的知识，您现在应该能够使用我们讨论过的各种工具，并为自己的服务部署创建自己的迷你 PaaS，再经过一些额外的工作，您可以将其转变为全面的 PaaS！

在下一章中，我们将看看如何将我们当前的 Docker 和基础架构工作扩大。我们还将探讨这个领域可能朝着什么方向发展，所以如果您想了解世界上最大规模的部署，敬请关注。


# 第九章：探索最大规模的部署

在前几章中，我们涵盖了部署 Docker 容器的许多不同方面，但是如果我们要将我们的例子转化为一个全球服务，能够承受每秒数百万请求的吞吐量，仍然有一些事情需要解决，这一章特别写作是为了详细讨论其中最重要的一些。由于这里涉及的主题实施将涉及足够的材料，可以单独成书，并且基础设施会根据多种因素大相径庭，因此这里的文本大部分将是理论性的，但是在本章之前我们对服务的理解应该足够好，可以给你一些关于如何以最少的痛苦进行下一步操作的想法。

在其核心，我们将要讨论的主题围绕选择合适的技术，然后遵循三个基本理念：

+   一切都要自动化！

+   真的，一切都要自动化！

+   是的，甚至自动化那些你每隔几周做一次的事情

这可能是一个玩笑，但希望到现在为止应该清楚，所有这些工作的主要目的之一（除了隔离）是从你的系统中消除任何人为干预，以保持你的服务运行，这样你和你的团队就可以专注于实际开发服务，而不是浪费时间在部署上。

# 维护法定人数

在我们之前的例子中，我们大多数时间都是使用单节点管理器，但是如果你想要弹性，你必须确保最小的故障点不会导致整个基础架构崩溃，而单个编排管理节点绝对不足以支持生产服务，无论你使用 Swarm、Kubernetes、Marathon 还是其他编排工具。从最佳实践的角度来看，你至少需要在集群中拥有三个或更多的管理节点，这些节点分布在云的三个或更多的**可用区**（**AZ**）或等效的分组中，以确保在规模上真正实现稳定性，因为数据中心的故障已经被证明会发生，并且给那些没有减轻这类情况的公司造成严重问题。

While in most orchestration platforms you can have any number of backing management nodes (or backing key-value stores in some cases), you will always have to balance resiliency vs speed due to the fact that with more nodes comes better capability to handle failures of larger parts of the system, but changes to this system (such as node additions and removals) must reach more points that will all have to agree, thus making it slower to process data. In most cases where this 3+ availability zone topology is required, we will need to go in details about quorums—the concept we lightly covered earlier, which is the backbone of all **high availability** (**HA**) systems.

Quorums in their basic sense are a grouping of the majority of management nodes, which together can decide whether updates to the cluster are going to be allowed or not. If the quorum is lost by the fact that half or more management nodes are unavailable, all changes to the cluster will be stopped to prevent your cluster infrastructure from having effectively split clusters. To properly divide your network topology for scale in this respect, you must make sure that you have a minimum of three nodes and/or availability zones as the quorum majority is lost with a single failure with less than that number. Taking this further, you will generally also want an odd number of nodes and availability zones since even numbers do not provide much additional protection for maintaining quorum, as we will see in a moment.

在大多数编排平台中，您可以拥有任意数量的后备管理节点（或在某些情况下是后备键值存储），但由于更多的节点意味着更好地处理系统更大部分的故障的能力，您总是必须在弹性和速度之间取得平衡，但对于这个系统的更改（如节点的添加和删除）必须达到更多的点，所有这些点都必须同意，因此处理数据的速度会变慢。在大多数需要 3 个或更多可用区域的拓扑结构中，我们需要详细了解法定人数——这是我们稍早轻描淡写提到的概念，它是所有**高可用性**（**HA**）系统的支柱。

To start off, let's say that you have five management nodes. To maintain a quorum of this number, you must have three or more nodes available, but if you have only two availability zones, the best split you can do is *3-2*, which will work fine if a connection is broken or the **AZ** with two management nodes goes down, but if the **AZ** with three nodes goes down, a quorum cannot be established since two is less than half of the total node count.

现在让我们看看在三个可用区域中我们可以获得什么样的弹性。使用五个管理节点的最佳布局将是*2-2-1*，如果你仔细观察任何一个区域失效时会发生什么，你会发现始终保持了法定人数，因为我们将从集群的其余部分获得*3 (2+1)*或*4 (2+2)*个节点，确保我们的服务运行正常：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/d0bb04d0-17b7-43d7-8740-b047fd872717.png)

当然，展示偶数对效果的影响也是很好的，因为我们提到它们可能有点麻烦。有了四个可用区域，我们可以做出的最佳分割是在它们之间进行*2-1-1-1*的分配，根据这些数字，我们只能容忍两个区域不可用，如果它们都只包含一个节点。通过这种设置，我们有一半的几率，即两个不可用的区域将包括其中有两个节点的区域，使得不可用的总节点数超过 3 个，因此集群将完全离线：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/8afaa925-f216-4b68-b3e6-58dc2560d26e.png)

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/f48bc1dc-a1b2-4515-b900-c8bf945aafb3.png)

对于集群中更多的可用区域和管理节点，跨更多可用区域的管理节点的分布会更加稳定，但是对于我们这里的简单示例，如果我们有五个管理节点和五个可用区域（*1-1-1-1-1*布局），我们可以看到这种效果。由于法定人数要求至少三个节点，如果五个区域中的任意两个不可用，我们仍将完全运行，从 3 个可用区域的拓扑结构中将故障容忍度提高了 100％；但是您可以假设可能在地理位置上相距很远的区域之间的通信会给任何更新增加大量的延迟。

希望通过这些例子，现在应该清楚了在尝试保持集群的弹性并且能够保持法定人数时，您将使用什么样的考虑和计算。虽然工具可能会有所不同，具体取决于编排工具（即`etcd`节点与 Zookeeper 节点），但原则在几乎所有情况下都是相对相同的，因此这一部分应该是相对可移植的。

# 节点自动化

当我们使用 Packer 制作 Amazon Machine Images（AMIs）时，我们已经看到了我们可以使用预先烘焙的实例映像做什么，但是只有当整个基础设施由它们组成时，它们的真正力量才能得到充分发挥。如果您的编排管理节点和工作节点有自己的系统映像，并且还有一些启动脚本通过 init 系统（例如，systemd 启动服务）烘焙进去，您可以使使用这些映像启动的实例在其预定义角色中在启动时自动加入到集群中。将这进一步提升到概念层面，如果我们将所有有状态的配置提取到映像配置中，将所有动态配置提取到一个对所有节点可访问的单独服务中，例如 EC2 `user-data`或 HashiCorp Vault，除了初始部署和映像构建之外，您的集群几乎完全自我配置。

通过拥有这种强大的自动加入功能，您可以消除与扩展集群的手动工作大部分相关的工作，因为除了启动它之外，无需与 VM 实例进行交互。这种架构的一个相当简单的示例如下图所示，其中编排和工作节点有各自的映像，并在启动时使用 VPC 内的共享配置数据提供程序进行自我配置：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/9fdaeb81-160f-41d5-bdd1-0e5b8aba0619.png)注意！为了防止严重的安全漏洞，请确保将任何敏感信息分离和隔离，只能由此配置服务布局中的所需系统访问。正如我们在早期的章节中提到的，通过使用需要知道的最佳实践，可以确保单个点（很可能是工作节点）的妥协不会轻易传播到集群的其余部分。举个简单的例子，这将包括确保管理秘密对工作节点或其网络不可读。

# 反应式自动扩展

通过实施自动化的自我配置，我们可以开始自动启动实例，从而实现更大规模的目标。如果你还记得之前章节中提到的自动扩展组，即使在大多数云服务中，这也可以实现自动化。通过使用启动配置和预配置的镜像，就像我们刚刚讨论的那样，使用这种设置添加或移除节点将变得像拨号设置所需节点一样简单。自动扩展组将增加或减少工作实例的数量，因为镜像是自我配置的，这将是你所需的全部输入。通过这样简单的输入，你可以轻松地对基础架构进行扩展，并通过许多不同的方式完成。

在进一步的自动化步骤中，有一些云服务提供商可以基于其指标或类似`cron`的计划来触发自动扩展组中的这些操作。原则上，如果你的集群负载增加，你可以触发节点计数的增加，反之，如果集群或单个节点的负载下降到预定义的值以下，你可以激活服务排水并关闭一部分节点来根据需要扩展系统。对于周期性但可预测的需求变化（参见[`en.wikipedia.org/wiki/Internet_Rush_Hour`](https://en.wikipedia.org/wiki/Internet_Rush_Hour)了解更多信息），我们提到的计划的扩展变化可以确保你有足够的资源来处理预期的需求。

# 预测性自动扩展

如果你手动调整节点计数并根据计划或指标触发自动扩展，你仍然会遇到一些问题，因为服务需要一些时间才能上线、自我配置，并开始传播到网络中的各种负载均衡器。在这种架构下，很可能是你的用户发现你没有足够的容量，然后你的系统做出反应来补偿。如果你真的希望从你的服务中获得最佳的用户体验，有时你可能还需要在自动扩展触发器中添加一层，可以在实际需要之前预测你的服务何时需要更多资源，这就是所谓的**预测性扩展**。

在非常广泛的范围内，要将预测层添加到基础架构中，您需要将过去`x`时间内收集的一些指标的一部分导入到诸如 TensorFlow（[`www.tensorflow.org/`](https://www.tensorflow.org/)）之类的**机器学习**（**ML**）工具中，并生成一个训练集，使该工具能够以一定的确定性预测您是否需要更多节点。通过使用这种方法，您的服务可以在需要之前就进行扩展，并且比简单的基于计划的方法更加智能。这些系统在正确整合到您的流水线中时可能会相当困难，但如果您正在全球范围内处理大量数据，并且简单的反应式自动扩展不足以满足需求，那么这可能是一个值得探索的途径。

在机器学习中，训练集指的只是一组训练数据（在我们的情况下，它将是我们长期指标的一部分），您可以使用它来教会神经网络如何正确预测您将需要的需求。就像最近章节中的许多主题一样，实际上有很多关于这个材料（机器学习）的书籍，它们的内容会远远超过这本书，并且对您的实用性也只会提供边际帮助。如果您想详细了解机器学习，这个维基百科页面对此有一个很好的入门介绍：[`en.wikipedia.org/wiki/Machine_learning`](https://en.wikipedia.org/wiki/Machine_learning)，您也可以在[`www.tensorflow.org/get_started/get_started`](https://www.tensorflow.org/get_started/get_started)上尝试 TensorFlow。

最终，如果您成功实施了这些技术中的一些或全部，您几乎不需要对集群进行任何干预，以处理扩展或收缩。作为能够安心入睡的额外奖励，您还将节省资源，因为您将能够将处理资源与服务的实际使用情况紧密匹配，使您、您的预算和您的用户都感到满意。

# 监控

您在服务交付中依赖的任何服务理想情况下都应该有一种方式来通知您它是否出现了问题，我指的不是用户反馈。大多数服务开发现在都以令人难以置信的速度发展，监控就像备份一样，大多数开发人员在发生灾难性事件之前都不会考虑，因此我们应该稍微涉及一下。真正应该决定您如何处理这个问题的重要问题是，如果您的用户能够处理您在没有监控的情况下看不到的停机时间。

大多数小型服务可能对一些中断没有太大问题，但对于其他所有情况，这至少会导致用户发来一些愤怒的电子邮件，最坏的情况是您的公司失去了大部分用户，因此强烈鼓励在各个规模上进行监控。

尽管监控可能被认为是基础设施中那些无聊的部分之一，但在任何时候都能获得对云端正在进行的工作的洞察力绝对是管理多样化系统和服务的绝对必要部分。通过将监控添加到您的关键绩效指标（KPIs）中，您可以确保整个系统的性能符合预期，并通过向关键监控目标添加触发器，您可以立即收到可能影响用户的任何活动的警报。对基础设施的这种洞察力既可以帮助减少用户流失，也可以推动更好的业务决策。

当我们通过示例进行工作时，您可能已经想到了要监控的内容，但以下是一些常见的内容，它们一直被认为是最有用的：

+   **节点 RAM 利用率**：如果您注意到您的节点没有使用分配的所有 RAM，您可以切换到较小的节点，反之亦然。如果您使用受内存限制的 Docker 容器，这个指标通常会变得不那么有用，但仍然是一个很好的指标，因为您希望确保您的节点从未达到系统级最大内存利用率，否则您的容器将以更慢的交换方式运行。

+   **节点 CPU 利用率**：通过这个指标，您可以看到服务密度是否过低或过高，或者服务需求是否出现波动。

+   **节点意外终止**：这个指标很好地跟踪确保您的 CI/CD 流水线没有创建错误的镜像，您的配置服务是在线的，以及可能导致服务中断的其他问题。

+   服务意外终止：找出服务为何意外终止对于消除任何系统中的错误至关重要。看到这个值的增加或减少可能是代码质量的良好指标，尽管它们也可能表明一系列其他问题，无论是内部的还是外部的。

+   消息队列大小：我们之前详细介绍了这一点，但膨胀的队列大小表明您的基础设施无法快速处理生成的数据，因此这个指标总是很有用的。

+   连接吞吐量：准确了解您正在处理的数据量可以很好地指示服务负载。将其与其他收集的统计数据进行比较，还可以告诉您所见问题是内部还是外部造成的。

+   服务延迟：仅仅因为没有故障并不意味着服务不可用。通过跟踪延迟，您可以详细了解需要改进的地方，或者哪些性能不符合您的期望。

+   内核恐慌：虽然罕见但极其致命，内核恐慌可能对部署的服务造成严重影响。尽管监控这些情况相当棘手，但跟踪内核恐慌将在出现潜在的内核或硬件问题时向您发出警报，这将需要您开始解决。

显然，这并不是一个详尽的列表，但它涵盖了一些更有用的内容。随着基础设施的发展，您会发现在各处添加监控会更快地解决问题，并发现服务的可扩展性问题。因此，一旦将监控添加到基础设施中，不要害怕将其连接到系统的尽可能多的部分。最终，通过监控整个基础设施获得可见性和透明度，您可以做出更明智的决策并构建更好的服务，这正是我们想要的。

# 评估下一代技术

我个人感觉大多数关于容器（以及大多数其他技术主题）的文档和学习材料中都忽略了新兴技术的适当评估和风险评估。虽然选择一个基本有缺陷的音乐播放器的风险微不足道，但选择一个基本有缺陷的云技术可能会让你陷入多年的痛苦和开发中，而这些本来是你不需要的。随着云空间中工具的创建和发展速度飞快，良好的评估技术是你可能想要掌握的技能之一，因为它们可以在长远来看为你节省精力、时间和金钱。直觉很棒，但拥有一种坚实、可重复和确定性的评估技术的方式更有可能带来长期的成功。

请注意，尽管这里给出的建议对我和我职业生涯中接触过的其他人来说都有相当不错的记录，但你永远无法完全预测技术领域的发展方向，特别是当大多数科技初创公司可能随时关门（例如 ClusterHQ）时。因此，请记住，这些只是一些有趣的观点，而不是一个能让选择技术中最常见问题消失的神奇清单。

# 技术需求

这应该是一个非常明显的观点，但需要写下来。如果你需要一个工具提供的功能，而你又不想自己开发，那么你将别无选择，只能选择它并希望一切顺利。幸运的是，在大多数云技术和支持它们的工具模块中，通常至少有两个竞争对手在争夺相同的用户，所以事情并不像今天看起来那么可怕，尽管就在一年前，这个领域几乎所有东西的版本号都低于`1.0`。在评估竞争工具如何满足你的需求时，也要记住，即使它们解决了相同的问题，也并非每个工具都面向相同的目的。如果我们以当前的 Kubernetes 与 Marathon 为例，尽管它们都可以用来解决相同的服务部署问题，但 Kubernetes 主要面向单一目的，而 Marathon，例如，还可以用于调度和集群管理作为额外的功能，所以在谚语意义上，我们真的在比较苹果和橙子。

总的来说，你的服务基础设施需求将驱动你的工具需求，所以你通常不会最终使用你最喜欢的编程语言，拥有易于集成的接入点，或者使用一个合理的工具代码库，但集成一个可以节省数百或数千人时的工具绝不可轻视。有时可能通过改变系统架构的部分来完全规避技术要求，以避免给系统增加复杂性，但根据我的个人经验，这几乎从来不容易做到，所以你的情况可能有所不同。

# 流行度

这可能是考虑的最具争议性的维度之一，但也是处理新技术时要注意的最重要的维度之一。虽然绝对真实的是，流行并不等同于技术优点，但可以假设：

+   更多使用特定工具的人将能够提供更好的集成帮助。

+   更容易找到解决问题的方法。

+   如果代码库是开源的，项目更有可能得到修复和功能的添加。

另一种描述这个问题的方式是，你能承担风险将几周/几个月/几年的集成工作投入到一个未经验证或在未来几年内可能被放弃的工具上吗？如果你是一个拥有庞大预算的大型企业，这可能不是一个问题，但在大多数情况下，你将没有机会尝试集成不同的竞争性技术，以找出最好的那个。虽然有时存在完全有效的情况，可以冒险尝试新工具，但由于云系统的复杂性和长期性，失败的代价非常高，因此一般建议采取务实的方法，但你的个人需求可能会有所不同，所以请相应选择。

要评估项目的这一方面，可以使用各种工具，但最简单和最容易的是 GitHub 项目的 forks/stars（对于开源项目）、Google 趋势（[`trends.google.com`](https://trends.google.com)）预测，以及使用过该技术的人们的社交媒体反馈。通过观察这些价值的变化和转变，可以相对准确地推断长期的可行性，并结合对现有工具的比较，可以形成一个项目的总体脉搏的良好图景。上升的项目通常表明具有优越的技术基础，但在某些情况下，这是由于对现有工具的拒绝或大规模的营销推动，因此在评估工具时，不要总是认为流行的选项更好。

**![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/fac939d5-87a1-4de2-80f1-a8b5fbc11d9f.png)**

在上面的截图中，你可以看到 Kubernetes 的兴趣随时间的增加而明显增加，这在某种程度上反映了社区对该编排工具的采纳和接受。如果我们要自己实施这项技术，我们可以相当肯定，在一段时间内，我们将使用一种更容易使用并获得支持的工具。

当将 Kubernetes 与 Marathon 进行比较并使用相同的技术时，情况变得非常混乱，因为 Marathon 也是一种非常常见的长跑活动，因此结果会与不相关的谷歌查询混在一起。在下面的截图中，我们将结果与其他一些与云相关的关键词进行了叠加，你可以看到我们的数据有些问题：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/f9e6c5e8-01cf-4e88-b1a1-4f87c0199812.png)

然而，看一下它们的 GitHub 页面右上角以及 forks/stars，我们可以看到它们的比较情况（**3,483** stars 和**810** forks 对比**28,444** stars 和**10,167** forks）：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/ad45d9ff-4388-4ece-a644-aff9600199c8.png)

将上述 GitHub 页面与以下页面进行比较：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/9b4d4d63-a545-4a67-875d-639c8fb138df.png)

在这个特定的例子中，很难看到长期的趋势，我们已经提到这两个工具解决的问题不同，而且这两个工具的设置复杂性迥然不同，因此很难进行适当的评估。

在我们继续下一个维度之前，有一件非常重要的事情需要提到：对于不成熟的工具（这种情况比你想象的更有可能），一个常见且强烈推荐的风险缓解措施是，如果您的开发人员有能力并且被允许在相关的上游项目上修复错误和添加功能。如果一个工具非常适合您的基础架构，并且您可以投入开发资源，那么它是否受欢迎并不重要，只要您可以使其按照您满意的方式工作。

作为参考数据点，在开发云实施过程中，我所在的团队无数次发现了上游项目中的错误和问题，我们很快就修复了这些问题，同时也帮助了该软件的所有其他用户，而不是潜在地等待上游开发人员花时间来修复它们。如果可能的话，我强烈鼓励这种回馈贡献的方式应用到你的工作场所，因为它有助于整个项目的社区，并间接地防止由于未修复的错误而导致项目动力的丧失。

# 团队的技术能力

新的工具往往有一个很好的初始想法，但由于糟糕的执行或架构，很快就变成了难以维护且容易出现错误的意大利面代码。如果设计和实施保持高标准，您可以更有把握地确保不会出现意外的故障，或者至少可以更容易地找到和修复错误。核心项目开发人员的能力在这方面起着巨大作用，由于大多数较新的工具都是开源的，因此查看代码库在这方面通常会非常有帮助。

评估涉及各种技术和系统的项目几乎不可能制定确切的指导方针，但有一些红旗应该被视为对未来可能出现的工具问题的警告信号：

+   **缺乏测试**：没有测试，代码是否有效的保证几乎被消除，您只能希望进行更改的开发人员在实现新功能时足够小心，并且他们没有破坏当前功能。在我的生活中，我只见过少数几个开发人员可以像测试工具一样留意所有边缘情况，但我不会抱太大希望，你正在调查的项目是否有这样的人。

+   **聪明的代码**：有时，一个项目会有一个或多个开发人员更关心展示他们的技能，而不是项目的可维护性，他们几乎总是会把他们接触的文件变成只有他们自己能够处理的代码，导致将来在添加功能或修复错误时出现问题。几乎总是这种改变是单向的，经过足够长的时间后，通常会导致项目的死亡（根据我的经验，这种情况更常见）。

+   **长时间开放的关键错误数量较高**：对于任何项目，总会有一个时刻，你会遇到一个必须尽快修复的关键错误，通过观察修复所需的时间趋势，你可以看出团队是否有能力快速解决问题，或者是否关注更广泛的社区。虽然更多是主观指标，但随着服务的概况或安全姿态的增加，它变得极为重要。

您还可以使用其他评估指标，例如：旧的未合并的拉取请求，任意关闭的错误报告等，只要您能正确了解代码库的质量概念。有了这些知识，您可以正确评估候选工具的未来可能性，以及您的基础架构如何随之发展。

# 摘要

到此为止，我们已经到达了我们书的结尾！在这一章中，我们涵盖了各种你需要通过积极的自动化、将事物分割成多个可用区，并为你的基础设施添加监控来将你的小型服务变成全球化的事物。由于云技术也相对年轻，我们更重要地包括了一些关于如何客观评估新兴工具的建议，以确保你的项目在可预见的未来工具生态系统变化中具有最大的成功可能性。通过假设未来会发生变化，并拥有处理这些变化的工具，我们可以准备好接受任何被扔向我们的东西。
