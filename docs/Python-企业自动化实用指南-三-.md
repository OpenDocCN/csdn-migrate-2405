# Python 企业自动化实用指南（三）

> 原文：[`zh.annas-archive.org/md5/0bfb2f4dbc80a06d99550674abb53d0d`](https://zh.annas-archive.org/md5/0bfb2f4dbc80a06d99550674abb53d0d)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：系统管理的 Ansible

在本章中，我们将探索一种被成千上万的网络和系统工程师使用的流行自动化框架*Ansible*，Ansible 用于管理服务器和网络设备，通过多种传输协议如 SSH、Netconf 和 API 来提供可靠的基础设施。

我们首先将学习 ansible 中使用的术语，如何构建包含基础设施访问详细信息的清单文件，使用条件、循环和模板渲染等功能构建强大的 Ansible playbook。

Ansible 属于软件配置管理类别；它用于管理多个不同设备和服务器上的配置生命周期，确保所有设备上都应用相同的步骤，并帮助创建基础设施即代码（IaaC）环境。

本章将涵盖以下主题：

+   Ansible 及其术语

+   在 Linux 上安装 Ansible

+   在临时模式下使用 Ansible

+   创建您的第一个 playbook

+   理解 Ansible 的条件、处理程序和循环

+   使用 Ansible 事实

+   使用 Ansible 模板

# Ansible 术语

Ansible 是一个自动化工具和完整的框架，它提供了基于 Python 工具的抽象层。最初，它是设计用来处理任务自动化的。这个任务可以在单个服务器上执行，也可以在成千上万的服务器上执行，ansible 都可以毫无问题地处理；后来，Ansible 的范围扩展到了网络设备和云提供商。Ansible 遵循“幂等性”的概念，其中 Ansible 指令可以多次运行相同的任务，并始终在所有设备上给出相同的配置，最终达到期望的状态，变化最小。例如，如果我们运行 Ansible 将文件上传到特定组的服务器，然后再次运行它，Ansible 将首先验证文件是否已经存在于远程目的地，如果存在，那么 ansible 就不会再次上传它。

再次。这个功能叫做“幂等性”。

Ansible 的另一个方面是它是无代理的。在运行任务之前，Ansible 不需要在服务器上安装任何代理。它利用 SSH 连接和 Python 标准库在远程服务器上执行任务，并将输出返回给 Ansible 服务器。此外，它不会创建数据库来存储远程机器信息，而是依赖于一个名为`inventory`的平面文本文件来存储所有所需的服务器信息，如 IP 地址、凭据和基础设施分类。以下是一个简单清单文件的示例：

```py
[all:children] web-servers db-servers   [web-servers] web01 Ansible_ssh_host=192.168.10.10     [db-servers] db01 Ansible_ssh_host=192.168.10.11 db02 Ansible_ssh_host=192.168.10.12   [all:vars] Ansible_ssh_user=root Ansible_ssh_pass=access123   [db-servers:vars] Ansible_ssh_user=root Ansible_ssh_pass=access123   
```

```py
[local] 127.0.0.1 Ansible_connection=local Ansible_python_interpreter="/usr/bin/python"
```

请注意，我们将在我们的基础设施中执行相同功能的服务器分组在一起（比如数据库服务器，在一个名为`[db-servers]`的组中；同样的，对于`[web-servers]`也是如此）。然后，我们定义一个特殊的组，称为`[all]`，它结合了这两个组，以防我们有一个针对所有服务器的任务。

`children`关键字在`[all:children]`中的意思是组内的条目也是包含主机的组。

Ansible 的“临时”模式允许用户直接从终端向远程服务器执行任务。假设您想要在特定类型的服务器上更新特定的软件包，比如数据库或 Web 后端服务器，以解决一个新的 bug。与此同时，您不想要开发一个复杂的 playbook 来执行一个简单的任务。通过利用 Ansible 的临时模式，您可以在 Ansible 主机终端上输入命令来在远程服务器上执行任何命令。甚至一些模块也可以在终端上执行；我们将在“在临时模式下使用 Ansible”部分中看到这一点。

# 在 Linux 上安装 Ansible

Ansible 软件包在所有主要的 Linux 发行版上都可用。在本节中，我们将在 Ubuntu 和 CentOS 机器上安装它。在编写本书时使用的是 Ansible 2.5 版本，并且它支持 Python 2.6 和 Python 2.7。此外，从 2.2 版本开始，Ansible 为 Python 3.5+提供了技术预览。

# 在 RHEL 和 CentOS

在安装 Ansible 之前，您需要安装和启用 EPEL 存储库。要这样做，请使用以下命令：

```py
sudo yum install epel-release
```

然后，按照以下命令安装 Ansible 软件包：

```py
sudo yum install Ansible
```

# Ubuntu

首先确保您的系统是最新的，并添加 Ansible 通道。最后，安装 Ansible 软件包本身，如下面的代码片段所示：

```py
$ sudo apt-get update
$ sudo apt-get install software-properties-common
$ sudo apt-add-repository ppa:Ansible/Ansible
$ sudo apt-get update
$ sudo apt-get install Ansible
```

有关更多安装选项，请查看官方 Ansible 网站（[`docs.Ansible.com/Ansible/latest/installation_guide/intro_installation.html?#installing-the-control-machine`](http://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html?#installing-the-control-machine)）。

您可以通过运行`Ansible --version`来验证您的安装，以检查已安装的版本：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00164.jpeg)Ansible 配置文件通常存储在`/etc/Ansible`中，文件名为`Ansible.cfg`。

# 在临时模式下使用 Ansible

当您需要在远程机器上执行简单操作而不创建复杂和持久的任务时，可以使用 Ansible 临时模式。这通常是用户在开始使用 Ansible 时首先使用的地方，然后再执行 playbook 中的高级任务。

执行临时命令需要两件事。首先，您需要清单文件中的主机或组；其次，您需要要执行的针对目标机器的 Ansible 模块：

1.  首先，让我们定义我们的主机，并将 CentOS 和 Ubuntu 机器添加到一个单独的组中：

```py
[all:children] centos-servers ubuntu-servers   [centos-servers] centos-machine01 Ansible_ssh_host=10.10.10.193   [ubuntu-servers] ubuntu-machine01 Ansible_ssh_host=10.10.10.140   [all:vars] Ansible_ssh_user=root Ansible_ssh_pass=access123   [centos-servers:vars] Ansible_ssh_user=root Ansible_ssh_pass=access123   [ubuntu-servers:vars] Ansible_ssh_user=root Ansible_ssh_pass=access123

[routers]
gateway ansible_ssh_host = 10.10.88.110 ansible_ssh_user=cisco ansible_ssh_pass=cisco   [local] 127.0.0.1 Ansible_connection=local Ansible_python_interpreter="/usr/bin/python"
```

1.  将此文件保存为`hosts`，放在`/root/`或您的主目录中的`AutomationServer`下。

1.  然后，使用`ping`模块运行`Ansible`命令：

```py
# Ansible -i hosts all -m ping
```

`-i`参数将接受我们添加的清单文件，而`-m`参数将指定 Ansible 模块的名称。

运行命令后，您将得到以下输出，指示连接到远程机器失败：

```py
ubuntu-machine01 | FAILED! => {
 "msg": "Using a SSH password instead of a key is not possible because Host Key checking is enabled and sshpass does not support this.  Please add this host's fingerprint to your known_hosts file to manage this host."
}
centos-machine01 | FAILED! => {
 "msg": "Using a SSH password instead of a key is not possible because Host Key checking is enabled and sshpass does not support this.  Please add this host's fingerprint to your known_hosts file to manage this host."
}
```

这是因为远程机器不在 Ansible 服务器的`known_hosts`中；可以通过两种方法解决。

第一种方法是手动 SSH 到它们，这将将主机指纹添加到服务器。或者，您可以在 Ansible 配置中完全禁用主机密钥检查，如下面的代码片段所示：

```py
sed -i -e 's/#host_key_checking = False/host_key_checking = False/g' /etc/Ansible/Ansible.cfg

sed -i -e 's/#   StrictHostKeyChecking ask/   StrictHostKeyChecking no/g' /etc/ssh/ssh_config
```

重新运行`Ansible`命令，您应该从三台机器中获得成功的输出：

```py
127.0.0.1 | SUCCESS => {
 "changed": false, 
 "ping": "pong"
}
ubuntu-machine01 | SUCCESS => {
 "changed": false, 
 "ping": "pong"
}
centos-machine01 | SUCCESS => {
 "changed": false, 
 "ping": "pong"
}
```

Ansible 中的`ping`模块不执行针对设备的 ICMP 操作。它实际上尝试使用提供的凭据通过 SSH 登录到设备；如果登录成功，它将返回`pong`关键字给 Ansible 主机。

另一个有用的模块是`apt`或`yum`，用于管理 Ubuntu 或 CentOS 服务器上的软件包。以下示例将在 Ubuntu 机器上安装`apache2`软件包：

```py
# Ansible -i hosts ubuntu-servers -m apt -a "name=apache2 state=present" 
```

`apt`模块中的状态可以有以下值：

| **状态** | **操作** |
| --- | --- |
| `absent` | 从系统中删除软件包。 |
| `present` | 确保软件包已安装在系统上。 |
| `latest` | 确保软件包是最新版本。 |

您可以通过运行`Ansible-doc <module_name>`来访问 Ansible 模块文档；您将看到模块的完整选项和示例。

`service`模块用于管理服务的操作和当前状态。您可以在`state`选项中将服务状态更改为`started`、`restarted`或`stopped`，ansible 将运行适当的命令来更改状态。同时，您可以通过配置`enabled`来配置服务是否在启动时启用或禁用。

```py
#Ansible -i hosts centos-servers -m service -a "name=httpd state=stopped, enabled=no"
```

此外，您可以通过提供服务名称并将`state`设置为`restarted`来重新启动服务：

```py
#Ansible -i hosts centos-servers -m service -a "name=mariadb state=restarted"
```

以 adhoc 模式运行 Ansible 的另一种方法是直接将命令传递给 Ansible，而不是使用内置模块，而是使用`-a`参数：

```py
#Ansible -i hosts all -a "ifconfig"
```

您甚至可以通过运行`reboot`命令重新启动服务器；但这次，我们只会针对 CentOS 服务器运行它：

```py
#Ansible -i hosts centos-servers -a "reboot"
```

有时，您需要使用不同的用户运行命令（或模块）。当您在具有分配给不同于 SSH 用户的特定权限的远程服务器上运行脚本时，这将非常有用。在这种情况下，我们将添加`-u`，`--become`和`--ask-become-pass`（`-K`）开关。这将使 Ansible 使用提供的用户名运行命令，并提示您输入用户的密码：

```py
#Ansible -i hosts ubuntu-servers --become-user bassim  --ask-become-pass -a "cat /etc/sudoers"
```

# Ansible 的实际工作方式

Ansible 基本上是用 Python 编写的，但它使用自己的 DSL（领域特定语言）。您可以使用此 DSL 编写，ansible 将在远程机器上将其转换为 Python 以执行任务。因此，它首先验证任务语法并从 Ansible 主机复制模块到远程服务器，然后在远程服务器上执行它。

执行的结果以`json`格式返回到 Ansible 主机，因此您可以通过了解其键来匹配任何返回的值：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00165.jpeg)

在安装了 Python 的网络设备的情况下，Ansible 使用 API 或`netconf`（如果网络设备支持，例如 Juniper 和 Cisco Nexus）；或者，它只是使用 paramiko 的`exec_command()`函数执行命令，并将输出返回到 Ansible 主机。这可以通过使用`raw`模块来完成，如下面的代码片段所示：

```py
# Ansible -i hosts routers -m raw -a "show arp" 
gateway | SUCCESS | rc=0 >>

Sat Apr 21 01:33:58.391 CAIRO

Address         Age        Hardware Addr   State      Type  Interface
85.54.41.9         -          45ea.2258.d0a9  Interface  ARPA  TenGigE0/2/0/0
10.88.18.1      -          d0b7.428b.2814  Satellite  ARPA  TenGigE0/2/0/0
192.168.100.1   -          00a7.5a3b.4193  Interface  ARPA  GigabitEthernet100/0/0/9
192.168.100.2   02:08:03   fc5b.3937.0b00  Dynamic    ARPA  \
```

# 创建您的第一个剧本

现在魔术派对可以开始了。Ansible 剧本是一组需要按顺序执行的命令（称为任务），它描述了执行完成后主机的期望状态。将剧本视为包含一组指令的手册，用于更改基础设施的状态；每个指令都依赖于许多内置的 Ansible 模块来执行任务。例如，您可能有一个用于构建 Web 应用程序的剧本，其中包括 SQL 服务器，用作后端数据库和 nginx Web 服务器。剧本将有一系列任务针对每组服务器执行，以将它们的状态从`不存在`更改为`存在`，或者更改为`重新启动`或`不存在`，如果要删除 Web 应用程序。

剧本的强大之处在于您可以使用它在任何地方配置和设置基础设施。用于创建开发环境的相同过程将用于生产环境。剧本用于创建在您的基础设施上运行的自动化工作流程：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00166.jpeg)

剧本是用 YAML 编写的，我们在第六章中讨论过，*使用 Python 和 Jinja2 生成配置*。剧本由多个 play 组成，针对清单文件中定义的一组主机执行。主机将被转换为 Python `list`，列表中的每个项目将被称为`play`。在前面的示例中，`db-servers`任务是一些 play，并且仅针对`db-servers`执行。在剧本执行期间，您可以决定运行文件中的所有 play，仅特定 play 或具有特定标记的任务，而不管它们属于哪个 play。

现在，让我们看看我们的第一个剧本，以了解其外观和感觉：

```py
- hosts: centos-servers
  remote_user: root

  tasks:
    - name: Install openssh
      yum: pkg=openssh-server state=installed

    - name: Start the openssh
      service: name=sshd state=started enabled=yes
```

这是一个简单的剧本，有一个包含两个任务的`play`：

1.  安装`openssh-server`。

1.  安装后启动`sshd`服务，并确保它在启动时可用。

现在，我们需要将其应用于特定主机（或一组主机）。因此，我们将`hosts`设置为之前在 inventory 文件中定义的`CentOS-servers`，并且我们还将`remote_user`设置为 root，以确保之后的任务将以 root 权限执行。

任务将包括名称和 Ansible 模块。名称用于描述任务。为任务提供名称并不是强制性的，但建议这样做，以防需要从特定任务开始执行。

第二部分是 Ansible 模块，这是必需的。在我们的示例中，我们使用了核心模块`yum`来在目标服务器上安装`openssh-server`软件包。第二个任务具有相同的结构，但这次我们将使用另一个核心模块，称为`service`，来启动和启用`sshd`守护程序。

最后要注意 Ansible 中不同组件的缩进。例如，任务的名称应该在同一级别，而`tasks`应该与同一行上的`hosts`对齐。

让我们在我们的自动化服务器上运行 playbook 并检查输出：

```py
#Ansible-playbook -i hosts first_playbook.yaml 

PLAY [centos-servers] **********************************************************************

TASK [Gathering Facts] *********************************************************************
ok: [centos-machine01]

TASK [Install openssh] *********************************************************************
ok: [centos-machine01]

TASK [Start the openssh] *******************************************************************
ok: [centos-machine01]

```

```py
PLAY RECAP *********************************************************************************
centos-machine01           : ok=3    changed=0    unreachable=0    failed=0   
```

您可以看到 playbook 在`centos-machine01`上执行，并且任务按照 playbook 中定义的顺序依次执行。

YAML 要求保留缩进级别，并且不要混合制表符和空格；否则，将会出现错误。许多文本编辑器和 IDE 将制表符转换为一组空格。以下截图显示了该选项的示例，在 notepad++编辑器首选项中：![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00167.jpeg)

# 理解 Ansible 条件、处理程序和循环

在本章的这一部分，我们将看一些 Ansible playbook 中的高级功能。

# 设计条件

Ansible playbook 可以根据任务内部特定条件的结果执行任务（或跳过任务）——例如，当您想要在特定操作系统家族（Debian 或 CentOS）上安装软件包时，或者当操作系统是特定版本时，甚至当远程主机是虚拟机而不是裸机时。这可以通过在任务内部使用`when`子句来实现。

让我们增强先前的 playbook，并将`openssh-server`安装限制为仅适用于基于 CentOS 的系统，这样当它遇到使用`apt`模块而不是`yum`的 Ubuntu 服务器时，就不会出错。

首先，我们将在我们的`inventory`文件中添加以下两个部分，将 CentOS 和 Ubuntu 机器分组到`infra`部分中：

```py
[infra:children] centos-servers ubuntu-servers     [infra:vars] Ansible_ssh_user=root Ansible_ssh_pass=access123 
```

然后，我们将重新设计 playbook 中的任务，添加`when`子句，将任务执行限制为仅适用于基于 CentOS 的机器。这应该读作`如果远程机器是基于 CentOS 的，那么我将执行任务；否则，跳过`。

```py
- hosts: infra
  remote_user: root

  tasks:
    - name: Install openssh
      yum: pkg=openssh-server state=installed
      when: Ansible_distribution == "CentOS"

    - name: Start the openssh
      service: name=sshd state=started enabled=yes
  when: Ansible_distribution == "CentOS"
```

让我们运行 playbook：

```py
# Ansible-playbook -i hosts using_when.yaml 

PLAY [infra] *******************************************************************************

TASK [Gathering Facts] *********************************************************************
ok: [centos-machine01]
ok: [ubuntu-machine01]

TASK [Install openssh] *********************************************************************
skipping: [ubuntu-machine01]
ok: [centos-machine01]

TASK [Start the openssh] *******************************************************************
skipping: [ubuntu-machine01]
ok: [centos-machine01]

PLAY RECAP *********************************************************************************
centos-machine01           : ok=3    changed=0    unreachable=0    failed=0 
ubuntu-machine01           : ok=1    changed=0    unreachable=0    failed=0  
```

请注意，playbook 首先收集有关远程机器的信息（我们将在本章后面讨论），然后检查操作系统。当它遇到`ubuntu-machine01`时，任务将被跳过，并且在 CentOS 上将正常运行。

您还可以有多个条件需要满足才能运行任务。例如，您可以有以下 playbook，验证两件事情——首先，机器基于 Debian，其次，它是一个虚拟机，而不是裸机：

```py
- hosts: infra
  remote_user: root

  tasks:
    - name: Install openssh
      apt: pkg=open-vm-tools state=installed
      when:
        - Ansible_distribution == "Debian"
        - Ansible_system_vendor == "VMware, Inc."
```

运行此 playbook 将产生以下输出：

```py
# Ansible-playbook -i hosts using_when_1.yaml 

PLAY [infra] *******************************************************************************

TASK [Gathering Facts] *********************************************************************
ok: [centos-machine01]
ok: [ubuntu-machine01]

TASK [Install openssh] *********************************************************************
skipping: [centos-machine01]
ok: [ubuntu-machine01]

PLAY RECAP *********************************************************************************
centos-machine01           : ok=1    changed=0    unreachable=0    failed=0
ubuntu-machine01           : ok=2    changed=0    unreachable=0    failed=0 
```

Ansible 的`when`子句还接受表达式。例如，您可以检查返回的输出中是否存在特定关键字（使用注册标志保存），并根据此执行任务。

以下 playbook 将验证 OSPF 邻居状态。第一个任务将在路由器上执行`show ip ospf neighbor`并将输出注册到名为`neighbors`的变量中。接下来的任务将检查返回的输出中是否有`EXSTART`或`EXCHANGE`，如果找到，将在控制台上打印一条消息：

```py
hosts: routers

tasks:
  - name: "show the ospf neighbor status"
    raw: show ip ospf neighbor
    register: neighbors

  - name: "Validate the Neighbors"
    debug:
      msg: "OSPF neighbors stuck"
    when: ('EXSTART' in neighbors.stdout) or ('EXCHANGE' in neigbnors.stdout)
```

您可以在[`docs.Ansible.com/Ansible/latest/user_guide/playbooks_conditionals.html#commonly-used-facts`](http://docs.ansible.com/ansible/latest/user_guide/playbooks_conditionals.html#commonly-used-facts)中检查在`when`子句中常用的事实。

# 在 ansible 中创建循环

Ansible 提供了许多重复在 play 中执行相同任务的方法，但每次都有不同的值。例如，当您想在服务器上安装多个软件包时，您不需要为每个软件包创建一个任务。相反，您可以创建一个任务，安装一个软件包并向任务提供软件包名称的列表，Ansible 将对它们进行迭代，直到完成安装。为此，我们需要在包含列表的任务内使用`with_items`标志，并使用变量`{{ item }}`，它作为列表中项目的占位符。playbook 将利用`with_items`标志对一组软件包进行迭代，并将它们提供给`yum`模块，该模块需要软件包的名称和状态：

```py
- hosts: infra
  remote_user: root

  tasks:
    - name: "Modifying Packages"
  yum: name={{ item.name }} state={{ item.state }}
  with_items:
        - { name: python-keyring-5.0-1.el7.noarch, state: absent }
  - { name: python-django, state: absent }
  - { name: python-django-bash-completion, state: absent }
  - { name: httpd, state: present }
  - { name: httpd-tools, state: present }
  - { name: python-qpid, state: present }
  when: Ansible_distribution == "CentOS"
```

您可以将状态的值硬编码为`present`；在这种情况下，所有的软件包都将被安装。然而，在前一种情况下，`with_items`将向`yum`模块提供两个元素。

playbook 的输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00168.jpeg)

# 使用处理程序触发任务

好的；您已经在系统中安装和删除了一系列软件包。您已经将文件复制到/从服务器。并且您已经通过使用 Ansible playbook 在服务器上做了很多改变。现在，您需要重新启动一些其他服务，或者向文件中添加一些行，以完成服务的配置。所以，您应该添加一个新的任务，对吗？是的，这是正确的。然而，Ansible 提供了另一个很棒的选项，称为**handlers**，它不会在触发时自动执行（不像任务），而是只有在被调用时才会执行。这为您提供了灵活性，可以在 play 中的任务执行时调用它们。

处理程序与主机和任务具有相同的对齐方式，并位于每个 play 的底部。当您需要调用处理程序时，您可以在原始任务内使用`notify`标志，以确定将执行哪个处理程序；Ansible 将它们链接在一起。

让我们看一个例子。我们将编写一个 playbook，在 CentOS 服务器上安装和配置 KVM。KVM 在安装后需要进行一些更改，比如加载`sysctl`，启用`kvm`和`802.1q`模块，并在`boot`时加载`kvm`：

```py
- hosts: centos-servers
  remote_user: root

  tasks:
    - name: "Install KVM"
  yum: name={{ item.name }} state={{ item.state }}
  with_items:
        - { name: qemu-kvm, state: installed }
  - { name: libvirt, state: installed }
  - { name: virt-install, state: installed }
  - { name: bridge-utils, state: installed }    notify:
        - load sysctl
        - load kvm at boot
        - enable kvm

  handlers:
    - name: load sysctl
      command: sysctl -p

    - name: enable kvm
      command: "{{ item.name }}"
      with_items:
        - {name: modprobe -a kvm}
  - {name: modprobe 8021q}
  - {name: udevadm trigger}    - name: load kvm at boot
      lineinfile: dest=/etc/modules state=present create=True line={{ item.name }}
  with_items:
        - {name: kvm}   
```

注意安装任务后使用`notify`。当任务运行时，它将按顺序通知三个处理程序，以便它们将被执行。处理程序将在任务成功执行后运行。这意味着如果任务未能运行（例如，找不到`kvm`软件包，或者没有互联网连接来下载它），则系统不会发生任何更改，`kvm`也不会被启用。

处理程序的另一个很棒的特性是，它只在任务中有更改时才运行。例如，如果您重新运行任务，Ansible 不会安装`kvm`软件包，因为它已经安装；它不会调用任何处理程序，因为它在系统中没有检测到任何更改。

我们将在最后关于两个模块添加一个注释：`lineinfile`和`command`。第一个模块实际上是通过使用正则表达式向配置文件中插入或删除行；我们使用它来将`kvm`插入`/etc/modules`，以便在机器启动时自动启动 KVM。第二个模块`command`用于在设备上直接执行 shell 命令并将输出返回给 Ansible 主机。

# 使用 Ansible 事实

Ansible 不仅用于部署和配置远程主机。它可以用于收集有关它们的各种信息和事实。事实收集可能需要大量时间来从繁忙的系统中收集所有内容，但将为目标机器提供全面的视图。

收集到的事实可以在后续的 playbook 中使用，设计任务条件。例如，我们使用`when`子句将`openssh`安装限制为仅适用于基于 CentOS 的系统：

```py
when: Ansible_distribution == "CentOS"
```

您可以通过在与主机和任务相同级别上配置`gather_facts`来在 Ansible plays 中启用/禁用事实收集。

```py
- hosts: centos-servers
  gather_facts: yes
  tasks:
    <your tasks go here>
```

在 Ansible 中收集事实并打印它们的另一种方法是在 adhoc 模式中使用`setup`模块。返回的结果以嵌套的字典和列表的形式描述远程目标的事实，例如服务器架构、内存、网络设置、操作系统版本等：

```py
#Ansible -i hosts ubuntu-servers -m setup | less 
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00169.jpeg)

您可以使用点表示法或方括号从事实中获取特定值。例如，要获取`eth0`的 IPv4 地址，可以使用`Ansible_eth0["ipv4"]["address"]`或`Ansible_eth0.ipv4.address`。

# 使用 Ansible 模板

与 Ansible 一起工作的最后一部分是了解它如何处理模板。Ansible 使用我们在第六章中讨论过的 Jinja2 模板，*使用 Python 和 Jinja2 生成配置*。它使用 Ansible 事实或在`vars`部分提供的静态值填充参数，甚至使用使用`register`标志存储的任务的结果。

在以下示例中，我们将构建一个 Ansible playbook，其中包含前面三个案例。首先，在`vars`部分中定义一个名为`Header`的变量，其中包含一个欢迎消息作为静态值。然后，我们启用`gather_facts`标志，以从目标机器获取所有可能的信息。最后，我们执行`date`命令，以获取服务器的当前日期并将输出存储在`date_now`变量中：

```py
- hosts: centos-servers
  vars:
    - Header: "Welcome to Server facts page generated from Ansible playbook"
 gather_facts: yes  tasks:
    - name: Getting the current date
      command: date
      register: date_now
    - name: Setup webserver
      yum: pkg=nginx state=installed
      when: Ansible_distribution == "CentOS"

      notify:
        - enable the service
        - start the service

    - name: Copying the index page
      template: src=index.j2 dest=/usr/share/nginx/html/index.html

  handlers:
    - name: enable the service
      service: name=nginx enabled=yes    - name: start the service
      service: name=nginx state=started
```

在前面的 playbook 中使用的模板模块将接受一个名为`index.j2`的 Jinja2 文件，该文件位于 playbook 的同一目录中；然后，它将从我们之前讨论过的三个来源中提供所有 jinj2 变量的值。然后，渲染后的文件将存储在模板模块提供的`dest`选项中的路径中。

`index.j2`的内容如下。它将是一个简单的 HTML 页面，利用 jinja2 语言生成最终的 HTML 页面：

```py
<html> <head><title>Hello world</title></head> <body>   <font size="6" color="green">{{ Header }}</font>   <br> <font size="5" color="#ff7f50">Facts about the server</font> <br> <b>Date Now is:</b> {{ date_now.stdout }}

<font size="4" color="#00008b"> <ul>
 <li>IPv4 Address: {{ Ansible_default_ipv4['address'] }}</li>
 <li>IPv4 gateway: {{ Ansible_default_ipv4['gateway'] }}</li>
 <li>Hostname: {{ Ansible_hostname }}</li>
 <li>Total Memory: {{ Ansible_memtotal_mb }}</li>
 <li>Operating System Family: {{ Ansible_os_family }}</li>
 <li>System Vendor: {{ Ansible_system_vendor }}</li> </ul> </font> </body> </html>
```

运行此 playbook 将在 CentOS 机器上安装 nginx web 服务器，并向其添加一个`index.html`页面。您可以通过浏览器访问该页面：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00170.gif)

您还可以利用模板模块生成网络设备配置。在[第六章](https://cdp.packtpub.com/hands_on_enterprise_automation_with_python/wp-admin/post.php?post=322&action=edit#post_33)中使用的 jinja2 模板，*使用 Python 和 Jinja2 生成配置*，为路由器生成了`day0`和`day1`配置，可以在 Ansible playbook 中重复使用。

# 总结

Ansible 是一个非常强大的工具，用于自动化 IT 基础设施。它包含许多模块和库，几乎涵盖了系统和网络自动化中的所有内容，使软件部署、软件包管理和配置管理变得非常容易。虽然 Ansible 可以在 adhoc 模式下执行单个模块，但 Ansible 的真正力量在于编写和开发 playbook。


# 第十四章：创建和管理 VMware 虚拟机

很长一段时间以来，虚拟化一直是 IT 行业中的重要技术，因为它为硬件资源提供了高效的方式，并允许我们轻松地管理**虚拟机**（**VM**）内的应用程序生命周期。2001 年，VMware 发布了 ESXi 的第一个版本，可以直接在**现成的商用服务器**（**COTS**）上运行，并将其转换为可以被多个独立虚拟机使用的资源。在本章中，我们将探索许多可用于通过 Python 和 Ansible 自动构建虚拟机的选项。

本章将涵盖以下主题：

+   设置实验室环境

+   使用 Jinja2 生成 VMX 文件

+   VMware Python 客户端

+   使用 Ansible Playbooks 管理实例

# 设置环境

在本章中，我们将在 Cisco UCS 服务器上安装 VMware ESXi 5.5，并托管一些虚拟机。我们需要在 ESXi 服务器中启用一些功能，以便将一些外部端口暴露给外部世界：

1.  首先要启用 ESXi 控制台的 Shell 和 SSH 访问。基本上，ESXi 允许您使用 vSphere 客户端来管理它（基于 C#的 5.5.x 版本之前和基于 HTML 的 6 及更高版本）。一旦我们启用了 Shell 和 SSH 访问，这将使我们能够使用 CLI 来管理虚拟基础架构，并执行诸如创建、删除和自定义虚拟机等任务。

1.  访问 ESXi vSphere 客户端，转到“配置”，然后从左侧选项卡中选择“安全配置文件”，最后点击“属性”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00171.jpeg)

将打开一个弹出窗口，其中包含服务、状态和各种可以应用的选项：

1.  选择 SSH 服务，然后点击“选项”。将打开另一个弹出窗口。

1.  在启动策略下选择第一个选项，即如果有任何端口打开则自动启动，并在所有端口关闭时停止。

1.  此外，点击“服务命令”下的“启动”，然后点击“确定”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00172.jpeg)

再次为 ESXi Shell 服务重复相同的步骤。这将确保一旦 ESXi 服务器启动，两个服务都将启动，并且将打开并准备好接受连接。您可以测试两个服务，通过 SSH 连接到 ESXi IP 地址，并提供 root 凭据：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00173.jpeg)

# 使用 Jinja2 生成 VMX 文件

虚拟机（有时称为客户机）的基本单元是 VMX 文件。该文件包含构建虚拟机所需的所有设置，包括计算资源、分配的内存、硬盘和网络。此外，它定义了在机器上运行的操作系统，因此 VMware 可以安装一些工具来管理 VM 的电源。

还需要一个额外的文件：VMDK。该文件存储 VM 的实际内容，并充当 VM 分区的硬盘：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00174.jpeg)

这些文件（VMX 和 VMDK）应存储在 ESXi Shell 中的`/vmfs/volumes/datastore1`目录下，并且应该位于以虚拟机名称命名的目录中。

# 构建 VMX 模板

现在我们将创建模板文件，用于在 Python 中构建虚拟机。以下是我们需要使用 Python 和 Jinja2 生成的最终运行的 VMX 文件的示例：

```py
.encoding = "UTF-8" vhv.enable = "TRUE" config.version = "8" virtualHW.version = "8"   vmci0.present = "TRUE" hpet0.present = "TRUE" displayName = "test_jinja2"   # Specs memSize = "4096" numvcpus = "1" cpuid.coresPerSocket = "1"     # HDD scsi0.present = "TRUE" scsi0.virtualDev = "lsilogic" scsi0:0.deviceType = "scsi-hardDisk" scsi0:0.fileName = "test_jinja2.vmdk" scsi0:0.present = "TRUE"   # Floppy floppy0.present = "false"   #  CDRom ide1:0.present = "TRUE" ide1:0.deviceType = "cdrom-image" ide1:0.fileName = "/vmfs/volumes/datastore1/ISO Room/CentOS-7-x86_64-Minimal-1708.iso"   #  Networking ethernet0.virtualDev = "e1000" ethernet0.networkName = "network1" ethernet0.addressType = "generated" ethernet0.present = "TRUE"   # VM Type guestOS = "ubuntu-64"   # VMware Tools toolScripts.afterPowerOn = "TRUE" toolScripts.afterResume = "TRUE" toolScripts.beforeSuspend = "TRUE" toolScripts.beforePowerOff = "TRUE" tools.remindInstall = "TRUE" tools.syncTime = "FALSE"
```

我在文件中添加了一些注释，以说明每个块的功能。但是，在实际文件中，您看不到这些注释。

让我们分析文件并理解一些字段的含义：

+   `vhv.enable`：当设置为`True`时，ESXi 服务器将向客户机 CPU 公开 CPU 主机标志，从而允许在客户机内运行 VM（称为嵌套虚拟化）。

+   `displayName`：在 ESXi 中注册的名称，并在 vSphere 客户端中显示的名称。

+   `memsize`：定义分配给 VM 的 RAM，应以兆字节为单位提供。

+   `numvcpus`：这定义了分配给 VM 的物理 CPU 数量。此标志与`cpuid.coresPerSocket`一起使用，因此可以定义分配的 vCPU 总数。

+   `scsi0.virtualDev`：虚拟硬盘的 SCSI 控制器类型。它可以是四个值之一：BusLogic，LSI Logic parallel，LSI Logic SAS 或 VMware paravirtual。

+   `scsi0:0.fileName`：这定义了将存储实际虚拟机设置的`vmdk`（在同一目录中）的名称。

+   `ide1:0.fileName`：包含以 ISO 格式打包的安装二进制文件的镜像路径。这将使 ESXi 连接到镜像 CD-ROM（IDE 设备）中的 ISO 镜像。

+   `ethernet0.networkName`：这是 ESXi 中应连接到 VM NIC 的虚拟交换机的名称。您可以添加此参数的其他实例，以反映其他网络接口。

现在我们将构建 Jinja2 模板；您可以查看第六章，*使用 Python 和 Jinja2 进行配置生成*，了解使用 Jinja2 语言进行模板化的基础知识：

```py
.encoding = "UTF-8" vhv.enable = "TRUE" config.version = "8" virtualHW.version = "8"   vmci0.present = "TRUE" hpet0.present = "TRUE" displayName = "{{vm_name}}"   # Specs memSize = "{{ vm_memory_size }}" numvcpus = "{{ vm_cpu }}" cpuid.coresPerSocket = "{{cpu_per_socket}}"     # HDD scsi0.present = "TRUE" scsi0.virtualDev = "lsilogic" scsi0:0.deviceType = "scsi-hardDisk" scsi0:0.fileName = "{{vm_name}}.vmdk" scsi0:0.present = "TRUE"   # Floppy floppy0.present = "false"     # CDRom ide1:0.present = "TRUE" ide1:0.deviceType = "cdrom-image" ide1:0.fileName = "/vmfs/volumes/datastore1/ISO Room/{{vm_image}}"     # Networking ethernet0.virtualDev = "e1000" ethernet0.networkName = "{{vm_network1}}" ethernet0.addressType = "generated" ethernet0.present = "TRUE"   # VM Type guestOS = "{{vm_guest_os}}" #centos-64 or ubuntu-64   # VMware Tools toolScripts.afterPowerOn = "TRUE" toolScripts.afterResume = "TRUE" toolScripts.beforeSuspend = "TRUE" toolScripts.beforePowerOff = "TRUE" tools.remindInstall = "TRUE" tools.syncTime = "FALSE"
```

请注意，我们已经删除了相关字段的静态值，比如`diplayName`，`memsize`等，并用双大括号替换为变量名。在 Python 模板渲染期间，这些字段将被实际值替换，以构建有效的 VMX 文件。

现在，让我们构建渲染文件的 Python 脚本。通常，我们会将 YAML 数据序列化与 Jinja2 结合使用，以填充模板的数据。但是，由于我们已经在[第六章](https://cdp.packtpub.com/hands_on_enterprise_automation_with_python/wp-admin/post.php?post=295&action=edit#post_33)中解释了 YAML 概念，*使用 Python 和 Jinja2 进行配置生成*，我们将从另一个数据源，Microsoft Excel 中获取数据：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00175.jpeg)

# 处理 Microsoft Excel 数据

Python 有一些出色的库，可以处理 Excel 表中的数据。在第四章中，我们已经使用了 Excel 表，*使用 Python 管理网络设备*，当我们需要自动化`netmiko`配置并读取描述 Excel 文件基础设施的数据时。现在，我们将开始在自动化服务器中安装 Python `xlrd`库。

使用以下命令安装`xlrd`：

```py
pip install xlrd
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00176.jpeg)

按照以下步骤进行：

1.  XLRD 模块可以打开 Microsoft 工作簿，并使用`open_workbook()`方法解析内容。

1.  然后，您可以通过将工作表索引或工作表名称提供给`sheet_by_index()`或`sheet_by_name()`方法来选择包含数据的工作表。

1.  最后，您可以通过将行号提供给`row()`函数来访问行数据，该函数将行数据转换为 Python 列表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00177.jpeg)

请注意，`nrows`和`ncols`是特殊变量，一旦打开计算工作表中的行数和列数的工作表，它们将被填充。您可以使用`for`循环进行迭代。编号始终从开始。

回到虚拟机示例。在 Excel 表中，我们将有以下数据，反映虚拟机设置：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00178.jpeg)

为了将数据读入 Python，我们将使用以下脚本：

```py
import xlrd
workbook = xlrd.open_workbook(r"/media/bassim/DATA/GoogleDrive/Packt/EnterpriseAutomationProject/Chapter14_Creating_and_managing_VMware_virtual_machines/vm_inventory.xlsx") sheet = workbook.sheet_by_index(0) print(sheet.nrows) print(sheet.ncols)   print(int(sheet.row(1)[1].value))   for row in range(1,sheet.nrows):
  vm_name = sheet.row(row)[0].value
    vm_memory_size = int(sheet.row(row)[1].value)
  vm_cpu = int(sheet.row(row)[2].value)
  cpu_per_socket = int(sheet.row(row)[3].value)
  vm_hdd_size = int(sheet.row(row)[4].value)
  vm_guest_os = sheet.row(row)[5].value
    vm_network1 = sheet.row(row)[6].value
```

在前面的脚本中，我们做了以下事情：

1.  我们导入了`xlrd`模块，并将 Excel 文件提供给`open_workbook()`方法以读取 Excel 工作表，并将其保存到`workbook`变量中。

1.  然后，我们使用`sheet_by_index()`方法访问了第一个工作表，并将引用保存到`sheet`变量中。

1.  现在，我们将遍历打开的表格，并使用`row()`方法获取每个字段。这将允许我们将行转换为 Python 列表。由于我们只需要行内的一个值，我们将使用列表切片来访问索引。请记住，列表索引始终从零开始。我们将把该值存储到变量中，并在下一部分中使用该变量来填充 Jinja2 模板。

# 生成 VMX 文件

最后一部分是从 Jinja2 模板生成 VMX 文件。我们将从 Excel 表中读取数据，并将其添加到空字典`vmx_data`中。稍后将该字典传递给 Jinja2 模板中的`render()`函数。Python 字典键将是模板变量名，而值将是应该在文件中替换的值。脚本的最后一部分是在`vmx_files`目录中以写入模式打开文件，并为每个 VMX 文件写入数据：

```py
  from jinja2 import FileSystemLoader, Environment
import os
import xlrd

print("The script working directory is {}" .format(os.path.dirname(__file__))) script_dir = os.path.dirname(__file__)   vmx_env = Environment(
  loader=FileSystemLoader(script_dir),
  trim_blocks=True,
  lstrip_blocks= True )     workbook = xlrd.open_workbook(os.path.join(script_dir,"vm_inventory.xlsx")) sheet = workbook.sheet_by_index(0) print("The number of rows inside the Excel sheet is {}" .format(sheet.nrows)) print("The number of columns inside the Excel sheet is {}" .format(sheet.ncols))     vmx_data = {}   for row in range(1,sheet.nrows):
  vm_name = sheet.row(row)[0].value
    vm_memory_size = int(sheet.row(row)[1].value)
  vm_cpu = int(sheet.row(row)[2].value)
  cpu_per_socket = int(sheet.row(row)[3].value)
  vm_hdd_size = int(sheet.row(row)[4].value)
  vm_guest_os = sheet.row(row)[5].value
    vm_network1 = sheet.row(row)[6].value

    vmx_data["vm_name"] = vm_name
    vmx_data["vm_memory_size"] = vm_memory_size
    vmx_data["vm_cpu"] = vm_cpu
    vmx_data["cpu_per_socket"] = cpu_per_socket
    vmx_data["vm_hdd_size"] = vm_hdd_size
    vmx_data["vm_guest_os"] = vm_guest_os
    if vm_guest_os == "ubuntu-64":
  vmx_data["vm_image"] = "ubuntu-16.04.4-server-amd64.iso"    elif vm_guest_os == "centos-64":
  vmx_data["vm_image"] = "CentOS-7-x86_64-Minimal-1708.iso"    elif vm_guest_os == "windows7-64":
  vmx_data["vm_image"] = "windows_7_ultimate_sp1_ x86-x64_bg-en_IE10_ April_2013.iso"    vmx_data["vm_network1"] = vm_network1

    vmx_data = vmx_env.get_template("vmx_template.j2").render(vmx_data)
  with open(os.path.join(script_dir,"vmx_files/{}.vmx".format(vm_name)), "w") as f:
  print("Writing Data of {} into directory".format(vm_name))
  f.write(vmx_data)
  vmx_data = {} 
```

脚本输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00179.jpeg)

文件存储在`vmx_files`下，每个文件都包含在 Excel 表中配置的虚拟机的特定信息：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00180.jpeg)

现在，我们将使用`paramiko`和`scp`库连接到 ESXi Shell，并将这些文件上传到`/vmfs/volumes/datastore1`下。为了实现这一点，我们将首先创建一个名为`upload_and_create_directory()`的函数，该函数接受`vm name`、`hard disk size`和 VMX`source file`。`paramiko`将连接到 ESXi 服务器并执行所需的命令，这将在`/vmfs/volumes/datastore1`下创建目录和 VMDK。最后，我们将使用`scp`模块中的`SCPClient`将源文件上传到先前创建的目录，并运行注册命令将机器添加到 vSphere 客户端：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   import paramiko
from scp import SCPClient
import time

def upload_and_create_directory(vm_name, hdd_size, source_file):    commands = ["mkdir /vmfs/volumes/datastore1/{0}".format(vm_name),
  "vmkfstools -c {0}g -a lsilogic -d zeroedthick /vmfs/volumes/datastore1/{1}/{1}.vmdk".format(hdd_size,
  vm_name),]
  register_command = "vim-cmd solo/registervm /vmfs/volumes/datastore1/{0}/{0}.vmx".format(vm_name)
  ipaddr = "10.10.10.115"
  username = "root"
  password = "access123"    ssh = paramiko.SSHClient()
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())    ssh.connect(ipaddr, username=username, password=password, look_for_keys=False, allow_agent=False)    for cmd in commands:
  try:
  stdin, stdout, stderr = ssh.exec_command(cmd)
  print " DEBUG: ... Executing the command on ESXi server".format(str(stdout.readlines()))    except Exception as e:
  print e
            pass
 print " DEBUG: **ERR....unable to execute command"
  time.sleep(2)
  with SCPClient(ssh.get_transport()) as scp:
  scp.put(source_file, remote_path='/vmfs/volumes/datastore1/{0}'.format(vm_name))
  ssh.exec_command(register_command)
  ssh.close()
```

我们需要在运行 Jinja2 模板并生成 VMX 之前定义这个函数*之前*，并在将文件保存到`vmx_files`目录并传递所需的参数后调用该函数。

最终代码应该如下所示：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   import paramiko
from scp import SCPClient
import time
from jinja2 import FileSystemLoader, Environment
import os
import xlrd

def upload_and_create_directory(vm_name, hdd_size, source_file):    commands = ["mkdir /vmfs/volumes/datastore1/{0}".format(vm_name),
  "vmkfstools -c {0}g -a lsilogic -d zeroedthick /vmfs/volumes/datastore1/{1}/{1}.vmdk".format(hdd_size,
  vm_name),]
  register_command = "vim-cmd solo/registervm /vmfs/volumes/datastore1/{0}/{0}.vmx".format(vm_name)    ipaddr = "10.10.10.115"
  username = "root"
  password = "access123"    ssh = paramiko.SSHClient()
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())    ssh.connect(ipaddr, username=username, password=password, look_for_keys=False, allow_agent=False)    for cmd in commands:
  try:
  stdin, stdout, stderr = ssh.exec_command(cmd)
  print " DEBUG: ... Executing the command on ESXi server".format(str(stdout.readlines()))    except Exception as e:
  print e
            pass
 print " DEBUG: **ERR....unable to execute command"
  time.sleep(2)
  with SCPClient(ssh.get_transport()) as scp:
  print(" DEBUG: ... Uploading file to the datastore")
  scp.put(source_file, remote_path='/vmfs/volumes/datastore1/{0}'.format(vm_name))
  print(" DEBUG: ... Register the virtual machine {}".format(vm_name))
  ssh.exec_command(register_command)    ssh.close()   print("The script working directory is {}" .format(os.path.dirname(__file__))) script_dir = os.path.dirname(__file__)   vmx_env = Environment(
  loader=FileSystemLoader(script_dir),
  trim_blocks=True,
  lstrip_blocks= True )   workbook = xlrd.open_workbook(os.path.join(script_dir,"vm_inventory.xlsx")) sheet = workbook.sheet_by_index(0) print("The number of rows inside the Excel sheet is {}" .format(sheet.nrows)) print("The number of columns inside the Excel sheet is {}" .format(sheet.ncols))     vmx_data = {}   for row in range(1,sheet.nrows):
  vm_name = sheet.row(row)[0].value
    vm_memory_size = int(sheet.row(row)[1].value)
  vm_cpu = int(sheet.row(row)[2].value)
  cpu_per_socket = int(sheet.row(row)[3].value)
  vm_hdd_size = int(sheet.row(row)[4].value)
  vm_guest_os = sheet.row(row)[5].value
    vm_network1 = sheet.row(row)[6].value

    vmx_data["vm_name"] = vm_name
    vmx_data["vm_memory_size"] = vm_memory_size
    vmx_data["vm_cpu"] = vm_cpu
    vmx_data["cpu_per_socket"] = cpu_per_socket
    vmx_data["vm_hdd_size"] = vm_hdd_size
    vmx_data["vm_guest_os"] = vm_guest_os
    if vm_guest_os == "ubuntu-64":
  vmx_data["vm_image"] = "ubuntu-16.04.4-server-amd64.iso"    elif vm_guest_os == "centos-64":
  vmx_data["vm_image"] = "CentOS-7-x86_64-Minimal-1708.iso"    elif vm_guest_os == "windows7-64":
  vmx_data["vm_image"] = "windows_7_ultimate_sp1_ x86-x64_bg-en_IE10_ April_2013.iso"    vmx_data["vm_network1"] = vm_network1

    vmx_data = vmx_env.get_template("vmx_template.j2").render(vmx_data)
  with open(os.path.join(script_dir,"vmx_files/{}.vmx".format(vm_name)), "w") as f:
  print("Writing Data of {} into directory".format(vm_name))
  f.write(vmx_data)
  print(" DEBUG:Communicating with ESXi server to upload and register the VM")
  upload_and_create_directory(vm_name,
  vm_hdd_size,
  os.path.join(script_dir,"vmx_files","{}.vmx".format(vm_name)))
  vmx_data = {}
```

脚本输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00181.jpeg)

如果在运行脚本后检查 vSphere 客户端，您会发现已经创建了四台机器，这些机器的名称是在 Excel 表中提供的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00182.jpeg)

此外，您会发现虚拟机已经定制了诸如 CPU、内存和连接的 ISO 室等设置：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00183.jpeg)您可以通过将创建的虚拟机连接到 Cobbler 来在 VMware 中完成自动化工作流程。我们在第八章中介绍了这一点，*准备系统实验环境*。Cobbler 将自动化操作系统安装和定制，无论是 Windows、CentOS 还是 Ubuntu。之后，您可以使用我们在第十三章中介绍的 Ansible，*系统管理的 Ansible*，来准备系统的安全性、配置和已安装的软件包，然后部署您的应用程序。这是一个全栈自动化，涵盖了虚拟机创建和应用程序的运行。

# VMware Python 客户端

VMware 产品（用于管理 ESXi 的 ESXi 和 vCenter）支持通过 Web 服务接收外部 API 请求。您可以执行与 vSphere 客户端上相同的管理任务，例如创建新的虚拟机、创建新的 vSwitch，甚至控制`vm`状态，但这次是通过支持的 API 进行的，该 API 具有许多语言的绑定，例如 Python、Ruby 和 Go。

vSphere 具有库存的特殊模型，其中的每个对象都具有特定的值。您可以访问此模型，并通过**托管对象浏览器**（**MoB**）查看基础设施的实际值。我们将使用 VMware 的官方 Python 绑定（`pyvmomi`）与此模型进行交互，并更改库存中的值（或创建它们）。

值得注意的是，可以通过浏览器访问 MoB，方法是转到`http://<ESXi_server_ip_or_domain>/mob`，这将要求您提供根用户名和密码：

！[](../images/00184.jpeg)

您可以单击任何超链接以查看更多详细信息并访问每个树或上下文中的每个*叶*。例如，单击 Content.about 以查看有关服务器的完整详细信息，例如确切的版本、构建和完整名称：

！[](../images/00185.jpeg)

注意表的结构。第一列包含属性名称，第二列是该属性的数据类型，最后，第三列是实际运行值。

# 安装 PyVmomi

PyVmomi 可以通过 Python `pip`或不同仓库的系统包进行下载。

对于 Python 安装，请使用以下命令：

```py
pip install -U pyvmomi
```

！[](../images/00186.jpeg)

请注意，从`pip`下载的版本是`6.5.2017.5-1`，与 vSphere 发布的 VMware vSphere 6.5 相对应，但这并不意味着它不能与旧版本的 ESXi 一起使用。例如，我有 VMware vSphere 5.5，它可以与最新的`pyvmomi`版本完美配合使用。

系统安装：

```py
yum install pyvmomi -y
```

Pyvmomi 库使用动态类型，这意味着 IDE 中的智能感知和自动完成功能等功能无法与其一起使用。您必须依赖文档和 MoB 来发现需要哪些类或方法来完成工作，但是一旦您发现它的工作原理，就会很容易使用。

# 使用 pyvmomi 的第一步

首先，您需要通过提供用户名、密码和主机 IP 连接到 ESXi MoB，并开始导航到 MoB 以获取所需的数据。这可以通过使用`SmartConnectNoSSL()`方法来完成：

```py
from pyVim.connect import SmartConnect, Disconnect,SmartConnectNoSSL  ESXi_connection = SmartConnectNoSSL(host="10.10.10.115", user="root", pwd='access123')
```

请注意，还有另一种称为`SmartConnect()`的方法，当建立连接时必须向其提供 SSL 上下文，否则连接将失败。但是，您可以使用以下代码片段请求 SSL 不验证证书，并将此上下文传递给`SmartConnect()`的`sslCContext`参数：

```py
import ssl import requests certificate = ssl.SSLContext(ssl.PROTOCOL_TLSv1) certificate.verify_mode = ssl.CERT_NONE
requests.packages.urllib3.disable_warnings()    
```

为了严谨性和保持代码简洁，我们将使用内置的`SmartConnectNoSSL()`。

接下来，我们将开始探索 MoB 并在`about`对象中获取服务器的完整名称和版本。请记住，它位于`content`对象下，所以我们也需要访问它：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   from pyVim.connect import SmartConnect, Disconnect,SmartConnectNoSSL
ESXi_connection = SmartConnectNoSSL(host="10.10.10.115", user="root", pwd='access123')   full_name = ESXi_connection.content.about.fullName
version = ESXi_connection.content.about.version
print("Server Full name is {}".format(full_name)) print("ESXi version is {}".format(version))
Disconnect(ESXi_connection) 
```

输出如下：

**！[](../images/00187.jpeg)**

现在我们了解了 API 的工作原理。让我们进入一些严肃的脚本，并检索有关我们 ESXi 中部署的虚拟机的一些详细信息。

脚本如下：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   from pyVim.connect import SmartConnect, Disconnect,SmartConnectNoSSL

ESXi_connection = SmartConnectNoSSL(host="10.10.10.115", user="root", pwd='access123')   datacenter = ESXi_connection.content.rootFolder.childEntity[0] #First Datacenter in the ESXi\   virtual_machines = datacenter.vmFolder.childEntity #Access the child inside the vmFolder   print virtual_machines

for machine in virtual_machines:
  print(machine.name)
  try:
  guest_vcpu = machine.summary.config.numCpu
        print("  The Guest vCPU is {}" .format(guest_vcpu))    guest_os = machine.summary.config.guestFullName
        print("  The Guest Operating System is {}" .format(guest_os))    guest_mem = machine.summary.config.memorySizeMB
        print("  The Guest Memory is {}" .format(guest_mem))    ipadd = machine.summary.guest.ipAddress
        print("  The Guest IP Address is {}" .format(ipadd))
  print "================================="
  except:
  print("  Can't get the summary")
```

在前面的示例中，我们做了以下事情：

1.  我们再次通过向`SmartConnectNoSSL`方法提供 ESXi/vCenter 凭据来建立 API 连接到 MoB。

1.  然后，我们通过访问`content`然后`rootFolder`对象和最后`childEntity`来访问数据中心对象。返回的对象是可迭代的，因此我们访问了第一个元素（实验室中只有一个 ESXi 的第一个数据中心）。您可以遍历所有数据中心以获取所有注册数据中心中所有虚拟机的列表。

1.  虚拟机可以通过`vmFolder`和`childEntity`访问。同样，请记住返回的输出是可迭代的，并表示存储在`virtual_machines`变量中的虚拟机列表：

！[](../images/00188.jpeg)

1.  我们遍历了`virtual_machines`对象，并查询了每个元素（每个虚拟机）的 CPU、内存、全名和 IP 地址。这些元素位于`summary`和`config`叶子下的每个虚拟机树中。以下是我们的`AutomationServer`设置的示例：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00189.jpeg)

脚本输出如下：

请注意，在本章的开头我们创建的`python-vm`虚拟机在最后一个截图中显示出来。您可以使用 PyVmomi 作为验证工具，与您的自动化工作流集成，验证虚拟机是否正在运行，并根据返回的输出做出决策。

# 更改虚拟机状态

这次我们将使用`pyvmomi`绑定来更改虚拟机状态。这将通过检查虚拟机名称来完成；然后，我们将导航到 MoB 中的另一个树，并获取运行时状态。最后，我们将根据其当前状态在机器上应用`PowerOn()`或`PowerOff()`函数。这将把机器状态从`On`切换到`Off`，反之亦然。

脚本如下：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   from pyVim.connect import SmartConnect, Disconnect,SmartConnectNoSSL

ESXi_connection = SmartConnectNoSSL(host="10.10.10.115", user="root", pwd='access123')   datacenter = ESXi_connection.content.rootFolder.childEntity[0] #First Datacenter in the ESXi\   virtual_machines = datacenter.vmFolder.childEntity #Access the child inside the vmFolder   for machine in virtual_machines:
  try:
  powerstate = machine.summary.runtime.powerState
        if "python-vm" in machine.name and powerstate == "poweredOff":
  print(machine.name)
  print("     The Guest Power state is {}".format(powerstate))
  machine.PowerOn()
  print("**Powered On the virtual machine**")    elif "python-vm" in machine.name and powerstate == "poweredOn":
  print(machine.name)
  print("     The Guest Power state is {}".format(powerstate))
  machine.PowerOff()
  print("**Powered Off the virtual machine**")
  except:
  print("  Can't execute the task")   Disconnect(ESXi_connection)
```

脚本输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00191.jpeg)

此外，您还可以从 vSphere 客户端验证虚拟机状态，并检查以`python-vm*`开头的主机，将它们的电源状态从`poweredOff`更改为`poweredOn`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00192.gif)

# 还有更多

您可以在 GitHub 的官方 VMware 存储库中找到基于`pyvmomi`绑定的许多有用的脚本（使用不同的语言）（[`github.com/vmware/pyvmomi-community-samples/tree/master/samples`](https://github.com/vmware/pyvmomi-community-samples/tree/master/samples)）。这些脚本由许多使用工具并在日常基础上测试它们的贡献者提供。大多数脚本提供了输入您的配置（如 ESXi IP 地址和凭据）的空间，而无需通过提供它作为参数修改脚本源代码。

# 使用 Ansible Playbook 管理实例

在 VMware 自动化的最后部分，我们将利用 Ansible 工具来管理 VMware 基础架构。Ansible 附带了 20 多个 VMware 模块（[`docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#vmware`](http://docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#vmware)），可以执行许多任务，如管理数据中心、集群和虚拟机。在较旧的 Ansible 版本中，Ansible 使用`pysphere`模块（这不是官方的；模块的作者自 2013 年以来就没有维护过它）来自动化任务。然而，新版本现在支持`pyvmomi`绑定。

Ansible 还支持 VMware SDN 产品（NSX）。Ansible Tower 可以从**VMware vRealize Automation**（**vRA**）访问，允许在不同工具之间实现完整的工作流集成。

以下是 Ansible Playbook：

```py
- name: Provision New VM
  hosts: localhost
  connection: local
  vars:
  - VM_NAME: DevOps
  - ESXi_HOST: 10.10.10.115
  - USERNAME: root
  - PASSWORD: access123
  tasks:   - name: current time
  command: date +%D
  register: current_time
  - name: Check for vSphere access parameters
  fail: msg="Must set vsphere_login and vsphere_password in a Vault"
  when: (USERNAME is not defined) or (PASSWORD is not defined)
  - name: debug vCenter hostname
  debug: msg="vcenter_hostname = '{{ ESXi_HOST }}'"
  - name: debug the time
  debug: msg="Time is = '{{ current_time }}'"    - name: "Provision the VM"
  vmware_guest:
 hostname: "{{ ESXi_HOST }}"
  username: "{{ USERNAME }}"
  password: "{{ PASSWORD }}"
  datacenter: ha-datacenter
  validate_certs: False
  name: "{{ VM_NAME }}"
  folder: /
  guest_id: centos64Guest
  state: poweredon
  force: yes
  disk:
  - size_gb: 100
  type: thin
  datastore: datastore1    networks:
  - name: network1
  device_type: e1000 #            mac: ba:ba:ba:ba:01:02 #            wake_on_lan: True    - name: network2
  device_type: e1000    hardware:
 memory_mb: 4096
  num_cpus: 4
  num_cpu_cores_per_socket: 2
  hotadd_cpu: True
  hotremove_cpu: True
  hotadd_memory: True
  scsi: lsilogic
  cdrom:
 type: "iso"
  iso_path: "[datastore1] ISO Room/CentOS-7-x86_64-Minimal-1708.iso"
  register: result 
```

在前面的 playbook 中，我们可以看到以下内容：

+   playbook 的第一部分是在`vars`部分中定义 ESXi 主机 IP 和凭据，并在后续任务中使用它们。

+   然后我们编写了一个简单的验证，如果未提供用户名或密码，就会使 playbook 失败。

+   然后，我们使用 ansible 提供的`vmware_guest`模块（[`docs.ansible.com/ansible/2.4/vmware_guest_module.html`](https://docs.ansible.com/ansible/2.4/vmware_guest_module.html)）来提供虚拟机。在这个任务中，我们提供了所需的信息，比如磁盘大小和 CPU 和内存方面的硬件。请注意，我们将虚拟机的状态定义为`poweredon`，因此 ansible 将在创建后启动虚拟机。

+   磁盘、网络、硬件和 CD-ROM 都是`vmware_guest`模块中的关键，用于描述在 VMware ESXi 上生成新 VM 所需的虚拟化硬件规格。

使用以下命令运行 playbook：

```py
# ansible-playbook esxi_create_vm.yml -vv
```

以下是 Playbook 输出的截图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00193.jpeg)

您可以在 vSphere 客户端中验证虚拟机的创建和与 CentOS ISO 文件的绑定：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00194.jpeg)

您还可以通过更改剧本中“状态”中的值来更改现有虚拟机的状态，并从`poweredon`、`poweredoff`、`restarted`、`absent`、`suspended`、`shutdownguest`和`rebootguest`中进行选择。

# 摘要

VMware 产品广泛用于 IT 基础设施中，为运行应用程序和工作负载提供虚拟化环境。与此同时，VMware 还提供了许多语言的 API 绑定，可用于自动化管理任务。在下一章中，我们将探索另一个名为 OpenStack 的虚拟化框架，该框架依赖于红帽公司的 KVM hypervisor。


# 第十五章：与 OpenStack API 交互

长期以来，IT 基础设施依赖于商业软件（来自 VMWare、Microsoft 和 Citrix 等供应商）提供运行工作负载和管理资源（如计算、存储和网络）的虚拟环境。然而，IT 行业正在迈向云时代，工程师正在将工作负载和应用程序迁移到云（无论是公共还是私有），这需要一个能够管理所有应用程序资源的新框架，并提供一个开放和强大的 API 接口，以与其他应用程序的外部调用进行交互。

OpenStack 提供了开放访问和集成，以管理所有计算、存储和网络资源，避免在构建云时出现供应商锁定。它可以控制大量的计算节点、存储阵列和网络设备，无论每个资源的供应商如何，并在所有资源之间提供无缝集成。OpenStack 的核心思想是将应用于底层基础设施的所有配置抽象为一个负责管理资源的*项目*。因此，您将找到一个管理计算资源的项目（称为 Nova），另一个提供实例网络的项目（neutron），以及与不同存储类型交互的项目（Swift 和 Cinder）。

您可以在此链接中找到当前 OpenStack 项目的完整列表

[`www.OpenStack.org/software/project-navigator/`](https://www.openstack.org/software/project-navigator/)

此外，OpenStack 为应用程序开发人员和系统管理员提供统一的 API 访问，以编排资源创建。

在本章中，我们将探索 OpenStack 的新开放世界，并学习如何利用 Python 和 Ansible 与其交互。

本章将涵盖以下主题：

+   了解 RESTful web 服务

+   设置环境

+   向 OpenStack 发送请求

+   从 Python 创建工作负载

+   使用 Ansible 管理 OpenStack 实例

# 了解 RESTful web 服务

**表述状态转移**（**REST**）依赖于 HTTP 协议在客户端和服务器之间传输消息。HTTP 最初设计用于在请求时从 Web 服务器（服务器）向浏览器（客户端）传递 HTML 页面。页面代表用户想要访问的一组资源，并由**统一资源标识符**（**URI**）请求。

HTTP 请求通常包含一个方法，该方法指示需要在资源上执行的操作类型。例如，当从浏览器访问网站时，您可以看到（在下面的屏幕截图中）方法是`GET`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00195.jpeg)

以下是最常见的 HTTP 方法及其用法：

| HTTP 方法 | 操作 |
| --- | --- |
| `GET` | 客户端将要求服务器检索资源。 |
| `POST` | 客户端将指示服务器创建新资源。 |
| `PUT` | 客户端将要求服务器修改/更新资源。 |
| `DELETE` | 客户端将要求服务器删除资源。 |

应用程序开发人员可以公开其应用程序的某些资源，以供外部世界的客户端使用。携带请求从客户端到服务器并返回响应的传输协议是 HTTP。它负责保护通信并使用服务器接受的适当数据编码机制对数据包进行编码，并且在两者之间进行无状态通信。

另一方面，数据包有效载荷通常以 XML 或 JSON 编码，以表示服务器处理的请求结构以及客户端偏好的响应方式。

世界各地有许多公司为开发人员提供其数据的公共访问权限，实时提供。例如，Twitter API（[`developer.twitter.com/`](https://developer.twitter.com/)）提供实时数据获取，允许其他开发人员在第三方应用程序中使用数据，如广告、搜索和营销。谷歌（[`developers.google.com/apis-explorer/#p/discovery/v1/`](https://developers.google.com/apis-explorer/#p/discovery/v1/)）、LinkedIn（[`developer.linkedin.com/`](https://developer.linkedin.com/)）和 Facebook（[`developers.facebook.com/`](https://developers.facebook.com/)）等大公司也是如此。

对 API 的公共访问通常限制为特定数量的请求，无论是每小时还是每天，对于单个应用程序，以免过度使用公共资源。

Python 提供了大量的工具和库来消耗 API、编码消息和解析响应。例如，Python 有一个`requests`包，可以格式化并发送 HTTP 请求到外部资源。它还有工具来解析 JSON 格式的响应并将其转换为 Python 中的标准字典。

Python 还有许多框架可以将您的资源暴露给外部世界。`Django`和`Flask`是最好的之一，可以作为全栈框架。

# 设置环境

OpenStack 是一个免费的开源项目，用于**基础设施即服务**（**IaaS**），可以控制 CPU、内存和存储等硬件资源，并为许多供应商构建和集成插件提供一个开放的框架。

为了设置我们的实验室，我将使用最新的`OpenStack-rdo`版本（在撰写时），即 Queens，并将其安装到 CentOS 7.4.1708 上。安装步骤非常简单，可以在[`www.rdoproject.org/install/packstack/`](https://www.rdoproject.org/install/packstack/)找到。

我们的环境包括一台具有 100GB 存储、12 个 vCPU 和 32GB RAM 的机器。该服务器将包含 OpenStack 控制器、计算和 neutron 角色在同一台服务器上。OpenStack 服务器连接到具有我们自动化服务器的相同交换机和相同子网。请注意，这在生产环境中并不总是这样，但您需要确保运行 Python 代码的服务器可以访问 OpenStack。

实验室拓扑如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00196.jpeg)

# 安装 rdo-OpenStack 软件包

在 RHEL 7.4 和 CentOS 上安装 rdo-OpenStack 的步骤如下：

# 在 RHEL 7.4 上

首先确保您的系统是最新的，然后从网站安装`rdo-release.rpm`以获取最新版本。最后，安装`OpenStack-packstack`软件包，该软件包将自动化 OpenStack 安装，如下段所示：

```py
$ sudo yum install -y https://www.rdoproject.org/repos/rdo-release.rpm
$ sudo yum update -y
$ sudo yum install -y OpenStack-packstack
```

# 在 CentOS 7.4 上

首先确保您的系统是最新的，然后安装 rdoproject 以获取最新版本。最后，安装`centos-release-OpenStack-queens`软件包，该软件包将自动化 OpenStack 安装，如下段所示：

```py
$ sudo yum install -y centos-release-OpenStack-queens
$ sudo yum update -y
$ sudo yum install -y OpenStack-packstack
```

# 生成答案文件

现在，您需要生成包含部署参数的答案文件。这些参数中的大多数都是默认值，但我们将更改一些内容：

```py
# packstack --gen-answer-file=/root/EnterpriseAutomation
```

# 编辑答案文件

使用您喜欢的编辑器编辑`EnterpriseAutomtion`文件，并更改以下内容：

```py
CONFIG_DEFAULT_PASSWORD=access123 CONFIG_CEILOMETER_INSTALL=n CONFIG_AODH_INSTALL=n CONFIG_KEYSTONE_ADMIN_PW=access123 CONFIG_PROVISION_DEMO=n 
```

`CELIOMETER`和`AODH`是 OpenStack 生态系统中的可选项目，可以在实验室环境中忽略。

我们还设置了一个用于生成临时令牌以访问 API 资源并访问 OpenStack GUI 的`KEYSTONE`密码

# 运行 packstack

保存文件并通过`packstack`运行安装：

```py
# packstack answer-file=EnterpriseAutomation
```

此命令将从 Queens 存储库下载软件包并安装 OpenStack 服务，然后启动它们。安装成功完成后，将在控制台上打印以下消息：

```py
 **** Installation completed successfully ******

Additional information:
 * Time synchronization installation was skipped. Please note that unsynchronized time on server instances might be problem for some OpenStack components.
 * File /root/keystonerc_admin has been created on OpenStack client host 10.10.10.150\. To use the command line tools you need to source the file.
 * To access the OpenStack Dashboard browse to http://10.10.10.150/dashboard .
Please, find your login credentials stored in the keystonerc_admin in your home directory.
 * The installation log file is available at: /var/tmp/packstack/20180410-155124-CMpsKR/OpenStack-setup.log
 * The generated manifests are available at: /var/tmp/packstack/20180410-155124-CMpsKR/manifests
```

# 访问 OpenStack GUI

现在您可以使用`http://<server_ip_address>/dashboard`访问 OpenStack GUI。凭证将是 admin 和 access123（取决于您在之前步骤中在`CONFIG_KEYSTONE_ADMIN_PW`中写入了什么）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00197.gif)

我们的云现在已经启动运行，准备接收请求。

# 向 OpenStack keystone 发送请求

OpenStack 包含一系列服务，这些服务共同工作以管理虚拟机的创建、读取、更新和删除（CRUD）操作。每个服务都可以将其资源暴露给外部请求进行消费。例如，`nova`服务负责生成虚拟机并充当一个 hypervisor 层（虽然它本身不是一个 hypervisor，但可以控制其他 hypervisors，如 KVM 和 vSphere）。另一个服务是`glance`，负责以 ISO 或 qcow2 格式托管实例镜像。`neutron`服务负责为生成的实例提供网络服务，并确保位于不同租户（项目）上的实例相互隔离，而位于相同租户上的实例可以通过覆盖网络（VxLAN 或 GRE）相互访问。

为了访问上述每个服务的 API，您需要具有用于特定时间段的经过身份验证的令牌。这就是`keystone`的作用，它提供身份服务并管理每个用户的角色和权限。

首先，我们需要在自动化服务器上安装 Python 绑定。这些绑定包含用于访问每个服务并使用从 KEYSTONE 生成的令牌进行身份验证的 Python 代码。此外，绑定包含每个项目的支持操作（如创建/删除/更新/列出）：

```py
yum install -y gcc openssl-devel python-pip python-wheel
pip install python-novaclient
pip install python-neutronclient
pip install python-keystoneclient
pip install python-glanceclient
pip install python-cinderclient
pip install python-heatclient
pip install python-OpenStackclient
```

请注意，Python 客户端名称为`python-<service_name>client`

您可以将其下载到站点的全局包或 Python `virtualenv`环境中。然后，您将需要 OpenStack 管理员权限，这些权限可以在 OpenStack 服务器内的以下路径中找到：

```py
cat /root/keystonerc_admin
unset OS_SERVICE_TOKEN
export OS_USERNAME=admin
export OS_PASSWORD='access123'
export OS_AUTH_URL=http://10.10.10.150:5000/v3
export PS1='[\u@\h \W(keystone_admin)]\$ '

export OS_PROJECT_NAME=admin
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_IDENTITY_API_VERSION=3
```

请注意，当我们与 OpenStack keystone 服务通信时，我们将在`OS_AUTH_URL`和`OS_IDENTITY_API_VERSION`参数中使用 keystone 版本 3。大多数 Python 客户端与旧版本兼容，但需要您稍微更改脚本。在令牌生成期间还需要其他参数，因此请确保您可以访问`keystonerc_admin`文件。还可以在同一文件中的`OS_USERNAME`和`OS_PASSWORD`中找到访问凭证。

我们的 Python 脚本将如下所示：

```py
from keystoneauth1.identity import v3
from keystoneauth1 import session

auth = v3.Password(auth_url="http://10.10.10.150:5000/v3",
  username="admin",
  password="access123",
  project_name="admin",
  user_domain_name="Default",
  project_domain_name="Default")
sess = session.Session(auth=auth, verify=False)
print(sess) 
```

在上述示例中，以下内容适用：

+   `python-keystoneclient`使用`v3`类（反映了 keystone API 版本）向 keystone API 发出请求。此类可在`keystoneayth1.identity`内使用。

+   然后，我们将从`keystonerc_admin`文件中获取的完整凭证提供给`auth`变量。

+   最后，我们建立了会话，使用 keystone 客户端内的会话管理器。请注意，我们将`verify`设置为`False`，因为我们不使用证书来生成令牌。否则，您可以提供证书路径。

+   生成的令牌可以用于任何服务，并将持续一个小时，然后过期。此外，如果更改用户角色，令牌将立即过期，而不必等待一个小时。

OpenStack 管理员可以在`/etc/keystone/keystone.conf`文件中配置`admin_token`字段，该字段永不过期。但出于安全原因，这在生产环境中不被推荐。

如果您不想将凭证存储在 Python 脚本中，可以将它们存储在`ini`文件中，并使用`configparser`模块加载它们。首先，在自动化服务器上创建一个`creds.ini`文件，并赋予适当的 Linux 权限，以便只能使用您自己的帐户打开它。

```py
#vim /root/creds.ini [os_creds]  auth_url="http://10.10.10.150:5000/v3" username="admin" password="access123" project_name="admin" user_domain_name="Default" project_domain_name="Default"
```

修改后的脚本如下：

```py
from keystoneauth1.identity import v3
from keystoneauth1 import session
import ConfigParser
config = ConfigParser.ConfigParser() config.read("/root/creds.ini") auth = v3.Password(auth_url=config.get("os_creds","auth_url"),
  username=config.get("os_creds","username"),
  password=config.get("os_creds","password"),
  project_name=config.get("os_creds","project_name"),
  user_domain_name=config.get("os_creds","user_domain_name"),
  project_domain_name=config.get("os_creds","project_domain_name")) sess = session.Session(auth=auth, verify=False) print(sess)   
```

`configparser`模块将解析`creds.ini`文件并查看文件内部的`os_creds`部分。然后，它将使用`get()`方法获取每个参数前面的值。

`config.get()`方法将接受两个参数。第一个参数是`.ini`文件内的部分名称，第二个是参数名称。该方法将返回与参数关联的值。

此方法应该为您的云凭据提供额外的安全性。保护文件的另一种有效方法是使用 Linux 的`source`命令将`keystonerc_admin`文件加载到环境变量中，并使用`os`模块内的`environ()`方法读取凭据。

# 从 Python 创建实例

要使实例运行起来，OpenStack 实例需要三个组件。由`glance`提供的引导镜像，由`neutron`提供的网络端口，最后是由`nova`项目提供的定义分配给实例的 CPU 数量、RAM 数量和磁盘大小的计算 flavor。

# 创建图像

我们将首先下载一个`cirros`图像到自动化服务器。`cirros`是一个轻量级的基于 Linux 的图像，被许多 OpenStack 开发人员和测试人员用来验证 OpenStack 服务的功能：

```py
#cd /root/ ; wget http://download.cirros-cloud.net/0.4.0/cirros-0.4.0-x86_64-disk.img
```

然后，我们将使用`glanceclient`将图像上传到 OpenStack 图像存储库。请注意，我们需要首先具有 keystone 令牌和会话参数，以便与`glance`通信，否则，`glance`将不接受我们的任何 API 请求。

脚本将如下所示：

```py
from keystoneauth1.identity import v3
from keystoneauth1 import session
from glanceclient import client as gclient
from pprint import pprint

auth = v3.Password(auth_url="http://10.10.10.150:5000/v3",
  username="admin",
  password="access123",
  project_name="admin",
  user_domain_name="Default",
  project_domain_name="Default")     sess = session.Session(auth=auth, verify=False)    #Upload the image to the Glance  glance = gclient.Client('2', session=sess)   image = glance.images.create(name="CirrosImage",
  container_format='bare',
  disk_format='qcow2',
  )   glance.images.upload(image.id, open('/root/cirros-0.4.0-x86_64-disk.img', 'rb'))   
```

在上面的示例中，适用以下内容：

+   由于我们正在与`glance`（图像托管项目）通信，因此我们将从安装的`glanceclient`模块导入`client`。

+   使用相同的 keystone 脚本生成包含 keystone 令牌的`sess`。

+   我们创建了 glance 参数，该参数使用`glance`初始化客户端管理器，并提供版本（`版本 2`）和生成的令牌。

+   您可以通过访问 OpenStack GUI | API Access 选项卡来查看所有支持的 API 版本，如下面的屏幕截图所示。还要注意每个项目的支持版本。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00198.jpeg)

+   glance 客户端管理器旨在在 glance OpenStack 服务上运行。指示管理器使用名称`CirrosImage`创建一个磁盘类型为`qcow2`格式的图像。

+   最后，我们将以二进制形式打开下载的图像，使用'rb'标志，并将其上传到创建的图像中。现在，`glance`将图像导入到图像存储库中新创建的文件中。

您可以通过两种方式验证操作是否成功：

1.  执行`glance.images.upload()`后如果没有打印出错误，这意味着请求格式正确，并已被 OpenStack `glance` API 接受。

1.  运行`glance.images.list()`。返回的输出将是一个生成器，您可以遍历它以查看有关上传图像的更多详细信息：

```py
print("==========================Image Details==========================") for image in glance.images.list(name="CirrosImage"):
  pprint(image) 
{u'checksum': u'443b7623e27ecf03dc9e01ee93f67afe',
 u'container_format': u'bare',
 u'created_at': u'2018-04-11T03:11:58Z',
 u'disk_format': u'qcow2',
 u'file': u'/v2/images/3c2614b0-e53c-4be1-b99d-bbd9ce14b287/file',
 u'id': u'3c2614b0-e53c-4be1-b99d-bbd9ce14b287',
 u'min_disk': 0,
 u'min_ram': 0,
 u'name': u'CirrosImage',
 u'owner': u'8922dc52984041af8fe22061aaedcd13',
 u'protected': False,
 u'schema': u'/v2/schemas/image',
 u'size': 12716032,
 u'status': u'active',
 u'tags': [],
 u'updated_at': u'2018-04-11T03:11:58Z',
 u'virtual_size': None,
 u'visibility': u'shared'}
```

# 分配 flavor

Flavors 用于确定实例的 CPU、内存和存储大小。OpenStack 带有一组预定义的 flavors，具有从微小到超大的不同大小。对于`cirros`图像，我们将使用小型 flavor，它具有 2GB RAM，1 个 vCPU 和 20GB 存储。访问 flavors 没有独立的 API 客户端；而是作为`nova`客户端的一部分。

您可以在 OpenStack GUI | Admin | Flavors 中查看所有可用的内置 flavors：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00199.gif)

脚本将如下所示：

```py
from keystoneauth1.identity import v3
from keystoneauth1 import session
from novaclient import client as nclient
from pprint import pprint

auth = v3.Password(auth_url="http://10.10.10.150:5000/v3",
  username="admin",
  password="access123",
  project_name="admin",
  user_domain_name="Default",
  project_domain_name="Default")   sess = session.Session(auth=auth, verify=False)   nova = nclient.Client(2.1, session=sess) instance_flavor = nova.flavors.find(name="m1.small") print("==========================Flavor Details==========================") pprint(instance_flavor)
```

在上述脚本中，适用以下内容：

+   由于我们将与`nova`（计算服务）通信以检索 flavor，因此我们将导入`novaclient`模块作为`nclient`。

+   使用相同的 keystone 脚本生成包含 keystone 令牌的`sess`。

+   我们创建了`nova`参数，用它来初始化具有`nova`的客户端管理器，并为客户端提供版本（版本 2.1）和生成的令牌。

+   最后，我们使用`nova.flavors.find()`方法来定位所需的规格，即`m1.small`。名称必须与 OpenStack 中的名称完全匹配，否则将抛出错误。

# 创建网络和子网

为实例创建网络需要两件事：网络本身和将子网与之关联。首先，我们需要提供网络属性，例如 ML2 驱动程序（Flat、VLAN、VxLAN 等），区分在同一接口上运行的网络之间的分段 ID，MTU 和物理接口，如果实例流量需要穿越外部网络。其次，我们需要提供子网属性，例如网络 CIDR、网关 IP、IPAM 参数（如果定义了 DHCP/DNS 服务器）以及与子网关联的网络 ID，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00200.jpeg)

现在我们将开发一个 Python 脚本来与 neutron 项目进行交互，并创建一个带有子网的网络

```py
from keystoneauth1.identity import v3
from keystoneauth1 import session
import neutronclient.neutron.client as neuclient

auth = v3.Password(auth_url="http://10.10.10.150:5000/v3",
  username="admin",
  password="access123",
  project_name="admin",
  user_domain_name="Default",
  project_domain_name="Default")   sess = session.Session(auth=auth, verify=False)   neutron = neuclient.Client(2, session=sess)   # Create Network   body_network = {'name': 'python_network',
  'admin_state_up': True,
 #'port_security_enabled': False,
  'shared': True,
  # 'provider:network_type': 'vlan|vxlan',
 # 'provider:segmentation_id': 29 # 'provider:physical_network': None, # 'mtu': 1450,  } neutron.create_network({'network':body_network}) network_id = neutron.list_networks(name="python_network")["networks"][0]["id"]     # Create Subnet   body_subnet = {
  "subnets":[
  {
  "name":"python_network_subnet",
  "network_id":network_id,
  "enable_dhcp":True,
  "cidr": "172.16.128.0/24",
  "gateway_ip": "172.16.128.1",
  "allocation_pools":[
  {
  "start": "172.16.128.10",
  "end": "172.16.128.100"
  }
  ],
  "ip_version": 4,
  }
  ]
  } neutron.create_subnet(body=body_subnet) 
```

在上述脚本中，以下内容适用：

+   由于我们将与`neutron`（网络服务）通信来创建网络和关联子网，我们将导入`neutronclient`模块作为`neuclient`。

+   相同的 keystone 脚本用于生成`sess`，该`sess`保存后来用于访问 neutron 资源的 keystone 令牌。

+   我们将创建`neutron`参数，用它来初始化具有 neutron 的客户端管理器，并为其提供版本（版本 2）和生成的令牌。

+   然后，我们创建了两个 Python 字典，`body_network`和`body_subnet`，它们分别保存了网络和子网的消息主体。请注意，字典键是静态的，不能更改，而值可以更改，并且通常来自外部门户系统或 Excel 表格，具体取决于您的部署。此外，我对在网络创建过程中不必要的部分进行了评论，例如`provider:physical_network`和`provider:network_type`，因为我们的`cirros`镜像不会与提供者网络（在 OpenStack 域之外定义的网络）通信，但这里提供了参考。

+   最后，通过`list_networks()`方法获取`network_id`，并将其作为值提供给`body_subnet`变量中的`network_id`键，将子网和网络关联在一起。

# 启动实例

最后一部分是将所有内容粘合在一起。我们有引导镜像、实例规格和连接机器与其他实例的网络。我们准备使用`nova`客户端启动实例（记住`nova`负责虚拟机的生命周期和 VM 上的 CRUD 操作）：

```py

print("=================Launch The Instance=================")   image_name = glance.images.get(image.id)   network1 = neutron.list_networks(name="python_network") instance_nics = [{'net-id': network1["networks"][0]["id"]}]   server = nova.servers.create(name = "python-instance",
  image = image_name.id,
  flavor = instance_flavor.id,
  nics = instance_nics,) status = server.status
while status == 'BUILD':
  print("Sleeping 5 seconds till the server status is changed")
  time.sleep(5)
  instance = nova.servers.get(server.id)
  status = instance.status
    print(status) print("Current Status is: {0}".format(status))
```

在上述脚本中，我们使用了`nova.servers.create()`方法，并传递了生成实例所需的所有信息（实例名称、操作系统、规格和网络）。此外，我们实现了一个轮询机制，用于轮询 nova 服务的服务器当前状态。如果服务器仍处于`BUILD`阶段，则脚本将休眠五秒，然后再次轮询。当服务器状态更改为`ACTIVE`或`FAILURE`时，循环将退出，并在最后打印服务器状态。

脚本的输出如下：

```py
Sleeping 5 seconds till the server status is changed
Sleeping 5 seconds till the server status is changed
Sleeping 5 seconds till the server status is changed
Current Status is: ACTIVE
```

此外，您可以从 OpenStack GUI | 计算 | 实例中检查实例：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00201.gif)

# 从 Ansible 管理 OpenStack 实例

Ansible 提供了可以管理 OpenStack 实例生命周期的模块，就像我们使用 API 一样。您可以在[`docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#OpenStack`](http://docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#openstack)找到支持的模块的完整列表。

所有 OpenStack 模块都依赖于名为`shade`的 Python 库（[`pypi.python.org/pypi/shade`](https://pypi.python.org/pypi/shade)），该库提供了对 OpenStack 客户端的包装。

一旦您在自动化服务器上安装了`shade`，您将可以访问`os-*`模块，这些模块可以操作 OpenStack 配置，比如`os_image`（处理 OpenStack 镜像），`os_network`（创建网络），`os_subnet`（创建并关联子网到创建的网络），`os_nova_flavor`（根据 RAM、CPU 和磁盘创建 flavors），最后是`os_server`模块（启动 OpenStack 实例）。

# 安装 Shade 和 Ansible

在自动化服务器上，使用 Python 的`pip`来下载和安装`shade`，以及所有依赖项：

```py
pip install shade
```

安装完成后，您将在 Python 的正常`site-packages`下拥有`shade`，但我们将使用 Ansible。

此外，如果您之前没有在自动化服务器上安装 Ansible，您将需要安装 Ansible：

```py
# yum install ansible -y
```

通过从命令行查询 Ansible 版本来验证 Ansible 是否已成功安装：

```py
[root@AutomationServer ~]# ansible --version
ansible 2.5.0
 config file = /etc/ansible/ansible.cfg
 configured module search path = [u'/root/.ansible/plugins/modules', u'/usr/share/ansible/plugins/modules']
 ansible python module location = /usr/lib/python2.7/site-packages/ansible
 executable location = /usr/bin/ansible
 python version = 2.7.5 (default, Aug  4 2017, 00:39:18) [GCC 4.8.5 20150623 (Red Hat 4.8.5-16)]
```

# 构建 Ansible playbook

正如我们在第十三章中所看到的，*用于管理的 Ansible*，依赖于一个 YAML 文件，其中包含了您需要针对清单中的主机执行的一切。在这种情况下，我们将指示 playbook 在自动化服务器上建立与`shade`库的本地连接，并提供`keystonerc_admin`凭据，以帮助`shade`向我们的 OpenStack 服务器发送请求。

playbook 脚本如下：

```py
--- - hosts: localhost
  vars:
 os_server: '10.10.10.150'
  gather_facts: yes
  connection: local
  environment:
 OS_USERNAME: admin
  OS_PASSWORD: access123
  OS_AUTH_URL: http://{{ os_server }}:5000/v3
  OS_TENANT_NAME: admin
  OS_REGION_NAME: RegionOne
  OS_USER_DOMAIN_NAME: Default
  OS_PROJECT_DOMAIN_NAME: Default    tasks:
  - name: "Upload the Cirros Image"
  os_image:
 name: Cirros_Image
  container_format: bare
  disk_format: qcow2
  state: present
  filename: /root/cirros-0.4.0-x86_64-disk.img
  ignore_errors: yes    - name: "CREATE CIRROS_FLAVOR"
  os_nova_flavor:
 state: present
  name: CIRROS_FLAVOR
  ram: 2048
  vcpus: 4
  disk: 35
  ignore_errors: yes    - name: "Create the Cirros Network"
  os_network:
 state: present
  name: Cirros_network
  external: True
  shared: True
  register: Cirros_network
  ignore_errors: yes      - name: "Create Subnet for The network Cirros_network"
  os_subnet:
 state: present
  network_name: "{{ Cirros_network.id }}"
  name: Cirros_network_subnet
  ip_version: 4
  cidr: 10.10.128.0/18
  gateway_ip: 10.10.128.1
  enable_dhcp: yes
  dns_nameservers:
  - 8.8.8.8
  register: Cirros_network_subnet
  ignore_errors: yes      - name: "Create Cirros Machine on Compute"
  os_server:
 state: present
  name: ansible_instance
  image: Cirros_Image
  flavor: CIRROS_FLAVOR
  security_groups: default
  nics:
  - net-name: Cirros_network
  ignore_errors: yes 
```

在 playbook 中，我们使用`os_*`模块将镜像上传到 OpenStack 的`glance`服务器，创建一个新的 flavor（而不是使用内置的 flavor），并创建与子网关联的网络；然后，我们在`os_server`中将所有内容粘合在一起，该模块与`nova`服务器通信以生成机器。

请注意，主机将是本地主机（或托管`shade`库的机器名称），同时我们在环境变量中添加了 OpenStack keystone 凭据。

# 运行 playbook

将 playbook 上传到自动化服务器并执行以下命令来运行它：

```py
ansible-playbook os_playbook.yml
```

playbook 的输出将如下所示：

```py
 [WARNING]: No inventory was parsed, only implicit localhost is available

 [WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'

PLAY [localhost] ****************************************************************************

TASK [Gathering Facts] **********************************************************************
ok: [localhost]

TASK [Upload the Cirros Image] **************************************************************
changed: [localhost]

TASK [CREATE CIRROS_FLAVOR] *****************************************************************
ok: [localhost]

TASK [Create the Cirros Network] ************************************************************
changed: [localhost]

TASK [Create Subnet for The network Cirros_network] *****************************************
changed: [localhost]

TASK [Create Cirros Machine on Compute] *****************************************************
changed: [localhost]

PLAY RECAP **********************************************************************************
localhost                  : ok=6    changed=4    unreachable=0    failed=0   
```

您可以访问 OpenStack GUI 来验证实例是否是从 Ansible playbook 创建的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00202.gif)

# 摘要

如今，IT 行业正在尽可能地避免供应商锁定，转向开源世界。OpenStack 为我们提供了窥视这个世界的窗口；许多大型组织和电信运营商正在考虑将其工作负载迁移到 OpenStack，以在其数据中心构建私有云。然后，他们可以构建自己的工具来与 OpenStack 提供的开源 API 进行交互。

在下一章中，我们将探索另一个（付费的）公共亚马逊云，并学习如何利用 Python 来自动化实例创建。


# 第十六章：使用 Boto3 自动化 AWS

在之前的章节中，我们探讨了如何使用 Python 自动化 OpenStack 和 VMware 私有云。我们将继续通过自动化最受欢迎的公共云之一——亚马逊网络服务（AWS）来继续我们的云自动化之旅。在本章中，我们将探讨如何使用 Python 脚本创建 Amazon Elastic Compute Cloud（EC2）和 Amazon Simple Storage Systems（S3）。

本章将涵盖以下主题：

+   AWS Python 模块

+   管理 AWS 实例

+   自动化 AWS S3 服务

# AWS Python 模块

Amazon EC2 是一个可扩展的计算系统，用于为托管不同虚拟机（例如 OpenStack 生态系统中的 nova-compute 项目）提供虚拟化层。它可以与其他服务（如 S3、Route 53 和 AMI）通信，以实例化实例。基本上，您可以将 EC2 视为其他在虚拟基础设施管理器上设置的虚拟化程序（如 KVM 和 VMware）之上的抽象层。EC2 将接收传入的 API 调用，然后将其转换为适合每个虚拟化程序的调用。

Amazon Machine Image（AMI）是一个打包的镜像系统，其中包含了启动虚拟机所需的操作系统和软件包（类似于 OpenStack 中的 Glance）。您可以从现有的虚拟机创建自己的 AMI，并在需要在其他基础设施上复制这些机器时使用它，或者您可以简单地从互联网或亚马逊市场上选择公开可用的 AMI。我们需要从亚马逊网络控制台获取 AMI ID，并将其添加到我们的 Python 脚本中。

AWS 设计了一个名为 Boto3 的 SDK（[`github.com/boto/boto3`](https://github.com/boto/boto3)），允许 Python 开发人员编写与不同服务的 API 进行交互和消费的脚本和软件，如 Amazon EC2 和 Amazon S3。该库是为提供对 Python 2.6.5、2.7+和 3.3 的本地支持而编写的。

Boto3 的主要功能在官方文档中有描述，网址为[`boto3.readthedocs.io/en/latest/guide/new.html`](https://boto3.readthedocs.io/en/latest/guide/new.html)，以下是一些重要功能：

+   资源：高级、面向对象的接口。

+   集合：用于迭代和操作资源组的工具。

+   客户端：低级服务连接。

+   分页器：自动分页响应。

+   等待者：一种暂停执行直到达到某种状态或发生故障的方式。每个 AWS 资源都有一个等待者名称，可以使用`<resource_name>.waiter_names`访问。

# Boto3 安装

在连接到 AWS 之前需要一些东西：

1.  首先，您需要一个具有创建、修改和删除基础设施权限的亚马逊管理员帐户。

1.  其次，安装用于与 AWS 交互的`boto3` Python 模块。您可以通过转到 AWS 身份和访问管理（IAM）控制台并添加新用户来创建一个专用于发送 API 请求的用户。您应该在“访问类型”部分下看到“编程访问”选项。 

1.  现在，您需要分配一个允许在亚马逊服务中具有完全访问权限的策略，例如 EC2 和 S3。通过单击“附加现有策略到用户”并将 AmazonEC2FullAccess 和 AmazonS3FullAccess 策略附加到用户名来实现。

1.  最后，点击“创建用户”以添加具有配置选项和策略的用户。

您可以在 AWS 上注册免费的基础套餐帐户，这将使您在 12 个月内获得亚马逊提供的许多服务。免费访问可以在[`aws.amazon.com/free/`](https://aws.amazon.com/free/)上获得。

在使用 Python 脚本管理 AWS 时，访问密钥 ID 用于发送 API 请求并从 API 服务器获取响应。我们不会使用用户名或密码发送请求，因为它们很容易被他人捕获。此信息是通过下载创建用户名后出现的文本文件获得的。重要的是将此文件放在安全的位置并为其提供适当的 Linux 权限，以打开和读取文件内容。

另一种方法是在您的家目录下创建一个`.aws`目录，并在其中放置两个文件：`credentials`和`config`。第一个文件将同时包含访问密钥 ID 和秘密访问 ID。

`~/.aws/credentials`如下所示：

```py
[default]
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

第二个文件将保存用户特定的配置，例如首选数据中心（区域），用于托管创建的虚拟机。在下面的示例中，我们指定要在`us-west-2`数据中心托管我们的机器。

配置文件`~/.aws/config`如下所示：

```py
[default]
region=us-west-2
```

现在，安装`boto3`需要使用通常的`pip`命令来获取最新的`boto3`版本：

```py
pip install boto3
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00203.jpeg)

要验证模块是否成功安装，请在 Python 控制台中导入`boto3`，您不应该看到任何导入错误报告：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00204.jpeg)

# 管理 AWS 实例

现在，我们准备使用`boto3`创建我们的第一个虚拟机。正如我们所讨论的，我们需要 AMI，我们将从中实例化一个实例。将 AMI 视为 Python 类；创建一个实例将从中创建一个对象。我们将使用 Amazon Linux AMI，这是由 Amazon 维护的特殊 Linux 操作系统，用于部署 Linux 机器而不收取任何额外费用。您可以在每个区域找到完整的 AMI ID，网址为[`aws.amazon.com/amazon-linux-ami/`](https://aws.amazon.com/amazon-linux-ami/)：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00205.jpeg)

```py
import boto3
ec2 = boto3.resource('ec2') instance = ec2.create_instances(ImageId='ami-824c4ee2', MinCount=1, MaxCount=1, InstanceType='m5.xlarge',
  Placement={'AvailabilityZone': 'us-west-2'},
  ) print(instance[0])   
```

在上面的示例中，以下内容适用：

1.  我们导入了之前安装的`boto3`模块。

1.  然后，我们指定了要与之交互的资源类型，即 EC2，并将其分配给`ec2`对象。

1.  现在，我们有资格使用`create_instance()`方法，并为其提供实例参数，例如`ImageID`和`InstanceType`（类似于 OpenStack 中的 flavor，它确定了计算和内存方面的实例规格），以及我们应该在`AvailabilityZone`中创建此实例。

1.  `MinCount`和`MaxCount`确定 EC2 在扩展我们的实例时可以走多远。例如，当一个实例发生高 CPU 时，EC2 将自动部署另一个实例，以分享负载并保持服务处于健康状态。

1.  最后，我们打印了要在下一个脚本中使用的实例 ID。

输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00206.jpeg)您可以在以下链接中检查所有有效的 Amazon EC2 实例类型；请仔细阅读，以免因选择错误的类型而被过度收费：[`aws.amazon.com/ec2/instance-types/`](https://aws.amazon.com/ec2/instance-types/)

# 实例终止

打印的 ID 用于 CRUD 操作，以便稍后管理或终止实例。例如，我们可以使用之前创建的`ec2`资源提供的`terminate()`方法来终止实例：

```py
import boto3
ec2 = boto3.resource('ec2') instance_id = "i-0a81k3ndl29175220" instance = ec2.Instance(instance_id) instance.terminate() 
```

请注意，在前面的代码中我们硬编码了`instance_id`（当您需要创建一个可以在不同环境中使用的动态 Python 脚本时，这并不总是适用）。我们可以使用 Python 中可用的其他输入方法，例如`raw_input()`，从用户那里获取输入或查询我们帐户中可用的实例，并让 Python 提示我们需要终止哪些实例。另一个用例是创建一个 Python 脚本，检查我们实例的最后登录时间或资源消耗；如果它们超过特定值，我们将终止该实例。这在实验室环境中非常有用，您不希望因为恶意或设计不良的软件而被收取额外资源的费用。

# 自动化 AWS S3 服务

AWS **简单存储系统**（**S3**）提供了安全和高度可扩展的对象存储服务。您可以使用此服务存储任意数量的数据，并从任何地方恢复它。系统为您提供了版本控制选项，因此您可以回滚到文件的任何先前版本。此外，它提供了 REST Web 服务 API，因此您可以从外部应用程序访问它。

当数据传入 S3 时，S3 将为其创建一个`对象`，并将这些对象存储在`存储桶`中（将它们视为文件夹）。您可以为每个创建的存储桶提供复杂的用户权限，并且还可以控制其可见性（公共、共享或私有）。存储桶访问可以是策略或**访问控制列表**（**ACL**）。

存储桶还存储有描述键值对中对象的元数据，您可以通过 HTTP `POST`方法创建和设置。元数据可以包括对象的名称、大小和日期，或者您想要的任何其他自定义键值对。用户帐户最多可以拥有 100 个存储桶，但每个存储桶内托管的对象大小没有限制。

# 创建存储桶

与 AWS S3 服务交互时，首先要做的事情是创建一个用于存储文件的存储桶。在这种情况下，我们将`S3`提供给`boto3.resource()`。这将告诉`boto3`开始初始化过程，并加载与 S3 API 系统交互所需的命令：

```py
import boto3
s3_resource = boto3.resource("s3")   bucket = s3_resource.create_bucket(Bucket="my_first_bucket", CreateBucketConfiguration={
  'LocationConstraint': 'us-west-2'}) print(bucket)
```

在前面的例子中，以下内容适用：

1.  我们导入了之前安装的`boto3`模块。

1.  然后，我们指定了我们想要与之交互的资源类型，即`s3`，并将其分配给`s3_resource`对象。

1.  现在，我们可以在资源内部使用`create_bucket()`方法，并为其提供所需的参数来创建存储桶，例如`Bucket`，我们可以指定其名称。请记住，存储桶名称必须是唯一的，且之前不能已经使用过。第二个参数是`CreateBucketConfiguration`字典，我们在其中设置了创建存储桶的数据中心位置。

# 将文件上传到存储桶

现在，我们需要利用创建的存储桶并将文件上传到其中。请记住，存储桶中的文件表示为对象。因此，`boto3`提供了一些包含对象作为其一部分的方法。我们将从使用`put_object()`开始。此方法将文件上传到创建的存储桶并将其存储为对象：

```py
import boto3
s3_resource = boto3.resource("s3") bucket = s3_resource.Bucket("my_first_bucket")   with open('~/test_file.txt', 'rb') as uploaded_data:
  bucket.put_object(Body=uploaded_data) 
```

在前面的例子中，以下内容适用：

1.  我们导入了之前安装的`boto3`模块。

1.  然后，我们指定了我们想要与之交互的资源类型，即`s3`，并将其分配给`s3_resource`对象。

1.  我们通过`Bucket()`方法访问了`my_first_bucket`并将返回的值分配给了存储桶变量。

1.  然后，我们使用`with`子句打开了一个文件，并将其命名为`uploaded_data`。请注意，我们以二进制数据的形式打开了文件，使用了`rb`标志。

1.  最后，我们使用存储桶空间中提供的`put_object()`方法将二进制数据上传到我们的存储桶。

# 删除存储桶

要完成对存储桶的 CRUD 操作，我们需要做的最后一件事是删除存储桶。这是通过在我们的存储桶变量上调用`delete()`方法来实现的，前提是它已经存在，并且我们通过名称引用它，就像我们创建它并向其中上传数据一样。然而，当存储桶不为空时，`delete()`可能会失败。因此，我们将使用`bucket_objects.all().delete()`方法获取存储桶内的所有对象，然后对它们应用`delete()`操作，最后删除存储桶：

```py
import boto3
s3_resource = boto3.resource("s3") bucket = s3_resource.Bucket("my_first_bucket") bucket.objects.all().delete() bucket.delete()
```

# 总结

在本章中，我们学习了如何安装亚马逊弹性计算云（EC2），以及学习了 Boto3 及其安装。我们还学习了如何自动化 AWS S3 服务。

在下一章中，我们将学习 SCAPY 框架，这是一个强大的 Python 工具，用于构建和制作数据包并将其发送到网络上。


# 第十七章：使用 Scapy 框架

Scapy 是一个强大的 Python 工具，用于构建和制作数据包，然后将其发送到网络。您可以构建任何类型的网络流并将其发送到网络。它可以帮助您使用不同的数据包流测试您的网络，并操纵从源返回的响应。

本章将涵盖以下主题：

+   了解 Scapy 框架

+   安装 Scapy

+   使用 Scapy 生成数据包和网络流

+   捕获和重放数据包

# 了解 Scapy

Scapy ([`scapy.net`](https://scapy.net))是强大的 Python 工具之一，用于捕获、嗅探、分析和操纵网络数据包。它还可以构建分层协议的数据包结构，并将 wiuthib 流注入到网络中。您可以使用它在许多协议之上构建广泛的协议，并设置协议内每个字段的细节，或者更好地让 Scapy 发挥其魔力并选择适当的值，以便每个值都可以有一个有效的帧。如果用户没有覆盖，Scapy 将尝试使用数据包的默认值。以下值将自动设置为每个流：

+   IP 源根据目的地和路由表选择

+   校验和会自动计算

+   源 Mac 根据输出接口选择

+   以太网类型和 IP 协议由上层确定

Scapy 可以编程地将帧注入到流中并重新发送。例如，您可以将 802.1q VLAN ID 注入到流中并重新发送，以执行对网络的攻击或分析。此外，您可以使用`Graphviz`和`ImageMagick`模块可视化两个端点之间的对话并绘制图形。

Scapy 有自己的**领域特定语言**（**DSL**），使用户能够描述他想要构建或操纵的数据包，并以相同的结构接收答案。这与 Python 内置的数据类型（如列表和字典）非常好地配合和集成。我们将在示例中看到，从网络接收的数据包实际上是一个 Python 列表，我们可以对它们进行常规列表函数的迭代。

# 安装 Scapy

Scapy 支持 Python 2.7.x 和 3.4+，从 Scapy 版本 2.x 开始。但是，对于低于 2.3.3 的版本，Scapy 需要 Python 2.5 和 2.7，或者 3.4+用于之后的版本。由于我们已经安装了最新的 Python 版本，应该可以毫无问题地运行最新版本的 Scapy。

此外，Scapy 还有一个较旧的版本（1.x），已经不再支持 Python 3，仅在 Python 2.4 上运行。

# 基于 Unix 的系统

要获取最新版本，您需要使用 python pip：

```py
pip install scapy 
```

输出应该类似于以下屏幕截图：![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00207.jpeg)

要验证 Scapy 是否成功安装，请访问 Python 控制台并尝试将`scapy`模块导入其中。如果控制台没有报告任何导入错误，则安装已成功完成：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00208.jpeg)

需要一些附加软件包来可视化对话和捕获数据包。根据您的平台使用以下命令安装附加软件包：

# 在 Debian 和 Ubuntu 上安装

运行以下命令安装附加软件包：

```py
sudo apt-get install tcpdump graphviz imagemagick python-gnuplot python-cryptography python-pyx
```

# 在 Red Hat/CentOS 上安装

运行以下命令安装附加软件包：

```py
yum install tcpdump graphviz imagemagick python-gnuplot python-crypto python-pyx -y
```

如果在基于 CentOS 的系统上找不到上述软件包中的任何一个，请安装`epel`存储库并更新系统。

# Windows 和 macOS X 支持

Scapy 是专为基于 Linux 的系统构建和设计的。但它也可以在其他操作系统上运行。您可以在 Windows 和 macOS 上安装和移植它，每个平台都有一些限制。对于基于 Windows 的系统，您基本上需要删除 WinPcap 驱动程序，并改用 Npcap 驱动程序（不要同时安装两个版本，以避免任何冲突问题）。您可以在[`scapy.readthedocs.io/en/latest/installation.html#windows`](http://scapy.readthedocs.io/en/latest/installation.html#windows)上阅读有关 Windows 安装的更多信息。

对于 macOS X，您需要安装一些 Python 绑定并使用 libdnet 和 libpcap 库。完整的安装步骤可在[`scapy.readthedocs.io/en/latest/installation.html#mac-os-x`](http://scapy.readthedocs.io/en/latest/installation.html#mac-os-x)上找到。

# 使用 Scapy 生成数据包和网络流

正如我们之前提到的，Scapy 有自己的 DSL 语言，与 Python 集成。此外，您可以直接访问 Scapy 控制台，并开始直接从 Linux shell 发送和接收数据包：

```py
sudo scapy 
```

前面命令的输出如下：![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00209.jpeg)

请注意，有一些关于一些缺少的*可选*软件包的警告消息，例如`matplotlib`和`PyX`，但这应该没问题，不会影响 Scapy 的核心功能。

我们可以首先通过运行`ls()`函数来检查 Scapy 中支持的协议。列出所有支持的协议：

```py
>>> ls()
```

输出非常冗长，如果在此处发布，将跨越多个页面，因此您可以快速查看终端，以检查它。

现在让我们开发一个 hello world 应用程序，并使用 SCAPY 运行它。该程序将向服务器的网关发送一个简单的 ICMP 数据包。我安装了 Wireshark 并配置它以监听将从自动化服务器（托管 Scapy）接收流的网络接口。

现在，在 Scapy 终端上，执行以下代码：

```py
>>> send(IP(dst="10.10.10.1")/ICMP()/"Welcome to Enterprise Automation Course") 
```

返回到 Wireshark，你应该看到通信：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00210.jpeg)

让我们分析 Scapy 执行的命令：

+   **Send：**这是 Scapy **Domain Specific Language** (**DSL**)中的内置函数，指示 Scapy 发送单个数据包（并不监听任何响应；它只发送一个数据包并退出）。

+   **IP：**现在，在这个类中，我们将开始构建数据包层。从 IP 层开始，我们需要指定将接收数据包的目标主机（在这种情况下，我们使用`dst`参数来指定目的地）。还要注意，我们可以在`src`参数中指定源 IP；但是，Scapy 将查询主机路由表并找到合适的源 IP，并将其放入数据包中。您可以提供其他参数，例如**生存时间**（**TTL**），Scapy 将覆盖默认值。

+   **/**：虽然它看起来像是 Python 中常用的普通除法运算符，但在 Scapy DSL 中，它用于区分数据包层，并将它们堆叠在一起。

+   **ICMP():**用于创建具有默认值的 ICMP 数据包的内置类。可以向函数提供的值之一是 ICMP 类型，它确定消息类型：`echo`，`echo reply`，`unreachable`等。

+   **欢迎来到企业自动化课程：**如果将字符串注入 ICMP 有效载荷中，Scapy 将自动将其转换为适当的格式。

请注意，我们没有在堆栈中指定以太网层，并且没有提供任何 mac 地址（源或目的地）。这在 Scapy 中默认填充，以创建一个有效的帧。它将自动检查主机 ARP 表，并找到源接口的 mac 地址（如果存在，也是目的地），然后将它们格式化为以太网帧。

在继续下一个示例之前，需要注意的最后一件事是，您可以使用与我们之前用于列出所有支持的协议的`ls()`函数相同的函数，以获取每个协议的默认值，然后在调用协议时将其设置为任何其他值。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00211.jpeg)

现在让我们做一些更复杂（和邪恶的）事情！假设我们有两台路由器之间形成 VRRP 关系，并且我们需要打破这种关系以成为新的主机，或者至少在网络中创建一个抖动问题，如下拓扑图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00212.jpeg)

请注意，配置为运行 VRRP 的路由器加入多播地址（`255.0.0.18`）以接收其他路由器的广告。VRRP 数据包的目标 MAC 地址应该包含最后两个数字的 VRRP 组号。它还包含在路由器之间选举过程中使用的路由器优先级。我们将构建一个 Scapy 脚本，该脚本将发送一个具有比网络中配置的更高优先级的 VRRP 通告。这将导致我们的 Scapy 服务器被选为新的主机：

```py
from scapy.layers.inet import * from scapy.layers.vrrp import VRRP

vrrp_packet = Ether(src="00:00:5e:00:01:01",dst="01:00:5e:00:00:30")/IP(src="10.10.10.130", dst="224.0.0.18")/VRRP(priority=254, addrlist=["10.10.10.1"]) sendp(vrrp_packet, inter=2, loop=1) 
```

在这个例子中：

+   首先，我们从`scapy.layers`模块中导入了一些需要的层，我们将这些层叠加在一起。例如，`inet`模块包含了`IP()`、`Ether()`、`ARP()`、`ICMP()`等层。

+   此外，我们还需要 VRRP 层，可以从`scapy.layers.vrrp`中导入。

+   其次，我们将构建一个 VRRP 数据包并将其存储在`vrrp_packet`变量中。该数据包包含以太网帧内的 mac 地址中的 VRRP 组号。多播地址将位于 IP 层内。此外，我们将在 VRRP 层内配置一个更高的优先级号码。这样我们将拥有一个有效的 VRRP 通告，路由器将接受它。我们为每个层提供了信息，例如目标 mac 地址（VRRP MAC +组号）和多播 IP（`225.0.0.18`）。

+   最后，我们使用了`sendp()`函数，并向其提供了一个精心制作的`vrrp_packet`。`sendp()`函数将在第 2 层发送数据包，与我们在上一个示例中使用的`send()`函数发送数据包的方式不同，后者是在第 3 层发送数据包。`sendp()`函数不会像`send()`函数那样尝试解析主机名，并且只会在第 2 层操作。此外，由于我们需要连续发送此通告，因此我们配置了`loop`和`inter`参数，以便每 2 秒发送一次通告。

脚本输出为：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00213.jpeg)您可以将此攻击与 ARP 欺骗和 VLAN 跳跃攻击相结合，以便在第 2 层更改 mac 地址，切换到 Scapy 服务器的 MAC 地址，并执行**中间人**（**MITM**）攻击。

Scapy 还包含一些执行扫描的类。例如，您可以使用`arping()`在网络范围内执行 ARP 扫描，并在其中指定 IP 地址的正则表达式格式。Scapy 将向这些子网上的所有主机发送 ARP 请求并检查回复：

```py
from scapy.layers.inet import *  arping("10.10.10.*")
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00214.jpeg)

脚本输出为：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00215.jpeg)

根据接收到的数据包，只有一个主机回复 SCAPY，这意味着它是扫描子网上唯一的主机。回复中列出了主机的 mac 地址和 IP 地址。

# 捕获和重放数据包

Scapy 具有监听网络接口并捕获其所有传入数据包的能力。它可以以与`tcpdump`相同的方式将其写入`pcap`文件，但是 Scapy 提供了额外的函数，可以再次读取和重放`pcap`文件。

从简单的数据包重放开始，我们将指示 Scapy 读取从网络中捕获的正常`pcap`文件（使用`tcpdump`或 Scapy 本身）并将其再次发送到网络。如果我们需要测试网络的行为是否通过特定的流量模式，这将非常有用。例如，我们可能已经配置了网络防火墙以阻止 FTP 通信。我们可以通过使用 Scapy 重放的 FTP 数据来测试防火墙的功能。

在这个例子中，我们有捕获的 FTP `pcap`文件，我们需要将其重新发送到网络：

```py
from scapy.layers.inet import * from pprint import pprint
pkts = PcapReader("/root/ftp_data.pcap") #should be in wireshark-tcpdump format   for pkt in pkts:
  pprint(pkt.show()) 
```

`PcapReader()`将`pcap`文件作为输入，并对其进行分析，以单独获取每个数据包，并将其作为`pkts`列表中的一个项目添加。现在我们可以遍历列表并显示每个数据包的内容。

脚本输出为：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00216.jpeg)

此外，您可以通过`get_layer()`函数获取特定层的信息，该函数访问数据包层。例如，如果我们有兴趣获取没有标头的原始数据，以便构建传输文件，我们可以使用以下脚本获取十六进制中所需的数据，然后稍后将其转换为 ASCII：

```py
from scapy.layers.inet import * from pprint import pprint
pkts = PcapReader("/root/ftp_data.pcap") #should be in wireshark-tcpdump format   ftp_data = b"" for pkt in pkts:
  try:
  ftp_data += pkt.get_layer(Raw).load
    except:
  pass
```

请注意，我们必须用 try-except 子句包围`get_layer()`方法，因为某些层不包含原始数据（例如 FTP 控制消息）。Scapy 会抛出错误，脚本将退出。此外，我们可以将脚本重写为一个`if`子句，只有在数据包中包含原始层时才会向`ftp_data`添加内容。

为了避免在读取`pcap`文件时出现任何错误，请确保将您的`pcap`文件保存（或导出）为 Wireshark/tcpdump 格式，如下所示，而不是默认格式：![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00217.jpeg)

# 向数据包中注入数据

在将数据包重新发送到网络之前，我们可以操纵数据包并更改其内容。由于我们的数据包实际上存储为列表中的项目，我们可以遍历这些项目并替换特定信息。例如，我们可以更改 MAC 地址、IP 地址，或者为每个数据包或符合特定条件的特定数据包添加附加层。但是，我们应该注意，在特定层（如 IP 和 TCP）中操纵数据包并更改内容将导致整个层的校验和无效，接收方可能因此丢弃数据包。

Scapy 有一个令人惊奇的功能（是的，我知道，我多次说了令人惊奇，但 Scapy 确实是一个很棒的工具）。如果我们在`pcap`文件中删除原始内容，它将基于新内容自动为我们计算校验和。

因此，我们将修改上一个脚本并更改一些数据包参数，然后在发送数据包到网络之前重新构建校验和：

```py

from scapy.layers.inet import * from pprint import pprint
pkts = PcapReader("/root/ftp_data.pcap") #should be in wireshark-tcpdump format     p_out = []   for pkt in pkts:
  new_pkt = pkt.payload

    try:
  new_pkt[IP].src = "10.10.88.100"
  new_pkt[IP].dst = "10.10.88.1"
  del (new_pkt[IP].chksum)
  del (new_pkt[TCP].chksum)
  except:
  pass    pprint(new_pkt.show())
  p_out.append(new_pkt) send(PacketList(p_out), iface="eth0")
```

在上一个脚本中：

+   我们使用`PcapReader()`类来读取 FTP `pcap`文件的内容，并将数据包存储在`pkts`变量中。

+   然后，我们遍历数据包并将有效载荷分配给`new_pkt`，以便我们可以操纵内容。

+   请记住，数据包本身被视为来自该类的对象。我们可以访问`src`和`dst`成员，并将它们设置为任何所需的值。在这里，我们将目的地设置为网关，将源设置为与原始数据包不同的值。

+   设置新的 IP 值将使校验和无效，因此我们使用`del`关键字删除了 IP 和 TCP 校验和。Scapy 将根据新数据包内容重新计算它们。

+   最后，我们将`new_pkt`附加到空的`p_out`列表中，并使用`send()`函数发送它。请注意，我们可以在发送函数中指定退出接口，或者只需离开它，Scapy 将查询主机路由表；它将为每个数据包获取正确的退出接口。

脚本输出为：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00218.jpeg)

此外，如果我们仍然在网关上运行 Wireshark，我们会注意到 Wireshark 捕获了在重新计算后设置校验和值的`ftp`数据包流：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00219.jpeg)

# 数据包嗅探

Scapy 有一个名为`sniff()`的内置数据包捕获函数。默认情况下，如果您不指定任何过滤器或特定接口，它将监视所有接口并捕获所有数据包：

```py
from scapy.all import * from pprint import pprint

print("Begin capturing all packets from all interfaces. send ctrl+c to terminate and print summary") pkts = sniff()   pprint(pkts.summary())
```

脚本输出为：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00220.jpeg)

当然，您可以提供过滤器和特定接口来监视是否满足条件。例如，在前面的输出中，我们可以看到混合了 ICMP、TCP、SSH 和 DHCP 流量命中了所有接口。如果我们只对在 eth0 上获取 ICMP 流量感兴趣，那么我们可以提供过滤器和`iface`参数来嗅探函数，并且它将只过滤所有流量并记录只有 ICMP 的数据：

```py
from scapy.all import * from pprint import pprint

print("Begin capturing all packets from all interfaces. send ctrl+c to terminate and print summary") pkts = sniff(iface="eth0", filter="icmp")   pprint(pkts.summary())
```

脚本输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00221.jpeg)

请注意，我们只捕获 eth0 接口上的 ICMP 通信，所有其他数据包都由于应用在它们上的过滤器而被丢弃。*iface*值接受我们在脚本中使用的单个接口或要监视它们的接口列表。

`sniff`的高级功能之一是`stop_filter`，它是应用于每个数据包的 Python 函数，用于确定我们是否必须在该数据包之后停止捕获。例如，如果我们设置`stop_filter = lambda x: x.haslayer(TCP)`，那么一旦我们命中具有 TCP 层的数据包，我们将停止捕获。此外，`store`选项允许我们将数据包存储在内存中（默认情况下已启用）或在对每个数据包应用特定函数后丢弃它们。如果您正在从 SCAPY 中获取来自线缆的实时流量，并且不希望将其写入内存，那么将`sniff`函数中的 store 参数设置为 false，然后 SCAPY 将在丢弃原始数据包之前应用您开发的任何自定义函数（例如获取数据包的一些信息或将其重新发送到不同的目的地等）。这将在嗅探期间节省一些内存资源。

# 将数据包写入 pcap

最后，我们可以将嗅探到的数据包写入标准的`pcap`文件，并像往常一样使用 Wireshark 打开它。这是通过一个简单的`wrpcap()`函数实现的，它将数据包列表写入`pcap`文件。`wrpcap()`函数接受两个参数——第一个是文件位置的完整路径，第二个是在使用`sniff()`函数之前捕获的数据包列表：

```py
from scapy.all import *   print("Begin capturing all packets from all interfaces. send ctrl+c to terminate and print summary") pkts = sniff(iface="eth0", filter="icmp")   wrpcap("/root/icmp_packets_eth0.pcap",pkts)
```

# 摘要

在本章中，我们学习了如何利用 Scapy 框架构建任何类型的数据包，包含任何网络层，并用我们的值填充它。此外，我们还看到了如何在接口上捕获数据包并重放它们。
