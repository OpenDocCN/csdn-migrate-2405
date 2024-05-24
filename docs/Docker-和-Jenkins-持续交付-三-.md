# Docker 和 Jenkins 持续交付（三）

> 原文：[`zh.annas-archive.org/md5/7C44824F34694A0D5BA0600DC67F15A8`](https://zh.annas-archive.org/md5/7C44824F34694A0D5BA0600DC67F15A8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用 Ansible 进行配置管理

我们已经涵盖了持续交付过程的两个最关键的阶段：提交阶段和自动接受测试。在本章中，我们将专注于配置管理，将虚拟容器化环境与真实服务器基础设施连接起来。

本章涵盖以下要点：

+   介绍配置管理的概念

+   解释最流行的配置管理工具

+   讨论 Ansible 的要求和安装过程

+   使用 Ansible 进行即时命令

+   展示 Ansible 自动化的强大力量与 playbooks

+   解释 Ansible 角色和 Ansible Galaxy

+   实施部署过程的用例

+   使用 Ansible 与 Docker 和 Docker Compose 一起

# 介绍配置管理

配置管理是一种控制配置更改的过程，以使系统随时间保持完整性。即使这个术语并非起源于 IT 行业，但目前它被广泛用来指代软件和硬件。在这个背景下，它涉及以下方面：

+   **应用程序配置**：这涉及决定系统如何工作的软件属性，通常以传递给应用程序的标志或属性文件的形式表达，例如数据库地址、文件处理的最大块大小或日志级别。它们可以在不同的开发阶段应用：构建、打包、部署或运行。

+   **基础设施配置**：这涉及服务器基础设施和环境配置，负责部署过程。它定义了每台服务器应安装哪些依赖项，并指定了应用程序的编排方式（哪个应用程序在哪个服务器上运行以及有多少个实例）。

举个例子，我们可以想象一个使用 Redis 服务器的计算器 Web 服务。让我们看一下展示配置管理工具如何工作的图表。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/886430b5-6e25-4fba-925d-5e18c53eea0d.png)

配置管理工具读取配置文件并相应地准备环境（安装依赖工具和库，将应用程序部署到多个实例）。

在前面的例子中，**基础设施配置**指定了**计算器**服务应该在**服务器 1**和**服务器 2**上部署两个实例，并且**Redis**服务应该安装在**服务器 3**上。**计算器应用程序配置**指定了**Redis**服务器的端口和地址，以便服务之间可以通信。

配置可能因环境类型（QA、staging、production）的不同而有所不同，例如，服务器地址可能不同。

配置管理有许多方法，但在我们研究具体解决方案之前，让我们评论一下一个好的配置管理工具应该具备的特征。

# 良好配置管理的特点

现代配置管理解决方案应该是什么样的？让我们来看看最重要的因素：

+   **自动化**：每个环境都应该自动可再现，包括操作系统、网络配置、安装的软件和部署的应用程序。在这种方法中，修复生产问题意味着自动重建环境。更重要的是，这简化了服务器复制，并确保暂存和生产环境完全相同。

+   **版本控制**：配置的每个更改都应该被跟踪，这样我们就知道是谁做的，为什么，什么时候。通常，这意味着将配置保存在源代码存储库中，要么与代码一起，要么在一个单独的地方。前者的解决方案是推荐的，因为配置属性的生命周期与应用程序本身不同。版本控制还有助于修复生产问题-配置始终可以回滚到先前的版本，并自动重建环境。唯一的例外是基于版本控制的解决方案是存储凭据和其他敏感信息-这些信息永远不应该被检入。

+   **增量更改**：应用配置的更改不应该需要重建整个环境。相反，配置的小改变应该只改变基础设施的相关部分。

+   **服务器配置**：通过自动化，添加新服务器应该像将其地址添加到配置（并执行一个命令）一样快。

+   **安全性**：对配置管理工具和其控制下的机器的访问应该得到很好的保护。当使用 SSH 协议进行通信时，密钥或凭据的访问需要得到很好的保护。

+   **简单性**：团队的每个成员都应该能够阅读配置，进行更改，并将其应用到环境中。属性本身也应尽可能简单，不受更改影响的属性最好保持硬编码。

在创建配置时以及在选择正确的配置管理工具之前，重要的是要牢记这些要点。

# 配置管理工具概述

最流行的配置管理工具是 Ansible、Puppet 和 Chef。它们每个都是一个不错的选择；它们都是开源产品，有免费的基本版本和付费的企业版本。它们之间最重要的区别是：

+   **配置语言**：Chef 使用 Ruby，Puppet 使用其自己的 DSL（基于 Ruby），而 Ansible 使用 YAML。

+   **基于代理**：Puppet 和 Chef 使用代理进行通信，这意味着每个受管服务器都需要安装特殊工具。相反，Ansible 是无代理的，使用标准的 SSH 协议进行通信。

无代理的特性是一个重要的优势，因为它意味着不需要在服务器上安装任何东西。此外，Ansible 正在迅速上升，这就是为什么选择它作为本书的原因。然而，其他工具也可以成功地用于持续交付过程。

# 安装 Ansible

Ansible 是一个开源的、无代理的自动化引擎，用于软件供应、配置管理和应用部署。它于 2012 年首次发布，其基本版本对个人和商业用途都是免费的。企业版称为 Ansible Tower，提供 GUI 管理和仪表板、REST API、基于角色的访问控制等更多功能。

我们介绍了安装过程以及如何单独使用它以及与 Docker 一起使用的描述。

# Ansible 服务器要求

Ansible 使用 SSH 协议进行通信，对其管理的机器没有特殊要求。也没有中央主服务器，因此只需在任何地方安装 Ansible 客户端工具，就可以用它来管理整个基础架构。

被管理的机器的唯一要求是安装 Python 工具和 SSH 服务器。然而，这些工具几乎总是默认情况下在任何服务器上都可用。

# Ansible 安装

安装说明因操作系统而异。在 Ubuntu 的情况下，只需运行以下命令即可：

```
$ sudo apt-get install software-properties-common
$ sudo apt-add-repository ppa:ansible/ansible
$ sudo apt-get update
$ sudo apt-get install ansible
```

您可以在官方 Ansible 页面上找到所有操作系统的安装指南：[`docs.ansible.com/ansible/intro_installation.html`](http://docs.ansible.com/ansible/intro_installation.html)。

安装过程完成后，我们可以执行 Ansible 命令来检查是否一切都安装成功。

```
$ ansible --version
ansible 2.3.2.0
    config file = /etc/ansible/ansible.cfg
    configured module search path = Default w/o overrides
```

# 基于 Docker 的 Ansible 客户端

还可以将 Ansible 用作 Docker 容器。我们可以通过运行以下命令来实现：

```
$ docker run williamyeh/ansible:ubuntu14.04
ansible-playbook 2.3.2.0
 config file = /etc/ansible/ansible.cfg
 configured module search path = Default w/o overrides
```

Ansible Docker 镜像不再得到官方支持，因此唯一的解决方案是使用社区驱动的版本。您可以在 Docker Hub 页面上阅读更多关于其用法的信息。

# 使用 Ansible

为了使用 Ansible，首先需要定义清单，代表可用资源。然后，我们将能够执行单个命令或使用 Ansible playbook 定义一组任务。

# 创建清单

清单是由 Ansible 管理的所有服务器的列表。每台服务器只需要安装 Python 解释器和 SSH 服务器。默认情况下，Ansible 假定使用 SSH 密钥进行身份验证；但是，也可以通过在 Ansible 命令中添加`--ask-pass`选项来使用用户名和密码进行身份验证。

SSH 密钥可以使用`ssh-keygen`工具生成，并通常存储在`~/.ssh`目录中。

清单是在`/etc/ansible/hosts`文件中定义的，它具有以下结构：

```
[group_name]
<server1_address>
<server2_address>
...
```

清单语法还接受服务器范围，例如`www[01-22].company.com`。如果 SSH 端口不是默认的 22 端口，还应该指定。您可以在官方 Ansible 页面上阅读更多信息：[`docs.ansible.com/ansible/intro_inventory.html`](http://docs.ansible.com/ansible/intro_inventory.html)。

清单文件中可能有 0 个或多个组。例如，让我们在一个服务器组中定义两台机器。

```
[webservers]
192.168.0.241
192.168.0.242
```

我们还可以创建带有服务器别名的配置，并指定远程用户：

```
[webservers]
web1 ansible_host=192.168.0.241 ansible_user=admin
web2 ansible_host=192.168.0.242 ansible_user=admin
```

前面的文件定义了一个名为`webservers`的组，其中包括两台服务器。Ansible 客户端将作为用户`admin`登录到它们两台。当我们创建了清单后，让我们发现如何使用它来在许多服务器上执行相同的命令。

Ansible 提供了从云提供商（例如 Amazon EC2/Eucalyptus）、LDAP 或 Cobbler 动态获取清单的可能性。在[`docs.ansible.com/ansible/intro_dynamic_inventory.html`](http://docs.ansible.com/ansible/intro_dynamic_inventory.html)了解更多关于动态清单的信息。

# 临时命令

我们可以运行的最简单的命令是对所有服务器进行 ping 测试。

```
$ ansible all -m ping
web1 | SUCCESS => {
 "changed": false,
 "ping": "pong"
}
web2 | SUCCESS => {
 "changed": false,
 "ping": "pong"
}
```

我们使用了`-m <module_name>`选项，允许指定应在远程主机上执行的模块。结果是成功的，这意味着服务器是可达的，并且身份验证已正确配置。

可以在[`docs.ansible.com/ansible/modules.htm`](http://docs.ansible.com/ansible/modules.htm)找到 Ansible 可用模块的完整列表。

请注意，我们使用了`all`，以便可以处理所有服务器，但我们也可以通过组名`webservers`或单个主机别名来调用它们。作为第二个例子，让我们只在其中一个服务器上执行一个 shell 命令。

```
$ ansible web1 -a "/bin/echo hello"
web1 | SUCCESS | rc=0 >>
hello
```

`-a <arguments>`选项指定传递给 Ansible 模块的参数。在这种情况下，我们没有指定模块，因此参数将作为 shell Unix 命令执行。结果是成功的，并且打印了`hello`。

如果`ansible`命令第一次连接服务器（或服务器重新安装），那么我们会收到密钥确认消息（当主机不在`known_hosts`中时的 SSH 消息）。由于这可能会中断自动化脚本，我们可以通过取消注释`/etc/ansible/ansible.cfg`文件中的`host_key_checking = False`或设置环境变量`ANSIBLE_HOST_KEY_CHECKING=False`来禁用提示消息。

在其简单形式中，Ansible 临时命令的语法如下：

```
ansible <target> -m <module_name> -a <module_arguments>
```

临时命令的目的是在不必重复时快速执行某些操作。例如，我们可能想要检查服务器是否存活，或者在圣诞假期关闭所有机器。这种机制可以被视为在一组机器上执行命令，并由模块提供的附加语法简化。然而，Ansible 自动化的真正力量在于 playbooks。

# Playbooks

Ansible playbook 是一个配置文件，描述了服务器应该如何配置。它提供了一种定义一系列任务的方式，这些任务应该在每台机器上执行。Playbook 使用 YAML 配置语言表示，这使得它易于阅读和理解。让我们从一个示例 playbook 开始，然后看看我们如何使用它。

# 定义一个 playbook

一个 playbook 由一个或多个 plays 组成。每个 play 包含一个主机组名称，要执行的任务以及配置细节（例如，远程用户名或访问权限）。一个示例 playbook 可能如下所示：

```
---
- hosts: web1
  become: yes
  become_method: sudo
  tasks:
  - name: ensure apache is at the latest version
    apt: name=apache2 state=latest
  - name: ensure apache is running
    service: name=apache2 state=started enabled=yes
```

此配置包含一个 play，其中：

+   仅在主机`web1`上执行

+   使用`sudo`命令获取 root 访问权限

+   执行两个任务：

+   安装最新版本的`apache2`：Ansible 模块`apt`（使用两个参数`name=apache2`和`state=latest`）检查服务器上是否安装了`apache2`软件包，如果没有，则使用`apt-get`工具安装`apache2`

+   运行`apache2`服务：Ansible 模块`service`（使用三个参数`name=apache2`，`state=started`和`enabled=yes`）检查 Unix 服务`apache2`是否已启动，如果没有，则使用`service`命令启动它

在处理主机时，您还可以使用模式，例如，我们可以使用`web*`来寻址`web1`和`web2`。您可以在[`docs.ansible.com/ansible/intro_patterns.html`](http://docs.ansible.com/ansible/intro_patterns.html)了解更多关于 Ansible 模式的信息。

请注意，每个任务都有一个易于阅读的名称，在控制台输出中使用，例如`apt`和`service`是 Ansible 模块，`name=apache2`，`state=latest`和`state=started`是模块参数。在使用临时命令时，我们已经看到了 Ansible 模块和参数。在前面的 playbook 中，我们只定义了一个 play，但可以有很多 play，并且每个 play 可以与不同的主机组相关联。

例如，我们可以在清单中定义两组服务器：`database`和`webservers`。然后，在 playbook 中，我们可以指定应该在所有托管数据库的机器上执行的任务，以及应该在所有 web 服务器上执行的一些不同的任务。通过使用一个命令，我们可以设置整个环境。

# 执行 playbook

当定义了 playbook.yml 时，我们可以使用`ansible-playbook`命令来执行它。

```
$ ansible-playbook playbook.yml

PLAY [web1] *************************************************************

TASK [setup] ************************************************************
ok: [web1]

TASK [ensure apache is at the latest version] ***************************
changed: [web1]

TASK [ensure apache is running] *****************************************

ok: [web1]

PLAY RECAP **************************************************************
web1: ok=3 changed=1 unreachable=0 failed=0   
```

如果服务器需要输入`sudo`命令的密码，那么我们需要在`ansible-playbook`命令中添加`--ask-sudo-pass`选项。也可以通过设置额外变量`-e ansible_become_pass=<sudo_password>`来传递`sudo`密码（如果需要）。

已执行 playbook 配置，因此安装并启动了`apache2`工具。请注意，如果任务在服务器上做了一些改变，它会被标记为`changed`。相反，如果没有改变，它会被标记为`ok`。

可以使用`-f <num_of_threads>`选项并行运行任务。

# Playbook 的幂等性

我们可以再次执行命令。

```
$ ansible-playbook playbook.yml

PLAY [web1] *************************************************************

TASK [setup] ************************************************************
ok: [web1]

TASK [ensure apache is at the latest version] ***************************
ok: [web1]

TASK [ensure apache is running] *****************************************
ok: [web1]

PLAY RECAP **************************************************************
web1: ok=3 changed=0 unreachable=0 failed=0
```

请注意输出略有不同。这次命令没有在服务器上做任何改变。这是因为每个 Ansible 模块都设计为幂等的。换句话说，按顺序多次执行相同的模块应该与仅执行一次相同。

实现幂等性的最简单方法是始终首先检查任务是否尚未执行，并且仅在尚未执行时执行它。幂等性是一个强大的特性，我们应该始终以这种方式编写我们的 Ansible 任务。

如果所有任务都是幂等的，那么我们可以随意执行它们。在这种情况下，我们可以将 playbook 视为远程机器期望状态的描述。然后，`ansible-playbook`命令负责将机器（或一组机器）带入该状态。

# 处理程序

某些操作应仅在某些其他任务更改时执行。例如，假设您将配置文件复制到远程机器，并且只有在配置文件更改时才应重新启动 Apache 服务器。如何处理这种情况？

例如，假设您将配置文件复制到远程机器，并且只有在配置文件更改时才应重新启动 Apache 服务器。如何处理这种情况？

Ansible 提供了一种基于事件的机制来通知变化。为了使用它，我们需要知道两个关键字：

+   `handlers`：指定通知时执行的任务

+   `notify`：指定应执行的处理程序

让我们看一个例子，我们如何将配置复制到服务器并且仅在配置更改时重新启动 Apache。

```
tasks:
- name: copy configuration
  copy:
    src: foo.conf
    dest: /etc/foo.conf
  notify:
  - restart apache
handlers:
- name: restart apache
  service:
    name: apache2
    state: restarted
```

现在，我们可以创建`foo.conf`文件并运行`ansible-playbook`命令。

```
$ touch foo.conf
$ ansible-playbook playbook.yml

...
TASK [copy configuration] **********************************************
changed: [web1]

RUNNING HANDLER [restart apache] ***************************************
changed: [web1]

PLAY RECAP *************************************************************
web1: ok=5 changed=2 unreachable=0 failed=0   
```

处理程序始终在 play 结束时执行，只执行一次，即使由多个任务触发。

Ansible 复制了文件并重新启动了 Apache 服务器。重要的是要理解，如果我们再次运行命令，将不会发生任何事情。但是，如果我们更改`foo.conf`文件的内容，然后运行`ansible-playbook`命令，文件将再次被复制（并且 Apache 服务器将被重新启动）。

```
$ echo "something" > foo.conf
$ ansible-playbook playbook.yml

...

TASK [copy configuration] ***********************************************
changed: [web1]

RUNNING HANDLER [restart apache] ****************************************
changed: [web1]

PLAY RECAP **************************************************************
web1: ok=5 changed=2 unreachable=0 failed=0   
```

我们使用了`copy`模块，它足够智能，可以检测文件是否已更改，然后在这种情况下在服务器上进行更改。

Ansible 中还有一个发布-订阅机制。使用它意味着将一个主题分配给许多处理程序。然后，一个任务通知主题以执行所有相关的处理程序。您可以在以下网址了解更多信息：[`docs.ansible.com/ansible/playbooks_intro.html`](http://docs.ansible.com/ansible/playbooks_intro.html)。

# 变量

虽然 Ansible 自动化使多个主机的事物变得相同和可重复，但不可避免地，服务器可能需要一些差异。例如，考虑应用程序端口号。它可能因机器而异。幸运的是，Ansible 提供了变量，这是一个处理服务器差异的良好机制。让我们创建一个新的 playbook 并定义一个变量。

例如，考虑应用程序端口号。它可能因机器而异。幸运的是，Ansible 提供了变量，这是一个处理服务器差异的良好机制。让我们创建一个新的 playbook 并定义一个变量。

```
---
- hosts: web1
  vars:
    http_port: 8080
```

配置定义了`http_port`变量的值为`8080`。现在，我们可以使用 Jinja2 语法来使用它。

```
tasks:
- name: print port number
  debug:
    msg: "Port number: {{http_port}}"
```

Jinja2 语言不仅允许获取变量，还可以用它来创建条件、循环等。您可以在 Jinja 页面上找到更多详细信息：[`jinja.pocoo.org/`](http://jinja.pocoo.org/)。

`debug`模块在执行时打印消息。如果我们运行`ansible-playbook`命令，就可以看到变量的使用情况。

```
$ ansible-playbook playbook.yml

...

TASK [print port number] ************************************************
ok: [web1] => {
 "msg": "Port number: 8080"
}  
```

变量也可以在清单文件中的`[group_name:vars]`部分中定义。您可以在以下网址了解更多信息：[`docs.ansible.com/ansible/intro_inventory.html#host-variables`](http://docs.ansible.com/ansible/intro_inventory.html#host-variables)。

除了用户定义的变量，还有预定义的自动变量。例如，`hostvars`变量存储了有关清单中所有主机信息的映射。使用 Jinja2 语法，我们可以迭代并打印清单中所有主机的 IP 地址。

```
---
- hosts: web1
  tasks:
  - name: print IP address
    debug:
      msg: "{% for host in groups['all'] %} {{
              hostvars[host]['ansible_host'] }} {% endfor %}"
```

然后，我们可以执行`ansible-playbook`命令。

```
$ ansible-playbook playbook.yml

...

TASK [print IP address] ************************************************
ok: [web1] => {
 "msg": " 192.168.0.241  192.168.0.242 "
}
```

请注意，使用 Jinja2 语言，我们可以在 Ansible 剧本文件中指定流程控制操作。

对于条件和循环，Jinja2 模板语言的替代方案是使用 Ansible 内置关键字：`when`和`with_items`。您可以在以下网址了解更多信息：[`docs.ansible.com/ansible/playbooks_conditionals.html`](http://docs.ansible.com/ansible/playbooks_conditionals.html)。

# 角色

我们可以使用 Ansible 剧本在远程服务器上安装任何工具。想象一下，我们想要一个带有 MySQL 的服务器。我们可以轻松地准备一个类似于带有`apache2`包的 playbook。然而，如果你想一想，带有 MySQL 的服务器是一个相当常见的情况，肯定有人已经为此准备了一个 playbook，所以也许我们可以重用它？这就是 Ansible 角色和 Ansible Galaxy 的用武之地。

# 理解角色

Ansible 角色是一个精心构建的剧本部分，准备包含在剧本中。角色是独立的单元，始终具有以下目录结构：

```
templates/
tasks/
handlers/
vars/
defaults/
meta/
```

您可以在官方 Ansible 页面上阅读有关角色及每个目录含义的更多信息：[`docs.ansible.com/ansible/playbooks_roles.html`](http://docs.ansible.com/ansible/playbooks_roles.html)。

在每个目录中，我们可以定义`main.yml`文件，其中包含可以包含在`playbook.yml`文件中的剧本部分。继续 MySQL 案例，GitHub 上定义了一个角色：[`github.com/geerlingguy/ansible-role-mysql`](https://github.com/geerlingguy/ansible-role-mysql)。该存储库包含可以在我们的 playbook 中使用的任务模板。让我们看一下`tasks/main.yml`文件的一部分，它安装`mysql`包。

```
...
- name: Ensure MySQL Python libraries are installed.
  apt: "name=python-mysqldb state=installed"

- name: Ensure MySQL packages are installed.
  apt: "name={{ item }} state=installed"
  with_items: "{{ mysql_packages }}"
  register: deb_mysql_install_packages
...
```

这只是在`tasks/main.yml`文件中定义的任务之一。其他任务负责 MySQL 配置。

`with_items`关键字用于在所有项目上创建循环。`when`关键字意味着任务仅在特定条件下执行。

如果我们使用这个角色，那么为了在服务器上安装 MySQL，只需创建以下 playbook.yml：

```
---
- hosts: all
  become: yes
  become_method: sudo
  roles:
  - role: geerlingguy.mysql
    become: yes
```

这样的配置使用`geerlingguy.mysql`角色将 MySQL 数据库安装到所有服务器上。

# Ansible Galaxy

Ansible Galaxy 是 Ansible 的角色库，就像 Docker Hub 是 Docker 的角色库一样，它存储常见的角色，以便其他人可以重复使用。您可以在 Ansible Galaxy 页面上浏览可用的角色：[`galaxy.ansible.com/`](https://galaxy.ansible.com/)。

要从 Ansible Galaxy 安装角色，我们可以使用`ansible-galaxy`命令。

```
$ ansible-galaxy install username.role_name
```

此命令会自动下载角色。在 MySQL 示例中，我们可以通过执行以下命令下载角色：

```
$ ansible-galaxy install geerlingguy.mysql
```

该命令下载`mysql`角色，可以在 playbook 文件中后续使用。

如果您需要同时安装许多角色，可以在`requirements.yml`文件中定义它们，并使用`ansible-galaxy install -r requirements.yml`。了解更多关于这种方法和 Ansible Galaxy 的信息，请访问：[`docs.ansible.com/ansible/galaxy.html`](http://docs.ansible.com/ansible/galaxy.html)。

# 使用 Ansible 进行部署

我们已经介绍了 Ansible 的最基本功能。现在，让我们暂时忘记 Docker，使用 Ansible 配置完整的部署步骤。我们将在一个服务器上运行计算器服务，而在第二个服务器上运行 Redis 服务。

# 安装 Redis

我们可以在新的 playbook 中指定一个 play。让我们创建`playbook.yml`文件，内容如下：

```
---
- hosts: web1
  become: yes
  become_method: sudo
  tasks:
  - name: install Redis
    apt:
      name: redis-server
      state: present
  - name: start Redis
    service:
      name: redis-server
      state: started
  - name: copy Redis configuration
    copy:
      src: redis.conf
      dest: /etc/redis/redis.conf
    notify: restart Redis
  handlers:
  - name: restart Redis
    service:
      name: redis-server
      state: restarted
```

该配置在一个名为`web1`的服务器上执行。它安装`redis-server`包，复制 Redis 配置，并启动 Redis。请注意，每次更改`redis.conf`文件的内容并重新运行`ansible-playbook`命令时，配置都会更新到服务器上，并且 Redis 服务会重新启动。

我们还需要创建`redis.conf`文件，内容如下：

```
daemonize yes
pidfile /var/run/redis/redis-server.pid
port 6379
bind 0.0.0.0
```

此配置将 Redis 作为守护程序运行，并将其暴露给端口号为 6379 的所有网络接口。现在让我们定义第二个 play，用于设置计算器服务。

# 部署 Web 服务

我们分三步准备计算器 Web 服务：

1.  配置项目可执行。

1.  更改 Redis 主机地址。

1.  将计算器部署添加到 playbook 中。

# 配置项目可执行

首先，我们需要使构建的 JAR 文件可执行，以便它可以作为 Unix 服务轻松在服务器上运行。为了做到这一点，只需将以下代码添加到`build.gradle`文件中：

```
bootRepackage {
    executable = true
}
```

# 更改 Redis 主机地址

以前，我们已将 Redis 主机地址硬编码为`redis`，所以现在我们应该在`src/main/java/com/leszko/calculator/CacheConfig.java`文件中将其更改为`192.168.0.241`。

在实际项目中，应用程序属性通常保存在属性文件中。例如，对于 Spring Boot 框架，有一个名为`application.properties`或`application.yml`的文件。

# 将计算器部署添加到 playbook 中

最后，我们可以将部署配置作为`playbook.yml`文件中的新 play 添加。

```
- hosts: web2
  become: yes
  become_method: sudo
  tasks:
  - name: ensure Java Runtime Environment is installed
    apt:
      name: default-jre
      state: present
  - name: create directory for Calculator
    file:
      path: /var/calculator
      state: directory
  - name: configure Calculator as a service
    file:
      path: /etc/init.d/calculator
      state: link
      force: yes
      src: /var/calculator/calculator.jar
  - name: copy Calculator
    copy:
      src: build/libs/calculator-0.0.1-SNAPSHOT.jar
      dest: /var/calculator/calculator.jar
      mode: a+x
    notify:
    - restart Calculator
  handlers:
  - name: restart Calculator
    service:
      name: calculator
      enabled: yes
      state: restarted
```

让我们走一遍我们定义的步骤：

+   **准备环境**：此任务确保安装了 Java 运行时环境。基本上，它准备了服务器环境，以便计算器应用程序具有所有必要的依赖关系。对于更复杂的应用程序，依赖工具和库的列表可能会更长。

+   **将应用程序配置为服务**：我们希望将计算器应用程序作为 Unix 服务运行，以便以标准方式进行管理。在这种情况下，只需在`/etc/init.d/`目录中创建一个指向我们应用程序的链接即可。

+   **复制新版本**：将应用程序的新版本复制到服务器上。请注意，如果源文件没有更改，则文件不会被复制，因此服务不会重新启动。

+   **重新启动服务**：作为处理程序，每次复制应用程序的新版本时，服务都会重新启动。

# 运行部署

与往常一样，我们可以使用`ansible-playbook`命令执行 playbook。在此之前，我们需要使用 Gradle 构建计算器项目。

```
$ ./gradlew build
$ ansible-playbook playbook.yml
```

成功部署后，服务应该可用，并且我们可以在`http://192.168.0.242:8080/sum?a=1&b=2`上检查它是否正常工作。预期地，它应该返回`3`作为输出。

请注意，我们通过执行一个命令配置了整个环境。而且，如果我们需要扩展服务，只需将新服务器添加到清单中并重新运行`ansible-playbook`命令即可。

我们已经展示了如何使用 Ansible 进行环境配置和应用程序部署。下一步是将 Ansible 与 Docker 一起使用。

# Ansible 与 Docker

正如您可能已经注意到的，Ansible 和 Docker 解决了类似的软件部署问题：

+   **环境配置**：Ansible 和 Docker 都提供了配置环境的方式；然而，它们使用不同的方法。虽然 Ansible 使用脚本（封装在 Ansible 模块中），Docker 将整个环境封装在一个容器中。

+   **依赖性**：Ansible 提供了一种在相同或不同的主机上部署不同服务并让它们一起部署的方式。Docker Compose 具有类似的功能，允许同时运行多个容器。

+   **可扩展性**：Ansible 有助于扩展服务，提供清单和主机组。Docker Compose 具有类似的功能，可以自动增加或减少运行容器的数量。

+   **配置文件自动化**：Docker 和 Ansible 都将整个环境配置和服务依赖关系存储在文件中（存储在源代码控制存储库中）。对于 Ansible，这个文件称为`playbook.yml`。在 Docker 的情况下，我们有 Dockerfile 用于环境和 docker-compose.yml 用于依赖关系和扩展。

+   **简单性**：这两个工具都非常简单易用，并提供了一种通过配置文件和一条命令执行来设置整个运行环境的方式。

如果我们比较这些工具，那么 Docker 做了更多，因为它提供了隔离、可移植性和某种安全性。我们甚至可以想象在没有任何其他配置管理工具的情况下使用 Docker。那么，我们为什么还需要 Ansible 呢？

# Ansible 的好处

Ansible 可能看起来多余；然而，它为交付过程带来了额外的好处：

+   **Docker 环境**：Docker 主机本身必须进行配置和管理。每个容器最终都在 Linux 机器上运行，需要内核打补丁、Docker 引擎更新、网络配置等。而且，可能有不同的服务器机器使用不同的 Linux 发行版，Ansible 的责任是确保 Docker 引擎正常运行。

+   **非 Docker 化应用程序**：并非所有东西都在容器内运行。如果基础设施的一部分是容器化的，另一部分以标准方式或在云中部署，那么 Ansible 可以通过 playbook 配置文件管理所有这些。不以容器方式运行应用程序可能有不同的原因，例如性能、安全性、特定的硬件要求、基于 Windows 的软件，或者与旧软件的工作。

+   **清单**：Ansible 提供了一种非常友好的方式来使用清单管理物理基础设施，清单存储有关所有服务器的信息。它还可以将物理基础设施分成不同的环境：生产、测试、开发。

+   **GUI**：Ansible 提供了一个（商业）名为 Ansible Tower 的 GUI 管理器，旨在改进企业的基础设施管理。

+   **改进测试流程**：Ansible 可以帮助集成和验收测试，并可以以与 Docker Compose 类似的方式封装测试脚本。

我们可以将 Ansible 视为负责基础设施的工具，而将 Docker 视为负责环境配置的工具。概述如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/a8d7f1ee-0867-4b62-a53b-0ae730381cd1.png)

Ansible 管理基础设施：Docker 服务器、Docker 注册表、没有 Docker 的服务器和云提供商。它还关注服务器的物理位置。使用清单主机组，它可以将 Web 服务链接到其地理位置附近的数据库。

# Ansible Docker playbook

Ansible 与 Docker 集成得很顺利，因为它提供了一组专门用于 Docker 的模块。如果我们为基于 Docker 的部署创建一个 Ansible playbook，那么第一个任务需要确保 Docker 引擎已安装在每台机器上。然后，它应该使用 Docker 运行一个容器，或者使用 Docker Compose 运行一组交互式容器。

Ansible 提供了一些非常有用的与 Docker 相关的模块：`docker_image`（构建/管理镜像）、`docker_container`（运行容器）、`docker_image_facts`（检查镜像）、`docker_login`（登录到 Docker 注册表）、`docker_network`（管理 Docker 网络）和`docker_service`（管理 Docker Compose）。

# 安装 Docker

我们可以使用 Ansible playbook 中的以下任务来安装 Docker 引擎。

```
tasks:
- name: add docker apt keys
  apt_key:
    keyserver: hkp://p80.pool.sks-keyservers.net:80
    id: 9DC858229FC7DD38854AE2D88D81803C0EBFCD88
- name: update apt
  apt_repository:
    repo: deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial main stable
    state: present
- name: install Docker
  apt:
    name: docker-ce
    update_cache: yes
    state: present
- name: add admin to docker group
  user:
    name: admin
    groups: docker
    append: yes
- name: install python-pip
  apt:
    name: python-pip
    state: present
- name: install docker-py
  pip:
    name: docker-py
- name: install Docker Compose
  pip:
    name: docker-compose
    version: 1.9.0
```

每个操作系统的 playbook 看起来略有不同。这里介绍的是针对 Ubuntu 16.04 的。

此配置安装 Docker 引擎，使`admin`用户能够使用 Docker，并安装了 Docker Compose 及其依赖工具。

或者，您也可以使用`docker_ubuntu`角色，如此处所述：[`www.ansible.com/2014/02/12/installing-and-building-docker-with-ansible`](https://www.ansible.com/2014/02/12/installing-and-building-docker-with-ansible)。

安装 Docker 后，我们可以添加一个任务，该任务将运行一个 Docker 容器。

# 运行 Docker 容器

使用`docker_container`模块来运行 Docker 容器，它看起来与我们为 Docker Compose 配置所呈现的非常相似。让我们将其添加到`playbook.yml`文件中。

```
- name: run Redis container
  docker_container:
    name: redis
    image: redis
    state: started
    exposed_ports:
    - 6379
```

您可以在官方 Ansible 页面上阅读有关`docker_container`模块的所有选项的更多信息：[`docs.ansible.com/ansible/docker_container_module.html`](https://docs.ansible.com/ansible/docker_container_module.html)。

现在我们可以执行 playbook 来观察 Docker 是否已安装并且 Redis 容器已启动。请注意，这是一种非常方便的使用 Docker 的方式，因为我们不需要在每台机器上手动安装 Docker 引擎。

# 使用 Docker Compose

Ansible playbook 与 Docker Compose 配置非常相似。它们甚至共享相同的 YAML 文件格式。而且，可以直接从 Ansible 使用`docker-compose.yml`。我们将展示如何做到这一点，但首先让我们定义`docker-compose.yml`文件。

```
version: "2"
services:
  calculator:
    image: leszko/calculator:latest
    ports:
    - 8080
  redis:
    image: redis:latest
```

这几乎与我们在上一章中定义的内容相同。这一次，我们直接从 Docker Hub 注册表获取计算器镜像，并且不在`docker-compose.yml`中构建它，因为我们希望构建一次镜像，将其推送到注册表，然后在每个部署步骤（在每个环境中）重复使用它，以确保相同的镜像部署在每台 Docker 主机上。当我们有了`docker-compose.yml`，我们就准备好向`playbook.yml`添加新任务了。

```
- name: copy docker-compose.yml
  copy:
    src: ./docker-compose.yml
    dest: ./docker-compose.yml
- name: run docker-compose
  docker_service:
    project_src: .
    state: present
```

我们首先将 docker-compose.yml 文件复制到服务器，然后执行`docker-compose`。结果，Ansible 创建了两个容器：计算器和 Redis。

我们已经看到了 Ansible 的最重要特性。在接下来的章节中，我们会稍微介绍一下基础设施和应用程序版本控制。在本章结束时，我们将介绍如何使用 Ansible 来完成持续交付流程。

# 练习

在本章中，我们已经介绍了 Ansible 的基础知识以及与 Docker 一起使用它的方式。作为练习，我们提出以下任务：

1.  创建服务器基础设施并使用 Ansible 进行管理。

+   连接物理机器或运行 VirtualBox 机器来模拟远程服务器

+   配置 SSH 访问远程机器（SSH 密钥）

+   在远程机器上安装 Python

+   创建一个包含远程机器的 Ansible 清单

+   运行 Ansible 的临时命令（使用`ping`模块）来检查基础设施是否配置正确

1.  创建一个基于 Python 的“hello world”网络服务，并使用 Ansible 剧本在远程机器上部署它。

+   服务可以与本章练习中描述的完全相同

+   创建一个部署服务到远程机器的剧本

+   运行`ansible-playbook`命令并检查服务是否已部署

# 总结

我们已经介绍了配置管理过程及其与 Docker 的关系。本章的关键要点如下：

+   配置管理是创建和应用基础设施和应用程序的配置的过程

+   Ansible 是最流行的配置管理工具之一。它是无代理的，因此不需要特殊的服务器配置

+   Ansible 可以与临时命令一起使用，但真正的力量在于 Ansible 剧本

+   Ansible 剧本是环境应该如何配置的定义

+   Ansible 角色的目的是重用剧本的部分。

+   Ansible Galaxy 是一个在线服务，用于共享 Ansible 角色

+   与仅使用 Docker 和 Docker Compose 相比，Ansible 与 Docker 集成良好并带来额外的好处

在下一章中，我们将结束持续交付过程并完成最终的 Jenkins 流水线。


# 第七章：持续交付流水线

我们已经涵盖了持续交付过程中最关键的部分：提交阶段、构件存储库、自动验收测试和配置管理。

在本章中，我们将重点关注最终流水线的缺失部分，即环境和基础设施、应用程序版本控制和非功能性测试。

本章涵盖以下要点：

+   设计不同的软件环境及其基础设施

+   保护 Jenkins 代理和服务器之间的连接

+   引入各种非功能性测试

+   介绍持续交付过程中非功能性测试的挑战

+   解释不同类型的应用程序版本控制

+   完成持续交付流水线

+   介绍烟雾测试的概念并将其添加到最终流水线中

# 环境和基础设施

到目前为止，我们总是使用一个 Docker 主机来处理一切，并将其视为无尽资源的虚拟化，我们可以在其中部署一切。显然，Docker 主机实际上可以是一组机器，我们将在接下来的章节中展示如何使用 Docker Swarm 创建它。然而，即使 Docker 主机在资源方面是无限的，我们仍然需要考虑底层基础设施，至少有两个原因：

+   机器的物理位置很重要

+   不应在生产物理机器上进行测试

考虑到这些事实，在本节中，我们将讨论不同类型的环境，在持续交付过程中的作用以及基础设施安全方面。

# 环境类型

有四种最常见的环境类型：生产、暂存、QA（测试）和开发。让我们讨论每种环境及其基础设施。

# 生产

生产环境是最终用户使用的环境。它存在于每家公司中，当然，它是最重要的环境。

让我们看看下面的图表，看看大多数生产环境是如何组织的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/3092eae3-1a55-4505-987b-d3aff24db07c.png)

用户通过负载均衡器访问服务，负载均衡器选择确切的机器。如果应用程序在多个物理位置发布，那么（首先）设备通常是基于 DNS 的地理负载均衡器。在每个位置，我们都有一个服务器集群。如果我们使用 Docker，那么这个服务器集群可以隐藏在一个或多个 Docker 主机后面（这些主机在内部由使用 Docker Swarm 的许多机器组成）。

机器的物理位置很重要，因为请求-响应时间可能会因物理距离而有显着差异。此外，数据库和其他依赖服务应该位于靠近部署服务的机器上。更重要的是，数据库应该以一种方式进行分片，以使不同位置之间的复制开销最小化。否则，我们可能会等待数据库在彼此相距很远的实例之间达成共识。有关物理方面的更多细节超出了本书的范围，但重要的是要记住，Docker 并不总是解决问题的灵丹妙药。

容器化和虚拟化使您可以将服务器视为无限资源；然而，一些物理方面，如位置，仍然相关。

# 暂存

暂存环境是发布候选版本部署的地方，以便在上线之前进行最终测试。理想情况下，这个环境应该是生产环境的镜像。

让我们看看以下内容，以了解在交付过程的背景下，这样的环境应该是什么样子的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/3dcb04d1-39d0-4e73-9773-1de9f5de4b47.png)

请注意，暂存环境是生产的精确克隆。如果应用程序在多个位置部署，那么暂存环境也应该有多个位置。

在持续交付过程中，所有自动接受功能和非功能测试都针对这个环境运行。虽然大多数功能测试通常不需要相同的类似生产的基础设施，但在非功能（尤其是性能）测试的情况下，这是必须的。

为了节省成本，暂存基础设施与生产环境不同（通常包含较少的机器）并不罕见。然而，这种方法可能导致许多生产问题。 *Michael T. Nygard* 在他的著作 *Release It!* 中举了一个真实场景的例子，其中暂存环境使用的机器比生产环境少。

故事是这样的：在某家公司，系统一直很稳定，直到某个代码更改导致生产环境变得极其缓慢，尽管所有压力测试都通过了。这是怎么可能的？事实上，有一个同步点，每个服务器都要与其他服务器通信。在暂存环境中，只有一个服务器，所以实际上没有阻塞。然而，在生产环境中，有许多服务器，导致服务器相互等待。这个例子只是冰山一角，如果暂存环境与生产环境不同，许多生产问题可能无法通过验收测试来测试。

# QA

QA 环境（也称为测试环境）旨在供 QA 团队进行探索性测试，以及依赖我们服务的外部应用程序进行集成测试。QA 环境的用例和基础设施如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/e9e70c25-4395-435b-91ff-36d3657f285d.png)

虽然暂存环境不需要稳定（在持续交付的情况下，它在每次提交到存储库的代码更改后都会更改），但 QA 实例需要提供一定的稳定性，并公开与生产环境相同（或向后兼容）的 API。与暂存环境相反，基础设施可以与生产环境不同，因为其目的不是确保发布候选版本正常工作。

一个非常常见的情况是为了 QA 实例的目的分配较少的机器（例如，只来自一个位置）。

部署到 QA 环境通常是在一个单独的流水线中进行的，这样它就可以独立于自动发布流程。这种方法很方便，因为 QA 实例的生命周期与生产环境不同（例如，QA 团队可能希望对从主干分支出来的实验性代码进行测试）。

# 开发

开发环境可以作为所有开发人员共享的服务器创建，或者每个开发人员可以拥有自己的开发环境。这里呈现了一个简单的图表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/4ded0bd8-f76b-4509-bd96-f0cb95bd5606.png)

开发环境始终包含代码的最新版本。它用于实现开发人员之间的集成，并且可以像 QA 环境一样对待，但是由开发人员而不是 QA 使用。

# 持续交付中的环境

对于持续交付过程，暂存环境是必不可少的。在一些非常罕见的情况下，当性能不重要且项目没有太多依赖性时，我们可以在本地（开发）Docker 主机上执行验收测试（就像我们在上一章中所做的那样），但这应该是一个例外，而不是规则。在这种情况下，我们总是面临与环境相关的一些生产问题的风险。

其他环境通常对于持续交付并不重要。如果我们希望在每次提交时部署到 QA 或开发环境，那么我们可以为此创建单独的流水线（小心不要混淆主要发布流水线）。在许多情况下，部署到 QA 环境是手动触发的，因为它可能与生产环境有不同的生命周期。

# 保护环境

所有环境都需要得到很好的保护。这是明显的。更明显的是，最重要的要求是保持生产环境的安全，因为我们的业务取决于它，任何安全漏洞的后果在那里可能是最严重的。

安全是一个广泛的话题。在本节中，我们只关注与持续交付过程相关的主题。然而，建立完整的服务器基础设施需要更多关于安全的知识。

在持续交付过程中，从属必须能够访问服务器，以便它可以部署应用程序。

提供从属机器与服务器凭据的不同方法：

+   **将 SSH 密钥放入从属中：**如果我们不使用动态 Docker 从属配置，那么我们可以配置 Jenkins 从属机器以包含私有 SSH 密钥。

+   **将 SSH 密钥放入从属镜像中：**如果我们使用动态 Docker 从属配置，我们可以将 SSH 私钥添加到 Docker 从属镜像中。然而，这会产生可能的安全漏洞，因为任何访问该镜像的人都将可以访问生产服务器。

+   **Jenkins 凭据**：我们可以配置 Jenkins 来存储凭据并在流程中使用它们。

+   **复制到从属 Jenkins 插件**：我们可以在启动 Jenkins 构建时动态地将 SSH 密钥复制到从属系统中。

每种解决方案都有一些优点和缺点。在使用任何一种解决方案时，我们都必须格外小心，因为当一个从属系统可以访问生产环境时，任何人入侵从属系统就等于入侵生产环境。

最危险的解决方案是将 SSH 私钥放入 Jenkins 从属系统镜像中，因为镜像存储的所有地方（Docker 注册表或带有 Jenkins 的 Docker 主机）都需要得到很好的保护。

# 非功能性测试

在上一章中，我们学到了很多关于功能需求和自动化验收测试。然而，对于非功能性需求，我们应该怎么办呢？甚至更具挑战性的是，如果没有需求怎么办？在持续交付过程中，我们应该完全跳过它们吗？让我们在本节中回答这些问题。

软件的非功能性方面总是重要的，因为它们可能对系统的运行造成重大风险。

例如，许多应用程序失败，是因为它们无法承受用户数量突然增加的负载。在《可用性工程》一书中，Jakob Nielsen 写道，1.0 秒是用户思维流程保持不间断的极限。想象一下，我们的系统在负载增加的情况下开始超过这个极限。用户可能会因为性能问题而停止使用服务。考虑到这一点，非功能性测试与功能性测试一样重要。

长话短说，我们应该始终为非功能性测试采取以下步骤：

+   决定哪些非功能性方面对我们的业务至关重要

+   对于每一个：

+   指定测试的方式与我们为验收测试所做的方式相同

+   在持续交付流程中添加一个阶段（在验收测试之后，应用程序仍然部署在暂存环境中）

+   应用程序只有在所有非功能性测试通过后才能进入发布阶段

无论非功能性测试的类型如何，其思想总是相同的。然而，方法可能略有不同。让我们来看看不同的测试类型以及它们带来的挑战。

# 非功能性测试的类型

功能测试总是与系统行为相关。相反，非功能测试涉及许多不同的方面。让我们讨论最常见的系统属性以及它们如何在持续交付过程中进行测试。

# 性能测试

性能测试是最广泛使用的非功能测试。它们衡量系统的响应能力和稳定性。我们可以创建的最简单的性能测试是向 Web 服务发送请求并测量其往返时间（RTT）。

性能测试有不同的定义。在许多地方，它们意味着包括负载、压力和可伸缩性测试。有时它们也被描述为白盒测试。在本书中，我们将性能测试定义为衡量系统延迟的最基本的黑盒测试形式。

为了进行性能测试，我们可以使用专用框架（对于 Java 来说，最流行的是 JMeter），或者只是使用我们用于验收测试的相同工具。一个简单的性能测试通常被添加为管道阶段，就在验收测试之后。如果往返时间超过给定限制，这样的测试应该失败，并且它可以检测到明显减慢服务的错误。

Jenkins 的 JMeter 插件可以显示随时间变化的性能趋势。

# 负载测试

负载测试用于检查系统在有大量并发请求时的功能。虽然系统对单个请求可能非常快，但这并不意味着它在同时处理 1000 个请求时速度足够快。在负载测试期间，我们测量许多并发调用的平均请求-响应时间，通常是从许多机器上执行的。负载测试是发布周期中非常常见的 QA 阶段。为了自动化它，我们可以使用与简单性能测试相同的工具；然而，在较大系统的情况下，我们可能需要一个单独的客户端环境来执行大量并发请求。

# 压力测试

压力测试，也称为容量测试或吞吐量测试，是一种确定多少并发用户可以访问我们的服务的测试。这听起来与负载测试相同；然而，在负载测试的情况下，我们将并发用户数量（吞吐量）设置为一个给定的数字，检查响应时间（延迟），并且如果超过限制，则使构建失败。然而，在压力测试期间，我们保持延迟恒定，并增加吞吐量以发现系统仍然可操作时的最大并发调用数量。因此，压力测试的结果可能是通知我们的系统可以处理 10,000 个并发用户，这有助于我们为高峰使用时间做好准备。

压力测试不太适合连续交付流程，因为它需要进行长时间的测试，同时并发请求数量不断增加。它应该准备为一个独立的脚本或一个独立的 Jenkins 流水线，并在需要时触发，当我们知道代码更改可能会导致性能问题时。

# 可扩展性测试

可扩展性测试解释了当我们增加更多服务器或服务时延迟和吞吐量的变化。完美的特征应该是线性的，这意味着如果我们有一个服务器，当有 100 个并行用户使用时，平均请求-响应时间为 500 毫秒，那么添加另一个服务器将保持响应时间不变，并允许我们添加另外 100 个并行用户。然而，在现实中，由于保持服务器之间的数据一致性，通常很难实现这一点。

可扩展性测试应该是自动化的，并且应该提供图表，展示机器数量和并发用户数量之间的关系。这些数据有助于确定系统的限制以及增加更多机器不会有所帮助的点。

可扩展性测试，类似于压力测试，很难放入连续交付流程中，而应该保持独立。

# 耐久测试

耐久测试，也称为长期测试，长时间运行系统，以查看性能是否在一定时间后下降。它们可以检测内存泄漏和稳定性问题。由于它们需要系统长时间运行，因此在连续交付流程中运行它们是没有意义的。

# 安全测试

安全测试涉及与安全机制和数据保护相关的不同方面。一些安全方面纯粹是功能需求，例如身份验证、授权或角色分配。这些部分应该与任何其他功能需求一样在验收测试阶段进行检查。还有其他安全方面是非功能性的；例如，系统应该受到 SQL 注入的保护。没有客户可能会明确指定这样的要求，但这是隐含的。

安全测试应该作为连续交付的一个流水线阶段包括在内。它们可以使用与验收测试相同的框架编写，也可以使用专门的安全测试框架，例如 BDD 安全。

安全也应始终成为解释性测试过程的一部分，测试人员和安全专家会发现安全漏洞并添加新的测试场景。

# 可维护性测试

可维护性测试解释了系统维护的简单程度。换句话说，它们评判了代码质量。我们已经在提交阶段有了相关的阶段，检查测试覆盖率并进行静态代码分析。Sonar 工具也可以提供一些关于代码质量和技术债务的概述。

# 恢复测试

恢复测试是一种确定系统在因软件或硬件故障而崩溃后能够多快恢复的技术。最好的情况是，即使系统的一部分服务停止，系统也不会完全崩溃。一些公司甚至会故意进行生产故障，以检查他们是否能够在灾难中生存。最著名的例子是 Netflix 和他们的混沌猴工具，该工具会随机终止生产环境的随机实例。这种方法迫使工程师编写能够使系统对故障具有弹性的代码。

恢复测试显然不是连续交付过程的一部分，而是定期事件，用于检查整体健康状况。

您可以在[`github.com/Netflix/chaosmonkey`](https://github.com/Netflix/chaosmonkey)了解更多关于混沌猴的信息。

还有许多与代码和持续交付过程更接近或更远的非功能测试类型。其中一些与法律相关，如合规性测试；其他与文档或国际化相关。还有可用性测试和容量测试（检查系统在大量数据情况下的表现）。然而，大多数这些测试在持续交付过程中并没有任何作用。

# 非功能挑战

非功能方面给软件开发和交付带来了新的挑战：

+   **长时间运行测试**：测试可能需要很长时间运行，并且可能需要特殊的执行环境。

+   **增量性质**：很难设置测试应该在何时失败的限值（除非 SLA 定义得很好）。即使设置了边缘限制，应用程序也可能逐渐接近限制。实际上，在大多数情况下，没有任何代码更改导致测试失败。

+   **模糊的需求**：用户通常对非功能需求没有太多的输入。他们可能会提供一些关于请求-响应时间或用户数量的指导，但他们可能不会太了解可维护性、安全性或可扩展性。

+   **多样性**：有很多不同的非功能测试，选择应该实施哪些需要做一些妥协。

解决非功能方面的最佳方法是采取以下步骤：

1.  列出所有非功能测试类型。

1.  明确划掉您的系统不需要的测试。您可能不需要某种测试的原因有很多，例如：

+   该服务非常小，简单的性能测试就足够了

+   该系统仅内部使用，仅供只读，因此可能不需要进行任何安全检查。

+   该系统仅设计用于一台机器，不需要任何扩展

+   创建某些测试的成本太高

1.  将您的测试分为两组：

+   **持续交付**：可以将其添加到流水线中

+   **分析**：由于执行时间、性质或相关成本，无法将其添加到流水线中

1.  对于持续交付组，实施相关的流水线阶段。

1.  对于分析组：

+   创建自动化测试

+   安排何时运行它们

+   安排会议讨论它们的结果并制定行动计划

一个非常好的方法是进行夜间构建，其中包括不适合持续交付流程的长时间测试。然后，可以安排每周一次的会议来监视和分析系统性能的趋势。

正如所述，有许多类型的非功能性测试，它们给交付过程带来了额外的挑战。然而，为了系统的稳定性，这些测试绝不能被简单地跳过。技术实现因测试类型而异，但在大多数情况下，它们可以以类似的方式实现功能验收测试，并应该针对暂存环境运行。

如果您对非功能性测试、系统属性和系统稳定性感兴趣，请阅读 Michael T. Nygard 的书《发布它！》。

# 应用版本控制

到目前为止，在每次 Jenkins 构建期间，我们都创建了一个新的 Docker 镜像，将其推送到 Docker 注册表，并在整个过程中使用**最新**版本。然而，这种解决方案至少有三个缺点：

+   如果在 Jenkins 构建期间，在验收测试之后，有人推送了图像的新版本，那么我们可能会发布未经测试的版本。

+   我们总是推送以相同方式命名的镜像；因此，在 Docker 注册表中，它被有效地覆盖了。

+   仅通过哈希样式 ID 来管理没有版本的图像非常困难

管理 Docker 镜像版本与持续交付过程的推荐方式是什么？在本节中，我们将看到不同的版本控制策略，并学习在 Jenkins 流水线中创建版本的不同方法。

# 版本控制策略

有不同的应用版本控制方式。

让我们讨论这些最流行的解决方案，这些解决方案可以与持续交付过程一起应用（每次提交都创建一个新版本）。

+   语义化版本控制：最流行的解决方案是使用基于序列的标识符（通常以 x.y.z 的形式）。这种方法需要 Jenkins 在存储库中进行提交，以增加当前版本号，通常存储在构建文件中。这种解决方案得到了 Maven、Gradle 和其他构建工具的良好支持。标识符通常由三个数字组成。

+   **x**：这是主要版本；当增加此版本时，软件不需要向后兼容

+   **y**：这是次要版本；当增加版本时，软件需要向后兼容

+   **z:** 这是构建编号；有时也被认为是向后和向前兼容的更改

+   **时间戳**：对于应用程序版本，使用构建的日期和时间比顺序号更简洁，但在持续交付过程中非常方便，因为它不需要 Jenkins 向存储库提交。

+   **哈希**：随机生成的哈希版本具有日期时间的好处，并且可能是可能的最简单的解决方案。缺点是无法查看两个版本并告诉哪个是最新的。

+   **混合**：有许多先前描述的解决方案的变体，例如，带有日期时间的主要和次要版本。

所有解决方案都可以与持续交付流程一起使用。语义化版本控制要求从构建执行向存储库提交，以便在源代码存储库中增加版本。

Maven（和其他构建工具）推广了版本快照，为未发布的版本添加了后缀 SNAPSHOT，但仅用于开发过程。由于持续交付意味着发布每个更改，因此没有快照。

# Jenkins 流水线中的版本控制

正如前面所述，使用软件版本控制时有不同的可能性，每种可能性都可以在 Jenkins 中实现。

举个例子，让我们使用日期时间。

为了使用 Jenkins 中的时间戳信息，您需要安装 Build Timestamp 插件，并在 Jenkins 配置中设置时间戳格式（例如为"yyyyMMdd-HHmm"）。

在我们使用 Docker 镜像的每个地方，我们需要添加标签后缀：`${BUILD_TIMESTAMP}`。

例如，`Docker 构建`阶段应该是这样的：

```
sh "docker build -t leszko/calculator:${BUILD_TIMESTAMP} ."
```

更改后，当我们运行 Jenkins 构建时，我们应该在我们的 Docker 注册表中使用时间戳版本标记图像。

请注意，在显式标记图像后，它不再隐式标记为最新版本。

版本控制完成后，我们终于准备好完成持续交付流程。

# 完成持续交付流程

在讨论了 Ansible、环境、非功能测试和版本控制的所有方面后，我们准备扩展 Jenkins 流水线并完成一个简单但完整的持续交付流程。

我们将分几步来完成：

+   创建暂存和生产环境清单

+   更新验收测试以使用远程主机（而不是本地）

+   将应用程序发布到生产环境

+   添加一个冒烟测试，确保应用程序已成功发布

# 清单

在最简单的形式中，我们可以有两个环境：暂存和生产，每个环境都有一个 Docker 主机。在现实生活中，如果我们希望在不同位置拥有服务器或具有不同要求，可能需要为每个环境添加更多的主机组。

让我们创建两个 Ansible 清单文件。从暂存开始，我们可以定义`inventory/staging`文件。假设暂存地址是`192.168.0.241`，它将具有以下内容：

```
[webservers]
web1 ansible_host=192.168.0.241 ansible_user=admin
```

类比而言，如果生产 IP 地址是`192.168.0.242`，那么`inventory/production`应该如下所示：

```
[webservers]
web2 ansible_host=192.168.0.242 ansible_user=admin
```

只为每个环境拥有一个机器可能看起来过于简化了；然而，使用 Docker Swarm（我们稍后在本书中展示），一组主机可以隐藏在一个 Docker 主机后面。

有了定义的清单，我们可以更改验收测试以使用暂存环境。

# 验收测试环境

根据我们的需求，我们可以通过在本地 Docker 主机上运行应用程序（就像我们在上一章中所做的那样）或者使用远程暂存环境来测试应用程序。前一种解决方案更接近于生产中发生的情况，因此可以被认为是更好的解决方案。这与上一章的*方法 1：首先使用 Jenkins 验收测试*部分非常接近。唯一的区别是现在我们将应用程序部署到远程 Docker 主机上。

为了做到这一点，我们可以使用带有`-H`参数的`docker`（或`docker-compose`命令），该参数指定了远程 Docker 主机地址。这将是一个很好的解决方案，如果您不打算使用 Ansible 或任何其他配置管理工具，那么这就是前进的方式。然而，出于本章已经提到的原因，使用 Ansible 是有益的。在这种情况下，我们可以在持续交付管道中使用`ansible-playbook`命令。

```
stage("Deploy to staging") {
    steps {
        sh "ansible-playbook playbook.yml -i inventory/staging"
    }
}
```

如果`playbook.yml`和 docker-compose.yml 看起来与*使用 Docker 的 Ansible*部分中的内容相同，那么将足以将应用程序与依赖项部署到暂存环境中。

“验收测试”阶段与上一章完全相同。唯一的调整可能是暂存环境的主机名（或其负载均衡器）。还可以添加用于对运行在暂存环境上的应用程序进行性能测试或其他非功能测试的阶段。

在所有测试通过后，是时候发布应用程序了。

# 发布

生产环境应尽可能接近暂存环境。发布的 Jenkins 步骤也应与将应用程序部署到暂存环境的阶段非常相似。

在最简单的情况下，唯一的区别是清单文件和应用程序配置（例如，在 Spring Boot 应用程序的情况下，我们将设置不同的 Spring 配置文件，这将导致使用不同的属性文件）。在我们的情况下，没有应用程序属性，所以唯一的区别是清单文件。

```
stage("Release") {
    steps {
        sh "ansible-playbook playbook.yml -i inventory/production"
    }
}
```

实际上，如果我们想要实现零停机部署，发布步骤可能会更加复杂。关于这个主题的更多内容将在接下来的章节中介绍。

发布完成后，我们可能认为一切都已完成；然而，还有一个缺失的阶段，即冒烟测试。

# 冒烟测试

冒烟测试是验收测试的一个非常小的子集，其唯一目的是检查发布过程是否成功完成。否则，我们可能会出现这样的情况：应用程序完全正常，但发布过程中出现问题，因此我们可能最终得到一个无法工作的生产环境。

冒烟测试通常与验收测试以相同的方式定义。因此，管道中的“冒烟测试”阶段应该如下所示：

```
stage("Smoke test") {
    steps {
        sleep 60
        sh "./smoke_test.sh"
    }
}
```

设置完成后，连续交付构建应该自动运行，并且应用程序应该发布到生产环境。通过这一步，我们已经完成了连续交付管道的最简单但完全有效的形式。

# 完整的 Jenkinsfile

总之，在最近的章节中，我们创建了相当多的阶段，这导致了一个完整的连续交付管道，可以成功地应用于许多项目。

接下来我们看到计算器项目的完整 Jenkins 文件：

```
pipeline {
  agent any

  triggers {
    pollSCM('* * * * *')
  }

  stages {
    stage("Compile") { steps { sh "./gradlew compileJava" } }
    stage("Unit test") { steps { sh "./gradlew test" } }

    stage("Code coverage") { steps {
      sh "./gradlew jacocoTestReport"
      publishHTML (target: [
              reportDir: 'build/reports/jacoco/test/html',
              reportFiles: 'index.html',
              reportName: "JaCoCo Report" ])
      sh "./gradlew jacocoTestCoverageVerification"
    } }

    stage("Static code analysis") { steps {
      sh "./gradlew checkstyleMain"
      publishHTML (target: [
              reportDir: 'build/reports/checkstyle/',
              reportFiles: 'main.html',
              reportName: "Checkstyle Report" ])
    } }

    stage("Build") { steps { sh "./gradlew build" } }

    stage("Docker build") { steps {
      sh "docker build -t leszko/calculator:${BUILD_TIMESTAMP} ."
   } }

    stage("Docker push") { steps {
      sh "docker push leszko/calculator:${BUILD_TIMESTAMP}"
    } }

    stage("Deploy to staging") { steps {
      sh "ansible-playbook playbook.yml -i inventory/staging"
      sleep 60
    } }

    stage("Acceptance test") { steps { sh "./acceptance_test.sh" } }  

    // Performance test stages

    stage("Release") { steps {
      sh "ansible-playbook playbook.yml -i inventory/production"
      sleep 60
    } }

    stage("Smoke test") { steps { sh "./smoke_test.sh" } }
  }
}
```

您可以在 GitHub 上找到这个 Jenkinsfile：[`github.com/leszko/calculator/blob/master/Jenkinsfile`](https://github.com/leszko/calculator/blob/master/Jenkinsfile)。

# 练习

在本章中，我们涵盖了持续交付管道的许多新方面；为了更好地理解这个概念，我们建议您进行以下练习：

1.  添加一个性能测试，测试“hello world”服务：

+   “hello world”服务可以从上一章中获取

+   创建一个`performance_test.sh`脚本，同时进行 100 次调用，并检查平均请求-响应时间是否低于 1 秒

+   您可以使用 Cucumber 或`curl`命令来执行脚本

1.  创建一个 Jenkins 管道，构建“hello world”网络服务作为版本化的 Docker 镜像，并执行性能测试：

+   创建“Docker 构建”阶段，用于构建带有“hello world”服务的 Docker 镜像，并添加时间戳作为版本标记

+   创建一个使用 Docker 镜像的 Ansible 剧本

+   添加“部署到暂存”阶段，将镜像部署到远程机器

+   添加“性能测试”阶段，执行`performance_test.sh`

+   运行管道并观察结果

# 摘要

在本章中，我们完成了持续交付管道，最终发布了应用程序。以下是本章的要点：

+   为了持续交付的目的，两个环境是必不可少的：暂存和生产。

+   非功能测试是持续交付过程的重要组成部分，应始终被视为管道阶段。

+   不符合持续交付过程的非功能测试应被视为定期任务，以监控整体性能趋势。

+   应用程序应始终进行版本控制；但是，版本控制策略取决于应用程序的类型。

+   最小的持续交付管道可以被实现为一系列以发布和冒烟测试为结束的脚本阶段。

+   冒烟测试应始终作为持续交付管道的最后阶段添加，以检查发布是否成功。

在下一章中，我们将介绍 Docker Swarm 工具，该工具可帮助我们创建 Docker 主机集群。


# 第八章：使用 Docker Swarm 进行集群化

我们已经涵盖了持续交付流水线的所有基本方面。在本章中，我们将看到如何将 Docker 环境从单个 Docker 主机更改为一组机器，并如何与 Jenkins 一起使用它。

本章涵盖以下内容：

+   解释服务器集群的概念

+   介绍 Docker Swarm 及其最重要的功能

+   介绍如何从多个 Docker 主机构建群集

+   在集群上运行和扩展 Docker 镜像

+   探索高级群集功能：滚动更新、排水节点、多个管理节点和调整调度策略

+   在集群上部署 Docker Compose 配置

+   介绍 Kubernetes 和 Apache Mesos 作为 Docker Swarm 的替代方案

+   在集群上动态扩展 Jenkins 代理

# 服务器集群

到目前为止，我们已经分别与每台机器进行了交互。即使我们使用 Ansible 在多台服务器上重复相同的操作，我们也必须明确指定应在哪台主机上部署给定服务。然而，在大多数情况下，如果服务器共享相同的物理位置，我们并不关心服务部署在哪台特定的机器上。我们所需要的只是让它可访问并在许多实例中复制。我们如何配置一组机器以便它们共同工作，以至于添加新的机器不需要额外的设置？这就是集群的作用。

在本节中，您将介绍服务器集群的概念和 Docker Swarm 工具包。

# 介绍服务器集群

服务器集群是一组连接的计算机，它们以一种可以类似于单个系统的方式一起工作。服务器通常通过本地网络连接，连接速度足够快，以确保服务分布的影响很小。下图展示了一个简单的服务器集群：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/5932276e-c8df-4777-80c1-69ac1bbccded.png)

用户通过称为管理器的主机访问集群，其界面应类似于常规 Docker 主机。在集群内，有多个工作节点接收任务，执行它们，并通知管理器它们的当前状态。管理器负责编排过程，包括任务分派、服务发现、负载平衡和工作节点故障检测。

管理者也可以执行任务，这是 Docker Swarm 的默认配置。然而，对于大型集群，管理者应该配置为仅用于管理目的。

# 介绍 Docker Swarm

Docker Swarm 是 Docker 的本地集群系统，将一组 Docker 主机转换为一个一致的集群，称为 swarm。连接到 swarm 的每个主机都扮演管理者或工作节点的角色（集群中必须至少有一个管理者）。从技术上讲，机器的物理位置并不重要；然而，将所有 Docker 主机放在一个本地网络中是合理的，否则，管理操作（或在多个管理者之间达成共识）可能需要大量时间。

自 Docker 1.12 以来，Docker Swarm 已经作为 swarm 模式被原生集成到 Docker Engine 中。在旧版本中，需要在每个主机上运行 swarm 容器以提供集群功能。

关于术语，在 swarm 模式下，运行的镜像称为**服务**，而不是在单个 Docker 主机上运行的**容器**。一个服务运行指定数量的**任务**。任务是 swarm 的原子调度单元，保存有关容器和应在容器内运行的命令的信息。**副本**是在节点上运行的每个容器。副本的数量是给定服务的所有容器的预期数量。

让我们看一下展示术语和 Docker Swarm 集群过程的图像：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/503d41a5-5167-45a9-ac26-547095f5f638.png)

我们首先指定一个服务，Docker 镜像和副本的数量。管理者会自动将任务分配给工作节点。显然，每个复制的容器都是从相同的 Docker 镜像运行的。在所呈现的流程的上下文中，Docker Swarm 可以被视为 Docker Engine 机制的一层，负责容器编排。

在上面的示例图像中，我们有三个任务，每个任务都在单独的 Docker 主机上运行。然而，也可能所有容器都在同一个 Docker 主机上启动。一切取决于分配任务给工作节点的管理节点使用的调度策略。我们将在后面的单独章节中展示如何配置该策略。

# Docker Swarm 功能概述

Docker Swarm 提供了许多有趣的功能。让我们来看看最重要的几个：

+   负载均衡：Docker Swarm 负责负载均衡和分配唯一的 DNS 名称，使得部署在集群上的应用可以与部署在单个 Docker 主机上的应用一样使用。换句话说，一个集群可以以与 Docker 容器类似的方式发布端口，然后集群管理器在集群中的服务之间分发请求。

+   动态角色管理：Docker 主机可以在运行时添加到集群中，因此无需重新启动集群。而且，节点的角色（管理器或工作节点）也可以动态更改。

+   动态服务扩展：每个服务都可以通过 Docker 客户端动态地扩展或缩减。管理节点负责从节点中添加或删除容器。

+   故障恢复：管理器不断监视节点，如果其中任何一个失败，新任务将在不同的机器上启动，以便声明的副本数量保持不变。还可以创建多个管理节点，以防止其中一个失败时发生故障。

+   滚动更新：对服务的更新可以逐步应用；例如，如果我们有 10 个副本并且想要进行更改，我们可以定义每个副本部署之间的延迟。在这种情况下，当出现问题时，我们永远不会出现没有副本正常工作的情况。

+   两种服务模式：可以运行在两种模式下：

+   复制服务：指定数量的复制容器根据调度策略算法分布在节点之间。

+   全球服务：集群中的每个可用节点上都运行一个容器

+   安全性：由于一切都在 Docker 中，Docker Swarm 强制执行 TLS 身份验证和通信加密。还可以使用 CA（或自签名）证书。

让我们看看这在实践中是什么样子。

# 实际中的 Docker Swarm

Docker Engine 默认包含了 Swarm 模式，因此不需要额外的安装过程。由于 Docker Swarm 是一个本地的 Docker 集群系统，管理集群节点是通过`docker`命令完成的，因此非常简单和直观。让我们首先创建一个管理节点和两个工作节点。然后，我们将从 Docker 镜像运行和扩展一个服务。

# 建立一个 Swarm

为了设置一个 Swarm，我们需要初始化管理节点。我们可以在一个即将成为管理节点的机器上使用以下命令来做到这一点：

```
$ docker swarm init

Swarm initialized: current node (qfqzhk2bumhd2h0ckntrysm8l) is now a manager.

To add a worker to this swarm, run the following command:
docker swarm join \
--token SWMTKN-1-253vezc1pqqgb93c5huc9g3n0hj4p7xik1ziz5c4rsdo3f7iw2-df098e2jpe8uvwe2ohhhcxd6w \
192.168.0.143:2377

To add a manager to this swarm, run 'docker swarm join-token manager' and follow the instructions.
```

一个非常常见的做法是使用`--advertise-addr <manager_ip>`参数，因为如果管理机器有多个潜在的网络接口，那么`docker swarm init`可能会失败。

在我们的情况下，管理机器的 IP 地址是`192.168.0.143`，显然，它必须能够从工作节点（反之亦然）访问。请注意，在控制台上打印了要在工作机器上执行的命令。还要注意，已生成了一个特殊的令牌。从现在开始，它将被用来连接机器到集群，并且必须保密。

我们可以使用`docker node`命令来检查 Swarm 是否已创建：

```
$ docker node ls
ID                          HOSTNAME       STATUS  AVAILABILITY  MANAGER STATUS
qfqzhk2bumhd2h0ckntrysm8l * ubuntu-manager Ready   Active        Leader
```

当管理器正常运行时，我们准备将工作节点添加到 Swarm 中。

# 添加工作节点

为了将一台机器添加到 Swarm 中，我们必须登录到给定的机器并执行以下命令：

```
$ docker swarm join \
--token SWMTKN-1-253vezc1pqqgb93c5huc9g3n0hj4p7xik1ziz5c4rsdo3f7iw2-df098e2jpe8uvwe2ohhhcxd6w \
192.168.0.143:2377

This node joined a swarm as a worker.
```

我们可以使用`docker node ls`命令来检查节点是否已添加到 Swarm 中。假设我们已经添加了两个节点机器，输出应该如下所示：

```
$ docker node ls
ID                          HOSTNAME        STATUS  AVAILABILITY  MANAGER STATUS
cr7vin5xzu0331fvxkdxla22n   ubuntu-worker2  Ready   Active 
md4wx15t87nn0c3pyv24kewtz   ubuntu-worker1  Ready   Active 
qfqzhk2bumhd2h0ckntrysm8l * ubuntu-manager  Ready   Active        Leader
```

在这一点上，我们有一个由三个 Docker 主机组成的集群，`ubuntu-manager`，`ubuntu-worker1`和`ubuntu-worker2`。让我们看看如何在这个集群上运行一个服务。

# 部署一个服务

为了在集群上运行一个镜像，我们不使用`docker run`，而是使用专门为 Swarm 设计的`docker service`命令（在管理节点上执行）。让我们启动一个单独的`tomcat`应用并给它命名为`tomcat`：

```
$ docker service create --replicas 1 --name tomcat tomcat
```

该命令创建了服务，因此发送了一个任务来在一个节点上启动一个容器。让我们列出正在运行的服务：

```
$ docker service ls
ID            NAME    MODE        REPLICAS  IMAGE
x65aeojumj05  tomcat  replicated  1/1       tomcat:latest
```

日志确认了`tomcat`服务正在运行，并且有一个副本（一个 Docker 容器正在运行）。我们甚至可以更仔细地检查服务：

```
$ docker service ps tomcat
ID           NAME      IMAGE          NODE            DESIRED STATE CURRENT STATE 
kjy1udwcnwmi tomcat.1  tomcat:latest  ubuntu-manager  Running     Running about a minute ago
```

如果您对服务的详细信息感兴趣，可以使用`docker service inspect <service_name>`命令。

从控制台输出中，我们可以看到容器正在管理节点（`ubuntu-manager`）上运行。它也可以在任何其他节点上启动；管理器会自动使用调度策略算法选择工作节点。我们可以使用众所周知的`docker ps`命令来确认容器正在运行：

```
$ docker ps
CONTAINER ID     IMAGE
COMMAND           CREATED            STATUS              PORTS            NAMES
6718d0bcba98     tomcat@sha256:88483873b279aaea5ced002c98dde04555584b66de29797a4476d5e94874e6de 
"catalina.sh run" About a minute ago Up About a minute   8080/tcp         tomcat.1.kjy1udwcnwmiosiw2qn71nt1r
```

如果我们不希望任务在管理节点上执行，可以使用`--constraint node.role==worker`选项来限制服务。另一种可能性是完全禁用管理节点执行任务，使用`docker node update --availability drain <manager_name>`。

# 扩展服务

当服务运行时，我们可以扩展或缩小它，以便它在许多副本中运行：

```
$ docker service scale tomcat=5
tomcat scaled to 5
```

我们可以检查服务是否已扩展：

```
$ docker service ps tomcat
ID            NAME     IMAGE          NODE            DESIRED STATE  CURRENT STATE 
kjy1udwcnwmi  tomcat.1  tomcat:latest  ubuntu-manager  Running    Running 2 minutes ago 
536p5zc3kaxz  tomcat.2  tomcat:latest  ubuntu-worker2  Running    Preparing 18 seconds ago npt6ui1g9bdp  tomcat.3  tomcat:latest  ubuntu-manager  Running    Running 18 seconds ago zo2kger1rmqc  tomcat.4  tomcat:latest  ubuntu-worker1  Running    Preparing 18 seconds ago 1fb24nf94488  tomcat.5  tomcat:latest  ubuntu-worker2  Running    Preparing 18 seconds ago  
```

请注意，这次有两个容器在`manager`节点上运行，一个在`ubuntu-worker1`节点上，另一个在`ubuntu-worker2`节点上。我们可以通过在每台机器上执行`docker ps`来检查它们是否真的在运行。

如果我们想要删除服务，只需执行以下命令即可：

```
$ docker service rm tomcat
```

您可以使用`docker service ls`命令检查服务是否已被删除，因此所有相关的`tomcat`容器都已停止并从所有节点中删除。

# 发布端口

Docker 服务，类似于容器，具有端口转发机制。我们可以通过添加`-p <host_port>:<container:port>`参数来使用它。启动服务可能如下所示：

```
$ docker service create --replicas 1 --publish 8080:8080 --name tomcat tomcat
```

现在，我们可以打开浏览器，在地址`http://192.168.0.143:8080/`下查看 Tomcat 的主页。

该应用程序可在充当负载均衡器并将请求分发到工作节点的管理主机上使用。可能听起来有点不太直观的是，我们可以使用任何工作节点的 IP 地址访问 Tomcat，例如，如果工作节点在`192.168.0.166`和`192.168.0.115`下可用，我们可以使用`http://192.168.0.166:8080/`和`http://192.168.0.115:8080/`访问相同的运行容器。这是可能的，因为 Docker Swarm 创建了一个路由网格，其中每个节点都有如何转发已发布端口的信息。

您可以阅读有关 Docker Swarm 如何进行负载平衡和路由的更多信息[`docs.docker.com/engine/swarm/ingress/`](https://docs.docker.com/engine/swarm/ingress/)。

默认情况下，使用内部 Docker Swarm 负载平衡。因此，只需将所有请求发送到管理机器，它将负责在节点之间进行分发。另一种选择是配置外部负载均衡器（例如 HAProxy 或 Traefik）。

我们已经讨论了 Docker Swarm 的基本用法。现在让我们深入了解更具挑战性的功能。

# 高级 Docker Swarm

Docker Swarm 提供了许多在持续交付过程中有用的有趣功能。在本节中，我们将介绍最重要的功能。

# 滚动更新

想象一下，您部署了应用程序的新版本。您需要更新集群中的所有副本。一种选择是停止整个 Docker Swarm 服务，并从更新后的 Docker 镜像运行一个新的服务。然而，这种方法会导致服务停止和新服务启动之间的停机时间。在持续交付过程中，停机时间是不可接受的，因为部署可以在每次源代码更改后进行，这通常是经常发生的。那么，在集群中如何实现零停机部署呢？这就是滚动更新的作用。

滚动更新是一种自动替换服务副本的方法，一次替换一个副本，以确保一些副本始终在工作。Docker Swarm 默认使用滚动更新，并且可以通过两个参数进行控制：

+   `update-delay`：启动一个副本和停止下一个副本之间的延迟（默认为 0 秒）

+   `update-parallelism`：同时更新的最大副本数量（默认为 1）

Docker Swarm 滚动更新过程如下：

1.  停止`<update-parallelism>`数量的任务（副本）。

1.  在它们的位置上，运行相同数量的更新任务。

1.  如果一个任务返回**RUNNING**状态，那么等待`<update-delay>`时间。

1.  如果任何时候任何任务返回**FAILED**状态，则暂停更新。

`update-parallelism`参数的值应该根据我们运行的副本数量进行调整。如果数量较小，服务启动速度很快，保持默认值 1 是合理的。`update-delay`参数应设置为比我们应用程序预期的启动时间更长的时间，这样我们就会注意到失败，因此暂停更新。

让我们来看一个例子，将 Tomcat 应用程序从版本 8 更改为版本 9。假设我们有`tomcat:8`服务，有五个副本：

```
$ docker service create --replicas 5 --name tomcat --update-delay 10s tomcat:8
```

我们可以使用`docker service ps tomcat`命令检查所有副本是否正在运行。另一个有用的命令是`docker service inspect`命令，可以帮助检查服务：

```
$ docker service inspect --pretty tomcat

ID:    au1nu396jzdewyq2y8enm0b6i
Name:    tomcat
Service Mode:    Replicated
 Replicas:    5
Placement:
UpdateConfig:
 Parallelism:    1
 Delay:    10s
 On failure:    pause
 Max failure ratio: 0
ContainerSpec:
 Image:    tomcat:8@sha256:835b6501c150de39d2b12569fd8124eaebc53a899e2540549b6b6f8676538484
Resources:
Endpoint Mode:    vip
```

我们可以看到服务已经创建了五个副本，来自于`tomcat:8`镜像。命令输出还包括有关并行性和更新之间的延迟时间的信息（由`docker service create`命令中的选项设置）。

现在，我们可以将服务更新为`tomcat:9`镜像：

```
$ docker service update --image tomcat:9 tomcat
```

让我们看看发生了什么：

```
$ docker service ps tomcat
ID            NAME      IMAGE     NODE            DESIRED STATE  CURRENT STATE 
4dvh6ytn4lsq  tomcat.1  tomcat:8  ubuntu-manager  Running    Running 4 minutes ago 
2mop96j5q4aj  tomcat.2  tomcat:8  ubuntu-manager  Running    Running 4 minutes ago 
owurmusr1c48  tomcat.3  tomcat:9  ubuntu-manager  Running    Preparing 13 seconds ago 
r9drfjpizuxf   \_ tomcat.3  tomcat:8  ubuntu-manager  Shutdown   Shutdown 12 seconds ago 
0725ha5d8p4v  tomcat.4  tomcat:8  ubuntu-manager  Running    Running 4 minutes ago 
wl25m2vrqgc4  tomcat.5  tomcat:8  ubuntu-manager  Running    Running 4 minutes ago       
```

请注意，`tomcat:8`的第一个副本已关闭，第一个`tomcat:9`已经在运行。如果我们继续检查`docker service ps tomcat`命令的输出，我们会注意到每隔 10 秒，另一个副本处于关闭状态，新的副本启动。如果我们还监视`docker inspect`命令，我们会看到值**UpdateStatus: State**将更改为**updating**，然后在更新完成后更改为**completed**。

滚动更新是一个非常强大的功能，允许零停机部署，并且应该始终在持续交付过程中使用。

# 排水节点

当我们需要停止工作节点进行维护，或者我们只是想将其从集群中移除时，我们可以使用 Swarm 排水节点功能。排水节点意味着要求管理器将所有任务移出给定节点，并排除它不接收新任务。结果，所有副本只在活动节点上运行，排水节点处于空闲状态。

让我们看看这在实践中是如何工作的。假设我们有三个集群节点和一个具有五个副本的 Tomcat 服务：

```
$ docker node ls
ID                          HOSTNAME        STATUS  AVAILABILITY  MANAGER STATUS
4mrrmibdrpa3yethhmy13mwzq   ubuntu-worker2  Ready   Active 
kzgm7erw73tu2rjjninxdb4wp * ubuntu-manager  Ready   Active        Leader
yllusy42jp08w8fmze43rmqqs   ubuntu-worker1  Ready   Active 

$ docker service create --replicas 5 --name tomcat tomcat
```

让我们检查一下副本正在哪些节点上运行：

```
$ docker service ps tomcat
ID            NAME      IMAGE          NODE            DESIRED STATE  CURRENT STATE 
zrnawwpupuql  tomcat.1  tomcat:latest  ubuntu-manager  Running    Running 17 minutes ago 
x6rqhyn7mrot  tomcat.2  tomcat:latest  ubuntu-worker1  Running    Running 16 minutes ago 
rspgxcfv3is2  tomcat.3  tomcat:latest  ubuntu-worker2  Running    Running 5 weeks ago 
cf00k61vo7xh  tomcat.4  tomcat:latest  ubuntu-manager  Running    Running 17 minutes ago 
otjo08e06qbx  tomcat.5  tomcat:latest  ubuntu-worker2  Running    Running 5 weeks ago      
```

有两个副本正在`ubuntu-worker2`节点上运行。让我们排水该节点：

```
$ docker node update --availability drain ubuntu-worker2
```

节点被设置为**drain**可用性，因此所有副本应该移出该节点：

```
$ docker service ps tomcat
ID            NAME      IMAGE          NODE            DESIRED STATE  CURRENT STATE
zrnawwpupuql  tomcat.1  tomcat:latest  ubuntu-manager  Running    Running 18 minutes ago 
x6rqhyn7mrot  tomcat.2  tomcat:latest  ubuntu-worker1  Running    Running 17 minutes ago qrptjztd777i  tomcat.3  tomcat:latest  ubuntu-worker1  Running    Running less than a second ago 
rspgxcfv3is2   \_ tomcat.3  tomcat:latest  ubuntu-worker2  Shutdown   Shutdown less than a second ago 
cf00k61vo7xh  tomcat.4  tomcat:latest  ubuntu-manager  Running    Running 18 minutes ago k4c14tyo7leq  tomcat.5  tomcat:latest  ubuntu-worker1  Running    Running less than a second ago 
otjo08e06qbx   \_ tomcat.5  tomcat:latest  ubuntu-worker2  Shutdown   Shutdown less than a second ago   
```

我们可以看到新任务在`ubuntu-worker1`节点上启动，并且旧副本已关闭。我们可以检查节点的状态：

```
$ docker node ls
ID                          HOSTNAME        STATUS  AVAILABILITY  MANAGER STATUS
4mrrmibdrpa3yethhmy13mwzq   ubuntu-worker2  Ready   Drain 
kzgm7erw73tu2rjjninxdb4wp * ubuntu-manager  Ready   Active        Leader
yllusy42jp08w8fmze43rmqqs   ubuntu-worker1  Ready   Active   
```

如预期的那样，`ubuntu-worker2`节点可用（状态为`Ready`），但其可用性设置为排水，这意味着它不托管任何任务。如果我们想要将节点恢复，可以将其可用性检查为`active`：

```
$ docker node update --availability active ubuntu-worker2
```

一个非常常见的做法是排水管理节点，结果是它不会接收任何任务，只做管理工作。

排水节点的另一种方法是从工作节点执行`docker swarm leave`命令。然而，这种方法有两个缺点：

+   有一段时间，副本比预期少（离开 Swarm 之后，在主节点开始在其他节点上启动新任务之前）

+   主节点不控制节点是否仍然在集群中

出于这些原因，如果我们计划暂停工作节点一段时间然后再启动它，建议使用排空节点功能。

# 多个管理节点

拥有单个管理节点是有风险的，因为当管理节点宕机时，整个集群也会宕机。在业务关键系统的情况下，这种情况显然是不可接受的。在本节中，我们将介绍如何管理多个主节点。

为了将新的管理节点添加到系统中，我们需要首先在（当前单一的）管理节点上执行以下命令：

```
$ docker swarm join-token manager

To add a manager to this swarm, run the following command:

docker swarm join \
--token SWMTKN-1-5blnptt38eh9d3s8lk8po3069vbjmz7k7r3falkm20y9v9hefx-a4v5olovq9mnvy7v8ppp63r23 \
192.168.0.143:2377
```

输出显示了令牌和需要在即将成为管理节点的机器上执行的整个命令。执行完毕后，我们应该看到添加了一个新的管理节点。

另一种添加管理节点的选项是使用`docker node promote <node>`命令将其从工作节点角色提升为管理节点。为了将其重新转换为工作节点角色，我们可以使用`docker node demote <node>`命令。

假设我们已经添加了两个额外的管理节点；我们应该看到以下输出：

```
$ docker node ls
ID                          HOSTNAME         STATUS  AVAILABILITY  MANAGER STATUS
4mrrmibdrpa3yethhmy13mwzq   ubuntu-manager2  Ready   Active 
kzgm7erw73tu2rjjninxdb4wp * ubuntu-manager   Ready   Active        Leader
pkt4sjjsbxx4ly1lwetieuj2n   ubuntu-manager1  Ready   Active        Reachable
```

请注意，新的管理节点的管理状态设置为可达（或留空），而旧的管理节点是领导者。其原因是始终有一个主节点负责所有 Swarm 管理和编排决策。领导者是使用 Raft 共识算法从管理节点中选举出来的，当它宕机时，会选举出一个新的领导者。

Raft 是一种共识算法，用于在分布式系统中做出决策。您可以在[`raft.github.io/`](https://raft.github.io/)上阅读有关其工作原理的更多信息（并查看可视化）。用于相同目的的非常流行的替代算法称为 Paxos。

假设我们关闭了`ubuntu-manager`机器；让我们看看新领导者是如何选举的：

```
$ docker node ls
ID                          HOSTNAME         STATUS  AVAILABILITY  MANAGER STATUS
4mrrmibdrpa3yethhmy13mwzq   ubuntu-manager2  Ready   Active        Reachable
kzgm7erw73tu2rjjninxdb4wp   ubuntu-manager   Ready   Active        Unreachable 
pkt4sjjsbxx4ly1lwetieuj2n * ubuntu-manager1  Ready   Active        Leader
```

请注意，即使其中一个管理节点宕机，Swarm 也可以正常工作。

管理节点的数量没有限制，因此听起来管理节点越多，容错能力就越好。这是真的，然而，拥有大量管理节点会影响性能，因为所有与 Swarm 状态相关的决策（例如，添加新节点或领导者选举）都必须使用 Raft 算法在所有管理节点之间达成一致意见。因此，管理节点的数量始终是容错能力和性能之间的权衡。

Raft 算法本身对管理者的数量有限制。分布式决策必须得到大多数节点的批准，称为法定人数。这一事实意味着建议使用奇数个管理者。

要理解为什么，让我们看看如果我们有两个管理者会发生什么。在这种情况下，法定人数是两个，因此如果任何一个管理者宕机，那么就不可能达到法定人数，因此也无法选举领导者。结果，失去一台机器会使整个集群失效。我们增加了一个管理者，但整个集群变得不太容错。在三个管理者的情况下情况会有所不同。然后，法定人数仍然是两个，因此失去一个管理者不会停止整个集群。这是一个事实，即使从技术上讲并不是被禁止的，但只有奇数个管理者是有意义的。

集群中的管理者越多，就涉及到越多与 Raft 相关的操作。然后，“管理者”节点应该被放入排水可用性，以节省它们的资源。

# 调度策略

到目前为止，我们已经了解到管理者会自动将工作节点分配给任务。在本节中，我们将深入探讨自动分配的含义。我们介绍 Docker Swarm 调度策略以及根据我们的需求进行配置的方法。

Docker Swarm 使用两个标准来选择合适的工作节点：

+   **资源可用性**：调度器知道节点上可用的资源。它使用所谓的**扩展策略**，试图将任务安排在负载最轻的节点上，前提是它符合标签和约束指定的条件。

+   **标签和约束**：

+   标签是节点的属性。有些标签是自动分配的，例如`node.id`或`node.hostname`；其他可以由集群管理员定义，例如`node.labels.segment`。

+   约束是服务创建者应用的限制，例如，仅选择具有特定标签的节点

标签分为两类，`node.labels`和`engine.labels`。第一类是由运营团队添加的；第二类是由 Docker Engine 收集的，例如操作系统或硬件特定信息。

例如，如果我们想在具体节点`ubuntu-worker1`上运行 Tomcat 服务，那么我们需要使用以下命令：

```
$ docker service create --constraint 'node.hostname == ubuntu-worker1' tomcat
```

我们还可以向节点添加自定义标签：

```
$ docker node update --label-add segment=AA ubuntu-worker1
```

上述命令添加了一个标签`node.labels.segment`，其值为`AA`。然后，在运行服务时我们可以使用它：

```
$ docker service create --constraint 'node.labels.segment == AA' tomcat
```

这个命令只在标记有给定段`AA`的节点上运行`tomcat`副本。

标签和约束使我们能够配置服务副本将在哪些节点上运行。尽管这种方法在许多情况下是有效的，但不应该过度使用，因为最好让副本分布在多个节点上，并让 Docker Swarm 负责正确的调度过程。

# Docker Compose 与 Docker Swarm

我们已经描述了如何使用 Docker Swarm 来部署一个服务，该服务又从给定的 Docker 镜像中运行多个容器。另一方面，还有 Docker Compose，它提供了一种定义容器之间依赖关系并实现容器扩展的方法，但所有操作都在一个 Docker 主机内完成。我们如何将这两种技术合并起来，以便我们可以指定`docker-compose.yml`文件，并自动将容器分布在集群上？幸运的是，有 Docker Stack。

# 介绍 Docker Stack

Docker Stack 是在 Swarm 集群上运行多个关联容器的方法。为了更好地理解它如何将 Docker Compose 与 Docker Swarm 连接起来，让我们看一下下面的图：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/86ad1636-d244-4a44-9c67-c64b8080eba1.png)

Docker Swarm 编排哪个容器在哪台物理机上运行。然而，容器之间没有任何依赖关系，因此为了它们进行通信，我们需要手动链接它们。相反，Docker Compose 提供了容器之间的链接。在前面图中的例子中，一个 Docker 镜像（部署为三个复制的容器）依赖于另一个 Docker 镜像（部署为一个容器）。然而，所有容器都运行在同一个 Docker 主机上，因此水平扩展受限于一台机器的资源。Docker Stack 连接了这两种技术，并允许使用`docker-compose.yml`文件在一组 Docker 主机上运行链接容器的完整环境。

# 使用 Docker Stack

举个例子，让我们使用依赖于`redis`镜像的`calculator`镜像。让我们将这个过程分为四个步骤：

1.  指定`docker-compose.yml`。

1.  运行 Docker Stack 命令。

1.  验证服务和容器。

1.  移除堆栈。

# 指定 docker-compose.yml

我们已经在前面的章节中定义了`docker-compose.yml`文件，它看起来类似于以下内容：

```
version: "3"
services:
    calculator:
        deploy:
            replicas: 3
        image: leszko/calculator:latest
        ports:
        - "8881:8080"
    redis:
        deploy:
            replicas: 1
        image: redis:latest
```

请注意，所有镜像在运行`docker stack`命令之前必须推送到注册表，以便它们可以从所有节点访问。因此，不可能在`docker-compose.yml`中构建镜像。

使用所提供的 docker-compose.yml 配置，我们将运行三个`calculator`容器和一个`redis`容器。计算器服务的端点将在端口`8881`上公开。

# 运行 docker stack 命令

让我们使用`docker stack`命令来运行服务，这将在集群上启动容器：

```
$ docker stack deploy --compose-file docker-compose.yml app
Creating network app_default
Creating service app_redis
Creating service app_calculator
```

Docker 计划简化语法，以便不需要`stack`这个词，例如，`docker deploy --compose-file docker-compose.yml app`。在撰写本文时，这仅在实验版本中可用。

# 验证服务和容器

服务已经启动。我们可以使用`docker service ls`命令来检查它们是否正在运行：

```
$ docker service ls
ID            NAME            MODE        REPLICAS  IMAGE
5jbdzt9wolor  app_calculator  replicated  3/3       leszko/calculator:latest
zrr4pkh3n13f  app_redis       replicated  1/1       redis:latest
```

我们甚至可以更仔细地查看服务，并检查它们部署在哪些 Docker 主机上：

```
$ docker service ps app_calculator
ID            NAME              IMAGE                     NODE  DESIRED STATE  CURRENT STATE 
jx0ipdxwdilm  app_calculator.1  leszko/calculator:latest  ubuntu-manager  Running    Running 57 seconds ago 
psweuemtb2wf  app_calculator.2  leszko/calculator:latest  ubuntu-worker1  Running    Running about a minute ago 
iuas0dmi7abn  app_calculator.3  leszko/calculator:latest  ubuntu-worker2  Running    Running 57 seconds ago 

$ docker service ps app_redis
ID            NAME         IMAGE         NODE            DESIRED STATE  CURRENT STATE 
8sg1ybbggx3l  app_redis.1  redis:latest  ubuntu-manager  Running  Running about a minute ago    
```

我们可以看到，`ubuntu-manager`机器上启动了一个`calculator`容器和一个`redis`容器。另外两个`calculator`容器分别在`ubuntu-worker1`和`ubuntu-worker2`机器上运行。

请注意，我们明确指定了`calculator` web 服务应该发布的端口号。因此，我们可以通过管理者的 IP 地址`http://192.168.0.143:8881/sum?a=1&b=2`来访问端点。操作返回`3`作为结果，并将其缓存在 Redis 容器中。

# 移除 stack

当我们完成了 stack，我们可以使用方便的`docker stack rm`命令来删除所有内容：

```
$ docker stack rm app
Removing service app_calculator
Removing service app_redis
Removing network app_default
```

使用 Docker Stack 允许在 Docker Swarm 集群上运行 Docker Compose 规范。请注意，我们使用了确切的`docker-compose.yml`格式，这是一个很大的好处，因为对于 Swarm，不需要指定任何额外的内容。

这两种技术的合并使我们能够在 Docker 上部署应用程序的真正力量，因为我们不需要考虑单独的机器。我们只需要指定我们的（微）服务如何相互依赖，用 docker-compose.yml 格式表达出来，然后让 Docker 来处理其他一切。物理机器可以简单地被视为一组资源。

# 替代集群管理系统

Docker Swarm 不是唯一用于集群 Docker 容器的系统。尽管它是开箱即用的系统，但可能有一些有效的理由安装第三方集群管理器。让我们来看一下最受欢迎的替代方案。

# Kubernetes

Kubernetes 是一个由谷歌最初设计的开源集群管理系统。尽管它不是 Docker 原生的，但集成非常顺畅，而且有许多额外的工具可以帮助这个过程；例如，**kompose** 可以将 `docker-compose.yml` 文件转换成 Kubernetes 配置文件。

让我们来看一下 Kubernetes 的简化架构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/6ae7e3ed-c6d5-4034-bbb2-e34bae100556.png)

Kubernetes 和 Docker Swarm 类似，它也有主节点和工作节点。此外，它引入了 **pod** 的概念，表示一组一起部署和调度的容器。大多数 pod 都有几个容器组成一个服务。Pod 根据不断变化的需求动态构建和移除。

Kubernetes 相对较年轻。它的开发始于 2014 年；然而，它基于谷歌的经验，这是它成为市场上最受欢迎的集群管理系统之一的原因之一。越来越多的组织迁移到 Kubernetes，如 eBay、Wikipedia 和 Pearson。

# Apache Mesos

Apache Mesos 是一个在 2009 年由加州大学伯克利分校发起的开源调度和集群系统，早在 Docker 出现之前就开始了。它提供了一个在 CPU、磁盘空间和内存上的抽象层。Mesos 的一个巨大优势是它支持任何 Linux 应用程序，不一定是（Docker）容器。这就是为什么可以创建一个由数千台机器组成的集群，并且用于 Docker 容器和其他程序，例如基于 Hadoop 的计算。

让我们来看一下展示 Mesos 架构的图：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/8debdc02-d7c6-4f97-948f-e6f51db3e6ef.png)

Apache Mesos，类似于其他集群系统，具有主从架构。它使用安装在每个节点上的节点代理进行通信，并提供两种类型的调度器，Chronos - 用于 cron 风格的重复任务和 Marathon - 提供 REST API 来编排服务和容器。

与其他集群系统相比，Apache Mesos 非常成熟，并且已经被许多组织采用，如 Twitter、Uber 和 CERN。

# 比较功能

Kubernetes、Docker Swarm 和 Mesos 都是集群管理系统的不错选择。它们都是免费且开源的，并且它们都提供重要的集群管理功能，如负载均衡、服务发现、分布式存储、故障恢复、监控、秘钥管理和滚动更新。它们在持续交付过程中也可以使用，没有太大的区别。这是因为，在 Docker 化的基础设施中，它们都解决了同样的问题，即 Docker 容器的集群化。然而，显然，这些系统并不完全相同。让我们看一下表格，展示它们之间的区别：

|  | **Docker Swarm** | **Kubernetes** | **Apache Mesos** |
| --- | --- | --- | --- |
| **Docker 支持** | 本机支持 | 支持 Docker 作为 Pod 中的容器类型之一 | Mesos 代理（从属）可以配置为托管 Docker 容器 |
| **应用程序类型** | Docker 镜像 | 容器化应用程序（Docker、rkt 和 hyper） | 任何可以在 Linux 上运行的应用程序（也包括容器） |
| **应用程序定义** | Docker Compose 配置 | Pod 配置，副本集，复制控制器，服务和部署 | 以树形结构形成的应用程序组 |
| 设置过程 | 非常简单 | 根据基础设施的不同，可能需要运行一个命令或者进行许多复杂的操作 | 相当复杂，需要配置 Mesos、Marathon、Chronos、Zookeeper 和 Docker 支持 |
| **API** | Docker REST API | REST API | Chronos/Marathon REST API |
| **用户界面** | Docker 控制台客户端，Shipyard 等第三方 Web 应用 | 控制台工具，本机 Web UI（Kubernetes 仪表板） | Mesos、Marathon 和 Chronos 的官方 Web 界面 |
| **云集成** | 需要手动安装 | 大多数提供商（Azure、AWS、Google Cloud 等）提供云原生支持 | 大多数云提供商提供支持 |
| **最大集群大小** | 1,000 个节点 | 1,000 个节点 | 50,000 个节点 |
| **自动扩展** | 不可用 | 根据观察到的 CPU 使用情况提供水平 Pod 自动扩展 | Marathon 根据资源（CPU/内存）消耗、每秒请求的数量和队列长度提供自动扩展 |

显然，除了 Docker Swarm、Kubernetes 和 Apache Mesos 之外，市场上还有其他可用的集群系统。然而，它们并不那么受欢迎，它们的使用量随着时间的推移而减少。

无论选择哪个系统，您都可以将其用于暂存/生产环境，也可以用于扩展 Jenkins 代理。让我们看看如何做到这一点。

# 扩展 Jenkins

服务器集群的明显用例是暂存和生产环境。在使用时，只需连接物理机即可增加环境的容量。然而，在持续交付的背景下，我们可能还希望通过在集群上运行 Jenkins 代理（从属）节点来改进 Jenkins 基础设施。在本节中，我们将看两种不同的方法来实现这个目标。

# 动态从属配置

我们在《配置 Jenkins》的第三章中看到了动态从属配置。使用 Docker Swarm，这个想法保持完全一样。当构建开始时，Jenkins 主服务器会从 Jenkins 从属 Docker 镜像中运行一个容器，并在容器内执行 Jenkinsfile 脚本。然而，Docker Swarm 使解决方案更加强大，因为我们不再局限于单个 Docker 主机，而是可以提供真正的水平扩展。向集群添加新的 Docker 主机有效地扩展了 Jenkins 基础设施的容量。

在撰写本文时，Jenkins Docker 插件不支持 Docker Swarm。其中一个解决方案是使用 Kubernetes 或 Mesos 作为集群管理系统。它们每个都有一个专用的 Jenkins 插件：Kubernetes 插件（[`wiki.jenkins.io/display/JENKINS/Kubernetes+Plugin`](https://wiki.jenkins.io/display/JENKINS/Kubernetes+Plugin)）和 Mesos 插件（[`wiki.jenkins.io/display/JENKINS/Mesos+Plugin`](https://wiki.jenkins.io/display/JENKINS/Mesos+Plugin)）。

无论从属是如何配置的，我们总是通过安装适当的插件并在 Manage Jenkins | Configure System 的 Cloud 部分中添加条目来配置它们。

# Jenkins Swarm

如果我们不想使用动态从属配置，那么集群化 Jenkins 从属的另一个解决方案是使用 Jenkins Swarm。我们在《配置 Jenkins》的第三章中描述了如何使用它。在这里，我们为 Docker Swarm 添加描述。

首先，让我们看看如何使用从 swarm-client.jar 工具构建的 Docker 镜像来运行 Jenkins Swarm 从属。Docker Hub 上有一些可用的镜像；我们可以使用 csanchez/jenkins-swarm-slave 镜像：

```
$ docker run csanchez/jenkins-swarm-slave:1.16 -master -username -password -name jenkins-swarm-slave-2
```

该命令执行应该与第三章中介绍的具有完全相同的效果，*配置 Jenkins*；它动态地向 Jenkins 主节点添加一个从节点。

然后，为了充分利用 Jenkins Swarm，我们可以在 Docker Swarm 集群上运行从节点容器：

```
$ docker service create --replicas 5 --name jenkins-swarm-slave csanchez/jenkins-swarm-slave -master -disableSslVerification -username -password -name jenkins-swarm-slave
```

上述命令在集群上启动了五个从节点，并将它们附加到了 Jenkins 主节点。请注意，通过执行 docker service scale 命令，可以非常简单地通过水平扩展 Jenkins。

# 动态从节点配置和 Jenkins Swarm 的比较

动态从节点配置和 Jenkins Swarm 都可以在集群上运行，从而产生以下图表中呈现的架构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/165c3a7a-c681-4d65-bb26-93517bf1e7e2.png)

Jenkins 从节点在集群上运行，因此非常容易进行水平扩展和缩减。如果我们需要更多的 Jenkins 资源，我们就扩展 Jenkins 从节点。如果我们需要更多的集群资源，我们就向集群添加更多的物理机器。

这两种解决方案之间的区别在于，动态从节点配置会在每次构建之前自动向集群添加一个 Jenkins 从节点。这种方法的好处是，我们甚至不需要考虑此刻应该运行多少 Jenkins 从节点，因为数量会自动适应流水线构建的数量。这就是为什么在大多数情况下，动态从节点配置是首选。然而，Jenkins Swarm 也具有一些显著的优点：

+   **控制从节点数量**：使用 Jenkins Swarm，我们明确决定此刻应该运行多少 Jenkins 从节点。

+   **有状态的从节点**：许多构建共享相同的 Jenkins 从节点，这可能听起来像一个缺点；然而，当一个构建需要从互联网下载大量依赖库时，这就成为了一个优势。在动态从节点配置的情况下，为了缓存这些依赖，我们需要设置一个共享卷。

+   **控制从节点运行的位置**：使用 Jenkins Swarm，我们可以决定不在集群上运行从节点，而是动态选择主机；例如，对于许多初创公司来说，当集群基础设施成本高昂时，从节点可以动态地在开始构建的开发人员的笔记本电脑上运行。

集群化 Jenkins 从属节点带来了许多好处，这就是现代 Jenkins 架构应该看起来的样子。这样，我们可以为持续交付过程提供动态的水平扩展基础设施。

# 练习

在本章中，我们详细介绍了 Docker Swarm 和集群化过程。为了增强这方面的知识，我们建议进行以下练习：

1.  建立一个由三个节点组成的 Swarm 集群：

+   +   使用一台机器作为管理节点，另外两台机器作为工作节点

+   您可以使用连接到一个网络的物理机器，来自云提供商的机器，或者具有共享网络的 VirtualBox 机器

+   使用 `docker node` 命令检查集群是否正确配置

1.  在集群上运行/扩展一个 hello world 服务：

+   +   服务可以与第二章中描述的完全相同

+   发布端口，以便可以从集群外部访问

+   将服务扩展到五个副本

+   向“hello world”服务发出请求，并检查哪个容器正在提供请求

1.  使用在 Swarm 集群上部署的从属节点来扩展 Jenkins：

+   +   使用 Jenkins Swarm 或动态从属节点供应

+   运行管道构建并检查它是否在其中一个集群化的从属节点上执行

# 总结

在本章中，我们看了一下 Docker 环境的集群化方法，这些方法可以实现完整的分段/生产/Jenkins 环境的设置。以下是本章的要点：

+   聚类是一种配置一组机器的方法，从许多方面来看，它可以被视为一个单一的系统

+   Docker Swarm 是 Docker 的本地集群系统

+   可以使用内置的 Docker 命令动态配置 Docker Swarm 集群

+   可以使用 docker service 命令在集群上运行和扩展 Docker 镜像

+   Docker Stack 是在 Swarm 集群上运行 Docker Compose 配置的方法

+   支持 Docker 的最流行的集群系统是 Docker Swarm、Kubernetes 和 Apache Mesos

+   Jenkins 代理可以使用动态从属节点供应或 Jenkins Swarm 插件在集群上运行

在下一章中，我们将描述持续交付过程的更高级方面，并介绍构建流水线的最佳实践
