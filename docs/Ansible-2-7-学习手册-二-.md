# Ansible 2.7 学习手册（二）

> 原文：[`zh.annas-archive.org/md5/89BF78DDE1DEE382F084F8254DF8B8DD`](https://zh.annas-archive.org/md5/89BF78DDE1DEE382F084F8254DF8B8DD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：处理复杂部署

到目前为止，我们已经学习了如何编写基本的 Ansible playbook，与 playbook 相关的选项，使用 Vagrant 开发 playbook 的实践，以及如何在流程结束时测试 playbook。现在我们为你和你的团队提供了一个学习和开始开发 Ansible playbook 的框架。把这看作是从驾校教练那里学开车的类似过程。你首先学习如何通过方向盘控制汽车，然后你慢慢开始控制刹车，最后，你开始操纵换挡器，因此控制你的汽车速度。一段时间后，随着在不同类型的道路（如平坦、多山、泥泞、坑洼等）上进行越来越多的练习，并驾驶不同的汽车，你会获得专业知识、流畅性、速度，基本上，你会享受整个驾驶过程。从本章开始，我们将深入探讨 Ansible，并敦促你练习并尝试更多的示例以熟悉它。

你一定想知道为什么这一章被命名为这样。原因是，到目前为止，我们还没有达到一个能够在生产环境中部署 playbook 的阶段，特别是在复杂情况下。复杂情况包括您需要与数百或数千台机器进行交互的情况，每组机器都依赖于另一组或几组机器。这些组可能彼此依赖于所有或部分交易，以执行与主从服务器的安全复杂数据备份和复制有关的操作。此外，还有几个有趣而相当引人入胜的 Ansible 功能我们还没有探讨过。在本章中，我们将通过示例介绍所有这些功能。我们的目标是，到本章结束时，您应该清楚如何编写可以从配置管理角度部署到生产中的 playbook。接下来的章节将进一步丰富我们所学内容，以增强使用 Ansible 的体验。

本章将涵盖以下主题：

+   与`local_action`功能以及其他任务委派和条件策略一起工作

+   使用`include`、处理程序和角色

+   转换你的 playbook

+   Jinja 过滤器

+   安全管理提示和工具

# 技术要求

您可以从本书的 GitHub 存储库下载所有文件，网址为[`github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter04`](https://github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter04)。

# 使用`local_action`功能

Ansible 的`local_action`功能是一个强大的功能，特别是当我们考虑**编排**时。该功能允许您在运行 Ansible 的机器上本地运行某些任务。

考虑以下情况：

+   生成新的机器或创建 JIRA 工单

+   管理您的命令中心，包括安装软件包和设置配置

+   调用负载均衡器 API 以禁用负载均衡器中某个 Web 服务器条目

这些通常是可以在运行 `ansible-playbook` 命令的同一台机器上运行的任务，而不是登录到远程框并运行这些命令。

让我们举个例子。假设你想在本地系统上运行一个 shell 模块，你正在那里运行你的 Ansible playbook。在这种情况下，`local_action` 选项就会发挥作用。如果你将模块名称和模块参数传递给 `local_action`，它将在本地运行该模块。

让我们看看这个选项如何与 `shell` 模块一起工作。考虑下面的代码，显示了 `local_action` 选项的输出：

```
--- 
- hosts: database 
  remote_user: vagrant
  tasks: 
    - name: Count processes running on the remote system 
      shell: ps | wc -l 
      register: remote_processes_number 
    - name: Print remote running processes 
      debug: 
        msg: '{{ remote_processes_number.stdout }}' 
    - name: Count processes running on the local system 
      local_action: shell ps | wc -l 
      register: local_processes_number 
    - name: Print local running processes 
      debug: 
        msg: '{{ local_processes_number.stdout }}' 
```

现在我们可以将其保存为 `local_action.yaml` 并使用以下命令运行它：

```
ansible-playbook -i hosts local_action.yaml
```

我们会收到以下结果：

```
PLAY [database] ****************************************************
TASK [Gathering Facts] *********************************************
ok: [db01.fale.io]
TASK [Count processes running on the remote system] ****************
changed: [db01.fale.io]
TASK [Print remote running processes] ******************************
ok: [db01.fale.io] => {
 "msg": "6"
}
TASK [Count processes running on the local system] *****************
changed: [db01.fale.io -> localhost]
TASK [Print local running processes] *******************************
ok: [db01.fale.io] => {
 "msg": "9"
}
PLAY RECAP *********************************************************
db01.fale.io                : ok=5 changed=2 unreachable=0 failed=0 
```

正如你所看到的，这两个命令提供给我们不同的数字，因为它们在不同的主机上执行。你可以用 `local_action` 运行任何模块，Ansible 将确保该模块在运行 `ansible-playbook` 命令的主机上本地运行。另一个你可以（也应该！）尝试的简单例子是运行两个任务：

+   在远程机器（上述情况中的 `db01`）上执行 `uname`

+   在启用 `local_action` 的情况下在本地机器上执行 `uname`

这将进一步阐明 `local_action` 的概念。

Ansible 提供了另一种方法，可以将某些操作委托给特定（或不同的）机器：`delegate_to` 系统。

# 委托任务

有时，你会想在不同的系统上执行某个操作。例如，在你部署应用程序服务器节点时，可能会是数据库节点，也可能是本地主机。为此，你可以简单地将 `delegate_to: HOST` 属性添加到你的任务中，它将在适当的节点上运行。让我们重新设计上一个例子以实现这一点：

```
--- 
- hosts: database 
  remote_user: vagrant
  tasks: 
    - name: Count processes running on the remote system 
      shell: ps | wc -l 
      register: remote_processes_number 
    - name: Print remote running processes 
      debug: 
        msg: '{{ remote_processes_number.stdout }}' 
    - name: Count processes running on the local system 
      shell: ps | wc -l 
      delegate_to: localhost 
      register: local_processes_number 
    - name: Print local running processes 
      debug: 
        msg: '{{ local_processes_number.stdout }}' 
```

将其保存为 `delegate_to.yaml`，我们可以使用以下命令运行它：

```
ansible-playbook -i hosts delegate_to.yaml
```

我们会收到与前一个示例相同的输出：

```
PLAY [database] **************************************************

TASK [Gathering Facts] *******************************************
ok: [db01.fale.io]
TASK [Count processes running on the remote system] **************
changed: [db01.fale.io]
TASK [Print remote running processes] ****************************
ok: [db01.fale.io] => {
 "msg": "6"
}
TASK [Count processes running on the local system] ***************
changed: [db01.fale.io -> localhost]

TASK [Print local running processes] *****************************
ok: [db01.fale.io] => {
 "msg": "9"
}
PLAY RECAP *******************************************************
db01.fale.io              : ok=5 changed=2 unreachable=0 failed=0 
```

在这个例子中，我们看到了如何在同一个 playbook 中对远程主机和本地主机执行操作。在复杂的流程中，这变得很方便，其中一些步骤需要由本地机器或你可以连接到的任何其他机器执行。

# 使用条件

到目前为止，我们只看到了 playbook 的工作原理以及任务是如何执行的。我们也看到了 Ansible 顺序执行所有这些任务。然而，这不会帮助你编写一个包含数十个任务并且只需要执行其中一部分任务的高级 playbook。例如，假设你有一个 playbook，它会在远程主机上安装 Apache HTTPd 服务器。现在，Debian-based 操作系统对 Apache HTTPd 服务器有一个不同的包名称，叫做 `apache2`；对于基于 Red Hat 的操作系统，它叫做 `httpd`。

在 playbook 中有两个任务，一个用于 `httpd` 包（适用于基于 Red Hat 的系统），另一个用于 `apache2` 包（适用于基于 Debian 的系统），这样 Ansible 就会安装这两个包，但是执行会失败，因为如果你在基于 Red Hat 的操作系统上安装，`apache2` 将不可用。为了克服这样的问题，Ansible 提供了条件语句，帮助仅在满足指定条件时运行任务。在这种情况下，我们执行类似以下伪代码的操作：

```
If os = "redhat" 
  Install httpd 
Else if os = "debian" 
  Install apache2 
End 
```

在基于 Red Hat 的操作系统上安装 `httpd` 时，我们首先检查远程系统是否运行了基于 Red Hat 的操作系统，如果是，则安装 `httpd` 包；否则，我们跳过该任务。让我们直接进入一个名为 `conditional_httpd.yaml` 的示例 playbook，其内容如下：

```
--- 
- hosts: webserver 
  remote_user: vagrant
  tasks: 
    - name: Print the ansible_os_family value 
      debug: 
        msg: '{{ ansible_os_family }}' 
    - name: Ensure the httpd package is updated 
      yum: 
        name: httpd 
        state: latest 
      become: True 
      when: ansible_os_family == 'RedHat' 
    - name: Ensure the apache2 package is updated 
      apt: 
        name: apache2 
        state: latest 
      become: True 
      when: ansible_os_family == 'Debian' 
```

使用以下方式运行它：

```
ansible-playbook -i hosts conditional_httpd.yaml
```

这是结果。完整的代码输出文件可以在 GitHub 上找到：

```
PLAY [webserver] ***********************************************

TASK [Gathering Facts] *****************************************
ok: [ws03.fale.io]
ok: [ws02.fale.io]
ok: [ws01.fale.io]

TASK [Print the ansible_os_family value] ***********************
ok: [ws01.fale.io] => {
 "msg": "RedHat"
}
ok: [ws02.fale.io] => {
 "msg": "RedHat"
}
ok: [ws03.fale.io] => {
 "msg": "Debian"
}
...
```

如你所见，我为此示例创建了一个名为 `ws03` 的新服务器，它是基于 Debian 的。如预期，在两个 CentOS 节点上执行了 `httpd` 包的安装，而在 Debian 节点上执行了 `apache2` 包的安装。

Ansible 只区分少数家族（在撰写本书时为 AIX、Alpine、Altlinux、Archlinux、Darwin、Debian、FreeBSD、Gentoo、HP-UX、Mandrake、Red Hat、Slackware、Solaris 和 Suse）；因此，CentOS 机器具有一个 `ansible_os_family` 值：`RedHat`。

同样，你也可以匹配不同的条件。Ansible 支持等于 (`==`)，不等于 (`!=`)，大于 (`>`)，小于 (`<`)，大于或等于 (`>=`) 和小于或等于 (`<=`)。

到目前为止，我们见过的运算符将匹配变量的整个内容，但如果你只想检查变量中是否存在特定字符或字符串怎么办？为了执行这些类型的检查，Ansible 提供了 `in` 和 `not` 运算符。你还可以使用 `and` 和 `or` 运算符匹配多个条件。`and` 运算符会确保在执行此任务之前所有条件都匹配，而 `or` 运算符会确保至少有一个条件匹配。

# 布尔条件

除了字符串匹配外，你还可以检查一个变量是否为 `True`。当你想要检查一个变量是否被赋值时，这种类型的验证将非常有用。你甚至可以根据变量的布尔值执行任务。

例如，让我们将以下代码放入名为 `crontab_backup.yaml` 的文件中：

```
--- 
- hosts: all 
  remote_user: vagrant
  vars: 
    backup: True 
  tasks: 
    - name: Copy the crontab in tmp if the backup variable is true 
      copy: 
        src: /etc/crontab 
        dest: /tmp/crontab 
        remote_src: True 
      when: backup 
```

我们可以使用以下方式执行它：

```
ansible-playbook -i hosts crontab_backup.yaml
```

然后我们得到以下结果：

```
PLAY [all] ***************************************************

TASK [Gathering Facts] ***************************************
ok: [ws03.fale.io]
ok: [ws01.fale.io]
ok: [db01.fale.io]
ok: [ws02.fale.io]

TASK [Copy the crontab in tmp if the backup variable is true]
changed: [ws03.fale.io]
changed: [ws02.fale.io]
changed: [ws01.fale.io]
changed: [db01.fale.io]

PLAY RECAP ***************************************************
db01.fale.io          : ok=2 changed=1 unreachable=0 failed=0 
ws01.fale.io          : ok=2 changed=1 unreachable=0 failed=0 
ws02.fale.io          : ok=2 changed=1 unreachable=0 failed=0 
ws03.fale.io          : ok=2 changed=1 unreachable=0 failed=0 
```

我们可以稍微改变命令为这样：

```
ansible-playbook -i hosts crontab_backup.yaml --extra-vars="backup=False"
```

然后我们将收到这个输出：

```
PLAY [all] ***************************************************

TASK [Gathering Facts] ***************************************
ok: [ws03.fale.io]
ok: [ws01.fale.io]
ok: [db01.fale.io]
ok: [ws02.fale.io]

TASK [Copy the crontab in tmp if the backup variable is true]
skipping: [ws01.fale.io]
skipping: [ws02.fale.io]
skipping: [ws03.fale.io]
skipping: [db01.fale.io]

PLAY RECAP ***************************************************
db01.fale.io          : ok=1 changed=0 unreachable=0 failed=0 
ws01.fale.io          : ok=1 changed=0 unreachable=0 failed=0 
ws02.fale.io          : ok=1 changed=0 unreachable=0 failed=0 
ws03.fale.io          : ok=1 changed=0 unreachable=0 failed=0 
```

正如你所看到的，在第一种情况下，操作被执行了，而在第二种情况下，它被跳过了。我们可以通过配置文件、`host` 变量或 `group` 变量覆盖备份值。

如果以这种方式检查并且变量未设置，Ansible 将假定其为 `False`。

# 检查变量是否设置

有时候，你会发现自己不得不在命令中使用一个变量。每次这样做时，你都必须确保变量是*设置*的。这是因为一些命令如果用一个*未设置*的变量调用可能会造成灾难性后果（也就是说，如果你执行 `rm -rf $VAR/*` 而 `$VAR` 没有设置或为空，它会清空你的机器）。为了做到这一点，Ansible 提供了一种检查变量是否定义的方式。

我们可以按以下方式改进前面的示例：

```
--- 
- hosts: all 
  remote_user: ansible 
  vars: 
    backup: True 
  tasks: 
    - name: Check if the backup_folder is set 
      fail: 
        msg: 'The backup_folder needs to be set' 
      when: backup_folder is not defined or backup_folder == “” 
    - name: Copy the crontab in tmp if the backup variable is true 
      copy: 
        src: /etc/crontab 
        dest: '{{ backup_folder }}/crontab' 
        remote_src: True 
      when: backup 
```

如您所见，我们使用了 fail 模块，它允许我们在 `backup_folder` 变量未设置时将 Ansible playbook 放入失败状态。

# 使用 include 进行操作

include 功能帮助您减少编写任务时的重复性。这也允许我们通过将可重用代码包含在单独的任务中来拥有更小的 playbooks，使用**不要重复自己**（**DRY**）原则。

要触发包含另一个文件的过程，您需要将以下内容放在 tasks 对象下方：

```
 - include: FILENAME.yaml 
```

您还可以将一些变量传递给被包含的文件。为此，我们可以按以下方式指定它们：

```
- include: FILENAME.yaml variable1="value1" variable2="value2"
```

使用 include 语句保持您的变量清洁和简洁，并遵循 DRY 原则，这将使您能够编写更易于维护和遵循的 Ansible 代码。

# 处理程序

在许多情况下，您将有一个任务或一组任务，这些任务会更改远程机器上的某些资源，需要触发一个事件才能生效。例如，当您更改服务配置时，您需要重新启动或重新加载服务本身。在 Ansible 中，您可以使用 `notify` 动作触发此事件。

每个处理程序任务将在通知时在 playbooks 结束时运行。例如，您多次更改了 HTTPd 服务器配置，并且希望重新启动 HTTPd 服务以应用更改。现在，每次更改配置时重新启动 HTTPd 并不是一个好的做法；即使没有对其配置进行任何更改，重新启动服务器也不是一个好的做法。为了处理这种情况，您可以通知 Ansible 在每次配置更改时重新启动 HTTPd 服务，但是 Ansible 会确保，无论您多少次通知它重新启动 HTTPd，它都将在所有其他任务完成后仅调用该任务一次。让我们按照以下方式稍微更改我们在前几章中创建的 `webserver.yaml` 文件；完整代码可在 GitHub 上找到：

```
--- 
- hosts: webserver 
  remote_user: vagrant
  tasks: 
    - name: Ensure the HTTPd package is installed 
      yum: 
        name: httpd 
        state: present 
      become: True 
    - name: Ensure the HTTPd service is enabled and running 
      service: 
        name: httpd 
        state: started 
        enabled: True 
      become: True 
    - name: Ensure HTTP can pass the firewall 
      firewalld: 
 service: http 
        state: enabled 
        permanent: True 
        immediate: True 
      become: True 
   ...
```

使用以下方式运行此脚本：

```
ansible-playbook -i hosts webserver.yaml
```

我们将得到以下输出。完整的代码输出文件可在 GitHub 上找到：

```
PLAY [webserver] *********************************************

TASK [Gathering Facts] ***************************************
ok: [ws01.fale.io]
ok: [ws02.fale.io]

TASK [Ensure the HTTPd package is installed] *****************
ok: [ws01.fale.io]
ok: [ws02.fale.io]

TASK [Ensure the HTTPd service is enabled and running] *******
changed: [ws02.fale.io]
changed: [ws01.fale.io]

...
```

在这种情况下，处理程序是从配置文件更改中触发的。但是如果我们再运行一次，配置将不会改变，因此，我们将得到以下结果：

```
PLAY [webserver] *********************************************

TASK [Gathering Facts] ***************************************
ok: [ws01.fale.io]
ok: [ws02.fale.io]

TASK [Ensure the HTTPd package is installed] *****************
ok: [ws01.fale.io]
ok: [ws02.fale.io]

TASK [Ensure the HTTPd service is enabled and running] *******
ok: [ws02.fale.io]
ok: [ws01.fale.io]

TASK [Ensure HTTP can pass the firewall] *********************
ok: [ws02.fale.io]
ok: [ws01.fale.io]

TASK [Ensure HTTPd configuration is updated] *****************
ok: [ws02.fale.io]
ok: [ws01.fale.io]

PLAY RECAP ***************************************************
ws01.fale.io          : ok=5 changed=0 unreachable=0 failed=0 
ws02.fale.io          : ok=5 changed=0 unreachable=0 failed=0
```

如你所见，这次没有执行任何处理程序，因为所有可能触发它们执行的步骤都没有改变，所以不需要处理程序。记住这个行为，以确保你不会对未执行的处理程序感到惊讶。

# 处理角色

我们已经看到了如何自动化简单的任务，但我们到目前为止看到的内容不会解决你所有的问题。这是因为 playbook 很擅长执行操作，但不太擅长配置大量的机器，因为它们很快就会变得混乱。为了解决这个问题，Ansible 有**角色**。

我对角色的定义是一组用于实现特定目标的 playbook、模板、文件或变量。例如，我们可以有一个数据库角色和一个 Web 服务器角色，以便这些配置保持清晰分离。

在开始查看角色内部之前，让我们谈谈组织项目的问题。

# 组织项目

在过去的几年里，我为多个组织的多个 Ansible 仓库工作过，其中许多非常混乱。为了确保您的存储库易于管理，我将给您一个我始终使用的模板。

首先，我总是在 `root` 文件夹中创建三个文件：

+   `ansible.cfg`：一个小配置文件，用于告诉 Ansible 在我们的文件夹结构中查找文件的位置。

+   `hosts`：我们已经在前几章中看到的主机文件。

+   `master.yaml`：一个将整个基础架构对齐的 playbook。

除了这三个文件外，我还创建了两个文件夹：

+   `playbooks`：这将包含 playbook 和一个名为 `groups` 的文件夹，用于组管理。

+   `roles`：这将包含我们需要的所有角色。

为了澄清这一点，让我们使用 Linux 的 `tree` 命令来查看一个需要 Web 服务器和数据库服务器的简单 Web 应用程序的 Ansible 仓库的结构：

```
    ├── ansible.cfg
    ├── hosts
    ├── master.yaml
    ├── playbooks
    │   ├── firstrun.yaml
    │   └── groups
    │       ├── database.yaml
    │       └── webserver.yaml
    └── roles
        ├── common
        ├── database
        └── webserver

```

如你所见，我也添加了一个 `common` 角色。这对于将所有应该为每台服务器执行的事情放在一起非常有用。通常，我在这个角色中配置 NTP、`motd` 和其他类似的服务，以及机器主机名。

现在我们将看看如何结构化一个角色。

# 角色的解剖

角色中的文件夹结构是标准的，你不能改变它太多。

角色中最重要的文件夹是 `tasks` 文件夹，因为这是其中唯一必需的文件夹。它必须包含一个 `main.yaml` 文件，这将是要执行的任务列表。在角色中经常存在的其他文件夹是模板和文件。第一个将用于存储 **模板任务** 使用的模板，而第二个将用于存储 **复制任务** 使用的文件。

# 将你的 playbook 转换成一个完整的 Ansible 项目

让我们看看如何将我们用来设置我们的 Web 基础架构的三个 playbooks（`common_tasks.yaml`、`firstrun.yaml`和`webserver.yaml`）转换为适合这个文件组织的文件。我们必须记住，我们在这些角色中还使用了两个文件（`index.html.j2`和`motd`），所以我们也必须适当地放置这些文件。

首先，我们将创建我们在前一段中看到的文件夹结构。

最容易转换的 playbook 是`firstrun.yaml`，因为我们只需要将它复制到`playbooks`文件夹中。这个 playbook 将保持为一个 playbook，因为它是一组操作，每台服务器只需运行一次。

现在，我们转到`common_tasks.yaml` playbook，它需要一点重新调整以匹配角色范例。

# 将一个 playbook 转换为一个角色

我们需要做的第一件事是创建`roles/common/tasks`和`roles/common/templates`文件夹。在第一个文件夹中，我们将添加以下`main.yaml`文件。完整的代码在 GitHub 上可用：

```
---
- name: Ensure EPEL is enabled 
  yum: 
    name: epel-release 
    state: present 
  become: True 
- name: Ensure libselinux-python is present 
  yum: 
    name: libselinux-python 
    state: present 
  become: True 
- name: Ensure libsemanage-python is present 
  yum: 
    name: libsemanage-python 
    state: present 
  become: True 
...
```

正如你所看到的，这与我们的`common_tasks.yaml` playbooks 非常相似。事实上，只有两个区别：

+   `hosts`、`remote_user`和`tasks`行（第 2、3 和 4 行）已被删除。

+   文件的其余部分的缩进已经相应地修正了。

在这个角色中，我们使用了模板任务在服务器上创建了一个名为`motd`的文件，其中包含了机器的 IP 和其他有趣的信息。因此，我们需要创建`roles/common/templates`并把`motd`模板放在里面。

在这一点上，我们的常规任务将具有这种结构：

```
common/ 
├── tasks 
│   └── main.yaml 
└── templates 
    └── motd 
```

现在，我们需要指示 Ansible 在哪些机器上执行`common`角色中指定的所有任务。为此，我们应该查看 playbooks/groups 目录。在这个目录中，为每组逻辑上相似的机器（即执行相同类型操作的机器）准备一个文件非常方便，就像数据库和 Web 服务器一样。

因此，让我们在`playbooks/groups`中创建一个名为`database.yaml`的文件，内容如下：

```
--- 
- hosts: database 
  user: vagrant 
  roles: 
  - common 
```

在相同文件夹中创建一个名为`webserver.yaml`的文件，内容如下：

```
--- 
- hosts: webserver 
  user: vagrant 
  roles: 
  - common 
```

如你所见，这些文件指定了我们要操作的主机组、要在这些主机上使用的远程用户以及我们要执行的角色。

# 辅助文件

当我们在前一章中创建`hosts`文件时，我们注意到它有助于简化我们的命令行。因此，让我们开始将我们之前在`root`文件夹中使用的 hosts 文件复制到我们 Ansible 存储库的根目录中。到目前为止，我们总是在命令行上指定这个文件的路径。如果我们创建一个告诉 Ansible 我们的`hosts`文件位置的`ansible.cfg`文件，这将不再需要。因此，让我们在我们 Ansible 存储库的根目录中创建一个名为`ansible.cfg`的文件，并添加以下内容：

```
[defaults] 
inventory = hosts 
host_key_checking = False 
roles_path = roles 
```

在这个文件中，除了我们已经谈论过的`inventory`之外，我们还指定了另外两个变量，它们是`host_key_checking`和`roles_path`。

`host_key_checking`标志对于不要求验证远程系统 SSH 密钥非常有用。尽管在生产中不建议使用这种方式，因为建议在这种环境中使用公钥传播系统，但在测试环境中非常方便，因为它将帮助您减少 Ansible 等待用户输入的时间。

`roles_path`用于告诉 Ansible 在哪里找到我们 playbooks 的角色。

我通常会添加一个额外的文件，即`master.yaml`。我发现这非常有用，因为你经常需要保持基础架构与你的 Ansible 代码保持一致。为了在单个命令中执行它，你需要一个能运行 playbooks/groups 中所有文件的文件。因此，让我们在 Ansible 仓库的`root`文件夹中创建一个`master.yaml`文件，内容如下：

```
--- 
- import_playbook: playbooks/groups/database.yaml 
- import_playbook: playbooks/groups/webserver.yaml 
```

此时，我们可以执行以下操作：

```
ansible-playbook master.yaml 
```

结果将是以下内容。完整的代码输出文件可在 GitHub 上找到：

```
PLAY [database] ********************************************** 
TASK [Gathering Facts] ***************************************
ok: [db01.fale.io]

TASK [common : Ensure EPEL is enabled] ***********************
ok: [db01.fale.io]

TASK [common : Ensure libselinux-python is present] **********
ok: [db01.fale.io]

TASK [common : Ensure libsemanage-python is present] *********
ok: [db01.fale.io]

TASK [common : Ensure we have last version of every package] *
ok: [db01.fale.io]
...
```

如前面的输出所示，列在`common`角色中的操作首先在`database`组中的节点上执行，然后在`webserver`组中的节点上执行。

# 转换 web 服务器角色

正如我们将`common` playbook 转换为`common`角色一样，我们可以将`webserver`角色也转换为`webserver`角色。

在角色中，我们需要有带有`tasks`子文件夹的`webserver`文件夹。在这个文件夹中，我们必须放置包含从 playbooks 复制的`tasks`的`main.yaml`文件。以下是代码片段；完整的代码可以在 GitHub 上找到：

```
--- 
- name: Ensure the HTTPd package is installed 
  yum: 
    name: httpd 
    state: present 
  become: True 
- name: Ensure the HTTPd service is enabled and running 
  service: 
    name: httpd 
    state: started 
    enabled: True 
  become: True 
- name: Ensure HTTP can pass the firewall 
  firewalld: 
    service: http 
    state: enabled 
    permanent: True 
    immediate: True 
  become: True 
... 
```

在此角色中，我们使用了多个任务，这些任务需要额外的资源才能正常工作；更具体地说，我们需要执行以下操作：

+   将`website.conf`文件放在`roles/webserver/files`中。

+   将`index.html.j2`模板放在`roles/webserver/templates`中。

+   创建`Restart HTTPd`处理程序。

前两个应该很简单。实际上，第一个是一个空文件（因为默认配置已经足够我们使用），而`index.html.j2`文件应包含以下内容：

```
<html> 
    <body> 
        <h1>Hello World!</h1> 
        <p>This page was created on {{ ansible_date_time.date }}.</p> 
        <p>This machine can be reached on the following IP addresses</p> 
        <ul> 
{% for address in ansible_all_ipv4_addresses %} 
            <li>{{ address }}</li> 
{% endfor %} 
        </ul> 
    </body> 
</html> 
```

# 角色中的处理程序

完成此角色的最后一件事是创建`Restart HTTPd`通知的处理程序。为此，我们需要在`roles/webserver/handlers`中创建一个`main.yaml`文件，内容如下：

```
--- 
- name: Restart HTTPd 
  service: 
    name: httpd 
    state: restarted 
  become: True 
```

正如您可能已经注意到的，这与我们在 playbook 中使用的处理程序非常相似，只是文件位置和缩进不同。

使我们的角色可应用的唯一还需要做的事情是将条目添加到`playbooks/groups/webserver.yaml`文件中，以便通知 Ansible 服务器应用 Web 服务器角色以及常见角色。我们的`playbooks/groups/webserver.yaml`文件应该如下所示：

```
--- 
- hosts: webserver 
  user: ansible 
  roles: 
  - common 
  - webserver 
```

现在我们可以再次执行 `master.yaml`，以将 Web 服务器角色应用于相关服务器，但我们也可以只执行 `playbooks/groups/webserver.yaml`，因为我们刚刚进行的更改只与此服务器组相关。为此，我们运行以下命令：

```
ansible-playbook playbooks/groups/webserver.yaml 
```

我们应该收到类似于以下的输出。完整的代码输出文件可在 GitHub 上找到：

```
PLAY [webserver] *********************************************

TASK [Gathering Facts] ***************************************
ok: [ws01.fale.io]
ok: [ws02.fale.io]

TASK [common : Ensure EPEL is enabled] ***********************
ok: [ws01.fale.io]
ok: [ws02.fale.io]

TASK [common : Ensure libselinux-python is present] **********
ok: [ws01.fale.io]
ok: [ws02.fale.io]

TASK [common : Ensure libsemanage-python is present] *********
ok: [ws01.fale.io]
ok: [ws02.fale.io]

...
```

正如您在上述输出中所看到的，`common` 和 `webserver` 角色都已应用于 `webserver` 节点。

对于一个特定的节点，应用所有相关角色而不仅仅是您更改的角色非常重要，因为往往情况是，如果一个组中的一个或多个节点出现问题，而同一组中的其他节点没有问题，那么问题可能是该组中的某些角色被不均等地应用了。仅将所有相关角色应用于组将授予您该组节点的平等。

# 执行策略

在 Ansible 2 之前，每个任务都需要在每台机器上执行（并完成），然后 Ansible 才会在所有机器上发出新任务。这意味着，如果您正在对一百台机器执行任务，其中一台机器性能不佳，所有机器都将以性能不佳的机器的速度运行。

使用 Ansible 2，执行策略已被制作成模块化和可插拔的；因此，您现在可以为您的播放书选择您喜欢的执行策略。您还可以编写自定义执行策略，但这超出了本书的范围。目前（在 Ansible 2.7 中），只有三种执行策略，**线性**，**串行** 和 **自由**：

+   **线性执行**：此策略与 Ansible 版本 2 之前的行为完全相同。这是默认策略。

+   **串行执行**：此策略将获取一组主机（默认为五个）并在移动到下一组之前对这些主机执行所有任务，然后从头开始。这种执行策略可以帮助您在有限数量的主机上工作，以便您始终有一些可用于用户的主机。如果您正在寻找这种部署类型，您将需要一个位于主机之前的负载均衡器，该负载均衡器需要在每个给定时刻知道哪些节点正在维护。

+   **自由执行**：此策略将为每个主机提供一个新任务，一旦该主机完成了前一个任务。这将允许更快的主机在较慢的节点之前完成播放。如果选择此执行策略，您必须记住，某些任务可能需要在所有节点上完成先前的任务（例如，集群数据库需要所有数据库节点安装并运行数据库），在这种情况下，它们可能会失败。

# Ansible 模板 - Jinja 过滤器

我们已经在第二章，*自动化简单任务*中看到，这些模板允许您动态完成您的 playbook，并根据诸如`host`和`group`变量等动态数据在服务器上放置文件。在这一节中，我们将进一步看到**Jinja2 过滤器**如何与 Ansible 协同工作。

Jinja2 过滤器是简单的 Python 函数，它们接受一些参数，处理它们，并返回结果。例如，考虑以下命令：

```
{{ myvar | filter }}
```

在上面的示例中，`myvar`是一个变量；Ansible 将`myvar`作为参数传递给 Jinja2 过滤器。然后 Jinja2 过滤器会处理它并返回结果数据。Jinja2 过滤器甚至接受额外的参数，如下所示：

```
{{ myvar | filter(2) }}
```

在这个例子中，Ansible 现在会传递两个参数，即`myvar`和`2`。同样，你可以通过逗号分隔传递多个参数给过滤器。

Ansible 支持各种各样的 Jinja2 过滤器，我们将看到一些你在编写 playbook 时可能需要使用的重要 Jinja2 过滤器。

# 使用过滤器格式化数据

Ansible 支持 Jinja2 过滤器将数据格式化为 JSON 或 YAML。你将一个字典变量传递给这个过滤器，它将把你的数据格式化为 JSON 或 YAML。例如，考虑以下命令行：

```
{{ users | to_nice_json }}
```

在前面的示例中，`users`是变量，`to_nice_json`是 Jinja2 过滤器。正如我们之前看到的，Ansible 将`users`作为参数内部传递给 Jinja2 过滤器`to_nice_json`。同样，你也可以使用以下命令将你的数据格式化为 YAML：

```
{{ users | to_nice_yaml }}
```

# 默认未定义的变量

我们在前面的章节中已经看到，在使用变量之前检查它是否被定义是明智的。我们可以为变量设置一个`default`值，这样，如果变量没有被定义，Ansible 将使用该值而不是失败。要这样做，我们使用这个：

```
{{ backup_disk | default("/dev/sdf") }}
```

这个过滤器不会将`default`值分配给变量；它只会将`default`值传递给正在使用它的当前任务。在结束本节之前，让我们看一些 Jinja 过滤器本身的更多示例：

+   执行此命令以从列表中获取一个随机字符：

```
{{ ['a', 'b', 'c', 'd'] | random }} 
```

+   执行此命令以获取从`0`到`100`的随机数：

```
{{ 100 | random }}
```

+   执行此命令以获取从`10`到`50`的随机数：

```
{{ 50  | random(10) }}
```

+   执行此命令以获取从`20`到`50`，步长为`10`的随机数：

```
{{ 50 | random(20, 10) }}
```

+   使用过滤器将列表连接为字符串：Jinja2 过滤器允许您使用 join 过滤器将列表连接为字符串。这个过滤器将一个分隔符作为额外参数。如果你不指定分隔符，则该过滤器会将列表的所有元素组合在一起而不进行任何分隔。考虑以下例子：

```
{{ ["This", "is", "a", "string"] | join(" ") }} 
```

前述过滤器将产生一个输出`This is a string`。您可以指定任何分隔符，而不是空格。

当涉及使用过滤器编码或解码数据时，你可以按如下方式使用过滤器编码或解码数据：

+   使用`b64encode`过滤器将您的数据编码为`base64`：

```
{{ variable | b64encode }} 
```

+   使用 `b64decode` 过滤器解码编码的 `base64` 字符串：

```
{{ "aGFoYWhhaGE=" | b64decode }} 
```

# 安全管理

本章的最后一部分是关于**安全管理**的。如果你告诉系统管理员你想引入一个新功能或工具，他们会问你的第一个问题之一是："*你的工具有哪些安全功能？*"我们将尝试在这一部分从 Ansible 的角度回答这个问题。让我们更详细地看一下。

# 使用 Ansible Vault

**Ansible Vault** 是 Ansible 中一个令人兴奋的功能，它在 Ansible 版本 1.5 中引入。这允许你在源代码中使加密密码成为一部分。建议最好*不要*在你的存储库中以明文形式包含密码（以及其他敏感信息，如私钥和 SSL 证书），因为任何检出你存储库的人都可以查看你的密码。Ansible Vault 可以通过加密和解密来帮助你保护机密信息。

Ansible Vault 支持交互模式，在该模式下它将要求你输入密码，或非交互模式，在该模式下你将需要指定包含密码的文件，Ansible Vault 将直接读取它。

对于这些示例，我们将使用密码 `ansible`，因此让我们开始创建一个名为 `.password` 的隐藏文件，并在其中放置字符串 `ansible`。为此，请执行以下操作：

```
echo 'ansible' > .password
```

现在我们可以在交互和非交互模式下都创建 `ansible-vault`。如果我们想以交互模式进行，我们将需要执行以下操作：

```
ansible-vault create secret.yaml
```

Ansible 将要求我们提供保险柜密码，然后确认。稍后，它将打开默认文本编辑器（在我的情况下是**vi**）以添加明文内容。我已使用密码 `ansible` 和文本是 `This is a password protected file`。现在我们可以保存并关闭编辑器，并检查 `ansible-vault` 是否已加密我们的内容；事实上，我们可以运行以下命令：

```
cat secret.yaml
```

它将输出以下内容：

```
$ANSIBLE_VAULT;1.1;AES256
65396465353561366635653333333962383237346234626265633461353664346532613566393365
3263633761383434363766613962386637383465643130320a633862343137306563323236313930
32653533316238633731363338646332373935353935323133666535386335386437373539393365
3433356539333232650a643737326362396333623432336530303663366533303465343737643739
63373438316435626138646236643663313639303333306330313039376134353131323865373330
6333663133353730303561303535356230653533346364613830
```

同样，我们可以使用 `- vault-password-file=VAULT_PASSWORD_FILE` 选项在 `ansible-vault` 命令上调用非交互模式来指定我们的 `.password` 文件。例如，我们可以使用以下命令编辑我们的 `secret.yaml` 文件：

```
ansible-vault --vault-password-file=.password edit secret.yaml 
```

这将打开你的默认文本编辑器，你将能够更改文件，就像它是一个普通文件一样。当你保存文件时，Ansible Vault 会在保存之前执行加密，确保你内容的保密性。

有时，你需要查看文件的内容，但你不想在文本编辑器中打开它，所以通常使用 `cat` 命令。Ansible Vault 有一个类似的功能叫做 `view`，所以你可以运行以下命令：

```
ansible-vault --vault-password-file=.password view secret.yaml
```

Ansible Vault 允许你解密文件，将其加密内容替换为其明文内容。为此，你可以执行以下操作：

```
ansible-vault --vault-password-file=.password decrypt secret.yaml 
```

此时，我们可以在 `secret.yaml` 文件上使用 `cat` 命令，结果如下：

```
This is a password protected file
```

Ansible Vault 还提供了加密已经存在的文件的功能。如果您想要在受信任的机器上（例如，您自己的本地机器）上以明文形式开发所有文件以提高效率，然后在之后加密所有敏感文件，这将特别有用。为此，您可以执行以下操作：

```
ansible-vault --vault-password-file=.password encrypt secret.yaml
```

您现在可以检查`secret.yaml`文件是否再次加密。

Ansible Vault 的最后一个选项非常重要，因为它是一个`rekey`功能。此功能将允许您在单个命令中更改加密密钥。您可以使用两个命令执行相同的操作（使用**旧密钥**解密`secret.yaml`文件，然后使用**新密钥**加密它），但能够在单个步骤中执行此操作具有重大优势，因为文件以明文形式存储在磁盘上的任何时刻都不会被存储。

为此，我们需要一个包含新密码的文件（在我们的情况下，文件名为`.newpassword`，包含字符串`ansible2`），并且您需要执行以下命令：

```
ansible-vault --vault-password-file=.password --new-vault-password-file=.newpassword rekey secret.yaml 
```

我们现在可以使用`cat`命令查看`secret.yaml`文件，我们将看到以下输出：

```
$ANSIBLE_VAULT;1.1;AES256
32623466356639646661326164313965313366393935623236323465356265313630353930346135
3730616433353331376537343962366661616363386235330a643261303132336437613464636332
36656564653836616238383836383562633037376533376135663034316263323764656531656137
3462323739653339360a613933633865383837393331616363653765646165363333303232633132
63393237383231393738316465356636396133306132303932396263333735643230316361383339
3365393438636530646366336166353865376139393361396539
```

这与我们以前的非常不同。

# 保险库和播放脚本

您还可以使用`ansible-playbook`与保险库。您需要使用如下命令动态解密文件：

```
$ ansible-playbook site.yml --vault-password-file .password
```

还有另一个选项允许您使用脚本解密文件，该脚本然后可以查找其他源并解密文件。这也可以是提供更多安全性的有用选项。但是，请确保`get_password.py`脚本具有可执行权限：

```
$ ansible-playbook site.yml --vault-password-file ~/.get_password.py 
```

在结束本章之前，我想稍微谈谈密码文件。此文件需要存在于执行 playbooks 的机器上，在位置和权限方面，以便由执行 playbook 的用户可读取。您可以在启动时创建`.password`文件。

`.password`文件名中的`.`字符是为了确保文件默认隐藏在查找时。这不直接是一项安全措施，但它可能有助于减轻攻击者不知道他们正在寻找什么的情况。

`.password`文件内容应该是一个安全且只能由具有运行 Ansible playbooks 权限的人员访问的密码或密钥。

最后，请确保您没有加密每个可用的文件！ Ansible Vault 应仅用于需要安全的重要信息。

# 加密用户密码

Ansible Vault 负责检查已检入的密码，并在运行 Ansible playbooks 或命令时帮助您处理它们。但是，在运行 Ansible play 时，有时您可能需要用户输入密码。您还希望确保这些密码不会出现在详尽的 Ansible 日志（默认`/var/log/ansible.log`位置）或`stdout`上。

Ansible 使用 `Passlib`，这是一个用于 Python 的密码哈希库，用于处理提示密码的加密。您可以使用 `Passlib` 支持的以下任何算法：

+   `des_crypt`: DES 加密

+   `bsdi_crypt`: BSDi 加密

+   `bigcrypt`: BigCrypt

+   `crypt16`: Crypt16

+   `md5_crypt`: MD5 加密

+   `bcrypt`: BCrypt

+   `sha1_crypt`: SHA-1 加密

+   `sun_md5_crypt`: Sun MD5 加密

+   `sha256_crypt`: SHA-256 加密

+   `sha512_crypt`: SHA-512 加密

+   `apr_md5_crypt`: Apache 的 MD5-crypt 变体

+   `phpass`: PHPass 可移植哈希

+   `pbkdf2_digest`: 通用 PBKDF2 哈希

+   `cta_pbkdf2_sha1`: Cryptacular 的 PBKDF2 哈希

+   `dlitz_pbkdf2_sha1`: Dwayne Litzenberger 的 PBKDF2 哈希

+   `scram`: SCRAM 哈希

+   `bsd_nthash`: FreeBSD 的 MCF 兼容 `nthash` 编码

现在让我们看看如何使用变量提示进行加密：

```
- name: ssh_password 
  prompt: Enter ssh_password 
  private: True 
  encryption: md5_crypt 
  confirm: True 
  salt_size: 7 
```

在上述代码片段中，`vars_prompt` 用于提示用户输入一些数据。

这将提示用户输入密码，类似于 SSH 的方式。

`name` 键指示 Ansible 将存储用户密码的实际变量名，如下所示：

```
name: ssh_password  
```

我们使用 `prompt` 键提示用户输入密码，如下所示：

```
prompt: Enter ssh password  
```

我们通过使用 `private` 键显式要求 Ansible 隐藏密码不输出到 `stdout`；这与 Unix 系统上的任何其他密码提示相似。`private` 键的访问方式如下所示：

```
private: True  
```

我们在此处使用 `md5_crypt` 算法，并使用 `7` 作为盐的大小：

```
encrypt: md5_crypt
salt_size: 7  
```

此外，Ansible 将提示两次密码并比较两个密码：

```
confirm: True  
```

# 隐藏密码

默认情况下，Ansible 过滤包含 `login_password` 键、`password` 键和 `user:pass` 格式的输出。例如，如果您正在使用 `login_password` 或 `password` 键传递密码，则 Ansible 将使用 `VALUE_HIDDEN` 替换您的密码。现在让我们看看如何使用 `password` 键隐藏密码：

```
- name: Running a script
  shell: script.sh
    password: my_password  
```

在上述 `shell` 任务中，我们使用 `password` 键来传递密码。这将使 Ansible 能够隐藏它在 `stdout` 和其日志文件中。

现在，当您以*详细*模式运行上述任务时，您不应该看到您的 `mypass` 密码；相反，Ansible 将使用 `VALUE_HIDDEN` 替换它，如下所示：

```
REMOTE_MODULE command script.sh password=VALUE_HIDDEN #USE_SHELL  
```

# 使用 `no_log`

只有在使用特定的键时，Ansible 才会隐藏您的密码。然而，这可能并非每次都是这样；此外，您可能还想隐藏其他一些机密数据。Ansible 的 `no_log` 功能将隐藏整个任务，防止其记录到 `syslog` 文件中。它仍将在 `stdout` 上打印您的任务，并记录到其他 Ansible 日志文件中。

在撰写本书时，Ansible 不支持使用 `no_log` 从 `stdout` 隐藏任务。

现在让我们看看如何使用 `no_log` 隐藏整个任务：

```
- name: Running a script
  shell: script.sh
    password: my_password
  no_log: True  
```

通过将 `no_log: True` 传递给您的任务，Ansible 将防止整个任务被记录到 `syslog` 中。

# 概要

在本章中，我们看到了大量 Ansible 的特性。我们从`local_actions`开始，用于在一台机器上执行操作，然后我们转向委托，在第三台机器上执行任务。然后，我们转向条件语句和 include，使 playbooks 更加灵活。我们学习了角色以及它们如何帮助您保持系统一致，还学会了如何正确组织 Ansible 仓库，充分利用 Ansible 和 Git。接着，我们讨论了执行策略和 Jinja 过滤器，以实现更加灵活的执行。

我们结束了本章对 Ansible Vault 的讲解，并提供了许多其他提示，以使您的 Ansible 执行更安全。

在下一章中，我们将看看如何使用 Ansible 来创建基础设施，更具体地说，如何在云提供商 AWS 和 DigitalOcean 上使用它。


# 第七章：往云端前进

在本章中，我们将看到如何使用 Ansible 在几分钟内配置基础架构。在我看来，这是 Ansible 最有趣和强大的功能之一，因为它允许你快速，一致地重建环境。当你有多个环境用于你的部署流程的不同阶段时，这非常重要。事实上，它允许你创建相等的环境，并在需要进行更改时保持其对齐，而不会感到任何痛苦。

让 Ansible 配置你的设备还有其他的优点，为此，我总是建议执行以下操作：

+   **审计追踪**：最近几年来，IT 行业吞食了大量其他行业，作为这个过程的一部分，审计流程现在将 IT 视为流程的关键部分。当审计师来到 IT 部门询问服务器的历史记录，从创建到目前为止，有 Ansible 播放脚本的整个过程将非常有帮助。

+   **多个分阶段的环境**：正如我们之前提到的，如果你有多个环境，使用 Ansible 配置服务器将会对你非常有帮助。

+   **迁移服务器**：当一家公司使用全球云提供商（如 AWS、DigitalOcean 或 Azure）时，他们通常会选择距离他们办公室或客户最近的区域来创建第一台服务器。这些提供商经常开设新区域，如果他们的新区域更靠近你，你可能会想将整个基础架构迁移到新区域。如果你手动配置了每个资源，这将是一场噩梦！

在本章中，从宏观层面上，我们将涵盖以下主题：

+   在 AWS 中配置机器

+   在 DigitalOcean 中配置机器

+   在 Azure 中配置机器

大多数新设备创建有两个阶段：

+   配置新机器或一组新机器

+   运行播放脚本，确保新机器被正确配置以发挥其在你的基础架构中的作用

在最初的章节中，我们已经看过了配置管理方面。在本章中，我们将更加专注于配置新机器，对配置管理的关注较少。

# 技术要求

你可以从本书的 GitHub 存储库中下载所有文件，网址为 [`github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter05`](https://github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter05)。

# 在云中配置资源

有了这个，让我们跳到第一个主题。管理基础架构的团队今天有很多选择来运行他们的构建、测试和部署。提供商比如亚马逊、Azure 和 DigitalOcean 主要提供基础设施即服务（**IaaS**）。当我们谈论 IaaS 时，最好谈论资源而不是虚拟机，有几个原因：

+   这些公司允许您提供的多数产品都不是机器，而是其他关键资源，例如网络和存储。

+   最近，这些公司开始提供许多不同类型的计算实例，从裸金属机器到容器。

+   在某些非常简单的环境中，无网络（或存储）的机器设置可能就足够了，但在生产环境中可能不够。

这些公司通常提供 API、CLI、GUI 和 SDK 工具，以创建和管理云资源的整个生命周期。我们更感兴趣的是使用它们的 SDK，因为它在我们的自动化努力中将发挥重要作用。在刚开始时，建立新服务器并进行配置是有趣的，但在某个阶段，它可能变得乏味，因为它是相当重复的。每个配置步骤都会涉及几个类似的步骤，以使它们正常运行。

想象一下，某天早上您收到一封电子邮件，要求为三个新的客户设置安装，其中每个客户设置都有三到四个实例和一堆服务和依赖项。对您来说，这可能是个简单的任务，但它需要多次运行相同的重复命令，然后在服务器启动后监视它们以确认一切顺利。此外，您手动进行的任何操作都有可能引入问题。如果前两个客户设置正确启动，但由于疲劳，您遗漏了第三个客户的一个步骤，从而引入了问题怎么办？为了处理这种情况，就需要自动化。

云配置自动化使工程师能够尽快建立新的服务器，从而使他们能够集中精力处理其他优先事项。使用 Ansible，您可以轻松执行这些操作，并以最少的工作量自动化云配置。Ansible 为您提供了自动化各种不同云平台的能力，如 Amazon、Azure、DigitalOcean、Google Cloud、Rackspace 等，其中涵盖了 Ansible 核心版或扩展模块包中提供的不同服务的模块。

如前所述，启动新机器并不是结束游戏的标志。我们还需要确保我们配置它们以发挥所需的作用。

在接下来的章节中，我们将在以下环境中配置我们在之前章节中使用的环境（两个 Web 服务器和一个数据库服务器）：

+   **简单的 AWS 部署**：所有机器将放置在相同的**可用区**（AZs）和相同的网络中。

+   **复杂的 AWS 部署**：在此部署中，机器将分割到多个可用区（AZs）和网络中。

+   **DigitalOcean**：由于 DigitalOcean 不允许我们进行许多网络调整，因此它与第一个相似。

+   **Azure**：在这种情况下，我们将创建一个简单的部署。

# 在 AWS 中配置机器

AWS 是被广泛使用的最大的公有云，通常会被选择，因为它有大量可用的服务以及大量的文档、回答问题和相关文章可以在这样一个热门产品周围找到。

由于 AWS 的目标是成为完整的虚拟数据中心提供商（以及更多），我们将需要创建和管理我们的网络，就像我们如果要建立一个真实的数据中心一样。显然，我们不需要为电缆等东西，因为这是一个虚拟数据中心。因此，几行 Ansible playbook 就足够了。

# AWS 全球基础设施

亚马逊一直非常谨慎地分享其云实际上由哪些数据中心组成的位置或确切数量。在我写这篇文章时，AWS 拥有 21 个区域（还宣布了四个更多的区域），共 61 个 AZ 和数百个边缘位置。亚马逊将一个区域定义为“*我们（亚马逊）拥有多个 AZ 的世界中的物理位置*”。查看亚马逊关于 AZ 的文档，它说“*一个 AZ 由一个或多个离散的数据中心组成，每个数据中心都有冗余的电力、网络和连接，设立在不同的设施中*”。对于边缘位置，没有官方定义。

如你所见，从现实生活的角度来看，这些定义并没有帮助太多。当我尝试解释这些概念时，我通常使用我自己创造的不同定义：

+   **区域**：一组物理上靠近的 AZ

+   **AZ**：一个区域中的数据中心（亚马逊表示它可能不止一个数据中心，但由于没有列出每个 AZ 的具体几何形状的文件，我假定最坏情况）

+   **边缘位置**：互联网交换或第三方数据中心，亚马逊在这里拥有 CloudFront 和 Route 53 终端点。

尽管我试图使这些定义尽可能简单和有用，但其中一些仍然很模糊。当我们开始谈论现实世界的差异时，这些定义会立即变得清晰。例如，从网络速度的角度看，当你在同一个 AZ 内移动内容时，带宽非常高。当你在同一区域内使用两个 AZ 进行相同操作时，你会获得高带宽，而如果你在两个不同区域使用两个 AZ，带宽将更低。此外，还有价格差异，因为同一区域内的所有流量是免费的，而不同区域之间的流量是免费的。

# AWS 简单存储服务

亚马逊 **简单存储服务**（**S3**）是推出的第一项 AWS 服务，也是最为人所知的 AWS 服务之一。Amazon S3 是一种对象存储服务，具有公共端点和私有端点。它使用 bucket 的概念，允许您管理不同类型的文件并以简单的方式管理它们。Amazon S3 还提供了用户更高级的功能，例如使用内置 Web 服务器来提供 bucket 内容的能力。这就是许多人决定在 Amazon S3 上托管其网站或网站上的图片的原因之一。

S3 的优点主要有以下几点：

+   **价格方案**：您将按照已使用的每 GB/月和已传输的每 GB 计费。

+   **可靠性**：亚马逊声称 AWS S3 上的对象在任何一年内有 99.999999999% 的存活率。这比任何硬盘都要高出数量级。

+   **工具**：因为 S3 是一个已经存在多年的服务，许多工具已被实现以利用这项服务。

# AWS 弹性计算云

AWS 推出的第二项服务是 **弹性计算云**（**EC2**）服务。该服务允许您在 AWS 基础设施上创建计算机。您可以将这些 EC2 实例视为 OpenStack 计算实例或 VMware 虚拟机。最初，这些机器与 VPS 非常相似，但过了一段时间亚马逊决定赋予这些机器更多的灵活性，并引入了非常先进的网络选项。旧类型的机器仍然在最古老的数据中心中提供，名为 EC2 Classic，而新类型是当前的默认选项，只被称为 EC2。

# AWS 虚拟私有云

**虚拟私有云**（**VPC**）是亚马逊在前面提到的网络实现。VPC 更多的是一组工具而不是单个工具；实际上，它所提供的功能由经典数据中心中的多个金属盒子提供。

您可以通过 VPC 创建以下主要事项：

+   交换机

+   路由器

+   DHCP

+   网关

+   防火墙

+   **虚拟专用网络**（**VPN**）

当使用 VPC 时，重要的是要了解您的网络布局不是完全任意的，因为亚马逊创建了一些限制来简化其网络。基本限制如下：

+   您不能在 AZ 之间生成子网络。

+   您不能在不同的区域之间生成网络。

+   您不能直接路由不同区域的网络。

而对于前两者，唯一的解决方案是创建多个网络和子网络，而对于第三者，您实际上可以使用 VPN 服务来实现一个解决方法，该 VPN 服务可以是自我提供的，也可以是使用官方的 AWS VPN 服务提供的。

我们将主要使用 VPC 的交换和路由功能。

# AWS Route 53

与许多其他云服务一样，亚马逊提供了 **作为服务的 DNS**（**DNSaaS**） 功能，而在亚马逊的情况下，它被称为 **Route 53**。 Route 53 是一个分布式 DNS 服务，在全球各地拥有数百个端点（Route 53 存在于所有 AWS 边缘位置）。

Route 53 允许您为域创建不同的区域，从而允许分割地平线情况，根据请求 DNS 解析的客户端是否在您的 VPC 内或外部，将接收不同的响应。当您希望您的应用程序轻松地在您的 VPC 内外移动而无需更改时，这非常有用，但同时，您希望您的流量尽可能地保留在一个私有（虚拟）网络中。

# AWS 弹性块存储

AWS **弹性块存储**（**EBS**）是一个块存储提供者，允许您的 EC2 实例保留数据，这些数据将在重新启动后保留，并且非常灵活。从用户的角度来看，EBS 看起来很像任何其他 SAN 产品，只是具有更简单的界面，因为您只需要创建卷并告诉 EBS 需要连接到哪台机器，然后 EBS 会完成其余工作。您可以将多个卷附加到单个服务器，但每个卷一次只能连接到一个服务器。

# AWS 身份和访问管理

为了允许您管理用户和访问方法，亚马逊提供了 **身份和访问管理**（**IAM**） 服务。IAM 服务的主要特点如下：

+   创建、编辑和删除用户

+   更改用户密码

+   创建、编辑和删除组

+   管理用户和组关联

+   管理令牌

+   管理双因素身份验证

+   管理 SSH 密钥

我们将使用此服务来设置用户及其权限。

# 亚马逊关系型数据库服务

设置和维护关系数据库是复杂且非常耗时的。为了简化这一过程，亚马逊提供了一些广泛使用的 **作为服务的数据库**（**DBaaS**），具体如下：

+   Aurora

+   MariaDB

+   MySQL

+   Oracle

+   PostgreSQL

+   SQL Server

对于这些引擎中的每一个，亚马逊提供不同的功能和价格模型，但每个引擎的具体细节超出了本书的目标。

# 在 AWS 上设置账户

在开始使用 AWS 之前，我们需要的第一件事是账户。在 AWS 上创建账户非常简单，并且由亚马逊官方文档以及多个独立站点进行了很好的记录，因此在这些页面中不会涉及此操作。

创建好 AWS 账户后，需要进入 AWS 并完成以下操作：

+   在 EC2 | Keypairs 中上传您的 SSH 密钥。

+   在 Identity & Access Management | Users | 创建新用户 中创建新用户，并在 `~/.aws/credentials` 中创建一个文件，其中包含以下行：

```
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
```

创建好 AWS 密钥并上传 SSH 密钥后，您需要设置 Route 53。在 Route 53 中，您需要为您的域创建两个区域（如果您没有未使用的域，也可以使用子域）：一个公共区域和一个私有区域。

如果你只创建公共区域，Route 53 将在全局范围内传播该区域，但如果你创建了一个公共区域和一个私有区域，Route 53 将在创建私有区域时指定的 VPC 以外的所有地方提供你的公共区域服务。如果你在该 VPC 内查询这些 DNS 条目，将使用私有区域。这种方法有多个优点：

+   只公开公共机器的 IP 地址。

+   即使对于内部流量，也要始终使用 DNS 名称而不是 IP 地址。

+   确保你的内部机器直接通信，而无需通过公共网络传递数据。

+   由于 AWS 中的外部 IP 是由 Amazon 管理的虚拟 IP 地址，并使用 NAT 与你的实例关联，因此这种方法可以提供最少的跳数，从而减少时延。

如果你在公共区域中声明了一个条目，但在私有区域中没有声明该条目，那么 VPC 中的机器将无法解析该条目。

在创建公共区域后，AWS 将给出一些域名服务器 IP 地址，你需要将这些 IP 地址放入你的注册/根区域 DNS 中，以便你实际上可以解析这些 DNS。

# 简单的 AWS 部署

正如我们之前所说，我们首先需要的是网络连接。对于这个示例，我们只需要一个单独的可用区中的一个网络来容纳所有的机器。

在本节中，我们将在`playbooks/aws_simple_provision.yaml`文件中工作。

前两行只用于声明将执行命令的主机（localhost）和任务部分的开始：

```
- hosts: localhost
  tasks:  
```

首先，我们将确保存在公钥/私钥对：

```
    - name: Ensure key pair is present
      ec2_key:
        name: fale
        key_material: "{{ lookup('file', '~/.ssh/fale.pub') }}"
```

在 AWS 中，我们需要有一个 VPC 网络和子网。默认情况下，它们已经存在，但如果需要，可以执行以下步骤创建 VPC 网络：

```
    - name: Ensure VPC network is present
      ec2_vpc_net:
        name: NET_NAME
        state: present
        cidr_block: 10.0.0.0/16
        region: AWS_REGION
      register: aws_net
    - name: Ensure the VPC subnetwork is present
      ec2_vpc_subnet:
        state: present
        az: AWS_AZ
        vpc_id: '{{ aws_simple_net.vpc_id }}'
        cidr: 10.0.1.0/24
      register: aws_subnet
```

由于我们使用的是默认的 VPC，我们需要查询 AWS 以了解 VPC 网络和子网的值：

```
   - name: Ensure key pair is present
      ec2_key:
        name: fale
        key_material: "{{ lookup('file', '~/.ssh/fale.pub') }}"
    - name: Gather information of the EC2 VPC net in eu-west-1
 ec2_vpc_net_facts:
 region: eu-west-1
 register: aws_simple_net
 - name: Gather information of the EC2 VPC subnet in eu-west-1
 ec2_vpc_subnet_facts:
 region: eu-west-1
 filters:
 vpc-id: '{{ aws_simple_net.vpcs.0.id }}'
 register: aws_simple_subnet
```

现在我们已经获得了关于网络和子网的所有信息，接下来我们可以转向安全组。我们可以使用`ec2_group`模块来完成。在 AWS 世界中，安全组用于防火墙。安全组与共享相同目标的防火墙规则组非常相似（对于入口规则）或相同目标（对于出口规则）。与标准防火墙规则相比，实际上有三个不同之处值得一提：

+   多个安全组可以应用于同一个 EC2 实例。

+   作为源（对于入口规则）或目标（对于出口规则），你可以指定以下之一：

    +   一个实例 ID

    +   另一个安全组

    +   一个 IP 范围

+   你不需要在链的末尾指定默认拒绝规则，因为 AWS 会默认添加它。

所以，对于我的情况，以下代码将被添加到`playbooks/aws_simple_provision.yaml`中：

```
    - name: Ensure wssg Security Group is present
      ec2_group:
        name: wssg
        description: Web Security Group
        region: eu-west-1
        vpc_id: '{{ aws_simple_net.vpcs.0.id }}'
        rules:
          - proto: tcp 
            from_port: 22
            to_port: 22
            cidr_ip: 0.0.0.0/0
          - proto: tcp 
            from_port: 80
            to_port: 80
            cidr_ip: 0.0.0.0/0
          - proto: tcp 
            from_port: 443 
            to_port: 443 
            cidr_ip: 0.0.0.0/0
        rules_egress:
          - proto: all 
            cidr_ip: 0.0.0.0/0
      register: aws_simple_wssg
```

现在我们即将为我们的数据库创建另一个安全组。在这种情况下，我们只需要向 Web 安全组中的服务器打开`3036`端口即可：

```
    - name: Ensure dbsg Security Group is present
      ec2_group:
        name: dbsg
        description: DB Security Group
        region: eu-west-1
        vpc_id: '{{ aws_simple_net.vpcs.0.id }}'
        rules:
          - proto: tcp
            from_port: 3036
            to_port: 3036
            group_id: '{{ aws_simple_wssg.group_id }}'
        rules_egress:
          - proto: all
            cidr_ip: 0.0.0.0/0
```

如你所见，我们允许所有出站流量流动。这并不是安全最佳实践建议的做法，因此您可能需要调节出站流量。经常迫使您调节出站流量的情况是，如果您希望目标机器符合 PCI-DSS 标准。

现在我们有了 VPC、VPC 中的子网和所需的安全组，我们现在可以继续实际创建 EC2 实例了：

```
    - name: Setup instances
      ec2:
        assign_public_ip: '{{ item.assign_public_ip }}'
        image: ami-3548444c
        region: eu-west-1
        exact_count: 1
        key_name: fale
        count_tag:
          Name: '{{ item.name }}'
        instance_tags:
          Name: '{{ item.name }}'
        instance_type: t2.micro
        group_id: '{{ item.group_id }}'
        vpc_subnet_id: '{{ aws_simple_subnet.subnets.0.id }}'
        volumes:
          - device_name: /dev/sda1
            volume_type: gp2
            volume_size: 10
            delete_on_termination: True
      register: aws_simple_instances
      with_items:
        - name: ws01.simple.aws.fale.io
          group_id: '{{ aws_simple_wssg.group_id }}'
          assign_public_ip: True
        - name: ws02.simple.aws.fale.io
          group_id: '{{ aws_simple_wssg.group_id }}'
          assign_public_ip: True
        - name: db01.simple.aws.fale.io
          group_id: '{{ aws_simple_dbsg.group_id }}'
          assign_public_ip: False 
```

当我们创建 DB 机器时，我们没有指定 `assign_public_ip: True` 行。在这种情况下，该机器将不会收到公共 IP，因此它将无法从 VPC 外部访问。由于我们为此服务器使用了非常严格的安全组，因此它不会从 `wssg` 外的任何机器访问。

正如你所猜到的那样，我们刚刚看到的代码片段将创建我们的三个实例（两个 Web 服务器和一个 DB 服务器）。

现在，我们可以将这些新创建的实例添加到我们的 Route 53 帐户中，以便解析这些机器的完全限定域名。为了与 AWS Route 53 交互，我们将使用 `route53` 模块，该模块允许我们创建条目、查询条目和删除条目。要创建新条目，我们将使用以下代码：

```
    - name: Add route53 entry for server SERVER_NAME
      route53:
        command: create
        zone: ZONE_NAME
        record: RECORD_TO_ADD
        type: RECORD_TYPE
        ttl: TIME_TO_LIVE
        value: IP_VALUES
        wait: True
```

因此，为我们的服务器创建条目，我们将添加以下代码：

```
    - name: Add route53 rules for instances
      route53:
        command: create
        zone: aws.fale.io
        record: '{{ item.tagged_instances.0.tags.Name }}'
        type: A
        ttl: 1
        value: '{{ item.tagged_instances.0.public_ip }}'
        wait: True
      with_items: '{{ aws_simple_instances.results }}'
      when: item.tagged_instances.0.public_ip
    - name: Add internal route53 rules for instances
      route53:
        command: create
        zone: aws.fale.io
        private_zone: True
        record: '{{ item.tagged_instances.0.tags.Name }}'
        type: A
        ttl: 1
        value: '{{ item.tagged_instances.0.private_ip }}'
        wait: True
      with_items: '{{ aws_simple_instances.results }}'  
```

由于数据库服务器没有公共地址，将此机器发布到公共区域是没有意义的，因此我们只在内部区域中创建了此机器条目。

将所有内容整合在一起，`playbooks/aws_simple_provision.yaml` 将如下所示。完整的代码可在 GitHub 上找到：

```
---
- hosts: localhost
  tasks:
    - name: Ensure key pair is present
      ec2_key:
        name: fale
        key_material: "{{ lookup('file', '~/.ssh/fale.pub') }}"
    - name: Gather information of the EC2 VPC net in eu-west-1
      ec2_vpc_net_facts:
        region: eu-west-1
      register: aws_simple_net
    - name: Gather information of the EC2 VPC subnet in eu-west-1
      ec2_vpc_subnet_facts:
        region: eu-west-1
        filters:
          vpc-id: '{{ aws_simple_net.vpcs.0.id }}'
      register: aws_simple_subnet
   ...
```

运行 `ansible-playbook playbooks/aws_simple_provision.yaml`，Ansible 将负责创建我们的环境。

# 复杂的 AWS 部署

在本节中，我们将稍微修改之前的示例，将其中一个 Web 服务器移至同一地区的另一个可用区。为此，我们将在 `playbooks/aws_complex_provision.yaml` 中创建一个新文件，该文件与之前的文件非常相似，唯一的区别在于帮助我们配置机器的部分。事实上，我们将使用以下代码片段代替我们上次运行时使用的代码片段。完整的代码可在 GitHub 上找到：

```
    - name: Setup instances
      ec2:
        assign_public_ip: '{{ item.assign_public_ip }}'
        image: ami-3548444c
        region: eu-west-1
        exact_count: 1
        key_name: fale
        count_tag:
          Name: '{{ item.name }}'
        instance_tags:
          Name: '{{ item.name }}'
        instance_type: t2.micro
        group_id: '{{ item.group_id }}'
        vpc_subnet_id: '{{ item.vpc_subnet_id }}'
        volumes:
          - device_name: /dev/sda1
            volume_type: gp2
            volume_size: 10
            delete_on_termination: True
    ...
```

如你所见，我们将 `vpc_subnet_id` 放入一个变量中，这样我们就可以为 `ws02` 机器使用不同的子网。由于 AWS 已经默认提供了两个子网（每个子网都绑定到不同的可用区），因此只需使用以下的可用区即可。安全组和 Route 53 代码不需要更改，因为它们不在子网/可用区级别工作，而在 VPC 级别（对于安全组和内部 Route 53 区域）或全局级别（对于公共 Route 53）工作。

# 在 DigitalOcean 中进行机器配置

与 AWS 相比，DigitalOcean 似乎非常不完整。直到几个月前，DigitalOcean 只提供了小水滴、SSH 密钥管理和 DNS 管理。在撰写本文时，DigitalOcean 最近推出了额外的块存储服务。与许多竞争对手相比，DigitalOcean 的优势如下：

+   价格比 AWS 低。

+   非常简单的 API。

+   文档非常完善的 API。

+   小水滴与标准虚拟机非常相似（它们不进行奇怪的自定义）。

+   小水滴上下移动速度很快。

+   由于 DigitalOcean 具有非常简单的网络堆栈，因此比 AWS 更高效。

# 小水滴

小水滴是 DigitalOcean 提供的主要服务，是非常类似于 Amazon EC2 Classic 的计算实例。DigitalOcean 依赖于**Kernel Virtual Machine**（**KVM**）来虚拟化机器，确保非常高的性能和安全性。

由于他们没有以任何明智的方式更改 KVM，而且由于 KVM 是开源的，并且可在任何 Linux 机器上使用，这使得系统管理员可以在私有和公共云上创建相同的环境。DigitalOcean 小水滴将具有一个外部 IP，它们最终可以添加到一个虚拟网络中，该虚拟网络将允许您的机器使用内部 IP。

与许多其他可比较的服务不同，DigitalOcean 允许您的小水滴除了 IPv4 地址外，还具有 IPv6 地址。该服务是免费的。

# SSH 密钥管理

每次想要创建一个小水滴时，都必须指定是否要为 root 用户分配特定的 SSH 密钥，或者是否要设置一个密码（第一次登录时必须更改）。要能够选择一个 SSH 密钥，您需要一个用于上传的接口。DigitalOcean 允许您使用非常简单的界面进行此操作，该界面允许您列出当前的密钥，以及创建和删除密钥。

# 私有网络

正如在小水滴部分中所提到的，DigitalOcean 允许我们拥有一个私有网络，我们的机器可以与另一个机器通信。这允许对服务进行隔离（例如数据库服务）仅在内部网络上以提供更高级别的安全性。由于默认情况下，MySQL 绑定到所有可用接口，因此我们将需要稍微调整数据库角色以仅绑定到内部网络。

为了识别内部网络和外部网络，由于一些 DigitalOcean 的特殊性，有许多方法：

+   私有网络始终位于`10.0.0.0/8`网络中，而公共 IP 从不在该网络中。

+   公网始终是`eth0`，而私网始终是`eth1`。

根据您的可移植性需求，您可以使用这两种策略之一来了解在哪里绑定您的服务。

# 在 DigitalOcean 中添加 SSH 密钥

我们首先需要一个 DigitalOcean 帐户。一旦我们有了 DigitalOcean 用户、设置了信用卡和 API 密钥，我们就可以开始使用 Ansible 将我们的 SSH 密钥添加到我们的 DigitalOcean 云中。为此，我们需要创建一个名为`playbooks/do_provision.yaml`的文件，其结构如下：

```
- hosts: localhost
  tasks:
    - name: Add the SSH Key to Digital Ocean
      digital_ocean:
        state: present
        command: ssh
        name: SSH_KEY_NAME
        ssh_pub_key: 'ssh-rsa AAAA...'
        api_token: XXX
      register: ssh_key
```

在我这个案例中，这是我的文件内容：

```
    - name: Add the SSH Key to Digital Ocean
      digital_ocean:
        state: present
        command: ssh
        name: faleKey
        ssh_pub_key: "{{ lookup('file', '~/.ssh/fale.pub') }}"
        api_token: ee02b...2f11d
      register: ssh_key
```

然后我们可以执行它，你将会得到类似以下的结果：

```
PLAY [all] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [localhost]

TASK [Add the SSH Key to Digital Ocean] ******************************
changed: [localhost]

PLAY RECAP ***********************************************************
localhost : ok=2 changed=1 unreachable=0 failed=0
```

此任务是幂等的，因此我们可以多次执行它。如果密钥已经上传，那么每次运行都会返回 SSH 密钥 ID。

# 在 DigitalOcean 中部署

在撰写本文时，使用 Ansible 创建 droplet 的唯一方法是使用`digital_ocean`模块，该模块可能很快就会被弃用，因为它的许多功能现在已经由其他模块以更好、更干净的方式完成，而且 Ansible 错误跟踪器上已经有一个 bug 来跟踪它的完全重写和可能的弃用。我猜新模块将被称为`digital_ocean_droplet`，并且将具有类似的语法，但目前没有代码，所以这只是我的猜测。

要创建 droplets，我们将使用类似以下的`digital_ocean`模块语法：

```
 - name: Ensure the ws and db servers are present
   digital_ocean:
     state: present
     ssh_key_ids: KEY_ID
     name: '{{ item }}'
     api_token: DIGITAL_OCEAN_KEY
     size_id: 512mb
     region_id: lon1
     image_id: centos-7-0-x64
     unique_name: True
   with_items:
     - WEBSERVER 1
     - WEBSERVER 2
     - DBSERVER 1
```

为了确保我们所有的 provisioning 都是完全且健康的，我始终建议为整个基础架构创建一个单独的 provision 文件。因此，在我的情况下，我将在`playbooks/do_provision.yaml`文件中添加以下任务：

```
    - name: Ensure the ws and db servers are present
      digital_ocean:
        state: present
        ssh_key_ids: '{{ ssh_key.ssh_key.id }}'
        name: '{{ item }}'
        api_token: ee02b...2f11d
        size_id: 512mb
        region_id: lon1
        image_id: centos-7-x64
        unique_name: True
      with_items:
        - ws01.do.fale.io
        - ws02.do.fale.io
        - db01.do.fale.io
      register: droplets
```

这之后，我们可以使用`digital_ocean_domain`模块添加域名：

```
    - name: Ensure domain resolve properly
      digital_ocean_domain:
        api_token: ee02b...2f11d
        state: present
        name: '{{ item.droplet.name }}'
        ip: '{{ item.droplet.ip_address }}'
      with_items: '{{ droplets.results }}'
```

因此，将所有这些放在一起，我们的`playbooks/do_provision.yaml`将如下所示，完整的代码块可在 GitHub 上找到：

```
---
- hosts: localhost
  tasks:
    - name: Ensure domain is present
      digital_ocean_domain:
        api_token: ee02b...2f11d
        state: present
        name: do.fale.io
        ip: 127.0.0.1
    - name: Add the SSH Key to Digital Ocean
      digital_ocean:
        state: present
        command: ssh
        name: faleKey
        ssh_pub_key: "{{ lookup('file', '~/.ssh/fale.pub') }}"
        api_token: ee02b...2f11d
      register: ssh_key
   ...
```

因此，我们现在可以用以下命令运行它：

```
ansible-playbook playbooks/do_provision.yaml 
```

我们将看到类似以下的结果。完整的代码输出文件可在 GitHub 上找到：

```
PLAY [localhost] *****************************************************

TASK [Gathering Facts] ***********************************************
ok: [localhost]

TASK [Ensure domain is present] **************************************
changed: [localhost]

TASK [Add the SSH Key to Digital Ocean] ******************************
changed: [localhost]

TASK [Ensure the ws and db servers are present] **********************
changed: [localhost] => (item=ws01.do.fale.io)
changed: [localhost] => (item=ws02.do.fale.io)
changed: [localhost] => (item=db01.do.fale.io)

...
```

我们已经看到了如何使用几行 Ansible 在 DigitalOcean 上提供三台机器。我们现在可以使用我们在前几章中讨论过的 playbook 来配置它们。

# 在 Azure 中提供机器

最近，Azure 正在成为一些公司中最大的云之一。

正如你可能想象的那样，Ansible 有 Azure 特定的模块，可以轻松创建 Azure 环境。

在创建了帐户之后，我们在 Azure 上首先需要做的事情是设置授权。

有几种方法可以做到这一点，但最简单的方法可能是创建以 INI 格式包含`[default]`部分的`~/.azure/credentials`文件，其中包含`subscription_id`和，可选的，`client_id`和`secret`或`ad_user`和`password`。

一个示例如下文件：

```
[default]
subscription_id: __AZURE_SUBSCRIPTION_ID__
client_id: __AZURE_CLIENT_ID__ secret: __AZURE_SECRET__
```

之后，我们需要一个资源组，然后我们将在其中创建所有资源。

为此，我们可以使用`azure_rm_resourcegroup`，语法如下：

```
    - name: Create resource group
      azure_rm_resourcegroup:
        name: myResourceGroup
        location: eastus
```

现在我们有了资源组，我们可以在其中创建虚拟网络和虚拟子网络：

```
     - name: Create Azure VM
            hosts: localhost
            tasks:
      - name: Create resource group
            azure_rm_resourcegroup:
            name: myResourceGroup
            location: eastus
      - name: Create virtual network
            azure_rm_virtualnetwork:
            resource_group: myResourceGroup
            name: myVnet
           address_prefixes: "10.0.0.0/16"
    - name: Add subnet
           azure_rm_subnet:
           resource_group: myResourceGroup
          name: mySubnet
          address_prefix: "10.0.1.0/24"
          virtual_network: myVnet
```

在我们继续创建虚拟机之前，我们仍然需要一些网络项目，更具体地说，需要一个公共 IP、一个网络安全组和一个虚拟网络卡：

```
    - name: Create public IP address
      azure_rm_publicipaddress:
        resource_group: myResourceGroup
        allocation_method: Static
        name: myPublicIP
      register: output_ip_address
    - name: Dump public IP for VM which will be created
      debug:
        msg: "The public IP is {{ output_ip_address.state.ip_address }}."
    - name: Create Network Security Group that allows SSH 
      azure_rm_securitygroup:
        resource_group: myResourceGroup
        name: myNetworkSecurityGroup
        rules:
          - name: SSH 
            protocol: Tcp 
            destination_port_range: 22
            access: Allow
            priority: 1001
            direction: Inbound
    - name: Create virtual network inteface card
      azure_rm_networkinterface:
        resource_group: myResourceGroup
        name: myNIC
        virtual_network: myVnet
        subnet: mySubnet
        public_ip_name: myPublicIP
        security_group: myNetworkSecurityGroup
```

现在我们准备创建我们的第一台 Azure 机器，使用以下代码：

```
    - name: Create VM
      azure_rm_virtualmachine:
        resource_group: myResourceGroup
        name: myVM
        vm_size: Standard_DS1_v2
        admin_username: azureuser
        ssh_password_enabled: false
        ssh_public_keys:
          - path: /home/azureuser/.ssh/authorized_keys
            key_data: "{{ lookup('file', '~/.ssh/fale.pub') }}"
        network_interfaces: myNIC
        image:
          offer: CentOS
          publisher: OpenLogic
          sku: '7.5'
        version: latest
```

运行 playbook 后，您将在 Azure 上获得一个运行 CentOS 的机器！

# 摘要

在本章中，我们看到了如何在 AWS 云、DigitalOcean 和 Azure 中配置我们的机器。在 AWS 云的情况下，我们看到了两个不同的示例，一个非常简单，一个稍微复杂一些。

在下一章中，我们将讨论当 Ansible 发现问题时如何通知我们。


# 第八章：从 Ansible 获取通知

与 bash 脚本相比，Ansible 的一个重大优势之一是其幂等性，确保一切井然有序。这是一个非常好的功能，不仅向您保证服务器配置没有变化，而且新配置也将在短时间内生效。

因为这些原因，许多人每天运行他们的 `master.yaml` 文件一次。当您这样做时（也许您应该！），您希望 Ansible 本身向您发送某种反馈。还有许多其他情况，您可能希望 Ansible 向您或您的团队发送消息。例如，如果您使用 Ansible 部署您的应用程序，您可能希望向开发团队频道发送 IRC 消息（或其他类型的群聊消息），以便他们都了解系统的状态。

有时，你希望 Ansible 通知 Nagios 即将破坏某些东西，这样 Nagios 就不会担心，也不会开始向系统管理员发送电子邮件和消息。在本章中，我们将探讨多种方法，帮助您设置 Ansible Playbooks，既可以与您的监控系统配合工作，又可以最终发送通知。

在本章中，我们将探讨以下主题：

+   电子邮件通知

+   Ansible XMPP/Jabber

+   Slack 和 Rocket 聊天

+   向 IRC 频道发送消息（社区信息和贡献）

+   Amazon 简单通知服务

+   Nagios

# 技术要求

许多示例将需要第三方系统（用于发送消息），您可能正在使用或没有使用。如果您无法访问其中一个系统，则相关示例将无法执行。这并不是一个大问题，因为您仍然可以阅读该部分，并且许多通知模块非常相似。您可能会发现，适用于您环境的模块与另一个模块的功能非常相似。您可以参考 Ansible 通知模块的完整列表：[`docs.ansible.com/ansible/latest/modules/list_of_notification_modules.html`](https://docs.ansible.com/ansible/latest/modules/list_of_notification_modules.html)。

您可以从本书的 GitHub 存储库下载所有文件：[`github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter06`](https://github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter06)。

# 使用 Ansible 发送电子邮件

经常有用户需要及时通知有关 Ansible Playbook 执行的操作。这可能是因为这个用户知道这一点很重要，或者因为有一个自动化系统必须通知以便（不）启动某个过程。

提醒人们的最简单和最常见的方法是发送电子邮件。Ansible 允许您使用`mail`模块从您的 playbook 发送电子邮件。您可以在任何任务之间使用此模块，并在需要时通知用户。此外，在某些情况下，您无法自动化每一件事，因为要么您缺乏权限，要么需要进行一些手动检查和确认。如果是这种情况，您可以通知负责人员 Ansible 已经完成了其工作，现在是他们执行其职责的时候了。让我们使用名为`uptime_and_email.yaml`的非常简单的 playbook 来使用`mail`模块通知您的用户：

```
---
- hosts: localhost 
  connection: local
  tasks: 
    - name: Read the machine uptime 
      command: uptime -p 
      register: uptime 
    - name: Send the uptime via e-mail 
      mail: 
        host: mail.fale.io 
        username: ansible@fale.io 
        password: PASSWORD 
        to: me@fale.io 
        subject: Ansible-report 
        body: 'Local system uptime is {{ uptime.stdout }}.' 

```

前述 playbook 首先读取当前机器的正常运行时间，发出`uptime`命令，然后通过电子邮件发送到`me@fale.io`电子邮件地址。要发送电子邮件，我们显然需要一些额外信息，如 SMTP 主机、有效的 SMTP 凭据以及电子邮件的内容。这个例子非常简单，将使我们能够保持示例简短，但显然，你可以以非常类似的方式在非常长且复杂的 playbooks 中生成电子邮件。如果我们稍微专注于`mail`任务，我们可以看到我们正在使用以下数据：

+   要用于发送电子邮件的电子邮件服务器（还需登录信息，这是该服务器所必需的）

+   接收者电子邮件地址

+   电子邮件主题

+   电子邮件正文

`mail`模块支持的其他有趣参数如下：

+   `attach`参数：这用于向将生成的电子邮件添加附件。例如，当您希望通过电子邮件发送日志时，这非常有用。

+   `port`参数：这用于指定电子邮件服务器使用的端口。

有关此模块的有趣之处在于，唯一强制性字段是`subject`，而不是正文，许多人可能期望正文也是必需的。RFC 2822 不强制要求主题或正文的存在，因此即使没有它们，电子邮件仍然有效，但对于人来说，管理这种格式的电子邮件将非常困难。因此，Ansible 将始终发送带有主题和正文的电子邮件，如果正文为空，则会在主题和正文中都使用`subject`字符串。

我们现在可以继续执行脚本以验证其功能，使用以下命令：

```
    ansible-playbook -i localhost, uptime_and_email.yaml 
```

由于`uptime`的`-p`参数是特定于 Linux 的，可能无法在其他 POSIX 操作系统（如 macOS）上运行，因此此 playbook 可能在某些机器上无法正常工作。

通过运行上述 playbook，我们将得到类似以下的结果：

```
    PLAY [localhost] *************************************************

    TASK [setup] *****************************************************
    ok: [localhost]

    TASK [Read the machine uptime] ***********************************
    changed: [localhost]

    TASK [Send the uptime via email] ********************************
    changed: [localhost]

    PLAY RECAP *******************************************************
    localhost         : ok=3    changed=2    unreachable=0    failed=0

```

正如预期的那样，Ansible 已经向我发送了一封带有以下内容的电子邮件：

```
Local system uptime is up 38 min
```

该模块可以以许多不同的方式使用。我见过一个实际案例，那就是为了自动化一个非常复杂但顺序流程的一部分，涉及多个人员。每个人在流程的特定点必须开始他们的工作，而链中的下一个人在前一个人完成他们的工作之前不能开始他们的工作。保持该过程运作的关键在于每个人手动向链中的下一个人发送电子邮件，通知他们他们自己的部分已经完成，因此接收者需要开始他们在流程中的工作。在我们开始自动化该程序之前，人们通常手动进行电子邮件通知，但当我们开始自动化该程序的一部分时，没有人注意到该部分已经自动化。

对于这样的复杂、顺序流程，通过电子邮件进行跟踪并不是处理它们的最好方式，因为错误很容易犯，可能导致跟踪丢失。此外，此类复杂顺序流程往往非常缓慢，但它们在组织中被广泛使用，通常您无法进行更改。

有些情况下，流程需要以比电子邮件更实时的方式发送通知，因此 XMPP 是一个好的选择。

# XMPP

电子邮件速度慢，不可靠，并且人们通常不会立即对其做出反应。在某些情况下，您希望向您的用户发送实时消息。许多组织依赖 XMPP/Jabber 作为其内部聊天系统，而美妙的事情是 Ansible 能够直接向 XMPP/Jabber 用户和会议室发送消息。

让我们修改之前的示例，在 `uptime_and_xmpp_user.yaml` 文件中发送可靠性信息给某个用户：

```
---
- hosts: localhost 
  connection: local
  tasks: 
    - name: Read the machine uptime 
      command: 'uptime -p' 
      register: uptime 
    - name: Send the uptime to user 
      jabber: 
        user: ansible@fale.io 
        password: PASSWORD 
        to: me@fale.io 
        msg: 'Local system uptime is {{ uptime.stdout }}.' 
```

如果您想要使用 Ansible 的 `jabber` 任务，需要在执行该任务的系统上安装 `xmpppy` 库。其中一种安装方法是使用您的软件包管理器。例如，在 Fedora 上，您只需执行 `sudo dnf install -y python2-xmpp` 即可进行安装。您也可以使用 `pip install xmpppy` 进行安装。

第一个任务与前一节完全相同，而第二个任务则有一些细微的差别。正如您所看到的，`jabber` 模块非常类似于 `mail` 模块，并且需要类似的参数。在 XMPP 的情况下，我们不需要指定服务器主机和端口，因为 XMPP 会从 DNS 自动收集该信息。在需要使用不同服务器主机或端口的情况下，我们可以分别使用 `host` 和 `port` 参数。

现在，我们可以使用以下命令执行该脚本以验证其功能：

```
    ansible-playbook -i localhost, uptime_and_xmpp_user.yaml
```

我们将得到类似于以下的结果：

```
    PLAY [localhost] *************************************************

    TASK [setup] *****************************************************
    ok: [localhost]

    TASK [Read the machine uptime] ***********************************
    changed: [localhost]

    TASK [Send the uptime to user] ***********************************
    changed: [localhost]

    PLAY RECAP *******************************************************
    localhost         : ok=3    changed=2    unreachable=0    failed=0

```

对于我们想要发消息到会议室而不是单个用户的情况，只需要将接收者在 `to` 参数中更改为与会议室相应的接收者即可。

```
to: sysop@conference.fale.io (mailto:sysop@conference.fale.io)/ansiblebot
```

除了接收者更改和添加 `(mailto:sysop@conference.fale.io)/ansiblebot`（标识要使用的聊天句柄 `ansiblebot`，在本例中）之外，XMPP 对用户和会议室的处理方式是相同的，因此从一种切换到另一种非常容易。

尽管 XMPP 相当流行，但并非每家公司都使用它。另一个 Ansible 可以发送消息的协作平台是 Slack。

# Slack

在过去几年中，出现了许多新的聊天和协作平台。其中最常用的之一是 Slack。Slack 是一个基于云的团队协作工具，这使得与 XMPP 相比，与 Ansible 的集成更加容易。

让我们将以下行放入 `uptime_and_slack.yaml` 文件中：

```
---
- hosts: localhost 
  connection: local
  tasks: 
    - name: Read the machine uptime 
      command: 'uptime -p' 
      register: uptime 
    - name: Send the uptime to slack channel 
      slack: 
        token: TOKEN 
        channel: '#ansible' 
        msg: 'Local system uptime is {{ uptime.stdout }}.' 
```

正如我们讨论的那样，此模块的语法甚至比 XMPP 更简单。事实上，它只需要知道令牌（您可以在 Slack 网站上生成），要发送消息的频道以及消息本身。

自 Ansible 的 1.8 版本以来，需要新版本的 Slack 令牌，例如 `G522SJP14/D563DW213/7Qws484asdWD4w12Md3avf4FeD`。

使用以下命令运行 Playbook：

```
    ansible-playbook -i localhost, uptime_and_slack.yaml  
```

这导致以下输出：

```
    PLAY [localhost] *************************************************

    TASK [setup] *****************************************************
    ok: [localhost]

    TASK [Read the machine uptime] ***********************************
    changed: [localhost]

    TASK [Send the uptime to slack channel] **************************
    changed: [localhost]

    PLAY RECAP *******************************************************
    localhost         : ok=3    changed=2    unreachable=0    failed=0

```

由于 Slack 的目标是使通信更有效，它允许我们调整消息的多个方面。从我的角度来看，最有趣的几点是：

+   `color`：这允许您指定一个颜色条，放在消息开头以标识以下状态：

    +   Good: green bar

    +   Normal: no bar

    +   警告：黄色条

    +   Danger: red bar

+   `icon_url`：这允许您为该消息更改用户图像。

例如，以下代码将以警告颜色和自定义用户图像发送消息：

```
    - name: Send the uptime to slack channel 
      slack: 
        token: TOKEN 
        channel: '#ansible' 
        msg: 'Local system uptime is {{ uptime.stdout }}.' 
        color: warning
        icon_url: https://example.com/avatar.png
```

由于并非每家公司都愿意让 Slack 看到他们的私人对话，因此存在替代方案，例如 Rocket Chat。

# Rocket Chat

许多公司喜欢 Slack 的功能，但不想在使用 Slack 时失去本地服务所提供的隐私。**Rocket Chat** 是一个开源软件解决方案，实现了 Slack 的大多数功能以及其大部分界面。作为开源软件，每家公司都可以将其安装在本地，并以符合其 IT 规则的方式进行管理。

由于 Rocket Chat 的目标是成为 Slack 的即插即用替代方案，从我们的角度来看，几乎不需要做任何更改。事实上，我们可以创建 `uptime_and_rocket.yaml` 文件，其中包含以下内容：

```
---
- hosts: localhost 
  connection: local
  tasks: 
    - name: Read the machine uptime 
      command: 'uptime -p' 
      register: uptime 
    - name: Send the uptime to rocketchat channel 
      rocketchat: 
        token: TOKEN 
        domain: chat.example.com 
        channel: '#ansible' 
        msg: 'Local system uptime is {{ uptime.stdout }}.' 
```

如您所见，仅有第六和第七行发生了变化，其中 `slack` 一词已被替换为 `rocketchat`。此外，我们需要添加一个 `domain` 字段，指定我们的 Rocket Chat 安装位于何处。

使用以下命令运行代码：

```
    ansible-playbook -i localhost, uptime_and_rocketchat.yaml  
```

这导致以下输出：

```
    PLAY [localhost] *************************************************

    TASK [setup] *****************************************************
    ok: [localhost]

    TASK [Read the machine uptime] ***********************************
    changed: [localhost]

    TASK [Send the uptime to rocketchat channel] *********************
    changed: [localhost]

    PLAY RECAP *******************************************************
    localhost         : ok=3    changed=2    unreachable=0    failed=0

```

另一种自托管公司对话的方式是使用 IRC，这是一个非常古老但仍然常用的协议。Ansible 也能够使用它发送消息。

# Internet Relay Chat

**互联网中继聊天**（**IRC**）可能是 1990 年代最著名和广泛使用的聊天协议，至今仍在使用。它的受欢迎程度和持续使用主要是由于它在开源社区中的使用和其简单性。从 Ansible 的角度来看，IRC 是一个非常直接的模块，我们可以像以下示例一样使用它（放在 `uptime_and_irc.yaml` 文件中）：

```
---
- hosts: localhost 
  connection: local
  tasks: 
    - name: Read the machine uptime 
      command: 'uptime -p' 
      register: uptime 
    - name: Send the uptime to IRC channel 
      irc: 
        port: 6669 
        server: irc.example.net 
        channel: '#desired_channel'
        msg: 'Local system uptime is {{ uptime.stdout }}.' 
        color: green 
```

您需要安装 `socket` Python 库才能使用 Ansible IRC 模块。

在 IRC 模块中，需要以下字段：

+   `channel`：指定消息将要传送到的频道。

+   `msg`：这是您要发送的消息。

通常您需要指定的其他配置包括：

+   `server`：选择要连接的`服务器`，如果不是`localhost`。

+   `port`：选择连接的`端口`，如果不是`6667`。

+   `color`：指定消息`颜色`，如果不是`黑色`。

+   `nick`：指定发送消息的`昵称`，如果不是`ansible`。

+   `use_ssl`：使用 SSL 和 TLS 安全性。

+   `style`：如果要以粗体、斜体、下划线或反向样式发送消息，则使用此选项。

使用以下命令运行代码：

```
    ansible-playbook uptime_and_irc.yaml  
```

这将产生以下输出：

```
    PLAY [localhost] *************************************************

    TASK [setup] *****************************************************
    ok: [localhost]

    TASK [Read the machine uptime] ***********************************
    changed: [localhost]

    TASK [Send the uptime to IRC channel] ****************************
    changed: [localhost]

    PLAY RECAP *******************************************************
    localhost         : ok=3    changed=2    unreachable=0    failed=0

```

我们已经看到许多不同的通信系统可能在您的公司或项目中使用，但这些通常用于人与人或机器与人的通信。机器对机器的通信通常使用不同的系统，例如亚马逊 SNS。

# 亚马逊简单通知服务

有时，您希望您的 Playbook 在接收警报的方式上是不可知的。这具有多个优点，主要是灵活性。事实上，在这种模型中，Ansible 将消息交付给一个通知服务，然后通知服务将负责交付消息。**亚马逊简单通知服务**（**SNS**）并不是唯一可用的通知服务，但它可能是最常用的。SNS 有以下组件：

+   **消息**：由 UUID 识别的发布者生成的消息

+   **发布者**：生成消息的程序

+   **主题**：命名的消息组，可以类比于聊天频道或房间

+   **订阅者**：订阅了他们感兴趣主题的所有消息的客户端

因此，在我们的情况下，具体如下：

+   **消息**：Ansible 通知

+   **发布者**：Ansible 本身

+   **主题**：根据系统和/或通知类型（例如存储、网络或计算）对消息进行分组的可能不同主题

+   **订阅者**：您团队中必须得到通知的人员

正如我们所说，SNS 的一个重大优势是，您可以将 Ansible 发送消息的方式（即 SNS API）与用户接收消息的方式分离开来。事实上，您将能够为每个用户和每个主题规则选择不同的传送系统，并最终可以动态更改它们，以确保消息以最佳方式发送到任何情况中。目前，SNS 可以发送消息的五种方式如下：

+   Amazon **Lambda** 函数（用 Python、Java 和 JavaScript 编写的无服务器函数）

+   Amazon **Simple Queue Service**（**SQS**）（一种消息队列系统）

+   电子邮件

+   HTTP(S) 调用

+   短信

让我们看看如何使用 Ansible 发送 SNS 消息。为此，我们可以创建一个名为 `uptime_and_sns.yaml` 的文件，其中包含以下内容：

```
---
- hosts: localhost 
  connection: local
  tasks: 
    - name: Read the machine uptime 
      command: 'uptime -p' 
      register: uptime 
    - name: Send the uptime to SNS 
      sns: 
        msg: 'Local system uptime is {{ uptime.stdout }}.' 
        subject: "System uptime" 
        topic: "uptime"
```

在此示例中，我们使用 `msg` 键来设置将要发送的消息，`topic` 选择最合适的主题，并且 `subject` 将用作电子邮件投递的主题。您可以设置许多其他选项。主要用于使用不同的传送方式发送不同的消息。

例如，通过短信发送短消息（最后，**SMS** 中的第一个 **S** 意味着 **短**），通过电子邮件发送更长且更详细的消息是有意义的。为此，SNS 模块为我们提供了以下针对传送的特定选项

+   `email`

+   `http`

+   `https`

+   `sms`

+   `sqs`

正如我们在前一章中所看到的，AWS 模块需要凭据，我们可以以多种方式设置它们。运行此模块所需的三个 AWS 特定参数是：

+   `aws_access_key`：这是 AWS 访问密钥；如果未指定，则将考虑环境变量 `aws_access_key` 或 `~/.aws/credentials` 的内容。

+   `aws_secret_key`：这是 AWS 秘密密钥；如果未指定，则将考虑环境变量 `aws_secret_key` 或 `~/.aws/credentials` 的内容。

+   `region`：这是要使用的 AWS 区域；如果未指定，则将考虑环境变量 `ec2_region` 或 `~/.aws/config` 的内容。

使用以下命令运行代码：

```
    ansible-playbook uptime_and_sns.yaml  
```

这将导致以下输出：

```
PLAY [localhost] ************************************************* 

TASK [setup] ***************************************************** 
ok: [localhost] 

TASK [Read the machine uptime] *********************************** 
changed: [localhost] 

TASK [Send the uptime to SNS] ************************************ 
changed: [localhost] 

PLAY RECAP ******************************************************* 
localhost         : ok=3    changed=2    unreachable=0    failed=0 
```

有时我们希望通知监控系统，以便它不会由于 Ansible 操作而触发任何警报。这种系统的常见示例是 Nagios。

# Nagios

**Nagios**是用于监控服务和服务器状态的最常用工具之一。Nagios 能够定期审计服务器和服务的状态，并在出现问题时通知用户。如果您的环境中有 Nagios，那么在管理机器时必须非常小心，因为在 Nagios 发现服务器或服务处于不健康状态时，它会开始发送电子邮件和短信并向您的团队打电话。当您对由 Nagios 控制的节点运行 Ansible 脚本时，您必须更加小心，因为您会面临在夜间或其他不适当时间触发电子邮件、短信消息和电话的风险。为了避免这种情况，Ansible 能够事先通知 Nagios，以便在那个时间窗口内 Nagios 不会发送通知，即使一些服务处于下线状态（例如，因为它们正在重新启动）或其他检查失败。

在这个例子中，我们将会停止一个服务，等待五分钟，然后再次启动它，因为这实际上会导致在大多数配置中出现 Nagios 故障。事实上，通常情况下，Nagios 被配置为接受最多两次连续的测试失败（通常每分钟执行一次测试），在提升为关键状态之前将服务置于警告状态。我们将创建名为`long_restart_service.yaml`的文件，这将触发 Nagios 关键状态：

```
---
- hosts: ws01.fale.io 
  tasks: 
    - name: Stop the HTTPd service 
      service: 
        name: httpd 
        state: stopped 
    - name: Wait for 5 minutes 
      pause: 
        minutes: 5 
    - name: Start the HTTPd service 
      service: 
        name: httpd 
        state: stopped 
```

运行以下命令来执行代码：

```
ansible-playbook long_restart_service.yaml
```

这应该会触发 Nagios 警报，并导致以下输出：

```
PLAY [ws01.fale.io] ********************************************** 

TASK [setup] ***************************************************** 
ok: [ws01.fale.io] 

TASK [Stop the HTTpd service] ************************************ 
changed: [ws01.fale.io] 

TASK [Wait for 5 minutes] **************************************** 
changed: [ws01.fale.io] 

TASK [Start the HTTpd service] *********************************** 
changed: [ws01.fale.io] 

PLAY RECAP ******************************************************* 
ws01.fale.io      : ok=4    changed=3    unreachable=0    failed=0 
```

如果没有触发 Nagios 警报，那么可能是因为您的 Nagios 安装没有跟踪该服务，或者五分钟不足以使其提升为关键状态。要检查，请联系管理您 Nagios 安装的人员或团队，因为 Nagios 允许完全配置到一个非常难以预测 Nagios 行为的地步，而不知道其配置是很难的。

现在我们可以创建一个非常相似的 playbook，以确保 Nagios 不会发送任何警报。我们将创建一个名为`long_restart_service_no_alert.yaml`的文件，其内容如下（完整代码可在 GitHub 上找到）：

```
---
- hosts: ws01.fale.io 
  tasks: 
    - name: Mute Nagios 
      nagios: 
        action: disable_alerts 
        service: httpd 
        host: '{{ inventory_hostname }}' 
      delegate_to: nagios.fale.io 
    - name: Stop the HTTPd service 
      service: 
        name: httpd 
        state: stopped 
   ...
```

正如你所见，我们添加了两个任务。第一个任务是告诉 Nagios 不要发送有关给定主机上 HTTPd 服务的警报，第二个任务是告诉 Nagios 再次开始发送有关该服务的警报。即使您没有指定服务，因此静音了该主机上的所有警报，我的建议是仅禁用您将要中断的警报，以便 Nagios 仍然能够在大多数基础架构上正常工作。

如果 playbook 运行在恢复警报之前失败，你的警报将保持*禁用*状态。

该模块的目标是切换 Nagios 警报以及安排停机时间，从 Ansible 2.2 开始，该模块还可以取消安排的停机时间。

使用以下命令来运行代码：

```
    ansible-playbook long_restart_service_no_alert.yaml  
```

这将触发 Nagios 警报，并导致以下输出（完整的代码输出可在 GitHub 上获得）：

```
    PLAY [ws01.fale.io] **********************************************

    TASK [setup] *****************************************************
    ok: [ws01.fale.io]

    TASK [Mute Nagios] ***********************************************
    changed: [nagios.fale.io]

    TASK [Stop the HTTpd service] ************************************
    changed: [ws01.fale.io]

  ...
```

要使用 Nagios 模块，您需要使用 `delegate_to` 参数将操作委托给 Nagios 服务器，如示例所示。

有时，与 Nagios 集成要实现的目标完全相反。事实上，你并不想把它静音，而是想让 Nagios 处理你的测试结果。一个常见的情况是，如果您想利用您的 Nagios 配置通知您的管理员一个任务的输出。为此，我们可以使用 Nagios 的 `nsca` 工具，将其集成到我们的 playbook 中。Ansible 还没有一个管理它的特定模块，但您可以使用命令模块来运行它，利用 `send_nsca` CLI 程序。

# 总结

在本章中，我们已经学习了如何让 Ansible 发送通知到其他系统和人员。您学会了通过电子邮件和消息服务（如 Slack）发送通知的方法。最后，你学会了如何在你运行 Nagios 时防止它发送关于系统健康状况的不必要通知。

在下一章中，我们将学习如何创建一个模块，以便您可以扩展 Ansible 来执行任何类型的任务。
