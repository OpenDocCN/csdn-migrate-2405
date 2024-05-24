# Ansible 剧本基础知识（一）

> 原文：[`zh.annas-archive.org/md5/F3D5D082C2C7CD8C77793DEE22B4CF30`](https://zh.annas-archive.org/md5/F3D5D082C2C7CD8C77793DEE22B4CF30AZXRT4567YJU8KI-9LO-0P0[-])
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

随着云计算、敏捷开发方法学的演进和近年来数据的爆炸性增长，管理大规模基础设施的需求日益增长。DevOps 工具和实践已经成为自动化此类可扩展、动态和复杂基础设施的每个阶段的必要条件。配置管理工具是这种 DevOps 工具集的核心。

Ansible 是一个简单、高效、快速的配置管理、编排和应用部署工具，集所有功能于一身。本书将帮助您熟悉编写 Playbooks，即 Ansible 的自动化语言。本书采用实践方法向您展示如何创建灵活、动态、可重用和数据驱动的角色。然后，它将带您了解 Ansible 的高级功能，如节点发现、集群化、使用保险库保护数据以及管理环境，最后向您展示如何使用 Ansible 来编排多层次基础架构堆栈。

# 本书内容概述

第一章，*为基础设施绘制蓝图*，将向您介绍 Playbooks、YAML 等内容。您还将了解 Playbook 的组成部分。

第二章, *使用 Ansible 角色进行模块化*，将演示如何使用 Ansible 角色创建可重用的模块化自动化代码，这些角色是自动化的单位。

第三章, *分离代码和数据 – 变量、事实和模板*，涵盖了使用模板和变量创建灵活、可定制、数据驱动的角色。您还将学习自动发现变量，即事实。

第四章，*引入您的代码 – 自定义命令和脚本*，涵盖了如何引入您现有的脚本，并使用 Ansible 调用 Shell 命令。

第五章，*控制执行流程 – 条件语句*，讨论了 Ansible 提供的控制结构，以改变执行方向。

第六章，*迭代控制结构 – 循环*，演示了如何使用强大的 with 语句来遍历数组、哈希等内容。

第七章，*节点发现和集群化*，讨论了拓扑信息的发现，并使用魔术变量和事实缓存创建动态配置。

第八章，*使用 Vault 加密数据*，讨论了使用 Ansible-vault 在版本控制系统中存储和共享的安全变量。

第九章，“管理环境”，涵盖了使用 Ansible 创建和管理隔离环境以及将自动化代码映射到软件开发工作流程中。

第十章，“使用 Ansible 编排基础设施”，涵盖了 Ansible 的编排功能，如滚动更新、预任务和后任务、标签、在 playbook 中构建测试等。

# 阅读本书所需材料

本书假设您已经安装了 Ansible，并且对 Linux/Unix 环境和系统操作有很好的了解，并且熟悉使用命令行接口。

# 本书的目标读者

本书的目标读者是系统或自动化工程师，具有数年管理基础设施各个部分经验，包括操作系统、应用配置和部署。本书也针对任何打算以最短的学习曲线有效自动化管理系统和应用配置的人群。

假设读者对 Ansible 有概念性的了解，已经安装过，并熟悉基本操作，比如创建清单文件和使用 Ansible 运行临时命令。

# 约定

在本书中，您会发现一些不同类型信息的文本样式。以下是这些样式的一些示例，以及其含义的解释。

文本中的代码单词显示如下：“我们可以通过使用`include`指令来包含其他上下文。”

代码块设置如下：

```
---
# site.yml : This is a sitewide playbook
- include: www.yml
```

任何命令行输入或输出会写成如下形式：

```
$ ansible-playbook simple_playbook.yml -i customhosts

```

**新术语**和**重要词汇**都显示为加粗。例如，屏幕上看到的文本、菜单或对话框中的单词会像这样出现在文本中：“结果变量哈希应包含**defaults**中的项目以及**vars**中的覆盖值”。

### 注意

警告或重要提示会显示为这样的框。

### 小贴士

贴士和技巧将以这种方式出现。

# 读者反馈

我们非常欢迎读者的反馈。请告诉我们您对本书的看法——您喜欢或不喜欢的地方。读者的反馈对我们开发您能够充分利用的标题非常重要。

要给我们发送一般性反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在标题中提及书名。

如果您对某个专题非常了解，并且有兴趣写作或为书籍做出贡献，请查看我们的作者指南，网址为[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 书籍的骄傲拥有者，我们有一些事项可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)购买的所有 Packt 图书中下载示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接将文件通过电子邮件发送给您。

## 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误还是会发生。如果您在我们的任何一本书中发现错误——可能是文字或代码方面的错误——我们将不胜感激地接受您的报告。通过这样做，您可以帮助其他读者避免困惑，并帮助我们改进后续版本的本书。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**勘误提交表单**链接，然后输入您的勘误详细信息。一旦您的勘误被验证，您的提交将被接受，并且勘误将被上传到我们的网站上，或者被添加到该书籍的任何现有勘误列表中，位于该标题的勘误部分下面。您可以通过从[`www.packtpub.com/support`](http://www.packtpub.com/support)选择您的书籍来查看任何现有的勘误。

## 盗版

互联网上的版权盗版是各种媒体上持续存在的问题。在 Packt，我们非常重视我们的版权和许可的保护。如果您在互联网上发现我们任何形式的作品的非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过链接<copyright@packtpub.com>与我们联系，报告涉嫌盗版材料。

我们感谢您帮助保护我们的作者，以及我们为您提供有价值内容的能力。

## 问题

如果您在阅读本书的任何方面遇到问题，请通过链接<questions@packtpub.com>与我们联系，我们将尽力解决。


# 第一章：设置学习环境

要最有效地使用本书并检查、运行和编写本书提供的练习中的代码，建立学习环境至关重要。虽然 Ansible 可以与任何类型的节点、虚拟机、云服务器或已安装操作系统和运行 SSH 服务的裸机主机一起使用，但首选模式是使用虚拟机。

在本次会话中，我们将涵盖以下主题：

+   理解学习环境

+   理解先决条件

+   安装和配置虚拟盒和 vagrant

+   创建虚拟机

+   安装 Ansible

+   使用示例代码

# 理解学习环境

我们假设大多数学习者都希望在本地设置环境，因此建议使用开源和免费的软件 VirtualBox 和 Vagrant，它们支持大多数桌面操作系统，包括 Windows、OSX 和 Linux。

理想的设置包括五台虚拟机，其目的解释如下。您还可以合并一些服务，例如，负载均衡器和 Web 服务器可以是同一主机：

+   **控制器**：这是唯一需要安装 Ansible 并充当控制器的主机。这用于从控制器启动`ansible-playbook`命令。

+   **数据库（Ubuntu）**：此主机配置有 Ansible 以运行 MySQL 数据库服务，并运行 Linux 的 Ubuntu 发行版。

+   **数据库（CentOS）**：此主机配置有 Ansible 以运行 MySQL 数据库服务，但它运行的是 Linux 的 CentOS 发行版。这是为了在为 Ansible 编写 MySQL 角色时测试多平台支持而添加的。

+   **Web 服务器**：此主机配置有 Ansible 以运行 Apache Web 服务器应用程序。

+   **负载均衡器**：此主机配置有 haproxy 应用程序，这是一个开源的 HTTP 代理服务。此主机充当负载均衡器，接受 HTTP 请求并将负载分布到可用的 Web 服务器上。

## 先决条件

有关先决条件、软件和硬件要求以及设置说明的最新说明，请参阅以下 GitHub 存储库：

[`github.com/schoolofdevops/ansible-playbook-essentials`](https://github.com/schoolofdevops/ansible-playbook-essentials)。

### 系统先决条件

适度配置的台式机或笔记本系统应该足以设置学习环境。以下是在软件和硬件上下文中推荐的先决条件：

| **处理器** | 2 个核心 |
| --- | --- |
| **内存** | 2.5 GB 可用内存 |
| **磁盘空间** | 20 GB 的可用空间 |
| **操作系统** | Windows，OS X（Mac），Linux |

## 基本软件

为了设置学习环境，我们建议使用以下软件：

+   **VirtualBox**：Oracle 的 virtualbox 是一种桌面虚拟化软件，可免费使用。它适用于各种操作系统，包括 Windows、OS X、Linux、FreeBSD、Solaris 等。它提供了一个 hypervisor 层，并允许在现有基础 OS 的顶部创建和运行虚拟机。本书提供的代码已经在 virtualbox 的 4.3x 版本上进行了测试。但是，任何与 vagrant 版本兼容的 virtualbox 版本都可以使用。

+   **Vagrant**：这是一个工具，允许用户轻松在大多数虚拟化程序和云平台上创建和共享虚拟环境，包括但不限于 virtualbox。它可以自动化任务，如导入镜像、指定资源（分配给 VM 的内存和 CPU 等）以及设置网络接口、主机名、用户凭据等。由于它提供了一个 Vagrant 文件形式的文本配置，虚拟机可以通过编程方式进行配置，使其易于与其他工具（如 **Jenkins**）一起使用，以自动化构建和测试流水线。

+   **Git for Windows**：尽管我们不打算使用 Git，它是一种版本控制软件，但我们使用此软件在 Windows 系统上安装 SSH 实用程序。Vagrant 需要在路径中可用的 SSH 二进制文件。Windows 未打包 SSH 实用程序，而 Git for Windows 是在 Windows 上安装它的最简单方法。还存在其他选择，如 **Cygwin**。

以下表格列出了用于开发提供的代码的软件版本 OS，附有下载链接：

| 软件 | 版本 | 下载链接 |
| --- | --- | --- |
| VirtualBox | 4.3.30 | [虚拟箱](https://www.virtualbox.org/wiki/Downloads) |
| Vagrant | 1.7.3 | [`www.vagrantup.com/downloads.html`](https://www.vagrantup.com/downloads.html) |
| Git for Windows | 1.9.5 | [`git-scm.com/download/win`](https://git-scm.com/download/win) |

建议学习者在继续之前下载、安装并参考相应的文档页面以熟悉这些工具。

## 创建虚拟机

安装基础软件后，您可以使用 Vagrant 来启动所需的虚拟机。Vagrant 使用一个名为 `Vagrantfile` 的规范文件，示例如下：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :
# Sample Vagranfile to setup Learning Environment
# for Ansible Playbook Essentials

VAGRANTFILE_API_VERSION = "2"
Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "ansible-ubuntu-1204-i386"
  config.vm.box_url = "https://cloud-images.ubuntu.com/vagrant/precise/current/precise-server-cloudimg-i386-vagrant-disk1.box"
  config.vm.define "control" do |control|
    control.vm.network :private_network, ip: "192.168.61.10"
  end
  config.vm.define "db" do |db|
    db.vm.network :private_network, ip: "192.168.61.11"
  end
  config.vm.define "dbel" do |db|
    db.vm.network :private_network, ip: "192.168.61.14"
    db.vm.box = "opscode_centos-6.5-i386"
    db.vm.box = "http://opscode-vm-bento.s3.amazonaws.com/vagrant/virtualbox/opscode_centos-6.5_chef-provisionerless.box"
  end
  config.vm.define "www" do |www|
    www.vm.network :private_network, ip: "192.168.61.12"
  end
  config.vm.define "lb" do |lb|
    lb.vm.network :private_network, ip: "192.168.61.13"
  end
end
```

先前的 Vagrant 文件包含了设置五个虚拟机的规范，如本章开头所述，它们是 `control`、`db`、`dbel`、`www` 和 `lb`。

建议学习者使用以下说明创建和启动所需的虚拟机以设置学习环境：

1.  在系统的任何位置为学习环境设置创建一个目录结构，例如 `learn/ansible`。

1.  将先前提供的 `Vagrantfile` 文件复制到 `learn/ansible` 目录。现在目录树应如下所示：

    ```
                         learn
                            \_ ansible
                                  \_ Vagrantfile
    ```

    ### 注意

    `Vagrantfile` 文件包含了前一部分描述的虚拟机的规格。

1.  打开终端并进入 `learn/ansible` 目录。

1.  启动控制节点并登录到它，步骤如下：

    ```
    $ vagrant up control 
    $ vagrant ssh control

    ```

1.  从单独的终端窗口，在 `learn/ansible` 目录下，逐个启动剩余的虚拟机，步骤如下：

    ```
    $ vagrant up db
    $ vagrant up www
    $ vagrant up lb
    optionally (for centos based mysql configurations)
    $ vagrant up dbel 
    Optionally, to login to to the virtual machines as
    $ vagrant ssh db
    $ vagrant ssh www
    $ vagrant ssh lb
    optionally (for centos based mysql configurations)
    $ vagrant ssh dbel 

    ```

## 安装 Ansible 到控制节点

一旦虚拟机创建并启动，需要在控制节点上安装 Ansible。由于 Ansible 是无代理的，使用 SSH 传输来管理节点，因此在节点上除了确保 SSH 服务正在运行外，不需要进行额外的设置。要在控制节点上安装 Ansible，请参考以下步骤。这些说明特定适用于 Linux 的 Ubuntu 发行版，因为这是我们在控制节点上使用的操作系统。有关通用的安装说明，请参考以下页面：

[`docs.ansible.com/intro_installation.html`](http://docs.ansible.com/intro_installation.html).

步骤如下：

1.  使用以下命令登录到控制节点：

    ```
    # from inside learn/ansible directory 
    $ vagrant ssh control 

    ```

1.  使用以下命令更新仓库缓存：

    ```
    $ sudo apt-get update

    ```

1.  安装先决软件和仓库：

    ```
    # On Ubuntu 14.04 and above 
    $ sudo apt-get install -y software-properties-common
    $ sudo apt-get install -y python-software-properties
    $ sudo apt-add-repository ppa:ansible/ansible

    ```

1.  添加新仓库后，请更新仓库缓存，步骤如下：

    ```
    $ sudo apt-get update 

    ```

1.  使用以下命令安装 Ansible：

    ```
    $ sudo apt-get install -y ansible 

    ```

1.  使用以下命令验证 Ansible：

    ```
    $ ansible --version
    [sample output]
    vagrant@vagrant:~$ ansible --version
    ansible 1.9.2
     configured module search path = None

    ```

## 使用示例代码

本书提供的示例代码按章节号进行划分。以章节号命名的目录包含代码在相应章节结束时的快照。建议学习者独立创建自己的代码，并将示例代码用作参考。此外，如果读者跳过一个或多个章节，他们可以将前一章节的示例代码用作基础。

例如，在使用 Chapter 6 *迭代控制结构 - 循环* 时，您可以将 Chapter 5 *控制执行流程 - 条件* 的示例代码用作基础。

### 提示

**下载示例代码**

您可以从您在 [`www.packtpub.com`](http://www.packtpub.com) 购买的所有 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了本书，您可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 并注册以直接通过电子邮件接收文件。


# 第二章：蓝图化您的基础设施

这本书是为那些对 Ansible 有概念性知识并想开始编写 Ansible playbook 自动化常见基础设施任务、编排应用部署和/或管理多个环境配置的人而设计的入门指南。本书采用渐进式方法，从基础知识开始，比如学习 playbook 的解剖学和编写简单角色以创建模块化代码。一旦熟悉了基础知识，您将被介绍如何使用变量和模板添加动态数据，并使用条件和迭代器控制执行流程等基本概念。然后是更高级的主题，比如节点发现、集群化、数据加密和环境管理。最后我们将讨论 Ansible 的编排特性。让我们通过学习 playbooks 来开始成为 Ansible 实践者的旅程吧。

在本章中，我们将学习：

+   Playbook 的解剖学

+   什么是 plays 以及如何编写主机清单和搜索模式

+   Ansible 模块和“电池内置”方法

# 熟悉 Ansible

**Ansible** 是一个简单、灵活且非常强大的工具，它能够帮助您自动化常见的基础设施任务、运行临时命令并部署跨多台机器的多层应用程序。虽然您可以使用 Ansible 同时在多个主机上启动命令，但其真正的力量在于使用 playbooks 管理这些主机。

作为系统工程师，我们通常需要自动化的基础设施包含复杂的多层应用程序。其中每个代表一类服务器，例如负载均衡器、Web 服务器、数据库服务器、缓存应用程序和中间件队列。由于这些应用程序中的许多必须一起工作才能提供服务，所以还涉及拓扑。例如，负载均衡器会连接到 Web 服务器，后者会读写数据库并连接到缓存服务器以获取内存中的对象。大多数情况下，当我们启动这样的应用程序堆栈时，我们需要按照非常具体的顺序配置这些组件。

这里是一个非常常见的三层 Web 应用程序示例，其中包括一个负载均衡器、一个 Web 服务器和一个数据库后端：

![熟悉 Ansible](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_01_01.jpg)

Ansible 允许您将此图表转换为蓝图，定义您的基础设施策略。用于指定此类策略的格式就是 playbook。

示例策略及其应用顺序如下步骤所示：

1.  在数据库服务器上安装、配置和启动 MySQL 服务。

1.  安装和配置运行 **Nginx** 和 **PHP** 绑定的 Web 服务器。

1.  在 Web 服务器上部署 Wordpress 应用程序，并向 Nginx 添加相应的配置。

1.  在部署 Wordpress 后在所有 Web 服务器上启动 Nginx 服务。最后，在负载均衡器主机上安装、配置和启动**haproxy**服务。更新 haproxy 配置以包含之前创建的所有 Web 服务器的主机名。

以下是一个示例 Playbook，将基础设施蓝图转换为 Ansible 可执行的策略：

![介绍 Ansible](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_01_02.jpg)

# Plays

一个 Playbook 包含一个或多个 Play，将主机组映射到明确定义的任务。上述示例包含三个 Play，每个 Play 用于配置多层 Web 应用程序中的一个层。Play 也定义了任务配置的顺序。这使我们能够编排多层部署。例如，仅在启动 Web 服务器后配置负载均衡器，或执行两阶段部署，其中第一阶段仅添加这些配置，第二阶段按预期顺序启动服务。

## YAML – Playbook 语言

正如你可能已经注意到的，我们之前编写的 Playbook 更像是一个文本配置，而不是一个代码片段。这是因为 Ansible 的创建者选择使用简单、易读且熟悉的 YAML 格式来蓝图基础设施。这增加了 Ansible 的吸引力，因为这个工具的用户无需学习任何特殊的编程语言即可开始使用。Ansible 代码是自解释且自描述的。对 YAML 的快速入门就足以理解基本语法。以下是您需要了解的有关 YAML 的内容，以便开始您的第一个 Playbook：

+   Playbook 的第一行应以 "--- "（三个连字符）开头，表示 YAML 文档的开始。

+   在 YAML 中，列表以一个连字符和一个空格表示。Playbook 包含一系列 Play；它们用 "- " 表示。每个 Play 都是一个关联数组、字典或映射，具有键值对。

+   缩进很重要。列表的所有成员应位于相同的缩进级别。

+   每个 Play 都可以包含用 ":" 分隔的键值对，以表示主机、变量、角色、任务等。

# 我们的第一个 Playbook

配备了前面解释的基本规则，并假设读者已经对 YAML 基础知识有所了解，我们现在将开始编写我们的第一个 Playbook。我们的问题陈述如下：

1.  在所有主机上创建一个 devops 用户。该用户应该是 `devops` 组的一部分。

1.  安装 "htop" 实用程序。**Htop**是 top 的改进版本——一个交互式系统进程监视器。

1.  将 Nginx 仓库添加到 Web 服务器，并将其作为服务启动。

现在，我们将创建我们的第一个 Playbook 并将其保存为 `simple_playbook.yml`，其中包含以下代码：

```
---
- hosts: all
  remote_user: vagrant
  sudo: yes
  tasks:

  - group:
      name: devops
      state: present
  - name: create devops user with admin privileges

    user:
      name: devops
      comment: "Devops User"
      uid: 2001
      group: devops
  - name: install htop package
    action: apt name=htop state=present update_cache=yes

- hosts: www
  user: vagrant
  sudo: yes
  tasks:
  - name: add official nginx repository
    apt_repository:
      repo: 'deb http://nginx.org/packages/ubuntu/ lucid nginx'
  - name: install nginx web server and ensure its at the latest version
    apt:
      name: nginx
      state: latest
  - name: start nginx service
    service:
      name: nginx
      state: started
```

我们的 Playbook 包含两个 Play。每个 Play 包含以下两个重要部分：

+   **要配置什么**：我们需要配置一个主机或一组主机来运行剧本。此外，我们需要包含有用的连接信息，例如要连接为哪个用户，是否使用`sudo`命令等。

+   **要运行什么**：这包括要运行的任务的规范，包括要修改的系统组件以及它们应该处于的状态，例如，安装、启动或最新状态。这可以用任务来表示，稍后可以通过角色来表示。

现在让我们简要介绍一下每个。

## 创建主机清单

即使在我们开始使用 Ansible 编写剧本之前，我们也需要定义一个所有需要配置的主机的清单，并使其可供 Ansible 使用。稍后，我们将开始对此清单中的一些主机运行剧本。如果您有现有的清单，例如 cobbler、LDAP、CMDB 软件或希望从云提供商（如 ec2）那里拉取清单，则可以使用动态清单的概念从 Ansible 那里拉取。

对于基于文本的本地清单，默认位置是`/etc/ansible/hosts`。然而，对于我们的学习环境，我们将在工作目录中创建一个自定义清单文件`customhosts`，其内容如下所示。您可以自由创建自己的清单文件：

```
#customhosts
#inventory configs for my cluster
[db]
192.168.61.11  ansible_ssh_user=vagrant

[www]
www-01.example.com ansible_ssh_user=ubuntu
www-02 ansible_ssh_user=ubuntu

[lb]
lb0.example.com
```

现在，当我们的剧本将一场戏映射到该组时，`www`（`hosts:` `www`），该组中的主机将被配置。 `all`关键字将匹配清单中的所有主机。

以下是创建清单文件的指南：

+   清单文件遵循 INI 风格的配置，基本上包含以包含在“`[ ]`”中的主机组/类名开头的配置块。这允许选择性地在系统类别上执行操作，例如，`[namenodes]`。

+   单个主机可以是多个组的一部分。在这种情况下，来自两个组的主机变量将被合并，并且优先规则适用。稍后我们将详细讨论变量和优先级。

+   每个组包含主机列表和连接详细信息，例如要连接的 SSH 用户、如果不是默认值的 SSH 端口号、SSH 凭据/密钥、sudo 凭据等。主机名还可以包含通配符、范围等，以便轻松地包含相同类型的多个主机，这些主机遵循一些命名模式。

### 提示

创建主机清单后，最好使用 Ansible 的 ping 模块进行连接性验证（例如，`ansible -m ping all`）。

## 模式

在上一个剧本中，以下行决定了选择哪些主机来运行特定的剧本：

```
- hosts: all
- hosts: www
```

第一行代码将匹配所有主机，而第二行代码将匹配属于`www`组的主机。

模式可以是以下任何一个或它们的组合：

| 模式类型 | 示例 |
| --- | --- |
| 组名 | `namenodes` |
| 匹配全部 | `all`或`*` |
| 范围 | `namenode[0:100]` |
| 主机名/主机名模式 | `*.example.com`，`host01.example.com` |
| 排除 | `namenodes:!secondaynamenodes` |
| 交集 | `namenodes:&zookeeper` |
| 正则表达式 | `~(nn&#124;zk).*\.example\.org` |

## 任务

Plays 将主机映射到任务。任务是针对与播放中指定的模式匹配的一组主机执行的操作序列。每个播放通常包含在匹配模式的每台机器上串行运行的多个任务。例如，看下面的代码片段：

```
- group:
 name:devops
 state: present
- name: create devops user with admin privileges
 user:
 name: devops
 comment: "Devops User"
 uid: 2001
 group: devops

```

在上述示例中，我们有两个任务。第一个是创建一个组，第二个是创建一个用户并将其添加到之前创建的组中。如果你注意到，第二个任务中有一行额外的内容，以 `name:` 开头。在编写任务时，最好提供一个名称，描述这个任务将实现什么。如果没有，将打印动作字符串。

任务列表中的每个操作都可以通过指定以下内容来声明：

+   模块的名称

+   可选地，管理的系统组件的状态

+   可选参数

### 提示

使用更新的 Ansible 版本（从 0.8 开始），现在写入一个动作关键字是可选的。我们可以直接提供模块的名称。因此，这两行将具有相似的动作，即。使用 `apt` 模块安装软件包：

```
action: apt name=htop state=present update_cache=yes
apt: name=nginx state=latest

```

Ansible 以其一体化的方法脱颖而出，与其他配置管理工具不同。这些“电池”即为“模块”。在继续之前了解模块的含义是很重要的。

### 模块

模块是负责在特定平台上管理特定系统组件的封装程序。

考虑以下示例：

+   `apt` 模块用于 Debian，而 `yum` 模块用于 RedHat，有助于管理系统包

+   `user` 模块负责在系统上添加、删除或修改用户

+   `service` 模块将启动/停止系统服务

模块将实际的实现与用户抽象出来。它们公开了一个声明性语法，接受一系列参数和要管理的系统组件的状态。所有这些都可以使用人类可读的 YAML 语法，使用键-值对来声明。

在功能上，对于熟悉 Chef/Puppet 软件的人来说，模块类似于提供程序。与编写创建用户的流程不同，使用 Ansible，我们声明我们的组件应处于哪种状态，即应创建哪个用户，其状态及其特征，如 UID、组、shell 等。实际的过程是通过模块隐含地为 Ansible 所知，并在后台执行。

### 提示

`Command` 和 `Shell` 模块是特殊的模块。它们既不接受键-值对作为参数，也不是幂等的。

Ansible 预先安装了一系列模块库，从管理基本系统资源的模块到发送通知、执行云集成等更复杂的模块。如果您想要在远程 PostgreSQL 服务器上配置 ec2 实例、创建数据库，并在 **IRC** 上接收通知，那么 Ansible 就有一个模块可供使用。这难道不是令人惊讶的吗？

无需担心找外部插件，或者努力与云提供商集成等。要查看可用模块的列表，您可以参考 Ansible 文档中的 [`docs.ansible.com/list_of_all_modules.html`](http://docs.ansible.com/list_of_all_modules.html)。

Ansible 也是可扩展的。如果找不到适合您的模块，编写一个模块很容易，而且不一定要用 Python。模块可以用您选择的语言为 Ansible 编写。这在 [`docs.ansible.com/developing_modules.html`](http://docs.ansible.com/developing_modules.html) 中有详细讨论。

#### 模块和幂等性

幂等性是模块的一个重要特征。它可以多次应用于系统，并返回确定性的结果。它具有内置的智能。例如，我们有一个使用 `apt` 模块安装 Nginx 并确保其为最新版本的任务。如果多次运行它，会发生以下情况：

+   每次运行幂等性时，`apt` 模块都会比较 playbook 中声明的内容与系统上该软件包的当前状态。第一次运行时，Ansible 将确定 Nginx 未安装，并继续安装。

+   对于每次后续运行，它都会跳过安装部分，除非在上游仓库中有新版本的软件包可用。

这允许多次执行相同的任务而不会导致错误状态。大多数 Ansible 模块都是幂等的，除了 command 和 shell 模块。用户需要使这些模块幂等。

## 运行 playbook

Ansible 配备了 `ansible-playbook` 命令来启动 playbook。现在让我们运行我们创建的 plays：

```
$ ansible-playbook simple_playbook.yml -i customhosts

```

运行上述命令时会发生以下情况：

+   `ansible-playbook` 参数是一个命令，它将 playbook 作为参数（`simple_playbook.yml`）并对主机运行 plays。

+   `simple_playbook` 参数包含我们创建的两个 plays：一个用于常规任务，另一个用于安装 Nginx。

+   `customhosts` 参数是我们主机清单，它让 Ansible 知道要针对哪些主机或主机组执行 plays。

启动上述命令将开始调用 plays，在 playbook 中描述的顺序中进行编排。以下是上述命令的输出：

![运行 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_01_03.jpg)

现在让我们分析发生了什么：

+   Ansible 读取指定为`ansible-playbook`命令参数的 playbooks，并开始按顺序执行 play。

+   我们声明的第一个 play 针对"`all`"主机运行。`all`关键字是一种特殊模式，将匹配所有主机（类似于`*`）。因此，第一个 play 中的任务将在我们作为参数传递的清单中的所有主机上执行。

+   在运行任何任务之前，Ansible 将收集有关将要配置的系统的信息。这些信息以事实的形式收集。

+   第一个 play 包括创建`devops`组和用户，并安装 htop 包。由于我们的清单中有三个主机，所以每个主机被打印一行，这表明被管理实体的状态是否发生了变化。如果状态没有更改，将打印“ok”。

+   然后 Ansible 转移到下一个 play。这只在一个主机上执行，因为我们在 play 中指定了"`hosts:www`"，而我们的清单中只包含一个位于组"`www`"中的单个主机。

+   在第二个 play 期间，添加了 Nginx 存储库，安装了该软件包，并启动了该服务。

+   最后，Ansible 会在"`PLAY RECAP`"部分打印播放概要。它指示进行了多少修改，如果其中任何主机无法访问，或者在任何系统上执行失败。

### 小贴士

如果主机无响应或无法运行任务怎么办？Ansible 具有内置智能，将识别此类问题并将失败的主机从轮换中移出。这不会影响其他主机的执行。

# 复习问题

你认为你已经充分理解了这一章吗？试着回答以下问题来测试你的理解：

1.  当涉及到模块时，幂等性是什么？

1.  主机清单是什么，为什么需要它？

1.  Playbooks 将 ___ 映射到 ___（填空）

1.  在选择要对其运行 plays 的主机列表时，可以使用哪些类型的模式？

1.  实际执行特定平台上操作的程序在哪里定义？

1.  为什么说 Ansible 自带电池？

# 总结

在本章中，您了解了 Ansible playbooks 是什么，它们由哪些组件组成，以及如何使用它来为基础设施提供蓝图。我们还对 YAML 进行了简要介绍——用于创建 plays 的语言。您了解了 plays 如何将任务映射到主机，如何创建主机清单，如何使用模式过滤主机以及如何使用模块在我们的系统上执行操作。然后，我们创建了一个简单的 playbook 作为概念验证。

在即将到来的章节中，我们将开始重构我们的代码，创建可重用和模块化的代码块，并称之为角色。


# 第三章：使用 Ansible 角色进行模块化

在上一章中，你学习了使用 Ansible 编写简单 playbook。你还了解了将主机映射到任务的 plays 概念。在单个 playbook 中编写任务对于非常简单的设置可能效果很好。然而，如果我们有多个跨越多个主机的应用程序，这将很快变得难以管理。

在本章中，你将会接触到以下概念：

+   什么是角色，角色用于什么？

+   如何创建角色以提供抽象化？

+   组织内容以提供模块化

+   使用包含语句

+   编写简单任务和处理程序

+   使用 Ansible 模块安装包、管理服务和提供文件

# 理解角色

在现实生活中的场景中，我们大多数时间都会配置 web 服务器、数据库服务器、负载均衡器、中间件队列等等。如果你退一步看一下大局，你会意识到你正在以可重复的方式配置一组相同的服务器。

为了以最有效的方式管理这样的基础设施，我们需要一些抽象化的方法，使我们能够定义每个组中需要配置的内容，并通过名称进行调用。这正是角色所做的。Ansible 角色允许我们同时配置多个节点组，而不需要重复自己。角色还提供了一种创建模块化代码的方法，然后可以共享和重用。

# 命名角色

一个常见的做法是创建映射到你想要配置的基础设施的每个应用程序或组件的角色。例如：

+   Nginx

+   MySQL

+   MongoDB

+   Tomcat

# 角色的目录布局

角色只不过是以特定方式布局的目录。角色遵循预定义的目录布局约定，并期望每个组件都在为其准备的路径中。

以下是一个名为 Nginx 的角色示例：

![角色的目录布局](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_02_01.jpg)

现在让我们看看游戏规则以及前面图表中的每个组件的作用：

+   每个角色都包含一个以自己命名的目录，例如，`Nginx`，其父目录为`roles/`。每个命名角色目录包含一个或多个可选的子目录。最常见的子目录通常包含 `tasks`、`templates` 和 `handlers`。每个子目录通常包含 `main.yml` 文件，这是一个默认文件。

+   任务包含核心逻辑，例如，它们将具有安装包、启动服务、管理文件等代码规范。如果我们将角色比作电影，那么任务将是主角。

+   任务本身无法完成所有工作。考虑我们与电影的类比，缺少支持角色是不完整的。主角有朋友、车辆、爱人和反派分子，来完成故事。同样，任务消耗数据，调用静态或动态文件，触发动作等。这就是文件、处理程序、模板、默认值和`vars`发挥作用的地方。让我们看看这些是什么。

+   `Vars`和默认值提供了关于您的应用程序/角色的数据，例如，您的服务器应该运行在哪个端口，存储应用程序数据的路径，应该以哪个用户身份运行服务等等。默认变量是在 1.3 版本中引入的，这些可以为我们提供合理的默认值。这些稍后可以被其他地方覆盖，例如，`vars`、`group_vars`和`host_vars`。变量被合并，并且存在优先规则。这给了我们很大的灵活性来有选择性地配置我们的服务器。例如，在除了在暂存环境中应该在端口`8080`上运行之外的所有主机上运行 web 服务器，在端口`80`上。

+   文件和模板子目录提供了管理文件的选项。通常，文件子目录用于将静态文件复制到目的主机，例如，一些应用程序安装程序将静态文本文件存档，等等。除了静态文件，你可能经常需要管理动态生成的文件。例如，具有参数（例如端口、用户和内存）的配置文件，可以使用变量动态提供。生成这些文件需要一种称为模板的特殊类型的原始。

+   任务可以根据状态或条件的更改触发动作。在电影中，主角可以追逐反派，基于挑衅或事件进行报复。一个例子是绑架主角的爱人这个事件。同样地，您可能需要根据之前发生的事情在您的主机上执行一个动作，例如，重新启动一个服务，这可能是由于配置文件状态的更改。可以使用处理程序指定此触发-动作关系。

继续我们的类比，许多热门电影有续集，有时甚至有前传。在这种情况下，应该按照特定的顺序观看，因为续集的故事情节取决于发生在以前的电影中的事情。同样地，一个角色可以依赖于另一个角色。一个非常常见的例子是，在安装 Tomcat 之前，系统上应该存在 Java。这些依赖关系定义在一个角色的 meta 子目录中。

让我们通过为 Nginx 应用程序创建一个角色来动手实践这个。让我们提出一个问题陈述，尝试解决它，并在过程中了解角色。

考虑以下情景。随着足球世界杯的开始，我们需要创建一个 Web 服务器来提供有关体育新闻的页面。

作为敏捷方法的追随者，我们将分阶段进行。在第一阶段，我们将只安装一个 Web 服务器并提供一个主页。现在让我们将此分解为实现此目标所需的步骤：

1.  安装一个 Web 服务器。在这种情况下，我们将使用'Nginx'，因为它是一个轻量级的 Web 服务器。

1.  管理 Nginx Web 服务器的配置。

1.  安装完成后启动 Web 服务器。

1.  复制一个 HTML 文件，它将作为主页提供。

现在我们已经确定了要采取的步骤，我们还需要将它们映射到我们将用于实现每个步骤的相应模块类型：

+   安装 Nginx = 包模块（apt）

+   配置 Nginx = 文件模块（file）

+   启动 Nginx = 系统模块（service）

+   提供网页 = 文件模块（file）

在我们开始编写代码之前，我们将先创建一个布局来组织我们的文件。

# 创建站点范围的播放，嵌套和使用 include 语句

作为最佳实践，我们将创建一个顶级文件，其中将包含我们完整基础设施的蓝图。从技术上讲，我们可以将所有需要配置的内容都包含在一个文件中。但是，这会有两个问题：

+   随着我们开始向这个单一文件添加任务、变量和处理程序，它会很快失控。维护这样的代码将是一场噩梦。

+   这也将难以重用和共享这样的代码。使用 Ansible 等工具的优点之一是它能够将数据与代码分离。数据是组织特定的，而代码是通用的。然后，可以与其他人共享此通用代码。但是，如果您将所有内容都写在一个文件中，这将是不可能的。

为了避免这个问题，我们将以模块化的方式开始组织我们的代码，如下所示：

+   我们将为需要配置的每个应用程序创建角色。在这种情况下，它是 Nginx

+   我们的 Web 服务器可能需要安装除了 Nginx 之外的多个应用程序，例如 PHP 和 OpenSSL。为了封装所有这些内容，我们将创建一个名为`www.yml`的播放。

+   我们创建的前置播放将主机与 Nginx 角色进行映射。我们以后可能会添加更多角色。

+   我们将把这个播放添加到顶层播放，即`site.yml`

以下图表简要描述了前面的步骤：

![创建站点范围的播放，嵌套和使用 include 语句](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_02_02.jpg)

这是我们的`site.yml`文件：

```
---
# site.yml : This is a sitewide playbook
- include: www.yml
```

前面的 `include` 指令帮助我们模块化代码。我们不是将所有内容都写在一个文件中，而是拆分逻辑并导入所需的内容。在这种情况下，我们将包含另一个播放，称为**嵌套播放**。

以下是一些关于可以包含和如何包含的指南：

+   `include`指令可用于包含任务、处理程序，甚至其他播放

+   如果您在另一个文件中包含一个播放，就像我们在`site.yml`文件中所做的那样，您不能替换变量

+   `include` 关键字可与常规任务/处理程序规格结合使用。

+   可以在 include 语句中传递参数。这被称为**参数化 include**。

### 提示

**Roles 和自动包括**

Roles 具有隐式规则来自动包括文件。只要遵循目录布局约定，您可以确保所有任务、处理程序以及其他文件都会自动包含。因此，创建与 Ansible 指定的完全相同名称的子目录非常重要。

# 创建 www playbook

我们创建了一个网站范围的 playbook，并使用 include 语句来调用另一个名为`www.yml`的 playbook。我们现在将创建这个文件，其中包含一个 play，将我们的 web 服务器主机映射到 Nginx role：

```
---
#www.yml : playbook for web servers
- hosts: www
  remote_user: vagrant
  sudo: yes
  roles:
     - nginx
```

以上代码的工作方式如下：

+   在任何映射到 hosts 文件中指定的`[www]`组的主机上运行此代码。

+   对于`roles/nginx/*`文件内的每个目录，将`roles/nginx/*/main.yml`包含到 play 中。这包括`tasks`、`handlers`、`vars`、`meta`、`default`等等。这就是自动包括规则适用的地方。

## 默认和自定义 role 路径

默认情况下，Ansible 会查找我们为其创建 playbooks 的项目的子目录`roles/`。作为一流的 devops 工程师，我们将遵循最佳实践，建立一个集中的、版本受控的仓库，用于存储您的所有 role。我们可能最终会重用 community 创建的 roles。这样做后，我们可以在多个项目中重用这些 roles。在这种情况下，我们将在一个或多个位置检出代码，例如：

+   `/deploy/ansible/roles`

+   `/deploy/ansible/community/roles`

对于非默认路径，我们需要在 `ansible.cfg` 中添加`roles_path`参数，如下命令所示：

```
roles_path = /deploy/ansible/roles:/deploy/ansible/community/roles

```

## 参数化 roles

有时，我们可能需要在 role 的 vars 或 default 目录中覆盖默认参数，例如，在端口 8080 上运行 web 服务器而不是 80。在这种情况下，我们也可以在前面的 playbook 中传递参数给 roles，如下所示：

```
---
#www.yml : playbook for web servers
- hosts: www
  roles:
- { role: nginx, port: 8080 }
```

# 创建一个基本 role

在上一章中，我们创建了一个简单的 playbook，所有 play 都写在同一个文件中。在发现关于 roles 的新信息后，我们将开始重构我们的代码，使其具有模块化。

## 重构我们的代码 — 创建一个基本 role

我们在`simple_playbook.yml`文件中编写了两个 play。我们打算在所有主机上运行第一个 play。该 play 有任务来创建用户，安装必要的软件包，等等：

![重构我们的代码 — 创建一个基本 role](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_02_03.jpg)

将所有这类基本任务组合在一起并创建一个基本 role 是一种良好的实践。您可以将其命名为 base、common、essential 或任何您喜欢的名称，但概念是相同的。我们现在将此代码移至 base role 中：

1.  为基本 role 创建目录布局。由于我们只会指定任务，所以我们只需要在 base 内创建一个子目录：

    ```
    $ mkdir -p roles/base/tasks

    ```

1.  在 `roles/base/tasks` 目录下创建 `main.yml` 文件，以指定基本角色的任务。

1.  编辑 `main.yml` 文件，并添加以下代码：

    ```
    ---
    # essential tasks. should run on all nodes
     - name: creating devops group
       group: name=devops state=present
     - name: create devops user
       user: name=devops comment="Devops User" uid=2001 group=devops
     - name: install htop package
       action: apt name=htop state=present update_cache=yes
    ```

# 创建 Nginx 角色

现在我们将为 Nginx 创建一个单独的角色，并将之前在 `simple_playbook.yml` 文件中编写的代码移动到其中，如下所示：

1.  为 Nginx 角色创建目录布局：

    ```
    $ mkdir roles/nginx
    $ cd roles/nginx
    $ mkdir tasks meta files
    $ cd tasks

    ```

1.  在 `roles/base` 目录下创建 `install.yml` 文件。将与 Nginx 相关的任务移动到其中。它应该如下所示：

    ```
    ---
     - name: add official nginx repository
       apt_repository: repo='deb http://nginx.org/packages/ubuntu/ lucid nginx'
     - name: install nginx web server and ensure its at the latest version
       apt: name=nginx state=latest force=yes
    ```

1.  我们还将创建 `service.yml` 文件来管理 Nginx 守护程序的状态：

    ```
    ---
     - name: start nginx service
       service: name=nginx state=started
    ```

1.  我们之前看过 `include` 指令。我们将使用它来在 `main.yml` 文件中包含 `install.yml` 和 `service.yml` 文件，如下所示：

    ```
    ---
    # This is main tasks file for nginx role
     - include: install.yml
    - include: service.yml
    ```

### 提示

**最佳实践**

为什么我们要创建多个文件来分别保存安装包和管理服务的代码呢？因为精心设计的角色允许您选择性地启用特定的功能。例如，有时您可能想要在多个阶段部署服务。在第一阶段，您可能只想安装和配置应用程序，并在部署的第二阶段才启动服务。在这种情况下，具有模块化任务可以帮助。您始终可以将它们全部包含在 `main.yml` 文件中。

## 添加角色依赖关系

在基本角色中指定了一些重要的任务。我们可以不断添加更多任务，这些任务是后续应用程序的先决条件。在这种情况下，我们希望我们的 Nginx 角色依赖于基本角色。现在让我们在 meta 子目录中指定这个依赖关系。让我们看看以下步骤：

1.  在 `roles/nginx/meta/main.yml` 路径下创建 `main.yml` 文件。

1.  在 `meta` 目录下的 `main.yml` 文件中添加以下代码：

    ```
    ---
    dependencies:
      - {role: base}
    ```

上述规范将确保在任何 Nginx 任务开始运行之前始终应用基本角色。

## 管理 Nginx 的文件

根据我们对情景的解决方案，我们已经有了安装 Nginx 和启动服务的 Ansible 任务。但我们还没有要提供的网页内容，也没有考虑过 Nginx 站点配置。我们难道指望 Nginx 神奇地知道如何以及从哪里提供网页吗？

我们需要执行以下步骤来提供 HTML 页面服务：

1.  创建一个站点配置，让 Nginx 知道监听请求的端口，并在请求到来时执行什么操作。

1.  创建一些 HTML 内容，当收到 HTTP 请求时将提供服务。

1.  在 `tasks/main.yml` 中添加代码以复制这些文件。

你可能已经注意到，步骤 1 和步骤 2 都要求你在托管 Nginx Web 服务器的主机上创建和管理一些文件。你还了解了角色的文件和子目录。你猜对了。我们将使用这个子目录来托管我们的文件，并将它们复制到所有使用 Ansible 的 Nginx 主机上。所以，现在让我们使用以下命令创建这些文件：

```
$ cd roles/nginx/files

```

创建一个`default.configuration`文件来管理默认的 Nginx 站点配置。这个文件应该包含端口、服务器名称和 Web 根配置等参数，如下所示：

```
#filename: roles/nginx/files/default.conf
server {
  listen 80;
  server_name localhost;
  location / {
    root /usr/share/nginx/html;
    index index.html;
  }
}
```

我们还将创建一个`index.html`文件，将其推送到所有的 Web 服务器上：

```
#filename: roles/nginx/files/indx.html
<html>
  <body>
    <h1>Ole Ole Ole </h1>
    <p> Welcome to FIFA World Cup News Portal</p>
  </body>
</html>
```

现在我们已经创建了这些文件，我们将添加任务来将它们复制过去，并放在`roles/nginx/tasks/configure.yml`中，如下所示：

```
---
 - name: create default site configurations
   copy: src=default.conf dest=/etc/nginx/conf.d/default.conf mode=0644
 - name: create home page for default site
   copy: src=index.html dest=/usr/share/nginx/html/index.html
```

我们还将在任务中的`main.yaml`文件中更新，包括新创建的文件，并在`service.yml`文件之前添加：

```
---
# This is the main tasks file for the nginx role
 - include: install.yml
 - include: configure.yml
 - include: service.yml
```

# 使用处理程序自动化事件和操作

假设我们在手动管理 Nginx，并且我们需要将 Nginx 监听的端口从默认站点更改为`8080`。我们需要做什么来实现这一点？当然，我们会编辑`default.conf`文件，将端口从`80`更改为`8080`。但是，这样就足够了吗？这样一编辑文件，Nginx 会立即监听端口`8080`吗？答案是否定的。还需要一步骤。让我们来看一下下面的截图：

![使用处理程序自动化事件和操作](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_02_04.jpg)

当我们更改配置文件时，通常也会重新启动/重新加载服务，以便读取我们的修改并应用这些修改。

到目前为止，一切都好。现在让我们回到我们的 Ansible 代码。我们将以自动化的方式在大量服务器上运行此代码，可能是数百台服务器。考虑到这一点，我们不可能登录到每个系统上，在每次更改后重新启动服务。这会违反自动化过程的目的。那么，当事件发生时，我们如何要求 Ansible 采取行动呢？这就是处理程序能够帮助的地方。

你已经了解到 Ansible 模块是幂等的。只有在存在配置漂移时，它们才会强制改变状态。在使用 Ansible 进行管理时，我们将在`roles/nginx/files`下提交之前的端口更改`default.conf`文件。如果在进行此更改后启动 Ansible 运行，它将在执行过程中比较我们角色中的文件与系统上的文件，检测到配置漂移，并将其复制到更改的文件中。而使用 Ansible，我们将添加一个通知，它将触发一个处理程序运行。在这种情况下，我们将调用处理程序重新启动 Nginx 服务。

现在让我们将这个处理程序添加到`roles/nginx/handlers/main.yml`中：

```
---
- name: restart nginx service
  service: name=nginx state=restarted
```

处理程序与普通任务类似。它们指定了一个模块的名称、实例和状态。为什么我们不将它们与普通任务一起添加呢？好吧，我们只需要在发生事件时执行处理程序，而不是每次运行 Ansible 时都执行。这就是为什么我们为它创建一个单独的部分的确切原因。

现在我们已经写了处理程序，我们还需要为它添加一个触发器。我们将通过在 `roles/tasks/nginx/configure.yml` 中添加`notify`指令来实现，如下所示：

![使用处理程序自动化事件和操作](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_02_05.jpg)

### 小贴士

即使多个任务通知处理程序，处理程序也只会在最后调用一次。这将避免不必要地多次重新启动同一服务。

到目前为止，我们的 Nginx 角色布局看起来更完整，并且具有文件、处理程序、任务和具有管理 Nginx 设置每个阶段的单独任务的目录。角色布局如下：

![使用处理程序自动化事件和操作](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_02_06.jpg)

# 向 playbook 中添加预先任务和后置任务

我们希望在开始应用 Nginx 之前和之后打印状态消息。让我们使用`www.yml` playbook，并添加`pre_tasks`和`post_tasks`参数：

```
---
- hosts: www
 remote_user: vagrant
 sudo: yes
 pre_tasks:
 - shell: echo 'I":" Beginning to configure web server..'
 roles:
 - nginx
 post_tasks:
 - shell: echo 'I":" Done configuring nginx web server...'

```

在前面的示例中，我们仅使用`echo`命令打印了一些消息。但是，我们可以使用 Ansible 提供的任何模块创建任务，这些任务可以在应用角色之前或之后运行。

# 使用角色运行 playbook

现在让我们将重构后的代码应用到我们的主机上。我们将仅启动站点范围的 playbook，即`site.yml`文件，然后依赖于包含语句和角色来完成工作：

```
$ ansible-playbook -i customhosts site.yml

```

让我们来看看以下的屏幕截图：

![使用角色运行 Playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_02_07.jpg)

除了上次看到的输出之外，这次还有一些新的消息。让我们来分析一下：

+   在应用角色之前和之后，将触发预先任务和后置任务；这将使用 shell 模块打印消息。

+   现在我们有了复制到我们的 Nginx Web 服务器的`config`和`.html`文件的代码。

+   我们还看到处理程序触发了 Nginx 服务的重新启动。这是由于`configuration`文件状态的改变，触发了处理程序。

### 提示

你注意到了吗？即使我们没有在`www` playbook 中提及基础角色，基础角色中的任务也会被触发。这就是元信息的作用。记得我们在 Nginx 的`meta/main.yml`中为基础角色指定了一个依赖关系吗？那就是起作用的地方。

依赖关系：

```
           - { role: base}
```

# 复习问题

你认为你是否足够理解了本章？试着回答以下问题来测试你的理解：

1.  角色包含 ___ 和 ___ 子目录以指定变量/参数。

1.  如何指定对另一个角色的依赖关系？

1.  当我们向 play 中添加角色时，为什么不需要使用`include`指令？任务、处理程序等是如何自动添加到 play 中的？

1.  如果处理程序与常规任务相似，为什么我们需要一个单独的部分来处理处理程序？

1.  哪个模块可以用于将静态文件复制到目标主机？

1.  如何在 playbook 中指定在应用角色之前运行的任务？

# 摘要

在这一章中，你学会了如何使用角色提供抽象并帮助模块化代码以供重用。这正是社区正在做的事情。创建角色，并与你分享。你还学习了关于`include`指令、角色的目录布局以及添加角色依赖项。然后我们进行了代码重构，并创建了一个基本角色，即 Nginx 角色。我们还了解了如何管理事件并使用处理程序采取行动。

在下一章中，我们将扩展角色的概念，并开始使用变量和模板添加动态数据。


# 第四章：代码和数据的分离 - 变量、事实和模板

在上一章中，我们看过如何编写一个角色以提供模块化和抽象化。在这样做的同时，我们创建了配置文件，并使用 Ansible 的复制模块将文件复制到目标主机上。

在本章中，我们将涵盖以下概念：

+   如何将数据与代码分开？

+   什么是 Jinja2 模板？它们是如何创建的？

+   什么是变量？它们是如何以及在哪里使用的？

+   什么是系统事实？它们是如何被发现的？

+   不同类型的变量是什么？

+   什么是变量合并顺序？它的优先规则是什么？

# 静态内容爆炸

让我们想象我们正在管理跨越多个数据中心的数百个 Web 服务器的集群。由于我们在配置文件中硬编码了`server_name`参数，因此我们将不得不为每台服务器创建一个文件。这也意味着我们将管理数百个静态文件，这将很快失控。我们的基础架构是动态的，管理变更是 DevOps 工程师日常任务中最常见的方面之一。如果明天，我们公司的政策规定应该在生产环境中运行 Web 服务器的端口为 8080 而不是端口 80，想象一下你要单独更改所有这些文件会有多么头痛。有一个接受动态输入的单个文件，这个输入是特定于它正在运行的主机的，这不是更好吗？这正是模板的作用所在，正如下图所示，一个模板可以替代多个静态文件：

![静态内容爆炸](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_03_01.jpg)

在我们定义模板是什么之前，让我们首先了解如何将代码与数据分开，以及这如何帮助我们解决静态内容爆炸的问题。

# 分离代码和数据

基础架构即代码工具（例如 Ansible）的真正魔力在于它分离数据和代码的能力。在我们的示例中，`default.conf` 文件是一个特定于 Nginx Web 服务器的配置文件。配置参数，例如端口、用户、路径等，在任何时候都保持通用和恒定，无论是谁安装和配置它们。不恒定的是这些参数的值。这是我们组织特有的。因此，对于这一点，我们将决定以下事项：

+   Nginx 应该在哪个端口运行？

+   哪个用户应该拥有 Web 服务器进程？

+   日志文件应该放在哪里？

+   应该运行多少个工作进程？

我们组织特定的策略也可能要求我们根据主机所在的环境或地理位置传递不同的值给这些参数。

Ansible 将这些分成两部分：

+   泛型代码

+   对组织特定的数据

这有两个优点；一个优点是解决了我们的静态数据爆炸问题。现在我们已经将代码和数据分开，我们可以灵活和动态地创建`config`文件。第二个优点，你可能会意识到，现在代码和数据被分开了，代码中没有任何特定于特定组织的内容。这使得与任何发现它有用的人分享网站变得容易。这正是您在 Ansible-Galaxy 或者甚至在 GitHub 上找到的东西，推动了像 Ansible 这样的工具的增长。与其重新发明轮子，您可以下载别人编写的代码，自定义它，填写与代码相关的数据，然后完成工作。

现在，这段代码与数据如何分离呢？答案是 Ansible 有两种原始：

+   Jinja 模板（代码）

+   变量（数据）

以下图解释了如何从模板和变量生成结果文件：

![分离代码和数据](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_03_02.jpg)

模板提供参数值的占位符，这些占位符然后由变量定义。变量可以来自各种地方，包括角色、剧本、清单，甚至是在启动 Ansible 时从命令行输入。现在让我们详细了解模板和变量。

# Jinja2 模板

Jinja 是什么？ **Jinja2** 是一个非常流行和强大的基于 Python 的模板引擎。由于 Ansible 是用 Python 编写的，所以它成为大多数用户的默认选择，就像其他基于 Python 的配置管理系统，例如 **Fabric** 和 **SaltStack** 一样。Jinja 的名称源自日语单词“寺庙”，与“模板”的音标相似。

Jinja2 的一些重要特性包括：

+   它快速并且使用 Python 字节码即时编译

+   它有一个可选的沙盒环境

+   它易于调试

+   它支持模板继承

## 模板的形成

模板看起来非常类似于普通的基于文本的文件，除了偶尔出现的变量或者围绕特殊标签的代码。这些会在运行时被评估，大多数情况下被值替换，从而创建一个文本文件，然后被复制到目标主机。以下是 Jinja2 模板接受的两种类型的标签：

+   `{{ }}` 将变量嵌入到模板中并在生成的文件中打印其值。这是模板的最常见用法。

    例如：

    ```
        {{ nginx_port }}
    ```

+   `{% %}` 将代码语句嵌入到模板中，例如，用于循环的 if-else 语句，这些语句在运行时被评估但不会被打印。

# 事实和变量

现在我们已经看过了 Jinja2 模板提供的代码，让我们来理解数据来自何处，然后在运行时嵌入到模板中。数据可以来自事实或变量。当涉及到 Jinja2 模板时，相同的规则适用于事实和变量的使用。事实是一种变量；这里的区别因素是两者的来源。事实在运行时自动可用并发现，而变量是用户定义的。

## 自动变量 - 事实

我们系统中的许多数据是在握手过程中由托管主机自动发现和提供给 Ansible 的。这些数据非常有用，告诉我们关于该系统的一切，例如：

+   主机名、网络接口和 IP 地址

+   系统架构

+   操作系统

+   磁盘驱动器

+   使用的处理器和内存量

+   是否是虚拟机；如果是，是虚拟化/云提供商吗？

### 提示

事实是在 Ansible 运行的最开始收集的。记住输出中的那行说 **GATHERING FACTS ********* 吗？这正是发生这种情况的时候。

您可以通过运行以下命令然后跟一个简短的输出来查找有关任何系统的事实：

```
$ ansible -i customhosts www -m setup | less
192.168.61.12 | success >> {
  "ansible_facts": {
    "ansible_all_ipv4_addresses": [
      "10.0.2.15",
      "192.168.61.12"
    ],
    "ansible_architecture": "i386",
    "ansible_bios_date": "12/01/2006",
    "ansible_cmdline": {
      "BOOT_IMAGE": "/vmlinuz-3.5.0-23-generic",
      "quiet": true,
      "ro": true,
      "root": "/dev/mapper/vagrant-root"
    },
    "ansible_distribution": "Ubuntu",
    "ansible_distribution_major_version": "12",
    "ansible_distribution_version": "12.04",
    "ansible_domain": "vm",
    "ansible_fqdn": "vagrant.vm",
    "ansible_hostname": "vagrant",
    "ansible_nodename": "vagrant",
    "ansible_os_family": "Debian",
    "ansible_pkg_mgr": "apt",
    "ansible_processor": [
      "GenuineIntel",
      "Intel(R) Core(TM) i5-3210M CPU @ 2.50GHz"
    ],
    "ansible_processor_cores": 1,
    "ansible_processor_count": 2,
    "ansible_processor_threads_per_core": 1,
    "ansible_processor_vcpus": 2,
    "ansible_product_name": "VirtualBox",
  }
}
```

上述输出是以 Ansible 自己的格式并使用其核心设置模块。类似于设置模块，还有另一个名为 `facter` 的模块，它发现并显示与 Puppet 发现的格式相同的事实，另一个配置管理系统。以下是如何使用 `facter` 模块为同一主机发现事实的示例：

```
$ ansible -i customhosts www -m facter | less

```

在使用 `facter` 模块时，您需要注意的一点是，该模块不是核心模块，而是作为额外模块的一部分提供的。额外模块是 Ansible 模块的一个子集，它的使用频率较低，与核心模块相比较不流行。此外，要使用 `facter` 模块，您需要在目标主机上预安装 "`facter`" 和 "`ruby-json`" 包。

## 用户定义的变量

我们看了自动可用的事实，并且发现的数据量是压倒性的。然而，它并不能为我们提供我们需要的基础设施的每个属性。例如，Ansible 无法发现：

+   我们想让我们的 Web 服务器监听哪个端口

+   哪个用户应该拥有一个进程

+   用户需要创建的系统，以及授权规则

所有这些数据都是外部的系统概要，并由我们，用户，提供。这肯定是用户定义的，但我们应该如何在哪里定义它？这就是我们接下来要看的。

### 在哪里定义一个变量

变量可以从哪里定义是一个复杂的现象，因为 Ansible 在这方面提供了丰富的选择。这也为用户配置其基础设施的部分提供了很大的灵活性。例如，生产环境中的所有 Linux 主机应该使用本地软件包存储库或分段中的 Web 服务器，并且应该运行在端口`8080`上。所有这些都不需要更改代码，仅通过数据驱动完成，由变量完成。

以下是 Ansible 接受变量的地方：

+   角色内的`default`目录

+   库存变量

    +   分别在不同目录中定义的`host_vars`和`group_vars`参数

    +   在清单文件中定义的`host/group vars`参数

+   剧本和角色参数中的变量

+   角色内的`vars`目录和在一个播放中定义的变量

+   在运行时使用`-e`选项提供的额外变量

### 如何定义变量

看完变量定义的位置后，我们将开始看如何在各种地方定义它。

以下是您可以使用的一些简单规则来形成有效的 Ansible 变量：

+   变量应始终以字母开头

+   它可以包含：

    +   字母

    +   数字

    +   下划线

让我们看一下下面的表格：

| 有效变量 | 无效变量 |
| --- | --- |
| `app_port` | `app-port` |
| `userid_5` | `5userid` |
| `logdir` | `log.dir` |

我们已经看过了优先规则，现在我们知道有多个地方可以定义变量。不考虑优先级水平，所有使用相同的语法来定义变量。

要以键值对格式定义简单变量，请使用`var: value`，例如：

```
      nginx_port: 80
```

字典或哈希可以被定义为 Nginx：

```
       port: 80
       user: www-data
```

数组可以被定义为：

```
    nginx_listners:
      - '127.0.0.1:80'
      - '192.168.4.5:80'
```

# 对 Nginx 配置进行模板化

你已经学到了很多关于事实、变量和模板的知识。现在，让我们将我们的 Nginx 角色转换为数据驱动的。我们将开始为我们之前创建的 Nginx 的`default.conf`文件进行模板化。将文件转换为模板的方法如下：

1.  创建所需目录以保存角色内的模板和默认变量：

    ```
    $ mkdir roles/nginx/templates
    $ mkdir roles/nginx/defaults

    ```

1.  总是从实际的配置文件开始，即此过程的最终结果，以了解它所需的所有参数。然后，往回工作。例如，我们系统上的`default.conf`文件的配置如下：

    ```
            server {
                     listen       80;
                     server_name  localhost; 
                     location / {
                        root   /usr/share/nginx/html;
                        index  index.html;
                   }
             }
    ```

1.  确定您想要动态生成的配置参数，删除这些参数的值，单独记录下来，并用模板变量替换它们：

    ```
        Template Snippets:
          listen {{ nginx_port }} ;
          root   {{ nginx_root }};
          index  {{ nginx_index }};

        Variables:
          nginx_port: 80
          nginx_root: /usr/share/nginx/html
          nginx_index: index.html
    ```

1.  如果任何配置参数的值应该从事实中获取，通常是系统参数或拓扑信息，比如主机名、IP 地址等，则可以使用以下命令找到相关的事实：

    例如：

    ```
    $ ansible -i customhosts www -m setup | less

    ```

    要找出系统的主机名：

    ```
    $ ansible -i customhosts www -m setup | grep -i hostname

      "ansible_hostname": "vagrant",
      "ohai_hostname": "vagrant",
    ```

1.  在模板中使用发现的事实，而不是用户定义的变量。例如：

    ```
      server_name  {{ ansible_hostname }},
    ```

1.  将结果文件保存在模板目录中，最好使用`.j2`扩展名。例如，对于`roles/nginx/templates/default.conf.j2`，结果文件如下所示：

    ```
    #roles/nginx/templates/default.conf.j2
    server {
        listen       {{ nginx_port }};
        server_name  {{ ansible_hostname }};

        location / {
            root   {{ nginx_root }};
            index  {{ nginx_index }};
        }
    }
    ```

1.  创建`roles/nginx/defaults/main.yml`并将默认值存储如下：

    ```
    ---
    #file: roles/nginx/defaults/main.yml
    nginx_port: 80
    nginx_root: /usr/share/nginx/html
    nginx_index: index.html
    ```

1.  一旦模板创建完成，将`configure.yml`文件中的任务更改为使用模板而不是复制模块:![模板化 Nginx 配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_03_04.jpg)

1.  最后，到了删除我们之前使用复制模块的静态文件的时候：

    ```
    $ rm roles/nginx/files/default.conf

    ```

    然后是运行 Ansible playbook 的时间：

    ```
    $ ansible-playbook -i customhosts site.yml

    ```

让我们来看一下以下的屏幕截图：

![模板化 Nginx 配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_03_05.jpg)

让我们分析此次运行中发生的情况：

+   我们将配置任务更改为使用模板而不是复制模块，这在任务显示其更改状态时在屏幕截图中反映出来。

+   由于任务已更新，会触发通知，该通知调用处理程序以重新启动服务。

我们的 Nginx 角色的代码树在进行此更改后如下所示：

![模板化 Nginx 配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_03_06.jpg)

# 添加另一个层——MySQL 角色。

到目前为止，我们一直关注基础架构的单个层，即 web 服务器层。仅为一个层编写代码并不有趣。作为一个酷炫的 DevOps 团队，我们将创建一个具有数据库、web 服务器和负载均衡器的多层基础架构。接下来，我们将开始创建 MySQL 角色，应用到目前为止学到的所有知识，并扩展这些知识以涵盖一些新概念。

这是我们的 MySQL 角色规范：

+   它应该安装 MySQL 服务器包。

+   它应该配置 '`my.cnf`'，这是 MySQL 服务器的主配置。

+   它应该启动 MySQL 服务器守护进程。

+   它应该支持 Ubuntu 12.04 以及 CentOS/RedHat Enterprise 6.x。

## 使用 Ansible-Galaxy 创建角色的脚手架。

到目前为止，我们一直在努力理解和创建角色所需的目录结构。然而，为了让我们的工作更轻松，Ansible 提供了一个叫做**Ansible-Galaxy**的工具，它可以帮助我们自动创建脚手架并遵循最佳实践。实际上，Ansible-Galaxy 的功能不仅仅是如此。它还是一个连接到[`galaxy.ansible.com`](http://galaxy.ansible.com)上免费可用的 Ansible 角色仓库的实用工具。这类似于我们使用**CPAN**或**RubyGems**的方式。

让我们首先使用以下命令使用 Ansible-Galaxy 对 MySQL 角色进行初始化：

```
$ ansible-galaxy init --init-path roles/ mysql

```

在这里，以下是对前面命令的分析：

+   `init`：这是传递给 Ansible-Galaxy 的子命令，用于创建脚手架。

+   `--init-path`或`-p`：这些提供了角色目录路径，在该路径下创建目录结构。

+   `mysql`：这是角色的名称。

让我们来看一下以下的屏幕截图：

![使用 Ansible-Galaxy 创建角色的支架](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_03_07.jpg)

在使用 Ansible-Galaxy 初始化角色后创建的目录布局如上图所示，它创建了一个空角色，具有适用于 Galaxy 上传的结构。它还初始化了必要的组件，包括任务、处理程序、变量和带有占位符的元文件。

## 向角色添加元数据

我们之前使用`meta`文件指定了对另一个角色的依赖关系。除了指定依赖关系外，元文件还可以为角色指定更多数据，例如：

+   作者和公司信息

+   支持的操作系统和平台

+   角色功能的简要描述

+   支持的 Ansible 版本

+   这个角色试图自动化的软件类别

+   许可信息

让我们通过编辑`roles/meta/main.yml`来更新所有这些数据：

```
---
galaxy_info:
  author: Gourav Shah
  description: MySQL Database Role
  company: PACKT
  min_ansible_version: 1.4
  platforms:
  - name: EL
    versions:
      - all
  - name: Ubuntu
    versions:
      - all
  categories:
  - database:sql
```

在上面的片段中，我们向角色添加了元数据，如作者和公司详细信息，角色功能的简要描述，与 Ansible 版本的兼容性，支持的平台，角色所属的类别等等。

## 在任务和处理程序中使用变量

你已经学会了如何在模板中使用变量。那不是用来定义变量的全部代码。除了模板之外，我们还可以在任务、剧本等中使用变量。这一次，我们还承诺提供一个支持多平台的角色，支持 Ubuntu 和 RedHat。与**Chef**和**Puppet**不同，Ansible 使用特定于操作系统的模块（例如，`apt`和`yum`），而不是平台无关的资源（软件包）。我们将不得不创建特定于操作系统的任务文件，并根据它们将它们选择性地调用。我们是这样做的：

+   我们将找到一个事实，确定操作系统平台/系列。这里我们有几个选项：

    +   `ansible_distribution`

    +   `ansible_os_family`

+   RedHat、CentOS 和 Amazon Linux 都基于`rpm`，行为类似。Ubuntu 和 Debian 操作系统也是同一平台系列的一部分。因此，我们选择使用`ansible_os_family`事实，这将为我们提供更广泛的支持。

+   我们将在角色中的两个地方定义变量：

    +   从适用于 Debian 的默认`vars`文件中获取合理的默认值。

    +   如果不是 Debian 的特定于`os_family`的变量。

+   我们还将创建特定于操作系统的任务文件，因为我们可能需要调用不同的模块（`apt`与`yum`）和特定于该操作系统的额外任务。

+   对于处理程序和任务，我们将使用变量提供特定于操作系统的名称（例如，MySQL 与 mysqld，用于服务）。

+   最后，我们将创建`main.yml`文件，通过检查这个事实的值来选择性地包含特定于主机的变量以及任务文件。

### 创建变量

我们将从创建变量开始。让我们在`/mysql/defaults/main.yml`文件中为 Debian/Ubuntu 设置合理的默认值：

```
---
#roles/mysql/defaults/main.yml
mysql_user: mysql
mysql_port: 3306
mysql_datadir: /var/lib/mysql
mysql_bind: 127.0.0.1
mysql_pkg: mysql-server
mysql_pid: /var/run/mysqld/mysqld.pid
mysql_socket: /var/run/mysqld/mysqld.sock
mysql_cnfpath: /etc/mysql/my.cnf
mysql_service: mysql
```

然后它将在 RedHat/CentOS 机器上运行，但是我们需要覆盖一些变量，以配置特定于 RedHat 的参数。

### 注意事项

请注意，文件名应与 `ansible_os_family` fact 返回的确切名称（即 RedHat）完全匹配，并正确使用大小写。

我们将创建并编辑 `roles/mysql/vars/RedHat.yml` 文件，如下所示：

```
---
# RedHat Specific Configs.
# roles/mysql/vars/RedHat.yml
mysql_socket: /var/lib/mysql/mysql.sock
mysql_cnfpath: /etc/my.cnf
mysql_service: mysqld
mysql_bind: 0.0.0.0
```

最后，我们将创建 `group_vars` fact 并提供一个变量来覆盖默认设置。您已经学到了可以在 `inventory` 文件、`group_vars` 和 `host_vars` facts 中指定变量。我们现在将开始使用 `group_vars` fact。您可以在库存文件中创建这些，也可以创建一个名为 `group_vars` 的单独目录。我们将采用第二种方法，这是推荐的方法：

```
# From our top level dir, which also holds site.yml
$ mkdir group_vars
$ touch group_vars/all

```

编辑 `group_vars`/`all` 文件并添加以下行：

```
mysql_bind: "{{ ansible_eth0.ipv4.address }}"
```

### 创建任务

现在是创建任务的时候了。遵循最佳实践，我们将任务分解成多个文件，并使用包括语句，就像我们为 Nginx 所做的那样。现在我们将在 `roles/mysql/tasks` 内创建默认的 `main.yml` 文件，如下所示：

```
---
# This is main tasks file for mysql role
# filename: roles/mysql/tasks/main.yml
# Load vars specific to OS Family. 
- include_vars: "{{ ansible_os_family }}.yml"
  when: ansible_os_family != 'Debian'

- include: install_RedHat.yml
  when: ansible_os_family == 'RedHat'

- include: install_Debian.yml
  when: ansible_os_family == 'Debian'

- include: configure.yml
- include: service.yml
```

我们早先已经看到了 `include` 语句。这里新增的内容是使用了 `include_vars` fact 并使用了 `ansible_os_family` fact。如果您注意到：

+   我们使用了 `ansible_os_family` fact 和 `include_vars` fact，在不是 Debian 系统的情况下来确定是否包含特定于操作系统的变量。为什么不适用于 Debian 系统？因为我们已在 `default` 文件中指定了特定于 Debian 的配置。`include_vars` fact 与前面的条件语句配合得很好。

+   我们还使用 `when` 条件调用特定于操作系统的安装脚本。我们目前已包含支持 Debian 和 RedHat 家族的两个脚本。但是，稍后我们可以通过添加更多 `install_<os_family>.yml` 脚本来扩展脚本，以支持其他平台。

现在，让我们创建适用于 Debian 和 RedHat 的安装任务：

```
$ vim roles/mysql/tasks/install_Debian.yml

```

然后如下编辑文件：

```
---
# filename: roles/mysql/tasks/install_Debian.yml
  - name: install mysql server
    apt:
      name:"{{ mysql_pkg }}"
      update_cache:yes

$ vim roles/mysql/tasks/install_Redhat.yml

```

运行前面的命令后，将文件编辑如下所示：

```
---
# filename: roles/mysql/tasks/install_RedHat.yml
- name: install mysql server
   yum:
     name:"{{ mysql_pkg }}"
     update_cache:yes
```

在上一示例中，我们在基于 Debian 和 RedHat 的系统分别使用了 `apt` 和 `yum` 模块。遵循最佳实践，我们将编写数据驱动的角色，使用变量 `mysql_pkg` 提供软件包名称。该变量根据其运行的平台设置。我们来看看以下步骤：

1.  下一步是创建用于配置 MySQL 的任务。由于我们知道每个配置文件应该是一个模板，我们将为 `my.cnf` 文件创建一个模板，即 MySQL 服务器的默认配置文件：

    ```
    $ touch roles/mysql/templates/my.cnf.j2

    ```

    然后如下编辑文件：

    ```
    # Notice:This file is being managed by Ansible
    # Any manual updates will be overwritten
    # filename: roles/mysql/templates/my.cnf.j2
    [mysqld]
    user = {{ mysql_user | default("mysql") }}
    pid-file	 = {{ mysql_pid }}
    socket = {{ mysql_socket }}
    port = {{ mysql_port }}
    datadir = {{ mysql_datadir }}
    bind-address = {{ mysql_bind }}
    ```

1.  我们创建了一个模板，使用了 `.j2` 扩展名，因为它是 Jinja2 模板。这不是必须的，但建议这样做。

1.  所有配置参数都来自 `{{var}}` 格式的变量。这是管理配置文件的推荐做法。我们可以让属性的优先级决定值来自哪里。

### 提示

为每个由 Ansible 管理的文件添加注意事项是个好习惯。这样可以避免可能的手动更新或临时更改。

我们将编写一个任务来管理这个模板，并将生成的文件复制到主机上的目标路径：

```
---
# filename: roles/mysql/tasks/configure.yml
 - name: create mysql config
   template: src="img/my.cnf" dest="{{ mysql_cnfpath }}" mode=0644
   notify:
    - restart mysql service
```

我们有一个通用的配置文件模板；然而，复制这个模板的路径因平台而异，也根据您计划使用的 MySQL 版本不同。在这里，我们使用的是默认情况下包含在 Ubuntu 和 CentOS 仓库中的 MySQL 发行版，并且我们将从角色变量中设置 `mysql_cnfpath` 路径，如下所示：

+   在 Ubuntu/Debian 上，使用命令：`mysql_cnfpath = /etc/mysql/my.cnf`

+   在 RedHat/CentOS 上，使用命令：`mysql_cnfpath = /etc/my.cnf`

同时，我们将通知发送给 MySQL 服务重启处理程序。这将确保如果配置文件发生任何更改，服务将自动重新启动。

要管理一个服务，我们将创建一个服务任务和处理程序：

任务：

```
$ touch roles/mysql/tasks/service.yml

```

然后按如下所示编辑文件：

```
---
# filename: roles/mysql/tasks/service.yml
 - name: start mysql server
   service: name="{{ mysql_service }}" state=started
```

处理程序：

```
$ touch roles/mysql/handlers/main.yml

```

运行上述命令后，按如下所示编辑文件：

```
---
# handlers file for mysql
# filename: roles/mysql/handlers/main.yml
- name: restart mysql service
  service: name="{{ mysql_service }}" state=restarted
```

在这里，任务和处理程序与 Nginx 服务类似，所以不需要太多描述。唯一的变化是我们使用 `mysql_service` 变量来决定要启动或重新启动服务的服务名称。

## 在剧本中使用变量

变量也可以在剧本中指定。这样做的首选方法是将它们作为角色参数传递，示例如下。当角色中有默认值，并且您想要覆盖一些特定于您设置的配置参数时，这通常是有用的。这样，角色仍然是通用的和可共享的，不包含组织特定的数据。

我们将创建一个用于管理数据库的剧本，然后将其包含在全局剧本中，如下所示：

```
$ touch db.yml

```

然后按如下所示编辑文件：

```
---
# Playbook for Database Servers
# filename: db.yml
- hosts: db
  remote_user: vagrant
  sudo: yes
  roles:
    - { role: mysql, mysql_bind: "{{ ansible_eth1.ipv4.address }}" }
```

在这里，我们假设主机清单包含一个名为 `db` 的主机组。在我们的示例中，我们有两个运行在 Ubuntu 和 CentOS 上的 `db` 服务器。这被添加为：

```
[db]
192.168.61.11 ansible_ssh_user=vagrant ansible_ssh_private_key_file=/vagrant/insecure_private_key
192.168.61.14 ansible_ssh_user=vagrant ansible_ssh_private_key_file=/vagrant/insecure_private_key
```

在上面的剧本中，我们使用了一个参数化角色，它覆盖了一个变量，即 `mysql_bind`。该值是从一个多级事实中设置的。

让我们来看一下以下的截图：

![在剧本中使用变量](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_03_08.jpg)

一个多级事实也可以被指定为 `ansible_eth1["ipv4"]["address"]`，两种格式都是有效的。当我们想要创建多个角色实例时，例如运行在不同端口上的虚拟主机和 WordPress 实例，参数化角色也非常有用。

现在让我们使用 `include` 语句将这个剧本包含在顶级的 `site.yml` 文件中：

如下编辑 `site.yml` 文件：

```
---
# This is a sitewide playbook
# filename: site.yml
- include: www.yml 
- include: db.yml
```

## 将 MySQL 角色应用于数据库服务器

我们已准备好配置我们的数据库服务器。让我们继续将新创建的角色应用于我们库存中的所有 `db` 服务器：

```
$ ansible-playbook -i customhosts site.yml

```

以下图像包含仅与数据库 Play 相关的输出片段：

![将 MySQL 角色应用于数据库服务器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_03_09.jpg)

我们在前几章已经解释了 Ansible 的运行，当我们创建第一个 Playbook 以及应用 Nginx 角色时。这里唯一的新概念是 `include_var` 部分。Ansible 将根据 `ansible_os_family` 事实检查我们的条件，并调用特定于操作系统的变量。在我们的情况下，我们每个有一个 Ubuntu 和 CentOS 主机，并且在仅在 CentOS 主机上运行时都调用 `RedHat.yml` 文件。

这里真正有趣的是要找出在每个平台上我们的配置文件发生了什么以及哪些变量具有优先权。

# 变量优先级

我们指定了变量默认值，并在库存文件中使用它们，并从不同位置定义了相同的变量（例如，默认值、vars 和库存）。现在让我们分析模板的输出，以了解所有这些变量发生了什么。 

以下是显示 Ubuntu 上 `my.cnf` 文件的图表：

![变量优先级](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_03_11.jpg)

以下是对截图的分析：

+   文件在注释部分有一条通知。这可以阻止管理员对文件进行手动更改。

+   大多数变量来自角色中的默认值。这是因为 Debian 是我们默认的操作系统系列，我们已经为其设置了合理的默认值。类似地，对于其他操作系统平台，我们正在从角色的 `vars` 目录中设置变量默认值。

+   尽管 `bind_address` 参数在默认设置和 `group_vars` 中指定，但它从 Playbook 的角色参数中取值，后者优先于其他两个级别。

以下图表解释了在各个级别定义变量时会发生什么情况。它们都在运行时合并。如果相同的变量在多个位置定义，则会应用优先规则：

![变量优先级](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_03_10.jpg)

要理解优先规则，让我们看看我们的 CentOS 主机上发生了什么。以下是在 CentOS 上创建的 `my.cnf` 文件：

![变量优先级](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_03_12.jpg)

如前图所示，在 CentOS 的情况下，我们看到一些有趣的结果：

+   **user**、**pid**、**datadir** 和 **port** 的值来自默认设置。我们已经查看了合并顺序。如果变量不相同，则合并它们以创建最终配置。

+   套接字的值来自 vars，因为那是它唯一被定义的地方。尽管如此，我们希望这个套接字对于基于 RedHat 的系统是恒定的，因此，我们在角色的 vars 目录中指定了它。

+   `bind_address`参数再次来自 vars 目录。这很有趣，因为我们在以下位置定义了`mysql_bind`变量：

    +   角色中的`默认`值

    +   `group_vars`

    +   `playbook`

    +   角色中的`vars`

以下图展示了当我们多次定义相同变量时的优先级规则：

![变量优先级](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_03_03.jpg)

由于我们的角色在`vars`目录中定义了`bind_address`参数，它优先于其他。

有一种方法可以使用额外的变量或在运行 Ansible 时使用`-e`开关来重写角色参数。这是 Ansible 管理的变量的最高优先级。

例如：

```
ansible-playbook -i customhosts db.yml  -e mysql_bind=127.0.0.1

```

在前面的启动命令中，我们使用了`-e`开关，它将覆盖所有其他变量级别，并确保 MySQL 服务器绑定到`127.0.0.1`。

# 变量使用的最佳实践

觉得压力大了？别担心。我们将为您提供使用变量时的最佳实践建议：

+   从一个角色中开始使用默认值。这是所有优先级中最低的。这也是提供应用程序的合理默认值的好地方，稍后可以从各种地方覆盖。

+   组变量非常有用。很多时候，我们会进行特定于区域或环境的配置。我们还会为一组特定服务器应用特定的角色，例如，对于所有亚洲的 web 服务器，我们应用 Nginx 角色。还有一个名为"`all`"的默认组，其中包含所有组的所有主机。将对所有组通用的变量放在"`all`"（`group_vars/all`）中是一个好习惯，然后可以被更具体的组覆盖。

+   如果有主机特定的异常情况，请使用`hosts_vars`，例如，`host_vars/specialhost.example.org`。

+   如果你想要将变量分开存储在不同的文件中，创建以主机名命名的目录，然后将变量文件放在其中。在这些目录中的所有文件都将被评估：

    +   `group_vars/asia/web`

    +   `host_vars/specialhost/nginx`

    +   `host_vars/specialhost/mysql`

+   如果你想要保持你的角色通用且可共享，在角色中使用默认值，然后从 playbooks 中指定特定于组织的变量。这些可以被指定为角色参数。

+   如果希望角色变量始终优先于清单变量和 playbooks，请在角色内的`vars`目录中指定它们。这对于为特定平台提供角色常量非常有用。

+   最后，如果你想要覆盖之前的任何变量并在运行时提供一些数据，请使用 Ansible 命令使用`-e`选项提供额外的变量。

到目前为止，我们的 MySQL 角色和 DB playbook 的树应该如下图所示：

![变量使用的最佳实践](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_03_13.jpg)

# 复习问题

你觉得自己对本章有足够的理解吗？尝试回答以下问题来测试你的理解：

1.  什么是 Jinja2 模板与静态文件的区别？

1.  什么是事实？它们是如何被发现的？

1.  在 Jinja2 模板的上下文中 `{{ }}` 和 `{% %}` 有什么区别？

1.  除了模板之外，您可以在任何地方使用变量吗？如果可以，在哪里？

1.  如果在角色的 `vars` 目录中定义了变量 `foo`，并且在 `hosts_var` 文件中也定义了相同的变量，那么这两者中哪个优先级更高？

1.  如何编写支持多个平台的 Ansible 角色？

1.  您可以在角色中的哪里指定作者和许可信息？

1.  在启动 Ansible-playbook 命令时如何提供变量？

1.  你会使用哪个命令来自动创建角色所需的目录结构？

1.  如何覆盖角色的 `vars` 目录中指定的变量？

# 摘要

我们从学习使用 Ansible 变量、事实和 Jinja2 模板将数据与代码分离的原因和方法开始了这一章节。您学会了如何通过在模板、任务、处理程序和 Playbooks 中提供变量和事实来创建数据驱动的角色。此外，我们为数据库层创建了一个新角色，支持 Debian 和 RedHat 系列操作系统。您学会了系统事实是什么以及如何发现和使用它们。您学会了如何从多个位置指定变量、它们是如何合并的以及优先级规则。最后，您学会了使用变量的最佳实践。

在下一章中，我们将使用自定义命令和脚本，了解注册变量是什么，并使用所有这些信息部署一个示例 WordPress 应用程序。


# 第五章：引入您的代码 - 自定义命令和脚本

Ansible 附带了各种内置模块，允许我们管理各种系统组件，例如用户、软件包、网络、文件和服务。Ansible 的一揽子方法还提供了将这些组件与云平台、数据库和应用程序（如**Jira**、**Apache**、**IRC**和**Nagios**等）集成的能力。然而，有时我们会发现自己处于无法找到完全符合要求的模块的位置。例如，从源代码安装软件包涉及下载、提取源码 tarball，然后是 make 命令，最后是"make install"。没有一个单一的模块来完成这个任务。还会有一些时候，我们希望引入我们已经花费了夜晚时间创建的现有脚本，并让它们与 Ansible 一起被调用或定时执行，例如夜间备份脚本。Ansible 的命令模块将在这种情况下拯救我们。

在本章中，我们将向您介绍：

+   如何运行自定义命令和脚本

+   Ansible 命令模块：原始、命令、shell 和脚本

+   如何控制命令模块的幂等性

+   已注册的变量

+   如何创建 WordPress 应用程序

# 命令模块

Ansible 拥有四个属于这一类别的模块，并在运行系统命令或脚本时为我们提供选择。这四个模块是：

+   原始

+   命令

+   Shell

+   脚本

我们将逐个学习这些知识点。

## 使用原始模块

大多数 Ansible 模块要求目标节点上存在 Python。然而，顾名思义，原始模块提供了一种通过 SSH 与主机通信以执行原始命令而不涉及 Python 的方式。使用这个模块将完全绕过 Ansible 的模块子系统。这在某些特殊情况或情况下会非常有用。例如：

+   对于运行的 Python 版本早于 2.6 的传统系统，在运行 playbooks 之前，需要安装`Python-simplejson`包。可以使用原始模块连接到目标主机并安装先决条件软件包，然后再执行任何 Ansible 代码。

+   在网络设备（如路由器、交换机和其他嵌入式系统）的情况下，Python 可能根本不存在。这些设备仍然可以使用原始模块简单地通过 Ansible 进行管理。

除了这些例外情况之外，在所有其他情况下，建议您使用命令模块或 shell 模块，因为它们提供了控制命令何时、从何处以及如何运行的方法。

让我们看看以下给定的示例：

```
$ ansible -i customhosts all  -m raw -a "uptime"
[Output]
192.168.61.13 | success | rc=0 >>
 04:21:10 up 1 min,  1 user,  load average: 0.27, 0.10, 0.04
192.168.61.11 | success | rc=0 >>
 04:21:10 up 5 min,  1 user,  load average: 0.01, 0.07, 0.05
192.168.61.12 | success | rc=0 >>
 04:21:12 up  9:04,  1 user,  load average: 0.00, 0.01, 0.05

```

上述命令连接到使用 SSH 提供的`customhosts`清单中的所有主机，运行一个原始命令 uptime，并返回结果。即使目标主机没有安装 Python，这也能起作用。这类似于在一组主机上编写一个`for`循环以进行即席 shell 命令。

同样的命令可以转换为一个任务：

```
   - name: running a raw command 
     raw: uptime
```

## 使用命令模块

这是在目标节点上执行命令的最佳模块。该模块接受自由形式的命令序列，并允许您运行任何可以从命令行界面启动的命令。除了命令之外，我们还可以选择指定：

+   要从哪个目录运行命令

+   用于执行的 shell

+   何时不运行命令

让我们看看以下例子：

```
   - name: run a command on target node
     command: ls -ltr
     args:
       chdir: /etc
```

在这里，调用命令模块来在目标主机上运行`ls -ltr`，并使用一个参数来改变目录为`/etc`，然后再运行命令。

除了将其写为任务之外，命令模块还可以直接调用为：

```
$ ansible -i customhosts all  -m command -a "ls -ltr"

```

## 使用 shell 模块

这个模块与我们刚刚学到的命令模块非常相似。它接受一个自由形式的命令和可选参数，并在目标节点上执行它们。但是，shell 模块和命令模块之间存在一些微妙的差异，如下所列：

+   Shell 在目标主机上通过'/`bin/sh`' shell 运行命令，这也意味着任何通过此模块执行的命令都可以访问该系统上的所有 shell 变量

+   与命令模块不同，shell 也允许使用操作符，比如重定向（`<, <<, >> , >`）、管道（`|`）、`&&`和`||`

+   Shell 比命令模块不够安全，因为它可能受到远程主机上的 shell 环境的影响

让我们看看以下例子：

```
   - name: run a shell command on target node
     shell: ls -ltr | grep host >> /tmp/hostconfigs
     args:
       chdir: /etc
```

与使用命令模块类似，前面的任务使用 shell 模块运行命令序列。但是，在这种情况下，它接受操作符，如`|`和`>>`，使用`grep`进行过滤，并将结果重定向到文件。

不要将此任务指定为 Playbook 的一部分，它可以作为一个临时命令与 Ansible 一起运行，如下所示：

```
ansible -i customhosts all --sudo -m shell \
 -a "ls -ltr | grep host >> /tmp/hostconfigs2 \
chdir=/etc"
```

在这里，您需要明确指定`--sudo`选项，以及模块选项作为参数，比如`chdir=/etc`和实际命令序列。

## 使用脚本模块

到目前为止我们学到的命令模块只允许在远程主机上执行一些系统命令。在某些情况下，我们会有一个现有的脚本需要复制到远程主机上，然后在那里执行。使用 shell 或命令模块，可以通过以下两个步骤实现这一目标：

1.  使用复制模块将脚本文件传输到远程主机。

1.  然后，使用命令或 shell 模块来执行之前传输的脚本。

Ansible 有一个专门定制的模块来更高效地解决这个问题。使用脚本模块而不是命令或 shell，我们可以一步完成复制和执行脚本。

例如，请考虑以下代码片段：

```
   - name: run script sourced from inside a role
     script:  backup.sh
   - name: run script sourced from a system path on target host
     script: /usr/local/bin/backup.sh
```

如前面的代码片段所示，脚本可以从以下两者之一中源：

+   在调用这个模块时，从角色内部的任务中显示的角色的内部文件目录，如第一个示例所示

+   控制主机上的绝对系统路径（这是运行 Ansible 命令的主机）

就像所有其他模块一样，脚本也可以作为临时命令调用，如下所示：

```
$ ansible -i customhosts www --sudo -m script \

  -a "/usr/local/backup.sh"
```

这里，`script` 模块仅在清单中属于 `www` 组的主机上调用。此命令将从控制主机复制一个位于 `/usr/local/backup.sh` 的脚本，并在目标节点上运行它；在本例中，所有属于 `www` 组的主机。

# 部署 WordPress 应用程序 - 一种实践方法

在我们的第一个迭代中，我们已经配置了一个 Nginx Web 服务器和一个 MySQL 数据库来托管一个简单的网页。我们现在将配置一个 WordPress 应用程序在 Web 服务器上托管新闻和博客。

### 注意

**情景：**

在第一次迭代中，我们已经配置了一个 Nginx Web 服务器和一个 MySQL 数据库来托管一个简单的网页。现在，我们将在 Web 服务器上配置一个 WordPress 应用程序来托管新闻和博客。

WordPress 是一个流行的基于 LAMP 平台的开源 Web 发布框架，它是 Linux、Apache、MySQL 和 PHP。WordPress 是一个简单而灵活的开源应用程序，用于支持许多博客和动态网站。运行 WordPress 需要一个 Web 服务器、PHP 和 MySQL 数据库。我们已经配置了一个 Nginx Web 服务器和 MySQL 数据库。我们将通过创建一个角色来安装和配置 WordPress，然后稍后配置 PHP。

要创建角色，我们将使用前一章节中学到的 Ansible-Galaxy 工具：

```
$ ansible-galaxy init --init-path roles/ wordpress

```

这将创建 WordPress 角色所需的脚手架。到目前为止，我们知道核心逻辑放在任务中，并由文件、模板、处理程序等支持。我们将首先编写任务以安装和配置 WordPress。首先，我们将创建主任务文件，如下所示：

```
---
# tasks file for wordpress
# filename: roles/wordpress/tasks/main.yml
 - include: install.yml 
 - include: configure.yml
```

### 注意

我们遵循最佳实践，并进一步模块化任务。我们将创建一个 `install.yml` 文件和一个 `configure.yml` 文件，并从主文件中包含它们，而不是将所有内容放在 `main.yml` 文件中。

## 安装 WordPress

WordPress 的安装过程将从任务目录中的 `install.yml` 文件中处理。安装 WordPress 的过程通常涉及：

1.  从 [`wordpress.org`](https://wordpress.org) 下载 WordPress 安装包。

1.  解压安装包。

1.  将提取的目录移动到 Web 服务器的文档“根”目录中。

我们将开始为上述提到的每个步骤编写代码，如下所示：

```
---
# filename: roles/wordpress/tasks/install.yml
  - name: download wordpress
    command: /usr/bin/wget -c https://wordpress.org/latest.tar.gz
    args: 
      chdir: "{{ wp_srcdir }}"
      creates: "{{ wp_srcdir }}/latest.tar.gz"
    register: wp_download
```

我们在前面的步骤中看到了一些新功能。让我们分析一下这段代码：

+   我们正在使用新的样式编写任务。除了为任务使用键值对外，我们还可以将参数分开，并将它们以键值格式的每一行写入。

+   要下载 WordPress 安装程序，我们使用了带有 `wget` 命令的命令模块。该命令采用具有附加参数的可执行序列，这些参数是 `chdir` 和 `creates`。

+   `Creates` 在这里是一个特殊选项。通过此选项，我们指定了 WordPress 安装程序正在下载的文件路径。我们将看看这对我们有什么用处。

+   我们还将此模块的结果注册到名为 `wp_download` 的变量中，我们将在后续任务中使用它。

### 提示

建议您使用 Ansible 内置的 `get_url` 模块通过 HTTP/FTP 协议下载文件。由于我们想要演示命令模块的使用方法，我们选择使用它而不是使用 `get_url` 模块。

现在让我们来看一下我们之前介绍的新概念。

### 控制命令模块的幂等

Ansible 自带了许多内置模块。正如我们在第一章中所学到的 *Blueprinting Your Infrastructure* 中提到的那样，大多数这些模块都是幂等的，并且确定配置漂移的逻辑已内置到模块代码中。

但是，命令模块允许我们运行本质上不是幂等的 shell 命令。由于命令模块无法确定任务的结果，因此预期这些模块默认情况下不是幂等的。Ansible 为我们提供了一些选项，使这些模块可以有条件地运行，并使它们成为幂等的。

以下是确定命令是否运行的两个参数：

+   `Creates`

+   `Removes`

两者都接受文件名作为参数值。在 `creates` 的情况下，如果文件存在，则不会运行命令。`removes` 命令则相反。

"creates" 和 "removes" 选项适用于除了原始模块之外的所有命令模块。

以下是如何使用 `creates` 和 `removes` 标志的一些指导原则：

+   如果您执行的命令序列或脚本创建文件，请将该文件名作为参数值提供

+   如果命令序列不创建标志，请确保在命令序列或脚本中加入创建标志文件的逻辑

### 注册变量

我们之前已经看过变量。但是，我们以前从未注册过变量。在我们编写用于下载 WordPress 的任务中，我们使用了以下选项：

```
           register: wp_download
```

此选项将任务的结果存储在名为 `wp_download` 的变量中。然后可以稍后访问此注册结果。以下是注册变量的一些重要组成部分：

+   `changed`：这显示了状态是否已更改

+   `cmd`：通过此，启动命令序列

+   `rc`：这是返回代码

+   `stdout`：这是命令的输出

+   `stdout_lines`：这是逐行输出

+   `stderr`：这些说明了错误，如果有的话

然后，这些可以作为 `wp_download.rc`、`wp_download.stdout` 访问，并且可以在模板中、动作行中或更常见的是在 `when` 语句中使用。在这种情况下，我们将使用 `wp_download` 的返回代码来决定是否提取包。这是有道理的，因为提取甚至不存在的文件是没有意义的。

### 使用 shell 模块提取 WordPress

现在让我们编写一个任务，提取 WordPress 安装程序并将其移动到所需位置。在此之前，我们还需要确保在运行此代码之前已创建文档 `root` 目录：

```
  # filename: roles/wordpress/tasks/install.yml
  - name: create nginx docroot
    file:
      path: "{{ wp_docroot }}"
      state: directory
      owner: "{{ wp_user }}"
      group: "{{ wp_group }}"

  - name: extract wordpress
    shell: "tar xzf latest.tar.gz && mv wordpress {{ wp_docroot }}/{{ wp_sitedir }}"
    args: 
      chdir: "{{ wp_srcdir }}"
      creates: "{{ wp_docroot }}/{{ wp_sitedir }}"
    when: wp_download.rc == 0
```

现在让我们分析一下刚才所写的内容：

+   我们使用 `file` 模块为 web 服务器创建文档根目录。路径、用户和组等参数都来自变量。

+   为了提取 WordPress，我们使用 `shell` 模块而不是命令。这是因为我们在这里使用 `&&` 运算符将两个命令组合在一起，而命令模块不支持这一点。

+   我们使用 `when` 语句来决定是否运行提取命令。要检查条件，我们使用之前存储在注册变量 `wp_download` 中的下载命令的返回代码。

## 配置 WordPress

下载和提取 WordPress 后，下一步是配置它。WordPress 的主要配置位于我们提取的 `wordpress` 目录下的 `wp-config.php` 中。作为良好的实践，我们将使用模板管理此配置文件。以下是配置 WordPress 的代码：

```
---
# filename: roles/wordpress/tasks/configure.yml
  - name: change permissions for wordpress site
    file:
      path: "{{ wp_docroot }}/{{ wp_sitedir }}"
      state: directory
      owner: "{{ wp_user }}"
      group: "{{ wp_group }}"
      recurse: true

  - name: get unique salt for wordpress
    local_action: command curl https://api.wordpress.org/secret-key/1.1/salt
    register: wp_salt

  - name: copy wordpress template
    template:
      src: wp-config.php.j2
      dest: "{{ wp_docroot }}/{{ wp_sitedir }}/wp-config.php"
      mode: 0644
```

让我们分析一下这段代码：

+   第一个任务递归地为所有 WordPress 文件设置权限。

+   第二个任务在本地运行命令并将结果注册到 `wp_salt` 变量中。这是为了为 WordPress 提供额外的安全密钥。这次将使用模板内的此变量。

+   最后一个任务是生成一个 Jinja2 模板并将其复制到目标主机上作为 `wp-config.php` 文件。

让我们也看一下 Jinja2 模板：

```
# filename: roles/wordpress/templates/wp-config.php.j2
<?php
define('DB_NAME', 'wp_dbname');
define('DB_USER', 'wp_dbuser');
define('DB_PASSWORD', '{{ wp_dbpass }}');
define('DB_HOST', '{{ wp_dbhost }}');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');
{{ wp_salt.stdout }}
$table_prefix  = 'wp_';
define('WP_DEBUG', false);
if ( !defined('ABSPATH') )
  define('ABSPATH', dirname(__FILE__) . '/');
require_once(ABSPATH . 'wp-settings.php');
```

在这里，我们将配置参数的值填充到变量中。另一个有趣的地方是，我们嵌入了使用 `stdout` 变量的 salt 下载的输出：

```
            {{ wp_salt.stdout }}
```

从填充变量和从注册变量的 `stdut` 获取的模板创建的结果文件将如下所示：

![配置 WordPress](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_04_01.jpg)

现在我们将这个新角色添加到 `www.yml` playbook 中，以便它在所有我们的 web 服务器上执行：

```
#filename: www.yml
  roles:
     - nginx
     - wordpress
```

然后，我们将仅针对 web 服务器运行 Ansible playbook：

```
$ ansible-playbook www.yml  -i customhosts

```

这将在所有 web 服务器主机上下载、提取和配置 WordPress。我们还没有安装 PHP 并配置 Nginx 来提供 WordPress 页面，所以我们的更改还没有反映出来。

# 回顾问题

你觉得你对本章的理解足够吗？试着回答以下问题来测试你的理解：

1.  当 Ansible 采用一揽子方法时，为什么我们还需要命令模块？

1.  何时以及为什么要使用 raw 模块？

1.  如何在命令执行时，当执行的命令不创建文件时，使用 `creates` 参数？

1.  `command` 和 `shell` 模块有何不同？什么时候会使用 shell？

1.  如果 `var3` 是一个注册变量，你将如何在模板中打印它的输出？

# 总结

在本章中，你学习了如何使用 Ansible 的命令模块运行自定义命令和脚本，即 raw、command、shell 和 script。你还学会了如何使用 `creates` 和 `removes` 标志控制命令模块的幂等性。我们开始使用注册变量来存储任务的结果，然后可以在以后有条件地运行其他任务或将输出嵌入模板中。最后，我们创建了一个角色来安装和配置 WordPress 应用程序。

在下一章中，我们将开始学习如何使用条件语句控制执行流程，如何有选择性地应用角色，以及如何在模板中使用条件控制结构。
