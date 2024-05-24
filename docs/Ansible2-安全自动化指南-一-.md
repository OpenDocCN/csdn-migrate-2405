# Ansible2 安全自动化指南（一）

> 原文：[`zh.annas-archive.org/md5/CFD4FC07D470F8B8541AAD40C25E807E`](https://zh.annas-archive.org/md5/CFD4FC07D470F8B8541AAD40C25E807E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

IT 正在经历一次巨大的范式转变。从以正常运行时间作为 IT 成功的衡量标准的时代，我们正在转向不可变基础设施的理念，根据需求，我们可以自动地随时启动和销毁服务器。Ansible 在这种转变中扮演着主导角色。它已经成为各大公司和小公司选择的工具，用于单个服务器到整个集群的任务。

本书介绍了安全自动化。我们运用对 Ansible 的知识到不同的场景和工作负载中，这些场景和工作负载围绕着安全展开，因此得名。当无聊和单调的任务被自动化时，做这些任务的人可以集中精力解决他们所面对的安全问题。这为我们学习安全（培训）的方式、我们可以存储、处理和分析日志数据的数量（DFIR）、我们如何可以在没有任何中断的情况下保持应用安全更新（安全运营），以及更多内容提供了全新的观点。

在本书中，我们将分享使用 Ansible 可以实现的各种自动化类型的经验。你可能对其中一些内容很熟悉，或者对你来说它们可能是全新的。无论如何，我们希望你不要试图规定应该如何使用 Ansible，而是希望你阅读并理解如何使用每个 playbook/工作流程，使你的安全工作更快、更好、更可靠，或者只是为自己或他人创建复杂的基础架构场景而感到开心。

如果没有 Red Hat Ansible 的同事以及其他无数的博客和项目提供的优秀文档，本书将不可能问世，他们已经创建了安全、具有弹性的 playbooks，我们都可以从中学习并使用。

本书分为三个主要部分：

+   构建有用的 playbook 所需的基本 Ansible

+   安全自动化技术和方法

+   扩展和编程 Ansible 以获得更多的安全性

我们的目标是让你快速更新你对 Ansible 的知识，然后让你变得对它更加高效，最后，你将看到如何通过扩展 Ansible 或创建你自己的安全模块来做更多事情

# 这本书涵盖的内容

第一章，*介绍 Ansible Playbooks 和 Roles*，介绍了您在 Ansible 中可能已经熟悉的术语。它们通过示例 playbooks 和运行这些 playbooks 所需的 Ansible 命令进行了解释。如果你觉得你的 Ansible 概念和技能有点生疏，可以从这里开始。

第二章，*Ansible Tower、Jenkins 和其他自动化工具*，全都是关于自动化的自动化。我们涵盖了与 Ansible 一起常用的调度自动化工具的使用，例如 Ansible Tower、Jenkins 和 Rundeck。如果您开始使用这些工具，那么记住何时安排和执行 playbooks 以及获取有关输出的通知等单调乏味的任务可以委托给这些工具，而不是留在您的头脑中。如果您还没有使用过这些工具，您应该阅读本章。

第三章，*使用加密自动备份设置加固的 WordPress*，涵盖了各种安全自动化技术和方法的探索。与任何技术或方法一样，我们所说的一些内容可能并不适用于您的用例。然而，通过采取一种主观的方法，我们向您展示了一种我们认为在很大程度上运行良好的方法。WordPress 是目前最流行的网站创建软件。通过使用 playbooks（并在 IT 自动化工具中运行），我们开始讨论一个 IT/ops 需求，即保持正在运行的服务器安全，并确保我们可以从故障中恢复。如果您负责管理网站（即使只是您自己的网站），这一章应该是有用的。如果您不使用 WordPress，在本章中有足够的内容让您思考如何将本章应用于您的用例。

第四章，*日志监视和无服务器自动防御（AWS 中的 Elastic Stack）*，涵盖了日志监视和安全自动化，就像花生酱和果冻一样。在本章中，我们使用 Ansible 在 AWS 中的服务器上设置日志监视服务器基础架构。基于攻击通知，我们使用 AWS Lambda、Dynamo DB 和 AWS Cloudwatch 等 AWS 服务创建一个几乎实时的动态防火墙服务。

第五章，*使用 OWASP ZAP 自动化 Web 应用程序安全测试*，涵盖了测试网站安全性的最常见安全工作流程之一，即使用最流行的开源工具之一 OWASP ZAP。一旦我们弄清了基本工作流程，我们就会通过 Ansible 和 Jenkins 对您的网站进行持续扫描，使其超级强大。阅读本章，了解如何使用 Ansible 在处理持续安全扫描时与 Docker 容器一起工作。这是一个确保双赢的策略！

第六章，*使用 Nessus 进行漏洞扫描*，解释了使用 Nessus 与 Ansible 进行漏洞扫描的方法。本章涵盖了进行基本网络扫描、进行安全补丁审核和枚举漏洞的方法。

第七章，*应用程序和网络的安全加固*，展示了 Ansible 已经使我们能够以声明方式表达我们的安全思想。通过利用系统状态应该是什么的想法，我们可以基于标准（如 CIS 和 NIST）以及美国国防部的 STIGs 提供的指南创建安全加固剧本。熟悉使用现有安全文档来加固应用程序和服务器的方法，但最重要的是，以可重复自描述的方式进行，这是在版本控制下进行的。如果你和我们一样，多年来一直手动执行所有这些任务，你会很感激这对安全自动化的改变。

第八章，*Docker 容器的持续安全扫描*，介绍了如何对 Docker 容器运行安全扫描工具。许多现代应用程序都使用容器部署，本章将帮助你快速了解是否有容器存在漏洞，并且一如既往地，与 Ansible Tower 结合使用，如何使这成为一个持续的过程。

第九章，*自动设置实验室进行取证收集、恶意软件分析*，特别适用于恶意软件研究人员。如果你一直想使用 Cuckoo 沙箱和 MISP，但因为设置这些工具涉及的步骤太复杂而望而却步，那么本章将为你提供帮助。

第十章，*编写用于安全测试的 Ansible 模块*，介绍了我们如何扩展 Ansible 提供的功能，并学习其他项目如何使用 Ansible 提供优秀的软件解决方案。本章和下一章，带领我们进入本书的第三部分。

有时候，尽管 Ansible 自带了许多惊人的模块，但它们仍然不足以满足我们的需求。本章探讨了创建 Ansible 模块，如果我们可以这么说的话，它并不试图对方法非常正式。记住我们想要关注的是安全自动化，我们创建了一个模块来运行使用 ZAP 代理进行网站安全扫描。提供了完整的模块，这将帮助你在很短的时间内编写和使用你自己的模块。

第十一章，*Ansible 安全最佳实践、参考和进一步阅读*，介绍了如何使用 Ansible Vault 管理密码和凭证。它将帮助你建立自己的 Ansible Galaxy 实例。我们还介绍了其他使用 Ansible 剧本进行安全解决方案的项目，如 DebOps 和 Algo。我们还介绍了 AWX，这是 Ansible Tower 的免费开源版本，并向你展示如何设置和使用它。最后，我们简要讨论了预计在 2018 年第一或第二季度发布的 Ansible 2.5 版本。

# 为了阅读本书，你需要什么

Ansible 是一种用 Python2 编写的工具。对于控制机器，如果 Python2 安装了最低版本 2.6，那就没问题了。自 Ansible 2.2 起，Python3 作为技术预览版本得到支持。

# 这本书适合谁

这本书最理想的读者是那些明白自动化是实现可重复、无错误部署和基础架构、应用程序和网络配置的关键的人。不过，我们确实想要指明这一点。

如果您是负责网站、服务器和网络安全的系统管理员，那么这本书适合您。

安全顾问和分析师将通过专注于 [第三章](https://cdp.packtpub.com/security_automation_with_ansible_2/wp-admin/post.php?post=23&action=edit#post_72)，*设置具有加密自动备份的强化 WordPress*，到 [第十章](https://cdp.packtpub.com/security_automation_with_ansible_2/wp-admin/post.php?post=23&action=edit#post_442)，*编写用于安全测试的 Ansible 模块* 而受益。即使某些工作负载不适用于您，您也将了解如何使用 Ansible 为团队提供安全服务的见解。所有 DevOps 团队都愿意与将自动化视为与安全本身一样重要的人一起工作。

希望轻松部署安全服务器的应用程序开发人员尤其应该查看 [第三章](https://cdp.packtpub.com/security_automation_with_ansible_2/wp-admin/post.php?post=23&action=edit#post_72)，*设置具有加密自动备份的强化 WordPress*，到 [第七章](https://cdp.packtpub.com/security_automation_with_ansible_2/wp-admin/post.php?post=23&action=edit#post_265)，*应用程序和网络的安全强化*。

如果您是以下人员之一，您将从这本书中受益最多：

+   之前使用过 Ansible 基本命令的人

+   对 Linux 和 Windows 操作系统熟悉的人。

+   对 IP 地址、网络和软件安装程序有基本了解的人。

# 惯例

在本书中，您将找到一些区分不同类型信息的文本样式。以下是这些样式的一些示例及其含义的解释。文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“`harden.yml` 执行 MySQL 服务器配置的加固” 代码块设置如下：

```
- name: deletes anonymous mysql user
  mysql_user:
    user: ""
    state: absent
    login_password: "{{ mysql_root_password }}"
    login_user: root
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```
- name: deletes anonymous mysql user
  mysql_user:
    user: ""
    state: absent
    login_password: "{{ mysql_root_password }}"
    login_user: root
```

任何命令行输入或输出写成如下格式：

```
ansible-playbook -i inventory playbook.yml
```

**新术语** 和 **重要单词** 以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“点击 确认安全异常 并继续执行安装步骤”。

警告或重要提示会以这种方式出现。

提示和技巧会以这种方式出现。

# 读者反馈

我们的读者的反馈意见始终受到欢迎。告诉我们您对这本书的看法 - 您喜欢或不喜欢什么。读者的反馈对我们很重要，因为它帮助我们开发您真正能充分利用的标题。要向我们发送一般反馈，只需发送电子邮件至`feedback@packtpub.com`，并在您的消息主题中提到书名。如果您在某个专题上有专业知识，并且您有兴趣撰写或贡献一本书，请参阅我们的作者指南，网址为[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在，您是 Packt 书籍的自豪所有者，我们有很多东西可以帮助您充分利用您的购买。

# 下载示例代码

你可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果你在其他地方购买了这本书，你可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)，并注册以直接将文件通过电子邮件发送给你。按照以下步骤下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册到我们的网站。

1.  将鼠标指针悬停在顶部的 SUPPORT 选项卡上。

1.  单击“代码下载与勘误”。

1.  在搜索框中输入书名。

1.  选择您要下载代码文件的书籍。

1.  从下拉菜单中选择购买本书的位置。

1.  单击“代码下载”。

下载文件后，请确保使用以下最新版本的解压缩或提取文件夹：

+   Windows 上的 WinRAR / 7-Zip

+   Mac 上的 Zipeg / iZip / UnRarX

+   Linux 上的 7-Zip / PeaZip

本书的代码捆绑包也托管在 GitHub 上，地址为[`github.com/PacktPublishing/Security-Automation-with-Ansible-2`](https://github.com/PacktPublishing/Security-Automation-with-Ansible-2)。我们还提供了来自我们丰富书籍和视频目录的其他代码捆绑包，地址为[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)。来看看吧！

# 下载本书的彩色图像

我们还为您提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。彩色图像将帮助您更好地理解输出的变化。您可以从[`www.packtpub.com/sites/default/files/downloads/SecurityAutomationwithAnsible2_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/SecurityAutomationwithAnsible2_ColorImages.pdf)下载此文件。

# 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误还是会发生。如果您在我们的书籍中发现错误——也许是文字或代码上的错误——我们将不胜感激地请您向我们报告。通过这样做，您可以避免其他读者的困扰，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击"勘误提交表格"链接，并输入您的勘误详情。一旦您的勘误被验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该书籍的"勘误"部分的任何现有勘误列表中。要查看之前提交的勘误，请转至[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索框中输入书名。所需信息将显示在"勘误"部分下面。

# 盗版

互联网上的版权物资盗版是跨所有媒体持续存在的问题。在 Packt，我们非常重视保护我们的版权和许可。如果您在互联网上的任何形式上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。请通过`copyright@packtpub.com`与我们联系，并附上可疑盗版材料的链接。感谢您帮助我们保护我们的作者和我们为您带来有价值内容的能力。

# 问题

如果您对本书的任何方面有问题，请通过`questions@packtpub.com`与我们联系，我们将尽力解决问题。


# 第一章：Ansible Playbooks 和 Roles 介绍

根据维基百科，Ansible 是一个自动化软件配置、配置管理和应用部署的开源自动化引擎。但你已经知道这一点了。这本书是关于将 IT 自动化软件的理念应用于信息安全自动化领域。

本书将带领你踏上 *安全自动化* 之旅，展示 Ansible 在现实世界中的应用。

在这本书中，我们将以一种结构化、模块化的方式，使用一种简单易读的格式 YAML 自动化执行与安全相关的任务。最重要的是，你将学会创建的内容是可重复的。这意味着一旦完成，你可以专注于微调、扩展范围等。这个工具确保我们可以构建和销毁从简单应用堆栈到简单但广泛的多应用框架一切。

如果你已经玩过 Ansible，我们假设你已经这样做了，那么你肯定遇到了以下一些术语：

+   Playbook

+   Ansible 模块

+   YAML

+   Roles

+   模板（Jinja2）

别担心，我们将在本章节中解释所有上述术语。一旦你对这些主题感到舒适，我们将继续覆盖调度器工具，然后转向构建安全自动化 playbooks。

# 需记住的 Ansible 术语

像所有新的主题或话题一样，熟悉该主题或话题的术语是一个不错的主意。我们将介绍一些我们将在整本书中使用的 Ansible 术语，如果在任何时候你无法跟上，你可能需要回到这一章节，重新理解特定术语。

# Playbooks

在经典意义上，playbook 是关于足球比赛中的进攻和防守战术的。球员们会记录这些战术（行动计划），通常以图表形式呈现在一本书中。

在 Ansible 中，playbook 是一个 IT 过程的一系列有序步骤或指令。把它想象成一本可以被人类和计算机同时阅读和理解的精心撰写的说明书。

在随后的章节中，我们将专注于安全方面的自动化，引导我们构建简单和复杂的 playbooks。

一个 Ansible playbook 命令看起来像这样：

```
ansible-playbook -i inventory playbook.yml
```

暂时忽略`-i` 标志，并注意 playbook 文件的扩展名。

正如 [`docs.ansible.com/ansible/playbooks_intro.html`](http://docs.ansible.com/ansible/playbooks_intro.html) 中所述：

"Playbooks 以 YAML 格式表达（参见 YAML 语法 ([`docs.ansible.com/ansible/YAMLSyntax.html`](http://docs.ansible.com/ansible/YAMLSyntax.html)）, 且具有最少的语法，其旨在有意尝试不成为编程语言或脚本，而是一个配置或过程的模型。"

# Ansible 模块

Ansible 随附了一些模块（称为 **模块库**），可以直接在远程主机上执行或通过 playbook 执行。Playbook 中的任务调用模块来完成工作。

Ansible 有许多模块，其中大多数是由社区贡献和维护的。核心模块由 Ansible 核心工程团队维护，并将随着 Ansible 一起发布。

用户还可以编写自己的模块。这些模块可以控制系统资源，如服务、软件包或文件（实际上是任何东西），或者处理执行系统命令。

下面是 Ansible 提供的模块列表：[`docs.ansible.com/ansible/latest/modules_by_category.html#module-index`](http://docs.ansible.com/ansible/latest/modules_by_category.html#module-index)。

如果您使用 Dash ([`kapeli.com/dash`](https://kapeli.com/dash)) 或 Zeal ([`zealdocs.org/`](https://zealdocs.org/))，您可以下载离线版本以便参考。

模块也可以通过命令行执行。我们将使用模块来编写 playbook 中的所有任务。所有模块在技术上都返回 JSON 格式的数据。

模块应该是幂等的，如果检测到当前状态与期望的最终状态匹配，则应该避免进行任何更改。当使用 Ansible playbook 时，这些模块可以触发 *change events*，以通知 *handlers* 运行额外的任务。

每个模块的文档可以通过命令行工具 `ansible-doc` 访问：

```
$ ansible-doc apt

```

我们可以列出主机上所有可用的模块：

```
$ ansible-doc -l
```

通过执行 `httpd` 模块，在所有节点分组为 `webservers` 下启动 Apache Web 服务器。注意使用了 `-m` 标志：

```
$ ansible webservers -m service -a "name=httpd state=started"
```

这个片段展示了完全相同的命令，但是在一个 YAML 语法的 playbook 中：

```
- name: restart webserver
  service:
    name: httpd
    state: started
```

每个模块包含多个参数和选项，通过查看它们的文档和示例来了解模块的特性。

# 用于编写 Ansible playbook 的 YAML 语法

Ansible playbook 使用 **YAML** 编写，它代表 **YAML Ain't Markup Language**。

根据官方文档 ([`yaml.org/spec/current.html`](http://yaml.org/spec/current.html))：

"YAML Ain't Markup Language"（缩写为 YAML）是一种设计成对人类友好并且与现代编程语言一起使用的数据序列化语言，用于日常任务。

Ansible 使用 YAML 是因为它比其他常见的数据格式（如 XML 或 JSON）更易于人类阅读和编写。所有的 YAML 文件（无论它们是否与 Ansible 相关）都可以选择以 `---` 开始并以 `...` 结束。这是 YAML 格式的一部分，表示文档的开始和结束。

YAML 文件应该以 `.yaml` 或 `.yml` 结尾。YAML 区分大小写。

您还可以使用诸如 [www.yamllint.com](http://www.yamllint.com) 这样的 Linters，或者您的文本编辑器插件来进行 YAML 语法的代码检查，这有助于您排除任何语法错误等等。

这里是一个简单 playbook 的示例，展示了来自 Ansible 文档的 YAML 语法（[`docs.ansible.com/ansible/playbooks_intro.html#playbook-language-example`](http://docs.ansible.com/ansible/playbooks_intro.html#playbook-language-example)）：

```
- hosts: webservers
  vars:
    http_port: 80
    max_clients: 200
  remote_user: root

  tasks:
  - name: Ensure apache is at the latest version
    yum:
      name: httpd
      state: latest
  - name: Write the apache config file
    template:
      src: /srv/httpd.j2
      dest: /etc/httpd.conf

    notify:
    - restart apache

  - name: Ensure apache is running (and enable it at boot)
    service:
      name: httpd
      state: started
      enabled: yes

  handlers:
    - name: Restart apache
      service:
        name: httpd
        state: restarted
```

# Ansible 角色

虽然 playbook 提供了一种以预定义顺序执行 *plays* 的好方法，但 Ansible 上有一个很棒的功能将整个理念提升到完全不同的层次。角色是一种方便的方式来捆绑任务，支持文件和模板等支持资产，并带有一组自动搜索路径。

通过使用大多数程序员熟悉的 *包含* 文件和文件夹的概念，并指定被包含的内容，playbook 变得无限可读且易于理解。角色基本上由任务、处理程序和配置组成，但通过向 playbook 结构添加附加层，我们可以轻松获得大局观以及细节。

这样可以实现可重用的代码，并且在负责编写 playbook 的团队中分工明确。例如，数据库专家编写了一个角色（几乎像是一个部分 playbook）来设置数据库，安全专家则编写了一个加固此类数据库的角色。

虽然可以在一个非常大的文件中编写 playbook，但最终你会想要重用文件并开始组织事务。

大而复杂的 playbook 难以维护，很难重用大 playbook 的部分。将 playbook 拆分为角色允许非常高效的代码重用，并使 playbook 更容易理解。

在构建大 playbook 时使用角色的好处包括：

+   协作编写 playbooks

+   重用现有角色

+   角色可以独立更新、改进

+   处理变量、模板和文件更容易

**LAMP** 通常代表 **Linux，Apache，MySQL，PHP**。这是一种流行的软件组合，用于构建 Web 应用程序。如今，在 PHP 世界中另一个常见的组合是 **LEMP**，即 **Linux，NGINX，MySQL，PHP**。

这是一个可能的 LAMP 堆栈 `site.yml` 的示例：

```
- name: LAMP stack setup on ubuntu 16.04
  hosts: all
  gather_facts: False
  remote_user: "{{remote_username}}"
  become: yes

 roles:
   - common
   - web
   - db
   - php
```

注意角色列表。仅通过阅读角色名称，我们就可以了解该角色下可能包含的任务类型。

# 使用 Jinja2 的模板

Ansible 使用 Jinja2 模板来实现动态表达式和访问变量。在 playbook 和任务中使用 Jinja2 变量和表达式使我们能够创建非常灵活的角色。通过向这种方式编写的角色传递变量，我们可以使相同的角色执行不同的任务或配置。使用模板语言，比如 Jinja2，我们能够编写简洁且易于阅读的 playbooks。

通过确保所有模板化发生在 Ansible 控制器上，Jinja2 不需要在目标机器上。只复制所需的数据，这减少了需要传输的数据量。正如我们所知，数据传输量越少，通常执行速度越快，反馈越快。

# Jinja 模板示例

一个良好模板语言的标志是允许控制内容而不显得是完整的编程语言。Jinja2 在这方面表现出色，通过提供条件输出的能力，如使用循环进行迭代等等。

让我们看一些基本示例（显然是 Ansible playbook 相关的），看看是什么样子。

# 条件示例

仅当操作系统家族为 `Debian` 时执行：

```
tasks:
  - name: "shut down Debian flavored systems"
    command: /sbin/shutdown -t now
    when: ansible_os_family == "Debian"
```

# 循环示例

下面的任务使用 Jinja2 模板添加用户。这允许 playbooks 中的动态功能。我们可以使用变量在需要时存储数据，只需更新变量而不是整个 playbook：

```
- name: add several users
  user:
    name: "{{ item.name }}"
    state: present
    groups: "{{ item.groups }}"
  with_items:
    - { name: 'testuser1', groups: 'wheel' }
    - { name: 'testuser2', groups: 'root' }
```

# LAMP 栈 playbook 示例 - 结合所有概念

我们将看看如何使用我们迄今学到的技能编写一个 LAMP 栈 playbook。这是整个 playbook 的高层次结构：

```
inventory               # inventory file
group_vars/             #
   all.yml              # variables
site.yml                # master playbook (contains list of roles)
roles/                  #
    common/             # common role
        tasks/          #
            main.yml    # installing basic tasks
    web/                # apache2 role
        tasks/          #
            main.yml    # install apache
        templates/      #
            web.conf.j2 # apache2 custom configuration
        vars/           # 
            main.yml    # variables for web role 
        handlers/       #
            main.yml    # start apache2
    php/                # php role
        tasks/          # 
            main.yml    # installing php and restart apache2
    db/                 # db role
        tasks/          #
            main.yml    # install mysql and include harden.yml
            harden.yml  # security hardening for mysql
        handlers/       #
            main.yml    # start db and restart apache2
        vars/           #
            main.yml    # variables for db role
```

让我们从创建一个清单文件开始。下面的清单文件是使用静态手动输入创建的。这是一个非常基本的静态清单文件，我们将在其中定义一个主机，并设置用于连接到它的 IP 地址。

根据需要配置以下清单文件：

```
[lamp]
lampstack    ansible_host=192.168.56.10
```

下面的文件是 `group_vars/lamp.yml`，其中包含所有全局变量的配置：

```
remote_username: "hodor"
```

下面的文件是 `site.yml`，这是启动的主要 playbook 文件：

```
- name: LAMP stack setup on Ubuntu 16.04
 hosts: lamp
 gather_facts: False
 remote_user: "{{ remote_username }}"
 become: True

 roles:
   - common
   - web
   - db
   - php
```

下面是 `roles/common/tasks/main.yml` 文件，它将安装 `python2`、`curl` 和 `git`：

```
# In ubuntu 16.04 by default there is no python2
- name: install python 2
  raw: test -e /usr/bin/python || (apt -y update && apt install -y python-minimal)

- name: install curl and git
  apt:
    name: "{{ item }}"
    state: present
    update_cache: yes

  with_items:
    - curl
    - git
```

下面的任务，`roles/web/tasks/main.yml`，执行多个操作，如安装和配置 `apache2`。它还将服务添加到启动过程中：

```
- name: install apache2 server
  apt:
    name: apache2
    state: present

- name: update the apache2 server configuration
  template: 
    src: web.conf.j2
    dest: /etc/apache2/sites-available/000-default.conf
    owner: root
    group: root
    mode: 0644

- name: enable apache2 on startup
  systemd:
    name: apache2
    enabled: yes
  notify:
    - start apache2
```

`notify` 参数将触发 `roles/web/handlers/main.yml` 中找到的处理程序：

```
- name: start apache2
  systemd:
    state: started
    name: apache2

- name: stop apache2
  systemd:
    state: stopped
    name: apache2

- name: restart apache2
  systemd:
    state: restarted
    name: apache2
    daemon_reload: yes
```

模板文件将从 `role/web/templates/web.conf.j2` 中获取，该文件使用 Jinja 模板，还从本地变量中获取值：

```
<VirtualHost *:80><VirtualHost *:80>
    ServerAdmin {{server_admin_email}}
    DocumentRoot {{server_document_root}}

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

本地变量文件位于 `roles/web/vars/main.yml`：

```
server_admin_email: hodor@localhost.local
server_document_root: /var/www/html
```

类似地，我们也会编写数据库角色。下面的文件 `roles/db/tasks/main.yml` 包括在提示时安装数据库服务器并分配密码。在文件末尾，我们包含了 `harden.yml`，它执行另一组任务：

```
- name: set mysql root password
  debconf:
    name: mysql-server
    question: mysql-server/root_password
    value: "{{ mysql_root_password | quote }}"
    vtype: password

- name: confirm mysql root password
  debconf: 
    name: mysql-server
    question: mysql-server/root_password_again
    value: "{{ mysql_root_password | quote }}"
    vtype: password

- name: install mysqlserver
  apt:
    name: "{{ item }}"
    state: present 
  with_items:
    - mysql-server
    - mysql-client

- include: harden.yml
```

`harden.yml` 执行 MySQL 服务器配置的加固：

```
- name: deletes anonymous mysql user
  mysql_user:
    user: ""
    state: absent
    login_password: "{{ mysql_root_password }}"
    login_user: root

- name: secures the mysql root user
  mysql_user: 
    user: root
    password: "{{ mysql_root_password }}"
    host: "{{ item }}"
    login_password: "{{mysql_root_password}}"
    login_user: root
 with_items:
   - 127.0.0.1
   - localhost
   - ::1
   - "{{ ansible_fqdn }}"

- name: removes the mysql test database
  mysql_db:
    db: test
    state: absent
    login_password: "{{ mysql_root_password }}"
    login_user: root

- name: enable mysql on startup
  systemd:
    name: mysql
    enabled: yes

  notify:
    - start mysql
```

`db` 服务器角色也有类似于 `web` 角色的 `roles/db/handlers/main.yml` 和本地变量：

```
- name: start mysql
  systemd:
    state: started
    name: mysql

- name: stop mysql
  systemd:
    state: stopped
    name: mysql

- name: restart mysql
  systemd:
    state: restarted
    name: mysql
    daemon_reload: yes
```

下面的文件是 `roles/db/vars/main.yml`，其中包含配置服务器时的 `mysql_root_password`。我们将在未来的章节中看到如何使用 `ansible-vault` 来保护这些明文密码：

```
mysql_root_password: R4nd0mP4$$w0rd
```

现在，我们将安装 PHP 并通过重新启动 `roles/php/tasks/main.yml` 服务来配置它与 `apache2` 一起工作：

```
- name: install php7
  apt:
    name: "{{ item }}"
    state: present
  with_items:
    - php7.0-mysql
    - php7.0-curl
    - php7.0-json
    - php7.0-cgi
    - php7.0
    - libapache2-mod-php7

- name: restart apache2
  systemd:
    state: restarted
    name: apache2
    daemon_reload: yes
```

要运行此剧本，我们需要在系统路径中安装 Ansible。请参阅[`docs.ansible.com/ansible/intro_installation.html`](http://docs.ansible.com/ansible/intro_installation.html)获取安装说明。

然后针对 Ubuntu 16.04 服务器执行以下命令来设置 LAMP 堆栈。当提示系统访问用户 `hodor` 时，请提供密码：

```
$ ansible-playbook -i inventory site.yml
```

完成剧本执行后，我们将准备在 Ubuntu 16.04 机器上使用 LAMP 堆栈。您可能已经注意到，每个任务或角色都可以根据我们在剧本中的需要进行配置。角色赋予了将剧本泛化并使用变量和模板轻松定制的能力。

# 摘要

我们已经使用 Ansible 的各种功能对一个相当不错的真实世界堆栈进行了编码。通过思考 LAMP 堆栈概述中的内容，我们可以开始创建角色。一旦我们确定了这一点，就可以将单个任务映射到 Ansible 中的模块。任何需要复制预定义配置但具有动态生成输出的任务都可以使用我们模板中的变量和 Jinja2 提供的结构来完成。

我们将使用同样的方法来进行各种安全相关的设置，这些设置可能需要一些自动化用于编排、操作等。一旦我们掌握了在运行于我们笔记本电脑上的虚拟机上执行此操作的方法，它也可以被重新用于部署到您喜欢的云计算实例上。输出是人类可读的文本，因此可以添加到版本控制中，各种角色也可以被重复使用。

现在，我们已经对本书中将要使用的术语有了相当不错的了解，让我们准备好最后一块拼图。在下一章中，我们将学习和理解如何使用自动化和调度工具，例如 Ansible Tower、Jenkins 和 Rundeck，根据某些事件触发器或时间持续时间来管理和执行基于剧本的操作。


# 第二章：Ansible Tower、Jenkins 和其他自动化工具

Ansible 很强大。一旦你意识到写下配置和提供系统的方式的无数好处，你就再也不想回去了。事实上，你可能想要继续为复杂的云环境编写 playbooks，为数据科学家部署堆栈。经验法则是，如果你可以编写脚本，你就可以为其创建一个 playbook。

假设你已经这样做了。为各种场景构建不同的 playbooks。如果你看到了将基础架构的构建和配置编码化的优势，你显然会想要将你的 playbooks 放入版本控制下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/c7d7e4ae-5685-4cd2-b4aa-fbb1f6e6dd35.png)

存储在版本控制下的多个 playbooks，准备部署到系统进行配置

到目前为止，我们已经解决了围绕自动化的有趣挑战：

+   现在我们有了对多个目标执行 *重放* 命令的能力

+   记住，如果 playbooks 是以幂等的方式，我们可以安全地对我们的目标运行它们 *n* 次而不必担心任何问题

+   凭借它们是基于文本的文档，我们获得了版本控制和由此带来的所有好处

现在仍然需要手动的是，我们需要某人或某物来执行 `ansible-playbook` 命令。不仅如此，这个某人或某物还需要执行以下操作：

+   记住何时执行 playbooks

+   相应地安排它们的时间表

+   安全存储秘密（通常我们需要 SSH 密钥才能登录）

+   存储输出或记住重新运行 playbook 如果出现失败的情况

当我们想起记住细微之处时，我们都可以渴望成为那样的壮观人物，或者我们可以接受，这些注重细节、基于调度的任务最好由称职的软件而不是超人来完成！

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/5754dba5-fa69-4104-9f99-8777b6372c2a.png)

超人将有能力记住、安排、执行并通知有关 playbooks 的情况

原来我们并不都需要成为超人。我们可以简单地使用安排和自动化工具，比如 Ansible Tower、Jenkins 或 Rundeck 来完成我们之前定义的所有任务，以及更多。

在本章中，我们将查看我们提到的所有三个工具，以了解它们提供了什么，以便将我们的自动化提升到自动化的下一个抽象层次。

具体来说，我们将涵盖以下主题：

+   安装和配置 Ansible Tower

+   使用 Ansible Tower 管理 playbooks 和调度

+   安装和配置 Jenkins

+   安装和配置 Rundeck

# 使用调度工具来启用下一层次的自动化

调度和自动化工具使我们能够自动化诸如持续集成和持续交付等任务。它们能够通过提供以下相当标准的服务来实现这一点：

+   我们可以使用基于 web 的 UI 来配置它们

+   通常，这是一个基于 REST 的 API，以便我们可以以编程方式使用它们的功能

+   能够对其本地存储或可能是另一个服务（OAuth/**安全断言标记语言** (**SAML**)）进行身份验证

+   它们从根本上为我们提供了一种清晰的方式来自动化任务以适应我们的工作流程

大多数与安全相关的自动化归结为一遍又一遍地执行类似的任务并查看差异。当您从事安全运营和安全评估时，这一点尤为真实。

请记住，通过使用 Ansible 角色和包含它们的 playbooks，我们已经在朝着进行安全自动化的目标迈出了一步。现在我们的目标是消除记得执行那些 playbooks 的麻烦工作并开始进行。

有三个主要竞争对手用于这种类型的自动化。它们在这里列出并描述：

+   Ansible Tower

+   Jenkins

+   Rundeck

| **工具** | **我们的看法** | **许可证 ** |
| --- | --- | --- |
| Ansible Tower | 由 Ansible 制造商推出的出色工具，非常适合 IT 自动化的理念，我们将其扩展到我们的安全需求。 | 付费，有免费试用版 |
| Jenkins | 工作流引擎，很多 CI/CD 流水线的主力。有数百个插件来扩展其核心功能。如果考虑价格或许可证问题，这是最佳选择。 | 免费和开源  |
| Rundeck | 用于作业调度和自动化的优秀工具。  | 有付费的专业版本 |

在本章中，我们将安装和配置所有三个工具，以便让您开始使用。

红帽公司于 2015 年 10 月收购了 Ansible，他们表示计划开源 Ansible Tower。他们在 2016 年 AnsibleFest 上宣布了这一消息。您可以在 [`www.ansible.com/open-tower`](https://www.ansible.com/open-tower) 上关注该进展。

# 起步运行

让我们从设置我们提到的三个工具开始，看一下它们的一些特点。

# 设置 Ansible Tower

有多种方法可以安装 Ansible Tower 试用版。最简单的设置方式是使用它们现有的镜像从 [`www.ansible.com/tower-trial`](https://www.ansible.com/tower-trial) 获取。

您还可以使用他们的捆绑安装手动设置。在安装之前，请查看 [`docs.ansible.com/ansible-tower/3.1.4/html/installandreference/index.html`](http://docs.ansible.com/ansible-tower/3.1.4/html/installandreference/index.html) 的要求。

运行以下命令在 Ubuntu 16.04 操作系统中安装 Ansible Tower：

```
$ sudo apt-get install software-properties-common

$ sudo apt-add-repository ppa:ansible/ansible

$ wget https://releases.ansible.com/ansible-tower/setup/ansible-tower-setup-latest.tar.gz

$ tar xvzf ansible-tower-setup-latest.tar.gz

$ cd ansible-tower-setup-<tower_version>
```

然后编辑清单文件以更新密码和其他变量，并运行设置。 清单文件包含了用于塔管理员登录帐户的`admin_password`，如果我们正在设置多节点设置，则需要 Postgres 数据库的`pg_host`和`pg_port`。最后是用于排队操作的`rabbitmq`详情。

```
[tower]
localhost ansible_connection=local

[database]

[all:vars]
admin_password='strongpassword'

pg_host='' # postgres.domain.com
pg_port='' #5432

pg_database='awx'
pg_username='awx'
pg_password='postgrespasswordforuserawx'

rabbitmq_port=5672
rabbitmq_vhost=tower
rabbitmq_username=tower
rabbitmq_password='giverabitmqpasswordhere'
rabbitmq_cookie=cookiemonster

# Needs to be true for fqdns and ip addresses
rabbitmq_use_long_name=false
$ sudo ./setup.sh
```

如果您已经安装了 Vagrant，则可以简单地下载他们的 Vagrant box 来开始使用。

在运行以下命令之前，请确保您的主机系统上已安装了 Vagrant：

`$ vagrant init ansible/tower`

`$ vagrant up`

`$ vagrant ssh`

它会提示您输入 IP 地址、用户名和密码以登录到 Ansible Tower 仪表板。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/5d64f647-7035-4b4f-929d-25e92ffadc07.png)

然后在浏览器中导航至 `https://10.42.0.42` 并接受 SSL 错误以继续。可以通过在 `/etc/tower` 配置中提供有效证书来修复此 SSL 错误，并需要重新启动 Ansible Tower 服务。输入登录凭据以访问 Ansible Tower 仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/129dc8fb-abed-4a43-853a-5a00bf690e8d.png)

登录后，会提示您输入 Ansible Tower 许可证：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/7046a7ee-92b0-49ba-8cf5-05e48c05cd10.png)

Ansible Tower 还提供了**基于角色的身份验证控制**（**RBAC**），为不同的用户和组提供了细粒度的控制，以管理 Tower。下面的截图显示了使用系统管理员权限创建新用户的过程：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/d59cb20b-cb31-40c8-8cb6-4e551ec6a913.png)

要将清单添加到 Ansible Tower 中，我们可以简单地手动输入它，还可以使用动态脚本从云提供商那里收集清单，方法是提供身份验证（或）访问密钥。下面的截图显示了我们如何将清单添加到 Ansible Tower 中，还可以通过在 YAML 或 JSON 格式中提供变量来为不同的主机提供变量：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/567b4e71-7c73-4b16-b147-56168d855c54.png)

我们还可以通过在凭据管理中提供它们来向 tower 添加凭据（或）密钥，这些凭据也可以重复使用。

Ansible Tower 中存储的秘密信息使用每个 Ansible Tower 集群独有的对称密钥进行加密。一旦存储在 Ansible Tower 数据库中，凭据只能在 Web 界面中使用，而不能查看。Ansible Tower 可以存储的凭据类型包括密码、SSH 密钥、Ansible Vault 密钥和云凭据。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/78d67f33-0a8a-440d-a564-5ad6814bf7f0.png)

一旦我们收集了清单，就可以创建作业来执行 Playbook 或即席命令操作：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/4c1877ad-17b2-4efe-b7e8-674c83e238c9.png)

在这里，我们选择了 `shell` 模块，并针对两个节点运行了 `uname -a` 命令：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/fc8e0186-52a9-4dce-b9f7-a65a0e4c3183.png)

一旦启动执行，我们就可以在仪表板中看到标准输出。我们也可以使用 REST API 访问：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/3ff8c0c0-ec93-40ec-923a-60daef08eb5b.png)

请参考 Ansible Tower 文档获取更详细的参考资料。

还有另一种使用 Ansible Tower 的方式：`tower-cli` 是 Ansible Tower 的命令行工具。可以通过 `pip install ansible-tower-cli` 命令开始使用。

Ansible Tower REST API 是与系统交互的一种非常强大的方式。

这基本上允许您使用易于遵循的 Web GUI 设计 Playbook 工作流程等，同时还可以从另一个 CI/CD 工具（如 Jenkins）调用此功能。顺便说一句，Jenkins 是接下来要设置和学习的软件。

# 设置 Jenkins

让我们使用一个 Ansible playbook 来安装 Jenkins 并开始使用它。

以下代码片段是我们为在 Ubuntu 16.04 操作系统中设置 Jenkins 编写的 Ansible playbook 的片段。

完成设置后，Playbook 将返回首次登录到应用程序所需的默认管理员密码：

```
- name: installing jenkins in ubuntu 16.04
  hosts: "192.168.1.7"
  remote_user: ubuntu
  gather_facts: False
  become: True

tasks:
  - name: install python 2
    raw: test -e /usr/bin/python || (apt -y update && apt install -y python-minimal)

  - name: install curl and git
    apt: name={{ item }} state=present update_cache=yes

    with_items:
      - curl
      - git

```

```
  - name: adding jenkins gpg key
    apt_key:
      url: https://pkg.jenkins.io/debian/jenkins-ci.org.key
      state: present

  - name: jeknins repository to system
    apt_repository:
      repo: http://pkg.jenkins.io/debian-stable binary/
      state: present

  - name: installing jenkins
    apt:
      name: jenkins
      state: present
      update_cache: yes

  - name: adding jenkins to startup
    service:
      name: jenkins
      state: started
      enabled: yes

  - name: printing jenkins default administration password
    command: cat /var/lib/jenkins/secrets/initialAdminPassword
    register: jenkins_default_admin_password

  - debug:
      msg: "{{ jenkins_default_admin_password.stdout }}"

```

要设置 Jenkins，请运行以下命令。其中 `192.168.1.7` 是 Jenkins 将被安装在的服务器 IP 地址：

```
ansible-playbook -i '192.168.1.7,' site.yml --ask-sudo-pass
```

现在我们可以配置 Jenkins 来安装插件、运行定期作业以及执行许多其他操作。首先，我们必须通过浏览到 `http://192.168.1.7:8080` 并提供自动生成的密码来导航到 Jenkins 仪表板。如果 Playbook 在没有任何错误的情况下运行，则会在操作结束时显示密码：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/b53f3348-ad91-47a6-8fed-99f1792e07ce.png)

通过填写详细信息并确认登录到 Jenkins 控制台来创建新用户：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/3655c6ce-9792-4549-86ec-846d12b19063.png)

现在我们可以在 Jenkins 中安装自定义插件，导航至“管理 Jenkins”选项卡，选择“管理插件”，然后导航至“可用”选项卡。在“过滤器:”中输入插件名称为 `Ansible`。然后选中复选框，单击“安装但不重新启动”：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/fdaded9b-7399-4635-a2e5-635a9d4ea6bf.png)

现在我们准备好使用 Jenkins 的 Ansible 插件了。在主仪表板中创建一个新项目，为其命名，然后选择自由风格项目以继续：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/eff81a92-6242-49ab-8ebc-4b35971e64b7.png)

现在我们可以配置构建选项，这是 Jenkins 将为我们提供更大灵活性以定义我们自己的触发器、构建说明和后构建脚本的地方：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/d7712e23-9f6d-4743-a9b5-abca87358929.png)

上述截图是一个构建调用 Ansible 临时命令的示例。这可以根据某些事件修改为 ansible-playbook 或基于特定事件的任何其他脚本。

Jenkins Ansible 插件还提供了有用的功能，例如从 Jenkins 本身配置高级命令和传递凭据、密钥。

一旦基于事件触发了构建，它可以被发送到某个构件存储中，也可以在 Jenkins 构建控制台输出中找到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/e933fb26-6493-48e9-b312-e52850dbcda8.png)

这是执行动态操作的非常强大的方式，例如基于对存储库的代码推送触发自动服务器和堆栈设置，以及定期扫描和自动报告。

# 设置 Rundeck

以下 Ansible playbook 将在 Ubuntu 16.04 操作系统上设置 Rundeck。它还添加了启动进程的 Rundeck 服务：

```
- name: installing rundeck on ubuntu 16.04
  hosts: "192.168.1.7"
  remote_user: ubuntu
  gather_facts: False
  become: True

  tasks:
    - name: installing python2 minimal
      raw: test -e /usr/bin/python || (apt -y update && apt install -y python-minimal)

    - name: java and curl installation
      apt:
        name: "{{ item }}"
        state: present
        update_cache: yes

      with_items:
        - curl
        - openjdk-8-jdk

    - name: downloading and installing rundeck deb package
      apt:
        deb: "http://dl.bintray.com/rundeck/rundeck-deb/rundeck-2.8.4-1-GA.deb"

    - name: add to startup and start rundeck
      service:
        name: rundeckd
        state: started
```

要设置 Rundeck，请运行以下命令。其中 `192.168.1.7` 是 Rundeck 将安装在的服务器 IP 地址：

```
ansible-playbook -i '192.168.1.7,' site.yml --ask-sudo-pass
```

成功执行后，在浏览器中导航至 `http://192.168.1.7:4440`，您将看到 Rundeck 应用程序的登录面板。登录到 Rundeck 的默认用户名和密码是 `admin`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/c8287e07-3bd9-4c2c-93c0-f1101585a763.png)

现在我们可以创建一个新项目开始工作。提供一个新的项目名称，并暂时使用默认设置：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/08461d41-6711-4464-8591-a6d421ca287b.png)

现在，我们可以将多个主机添加到 Rundeck 中执行多个操作。下面的屏幕截图显示了在多个节点上运行 `uname -a` 命令的示例，与 `osArch: amd64` 匹配，我们也可以为不同的用例创建过滤器：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/2d416d9a-ffe1-45d0-beb7-05149da3c0d1.png)

使用 Rundeck，我们还可以按照特定时间安排作业运行，并以不同的格式存储输出。Rundeck 还提供了可集成到现有工具集中的 REST API。

# 安全自动化用例。

现在，一旦我们设置好了工具，让我们来执行一些标准任务，以便让我们可以利用它们做一些有用的事情。如果你还没注意到，我们喜欢列表。以下是一些任务的列表，这些任务将使您能够为对您重要的事物构建自动化层：

1.  添加 playbooks 或连接您的源代码管理（SCM）工具，如 GitHub/GitLab/BitBucket。

1.  身份验证和数据安全。

1.  记录输出和管理自动化作业的报告。

1.  作业调度。

1.  警报、通知和 Webhooks。

# 添加 playbooks。

刚开始时，我们可能希望将自定义 playbooks 添加到 IT 自动化工具中，或者可能将它们添加到 SCM 工具，如 GitHub、GitLab 和 BitBucket 中。我们将配置并将我们的 playbooks 添加到这里讨论的所有三个工具中。

# Ansible Tower 配置。

Ansible Tower 有多个功能可添加 playbooks 进行调度和执行。我们将看看如何添加自定义编写的 playbooks（手动）以及从 Git 等版本控制系统添加 playbooks。还可以从 Ansible Galaxy 拉取 playbooks。Ansible Galaxy 是您查找、重用和共享最佳 Ansible 内容的中心。

要将 playbooks 添加到 Ansible Tower 中，我们必须首先创建项目，然后选择 SCM 类型为 Manual，并添加已经存在的 playbooks。

**警告**：`/var/lib/awx/projects` 中没有可用的 playbook 目录。要么该目录为空，要么所有内容已分配给其他项目。在那里创建一个新目录，并确保 `awx` 系统用户可以读取 playbook 文件，或者让 Tower 使用前面讨论过的 SCM 类型选项直接从源代码控制中检索您的 playbooks。

我们可以选择 SCM 类型设置为 Git，并提供指向 playbook 的 `github.com` URL：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/554af815-f886-4992-9ff5-d82187098819.png)

Git SCM 添加 playbooks 到项目中。

我们还可以在 CONFIGURE TOWER 下更改 `PROJECTS_ROOT` 来更改此位置。

添加的 playbooks 是通过创建作业模板来执行的。然后我们可以安排这些作业（或者）可以直接启动：

以下是为 playbook 执行创建的新作业模板的屏幕截图：

**![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/c33ce511-85d7-4df6-b2c0-5d1edf3052e8.png)**

Playbook 执行作业模板。

作业运行成功并显示输出如下截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/fe07b80e-0344-4855-a6f8-5f3e1dbdd6b0.png)

Ansible Tower 中的 Playbook 执行输出

# Jenkins Ansible 集成配置

毫不奇怪，Jenkins 支持 SCM 以使用 Playbook 和本地目录用于手动 Playbook。这可以通过构建选项进行配置。Jenkins 支持即席命令和 Playbook 作为构建（或）后置构建操作触发。

以下屏幕截图显示了我们如何指定我们的存储库并指定分支。如果要访问私有存储库，我们还可以指定凭据：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/c2733a7a-ebce-4801-8289-a147ebadb44a.png)

添加基于 Github（SCM）的 Playbooks 以进行构建

然后，我们可以通过指定 Playbook 的位置并根据需要定义清单和变量来添加 Playbook 路径：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/0028f394-5ea7-4bd2-be0d-5a599f72cd9c.png)

在构建触发器启动 Playbook 执行

最后，我们可以通过触发 Jenkins 构建来执行 Jenkins 作业（或者）我们可以将其与其他工具集成：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/bcef17b5-87e0-489b-a2a3-24e8c8ebac4c.png)

Playbook 执行的 Jenkins 构建输出

# Rundeck 配置

Rundeck 支持添加自定义 Playbook，以及 SCM 和许多其他选项。以下屏幕截图显示了使用作业功能在 Rundeck 中添加 Playbook 和模块的不同选项。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/525750e9-851f-4874-be36-3c44b66ec960.png)

Rundeck 有多个选项供我们选择

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/6e072793-3c21-494b-9ad5-e2befc0fa520.png)

用于变量和密钥的 Rundeck Ansible Playbook 配置

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/8baeae91-7dfc-441e-be3b-becacc09fc15.png)

包括作业详情概述的 Rundeck 作业定义

# 身份验证和数据安全

当我们谈论自动化和与系统一起工作时，我们应该谈论安全性。我们将继续谈论安全自动化，因为这是本书的标题。

工具提供的一些安全功能包括：

+   RBAC（身份验证和授权）

+   Web 应用程序通过 TLS/SSL（数据在传输中的安全性）

+   用于存储密钥的加密（数据在静止时的安全性）

# Ansible Tower 的 RBAC

Ansible Tower 支持 RBAC 以管理具有不同权限和角色的多个用户。企业版还支持 **轻量目录访问协议** (**LDAP**) 集成以支持 Active Directory。此功能允许我们为访问 Ansible Tower 创建不同级别的用户。例如：

+   运维团队需要系统管理员角色来执行 Playbook 执行和其他活动，如监视

+   安全团队需要系统审计员角色来执行符合标准（如 **支付卡行业数据安全标准** (**PCI DSS**) 或甚至内部策略验证）的审计检查

+   普通用户，如团队成员，可能只想查看事物的进展，以状态更新和作业状态的成功或失败的形式

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/10acb85d-52aa-4b55-8780-f959c561b05b.png)

用户可以被分配到不同类型的角色

# Ansible Tower 的 TLS/SSL

默认情况下，Ansible Tower 使用自签名证书在 `/etc/tower/tower.cert` 和 `/etc/tower/tower.key` 上进行 HTTPS，这些可以在设置脚本中配置。以后我们也可以使用相同的文件名进行更新。

获取更多信息，请访问 [`docs.ansible.com/ansible-tower/latest/html/installandreference/install_notes_reqs.html#installation-notes`](http://docs.ansible.com/ansible-tower/latest/html/installandreference/install_notes_reqs.html#installation-notes)。

# Ansible Tower 的加密和数据安全

Ansible Tower 已经创建了内置安全性，用于处理包括密码和密钥在内的凭据的加密。它使用 Ansible Vault 执行此操作。它将数据库中的密码和密钥信息进行加密。

阅读更多请访问 [`docs.ansible.com/ansible-tower/latest/html/userguide/credentials.html`](http://docs.ansible.com/ansible-tower/latest/html/userguide/credentials.html)。

# Jenkins 的 RBAC

在 Jenkins 中，这是一个更通用的工具，我们可以通过使用插件来扩展其功能。Role Strategy Plugin 是一个管理 Jenkins 角色的社区插件。使用它，我们可以为用户和组创建不同的访问级别控制：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/c745e9a1-51da-4ea4-bb21-0d3b65ed6b4c.png)

Jenkins 的角色策略插件

角色通常需要与团队设置和业务要求保持一致。您可能希望根据您的要求进行微调。

阅读更多请访问 [`wiki.jenkins.io/display/JENKINS/Role+Strategy+Plugin`](https://wiki.jenkins.io/display/JENKINS/Role+Strategy+Plugin)。

# Jenkins 的 TLS/SSL

默认情况下，Jenkins 作为普通的 HTTP 运行。要启用 HTTPS，我们可以使用反向代理，例如 Nginx，在 Jenkins 前端充当 HTTPS 服务。

有关参考，请访问 [`www.digitalocean.com/community/tutorials/how-to-configure-jenkins-with-ssl-using-an-nginx-reverse-proxy`](https://www.digitalocean.com/community/tutorials/how-to-configure-jenkins-with-ssl-using-an-nginx-reverse-proxy)。

# Jenkins 的加密和数据安全

我们正在使用 Jenkins 的默认凭据功能。这将把密钥和密码存储在本地文件系统中。还有不同的 Jenkins 插件可用于处理此问题，例如 [`wiki.jenkins.io/display/JENKINS/Credentials+Plugin`](https://wiki.jenkins.io/display/JENKINS/Credentials+Plugin)。

以下截图是一个参考，显示了我们如何在 Jenkins 中添加凭据：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/0c385f10-eced-4595-8d00-6e8fcfab0550.png)

# Rundeck 的 RBAC

Rundeck 也提供了 RBAC，就像 Ansible Tower 一样。与 Tower 不同，在 `/etc/rundeck/` 中我们必须使用 YAML 配置文件进行配置。

以下代码片段是创建管理员用户策略的示例：

```
description: Admin, all access.
context:
 application: 'rundeck'
for:
 resource: 
 - allow: '*' # allow create of projects 
 project: 
 - allow: '*' # allow view/admin of all projects
 project_acl: 
 - allow: '*' # allow all project-level ACL policies
 storage: 
 - allow: '*' # allow read/create/update/delete for all /keys/* storage content 
by: group: admin 
```

有关创建不同策略的更多信息，请访问 [`rundeck.org/docs/administration/access-control-policy.html`](http://rundeck.org/docs/administration/access-control-policy.html)。

# Rundeck 的 HTTP/TLS

可以使用 `/etc/rundeck/ssl/ssl.properties` 文件为 Rundeck 配置 HTTPS： 

```
keystore=/etc/rundeck/ssl/keystore
keystore.password=adminadmin
key.password=adminadmin
truststore=/etc/rundeck/ssl/truststore
truststore.password=adminadmin
```

有关更多信息，请访问 [`rundeck.org/docs/administration/configuring-ssl.html`](http://rundeck.org/docs/administration/configuring-ssl.html)。

# Rundeck 的加密和数据安全

凭证，例如密码和密钥，存储在本地存储中并加密，使用 Rundeck 密钥存储进行加密和解密。这还支持使用不同的密钥存储插件来使用密钥存储，例如存储转换器插件。对存储设施中的密钥的访问受到 **访问控制列表** (**ACL**) 策略的限制。

# playbooks 的输出

一旦自动化作业完成，我们想知道发生了什么。它们是否完全运行，是否遇到任何错误等。我们想知道在哪里可以看到执行 playbooks 的输出以及是否创建了任何其他日志。

# Ansible Tower 的报告管理

默认情况下，Ansible Tower 本身是 playbooks、作业执行和清单收集状态的报告平台。Ansible Tower 仪表板提供了项目总数、清单、主机和作业状态的概览。

输出可以在仪表板、标准输出中使用，也可以通过 REST API 获取，并且我们也可以通过 `tower-cli` 命令行工具获取，这只是一个用于与 REST API 交互的预构建命令行工具。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/b8421697-957d-4527-a83c-bd6fe22d6635.png)

Ansible Tower 仪表板

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/ae0d5c7e-73d7-4508-aa80-ed924e9c1699.png)

Ansible Tower 的标准输出

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/adfa2820-d792-48fb-8012-0e03a7eb070f.png)

Ansible Tower REST API

# Jenkins 的报告管理

Jenkins 提供了用于管理报告的标准输出和 REST API。Jenkins 拥有一个庞大的社区，有多个可用的插件，例如 HTML Publisher Plugin 和 Cucumber Reports Plugin。

这些插件提供了输出的可视化表示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/15fd8b11-130c-42e3-9def-8c0b684f6d18.png)

Jenkins 作业控制台的标准输出

# Rundeck 的报告管理

Rundeck 还提供了标准输出和 REST API 来查询结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/f50f2cbf-da86-4ca6-ac4f-184e84d63b84.png)

可以通过 stdout、TXT 和 HTML 格式消耗的作业输出

# 作业的调度

在 Ansible Tower 中，作业的调度简单而直接。对于一个作业，你可以指定一个时间表，选项大多类似于 cron。

例如，你可以说你有一个每天扫描的模板，并希望在未来三个月的每天上午 4 点执行它。这种类型的时间表使我们的元自动化非常灵活和强大。

# 警报、通知和 webhook

Tower 支持多种方式的警报和通知用户按配置。甚至可以配置它使用 webhook 向您选择的 URL 发送 HTTP `POST` 请求：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/de4acb14-dd56-484a-9dc7-3092d583ff66.png)

使用 slack webhook 的 Ansible Tower 通知

# 摘要

我们快速浏览了一些 IT 自动化和调度软件。我们的主要目的是介绍该软件并突出其一些常见功能。

这些功能包括以下内容：

+   为我们的秘密提供加密

+   根据我们的时间表要求运行

+   获得良好报告的能力

我们已经了解了允许我们重复使用和创建出色 playbooks 的 Ansible 角色。结合这些功能，我们有一个完整的自动化系统准备好了。我们不仅能够随意运行我们的任务和作业多次，还会得到关于它们运行情况的更新。此外，由于我们的任务在受保护的服务器上运行，因此重要的是我们分享的用于运行的秘密也是安全的。

在下一章中，我们将不再考虑 Ansible 自动化的机制，而是直接思考特定情况下的安全自动化。自动化服务器的补丁是最明显、可能也是最受欢迎的需求。我们将应用安全自动化技术和方法来设置一个强化的 WordPress，并启用加密备份。


# 第三章：使用加密自动备份的强化 WordPress

现在基本设置已完成，让我们逐个讨论各种安全自动化场景，并一一查看它们。

每个人都会同意，建立一个安全的网站并保持其安全性是一个相当普遍的安全要求。由于这是如此普遍，因此对于那些负责构建和管理网站以保持安全的人来说，查看特定情景可能是有用的。

您是否知道，根据维基百科的数据，前 1000 万个网站中有 27.5%使用 WordPress？根据另一项统计数据，整个网络上所有已知软件中有 58.7%的网站在运行 WordPress。

如果有这么多，那么一种自动化的安全方式来设置和维护 WordPress 对一些读者应该是有用的。

即使 WordPress 不是您非常感兴趣的内容，也请记住，设置和保护 LAMP/LEMP 堆栈应用程序的整体步骤是普遍适用的。

对我们来说，使用加密自动备份的强化 WordPress 可以分解为以下步骤：

1.  设置带有安全措施的 Linux/Windows 服务器。

1.  设置 Web 服务器（Linux 上的 Apache/Nginx 和 Windows 上的 IIS）。

1.  在同一主机上设置数据库服务器（MySQL）。

1.  使用名为**WP-CLI**的命令行实用程序设置 WordPress。

1.  为网站文件和数据库设置增量、加密和最重要的自动化备份。

在本章中，我们将使用 Ansible playbook 和 roles 完成所有这些。我们将假设我们计划部署 WordPress 网站的服务器已经启动并运行，并且我们能够连接到它。我们将备份存储在已经配置好的 AWS S3 存储桶中，其中访问密钥和秘密访问密钥已经提供。

我们将讨论以下主题：

+   WordPress 的 CLI

+   为什么选择 Ansible 进行此设置？

+   逐步完成 WordPress 安装

+   设置 Apache2 Web 服务器

+   如果您不想自己构建，那么 Trellis 堆栈呢？

+   我们为什么要使用 Trellis，并且何时使用它是一个好主意？

+   使用 Let's Encrypt 启用 TLS/SSL

+   Windows 上的 WordPress

# WordPress 的 CLI

我们将使用一个名为 WP-CLI 的工具，它允许我们在 WordPress 中执行许多传统上需要使用 Web 浏览器的操作。

WP-CLI 是 WordPress 的 CLI。您可以更新插件、配置多站点安装等，而无需使用 Web 浏览器。有关 WP-CLI 的更多信息，请访问[`WP-CLI.org/`](https://wp-cli.org/)，有关 WordPress，请访问[`wordpress.org/`](https://wordpress.org/)。

例如，以下命令将下载并设置 WordPress：

```
wp core install # with some options such as url, title of the website etc. etc.
```

完整示例可在[`developer.WordPress.org/cli/commands/core/#examples`](https://developer.wordpress.org/cli/commands/core/#examples)找到：

```
wp core install --url=example.com --title=Example --admin_user=supervisor --admin_password=strongpassword --admin_email=info@example.com
```

此示例让我们一窥从 Ansible playbook 中调用 WP-CLI 工具的威力。

# 为什么选择 Ansible 进行此设置？

Ansible 专为安全自动化和硬化而设计。它使用 YAML 语法，帮助我们对重复任务的整个过程进行编码。通过使用这个，我们可以使用角色和播放书自动化基础架构的持续交付和部署过程。

模块化方法使我们能够非常简单地执行任务。例如，运维团队可以编写一个播放书来设置 WordPress 站点，安全团队可以创建另一个角色，用于加固 WordPress 站点。

使用模块实现可重复性非常容易，并且输出是幂等的，这意味着可以为服务器、应用程序和基础架构创建标准。一些用例包括使用内部政策标准为组织创建基础镜像。

Ansible 使用 SSH 协议，默认情况下使用加密传输和主机加密进行保护。而且，在处理不同类型的操作系统时不存在依赖性问题。它使用 Python 执行；根据我们的用例，这可以很容易地扩展。

# 逐步完成 WordPress 安装

在本节中，我们将继续完成 WordPress、所需的数据库服务器、硬化和备份的完整设置。我们选择的平台是 Linux（Ubuntu 16.04），使用 nginx Web 服务器和 PHP-FPM 作为 PHP 运行时。我们将使用 duply 设置备份，备份将存储在 AWS S3 中。

# 设置 nginx Web 服务器

设置 nginx 就像`sudo apt-get install nginx`这样简单，但是为我们的用例配置并管理配置的自动化方式是 Ansible 的强大之处。让我们看一下播放书中 nginx 角色的以下片段：

```
- name: adding nginx signing key
  apt_key:
    url: http://nginx.org/keys/nginx_signing.key
    state: present

- name: adding sources.list deb url for nginx
  lineinfile:
    dest: /etc/apt/sources.list
    line: "deb http://nginx.org/packages/mainline/ubuntu/ trusty nginx"

- name: update the cache and install nginx server
  apt:
    name: nginx
    update_cache: yes
    state: present

- name: updating customized templates for nginx configuration
  template:
    src: "{{ item.src }}"
    dest: "{{ item.dst }}"

  with_items:
    - { src: "templates/defautlt.conf.j2", dst: "/etc/nginx/conf.d/default.conf" }    

  notify
    - start nginx
    - startup nginx
```

在上述代码片段中，我们正在添加签名密钥，然后添加存储库，然后进行安装。这样可以确保我们在从存储库下载软件包时也可以执行完整性检查。

然后，我们使用 Jinja2 模板执行配置更改，这些更改可以在服务器更新之前预定义在我们的配置中。

# 设置先决条件

要设置 WordPress CMS，我们需要安装数据库和 PHP，因此我们将安装 MySQL 作为数据库，以及 PHP-FPM 用于处理。

# 设置 MySQL 数据库

我们已经在前一章中看到了如何设置 MySQL。在这里，我们将看到如何为 WordPress 应用程序创建新用户和数据库。然后，我们将通过 Ansible 模块应用硬化步骤：

```
- name: create WordPress database
    mysql_db:
      name: "{{ WordPress_database_name }}"
      state: present
      login_user: root
      login_password: "{{ mysql_root_password }}"

- name: create WordPress database user
    mysql_user:
      name: "{{ WordPress_database_username }}"
      password: "{{ WordPress_database_password }}"
      priv: '"{{ WordPress_database_name }}".*:ALL'
      state: present
      login_user: root
      login_password: "{{ mysql_root_password }}"
```

上述代码片段描述了使用`mysql_db`和`mysql_user`模块创建新数据库和用户，并分别将该用户赋予 WordPress 应用数据库完全权限。

# 为 WordPress 设置安装 PHP

以下代码片段使用不同的模块来执行 PHP 和其他所需包的安装。然后，它使用 `replace` 模块更新 PHP-FPM 配置。最后，它还使用 `template` 模块更新 nginx 配置以更新 PHP-FPM 处理，并重新启动服务以应用更改：

```
- name: installing php
  apt:
    name: "{{ item }}"
    state: present
    update_cache: yes

  with_items:
    - php
    - php-curl
    - php-fpm
    - php-mysql
    - php-xmlrpc

- name: configuring php.ini for php processor
  replace:
    path: /etc/php5/fpm/php.ini
    regex: ';cgi.fix_pathinfo=1'
    replace: 'cgi.fix_pathinfo=0'
    backup: yes

- name: enable and restart the php fpm service
  service:
    name: php7.0-fpm
    enabled: yes
    state: restarted

- name: update the nginx configuration to support php-fpm
  template:
    src: "{{ item.src }}"
    dest: "{{ item.dst }}"

  with_items:
    - { src: "defautlt.conf.j2", dst: "/etc/nginx/conf.d/default.conf" }

- name: restart the nginx
  service:
    state: restarted
    name: nginx
```

# 使用 WP-CLI 安装 WordPress

以下代码片段将安装和设置 WordPress，以便它能够正常运行：

```
- debug:
  msg: ensure you have installed lamp (or) lemp stack

- name: downloading WordPress cli aka wp-cli
  get_url:
    url: https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    dest: /usr/local/bin/wp
    mode: 0755

- name: download latest WordPress locally
  command: wp core download
  become_user: "{{ new_user_name }}"
  args:
    chdir: /var/www/html/

- name: WordPress site configuration
  command: "wp core config --dbname={{ WordPress_database_name }} --dbuser={{ WordPress_database_username }} --dbpass={{ WordPress_database_password }}

- name: information for WordPress site
  command: "wp core install --url={{ WordPress_site_name }} --title={{ WordPress_site_title }} --admin_user={{ WordPress_admin_username }} --admin_password={{ WordPress_admin_password }} --admin_email={{ WordPress_admin_email }}"
```

# 强化 SSH 服务

这将是一个更传统的方法，采用现代化的自动化方法，使用 Ansible。这里包括的一些项目有：

+   禁用 `root` 用户登录，并创建一个不同的用户，如果需要，提供 `sudo` 权限：

```
    - name: create new user
      user:
        name: "{{ new_user_name }}"
        password: "{{ new_user_password }}"
        shell: /bin/bash
        groups: sudo
        append: yes
```

+   使用基于密钥的身份验证登录。与基于密码的身份验证不同，我们可以生成 SSH 密钥并将公钥添加到授权密钥中：

```
    - name: add ssh key for new user
      authorized_key:
        user: "{{ new_user_name }}"
        key: "{{ lookup('file', '/home/user/.ssh/id_rsa.pub') }}"
        state: present
```

+   使用 SSH 配置文件进行一些配置调整；例如，`PermitRootLogin`、`PubkeyAuthentication` 和 `PasswordAuthentication`：

```
    - name: ssh configuration tweaks
      lineinfile:
        dest: /etc/ssh/sshd_config
        state: present
        line: "{{ item }}"
        backups: yes

      with_items:
        - "PermitRootLogin no"
        - "PasswordAuthentication no"

      notify:
        - restart ssh
```

+   我们还可以设置诸如 `fail2ban` 之类的服务，以保护免受基本攻击。

+   此外，如果需要登录，则可以启用 MFA。欲了解更多信息，请访问 [`www.digitalocean.com/community/tutorials/how-to-set-up-multi-factor-authentication-for-ssh-on-ubuntu-16-04`](https://www.digitalocean.com/community/tutorials/how-to-set-up-multi-factor-authentication-for-ssh-on-ubuntu-16-04)。

下面的操作手册将由 dev-sec 团队提供更多关于 SSH 强化的高级功能：[`github.com/dev-sec/ansible-ssh-hardening`](https://github.com/dev-sec/ansible-ssh-hardening)

# 强化数据库服务

我们已经看到如何设置数据库。以下代码片段显示了如何通过将其绑定到 localhost 和与应用程序交互所需的接口来加固 MySQL 服务。然后，它移除了匿名用户和测试数据库：

```
- name: delete anonymous mysql user for localhost
  mysql_user:
    user: ""
    state: absent
    login_password: "{{ mysql_root_password }}"
    login_user: root

- name: secure mysql root user
  mysql_user:
    user: "root"
    password: "{{ mysql_root_password }}"
    host: "{{ item }}"
    login_password: "{{ mysql_root_password }}"
    login_user: root

  with_items:
    - 127.0.0.1
    - localhost
    - ::1
    - "{{ ansible_fqdn }}"

- name: removes mysql test database
  mysql_db:
    db: test
    state: absent
    login_password: "{{ mysql_root_password }}"
    login_user: root
```

# 强化 nginx

在这里，我们可以开始查看如何禁用服务器标记以不显示版本信息，添加诸如 `X-XSS-Protection` 之类的头部，以及许多其他配置调整。这些大多数更改都是通过配置更改完成的，Ansible 允许我们根据用户需求对这些更改进行版本控制和自动化： 

+   可以通过在配置中添加 `server_tokens off;` 来阻止 nginx 服务器版本信息

+   `add_header X-XSS-Protection "1; mode=block";` 将启用跨站点脚本 (XSS) 过滤器

+   可以通过添加 `ssl_protocols TLSv1 TLSv1.1 TLSv1.2;` 来禁用 SSLv3

+   这个列表可能会相当长，根据使用情况和场景而定：

以下代码片段包含了用于更新强化的 nginx 配置更改的 nginx 配置模板：

```
    - name: update the hardened nginx configuration changes
      template:
        src: "hardened-nginx-config.j2"
        dest: "/etc/nginx/sites-available/default"

      notify:
        - restart nginx
```

Mozilla 在 [`wiki.mozilla.org/Security/Server_Side_TLS`](https://wiki.mozilla.org/Security/Server_Side_TLS) 上提供了更新的有关 SSL/TLS 指导的网页。该指导提供了关于使用什么密码套件以及其他安全措施的建议。此外，如果您信任他们的判断，您还可以使用他们的 SSL/TLS 配置生成器快速生成您的 Web 服务器配置的配置。欲了解更多信息，请访问 [`mozilla.github.io/server-side-tls/ssl-config-generator/`](https://mozilla.github.io/server-side-tls/ssl-config-generator/)。

无论您决定使用哪种配置，模板都需要命名为 `hardened-nginx-config.j2`。

# 加固 WordPress

这包括对 WordPress 安全配置错误的基本检查。其中一些包括：

+   目录和文件权限：

```
    - name: update the file permissions
      file:
        path: "{{ WordPress_install_directory }}"
        recurse: yes
        owner: "{{ new_user_name }}"
        group: www-data

    - name: updating file and directory permissions
      shell: "{{ item }}"

      with_items:
        - "find {{ WordPress_install_directory }} -type d -exec chmod
         755 {} \;"
        - "find {{ WordPress_install_directory }} -type f -exec chmod 
        644 {} \;"
```

+   用户名和附件枚举阻止。以下代码片段是 nginx 配置的一部分：

```
    # Username enumeration block
    if ($args ~ "^/?author=([0-9]*)"){
        return 403;
    }

    # Attachment enumeration block
    if ($query_string ~ "attachment_id=([0-9]*)"){
        return 403;
    }
```

+   禁止在 WordPress 编辑器中编辑文件：

```
    - name: update the WordPress configuration
      lineinfile:
        path: /var/www/html/wp-config.php
        line: "{{ item }}"

      with_items:
        - define('FS_METHOD', 'direct');
        - define('DISALLOW_FILE_EDIT', true);
```

随着配置的更改和更新，我们可以添加许多其他检查。

# 加固主机防火墙服务

以下代码片段是用于安装和配置**简易防火墙**（**UFW**）及其所需的服务和规则。Ansible 甚至有一个用于 UFW 的模块，因此以下片段以安装此模块并启用日志记录开始。接着它添加了默认策略，比如默认拒绝所有入站流量并允许出站流量。

然后将添加 SSH、HTTP 和 HTTPS 服务以允许进入。这些选项是完全可配置的，根据需要。然后它将启用并添加到启动程序中以应用更改：

```
- name: installing ufw package
  apt:
    name: "ufw"
    update_cache: yes
    state: present

- name: enable ufw logging
  ufw:
    logging: on

- name: default ufw setting
  ufw:
    direction: "{{ item.direction }}"
    policy: "{{ item.policy }}"

  with_items:
    - { direction: 'incoming', policy: 'deny' }
    - { direction: 'outgoing', policy: 'allow' }

- name: allow required ports to access server
  ufw:
    rule: "{{ item.policy }}"
    port: "{{ item.port }}"
    proto: "{{ item.protocol }}"

  with_items:
    - { port: "22", protocol: "tcp", policy: "allow" }
    - { port: "80", protocol: "tcp", policy: "allow" }
    - { port: "443", protocol: "tcp", policy: "allow" }

- name: enable ufw
  ufw:
    state: enabled

- name: restart ufw and add to start up programs
  service:
    name: ufw
    state: restarted
    enabled: yes
```

# 在 AWS S3 中设置自动化的加密备份

备份始终是我们大多数人觉得应该完成的事情，但它们似乎相当繁琐。多年来，人们已经做了大量工作，以确保我们可以有足够简单的方式来备份和恢复我们的数据。

在当今这个时代，一个出色的备份解决方案/软件应该能够执行以下操作：

| **特性** | **备注** |
| --- | --- |
| 自动化 | 自动化允许围绕其进行流程 |
| 增量 | 尽管整体存储成本较低，但如果我们想要每五分钟备份一次，那么已更改的内容应该被备份 |
| 离开我们的服务器之前加密 | 这是为了确保数据在静止和运动中的安全性 |
| 便宜 | 尽管我们关心我们的数据，但一个好的备份解决方案会比需要备份的服务器便宜得多 |

对于我们的备份解决方案，我们将选择以下堆栈：

| **软件** | Duply - 一个包装在 duplicity 上的包装器，是一个 Python 脚本 |
| --- | --- |
| **存储** | 尽管 duply 提供了许多后端，但它与 AWS S3 非常兼容 |
| **加密** | 通过使用 GPG，我们可以使用非对称的公钥和私钥对 |

以下代码片段是为了在服务器和 AWS S3 之间设置 duply 进行加密的自动化备份：

```
- name: installing duply
  apt:
    name: "{{ item }}"
    update_cache: yes
    state: present

  with_items:
    - python-boto
    - duply

- name: check if we already have backup directory
  stat:
    path: "/root/.duply/{{ new_backup_name }}"
  register: duply_dir_stats

- name: create backup directories
  shell: duply {{ new_backup_name }} create
  when: duply_dir_stats.stat.exists == False

- name: update the duply configuration
  template:
    src: "{{ item.src }}"
    dest: "{{ item.dest }}"

  with_items:
    - { src: conf.j2, dest: /root/.duply/{{ new_backup_name }}/conf }
    - { src: exclude.j2, dest: /root/.duply/{{ new_backup_name }}/exclude }

- name: create cron job for automated backups
  template:
    src: duply-backup.j2
    dest: /etc/cron.hourly/duply-backup
```

# 使用 Ansible Tower 对 Ubuntu 16.04 服务器执行 playbook

一旦我们准备好 playbook 并根据需要更新变量，我们就可以继续执行 playbook。在那之前，我们必须在 Ansible Tower 中创建模板来执行此操作。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/266b5435-4813-4632-b833-57f4ab04cb58.png)

用于 WordPress 设置 playbook 的 Ansible Tower 作业模板

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/5ade359b-1b20-4bf1-8ac1-cd68381d87ac.png)

WordPress 设置 playbook 作业执行

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/3958664f-96b6-458d-bac0-11c931a7a00f.png)

使用 HTTPS 的 WordPress 网站

# 安全地自动化 WordPress 更新

以下代码片段是用于运行备份并更新 WordPress 核心、主题和插件的。可以通过 Ansible Tower 作业每天定时执行：

```
- name: running backup using duply
  command: /etc/cron.hourly/duply-backup

- name: updating WordPress core
  command: wp core update
  register: wp_core_update_output
  ignore_errors: yes

- name: wp core update output
  debug:
    msg: "{{ wp_core_update_output.stdout }}"

- name: updating WordPress themes
  command: wp theme update --all
  register: wp_theme_update_output
  ignore_errors: yes

- name: wp themes update output
  debug:
    msg: "{{ wp_theme_update_output.stdout }}"

- name: updating WordPress plugins
  command: wp plugin update --all
  register: wp_plugin_update_output
  ignore_errors: yes

- name: wp plugins update output
  debug:
    msg: "{{ wp_plugin_update_output.stdout }}"
```

# 通过 Ansible Tower 进行每日更新的调度

Ansible Tower 允许我们安排自动运行对服务器的作业。我们可以在模板中配置开始日期和重复频率以执行 playbook。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/6f760e32-86f5-44da-afc2-6cbb8965f516.png)

通过 Ansible Tower 进行自动化 WordPress 更新的作业调度

否则，我们可以使用 `cron` 作业模板每天执行此操作，并在部署 WordPress 设置时添加此模板：

```
#!/bin/bash

/etc/cron.hourly/duply-backup
wp core update
wp theme update --all
wp plugin update --all
```

# 设置 Apache2 web 服务器

我们在我们的 LEMP 栈设置中已经见过这个，它非常相似。但是在这里，我们必须使用与 WordPress 一起工作的所需模块。以下代码片段显示了我们如何使用模板来执行服务器上的配置更新：

```
- name: installing apache2 server
  apt:
    name: "apache2"
    update_cache: yes
    state: present

- name: updating customized templates for apache2 configuration
  template:
    src: "{{ item.src }}"
    dest: "{{ item.dst }}"
    mode: 0644

  with_tems:
    - { src: apache2.conf.j2, dst: /etc/apache2/conf.d/apache2.conf }
    - { src: 000-default.conf.j2, dst: /etc/apache2/sites-available/000-default.conf }
    - { src: default-ssl.conf.j2, dst: /etc/apache2/sites-available/default-ssl.conf }

- name: adding custom link for sites-enabled from sites-available
  file:
    src: "{{ item.src }}"
    dest: "{{ item.dest }}"
    state: link

  with_items:
    - { src: '/etc/apache2/sites-available/000-default.conf', dest: '/etc/apache2/sites-enabled/000-default.conf' }
    - { src: '/etc/apache2/sites-available/default-ssl.conf', dest: '/etc/apache2/sites-enabled/default-ssl.conf' }

  notify:
    - start apache2
    - startup apache2
```

# 使用 Let's Encrypt 启用 TLS/SSL

我们可以使用 Let's Encrypt 提供的命令行工具以开放、自动化的方式获取免费的 SSL/TLS 证书。

该工具能够完全自动地读取和理解一个 nginx 虚拟主机文件，并生成相关的证书，不需要任何手动干预：

```
- name: adding certbot ppa
  apt_repository:
    repo: "ppa:certbot/certbot"

- name: install certbot
  apt:
    name: "{{ item }}"
    update_cache: yes
    state: present

  with_items:
    - python-certbot-nginx

- name: check if we have generated a cert already
  stat:
    path: "/etc/letsencrypt/live/{{ website_domain_name }}/fullchain.pem"
  register: cert_stats

- name: run certbot to generate the certificates
  shell: "certbot certonly --standalone -d {{ website_domain_name }} --email {{ service_admin_email }} --non-interactive --agree-tos"
  when: cert_stats.stat.exists == False

- name: configuring site files
  template:
    src: website.conf
    dest: "/etc/nginx/sites-available/{{ website_domain_name }}"

- name: restart nginx
  service:
    name: nginx
    state: restarted

```

Let's Encrypt 已成为在网站上启用 SSL/TLS 的一种极其流行和安全的方式。

到 2017 年 6 月底，Let's Encrypt 已经以自动方式发布了超过 1 亿个免费的 SSL/TLS 证书。有关更多信息，请访问 [`letsencrypt.org/2017/06/28/hundred-million-certs.html`](https://letsencrypt.org/2017/06/28/hundred-million-certs.html)。

# 如果你不想自己动手怎么办？Trellis 栈

Trellis 栈是开发团队为 WordPress 网站建立本地临时和生产环境设置的一种方式。

Trellis 是一个为 WordPress LEMP 栈设计的一组开源 MIT 许可的 Ansible playbook。

# 我们为什么要使用 Trellis，以及什么时候使用它是一个好主意？

Trellis 是一个完整的项目，基于各种工具，由 Ansible 组合在一起。在许多方面，它是使用本章节的 playbook 的一个更好的选择的替代品。

如果你预期要构建/开发、部署，然后维护 WordPress 网站或网站的生产环境，那么 Trellis 是一个不错的选择。

唯一的注意事项是，如果有团队进行开发和部署，则许多可用功能更有用。否则，堆栈是有偏见的，你可能会被一些你不喜欢的软件选择所困扰。

# Windows 上的 WordPress

这是我们现在要执行的新事物之一。到目前为止，我们一直在 Linux 操作系统中设置东西。现在我们要在 Windows 操作系统中设置 IIS Web 服务器，这需要我们在 Windows 服务中启用`WinRM`功能以执行 Ansible playbook。

我们需要确保在控制机器上安装了`pywinrm`模块；我们可以通过执行以下`pip`命令来安装它：

```
pip install "pywinrm>=0.2.2"
```

# 如何在 Windows 中启用 WinRM

为了简化这个过程，Ansible 提供了一个 PowerShell 脚本，需要在 PowerShell 控制台中以管理员身份运行。从[`raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1`](https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1)下载 PowerShell 脚本。

在 Windows 机器上，以管理员身份打开命令提示符，并运行以下命令：

```
powershell.exe -File ConfigureRemotingForAnsible.ps1 -CertValidityDays 100
```

请确保在防火墙规则中为 Windows 机器打开了端口`5986`。有关 Windows 设置的更多参考信息，请访问[`docs.ansible.com/ansible/latest/intro_windows.html`](http://docs.ansible.com/ansible/latest/intro_windows.html)。

# 运行 Ansible 针对 Windows 服务器

现在，让我们通过执行简单的 ping 模块来测试针对 Windows 服务器的情况。

首先，我们需要创建包括连接 Windows `winrm`服务选项的`inventory`文件：

```
[windows]
192.168.56.120 ansible_user=Administrator ansible_password=strongpassowrd ansible_connection=winrm ansible_winrm_server_cert_validation=ignore ansible_port=5986
```

要执行 Windows ping 模块，我们可以运行以下 Ansible 命令：

```
ansible -i inventory windows -m win_ping
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/f2ec7fad-707a-4d82-9128-f61098edddd3.png)

要了解有关 Windows 中可用模块的不同可用模块的更多信息，请参阅[`docs.ansible.com/ansible/latest/list_of_windows_modules.html`](http://docs.ansible.com/ansible/latest/list_of_windows_modules.html)。

# 使用 playbook 安装 IIS 服务器

以下代码片段解释了我们如何在 Windows 服务器操作系统中安装和启动 IIS 服务：

```
- name: Install and start IIS web server in Windows server
  hosts: winblows

  tasks:
    - name: Install IIS
      win_feature:
        name: "Web-Server"
        state: present
        restart: yes
        include_sub_features: yes
        include_management_tools: yes

```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/d1c4c6a1-656c-4c98-93a3-aa7201ba86ff.png)

我们将使用 Chocolatey（有关更多信息，请访问[`chocolatey.org/`](https://chocolatey.org/)），这是 Windows 的软件包管理器，用于在 Windows 中进行高级安装和设置。

下一步是安装 Web 平台安装程序。

Microsoft Web 平台安装程序（Web PI）是一个免费工具，可轻松获取 Microsoft Web 平台的最新组件，包括**Internet 信息服务**（**IIS**），SQL Server Express，.NET Framework 和 Visual Web 开发人员工具。有关更多信息，请访问[`www.microsoft.com/web/downloads/platform.aspx`](https://www.microsoft.com/web/downloads/platform.aspx)。

安装完毕后，我们可以使用此方法安装 MySQL 和 WordPress：

以下剧本运行了由[`gist.github.com/chrisloweau/8a15516d551a87b096620134c3624b73`](https://gist.github.com/chrisloweau/8a15516d551a87b096620134c3624b73)创建的 PowerShell 脚本。有关 PowerShell 脚本的更多详细信息，请参阅[`www.lowefamily.com.au/2017/04/11/how-to-install-wordpress-on-windows-server-2016/`](http://www.lowefamily.com.au/2017/04/11/how-to-install-wordpress-on-windows-server-2016/)。

此设置需要一些先决条件。其中包括设置 PowerShell 执行策略和支持的 Windows 版本。

+   首先，我们需要运行以下命令设置执行策略：

```
 Set-ExecutionPolicy RemoteSigned CurrentUser
```

+   此脚本仅支持 Windows Server 2016 操作系统和 Windows 10。

以下 Ansible 剧本正在执行 PowerShell 脚本，以在 Windows 操作系统中设置 WordPress。

```
- name: Windows Wordpress Setup Playbook
  hosts: winblows

  tasks:
    - name: download wordpress setup script
      win_get_url:
        url: https://gist.githubusercontent.com/chrisloweau/8a15516d551a87b096620134c3624b73/raw/b7a94e025b3cbf11c3f183d20e87c07de86124a3/wordpress-install.ps1
        dest: ~\Downloads\wordpress-install.ps1

    # This requires `Set-ExecutionPolicy RemoteSigned CurrentUser` to All
    - name: running windows wordpress script
      win_shell: ~\Downloads\wordpress-install.ps1
      args:
        chdir: ~\Downloads\wordpress-install.ps1
      register: output

    - debug:
        msg: "{{ output.stdout }}"
```

+   执行后，它会返回类似以下的输出。然后我们可以导航到 IP 地址并按照说明设置 WordPress 的最终配置。

```
Installation Complete!

MySQL Accounts
       root = 2*Bb!o4#4T2yy/*44ngb
  wordpress = B*OGGrg{{ghr$35nGt4rU

Connect your web browser to http://192.168.56.100/ to complete this WordPress
installation.
```

# 摘要

这一章主要讲解了 WordPress。我们使用 Ansible 默认创建了一个相当安全的 WordPress 安装。通过改变数据库、Web 服务器和 WordPress 的默认值，我们利用了使用 Ansible 剧本编码安全知识的能力。此外，通过设置自动、增量、加密备份，我们实现了对最坏情况的弹性和连续性。

我们简要介绍了如何启用 Windows 以便与 Ansible 一起使用。

在下一章中，我们将研究 Elastic Stack 用于设置集中式日志基础设施。这不仅适用于存储各种日志，而且还会在我们受到攻击时提醒和通知我们。我们还将学习如何部署无服务器防御以自动阻止攻击者。
