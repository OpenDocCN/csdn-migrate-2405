# Ansible 快速启动指南（三）

> 原文：[`zh.annas-archive.org/md5/5ed89b17596e56ef11e7d3cab54e2924`](https://zh.annas-archive.org/md5/5ed89b17596e56ef11e7d3cab54e2924)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Ansible Galaxy 和社区角色

在上一章中，我们向您展示了如何根据 Ansible 规范和最佳实践创建自己的角色。无需重复造轮子；相反，我们可以寻找已经创建的内容并使用它或修改它以满足我们的需求。本章将简要介绍 Ansible Galaxy 的命令和存储库。我们将学习如何将我们创建的角色上传到存储库，搜索流行的社区角色进行下载、设置和使用，并进行故障排除。

本章涵盖以下主题：

+   Ansible Galaxy 介绍

+   将角色上传到 Ansible Galaxy

+   搜索社区角色的最佳实践

+   设置和使用社区角色

+   故障排除角色

# Ansible Galaxy

Ansible Galaxy 是 Ansible 为其社区创建的平台。它允许其成员创建和提交自己的角色供其他成员使用、修改、升级、增强和优化。

Ansible Galaxy 旨在让开发人员更轻松地提交角色，并让用户更轻松地导入角色。在控制主机上安装 Ansible 时，添加`ansible-galaxy`命令行。此命令允许通过终端与 Ansible Galaxy 存储库进行交互。

Ansible Galaxy 为 Ansible 带来了巨大的优势，并使其比任何其他自动化工具都增长更快。有经验的用户编写的代码供不太有经验的用户轻松访问和学习，这是无价的。这些资源由基于 Ansible 的项目和工作流组成。

# Ansible Galaxy hub

Ansible Galaxy hub 是一个托管大量社区角色的 Web 门户。它被分类为几个组，以便更轻松地搜索角色，并提供由 Ansible 用户开发和维护的各种角色。一些角色的编码和维护比其他角色更好。Ansible Galaxy hub 还提供有关如何导入和使用每个角色的有用信息，其中大部分由作者填写。每个角色还应包含指向其 GitHub 项目的源代码链接。此外，信息还应包括每个角色的下载次数、星标、观察者和分支数。界面还提供了所有注册到 hub 的作者列表。

其 Web 界面如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/18f9bffd-da41-4358-9af4-1d79216fafe9.png)

Ansible Galaxy 使用 GitHub 访问 API，需要您登录其作者或贡献者服务。通过登录，界面会添加一些额外的贡献选项。登录界面如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/9ef1f38a-c607-4355-bb5c-09b2bb43d213.png)

Ansible 不需要身份验证即可访问其角色并使用它们。登录仅用于作者和贡献者能够将其代码提交为社区贡献。

Ansible Galaxy 存储库按标签组织，指示每个角色的类别和服务。标签不仅限于主页上的标签。它们可以根据角色进行个性化设置。但是，在角色中包含主页标签之一可以更容易地找到它。

# Ansible Galaxy 命令行

Ansible Galaxy 命令行`ansible-galaxy`是用于在本地初始化角色的工具。

在上一章中，我们使用`init`选项初始化了一个角色，如下所示：

```
ansible-galaxy init lab-edu.samba
```

此命令将创建一个以角色名称命名的文件夹，其中包含必要的基本文件夹和文件。然后需要编辑并填写适当的代码和文件，使角色正常运行。

Ansible Galaxy 命令行管理 Ansible 控制主机中的所有角色。它还允许您在 hub 中浏览角色。此命令行最常用的选项如下。

Ansible Galaxy 命令行允许使用以下命令从本地 Ansible 安装中删除不再需要的一个或多个角色：

```
ansible-galaxy remove lab-edu.ntp
```

它还允许您通过关键字或标签搜索角色，并查看有关它们的有用信息，以便在不使用 Web 界面的情况下，要么再次检查其评级，要么了解更多信息。可以使用以下命令完成：

```
ansible-galaxy search geerlingguy.ntp
ansible-galaxy search --galaxy-tags system
ansible-galaxy info geerlingguy.ntp
```

以下截图显示了角色信息的示例输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/e1ea7609-7fc7-4791-bc2c-3b7966422eaa.png)

如果找到所需的角色，可以使用`install`选项进行安装。您可以始终使用`list`选项查看已安装角色的列表。以下命令显示了如何完成此操作：

```
ansible-galaxy install geerlingguy.ntp
ansible-galaxy list
```

以下截图显示了上述命令的示例输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/519c9591-9a97-441a-b186-39d0821b673c.png)

我们将在后面的部分讨论此命令的更多功能和选项。

要能够在您的 Ansible 安装中使用尚未上传到 Galaxy hub 的本地创建的角色，只需将其文件夹复制到 Ansible 配置中的指定角色文件夹中。Ansible 目前正在开发一个名为`mazer`的新命令行工具。这是一个用于管理 Ansible 内容的开源项目。它目前是一个实验性工具，不应替代`ansible-galaxy`命令行工具。 

# Galaxy 贡献-角色导入

就 Ansible Galaxy hub 上免费提供给公众的角色数量和质量而言，Ansible 社区的影响力非常明显。来自世界各地的用户为他人的利益贡献他们的代码。这是开源精神，它已经帮助构建了伟大的工具。在前人的步伐中，重要的是贡献我们认为不可用且可能帮助某人应对挑战的每一点代码。

# 提交角色之前要做的事情

要能够上传和贡献到 Ansible Galaxy，您需要拥有一个 GitHub 账户。这是出于两个原因：登录到 Galaxy hub 门户和将角色代码作为项目上传到 Galaxy hub。

首次登录到 Ansible Galaxy hub 时，我们将看到各种项目访问权限配置。这将允许 Galaxy 将项目链接到您的组织。

访问权限配置始终可以从 GitHub 帐户选项界面中稍后更改。

“My Content”菜单将出现在 Galaxy hub 主页上。这可用于列出从您的帐户编写的角色。该菜单允许您添加、删除和编辑版本，以及升级角色。如果角色由多个作者维护，还可以添加贡献者。以下截图显示了 Web 界面的外观：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/8735dba8-3379-487f-a0f2-2dc4370ecc17.png)

在本地机器上，建议您使用 Git 工具的某种形式，无论是通常适用于 macOS 和 Windows OS 的漂亮图形界面，还是老式的`git`命令行。我们需要在本地登录到我们的 GitHub 存储库，以便更轻松地上传：

```
git tag 0.1
git push lab-edu.samba
```

您始终可以从 GitHub Web 界面创建一个角色。使用起来可能有点笨拙，但它完全可以胜任。

# 角色存储库

将代码上传到 GitHub 后，我们现在可以将角色导入到 Ansible Galaxy hub。从“我的内容”页面，选择“添加内容”按钮。将显示一个包含与该帐户关联的所有 GitHub 项目的框。我们选择要导入的角色，然后按“确定”。菜单如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/bf1798d5-cfd7-4810-9181-08517b52e0ff.png)

然后，角色将添加到内容列表中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/cb01bd21-cdba-4d25-8696-d1ea9eafd68a.png)

这种方法允许您向 GitHub 帐户添加任意数量的角色。这一步是角色的实际导入，Ansible Galaxy 根据`meta`文件夹中的元数据进行了一些静态分析。

添加角色后，我们可以链接从我们的 GitHub 账户导入的组织。这有助于指示合作关系并作为搜索标签。

用户帐户中的每个角色都可以进行管理，以添加作者并赋予他们某些权限，例如管理员权限。这可以在“编辑属性”菜单中更改。通过此菜单添加的任何用户都可以编辑、禁用、启用、删除和更新角色及其内容。

最后，更新 Galaxy 上的角色的最佳方法是为其内容设置版本控制方案。这个过程是通过 GitHub 标签来完成的。每当 Ansible Galaxy 从 GitHub 导入一个角色代码时，它会扫描项目以查找标签，寻找格式化以包含版本语法的标签。

# Ansible Galaxy 角色管理

现在让我们来发现 Ansible Galaxy 库提供了什么。在这一部分中，我们将探讨如何找到一个角色，以及我们应该根据什么基础来使用它，与其他具有相同功能的角色相比。我们还将探讨一些关于如何安装角色以及如何排除安装和导入问题的推荐方法。

# Ansible Galaxy 角色搜索

在这个小节中，我们将讨论如何使用 Galaxy 网页门户来查找 Ansible 角色。为了做到这一点，我们要么使用标签页面，要么使用一般搜索页面。我们建议使用其中一个标签页面来获取分类列表。

一旦我们选择了一个类别，我们就可以查看筛选器，这是一种锁定角色特定方面的方法。类别使用的筛选器可以从下拉菜单中选择。类别可以是一个简单的关键词，例如贡献者或平台，也可以是一个标签。通过选择除关键词或标签之外的类别，我们可以访问第二个下拉菜单，其中包含该类别中所有可用选项，供我们选择。

筛选器可以组合，可以跨类别组合，也可以从同一筛选器类别中选择多个条目。这将进一步缩小返回的结果。您还可以通过从搜索栏下方的筛选器列表中删除它们来删除不再需要的筛选器。筛选器功能可以在门户上的任何类别页面上使用。它也可以在社区页面上使用，该页面上包含所有作者的列表。

找到与我们的搜索匹配的角色列表并不意味着我们已经完成了。然后我们需要选择哪个角色来执行所需的任务。从与我们的搜索匹配的角色列表中，我们可以再次使用其他 Ansible 用户的帮助。Ansible Galaxy 提供了一个由不同变量组成的评级系统。您可以通过查看它有多少星来判断一个角色的质量以及其用户的满意程度。我们还可以查看有多少人正在关注该角色以跟踪正在进行的更改，这是一个很好的维护指标。特定角色被下载的次数也很有用，但您应该将其与给出的星级评分数量进行比较，因为它不显示一个角色是否被同一用户多次下载。

了解角色的作者也很重要。一些 Ansible Galaxy 作者以其高质量的角色和持续的维护而闻名。

# Ansible Galaxy 角色安装

我们可以以多种方式安装 Ansible 角色。最简单的方法是使用带有`install`选项的命令行，如下所示：

```
ansible-galaxy install geerlingguy.ntp
```

或者，我们可以通过选择我们想要的版本和来源来个性化我们的安装命令。可以按照以下步骤进行：

```
ansible-galaxy install geerlingguy.ntp,v1.6.0
ansible-galaxy install git+https://github.com/geerlingguy/ansible-role-ntp.git
```

我们还可以使用 YAML 需求文件一次安装多个角色。命令行如下所示：

```
ansible-galaxy install -r requirements.yml
```

要求文件是一个包含有关如何安装所需不同角色的指令的 YAML 结构化文件。这是一个示例要求文件：

```
# install NTP from Galaxy hub
- src: geerlingguy.ntp

# install Apache from GitHub repo
- src: https://github.com/geerlingguy/ansible-role-apache
  name: apache

# install NFS version 1.2.3 from GitHub
- src: https://github.com/geerlingguy/ansible-role-nfs
  name: nfs4
  version: 1.2.3
```

要求文件可以调用其他要求文件来安装原始要求文件中已经声明的额外角色。如下所示：

```
- include: ~/role_req/haproxy_req.yml
```

安装多个角色的另一种方法是依赖角色的`meta`文件中的依赖项部分。依赖项部分遵循与要求文件相同的规则，用于声明特定角色的来源和版本。

# Ansible Galaxy 角色故障排除

从用户的角度来看，在 Ansible 控制机器中设置角色可能会导致一些问题，这些问题主要与没有权限访问角色或角色发生故障有关。大多数错误的原因是 Ansible 的安装方式。默认的 Ansible 安装将所有配置文件、清单、角色和变量放在一个属于 root 的文件夹（`/etc/ansible`）中。因此，作为普通用户使用可能会导致一些问题。这就是为什么我们总是建议拥有一个用户个性化的 Ansible 配置文件，指向用户可以访问的文件夹。安装角色需要创建多个文件夹和文件；如果这不是在授权位置完成的，安装将失败。

我们还需要仔细检查每个角色的系统要求。它们可能需要特定版本的 Ansible 或特定文件中的特定配置。如果它们的要求之一没有得到满足，角色将无法正常工作。

关于将角色导入 Galaxy 中心，用户通常遇到的主要错误是导入失败，这通常与 playbook 中的错误或`meta`文件夹中保存的有关角色信息有关。Galaxy 中心会提供详细的错误日志，甚至可以显示发生错误的特定文件的确切行。一旦您修复了错误，就可以轻松重新启动导入并继续进行。

# 总结

Ansible Galaxy 中心是加速 Ansible 开发和成功的重要资源。借助这一资源，大多数日常任务已经转换为组织良好且资源优化的角色，可供公众使用。在本章中，我们介绍了 Ansible Galaxy，并介绍了如何在社区中进行协作。然后，我们看了如何搜索、安装和排除角色。

在[第八章]（43750355-ab57-4d16-b464-10d2a47be2ea.xhtml）*Ansible 高级功能*中，我们将简要介绍一些更高级的 Ansible 功能，这些功能对于安全性和更高级用户的需求可能会很方便。

# 参考资料

Ansible Galaxy 文档：[`galaxy.ansible.com/docs/`](https://galaxy.ansible.com/docs/)

Ansible 文档：[`docs.ansible.com/ansible/latest/`](https://docs.ansible.com/ansible/latest/)


# 第八章：Ansible 高级功能

在完成本书之前，我们想简要介绍一些 Ansible 更有趣和先进的功能。这些功能可以帮助进一步增强您的自动化。在本章中，我们将介绍三个功能：Ansible Vault，以及它增加 playbooks 和 roles 安全性的能力；Ansible Container，实现与 Ansible 的完全容器自动化；以及 Ansible 插件，具有丰富和灵活的功能集。

本章涵盖以下主题：

+   Ansible Vault 概述

+   如何配置和使用 Ansible Vault

+   Ansible Container 的好处

+   使用 Ansible Container

+   Ansible 插件及其功能概述

# Ansible Vault

在本节中，我们将介绍与 Ansible Vault 相关的功能、用例和最佳实践。

# 什么是 Ansible Vault？

Ansible Vault 是 Ansible 提供的工具，允许用户加密秘密变量，这些变量可以是认证凭据和密钥，也可以是敏感和个人用户信息。Ansible Vault 创建加密文件来存储变量，如果需要，可以将其移动到安全位置。

Ansible Vault 透明地集成到 Ansible roles 和 playbooks 的脚本中。这意味着 Vault 可以加密位于这些脚本中的任何数据结构。这包括主机和组变量，无论是存储在脚本中还是使用 `include_vars` 选项从另一个位置导入的变量。处理 Ansible role 时，它们也可以位于 `defaults` 或 `vars` 文件夹中。当需要隐藏特定变量的名称时，Vault 也可以加密任务文件。

Ansible Vault 还可以扩展到加密常规文件，如二进制文件、存档文件或文本文件。此功能与文件管理模块（如 `copy`、`unarchive` 和 `script`）一起使用。

# 使用 Ansible Vault

为了能够探索 Ansible Vault 的功能，我们需要确保至少创建了一个加密文件来存储我们的变量。为此，我们需要使用 `ansible-vault` 工具，如下所示：

```
ansible-vault create /home/admin/Vault/vault.yml
```

将出现密码输入提示，询问新创建的 Vault 文件的密码。输入密码并确认后，将在指定位置创建一个新的 Vault 文件。默认文本编辑器将打开，以便我们填写 vault 文件。

Ansible Vault 将查找 `EDITOR` 环境变量，以检查打开 vault 文件时要使用的系统默认文本编辑器。要使用特定的文本编辑器，我们需要临时更改变量，如下所示：`export EDITOR=nano; ansible-vault create /home/admin/Vault/vault.yml`。

写入 vault 文件的任何数据在文件关闭时都将被加密。我们可以尝试使用 `cat` 命令行工具绘制文本文件的内容，如下所示：

```
cat /home/admin/Vault/vault.yml
```

工具的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/b17d63b4-210d-4464-8be8-cfed1888d951.png)

Vault 文件只能使用 `ansible-vault` 命令行工具正确修改。为此，我们需要使用 `edit` 选项，如下所示：

```
ansible-vault edit /home/admin/Vault/vault.yml
```

输入文件创建时选择的 Vault 文件密码后，将默认文本编辑器打开文件并以明文显示其内容，以便更容易编辑。我们还可以使用 `view` 选项以只读模式打开 vault 文件。

```
 ansible-vault view /home/admin/Vault/vault.yml
```

运行 `ansible-vault` 命令行工具时，使用任何选项都需要输入要执行操作的 vault 文件的密码。可以使用 `rekey` 选项编辑 vault 文件密码：`ansible-vault rekey /home/admin/Vault/vault.yml`。我们需要输入原始密码，然后输入新密码并确认。

正如我们之前提到的，当与文件模块一起使用时，Ansible Vault 可以加密和解密文件。这个功能可以用来手动加密文件，并将它们转换成 vault 文件。以后需要时，始终可以手动解密它们。要执行文件加密，我们需要使用`ansible-vault`命令行工具的`encrypt`选项。

```
ansible-vault encrypt /home/admin/variables.yml
```

这个命令行将需要一个密码和确认来加密和保护新转换的 vault 文件。这个文件可以直接在下一小节中的任何 playbook 中使用。

要将 vault 文件转换为普通文本文件，我们使用相同的命令行工具，只是使用不同的选项，`decrypt`：

```
ansible-vault decrypt /home/admin/variables.yml
```

输入 vault 文件的密码后，我们应该能够使用任何工具查看和编辑文件。

# 在使用 Ansible Vault 时的最佳实践

现在我们已经学会了如何创建和加密 vault 文件，让我们看看如何在 Ansible playbooks 和 roles 中正确使用它们。为了能够使用加密变量，我们需要为 Vault 文件提供密码。当执行 playbook 时，可以通过交互式提示来简单地完成这个操作，如下所示：

```
ansible-playbook playbook.yml --ask-vault-pass 
```

或者，对于更自动化的方法，您可以指向 vault 密码将被存储的文件。操作如下：

```
ansible-playbook playbook.yml --vault-password-file /home/admin/.secrets/vault_pass.txt
```

该文件应该是一个包含密码的一行文件。如果有站点 vault 密码，我们可以通过在 Ansible 全局配置文件中添加以下行到`[defaults]`部分来设置一个持久的 vault 密码文件：

```
vault_password_file = /home/admin/.secrets/vault_pass.txt
```

从 2.3 版本开始，Ansible 引入了一种加密单个 vault 变量的方法。这需要您使用`ansible-vault`命令行工具的`encrypt_string`选项。

作为示例，我们将使用一个包含敏感变量的 vault 文件，该变量将在 playbook 中调用。首先，我们需要确保 vault 文件正确定义了变量：

```
ansible-vault edit /home/admin/vault.yml
```

我们可以使用`view`选项来验证 vault 文件的内容，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/2e20ed8b-ed16-46fe-8b84-1e466e4da441.png)

然后，我们需要验证 vault 文件是否包含在 playbook 中，并且变量是否被调用：

```
...
  include_vars: /home/admin/vault.yml
  tasks:
    name: connect to a web service
    shell: service-x -user user1 -password "{{ vault_user_pass }}"
...
```

最后，我们执行 playbook 时，指向 vault 密码文件的位置：

```
ansible-playbook service_connect.yml --vault-password-file /home/admin/.vault
```

在通常的主机或组变量文件夹中，最好有一组两个变量文件。您应该在第一个文件中填写所有必要的变量，并且只在第二个文件中填写要加密的变量，通过给它们的名称添加特殊的前缀。然后，使用 Jinja2 语法调整第一个文件中的变量，使它们指向第二个文件中匹配的带前缀的变量。确保您的第二个文件使用 Ansible Vault 进行加密。这种方法在管理许多需要加密的变量时会更加方便。

为了增强使用 Ansible Vault 时的加密和解密速度，建议在系统上安装 Python `cryptography`包。这可以通过 Python PyPI 轻松安装：`pip install cryptography`。

# Ansible Container

在这一部分，我们将讨论 Ansible 为其容器用户提供的非常方便的功能。

# Ansible Container 是什么？

Ansible Container 是一个帮助 Ansible 用户自动构建、部署和管理他们的容器的开源项目。这个功能允许在构建 compose 文件时更好地管理容器代码，并允许您在任何公共或私有云注册表上部署容器。

使用 Ansible Container，我们可以像在虚拟机和裸机主机上一样使用 Ansible 功能与容器。

# 使用 Ansible Container

Ansible Container 默认情况下不作为 Ansible 原始安装的一部分安装。我们需要在容器主机上单独安装它。为了简化安装过程，我们将依赖于 Python PyPI 来安装必要的软件包。Ansible Container 需要容器引擎才能工作，因此我们需要在安装过程中指定一个。以下命令显示了我们如何使用两个引擎 Docker 和 Kubernetes 安装 Ansible Container：

```
pip install ansible-container[docker,k8s]
```

Ansible Container 有一个特殊的重型容器，称为 Conductor，在构建过程中生成。Conductor 包含了构建目标容器镜像所需的所有依赖项。

用于管理容器的 Ansible 命令行 `ansible-container` 提供了从开发级别到测试和生产的多种功能。我们使用 `init` 选项来创建容器文件夹和初始配置文件：

```
ansible-container init
```

在执行命令的目录中应该存在以下文件列表：

```
ansible.cfg
ansible-requirements.txt
container.yml
meta.yml
requirements.yml
.dockerignore
```

`ansible-container` 命令行还通过启动 Conductor 容器来启动容器构建过程，以运行在 `container.yml` 文件中指定的实例和基础容器镜像。然后，在容器的多个层中安装了在文件中指定的 Ansible 角色。所有这些都是通过容器引擎完成的。完整的命令行应该如下所示：

```
ansible-container build
```

我们还可以编排一个容器修改，只更新受更改影响的容器镜像，而不重新构建所有镜像，以加快开发速度。在运行以下命令之前，我们需要确保更改已经在 `container.yml` 文件中进行了保存：

```
ansible-container run
```

然后，为了上传和构建容器镜像到云注册表，我们需要使用 `deploy` 选项。这个选项还允许您生成 Ansible 代码来编排容器镜像的构建以及在使用 Kubernetes 或 Red Hat OpenShift 时的生产容器平台。完整的命令行应该如下所示：

```
ansible-container deploy
```

至于 `init` 选项生成的文件，我们可以识别出以下内容：

+   `container.yml`：这是一个描述容器服务、如何构建和运行容器以及要推送到哪些存储库的 YAML 文件。

+   `meta.yml`：这个文件包含了使容器项目能够在 Ansible Galaxy 上共享所需的信息。

+   `ansible-requirements.yml`：这个文件存储了 Conductor 容器在构建时使用的 Python 依赖项。

+   `requirements.yml`：这个文件列出了容器中要使用的角色。

+   `ansible.cfg`：这个文件包含了在 Conductor 容器中要遵循的 Ansible 配置。

+   `.dockerignore`：这个文件包含与容器项目无关的文件列表。在构建和上传容器项目时应该忽略这些文件。

# 示例 Ansible 容器

例如，我们将创建一个简单的 Web 服务器。首先，我们需要创建我们的 Ansible 容器文件夹和初始配置文件：

```
mkdir /home/admin/Containers/webserver
cd /home/admin/Containers/webserver
ansible-container init
```

然后，我们开始编辑我们创建的文件。我们从 `container.yml` 文件开始，并填写以下代码：

```
version: '2'
settings:
  conductor:
    base: 'ubuntu:xenial'
  project_name: webserver

services:
  web:
    from: centos:7
    command: [nginx]
    entrypoint: [/usr/bin/entrypoint.sh]
    ports:
      - 80:80
    roles:
      - nginx-server
```

然后，我们填写 `meta.yml` 文件，以防需要将我们的容器项目上传到 Ansible Galaxy。我们需要向其中添加以下代码：

```
galaxy_info:
   author: alibi
   description: A generic webserver
   licence: GPL3

   galaxy_tags:
        - container
        - webserver
        - nginx
```

然后，我们编辑 `requirements.txt` 文件，并添加以下要求：

```
 nginx-server
```

我们将保留 `ansible.cfg`、`.dockerignore` 和 `ansible-requirements.yml` 文件不变。对于这个容器项目，我们不需要改变这些文件中的任何内容。

现在我们可以构建我们的容器了：

```
ansible-container build
```

# Ansible 插件

在本节中，我们将简要介绍 Ansible 插件，并讨论如何开发我们自己的插件。

# 什么是 Ansible 插件？

Ansible 插件是一些代码和功能，它们增加了 Ansible 的原始核心功能。这些插件使 Ansible 能够控制几个 API 和工具，从而实现多个模块的正确功能。

Ansible 的默认安装包括几个基本插件，如下列表所示：

+   动作插件：这些是模块的前端插件。它们可以在调用模块本身之前在主机上执行操作。

+   缓存插件：这些是用于缓存主机事实的后台插件。这有助于优化事实收集。

+   回调插件：这些帮助监控和日志收集工具与 Ansible 一起进行优化监控。

+   连接插件：这些负责与支持不同类型连接的远程主机进行通信。

+   清单插件：这些插件帮助从指定的主机生成清单。

+   Shell 插件：这些是用于检查命令是否格式正确并符合目标机器的命令控制器。

+   策略插件：这些控制 Ansible plays 的执行以及任务和计划的流水线化。

+   Vars 插件：这些插入在清单或组或主机变量中定义但对任务执行所需的变量。

# 开发 Ansible 插件

Ansible 确实包含了许多插件在其软件包中，但总是可以开发我们自己的插件。这将有助于扩展 Ansible 的功能。Ansible 通过提供托管多个预先编写的方法和函数的基类来帮助开发人员创建新的插件，这些方法和函数可以与新的插件一起使用，以防止不必要的编码。此外，当我们完成编写一个插件后，可以使用 Ansible 的插件 API 轻松地为其编写一个简单的单元测试。

# 总结

在本章中，我们介绍了 Ansible 提供的一些适用于更高级用途的便利功能。我们首先看了 Ansible Vault，它在基础设施自动化过程中提供了增强的安全性。然后我们看了 Ansible Container，它涵盖了构建和管理容器的新趋势。最后，我们看了 Ansible 插件以及它们如何允许我们个性化我们的自动化。

通过本章，我们完成了*Ansible 快速入门指南*。然而，这并不是旅程的终点；Ansible 还有很多可以提供的，真正掌握它的最佳方法是尽可能多地进行项目。总会有其他书籍、网络论坛和博客来帮助指导您。

# 参考

这是 Ansible 文档网站：[`docs.ansible.com/ansible/latest`](https://docs.ansible.com/ansible/latest)。
