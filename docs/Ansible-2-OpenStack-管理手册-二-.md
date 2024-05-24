# Ansible 2 OpenStack 管理手册（二）

> 原文：[`zh.annas-archive.org/md5/F107565E531514C473B8713A397D43CB`](https://zh.annas-archive.org/md5/F107565E531514C473B8713A397D43CB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：迁移实例

在本章中，我们将介绍使用内置在计算服务（Nova）中的 OpenStack 本机功能迁移实例的任务。如前所述，许多人并不知道这种功能的存在。在本章中，我们将通过演示如何手动迁移实例来证明这种功能。此外，我们将审查自动化此任务所需的步骤，并最终创建一个包含角色的 playbook，以完全自动化实例迁移到指定的计算节点。

本章将涵盖以下主题：

+   实例迁移

+   自动化考虑

+   编写 playbook 和角色

+   Playbook 和角色审查

# 实例迁移

每当提到实例迁移的话题时，通常会因为各种原因而引发一场激烈的讨论。因此，作为一个负责任的成年人，我将继续记录并说实例迁移并不完美。

它有其缺陷，可能有些古怪。无论是实时迁移还是非实时迁移，都对您的 OpenStack 云具有实际用途。在 OpenStack 中，您可以将实例从一个计算节点迁移到另一个计算节点。您可能这样做的原因之一是为了维护目的和/或在云中重新平衡资源利用率。此外，请记住，有多种方法可以清除计算节点以进行维护，我们将在第八章中更详细地介绍这一点，*设置主动-主动区域*。

### 注意

如前所述，OpenStack 计算服务（Nova）具有传统方法迁移实例和实例迁移的功能。

我们将首先检查传统迁移方法及其属性。

传统迁移方法将通过关闭该实例，将实例镜像/文件复制到下一个可用的计算节点，启动新节点上的实例，最后从原始节点中删除实例来移动实例。在这种方法中需要关注的区域是：

+   实例已关闭

+   实例镜像/文件将需要一些时间复制到新的计算节点

+   新的计算节点选择由 Nova Scheduler 完成；您不能在没有额外步骤的情况下分配一个

+   一旦复制完成，实例就会重新上线

正如您所注意到的，这种方法可能被一些人认为是侵入性的。关闭实例以移动它的想法通常不是虚拟化时代中的理想情景。请记住，我们处于一个新时代，*云和可丢弃资源的时代*。

由于资源是随时可用的，并且您有控制权来确定如何使用这些资源，应该没有问题将实例下线。对吗？是的，我知道要摆脱那种*宠物*心态可能需要一段时间，但您会做到的。如果情况允许，通常意味着您在分布在您的 hypervisors 上运行应用程序的实例方面做得很好，您可以非常容易地使用这种方法来迁移实例。

通过 OpenStackClient CLI 进行传统实例迁移命令的工作示例如下：

```
**$ openstack server migrate <instance>**
**$ openstack server migrate testinst**

```

另一种迁移方法是执行实时实例迁移。这种方法将消除之前描述的传统迁移过程中关闭实例的要求。而不是关闭实例，它被挂起（仍处于运行状态），同时实例被重新分配到新的计算节点。自**Mitaka**发布以来，已经取得了很大进展，以改进此功能。这些新增功能包括跟踪迁移进度的能力，暂停或取消正在进行的迁移以及排除某些附加卷的可能性。

为了利用实时迁移功能，还需要满足其他系统要求。这些要求如下：

+   您的计算节点之间必须存在某种共享或外部存储能力

+   使用实时迁移，您可以选择新的计算节点，但必须确保新节点具有新实例所需的资源

+   旧的和新的计算节点必须具有相同的 CPU；如果不是这种情况，Kilo 之前的 OpenStack 版本可能会遇到问题

列表中的第一个要求是最重要的，它值得进一步解释。附加存储要求可以通过以下三种不同方式进行满足：

+   满足需求的第一种方法是配置您的 hypervisor 以存储并访问共享存储以进行实例放置。这意味着实例存储在共享存储设备上，而不是在临时存储上。这可能涉及在计算节点上挂载 NFS 共享以用于存储实例，或通过光纤通道在计算节点之间共享 LUN，例如。

+   满足共享/外部存储要求的第二种方法可能是利用直接块存储，其中您的实例由基于镜像的根磁盘支持。

+   第三种和最后一种方法可能是来自卷存储功能的引导。这是您从 Cinder 基于卷引导实例的地方。当然，您需要在 OpenStack 云中启用和配置块存储服务（Cinder）。

### 注意

在 Nova 中使用实时迁移功能时的一个关键消息是，您的实例必须存在于某种共享/外部存储上，并且不能使用计算节点本地的临时存储。有关所需配置的更多详细信息，请访问[`docs.openstack.org/admin-guide/compute-configuring-migrations.html`](http://docs.openstack.org/admin-guide/compute-configuring-migrations.html)。

通过 Nova CLI 执行实例`server migrate`命令的工作示例如下：

```
**$ openstack server migrate --live=<new compute node> <instance>**
**$ openstack server migrate --live=compute01 testinst**

```

如前所述，实例迁移的整个概念可以从非常简单到极其复杂。希望您现在可以清楚地了解所需的内容以及实例迁移过程。现在让我们来检查使用 CLI 手动迁移实例的过程。

### 注意

出于简单起见，我们将仅使用 OpenStack CLI 演示手动命令。

## 手动迁移实例

计算服务（Nova）负责管理实例迁移过程。 Nova 在幕后将执行重新分配实例到新节点以及实例镜像/文件移动所需的所有步骤。与每个 OpenStack 服务一样，您必须首先进行身份验证，要么通过在第一章中讨论的 OpenRC 文件中进行源化，要么通过在命令中使用内联传递身份验证参数。这两个任务分别需要提供不同的参数值，以便成功执行命令。这里提到了示例。

使用 OpenRC 文件进行实例迁移：

```
**$ source openrc** 
**$ openstack server migrate <instance>**

```

通过内联传递身份验证参数进行实例迁移：

```
**$ openstack --os-cloud=<cloud name> server migrate <instance>**

```

发出`openstack server migrate`命令后，我通常会跟上`openstack server show`命令，以报告实例迁移过程。这是我通常不会经常使用的东西，当自动化 OpenStack 任务时，这是显而易见的原因。由于迁移过程可能需要一些时间，而我们正在手动执行任务，因此有助于跟踪其进展。

另一种检查迁移的方法是使用传统的 Nova CLI 和`nova migration-list`命令。

使用 OpenRC 文件的实际工作示例可能如下所示：

```
**$ source openrc**
**$ openstack server list**
**$ openstack server migrate test-1ae02fae-93ca-4485-a797-e7f781a7a25b**
**$ nova migration-list**

```

`nova migration-list`命令的输出将类似于这样：

![手动迁移实例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/B06086_06_01.jpg)

在之前的命令中提供的完整输出将根据之前执行的任何迁移而有所不同。要关注的关键信息是您刚刚尝试迁移的实例的迁移`Status`。状态将报告为`migrating`或`finished`。一旦状态更新为`finished`，您就可以确认实例的迁移。

迁移后，实例将默认处于`VERIFY_RESIZE`状态，无论您是否实际上调整了它的大小。

![手动迁移实例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_06_002.jpg)

然后，您需要执行`openstack server resize`命令将实例恢复到`ACTIVE`状态。以下示例演示了这个任务：

```
**$ openstack server resize 
  --confirm test-1ae02fae-93ca-4485-a797-e7f781a7a25b**

```

到此为止，您可以开始了！您的实例已经迁移到一个新的计算节点，并且现在处于`ACTIVE`状态。对于我们中的一些人来说，已经习惯了接受传统的迁移过程，下一个问题通常是，为什么我不能使用 nova migrate 命令将实例迁移到特定的计算节点？我们将在下一节讨论这个问题。

## 将实例迁移到特定的计算节点

对于之前提到的问题，诚实而直接的答案是我不知道为什么没有包括这个功能。好消息是，就像 OpenStack 内的大多数事物一样，总是有办法让它按照您的意愿去做。

### 注意

请注意，下面概述的步骤是 100%的解决方法（中等脏的解决方法），在未经多层测试以确保预期功能的情况下，不应在生产环境中使用。

如前面的章节所述，您无法使用传统的迁移方法将实例迁移到特定的计算节点。这个选项实际上是不存在的（希望很快会改变）。但是，您可以通过禁用其他计算节点来欺骗 Nova 调度程序，将实例放置在选定的计算节点上。Nova 调度程序将别无选择，迁移实例到您选择的计算节点上。是的，在您的脑海中，您刚刚称呼我为白痴。不要担心，这在纸上听起来并不像是那么具有侵入性。

OpenStack 控制平面服务旨在报告分布式组件（如计算节点和/或 Cinder 节点）的状态。然后，接收到的报告存储在 OpenStack 数据库中，控制平面服务就知道特定节点是上线还是下线。同样，控制平面服务也可以强制报告节点的状态。

计算服务（Nova）是一个可以强制报告计算节点状态的示例服务。这只会在数据库中标记计算节点的上线或下线状态，实际上并不会对计算节点做任何物理操作。所有运行在这些计算节点上的实例将继续运行，节点的整体功能将保持不变。然而，在数据库中禁用节点的时间内，将阻止在该节点上创建新实例。如果您的 OpenStack 云非常繁忙且不使用分离的计算节点集，这种解决方法可能不是一个明智的选择。

由于其侵入性，这感觉像是一个完美的管理任务，可以尝试自动化。对于这样的任务，时间和准确性非常关键。浪费一分钟的时间可能导致无法在 OpenStack 云内部创建任意数量的新实例。对于这种性质的任务，自动化是王道。在接下来的几节中，我们将回顾自动化这个任务所需的步骤。

# 自动化考虑

这个任务也不需要做出任何新的框架决定。我们之前审查过的所有其他自动化决策都被延续了。

在我们开始之前，值得注意的是，当自动化像这样的任务（迁移实例并禁用计算节点）时，最好在迁移前后收集有关它们的详细信息。拥有这些详细信息将简化您需要时撤销更改的过程。是的，这将为您的角色增加额外的任务，使其稍微复杂一些，但仍然非常值得。

有了这些说法，我们现在准备继续创建我们的下一个剧本和角色。

# 编写剧本和角色

在本节中，我们将创建允许您使用传统的`openstack server migrate`命令将实例迁移到特定计算节点的剧本和角色。与迄今为止创建的其他任务不同，处理此任务实际上只有一种方法。我们将采取前两节中概述的步骤，自动化它们，以便您只需要提供一些变量值，然后执行一个命令。

本章开始讨论了实例迁移以及在 Nova 中处理此问题的两种选项：传统迁移和在线迁移。传统迁移过程实际上是一个一步过程，但为了正确自动化此任务，我们需要向该过程添加一些步骤。我们将不得不创建的任务的简要概述如下：

1.  列出计算节点。

1.  收集预迁移实例详细信息。

1.  禁用除了我们希望实例迁移到的计算节点之外的所有计算节点。

1.  迁移实例。

1.  启用所有计算节点。

1.  确认实例迁移。

1.  收集迁移后实例的详细信息。

## 角色详细信息

由于在此示例中我们只创建一个角色，因此可以从角色目录中的`instance-migrate/tasks`中的`main.yml`文件开始。此文件的初始内容将如下所示：

```
--- 

- name: Retrieve hypervisor list 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}" 
     hypervisor list | awk 'NR > 3' | awk '$4 != "{{ desthype }}" 
     { print $4 }' 
 register: hypelist 

```

检索 OpenStack 云中所有计算节点的完整列表的第一步非常容易，只需使用`openstack hypervisor list`命令。一旦获得这些结果，最好将输出精简为您所需的信息。同样，我们将使用`awk`命令和管道（`|`）符号来做到这一点。您会注意到这与我们在上一章中所做的方式类似。请记住，这里使用 shell 模块是因为我们正在执行需要特定于 shell 的操作的命令。

对于这个特定的任务，我们必须使用`awk`命令进行一些魔术操作：

```
**awk 'NR > 3' | awk '$4 != "{{ desthype }}" { print $4 }'**

```

它不仅会提取标准 CLI 输出的前三行，还会检查第四列并打印所有输出，除了与`{{ desthype }}`变量匹配的内容。然后将整理后的输出注册到名为`hypelist`的变量中。

下一个任务现在将收集预迁移实例详细信息，这些信息将在角色内稍后使用。完成此操作的代码如下：

```
- name: Collect pre-migration instance details 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}"  
     server list --name "{{ instance }}" --long | awk 'NR > 3' | awk '{ print $16 }' 
 register: preinststat 

```

对于这个任务，我们再次使用 OpenStackClient CLI 使用`openstack server list`命令提供实例详细信息。您也可以使用`openstack server show`命令列出实例详细信息。这两个命令之间的明显区别在于`openstack server list`命令可以选择在输出上显示附加字段。要执行此操作，请添加`--long`的可选参数。

在我们的特定情况下，我们想知道特定实例当前正在运行的计算节点。因此，我们需要确保`openstack server list`命令如下所示：

```
**openstack server list --name {{ instance }} --long**

```

第三个任务将是禁用您不希望实例迁移到的计算节点。请记住，我们只是在 Nova 中禁用计算节点，而不是物理上改变计算节点的状态。执行此操作的代码将如下所示：

```
- name: Disable unselected hypervisors 
 command: nova "{{ AUTH_S }}"  
      service-disable "{{ item }}" nova-compute --reason '{{ migreason }}' 
 with_items: "{{hypelist.stdout_lines}}" 

```

通过使用`nova service-disable`命令，您可以告诉 Nova 在远程主机上禁用任何特定的与 Nova 相关的服务。为了让 Nova Scheduler 忽略/跳过计算节点，您需要禁用 nova-compute 服务。该命令还需要提供一个原因，如果需要的话，将存储在 Nova 数据库中以供以后参考。在这个任务中，我们将使用之前收集到的`hypelist`变量中存储的计算节点列表。

### 注意

请注意，我们不会禁用我们希望将实例迁移到的计算节点，因为我们已经将其从列表中过滤出来。

进入第四个任务，我们现在将执行实例迁移。在这一点上，只有您选择接收迁移实例的计算节点是启用的，关于`openstack server migrate`不需要做任何特殊的事情。支持代码请参见这里：

```
- name: Migrate instance 
 command: openstack --os-cloud="{{ CLOUD_NAME }}"  
      server migrate "{{ instance }}" 

```

迁移完成后，我们需要立即重新启用被禁用的计算节点。我欣赏 OpenStack 的一点是，如果您被给予禁用某些东西的命令，通常也会给您一个重新启用它的命令。因此，我们只需执行`nova service-enable`命令。同样，我们将使用`hypelist`变量来提供要执行的计算节点列表。使用的代码如下：

```
- name: Enable the disabled hypervisors 
 command: nova "{{ AUTH_S }}" 
      service-enable "{{ item }}" nova-compute 
 with_items: "{{hypelist.stdout_lines}}" 

```

现在迁移已经完成，并且计算节点都已启用，我们可以专注于完成实例迁移过程。实例迁移的最后一步是通知 Nova，您确认实例已经移动。乍一看，我可以不做这一步，但事后来看，某种确认确实是有意义的。此任务的代码可以在这里找到：

```
- name: Confirm instance migration 
 command: openstack --os-cloud="{{ CLOUD_NAME }}"  
      server resize --confirm "{{ instance }}" 

```

最后两个任务将用于向运行 playbook 的个人提供对所做工作的可视确认。考虑这更多是一个自动化的故障安全，而不是一个要求。对于这样一个复杂的管理任务，总是一个很好的常规做法是输出一些关于系统上发生了什么变化的细节：

```
- name: Collect post-migration instance details 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}"  
     server list --name "{{ instance }}" --long | awk 'NR > 3' | awk '{ print $16 " and has a status of " $10 }' | awk 'NR == 1' 
 register: postinststat 

- name: Show instance location and status 
 debug: msg="{{ instance }} was migrated from {{ item.0 }} to {{ item.1 }}" 
 with_together: 
  - "{{preinststat.stdout_lines}}" 
  - "{{postinststat.stdout_lines}}" 

```

这两个任务将首先收集迁移后实例的详细信息，然后使用从`preinststat`和`postinststat`变量收集到的信息在屏幕上输出变更的摘要。使用的摘要模板将是：

<实例已迁移>已从<计算节点>迁移到<计算节点>，状态为<实例当前状态>

### 提示

随意进入并进行更改以适应您的需求。这只是我的意见方法。保持简单，同时提供处理迁移时关心的相关细节，这样做感觉是正确的。在回顾 playbook 时，如果出现问题和/或实施不正确，您应该能够快速定位需要纠正的步骤。

## 变量细节

再次恭喜，您已经完成了第四个 OpenStack 管理角色。为了支持这个角色，我们现在需要创建与之配套的变量文件。变量文件名为`main.yml`，将位于`instance-migrate/vars`目录中。

### 提示

请记住，变量文件中定义的值是为了在正常的日常使用中在每次执行之前进行更改的。

对于这个角色，我们在变量方面保持了相当简单，只需要定义三个变量：

```
--- 
desthype: 021579-compute02 
instance: testG-2c00131c-c2c7-4eae-aa90-981e54ca7b04 
migreason: "Migrating instance to new compute node" 

```

让我们花点时间来分解每个变量。总结如下：

```
desthype   # this value would be the name of the compute node you wish 
             to migrate the instance to 

instance   # the name of the instance to be migrated 

migreason: # a string encapsulated in quotes to explain the reason 
             for migrating the instance (keep the string brief) 

```

## Playbook 细节

完成变量文件后，我们可以继续创建主 playbook 文件。文件名为`migrate.yml`，保存在`playbook`目录的`root`目录中。

### 注意

playbook 和角色的名称可以是您选择的任何内容。这里提供了具体的名称，以便您可以轻松地跟踪并参考 GitHub 存储库中找到的完成代码。唯一的警告是，无论您决定如何命名角色，都必须在 playbook 中引用时保持统一。

`migrate.yml`文件的内容将是：

```
--- 
# This playbook used to migrate instance to specific compute node.  

- hosts: util_container 
 remote_user: root 
 become: true 
 roles: 
  - instance-migrate 

```

该文件的摘要如下：

```
hosts       # the host or host group to execute the playbook against 

remote_user # the user to use when executing the playbook on the remote host(s) 

become      # will tell Ansible to become the above user on the remote host(s) 

roles       # provide a list of roles to execute as part of this playbook 

```

我们已经在两章前向主机清单文件和全局变量文件添加了内容，所以我们已经完成了这部分。之前定义的值将保持不变。以下是这些文件配置的快速回顾。

`hosts`文件位于 playbook 目录的 root 目录中：

```
[localhost] 
localhost ansible_connection=local 

[util_container] 
172.29.236.199 

```

`group_vars/`目录中的全局变量文件是：

```
# Here are variables related globally to the util_container host group 

CLOUD_NAME: default 

AUTH_S: --os-username {{ OS_USERNAME }} --os-password {{ OS_PASSWORD }} --os-project-name {{ OS_TENANT_NAME }} --os-domain-name {{ OS_DOMAIN_NAME }} --os-auth-url {{ OS_AUTH_URL }} 

OS_USERNAME: admin 
OS_PASSWORD: passwd 
OS_TENANT_NAME: admin 
OS_DOMAIN_NAME: default 
OS_AUTH_URL: http://172.29.238.2:5000/v3 

```

### 注意

**警告**

由于该文件的内容，它应该作为安全文件存储在您可能用来存储 Ansible playbooks/roles 的任何代码存储库中。获取这些信息可能会危及您的 OpenStack 云安全。

我们现在进展非常顺利，微笑，您做到了！希望到目前为止一切都变得更加清晰。保持我们的传统，我们将以快速回顾刚刚创建的 playbook 和 role 结束本章。

# 审查 playbook 和 role

让我们直接开始检查我们创建的 role，名为`instance-migrate`。位于`instance-migrate/tasks`目录中的已完成 role 和文件，名为`main.yml`，看起来是这样的：

```
--- 

- name: Retrieve hypervisor list 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}" 
     hypervisor list | awk 'NR > 3' | awk '$4 != "{{ desthype }}" { print $4 }' 
 register: hypelist 

- name: Collect pre-migration instance details 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}"  
     server list --name "{{ instance }}" --long | awk 'NR > 3' | awk '{ print $16 }' 
 register: preinststat 

- name: Disable unselected hypervisors 
 command: nova "{{ AUTH_S }}"  
      service-disable "{{ item }}" nova-compute --reason '{{ migreason }}' 
 with_items: "{{hypelist.stdout_lines}}" 

- name: Migrate instance 
 command: openstack --os-cloud="{{ CLOUD_NAME }}"  
      server migrate "{{ instance }}" 

- name: Enable the disabled hypervisors 
 command: nova "{{ AUTH_S }}" 
      service-enable "{{ item }}" nova-compute 
 with_items: "{{hypelist.stdout_lines}}" 

- name: Confirm instance migration 
 command: openstack --os-cloud="{{ CLOUD_NAME }}"  
      server resize --confirm "{{ instance }}" 

- name: Collect post-migration instance details 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}"  
     server list --name "{{ instance }}" --long | awk 'NR > 3' | awk '{ print $16 " and has a status of " $10 }' | awk 'NR == 1' 
 register: postinststat 

- name: Show instance location and status 
 debug: msg="{{ instance }} was migrated from {{ item.0 }} to {{ item.1 }}" 
 with_together: 
  - "{{preinststat.stdout_lines}}" 
  - "{{postinststat.stdout_lines}}" 

```

该角色的对应变量文件，名为`main.yml`，位于`instance-migrate/vars`目录中，将如下所示：

```
--- 
desthype: 021579-compute02 
instance: testG-2c00131c-c2c7-4eae-aa90-981e54ca7b04 
migreason: "Migrating instance to new compute node" 

```

接下来，位于`playbook`目录的`root`目录中的主 playbook 文件，名为`migrate.yml`，将如下所示：

```
--- 
# This playbook used to migrate instance to specific compute node.  

- hosts: util_container 
 remote_user: root 
 become: true 
 roles: 
  - instance-migrate 

```

接下来，我们创建了`hosts`文件，它也位于`playbook`目录的`root`目录中：

```
[localhost] 
localhost ansible_connection=local 

[util_container] 
172.29.236.199 

```

最后，创建名为`util_container`的全局变量文件，并将其保存到 playbook 的`group_vars/`目录中将完成 playbook：

```
# Here are variables related globally to the util_container host group 

CLOUD_NAME: default 

AUTH_S: --os-username {{ OS_USERNAME }} --os-password {{ OS_PASSWORD }} --os-project-name {{ OS_TENANT_NAME }} --os-domain-name {{ OS_DOMAIN_NAME }} --os-auth-url {{ OS_AUTH_URL }} 

OS_USERNAME: admin 
OS_PASSWORD: passwd 
OS_TENANT_NAME: admin 
OS_DOMAIN_NAME: default 
OS_AUTH_URL: http://172.29.238.2:5000/v3 

```

### 注意

完整的代码集可以在 GitHub 存储库中找到，[`github.com/os-admin-with-ansible/os-admin-with-ansible-v2`](https://github.com/os-admin-with-ansible/os-admin-with-ansible-v2)。

我们终于来到了我最喜欢的部分，即测试我们的出色工作。幸运的是，我已经解决了所有的错误（眨眼）。假设您已经克隆了前面的 GitHub 存储库，从部署节点测试 playbook 的命令将如下所示：

```
**$ cd os-admin-with-ansible-v2**
**$ ansible-playbook -i hosts migrate.yml**

```

可以在此处查看 playbook 执行输出的示例：

![审查 playbook 和 role](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/B06086_06_03.jpg)

# 摘要

很高兴完成了另一个涵盖现实生活中 OpenStack 管理职责的章节。您创建的 playbooks 和 roles 越多，您就能够通过简单地重用先前为其他目的创建的代码来更快地创建新代码。在本书结束之前，您将拥有一个不错的 playbooks/roles 集合，以供将来的 Ansible 自动化参考。

回顾本章时，您会回想起我们讨论了实例迁移是什么，以及为什么您会想要使用这个功能。我们回顾了两种可能的迁移方法：传统迁移和在线迁移。您学会了如何手动迁移实例，以及如何使用传统迁移将实例迁移到特定计算节点的解决方法。最后，我们创建了 Ansible playbook 和 role 来自动化这种解决方法。总体而言，实例的维护和在计算节点之间的移动不断改进。在某个时候，您将不需要使用本章提到的一些解决方法。敬请期待一些很棒的改进！

下一章是一个热门话题，因为我们许多人都在探索容器技术。特别是，我们关注如何在利用 OpenStack 云的同时消耗和使用容器。现在有几种方法可用，但关键是自动化这个过程，使其成为可重复使用的功能。在下一章中，我们将介绍每种方法，并展示如何成功地完成这一过程的构建模块。再拿一杯咖啡，做个快速伸展，让我们开始《第七章》*在您的云上管理容器*！


# 第七章：在您的云上管理容器

在本章中，我们将介绍当前最受讨论的技术方法之一，即容器。围绕容器的流行度不断增加，这是理所当然的，谁不希望有一种更容易部署应用程序和一种整合的方法来使用计算资源？我喜欢使用的最佳类比之一是，在谈论容器时，除了显而易见的船上的集装箱类比之外，想象把所有的代码放进一辆汽车或 SUV 中。然后一辆车辆载体出现在你家门口来接你的车辆。你的车辆的维护将几乎没有，因为车辆载体正在做所有的工作。你只需要担心确保车辆载体正常工作。这就是容器背后的原理，我们将深入探讨容器概念，还将学习如何利用 OpenStack 和/或 Ansible 来构建和部署它们。与我们通常的做法一样，当我们逐个部分进行时，我们将创建一些 Ansible 示例，以展示您可能如何管理各种不同的容器格式。本章将涵盖以下主题：

+   解释容器概念

+   构建和部署容器

+   使用 Ansible Container 构建容器

+   在 OpenStack 上部署 Kubernetes

+   使用 Ansible 管理 CoreOS 和 Docker

+   在 OpenStack 上部署 Nova LXD

+   审查 playbooks 和 roles

# 解释容器概念

我必须相信大多数对技术感兴趣的人已经知道容器化（又称容器）是什么，但在我假设错误的怪异机会中，开始解释它究竟是什么感觉是一个好主意。我会尽力不只是给出维基百科的定义，而是尽力为为什么容器模型是资源虚拟化的一个非常有用的补充提供一些实质性的意义。

随着传统虚拟化的开始，人们意识到我可以将我的服务器切成可消耗的块。不再需要将整个服务器专用于成为网络或应用程序服务器。随之而来的是云的采用，因为许多人开始意识到他们没有正确使用这些虚拟化资源。虚拟机闲置或拥有不需要的过多资源。云的一个主要卖点是你可以只使用你需要的资源，并且这些资源是可丢弃的，即使用后就丢弃。尽管这些技术使消耗计算资源变得更容易，但它们都没有真正帮助改善应用程序的部署方式。

记住你为什么需要那些虚拟机和实例，那就是为了运行应用程序。如果获取资源的速度更快，但部署新应用程序仍然需要几天，那有什么意义呢？在我看来，这就是容器化方法被设计的基础。开发人员和系统管理员（主要是系统管理员）希望有一种更有效的部署应用程序的方法。我个人还记得部署新应用程序或 API 的极其痛苦的过程。它包括尝试按照开发人员编写的部署文档进行部署，而这些开发人员很可能以前从未登录过服务器或管理过网络/应用程序服务器软件。让我们只说它充满了遗漏的步骤、错误的命令，并且永远无法考虑到可能需要的任何环境修改（例如依赖软件版本）。

快进到现在，你现在有更多的选择。现在有很多不同的容器技术，允许开发人员将应用程序打包到容器中，然后将其直接*部署*到你选择的容器平台。不再需要部署文档，不再需要凌晨 2 点的部署派对，最重要的是不再有部署错误。由于容器包含了应用程序的完整运行时环境，你只需要管理容器技术本身和它运行的操作系统。容器也很容易在环境之间或系统之间移动，因为唯一的依赖是运行相同容器技术的服务器。

现在你已经了解了一些关于容器的知识，你必须选择最适合你需求的平台。一些最流行的容器技术包括 Docker ([`www.docker.com`](https://www.docker.com))，Kubernetes ([`kubernetes.io`](http://kubernetes.io))，CoreOS ([`coreos.com`](https://coreos.com))和 LXC/LXD ([`linuxcontainers.org`](https://linuxcontainers.org))。

所以在你问之前，你可能会想，由于容器相对较新，它是否可以被信任，容器化概念是否已被证明有效？答案是肯定的，因为容器并不是一个新概念。容器或容器化的概念已经存在了 10 年。第一个容器技术是 LXC，它已经成为 Linux 内核的一部分多年了。因此，我可以肯定地说它已经经过了测试，并且绝对是一个值得加入你的组织组合中的技术。

我们现在可以开始探索容器并制定如何在你的 OpenStack 云上自动构建和部署它们的旅程。我们旅程中需要走的第一步是构建我们的第一个容器。

# 构建和部署容器

在这一部分，我们将学习如何设计、构建和部署各种容器技术的容器。我们将在这里涵盖的主题包括：

+   使用 Ansible Container 构建容器

+   在 OpenStack 上部署 Kubernetes

+   使用 Ansible 管理 CoreOS 和 Docker

+   在 OpenStack 上部署 Nova LXD

如前所述，我们将首先学习如何使用我认为是最简单的容器工具 Ansible Container 构建我们的第一个容器。希望你也很兴奋，因为我肯定是，让我们开始吧！

## 使用 Ansible Container 构建容器

什么是 Ansible Container？

> *Ansible 将 Ansible Container 描述为"容器开发、测试和部署的终极工作流" - ([`docs.ansible.com/ansible-container`](https://docs.ansible.com/ansible-container))*

把它看作是一个工作流工具，它不仅可以帮助你构建 Docker 镜像，还可以使用 Ansible playbooks 编排它们和应用程序的部署。我会给你一点时间来整理一下自己。是的，我们的朋友 Ansible 又一次做到了，并提供了另一个很棒的工具放入我们的工具箱中。不再只依赖 Dockerfile。Ansible 带来的所有功能现在可以直接与构建、运行、部署，甚至将容器镜像推送到选择的注册表相结合。关于 Ansible Container 的所有信息都可以在这里找到：[`docs.ansible.com/ansible-container`](http://docs.ansible.com/ansible-container)。

就像对待每个其他工具一样，Ansible 使得以 Ansible Container 为中心的焦点变得简单易用。就我个人而言，我能够在短短几个小时内安装它并部署我的第一个容器。Ansible Container 的关键功能之一是能够利用来自 Ansible Galaxy（[`galaxy.ansible.com/intro`](https://galaxy.ansible.com/intro)）的共享容器构建，以便快速设计您的容器映像。请记住，开源就是与社区分享。

### 自动化考虑

第一步是安装它，由于 Ansible 文档与众不同，我无需重新发明轮子。安装选项和详细信息可以在以下位置找到：[`docs.ansible.com/ansible-container/installation.html`](http://docs.ansible.com/ansible-container/installation.html)。在您运行它之后，我建议的下一步是查看此处的入门指南：[`docs.ansible.com/ansible-container/getting_started.html`](http://docs.ansible.com/ansible-container/getting_started.html)。

现在，我们将逐步介绍我创建的一个示例 Ansible Container 项目以供开始使用。对我来说，这是学习新技术的最佳方式。花些时间，动手尝试一下，然后变得更有见识。

#### 步骤 1

使用 Ansible Container 项目开始就像创建一个新目录一样简单。创建新目录后，您需要进入该目录并执行 Ansible Container 初始化命令。这些命令的工作示例如下：

```
**$ mkdir elk-containers**
**$ cd elk-containers**
**$ ansible-container init**

```

命令的输出将类似于这样：

![步骤 1](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_07_001.jpg)

在所示的示例中，我们的项目将被命名为`elk-containers`，并将在同名的目录中初始化。现在您已经初始化了您的项目，您会发现 Ansible Container 文件被创建在一个名为`ansible`的目录中。您的项目的目录结构将如下所示：

```
ansible/ 
  container.yml 
  main.yml 
  meta.yml 
  requirements.txt 
  requirements.yml 
  ansible.cfg 

```

在这里创建的文件是提供一个起点的骨架文件。如果您检查两个最重要的文件`container.yml`和`main.yml`，它们将看起来像这样：

**container.yml**

```
version: "1" 
services: 
 # Add your containers here, specifying the base image you want to build from 
 # For example: 
 # 
 # web: 
 #    image: ubuntu:trusty 
   #  ports: 
   #     - "80:80" 
   #  command: ['/usr/bin/dumb-init', '/usr/sbin/apache2ctl', '-D', 'FOREGROUND'] 
 #    dev_overrides: 
 #   environment: 
 #    - "DEBUG=1" 
 # 
registries: {} 
 # Add optional registries used for deployment. For example: 
 # google: 
 #  url: https://gcr.io 
 #  namespace: my-cool-project-xxxxxx  

```

**main.yml**

```
# This should be your Ansible playbooks to provision your containers. 
# An inventory will be automatically created using the names of the services 
# from your container.yml file. 
# Add any roles or other modules you'll need to this directory too. 
# For many examples of roles, check out Ansible Galaxy: https://galaxy.ansible.com/ 
# 
--- 
- hosts: all 
 gather_facts: false 

```

#### 步骤 2

现在，我们可以手动配置我们的容器和/或利用 Ansible Galaxy 上托管的许多预打包的 Ansible Container 配置。在这里的示例中，我们将从 Ansible Galaxy 拉取并使用三种不同的配置。我们的示例项目将部署三个容器，这些容器将共同运行 ELK 堆栈（Elasticsearch，Logstash 和 Kibana）。

### 注意

在执行以下命令之前，请确保您已安装了 Ansible Container 和所有先决软件。有关详细信息，请参阅 Ansible Container 安装说明：[`docs.ansible.com/ansible-container/installation.html`](https://docs.ansible.com/ansible-container/installation.html)。

处理此的命令在此处提到；确保在执行时您在项目目录的`root`目录中：

```
**$ cd elk-containers**
**$ ansible-container install chouseknecht.kibana-container**
**$ ansible-container install chouseknecht.elasticsearch-container**
**$ ansible-container install chouseknecht.logstash-container**

```

命令的输出将类似于这样：

![步骤 2](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_07_002.jpg)

下载基础镜像后，Ansible Container 将其加载到一个虚拟容器中，其中包含所有可能的镜像依赖项，以准备构建它。

![步骤 2](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_07_003.jpg)

#### 步骤 3

接下来，我们将回顾之前的`ansible-container`安装命令对我们的项目做了什么。如果我们现在查看我们的`container.yml`和`main.yml`文件，我们会注意到部署 ELK 堆栈到容器所需的所有自动化代码都在那里。让我们看看这些文件的变化：

**container.yml**

```
version: '1' 
services: 
 kibana: 
    image: centos:7 
    ports: 
    - 5601:5601 
    user: kibana 
    links: 
    - elasticsearch 
    working_dir: /opt/kibana/bin 
    command: [./kibana] 
 elasticsearch: 
    image: centos:7 
    ports: 
    - 9200:9200 
    expose: 
    - 9300 
    restart: always 
    user: elasticsearch 
    working_dir: /usr/share/elasticsearch/bin 
    command: [./elasticsearch] 
 logstash: 
 image: centos:7 
    ports: 
    - 5044:5044 
    links: 
    - elasticsearch 
    restart: always 
    working_dir: /opt/logstash/bin 
    command: [./logstash, agent, -f, /etc/logstash/conf.d] 
    environment: 
    - JAVACMD=/usr/bin/java 

 # volumes: 
   # - your_configuration_volume:/etc/logstash/conf.d 
 # Add your containers here, specifying the base image you want to build from 
 # For example: 
 # 
 # web: 
 #    image: ubuntu:trusty 
 #    ports: 
 #       - "80:80" 
   #  command: ['/usr/bin/dumb-init', '/usr/sbin/apache2ctl', '-D', 'FOREGROUND'] 
 #    dev_overrides: 
   #     environment: 
   #        - "DEBUG=1" 
 # 
registries: {} 
 # Add optional registries used for deployment. For example: 
   # google: 
 #      url: https://gcr.io 
   #    namespace: my-cool-project-xxxxxx 

```

**main.yml**

```
- hosts: all 
 gather_facts: false 
- hosts: kibana 
 roles: 
 - role: chouseknecht.kibana-container 
    kibana_host: 0.0.0.0 
    kibana_port: 5601 
    kibana_elasticsearch_url: http://elasticsearch:9200 
    kibana_index: .kibana 
    kibana_log_dest: stdout 
    kibana_logging_silent: false 
    kibana_logging_quiet: false 
    kibana_logging_verbose: true 
- hosts: elasticsearch 
 roles: 
 - role: chouseknecht.elasticsearch-container 
    elasticsearch_network_host: 0.0.0.0 
    elasticsearch_http_port: 9200 
    elasticsearch_script_inline: true 
    elasticsearch_script_indexed: true 
    elasticsearch_data: /usr/share/elasticsearch/data 
    elasticsearch_logs: /usr/share/elasticsearch/logs 
    elasticsearch_config: /usr/share/elasticsearch/config 
    java_home: '' 
- hosts: logstash 
 roles: 
 - role: chouseknecht.logstash-container 
    logstash_elasticsearch_hosts: 
    - http://elasticsearch:9200 

    logstash_listen_port_beats: 5044 

    logstash_local_syslog_path: /var/log/syslog 
    logstash_monitor_local_syslog: true 

    logstash_ssl_dir: /etc/pki/logstash 
  logstash_ssl_certificate_file: '' 
  logstash_ssl_key_file: '' 

  logstash_enabled_on_boot: yes 

  logstash_install_plugins: 
  - logstash-input-beats 

```

现在我们需要检查的另一个文件是`requirements.yml`文件。由于我们使用预打包的配置，这些配置的链接将被添加到此文件中：

**requirements.yml**

```
- src: chouseknecht.kibana-container 
- src: chouseknecht.elasticsearch-container 
- src: geerlingguy.java 
- src: chouseknecht.logstash-container 

```

在这一点上，如果您需要调整变量、特定应用程序更改或添加额外的编排步骤，您可以选择对文件进行更改。最好的是，您也可以选择不进行任何更改。您可以构建和运行这个容器项目就像它是的那样。

#### 步骤 4

在我们的最后一步中，我们将采用我们设计的内容，执行 Ansible Container 构建过程，并最终在本地部署这些容器。同样，对于我们的示例，我们不需要对容器设计文件进行任何更改。

构建过程非常强大，因为所有容器依赖关系和编排将被实现以创建容器映像。当您希望部署容器时，将使用这些映像。以下是用于构建我们的容器的命令：

```
**$ ansible-container build**

```

命令的输出片段将类似于这样：

![步骤 4](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/B06086_07_04_resized-769x1024.jpg)

最后，我们准备测试我们全新的容器。正如容器化世界所说，“只需发布它！”。使用 Ansible Container 在本地部署容器映像以测试它们是另一个非常合理的功能。您将使用`ansible-container run`命令将容器部署到您本地配置的 Docker Engine 安装中：

```
**$ ansible-container run -d**

```

运行后，命令的输出将类似于这样，我们可以通过执行`docker ps`命令来确认我们的容器部署：

![步骤 4](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_07_005.jpg)

正如你所看到的，我们在本地运行了三个容器，做得很好。我们成功了！我们的第一个容器已经设计、配置、构建和部署（在不到一个小时的时间内）。在我们继续之前，我们应该暂停或移除我们的容器。请使用以下命令来停止或移除您的容器：

```
**$ docker stop <container ID>**
**$ docker rm <container ID>**

```

## 在 OpenStack 上部署 Kubernetes

在撰写本文时，Kubernetes 已成为容器编排的市场选择，成为顶级 GitHub 项目之一，并成为管理容器的领先企业选择。Kubernetes 的一些高级功能包括能够执行滚动升级、零停机部署、管理大规模复杂工作负载以及开箱即用的高可用/容错。如果您希望在生产环境中管理容器集群，您绝对应该尝试一下 Kubernetes。

在这种情况下，经常出现的问题是，为什么我要在 OpenStack 等平台上运行 Kubernetes？许多人经常忘记 OpenStack 是一个虚拟化管理器，而不是虚拟化本身。OpenStack 使操作员能够管理许多不同类型的虚拟化管理器，容器编排软件只是另一种虚拟化管理器。在 OpenStack 中，您可以选择几种方式来管理和部署 Kubernetes 集群。可以通过 Magnum 来完成，这是 OpenStack 中的容器管理项目。另一种方法是使用 Heat 模板来将 Kubernetes 集群作为堆栈进行管理。最后，您可以使用一个名为 kargo 的 GitHub 项目，它允许您在许多不同的系统和云平台上使用 Ansible 部署 Kubernetes。

对于我们的示例，我们将涵盖最后一个选项，并使用 kargo 在我们的 OpenStack 云上部署 Kubernetes。尝试通过创建我们自己的 Ansible playbooks/roles 来部署 Kubernetes 似乎不是一个很好的时间利用。kargo 项目可以在以下网址找到：[`github.com/kubernetes-incubator/kargo`](https://github.com/kubernetes-incubator/kargo)。存储库中有说明，将指导您如何设置以运行设置 playbook。

### 注意

请记住，kargo 是一个开源项目，就像其他开源项目一样，它可能会发生变化。变化可能包括重新组织存储库布局、更改部署说明甚至废弃。在撰写本文时，该项目仍在运行。

OpenStack 特定的说明可以在这里找到：[`github.com/kubernetes-incubator/kargo/blob/master/docs/openstack.md`](https://github.com/kubernetes-incubator/kargo/blob/master/docs/openstack.md)。要开始，您需要将 kargo 存储库克隆到 OpenStack 云上的 Utility 容器中：

```
**$ git clone https://github.com/kubernetes-incubator/kargo.git**
**$ cd kargo**

```

### 自动化考虑

在大多数情况下，安装将顺利进行。我确实不得不调整两个小细节，以确保 playbooks 成功完成。第一个调整是在我的 OpenRC 文件中。正如您在说明中所注意到的，第二步是在运行设置 playbook 之前源化您的 OpenRC 文件。我的文件缺少 playbook 检查的两个参数；它是`OS_TENANT_ID`和`OS_REGION_NAME`参数。我的 OpenRC 文件的工作示例如下：

```
# Ansible managed: /etc/ansible/roles/openstack_openrc/templates/openrc.j2 
export LC_ALL=C 

# COMMON CINDER ENVS 
export CINDER_ENDPOINT_TYPE=publicURL 

# COMMON NOVA ENVS 
export NOVA_ENDPOINT_TYPE=publicURL 

# COMMON OPENSTACK ENVS 
export OS_ENDPOINT_TYPE=publicURL 
export OS_USERNAME=admin 
export OS_PASSWORD=passwd 
export OS_PROJECT_NAME=admin 
export OS_TENANT_NAME=admin 
**export OS_TENANT_ID=bcf04d870b4c469cb1728e71ef9a6422** 
export OS_AUTH_URL=https://192.168.0.249:5000/v3 
export OS_NO_CACHE=1 
export OS_USER_DOMAIN_NAME=Default 
export OS_PROJECT_DOMAIN_NAME=Default 
export OS_INTERFACE=publicURL 
**export OS_REGION_NAME=RegionOne** 

# For openstackclient 
export OS_IDENTITY_API_VERSION=3 
export OS_AUTH_VERSION=3 

```

我不得不做的另一个调整是调整如何拉取特定的 Kubernetes 依赖软件容器。容器存储库标签已更改，而 kargo 项目尚未更新。在项目中对`roles/download/defaults/main.yml`文件执行更新。原始文件的片段如下：

```
... 
exechealthz_version: 1.1 
exechealthz_image_repo: "gcr.io/google_containers/exechealthz-amd64" 
exechealthz_image_tag: "{{ exechealthz_version }}" 
hyperkube_image_repo: "quay.io/coreos/hyperkube" 
**hyperkube_image_tag: "{{ kube_version }}_coreos.0"**

```

需要更改的文件如下所示：

```
... 
exechealthz_version: 1.1 
exechealthz_image_repo: "gcr.io/google_containers/exechealthz-amd64" 
exechealthz_image_tag: "{{ exechealthz_version }}" 
hyperkube_image_repo: "quay.io/coreos/hyperkube" 
**hyperkube_image_tag: "v{{ kube_version }}_coreos.0"**

```

有了这两个更改，您所需要做的就是启动实例，作为 Kubernetes 主节点、etcd 和节点。实例可以是您希望的任何基于 Linux 的操作系统。您布置 Kubernetes 集群的方式取决于环境类型和最终用例。稳定的 Kubernetes 集群的参考架构是将两个实例作为主节点，三个实例作为 etcd，并利用 Ironic 来部署至少三个裸金属服务器作为节点。当然，出于测试目的，您可以将整个集群部署为 OpenStack 云上的实例。

下一步是配置您的清单文件，以包括您启动的实例，以充当您的 Kubernetes 集群。我的清单文件名为`os-inventory`。清单文件的工作示例如下：

```
[kube-master] 
kubes-1 
kubes-2 
[etcd] 
kubes-3 
kubes-4 

[kube-node] 
kubes-5 
kubes-6 
kubes-7 

[k8s-cluster:children] 
kube-node 
kube-master 
etcd 

```

信不信由你，您现在已经准备好运行设置 playbook 来部署您的 Kubernetes 集群了。要这样做的命令如下，请确保您在 kargo 存储库的`root`目录中：

```
**$ ansible-playbook -i inventory/os-inventory -b cluster.yml**

```

安装将运行一段时间，但最终您将拥有一个可用的 Kubernetes 集群进行实验。现在我们将转向另一种容器编排技术，并尝试如何使用 Ansible 来管理容器，同时利用 OpenStack。

## 使用 Ansible 管理 CoreOS 和 Docker

CoreOS 似乎是另一个很好的选择，可以在 OpenStack 上运行，因为它是：

> *一种专为集群部署设计的轻量级 Linux 操作系统，为您最关键的应用程序提供自动化、安全性和可伸缩性                                                                          –  ([`coreos.com/why/#cluster`](https://coreos.com/why/#cluster))*

CoreOS 的重点是提供一个默认情况下具有集群意识的操作系统，使其非常适合容器技术等平台。Docker 也是一个明显的选择，用于实验容器，因为它是使容器再次流行的原因。此外，Docker 有各种各样的镜像可以随时拉取和部署。在我们的示例中，我们将审查一个非常简单的 playbook，它将在 CoreOS 上的容器中部署 ELK 堆栈。

### 自动化考虑

这个过程的第一步是启动至少三个具有至少 2GB 内存和稳定 CoreOS 镜像的 flavor 的实例。由于我喜欢使用 Heat 来做这样的事情，我使用了一个 Heat 模板来启动我的实例。我创建的模板可以在这里找到：[`github.com/wbentley15/openstack-heat-templates/tree/master/coreos`](https://github.com/wbentley15/openstack-heat-templates/tree/master/coreos)。然后使用 Heat 部署堆栈的命令如下：

```
**$ heat stack-create coreos --template-file=heat-coreos-prod.yaml -- 
  parameters="key-name=my-key;user-data=cloud-config-prod.yaml;
  network=24b9b982-b847-4d0e-9088-61acbf92a37f"**

```

![自动化考虑](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_07_006.jpg)

### 编写 playbooks 和角色

一旦您的 CoreOS 堆栈在线，您可以执行我们将要创建的 playbook。在本例中，所有任务将在名为`base.yml`的 playbook 中，该文件位于`playbook`目录的`root`目录中。该文件的初始内容将如下所示：

```
--- 
# This playbook deploys the ELK stack on CoreOS 

- name: Bootstrap CoreOS 
 hosts: coreos 
 gather_facts: False 
 roles: 
 - defunctzombie.coreos-bootstrap 

```

playbook 中的第一个任务对于运行诸如 Ansible 之类的软件包对目标 CoreOS 实例至关重要。由于 CoreOS 是一个最小的操作系统，它没有安装任何版本的 Python。我们知道，运行 Ansible 对主机的一个主要先决条件是安装 Python。为了规避这个限制，我们将使用一个名为`defunctzombie.coreos-bootstrap`的角色，在我们的 CoreOS 实例上安装`pypy`。我们将在稍后学习如何告诉 Ansible 在这些节点上找到我们的 Python 解释器。

您可以通过执行以下命令从 Galaxy 上拉取此角色：

```
**$ ansible-galaxy install defunctzombie.coreos-bootstrap**

```

接下来的两个任务将在 CoreOS 实例上设置环境，以便将 Docker 镜像作为容器运行。请注意，我们将固定`docker-py`和`docker-compose`软件包的版本；这是由于`docker_image`和`docker_container`模块的已知错误。一旦错误得到解决，这种依赖关系可以被移除，或者随着时间的推移，这些版本可能需要进行调整：

```
- name: Deploy ELK Stack 
 hosts: coreos 
 remote_user: core 
 become: false 
 tasks: 
    - name: Start etcd 
       service: name=etcd.service state=started 
       become: true 

    - name: Install docker-py 
       shell: /home/core/bin/pip install docker-py==1.9.0 docker-compose==1.8.0 

```

最后剩下的任务将处理拉取 ELK 堆栈的 Docker 镜像，然后在您的 CoreOS 集群上启动这些容器：

```
 - name: Pull Elasticsearch container 
       docker_image: name=elasticsearch 

    - name: Pull Kibana container 
       docker_image: name=kibana 

    - name: Pull Logstash container 
     docker_image: name=logstash 

  - name: Launch Elasticsearch container 
   docker_container: 
    name: elasticsearch-cont 
          image: elasticsearch 
          state: started 

    - name: Launch Kibana container 
       docker_container: 
          name: kibana-cont 
          image: kibana 
          state: started 

    - name: Launch Logstash container 
     docker_container: 
    name: logstash-cont 
    image: logstash 
    state: started 

```

Docker 镜像是从[`hub.docker.com`](https://hub.docker.com)上的存储库中拉取下来，然后部署在托管 Docker 的 CoreOS 实例上。

我们这个例子的`hosts`文件又有点独特，因为我们不得不为 CoreOS 安装自定义的 Python 解释器。我们需要配置 Ansible 来使用这个替代的 Python 解释器。在下面的工作示例中，您会发现我们配置了 Ansible 来使用位于`/home/core/bin/python`的 Python 解释器和位于`/home/core/bin/pip`的 pip 软件包：

```
[coreos] 
162.209.96.54 

[coreos:vars] 
ansible_ssh_user=core 
ansible_python_interpreter=/home/core/bin/python 
ansible_pip_interpreter=/home/core/bin/pip 

```

在本章的后面，我们将通过再次审查这些 playbooks 和角色来结束，然后进行测试，以查看最终的结果。

## 部署 Nova LXD 在 OpenStack

最后，但肯定不是最不重要的，我们将以真正开始一切的容器选项 LXC 或者它的新的大哥 LXD 来结束本章。LXD 被描述为：

> *LXC 的容器“hypervisor”和一个新的用户体验*                                                                      –   ([`www.ubuntu.com/cloud/lxd`](https://www.ubuntu.com/cloud/lxd))

LXD 的三个主要组件是其系统范围的守护程序（**lxd**）、命令行客户端（**lxc**）和 OpenStack Nova 插件。正是这个插件使我们能够在 OpenStack 控制下将 LXD 作为 hypervisor 运行，并使用传统的 OpenStack 命令来启动容器。有了这样的东西，您可以在相同的控制平面下在单独的计算节点上运行实例和容器。LXD 进一步被描述为安全设计、可扩展、直观、基于镜像和具有执行实时迁移的能力。

幸运的是，Ansible 之神已经听到并回答了我们的祈祷。在**openstack-ansible 项目**（**OSA**）的 Newton 版本（以及以后），您现在可以将 LXD 作为 KVM 的替代 hypervisor 部署。现在只需在部署 OSA 云之前编辑两个配置文件即可。我们将概述这些更改，并演示如何使用 OpenStack 启动您的第一个 LXD 容器。

在开始之前，您应该知道在 OSA 上启用 LXD 的详细说明可以在这里找到：[`docs.openstack.org/developer/openstack-ansible-os_nova/`](http://docs.openstack.org/developer/openstack-ansible-os_nova/)。

### 自动化考虑

OSA 部署围绕部署节点上`/etc/openstack_deploy`目录中的三个主要配置文件展开。您需要编辑`user_variables.yml`和`user_secrets.yml`文件。从`user_variables.yml`文件开始，您需要将`nova_virt_type`变量设置为使用 LXD。一个工作示例如下：

```
# This defaults to KVM, if you are deploying on a host that is not KVM capable 
# change this to your hypervisor type: IE "qemu", "lxc". 
**nova_virt_type: lxd**

```

需要编辑的第二个文件是`user_secrets.yml`文件。您只需要为 LXD 信任提供密码。需要编辑的行的示例如下：

```
# LXD Options for nova compute 
lxd_trust_password: 

```

### 提示

如果您计划设置混合计算节点农场并希望拥有 KVM 和 LXD 主机。您需要编辑`openstack_user_config.yml`文件，并为每个主机设置`nova_virt_type`。如何配置的工作示例可以在前面的文档链接中找到。

现在您可以开始安装 OSA，知道您将能够启动 LXD 容器以及在 KVM 上运行的实例。安装完成后，您还需要完成最后一步。我们现在必须创建一个 LXD 兼容的镜像，该镜像将在您启动容器时使用。LXD 需要使用原始镜像，因此我们将下载符合这些要求的镜像。在 OSA 云的实用程序容器中，执行以下命令：

```
**$ wget http://cloud-images.ubuntu.com/trusty/current/
  trusty-server-cloudimg-amd64-root.tar.gz**
**$ glance image-create --name=trusty-LXD --visibility=public --container-
  format=bare --disk-format=raw 
  --file=trusty-server-cloudimg-amd64-root.tar.gz**

```

![自动化考虑](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_07_007.jpg)

有了您的新镜像，现在您已经准备好启动您的第一个 LXD 容器了。LXD 容器的管理方式与在 KVM 上运行的实例类似。您可以通过 Horizon 仪表板或通过 OpenStack Client CLI 创建容器。在本例中，我们将使用 OpenStack Client 来创建容器。以下命令将创建您的容器：

```
**$ nova boot --image=<image name> --flavor=<flavor> --nic net-id=<network ID> --security-group=<security group> --min-count <number of containers> <container name>**
**$ nova boot --image=trusty-LXD --flavor=m1.small --nic net-id=eb283939-2c65-4ecb-9d9f-cbbea9bf252c --security-group default --min-count 3 first-lxd-container**

```

如果您的输出看起来与此类似，您可以将其视为成功：

![自动化考虑](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_07_008.jpg)

然后，您可以执行`openstack server list`命令来验证您的新容器是否正在运行。

![自动化考虑](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_07_009.jpg)

非常棒，我的朋友，你又做得很好！我知道我们涵盖了很多内容，但是你现在已经是一个老手了，所以不用担心。保持我们的传统，我们将以快速回顾我们所涵盖的内容以及下一章的预期结束本章。

# 审查 playbooks 和 roles

让我们直接开始检查我们之前创建的主 playbook，以部署名为**ansible-coreos**的 CoreOS 上的 Docker 容器。位于`ansible-coreos`目录的根目录中的已完成的 playbook 和文件名为`base.yml`，看起来是这样的：

```
--- 
# This playbook deploys the ELK stack on CoreOS 

- name: Bootstrap CoreOS 
 hosts: coreos 
 gather_facts: False 
 roles: 
    - defunctzombie.coreos-bootstrap 

- name: Deploy ELK Stack 
 hosts: coreos 
 remote_user: core 
 become: false 
 tasks: 
    - name: Start etcd 
       service: name=etcd.service state=started 
       become: true 

    - name: Install docker-py 
       shell: /home/core/bin/pip install docker-py==1.9.0 docker-compose==1.8.0 

    - name: Pull Elasticsearch container 
       docker_image: name=elasticsearch 

    - name: Pull Kibana container 
       docker_image: name=kibana 

    - name: Pull Logstash container 
       docker_image: name=logstash 

    - name: Launch Elasticsearch container 
       docker_container: 
          name: elasticsearch-cont 
          image: elasticsearch 
          state: started 

  - name: Launch Kibana container 
   docker_container: 
          name: kibana-cont 
          image: kibana 
          state: started 

    - name: Launch Logstash container 
       docker_container: 
          name: logstash-cont 
        image: logstash 
    state: started 

```

我们从 Galaxy 中拉下来的相应角色位于`ansible-coreos/roles/defunctzombie.coreos-bootstrap/tasks`目录中，看起来是这样的：

```
- name: Check if bootstrap is needed 
 raw: stat $HOME/.bootstrapped 
 register: need_bootstrap 
 ignore_errors: True 

- name: Run bootstrap.sh 
 script: bootstrap.sh 
 when: need_bootstrap | failed 

- name: Check if we need to install pip 
 shell: "{{ansible_python_interpreter}} -m pip --version" 
 register: need_pip 
 ignore_errors: True 
 changed_when: false 
 when: need_bootstrap | failed 

- name: Copy get-pip.py 
 copy: src=get-pip.py dest=~/get-pip.py 
 when: need_pip | failed 

- name: Install pip 
 shell: "{{ansible_python_interpreter}} ~/get-pip.py" 
 when: need_pip | failed 

- name: Remove get-pip.py 
 file: path=~/get-pip.py state=absent 
 when: need_pip | failed 

- name: Install pip launcher 
 copy: src=runner dest=~/bin/pip mode=0755 
 when: need_pip | failed 

```

最后，我们创建了`hosts`文件，也位于`playbook`目录的`root`目录中：

```
[coreos] 
162.209.96.54 

[coreos:vars] 
ansible_ssh_user=core 
ansible_python_interpreter=/home/core/bin/python 
ansible_pip_interpreter=/home/core/bin/pip 

```

### 注意

完整的代码集可以再次在以下 GitHub 存储库中找到：[`github.com/os-admin-with-ansible/os-admin-with-ansible-v2`](https://github.com/os-admin-with-ansible/os-admin-with-ansible-v2)。

我们终于准备好尝试这个 playbook 了。假设您已经克隆了之前的 GitHub 存储库，则从部署节点测试 playbook 的命令如下：

```
**$ cd os-admin-with-ansible-v2**
**$ cd ansible-coreos**
**$ ansible-playbook -i hosts base.yml**

```

假设一切顺利，输出应该类似于以下截图中的片段：![审查 playbooks 和角色](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_07_010.jpg)

通常，我还喜欢采取额外的步骤，通过在 CoreOS 实例上执行`docker ps`命令来验证容器是否正在运行。

![审查 playbooks 和角色](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_07_011.jpg)

# 摘要

穿过终点线确实感觉不错。我希望容器的原始力量能激励您开始在 OpenStack 云上部署它们。在传统虚拟机和实例之外拥有选择总是让人感觉良好。

在结束本章之前，让我们花一点时间回顾本章。我们从探索容器化的概念以及为什么它变得如此流行开始本章。您学会了如何使用 Ansible Container 来创建我们的第一个容器镜像和构建。我们审查了 kargo 项目，该项目使您能够使用 Ansible 在多个云平台上部署 Kubernetes，包括 OpenStack。接下来，我们演示了如何使用 Ansible 来管理在 OpenStack 上运行 Docker 集群的 CoreOS。最后，我们审查了部署 LXD 所需的配置更改与**openstack-ansible**项目。

下一章也将是非常有趣的一章，因为作为云运营商，您最终将不得不考虑扩展/缩小您的云足迹。OpenStack 具有有用的内置功能，使得扩展的过程相当容易和简单。在下一章中，我们将介绍设置活跃-活跃云区域的概念，然后通过自动化这项任务来减轻在需要时进行扩展的压力。如果您准备好迎接一些未知的领域，请前往第八章*设置活跃-活跃区域*！


# 第八章：设置 Active-Active 区域

在本章中，我们将重点介绍 OpenStack 的一个非常有用的内置功能。这将是能够集中管理多个可能在不同地理位置运行的 OpenStack 区域的能力。OpenStack 中的区域概念并不新鲜，但请问你是否曾经真正见过它的实现。在许多场合，我发现自己对完成这些步骤感到不清楚。今天是你将对这个问题有一个积极回答的日子。

稳定性和可用性目前是 OpenStack 社区中热门话题，我认为分享一个可行的用例来实现云高可用性是很好的。这将是云操作员可以设置的许多方式之一。正如我们可能已经知道的，OpenStack 可以满足许多高可用性要求。我们将简要回顾这些场景，然后转向为什么要使用这个功能。与之前的所有章节一样，我们将通过演示如何使用 Ansible 自动设置 Active-Active 云区域来完成本章。本章将涵盖以下主题：

+   回顾 OpenStack 高可用性场景

+   为什么要使用 Active-Active 云区域？

+   设置 Active-Active 云区域

+   创建和设置管理员区域

+   配置活动区域的身份验证

+   编写 playbooks 和 roles

+   回顾 playbook 和 roles

# 回顾 OpenStack 高可用性场景

这个话题恰好是我总是喜欢讨论的话题之一。**高可用性**（**HA**）和灾难恢复总是因为明显的原因在 IT 人员中引起非常情绪化的对话。可以说，你的命运掌握在手中，确保你的组织系统在灾难/故障发生时保持在线。在过去，本地系统、HA 和冷（未使用）灾难恢复站点已经足够了。云的当前灵活性现在为系统稳定性提供了新的更好的选择。不要满足于旧的解决方案。你有选择！

如前所述，有多种方法可以实现 OpenStack 的 HA。我们将概述三种可能成功的场景，并满足大多数组织的 HA 要求。以下是三种可能的场景，附加了图表以提供更多上下文：

+   **多个数据中心**：多个 OpenStack 区域跨越多个地理位置的数据中心

+   **单数据中心**：一个数据中心内有多个 OpenStack 区域

+   **可用区**：在一个数据中心内的单个 OpenStack 区域中使用成对的可用区

![回顾 OpenStack 高可用性场景](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_08_001.jpg)

## 多个数据中心

我们将从三种情景中最复杂的情景开始。这种情景包括在多个数据中心部署多组 OpenStack 区域，并使它们作为一个云系统运行的概念。虽然这听起来复杂，但实际上并不像听起来那么困难。当将它们全部绑定在一起时，以及当您去支持/管理它们时，复杂性就会出现。这种模式不仅为您提供了跨数据中心的 HA（多个 Active-Active 区域），而且还在每个数据中心内提供了 HA（独立的 Active-Active 区域）。您必须经历多层故障才能使您的云下线。

![多个数据中心](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_08_002.jpg)

## 单数据中心

与前面的情景类似，主要区别在于，它只限于单个数据中心。在这种情况下，您可以部署一组仅限于一个数据中心的 OpenStack Active-Active 区域。这种模型只会在运行区域的数据中心内提供高可用性。如果该数据中心发生火灾，您的云将**彻底倒霉**（**SOL**）。

如果没有其他选择，这种模型仍然可以避免完全的云故障。

![单个数据中心](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_08_003.jpg)

## 可用区域

这种情景可能是最简单的选择，但肯定可以在提供客户级别的高可用性方面发挥作用。是的，如果您希望获得真正的灾难恢复设计，这种模型就不够了。通过利用多个 AZ，您可以使用反亲和性过滤器将实例分布在不同的计算节点上，从而提供客户级别的高可用性。

现在，让我们专注于我们之前描述的多数据中心模型的简化版本。我们将回顾为什么您可能有兴趣使用 Active-Active 区域方法。

![可用区域](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/B06086_08_10.jpg)

# 为什么要使用 Active-Active 云区域？

除了能够积极使用多个 OpenStack 区域的纯粹令人敬畏之外，Active-Active 云区域方法还能最大限度地利用您的整体云投资。不再需要因为第二个站点不经常使用而进行灾难恢复测试。此外，您还获得了集中管理区域的额外好处。处处都是*双赢*的局面。

因此，让我们深入了解架构，以提供一个 OpenStack Active-Active 区域。以下图表以最简单的形式解释了架构：

![为什么要使用 Active-Active 云区域？](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_08_004.jpg)

上述架构的组件是：

+   两个独立的 OpenStack 云部署，也就是两个区域。在这个例子中，我们有**A 区**和**B 区**。这些区域运行核心 OpenStack 服务，除了 Keystone 和 Horizon。每个区域可以有任意数量的互补 AZ。

+   创建另一个专门用于托管 Keystone 和 Horizon 服务的 OpenStack 区域。这个区域可以被归类为 Admin 区域。

+   然后，A 区和 B 区将利用 Admin 区域来处理身份验证和 GUI Web 界面，通过集中用户、租户和项目管理/创建，并提供一个单一的 Web 仪表板来管理所有活动区域。

# 设置 Active-Active 云区域

实施这一过程相对简单，但确实需要特别注意细节。提前概述步骤非常有用，可以避免遗漏步骤。我还了解到，手动执行更改通常也不会有好结果。编辑服务配置文件的过程会导致错误修改，导致服务无法启动。不好！！！更不用说这会使实施过程时间变长三倍。首先，我们将手动回顾步骤，然后在接下来的部分，我们将学习如何尽可能自动化设置过程。我只能说感谢 Ansible！

在这一部分，我们将回顾设置 Active-Active OpenStack 云区域的手动步骤。以下是步骤的简要概述：

1.  记录每个区域的端点并注意 URL。

1.  在 Admin 区域创建服务用户帐户。

1.  在 Admin 区域创建服务。

1.  将每个区域的端点注册到 Admin 区域。

1.  调整 Admin 区域的身份端点。

1.  配置每个区域的服务，以便对 Admin 区域的身份验证服务进行身份验证，而不是本地区域的身份验证服务。

现在，让我们逐步通过这里显示的每个配置步骤，演示工作配置示例。

## 区域端点清单

这一步将是简单地查询您想要包括在主-主设置中的每个区域的端点。由于我们使用**openstack-ansible**（**OSA**）来部署我们的 OpenStack 云，您需要连接到每个区域的实用程序容器，以便使用 OpenStack CLI。一旦连接并源化 OpenRC 文件，命令将是：

```
**$ openstack endpoint list**

```

这个命令的输出应该类似于这样：

![区域端点清单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_08_005.jpg)

请记住，我们这里的重点是要注意可用的公共端点。

由于 openstack-ansible 将 OpenStack 服务安装到 LXC 容器中，您需要知道如何连接到每个容器以使用 CLI 并配置/维护服务。列出在控制平面服务器上运行的所有容器的 LXC 命令是`lxc-ls -fancy`，输出将类似于以下内容：

![区域端点清单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_08_006.jpg)

## 管理区域配置

接下来的步骤将涉及定制管理区域的安装和配置。这将是您的集中管理区域，只为身份验证请求提供服务。管理区域可以存在于与其他区域相同的数据中心，也可以存在于与其他区域完全不同的区域。显然，数据中心之间需要网络连接。请按照稍后给出的说明进行操作。

### 在管理区域创建服务用户帐户

在这一点上，您应该有一个仅运行身份服务（Keystone）和 Web 仪表板（Horizon）的运行中的管理区域。只有这两个服务应该存在并处于活动状态。由于我们希望使用管理区域来管理其他区域，您必须让它了解其他区域的服务和端点。这个过程从在管理区域上创建服务用户帐户开始：

1.  对于这一步，我们将使用以下命令使用 CLI 创建服务用户帐户：

```
 **$ openstack user create 
        --project <project reserved for services> 
        --password <user password> <user name>**

```

这个命令的一个工作示例看起来像这样：

```
**$ openstack user create --project service 
         --password passwd glance**

```

1.  现在我们必须为刚刚创建的新用户分配一个具有适当权限的角色。完成此操作的 CLI 命令在这里：

```
**$ openstack role add --user <user name> 
         --project <project reserved for services> <role>**

```

这个命令的一个工作示例看起来像这样：

```
**openstack role add --user glance 
       --project service admin**

```

现在我们已经创建了服务用户帐户，我们可以过渡到在管理区域上注册新服务的下一步。

### 在管理区域创建服务

在这一步中，我们只是在管理区域为活动区域上运行的服务创建占位符。请记住，活动区域上运行其他核心服务，管理区域将为它们处理身份验证。然后管理区域必须知道这些服务。

使用以下命令在管理区域上注册服务：

```
**$ openstack service create --name <service name> 
  --description "<service description>" <service type>**

```

这个命令的一个工作示例看起来像这样：

```
**openstack service create --name glance 
--description "Glance Image Service" image**

```

下一步将是在管理区域注册活动区域的端点。这一步需要一定的精度，因为端点 URL 是管理区域用来进行功能调用的。如果 URL 不正确或输入错误，服务将被管理区域视为已关闭。

### 将每个区域的端点注册到管理区域

注册活动区域端点的过程涉及使用我们之前开始的端点清单。这里的关键点是，您必须使用每个区域公共端点的 IP 地址。分配给公共端点的 IP 地址需要是公共 IP 地址（可通过互联网访问）或在每个数据中心之间可访问的内部 IP 地址。再次强调，管理区域将使用此 URL 进行服务调用，因此端点必须是可访问的。

您需要注册两种类型的端点：**公共**和**内部**。我在设置过程中发现了这个关键组件。一些 OpenStack 服务仅利用内部端点，而其他服务将使用公共端点。为了避免任何问题，我们将注册两者。从技术上讲，注册两者没有任何风险，这是一个好的做法。

注册服务的命令示例如下：

```
**$ openstack endpoint create --region <region name> 
  <service name> <service type> <endpoint url>**

```

一组命令的工作示例如下：

```
**$ openstack endpoint create --region alpha glance 
  internal 
  http://127.0.0.1:9292**
**$ openstack endpoint create --region alpha glance 
  public 
  http://127.0.0.1:9292**

```

前面的步骤需要为您希望加入 Admin 区域的每个活动区域重复执行。如前面的示例所示，我们将为**Region A**和**Region B**执行此步骤。

### 调整 Admin 区域的身份端点

设置 Admin 区域的最后一步是确保活动区域可以成功连接到那里运行的身份服务。之前分享的关于必须公开服务公共端点的原则在这里同样适用于 Keystone。每个云设置可能略有不同，因此并非所有云都需要此步骤。

为了评估是否需要进行此调整，请执行以下命令，并确定公共和管理员端点是否为 URL 配置了本地 IP 地址：

```
**$ openstack endpoint list --service identity**

```

如果输出看起来类似于这样，您必须在创建新的公共 IP 或数据中心之间可访问的 IP 地址后禁用公共和管理员端点。有关如何处理此问题的更多详细信息将在此处分享：

![调整 Admin 区域的身份端点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_08_007.jpg)

为了创建新的公共和管理员端点，然后禁用当前的端点，您将执行以下命令：

```
**# Add public Keystone endpoint**
**$ openstack endpoint create --region <region name> 
  keystone public <endpoint url>**
**# Add an additional admin Keystone endpoint**
**$ openstack endpoint create --region <region name> 
  keystone admin <endpoint url>**
**# Disable the original public Keystone endpoint 
  with the local IP address 
  configured (URL will have a non-routable address)**
**$ openstack endpoint set --disable <endpoint-id>**
**# Disable the original admin Keystone endpoint with 
  the local IP address configured 
  (URL will have a non-routable address)**
**$ openstack endpoint set --disable <endpoint-id>**

```

完成后，执行`openstack endpoint list --service identity`命令，输出应该类似于这样：

![调整 Admin 区域的身份端点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_08_008.jpg)

## 活动区域配置

本节将包括设置活动区域的步骤，这些区域将成为您的 Active-Active 云设计的一部分。这些区域运行核心 OpenStack 服务。在这一点上，我们已经设置了 Admin 区域，以便与这些活动区域进行通信。现在，我们必须配置核心服务，通过 Admin 区域进行身份验证，而不是使用本地身份服务（Keystone）。

在部署本地身份服务之前，您无法部署 OpenStack 云。身份服务必须是第一个安装的服务，因此将存在于活动区域。要使服务不使用本地身份服务，您必须重新配置每个服务。仅仅禁用本地身份服务是不够的。重新配置每个核心服务的过程包括编辑配置文件。如前所述，编辑服务配置文件会留下错误编辑的可能性，这可能导致该服务无法启动。

这就是您必须更聪明而不是更努力的地方。问问自己：有没有工具可以帮助完成这样的任务？是的，答案再次是 Ansible！Ansible 可以帮助大大减少打字错误，从而进行许多服务配置更改。在第二章中，*介绍 Ansible*，我们简要讨论了 Ansible 的临时命令。临时命令允许直接运行模块命令，而无需将任务包装成 playbook 或 role。

临时命令的基本示例如下：

```
**$ ansible <host> -m <module> -a <module arguments>**

```

在我们的情况下，我们需要连接到运行在控制平面上的特定容器，并更改该服务的配置文件。这需要针对在该活动区域上运行的每个核心服务重复进行。好消息是，我们可以利用 openstack-ansible 部署的动态清单部分来简化整个过程。让我们使用以下示例作为示例，展示如何完成这个过程。

在这个例子中，我们将尝试对 Alpha 区域的镜像服务（Glance）进行所需的更改。所以，我们知道的是：

+   您必须连接到 Glance 容器

+   使用`sed`命令，我们需要利用 shell Ansible 模块

+   我们准备了一个`sed`命令，将更改`glance-api.conf`文件中的`auth_url`值

现在，命令参数的进一步细分将是：

```
host = glance_container  
module = shell  
adhoc command = sed -i 's+^auth_url = <current IP>:35357+auth_url = http://<alpha region IP>:35357+' /etc/glance/glance-api.conf 

```

### 注意

为了利用*openstack-ansible 安装*的动态清单功能，您必须从部署节点（用于部署该区域的节点）执行这些命令。此外，您必须在`/opt/openstack-ansible/playbooks`目录中执行这些命令。

命令的一个工作示例将如下所示：

```
**$ ansible glance_container -m shell -a "sed -i 
's+^auth_url = http://172.30.238.2:35357+auth_url =  
 http://166.78.18.131:35357+' /etc/glance/glance-api.conf"**

```

您可以使用前面的原则对活动区域上的所有服务进行所需的更改。确保记住在更改配置文件后重新启动服务。

```
**$ ansible nova_scheduler_container -m service -a 
   "name=nova-scheduler state=restarted" **

```

# 编写 playbooks 和 roles

在本节中，我们将创建 playbooks 和 roles 来设置管理区域。我们还将概述设置 Active-Active 云所需的 Ansible 临时命令的其他步骤。在为这类事情创建 Ansible 自动化代码时，我通常喜欢创建多个任务，分解成单独的角色。这种格式允许您能够重用与其他 playbooks 创建的角色。最终，我们将得到两个 playbooks 和两个角色，以自动化设置管理区域的步骤。最后，我们将总结使用这些角色的 playbooks。

在本节的另一半中，我们还将概述设置 Active-Active 云所需的 Ansible 临时命令。您可以收集命令以创建 playbooks 和 roles。我觉得这将是几百行不必要的代码，所以我选择了起草命令并使用搜索和替换。

## 设置管理区域

我们将创建的第一个角色将包括配置管理区域所需的任务。文件的名称将是`main.yml`，位于名为`config-admin-region/tasks`的角色目录中。该文件的内容将如下所示：

```
--- 

- name: Create users 
 os_user: 
  cloud: "{{CLOUD_NAME}}" 
  state: present 
  name: "{{ item.0 }}" 
  password: "{{ item.1 }}" 
  default_project: "{{ servicesproject }}" 
  domain: default 
 with_together: 
  - "{{userid}}" 
  - "{{passwdss}}" 

- name: Assign user to specified role in designated environment 
 os_user_role: 
  cloud: "{{CLOUD_NAME}}" 
  user: "{{ item.0 }}" 
  role: "{{ urole }}" 
  project: "{{ servicesproject }}" 
 with_together:  
  - "{{userid}}" 

- name: Register the new services on the Admin region 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}" 
     service create --name "{{ item.0 }}" --description "{{ item.1 }}" "{{ servicetype }}" 
 with_together: 
  - "{{userid}}" 
  - "{{descrip}}" 

```

第一个任务将在管理区域创建服务用户帐户。然后，第二个任务将分配管理员角色给刚刚创建的用户。最后一个任务将在活动区域创建服务的占位符。

接下来要创建的角色将处理在管理区域内注册每个区域端点的任务。与前一个角色一样，文件的名称将是`main.yml`，位于名为`register-endpoints/tasks`的角色目录中。该文件的内容将如下所示：

```
--- 

- name: Register the region service endpoints on the Admin region 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}" 
     service endpoint create --region "{{ item.1 }}" "{{ item.0 }}" "{{ item.2 }}" "{{ item.3 }}" 
 with_together: 
  - "{{endpointname}}" 
  - "{{regionname}}" 
  - "{{endpointtype}}" 
  - "{{endpointurl}}" 

```

该角色只有一个任务，即使用服务端点`create to register`的 CLI 命令来注册端点。在这种情况下，我们使用了`with_together`参数，以便可以循环遍历四个变量定义的参数。这样，您可以只需调整变量值就可以重新运行 playbook。在我们的情况下，我们需要运行这个 playbook 两次，一次用于内部端点，一次用于公共端点。

为了支持这些角色，我们现在需要创建与之配套的变量文件。对于这两个角色，我们将使用角色定义的变量文件来简化一些事情。变量文件将存储在`role`目录中，另一个名为`vars`的目录中。该目录中的文件将命名为`main.yml`。

与名为`config-admin-region`的角色对应的变量文件的内容如下：

```
--- 
userid: [ 'glance', 'nova', 'neutron', 'heat' ] 
passwdss: [ 'passwd', 'passwd', 'passwd', 'passwd' ] 
descrip: [ 'Glance Image Service', 'Nova Compute Service', 'Neutron Network Service', 'Heat Orchestration Service' ] 
servicetype: [ 'image', 'compute', 'network', 'orchestration' ] 

servicesproject: service 
urole: admin 

```

与名为`register-endpoints`的角色对应的第二个变量文件的内容如下：

```
--- 
endpointname: [ 'glance', 'nova', 'neutron', 'heat' ]  
regionname: alpha 
endpointtype: internal 
endpointurl: [ 'http://<alpha region IP>:9292', 'http://<alpha region IP>:8774/v2.1/%\(tenant_id\)s', 'http://<alpha region IP>:9696', 'http://<alpha region IP>:8004/v1/%\(tenant_id\)s' ] 

```

请记住，变量文件中定义的值旨在在每次执行正常日常使用之前更改。

让我们花点时间来分解变量及其预期用途。总结如下：

```
userid          # name of the user to create 

passwdss        # passwords for the users being created 

descript        # description for the service being registered 

servicetype     # type of service being registered 

servicesproject # name of the project where the services user accounts are associated 

urole           # name of the role to associate with the user 

endpointname    # service name of the endpoint being registered 

regionname      # name of the region 

endpointtype    # the type of endpoint being registered 

endpointurl     # the url of the endpoint 

```

变量文件完成后，我们可以继续创建主剧本文件。为了演示，我决定将剧本文件分成两个单独的文件。这完全是我的选择，可以合并成一个文件而不会出现问题。我觉得有两个单独的主剧本会更容易在需要注册多组端点时重新运行。以下是剧本文件的列表：

```
config-admin.yml 
  config-admin-region 

register-endpoints.yml 
  register-endpoints 

```

剧本和角色的名称可以是您选择的任何内容。这里提供了具体的名称，以便您可以轻松跟踪并引用 GitHub 存储库中找到的完成代码。唯一的警告是，无论您决定如何命名角色，在剧本中引用时必须保持统一。

## 设置活动区域

这是我们将使用 Ansible 临时命令完成配置的地方。如前所述，我们将利用 openstack-ansible 部署模型的动态清单功能来实现这一目标。这些命令将重新配置 OpenStack 服务以使用 Admin 区域进行身份验证。以下是您需要执行的命令片段，以重新配置每个区域上的核心服务，成为 Active-Active 区域设置的一部分。完整的命令列表可以在**os-admin-with-ansible/os-admin-with-ansible-v2** Github 存储库中的`root`目录中的名为`configure-region-authentication.txt`的文件中找到。

```
## Glance 
ansible glance_container -m shell -a "sed -i 's+^auth_url = http://172.30.238.2:35357+auth_url = http://<admin region IP>:35357+' /etc/glance/glance-api.conf" 
ansible glance_container -m shell -a "sed -i 's+^auth_url = http://172.30.238.2:35357+auth_url = http://<admin region IP>:35357+' /etc/glance/glance-registry.conf" 
ansible glance_container -m shell -a "sed -i 's+^auth_url = http://172.30.238.2:5000/v3+auth_url = http://<admin region IP>:5000/v3+' /etc/glance/glance-cache.conf" 

ansible glance_container -m shell -a "sed -i 's+^auth_uri = http://172.30.238.2:5000+auth_uri = http://<admin region IP>:5000+' /etc/glance/glance-api.conf" 
ansible glance_container -m shell -a "sed -i 's+^auth_uri = http://172.30.238.2:5000+auth_uri = http://<admin region IP>:5000+' /etc/glance/glance-registry.conf" 

ansible glance_container -m shell -a "service glance-api restart" 
ansible glance_container -m shell -a "service glance-registry restart"  

```

我发现最好和最有效的方法是搜索占位符`<admin region IP>`并将其替换为与 Admin 区域关联的公共 IP 或内部 IP。您可以使用任何文本编辑器进行操作，并且可以设置为针对任何区域执行的命令。

大家做得很好！您刚刚配置了具有多个活动区域的 OpenStack 云。与往常一样，为了保持我们的传统，我们将以快速回顾刚刚创建的剧本和角色结束本章。

# 审查剧本和角色

让我们立即开始检查我们创建的角色。

完成的角色和文件名为`main.yml`，位于`config-admin-region/tasks`目录中，如下所示：

```
--- 

- name: Create users 
 os_user: 
  cloud: "{{CLOUD_NAME}}" 
  state: present 
  name: "{{ item.0 }}" 
  password: "{{ item.1 }}" 
  default_project: "{{ servicesproject }}" 
  domain: default 
 with_together: 
  - "{{userid}}" 
  - "{{passwdss}}" 

- name: Assign user to specified role in designated environment 
 os_user_role: 
  cloud: "{{CLOUD_NAME}}" 
  user: "{{ item.0 }}" 
  role: "{{ urole }}" 
  project: "{{ servicesproject }}" 
 with_together:  
  - "{{userid}}" 

- name: Register the new services on the Admin region 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}" 
     service create --name "{{ item.0 }}" --description "{{ item.1 }}" "{{ servicetype }}" 
 with_together: 
  - "{{userid}}" 
  - "{{descrip}}" 

```

完成的角色和文件名为`main.yml`，位于`register-endpoints/tasks`目录中，如下所示：

```
--- 

- name: Register the region service endpoints on the Admin region 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}" 
     service endpoint create --region "{{ item.1 }}" "{{ item.0 }}" "{{ item.2 }}" "{{ item.3 }}" 
 with_together: 
  - "{{endpointname}}" 
  - "{{regionname}}" 
  - "{{endpointtype}}" 
  - "{{endpointurl}}" 

```

相应的角色本地变量文件都命名为`main.yml`，并保存在角色的`vars`目录中：

```
# variables for config-admin-region 

--- 
userid: [ 'glance', 'nova', 'neutron', 'heat' ] 
passwdss: [ 'passwd', 'passwd', 'passwd', 'passwd' ] 
descrip: [ 'Glance Image Service', 'Nova Compute Service', 'Neutron Network Service', 'Heat Orchestration Service' ] 
servicetype: [ 'image', 'compute', 'network', 'orchestration' ] 

servicesproject: service 
urole: admin 

# variables for register-endpoints 

--- 
endpointname: [ 'glance', 'nova', 'neutron', 'heat' ]  
regionname: alpha 
endpointtype: internal 
endpointurl: [ 'http://<alpha region IP>:9292', 'http://<alpha region IP>:8774/v2.1/%\(tenant_id\)s', 'http://<alpha region IP>:9696', 'http://<alpha region IP>:8004/v1/%\(tenant_id\)s' ] 

```

接下来，我们创建了以下主剧本文件；所有文件都位于`playbook`目录的`root`目录中：

+   `config-admin.yml`：

```
       --- 
       # This playbook used to demo OpenStack Juno user, role and project 
       features.  

      - hosts: util_container 
      remote_user: root 
      become: true 
      roles: 
         - config-admin-region 

```

+   `register-endpoints.yml`：

```
       --- 
       # This playbook used to demo OpenStack Juno user, role and project 
       features.  

       - hosts: util_container 
        remote_user: root 
        become: true 
        roles: 
         - register-endpoints 

```

最后，我们创建了`hosts`文件，它也位于`playbook`目录的`root`目录中：

```
[localhost] 
localhost ansible_connection=local 

[util_container] 
172.29.236.224 

```

### 注意

完整的代码集可以再次在 GitHub 存储库中找到[`github.com/os-admin-with-ansible/os-admin-with-ansible-v2`](https://github.com/os-admin-with-ansible/os-admin-with-ansible-v2)。

现在是有趣的部分，是时候测试我们的新 playbooks 和角色了。您还需要执行之前描述的额外的临时命令，以完全测试此功能。假设您已经克隆了之前提到的 GitHub 存储库，从部署节点测试 playbook 的命令将如下所示：

```
**$ ansible-playbook -i hosts config-admin.yml**
**$ ansible-playbook -i hosts register-endpoints.yml** 

```

接下来，您将执行`configure-region-authentication.txt`文件中的命令，该文件位于`playbook`目录的`root`目录中。如果一切顺利，您将能够登录到管理区域的 Web 仪表板，并在页面顶部标题中单击项目名称时看到以下内容：

![审查 playbooks 和角色](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/B06086_08_09.jpg)

# 摘要

是的！您刚刚在 Active-Active 设计中设置了您的 OpenStack 云。您刚刚获得的灵活性和可靠性解决了大多数主流 HA 要求。在区域之间跳转并在一两次点击内分离应用程序资源会很有趣。在结束本章之前，让我们花点时间回顾一下本章。我们讨论了 OpenStack 提供的开箱即用的处理高可用性要求的好处。然后，我们过渡到您可能想要使用 Active-Active 云区域的一些可能原因。接下来，我们将介绍如何设置 Active-Active 云区域的步骤。最后，我们开发了 Ansible playbooks 和角色来自动设置管理区域。

下一章恰好也是一个相当大的 OpenStack 云作为客户需求而提出的。没有任何云运营商不想知道或拥有他们的云的完整清单。跟踪资源、审计用户和总结网络利用率只是我们日常/每周例行工作的一部分。想象一下，您可以通过一个命令创建完整的报告。这可能吗？好吧，我不告诉你。您将不得不继续阅读第九章，“清点您的云”，以找出答案。


# 第九章：清单您的云

我非常兴奋地进入这一章，因为我们将专注于在管理 OpenStack 云时被认为具有挑战性的一个主题。收集有关正在使用的系统的指标是日常优先事项清单上的一个非常重要的项目。坏消息是，OpenStack 并不一定使这成为一项容易的任务。为了辩护 OpenStack，我会说最近的版本已经做了很多工作来改进这一点。新的 OpenStackClient（OSC）做得更好，允许云操作员汇总有关云的各种不同指标。

与此同时，有办法以临时方式收集这些指标，然后制作一个非常简单的报告。与 OpenStack 相关的大多数事情一样，有几种方法可以解决。在尝试使用多种方法进行此操作后，我发现通过对 OpenStack 数据库执行查询很容易实现。我知道，我知道……没有人想要触碰数据库。在过去的生活中，我曾经是一名数据库管理员，从那段经历中我学到的一件事是，简单明了的查询对任何数据库都是无害的。结合这个理论，并使用诸如 Ansible 之类的工具将收集到的所有信息汇总在一起是一个成功的组合。在本章中，我们将回顾如何动态地对 OpenStack 云资源的各个部分进行清单。我们将学习哪些指标具有价值，以及如何将这些信息存储以供以后参考。作为云操作员，拥有这样一个极其强大的工具是非常有用的。

+   收集云指标

+   用户报告

+   项目报告

+   网络报告

+   卷度报告

+   一目了然的云报告

+   编写操作手册和角色

+   审查操作手册和角色

# 收集云指标

这个过程的第一步是确定对您来说哪些指标是重要的。请记住，这里概述的方法只是我个人处理这个问题的方式。作为云操作员，您可能有不同的处理方式。将其作为一个起点来帮助您开始。

根据我的经验，最好汇总用户、项目、网络和卷度指标。然后，将所有数据合并在一起，输出总的云利用率指标。这与 Horizon 仪表板的功能非常相似。虽然登录 Horizon 并进行快速审查很容易，但如果您想向领导提供全面的报告呢？或者您可能想要拍摄一个时间点的快照，以比较一段时间内的云利用情况。将来可能需要对您的云进行审计。在不使用第三方工具的情况下，没有真正简单的方法以报告格式来做到这一点。下面的方法可以满足所有这些情况。

让我们从收集用户指标开始。

## 用户报告

捕获有关云中定义的用户的信息可能是记录的最简单的指标。当有一天您必须因合规性和安全原因对您的云进行审计时，您会注意到您列出了用户，甚至列出了分配给用户的角色，但没有将两者结合在一起。同样，您可以列出项目中的用户，但没有将分配给该用户的项目的角色一起列出。您可以看出我要说的是什么。将用户的完整列表与他们的 ID、分配给他们的角色以及他们可以访问的项目一起列在一份报告中是很有意义的。使用以下简单的数据库查询，您可以非常容易地获得这些信息：

```
USE keystone; 
SELECT local_user.user_id, local_user.name as username, role.name as role, project.name as tenant from local_user  
INNER JOIN assignment ON  
local_user.user_id=assignment.actor_id INNER JOIN  
role ON assignment.role_id=role.id INNER JOIN 
project ON assignment.target_id=project.id 
ORDER BY tenant; 

```

这个查询将结合数据库中名为 keystone 的四个不同表的数据。keystone 数据库是所有与用户相关的数据的所有者。数据库中的每个表至少有一个可以用来将数据联系在一起的主键。以下是这里使用的表及其功能的快速概述：

```
User       # contains the raw user information such as ID, name, 
             password and etc. 
Assignment # contains the role assignment for all users 
Role       # is the list of roles created/available 
Project    # contains the list of projects/tenants created/available 

```

在这个例子中，我们将专注于从四个表中只拉回必要的列。为了让事情变得更容易阅读，我们还重新命名了一些列标签。最后，我们将按项目名称按升序对数据进行排序，以便得到清晰和简单的输出。我保证不会在这个 SQL 查询中深入探讨太多。这是一本关于 OpenStack 和 Ansible 的书，不是 SQL 命令，对吧？

### 提示

始终尝试使用表的 ID 列来在可能的情况下链接其他表中的数据。ID 列将始终是一个唯一值，每次都会提供可靠的数据关联。如果使用包含项目名称值的列，最终可能会导致冲突，如果表中存在具有重复值的行。即使整个 OpenStack 也使用这种方法，您会注意到在 OpenStack 中创建的任何内容都有一个与之关联的 ID。

执行此查询后，输出将类似于以下内容：

![用户报告](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_09_001.jpg)

## 项目报告

在整个云生命周期中，清晰地了解云中存在的项目和正在使用的资源可以非常有价值。最近，部门或部门费用分摊似乎是一种非常流行的方法。将这些指标作为时间点资源审查可以清楚地了解每个项目正在使用多少资源。为了成功完成这一点，必须为每个项目收集 vCPU、内存和磁盘指标。使用以下简单的数据库查询，您可以非常容易地获得这些信息：

```
USE nova; 
SELECT SUM(instances.vcpus) as vCPU, SUM(instances.memory_mb) as memory_MB, SUM(instances.root_gb) as disk_GB, keystone.project.name as tenant from instances 
INNER JOIN keystone.project ON 
instances.project_id=keystone.project.id  
WHERE instances.vm_state='active' GROUP BY tenant; 

```

此查询将合并来自两个不同数据库（`nova`和`keystone`）中的数据。`nova`数据库拥有所有与实例相关的数据。`keystone`数据库在前面的部分中已经审查过。就像之前的例子一样，每个表至少有一个主键。以下是这里使用的表及其功能的快速概述：

```
nova 
Instances # contains the raw information about instances created 

keystone 
Project   # contains the list of projects/tenants created/available 

```

为了获得这些数据，我们必须有点巧妙，并直接从包含原始实例信息的表中提取资源指标。如果我们安装了 Ceilometer，将会有一个特定的数据库，记录这些指标在更微观的水平上。由于我们目前没有这个功能，这种方法是目前可用的最好方法。在此查询中，我们将再次只返回必要的列并重新命名列标签。最后，我们将缩小输出范围，只包括活动实例，并按项目名称按升序对数据进行排序。因此，通过获取每个实例的资源信息并将其与实例所属的每个项目相关联，我们能够创建类似于这样的简单输出：

![项目报告](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_09_002.jpg)

## 网络报告

在您的云上创建的 Neutron 网络的快照可能看起来对管理整个 OpenStack 云并不重要。相信我，在大局中是重要的。不必要或配置不正确的网络可能会给整个云功能增加延迟。直接导致这种情况的并不是网络本身，而是与每个项目相关的安全组的存在。这些信息主要可以帮助解决项目报告的问题。它提供了一个快速参考，了解每个项目中存在哪些网络以及与之关联的网络**无类域间路由选择（CIDR）**，即网络地址空间。在本地，网络服务（Neutron）在一个命令中并不提供这样的报告。就像之前一样，我们将直接从数据库中提取这些信息。使用以下简单的数据库查询，我们将收集网络 ID、名称、子网、分配的 CIDR、状态和关联的项目：

```
USE neutron; 
SELECT networks.id, networks.name, subnets.name as subnet, subnets.cidr, networks.status, keystone.project.name as tenant from networks 
INNER JOIN keystone.project ON networks.project_id COLLATE utf8_unicode_ci = keystone.project.id  
INNER JOIN subnets ON networks.id=subnets.network_id 
ORDER BY tenant; 

```

对于这个查询，我们将合并来自两个不同数据库`neutron`和`keystone`中的三个不同表的数据。`neutron`数据库拥有所有与网络相关的数据。以下是这里使用的表及其功能的快速概述：

```
neutron 
Networks # contains the raw information about networks created 
Subnets  # contains the subnet details associated with the networks 

keystone 
Project  # contains the list of projects/tenants created/available 

```

收集这些指标相当简单，因为大部分数据都存在于网络表中。我们所要做的就是从子网表中提取匹配的 CIDR，然后引入与该网络相关联的项目名称。在组合这个查询的过程中，我注意到`keystone`和`neutron`数据库表之间存在连接问题。显然，`neutron`数据库对 ID 列的模式定义不同，因此必须在内部连接语句中添加以下值：`COLLATE utf8_unicode_ci`。最终，输出将按项目名称按升序排序。输出的示例将类似于：

![网络报告](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_09_003.jpg)

## 卷报告

在云中对整体卷消耗进行详细报告的能力似乎是 OpenStack 目前的一个较大的空白。块存储服务（Cinder）负责在云中维护和跟踪卷。为了获得准确的指标，我们需要直接查询 Cinder。能够有一份报告来分解每个项目创建的卷的数量将是很好的。然后，能够有一个快速的汇总报告来显示每个项目使用了多少卷存储。现在由于 Cinder 支持多个存储后端，最好跟踪卷类型的消耗情况。随着 Cinder 的成熟，我相信这将成为一个更容易的任务，但目前，我们可以再次直接查询数据库以提取我们正在寻找的指标。以下是用于收集这些指标的数据库查询的示例：

```
USE cinder; 
SELECT volumes.id, volumes.display_name as volume_name, volumes.size as size_GB, volume_types.name as volume_type, keystone.project.name as tenant from volumes 
INNER JOIN keystone.project ON volumes.project_id=keystone.project.id  
INNER JOIN volume_types ON volumes.volume_type_id=volume_types.id 
WHERE volumes.status='available' 
ORDER BY tenant; 

SELECT SUM(volumes.size) as volume_usage_GB, keystone.project.name as tenant from volumes 
INNER JOIN keystone.project ON volumes.project_id=keystone.project.id 
WHERE volumes.status='available' 
GROUP BY tenant; 

SELECT volume_types.name as volume_type, SUM(volumes.size) as volume_usage_GB from volumes 
INNER JOIN volume_types ON volumes.volume_type_id=volume_types.id 
WHERE volumes.status='available' 
GROUP BY volume_type; 

```

对于这个查询，至少涉及两个数据库`cinder`和`keystone`中的三个不同表。如您所见，收集这些信息相当复杂。我们需要发出三个单独的`SELECT`语句。第一个`SELECT`语句将从卷表中关联原始卷信息和来自 keystone 表的项目数据。此外，在同一个语句中，我们将包括卷类型的名称。由于卷表包含活动和非活动卷，必须应用额外的过滤器来仅返回活动卷。完整的输出将按项目名称按升序排序。第一个查询的输出将类似于这样：

![卷报告](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_09_004.jpg)

下一个`SELECT`语句将查询数据库，收集每个项目的总卷消耗指标。它与前一个语句非常相似，但这里的主要区别是我们将为每个项目添加`volume_usage_GB`列，以计算总消耗量。第二个查询的输出将类似于这样：

![卷报告](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_09_005.jpg)

最终的`SELECT`语句专注于报告卷类型的消耗情况。由于卷表仅记录卷类型 ID，我们必须内部连接`volume_types`表，以引入创建时定义的实际卷名称。这也是之前提到的其他语句所做的事情。第三个查询的输出将类似于：

![卷报告](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_09_006.jpg)

## 一览云报告

这份报告旨在快速概述云的整体消耗情况。它返回云中存在的用户、项目、卷和网络的总数。以及当前使用的 vCPU、内存和临时磁盘的总数。以下是用于收集这些数据的数据库查询：

```
USE keystone; 
SELECT count(*) as total_users from user WHERE user.enabled=1; 
SELECT count(*) as total_projects from project WHERE project.enabled=1; 
USE cinder; 
SELECT count(*) as total_volumes, SUM(volumes.size) as total_volume_usage_GB from volumes 
WHERE volumes.status='available'; 
USE neutron; 
SELECT count(*) as total_networks from networks WHERE networks.status='ACTIVE'; 
USE nova; 
SELECT SUM(instances.vcpus) as total_vCPU, SUM(instances.memory_mb) as total_memory_MB, SUM(instances.root_gb) as total_disk_GB from instances 
WHERE instances.vm_state='active'; 

```

基本上使用的`SELECT`语句是将被调用的表中的列相加。然后将列名重命名为更具描述性的标签，最后进行过滤，忽略任何不处于活动状态的行。一旦执行，前面查询的输出将类似于这样：

![一览云报告](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_09_007.jpg)

现在我们知道如何收集报告的指标，让我们去学习如何完全自动化这个任务。

# 编写 playbooks 和 roles

在本节中，我们将创建 playbook 和 roles 来生成全面的*云报告*。一旦执行 playbook，输出和最终结果将是两份报告，包括我们在上一节中学习如何收集的信息。这两份报告将保存在您确定的目录中以便检索。在那时，您可以直接将其发送给领导和/或同行进行审查。在下一章中，我们将学习如何进一步进行，并直接通过电子邮件发送报告作为额外的奖励。

与上一章非常相似，我们将将多个任务分解为单独的角色，以保持组织。接下来，我们将审查用于自动创建我们的云报告的六个角色。

## 云清单

我们将创建的第一个角色将包括设置云报告基础所需的任务。文件名将是`main.yml`，位于名为`cloud-inventory/tasks`的角色目录中。该文件的内容将如下所示：

```
--- 
 name: Create working directory 
 file: path="{{ REPORT_DIR }}" state=directory 
 ignore_errors: yes 

 name: Copy the cloud_report script 
 copy: src=cloud_report.sql dest=/usr/share mode=0755 

 name: Add report header 
 shell: ( echo "+------------------------------------+"; echo "| {{ COMPANY }} Cloud Report     |"; echo "| Created at {{ lookup('pipe', 'date +%Y-%m-%d%t%X') }} |"; echo "+------------------------------------+"; ) >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log  

 name: Execute cloud report 
 shell: chdir=/usr/bin mysql -u root --password={{ MYSQLPASS }} --table < /usr/share/cloud_report.sql >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log 

```

前三个任务只是处理创建报告所需的先决步骤。这将包括创建报告保存的目录，处理要执行的 SQL 脚本，并向报告添加标题。总体思路是创建一个视觉上吸引人、准确且灵活的报告。这是通过动态添加报告运行时间/日期并相应命名报告来实现的。最后一个任务将直接针对云中 Galera 容器中找到的 MySQL 数据库执行`cloud_report.sql`文件。

`cloud_report.sql`文件包含前面**一览云报告**部分中描述的 SQL 查询。该文件可以在此角色的`cloud-inventory/files`目录中找到。

## 云使用

接下来的角色将创建第二份报告，概述当前云利用率按项目分解。该文件将命名为`main.yml`，位于名为`cloud-usage/tasks`的角色目录中。该文件的内容将如下所示：

```
--- 
 name: Create working directory 
 file: path="{{ REPORT_DIR }}" state=directory 
 ignore_errors: yes 

 name: Retrieve projectIDs 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}" 
     project list | awk 'NR > 3 { print $2 }' 
register: tenantid 

 name: Add report header 
 shell: ( echo "+------------------------------------+"; echo "| Project Usage Report        |"; echo "| Created at {{ lookup('pipe', 'date +%Y-%m-%d%t%X') }} |"; echo "+------------------------------------+"; echo " "; ) >> {{ REPORT_DIR }}/os_usage_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log  

 name: Record project usage 
 shell: ( echo "Project - {{ item }}" && openstack --os-cloud="{{ CLOUD_NAME }}" 
     usage show --start {{ RPTSTART }} --end {{ RPTEND }} --project {{ item }} && echo " " ) >> {{ REPORT_DIR }}/os_usage_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log 
 with_items: "{{ tenantid.stdout_lines }}" 

 name: Retrieve project usage report file 
 fetch: src={{ REPORT_DIR }}/os_usage_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log dest={{ REPORT_DEST }} flat=yes 

```

所有报告的预设置工作都在前面显示的第一和第三个任务中处理（创建报告目录和标题）。为了收集我们需要的报告指标，我们可以使用本机 OpenStack CLI 命令。使用的两个命令是：`openstack project list`和`usage show`。这些命令作为上面显示的第二和第四个任务的一部分执行。此角色中的最后一个任务将从远程位置检索报告并将其移动到 playbook/roles 执行的本地位置。

## 用户清单

该角色将负责执行前面部分描述的**用户报告**。文件将命名为`main.yml`，位于名为`user-inventory/tasks`的角色目录中。在这里，您将找到该文件的内容：

```
--- 
 name: Create working directory 
 file: path={{ REPORT_DIR }} state=directory 
 ignore_errors: yes 

 name: Copy the user_report script 
 copy: src=user_report.sql dest=/usr/share mode=0755 

 name: Add report header 
 shell: ( echo "+------------------------+"; echo "| Cloud User Report   |"; echo "+------------------------+"; ) >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log  

 name: Execute user report 
 shell: chdir=/usr/bin mysql -u root --password={{ MYSQLPASS }} --table < /usr/share/user_report.sql >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log 

```

为了使报告模块化且不相互依赖，我让每个角色创建一个报告工作目录并插入特定于报告的标题。这样，您可以包含或排除您希望的任何角色/报告。

用于创建此角色的基本原则将重复用于其余角色。它包括以下步骤：

+   创建报告工作目录；如果目录已经存在，它将继续报告无错误

+   将 SQL 脚本复制到远程位置

+   向报告添加自定义标题信息

+   执行 SQL 脚本以生成特定子报告

`user_report.sql`文件包含了前面部分描述的**用户报告**中的 SQL 查询。现在我们已经定义了框架，我们可以快速地完成剩下的角色。

## project-inventory

这个角色的目的是执行我们在前面部分审查过的**项目报告**。文件将被命名为`main.yml`，存放在名为`project-inventory/tasks`的角色目录中。在这里，你会找到这个文件的内容：

```
--- 
 name: Create working directory 
 file: path={{ REPORT_DIR }} state=directory 
 ignore_errors: yes 

 name: Copy the tenant_report script 
 copy: src=project_report.sql dest=/usr/share mode=0755 

 name: Add report header 
 shell: ( echo "+-------------------------+"; echo "| Cloud Project Report   |"; echo "+-------------------------+"; ) >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log  

 name: Execute tenant report 
 shell: chdir=/usr/bin mysql -u root --password={{ MYSQLPASS }} --table < /usr/share/project_report.sql >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log 

```

由于这个角色将遵循为用户清单角色概述的相同步骤，我们将注意力集中在执行的独特功能上。对于这个角色，`project_report.sql`文件将包含前面**项目报告**部分中描述的 SQL 查询。

## network-inventory

这个角色的目的是执行我们在前面部分审查过的**网络报告**。文件将被命名为`main.yml`，存放在名为`network-inventory/tasks`的角色目录中。在这里，你会找到这个文件的内容：

```
--- 
 name: Create working directory 
 file: path={{ REPORT_DIR }} state=directory 
 ignore_errors: yes 

 name: Copy the network_report script 
 copy: src=network_report.sql dest=/usr/share mode=0755 

 name: Add report header 
 shell: ( echo "+-------------------------+"; echo "| Cloud Network Report  |"; echo "+-------------------------+"; ) >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log  

 name: Execute network report 
 shell: chdir=/usr/bin mysql -u root --password={{ MYSQLPASS }} --table < /usr/share/network_report.sql >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log 

```

## volume-inventory

这个最后的角色将执行我们之前涵盖的**卷报告**的最终子报告。文件将被命名为`main.yml`，存放在名为`volume-inventory/tasks`的角色目录中。在这里，你会找到这个文件的内容：

```
--- 
 name: Create working directory 
 file: path={{ REPORT_DIR }} state=directory 
 ignore_errors: yes 

 name: Copy the volume_report script 
 copy: src=volume_report.sql dest=/usr/share mode=0755 

 name: Add report header 
 shell: ( echo "+--------------------------+"; echo "| Cloud Volume Report   |"; echo "+--------------------------+"; ) >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log  

 name: Execute volume report 
 shell: chdir=/usr/bin mysql -u root --password={{ MYSQLPASS }} --table < /usr/share/volume_report.sql >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log 

 name: Retrieve completed cloud report file 
 fetch: src={{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log dest={{ REPORT_DEST }} flat=yes 

```

值得注意的一件特别的事情是，这个角色的最后一个任务使用`fetch` Ansible 模块从远程位置检索创建的报告。这与云使用角色中使用的行为相同。就个人而言，我觉得这个模块非常方便，让我们不必处理一系列的安全复制命令。这对任何人来说都不是一个好时机。

为了支持这些角色，我们现在需要创建与之配套的变量文件。由于我们将使用两个单独的主机来执行一系列角色，所以需要两个全局变量文件。文件名分别是`util_container`和`galera_container`，它们将被保存到 playbook 的`group_vars/`目录中。

### 提示

请记住，变量文件中定义的值是为了在正常的日常使用中在每次执行前进行更改的。

你应该注意到为新角色定义的一些新变量。除了用于认证进入你的 OpenStack 云的标准变量之外，我们还添加了一些与报告创建和位置相关的新变量：

```
util_container 

# Here are variables related globally to the util_container host group 

CLOUD_NAME: default 

REPORT_DIR: /usr/share/os-report 
REPORT_DEST: /usr/share/ 
RPTSTART: 2016-10-01 
RPTEND: 2016-11-01 

galera_container 

# Here are variables related globally to the galera_container host group 

MYSQLPASS: passwd 
COMPANY: Rackspace RPC 
REPORT_DIR: /usr/share/os-report 
REPORT_DEST: /usr/share/ 

```

### 注意

**注意：**

由于这个文件的内容，它应该被存储为一个安全文件，无论你使用什么代码库来存储你的 Ansible playbooks/roles。获取这些信息可能会危及你的 OpenStack 云安全。

让我们花点时间来分解新的变量。总结如下：

```
REPORT_DIR  # the directory where the report is 
              stored temporarily remotely 
REPORT_DEST # the directory where the report is saved locally 

RPTSTART    # the start date when collecting cloud usage 

RPTEND      # the end date when collecting cloud usage 

MYSQLPASS   # the password for the root database user 

COMPANY     # the company name to show up in the report header 

```

### 注意

由于有两个共享相同变量名的全局变量文件，请确保如果你希望两个报告存在于同一个目录中，保持变量值同步。这不是一个要求，因为每个报告（云报告和云使用）都可以独立存在。只是觉得值得一提，以免引起混淆。

变量文件完成后，我们可以继续创建主要的 playbook 文件。由于我们的目标是创建一个关于云资源的报告（记住我们将云使用报告作为奖励添加了进来），我们将从一个 playbook 中调用所有的角色。playbook 文件的完整内容最终看起来会类似于这样：

```
--- 
# This playbook used to run a cloud resource inventory report.  

 hosts: galera_container 
 remote_user: root 
 become: true 
 roles: 
  - cloud-inventory 

 hosts: util_container 
 remote_user: root 
 become: true 
 roles: 
  - cloud-usage 

 hosts: galera_container 
 remote_user: root 
 become: true 
 roles: 
  - user-inventory 
  - project-inventory 
  - network-inventory 
  - volume-inventory 

```

正如提到的，我们创建的所有用于清点云的角色将按照 playbook 中显示的顺序执行。所有的角色都使用相同的主机，除了云使用角色。背后的原因是我们在那个角色中使用了 OpenStack CLI 命令，这就需要使用`util_container`。

### 注意

playbook 和 role 的名称可以是您选择的任何内容。这里提供了具体的名称，以便您可以轻松地跟踪并引用 GitHub 存储库中找到的已完成代码。唯一的警告是，无论您决定如何命名角色，当在 playbook 中引用时，它必须保持统一。

因此，由于我们现在在此 playbook 中涉及了一个额外的主机，我们必须将此主机添加到名为`hosts`的清单文件中。通过添加新主机占位符，主机文件现在将如下所示：

```
[localhost] 
localhost ansible_connection=local 

[util_container] 
172.29.236.85 

[galera_container] 
172.29.236.72 

```

我非常兴奋地确认我们现在已经准备好开始运行一些云报告了。按照我们的传统，我们将以快速回顾刚刚创建的 playbook 和 role 来结束本章。

# 审查 playbooks 和 roles

让我们立即开始审查我们创建的 roles。

位于`cloud-inventory/tasks`目录中的已完成的 role 和名为`main.yml`的文件如下所示：

```
--- 
 name: Create working directory 
 file: path="{{ REPORT_DIR }}" state=directory 
 ignore_errors: yes 

 name: Copy the cloud_report script 
 copy: src=cloud_report.sql dest=/usr/share mode=0755 

 name: Add report header 
 shell: ( echo "+------------------------------------+"; echo "| {{ COMPANY }} Cloud Report     |"; echo "| Created at {{ lookup('pipe', 'date +%Y-%m-%d%t%X') }} |"; echo "+------------------------------------+"; ) >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log  

 name: Execute cloud report 
 shell: chdir=/usr/bin mysql -u root --password={{ MYSQLPASS }} --table < /usr/share/cloud_report.sql >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log 

```

位于`cloud-usage/tasks`目录中的已完成的 role 和名为`main.yml`的文件如下所示：

```
--- 
 name: Create working directory 
 file: path="{{ REPORT_DIR }}" state=directory 
 ignore_errors: yes 

 name: Retrieve projectIDs 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}" 
     project list | awk 'NR > 3 { print $2 }' 
 register: tenantid 

 name: Add report header 
 shell: ( echo "+------------------------------------+"; echo "| Project Usage Report        |"; echo "| Created at {{ lookup('pipe', 'date +%Y-%m-%d%t%X') }} |"; echo "+------------------------------------+"; echo " "; ) >> {{ REPORT_DIR }}/os_usage_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log  

 name: Record project usage 
 shell: ( echo "Project - {{ item }}" && openstack --os-cloud="{{ CLOUD_NAME }}" 
     usage show --start {{ RPTSTART }} --end {{ RPTEND }} --project {{ item }} && echo " " ) >> {{ REPORT_DIR }}/os_usage_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log 
 with_items: "{{ tenantid.stdout_lines }}" 

 name: Retrieve project usage report file 
 fetch: src={{ REPORT_DIR }}/os_usage_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log dest={{ REPORT_DEST }} flat=yes 

```

位于`user-inventory/tasks`目录中的已完成的 role 和名为`main.yml`的文件如下所示：

```
--- 
 name: Create working directory 
 file: path={{ REPORT_DIR }} state=directory 
 ignore_errors: yes 

 name: Copy the user_report script 
 copy: src=user_report.sql dest=/usr/share mode=0755 

 name: Add report header 
 shell: ( echo "+------------------------+"; echo "| Cloud User Report   |"; echo "+------------------------+"; ) >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log  

 name: Execute user report 
 shell: chdir=/usr/bin mysql -u root --password={{ MYSQLPASS }} --table < /usr/share/user_report.sql >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log 

```

位于`project-inventory/tasks`目录中的已完成的 role 和名为`main.yml`的文件如下所示：

```
--- 
 name: Create working directory 
 file: path={{ REPORT_DIR }} state=directory 
 ignore_errors: yes 

 name: Copy the tenant_report script 
 copy: src=project_report.sql dest=/usr/share mode=0755 

 name: Add report header 
 shell: ( echo "+-------------------------+"; echo "| Cloud Project Report   |"; echo "+-------------------------+"; ) >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log  

 name: Execute tenant report 
 shell: chdir=/usr/bin mysql -u root --password={{ MYSQLPASS }} --table < /usr/share/project_report.sql >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log 

```

位于`network-inventory/tasks`目录中的已完成的 role 和名为`main.yml`的文件如下所示：

```
--- 
 name: Create working directory 
 file: path={{ REPORT_DIR }} state=directory 
 ignore_errors: yes 

 name: Copy the network_report script 
 copy: src=network_report.sql dest=/usr/share mode=0755 

 name: Add report header 
 shell: ( echo "+-------------------------+"; echo "| Cloud Network Report  |"; echo "+-------------------------+"; ) >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log  

 name: Execute network report 
 shell: chdir=/usr/bin mysql -u root --password={{ MYSQLPASS }} --table < /usr/share/network_report.sql >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log 

```

位于`volume-inventory/tasks`目录中的已完成的 role 和名为`main.yml`的文件如下所示：

```
--- 
 name: Create working directory 
 file: path={{ REPORT_DIR }} state=directory 
 ignore_errors: yes 
 name: Copy the volume_report script 
 copy: src=volume_report.sql dest=/usr/share mode=0755 

 name: Add report header 
 shell: ( echo "+--------------------------+"; echo "| Cloud Volume Report   |"; echo "+--------------------------+"; ) >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log  

 name: Execute volume report 
 shell: chdir=/usr/bin mysql -u root --password={{ MYSQLPASS }} --table < /usr/share/volume_report.sql >> {{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log 

 name: Retrieve completed cloud report file 
 fetch: src={{ REPORT_DIR }}/os_report_{{ lookup('pipe', 'date +%Y%m%d') }}.log dest={{ REPORT_DEST }} flat=yes 

```

相应的全局变量文件名为`util_container`，保存在完整 playbook 的`group_vars/`目录中：

```
# Here are variables related globally to the util_container host group 

CLOUD_NAME: default 

REPORT_DIR: /usr/share/os-report 
REPORT_DEST: /usr/share/ 
RPTSTART: 2016-10-01 
RPTEND: 2016-11-01 

```

相应的全局变量文件名为`galera_container`，保存在完整 playbook 的`group_vars/`目录中：

```
# Here are variables related globally to the galera_container host group 

MYSQLPASS: passwd 
COMPANY: Rackspace RPC 
REPORT_DIR: /usr/share/os-report 
REPORT_DEST: /usr/share/ 

```

现在主 playbook 文件已经创建，并将位于`playbook`目录的`root`目录中：

**inventory.yml**

```
--- 
# This playbook used to run a cloud resource inventory report.  

 hosts: galera_container 
 remote_user: root 
 become: true 
 roles: 
  - cloud-inventory 

 hosts: util_container 
 remote_user: root 
 become: true 
 roles: 
  - cloud-usage 

 hosts: galera_container 
 remote_user: root 
 become: true 
 roles: 
  - user-inventory 
  - project-inventory 
  - network-inventory 
  - volume-inventory 

```

最后，我们创建了`hosts`文件，也位于`playbook`目录的`root`目录中：

```
[localhost] 
localhost ansible_connection=local 

[util_container] 
172.29.236.85 

[galera_container] 
172.29.236.72 

```

### 注

完整的代码集可以在以下 GitHub 存储库中找到：[`github.com/os-admin-with-ansible/os-admin-with-ansible-v2/tree/master/cloud-inventory`](https://github.com/os-admin-with-ansible/os-admin-with-ansible-v2/tree/master/cloud-inventory)。

在我们结束这个话题之前，当然需要测试我们的工作。在运行此 playbook 和 roles 结束时，您将有两份报告需要审查。假设您之前已经克隆了 GitHub 存储库，从部署节点测试 playbook 的命令如下：

```
**$ cd os-admin-with-ansible-v2/cloud-inventory**
**$ ansible-playbook -i hosts inventory.yml**

```

假设 playbook 成功运行并且没有错误，您将在全局变量文件中指定的目录中找到创建的两个报告。报告应该类似于这样：

![审查 playbooks 和 roles](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_09_008.jpg)

...

![审查 playbooks 和 roles](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_09_009.jpg)

再次干得好！希望这些云报告能够真正帮助简化您日常的 OpenStack 管理任务！

# 总结

我们的 OpenStack 管理工具箱在本书中已经开始看起来相当丰富。强调拥有云状态的快照有多么重要是无法言喻的。这些报告可能是拥有快照的一个很好的起点。在结束本章之前，让我们花一点时间回顾本章。我们一起审查了 OpenStack 关于云库存报告的一些空白以及您如何克服它们。然后提供了如何通过查询数据库来获取我们需要的指标和统计信息的详细信息。接下来，我们详细研究了用于从数据库中提取数据的自定义 SQL 查询。最后，我们开发了 Ansible playbook 和 role 来自动生成云报告。

很遗憾地说，下一章是我们的最后一章。话虽如此，它肯定是最重要的章节之一。了解您的云的健康状况对于拥有一个正常运行的 OpenStack 生态系统至关重要。由于 OpenStack 的模块化性质，您将有许多服务需要跟踪。让它们都正常工作是在 OpenStack 内部创造了良好的和谐。虽然您当然可以手动完成，但我相信您会同意自动化这样的任务更理想。请继续阅读下一章，了解如何可以自动监控您的云的健康状况，甚至将健康报告直接发送到您的收件箱。
