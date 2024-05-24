# Ansible 2 实战（二）

> 原文：[`zh.annas-archive.org/md5/B93AA180F347B680872C5A7851966C2F`](https://zh.annas-archive.org/md5/B93AA180F347B680872C5A7851966C2F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：定义您的清单

正如我们在前两章中已经讨论过的，除非告诉它负责哪些主机，否则 Ansible 无法做任何事情。这当然是合乎逻辑的——无论自动化工具有多容易使用和设置，你都不希望它简单地控制网络上的每个设备。因此，至少，您必须告诉 Ansible 它将自动化任务的主机是哪些，这在最基本的术语中就是清单。

然而，清单中有很多东西不仅仅是自动化目标的列表。Ansible 清单可以以几种格式提供；它们可以是静态的或动态的，并且它们可以包含定义 Ansible 与每个主机（或主机组）交互的重要变量。因此，它们值得有一个章节来讨论，而在本章中，我们将对清单进行实际探索，以及如何在使用 Ansible 自动化基础设施时充分利用它们。

在本章中，我们将涵盖以下主题：

+   创建清单文件并添加主机

+   生成动态清单文件

+   使用模式进行特殊主机管理

# 技术要求

本章假设您已经按照第一章 *开始使用 Ansible*中详细说明的设置了控制主机，并且您正在使用最新版本——本章的示例是使用 Ansible 2.9 进行测试的。本章还假设您至少有一个额外的主机进行测试，并且最好是基于 Linux 的。尽管本章将给出主机名的具体示例，但您可以自由地用自己的主机名和/或 IP 地址替换它们，如何做到这一点的详细信息将在适当的地方提供。

本章的代码包在此处可用：[`github.com/PacktPublishing/Ansible-2-Cookbook/tree/master/Chapter%203`](https://github.com/PacktPublishing/Ansible-2-Cookbook/tree/master/Chapter%203)。

# 创建清单文件并添加主机

每当您在 Ansible 中看到“创建清单”的参考时，通常可以安全地假定它是一个静态清单。Ansible 支持两种类型的清单——静态和动态，我们将在本章后面讨论后者。静态清单本质上是静态的；除非有人去手动编辑它们，否则它们是不会改变的。当您开始测试 Ansible 时，这是一个很好的选择，因为它为您提供了一个非常快速和简单的方法来快速启动和运行。即使在小型封闭环境中，静态清单也是管理环境的好方法，特别是在基础设施的更改不频繁时。

大多数 Ansible 安装将在`/etc/ansible/hosts`中寻找默认的清单文件（尽管这个路径在 Ansible 配置文件中是可配置的，如第二章 *理解 Ansible 的基础知识*中所讨论的）。您可以填充此文件，或为每个 playbook 运行提供自己的清单，通常可以看到清单与 playbooks 一起提供。毕竟，很少有“一刀切”的 playbook，尽管您可以使用组来细分您的清单（稍后会详细介绍），但通常提供一个较小的静态清单文件与特定的 playbook 一起提供也同样容易。正如您在本书的前几章中所看到的，大多数 Ansible 命令在不使用默认值时使用`-i`标志来指定清单文件的位置。假设情况下，这可能看起来像以下示例：

```
$ ansible -i /home/cloud-user/inventory all -m ping
```

您可能会遇到的大多数静态清单文件都是以 INI 格式创建的，尽管重要的是要注意其他格式也是可能的。在 INI 格式的文件之后，您将发现的最常见格式是 YAML 格式 - 您可以在这里找到更多关于您可以使用的清单文件类型的详细信息：[`docs.ansible.com/ansible/latest/user_guide/intro_inventory.html`](https://docs.ansible.com/ansible/latest/user_guide/intro_inventory.html)。

在本章中，我们将为您提供一些 INI 和 YAML 格式的清单文件示例，供您考虑，因为您必须对两者都有所了解。就我个人而言，我已经使用 Ansible 工作了很多年，使用过 INI 格式的文件或动态清单，但他们说知识就是力量，所以了解一下这两种格式也无妨。

让我们从创建一个静态清单文件开始。这个清单文件将与默认清单分开。

在`/etc/ansible/my_inventory`中创建一个清单文件，使用以下格式化的 INI 代码：

```
target1.example.com ansible_host=192.168.81.142 ansible_port=3333  target2.example.com ansible_port=3333 ansible_user=danieloh  target3.example.com ansible_host=192.168.81.143 ansible_port=5555
```

清单主机之间的空行不是必需的 - 它们只是为了使本书中的清单更易读而插入的。这个清单文件非常简单，不包括任何分组；但是，在引用清单时，您仍然可以使用特殊的`all`组来引用所有主机，这个组是隐式定义的，无论您如何格式化和划分您的清单文件。

上述文件中的每一行都包含一个清单主机。第一列包含 Ansible 将使用的清单主机名（并且可以通过我们在第二章中讨论的`inventory_hostname`魔术变量来访问）。之后同一行上的所有参数都是分配给主机的变量。这些可以是用户定义的变量或特殊的 Ansible 变量，就像我们在这里设置的一样。

有许多这样的变量，但前面的例子特别包括以下内容：

+   `ansible_host`：如果无法直接访问清单主机名 - 例如，因为它不在 DNS 中，那么这个变量包含 Ansible 将连接的主机名或 IP 地址。

+   `ansible_port`：默认情况下，Ansible 尝试通过 SSH 的 22 端口进行所有通信 - 如果您在另一个端口上运行 SSH 守护程序，可以使用此变量告诉 Ansible。

+   `ansible_user`：默认情况下，Ansible 将尝试使用您从中运行 Ansible 命令的当前用户帐户连接到远程主机 - 您可以以多种方式覆盖这一点，其中之一就是这个。

因此，前面的三个主机可以总结如下：

+   `target1.example.com`主机应该使用`192.168.81.142`IP 地址连接，端口为`3333`。

+   `target2.example.com`主机也应该连接到端口`3333`，但这次使用`danieloh`用户，而不是运行 Ansible 命令的帐户。

+   `target3.example.com`主机应该使用`192.168.81.143`IP 地址连接，端口为`5555`。

通过这种方式，即使没有进一步的构造，您也可以开始看到静态的 INI 格式的清单的强大之处。

现在，如果您想要创建与前面完全相同的清单，但这次以 YAML 格式进行格式化，您可以指定如下：

```
---
ungrouped:
  hosts:
    target1.example.com:
      ansible_host: 192.168.81.142
      ansible_port: 3333
    target2.example.com:
      ansible_port: 3333
      ansible_user: danieloh
    target3.example.com:
      ansible_host: 192.168.81.143
      ansible_port: 5555
```

您可能会遇到包含参数如`ansible_ssh_port`、`ansible_ssh_host`和`ansible_ssh_user`的清单文件示例 - 这些变量名称（以及类似的其他变量）在 2.0 版本之前的 Ansible 版本中使用。对许多这些变量已经保持了向后兼容性，但在可能的情况下，您应该更新它们，因为这种兼容性可能在将来的某个时候被移除。

现在，如果您在 Ansible 中运行上述清单，使用一个简单的`shell`命令，结果将如下所示：

```
$ ansible -i /etc/ansible/my_inventory.yaml all -m shell -a 'echo hello-yaml' -f 5
target1.example.com | CHANGED | rc=0 >>
hello-yaml
target2.example.com | CHANGED | rc=0 >>
hello-yaml
target3.example.com | CHANGED | rc=0 >>
hello-yaml
```

这涵盖了创建一个简单静态清单文件的基础知识。现在让我们通过在本章的下一部分将主机组添加到清单中来扩展这一点。

# 使用主机组

很少有一个 playbook 适用于整个基础架构，尽管很容易告诉 Ansible 为不同的 playbook 使用备用清单，但这可能会变得非常混乱，非常快速，潜在地在你的网络中散布了数百个小清单文件。你可以想象这会变得多么难以管理，而 Ansible 的目的是使事情更容易管理，而不是相反。这个问题的一个可能简单的解决方案是开始在你的清单中添加组。

假设你有一个简单的三层 Web 架构，每层都有多个主机以实现高可用性和/或负载平衡。这种架构中的三个层可能是以下内容：

+   前端服务器

+   应用服务器

+   数据库服务器

有了这个架构，让我们开始创建一个清单，再次混合使用 YAML 和 INI 格式，以便你在两种格式中都有经验。为了使示例清晰简洁，我们假设你可以使用它们的**完全限定域名**（**FQDNs**）访问所有服务器，因此不会在这些清单文件中添加任何主机变量。当然，没有什么能阻止你这样做，每个示例都是不同的。

首先，让我们使用 INI 格式为三层前端创建清单。我们将称此文件为`hostsgroups-ini`，此文件的内容应该如下所示：

```
loadbalancer.example.com

[frontends]
frt01.example.com
frt02.example.com

[apps]
app01.example.com
app02.example.com

[databases]
dbms01.example.com
dbms02.example.com
```

在前面的清单中，我们创建了三个名为`frontends`、`apps`和`databases`的组。请注意，在 INI 格式的清单中，组名放在方括号内。在每个组名下面是属于每个组的服务器名，因此前面的示例显示了每个组中的两个服务器。请注意顶部的异常值`loadbalancer.example.com` - 这个主机不属于任何组。所有未分组的主机必须放在 INI 格式文件的顶部。

在我们进一步进行之前，值得注意的是，清单也可以包含组的组，这对于通过不同的部门处理某些任务非常有用。前面的清单是独立的，但如果我们的前端服务器是建立在 Ubuntu 上，而应用和数据库服务器是建立在 CentOS 上呢？在处理这些主机的方式上会有一些根本的不同 - 例如，我们可能会在 Ubuntu 上使用`apt`模块来管理软件包，在 CentOS 上使用`yum`模块。

当然，我们可以使用从每个主机收集的事实来处理这种情况，因为这些事实将包含操作系统的详细信息。我们还可以创建清单的新版本，如下所示：

```
loadbalancer.example.com

[frontends]
frt01.example.com
frt02.example.com

[apps]
app01.example.com
app02.example.com

[databases]
dbms01.example.com
dbms02.example.com

[centos:children]
apps
databases

[ubuntu:children]
frontends
```

在组定义中使用`children`关键字（在方括号内），我们可以创建组的组；因此，我们可以进行巧妙的分组，以帮助我们的 playbook 设计，而无需多次指定每个主机。

INI 格式中的这种结构相当易读，但当转换为 YAML 格式时需要一些时间来适应。下面列出的代码显示了前面清单的 YAML 版本 - 就 Ansible 而言，两者是相同的，但你可以决定你更喜欢使用哪种格式：

```
all:
  hosts:
    loadbalancer.example.com:
  children:
    centos:
      children:
        apps:
          hosts:
            app01.example.com:
            app02.example.com:
        databases:
          hosts:
            dbms01.example.com:
            dbms02.example.com:
    ubuntu:
      children:
        frontends:
          hosts:
            frt01.example.com:
            frt02.example.com:
```

你可以看到`children`关键字仍然在 YAML 格式的清单中使用，但现在结构比 INI 格式更加分层。缩进可能更容易让你理解，但请注意主机最终是在相当高层次的缩进下定义的 - 这种格式可能更难扩展，取决于你希望采用的方法。

当你想要使用前面清单中的任何组时，你可以在你的 playbook 或命令行中简单地引用它。例如，在上一节中我们运行的，我们可以使用以下命令：

```
$ ansible -i /etc/ansible/my_inventory.yaml all -m shell -a 'echo hello-yaml' -f 5
```

请注意该行中间的`all`关键字。这是所有库存中都隐含的特殊`all`组，并且在你之前的 YAML 示例中明确提到。如果我们想运行相同的命令，但这次只在之前的 YAML 库存中的`centos`组主机上运行，我们将运行这个命令的变体：

```
$ ansible -i hostgroups-yml centos -m shell -a 'echo hello-yaml' -f 5
app01.example.com | CHANGED | rc=0 >>
hello-yaml
app02.example.com | CHANGED | rc=0 >>
hello-yaml
dbms01.example.com | CHANGED | rc=0 >>
hello-yaml
dbms02.example.com | CHANGED | rc=0 >>
hello-yaml 
```

正如你所看到的，这是一种管理库存并轻松运行命令的强大方式。创建多个组的可能性使生活变得简单和容易，特别是当你想在不同的服务器组上运行不同的任务时。

作为开发库存的一部分，值得注意的是，有一种快速的简写表示法，可以用来创建多个主机。假设你有 100 个应用服务器，所有的名称都是顺序的，如下所示：

```
[apps]
app01.example.com
app02.example.com
...
app99.example.com
app100.example.com
```

这是完全可能的，但手工创建将是乏味和容易出错的，并且会产生一些非常难以阅读和解释的库存。幸运的是，Ansible 提供了一种快速的简写表示法来实现这一点，以下库存片段实际上产生了一个与我们可以手动创建的相同的 100 个应用服务器的库存：

```
[apps]
app[01:100].prod.com
```

也可以使用字母范围以及数字范围——扩展我们的示例以添加一些缓存服务器，你可能会有以下内容：

```
[caches]
cache-[a:e].prod.com  
```

这与手动创建以下内容相同：

```
[caches]
cache-a.prod.com cache-b.prod.com
cache-c.prod.com
cache-d.prod.com
cache-e.prod.com 
```

现在我们已经完成了对各种静态库存格式的探索以及如何创建组（甚至是子组），让我们在下一节中扩展我们之前简要介绍的主机变量。

# 向库存添加主机和组变量

我们已经提到了主机变量——在本章的前面部分，当我们用它们来覆盖连接细节时，比如要连接的用户帐户、要连接的地址和要使用的端口。然而，你可以在 Ansible 和库存变量中做的事情远不止这些，重要的是要注意，它们不仅可以在主机级别定义，还可以在组级别定义，这再次为你提供了一些非常强大的方式来高效地管理你的基础设施。

让我们在之前的三层示例基础上继续建设，并假设我们需要为我们的两个前端服务器中的每一个设置两个变量。这些不是特殊的 Ansible 变量，而是完全由我们自己选择的变量，我们将在稍后运行对这台服务器的 playbook 中使用。假设这些变量如下：

+   `https_port`，定义了前端代理应该监听的端口

+   `lb_vip`，定义了前端服务器前面的负载均衡器的 FQDN

让我们看看这是如何完成的：

1.  我们可以简单地将这些添加到我们库存文件中`frontends`部分的每个主机中，就像我们之前用 Ansible 连接变量做的那样。在这种情况下，我们的 INI 格式的库存的一部分可能是这样的：

```
[frontends]
frt01.example.com https_port=8443 lb_vip=lb.example.com
frt02.example.com https_port=8443 lb_vip=lb.example.com
```

如果我们对这个库存运行一个临时命令，我们可以看到这两个变量的内容：

```
$ ansible -i hostvars1-hostgroups-ini frontends -m debug -a "msg=\"Connecting to {{ lb_vip }}, listening on {{ https_port }}\""
frt01.example.com | SUCCESS => {
 "msg": "Connecting to lb.example.com, listening on 8443"
}
frt02.example.com | SUCCESS => {
 "msg": "Connecting to lb.example.com, listening on 8443"
}
```

这已经按我们的期望工作了，但这种方法效率低下，因为你必须将相同的变量添加到每个主机。

1.  幸运的是，你可以将变量分配给主机组以及单独的主机。如果我们编辑前面的库存以实现这一点，`frontends`部分现在看起来像这样：

```
[frontends]
frt01.example.com
frt02.example.com

[frontends:vars]
https_port=8443
lb_vip=lb.example.com
```

请注意这种方式更易读？然而，如果我们对新组织的库存运行与之前相同的命令，我们会发现结果是一样的：

```
$ ansible -i groupvars1-hostgroups-ini frontends -m debug -a "msg=\"Connecting to {{ lb_vip }}, listening on {{ https_port }}\""
frt01.example.com | SUCCESS => {
 "msg": "Connecting to lb.example.com, listening on 8443"
}
frt02.example.com | SUCCESS => {
 "msg": "Connecting to lb.example.com, listening on 8443"
}
```

1.  有时候你会想要为单个主机使用主机变量，有时候组变量更相关。由你来决定哪个对你的情况更好；然而，请记住主机变量可以组合使用。值得注意的是主机变量会覆盖组变量，所以如果我们需要将连接端口更改为`8444`，我们可以这样做：

```
[frontends]
frt01.example.com https_port=8444
frt02.example.com

[frontends:vars]
https_port=8443
lb_vip=lb.example.com
```

现在，如果我们再次使用新的清单运行我们的临时命令，我们可以看到我们已经覆盖了一个主机上的变量：

```
$ ansible -i hostvars2-hostgroups-ini frontends -m debug -a "msg=\"Connecting to {{ lb_vip }}, listening on {{ https_port }}\""
frt01.example.com | SUCCESS => {
 "msg": "Connecting to lb.example.com, listening on 8444"
}
frt02.example.com | SUCCESS => {
 "msg": "Connecting to lb.example.com, listening on 8443"
}
```

当然，当只有两个主机时，仅为一个主机执行此操作可能看起来有点无意义，但当你的清单中有数百个主机时，覆盖一个主机的这种方法突然变得非常有价值。

1.  为了完整起见，如果我们要将之前定义的主机变量添加到我们的清单的 YAML 版本中，`frontends`部分将如下所示（其余清单已被删除以节省空间）：

```
        frontends:
          hosts:
            frt01.example.com:
              https_port: 8444
            frt02.example.com:
          vars:
            https_port: 8443
            lb_vip: lb.example.com
```

运行与之前相同的临时命令，你会看到结果与我们的 INI 格式的清单相同：

```
$ ansible -i hostvars2-hostgroups-yml frontends -m debug -a "msg=\"Connecting to {{ lb_vip }}, listening on {{ https_port }}\""
frt01.example.com | SUCCESS => {
 "msg": "Connecting to lb.example.com, listening on 8444"
}
frt02.example.com | SUCCESS => {
 "msg": "Connecting to lb.example.com, listening on 8443"
}
```

1.  到目前为止，我们已经介绍了几种向清单提供主机变量和组变量的方法；然而，还有一种方法值得特别提及，并且在你的清单变得更大更复杂时会变得有价值。

现在，我们的示例很小很简洁，只包含少数组和变量；然而，当你将其扩展到一个完整的服务器基础设施时，再次使用单个平面清单文件可能会变得难以管理。幸运的是，Ansible 也提供了解决方案。两个特别命名的目录`host_vars`和`group_vars`，如果它们存在于剧本目录中，将自动搜索适当的变量内容。我们可以通过使用这种特殊的目录结构重新创建前面的前端变量示例来测试这一点，而不是将变量放入清单文件中。

让我们首先为此目的创建一个新的目录结构：

```
$ mkdir vartree
$ cd vartree
```

1.  现在，在这个目录下，我们将为变量创建两个更多的目录：

```
$ mkdir host_vars group_vars
```

1.  现在，在`host_vars`目录下，我们将创建一个文件，文件名为需要代理设置的主机名，后面加上`.yml`（即`frt01.example.com.yml`）。这个文件应该包含以下内容：

```
---
https_port: 8444
```

1.  同样，在`group_vars`目录下，创建一个名为要分配变量的组的 YAML 文件（即`frontends.yml`），内容如下：

```
---
https_port: 8443
lb_vip: lb.example.com
```

1.  最后，我们将像以前一样创建我们的清单文件，只是它不包含变量：

```
loadbalancer.example.com

[frontends]
frt01.example.com
frt02.example.com

[apps]
app01.example.com
app02.example.com

[databases]
dbms01.example.com
dbms02.example.com
```

为了清晰起见，你的最终目录结构应该是这样的：

```
$  tree
.
├── group_vars
│   └── frontends.yml
├── host_vars
│   └── frt01.example.com.yml
└── inventory

2 directories, 3 files
```

1.  现在，让我们尝试运行我们熟悉的临时命令，看看会发生什么：

```
$ ansible -i inventory frontends -m debug -a "msg=\"Connecting to {{ lb_vip }}, listening on {{ https_port }}\""
frt02.example.com | SUCCESS => {
 "msg": "Connecting to lb.example.com, listening on 8443"
}
frt01.example.com | SUCCESS => {
 "msg": "Connecting to lb.example.com, listening on 8444"
}
```

正如你所看到的，这与以前完全一样，而且在没有进一步的指示的情况下，Ansible 已经遍历了目录结构并摄取了所有的变量文件。

1.  如果你有数百个变量（或需要更精细的方法），你可以用主机和组的名字命名目录来替换 YAML 文件。现在，我们重新创建目录结构，但现在用目录代替：

```
$ tree
.
├── group_vars
│   └── frontends
│       ├── https_port.yml
│       └── lb_vip.yml
├── host_vars
│   └── frt01.example.com
│       └── main.yml
└── inventory
```

注意我们现在有了以`frontends`组和`frt01.example.com`主机命名的目录？在`frontends`目录中，我们将变量分成了两个文件，这对于在组中逻辑地组织变量尤其有用，特别是当你的剧本变得更大更复杂时。

这些文件本身只是我们之前的文件的一种改编：

```
$ cat host_vars/frt01.example.com/main.yml
---
https_port: 8444

$ cat group_vars/frontends/https_port.yml
---
https_port: 8443

$ cat group_vars/frontends/lb_vip.yml
---
lb_vip: lb.example.com
```

即使使用这种更细分的目录结构，运行临时命令的结果仍然是相同的：

```
$ ansible -i inventory frontends -m debug -a "msg=\"Connecting to {{ lb_vip }}, listening on {{ https_port }}\""
frt01.example.com | SUCCESS => {
 "msg": "Connecting to lb.example.com, listening on 8444"
}
frt02.example.com | SUCCESS => {
 "msg": "Connecting to lb.example.com, listening on 8443"
}
```

1.  在我们结束本章之前，还有一件事需要注意，即如果您在组级别和子组级别同时定义了相同的变量，则子组级别的变量优先。这并不像听起来那么明显。考虑我们之前的清单，我们在其中使用子组来区分 CentOS 和 Ubuntu 主机——如果我们在`ubuntu`子组和`frontends`组（`ubuntu`组的**子组**）中都添加了同名的变量，结果会是什么？清单将如下所示：

```
loadbalancer.example.com

[frontends]
frt01.example.com
frt02.example.com

[frontends:vars]
testvar=childgroup

[apps]
app01.example.com
app02.example.com

[databases]
dbms01.example.com
dbms02.example.com

[centos:children]
apps
databases

[ubuntu:children]
frontends

[ubuntu:vars]
testvar=group
```

现在，让我们运行一个临时命令，看看`testvar`的实际设置值是多少：

```
$ ansible -i hostgroups-children-vars-ini ubuntu -m debug -a "var=testvar"
frt01.example.com | SUCCESS => {
 "testvar": "childgroup"
}
frt02.example.com | SUCCESS => {
 "testvar": "childgroup"
}
```

需要注意的是，在这个清单中，`frontends`组是`ubuntu`组的子组（因此，组定义是`[ubuntu:children]`），因此在这种情况下，我们在`frontends`组级别设置的变量值会胜出。

到目前为止，您应该已经对如何使用静态清单文件有了相当好的了解。然而，没有查看动态清单的 Ansible 清单功能是完整的，我们将在下一节中做到这一点。

# 生成动态清单文件

在云计算和基础设施即代码的今天，您可能希望自动化的主机每天甚至每小时都会发生变化！保持静态的 Ansible 清单最新可能会成为一项全职工作，在许多大规模的场景中，因此，尝试在持续基础上使用静态清单变得不切实际。

这就是 Ansible 的动态清单支持发挥作用的地方。简而言之，Ansible 可以从几乎任何可执行文件中收集其清单数据（尽管您会发现大多数动态清单都是用 Python 编写的）——唯一的要求是可执行文件以指定的 JSON 格式返回清单数据。如果愿意，您可以自己创建清单脚本，但值得庆幸的是，已经有许多可供您使用的脚本，涵盖了许多潜在的清单来源，包括 Amazon EC2、Microsoft Azure、Red Hat Satellite、LDAP 目录等等。

在撰写书籍时，很难确定要使用哪个动态清单脚本作为示例，因为并不是每个人都有一个可以自由使用来进行测试的 Amazon EC2 帐户（例如）。因此，我们将以 Cobbler 配置系统作为示例，因为这是免费提供的，并且在 CentOS 系统上很容易部署。对于感兴趣的人来说，Cobbler 是一个用于动态配置和构建 Linux 系统的系统，它可以处理包括 DNS、DHCP、PXE 引导等在内的所有方面。因此，如果您要使用它来配置基础架构中的虚拟或物理机器，那么使用它作为清单来源也是有道理的，因为 Cobbler 负责首次构建系统，因此了解所有系统名称。

这个示例将为您演示使用动态清单的基本原理，然后您可以将其应用到其他系统的动态清单脚本中。让我们开始这个过程，首先安装 Cobbler——这个过程在 CentOS 7.8 上进行了测试：

1.  您的第一个任务是使用`yum`安装相关的 Cobbler 软件包。请注意，在撰写本文时，CentOS 7 提供的 SELinux 策略不支持 Cobbler 的功能，并阻止了一些方面的工作。尽管这不是您在生产环境中应该做的事情，但让这个演示快速运行的最简单方法是简单地禁用 SELinux：

```
$ yum install -y cobbler cobbler-web
$ setenforce 0
```

1.  接下来，请确保`cobblerd`服务已配置为在环回地址上监听，方法是检查`/etc/cobbler/settings`中的设置——文件的相关片段如下所示：

```
# default, localhost server: 127.0.0.1  
```

这不是一个公共监听地址，请*不要使用*`0.0.0.0`。您也可以将其设置为 Cobbler 服务器的 IP 地址。

1.  完成这一步后，您可以使用`systemctl`启动`cobblerd`服务。

```
$ systemctl start cobblerd.service
$ systemctl enable cobblerd.service
$ systemctl status cobblerd.service
```

1.  Cobbler 服务已经启动运行，现在我们将逐步介绍向 Cobbler 添加发行版的过程，以创建一些主机。这个过程非常简单，但您需要添加一个内核文件和一个初始 RAM 磁盘文件。获取这些文件的最简单来源是您的`/boot`目录，假设您已在 CentOS 7 上安装了 Cobbler。在用于此演示的测试系统上使用了以下命令，但是，您必须将`vmlinuz`和`initramfs`文件名中的版本号替换为您系统`/boot`目录中的适当版本号：

```
$ cobbler distro add --name=CentOS --kernel=/boot/vmlinuz-3.10.0-957.el7.x86_64 --initrd=/boot/initramfs-3.10.0-957.el7.x86_64.img

$ cobbler profile add --name=webservers --distro=CentOS
```

这个定义非常基础，可能无法生成可用的服务器镜像；但是，对于我们的简单演示来说，它足够了，因为我们可以基于这个假设的基于 CentOS 的镜像添加一些系统。请注意，我们正在创建的配置文件名`webservers`将在我们的动态清单中成为我们的清单组名。

1.  现在让我们将这些系统添加到 Cobbler 中。以下两个命令将向我们的 Cobbler 系统添加两个名为`frontend01`和`frontend02`的主机，使用我们之前创建的`webservers`配置文件：

```
$ cobbler system add --name=frontend01 --profile=webservers --dns-name=frontend01.example.com --interface=eth0

$ cobbler system add --name=frontend02 --profile=webservers --dns-name=frontend02.example.com --interface=eth0
```

请注意，为了使 Ansible 工作，它必须能够到达`--dns-name`参数中指定的这些 FQDN。为了实现这一点，我还在 Cobbler 系统的`/etc/hosts`中添加了这两台机器的条目，以确保我们以后可以到达它们。这些条目可以指向您选择的任何两个系统，因为这只是一个测试。

此时，您已成功安装了 Cobbler，创建了一个配置文件，并向该配置文件添加了两个假设系统。我们过程的下一阶段是下载并配置 Ansible 动态清单脚本，以便与这些条目一起使用。为了实现这一点，让我们开始执行以下给出的过程：

1.  从 GitHub Ansible 存储库下载 Cobbler 动态清单文件以及相关的配置文件模板。请注意，大多数由 Ansible 提供的动态清单脚本也有一个模板化的配置文件，其中包含您可能需要设置的参数，以使动态清单脚本工作。对于我们的简单示例，我们将把这些文件下载到我们当前的工作目录中：

```
$ wget https://raw.githubusercontent.com/ansible/ansible/devel/contrib/inventory/cobbler.py
$ wget https://raw.githubusercontent.com/ansible/ansible/devel/contrib/inventory/cobbler.ini
$ chmod +x cobbler.py
```

重要的是要记住，要使您下载的任何动态清单脚本可执行，就像之前展示的那样；如果您不这样做，那么即使其他一切都设置得完美，Ansible 也无法运行该脚本。

1.  编辑`cobbler.ini`文件，并确保它指向本地主机，因为在本例中，我们将在同一系统上运行 Ansible 和 Cobbler。在现实生活中，您会将其指向 Cobbler 系统的远程 URL。以下是配置文件的一部分，以便让您了解如何配置：

```
[cobbler]

# Specify IP address or Hostname of the cobbler server. The default variable is here:
host = http://127.0.0.1/cobbler_api

# (Optional) With caching, you will have responses of API call with the cobbler server quicker
cache_path = /tmp
cache_max_age = 900
```

1.  现在，您可以按照您习惯的方式运行 Ansible 的临时命令——这次唯一的区别是，您将指定动态清单脚本的文件名，而不是静态清单文件的名称。假设您已经在 Cobbler 中输入了两个地址的主机，您的输出应该看起来像这样：

```
$  ansible -i cobbler.py webservers -m ping
frontend01.example.com | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python"
    },
    "changed": false,
    "ping": "pong"
}
frontend02.example.com | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python"
    },
    "changed": false,
    "ping": "pong"
} 
```

就是这样！您刚刚在 Ansible 中实现了您的第一个动态清单。当然，我们知道许多读者不会使用 Cobbler，一些其他动态清单插件更复杂。例如，Amazon EC2 动态清单脚本需要您的 Amazon Web Services 的身份验证详细信息（或适当的 IAM 帐户）以及 Python `boto`和`boto3`库的安装。您怎么知道要做所有这些？幸运的是，所有这些都在动态清单脚本或配置文件的头部有记录，所以我能给出的最基本的建议是：每当您下载新的动态清单脚本时，请务必在您喜欢的编辑器中查看文件本身，因为它们的要求很可能已经为您记录了。

在本书的这一节结束之前，让我们看一下使用多个清单来源的其他一些方便提示，从下一节开始。

# 在清单目录中使用多个清单来源

到目前为止，在本书中，我们一直在使用我们的 Ansible 命令中的`-i`开关来指定我们的清单文件（静态或动态）。可能不明显的是，您可以多次指定`-i`开关，因此同时使用多个清单。这使您能够执行跨静态和动态清单的主机的任务，例如运行一个 playbook（或临时命令）。Ansible 将会计算出需要做什么——静态清单不应标记为可执行，因此不会被处理为这样，而动态清单将会被处理。这个小巧但聪明的技巧使您能够轻松地结合多个清单来源。让我们在下一节中继续看一下静态清单组与动态清单组的使用，这是多清单功能的扩展。

# 在动态组中使用静态组

当然，混合清单的可能性带来了一个有趣的问题——如果您同时定义动态清单和静态清单中的组，会发生什么？答案是 Ansible 会将两者结合起来，这带来了一个有趣的可能性。正如您所看到的，我们的 Cobbler 清单脚本从我们称为`webservers`的 Cobbler 配置文件中产生了一个名为`webservers`的 Ansible 组。这对于大多数动态清单提供者来说很常见；大多数清单来源（例如 Cobbler 和 Amazon EC2）都不是 Ansible 感知的，因此不提供 Ansible 可以直接使用的组。因此，大多数动态清单脚本将使用清单来源的某些信息来产生分组，Cobbler 机器配置文件就是一个例子。

让我们通过混合静态清单来扩展前一节中的 Cobbler 示例。假设我们想要将我们的`webservers`机器作为名为`centos`的组的子组，以便我们将来可以将所有 CentOS 机器分组在一起。我们知道我们只有一个名为`webservers`的 Cobbler 配置文件，理想情况下，我们不想开始干扰 Cobbler 设置，只是为了做一些与 Ansible 相关的事情。

解决这个问题的方法是创建一个具有两个组定义的静态清单文件。第一个必须与您从动态清单中期望的组的名称相同，只是您应该将其留空。当 Ansible 组合静态和动态清单内容时，它将重叠这两个组，因此将 Cobbler 的主机添加到这些`webservers`组中。

第二个组定义应该说明`webservers`是`centos`组的子组。生成的文件应该看起来像这样：

```
[webservers]

[centos:children]
webservers
```

现在让我们在 Ansible 中运行一个简单的临时`ping`命令，以查看它如何评估两个清单。请注意，我们将指定`centos`组来运行`ping`，而不是`webservers`组。我们知道 Cobbler 没有`centos`组，因为我们从未创建过，我们知道当您组合两个清单时，此组中的任何主机必须通过`webservers`组来，因为我们的静态清单中没有主机。结果将看起来像这样：

```
$ ansible -i static-groups-mix-ini -i cobbler.py centos -m ping
frontend01.example.com | SUCCESS => {
 "ansible_facts": {
 "discovered_interpreter_python": "/usr/bin/python"
 },
 "changed": false,
 "ping": "pong"
}
frontend02.example.com | SUCCESS => {
 "ansible_facts": {
 "discovered_interpreter_python": "/usr/bin/python"
 },
 "changed": false,
 "ping": "pong"
}
```

从前面的输出中可以看出，我们引用了两个不同的清单，一个是静态的，另一个是动态的。我们已经组合了组，将仅存在于一个清单源中的主机与仅存在于另一个清单源中的组合在一起。正如您所看到的，这是一个非常简单的例子，很容易将其扩展为组合静态和动态主机的列表，或者向来自动态清单的主机添加自定义变量。

这是 Ansible 的一个鲜为人知的技巧，但在清单扩展和增长时可以非常强大。当我们通过本章工作时，您会注意到我们非常精确地指定了我们的清单主机，要么是单独的，要么是通过组；例如，我们明确告诉`ansible`对`webservers`组中的所有主机运行临时命令。在下一节中，我们将继续探讨 Ansible 如何管理使用模式指定的一组主机。

# 使用模式进行特殊主机管理

我们已经确定，您经常会想要针对清单的一个子部分运行一个临时命令或一个 playbook。到目前为止，我们一直在做得很精确，但现在让我们通过查看 Ansible 如何使用模式来确定应该针对哪些主机运行命令（或 playbook）来扩展这一点。

作为起点，让我们再次考虑本章早些时候定义的清单，以便探索主机组和子组。为了方便起见，清单内容再次提供如下：

```
loadbalancer.example.com

[frontends]
frt01.example.com
frt02.example.com

[apps]
app01.example.com
app02.example.com

[databases]
dbms01.example.com
dbms02.example.com

[centos:children]
apps
databases

[ubuntu:children]
frontends
```

为了演示通过模式进行主机/组选择，我们将使用`ansible`命令的`--list-hosts`开关来查看 Ansible 将对哪些主机进行操作。您可以扩展示例以使用`ping`模块，但出于空间和输出简洁可读的考虑，我们将在这里使用`--list-hosts`：

1.  我们已经提到了特殊的`all`组来指定清单中的所有主机：

```
$ ansible -i hostgroups-children-ini all --list-hosts
 hosts (7):
 loadbalancer.example.com
 frt01.example.com
 frt02.example.com
 app01.example.com
 app02.example.com
 dbms01.example.com
 dbms02.example.com
```

星号字符具有与`all`相同的效果，但需要在 shell 中用单引号引起来，以便 shell 正确解释命令：

```
$ ansible -i hostgroups-children-ini '*' --list-hosts
 hosts (7):
 loadbalancer.example.com
 frt01.example.com
 frt02.example.com
 app01.example.com
 app02.example.com
 dbms01.example.com
 dbms02.example.com
```

1.  使用`:`来指定逻辑`OR`，意思是“应用于这个组或那个组中的主机”，就像这个例子中一样：

```
$ ansible -i hostgroups-children-ini frontends:apps --list-hosts
 hosts (4):
 frt01.example.com
 frt02.example.com
 app01.example.com
 app02.example.com
```

1.  使用`!`来排除特定组——您可以将其与其他字符（例如`:`）结合使用，以显示（例如）除`apps`组中的所有主机之外的所有主机。同样，`!`是 shell 中的特殊字符，因此您必须在单引号中引用模式字符串，以使其正常工作，就像这个例子中一样：

```
$ ansible -i hostgroups-children-ini 'all:!apps' --list-hosts
 hosts (5):
 loadbalancer.example.com
 frt01.example.com
 frt02.example.com
 dbms01.example.com
 dbms02.example.com
```

1.  使用`:&`来指定两个组之间的逻辑`AND`，例如，如果我们想要在`centos`组和`apps`组中的所有主机（再次，您必须在 shell 中使用单引号）：

```
$ ansible -i hostgroups-children-ini 'centos:&apps' --list-hosts
  hosts (2):
    app01.example.com
    app02.example.com
```

1.  使用`*`通配符的方式与在 shell 中使用的方式类似，就像这个例子中一样：

```
$ ansible -i hostgroups-children-ini 'db*.example.com' --list-hosts
 hosts (2):
 dbms02.example.com
 dbms01.example.com
```

另一种限制命令运行的主机的方法是使用 Ansible 的`--limit`开关。这与前面的语法和模式表示完全相同，但它的优势在于您可以在`ansible-playbook`命令中使用它，而在命令行上指定主机模式仅支持`ansible`命令本身。因此，例如，您可以运行以下命令：

```
$ ansible-playbook -i hostgroups-children-ini site.yml --limit frontends:apps

PLAY [A simple playbook for demonstrating inventory patterns] ******************

TASK [Gathering Facts] *********************************************************
ok: [frt02.example.com]
ok: [app01.example.com]
ok: [frt01.example.com]
ok: [app02.example.com]

TASK [Ping each host] **********************************************************
ok: [app01.example.com]
ok: [app02.example.com]
ok: [frt02.example.com]
ok: [frt01.example.com]

PLAY RECAP *********************************************************************
app01.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
app02.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt01.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

模式是处理清单的非常有用和重要的部分，您无疑会发现它们非常有价值。这结束了我们关于 Ansible 清单的章节；但是，希望这为您提供了一切您需要自信地使用 Ansible 清单。

# 摘要

创建和管理 Ansible 清单是您使用 Ansible 的工作的重要部分，因此我们在本书的早期阶段就介绍了这个基本概念。它们至关重要，因为没有它们，Ansible 将不知道要针对哪些主机运行自动化任务，但它们提供的远不止这些。它们为配置管理系统提供了一个集成点，它们为存储主机特定（或组特定）变量提供了一个明智的来源，并且它们为您提供了运行此 playbook 的灵活方式。

在本章中，您学习了如何创建简单的静态清单文件并向其中添加主机。然后，我们通过学习如何添加主机组并为主机分配变量来扩展了这一点。我们还研究了在单个平面清单文件变得太难处理时如何组织您的清单和变量。然后，我们学习了如何利用动态清单文件，最后通过查看有用的技巧和诀窍，如组合清单来源和使用模式来指定主机，使您处理清单更加容易，同时更加强大。

在下一章中，我们将学习如何开发 playbooks 和 roles 来使用 Ansible 配置，部署和管理远程机器。

# 问题

1.  如何将`frontends`组变量添加到您的清单中？

A) `[frontends::]`

B) `[frontends::values]`

C) `[frontends:host:vars]`

D) `[frontends::variables]`

E) `[frontends:vars]`

1.  什么使您能够自动执行 Linux 任务，如提供 DNS，管理 DHCP，更新软件包和配置管理？

A) 播放书

B) Yum

C) 修鞋匠

D) Bash

E) 角色

1.  Ansible 允许您使用命令行上的`-i`选项来指定清单文件位置。

A) 真

B) 错误

# 进一步阅读

+   Ansible 的所有常见动态清单都在 GitHub 存储库中：[`github.com/ansible/ansible/tree/devel/contrib/inventory`](https://github.com/ansible/ansible/tree/devel/contrib/inventory)。


# 第四章：playbook 和角色

到目前为止，在这本书中，我们主要使用临时的 Ansible 命令来简化操作，并帮助您理解基本原理。然而，Ansible 的生命线无疑是 playbook，它是任务的逻辑组织（类似于临时命令），以创建有用的结果的结构。这可能是在新建的虚拟机上部署 Web 服务器，也可能是应用安全策略。甚至可能处理虚拟机的整个构建过程！可能性是无限的。正如我们已经介绍过的，Ansible playbook 的设计是简单易写、易读——它们旨在自我记录，因此将成为您 IT 流程中宝贵的一部分。

在本章中，我们将更深入地探讨 playbook，从创建的基础知识到更高级的概念，如循环和块中运行任务、执行条件逻辑，以及 playbook 组织和代码重用中可能最重要的概念之一——Ansible 角色。我们将稍后更详细地介绍角色，但请知道，这是您在创建可管理的 playbook 代码时希望尽可能使用的内容。

具体来说，在本章中，我们将涵盖以下主题：

+   理解 playbook 框架

+   理解角色——playbook 的组织者

+   在代码中使用条件

+   使用循环重复任务

+   使用块分组任务

+   通过策略配置 play 执行

+   使用`ansible-pull`

# 技术要求

本章假设您已经按照第一章中详细介绍的方式在控制主机上安装了 Ansible，并且正在使用最新版本——本章中的示例是使用 Ansible 2.9 进行测试的。本章还假设您至少有一个额外的主机进行测试，并且最好是基于 Linux 的。尽管本章中将给出主机名的具体示例，但您可以自由地用自己的主机名和/或 IP 地址替换它们，如何做到这一点的详细信息将在适当的地方提供。

本章的代码包在此处可用：[`github.com/PacktPublishing/Ansible-2-Cookbook/tree/master/Chapter%204`](https://github.com/PacktPublishing/Ansible-2-Cookbook/tree/master/Chapter%204)。

# 理解 playbook 框架

playbook 允许您简单轻松地管理多台机器上的多个配置和复杂部署。这是使用 Ansible 交付复杂应用程序的关键优势之一。通过 playbook，您可以将任务组织成逻辑结构，因为任务通常按照编写的顺序执行，这使您能够对自动化过程有很好的控制。话虽如此，也可以异步执行任务，因此我们将强调任务不按顺序执行的情况。我们的目标是，一旦您完成本章，您将了解编写自己的 Ansible playbook 的最佳实践。

尽管 YAML 格式易于阅读和编写，但在间距方面非常严谨。例如，您不能使用制表符来设置缩进，即使在屏幕上，制表符和四个空格看起来可能相同——在 YAML 中，它们并不相同。如果您是第一次编写 playbook，我们建议您采用支持 YAML 的编辑器，例如 Vim、Visual Studio Code 或 Eclipse，这些编辑器将帮助您确保缩进正确。为了测试本章中开发的 playbook，我们将重复使用第三章中创建的清单的变体，*定义您的清单*（除非另有说明）：

```
[frontends]
frt01.example.com https_port=8443
frt02.example.com http_proxy=proxy.example.com

[frontends:vars]
ntp_server=ntp.frt.example.com
proxy=proxy.frt.example.com

[apps]
app01.example.com
app02.example.com

[webapp:children]
frontends
apps

[webapp:vars]
proxy_server=proxy.webapp.example.com
health_check_retry=3
health_check_interal=60
```

让我们立即开始编写一个 playbook。在第二章的*理解 Ansible 基础*中的*分解 Ansible 组件*一节中，我们涵盖了 playbook 的一些基本方面，因此我们不会在这里详细重复，而是在此基础上展示 playbook 开发的内容：

1.  创建一个简单的 playbook，在我们的清单文件中定义的`frontends`主机组中运行。我们可以在 playbook 中使用`remote_user`指令设置访问主机的用户，如下所示（您也可以在命令行上使用`--user`开关，但由于本章是关于 playbook 开发的，我们暂时忽略它）：

```
---
- hosts: frontends
  remote_user: danieloh

  tasks:
  - name: simple connection test
    ping:
    remote_user: danieloh
```

1.  在第一个任务下面添加另一个任务来运行`shell`模块（这将依次在远程主机上运行`ls`命令）。我们还将在这个任务中添加`ignore_errors`指令，以确保如果`ls`命令失败（例如，如果我们尝试列出的目录不存在），我们的 playbook 不会失败。小心缩进，并确保它与文件的第一部分匹配：

```
  - name: run a simple command
    shell: /bin/ls -al /nonexistent
    ignore_errors: True
```

让我们看看当我们运行时，我们新创建的 playbook 的行为如何：

```
$ ansible-playbook -i hosts myplaybook.yaml

PLAY [frontends] ***************************************************************

TASK [Gathering Facts] *********************************************************
ok: [frt02.example.com]
ok: [frt01.example.com]

TASK [simple connection test] **************************************************
ok: [frt01.example.com]
ok: [frt02.example.com]

TASK [run a simple command] ****************************************************
fatal: [frt02.example.com]: FAILED! => {"changed": true, "cmd": "/bin/ls -al /nonexistent", "delta": "0:00:00.015687", "end": "2020-04-10 16:37:56.895520", "msg": "non-zero return code", "rc": 2, "start": "2020-04-10 16:37:56.879833", "stderr": "/bin/ls: cannot access /nonexistent: No such file or directory", "stderr_lines": ["/bin/ls: cannot access /nonexistent: No such file or directory"], "stdout": "", "stdout_lines": []}
...ignoring
fatal: [frt01.example.com]: FAILED! => {"changed": true, "cmd": "/bin/ls -al /nonexistent", "delta": "0:00:00.012160", "end": "2020-04-10 16:37:56.930058", "msg": "non-zero return code", "rc": 2, "start": "2020-04-10 16:37:56.917898", "stderr": "/bin/ls: cannot access /nonexistent: No such file or directory", "stderr_lines": ["/bin/ls: cannot access /nonexistent: No such file or directory"], "stdout": "", "stdout_lines": []}
...ignoring

PLAY RECAP *********************************************************************
frt01.example.com : ok=3 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=1
frt02.example.com : ok=3 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=1 
```

从 playbook 运行的输出中，您可以看到我们的两个任务是按照指定的顺序执行的。我们可以看到`ls`命令失败，因为我们尝试列出一个不存在的目录，但是 playbook 没有注册任何`failed`任务，因为我们为这个任务设置了`ignore_errors`为`true`（仅针对这个任务）。

大多数 Ansible 模块（除了运行用户定义命令的模块，如`shell`、`command`和`raw`）都被编码为幂等的，也就是说，如果您运行相同的任务两次，结果将是相同的，并且任务不会进行相同的更改两次 - 如果检测到被请求执行的操作已经完成，那么它不会再次执行。当然，对于前述模块来说这是不可能的，因为它们可以用于执行几乎任何可以想象的任务 - 因此，模块如何知道它被执行了两次呢？

每个模块都会返回一组结果，其中包括任务状态。您可以在前面 playbook 运行输出的底部看到这些总结，它们的含义如下：

+   `ok`：任务成功运行，没有进行任何更改。

+   `changed`：任务成功运行，并进行了更改。

+   `failed`：任务运行失败。

+   `unreachable`：无法访问主机以运行任务。

+   `skipped`：此任务被跳过。

+   `ignored`：此任务被忽略（例如，在`ignore_errors`的情况下）。

+   `rescued`：稍后我们将在查看块和救援任务时看到一个例子。

这些状态可能非常有用，例如，如果我们有一个任务从模板部署新的 Apache 配置文件，我们知道必须重新启动 Apache 服务才能应用更改。但是，我们只想在文件实际更改时才这样做 - 如果没有进行任何更改，我们不希望不必要地重新启动 Apache，因为这会打断可能正在使用服务的人。因此，我们可以使用`notify`操作，告诉 Ansible 在任务结果为`changed`时（仅在此时）调用一个`handler`。简而言之，处理程序是一种特殊类型的任务，作为`notify`的结果而运行。但是，与按顺序执行的 Ansible playbook 任务不同，处理程序都被分组在一起，并在 play 的最后运行。此外，它们可以被通知多次，但无论如何只会运行一次，再次防止不必要的服务重启。考虑以下 playbook：

```
---
- name: Handler demo 1
  hosts: frt01.example.com
  gather_facts: no
  become: yes

  tasks:
    - name: Update Apache configuration
      template:
        src: template.j2
        dest: /etc/httpd/httpd.conf
      notify: Restart Apache

  handlers:
    - name: Restart Apache
      service:
        name: httpd
        state: restarted
```

为了保持输出简洁，我已经关闭了这个 playbook 的事实收集（我们不会在任何任务中使用它们）。出于简洁起见，我再次只在一个主机上运行，但您可以根据需要扩展演示代码。如果我们第一次运行这个任务，我们将看到以下结果：

```
$ ansible-playbook -i hosts handlers1.yml

PLAY [Handler demo 1] **********************************************************

TASK [Update Apache configuration] *********************************************
changed: [frt01.example.com]

RUNNING HANDLER [Restart Apache] ***********************************************
changed: [frt01.example.com]

PLAY RECAP *********************************************************************
frt01.example.com : ok=2 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

请注意，当配置文件更新时，处理程序被运行。然而，如果我们再次运行这个 playbook，而没有对模板或配置文件进行任何更改，我们将看到类似以下的结果：

```
$ ansible-playbook -i hosts handlers1.yml

PLAY [Handler demo 1] **********************************************************

TASK [Update Apache configuration] *********************************************
ok: [frt01.example.com]

PLAY RECAP *********************************************************************
frt01.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

这一次，由于配置任务的结果是 OK，处理程序没有被调用。所有处理程序的名称应该是全局唯一的，这样通知操作才能调用正确的处理程序。您还可以通过设置一个公共名称来调用多个处理程序，使用`listen`指令——这样，您可以调用`name`或`listen`字符串中的任何一个处理程序，就像下面的示例中演示的那样：

```
---
- name: Handler demo 1
  hosts: frt01.example.com
  gather_facts: no
  become: yes

  handlers:
    - name: restart chronyd
      service:
        name: chronyd
        state: restarted
      listen: "restart all services"
    - name: restart apache
      service:
        name: httpd
        state: restarted
      listen: "restart all services"

  tasks:
    - name: restart all services
      command: echo "this task will restart all services"
      notify: "restart all services"
```

我们的 playbook 中只有一个任务，但当我们运行它时，两个处理程序都会被调用。另外，请记住我们之前说过的，`command`是一组特殊情况下的模块之一，因为它们无法检测到是否发生了更改——因此，它们总是返回`changed`值，因此，在这个演示 playbook 中，处理程序将始终被通知：

```
$ ansible-playbook -i hosts handlers2.yml

PLAY [Handler demo 1] **********************************************************

TASK [restart all services] ****************************************************
changed: [frt01.example.com]

RUNNING HANDLER [restart chronyd] **********************************************
changed: [frt01.example.com]

RUNNING HANDLER [restart apache] ***********************************************
changed: [frt01.example.com]

PLAY RECAP *********************************************************************
frt01.example.com : ok=3 changed=3 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

这些是您需要了解的一些基础知识，以开始编写自己的 playbooks。有了这些知识，让我们在下一节中比较临时命令和 playbooks。

# 比较 playbooks 和临时任务

临时命令允许您快速创建和执行一次性命令，而不保留任何已完成的记录（除了可能是您的 shell 历史）。这些命令具有重要的作用，并且在快速进行小改动和学习 Ansible 及其模块方面非常有价值。

相比之下，playbooks 是逻辑上组织的一系列任务（每个任务都可以是一个临时命令），按顺序组合在一起执行一个更大的动作。条件逻辑、错误处理等的添加意味着，很多时候，playbooks 的好处超过了临时命令的用处。此外，只要保持它们有组织，你将拥有你运行的所有以前的 playbooks 的副本，因此你将能够回顾（如果你需要的话）看看你运行了什么以及何时运行的。

让我们来开发一个实际的例子——假设你想在 CentOS 上安装 Apache 2.4。即使默认配置足够（这不太可能，但现在我们将保持例子简单），也涉及到一些步骤。如果你要手动执行基本安装，你需要安装软件包，打开防火墙，并确保服务正在运行（并且在启动时运行）。

要在 shell 中执行这些命令，您可能会这样做：

```
$ sudo yum install httpd
$ sudo firewall-cmd --add-service=http --permanent 
$ sudo firewall-cmd --add-service=https --permanent
$ sudo firewall-cmd --reload
$ sudo systemctl enable httpd.service
$ sudo systemctl restart httpd.service
```

现在，对于这些命令中的每一个，都有一个等效的临时 Ansible 命令可以运行。出于篇幅考虑，我们不会在这里逐个讨论它们；然而，假设你想要重新启动 Apache 服务——在这种情况下，你可以运行类似以下的临时命令（同样，为了简洁起见，我们只在一个主机上执行）：

```
$ ansible -i hosts frt01* -m service -a "name=httpd state=restarted"
```

当成功运行时，您将看到包含从以这种方式运行服务模块返回的所有变量数据的页面式 shell 输出。下面是一个片段供您检查您的结果——关键是命令导致`changed`状态，这意味着它成功运行，并且服务确实被重新启动了：

```
frt01.example.com | CHANGED => {
 "ansible_facts": {
 "discovered_interpreter_python": "/usr/bin/python"
 },
 "changed": true,
 "name": "httpd",
 "state": "started",
```

你可以创建并执行一系列临时命令来复制前面给出的六个 shell 命令，并分别运行它们。通过一些巧妙的方法，你应该可以将这个减少到六个命令（例如，Ansible 的`service`模块可以在一个临时命令中同时启用服务和重新启动它）。然而，你最终仍然会至少需要三到四个临时命令，如果你想在以后的另一台服务器上再次运行这些命令，你将需要参考你的笔记来弄清楚你是如何做的。

因此，playbook 是一种更有价值的方法来处理这个问题——它不仅会一次性执行所有步骤，而且还会为你记录下来以供以后参考。有多种方法可以做到这一点，但请将以下内容作为一个例子：

```
---
- name: Install Apache
  hosts: frt01.example.com
  gather_facts: no
  become: yes

  tasks:
    - name: Install Apache package
      yum:
        name: httpd
        state: latest
    - name: Open firewall for Apache
      firewalld:
        service: "{{ item }}"
        permanent: yes
        state: enabled
        immediate: yes
      loop:
        - "http"
        - "https"
    - name: Restart and enable the service
      service:
        name: httpd
        state: restarted
        enabled: yes
```

现在，当你运行这个时，你应该看到我们所有的安装要求都已经通过一个相当简单和易于阅读的 playbook 完成了。这里有一个新的概念，循环，我们还没有涉及，但不要担心，我们将在本章后面涉及到：

```
$ ansible-playbook -i hosts installapache.yml

PLAY [Install Apache] **********************************************************

TASK [Install Apache package] **************************************************
changed: [frt01.example.com]

TASK [Open firewall for Apache] ************************************************
changed: [frt01.example.com] => (item=http)
changed: [frt01.example.com] => (item=https)

TASK [Restart and enable the service] ******************************************
changed: [frt01.example.com]

PLAY RECAP *********************************************************************
frt01.example.com : ok=2 changed=3 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

正如你所看到的，这样做要比实际操作和记录在一个格式中更好，其他人可以很容易地理解。尽管我们将在书的后面讨论循环，但从前面的内容很容易看出它们是如何工作的。有了这个设置，让我们在下一节中更详细地看一下我们已经多次使用的一些术语，以确保你清楚它们的含义：**plays**和**tasks**。

# 定义 plays 和 tasks

到目前为止，当我们使用 playbook 时，我们一直在每个 playbook 中创建一个单一的 play（从逻辑上讲，这是你可以做的最少的）。然而，你可以在一个 playbook 中有多个 play，并且在 Ansible 术语中，“play”简单地是与主机（或主机组）相关联的一组任务（和角色、处理程序和其他 Ansible 方面）。任务是 play 的最小可能元素，负责使用一组参数运行单个模块以实现特定的目标。当然，在理论上，这听起来相当复杂，但在实际示例的支持下，它变得非常容易理解。

如果我们参考我们的示例清单，这描述了一个简单的两层架构（我们暂时忽略了数据库层）。现在，假设我们想编写一个单一的 playbook 来配置前端服务器和应用服务器。我们可以使用两个单独的 playbook 来配置前端和应用服务器，但这会使你的代码变得零散并且难以组织。然而，前端服务器和应用服务器（从它们的本质上）本质上是不同的，因此不太可能使用相同的任务集进行配置。

解决这个问题的方法是创建一个包含两个 play 的单一 playbook。每个 play 的开始可以通过最低缩进的行来识别（即在其前面没有空格）。让我们开始构建我们的 playbook：

1.  将第一个 play 添加到 playbook 中，并定义一些简单的任务来设置前端的 Apache 服务器，如下所示：

```
---
- name: Play 1 - configure the frontend servers
  hosts: frontends
  become: yes

  tasks:
  - name: Install the Apache package
    yum:
      name: httpd
      state: latest
  - name: Start the Apache server
    service:
      name: httpd
      state: started
```

1.  在同一个文件中，立即在下面添加第二个 play 来配置应用程序层服务器：

```
- name: Play 2 - configure the application servers
  hosts: apps
  become: true

  tasks:
  - name: Install Tomcat
    yum:
      name: tomcat
      state: latest
  - name: Start the Tomcat server
    service:
      name: tomcat
      state: started
```

现在，你有两个 plays：一个用于在`frontends`组中安装 web 服务器，另一个用于在`apps`组中安装应用服务器，全部合并成一个简单的 playbook。

当我们运行这个 playbook 时，我们将看到两个 play 按顺序执行，按照 playbook 中的顺序。请注意`PLAY`关键字的存在，它表示每个 play 的开始：

```
$ ansible-playbook -i hosts playandtask.yml

PLAY [Play 1 - configure the frontend servers] *********************************

TASK [Gathering Facts] *********************************************************
changed: [frt02.example.com]
changed: [frt01.example.com]

TASK [Install the Apache package] *********************************************
changed: [frt01.example.com]
changed: [frt02.example.com]

TASK [Start the Apache server] *************************************************
changed: [frt01.example.com]
changed: [frt02.example.com]

PLAY [Play 2 - configure the application servers] *******************************

TASK [Gathering Facts] *********************************************************
changed: [app01.example.com]
changed: [app02.example.com]

TASK [Install Tomcat] **********************************************************
changed: [app02.example.com]
changed: [app01.example.com]

TASK [Start the Tomcat server] *************************************************
changed: [app02.example.com]
changed: [app01.example.com]

PLAY RECAP *********************************************************************
app01.example.com : ok=3 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
app02.example.com : ok=3 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt01.example.com : ok=3 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=3 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

我们有一个 playbook，但是有两个不同的 play 在提供的清单中操作不同的主机集。这非常强大，特别是与角色结合使用时（这将在本书的后面部分介绍）。当然，您的 playbook 中可以只有一个 play——您不必有多个 play，但是能够开发多 play playbook 非常重要，因为随着环境变得更加复杂，您几乎肯定会发现它们非常有用。

Playbooks 是 Ansible 自动化的生命线——它们将其扩展到不仅仅是单个任务/命令（它们本身就非常强大），而是一系列以逻辑方式组织的任务。然而，随着您扩展 playbook 库，您如何保持工作的组织？如何有效地重用相同的代码块？在前面的示例中，我们安装了 Apache，这可能是您的许多服务器的要求。但是，您应该尝试从一个 playbook 管理它们所有吗？或者您应该一遍又一遍地复制和粘贴相同的代码块？有一个更好的方法，在 Ansible 术语中，我们需要开始看角色，我们将在下一节中进行介绍。

# 理解角色——playbook 组织者

角色旨在使您能够高效有效地重用 Ansible 代码。它们始终遵循已知的结构，并且通常会包含变量、错误处理、处理程序等的合理默认值。以前一章中的 Apache 安装示例为例，我们知道这是我们可能想一遍又一遍地做的事情，也许每次都使用不同的配置文件，也许每台服务器（或每个清单组）都需要进行一些其他调整。在 Ansible 中，支持以这种方式重用代码的最有效方法是将其创建为一个角色。

创建角色的过程实际上非常简单——Ansible（默认情况下）将在您运行 playbook 的同一目录中寻找`roles/`目录，在这里，您将为每个角色创建一个子目录。角色名称源自子目录名称——无需创建复杂的元数据或其他任何东西——就是这么简单。在每个子目录中，都有一个固定的目录结构，告诉 Ansible 每个角色的任务、默认变量、处理程序等是什么。

`roles/`目录并不是 Ansible 寻找角色的唯一目录——这是它首先查找的目录，但然后它会在`/etc/ansible/roles`中查找任何额外的角色。这可以通过 Ansible 配置文件进一步定制，如第二章中所讨论的那样，*理解 Ansible 的基本原理*。

让我们更详细地探讨一下。考虑以下目录结构：

```
site.yml
frontends.yml
dbservers.yml
roles/
   installapache/
     tasks/
     handlers/
     templates/
     vars/
     defaults/
   installtomcat/
     tasks/
     meta/
```

前面的目录结构显示了在我们假设的 playbook 目录中定义的两个角色，名为`installapache`和`installtomcat`。在这些目录中，您会注意到一系列子目录。这些子目录不需要存在（稍后会详细说明它们的含义，但例如，如果您的角色没有处理程序，则无需创建`handlers/`）。但是，如果您确实需要这样的目录，您应该用名为`main.yml`的 YAML 文件填充它。每个`main.yml`文件都应该有特定的内容，具体取决于包含它们的目录。

角色中可以存在的子目录如下：

+   `tasks`：这是在角色中找到的最常见的目录，它包含角色应执行的所有 Ansible 任务。

+   `handlers`：角色中使用的所有处理程序都应该放在这个目录中。

+   `defaults`：角色的所有默认变量都放在这里。

+   `vars`：这些是其他角色变量——它们会覆盖`defaults/`目录中声明的变量，因为它们在优先顺序中更高。

+   `files`：角色需要的文件应该放在这里 - 例如，需要部署到目标主机的任何配置文件。

+   `templates`：与`files/`目录不同，这个目录应该包含角色使用的所有模板。

+   `meta`：角色所需的任何元数据都放在这里。例如，角色通常按照从父 playbook 调用它们的顺序执行 - 但是，有时角色会有需要先运行的依赖角色，如果是这种情况，它们可以在这个目录中声明。

对于我们在本章的这一部分中将开发的示例，我们将需要一个清单，所以让我们重用我们在上一节中使用的清单（以下是为了方便包含的）：

```
[frontends]
frt01.example.com https_port=8443
frt02.example.com http_proxy=proxy.example.com

[frontends:vars]
ntp_server=ntp.frt.example.com
proxy=proxy.frt.example.com

[apps]
app01.example.com
app02.example.com

[webapp:children]
frontends
apps

[webapp:vars]
proxy_server=proxy.webapp.example.com
health_check_retry=3
health_check_interal=60
```

让我们开始一些实际的练习，帮助你学习如何创建和使用角色。我们将首先创建一个名为`installapache`的角色，该角色将处理我们在上一节中看到的 Apache 安装过程。但是，在这里，我们将扩展它以涵盖在 CentOS 和 Ubuntu 上安装 Apache。这是一个很好的实践，特别是如果您希望将您的角色提交回社区，因为它们越通用（以及能够在更广泛的系统上运行），对人们就越有用。按照以下过程创建您的第一个角色：

1.  从您选择的 playbook 目录中创建`installapache`角色的目录结构 - 这就是这么简单：

```
$ mkdir -p roles/installapache/tasks
```

1.  现在，让我们在我们刚刚创建的`tasks`目录中创建一个必需的`main.yml`。这实际上不会执行 Apache 安装 - 而是在事实收集阶段检测到目标主机的操作系统后，将调用两个外部任务文件中的一个。我们可以使用这个特殊的变量`ansible_distribution`在`when`条件中确定要导入哪个任务文件：

```
---
- name: import a tasks based on OS platform 
 import_tasks: centos.yml 
  when: ansible_distribution == 'CentOS' 
- import_tasks: ubuntu.yml 
  when: ansible_distribution == 'Ubuntu'
```

1.  在`roles/installapache/tasks`中创建一个名为`centos.yml`的文件，以通过`yum`软件包管理器安装 Apache Web 服务器的最新版本。这应该包含以下内容：

```
---
- name: Install Apache using yum
 yum:
    name: "httpd"
    state: latest
- name: Start the Apache server
  service:
    name: httpd
    state: started 
```

1.  在`roles/installapache/tasks`中创建一个名为`ubuntu.yml`的文件，以通过`apt`软件包管理器在 Ubuntu 上安装 Apache Web 服务器的最新版本。注意在 CentOS 和 Ubuntu 主机之间内容的不同：

```
---
- name: Install Apache using apt
 apt:
    name: "apache2"
    state: latest
- name: Start the Apache server
  service:
    name: apache2
    state: started
```

目前，我们的角色代码非常简单 - 但是，您可以看到前面的任务文件就像一个 Ansible playbook，只是它们缺少了 play 定义。由于它们不属于一个 play，所以它们的缩进级别也比 playbook 中的低，但是除了这个差异，代码应该对您来说非常熟悉。事实上，这就是角色的美妙之处之一：只要您注意正确的缩进级别，您几乎可以在 playbook 或角色中使用相同的代码。

现在，角色不能自行运行 - 我们必须创建一个 playbook 来调用它们，所以让我们编写一个简单的 playbook 来调用我们新创建的角色。这与我们之前看到的一样有一个 play 定义，但是不是在 play 中有一个`tasks:`部分，而是有一个`roles:`部分，在那里声明了角色。惯例规定这个文件被称为`site.yml`，但您可以自由地称它为任何您喜欢的名字：

```
---
- name: Install Apache using a role
  hosts: frontends
  become: true

  roles:
    - installapache
```

为了清晰起见，您的最终目录结构应该如下所示：

```
.
├── roles
│   └── installapache
│   └── tasks
│   ├── centos.yml
│   ├── main.yml
│   └── ubuntu.yml
└── site.yml
```

完成后，您现在可以以正常方式使用`ansible-playbook`运行您的`site.yml` playbook - 您应该会看到类似于这样的输出：

```
$ ansible-playbook -i hosts site.yml

PLAY [Install Apache using a role] *********************************************

TASK [Gathering Facts] *********************************************************
ok: [frt01.example.com]
ok: [frt02.example.com]

TASK [installapache : Install Apache using yum] ********************************
changed: [frt02.example.com]
changed: [frt01.example.com]

TASK [installapache : Start the Apache server] *********************************
changed: [frt01.example.com]
changed: [frt02.example.com]

TASK [installapache : Install Apache using apt] ********************************
skipping: [frt01.example.com]
skipping: [frt02.example.com]

TASK [installapache : Start the Apache server] *********************************
skipping: [frt01.example.com]
skipping: [frt02.example.com]

PLAY RECAP *********************************************************************
frt01.example.com : ok=3 changed=2 unreachable=0 failed=0 skipped=2 rescued=0 ignored=0
frt02.example.com : ok=3 changed=2 unreachable=0 failed=0 skipped=2 rescued=0 ignored=0
```

就是这样 - 您已经在最简单的级别上创建了您的第一个角色。当然（正如我们之前讨论的那样），角色不仅仅是我们在这里添加的简单任务，还有更多内容，当我们在本章中进行工作时，我们将看到扩展的示例。然而，前面的示例旨在向您展示如何快速轻松地开始使用角色。

在我们看一些与角色相关的其他方面之前，让我们看一些调用角色的其他方法。当您编写 playbook 时，Ansible 允许您静态导入或动态包含角色。这两种导入或包含角色的语法略有不同，值得注意的是，两者都在 playbook 的任务部分而不是角色部分。以下是一个假设的示例，展示了一个非常简单的 playbook 中的两种选项。包括`common`和`approle`角色的角色目录结构将以与前面示例类似的方式创建：

```
--- 
- name: Play to import and include a role
 hosts: frontends

 tasks:
  - import_role:
      name: common
  - include_role:
      name: approle
```

这些功能在 2.3 之前的 Ansible 版本中是不可用的，并且它们在 2.4 版本中的使用方式略有改变，以保持与其他一些 Ansible 功能的一致性。我们不会在这里担心这些细节，因为现在 Ansible 的版本是 2.9，所以除非您绝对必须运行早期版本的 Ansible，否则可以假定这两个语句的工作方式如我们将在接下来的内容中概述的那样。

基本上，`import_role`语句在解析所有 playbook 代码时执行您指定的角色的静态导入。因此，使用`import_role`语句将角色引入您的 playbook 时，Ansible 在开始解析时将其视为 play 或角色中的任何其他代码一样。使用`import_role`基本上与在`site.yml`中的`roles:`语句之后声明您的角色一样，就像我们在前面的示例中所做的那样。

`include_role`在某种程度上与`import_role`有根本的不同，因为您指定的角色在解析 playbook 时不会被评估，而是在 playbook 运行期间动态处理，在遇到`include_role`时进行处理。

在选择前面提到的`include`或`import`语句之间最基本的原因可能是循环——如果您需要在循环内运行一个角色，您不能使用`import_role`，因此必须使用`include_role`。然而，两者都有好处和局限性，您需要根据您的情况选择最合适的方法——官方的 Ansible 文档（[`docs.ansible.com/ansible/latest/user_guide/playbooks_reuse.html#dynamic-vs-static`](https://docs.ansible.com/ansible/latest/user_guide/playbooks_reuse.html#dynamic-vs-static)）将帮助您做出正确的决定。

正如我们在本节中所看到的，角色非常简单易用，但却提供了一种非常强大的方式来组织和重用您的 Ansible 代码。在下一节中，我们将通过查看如何将角色特定的变量和依赖项添加到您的代码中来扩展我们简单的基于任务的示例。

# 设置基于角色的变量和依赖关系

变量是使 Ansible playbook 和角色可重用的核心，因为它们允许相同的代码以略有不同的值或配置数据重新利用。Ansible 角色目录结构允许在两个位置声明特定于角色的变量。虽然乍一看，这两个位置之间的区别可能并不明显，但它具有根本重要性。

基于角色的变量可以放在两个位置之一：

+   `defaults/main.yml`

+   `vars/main.yml`

这两个位置之间的区别在于它们在 Ansible 变量优先顺序中的位置。放在`defaults/`目录中的变量在优先级方面较低，因此很容易被覆盖。这个位置是你想要轻松覆盖的变量的位置，但你不想让变量未定义。例如，如果你要安装 Apache Tomcat，你可能会构建一个安装特定版本的角色。然而，如果有人忘记设置版本，你不希望角色因此退出错误，而是更愿意设置一个合理的默认值，比如`7.0.76`，然后可以用清单变量或命令行（使用`-e`或`--extra-vars`开关）轻松覆盖它。这样，即使没有人明确设置这个变量，你也知道角色可以正常工作，但如果需要，它可以很容易地更改为更新的 Tomcat 版本。

然而，放在`vars/`目录中的变量在 Ansible 的变量优先顺序中更靠前。这不会被清单变量覆盖，因此应该用于更重要的保持静态的变量数据。当然，这并不是说它们不能被覆盖——`-e`或`--extra-vars`开关是 Ansible 中优先级最高的，因此会覆盖你定义的任何其他内容。

大多数情况下，你可能只会使用基于`defaults/`的变量，但无疑会有时候，拥有更高优先级变量的选项对你的自动化变得更有价值，因此知道这个选项对你是可用的是至关重要的。

除了之前描述的基于角色的变量之外，还可以使用`meta/`目录为角色添加元数据。与之前一样，只需在这个目录中添加一个名为`main.yml`的文件即可。为了解释如何使用`meta/`目录，让我们构建并运行一个实际的例子，展示它如何被使用。在开始之前，重要的是要注意，默认情况下，Ansible 解析器只允许你运行一个角色一次。这在某种程度上类似于我们之前讨论的处理程序，可以被多次调用，但最终只在 play 结束时运行一次。角色也是一样的，它们可以被多次引用，但实际上只会运行一次。有两个例外情况——第一个是如果角色被多次调用，但使用了不同的变量或参数，另一个是如果被调用的角色在其`meta/`目录中将`allow_duplicates`设置为`true`。在构建示例时，我们将看到这两种情况的例子：

1.  在我们实际的例子的顶层，我们将有一个与本章节中一直在使用的清单相同的副本。我们还将创建一个名为`site.yml`的简单 playbook，其中包含以下代码：

```
---
- name: Role variables and meta playbook
  hosts: frt01.example.com

  roles:
    - platform
```

请注意，我们只是从这个 playbook 中调用了一个名为`platform`的角色，playbook 本身没有调用其他内容。

1.  让我们继续创建`platform`角色——与我们之前的角色不同，这个角色不包含任何任务，甚至不包含任何变量数据；相反，它只包含一个`meta`目录。

```
$ mkdir -p roles/platform/meta
```

在这个目录中，创建一个名为`main.yml`的文件，内容如下：

```
---
dependencies:
- role: linuxtype
  vars:
    type: centos
- role: linuxtype
  vars:
    type: ubuntu
```

这段代码将告诉 Ansible 平台角色依赖于`linuxtype`角色。请注意，我们指定了依赖两次，但每次指定时，我们都传递了一个名为`type`的变量，并赋予不同的值。这样，Ansible 解析器允许我们调用角色两次，因为每次作为依赖项引用时都传递了不同的变量值。

1.  现在让我们继续创建`linuxtype`角色，这将不包含任何任务，但会有更多的依赖声明：

```
$ mkdir -p roles/linuxtype/meta/
```

再次在`meta`目录中创建一个`main.yml`文件，但这次包含以下内容：

```
---
dependencies:
- role: version
- role: network
```

再次创建更多的依赖关系——这次，当调用`linuxtype`角色时，它反过来声明对称为`version`和`network`的角色的依赖。

1.  首先创建`version`角色——它将包含`meta`和`tasks`目录：

```
$ mkdir -p roles/version/meta
$ mkdir -p roles/version/tasks
```

在`meta`目录中，我们将创建一个包含以下内容的`main.yml`文件：

```
---
allow_duplicates: true
```

这个声明在这个例子中很重要——正如前面讨论的，通常情况下，Ansible 只允许一个角色被执行一次，即使它被多次调用。将`allow_duplicates`设置为`true`告诉 Ansible 允许角色被执行多次。这是必需的，因为在`platform`角色中，我们通过依赖两次调用了`linuxtype`角色，这意味着我们将两次调用`version`角色。

我们还将在任务目录中创建一个简单的`main.yml`文件，打印传递给角色的`type`变量的值：

```
---
- name: Print type variable
  debug:
    var: type
```

1.  现在我们将使用`network`角色重复这个过程——为了保持我们的示例代码简单，我们将使用与`version`角色相同的内容定义它：

```
$ mkdir -p roles/network/meta
$ mkdir -p roles/network/tasks
```

在`meta`目录中，我们将再次创建一个`main.yml`文件，其中包含以下内容：

```
---
allow_duplicates: true
```

再次在`tasks`目录中创建一个简单的`main.yml`文件，打印传递给角色的`type`变量的值：

```
---
- name: Print type variable
  debug:
    var: type
```

在这个过程结束时，你的目录结构应该是这样的：

```
.
├── hosts
├── roles
│   ├── linuxtype
│   │   └── meta
│   │       └── main.yml
│   ├── network
│   │   ├── meta
│   │   │   └── main.yml
│   │   └── tasks
│   │       └── main.yml
│   ├── platform
│   │   └── meta
│   │       └── main.yml
│   └── version
│       ├── meta
│       │   └── main.yml
│       └── tasks
│           └── main.yml
└── site.yml

11 directories, 8 files
```

让我们看看运行这个剧本会发生什么。现在，你可能会认为剧本会像这样运行：根据我们在前面的代码中创建的依赖结构，我们的初始剧本静态导入`platform`角色。`platform`角色然后声明依赖于`linuxtype`角色，并且每次使用名为`type`的变量声明两次不同的值。`linuxtype`角色然后声明依赖于`network`和`version`角色，这些角色可以运行多次并打印`type`的值。因此，你可能会认为我们会看到`network`和`version`角色被调用两次，第一次打印`centos`，第二次打印`ubuntu`（因为这是我们最初在`platform`角色中指定依赖关系的方式）。然而，当我们运行它时，实际上看到的是这样的：

```
$ ansible-playbook -i hosts site.yml

PLAY [Role variables and meta playbook] ****************************************

TASK [Gathering Facts] *********************************************************
ok: [frt01.example.com]

TASK [version : Print type variable] *******************************************
ok: [frt01.example.com] => {
 "type": "ubuntu"
}

TASK [network : Print type variable] *******************************************
ok: [frt01.example.com] => {
 "type": "ubuntu"
}

TASK [version : Print type variable] *******************************************
ok: [frt01.example.com] => {
 "type": "ubuntu"
}

TASK [network : Print type variable] *******************************************
ok: [frt01.example.com] => {
 "type": "ubuntu"
}

PLAY RECAP *********************************************************************
frt01.example.com : ok=5 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

发生了什么？尽管我们看到`network`和`version`角色被调用了两次（如预期的那样），但`type`变量的值始终是`ubuntu`。这突出了关于 Ansible 解析器工作方式的重要一点，以及静态导入（我们在这里所做的）和动态包含（我们在前一节中讨论过）之间的区别。

使用静态导入时，角色变量的作用域就好像它们是在播放级别而不是角色级别定义的一样。角色本身在解析时都会被解析并合并到我们在`site.yml`剧本中创建的播放中，因此，Ansible 解析器会创建（在内存中）一个包含来自我们目录结构的所有合并变量和角色内容的大型剧本。这样做并没有错，但意味着`type`变量每次声明时都会被覆盖，因此我们声明的最后一个值（在这种情况下是`ubuntu`）是用于播放运行的值。

那么，我们如何使这个剧本按照我们最初的意图运行——加载我们的依赖角色，但使用我们为`type`变量定义的两个不同值？

这个问题的答案是，如果我们要继续使用静态导入的角色，那么在声明依赖关系时就不应该使用角色变量。相反，我们应该将`type`作为角色参数传递。这是一个小但至关重要的区别——即使在运行 Ansible 解析器时，角色参数仍然保持在角色级别上，因此我们可以在不覆盖变量的情况下声明我们的依赖两次。要做到这一点，将`roles/platform/meta/main.yml`文件的内容更改为以下内容：

```
---
dependencies:
- role: linuxtype
  type: centos
- role: linuxtype
  type: ubuntu
```

您注意到微妙的变化了吗？`vars:`关键字消失了，`type`的声明现在处于较低的缩进级别，这意味着它是一个角色参数。现在，当我们运行 playbook 时，我们得到了我们所希望的结果：

```
$ ansible-playbook -i hosts site.yml

PLAY [Role variables and meta playbook] ****************************************

TASK [Gathering Facts] *********************************************************
ok: [frt01.example.com]

TASK [version : Print type variable] *******************************************
ok: [frt01.example.com] => {
 "type": "centos"
}

TASK [network : Print type variable] *******************************************
ok: [frt01.example.com] => {
 "type": "centos"
}

TASK [version : Print type variable] *******************************************
ok: [frt01.example.com] => {
 "type": "ubuntu"
}

TASK [network : Print type variable] *******************************************
ok: [frt01.example.com] => {
 "type": "ubuntu"
}

PLAY RECAP *********************************************************************
frt01.example.com : ok=5 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

这是一个相当高级的 Ansible 角色依赖示例，但是提供给您是为了演示了解变量优先级（即变量的作用域）和解析器工作的重要性。如果您编写简单的、按顺序解析的任务，那么您可能永远不需要了解这一点，但我建议您广泛使用调试语句，并测试您的 playbook 设计，以确保在 playbook 开发过程中不会遇到这种问题。

在对角色的许多方面进行了详细的研究之后，让我们在下一节中看一下一个用于公开可用的 Ansible 角色的集中存储——Ansible Galaxy。

# Ansible Galaxy

没有关于 Ansible 角色的部分会完整无缺地提到 Ansible Galaxy。Ansible Galaxy 是 Ansible 托管的一个由社区驱动的 Ansible 角色集合，托管在[`galaxy.ansible.com/`](https://galaxy.ansible.com/)。它包含了许多社区贡献的 Ansible 角色，如果您能构想出一个自动化任务，很有可能已经有人编写了一个角色来完全满足您的需求。它非常值得探索，并且可以让您的自动化项目迅速起步，因为您可以开始使用一组现成的角色。

除了网站之外，`ansible-galaxy`客户端也包含在 Ansible 中，这为您提供了一种快速便捷的方式，让您下载并部署角色到您的 playbook 结构中。假设您想要在目标主机上更新**每日消息**（**MOTD**）—这肯定是有人已经想出来的事情。在 Ansible Galaxy 网站上快速搜索返回（在撰写本文时）106 个设置 MOTD 的角色。如果我们想使用其中一个，我们可以使用以下命令将其下载到我们的角色目录中：

```
$ ansible-galaxy role install -p roles/ arillso.motd
```

这就是您需要做的一切——一旦下载完成，您可以像在本章讨论的手动创建的角色一样，在 playbook 中导入或包含角色。请注意，如果您不指定`-p roles/`，`ansible-galaxy`会将角色安装到`~/.ansible/roles`，这是您的用户帐户的中央角色目录。当然，这可能是您想要的，但如果您希望将角色直接下载到 playbook 目录结构中，您可以添加此参数。

另一个巧妙的技巧是使用`ansible-galaxy`为您创建一个空的角色目录结构，以便您在其中创建自己的角色——这样可以节省我们在本章中一直在进行的所有手动目录和文件创建，就像在这个例子中一样：

```
$ ansible-galaxy role init --init-path roles/ testrole
- Role testrole was created successfully
$ tree roles/testrole/
roles/testrole/
├── defaults
│   └── main.yml
├── files
├── handlers
│   └── main.yml
├── meta
│   └── main.yml
├── README.md
├── tasks
│   └── main.yml
├── templates
├── tests
│   ├── inventory
│   └── test.yml
└── vars
 └── main.yml 
```

这应该为您提供足够的信息，让您开始进入 Ansible 角色的旅程。我无法再次强调开发代码作为角色是多么重要——最初可能看起来不重要，但随着您的自动化用例的扩展，以及重用代码的需求增长，您会为自己的决定感到高兴。在下一节中，让我们扩展一下对 Ansible playbook 的讨论，讨论条件逻辑在您的 Ansible 代码中的使用方式。

# 在您的代码中使用条件

到目前为止，在我们的大多数示例中，我们创建了一组简单的任务集，这些任务总是运行。然而，当你生成你想要应用于更广泛主机数组的任务（无论是在角色还是 playbooks 中），迟早你会想要执行某种条件动作。这可能是只对先前任务的结果执行任务。或者可能是只对从 Ansible 系统中收集的特定事实执行任务。在本节中，我们将提供一些实际的条件逻辑示例，以演示如何在你的 Ansible 任务中应用这个特性。

和以往一样，我们需要一个清单来开始，并且我们将重用本章中一直使用的清单：

```
[frontends]
frt01.example.com https_port=8443
frt02.example.com http_proxy=proxy.example.com

[frontends:vars]
ntp_server=ntp.frt.example.com
proxy=proxy.frt.example.com

[apps]
app01.example.com
app02.example.com

[webapp:children]
frontends
apps

[webapp:vars]
proxy_server=proxy.webapp.example.com
health_check_retry=3
health_check_interal=60
```

假设你只想在某些操作系统上执行 Ansible 任务。我们已经讨论了 Ansible 事实，这为在 playbooks 中探索条件逻辑提供了一个完美的平台。考虑一下：所有你的 CentOS 系统都发布了一个紧急补丁，你想立即应用它。当然，你可以逐个创建一个专门的清单（或主机组）来适用于 CentOS 主机，但这是你不一定需要做的额外工作。

相反，让我们定义一个将执行我们的更新的任务，但在一个简单的示例 playbook 中添加一个包含 Jinja 2 表达式的`when`子句：

```
---
- name: Play to patch only CentOS systems
  hosts: all
  become: true

  tasks:
  - name: Patch CentOS systems
    yum:
      name: httpd
      state: latest
    when: ansible_facts['distribution'] == "CentOS"
```

现在，当我们运行这个任务时，如果你的测试系统是基于 CentOS 的（我的也是），你应该会看到类似以下的输出：

```
$ ansible-playbook -i hosts condition.yml

PLAY [Play to patch only CentOS systems] ***************************************

TASK [Gathering Facts] *********************************************************
ok: [frt02.example.com]
ok: [app01.example.com]
ok: [frt01.example.com]
ok: [app02.example.com]

TASK [Patch CentOS systems] ****************************************************
ok: [app01.example.com]
changed: [frt01.example.com]
ok: [app02.example.com]
ok: [frt02.example.com]

PLAY RECAP *********************************************************************
app01.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
app02.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt01.example.com : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

前面的输出显示，我们所有的系统都是基于 CentOS 的，但只有`frt01.example.com`需要应用补丁。现在我们可以使我们的逻辑更加精确——也许只有我们的旧系统运行在 CentOS 6 上需要应用补丁。在这种情况下，我们可以扩展 playbook 中的逻辑，检查发行版和主要版本，如下所示：

```
---
- name: Play to patch only CentOS systems
  hosts: all
  become: true

  tasks:
  - name: Patch CentOS systems
    yum:
      name: httpd
      state: latest
    when: (ansible_facts['distribution'] == "CentOS" and ansible_facts['distribution_major_version'] == "6")
```

现在，如果我们运行我们修改后的 playbook，根据你的清单中有哪些系统，你可能会看到类似以下的输出。在这种情况下，我的`app01.example.com`服务器基于 CentOS 6，因此已应用了补丁。所有其他系统都被跳过，因为它们不符合我的逻辑表达式：

```
$ ansible-playbook -i hosts condition2.yml

PLAY [Play to patch only CentOS systems] ***************************************

TASK [Gathering Facts] *********************************************************
ok: [frt01.example.com]
ok: [app02.example.com]
ok: [app01.example.com]
ok: [frt02.example.com]

TASK [Patch CentOS systems] ****************************************************
changed: [app01.example.com]
skipping: [frt01.example.com]
skipping: [frt02.example.com]
skipping: [app02.example.com]

PLAY RECAP *********************************************************************
app01.example.com : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
app02.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=1 rescued=0 ignored=0
frt01.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=1 rescued=0 ignored=0
frt02.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=1 rescued=0 ignored=0
```

当你运行任何 Ansible 模块（无论是`shell`、`command`、`yum`、`copy`还是其他模块），模块都会返回详细的运行结果数据。你可以使用`register`关键字将其捕获到一个标准的 Ansible 变量中，然后在 playbook 中稍后进一步处理它。

考虑以下 playbook 代码。它包含两个任务，第一个任务是获取当前目录的列表，并将`shell`模块的输出捕获到一个名为`shellresult`的变量中。然后打印一个简单的`debug`消息，但只有在`shell`命令的输出中包含`hosts`字符串时才会打印：

```
---
- name: Play to patch only CentOS systems
  hosts: localhost
  become: true

  tasks:
    - name: Gather directory listing from local system
      shell: "ls -l"
      register: shellresult

    - name: Alert if we find a hosts file
      debug:
        msg: "Found hosts file!"
      when: '"hosts" in shellresult.stdout'
```

现在，当我们在当前目录中运行这个命令时，如果你是从本书附带的 GitHub 仓库中工作，那么目录中将包含一个名为`hosts`的文件，那么你应该会看到类似以下的输出：

```
$ ansible-playbook condition3.yml
[WARNING]: provided hosts list is empty, only localhost is available. Note that
the implicit localhost does not match 'all'

PLAY [Play to patch only CentOS systems] ***************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [Gather directory listing from local system] ******************************
changed: [localhost]

TASK [Alert if we find a hosts file] *******************************************
ok: [localhost] => {
 "msg": "Found hosts file!"
}

PLAY RECAP *********************************************************************
localhost : ok=3 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

然而，如果文件不存在，那么你会发现`debug`消息被跳过了。

```
$ ansible-playbook condition3.yml
[WARNING]: provided hosts list is empty, only localhost is available. Note that
the implicit localhost does not match 'all'

PLAY [Play to patch only CentOS systems] ***************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [Gather directory listing from local system] ******************************
changed: [localhost]

TASK [Alert if we find a hosts file] *******************************************
skipping: [localhost]

PLAY RECAP *********************************************************************
localhost : ok=2 changed=1 unreachable=0 failed=0 skipped=1 rescued=0 ignored=0
```

你也可以为生产中的 IT 运维任务创建复杂的条件；但是，请记住，在 Ansible 中，默认情况下变量不会被转换为任何特定的类型，因此即使变量（或事实）的内容看起来像一个数字，Ansible 默认也会将其视为字符串。如果你需要执行整数比较，你必须首先将变量转换为整数类型。例如，这是一个 playbook 的片段，它只在 Fedora 25 及更新版本上运行一个任务：

```
tasks:
  - name: Only perform this task on Fedora 25 and later
 shell: echo "only on Fedora 25 and later"
    when: ansible_facts['distribution'] == "Fedora" and ansible_facts['distribution_major_version']|int >= 25 
```

你可以应用许多不同类型的条件到你的 Ansible 任务中，这一节只是触及了表面；然而，它应该为你扩展你在 Ansible 任务中应用条件的知识提供了一个坚实的基础。你不仅可以将条件逻辑应用到 Ansible 任务中，还可以在一组数据上运行它们，并且我们将在下一节中探讨这一点。

# 使用循环重复任务

通常，我们希望执行一个单一的任务，但使用该单一任务来迭代一组数据。例如，你可能不想创建一个用户帐户，而是创建 10 个。或者你可能想要将 15 个软件包安装到系统中。可能性是无穷无尽的，但要点仍然是一样的——你不想编写 10 个单独的 Ansible 任务来创建 10 个用户帐户。幸运的是，Ansible 支持对数据集进行循环，以确保你可以使用紧密定义的代码执行大规模操作。在本节中，我们将探讨如何在你的 Ansible playbook 中实际使用循环。

和以往一样，我们必须从清单开始工作，并且我们将使用我们在本章中一直使用的熟悉清单：

```
[frontends]
frt01.example.com https_port=8443
frt02.example.com http_proxy=proxy.example.com

[frontends:vars]
ntp_server=ntp.frt.example.com
proxy=proxy.frt.example.com

[apps]
app01.example.com
app02.example.com

[webapp:children]
frontends
apps

[webapp:vars]
proxy_server=proxy.webapp.example.com
health_check_retry=3
health_check_interal=60
```

让我们从一个非常简单的 playbook 开始，向你展示如何在单个任务中循环一组数据。虽然这是一个相当牵强的例子，但它旨在简单地向你展示循环在 Ansible 中的工作原理。我们将定义一个单个任务，在清单中的单个主机上运行`command`模块，并使用`command`模块在远程系统上依次`echo`数字 1 到 6（可以很容易地扩展到添加用户帐户或创建一系列文件）。

考虑以下代码：

```
---
- name: Simple loop demo play
  hosts: frt01.example.com

  tasks:
    - name: Echo a value from the loop
      command: echo "{{ item }}"
      loop:
        - 1
        - 2
        - 3
        - 4
        - 5
        - 6
```

`loop:`语句定义了循环的开始，循环中的项目被定义为一个 YAML 列表。此外，请注意更高的缩进级别，这告诉解析器它们是循环的一部分。在处理循环数据时，我们使用一个名为`item`的特殊变量，其中包含要回显的循环迭代的当前值。因此，如果我们运行这个 playbook，我们应该看到类似以下的输出：

```
$ ansible-playbook -i hosts loop1.yml

PLAY [Simple loop demo play] ***************************************************

TASK [Gathering Facts] *********************************************************
ok: [frt01.example.com]

TASK [Echo a value from the loop] **********************************************
changed: [frt01.example.com] => (item=1)
changed: [frt01.example.com] => (item=2)
changed: [frt01.example.com] => (item=3)
changed: [frt01.example.com] => (item=4)
changed: [frt01.example.com] => (item=5)
changed: [frt01.example.com] => (item=6)

PLAY RECAP *********************************************************************
frt01.example.com : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

你可以将我们在前一节中讨论的条件逻辑与循环结合起来，使循环仅对其数据的子集进行操作。例如，考虑以下 playbook 的迭代：

```

---
- name: Simple loop demo play
  hosts: frt01.example.com

  tasks:
    - name: Echo a value from the loop
      command: echo "{{ item }}"
      loop:
        - 1
        - 2
        - 3
        - 4
        - 5
        - 6
      when: item|int > 3
```

现在，当我们运行这个时，我们会看到任务被跳过，直到我们达到循环内容中的整数值 4 及以上：

```
$ ansible-playbook -i hosts loop2.yml

PLAY [Simple loop demo play] ***************************************************

TASK [Gathering Facts] *********************************************************
ok: [frt01.example.com]

TASK [Echo a value from the loop] **********************************************
skipping: [frt01.example.com] => (item=1)
skipping: [frt01.example.com] => (item=2)
skipping: [frt01.example.com] => (item=3)
changed: [frt01.example.com] => (item=4)
changed: [frt01.example.com] => (item=5)
changed: [frt01.example.com] => (item=6)

PLAY RECAP *********************************************************************
frt01.example.com : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

当然，你可以将这个与基于 Ansible 事实和其他变量的条件逻辑相结合，就像我们之前讨论过的那样。就像我们以前使用`register`关键字捕获模块执行的结果一样，我们也可以使用循环来做到这一点。唯一的区别是，结果现在将存储在一个字典中，每次循环迭代都会有一个字典条目，而不仅仅是一组结果。

因此，让我们看看如果我们进一步增强 playbook 会发生什么：

```
---
- name: Simple loop demo play
  hosts: frt01.example.com

  tasks:
    - name: Echo a value from the loop
      command: echo "{{ item }}"
      loop:
        - 1
        - 2
        - 3
        - 4
        - 5
        - 6
      when: item|int > 3
      register: loopresult

    - name: Print the results from the loop
      debug:
        var: loopresult
```

现在，当我们运行 playbook 时，你将看到包含`loopresult`内容的字典的输出页面。由于空间限制，以下输出被截断，但演示了运行此 playbook 时你应该期望的结果类型：

```
$ ansible-playbook -i hosts loop3.yml

PLAY [Simple loop demo play] ***************************************************

TASK [Gathering Facts] *********************************************************
ok: [frt01.example.com]

TASK [Echo a value from the loop] **********************************************
skipping: [frt01.example.com] => (item=1)
skipping: [frt01.example.com] => (item=2)
skipping: [frt01.example.com] => (item=3)
changed: [frt01.example.com] => (item=4)
changed: [frt01.example.com] => (item=5)
changed: [frt01.example.com] => (item=6)

TASK [Print the results from the loop] *****************************************
ok: [frt01.example.com] => {
 "loopresult": {
 "changed": true,
 "msg": "All items completed",
 "results": [
 {
 "ansible_loop_var": "item",
 "changed": false,
 "item": 1,
 "skip_reason": "Conditional result was False",
 "skipped": true
 },
 {
 "ansible_loop_var": "item",
 "changed": false,
 "item": 2,
 "skip_reason": "Conditional result was False",
 "skipped": true
 },
```

正如你所看到的，输出的结果部分是一个字典，我们可以清楚地看到列表中的前两个项目被`skipped`，因为我们`when`子句的结果(`Conditional`)是`false`。

因此，到目前为止，我们可以看到循环很容易定义和使用，但你可能会问，*你能创建嵌套循环吗？*这个问题的答案是*可以*，但有一个问题——特殊变量`item`会发生冲突，因为内部循环和外部循环都会使用相同的变量名。这意味着你嵌套循环运行的结果将是意想不到的。

幸运的是，有一个名为`loop_control`的`loop`参数，允许您更改包含当前`loop`迭代数据的特殊变量的名称，从`item`更改为您选择的内容。让我们创建一个嵌套循环来看看它是如何工作的。

首先，我们将以通常的方式创建一个 playbook，其中包含一个要在循环中运行的单个任务。为了生成我们的嵌套循环，我们将使用`include_tasks`目录来动态包含另一个 YAML 文件中的单个任务，该文件还将包含一个循环。由于我们打算在嵌套循环中使用此 playbook，因此我们将使用`loop_var`指令将特殊循环内容变量的名称从`item`更改为`second_item`：

```
---
- name: Play to demonstrate nested loops
  hosts: localhost

  tasks:
    - name: Outer loop
      include_tasks: loopsubtask.yml
      loop:
        - a
        - b
        - c
      loop_control:
        loop_var: second_item
```

然后，我们将创建一个名为`loopsubtask.yml`的第二个文件，其中包含内部循环，并包含在前面的 playbook 中。由于我们已经在外部循环中更改了循环项变量名称，因此在这里不需要再次更改它。请注意，此文件的结构非常类似于角色中的任务文件-它不是一个完整的 playbook，而只是一个任务列表：

```
---
- name: Inner loop
  debug:
    msg: "second item={{ second_item }} first item={{ item }}"
  loop:
    - 100
    - 200
    - 300
```

现在，您应该能够运行 playbook，并且您将看到 Ansible 首先迭代外部循环，然后处理由外部循环定义的数据的内部循环。由于循环变量名称不冲突，一切都按我们的预期工作：

```
$ ansible-playbook loopmain.yml
[WARNING]: provided hosts list is empty, only localhost is available. Note that
the implicit localhost does not match 'all'

PLAY [Play to demonstrate nested loops] ****************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [Outer loop] **************************************************************
included: /root/Practical-Ansible-2/Chapter 4/loopsubtask.yml for localhost
included: /root/Practical-Ansible-2/Chapter 4/loopsubtask.yml for localhost
included: /root/Practical-Ansible-2/Chapter 4/loopsubtask.yml for localhost

TASK [Inner loop] **************************************************************
ok: [localhost] => (item=100) => {
 "msg": "second item=a first item=100"
}
ok: [localhost] => (item=200) => {
 "msg": "second item=a first item=200"
}
ok: [localhost] => (item=300) => {
 "msg": "second item=a first item=300"
}

TASK [Inner loop] **************************************************************
ok: [localhost] => (item=100) => {
 "msg": "second item=b first item=100"
}
ok: [localhost] => (item=200) => {
 "msg": "second item=b first item=200"
}
ok: [localhost] => (item=300) => {
 "msg": "second item=b first item=300"
}

TASK [Inner loop] **************************************************************
ok: [localhost] => (item=100) => {
 "msg": "second item=c first item=100"
}
ok: [localhost] => (item=200) => {
 "msg": "second item=c first item=200"
}
ok: [localhost] => (item=300) => {
 "msg": "second item=c first item=300"
}

PLAY RECAP *********************************************************************
localhost : ok=7 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

循环很容易使用，但非常强大，因为它们允许您轻松地使用一个任务来迭代大量数据。在下一节中，我们将看一下 Ansible 语言的另一个构造，用于控制 playbook 流程-块。

# 使用块分组任务

在 Ansible 中，块允许您逻辑地将一组任务组合在一起，主要用于两个目的之一。一个可能是对整组任务应用条件逻辑；在这个例子中，您可以将相同的 when 子句应用于每个任务，但这很麻烦和低效-最好将所有任务放在一个块中，并将条件逻辑应用于块本身。这样，逻辑只需要声明一次。块在处理错误和特别是从错误条件中恢复时也非常有价值。在本章中，我们将通过简单的实际示例来探讨这两个问题，以帮助您快速掌握 Ansible 中的块。

一如既往，让我们确保我们有一个清单可以使用：

```
[frontends]
frt01.example.com https_port=8443
frt02.example.com http_proxy=proxy.example.com

[frontends:vars]
ntp_server=ntp.frt.example.com
proxy=proxy.frt.example.com

[apps]
app01.example.com
app02.example.com

[webapp:children]
frontends
apps

[webapp:vars]
proxy_server=proxy.webapp.example.com
health_check_retry=3
health_check_interal=60
```

现在，让我们直接看一个如何使用块来对一组任务应用条件逻辑的示例。在高层次上，假设我们想在所有 Fedora Linux 主机上执行以下操作：

+   为 Apache web 服务器安装软件包。

+   安装一个模板化的配置。

+   启动适当的服务。

我们可以通过三个单独的任务来实现这一点，所有这些任务都与一个`when`子句相关联，但是块为我们提供了更好的方法。以下示例 playbook 显示了包含在块中的三个任务（请注意需要额外的缩进级别来表示它们在块中的存在）：

```
---
- name: Conditional block play
  hosts: all
  become: true

  tasks:
  - name: Install and configure Apache
    block:
      - name: Install the Apache package
        dnf:
          name: httpd
          state: installed
      - name: Install the templated configuration to a dummy location
        template:
          src: templates/src.j2
          dest: /tmp/my.conf
      - name: Start the httpd service
        service:
          name: httpd
          state: started
          enabled: True
    when: ansible_facts['distribution'] == 'Fedora'
```

当您运行此 playbook 时，您应该发现与您可能在清单中拥有的任何 Fedora 主机上只运行与 Apache 相关的任务；您应该看到三个任务中的所有任务都被运行或跳过-取决于清单的组成和内容，它可能看起来像这样：

```
$ ansible-playbook -i hosts blocks.yml

PLAY [Conditional block play] **************************************************

TASK [Gathering Facts] *********************************************************
ok: [app02.example.com]
ok: [frt01.example.com]
ok: [app01.example.com]
ok: [frt02.example.com]

TASK [Install the Apache package] **********************************************
changed: [frt01.example.com]
changed: [frt02.example.com]
skipping: [app01.example.com]
skipping: [app02.example.com]

TASK [Install the templated configuration to a dummy location] *****************
changed: [frt01.example.com]
changed: [frt02.example.com]
skipping: [app01.example.com]
skipping: [app02.example.com]

TASK [Start the httpd service] *************************************************
changed: [frt01.example.com]
changed: [frt02.example.com]
skipping: [app01.example.com]
skipping: [app02.example.com]

PLAY RECAP *********************************************************************
app01.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=3 rescued=0 ignored=0
app02.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=3 rescued=0 ignored=0
frt01.example.com : ok=4 changed=3 unreachable=0 failed=0 skipped=3 rescued=0 ignored=0
frt02.example.com : ok=4 changed=3 unreachable=0 failed=0 skipped=3 rescued=0 ignored=0
```

这很容易构建，但在控制大量任务流程方面非常强大。

这一次，让我们构建一个不同的示例，以演示如何利用块来帮助 Ansible 优雅地处理错误条件。到目前为止，您应该已经经历过，如果您的 playbook 遇到任何错误，它们可能会在失败点停止执行。在某些情况下，这远非理想，您可能希望在此事件中执行某种恢复操作，而不仅仅是停止 playbook。

让我们创建一个新的 playbook，这次内容如下：

```
---
- name: Play to demonstrate block error handling
  hosts: frontends

  tasks:
    - name: block to handle errors
      block:
        - name: Perform a successful task
          debug:
            msg: 'Normally executing....'
        - name: Deliberately create an error
          command: /bin/whatever
        - name: This task should not run if the previous one results in an error
          debug:
            msg: 'Never print this message if the above command fails!!!!'
      rescue:
        - name: Catch the error (and perform recovery actions)
          debug:
            msg: 'Caught the error'
        - name: Deliberately create another error
          command: /bin/whatever
        - name: This task should not run if the previous one results in an error
          debug:
            msg: 'Do not print this message if the above command fails!!!!'
      always:
        - name: This task always runs!
          debug:
            msg: "Tasks in this part of the play will be ALWAYS executed!!!!"
```

请注意，在前面的 play 中，我们现在有了额外的`block`部分——除了`block`本身中的任务外，我们还有两个标记为`rescue`和`always`的新部分。执行流程如下：

1.  `block`部分中的所有任务都按照其列出的顺序正常执行。

1.  如果`block`中的任务导致错误，则不会运行`block`中的其他任务：

+   `rescue`部分中的任务按其列出的顺序开始运行。

+   如果`block`任务没有导致错误，则`rescue`部分中的任务不会运行。

1.  如果在`rescue`部分运行的任务导致错误，则不会执行进一步的`rescue`任务，执行将移至`always`部分。

1.  `always`部分中的任务始终运行，无论`block`或`rescue`部分是否出现错误。即使没有遇到错误，它们也会运行。

考虑到这种执行流程，当您执行此 playbook 时，您应该会看到类似以下的输出，注意我们故意创建了两个错误条件来演示流程：

```
$ ansible-playbook -i hosts blocks-error.yml

PLAY [Play to demonstrate block error handling] ********************************

TASK [Gathering Facts] *********************************************************
ok: [frt02.example.com]
ok: [frt01.example.com]

TASK [Perform a successful task] ***********************************************
ok: [frt01.example.com] => {
    "msg": "Normally executing...."
}
ok: [frt02.example.com] => {
    "msg": "Normally executing...."
}

TASK [Deliberately create an error] ********************************************
fatal: [frt01.example.com]: FAILED! => {"changed": false, "cmd": "/bin/whatever", "msg": "[Errno 2] No such file or directory", "rc": 2}
fatal: [frt02.example.com]: FAILED! => {"changed": false, "cmd": "/bin/whatever", "msg": "[Errno 2] No such file or directory", "rc": 2}

TASK [Catch the error (and perform recovery actions)] **************************
ok: [frt01.example.com] => {
    "msg": "Caught the error"
}
ok: [frt02.example.com] => {
    "msg": "Caught the error"
}

TASK [Deliberately create another error] ***************************************
fatal: [frt01.example.com]: FAILED! => {"changed": false, "cmd": "/bin/whatever", "msg": "[Errno 2] No such file or directory", "rc": 2}
fatal: [frt02.example.com]: FAILED! => {"changed": false, "cmd": "/bin/whatever", "msg": "[Errno 2] No such file or directory", "rc": 2}

TASK [This task always runs!] **************************************************
ok: [frt01.example.com] => {
    "msg": "Tasks in this part of the play will be ALWAYS executed!!!!"
}
ok: [frt02.example.com] => {
    "msg": "Tasks in this part of the play will be ALWAYS executed!!!!"
}

PLAY RECAP *********************************************************************
frt01.example.com : ok=4 changed=0 unreachable=0 failed=1 skipped=0 rescued=1 ignored=0
frt02.example.com : ok=4 changed=0 unreachable=0 failed=1 skipped=0 rescued=1 ignored=0
```

Ansible 有两个特殊变量，其中包含您可能在`rescue`块中找到有用的信息以执行恢复操作：

+   `ansible_failed_task`：这是一个包含来自`block`失败的任务的详细信息的字典，导致我们进入`rescue`部分。您可以通过使用`debug`显示其内容来探索这一点，但例如，失败任务的名称可以从`ansible_failed_task.name`中获取。

+   `ansible_failed_result`：这是失败任务的结果，并且与如果您在失败的任务中添加了`register`关键字的行为相同。这样可以避免在每个任务中添加`register`以防它失败。

随着您的 playbooks 变得更加复杂，错误处理变得越来越重要（或者条件逻辑变得更加重要），`block`将成为编写良好、健壮的 playbooks 的重要组成部分。让我们在下一节中继续探讨执行策略，以进一步控制您的 playbook 运行。

# 通过策略配置 play 执行

随着您的 playbooks 变得越来越复杂，调试任何可能出现的问题变得越来越重要。例如，您是否可以在执行过程中检查给定变量（或变量）的内容，而无需在整个 playbook 中插入`debug`语句？同样，我们迄今为止已经看到，Ansible 将确保特定任务在应用于所有清单主机之前完成，然后再移动到下一个任务——是否有办法改变这一点？

当您开始使用 Ansible 时，默认情况下看到的执行策略（尽管我们尚未提到它的名称）被称为`linear`。这正是它所描述的——在开始下一个任务之前，每个任务都会在所有适用的主机上依次执行。然而，还有另一种不太常用的策略称为`free`，它允许所有任务在每个主机上尽快完成，而不必等待其他主机。

然而，当您开始使用 Ansible 时，最有用的策略将是`debug`策略，这使得 Ansible 可以在 playbook 中发生错误时直接将您置于集成的调试环境中。让我们通过创建一个有意义的错误的 playbook 来演示这一点。请注意 play 定义中的`strategy: debug`和`debugger: on_failed`语句：

```
---
- name: Play to demonstrate the debug strategy
  hosts: frt01.example.com
  strategy: debug
  debugger: on_failed
  gather_facts: no
  vars:
    username: daniel

  tasks:
    - name: Generate an error by referencing an undefined variable
      ping: data={{ mobile }}
```

现在，如果您执行此 playbook，您应该会看到它开始运行，但是当遇到它包含的故意错误时，它会将您带入集成调试器。输出的开头应该类似于以下内容：

```
$ ansible-playbook -i hosts debug.yml

PLAY [Play to demonstrate the debug strategy] **********************************

TASK [Generate an error by referencing an undefined variable] ******************
fatal: [frt01.example.com]: FAILED! => {"msg": "The task includes an option with an undefined variable. The error was: 'mobile' is undefined\n\nThe error appears to be in '/root/Practical-Ansible-2/Chapter 4/debug.yml': line 11, column 7, but may\nbe elsewhere in the file depending on the exact syntax problem.\n\nThe offending line appears to be:\n\n tasks:\n - name: Generate an error by referencing an undefined variable\n ^ here\n"}
[frt01.example.com] TASK: Generate an error by referencing an undefined variable (debug)>

[frt02.prod.com] TASK: make an error with refering incorrect variable (debug)> p task_vars
{'ansible_check_mode': False,
 'ansible_current_hosts': [u'frt02.prod.com'],
 'ansible_diff_mode': False,
 'ansible_facts': {},
 'ansible_failed_hosts': [],
 'ansible_forks': 5,
...
[frt02.prod.com] TASK: make an error with refering incorrect variable (debug)> quit
User interrupted execution
$ 
```

请注意，剧本开始执行，但在第一个任务上失败，并显示错误，因为变量未定义。但是，它不是退出到 shell，而是进入交互式调试器。本书不涵盖调试器的详尽指南，但如果您有兴趣学习，可以在此处找到更多详细信息：[`docs.ansible.com/ansible/latest/user_guide/playbooks_debugger.html`](https://docs.ansible.com/ansible/latest/user_guide/playbooks_debugger.html)。

然而，为了带您进行一个非常简单的实际调试示例，输入`p task`命令——这将导致 Ansible 调试器打印失败任务的名称；如果您正在进行一个大型剧本，这将非常有用：

```
[frt01.example.com] TASK: Generate an error by referencing an undefined variable (debug)> p task
TASK: Generate an error by referencing an undefined variable
```

现在我们知道了剧本失败的原因，所以让我们通过发出`p task.args`命令来深入了解一下，这将显示传递给任务模块的参数：

```
[frt01.example.com] TASK: Generate an error by referencing an undefined variable (debug)> p task.args
{u'data': u'{{ mobile }}'}
```

因此，我们可以看到我们的模块传递了一个名为`data`的参数，参数值是一个变量（由大括号对表示）称为`mobile`。因此，可能有必要查看任务可用的变量，看看这个变量是否存在，如果存在的话，值是否合理（使用`p task_vars`命令来执行此操作）：

```
[frt01.example.com] TASK: Generate an error by referencing an undefined variable (debug)> p task_vars
{'ansible_check_mode': False,
 'ansible_current_hosts': [u'frt01.example.com'],
 'ansible_dependent_role_names': [],
 'ansible_diff_mode': False,
 'ansible_facts': {},
 'ansible_failed_hosts': [],
 'ansible_forks': 5,
```

上述输出被截断了，您会发现与任务相关的许多变量——这是因为任何收集的事实和内部 Ansible 变量都可用于任务。但是，如果您浏览列表，您将能够确认没有名为`mobile`的变量。

因此，这应该足够的信息来修复您的剧本。输入`q`退出调试器：

```
[frt01.example.com] TASK: Generate an error by referencing an undefined variable (debug)> q
User interrupted execution
$
```

Ansible 调试器是一个非常强大的工具，您应该学会有效地使用它，特别是当您的剧本复杂性增加时。这结束了我们对剧本设计各个方面的实际考察——在下一节中，我们将看看您可以将 Git 源代码管理集成到您的剧本中的方法。

# 使用 ansible-pull

`ansible-pull`命令是 Ansible 的一个特殊功能，允许您一次性从 Git 存储库（例如 GitHub）中拉取一个剧本，然后执行它，因此节省了克隆（或更新工作副本）存储库，然后执行剧本等常规步骤。`ansible-pull`的好处在于它允许您集中存储和版本控制您的剧本，然后使用单个命令执行它们，从而使它们能够使用`cron`调度程序执行，而无需甚至在给定的主机上安装 Ansible 剧本。

然而，需要注意的一点是，虽然`ansible`和`ansible-playbook`命令都可以在整个清单上运行剧本，并针对一个或多个远程主机运行剧本，但`ansible-pull`命令只打算在本地主机上运行从您的源代码控制系统获取的剧本。因此，如果您想在整个基础架构中使用`ansible-pull`，您必须将其安装到每个需要它的主机上。

尽管如此，让我们看看这可能是如何工作的。我们将简单地手动运行命令来探索它的应用，但实际上，您几乎肯定会将其安装到您的`crontab`中，以便定期运行，捕捉您对剧本所做的任何更改版本控制系统中。

由于`ansible-pull`只打算在本地系统上运行剧本，因此清单文件有些多余——相反，我们将使用一个很少使用的清单规范，您可以在命令行上简单地指定清单主机目录为逗号分隔的列表。如果您只有一个主机，只需指定其名称，然后加上逗号。

让我们使用 GitHub 上的一个简单的剧本，根据变量内容设置每日消息。为此，我们将运行以下命令（我们将在一分钟内分解）：

```
$ ansible-pull -d /var/ansible-set-motd -i ${HOSTNAME}, -U https://github.com/jamesfreeman959/ansible-set-motd.git site.yml -e "ag_motd_content='MOTD generated by ansible-pull'" >> /tmp/ansible-pull.log 2>&1
```

这个命令分解如下：

+   `-d /var/ansible-set-motd`：这将设置包含来自 GitHub 的代码检出的工作目录。

+   `-i ${HOSTNAME},`：这仅在当前主机上运行，由适当的 shell 变量指定其主机名。

+   `-U https://github.com/jamesfreeman959/ansible-set-motd.git`：我们使用此 URL 来获取 playbooks。

+   `site.yml`：这是要运行的 playbook 的名称。

+   `-e "ag_motd_content='MOTD generated by ansible-pull'"`：这将设置适当的 Ansible 变量以生成 MOTD 内容。

+   `>> /tmp/ansible-pull.log 2>&1`：这将重定向命令的输出到日志文件，以便以后分析 - 特别是在`cron job`中运行命令时，输出将永远不会打印到用户的终端上，这是非常有用的。

当您运行此命令时，您应该会看到类似以下的输出（请注意，为了更容易看到输出，已删除了日志重定向）：

```
$ ansible-pull -d /var/ansible-set-motd -i ${HOSTNAME}, -U https://github.com/jamesfreeman959/ansible-set-motd.git site.yml -e "ag_motd_content='MOTD generated by ansible-pull'"
Starting Ansible Pull at 2020-04-14 17:26:21
/usr/bin/ansible-pull -d /var/ansible-set-motd -i cookbook, -U https://github.com/jamesfreeman959/ansible-set-motd.git site.yml -e ag_motd_content='MOTD generated by ansible-pull'
cookbook |[WARNING]: SUCCESS = Your git > {
    "aversion isfter": "7d too old t3a191ecb2do fully suebe7f84f4fpport the a5817b0f1bdepth argu49c4cd54",ment.
Fall
    "ansing back tible_factso full che": {
     ckouts.
   "discovered_interpreter_python": "/usr/bin/python"
    },
    "before": "7d3a191ecb2debe7f84f4fa5817b0f1b49c4cd54",
    "changed": false,
    "remote_url_changed": false
}

PLAY [Update the MOTD on hosts] ************************************************

TASK [Gathering Facts] *********************************************************
ok: [cookbook]

TASK [ansible.motd : Add 99-footer file] ***************************************
skipping: [cookbook]

TASK [ansible.motd : Delete 99-footer file] ************************************
ok: [cookbook]

TASK [ansible.motd : Delete /etc/motd file] ************************************
skipping: [cookbook]

TASK [ansible.motd : Check motd tail supported] ********************************
fatal: [cookbook]: FAILED! => {"changed": true, "cmd": "test -f /etc/update-motd.d/99-footer", "delta": "0:00:00.004444", "end": "2020-04-14 17:26:25.489793", "msg": "non-zero return code", "rc": 1, "start": "2020-04-14 17:26:25.485349", "stderr": "", "stderr_lines": [], "stdout": "", "stdout_lines": []}
...ignoring

TASK [ansible.motd : Add motd tail] ********************************************
skipping: [cookbook]

TASK [ansible.motd : Add motd] *************************************************
changed: [cookbook]

PLAY RECAP *********************************************************************
cookbook : ok=4 changed=2 unreachable=0 failed=0 skipped=3 rescued=0 ignored=1
```

这个命令可以成为您整体 Ansible 解决方案的一个非常强大的部分，特别是因为这意味着您不必过于担心集中运行所有 playbooks，或者确保每次运行它们时它们都是最新的。在大型基础架构中，将其安排在`cron`中的能力尤其强大，理想情况下，自动化应该能够自行处理事务。

这结束了我们对 playbooks 的实际观察，以及如何编写自己的代码 - 通过对 Ansible 模块进行一些研究，现在您应该足够轻松地编写自己的强大 playbooks 了。

# 总结

Playbooks 是 Ansible 自动化的生命线，提供了一个强大的框架，用于定义任务的逻辑集合并清晰而强大地处理错误条件。将角色添加到这个混合中对于组织代码和支持代码重用都是有价值的，尤其是在您的自动化需求增长时。Ansible playbooks 为您的技术需求提供了一个真正完整的自动化解决方案。

在本章中，您学习了 playbook 框架以及如何开始编写自己的 playbooks。然后，您学习了如何将代码组织成角色，并设计代码以有效地支持重用。然后，我们探讨了一些更高级的 playbook 编写主题，如使用条件逻辑、块和循环。最后，我们看了一下 playbook 执行策略，特别是为了能够有效地调试您的 playbooks，最后，我们看了一下如何直接从 GitHub 在本地机器上运行 Ansible playbooks。

在下一章中，我们将学习如何使用和创建我们自己的模块，为您提供扩展 Ansible 功能的技能，以适应自己定制的环境，并为社区做出贡献。

# 问题

1.  如何通过临时命令在`frontends`主机组中重新启动 Apache Web 服务器？

A) `ansible frontends -i hosts -a "name=httpd state=restarted"`

B) `ansible frontends -i hosts -b service -a "name=httpd state=restarted"`

C) `ansible frontends -i hosts -b -m service -a "name=httpd state=restarted"`

D) `ansible frontends -i hosts -b -m server -a "name=httpd state=restarted"`

E) `ansible frontends -i hosts -m restart -a "name=httpd"`

1.  Do 块允许您逻辑地组合一组任务，或执行错误处理吗？

A) 正确

B) 错误

1.  默认策略是通过 playbook 中的相关模块进行设置。

A) 正确

B) 错误

# 进一步阅读

`ansible-galaxy`和文档可以在这里找到：[`galaxy.ansible.com/docs/`](https://galaxy.ansible.com/docs/)。
