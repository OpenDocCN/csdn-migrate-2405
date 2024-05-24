# Ansible 配置管理手册（二）

> 原文：[`zh.annas-archive.org/md5/B284B07EA563637C44B0B69D722236FE`](https://zh.annas-archive.org/md5/B284B07EA563637C44B0B69D722236FE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：自定义模块

到目前为止，我们一直在使用 Ansible 提供给我们的工具。这确实为我们提供了很多力量，并使许多事情成为可能。但是，如果您遇到特别复杂的情况，或者发现自己经常使用脚本模块，您可能希望学习如何扩展 Ansible。

在本章中，您将学习以下主题：

+   如何使用 Bash 脚本或 Python 编写模块

+   使用您开发的自定义模块

+   编写一个脚本以使用外部数据源作为清单

通常在处理 Ansible 中的复杂问题时，您会编写一个脚本模块。脚本模块的问题在于您无法轻松处理它们的输出，或者根据它们的输出触发处理程序。因此，尽管脚本模块在某些情况下有效，但使用模块可能更好。

在以下情况下使用模块而不是编写脚本：

+   您不希望每次都运行脚本

+   你需要处理输出

+   您的脚本需要生成事实

+   需要将复杂变量作为参数发送

如果您想开始编写模块，您应该查看 Ansible 存储库。如果您希望您的模块与特定版本兼容，您还应该切换到该版本以确保兼容性。以下命令将为您设置开发 Ansible 1.3.0 的模块。

```
**$ git clone (https://github.com/ansible/ansible.git)**
**$ cd ansible**
**$ git checkout v1.3.0**
**$ chmod +x hacking/test-module**

```

查看 Ansible 代码可以让您访问一个方便的脚本，我们稍后将用它来测试我们的模块。我们还将使这个脚本可执行，以便在本章后期使用。

# 用 Bash 编写模块

Ansible 允许您使用任何您喜欢的语言编写模块。尽管 Ansible 中的大多数模块都使用 JSON，但如果您没有任何 JSON 解析工具可用，您可以使用快捷方式。如果以原始键值形式提供了参数，Ansible 将以原始键值形式将其交给您。如果提供了复杂参数，您将收到 JSON 编码的数据。您可以使用类似 jsawk ([`github.com/micha/jsawk`](https://github.com/micha/jsawk))或 jq ([`stedolan.github.io/jq/`](http://stedolan.github.io/jq/))的工具进行解析，但前提是它们已安装在您的远程机器上。

Ansible 已经有一个模块，可以更改系统的主机名，但它只适用于基于 systemd 的系统。因此，让我们编写一个可以使用标准`hostname`命令的模块。我们将从打印当前主机名开始，然后从那里扩展脚本。这就是这个简单模块的样子：

```
#!/bin/bash

HOSTNAME="$(hostname)"

echo "hostname=${HOSTNAME}"
```

如果您以前编写过 Bash 脚本，这应该看起来非常基础。基本上，我们所做的是获取主机名并以键值形式打印出来。现在我们已经编写了模块的第一个版本，我们应该测试一下。

为了测试 Ansible 模块，我们使用之前运行`chmod`命令的脚本。这个命令简单地运行你的模块，记录输出，并将其返回给你。它还显示了 Ansible 如何解释模块的输出。我们将使用的命令看起来像下面这样：

```
**ansible/hacking/test-module -m ./hostname**

```

上一个命令的输出应该如下所示：

```
* module boilerplate substitution not requested in module, line numbers will be unaltered
***********************************
RAW OUTPUT
hostname=admin01.int.example.com

***********************************
PARSED OUTPUT
{
    "hostname": "admin01.int.example.com"
}
```

忽略顶部的通知；它不适用于使用 bash 构建的模块。您可以看到我们的脚本发送的原始输出，它看起来正是我们预期的样子。测试脚本还会给您解析后的输出。在我们的示例中，我们使用了短输出格式，我们可以看到 Ansible 正确地将其解释为它通常从模块接受的 JSON。

让我们扩展模块以允许设置`hostname`。我们应该这样写，以便除非需要，否则不做任何更改，并让 Ansible 知道是否已经进行了更改。对于我们正在编写的小命令来说，这实际上非常简单。新脚本应该看起来像这样：

```
#!/bin/bash

set -e

# This is potentially dangerous
source ${1}

OLDHOSTNAME="$(hostname)"
CHANGED="False"

if [ ! -z "$hostname" -a "${hostname}x" != "${OLDHOSTNAME}x" ]; then
  hostname $hostname
  OLDHOSTNAME="$hostname"
  CHANGED="True"
fi

echo "hostname=${OLDHOSTNAME} changed=${CHANGED}"
exit 0
```

前面的脚本的工作原理如下：

1.  我们设置 Bash 的错误退出模式，这样我们就不必处理`hostname`方法的错误。Bash 将在失败时自动退出并显示其退出代码。这将向 Ansible 发出信号，表明出现了问题。

1.  我们获取参数文件。这个文件是从 Ansible 传递给脚本的第一个参数。它包含发送到我们模块的参数。因为我们正在获取文件，这可以用来运行任意命令；但是，Ansible 已经可以做到这一点，所以这不是一个很大的安全问题。

1.  我们收集旧的主机名并将默认的`CHANGED`设置为`False`。这样可以让我们看到我们的模块是否需要执行任何更改。

1.  我们检查是否发送了一个新的主机名来设置，以及该主机名是否与当前设置的主机名不同。

1.  如果这两个测试都为真，我们尝试更改主机名，并将`CHANGED`设置为`True`。

1.  最后，我们输出结果并退出。这包括当前的主机名以及我们是否进行了更改。

在 Unix 机器上更改主机名需要 root 权限。因此，在测试这个脚本时，您需要确保以 root 用户身份运行它。让我们使用`sudo`来测试这个脚本，看看它是否有效。这是您将使用的命令：

```
**sudo ansible/hacking/test-module -m ./hostname -a 'hostname=test.example.com'**

```

如果`test.example.com`不是机器的当前主机名，您应该会得到以下输出：

```
* module boilerplate substitution not requested in module, line numbers will be unaltered
***********************************
RAW OUTPUT
hostname=test.example.com changed=True

***********************************
PARSED OUTPUT
{
    "changed": true,
    "hostname": "test.example.com"
}
```

如您所见，我们的输出被正确解析，并且模块声称已对系统进行了更改。您可以使用`hostname`命令自行检查。现在，再次使用相同的主机名运行模块。您应该会看到以下输出：

```
* module boilerplate substitution not requested in module, line numbers will be unaltered
***********************************
RAW OUTPUT
hostname=test.example.com changed=False

***********************************
PARSED OUTPUT
{
    "changed": false,
    "hostname": "test.example.com"
}
```

再次看到输出被正确解析。然而，这次模块声称没有进行任何更改，这是我们所期望的。您也可以使用`hostname`命令进行检查。

# 使用自定义模块

现在我们已经为 Ansible 编写了我们的第一个模块，我们应该在 playbook 中试一下。Ansible 会在几个地方查找它的模块——首先它会查找`config`文件(`/etc/ansible/ansible.cfg`)中`library`键指定的位置，然后它会查找使用命令行中的`--module-path`参数指定的位置，然后它会在与 playbook 相同的目录中查找包含模块的`library`目录，最后它会在`library`目录中查找可能设置的任何角色。

让我们创建一个使用我们的新模块的 playbook，并将其放在与 playbook 相同的位置的`library`目录中，以便我们可以看到它的效果。这是一个使用`hostname`模块的 playbook：

```
---
- name: Test the hostname file
  hosts: testmachine
  tasks:
    - name: Set the hostname
      hostname: hostname=testmachine.example.com
```

然后在与 playbook 文件相同的目录中创建一个名为`library`的目录。将`hostname`模块放在库中。您的目录布局应该如下所示：

![使用自定义模块](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-cfg-mgt-2e/img/4267_05_01.jpg)

现在当您运行 playbook 时，它将在`library`目录中找到`hostname`模块并执行它。您应该会看到以下输出：

```
PLAY [Test the hostname file] ***************************************

GATHERING FACTS *****************************************************
ok: [ansibletest]

TASK: [Set the hostname] ********************************************
changed: [ansibletest]

PLAY RECAP **********************************************************
ansibletest                : ok=2    changed=1    unreachable=0    failed=0
```

再次运行应该将结果从`changed`更改为`ok`。恭喜！您现在已经创建并执行了您的第一个模块。这个模块现在非常简单，但您可以扩展它以了解`hostname`文件，或其他配置主机名的方法。

# 用 Python 编写模块

所有与 Ansible 一起分发的模块都是用 Python 编写的。因为 Ansible 也是用 Python 编写的，所以这些模块可以直接集成到 Ansible 中。以下是为什么应该用 Python 编写模块的几个原因：

+   用 Python 编写的模块可以使用样板文件，这样可以减少所需的代码量

+   Python 模块可以提供文档供 Ansible 使用

+   模块的参数会自动处理

+   输出会自动转换为 JSON 格式

+   Ansible 仅接受使用包含样板代码的 Python 编写的插件

您仍然可以构建 Python 模块，而无需通过解析参数和自己输出 JSON 来实现此集成。但是，考虑到您可以免费获得的所有功能，很难提出这样做的理由。

让我们构建一个 Python 模块，让我们能够更改系统当前运行的初始化级别。有一个名为`pyutmp`的 Python 模块，它将允许我们解析`utmp`文件。不幸的是，由于 Ansible 模块必须包含在单个文件中，除非我们知道它将安装在远程系统上，否则我们无法使用它，因此我们将使用`runlevel`命令并解析其输出。可以使用`init`命令设置运行级别。

第一步是弄清楚模块支持的参数和功能。为了简单起见，让我们的模块只接受一个参数。我们将使用参数`runlevel`来获取用户想要更改为的运行级别。为此，我们将使用我们的数据实例化`AnsibleModule`类，如下所示：

```
module = AnsibleModule(
  argument_spec = dict(
    runlevel=dict(default=None, type='str')
  )
)
```

现在我们需要实现模块的实际要点。我们之前创建的模块对象为我们提供了一些快捷方式。在下一步中，我们将使用三个快捷方式。由于有太多的方法需要在这里记录，您可以在`lib/ansible/module_common.py`中看到整个`AnsibleModule`类和所有可用的辅助函数。

+   `run_command`：此方法用于启动外部命令并检索返回代码、`stdout`的输出以及`stderr`的输出。

+   `exit_json`：此方法用于在模块成功完成时向 Ansible 返回数据。

+   `fail_json`：此方法用于向 Ansible 发出失败信号，附带错误消息和返回代码。

以下代码实际上管理了系统注释的初始化级别，以解释其功能：

```
def main():     #1
  module = AnsibleModule(    #2
    argument_spec = dict(    #3
      runlevel=dict(default=None, type='str')     #4
    )     #5
  )     #6

  # Ansible helps us run commands     #7
  rc, out, err = module.run_command('/sbin/runlevel')     #8
  if rc != 0:     #9
    module.fail_json(msg="Could not determine current runlevel.", rc=rc, err=err)     #10

  # Get the runlevel, exit if its not what we expect     #11
  last_runlevel, cur_runlevel = out.split(' ', 1)     #12
  cur_runlevel = cur_runlevel.rstrip()     #13
  if len(cur_runlevel) > 1:     #14
    module.fail_json(msg="Got unexpected output from runlevel.", rc=rc)     #15

  # Do we need to change anything     #16
  if module.params['runlevel'] is None or module.params['runlevel'] == cur_runlevel:     #17
    module.exit_json(changed=False, runlevel=cur_runlevel)     #18

  # Check if we are root     #19
  uid = os.geteuid()     #20
  if uid != 0:     #21
    module.fail_json(msg="You need to be root to change the runlevel")     #22

  # Attempt to change the runlevel     #23
  rc, out, err = module.run_command('/sbin/init %s' % module.params['runlevel'])     #24
  if rc != 0:     #25
    module.fail_json(msg="Could not change runlevel.", rc=rc, err=err)     #26

  # Tell ansible the results     #27
  module.exit_json(changed=True, runlevel=cur_runlevel)     #28
```

还有一件事要添加到样板中，让 Ansible 知道它需要动态地将集成代码添加到我们的模块中。这是让我们使用`AnsibleModule`类并启用与 Ansible 的紧密集成的魔法。样板代码需要放在文件底部，之后没有代码。这样做的代码如下：

```
# include magic from lib/ansible/module_common.py
#<<INCLUDE_ANSIBLE_MODULE_COMMON>>
main()
So, finally, we have the code for our module built. Putting it all together, it should look like the following code:
#!/usr/bin/python     #1
# -*- coding: utf-8 -*-    #2

import os     #3

def main():     #4
  module = AnsibleModule(    #5
    argument_spec = dict(    #6
      runlevel=dict(default=None, type='str'),     #7
    ),     #8
  )     #9

  # Ansible helps us run commands     #10
  rc, out, err = module.run_command('/sbin/runlevel')     #11
  if rc != 0:     #12
    module.fail_json(msg="Could not determine current runlevel.", rc=rc, err=err)     #13

  # Get the runlevel, exit if its not what we expect     #14
  last_runlevel, cur_runlevel = out.split(' ', 1)     #15
  cur_runlevel = cur_runlevel.rstrip()     #16
  if len(cur_runlevel) > 1:     #17
    module.fail_json(msg="Got unexpected output from runlevel.", rc=rc)     #18

  # Do we need to change anything     #19
  if (module.params['runlevel'] is None or module.params['runlevel'] == cur_runlevel):     #20
    module.exit_json(changed=False, runlevel=cur_runlevel)     #21

  # Check if we are root     #22
  uid = os.geteuid()     #23
  if uid != 0:     #24
    module.fail_json(msg="You need to be root to change the runlevel")     #25

  # Attempt to change the runlevel     #26
  rc, out, err = module.run_command('/sbin/init %s' % module.params['runlevel'])     #27
  if rc != 0:     #28
    module.fail_json(msg="Could not change runlevel.", rc=rc, err=err)     #29

  # Tell ansible the results     #30
  module.exit_json(changed=True, runlevel=cur_runlevel)     #31

# include magic from lib/ansible/module_common.py     #32
#<<INCLUDE_ANSIBLE_MODULE_COMMON>>     #33
main()     #34
```

您可以使用`test-module`脚本测试此模块，就像您测试 Bash 模块一样。但是，您需要小心，因为如果您使用`sudo`运行它，可能会重新启动您的机器或更改初始化级别为您不想要的级别。最好使用 Ansible 本身在远程测试机器上测试此模块。我们遵循本章前面描述的“在 Bash 中编写模块”部分相同的过程。我们创建一个使用该模块的 playbook，然后将该模块放在与 playbook 相同目录中创建的库目录中。这是我们需要使用的 playbook：

```
---
- name: Test the new init module
  hosts: testmachine
  user: root
  tasks:
    - name: Set the init level to 5
      init: runlevel=5
```

现在您应该能够尝试在远程机器上运行此模块。第一次运行时，如果机器尚未处于运行级别 5，则应该看到它更改运行级别。然后您应该能够再次运行它，以查看是否没有发生任何更改。您可能还想检查以确保模块在非 root 用户运行时能够正确失败。

# 外部清单

在第一章*开始使用 Ansible*中，我们看到 Ansible 需要一个清单文件，以便它知道其主机在哪里以及如何访问它们。Ansible 还允许您指定一个脚本，允许您从另一个源获取清单。外部清单脚本可以用任何您喜欢的语言编写，只要它们输出有效的 JSON。

外部清单脚本必须接受来自 Ansible 的两种不同调用。如果使用`–list`调用，它必须返回所有可用组和主机的列表。此外，它可能会被调用`--host`。在这种情况下，第二个参数将是主机名，脚本应返回该主机的变量列表。所有输出都应以 JSON 格式呈现，因此您应该使用自然支持它的语言。

让我们编写一个模块，它接受列出所有机器的 CSV 文件，并将其呈现给 Ansible 作为清单。如果您有一个允许您将机器列表导出为 CSV 的**配置管理数据库**（**CMDB**），或者有人在电子表格中记录他们的机器，这将非常方便。此外，它不需要 Python 之外的任何依赖项，因为 Python 已经包含了一个 CSV 处理模块。这只是将 CSV 文件解析为正确的数据结构，并将它们打印为 JSON 数据结构。以下是我们希望处理的示例 CSV 文件；您可能希望为您的环境中的机器定制它：

```
Group,Host,Variables
test,example,ansible_ssh_user=root
test,localhost,connection=local
```

这个文件需要转换为两种不同的 JSON 输出。当调用`--list`时，我们需要以以下形式输出整个内容：

```
{"test": ["example", "localhost"]}
```

当使用参数`--host example`调用时，它应该返回这个：

```
{"ansible_ssh_user": "root"}
```

以下是打开名为`machines.csv`的文件并在给出`--list`时生成组的字典的脚本：此外，当给出`--host`和主机名时，它会解析该主机的变量并将它们作为字典返回。脚本有很好的注释，所以您可以看到它在做什么。您可以手动运行脚本，使用`--list`和`--host`参数来确认它的行为是否正确。

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import csv
import json

def getlist(csvfile):
  # Init local variables
  glist = dict()
  rowcount = 0

  # Iterate over all the rows
  for row in csvfile:
    # Throw away the header (Row 0)
    if rowcount != 0:
      # Get the values out of the row
      (group, host, variables) = row

      # If this is the first time we've
      # read this group create an empty
      # list for it
      if group not in glist:
        glist[group] = list()

      # Add the host to the list
      glist[group].append(host)

    # Count the rows we've processed
    rowcount += 1

  return glist

def gethost(csvfile, host):
  # Init local variables
  rowcount = 0

  # Iterate over all the rows
  for row in csvfile:
    # Throw away the header (Row 0)
    if rowcount != 0 and row[1] == host:
      # Get the values out of the row
      variables = dict()
      for kvpair in row[2].split():
        key, value = kvpair.split('=', 1)
        variables[key] = value

      return variables

    # Count the rows we've processed
    rowcount += 1

command = sys.argv[1]

#Open the CSV and start parsing it
with open('machines.csv', 'r') as infile:
  result = dict()
  csvfile = csv.reader(infile)

  if command == '--list':
    result = getlist(csvfile)
  elif command == '--host':
    result = gethost(csvfile, sys.argv[2])

  print json.dumps(result)
```

现在您可以使用此清单脚本在使用 Ansible 时提供清单。测试一切是否正常工作的快速方法是使用`ping`模块测试与所有机器的连接。此命令不会测试主机是否在正确的组中；如果您想要这样做，您可以使用相同的`ping`模块命令，但是不是在所有机器上运行，而是只使用您想要测试的组**。**如果您的清单文件是可执行的，那么 Ansible 将运行它并使用输出。您还可以使用一个目录，Ansible 将包含其中的所有文件，并在它们可执行时运行它们。

```
**$ ansible -i csvinventory –list-hosts -m ping all**

```

与您在第一章中使用`ping`模块时类似，*开始使用 Ansible*，您应该看到类似以下的输出：

```
localhost | success >> {
  "changed": false,
  "ping": "pong"
}

example | success >> {
  "changed": false,
  "ping": "pong"
}
```

这表明您可以连接并使用 Ansible 在清单中的所有主机上。您可以使用相同的`-i`参数与`ansible-playbook`一起使用相同的清单运行您的 playbook。

# 扩展 Ansible

除了编写模块和外部清单脚本，您还可以扩展 Ansible 本身的核心功能。这允许您使用 Python 将更多功能包含到 Ansible 中。通过为 Ansible 编写插件，您可以执行以下操作：

+   使用连接插件控制其他机器的新方法

+   使用查找插件从 Ansible 外部的数据源中获取数据并进行循环或查找

+   使用过滤器插件为变量或模板添加新的过滤器

+   使用回调插件在 Ansible 内部发生某些操作时运行回调

要向您的 Ansible 项目添加额外的插件，我们在`ansible.cfg`文件中指定的插件目录中创建一个 Python 文件。或者，我们可以将包含我们插件的新目录添加到已经存在的目录列表中。

### 注意

不要删除任何现有目录，因为您将删除提供核心 Ansible 功能的插件，例如我们在本书中早期提到的插件。

编写 Ansible 插件时，应该专注于使它们尽可能灵活和可重用。这样，您最终可以将一些复杂性从您的剧本和模板中移除，转移到几个复杂的 Python 文件中。专注于插件的可重用性也意味着可以通过 GitHub 拉取请求将它们提交回 Ansible 项目。如果将插件提交回 Ansible，那么每个人都可以利用您的插件，并且您将在 Ansible 本身的开发中发挥作用。有关如何为 Ansible 做出贡献的更多信息，请参阅 Ansible 源代码中的`CONTRIBUTORS.md`文件。

## 连接插件

连接插件负责在远程机器之间中继文件，并执行模块。您无疑已经在本书前面使用了 SSH、本地和可能是 winrm 插件。

除了普通的`__init__()`方法外，连接插件必须实现以下方法：

| 方法 | 目的 |
| --- | --- |
| `connect()` | 这将打开到我们正在管理的主机的连接 |
| `exec_command()` | 这在托管主机上执行命令 |
| `put_file()` | 这将文件复制到托管主机 |
| `fetch_file()` | 这从托管主机下载文件 |
| `close()` | 这将关闭我们正在管理的主机的连接 |

## 查找插件

查找插件有两种用法：作为`lookup()`从外部包含数据，或者以`with_`样式循环遍历项目。甚至可以将两者结合起来，循环遍历外部数据，就像在`with_fileglob`查找插件中所做的那样。本书前面已经演示了几个查找插件，特别是在第三章的*循环*部分，*高级剧本*。

查找插件很容易编写，除了普通的`__init__()`方法外，它们只需要你实现一个`run()`方法。这个方法使用 Ansible `utils`包中的`listify_lookup_plugin_terms()`方法来收集传递给它的参数列表，并返回结果。例如，我们现在将演示一个查找插件，从 JSON 编码文件中读取数据：

```
import json

class LookupModule(object):
    def __init__(self, basedir=None, **kwargs):
        pass

    def run(self, terms, inject=None, **kwargs):
        with open(terms, 'r') as f:
            json_obj = json.load(f)

        return json_obj
```

这可以作为查找插件来获取复杂数据，或者如果文件包含 JSON 列表，则可以使用`with_jsonfile`进行循环。将前面的示例保存为`jsonfile.py`，放在您的查找插件目录之一中。您可以看到我们声明了一个名为`LookupModule`的新类；这是 Ansible 尝试在您的 Python 文件中找到的内容，因此您必须使用这个名称。然后，我们创建一个构造函数（名为`__init__`），以便 Ansible 可以创建我们的类。最后，我们创建一个简单的方法，它只是打开一个 JSON 文件，解析它，并将结果返回给 Ansible。

我们应该注意，这个例子真的很简化，只在当前工作目录中查找文件。稍后可以扩展以在角色文件目录或其他位置查找文件，以更好地符合其他 Ansible 模块设置的约定。

然后可以在剧本中像这样使用这个查找插件：

```
- name: Print the JSON data we received
  debug:
    msg: "{{ lookup('json', 'file.json') }}"
```

## 过滤器插件

过滤器插件是 Ansible 用于处理变量并从模板生成文件的 Jinja2 模板引擎的扩展。这些扩展可以在剧本中用于对变量进行数据处理，也可以在模板中用于在包含在文件中之前处理数据。它们通过将复杂性转移到 Python 文件中，使数据处理变得简单，并远离模板或 Ansible 配置。

过滤器插件与其他插件有些不同。要实现一个，首先编写一个简单的函数，它只需获取所需的输入并返回结果。其次，创建一个名为`FilterModule`的类，并在其中实现一个`filters`方法，该方法返回一个 Python 字典，其中键是过滤器名称，值是要调用的函数。

这是一个可以用来计算任何组中所需的最小服务器数量以避免分裂脑情况的插件的示例实现：在大多数系统中，此数字比可用节点的 50%多一个。

```
def quorum(list_of_machines):

    n = len(list_of_machines)
    quorum = n / 2 + 1

    return quorum

class FilterModule(object):
    def filters(self):
        return {
            'quorum': quorum,
        }
```

简而言之，此模块计算传递给它的列表中有多少项，将其除以 2，然后加 1。这都是整数运算，因此忽略了余数，并且所有内容都是整数，这适合我们的目的。

这个过滤器可以在 playbook 或模板中使用。例如，如果我们想要配置一个 Elasticsearch 集群以具有法定人数并避免分裂脑问题，我们将使用以下代码行：

```
discovery.zen.minimum_master_nodes: {{ play_hosts|quorum }}
```

这将获取此 play 正在运行的主机列表（从`play_hosts`变量中），然后计算需要多少个主机才能获得法定人数。

## 回调插件

回调插件用于向外部系统提供有关在 Ansible 中发生的操作的信息。如果在 Ansible 配置中的`callback_plugins`目录下找到它们，它们将自动激活。当 playbook 作为自动化任务运行时，它们通常很有用，因为它们可以通过标准输出以外的其他渠道提供反馈。回调插件有各种用途，如下所示：

+   在 playbook 结束时发送一封电子邮件，其中包含更改的统计信息

+   记录正在进行的更改的运行日志到`syslog`

+   当 playbook 任务失败时通知聊天频道

+   在更改时更新 CMDB 以确保对每个系统的配置的准确视图。

+   当 play 因为所有主机都失败而提前退出时向管理员发出警报。

回调插件是最复杂的插件，因为它们可以连接到 Ansible 的大多数功能。但是，只是因为有很多选项并不意味着您需要实现它们所有。您只需要实现您的回调将使用的那些。以下是您可以实现的方法列表，以及它们的描述：

+   `def on_any(self, *args, **kwargs)`: 这在调用任何其他回调之前调用。由于参数因回调而异，它将其参数扩展为`args`和`kwargs`。这种方法适用于日志记录。将其用于其他任何事情可能会变得非常复杂。

+   `runner_on_failed(self, host, res, ignore_errors=False)`: 这在任务失败后运行。`host`参数包含运行任务的主机，`res`包含 playbook 中的任务数据和任何返回的数据，`ignore_errors`包含一个布尔值，指定是否应忽略 playbook 指示的错误。

+   `runner_on_ok(self, host, res)`: 这在任务成功或异步作业的轮询成功后运行。参数`host`包含运行任务的主机，`res`包含 playbook 中的任务数据和任何返回的数据。

+   `runner_on_skipped(self, host, item=None)`: 这在任务被跳过后运行。参数`host`包含如果未被跳过则将运行任务的主机，`item`参数包含当前正在迭代的循环项。

+   `runner_on_unreachable(self, host, res)`: 当发现主机无法访问时运行。`host`参数包含无法访问的主机，`res`包含连接插件的错误消息。

+   `runner_on_no_hosts(self)`: 当没有任何主机启动任务时，此回调运行。它没有任何变量。

+   `runner_on_async_poll(self, host, res, jid, clock)`: 每当轮询异步作业的状态时运行。变量`host`包含正在轮询的主机，`res`包含轮询的详细信息，`jid`包含作业 ID，`clock`包含作业失败之前剩余的时间。

+   `runner_on_async_ok(self, host, res, jid)`: 当轮询完成且没有错误时运行。参数`host`包含被轮询的主机，`res`保存任务的结果，`jid`包含作业 ID。

+   `runner_on_async_failed(self, host, res, jid)`: 当轮询完成并出现错误时运行。参数`host`包含被轮询的主机，`res`保存任务的结果，`jid`包含作业 ID。

+   `playbook_on_start(self)`: 当使用`ansible-playbook`启动 playbook 时执行此回调。它不使用任何变量。

+   `playbook_on_notify(self, host, handler)`: 每当通知处理程序时运行此回调。因为这是在通知发生时而不是处理程序运行时运行的，所以对于每个处理程序可能会运行多次。它有两个变量：`host`存储了任务通知的主机名，`handler`存储了被通知的处理程序的名称。

+   `playbook_on_no_hosts_matched(self)`: 如果开始了一个不匹配任何主机的 play，则运行此回调。它没有任何变量。

+   `playbook_on_no_hosts_remaining(self)`: 当 play 中的所有主机都有错误且 play 无法继续时运行此回调。

+   `playbook_on_task_start(self, name, is_conditional)`: 此回调在每个任务之前运行，即使任务将被跳过也是如此。`name`变量设置为任务的名称，`is_conditional`设置为 when 子句的结果——如果任务将运行，则为`True`，否则为`False`。

+   `playbook_on_setup(self)`: 此回调在 setup 模块在主机上执行之前执行。无论包含多少主机，它只运行一次。它不包括任何变量。

+   `playbook_on_play_start(self, name)`: 此回调在每个 play 开始时运行。`name`变量包含正在开始的 play 的名称。

+   `playbook_on_stats(self, stats)`: 此回调在 playbook 结束之前运行，就在统计信息打印之前。`stats`变量包含 playbook 的详细信息。

# 总结

阅读完本章后，您现在应该能够使用 Bash 或其他任何您了解的语言构建模块。您应该能够安装模块，无论是从互联网上获取的还是自己编写的。我们还介绍了如何使用 Python 中的样板代码更有效地编写模块，并编写了一个库存脚本，允许您从外部来源获取库存。最后，我们介绍了通过编写连接、查找、过滤和回调插件向 Ansible 本身添加新功能。

我们已经尽量涵盖了您在了解 Ansible 时需要的大部分内容，但我们不可能涵盖一切。如果您想继续学习有关 Ansible 的知识，可以访问官方 Ansible 文档[`docs.ansible.com/`](http://docs.ansible.com/)。

Ansible 项目目前正在进行重写，最终将作为 2.0 版本发布。本书应该与此版本和以后的版本保持兼容，但会有一些未在此处介绍的新功能。在 Ansible 2.0 版本中，您可以期待以下功能，这些功能可能会在未来发生变化（因为尚未发布）：

+   在 playbook 中从失败中恢复的能力

+   允许您并行运行大量任务

+   与 Python 3 兼容

+   更容易调试，因为错误将包含行号
