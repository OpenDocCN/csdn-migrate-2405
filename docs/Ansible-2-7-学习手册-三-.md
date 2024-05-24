# Ansible 2.7 学习手册（三）

> 原文：[`zh.annas-archive.org/md5/89BF78DDE1DEE382F084F8254DF8B8DD`](https://zh.annas-archive.org/md5/89BF78DDE1DEE382F084F8254DF8B8DD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三部分：使用 Ansible 部署应用

本节将解释如何调试和测试 Ansible 以确保您的 Playbook 总是正常工作。您还将学习如何使用 Ansible 管理多个层、多个环境和多个部署。

本节包括以下章节：

+   第七章，*创建自定义模块*

+   第八章，*调试和错误处理*

+   第九章，*复杂环境*


# 第九章：创建自定义模块

本章将重点介绍如何编写和测试自定义模块。我们已经讨论了模块的工作原理以及如何在任务中使用它们。为了快速回顾，Ansible 中的一个模块是每次运行 Ansible 任务时传输和执行到你的远程主机上的代码片段（如果你使用了`local_action`，它也可以在本地运行）。

从我的经验来看，每当需要将某个特定功能暴露为一流任务时，就会编写自定义模块。虽然可以通过现有模块执行相同的功能，但为了实现最终目标，可能需要一系列任务（有时还包括命令和 shell 模块）。例如，假设你想通过**预启动执行环境**（**PXE**）配置服务器。没有自定义模块，你可能会使用一些 shell 或命令任务来完成这个任务。然而，通过自定义模块，你只需将所需参数传递给它，业务逻辑将嵌入到自定义模块中，以执行 PXE 启动。这使你能够编写更简单易读的 playbook，并提供了更好的可重用性，因为你只需创建一次模块，就可以在角色和 playbook 中的任何地方使用它。

你传递给模块的参数（只要它们以**键值**格式提供）将与模块一起在一个单独的文件中转发。Ansible 期望你的模块输出至少有两个变量（即，模块运行的结果），无论它是通过还是失败的，以及用户的消息 - 它们都必须以 JSON 格式提供。如果你遵循这个简单的规则，你可以根据自己的需要定制你的模块！

在本章中，我们将涵盖以下主题：

+   Python 模块

+   Bash 模块

+   Ruby 模块

+   测试模块

# 先决条件

当你选择特定的技术或工具时，通常从它提供的内容开始。你慢慢地了解哲学，然后开始构建工具以及它帮助你解决的问题。然而，只有当你深入了解它的工作原理时，你才真正感到舒适和掌控。在某个阶段，为了充分利用工具的全部功能，你将不得不以适合你特定需求的方式定制它。随着时间的推移，那些提供了方便的方式来插入新功能的工具会留下来，而那些没有的则会从市场上消失。Ansible 也是类似的情况。Ansible playbook 中的所有任务都是某种类型的模块，并且它加载了数百个模块。你几乎可以找到任何你可能需要的模块。然而，总会有例外，这就是通过添加自定义模块来扩展 Ansible 功能的力量所在。

Chef 提供了**轻量级资源和提供者**（**LWRPs**）来执行此操作，而 Ansible 允许您使用自定义模块扩展其功能。使用 Ansible，您可以使用您选择的任何语言编写模块（前提是您有该语言的解释器），而在 Chef 中，模块必须是 Ruby 编写的。Ansible 开发人员建议对于任何复杂模块都使用 Python，因为有内置支持来解析参数；几乎所有的***nix**系统默认都安装了 Python，并且 Ansible 本身也是用 Python 编写的。在本章中，我们还将学习如何使用其他语言编写模块。

要使自定义模块可用于 Ansible，您可以执行以下操作之一：

+   在`ANSIBLE_LIBRARY`环境变量中指定自定义模块的路径。

+   使用`--module-path`命令行选项。

+   将模块放在您的 Ansible 顶层目录中的`library`目录中，并在`ansible.cfg`文件的`[default]`部分中添加`library=library`。

您可以从本书的 GitHub 存储库中下载所有文件，网址为[`github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter07`](https://github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter07)。

现在我们已经了解了这些背景信息，让我们来看一些代码吧！

# 使用 Python 编写模块

Ansible 允许用户使用任何语言编写模块。但是，使用 Python 编写模块具有自己的优势。您可以利用 Ansible 的库来缩短您的代码 - 这是其他语言编写的模块所不具备的优势。借助 Ansible 库的帮助，解析用户参数、处理错误并返回所需值变得更加容易。此外，由于 Ansible 是用 Python 编写的，因此您将在整个 Ansible 代码库中使用相同的语言，使审查更加容易，可维护性更高。我们将看到两个自定义 Python 模块的示例，一个使用 Ansible 库，一个不使用，以便让您了解自定义模块的工作原理。在创建模块之前，请确保按照前一节中提到的方式组织您的目录结构。第一个示例创建了一个名为`check_user`的模块。为此，我们需要在 Ansible 顶层目录中的`library`文件夹中创建`check_user.py`文件。完整的代码可以在 GitHub 上找到：

```
def main(): 
    # Parsing argument file 
    args = {} 
    args_file = sys.argv[1] 
    args_data = file(args_file).read() 
    arguments = shlex.split(args_data) 
    for arg in arguments: 
        if '=' in arg: 
            (key, value) = arg.split('=') 
            args[key] = value 
    user = args['user'] 

    # Check if user exists 
    try: 
        pwd.getpwnam(user) 
        success = True 
        ret_msg = 'User %s exists' % user 
    except KeyError: 
        success = False 
        ret_msg = 'User %s does not exists' % user 
...
```

先前的自定义模块`check_user`，将检查用户是否存在于主机上。该模块期望来自 Ansible 的用户参数。让我们分解前面的模块，看看它的作用。我们首先声明 Python 解释器，并导入解析参数所需的库：

```
#!/usr/bin/env python 

import pwd 
import sys 
import shlex 
import json 
```

使用`sys`库，然后解析由 Ansible 在文件中传递的参数。参数的格式为`param1=value1 param2=value2`，其中`param1`和`param2`是参数，`value1`和`value2`是参数的值。有多种方式可以拆分参数并创建字典，我们选择了一种简单的方式来执行操作。我们首先通过空格字符拆分参数创建参数列表，然后通过`=`字符拆分参数将键和值分开，并将其赋给 Python 字典。例如，如果您有一个字符串，如`user=foo gid=1000`，那么您将首先创建一个列表，`["user=foo", "gid=1000"]`，然后循环遍历该列表以创建字典。此字典将是`{"user": "foo", "gid": 1000}`；此操作使用以下行执行：

```
def main(): 
    # Parsing argument file 
    args = {} 
    args_file = sys.argv[1] 
    args_data = file(args_file).read() 
    arguments = shlex.split(args_data) 
    for arg in arguments: 
        if '=' in arg: 
            (key, value) = arg.split('=') 
            args[key] = value 
    user = args['user'] 
```

我们根据空格字符分隔参数，因为这是核心 Ansible 模块遵循的标准。您可以使用任何分隔符来代替空格，但我们建议您保持统一性。

一旦我们有了用户参数，我们就会检查该用户是否存在于主机上，具体如下：

```
    # Check if user exists 
    try: 
        pwd.getpwnam(user) 
        success = True 
        ret_msg = 'User %s exists' % user 
    except KeyError: 
        success = False 
        ret_msg = 'User %s does not exists' % user 
```

我们使用`pwd`库来检查用户的`passwd`文件。为简单起见，我们使用两个变量：一个用于存储成功或失败的消息，另一个用于存储用户的消息。最后，我们使用`try-catch`块中创建的变量来检查模块是否成功或失败：

```
    # Error handling and JSON return 
    if success: 
        print json.dumps({ 
            'msg': ret_msg 
        }) 
        sys.exit(0) 
    else: 
        print json.dumps({ 
            'failed': True, 
            'msg': ret_msg 
        }) 
        sys.exit(1) 
```

如果模块成功，则会以`0`的退出代码（`exit(0)`）退出执行；否则，它将以非零代码退出。Ansible 将查找失败的变量，如果它设置为`True`，则退出，除非您已明确要求 Ansible 使用`ignore_errors`参数忽略错误。您可以像使用 Ansible 的任何其他核心模块一样使用自定义模块。为了测试自定义模块，我们将需要一个 playbook，所以让我们使用以下代码创建`playbooks/check_user.yaml`文件：

```
---
- hosts: localhost
  connection: local
  vars:
    user_ok: root
    user_ko: this_user_does_not_exists
  tasks:
    - name: 'Check if user {{ user_ok }} exists'
      check_user:
        user: '{{ user_ok }}'
    - name: 'Check if user {{ user_ko }} exists'
      check_user:
        user: '{{ user_ko }}'
```

如您所见，我们像使用任何其他核心模块一样使用了`check_user`模块。Ansible 将通过将模块复制到远程主机并在单独的文件中使用参数执行该模块。让我们看看这个 playbook 如何运行，使用以下代码：

```
ansible-playbook playbooks/check_user.yaml
```

我们应该收到以下输出：

```
PLAY [localhost] ***************************************************

TASK [Gathering Facts] *********************************************
ok: [localhost]

TASK [Check if user root exists] ***********************************
ok: [localhost]

TASK [Check if user this_user_does_not_exists exists] **************
fatal: [localhost]: FAILED! => {"changed": false, "msg": "User this_user_does_not_exists does not exists"}
 to retry, use: --limit @playbooks/check_user.retry

PLAY RECAP *********************************************************
localhost                   : ok=2 changed=0 unreachable=0 failed=1
```

如预期，由于我们有`root`用户，但没有`this_user_does_not_exists`，它通过了第一个检查，但在第二个检查失败了。

Ansible 还提供了一个 Python 库来解析用户参数并处理错误和返回值。现在是时候探索 Ansible Python 库如何使您的代码更短、更快且更不容易出错了。为此，让我们创建一个名为`library/check_user_py2.py`的文件，其中包含以下代码。完整的代码可在 GitHub 上找到：

```
#!/usr/bin/env python 

import pwd 
from ansible.module_utils.basic import AnsibleModule 

def main(): 
    # Parsing argument file 
    module = AnsibleModule( 
        argument_spec = dict( 
            user = dict(required=True) 
        ) 
    ) 
    user = module.params.get('user') 

    # Check if user exists 
    try: 
        pwd.getpwnam(user) 
        success = True 
        ret_msg = 'User %s exists' % user 
    except KeyError: 
        success = False 
        ret_msg = 'User %s does not exists' % user 

...
```

让我们分解前面的模块，看看它是如何工作的，具体如下：

```
#!/usr/bin/env python 

import pwd 
from ansible.module_utils.basic import AnsibleModule 
```

如您所见，我们不再导入`sys`，`shlex`和`json`； 我们不再使用它们，因为所有需要它们的操作现在都由 Ansible 的`module_utils`模块完成：

```
    # Parsing argument file 
    module = AnsibleModule( 
        argument_spec = dict( 
            user = dict(required=True) 
        ) 
    ) 
    user = module.params.get('user') 
```

以前，我们对参数文件进行了大量处理，以获取最终的用户参数。 Ansible 通过提供一个`AnsibleModule`类来简化这个过程，该类自行处理所有处理并为我们提供最终参数。 `required=True`参数意味着该参数是必需的，如果未传递该参数，则执行将失败。 默认值`required`为`False`，这将允许用户跳过该参数。 然后，您可以通过在`module.params`字典上调用`module.params`上的`get`方法来访问参数的值。 远程主机上检查用户的逻辑将保持不变，但错误处理和返回方面将如下更改：

```
    # Error handling and JSON return 
    if success: 
        module.exit_json(msg=ret_msg) 
    else: 
        module.fail_json(msg=ret_msg) 
```

使用`AnsibleModule`对象的一个优点是你有一个非常好的设施来处理返回值到 playbook。 我们将在下一节中更深入地讨论。

我们本可以将检查用户和返回方面的逻辑压缩在一起，但我们将它们分开以提高可读性。

要验证一切是否按预期工作，我们可以在`playbooks/check_user_py2.yaml`中创建一个新的 playbook，并使用以下代码：

```
---
- hosts: localhost
  connection: local
  vars:
    user_ok: root
    user_ko: this_user_does_not_exists
  tasks:
    - name: 'Check if user {{ user_ok }} exists'
      check_user_py2:
        user: '{{ user_ok }}'
    - name: 'Check if user {{ user_ko }} exists'
      check_user_py2:
        user: '{{ user_ko }}'
```

你可以使用以下代码来运行它：

```
ansible-playbook playbooks/check_user_py2.yaml
```

然后，我们应该收到以下输出：

```
PLAY [localhost] ***************************************************

TASK [Gathering Facts] *********************************************
ok: [localhost]

TASK [Check if user root exists] ***********************************
ok: [localhost]

TASK [Check if user this_user_does_not_exists exists] **************
fatal: [localhost]: FAILED! => {"changed": false, "msg": "User this_user_does_not_exists does not exists"}
 to retry, use: --limit @playbooks/check_user_py2.retry

PLAY RECAP *********************************************************
localhost                   : ok=2 changed=0 unreachable=0 failed=1
```

这个输出与我们的预期一致。

# 使用 exit_json 和 fail_json

Ansible 通过`exit_json`和`fail_json`方法提供了更快和更短的处理成功和失败的方法，分别。 您可以直接将消息传递给这些方法，Ansible 将处理剩余的部分。 您还可以将其他变量传递给这些方法，并且 Ansible 将这些变量打印到`stdout`。 例如，除了消息之外，您可能还想打印用户的`uid`和`gid`参数。 您可以通过将这些变量分隔符传递给`exit_json`方法来实现这一点。

让我们看看如何将多个值返回到`stdout`，如下面的代码所示，放置在`library/check_user_id.py`中。 完整的代码在 GitHub 上可用：

```
#!/usr/bin/env python 

import pwd 
from ansible.module_utils.basic import AnsibleModule 

class CheckUser: 
    def __init__(self, user): 
        self.user = user 

    # Check if user exists 
    def check_user(self): 
        uid = '' 
        gid = '' 
        try: 
            user = pwd.getpwnam(self.user) 
            success = True 
            ret_msg = 'User %s exists' % self.user 
            uid = user.pw_uid 
            gid = user.pw_gid 
        except KeyError: 
            success = False 
            ret_msg = 'User %s does not exists' % self.user 
        return success, ret_msg, uid, gid 

...
```

正如你所见，我们返回了用户的`uid`和`gid`参数，以及消息`msg`。 你可以有多个值，Ansible 将以字典格式打印所有这些值。 创建一个包含以下内容的 playbook：`playbooks/check_user_id.yaml`：

```
---
- hosts: localhost
  connection: local
  vars:
    user: root
  tasks:
    - name: 'Retrive {{ user }} data if it exists'
      check_user_id:
        user: '{{ user }}'
      register: user_data
    - name: 'Print user {{ user }} data'
      debug:
        msg: '{{ user_data }}'
```

你可以使用以下代码来运行它：

```
ansible-playbook playbooks/check_user_id.yaml
```

我们应该收到以下输出：

```
PLAY [localhost] ***************************************************

TASK [Gathering Facts] *********************************************
ok: [localhost] 
TASK [Retrive root data if it exists] ******************************
ok: [localhost]

TASK [Print user root data] ****************************************
ok: [localhost] => {
 "msg": {
 "changed": false, 
 "failed": false, 
 "gid": 0, 
 "msg": "User root exists", 
 "uid": 0
 }
}

PLAY RECAP *********************************************************
localhost : ok=3 changed=0 unreachable=0 failed=0
```

在这里，我们完成了两种方法的工作，这反过来又帮助我们找到了在 Ansible 中处理成功和失败的更快方式，同时向用户传递参数。

# 测试 Python 模块

正如你所见，你可以通过创建非常简单的 playbooks 来测试你的模块。 为此，我们需要克隆 Ansible 官方仓库（如果你还没有这样做）：

```
git clone git://github.com/ansible/ansible.git --recursive
```

接下来，像下面这样来源一个环境文件：

```
source ansible/hacking/env-setup
```

现在我们可以使用`test-module`工具通过将文件名作为命令行参数来运行脚本：

```
ansible/hacking/test-module -m library/check_user_id.py -a "user=root"
```

结果将类似于以下输出：

```
* including generated source, if any, saving to: /home/fale/.ansible_module_generated 
* ansiballz module detected; extracted module source to: /home/fale/debug_dir 
*********************************** 
RAW OUTPUT 

{"msg": "User root exists", "invocation": {"module_args": {"user": "root"}}, "gid": 0, "uid": 0, "changed": false} 

*********************************** 
PARSED OUTPUT 
{ 
    "changed": false, 
    "gid": 0, 
    "invocation": { 
        "module_args": { 
            "user": "root" 
        } 
    }, 
    "msg": "User root exists", 
    "uid": 0 
}
```

如果你没有使用`AnsibleModule`，直接执行脚本也很容易。这是因为该模块需要很多 Ansible 特定的变量，所以"模拟" Ansible 运行比实际运行 Ansible 本身更复杂。

# 使用 bash 模块

Ansible 中的 Bash 模块与任何其他 bash 脚本没有任何区别，唯一不同之处在于它们将数据打印在`stdout`上。Bash 模块可以是非常简单的，比如检查远程主机上是否有进程正在运行，也可以是运行一些更复杂的命令。

如前所述，一般推荐使用 Python 编写模块。在我看来，第二选择（仅适用于非常简单的模块）是`bash` 模块，因为它简单易用，用户基础广泛。

让我们创建一个名为`library/kill_java.sh`的文件，并包含以下内容：

```
#!/bin/bash 
source $1 

SERVICE=$service_name 

JAVA_PIDS=$(/usr/java/default/bin/jps | grep ${SERVICE} | awk '{print $1}') 

if [ ${JAVA_PIDS} ]; then 
    for JAVA_PID in ${JAVA_PIDS}; do 
        /usr/bin/kill -9 ${JAVA_PID} 
    done 
    echo "failed=False msg=\"Killed all the orphaned processes for ${SERVICE}\"" 
    exit 0 
else 
    echo "failed=False msg=\"No orphaned processes to kill for ${SERVICE}\"" 
    exit 0 
fi
```

前述的`bash`模块将使用`service_name`参数并强制终止所有属于该服务的 Java 进程。正如你所知，Ansible 将参数文件传递给模块。然后我们使用`$1` source 来来源参数文件。这将实际上设置一个名为`service_name`的环境变量。然后我们使用`$service_name`来访问这个变量，如下所示：

```
source $1 

SERVICE=$service_name 
```

然后我们检查我们是否得到了该服务的 `PIDS`，并遍历这些 `PIDS` 来强制终止所有与 `service_name` 匹配的 Java 进程。一旦它们被终止，我们通过`failed=False`退出模块，并且附上一个退出码为`0`的消息，如下所示：

```
if [ ${JAVA_PIDS} ]; then 
    for JAVA_PID in ${JAVA_PIDS}; do 
        /usr/bin/kill -9 ${JAVA_PID} 
    done 
    echo "failed=False msg=\"Killed all the orphaned processes for ${SERVICE}\"" 
    exit 0 
```

如果我们没有找到该服务的正在运行的进程，我们仍将以退出码`0`退出模块，因为终止 Ansible 运行可能没有意义：

```
else 
    echo "failed=False msg=\"No orphaned processes to kill for ${SERVICE}\"" 
    exit 0 
fi 
```

你也可以通过打印`failed=True`并将退出码设置为`1`来终止 Ansible 运行。

如果语言本身不支持 JSON，则 Ansible 允许返回键值输出。这使得 Ansible 更加友好于开发人员和系统管理员，并允许以您选择的任何语言编写自定义模块。让我们通过将参数文件传递给模块来测试`bash`模块。现在我们可以在`/tmp/arguments`中创建一个参数文件，将`service_name`参数设置为`jenkins`，如下所示：

```
service_name=jenkins
```

现在，你可以像运行任何其他 bash 脚本一样运行模块。让我们看看当我们用以下代码运行时会发生什么：

```
bash library/kill_java.sh /tmp/arguments
```

我们应该收到以下输出：

```
failed=False msg="No orphaned processes to kill for jenkins"
```

如预期，即使本地主机上没有运行 Jenkins 进程，模块也没有失败。

如果你收到 `jps command does not exists` 错误而不是上述输出，那么你的机器可能缺少 Java。如果是这样，你可以按照操作系统的说明安装它：[`www.java.com/en/download/help/download_options.xml`](https://www.java.com/en/download/help/download_options.xml)。

# 使用 Ruby 模块

在 Ruby 中编写模块与在 Python 或 bash 中编写模块一样简单。您只需要注意参数、错误、返回语句，当然还需要了解基本的 Ruby！让我们创建`library/rsync.rb`文件，其中包含以下代码。完整代码可在 GitHub 上找到：

```
#!/usr/bin/env ruby 

require 'rsync' 
require 'json' 

src = '' 
dest = '' 
ret_msg = '' 
SUCCESS = '' 

def print_message(state, msg, key='failed') 
    message = { 
        key => state, 
        "msg" => msg 
    } 
    print message.to_json 
    exit 1 if state == false 
    exit 0 
...
```

在前述模块中，我们首先处理用户参数，然后使用`rsync`库复制文件，最后返回输出。

要使用这个功能，您需要确保系统上存在用于 Ruby 的`rsync`库。为此，您可以执行以下命令：

```
gem install rsync
```

让我们逐步分解上述代码，看看它是如何工作的。

我们首先编写一个名为`print_message`的方法，该方法将以 JSON 格式打印输出。通过这样做，我们可以在多个地方重用相同的代码。请记住，如果要使 Ansible 运行失败，则您的模块的输出应包含`failed=true`；否则，Ansible 将认为模块成功并将继续进行下一个任务。获得的输出如下所示：

```
#!/usr/bin/env ruby 

require 'rsync' 
require 'json' 

src = '' 
dest = '' 
ret_msg = '' 
SUCCESS = '' 

def print_message(state, msg, key='failed') 
    message = { 
        key => state, 
        "msg" => msg 
    } 
    print message.to_json 
    exit 1 if state == false 
    exit 0 
end
```

然后我们处理参数文件，其中包含由空格字符分隔的键值对。这类似于我们之前使用 Python 模块时所做的，我们负责解析参数。我们还执行一些检查，以确保用户没有漏掉任何必需的参数。在这种情况下，我们检查是否已指定了`src`和`dest`参数，并在未提供参数时打印一条消息。进一步的检查可能包括参数的格式和类型。您可以添加这些检查和您认为重要的任何其他检查。例如，如果您的参数之一是`date`参数，则需要验证输入是否确实是正确的日期。考虑以下代码片段，其中显示了讨论过的参数：

```
args_file = ARGV[0] 
data = File.read(args_file) 
arguments = data.split(" ") 
arguments.each do |argument| 
    print_message(false, "Argument should be name-value pairs. Example name=foo") if not argument.include?("=") 
    field, value = argument.split("=") 
    if field == "src" 
        src = value 
    elsif field == "dest" 
        dest = value 
    else print_message(false, "Invalid argument provided. Valid arguments are src and dest.") 
    end 
end 
```

一旦我们拥有了必需的参数，我们将使用`rsync`库复制文件，如下所示：

```
result = Rsync.run("#{src}", "#{dest}") 
if result.success? 
    success = true 
    ret_msg = "Copied file successfully" 
else 
    success = false 
    ret_msg = result.error 
end 
```

最后，我们检查`rsync`任务是通过还是失败，然后调用`print_message`函数将输出打印在`stdout`上，如下所示：

```
if success 
    print_message(false, "#{ret_msg}") 
else 
    print_message(true, "#{ret_msg}") 
end
```

您可以通过简单地将参数文件传递给模块来测试您的 Ruby 模块。为此，我们可以创建`/tmp/arguments`文件，并包含以下内容：

```
src=/etc/resolv.conf dest=/tmp/resolv_backup.conf
```

现在让我们运行模块，如下所示：

```
ruby library/rsync.rb /tmp/arguments
```

我们将收到以下输出：

```
{"failed":false,"msg":"Copied file successfully"} 
```

我们将留下`serverspec`测试由您完成。

# 测试模块

由于对其目的和其为业务带来的好处的理解不足，测试经常被低估。测试模块与测试 Ansible playbook 的任何其他部分一样重要，因为模块中的微小更改可能会破坏整个 playbook。我们将以本章的 *使用 Python 编写模块* 部分中编写的 Python 模块为例，并使用 Python 的 `nose` 测试框架编写一个集成测试。虽然也鼓励进行单元测试，但对于我们的场景，即检查远程用户是否存在，集成测试更有意义。

`nose` 是一个 Python 测试框架；您可以在 [`nose.readthedocs.org/en/latest/`](https://nose.readthedocs.org/en/latest/) 上找到有关该测试框架的更多信息。

为了对模块进行测试，我们将先前的模块转换为一个 Python 类，以便我们可以直接将该类导入到我们的测试中，并仅运行模块的主要逻辑。以下代码显示了重组的 `library/check_user_py3.py` 模块，该模块将检查远程主机上是否存在用户。完整代码可在 GitHub 上找到：

```
#!/usr/bin/env python 

import pwd 
from ansible.module_utils.basic import AnsibleModule 

class User: 
    def __init__(self, user): 
        self.user = user 

    # Check if user exists 
    def check_if_user_exists(self): 
        try: 
            user = pwd.getpwnam(self.user) 
            success = True 
            ret_msg = 'User %s exists' % self.user 
        except KeyError: 
            success = False 
            ret_msg = 'User %s does not exists' % self.user 
        return success, ret_msg 

 ...
```

正如您在上述代码中所见，我们创建了一个名为 `User` 的类。我们实例化了该类并调用了 `check_if_user_exists` 方法来检查用户是否实际存在于远程计算机上。现在是时候编写集成测试了。我们假设您已经在系统上安装了 `nose` 包。如果没有，不用担心！您仍然可以使用以下命令安装该包：

```
pip install nose
```

现在让我们在 `library/test_check_user_py3.py` 中编写集成测试文件，如下所示：

```
from nose.tools import assert_equals, assert_false, assert_true 
import imp 
imp.load_source("check_user","check_user_py3.py") 
from check_user import User 

def test_check_user_positive(): 
    chkusr = User("root") 
    success, ret_msg = chkusr.check_if_user_exists() 
    assert_true(success) 
    assert_equals('User root exists', ret_msg) 

def test_check_user_negative(): 
    chkusr = User("this_user_does_not_exists") 
    success, ret_msg = chkusr.check_if_user_exists() 
    assert_false(success) 
    assert_equals('User this_user_does_not_exists does not exists', ret_msg) 
```

在上述集成测试中，我们导入了 `nose` 包和我们的 `check_user` 模块。我们通过传递我们想要检查的用户来调用 `User` 类。然后，我们通过调用 `check_if_user_exists()` 方法来检查用户是否存在于远程主机上。`nose` 方法 - `assert_true`、`assert_false` 和 `assert_equals` - 可以用于比较预期值与实际值。只有当 `assert` 方法通过时，测试也会通过。您可以通过具有以 `test_` 开头的多个方法来在同一个文件中拥有多个测试；例如，`test_check_user_positive()` 和 `test_check_user_negative()` 方法。`nose` 测试将获取所有以 `test_` 开头的方法并执行它们。

正如您所见，我们实际上为一个函数创建了两个测试。这是测试的一个关键部分。始终尝试您知道会成功的情况，但也不要忘记测试您期望失败的情况。

现在我们可以通过运行以下代码使用 `nose` 来测试它是否正常工作：

```
cd library
nosetests -v test_check_users_py3.py
```

您应该会收到类似以下代码块的输出：

```
test_check_user_py3.test_check_user_positive ... ok test_check_user_py3.test_check_user_negative ... ok --------------------------------------------------- Ran 2 tests in 0.001sOK
```

正如您所见，测试通过了，因为主机上存在 `root` 用户，而 `this_user_does_not_exists` 用户不存在。

我们使用 `nose` 测试的 `-v` 选项来启用 **详细模式**。

对于更复杂的模块，我们建议您编写单元测试和集成测试。您可能会想知道为什么我们没有使用 `serverspec` 来测试模块。

我们仍然建议将 `serverspec` 测试作为 playbook 的功能测试的一部分进行运行；然而，对于单元测试和集成测试，建议使用知名框架。同样，如果您编写了 Ruby 模块，我们建议您使用诸如 `rspec` 等框架为其编写测试。如果您的自定义 Ansible 模块具有多个参数和多个组合，则您将编写更多的测试来测试每个场景。最后，我们建议您将所有这些测试作为您的 CI 系统的一部分运行，无论是 Jenkins、Travis 还是其他任何系统。

# 摘要

到此，我们结束了这一小而重要的章节，重点介绍了如何通过编写自定义模块来扩展 Ansible。您学会了如何使用 Python、bash 和 Ruby 来编写自己的模块。我们还学习了如何为模块编写集成测试，以便将其集成到您的 CI 系统中。希望未来通过使用模块来扩展 Ansible 的功能将会更加容易！

在下一章中，我们将进入供应、部署和编排的世界，看看当我们为环境中的各种实例提供新的实例或者想要将软件更新部署到各种实例时，Ansible 如何解决我们的基础设施问题。我们承诺这段旅程将会很有趣！


# 第十章：调试和错误处理

像软件代码一样，测试基础架构代码是一项非常重要的任务。在生产环境中最好没有未经测试的代码浮现，尤其是当您有严格的客户 SLA 需要满足时，即使对于基础架构也是如此。在本章中，我们将看到语法检查、在不将代码应用于机器上进行测试（no-op 模式）以及用于 playbook 的功能测试，playbook 是 Ansible 的核心，触发您想在远程主机上执行的各种任务。建议您将其中一些集成到您为 Ansible 设置的**持续集成**（**CI**）系统中，以更好地测试您的 playbook。我们将看到以下要点：

+   语法检查

+   带有和不带有`--diff`的检查模式

+   功能测试

作为功能测试的一部分，我们将关注以下内容：

+   对系统最终状态的断言

+   使用标签进行测试

+   使用`--syntax-check`选项

+   使用`ANSIBLE_KEEP_REMOTE_FILES`和`ANSIBLE_DEBUG`标志

然后，我们将看看如何处理异常以及如何自愿触发错误。

# 技术要求

对于本章，除了常规要求外，没有特定要求，例如 Ansible、Vagrant 和一个 shell。 

您可以从本书的 GitHub 存储库中下载所有文件，网址为[`github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter08`](https://github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter08)。

# 语法检查

每次运行 playbook 时，Ansible 首先检查 playbook 文件的语法。如果遇到错误，Ansible 会报告语法错误，并且不会继续，除非您修复了该错误。仅当运行`ansible-playbook`命令时才执行此语法检查。在编写大型 playbook 或包含任务文件时，可能很难修复所有错误；这可能会浪费更多时间。为了应对这种情况，Ansible 提供了一种方式，让您随着 playbook 的编写进度来检查您的 YAML 语法。对于此示例，我们将需要创建名为`playbooks/setup_apache.yaml`的文件，并包含以下内容：

```
---
- hosts: all
  tasks: 
    - name: Install Apache 
      yum: 
        name: httpd 
        state: present 
      become: True
    - name: Enable Apache 
    service: 
        name: httpd 
        state: started 
        enabled: True 
      become: True
```

现在我们有了示例文件，我们需要用`--syntax-check`参数运行它；因此，您需要按照以下方式调用 Ansible：

```
ansible-playbook playbooks/setup_apache.yaml --syntax-check
```

`ansible-playbook`命令检查了`setup_apache.yml` playbook 的 YAML 语法，并显示了 playbook 的语法是正确的。让我们看看 playbook 中无效语法导致的结果错误：

```
ERROR! Syntax Error while loading YAML.
  did not find expected '-' indicator

The error appears to have been in '/home/fale/Learning-Ansible-2.X-Third-Edition/Ch8/playbooks/setup_apache.yaml': line 10, column 5, but may
be elsewhere in the file depending on the exact syntax problem.

The offending line appears to be:

    - name: Enable Apache
    service:
    ^ here
```

错误显示`Enable Apache`任务中存在缩进错误。Ansible 还会提供错误的行号、列号和发现错误的文件名（即使这并不是确切错误位置的保证）。这肯定应该是您为 Ansible 的 CI 运行的基本测试之一。

# 检查模式

检查模式（也称为**dry-run**或**no-op 模式**）将以无操作模式运行你的 playbook - 也就是说，它不会将任何更改应用于远程主机; 相反，它只会显示运行任务时将引入的更改。检查模式是否实际启用取决于每个模块。有一些命令可能会引起你的兴趣。所有这些命令都必须在`/usr/lib/python2.7/site-packages/ansible/modules`或你的 Ansible 模块文件夹所在的位置运行（根据你使用的操作系统以及你安装 Ansible 的方式，可能存在不同的路径）。

要计算安装的可用模块数量，你可以执行此命令：

```
find . -type f | grep '.py$' | grep -v '__init__' | wc -l 
```

使用 Ansible 2.7.2，此命令的结果是`2095`，因为 Ansible 有那么多模块。

如果你想看看有多少支持检查模式的模块，你可以运行以下代码：

```
grep -r 'supports_check_mode=True' | awk -F: '{print $1}' | sort | uniq | wc -l 
```

使用 Ansible 2.7.2，此命令的结果是`1239`。

你可能还会发现以下命令对于列出支持检查模式的所有模块很有用：

```
grep -r 'supports_check_mode=True' | awk -F: '{print $1}' | sort | uniq 
```

这有助于你测试 playbook 的行为方式，并在将其运行在生产服务器之前检查是否可能存在任何故障。你只需简单地在`ansible-playbook`命令中传递`--check`选项来运行检查模式下的 playbook。让我们看看检查模式如何与`setup_apache.yml` playbook 一起运行，运行以下代码：

```
ansible-playbook --check -i ws01, playbooks/setup_apache.yaml
```

结果将如下所示：

```
PLAY [all] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws01]

TASK [Install Apache] ************************************************
changed: [ws01]

TASK [Enable Apache] *************************************************
changed: [ws01]

PLAY RECAP ***********************************************************
ws01                          : ok=3 changed=2 unreachable=0 failed=0
```

在上述运行中，Ansible 不会在目标主机上进行更改，而是会突出显示在实际运行期间将发生的所有更改。从上述运行中，你可以发现`httpd`服务已经安装在目标主机上。因此，Ansible 对该任务的退出消息是 OK：

```
TASK [Install Apache] ************************************************
changed: [ws01]
```

但是，对于第二个任务，它发现`httpd`服务在目标主机上未运行：

```
TASK [Enable Apache] *************************************************
changed: [ws01]
```

当你再次运行上述的 playbook 时，如果没有启用检查模式，Ansible 会确保服务状态正在运行。

# 使用--diff 指示文件之间的差异

在检查模式下，你可以使用`--diff`选项来显示将应用于文件的更改。为了能够看到`--diff`选项的使用，我们需要创建一个`playbooks/setup_and_config_apache.yaml` playbook，以匹配以下内容：

```
- hosts: all
  tasks: 
    - name: Install Apache 
      yum: 
        name: httpd 
        state: present 
      become: True
    - name: Enable Apache 
      service: 
        name: httpd 
        state: started 
        enabled: True 
      become: True
    - name: Ensure Apache userdirs are properly configured
      template:
        src: ../templates/userdir.conf
        dest: /etc/httpd/conf.d/userdir.conf
      become: True
```

正如你所看到的，我们添加了一个任务，将确保`/etc/httpd/conf.d/userdir.conf`文件处于特定状态。

我们还需要创建一个模板文件，放置在`templates/userdir.conf`中，并包含以下内容（完整文件可在 GitHub 上找到）：

```
#
# UserDir: The name of the directory that is appended onto a user's home
# directory if a ~user request is received.
#
# The path to the end user account 'public_html' directory must be
# accessible to the webserver userid. This usually means that ~userid
# must have permissions of 711, ~userid/public_html must have permissions
# of 755, and documents contained therein must be world-readable.
# Otherwise, the client will only receive a "403 Forbidden" message.
#
<IfModule mod_userdir.c>
    #
    # UserDir is disabled by default since it can confirm the presence
    # of a username on the system (depending on home directory
    # permissions).
    #
    UserDir enabled

  ...

```

在此模板中，我们仅更改了`UserDir enabled`行，默认情况下为`UserDir disabled`。

`--diff`选项与`file`模块不兼容；你必须仅使用`template`模块。

现在我们可以使用以下命令测试此结果：

```
ansible-playbook -i ws01, playbooks/setup_and_config_apache.yaml --diff --check 
```

正如你所看到的，我们正在使用`--check`参数，确保这将是一个干运行。我们将收到以下输出：

```
PLAY [all] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws01]

TASK [Install Apache] ************************************************
ok: [ws01]

TASK [Enable Apache] *************************************************
ok: [ws01]

TASK [Ensure Apache userdirs are properly configured] ****************
--- before: /etc/httpd/conf.d/userdir.conf
+++ after: /home/fale/.ansible/tmp/ansible-local-6756FTSbL0/tmpx9WVXs/userdir.conf
@@ -14,7 +14,7 @@
 # of a username on the system (depending on home directory
 # permissions).
 #
- UserDir disabled
+ UserDir enabled

 #
 # To enable requests to /~user/ to serve the user's public_html

changed: [ws01]

PLAY RECAP ***********************************************************
ws01                          : ok=4 changed=1 unreachable=0 failed=0 
```

我们可以看到，Ansible 比较远程主机的当前文件与源文件；以 "+" 开头的行表示向文件中添加了一行，而 "-" 表示删除了一行。

你也可以使用 `--diff` 选项而不用 `--check`，这将允许 Ansible 进行指定的更改并显示两个文件之间的差异。

在 CI 测试的一部分中，将 `--diff` 和 `--check` 模式一起使用作为测试步骤，可以断言有多少步骤在运行过程中发生了变化。另一个可以同时使用这些功能的情况是部署过程的一部分，用于检查运行 Ansible 时会发生什么变化。

有时候会出现这样的情况——尽管不应该出现，但有时候确实会出现——你在一台机器上很长一段时间没有运行 playbook，而你担心再次运行会破坏某些东西。使用这些选项可以帮助你了解到这只是你的担忧，还是一个真正的风险。

# Ansible 中的功能测试

维基百科称功能测试是一种**质量保证**（**QA**）过程和一种基于所测试软件组件的规格的黑盒测试。功能测试通过提供输入并检查输出来测试函数；内部程序结构很少被考虑。在基础设施方面，在代码方面同样重要。

从基础设施的角度来看，就功能测试而言，我们在实际机器上测试 Ansible 运行的输出。Ansible 提供了多种执行 playbook 的功能测试的方式，让我们来看看其中一些最常用的方法。

# 使用 `assert` 进行功能测试

仅当你想要检查任务是否会在主机上改变任何内容时，`check` 模式才会起作用。当你想检查你的模块的输出是否符合预期时，这并没有帮助。例如，假设你编写了一个模块来检查端口是开启还是关闭。为了测试这一点，你可能需要检查你的模块的输出，看它是否与期望的输出匹配。为了执行这样的测试，Ansible 提供了一种将模块的输出与期望的输出直接进行比较的方法。

让我们通过创建 `playbooks/assert_ls.yaml` 文件，并使用以下内容来查看它是如何工作的：

```
---
- hosts: all
  tasks: 
    - name: List files in /tmp 
      command: ls /tmp 
      register: list_files 
    - name: Check if file testfile.txt exists 
      assert: 
        that: 
          - "'testfile.txt' in list_files.stdout_lines" 
```

在上述 playbook 中，我们在目标主机上运行 `ls` 命令，并将该命令的输出记录在 `list_files` 变量中。接下来，我们要求 Ansible 检查 `ls` 命令的输出是否具有期望的结果。我们使用 `assert` 模块来实现这一点，该模块使用某些条件检查来验证任务的 `stdout` 值是否符合用户的预期输出。让我们运行上述 playbook，看看 Ansible 返回什么输出，使用以下命令：

```
ansible-playbook -i ws01, playbooks/assert_ls.yaml
```

由于我们没有这个文件，所以我们会收到以下输出：

```
PLAY [all] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws01]

TASK [List files in /tmp] ********************************************
changed: [ws01]

TASK [Check if file testfile.txt exists] *****************************
fatal: [ws01]: FAILED! => {
 "assertion": "'testfile.txt' in list_files.stdout_lines", 
 "changed": false, 
 "evaluated_to": false, 
 "msg": "Assertion failed"
}
 to retry, use: --limit @/home/fale/Learning-Ansible-2.X-Third-Edition/Ch8/playbooks/assert_ls.retry

PLAY RECAP ***********************************************************
ws01                          : ok=2 changed=1 unreachable=0 failed=1 
```

如果我们在创建预期的文件之后重新运行 playbook，这将是结果：

```
PLAY [all] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws01]

TASK [List files in /tmp] ********************************************
changed: [ws01]

TASK [Check if file testfile.txt exists] *****************************
ok: [ws01] => {
 "changed": false, 
 "msg": "All assertions passed"
}

PLAY RECAP ***********************************************************
ws01                          : ok=3 changed=1 unreachable=0 failed=0
```

这次，任务通过了 OK 信息，因为`testfile.txt`在`list_files `变量中存在。同样，你可以使用`and`和`or`运算符在变量中匹配多个字符串或多个变量。断言功能非常强大，编写过单元测试或集成测试的用户将非常高兴看到这个功能！

# 使用标签进行测试

标签是一种在不运行整个 playbook 的情况下测试一堆任务的好方法。我们可以使用标签在节点上运行实际测试，以验证用户在 playbook 中所期望的状态。我们可以将其视为在实际框中运行 Ansible 的另一种方法来运行集成测试。标签测试方法可以在实际运行 Ansible 的机器上运行，并且主要在部署期间用于测试终端系统的状态。在本节中，我们首先看一下如何通用地使用`tags`，它们可能会帮助我们，不仅仅是用于测试，而且甚至是用于测试目的。

要在 playbook 中添加标签，请使用`tags`参数，后面跟着一个或多个标签名称，用逗号或 YAML 列表分隔。让我们在`playbooks/tag_example.yaml`中创建一个简单的 playbook，以查看标签如何与以下内容一起工作：

```
- hosts: all
  tasks: 
    - name: Ensure the file /tmp/ok exists 
      file: 
        name: /tmp/ok 
        state: touch 
      tags: 
        - file_present 
    - name: Ensure the file /tmp/ok does not exists 
      file: 
        name: /tmp/ok 
        state: absent 
      tags: 
        - file_absent 
```

如果现在运行 playbook，文件将被创建和销毁。我们可以看到它的运行情况：

```
ansible-playbook -i ws01, playbooks/tags_example.yaml
```

它会给我们这个输出：

```
PLAY [all] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws01]

TASK [Ensure the file /tmp/ok exists] ********************************
changed: [ws01]

TASK [Ensure the file /tmp/ok does not exists] ***********************
changed: [ws01]

PLAY RECAP ***********************************************************
ws01                          : ok=3 changed=2 unreachable=0 failed=0 
```

由于这不是一个幂等的 playbook，如果我们反复运行它，我们将始终看到相同的结果，因为 playbook 将每次都创建和删除文件。

但是，我们添加了两个标签：`file_present`和`file_absent`。你现在可以仅传递`file_present `标签或`file_absent`标签以执行其中一个动作，就像以下示例中所示：

```
ansible-playbook -i ws01, playbooks/tags_example.yaml -t file_present
```

由于`-t file_present`部分，只有带有`file_present`标签的任务将被执行。事实上，这将是输出：

```
PLAY [all] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws01]

TASK [Ensure the file /tmp/ok exists] ********************************
changed: [ws01]

PLAY RECAP ***********************************************************
ws01                          : ok=2 changed=1 unreachable=0 failed=0 
```

你还可以使用标签在远程主机上执行一组任务，就像从负载均衡器中取出一个服务器并将其添加回负载均衡器。

你还可以将标签与`--check`选项一起使用。通过这样做，你可以在不实际在主机上运行任务的情况下测试你的任务。这使你能够直接测试一堆个别任务，而不必将任务复制到临时 playbook 并从那里运行。

# 理解--skip-tags 选项

Ansible 还提供了一种跳过 playbook 中某些标签的方法。如果你有一个带有多个标签（例如 10 个）的长 playbook，并且你想要执行它们中的全部，但不包括一个，那么向 Ansible 传递九个标签不是一个好主意。如果你忘了传递一个标签，`ansible-run`命令将失败，情况将变得更加困难。为了克服这种情况，Ansible 提供了一种跳过几个标签而不是传递多个应该运行的标签的方法。它的工作方式非常简单，可以按以下方式触发：

```
ansible-playbook -i ws01, playbooks/tags_example.yaml --skip-tags file_present 
```

输出将类似于以下内容：

```
PLAY [all] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws01]

TASK [Ensure the file /tmp/ok exists] ********************************
changed: [ws01]

PLAY RECAP ***********************************************************
ws01                          : ok=2 changed=1 unreachable=0 failed=0 
```

正如你所见，除了具有 `file_present` 标签的任务之外，所有任务都已执行。

# 理解调试命令

Ansible 允许我们使用两个非常强大的变量来帮助我们调试。

`ANSIBLE_KEEP_REMOTE_FILES` 变量允许我们告诉 Ansible 保留它在远程机器上创建的文件，以便我们可以回过头来调试它们。

`ANSIBLE_DEBUG` 变量允许我们告诉 Ansible 将所有调试内容打印到 shell。调试输出通常过多，但对于某些非常复杂的问题可能有所帮助。

我们已经看到如何在你的 playbook 中查找问题。有时，你知道特定步骤可能会失败，但没关系。在这种情况下，我们应该适当地管理异常。让我们看看如何做到这一点。

# 管理异常

有很多情况下，出于各种原因，你希望你的 playbook 和角色在一个或多个任务失败的情况下继续执行。一个典型的例子是你想检查软件是否安装。让我们看一个以下示例，在只有当 Java 8 未安装时才安装 Java 11。在 `roles/java/tasks/main.yaml` 文件中，我们将输入以下代码：

```
- name: Verify if Java8 is installed
  command: rpm -q java-1.8.0-openjdk
  args:
    warn: False
  register: java 
  ignore_errors: True 
  changed_when: java is failed 

- name: Ensure that Java11 is installed
  yum:
    name: java-11-openjdk
    state: present
  become: True
  when: java is failed
```

在继续执行此角色所需的其他部分之前，我想在角色任务列表的各个部分上花几句话，因为有很多新东西。

在此任务中，我们将执行一个 `rpm` 命令：

```
- name: Verify if Java8 is installed
  command: rpm -q java-1.8.0-openjdk
  args:
    warn: False
  register: java 
  ignore_errors: True 
  changed_when: java is failed 
```

此代码可能有两种可能的输出：

+   失败

+   返回 JDK 软件包的完整名称

由于我们只想检查软件包是否存在，然后继续执行，我们会记录输出（第五行），并忽略可能的失败（第六行）。

当它失败时，意味着 `Java8` 未安装，因此我们可以继续安装 `Java11`：

```
- name: Ensure that Java11 is installed
  yum:
    name: java-11-openjdk
    state: present
  become: True
  when: java is failed
```

创建角色后，我们将需要包含主机机器的 `hosts` 文件；在我的情况下，它将如下所示：

```
ws01
```

我们还需要一个用于应用角色的 playbook，放置在 `playbooks/hosts/j01.fale.io.yaml` 中，内容如下：

```
- hosts: ws01
  roles: 
    - java 
```

现在我们可以用以下命令执行它：

```
ansible-playbook playbooks/hosts/ws01.yaml 
```

我们将得到以下结果：

```
PLAY [ws01] **********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws01]

TASK [java : Verify if Java8 is installed] ***************************
fatal: [ws01]: FAILED! => {"changed": true, "cmd": ["rpm", "-q", "java-1.8.0-openjdk"], "delta": "0:00:00.028358", "end": "2019-02-10 10:56:22.474350", "msg": "non-zero return code", "rc": 1, "start": "2019-02-10 10:56:22.445992", "stderr": "", "stderr_lines": [], "stdout": "package java-1.8.0-openjdk is not installed", "stdout_lines": ["package java-1.8.0-openjdk is not installed"]}
...ignoring

TASK [java : Ensure that Java11 is installed] ************************
changed: [ws01]

PLAY RECAP ***********************************************************
ws01 : ok=3 changed=2 unreachable=0 failed=0
```

正如你所见，安装检查失败，因为机器上未安装 Java，因此其他任务已按预期执行。

# 触发失败

有些情况下，您希望直接触发一个失败。这可能发生在多种原因下，即使这样做有一些不利之处，因为当您触发失败时，Playbook 将被强行中断，如果您不小心的话，这可能会导致机器处于不一致的状态。我曾亲眼见过一个情况非常适用的场景，那就是当您运行一个不是幂等的 Playbook 时（例如，构建一个应用的新版本），您需要一个变量（例如，要部署的版本/分支）设置。在这种情况下，您可以在开始运行操作之前检查预期的变量是否正确配置，以确保以后的一切都能正常运行。

让我们将以下代码放入`playbooks/maven_build.yaml`中：

```
- hosts: all
  tasks: 
    - name: Ensure the tag variable is properly set
      fail: 'The version needs to be defined. To do so, please add: --extra-vars "version=$[TAG/BRANCH]"' 
      when: version is not defined 
    - name: Get last Project version 
      git: 
        repo: https://github.com/org/project.git 
        dest: "/tmp" 
        version: '{{ version }}' 
    - name: Maven clean install 
      shell: "cd /tmp/project && mvn clean install" 
```

如您所见，我们期望用户在调用脚本的命令中添加`--extra-vars "version=$[TAG/BRANCH]"`。我们本可以设置一个默认要使用的分支，但这样做太冒险，因为用户可能分心并忘记自己添加正确的分支名称，这将导致编译（和部署）错误的应用程序版本。`fail`模块还允许我们指定将显示给用户的消息。

我认为，在手动运行 Playbook 时，`fail`任务要比失败更加有用，因为自动运行 Playbook 时，管理异常通常比直接失败更好。

使用`fail`模块，一旦发现问题，您就可以退出 Playbooks。

# 摘要

在本章中，我们已经学习了如何使用语法检查、带有和不带`--diff`的检查模式以及功能测试来调试 Ansible Playbooks。

作为功能测试的一部分，我们已经看到如何对系统的最终状态进行断言，如何利用标签进行测试，以及如何使用`--syntax-check`选项和`ANSIBLE_KEEP_REMOTE_FILES`和`ANSIBLE_DEBUG`标志。然后，我们转向了失败的管理，最后，我们学习了如何故意触发失败。

在下一章中，我们将讨论多层环境以及部署方法论。


# 第十一章：复杂环境

到目前为止，我们已经了解了如何开发 Ansible 剧本并对其进行测试。最后一个方面是如何将剧本发布到生产环境。在大多数情况下，发布剧本到生产环境之前，你将需要处理多个环境。这类似于你的开发人员编写的软件。许多公司有多个环境，通常你的剧本将按照以下步骤进行：

+   开发环境

+   测试环境

+   阶段环境

+   生产

一些公司以不同的方式命名这些环境，有些公司还有额外的环境，比如所有软件都必须在进入生产环境之前通过认证的认证环境。

当你编写你的剧本并设置角色时，我们强烈建议你从一开始就牢记环境的概念。与你的软件和运维团队交流，了解你的设置必须满足多少个环境可能是值得的。我们将列举一些方法，并提供你可以在你的环境中遵循的示例。

本章将涵盖以下主题：

+   基于 Git 分支的代码

+   软件分发策略

+   使用修订控制系统部署 Web 应用程序

+   使用 RPM 包部署 Web 应用程序

+   使用 RPM 打包编译软件

# 技术要求

要能够跟随本章的示例，你需要一台能够构建 RPM 包的 UNIX 机器。我的建议是安装 Fedora 或 CentOS（无论是裸金属还是虚拟机）。

你可以从本书的 GitHub 存储库下载所有文件，网址为[`github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter09`](https://github.com/PacktPublishing/Learning-Ansible-2.X-Third-Edition/tree/master/Chapter09)。

# 基于 Git 分支的代码

假设你要照顾四个环境，它们如下：

+   开发

+   测试

+   阶段

+   生产

在基于 Git 分支的方法中，你将每个分支拥有一个环境。你总是首先对**开发**进行更改，然后将这些更改提升到**测试**（在 Git 中合并或挑选，以及标记提交），**阶段**和**生产**。在这种方法中，你将拥有一个单一的清单文件，一组变量文件，最后，针对每个分支的角色和剧本的一堆文件夹。

# 具有多个文件夹的单一稳定分支

在这种方法中，您将始终保持开发和主分支。初始代码提交到开发分支，一旦稳定，将其推广到主分支。在主分支上存在的相同角色和 playbooks 将在所有环境中运行。另一方面，您将为每个环境有单独的文件夹。让我们看一个例子。我们将展示如何针对两个环境（暂存和生产）拥有单独的配置和清单。您可以根据自己的情况来扩展到您使用的所有环境。首先，让我们看一下`playbooks/variables.yaml`中的 playbook，它将在这些多个环境中运行，并具有以下内容。完整代码可在 GitHub 上查看：

```
- hosts: web 
  user: vagrant 
  tasks: 
    - name: Print environment name 
      debug: 
        var: env 
    - name: Print db server url 
      debug: 
        var: db_url 
    - name: Print domain url 
      debug: 
        var: domain 
...
```

正如您所见，在这个 playbook 中有两组任务：

+   运行在 DB 服务器上的任务

+   运行在 Web 服务器上的任务

还有一个额外的任务来打印特定环境中所有服务器共有的环境名称。我们也将有两个不同的清单文件。

第一个将被称为`inventory/production`，内容如下：

```
[web] 
ws01.fale.io 
ws02.fale.io 

[db] 
db01.fale.io 

[production:children] 
db 
web 
```

第二个将被称为`inventory/staging`，内容如下：

```
[web] 
ws01.staging.fale.io 
ws02.staging.fale.io 

[db] 
db01.staging.fale.io 

[staging:children] 
db 
web
```

如您所见，在每个环境中`web`部分有两台机器，`db`部分有一台。此外，我们对阶段和生产环境有不同的机器组。附加部分`[ENVIRONMENT:children]`允许您创建一组组。这意味着在`ENVIRONMENT`部分定义的任何变量都将应用于`db`和`web`组，除非在各自的部分中覆盖。接下来看看如何在每个环境中分离变量值将是有趣的。

我们先从位于`inventory/group_vars/all`的所有环境相同的变量开始：

```
db_user: mysqluser 
```

两个环境中唯一相同的变量是`db_user`。

现在我们可以查看位于`inventory/group_vars/production`的特定于生产环境的变量：

```
env: production 
domain: fale.io 
db_url: db.fale.io 
db_pass: this_is_a_safe_password 
```

如果我们现在查看位于`inventory/group_vars/staging`的特定于阶段环境的变量，我们会发现与生产环境中相同的变量，但值不同：

```
env: staging 
domain: staging.fale.io 
db_url: db.staging.fale.io 
db_pass: this_is_an_unsafe_password 
```

我们现在可以验证我们收到了预期的结果。首先，我们将对暂存环境运行：

```
ansible-playbook -i inventory/staging playbooks/variables.yaml
```

我们应该会收到类似以下的输出。完整代码输出可在 GitHub 上查看：

```
PLAY [web] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws01.staging.fale.io]
ok: [ws02.staging.fale.io]

TASK [Print environment name] ****************************************
ok: [ws01.staging.fale.io] => {
 "env": "staging"
}
ok: [ws02.staging.fale.io] => {
 "env": "staging"
}

TASK [Print db server url] *******************************************
ok: [ws01.staging.fale.io] => {
 "db_url": "db.staging.fale.io"
}
ok: [ws02.staging.fale.io] => {
 "db_url": "db.staging.fale.io"
}

...
```

现在我们可以针对生产环境运行：

```
ansible-playbook -i inventory/production playbooks/variables.yaml 
```

我们将收到以下结果：

```
PLAY [web] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws02.fale.io]
ok: [ws01.fale.io]

TASK [Print environment name] ****************************************
ok: [ws01.fale.io] => {
 "env": "production"
}
ok: [ws02.fale.io] => {
 "env": "production"
}

TASK [Print db server url] *******************************************
ok: [ws01.fale.io] => {
 "db_url": "db.fale.io"
}
ok: [ws02.fale.io] => {
 "db_url": "db.fale.io"
}

...
```

您可以看到 Ansible 运行捕获了为暂存环境定义的所有相关变量。

如果您使用这种方法获得多个环境的稳定主分支，最好使用混合环境特定目录，`group_vars`和清单组来应对这种情况。

# 软件分发策略

部署应用程序可能是**信息与通信技术（ICT）**领域中最复杂的任务之一。这主要是因为它经常需要更改作为该应用程序某种程度上组成部分的大多数机器的状态。事实上，通常您会发现自己在部署过程中需要同时更改负载均衡器、分发服务器、应用服务器和数据库服务器的状态。新技术，如容器，正试图简化这些操作，但通常很难或不可能将传统应用程序移至容器中。

现在我们将分析各种软件分发策略以及 Ansible 如何帮助每一种。

# 从本地机器复制文件

这可能是最古老的软件分发策略了。其思想是将文件放在本地机器上（通常用于开发代码），一旦更改完成，文件的副本就会被放在服务器上（通常通过 FTP）。这种部署代码的方式经常用于 Web 开发，其中的代码（通常是 PHP）不需要任何编译。

由于多个问题，应避免使用这种分发策略：

+   回滚很困难。

+   无法跟踪各个部署的更改。

+   没有部署历史记录。

+   在部署过程中很容易出错。

尽管这种分发策略可以非常容易地通过 Ansible 自动化，我强烈建议立即转向其他能够让您拥有更安全的分发策略的策略。

# 带有分支的版本控制系统

许多公司正在使用这种技术来分发他们的软件，主要用于非编译软件。这种技术背后的理念是设置服务器使用代码库的本地副本。通过 SVN，这是可能的，但不是很容易正确管理，而 Git 允许这种技术的简化，使其非常受欢迎。

这种技术与我们刚刚看到的技术相比有很大的优势；其中主要优势如下：

+   易于回滚

+   非常容易获取更改历史记录

+   非常容易的部署（特别是如果使用 Git）

另一方面，这种技术仍然存在多个缺点：

+   没有部署历史记录

+   编译软件困难

+   可能存在安全问题

我想更详细地讨论一下您可能会遇到的这种技术的潜在安全问题。非常诱人的做法是直接在用于分发内容的文件夹中下载您的 Git 存储库，因此，如果这是一个 Web 服务器，那么这将是`/var/www/`文件夹。这样做有明显的优势，因为要部署，您只需要执行`git pull`。缺点是 Git 将创建`/var/www/.git`文件夹，其中包含整个 Git 存储库（包括历史记录），如果没有得到妥善保护，将可以被任何人自由下载。

Alexa 排名前 100 万的网站中约有 1%的网站可以公开访问 Git 文件夹，所以如果您想使用这种分发策略，一定要非常小心。

# 带有标签的修订控制系统

使用稍微复杂但具有一些优点的修订控制系统的另一种方法是利用标记系统。此方法要求您每次进行新部署时都要打标签，然后在服务器上检查特定的标签。

这具有上一种方法的所有优点，并加入了部署历史记录。已编译的软件问题和可能的安全问题与上一种方法相同。

# RPM 软件包

部署软件的一种非常常见的方法（主要用于已编译的应用程序，但对于非编译的应用程序也有优势）是使用某种打包系统。一些语言，如 Java，已经包含了系统（Java 的情况下是 WAR），但也有可以用于任何类型的应用程序的打包系统，比如**RPM 软件包管理器**（**RPM**）。RPM 最初由 Erik Troan 和 Marc Ewing 开发，并于 1997 年发布用于 Red Hat Linux。自那时起，它已被许多 Linux 发行版采用，并且是 Linux 世界中分发软件的两种主要方式之一，另一种是 DEB。这些系统的缺点是它们比以前的方法稍微复杂一些，但是这些系统可以提供更高级别的安全性，以及版本控制。此外，这些系统很容易嵌入到 CI/CD 流水线中，因此实际复杂性远低于乍看之下所见。

# 准备环境

要查看我们如何以我们在*软件分发策略*部分讨论的方式部署代码，我们将需要一个环境，显然我们将使用 Ansible 创建它。首先，为了确保我们的角色被正确加载，我们需要`ansible.cfg`文件，内容如下：

```
[defaults] 
roles_path = roles
```

然后，我们需要`playbooks/groups/web.yaml`文件来正确引导我们的 Web 服务器：

```
- hosts: web 
  user: vagrant 
  roles: 
    - common 
    - webserver 
```

正如您可以从前面的文件内容中想象的那样，我们将需要创建`common`和`webserver`角色，它们与我们在第四章中创建的角色非常相似，*处理复杂的部署*。我们将从`roles/common/tasks/main.yaml`文件开始，内容如下。完整的代码可在 GitHub 上找到：

```
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

这是`motd`模板在`roles/common/templates/motd`中的模板：

```
                This system is managed by Ansible 
  Any change done on this system could be overwritten by Ansible 

OS: {{ ansible_distribution }} {{ ansible_distribution_version }} 
Hostname: {{ inventory_hostname }} 
eth0 address: {{ ansible_eth0.ipv4.address }} 

            All connections are monitored and recorded 
    Disconnect IMMEDIATELY if you are not an authorized user
```

现在我们可以转移到`webserver`角色——更具体地说是`roles/webserver/tasks/main.yaml`文件。完整的代码文件可以在 GitHub 上找到：

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

我们还需要在`roles/webserver/handlers/main.yaml`中创建处理程序，内容如下：

```
--- 
- name: Restart HTTPd 
  service: 
    name: httpd 
    state: restarted 
  become: True
```

我们在`roles/webserver/templates/index.html.j2`文件中添加以下内容：

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

最后，我们需要触及`roles/webserver/files/website.conf`文件，暂时将其留空，但它必须存在。

现在我们可以预配一对 CentOS 机器（我预配了`ws01.fale.io`和`ws02.fale.io`），并确保清单正确。我们可以通过运行它们的组播放本来配置这些机器：

```
ansible-playbook -i inventory/production playbooks/groups/web.yaml 
```

我们将收到以下输出。完整的代码输出可在 GitHub 上找到：

```
PLAY [web] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws01.fale.io]
ok: [ws02.fale.io]

TASK [common : Ensure EPEL is enabled] *******************************
ok: [ws02.fale.io]
ok: [ws01.fale.io]

TASK [common : Ensure libselinux-python is present] ******************
ok: [ws02.fale.io]
ok: [ws01.fale.io]

TASK [common : Ensure libsemanage-python is present] *****************
ok: [ws01.fale.io]
ok: [ws02.fale.io]

TASK [common : Ensure we have last version of every package] *********
changed: [ws02.fale.io]
changed: [ws01.fale.io]

...
```

现在，我们可以在端口`80`上指向我们的节点，检查是否如预期显示了 HTTPd 页面。既然我们已经有了基本的 Web 服务器运行，我们现在可以专注于部署 Web 应用程序。

# 使用修订控制系统部署 Web 应用

现在我们将从修订控制系统（Git）直接将 Web 应用程序首次部署到我们的服务器上，使用 Ansible。因此，我们将部署一个简单的 PHP 应用程序，只由一个单独的 PHP 页面组成。源代码可在以下存储库找到：[`github.com/Fale/demo-php-app`](https://github.com/Fale/demo-php-app)。

要部署它，我们将需要将以下代码放置在`playbooks/manual/rcs_deploy.yaml`中：

```
- hosts: web 
  user: vagrant 
  tasks:
    - name: Ensure git is installed
      yum:
        name: git
        state: present 
      become: True
    - name: Install or update website 
      git: 
        repo: https://github.com/Fale/demo-php-app.git 
        dest: /var/www/application 
      become: True
```

现在我们可以使用以下命令运行部署器：

```
ansible-playbook -i inventory/production/playbooks/manual/rcs_deploy.yaml 
```

这是预期的结果：

```
PLAY [web] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws02.fale.io]
ok: [ws01.fale.io]

TASK [Ensure git is installed] ***************************************
changed: [ws01.fale.io]
changed: [ws02.fale.io]

TASK [Install or update website] *************************************
changed: [ws02.fale.io]
changed: [ws01.fale.io]

PLAY RECAP ***********************************************************
ws01.fale.io                  : ok=3 changed=2 unreachable=0 failed=0 
ws02.fale.io                  : ok=3 changed=2 unreachable=0 failed=0
```

目前，我们的应用程序还无法访问，因为我们没有 HTTPd 规则来访问该文件夹。为了实现这一点，我们将需要更改`roles/webserver/files/website.conf`文件，内容如下：

```
<VirtualHost *:80> 
    ServerName app.fale.io 
    DocumentRoot /var/www/application 
    <Directory /var/www/application> 
        Options None 
    </Directory> 
    <DirectoryMatch ".git*"> 
        Require all denied 
    </DirectoryMatch> 
</VirtualHost>
```

正如您所见，我们只向通过`app.fale.io`URL 到达我们服务器的用户显示此应用程序，而不是向所有人。这将确保所有用户都拥有一致的体验。此外，您可以看到我们阻止所有对`.git`文件夹（及其所有内容）的访问。这是出于我们在本章的*软件分发策略*部分提到的安全原因。

现在我们可以重新运行 Web 播放本以确保我们的 HTTPd 配置被传播：

```
ansible-playbook -i inventory/production playbooks/groups/web.yaml 
```

这是我们将要收到的结果。完整的代码输出可在 GitHub 上找到：

```
PLAY [web] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws01.fale.io]
ok: [ws02.fale.io]

TASK [common : Ensure EPEL is enabled] *******************************
ok: [ws02.fale.io]
ok: [ws01.fale.io]

TASK [common : Ensure libselinux-python is present] ******************
ok: [ws01.fale.io]
ok: [ws02.fale.io]

TASK [common : Ensure libsemanage-python is present] *****************
ok: [ws01.fale.io]
ok: [ws02.fale.io]
 ...
```

您现在可以检查并确保一切正常运行。

我们已经看到了如何从 Git 获取源代码并将其部署到 Web 服务器，以便及时提供给我们的用户。现在，我们将深入研究另一种分发策略：使用 RPM 软件包部署 Web 应用程序。

# 使用 RPM 软件包部署 Web 应用程序

要部署 RPM 软件包，我们首先需要创建它。为此，我们需要的第一件事是一个**SPEC 文件**。

# 创建 SPEC 文件

我们需要做的第一件事是创建一个 SPEC 文件，这是一个指导`rpmbuild`如何实际创建 RPM 软件包的配方。我们将把 SPEC 文件定位在`spec/demo-php-app.spec`中。以下是代码片段内容，完整代码可在 GitHub 上找到：

```
%define debug_package %{nil} 
%global commit0 b49f595e023e07a8345f47a3ad62a6f50f03121e 
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7}) 

Name: demo-php-app 
Version: 0 
Release: 1%{?dist} 
Summary: Demo PHP application 

License: PD 
URL: https://github.com/Fale/demo-php-app 
Source0: %{url}/archive/%{commit0}.tar.gz#/%{name}-%{shortcommit0}.tar.gz 

%description 
This is a demo PHP application in RPM format 
 ...
```

在继续之前，让我们看看各个部分的作用和含义：

```
%define debug_package %{nil} 
%global commit0 b49f595e023e07a8345f47a3ad62a6f50f03121e 
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7}) 
```

前三行是变量声明。

第一步将禁用调试包的生成。默认情况下，`rpmbuild`每次都会创建一个调试包并包含所有调试符号，但在本例中我们没有任何调试符号，因为我们没有进行任何编译。

第二个将提交的哈希放入`commit0`变量。第三个计算`shortcommit0`的值，该值计算为`commit0`字符串的前八个字符：

```
Name:       demo-php-app 
Version:    0 
Release:    1%{?dist} 
Summary:    Demo PHP application 

License:    PD 
URL:        https://github.com/Fale/demo-php-app 
Source0:    %{url}/archive/%{commit0}.tar.gz#/%{name}-%{shortcommit0}.tar.gz 
```

在第一行中，我们声明名称、版本、发布编号和摘要。版本和发布的区别在于版本是上游版本，而发布是上游版本的 SPEC 版本。

许可证是源许可证，而不是 SPEC 许可证。URL 用于跟踪上游网站。`source0`字段用于`rpmbuild`查找源文件的名称（如果存在多个文件，我们可以使用`source1`、`source2`等）。此外，如果源字段是有效的 URI，则可以使用`spectool`来自动下载它们。这是打包到 RPM 软件包中的软件的`description`：

```
%description 
This is a demo PHP application in RPM format
```

`prep`阶段是源文件解压缩和最终应用补丁的阶段。`%autosetup`将解压缩第一个源文件，并应用所有补丁。在这部分，您还可以执行在构建阶段前需要执行的其他操作，其目的是为构建阶段准备环境：

```
%prep 
%autosetup -n %{name}-%{commit0}
```

在这里，我们将列出所有构建阶段的操作。在我们的情况下，我们的源代码不需要编译，因此为空：

```
%build
```

在`install`阶段，我们将文件放入`%{buildroot}`文件夹，模拟目标文件系统：

```
%install 
mkdir -p %{buildroot}/var/www/application 
ls -alh 
cp index.php %{buildroot}/var/www/application 
```

`files`部分需要声明要放入软件包中的文件：

```
%files 
%dir /var/www/application 
/var/www/application/index.php 
```

`changelog`用于跟踪谁何时发布了新版本以及带有哪些更改：

```
%changelog  
* Sun Feb 24 2019 Fabio Alessandro Locati - 0.1
- Initial packaging 
```

现在我们有了 SPEC 文件，我们需要构建它。为此，我们可以使用生产机器，但这样会增加对该机器的攻击面，所以最好避免。构建 RPM 软件的多种方式。主要的四种方式如下：

+   手动

+   使用 Ansible 自动化手动方式

+   Jenkins

+   Koji

让我们简要看一下区别。

# 手动构建 RPM 包

构建 RPM 软件包的最简单方式是以手动方式进行。

最大的优势在于您只需要几个简单的步骤来安装`build`，因此许多刚开始使用 RPM 的人都从这里开始。缺点是这个过程将是手动的，因此人为的错误可能会破坏结果。此外，手动构建非常难以审计，因为唯一可审计的部分是输出而非过程本身。

要构建 RPM 软件包，您需要一个 Fedora 或 EL（Red Hat Enterprise Linux，CentOS，Scientific Linux，Oracle Enterprise Linux）系统。如果您使用 Fedora，您需要执行以下命令来安装所有必需的软件：

```
sudo dnf install -y fedora-packager 
```

如果您正在运行 EL 系统，则需要执行以下命令：

```
sudo yum install -y mock rpm-build spectool 
```

无论哪种情况，您都需要将要使用的用户添加到 `mock` 组中，为此，您需要执行以下操作：

```
sudo usermod -a -G mock [yourusername] 
```

Linux 在登录时加载用户，因此要应用组更改，您需要重新启动会话。

此时，我们可以将 SPEC 文件复制到文件夹中（通常情况下，`$HOME` 是一个不错的选择），然后执行以下操作：

```
mkdir -p ~/rpmbuild/SOURCES 
```

这将创建所需的 `$HOME/rpmbuild/SOURCES` 文件夹。 `-p` 选项将自动创建路径中缺失的所有文件夹。我们使用 `spectool` 下载源文件并将其放置在适当的目录中。 `spectool` 将自动从 SPEC 文件中获取 URL，因此我们不必记住它：

```
spectool -R -g demo-php-app.spec 
```

现在我们需要创建一个 `src.rpm` 文件，为此，我们可以使用 `rpmbuild`：

```
rpmbuild -bs demo-php-app.spec
```

此命令将输出类似于以下内容：

```
Wrote: /home/fale/rpmbuild/SRPMS/demo-php-app-0-1.fc28.src.rpm
```

名称中可能存在一些小差异；例如，您可能具有不同于 Fedora 24 的 `$HOME` 文件夹，如果您使用的是 Fedora 24 以外的其他版本，则可能有 `fc24` 以外的内容。此时，我们可以使用以下代码创建二进制文件：

```
mock -r epel-7-x86_64 /home/fale/rpmbuild/SRPMS/demo-php-app-0-1.fc28.src.rpm 
```

Mock 允许我们在干净的环境中构建 RPM 包，并且还由于 `-r` 选项而允许我们构建不同版本的 Fedora、EL 和 Mageia。该命令将给出非常长的输出，我们在此不涵盖，但在最后几行中有有用的信息。如果一切都构建正确，这是您应该看到的最后几行：

```
Wrote: /builddir/build/RPMS/demo-php-app-0-1.el7.centos.x86_64.rpm
Executing(%clean): /bin/sh -e /var/tmp/rpm-tmp.d4vPhr
+ umask 022
+ cd /builddir/build/BUILD
+ cd demo-php-app-b49f595e023e07a8345f47a3ad62a6f50f03121e
+ /usr/bin/rm -rf /builddir/build/BUILDROOT/demo-php-app-0-1.el7.centos.x86_64
+ exit 0
Finish: rpmbuild demo-php-app-0-1.fc28.src.rpm
Finish: build phase for demo-php-app-0-1.fc28.src.rpm
INFO: Done(/home/fale/rpmbuild/SRPMS/demo-php-app-0-1.fc28.src.rpm) Config(epel-7-x86_64) 0 minutes 58 seconds
INFO: Results and/or logs in: /var/lib/mock/epel-7-x86_64/result
Finish: run 
```

倒数第二行包含您可以找到结果的路径。如果您在该文件夹中查找，应该会找到以下文件：

```
drwxrwsr-x. 2 fale mock 4.0K Feb 24 12:26 .
drwxrwsr-x. 4 root mock 4.0K Feb 24 12:25 ..
-rw-rw-r--. 1 fale mock 4.6K Feb 24 12:26 build.log
-rw-rw-r--. 1 fale mock 3.3K Feb 24 12:26 demo-php-app-0-1.el7.centos.src.rpm
-rw-rw-r--. 1 fale mock 3.1K Feb 24 12:26 demo-php-app-0-1.el7.centos.x86_64.rpm
-rw-rw-r--. 1 fale mock 184K Feb 24 12:26 root.log
-rw-rw-r--. 1 fale mock  792 Feb 24 12:26 state.log
```

在编译过程中出现问题时，这三个日志文件非常有用。 `src.rpm` 文件将是我们使用第一个命令创建的 `src.rpm` 文件的副本，而 `x86_64.rpm` 文件是我们创建的 mock 文件，也是我们需要在机器上安装的文件。

# 使用 Ansible 构建 RPM 包

由于手动执行所有这些步骤可能会很长、乏味且容易出错，因此我们可以使用 Ansible 自动化它们。生成的 playbook 可能不是最清晰的，但可以以可重复的方式执行所有操作。

出于这个原因，我们将从头开始构建一个新的机器。我将这台机器称为 `builder01.fale.io`，我们还将更改 `inventory/production` 文件以匹配此更改：

```
[web] 
ws01.fale.io 
ws02.fale.io 

[db] 
db01.fale.io 

[builders] 
builder01.fale.io 

[production:children] 
db 
web 
builders 
```

在深入研究 `builders` 角色之前，我们需要对 `webserver` 角色进行一些更改，以启用新的存储库。首先是在 `roles/webserver/tasks/main.yaml` 文件末尾添加一个任务，其中包含以下代码：

```
- name: Install our private repository 
  copy: 
    src: privaterepo.repo 
    dest: /etc/yum.repos.d/privaterepo.repo 
  become: True
```

第二个更改实际上是使用以下内容创建 `roles/webserver/files/privaterepo.repo` 文件：

```
[privaterepo] 
name=Private repo that will keep our apps packages 
baseurl=http://repo.fale.io/ 
skip_if_unavailable=True 
gpgcheck=0 
enabled=1 
enabled_metadata=1
```

现在我们可以执行 `webserver` 组 playbook 以使更改生效，命令如下：

```
ansible-playbook -i inventory/production playbooks/groups/web.yaml 
```

应该显示如下输出。完整代码输出可在 GitHub 上找到：

```
PLAY [web] ***********************************************************

TASK [Gathering Facts] ***********************************************
ok: [ws02.fale.io]
ok: [ws01.fale.io]

TASK [common : Ensure EPEL is enabled] *******************************
ok: [ws02.fale.io]
ok: [ws01.fale.io]

TASK [common : Ensure libselinux-python is present] ******************
ok: [ws01.fale.io]
ok: [ws02.fale.io]

TASK [common : Ensure libsemanage-python is present] *****************
ok: [ws01.fale.io]
ok: [ws02.fale.io]

...
```

如预期的那样，唯一的变化是部署了我们新生成的仓库文件。

我们还需要为`builders`创建一个角色，其中包含位于`roles/builder/tasks/main.yaml`的`tasks`文件，内容如下。完整代码可在 GitHub 上找到：

```
- name: Ensure needed packages are present 
  yum: 
    name: '{{ item }}' 
    state: present 
  become: True 
  with_items: 
    - mock 
    - rpm-build 
    - spectool 
    - createrepo 
    - httpd 

- name: Ensure the user ansible is in the mock group 
  user: 
    name: ansible 
    groups: mock 
    append: True 
  become: True 

...
```

同样作为`builder`角色的一部分，我们需要`roles/builder/handlers/main.yaml`处理文件，内容如下：

```
- name: Restart HTTPd 
  service: 
    name: httpd 
    state: restarted 
  become: True 
```

如您从`tasks`文件中可以猜想的，我们还需要`roles/builder/files/repo.conf`文件，内容如下：

```
<VirtualHost *:80> 
    ServerName repo.fale.io 
    DocumentRoot /var/www/repo 
    <Directory /var/www/repo> 
        Options Indexes FollowSymLinks 
    </Directory> 
</VirtualHost>
```

我们还需要一个新的`group` playbook，位于`playbooks/groups/builders.yaml`，内容如下：

```
- hosts: builders 
  user: vagrant 
  roles: 
    - common 
    - builder 
```

现在我们可以创建主机本身，内容如下：

```
ansible-playbook -i inventory/production playbooks/groups/builders.yaml 
```

我们期望得到类似下面的结果：

```
PLAY [builders] ******************************************************

TASK [Gathering Facts] ***********************************************
ok: [builder01.fale.io]

TASK [common : Ensure EPEL is enabled] *******************************
changed: [builder01.fale.io]

TASK [common : Ensure libselinux-python is present] ******************
ok: [builder01.fale.io]

TASK [common : Ensure libsemanage-python is present] *****************
changed: [builder01.fale.io]

TASK [common : Ensure we have last version of every package] *********
changed: [builder01.fale.io]

TASK [common : Ensure NTP is installed] ******************************
changed: [builder01.fale.io]

TASK [common : Ensure the timezone is set to UTC] ********************
changed: [builder01.fale.io]

...
```

现在我们已经准备好基础设施的所有部分，可以创建`playbooks/manual/rpm_deploy.yaml`文件，内容如下。完整代码可在 GitHub 上找到：

```
- hosts: builders 
  user: vagrant 
  tasks: 
    - name: Copy SPEC file to user folder 
      copy: 
        src: ../../spec/demo-php-app.spec 
        dest: /home/vagrant
    - name: Ensure rpmbuild exists 
      file: 
        name: ~/rpmbuild 
        state: directory 
    - name: Ensure rpmbuild/SOURCES exists 
      file: 
        name: ~/rpmbuild/SOURCES 
        state: directory 
   ...
```

正如我们讨论过的，此 playbook 有许多不太干净的命令和 shell。将来可能有可能编写一个具有相同功能但使用模块的 playbook。大多数操作与我们在前一节讨论过的相同。新操作在最后; 实际上，在这种情况下，我们将生成的 RPM 文件复制到特定文件夹，我们调用`createrepo`在该文件夹中生成一个仓库，然后强制所有 Web 服务器更新生成的软件包至最新版本。

为确保应用程序的安全性，重要的是仓库仅在内部可访问，而不是公开的。

现在我们可以用以下命令运行 playbook：

```
ansible-playbook -i inventory/production playbooks/manual/rpm_deploy.yaml 
```

我们期望得到类似以下的结果。完整代码输出在 GitHub 上找到：

```
PLAY [builders] ******************************************************

TASK [setup] *********************************************************
ok: [builder01.fale.io]

TASK [Copy SPEC file to user folder] *********************************
changed: [builder01.fale.io]

TASK [Ensure rpmbuild exists] ****************************************
changed: [builder01.fale.io]

TASK [Ensure rpmbuild/SOURCES exists] ********************************
changed: [builder01.fale.io]

TASK [Download the sources] ******************************************
changed: [builder01.fale.io]

TASK [Ensure no SRPM files are present] ******************************
changed: [builder01.fale.io]

TASK [Build the SRPM file] *******************************************
changed: [builder01.fale.io]
...
```

# 使用 CI/CD 流水线构建 RPM 软件包

虽然本书未涉及此内容，但在更复杂的情况下，您可能希望使用 CI/CD 流水线来创建和管理 RPM 软件包。这两个主要的流水线基于两种不同类型的软件：

+   Koji

+   Jenkins

Koji 软件由 Fedora 社区和 Red Hat 开发。它根据 LGPL 2.1 许可证发布。这是目前由 Fedora、CentOS 以及许多其他公司和社区用来创建所有他们的 RPM 软件包（包括官方测试，也称为**临时构建**）的流水线。 Koji 默认情况下不会由提交触发；需要通过用户（通过 Web 界面或 CLI）进行**手动**调用。 Koji 将自动从 Git 下载 SPEC 文件的最新版本，从侧边缓存（这是可选的，但建议的）或原始位置下载源代码，并触发模拟构建。 Koji 仅支持模拟构建，因为它是唯一支持一致和可重复构建的系统。 Koji 可以永久存储所有输出的构件或根据配置的设置存储一段时间。这是为了确保非常高的审计级别。

Jenkins 是最常用的 CI/CD 管理器之一，也可以用于 RPM 流水线。其主要缺点是需要从头开始配置，这意味着需要更多的时间，但这意味着它具有更高的灵活性。此外，Jenkins 的一个重大优势是许多公司已经有了 Jenkins 实例，这使得设置和维护基础设施更容易，因为您可以重用您已经拥有的安装，因此您总体上不必管理较少的系统。

# 使用 RPM 打包构建编译软件

**RPM 打包**对于非二进制应用程序非常有用，并且对于二进制应用程序几乎是必需的。这也是因为非二进制和二进制情况之间的复杂性差异非常小。事实上，构建和安装将以完全相同的方式工作。唯一会改变的是 SPEC 文件。

让我们看看编写一个简单的用 C 编写的`Hello World!`应用程序所需的 SPEC 文件：

```
%global commit0 7c288b9d80a6ef525c0cca8a744b32e018eaa386 
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7}) 

Name:           hello-world 
Version:        1.0 
Release:        1%{?dist} 
Summary:        Hello World example implemented in C 

License:        GPLv3+ 
URL:            https://github.com/Fale/hello-world 
Source0:        %{url}/archive/%{commit0}.tar.gz#/%{name}-%{shortcommit0}.tar.gz 

BuildRequires:  gcc 
BuildRequires:  make 

%description 
The description for our Hello World Example implemented in C 

%prep 
%autosetup -n %{name}-%{commit0} 

%build 
make %{?_smp_mflags} 

%install 
%make_install 

%files 
%license LICENSE 
%{_bindir}/hello 

%changelog 
* Sun Feb 24 2019 Fabio Alessandro Locati - 1.0-1 
- Initial packaging
```

正如你所看到的，这与我们在 PHP 演示应用程序中看到的非常相似。让我们看看其中的区别。

让我们稍微深入了解 SPEC 文件的各个部分：

```
%global commit0 7c288b9d80a6ef525c0cca8a744b32e018eaa386 
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7}) 
```

正如你所看到的，我们没有禁用调试包的行。每次打包编译应用程序时，都应该让`rpm`创建调试符号包，这样在崩溃的情况下，调试和理解问题会更容易。

SPEC 文件的以下部分显示在这里：

```
Name:           hello-world 
Version:        1.0 
Release:        1%{?dist} 
Summary:        Hello World example implemented in C 

License:        GPLv3+ 
URL:            https://github.com/Fale/hello-world 
Source0:        %{url}/archive/%{commit0}.tar.gz#/%{name}-%{shortcommit0}.tar.gz 
```

正如你所看到的，此部分的更改仅是由于新包具有不同的名称和`URL`，但它们与这是一个可编译应用程序的事实无关联：

```
BuildRequires:  gcc 
BuildRequires:  make
```

在非编译应用程序中，我们不需要任何构建时存在的软件包，而在这种情况下，我们将需要`make`和`gcc`（编译器）应用程序。不同的应用程序可能需要不同的工具和/或库在构建时存在于系统中：

```
%description 
The description for our Hello World Example implemented in C 

%prep 
%autosetup -n %{name}-%{commit0} 

%build 
make %{?_smp_mflags} 
```

`description`是特定于包的，并不受包的编译影响。同样，`%prep`阶段也是如此。

在`%build`阶段，我们现在必须制作`%{?_smp_mflags}`。这是需要告诉`rpmbuild`实际运行`make`来构建我们的应用程序。`_smp_mflags`变量将包含一组参数，以优化编译为多线程：

```
%install 
%make_install 
```

在`%install`阶段，我们将发出`%make_install`命令。此宏将调用`make install`，并带有一组额外的参数，以确保库位于正确的文件夹中，以及二进制文件等等：

```
%files 
%license LICENSE 
%{_bindir}/hello 
```

在这种情况下，我们只需要将`hello`二进制文件放置在`%install`阶段的`buildroot`正确文件夹中，并添加包含许可证的`LICENSE`文件：

```
%changelog 
* Sun Feb 24 2019 Fabio Alessandro Locati - 1.0-1 
- Initial packaging 
```

`%changelog`与我们看到的其他 SPEC 文件非常相似，因为它不受编译的影响。

完成后，您可以将其放在 `spec/hello-world.spec` 中，并通过以下代码段将 `playbooks/manual/rpm_deploy.yaml` 调整为 `playbooks/manual/hello_deploy.yaml` 保存。全部代码可在 GitHub 上找到：

```
- hosts: builders 
  user: vagrant 
  tasks: 
    - name: Copy SPEC file to user folder 
      copy: 
        src: ../../spec/hello-world.spec 
        dest: /home/ansible 
    - name: Ensure rpmbuild exists 
      file: 
        name: ~/rpmbuild 
        state: directory 
    - name: Ensure rpmbuild/SOURCES exists 
      file: 
        name: ~/rpmbuild/SOURCES 
        state: directory 
    ...
```

正如您所见，我们唯一更改的是所有对 `demo-php-app` 的引用都替换为 `hello-world`。使用以下命令运行它：

```
ansible-playbook -i inventory/production playbooks/manual/hello_deploy.yaml
```

我们将得到以下结果。全部代码输出可在 GitHub 上找到：

```
PLAY [builders] ******************************************************

TASK [setup] *********************************************************
ok: [builder01.fale.io]

TASK [Copy SPEC file to user folder] *********************************
changed: [builder01.fale.io]

TASK [Ensure rpmbuild exists] ****************************************
ok: [builder01.fale.io]

TASK [Ensure rpmbuild/SOURCES exists] ********************************
ok: [builder01.fale.io]

TASK [Download the sources] ******************************************
changed: [builder01.fale.io]

TASK [Ensure no SRPM files are present] ******************************
changed: [builder01.fale.io]

TASK [Build the SRPM file] *******************************************
changed: [builder01.fale.io]

TASK [Execute mock] **************************************************
changed: [builder01.fale.io]

...
```

您最终可以创建一个接受要构建的包的名称作为参数的 Playbook，这样您就不需要为每个包创建不同的 Playbook。

# 部署策略

我们已经看到如何在您的环境中分发软件，所以现在，我们将谈论部署策略，即如何升级您的应用程序而不会使您的服务受到影响。

在更新期间可能遇到三种不同的问题：

+   更新推出期间的停机时间。

+   新版本存在问题。

+   新版本似乎工作正常，直到它失败。

第一个问题是每个系统管理员都知道的。在更新期间，您可能会重新启动一些服务，而在服务启动和结束之间的时间内，您的应用程序将无法在该机器上使用。为了解决这个问题，您需要具有智能负载均衡器的多台机器，该负载均衡器将在执行特定节点的升级之前，从可用节点池中删除指定节点，然后在节点升级后尽快将它们添加回去。

第二个问题可以通过多种方式预防。最清洁的方法是在 CI/CD 流水线中进行测试。事实上，这些问题很容易通过简单的测试找到。我们即将看到的方法也可以预防这种情况。

第三个问题迄今为止是最复杂的。许多次，甚至是全球范围内的问题，都是由这些问题引起的。通常，问题在于新版本存在一些性能问题或内存泄漏。由于大多数部署是在服务器负载最轻的时期完成的，一旦负载增加，性能问题或内存泄漏可能会导致服务器崩溃。

要能够正确使用这些方法，您必须能够确保您的软件可以接受回滚。有些情况下这是不可能的（即，在更新中删除了一个数据库表）。我们不会讨论如何避免这种情况，因为这是开发策略的一部分，与 Ansible 无关。

为了解决这些问题，通常使用两种常见的部署模式：**金丝雀部署** 和 **蓝绿部署**。

# 金丝雀部署

金丝雀部署是一种技术，涉及将你的一小部分机器（通常为 5%）更新到新版本，并指示负载均衡器仅将等量的流量发送到它。这有几个优点：

+   在更新期间，你的容量永远不会低于 95%

+   如果新版本完全失败，你会损失 5% 的容量。

+   由于负载均衡器在新旧版本之间分配流量，如果新版本有问题，只有你的用户的 5% 将看到问题。

+   只需要比预期负载多 5% 的容量

金丝雀部署能够避免我们提到的所有三个问题，而且额外开销很小（5%），并且在回滚时成本低廉（5%）。因此，许多大型公司都广泛使用这种技术。通常，为了确保用户在相近地理位置的体验相似，会根据地理位置选择用户是使用旧版本还是新版本。

当测试看起来成功时，可以逐步增加百分比，直到达到 100%。

可以以多种方式在 Ansible 中实现金丝雀部署。我建议的方式是最干净的方式，即使用清单文件，这样你会有如下内容：

```
[web-main] 
ws[00:94].fale.io 

[web-canary] 
ws[95:99].fale.io 

[web:children] 
web-main 
web-canary
```

通过这种方式，你可以在 web 组上设置所有变量（变量将是相同的，无论是什么版本的操作系统，或者至少应该是相同的），但你可以很容易地对金丝雀组、主要组或同时对两个组运行 playbook。另一个选项是创建两个不同的清单文件，一个用于金丝雀组，另一个用于主要组，组的名称相同，以便共享变量。

# 蓝/绿部署

蓝/绿部署与金丝雀部署非常不同，它有一些优点和一些缺点。主要优点如下：

+   更容易实现

+   允许更快的迭代

+   所有用户同时转移

+   回滚不会有性能下降

缺点中，主要的是需要比应用程序所需的机器多一倍。如果应用程序在云上运行（无论是私有、公共还是混合），这个缺点可以很容易地缓解，为部署扩展应用程序资源，然后再缩减它们。

在 Ansible 中实现蓝/绿部署非常简单。最简单的方法是创建两个不同的清单（一个用于蓝色，一个用于绿色），然后简单地管理你的基础设施，就像它们是不同的环境，如生产、暂存、开发等。

# 优化

有时，Ansible 感觉很慢，主要是因为要执行一个非常长的任务列表和/或有大量的机器。有多种原因和方法可以避免这种情况，我们将看一下其中的三种方式。

# 流水线

Ansible 默认较慢的原因之一是，对于每个模块的执行和每个主机，Ansible 将执行以下操作：

+   SSH 握手

+   执行任务

+   关闭 SSH 连接

正如你所看到的，这意味着如果你有 10 个任务要在单个远程服务器上执行，Ansible 将会打开（并关闭）10 次连接。由于 SSH 协议是一种加密协议，这使得 SSH 握手过程变得更长，因为两个部分必须每次都要协商密码。

Ansible 允许我们通过在 playbook 开始时初始化连接并在整个执行过程中保持连接处于活动状态来大幅减少执行时间，这样就不需要在每个任务中重新打开连接。在 Ansible 的发展过程中，这个特性已经多次改名，以及启用方式也有所变化。从 1.5 版本开始，它被称为**pipelining**，启用它的方式是在你的 `ansible.cfg` 文件中添加以下行：

```
pipelining=True 
```

这个功能默认没有启用的原因是许多发行版都带有 `sudo` 中的 `requiretty` 选项。Ansible 中的 pipelining 模式和 `sudo` 中的 `requiretty` 选项会冲突，并且会导致你的 playbook 失败。

如果你想要启用 pipelining 模式，请确保你的目标机器上已禁用了 `sudo requiretty` 模式。

# 使用 `with_items` 进行优化

如果你想要多次执行类似的操作，可以多次使用相同的任务并带有不同的参数，或者使用 `with_items` 选项。除了使你的代码更易于阅读和理解之外，`with_items` 还可以提高你的性能。一个例子是在安装软件包（即 `apt`，`dnf`，`yum`，`package` 模块）时，如果使用 `with_items`，Ansible 将执行一个命令，而不是如果不使用则为每个软件包执行一个命令。你可以想象，这可以帮助提高你的性能。

# 理解任务执行时发生的情况

即使你已经实施了我们刚刚讨论过的加快 playbook 执行速度的方法，你可能仍然会发现一些任务需要很长时间。即使对许多其他模块来说可能是可能的，对一些任务来说这是非常普遍的。通常会给你带来这种问题的模块如下：

+   包管理（即 `apt`，`dnf`，`yum`，`package`）

+   云机器创建（即 `digital_ocean`，`ec2`）

这种慢的原因通常不是特定于 Ansible 的。一个示例情况可能是，如果你使用了一个包管理模块来更新你的机器。这需要在每台机器上下载几十甚至几百兆的软件并安装大量软件。加快这种操作的方法是在你的数据中心中拥有一个本地仓库，并让所有的机器指向它，而不是你的发行版仓库。这将允许你的机器以更高的速度下载，并且不使用通常带宽有限或计量的公共连接。

了解模块在后台执行的操作对优化 playbook 的执行至关重要。

在云机器创建的情况下，Ansible 只需向所选的云提供商执行 API 调用，并等待机器准备就绪。DigitalOcean 的机器可能需要长达一分钟才能创建（其他云可能需要更长时间），因此 Ansible 将等待该时间。一些模块具有异步模式，以避免此等待时间，但您必须确保机器准备就绪后才能使用它；否则，使用创建的机器的模块将失败。

# 总结

在本章中，我们看到了如何使用 Ansible 部署应用程序，以及您可以使用的各种分发和部署策略。我们还看到了如何使用 Ansible 创建 RPM 包以及如何使用不同的方法优化 Ansible 的性能。

在下一章中，我们将学习如何在 Windows 机器上使用 Ansible，以及如何找到其他人编写的角色并如何使用它们，还有一个用于 Ansible 的用户界面。
