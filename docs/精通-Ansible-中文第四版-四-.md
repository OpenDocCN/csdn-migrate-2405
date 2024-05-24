# 精通 Ansible 中文第四版（四）

> 原文：[`zh.annas-archive.org/md5/F58519F0D978AE01B8EEFA01F4E150D0`](https://zh.annas-archive.org/md5/F58519F0D978AE01B8EEFA01F4E150D0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：扩展 Ansible

必须说**Ansible**采用了*厨房水槽*的功能方法，并试图在开箱即用时提供您可能需要的所有功能。随着`ansible-core`包及其相关集合，截至撰写本文时，几乎有 6000 个模块可供在 Ansible 中使用-与本书第二版出版时包含的（大约）800 个相比！除此之外，还有丰富的插件和过滤器架构，包括多个回调插件、查找插件、过滤器插件和包括动态清单插件在内的插件。现在，集合提供了一个全新的向量，通过它可以提供新的功能。

尽管如此，总会有一些情况，Ansible 并不能完全执行所需的任务，特别是在大型和复杂的环境中，或者在自定义的内部系统已经开发的情况下。幸运的是，Ansible 的设计，加上其开源性质，使任何人都可以通过开发功能来扩展它变得很容易。随着 Ansible 3.0 的集合的出现，扩展功能比以往任何时候都更容易。然而，在本章中，我们将专注于为`ansible-core`包做出贡献的具体内容。如果您希望通过创建集合来做出贡献，您可以按照本章提供的步骤轻松开发所需的代码（例如，创建一个新模块），然后将其打包为集合，就像我们在*第二章*中描述的那样，*从早期的 Ansible 版本迁移*。您如何做出贡献取决于您和您的目标受众-如果您觉得您的代码将帮助所有使用 Ansible 的人，那么您可能希望将其提交给`ansible-core`；否则，最好将其构建到一个集合中。

本章将探讨以下几种方式，可以向 Ansible 添加新功能：

+   开发模块

+   开发插件

+   开发动态清单插件

+   向 Ansible 项目贡献代码

# 技术要求

要按照本章中提供的示例，您需要一台运行**Ansible 4.3**或更新版本的 Linux 机器。几乎任何 Linux 发行版都可以-对于那些感兴趣的人，所有本章中提供的代码都是在**Ubuntu Server 20.04 LTS**上测试的，除非另有说明，并且在 Ansible 4.3 上测试。本章附带的示例代码可以从 GitHub 上下载：[`github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter10`](https://github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter10)。

查看以下视频，了解代码的实际操作：[`bit.ly/3DTKL35`](https://bit.ly/3DTKL35)。

# 开发模块

模块是 Ansible 的工作马。它们提供了足够的抽象，使得 playbook 可以简单明了地陈述。由核心 Ansible 开发团队维护的模块和插件有 100 多个，并作为`ansible-core`包的一部分进行分发，涵盖命令、文件、软件包管理、源代码控制、系统、实用程序等。此外，社区贡献者维护了近 6000 个其他模块，扩展了许多这些类别和其他许多功能，例如公共云提供商、数据库、网络等，通过集合。真正的魔力发生在模块的代码内部，它接收传递给它的参数，并努力建立所需的结果。

在 Ansible 中，模块是被传输到远程主机以执行的代码片段。它们可以用远程主机可以执行的任何语言编写；然而，Ansible 提供了一些非常有用的快捷方式，用于用 Python 编写模块，您会发现大多数模块确实是用 Python 编写的。

## 基本模块构造

模块存在以满足需求-在主机上执行一项工作的需求。模块通常需要输入，但并不总是期望输入，并且将返回某种输出。模块还努力成为幂等，允许模块一遍又一遍地运行而不会产生负面影响。在 Ansible 中，输入以命令行参数的形式提供给模块，并且输出以 JSON 格式传递到`STDOUT`。

输入通常以空格分隔的`key=value`语法提供，模块负责将其解构为可用数据。如果您使用 Python，有方便的函数来管理这一点，如果您使用不同的语言，那么完全处理输入就取决于您的模块代码。

输出采用 JSON 格式。惯例规定，在成功的情况下，JSON 输出应至少有一个键`changed`，这是一个布尔值，表示模块执行是否导致更改。还可以返回其他数据，这些数据可能有助于定义发生了什么变化，或者为以后使用向 playbook 提供重要信息。此外，主机信息可以在 JSON 数据中返回，以根据模块执行结果自动创建主机变量。我们将在以后更详细地看一下这一点，在*提供事实数据*部分。

## 自定义模块

Ansible 提供了一种简单的机制来利用除 Ansible 自带模块之外的自定义模块。正如我们在[*第一章*]（B17462_01_Final_JC_ePub.xhtml#_idTextAnchor015）中学到的，*Ansible 的系统架构和设计*，Ansible 会搜索许多位置来找到所请求的模块。其中一个位置，实际上是第一个位置，是顶层 playbook 所在路径的`library/`子目录。这就是我们将放置自定义模块的地方，以便我们可以在示例 playbook 中使用它，因为我们的重点是为`ansible-core`软件包开发。但是，正如我们已经提到的，您也可以通过集合分发模块，并且[*第二章*]（B17462_02_Final_JC_ePub.xhtml#_idTextAnchor047）描述了（以本章节为例的实际示例）如何打包模块以通过集合进行分发。

除此之外，模块也可以嵌入在角色中，以提供角色可能依赖的附加功能。这些模块仅对包含模块的角色或在包含模块的角色之后执行的任何其他角色或任务可用。要使用角色提供模块，将模块放在角色根目录的`library/`子目录中。虽然这仍然是一种可行的途径，但预计随着 Ansible 3.0 及以后版本的普及，您将通过集合分发您的模块。提供了一个重叠期来支持许多现有的 Ansible 2.9 及更早版本的发行版。

## 示例-简单模块

为了演示编写基于 Python 的模块的简易性，让我们创建一个简单的模块。这个模块的目的是远程复制源文件到目标文件，这是一个简单的任务，我们可以逐步构建起来。为了启动我们的模块，我们需要创建模块文件。为了方便访问我们的新模块，我们将在已经使用的工作目录的`library/`子目录中创建文件。我们将这个模块称为`remote_copy.py`，为了开始它，我们需要放入一个 shebang 行，以指示这个模块将使用 Python 执行：

```
#!/usr/bin/python 
# 
```

对于基于 Python 的模块，约定使用`/usr/bin/python`作为列出的可执行文件。在远程系统上执行时，将使用远程主机的配置 Python 解释器来执行模块，因此如果您的 Python 代码不存在于此路径，也不必担心。接下来，我们将导入一个稍后在模块中使用的 Python 库，称为`shutil`：

```
import shutil 
```

现在，我们准备创建我们的`main`函数。`main`函数本质上是模块的入口点，模块的参数将在这里定义，执行也将从这里开始。在 Python 中创建模块时，我们可以在这个`main`函数中采取一些捷径，绕过大量样板代码，直接进行参数定义。

我们可以通过创建一个`AnsibleModule`对象并为参数提供一个`argument_spec`字典来实现这一点：

```
def main(): 
    module = AnsibleModule( 
        argument_spec = dict( 
            source=dict(required=True, type='str'), 
            dest=dict(required=True, type='str') 
        ) 
    ) 
```

在我们的模块中，我们提供了两个参数。第一个参数是`source`，我们将用它来定义复制的源文件。第二个参数是`dest`，它是复制的目的地。这两个参数都标记为必需，如果其中一个未提供，将引发错误。这两个参数都是`string`类型。`AnsibleModule`类的位置尚未定义，因为这将在文件的后面发生。

有了模块对象，我们现在可以创建在远程主机上执行实际工作的代码。我们将利用`shutil.copy`和我们提供的参数来实现这一点：

```
    shutil.copy(module.params['source'], 
                module.params['dest']) 
```

`shutil.copy`函数期望一个源和一个目的地，我们通过访问`module.params`来提供这些。`module.params`字典包含模块的所有参数。完成复制后，我们现在准备将结果返回给 Ansible。这是通过另一个`AnsibleModule`方法`exit_json`完成的。这个方法期望一组`key=value`参数，并将适当地格式化为 JSON 返回。由于我们总是执行复制，出于简单起见，我们将始终返回一个更改：

```
    module.exit_json(changed=True) 
```

这一行将退出函数，因此也将退出模块。这个函数假设操作成功，并将以成功的适当返回代码`0`退出模块。不过，我们还没有完成模块的代码；我们仍然需要考虑`AnsibleModule`的位置。这是一个小魔术发生的地方，我们告诉 Ansible 要与我们的模块结合的其他代码，以创建一个完整的可传输的作品：

```
from ansible.module_utils.basic import * 
```

就是这样！这一行就可以让我们访问所有基本的`module_utils`，一组不错的辅助函数和类。我们应该在我们的模块中加入最后一件事：几行代码，告诉解释器在执行模块文件时执行`main()`函数。

```
if __name__ == '__main__': 
    main() 
```

现在，我们的模块文件已经完成，这意味着我们可以用一个 playbook 来测试它。我们将称我们的 playbook 为`simple_module.yaml`，并将其存储在与`library/`目录相同的目录中，我们刚刚编写了我们的模块文件。出于简单起见，我们将在`localhost`上运行 play，并在`/tmp`中使用一些文件名作为源和目的地。我们还将使用一个任务来确保我们首先有一个源文件：

```
--- 
- name: test remote_copy module 
  hosts: localhost 
  gather_facts: false 

  tasks: 
  - name: ensure foo
    ansible.builtin.file:
      path: /tmp/rcfoo
      state: touch
  - name: do a remote copy
    remote_copy:
      source: /tmp/rcfoo
      dest: /tmp/rcbar
```

由于我们的新模块是从与 playbook 本地的`library/`目录运行的，它没有一个**完全合格的集合名称**（**FQCN**），因此在 playbook 中我们只会用它的简称来引用它。要运行这个 playbook，我们将运行以下命令：

```
ansible-playbook -i mastery-hosts simple_module.yaml -v
```

如果`remote_copy`模块文件写入了正确的位置，一切都将正常工作，屏幕输出将如下所示：

![图 10.1-运行一个简单的 playbook 来测试我们的第一个自定义 Ansible 模块](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_01.jpg)

图 10.1-运行一个简单的 playbook 来测试我们的第一个自定义 Ansible 模块

我们的第一个任务涉及`/tmp/rcfoo`路径，以确保它存在，然后我们的第二个任务使用`remote_copy`将`/tmp/rcfoo`复制到`/tmp/rcbar`。两个任务都成功，每次都会产生一个`changed`状态。

### 记录模块

除非包含了有关如何操作它的文档，否则不应该认为模块是完整的。模块的文档存在于模块本身中，称为`DOCUMENTATION`、`EXAMPLES`和`RETURN`的特殊变量中。

`DOCUMENTATION`变量包含一个特殊格式的字符串，描述了模块的名称，`ansible-core`的版本或其添加到的父集合的版本，模块的简短描述，更长的描述，模块参数的描述，作者和许可信息，额外要求以及对模块用户有用的任何额外说明。让我们在现有的`import shutil`语句下为我们的模块添加一个`DOCUMENTATION`字符串：

```
import shutil 

DOCUMENTATION = ''' 
--- 
module: remote_copy 
version_added: future 
short_description: Copy a file on the remote host 
description: 
  - The remote_copy module copies a file on the remote host from a given source to a provided destination. 
options: 
  source: 
    description: 
      - Path to a file on the source file on the remote host 
    required: True 
  dest: 
    description: 
      - Path to the destination on the remote host for the copy 
    required: True 
author: 
  - Jesse Keating 
''' 
```

字符串的格式本质上是 YAML，其中一些顶级键包含其中的哈希结构（与`options`键相同）。每个选项都有子元素来描述选项，指示选项是否是必需的，列出选项的任何别名，列出选项的静态选择，或指示选项的默认值。将此字符串保存到模块后，我们可以测试我们的格式，以确保文档将正确呈现。这是通过`ansible-doc`工具完成的，使用参数指示在哪里搜索模块。如果我们从与我们的 playbook 相同的位置运行它，命令将如下所示：

```
ansible-doc -M library/ remote_copy
```

输出应如下所示：

图 10.2 - 使用 ansible-doc 工具查看我们的新模块的文档

](Images/B17462_10_02.jpg)

图 10.2 - 使用 ansible-doc 工具查看我们的新模块的文档

在这个例子中，我将输出导入`cat`以防止分页程序隐藏执行行。我们的文档字符串似乎格式正确，并为用户提供了有关模块使用的重要信息。

`EXAMPLES`字符串用于提供模块的一个或多个示例用法，以及在 playbook 中使用的任务代码片段。让我们添加一个示例任务来演示其用法。这个变量定义传统上是在`DOCUMENTATION`定义之后：

```
EXAMPLES = ''' 
# Example from Ansible Playbooks 
- name: backup a config file 
  remote_copy: 
    source: /etc/herp/derp.conf 
    dest: /root/herp-derp.conf.bak 
''' 
```

有了这个变量定义，我们的`ansible-doc`输出现在将包括示例，如下所示：

图 10.3 - 通过 EXAMPLES 部分扩展我们的模块文档

](Images/B17462_10_03.jpg)

图 10.3 - 通过 EXAMPLES 部分扩展我们的模块文档

最后一个文档变量`RETURN`用于描述模块执行的返回数据。返回数据通常作为注册变量对后续使用很有用，并且有关预期返回数据的文档可以帮助 playbook 的开发。我们的模块还没有任何返回数据；因此，在我们可以记录任何返回数据之前，我们必须添加返回数据。这可以通过修改`module.exit_json`行来添加更多信息来完成。让我们将`source`和`dest`数据添加到返回输出中：

```
    module.exit_json(changed=True, source=module.params['source'], 
                     dest=module.params['dest']) 
```

重新运行 playbook 将显示返回额外数据，如下面的截图所示：

图 10.4 - 运行我们扩展的模块并添加返回数据

](Images/B17462_10_04.jpg)

图 10.4 - 运行我们扩展的模块并添加返回数据

仔细观察返回数据，我们可以看到比我们在模块中放入的更多数据。这是 Ansible 中的一些辅助功能；当返回数据集包括`dest`变量时，Ansible 将收集有关目标文件的更多信息。收集的额外数据是`gid`（组 ID），`group`（组名），`mode`（权限），`uid`（所有者 ID），`owner`（所有者名），`size`和`state`（文件，链接或目录）。我们可以在我们的`RETURN`变量中记录所有这些返回项，它是在`EXAMPLES`变量之后添加的。两组三个单引号（`'''`）之间的所有内容都会被返回 - 因此，这第一部分返回文件路径和所有权：

```
RETURN = ''' 
source: 
  description: source file used for the copy 
  returned: success 
  type: string 
  sample: "/path/to/file.name" 
dest: 
  description: destination of the copy 
  returned: success 
  type: string 
  sample: "/path/to/destination.file" 
gid: 
  description: group ID of destination target 
  returned: success 
  type: int 
  sample: 502 
group: 
  description: group name of destination target 
  returned: success 
  type: string 
  sample: "users" 
uid: 
  description: owner ID of destination target 
  returned: success 
  type: int 
  sample: 502 
owner: 
  description: owner name of destination target 
  returned: success 
  type: string 
  sample: "fred"
```

继续模块定义文件的这一部分，这一部分返回有关文件大小，状态和权限的详细信息：

```
mode: 
  description: permissions of the destination target 
  returned: success 
  type: int 
  sample: 0644 
size: 
  description: size of destination target 
  returned: success 
  type: int 
  sample: 20 
state: 
  description: state of destination target 
  returned: success 
  type: string 
  sample: "file" 
''' 
```

每个返回的项目都列有描述、项目在返回数据中的情况、项目的类型和值的示例。`RETURN`字符串由`ansible-doc`解析，但返回值按字母顺序排序，在本书的上一个版本中，我们看到值是按模块本身中列出的顺序打印的。以下屏幕截图显示了这一点：

![图 10.5 - 向我们的模块添加返回数据文档](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_05.jpg)

图 10.5 - 向我们的模块添加返回数据文档

通过这种方式，我们建立了一个包含文档的模块，如果我们将其贡献给社区，对其他人来说非常有用，甚至对我们自己来说，当我们一段时间后回来时也很有用。

### 提供事实数据

与作为模块的一部分返回的数据类似，例如`exit`，模块可以通过在名为`ansible_facts`的键中返回数据来直接为主机创建事实。直接从模块提供事实可以消除需要使用后续的`set_fact`任务注册任务的返回的需要。为了演示这种用法，让我们修改我们的模块以返回`source`和`dest`数据作为事实。因为这些事实将成为顶级主机变量，我们希望使用比`source`和`dest`更具描述性的事实名称。用以下代码替换我们模块中的当前`module.exit_json`行：

```
    facts = {'rc_source': module.params['source'], 
             'rc_dest': module.params['dest']} 

    module.exit_json(changed=True, ansible_facts=facts) 
```

我们还将向我们的 playbook 添加一个任务，使用`debug`语句中的一个事实：

```
  - name: show a fact 
    ansible.builtin.debug: 
      var: rc_dest 
```

现在，运行 playbook 将显示新的返回数据，以及变量的使用，如下屏幕截图所示：

![图 10.6 - 向我们的自定义模块添加事实，并在 playbook 执行期间查看它们的值](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_06.jpg)

图 10.6 - 向我们的自定义模块添加事实，并在 playbook 执行期间查看它们的值

如果我们的模块不返回事实（我们之前的`remote_copy.py`版本没有），我们将不得不注册输出并使用`set_fact`为我们创建事实，如下面的代码所示：

```
  - name: do a remote copy 
    remote_copy: 
      source: /tmp/rcfoo 
      dest: /tmp/rcbar 
    register: mycopy 

  - name: set facts from mycopy 
    ansible.builtin.set_fact: 
      rc_dest: "{{ mycopy.dest }}" 
```

虽然能够这样做很有用，但在设计我们的模块时，最好让模块定义所需的事实。如果不这样做，那么以前的注册和`set_fact`代码将需要在 playbook 中每次使用我们的模块时重复！

### 检查模式

自其存在以来，Ansible 就支持**检查模式**，这是一种操作模式，会假装对系统进行更改，而实际上并未更改系统。检查模式对于测试是否会发生更改或系统状态是否已漂移自上次 Ansible 运行以来非常有用。检查模式取决于模块是否支持它并返回数据，就好像已经完成了更改一样。在我们的模块中支持检查模式需要两个更改；第一个是指示模块支持检查模式，而第二个是在执行之前检测检查模式是否激活并返回数据。

#### 支持检查模式

要指示模块支持检查模式，必须在创建模块对象时设置一个参数。这可以在定义模块对象中的`argument_spec`变量之前或之后完成；在这里，我们将在定义之后完成：

```
    module = AnsibleModule( 
        argument_spec = dict( 
            source=dict(required=True, type='str'), 
            dest=dict(required=True, type='str') 
        ), 
        supports_check_mode=True 
    ) 
```

如果您正在修改现有代码，请不要忘记在`argument_spec`字典定义之后添加逗号，如前面的代码所示。

#### 处理检查模式

检测检查模式是否激活非常容易。模块对象将具有一个`check_mode`属性，当检查模式激活时，它将设置为布尔值`true`。在我们的模块中，我们希望在执行复制之前检测检查模式是否激活。我们可以简单地将复制操作移到一个`if`语句中，以避免在检查模式激活时进行复制。除此之外，对模块不需要进行进一步的更改：

```
    if not module.check_mode: 
        shutil.copy(module.params['source'], 
                    module.params['dest']) 
```

现在，我们可以运行我们的 playbook，并在执行中添加`-C`参数。这个参数启用检查模式。我们还将测试以确保 playbook 没有创建和复制文件。以下截图显示了这一点：

![图 10.7-为我们的 Ansible 模块添加检查模式支持](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_07.jpg)

图 10.7-为我们的 Ansible 模块添加检查模式支持

尽管模块的输出看起来好像创建并复制了文件，但我们可以看到在执行之前这些文件并不存在，并且在执行之后仍然不存在，这清楚地表明我们的简单模块是在检查模式下运行的。

现在我们已经看了我们的简单示例模块，我们将探讨如何通过另一个重要的项目-插件来扩展 Ansible 的功能。

# 开发插件

插件是扩展或修改 Ansible 功能的另一种方式。虽然模块是作为任务执行的，但插件在各种其他地方使用。插件根据它们插入到 Ansible 执行的位置被分为几种类型。Ansible 为每个领域提供了一些插件，最终用户可以创建自己的插件来扩展这些特定领域的功能。

## 连接类型插件

每当 Ansible 连接到主机执行任务时，都会使用连接插件。Ansible 附带了一些连接插件，包括`ssh`、`community.docker.docker`、`local`和`winrm`。Ansible 可以通过创建连接插件来利用其他连接机制，这可能会有用，如果您必须连接到一些新类型的系统，比如网络交换机，或者也许有一天连接到您的冰箱。要创建一个新的连接插件，我们必须了解并使用底层通信协议，这本身可能需要一本专门的书籍；因此，我们不会在这里尝试创建一个。然而，开始的最简单方法是阅读与 Ansible 一起提供的现有插件，并选择一个进行必要的修改。现有的插件可以在您的系统上安装 Ansible Python 库的位置中找到，例如在我的系统上是`/usr/local/lib/python3.8/dist-packages/ansible/plugins/connection/`。您也可以在 GitHub 上查看它们-例如，如果您想查找与`ansible-core`的`2.11.1`版本相关的文件，您可以在这里查看：[`github.com/ansible/ansible/tree/v2.11.1/lib/ansible/plugins/connection`](https://github.com/ansible/ansible/tree/v2.11.1/lib/ansible/plugins/connection)。

## Shell 插件

与连接插件类似，Ansible 使用**shell 插件**在 shell 环境中执行操作。每个 shell 都有 Ansible 关心的微妙差异，以正确执行命令，重定向输出，发现错误等交互。Ansible 支持多种 shell，包括`sh`、`ansible.posix.csh`、`ansible.posix.fish`和`powershell`。我们可以通过实现新的 shell 插件来添加更多的 shell。您可以在这里查看它们的代码（对于`ansible-core`的`2.11.1`版本）：[`github.com/ansible/ansible/tree/v2.11.1/lib/ansible/plugins/shell`](https://github.com/ansible/ansible/tree/v2.11.1/lib/ansible/plugins/shell)。

## 查找插件

**查找插件**是 Ansible 从主机系统访问外部数据源并实现语言特性，比如循环结构（`loop`或`with_*`）的方式。可以创建查找插件来访问现有数据存储中的数据或创建新的循环机制。现有的查找插件可以在`plugins/lookup/`中找到，或者在 GitHub 上找到：[`github.com/ansible/ansible/tree/v2.11.1/lib/ansible/plugins/lookup`](https://github.com/ansible/ansible/tree/v2.11.1/lib/ansible/plugins/lookup)。查找插件可以添加以引入新的循环内容的方式，或者用于在外部系统中查找资源。

## Vars 插件

存在用于注入变量数据的构造，形式为**vars 插件**。诸如`host_vars`和`group_vars`之类的数据是通过插件实现的。虽然可以创建新的变量插件，但通常最好创建自定义清单源或事实模块。

## 事实缓存插件

Ansible 可以在 playbook 运行之间缓存事实。事实的缓存位置取决于所使用的配置缓存插件。Ansible 包括在`memory`（它们在运行之间不会被缓存，因为这不是持久的）、`community.general.memcached`、`community.general.redis`和`jsonfile`中缓存事实的插件。创建一个**事实缓存插件**可以启用额外的缓存机制。

## 过滤插件

虽然 Jinja2 包含了几个过滤器，但 Ansible 已经使过滤器可插拔以扩展 Jinja2 的功能。Ansible 包括了一些对 Ansible 操作有用的过滤器，并且 Ansible 的用户可以添加更多过滤器。现有的插件可以在`plugins/filter/`中找到。

为了演示过滤器插件的开发，我们将创建一个简单的过滤器插件来对文本字符串进行一些愚蠢的操作。我们将创建一个过滤器，它将用字符串`somebody else's computer`替换任何出现的`the cloud`。我们将在现有工作目录中的新目录`filter_plugins/`中的文件中定义我们的过滤器。文件的名称无关紧要，因为我们将在文件中定义过滤器的名称；所以，让我们将文件命名为`filter_plugins/sample_filter.py`。

首先，我们需要定义执行翻译的函数，并提供翻译字符串的代码：

```
def cloud_truth(a): 
    return a.replace("the cloud", "somebody else's computer") 
```

接下来，我们需要构建一个`FilterModule`对象，并在其中定义我们的过滤器。这个对象是 Ansible 将要加载的对象，Ansible 期望在对象内有一个`filters`函数，该函数返回文件中的一组过滤器名称到函数的映射：

```
class FilterModule(object): 
    '''Cloud truth filters''' 
    def filters(self): 
        return {'cloud_truth': cloud_truth} 
```

现在，我们可以在一个 playbook 中使用这个过滤器，我们将其命名为`simple_filter.yaml`：

```
--- 
- name: test cloud_truth filter 
  hosts: localhost 
  gather_facts: false 
  vars: 
    statement: "I store my files in the cloud" 
  tasks: 
  - name: make a statement 
    ansible.builtin.debug: 
      msg: "{{ statement | cloud_truth }}" 
```

现在，让我们运行我们的 playbook，看看我们的过滤器如何运行：

![图 10.8 - 执行 playbook 以测试我们的新过滤器插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_08.jpg)

图 10.8 - 执行 playbook 以测试我们的新过滤器插件

我们的过滤器起作用了，它将`the cloud`这个词替换为`somebody else's computer`。这是一个愚蠢的例子，没有任何错误处理，但它展示了我们扩展 Ansible 和 Jinja2 的过滤器功能的能力。

重要提示

虽然包含过滤器定义的文件的名称可以是开发人员想要的任何名称，但最佳做法是将其命名为过滤器本身，以便将来可以轻松找到它，可能是由其他合作者找到。这个例子没有遵循这个规则，以演示文件名不附加到过滤器名称。

## 回调插件

**回调**是可以插入以增加功能的 Ansible 执行中的位置。有预期的回调点可以注册以触发这些点的自定义操作。以下是可能用于在编写时触发功能的点的列表：

+   `v2_on_any`

+   `v2_runner_on_failed`

+   `v2_runner_on_ok`

+   `v2_runner_on_skipped`

+   `v2_runner_on_unreachable`

+   `v2_runner_on_async_poll`

+   `v2_runner_on_async_ok`

+   `v2_runner_on_async_failed`

+   `v2_runner_on_start`

+   `v2_playbook_on_start`

+   `v2_playbook_on_notify`

+   `v2_playbook_on_no_hosts_matched`

+   `v2_playbook_on_no_hosts_remaining`

+   `v2_playbook_on_task_start`

+   `v2_playbook_on_cleanup_task_start`

+   `v2_playbook_on_handler_task_start`

+   `v2_playbook_on_vars_prompt`

+   `v2_playbook_on_import_for_host`

+   `v2_playbook_on_not_import_for_host`

+   `v2_playbook_on_play_start`

+   `v2_playbook_on_stats`

+   `v2_on_file_diff`

+   `v2_playbook_on_include`

+   `v2_runner_item_on_ok`

+   `v2_runner_item_on_failed`

+   `v2_runner_item_on_skipped`

+   `v2_runner_retry`

当 Ansible 运行达到这些状态时，任何具有在这些点运行代码的插件都将被执行。这提供了在不修改基本代码的情况下扩展 Ansible 的巨大能力。

回调可以以各种方式使用：更改屏幕上的显示方式，更新进度的中央状态系统，实现全局锁定系统，或者几乎可以想象的任何事情。这是扩展 Ansible 功能的最强大方式。但是，您会注意到先前列出的项目在官方 Ansible 文档网站([`docs.ansible.com`](https://docs.ansible.com))上没有出现，也不会被`ansible-doc`命令列出。查找这些回调并了解更多关于它们的信息的好地方是`plugins/callback/__init__.py`文件，在您的`ansible-core`安装目录下。例如，在我的系统上，Ansible 是使用 pip 安装的，完整路径是`/usr/local/lib/python3.8/dist-packages/ansible/plugins/callback/__init__.py`（如果您想在互联网上查找此文件，`ansible-core`的`2.11.1`版本的文件可以在此处找到：[`github.com/ansible/ansible/blob/v2.11.1/lib/ansible/plugins/callback/__init__.py`](https://github.com/ansible/ansible/blob/v2.11.1/lib/ansible/plugins/callback/__init__.py)）。

为了演示我们开发回调插件的能力，我们将创建一个简单的插件，当 playbook 在最后打印 play 摘要时，它将在屏幕上打印一些愚蠢的东西：

1.  首先，我们需要创建一个新目录来保存我们的回调。Ansible 将查找的位置是`callback_plugins/`。与之前的`filter`插件不同，我们确实需要仔细命名我们的回调插件文件，因为它也必须在`ansible.cfg`文件中反映出来。

1.  我们将命名为`callback_plugins/shrug.py`。由于 Ansible 版本大于 3.0 正在向 Python 3 支持移动（尽管在撰写本文时仍支持 Python 2.7），因此您的插件代码应该是为 Python 3 编写的。首先在插件中添加以下 Python 3 头：

```
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
```

1.  接下来，您需要添加一个文档块，就像我们在本章的*开发模块*部分所做的那样。在本书的上一版中，不需要这样做，但现在，如果您不这样做，将会收到弃用警告，并且您的回调插件在`ansible-core` 2.14 发布时可能无法工作。我们的文档块将如下所示：

```
DOCUMENTATION = '''
    callback: shrug
    type: stdout
    short_description: modify Ansible screen output
    version_added: 4.0
    description:
        - This modifies the default output callback for ansible-playbook.
    extends_documentation_fragment:
      - default_callback
    requirements:
      - set as stdout in configuration
'''
```

文档中的大多数项目都是不言自明的，但值得注意的是`extends_documentation_fragment`项目。文档块的这一部分是与`ansible-core` 2.14 兼容所必需的部分，因为我们在这里扩展了`default_callback`插件，我们需要告诉 Ansible 我们正在扩展这一部分文档。

1.  完成后，我们需要创建一个`CallbackModule`类，它是从`ansible.plugins.callback.default`中找到的`default`回调插件中定义的`CallbackModule`的子类，因为我们只需要更改正常输出的一个方面。

1.  在这个类中，我们将定义变量值来指示它是`2.0`版本的回调，它是`stdout`类型的回调，并且它的名称是`shrug`。

1.  此外，在这个类中，我们必须初始化它，以便我们可以定义我们想要插入以使某些事情发生的回调点中的一个或多个。在我们的示例中，我们想要修改运行结束时生成的 playbook 摘要的显示，因此我们将修改`v2_playbook_on_stats`回调。

1.  为了完成我们的插件，我们必须调用原始的回调模块本身。Ansible 现在一次只支持一个`stdout`插件，因此如果我们不调用原始插件，我们将发现我们的插件的输出是唯一产生的输出-有关 playbook 运行的所有其他信息都将丢失！文档块下面的最终代码应该如下所示：

```
from ansible.plugins.callback.default import CallbackModule as CallbackModule_default
class CallbackModule(CallbackModule_default):
  CALLBACK_VERSION = 2.0
  CALLBACK_TYPE = 'stdout'
  CALLBACK_NAME = 'shrug'
  def __init__(self):
    super(CallbackModule, self).__init__()
  def v2_playbook_on_stats(self, stats):
    msg = b'\xc2\xaf\\_(\xe3\x83\x84)_/\xc2\xaf'
    self._display.display(msg.decode('utf-8') * 8)
    super(CallbackModule, self).v2_playbook_on_stats(stats)
```

1.  由于此回调是`stdout_callback`，我们需要创建一个`ansible.cfg`文件，并在其中指示应使用`shrug` `stdout`回调。`ansible.cfg`文件可以在`/etc/ansible/`中找到，也可以在与 playbook 相同的目录中找到：

```
[defaults] 
stdout_callback = shrug 
```

1.  这就是我们在回调中要写的全部内容。一旦保存，我们就可以重新运行之前的 playbook，这个 playbook 练习了我们的`sample_filter`，但这次，在屏幕上会看到不同的东西：

![图 10.9-将我们的 shrug 插件添加到修改 playbook 运行输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_09.jpg)

图 10.9-将我们的 shrug 插件添加到修改 playbook 运行输出

这很愚蠢，但它展示了插入到 playbook 执行的各个点的能力。我们选择在屏幕上显示一系列耸肩，但我们也可以与一些内部审计和控制系统进行交互，记录操作，或者向 IRC 或 Slack 频道报告进度。

## 动作插件

**动作插件**用于在不实际执行模块的情况下钩入任务结构，或者在在远程主机上执行模块之前在 Ansible 主机上执行代码。Ansible 包含多个动作插件，它们可以在`plugins/action/`中找到。其中一个动作插件是`template`插件，它可以用来代替`template`模块。当 playbook 作者编写`template`任务时，该任务将调用`template`插件来执行工作。该插件将在将内容复制到远程主机之前在本地渲染模板。因为动作必须在本地发生，所以由动作插件完成工作。我们应该熟悉的另一个动作插件是`debug`插件，在本书中我们大量使用它来打印内容。当我们尝试在同一个任务中完成本地工作和远程工作时，创建自定义动作插件是有用的。

## 分发插件

与分发自定义模块类似，存储自定义插件的标准位置与期望使用插件的 playbooks 一起。插件的默认位置是与 Ansible 代码安装一起提供的位置，`~/.ansible/plugins/`的子目录，以及项目根目录的子目录（顶级 playbook 存储的位置）。插件也可以在角色的相同子目录中分发，以及集合中，正如我们在*第二章*中所介绍的那样，*从早期 Ansible 版本迁移*。要使用来自任何其他位置的插件，我们需要在`ansible.cfg`文件中定义查找插件类型的插件的位置，或者引用集合，就像我们在*第二章*中加载示例过滤器模块时所演示的那样，*从早期 Ansible 版本迁移*。

如果您在项目根目录内分发插件，每种插件类型都有自己的顶级目录：

+   `action_plugins/`

+   `cache_plugins/`

+   `callback_plugins/`

+   `connection_plugins/`

+   `shell_plugins/`

+   `lookup_plugins/`

+   `vars_plugins/`

+   `filter_plugins/`

与其他 Ansible 结构一样，找到的具有相同名称的第一个插件将被使用，并且与模块一样，首先检查相对于项目根目录的路径，允许本地覆盖现有插件。只需将过滤器文件放在适当的子目录中，当引用时将自动使用它。

# 开发动态清单插件

**清单插件**是一些代码，将为 Ansible 执行创建清单数据。在许多环境中，简单的`ini`文件样式的清单源和变量结构不足以表示实际管理的基础设施。在这种情况下，需要动态清单源，它将在每次执行 Ansible 时动态发现清单和数据。许多这些动态源与 Ansible 一起提供，主要是为了在一个云计算平台或另一个云计算平台内部构建的基础设施上操作 Ansible。与 Ansible 4.3 一起提供的动态清单插件的简短而不完整的列表（现在有超过 40 个）包括以下内容-请注意来自 FQCNs 的这些插件，这些插件曾经作为 Ansible 2.x 版本的一部分提供，现在作为构成 Ansible 4.3 的更广泛集合的一部分被包含进来：

+   `azure.azcollection.azure_rm`

+   `community.general.cobbler`

+   `community.digitalocean.digitalocean`

+   `community.docker.docker_containers`

+   `amazon.aws.aws_ec2`

+   `google.cloud.gcp_compute`

+   `community.libvirt.libvirt`

+   `community.general.linode`

+   `kubernetes.core.openshift`

+   `openstack.cloud.openstack`

+   `community.vmware.vmware_vm_inventory`

+   `servicenow.servicenow.now`

清单插件本质上是可执行脚本。Ansible 使用设置的参数（`--list`或`--host <hostname>`）调用脚本，并期望在`STDOUT`上以 JSON 格式输出。当提供`--list`参数时，Ansible 期望列出要管理的所有组的列表。每个组可以列出主机成员资格、子组成员资格和组变量数据。当使用`--host <hostname>`参数调用脚本时，Ansible 期望返回特定于主机的数据（或空的 JSON 字典）。

使用动态清单源很容易。可以通过在`ansible`和`ansible-playbook`中使用`-i`（`--inventory-file`）选项直接引用源，也可以通过将插件文件放在`ansible.cfg`中清单路径引用的目录中。

在创建清单插件之前，我们必须了解在使用我们的脚本时`--list`或`--host`的预期格式。

## 列出主机

当`--list`参数传递给清单脚本时，Ansible 期望 JSON 输出数据具有一组顶级键。这些键以清单中的组命名。每个组都有一个键。组键内的结构因需要在组中表示的数据而异。如果一个组只有主机而没有组级变量，则键内的数据可以简单地是主机名的列表。如果组有变量或子组（一组组），则数据需要是一个哈希，可以有一个或多个名为`hosts`、`vars`或`children`的键。`hosts`和`children`子键具有列表值，即组中存在的主机列表或子组列表。`vars`子键具有哈希值，其中每个变量的名称和值由键和值表示。

## 列出主机变量

当`--host <hostname>`参数传递给清单脚本时，Ansible 期望 JSON 输出数据只是变量的哈希，其中每个变量的名称和值由键和值表示。如果对于给定主机没有变量，则期望一个空的哈希。 

## 简单的库存插件

为了演示开发清单插件，我们将创建一个简单打印一些静态清单主机数据的插件 - 它不会是动态的，但这是理解基础知识和所需输出格式的一个很好的第一步。这是基于我们在整本书中使用过的一些清单，所以它们在某些部分可能看起来很熟悉。我们将把我们的清单插件写入项目根目录中名为`mastery-inventory.py`的文件，并使其可执行。我们将使用 Python 编写此文件，以便轻松处理执行参数和 JSON 格式化，但请记住，您可以使用任何您喜欢的语言编写清单脚本，只要它们产生所需的 JSON 输出：

1.  首先，我们需要添加一个 shebang 行来指示此脚本将使用 Python 执行：

```
#!/usr/bin/env python 
# 
```

1.  接下来，我们需要导入一些稍后在插件中需要的 Python 模块：

```
import json 
import argparse 
```

1.  现在，我们将创建一个 Python 字典来保存我们所有的组。我们的一些组只有主机，而其他组有变量或子组。我们将相应地格式化每个组：

```
inventory = {} 
inventory['web'] = {'hosts': ['mastery.example.name'], 
'vars': {'http_port': 80, 
'proxy_timeout': 5}} 
inventory['dns'] = {'hosts': ['backend.example.name']} 
inventory['database'] = {'hosts': ['backend.example.name'], 
'vars': {'ansible_ssh_user': 'database'}} 
inventory['frontend'] = {'children': ['web']} 
inventory['backend'] = {'children': ['dns', 'database'], 
'vars': {'ansible_ssh_user': 'blotto'}} 
inventory['errors'] = {'hosts': ['scsihost']} 
inventory['failtest'] = {'hosts': ["failer%02d" % n for n in 
                                   range(1,11)]} 
```

1.  创建我们的`failtest`组（您将在下一章中看到此操作），在我们的清单文件中将表示为`failer[01:10]`，我们可以使用 Python 列表推导来为我们生成列表，格式化列表中的项目与我们的`ini`格式的清单文件完全相同。其他组条目应该是不言自明的。

1.  我们的原始清单还有一个`all`组变量，它为所有组提供了一个默认变量`ansible_ssh_user`（组可以覆盖），我们将在这里定义并在文件后面使用：

```
allgroupvars = {'ansible_ssh_user': 'otto'} 
```

1.  接下来，我们需要在它们自己的字典中输入特定于主机的变量。我们原始清单中只有一个节点具有特定于主机的变量 - 我们还将添加一个新主机`scsihost`，以进一步开发我们的示例：

```
hostvars = {} 
hostvars['mastery.example.name'] = {'ansible_ssh_host': '192.168.10.25'} 
hostvars['scsihost'] = {'ansible_ssh_user': 'jfreeman'} 
```

1.  定义了所有数据后，我们现在可以继续处理参数解析的代码。这可以通过我们在文件中导入的`argparse`模块来完成：

```
parser = argparse.ArgumentParser(description='Simple Inventory')
parser.add_argument('--list', action='store_true', help='List all hosts')
parser.add_argument('--host', help='List details of a host')
args = parser.parse_args()
```

1.  解析参数后，我们可以处理`--list`或`--host`操作。如果请求列表，我们只需打印我们清单的 JSON 表示。这是我们将考虑`allgroupvars`数据的地方；每个组的默认`ansible_ssh_user`。我们将循环遍历每个组，创建`allgroupvars`数据的副本，更新该数据以及可能已经存在于组中的任何数据，然后用新更新的副本替换组的变量数据。最后，我们将打印结果：

```
if args.list: 
for group in inventory: 
ag = allgroupvars.copy() 
ag.update(inventory[group].get('vars', {})) 
inventory[group]['vars'] = ag 
    print(json.dumps(inventory)) 
```

1.  最后，我们将通过构建一个字典来处理`--host`操作，该字典包含可以应用于传递给此脚本的主机的所有变量。我们将使用 Ansible 在解析`ini`格式清单时使用的优先顺序的近似值来执行此操作。这段代码是迭代的，嵌套循环在生产环境中效率不高，但在这个例子中，它对我们很有用。输出是提供的主机的 JSON 格式的变量数据，如果提供的主机没有特定的变量数据，则为空哈希：

```
elif args.host:
    hostfound = False
    agghostvars = allgroupvars.copy()
    for group in inventory:
        if args.host in inventory[group].get('hosts', {}):
            hostfound = True
            for childgroup in inventory:
                if group in inventory[childgroup].get('children', {}):
                    agghostvars.update(inventory[childgroup].get('vars', {}))
    for group in inventory:
        if args.host in inventory[group].get('hosts', {}):
            hostfound = True
            agghostvars.update(inventory[group].get('vars', {}))
    if hostvars.get(args.host, {}):
        hostfound = True
    agghostvars.update(hostvars.get(args.host, {}))
    if not hostfound:
        agghostvars = {}
    print(json.dumps(agghostvars))
```

现在，我们的清单已经准备好测试了！我们可以直接执行它，并传递`--help`参数，我们可以免费使用`argparse`获得。这将根据我们之前在文件中提供的`argparse`数据显示我们脚本的用法：

![图 10.10 - 测试我们的动态清单脚本的内置帮助函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_10.jpg)

图 10.10 - 测试我们的动态清单脚本的内置帮助函数

重要提示

不要忘记使动态清单脚本可执行；例如，`chmod +x mastery-inventory.py`。

如果我们传递`--list`，我们将得到所有组的输出，以及每个组中的所有主机和所有相关的清单变量：

![图 10.11 - 显示我们的动态清单脚本的--list 参数产生的 JSON 输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_11.jpg)

图 10.11-显示我们的动态清单脚本的--list 参数产生的 JSON 输出

同样，如果我们使用`--host`参数和我们知道在清单中的主机名运行这个 Python 脚本，我们将看到传递的主机名的主机变量。如果我们传递一个组名，什么都不应该返回，因为脚本只返回有效的单个主机名的数据：

![图 10.12-显示我们的动态清单脚本的--list 参数产生的 JSON 输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_12.jpg)

图 10.12-显示我们的动态清单脚本的--list 参数产生的 JSON 输出

现在，我们准备使用我们的清单文件与 Ansible。让我们制作一个新的 playbook（`inventory_test.yaml`）来显示主机名和`ssh`用户名数据：

```
--- 
- name: test the inventory 
  hosts: all 
  gather_facts: false 

  tasks: 
  - name: hello world 
    ansible.builtin.debug: 
      msg: "Hello world, I am {{ inventory_hostname }}. 
            My username is {{ ansible_ssh_user }}"
```

在我们可以使用新的清单插件之前，我们还有一件事要做。默认情况下（作为安全功能），大多数 Ansible 的清单插件都是禁用的。为了确保我们的动态清单脚本能够运行，打开适用的`ansible.cfg`文件编辑器，并在`[inventory]`部分查找`enable_plugins`行。至少，它应该看起来像这样（尽管如果您愿意，您可以选择启用更多插件）：

```
[inventory]
enable_plugins = ini, script
```

要使用我们的新清单插件与这个 playbook，我们可以简单地使用`-i`参数引用插件文件。因为我们在 playbook 中使用了`all`主机组，我们还将限制运行到一些组以节省屏幕空间。我们还将计时执行，这在下一节中将变得重要，所以运行以下命令来执行 playbook：

```
time ansible-playbook -i mastery-inventory.py inventory_test.yaml --limit backend,frontend,errors
```

这次运行的输出应该如下所示：

![图 10.13-运行测试 playbook 针对我们的动态清单脚本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_13.jpg)

图 10.13-运行测试 playbook 针对我们的动态清单脚本

正如你所看到的，我们得到了我们期望的主机，我们得到了`master.example.name`的默认`ssh`用户。`backend.example.name`和`scsihost`分别显示了它们特定于主机的`ssh`用户名。

### 优化脚本性能

使用这个清单脚本，当 Ansible 启动时，它将使用`--list`一次执行脚本来收集组数据。然后，Ansible 将再次使用`--host <hostname>`执行脚本，对于第一次调用中发现的每个主机。使用我们的脚本，这需要很少的时间，因为主机很少，我们的执行非常快。然而，在具有大量主机或需要较长时间运行的插件的环境中，收集清单数据可能是一个耗时的过程。幸运的是，有一个优化可以在`--list`调用的返回数据中进行，这将防止 Ansible 为每个主机重新运行脚本。主机特定的数据可以一次性返回到组数据返回中，放在名为`_meta`的顶级键内，它有一个名为`hostvars`的子键，其中包含具有主机变量和变量数据本身的所有主机的哈希。当 Ansible 在`--list`返回中遇到`_meta`键时，它将跳过`--host`调用，并假定所有主机特定的数据已经返回，可能节省大量时间！让我们修改我们的清单脚本，将主机变量返回到`_meta`中，然后在`--host`选项中创建一个错误条件，以显示`--host`没有被调用：

1.  首先，一旦所有的`hostvars`都使用与之前相同的算法构建起来，我们将在清单字典中添加`_meta`键，并在参数解析之前：

```
hostvars['scsihost'] = {'ansible_ssh_user': 'jfreeman'}
agghostvars = dict()
for outergroup in inventory:
    for grouphost in inventory[outergroup].get('hosts', {}):
        agghostvars[grouphost] = allgroupvars.copy()
        for group in inventory:
            if grouphost in inventory[group].get('hosts', {}):
                for childgroup in inventory:
                    if group in inventory[childgroup].get('children', {}):
                        agghostvars[grouphost].update(inventory[childgroup].get('vars', {}))
        for group in inventory:
            if grouphost in inventory[group].get('hosts', {}):
                agghostvars[grouphost].update(inventory[group].get('vars', {}))
        agghostvars[grouphost].update(hostvars.get(grouphost, {}))
inventory['_meta'] = {'hostvars': agghostvars}
parser = argparse.ArgumentParser(description='Simple Inventory')
```

接下来，我们将改变`--host`处理以引发异常：

```
elif args.host:
raise StandardError("You've been a bad person") 
```

1.  现在，我们将使用与之前相同的命令重新运行`inventory_test.yaml` playbook，以确保我们仍然得到正确的数据：![图 10.14-运行我们优化的动态清单脚本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_14.jpg)

图 10.14-运行我们优化的动态清单脚本

1.  只是为了确保，我们将手动使用`--host`参数运行清单插件，以显示异常：

![图 10.15 - 演示--host 参数在我们新优化的脚本上不起作用](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_15.jpg)

图 10.15 - 演示--host 参数在我们新优化的脚本上不起作用

通过这种优化，我们的简单 playbook，使用我们的清单模块，现在运行速度快了几个百分点，因为清单解析效率提高了。这在这里可能看起来不算什么，但是当扩展到更复杂的清单时，这将是显著的。

# 为 Ansible 项目做贡献

并非所有修改都需要符合本地站点的要求。Ansible 用户通常会发现可以对项目进行增强的地方，从而使其他人受益。这些增强可以通过集合进行贡献，在 Ansible 3.0 版本之后的新结构中，这很可能是大多数人最合适的途径。在这种情况下，您可以按照*第二章*中给出的指导，*从早期的 Ansible 版本迁移*，构建和发布一个集合。但是，如果您开发了下一个杀手级插件或过滤器，应该将其添加到`ansible-core`项目本身呢？在本节中，我们将看看您可以如何做到这一点。贡献可以是对现有内置模块或核心 Ansible 代码的更新，对文档的更新，新的过滤器或插件，或者仅仅是测试其他社区成员提出的贡献。

## 贡献提交

Ansible 项目使用 GitHub ([`github.com`](https://github.com))来管理代码存储库、问题和项目的其他方面。Ansible 组织([`github.com/ansible`](https://github.com/ansible))是代码存储库的所在地。主要存储库是`ansible`存储库（现在包含`ansible-core`代码），出于传统原因，它位于这里：[`github.com/ansible/ansible`](https://github.com/ansible/ansible)。这是`ansible-core`代码、内置模块和文档的所在地。这是应该分叉以开发贡献的存储库。

重要提示

Ansible 项目使用名为`devel`的开发分支，而不是传统的`master`名称。大多数贡献都针对`devel`分支或稳定发布分支。

### Ansible 存储库

Ansible 存储库的根目录下有几个文件和文件夹。这些文件主要是高级文档文件、代码许可证或持续集成测试平台配置。

其中一些目录值得注意：

+   `bin`：各种 ansible 核心可执行文件的源代码

+   `docs`：API 文档、[`docs.ansible.com`](https://docs.ansible.com)网站和主要页面的源代码

+   `hacking`：用于在 Ansible 源上进行黑客攻击的指南和实用程序

+   `lib/ansible`：核心 Ansible 源代码

+   `test`：单元测试和集成测试代码

对 Ansible 的贡献可能会出现在这些关键文件夹中的一个。

### 执行测试

在 Ansible 接受任何提交之前，更改必须通过测试。这些测试分为三类：单元测试、集成测试和代码风格测试。单元测试涵盖源代码功能的非常狭窄的方面，而集成测试则采用更全面的方法，确保所需的功能发生。代码风格测试检查使用的语法，以及空格和其他风格方面。

在执行任何测试之前，必须准备好与 Ansible 代码检出一起工作的 shell 环境。存在一个 shell 环境文件来设置所需的变量，可以使用以下命令激活：

```
    $ source ./hacking/env-setup
```

确保在进行修改之前通过测试可以节省大量的调试时间，因为`devel`分支是最前沿的，有可能已提交到该分支的代码未能通过所有测试。

#### 单元测试

所有单元测试都位于从`test/units`开始的目录树中。这些测试应该都是自包含的，不需要访问外部资源。运行测试就像从 Ansible 源代码检出的根目录执行`make tests`一样简单。这将测试大部分代码库，包括模块代码。

重要提示

执行测试可能需要安装其他软件。在使用 Python 虚拟环境管理 Python 软件安装时，最好创建一个新的`venv`用于测试 Ansible-一个没有安装 Ansible 的`venv`。

要运行特定的一组测试，可以直接调用`pytest`（有时作为`py.test`访问），并提供要测试的目录或特定文件的路径。在 Ubuntu Server 20.04 上，您可以使用以下命令安装此工具：

```
sudo apt install python3-pytest
```

假设您已经检出了`ansible-core`存储库代码，您可以使用以下命令仅运行`parsing`单元测试。请注意，其中一些测试需要您安装额外的 Python 模块，并且 Ansible 现在默认在 Python 3 下运行，因此您应始终确保安装和使用基于 Python 3 的模块和工具。以下命令可能不足以运行所有测试，但足以运行解析测试，并让您了解为准备运行包含的测试套件需要做的事情的类型：

```
sudo apt install python3-pytest python3-tz python3-pytest-mock
cd ansible
source ./hacking/env-setup
pytest-3 test/units/parsing
```

如果一切顺利，输出应如下所示，并显示任何警告和/或错误，以及最后的摘要：

![图 10.16 - 使用 Python 3 的 pytest 工具运行 ansible-core 源代码中包含的解析单元测试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_16.jpg)

图 10.16 - 使用 Python 3 的 pytest 工具运行 ansible-core 源代码中包含的解析单元测试

正如您所看到的，`pytest-3`实用程序正在运行定义的单元测试，并将报告它发现的任何错误，这将极大地帮助您检查您可能计划提交的任何代码。在前面的截图中一切似乎都很顺利！

#### 集成测试

Ansible 集成测试是旨在验证 playbook 功能的测试。测试也是由 playbooks 执行的，这使得事情有点递归。测试被分为几个主要类别：

+   非破坏性

+   破坏性

+   遗留云

+   Windows

+   网络

这些测试类别的更详细解释可以在这里找到：[`docs.ansible.com/ansible/latest/dev_guide/testing_integration.html`](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html)。

重要提示

许多集成测试需要`ssh`到 localhost 是可用的。请确保`ssh`正常工作，最好不需要密码提示。远程主机可以通过更改特定集成测试所需的清单文件来使用。例如，如果要运行`connection_ssh`集成测试，请确保查看`test/integration/targets/connection_ssh/test_connection.inventory`并根据需要进行更新。您可以自行探索此目录树，并找到可能需要更新的适当清单文件。

与单元测试一样，可以使用位于`bin/ansible-test`的`ansible-test`实用程序来执行单个集成测试。许多集成测试需要外部资源，例如计算机云帐户，再次，您需要探索文档和目录树，以确定您需要配置什么来在您的环境中运行这些测试。`test/integration/targets`中的每个目录都是可以单独测试的目标。让我们选择一个简单的示例来测试`ping`目标的 ping 功能。可以使用以下命令完成：

```
source ./hacking/env-setup
ansible-test integration --python 3.8 ping
```

请注意，我们已经专门设置了要针对的 Python 环境。这很重要，因为我的 Ubuntu Server 20.04 测试机安装了一些 Python 2.7，并且已经安装和配置了使用 Python 3.8 的 Ansible（也已经存在）。如果`ansible-test`工具使用 Python 2.7 环境，它可能会发现缺少模块，测试将失败，但这并不是因为我们的代码有错 - 而是因为我们没有正确设置环境。

当您运行`ansible-test`时，请确保知道您正在使用的 Python 环境，并相应地在命令中设置它。如果要针对另一个 Python 版本进行测试，您需要确保 Ansible 依赖的所有先决 Python 模块（如 Jinja2）都安装在该 Python 环境下。

成功的测试运行应该如下所示：

![图 10.17 - 对 Python 3.8 环境运行 Ansible ping 集成测试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_17.jpg)

图 10.17 - 对 Python 3.8 环境运行 Ansible ping 集成测试

请注意，甚至在这个测试套件中设计了一个旨在失败的测试 - 最终，我们将看到`ok=7`和`failed=0`，意味着所有测试都通过了。可以通过以下命令执行一组大型的与 POSIX 兼容的非破坏性集成测试，这些测试由持续集成系统在对 Ansible 的建议更改上运行：

```
ansible-test integration shippable/ --docker fedora32
```

重要提示

为了确保一致和稳定的测试环境，这些测试在本地 Fedora 32 容器中运行。您需要确保 Docker 在您的测试主机上设置并可访问，以使此命令生效。

#### 代码风格测试

Ansible 测试的第三类是代码风格类别。这些测试检查 Python 文件中使用的语法，确保代码库中的外观统一。强制执行的代码风格由 PEP8 定义，这是 Python 的风格指南。更多信息请参见：[`docs.ansible.com/ansible/latest/dev_guide/testing/sanity/pep8.html`](https://docs.ansible.com/ansible/latest/dev_guide/testing/sanity/pep8.html)。这种风格是通过`pep8`健全性测试目标来强制执行的。要运行此测试，您必须为 Python 3 安装了`pycodestyle`模块。因此，您的命令可能如下所示：从您的 Ansible 源目录的根目录开始。

```
sudo apt install python3-pycodestyle
source ./hacking/env-setup
ansible-test sanity --test pep8
echo $?
```

如果没有错误，此目标不会输出任何文本；但是可以验证返回代码。退出代码为`0`表示没有错误，如下截图所示：

![图 10.18 - 成功运行的 pep8 Python 代码风格测试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_18.jpg)

图 10.18 - 成功运行的 pep8 Python 代码风格测试

重要提示

正如您已经看到的，运行任何 Ansible 测试可能需要额外的 Python 模块 - 安装它们的方法会因系统而异，所需的模块也会因测试而异。这些通常可以通过使用`pip3`工具或本地操作系统包来安装，就像我们在这里所做的那样。

如果 Python 文件确实存在`pep8`违规，输出将反映违规 - 例如，我们将故意编辑`ansible.builtin.file`模块的代码，该模块可以在源代码根目录下的`lib/ansible/modules/file.py`中找到。我们将故意引入一些错误，比如带有空格的空行，并将一些至关重要的缩进空格替换为制表符，然后像之前一样重新运行测试。我们不需要重新安装 Python 模块或重新设置环境；此测试的输出将准确显示错误的位置，如下截图所示：

![图 10.19 - 重新运行带有故意引入文件模块的编码风格错误的 pep8 健全性测试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_10_19.jpg)

图 10.19 - 重新运行带有故意引入文件模块的 pep8 健全性测试

`pep8`错误将指示一个错误代码，可以查找详细的解释和指导，以及位置和文件名，甚至行号和列号，以帮助您快速定位和纠正问题。

### 发起拉取请求

一旦所有测试都通过了，就可以提交。Ansible 项目使用 GitHub 拉取请求来管理提交。要创建拉取请求，您的更改必须提交并推送到 GitHub。开发者使用他们账户下的 Ansible 存储库的分支来推送建议的更改。

一旦推送，可以使用 GitHub 网站打开拉取请求。这将创建拉取请求，开始持续集成测试，并通知审阅者有一个新的提交。有关 GitHub 拉取请求的更多信息，请访问[`docs.github.com/en/github/collaborating-with-pull-requests`](https://docs.github.com/en/github/collaborating-with-pull-requests)。

一旦拉取请求打开，审阅者将对拉取请求进行评论，要么要求更多信息，要么建议更改，要么批准更改。对于新的模块提交，建议您使用集合路线，但如果您希望进一步探索，这里有大量有价值的信息可供开发者使用：[`docs.ansible.com/ansible/latest/dev_guide/index.html`](https://docs.ansible.com/ansible/latest/dev_guide/index.html)。

经过接受的提交将在下一个 Ansible 版本中普遍可用。这结束了我们对向 Ansible 项目贡献代码和对 Ansible 进行扩展的章节的讨论。希望本章能给您一些想法和灵感，让您能够在 Ansible 提供的优秀基础上解决自动化挑战。

# 摘要

Ansible 是一个很好的工具；然而，有时它并不能提供您所需的所有功能。并非所有功能都适合提交到`ansible-core`项目，也不可能为自定义专有数据源提供定制集成，因为每种情况都不同。因此，Ansible 内部有许多设施来扩展其功能。通过共享的模块基础代码，创建和使用自定义模块变得非常容易。可以创建许多不同类型的插件，并与 Ansible 一起使用，以各种方式影响操作。除了 Ansible 发布集合提供的清单源之外，仍然可以相对轻松和高效地使用其他清单源。

在本章中，您学习了开发模块并将其包含在 playbooks 中。然后，您了解了通过插件扩展 Ansible，并详细介绍了创建动态清单插件的具体细节。最后，您学会了如何向 Ansible 项目贡献代码，以增强整个社区的代码。总之，您学会了，在所有情况下，都有机制可以在 playbooks 和依赖于增强功能的角色旁边提供模块、插件和清单源，使其无缝分发。这使得几乎可以无限地扩展或定制 Ansible 以满足您的需求，并且如果需要，可以轻松地为更广泛的社区做出贡献。

在*第十二章*，*基础设施配置*中，我们将探讨使用 Ansible 创建要管理的基础设施。

# 问题

1.  对于 3.0 之后的 Ansible 版本，您几乎总是会开发一个新模块，并通过以下哪种方式分发？

a) `ansible-core`项目。

b) 您的集合。

c) 与项目维护者批准的现有集合功能重叠。

d) 一个角色。

e) 只有 b、c，也许 d

1.  开发自定义模块的最简单方法是用哪种语言编写？

a) Bash

b) Perl

c) Python

d) C++

1.  从自定义模块提供事实会做什么？

a) 节省您不需要注册输出到变量，然后使用`set_fact`。

b) 使您的代码具有更大的能力。

c) 帮助您调试您的代码。

d) 显示模块的运行方式。

1.  回调插件允许您做什么？

a) 帮助您调用其他 playbook。

b) 在关键操作点轻松改变 Ansible 的行为，而无需修改`ansible-core`代码。

c) 提供一种有效的方式来改变代码的状态。

d) 帮助您在运行时回调到您的 playbook。

1.  要分发插件，您应该把它们放在哪里？

a) 在与它们的功能相关的专门命名的目录中（例如，回调插件将放在`callback_plugins/`目录中）。

b) 在 Ansible 安装目录中。

c) 在`~/.ansible/plugins`下。

d) 无论在哪里，只要您在`ansible.cfg`中指定它们。

1.  动态清单插件应该用什么语言编写？

a) Python。

b) Bash。

c) C++。

d) 任何语言，只要输出以正确的 JSON 数据结构返回。

1.  动态清单插件应该解析哪两个命令行参数？

a) `--list` 和 `--hostname`

b) `--list` 和 `--host`

c) `--list-all` 和 `--hosts`

d) `--list` 和 `--server`

1.  动态清单性能可以通过做什么来提高？

a) 当传递`--list`参数时，在`_meta`键下返回所有特定于主机的数据。

b) 返回所有特定于主机的数据，无论传递了哪些参数。

c) 缓存脚本运行的输出。

d) 压缩输出数据以减少传输时间。

1.  如果您希望向`ansible-core`项目贡献代码，您应该通过以下哪种方法提交它？

a) 对项目提出的一张票，详细说明您的更改

b) 向 Red Hat 提交支持票

c) 一旦您的代码通过了所有包含的测试，就可以通过 GitHub 拉取请求提交。

d) 在 Twitter 上大声抱怨

1.  哪个实用程序用于启动和控制大部分 Ansible 代码测试？

a) `test-runner`

b) `integration-test`

c) Jenkins

d) `ansible-test`


# 第三部分：使用 Ansible 进行编排

在本节中，我们将了解 Ansible 在现实世界中协调和管理系统和服务的用途，无论是在本地还是在云中。

本节包括以下章节：

+   第十一章 通过滚动部署最小化停机时间

+   第十二章 基础设施供应

+   第十三章 网络自动化


# 第十一章：通过滚动部署最小化停机时间

Ansible 非常适合在实时服务环境中升级或部署应用程序的任务。当然，可以采用多种不同的策略来处理应用程序的部署和升级。最佳方法取决于应用程序本身、应用程序运行的基础设施的能力以及与应用程序用户承诺的服务级别协议（SLA）。无论采用何种方法，都必须控制、可预测和可重复地进行应用程序部署或升级，以确保用户在自动部署后体验到稳定的服务。任何人都不希望由其自动化工具的意外行为导致中断；自动化工具应该是可信赖的，而不是额外的风险因素。

尽管有很多选择，但有些部署策略比其他策略更常见，在本章中，我们将介绍一些更常见的部署策略。在这样做的过程中，我们将展示在这些策略中有用的 Ansible 功能。我们还将讨论一些在两种部署策略中都常见的其他部署考虑因素。为了实现这一点，我们将在滚动 Ansible 部署的背景下深入讨论以下主题的细节：

+   原地升级

+   扩展和收缩

+   快速失败

+   最小化中断

+   串行单个任务

# 技术要求

要按照本章中提供的示例，您需要一台运行**Ansible 4.3**或更新版本的 Linux 机器。几乎任何 Linux 版本都可以使用——对于感兴趣的人，本章中提供的所有代码都是在**Ubuntu Server 20.04 长期支持版（LTS）**上测试的，除非另有说明，并且在 Ansible 4.3 上进行了测试。本章附带的示例代码可以从 GitHub 上下载：[`github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter11`](https://github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter11)。

查看以下视频，以查看代码的运行情况：[`bit.ly/3lZ6Y9W`](https://bit.ly/3lZ6Y9W)

# 原地升级

我们将要介绍的第一种部署类型是原地升级。这种部署方式在已经存在的基础设施上进行，以升级现有的应用程序。这种模式是一种传统模式，当创建新基础设施是一项耗时和昂贵的工作时使用。

在这种类型的升级过程中，最小化停机时间的一般设计模式是将应用程序部署在多个主机上，负载平衡器后面。负载平衡器将充当应用程序用户和运行应用程序的服务器之间的网关。应用程序的请求将发送到负载平衡器，根据配置，负载平衡器将决定将请求发送到哪个后端服务器。

要执行使用此模式部署的应用程序的滚动原地升级，将禁用每个服务器（或一小部分服务器）在负载平衡器上，进行升级，然后重新启用以接受新请求。这个过程将重复进行，直到池中的其余服务器都升级完毕。由于只有部分可用的应用程序服务器被下线进行升级，整个应用程序仍然可用于请求。当然，这假设应用程序可以在同时运行的不同版本下表现良好。

让我们创建一个用于升级虚构应用程序的 playbook。我们的虚构应用程序将在`foo-app01`到`foo-app08`服务器上运行，这些服务器存在于`foo-app`组中。这些服务器将有一个简单的网站，通过`nginx` Web 服务器提供，内容来自`foo-app` Git 存储库，由`foo-app.repo`变量定义。一个运行`haproxy`软件的负载均衡器服务器`foo-lb`将为这些应用服务器提供前端服务。

为了在我们的`foo-app`服务器子集上操作，我们需要使用`serial`模式。这种模式改变了 Ansible 执行 play 的方式。默认情况下，Ansible 将按照任务列出的顺序在每个主机上执行 play 的任务。Ansible 在继续执行 play 中的下一个任务之前，会在每个主机上执行 play 的每个任务。如果我们使用默认方法，我们的第一个任务将从负载均衡器中移除每个服务器，这将导致我们的应用程序完全中断。相反，`serial`模式让我们可以在子集上操作，以便整个应用程序保持可用，即使一些成员处于离线状态。在我们的示例中，我们将使用`2`的串行计数，以保持大多数应用程序成员在线：

```
--- 
- name: Upgrade foo-app in place 
  hosts: foo-app 
  serial: 2 
```

重要提示

Ansible 2.2 引入了`serial`批处理的概念：一个可以增加每次通过 play 串行处理的主机数量的数字列表。这允许在信心增加时增加处理的主机数量。如果`serial`关键字提供了一组数字，那么提供的最后一个数字将是任何剩余批次的大小，直到清单中的所有主机都已完成。

现在，我们可以开始创建我们的任务。第一个任务将是从负载均衡器中禁用主机。负载均衡器运行在`foo-lb`主机上；但是，我们正在操作`foo-app`主机。因此，我们需要使用`delegate_to`任务运算符委派任务。该运算符重定向 Ansible 将连接到以执行任务的位置，但它保留了原始主机的所有变量上下文。我们将使用`community.general.haproxy`模块来禁用当前主机的`foo-app`后端池。代码如下所示：

```
  tasks: 
  - name: disable member in balancer 
    community.general.haproxy: 
      backend: foo-app 
      host: "{{ inventory_hostname }}" 
      state: disabled 
    delegate_to: foo-lb 
```

在主机禁用的情况下，我们现在可以更新`foo-app`内容。我们将使用`ansible.builtin.git`模块将所需版本定义为`foo-version`的内容路径进行更新。我们将为此任务添加一个`notify`处理程序，以便在内容更新导致更改时重新加载`nginx`服务器。这种重启可以每次都进行，但我们也将其用作`notify`的示例用法。您可以在下面的代码片段中查看代码：

```
  - name: pull stable foo-app 
    ansible.builtin.git: 
      repo: "{{ foo-app.repo }}" 
      dest: /srv/foo-app/ 
      version: "{{ foo-version }}" 
    notify: 
      - reload nginx 
```

我们的下一步将是重新启用负载均衡器中的主机；但是，如果我们下一步执行该任务，我们会将旧版本放回原位，因为我们的通知处理程序尚未运行。因此，我们需要通过`meta: flush_handlers`调用提前触发我们的处理程序，你在*第十章*中学到了这一点，*扩展 Ansible*。你可以在这里再次看到这一点：

```
  - meta: flush_handlers 
```

现在，我们可以重新启用负载均衡器中的主机。我们可以立即启用它，并依赖负载均衡器等待主机健康后再发送请求。但是，由于我们正在使用较少数量的可用主机，我们需要确保所有剩余的主机都是健康的。我们可以利用`ansible.builtin.wait_for`任务来等待`nginx`服务再次提供连接。`ansible.builtin.wait_for`模块将等待端口或文件路径上的条件。在下面的示例中，我们将等待端口`80`，并且端口应该在其中的条件。如果它已启动（默认情况下），这意味着它正在接受连接：

```
  - name: ensure healthy service 
    ansible.builtin.wait_for: 
      port: 80 
```

最后，我们可以重新启用`haproxy`中的成员。再次，我们将将任务委派给`foo-lb`，如下面的代码片段所示：

```
  - name: enable member in balancer 
    community.general.haproxy: 
      backend: foo-app 
      host: "{{ inventory_hostname }}" 
      state: enabled 
    delegate_to: foo-lb 
```

当然，我们仍然需要定义我们的`reload nginx`处理程序。我们可以通过运行以下代码来实现这一点：

```
  handlers: 
  - name: reload nginx 
    ansible.builtin.service: 
      name: nginx 
      state: restarted 
```

当运行此剧本时，现在将执行我们应用程序的滚动就地升级。当然，并不总是希望进行就地升级 - 总是有可能会影响服务，特别是如果服务遇到意外负载。在下一节中，将探讨一种可以防止这种情况发生的替代策略，即扩张和收缩。

# 扩张和收缩

扩张和收缩策略是对就地升级策略的一种替代方案。由于自助服务性质的按需基础设施（如云计算或虚拟化池）的流行，这种策略近来变得流行起来。可以从大量可用资源池中按需创建新服务器的能力意味着每次应用程序的部署都可以在全新的系统上进行。这种策略避免了一系列问题，例如长时间运行系统上的积累问题，例如以下问题：

+   不再由 Ansible 管理的配置文件被遗留下来

+   后台运行的进程消耗资源

+   对服务器进行人工手动更改而不更新 Ansible 剧本

每次重新开始也消除了初始部署和升级之间的差异。可以使用相同的代码路径，减少升级应用程序时出现意外的风险。这种类型的安装也可以使回滚变得非常容易，如果新版本的表现不如预期。除此之外，随着新系统被创建来替换旧系统，在升级过程中应用程序不需要降级。

让我们重新使用扩张和收缩策略来重新处理我们之前的升级剧本。我们的模式将是创建新服务器，部署我们的应用程序，验证我们的应用程序，将新服务器添加到负载均衡器，并从负载均衡器中删除旧服务器。让我们从创建新服务器开始。在这个例子中，我们将利用 OpenStack 计算云来启动新实例：

```
--- 
- name: Create new foo servers 
  hosts: localhost 

  tasks: 
  - name: launch instances
    openstack.cloud.os_server:
      name: foo-appv{{ version }}-{{ item }}
      image: foo-appv{{ version }}
      flavor: 4
      key_name: ansible-prod
      security_groups: foo-app
      auto_floating_ip: false
      state: present
      auth:
        auth_url: https://me.openstack.blueboxgrid.com:5001/v2.0
        username: jlk
        password: FAKEPASSW0RD
        project_name: mastery
    register: launch
    loop: "{{ range(1, 8 + 1, 1)|list }}"
```

在这个任务中，我们正在循环遍历`8`的计数，使用在 Ansible 2.5 中引入的新的`loop`和`range`语法。对于循环的每次迭代，`item`变量将被一个数字替换。这使我们能够创建基于应用程序版本和循环次数的八个新服务器实例。我们还假设有一个预构建的镜像，这样我们就不需要对实例进行任何进一步的配置。为了在将来的剧本中使用这些服务器，我们需要将它们的详细信息添加到清单中。为了实现这一点，我们将运行结果注册到`launch`变量中，然后使用它来创建运行时清单条目。代码如下所示：

```
  - name: add hosts 
    ansible.builtin.add_host: 
      name: "{{ item.openstack.name }}" 
      ansible_ssh_host: "{{ item.openstack.private_v4 }}" 
      groups: new-foo-app 
    loop: launch.results 
```

此任务将创建具有与我们服务器实例相同名称的新清单项目。为了帮助 Ansible 知道如何连接，我们将`ansible_ssh_host`设置为云提供商分配给实例的**IP**地址（假设该地址可以被运行 Ansible 的主机访问）。最后，我们将主机添加到`new-foo-app`组中。由于我们的`launch`变量来自一个带有循环的任务，我们需要通过访问`results`键来迭代该循环的结果。这使我们能够循环遍历每个`launch`操作以访问特定于该任务的数据。

接下来，我们将在服务器上操作，以确保新服务已经准备好供使用。我们将再次使用`ansible.builtin.wait_for`，就像之前一样，作为在`new-foo-app`组上操作的新任务的一部分。代码如下所示：

```
- name: Ensure new app 
  hosts: new-foo-app 
  tasks: 
    - name: ensure healthy service 
      ansible.builtin.wait_for: 
        port: 80 
```

一旦它们都准备就绪，我们可以重新配置负载均衡器以利用我们的新服务器。为了简单起见，我们将假设`haproxy`配置的模板期望`new-foo-app`组中的主机，并且最终的结果将是一个了解我们的新主机并忘记我们的旧主机的配置。这意味着我们可以在负载均衡器系统本身上简单地调用`ansible.builtin.template`任务，而不是尝试操纵负载均衡器的运行状态。代码如下所示：

```
- name: Configure load balancer 
  hosts: foo-lb 
  tasks:
  - name: haproxy config
    ansible.builtin.template:
      dest: /etc/haproxy/haproxy.cfg
      src: templates/etc/haproxy/haproxy.cfg
  - name: reload haproxy
    ansible.builtin.service:
      name: haproxy
      state: reloaded
```

一旦新的配置文件就位，我们可以重新加载`haproxy`服务。这将解析新的配置文件并为新的传入连接启动一个新的监听进程。现有的连接最终会关闭，旧进程将终止。所有新的连接将被路由到运行我们新应用程序版本的新服务器。

这个 playbook 可以扩展到退役旧版本的服务器，或者当决定不再需要回滚到旧版本时，该操作可能会在不同的时间发生。

扩展和收缩策略可能涉及更多的任务，甚至为创建一个黄金镜像集而单独创建 playbooks，但是每次发布都为新基础架构带来的好处远远超过了额外的任务或创建后删除的复杂性。

# 快速失败

在升级应用程序时，可能希望在出现错误的迹象时完全停止部署。具有混合版本的部分升级系统可能根本无法工作，因此在留下失败的系统的同时继续部分基础架构可能会导致重大问题。幸运的是，Ansible 提供了一种机制来决定何时达到致命错误的情况。

默认情况下，当 Ansible 通过 playbook 运行并遇到错误时，它将从 play 主机列表中删除失败的主机，并继续执行任务或 play。当所有 play 的请求主机都失败或所有 play 都已完成时，Ansible 将停止执行。要更改此行为，可以使用一些 play 控件。这些控件是`any_errors_fatal`，`max_fail_percentage`和`force_handlers`，下面将讨论这些控件。

## any_errors_fatal 选项

此设置指示 Ansible 将整个操作视为致命错误，并在任何主机遇到错误时立即停止执行。为了演示这一点，我们将编辑我们的`mastery-hosts`清单，定义一个可以扩展到 10 个新主机的模式，如下面的代码片段所示：

```
[failtest] 
failer[01:10] 
```

然后，我们将在这个组上创建一个 play，将`any_errors_fatal`设置为`true`。我们还将关闭事实收集，因为这些主机不存在。代码如下所示：

```
--- 
- name: any errors fatal 
  hosts: failtest 
  gather_facts: false 
  any_errors_fatal: true 
```

我们希望有一个任务会对其中一个主机失败，但不会对其他主机失败。然后，我们还希望有第二个任务，仅仅是为了演示它不会运行。这是我们需要执行的代码：

```
  tasks: 
  - name: fail last host
    ansible.builtin.fail:
      msg: "I am last"
    when: inventory_hostname == play_hosts[-1]
  - name: never run
    ansible.builtin.debug:
      msg: "I should never be run"
    when: inventory_hostname == play_hosts[-1]
```

然后，我们将使用以下命令执行 playbook：

```
ansible-playbook -i mastery-hosts failtest.yaml
```

当我们这样做时，我们会看到一个主机失败，但整个 play 将在第一个任务后停止，并且`ansible.builtin.debug`任务从未尝试，如下面的屏幕截图所示：

![图 11.1 - 当清单中的一个主机失败时提前失败整个 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_11_01.jpg)

图 11.1 - 当清单中的一个主机失败时提前失败整个 playbook

我们可以看到只有一个主机失败；但是，Ansible 报告了`NO MORE HOSTS LEFT`（暗示所有主机都失败了），并在进入下一个 play 之前中止了 playbook。

## max_fail_percentage 选项

这个设置允许 play 开发人员定义可以失败的主机的百分比，然后整个操作就会中止。在每个任务结束时，Ansible 将进行计算，以确定 play 所针对的主机中达到失败状态的数量，如果该数量大于允许的数量，Ansible 将中止 playbook。这类似于`any_errors_fatal`；实际上，`any_errors_fatal`内部只是表示`max_fail_percentage`参数为`0`，其中任何失败都被视为致命。让我们编辑上一节的 play，并删除`any_errors_fatal`，将其替换为设置为`20`的`max_fail_percentage`参数，如下所示：

```
--- 
- name: any errors fatal 
  hosts: failtest 
  gather_facts: false 
  max_fail_percentage: 20 
```

通过进行这种更改并使用与之前相同的命令运行我们的 playbook，我们的 play 应该能够完成两个任务而不会中止，如下面的截图所示：

![图 11.2 - 演示我们之前的失败测试 playbook 在失败主机少于 20％的情况下继续进行](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_11_02.jpg)

图 11.2 - 演示我们之前的失败测试 playbook 在失败主机少于 20％的情况下继续进行

现在，如果我们更改我们第一个任务的条件，以便故意在超过`20`％的主机上失败，我们将看到 playbook 提前中止：

```
  - name: fail last host
    ansible.builtin.fail:
      msg: "I am last"
    when: inventory_hostname in play_hosts[0:3]
```

我们故意设置三个主机失败，这将使我们的失败率超过`20`％。 `max_fail_percentage`设置是允许的最大值，因此我们的设置为`20`将允许十个主机中的两个失败。由于有三个主机失败，我们将在第二个任务被允许执行之前看到致命错误，如下面的截图所示：

![图 11.3 - 当百分比超过限制时，演示 max_fail_percentage 操作导致 play 失败](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_11_03.jpg)

图 11.3 - 当百分比超过限制时，演示 max_fail_percentage 操作导致 play 失败

通过这些参数的组合，我们可以轻松设置和控制一组主机上的**快速失败**条件，这在 Ansible 部署期间维护环境的完整性方面非常有价值。

## 强制处理程序

通常，当 Ansible 失败时，它会停止在该主机上执行任何操作。这意味着任何未决的处理程序都不会运行。这可能是不希望的，有一个 play 控制可以强制 Ansible 处理失败的主机的未决处理程序。这个 play 控制是`force_handlers`，必须设置为`true`布尔值。

让我们稍微修改上一个示例，以演示这个功能。我们将删除我们的`max_fail_percentage`参数，并添加一个新的第一个任务。我们需要创建一个任务，它将返回成功的更改。这可以通过`ansible.builtin.debug`模块实现，使用`changed_when`任务控制，因为这个模块否则永远不会注册更改。我们将将我们的`ansible.builtin.fail`任务条件恢复到原始状态。代码如下所示：

```
--- 
- name: any errors fatal 
  hosts: failtest 
  gather_facts: false 
  tasks:
  - name: run first
    ansible.builtin.debug:
      msg: "I am a change"
    changed_when: true
    when: inventory_hostname == play_hosts[-1]
    notify: critical handler
  - name: change a host
    ansible.builtin.fail:
      msg: "I am last"
    when: inventory_hostname == play_hosts[-1] 
```

我们的第三个任务保持不变，但我们将定义我们的关键处理程序，如下所示：

```
  - name: never run
    ansible.builtin.debug:
      msg: "I should never be run"
    when: inventory_hostname == play_hosts[-1]
  handlers:
    - name: critical handler
      ansible.builtin.debug:
        msg: "I really need to run"
```

让我们运行这个新的 play 来展示处理程序不被执行的默认行为。为了减少输出，我们将限制执行到其中一个主机，使用以下命令：

```
ansible-playbook -i mastery-hosts failtest.yaml --limit failer01:failer01
```

请注意，尽管处理程序在 play 输出中被引用，但实际上并没有运行，这可以从缺少任何调试消息来证明，如下面的截图清楚地显示：

![图 11.4 - 即使在 play 失败时也不运行处理程序的演示](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_11_04.jpg)

图 11.4 - 演示即使在 play 失败时也不运行处理程序的情况

现在，我们添加`force_handlers` play 控制并将其设置为`true`，如下所示：

```
---
- name: any errors fatal
  hosts: failtest
  gather_facts: false
  force_handlers: true
```

这次，当我们运行 playbook（使用与之前相同的命令）时，我们应该看到即使对于失败的主机，处理程序也会运行，如下面的截图所示：

![图 11.5-演示处理程序可以被强制运行，即使在失败的 play 中也是如此](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_11_05.jpg)

图 11.5-演示处理程序可以被强制运行，即使在失败的 play 中也是如此

重要提示

强制处理程序也可以是一个运行时决定，可以在`ansible-playbook`上使用`--force-handlers`命令行参数。它也可以作为`ansible.cfg`中的参数进行全局设置。

强制处理程序运行对于重复的 playbook 运行非常有用。第一次运行可能会导致一些更改，但如果在刷新处理程序之前遇到致命错误，那些处理程序调用将丢失。重复运行不会导致相同的更改，因此处理程序将永远不会在没有手动交互的情况下运行。强制处理程序可以确保这些处理程序调用不会丢失，因此无论任务结果如何，处理程序始终会运行。当然，任何升级策略的整体目标是尽可能降低对任何给定服务的影响-您能想象您最喜欢的零售网站因为有人升级软件而宕机吗？在当今这个时代是不可想象的！在下一节中，我们将探讨使用 Ansible 来最小化潜在的破坏性行为的方法。

# 最小化中断

在部署过程中，通常有一些可以被视为具有破坏性或破坏性的任务。这些任务可能包括重新启动服务，执行数据库迁移等。破坏性任务应该被集中在一起，以最小化对应用程序的整体影响，而破坏性任务应该只执行一次。接下来的两个小节将探讨如何使用 Ansible 来实现这两个目标。

## 延迟中断

重新启动服务以适应新的配置或代码版本是一个非常常见的需求。当单独查看时，只要应用程序的代码和配置发生了变化，就可以重新启动单个服务，而不必担心整个分布式系统的健康状况。通常，分布式系统将为系统的每个部分分配角色，每个角色将在目标主机上独立运行。首次部署应用程序时，无需担心整个系统的运行时间，因此可以随意重新启动服务。然而，在升级过程中，可能希望延迟所有服务的重新启动，直到每个服务都准备就绪，以最小化中断。

强烈鼓励重用角色代码，而不是设计完全独立的升级代码路径。为了适应协调的重启，特定服务的角色代码需要在服务重新启动周围进行保护。一个常见的模式是在破坏性任务上放置一个条件语句，检查变量的值。在执行升级时，可以在运行时定义变量以触发这种替代行为。这个变量也可以在主 playbook 完成所有角色后触发协调的服务重启，以便对中断进行集群化处理并最小化总的中断时间。

让我们创建一个虚构的应用程序升级，其中涉及两个角色，模拟服务的重新启动。我们将这些角色称为`microA`和`microB`。代码如下所示：

```
roles/microA 
├── handlers 
│   └── main.yaml 
└── tasks 
    └── main.yaml 
roles/microB 
├── handlers 
│   └── main.yaml 
└── tasks 
    └── main.yaml 
```

对于这两个角色，我们将有一个简单的调试任务，模拟安装软件包。我们将通知一个处理程序来模拟服务的重新启动，并确保处理程序将触发，我们将强制任务始终注册为更改。以下代码片段显示了`roles/microA/tasks/main.yaml`的内容：

```
--- 
- name: install microA package 
  ansible.builtin.debug: 
    msg: "This is installing A" 
  changed_when: true 
  notify: restart microA 
```

`roles/microB/tasks/main.yaml`的内容如下所示：

```
---
- name: install microB package
  ansible.builtin.debug:
    msg: "This is installing B"
  changed_when: true
  notify: restart microB
```

这些角色的处理程序也将是调试操作，并且我们将附加一个条件语句到处理程序任务，只有当升级变量评估为`false`布尔值时才重新启动。我们还将使用默认过滤器为这个变量赋予默认值`false`。`roles/microA/handlers/main.yaml`的内容如下所示：

```
--- 
- name: restart microA 
  ansible.builtin.debug: 
    msg: "microA is restarting" 
  when: not upgrade | default(false) | bool 
```

`roles/microB/handlers/main.yaml`的内容如下所示：

```
---
- name: restart microB
  ansible.builtin.debug:
    msg: "microB is restarting"
  when: not upgrade | default(false) | bool
```

对于我们的顶层 playbook，我们将创建四个 play（记住 playbook 可以由一个或多个 play 组成）。前两个 play 将应用每个微服务角色，最后两个 play 将进行重新启动。只有在执行升级时，最后两个 play 才会被执行；因此，它们将使用`upgrade`变量作为条件。让我们看一下以下代码片段（名为`micro.yaml`）：

```
---
- name: apply microA
  hosts: localhost
  gather_facts: false
  roles:
  - role: microA
- name: apply microB
  hosts: localhost
  gather_facts: false
  roles:
  - role: microB
- name: restart microA
  hosts: localhost
  gather_facts: false
  tasks:
  - name: restart microA for upgrade
    ansible.builtin.debug:
      msg: "microA is restarting"
    when: upgrade | default(false) | bool
- name: restart microB
  hosts: localhost
  gather_facts: false
  tasks:
  - name: restart microB for upgrade
    ansible.builtin.debug:
      msg: "microB is restarting"
    when: upgrade | default(false) | bool
```

我们在不定义`upgrade`变量的情况下执行这个 playbook，使用以下命令：

```
ansible-playbook -i mastery-hosts micro.yaml
```

当我们这样做时，我们将看到每个角色的执行，以及其中的处理程序。最后两个 play 将有跳过的任务，如下截图所示：

![图 11.6 - 演示了安装微服务架构的基于角色的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_11_06.jpg)

图 11.6 - 演示了安装微服务架构的基于角色的 playbook

现在，让我们再次执行 playbook；这次，我们将在运行时将`upgrade`变量定义为`true`，使用`-e`标志如下：

```
ansible-playbook -i mastery-hosts micro.yaml -e upgrade=true
```

这次，结果应该是这样的：

![图 11.7 - 演示相同的 playbook，但在升级场景中所有重新启动都在最后批处理](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_11_07.jpg)

图 11.7 - 演示相同的 playbook，但在升级场景中所有重新启动都集中在最后

这次，我们可以看到我们的处理程序被跳过，但最后两个 play 有执行的任务。在一个真实的场景中，在`microA`和`microB`角色中发生了更多的事情（可能还有其他主机上的其他微服务角色），这种差异可能会达到几分钟甚至更长。将重新启动集中在最后可以显著减少中断时间。

## 仅运行破坏性任务一次

破坏性任务有很多种。它们可以是极其难以回滚的单向任务，无法轻易重新运行的一次性任务，或者如果并行执行会导致灾难性失败的竞争条件任务。因此，非常重要的是这些任务只能从单个主机执行一次。Ansible 通过`run_once`任务控制提供了一种实现这一点的机制。

`run_once`任务控制将确保任务只从单个主机执行一次，而不管 play 中有多少个主机。虽然还有其他方法可以实现这个目标，比如使用条件语句使任务只在 play 的第一个主机上执行，但`run_once`控制是表达这个愿望最简单直接的方式。此外，从`run_once`控制的任务注册的任何变量数据将对 play 的所有主机可用，而不仅仅是由 Ansible 选择执行操作的主机。这可以简化后续变量数据的检索。

让我们创建一个示例 playbook 来演示这个功能。我们将重用之前创建的`failtest`主机，以便有一个主机池，然后我们将通过主机模式选择其中的两个。我们将创建一个设置为`run_once`的`ansible.builtin.debug`任务并注册结果，然后我们将在不同的任务中使用不同的主机访问结果。代码如下：

```
--- 
- name: run once test 
  hosts: failtest[0:1] 
  gather_facts: false 

  tasks: 
  - name: do a thing
    ansible.builtin.debug:
      msg: "I am groot"
    register: groot
    run_once: true
  - name: what is groot
    ansible.builtin.debug:
      var: groot
    when: inventory_hostname == play_hosts[-1]
```

我们使用以下命令运行这个 play：

```
ansible-playbook -i mastery-hosts runonce.yaml
```

当我们这样做时，我们将特别关注每个任务操作中列出的主机名，如下截图所示：

![图 11.8 - 演示了 run_once 任务参数的使用，以及该任务在播放中其他主机上的变量数据的可用性](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_11_08.jpg)

图 11.8 - 演示了使用 run_once 任务参数以及在剧本中的其他主机上可用的变量数据的使用

我们可以看到`do a thing`任务在`failer01`主机上执行，而检查来自`do a thing`任务的数据的`what is groot`任务在`failer02`主机上操作。当然，通过使用我们在这里讨论的技术，您可以减少对生产服务的干扰风险，还有更多的事情可以做，比如限制任务运行的次数或运行的主机数量。我们将在本章的下一节中探讨这个话题。

# 序列化单个任务

运行多个服务副本的某些应用程序可能对所有这些服务同时重新启动作出不良反应。通常，在升级此类应用程序时，会使用`serial`剧本。但是，如果应用程序规模足够大，序列化整个剧本可能会非常低效。可以使用不同的方法，即仅对敏感任务（通常是重新启动服务的处理程序）进行序列化。

要对特定的处理程序任务进行序列化，我们可以使用内置变量`play_hosts`。该变量保存应作为剧本的一部分用于给定任务的主机列表。它会随着失败或不可达的主机而更新。使用此变量，我们可以构建一个循环，以便遍历每个可能运行处理程序任务的主机。我们将使用`when`条件和`delegate_to`指令中的`item`值，而不是在模块参数中使用`item`值。通过这种方式，剧本中通知的处理程序任务可以被委派到上述循环中的主机，而不是原始主机。但是，如果我们将其作为`loop`指令的列表使用，我们将会为触发处理程序的每个主机执行任务。这显然是不希望的，因此我们可以使用任务指令`run_once`来改变行为。`run_once`指令指示 Ansible 仅为一个主机执行任务，而不是通常会目标的每个主机。结合`run_once`和我们的`play_hosts`循环，就会创建一种情况，即 Ansible 只会通过循环运行一次。最后，我们希望在每个循环之间等待一小段时间，以便重新启动的服务在我们重新启动下一个服务之前可以正常运行。我们可以使用一个名为`pause`的`loop_control`参数（在 Ansible 版本 2.2 中引入）在循环的每次迭代之间插入暂停。

为了演示这种序列化的工作原理，我们将编写一个使用我们`failtest`组中的一些主机的剧本，其中包含一个创建更改并注册输出的任务，以便我们可以在我们通知的处理程序任务中检查此输出，称为`restart groot`。然后我们在剧本底部创建一个序列化的处理程序任务本身。代码如下所示：

```
--- 
- name: parallel and serial 
  hosts: failtest[0:3] 
  gather_facts: false 

  tasks: 
  - name: do a thing
    ansible.builtin.debug:
      msg: "I am groot"
    changed_when: inventory_hostname in play_hosts[0:2]
    register: groot
    notify: restart groot
  handlers:
  - name: restart groot
    debug:
      msg: "I am groot?"
    loop: "{{ play_hosts }}"
    delegate_to: "{{ item }}"
    run_once: true
    when: hostvars[item]['groot']['changed'] | bool
    loop_control:
      pause: 2
```

在执行此剧本时，我们可以看到处理程序通知（通过使用以下命令进行双重详细度）：

```
ansible-playbook -i mastery-hosts forserial.yaml -vv
```

在处理程序任务中，我们可以看到循环、条件和委托，如下面的屏幕截图所示：

![图 11.9 - 一个带有序列化处理程序路由的剧本，用于重新启动服务](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_11_09.jpg)

图 11.9 - 一个带有序列化处理程序路由的剧本，用于重新启动服务

如果您自己尝试了这段代码，您会注意到每个处理程序运行之间的延迟，就像我们在任务的`loop_control`部分中指定的那样。使用这些技术，您可以自信地推出更新和升级到您的环境，同时将干扰降到最低。希望本章为您提供了在您的环境中自信地执行此类操作的工具和技术。

# 总结

部署和升级策略是一种品味。每种策略都有明显的优势和劣势。Ansible 不会对哪种更好发表意见，因此它非常适合执行部署和升级，无论采用哪种策略。Ansible 提供了功能和设计模式，可以轻松地促进各种风格。了解每种策略的性质以及如何调整 Ansible 以适应该策略将使你能够决定并设计每个应用的部署。任务控制和内置变量提供了有效升级大规模应用程序的方法，同时小心处理特定任务。

在本章中，你学会了如何使用 Ansible 进行就地升级以及一些不同的方法论，包括扩展和收缩环境等技术。你了解了快速失败以确保 playbook 在 play 的早期出现问题时不会造成严重损害，以及如何最小化破坏性和破坏性行为。最后，你学会了对单个任务进行串行化，以最小化对正在运行的服务的干扰，通过以最小受控的方式将节点脱离服务来确保服务在维护工作（如升级）进行时仍然保持运行。这确保了服务在维护工作（如升级）进行时仍然保持运行。

在下一章中，我们将详细介绍如何使用 Ansible 与云基础设施提供商和容器系统合作，以创建一个用于管理的基础设施。

# 问题

1.  在进行就地升级时，最小化干扰的有效策略是什么？

a) 使用`serial`模式来改变 Ansible 一次执行升级的主机数量。

b) 使用`limit`参数来改变 Ansible 一次执行升级的主机数量。

c) 拥有许多小清单，每个清单中只有少量主机。

d) 撤销 Ansible 对主机的访问权限。

1.  扩展和收缩作为升级策略的一个关键好处是什么？

a) 减少云操作成本。

b) 它与**开发运维**（DevOps）文化相契合。

c) 每次应用部署或升级都会为所有主机新建，减少了过期库和配置的可能性。

d) 它为升级的方法提供了灵活性。

1.  为什么你想要快速失败？

a) 这样你就可以尽快了解你的 playbook 错误。

b) 这样你就可以最小化失败 play 造成的损害或中断。

c) 这样你就可以调试你的代码。

d) 这样你就可以在部署中灵活应对。

1.  你会使用哪个 Ansible play 选项来确保你的 play 在任何单个主机出现错误时提前停止执行？

a) `ansible.builtin.fail`

b) `any_errors_fatal`

c) `when: failed`

d) `max_fail_percentage: 50`

1.  你会使用哪个 Ansible play 选项来确保在清单中超过 30%的主机出现错误时，你的 play 会提前停止执行？

a) `any_errors_fatal`

b) `max_fail_percentage: 30%`

c) `max_fail_percentage: 30`

d) `max_fail: 30%`

1.  你可以指定哪个 play 级选项来确保即使 play 失败，也会运行 handlers？

a) `handlers_on_fail`

b) `handlers_on_failure`

c) `always_handlers`

d) `force_handlers`

1.  为什么你可能希望延迟运行 handlers 到 play 的最后？

a) 这可能会节省 play 执行的时间。

b) 它使操作更可预测。

c) 它减少了停机的风险。

d) 这可能有助于增加升级成功的机会。

1.  你可以使用哪个任务级参数来确保任务不会在清单中有多个主机时执行多次？

a) `task_once`

b) `run_once`

c) `limit: 1`

d) `run: once`

1.  哪个`loop_control`参数可以在 Ansible 的循环迭代之间插入延迟？

a) `pause`

b) `sleep`

c) `delay`

d) `wait_for`

1.  你可以使用哪个任务条件来确保只在清单中的前四个主机上运行任务？

a) `when: inventory_hostname in play_hosts[0:3]`

b) `when: inventory_hostname in play_hosts[1:4]`

c) `when: inventory_hostname[0:3]`

d) `when: play_hosts[0:3]`


# 第十二章：基础设施供应

数据中心中的几乎所有内容都变成了软件定义，从网络到我们的软件运行的服务器基础设施。**基础设施即服务**（**IaaS**）提供商提供 API，用于以编程方式管理镜像、服务器、网络和存储组件。通常期望这些资源是即时创建的，以降低成本并提高效率。

因此，多年来，Ansible 在云供应方面投入了大量的工作，官方发布的 Ansible 版本中支持了 30 多个基础设施提供商。这些范围从 OpenStack 和 oVirt 等开源解决方案到专有提供商如 VMware 和云提供商如 AWS、GCP 和 Azure。

本章涵盖的用例比我们能够覆盖的要多，但尽管如此，我们将探讨 Ansible 与各种这些服务进行交互的方式：

+   管理本地云基础设施

+   管理公共云基础设施

+   与 Docker 容器交互

+   使用 Ansible 构建容器

# 技术要求

要跟随本章中提供的示例，您需要一台运行**Ansible 4.3**或更新版本的 Linux 机器。几乎任何 Linux 版本都可以 - 对于那些对具体细节感兴趣的人，本章中提供的所有代码都是在 Ubuntu Server 20.04 LTS 上测试的，除非另有说明，并且在 Ansible 4.3 上测试。本章附带的示例代码可以从 GitHub 的以下网址下载：[`github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter12`](https://github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter12)。

观看以下视频以查看代码的实际操作：[`bit.ly/3BU6My2`](https://bit.ly/3BU6My2)

# 管理本地云基础设施

云是一个常见但模糊的术语，用于描述 IaaS。云可以提供许多类型的资源，尽管最常讨论的是计算和存储。Ansible 能够与许多云提供商进行交互，以便在其中发现、创建或管理资源。请注意，尽管本章将专注于计算和存储资源，但 Ansible 还有一个模块用于与许多其他云资源类型进行交互，例如负载均衡器，甚至云角色访问控制。

Ansible 可以与之交互的一个这样的云提供商是 OpenStack（一个开源的云操作系统），对于那些需要本地 IaaS 功能的人来说，这是一个可能的解决方案。一套服务提供了管理计算、存储和网络服务以及许多其他支持服务的接口。OpenStack 并不是一个单一的提供商；相反，许多公共和私有云提供商使用 OpenStack 构建其产品，因此尽管提供商本身可能是分散的，它们提供相同的 API 和软件接口，以便 Ansible 可以轻松地在这些环境中自动化任务。

Ansible 自项目早期就支持 OpenStack 服务，现在这种支持可以在`OpenStack.Cloud`集合中找到。最初的支持已经发展到包括 70 多个模块，支持管理以下内容：

+   计算

+   裸金属计算

+   计算镜像

+   认证账户

+   网络

+   对象存储

+   块存储

除了在前面的资源类型上执行**创建、读取、更新和删除**（CRUD）操作之外，Ansible 还包括使用 OpenStack（和其他云）作为清单来源的能力，我们之前在*第一章*中已经提到过这一点，*Ansible 的系统架构和设计*。再次强调，动态清单提供程序可能在`OpenStack.Cloud`集合中找到。每次使用 OpenStack 云作为清单来源的`ansible`或`ansible-playbook`执行都将获取关于现有计算资源的即时信息，以及有关这些计算资源的各种事实。由于云服务已经跟踪了这些细节，这可以通过消除资源的手动跟踪来减少开销。

为了展示 Ansible 管理和与云资源交互的能力，我们将演示两种情景：一个是创建并与新的计算资源交互的情景，另一个是演示使用 OpenStack 作为清单来源的情景。

## 创建服务器

OpenStack 计算服务提供了一个 API，用于创建、读取、更新和删除虚拟机服务器。通过这个 API，我们将能够为我们的演示创建服务器。在通过 SSH 访问和修改服务器之后，我们还将使用 API 来删除服务器。这种自助服务能力是云计算的一个关键特性。

Ansible 可以使用各种`openstack.cloud`模块来管理这些服务器：

+   `openstack.cloud.server`：此模块用于创建和删除虚拟服务器。

+   `openstack.cloud.server_info`：此模块用于收集有关服务器的信息-在 Ansible 2.9 及更早版本中，它将这些信息返回为事实，但现在不再是这样。

+   `openstack.cloud.server_action`：此模块用于对服务器执行各种操作。

+   `openstack.cloud.server_group`：此模块用于创建和删除服务器组。

+   `openstack.cloud.server_volume`：此模块用于将块存储卷附加到服务器或从服务器分离。

+   `openstack.cloud.server_metadata`：此模块用于创建、更新和删除虚拟服务器的元数据。

### 启动虚拟服务器

对于我们的演示，我们将使用`openstack.cloud.server`。我们需要提供关于我们的云的身份验证详细信息，如认证 URL 和登录凭据。除此之外，我们还需要为我们的 Ansible 主机设置正确的先决条件软件，以使此模块正常运行。正如我们在本书早期讨论动态清单时所讨论的，Ansible 有时需要主机上的额外软件或库才能正常运行。事实上，Ansible 开发人员的政策是不将云库与 Ansible 本身一起发布，因为它们会迅速过时，并且不同的操作系统需要不同的版本-即使是集合的出现也没有改变这一点。

您可以在每个模块的 Ansible 文档中找到软件依赖关系，因此在第一次使用模块时（特别是云提供商模块）值得检查这一点。本书中用于演示的 Ansible 主机基于 Ubuntu Server 20.04，为了使`openstack.cloud.server`模块正常运行，我首先必须运行以下命令：

```
sudo apt install python3-openstacksdk
```

确切的软件和版本将取决于我们的主机操作系统，并可能随着较新的 Ansible 版本而改变。您的操作系统可能有本机软件包可用，或者您可以使用`pip`安装这个 Python 模块。在继续之前，值得花几分钟时间检查您的操作系统的最佳方法。

一旦先决条件模块就位，我们就可以继续创建服务器。为此，我们将需要一个 flavor，一个 image，一个 network 和一个名称。您还需要一个密钥，在继续之前需要在 OpenStack GUI（或 CLI）中定义。当然，这些细节可能对每个 OpenStack 云都不同。在这个演示中，我正在使用基于**DevStack**的单个一体化虚拟机，并尽可能使用默认设置，以便更容易跟进。您可以在这里下载 DevStack 并了解快速入门：[`docs.openstack.org/devstack/latest/`](https://docs.openstack.org/devstack/latest/)。

我将命名我们的剧本为`boot-server.yaml`。我们的剧本以一个名称开始，并使用`localhost`作为主机模式，因为我们调用的模块直接从本地 Ansible 机器与 OpenStack API 交互。由于我们不依赖于任何本地事实，我也会关闭事实收集：

```
--- 
- name: boot server 
  hosts: localhost 
  gather_facts: false 
```

为了创建服务器，我将使用`openstack.cloud.server`模块，并提供与我可以访问的 OpenStack 云相关的`auth`详细信息，以及一个 flavor，image，network 和 name。请注意`key_name`，它指示了在编写此剧本之前您在 OpenStack 中为自己创建的密钥对的 SSH 公钥（如本章前面讨论的）。这个 SSH 公钥被集成到我们在 OpenStack 上首次引导时使用的`Fedora34`镜像中，以便我们随后可以通过 SSH 访问它。我还上传了一个`Fedora34`镜像，以便在本章中进行演示，因为它比 OpenStack 发行版中包含的默认 Cirros 镜像具有更大的操纵空间。这些镜像可以从[`alt.fedoraproject.org/cloud/`](https://alt.fedoraproject.org/cloud/)免费下载。最后，正如您所期望的，我已经对我的密码进行了混淆：

```
  tasks:
    - name: boot the server
      openstack.cloud.server:
        auth:
          auth_url: "http://10.0.50.32/identity/v3"
          username: "demo"
          password: "password"
          project_name: "demo"
          project_domain_name: "default"
          user_domain_name: "default"
        flavor: "ds1G"
        image: "Fedora34"
        key_name: "mastery-key"
        network: "private"
        name: "mastery1"
```

重要提示

认证详细信息可以写入一个外部文件，该文件将被底层模块代码读取。这个模块代码使用`openstacksdk`，这是一个用于管理 OpenStack 凭据的标准库。或者，它们可以存储在 Ansible 保险库中，正如我们在*第三章*中描述的那样，*用 Ansible 保护您的秘密*，然后作为变量传递给模块。

按原样运行这个剧本将只是创建服务器，没有别的。要测试这一点（假设您可以访问合适的 OpenStack 环境），请使用以下命令运行剧本：

```
export ANSIBLE_PYTHON_INTERPRETER=$(which python3)
ansible-playbook -i mastery-hosts boot-server.yaml -vv
```

确保使用正确的 Python 环境

请注意，在 Ubuntu Server 20.04 上，默认情况下，Ansible 在 Python 2.7 下运行 - 这不是问题，我们在本书中到目前为止已经忽略了这一点 - 但是，在这种特殊情况下，我们只在 Python 3 上安装了`openstacksdk`模块，因此我们必须告诉 Ansible 使用 Python 3 环境。我们通过设置一个环境变量来做到这一点，但您也可以通过`ansible.cfg`文件轻松地完成这一点 - 这留给您去探索。

成功运行剧本应该产生类似于*图 12.1*所示的输出：

![图 12.1 - 使用 Ansible 在 OpenStack 中创建虚拟实例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_01.jpg)

图 12.1 - 使用 Ansible 在 OpenStack 中创建虚拟实例

我已经截断了输出，因为模块返回了大量数据。最重要的是，我们获得了有关主机 IP 地址的数据。这个特定的云使用浮动 IP 来提供对服务器实例的公共访问，我们可以通过注册输出然后调试打印`openstack.accessIPv4`的值来看到这个值：

```
  tasks:
    - name: boot the server
      openstack.cloud.server:
        auth:
          auth_url: "http://10.0.50.32/identity/v3"
          username: "demo"
          password: "password"
          project_name: "demo"
          project_domain_name: "default"
          user_domain_name: "default"
        flavor: "ds1G"
        image: "Fedora34"
        key_name: "mastery-key"
        network: "private"
        name: "mastery1"
      register: newserver
    - name: show floating ip
      ansible.buitin.debug:
        var: newserver.openstack.accessIPv4
```

使用类似于前面的命令执行此剧本（但不要添加冗长）：

```
export ANSIBLE_PYTHON_INTERPRETER=$(which python3)
ansible-playbook -i mastery-hosts boot-server.yaml
```

这一次，第一个任务不会导致更改，因为我们想要的服务器已经存在 - 但是，它仍然会检索有关服务器的信息，使我们能够发现其 IP 地址：

![图 12.2 - 使用 Ansible 检索我们在上一个示例中启动的 OpenStack 虚拟机的 IP 地址](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_02.jpg)

图 12.2 - 使用 Ansible 检索我们在上一个示例中启动的 OpenStack 虚拟机的 IP 地址

输出显示 IP 地址为`172.24.4.81`。我可以使用这些信息连接到我新创建的云服务器。

### 添加到运行时清单

启动服务器本身并不是很有用。服务器存在是为了使用，并且可能需要一些配置才能变得有用。虽然可以有一个 playbook 来创建资源，另一个完全不同的 playbook 来管理配置，但我们也可以在同一个 playbook 中完成所有这些。Ansible 提供了一个功能，可以在 play 的一部分中将主机添加到清单中，这将允许在后续 play 中使用这些主机。

根据上一个示例，我们有足够的信息通过`ansible.builtin.add_host`模块将新主机添加到运行时清单：

```
    - name: add new server
      ansible.builtin.add_host:
        name: "mastery1"
        ansible_ssh_host: "{{ newserver.openstack.accessIPv4 }}"
        ansible_ssh_user: "fedora" 
```

我知道这个镜像有一个默认的用户`fedora`，所以我相应地设置了一个主机变量，并设置 IP 地址作为连接地址。

重要提示

这个例子也忽略了在 OpenStack 中所需的安全组配置，以及接受 SSH 主机密钥。可以添加其他任务来管理这些事情，或者您可以像我在我的环境中所做的那样预先配置它们。

将服务器添加到清单后，我们可以对其进行操作。假设我们想要使用这个云资源来转换图像文件，使用`ImageMagick`软件。为了实现这一点，我们需要一个新的 play 来利用新的主机。我知道这个特定的 Fedora 镜像不包含 Python，所以我们需要添加 Python 和`dnf`的 Python 绑定（这样我们就可以使用`ansible.builtin.dnf`模块）作为我们的第一个任务，使用`ansible.builtin.raw`模块：

```
- name: configure server 
  hosts: mastery1 
  gather_facts: false 

  tasks: 
    - name: install python 
      ansible.builtin.raw: "sudo dnf install -y python python-dnf" 
```

接下来，我们需要`ImageMagick`软件，我们可以使用`dnf`模块安装它：

```
    - name: install imagemagick 
      ansible.builtin.dnf: 
        name: "ImageMagick" 
      become: "yes" 
```

此时运行 playbook 将显示我们新主机的更改任务；请注意，这一次，我们必须给`ansible-playbook`提供来自 OpenStack 的私钥文件的位置，以便它可以使用以下命令对`Fedora`镜像进行身份验证：

```
export ANSIBLE_PYTHON_INTERPRETER=$(which python3)
ansible-playbook -i mastery-hosts boot-server.yaml --private-key=mastery-key
```

成功运行 playbook 应该产生像*图 12.3*中显示的输出：

![图 12.3 - 在我们的 OpenStack 虚拟机上执行实例化后配置使用 Ansible 的机器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_03.jpg)

图 12.3 - 在我们的 OpenStack 虚拟机上执行实例化后配置，使用 Ansible

我们可以看到 Ansible 在主机`mastery1`上报告了两个更改的任务，这是我们在第一个 play 中刚刚创建的。这个主机在`mastery-hosts`清单文件中不存在。

这里我们也关闭了冗长的报告，因为输出会很繁琐；但是，鉴于我们有 OpenStack 实例的私钥文件，我们可以手动登录并检查我们 playbook 的结果，例如，使用以下命令：

```
rpm -qa --last | head
```

这个命令查询 RPM 软件包数据库，并显示最近安装的软件包的简短列表。输出可能看起来像*图 12.4*中显示的那样，尽管日期肯定会有所不同：

![图 12.4 - 检查我们在 OpenStack VM 上的 playbook 成功](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_04.jpg)

图 12.4 - 检查我们在 OpenStack VM 上的 playbook 成功

从这里开始，我们可以扩展我们的第二个 play，通过使用`ansible.builtin.copy`上传源图像文件，然后通过在主机上使用`ImageMagick`执行命令来转换图像。可以添加另一个任务，通过使用`ansible.builtin.slurp`模块将转换后的文件下载回来，或者将修改后的文件上传到基于云的对象存储中。最后，可以添加最后一个 play 来删除服务器本身。

服务器的整个生命周期，从创建到配置再到使用，最后到移除，都可以通过一个单一的 playbook 来管理。通过读取运行时变量数据，playbook 可以变得动态，以定义应上传/修改哪个文件以及应存储在何处，从而将 playbook 转变为可重复使用的程序。虽然有些简单，但希望这能让您清楚地了解 Ansible 在与基础设施服务提供商合作时有多强大。

## 使用 OpenStack 清单源

我们之前的示例展示了一个一次性的短暂的云服务器。如果我们想要创建和使用长期的云服务器呢？每次想要操作它们时，都要手动记录创建它们并将它们添加到临时清单的任务似乎效率低下。在静态清单中手动记录服务器详细信息似乎也效率低下，而且容易出错。幸运的是，有一个更好的方法：使用云本身作为动态清单源。

Ansible 附带了许多云提供商的动态清单脚本，正如我们在[*第一章*]（B17462_01_Final_JC_ePub.xhtml#_idTextAnchor015）中讨论的那样，*Ansible 的系统架构和设计*。我们将在这里继续使用 OpenStack 的示例。回顾一下，`openstack.cloud`集合提供了我们需要的动态清单脚本。要使用此脚本，我们需要创建一个 YAML 文件，告诉 Ansible 使用此清单脚本 - 此文件必须命名为`openstack.yaml`或`openstack.yml`。它应该包含类似以下的代码：

```
# file must be named openstack.yaml or openstack.yml
plugin: openstack.cloud.openstack
expand_hostvars: yes
fail_on_errors: yes
all_projects: yes
```

配置文件需要更多考虑。该文件保存了连接到 OpenStack 云的身份验证详细信息。这使得该文件非常敏感，只应对需要访问这些信息的用户可见。此外，清单脚本将尝试从`os-client-config`（https://docs.openstack.org/os-client-config/latest/user/configuration.html#config-files）使用的标准路径加载配置，这是底层身份验证代码。这意味着此清单源的配置可以存在于以下位置：

+   `clouds.yaml`（在执行清单脚本时的当前工作目录）

+   `~/.config/openstack/clouds.yaml`

+   `/etc/openstack/clouds.yaml`

找到的第一个文件将被使用。您可以通过在我们之前在本节中创建的`openstack.yaml`中添加`clouds_yaml_path`来覆盖此设置。在我们的示例中，我将在 playbook 目录中与脚本本身一起使用`clouds.yaml`文件，以便将配置与任何其他路径隔离开来。

您的`clouds.yaml`文件将与我们在之前示例中使用的`openstack.cloud.server`模块的参数的`auth:`部分非常相似。但有一个关键的区别 - 在我们之前的示例中，我们使用了`demo`账户，并且限制了自己只能在 OpenStack 的`demo`项目中。为了查询所有项目中的所有实例（我们想要演示一些功能），我们需要一个具有管理员权限而不是`demo`账户的账户。在本章的这部分中，我的`clouds.yaml`文件包含以下内容：

```
clouds:
  mastery_cloud:
    auth:
      auth_url: "http://10.0.50.32/identity/v3"
      username: "admin"
      password: "password"
      project_name: "demo"
      project_domain_name: "default"
      user_domain_name: "default"
```

实际的动态清单脚本有一个内置的帮助功能，您也可以使用它来了解更多信息。如果您可以在系统上找到它，您可以运行以下命令 - 在我的系统上，我使用了这个命令：

```
python3 /usr/local/lib/python3.8/dist-packages/ansible_collections/openstack/cloud/scripts/inventory/openstack_inventory.py --help
```

在我们开始之前，还有一件事需要知道：如果您使用的是 Ansible 4.0 版本，它附带了`openstack.cloud`集合的`1.4.0`版本。其中存在一个错误，使得动态清单脚本无法运行。您可以使用以下命令查询您安装的集合版本：

```
ansible-galaxy collection list | grep openstack.cloud
```

如果您需要安装更新版本，可以使用以下命令进行安装：

```
ansible-galaxy collection install openstack.cloud
```

这将在您的主目录中的一个隐藏目录中安装集合，因此如果您使用本地副本，请不要使用此命令：

```
/usr/local/lib/python3.8/dist-packages/ansible_collections/openstack/cloud/scripts/inventory/openstack_inventory.py
```

请使用这个代替：

```
~/.ansible/collections/ansible_collections/openstack/cloud/scripts/inventory/openstack_inventory.py
```

脚本的`help`输出显示了一些可能的参数；然而，Ansible 将使用的是`--list`和`--host`，就像*图 12.5*所示：

![图 12.5 – 展示 openstack_inventory.py 脚本的帮助功能](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_05.jpg)

图 12.5 – 展示 openstack_inventory.py 脚本的帮助功能

第一个用于获取账户可见的所有服务器列表，第二个用于从每个服务器获取主机变量数据，不过这个清单脚本使用`--list`调用返回所有主机变量。使用主机列表返回数据是一种性能增强，正如我们在本书前面讨论的那样，消除了需要为每个主机调用 OpenStack API 的需求。

使用`--list`的输出相当长；以下是前几行：

![图 12.6 – 展示 openstack_inventory.py 动态清单返回的数据](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_06.jpg)

图 12.6 – 展示 openstack_inventory.py 动态清单返回的数据

配置的账户只有一个可见的服务器，其 UUID 为`875f88bc-ae18-42da-b988-0e4481e35f7e`，这是我们在之前的示例中启动的实例。我们在`flavor-ds1G`和`image-Fedora34`组中看到了这个实例的列表，例如。第一个组是所有使用`ds1G`口味运行的服务器，第二个组是所有使用我们的`Fedora34`镜像运行的服务器。这些分组在清单插件中自动发生，可能根据您使用的 OpenStack 设置而有所不同。输出的末尾将显示插件提供的其他组：

![图 12.7 – 展示 openstack_inventory.py 动态清单返回的更多数据](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_07.jpg)

图 12.7 – 展示 openstack_inventory.py 动态清单返回的更多数据

重要提示

请注意，要出现前述分组，`openstack.yaml`文件中必须设置`expand_hostvars: True`。

一些额外的组如下：

+   `mastery_cloud`：在我们的`clouds.yaml`文件中指定的`mastery_cloud`实例上运行的所有服务器

+   `flavor-ds1G`：使用`ds1G`口味的所有服务器

+   `image-Fedora 29`：使用`Fedora 29`镜像的所有服务器

+   `instance-875f88bc-ae18-42da-b988-0e4481e35f7e`：以实例本身命名的一个组

+   `nova`：在`nova`服务下运行的所有服务器

提供了许多组，每个组可能都有清单脚本找到的服务器的不同部分。这些组使得通过 play 轻松地定位到正确的实例。主机被定义为服务器的 UUID。由于这些本质上是唯一的，而且也相当长，它们在 play 中作为目标是笨拙的。这使得组变得更加重要。

为了演示使用此脚本作为清单来源，我们将重新创建前面的示例，跳过创建服务器的步骤，只需使用适当的组目标编写第二个 play。我们将命名这个 playbook 为`configure-server.yaml`：

```
--- 
- name: configure server 
  hosts: all 
  gather_facts: false 
  remote_user: fedora 

  tasks: 
    - name: install python 
      ansible.builtin.raw: "sudo dnf install -y python python-dnf" 

    - name: install imagemagick 
      ansible.builtin.dnf: 
        name: "ImageMagick" 
      become: "yes" 
```

此镜像的默认用户是`fedora`；然而，这些信息在 OpenStack API 中并不容易获得，因此在我们的清单脚本提供的数据中并没有反映出来。我们可以在 play 级别简单地定义要使用的用户。

这次，主机模式设置为`all`，因为我们的演示 OpenStack 服务器上目前只有一个主机；然而，在现实生活中，你不太可能在 Ansible 中如此公开地定位主机。

play 的其余部分保持不变，输出应该与以前的执行类似：

![图 12.8 – 通过动态清单插件重新配置我们的虚拟实例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_08.jpg)

图 12.8 – 通过动态清单插件重新配置我们的虚拟实例

这个输出与上次执行`boot-server.yaml` playbook 时有一些不同。首先，`mastery1`实例没有被创建或启动。我们假设我们想要交互的服务器已经被创建并正在运行。其次，我们直接从 OpenStack 服务器本身中提取了这个 playbook 运行的清单，使用了一个动态清单插件，而不是在 playbook 中使用`add_host`创建一个清单。除此之外，输出是一样的，除了两个弃用警告。关于组名的警告出现是因为动态清单脚本提供了自动创建的组名，需要进行清理 - 我想这将在插件的未来版本中得到修复。此外，Python 弃用警告在 Ansible 完全转向 Python 3 的过渡阶段是常见的，只要你的 Python 2 环境没有缺少任何模块，它是无害的。

随着时间的推移，每次运行清单插件时都会发现当前 playbook 执行时有哪些服务器被添加或移除。这可以节省大量时间，因为不需要试图维护静态清单文件中服务器的准确列表。

# 管理公共云基础设施

使用 Ansible 管理公共云基础设施并不比使用它管理 OpenStack 更困难，就像我们之前讨论的那样。一般来说，对于任何被 Ansible 支持的 IaaS 提供商，让它工作的过程是一个三步骤的过程。

1.  建立支持云提供商的 Ansible 集合、模块和动态清单插件。

1.  在 Ansible 主机上安装任何先决条件软件或库。

1.  定义 playbook 并对基础设施提供商运行它。

大多数提供商也有现成的动态清单插件可用，我们在本书中已经演示了其中两个：

+   `amazon.aws.aws_ec2`在*第一章*中讨论过，*Ansible 的系统架构和设计*。

+   `openstack.cloud.openstack`在本章前面已经演示过。

让我们来看看**亚马逊网络服务**（**AWS**），特别是 EC2 服务。我们可以使用我们选择的镜像启动一个新的服务器，使用与之前在 OpenStack 中完全相同的高级流程。然而，正如你现在肯定已经猜到的那样，我们必须使用一个提供特定 EC2 支持的 Ansible 模块。让我们构建 playbook。首先，我们的初始 play 将再次从本地主机运行，因为这将调用 EC2 来启动我们的新服务器：

```
---
- name: boot server
  hosts: localhost
  gather_facts: false
```

接下来，我们将使用`community.aws.ec2_instance`模块来代替`openstack.cloud.server`模块来启动我们想要的服务器。这段代码只是一个示例，用来展示如何使用模块；通常情况下，就像我们的`openstack.cloud.server`示例一样，你不会在 playbook 中包含密钥，而是会将它们存储在某个保险库中：

```
    - name: boot the server
      community.aws.ec2_instance:
        access_key: XXXXXXXXXXXXXXXXX
        secret_key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        key_name: mastery-demo
        security_group: default
        instance_type: t2.micro
        image_id: "ami-04d4a52790edc7894"
        region: eu-west-2
        tags: "{'ansible_group':'mastery_server', 'Name':'mastery1'}"
        wait: true
        user_data: |
          #!/bin/bash
          sudo dnf install -y python python-dnf
      register: newserver
```

重要提示

`community.aws.ec2_instance`模块需要在 Ansible 主机上安装 Python 的`boto3`库；这个方法在不同的操作系统上会有所不同，但在我们的 Ubuntu Server 20.04 演示主机上，它是使用`sudo apt install python3-boto3`命令安装的。另外，如果你在 Python 3 下安装这个模块，请确保你的 Ansible 安装使用 Python 3，设置`ANSIBLE_PYTHON_INTERPRETER`变量。

上述代码旨在执行与我们的`openstack.cloud.server`示例相同的工作，尽管在高层次上看起来相似，但有许多不同之处。因此，在使用新模块时，有必要阅读模块文档，以确切了解如何使用它。特别值得注意的是，`user_data`字段可用于将创建后的脚本发送到新的 VM；当需要立即进行初始配置时，这非常有用，适用于`ansible.builtin.raw`命令。在这种情况下，我们使用它来安装后续使用 Ansible 安装`ImageMagick`所需的 Python 3 先决条件。

接下来，我们可以通过使用在前面的任务中注册的`newserver`变量来获取我们新创建的服务器的公共 IP 地址。但是，请注意与使用`openstack.cloud.server`模块时访问此信息的方式相比，变量结构不同（再次，始终参考文档）：

```
    - name: show floating ip 
      ansible.builtin.debug: 
        var: newserver.instances[0].public_ip_address 
```

`community.aws.ec2_instance`模块和`openstack.cloud.server`模块之间的另一个关键区别是，`community.aws.ec2_instance`不一定会在 SSH 连接可用之前完成 - 这可以使用`wait`参数进行设置；因此，定义一个专门用于此目的的任务是一个良好的做法，以确保我们的 playbook 不会因为缺乏连接而在后来失败：

```
    - name: Wait for SSH to come up
      ansible.builtin.wait_for_connection:
        delay: 5
        timeout: 320 
```

完成此任务后，我们将知道我们的主机是活动的并且响应 SSH，因此我们可以继续使用`ansible.builtin.add_host`将这个新主机添加到清单中，然后像之前一样安装`ImageMagick`（这里使用的图像是在 OpenStack 示例中使用的相同的 Fedora 34 云图像）：

```
    - name: add new server 
      ansible.builtin.add_host: 
        name: "mastery1" 
        ansible_ssh_host: "{{ newserver.instances[0].public_ip_address }}" 
        ansible_ssh_user: "fedora"
- name: configure server
  hosts: mastery1
  gather_facts: false
  tasks:
    - name: install imagemagick
      ansible.builtin.dnf:
        name: "ImageMagick"
      become: "yes" 
```

将所有这些放在一起并运行 playbook 应该会产生类似以下截图的结果。请注意，我已经关闭了 SSH 主机密钥检查，以防止 SSH 传输代理在第一次运行时询问添加主机密钥，这将导致 playbook 挂起并等待用户干预，使用以下命令：

```
export ANSIBLE_PYTHON_INTERPRETER=$(which python3)
ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i mastery-hosts boot-ec2-server.yaml --private-key mastery-key.pem
```

您还会注意到，我已经将我在 AWS 帐户上生成的密钥对中保存的私人 SSH 密钥保存为`mastery-key.pem`，保存在与 playbook 相同的目录中 - 您需要将您自己的密钥保存在此位置，并相应地在命令行中引用它。成功运行应该看起来像*图 12.9*中显示的输出：

![图 12.9 - 使用 Ansible 引导和设置 Amazon EC2 实例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_09.jpg)

图 12.9 - 使用 Ansible 引导和设置 Amazon EC2 实例

正如我们在这里看到的，我们可以在不同的云提供商上使用略有不同的 playbook 来实现相同的结果。关键在于阅读每个模块附带的文档，并确保正确引用参数和返回值。

我们可以将这种方法应用到 Azure、Google Cloud 或 Ansible 支持的任何其他云提供商。如果我们想在 Azure 上重复这个例子，那么我们需要使用`azure.azcollection.azure_rm_virtualmachine`模块。该模块的文档说明我们需要 Python 2.7 或更新版本（这已经是我们 Ubuntu Server 20.04 演示机的一部分），以及一整套 Python 模块，这些模块的名称以及所需版本可以在一个名为`requirements-azure.txt`的文件中找到，该文件包含在集合中。期望您将使用`pip`安装这些要求，并且您可以通过在文件系统上找到上述文件，然后安装所需的模块来实现这一点。在我的演示系统上，我使用了以下命令来实现这一点：

```
locate requirements-azure.txt
sudo pip3 install -r /usr/local/lib/python3.8/dist-packages/ansible_collections/azure/azcollection/requirements-azure.txt
```

满足了这些先决条件，我们可以再次构建我们的 playbook。请注意，使用 Azure，可以使用多种身份验证方法。为了简单起见，我使用了为此演示创建的 Azure Active Directory 凭据；但是，为了启用此功能，我还必须安装官方的 Azure CLI 实用程序（按照此处提供的说明进行：[`docs.microsoft.com/en-gb/cli/azure/install-azure-cli-linux?pivots=apt`](https://docs.microsoft.com/en-gb/cli/azure/install-azure-cli-linux?pivots=apt)），并使用以下命令登录：

```
az login
```

这确保您的 Ansible 主机受到 Azure 的信任。在实践中，您可以设置一个**服务主体**，从而无需进行此操作，鼓励您自行探索这个选项。继续进行当前的简单示例，我们像以前一样设置 playbook 的头部：

```
---
- name: boot server
  hosts: localhost
  gather_facts: false
  vars:
    vm_password: Password123!
```

请注意，这一次，我们将为新 VM 存储一个密码变量；通常情况下，我们会将其存储在保险库中，但这又留给读者作为练习。从这里开始，我们使用`azure.azcollection.azure_rm_virtualmachine`模块来启动我们的新 VM。为了保持与之前示例的连贯性，我必须在 Azure 的图像市场上找到`Fedora 34`图像，这需要定义一些额外的参数，例如`plan`。为了使 Ansible 能够使用此图像，我首先必须找到它，然后接受作者的条款以启用其使用，使用以下命令使用`az`命令行实用程序：

```
az vm image list --offer fedora --all --output table
az vm image show --urn tunnelbiz:fedora:fedoraupdate:34.0.1
az vm image terms accept --urn tunnelbiz:fedora:fedoraupdate:34.0.1
```

我还必须创建 VM 将使用的资源组和网络；这些都是非常 Azure 特定的步骤，并且有很好的文档记录（如果您熟悉 Azure，则被认为是*基本操作*）。完成所有先决条件后，我就能够编写以下 playbook 代码来启动我们基于 Azure 的`Fedora 34`图像：

```
  tasks:
    - name: boot the server
      azure.azcollection.azure_rm_virtualmachine:
        ad_user: masteryadmin@example.com
        password: < insert your ad password here >
        subscription_id: xxxxxxxx-xxxxxx-xxxxxx-xxxxxxxx
        resource_group: mastery
        name: mastery1
        admin_username: fedora
        admin_password: "{{ vm_password }}"
        vm_size: Standard_B1s
        managed_disk_type: "Standard_LRS"
        image:
          offer: fedora
          publisher: tunnelbiz
          sku: fedoraupdate
          version: 34.0.1
        plan:
          name: fedoraupdate
          product: fedora
          publisher : tunnelbiz
      register: newserver
```

与之前的示例一样，我们获取图像的公共 IP 地址（注意访问此地址所需的复杂变量），确保 SSH 访问正常工作，然后使用`ansible.builtin.add_host`将新的 VM 添加到我们的运行时清单中：

```
    - name: show floating ip
      ansible.builtin.debug:
        var: newserver.ansible_facts.azure_vm.properties.networkProfile.networkInterfaces[0].properties.ipConfigurations[0].properties.publicIPAddress.properties.ipAddress
    - name: Wait for SSH to come up
      ansible.builtin.wait_for_connection:
        delay: 1
        timeout: 320
    - name: add new server
      ansible.builtin.add_host:
        name: "mastery1"
        ansible_ssh_host: "{{ newserver.ansible_facts.azure_vm.properties.networkProfile.networkInterfaces[0].properties.ipConfigurations[0].properties.publicIPAddress.properties.ipAddress }}"
        ansible_ssh_user: "fedora"
        ansible_ssh_pass: "{{ vm_password }}"
        ansible_become_pass: "{{ vm_password }}"
```

Azure 允许在 Linux VM 上使用基于密码或基于密钥的 SSH 身份验证；我们在这里使用基于密码的方式是为了简单起见。还要注意新使用的`ansible_become_pass`连接变量，因为我们使用的`Fedora 34`图像在使用`sudo`时会提示输入密码，可能会阻止执行。最后，完成这项工作后，我们像以前一样安装`ImageMagick`：

```
- name: configure server
  hosts: mastery1
  gather_facts: false
  tasks:
    - name: install python
      ansible.builtin.raw: "dnf install -y python python-dnf"
      become: "yes"
    - name: install imagemagick
      ansible.builtin.dnf:
        name: "ImageMagick"
      become: "yes"
```

代码完成后，使用以下命令运行它（根据需要设置您系统的 Python 环境）：

```
export ANSIBLE_PYTHON_INTERPRETER=$(which python3)
ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i mastery-hosts boot-azure-server.yaml
```

让我们看看它是如何运作的：

![图 12.10–使用 Ansible 创建和配置 Azure 虚拟机](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_10.jpg)

图 12.10–使用 Ansible 创建和配置 Azure 虚拟机

输出与我们的 AWS 示例非常相似，表明我们可以非常轻松地跨不同的云平台执行相同的操作，只需稍微学习每个云提供商所需模块的工作原理。本章的这一部分绝不是最终的，因为 Ansible 支持的平台和操作数量很多，但我们希望所提供的信息能够让您了解将 Ansible 与新的云平台集成所需的流程和步骤。接下来，我们将看看如何使用 Ansible 与 Docker 容器交互。

# 与 Docker 容器交互

Linux 容器技术，特别是 Docker，在近年来变得越来越受欢迎，自本书上一版出版以来这种趋势一直在持续。容器提供了一种快速的资源隔离路径，同时保持运行时环境的一致性。它们可以快速启动，并且运行效率高，因为几乎没有额外的开销。诸如 Docker 之类的实用工具为容器管理提供了许多有用的工具，例如用作文件系统的镜像注册表、构建镜像本身的工具、集群编排等。通过其易用性，Docker 已成为管理容器的最流行方式之一，尽管其他工具，如 Podman 和 LXC，也变得越来越普遍。不过，目前我们将专注于 Docker，因为它具有广泛的吸引力和广泛的安装基础。

Ansible 也可以以多种方式与 Docker 进行交互。特别是，Ansible 可以用于构建镜像，启动或停止容器，组合多个容器服务，连接到并与活动容器进行交互，甚至从容器中发现清单。Ansible 提供了一整套用于与 Docker 一起工作的工具，包括相关模块、连接插件和清单脚本。

为了演示如何使用 Docker，我们将探讨一些用例。第一个用例是构建一个新的镜像以供 Docker 使用。第二个用例是从新镜像启动一个容器并与其交互。最后一个用例是使用清单插件与活动容器进行交互。

重要提示

创建一个功能齐全的 Docker 安装非常依赖于您的基础操作系统。一个很好的资源是 Docker 网站，提供了详细的安装和使用说明，网址是[`docs.docker.com`](https://docs.docker.com)。Ansible 在 Linux 主机上与 Docker 配合效果最佳，因此我们将继续使用本书中一直使用的 Ubuntu Server 20.04 LTS 演示机。

## 构建镜像

Docker 镜像基本上是与运行时使用的参数捆绑在一起的文件系统。文件系统通常是 Linux Userland 的一小部分，包含足够的文件来启动所需的进程。Docker 提供了构建这些镜像的工具，通常基于非常小的、预先存在的基础镜像。该工具使用 Dockerfile 作为输入，Dockerfile 是一个带有指令的纯文本文件。该文件由 docker build 命令解析，我们可以通过 docker_image 模块解析它。其余的示例将来自使用 Docker CE 版本 20.10.8 的 Ubuntu Server 20.04 虚拟机，其中添加了 cowsay 和 nginx 包，以便运行容器将提供一个显示 cowsay 内容的 Web 服务器。

首先，我们需要一个 Dockerfile。如果您以前没有遇到过这个文件，它是用于构建 Docker 容器的一组指令-如果您愿意，您可以在这里了解更多信息：[`docs.docker.com/engine/reference/builder/`](https://docs.docker.com/engine/reference/builder/)。这个文件需要存在于 Ansible 可以读取的路径中，我们将把它放在与我的 playbooks 相同的目录中。Dockerfile 的内容将非常简单。我们需要定义一个基本镜像，一个运行安装必要软件的命令，一些最小的软件配置，一个要暴露的端口，以及一个使用此镜像运行容器的默认操作：

```
FROM docker.io/fedora:34 

RUN dnf install -y cowsay nginx 
RUN echo "daemon off;" >> /etc/nginx/nginx.conf 
RUN cowsay boop > /usr/share/nginx/html/index.html 

EXPOSE 80 

CMD /usr/sbin/nginx 
```

构建过程执行以下步骤：

1.  我们正在使用 Docker Hub 镜像注册表上的 fedora 存储库中的 Fedora 34 镜像。

1.  为了安装必要的 cowsay 和 nginx 包，我们使用 dnf。

1.  要直接在容器中运行 nginx，我们需要在 nginx.conf 中将 daemon 模式关闭。

1.  我们使用 cowsay 生成默认网页的内容。

1.  然后，我们指示 Docker 在容器中暴露端口 80，其中 nginx 将监听连接。

1.  最后，这个容器的默认操作将是运行 nginx。

构建和使用镜像的 playbook 可以放在同一个目录中。我们将其命名为`docker-interact.yaml`。该 playbook 将在`localhost`上运行，并有两个任务；一个是使用`community.docker.docker_image`构建镜像，另一个是使用`community.docker.docker_container`启动容器：

```
--- 
- name: build an image 
  hosts: localhost 
  gather_facts: false 

  tasks: 
    - name: build that image 
      community.docker.docker_image: 
        path: . 
        state: present 
        name: fedora-moo 

    - name: start the container 
      community.docker.docker_container: 
        name: playbook-container 
        image: fedora-moo 
        ports: 8080:80 
        state: started
        container_default_behavior: no_defaults
```

在运行我们的 playbook 之前，我们将检查可能与我们之前的 playbook 定义匹配的任何可能的容器镜像或正在运行的容器 - 这将帮助我们确信我们的代码正在产生期望的结果。如果您有从以前的测试中运行的任何其他容器，可以运行以下命令来检查与我们的规范匹配的`fedora`-based 容器：

```
docker ps -a --filter ancestor=fedora-moo
docker images --filter reference='fedora*'
```

除非您之前已运行过此代码，否则应该看到没有正在运行的容器，如*图 12.11*所示：

![图 12.11 - 在运行我们的 playbook 之前检查容器的缺席](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_11.jpg)

图 12.11 - 在运行我们的 playbook 之前检查容器的缺席

现在，让我们运行 playbook 来构建镜像并使用该镜像启动容器 - 请注意，与许多其他 Ansible 模块一样，您可能需要安装额外的 Python 模块才能使您的代码正常工作。在我的 Ubuntu Server 20.04 演示机器上，我不得不运行以下命令：

```
sudo apt install python3-docker
export ANSIBLE_PYTHON_INTERPRETER=$(which python3)
```

安装了 Python 支持后，您可以使用以下命令运行 playbook：

```
ansible-playbook -i mastery-hosts docker-interact.yaml
```

成功运行 playbook 应该类似于*图 12.12*：

![图 12.12 - 使用 Ansible 构建和运行我们的第一个 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_12.jpg)

图 12.12 - 使用 Ansible 构建和运行我们的第一个 Docker 容器

为了节省屏幕空间，此 playbook 执行的冗长度已经减少。我们的输出只是显示构建镜像的任务和启动容器的任务都产生了变化。快速检查运行的容器和可用的镜像应该反映我们的工作 - 您可以使用与 playbook 运行之前相同的`docker`命令来验证这一点：

![图 12.13 - 验证我们在 Docker 中运行的 Ansible playbook 的结果](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_13.jpg)

图 12.13 - 验证我们在 Docker 中运行的 Ansible playbook 的结果

我们可以使用`curl`来访问 Web 服务器来测试容器的功能，这应该会显示一头牛说`boop`，就像*图 12.14*中演示的那样：

![图 12.14 - 检索使用 Ansible 创建和运行的容器的结果](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_14.jpg)

图 12.14 - 检索使用 Ansible 创建和运行的容器的结果

通过这种方式，我们已经展示了使用 Ansible 与 Docker 进行交互有多么容易。但是，这个例子仍然是基于使用本地的`Dockerfile`，随着我们在本章中的进展，我们将看到一些更高级的 Ansible 用法，这些用法不需要`Dockerfile`。

## 构建不需要 Dockerfile 的容器

Dockerfile 很有用，但 Dockerfile 内部执行的许多操作都可以用 Ansible 来完成。Ansible 可以用于使用基础镜像启动容器，然后使用`docker`连接方法（而不是 SSH）与该容器进行交互以完成配置。让我们通过重复之前的示例来演示这一点，但不需要`Dockerfile`。相反，所有的工作都将由一个名为`docker-all.yaml`的全新 playbook 处理。该 playbook 的第一部分从 Docker Hub 的`Fedora 34`的预先存在的镜像中启动一个容器，并使用`ansible.builtin.add_host`将生成的容器详细信息添加到 Ansible 的内存库存中：

```
--- 
- name: build an image 
  hosts: localhost 
  gather_facts: false 
  tasks: 
    - name: start the container 
      community.docker.docker_container: 
        name: playbook-container 
        image: docker.io/fedora:34
        ports: 8080:80 
        state: started 
        command: sleep 500 
        container_default_behavior: no_defaults

    - name: make a host 
      ansible.builtin.add_host: 
        name: playbook-container 
        ansible_connection: docker 
        ansible_ssh_user: root
```

然后，使用这个新添加的库存主机，我们定义了第二个播放，该播放在刚刚启动的容器中运行 Ansible 任务，配置我们的`cowsay`服务，就像以前一样，但不需要`Dockerfile`：

```
- name: do things 
  hosts: playbook-container 
  gather_facts: false 

  tasks: 
    - name: install things 
      ansible.builtion.raw: dnf install -y python-dnf 

    - name: install things 
      ansible.builtin.dnf: 
        name: ['nginx', 'cowsay']

    - name: configure nginx 
      ansible.builtin.lineinfile: 
        line: "daemon off;" 
        dest: /etc/nginx/nginx.conf 
    - name: boop 
      ansible.builtin.shell: cowsay boop > /usr/share/nginx/html/index.html 

    - name: run nginx 
      ansible.builtin.shell: nginx & 
```

回顾一下，播放书包括两个播放。第一个播放从基本`Fedora 34`镜像创建容器。`community.docker.docker_container`任务被赋予一个`sleep`命令，以保持容器运行一段时间，因为`docker`连接插件只能与活动容器一起工作（从 Docker Hub 获取的未配置的操作系统镜像通常在运行时立即退出，因为它们没有默认操作要执行）。第一个播放的第二个任务创建了容器的运行时清单条目。清单主机名必须与容器名称匹配。连接方法也设置为`docker`。

第二个播放目标是新创建的主机，第一个任务使用`ansible.builtin.raw`模块来放置`python-dnf`包（这将带来其余的`Python`），以便我们可以在下一个任务中使用`ansible.builtin.dnf`模块。然后，使用`ansible.builtin.dnf`模块安装所需的软件包，即`nginx`和`cowsay`。然后，使用`ansible.builtin.lineinfile`模块向`nginx`配置添加新行。一个`ansible.builtin.shell`任务使用`cowsay`来为`nginx`创建内容。最后，`nginx`本身作为后台进程启动。

在运行播放书之前，让我们通过运行以下命令删除上一个示例中的任何运行的容器：

```
docker ps -a --filter ancestor=fedora-moo
docker rm -f playbook-container
docker ps -a --filter ancestor=fedora-moo
```

您可以将其与*图 12.15*中的屏幕截图进行验证：

![图 12.15 - 清理上一次播放书运行中的运行容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_15.jpg)

图 12.15 - 清理上一次播放书运行中的运行容器

删除运行的容器后，我们现在可以运行我们的新播放书来重新创建容器，绕过构建镜像的步骤，使用以下命令：

```
ansible-playbook -i mastery-hosts docker-all.yaml
```

成功运行的输出应该看起来像*图 12.16*中显示的那样：

![图 12.16 - 使用 Ansible 构建没有 Dockerfile 的容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_16.jpg)

图 12.16 - 使用 Ansible 构建没有 Dockerfile 的容器

我们看到第一个播放执行任务在`localhost`上，然后第二个播放在`playbook-container`上执行。完成后，我们可以使用以下命令测试 Web 服务并列出运行的容器以验证我们的工作：

```
curl http://localhost:8080
docker ps -a --filter ancestor=fedora:34
```

注意这次不同的过滤器；我们的容器是直接从`fedora`镜像构建和运行的，而没有创建`fedora-moo`镜像的中间步骤 - 输出应该看起来像*图 12.17*中显示的那样：

![图 12.17 - 验证我们的播放书运行结果](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_17.jpg)

图 12.17 - 验证我们的播放书运行结果

使用 Ansible 配置运行容器的这种方法有一些优势。首先，您可以重用现有角色来设置应用程序，轻松地从云虚拟机目标切换到容器，甚至切换到裸金属资源（如果需要的话）。其次，您可以通过审查播放书内容轻松地审查所有配置进入应用程序的内容。

使用这种交互方法的另一个用例是使用 Docker 容器模拟多个主机，以验证跨多个主机执行播放书的执行。可以启动一个带有`init`系统作为运行进程的容器，允许启动其他服务，就像它们在完整的操作系统上一样。在持续集成环境中，这种用例对于快速有效地验证播放书内容的更改非常有价值。 

## Docker 清单

与本书前面详细介绍的 OpenStack 和 EC2 清单插件类似，还提供了 Docker 清单插件。如果您希望检查 Docker 清单脚本或以类似于我们在本章前面使用其他动态清单插件的方式使用它，可以找到 Docker 清单脚本，通过创建一个 YAML 清单文件来引用该插件。

让我们首先找到清单脚本本身 - 在我的演示系统上，它位于这里：

```
/usr/local/lib/python3.8/dist-packages/ansible_collections/community/general/scripts/inventory/docker.py
```

一旦你习惯了 Ansible 的安装基本路径，你会发现通过集合轻松浏览目录结构，找到你要找的东西。让我们尝试直接运行这个脚本，看看在配置它用于 playbook 清单目的时我们有哪些选项可用：

```
python3 /usr/local/lib/python3.8/dist-packages/ansible_collections/community/general/scripts/inventory/docker.py --help
```

脚本的`help`输出显示了许多可能的参数；然而，Ansible 将使用的是`--list`和`--host` - 您的输出将类似于*图 12.18*所示：

![图 12.18 - 检查 Docker 动态清单脚本上可用的选项](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_18.jpg)

图 12.18 - 检查 Docker 动态清单脚本上可用的选项

如果之前构建的容器在执行此脚本时仍在运行，您可以使用以下命令列出主机：

```
python3 /usr/local/lib/python3.8/dist-packages/ansible_collections/community/general/scripts/inventory/docker.py --list --pretty | grep -C2 playbook-container
```

它应该出现在输出中（`grep`已经被用来在截图中更明显地显示这一点）：

![图 12.19 - 手动运行 Docker 动态清单插件以探索其行为](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_19.jpg)

图 12.19 - 手动运行 Docker 动态清单插件以探索其行为

与之前一样，提供了许多组，这些组的成员是正在运行的容器。之前显示的两个组是短容器 ID 和长容器 ID。许多变量也作为输出的一部分进行了定义，在前面的截图中已经被大幅缩减。输出的最后一部分显示了另外一些组：

![图 12.20 - 进一步探索动态清单脚本输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_20.jpg)

图 12.20 - 进一步探索动态清单脚本输出

附加的组如下：

+   `docker_hosts`：所有与动态清单脚本通信并查询容器的 Docker 守护程序运行的主机。

+   `image_name`：每个被发现容器使用的图像的组。

+   `container name`：与容器名称匹配的组

+   `running`：所有正在运行的容器的组。

+   `stopped`：所有已停止的容器的组 - 您可以在前面的输出中看到，我们之前启动的容器现在已经停止，因为 500 秒的休眠时间已经过期。

此清单插件及其提供的组和数据可以被 playbook 用来针对可用的各种容器进行交互，而无需手动清单管理或使用`add_host`。在 playbook 中使用插件只需简单地定义一个 YAML 清单文件，其中包含插件名称和连接详细信息 - 要查询本地 Docker 主机，我们可以定义我们的清单如下：

```
---
plugin: community.docker.docker_containers
docker_host: unix://var/run/docker.sock
```

您可以以正常方式对此清单定义使用 Ansible 运行临时命令或 playbook，并获取本地主机上运行的所有容器的详细信息。连接到远程主机并不会更加困难，插件文档（可在此处找到：[`docs.ansible.com/ansible/latest/collections/community/docker/docker_containers_inventory.html`](https://docs.ansible.com/ansible/latest/collections/community/docker/docker_containers_inventory.html)）向您展示了可用于此的选项。我们现在已经看过了几种构建和与 Docker 容器交互的方法，但如果我们想要一个更加协调的方法呢？我们将在下一节中详细讨论这个问题。

# 使用 Ansible 构建容器

正如我们在上一节开头提到的，自本书上一版出版以来，容器的世界已经取得了很大的进步。尽管 Docker 仍然是一种非常流行的容器技术，但新的和改进的技术已经成为首选，并且被纳入到 Linux 操作系统中。Canonical（Ubuntu 的发布者）正在支持**LXC**容器环境，而 Red Hat（Ansible 的所有者）正在支持**Buildah**和**Podman**。

如果你读过本书的第三版，你会知道我们介绍了一个名为**Ansible Container**的技术，它用于直接集成 Ansible 和 Docker，消除了*glue*步骤，比如将主机添加到内存中的清单，有两个单独的 play 来实例化容器，以及构建容器镜像内容。Ansible Container 现在已经被弃用，所有的开发工作都已经停止（根据他们的 GitHub 页面 - 如果你感兴趣，可以查看[`github.com/ansible/ansible-container`](https://github.com/ansible/ansible-container)）。

Ansible Container 已被一个名为**ansible-bender**的新工具取代，它具有不同容器构建环境的可插拔架构。在开发的早期阶段，它只支持**Buildah**，但希望将来会支持更多的容器技术。

Podman/Buildah 工具集可在较新版本的 Red Hat Enterprise Linux、CentOS、Fedora 和 Ubuntu Server 上使用（但不包括 20.04，除非你选择更先进的版本）。由于我们在本书中一直使用 Ubuntu Server 作为演示机器，我们将继续使用这个操作系统，但在本章的这一部分，我们将切换到 20.10 版本，虽然不是 LTS 版本，但有 Buildah 和 Podman 的本地版本可用。

要在 Ubuntu Server 20.10（以及更新版本）上安装 Buildah 和 Podman，只需运行以下命令：

```
sudo apt update
sudo apt install podman runc
```

一旦你安装了容器环境（如果你还没有安装 Ansible，请不要忘记安装 - `ansible-bender`需要它来运行！），你可以使用以下命令安装`ansible-bender`：

```
sudo pip3 install ansible-bender
```

就是这样 - 现在你已经准备好了！在我们深入示例代码之前，值得注意的是`ansible-bender`在功能上比 Ansible Container 简单得多。虽然 Ansible Container 可以管理容器的整个生命周期，但`ansible-bender`只关注容器的构建阶段 - 尽管如此，它提供了一个有用的抽象层，可以使用 Ansible 轻松构建容器镜像，一旦它支持其他容器化构建平台（如 LXC 和/或 Docker），它将成为你自动化工具中非常有价值的工具，因为你将能够使用几乎相同的 playbook 代码在各种平台上构建容器镜像。

让我们为`ansible-bender`构建我们的第一个 playbook。play 的头部现在看起来应该很熟悉 - 有一个重要的例外。注意 play 定义中的`vars:`部分 - 这部分包含了`ansible-bender`使用的重要保留变量，并定义了诸如源容器镜像（我们将再次使用`Fedora 34`）和目标容器镜像详细信息，包括容器启动时要运行的命令：

```
--- 
- name: build an image with ansible-bender
  hosts: localhost 
  gather_facts: false 
  vars:
    ansible_bender:
      base_image: fedora:34
      target_image:
        name: fedora-moo
        cmd: nginx &
```

有了这个定义，我们编写我们的 play 任务的方式与之前完全相同。请注意，我们不需要担心清单定义（无论是通过动态清单提供程序还是通过`ansible.builtin.add_host`） - `ansible-bender`会在实例化容器镜像时使用`ansible_bender`变量结构中的详细信息运行所有任务。因此，我们的代码应该是这样的 - 它与我们之前使用的第二个 play 完全相同，只是我们不运行最后的`ansible.builtin.shell`任务来启动`nginx` web 服务器，因为这是由`ansible_bender`变量中的详细信息处理的。

```
  tasks: 
    - name: install things 
      ansible.builtin.raw: dnf install -y python-dnf 

    - name: install things 
      ansible.builtin.dnf: 
        name: ['nginx', 'cowsay']

    - name: configure nginx 
      ansible.builtin.lineinfile: 
        line: "daemon off;" 
        dest: /etc/nginx/nginx.conf 

    - name: boop 
      ansible.builtin.shell: cowsay boop > /usr/share/nginx/html/index.html
```

就是这样 - 代码没有比这更复杂的了！现在，使用`ansible-bender`构建你的第一个容器就像运行以下命令一样简单：

```
sudo ansible-bender build moo-bender.yaml
```

请注意，命令必须以 root 身份运行（即通过`sudo`） - 这是与 Buildah 和 Podman 相关的特定行为。

`ansible-bender`的一个奇怪之处是，当它开始运行时，您会看到一些声明`ERROR`的行（见*图 12.21*）。这是`ansible-bender`中的一个错误，因为这些行实际上并不是错误 - 它们只是从 Buildah 工具返回的信息：

![图 12.21 - 使用 ansible-bender 开始容器构建过程，以及虚假的 ERROR 消息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_21.jpg)

图 12.21 - 使用 ansible-bender 开始容器构建过程，以及虚假的 ERROR 消息

随着构建的继续，您应该看到 Ansible playbook 消息以您熟悉的方式返回。在过程结束时，您应该看到类似于*图 12.22*所示的成功构建的输出：

![图 12.22 - 使用 ansible-bender 成功构建容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_22.jpg)

图 12.22 - 使用 ansible-bender 成功构建容器

从这里，您可以使用以下命令运行您新构建的容器：

```
sudo podman run -d fedora-moo
```

`fedora-moo`容器名称是在之前的 playbook 文件中的`ansible_bender`变量结构中设置的，而`-d`标志用于从容器中分离并在后台运行。与 Docker 类似，您可以使用以下命令查询系统上正在运行的容器：

```
sudo podman ps
```

这个过程的输出看起来有点像*图 12.23*所示：

![图 12.23 - 运行和查询我们新构建的 Podman 容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_23.jpg)

图 12.23 - 运行和查询我们新构建的 Podman 容器

最后，让我们看看我们是否可以从容器中实际检索到我们的`cowsay`网页。与我们的 Docker 示例不同，我们没有指示 Podman 将 Web 服务器端口重定向到构建机器上的端口，因此我们需要查询容器本身的 IP 地址。在获得`sudo podman ps`输出中的`CONTAINER ID`或`NAMES`后，我们可以使用以下命令查询这个（确保用您系统中的 ID 替换容器 ID）：

```
sudo podman inspect -f '{{ .NetworkSettings.IPAddress }}' f711
```

与 Docker 一样，只要您输入的字符在正在运行的容器列表中是唯一的，您就可以缩写您的容器 ID。一旦获得了 IP 地址，您就可以使用`curl`下载网页，就像我们之前做的那样 - 例如：

```
curl http://172.16.16.9
```

整个过程应该看起来像*图 12.24*所示：

![图 12.24 - 从使用 ansible-bender 构建的 Podman 容器中下载我们的 cowsay 网页](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_12_24.jpg)

图 12.24 - 从使用 ansible-bender 构建的 Podman 容器中下载我们的 cowsay 网页

就是这样了！`ansible-bender`工具在使用一种通用语言 - 我们自己喜欢的 Ansible 来构建容器映像方面显示出了巨大的潜力！随着工具的发展，希望一些粗糙的地方（比如虚假的`ERROR`语句）将得到解决，并且对更多容器平台的支持的添加将真正使其成为一个有价值的容器映像自动化工具。这就结束了我们对使用 Ansible 进行基础架构提供的介绍 - 希望您觉得有价值。

# 总结

DevOps 已经推动了许多新方向的自动化，包括应用程序的容器化，甚至基础架构本身的创建。云计算服务使得可以自助管理用于运行服务的服务器群。Ansible 可以轻松地与这些服务进行交互，提供自动化和编排引擎。

在本章中，您学习了如何使用 Ansible 管理本地云基础架构，例如 OpenStack。然后，我们通过 AWS 和 Microsoft Azure 的公共云基础架构提供示例进行了扩展。最后，您学习了如何使用 Ansible 与 Docker 进行交互，以及如何使用 Ansible Container 整洁地打包 Docker 服务定义。

Ansible 可以启动几乎任何主机，除了正在运行的主机之外，并且在具有适当凭据的情况下，它可以创建它想要管理的基础架构，无论是一次性操作还是将应用程序的新版本部署到生产容器管理系统中。 最终结果是，一旦硬件就位并且服务提供商已配置，如果您愿意，您可以通过 Ansible 管理整个基础架构！

在本书的最后一章中，我们将研究自动化的一个新且迅速增长的领域：使用 Ansible 进行网络配置。

# 问题

1.  在 OpenStack 上创建或删除 VM 实例时，在您的播放中应该引用哪个清单主机？

a) OpenStack 主机

b) 本地主机

c) VM 浮动 IP 地址

d) 以上都不是

1.  如何在第二个播放中引用新创建的虚拟机，而无需使用动态清单脚本？

a) 使用`ansible.builtin.raw`命令。

b) 使用`ansible.builtin.shell`命令。

c) 使用`ansible.builtin.add_host`将新的 VM 添加到内存清单中。

d) 您需要使用动态清单插件。

1.  您仍然可以直接在 Ansible 4.x 及更高版本中运行动态清单脚本，就像在 Ansible 2.x 版本中一样。

a) 正确

b) 错误

1.  要使用动态清单脚本，并设置其参数，您现在可以（假设集合已安装）：

a) 使用插件名称和参数定义 YAML 清单文件。

b) 在`ansible`/`ansible-playbook`的`-i`参数中引用动态清单脚本。

c) 将插件名称放在播放定义中。

1.  第一次使用集合中的新模块（例如，与云提供商一起），您应该：

a) 始终阅读文档，检查已知问题。

b) 始终阅读文档，查看是否需要安装其他 Python 模块。

c) 始终阅读文档，查看应如何定义您的身份验证参数。

d) 以上所有

1.  如果目标主机上没有 Python 环境，Ansible 无法运行（这在最小的云操作系统映像上有时是这样）。 如果是这种情况，您仍然可以使用哪个模块从 playbook 任务中安装 Python？

a) `ansible.builtin.python`

b) `ansible.builtin.raw`

c) `ansible.builtin.command`

d) `ansible.builtin.shell`

1.  所有云提供商模块都将等待 VM 实例启动，然后才允许播放继续执行下一个任务。

a) 正确

b) 错误

1.  如果要等待确保主机在执行其他任务之前可以通过 SSH 访问，可以使用哪个模块？

a) `ansible.builtin.wait_for`

b) `ansible.builtin.ssh`

c) `ansible.builtin.test_connection`

d) `ansible.builtin.connect`

1.  Ansible 可以使用 Dockerfile 构建 Docker 容器，也可以不使用 Dockerfile。

a) 正确

b) 错误

1.  `ansible-bender`工具目前支持哪种构建环境？

a) Docker

b) LXC

c) Podman/Buildah

d) 以上所有
