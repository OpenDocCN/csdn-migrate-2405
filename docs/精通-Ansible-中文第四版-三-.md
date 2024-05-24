# 精通 Ansible 中文第四版（三）

> 原文：[`zh.annas-archive.org/md5/F58519F0D978AE01B8EEFA01F4E150D0`](https://zh.annas-archive.org/md5/F58519F0D978AE01B8EEFA01F4E150D0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：控制任务条件

Ansible 是一个在一个或多个主机上运行任务的系统，并确保操作员了解是否发生了变更（以及是否遇到了任何问题）。因此，Ansible 任务会产生四种可能的状态：`ok`、`changed`、`failed`或`skipped`。这些状态执行了许多重要的功能。

从运行 Ansible playbook 的操作员的角度来看，它们提供了已完成的 Ansible 运行的概述——无论是否发生了任何变更，以及是否有任何需要解决的失败。此外，它们确定了 playbook 的流程——例如，如果一个任务的状态是`changed`，我们可能希望执行服务的重启，否则保持运行。Ansible 具有实现这一切所需的所有功能。

同样，如果一个任务的状态是`failed`，那么 Ansible 的默认行为就是不在该主机上尝试任何进一步的任务。任务还可以使用条件来检查先前任务的状态以控制操作。因此，这些状态或任务条件对于 Ansible 的几乎所有操作都是至关重要的，重要的是要了解如何处理它们，从而控制 playbook 的流程，以满足例如可能发生失败的情况。我们将在本章中详细讨论如何处理这些情况。

在本章中，我们将详细探讨这一点，特别关注以下主题：

+   控制定义失败的内容

+   从失败中恢复

+   控制定义变更的内容

+   使用循环迭代一组任务

# 技术要求

要跟随本章中提出的示例，您需要一台运行**Ansible 4.3**或更新版本的 Linux 机器。几乎任何 Linux 版本都可以使用——对于那些对细节感兴趣的人，本章中提供的所有代码都是在**Ubuntu Server 20.04 LTS**上测试的，除非另有说明，并且在 Ansible 4.3 上。本章附带的示例代码可以从 GitHub 的以下网址下载：[`github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter07`](https://github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter07)。

查看以下视频以查看代码的实际操作：[`bit.ly/3AVXxME`](https://bit.ly/3AVXxME)。

# 定义失败

大多数与 Ansible 一起提供的模块对于什么构成错误有不同的标准。错误条件高度依赖于模块以及模块试图实现的内容。当一个模块返回错误时，主机将从可用主机集合中移除，阻止在该主机上执行任何进一步的任务或处理程序。此外，`ansible-playbook`和`ansible`可执行文件将以非零退出代码退出以指示失败。然而，我们并不受限于模块对错误的看法。我们可以忽略错误或重新定义错误条件。

## 忽略错误

名为`ignore_errors`的任务条件用于忽略错误。这个条件是一个布尔值，意味着值应该是`Ansible`理解为`true`的东西，比如`yes`、`on`、`true`或`1`（字符串或整数）。

为了演示如何使用`ignore_errors`，让我们创建一个 playbook，尝试查询一个不存在的 web 服务器。通常，这将是一个错误，如果我们不定义`ignore_errors`，我们将得到默认行为；也就是说，主机将被标记为失败，并且不会在该主机上尝试任何进一步的任务。创建一个名为`error.yaml`的新 playbook，如下所示，以进一步查看这种行为：

```
---
- name: error handling
  hosts: localhost
  gather_facts: false
  tasks:
  - name: broken website 
    ansible.builtin.uri: 
      url: http://notahost.nodomain 
```

使用以下命令运行此 playbook：

```
ansible-playbook -i mastery-hosts error.yaml
```

这本 playbook 中的单个任务应该导致一个看起来像*图 7.1*中所示的错误：

![图 7.1 – 运行一个故意引发任务错误的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_01.jpg)

图 7.1 – 运行一个故意引发任务错误的 playbook

现在，假设我们不希望 Ansible 在这里停止，而是希望它继续。我们可以像这样在我们的任务中添加`ignore_errors`条件：

```
  - name: broken website 
    ansible.builtin.uri: 
      url: http://notahost.nodomain 
    ignore_errors: true 
```

这次，当我们使用与之前相同的命令运行 playbook 时，我们的错误将被忽略，如*图 7.2*所示：

![图 7.2 - 运行相同的 playbook，但添加了`ignore_errors`任务条件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_02.jpg)

图 7.2 - 运行相同的 playbook，但添加了`ignore_errors`任务条件

对于该主机的任何进一步任务仍将尝试，并且 playbook 不会注册任何失败的主机。

## 定义错误条件

`ignore_errors`条件有点粗糙。来自任务使用的模块的任何错误都将被忽略。此外，乍一看，输出仍然看起来像一个错误，并且可能会让试图发现真正故障的操作员感到困惑。更微妙的工具是`failed_when`条件。这个条件更像是一把精细的手术刀，允许 playbook 作者非常具体地指出什么对于任务来说构成错误。这个条件执行一个测试来生成一个布尔结果，就像`when`条件一样。如果条件导致布尔`true`值，任务将被视为失败。否则，任务将被视为成功。

当与`command`或`shell`模块结合使用并注册执行结果时，`failed_when`条件非常有用。许多执行的程序可能具有详细的非零退出代码，意味着不同的含义。然而，这些 Ansible 模块都认为除`0`之外的任何退出代码都是失败。让我们看看`iscsiadm`实用程序。这个实用程序可以用于与 iSCSI 相关的许多事情。为了演示，我们将在`error.yaml`中替换我们的`uri`模块，并尝试发现任何活动的`iscsi`会话：

```
  - name: query sessions
    ansible.builtin.command: /sbin/iscsiadm -m session
    register: sessions
```

使用与之前相同的命令运行这个 playbook；除非您在具有活动 iSCSI 会话的系统上，否则您将看到与*图 7.3*非常相似的输出：

![图 7.3 - 运行一个 playbook 来发现没有任何故障处理的活动 iSCSI 会话](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_03.jpg)

图 7.3 - 运行一个 playbook 来发现没有任何故障处理的活动 iSCSI 会话

重要提示

`iscsiadm`工具可能不是默认安装的，如果是这样，您将得到与前面不同的错误。在我们的 Ubuntu Server 20.04 测试机器上，它是使用以下命令安装的：`sudo apt install open-iscsi`。

我们可以只使用`ignore_errors`条件，但这将掩盖`iscsi`的其他问题，所以我们不想这样做，而是想指示 Ansible 退出代码`21`是可以接受的。为此，我们可以利用注册变量来访问`rc`变量，该变量保存返回代码。我们将在`failed_when`语句中使用这个：

```
  - name: query sessions
    command: /sbin/iscsiadm -m session
    register: sessions
    failed_when: sessions.rc not in (0, 21) 
```

我们只是声明除`0`或`21`之外的任何退出代码都应被视为失败。再次运行 playbook，但这次增加了详细信息，使用命令的`-v`标志，就像这样：

```
ansible-playbook -i mastery-hosts error.yaml -v
```

再次假设您没有活动的 iSCSI 会话，输出将如*图 7.4*所示。当然，使用`-v`标志并不是强制的，但在这种情况下很有帮助，因为它显示了`iscsiadm`实用程序的退出代码：

![图 7.4 - 运行相同的 playbook，但根据命令退出代码处理故障](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_04.jpg)

图 7.4 - 运行相同的 playbook，但根据命令退出代码处理故障

现在输出显示没有错误，实际上，我们在结果中看到了一个新的数据键 - `failed_when_result`。这显示了我们的`failed_when`语句是否渲染为`true`或`false`；在这种情况下是`false`。

许多命令行工具没有详细的退出代码。实际上，大多数通常使用`0`表示成功，另一个非零代码表示所有失败类型。幸运的是，`failed_when`语句不仅仅限于应用程序的退出代码；它是一个自由形式的布尔语句，可以访问任何所需的数据。让我们看一个不同的问题，涉及`Git`。我们将想象一个场景，我们想要确保`Git`检出中不存在特定的分支。此任务假定`/srv/app`目录中已经检出了`Git`存储库。删除`Git`分支的命令是`git branch -D`。让我们看一下以下代码片段：

```
  - name: delete branch bad
    ansible.builtin.command: git branch -D badfeature
    args:
      chdir: /srv/app
```

要使此代码工作，您需要将`Git`存储库检出到上一个目录中。如果您没有要测试的存储库，可以使用以下命令轻松创建一个（只需确保`/srv/app`中没有任何重要的内容会被覆盖！）：

```
sudo mkdir -p /srv/app
sudo chown $USER /srv/app
cd /srv/app
git init
git commit --allow-empty -m "initial commit"
```

完成这些步骤后，您就可以运行我们之前详细介绍的更新后的 playbook 任务。与以前一样，我们将增加输出的详细信息，以便更好地理解我们 playbook 的行为。

重要提示

`ansible.builtin.command`和`ansible.builtin.shell`模块使用不同的格式来提供模块参数。`ansible.buitin.command`本身以自由形式提供，而模块参数进入`args`哈希。

按照描述运行 playbook 应该会产生错误，因为`git`将产生一个退出代码为`1`的错误，因为分支不存在，如*图 7.5*所示：

![图 7.5 - 在 Ansible playbook 中运行 git 命令而没有错误处理](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_05.jpg)

图 7.5 - 在 Ansible playbook 中运行 git 命令而没有错误处理

如您所见，错误没有得到优雅处理，`localhost`的 play 已中止。

重要提示

我们使用`ansible.builtin.command`模块来轻松演示我们的主题，尽管存在`ansible.builtin.git`模块。处理 Git 存储库时，应改用`ansible.builtin.git`模块。

没有`failed_when`和`changed_when`条件，我们将不得不创建一个两步任务组合来保护自己免受错误的影响：

```
  - name: check if branch badfeature exists
    ansible.builtin.command: git branch
    args:
      chdir: /srv/app
    register: branches
  - name: delete branch bad
    ansible.builtin.command: git branch -D badfeature
    args:
      chdir: /srv/app
    when: branches.stdout is search('badfeature')
```

在分支不存在的情况下，运行这些任务应该如*图 7.6*所示：

![图 7.6 - 在 Ansible playbook 中使用两个任务处理错误](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_06.jpg)

图 7.6 - 在 Ansible playbook 中使用两个任务处理错误

虽然两个任务集是功能性的，但并不高效。让我们改进这一点，并利用`failed_when`功能将两个任务减少到一个：

```
  - name: delete branch bad
    ansible.builtin.command: git branch -D badfeature
    args:
      chdir: /srv/app
    register: gitout
    failed_when:
      - gitout.rc != 0
      - not gitout.stderr is search('branch.*not found')
```

重要提示

通常会使用`and`连接的多个条件可以表示为列表元素。这可以使 playbooks 更易于阅读，逻辑问题更易于发现。

我们检查命令返回代码是否为`0`以外的任何值，然后使用`search`过滤器来搜索带有`branch.*not found`正则表达式的`stderr`值。我们使用 Jinja2 逻辑来组合这两个条件，这将评估为包容的`true`或`false`选项，如*图 7.7*所示：

![图 7.7 - 在 Ansible playbook 中单个任务内有效地处理错误](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_07.jpg)

图 7.7 - 在 Ansible playbook 中单个任务内有效地处理错误

这演示了我们如何重新定义 Ansible playbook 中的失败，并优雅地处理否则会中断 play 的条件。我们还可以重新定义 Ansible 视为更改的内容，接下来我们将看到这一点。

# 定义更改

与定义任务失败类似，也可以定义什么构成了更改的任务结果。这种能力在`ansible.builtin.command`系列模块（`command`，`shell`，`raw`和`script`）中特别有用。与大多数其他模块不同，这个系列的模块没有更改可能是什么的固有概念。事实上，除非另有指示，否则这些模块只会产生`failed`，`changed`或`skipped`。对于这些模块来说，根本没有办法假设更改与未更改的条件，因为它们不能期望理解或解释您可能使用它们执行的每个可能的 shell 命令。

`changed_when`条件允许 playbook 的作者指示模块如何解释更改。就像`failed_when`一样，`changed_when`执行测试以生成布尔结果。经常与`changed_when`一起使用的任务是会以非零退出来指示不需要进行任何工作的命令；因此，作者经常会结合`changed_when`和`failed_when`来微调任务结果的评估。

在我们之前的例子中，`failed_when`条件捕捉到了没有需要做的工作但任务仍然显示了更改的情况。我们希望在退出码`0`时注册更改，但在任何其他退出码时不注册更改。让我们扩展我们的示例任务以实现这一点：

```
  - name: delete branch bad
    ansible.builtin.command: git branch -D badfeature
    args:
      chdir: /srv/app
    register: gitout
    failed_when:
      - gitout.rc != 0
      - not gitout.stderr is search('branch.*not found')
    changed_when: gitout.rc == 0
```

现在，如果我们在分支仍不存在的情况下运行我们的任务（再次增加输出的详细程度，以帮助我们看到底层发生了什么），我们将看到类似于*图 7.8*所示的输出：

![图 7.8 – 通过 changed_when 任务条件扩展我们的 Git playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_08.jpg)

图 7.8 – 通过 changed_when 任务条件扩展我们的 Git playbook

请注意，`changed`键现在的值为`false`。

为了完整起见，我们将改变场景，使分支存在并再次运行它。要创建分支，只需从`/srv/app`目录运行`git branch badfeature`。现在，我们可以再次执行我们的 playbook 以查看输出，输出应该看起来像*图 7.9*所示：

![图 7.9 – 在我们的测试存储库中存在 badfeature 分支时测试相同的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_09.jpg)

图 7.9 – 在我们的测试存储库中存在 badfeature 分支时测试相同的 playbook

这次，我们的输出不同了；它注册了一个更改，而`stdout`数据显示分支被删除了。

## 命令系列的特殊处理

命令系列模块的一个子集（`ansible.builtin.command`，`ansible.builtin.shell`和`ansible.builtin.script`）有一对特殊参数，它们将影响任务工作是否已经完成，从而决定任务是否会导致更改。这些选项是`creates`和`removes`。这两个参数期望一个文件路径作为值。当 Ansible 尝试使用`creates`或`removes`参数执行任务时，它将首先检查引用的文件路径是否存在。

如果路径存在并且使用了`creates`参数，Ansible 将认为工作已经完成，并返回`ok`。相反，如果路径不存在并且使用了`removes`参数，那么 Ansible 将再次认为工作已经完成，并返回`ok`。任何其他组合将导致工作实际发生。预期是任务正在做的任何工作都将导致引用的文件的创建或删除。

`creates`和`removes`的便利性使开发人员无需进行两个任务的组合。让我们创建一个场景，我们想要从项目根目录的`files/`子目录运行`frobitz`脚本。在我们的场景中，我们知道`frobitz`脚本将创建一个路径`/srv/whiskey/tango`。实际上，`frobitz`的源代码如下：

```
#!/bin/bash 
rm -rf /srv/whiskey/tango 
mkdir -p /srv/whiskey/tango 
```

我们不希望这个脚本运行两次，因为它可能对任何现有数据造成破坏。替换我们的`error.yaml` playbook 中的现有任务，两个任务的组合将如下所示：

```
  - name: discover tango directory
    ansible.builtin.stat: path=/srv/whiskey/tango
    register: tango
  - name: run frobitz
    ansible.builtin.script: files/frobitz --initialize /srv/whiskey/tango
    when: not tango.stat.exists
```

像我们在本章中一样，以增加的详细程度运行 playbook。如果`/srv/whiskey/tango`路径已经存在，输出将如*图 7.10*所示：

![图 7.10 – 一个两个任务的 play，有条件地运行破坏性脚本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_10.jpg)

图 7.10 – 一个两个任务的 play，有条件地运行破坏性脚本

如果`/srv/whiskey/tango`路径不存在，`ansible.builtin.stat`模块将返回更少的数据，`exists`键的值将为`false`。因此，我们的`frobitz`脚本将被运行。

现在，我们将使用`creates`将其减少为一个单独的任务：

```
  - name: run frobitz 
    ansible.builtin.script: files/frobitz 
    args:
      creates: /srv/whiskey/tango 
```

重要提示

`ansible.builtin.script`模块实际上是一个`action_plugin`，将在*第十章*中讨论，*扩展 Ansible*。

这一次，我们的输出将会有些不同，如*图 7.11*所示：

![图 7.11 – 通过将所有任务条件合并为一个任务使我们以前的 playbook 更加高效](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_11.jpg)

图 7.11 – 通过将所有任务条件合并为一个任务使我们以前的 playbook 更加高效

这一次，我们完全跳过了运行脚本，因为在 playbook 甚至运行之前目录已经存在。这样可以节省 playbook 执行时间，也可以防止运行脚本可能导致的任何潜在破坏性行为。

重要提示

充分利用`creates`和`removes`将使您的 playbook 简洁高效。

## 抑制更改

有时，完全抑制更改是可取的。这经常用于执行命令以收集数据。命令执行实际上并没有改变任何东西；相反，它只是收集信息，就像`ansible.builtin.setup`模块一样。在这种任务上抑制更改可以帮助快速确定 playbook 运行是否导致了舰队中的任何实际更改。

要抑制更改，只需将`false`作为`changed_when`任务键的参数。让我们扩展我们以前的一个例子，以发现要抑制更改的活动`iscsi`会话：

```
  - name: discover iscsi sessions
    ansible.builtin.command: /sbin/iscsiadm -m session
    register: sessions
    failed_when:
      - sessions.rc != 0
      - not sessions.stderr is
        search('No active sessions')
    changed_when: false
```

现在，无论返回的数据是什么，Ansible 都会将任务视为`ok`而不是 changed，如*图 7.12*所示：

![图 7.12 – 抑制 Ansible playbook 中的更改](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_12.jpg)

图 7.12 – 抑制 Ansible playbook 中的更改

因此，这个任务现在只有两种可能的状态——`failed`和`ok`。我们实际上否定了`changed`任务结果的可能性。当然，运行代码时出现故障是生活的一部分，重要的是我们能够在 playbook 中优雅地处理这些问题。在下一节中，我们将看看在 Ansible 中如何实现这一点。

# 错误恢复

虽然错误条件可以被严格定义，但有时会发生真正的错误。Ansible 提供了一种方法来对真正的错误做出反应，一种允许在发生错误时运行附加任务的方法，定义特定任务，即使出现错误也始终执行，或者两者都执行。这种方法就是**block**功能。

block 功能是在 Ansible 2.0 版本中引入的，它为相关的 play 任务集提供了一些额外的结构。块可以将任务组合成一个逻辑单元，该单元（或块）可以对整个单元（或块）应用任务控制。此外，一组任务的块可以有可选的`rescue`和`always`部分，它们分别在错误状态下执行和不管错误状态如何执行。我们将在接下来的两个部分中探讨它们的工作原理。

## 使用 rescue 部分

`block`的`rescue`部分定义了一个逻辑单元的任务，当块内遇到实际失败时将执行。当 Ansible 执行块内的任务时，执行通常从上到下进行，当遇到实际失败时，执行将跳转到`rescue`部分的第一个任务（如果存在；此部分是可选的）。然后，任务将从上到下执行，直到到达`rescue`部分的末尾或遇到另一个错误为止。

在`rescue`部分完成后，任务执行将继续进行，就像没有错误一样。这提供了一种优雅地处理错误的方式，允许定义`cleanup`任务，以便系统不会处于完全破碎的状态，并且 play 的其余部分可以继续。这比基于错误状态的一组复杂的任务注册结果和任务条件要干净得多。

为了演示这一点，让我们在一个块内创建一个新的任务集。这个任务集中将有一个未处理的错误，这将导致执行切换到`rescue`部分，从那里我们将执行一个`cleanup`任务。

我们还将在块之后提供一个任务，以确保执行继续。我们将重用`error.yaml` playbook:

```
---
- name: error handling
  hosts: localhost
  gather_facts: false
  tasks:
  - block:
      - name: delete branch bad
        ansible.builtin.command: git branch -D badfeature
        args:
          chdir: /srv/app
      - name: this task is lost
        ansible.builtin.debug:
          msg: "I do not get seen"
```

`block`部分中列出的两个任务按照它们列出的顺序执行。如果其中一个导致`failed`结果，那么`rescue`块中显示的以下代码将被执行：

```
    rescue:
      - name: cleanup task
        ansible.builtin.debug:
          msg: "I am cleaning up"
      - name: cleanup task 2
        ansible.builtin.debug:
          msg: "I am also cleaning up"
```

最后，无论之前的任务如何，都会执行这个任务。请注意，较低的缩进级别意味着它与块的相同级别运行，而不是作为`block`结构的一部分运行：

```
  - name: task after block
    ansible.builtin.debug:
      msg: "Execution goes on" 
```

尝试执行此 playbook 以观察其行为；像我们在本章中一样，向输出添加详细信息，以帮助您理解发生了什么。当此 play 执行时，第一个任务将导致错误，并且第二个任务将被跳过。执行将继续进行`cleanup`任务，并且应该如*图 7.13*所示：

![图 7.13 - 执行包含救援部分的块的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_13.jpg)

图 7.13 - 执行包含救援部分的块的 playbook

不仅执行了`rescue`部分，而且整个 play 也完成了，并且整个`ansible-playbook`执行被认为是成功的，尽管块内的先前任务失败。让我们在下一节中通过查看块的`always`部分来扩展这个例子。

## 使用 always 部分

除了`rescue`，我们还可以使用另一个部分，名为`always`。块的这部分将始终执行，无论是否出现错误。这个功能对于确保系统状态始终保持功能非常方便，无论一组任务是否成功。由于一些块任务可能由于错误而被跳过，而`rescue`部分仅在出现错误时执行，`always`部分提供了在每种情况下执行任务的保证。

让我们扩展我们之前的例子，并向我们的块添加一个`always`部分：

```
    always:
      - name: most important task
        ansible.builtin.debug:
          msg: "Never going to let you down"
```

重新运行我们的 playbook，如前一节所示，我们可以看到额外的任务显示如下，如*图 7.14*所示：

![图 7.14 - 运行包含救援和 always 部分的 Ansible playbook 的块](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_14.jpg)

图 7.14 - 运行包含救援和 always 部分的 Ansible playbook 的块

为了验证`always`部分确实总是执行，我们可以修改 play，以便使用我们在前一节中开发的任务条件来使 Git 任务被认为是成功的。修改后的 play 的第一部分如下所示，供您参考：

```
---
- name: error handling
  hosts: localhost
  gather_facts: false
  tasks:
  - block:
      - name: delete branch bad
        ansible.builtin.command: git branch -D badfeature
        args:
          chdir: /srv/app
        register: gitout
        failed_when:
          - gitout.rc != 0
          - not gitout.stderr is search('branch.*not found')
```

请注意更改的`failed_when`条件，这将使`git`命令在不被视为失败的情况下运行。playbook 的其余部分（到目前为止在先前的示例中已经构建起来）保持不变。

这一次，当我们执行 playbook 时，我们的`rescue`部分被跳过，我们之前由于错误而被屏蔽的任务被执行，我们的`always`块仍然被执行，正如*图 7.15*所示：

![图 7.15 - 执行一个包含救援和总是部分但没有任务错误的块的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_15.jpg)

图 7.15 - 执行一个包含救援和总是部分但没有任务错误的块的 playbook

还要注意，我们之前丢失的任务现在已经被执行，因为`delete branch bad`任务的失败条件已经更改，因此在此播放中不再失败。类似地，我们的`rescue`部分不再需要，并且所有其他任务（包括`always`部分）都如预期地完成。在 ansible 中处理由不可靠环境引起的错误的最后部分中，我们将看到如何处理这些错误。 

## 处理不可靠的环境

到目前为止，在本章中，我们已经专注于优雅地处理错误，并改变了 ansible 对于更改和失败的默认行为。这对于任务来说都很好，但是如果您在一个不可靠的环境中运行 ansible 呢？例如，可能使用较差或瞬时的连接来到达受管主机，或者由于某种原因主机可能经常宕机。后一种情况可能是一个动态扩展的环境，可以在高负载时扩展，并在需求低时缩减以节省资源-因此您无法保证所有主机始终可用。

幸运的是，playbook 关键字`ignore_unreachable`恰好处理这些情况，并确保在我们的清单上尝试所有任务，即使在执行任务期间标记为不可达的主机。这与默认行为相反，即当 ansible 发生第一个错误时，将停止处理给定主机的任务。就像在许多情况下一样，最好通过一个例子来解释，所以让我们重用`error.yaml` playbook 来创建这样一个情况：

```
---
- name: error handling
  hosts: all
  gather_facts: false
  tasks:
  - name: delete branch bad
    ansible.builtin.command: git branch -D badfeature
    args:
      chdir: /srv/app
  - name: important task
    ansible.builtin.debug:
      msg: It is important we attempt this task!
```

我们将尝试从我们的清单中定义的两个远程主机的 Git 仓库中删除`badfeature`分支。这个清单将与本书中使用的其他清单有所不同，因为我们将故意创建两个不可达的虚构主机。这些主机的实际名称或定义的 IP 地址并不重要，但是为了使本节中描述的示例能够正常工作，这些主机必须是不可达的。我的清单文件如下所示：

```
[demo]
mastery.example.com ansible_host=192.168.10.25
backend.example.com ansible_host=192.168.10.26
```

由于我们故意创建了一个不存在的主机清单，我们知道它们将在尝试第一个任务时被标记为不可达。尽管如此，在第二个任务中仍然有一个绝对必须尝试的任务。让我们按原样运行 playbook，看看会发生什么；输出应该如*图 7.16*所示：

![图 7.16 - 尝试在不可达主机清单上进行两个任务的播放](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_16.jpg)

图 7.16 - 尝试在不可达主机清单上进行两个任务的播放

从输出中可以看出，名为`important task`的任务从未被尝试过-在第一个任务后播放被中止，因为主机不可达。然而，让我们使用我们新发现的标志来改变这种行为。将代码更改为如下所示：

```
---
- name: error handling
  hosts: all
  gather_facts: false
  tasks:
  - name: delete branch bad
    ansible.builtin.command: git branch -D badfeature
    args:
      chdir: /srv/app
    ignore_unreachable: true
  - name: important task
    ansible.builtin.debug:
      msg: It is important we attempt this task!
```

这一次，请注意，即使在第一次尝试时主机不可达，我们的第二个任务仍然被执行，正如*图 7.17*所示：

![图 7.17 - 尝试在不可达主机上进行相同的两个任务播放，但这次忽略可达性](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_17.jpg)

图 7.17 - 尝试在不可达主机上进行相同的两个任务播放，但这次忽略可达性

如果像`debug`命令一样，它可能在本地运行，或者它是至关重要的，并且即使在第一次尝试时连接失败也应该尝试。到目前为止，在本章中，你已经了解了 Ansible 提供的处理各种错误条件的工具。接下来，我们将继续探讨使用循环来控制任务流程——这是使代码简洁并防止重复的特别重要的工具。

# 使用循环的迭代任务

循环在本章中值得特别提及。到目前为止，我们已经专注于以自上而下的方式控制 playbook 的流程——我们已经改变了在 playbook 运行时可能被评估的各种条件，并且我们也专注于创建简洁、高效的代码。然而，如果你有一个单独的任务，但需要针对一组数据运行它会发生什么呢？例如，创建多个用户帐户、目录，或者更复杂的东西？

循环在 Ansible 2.5 中发生了变化——在此之前，循环通常是使用`with_items`等关键字创建的，你可能仍然在旧代码中看到这种情况。尽管一些向后兼容性仍然存在，但建议使用更新的`loop`关键字。

让我们举一个简单的例子——我们需要创建两个目录。创建`loop.yaml`如下：

```
---
- name: looping demo
  hosts: localhost
  gather_facts: false
  become: true
  tasks:
  - name: create a directory
    ansible.builtin.file:
      path: /srv/whiskey/alpha
      state: directory
  - name: create another directory
    ansible.builtin.file:
      path: /srv/whiskey/beta
      state: directory
```

当我们运行这个时，如预期的那样，我们的两个目录被创建了，就像*图 7.18*所示：

![图 7.18 – 运行一个简单的 playbook 来创建两个目录](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_18.jpg)

图 7.18 – 运行一个简单的 playbook 来创建两个目录

然而，你可以看到这段代码是重复的和低效的。相反，我们可以将其改为以下内容：

```
---
- name: looping demo
  hosts: localhost
  gather_facts: false
  become: true
  tasks:
  - name: create a directory
    ansible.builtin.file:
      path: "{{ item }}"
      state: directory
    loop:
      - /srv/whiskey/alpha
      - /srv/whiskey/beta
```

注意特殊的`item`变量的使用，它现在用于定义任务底部的`loop`项的`path`。现在，当我们运行这段代码时，输出看起来有些不同，就像*图 7.19*所示：

![图 7.19 – 一个用循环创建相同两个目录的 playbook 一个用于更高效的代码的循环](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_19.jpg)

图 7.19 – 一个用循环创建相同两个目录的 playbook，这次使用循环以获得更高效的代码

这两个目录仍然像以前一样被创建，但这次是在一个任务中。这使得我们的 playbook 更加简洁和高效。Ansible 提供了许多更强大的循环选项，包括嵌套循环和创建循环，直到满足给定条件（在其他语言中通常称为`do until`循环），而不是特定的有限数据集。

`do until`循环在等待满足某个条件时非常有用。例如，如果我们想要等待直到文件系统写入了一个标志文件，我们可以使用`ansible.builtin.stat`模块来查询文件，将模块运行的结果注册到一个变量中，然后在循环中运行，直到满足文件存在的条件。以下代码片段正是这样做的——它将循环（`retries`）五次，每次重试之间间隔 10 秒：

```
    - name: Wait until /tmp/flag exists
      ansible.builtin.stat:
        path: /tmp/flag
      register: statresult
      until: statresult.stat.exists
      retries: 5
      delay: 10
```

嵌套循环可以通过两种方式创建——要么通过对嵌套列表进行迭代，要么通过对包含的任务文件进行迭代。例如，假设我们想要在两个路径中分别创建两个新文件（由 Ansible 中的两个列表定义）。我们的代码可能是这样的：

```
---
- name: Nested loop example
  hosts: all
  gather_facts: no
  vars:
    paths:
      - /tmp
      - /var/tmp
    files:
      - test1
      - test2
  tasks:
    - name: Create files with nested loop
      ansible.builtin.file:
        path: "{{ item[0] }}/{{ item[1] }}"
        state: touch
      loop: "{{ paths | product(files) | list }}"
```

在这里，我们使用了`product` Jinja2 过滤器，将两个变量列表创建为嵌套列表，然后`loop`忠实地为我们迭代。运行这个 playbook 应该会产生类似*图 7.20*中的输出：

![图 7.20 – 使用 product Jinja2 过滤器构建嵌套循环运行 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_20.jpg)

图 7.20 – 使用 product Jinja2 过滤器构建嵌套循环运行 playbook

您还可以通过在外部循环中包含一个外部任务文件，然后在任务文件中放置一个内部循环来创建嵌套循环。现在，如果您这样做而不做任何进一步的操作，两个循环都将使用`item`循环变量，这当然会发生冲突。为了防止这成为一个问题，有必要使用特殊的`loop_control`参数之一来更改外部循环的循环变量名称。因此，使用与之前相同的标题代码和变量，我们可以将我们的原始任务更改为以下内容：

```
    - name: Create files with nested loop
      ansible.builtin.include_tasks: createfile.yml
      loop: "{{ paths }}"
      loop_control:
        loop_var: pathname
```

然后包含的任务文件将如下所示：

```
---
- name: Create a file
  ansible.builtin.file:
    path: "{{ pathname }}/{{ item }}"
    state: touch
  loop: "{{ files }}"
```

这段代码执行的功能与第一个嵌套循环示例完全相同，但稍微麻烦一些，因为它需要一个外部任务文件。此外，您将从*图 7.21*的屏幕截图中看到它的操作方式有些不同。在构建嵌套循环时，这一点很重要，因为这可能（或可能不）是您想要的：

![图 7.21 - 通过包含的任务文件在 Ansible 中构建嵌套循环，使用 loop_control 变量](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_07_21.jpg)

图 7.21 - 通过包含的任务文件在 Ansible 中构建嵌套循环，使用 loop_control 变量

可以说这种格式更容易阅读，但最终由您决定哪种更适合您的需求，以及是否有一种比另一种更适合您。有关循环创建技术和参数的完整详细信息，请参阅 Ansible 文档：[`docs.ansible.com/ansible/latest/user_guide/playbooks_loops.html`](https://docs.ansible.com/ansible/latest/user_guide/playbooks_loops.html)。

# 总结

在本章中，您了解到可以具体定义 Ansible 在运行特定任务时如何感知失败或更改，如何使用块来优雅地处理错误和执行清理，并且如何使用循环编写紧凑高效的代码。

因此，您现在应该能够修改任何给定任务，以提供特定条件，使得 Ansible 在失败或者考虑更改成功时失败。当运行 shell 命令时，这是非常有价值的，正如我们在本章中所演示的，也适用于定义现有模块的专门用例。您现在还应该能够将您的 Ansible 任务组织成块，确保如果发生故障，可以采取恢复操作，否则不需要运行。最后，您现在应该能够使用循环编写紧凑高效的 Ansible Playbook，消除重复代码和冗长低效的 Playbook 的需要。

在下一章中，我们将探讨使用角色来组织任务、文件、变量和其他内容。

# 问题

1.  默认情况下，Ansible 在给定主机的第一个失败发生后将停止处理进一步的任务：

a) 真

b) 假

1.  `ansible.builtin.command`和`ansible.builtin.shell`模块的默认行为是只给出任务状态为`changed`或`failed`：

a) 真

b) 假

1.  您可以使用哪个 Ansible 关键字存储任务的结果？

a) `store:`

b) `variable:`

c) `register:`

d) `save:`

1.  以下哪个指令可以用来改变任务的失败条件？

a) `error_if:`

b) `failed_if:`

c) `error_when:`

d) `failed_when:`

1.  您可以使用以下哪个来组合多个条件语句？

a) `and`

b) `或`

c) YAML 列表格式（与逻辑`AND`相同）

d) 以上所有

1.  以下哪个可以抑制更改？

a) `suppress_changed: true`

b) `changed_when: false`

c) `changed: false`

d) `failed_when: false`

1.  在`block`部分中，所有任务都按顺序在所有主机上执行：

a) 直到发生第一个错误

b) 无论任何错误条件

1.  块任务中的哪个可选部分只有在块任务中发生错误时才运行？

a) `recover`

b) `rescue`

c) `always`

d) `on_error`

1.  块中的`always`部分中的任务将被运行：

a) 无论发生了什么，无论是在块任务还是在`rescue`部分

b) 只有在`rescue`部分没有运行时

c) 只有在没有遇到错误时

d) 当用户手动调用时

1.  循环中引用当前元素的变量的默认名称是：

a) `loopvar`

b) `loopitem`

c) `item`

d) `val`


# 第八章：使用角色组合可重用的 Ansible 内容

对于许多项目，一个简单的、单一的**Ansible**剧本可能就足够了。随着时间的推移和项目的增长，会添加额外的剧本和变量文件，并且任务文件可能会被拆分。组织内的其他项目可能希望重用一些内容，要么将项目添加到目录树中，要么将所需内容复制到多个项目中。随着场景的复杂性和规模的增长，远不止一个松散组织的一小部分剧本、任务文件和变量文件是非常需要的。创建这样的层次结构可能是令人生畏的，这也可以解释为什么许多 Ansible 实现一开始都很简单，只有在分散的文件变得难以控制和难以维护时才变得更加有组织。迁移可能很困难，并且可能需要重写剧本的重要部分，这可能会进一步延迟重新组织的努力。

在本章中，我们将介绍在 Ansible 中组合、可重用和组织良好的最佳实践。本章中学到的经验将帮助开发人员设计能够与项目良好增长的 Ansible 内容，避免以后需要进行困难的重新设计工作。以下是我们将要涵盖的内容大纲：

+   任务、处理程序、变量和剧本包含概念

+   角色（结构、默认值和依赖项）

+   设计顶层剧本以利用角色

+   在项目之间共享角色（通过 Galaxy 进行依赖项；类似 Git 的存储库）

# 技术要求

要按照本章中提供的示例，您需要一台运行**Ansible 4.3**或更新版本的 Linux 机器。几乎任何 Linux 版本都可以——对于那些对具体情况感兴趣的人，本章中提供的所有代码都是在**Ubuntu Server 20.04 长期支持版**（**LTS**）上测试的，除非另有说明，并且在 Ansible 4.3 上也进行了测试。

本章附带的示例代码可以从 GitHub 的以下链接下载：[`github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter08`](https://github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter08)。

查看以下视频，了解代码的实际操作：[`bit.ly/3E0mmIX`](https://bit.ly/3E0mmIX)。

# 任务、处理程序、变量和剧本包含概念

了解如何高效组织 Ansible 项目结构的第一步是掌握包含文件的概念。包含文件的行为允许在一个专题文件中定义内容，并在项目中的一个或多个文件中包含这些内容。这种包含功能支持**不要重复自己**（**DRY**）的概念。

## 包括任务

任务文件是**YAML Ain't Markup Language**（**YAML**）文件，用于定义一个或多个任务。这些任务与任何特定的游戏或剧本没有直接联系；它们纯粹存在作为任务列表。这些文件可以通过`include`运算符被**剧本**或其他任务文件引用。现在，您可能期望`include`运算符是 Ansible 自己的关键字——然而，事实并非如此；它实际上是一个模块，就像`ansible.builtin.debug`一样。为了简洁起见，我们在本章中将其称为`include`运算符，但当我们说这个时候，您的代码实际上将包含**Fully Qualified Collection Name**（**FQCN**—参见*第二章*，*从早期 Ansible 版本迁移*），即`ansible.builtin.include`。您很快就会看到它的作用，所以不用担心——这一切很快就会讲得通！这个运算符接受一个任务文件的路径，正如我们在*第一章*中学到的那样，*Ansible 的系统架构和设计*，路径可以是相对于引用它的文件的。

为了演示如何使用`include`运算符来包含任务，让我们创建一个简单的 play，其中包含一个带有一些调试任务的任务文件。首先，让我们编写我们的 playbook 文件，我们将其命名为`includer.yaml`，如下所示：

```
--- 
- name: task inclusion 
  hosts: localhost 
  gather_facts: false 

  tasks: 
  - name: non-included task
    ansible.builtin.debug:
      msg: "I am not included"
  - ansible.builtin.include: more-tasks.yaml
```

接下来，我们将创建一个`more-tasks.yaml`文件，你可以在`include`语句中看到它的引用。这应该在保存`includer.yaml`的同一目录中创建。代码如下所示：

```
--- 
- name: included task 1 
  ansible.builtin.debug: 
    msg: "I am the first included task" 

- name: included task 2 
  ansible.builtin.debug: 
    msg: "I am the second included task" 
```

现在，我们可以使用以下命令执行我们的 playbook 以观察输出：

```
ansible-playbook -i mastery-hosts includer.yaml
```

如果一切顺利，你应该看到类似于这样的输出：

![图 8.1 - 执行包含单独任务文件的 Ansible playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_01.jpg)

图 8.1 - 执行包含单独任务文件的 Ansible playbook

我们可以清楚地看到我们的`include`文件执行的任务。因为`include`运算符是在 play 的`tasks`部分中使用的，所以包含的任务在该 play 中执行。实际上，如果我们在`include`运算符之后向 play 添加一个任务，如下面的代码片段所示，我们会看到执行顺序遵循包含文件的所有任务存在的位置：

```
  tasks:
  - name: non-included task
    ansible.builtin.debug:
      msg: "I am not included"
  - ansible.builtin.include: more-tasks.yaml
  - name: after-included tasks
    ansible.builtin.debug:
      msg: "I run last"
```

如果我们使用与之前相同的命令运行我们修改后的 playbook，我们将看到我们期望的任务顺序，如下面的截图所示：

![图 8.2 - 演示使用 include 运算符的 playbook 中任务执行顺序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_02.jpg)

图 8.2 - 演示使用 include 运算符的 playbook 中任务执行顺序

通过将这些任务拆分成它们自己的文件，我们可以多次包含它们或在多个 playbook 中包含它们。如果我们需要修改其中一个任务，我们只需要修改一个文件，无论这个文件被引用了多少次。

### 将变量值传递给包含的任务

有时，我们想要拆分一组任务，但这些任务的行为可能会根据变量数据略有不同。`include`运算符允许我们在包含时定义和覆盖变量数据。定义的范围仅限于包含的任务文件（以及该文件可能包含的任何其他文件）。

为了说明这种能力，让我们创建一个新的场景，我们需要触摸两个文件，每个文件都在自己的目录路径中。我们将创建一个任务文件，其中包含每个任务的变量名称。然后，我们将两次包含任务文件，每次传递不同的数据。首先，我们将使用`files.yaml`任务文件，如下所示：

```
---
- name: create leading path
  ansible.builtin.file:
    path: "{{ path }}"
    state: directory
- name: touch the file
  ansible.builtin.file:
    path: "{{ path + '/' + file }}"
    state: touch
```

接下来，我们将修改我们的`includer.yaml` playbook，包含我们刚刚创建的任务文件，并传递`path`和`file`变量的变量数据，如下所示：

```
---
- name: touch files
  hosts: localhost
  gather_facts: false
  tasks:
  - ansible.builtin.include: files.yaml
    vars:
      path: /tmp/foo
      file: herp
  - ansible.builtin.include: files.yaml
    vars:
      path: /tmp/foo
      file: derp
```

重要提示

在包含文件时提供的变量定义可以是`key=value`的内联格式，也可以是`key: value`的 YAML 格式，位于`vars`哈希内。

当我们运行这个 playbook 时，我们将看到四个任务被执行：两个任务来自包含的`files.yaml`文件，每个任务执行两次。第二组应该只有一个更改，因为两组的路径相同，并且应该在执行任务时创建。通过使用以下命令添加详细信息来运行 playbook，以便我们可以更多地了解底层发生了什么：

```
ansible-playbook -i mastery-hosts includer.yaml -v
```

运行此 playbook 的输出应该类似于这样：

![图 8.3 - 运行一个包含两个不同变量数据的任务文件的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_03.jpg)

图 8.3 - 运行一个包含两个不同变量数据的任务文件的 playbook

正如我们在这里所看到的，用于创建前导路径和文件的代码被重复使用，每次只是使用不同的值，使我们的代码非常高效易于维护。

### 将复杂数据传递给包含的任务

当想要向包含的任务传递复杂数据，比如列表或哈希时，可以在包含文件时使用另一种语法。让我们重复上一个场景，只是这次不是两次包含任务文件，而是一次包含并传递路径和文件的哈希。首先，我们将重新创建`files.yaml`文件，如下所示：

```
--- 
- name: create leading path 
  ansible.builtin.file: 
    path: "{{ item.value.path }}" 
    state: directory 
  loop: "{{ files | dict2items }}" 

- name: touch the file 
  ansible.builtin.file: 
    path: "{{ item.value.path + '/' + item.key }}" 
    state: touch 
  loop: "{{ files | dict2items }}" 
```

现在，我们将修改我们的`includer.yaml` playbook，以提供文件的哈希值在单个`ansible.builtin.include`语句中，如下所示：

```
---
- name: touch files
  hosts: localhost
  gather_facts: false
  tasks:
  - ansible.builtin.include: files.yaml
    vars:
      files:
        herp:
          path: /tmp/foo
        derp:
          path: /tmp/foo
```

如果我们像以前一样运行这个新的 playbook 和任务文件，我们应该会看到一个类似但略有不同的输出，最终结果是`/tmp/foo`目录已经存在，并且两个`herp`和`derp`文件被创建为空文件（被触摸）在其中，如下面的截图所示：

![图 8.4 - 将复杂数据传递给 Ansible play 中包含的任务文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_04.jpg)

图 8.4 - 将复杂数据传递给 Ansible play 中包含的任务文件

使用这种方式传递数据的哈希允许创建一组事物，而无需在主 playbook 中增加`include`语句的数量。

### 条件任务包括

类似于将数据传递给包含的文件，条件也可以传递给包含的文件。这是通过将`when`语句附加到`include`运算符来实现的。这个条件并不会导致 Ansible 评估测试以确定是否应该包含文件；相反，它指示 Ansible 将条件添加到包含文件中的每个任务以及该文件可能包含的任何其他文件中。

重要提示

不可能有条件地包含一个文件。文件将始终被包含；但是，可以对`include`层次结构中的每个任务应用任务条件。

让我们通过修改包含简单调试语句的第一个示例来演示这一点。我们将添加一个条件并传递一些数据供条件使用。首先，让我们修改`includer.yaml` playbook，如下所示：

```
---
- name: task inclusion
  hosts: localhost
  gather_facts: false
  tasks:
  - ansible.builtin.include: more-tasks.yaml
    when: item | bool
    vars:
      a_list:
        - true
        - false
```

接下来，让我们修改`more-tasks.yaml`，在每个任务中循环`a_list`变量，如下所示：

```
---
- name: included task 1
  ansible.builtin.debug:
    msg: "I am the first included task"
  loop: "{{ a_list }}"
- name: include task 2
  ansible.builtin.debug:
    msg: "I am the second included task"
  loop: "{{ a_list }}"
```

现在，让我们用与之前相同的命令运行 playbook，并查看我们的新输出，应该是这样的：

![图 8.5 - 将条件应用于包含文件中的所有任务](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_05.jpg)

图 8.5 - 将条件应用于包含文件中的所有任务

我们可以看到每个任务的跳过迭代，其中`item`被评估为`false`布尔值。重要的是要记住，所有主机都将评估所有包含的任务。没有办法影响 Ansible 不为一部分主机包含文件。最多，可以对`include`层次结构中的每个任务应用条件，以便可以跳过包含的任务。根据主机事实包含任务的一种方法是利用`ansible.builtin.group_by`动作插件根据主机事实创建动态组。然后，您可以为这些组提供自己的 play 以包含特定的任务。这是留给您的一个练习。

### 对包含的任务进行标记

在包含任务文件时，可以对文件中的所有任务进行标记。`tags`关键字用于定义要应用于`include`层次结构中所有任务的一个或多个标记。在`include`时进行标记的能力可以使任务文件本身不对任务应该如何标记持有意见，并且可以允许一组任务被多次包含，但传递不同的数据和标记。

重要提示

可以在`include`语句或 play 本身中定义标记，以覆盖给定 play 中所有包含（和其他任务）。

让我们创建一个简单的演示来说明标记如何使用。我们将首先编辑我们的`includer.yaml`文件，创建一个包含任务文件的 playbook，每个任务文件都有不同的标记名称和不同的变量数据。代码如下所示：

```
---
- name: task inclusion
  hosts: localhost
  gather_facts: false
  tasks:
  - ansible.builtin.include: more-tasks.yaml
    vars:
      data: first
    tags: first
  - ansible.builtin.include: more-tasks.yaml
    vars:
      data: second
    tags: second
```

现在，我们将更新`more-tasks.yaml`以处理提供的数据，如下所示：

```
---
- name: included task
  ansible.builtin.debug:
    msg: "My data is {{ data }}"
```

如果我们在不选择标记的情况下运行这个 playbook，我们将看到这个任务运行两次，如下的屏幕截图所示：

![图 8.6 - 运行带有标记的包含任务的 playbook，但没有启用任何基于标记的过滤](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_06.jpg)

图 8.6 - 运行带有标记的包含任务的 playbook，但没有启用任何基于标记的过滤

现在，我们可以通过修改我们的`ansible-playbook`参数来选择要运行的标记，比如第二个标记，如下所示：

```
ansible-playbook -i mastery-hosts includer.yaml -v --tags second
```

在这种情况下，我们应该只看到被包含任务的发生，如下的屏幕截图所示：

![图 8.7 - 运行带有标记的包含任务的 playbook，只运行标记为"second"的任务](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_07.jpg)

图 8.7 - 运行带有标记的包含任务的 playbook，只运行标记为"second"的任务

我们的示例使用`--tags`命令行参数来指示要运行的标记任务。另一个参数`--skip-tags`允许表示相反的意思，或者换句话说，不要运行哪些标记的任务。

## 循环中的任务包含

任务包含也可以与循环结合使用。当向任务包含添加一个`loop`实例（或者如果使用早于 2.5 版本的 Ansible，则使用`with_`循环），文件内的任务将使用`item`变量执行，该变量保存当前循环值的位置。整个`include`文件将重复执行，直到循环用完项目。让我们更新我们的示例 play 来演示这一点，如下所示：

```
---
- name: task inclusion
  hosts: localhost
  gather_facts: false
  tasks:
  - ansible.builtin.include: more-tasks.yaml
    loop:
      - one
      - two
```

我们还需要更新我们的`more-tasks.yaml`文件，以使用循环`item`变量，如下所示：

```
--- 
- name: included task 1 
  ansible.builtin.debug: 
    msg: "I am the first included task with {{ item }}"
- name: included task 2 
  ansible.builtin.debug: 
    msg: "I am the second included task with {{ item }}" 
```

当以增加的详细程度执行时，我们可以看到任务`1`和`2`针对循环中的每个`item`变量执行一次，如下的屏幕截图所示：

![图 8.8 - 在循环中运行包含的任务文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_08.jpg)

图 8.8 - 在循环中运行包含的任务文件

**包含**循环是一个强大的概念，但它确实引入了一个问题。如果包含的文件中有其自己循环的任务，会产生`item`变量的冲突，导致意外的结果。因此，在 Ansible 的 2.1 版本中添加了`loop_control`功能。除其他功能外，此功能提供了一种方法来命名用于循环的变量，而不是默认的`item`。使用这个功能，我们可以区分`include`语句外部的`item`实例和`include`语句内部使用的任何`item`变量。为了演示这一点，我们将在我们的外部`include`语句中添加一个`loop_var`循环控制，如下所示：

```
---
- name: task inclusion
  hosts: localhost
  gather_facts: false
  tasks:
    - ansible.builtin.include: more-tasks.yaml
      loop:
        - one
        - two
      loop_control:
        loop_var: include_item
```

在`more-tasks.yaml`中，我们将有一个带有自己循环的任务，使用`include_item`和本地的`item`变量，如下所示：

```
--- 
- name: included task 1 
  ansible.builtin.debug: 
    msg: "I combine {{ item }} and {{ include_item }}" 
  loop: 
    - a 
    - b 
```

当执行时，我们看到每次包含循环都会执行`任务 1`两次，并且使用了两个`loop`变量，如下的屏幕截图所示：

![图 8.9 - 在包含的任务文件中运行嵌套循环，避免循环变量名称冲突](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_09.jpg)

图 8.9 - 在包含的任务文件中运行嵌套循环，避免循环变量名称冲突

还有其他循环控制，比如`label`，它将定义在任务输出中显示在屏幕上的`item`值（用于防止大型数据结构在屏幕上混乱），以及`pause`，提供在每个循环之间暂停一定秒数的能力。

## 包括处理程序

**处理程序**本质上是任务。它们是由其他任务的通知触发的一组潜在任务。因此，处理程序任务可以像常规任务一样被包含。`include`运算符在`handlers`块内是合法的。

与任务包含不同，当包含`handler`任务时，无法传递变量数据。但是，可以将条件附加到`handler`包含中，以将条件应用于文件中的每个`handler`任务。

让我们创建一个示例来演示这一点。首先，我们将创建一个总是会改变的任务的 playbook，并包含一个`handler`任务文件，并将条件附加到该包含中。代码如下所示：

```
--- 
- name: touch files 
  hosts: localhost 
  gather_facts: false 

  tasks:
  - name: a task
    ansible.builtin.debug:
      msg: "I am a changing task"
    changed_when: true
    notify: a handler
  handlers:
  - ansible.builtin.include: handlers.yaml
    when: foo | default('true') | bool
```

重要提示

在评估可能在 playbook 外定义的变量时，最好使用`bool`过滤器来确保字符串被正确转换为它们的布尔含义。

接下来，我们将创建一个`handlers.yaml`文件来定义我们的`handler`任务，如下所示：

```
---
- name: a handler
  ansible.builtin.debug:
    msg: "handling a thing"
```

如果我们在不提供任何进一步数据的情况下执行这个 playbook，我们应该看到我们的`handler`任务被触发，如下面的截图所示：

![图 8.10 - 使用包含运算符从任务文件运行处理程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_10.jpg)

图 8.10 - 使用包含运算符从任务文件运行处理程序

现在，让我们再次运行 playbook；这次，我们将在`ansible-playbook`执行参数中将`foo`定义为`extra-var`（覆盖每个其他实例），并将其设置为`false`，如下所示：

```
ansible-playbook -i mastery-hosts includer.yaml -v -e foo=false
```

这次，输出将看起来有些不同，如下面的截图所示：

![图 8.11 - 运行相同的 play，但这次强制 foo 条件变量为 false](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_11.jpg)

图 8.11 - 运行相同的 play，但这次强制 foo 条件变量为 false

由于`foo`评估为`false`，所以在这次运行 playbook 时我们的包含处理程序被跳过了。

## 包含变量

**变量**数据也可以分开成可加载的文件。这允许在多个 play 或 playbook 之间共享变量，或者包含项目目录之外的变量数据（如秘密数据）。变量文件是简单的**YAML 格式**文件，提供键和值。与任务包含文件不同，变量包含文件不能包含更多文件。

变量可以通过三种不同的方式包含：通过`vars_files`，通过`include_vars`，或通过`--extra-vars`(`-e`)。

### vars_files

`vars_files`键是一个 play 指令。它定义了要从中读取变量数据的文件列表。这些文件在解析 playbook 本身时被读取和解析。与包含任务和处理程序一样，路径是相对于引用文件的文件的。

这是一个从文件加载变量的示例 play：

```
--- 
- name: vars 
  hosts: localhost 
  gather_facts: false 

  vars_files:
  - variables.yaml
  tasks:
  - name: a task
    ansible.builtin.debug:
      msg: "I am a {{ varname }}" 
```

现在，我们需要在与我们的 playbook 相同的目录中创建一个`variables.yaml`文件，如下所示：

```
---
varname: derp 
```

使用我们通常的命令运行 playbook 将显示`varname`变量值正确地从`variables.yaml`文件中获取，如下面的截图所示：

![图 8.12 - 使用 vars_files 指令在 play 中包含变量](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_12.jpg)

图 8.12 - 使用 vars_files 指令在 play 中包含变量

当然，这只是一个非常简单的例子，但它清楚地演示了从单独文件导入变量的简易性。

### 动态 vars_files 包含

在某些情况下，希望参数化要加载的变量文件。可以通过使用变量作为文件名的一部分来实现这一点；然而，变量必须在解析 playbook 时有一个定义的值，就像在任务名称中使用变量时一样。让我们根据执行时提供的数据更新我们的示例 play，以加载基于数据提供的变量文件，如下所示：

```
--- 
- name: vars 
  hosts: localhost 
  gather_facts: false 

  vars_files:
  - "{{ varfile }}"
  tasks:
  - name: a task
    ansible.builtin.debug:
      msg: "I am a {{ varname }}"
```

现在，当我们执行 playbook 时，我们将使用类似以下命令的`-e`参数为`varfile`提供值：

```
ansible-playbook -i mastery-hosts includer.yaml -v -e varfile=variables.yaml
```

输出应该如下所示：

![图 8.13 - 在 playbook 运行时动态加载 variables.yaml 文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_13.jpg)

图 8.13 - 在 playbook 运行时动态加载 variables.yaml 文件

除了需要在执行时定义变量值之外，要加载的文件也必须在执行时存在。即使文件是由 Ansible playbook 自己生成的，这条规则也适用。假设一个 Ansible playbook 由四个 play 组成。第一个 play 生成一个 YAML 变量文件。然后，在更下面，第四个 play 在`vars_file`指令中引用这个文件。尽管最初看起来这似乎会起作用，但是文件在执行时（即首次运行`ansible-playbook`时）并不存在，因此会报告错误。

### include_vars

包含从文件中加载变量数据的第二种方法是通过`include_vars`模块。该模块将变量作为`task`操作加载，并将为每个主机执行。与大多数模块不同，此模块在 Ansible 主机上本地执行；因此，所有路径仍然相对于 play 文件本身。由于变量加载是作为任务执行的，因此在执行任务时会评估文件名中的变量。文件名中的变量数据可以是特定于主机的，并在前面的任务中定义。此外，文件本身在执行时不必存在；它也可以由前面的任务生成。如果使用正确，这是一个非常强大和灵活的概念，可以导致非常动态的 playbook。

在我们继续之前，让我们通过修改现有的 play 来演示`include_vars`的简单用法，将变量文件加载为一个任务，如下所示：

```
--- 
- name: vars 
  hosts: localhost 
  gather_facts: false 

  tasks: 
    - name: load variables 
      ansible.builtin.include_vars: "{{ varfile }}" 

    - name: a task 
      ansible.builtin.debug: 
        msg: "I am a {{ varname }}" 
```

与前面的示例一样，playbook 的执行与之前的示例中保持一致，我们将`varfile`变量的值指定为额外变量。我们的输出与以前的迭代略有不同，如下面的截图所示：

![图 8.14 - 运行使用 include_vars 语句的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_14.jpg)

图 8.14 - 运行使用 include_vars 语句的 playbook

与其他任务一样，可以循环执行以在单个任务中加载多个文件。当使用特殊的`with_first_found`循环通过一系列越来越通用的文件名迭代直到找到要加载的文件时，这是特别有效的。

让我们通过更改我们的 play 来演示这一点，使用收集的主机事实来尝试加载特定于分发的变量文件，特定于分发系列，或者最后是默认文件，如下所示：

```
---
- name: vars
  hosts: localhost
  gather_facts: true
  tasks:
  - name: load variables
    ansible.builtin.include_vars: "{{ item }}"
    with_first_found:
      - "{{ ansible_distribution }}.yaml"
      - "{{ ansible_os_family }}.yaml"
      - variables.yaml
  - name: a task
    ansible.builtin.debug:
      msg: "I am a {{ varname }}"
```

执行应该看起来与以前的运行非常相似，只是这次我们将看到一个收集事实的任务，并且在执行中不会传递额外的变量数据。输出应该如下所示：

![图 8.15 - 动态包含在 Ansible play 中找到的第一个有效变量文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_15.jpg)

图 8.15 - 动态包含在 Ansible play 中找到的第一个有效变量文件

我们还可以从输出中看到找到要加载的文件。在这种情况下，`variables.yaml`被加载，因为其他两个文件不存在。这种做法通常用于加载特定于主机的操作系统的变量。可以将各种操作系统的变量写入适当命名的文件中。通过使用由收集事实填充的`ansible_distribution`变量，可以通过`with_first_found`参数加载使用`ansible_distribution`值作为其名称一部分的变量文件。可以在一个不使用任何变量数据的文件中提供一组默认变量作为备用，就像我们在`variables.yaml`文件中所做的那样。

### extra-vars

从文件中加载变量数据的最终方法是使用`--extra-vars`（或`-e`）参数引用文件路径到`ansible-playbook`。通常，此参数期望一组`key=value`数据；但是，如果提供了文件路径并以`@`符号为前缀，Ansible 将读取整个文件以加载变量数据。让我们修改我们之前的一个示例，其中我们使用了`-e`，而不是直接在命令行上定义变量，我们将包含我们已经编写的变量文件，如下所示：

```
--- 
- name: vars 
  hosts: localhost 
  gather_facts: false 

  tasks:
  - name: a task
    ansible.builtin.debug:
      msg: "I am a {{ varname }}" 
```

当我们在`@`符号后提供路径时，该路径是相对于当前工作目录的，而不管 playbook 本身位于何处。让我们执行我们的 playbook 并提供`variables.yaml`的路径，如下所示：

```
ansible-playbook -i mastery-hosts includer.yaml -v -e @variables.yaml
```

输出应该如下所示：

![图 8.16 - 通过额外的变量命令行参数包含 variables.yaml 文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_16.jpg)

图 8.16 - 通过额外的变量命令行参数包含 variables.yaml 文件

在这里，我们可以看到我们的`variables.yaml`文件再次成功包含，但是，正如您从前面的代码中看到的那样，它甚至没有在 playbook 中提到 - 我们能够通过`-e`标志完全加载它。

重要提示

使用`--extra-vars`参数包含变量文件时，文件必须在`ansible-playbook`执行时存在。

在 Ansible 中，变量包含非常强大 - 但是 playbooks 本身呢？在这里，情况有所不同，随着本章的进行，我们将看到如何有效地重用任务和 playbook 代码，从而鼓励使用 Ansible 进行良好的编程实践。

## 包含 playbooks

Playbook 文件可以包含其他整个 playbook 文件。这种结构对于将几个独立的 playbook 绑定成一个更大、更全面的 playbook 非常有用。Playbook 包含比任务包含更为原始。在包含 playbook 时，您不能执行变量替换，也不能应用条件，也不能应用标签。要包含的 playbook 文件必须在执行时存在。

在 Ansible 2.4 之前，可以使用`include`关键字来实现 playbook 包含 - 但是在 Ansible 2.8 中已将其删除，因此不应使用。相反，现在应该使用`ansible.builtin.import_playbook`。这是一个 play 级别的指令 - 不能用作任务。但是，它非常容易使用。让我们定义一个简单的示例来演示这一点。首先，让我们创建一个将被包含的 playbook，名为`includeme.yaml`。以下是要执行此操作的代码：

```
---
- name: include playbook
  hosts: localhost
  gather_facts: false
  tasks:
  - name: an included playbook task
    ansible.builtin.debug:
      msg: "I am in the included playbook"
```

正如您现在无疑已经认识到的那样，这是一个完整的独立 playbook，我们可以使用以下命令单独运行它：

```
ansible-playbook -i mastery-hosts includeme.yaml
```

成功运行将产生如下所示的输出：

![图 8.17 - 首先作为独立 playbook 运行我们的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_17.jpg)

图 8.17 - 首先作为独立 playbook 运行我们的 playbook

但是，我们也可以将其导入到另一个 playbook 中。修改原始的`includer.yaml` playbook，使其如下所示：

```
---
- name: include playbook
  hosts: localhost
  gather_facts: false
  tasks:
  - name: a task
    ansible.builtin.debug:
      msg: "I am in the main playbook"
- name: include a playbook
  ansible.builtin.import_playbook: includeme.yaml
```

然后使用以下命令运行它：

```
ansible-playbook -i mastery-hosts includer.yaml
```

我们可以看到两条调试消息都显示出来，并且导入的 playbook 在初始任务之后运行，这是我们在原始 playbook 中定义的顺序。以下截图显示了这一点：

![图 8.18 - 运行包含第二个 playbook 的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_18.jpg)

图 8.18 - 运行包含第二个 playbook 的 playbook

通过这种方式，非常容易地重用整个 playbooks，而无需将它们重构为角色、任务文件或其他格式。但是，请注意，此功能正在积极开发中，因此建议您始终参考文档，以确保您可以实现所需的结果。

# 角色（结构、默认值和依赖关系）

通过对变量、任务、处理程序和剧本的包含的功能理解，我们可以进一步学习**角色**的更高级主题。角色将 Ansible 代码创建的不同方面结合在一起，提供了一套完全独立的变量、任务、文件、模板和模块的集合，可以在不同的剧本中重复使用。尽管设计上并不受限制，但通常每个角色通常被限制在特定的目的或期望的最终结果上，所有必要的步骤要么在角色本身内，要么通过依赖项（换句话说，进一步的角色本身被指定为角色的依赖项）中。重要的是要注意，角色不是剧本，也没有直接执行角色的方法。角色没有设置适用于哪些主机的设置。顶层剧本是将清单中的主机与应该应用于这些主机的角色绑定在一起的粘合剂。正如我们在*第二章*中所看到的，*从早期 Ansible 版本迁移*，角色也可以是 Ansible 集合的一部分。由于我们已经在早期章节中看过集合的结构，因此在本节中，我们将更深入地关注如何构建角色本身。

## 角色结构

**角色**在**文件系统**上有一个结构化的布局。这个结构存在是为了自动包含任务、处理程序、变量、模块和角色依赖关系。该结构还允许轻松地从角色内的任何位置引用文件和模板。

在*第二章*中，*从早期 Ansible 版本迁移*，我们将看看如何从集合中引用角色。但是，它们不一定要作为集合的一部分使用，假设您在这种情况之外使用角色，它们都位于`roles/`目录下的剧本目录结构的子目录中。当然，这可以通过`roles_path`通用配置键进行配置，但让我们坚持使用默认值。每个角色本身都是一个目录树。角色名称是`roles/`目录中的目录名称。每个角色可以有许多具有特殊含义的子目录，在将角色应用于一组主机时会进行处理。

一个角色可以包含所有这些元素，也可以只包含其中的一个。缺少的元素将被简单地忽略。有些角色只是为项目提供通用处理程序。其他角色存在作为单个依赖点，反过来又依赖于许多其他角色。

### 任务

任务文件是角色的核心部分，如果`roles/<role_name>/tasks/main.yaml`存在，那么该文件中的所有任务（以及它包含的任何其他文件）将被加载到播放中并执行。

### 处理程序

与任务类似，如果存在`roles/<role_name>/handlers/main.yaml`文件，则处理程序将自动从中加载。这些处理程序可以被角色内的任何任务引用，或者被列出该角色为依赖项的任何其他角色内的任务引用。

### 变量

角色中可以定义两种类型的变量。有角色变量，从`roles/<role_name>/vars/main.yaml`加载，还有角色默认值，从`roles/<role_name>/defaults/main.yaml`加载。`vars`和`defaults`之间的区别在于优先顺序。有关顺序的详细描述，请参阅*第一章*，*Ansible 的系统架构和设计*。**角色默认值**是最低优先级的变量。实际上，任何其他变量的定义都将优先于角色默认值。角色默认值可以被视为实际数据的占位符，开发人员可能有兴趣使用站点特定值来定义哪些变量。另一方面，**角色变量**具有更高的优先级。角色变量可以被覆盖，但通常在角色内多次引用相同数据集时使用。如果要使用站点本地值重新定义数据集，则应该将变量列在角色默认值而不是角色变量中。

### 模块和插件

一个角色可以包括自定义模块和插件。虽然我们正在过渡到 Ansible 4.0 及更高版本的阶段，但这仍然受支持，但您无疑已经注意到集合也可以包括自定义**模块**和**插件**。在当前时期，您放置模块和插件的位置将取决于您为其编写角色的目标 Ansible 版本。如果您希望与 2.x 版本保持向后兼容性，那么您应该将模块和插件放入角色目录结构中，如此处所述。如果您只希望与 Ansible 3.0 及更高版本兼容，您可以考虑将它们放入集合中。然而，请注意，随着转向集合，您的插件和模块不太可能被接受到`ansible-core`包中，除非它们提供被认为是核心功能。

（如果在角色中存在）模块从`roles/<role_name>/library/`加载，并且可以被角色中的任何任务或者后续的角色使用。重要的是要注意，此路径中提供的模块将覆盖同名模块的任何其他副本，因此尽可能使用 FQCNs 引用模块以避免任何意外结果。

如果在角色的一个以下子目录中找到插件，插件将自动加载：

+   `action_plugins`

+   `lookup_plugins`

+   `callback_plugins`

+   `connection_plugins`

+   `filter_plugins`

+   `strategy_plugins`

+   `cache_plugins`

+   `test_plugins`

+   `shell_plugins`

### 依赖

角色可以表达对另一个角色的**依赖**。一组角色通常都依赖于一个常见的角色，用于任务、处理程序、模块等。这些角色可能只依赖于一次定义。当 Ansible 处理一组主机的角色时，它首先查找`roles/<role_name>/meta/main.yaml`中列出的依赖关系。如果有任何定义，那么这些角色将立即被处理，并且这些角色中包含的任务将被执行（在检查其中列出的任何依赖关系之后）。这个过程会一直持续，直到所有依赖关系都被建立和加载（并在存在的情况下执行任务），然后 Ansible 开始执行初始角色任务。请记住——依赖关系总是在角色本身之前执行。我们将在本章后面更深入地描述角色依赖关系。

### 文件和模板

任务和处理程序模块只能在`roles/<role_name>/files/`中使用相对路径引用文件。文件名可以提供没有任何前缀（尽管如果您愿意，这是允许的），并且将从`roles/<role_name>/files/<relative_directory>/<file_name>`获取。诸如`ansible.builtin.template`、`ansible.builtin.copy`和`ansible.builtin.script`之类的模块是您将看到许多利用这一有用功能的示例的典型模块。

同样，`ansible.builtin.template`模块使用的模板可以在`roles/<role_name>/templates/`中相对引用。以下代码示例使用相对路径从完整路径`roles/<role_name>/templates/herp/derp.j2`加载`derp.j2`模板：

```
- name: configure herp 
  ansible.builtin.template: 
    src: herp/derp.j2 
    dest: /etc/herp/derp.j2 
```

通过这种方式，可以轻松地在标准角色目录结构中组织文件，并且仍然可以轻松地从角色内部访问它们，而无需输入长而复杂的路径。在本章后面，我们将向您介绍`ansible-galaxy role init`命令，该命令将帮助您更轻松地为新角色构建骨架目录结构-有关更多详细信息，请参见*角色共享*部分。

### 将所有内容放在一起

为了说明完整的角色结构可能是什么样子，这里有一个名为`demo`的示例角色：

```
roles/demo 
├── defaults 
|   |--- main.yaml 
|---- files 
|   |--- foo 
|---- handlers 
|   |--- main.yaml 
|---- library 
|   |--- samplemod.py 
|---- meta 
|   |--- main.yaml 
|---- tasks 
|   |--- main.yaml 
|---- templates 
|   |--- bar.j2 
|--- vars 
    |--- main.yaml 
```

创建角色时，并不是每个目录或文件都是必需的。只有存在的文件才会被处理。因此，我们的角色示例不需要或使用处理程序；整个树的`handlers`部分可以简单地被省略。

## 角色依赖

如前所述，角色可以依赖于其他角色。这些关系称为依赖关系，并且它们在角色的`meta/main.yaml`文件中描述。该文件期望具有`dependencies`键的顶级数据哈希；其中的数据是角色列表。您可以在以下代码片段中看到这一点的说明： 

```
--- 
dependencies: 
  - role: common 
  - role: apache 
```

在这个例子中，Ansible 将在继续`apache`角色并最终开始角色任务之前，首先完全处理`common`角色（及其可能表达的任何依赖关系）。

如果依赖项存在于相同的目录结构中或位于配置的`roles_path`配置键中，则可以通过名称引用依赖项而无需任何前缀。否则，可以使用完整路径来定位角色，如下所示：

```
role: /opt/ansible/site-roles/apache 
```

在表达依赖关系时，可以将数据传递给依赖项。数据可以是变量、标签，甚至是条件。

### 角色依赖变量

在列出依赖项时传递的变量将覆盖`defaults/main.yaml`或`vars/main.yaml`中定义的匹配变量的值。这对于使用常见角色（例如`apache`角色）作为依赖项并提供特定于站点的数据（例如在防火墙中打开哪些端口或启用哪些`apache`模块）非常有用。变量表示为角色列表的附加键。因此，继续我们的假设示例，考虑到我们需要将一些变量传递给我们讨论的`common`和`apache`角色依赖项，如下所示：

```
--- 
dependencies: 
  - role: common 
    simple_var_a: True 
    simple_var_b: False 
  - role: apache 
    complex_var: 
      key1: value1 
      key2: value2 
    short_list: 
      - 8080 
      - 8081 
```

在提供依赖变量数据时，有两个名称被保留，不应该用作角色变量：`tags`和`when`。前者用于将标签数据传递到角色中，后者用于将条件传递到角色中。

### 标签

标签可以应用于依赖角色中找到的所有任务。这与标签应用于包含的任务文件的方式相同，如本章前面所述。语法很简单：`tags`键可以是单个项目或列表。为了演示，让我们通过添加一些标签来进一步扩展我们的理论示例，如下所示：

```
--- 
dependencies: 
  - role: common 
    simple_var_a: True 
    simple_var_b: False 
    tags: common_demo 
  - role: apache 
    complex_var: 
      key1: value1 
      key2: value2 
    short_list: 
      - 8080 
      - 8081 
    tags: 
      - apache_demo 
      - 8080 
      - 8181 
```

与向包含的任务文件添加标签一样，所有在依赖中找到的任务（以及该层次结构中的任何依赖）都将获得提供的标签。

### 角色依赖条件

虽然不可能通过条件来阻止依赖角色的处理，但可以通过将条件应用到依赖项来跳过依赖角色层次结构中的所有任务。这也反映了使用条件的任务包含的功能。`when`关键字用于表达条件。我们将再次通过添加一个依赖项来扩展我们的示例，以演示语法，如下所示：

```
--- 
dependencies: 
  - role: common 
    simple_var_a: True 
    simple_var_b: False 
    tags: common_demo 
  - role: apache 
    complex_var: 
      key1: value1 
      key2: value2 
    short_list: 
      - 8080 
      - 8081 
    tags: 
      - apache_demo 
      - 8080 
      - 8181 
    when: backend_server == 'apache' 
```

在这个例子中，`apache`角色将始终被处理，但角色内的任务只有在`backend_server`变量包含`apache`字符串时才会运行。

## 角色应用

角色不是剧本。它们不会对角色任务应该在哪些主机上运行、使用哪种连接方法、是否按顺序操作或者在*第一章*中描述的任何其他剧本行为方面持有任何意见。角色必须在剧本中的一个剧本中应用，所有这些意见都可以在其中表达。

在播放中应用角色时，使用`roles`操作符。该操作符期望应用到播放中的主机的角色列表。与描述角色依赖关系类似，当描述要应用的角色时，可以传递数据，例如变量、标签和条件。语法完全相同。

为了演示在播放中应用角色，让我们创建一个简单的角色并将其应用到一个简单的剧本中。首先，让我们构建一个名为`simple`的角色，它将在`roles/simple/tasks/main.yaml`中具有一个单独的`debug`任务，打印在`roles/simple/defaults/main.yaml`中定义的角色默认变量的值。首先，让我们创建一个任务文件（在`tasks/`子目录中），如下所示：

```
--- 
- name: print a variable 
  ansible.builtin.debug: 
    var: derp 
```

接下来，我们将编写我们的默认文件，其中包含一个变量`derp`，如下所示：

```
--- 
derp: herp 
```

要执行此角色，我们将编写一个播放以应用该角色。我们将称我们的剧本为`roleplay.yaml`，它将与`roles/`目录处于相同的目录级别。代码如下所示：

```
--- 
- hosts: localhost 
  gather_facts: false 

  roles: 
  - role: simple 
```

重要提示

如果没有为角色提供数据，可以使用另一种语法，只列出要应用的角色，而不是哈希。但为了保持一致，我觉得最好在项目中始终使用相同的语法。

我们将重用之前章节中的`mastery-hosts`清单，并以正常方式执行这本手册（这里我们不需要任何额外的冗长），通过运行以下命令：

```
ansible-playbook -i mastery-hosts roleplay.yaml
```

输出应该看起来像这样：

![图 8.19 - 从剧本中运行我们的简单角色，使用默认角色变量数据](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_19.jpg)

图 8.19 - 从剧本中运行我们的简单角色，使用默认角色变量数据

由于角色的魔力，`derp`变量值会自动从角色默认值中加载。当应用角色时，当然可以覆盖默认值。让我们修改我们的剧本，并为`derp`提供一个新值，如下所示：

```
--- 
- hosts: localhost 
  gather_facts: false 

  roles: 
  - role: simple 
    derp: newval 
```

这次，当我们执行（使用与之前相同的命令），我们将看到`newval`作为`derp`的值，如下截图所示：

![图 8.20 - 从剧本中运行相同的角色，但这次在播放级别覆盖默认变量数据](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_20.jpg)

图 8.20 - 运行相同的角色，但这次在播放级别覆盖默认变量数据

可以在一个播放中应用多个角色。`roles:`关键字期望一个列表值。只需添加更多角色以应用更多角色，如下所示（下一个示例是理论的，留给你作为练习）：

```
--- 
- hosts: localhost 
  gather_facts: false 

  roles: 
  - role: simple 
    derp: newval 
  - role: second_role 
    othervar: value 
  - role: third_role 
  - role: another_role 
```

这本手册将加载四个角色——`simple`、`second_role`、`third_role`和`another_role`——并且每个角色将按照它们列出的顺序执行。

### 混合角色和任务

使用角色的 play 不仅限于角色。这些 play 可以有自己的任务，以及两个其他任务块：`pre_tasks`和`post_tasks`块。与本书中一直关注的任务执行顺序不同，这些任务的执行顺序不取决于这些部分在 play 中列出的顺序，而是在 play 内部块执行中有严格的顺序。有关 playbook 操作顺序的详细信息，请参见*第一章*，*Ansible 的系统架构和设计*。

play 的处理程序在多个点被刷新。如果有`pre_tasks`块，则在执行所有`pre_tasks`块后刷新处理程序。然后执行角色和任务块（首先是角色，然后是任务，不管它们在 playbook 中的书写顺序如何），之后处理程序将再次被刷新。最后，如果存在`post_tasks`块，则在执行所有`post_tasks`块后再次刷新处理程序。当然，可以随时使用`meta: flush_handlers`调用刷新处理程序。让我们扩展我们的`roleplay.yaml`文件，以演示处理程序可以被触发的所有不同时间，如下所示：

```
---
- hosts: localhost
  gather_facts: false
  pre_tasks:
  - name: pretask
    ansible.builtin.debug:
      msg: "a pre task"
    changed_when: true
    notify: say hi
  roles:
  - role: simple
    derp: newval
  tasks:
  - name: task
    ansible.builtin.debug:
      msg: "a task"
    changed_when: true
    notify: say hi

  post_tasks:
  - name: posttask
    ansible.builtin.debug:
      msg: "a post task"
    changed_when: true
    notify: say hi
  handlers:
  - name: say hi
    ansible.builtin.debug:
      msg: "hi"
```

我们还将修改我们简单角色的任务，以通知`say hi`处理程序，如下所示：

```
--- 
- name: print a variable 
  ansible.builtin.debug:     
    var: derp 
  changed_when: true 
  notify: say hi 
```

重要提示

这仅在调用`simple`角色的 play 中定义了`say hi`处理程序才有效。如果处理程序未定义，将会出现错误。最佳实践是只通知存在于相同角色或任何标记为依赖项的角色中的处理程序。

再次运行我们的 playbook，使用与之前示例中相同的命令，应该会导致`say hi`处理程序被调用三次：一次用于`pre_tasks`块，一次用于角色和任务，一次用于`post_tasks`块，如下面的屏幕截图所示：

![图 8.21 - 运行 playbook 以演示混合角色和任务以及处理程序执行](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_21.jpg)

图 8.21 - 运行 playbook 以演示混合角色和任务以及处理程序执行

`pre_tasks`、`roles`、`tasks`和`post_tasks`块的书写顺序不会影响这些部分执行的顺序，但最佳实践是按照它们将被执行的顺序进行书写。这是一个视觉提示，有助于记住顺序，并在以后阅读 playbook 时避免混淆。

### 角色包含和导入

在 Ansible 2.2 版本中，新的`ansible.builtin.include_role`动作插件作为技术预览可用。然后，在**Ansible 2.4**版本中，通过添加`ansible.builtin.import_role`插件进一步开发了这个概念。为了简洁起见，我们将不使用它们的 FQCNs 来引用这些插件。

这些插件用于在任务中包含和执行整个角色。两者之间的区别微妙但重要——`include_role`插件被认为是动态的，这意味着在遇到引用它的任务时，代码会在运行时进行处理。

另一方面，`import_role`插件被认为是静态的，这意味着所有导入都在解析 playbook 时进行预处理。这对于在 playbooks 中的使用有各种影响，例如，`import_role`不能在循环中使用，而`include_role`可以。

重要提示

有关导入和包含之间权衡的详细信息可以在官方 Ansible 文档中找到：[`docs.ansible.com/ansible/latest/user_guide/playbooks_reuse.html`](https://docs.ansible.com/ansible/latest/user_guide/playbooks_reuse.html)。

在本书的上一版中，这些插件被视为技术预览，但现在它们已经成为`ansible.builtin`集合的一部分，因此现在可以认为它们是稳定的，并且可以根据需要用于您的代码。

## 角色共享

使用角色的一个优势是能够在不同的 play、playbook、整个项目空间甚至不同的组织之间共享角色。角色被设计为自包含的（或者清楚地引用依赖角色），以便它们可以存在于应用角色的 playbook 所在的项目空间之外。角色可以安装在 Ansible 主机上的共享路径上，也可以通过源代码控制进行分发。

### Ansible Galaxy

**Ansible Galaxy**（[`galaxy.ansible.com/`](https://galaxy.ansible.com/)），正如我们在*第二章*中讨论的那样，*从早期的 Ansible 版本迁移*，是一个用于查找和共享 Ansible 角色和集合的社区中心。任何人都可以访问该网站浏览这些角色和评论；此外，创建登录的用户可以对他们测试过的角色进行评论。可以使用`ansible-galaxy`工具提供的实用程序下载 Galaxy 中的角色。

`ansible-galaxy`实用程序可以连接到 Ansible Galaxy 网站并安装角色。该实用程序默认将角色安装到`/etc/ansible/roles`中。如果配置了`roles_path`，或者使用`--roles-path`（或`-p`）选项提供了运行时路径，角色将安装到那里。如果已经将角色安装到`roles_path`选项或提供的路径中，`ansible-galaxy`也可以列出这些角色并显示有关这些角色的信息。为了演示`ansible-galaxy`的用法，让我们使用它将一个用于在 Ubuntu 上安装和管理 Docker 的角色从 Ansible Galaxy 安装到我们一直在使用的`roles`目录中。从 Ansible Galaxy 安装角色需要`username.rolename`，因为多个用户可能上传了具有相同名称的角色。为了演示，我们将使用`angstwad`用户的`docker_ubuntu`角色，如下面的截图所示：

![图 8.22 - 在 Ansible Galaxy 上找到一个示例社区贡献的角色](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_22.jpg)

图 8.22 - 在 Ansible Galaxy 上找到一个示例社区贡献的角色

现在我们可以通过在 play 或其他角色的依赖块中引用`angstwad.docker_ubuntu`来使用这个角色。然而，让我们首先演示如何在当前工作目录中安装这个角色。我们首先创建一个`roles/`目录，然后使用以下命令将上述角色安装到这个目录中：

```
mkdir roles/
ansible-galaxy role install -p roles/ angstwad.docker_ubuntu
```

一旦我们安装了示例角色，我们可以使用以下命令查询它（以及可能存在于`roles/`目录中的任何其他角色）：

```
ansible-galaxy role list -p roles/
```

你还可以使用以下命令在本地查询有关角色的描述、创建者、版本等信息：

```
ansible-galaxy role info -p roles/ angstwad.docker_ubuntu
```

以下截图给出了你可以从前面两个命令中期望的输出类型：

![图 8.23 - 使用 ansible-galaxy 命令查询已安装的角色](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_23.jpg)

图 8.23 - 使用 ansible-galaxy 命令查询已安装的角色

输出已经被截断以节省书中的空间，如果你浏览输出，会发现更多有用的信息。`info`命令显示的一些数据存在于角色本身，在`meta/main.yml`文件中。以前，我们只在这个文件中看到了依赖信息，也许给目录命名为`meta`并没有太多意义，但现在我们看到这个文件中还有其他元数据，如下面的截图所示：

![图 8.24 - 可以放置在角色的 meta/main.yml 文件中的元数据的示例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_24.jpg)

图 8.24 - 可以放置在角色的 meta/main.yml 文件中的元数据的示例

`ansible-galaxy`工具还可以帮助创建新的角色。`role init`方法将为角色创建一个骨架目录树，并在`meta/main.yml`文件中填充与 Galaxy 相关数据的占位符。

让我们通过使用这个命令在我们的工作目录中创建一个名为`autogen`的新角色来演示这种能力：

```
ansible-galaxy role init --init-path roles/ autogen
```

如果你检查这个命令创建的目录结构，你会看到创建全新角色所需的所有目录和占位符文件，如下面的截图所示：

![图 8.25 - 使用 ansible-galaxy 工具创建一个空的骨架角色](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_08_25.jpg)

图 8.25 - 使用 ansible-galaxy 工具创建一个空的骨架角色

请注意，在过去用于指定本地`roles/`目录的`-p`开关，现在必须改用`init`命令的`--init-path`开关。对于不适合 Ansible Galaxy 的角色，例如处理内部系统的角色，`ansible-galaxy`可以直接从 Git **Uniform Resource Locator** (**URL**)安装。不仅可以提供一个角色名称给`install`方法，还可以提供一个带有可选版本的完整 Git URL。例如，如果我们想要从内部 Git 服务器安装`foowhiz`角色，我们可以简单地运行以下命令：

```
ansible-galaxy role install -p /opt/ansible/roles git+git@git.internal.site:ansible-roles/foowhiz
```

没有版本信息时，将使用`master`分支。没有名称数据时，名称将根据 URL 本身确定。要提供版本，请附加一个逗号和 Git 可以理解的版本字符串，例如标签或分支名称，例如`v1`，如下所示：

```
ansible-galaxy role install -p /opt/ansible/roles git+git@git.internal.site:ansible-roles/foowhiz,v1
```

可以在另一个逗号后面添加一个角色名称，如下面的代码片段所示。如果需要提供名称但不希望提供版本，则仍然需要为版本留出一个空位：

```
ansible-galaxy role install -p /opt/ansible/roles git+git@git.internal.site:ansible-roles/foowhiz,,foo-whiz-common
```

角色也可以直接从 tarballs 安装，只需提供 tarball 的 URL，而不是完整的 Git URL 或要从 Ansible Galaxy 获取的角色名称。

当你需要为一个项目安装许多角色时，可以在以`.yaml`（或`.yml`）结尾的 YAML 格式文件中定义要下载和安装的多个角色。该文件的格式允许你从多个来源指定多个角色，并保留指定版本和角色名称的能力。此外，还可以列出源代码控制方法（目前仅支持`git`和`hg`）。你可以在以下代码片段中看到一个例子：

```
--- 
- src: <name or url> 
  version: <optional version> 
  name: <optional name override> 
  scm: <optional defined source control mechanism, defaults to git>
```

要安装文件中的所有角色，请使用`role install`方法的`--roles-file`（`-r`）选项，如下所示：

```
ansible-galaxy role install -r foowhiz-reqs.yaml
```

通过这种方式，非常容易在运行 playbooks 之前收集所有角色的依赖关系，无论你需要的角色是在 Ansible Galaxy 上公开可用，还是保存在你自己的内部源代码管理系统中，这一简单步骤都可以大大加快 playbook 的部署速度，同时支持代码重用。

# 总结

Ansible 提供了将内容逻辑地分成单独文件的能力。这种能力帮助项目开发人员不再重复相同的代码。Ansible 中的角色进一步利用了这种能力，并在内容的路径周围包装了一些魔法。角色是可调整的、可重用的、可移植的和可共享的功能块。Ansible Galaxy 作为开发人员的社区中心存在，可以在其中找到、评价和共享角色和集合。`ansible-galaxy`命令行工具提供了一种与 Ansible Galaxy 站点或其他角色共享机制进行交互的方法。这些能力和工具有助于组织和利用常见代码。

在本章中，您学习了与任务、处理程序、变量甚至整个 playbooks 相关的包含概念。然后，您通过学习角色的结构、设置默认变量值和处理角色依赖关系来扩展了这些知识。然后，您继续学习了设计 playbooks 以有效利用角色，并应用了角色缺乏的标签等选项。最后，您学习了如何使用 Git 和 Ansible Galaxy 等存储库在项目之间共享角色。

在下一章中，我们将介绍有用且有效的故障排除技术，以帮助您在 Ansible 部署遇到问题时解决问题。

# 问题

1.  在运行 playbook 时，可以使用哪个 Ansible 模块来运行来自单独外部任务文件的任务？

a) `ansible.builtin.import`

b) `ansible.builtin.include`

c) `ansible.builtin.tasks_file`

d) `ansible.builtin.with_tasks`

1.  变量数据可以在调用外部任务文件时传递：

a) True

b) False

1.  包含当前循环值的变量的默认名称是：

a) `i`

b) `loop_var`

c) `loop_value`

d) `item`

1.  在循环外部任务文件时，重要的是考虑设置哪个特殊变量以防止循环变量名称冲突？

a) `loop_name`

b) `loop_item`

c) `loop_var`

d) `item`

1.  处理程序通常运行：

a) 一次，在剧终

b) 每次，在`pre_tasks`，`roles/tasks`和`post_tasks`部分的最后

c) 每次，在`pre_tasks`，`roles/tasks`和`post_tasks`部分的最后，只有在通知时

d) 每次，在`pre_tasks`，`roles/tasks`和`post_tasks`部分的最后，只有在导入时

1.  Ansible 可以从以下外部来源加载变量：

a) 静态`vars_files`包含

b) 动态`vars_files`包含

c) 通过`include_vars`语句

d) 通过`extra-vars`命令行参数

e) 以上所有

1.  角色从角色目录名称中获取其名称（例如，`roles/testrole1`的名称为`testrole1`）：

a) True

b) False

1.  如果一个角色缺少`tasks/main.yml`文件，Ansible 将会：

a) 用错误中止播放

b) 完全跳过角色

c) 仍然引用角色的任何其他有效部分，包括元数据，默认变量和处理程序

d) 显示警告

1.  角色可以依赖于其他角色：

a) True

b) False

1.  当您为角色指定标签时，Ansible 的行为是：

a) 将标签应用于整个角色

b) 将标签应用于角色内的每个任务

c) 完全跳过角色

d) 仅执行具有相同标签的角色的任务


# 第九章：故障排除 Ansible

Ansible 简单而强大。Ansible 的简单意味着它的操作易于理解和遵循。然而，即使是最简单和最用户友好的系统，有时也会出现问题——也许是因为我们正在学习编写自己的代码（playbooks、roles、modules 或其他）并需要调试它，或者更少见的是，当我们可能在已发布版本的集合或 `ansible-core` 中发现了错误时。

在调试意外行为时，能够理解和遵循 Ansible 的操作至关重要。Ansible 提供了许多选项和工具，帮助您调试其核心组件的操作，以及您自己的 playbook 代码。我们将在本章中详细探讨这些内容，目标是让您有信心调试自己的 Ansible 工作。

具体来说，在本章中，我们将讨论以下主题：

+   Playbook 日志记录和详细程度

+   变量内省

+   调试代码执行

# 技术要求

要跟随本章中提出的示例，您需要运行 **Ansible 4.3** 或更新版本的 Linux 机器。几乎任何 Linux 版本都可以——对于那些感兴趣的人，本章中提出的所有代码都是在 Ubuntu Server 20.04 **长期支持**（**LTS**）上测试的，除非另有说明，并且在 Ansible 4.3 上测试。本章附带的示例代码可以从 GitHub 下载：[`github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter09`](https://github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter09)。

查看以下视频以查看代码的实际操作：[`bit.ly/2Xx46Ym`](https://bit.ly/2Xx46Ym)

# Playbook 日志记录和详细程度

增加 Ansible 输出的详细程度可以解决许多问题。从无效的模块参数到不正确的连接命令，增加详细程度在准确定位错误源头方面至关重要。在 *第三章* 中简要讨论了 playbook 日志记录和详细程度，关于在执行 playbook 时保护秘密值。本节将更详细地介绍详细程度和日志记录。

## 详细程度

在使用 `ansible-playbook` 执行 playbook 时，输出显示在 **标准输出**（**stdout**）上。在默认详细程度下，几乎没有显示任何信息。当执行 play 时，`ansible-playbook` 将打印一个带有 play 名称的 **play** 标头。然后，对于每个任务，将打印一个带有任务名称的 **task** 标头。当每个主机执行任务时，将显示主机的名称以及任务状态，可以是 `ok`、`fatal` 或 `changed`。不会显示有关任务的进一步信息——例如正在执行的模块、提供给模块的参数或执行的返回数据。虽然这对于已经建立的 playbook 来说是可以的，但我倾向于想要更多关于我的 play 的信息。在本书的早期示例中，我们使用了更高级别的详细程度，最高达到二级 (`-vv`)，以便我们可以看到任务的位置和返回数据。总共有五个详细程度级别，如下所述：

+   **无**：默认级别

+   **一** (`-v`)：显示返回数据和条件信息的位置

+   **二** (`-vv`)：用于任务位置和处理程序通知信息

+   **三** (`-vvv`)：提供连接尝试和任务调用信息的详细信息

+   **四** (`-vvvv`)：将额外的详细选项传递给连接插件（例如将 `-vvv` 传递给 `ssh` 命令）

增加详细程度可以帮助准确定位错误发生的位置，以及提供额外的洞察力，了解 Ansible 如何执行其操作。

正如我们在*第三章*中提到的，*使用 Ansible 保护您的机密信息*，超过一级的冗余度可能会将敏感数据泄露到标准输出和日志文件中，因此在可能共享的环境中增加冗余度时应谨慎使用。

## 日志记录

虽然`ansible-playbook`的默认日志记录到标准输出，但输出量可能大于所使用的终端仿真器的缓冲区；因此，可能需要将所有输出保存到文件中。虽然各种 shell 提供了一些重定向输出的机制，但更优雅的解决方案是将`ansible-playbook`指向日志记录到文件。这可以通过在`ansible.cfg`文件中定义`log_path`或者将`ANSIBLE_LOG_PATH`设置为环境变量来实现。任何一个的值都应该是文件的路径。如果路径不存在，Ansible 将尝试创建一个文件。如果文件已经存在，Ansible 将追加到文件，允许合并多个`ansible-playbook`执行日志。

使用日志文件并不意味着与记录到标准输出互斥。两者可以同时发生，并且所提供的冗余级别对两者都有影响。日志记录当然是有帮助的，但它并不一定告诉我们代码中发生了什么，以及我们的变量可能包含什么。我们将在下一节中看看如何执行变量内省，以帮助您完成这个任务。

# 变量内省

在开发 Ansible playbook 时遇到的常见问题是变量的值的不正确使用或无效假设。当在变量中注册一个任务的结果，然后在另一个任务或模板中使用该变量时，这种情况特别常见。如果没有正确访问结果的所需元素，最终结果将是意外的，甚至可能是有害的。

要排除变量使用不当的问题，检查变量值是关键。检查变量值的最简单方法是使用`ansible.builtin.debug`模块。`ansible.builtin.debug`模块允许在屏幕上显示自由格式的文本，并且与其他任务一样，模块的参数也可以利用 Jinja2 模板语法。让我们通过创建一个执行任务的示例播放来演示这种用法，注册结果，然后使用 Jinja2 语法在`ansible.builtin.debug`语句中显示结果，如下所示：

```
--- 
- name: variable introspection demo
  hosts: localhost
  gather_facts: false   
  tasks:     
- name: do a thing       
  ansible.builtin.uri:         
    url: https://derpops.bike       
    register: derpops     
- name: show derpops       
  ansible.builtin.debug:         
    msg: "derpops value is {{ derpops }}" 
```

我们将使用以下命令以一级冗余度运行此播放：

```
ansible-playbook -i mastery-hosts vintro.yaml -v
```

假设我们正在测试的网站是可访问的，我们将看到`derpops`的显示值，如下面的屏幕截图所示：

![图 9.1 - 使用一级冗余度检查注册变量的值](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_01.jpg)

图 9.1 - 使用一级冗余度检查注册变量的值

`ansible.builtin.debug`模块还有一个不同的选项，可能也很有用。该模块不是将自由格式的字符串打印到调试模板中，而是可以简单地打印任何变量的值。这是通过使用`var`参数而不是`msg`参数来完成的。让我们重复我们的例子，但这次我们将使用`var`参数，并且我们将仅访问`derpops`变量的`server`子元素，如下所示：

```
--- 
- name: variable introspection demo 
  hosts: localhost 
  gather_facts: false 

  tasks: 
    - name: do a thing 
      ansible.builtin.uri: 
        url: https://derpops.bike 
      register: derpops 

    - name: show derpops 
      ansible.builtin.debug: 
        var: derpops.server 
```

使用相同冗余度运行此修改后的播放将只显示`derpops`变量的`server`部分，如下面的屏幕截图所示：

![图 9.2 - 使用调试模块的 var 参数检查变量子元素](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_02.jpg)

图 9.2 - 使用调试模块的 var 参数来检查变量子元素

在我们使用`ansible.builtin.debug`的例子中，需要使用`msg`参数将变量表达为花括号内，但是在使用`var`时不需要。这是因为`msg`期望一个字符串，因此 Ansible 需要通过模板引擎将变量呈现为字符串。然而，`var`期望一个单个未呈现的变量。

## 变量子元素

playbook 中经常出现的一个错误是错误地引用复杂变量的子元素。复杂变量不仅仅是一个字符串，它可以是一个列表或一个哈希表。经常会引用错误的子元素，或者错误地引用元素，期望得到不同的类型。

虽然列表相当容易处理，但哈希表提出了一些独特的挑战。哈希表是一个无序的键-值集合，可能包含不同类型的元素，也可能是嵌套的。一个哈希表可以有一个元素是单个字符串，而另一个元素可以是一个字符串列表，第三个元素可以是另一个哈希表，其中包含更多的元素。知道如何正确访问正确的子元素对于成功至关重要。

例如，让我们稍微修改我们之前的 play。这一次，我们将允许 Ansible 收集事实，然后显示`ansible_python`的值。这是我们需要的代码：

```
--- 
- name: variable introspection demo 
  hosts: localhost 

  tasks: 
    - name: show a complex hash 
      ansible.builtin.debug: 
        var: ansible_python 
```

以一级详细程度运行此代码，您应该看到以下输出：

![图 9.3 – 使用 ansible.builtin.debug 检查 ansible_python 事实子元素](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_03.jpg)

图 9.3 – 使用 ansible.builtin.debug 检查 ansible_python 事实子元素

使用`ansible.builtin.debug`来显示整个复杂变量是学习所有子元素名称的好方法。

这个变量有一些元素是字符串，还有一些元素是字符串列表。让我们访问标志列表中的最后一个项目，如下所示：

```
--- 
- name: variable introspection demo 
  hosts: localhost 

  tasks: 
    - name: show a complex hash 
      ansible.builtin.debug: 
        var: ansible_python.version_info[-1] 
```

输出如下所示：

![图 9.4 – 进一步检查 ansible_python 事实子元素](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_04.jpg)

图 9.4 – 进一步检查 ansible_python 事实子元素

因为`ansible_python.version_info`是一个列表，我们可以使用**列表索引方法**来从列表中选择特定的项目。在这种情况下，`-1`将给我们列表中的最后一个项目。

### 子元素与 Python 对象方法

一个不太常见但令人困惑的坑来自 Jinja2 语法的一个怪癖。在 Ansible playbook 和模板中，复杂变量可以以两种方式引用。第一种样式是通过名称引用基本元素，后跟括号，括号内用引号括起来的子元素。这是**标准下标语法**。例如，要访问`derp`变量的`herp`子元素，我们将使用以下代码：

```
{{ derp['herp'] }} 
```

第二种样式是 Jinja2 提供的一种便利方法，即使用句点来**分隔**元素。这被称为**点表示法**，看起来像这样：

```
{{ derp.herp }} 
```

这些样式的工作方式有微妙的差异，这与 Python 对象和对象方法有关。由于 Jinja2 在本质上是一个 Python 实用程序，Jinja2 中的变量可以访问其本机 Python 方法。字符串变量可以访问 Python 字符串方法，列表可以访问列表方法，字典可以访问字典方法。使用第一种样式时，Jinja2 首先会搜索提供的名称的元素以查找子元素。如果找不到子元素，则 Jinja2 将尝试访问提供的名称的 Python 方法。然而，当使用第二种样式时，顺序是相反的；首先搜索 Python 对象方法，如果找不到，然后搜索子元素。当子元素和方法之间存在名称冲突时，这种差异很重要。想象一个名为`derp`的变量，它是一个复杂的变量。这个变量有一个名为`keys`的子元素。使用每种样式来访问`keys`元素将得到不同的值。让我们构建一个 playbook 来演示这一点，如下所示：

```
--- 
- name: sub-element access styles 
  hosts: localhost 
  gather_facts: false 
  vars: 
    - derp: 
        keys: 
          - c 
          - d 
  tasks: 
    - name: subscript style 
      ansible.builtin.debug: 
        var: derp['keys']  
    - name: dot notation style 
      ansible.builtin.debug: 
        var: derp.keys 
```

在运行这个剧本时，我们可以清楚地看到两种风格之间的区别。第一种风格成功地引用了`keys`子元素，而第二种风格引用了 Python 字典的`keys`方法，如下面的屏幕截图所示：

![图 9.5 - 演示标准下标语法和点符号在名称冲突发生时的区别](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_05.jpg)

图 9.5 - 演示标准下标语法和点符号在名称冲突发生时的区别

通常最好避免使用与 Python 对象方法冲突的子元素名称。但是，如果不可能的话，下一件最好的事情就是意识到子元素引用风格的差异，并选择适当的风格。

当然，变量只是剧本行为的一方面 - 有时，我们需要实际进入调试代码本身，我们将在下一节中仔细研究这一点。

# 调试代码执行

有时，记录和检查变量数据并不足以解决问题。当这种情况发生时，有必要交互式地调试剧本，或者深入研究 Ansible 代码的内部。Ansible 代码有两个主要集：在 Ansible 主机上本地运行的代码，以及在目标主机上远程运行的模块代码。

## 剧本调试

可以通过使用在 Ansible 2.1 中引入的执行策略**调试策略**来交互式地调试剧本。如果一个剧本在遇到错误状态时使用了这个策略，将开始一个交互式调试会话。这个交互式会话可以用于显示变量数据，显示任务参数，更新任务参数，更新变量，重新执行任务，继续执行或退出调试器。

让我们用一个成功的任务，然后是一个出错的任务，最后是一个成功的任务来演示这一点。我们将重用我们一直在使用的剧本，但稍微更新一下，如下面的代码所示：

```
--- 
- name: sub-element access styles 
  hosts: localhost 
  gather_facts: false 
  strategy: debug 

  vars: 
    - derp: 
        keys: 
          - c 
          - d 

  tasks: 
    - name: subscript style 
      ansible.builtin.debug: 
        var: derp['keys'] 

    - name: failing task 
      ansible.builtin.debug: 
        msg: "this is {{ derp['missing'] }}" 

    - name: final task 
      ansible.builtin.debug: 
        msg: "my only friend the end" 
```

执行时，Ansible 将在我们失败的任务中遇到错误，并显示(debug)提示，如下面的屏幕截图所示：

![图 9.6 - Ansible 调试器在执行失败任务时启动（执行策略为 debug）时](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_06.jpg)

图 9.6 - Ansible 调试器在执行失败任务时启动（执行策略为 debug）时

从这个提示中，我们可以使用`p`命令显示任务和任务参数，如下面的屏幕截图所示：

![图 9.7 - 使用 p 命令检查失败剧本任务的详细信息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_07.jpg)

图 9.7 - 使用 p 命令检查失败剧本任务的详细信息

我们还可以即时更改剧本以尝试不同的参数或变量值。让我们定义`derp`变量的缺失键，然后重试执行。所有变量都在顶层`vars`字典中。我们可以使用 Python 语法和`task_vars`命令直接设置变量数据，然后使用`r`命令重试，如下面的屏幕截图所示：

![图 9.8 - 添加先前未定义的变量值并从调试器中重试剧本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_08.jpg)

图 9.8 - 添加先前未定义的变量值并从调试器中重试剧本

调试执行策略是一个方便的工具，可以快速迭代不同的任务参数和变量组合，以找出正确的前进路径。然而，由于错误导致交互式控制台，调试策略不适用于剧本的自动执行，因为控制台上没有人来操作调试器。

重要观点

更改调试器中的数据不会保存更改到后备文件中。始终记得更新剧本文件以反映在调试过程中发现的内容。

## 调试本地代码

本地 Ansible 代码是随 Ansible 一起提供的大部分代码。所有的 playbook、play、role 和 task 解析代码都存储在本地。所有的任务结果处理代码和传输代码都存储在本地。除了传输到远程主机的组装模块代码之外，所有代码都存储在本地。

本地 Ansible 代码仍然可以分为三个主要部分：**清单**，**playbook**和**执行器**。清单代码处理来自主机文件，动态清单脚本或两者组合在目录树中的清单数据的解析。Playbook 代码用于将 playbook **YAML Ain't Markup Language** (**YAML**)代码解析为 Ansible 内的 Python 对象。执行器代码是核心**应用程序编程接口** (**API**)，处理分叉进程，连接到主机，执行模块，处理结果以及大多数其他事情。学习开始调试的一般区域需要实践，但这里描述的一般区域是一个起点。

由于 Ansible 是用 Python 编写的，因此用于调试本地代码执行的工具是`pdb` Python 调试器。这个工具允许我们在 Ansible 代码内部插入断点，并逐行交互式地执行代码。这对于检查 Ansible 在本地代码执行时的内部状态非常有用。许多书籍和网站涵盖了`pdb`的使用方法，可以通过简单的网络搜索找到 Python `pdb`的介绍，因此我们在这里不再重复。如果您正在寻找使用`pdb`的实践介绍，那么在书籍*Django 1.1 Testing and Debugging*，*Karen M. Tracey*，*Packt Publishing*中有许多很好的例子，这将使您能够在 Django（用 Python 编写）中使用`pdb`进行实际调试技术的练习。官方的 Python 文档也提供了大量关于使用调试器的信息。您可以在这里查看：https://docs.python.org/3/library/pdb.html。基本的方法是编辑要调试的源文件，插入新的代码行以创建断点，然后执行代码。代码执行将在创建断点的地方停止，并提供一个提示来探索代码状态。

当然，Ansible 有许多不同的组件，这些组件共同构建了其功能，从清单处理代码到实际的 playbook 执行引擎本身。可以在所有这些地方添加断点和调试，以帮助解决可能遇到的问题，尽管您需要编辑的文件在每种情况下略有不同。我们将在本章的以下小节中详细讨论您可能需要调试的 Ansible 代码的最常见方面。

### 调试清单代码

Inventory 代码处理查找清单来源、读取或执行已发现的文件、将清单数据解析为清单对象，并加载清单的变量数据。要调试 Ansible 如何处理清单，必须在 `inventory/__init__.py` 或 `inventory/` 子目录中的其他文件中添加断点。此目录将位于安装了 Ansible 的本地文件系统上。由于大多数 Ansible 4.0 的安装都是通过 `pip` 进行的，因此您的安装路径将根据诸如是否使用了虚拟环境、是否在用户目录中安装了 Ansible，或者是否使用 `sudo` 来系统范围安装 Ansible 等因素而有很大不同。例如，在我的 Ubuntu 20.04 测试系统上，此文件可能位于 `/usr/local/lib/python3.8/dist-packages/ansible/inventory` 路径下。要帮助您发现 Ansible 的安装位置，只需在命令行中输入 `which ansible`。此命令将显示 Ansible 可执行文件的安装位置，并可能指示 Python 虚拟环境。对于本书来说，Ansible 已经作为 root 用户使用操作系统 Python 发行版进行了安装，Ansible 二进制文件位于 `/usr/local/bin/` 中。

要发现 Ansible Python 代码的路径，只需输入 `python3 -c "import ansible; print(ansible)"`。请注意，就像我一样，您可能已经安装了 Python 2 和 Python 3 —— 如果您不确定 Ansible 运行在哪个版本的 Python 下，您需要执行版本 2 和 3 的二进制文件，以便发现您的模块位置。

在我的系统上，这显示 `<module 'ansible' from '/usr/local/lib/python3.8/dist-packages/ansible/__init__.py'>`，从中我们可以推断出清单子目录位于 `/usr/local/lib/python3.8/dist-packages/ansible/inventory/`。

清单目录在后续版本的 Ansible 中进行了重组，在 4.0 版本中，我们需要查看 `inventory/manager.py`。请注意，此文件来自 `ansible-core` 软件包，而不是依赖于它的 `ansible` 软件包。

在这个文件中，有一个 `Inventory` 类的定义。这是在整个 playbook 运行期间将使用的清单对象，当 `ansible-playbook` 解析为清单来源提供的选项时，它就会被创建。`Inventory` 类的 `__init__` 方法执行所有的清单发现、解析和变量加载。要排除这三个领域的问题，应该在 `__init__()` 方法中添加断点。一个好的起点是在所有类变量都被赋予初始值之后，以及在处理任何数据之前。

在 `ansible-core` 的 2.11.1 版本中，这将是 `inventory/manager.py` 的第 *167* 行，其中调用了 `parse_sources` 函数。

我们可以跳到第 *215* 行的 `parse_sources` 函数定义处插入我们的断点。要插入断点，我们必须首先导入 `pdb` 模块，然后调用 `set_trace()` 函数，如下面的截图所示：

![图 9.9 – 在 ansible-core inventory manager 代码中添加 pdb 断点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_09.jpg)

图 9.9 – 在 ansible-core inventory manager 代码中添加 pdb 断点

要开始调试，保存源文件，然后像平常一样执行 `ansible-playbook`。当达到断点时，执行将停止，并显示 `pdb` 提示，如下面的截图所示：

![图 9.10 – Ansible 在开始为我们的 play 设置清单时达到 pdb 断点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_10.jpg)

图 9.10 – Ansible 在开始为我们的 play 设置清单时达到 pdb 断点

从这里，我们可以发出任意数量的调试器命令，比如 `help` 命令，如下面的截图所示：

![图 9.11 – 演示 pdb 调试器的 help 命令](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_11.jpg)

图 9.11 – 演示 pdb 调试器的帮助命令

`where`和`list`命令可以帮助我们确定我们在堆栈中的位置和代码中的位置，如下面的屏幕截图所示：

![图 9.12 – 演示 where 和 list pdb 命令](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_12.jpg)

图 9.12 – 演示 where 和 list pdb 命令

`where`命令显示我们在`inventory/manager.py`中的`parse_sources()`方法中。下一个框架是相同的文件——`__init__()`函数。在此之前是另一个文件，`playbook.py`文件，该文件中的函数是`run()`。这一行调用`ansible.inventory.InventoryManager`来创建一个清单对象。在此之前是原始文件`ansible-playbook`，调用`cli.run()`。

`list`命令显示我们当前执行点周围的源代码，前后各五行。

从这里，我们可以使用`next`命令逐行引导`pdb`通过函数，如果选择，我们可以使用`step`命令跟踪其他函数调用。我们还可以使用`print`命令打印变量数据以检查值，如下面的屏幕截图所示：

![图 9.13 – 演示打印命令在执行过程中分析变量值](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_13.jpg)

图 9.13 – 演示打印命令在执行过程中分析变量值

我们可以看到`self._sources`变量具有我们的`mastery-hosts`清单文件的完整路径，这是我们为清单数据提供给`ansible-playbook`的字符串。我们可以继续逐步进行或跳转，或者只需使用`continue`命令运行直到下一个断点或代码完成。

### 调试 playbook 代码

Playbook 代码负责加载、解析和执行 playbooks。调试 playbook 处理的主要入口点是通过定位 Ansible 路径找到的，就像我们在*调试清单代码*部分中所做的那样，然后找到`playbook/__init__.py`文件。在这个文件中有`PlayBook`类。调试 playbook 处理的一个很好的起点是大约第*68*行（对于`ansible-core` 2.11.1），尽管这将根据您安装的版本而有所不同。以下屏幕截图显示了相邻的代码，以帮助您找到您版本的正确行：

![图 9.14 – 添加 pdb 调试器以调试 playbook 加载和执行](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_14.jpg)

图 9.14 – 添加 pdb 调试器以调试 playbook 加载和执行

在这里设置断点将允许我们跟踪查找 playbook 文件并解析它。具体来说，通过步入`self._loader.load_from_file()`函数调用，我们将能够跟踪解析过程。

`PlayBook`类的`_load_playbook_data()`函数只是进行初始解析。其他目录中的其他类用于执行 plays 和 tasks。一个特别有趣的目录是`executor/`目录，其中包含用于执行 playbooks、plays 和 tasks 的类文件。`executor/playbook_executor.py`文件中`PlaybookExecutor`类中的`run()`函数将循环遍历 playbook 中的所有 plays 并执行这些 plays，这将依次执行各个 tasks。如果遇到与 play 解析、play 或 task 回调、标签、play 主机选择、串行操作、处理程序运行或其他任何问题相关的问题，这就是要遍历的函数。

### 调试执行器代码

在 Ansible 中，执行器代码是连接清单数据、playbooks、plays、tasks 和连接方法的连接器代码。虽然这些其他代码片段可以分别进行调试，但它们的交互方式可以在执行器代码中进行检查。

执行器类在`executor/`中的各个文件中定义，`PlaybookExecutor`类。这个类处理给定 playbook 中所有 plays 和 tasks 的执行。`__init__()`类创建函数创建一系列占位符属性，并设置一些默认值，而`run()`函数是大部分有趣的地方。

调试通常会将您从一个文件带到另一个文件，跳转到代码库中的其他位置。例如，在`PlaybookExecutor`类的`__init__()`函数中，有一段代码来缓存默认的**Secure Shell**（**SSH**）可执行文件是否支持`ControlPersist`。您可以通过定位`ansible`安装路径中的`executor/playbook_executor.py`文件（就像我们在前面的部分中所做的那样），并查找声明`set_default_transport()`的行来找到它。这在`ansible-core` 2.11.1 中是第 76 行，以便您知道要查找的位置。一旦找到代码中的适当位置，请在此处设置断点，以便您可以跟踪代码，如下面的屏幕截图所示：

![图 9.15-将 Python 调试器插入到 Ansible playbook 执行器代码中](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_15.jpg)

图 9.15-将 Python 调试器插入到 Ansible playbook 执行器代码中

现在我们可以再次运行我们的`objmethod.yml` playbook 以进入调试状态，如下面的屏幕截图所示：

![图 9.16-执行示例 playbook 以触发调试器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_16.jpg)

图 9.16-执行示例 playbook 以触发调试器

我们需要步入函数以跟踪执行。步入函数将带我们到另一个文件，如下所示：

![图 9.17-步入代码以跟踪执行](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_17.jpg)

图 9.17-步入代码以跟踪执行

从这里，我们可以使用`list`来查看我们新文件中的代码，如下面的屏幕截图所示：

![图 9.18-列出调试器中我们当前位置附近的代码](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_18.jpg)

图 9.18-列出调试器中我们当前位置附近的代码

再走几行，我们来到一段代码块，将执行一个`ssh`命令并检查输出以确定`ControlPersist`是否受支持，如下面的屏幕截图所示：

![图 9.19-定位代码以确定是否支持 ControlPersist](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_19.jpg)

图 9.19-定位代码以确定是否支持 ControlPersist

让我们走过接下来的几行，然后打印出`err`的值。这将向我们展示`ssh`执行的结果以及`Ansible`将在其中搜索的整个字符串，如下面的屏幕截图所示：

![图 9.20-使用 pdb 调试器分析 SSH 连接结果](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_20.jpg)

图 9.20-使用 pdb 调试器分析 SSH 连接结果

正如我们所看到的，搜索字符串不在`err`变量中，因此`has_cp`的值仍然保持为`True`的默认值。

有关分叉和调试的快速说明

当`Ansible`使用多进程进行多个分叉时，调试变得困难。调试器可能连接到一个分叉而不是另一个分叉，这将使调试代码变得非常困难。除非专门调试多进程代码，最好还是坚持使用单个分叉。

### 调试远程代码

远程代码是`Ansible`传输到远程主机以执行的代码。这通常是模块代码，或者在动作插件的情况下，是其他代码片段。使用我们在前一节讨论的调试方法来调试模块执行将不起作用，因为`Ansible`只是复制代码然后执行它。远程代码执行没有连接到终端，因此没有办法将其连接到调试提示符，即在不编辑模块代码的情况下是不可能的。

要调试模块代码，我们需要编辑模块代码本身以插入调试器断点。不要直接编辑已安装的模块文件，而是在与 playbooks 相关的`library/`目录中创建文件的副本。这个模块代码的副本将被用来代替已安装的文件，这样就可以在不影响系统上模块的其他用户的情况下临时编辑模块。

与其他 Ansible 代码不同，模块代码不能直接使用`pdb`进行调试，因为模块代码是组装然后传输到远程主机的。幸运的是，有一个解决方案，即一个稍微不同的调试器，名为`rpdb` - 远程 Python 调试器。这个调试器有能力在提供的端口上启动一个监听服务，以允许远程连接到 Python 进程。远程连接到进程将允许逐行调试代码，就像我们对其他 Ansible 代码所做的那样。

为了演示这个调试器是如何工作的，我们首先需要一个远程主机。在这个例子中，我们使用一个名为`debug.example.com`的远程主机（当然，你可以根据需要使用你自己的示例进行相应的调整）。接下来，我们需要一个 playbook 来执行我们想要调试的模块。代码如下所示：

```
---
- name: remote code debug
  hosts: debug.example.com
  gather_facts: false
  become: true
  tasks:
    - name: a remote module execution
      systemd:
        name: nginx
        state: stopped
        enabled: no
```

重要提示

你们中敏锐的人可能已经注意到，在本书中，我们第一次没有使用**完全限定类名**（**FQCN**）来引用模块。这是因为 FQCN 告诉 Ansible 使用它自己期望的位置的内置模块，而我们实际上想要加载我们将放置在本地`library/`目录中的本地副本。因此，在这个特定情况下，我们必须只使用模块的简称。

我们还需要一个新的清单文件来引用我们的新测试主机。由于我没有为这个主机设置**域名系统**（**DNS**）条目，我在清单中使用特殊的`ansible_host`变量，告诉 Ansible 连接到`debug.example.com`上的**互联网协议**（**IP**）地址，如下面的代码片段所示：

```
debug.example.com ansible_host=192.168.81.154
```

重要提示

不要忘记在两个主机之间设置 SSH 身份验证 - 我使用 SSH 密钥，这样我就不需要每次运行`ansible-playbook`时都输入密码。

这个 play 只是调用`ansible.builtin.systemd`模块来确保`nginx`服务被停止，并且不会在启动时启动。正如我们之前所述，我们需要复制服务模块并将其放置在`library/`中。要复制的服务模块的位置将根据 Ansible 的安装方式而变化。在我为本书演示的演示系统上，它位于`/usr/local/lib/python3.8/dist-packages/ansible/modules/systemd.py`。然后，我们可以编辑它以插入我们的断点。我在我的系统上将其插入到第*358*行 - 这对于`ansible-core` 2.11.1 是正确的，但随着新版本的发布可能会发生变化。然而，下面的屏幕截图应该给你一个插入代码的想法：

![图 9.21 - 将远程 Python 调试器插入到 Ansible 模块代码中](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_21.jpg)

图 9.21 - 将远程 Python 调试器插入到 Ansible 模块代码中

我们将在创建`systemctl`变量值之前设置断点。首先，必须导入`rpdb`模块（这意味着远程主机上必须存在`rpdb` Python 库），然后需要使用`set_trace()`创建断点。

重要提示

在 Ubuntu Server 20.04 上（就像演示中使用的主机一样），可以使用以下命令使用`pip`安装`rpdb`：`sudo pip3 install rpdb`。

与常规调试器不同，此函数将打开一个端口并监听外部连接。默认情况下，该函数将在地址`127.0.0.1`上监听端口`4444`的连接。但是，该地址不会在网络上公开，因此在我的示例中，我已经指示`rpdb`在地址`0.0.0.0`上监听，这实际上是主机上的每个地址（尽管我相信您会理解，这会带来您需要小心的安全隐患！）。

重要提示

如果运行`rpdb`的主机有防火墙（例如`firewalld`或`ufw`），则需要为本例中的端口`4444`打开端口。

现在我们可以运行这个 playbook 来设置等待客户端连接的服务器，如下所示：

![图 9.22 - 运行远程模块调试的测试 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_22.jpg)

图 9.22 - 运行远程模块调试的测试 playbook

现在服务器正在运行，我们可以从另一个终端连接到它。可以使用`telnet`程序连接到正在运行的进程，如下面的截图所示：

![图 9.23 - 使用 telnet 连接到远程 Python 调试器会话进行模块调试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_23.jpg)

图 9.23 - 使用 telnet 连接到远程 Python 调试器会话进行模块调试

从这一点开始，我们可以像平常一样进行调试。我们之前使用的命令仍然存在，比如`list`用来显示当前帧在代码中的位置，如下面的截图所示：

![图 9.24 - 在远程调试会话中使用现熟悉的 Python 调试器命令](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_24.jpg)

图 9.24 - 在远程调试会话中使用现熟悉的 Python 调试器命令

使用调试器，我们可以逐步跟踪`systemd`模块，以跟踪它如何确定底层工具的路径，跟踪在主机上执行了哪些命令，确定如何计算更改等。整个文件都可以逐步执行，包括模块可能使用的任何其他外部库，从而允许调试远程主机上的其他非模块代码。

如果调试会话允许模块干净地退出，playbook 的执行将恢复正常。但是，如果在模块完成之前断开调试会话，playbook 将产生错误，如下面的截图所示：

![图 9.25 - 在提前终止远程调试会话时产生错误的示例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_09_25.jpg)

图 9.25 - 在提前终止远程调试会话时产生错误的示例

由于这种副作用，最好不要提前退出调试器，而是在调试完成后发出`continue`命令。

### 调试动作插件

有些模块实际上是动作插件。这些是在将代码传输到远程主机之前在本地执行一些代码的任务。一些示例动作插件包括`copy`、`fetch`、`script`和`template`。这些插件的源代码可以在`plugins/action/`中找到。该目录中的每个插件都有自己的文件，可以在其中插入断点，以便调试执行的代码，而不是将代码发送到远程主机。调试这些通常使用`pdb`来完成，因为大多数代码是在本地执行的。

# 摘要

Ansible 是一款软件，软件会出现故障；这不是一个“如果”，而是一个“何时”的问题。无效的输入、不正确的假设和意外的环境都可能导致任务和操作表现不如预期时产生令人沮丧的情况。内省和调试是可以快速将沮丧转化为喜悦的故障排除技术，当发现根本原因时。

在本章中，我们学习了如何让 Ansible 将其操作记录到文件中，以及如何更改 Ansible 输出的详细程度。然后，我们学习了如何检查变量，以确保它们的值符合您的期望，然后再详细调试 Ansible 代码。此外，我们演示了如何在核心 Ansible 代码中插入断点，并使用标准 Python 工具执行本地和远程 Python 调试会话。

在下一章中，我们将学习如何通过编写自己的模块、插件和清单来源来扩展 Ansible 的功能。

# 问题

1.  要查看连接尝试等详细信息，您需要以哪个详细程度启动 Ansible？

a）级别为 3 或以上

b）级别为 2 或以上

c）级别为 1 或以上

d）级别为 4

1.  如果您在 playbook 中使用敏感数据，为什么应该小心使用高于一级的详细程度？

a）更高的详细程度不支持使用 vaults。

b）更高的详细程度可能会将敏感数据记录到控制台和/或日志文件中。

c）更高的详细程度将打印 SSH 密码。

1.  可以通过集中配置 Ansible 将其输出记录到文件：

a）使用`ANSIBLE_LOG_PATH`环境变量

b）在`ansible.cfg`中使用`log_path`指令

c）将每个 playbook 运行的输出重定向到文件

d）所有这些

1.  用于变量内省的模块的名称是：

a）`ansible.builtin.analyze`

b）`ansible.builtin.introspect`

c）`ansible.builtin.debug`

d）`ansible.builtin.print`

1.  在引用 Ansible 变量中的子元素时，哪种语法最安全，以防止与保留的 Python 名称冲突？

a）点表示法

b）标准下标语法

c）Ansible 子元素表示法

d）标准点表示法

1.  除非您需要执行低级别的代码调试，否则可以使用以下方法调试 playbook 的流程：

a）调试策略

b）调试执行

c）调试任务计划程序

d）这些都不是

1.  在本书中演示的 Python 本地调试器的名称是：

a）`PyDebug`

b）`python-debug`

c）`pdb`

d）`pdebug`

1.  您还可以调试远程主机上模块的执行：

a）使用 Python 的`rpdb`模块。

b）通过将 playbook 复制到主机并使用`pdb`。

c）通过数据包跟踪器，如`tcpdump`。

d）这是不可能的。

1.  除非另有配置，远程 Python 调试器会在哪里接收连接？

a）`127.0.0.1:4433`

b）`0.0.0.0:4444`

c）`127.0.0.1:4444`

d）`0.0.0.0:4433`

1.  为什么不应该在不让代码运行完成的情况下结束远程 Python 调试会话？

a）这会导致在您的 playbook 运行中出现错误。

b）这将导致文件丢失。

c）这可能会损坏您的 Ansible 安装。

d）这将导致挂起的调试会话。
