# Ansible 2 实战（四）

> 原文：[`zh.annas-archive.org/md5/B93AA180F347B680872C5A7851966C2F`](https://zh.annas-archive.org/md5/B93AA180F347B680872C5A7851966C2F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：高级 Ansible 主题

到目前为止，我们已经努力为您提供了 Ansible 的坚实基础，这样无论您想要的自动化任务是什么，您都可以轻松自如地实现它。然而，当您真正开始加速自动化时，您如何确保能够以一种优雅的方式处理任何出现的情况呢？例如，当您必须启动长时间运行的操作时，如何确保您可以异步运行它们，并在稍后可靠地检查结果？或者，如果您正在更新一大群服务器，如何确保如果一小部分服务器出现故障，play 会及早失败？您最不希望做的事情就是在一百台服务器上部署一个有问题的更新（让我们面对现实，每个人的代码都会不时出现问题）——最好的办法是检测到一小部分服务器失败并根据这个基础中止整个 play，而不是试图继续并破坏整个负载均衡集群。

在本章中，我们将看看如何解决这些特定问题，以及使用 Ansible 的一些更高级功能来控制 playbook 流程和错误处理。我们将通过实际示例探讨如何使用 Ansible 执行滚动更新，如何使用代理和跳板主机（这对于安全环境和核心网络配置通常至关重要），以及如何使用本地 Ansible Vault 技术在静态环境中保护敏感的 Ansible 数据。通过本章结束时，您将全面了解如何在小型环境中以及在大型、安全、关键任务的环境中运行 Ansible。

在本章中，我们将涵盖以下主题：

+   异步与同步操作

+   控制滚动更新的 play 执行

+   配置最大失败百分比

+   设置任务执行委托

+   使用`run_once`选项

+   在本地运行 playbooks

+   使用代理和跳板主机

+   配置 playbook 提示

+   在 play 和任务中放置标签

+   使用 Ansible Vault 保护数据

# 技术要求

本章假设您已经按照第一章中详细介绍的方式在控制主机上设置了 Ansible，并且正在使用最新版本。本章的示例是在 Ansible 2.9 版本下测试的。本章还假设您至少有一个额外的主机进行测试，并且最好是基于 Linux 的。虽然本章将给出特定主机名的示例，但您可以自由地用自己的主机名和/或 IP 地址替换它们；如何做到这一点的详细信息将在适当的位置提供。

本章的代码包可以在[`github.com/PacktPublishing/Ansible-2-Cookbook/tree/master/Chapter%208`](https://github.com/PacktPublishing/Ansible-2-Cookbook/tree/master/Chapter%208)上找到。

# 异步与同步操作

到目前为止，我们已经在本书中看到，Ansible play 是按顺序执行的，每个任务在下一个任务开始之前都会完成。虽然这通常有利于流程控制和逻辑顺序，但有时你可能不希望这样。特别是，可能会出现某个任务运行时间长于配置的 SSH 连接超时时间，而 Ansible 在大多数平台上使用 SSH 来执行自动化任务，这可能会成为一个问题。

幸运的是，Ansible 任务可以异步运行，也就是说，任务可以在目标主机上后台运行，并定期轮询。这与同步任务形成对比，同步任务会保持与目标主机的连接，直到任务完成（这会导致超时的风险）。

和往常一样，让我们通过一个实际的例子来探讨这个问题。假设我们在一个简单的 INI 格式清单中有两台服务器：

```
[frontends]
frt01.example.com
frt02.example.com
```

现在，为了模拟一个长时间运行的任务，我们将使用`shell`模块运行`sleep`命令。但是，我们不会让它在`sleep`命令的持续时间内阻塞 SSH 连接，而是会给任务添加两个特殊参数，如下所示：

```
---
- name: Play to demonstrate asynchronous tasks
  hosts: frontends
  become: true

  tasks:
    - name: A simulated long running task
      shell: "sleep 20"
      async: 30
      poll: 5
```

两个新参数是`async`和`poll`。`async`参数告诉 Ansible 这个任务应该异步运行（这样 SSH 连接就不会被阻塞），最多运行`30`秒。如果任务运行时间超过配置的时间，Ansible 会认为任务失败，整个操作也会失败。当`poll`设置为正整数时，Ansible 会以指定的间隔（在这个例子中是每`5`秒）检查异步任务的状态。如果`poll`设置为`0`，那么任务会在后台运行，不会被检查，需要你编写一个任务来手动检查它的状态。

如果你不指定`poll`值，它将被设置为 Ansible 的`DEFAULT_POLL_INTERVAL`配置参数定义的默认值（即`10`秒）。

当你运行这个 playbook 时，你会发现它的运行方式和其他 playbook 一样；从终端输出中，你看不出任何区别。但在幕后，Ansible 会每`5`秒检查任务，直到成功或达到`30`秒的`async`超时值：

```
$ ansible-playbook -i hosts async.yml

PLAY [Play to demonstrate asynchronous tasks] **********************************

TASK [Gathering Facts] *********************************************************
ok: [frt02.example.com]
ok: [frt01.example.com]

TASK [A simulated long running task] *******************************************
changed: [frt02.example.com]
changed: [frt01.example.com]

PLAY RECAP *********************************************************************
frt01.example.com : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

如果你想稍后检查任务（也就是说，如果`poll`设置为`0`），你可以在 playbook 中添加第二个任务，使其如下所示：

```
---
- name: Play to demonstrate asynchronous tasks
  hosts: frontends
  become: true

  tasks:
    - name: A simulated long running task
      shell: "sleep 20"
      async: 30
      poll: 0
      register: long_task

    - name: Check on the asynchronous task
      async_status:
        jid: "{{ long_task.ansible_job_id }}"
      register: async_result
      until: async_result.finished
      retries: 30
```

在这个 playbook 中，初始的异步任务与之前一样定义，只是现在我们将`poll`设置为`0`。我们还选择将这个任务的结果注册到一个名为`long_task`的变量中，这样我们在后面检查时就可以查询任务的作业 ID。play 中的下一个（新的）任务使用`async_status`模块来检查我们从第一个任务中注册的作业 ID，并循环直到作业完成或达到`30`次重试为止。在 playbook 中使用这些时，你几乎肯定不会像这样连续添加两个任务——通常情况下，你会在它们之间执行其他任务，但为了保持这个例子简单，我们将连续运行这两个任务。运行这个 playbook 应该会产生类似以下的输出：

```
$ ansible-playbook -i hosts async2.yml

PLAY [Play to demonstrate asynchronous tasks] **********************************

TASK [Gathering Facts] *********************************************************
ok: [frt01.example.com]
ok: [frt02.example.com]

TASK [A simulated long running task] *******************************************
changed: [frt02.example.com]
changed: [frt01.example.com]

TASK [Check on the asynchronous task] ******************************************
FAILED - RETRYING: Check on the asynchronous task (30 retries left).
FAILED - RETRYING: Check on the asynchronous task (30 retries left).
FAILED - RETRYING: Check on the asynchronous task (29 retries left).
FAILED - RETRYING: Check on the asynchronous task (29 retries left).
FAILED - RETRYING: Check on the asynchronous task (28 retries left).
FAILED - RETRYING: Check on the asynchronous task (28 retries left).
FAILED - RETRYING: Check on the asynchronous task (27 retries left).
FAILED - RETRYING: Check on the asynchronous task (27 retries left).
changed: [frt01.example.com]
changed: [frt02.example.com]

PLAY RECAP *********************************************************************
frt01.example.com : ok=3 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=3 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

在上面的代码块中，我们可以看到长时间运行的任务一直在运行，下一个任务会轮询其状态，直到满足我们设置的条件。在这种情况下，我们可以看到任务成功完成，整个操作结果也是成功的。异步操作对于大型下载、软件包更新和其他可能需要长时间运行的任务特别有用。在你的 playbook 开发中，特别是在更复杂的基础设施中，你可能会发现它们很有用。

有了这个基础，让我们来看看另一个在大型基础设施中可能有用的高级技术——使用 Ansible 进行滚动更新。

# 控制滚动更新的 play 执行

默认情况下，Ansible 会在多个主机上并行执行任务，以加快大型清单中的自动化任务。这个设置由 Ansible 配置文件中的`forks`参数定义，默认值为`5`（因此，默认情况下，Ansible 尝试在五个主机上同时运行自动化任务）。

在负载均衡环境中，这并不理想，特别是如果你想避免停机时间。假设我们的清单中有五个前端服务器（或者甚至更少）。如果我们允许 Ansible 同时更新所有这些服务器，终端用户可能会遇到服务中断。因此，重要的是考虑在不同的时间更新所有服务器。让我们重用上一节中的清单，其中只有两个服务器。显然，如果这些服务器在负载均衡环境中，我们只能一次更新一个；如果同时取出服务，那么终端用户肯定会失去对服务的访问，直到 Ansible play 成功完成。

答案是在 play 定义中使用`serial`关键字来确定一次操作多少个主机。让我们通过一个实际的例子来演示这一点：

1.  创建以下简单的 playbook，在我们的清单中的两个主机上运行两个命令。在这个阶段，命令的内容并不重要，但如果你使用`command`模块运行`date`命令，你将能够看到每个任务运行的时间，以及当你运行 play 时，如果指定了`-v`来增加详细信息：

```
---
- name: Simple serial demonstration play
  hosts: frontends
  gather_facts: false

  tasks:
    - name: First task
      command: date
    - name: Second task
      command: date
```

1.  现在，如果你运行这个 play，你会发现它在每个主机上同时执行所有操作，因为我们的主机数量少于默认的 fork 数量——`5`。这种行为对于 Ansible 来说是正常的，但并不是我们想要的，因为我们的用户将会遇到服务中断：

```
$ ansible-playbook -i hosts serial.yml

PLAY [Simple serial demonstration play] ****************************************

TASK [First task] **************************************************************
changed: [frt02.example.com]
changed: [frt01.example.com]

TASK [Second task] *************************************************************
changed: [frt01.example.com]
changed: [frt02.example.com]

PLAY RECAP *********************************************************************
frt01.example.com : ok=2 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=2 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

1.  现在，让我们修改 play 定义，如下所示。我们将`tasks`部分保持与*步骤 1*中完全相同：

```
---
- name: Simple serial demonstration play
  hosts: frontends
  serial: 1
  gather_facts: false
```

1.  注意`serial: 1`这一行的存在。这告诉 Ansible 在移动到下一个主机之前一次在 1 个主机上完成 play。如果我们再次运行 play，我们可以看到它的运行情况：

```
$ ansible-playbook -i hosts serial.yml

PLAY [Simple serial demonstration play] ****************************************

TASK [First task] **************************************************************
changed: [frt01.example.com]

TASK [Second task] *************************************************************
changed: [frt01.example.com]

PLAY [Simple serial demonstration play] ****************************************

TASK [First task] **************************************************************
changed: [frt02.example.com]

TASK [Second task] *************************************************************
changed: [frt02.example.com]

PLAY RECAP *********************************************************************
frt01.example.com : ok=2 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=2 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

太好了！如果你想象一下，这个 playbook 实际上是在负载均衡器上禁用这些主机，执行升级，然后重新启用负载均衡器上的主机，这正是你希望操作进行的方式。如果没有`serial: 1`指令，所有主机将同时从负载均衡器中移除，导致服务中断。

值得注意的是，`serial`指令也可以取百分比而不是整数。当你指定一个百分比时，你告诉 Ansible 一次在百分之多少的主机上运行 play。所以，如果你的清单中有 4 个主机，并指定`serial: 25%`，Ansible 将一次只在一个主机上运行 play。如果你的清单中有 8 个主机，它将一次在两个主机上运行 play。我相信你明白了！

你甚至可以通过将列表传递给`serial`指令来构建这个。考虑以下代码：

```
  serial:
    - 1
    - 3
    - 5
```

这告诉 Ansible 一开始在 1 个主机上运行 play，然后在接下来的 3 个主机上运行，然后一次在 5 个主机上运行，直到清单完成。你也可以在整数主机数的位置指定一个百分比列表。通过这样做，你将建立一个强大的 playbook，可以执行滚动更新而不会导致终端用户服务中断。完成这一点后，让我们进一步通过控制 Ansible 在中止 play 之前可以容忍的最大失败百分比来增进这一知识，这在高可用或负载平衡环境中将会再次非常有用。

# 配置最大失败百分比

在其默认操作模式下，只要库存中有主机并且没有记录失败，Ansible 就会继续在一批服务器上执行播放（批处理大小由我们在前一节中讨论的`serial`指令确定）。显然，在高可用或负载平衡环境中（如我们之前讨论的环境），这并不理想。如果您的播放中有错误，或者可能存在代码问题，您最不希望的是 Ansible 忠实地将其部署到集群中的所有服务器，导致服务中断，因为所有节点都遭受了失败的升级。在这种环境中，最好的做法是尽早失败，并且在某人能够介入并解决问题之前至少保留一些主机不受影响。

对于我们的实际示例，让我们考虑一个扩展的库存，其中有`10`个主机。我们将定义如下：

```
[frontends]
frt[01:10].example.com
```

现在，让我们创建一个简单的 playbook 在这些主机上运行。我们将在 play 定义中将批处理大小设置为`5`，将`max_fail_percentage`设置为`50%`：

1.  创建以下 play 定义来演示`max_fail_percentage`指令的使用：

```
---
- name: A simple play to demonstrate use of max_fail_percentage
  hosts: frontends
  gather_facts: no
  serial: 5
  max_fail_percentage: 50
```

我们在库存中定义了`10`个主机，因此它将以 5 个一组（由`serial: 5`指定）进行处理。如果一批中超过 50%的主机失败，我们将失败整个播放并停止处理。

失败主机的数量必须超过`max_fail_percentage`的值；如果相等，则播放继续。因此，在我们的示例中，如果我们的主机正好有 50%失败，播放仍将继续。

1.  接下来，我们将定义两个简单的任务。第一个任务下面有一个特殊的子句，我们用它来故意模拟一个失败——这一行以`failed_when`开头，我们用它告诉任务，如果它在批次中的前三个主机上运行此任务，那么无论结果如何，它都应该故意失败此任务；否则，它应该允许任务正常运行：

```
  tasks:
    - name: A task that will sometimes fail
      debug:
        msg: This might fail
      failed_when: inventory_hostname in ansible_play_batch[0:3]
```

1.  最后，我们将添加一个始终成功的第二个任务。如果播放被允许继续，则运行此任务，但如果播放被中止，则不运行：

```
    - name: A task that will succeed
      debug:
        msg: Success!
```

因此，我们故意构建了一个将在 10 个主机库存中以 5 个主机一组的方式运行的 playbook，但是如果任何给定批次中超过 50%的主机经历失败，则播放将中止。我们还故意设置了一个失败条件，导致第一批 5 个主机中的三个（60%）失败。

1.  运行 playbook，让我们观察发生了什么：

```
$ ansible-playbook -i morehosts maxfail.yml

PLAY [A simple play to demonstrate use of max_fail_percentage] *****************

TASK [A task that will sometimes fail] *****************************************
fatal: [frt01.example.com]: FAILED! => {
 "msg": "This might fail"
}
fatal: [frt02.example.com]: FAILED! => {
 "msg": "This might fail"
}
fatal: [frt03.example.com]: FAILED! => {
 "msg": "This might fail"
}
ok: [frt04.example.com] => {
 "msg": "This might fail"
}
ok: [frt05.example.com] => {
 "msg": "This might fail"
}

NO MORE HOSTS LEFT *************************************************************

NO MORE HOSTS LEFT *************************************************************

PLAY RECAP *********************************************************************
frt01.example.com : ok=0 changed=0 unreachable=0 failed=1 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=0 changed=0 unreachable=0 failed=1 skipped=0 rescued=0 ignored=0
frt03.example.com : ok=0 changed=0 unreachable=0 failed=1 skipped=0 rescued=0 ignored=0
frt04.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt05.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

注意此 playbook 的结果。我们故意使前 5 个批次中的三个失败，超过了我们设置的`max_fail_percentage`的阈值。这立即导致播放中止，并且第二个任务不会在前 5 个批次上执行。您还会注意到，10 个主机中的第二批次从未被处理，因此我们的播放确实被中止。这正是您希望看到的行为，以防止失败的更新在整个集群中传播。通过谨慎使用批处理和`max_fail_percentage`，您可以在整个集群上安全运行自动化任务，而不必担心在出现问题时破坏整个集群。在下一节中，我们将介绍 Ansible 的另一个功能，当涉及到与集群一起工作时，这个功能可能非常有用——任务委派。

# 设置任务执行委托

到目前为止，我们运行的每个 play 都假设所有任务都按顺序在库存中的每个主机上执行。但是，如果您需要在不同的主机上运行一个或两个任务怎么办？例如，我们已经谈到了在集群上自动升级的概念。但是从逻辑上讲，我们希望自动化整个过程，包括从负载平衡器中逐个删除每个主机并在任务完成后将其返回。

尽管我们仍然希望在整个清单上运行我们的 play，但我们肯定不希望从这些主机上运行负载均衡器命令。让我们再次通过一个实际示例详细解释这一点。我们将重用本章前面使用的两个简单主机清单：

```
[frontends]
frt01.example.com
frt02.example.com
```

现在，让我们在与我们的 playbook 相同的目录中创建两个简单的 shell 脚本来处理这个问题。这只是示例，因为设置负载均衡器超出了本书的范围。但是，请想象您有一个可以调用的 shell 脚本（或其他可执行文件），可以将主机添加到负载均衡器中并从中删除：

1.  对于我们的示例，让我们创建一个名为`remove_from_loadbalancer.sh`的脚本，其中包含以下内容：

```
#!/bin/sh
echo Removing $1 from load balancer...
```

1.  我们还将创建一个名为`add_to_loadbalancer.sh`的脚本，其中包含以下内容：

```
#!/bin/sh
echo Adding $1 to load balancer...
```

显然，在实际示例中，这些脚本中会有更多的代码！

1.  现在，让我们创建一个 playbook，执行我们在这里概述的逻辑。我们首先创建一个非常简单的 play 定义（您可以自由地尝试`serial`和`max_fail_percentage`指令），以及一个初始任务：

```
---
- name: Play to demonstrate task delegation
  hosts: frontends

  tasks:
    - name: Remove host from the load balancer
      command: ./remove_from_loadbalancer.sh {{ inventory_hostname }}
      args:
        chdir: "{{ playbook_dir }}"
      delegate_to: localhost
```

请注意任务结构——大部分内容对您来说应该很熟悉。我们使用`command`模块调用我们之前创建的脚本，将从要从负载均衡器中移除的清单中的主机名传递给脚本。我们使用`chdir`参数和`playbook_dir`魔术变量告诉 Ansible 脚本要从与 playbook 相同的目录中运行。

这个任务的特殊之处在于`delegate_to`指令，它告诉 Ansible，即使我们正在遍历一个不包含`localhost`的清单，我们也应该在`localhost`上运行此操作（我们没有将脚本复制到远程主机，因此如果我们尝试从那里运行它，它将不会运行）。

1.  之后，我们添加一个任务，其中进行升级工作。这个任务没有`delegate_to`指令，因此实际上是在清单中的远程主机上运行的（这是我们想要的）：

```
    - name: Deploy code to host
      debug:
        msg: Deployment code would go here....
```

1.  最后，我们使用我们之前创建的第二个脚本将主机重新添加到负载均衡器。这个任务几乎与第一个任务相同：

```
    - name: Add host back to the load balancer
      command: ./add_to_loadbalancer.sh {{ inventory_hostname }}
      args:
        chdir: "{{ playbook_dir }}"
      delegate_to: localhost
```

1.  让我们看看这个 playbook 的运行情况：

```
$ ansible-playbook -i hosts delegate.yml

PLAY [Play to demonstrate task delegation] *************************************

TASK [Gathering Facts] *********************************************************
ok: [frt01.example.com]
ok: [frt02.example.com]

TASK [Remove host from the load balancer] **************************************
changed: [frt02.example.com -> localhost]
changed: [frt01.example.com -> localhost]

TASK [Deploy code to host] *****************************************************
ok: [frt01.example.com] => {
 "msg": "Deployment code would go here...."
}
ok: [frt02.example.com] => {
 "msg": "Deployment code would go here...."
}

TASK [Add host back to the load balancer] **************************************
changed: [frt01.example.com -> localhost]
changed: [frt02.example.com -> localhost]

PLAY RECAP *********************************************************************
frt01.example.com : ok=4 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=4 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

请注意，即使 Ansible 正在通过清单（其中不包括`localhost`）工作，与负载均衡器相关的脚本实际上是从`localhost`运行的，而升级任务是直接在远程主机上执行的。当然，这并不是您可以使用任务委派的唯一方式，但这是一个常见的例子，说明了它可以帮助您的一种方式。

事实上，您可以将任何任务委派给`localhost`，甚至是另一个非清单主机。例如，您可以委派一个`rsync`命令给`localhost`，使用类似于前面的任务定义来将文件复制到远程主机。这很有用，因为尽管 Ansible 有一个`copy`模块，但它无法执行`rsync`能够执行的高级递归`copy`和`update`功能。

另外，请注意，您可以选择在您的 playbooks（和 roles）中使用一种速记符号表示`delegate_to`，称为`local_action`。这允许您在单行上指定一个任务，该任务通常会在其下方添加`delegate_to: localhost`来运行。将所有这些内容整合到第二个示例中，我们的 playbook 将如下所示：

```
---
- name: Second task delegation example
  hosts: frontends

  tasks:
  - name: Perform an rsync from localhost to inventory hosts
    local_action: command rsync -a /tmp/ {{ inventory_hostname }}:/tmp/target/
```

上述速记符号等同于以下内容：

```
tasks:
  - name: Perform an rsync from localhost to inventory hosts
    command: rsync -a /tmp/ {{ inventory_hostname }}:/tmp/target/
    delegate_to: localhost
```

如果我们运行这个 playbook，我们可以看到`local_action`确实从`localhost`运行了`rsync`，使我们能够高效地将整个目录树复制到清单中的远程服务器上：

```
$ ansible-playbook -i hosts delegate2.yml

PLAY [Second task delegation example] ******************************************

TASK [Gathering Facts] *********************************************************
ok: [frt02.example.com]
ok: [frt01.example.com]

TASK [Perform an rsync from localhost to inventory hosts] **********************
changed: [frt02.example.com -> localhost]
changed: [frt01.example.com -> localhost]

PLAY RECAP *********************************************************************
frt01.example.com : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

这结束了我们对任务委派的讨论，尽管如前所述，这只是两个常见的例子。我相信您可以想出一些更高级的用例来使用这个功能。让我们继续通过在下一节中查看特殊的`run_once`选项来控制 Ansible 代码的流程。

# 使用`run_once`选项

在处理集群时，有时会遇到一项任务，应该只对整个集群执行一次。例如，你可能想要升级集群数据库的模式，或者发出一个重新配置 Pacemaker 集群的命令，这通常会在一个节点上发出，并由 Pacemaker 复制到所有其他节点。当然，你可以通过一个特殊的只有一个主机的清单来解决这个问题，或者甚至通过编写一个特殊的 play 来引用清单中的一个主机，但这是低效的，并且开始使你的代码变得分散。

相反，你可以像平常一样编写你的代码，但是利用特殊的`run_once`指令来运行你想要在你的清单上只运行一次的任务。例如，让我们重用本章前面定义的包含 10 个主机的清单。现在，让我们继续演示这个选项，如下所示：

1.  按照下面的代码块创建简单的 playbook。我们使用一个 debug 语句来显示一些输出，但在现实生活中，你可以插入你的脚本或命令来执行你的一次性集群功能（例如，升级数据库模式）：

```
---
- name: Play to demonstrate the run_once directive
  hosts: frontends

  tasks:
    - name: Upgrade database schema
      debug:
        msg: Upgrading database schema...
      run_once: true
```

1.  现在，让我们运行这个 playbook，看看会发生什么：

```
$ ansible-playbook -i morehosts runonce.yml

PLAY [Play to demonstrate the run_once directive] ******************************

TASK [Gathering Facts] *********************************************************
ok: [frt02.example.com]
ok: [frt05.example.com]
ok: [frt03.example.com]
ok: [frt01.example.com]
ok: [frt04.example.com]
ok: [frt06.example.com]
ok: [frt08.example.com]
ok: [frt09.example.com]
ok: [frt07.example.com]
ok: [frt10.example.com]

TASK [Upgrade database schema] *************************************************
ok: [frt01.example.com] => {
 "msg": "Upgrading database schema..."
}
---

PLAY RECAP *********************************************************************
frt01.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt03.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt04.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt05.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt06.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt07.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt08.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt09.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt10.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

请注意，正如所期望的那样，尽管 playbook 在所有 10 个主机上运行了（并且确实从所有 10 个主机收集了信息），我们只在一个主机上运行了升级任务。

1.  重要的是要注意，`run_once`选项适用于每批服务器，因此如果我们在我们的 play 定义中添加`serial: 5`（在我们的 10 台服务器清单上以 5 台服务器的两批运行我们的 play），模式升级任务实际上会运行两次！它按照要求运行一次，但是每批服务器运行一次，而不是整个清单运行一次。在处理这个指令时，要注意这个细微差别。

将`serial: 5`添加到你的 play 定义中，并重新运行 playbook。输出应该如下所示：

```
$ ansible-playbook -i morehosts runonce.yml

PLAY [Play to demonstrate the run_once directive] ******************************

TASK [Gathering Facts] *********************************************************
ok: [frt04.example.com]
ok: [frt01.example.com]
ok: [frt02.example.com]
ok: [frt03.example.com]
ok: [frt05.example.com]

TASK [Upgrade database schema] *************************************************
ok: [frt01.example.com] => {
 "msg": "Upgrading database schema..."
}

PLAY [Play to demonstrate the run_once directive] ******************************

TASK [Gathering Facts] *********************************************************
ok: [frt08.example.com]
ok: [frt06.example.com]
ok: [frt07.example.com]
ok: [frt10.example.com]
ok: [frt09.example.com]

TASK [Upgrade database schema] *************************************************
ok: [frt06.example.com] => {
 "msg": "Upgrading database schema..."
}

PLAY RECAP *********************************************************************
frt01.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt03.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt04.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt05.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt06.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt07.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt08.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt09.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt10.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

这就是`run_once`选项设计的工作原理 - 你可以观察到，在前面的输出中，我们的模式升级运行了两次，这可能不是我们想要的！然而，有了这个意识，你应该能够利用这个选项来控制你的 playbook 流程跨集群，并且仍然实现你想要的结果。现在让我们远离与集群相关的 Ansible 任务，来看一下在本地运行 playbook 和在`localhost`上运行 playbook 之间微妙但重要的区别。

# 在本地运行 playbook

重要的是要注意，当我们谈论使用 Ansible 在本地运行 playbook 时，这并不等同于在`localhost`上运行它。如果我们在`localhost`上运行 playbook，Ansible 实际上会建立一个到`localhost`的 SSH 连接（它不区分其行为，也不尝试检测清单中的主机是本地还是远程 - 它只是忠实地尝试连接）。

实际上，我们可以尝试创建一个包含以下内容的`local`清单文件：

```
[local]
localhost
```

现在，如果我们尝试对这个清单运行一个 ad hoc 命令中的`ping`模块，我们会看到以下内容：

```
$ ansible -i localhosts -m ping all --ask-pass
The authenticity of host 'localhost (::1)' can't be established.
ECDSA key fingerprint is SHA256:DUwVxH+45432pSr9qsN8Av4l0KJJ+r5jTo123n3XGvZs.
ECDSA key fingerprint is MD5:78:d1:dc:23:cc:28:51:42:eb:fb:58:49:ab:92:b6:96.
Are you sure you want to continue connecting (yes/no)? yes
SSH password:
localhost | SUCCESS => {
 "ansible_facts": {
 "discovered_interpreter_python": "/usr/bin/python"
 },
 "changed": false,
 "ping": "pong"
}
```

正如你所看到的，Ansible 建立了一个需要主机密钥验证的 SSH 连接，以及我们的 SSH 密码。尽管你可以添加主机密钥（就像我们在前面的代码块中所做的那样），为你的`localhost`添加基于密钥的 SSH 身份验证等等，但有一种更直接的方法来做到这一点。

现在我们可以修改我们的清单，使其如下所示：

```
[local]
localhost ansible_connection=local
```

我们在`localhost`条目中添加了一个特殊的变量 - `ansible_connection`变量 - 它定义了用于连接到这个清单主机的协议。因此，我们告诉它使用直接的本地连接，而不是 SSH 连接（这是默认值）。

应该注意的是，`ansible_connection`变量的这个特殊值实际上覆盖了您在清单中放置的主机名。因此，如果我们将我们的清单更改为如下所示，Ansible 甚至不会尝试连接到名为`frt01.example.com`的远程主机，它将在本地连接到运行 playbook 的机器（不使用 SSH）：

```
[local]
frt01.example.com ansible_connection=local
```

我们可以非常简单地演示这一点。让我们首先检查一下我们本地`/tmp`目录中是否缺少一个测试文件：

```
ls -l /tmp/foo
ls: cannot access /tmp/foo: No such file or directory
```

现在，让我们运行一个临时命令，在我们刚刚定义的新清单中的所有主机上触摸这个文件：

```
$ ansible -i localhosts2 -m file -a "path=/tmp/foo state=touch" all
frt01.example.com | CHANGED => {
 "ansible_facts": {
 "discovered_interpreter_python": "/usr/bin/python"
 },
 "changed": true,
 "dest": "/tmp/foo",
 "gid": 0,
 "group": "root",
 "mode": "0644",
 "owner": "root",
 "size": 0,
 "state": "file",
 "uid": 0
}
```

命令成功运行，现在让我们看看本地机器上是否存在测试文件：

```
$ ls -l /tmp/foo
-rw-r--r-- 1 root root 0 Apr 24 16:28 /tmp/foo
```

是的！因此，临时命令并没有尝试连接到`frt01.example.com`，即使这个主机名在清单中。`ansible_connection=local`的存在意味着这个命令在本地机器上运行，而不使用 SSH。

在本地运行命令而无需设置 SSH 连接、SSH 密钥等，这种能力可能非常有价值，特别是如果您需要在本地机器上快速启动和运行。完成后，让我们看看如何使用 Ansible 处理代理和跳转主机。

# 使用代理和跳转主机

通常，在配置核心网络设备时，这些设备通过代理或跳转主机与主网络隔离。Ansible 非常适合自动化网络设备配置，因为大部分操作都是通过 SSH 执行的：然而，这只在 Ansible 可以安装和从跳转主机操作的情况下才有帮助，或者更好的是可以通过这样的主机操作。

幸运的是，Ansible 确实可以做到这一点。假设您的网络中有两个 Cumulus Networks 交换机（这些基于 Linux 的特殊分发用于交换硬件，非常类似于 Debian）。这两个交换机分别具有`cmls01.example.com`和`cmls02.example.com`的主机名，但都只能从名为`bastion.example.com`的主机访问。

支持我们的`bastion`主机的配置是在清单中进行的，而不是在 playbook 中。我们首先按照正常方式定义一个包含交换机的清单组：

```
[switches]
cmls01.example.com
cmls02.example.com
```

然而，现在我们可以开始变得聪明起来，通过在清单变量中添加一些特殊的 SSH 参数来实现。将以下代码添加到您的清单文件中：

```
[switches:vars]
ansible_ssh_common_args='-o ProxyCommand="ssh -W %h:%p -q bastion.example.com"'
```

这个特殊的变量内容告诉 Ansible 在设置 SSH 连接时添加额外的选项，包括通过`bastion.example.com`主机进行代理。`-W %h:%p`选项告诉 SSH 代理连接，并连接到由`%h`指定的主机（这通常是`cmls01.example.com`或`cmls02.example.com`），在由`%p`指定的端口上（通常是端口`22`）。

现在，如果我们尝试对这个清单运行 Ansible 的`ping`模块，我们可以看到它是否有效：

```
$ ansible -i switches -m ping all
cmls02.example.com | SUCCESS => {
 "ansible_facts": {
 "discovered_interpreter_python": "/usr/bin/python"
 },
 "changed": false,
127.0.0.1 app02.example.com
 "ping": "pong"
}
cmls01.example.com | SUCCESS => {
 "ansible_facts": {
 "discovered_interpreter_python": "/usr/bin/python"
 },
 "changed": false,
 "ping": "pong"
}
```

您会注意到，我们实际上无法在命令行输出中看到 Ansible 行为上的任何差异。表面上，Ansible 的工作方式与平常一样，并且成功连接到了两个主机。然而，在幕后，它通过`bastion.example.com`进行代理。

请注意，这个简单的例子假设您使用相同的用户名和 SSH 凭据（或在这种情况下，密钥）连接到`bastion`主机和`switches`。有方法可以为这两个变量提供单独的凭据，但这涉及到更高级的 OpenSSH 使用，这超出了本书的范围。然而，本节旨在给您一个起点，并演示这种可能性，您可以自行探索 OpenSSH 代理。

现在让我们改变方向，探讨如何设置 Ansible 在 playbook 运行期间提示您输入数据的可能性。

# 配置 playbook 提示

到目前为止，我们所有的 playbook 都是在其中为它们指定的数据在运行时在 playbook 中定义的变量中。然而，如果您在 playbook 运行期间实际上想要从某人那里获取信息怎么办？也许您希望用户选择要安装的软件包的版本？或者，也许您希望从用户那里获取密码，以用于身份验证任务，而不将其存储在任何地方。（尽管 Ansible Value 可以加密静态数据，但一些公司可能禁止在他们尚未评估的工具中存储密码和其他凭据。）幸运的是，对于这些情况（以及许多其他情况），Ansible 可以提示您输入用户输入，并将输入存储在变量中以供将来处理。

让我们重用本章开头定义的两个主机前端清单。现在，让我们通过一个实际的例子演示如何在 playbook 运行期间从用户那里获取数据：

1.  以通常的方式创建一个简单的 play 定义，如下所示：

```
---
- name: A simple play to demonstrate prompting in a playbook
  hosts: frontends
```

1.  现在，我们将在 play 定义中添加一个特殊的部分。我们之前定义了一个`vars`部分，但这次我们将定义一个叫做`vars_prompt`的部分（它使您能够通过用户提示定义变量）。在这个部分，我们将提示两个变量——一个是用户 ID，一个是密码。一个将被回显到屏幕上，而另一个不会，通过设置`private: yes`：

```
  vars_prompt:
    - name: loginid
      prompt: "Enter your username"
      private: no
    - name: password
      prompt: "Enter your password"
      private: yes
```

1.  现在，我们将向我们的 playbook 添加一个任务，以演示设置变量的提示过程：

```
  tasks:
    - name: Proceed with login
      debug:
        msg: "Logging in as {{ loginid }}..."
```

1.  现在，让我们运行 playbook 并看看它的行为：

```
$ ansible-playbook -i hosts prompt.yml
Enter your username: james
Enter your password:

PLAY [A simple play to demonstrate prompting in a playbook] ********************

TASK [Gathering Facts] *********************************************************
ok: [frt01.example.com]
ok: [frt02.example.com]

TASK [Proceed with login] ******************************************************
ok: [frt01.example.com] => {
 "msg": "Logging in as james..."
}
ok: [frt02.example.com] => {
 "msg": "Logging in as james..."
}

PLAY RECAP *********************************************************************
frt01.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

正如您所看到的，我们提示输入两个变量，但密码没有回显到终端，这对于安全原因很重要。然后我们可以在 playbook 中稍后使用这些变量。在这里，我们只是使用一个简单的`debug`命令来演示变量已经设置；然而，您可以在此处实现一个实际的身份验证功能，而不是这样做。

完成后，让我们继续下一节，看看如何通过标记有选择地运行 play 中的任务。

# 在 play 和任务中放置标记

在本书的许多部分，我们已经讨论过，随着您对 Ansible 的信心和经验的增长，您的 playbook 可能会在大小、规模和复杂性上增长。虽然这无疑是一件好事，但有时您可能只想运行 playbook 的一个子集，而不是从头到尾运行它。我们已经讨论了如何根据变量或事实的值有条件地运行任务，但是否有一种方法可以根据在运行 playbook 时做出的选择来运行它们？

Ansible play 中的标记是解决这个问题的方法，在本节中，我们将构建一个简单的 playbook，其中包含两个任务——每个任务都有一个不同的标记，以向您展示标记的工作原理。我们将使用之前使用过的两个简单主机清单：

1.  创建以下简单的 playbook 来执行两个任务——一个是安装`nginx`包，另一个是从模板部署配置文件：

```
---
- name: Simple play to demonstrate use of tags
  hosts: frontends

  tasks:
    - name: Install nginx
      yum:
        name: nginx
        state: present
      tags:
        - install

    - name: Install nginx configuration from template
      template:
        src: templates/nginx.conf.j2
        dest: /etc/nginx.conf
      tags:
        - customize
```

1.  现在，让我们以通常的方式运行 playbook，但有一个区别——这一次，我们将在命令行中添加`--tags`开关。这个开关告诉 Ansible 只运行与指定标记匹配的任务。例如，运行以下命令：

```
$ ansible-playbook -i hosts tags.yml --tags install

PLAY [Simple play to demonstrate use of tags] **********************************

TASK [Gathering Facts] *********************************************************
ok: [frt02.example.com]
ok: [frt01.example.com]

TASK [Install nginx] ***********************************************************
changed: [frt02.example.com]
changed: [frt01.example.com]

PLAY RECAP *********************************************************************
frt01.example.com : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

请注意，部署配置文件的任务没有运行。这是因为它被标记为`customize`，而我们在运行 playbook 时没有指定这个标记。

1.  还有一个`--skip-tags`开关，它与前一个开关相反——它告诉 Ansible 跳过列出的标记。因此，如果我们再次运行 playbook 但跳过`customize`标记，我们应该会看到类似以下的输出：

```
$ ansible-playbook -i hosts tags.yml --skip-tags customize

PLAY [Simple play to demonstrate use of tags] **********************************

TASK [Gathering Facts] *********************************************************
ok: [frt02.example.com]
ok: [frt01.example.com]

TASK [Install nginx] ***********************************************************
ok: [frt02.example.com]
ok: [frt01.example.com]

PLAY RECAP *********************************************************************
frt01.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

这个 play 运行是相同的，因为我们跳过了标记为`customize`的任务，而不是只包括`install`标记的任务。

请注意，如果您不指定`--tags`或`--skip-tags`，则所有任务都会运行，而不管它们的标记如何。

关于标签的一些说明——首先，每个任务可以有多个标签，因此我们看到它们以 YAML 列表格式指定。如果使用`--tags`开关，如果任何一个标签与命令行上指定的标签匹配，任务将运行。其次，标签可以被重复使用，因此我们可以有五个被全部标记为`install`的任务，如果您通过`--tags`或`--skip-tags`要求执行它们，所有五个任务都将被执行或跳过。

您还可以在命令行上指定多个标签，运行与任何指定标签匹配的所有任务。尽管标签背后的逻辑相对简单，但可能需要一点时间来适应它，而您最不希望做的事情就是在真实主机上运行 playbook，以检查您是否理解标签！了解这一点的一个很好的方法是在您的命令中添加`--list-tasks`，这样—而不是运行 playbook—会列出 playbook 中将要执行的任务。以下代码块为您提供了一些示例，基于我们刚刚创建的示例 playbook：

```
$ ansible-playbook -i hosts tags.yml --skip-tags customize --list-tasks

playbook: tags.yml

 play #1 (frontends): Simple play to demonstrate use of tags TAGS: []
 tasks:
 Install nginx TAGS: [install]

$ ansible-playbook -i hosts tags.yml --tags install,customize --list-tasks

playbook: tags.yml

 play #1 (frontends): Simple play to demonstrate use of tags TAGS: []
 tasks:
 Install nginx TAGS: [install]
 Install nginx configuration from template TAGS: [customize]

$ ansible-playbook -i hosts tags.yml --list-tasks

playbook: tags.yml

 play #1 (frontends): Simple play to demonstrate use of tags TAGS: []
 tasks:
 Install nginx TAGS: [install]
 Install nginx configuration from template TAGS: [customize]
```

正如您所看到的，`--list-tasks`不仅会显示哪些任务将运行，还会显示与它们关联的标签，这有助于您进一步理解标签的工作方式，并确保您实现了所需的 playbook 流程。标签是一种非常简单但强大的控制 playbook 中哪些部分运行的方法，通常在创建和维护大型 playbook 时，最好能够一次只运行所选部分的 playbook。从这里开始，我们将继续进行本章的最后一部分，我们将看看如何通过使用 Ansible Vault 对变量数据进行加密来保护您的静止状态下的变量数据。

# 使用 Ansible Vault 保护数据

Ansible Vault 是 Ansible 附带的一个工具，允许您在静止状态下加密敏感数据，同时在 playbook 中使用它。通常，需要将登录凭据或其他敏感数据存储在变量中，以允许 playbook 无人值守运行。然而，这会使您的数据面临被恶意使用的风险。幸运的是，Ansible Vault 使用 AES-256 加密在静止状态下保护您的数据，这意味着您的敏感数据不会被窥探。

让我们继续进行一个简单的示例，向您展示如何使用 Ansible Vault：

1.  首先创建一个新的保险库来存储敏感数据；我们将称这个文件为`secret.yml`。您可以使用以下命令创建这个文件：

```
$ ansible-vault create secret.yml
New Vault password:
Confirm New Vault password:
```

在提示时输入您为保险库选择的密码，并通过第二次输入来确认它（本书在 GitHub 上附带的保险库是用`secure`密码加密的）。

1.  当您输入密码后，您将被设置为您的正常编辑器（由`EDITOR` shell 变量定义）。在我的测试系统中，这是`vi`。在这个编辑器中，您应该以正常的方式创建一个`vars`文件，其中包含您的敏感数据：

```
---
secretdata: "Ansible is cool!"
```

1.  保存并退出编辑器（在`vi`中按*Esc*，然后输入`:wq`）。您将退出到 shell。现在，如果您查看文件的内容，您会发现它们已经被加密，对于任何不应该能够读取文件的人来说是安全的：

```
$ cat secret.yml
$ANSIBLE_VAULT;1.1;AES256
63333734623764633865633237333166333634353334373862346334643631303163653931306138
6334356465396463643936323163323132373836336461370a343236386266313331653964326334
62363737663165336539633262366636383364343663396335643635623463626336643732613830
6139363035373736370a646661396464386364653935636366633663623261633538626230616630
35346465346430636463323838613037386636333334356265623964633763333532366561323266
3664613662643263383464643734633632383138363663323730
```

1.  然而，Ansible Vault 的伟大之处在于，您可以在 playbook 中像使用普通的`variables`文件一样使用这个加密文件（尽管显然，您必须告诉 Ansible 您的保险库密码）。让我们创建一个简单的 playbook，如下所示：

```
---
- name: A play that makes use of an Ansible Vault
  hosts: frontends

  vars_files:
    - secret.yml

  tasks:
    - name: Tell me a secret
      debug:
        msg: "Your secret data is: {{ secretdata }}"
```

`vars_files`指令的使用方式与使用未加密的`variables`文件时完全相同。Ansible 在运行时读取`variables`文件的头，并确定它们是否已加密。

1.  尝试在不告诉 Ansible 保险库密码的情况下运行 playbook——在这种情况下，您应该会收到类似于这样的错误：

```
$ ansible-playbook -i hosts vaultplaybook.yml
ERROR! Attempting to decrypt but no vault secrets found
```

1.  Ansible 正确地理解我们正在尝试加载使用`ansible-vault`加密的`variables`文件，但我们必须手动告诉它密码才能继续。有多种指定 vault 密码的方法（稍后会详细介绍），但为了简单起见，请尝试运行以下命令，并在提示时输入您的 vault 密码：

```
$ ansible-playbook -i hosts vaultplaybook.yml --ask-vault-pass
Vault password:

PLAY [A play that makes use of an Ansible Vault] *******************************

TASK [Gathering Facts] *********************************************************
ok: [frt01.example.com]
ok: [frt02.example.com]

TASK [Tell me a secret] ********************************************************
ok: [frt01.example.com] => {
 "msg": "Your secret data is: Ansible is cool!"
}
ok: [frt02.example.com] => {
 "msg": "Your secret data is: Ansible is cool!"
}

PLAY RECAP *********************************************************************
frt01.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

成功！Ansible 解密了我们的 vault 文件，并将变量加载到了 playbook 中，我们可以从我们创建的`debug`语句中看到。当然，这违背了使用 vault 的目的，但这是一个很好的例子。

这是使用 vault 的一个非常简单的例子。您可以指定密码的多种方式；您不必在命令行上提示输入密码-可以通过包含 vault 密码的纯文本文件提供，也可以通过脚本在运行时从安全位置获取密码（考虑一个动态清单脚本，只返回密码而不是主机名）。`ansible-vault`工具本身也可以用于编辑、查看和更改 vault 文件中的密码，甚至解密并将其转换回纯文本。Ansible Vault 的用户指南是获取更多信息的绝佳起点（[`docs.ansible.com/ansible/latest/user_guide/vault.html`](https://docs.ansible.com/ansible/latest/user_guide/vault.html)）。

需要注意的一点是，您实际上不必为敏感数据单独创建 vault 文件；您实际上可以将其内联包含在 playbook 中。例如，让我们尝试重新加密我们的敏感数据，以便包含在一个否则未加密的 playbook 中（再次使用`secure`密码作为 vault 的密码，如果您正在测试本书附带的 GitHub 存储库中的示例，请运行以下命令在您的 shell 中（它应该产生类似于所示的输出）：

```
$ ansible-vault encrypt_string 'Ansible is cool!' --name secretdata
New Vault password:
Confirm New Vault password:
secretdata: !vault |
 $ANSIBLE_VAULT;1.1;AES256
 34393431303339353735656236656130336664666337363732376262343837663738393465623930
 3366623061306364643966666565316235313136633264310a623736643362663035373861343435
 62346264313638656363323835323833633264636561366339326332356430383734653030306637
 3736336533656230380a316364313831666463643534633530393337346164356634613065396434
 33316338336266636666353334643865363830346566666331303763643564323065
Encryption successful
```

您可以将此命令的输出复制并粘贴到 playbook 中。因此，如果我们修改我们之前的例子，它将如下所示：

```
---
- name: A play that makes use of an Ansible Vault
  hosts: frontends

  vars:
    secretdata: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          34393431303339353735656236656130336664666337363732376262343837663738393465623930
          3366623061306364643966666565316235313136633264310a623736643362663035373861343435
          62346264313638656363323835323833633264636561366339326332356430383734653030306637
          3736336533656230380a316364313831666463643534633530393337346164356634613065396434
          33316338336266636666353334643865363830346566666331303763643564323065

  tasks:
    - name: Tell me a secret
      debug:
        msg: "Your secret data is: {{ secretdata }}"
```

现在，当您以与之前完全相同的方式运行此 playbook（使用用户提示指定 vault 密码）时，您应该看到它的运行方式与我们使用外部加密的`variables`文件时一样：

```
$ ansible-playbook -i hosts inlinevaultplaybook.yml --ask-vault-pass
Vault password:

PLAY [A play that makes use of an Ansible Vault] *******************************

TASK [Gathering Facts] *********************************************************
ok: [frt02.example.com]
ok: [frt01.example.com]

TASK [Tell me a secret] ********************************************************
ok: [frt01.example.com] => {
 "msg": "Your secret data is: Ansible is cool!"
}
ok: [frt02.example.com] => {
 "msg": "Your secret data is: Ansible is cool!"
}

PLAY RECAP *********************************************************************
frt01.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frt02.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

Ansible Vault 是一个强大而多功能的工具，可以在静止状态下加密您的敏感 playbook 数据，并且（只要小心）应该使您能够在不留下密码或其他敏感数据的情况下无人值守地运行大部分 playbook。这就结束了本节和本章；希望对您有所帮助。

# 总结

Ansible 具有许多高级功能，可以让您在各种场景中运行 playbook，无论是在受控方式下升级服务器集群，还是在安全的隔离网络上使用设备，或者通过提示和标记来控制 playbook 流程。Ansible 已被大量且不断增长的用户群体采用，因此它的设计和演变都是围绕解决现实世界问题而展开的。我们讨论的大多数 Ansible 的高级功能都是围绕着解决现实世界问题展开的。

在本章中，您学习了如何在 Ansible 中异步运行任务，然后了解了运行 playbook 升级集群的各种功能，例如在小批量清单主机上运行任务，如果一定比例的主机失败则提前失败，将任务委派给特定主机，甚至无论清单（或批量）大小如何都运行任务一次。您还学习了在本地运行 playbook 与在`localhost`上运行 playbook 之间的区别，以及如何使用 SSH 代理自动化在`堡垒`主机上的隔离网络上的任务。最后，您学习了如何处理敏感数据，而不是以未加密的形式存储它，可以通过在运行时提示用户或使用 Ansible Vault 来实现。您甚至学习了如何使用标记来运行 playbook 任务的子集。

在下一章中，我们将更详细地探讨我们在本章中简要提到的一个主题 - 使用 Ansible 自动化网络设备管理。

# 问题

1.  哪个参数允许您配置在批处理中失败的最大主机数，然后播放被中止？

A）`百分比`

B）`最大失败`

C）`最大失败百分比`

D）`最大百分比`

E）`失败百分比`

1.  真或假 - 您可以使用`--connect=local`参数在本地运行任何 playbooks 而不使用 SSH：

A）真

B）假

1.  真或假 - 为了异步运行 playbook，您需要使用`async`关键字：

A）真

B）假

# 进一步阅读

如果您安装了 Passlib，这是 Python 2 和 3 的密码哈希库，`vars_prompt`将使用任何加密方案（如`descrypt`，`md5crypt`，`sha56_crypt`等）进行加密：

+   [`passlib.readthedocs.io/en/stable/`](https://passlib.readthedocs.io/en/stable/)


# 第三部分：在企业中使用 Ansible

在这一部分，我们将从实际角度看如何在企业环境中充分利用 Ansible。我们将首先看如何使用 Ansible 自动化网络设备，然后转向使用 Ansible 来管理云和容器环境。接着，我们将介绍一些更高级的测试和故障排除策略，这些策略将帮助您在企业中使用 Ansible，最后我们将介绍 Ansible Tower/AWX 产品，在企业环境中提供丰富的基于角色的访问控制（RBAC）和审计功能。

本节包括以下章节：

+   第九章，*使用 Ansible 进行网络自动化*

+   第十章，*容器和云管理*

+   第十一章，*故障排除和测试策略*

+   第十二章，*开始使用 Ansible Tower*


# 第九章：使用 Ansible 进行网络自动化

多年前，标准做法是手动配置每个网络设备。这主要是因为路由器和交换机主要是路由物理服务器的流量，因此每个网络设备上不需要太多的配置，而且变化缓慢。此外，只有人类才有足够的信息来设置网络。无论是规划还是执行，一切都非常手动。

虚拟化改变了这种范式，因为它导致了数千台机器连接到同一交换机或路由器，每台机器可能具有不同的网络需求。变化快速且频繁预期，并且随着虚拟基础架构的代码定义，人类管理员只需跟上基础设施的变化就成了全职工作。虚拟化编排平台对机器位置有更好的了解，甚至可以为我们生成清单，正如我们在前几章中看到的。实际上，没有办法让一个人类记住或管理现代大规模虚拟化基础设施。因此，很明显，自动化在配置网络基础设施时是必需的。

我们将在本章中学习更多关于这一点，以及我们可以做些什么来自动化我们的网络，内容包括以下主题：

+   为什么要自动化网络管理？

+   Ansible 如何管理网络设备

+   如何启用网络自动化

+   可用的 Ansible 网络模块

+   连接到网络设备

+   网络设备的环境变量

+   网络设备的自定义条件语句

让我们开始吧！

# 技术要求

本章假定您已经按照第一章 *开始使用 Ansible*中详细介绍的方式设置了控制主机，并且正在使用最新版本——本章的示例是使用 Ansible 2.9 进行测试的。本章还假定您至少有一个额外的主机进行测试，并且最好是基于 Linux 的。由于本章以网络设备为中心，我们理解并不是每个人都能够访问特定的网络设备进行测试（例如 Cisco 交换机）。在给出示例并且您可以访问这些设备的情况下，请随时探索这些示例。但是，如果您无法访问任何网络硬件，我们将使用免费提供的 Cumulus VX 进行示例演示，该软件提供了 Cumulus Networks 的交换环境的完整演示。尽管本章将给出特定主机名的示例，但您可以自由地用自己的主机名和/或 IP 地址替换它们。如何进行替换将在适当的位置提供详细信息。

本章的代码包在此处可用：[`github.com/PacktPublishing/Practical-Ansible-2/tree/master/Chapter%209`](https://github.com/PacktPublishing/Practical-Ansible-2/tree/master/Chapter%209)。

# 为什么要自动化网络管理？

在过去的 30 年里，我们设计数据中心的方式发生了根本性的变化。在 90 年代，典型的数据中心充满了具有非常特定目的的物理机器。在许多公司，服务器是根据机器的用途由不同的供应商购买的。这意味着需要机器、网络设备和存储设备，并且这些设备被购买、配置和交付。

这里的一个重大缺点是在确定需要机器和交付之间存在显著的滞后。在那段时间里，这是可以接受的，因为大多数公司的系统非常少，它们很少改变。此外，这种方法非常昂贵，因为许多设备被低效利用。

随着社会和科技公司的进步，我们知道今天，对于公司来说削减基础设施部署时间和成本变得非常重要。这为一个新的想法打开了道路：虚拟化。通过创建一个虚拟化集群，您不需要拥有正确尺寸的物理主机，因此您可以预先配置一些主机，将它们添加到资源池中，然后在虚拟化平台中创建合适尺寸的机器。这意味着当需要新的机器时，您可以通过几次点击创建它，并且几秒钟内就可以准备好。

这种转变还使企业能够从每个项目都部署具有独特数据中心要求的基础设施转变为一个可以由软件和配置定义行为的大型中央基础设施。这意味着一个单一的网络基础设施可以支持所有项目，而不管它们的规模如何。我们称之为虚拟数据中心基础设施，在这种基础设施中，我们尽可能地利用通用设计模式。这使得企业能够以大规模部署、切换和提供基础设施，以便通过简单地对其进行细分（例如创建虚拟服务器）来成功实施多种项目。

虚拟化带来的另一个重大优势是工作负载和物理主机的解耦。从历史上看，由于工作负载与物理主机绑定，如果主机死机，工作负载本身也会死机，除非在不同硬件上进行适当复制。虚拟化解决了这个问题，因为工作负载现在与一个或多个虚拟主机绑定，但这些虚拟主机可以自由地从一个物理主机移动到另一个物理主机。

快速配置机器的能力以及这些机器能够从一个主机移动到另一个主机的能力，导致了网络配置管理的问题。以前，人为地在安装新机器时调整配置细节是可以接受的，但现在，机器在主机之间移动（因此从一个物理交换机端口移动到另一个端口）而不需要任何人为干预。这意味着系统也需要更新网络配置。

与此同时，VLAN 在网络中占据了一席之地，这使得网络设备的利用得到了显著改善，从而优化了它们的成本。

今天，我们在更大的规模上工作，虚拟对象（机器、容器、函数等）在我们的数据中心中移动，完全由软件系统管理，人类参与的越来越少。

在这种环境中，自动化网络是他们成功的关键部分。

今天，有一些公司（著名的“云服务提供商”）在一个规模上工作，手动网络管理不仅不切实际，而且即使雇佣了大量网络工程师团队，也是不可能的。另一方面，有许多环境在技术上可能（至少部分地）手动管理网络配置，但仍然不切实际。

除了配置网络设备所需的时间之外，网络自动化最大的优势（从我的角度来看）是大大减少人为错误的机会。如果一个人必须在 100 台设备上配置 VLAN，很可能在这个过程中会出现一些错误。这是绝对正常的，但仍然是有问题的，因为这些配置将需要进行全面测试和修改。通常情况下，问题并不会止步于此，因为当设备损坏并因此需要更换时，人们必须以与旧设备相同的方式配置新设备。通常情况下，随着时间的推移，配置会发生变化，而且很多时候没有明确的方法来追踪这一点，因此在更换有故障的网络设备时，可能会出现一些在旧设备中存在但在新设备中不存在的规则问题。

既然我们已经讨论了自动化网络管理的必要性，让我们看看如何使用 Ansible 管理网络设备。

# 学习 Ansible 如何管理网络设备

Ansible 允许您管理许多不同的网络设备，包括 Arista EOS、Cisco ASA、Cisco IOS、Cisco IOS XR、Cisco NX-OS、Dell OS 6、Dell OS 9、Dell OS 10、Extreme EXOS、Extreme IronWare、Extreme NOS、Extreme SLX-OS、Extreme VOSS、F5 BIG-IP、F5 BIG-IQ、Junos OS、Lenovo CNOS、Lenovo ENOS、MikroTik RouterOS、Nokia SR OS、Pluribus Netvisor、VyOS 和支持 NETCONF 的 OS。正如您可以想象的那样，我们可以通过各种方式让 Ansible 与它们进行通信。

此外，我们必须记住，Ansible 网络模块在控制器主机上运行（即您发出`ansible`命令的主机），而通常，Ansible 模块在目标主机上运行。这种差异很重要，因为它允许 Ansible 根据目标设备类型使用不同的连接机制。请记住，即使您的主机具有 SSH 管理功能（许多交换机都有），由于 Ansible 在目标主机上运行其模块，因此需要目标主机安装 Python。大多数交换机（和嵌入式硬件）缺乏 Python 环境，因此我们必须使用其他连接协议。Ansible 支持的用于网络设备管理的关键协议在此处给出。

Ansible 使用以下五种主要连接类型连接这些网络设备：

+   `network_cli`

+   `netconf`

+   `httpapi`

+   `local`

+   `ssh`

当您与网络设备建立连接时，您需要根据设备支持的连接机制和您的需求选择连接机制：

+   `network_cli` 得到大多数模块的支持，它与 Ansible 通常使用非网络模块的方式最相似。这种模式通过 SSH 使用 CLI。该协议在配置开始时创建持久连接，并在整个任务的持续时间内保持连接，因此您不必为每个后续任务提供凭据。

+   `netconf` 受到很少模块的支持（在撰写本文时，这些模块只是支持 NETCONF 和 Junos OS 的操作系统）。这种模式通过 SSH 使用 XML，因此基本上它将基于 XML 的配置应用到设备上。该协议在配置开始时创建持久连接，并在整个任务的持续时间内保持连接，因此您不必为每个后续任务提供凭据。

+   `httpapi` 受到少量模块的支持（在撰写本文时，这些模块是 Arista EOS、Cisco NX-OS 和 Extreme EXOS）。这种模式使用设备发布的 HTTP API。该协议在配置开始时创建持久连接，并在整个任务的持续时间内保持连接，因此您不必为每个后续任务提供凭据。

+   `Local`被大多数设备支持，但是它是一个已弃用的模式。这基本上是一个依赖于供应商的连接模式，可能需要使用一些供应商包。这种模式不会创建持久连接，因此在每个任务开始时，你都需要传递凭据。在可能的情况下，避免使用这种模式。

+   在本节中，`ssh` 不能被忘记。虽然许多设备依赖于此处列出的连接模式，但正在创建一种新型设备，它们在白盒交换机硬件上原生运行 Linux。Cumulus Networks 就是一个这样的例子，由于软件是基于 Linux 的，所有配置都可以通过 SSH 进行，就好像交换机实际上只是另一台 Linux 服务器一样。

了解 Ansible 如何连接和与你的网络硬件通信是很重要的，因为它能让你理解你构建 Ansible playbooks 和调试问题时所需的知识。在本节中，我们介绍了在处理网络硬件时会遇到的通信协议。在下一节中，我们将在此基础上继续，看看如何使用 Ansible 开始我们的网络自动化之旅的基础知识。

# 启用网络自动化

在你使用 Ansible 进行网络自动化之前，你需要确保你拥有一切所需的东西。

根据我们将要使用的连接方法的不同，我们需要不同的依赖。举例来说，我们将使用具有`network_cli`连接性的 Cisco IOS 设备。

Ansible 网络自动化的唯一要求如下：

+   Ansible 2.5+

+   与网络设备的正确连接

首先，我们需要检查 Ansible 的版本：

1.  确保你有一个最新的 Ansible 版本，你可以运行以下命令：

```
$ ansible --version
```

这将告诉你你的 Ansible 安装的版本。

1.  如果是 2.5 或更高版本，你可以发出以下命令（带有适当的选项）来检查网络设备的连接：

```
$ ansible all -i n1.example.com, -c network_cli -u my_user -k -m ios_facts -e ansible_network_os=ios all
```

这应该返回你设备的事实，证明我们能够连接。对于任何其他目标，Ansible 都能够检索事实，这通常是 Ansible 与目标交互时的第一步。

这是一个关键步骤，因为这使得 Ansible 能够了解设备的当前状态，从而采取适当的行动。

通过在目标设备上运行`ios_facts`模块，我们只是执行了这个第一个标准步骤（因此不会对设备本身或其配置进行任何更改），但这将确认 Ansible 能够连接到设备并对其执行命令。

显然，只有当你有权限访问运行 Cisco IOS 的网络设备时，你才能运行前面的命令并探索其行为。我们知道并非每个人都有相同的网络设备可用于测试（或者根本没有！）。幸运的是，一种新型交换机正在出现——“白盒”交换机。这些交换机由各种制造商制造，基于标准化硬件，你可以在上面安装自己的网络操作系统。Cumulus Linux 就是这样一种操作系统，它的一个免费测试版本叫做 Cumulus VX，可以供你下载。

在撰写本文时，Cumulus VX 的下载链接是[`cumulusnetworks.com/products/cumulus-vx/`](https://cumulusnetworks.com/products/cumulus-vx/)。你需要注册才能下载，但这样做可以让你免费访问开放网络的世界。

只需下载适合你的 hypervisor（例如 VirtualBox）的镜像，然后像运行任何其他 Linux 虚拟机一样运行它。完成后，你可以连接到 Cumulus VX 交换机，就像连接到任何其他 SSH 设备一样。例如，要运行一个关于所有交换机端口接口的事实的临时命令（在 Cumulus VX 上被枚举为`swp1`、`swp2`和`swpX`），你可以运行以下命令：

```
$ ansible -i vx01.example.com, -u cumulus -m setup -a 'filter=ansible_swp*' all --ask-pass
```

如果成功，这应该会导致关于 Cumulus VX 虚拟交换机的交换机端口接口的大量信息。在我的测试系统上，此输出的第一部分如下所示：

```
vx01.example.com | SUCCESS => {
 "ansible_facts": {
 "ansible_swp1": {
 "active": false,
 "device": "swp1",
 "features": {
 "esp_hw_offload": "off [fixed]",
 "esp_tx_csum_hw_offload": "off [fixed]",
 "fcoe_mtu": "off [fixed]",
 "generic_receive_offload": "on",
 "generic_segmentation_offload": "on",
 "highdma": "off [fixed]",
...
```

正如您所看到的，使用诸如 Cumulus Linux 之类的操作系统来使用白盒交换机的优势在于，您可以使用标准的 SSH 协议进行连接，甚至可以使用内置的`setup`模块来收集有关它的信息。使用其他专有硬件并不更加困难，但只是需要指定更多的参数，就像我们在本章前面展示的那样。

现在您已经了解了启用网络自动化的基本知识，让我们学习如何在 Ansible 中发现适合我们所需自动化任务的适当网络模块。

# 审查可用的 Ansible 网络模块

目前，有超过 20 种不同的网络平台上的数千个模块。让我们学习如何找到对您更相关的模块：

1.  首先，您需要知道您有哪种设备类型以及 Ansible 如何调用它。在[`docs.ansible.com/ansible/latest/network/user_guide/platform_index.html`](https://docs.ansible.com/ansible/latest/network/user_guide/platform_index.html)页面上，您可以找到 Ansible 支持的不同设备类型以及它们的指定方式。在我们的示例中，我们将以 Cisco IOS 为例。

1.  在[`docs.ansible.com/ansible/latest/modules/list_of_network_modules.html`](https://docs.ansible.com/ansible/latest/modules/list_of_network_modules.html)页面上，您可以搜索专门针对您所需交换机家族的类别，并且您将能够看到所有可以使用的模块。

模块列表对于我们来说太大且特定于家族，无法对其进行深入讨论。每个版本都会有数百个新的模块添加，因此此列表每次发布都会变得更大。

如果您熟悉如何以手动方式配置设备，您将很快发现模块的名称相当自然，因此您将很容易理解它们的功能。但是，让我们从 Cisco IOS 模块集合中挑选出一些例子，具体参考[`docs.ansible.com/ansible/latest/modules/list_of_network_modules.html#ios`](https://docs.ansible.com/ansible/latest/modules/list_of_network_modules.html#ios)：

+   `ios_banner`：顾名思义，此模块将允许您微调和修改登录横幅（在许多系统中称为`motd`）。

+   `ios_bgp`：此模块允许您配置 BGP 路由。

+   `ios_command`：这是 Ansible `command`模块的 IOS 等效模块，它允许您执行许多不同的命令。就像`command`模块一样，这是一个非常强大的模块，但最好使用特定的模块来执行我们要执行的操作，如果它们可用的话。

+   `ios_config`：此模块允许我们对设备的配置文件进行几乎任何更改。就像`ios_command`模块一样，这是一个非常强大的模块，但最好使用特定的模块来执行我们要执行的操作，如果它们可用的话。如果使用了缩写命令，则此模块的幂等性将无法保证。

+   `ios_vlan`：此模块允许配置 VLAN。

这只是一些例子，但对于 Cisco IOS 还有许多其他模块（在撰写本文时有 27 个），如果您找不到执行所需操作的特定模块，您总是可以退而使用`ios_command`和`ios_config`，由于它们的灵活性，将允许您执行任何您能想到的操作。

相比之下，如果你正在使用 Cumulus Linux 交换机，你会发现只有一个模块 - `nclu`（参见[`docs.ansible.com/ansible/latest/modules/list_of_network_modules.html#cumulus`](https://docs.ansible.com/ansible/latest/modules/list_of_network_modules.html#cumulus)）。这反映了在 Cumulus Linux 中所有配置工作都是用这个命令处理的事实。如果你需要自定义每日消息或 Linux 操作系统的其他方面，你可以以正常方式进行（例如，使用我们在本书中之前演示过的`template`或`copy`模块）。

与往常一样，Ansible 文档是你的朋友，当你学习如何在新类设备上自动化命令时，它应该是你的首要选择。在本节中，我们演示了一个简单的过程，用于查找适用于你的网络设备类别的 Ansible 模块，以 Cisco 作为具体示例（尽管你可以将这些原则应用于任何其他设备）。现在，让我们看看 Ansible 如何连接到网络设备。

# 连接到网络设备

正如我们所看到的，Ansible 网络中有一些特殊之处，因此需要特定的配置。

为了使用 Ansible 管理网络设备，你至少需要一个设备进行测试。假设我们有一个 Cisco IOS 系统可供使用。可以肯定的是，不是每个人都有这样的设备进行测试，因此以下内容仅作为假设示例提供。

根据[`docs.ansible.com/ansible/latest/network/user_guide/platform_index.html`](https://docs.ansible.com/ansible/latest/network/user_guide/platform_index.html)页面，我们可以看到这个设备的正确`ansible_network_os`是`ios`，我们可以使用`network_cli`和`local`连接到它。由于`local`已经被弃用，我们将使用`network_cli`。按照以下步骤配置 Ansible，以便你可以管理 IOS 设备：

1.  首先，让我们创建包含我们设备的清单文件在`routers`组中：

```
[routers]
n1.example.com
n2.example.com

[cumulusvx]
vx01.example.com
```

1.  要知道要使用哪些连接参数，我们将设置 Ansible 的特殊连接变量，以便它们定义连接参数。我们将在 playbook 的组变量子目录中进行这些操作，因此我们需要创建包含以下内容的`group_vars/routers.yml`文件：

```
---
ansible_connection: network_cli
ansible_network_os: ios
ansible_become: True
ansible_become_method: enable
```

凭借这些特殊的 Ansible 变量，它将知道如何连接到你的设备。我们在本书的前面已经涵盖了一些这些示例，但作为一个回顾，Ansible 使用这些变量的值来确定其行为的方式如下：

+   `ansible_connection`：这个变量被 Ansible 用来决定如何连接到设备。通过选择`network_cli`，我们指示 Ansible 以 SSH 模式连接到 CLI，就像我们在前一段讨论的那样。

+   `ansible_network_os`：这个变量被 Ansible 用来理解我们将要使用的设备的设备系列。通过选择`ios`，我们指示 Ansible 期望一个 Cisco IOS 设备。

+   `ansible_become`：这个变量被 Ansible 用来决定是否在设备上执行特权升级。通过指定`True`，我们告诉 Ansible 执行特权升级。

+   `ansible_become_method`：在各种设备上执行特权升级有许多不同的方法（通常在 Linux 服务器上是`sudo` - 这是默认设置），对于 Cisco IOS，我们必须将其设置为`enable`。

通过这些步骤，你已经学会了连接到网络设备的必要步骤。

为了验证连接是否按预期工作（假设你可以访问运行 Cisco IOS 的路由器），你可以运行这个简单的 playbook，名为`ios_facts.yaml`：

```
---
- name: Play to return facts from a Cisco IOS device
  hosts: routers
  gather_facts: False
  tasks:
    - name: Gather IOS facts
      ios_facts:
        gather_subset: all
```

你可以使用以下命令来运行这个过程：

```
$ ansible-playbook -i hosts ios_facts.yml --ask-pass
```

如果它成功返回，这意味着你的配置是正确的，并且你已经能够给予 Ansible 管理你的 IOS 设备所需的授权。

同样，如果您想连接到 Cumulus VX 设备，您可以添加另一个名为`group_vars/cumulusvx.yml`的组变量文件，其中包含以下代码：

```
---
ansible_user: cumulus
become: false
```

一个类似的 playbook，返回有关我们的 Cumulus VX 交换机的所有信息，可能如下所示：

```
---
- name: Simply play to gather Cumulus VX switch facts
  hosts: cumulusvx
  gather_facts: no

  tasks:
    - name: Gather facts
      setup:
        gather_subset: all
```

您可以通过使用以下命令以正常方式运行：

```
$ ansible-playbook -i hosts cumulusvx_facts.yml --ask-pass
```

如果成功，您应该会从您的 playbook 运行中看到以下输出：

```
SSH password:

PLAY [Simply play to gather Cumulus VX switch facts] ************************************************************************************************

TASK [Gather facts] ************************************************************************************************
ok: [vx01.example.com]

PLAY RECAP ************************************************************************************************
vx01.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

这演示了连接到 Ansible 中两种不同类型的网络设备的技术，其中一种您可以自行测试，而无需访问任何特殊硬件。现在，让我们通过查看如何为 Ansible 中的网络设备设置环境变量来进一步学习。

# 网络设备的环境变量

网络的复杂性很高，网络系统也非常多样化。因此，Ansible 拥有大量的变量，可以帮助您调整它，使 Ansible 适应您的环境。

假设您有两个不同的网络（即一个用于计算，一个用于网络设备），它们不能直接通信，但必须通过堡垒主机才能从一个网络到达另一个网络。由于我们在计算网络中使用了 Ansible，我们需要通过堡垒主机跳转网络，以配置管理网络中的 IOS 路由器。此外，我们的目标交换机需要代理才能访问互联网。

要连接到数据库网络中的 IOS 路由器，我们需要为我们的网络设备创建一个新的组，这些设备位于一个单独的网络上。例如，对于这个例子，可能会指定如下：

```
[bastion_routers]
n1.example.com
n2.example.com

[bastion_cumulusvx]
vx01.example.com
```

创建了更新后的清单后，我们可以创建一个新的组变量文件，例如`group_vars/bastion_routers.yaml`，其中包含以下内容：

```
---
ansible_connection: network_cli
ansible_network_os: ios
ansible_become: True
ansible_become_method: enable
ansible_ssh_common_args: '-o ProxyCommand="ssh -W %h:%p -q bastion.example.com"'
proxy_env:
    http_proxy: http://proxy.example.com:8080
```

如果我们的 Cumulus VX 交换机位于堡垒服务器后面，我们也可以创建一个`group_vars/bastion_cumulusvx.yml`文件来实现相同的效果：

```
---
ansible_user: cumulus
ansible_become: false
ansible_ssh_common_args: '-o ProxyCommand="ssh -W %h:%p -q bastion.example.com"'
proxy_env:
    http_proxy: http://proxy.example.com:8080
```

除了我们在上一节中讨论的选项之外，我们现在还有两个额外的选项：

+   `ansible_ssh_common_args`：这是一个非常强大的选项，允许我们向 SSH 连接添加额外的选项，以便我们可以调整它们的行为。这些选项应该相当容易识别，因为您已经在您的 SSH 配置中使用它们，只需简单地 SSH 到目标机器。在这种特定情况下，我们正在添加一个`ProxyCommand`，这是执行跳转到主机（通常是堡垒主机）的 SSH 指令，以便我们可以安全地进入目标主机。

+   `http_proxy`：这个选项位于`proxy_env`选项下面，在网络隔离很强的环境中非常关键，因此您的机器除非使用代理，否则无法与互联网进行交互。

假设您已经设置了无密码（例如基于 SSH 密钥的）访问到您的堡垒主机，您应该能够对您的 Cumulus VX 主机运行一个临时的 Ansible `ping`命令，如下所示：

```
$ ansible -i hosts -m ping -u cumulus --ask-pass bastion_cumulusvx
SSH password:

vx01.example.com | SUCCESS => {
 "ansible_facts": {
 "discovered_interpreter_python": "/usr/bin/python"
 },
 "changed": false,
 "ping": "pong"
}
```

请注意，堡垒服务器的使用变得透明 - 您可以继续使用 Ansible 进行自动化，就好像您在同一个平面网络上一样。如果您可以访问基于 Cisco IOS 的设备，您也应该能够对`bastion_routers`组运行类似的命令，并取得类似的积极结果。现在您已经学会了为网络设备设置环境变量的必要步骤，以及如何使用 Ansible 访问它们，即使它们在隔离的网络中，让我们学习如何为网络设备设置条件语句。

# 网络设备的条件语句

尽管没有特定于网络的 Ansible 条件语句，但在与网络相关的 Ansible 使用中，条件语句是相当常见的。

在网络中，启用和禁用端口是很常见的。要使数据通过电缆，电缆两端的端口都应该启用，并且结果为“连接”状态（一些供应商可能会使用不同的名称，但概念是相同的）。

假设我们有两个 Arista Networks EOS 设备，并且我们在端口上发出了 ON 状态，并且需要等待连接建立后再继续。

要等待`Ethernet4`接口启用，我们需要在我们的 playbook 中添加以下任务：

```
- name: Wait for interface to be enabled
  eos_command:
      commands:
          - show interface Ethernet4 | json
      wait_for:
          - "result[0].interfaces.Ethernet4.interfaceStatus  eq  connected"
```

`eos_command`是允许我们向 Arista Networks EOS 设备发出自由形式命令的模块。命令本身需要在`commands`选项中指定为数组。通过`wait_for`选项，我们可以指定一个条件，Ansible 将在指定任务上重复，直到条件满足。由于命令的输出被重定向到`json`实用程序，输出将是一个 JSON，因此我们可以使用 Ansible 操作 JSON 数据的能力来遍历其结构。

我们可以在 Cumulus VX 上实现类似的结果——例如，我们可以查询从交换机收集的事实，看看端口`swp2`是否已启用。如果没有启用，那么我们将启用它；但是，如果已启用，我们将跳过该命令。我们可以通过一个简单的 playbook 来实现这一点，如下所示：

```
---
- name: Simple play to demonstrate conditional on Cumulus Linux
  hosts: cumulusvx

  tasks:
    - name: Enable swp2 if it is disabled
      nclu:
        commands:
          - add int swp2
        commit: yes
      when: ansible_swp2.active == false
```

注意我们任务中`when`子句的使用，意味着我们只应在`swp2`不活动时发出配置指令。如果我们在未配置的 Cumulus Linux 交换机上第一次运行此 playbook，我们应该看到类似以下的输出：

```
PLAY [Simple play to demonstrate conditional on Cumulus Linux] ***************************************************************

TASK [Gathering Facts] 
***************************************************************
ok: [vx01.example.com]

TASK [Enable swp2 if it is disabled] ***************************************************************
changed: [vx01.example.com]

PLAY RECAP 
***************************************************************
vx01.example.com : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

正如我们所看到的，`nclu`模块将我们的更改提交到了交换机配置中。然而，如果我们再次运行 playbook，输出应该更像这样：

```
PLAY [Simple play to demonstrate conditional on Cumulus Linux] ***************************************************************

TASK [Gathering Facts] 
***************************************************************
ok: [vx01.example.com]

TASK [Enable swp2 if it is disabled] ***************************************************************
skipping: [vx01.example.com]

PLAY RECAP
***************************************************************
vx01.example.com : ok=1 changed=0 unreachable=0 failed=0 skipped=1 rescued=0 ignored=0
```

这一次，任务被跳过了，因为 Ansible 事实显示端口`swp2`已经启用。这显然是一个非常简单的例子，但它展示了你可以如何在网络设备上使用条件语句，这与你之前在本书中已经看到的在 Linux 服务器上使用条件语句的方式非常相似。

这就结束了我们对使用 Ansible 进行网络设备自动化的简要介绍——更深入的工作需要查看网络配置，并需要更多的硬件，因此这超出了本书的范围。然而，我希望这些信息向你展示了 Ansible 可以有效地用于自动化和配置各种网络设备。

# 摘要

快速变化的现代大规模基础设施需要自动化网络任务。幸运的是，Ansible 支持各种网络设备，从专有硬件，如基于 Cisco IOS 的设备，到运行操作系统如 Cumulus Linux 的白盒交换机等开放标准。当涉及管理网络配置时，Ansible 是一个强大而有支持性的工具，它允许你快速而安全地实施变更。你甚至可以在网络中替换整个设备，并且有信心能够通过你的 Ansible playbook 在新设备上放置正确的配置。

在本章中，你了解了自动化网络管理的原因。然后，你看了 Ansible 如何管理网络设备，如何在 Ansible 中启用网络自动化，以及如何找到执行你希望完成的自动化任务所需的 Ansible 模块。然后，通过实际示例，你学会了如何连接到网络设备，如何设置环境变量（并通过堡垒主机连接到隔离网络），以及如何对 Ansible 任务应用条件语句以配置网络设备。

在下一章中，我们将学习如何使用 Ansible 管理 Linux 容器和云基础设施。

# 问题

1.  以下哪个不是 Ansible 用于连接这些网络设备的四种主要连接类型之一？

A) `netconf`

B) `network_cli`

C) `local`

D) `netstat`

E) `httpapi`

1.  真或假：`ansible_network_os`变量被 Ansible 用来理解我们将要使用的设备的设备系列。

A) True

B) False

1.  真或假：为了连接到一个独立网络中的 IOS 路由器，您需要指定主机的特殊连接变量，可能作为清单组变量。

A) 正确

B) 错误

# 进一步阅读

+   有关 Ansible 网络的官方文档：[`docs.ansible.com/ansible/latest/network/index.html`](https://docs.ansible.com/ansible/latest/network/index.html)


# 第十章：容器和云管理

Ansible 是一个非常灵活的自动化工具，可以轻松用于自动化基础架构的任何方面。在过去几年中，基于容器的工作负载和云工作负载变得越来越受欢迎，因此我们将看看如何使用 Ansible 自动化与这些工作负载相关的任务。在本章中，我们将首先使用 Ansible 设计和构建容器。然后，我们将看看如何运行这些容器，最后，我们将看看如何使用 Ansible 管理各种云平台。

具体来说，本章将涵盖以下主题：

+   使用 playbooks 设计和构建容器

+   管理多个容器平台

+   使用 Ansible 自动化 Docker

+   探索面向容器的模块

+   针对亚马逊网络服务的自动化

+   通过自动化来补充谷歌云平台

+   与 Azure 的无缝自动化集成

+   通过 Rackspace Cloud 扩展您的环境

+   使用 Ansible 编排 OpenStack

让我们开始吧！

# 技术要求

本章假设您已经按照第一章 *开始使用 Ansible*中详细说明的方式设置了 Ansible 的控制主机，并且正在使用最新版本——本章的示例是在 Ansible 2.9 版本下测试的。尽管本章将给出特定的主机名示例，但您可以自由地用您自己的主机名和/或 IP 地址替换它们。如何做到这一点的细节将在适当的地方提供。本章还假设您可以访问 Docker 主机，尽管在大多数操作系统上都可以安装 Docker，但本章提供的所有命令都是针对 GNU/Linux 的，并且仅在该平台上进行了测试。

本章中的所有示例都可以在本书的 GitHub 存储库中找到：[`github.com/PacktPublishing/Practical-Ansible-2/tree/master/Chapter%2010`](https://github.com/PacktPublishing/Practical-Ansible-2/tree/master/Chapter%2010)。

# 使用 playbooks 设计和构建容器

使用 Dockerfile 构建容器可能是最常见的方法，但这并不意味着这是最好的方法。

首先，即使您在自动化路径上处于非常良好的位置，并且为您的基础架构编写了许多 Ansible 角色，您也无法在 Dockerfile 中利用它们，因此您最终会复制您的工作来创建容器。除了需要花费时间和需要学习一种新语言之外，公司很少能够在一夜之间放弃他们的基础架构并转向容器。这意味着您需要保持两个相同的自动化部分处于活动状态并保持最新，从而使自己处于犯错误和环境之间不一致行为的位置。

如果这还不够成问题，当您开始考虑云环境时，情况很快就会恶化。所有云环境都有自己的控制平面和本地自动化语言，因此在很短的时间内，您会发现自己一遍又一遍地重写相同操作的自动化，从而浪费时间并破坏环境的一致性。

Ansible 提供了`ansible-container`，以便您可以使用与创建机器相同的组件来创建容器。您应该做的第一件事是确保您已经安装了`ansible-container`。有几种安装它的方法，但最简单的方法是使用`pip`。为此，您可以运行以下命令：

```
$ sudo pip install ansible-container[docker,k8s]
```

`ansible-container`工具在撰写本文时带有三个支持的引擎：

+   `docker`：如果您想要在 Docker 引擎（即在您的本地机器上）中使用它，就需要它。

+   `k8s`：如果您想要在 Kubernetes 集群中使用它，无论是本地（即 MiniKube）还是远程（即生产集群）都需要它。

+   `openshift`：如果你想要在 OpenShift 集群中使用它，无论是本地（即 MiniShift）还是远程（即生产集群）。

按照以下步骤使用 playbooks 构建容器：

1.  发出`ansible-container init`命令将给我们以下输出：

```
$ ansible-container init
Ansible Container initialized.
```

运行这个命令还将创建以下文件：

+   +   `ansible.cfg`：一个空文件，用于（最终）用于覆盖 Ansible 系统配置

+   `ansible-requirements.txt`：一个空文件，用于（最终）列出构建过程中容器的 Python 要求

+   `container.yml`：一个包含构建的 Ansible 代码的文件

+   `meta.yml`：一个包含 Ansible Galaxy 元数据的文件

+   `requirements.yml`：一个空文件，用于（最终）列出构建所需的 Ansible 角色

1.  让我们尝试使用这个工具构建我们自己的容器-用以下内容替换`container.yml`的内容：

```
version: "2"
settings:
  conductor:
    base: centos:7
  project_name: http-server
services:
  web:
    from: "centos:7"
    roles:
      - geerlingguy.apache
    ports:
      - "80:80"
    command:
      - "/usr/bin/dumb-init"
      - "/usr/sbin/apache2ctl"
      - "-D"
      - "FOREGROUND"
    dev_overrides:
      environment:
        - "DEBUG=1"
```

现在我们可以运行`ansible-container build`来启动构建。

在构建过程结束时，我们将得到一个应用了`geerlingguy.apache`角色的容器。`ansible-container`工具执行多阶段构建能力，启动一个用于构建真实容器的 Ansible 容器。

如果我们指定了多个要应用的角色，输出将是一个具有更多层的图像，因为 Ansible 将为每个指定的角色创建一个层。这样，容器可以很容易地使用现有的 Ansible 角色构建，而不是 Dockerfiles。

现在你已经学会了如何使用 playbooks 设计和构建容器，接下来你将学习如何管理多个容器平台。

# 管理多个容器平台

在今天的世界中，仅仅能够运行一个镜像并不被认为是一个可以投入生产的设置。

要能够称呼一个部署为“投入生产使用”，你需要能够证明你的应用程序提供的服务将在合理的情况下运行，即使是在单个应用程序崩溃或硬件故障的情况下。通常，你的客户会有更多的可靠性约束。

幸运的是，你的软件并不是唯一具有这些要求的数据，因此为此目的开发了编排解决方案。

今天，最成功的一个是 Kubernetes，因为它有各种不同的发行版/版本，所以我们将主要关注它。

Kubernetes 的理念是，你告诉 Kubernetes 控制平面你想要 X 个实例的 Y 应用程序，Kubernetes 将计算运行在 Kubernetes 节点上的 Y 应用程序实例数量，以确保实例数量为 X。如果实例太少，Kubernetes 将负责启动更多实例，而如果实例太多，多余的实例将被停止。

由于 Kubernetes 不断检查所请求的实例数量是否在运行中，所以在应用程序失败或节点失败的情况下，Kubernetes 将重新启动丢失的实例。

由于安装和管理 Kubernetes 的复杂性，多家公司已经开始销售简化其运营的 Kubernetes 发行版，并且他们愿意提供支持。

目前使用最广泛的发行版是 OpenShift：红帽 Kubernetes 发行版。

为了简化开发人员和运维团队的生活，Ansible 提供了`ansible-container`，正如我们在前一节中所看到的，这是一个用于创建容器以及支持容器整个生命周期的工具。

# 使用 ansible-container 部署到 Kubernetes

让我们学习如何运行刚刚用`ansible-container`构建的镜像。

首先，我们需要镜像本身，你应该已经有了，因为这是上一节的输出！

我们假设您可以访问用于测试的 Kubernetes 或 OpenShift 集群。设置这些超出了本书的范围，因此您可能希望查看 Minikube 或 Minishift 等分发版，这两者都旨在快速且易于设置，以便您可以快速开始学习这些技术。我们还需要正确配置`kubectl`客户端或`oc`客户端，根据我们部署的是 Kubernetes 还是 OpenShift。让我们开始吧：

1.  要将应用程序部署到集群，您需要更改`container.yml`文件，以便添加一些附加信息。更具体地说，我们需要添加一个名为`settings`和一个名为`k8s_namespace`的部分来声明我们的部署设置。此部分将如下所示：

```
k8s_namespace:
  name: http-server
  description: An HTTP server
  display_name: HTTP server
```

1.  现在我们已经添加了关于 Kubernetes 部署的必要信息，我们可以继续部署：

```
$ ansible-container --engine kubernetes deploy
```

一旦 Ansible 完成执行，您将能够在 Kubernetes 集群上找到`http-server`部署。

幕后发生的是，Ansible 有一组模块（其名称通常以`k8s`开头），用于驱动 Kubernetes 集群，并使用它们自动部署应用程序。

根据我们在上一节中构建的图像和本节开头添加的其他信息，Ansible 能够填充部署模板，然后使用`k8s`模块部署它。

现在您已经学会了如何在 Kubernetes 集群上部署容器，接下来您将学习如何使用 Ansible 与 Kubernetes 集群进行交互。

# 使用 Ansible 管理 Kubernetes 对象

现在您已经使用`ansible-container`部署了第一个应用程序，与该应用程序进行交互将非常有用。获取有关 Kubernetes 对象状态的信息或部署应用程序，更一般地与 Kubernetes API 进行交互，而无需使用`ansible-containers`。

# 安装 Ansible Kubernetes 依赖项

首先，您需要安装 Python `openshift`包（您可以通过 pip 或操作系统的打包系统安装它）。

我们现在准备好我们的第一个 Kubernetes playbook 了！

# 使用 Ansible 列出 Kubernetes 命名空间

Kubernetes 集群在内部有多个命名空间，通常可以使用`kubectl get namespaces`找到集群中的命名空间。您可以通过创建一个名为`k8s-ns-show.yaml`的文件来使用 Ansible 执行相同的操作，内容如下：

```
---
- hosts: localhost
  tasks:
    - name: Get information from K8s
      k8s_info:
        api_version: v1
        kind: Namespace
      register: ns
    - name: Print info
      debug:
        var: ns
```

我们现在可以执行此操作，如下所示：

```
$ ansible-playbook k8s-ns-show.yaml
```

现在您将在输出中看到有关命名空间的信息。

请注意代码的第七行（`kind: Namespace`），我们在其中指定了我们感兴趣的资源类型。您可以指定其他 Kubernetes 对象类型以查看它们（例如，您可以尝试使用部署、服务和 Pod 进行此操作）。

# 使用 Ansible 创建 Kubernetes 命名空间

到目前为止，我们已经学会了如何显示现有的命名空间，但通常，Ansible 被用于以声明方式实现期望的状态。因此，让我们创建一个名为`k8s-ns.yaml`的新的 playbook，内容如下：

```
---
- hosts: localhost
  tasks:
    - name: Ensure the myns namespace exists
      k8s:
        api_version: v1
        kind: Namespace
        name: myns
        state: present
```

在运行之前，我们可以执行`kubectl get ns`，以确保`myns`不存在。在我的情况下，输出如下：

```
$ kubectl get ns
NAME STATUS AGE
default Active 69m
kube-node-lease Active 69m
kube-public Active 69m
kube-system Active 69m
```

我们现在可以使用以下命令运行 playbook：

```
$ ansible-playbook k8s-ns.yaml
```

输出应该类似于以下内容：

```
PLAY [localhost] *******************************************************************

TASK [Gathering Facts] *************************************************************
ok: [localhost]

TASK [Ensure the myns namespace exists] ********************************************
changed: [localhost]

PLAY RECAP *************************************************************************
localhost : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

正如您所看到的，Ansible 报告说它改变了命名空间的状态。如果我再次执行`kubectl get ns`，很明显 Ansible 创建了我们期望的命名空间：

```
$ kubectl get ns
NAME STATUS AGE
default Active 74m
kube-node-lease Active 74m
kube-public Active 74m
kube-system Active 74m
myns Active 22s 
```

现在，让我们创建一个服务。

# 使用 Ansible 创建 Kubernetes 服务

到目前为止，我们已经看到了如何从 Ansible 创建命名空间，现在让我们在刚刚创建的命名空间中放置一个服务。让我们创建一个名为`k8s-svc.yaml`的新 playbook，内容如下：

```
---
- hosts: localhost
  tasks:
    - name: Ensure the Service mysvc is present
      k8s:
        state: present
        definition:
          apiVersion: v1
          kind: Service
          metadata:
            name: mysvc
            namespace: myns
          spec:
            selector:
              app: myapp
              service: mysvc
            ports:
              - protocol: TCP
                targetPort: 800
                name: port-80-tcp
                port: 80
```

在运行之前，我们可以执行`kubectl get svc`来确保命名空间中没有服务。在运行之前，请确保您在正确的命名空间中！在我的情况下，输出如下：

```
$ kubectl get svc
No resources found in myns namespace.
```

我们现在可以使用以下命令运行它：

```
$ ansible-playbook k8s-svc.yaml
```

输出应该类似于以下内容：

```
PLAY [localhost] *******************************************************************

TASK [Gathering Facts] *************************************************************
ok: [localhost]

TASK [Ensure the myns namespace exists] ********************************************
changed: [localhost]

PLAY RECAP *************************************************************************
localhost : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0 
```

正如您所看到的，Ansible 报告说它改变了服务状态。如果我再次执行`kubectl get svc`，很明显 Ansible 创建了我们期望的服务：

```
$ kubectl get svc
NAME TYPE CLUSTER-IP EXTERNAL-IP PORT(S) AGE
mysvc ClusterIP 10.0.0.84 <none> 80/TCP 10s
```

正如您所看到的，我们遵循了在命名空间情况下使用的相同过程，但是我们指定了不同的 Kubernetes 对象类型，并指定了所需的服务类型的各种参数。您可以对所有其他 Kubernetes 对象类型执行相同的操作。

现在您已经学会了如何处理 Kubernetes 集群，您将学习如何使用 Ansible 自动化 Docker。

# 使用 Ansible 自动化 Docker

Docker 现在是一个非常常见和普遍的工具。在生产中，它通常由编排器管理（或者至少应该在大多数情况下），但在开发中，环境通常直接使用。

使用 Ansible，您可以轻松管理您的 Docker 实例。

由于我们将要管理一个 Docker 实例，我们需要确保我们手头有一个，并且我们机器上的`docker`命令已经正确配置。我们需要这样做以确保在终端上运行`docker images`足够。假设您得到类似以下的结果：

```
REPOSITORY TAG IMAGE ID CREATED SIZE
```

这意味着一切都正常工作。如果您已经克隆了镜像，可能会提供更多行作为输出。

另一方面，假设它返回了类似于这样的东西：

```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

这意味着我们没有运行 Docker 守护程序，或者我们的 Docker 控制台配置不正确。

此外，确保您有`docker` Python 模块是很重要的，因为 Ansible 将尝试使用它与 Docker 守护程序进行通信。让我们来看一下：

1.  首先，我们需要创建一个名为`start-docker-container.yaml`的 playbook，其中包含以下代码：

```
---
- hosts: localhost
  tasks:
    - name: Start a container with a command
      docker_container:
        name: test-container
        image: alpine
        command:
          - echo
          - "Hello, World!"
```

1.  现在我们有了 Ansible playbook，我们只需要执行它：

```
$ ansible-playbook start-docker-container.yaml
```

正如您可能期望的那样，它将给您一个类似于以下的输出：

```
PLAY [localhost] *********************************************************************

TASK [Gathering Facts] ***************************************************************
ok: [localhost]

TASK [Start a container with a command] **********************************************
changed: [localhost]

PLAY RECAP ***************************************************************************
localhost : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0  
```

1.  现在我们可以检查我们的命令是否正确执行，如下所示：

```
$ docker container list -a
```

这将显示运行的容器：

```
CONTAINER ID IMAGE  COMMAND              CREATED       STATUS                        PORTS NAMES
c706ec55fc0d alpine "echo Hello, World!" 3 minutes ago Exited (0) About a minute ago       test-container
```

这证明了一个容器被执行。

要检查`echo`命令是否被执行，我们可以运行以下代码：

```
$ docker logs c706ec55fc0d
```

这将返回以下输出：

```
Hello, World!
```

在本节中，我们执行了`docker_container`模块。这不是 Ansible 用来控制 Docker 守护程序的唯一模块，但它可能是最广泛使用的模块之一，因为它用于控制在 Docker 上运行的容器。

其他模块包括以下内容：

+   `docker_config`：用于更改 Docker 守护程序的配置

+   `docker_container_info`：用于从容器中收集信息（检查）

+   `docker_network`：用于管理 Docker 网络配置

还有许多以`docker_`开头的模块，但实际上用于管理 Docker Swarm 集群，而不是 Docker 实例。一些示例如下：

+   `docker_node`：用于管理 Docker Swarm 集群中的节点

+   `docker_node_info`：用于检索 Docker Swarm 集群中特定节点的信息

+   `docker_swarm_info`：用于检索有关 Docker Swarm 集群的信息

正如我们将在下一节中看到的，还有许多模块可以用来管理以各种方式编排的容器。

现在您已经学会了如何使用 Ansible 自动化 Docker，您将探索面向容器的模块。

# 探索面向容器的模块

通常，当组织发展壮大时，他们开始在组织的不同部分使用多种技术。通常发生的另一件事是，部门发现某个供应商对他们很有效后，他们更倾向于尝试该供应商提供的新技术。这两个因素的混合以及时间（通常情况下，技术周期较少）最终会在同一组织内为同一个问题创建多种解决方案。

如果您的组织处于这种容器的情况下，Ansible 可以帮助您，因为它能够与大多数，如果不是所有的容器平台进行互操作。

很多时候，使用 Ansible 的最大问题是找到你需要使用的模块的名称，以实现你想要实现的目标。在本节中，我们将尝试帮助您解决这个问题，主要是在容器化领域，但这可能也有助于您寻找不同类型的模块。

所有 Ansible 模块研究的起点应该是模块索引（[`docs.ansible.com/ansible/latest/modules/modules_by_category.html`](https://docs.ansible.com/ansible/latest/modules/modules_by_category.html)）。通常情况下，您可以找到一个明显与您寻找的内容匹配的类别，但情况并非总是如此。

容器是这种例外情况之一（至少在撰写本文时是如此），因此没有“容器”类别。解决方案是转到所有模块。从这里，您可以使用浏览器的内置功能进行搜索（通常可以通过使用*Ctrl*+*F*来实现），以找到可能与包名称或简短描述匹配的字符串。

Ansible 中的每个模块都属于一个类别，但很多时候，模块适用于多个类别，因此并不总是容易找到它们。

例如，许多与容器服务相关的 Ansible 模块属于云模块类别（ECS、Docker、LXC、LXD 和 Podman），而其他模块属于集群模块类别（Kubernetes、OpenShift 等）。

为了进一步帮助您，让我们来看一下一些主要的容器平台和 Ansible 提供的主要模块。

2014 年，亚马逊网络服务推出了弹性容器服务（ECS），这是一种在其基础设施中部署和编排 Docker 容器的方式。在接下来的一年，亚马逊网络服务还推出了弹性容器注册表（ECR），这是一个托管的 Docker 注册表服务。该服务并没有像 AWS 希望的那样普及，因此在 2018 年，AWS 推出了弹性 Kubernetes 服务（EKS），以允许希望在 AWS 上运行 Kubernetes 的人拥有一个托管服务。如果您正在使用或计划使用 EKS，这只是一个标准的托管 Kubernetes 集群，因此您可以使用我们即将介绍的 Kubernetes 特定模块。如果您决定使用 ECS，有几个模块可以帮助您。最重要的是`ecs_cluster`，它允许您创建或终止 ECS 集群；`ecs_ecr`，它允许您管理 ECR；`ecs_service`，它允许您在 ECS 中创建、终止、启动或停止服务；以及`ecs_task`，它允许您在 ECS 中运行、启动或停止任务。除此之外，还有`ecs_service_facts`，它允许 Ansible 列出或描述 ECS 中的服务。

2018 年，微软 Azure 宣布了 Azure 容器服务（ACS），然后宣布了 Azure Kubernetes 服务（AKS）。这些服务由 Kubernetes 解决方案管理，因此可以使用 Kubernetes 模块来管理。除此之外，Ansible 还提供了两个特定的模块：`azure_rm_acs`模块允许我们创建、更新和删除 Azure 容器服务实例，而`azure_rm_aks`模块允许我们创建、更新和删除 Azure Kubernetes 服务实例。

Google Cloud 于 2015 年推出了**Google Kubernetes Engine**（**GKE**）。GKE 是 Google Cloud Platform 的托管 Kubernetes 版本，因此与 Ansible Kubernetes 模块兼容。除此之外，还有各种 GKE 特定的模块，其中一些如下：

+   `gcp_container_cluster`：允许您创建 GCP Cluster

+   `gcp_container_cluster_facts`：允许您收集有关 GCP Cluster 的信息

+   `gcp_container_node_pool`：允许您创建 GCP NodePool

+   `gcp_container_node_pool_facts`：允许您收集有关 GCP NodePool 的信息

Red Hat 于 2011 年启动了 OpenShift，当时它是基于自己的容器运行时的。在 2015 年发布的第 3 版中，它完全基于 Kubernetes 重新构建，因此所有 Ansible Kubernetes 模块都可以使用。除此之外，还有`oc`模块，目前仍然存在但处于弃用状态，更倾向于使用 Kubernetes 模块。

2015 年，Google 发布了 Kubernetes，并迅速形成了一个庞大的社区。Ansible 允许您使用一些模块来管理您的 Kubernetes 集群：

+   `k8s`：允许您管理任何类型的 Kubernetes 对象

+   `k8s_auth`：允许您对需要显式登录的 Kubernetes 集群进行身份验证

+   `k8s_facts`：允许您检查 Kubernetes 对象

+   `k8s_scale`：允许您为部署、副本集、复制控制器或作业设置新的大小

+   `k8s_service`：允许您在 Kubernetes 上管理服务

LXC 和 LXD 也是可以在 Linux 中运行容器的系统。由于以下模块的支持，这些系统也受到 Ansible 的支持：

+   `lxc_container`：允许您管理 LXC 容器

+   `lxd_container`：允许您管理 LXD 容器

+   `lxd_profile`：允许您管理 LXD 配置文件

现在您已经学会了如何探索面向容器的模块，接下来将学习如何针对亚马逊网络服务进行自动化。

# 针对亚马逊网络服务进行自动化

在许多组织中，广泛使用云提供商，而在其他组织中，它们只是被引入。但是，无论如何，您可能都必须处理一些云提供商来完成工作。AWS 是最大的，也是最古老的，可能是您必须使用的东西。

# 安装

要能够使用 Ansible 自动化您的 Amazon Web Service 资源，您需要安装`boto`库。要执行此操作，请运行以下命令：

```
$ pip install boto
```

现在您已经安装了所有必要的软件，可以设置身份验证了。

# 身份验证

`boto`库在`~/.aws/credentials`文件中查找必要的凭据。确保凭据文件正确配置有两种不同的方法。

可以使用 AWS CLI 工具。或者，可以通过创建具有以下结构的文件来使用您选择的文本编辑器：

```
[default] aws_access_key_id = [YOUR_KEY_HERE] aws_secret_access_key = [YOUR_SECRET_ACCESS_KEY_HERE]
```

现在您已经创建了具有必要凭据的文件，`boto`将能够针对您的 AWS 环境进行操作。由于 Ansible 对 AWS 系统的每一次通信都使用`boto`，这意味着即使您不必更改任何特定于 Ansible 的配置，Ansible 也将被适当配置。

# 创建您的第一台机器

现在 Ansible 能够连接到您的 AWS 环境，您可以按照以下步骤进行实际的 playbook：

1.  创建具有以下内容的`aws.yaml` Playbook：

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
    - name: Setup instance
      ec2:
        assign_public_ip: true
        image: ami-3548444c
        region: eu-west-1
        exact_count: 1
        key_name: fale
        count_tag:
          Name: ws01.ansible2cookbook.com
        instance_tags:
          Name: ws01.ansible2cookbook.coms
        instance_type: t2.micro
        group_id: '{{ aws_simple_wssg.group_id }}'
        vpc_subnet_id: '{{ aws_simple_subnet.subnets.0.id }}'
        volumes:
          - device_name: /dev/sda1
            volume_type: gp2
            volume_size: 10
            delete_on_termination: True
```

1.  使用以下命令运行它：

```
$ ansible-playbook aws.yaml
```

此命令将返回类似以下内容：

```
PLAY [localhost] **********************************************************************************

TASK [Gathering Facts] ****************************************************************************
ok: [localhost]

TASK [Ensure key pair is present] *****************************************************************
ok: [localhost]

TASK [Gather information of the EC2 VPC net in eu-west-1] *****************************************
ok: [localhost]

TASK [Gather information of the EC2 VPC subnet in eu-west-1] **************************************
ok: [localhost]

TASK [Ensure wssg Security Group is present] ******************************************************
ok: [localhost]

TASK [Setup instance] *****************************************************************************
changed: [localhost]

PLAY RECAP ****************************************************************************************
localhost : ok=6 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0 
```

如果您检查 AWS 控制台，您将看到现在有一台机器正在运行！

要在 AWS 中启动虚拟机，我们需要准备一些东西，如下所示：

+   一个 SSH 密钥对

+   一个网络

+   一个子网络

+   一个安全组

默认情况下，您的帐户中已经有一个网络和一个子网络，但您需要检索它们的 ID。

这就是为什么我们首先将 SSH 密钥对的公共部分上传到 AWS，然后查询有关网络和子网络的信息，然后确保我们想要使用的安全组存在，最后触发机器构建。

现在您已经学会了如何针对亚马逊网络服务进行自动化，您将学习如何通过自动化来补充谷歌云平台。

# 通过自动化来补充谷歌云平台

另一个全球云服务提供商是谷歌，其谷歌云平台。谷歌对云的方法与其他提供商的方法相对不同，因为谷歌不试图在虚拟环境中模拟数据中心。这是因为谷歌希望重新思考云提供的概念，以简化它。

# 安装

在您开始使用 Ansible 与谷歌云平台之前，您需要确保已安装适当的组件。具体来说，您需要 Python 的`requests`和`google-auth`模块。要安装这些模块，请运行以下命令：

```
$ pip install requests google-auth
```

现在您已经准备好所有依赖项，可以开始认证过程。

# 认证

在谷歌云平台中获得工作凭据的两种不同方法：

+   服务帐户

+   机器帐户

第一种方法在大多数情况下是建议的，因为第二种方法仅适用于在谷歌云平台环境中直接运行 Ansible 的情况。

创建服务帐户后，您应该设置以下环境变量：

+   `GCP_AUTH_KIND`

+   `GCP_SERVICE_ACCOUNT_EMAIL`

+   `GCP_SERVICE_ACCOUNT_FILE`

+   `GCP_SCOPES`

现在，Ansible 可以使用适当的服务帐户。

第二种方法是最简单的，因为如果您在谷歌云实例中运行 Ansible，它将能够自动检测到机器帐户。

# 创建您的第一台机器

现在 Ansible 能够连接到您的 GCP 环境，您可以继续进行实际的 Playbook：

1.  创建`gce.yaml` Playbook，并包含以下内容：

```
---
- hosts: localhost
  tasks:
    - name: create a instance
      gcp_compute_instance:
        name: TestMachine
        machine_type: n1-standard-1
        disks:
        - auto_delete: 'true'
          boot: 'true'
          initialize_params:
            source_image: family/centos-7
            disk_size_gb: 10
        zone: eu-west1-c
        auth_kind: serviceaccount
        service_account_file: "~/sa.json"
        state: present
```

使用以下命令执行它：

```
$ ansible-playbook gce.yaml
```

这将创建以下输出：

```
PLAY [localhost] **********************************************************************************

TASK [Gathering Facts] ****************************************************************************
ok: [localhost]

TASK [create a instance] **************************************************************************
changed: [localhost]

PLAY RECAP ****************************************************************************************
localhost : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0 
```

与 AWS 示例一样，在云中运行机器对 Ansible 来说非常容易。

在 GCE 的情况下，您不需要预先设置网络，因为 GCE 默认设置将提供一个功能齐全的机器。

与 AWS 一样，您可以使用的模块列表非常庞大。您可以在[`docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#google`](https://docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#google)找到完整的列表。

现在您已经学会了如何通过自动化来补充谷歌云平台，您将学习如何无缝地执行与 Azure 的自动化集成。

# 与 Azure 的无缝自动化集成

Ansible 可以管理的另一个全球云是 Microsoft Azure。

与 AWS 类似，Azure 集成需要在 Playbooks 中执行相当多的步骤。

您需要首先设置认证，以便 Ansible 被允许控制您的 Azure 帐户。

# 安装

要让 Ansible 管理 Azure 云，您需要安装 Python 的 Azure SDK。通过执行以下命令来完成：

```
$ pip install 'ansible[azure]'
```

现在您已经准备好所有依赖项，可以开始认证过程。

# 认证

有不同的方法可以确保 Ansible 能够为您管理 Azure，这取决于您的 Azure 帐户设置方式，但它们都可以在`~/.azure/credentials`文件中配置。

如果您希望 Ansible 使用 Azure 帐户的主要凭据，您需要创建一个类似以下内容的文件：

```
[default] subscription_id = [YOUR_SUBSCIRPTION_ID_HERE] client_id = [YOUR_CLIENT_ID_HERE] secret = [YOUR_SECRET_HERE] tenant = [YOUR_TENANT_HERE]
```

如果您希望使用用户名和密码与 Active Directories，可以这样做：

```
[default] ad_user = [YOUR_AD_USER_HERE] password = [YOUR_AD_PASSWORD_HERE]
```

最后，您可以选择使用 ADFS 进行 Active Directory 登录。在这种情况下，您需要设置一些额外的参数。您最终会得到类似这样的东西：

```
[default] ad_user = [YOUR_AD_USER_HERE] password = [YOUR_AD_PASSWORD_HERE] client_id = [YOUR_CLIENT_ID_HERE] tenant = [YOUR_TENANT_HERE] adfs_authority_url = [YOUR_ADFS_AUTHORITY_URL_HERE]
```

相同的参数可以作为参数传递，也可以作为环境变量传递，如果更合理的话。

# 创建你的第一台机器

现在，Ansible 已经能够连接到你的 Azure 环境，你可以继续进行实际的 Playbook 了。

1.  创建`azure.yaml` Playbook，内容如下：

```
---
- hosts: localhost
  tasks:
    - name: Ensure the Storage Account is present
      azure_rm_storageaccount:
        resource_group: Testing
        name: mysa
        account_type: Standard_LRS
    - name: Ensure the Virtual Network is present
      azure_rm_virtualnetwork:
        resource_group: Testing
        name: myvn
        address_prefixes: "10.10.0.0/16"
    - name: Ensure the Subnet is present
      azure_rm_subnet:
        resource_group: Testing
        name: mysn
        address_prefix: "10.10.0.0/24"
        virtual_network: myvn
    - name: Ensure that the Public IP is set
      azure_rm_publicipaddress:
        resource_group: Testing
        allocation_method: Static
        name: myip
    - name: Ensure a Security Group allowing SSH is present
      azure_rm_securitygroup:
        resource_group: Testing
        name: mysg
        rules:
          - name: SSH
            protocol: Tcp
            destination_port_range: 22
            access: Allow
            priority: 101
            direction: Inbound
    - name: Ensure the NIC is present
      azure_rm_networkinterface:
        resource_group: Testing
        name: testnic001
        virtual_network: myvn
        subnet: mysn
        public_ip_name: myip
        security_group: mysg
    - name: Ensure the Virtual Machine is present
      azure_rm_virtualmachine:
        resource_group: Testing
        name: myvm01
        vm_size: Standard_D1
        storage_account: mysa
        storage_container: myvm01
        storage_blob: myvm01.vhd
        admin_username: admin
        admin_password: Password!
        network_interfaces: testnic001
        image:
          offer: CentOS
          publisher: OpenLogic
          sku: '8.0'
          version: latest
```

1.  我们可以使用以下命令运行它：

```
$ ansible-playbook azure.yaml
```

这将返回类似以下的结果：

```
PLAY [localhost] **********************************************************************************

TASK [Gathering Facts] ****************************************************************************
ok: [localhost]

TASK [Ensure the Storage Account is present] ******************************************************
changed: [localhost] TASK [Ensure the Virtual Network is present] ******************************************************
changed: [localhost]

TASK [Ensure the Subnet is present] ***************************************************************
changed: [localhost]

TASK [Ensure that the Public IP is set] ***********************************************************
changed: [localhost]

TASK [Ensure a Security Group allowing SSH is present] ********************************************
changed: [localhost]

TASK [Ensure the NIC is present] ******************************************************************
changed: [localhost]

TASK [Ensure the Virtual Machine is present] ******************************************************
changed: [localhost]

PLAY RECAP ****************************************************************************************
localhost : ok=8 changed=7 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0 
```

你现在可以在 Azure 云中运行你的机器了！

正如你所看到的，在 Azure 中，你需要在发出创建机器命令之前准备好所有资源。这就是你首先创建存储帐户、虚拟网络、子网、公共 IP、安全组和 NIC，然后只有在那时，才创建机器本身的原因。

除了市场上的三大主要参与者外，还有许多其他云选项。一个非常有趣的选择是 RackSpace，因为它的历史：Rackspace Cloud。

# 通过 Rackspace Cloud 扩展你的环境

Rackspace 是公共云业务中最早的公司之一。此外，Rackspace 在 2010 年与 NASA 联合创办了 OpenStack。在过去的 10 年中，Rackspace 一直是云基础设施、OpenStack 以及更广泛的托管领域的非常有影响力的提供商。

# 安装

为了能够从 Ansible 管理 Rackspace，你需要安装`pyrax`。

安装它的最简单方法是运行以下命令：

```
$ pip install pyrax
```

如果可用，你也可以通过系统包管理器安装它。

# 认证

由于`pyrax`没有凭据文件的默认位置，你需要创建一个文件，然后通过指示`pyrax`在文件位置设置一个环境变量来做到这一点。

让我们从在`~/.rackspace_credentials`中创建一个文件开始，文件内容如下：

```
[rackspace_cloud] username = [YOUR_USERNAME_HERE] api_key = [YOUR_API_KEY_HERE]
```

现在，我们可以通过将`RAX_CREDS_FILE`变量设置为正确的位置来继续进行：

```
**$ export RAX_CREDS_FILE=~/.rackspace_credentials** 
```

让我们继续使用 Rackspace Cloud 创建一台机器。

# 创建你的第一台机器

在 Rackspace Cloud 中创建一台机器非常简单，因为它是一个单步操作：

1.  创建`rax.yaml` Playbook，内容如下：

```
---
- hosts: localhost
  tasks:
    - name: Ensure the my_machine exists
      rax:
        name: my_machine
        flavor: 4
        image: centos-8
        count: 1
        group: my_group
        wait: True
```

1.  现在，你可以使用以下命令来执行它：

```
$ ansible-playbook rax.yaml
```

1.  这应该会产生类似以下的结果：

```
PLAY [localhost] **********************************************************************************

TASK [Gathering Facts] ****************************************************************************
ok: [localhost]

TASK [Ensure the my_machine exists] ***************************************************************
changed: [localhost]

PLAY RECAP ****************************************************************************************
localhost : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0 
```

正如你所看到的，在 Rackspace Cloud 中创建机器非常简单直接，而默认的 Ansible 模块已经集成了一些有趣的概念，比如组和计数。这些选项允许你以与单个实例相同的方式创建和管理实例组。

# 使用 Ansible 来编排 OpenStack

与我们刚讨论的各种公共云服务相反，OpenStack 允许你创建自己的（私有）云。

私有云的缺点是它们向管理员和用户暴露了更多的复杂性，但这也是它们可以被定制以完美适应组织的原因。

# 安装

能够使用 Ansible 控制 OpenStack 集群的第一步是确保安装了`openstacksdk`。

要安装`openstacksdk`，你需要执行以下命令：

```
$ pip install openstacksdk
```

现在你已经安装了`openstacksdk`，你可以开始认证过程了。

# 认证

由于 Ansible 将使用`openstacksdk`作为其后端，你需要确保`openstacksdk`能够连接到 OpenStack 集群。

为了做到这一点，你可以更改`~/.config/openstack/clouds.yaml`文件，确保为你想要使用它的云配置。

一个正确的 OpenStack 凭据集的示例可能如下所示：

```
clouds:
 test_cloud: region_name: MyRegion auth: auth_url: http://[YOUR_AUTH_URL_HERE]:5000/v2.0/     username: [YOUR_USERNAME_HERE]
 password: [YOUR_PASSWORD_HERE] project_name: myProject
```

如果愿意，也可以设置不同的配置文件位置，将`OS_CLIENT_CONFIG_FILE`变量作为环境变量导出。

现在你已经设置了所需的安全性，以便 Ansible 可以管理你的集群，你可以创建你的第一个 Playbook 了。

# 创建你的第一台机器

由于 OpenStack 非常灵活，它的许多组件可以有许多不同的实现，这意味着它们在行为上可能略有不同。为了能够适应各种情况，管理 OpenStack 的 Ansible 模块往往具有较低的抽象级别，与许多公共云的模块相比。

因此，要创建一台机器，您需要确保公共 SSH 密钥为 OpenStack 所知，并确保 OS 镜像也存在。在这样做之后，您可以设置网络、子网络和路由器，以确保我们要创建的机器可以通过网络进行通信。然后，您可以创建安全组及其规则，以便该机器可以接收连接（在本例中为 ping 和 SSH 流量）。最后，您可以创建一个机器实例。

要完成我们刚刚描述的所有步骤，您需要创建一个名为`openstack.yaml`的文件，其中包含以下内容：

```
---
- hosts: localhost
  tasks:
    - name: Ensure the SSH key is present on OpenStack
      os_keypair:
        state: present
        name: ansible_key
        public_key_file: "{{ '~' | expanduser }}/.ssh/id_rsa.pub"
    - name: Ensure we have a CentOS image
      get_url:
        url: http://cloud.centos.org/centos/8/x86_64/images/CentOS-8-GenericCloud-8.1.1911-20200113.3.x86_64.qcow2
        dest: /tmp/CentOS-8-GenericCloud-8.1.1911-20200113.3.x86_64.qcow2
    - name: Ensure the CentOS image is in OpenStack
      os_image:
        name: centos
        container_format: bare
        disk_format: qcow2
        state: present
        filename: /tmp/CentOS-8-GenericCloud-8.1.1911-20200113.3.x86_64.qcow2
    - name: Ensure the Network is present
      os_network:
        state: present
        name: mynet
        external: False
        shared: False
      register: net_out
    - name: Ensure the Subnetwork is present
      os_subnet:
        state: present
        network_name: "{{ net_out.id }}"
        name: mysubnet
        ip_version: 4
        cidr: 192.168.0.0/24
        gateway_ip: 192.168.0.1
        enable_dhcp: yes
        dns_nameservers:
          - 8.8.8.8
    - name: Ensure the Router is present
      os_router:
        state: present
        name: myrouter
        network: nova
        external_fixed_ips:
          - subnet: nova
        interfaces:
          - mysubnet
    - name: Ensure the Security Group is present
      os_security_group:
        state: present
        name: mysg
    - name: Ensure the Security Group allows ICMP traffic
      os_security_group_rule:
        security_group: mysg
        protocol: icmp
        remote_ip_prefix: 0.0.0.0/0
    - name: Ensure the Security Group allows SSH traffic
      os_security_group_rule:
        security_group: mysg
        protocol: tcp
        port_range_min: 22
        port_range_max: 22
        remote_ip_prefix: 0.0.0.0/0
    - name: Ensure the Instance exists
      os_server:
        state: present
        name: myInstance
        image: centos
        flavor: m1.small
        security_groups: mysg
        key_name: ansible_key
        nics:
          - net-id: "{{ net_out.id }}"
```

现在，您可以运行它，如下：

```
$ ansible-playbook openstack.yaml
```

输出应该如下：

```
PLAY [localhost] **********************************************************************************

TASK [Gathering Facts] ****************************************************************************
ok: [localhost]

TASK [Ensure the SSH key is present on OpenStack] *************************************************
changed: [localhost]

TASK [Ensure we have a CentOS image] **************************************************************
changed: [localhost]

TASK [Ensure the CentOS image is in OpenStack] ****************************************************
changed: [localhost]

TASK [Ensure the Network is present] **************************************************************
changed: [localhost]

TASK [Ensure the Subnetwork is present] ***********************************************************
changed: [localhost]

TASK [Ensure the Router is present] ***************************************************************
changed: [localhost]

TASK [Ensure the Security Group is present] *******************************************************
changed: [localhost]

TASK [Ensure the Security Group allows ICMP traffic] **********************************************
changed: [localhost]

TASK [Ensure the Security Group allows SSH traffic] ***********************************************
changed: [localhost]

TASK [Ensure the Instance exists] *****************************************************************
changed: [localhost]

PLAY RECAP ****************************************************************************************
localhost : ok=11 changed=10 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0 
```

正如您所看到的，这个过程比我们涵盖的公共云要长。但是，您确实可以上传您想要运行的镜像，这是许多云不允许的（或者允许的过程非常复杂）。

# 总结

在本章中，您学习了如何使用 playbooks 自动化任务，从设计和构建容器到在 Kubernetes 上管理部署，以及管理 Kubernetes 对象和使用 Ansible 自动化 Docker。您还探索了可以帮助您自动化云环境的模块，如 AWS、Google Cloud Platform、Azure、Rackspace 和 OpenShift。您还了解了各种云提供商使用的不同方法，包括它们的默认值以及您总是需要添加的参数。

现在您已经了解了 Ansible 如何与云进行交互，您可以立即开始自动化云工作流程。还记得要查看*进一步阅读*部分的文档，以查看 Ansible 支持的所有云模块及其选项。

在下一章中，您将学习如何排除故障和创建测试策略。

# 问题

1.  以下哪个不是 GKE Ansible 模块？

A) `gcp_container_cluster`

B) `gcp_container_node_pool`

C) `gcp_container_node_pool_facts`

D) `gcp_container_node_pool_count`

E) `gcp_container_cluster_facts`

1.  真或假：为了管理 Kubernetes 中的容器，您需要在设置部分中添加`k8s_namespace`。

A) True

B) False

1.  真或假：在使用 Azure 时，在创建实例之前，您不需要创建**网络接口控制器**（**NIC**）。

A) True

B) False

1.  真或假：`Ansible-Container`是与 Kubernetes 和 Doc 交互的唯一方式。

A) True

B) False

1.  真或假：在使用 AWS 时，在创建 EC2 实例之前，需要创建一个安全组。

A) True

B) False

# 进一步阅读

+   更多 AWS 模块：[`docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#amazon`](https://docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#amazon)

+   更多 Azure 模块：[`docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#azure`](https://docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#azure)

+   更多 Docker 模块：[`docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#docker`](https://docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#docker)

+   更多 GCP 模块：[`docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#google`](https://docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#google)

+   更多 OpenStack 模块：[`docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#openstack`](https://docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#openstack)

+   更多的 Rackspace 模块：[`docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#rackspace`](https://docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html#rackspace)
