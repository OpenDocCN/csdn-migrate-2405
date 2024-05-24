# 红帽企业 Linux 故障排除指南（二）

> 原文：[`zh.annas-archive.org/md5/4376391B1DCEF164F3ED989478713CD5`](https://zh.annas-archive.org/md5/4376391B1DCEF164F3ED989478713CD5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用函数创建构建块

在本章中，我们将深入了解函数的奇妙世界。我们可以将这些视为创建强大和适应性脚本的模块化构建块。通过创建函数，我们将代码添加到一个单独的构建块中，与脚本的其余部分隔离开来。专注于改进单个函数要比尝试改进整个脚本容易得多。没有函数，很难专注于问题区域，代码经常重复，这意味着需要在许多位置进行更新。函数被命名为代码块或脚本中的脚本，并且它们可以克服与更复杂代码相关的许多问题。

随着我们在本章中的学习，我们将涵盖以下主题：

+   函数

+   向函数传递参数

+   返回值

+   使用函数的菜单

# 介绍函数

函数是作为**命名元素**存在于内存中的代码块。这些元素可以在 shell 环境中创建，也可以在脚本执行中创建。当在命令行上发出命令时，首先检查别名，然后检查匹配的函数名称。要显示驻留在您的 shell 环境中的函数，可以使用以下代码：

```
$ declare -F

```

输出将根据您使用的发行版和创建的函数数量而变化。在我的 Raspbian OS 上，部分输出显示在以下截图中：

![介绍函数](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00064.jpeg)

使用`-f`选项，您可以显示函数及其相关定义。但是，如果我们只想看到单个函数定义，我们可以使用`type`命令：

```
$ type quote

```

前面的代码示例将显示`quote`函数的代码块，如果它存在于您的 shell 中。我们可以在以下截图中看到此命令的输出：

![介绍函数](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00065.jpeg)

在 bash 中，`quote`函数会在提供的输入参数周围插入单引号。例如，我们可以展开`USER`变量并将值显示为字符串文字；这在以下截图中显示。截图捕获了命令和输出：

![介绍函数](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00066.jpeg)

大多数代码都可以用伪代码表示，显示一个示例布局。函数也不例外，创建函数的代码列在以下示例中：

```
function <function-name> {
<code to execute>
}
```

该函数创建时没有`do`和`done`块，就像我们在之前的循环中使用的那样。大括号的目的是定义代码块的边界。

以下是一个简单的函数，用于显示聚合系统信息的代码。这可以在命令行中创建，并将驻留在您的 shell 中。这将不会保留登录信息，并且在关闭 shell 或取消函数设置时将丢失。要使函数持久存在，我们需要将其添加到用户帐户的登录脚本中。示例代码如下：

```
$ function show_system {
echo "The uptime is:"
uptime
echo
echo "CPU Detail"
lscpu
echo
echo "User list"
who
}

```

我们可以使用`type`命令打印函数的详细信息，类似于之前的示例；这在以下截图中显示：

![介绍函数](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00067.jpeg)

要执行函数，我们只需输入`show_system`，我们将看到静态文本和来自`uptime`、`lscpu`和`who`三个命令的输出。当然，这是一个非常简单的函数，但我们可以通过允许在运行时传递参数来开始添加更多功能。

# 向函数传递参数

在本章的前面，我们将函数称为脚本中的脚本，我们仍将保持这种类比。类似于脚本可以有输入参数，我们可以创建接受参数的函数，使它们的操作不那么静态。在我们开始编写脚本之前，我们可以看一下命令行中一个有用的函数。

### 提示

我最讨厌过度注释的配置文件，尤其是存在文档详细说明可用选项的情况。

GNU Linux 命令`sed`可以轻松地编辑文件并删除注释行和空行。我们在这里引入了流编辑器`sed`，但我们将在下一章节中更详细地讨论它。

进行原地编辑的`sed`命令行将是：

```
$ sed -i.bak '/^\s*#/d;/^$/d' <filename>

```

我们可以通过逐个元素地分解命令行来进行取证。让我们深入研究一下：

+   `sed -i.bak`：这会编辑文件并创建一个带有扩展名`.bak`的备份。原始文件将以`<filename>.bak`的形式可访问。

+   `/^`：以...开头的行，也就是行的第一个字符。

+   `\s*`：这意味着任意数量的空白，包括没有空格或制表符。

+   `#/`：后跟注释。整体上`/^\s*#/`表示我们正在寻找以注释或空格和注释开头的行。

+   `d`：删除匹配行的操作。

+   `; /^$/d`：分号用于分隔表达式，第二个表达式与第一个类似，但这次我们准备删除空行或以行结束标记`$`开头的行。

将此移入函数中，我们只需要考虑一个好名字。我喜欢在函数名中加入动词；这有助于确保唯一性并确定函数的目的。我们将创建`clean_file`函数如下：

```
$ function clean_file {
 sed -i.bak '/^\s*#/d;/^$/d' "$1"
}

```

与脚本中一样，我们使用位置参数来接受命令行参数。我们可以在函数中用`$1`替换之前使用的硬编码文件名。我们将引用这个变量以防止文件名中有空格。为了测试`clean_file`函数，我们将复制一个系统文件并使用副本进行操作。这样，我们可以确保不会对任何系统文件造成伤害。我们向所有读者保证，在编写本书的过程中没有损坏任何系统文件。以下是我们需要遵循的详细步骤，以对新函数进行测试：

1.  按照描述创建`clean_file`函数。

1.  使用`cd`命令而不带参数切换到你的主目录。

1.  将时间配置文件复制到你的主目录：`cp /etc/ntp.conf $HOME`。

1.  使用以下命令计算文件中的行数：`wc -l $HOME/ntp.conf`。

1.  现在，使用以下命令删除注释和空行：`clean_file $HOME/ntp.conf`。

1.  现在，使用`wc -l $HOME/ntp.conf`重新计算行数。

1.  从我们创建的原始备份中：`wc -l $HOME/ntp.conf.bak`。

命令序列如下截图所示：

![将参数传递给函数](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00068.jpeg)

我们可以使用执行函数时提供的参数将函数的注意力引向所需的文件。如果我们需要保留此函数，那么我们应该将其添加到登录脚本中。但是，如果我们想要在 shell 脚本中测试这个函数，我们可以创建以下文件来做这个练习，并练习我们学到的其他一些元素。我们需要注意，函数应该始终在脚本的开头创建，因为它们需要在被调用时存储在内存中。只需想象你的函数需要在你扣动扳机之前被解锁和加载。

我们将创建一个新的 shell 脚本`$HOME/bin/clean.sh`，并且像往常一样，需要设置执行权限。脚本的代码如下：

```
#!/bin/bash
# Script will prompt for filename
# then remove commented and blank lines

function is_file {
    if [ ! -f "$1" ] ; then
        echo "$1 does not seem to be a file"
        exit 2
    fi
}

function clean_file {
    is_file "$1"
    BEFORE=$(wc -l "$1")
    echo "The file $1 starts with $BEFORE"
    sed -i.bak '/^\s*#/d;/^$/d' "$1"
    AFTER=$(wc -l "$1")
    echo "The file $1 is now $AFTER"
}

read -p "Enter a file to clean: "
clean_file "$REPLY"
exit 1
```

我们在脚本中提供了两个函数。第一个`is_file`只是测试以确保我们输入的文件名是一个普通文件。然后我们声明`clean_file`函数并添加了一些额外的功能，显示操作前后文件的行数。我们还可以看到函数可以被嵌套，并且我们用`clean_file`调用`is_file`函数。

没有函数定义，我们在文件末尾只有三行代码，可以在之前的代码块中看到，并保存为`$HOME/bin/clean.sh`。我们首先提示输入文件名，然后运行`clean_file`函数，该函数又调用`is_file`函数。这里主要是主要代码的简单性。复杂性在函数中，因为每个函数都可以作为一个独立的单元进行处理。

我们现在可以测试脚本的操作，首先使用一个错误的文件名，如下面的截图所示：

![向函数传递参数](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00069.jpeg)

现在我们已经看到了对一个不正确的文件的操作，我们可以再试一次，使用一个实际的文件！我们可以使用之前操作过的同一个系统文件。我们需要首先将文件恢复到它们的原始状态：

```
$ cd $HOME
$ rm $HOME/ntp.conf
$ mv ntp.conf.bak ntp.conf

```

文件现在准备好了，我们可以在`$HOME`目录中执行脚本，如下面的截图所示：

![向函数传递参数](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00070.jpeg)

# 从函数返回值

每当我们在函数内打印在屏幕上的语句时，我们可以看到它们的结果。然而，很多时候我们希望函数在脚本中填充一个变量而不显示任何内容。在这种情况下，我们在函数中使用`return`。当我们从用户那里获得输入时，这一点尤为重要。我们可能更喜欢将输入转换为已知的情况，以使条件测试更容易。将代码嵌入函数中允许它在脚本中被多次使用。下面的代码显示了我们如何通过创建`to_lower`函数来实现这一点：

```
function to_lower ()
{
    input="$1"
    output=$(tr [A-Z] [a-z] <<<"$input")
return $output
}
```

通过逐步分析代码，我们可以开始理解这个函数的操作：

+   `input="$1"`：这更多是为了方便，我们将第一个输入参数分配给一个命名变量输入。

+   `output=$(tr [A-Z] [a-z] <<< "$input")`：这是函数的主要引擎，其中发生从大写到小写的转换。使用 here string 操作符`<<<`允许我们扩展变量以读取到`tr`程序的内容。这是一种输入重定向形式。

+   `return$output`：这是我们创建返回值的方法。

这个函数的一个用途将在一个读取用户输入并简化测试以查看他们是否选择了`Q`或`q`的脚本中。这可以在以下代码片段中看到：

```
function to_lower ()
{
    input="$1"
    output=$(tr [A-Z] [a-z] <<< "$input")
return $output
}

while true
do
  read -p "Enter c to continue or q to exit: "
  $REPLY=$(to_lower "$REPLY")
  if [ $REPLY = "q" ] ; then
    break
  fi

done
echo "Finished"
```

# 在菜单中使用函数

在上一章，第六章，*使用循环迭代*，我们创建了`menu.sh`文件。菜单是使用函数的很好的目标，因为`case`语句非常简单地维护单行条目，而复杂性仍然可以存储在每个函数中。我们应该考虑为每个菜单项创建一个函数。如果我们将之前的`$HOME/bin/menu.sh`复制到`$HOME/bin/menu2.sh`，我们可以改进功能。新菜单应该如下代码所示：

```
#!/bin/bash
# Author: @theurbanpenguin
# Web: www.theurbapenguin.com
# Sample menu with functions
# Last Edited: Sept 2015

function to_lower {
    input="$1"
    output=$(tr [A-Z] [a-z] <<< "$input")
return $output
}

function do_backup {
    tar -czvf $HOME/backup.tgz ${HOME}/bin
}

function show_cal {
    if [ -x /usr/bin/ncal ] ; then
      command="/usr/bin/ncal -w"
    else
      command="/usr/bin/cal"
    fi
    $command
}

while true
do
  clear
  echo "Choose an item: a, b or c"
  echo "a: Backup"
  echo "b: Display Calendar"
  echo "c: Exit"
  read -sn1
  REPLY=$(to_lower "$REPLY")
  case "$REPLY" in
    a) do_backup;;
    b) show_cal;;
    c) exit 0;;
  esac
  read -n1 -p "Press any key to continue"
done
```

正如我们所看到的，我们仍然保持`case`语句的简单性；然而，我们可以通过函数来增加脚本的复杂性。例如，当选择日历的选项 b 时，我们现在检查`ncal`命令是否可用。如果可用，我们使用`ncal`并使用`-w`选项来打印周数。我们可以在下面的截图中看到这一点，我们选择显示日历并安装`ncal`。

![在菜单中使用函数](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00071.jpeg)

我们也不必担心大写锁定键，因为`to_lower`函数将我们的选择转换为小写。随着时间的推移，很容易向函数中添加额外的元素，因为我们知道只会影响到单个函数。

# 总结

我们在脚本编写方面仍在飞速进步。我希望这些想法能留在你心中，并且你会发现代码示例很有用。函数对于脚本的易维护性和最终功能非常重要。脚本越容易维护，你就越有可能随着时间的推移添加改进。我们可以在命令行或脚本中定义函数，但在使用之前，它们需要被包含在脚本中。

函数本身在脚本运行时加载到内存中，但只要脚本被分叉而不是被源化，它们将在脚本完成后从内存中释放。在本章中，我们已经稍微涉及了`sed`，在下一章中我们将更多地学习如何使用流编辑器（`sed`）。`sed`命令非常强大，我们可以在脚本中充分利用它。


# 第八章：介绍 sed

在上一章中，我们看到我们可以利用`sed`在脚本中编辑文件。`sed`命令是**流编辑器**，逐行打开文件以搜索或编辑文件内容。从历史上看，这追溯到 Unix，那时系统可能没有足够的 RAM 来打开非常大的文件。使用`sed`绝对是必不可少的。即使在今天，我们仍然会使用`sed`来对包含数百或数千条记录的文件进行更改和显示数据。这比人类尝试做同样的事情更简单、更容易、更可靠。最重要的是，正如我们所见，我们可以在脚本中使用`sed`自动编辑文件，无需人工干预。

我们将首先查看`grep`并搜索文件中的文本。`grep`命令中的`re`是**正则表达式**的缩写。在我们查看`sed`之前，这介绍了 POSIX 兼容正则表达式的强大功能。即使在本章中我们不涉及脚本编写，我们也将介绍一些非常重要的工具，可以在脚本中使用。在下一章中，我们将看到`sed`在脚本中的实际应用。

目前，我们已经排队了足够的内容，我们将在本章中涵盖以下主题：

+   使用`grep`显示文本

+   使用正则表达式

+   理解`sed`的基础知识

# 使用 grep 显示文本

欢迎回来，欢迎来到在命令行中使用正则表达式的强大之处。我们将通过查看`grep`命令来开始这个旅程。这将使我们能够掌握一些简单的搜索文本的概念，然后再转向更复杂的正则表达式和使用`sed`编辑文件。

**全局正则表达式打印**（**grep**），或者我们更常用的称为`grep`命令，是一个用于全局搜索（跨文件中的所有行）并将结果打印到`STDOUT`的命令行工具。搜索字符串是一个正则表达式。

`grep`命令是如此常见的工具，它有许多简单的示例和许多我们每天都可以使用它的场合。在接下来的部分中，我们将包含一些简单而有用的示例，并进行解释。

## 在接口上显示接收到的数据

在这个示例中，我们将仅打印`eth0`接口接收到的数据。

### 注意

这是我在本课程中使用的树莓派的主要网络连接接口。如果您不确定您的接口名称，可以使用`ifconfig -a`命令显示所有接口，并在您的系统上选择正确的接口名称。如果找不到`ifconfig`，请尝试输入完整路径`/sbin/ifconfig`。

仅使用`ifconfig eth0`命令，就可以将大量数据打印到屏幕上。为了仅显示接收到的数据包，我们可以隔离包含`RX packets`（`RX`表示接收）的行。这就是`grep`发挥作用的地方：

```
$ ifconfig eth0 | grep "RX packets"

```

使用管道或竖线，我们可以将`ifconfig`命令的输出发送到`grep`命令的输入。在这种情况下，`grep`正在搜索一个非常简单的正则表达式，即"RX packet"。搜索字符串是区分大小写的，因此我们需要正确地获取这个或者使用`grep`的`-i`选项以不区分大小写地运行搜索，如下例所示：

```
$ ifconfig eth0 | grep -i "rx packets"

```

### 注意

在搜索配置文件选项时，不区分大小写的搜索特别有用，因为配置文件通常是混合大小写的。

我们可以在以下截图中看到初始命令的结果，确认我们已经能够隔离出单行输出，如下所示：

![在接口上显示接收到的数据](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00072.jpeg)

## 显示用户帐户数据

在 Linux 中，本地用户帐户数据库是`/etc/passwd`文件，所有用户帐户都可以读取。如果我们想要搜索包含我们自己数据的行，我们可以在搜索中使用我们自己的登录名，或者使用参数扩展和`$USER`变量。我们可以在以下命令示例中看到这一点：

```
$ grep "$USER" /etc/passwd

```

在这个例子中，`grep`的输入来自`/etc/passwd`文件，并且我们搜索`$USER`变量的值。同样，在这种情况下，它是一个简单的文本，但仍然是正则表达式，只是没有任何操作符。

为了完整起见，我们在下面的屏幕截图中包含了输出：

![显示用户帐户数据](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00073.jpeg)

我们可以使用这种类型的查询作为脚本中的条件来扩展一下。我们可以使用这个来检查用户帐户是否存在，然后再尝试创建一个新帐户。为了尽可能简化脚本，并确保不需要管理员权限，创建帐户将仅显示提示和条件测试，如下面的命令行示例所示：

```
$ bash
$ read -p "Enter a user name: "
$ if (grep "$REPLY" /etc/passwd > /dev/null) ; then
>  echo "The user $REPLY exists"
>  exit 1
>fi

```

`grep`搜索现在使用由`read`填充的`$REPLY`变量。如果我输入名称`pi`，将显示一条消息，然后退出，因为我的用户帐户也叫`pi`。没有必要显示`grep`的结果，我们只是在寻找一个返回代码，要么是`true`要么是`false`。为了确保如果用户在文件中，我们不会看到任何不必要的输出，我们将`grep`的输出重定向到特殊设备文件`/dev/null`。

如果要从命令行运行此命令，应首先启动一个新的 bash shell。您只需键入`bash`即可。这样，当`exit`命令运行时，它不会将您注销，而是关闭新打开的 shell。我们可以看到这种情况发生以及在以下图形中指定现有用户时的结果：

![显示用户帐户数据](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00074.jpeg)

## 列出系统中的 CPU 数量

另一个非常有用的功能是`grep`可以计算匹配的行数并且不显示它们。我们可以使用这个来计算系统上的 CPU 或 CPU 核心的数量。每个核心或 CPU 在`/proc/cpuinfo`文件中都有一个名称。然后我们搜索文本`name`并计算输出；使用的`-c`选项如下例所示：

```
$ grep -c name /proc/cpuinfo

```

我正在使用 Raspberry Pi 2，它有四个核心，如下面的输出所示：

![列出系统中的 CPU 数量](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00075.jpeg)

如果我们在具有单个核心的 Raspberry Pi Model B 上使用相同的代码，我们将看到以下输出：

![列出系统中的 CPU 数量](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00076.jpeg)

我们可以再次在脚本中使用这个来验证在运行 CPU 密集任务之前是否有足够的核心可用。要从命令行测试这一点，我们可以在只有单个核心的 Raspberry Pi 上执行以下代码：

```
$ bash
$ CPU_CORES=$(grep -c name /proc/cpuinfo)
$ if (( CPU_CORES < 4 )) ; then
> echo "A minimum of 4 cores are required"
> exit 1
> fi

```

我们只在开始时运行 bash，以确保我们不会因为退出命令而退出系统。如果这是在脚本中，这将是不需要的，因为我们将退出脚本而不是我们的 shell 会话。

通过在 Model B 上运行此命令，我们可以看到脚本的结果，还可以看到我们没有所需数量的核心：

![列出系统中的 CPU 数量](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00077.jpeg)

如果您需要在多个脚本中运行此检查，则可以在共享脚本中创建一个函数，并在需要进行检查的脚本中引用包含共享函数的脚本：

```
function check_cores {
 [ -z $1 ] && REQ_CORES=2
CPU_CORES=$(grep -c name /proc/cpuinfo)
if (( CPU_CORES < REQ_CORES  )) ; then
echo "A minimum of $REQ_CORES cores are required"
exit 1
fi
}
```

如果向函数传递了参数，则将其用作所需的核心数；否则，我们将默认值设置为`2`。如果我们在 Model B Raspberry Pi 的 shell 中定义这个作为函数，并使用`type`命令显示详细信息，我们应该会看到如下所示的情况：

![列出系统中的 CPU 数量](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00078.jpeg)

如果我们在单核系统上运行，并且指定了只有单核的要求，我们会看到当我们满足要求时没有输出。如果我们没有指定要求，那么默认为`2`个核心，我们将无法满足要求并退出 shell。

我们可以看到在使用参数`1`运行函数时的输出，然后在没有参数的情况下运行的输出，如下面的屏幕截图所示：

![列出系统中的 CPU 数量](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00079.jpeg)

我们可以看到即使是`grep`的基础知识在脚本中也可以非常有用，以及我们可以利用所学知识开始创建可用的模块以添加到我们的脚本中。

## 解析 CSV 文件

我们现在将看一下创建一个解析或格式化 CSV 文件的脚本。文件的格式化将添加新行、制表符和颜色到输出中，以使其更可读。然后我们可以使用`grep`来显示 CSV 文件中的单个项目。这里的实际应用是基于 CSV 文件的目录系统。

### CSV 文件

CSV 文件或逗号分隔值列表将来自我们当前目录中的名为 tools 的文件。这是我们销售产品的目录。文件内容显示如下输出：

```
drill,99,5
hammer,10,50
brush,5,100
lamp,25,30
screwdriver,5,23
table-saw,1099,3
```

这只是一个简单的演示，所以我们不希望有太多数据，但目录中的每个项目都包括以下内容：

+   名称

+   价格

+   库存单位

我们可以看到我们有一把钻头，售价为 99 美元，我们有五个单位库存。如果我们使用`cat`列出文件，它并不友好；但是我们可以编写一个脚本以更吸引人的方式显示数据。我们可以创建一个名为`$HOME/bin/parsecsv.sh`的新脚本：

```
#!/bin/bash
OLDIFS="$IFS"
IFS=","
while read product price quantity
do
echo -e "\0331;33m$product \
        ========================\033[0m\n\
Price : \t $price \n\
Quantity : \t $quantity \n"

done <"$1"
IFS=$OLDIFS
```

让我们逐步进行这个文件，并查看相关的步骤：

| 元素 | 含义 |
| --- | --- |
| `OLDIFS="$IFS"` | `IFS`变量存储文件分隔符，通常是空格。我们可以存储旧的`IFS`，以便在脚本结束时恢复它。确保一旦脚本完成，无论脚本如何运行，都能返回相同的环境。 |
| 我们将分隔符设置为逗号，以匹配 CSV 文件的需要。 |
| `while read product price quantity` | 我们进入一个`while`循环以填充我们需要的三个变量：产品、价格和数量。`while`循环将逐行读取输入文件，并填充每个变量。 |
| `echo …` | `echo`命令以蓝色显示产品名称，并在其下方显示双下划线。其他变量将打印在新行上并进行制表。 |
| `done <"$1"` | 这是我们读取输入文件的地方，我们将其作为脚本的参数传递。 |

该脚本显示在以下截图中：

![CSV 文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00080.jpeg)

我们可以使用以下命令在当前目录中执行工具目录文件的脚本：

```
$ parsecsv.sh tools
```

为了查看这将如何显示，我们可以查看以下截图的部分输出：

![CSV 文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00081.jpeg)

我们现在开始意识到我们在命令行上有很大的能力以更可读的方式格式化文件，而纯文本文件不需要是单调的。

### 隔离目录条目

如果我们需要搜索一个条目，那么我们需要不止一行。该条目占据了三行。因此，如果我们搜索锤子，我们需要转到锤子行和其后的两行。我们可以使用`grep`的`-A`选项来做到这一点。我们需要显示匹配的行和之后的两行。这将由以下代码表示：

```
$ parsecsv.sh tool | grep -A2 hammer

```

这在以下截图中显示：

![隔离目录条目](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00082.jpeg)

# 使用正则表达式

到目前为止，我们一直将**正则表达式**（**RE**）用于简单的文本，但当然还有很多东西可以从中学到。尽管人们经常认为正则表达式看起来像是在蝙蝠侠打斗中可能看到的漫画书亵渎语，但它们确实有强大的含义。

## 使用替代拼写

首先，让我们看一下拼写上的一些异常。单词"color"可能会根据我们使用的是英式英语还是美式英语而拼写为"colour"或"color"。这可能会导致搜索"color"这个词时出现问题，因为它可能以两种方式拼写。实施以下命令将仅返回包含单词"color"的第一行，而不是第二行：

```
$ echo -e "color\ncolour" | grep color

```

如果我们需要返回两种拼写，那么我们可以使用一个`RE`运算符。我们将使用`?`运算符。您应该知道，在`RE`中，`?`运算符与 shell 中的不同。在`RE`中，`?`运算符表示前一个字符是可选的。当运行带有额外运算符的`RE`时，我们可能需要运行`grep -E`或`egrep`以获得增强的 RE 引擎：

```
$ echo -e "color\ncolour" | grep -E 'colou?r'

```

我们可以通过快速查看以下截图来看到这一点：

![使用替代拼写](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00083.jpeg)

## 有多少单词有四个连续的元音字母？

这位女士们先生们，这就是为什么 RE 如此重要，值得坚持。我们还可以想一些有趣的游戏或填字游戏求解器。我们对 RE 玩得越开心，使用起来就越容易。许多 Linux 系统包括一个位于`/usr/share/dict/words`的字典文件，如果您的系统上存在这个文件，我们将使用它。

你能想到有四个连续元音字母的单词有多少？不确定的话，那就让我们用`grep`和 RE 来搜索文件：

```
$ grep -E '[aeiou]{5}' /usr/share/dict/words

```

首先，您可以看到我们使用了方括号。这与 shell 中的含义相同，并且`OR`分组字符，作为列表。结果搜索是字母`a`或`e`或`i`或`o`或`u`。在括号末尾添加大括号启用了乘法器。在大括号中只有数字`4`表示我们正在寻找四个连续的元音字母。

我们可以在以下截图中看到这一点：

![有多少单词有四个连续的元音字母？](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00084.jpeg)

这有多酷？现在我们永远不会有未完成的填字游戏了，也没有借口在 Scrabble 上输了。

## RE 锚点

当使用`clean_file`函数删除注释行和空行时，我们已经使用了 RE 锚点。`^`或插入符号代表行的开头，`$`代表行的结尾。如果我们想列出从字典文件开始的以`ante`开头的单词，我们将编写以下查询：

```
$ grep '^ante' /usr/share/dict/words

```

结果应该显示 anteater，antelope，antenna 等。如果我们想查询以`cord`结尾的单词，我们将使用：

```
$ grep 'cord$' /usr/share/dict/words

```

这将打印少量内容，并在我的系统上列出单词 accord，concord，cord，discord 和 record。

因此，即使这只是介绍了正则表达式的一小部分，我们也应该欣赏到我们可以从仅知道这么一点点中获得的东西。

# 理解 sed 的基础知识

在建立了一点基础之后，我们现在可以开始查看`sed`的一些操作。这些命令将在大多数 Linux 系统中提供，并且是核心命令。

我们将直接深入一些简单的例子：

```
$ sed 'p' /etc/passwd

```

`p`运算符将打印匹配的模式。在这种情况下，我们没有指定模式，所以我们将匹配所有内容。在不抑制`STDOUT`的情况下打印匹配的行将重复行。这个操作的结果是将`passwd`文件中的所有行都打印两次。要抑制`STDOUT`，我们使用`-n`选项：

```
$ sed -n 'p' /etc/passwd

```

太棒了！我们刚刚重新发明了`cat`命令。现在我们可以专门处理一系列行：

```
$ sed -n '1,3 p ' /etc/passwd

```

现在我们已经重新发明了`head`命令，但我们也可以在 RE 中指定范围来重新创建`grep`命令：

```
$ sed -n '/^root/ p' /etc/passwd

```

我们可以在以下截图中看到这一点：

![理解 sed 的基础知识](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00085.jpeg)

## 替换命令

我们已经看到了用于打印模式空间的`p`命令。现在我们将看一下替换命令或`s`。通过这个命令，我们可以用另一个字符串替换一个字符串。同样，默认情况下，我们将输出发送到`STDOUT`，并且不编辑文件。

要替换用户`pi`的默认 shell，我们可以使用以下命令：

```
sed -n ' /^pi/ s/bash/sh/p ' /etc/passwd

```

我们继续使用`p`命令来打印匹配的模式，并使用`-n`选项来抑制`STDOUT`。我们搜索以`pi`开头的行。这代表用户名。然后我们使用`s`命令来替换这些匹配的行中的文本。这需要两个参数，第一个是要搜索的文本，第二个代表用于替换原始文本的文本。在这种情况下，我们搜索`bash`并将其替换为`sh`。这很简单，确实有效，但从长远来看可能不太可靠。我们可以在下面的截图中看到输出：

![替换命令](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00086.jpeg)

我们必须强调，目前我们并没有编辑文件，只是将其显示在屏幕上。原始的`passwd`文件保持不变，我们可以以标准用户身份运行这个命令。我在前面的例子中提到，搜索可能不太可靠，因为我们要搜索的字符串是`bash`。这个字符串非常短，也许它可以在匹配的行中的其他地方被包含。可能某人的姓氏是"Tabash"，其中包含字符串`bash`。我们可以扩展搜索以查找`/bin/bash`并将其替换为`/bin/sh`。然而，这引入了另一个问题，即默认分隔符是斜杠，所以我们必须转义我们在搜索和替换字符串中使用的每个斜杠，即：

```
sed -n ' /^pi/ s/\/bin\/bash/\/usr\/bin\/sh/p ' /etc/passwd

```

这是一个选择，但不是一个整洁的选择。更好的解决方案是知道我们使用的第一个分隔符定义了分隔符。换句话说，您可以使用任何字符作为分隔符。在这种情况下，使用`@`符号可能是一个好主意，因为它既不出现在搜索字符串中，也不出现在替换字符串中：

```
sed -n ' /^pi/ s@/bin/bash@/usr/bin/sh@p ' /etc/passwd

```

现在我们有了一个更可靠的搜索和可读的命令行，这总是一件好事。我们只替换每行的第一个出现的`/bin/bash`为`/bin/sh`。如果我们需要替换不止第一个出现，我们在最后加上`g`命令以进行全局替换：

```
sed -n ' /^pi/ s@bash@sh@pg ' /etc/passwd

```

在我们的情况下，这并不是必需的，但了解这一点是很好的。

## 编辑文件

如果我们想要编辑文件，我们可以使用`-i`选项。我们需要有权限来处理文件，但我们可以复制文件以便处理，这样就不会损害任何系统文件或需要额外的访问权限。

我们可以将`passwd`文件复制到本地：

```
$ cp /etc/passwd "$HOME"
$ cd

```

我们用`cd`命令结束，以确保我们在家目录和本地`passwd`文件中工作。

`-i`选项用于进行原地更新。在编辑文件时，我们将不需要`-n`选项或`p`命令。因此，命令就像下面的例子一样简单：

```
$ sed -i ' /^pi/ s@/bin/bash@/bin/sh/ ' $HOME/passwd

```

命令不会有任何输出，但文件现在将反映出更改。下面的截图显示了命令的使用：

![编辑文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00087.jpeg)

在进行更改之前，我们应该备份文件，直接在`-i`选项后附加一个字符串，不加任何空格。这在下面的例子中显示：

```
$ sed -i.bak ' /^pi/ s@/bin/bash@/bin/sh/ ' $HOME/passwd

```

如果我们想要查看这个，我们可以反转搜索和替换字符串：

```
$ sed -i.bak ' /^pi/ s@/bin/sh@/bin/bash/ ' $HOME/passwd

```

这将使本地的`passwd`文件与之前一样，并且我们将有一个`passwd.bak`，其中包含之前的一系列更改。这样如果需要，我们就有了一个回滚选项，可以确保安全。

# 总结

这是另一个你牢牢掌握的伟大章节，我希望这对你真的很有用。虽然我们想集中使用`sed`，但我们从`grep`的强大之处开始，无论是在脚本内部还是外部。这使我们在查看`sed`的可能性之前先了解了正则表达式。虽然我们只是初步接触了`sed`，但我们将在下一章中开始扩展这一点，我们将扩展我们所学到的知识。这将以从当前配置中提取注释数据开始，取消注释并将其写入模板的形式进行。然后我们可以使用模板来创建新的虚拟主机。所有这些操作的工作马是`sed`和`sed`脚本。


# 第九章：自动化 Apache 虚拟主机

现在我们已经了解了一些流编辑器`sed`，我们可以将这些知识付诸实践。在第八章中，*介绍 sed*，我们已经习惯了`sed`的一些功能；然而，这只是编辑器中所包含的一小部分功能。在本章中，我们将更多地使用`sed`，并且在使用我们的 bash 脚本时，暴露自己于工具的一些实际用途。

在这个过程中，我们将使用`sed`来帮助我们自动创建基于名称的 Apache 虚拟主机。Apache 主机是我们演示的`sed`的实际用户，但更重要的是，我们将使用`sed`来搜索主配置中的选定行。然后我们将取消注释这些行并将它们保存为模板。创建了模板后，我们将从中创建新的配置。我们在 Apache 中演示的概念可以应用于许多不同的情况。

我们将发现，在我们的 shell 脚本中使用`sed`将允许我们轻松地从主配置中提取模板数据，并根据虚拟主机的需要进行调整。通过这种方式，我们将能够扩展对`sed`和 shell 脚本的知识。在本章中，我们将涵盖以下主题：

+   Apache HTTPD 虚拟主机

+   提取模板信息

+   自动创建主机

+   在主机创建过程中提示

# 基于名称的 Apache 虚拟主机

为了演示，我们将使用从 CentOS 6.6 主机中获取的 Apache 2.2 HTTPD 服务器的`httpd.conf`文件。坦率地说，我们对配置文件更感兴趣，因为 Red Hat 或 CentOS 提供它，而不是我们将进行的实际配置更改。我们的目的是学习如何从系统提供的文件中提取数据并创建模板。我们可以将此应用于 Apache 配置文件或任何其他文本数据文件。这是方法论，我们不关注实际结果。

为了对我们要做的事情有一些了解，我们必须首先查看随 Enterprise Linux 6 一起提供的`/etc/httpd/conf/httpd.conf`文件，即 CentOS、Red Hat Enterprise Linux 或 Scientific Linux。以下截图显示了我们感兴趣的文件的虚拟主机部分。

![基于名称的 Apache 虚拟主机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00088.jpeg)

看着这些行，我们可以看到它们被注释了，这都是一个单一的`httpd.conf`的一部分。在创建虚拟主机时，我们通常更喜欢为每个潜在的虚拟主机单独配置。我们需要能够从主文件中提取这些数据，并同时取消注释。然后我们可以将这些取消注释的数据保存为模板。

使用这个模板，我们将创建新的配置文件，代表我们需要在一个 Apache 实例上运行的不同命名的`hosts`。这使我们能够在单个服务器上托管`sales.example.com`和`marketing.example.com`。销售和营销将拥有各自独立的配置和网站。此外，使用我们创建的模板也很容易添加我们需要的其他站点。主要的 Web 服务器的任务是读取传入的 HTTP 头请求，并根据使用的域名将其定向到正确的站点。

我们的第一个任务是提取在开放和关闭`VirtualHost`标签之间的数据，取消注释并保存到模板中。这只需要做一次，不会成为创建虚拟主机的主要脚本的一部分。

## 创建虚拟主机模板

由于我们不打算测试我们创建的虚拟主机，我们将复制`httpd.conf`文件并在本地家目录中使用。在开发脚本时，这是一个很好的做法，以免影响工作配置。我正在使用的`httpd.conf`文件应该能够从发布者引用的其他脚本资源中下载。或者，您可以从安装了 Apache 的企业 Linux 6 主机上复制它。确保将`httpd.conf`文件复制到您的家目录，并且您正在家目录中工作。

## 第一步

创建模板的第一步是隔离我们需要的行。在我们的情况下，这将是在之前的屏幕截图中看到的示例虚拟主机定义中包括的行。这包括`VirtualHost`的开放和关闭标签以及中间的所有内容。我们可以使用行号来实现这一点；但是，这可能不太可靠，因为我们需要假设文件中的内容没有发生变化，行号才能保持一致。为了完整起见，我们将在转向更可靠的机制之前展示这一点。

首先，我们将回顾一下如何使用`sed`打印整个文件。这很重要，因为在下一步中，我们将过滤显示并仅显示我们想要的行：

```
$ sed -n ' p ' httpd.conf

```

使用`-n`选项来抑制标准输出，引号内的`sed`命令是`p`，用于显示模式匹配。由于我们在这里没有过滤任何内容，匹配的模式就是整个文件。如果我们要使用行号进行过滤，可以使用`sed`轻松添加行号，如下命令所示：

```
$ sed = httpd.conf

```

从以下屏幕截图中，我们可以看到在这个系统中，我们需要处理的行是从`1003`到`1009`；但是，我再次强调，这些数字可能会因文件而异：

![第一步](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00089.jpeg)

## 隔离行

要显示这些带有标签的行，我们可以在`sed`中添加一个数字范围。通过将这些数字添加到`sed`中，可以轻松实现这一点，如下命令所示：

```
$ sed -n '1003,1009 p ' httpd.conf

```

通过指定行范围，我们已经成功地隔离了我们需要的行，现在显示的只有虚拟主机定义的行。我们可以在以下屏幕截图中看到这一点，其中显示了命令和输出：

![隔离行](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00090.jpeg)

在硬编码行号时面临的问题是我们失去了灵活性。这些行号与这个文件相关，可能只与这个文件相关。我们将始终需要检查与我们正在处理的文件相关的文件中的正确行号。如果行不方便地位于文件的末尾，我们将不得不向后滚动以尝试找到正确的行号。为了克服这些问题，我们可以实现对开放和关闭标签的直接搜索，而不是使用行号。

```
$ sed -n '/^#<VirtualHost/,/^#<\/VirtualHost/p' httpd.conf

```

我们不再使用起始号码和结束号码，而是更可靠的起始正则表达式和结束正则表达式。开头的正则表达式寻找以`#<VirtualHost`开头的行。结束的正则表达式正在寻找关闭标签。但是，我们需要用转义字符保护`/VirtualHost`。通过查看结束的正则表达式，我们看到它转换为以`#\/VirtualHost`开头的行，带有转义的斜杠。

### 注意

如果您还记得第八章中的内容，*介绍 sed*，我们可以使用插入符(`^`)指定以指定字符开头的行。

通过查看以下屏幕截图，我们现在可以更可靠地隔离所需的行，而无需知道行号。这在编辑过的文件中更可取，这些文件的行号会有所不同：

![隔离行](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00091.jpeg)

## sed 脚本文件

隔离行只是第一步！我们仍然需要取消注释这些行，然后将结果保存为模板。虽然我们可以将其写成一个单独的`sed`命令字符串，但我们已经看到它会非常冗长，难以阅读和编辑。幸运的是，`sed`命令确实有从输入文件（通常称为脚本）读取命令的选项。我们使用`-f`选项与`sed`一起指定要读取的文件作为我们的控制。有关`sed`的所有选项的更多详细信息，请参阅主页。

我们已经看到我们可以正确地从文件中隔离出正确的行。因此，脚本的第一行配置了我们要处理的行。我们使用大括号`{}`来定义所选行后面的代码块。代码块是我们想要在给定选择上运行的一个或多个命令。

在我们的情况下，第一个命令将是删除注释，第二个命令将是将模式空间写入新文件。`sed`脚本应该如下例所示：

```
/^#<VirtualHost/,/^#<\/VirtualHost/ {
s/^#//
wtemplate.txt
}
```

我们可以将此文件保存为`$HOME/vh.sed`。

在第一行，我们选择要处理的行，就像我们之前看到的那样，然后用左大括号打开代码块。在第 2 行，我们使用替换命令`s`。这将查找以注释或`#`开头的行。我们用空字符串替换注释。中间和结束的斜杠之间没有字符或空格。用英语来说，我们是在取消注释该行，但对于代码来说，这是用空字符串替换`#`。代码的最后一行使用`write`命令`w`将其保存到`template.txt`。为了帮助您看到这一点，我们已经包含了`vh.sed`文件的以下截图：

![sed 脚本文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00092.jpeg)

现在我们可以看到我们所有的努力都得到了成果，只要确保我们在执行以下命令的`httpd.conf`和`vh.sed`文件所在的同一目录中：

```
$ sed -nf vh.sed httpd.conf

```

我们现在已经在我们的工作目录中创建了`template.txt`文件。这是从`httpd.conf`文件中隔离出的取消注释文本。简单来说，我们从数千行文本中提取了七行正确的文本，删除了注释，并将结果保存为新文件。`template.txt`文件显示在以下截图中：

![sed 脚本文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00093.jpeg)

现在，我们有一个模板文件，可以开始使用它来创建虚拟主机定义。即使我们一直在看 Apache，取消注释文本或删除所选行的第一个字符的相同想法也可以适用于许多情况，因此将其视为`sed`可以做什么的一个想法。

# 自动创建虚拟主机

创建了模板之后，我们现在可以使用它来创建虚拟主机配置。简单来说，我们需要将`dummy-host.example.com` URL 替换为`sales.example.com`或`marketing.example.com` URL。当然，我们还需要创建`DocumentRoot`目录，这是网页所在的目录，并添加一些基本内容。当我们使用脚本运行整个过程时，不会遗漏任何内容，每次编辑都将准确无误。脚本的基本内容如下：

```
#!/bin/bash
WEBDIR=/www/docs
CONFDIR=/etc/httpd/conf.d
TEMPLATE=$HOME/template.txt
[ -d $CONFDIR ] || mkdir -p $CONFDIR
sed s/dummy-host.example.com/$1/ $TEMPLATE > $CONFDIR/$1.conf
mkdir -p $WEBDIR/$1
echo "New site for $1" > $WEBDIR/$1/index.html
```

如果我们忽略第一行的 shebang，我们现在应该知道了。我们可以从脚本的第 2 行开始解释：

| 行 | 意思 |
| --- | --- |
| `WEBDIR=/www/docs/` | 我们初始化`WEDIR`变量，将其存储在将容纳不同网站的目录的路径中。 |
| `CONFDIR=/etc/httpd/conf.d` | 我们初始化`CONFDIR`变量，用于存储新创建的虚拟主机配置文件。 |
| `TEMPLATE=$HOME/template.txt` | 我们初始化将用于模板的变量。这应该指向您的模板路径。 |
| `[ -d $CONFDIR ] &#124;&#124; mkdir -p "$CONFDIR"` | 在一个工作的 EL6 主机上，这个目录将存在并包含在主配置中。如果我们将其作为纯测试运行，那么我们可以创建一个目录来证明我们可以在目标目录中创建正确的配置。 |
| `sed s/dummy-host.example.com/$1/ $TEMPLATE >$CONFDIR/$1.conf` | `sed`命令作为脚本中运行搜索和替换操作的引擎。使用`sed`中的替换命令，我们搜索虚拟文本并用传递给脚本的参数替换它。 |
| `mkdir -p $WEBDIR/$1` | 在这里，我们创建正确的子目录来存放新虚拟主机的网站。 |
| `echo "New site for $1" > $WEBDIR/$1/index.html` | 在最后一步中，我们为网站创建一个基本的临时页面。 |

我们可以将此脚本创建为`$HOME/bin/vhost.sh`。如下截图所示。不要忘记添加执行权限：

![自动化虚拟主机创建](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00094.jpeg)

要创建销售虚拟主机和网页，我们可以按照以下示例运行脚本。我们将直接以 root 用户身份运行脚本。或者，您也可以选择在脚本中使用`sudo`命令：

```
# vhost.sh sales.example.com

```

现在我们可以看到，使用精心制作的脚本可以轻松创建虚拟主机。虚拟主机的配置文件将在`/etc/httpd/conf.d/`目录中创建，并命名为`sales.example.com.conf`。该文件将类似于以下截图：

![自动化虚拟主机创建](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00095.jpeg)

网站内容必须已经创建在`/www/docs/sales.example.com`目录中。这将是一个简单的临时页面，证明我们可以从脚本中做到这一点。使用以下命令，我们可以列出用于存放每个站点的内容或基本目录：

```
$ ls -R /www/docs

```

`-R`选项允许递归列出。我们纯粹使用`/www/docs`目录，因为这是我们提取的原始虚拟主机定义中设置的。如果在实际环境中工作，您可能更喜欢使用`/var/www`或类似的内容，而不是在文件系统根目录创建新目录。编辑我们创建的模板将是一件简单的事情，也可以在模板创建时使用`sed`完成。

## 在站点创建过程中提示数据

现在我们可以使用脚本来创建虚拟主机和内容，但除了虚拟主机名称之外，我们还没有允许任何定制。当然，这很重要。毕竟，正是这个虚拟主机名称在配置本身以及设置网站目录和配置文件名中使用。

我们可以允许在虚拟主机创建过程中指定附加选项。我们将使用`sed`根据需要插入数据。`sed`命令`i`用于在选择之前插入数据，`a`用于在选择之后追加数据。

在我们的示例中，我们将添加主机限制，只允许本地网络访问网站。我们更感兴趣的是将数据插入文件中，而不是我们在特定 HTTP 配置文件中所做的事情。在脚本中，我们将添加`read`提示，并在配置中插入`Directory`块。

为了尝试解释我们要做的事情，当执行脚本时，我们应该看到类似于以下内容。您可以从我们为营销站点创建的文本中看到这一点，并添加对谁可以访问站点的限制：

![在站点创建过程中提示数据](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00096.jpeg)

正如您所看到的，我们可以提出两个问题，但如果需要，可以添加更多问题以支持定制；其想法是，额外的定制应该像脚本创建一样准确可靠。您还可以选择用示例答案详细说明问题，以便用户知道网络地址应该如何格式化。

为了帮助脚本创建，我们将原始的`vhost.sh`复制到`vhost2.sh`。我们可以整理脚本中的一些项目，以便更容易扩展，然后添加额外的提示。新脚本将类似于以下代码：

```
#!/bin/bash
WEBDIR=/www/docs/$1
CONFDIR=/etc/httpd/conf.d
CONFFILE=$CONFDIR/$1.conf
TEMPLATE=$HOME/template.txt
[ -d $CONFDIR ] || mkdir -p $CONFDIR 
sed s/dummy-host.example.com/$1/ $TEMPLATE > $CONFFILE
mkdir -p $WEBDIR
echo "New site for $1" > $WEBDIR/index.html
read -p "Do you want to restrict access to this site? y/n "
[ $REPLY = 'n' ] && exit 0
read -p "Which network should we restrict access to: " NETWORK
sed -i "/<\/VirtualHost>/i <Directory $WEBDIR >\
  \n  Order allow,deny\
  \n  Allow from 127.0.0.1\
  \n  Allow from $NETWORK\
\n</Directory>" $CONFFILE
```

### 注意

请注意，我们在脚本中没有运行太多检查。这是为了让我们专注于添加的元素而不是一个健壮的脚本。在您自己的环境中，一旦脚本按您希望的方式工作，您可能需要实施更多的检查以确保脚本的可靠性。

正如您所看到的，我们有更多的行。`WEBDIR`变量已经调整为包含目录的完整路径，类似地，我们添加了一个新变量`CONFFILE`，以便我们可以直接引用文件。如果对第一个提示的答案是`n`，并且用户不需要额外的定制，脚本将退出。如果他们对“否”回答任何其他答案，脚本将继续并提示网络授予访问权限。然后我们可以使用`sed`来编辑现有配置并插入新的目录块。这将默认拒绝访问，但允许`localhost`和`NETWORK`变量。我们在代码中将`localhost`称为`127.0.0.1`。

为了简化代码以便更好地理解，伪代码将如下例所示：

```
$ sed -i "/SearchText/i NewText <filename>

```

其中`SearchText`代表我们要在其前插入文本的文件中的行。此外，`NewText`代表将在`SearchText`之前添加的新行或多行。直接跟在`SearchText`后面的`i`命令表示我们正在插入文本。使用`a`命令进行追加意味着我们添加的文本将在`SearchText`之后添加。

我们可以看到`marketing.example.com`的结果配置文件，因为我们已经创建了它，并在以下截图中添加了额外的**Directory**块：

![在站点创建期间提示数据](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00097.jpeg)

我们可以看到我们已经在关闭的`VirtualHost`标签上方添加了新块。在脚本中，这是我们使用的`SearchText`。我们添加的**Directory**块替换了伪代码中的`NewText`。当我们看它时，它看起来更复杂，因为我们使用`\n`嵌入了新行，并使用行继续字符`\`格式化文件以便更容易阅读。再次强调，一旦脚本创建完成，这种编辑是容易和准确的。

为了完整起见，我们在以下截图中包括了脚本`vhost2.sh`的截图：

![在站点创建期间提示数据](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00098.jpeg)

# 总结

在本章中，我们已经看到了如何将`sed`扩展到一些非常酷的脚本中，这些脚本使我们能够从文件中提取数据，取消注释选定的行并编写新的配置。我们还看到了如何使用`sed`与脚本，将新行插入现有文件中。我认为`sed`很快就会成为您的朋友，我们已经创建了一些强大的脚本来支持学习体验。

你可能已经知道这一点，但`sed`有一个大哥`awk`。在下一章中，我们将看到如何使用`awk`从文件中提取数据。


# 第十章：awk 基础知识

流编辑器并不孤单，它还有一个大哥 awk。在本章中，我们将介绍 awk 的基础知识，并看到 awk 编程语言的强大之处。我们将了解为什么我们需要和喜爱 awk，以及在开始在接下来的两章中实际使用 awk 之前，我们如何利用一些基本功能。在这个过程中，我们将涵盖以下主题：

+   从文件中过滤内容

+   格式化输出

+   显示`/etc/passwd`中的非系统用户

+   使用`awk`控制文件

# awk 背后的历史

`awk`命令是 Unix 和 Linux 命令套件中的主要组成部分。Unix 命令`awk`最早是在 20 世纪 70 年代由贝尔实验室开发的，它的名字取自主要作者的姓氏：Alfred Aho，Peter Weinberger 和 Brian Kernighan。`awk`命令允许访问 awk 编程语言，该语言旨在处理文本流中的数据。

为了演示`awk`提供的编程语言，我们应该创建一个`hello world`程序。我们知道这对于所有语言来说都是强制性的：

```
$ awk 'BEGIN { print "Hello World!" }'

```

我们不仅可以看到这段代码将打印无处不在的 hello 消息，还可以使用`BEGIN`块生成头信息。稍后，我们将看到我们可以通过`END`代码块创建摘要信息，从而允许主代码块。

我们可以在以下截图中看到这个基本命令的输出：

![awk 背后的历史](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00099.jpeg)

# 显示和过滤文件中的内容

当然，我们都希望能够打印比**Hello World**更多的内容。`awk`命令可以用来过滤文件中的内容，如果需要的话，还可以处理非常大的文件。我们应该先打印完整的文件，然后再进行过滤。这样，我们就可以感受到命令的语法。稍后，我们将看到如何将此控制信息添加到`awk`文件中，以便简化命令行。使用以下命令，我们将打印`/etc/passwd`文件中的所有行：

```
$ awk ' { print } ' /etc/passwd

```

这相当于使用`print`语句的`$0`变量：

```
$ awk ' { print $0 }' /etc/passwd

```

`$0`变量指的是完整的行。如果`print`命令没有提供参数，我们假设要打印整行。如果我们只想打印`/etc/passwd`文件中的第一个字段，我们可以使用`$1`变量。但是，我们需要指定在该文件中使用的字段分隔符是冒号。`awk`的默认分隔符是空格或任意数量的空格或制表符和换行符。有两种方法可以指定输入分隔符；这些方法在以下示例中显示。

第一个示例很容易且简单易用。`-F`选项特别适用，特别是在我们不需要任何额外的头信息时：

```
$ awk -F":" '{ print $1 }' /etc/passwd

```

我们也可以在`BEGIN`块中执行此操作；当我们想要使用`BEGIN`块显示头信息时，这是很有用的：

```
$ awk ' BEGIN { FS=":" } { print $1 } ' /etc/passwd

```

我们可以在前面的示例中清楚地看到这一点，我们将其命名为`BEGIN`块，其中的所有代码都被大括号括起来。主块没有名称，并且被大括号括起来。

在看到`BEGIN`块和主代码块之后，我们现在将看一下`END`代码块。这通常用于显示摘要数据。例如，如果我们想要打印`passwd`文件中的总行数，我们可以利用`END`块。具有`BEGIN`和`END`块的代码只处理一次，而主块则对每一行进行处理。以下示例将添加到我们迄今为止编写的代码中，以包括总行数：

```
$ awk ' BEGIN { FS=":" } { print $1 } END { print NR } ' /etc/passwd

```

`awk`内部变量`NR`维护了处理的行数。如果需要，我们可以为此添加一些附加文本。这可以用于注释摘要数据。我们还可以利用 awk 语言中使用的单引号；它们允许我们将代码跨多行展开。一旦我们打开了单引号，我们就可以在命令行中添加新行，直到我们关闭引号。这在下一个示例中得到了展示，我们扩展了摘要信息：

```
$ awk ' BEGIN { FS=":" }
> { print $1 }
> END { print "Total:",NR } ' /etc/passwd

```

如果我们不想在这里结束我们的 awk 体验，我们可以轻松地显示每行的运行行数以及最终总数。这在下面的例子中得到了展示：

```
$ awk ' BEGIN { FS=":" }
> { print NR,$1 }
> END { print "Total:",NR } ' /etc/passwd

```

以下截图捕获了这个命令和部分输出：

![显示和过滤文件内容](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00100.jpeg)

在第一个使用`BEGIN`的示例中，我们看到没有理由不能单独使用`END`代码块而不使用主代码块。如果我们需要模拟`wc -l`命令，我们可以使用以下`awk`语句：

```
$ awk ' END { print NR }' /etc/passwd

```

输出将是文件的行数。以下截图显示了`awk`命令和`wc`命令用于计算`/etc/passwd`文件中的行数：

![显示和过滤文件内容](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00101.jpeg)

值得注意的是，我们可以看到输出确实符合 28 行，我们的代码也起作用了。

我们还可以练习的另一个功能是仅处理选定的行。例如，如果我们只想打印前五行，我们将使用以下语句：

```
$ awk ' NR < 6 ' /etc/passwd

```

如果我们想打印第`8`到`12`行，我们可以使用以下代码：

```
$ awk ' NR==8,NR==12 ' /etc/passwd

```

我们还可以使用正则表达式来匹配行中的文本。看看下面的例子，我们查看以单词 bash 结尾的行：

```
$ awk ' /bash$/ ' /etc/passwd

```

示例和输出如下截图所示：

![显示和过滤文件内容](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00102.jpeg)

# 格式化输出

到目前为止，我们一直忠于`print`命令，因为我们对输出的要求有限。如果我们想要打印出用户名、UID 和默认 shell，我们需要开始对输出进行一些格式化。在这种情况下，我们可以将输出组织成形状良好的列。没有格式化的话，我们使用的命令会类似于以下示例，其中我们使用逗号来分隔要打印的字段：

```
$ awk ' BEGIN { FS=":" } { print $1,$3,$7 } ' /etc/passwd

```

我们在这里使用`BEGIN`块，因为我们可以利用它稍后打印列标题。

为了更好地理解问题，我们可以看一下下面的截图，它说明了不均匀的列宽：

![格式化输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00103.jpeg)

我们输出中的问题是列不对齐，因为用户名的长度不一致。为了改进这一点，我们可以使用`printf`函数，其中我们可以指定列宽。`awk`语句的语法将类似于以下示例：

```
$ awk ' BEGIN { FS=":" }
> { printf "%10s %4d %17s\n",$1,$3,$7 } ' /etc/passwd

```

`printf`格式化包含在双引号内。我们还需要用`\n`包括换行符。`printf`函数不会自动添加新行，而`print`函数会。我们打印三个字段；第一个接受字符串值，并设置为`10`个字符宽。中间字段最多接受 4 个数字，最后是默认 shell 字段，我们允许最多`17`个字符串字符。

以下截图显示了如何改进输出：

![格式化输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00104.jpeg)

我们可以通过添加标题信息进一步增强这一点。尽管在这个阶段代码开始看起来凌乱，但我们稍后将看到如何使用 awk 控制文件解决这个问题。下面的例子显示了标题信息被添加到`Begin`块中。分号用于分隔`BEGIN`块中的两个语句：

```
$ awk 'BEGIN {FS=":" ; printf "%10s %4s %17s\n",""Name","UID","Shell"}
> { printf "%10s %4d %17s\n",$1,$3,$7 } ' /etc/passwd

```

在下面的截图中，我们可以看到这如何进一步改进了输出：

![格式化输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00105.jpeg)

在上一章中，我们看到如何在 shell 中使用颜色来增强输出。我们也可以通过在 awk 中添加自己的函数来使用颜色。在下面的代码示例中，您将看到 awk 允许我们定义自己的函数来促进更复杂的操作并隔离代码。我们现在将修改以前的代码以在标题中包含绿色输出：

```
$ awk 'function green(s) {
> printf "\0331;32m" s "\033[0m\n"
> }
> BEGIN {FS=":" ; green("   Name:  UID:    Shell:"}
> { printf "%10s %4d %17s\n",$1,$3,$7 } ' /etc/passwd

```

在`awk`中创建函数允许我们在需要的地方添加颜色，这种情况下是绿色文本。很容易创建函数来定义其他颜色。代码和输出包含在以下截图中：

![格式化输出

# 进一步过滤以显示 UID 用户

我们已经能够逐步建立我们的 awk 技能，我们学到的东西都很有用。我们可以将这些小步骤添加起来，开始创建一些更有用的东西。也许，我们想要只打印标准用户；这些通常是高于 500 或 1000 的用户，具体取决于您的特定发行版。

在我为本书使用的 Raspbian 发行版中，标准用户的 UID 从 1000 开始。UID 是第三个字段。这实际上只是简单地使用第三个字段的值作为范围运算符。我们可以在以下示例中看到这一点：

```
$ awk -F":" '$3 > 999 ' /etc/passwd

```

我们可以使用以下命令显示 UID 为 101 的用户：

```
$ awk -F":" '$3 < 101 ' /etc/passwd

```

这只是让您了解 awk 的一些可能性。事实上，我们可以整天玩我们的算术比较运算符。

我们还看到，有些示例中，`awk`语句变得有点长。这就是我们可以实现`awk`控制文件的地方。在我们陷入语法混乱之前，让我们立即看看这些。

# Awk 控制文件

就像`sed`一样，我们可以通过创建和包含控制文件来简化命令行。这也使得以后编辑命令更容易实现。控制文件包含我们希望`awk`执行的所有语句。我们在使用`sed`、`awk`和 shell 脚本时必须考虑的主要问题是模块化；创建可重用的元素，以隔离和重用代码。这样可以节省我们的时间和工作，并且我们有更多时间用于我们喜欢的任务。

要查看`awk`控制文件的示例，我们应该重新访问`passwd`文件的格式。创建以下文件将封装`awk`语句：

```
function green(s) {
    printf "\033[1;32m" s "\033[0m\n"
}
BEGIN {
    FS=":"
    green("   Name:   UID:       Shell:")
}
{
    printf "%10s %4d %17s\n",$1,$3,$7
}
```

我们可以将此文件保存为`passwd.awk`。

能够将所有的`awk`语句都包含在一个文件中非常方便，执行变得干净整洁：

```
$ awk -f passwd.awk /etc/passwd

```

这肯定鼓励更复杂的`awk`语句，并允许您为代码扩展更多功能。

# 总结

我希望您对可以使用 awk 工具有更好和更清晰的理解。这是一个数据处理工具，逐行运行文本文件并处理您添加的代码。如果已添加，主要块将针对符合行条件的每一行运行。而`BEGIN`和`END`块代码只执行一次。

在接下来的两章中，我们将继续使用 awk，并举一些 awk 在现实生活中的实际示例。


# 第十一章：使用 Awk 总结日志

awk 真正擅长的任务之一是从日志文件中过滤数据。这些日志文件可能有很多行，可能有 250,000 行或更多。我曾处理过超过一百万行的数据。Awk 可以快速有效地处理这些行。例如，我们将使用包含 30,000 行的 Web 服务器访问日志文件，以展示 awk 代码的有效性和良好编写。在本章中，我们将涵盖以下主题：

+   HTTPD 日志文件格式

+   显示来自 Web 服务器日志的数据

+   总结 HTTP 访问代码

+   显示排名最高的客户端 IP 地址

+   列出浏览器数据

+   处理电子邮件日志

# HTTPD 日志文件格式

在处理任何文件时，第一项任务是熟悉文件模式。简单来说，我们需要知道每个字段代表什么，以及用于分隔字段的内容。我们将使用 Apache HTTPD Web 服务器的访问日志文件。日志文件的位置可以从`httpd.conf`文件中控制。基于 Debian 的系统上，默认的日志文件位置是`/var/log/apache2/access.log`；其他系统可能使用`apache2`目录代替`httpd`。

为了演示文件的布局，我在 Ubuntu 15.10 系统上安装了一个全新的 Apache2 实例。安装完 Web 服务器后，我们从本地主机的 Firefox 浏览器进行了一次访问。

使用`tail`命令可以显示日志文件的内容。尽管公平地说，使用`cat`也可以，因为它只有几行：

```
# tail /var/log/apache2/access.log

```

命令的输出和文件的内容如下截图所示：

![HTTPD 日志文件格式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00107.jpeg)

命令的输出会有一些换行，但我们可以感受到日志的布局。我们还可以看到，尽管我们认为只访问了一个网页，但实际上我们访问了两个项目：`index.html`和`ubuntu-logo.png`。我们还未能访问`favicon.ico`文件。我们可以看到该文件是以空格分隔的。每个字段的含义在以下表格中列出：

| 字段 | 目的 |
| --- | --- |
| 1 | 客户端 IP 地址。 |
| 2 | RFC 1413 和`identd`客户端定义的客户端身份。除非启用`IdentityCheck`，否则不会读取此内容。如果未读取，该值将带有连字符。 |
| 3 | 如果启用了用户身份验证，则为用户身份验证的用户 ID。如果未启用身份验证，则该值将为连字符。 |
| 4 | 请求的日期和时间格式为`day/month/year:hour:minute:second offset`。 |
| 5 | 实际请求和方法。 |
| 6 | 返回状态代码，如 200 或 404。 |
| 7 | 文件大小（以字节为单位）。 |

即使这些字段是由 Apache 定义的，我们也必须小心。时间、日期和时区是一个字段，并且在方括号内定义；然而，在该数据和时区之间的字段内有额外的空格。为了确保在需要时打印完整的时间字段，我们需要同时打印`$4`和`$5`。这在以下命令示例中显示：

```
# awk ' { print $4,$5 } ' /var/log/apache2/access.log

```

我们可以在以下截图中查看命令和其产生的输出：

![HTTPD 日志文件格式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00108.jpeg)

# 显示来自 Web 日志的数据

我们已经预览了如何使用 awk 查看 Apache Web 服务器的日志文件；但是，现在我们将转向我们的演示文件，其中包含更丰富和更多样化的内容。

## 按日期选择条目

看到我们如何显示日期后，也许我们应该看看如何仅打印一天的条目。为此，我们可以在`awk`中使用匹配运算符。如果您愿意，这由波浪线表示。由于我们只需要日期元素，因此我们不需要同时使用日期和时区字段。以下命令显示了如何打印 2014 年 9 月 10 日的条目：

```
$ awk ' ( $4 ~ /10\/Sep\/2014/ ) ' access.log

```

为了完整起见，以下是该命令和部分输出的截图：

![按日期选择条目](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00109.jpeg)

圆括号或括号包含我们正在寻找的行范围，我们已经省略了主块，这确保我们打印出范围内的完整匹配行。没有什么能阻止我们进一步过滤匹配行中要打印的字段。例如，如果我们只想打印正在用于访问 Web 服务器的客户端 IP 地址，我们可以打印字段`1`。这在以下命令示例中显示。

```
 $ awk ' ( $4 ~ /10\/Sep\/2014/ ) { print $1 } ' access.log

```

如果我们想要能够打印给定日期的总访问次数，我们可以将条目通过管道传递到`wc`命令。这在以下示例中演示：

```
$ awk ' ( $4 ~ /10\/Sep\/2014/ ) { print $1 } ' access.log | wc -l

```

然而，如果我们想要使用`awk`来为我们做这个，这将比启动一个新进程更有效，并且我们可以计算条目。如果我们使用内置变量`NR`，我们可以打印文件中的整行而不仅仅是范围内的行。最好在主块中递增我们自己的变量，而不是为每行匹配范围。`END`块可以被实现以打印我们使用的`count`变量。以下命令行充当示例：

```
$ awk ' ( $4 ~ /10\/Sep\/2014/ ) { print $1; COUNT++ }  END { print COUNT }' access.log

```

![按日期选择条目](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00110.jpeg)

从`wc`和内部计数器的计数输出将使我们从演示文件中得到`16205`的结果。如果我们想要计数而不做其他操作，我们应该在主块中使用变量增量。

```
$ awk ' ( $4 ~ /10\/Sep\/2014/ ) { COUNT++ }  END { print COUNT }' access.log

```

我们可以在以下输出中看到这一点：

![按日期选择条目](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00111.jpeg)

## 总结 404 错误

请求页面的状态代码显示在日志的字段`9`中。`404`状态将表示服务器上找不到页面的错误，我相信我们都在某个阶段在我们的浏览器中看到过这个。这可能表明您网站上的链接配置错误，或者只是由浏览器搜索要在选项卡式浏览器中显示的图标图像而产生的。您还可以通过寻找标准页面的请求来识别对您网站的潜在威胁，这些页面可能会提供对 PHP 驱动站点的其他信息的访问，例如 WordPress。

首先，我们可以仅打印请求的状态：

```
$ awk '{ print $9 } ' access.log

```

现在我们可以稍微扩展代码，也可以扩展自己，只打印`404`错误：

```
$ awk ' ( $9 ~ /404/ ) { print $9 } ' access.log

```

这在以下代码中显示：

![总结 404 错误](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00112.jpeg)

我们可以进一步扩展，通过打印状态代码和正在访问的页面来打印。这将需要我们打印字段`9`和字段`7`。简而言之，这将如下所示：

```
$ awk ' ( $9 ~ /404/ ) { print $9, $7 } ' access.log

```

这些失败的访问页面中许多将是重复的。为了总结这些记录，我们可以使用`sort`和`uniq`命令的命令管道来实现这一点：

```
$ awk ' ( $9 ~ /404/ ) { print $9, $7 } ' access.log | sort | uniq

```

要使用`uniq`命令，数据必须经过预排序；因此，我们使用`sort`命令来准备数据。

## 总结 HTTP 访问代码

现在是时候离开纯命令行并开始使用 awk 控制文件了。与以往一样，当所需结果集的复杂性增加时，我们看到`awk`代码的复杂性也在增加。我们将在当前目录中创建一个`status.awk`文件。该文件应该类似于以下文件：

```
{ record[$9]++ }
END {
for (r in record)
print r, " has occurred ", record[r], " times." }
```

首先，我们将简化主代码块，这非常简单和稀疏。这是一种简单的方法来计算每个状态代码的唯一发生次数。我们不使用简单的变量，而是将其输入到数组中。这种情况下的数组称为记录。数组是一个多值变量，数组中的槽称为键。因此，我们将在数组中存储一组变量。例如，我们期望看到`record[200]`和`record[404]`的条目。我们用它们的发生次数填充每个键。每次我们找到`404`代码时，我们增加存储在相关键中的计数：

```
{ record[$9]++ }
```

在`END`块中，我们使用`for`循环创建摘要信息，以打印数组中的每个键和值：

```
END {
for (r in record)
print r, " has occurred ", record[r], " times." }
```

要运行这个，相关的命令行将类似于以下内容：

```
$ awk -f status.awk access.log

```

要查看命令和输出，我们已经包含了以下截图：

![总结 HTTP 访问代码](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00113.jpeg)

我们可以进一步关注`404`错误。当然，你可以选择任何状态代码。从结果中我们可以看到有`4382`个`404`状态代码。为了总结这些`404`代码，我们将`status.awk`复制到一个名为`404.awk`的新文件中。我们可以编辑`404.awk`，添加一个`if`语句，只处理`404`代码。文件应该类似于以下代码：

```
{ if ( $9 == "404" )
    record[$9,$7]++ }
END {
for (r in record)
print r, " has occurred ", record[r], " times." }
```

如果我们用以下命令执行代码：

```
$ awk -f 404.awk access.log

```

输出将类似于以下截图：

![总结 HTTP 访问代码](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00114.jpeg)

# 显示最高排名的 IP 地址

现在你应该意识到`awk`的一些功能，以及语言结构本身的强大之处。我们能够从这个 3 万行的文件中产生的数据是非常强大且容易提取的。我们只需要用`$1`替换之前使用过的字段。这个字段代表客户端 IP 地址。如果我们使用以下代码，我们将能够打印每个 IP 地址以及它被用来访问网页服务器的次数：

```
{ ip[$1]++ }
END {
for (i in ip)
print i, " has accessed the server ", ip[i], " times." }
```

我们希望能够扩展这个功能，只显示 IP 地址中排名最高的，即访问网站最频繁的地址。工作主要在`END`块中进行，将利用与当前最高排名地址的比较。可以创建以下文件并保存为`ip.awk`：

```
{ ip[$1]++ }
END {
for (i in ip)
    if ( max < ip[i] ) {
        max = ip[i]
        maxnumber = i }

print i, " has accessed ", ip[i], " times." }
```

我们可以在以下截图中看到命令的输出。客户端 IP 地址的部分已被隐藏，因为它来自我的公共网页服务器：

![显示最高排名的 IP 地址](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00115.jpeg)

代码的功能来自`END`块内部。进入`END`块时，我们进入一个`for`循环。我们遍历`ip`数组中的每个条目。我们使用条件`if`语句来查看我们正在遍历的当前值是否高于当前最大值。如果是，这将成为新的最高条目。当`循环`结束时，我们打印具有最高条目的 IP 地址。

# 显示浏览器数据

用于访问网站的浏览器包含在字段`12`的日志文件中。显示用于访问您网站的浏览器列表可能会很有趣。以下代码将帮助您显示报告的浏览器的访问列表：

```
{ browser[$12]++ }
END {
    for ( b in browser )
        print b, " has accessed ", browser[b], " times."
    }
```

你可以看到我们如何可以创建`awk`的小插件，并调整字段和数组名称以适应你自己的喜好。输出如下截图所示：

![显示浏览器数据](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00116.jpeg)

有趣的是，我们看到 Mozilla 4 和 5 占据了大部分请求客户端。我们看到 Mozilla 4 在这里列出了**1713**次。这里的 Mozilla/5.0 条目格式不正确，多了一个双引号。它稍后出现了 27K 次。

# 处理电子邮件日志

我们已经使用了来自 Apache HTTP Web 服务器的日志。事实是我们可以将相同的理念和方法应用到任何日志文件上。我们将查看 Postfix 邮件日志。邮件日志保存了来自 SMTP 服务器的所有活动，然后我们可以看到谁向谁发送了电子邮件。日志文件通常位于`/var/log/mail.log`。我将在我的 Ubuntu 15.10 服务器上访问这个文件，该服务器具有本地电子邮件传递功能。这意味着 STMP 服务器只监听`127.0.0.1`的本地接口。

日志格式将根据消息类型的不同而略有变化。例如，`$7`将包含出站消息的`from`日志，而入站消息将包含`to`。

如果我们想列出所有发送到 SMTP 服务器的入站消息，我们可以使用以下命令：

```
# awk '  ( $7 ~ /^to/ ) ' /var/log/mail.log

```

由于字符串`to`非常短，我们可以通过确保字段以`^`开头来为其添加标识。命令和输出如下截图所示：

![处理电子邮件日志](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00117.jpeg)

将扩展`to`或`from`搜索以包括用户名称将会很容易。我们可以看到交付或接收邮件的格式。使用与 Apache 日志相同的模板，我们可以轻松显示最高的收件人或发件人。

# 总结

现在我们在文本处理中有了一些重要的武器，我们可以开始理解`awk`有多么强大。使用真实数据在评估我们搜索的性能和准确性方面特别有用。在新安装的 Ubuntu 15.10 Apache Web 服务器上开始使用简单的 Apache 条目后，我们很快就迁移到了来自实时 Web 服务器的更大的样本数据。有 30,000 行，这个文件给了我们一些真实的数据来处理，我们很快就能够生成可信的报告。我们结束了返回 Ubuntu 15.10 服务器来分析 Postfix SMTP 日志。我们可以看到我们可以非常轻松地将之前使用过的技术拖放到新的日志文件中。

接下来，我们继续使用`awk`，看看如何报告 lastlog 数据和平面 XML 文件。


# 第十二章：使用 Awk 改进 lastlog

我们已经在第十一章中看到了如何从纯文本文件中挖掘大量数据并创建复杂报告。同样，我们可以使用标准命令行工具的输出来创建广泛的报告，比如`lastlog`工具。`lastlog`本身可以报告所有用户的最后登录时间。然而，我们可能希望过滤`lastlog`的输出。也许您需要排除从未用于登录系统的用户帐户。也可能不相关报告`root`，因为该帐户可能主要用于`sudo`，而不用于记录标准登录。

在本章中，我们将同时使用`lastlog`和 XML 数据格式化。由于这是我们调查 awk 的最后一章，我们将配置记录分隔符。我们已经看到了 awk 中字段分隔符的使用，但我们可以将默认记录分隔符从换行符更改为更符合我们需求的内容。具体来说，在本章中我们将涵盖：

+   使用 awk 范围来排除数据

+   基于行中字段数量的条件

+   操作 awk 记录分隔符以报告 XML 数据

# 使用 awk 范围来排除数据

到目前为止，在本书中，我们主要关注包括`sed`或`awk`的范围内的数据。使用这两个工具，我们可以否定范围，以便排除指定的行。这符合我们一直使用`lastlog`输出的需求。这将打印出所有用户的登录数据，包括从未登录的帐户。这些从未登录的帐户可能是服务帐户或尚未登录系统的新用户。

## lastlog 命令

如果我们查看`lastlog`的输出，当它没有任何选项时，我们可以开始理解问题。从命令行，我们以标准用户身份执行命令。没有必要以 root 帐户运行它。命令如下示例所示：

```
$ lastlog

```

部分输出如下截图所示：

![lastlog 命令](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00118.jpeg)

即使从这有限的输出中，我们可以看到由于从未登录的帐户创建的虚拟噪音而产生的混乱输出。使用`lastlog`选项可能在一定程度上缓解这一问题，但可能并不能完全解决问题。为了证明这一点，我们可以向`lastlog`添加一个选项，只包括通常由标准帐户使用的用户帐户。这可能因系统而异，但在我使用的样本 CentOS 6 主机上，第一个用户将是 UID 500。

如果我们使用`lastlog -u 500-5000`命令，我们将只打印 UID 在此范围内的用户的数据。在简单的演示系统中，我们只有三个用户帐户的输出是可以接受的。然而，我们可以理解到我们可能仍然有一些混乱，因为这些帐户尚未被使用。如下截图所示：

![lastlog 命令](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00119.jpeg)

除了从**从未登录**帐户打印出的多余数据之外，我们可能只对**用户名**和**最新**字段感兴趣。这是支持使用 awk 作为数据过滤器的另一个原因。通过这种方式，我们可以提供水平和垂直数据过滤，行和列。

## 使用 awk 进行水平过滤行

为了使用 awk 提供这种过滤，我们将把数据从`lastlog`直接传输到`awk`。我们将首先使用一个简单的控制文件来提供水平过滤或减少我们看到的行。首先，命令管道将如下命令示例一样简单：

```
$ lastlog | awk -f lastlog.awk

```

当然，复杂性是从命令行中抽象出来的，并隐藏在我们使用的控制文件中。最初，控制文件保持简单，读起来如下：

```
!(/Never logged in/ || /^Username/ || /^root/) {
  print $0;
}
```

范围设置与我们之前看到的一样，并在主代码块之前。在括号前使用感叹号可以否定或颠倒所选范围。双竖线作为逻辑`OR`。我们不包括包含`Never logged in`的行，也不包括以`Username`开头的行。这将移除`lastlog`打印的标题行。最后，我们排除 root 账户的显示。这初始化了我们要处理的行，主代码块将打印这些行。

## 匹配行的计数

我们可能还想计算过滤返回的行数。例如，使用内部的`NR`变量将显示所有行而不仅仅是匹配的行；为了能够报告已登录用户的数量，我们必须使用我们自己的变量。以下代码将在我们命名为`cnt`的变量中维护计数。我们使用 C 风格的`++`来增加主代码块的每次迭代。我们可以使用`END`代码块来显示这个变量的最终值：

```
!(/Never logged in/ || /^Username/ || /^root/) {
  cnt++
  print $0;
}
END {
  print "========================"
  print "Total Number of Users Processed: ", cnt
}
```

我们可以从以下代码和输出中看到这在我的系统上是如何显示的：

![匹配行的计数](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00120.jpeg)

从显示输出中，我们现在可以看到我们只显示已登录的用户，这种情况下只有一个用户。然而，我们可能还决定要进一步抽象数据，并且只显示匹配行中的某些字段。这应该是一个简单的任务，但它很复杂，因为字段的数量将取决于登录的方式。

# 基于字段数量的条件

如果用户直接登录到服务器的物理控制台，而不是通过远程或图形伪终端登录，那么`lastlog`输出将不会显示主机字段。为了证明这一点，我直接登录到我的 CentOS 主机的`tty1`控制台，并避免了图形界面。之前 awk 控制文件的输出显示我们现在有用户**tux**和**bob**；然而**bob**缺少主机字段，因为他连接到控制台。

![基于字段数量的条件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00121.jpeg)

虽然这本身不是问题，但如果我们想要过滤字段，两行的字段编号将有所不同，因为某些行中省略了字段。对于`lastlog`，大多数连接将有`9`个字段，而直接连接到服务器控制台的连接只有`8`个字段。应用程序的要求是打印用户名和日期，但不打印最后登录的时间。我们还将在`BEGIN`块中打印我们自己的标题。为了确保我们使用正确的位置，我们需要使用`NF`内部变量来计算每行的字段数。

对于有`8`个字段的行，我们想要打印字段`1`、`4`、`5`和`8`；对于有额外主机信息的较长行，我们将使用字段`1`、`5`、`6`和`9`。我们还将使用`printf`来正确对齐列数据。控制文件应该被编辑，如下例所示：

```
BEGIN {
printf "%8s %11s\n","Username","Login date"
print "===================="
}
!(/Never logged in/ || /^Username/ || /^root/) {
cnt++
if ( NF == 8 )
    printf "%8s %2s %3s %4s\n", $1,$5,$4,$8

else
    printf "%8s %2s %3s %4s\n", $1,$6,$5,$9
}
END {
print "===================="
print "Total Number of Users Processed: ", cnt
}
```

我们可以在以下截图中看到命令和它产生的输出。我们可以看到如何基于我们想要关注的信息创建更合适的显示：

![基于字段数量的条件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00122.jpeg)

如果我们看一下输出，我选择在月份之前显示日期，这样我们就不按数字顺序显示字段。当然，这是个人选择，可以根据你认为数据应该如何显示进行自定义。

我们可以使用`lastlog`控制文件中所见原则的输出来过滤任何命令的输出，并且你应该练习使用你想要过滤数据的命令。

# 操纵 awk 记录分隔符以报告 XML 数据

到目前为止，虽然我们一直在使用 awk，但我们只限于处理单独的行，每一行代表一个新记录。虽然这通常是我们想要的，当我们处理带有标记数据的情况时，比如 XML，其中一个单独的记录可能跨越多行。在这种情况下，我们可能需要设置`RS`或`record`分隔符内部变量。

## Apache 虚拟主机

在第九章中，*自动化 Apache 虚拟主机*，我们使用了**Apache 虚拟主机**。这使用了定义每个虚拟主机的开始和结束的标记数据。即使我们更喜欢将每个虚拟主机存储在自己的文件中，它们也可以合并到单个文件中。考虑以下文件，它存储了可能的虚拟主机定义，可以存储为`virtualhost.conf`文件，如下所示：

```
<VirtualHost *:80>
DocumentRoot /www/example
ServerName www.example.org
# Other directives here
</VirtualHost>

<VirtualHost *:80>
DocumentRoot /www/theurbanpenguin
ServerName www.theurbanpenguin.com
# Other directives here
</VirtualHost>

<VirtualHost *:80>
DocumentRoot /www/packt
ServerName www.packtpub.com
# Other directives here
</VirtualHost>
```

我们在单个文件中有三个虚拟主机。每个记录由一个空行分隔，这意味着我们有两个逻辑上分隔每个条目的新行字符。我们通过设置`RS`变量来告诉 awk 这一点：`RS="\n\n"`。有了这个设置，我们就可以打印所需的虚拟主机记录。这将在控制文件的`BEGIN`代码块中设置。

我们还需要动态搜索命令行以获取所需的主机配置。我们将这构建到控制文件中。控制文件应该类似于以下代码：

```
BEGIN { RS="\n\n" ; }
$0 ~ search { print }
```

`BEGIN`块设置变量，然后我们进入范围。范围设置为记录(`$0`)匹配(`~`)`search`变量。我们必须在执行`awk`时设置变量。以下命令演示了命令行执行，控制文件和配置文件位于我们的工作目录中：

```
$ awk -f vh.awk search=packt virtualhost.conf

```

通过查看以下屏幕截图中生成的命令和输出，我们可以更清楚地看到这一点：

![Apache 虚拟主机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00123.jpeg)

## XML 目录

我们可以进一步扩展到 XML 文件，其中我们可能不想显示完整的记录，而只是某些字段。如果我们考虑以下产品`目录`：

```
<product>
<name>drill</name>
<price>99</price>
<stock>5</stock>
</product>

<product>
<name>hammer</name>
<price>10</price>
<stock>50</stock>
</product>

<product>
<name>screwdriver</name>
<price>5</price>
<stock>51</stock>
</product>

<product>
<name>table saw</name>
<price>1099.99</price>
<stock>5</stock>
</product>
```

逻辑上，每个记录都与之前的空行分隔。每个字段都更详细，我们需要使用分隔符`FS="[><]"`。我们将开头或结尾的尖括号定义为字段分隔符。

为了帮助分析这一点，我们可以打印单个记录如下：

```
<product><name>top</name><price>9</price><stock>5</stock></product>
```

每个尖括号都是一个字段分隔符，这意味着我们将有一些空字段。我们可以将这行重写为 CSV 文件：

```
,product,,name,top,/name,,price,9,/price,,stock,5,/stock,,/product,
```

我们只需用逗号替换每个尖括号，这样我们更容易阅读。我们可以看到字段`5`的内容是`top`值。

当然，我们不会编辑 XML 文件，我们会保留它的 XML 格式。这里的转换只是为了突出字段分隔符的读取方式。

我们用于从 XML 文件中提取数据的控制文件在以下代码示例中说明：

```
BEGIN { FS="[><]"; RS="\n\n" ; OFS=""; }
$0 ~ search { print $4 ": " $5, $8 ": " $9, $12 ": " $13 }
```

在`BEGIN`代码块中，我们设置了`FS`和`RS`变量，正如我们讨论过的。我们还将`OFS`或**输出字段分隔符**设置为一个空格。这样，当我们打印字段时，我们用空格分隔值，而不是保留尖括号。这个范围使用了与我们之前查看虚拟主机时使用的相同匹配。

如果我们需要在`目录`中搜索产品`drill`，我们可以使用以下示例中列出的命令：

```
$ awk -f catalog.awk search=drill catalog.xml

```

以下屏幕截图详细显示了输出：

![XML 目录](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00124.jpeg)

我们现在已经能够从一个相当混乱的 XML 文件中创建可读的报告。awk 的强大再次得到了突出，并且对我们来说，这是本书中的最后一次。到目前为止，我希望你也能开始经常使用它。

# 总结

我们已经有了三个章节，在这些章节中我们使用了 awk。从第十章开始，*Awk 基础*，我们变得更加熟悉。在第十一章中，*使用 Awk 总结日志*以及这一章，我们开始构建我们定制的应用程序。

具体来说，在这一章中，我们看到了如何从标准命令的输出中创建报告，比如`lastlog`。我们看到我们可以否定范围，并且另外利用`OR`语句。然后我们构建了一个允许我们查询 XML 数据的应用程序。

在接下来的两章中，我们将远离 shell 脚本，转而使用 perl 和 Python 编写脚本，这样我们可以比较脚本语言并做出适当的选择。


# 第十三章：使用 Perl 作为 Bash 脚本的替代方案

使用 bash 进行脚本编写可以帮助您自动化任务，并且通过掌握 bash 脚本编写，您可以取得很大成就。然而，您的旅程不应该以 bash 结束。虽然我们已经看到了在 bash 脚本中可用的功能，但我们受到可以运行的命令和它们的选项的限制。Bash 脚本允许我们访问命令；而如果我们使用 Perl 脚本，我们就可以访问系统的编程接口或 API。通过这种方式，我们通常可以用更少的资源实现更多的功能。

在本章中，我们将介绍 Perl 脚本和一些其他基本脚本，我们可以用来学习 Perl；我们将涵盖以下主题：

+   什么是 Perl？

+   Hello World

+   Perl 中的数组

+   Perl 中的条件测试

+   函数

# 什么是 Perl？

Perl 是一种脚本语言，由 Larry Wall 在 1980 年代开发，用于扩展`sed`和`awk`的功能。它是**Practical Extraction and Reporting Language**的首字母缩写，但已经远远超出了最初的目的，今天它可以在 Unix、Linux、OS X 和 Windows 操作系统上使用。

尽管它是一种脚本语言，但它不是 shell 脚本；因此没有 Perl shell。这意味着代码必须通过 Perl 脚本执行，而不是直接从命令行执行。唯一的例外是`perl`命令的`-e`选项，它可以允许您执行一个`perl`语句。例如，我们可以使用以下命令行来打印无处不在的`Hello World`：

```
$ perl -e ' print("Hello World\n");'

```

您会发现 Perl 默认安装在大多数 Linux 和 Unix 系统上，因为许多程序将在它们的代码中使用 Perl。要检查您系统上安装的 Perl 版本，可以使用`perl`命令，如下所示：

```
$ perl -v

```

这个命令的输出显示在我树莓派上的以下截图中：

![什么是 Perl？](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00125.jpeg)

### 注意

在本章中，大写的 Perl 将指的是语言，小写的`perl`将指的是命令。

如果我们创建一个 Perl 脚本，就像 bash 一样，它将是一种解释性语言，第一行将是 shebang，以便系统知道要使用哪个命令来读取脚本。`/usr/bin/perl`命令通常用于定位`perl`。要验证这一点，可以使用：

```
$ which perl

```

与 bash 不同，当`perl`命令读取脚本时，它将在运行时优化脚本；这将使我们能够在脚本末尾定义函数，而不是在使用之前。当我们在本章中详细查看 Perl 脚本时，我们将看到这一点。

# Hello World

要创建一个简单的 Perl 脚本，我们可以使用所选的文本编辑器。对于短脚本，`vi`或`vim`效果很好，如果要在 GUI 中工作，`gedit`也可以。对于较大的项目，IDE 可能会有所帮助。通常，IDE 将允许您轻松地在整个脚本中更改对象名称并提供对象名称的扩展。在本章中，我们将继续使用`vi`。

我们将创建一个`$HOME/bin/hello.pl`文件来产生我们想要的输出：

```
#!/usr/bin/perl
print("Hello World\n");
```

文件仍然需要在我们的`PATH`变量中的目录中；因此，我们创建`$HOME/bin`。如果它不在`PATH`变量中，那么我们将需要指定文件的完整路径或相对路径，就像 bash 一样。

文件需要设置执行权限。我们可以使用以下命令来实现：

```
$ chmod u+x $HOME/bin/hello.pl

```

我们可以使用以下命令运行脚本：

```
$ hello.pl

```

我们可以看到我们添加的代码与我们之前运行的`perl -e`命令相同。唯一的区别是 shebang。这也与 bash 非常相似。我们现在使用 print 函数而不是使用`echo`命令。Bash 脚本运行一系列命令，而 Perl 脚本运行函数。print 函数不会自动添加新行，因此我们使用`\n`字符自己添加。我们还可以看到 Perl 使用分号来终止一行代码。shebang 不是一行代码，而 print 行以分号终止。

如果我们使用的是 Perl 5.10 或更高版本，在 Pi 上我们已经看到它是 5.14，我们还可以使用一个名为`say`的函数。类似于`print`命令，它用于显示输出，但它还包括换行符。我们必须启用此功能，由`use`关键字管理。以下任一脚本都将使用`say`函数打印`Hello World`：

```
#!/usr/bin/perl
use v5.10;
say("Hello World");

#!/usr/bin/perl
use 5.10.0;
say("Hello World");
```

`say`函数还简化了文件和列表的打印。

# Perl 数组

在 Perl 中我们可以利用的一点是数组。这些数组是从列表创建的变量；简单地说，它们基本上是多值变量。如果我们要使用容器类比来描述一个变量，它将是一个杯子或一个值的占位符。数组将类比为一个板条箱。我们可以用一个单一的名称描述板条箱，但是我们必须包括额外的命名元素来访问板条箱内的每个槽。一个板条箱可以容纳多个项目，就像一个数组一样。

我们看到通过使用 bash 脚本，我们可以在脚本中传递命令行参数。参数使用它们自己的变量名，`$1`，`$2`等。这也与程序的名称有一定的冲突，因为它是`$0`。即使它们看起来可能相似，但`$0`和`$1`之间没有逻辑关系。`$0`变量是脚本的名称，`$1`是第一个参数。当我们在 Perl 中看到这一点时，我们可以开始看到一些主要的区别。

## 程序名称？

在 Perl 中，程序名称仍然可以使用`$0`变量访问。我们可以在以下脚本中看到这一点：

```
#!/usr/bin/perl
print("You are using $0\n");
print("Hello World\n");
```

现在，即使我们认为`$0`使用起来相当简单，因为我们之前在 bash 中访问过它，但如果我们以全新的眼光来看待它，它并不那么明显。Perl 有一个名为`English`的模块，其中定义了许多其他在 Perl 中使用的变量的更友好的名称。如果我们看一下以下脚本，我们可以看到它的用法：

```
#!/usr/bin/perl
use English;
print("You are using $PROGRAM_NAME\n");
print("Hello World\n");
```

`use English`;这一行将导入重新定义`$0`的模块，以便可以将其引用为`$PROGRAM_NAME`。尽管这需要更多的输入，但它也作为一个更好的名称来记录其目的。

## 参数数组

不再使用`$1`，`$2`等参数；Perl 现在使用存储在单个数组变量中的参数列表。数组名称是`@ARGV`，我们可以通过索引号或槽号访问由此提供的每个参数。计算机从`0`开始计数，所以第一个参数将是`$ARGV[0]`，第二个将是`$ARGV[1]`，依此类推。

### 注意

使用`@`符号命名索引数组。数组的每个元素仍然是单个或标量变量，就像在 bash 中一样，它们使用`$`符号读取。

当我们查看以下脚本`$HOME/bin/args.pl`时，我们可以看到如何通过接受参数使 Hello 脚本更具可移植性：

```
#!/usr/bin/perl
use English;
print("You are using $PROGRAM_NAME\n");
print("Hello $ARGV[0]\n");
```

我们可以通过运行脚本来看到这一点，如下面的屏幕截图所示：

![参数数组](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00126.jpeg)

## 计算数组中的元素

我们可以看到命令行参数存储在`@ARGV`数组中。我们可以使用以下代码计算参数的数量，或者实际上是任何数组中的元素：

```
scalar @<array-name>;
```

因此，我们将使用以下代码来计算提供的参数，而不是使用`$#`：

```
scalar @ARGV;
```

如果我们将这个添加到我们的脚本中，它将会被看到，如下面的代码块所示：

```
#!/usr/bin/perl
use English;
print("You are using $PROGRAM_NAME\n");
print("You have supplied: " . scalar @ARGV . " arguments\n");
print("Hello $ARGV[0]\n");
```

### 注意

我们还可以从前面的代码块中注意到，我们可以使用句点字符将命令的输出与测试连接起来。

## 循环遍历数组

在 bash 中，我们有一个简单的机制，使用`$*`来引用提供给脚本的参数列表。在 Perl 中，这与必须循环遍历列表略有不同。然而，`foreach`关键字是为此而建立的：

```
#!/usr/bin/perl
use English;
print("You are using $PROGRAM_NAME\n");
print("You have supplied " . scalar @ARGV . " arguments\n");
foreach $arg (@ARGV) {
 print("Hello $arg\n");
}
```

我们可以看到，代码是在循环内定义的，并使用大括号括起来。如果您还记得，bash 并没有专门的`foreach`关键字，而是使用`do`和`done`来限制代码。

如果我们在`$HOME/bin/forargs.pl`文件中实现此代码，我们可以执行类似以下屏幕截图的代码：

![循环遍历数组](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00127.jpeg)

## 创建数组

到目前为止，我们一直依赖于`@ARGV`系统数组，这已被证明是学习如何访问数组的好方法。现在我们需要看看如何创建我们自己设计的数组。

数组是可以存储混合数据类型的值的列表；因此，我们可以有一个既存储字符串又存储数字的数组是毫无问题的。提供给数组的项目的顺序将设置它们的索引位置。换句话说，列表中的第一项将是数组中的第一个索引或索引`0`。考虑以下代码：`$HOME/bin/array.pl`：

```
#!/usr/bin/perl
use English;
print("You are using $PROGRAM_NAME\n");
@user = ("Fred","Bloggs",24);
print("$user[0] $user[1] is @user[2]\n");
```

我们应该注意的第一件事是，当我们设置任何类型的变量时，包括数组时，我们将使用变量类型的指示符。我们在这里看到，使用`@user = …`，将使用先前提到的`@`符号来表示变量是一个数组变量。如果我们设置一个类似于我们在 bash 中使用的标量变量，我们将设置`$user`。在 bash 中，设置变量时不使用指示符，并且我们不能在赋值运算符`=`周围有空格。Perl 将允许空格，并通过额外的空格提高可读性。

接下来，我们应该注意到列表包含字符串和整数。这是完全可以接受的，数组可以容纳不同的数据类型。数组的单个名称是有意义的，因为我们现在可以将相关数据存储到一个对象中。

在提供的代码中需要注意的最后一点是，我们可以轻松地使用 Perl 将字符串值与整数值连接起来。无需提供任何形式的数据转换。在单个字符串中，我们打印用户的名字、姓氏和年龄。

在脚本执行时，我们应该收到一个输出，如下面的屏幕截图所示：

![创建数组](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00128.jpeg)

# Perl 中的条件语句

与 Perl 语言的其余部分类似，我们将与 bash 脚本编写有相似之处，也有一些完全实现条件的新方法。这通常对我们有利，因此使代码更易读。

## 替换命令行列表

首先，我们没有命令行列表逻辑，我们在 bash 中使用的逻辑，也不使用`&&`和`||`。在 Perl 中，单个语句的条件逻辑是以以下方式编写的，而不是这些看起来相当奇怪的符号：

```
exit(2) if scalar @ARGV < 1;
print("Hello $ARGV[0]\n") unless scalar @ARGV == 0;
```

在第一个例子中，如果我们提供的命令行参数少于一个，我们将以错误代码`2`退出。这在 bash 中的等效操作将是：

```
[ $# -lt 1 ] && exit 2
```

在第二个例子中，只有在我们提供了参数时，我们才会打印`hello`语句。这将在 bash 中编写，如下例所示：

```
[ $# -eq 0 ] || echo "Hello $1"
```

就个人而言，我喜欢 Perl；至少它使用单词的方式，这样我们即使以前没有遇到过这些符号，也可以理解发生了什么。

## If 和 unless

在 Perl 中，我们已经在之前的例子中看到，我们可以使用`unless`来使用负逻辑。我们既有传统的`if`关键字，现在又有了`unless`。我们可以在我们已经看到的短代码中使用这些，也可以在完整的代码块中使用。

我们可以编辑现有的 `args.pl` 来创建一个新文件：`$HOME/bin/ifargs.pl`。文件应该类似于以下代码：

```
#!/usr/bin/perl
use English;
print("You are using $PROGRAM_NAME\n");
my $count = scalar @ARGV;
if ($count > 0) {
  print("You have supplied $count arguments\n");
  print("Hello $ARGV[0]\n");
}
```

现在代码有了一个额外的参数，我们已经声明并设置了这一行 `my $count = scalar @ARGV;`。我们使用这个值作为 `if` 语句的条件。在大括号中限定的代码块只有在条件为真时才会执行。

我们演示了在下面的截图中使用和不使用参数运行此程序：

![If and unless](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00129.jpeg)

我们可以使用 `unless` 来编写类似的代码：

```
print("You are using $PROGRAM_NAME\n");
my $count = scalar @ARGV;
unless ($count == 0) {
  print("You have supplied $count arguments\n");
  print("Hello $ARGV[0]\n");

}
```

括号中的代码现在只有在条件为假时才运行。在这种情况下，如果我们没有提供参数，代码将不运行。

# 在 Perl 中使用函数

与所有语言一样，将代码封装在函数中可以使代码更易读，并最终导致更易管理的代码，代码行数也更少。与 bash 不同，Perl 中的函数可以在代码中引用后定义，我们通常选择在脚本末尾定义函数。

## 提示用户输入

我们已经看到了在 Perl 中使用命令行参数；现在，让我们来看看如何提示用户输入。这成为了一种封装执行代码和存储提示的好方法。首先，我们将看一个简单的脚本，提示用户名，然后我们将修改它以包含函数。我们将创建 `$HOME/bin/prompt.pl` 文件来读取，如下面的代码示例所示：

```
#!/usr/bin/perl
my $name;
print("Enter your name: ");
chomp( $name = <STDIN> );
print("Hello $name\n");
```

在第 2 行，我们使用 `my` 声明了变量。关键字 `my` 定义了具有局部作用域的变量。换句话说，它仅在创建它的代码块中可用。由于这是在脚本的主体中创建的，变量对整个脚本都是可用的。这一行声明了变量，但我们此时没有设置值。Perl 不强制您声明变量，但这是一个好主意和一个很好的实践。事实上，我们可以告诉 Perl 使用 `use strict;` 行来强制执行这一点。我们可以实现这一点，如下面的代码块所示：

```
#!/usr/bin/perl
use strict;
my $name;
print("Enter your name: ");
chomp( $name = <STDIN> );
print("Hello $name\n");
```

有了这个，我们被迫声明变量，如果没有声明，代码将失败。这背后的想法是通过在代码后期识别拼写错误的变量来帮助故障排除。尝试删除以 `my` 开头的行并重新执行代码；它将失败。同样，我们可以使用 `use warnings;` 行，如果我们只使用了一次变量，它会警告我们。

我们提示用户输入用户名，这里不使用换行符。我们希望提示与用户输入数据的行在同一行上。`chomp` 函数很棒，不是吗？这个函数将删除或截断我们提交的输入中的换行符。我们需要使用 *Enter* 键提交数据，`chomp` 会为我们删除换行符。

## 创建函数

目前我们只提示用户输入用户名，所以我们只需要一个提示，但我们也可以很容易地要求名字和姓氏。我们可以创建一个函数，而不是每次都写提示的代码。这些是使用关键字 `sub` 定义的，如下面的代码所示：

```
#!/usr/bin/perl
use strict;
my $name = prompt_user("Enter a name: ");
print("Hello $name\n");

sub prompt_user () {
   my $n;
   print($_[0]);
   chomp( $n = <STDIN> );
   return($n);
}
```

`prompt_user` 函数接受一个参数，这个参数将成为显示提示的消息。对于参数的引用，我们使用系统数组 `@_` 和索引 `0`。这写作 `$_[0]`。如果我们记得，数组是多值的，数组中的每个条目都是一个标量变量。在函数内部，我们使用函数返回将用户设置的值发送回调用代码。我们可以看到主代码块现在更简单了，因为提示的代码被抽象成了一个函数。当我们看到这个时，可能会觉得这需要很多工作，但是当我们为名字和姓氏添加提示时，现在就简单多了。

使用函数是一个好习惯，希望下面的代码能帮助你看到这一点：

```
#!/usr/bin/perl
use strict;
my $fname = prompt_user("Enter a first name: ");
my $lname = prompt_user("Enter a last name: ");

print("Hello $fname $lname\n");

sub prompt_user () {
   my $n;
   print($_[0]);
   chomp( $n = <STDIN> );
   return($n);
}
```

# 总结

这就结束了我们的风风火火的旅程和对 Perl 的介绍。我们已经看到了它与 bash 的相似之处，以及新的特性和区别。从中可以得出的主要观点是，一旦你精通一种语言，学习其他编程语言就会变得更容易。

为了保持学习新语言的兴致，我们接下来将在下一章快速了解 Python。
