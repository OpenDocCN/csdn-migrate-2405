# Linux Shell 脚本编程基础知识（三）

> 原文：[`zh.annas-archive.org/md5/0DC4966A30F44E218A64746C6792BE8D`](https://zh.annas-archive.org/md5/0DC4966A30F44E218A64746C6792BE8D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：自定义环境

在默认系统中，我们会得到预配置的某些设置。随着时间的推移，我们经常感到需要修改一些默认设置。当我们在 shell 中工作以完成任务时，例如根据应用程序的需求修改环境时，会出现类似的需求。有些功能是如此令人难以抗拒，以至于我们可能每次都需要它们，例如应用程序使用的我们选择的编辑器。在处理重要任务时，可能会忘记几天前使用的命令。在这种情况下，我们会尽快回忆起该命令，以完成工作。如果我们记不起来，就会花费时间和精力在互联网或教科书中搜索确切的命令和语法。

在本章中，我们将看到如何通过添加或更改现有环境变量来修改环境，以满足我们的应用需求。我们还将看到用户如何修改`.bashrc`、`.bash_profile`和`.bash_logout`文件，以使设置更改永久生效。我们将看到如何搜索和修改先前执行的命令的历史记录。我们还将看到如何从单个 shell 运行多个任务并一起管理它们。

本章将详细介绍以下主题：

+   了解默认环境

+   修改 shell 环境

+   使用 bash 启动文件

+   了解你的历史

+   管理任务

# 了解默认环境

设置适当的环境对于运行进程非常重要。环境由环境变量组成，这些变量可能具有默认值或未设置默认值。通过修改现有环境变量或创建新的环境变量来设置所需的环境。环境变量是导出的变量，可用于当前进程及其子进程。在第一章, *脚本之旅的开始*中，我们了解了一些内置 shell 变量，可以将其用作环境变量来设置环境。

## 查看 shell 环境

要查看 shell 中的当前环境，可以使用`printenv`或`env`命令。环境变量可能没有值，有单个值，或者有多个值设置。如果存在多个值，每个值都用冒号(:)分隔。

### printenv

我们可以使用`printenv`来打印与给定环境变量相关联的值。语法如下：

`$ printenv [VARIABLE]`

考虑以下示例：

```
$ printenv SHELL    # Prints which shell is being used
/bin/bash
$ printenv PWD    # Present working directory
/home/foo/Documents
$ printenv HOME    # Prints user's home directory
/home/foo
$ printenv PATH    # Path where command to be executed is searched
/usr/lib64/qt-3.3/bin:/usr/lib64/ccache:/bin:/usr/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/home/foo
$ printenv USER HOSTNAME  # Prints value of both environment variables
foo
localhost

```

如果未指定`VARIABLE`，`printenv`将打印所有环境变量，如下所示：

```
$ printenv  # Prints all environment variables available to current shell

```

### 环境

我们也可以使用`env`命令来查看环境变量，如下所示：

```
$ env

```

这将显示为给定 shell 定义的所有环境变量。

### 注意

要查看特定环境变量的值，也可以使用`echo`命令，后跟以美元符号(`$`)为前缀的环境变量名称。例如，`echo $SHELL`。

## shell 和环境变量之间的区别

shell 变量和环境变量都是可访问和设置的变量，用于给定的 shell，可能被在该 shell 中运行的应用程序或命令使用。但是，它们之间有一些区别，如下表所示：

| Shell 变量 | 环境变量 |
| --- | --- |
| 本地和导出的变量都是 shell 变量 | 导出的 shell 变量是环境变量 |
| 使用`set builtin`命令可查看 shell 变量的名称和相应值 | 使用`env`或`printenv`命令可查看环境变量的名称和相应值 |
| 本地 shell 变量不可供子 shell 使用 | 子 shell 继承父 shell 中存在的所有环境变量 |
| 通过在等号（=）的右侧用冒号（:）分隔的值在左侧指定变量名称来创建 shell 变量 | 可以通过在现有 shell 变量前加上 export shell 内置命令的前缀，或者在创建新的 shell 变量时创建环境变量 |

# 修改 shell 环境

当启动新的 shell 时，它具有初始环境设置，将被任何在给定 shell 中执行的应用程序或命令使用。我们现在知道，`env`或`setenv` shell 内置命令可用于查看为该 shell 设置了哪些环境变量。shell 还提供了修改当前环境的功能。我们还可以通过创建、修改或删除环境变量来修改当前的 bash 环境。

## 创建环境变量

要在 shell 中创建一个新的环境变量，使用`export` shell 内置命令。

例如，我们将创建一个新的环境变量`ENV_VAR1`：

```
$ env | grep ENV_VAR1  # Verifying that ENV_VAR1 doesn't exist
$ export ENV_VAR1='New environment variable'

```

创建了一个名为`ENV_VAR1`的新环境变量。要查看新环境变量，可以调用`printenv`或`env`命令：

```
$ env | grep ENV_VAR1
ENV_VAR1=New environment variable
$ printenv ENV_VAR1    # Viewing value of ENV_VAR1 environment variable
New environment variable

```

我们还可以使用`echo`命令来打印环境变量的值：

```
$ echo $ENV_VAR1  # Printing value of ENV_VAR1 environment variable
New environment variable

```

本地 shell 变量也可以进一步导出为环境变量。例如，我们将创建`ENV_VAR2`和`LOCAL_VAR1`变量：

```
$ ENV_VAR2='Another environment variable'
$ LOCAL_VAR1='Local variable'
$ env | grep ENV_VAR2  # Verifying if ENV_VAR2 is an environment variable

```

找不到名为`ENV_VAR2`的环境变量。这是因为在创建`ENV_VAR2`时，它没有被导出。因此，它将被创建为 shell 的本地变量：

```
$ set | grep ENV_VAR2
ENV_VAR2='Another environment variable'
$ set | grep  LOCAL_VAR1
LOCAL_VAR1='Local variable'

```

现在，要将`ENV_VAR2` shell 变量作为环境变量，可以使用 export 命令：

```
$ export ENV_VAR2    # Becomes environment variable
$ printenv ENV_VAR2    # Checking of  ENV_VAR2 is an environment variable
Another environment variable
$ printenv LOCAL_VAR1

```

变量`LOCAL_VAR1`不是环境变量。

环境变量的一个重要特点是它对所有子 shell 都可用。我们可以在以下示例中看到这一点：

```
$ bash  # creating a new bash shell
$ env | grep ENV_VAR2  # Checking if  ENV_VAR2 is available in child shell
ENV_VAR2=Another environment variable
$ env | grep ENV_VAR1
ENV_VAR1=New environment variable
$ env | grep LOCAL_VAR1

```

我们可以看到，从父 shell 继承的环境变量被子 shell 继承，例如`ENV_VAR1`，`ENV_VAR2`，而本地变量，如`LOCAL_VAR1`，仅对创建变量的 shell 可用。

## 修改环境变量

Shell 提供了灵活性，可以修改任何现有的环境变量。例如，考虑`HOME`环境变量。默认情况下，`HOME`环境变量包含当前登录用户的主目录的路径：

```
$ printenv HOME
/home/foo
$ pwd    # Checking current working directory
/tmp
$ cd $HOME    # Should change directory to /home/foo
$ pwd    # Check now current working directory
/home/foo

```

现在，我们将修改`HOME`环境变量的值为`/tmp`：

```
$ HOME=/tmp    # Modifying HOME environment variable
$ printenv HOME    # Checking value of HOME environment variable
/tmp
$ cd $HOME    # Changing directory to what $HOME contains
$ pwd    # Checking current working directory
/tmp

```

我们还可以向环境变量附加一个值。为此，请确保新值用冒号（:）分隔。例如，考虑`PATH`环境变量：

```
$ printenv PATH
usr/lib64/ccache:/bin:/usr/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/home/foo/.local/bin:/home/foo/bin

```

现在，我们想要将一个新路径添加到`PATH`变量中，例如`/home/foo/projects/bin`，这样，在查找程序或命令时，shell 也可以搜索指定的路径。要将路径追加到`PATH`环境变量中，使用冒号（:）后跟新路径名称：

```
$ PATH=$PATH:/home/foo/projects/bin  # Appends new path
$ printenv PATH
usr/lib64/ccache:/bin:/usr/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/home/foo/.local/bin:/home/foo/bin:/home/foo/projects/bin

```

我们可以看到新路径已附加到`PATH`变量的现有值上。

我们还可以将多个值附加到环境变量；为此，每个值应该用冒号（:）分隔。

例如，我们将向`PATH`变量添加两个应用程序路径：

```
$ PATH=$PATH:/home/foo/project1/bin:PATH:/home/foo/project2/bin
$ printenv PATH
usr/lib64/ccache:/bin:/usr/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/home/foo/.local/bin:/home/foo/bin:/home/foo/projects/bin:/home/foo/project1/bin:PATH:/home/foo/project2/bin

```

两个新路径`/home/foo/project1/bin`和`/home/foo/project2/bin`已添加到`PATH`变量中。

## 删除环境变量

我们可以使用`unset` shell 内置命令删除或重置环境变量的值。

例如，我们将创建一个名为`ENV1`的环境变量：

```
$ export ENV1='My environment variable'
$ env | grep ENV1  # Checking if ENV1 environment variable exist
ENV1=My environment variable
$ unset ENV1    # Deleting ENV1 environment variable
$ env | grep ENV1

```

环境变量`ENV1`被`unset`命令删除。现在，要重置环境变量，将其赋予空值：

```
$ export ENV2='Another environment variable'
$ env | grep ENV2
ENV2=Another environment variable
$ ENV2=''	# Reset ENV2 to blank
$ env | grep ENV2
ENV2=

```

# 使用 bash 启动文件

到目前为止，要执行任务或为给定的 shell 设置任何内容，我们必须在 shell 中执行所需的命令。这种方法的主要局限性之一是相同的配置不会在新的 shell 中可用。在许多情况下，用户可能希望每当启动新的 shell 时，而不是使用新的自定义配置，而是使用默认配置之上的新的自定义配置。对于自定义 bash，用户的主目录中默认执行的三个文件是`bashrc`、`.bash_profile`和`.bash_logout`。

## .bashrc

在图形系统中，用户主要使用非登录 shell。要运行非登录 shell，我们不需要登录凭据。在图形系统中启动 shell 提供了一个非登录 shell。当 bash 以非登录模式调用时，会调用`~/.bashrc`文件，并执行其中可用的配置，并将其应用于任何启动的 bash shell。需要在登录和非登录 shell 中都需要的设置保存在`~/.bashrc`文件中。

例如，在 Fedora 22 系统上，默认的`~/.bashrc`文件如下：

```
# .bashrc

# Source global definitions
if [ -f /etc/bashrc ]; then
        . /etc/bashrc
fi

# Uncomment the following line if you don't like systemctl's auto-paging feature:
# export SYSTEMD_PAGER=

# User specific aliases and functions
```

在`~/.bashrc`中进行的任何添加只会反映到当前用户的 bash shell。我们可以看到`.bashrc`文件还检查`etc/bashrc`文件是否可用。如果可用，也会执行该文件。`/etc/bashrc`文件包含应用于所有用户的 bash shell 的系统范围配置。如果需要应用到所有用户的 bash shell 的任何配置，系统管理员可以修改`/etc/bashrc`文件。

`/etc/bashrc`文件还查看了`/etc/profile.d`中可用的脚本文件，可以通过`/etc/bashrc`文件中的以下代码片段确认：

```
 for i in /etc/profile.d/*.sh; do
        if [ -r "$i" ]; then
            if [ "$PS1" ]; then
                . "$i"
```

以下示例显示了修改后的`.bashrc`文件。将此文件命名为`custom_bashrc`：

```
# custom_bashrc

# Source global definitions
if [ -f /etc/bashrc ]; then
        . /etc/bashrc
fi

# Uncomment the following line if you don't like systemctl's auto-paging feature:
# export SYSTEMD_PAGER=

# User added settings
# Adding aliases
alias rm='rm -i'  # Prompt before every removal
alias cp='cp -i'  # Prompts before overwrite
alias df='df -h'  # Prints size in human readable format
alias ll='ls -l'  # Long listing of file

# Exporting environment variables
# Setting and exporting LD_LIBRARY_PATH variable
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:~/libs
# Setting number of commands saved in history file to 10000
export HISTFILESIZE=10000

# Defining functions
# Function to calculate size of current directory
function current_directory_size()
{
echo -n "Current directory is $PWD with total used space "
du -chs $PWD 2> /dev/null | grep total | cut -f1
}
```

`LD_LIBRARY_PATH`环境变量用于为运行时共享库加载器（`ld.so`）提供额外的目录，以便在搜索共享库时查找。您可以在[`tldp.org/HOWTO/Program-Library-HOWTO/shared-libraries.html`](http://tldp.org/HOWTO/Program-Library-HOWTO/shared-libraries.html)了解更多关于共享库的信息。

在修改之前，请备份您的原始`~/.bashrc`文件：

```
$ cp ~/.bashrc ~/.bashrc.bak

```

现在，将`custom_bashrc`文件复制到`~/.bashrc`中：

```
$ cp custom_bashrc ~/.bashrc

```

要应用修改后的设置，请打开一个新的 bash shell。要在相同的 bash shell 中应用新的`.bashrc`，您可以将其源到新的`~/.bashrc`文件中：

```
$ source ~/.bashrc

```

我们可以检查新的设置是否可用：

```
$ ll /home  # Using alias ll which we created

```

```
total 24
drwx------.  2 root    root    16384 Jun 11 00:46 lost+found
drwx--x---+ 41 foo  foo      4096  Aug  3 12:57 foo
```

```
$ alias  # To view aliases

```

```
alias cp='cp -i'
alias df='df -h'
alias ll='ls -l'
alias ls='ls --color=auto'
alias rm='rm -i'
alias vi='vim'
```

`alias`命令显示我们在`.bashrc`中添加的别名，即`rm`、`cp`、`df`和`ll`。

现在，调用我们在`.bashrc`中添加的`current_directory_size()`函数：

```
$ cd ~	# cd to user's home directory
$ current_directory_size
Current directory is /home/foo with total used space 97G
$ cd /tmp
$  current_directory_size
Current directory is /tmp with total used space 48K

```

确保将我们在本示例开始时创建的原始`.bashrc`文件移回去，并将其源到其中，以便在当前 shell 会话中反映设置。如果您不希望在执行前面示例时进行的任何配置更改，则需要这样做：

```
$ mv ~/.bashrc.bak ~/.bashrc
$ source ~/.bashrc

```

### 注意

当 bash 作为非登录 shell 调用时，它会加载`~/.bashrc`、`/etc/bashrc`和`/etc/profile.d/*.sh`文件中可用的配置。

## .bash_profile

在非图形系统中，成功登录后，用户会获得一个 shell。这样的 shell 称为登录 shell。当 bash 作为登录 shell 调用时，首先执行`/etc/profile`文件；这会运行`/etc/profile.d/`中可用的脚本。`/etc/profile`中的以下代码片段也提到了这一点：

```
for i in /etc/profile.d/*.sh ; do
    if [ -r "$i" ]; then
        if [ "${-#*i}" != "$-" ]; then 
            . "$i"
        else
```

这些是应用于任何用户登录 shell 的全局设置。此外，`~/.bash_profile`会为登录 shell 执行。在 Fedora 22 系统上，默认的`~/.bash_profile`文件内容如下：

```
# .bash_profile

# Get the aliases and functions
if [ -f ~/.bashrc ]; then
        . ~/.bashrc
fi

# User specific environment and startup programs

PATH=$PATH:$HOME/.local/bin:$HOME/bin

export PATH
```

从内容中，我们可以看到它在用户的主目录中查找`.bashrc`文件。如果主目录中有`.bashrc`文件，则会执行它。我们还知道`~/.bashrc`文件也会执行`/etc/bashrc`文件。接下来，我们看到`.bash_profile`将`PATH`变量附加到`$HOME/.local/bin`和`$HOME/bin`值。此外，修改后的`PATH`变量被导出为环境变量。

用户可以根据自己的定制配置需求修改`~/.bash_profile`文件，例如默认 shell、登录 shell 的编辑器等。

以下示例包含了`.bash_profile`中的修改配置。我们将使用`bash_profile`作为文件名：

```
# .bash_profile

# Get the aliases and functions
if [ -f ~/.bashrc ]; then
        . ~/.bashrc
fi

# User specific environment and startup programs

PATH=$PATH:$HOME/.local/bin:$HOME/bin

export PATH

# Added configuration by us
# Setting user's default editor
EDITOR=/usr/bin/vim
# Show a welcome message to user with some useful information
echo "Welcome 'whoami'"
echo "You are using $SHELL as your shell"
echo "You are running 'uname ' release 'uname -r'"
echo "The machine architecture is 'uname -m'"
echo "$EDITOR will be used as default editor"
echo "Have a great time here!"
```

在**我们添加的配置**注释之后进行更改。在应用新配置到`~/.bash_profile`之前，我们将首先备份原始文件。这将帮助我们恢复`.bash_profile`文件的原始内容：

```
$ cp ~/.bash_profile ~/.bash_profile.bak

```

在`home`目录中将创建一个新文件`.bash_profile.bak`。现在，我们将复制我们的新配置到`~/.bash_profile`：

```
$ cp bash_profile ~/.bash_profile

```

要在登录 shell 中看到反映的更改，我们可以以非图形界面登录，或者只需执行`ssh`到同一台机器上运行登录 shell。SSH（Secure Shell）是一种加密网络协议，用于以安全方式在远程计算机上启动基于文本的 shell 会话。在 UNIX 和基于 Linux 的系统中，可以使用`ssh`命令进行对本地或远程机器的 SSH。`ssh`的`man`页面（`man ssh`）显示了它提供的所有功能。要在同一台机器上进行远程登录，我们可以运行`ssh username@localhost`：

```
$ ssh foo@localhost    #  foo is the username of user

```

```
Last login: Sun Aug  2 20:47:46 2015 from 127.0.0.1
Welcome foo
You are using /bin/bash as your shell
You are running Linux release 4.1.3-200.fc22.x86_64
The machine architecture is x86_64
/usr/bin/vim will be used as default editor
Have a great time here!
```

我们可以看到我们添加的所有细节都打印在登录 shell 中。快速测试我们的新`.bash_profile`的另一种方法是通过对其进行源操作：

```
$ source ~/.bash_profile

```

```
Welcome foo
You are using /bin/bash as your shell
You are running Linux release 4.1.3-200.fc22.x86_64
The machine architecture is x86_64
/usr/bin/vim will be used as default editor
Have a great time here!
```

要重置`~/.bash_profile`文件中的更改，从我们在本示例开始时创建的`~/.bash_profile.bak`文件中复制，并对其进行源操作，以便在当前 shell 中反映更改：

```
$ mv ~/.bash_profile.bak ~/.bash_profile
$ source ~/.bash_profile

```

### 注意

当 bash 作为登录 shell 调用时，它会加载`/etc/profile`、`/etc/profile.d/*.sh`、`~/.bash_profile`、`.~/.bashrc`和`~/etc/bashrc`文件中可用的配置。

## .bash_logout

在用户的主目录中存在的`.bash_logout`文件在每次登录 shell 退出时都会执行。当用户远程登录或使用非图形界面时，这很有用。用户可以添加在从系统注销之前执行的清理任务。清理任务可能包括删除创建的临时文件、清除环境变量、注销重要数据、存档或加密某些任务、上传到 Web 等。

# 了解您的历史记录

Shell 提供了一个有趣的功能，允许您查看以前在 shell 中执行的所有命令的历史记录。经常发生我们忘记了前一天键入的命令来执行任务。我们可能能够回忆起确切的语法，也可能不行，但很方便的是我们可以参考 shell 保存的历史记录。

## 控制历史记录的 shell 变量

有一些 shell 变量可以更改用户可以看到的历史记录的内容和数量。这些 shell 变量在下表中提到：

| 名称 | 值 |
| --- | --- |
| HISTFILE | 默认情况下历史记录将保存在的文件名 |
| HISTFILESIZE | 历史文件中要保留的命令数 |
| HISTSIZE | 当前会话中要存储的历史记录数量 |
| HISTCONTROL | 以冒号分隔的值列表，控制如何保存命令在历史列表中 |

`HISTCONTROL` shell 变量的值可以是：

| 值 | 描述 |
| --- | --- |
| ignorespace | 以空格开头的行，不保存在历史记录列表中 |
| ignoredups | 不保存与先前保存的历史记录列表匹配的行 |
| ignoreboth | 应用 ignorespace 和 ignoredups |
| erasedups | 在将其保存到历史文件之前，删除与当前行匹配的历史中的所有先前行 |

让我们看看这些 shell 变量可能包含什么值：

```
$  echo $HISTFILE
/home/foo/.bash_history
$ echo $HISTFILESIZE
1000
$ echo $HISTSIZE
1000
$ echo $HISTCONTROL
ignoredups

```

从获得的值中，我们可以看到默认历史记录保存在用户`home`目录的`.bash_history`文件中，最大历史命令行保存为 1000。此外，已经存在于先前历史行中的任何重复历史都不会保存。

## history 内置命令

Shell 提供了`history`内置命令，以便用户了解到目前为止执行的命令历史。

在没有任何选项的情况下运行历史记录，会将所有先前输入的命令打印到`stdout`。命令序列按从顶部到底部的顺序提供，从最旧到最新：

```
$ history  # Prints all commands typed previously on stdout
$ history | tail -n10    # Prints last 10 commands executed

```

![history 内置命令](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_05_01.jpg)

以下表格解释了`history` shell 内置命令的可用选项：

| 选项 | 描述 |
| --- | --- |
| -a | 立即将新的历史行追加到历史记录中 |
| -c | 清除当前列表中的历史记录 |
| -d offset | 从指定的偏移量删除历史记录 |
| -r | 将保存的历史内容追加到当前列表 |
| -w | 在覆盖现有保存的历史内容后，将当前历史列表写入历史文件 |

要查看最后执行的五个命令，我们还可以执行以下命令：

```
$ history 5
 769  cd /tmp/
 770  vi hello
 771  cd ~
 772  vi .bashrc 
 773  history 5

```

我们将发现，所有执行的命令都与历史文件中的给定字符串匹配。例如，搜索其中包含`set`字符串的命令：

```
$ history | grep set 
 555  man setenv
 600  set | grep ENV_VAR2
 601  unset ENV_VAR2
 602  set | grep ENV_VAR2
 603  unset -u  ENV_VAR2 
 604  set -u  ENV_VAR2
 605  set | grep ENV_VAR2
 737  set |grep HIST
 778  history | grep set

```

要清除所有保存的命令历史记录并将当前列表中的历史追加到历史中，我们可以执行以下操作（如果不想丢失保存的命令历史，请不要运行以下命令）：

```
$ history -c  # Clears history from current list
$ history -w  # Overwrite history file and writes current list which is empty

```

## 修改默认历史记录行为

默认情况下，shell 为管理历史记录设置了一些值。在前一节中，我们看到历史文件中将存储最多 1000 行历史记录。如果用户大部分时间都在 shell 中工作，他可能在一两天内使用了 1000 条或更多命令。在这种情况下，如果他十天前输入了一个命令，他将无法查看历史记录。根据个人用例，用户可以修改要存储在历史文件中的行数。

执行以下命令将将历史文件的最大行数设置为`100000`：

```
$ HISTFILESIZE=100000

```

同样，我们可以更改历史文件应保存的位置。我们看到，默认情况下，它保存在`home`目录中的`.bash_history`文件中。我们可以修改`HISTFILE` shell 变量，并将其设置为我们想要保存命令历史的任何位置：

```
$  HISTFILE=~/customized_history_path

```

现在，执行的命令历史将保存在`home`目录中的`customized_history_path`文件中，而不是`~/.bash_history`文件中。

要使这些更改反映到用户启动的所有 shell 和所有会话中，将这些修改添加到`~/.bashrc`文件中。

## 查看历史记录的便捷快捷键

根据用户的历史记录大小设置，历史记录中可用的命令数量可能很大。如果用户想要查找特定命令，他或她将不得不查看整个历史记录，这有时可能会很麻烦。Shell 提供了一些快捷方式，以帮助我们在历史记录中找到先前执行的特定命令。了解这些快捷方式可以节省在历史记录中查找先前执行的命令的时间。

### [Ctrl + r]

在 shell 中工作时，[*Ctrl* + *r*]快捷键允许您在历史记录中搜索命令。按下[*Ctrl* + *r*]后开始输入命令；shell 会显示与输入的命令子字符串匹配的完整命令。要向前移动到下一个匹配项，再次在键盘上输入[*Ctrl* + *r*]，依此类推：

```
$ [ctrl + r]
(reverse-i-search)'his': man history

```

我们可以看到，从历史记录`man history`中建议输入`his`。

### 上下箭头键

键盘上的上下箭头键可用于在用户先前执行的命令历史记录中后退和前进。例如，要获取上一个命令，请按一次上箭头键。要进一步后退，请再次按上箭头键，依此类推。此外，要在历史记录中前进，请使用下箭头键。

### !!

快捷方式`!!`可用于重新执行 shell 中执行的最后一个命令：

```
$ ls /home/
lost+found  foo
$ !!
ls /home/
lost+found  foo

```

### !(search_string)

这个快捷方式执行最后一个以`search_string`开头的命令：

```
$ !l
ls /home/
lost+found  skumari
$ !his
history 12

```

### !?(search_string)

这个快捷方式执行最后一个包含子字符串`search_string`的命令：

```
$ !?h
ls /home/
lost+found  skumari

```

# 任务管理

当应用程序运行时，可能会长时间运行，或者一直运行直到计算机关闭。在 shell 中运行应用程序时，我们知道只有当在 shell 中运行的程序成功完成或由于某些错误终止时，shell 提示符才会返回。除非我们得到 shell 提示符返回，否则我们无法在同一个 shell 中运行另一个命令。我们甚至不能关闭该 shell，因为这将关闭正在运行的进程。

此外，要运行另一个应用程序，我们将不得不在新的终端中打开另一个 shell，然后运行它。如果我们必须运行很多任务，管理起来可能会变得困难和繁琐。Shell 提供了在后台运行、挂起、终止或移回前台的方法。

## 在后台运行任务

可以通过在命令末尾添加&来在 shell 中将任务作为后台启动。

例如，我们想在整个文件系统中搜索一个字符串。根据文件系统的大小和文件数量，可能需要很长时间。我们可以调用`grep`命令来搜索字符串并将结果保存在文件中。Linux 中的文件系统层次结构从根目录('/')开始。

```
$ grep -R "search Text" / 2>/dev/null >  out1.txt &
[1] 8871
$

```

在这里，`grep`在整个文件系统中搜索字符串，将任何错误消息发送到`/dev/null`，并将搜索结果保存到`out1.txt`文件中。在末尾的&将整个作业发送到后台，打印启动任务的 PID，并返回 shell 提示符。

现在，我们可以在同一个打开的 shell 中做其他工作并执行其他任务。

## 将正在运行的任务发送到后台

通常我们在 shell 中正常运行任务，即作为前台任务，但后来我们想将其移至后台。首先通过[*Ctrl* + *z*]暂停当前任务，然后使用`bg`将任务移至后台。

考虑最后一次文本搜索作为一个例子。我们正常地开始搜索如下：

```
$  grep -R "search Text" / 2>/dev/null >  out2.txt

```

我们不会看到 shell 上发生任何事情，我们只会等待 shell 提示符返回。或者，我们可以使用[Ctrl + z]暂停运行的作业：

```
[ctrl + z]
[2]+  Stopped            grep -R "search Text"  / 2> /dev/null > out2.txt

```

然后，要将挂起的任务发送到后台继续运行，请使用`bg`命令：

```
$ bg
[2]+ grep -R "search Text"  / 2> /dev/null > out2.txt

```

## 列出后台任务

要查看当前 shell 中正在后台运行或挂起的任务，使用内置`jobs` shell 如下：

```
$ jobs
```

```
[1]-  Running        grep -R "search Text" / 2> /dev/null > out1.txt &
[2]+ Running         grep -R "search Text" / 2> /dev/null > out2.txt &
```

这里，索引[1]和[2]是作业编号。

字符'+'标识将由`fg`或`bg`命令用作默认值的作业，字符'-'标识当前默认作业退出或终止后将成为默认作业的作业。

创建另一个任务并使用以下命令将其挂起：

```
$ grep -R "search Text" / 2>/dev/null >  out3.txt 
[ctrl + z]
[3]+  Stopped        grep -R "search Text"  / 2> /dev/null > out3.txt
$ jobs
[1]   Running        grep -R "search Text" / 2> /dev/null > out1.txt &
[2]-  Running        grep -R "search Text" / 2> /dev/null > out2.txt &
[3]+ Stopped         grep-R "search Text" / 2> /dev/null > out3.txt
```

要查看所有后台和挂起任务的 PID，我们可以使用`-p`选项：

```
$ jobs -p

```

```
8871
8873
8874
```

作业的 PID 是按顺序排列的。要查看只在后台运行的任务，使用`-r`选项如下：

```
$ jobs -r

```

```
[1]   Running                 grep -R "search Text" / 2> /dev/null > out1.txt &
[2]-  Running                 grep -R "search Text" / 2> /dev/null > out2.txt &
```

要查看只挂起的任务，使用`-s`选项如下：

```
$ jobs -s

```

```
[3]+ Stopped                grep-R "search Text" / 2> /dev/null > out3.txt
```

要查看特定索引作业，请使用带有`jobs`命令的索引号：

```
$ jobs 2

```

```
[2]-  Running                 grep -R "search Text" / 2> /dev/null > out2.txt &
```

## 将任务移动到前台

我们可以使用 shell 内置命令`fg`将后台或挂起的任务移动到前台：

```
$ jobs  # Listing background and suspended tasks

```

```
[1]   Running                 grep -R "search Text" / 2> /dev/null > out1.txt &
[2]-  Running                 grep -R "search Text" / 2> /dev/null > out2.txt &
[3]+ Stopped                grep-R "search Text" / 2> /dev/null > out3.txt
```

字符'+'在作业索引`3`中被提到。这意味着运行`fg`命令将在前台运行第三个作业：

```
$ fg
$ grep -R "search Text" / 2> /dev/null > out3.txt

[ctrl + z]
[3]+  Stopped                 grep -R "search Text" / 2> /dev/null > out3.txt

```

以下命令暂停第三个任务：

```
$ jobs
[1]   Running                 grep -R "search Text" / 2> /dev/null > out1.txt &
[2]-  Running                 grep -R "search Text" / 2> /dev/null > out2.txt &
[3]+ Stopped                grep-R "search Text" / 2> /dev/null > out3.txt

```

要将特定作业移到前台，请使用带有任务索引号的`fg`：

```
$  fg 1  # Moving first tasks to foreground
$ grep -R "search Text" / 2> /dev/null > out1.txt
[ctrl + z]
[1]+  Stopped            grep -R "search Text" / 2> /dev/null > out1.txt

```

## 终止任务

如果不再需要，我们也可以删除运行中或挂起的任务。这可以通过使用`disown` shell 内置命令来完成：

```
$ jobs  # List running or suspended tasks in current shell

```

```
[1]+  Stopped        grep -R "search Text" / 2> /dev/null > out1.txt
[2]   Running        grep -R "search Text" / 2> /dev/null > out2.txt &
[3]-  Stopped        grep -R "search Text" / 2> /dev/null > out3.txt
```

使用`disown`而不带任何选项，会删除具有字符'`+`'的任务：

```
$ disown
bash: warning: deleting stopped job 1 with process group 8871
```

```
$ jobs  # Listing available jobs
[2]-   Running       grep -R "search Text" / 2> /dev/null > out2.txt &
[3]+  Stopped        grep -R "search Text" / 2> /dev/null > out3.txt
```

要删除运行中的任务，使用`-r`选项：

```
$ disown -r
jobs
[3]-  Stopped                 grep -R "search Text" / 2> /dev/null > out3.txt
```

要删除所有任务，使用`-a`选项如下：

```
$ disown -a  # Gives warning for deleting a suspended task
bash: warning: deleting stopped job 3 with process group 8874
$ jobs

```

`jobs`的输出什么也不显示，因为所有挂起和运行中的任务都被`-a`选项删除了。

# 总结

阅读完本章后，您现在知道如何在 shell 中创建和修改环境变量。您还知道`.bashrc`和`.bash_profile`如何帮助永久地为用户的所有会话进行更改。您学会了如何搜索我们先前执行的命令的历史记录，以及如何使用`fg`和`bg` shell 内置命令在 shell 中运行和管理不同的任务。

在下一章中，我们将看到在基于 Linux 的系统上有哪些重要类型的文件，以及可以对它们执行哪些操作以获得有意义的结果。


# 第六章：处理文件

为了简单起见，UNIX 和基于 Linux 的操作系统中的所有内容都被视为文件。文件系统中的文件以分层树状结构排列，树的根由'/'（斜杠）表示。树的节点可以是目录或文件，其中目录也是一种特殊类型的文件，其中包含 inode 号和相应的文件名条目列表。inode 号是 inode 表中的条目，包含与文件相关的元数据信息。

在本章中，我们将更详细地了解重要和常用的文件类型。我们将看到如何创建、修改和执行文件的其他有用操作。我们还将看到如何监视进程或用户打开的文件列表。

本章将详细介绍以下主题：

+   执行基本文件操作

+   移动和复制文件

+   比较文件

+   查找文件

+   文件的链接

+   特殊文件

+   临时文件

+   权限和所有权

+   获取打开文件的列表

+   配置文件

# 执行基本文件操作

最常用的文件是常规文件和目录。在以下子节中，我们将看到基本文件操作。

## 创建文件

我们可以使用不同的 shell 命令在 shell 中创建常规文件和目录。

### 目录文件

目录是一种特殊类型的文件，其中包含文件名列表和相应的 inode 号。它充当容器或文件夹，用于保存文件和目录。

要通过 shell 创建新目录，我们可以使用`mkdir`命令：

```
$ mkdir dir1

```

我们还可以将多个目录名称作为参数提供给`mkdir`命令，如下所示：

```
$ mkdir dir2 dir3 dir4  # Creates multiple directories

```

如果指定的路径名不存在，我们可以使用`mkdir`中的`-p`选项创建父目录。这是通过`mkdir`中的`-p`选项完成的：

```
$ mkdir -p /tmp/dir1/dir2/dir3

```

在这里，如果`dir1`和`dir2`是`dir3`的父目录且尚不存在，则`-p`选项将首先创建`dir1`目录，然后在`dir1`内创建`dir2`子目录，最后在`dir2`内创建`dir3`子目录。

### 常规文件

一般来说，文本和二进制文件被称为常规文件。在 shell 中，可以通过多种方式创建常规文件。以下部分提到了其中一些。

#### Touch 命令

也可以使用`touch`命令创建新的常规文件。它主要用于修改现有文件的时间戳，但如果文件不存在，将创建一个新文件：

```
$ touch newfile.txt  # A new empty file newfile.txt gets created
$ test -f newfile.txt && echo File exists  # Check if file exists
File exists

```

#### 使用命令行编辑器

我们可以打开任何命令行编辑器；例如，在 shell 中使用`vi/vim`、emacs、nano，编写内容，并将内容保存在文件中。

现在，我们将使用`vi`编辑器创建并编写文本：

```
$ vi foo.txt  # Opens vi editor to write content

```

按下*I*键进入 vi 的`INSERT`模式，然后按照以下截图中显示的文本输入：

![使用命令行编辑器](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_06_01.jpg)

在写完文本后，按下*Esc*键，然后输入`:wq`命令保存并退出 vi 编辑器。要详细了解`vi/vim`，请参考其`man`页面或在线文档([`www.vim.org/docs.php`](http://www.vim.org/docs.php))：

![使用命令行编辑器](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_06_02.jpg)

#### 使用 cat 命令

我们甚至可以使用`cat`命令将内容写入现有或新的常规文件，如下所示：

```
$ cat > newfile1.txt
We are using cat command
to create a new file and write into 
it
[Ctrl + d]    # Press Ctrl + d to save and exit
$ cat newfile1.txt  # See content of file
We are using cat command
to create a new file and write into
it

```

通过使用`>>`运算符而不是`>`，我们可以追加而不是覆盖文件的内容。

#### 重定向命令的输出

在 bash 或脚本中执行命令时，我们可以将结果重定向到现有文件或新文件中：

```
$ ls -l /home > newfile2.txt  #File gets created containing command output
$ cat newfile2.txt
total 24
drwx------.     2    root    root   16384  Jun  11  00:46   lost+found
drwx—x---+  41  foo     foo    4096   Aug  22  12:19   foo

```

## 修改文件

要在 shell 中修改常规文件的内容，打开编辑器中的文件，进行所需的更改，然后保存并退出。我们还可以使用`>>`运算符将命令的输出追加到指定的文件中：

```
Command >> file.txt

```

例如，我们将保存`/home`的`ls`输出到`ls_output.txt`文件中：

```
$ ls /home/ >> ls_output.txt
$ cat ls_output.txt  # Viewing content of file
lost+found
foo

```

现在，我们将追加另一个目录`/home/foo/`的`ls`输出如下：

```
$ ls /home/foo >> ls_output.txt
lost+found
foo
Desktop
Documents
Downloads
Pictures

```

我们看到`ls_output.txt`文件通过追加`ls`命令的内容而被修改。

## 查看文件

要查看常规文件的内容，我们可以简单地在编辑器中打开文件，如 vi/vim，emacs 和 nano。我们还可以使用`cat`，`less`和`more`命令来查看文件的内容。

要查看目录的内容，我们使用`ls`命令：

```
$ ls /home/
lost+found  foo

```

要递归查看目录的内容，请使用带有`-R`或`--recursive`选项的`ls`。

### 使用 cat 查看内容

我们可以使用`cat`命令查看文件的内容如下：

```
$ cat newfile1.txt
We are using cat command
to create a new file and write into
it
$ cat -n newfile1.txt    # Display line number as well
 1  We are using cat command
 2  to create a new file and write into
 3  it

```

### more 和 less

`more`和`less`命令非常有用，方便查看当前终端上无法容纳的大文件。

`more`命令以页面格式显示文件的内容，我们可以向上和向下滚动以查看文件的其余内容：

```
$ more /usr/share/dict/words

```

将文件路径作为参数传递给`more`命令。在上面的示例中，它将显示`/usr/share/dict/`目录中可用的文件单词的内容。

键*s*用于向前跳过`k`行文本。键*f*用于向前跳过 k 屏幕文本。键*b*用于向后跳过 k 屏幕文本。

`less`命令更受欢迎，被广泛用于查看大文件的内容。使用`less`命令的优点之一是它不会在开始时加载整个文件，因此查看大文件的内容更快。

使用`less`的用法与`more`命令非常相似：

```
$ less  /usr/share/dict/words

```

导航使用`less`命令要容易得多。它还有更多选项来自定义文件内容的过滤视图。

如果没有提供输入文件，`more`和`less`命令可以从`stdin`接收输入。使用管道（'`|`'）从`stdin`提供输入：

```
$ cat /usr/share/dict/words | more    #  cat output redirected to more
$ grep ^.{3}$ /usr/share/dict/words | less  # Matches all 3 character words

```

查看`more`和`less`的`man`页面以获取详细用法。

### 注意

由于不同的实现，`more`命令的行为可能因不同系统而异。

## 删除文件

如果不再需要，我们也可以删除常规文件和目录。

### 删除常规文件

要删除常规文件，我们在 shell 中使用`rm`命令。

如果文件存在，则`rm`命令删除文件，否则会在`stdout`上打印错误：

```
$ rm newfile1.txt    # Deletes if file exists
$ rm newfile1.txt    # Prints error message if file doesn't exist
rm: cannot remove 'newfile1.txt': No such file or directory

```

要忽略错误消息，可以使用`rm`与`-f`选项：

```
$ rm -f newfile1.txt
$ rm -i  newfile.txt   # Interactive deletion of file
rm: remove regular empty file 'newfile.txt'? 

```

输入键*y*删除文件，*n*跳过删除文件。

### 删除目录

要删除目录，我们可以使用`rmdir`和`rm`命令。我们将考虑在`文件`创建子主题下创建的`目录`文件中创建的目录：

```
$ rmdir dir2/  # Deletes directory dir2
$ rmdir dir1/  #  Fails to delete because of non-empty directory
rmdir: failed to remove 'dir1/': Directory not empty

```

要删除非空目录，首先删除内容，然后删除目录。我们还可以使用`rm`来删除空目录或非空目录。

`-d`选项如下删除空目录：

```
$ ls dir3/  # Directory dir3 is empty
$ rm -d dir3/  # Empty diretcory dir3 gets deleted
$ ls dir1/  # Diretcory dir1 is not empty
dir2
$ rm -d dir1/  # Fails to delete non-empty directory dir1
rm: cannot remove 'dir1': Directory not empty

```

选项`-r`，`-R`或`--recursive`递归地删除目录及其内容：

```
$ rm -ri dir1/  # Asks to remove directory dir1 recursively
rm: descend into directory 'dir1'?  Y

```

输入*y*确认应删除`dir1`。

### 注意

小心使用`rm`选项`-r`。如果可能的话，使用`-i`选项以避免意外删除整个目录的内容。

# 移动和复制文件

我们经常需要复制或移动文件到另一个位置，以便根据需要整理文件。我们还可以将计算机数据复制到本地或远程可用的外部驱动器或另一台计算机，以便备份重要数据。

## 移动文件

移动常规文件和目录在我们想要在新位置保留数据的确切副本时非常有用。`mv`命令用于将文件从一个位置移动到另一个位置。

使用`mv`命令的语法如下：

```
mv [option] source... destination

```

这里，`source`是要移动的文件或目录。可以指定多个源文件，`destination`是应将文件和目录移动到的位置。

`mv`命令的一些重要选项在下表中解释：

| 选项 | 描述 |
| --- | --- |
| `-n` | 不覆盖现有文件 |
| `-i` | 在覆盖现有文件之前提示 |
| `-f` | 在覆盖现有文件时不提示 |
| `-u` | 仅在源文件较新或目标文件丢失时才移动源文件 |
| `-v` | 打印正在移动的文件的名称 |

### 将目录移动到新位置

要将目录从一个位置移动到另一个位置，请执行以下命令：

```
$ mkdir ~/test_dir1  # Directory test_dir1 created in home directory
$ mv ~/test_dir1/ /tmp # moving directory to /tmp

```

`test_dir1`目录已经移动到了`/tmp`，现在主目录中没有`test_dir1`的副本了。

现在，我们将在用户的主目录中再次创建一个名为`test_dir1`的目录：

```
$ mkdir ~/test_dir1  # Directory test_dir1 created in home directory

```

尝试使用`-i`选项再次将`test_dir1`移动到`/tmp`：

```
$ mv -i ~/test_dir1/ /tmp
mv: overwrite '/tmp/test_dir1'?

```

我们可以看到`-i`选项明确询问用户是否要用新目录覆盖现有目录。

### 注意

使用`mv`命令和`-i`选项来避免意外覆盖文件。

### 重命名文件

我们也可以使用`mv`命令来重命名文件。例如，我们在`/tmp`目录中有`test_dir1`目录。现在，我们想将其重命名为`test_dir`。我们可以执行以下命令：

```
$ mv  /tmp/test_dir1/  /tmp/test_dir  # directory got renamed to test_dir

```

## 复制文件

创建文件的副本是一个非常常见的操作，可以在本地或远程系统上执行。

### 在本地复制文件

要在本地机器上复制文件，使用`cp`命令。

使用`cp`命令的语法如下：

```
cp [option] source … destination

```

在这里，`source`可以是单个文件、多个文件或目录，而`destination`如果`source`是单个文件，则可以是文件。否则，`destination`将是一个目录。

`cp`命令的一些重要选项如下：

| 选项 | 描述 |
| --- | --- |
| `-f` | 在覆盖现有文件时不提示 |
| `-i` | 在覆盖现有文件之前提示 |
| `-R` | 递归复制目录 |
| `-u` | 仅在源文件较新或目标文件丢失时才复制源文件 |
| `-p` | 保留原始文件的属性 |
| `-v` | 显示正在复制的文件的详细信息 |

#### 将文件复制到另一个位置

要将文件复制到另一个位置，请执行以下命令：

```
$ touch ~/copy_file.txt    # Creating a file
$ cp ~/copy_file.txt /tmp/  # Copying file to /tmp

```

现在，`copy_file.txt`文件有两个副本，一个在用户的主目录，一个在`/tmp`目录。

要复制目录，我们使用带有`-R`选项的`cp`：

```
$ mkdir ~/test_dir2  # Creating a test diretcory
$ 
cp -R ~/test_dir2 /tmp/

```

`test_dir2`目录以及目录中的所有内容都被复制到了`/tmp`。

### 远程复制文件

要在远程机器上复制文件，使用`scp`命令。它在网络上的主机之间复制文件。`scp`命令使用`ssh`来验证目标主机并传输数据。

`scp`的简单语法如下：

```
scp [option] user1@host1:source user2@host2:destination

```

在`user1@host1:source`中，`user1`是要复制文件的源用户名，`host1`是主机名或 IP 地址；`source`可以是要复制的文件或目录。

在`user2@host2:destination`中，`user2`是目标主机的用户名，文件应该被复制到该主机，`host2`是主机名或 IP 地址；`destination`可以是要复制到的文件或目录。如果没有指定目的地，将在目标主机的主目录中进行复制。

如果没有提供远程源和目的地，将在本地进行复制。

讨论了`scp`的一些重要选项如下表所示：

| 选项 | 描述 |
| --- | --- |
| `-C` | 在网络上传输数据时启用压缩 |
| `-l limit` | 限制以 Kbit/s 指定的带宽使用 |
| `-p` | 保留原始文件的属性 |
| `-q` | 不在`stdout`上打印任何进度输出 |
| `-r` | 递归复制目录 |
| `-v` | 复制过程中显示详细信息 |

#### 将文件复制到远程服务器

要将文件复制到远程服务器，非常重要的是服务器上已经运行了`ssh`服务器。如果没有，请确保启动`ssh`服务器。要复制文件，请使用以下`scp`命令：

```
$ scp -r ~/test_dir2/ foo@localhost:/tmp/test_dir2/

```

在这里，我们已经将一个副本复制到了本地机器。所以使用的主机名是`localhost`。现在，在`/tmp/test_dir2/`内有另一个目录`test_dir2`：

```
$ ls -l /tmp/test_dir2
total 0
drwxrwxr-x. 2 foo foo 40 Aug 25 00:44 test_dir2

```

# 比较文件

比较两个相似文件之间的差异是有意义的，以了解这两个文件之间存在哪些差异。例如，比较在两组数据上运行的命令获得的结果。另一个例子可以是比较脚本文件的旧版本和新版本，以了解脚本中进行了哪些修改。Shell 提供了用于文件比较的`diff`命令。

## 使用 diff 进行文件比较

`diff`命令用于逐行比较文件。使用`diff`命令的语法如下：

```
diff [option] file1 file2

```

其中，`file1`和`file2`是要比较的文件。

`diff`命令的选项在下表中解释：

| 选项 | 描述 |
| --- | --- |
| `-q` | 仅在文件不同时打印 |
| `-s` | 如果两个文件相同，则在`stdout`上打印消息 |
| `-y` | 侧边显示`diff`结果 |
| `-i` | 对文件内容进行不区分大小写的比较 |
| `-b` | 忽略空格数的更改 |
| `-u NUM` | 输出`NUM`（默认 3）行统一上下文 |
| `-a` | 在比较时将文件视为文本文件 |

### 例子

`diff`命令显示了两个文件之间添加、删除和修改行的比较结果。

我们将以`comparison_file1.txt`和`comparison_file2.txt`文本文件为例：

```
$ cat comparison_file1.txt	# Viewing content of file
This is a comparison example.

This line should be removed.
We have added multiple consecutive blank spaces.
THIS line CONTAINS both CAPITAL and small letters
```

```
$ cat comparison_file2.txt	# Viewing content of file
This is a comparison example.
We have added       multiple consecutive blank spaces.
this line contains both CAPITAL and small letters
Addition of a line
```

现在，我们将比较`comparison_file1.txt`和`comparison_file2.txt`文件：

```
$ diff  comparison_file1.txt  comparison_file2.txt
2,5c2,4
< 
< This line should be removed.
< We have added multiple consecutive blank spaces.
< THIS line CONTAINS both CAPITAL and small letters
---
> We have added       multiple consecutive blank spaces.
> this line contains both CAPITAL and small letters
> Addition of a line
```

在这里，`<`（小于）表示删除的行，`>`（大于）表示添加的行。

使用`-u`选项使`diff`输出更易读，如下所示：

```
$ diff -u comparison_file1.txt comparison_file2.txt 
--- comparison_file1.txt        2015-08-23 16:47:28.360766660 +0530
+++ comparison_file2.txt        2015-08-23 16:40:01.629441762 +0530
@@ -1,6 +1,5 @@
 This is a comparison example.
-
-This line should be removed.
-We have added multiple consecutive blank spaces.
-THIS line CONTAINS both CAPITAL and small letters
+We have added       multiple consecutive blank spaces.
+this line contains both CAPITAL and small letters
+Addition of a line
```

在这里，'`-`'告诉旧文件（`comparison_file1.txt`）中可用的行，但在新文件（`comparison_file2.txt`）中不再存在。

'`+`'表示在新文件（`comparison_file2.txt`）中添加的行。

我们甚至可以使用`–i`选项对内容进行不区分大小写的比较：

```
$ diff -i comparison_file1.txt comparison_file2.txt 
2,4c2
< 
< This line should be removed.
< We have added multiple consecutive blank spaces.
---
> We have added       multiple consecutive blank spaces.
5a4
> Addition of a line
```

要忽略多个空格，请使用`diff`并使用`-b`选项：

```
$ diff -bi  comparison_file1.txt  comparison_file2.txt
2,3d1
< 
< This line should be removed.
5a4
> Addition of a line
```

# 查找文件

在文件系统中，有大量的文件可用。有时，还会连接外部设备，这些设备可能也包含大量的文件。想象一下系统中有数百万甚至数十亿个文件，我们需要在其中搜索特定的文件或文件模式。如果文件数量在 10 到 100 之间，手动搜索文件是可能的，但在数百万个文件中几乎是不可能的。为了解决这个问题，UNIX 和 Linux 提供了`find`命令。这是一个非常有用的用于在计算机中搜索文件的命令。

使用`find`命令的语法如下：

`find search_path [option]`

在`search_path`中，指定`find`应搜索`file_search_pattern`的路径。

以下表中提到了一些重要的选项：

| 选项 | 描述 |
| --- | --- |
| -P | 不要遵循符号链接。这是默认行为 |
| -L | 在搜索时遵循符号链接 |
| -exec cmd ; | 执行作为-exec 参数传递的命令 cmd |
| -mount | 不在其他文件系统中搜索 |
| -可执行 | 匹配可执行文件 |
| -group gname | 文件属于组 gname |
| -user uname | 属于用户 uname 的文件 |
| -名称模式 | 搜索文件以获取给定模式 |
| -iname 模式 | 对给定模式的文件进行不区分大小写的搜索 |
| -inum N | 搜索具有索引号 N 的文件 |
| -samefile name | 具有与名称相同的索引号的文件 |
| -regex 模式 | 匹配给定正则表达式模式的文件。匹配整个路径。 |
| -iregex 模式 | 对给定正则表达式模式的文件进行不区分大小写的匹配。匹配整个路径。 |

## 根据用例搜索文件

以下 shell 脚本显示了如何使用`find`命令的一些用例：

```
#!/bin/bash
# Filename: finding_files.sh
# Description: Searching different types of file in system

echo -n "Number of C/C++ header files in system: "
find / -name "*.h" 2>/dev/null |wc -l
echo -n "Number of shell script files in system: "
find / -name "*.sh" 2>/dev/null |wc -l
echo "Files owned by user who is running the script ..."
echo -n "Number of files owned by user $USER :"
find / -user $USER 2>/dev/null |wc -l
echo -n "Number of executable files in system: "
find / -executable 2>/dev/null | wc -l
```

在执行上述`finding_files.sh`脚本后，以下是示例输出：

```
Number of C/C++ header files in system: 73950
Number of shell script files in system: 2023
Files owned by user who is running the script ...
Number of files owned by user foo :341726
Number of executable files in system: 127602
```

## 根据索引号查找并删除文件

`find`命令可用于根据其索引号查找文件。

```
$ find ~/ -inum 8142358
/home/foo/Documents

```

`-inum`选项可以与`exec`一起使用，用于删除无法通过文件名删除的文件。例如，名为`-test.txt`的文件无法使用`rm`命令删除：

```
$  ls -i ~ |grep  test  # Viewing file with its inode number
8159146 -test.txt

```

要删除`-test.txt`文件，执行以下命令：

```
$ find ~/ -inum 8159146 -exec rm -i {} \;  # Interactive deletion
rm: remove regular file '/home/skumari/-test.txt?' y

```

# 链接到一个文件

文件的链接意味着用不同的文件名引用相同的文件。在 Linux 和基于 Unix 的系统中，存在以下两种类型的链接：

+   软链接或符号链接

+   硬链接

要创建文件之间的链接，可以使用`ln`命令。语法如下：

```
ln [option] target link_name

```

在这里，`target`是要创建链接的文件名，`link_name`是要创建链接的名称。

## 软链接

软链接是一种特殊类型的文件，它只是指向另一个文件。这使得更容易创建文件的快捷方式，并且可以更容易地在文件系统中的不同位置访问文件。

要创建文件的符号链接，使用`ln`命令带有`-s`选项。例如，我们将在我们的主目录中创建`/tmp`目录的符号链接：

```
$ ln -s /tmp ~/local_tmp

```

现在，我们在我们的主目录中有一个对`/tmp`目录的符号链接，名为`local_tmp`。要访问`/tmp`数据，我们也可以`cd`到`~/local_tmp`目录。要知道一个文件是否是符号链接，运行`ls -l`命令：

```
$ ls -l ~/local_tmp
lrwxrwxrwx. 1 foo foo 5 Aug 23 23:31 /home/foo/local_tmp -> /tmp/

```

如果第一列的第一个字符是`l`，那么它意味着它是一个符号链接。同时，最后一列显示`/home/foo/local_tmp -> /tmp/`，这意味着`local_tmp`指向`/tmp`。

## 硬链接

硬链接是一种用不同名称引用文件的方式。所有这些文件都将具有相同的索引节点号。索引节点号是索引表中的索引号，包含有关文件的元数据。

要创建文件的硬链接，使用`ln`命令而不带任何选项。在我们的情况下，我们将首先创建一个名为`file.txt`的常规文件：

```
$ touch file.txt
$ ls -l file.txt
-rw-rw-r--. 1 foo foo 0 Aug 24 00:13 file.txt

```

`ls`的第二列显示链接计数。我们可以看到当前是`1`。

现在，要创建`file.txt`的硬链接，我们将使用`ln`命令：

```
$ ln file.txt hard_link_file.txt

```

要检查是否为`file.txt`创建了硬链接，我们将查看其链接计数：

```
$ ls -l file.txt
-rw-rw-r--. 2 foo foo 0 Aug 24 00:13 file.txt

```

现在，链接计数为`2`，因为使用名称`hard_link_file.txt`创建了一个硬链接。

我们还可以看到`file.txt`和`hard_link_file.txt`文件的索引节点号是相同的：

```
$ ls -i file.txt hard_link_file.txt
96844   file.txt
96844   hard_link_file.txt

```

## 硬链接和软链接之间的区别

以下表格显示了硬链接和软链接之间的一些重要区别：

| 软链接 | 硬链接 |
| --- | --- |
| 实际文件和软链接文件的索引节点号是不同的。 | 实际文件和硬链接文件的索引节点号是相同的。 |
| 可以在不同的文件系统之间创建软链接。 | 只能在相同的文件系统中创建硬链接。 |
| 软链接可以链接到常规文件和目录。 | 硬链接不能链接到目录。 |
| 如果实际文件被删除，软链接不会更新。它将继续指向一个不存在的文件。 | 如果实际文件被移动或删除，硬链接总是会更新。 |

# 特殊文件

除了常规文件、目录和链接文件之外的文件都是特殊文件。它们如下：

+   块设备文件

+   字符设备文件

+   命名管道文件

+   套接字文件

## 块设备文件

块设备文件是以块形式读写数据的文件。这种文件在需要大量写入数据时非常有用。诸如硬盘驱动器、USB 驱动器和 CD-ROM 之类的设备被视为块设备文件。数据是异步写入的，因此其他用户不会被阻止执行写操作。

要创建块设备文件，使用`mknod`命令，带有`b`选项以及提供主要和次要编号。主要编号选择调用哪个设备驱动程序执行输入和输出操作。次要编号用于识别子设备：

```
$ sudo mknod  block_device b 0X7 0X6

```

在这里，`0X7`是十六进制格式的主要编号，`0X6`是次要编号：

```
$ ls -l block_device
brw-r--r--. 1 root root 7, 6 Aug 24 12:21 block_device

```

第一列的第一个字符是`b`，这意味着它是一个块设备文件。

`ls`输出的第五列是`7`和`6`。这里，`7`是一个主要号，`6`是一个次要号，以十进制格式表示。

字符设备文件是以逐个字符的方式读取和写入数据的文件。这些设备是同步的，一次只能有一个用户进行写操作。键盘、打印机和鼠标等设备被称为字符设备文件。

以下命令将创建一个字符特殊文件：

```
$ sudo  mknod  character_device  c 0X78 0X60

```

这里，`0X78`是一个主要号，`0X60`是一个次要号，以十六进制格式表示。

```
$ ls -l character_device  # viewing attribute of  character_device file
crw-r--r--. 1 root root 120, 96 Aug 24 12:21 character_device

```

第一列的第一个字符是`c`，表示它是一个字符设备文件。`ls`输出的第五列是`120`和`96`。这里，`120`是一个主要号，`96`是一个次要号，以十进制格式表示。

## 命名管道文件

命名管道文件被不同的系统进程用于相互通信。这种通信也被称为进程间通信。

要创建这样一个文件，我们使用`mkfifo`命令：

```
$ mkfifo pipe_file    # Pipe file created
$ ls pipe_file      # Viewing file content
prw-rw-r--. 1 foo foo 0 Aug 24 01:41 pipe_file

```

这里，第一列的第一个字符是`p`，表示它是一个管道文件。`/dev`目录中有很多管道文件。

我们还可以使用`mknod`命令的`p`选项创建一个命名管道：

```
$ mknod   named_pipe_file p
$ ls -l  named_pipe_file
prw-rw-r--. 1 foo foo 0 Aug 24 12:33 named_pipe_file

```

以下 shell 脚本演示了从命名管道中读取消息。`send.sh`脚本创建一个名为`named_pipe`的命名管道，如果它不存在的话，然后在其中发送一条消息：

```
#!/bin/bash
 # Filename: send.sh
# Description: Script which sends message over pipe

pipe=/tmp/named_pipe

if [[ ! -p $pipe ]]
then
 mkfifo $pipe
fi

echo "Hello message from Sender">$pipe

```

`receive.sh`脚本检查名为`named_pipe`的命名管道是否存在，从管道中读取消息，并显示在`stdout`上：

```
#!/bin/bash
#Filename: receive.sh
# Description: Script receiving message from sender from pipe file

pipe=/tmp/named_pipe

if [[ ! -p $pipe ]]
then
  echo "Reader is not running"
fi

while read line
do
  echo "Message from Sender:"
  echo $line
done < $pipe
```

要执行它，在一个终端中运行`send.sh`，在另一个终端中运行`receive.sh`：

```
$ sh send.sh  # In first terminal
$ sh receive.sh  # In second terminal
Message from Sender:
Hello message from Sender

```

## 套接字文件

套接字文件用于从一个应用程序传递信息到另一个应用程序。例如，如果**通用 UNIX 打印系统**（**CUPS**）守护程序正在运行，我的打印应用程序想要与它通信，那么我的打印应用程序将向套接字文件写入一个请求，CUPS 守护程序会监听即将到来的请求。一旦请求被写入套接字文件，守护程序将处理请求：

```
$ ls -l /run/cups/cups.sock  # Viewing socket file attributes
srw-rw-rw-. 1 root root 0 Aug 23 15:39 /run/cups/cups.sock

```

第一列中的第一个字符是`s`，表示它是一个套接字文件。

# 临时文件

临时文件是在应用程序运行时需要的一段时间内的文件。这些文件被用来保存运行程序的中间结果，在程序执行完成后就不再需要了。在 shell 中，我们可以使用`mktemp`命令创建临时文件。

## 使用`mktemp`创建临时文件

`mktemp`命令创建一个临时文件，并在`stdout`上打印其名称。临时文件默认创建在`/tmp`目录中。

创建临时文件的语法如下：

```
$ mktmp
/tmp/tmp.xEXXxYeRcF

```

一个名为`tmp.xEXXxYeRcF`的文件被创建到`/tmp`目录中。我们可以在应用程序中进一步读写这个文件以供临时使用。使用`mktemp`命令而不是使用一个随机名称来创建临时文件名，可以避免意外覆盖现有的临时文件。

要创建临时目录，我们可以使用`mktemp`的`-d`选项：

```
$ temp_dir=mktemp -d
$ echo $temp_dir
/tmp/tmp.Y6WMZrkcj4

```

此外，我们也可以明确地删除它：

```
$ rm -r /tmp/tmp.Y6WMZrkcj4

```

我们甚至可以通过提供一个参数作为`name.XXXX`来指定一个模板用于临时文件。这里，`name`可以是临时文件应该以哪个名称开头，`XXXX`表示在点（.）后使用随机字符的长度。通常，在编写应用程序时，如果需要临时文件，应用程序名称将作为临时文件名。

例如，一个测试应用程序需要创建一个临时文件。为了创建一个临时文件，我们将使用以下命令：

```
$ mktemp test.XXXXX
test.q2GEI

```

我们可以看到临时文件名以`test`开头，后面正好包含五个随机字母。

### 注意

临时文件将被清理的时间是与发行版相关的。

# 权限和所有权

作为 Linux 和 UNIX 系统的用户，重要的是用户对特定文件或目录具有所需的权限。例如，作为普通用户，执行`cd`进入`/root`：

```
$ cd /root
bash: cd: /root/: Permission denied

```

由于权限被拒绝，我们无法这样做：

```
$ cd ~/

```

我们成功地能够进入用户的主目录，因为用户有权限访问自己的主目录。

UNIX 或 Linux 中的每个文件都有一个所有者和一个关联的组。它还具有相对于用户、组和其他人的一组权限（读取、写入和执行）。

## 查看文件的所有权和权限

使用`ls -l`选项的`ls`命令用于查看文件的所有权和权限：

```
$ touch permission_test_file.txt    #  Creating a file
$ ls -l  permission_test_file.txt    # Seeing files' attributes
-rw-rw-r-- 1 foo foo 0 Aug 24 16:59 permission_test_file.txt

```

在这里，`ls`的第一列包含权限信息，即`-rw-rw-r--`。

第一个字符指定文件的类型，在这个例子中是短横线（-）。短横线表示这是一个常规文件。它可以有其他字符，如下所示：

+   p：这意味着这是一个命名管道文件

+   d：这意味着这是一个目录文件

+   s：这意味着这是一个套接字文件

+   c：这意味着这是一个字符设备文件

+   b：这意味着这是一个块设备文件

接下来的三个字符属于用户或所有者的权限。它可以是`rwx`或`-`中的任何一个。权限`r`表示读权限可用，`w`表示写权限可用，`x`表示给定文件上的执行权限可用。如果存在短横线，则相应的权限缺失。在上面的例子中，所有者的权限是`rw-`，这意味着所有者对`permission_test_file.txt`文件具有读和写权限，但没有执行权限。

接下来的三个字符属于组的权限。如果相应的权限缺失，则在这些位置中可以是`rwx`或`-`。在前面的例子中，授予组的权限是`rw-`，这意味着读取和写入权限存在，但执行权限缺失。

接下来的三个字符属于其他人的权限。在前面的例子中，授予其他人的权限是`r--`，这意味着其他用户可以读取`permission_test_file.txt`文件的内容，但不能修改或执行它。

`ls -l`输出中的下一列，即第二列指定文件的所有者是谁。在我们的例子中，第二列的值是`foo`，这意味着`foo`拥有该文件。默认情况下，文件的所有权归创建该文件的人。

`ls -l`输出中的第三列指定文件所属的组。在我们的例子中，`permission_test_file.txt`文件的组是`foo`。

## 更改权限

要更改文件的权限，使用`chmod`命令。使用`chmod`的语法如下：

```
chmod [option] mode[,mode] file

```

或者，

```
chmod [option] octal-mode file

```

`chmod`的一个重要选项是`-R`，它表示递归更改文件和目录的权限。

`mode`可以是`[ugoa][-+][rwx]`。

在这里，`u`是所有者，`g`是组，`o`是其他，`a`是所有用户，即`ugo`。

指定-（减号）会移除指定的权限，指定`+`（加号）会添加指定的权限。

字母`r`（读取）、`w`（写入）和`x`（执行）指定权限。

`八进制模式`以八进制格式指定用户的`rwx`权限，可以是`0 到 7`。以下表格解释了特定用户权限的八进制表示：

| 八进制值 | 二进制表示 | 意义 |
| --- | --- | --- |
| 0 | 000 | 没有读取、写入和执行权限（---） |
| 1 | 001 | 只有执行权限（--x） |
| 2 | 010 | 只有写权限（-w-） |
| 3 | 011 | 写和执行权限（-wx） |
| 4 | 100 | 只有读权限（r--） |
| 5 | 101 | 读取和执行权限（r-x） |
| 6 | 110 | 读取和写入权限（rw-） |
| 7 | 111 | 读取、写入和执行权限（rwx） |

为了演示对文件进行权限更改，我们将创建一个文件如下：

```
$ touch test_file.txt
$ ls -l test_file.txt    # Checking permission of file
-rw-rw-r--. 1 foo foo 0 Aug 24 18:59 test_file.txt

```

对于普通文件，默认权限是所有者、组和其他人都有“读”权限。所有者和组有“写”权限。没有人被赋予执行权限。

现在，我们想以只有所有者可以拥有“写”权限的方式修改权限，并保持其他权限不变。我们可以这样做：

```
$ chmod 644 test_file.txt
$ ls -l tst_file.txt
-rw-r--r--. 1 foo foo 0 Aug 24 19:03 test_file.txt

```

现在，我们可以看到只有所有者可以修改`test_file`。在使用八进制模式时，我们必须指定我们希望进一步查看的确切权限。在`chmod`中，我们将`octal_mode`设置为`644`；这里的第一个八进制数字，即`6`表示所有者的读、写和执行权限。同样，第二个八进制数字`4`指定了组的权限，第三个数字指定了其他人的权限。

还有另一种修改权限的方法，即使用模式。模式被指定为`[ugoa][-+][rwx]`。在这里，我们只需要指定要添加或删除的权限。

例如，我们想要从所有者那里删除写权限，并向所有人添加执行权限。我们可以这样做：

```
$ chmod u-w,a+x test_file.txt
$ ls -l test_file.txt
-r-xr-xr-x. 1 foo foo 0 Aug 24 19:03 test_file.txt

```

## 更改所有者和组

我们还可以更改文件的所有者和组所有权。这允许进一步修改文件的组和所有者。

### 更改文件的所有者

要更改命令的所有者，使用`chown`。这对于系统管理员在不同情况下非常有用。例如，用户正在进行一个项目，现在用户将要停止在该项目上的工作。在这种情况下，系统管理员可以将所有权修改为负责继续该项目的新用户。系统管理员可以将文件的所有权更改为项目中所有相关文件的新用户。

在我们之前的例子中，`foo`是`test_file.txt`文件的所有者。现在，我们想把文件的所有权转移到用户`bar`。

如果系统中不存在用户`bar`，可以使用`useradd`命令创建一个名为 bar 的新用户。需要 root 访问权限。

以下命令将创建一个名为`bar`的新用户：

```
$ sudo useradd bar  # New user bar will be created

```

我们可以通过以下命令将`test_file.txt`文件的所有权更改为用户`bar`：

```
$ sudo chown bar test_file.txt  # Changing ownership of file to user bar
$ ls -l  test_file.txt
-r-xr-xr-x. 1 bar foo 0 Aug 24 19:03 test_file.txt

```

我们可以看到文件的所有权已更改为 bar。

### 更改组所有权

要修改文件的组所有权，可以使用`chown`或`chgrp`命令。要创建一个新组，使用`groupadd`命令作为`sudo`或`root`。例如，我们想创建一个名为`test_group`的新组：

```
$ sudo groupadd test_group

```

现在，我们将使用`chown`命令将示例文件`test_file.txt`的组更改为。可以通过执行以下命令来完成这个操作：

```
$ sudo chown :test_group test_file.txt  # Modifying group ownership
$ ls -l test_file.txt
-r-xr-xr-x. 1 bar test_group 0 Aug 24 19:03 test_file.txt

```

我们可以看到组已经修改为`test_group`。要使用`chgrp`命令更改组，可以执行以下命令：

```
$  sudo chgrp bar test_file.txt  # Changing group ownership to bar
$ ls -l test_file.txt
-r-xr-xr-x. 1 bar bar 0 Aug 24 19:03 test_file.txt

```

现在，我们将把`test_file.txt`文件的所有者和组还原为`foo`：

```
$ sudo chown foo:foo test_file.txt
$ ls -l test_file.txt
-r-xr-xr-x. 1 foo foo 0 Aug 24 19:03 test_file.txt

```

在使用`chown`命令修改所有者和组所有权时，新的所有者名称在`:`（冒号）之前提供，组名称在`:`之后提供。

# 获取打开文件的列表

我们知道系统中可能有数百万个文件，可以是二进制文件、文本文件、目录等。当文件没有被使用时，它们只是作为“0 和 1”存储在存储设备上。要查看或处理文件，需要打开它。正在执行的应用程序可能会打开多个文件。知道运行应用程序打开了哪些文件非常有用。要知道已打开文件的列表，使用`lsof`命令。

执行以下命令会列出所有打开的文件：

```
$ lsof

```

这会给出所有打开文件的大量输出。

## 知道特定应用程序打开的文件

要知道特定应用程序打开的文件列表，首先获取正在运行应用程序的**进程 ID**（**PID**）：

```
$ pidof application_name

```

例如，让我们不带任何参数运行`cat`：

```
$ cat

```

在另一个终端中，运行以下命令：

```
$ pidof cat
15913
$ lsof -p 15913

```

或者，我们可以直接输入以下命令：

```
$ lsof -p 'pidof cat'

```

以下是`lsof`输出的示例截图：

![了解特定应用程序打开的文件](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_06_03.jpg)

在输出中，我们看到了各种结果的列。第一列是`COMMAND`，即打开此文件的应用程序，PID 列指定了打开文件的 PID，USER 指示打开文件的用户，FD 是文件描述符，TYPE 指定文件类型，DEVICE 指定设备号，值用逗号分隔，SIZE/OFF 指定文件大小或字节偏移量，NAME 是带有绝对路径的文件名。

在输出中，我们可以看到应用程序已经从`/usr/bin`打开了`cat binary`。它还加载了共享库文件，如`libc-2.21.so`和`ld-2.21.so`，这些文件位于`/usr/lib64/`中。此外，还有一个字符设备`dev/pts/2`被打开。

## 列出打开文件的应用程序

我们还可以找出哪些应用程序打开了一个文件。可以通过执行以下命令来实现：

```
$ lsof /usr/bin/bash

```

以下是示例输出：

![列出打开文件的应用程序](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_06_04.jpg)

从输出中，我们可以看到`bash`文件已被六个运行的应用程序打开。

## 了解用户打开的文件

要了解特定用户打开的文件列表，请使用`lsof`命令和`-u`选项。语法如下：

```
lsof -u user_name

```

例如，考虑以下命令：

```
$ lsof -u foo | wc -l
525

```

这意味着当前有`525`个文件由用户 root 打开。

# 配置文件

配置文件是包含应用程序设置的常规文件。在 Linux 和 UNIX 的执行初始阶段，许多应用程序从配置文件中读取设置，并相应地配置应用程序。

## 查看和修改配置文件

配置文件通常位于`/etc/`目录中，可以使用`cat`命令查看。

例如，考虑查看`resolv.conf`配置文件：

```
$ cat /etc/resolv.conf

```

```
# Generated by NetworkManager
search WirelessAP
nameserver 192.168.1.1
```

`resolv.conf`文件包含联系 DNS 服务器的顺序。

我们还可以修改配置文件以满足我们的需求。例如，如果一些网络 URL 可以通过`192.168.1.1`访问，我们可以在`/etc/resolv.conf`文件中添加另一个 DNS 条目，DNS 值为`8.8.8.8`。修改后的`cat /etc/resolv.conf`将如下所示：

```
$ cat /etc/resolv.conf

```

```
# Generated by NetworkManager
search WirelessAP
nameserver 192.168.1.1
nameserver 8.8.8.8
```

系统中还有许多其他配置文件，例如`ssh`、`passwd`、`profile`、`sysconfig`、`crontab`、`inittab`等，位于`/etc/`目录中。

# 总结

阅读本章后，您现在应该知道 UNIX 和基于 Linux 的操作系统将一切视为文件，可以进一步分类为常规、目录、链接、块设备、字符设备、套接字和管道文件。您还应该知道如何对这些文件中的任何一个执行基本操作。现在，您应该对如何查看和修改文件的权限和所有权有很好的了解。您还应该知道如何使用`lsof`命令监视和管理系统中打开文件的列表。

在下一章中，您将学习系统中如何创建进程以及如何监视和管理所有运行中的进程。我们还将看到两个或更多进程如何使用**进程间通信**（**IPC**）机制相互通信。
