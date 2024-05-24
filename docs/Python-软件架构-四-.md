# Python 软件架构（四）

> 原文：[`zh.annas-archive.org/md5/E8EC0BA674FAF6D2B8F974FE76F20D30`](https://zh.annas-archive.org/md5/E8EC0BA674FAF6D2B8F974FE76F20D30)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：安全 - 编写安全代码

软件应用程序的安全性（或缺乏安全性）在过去几年在行业和媒体中引起了很大的重视。似乎每隔一天，我们都会听到恶意黑客在世界各地的软件系统中造成大规模数据泄露，并造成数百万美元的损失。受害者可能是政府部门、金融机构、处理敏感客户数据（如密码、信用卡等）的公司等。

由于软件和硬件系统之间共享的数据数量空前增加 - 智能个人技术（如智能手机、智能手表、智能音乐播放器等）的爆炸式增长，以及其他智能系统的出现和帮助，已经在互联网上大规模传播了大量数据。随着 IPv6 的出现和预计在未来几年大规模采用**物联网**设备（**物联网**）的数量将呈指数级增长，数据量只会不断增加。

正如我们在第一章中讨论的，安全是软件架构的一个重要方面。除了使用安全原则构建系统外，架构师还应该尝试灌输团队安全编码原则，以最小化团队编写的代码中的安全漏洞。

在本章中，我们将探讨构建安全系统的原则，并探讨在 Python 中编写安全代码的技巧和技术。

我们将讨论的主题可以总结如下列表。

+   信息安全架构

+   安全编码

+   常见的安全漏洞

+   Python 是否安全？

+   读取输入

+   评估任意输入

+   溢出错误

+   序列化对象

+   Web 应用程序的安全问题

+   安全策略 - Python

+   安全编码策略

# 信息安全架构

安全架构涉及创建一个能够为授权人员和系统提供数据和信息访问权限的系统，同时防止任何未经授权的访问。为您的系统创建信息安全架构涉及以下方面：

+   **机密性**：一组规则或程序，限制对系统中信息的访问范围。机密性确保数据不会暴露给未经授权的访问或修改。

+   **完整性**：完整性是系统的属性，确保信息通道是可信赖和可靠的，并且系统没有外部操纵。换句话说，完整性确保数据在系统中的组件之间流动时是可信的。

+   **可用性**：系统将根据其服务级别协议（SLA）确保向其授权用户提供一定级别的服务的属性。可用性确保系统不会拒绝向其授权用户提供服务。

机密性、完整性和可用性这三个方面，通常称为 CIA 三位一体，构成了为系统构建信息安全架构的基石。

![信息安全架构](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00463.jpeg)

信息安全架构的 CIA 三位一体

这些方面受到其他特征的支持，例如以下特征：

+   **身份验证**：验证交易参与者的身份，并确保他们确实是他们所声称的人。例如，在电子邮件中使用的数字证书，用于登录系统的公钥等。

+   **授权**：授予特定用户/角色执行特定任务或相关任务组的权限。授权确保某些用户组与某些角色相关联，限制其在系统中的访问（读取）和修改（写入）权限。

+   不可否认性：保证参与交易的用户不能以后否认交易发生。例如，电子邮件的发送者不能以后否认他们发送了电子邮件；银行资金转账的接收方不能以后否认他们收到了钱，等等。

# 安全编码

安全编码是软件开发的实践，它保护程序免受安全漏洞的侵害，并使其抵抗恶意攻击，从程序设计到实施。这是关于编写固有安全的代码，而不是将安全视为后来添加的层。

安全编码背后的理念包括以下内容：

+   安全是设计和开发程序或应用程序时需要考虑的一个方面；这不是事后的想法。

+   安全需求应在开发周期的早期确定，并应传播到系统开发的后续阶段，以确保合规性得到维持。

+   使用威胁建模来预测系统从一开始面临的安全威胁。威胁建模包括以下内容：

1.  识别重要资产（代码/数据）。

1.  将应用程序分解为组件。

1.  识别和分类对每个资产或组件的威胁。

1.  根据已建立的风险模型对威胁进行排名。

1.  制定威胁缓解策略。

安全编码的实践或策略包括以下主要任务：

1.  应用程序的兴趣领域的定义：识别应用程序中代码/数据中的重要资产，这些资产是关键的，需要得到保护。

1.  软件架构分析：分析软件架构中的明显安全缺陷。组件之间的安全交互，以确保数据的保密性和完整性。确保通过适当的身份验证和授权技术保护机密数据。确保可用性从一开始就内置到架构中。

1.  实施细节审查：使用安全编码技术审查代码。确保进行同行审查以发现安全漏洞。向开发人员提供反馈并确保进行更改。

1.  逻辑和语法的验证：审查代码逻辑和语法，以确保实施中没有明显的漏洞。确保编程是根据编程语言/平台的常用安全编码指南进行的。

1.  白盒/单元测试：开发人员对其代码进行安全测试，除了确保功能的测试之外。可以使用模拟数据和/或 API 来虚拟化测试所需的第三方数据/API。

1.  黑盒测试：应用程序由经验丰富的质量保证工程师进行测试，他寻找安全漏洞，如未经授权访问数据，意外暴露代码或数据的路径，弱密码或哈希等。测试报告反馈给利益相关者，包括架构师，以确保修复已识别的漏洞。

实际上，安全编码是一个实践和习惯，软件开发组织应该通过经过精心制定和审查的安全编码策略来培养，如上述的策略。

# 常见的安全漏洞

那么，今天的专业程序员应该准备面对和减轻职业生涯中可能遇到的常见安全漏洞？从现有的文献来看，这些可以组织成几个特定的类别：

+   溢出错误：这些包括流行且经常被滥用的缓冲区溢出错误，以及较少为人知但仍然容易受到攻击的算术或整数溢出错误：

+   **缓冲区溢出**：缓冲区溢出是由编程错误产生的，允许应用程序在缓冲区的末尾或开头之外写入。缓冲区溢出允许攻击者通过精心制作的攻击数据访问应用程序的堆栈或堆内存，从而控制系统。

+   **整数或算术溢出**：当对整数进行算术或数学运算产生超出所用于存储的类型的最大大小的结果时，会发生这些错误。

如果未正确处理，整数溢出可能会导致安全漏洞。在支持有符号和无符号整数的编程语言中，溢出可能会导致数据包装并产生负数，从而允许攻击者获得类似于缓冲区溢出的结果，以访问程序执行限制之外的堆或栈内存。

+   **未经验证/未正确验证的输入**：现代 Web 应用程序中非常常见的安全问题，未经验证的输入可能会导致严重的漏洞，攻击者可以欺骗程序接受恶意输入，如代码数据或系统命令，当执行时可能会危害系统。旨在减轻此类攻击的系统应具有过滤器，以检查和删除恶意内容，并仅接受对系统合理和安全的数据。

此类攻击的常见子类型包括 SQL 注入、服务器端模板注入、**跨站脚本**（**XSS**）和 Shell 执行漏洞。

现代 Web 应用程序框架由于使用混合代码和数据的 HTML 模板而容易受到此类攻击的影响，但其中许多都有标准的缓解程序，如转义或过滤输入。

+   **不正确的访问控制**：现代应用程序应为其用户类别定义单独的角色，例如普通用户和具有特殊权限的用户，如超级用户或管理员。当应用程序未能或不正确地执行此操作时，可能会暴露路由（URL）或工作流程（由特定 URL 指定的一系列操作）的攻击向量，这可能会将敏感数据暴露给攻击者，或者在最坏的情况下，允许攻击者 compromise 并控制系统。

+   **密码学问题**：仅确保访问控制已经就位并不足以加固和保护系统。相反，应验证和确定安全级别和强度，否则，您的系统仍可能被黑客入侵或妥协。以下是一些示例：

+   **HTTP 而不是 HTTPS**：在实现 RestFUL Web 服务时，请确保优先选择 HTTPS（SSL/TLS）而不是 HTTP。在 HTTP 中，客户端和服务器之间的所有通信都是明文的，可以被被动网络嗅探器或精心制作的数据包捕获软件或安装在路由器中的设备轻松捕获。

像 letsencrypt 这样的项目已经为系统管理员提供了便利，可以获取和更新免费的 SSL 证书，因此使用 SSL/TLS 来保护您的服务器比以往任何时候都更容易。

+   **不安全的身份验证**：在 Web 服务器上，优先选择安全的身份验证技术而不是不安全的技术。例如，在 Web 服务器上，优先选择 HTTP 摘要身份验证而不是基本身份验证，因为在基本身份验证中，密码是明文传输的。同样，在大型共享网络中使用**Kerberos**身份验证，而不是**轻量级目录访问协议**（**LDAP**）或**NT LAN Manager**（**NTLM**）等不太安全的替代方案。

+   **使用弱密码**：易于猜测的或默认/琐碎的密码是许多现代 Web 应用程序的祸根。

+   **重用安全哈希/密钥** - 安全哈希或密钥通常特定于应用程序或项目，不应跨应用程序重用。每当需要时生成新的哈希和/或密钥。

+   **弱加密技术**：用于在服务器（SSL 证书）或个人计算机（GPG/PGP 密钥）上加密通信的密码应该使用高级别的安全性——至少 2048 位，并使用经过同行评审和加密安全的算法。

+   **弱哈希技术**：就像密码一样，用于保持敏感数据（如密码）的哈希技术应该谨慎选择强大的算法。例如，如果今天编写一个需要计算和存储哈希的应用程序，最好使用 SHA-1 或 SHA-2 算法，而不是较弱的 MD5。

+   **无效或过期的证书/密钥**：网站管理员经常忘记更新其 SSL 证书，这可能成为一个大问题，损害其 Web 服务器的安全性，因为无效的证书没有提供任何保护。类似地，用于电子邮件通信的个人密钥（如 GPG 或 PGP 公钥/私钥对）应该保持更新。

启用密码的 SSH - 使用明文密码对远程系统进行 SSH 访问是一个安全漏洞。禁用基于密码的访问，只允许特定用户通过授权的 SSH 密钥进行访问。禁用远程 root SSH 访问。

+   **信息泄漏**：许多 Web 服务器系统——主要是由于开放配置、或配置错误、或由于缺乏对输入的验证——可以向攻击者泄露许多关于自身的信息。以下是一些例子：

+   **服务器元信息**：许多 Web 服务器通过其 404 页面泄露有关自身的信息，有时还通过其登陆页面。以下是一个例子：![常见的安全漏洞](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00464.jpeg)

暴露服务器元信息的 Web 服务器 404 页面

仅仅通过请求一个不存在的页面，我们得知在前面截图中看到的网站在 Debian 服务器上运行 Apache 版本 2.4.10。对于狡猾的攻击者来说，这通常已经足够提供特定攻击的信息，针对特定的 Web 服务器/操作系统组合。

+   **打开索引页面**：许多网站不保护其目录页面，而是让它们对世界开放。以下图片显示了一个例子：![常见的安全漏洞](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00465.jpeg)

打开 Web 服务器的索引页面

+   **打开端口**：常见的错误是在远程 Web 服务器上运行的应用程序端口提供全球访问权限，而不是通过使用防火墙（如*iptables*）限制它们的访问权限，例如特定 IP 地址或安全组。类似的错误是允许服务在 0.0.0.0（服务器上的所有 IP 地址）上运行，而该服务仅在本地主机上使用。这使得攻击者可以使用网络侦察工具（如*nmap/hping3*等）扫描此类端口，并计划他们的攻击。

对文件/文件夹/数据库开放访问 - 提供应用程序配置文件、日志文件、进程 ID 文件和其他文件的开放或全球访问是一个非常糟糕的做法，以便任何登录用户都可以访问并从这些文件中获取信息。相反，这些文件应该成为安全策略的一部分，以确保只有具有所需特权的特定角色可以访问这些文件。

+   **竞争条件**：当程序有两个或更多的参与者试图访问某个资源，但输出取决于访问的正确顺序，而这不能得到保证时，就存在竞争条件。一个例子是两个线程试图在共享内存中递增一个数值而没有适当的同步。

狡猾的攻击者可以利用这种情况插入恶意代码，更改文件名，或者有时利用代码处理中的小时间间隙干扰操作的顺序。

+   **系统时钟漂移**：这是一个现象，即由于不正确或缺失的同步，服务器上的系统或本地时钟时间慢慢偏离参考时间。随着时间的推移，时钟漂移可能导致严重的安全漏洞，例如 SSL 证书验证错误，可以通过高度复杂的技术（如*定时攻击*）利用，攻击者试图通过分析执行加密算法所需的时间来控制系统。时间同步协议如 NTP 可以用来减轻这种情况。

+   **不安全的文件/文件夹操作**：程序员经常对文件或文件夹的所有权、位置或属性做出假设，而这在实践中可能并不成立。这可能导致安全漏洞或我们可能无法检测到对系统的篡改。以下是一些例子：

+   在写操作后未检查结果，假设它成功了

+   假设本地文件路径总是本地文件（而实际上，它们可能是对应用程序可能无法访问的系统文件的符号链接）

+   在执行系统命令时不正确使用 sudo，如果不正确执行，可能会导致漏洞，可以用来获取系统的根访问权限

+   对共享文件或文件夹过度使用权限，例如，打开程序的所有执行位，应该限制为一个组，或者可以被任何登录用户读取的开放家庭文件夹

+   使用不安全的代码或数据对象序列化和反序列化

本章的范围超出了访问此列表中每一种漏洞的范围。然而，我们将尽力审查和解释影响 Python 及其一些 Web 框架的常见软件漏洞类别，并在接下来的部分中进行解释。

# Python 安全吗？

Python 是一种非常易读的语言，语法简单，通常有一种清晰的方法来做事情。它配备了一组经过充分测试和紧凑的标准库模块。所有这些似乎表明 Python 应该是一种非常安全的语言。

但是真的吗？

让我们看看 Python 中的一些例子，并尝试分析 Python 及其标准库的安全性方面。

为了实用性，我们将展示本节中显示的代码示例使用 Python 2.x 和 Python 3.x 版本。这是因为 Python 2.x 版本中存在的许多安全漏洞在最近的 3.x 版本中得到了修复。然而，由于许多 Python 开发人员仍在使用 Python 2.x 的某种形式，这些代码示例对他们来说是有用的，并且还说明了迁移到 Python 3.x 的重要性。

所有示例都在运行 Linux（Ubuntu 16.0），x86_64 架构的机器上执行：

### 注意

注意：这些示例使用的 Python 3.x 版本是 Python 3.5.2，使用的 Python 2.x 版本是 Python 2.7.12。所有示例都在运行 Linux（Ubuntu 16.0）的机器上执行，64 位 x86 架构

```py
$ python3
Python 3.5.2 (default, Jul  5 2016, 12:43:10) 
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import sys
>>> print (sys.version)
3.5.2 (default, Jul  5 2016, 12:43:10) 
[GCC 5.4.0 20160609]
```

```py
$ python2
Python 2.7.12 (default, Jul  1 2016, 15:12:24) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import sys
>>> print sys.version
2.7.12 (default, Jul  1 2016, 15:12:24) 
[GCC 5.4.0 20160609]
```

### 注意

注意：大多数示例将使用一个版本的代码，该代码将在 Python 2.x 和 Python 3.x 中运行。在无法实现这一点的情况下，将列出代码的两个版本。

## 读取输入

让我们看看这个简单的猜数字游戏程序。它从标准输入读取一个数字，并将其与一个随机数进行比较。如果匹配，用户就赢了，否则，用户必须再试一次：

```py
# guessing.py
import random

# Some global password information which is hard-coded
passwords={"joe": "world123",
          "jane": "hello123"}

def game():
     """A guessing game """

    # Use 'input' to read the standard input
    value=input("Please enter your guess (between 1 and 10): ")
    print("Entered value is",value)
    if value == random.randrange(1, 10):
        print("You won!")
    else:
        print("Try again")

if __name__ == "__main__":
    game()
```

前面的代码很简单，只是有一些敏感的全局数据，即系统中一些用户的密码。在一个现实的例子中，这些可能由一些其他函数填充，这些函数读取密码并将它们缓存在内存中。

让我们尝试使用一些标准输入运行程序。我们将首先使用 Python 2.7 运行它，如下所示：

```py
$ python2 guessing.py
Please enter your guess (between 1 and 10): 6
('Entered value is', 6)
Try again
$ python2 guessing.py
Please enter your guess (between 1 and 10): 8
('Entered value is', 8)
You won!

```

现在，让我们尝试一个“非标准”的输入：

```py
$ python2 guessing.py
Please enter your guess (between 1 and 10): passwords
('Entered value is', {'jane': 'hello123', 'joe': 'world123'})
Try again
```

注意前面的运行暴露了全局密码数据！

问题在于在 Python 2 中，输入值被评估为一个表达式而不进行任何检查，当它被打印时，表达式打印出它的值。在这种情况下，它恰好匹配一个全局变量，所以它的值被打印出来。

现在让我们看看这个：

```py
$ python2 guessing.py
Please enter your guess (between 1 and 10): globals()
('Entered value is', {'passwords': {'jane': 'hello123', 
'joe' : 'world123'}, '__builtins__': <module '__builtin__' (built-in)>,
 '__file__': 'guessing.py', 'random': 
<module 'random' from '/usr/lib/python2.7/random.pyc'>,
 '__package__': None, 'game': 
<function game at 0x7f6ef9c65d70>,
 '__name__': '__main__', '__doc__': None})
Try again
```

现在，它不仅暴露了密码，还暴露了代码中的完整全局变量，包括密码。即使程序中没有敏感数据，使用这种方法的黑客也可以揭示有关程序的有价值的信息，如变量名、函数名、使用的包等等。

这个问题的解决方案是什么？对于 Python 2，一个解决方案是用`raw_input`替换`input`，`raw_input`不评估内容。由于`raw_input`不返回数字，需要将其转换为目标类型。（可以通过将返回数据转换为`int`来完成。）以下代码不仅完成了这一点，还为类型转换添加了异常处理程序以提高安全性：

```py
# guessing_fix.py
import random

passwords={"joe": "world123",
                  "jane": "hello123"}

def game():
    value=raw_input("Please enter your guess (between 1 and 10): ")
    try:
        value=int(value)
    except TypeError:
        print ('Wrong type entered, try again',value)
        return

    print("Entered value is",value)
    if value == random.randrange(1, 10):
        print("You won!")
    else:
        print("Try again")

if __name__ == "__main__":
    game()
```

让我们看看这个版本如何修复评估输入的安全漏洞

```py
$ python2 guessing_fix.py 
Please enter your guess (between 1 and 10): 9
('Entered value is', 9)
Try again
$ python2 guessing_fix.py 
Please enter your guess (between1 and 10): 2
('Entered value is', 2)
You won!

$ python2 guessing_fix.py 
Please enter your guess (between 1 and 10): passwords
(Wrong type entered, try again =>, passwords)

$ python2 guessing_fix.py 
Please enter your guess (between 1 and 10): globals()
(Wrong type entered, try again =>, globals())
```

新程序现在比第一个版本安全得多。

这个问题在 Python 3.x 中不存在，如下图所示。（我们使用原始版本来运行这个）。

```py
$ python3 guessing.py 
Please enter your guess (between 1 and 10): passwords
Entered value is passwords
Try again

$ python3 guessing.py 
Please enter your guess (between 1 and 10): globals()
Entered value is globals()
Try again
```

## 评估任意输入

Python 中的`eval`函数非常强大，但也很危险，因为它允许将任意字符串传递给它，这可能会评估潜在危险的代码或命令。

让我们看看这个相当愚蠢的代码作为一个测试程序，看看`eval`能做什么：

```py
# test_eval.py
import sys
import os

def run_code(string):
    """ Evaluate the passed string as code """

    try:
eval(string, {})
    except Exception as e:
        print(repr(e))

if __name__ == "__main__":
     run_code(sys.argv[1])
```

让我们假设一个攻击者试图利用这段代码来查找应用程序运行的目录的内容。（暂时可以假设攻击者可以通过 Web 应用程序运行此代码，但没有直接访问机器本身）。

假设攻击者试图列出当前文件夹的内容：

```py
$ python2 test_eval.py "os.system('ls -a')"
NameError("name 'os' is not defined",)
```

这个先前的攻击不起作用，因为`eval`需要一个第二个参数，在评估过程中提供要使用的全局值。由于在我们的代码中，我们将这个第二个参数作为空字典传递，我们会得到错误，因为 Python 无法解析`os`名称。

这是否意味着`eval`是安全的？不，它不是。让我们看看为什么。

当我们将以下输入传递给代码时会发生什么？

```py
$ python2 test_eval.py "__import__('os').system('ls -a')"
.   guessing_fix.py  test_eval.py    test_input.py
..  guessing.py      test_format.py  test_io.py
```

我们可以看到，我们仍然能够通过使用内置函数`__import__`来诱使`eval`执行我们的命令。

这样做的原因是因为像`__import__`这样的名称在默认内置的`__builtins__`全局中是可用的。我们可以通过将其作为空字典传递给第二个参数来拒绝`eval`。这是修改后的版本：

```py
# test_eval.py
import sys
import os

def run_code(string):
    """ Evaluate the passed string as code """

    try:
        # Pass __builtins__ dictionary as empty
        eval(string,  {'__builtins__':{}})
    except Exception as e:
        print(repr(e))

if __name__ == "__main__":
run_code(sys.argv[1])
```

现在攻击者无法通过内置的`__import__`进行利用：

```py
$ python2 test_eval.py "__import__('os').system('ls -a')"
NameError("name '__import__' is not defined",)
```

然而，这并不意味着`eval`更安全，因为它容易受到稍长一点但聪明的攻击。以下是这样一种攻击：

```py
$ python2 test_eval.py "(lambda f=(lambda x: [c for c in [].__class__.__bases__[0].__subclasses__() if c.__name__ == x][0]): f('function')(f('code')(0,0,0,0,'BOOM',(), (),(),'','',0,''),{})())()"
Segmentation fault (core dumped)
```

我们能够使用一个看起来相当晦涩的恶意代码来使 Python 解释器崩溃。这是怎么发生的？

这里是步骤的一些详细解释。

首先，让我们考虑一下这个：

```py
>>> [].__class__.__bases__[0]
<type 'object'>
```

这只是基类`object`。由于我们无法访问内置函数，这是一种间接访问它的方法。

接下来，以下代码行加载了 Python 解释器中当前加载的`object`的所有子类：

```py
>>> [c for c in [].__class__.__bases__[0].__subclasses__()]
```

其中，我们想要的是`code`对象类型。这可以通过检查项目的名称通过`__name__`属性来访问：

```py
>>> [c for c in [].__class__.__bases__[0].__subclasses__() if c.__name__ == 'code']
```

这是通过使用匿名`lambda`函数实现的相同效果：

```py
>>> (lambda x: [c for c in [].__class__.__bases__[0].__subclasses__() if c.__name__ == x])('code')
[<type 'code'>]
```

接下来，我们想要执行这个代码对象。然而，`code`对象不能直接调用。它们需要绑定到一个函数才能被调用。这是通过将前面的`lambda`函数包装在外部`lambda`函数中实现的：

```py
>>> (lambda f: (lambda x: [c for c in [].__class__.__bases__[0].__subclasses__() if c.__name__ == x])('code'))
<function <lambda> at 0x7f8b16a89668
```

现在我们的内部`lambda`函数可以分两步调用：

```py
>>> (lambda f=(lambda x: [c for c in [].__class__.__bases__[0].__subclasses__() if c.__name__ == x][0]): f('function')(f('code')))
<function <lambda> at 0x7fd35e0db7d0>
```

最后，我们通过这个外部的`lambda`函数调用`code`对象，传递了大多数默认参数。代码字符串被传递为字符串`BOOM`，当然，这是一个虚假的代码字符串，会导致 Python 解释器崩溃，产生核心转储：

```py
>>> (lambda f=(lambda x: 
[c for c in [].__class__.__bases__[0].__subclasses__() if c.__name__ == x][0]): 
f('function')(f('code')(0,0,0,0,'BOOM',(), (),(),'','',0,''),{})())()
Segmentation fault (core dumped)
```

这表明在任何情况下，即使没有内置模块的支持，`eval`都是不安全的，并且可以被聪明而恶意的黑客利用来使 Python 解释器崩溃，从而可能控制系统。

请注意，相同的利用在 Python 3 中也有效，但是我们需要对`code`对象的参数进行一些修改，因为在 Python 3 中，`code`对象需要额外的参数。此外，代码字符串和一些参数必须是`byte`类型。

以下是在 Python 3 上运行的利用。最终结果是相同的：

```py
$ python3 test_eval.py 
"(lambda f=(lambda x: [c for c in ().__class__.__bases__[0].__subclasses__() 
  if c.__name__ == x][0]): f('function')(f('code')(0,0,0,0,0,b't\x00\x00j\x01\x00d\x01\x00\x83\x01\x00\x01d\x00\x00S',(), (),(),'','',0,b''),{})())()"
Segmentation fault (core dumped)
```

## 溢出错误

在 Python 2 中，如果`xrange()`函数的范围无法适应 Python 的整数范围，则会产生溢出错误：

```py
>>> print xrange(2**63)
Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
OverflowError: Python int too large to convert to C long
```

`range()`函数也会出现略有不同的溢出错误：

```py
>>> print range(2**63)
Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
OverflowError: range() result has too many items
```

问题在于`xrange()`和`range()`使用普通整数对象（类型`<int>`），而不是自动转换为仅受系统内存限制的`long`类型。

然而，在 Python 3.x 版本中，这个问题已经得到解决，因为类型`int`和`long`被统一为一个（`int`类型），而`range()`对象在内部管理内存。此外，不再有单独的`xrange()`对象：

```py
>>> range(2**63)
range(0, 9223372036854775808)
```

这是 Python 中整数溢出错误的另一个例子，这次是针对`len`函数。

在以下示例中，我们尝试对两个类 A 和 B 的实例使用`len`函数，这两个类的魔术方法`__len__`已被覆盖以支持`len`函数。请注意，A 是一个新式类，继承自`object`，而 B 是一个旧式类。

```py
# len_overflow.py

class A(object):
    def __len__(self): 
        return 100 ** 100

class B:
    def __len__(self): 
        return 100 ** 100

try:
    len(A())
    print("OK: 'class A(object)' with 'return 100 ** 100' - len calculated")
except Exception as e:
    print("Not OK: 'class A(object)' with 'return 100 ** 100' - len raise Error: " + repr(e))

try:
    len(B())
    print("OK: 'class B' with 'return 100 ** 100' - len calculated")
except Exception as e:
    print("Not OK: 'class B' with 'return 100 ** 100' - len raise Error: " + repr(e))
```

以下是在 Python2 中执行代码时的输出：

```py
$ python2 len_overflow.py** 
Not OK: 'class A(object)' with 'return 100 ** 100' - len raise Error: OverflowError('long int too large to convert to int',)
Not OK: 'class B' with 'return 100 ** 100' - len raise Error: TypeError('__len__() should return an int',)

```

在 Python 3 中执行相同的代码如下：

```py
$ python3 len_overflow.py** 
Not OK: 'class A(object)' with 'return 100 ** 100' - len raise Error: OverflowError("cannot fit 'int' into an index-sized integer",)
Not OK: 'class B' with 'return 100 ** 100' - len raise Error: OverflowError("cannot fit 'int' into an index-sized integer",)

```

在前面的代码中的问题在于`len`返回`integer`对象，在这种情况下，实际值太大而无法适应`int`，因此 Python 引发了溢出错误。然而，在 Python 2 中，对于未从`object`派生的类的情况，执行的代码略有不同，它预期一个`int`对象，但得到了`long`并抛出了`TypeError`。在 Python 3 中，这两个示例都返回溢出错误。

这样的整数溢出错误是否存在安全问题？

在实际情况中，这取决于应用程序代码和所使用的依赖模块代码，以及它们如何处理或捕获/掩盖溢出错误。

然而，由于 Python 是用 C 编写的，任何在底层 C 代码中没有正确处理的溢出错误都可能导致缓冲区溢出异常，攻击者可以向溢出缓冲区写入并劫持底层进程/应用程序。

通常，如果一个模块或数据结构能够处理溢出错误并引发异常以阻止进一步的代码执行，那么代码利用的可能性就会减少。

## 对象序列化

对于 Python 开发人员来说，使用`pickle`模块及其 C 实现的`cPickle`来对 Python 中的对象进行序列化是非常常见的。然而，这两个模块都允许未经检查的代码执行，因为它们不对被序列化的对象进行任何类型检查或规则的强制，以验证它是一个良性的 Python 对象还是一个可能利用系统的潜在命令。

### 注意

注意：在 Python3 中，`cPickle`和`pickle`模块合并为一个单独的`pickle`模块。

这是通过 shell 利用的示例，它列出了 Linux/POSIX 系统中根文件夹（/）的内容：

```py
# test_serialize.py
import os
import pickle

class ShellExploit(object):
    """ A shell exploit class """

    def __reduce__(self):
        # this will list contents of root / folder.
        return (os.system, ('ls -al /',)

def serialize():
    shellcode = pickle.dumps(ShellExploit())
    return shellcode

def deserialize(exploit_code):
    pickle.loads(exploit_code)

if __name__ == '__main__':
    shellcode = serialize()
    deserialize(shellcode)
```

最后的代码简单地打包了一个`ShellExploit`类，该类在进行 pickle 时通过`os.system()`方法返回列出根文件系统`/`内容的命令。`Exploit`类将恶意代码伪装成`pickle`对象，该对象在解 pickle 时执行代码，并将机器的根文件夹内容暴露给攻击者。上述代码的输出如下所示：

![序列化对象](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00466.jpeg)

使用 pickle 进行序列化的 shell 利用代码的输出，暴露了/文件夹的内容。

正如你所看到的，输出清楚地列出了根文件夹的内容。

如何防止这种利用的解决方法是什么？

首先，不要在应用程序中使用像`pickle`这样的不安全模块进行序列化。而是依赖于更安全的替代方案，如`json`或`yaml`。如果你的应用程序确实依赖于某种原因使用`pickle`模块，那么使用沙箱软件或`codeJail`来创建防止系统上恶意代码执行的安全环境。

例如，这是对先前代码的轻微修改，现在使用一个简单的 chroot 监狱，防止在实际根文件夹上执行代码。它使用一个本地的`safe_root/`子文件夹作为新的根目录，通过上下文管理器钩子。请注意，这只是一个简单的例子。实际的监狱会比这个复杂得多：

```py
# test_serialize_safe.py
import os
import pickle
from contextlib import contextmanager

class ShellExploit(object):
    def __reduce__(self):
        # this will list contents of root / folder.
        return (os.system, ('ls -al /',))

@contextmanager
def system_jail():
    """ A simple chroot jail """

    os.chroot('safe_root/')
    yield
    os.chroot('/')

def serialize():
    with system_jail():
        shellcode = pickle.dumps(ShellExploit())
        return shellcode

def deserialize(exploit_code):
    with system_jail():
        pickle.loads(exploit_code)

if __name__ == '__main__':
    shellcode = serialize()
    deserialize(shellcode)
```

有了这个监狱，代码执行如下：

![序列化对象](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00467.jpeg)

使用 pickle 进行序列化的 shell 利用代码的输出，带有一个简单的 chroot 监狱。

现在不会产生任何输出，因为这是一个虚假的监狱，Python 在新根目录中找不到`ls`命令。当然，为了使这在生产系统中起作用，应该设置一个适当的监狱，允许程序执行，但同时防止或限制恶意程序的执行。

其他序列化格式如 JSON 怎么样？这样的利用可以使用它们吗？让我们用一个例子来看看。

这里是使用`json`模块编写的相同序列化代码：

```py
# test_serialize_json.py
import os
import json
import datetime

class ExploitEncoder(json.JSONEncoder):
    def default(self, obj):
        if any(isinstance(obj, x) for x in (datetime.datetime, datetime.date)):
            return str(obj)

        # this will list contents of root / folder.
        return (os.system, ('ls -al /',))

def serialize():
    shellcode = json.dumps([range(10),
                            datetime.datetime.now()],
                           cls=ExploitEncoder)
    print(shellcode)
    return shellcode

def deserialize(exploit_code):
    print(json.loads(exploit_code))

if __name__ == '__main__':
    shellcode = serialize()
    deserialize(shellcode)
```

请注意，使用自定义编码器`ExploitEncoder`覆盖了默认的 JSON 编码器。然而，由于 JSON 格式不支持这种序列化，它返回了作为输入传递的列表的正确序列化：

```py
$ python2 test_serialize_json.py 
[[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], "2017-04-15 12:27:09.549154"]
[[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], u'2017-04-15 12:27:09.549154']
```

使用 Python3，利用程序失败，因为 Python3 会引发异常。

![序列化对象](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00468.jpeg)

使用 Python3 进行序列化的 shell 利用代码的输出

# Web 应用程序的安全问题

到目前为止，我们已经看到了 Python 的四种安全问题，即读取输入、评估表达式、溢出错误和序列化问题。到目前为止，我们所有的例子都是在控制台上使用 Python。

然而，我们几乎每天都与 Web 应用程序进行交互，其中许多是使用 Python Web 框架编写的，如 Django、Flask、Pyramid 等。因此，我们更有可能在这些应用程序中暴露出安全问题。我们将在这里看一些例子。

## 服务器端模板注入

**服务器端模板注入**（**SSTI**）是一种使用常见 Web 框架的服务器端模板作为攻击向量的攻击。该攻击利用了用户输入嵌入模板的方式中的弱点。SSTI 攻击可以用于查找 Web 应用程序的内部情况，执行 shell 命令，甚至完全破坏服务器。

我们将看到一个使用 Python 中非常流行的 Web 应用程序框架 Flask 的示例。

以下是一个在 Flask 中使用内联模板的相当简单的 Web 应用程序的示例代码：

```py
# ssti-example.py
from flask import Flask
from flask import request, render_template_string, render_template

app = Flask(__name__)

@app.route('/hello-ssti')
defhello_ssti():
    person = {'name':"world", 'secret': 'jo5gmvlligcZ5YZGenWnGcol8JnwhWZd2lJZYo=='}
    if request.args.get('name'):
        person['name'] = request.args.get('name')

    template = '<h2>Hello %s!</h2>' % person['name']
    return render_template_string(template, person=person)

if __name__ == "__main__":
app.run(debug=True)
```

在控制台上运行，并在浏览器中打开，允许我们在`hello-ssti`路由中玩耍：

```py
$ python3 ssti_example.py 
 * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
 * Restarting with stat
 * Debugger is active!
 * Debugger pin code: 163-936-023
```

首先，让我们尝试一些良性输入：

![服务器端模板注入](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00469.jpeg)

这里是另一个例子。

![服务器端模板注入](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00470.jpeg)

接下来，让我们尝试一些攻击者可能使用的巧妙输入。

![服务器端模板注入](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00471.jpeg)

这里发生了什么？

由于模板使用不安全的`%s`字符串模板，它会将传递给它的任何内容评估为 Python 表达式。我们传递了`{{ person.secret }}`，在 Flask 模板语言（Flask 使用 Jinja2 模板）中，它被评估为字典`person`中密钥 secret 的值，从而有效地暴露了应用程序的秘密密钥！

我们可以进行更加雄心勃勃的攻击，因为代码中的这个漏洞允许攻击者尝试 Jinja 模板的全部功能，包括 for 循环。以下是一个示例：

![服务器端模板注入](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00472.jpeg)

用于攻击的 URL 如下：

```py
http://localhost:5000/hello-ssti?name={% for item in person %}<p>{{ item, person[item] }}</p>{% endfor %}
```

这通过一个 for 循环，尝试打印`person`字典的所有内容。

这也允许攻击者轻松访问敏感的服务器端配置参数。例如，他可以通过将名称参数传递为`{{ config }}`来打印 Flask 配置。

这是浏览器的图像，使用此攻击打印服务器配置。

![服务器端模板注入](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00473.jpeg)

## 服务器端模板注入 - 缓解

我们在上一节中看到了一些使用服务器端模板作为攻击向量来暴露 Web 应用程序/服务器敏感信息的示例。在本节中，我们将看到程序员如何保护他的代码免受此类攻击。

在这种特定情况下，修复此问题的方法是在模板中使用我们想要的特定变量，而不是危险的、允许所有`%s`字符串。以下是带有修复的修改后的代码：

```py
# ssti-example-fixed.py
from flask import Flask
from flask import request, render_template_string, render_template

app = Flask(__name__)

@app.route('/hello-ssti')
defhello_ssti():
    person = {'name':"world", 'secret': 'jo5gmvlligcZ5YZGenWnGcol8JnwhWZd2lJZYo=='}
    if request.args.get('name'):
        person['name'] = request.args.get('name')

    template = '<h2>Hello {{ person.name }} !</h2>'
    return render_template_string(template, person=person)

if __name__ == "__main__":
app.run(debug=True)
```

现在，先前的所有攻击都会失败。

这是第一次攻击的浏览器图像：

![服务器端模板注入 - 缓解](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00474.jpeg)

以下是下一次攻击的浏览器图像。

![服务器端模板注入 - 缓解](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00475.jpeg)

## 拒绝服务

现在让我们看看另一种常被恶意黑客使用的攻击，即**拒绝服务**（**DOS**）。

DoS 攻击针对 Web 应用程序中的易受攻击的路由或 URL，并向其发送巧妙的数据包或 URL，这些数据包或 URL 要么迫使服务器执行无限循环或 CPU 密集型计算，要么迫使服务器从数据库中加载大量数据，这会给服务器 CPU 带来很大负载，从而阻止服务器执行其他请求。

### 注意

DDoS 或分布式 DoS 攻击是指以协调的方式使用多个系统针对单个域的 DoS 攻击。通常使用数千个 IP 地址，这些 IP 地址通过僵尸网络进行管理以进行 DDoS 攻击。

我们将看到一个使用我们先前示例的变体的 DoS 攻击的最小示例：

```py
# ssti-example-dos.py
from flask import Flask
from flask import request, render_template_string, render_template

app = Flask(__name__)

TEMPLATE = '''
<html>
 <head><title> Hello {{ person.name }} </title></head>
 <body> Hello FOO </body>
</html>
'''

@app.route('/hello-ssti')
defhello_ssti():
    person = {'name':"world", 'secret': 'jo5gmvlligcZ5YZGenWnGcol8JnwhWZd2lJZYo=='} 
    if request.args.get('name'):
        person['name'] = request.args.get('name')

    # Replace FOO with person's name
    template = TEMPLATE.replace("FOO", person['name'])
    return render_template_string(template, person=person)

if __name__ == "__main__":
app.run(debug=True)
```

在上述代码中，我们使用一个名为`TEMPLATE`的全局模板变量，并使用`safer {{ person.name }}`模板变量作为与 SSTI 修复一起使用的模板变量。但是，这里的附加代码是用名称值替换了持有名称`FOO`。

这个版本具有原始代码的所有漏洞，即使删除了`%s`代码。例如，看一下浏览器暴露了`{{ person.secret }}`变量值的图像，但没有在页面标题中暴露。

![拒绝服务](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00476.jpeg)

这是由于我们添加的以下代码行。

```py
 # Replace FOO with person's name
 template = TEMPLATE.replace("FOO", person['name'])
```

任何传递的表达式都会被评估，包括算术表达式。例如：

![拒绝服务](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00477.jpeg)

这打开了通过传递服务器无法处理的 CPU 密集型计算的简单 DoS 攻击的途径。例如，在以下攻击中，我们传递了一个非常大的数字计算，它占用了系统的 CPU，减慢了系统的速度，并使应用程序无响应：

![拒绝服务](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00478.jpeg)

使用计算密集型代码演示 DoS 风格攻击的示例。请求从未完成。

此攻击使用的 URL 是`http://localhost:5000/hello-ssti?name=Tom`。

通过传入计算密集的算术表达式`{{ 100**100000000 }}`，服务器被超载，无法处理其他请求。

正如您在上一张图片中所看到的，请求从未完成，也阻止了服务器响应其他请求；正如您可以从右侧打开的新标签页上对同一应用程序的正常请求也被阻塞，导致了 DoS 风格攻击的效果。

![拒绝服务](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00479.jpeg)

右侧打开的新标签页显示应用程序已经无响应。

## 跨站脚本攻击（XSS）

我们在前一节中使用的代码来演示最小化 DOS 攻击也容易受到脚本注入的影响。以下是一个示例：

![跨站脚本攻击（XSS）](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00480.jpeg)

使用服务器端模板和 JavaScript 注入演示 XSS 脚本注入的简单示例

此攻击使用的 URL 是：

```py
http://localhost:5000/hello-ssti?name=Tom<script>alert("You are under attack!")</script>
```

这些脚本注入漏洞可能导致 XSS，这是一种常见的 Web 利用形式，攻击者能够将恶意脚本注入到您服务器的代码中，从其他网站加载，并控制它。

## 缓解- DoS 和 XSS

在上一节中，我们看到了一些 DoS 攻击和简单的 XSS 攻击的示例。现在让我们看看程序员如何在他的代码中采取措施来缓解这种攻击。

在我们用于说明的先前特定示例中，修复方法是删除替换字符串`FOO`的行，并将其替换为参数模板本身。为了保险起见，我们还确保输出通过使用 Jinja 2 的转义过滤器`|e`进行适当的转义。以下是重写的代码：

```py
# ssti-example-dos-fix.py
from flask import Flask
from flask import request, render_template_string, render_template

app = Flask(__name__)

TEMPLATE = '''
<html>
 <head><title> Hello {{ person.name | e }} </title></head>
 <body> Hello {{ person.name | e }} </body>
</html>
'''

@app.route('/hello-ssti')
defhello_ssti():
    person = {'name':"world", 'secret': 'jo5gmvlligcZ5YZGenWnGcol8JnwhWZd2lJZYo=='} 
    if request.args.get('name'):
        person['name'] = request.args.get('name')
    return render_template_string(TEMPLATE, person=person)

if __name__ == "__main__":
app.run(debug=True)
```

现在这两个漏洞都得到了缓解，攻击没有效果，也没有造成伤害。

这是一个演示 DoS 攻击的图像。

![缓解- DoS 和 XSS](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00481.jpeg)

这是一个演示 XSS 攻击的示例。

![缓解- DoS 和 XSS](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00482.jpeg)

由于服务器端模板中的糟糕代码，类似的漏洞也存在于其他 Python Web 框架，如 Django、Pyramid、Tornado 等。然而，逐步讨论每个框架的内容超出了本章的范围。有兴趣的读者可以查阅网络上讨论此类问题的安全资源。

# 安全策略- Python

我们已经讨论了 Python 编程语言核心中存在的许多漏洞，还看了一些影响 Python Web 应用程序的常见安全问题。

现在是时候了解安全架构师可以使用的策略-提示和技术，以便他们的团队可以从程序设计和开发阶段开始应用安全编码原则来缓解安全问题：

+   **读取输入**：在读取控制台输入时，优先使用 raw_input 而不是 input，因为前者不会评估 Python 表达式，而是将输入作为纯字符串返回。任何类型转换或验证都应手动完成，如果类型不匹配，则抛出异常或返回错误。对于读取密码，使用 getpass 等库，并对返回的数据进行验证。一旦验证成功，可以安全地对数据进行评估。

+   **评估表达式**：正如我们在示例中所看到的，eval 无论如何使用都存在漏洞。因此，Python 的最佳策略是避免使用 eval 及其邪恶的表亲 exec。如果必须使用 eval，请务必不要与用户输入字符串、或从第三方库或 API 读取的数据一起使用。只能与您控制并信任的函数的输入源和返回值一起使用 eval。

+   序列化：不要使用`pickle`或`cPickle`进行序列化。更倾向于其他模块，如 JASON 或 YAML。如果绝对必须使用`pickle`/`cPickle`，则使用缓解策略，如 chroot 监狱或沙盒，以避免恶意代码执行的不良影响。

+   溢出错误：通过使用异常处理程序来防范整数溢出。Python 不会受到纯缓冲区溢出错误的影响，因为它总是检查其容器是否超出边界的读/写访问，并抛出异常。对于类中重写的`__len__`方法，根据需要捕获溢出或`TypeError`异常。

+   字符串格式化：更倾向于使用模板字符串的新方法，而不是旧的和不安全的`%s`插值。

例如：

```py
def display_safe(employee):
    """ Display details of the employee instance """

    print("Employee: {name}, Age: {age}, 
             profession: {job}".format(**employee))

def display_unsafe(employee):
    """ Display details of employee instance """

    print ("Employee: %s, Age: %d, 
              profession: %s" % (employee['name'],
                                             employee['age'],
                                             employee['job']))

>>> employee={'age': 25, 'job': 'software engineer', 'name': 'Jack'}
>>> display_safe(employee)
Employee: Jack, Age: 25, profession: software engineer
>>> display_unsafe(employee)
Employee: Jack, Age: 25, profession: software engineer
```

+   文件：在处理文件时，最好使用上下文管理器来确保在操作后关闭文件描述符。

例如，更倾向于这种方法：

```py
with open('somefile.txt','w') as fp:
 fp.write(buffer)
```

并避免以下情况：

```py
fp = open('somefile.txt','w')
fp.write(buffer)
```

这也将确保在文件读取或写入期间发生任何异常时关闭文件描述符，而不是在系统中保持打开文件句柄。

+   处理密码和敏感信息：在验证密码等敏感信息时，最好比较加密哈希而不是比较内存中的原始数据：

+   这样，即使攻击者能够通过利用诸如 shell 执行漏洞或输入数据评估中的弱点等漏洞从程序中窃取敏感数据，实际的敏感数据也会受到保护，不会立即泄露。以下是一个简单的方法：

```py
# compare_passwords.py - basic
import hashlib
import sqlite3
import getpass

def read_password(user):
    """ Read password from a password DB """
    # Using an sqlite db for demo purpose

    db = sqlite3.connect('passwd.db')
    cursor = db.cursor()
    try:
        passwd=cursor.execute("select password from passwds where user='%(user)s'" % locals()).fetchone()[0]
        return hashlib.sha1(passwd.encode('utf-8')).hexdigest()
    except TypeError:
        pass

def verify_password(user):
    """ Verify password for user """

    hash_pass = hashlib.sha1(getpass.getpass("Password: ").encode('utf-8')).hexdigest()
    print(hash_pass)
    if hash_pass==read_password(user):
        print('Password accepted')
    else:
        print('Wrong password, Try again')

if __name__ == "__main__":
    import sys
    verify_password(sys.argv[1])
```

更加密码学上正确的技术是使用内置盐和固定数量的哈希轮次的强密码哈希库。

以下是在 Python 中使用`passlib`库的示例：

```py
# crypto_password_compare.py
import sqlite3
import getpass
from passlib.hash import bcrypt

def read_passwords():
    """ Read passwords for all users from a password DB """
    # Using an sqlite db for demo purpose

    db = sqlite3.connect('passwd.db')
    cursor = db.cursor()
    hashes = {}

    for user,passwd in cursor.execute("select user,password from passwds"):
        hashes[user] = bcrypt.encrypt(passwd, rounds=8)

    return hashes

def verify_password(user):
    """ Verify password for user """

    passwds = read_passwords()
    # get the cipher
    cipher = passwds.get(user)
    if bcrypt.verify(getpass.getpass("Password: "), cipher):
        print('Password accepted')      
    else:
        print('Wrong password, Try again')

if __name__ == "__main__":
    import sys
    verify_password(sys.argv[1])
```

为了说明，已创建了一个包含两个用户及其密码的`passwd.db` sqlite 数据库，如下截图所示：

![安全策略- Python](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00483.jpeg)

以下是代码的实际操作：

### 注意

请注意，为了清晰起见，此处显示了键入的密码-实际程序中不会显示，因为它使用`getpass`库。

以下是代码的实际操作：

```py
$ python3 crytpo_password_compare.py jack
Password: test
Wrong password, Try again

$ python3 crytpo_password_compare.py jack
Password: reacher123
Password accepted
```

+   本地数据：尽量避免将敏感数据存储在函数的本地。函数中的任何输入验证或评估漏洞都可以被利用来访问本地堆栈，从而访问本地数据。始终将敏感数据加密或散列存储在单独的模块中。

以下是一个简单的示例：

```py
def func(input):
  secret='e4fe5775c1834cc8bd6abb712e79d058'
  verify_secret(input, secret)
  # Do other things
```

上述函数对于秘钥“secret”是不安全的，因为任何攻击者访问函数堆栈的能力都可以访问秘密。

这些秘密最好保存在一个单独的模块中。如果您正在使用秘密进行哈希和验证，以下代码比第一个更安全，因为它不会暴露“秘密”的原始值：

```py
 # This is the 'secret' encrypted via bcrypt with eight rounds.
 secret_hash=''$2a$08$Q/lrMAMe14vETxJC1kmxp./JtvF4vI7/b/VnddtUIbIzgCwA07Hty'
 def func(input):
  verify_secret(input, secret_hash)
```

+   竞争条件：Python 提供了一组优秀的线程原语。如果您的程序使用多个线程和共享资源，请遵循以下准则来同步对资源的访问，以避免竞争条件和死锁：

+   通过互斥锁（`threading.Lock`）保护可以同时写入的资源

+   通过信号量（`threading.BoundedSemaphore`）保护需要序列化的资源，以便对多个但有限的并发访问进行处理

+   使用条件对象唤醒同步等待可编程条件或函数的多个线程（`threading.Condition`）

+   避免循环一段时间后休眠，然后轮询条件或标准。而是使用条件或事件对象进行同步（`threading.Event`）

对于使用多个进程的程序，应该使用`multiprocessing`库提供的类似对应物来管理对资源的并发访问

+   **保持系统更新**：尽管这听起来陈词滥调，但及时了解系统中软件包的安全更新以及一般安全新闻，特别是对影响您应用程序的软件包，是保持系统和应用程序安全的简单方法。许多网站提供了许多开源项目（包括 Python 及其标准库模块）安全状态的持续更新。

这些报告通常被称为**常见漏洞和暴露**（**CVEs**）-诸如 Mitre（[`cve.mitre.org`](http://cve.mitre.org)）之类的网站提供不断更新的信息。

在这些网站上搜索 Python 显示了 213 个结果：

![安全策略- Python](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00484.jpeg)

在 Mitre CVE 列表上搜索'python'关键字的结果

架构师、运维工程师和网站管理员也可以调整系统软件包更新，并始终默认启用安全更新。对于远程服务器，建议每两到三个月升级到最新的安全补丁。

+   同样，Python **开放式 Web 应用安全项目**（**OWASP**）是一个免费的第三方项目，旨在创建一个比标准 Cpython 更能抵御安全威胁的 Python 强化版本。它是更大的 OWASP 计划的一部分。

+   Python OWASP 项目通过其网站和相关的 GitHub 项目提供了 Python 错误报告、工具和其他工件。主要网站是，大部分代码可从 GitHub 项目页面获取：[`github.com/ebranca/owasp-pysec/`](https://github.com/ebranca/owasp-pysec/)。![安全策略- Python](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00485.jpeg)

OWASP Python 安全项目主页

对于利益相关者来说，跟踪该项目、运行测试并阅读报告以了解 Python 安全方面的最新信息是一个好主意。

# 安全编码策略

我们即将结束对软件架构安全方面的讨论。现在是总结应该从安全架构师的角度向软件开发团队传授的策略的好时机。以下是总结其中前 10 个策略的表格。其中一些可能与我们之前的讨论重复，因为我们之前已经看到过它们。

| SL | 策略 | 它如何帮助 |
| --- | --- | --- |
| 1 | 验证输入 | 验证来自所有不受信任数据源的输入。适当的输入验证可以消除绝大多数软件漏洞。 |
| 2 | 保持简单 | 尽量简化程序设计。复杂的设计增加了在实施、配置和部署过程中出现安全错误的几率。 |
| 3 | 最小权限原则 | 每个进程应以完成工作所需的最少系统权限执行。例如，要从/tmp 读取数据，不需要 root 权限，但任何非特权用户都可以。 |
| 4 | 清理数据 | 清理从所有第三方系统（如数据库、命令行 shell、COTs 组件、第三方中间件等）读取和发送的数据。这减少了 SQL 注入、shell 利用或其他类似攻击的机会。 |
| 5 | 授权访问 | 通过需要特定身份验证的角色将应用程序的各个部分分开。不要在同一代码中混合不同部分的应用程序，这些部分需要不同级别的访问权限。采用适当的路由确保不会通过未受保护的路由暴露敏感数据。 |
| 6 | 进行有效的 QA | 良好的安全测试技术能够有效地识别和消除漏洞。模糊测试、渗透测试和源代码审计应作为程序的一部分进行。 |
| 7 | 分层实践防御 | 通过多层安全性减轻风险。例如，将安全编程技术与安全运行时配置相结合，将减少在运行时环境中暴露任何剩余代码漏洞的机会。 |
| 8 | 定义安全需求 | 在系统早期生命周期中识别和记录安全约束，并不断更新它们，确保后续功能符合这些要求。 |
| 9 | 建模威胁 | 使用威胁建模来预测软件将受到的威胁。 |
| 10 | 为安全策略进行架构和设计 | 创建并维护一个软件架构，强制执行一致的安全策略模式，覆盖系统及其子系统。 |

# 总结

在本章中，我们首先看了一个建立安全性的系统架构的细节。我们继续定义了安全编码，并研究了安全编码实践背后的哲学和原则。

然后，我们研究了软件系统中遇到的常见安全漏洞类型，如缓冲区溢出、输入验证问题、访问控制问题、加密弱点、信息泄漏、不安全的文件操作等。

然后，我们详细讨论了 Python 安全问题，并举了很多例子。我们详细研究了读取和评估输入、溢出错误和序列化问题。然后，我们继续研究了 Python Web 应用程序框架中的常见漏洞，选择了 Flask 作为候选对象。我们看到了如何利用 Web 应用程序模板的弱点，并执行 SSTI、XSS 和 DOS 等攻击。我们还看到了如何通过多个代码示例来减轻这些攻击。

然后，我们列出了 Python 中编写安全代码的具体技术。我们详细研究了在代码中管理密码和其他敏感数据的加密哈希，并讨论了一些正确的示例。还提到了保持自己了解安全新闻和项目的重要性，以及保持系统更新安全补丁的重要性。

最后，我们总结了安全编码策略的前十名，安全架构师可以向团队传授这些策略，以创建安全的代码和系统。

在下一章中，我们将看一下软件工程和设计中最有趣的方面之一，即设计模式。


# 第七章：Python 中的设计模式

设计模式通过重用成功的设计和架构简化软件构建。模式建立在软件工程师和架构师的集体经验之上。当遇到需要编写新代码的问题时，经验丰富的软件架构师倾向于利用可用的设计/架构模式丰富的生态系统。

当专家发现特定的设计或架构帮助他们一贯解决相关问题类时，模式会不断演变。他们倾向于越来越多地应用它，将解决方案的结构编码为模式。

Python 是一种支持动态类型和高级面向对象结构（如类和元类）、一级函数、协程、可调用对象等的语言，非常适合构建可重用的设计和架构模式。实际上，与 C++或 Java 等语言相反，你会经常发现在 Python 中实现特定设计模式的多种方法。而且，往往你会发现 Python 实现模式的方式比从 C++/Java 中复制标准实现更直观和有说明性。

本章的重点主要是后一方面——说明如何构建更符合 Python 风格的设计模式，而不是通常关于这个主题的书籍和文献所倾向于做的。它并不旨在成为设计模式的全面指南，尽管随着内容的展开，我们将涵盖大部分常见方面。

我们计划在本章中涵盖的主题如下：

+   设计模式元素

+   设计模式的类别

+   可插拔哈希算法

+   总结可插拔哈希算法

+   Python 中的模式 - 创造性

+   单例模式

+   波格模式

+   工厂模式

+   原型模式

+   生成器模式

+   Python 中的模式 - 结构性

+   适配器模式

+   外观模式

+   代理模式

+   Python 中的模式 - 行为

+   迭代器模式

+   观察者模式

+   状态模式

# 设计模式 - 元素

设计模式试图记录面向对象系统中解决问题或一类问题的重复设计的方面。

当我们检查设计模式时，我们发现几乎所有设计模式都具有以下元素：

+   名称：常用于描述模式的知名句柄或标题。为设计模式使用标准名称有助于沟通并增加我们的设计词汇量。

+   背景：问题出现的情况。背景可以是通用的，如“开发 Web 应用软件”，也可以是具体的，如“在发布者-订阅者系统的共享内存实现中实现资源更改通知”。

+   问题：描述了模式适用的实际问题。问题可以根据其力量来描述，如下所示：

+   要求：解决方案应满足的要求，例如，“发布者-订阅者模式实现必须支持 HTTP”。

+   约束：解决方案的约束，如果有的话，例如，“可扩展的点对点发布者模式在发布通知时不应交换超过三条消息”。

+   属性：解决方案的期望属性，例如，“解决方案应在 Windows 和 Linux 平台上同样有效”。

+   解决方案：显示了问题的实际解决方案。它描述了解决方案的结构和责任、静态关系以及组成解决方案的元素之间的运行时交互（协作）。解决方案还应讨论它解决的问题的“力量”，以及它不解决的问题。解决方案还应尝试提及其后果，即应用模式的结果和权衡。

### 注意

设计模式解决方案几乎从不解决导致它的问题的所有力量，而是留下一些力量供相关或替代实现使用。

# 设计模式的分类

设计模式可以根据所选择的标准以不同的方式进行分类。一个常见的分类方式是使用模式的目的作为标准。换句话说，我们问模式解决了什么类的问题。

这种分类给我们提供了三种模式类的清晰变体。它们如下：

+   **创建模式**：这些模式解决了与对象创建和初始化相关的问题。这些问题是在对象和类的问题解决生命周期的最早阶段出现的。看一下以下的例子：

+   **工厂模式**："如何确保我可以以可重复和可预测的方式创建相关的类实例？"这个问题由工厂模式类解决

+   **原型模式**："如何智能地实例化一个对象，然后通过复制这个对象创建数百个类似的对象？"这个问题由原型模式解决

+   **单例和相关模式**："如何确保我创建的类的任何实例只创建和初始化一次"或"如何确保类的任何实例共享相同的初始状态？"这些问题由单例和相关模式解决

+   **结构模式**：这些模式涉及对象的组合和组装成有意义的结构，为架构师和开发人员提供可重用的行为，其中“整体大于部分的总和”。自然地，它们出现在解决对象问题的下一步，一旦它们被创建。这些问题的例子如下：

+   **代理模式**："如何通过包装器控制对对象及其方法的访问，以及在顶部的行为？"

+   **组合模式**："如何使用相同的类同时表示部分和整体来表示由许多组件组成的对象，例如，一个 Widget 树？"

+   **行为模式**：这些模式解决了对象在运行时交互产生的问题，以及它们如何分配责任。自然地，它们出现在后期阶段，一旦类被创建，然后组合成更大的结构。以下是一些例子：

+   **在这种情况下使用中介者模式**："确保所有对象在运行时使用松散耦合来相互引用，以促进交互的运行时动态性"

+   **在这种情况下使用观察者模式**："一个对象希望在资源的状态发生变化时得到通知，但它不想一直轮询资源来找到这一点。系统中可能有许多这样的对象实例"

### 注意

创建模式、结构模式和行为模式的顺序隐含地嵌入了系统中对象的生命周期。对象首先被创建（创建模式），然后组合成有用的结构（结构模式），然后它们相互作用（行为模式）。

让我们现在把注意力转向本章的主题，即以 Python 独特的方式在 Python 中实现模式。我们将看一个例子来开始讨论这个问题。

## 可插拔的哈希算法

让我们看一下以下的问题。

你想从输入流（文件或网络套接字）中读取数据，并以分块的方式对内容进行哈希。你写了一些像这样的代码：

```py
# hash_stream.py
from hashlib import md5

def hash_stream(stream, chunk_size=4096):
    """ Hash a stream of data using md5 """

    shash = md5()

    for chunk in iter(lambda: stream.read(chunk_size), ''):
        shash.update(chunk)

    return shash.hexdigest()
```

### 注意

所有代码都是 Python3，除非另有明确说明。

```py
>>> import hash_stream
>>> hash_stream.hash_stream(open('hash_stream.py'))
'e51e8ddf511d64aeb460ef12a43ce480'

```

所以这样做是符合预期的。

现在假设你想要一个更可重用和多功能的实现，可以与多个哈希算法一起使用。你首先尝试修改以前的代码，但很快意识到这意味着重写大量的代码，这不是一个很聪明的做法：

```py
# hash_stream.py
from hashlib import sha1
from hashlib import md5

def hash_stream_sha1(stream, chunk_size=4096):
    """ Hash a stream of data using sha1 """

    shash = sha1()

    for chunk in iter(lambda: stream.read(chunk_size), ''):
        shash.update(chunk.encode('utf-8'))

    return shash.hexdigest()

def hash_stream_md5(stream, chunk_size=4096):
    """ Hash a stream of data using md5 """

    shash = md5()

    for chunk in iter(lambda: stream.read(chunk_size), ''):
        shash.update(chunk.encode('utf-8'))

    return shash.hexdigest()
```

```py
>>> import hash_stream
>>> hash_stream.hash_stream_md5(open('hash_stream.py'))
'e752a82db93e145fcb315277f3045f8d'
>>> hash_stream.hash_stream_sha1(open('hash_stream.py'))
'360e3bd56f788ee1a2d8c7eeb3e2a5a34cca1710'

```

您会意识到，通过使用类，您可以重复使用大量代码。作为一名经验丰富的程序员，经过几次迭代后，您可能会得到类似这样的东西：

```py
# hasher.py
class StreamHasher(object):
    """ Stream hasher class with configurable algorithm """

    def __init__(self, algorithm, chunk_size=4096):
        self.chunk_size = chunk_size
        self.hash = algorithm()

    def get_hash(self, stream):

        for chunk in iter(lambda: stream.read(self.chunk_size), ''):
            self.hash.update(chunk.encode('utf-8'))

        return self.hash.hexdigest()  
```

首先让我们尝试使用`md5`，如下所示：

```py
>>> import hasher
>>> from hashlib import md5
>>> md5h = hasher.StreamHasher(algorithm=md5)
>>> md5h.get_hash(open('hasher.py'))
'7d89cdc1f11ec62ec918e0c6e5ea550d'

```

现在使用`sha1`：

```py
>>> from hashlib import sha1
>>> shah_h = hasher.StreamHasher(algorithm=sha1)
>>> shah_h.get_hash(open('hasher.py'))
'1f0976e070b3320b60819c6aef5bd6b0486389dd'

```

正如现在显而易见的那样，您可以构建不同的哈希对象，每个对象都有一个特定的算法，将返回流的相应哈希摘要（在这种情况下是文件）。

现在让我们总结一下我们刚刚做的事情。

我们首先开发了一个名为`hash_stream`的函数，它接受一个流对象，并使用`md5`算法逐块对其进行哈希。然后我们开发了一个名为`StreamHasher`的类，允许我们一次配置一个算法，从而使代码更可重用。我们通过`get_hash`方法获得哈希摘要，该方法接受流对象作为参数。

现在让我们把注意力转向 Python 可以为我们做的更多事情。

我们的类对于不同的哈希算法是多功能的，并且肯定更可重用，但是有没有一种方法可以像调用函数一样调用它？那将非常棒，不是吗？

这是我们的`StreamHasher`类的一个轻微重新实现，它就是这样做的：

```py
# hasher.py
class StreamHasher(object):
    """ Stream hasher class with configurable algorithm """

    def __init__(self, algorithm, chunk_size=4096):
        self.chunk_size = chunk_size
        self.hash = algorithm()

    def __call__(self, stream):

        for chunk in iter(lambda: stream.read(self.chunk_size), ''):
            self.hash.update(chunk.encode('utf-8'))

        return self.hash.hexdigest() 
```

在上一段代码中我们做了什么？我们只是将`get_hash`函数重命名为`Get_Call`。让我们看看这会产生什么影响。

```py
>>> from hashlib import md5, sha1
>>> md5_h = hasher.StreamHasher(md5)
>>> md5_h(open('hasher.py'))
'ad5d5673a3c9a4f421240c4dbc139b22'
>>> sha_h = hasher.StreamHasher(sha1)
>>> sha_h(open('hasher.py'))
'd174e2fae1d6e1605146ca9d7ca6ee927a74d6f2'

```

我们能够调用类的实例，就像调用函数一样，只需将文件对象传递给它。

因此，我们的类不仅为我们提供了可重用和多功能的代码，而且还可以像函数一样运行。这是通过在 Python 中使我们的类成为可调用类型来实现的，只需实现魔术方法`__call__`。

### 注意

在 Python 中，**可调用对象**是指可以被调用的任何对象。换句话说，如果我们可以执行`x()`，那么`x`就是一个可调用对象，具体取决于`__call__`方法如何被覆盖，可以带参数也可以不带参数。函数是最简单和最熟悉的可调用对象。

在 Python 中，`foo(args)`是`foo.__call__(args)`的一种语法糖。

## 总结可插拔的哈希算法

那么前面的例子说明了什么？它说明了 Python 的强大之处，它以一种更奇特和强大的方式解决了传统上在其他编程语言中解决的现有问题，这是由于 Python 的强大之处以及它的工作方式——在这种情况下，通过覆盖特殊方法使任何对象可调用。

但是我们在这里实现了什么模式？我们在本章开头讨论过，只有解决了一类问题，才能成为模式。这个特定的例子中是否隐藏着一种模式？

是的，这是策略行为模式的一种实现：

*当我们需要从一个类中获得不同的行为，并且我们应该能够使用众多可用的行为或算法之一来配置一个类时，就会使用策略模式*。

在这种特殊情况下，我们需要一个支持使用不同算法执行相同操作的类——使用块从流中哈希数据，并返回摘要。该类接受算法作为参数，由于所有算法都支持相同的返回数据方法（`hexdigest`方法），我们能够以非常简单的方式实现该类。

让我们继续我们的旅程，找出使用 Python 编写的其他有趣模式，以及它独特解决问题的方式。在这个旅程中，我们将按照创建型、结构型和行为型模式的顺序进行。

### 注意

我们对接下来讨论的模式的方法非常务实。它可能不使用流行的**四人帮**（**G4**）模式所使用的正式语言——这是设计模式的最基本方法。我们的重点是展示 Python 在构建模式方面的能力，而不是追求形式主义的正确性。

# Python 中的模式-创建型

在本节中，我们将介绍一些常见的创建型模式。我们将从 Singleton 开始，然后按顺序进行原型、生成器和工厂。

## 单例模式

单例模式是设计模式中最著名和最容易理解的模式之一。它通常被定义为：

*单例是一个只有一个实例和明确定义的访问点的类*。

单例的要求可以总结如下：

+   一个类必须只有一个通过一个众所周知的访问点可访问的实例

+   类必须可以通过继承进行扩展，而不会破坏模式

+   Python 中最简单的单例实现如下所示。它是通过重写基本`object`类型的`__new__`方法完成的：

```py
# singleton.py
class Singleton(object):
    """ Singleton in Python """

    _instance = None

    def __new__(cls):
        if cls._instance == None:
            cls._instance = object.__new__(cls)
        return cls._instance
```

```py
>>> from singleton import Singleton
>>> s1 = Singleton()
>>> s2 = Singleton()
>>> s1==s2
True

```

+   由于我们将需要一段时间进行这个检查，让我们为此定义一个函数：

```py
def test_single(cls):
    """ Test if passed class is a singleton """
    return cls() == cls()
```

+   现在让我们看看我们的单例实现是否满足第二个要求。我们将定义一个简单的子类来测试这一点：

```py
class SingletonA(Singleton):
    pass

>>> test_single(SingletonA)
True
```

太棒了！所以我们简单的实现通过了测试。我们现在完成了吗？

好吧，正如我们之前讨论过的，Python 提供了许多实现模式的方法，因为它的动态性和灵活性。所以，让我们继续关注单例一段时间，看看我们是否能得到一些有启发性的例子，这些例子会让我们了解 Python 的强大之处：

```py
class MetaSingleton(type):
    """ A type for Singleton classes (overrides __call__) """    

    def __init__(cls, *args):
        print(cls,"__init__ method called with args", args)
        type.__init__(cls, *args)
        cls.instance = None

    def __call__(cls, *args, **kwargs):
        if not cls.instance:
            print(cls,"creating instance", args, kwargs)
            cls.instance = type.__call__(cls, *args, **kwargs)
        return cls.instance

class SingletonM(metaclass=MetaSingleton):
    pass
```

前面的实现将创建单例的逻辑移到了类的类型，即其元类。

我们首先创建了一个名为`MetaSingleton`的单例类型，通过扩展类型并在元类上重写`__init__`和`__call__`方法。然后我们声明`SingletonM`类，`SingletonM`，使用元类。

```py
>>> from singleton import *
<class 'singleton.SingletonM'> __init__ method called with args ('SingletonM', (), {'__module__': 'singleton', '__qualname__': 'SingletonM'})
>>> test_single(SingletonM)
<class 'singleton.SingletonM'> creating instance ()
True
```

这里是一个对单例新实现背后发生的事情的一瞥：

+   **初始化类变量**：我们可以在类级别（在类声明后）进行，就像我们在之前的实现中看到的那样，或者我们可以将其放在元类`__init__`方法中。这就是我们在这里为`_instance`类变量所做的，它将保存类的单个实例。

+   **覆盖类创建**：可以在类级别通过重写类的`__new__`方法进行，就像我们在之前的实现中看到的那样，或者可以在元类中通过重写其`__call__`方法来进行。这就是新实现所做的。

### 注意

当我们重写一个类的`__call__`方法时，它会影响它的实例，并且实例变得可调用。同样，当我们重写元类的`_call_`方法时，它会影响它的类，并修改类被调用的方式-换句话说，类创建其实例的方式。

让我们来看看元类方法相对于类方法的优缺点：

+   一个好处是我们可以创建任意数量的新顶级类，通过元类获得单例行为。使用默认实现，每个类都必须继承顶级类 Singleton 或其子类以获得单例行为。元类方法提供了更多关于类层次结构的灵活性。

+   然而，与类方法相比，元类方法可能被解释为创建略微晦涩和难以维护的代码。这是因为了解元类和元编程的 Python 程序员数量较少，而了解类的程序员数量较多。这可能是元类解决方案的一个缺点。

现在让我们打破常规，看看我们是否可以以稍有不同的方式解决单例问题。

### 单例-我们需要单例吗？

让我们用一个与原始略有不同的方式来解释单例的第一个要求：

*类必须提供一种让所有实例共享相同初始状态的方法。*

为了解释这一点，让我们简要地看一下单例模式实际上试图实现什么。

当单例确保只有一个实例时，它保证的是类在创建和初始化时提供一个单一状态。换句话说，单例实际上提供的是一种让类确保所有实例共享单一状态的方式。

换句话说，单例的第一个要求可以用稍微不同的形式来表述，这与第一种形式有相同的结果。

*一个类必须提供一种方法，使其所有实例共享相同的初始状态*

*确保在特定内存位置只有一个实际实例的技术只是实现这一点的一种方式。*

啊！到目前为止，我们一直在用不太灵活和多用途的编程语言的实现细节来表达模式，实际上。使用 Python 这样的语言，我们不需要死板地坚持这个原始定义。

让我们看看以下类：

```py
class Borg(object):
    """ I ain't a Singleton """

    __shared_state = {}
    def __init__(self):
        self.__dict__ = self.__shared_state
```

这种模式确保当你创建一个类时，你可以明确地用属于类的共享状态初始化它的所有实例（因为它是在类级别声明的）。

在单例中我们真正关心的是这种共享状态，所以`Borg`可以在不担心所有实例完全相同的情况下工作。

由于这是 Python，它通过在类上初始化一个共享状态字典，然后将实例的字典实例化为这个值来实现这一点，从而确保所有实例共享相同的状态。

以下是`Borg`实际操作的一个具体示例：

```py
class IBorg(Borg):
    """ I am a Borg """

    def __init__(self):
        Borg.__init__(self)
        self.state = 'init'

    def __str__(self):
        return self.state

>>> i1 = IBorg()
>>> i2 = IBorg()
>>> print(i1)
init
>>> print(i2)
init
>>> i1.state='running'
>>> print(i2)
running
>>> print(i1)
running
>>> i1==i2
False
```

所以使用`Borg`，我们成功创建了一个类，其实例共享相同的状态，即使实例实际上并不相同。状态的改变也传播到了实例；正如前面的例子所示，当我们改变`i1`中的状态值时，`i2`中的状态值也会改变。

动态值呢？我们知道它在单例中可以工作，因为它总是相同的对象，但是波尔格呢？

```py
>>> i1.x='test'
>>> i2.x
'test'
```

所以我们给实例`i1`附加了一个动态属性`x`，它也出现在实例`i2`中。很整洁！

所以让我们看看`Borg`是否比单例有任何好处：

+   在一个复杂的系统中，我们可能有多个类从根单例类继承，由于导入问题或竞争条件（例如，如果系统正在使用线程），要求一个单一实例可能很难实现。波尔格模式通过巧妙地摆脱了内存中单一实例的要求，解决了这些问题。

+   波尔格模式还允许在波尔格类和其所有子类之间简单共享状态。这对于单例来说并非如此，因为每个子类都创建自己的状态。我们将在接下来的示例中看到一个说明。

## 状态共享——波尔格与单例

波尔格模式总是从顶级类（波尔格）向下到所有子类共享相同的状态。这在单例中并非如此。让我们看一个例子。

在这个练习中，我们将创建我们原始单例类的两个子类，即`SingletonA`和`SingletonB`：

```py
>>> class SingletonA(Singleton): pass
... 
>>> class SingletonB(Singleton): pass
... 
```

让我们创建`SingletonA`的一个子类，即`SingletonA1`：

```py
>>> class SingletonA1(SingletonA): pass
...
```

现在让我们创建实例：

```py
>>> a = SingletonA()
>>> a1 = SingletonA1()
>>> b = SingletonB()
```

让我们给`a`附加一个值为 100 的动态属性`x`：

```py
>>> a.x = 100
>>> print(a.x)
100
```

让我们检查一下子类`SingletonA1`的实例`a1`上是否可用：

```py
>>> a1.x
100
```

好了！现在让我们检查它是否在实例`b`上可用：

```py
>>> b.x
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
AttributeError: 'SingletonB' object has no attribute 'x'
```

糟糕！看起来`SingletonA`和`SingletonB`并不共享相同的状态。这就是为什么附加到`SingletonA`实例的动态属性会出现在其子类的实例上，但不会出现在同级或同级子类`SingletonB`的实例上的原因——因为它是类层次结构中与顶级`Singleton`类不同的分支。

让我们看看波尔格是否能做得更好。

首先，让我们创建类和它们的实例：

```py
>>> class ABorg(Borg):pass
... 
>>> class BBorg(Borg):pass
... 
>>> class A1Borg(ABorg):pass
... 
>>> a = ABorg()
>>> a1 = A1Borg()
>>> b = BBorg()
```

现在让我们给`a`附加一个值为 100 的动态属性 x：

```py
>>> a.x = 100
>>> a.x
100
>>> a1.x
100
```

让我们检查同级类波尔格的实例是否也有它：

```py
>>> b.x
100
```

这证明了 Borg 模式在跨类和子类之间共享状态方面比 Singleton 模式更好，并且这样做不需要大量的麻烦或确保单个实例的开销。

现在让我们转向其他创建模式。

## 工厂模式

工厂模式解决了创建与另一个类相关的类的实例的问题，通常通过单个方法实现实例创建，通常在父工厂类上定义，并由子类（根据需要）覆盖。

工厂模式为类的客户（用户）提供了一个方便的方式，通过`Factory`类的特定方法传递参数，通常是通过创建类和子类的实例的单个入口点。

让我们看一个具体的例子：

```py
from abc import ABCMeta, abstractmethod

class Employee(metaclass=ABCMeta):
    """ An Employee class """

    def __init__(self, name, age, gender):
        self.name = name
        self.age = age
        self.gender = gender

    @abstractmethod
    def get_role(self):
        pass

    def __str__(self):
        return "{} - {}, {} years old {}".format(self.__class__.__name__,
                                                 self.name,
                                                 self.age,
                                                 self.gender)

class Engineer(Employee):
    """ An Engineer Employee """

    def get_role(self):
        return "engineering"

class Accountant(Employee):
    """ An Accountant Employee """

    def get_role(self):
        return "accountant" 

class Admin(Employee):
    """ An Admin Employee """

    def get_role(self):
        return "administration"
```

我们创建了一个通用的`Employee`类，具有一些属性和三个子类，分别是`Engineer`，`Accountant`和`Admin`。

由于它们都是相关类，因此`Factory`类对于抽象化这些类的实例创建非常有用。

这是我们的`EmployeeFactory`类：

```py
class EmployeeFactory(object):
    """ An Employee factory class """

    @classmethod
    def create(cls, name, *args):
        """ Factory method for creating an Employee instance """

        name = name.lower().strip()

        if name == 'engineer':
            return Engineer(*args)
        elif name == 'accountant':
            return Accountant(*args)
        elif name == 'admin':
            return Admin(*args)
```

该类提供了一个`create`工厂方法，接受一个`name`参数，该参数与类的名称匹配，并相应地创建实例。其余参数是实例化类实例所需的参数，这些参数不变地传递给其构造函数。

让我们看看我们的`Factory`类如何运作：

```py
>>> factory = EmployeeFactory()
>>> print(factory.create('engineer','Sam',25,'M'))
Engineer - Sam, 25 years old M
>>> print(factory.create('engineer','Tracy',28,'F'))
Engineer - Tracy, 28 years old F

>>> accountant = factory.create('accountant','Hema',39,'F')
>>> print(accountant)

Accountant - Hema, 39 years old F
>>> accountant.get_role()

accounting
>>> admin = factory.create('Admin','Supritha',32,'F')
>>> admin.get_role()
'administration'
```

以下是关于我们的`Factory`类的一些有趣的注释：

+   单个工厂类可以创建员工层次结构中任何类的实例。

+   在工厂模式中，通常使用一个与类族（类及其子类层次结构）相关联的`Factory`类是常规做法。例如，`Person`类可以使用`PersonFactory`，汽车类可以使用`AutomobileFactory`，依此类推。

+   在 Python 中，工厂方法通常被装饰为`classmethod`。这样可以直接通过类命名空间调用它。例如：

```py
    >>> print(EmployeeFactory.create('engineer','Vishal',24,'M'))
    Engineer - Vishal, 24 years old M
```

换句话说，这种模式实际上不需要`Factory`类的实例。

## 原型模式

原型设计模式允许程序员创建一个类的实例作为模板实例，然后通过复制或克隆该原型来创建新实例。

原型在以下情况下最有用：

+   当系统中实例化的类是动态的，即作为配置的一部分指定，或者在运行时可以发生变化时。

+   当实例只有少量初始状态的组合时。与跟踪状态并每次实例化一个实例相比，更方便的是创建与每个状态匹配的原型并进行克隆。

原型对象通常支持通过`clone`方法复制自身。

以下是 Python 中原型的简单实现：

```py
import copy

class Prototype(object):
    """ A prototype base class """

    def clone(self):
        """ Return a clone of self """
        return copy.deepcopy(self)
```

`clone`方法使用`copy`模块实现，该模块深度复制对象并返回克隆。

让我们看看这是如何工作的。为此，我们需要创建一个有意义的子类：

```py
class Register(Prototype):
    """ A student Register class  """

    def __init__(self, names=[]):
        self.names = names

>>> r1=Register(names=['amy','stu','jack'])
>>> r2=r1.clone()
>>> print(r1)
<prototype.Register object at 0x7f42894e0128>
>>> print(r2)
<prototype.Register object at 0x7f428b7b89b0>

>>> r2.__class__
<class 'prototype.Register'>
```

### 原型-深复制与浅复制

现在让我们更深入地了解我们的原型类的实现细节。

您可能注意到我们使用`copy`模块的`deepcopy`方法来实现对象克隆。该模块还有一个`copy`方法，用于实现浅复制。

如果我们实现浅复制，您会发现所有对象都是通过引用复制的。对于不可变对象（如字符串或元组），这是可以接受的。

然而，对于像列表或字典这样的可变对象来说，这是一个问题，因为实例的状态是共享的，而不是完全由实例拥有的，对一个实例中可变对象的修改也会同时修改克隆实例中的相同对象！

让我们看一个例子。我们将使用我们的原型类的修改实现，该实现使用浅复制来演示这一点：

```py
class SPrototype(object):
    """ A prototype base class using shallow copy """

    def clone(self):
        """ Return a clone of self """
        return copy.copy(self)
```

`SRegister`类继承自新的原型类：

```py
class SRegister(SPrototype):
    """ Sub-class of SPrototype """

    def __init__(self, names=[]):
        self.names = names

>>> r1=SRegister(names=['amy','stu','jack'])
>>> r2=r1.clone()
```

让我们给`r1`实例的名称注册一个名称：

```py
>>> r1.names.append('bob')
```

现在让我们检查`r2.names`：

```py
>>> r2.names
['amy', 'stu', 'jack', 'bob']
```

哎呀！这不是我们想要的，但由于浅拷贝，`r1`和`r2`最终共享相同的`names`列表，因为只复制了引用，而不是整个对象。可以通过简单的检查来验证：

```py
>>> r1.names is r2.names
True
```

另一方面，深拷贝会对克隆的对象中包含的所有对象递归调用`copy`，因此没有任何共享，但每个克隆最终都会有自己的所有引用对象的副本。

### 使用元类构建原型

我们已经看到如何使用类构建原型模式。由于我们已经在单例模式示例中看到了 Python 中的一些元编程，因此有助于找出我们是否可以在原型中做同样的事情。

我们需要做的是将`clone`方法附加到所有原型类上。像这样动态地将方法附加到类中可以通过元类的`__init__`方法来完成。

这提供了使用元类的原型的简单实现：

```py
import copy

class MetaPrototype(type):

    """ A metaclass for Prototypes """

    def __init__(cls, *args):
        type.__init__(cls, *args)
        cls.clone = lambda self: copy.deepcopy(self) 

class PrototypeM(metaclass=MetaPrototype):
    pass
```

`PrototypeM`类现在实现了原型模式。让我们通过使用一个子类来进行说明：

```py
class ItemCollection(PrototypeM):
    """ An item collection class """

    def __init__(self, items=[]):
        self.items = items
```

首先我们将创建一个`ItemCollection`对象：

```py
>>> i1=ItemCollection(items=['apples','grapes','oranges'])
>>> i1
<prototype.ItemCollection object at 0x7fd4ba6d3da0>
```

现在我们将克隆它如下：

```py
>>> i2 = i1.clone()
```

克隆显然是一个不同的对象：

```py
>>> i2
<prototype.ItemCollection object at 0x7fd4ba6aceb8>
```

它有自己的属性副本：

```py
>>> i2.items is i1.items
False
```

### 使用元类组合模式

通过使用元类的强大功能，可以创建有趣和定制的模式。以下示例说明了一种既是单例又是原型的类型：

```py
class MetaSingletonPrototype(type):
    """ A metaclass for Singleton & Prototype patterns """

    def __init__(cls, *args):
        print(cls,"__init__ method called with args", args)
        type.__init__(cls, *args)
        cls.instance = None
        cls.clone = lambda self: copy.deepcopy(cls.instance)

    def __call__(cls, *args, **kwargs):
        if not cls.instance:
            print(cls,"creating prototypical instance", args, kwargs)
            cls.instance = type.__call__(cls,*args, **kwargs)
        return cls.instance
```

使用这个元类作为其类型的任何类都会显示单例和原型行为。

这可能看起来有点奇怪，因为一个单例只允许一个实例，而原型允许克隆来派生多个实例，但是如果我们从它们的 API 来考虑模式，那么它开始感觉更自然一些：

+   使用构造函数调用类总是会返回相同的实例 - 它的行为就像单例模式。

+   在类的实例上调用`clone`总是会返回克隆的实例。实例总是使用单例实例作为源进行克隆 - 它的行为就像原型模式。

在这里，我们修改了我们的`PrototypeM`类，现在使用新的元类：

```py
class PrototypeM(metaclass=MetaSingletonPrototype):
    pass
```

由于`ItemCollection`继续子类化`PrototypeM`，它会自动获得新的行为。

看一下以下代码：

```py
>>> i1=ItemCollection(items=['apples','grapes','oranges'])
<class 'prototype.ItemCollection'> creating prototypical instance () {'items': ['apples'
, 'grapes', 'oranges']}
>>> i1
<prototype.ItemCollection object at 0x7fbfc033b048>
>>> i2=i1.clone()
```

`clone`方法按预期工作，并产生一个克隆：

```py
>>> i2
<prototype.ItemCollection object at 0x7fbfc033b080>
>>> i2.items is i1.items
False
```

然而，通过构造函数构建实例总是只返回单例（原型）实例，因为它调用了单例 API：

```py
>>> i3=ItemCollection(items=['apples','grapes','mangoes'])
>>> i3 is i1
True
```

元类允许对类的创建进行强大的定制。在这个具体的例子中，我们通过元类将单例和原型模式的行为组合到一个类中。Python 使用元类的强大功能使程序员能够超越传统模式，提出这样的创造性技术。

### 原型工厂

原型类可以通过一个辅助的**原型工厂**或**注册类**进行增强，它可以提供用于创建配置的产品系列或产品组的原型实例的工厂函数。将其视为我们以前工厂模式的变体。

这是这个类的代码。看到我们从`Borg`继承它以自动共享状态从层次结构的顶部：

```py
class PrototypeFactory(Borg):
    """ A Prototype factory/registry class """

    def __init__(self):
        """ Initializer """

        self._registry = {}

    def register(self, instance):
        """ Register a given instance """

        self._registry[instance.__class__] = instance

    def clone(self, klass):
        """  Return cloned instance of given class """

        instance = self._registry.get(klass)
        if instance == None:
            print('Error:',klass,'not registered')
        else:
            return instance.clone()
```

让我们创建一些原型的子类，我们可以在工厂上注册它们的实例：

```py
class Name(SPrototype):
    """ A class representing a person's name """

    def __init__(self, first, second):
        self.first = first
        self.second = second

    def __str__(self):
        return ' '.join((self.first, self.second))

class Animal(SPrototype):
    """ A class representing an animal """

    def __init__(self, name, type='Wild'):
        self.name = name
        self.type = type

    def __str__(self):
        return ' '.join((str(self.type), self.name))
```

我们有两个类 - 一个是`Name`类，另一个是动物类，两者都继承自`SPrototype`。

首先创建一个名称和动物对象：

```py
>>> name = Name('Bill', 'Bryson')
>>> animal = Animal('Elephant')
>>> print(name)
Bill Bryson
>>> print(animal)
Wild Elephant
```

现在，让我们创建一个原型工厂的实例。

```py
>>> factory = PrototypeFactory()
```

现在让我们在工厂上注册这两个实例：

```py
>>> factory.register(animal)
>>> factory.register(name)
```

现在工厂已经准备好从配置的实例中克隆任意数量的实例：

```py
>>> factory.clone(Name)
<prototype.Name object at 0x7ffb552f9c50>

>> factory.clone(Animal)
<prototype.Animal object at 0x7ffb55321a58>
```

工厂如果尝试克隆未注册实例的类，会合理地抱怨：

```py
>>> class C(object): pass
... 
>>> factory.clone(C)
Error: <class '__main__.C'> not registered
```

### 注意

这里显示的工厂类可以通过检查已注册类上的`clone`方法的存在来增强，以确保任何注册的类都遵守原型类的 API。这留给读者作为练习。

如果读者还没有注意到，讨论我们选择的这个特定示例的一些方面是很有启发性的：

+   `PrototypeFactory`类是一个工厂类，因此通常是一个单例。在这种情况下，我们将其制作成了一个 Borg，因为我们已经看到`Borgs`在类层次结构之间的状态共享方面做得更好。

+   `Name`类和`Animal`类继承自`SPrototype`，因为它们的属性是不可变的整数和字符串，所以在这里浅复制就可以了。这与我们的第一个原型子类不同。

+   原型保留了原型实例中的类创建签名，即`clone`方法。这使得程序员很容易，因为他/她不必担心类创建签名——`__new__`的顺序和类型，因此也不必调用`__init__`方法——只需在现有实例上调用`clone`即可。

## 建造者模式

建造者模式将对象的构建与其表示（组装）分离，以便可以使用相同的构建过程来构建不同的表示。

换句话说，使用建造者模式，可以方便地创建同一类的不同类型或代表性实例，每个实例使用略有不同的构建或组装过程。

形式上，建造者模式使用一个`Director`类，该类指导`Builder`对象构建目标类的实例。不同类型（类）的构建者有助于构建同一类的略有不同的变体。

让我们看一个例子：

```py
class Room(object):
    """ A class representing a Room in a house """

    def __init__(self, nwindows=2, doors=1, direction='S'):
        self.nwindows = nwindows
        self.doors = doors
        self.direction = direction

    def __str__(self):
        return "Room <facing:%s, windows=#%d>" % (self.direction,
                                                  self.nwindows)
class Porch(object):
    """ A class representing a Porch in a house """

    def __init__(self, ndoors=2, direction='W'):
        self.ndoors = ndoors
        self.direction = direction

    def __str__(self):
        return "Porch <facing:%s, doors=#%d>" % (self.direction,
                                                 self.ndoors)   

class LegoHouse(object):
    """ A lego house class """

    def __init__(self, nrooms=0, nwindows=0,nporches=0):
        # windows per room
        self.nwindows = nwindows
        self.nporches = nporches
        self.nrooms = nrooms
        self.rooms = []
        self.porches = []

    def __str__(self):
        msg="LegoHouse<rooms=#%d, porches=#%d>" % (self.nrooms,
                                                   self.nporches)

        for i in self.rooms:
            msg += str(i)

        for i in self.porches:
            msg += str(i)

        return msg

    def add_room(self,room):
        """ Add a room to the house """

        self.rooms.append(room)

    def add_porch(self,porch):
        """ Add a porch to the house """

        self.porches.append(porch)
```

我们的示例显示了三个类，它们分别是：

+   `Room`和`Porch`类分别表示房子的房间和门廊——房间有窗户和门，门廊有门

+   `LegoHouse`类代表了一个玩具示例，用于实际房子（我们想象一个孩子用乐高积木建造房子，有房间和门廊。）——乐高房子将包括任意数量的房间和门廊。

让我们尝试创建一个简单的`LegoHouse`实例，其中有一个房间和一个门廊，每个都有默认配置：

```py
>>> house = LegoHouse(nrooms=1,nporches=1)
>>> print(house)
LegoHouse<rooms=#1, porches=#1>
```

我们完成了吗？没有！请注意，我们的`LegoHouse`是一个在其构造函数中并没有完全构建自身的类。房间和门廊实际上还没有建好，只是它们的计数器被初始化了。

因此，我们需要分别建造房间和门廊，并将它们添加到房子中。让我们来做：

```py
>>> room = Room(nwindows=1)
>>> house.add_room(room)
>>> porch = Porch()
>>> house.add_porch(porch)
>>> print(house)
LegoHouse<rooms=#1, porches=#1>
Room <facing:S, windows=#1>
Porch <facing:W, doors=#1>
```

现在你看到我们的房子已经建好了。打印它不仅显示了房间和门廊的数量，还显示了有关它们的详细信息。一切顺利！

现在，想象一下你需要建造 100 个这样不同配置的房子实例，每个实例的房间和门廊配置都不同，而且房间本身的窗户数量和方向也经常不同！

（也许你正在制作一个移动游戏，其中使用乐高房子，可爱的小角色像巨魔或小黄人住在里面，并做有趣的事情，无论是什么。）

从示例中很明显，编写像最后一个示例那样的代码将无法解决问题。

这就是建造者模式可以帮助你的地方。让我们从一个简单的`LegoHouse`构建者开始。

```py
class LegoHouseBuilder(object):
    """ Lego house builder class """

    def __init__(self, *args, **kwargs):
        self.house = LegoHouse(*args, **kwargs)

    def build(self):
        """ Build a lego house instance and return it """

        self.build_rooms()
        self.build_porches()
        return self.house

    def build_rooms(self):
        """ Method to build rooms """

        for i in range(self.house.nrooms):
            room = Room(self.house.nwindows)
            self.house.add_room(room)

    def build_porches(self):
        """ Method to build porches """     

        for i in range(self.house.nporches):
            porch = Porch(1)
            self.house.add_porch(porch)
```

这个类的主要方面如下：

+   你可以使用目标类配置来配置构建者类——在这种情况下是房间和门廊的数量

+   它提供了一个`build`方法，根据指定的配置构建和组装（建造）房子的组件，即`Rooms`和`Porches`

+   `build`方法返回构建和组装好的房子

现在用两行代码构建不同类型的乐高房子，每种类型的房子都有不同的房间和门廊设计：

```py
>>> builder=LegoHouseBuilder(nrooms=2,nporches=1,nwindows=1)
>>> print(builder.build())
LegoHouse<rooms=#2, porches=#1>
Room <facing:S, windows=#1>
Room <facing:S, windows=#1>
Porch <facing:W, doors=#1>
```

我们现在将建造一个类似的房子，但是房间里有两扇窗户：

```py
>>> builder=LegoHouseBuilder(nrooms=2,nporches=1,nwindows=2)
>>> print(builder.build())
LegoHouse<rooms=#2, porches=#1>
Room <facing:S, windows=#2>
Room <facing:S, windows=#2>
Porch <facing:W, doors=#1>
```

假设您发现自己继续使用这个配置构建了许多乐高房子。您可以将其封装在构建者的子类中，这样前面的代码就不会重复很多次：

```py
class SmallLegoHouseBuilder(LegoHouseBuilder):
""" Builder sub-class building small lego house with 1 room and 1porch and rooms having 2 windows """

    def __init__(self):
        self.house = LegoHouse(nrooms=2, nporches=1, nwindows=2)        
```

现在，房屋配置被*固定*到新的构建者类中，构建一个就像这样简单：

```py
>>> small_house=SmallLegoHouseBuilder().build()
>>> print(small_house)
LegoHouse<rooms=#2, porches=#1>
Room <facing:S, windows=#2>
Room <facing:S, windows=#2>
Porch <facing:W, doors=#1>
```

您也可以构建许多这样的实例（比如`100`，`50`用于巨魔，`50`用于小黄人）：

```py
>>> houses=list(map(lambda x: SmallLegoHouseBuilder().build(), range(100)))
>>> print(houses[0])
LegoHouse<rooms=#2, porches=#1>
Room <facing:S, windows=#2>
Room <facing:S, windows=#2>
Porch <facing:W, doors=#1>

>>> len(houses)
100
```

人们还可以创建更奇特的构建者类，做一些非常特定的事情。例如，这里有一个构建者类，它创建的房屋的房间和门廊总是朝向北方：

```py
class NorthFacingHouseBuilder(LegoHouseBuilder):
    """ Builder building all rooms and porches facing North """

    def build_rooms(self):

        for i in range(self.house.nrooms):
            room = Room(self.house.nwindows, direction='N')
            self.house.add_room(room)

    def build_porches(self):

        for i in range(self.house.nporches):
            porch = Porch(1, direction='N')
            self.house.add_porch(porch)

>>> print(NorthFacingHouseBuilder(nrooms=2, nporches=1, nwindows=1).build())
LegoHouse<rooms=#2, porches=#1>
Room <facing:N, windows=#1>
Room <facing:N, windows=#1>
Porch <facing:N, doors=#1>
```

利用 Python 的多重继承功能，可以将任何这样的构建者组合成新的有趣的子类。例如，这里有一个构建者，它产生朝北的小房子：

```py
class NorthFacingSmallHouseBuilder(NorthFacingHouseBuilder, SmallLegoHouseBuilder):
    pass
```

正如预期的那样，它总是重复产生朝北的小房子，有 2 个有窗的房间。也许不是很有趣，但确实非常可靠：

```py
>>> print(NorthFacingSmallHouseBuilder().build())
LegoHouse<rooms=#2, porches=#1>
Room <facing:N, windows=#2>
Room <facing:N, windows=#2>
Porch <facing:N, doors=#1>
```

在我们结束对创建模式的讨论之前，让我们总结一些有趣的方面，以及它们之间的相互作用，如下所示：

+   **构建者和工厂**：构建者模式将类的实例的组装过程与其创建分离。另一方面，工厂关注使用统一接口创建属于同一层次结构的不同子类的实例。构建者还将构建的实例作为最后一步返回，而工厂则立即返回实例，因为没有单独的构建步骤。

+   **构建者和原型**：构建者可以在内部使用原型来创建其实例。然后可以从该实例克隆同一构建者的更多实例。例如，建立一个使用我们的原型元类之一始终克隆原型实例的构建者类是很有启发性的。

+   **原型和工厂**：原型工厂可以在内部使用工厂模式来构建所讨论类的初始实例。

+   **工厂和单例**：工厂类通常是传统编程语言中的单例。另一个选项是将其方法设置为类或静态方法，因此无需创建工厂本身的实例。在我们的示例中，我们将其设置为 Borg。

我们现在将转移到下一个模式类，即结构模式。

# Python 中的模式-结构

结构模式关注于组合类或对象以形成更大的结构的复杂性，这些结构不仅仅是它们各自部分的总和。

结构模式通过这两种不同的方式来实现这一点：

+   通过使用类继承将类组合成一个。这是一种静态的方法。

+   通过在运行时使用对象组合来实现组合功能。这种方法更加动态和灵活。

由于支持多重继承，Python 可以很好地实现这两种功能。作为一种具有动态属性并使用魔术方法的语言，Python 也可以很好地进行对象组合和由此产生的方法包装。因此，使用 Python，程序员确实处于一个很好的位置，可以实现结构模式。

在本节中，我们将讨论以下结构模式：适配器，外观和代理。

## 适配器模式

顾名思义，适配器模式将特定接口的现有实现包装或适配到客户端期望的另一个接口中。适配器也被称为**包装器**。

在编程时，您经常会将对象适配到您想要的接口或类型中，而往往并不自知。

例如：

看看这个包含两个水果实例及其数量的列表：

```py
>>> fruits=[('apples',2), ('grapes',40)]
```

假设您想快速找到水果的数量，给定水果名称。列表不允许您将水果用作键，这是更适合操作的接口。

你该怎么办？嗯，你只需将列表转换为字典：

```py
>>> fruits_d=dict(fruits)
>>> fruits_d['apples']
2
```

看！你得到了一个更方便的对象形式，适应了你的编程需求。这是一种数据或对象适应。

程序员在他们的代码中几乎不断地进行数据或对象适应，而并没有意识到。代码或数据的适应比你想象的更常见。

让我们考虑一个多边形类，表示任何形状的正规或不规则多边形：

```py
class Polygon(object):
    """ A polygon class """

    def __init__(self, *sides):
        """ Initializer - accepts length of sides """
        self.sides = sides

    def perimeter(self):
        """ Return perimeter """

        return sum(self.sides)

    def is_valid(self):
        """ Is this a valid polygon """

        # Do some complex stuff - not implemented in base class
        raise NotImplementedError

    def is_regular(self):
        """ Is a regular polygon ? """

        # True: if all sides are equal
        side = self.sides[0]
        return all([x==side for x in self.sides[1:]])

    def area(self):
        """ Calculate and return area """

        # Not implemented in base class
        raise NotImplementedError
```

前面的类描述了几何学中的一个通用的封闭多边形图形。

### 注意

我们已经实现了一些基本方法，如`perimeter`和`is_regular`，后者返回多边形是否是正规的，比如六边形或五边形。

假设我们想要为一些常见的几何形状（如三角形或矩形）实现特定的类。当然，我们可以从头开始实现这些。但是，由于有一个多边形类可用，我们可以尝试重用它，并根据我们的需求进行适应。

假设`Triangle`类需要以下方法：

+   `is_equilateral`：返回三角形是否是等边三角形

+   `is_isosceles`：返回三角形是否是等腰三角形

+   `is_valid`：实现了三角形的`is_valid`方法

+   `area`：实现了三角形的面积方法

同样，`Rectangle`类需要以下方法：

+   `is_square`：返回矩形是否为正方形

+   `is_valid`：实现了矩形的`is_valid`方法

+   `area`：实现了矩形的面积方法

以下是适配器模式的代码，重用`Polygon`类用于`Triangle`和`Rectangle`类。

以下是`Triangle`类的代码：

```py
import itertools 

class InvalidPolygonError(Exception):
    pass

class Triangle(Polygon):
    """ Triangle class from Polygon using class adapter """

    def is_equilateral(self):
        """ Is this an equilateral triangle ? """

        if self.is_valid():
            return super(Triangle, self).is_regular()

    def is_isosceles(self):
        """ Is the triangle isosceles """

        if self.is_valid():
            # Check if any 2 sides are equal
            for a,b in itertools.combinations(self.sides, 2):
                if a == b:
                    return True
        return False

    def area(self):
        """ Calculate area """

        # Using Heron's formula
        p = self.perimeter()/2.0
        total = p
        for side in self.sides:
            total *= abs(p-side)

        return pow(total, 0.5)

    def is_valid(self):
        """ Is the triangle valid """

        # Sum of 2 sides should be > 3rd side
        perimeter = self.perimeter()
        for side in self.sides:
            sum_two = perimeter - side
            if sum_two <= side:
                raise InvalidPolygonError(str(self.__class__) + "is invalid!")

        return True
```

看一下以下的`Rectangle`类：

```py
class Rectangle(Polygon):
    """ Rectangle class from Polygon using class adapter """

    def is_square(self):
        """ Return if I am a square """

        if self.is_valid():
            # Defaults to is_regular
            return self.is_regular()

    def is_valid(self):
        """ Is the rectangle valid """

        # Should have 4 sides
        if len(self.sides) != 4:
            return False

        # Opposite sides should be same
        for a,b in [(0,2),(1,3)]:
            if self.sides[a] != self.sides[b]:
                return False

        return True

    def area(self):
        """ Return area of rectangle """

        # Length x breadth
        if self.is_valid():
            return self.sides[0]*self.sides[1]
```

现在让我们看看这些类的实际应用。

让我们为第一次测试创建一个等边三角形：

```py
>>> t1 = Triangle(20,20,20)
>>> t1.is_valid()
True
```

等边三角形也是等腰三角形：

```py
>>> t1.is_equilateral()
True
>>> t1.is_isosceles()
True
```

让我们计算面积：

```py
>>> t1.area()
173.20508075688772
```

让我们尝试一个无效的三角形：

```py
>>> t2 = Triangle(10, 20, 30)
>>> t2.is_valid()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/home/anand/Documents/ArchitectureBook/code/chap7/adapter.py", line 75, in is_valid
    raise InvalidPolygonError(str(self.__class__) + "is invalid!")
adapter.InvalidPolygonError: <class 'adapter.Triangle'>is invalid!
```

### 注意

尺寸显示这是一条直线，而不是一个三角形。`is_valid`方法没有在基类中实现，因此子类需要重写它以提供适当的实现。在这种情况下，如果三角形无效，我们会引发一个异常。

以下是`Rectangle`类的示例：

```py
>>> r1 = Rectangle(10,20,10,20)
>>> r1.is_valid()
True
>>> r1.area()
200
>>> r1.is_square()
False
>>> r1.perimeter()
60
```

让我们创建一个正方形：

```py
>>> r2 = Rectangle(10,10,10,10)
>>> r2.is_square()
True
```

这里显示的`Rectangle`/`Triangle`类是`类适配器`的示例。这是因为它们继承了它们想要适应的类，并提供了客户端期望的方法，通常将计算委托给基类的方法。这在`Triangle`和`Rectangle`类的`is_equilateral`和`is_square`方法中是明显的。

让我们看一下相同类的另一种实现方式——这次是通过对象组合，换句话说，`对象适配器`：

```py
import itertools

class Triangle (object) :
    """ Triangle class from Polygon using class adapter """

    def __init__(self, *sides):
        # Compose a polygon
        self.polygon = Polygon(*sides)

    def perimeter(self):
        return self.polygon.perimeter()

    def is_valid(f):
        """ Is the triangle valid """

        def inner(self, *args):
            # Sum of 2 sides should be > 3rd side
            perimeter = self.polygon.perimeter()
            sides = self.polygon.sides

            for side in sides:
                sum_two = perimeter - side
                if sum_two <= side:
                    raise InvalidPolygonError(str(self.__class__) + "is invalid!")

            result = f(self, *args)
            return result

        return inner

    @is_valid
    def is_equilateral(self):
        """ Is this equilateral triangle ? """

        return self.polygon.is_regular()

    @is_valid
    def is_isosceles(self):
        """ Is the triangle isoscles """

        # Check if any 2 sides are equal
        for a,b in itertools.combinations(self.polygon.sides, 2):
            if a == b:
                return True
        return False

    def area(self):
        """ Calculate area """

        # Using Heron's formula
        p = self.polygon.perimeter()/2.0
        total = p
        for side in self.polygon.sides:
            total *= abs(p-side)

        return pow(total, 0.5)
```

这个类与另一个类类似，尽管内部细节是通过对象组合而不是类继承实现的：

```py
>>> t1=Triangle(2,2,2)
>>> t1.is_equilateral()
True
>>> t2 = Triangle(4,4,5)
>>> t2.is_equilateral()
False
>>> t2.is_isosceles()
True
```

这个实现与类适配器的主要区别如下：

+   对象适配器类不继承我们想要适应的类。相反，它组合了该类的一个实例。

+   任何包装方法都会转发到组合实例。例如，`perimeter`方法。

+   在这个实现中，封装实例的所有属性访问都必须明确指定。没有什么是免费的（因为我们没有继承该类）。 （例如，检查我们如何访问封闭的`polygon`实例的`sides`属性的方式。）。

### 注意

观察我们如何将以前的`is_valid`方法转换为此实现中的装饰器。这是因为许多方法首先对`is_valid`进行检查，然后执行它们的操作，因此它是装饰器的理想候选者。这也有助于将此实现重写为更方便的形式，下面将讨论这一点。

对象适配器实现的一个问题是，对封闭的适配实例的任何属性引用都必须显式进行。例如，如果我们在这里忘记为`Triangle`类实现`perimeter`方法，那么根本就没有方法可供调用，因为我们没有从`Adapter`类继承。

以下是另一种实现，它利用了 Python 的一个魔术方法`__getattr__`的功能，以简化这个过程。我们在`Rectangle`类上演示这个实现：

```py
class Rectangle(object):
    """ Rectangle class from Polygon using object adapter """

    method_mapper = {'is_square': 'is_regular'}

    def __init__(self, *sides):
        # Compose a polygon
        self.polygon = Polygon(*sides)

    def is_valid(f):
        def inner(self, *args):
            """ Is the rectangle valid """

            sides = self.sides
            # Should have 4 sides
            if len(sides) != 4:
                return False

            # Opposite sides should be same
            for a,b in [(0,2),(1,3)]:
                if sides[a] != sides[b]:
                    return False

            result = f(self, *args)
            return result

        return inner

    def __getattr__(self, name):
        """ Overloaded __getattr__ to forward methods to wrapped instance """

        if name in self.method_mapper:
            # Wrapped name
            w_name = self.method_mapper[name]
            print('Forwarding to method',w_name)
            # Map the method to correct one on the instance
            return getattr(self.polygon, w_name)
        else:
            # Assume method is the same
            return getattr(self.polygon, name)

    @is_valid
    def area(self):
        """ Return area of rectangle """

        # Length x breadth
        sides = self.sides      
        return sides[0]*sides[1]
```

让我们看看使用这个类的例子：

```py
>>> r1=Rectangle(10,20,10,20)
>>> r1.perimeter()
60
>>> r1.is_square()
Forwarding to method is_regular
False
```

您可以看到，我们能够在`Rectangle`实例上调用`is_perimeter`方法，即使在类上实际上并没有定义这样的方法。同样，`is_square`似乎也能奇迹般地工作。这里发生了什么？

如果 Python 在通常的方式下找不到对象的属性，它会调用魔术方法`__getattr__`。它接受一个名称，因此为类提供了一个挂钩，以实现通过将方法查找路由到其他对象的方式。

在这种情况下，`__getattr__`方法执行以下操作：

+   在`method_mapper`字典中检查属性名称。这是一个我们在类上创建的字典，将我们想要在类上调用的方法名称（作为键）映射到包装实例上的实际方法名称（作为值）。如果找到条目，则返回它。

+   如果在`method_mapper`字典中找不到条目，则将条目原样传递给包装实例，以便按相同的名称查找。

+   我们在两种情况下都使用`getattr`来查找并从包装实例返回属性。

+   属性可以是任何东西——数据属性或方法。例如，看看我们如何在方法`area`和`is_valid`装饰器中将包装的`polygon`实例的`sides`属性称为属于`Rectangle`类的属性。

+   如果在包装实例上不存在属性，则会引发`AttributeError`：

```py
    >>> r1.convert_to_parallelogram(angle=30)
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
     File "adapter_o.py", line 133, in __getattr__
        return getattr(self.polygon, name)
    AttributeError: 'Polygon' object has no attribute 'convert_to_parallelogram'
```

使用这种技术实现的对象适配器更加灵活，比常规对象适配器需要编写每个方法并将其转发到包装实例的代码量要少。

## 外观模式

外观是一种结构模式，为子系统中的多个接口提供统一接口。外观模式在系统由多个子系统组成，每个子系统都有自己的接口，但需要捕获一些高级功能作为通用顶层接口提供给客户端时非常有用。

一个日常生活中的经典例子是汽车，它是一个外观。

例如，汽车由发动机、动力传动系统、轴和车轮组件、电子设备、转向系统、制动系统和其他组件组成。

然而，通常情况下，你并不需要担心你的汽车刹车是盘式刹车，还是悬架是螺旋弹簧或麦弗逊减震器，对吧？

这是因为汽车制造商为您提供了一个外观，以操作和维护汽车，从而减少了复杂性，并为您提供了更简单的子系统，这些子系统本身很容易操作，例如：

+   启动汽车的点火系统

+   用于操纵它的转向系统

+   控制它的离合器-油门-刹车系统

+   管理动力和速度的齿轮和传动系统

我们周围有很多复杂的系统都是外观。就像汽车的例子一样，计算机是一个外观，工业机器人是另一个。所有工厂控制系统都是外观，为工程师提供了一些仪表板和控件，以调整其背后的复杂系统，并使其保持运行。

### Python 中的外观

Python 标准库包含许多模块，它们是外观的很好的例子。`compiler`模块提供了解析和编译 Python 源代码的钩子，是词法分析器、解析器、ast 树生成器等的外观。

以下是此模块的帮助内容的图像。

![Python 中的外观](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00486.jpeg)

在帮助内容的下一页中，您可以看到这个模块是其他模块的外观，这些模块用于实现此包中定义的函数。（查看图像底部的“包内容”）：

![Python 中的外观](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00487.jpeg)

让我们看一个外观模式的示例代码。在这个例子中，我们将模拟一辆汽车及其多个子系统中的一些。

这是所有子系统的代码：

```py
class Engine(object):
    """ An Engine class """

    def __init__(self, name, bhp, rpm, volume, cylinders=4, type='petrol'):
        self.name = name
        self.bhp = bhp
        self.rpm = rpm
        self.volume = volume
        self.cylinders = cylinders
        self.type = type

    def start(self):
        """ Fire the engine """
        print('Engine started')

    def stop(self):
        """ Stop the engine """
        print('Engine stopped')

class Transmission(object):
    """ Transmission class """

    def __init__(self, gears, torque):
        self.gears = gears
        self.torque = torque
        # Start with neutral
        self.gear_pos = 0

    def shift_up(self):
        """ Shift up gears """

        if self.gear_pos == self.gears:
            print('Cant shift up anymore')
        else:
            self.gear_pos += 1
            print('Shifted up to gear',self.gear_pos)

    def shift_down(self):
        """ Shift down gears """

        if self.gear_pos == -1:
            print("In reverse, can't shift down")
        else:
            self.gear_pos -= 1
            print('Shifted down to gear',self.gear_pos)         

    def shift_reverse(self):
        """ Shift in reverse """

        print('Reverse shifting')
        self.gear_pos = -1

    def shift_to(self, gear):
        """ Shift to a gear position """

        self.gear_pos = gear
        print('Shifted to gear',self.gear_pos)      

class Brake(object):
    """ A brake class """

    def __init__(self, number, type='disc'):
        self.type = type
        self.number = number

    def engage(self):
        """ Engage the break """

        print('%s %d engaged' % (self.__class__.__name__,
                                 self.number))

    def release(self):
        """ Release the break """

        print('%s %d released' % (self.__class__.__name__,
                                  self.number))

class ParkingBrake(Brake):
    """ A parking brake class """

    def __init__(self, type='drum'):
        super(ParkingBrake, self).__init__(type=type, number=1)

class Suspension(object):
    """ A suspension class """

    def __init__(self, load, type='mcpherson'):
        self.type = type
        self.load = load

class Wheel(object):
    """ A wheel class """

    def __init__(self, material, diameter, pitch):
        self.material = material
        self.diameter = diameter
        self.pitch = pitch

class WheelAssembly(object):
    """ A wheel assembly class """

    def __init__(self, brake, suspension):
        self.brake = brake
        self.suspension = suspension
        self.wheels = Wheel('alloy', 'M12',1.25)

    def apply_brakes(self):
        """ Apply brakes """

        print('Applying brakes')
        self.brake.engage()

class Frame(object):
    """ A frame class for an automobile """

    def __init__(self, length, width):
        self.length = length
        self.width = width
```

正如你所看到的，我们已经涵盖了汽车中的大部分子系统，至少是那些必不可少的。

这是`Car`类的代码，它将它们组合为一个外观，有两个方法，即`start`和`stop`汽车：

```py
class Car(object):
    """ A car class - Facade pattern """

    def __init__(self, model, manufacturer):
        self.engine = Engine('K-series',85,5000, 1.3)
        self.frame = Frame(385, 170)
        self.wheel_assemblies = []
        for i in range(4):
            self.wheel_assemblies.append(WheelAssembly(Brake(i+1), Suspension(1000)))

        self.transmission = Transmission(5, 115)
        self.model = model
        self.manufacturer = manufacturer
        self.park_brake = ParkingBrake()
        # Ignition engaged
        self.ignition = False

    def start(self):
        """ Start the car """

        print('Starting the car')
        self.ignition = True
        self.park_brake.release()
        self.engine.start()
        self.transmission.shift_up()
        print('Car started.')

    def stop(self):
        """ Stop the car """

        print('Stopping the car')
        # Apply brakes to reduce speed
        for wheel_a in self.wheel_assemblies:
            wheel_a.apply_brakes()

        # Move to 2nd gear and then 1st
        self.transmission.shift_to(2)
        self.transmission.shift_to(1)
        self.engine.stop()
        # Shift to neutral
        self.transmission.shift_to(0)
        # Engage parking brake
        self.park_brake.engage()
        print('Car stopped.')
```

让我们首先建立一个`Car`的实例：

```py
>>> car = Car('Swift','Suzuki')
>>> car
<facade.Car object at 0x7f0c9e29afd0>
```

现在让我们把车开出车库去兜风：

```py
>>> car.start()
Starting the car
ParkingBrake 1 released
Engine started
Shifted up to gear 1
```

汽车已启动。

现在我们已经开了一段时间，我们可以停车了。正如你可能已经猜到的那样，停车比起开车更复杂！

```py
>>> car.stop()
Stopping the car
Shifted to gear 2
Shifted to gear 1
Applying brakes
Brake 1 engaged
Applying brakes
Brake 2 engaged
Applying brakes
Brake 3 engaged
Applying brakes
Brake 4 engaged
Engine stopped
Shifted to gear 0
ParkingBrake 1 engaged
Car stopped.
>>>
```

外观对于简化系统的复杂性以便更容易地使用它们是很有用的。正如前面的例子所示，如果我们没有像在这个例子中那样构建`start`和`stop`方法，那么它将会非常困难。这些方法隐藏了启动和停止`Car`中涉及的子系统的复杂性。

这正是外观最擅长的。

## 代理模式

代理模式包装另一个对象以控制对其的访问。一些使用场景如下：

+   我们需要一个更接近客户端的虚拟资源，它在另一个网络中代替真实资源，例如，远程代理

+   当我们需要控制/监视对资源的访问时，例如，网络代理和实例计数代理

+   我们需要保护一个资源或对象（保护代理），因为直接访问它会导致安全问题或损害它，例如，反向代理服务器

+   我们需要优化对昂贵计算或网络操作的结果的访问，以便不必每次都执行计算，例如，一个缓存代理

代理始终实现被代理对象的接口 - 换句话说，它的目标。这可以通过继承或组合来实现。在 Python 中，后者可以通过重写`__getattr__`方法更强大地实现，就像我们在适配器示例中看到的那样。

### 实例计数代理

我们将从一个示例开始，演示代理模式用于跟踪类的实例的用法。我们将在这里重用我们的`Employee`类及其子类，这些子类来自工厂模式：

```py
class EmployeeProxy(object):
    """ Counting proxy class for Employees """

    # Count of employees
    count = 0

    def __new__(cls, *args):
        """ Overloaded __new__ """
        # To keep track of counts
        instance = object.__new__(cls)
        cls.incr_count()
        return instance

    def __init__(self, employee):
        self.employee = employee

    @classmethod
    def incr_count(cls):
        """ Increment employee count """
        cls.count += 1

    @classmethod
    def decr_count(cls):
        """ Decrement employee count """
        cls.count -= 1

    @classmethod
    def get_count(cls):
        """ Get employee count """
        return cls.count

    def __str__(self):
        return str(self.employee)

    def __getattr__(self, name):
        """ Redirect attributes to employee instance """

        return getattr(self.employee, name)

    def __del__(self):
        """ Overloaded __del__ method """
        # Decrement employee count
        self.decr_count()

class EmployeeProxyFactory(object):
    """ An Employee factory class returning proxy objects """

    @classmethod
    def create(cls, name, *args):
        """ Factory method for creating an Employee instance """

        name = name.lower().strip()

        if name == 'engineer':
            return EmployeeProxy(Engineer(*args))
        elif name == 'accountant':
            return EmployeeProxy(Accountant(*args))
        elif name == 'admin':
            return EmployeeProxy(Admin(*args))
```

### 注意

我们没有复制员工子类的代码，因为这些已经在工厂模式讨论中可用。

这里有两个类，即`EmployeeProxy`和修改后的原始`factory`类，用于返回`EmployeeProxy`的实例而不是 Employee 的实例。修改后的工厂类使我们能够轻松创建代理实例，而不必自己去做。

在这里实现的代理是一个组合或对象代理，因为它包装目标对象（员工）并重载`__getattr__`以将属性访问重定向到它。它通过重写`__new__`和`__del__`方法来跟踪实例的数量，分别用于实例创建和实例删除。

让我们看一个使用代理的例子：

```py
>>> factory = EmployeeProxyFactory()
>>> engineer = factory.create('engineer','Sam',25,'M')
>>> print(engineer)
Engineer - Sam, 25 years old M
```

### 注意

这通过代理打印了工程师的详细信息，因为我们在代理类中重写了`__str__`方法，该方法调用了员工实例的相同方法。

```py
>>> admin = factory.create('admin','Tracy',32,'F')
>>> print(admin)
Admin - Tracy, 32 years old F
```

现在让我们检查实例计数。这可以通过实例或类来完成，因为它无论如何都引用一个类变量：

```py
>>> admin.get_count()
2
>>> EmployeeProxy.get_count()
2
```

让我们删除这些实例，看看会发生什么！

```py
>>> del engineer
>>> EmployeeProxy.get_count()
1
>>> del admin
>>> EmployeeProxy.get_count()
0
```

### 注意

Python 中的弱引用模块提供了一个代理对象，它执行了与我们实现的非常相似的操作，通过代理访问类实例。

这里有一个例子：

```py
>>> import weakref
>>> import gc
>>> engineer=Engineer('Sam',25,'M')
```

让我们检查一下新对象的引用计数：

```py
>>> len(gc.get_referrers(engineer))
1
```

现在创建一个对它的弱引用：

```py
>>> engineer_proxy=weakref.proxy(engineer)
```

`weakref`对象在所有方面都像它的代理对象一样：

```py
>>> print(engineer_proxy)
Engineer - Sam, 25 years old M
>>> engineer_proxy.get_role()
'engineering'
```

但是，请注意，`weakref`代理不会增加被代理对象的引用计数：

```py
>>> len(gc.get_referrers(engineer))
      1
```

# Python 中的模式-行为

行为模式是模式的复杂性和功能的最后阶段。它们也是系统中对象生命周期中的最后阶段，因为对象首先被创建，然后构建成更大的结构，然后彼此交互。

这些模式封装了对象之间的通信和交互模型。这些模式允许我们描述可能在运行时难以跟踪的复杂工作流程。

通常，行为模式更青睐对象组合而不是继承，因为系统中交互的对象通常来自不同的类层次结构。

在这个简短的讨论中，我们将看一下以下模式：**迭代器**，**观察者**和**状态**。

## 迭代器模式

迭代器提供了一种顺序访问容器对象元素的方法，而不暴露底层对象本身。换句话说，迭代器是一个代理，提供了一个遍历容器对象的方法。

在 Python 中，迭代器随处可见，因此没有特别需要引入它们。

Python 中的所有容器/序列类型，即列表、元组、字符串和集合都实现了自己的迭代器。字典也实现了对其键的迭代器。

在 Python 中，迭代器是实现魔术方法`__iter__`的任何对象，并且还响应于返回迭代器实例的函数 iter。

通常，在 Python 中，创建的迭代器对象是隐藏在幕后的。

例如，我们可以这样遍历列表：

```py
>>> for i in range(5):
...         print(i)
...** 
0
1
2
3
4

```

在内部，类似于以下的事情发生：

```py
>>> I = iter(range(5))
>>> for i in I:
...         print(i)
...** 
0
1
2
3
4

```

每种序列类型在 Python 中都实现了自己的迭代器类型。以下是一些示例：

+   **列表**：

```py
>>> fruits = ['apple','oranges','grapes']
>>> iter(fruits)
<list_iterator object at 0x7fd626bedba8>

```

+   **元组**：

```py
>>> prices_per_kg = (('apple', 350), ('oranges', 80), ('grapes', 120))
>>> iter(prices_per_kg)
<tuple_iterator object at 0x7fd626b86fd0>

```

+   **集合**：

```py
>>> subjects = {'Maths','Chemistry','Biology','Physics'}
>>> iter(subjects)
<set_iterator object at 0x7fd626b91558>

```

即使在 Python3 中，字典也有自己的特殊键迭代器类型：

```py
>>> iter(dict(prices_per_kg))
<dict_keyiterator object at 0x7fd626c35ae8>

```

现在我们将看到一个在 Python 中实现自己的迭代器类/类型的小例子：

```py
class Prime(object):
    """ An iterator for prime numbers """

    def __init__(self, initial, final=0):
        """ Initializer - accepts a number """
        # This may or may not be prime
        self.current = initial
        self.final = final

    def __iter__(self):
        return self

    def __next__(self):
        """ Return next item in iterator """
        return self._compute()

    def _compute(self):
        """ Compute the next prime number """

        num = self.current

        while True:
            is_prime = True

            # Check this number
            for x in range(2, int(pow(self.current, 0.5)+1)):
                if self.current%x==0:
                    is_prime = False
                    break

            num = self.current
            self.current += 1

            if is_prime:
                return num

            # If there is an end range, look for it
            if self.final > 0 and self.current>self.final:
                raise StopIteration
```

上述的类是一个素数迭代器，它返回两个限制之间的素数：

```py
>>> p=Prime(2,10)
>>> for num in p:
... print(num)
... 
2
3
5
7
>>> list(Prime(2,50))
[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
```

没有结束限制的素数迭代器是一个无限迭代器。例如，以下迭代器将返回从`2`开始的所有素数，并且永远不会停止：

```py
>>> p = Prime(2)
```

然而，通过与 itertools 模块结合，可以从这样的无限迭代器中提取所需的特定数据。

例如，在这里，我们使用`itertools`的`islice`方法计算前 100 个素数：

```py
>>> import itertools
>>> list(itertools.islice(Prime(2), 100))
[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541]
```

同样地，这里是以 1 结尾的前 10 个素数，使用`filterfalse`方法：

```py
>>> list(itertools.islice(itertools.filterfalse(lambda x: x % 10 != 1, Prime(2)), 10))
[11, 31, 41, 61, 71, 101, 131, 151, 181, 191]
```

同样地，这里是前 10 个回文素数：

```py
>>> list(itertools.islice(itertools.filterfalse(lambda x: str(x)!=str(x)[-1::-1], Prime(2)), 10))
[2, 3, 5, 7, 11, 101, 131, 151, 181, 191]
```

感兴趣的读者可以参考`itertools`模块及其方法的文档，找出使用和操作这样的无限生成器数据的有趣方法。

## 观察者模式

观察者模式解耦了对象，但同时允许一组对象（订阅者）跟踪另一个对象（发布者）的变化。这避免了一对多的依赖和引用，同时保持它们的交互活跃。

这种模式也被称为**发布-订阅**。

这是一个相当简单的例子，使用了一个`Alarm`类，它在自己的线程中运行，并每秒（默认）生成周期性的警报。它还作为一个`Publisher`类工作，通知其订阅者每当警报发生时。

```py
import threading
import time

from datetime import datetime

class Alarm(threading.Thread):
    """ A class which generates periodic alarms """

    def __init__(self, duration=1):
        self.duration = duration
        # Subscribers
        self.subscribers = []
        self.flag = True
        threading.Thread.__init__(self, None, None)

    def register(self, subscriber):
        """ Register a subscriber for alarm notifications """

        self.subscribers.append(subscriber)

    def notify(self):
        """ Notify all the subscribers """

        for subscriber in self.subscribers:
            subscriber.update(self.duration)

    def stop(self):
        """ Stop the thread """

        self.flag = False

    def run(self):
        """ Run the alarm generator """

        while self.flag:
            time.sleep(self.duration)
            # Notify
            self.notify()
```

我们的订阅者是一个简单的`DumbClock`类，它订阅`Alarm`对象以获取通知，并使用它来更新时间：

```py
class DumbClock(object):
    """ A dumb clock class using an Alarm object """

    def __init__(self):
        # Start time
        self.current = time.time()

    def update(self, *args):
        """ Callback method from publisher """

        self.current += args[0]

    def __str__(self):
        """ Display local time """

        return datetime.fromtimestamp(self.current).strftime('%H:%M:%S')
```

让我们让这些对象开始运行：

1.  首先创建一个通知周期为一秒的闹钟。这允许：

```py
>>> alarm=Alarm(duration=1)
```

1.  接下来创建`DumbClock`对象：

```py
>>> clock=DumbClock()
```

1.  最后，将时钟对象注册为观察者，以便它可以接收通知：

```py
>>> alarm.register(clock)
```

1.  现在时钟将不断接收来自闹钟的更新。每次打印时钟时，它将显示当前时间，精确到秒：

```py
>>> print(clock)
10:04:27
```

过一段时间它会显示如下内容：

```py
>>> print(clock)
10:08:20
```

1.  睡一会儿然后打印。

```py
>>> print(clock);time.sleep(20);print(clock)
10:08:23
10:08:43
```

在实现观察者时要记住的一些方面：

+   **订阅者的引用**：发布者可以选择保留对订阅者的引用，也可以使用中介者模式在需要时获取引用。中介者模式将系统中的许多对象从强烈相互引用中解耦。例如，在 Python 中，这可以是弱引用或代理的集合，或者如果发布者和订阅者对象都在同一个 Python 运行时中，则可以是管理这样一个集合的对象。对于远程引用，可以使用远程代理。

+   **实现回调**：在这个例子中，`Alarm`类直接通过调用其`update`方法来更新订阅者的状态。另一种实现方式是发布者简单地通知订阅者，然后订阅者使用`get_state`类型的方法查询发布者的状态来实现自己的状态改变。

这是与不同类型/类的订阅者交互的首选选项。这也允许从发布者到订阅者的代码解耦，因为如果订阅者的`update`或`notify`方法发生变化，发布者就不必更改其代码。

+   **同步与异步**：在这个例子中，当状态改变时，通知在与发布者相同的线程中调用，因为时钟需要可靠和即时的通知才能准确。在异步实现中，这可以异步完成，以便发布者的主线程继续运行。例如，在使用异步执行返回一个 future 对象的系统中，这可能是首选的方法，但实际通知可能在稍后发生。

由于我们已经在第五章中遇到了异步处理，关于可扩展性，我们将用一个更多的例子来结束我们对观察者模式的讨论，展示一个异步的例子，展示发布者和订阅者异步交互。我们将在 Python 中使用 asyncio 模块。

在这个例子中，我们将使用新闻发布的领域。我们的发布者从各种来源获取新闻故事作为新闻 URL，这些 URL 被标记为特定的新闻频道。这些频道的示例可能是 - "体育"，"国际"，"技术"，"印度"等等。

新闻订阅者注册他们感兴趣的新闻频道，以 URL 形式获取新闻故事。一旦他们获得 URL，他们会异步获取 URL 的数据。发布者到订阅者的通知也是异步进行的。

这是我们发布者的源代码：

```py
  import weakref
  import asyncio

  from collections import defaultdict, deque

  class NewsPublisher(object):
    """ A news publisher class with asynchronous notifications """

    def __init__(self):
        # News channels
        self.channels = defaultdict(deque)
        self.subscribers = defaultdict(list)
        self.flag = True

    def add_news(self, channel, url):
        """ Add a news story """

        self.channels[channel].append(url)

    def register(self, subscriber, channel):
        """ Register a subscriber for a news channel """

        self.subscribers[channel].append(weakref.proxy(subscriber))

    def stop(self):
        """ Stop the publisher """

        self.flag = False

    async def notify(self):
        """ Notify subscribers """

        self.data_null_count = 0

        while self.flag:
            # Subscribers who were notified
            subs = []

            for channel in self.channels:
                try:
                    data = self.channels[channel].popleft()
                except IndexError:
                    self.data_null_count += 1
                    continue

                subscribers = self.subscribers[channel]
                for sub in subscribers:
                    print('Notifying',sub,'on channel',channel,'with data=>',data)
                    response = await sub.callback(channel, data)
                    print('Response from',sub,'for channel',channel,'=>',response)
                    subs.append(sub)

            await asyncio.sleep(2.0)
```

发布者的`notify`方法是异步的。它遍历通道列表，找出每个通道的订阅者，并使用其`callback`方法回调订阅者，提供来自通道的最新数据。

`callback`方法本身是异步的，它返回一个 future 而不是任何最终处理的结果。这个 future 的进一步处理在订阅者的`fetch_urls`方法中异步进行。

这是我们订阅者的源代码：

```py
import aiohttp

class NewsSubscriber(object):
    """ A news subscriber class with asynchronous callbacks """

    def __init__(self):
        self.stories = {}
        self.futures = []
        self.future_status = {}
        self.flag = True

    async def callback(self, channel, data):
        """ Callback method """

        # The data is a URL
        url = data
        # We return the response immediately
        print('Fetching URL',url,'...')
        future = aiohttp.request('GET', url)
        self.futures.append(future)

        return future

    async def fetch_urls(self):

        while self.flag:

            for future in self.futures:
                # Skip processed futures
                if self.future_status.get(future):
                    continue

                response = await future

                # Read data
                data = await response.read()

                print('\t',self,'Got data for URL',response.url,'length:',len(data))
                self.stories[response.url] = data
                # Mark as such
                self.future_status[future] = 1

            await asyncio.sleep(2.0)
```

注意`callback`和`fetch_urls`方法都声明为异步。`callback`方法将 URL 从发布者传递给`aiohttp`模块的`GET`方法，该方法简单地返回一个 future。

未来将被添加到本地的未来列表中，再次异步处理 - 通过`fetch_urls`方法获取 URL 数据，然后将其附加到本地的故事字典中，URL 作为键。

这是代码的异步循环部分。

看一下以下步骤：

1.  为了开始，我们创建一个发布者，并通过特定的 URL 添加一些新闻故事到发布者的几个频道上：

```py
      publisher = NewsPublisher()

      # Append some stories to the 'sports' and 'india' channel

      publisher.add_news('sports', 'http://www.cricbuzz.com/cricket-news/94018/collective-dd-show-hands-massive-loss-to-kings-xi-punjab')

      publisher.add_news('sports', 'https://sports.ndtv.com/indian-premier-league-2017/ipl-2017-this-is-how-virat-kohli-recovered-from-the-loss-against-mumbai-indians-1681955')

publisher.add_news('india','http://www.business-standard.com/article/current-affairs/mumbai-chennai-and-hyderabad-airports-put-on-hijack-alert-report-117041600183_1.html')
    publisher.add_news('india','http://timesofindia.indiatimes.com/india/pakistan-to-submit-new-dossier-on-jadhav-to-un-report/articleshow/58204955.cms')
```

1.  然后我们创建两个订阅者，一个监听`sports`频道，另一个监听`india`频道：

```py
    subscriber1 = NewsSubscriber()
    subscriber2 = NewsSubscriber()  
    publisher.register(subscriber1, 'sports')
    publisher.register(subscriber2, 'india') 
```

1.  现在我们创建异步事件循环：

```py
    loop = asyncio.get_event_loop()
```

1.  接下来，我们将任务作为协程添加到循环中，以使异步循环开始处理。我们需要添加以下三个任务：

+   `publisher.notify()`:

+   `subscriber.fetch_urls()`: 每个订阅者一个

1.  由于发布者和订阅者处理循环都不会退出，我们通过其`wait`方法添加了一个超时来处理：

```py
    tasks = map(lambda x: x.fetch_urls(), (subscriber1, subscriber2))
    loop.run_until_complete(asyncio.wait([publisher.notify(), *tasks],                                    timeout=120))

    print('Ending loop')
    loop.close()
```

这是我们异步的发布者和订阅者在控制台上的操作。

![观察者模式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00488.jpeg)

现在，我们继续讨论设计模式中的最后一个模式，即状态模式。

## 状态模式

状态模式将对象的内部状态封装在另一个类（**状态对象**）中。对象通过将内部封装的状态对象切换到不同的值来改变其状态。

状态对象及其相关的表亲，**有限状态机**（**FSM**），允许程序员在不需要复杂代码的情况下实现对象在不同状态之间的状态转换。

在 Python 中，状态模式可以很容易地实现，因为 Python 为对象的类有一个魔术属性，即`__class__`属性。

听起来有点奇怪，但在 Python 中，这个属性可以在实例的字典上进行修改！这允许实例动态地改变其类，这是我们可以利用来在 Python 中实现这种模式的东西。

这是一个简单的例子：

```py
>>> class C(object):
...     def f(self): return 'hi'
... 
>>> class D(object): pass
... 
>>> c = C()
>>> c
<__main__.C object at 0x7fa026ac94e0>
>>> c.f()
'hi'
>>> c.__class__=D
>>> c
<__main__.D object at 0x7fa026ac94e0>
>>> c.f()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
AttributeError: 'D' object has no attribute 'f'
```

我们能够在运行时更改对象`c`的类。现在，在这个例子中，这证明是危险的，因为`C`和`D`是不相关的类，所以在这种情况下做这样的事情从来不是明智的。这在 c 在切换到`D`类的实例时忘记了它的方法`f`的方式中是显而易见的（`D`没有`f`方法）。

然而，对于相关的类，更具体地说，实现相同接口的父类的子类，这给了很大的权力，并且可以用来实现诸如状态之类的模式。

在下面的例子中，我们使用了这种技术来实现状态模式。它展示了一个可以从一个状态切换到另一个状态的计算机。

请注意，我们在定义这个类时使用了迭代器，因为迭代器通过其本质自然地定义了移动到下一个位置。我们利用了这一事实来实现我们的状态模式：

```py
import random

class ComputerState(object):
    """ Base class for state of a computer """

    # This is an iterator
    name = "state"
    next_states = []
    random_states = []

    def __init__(self):
        self.index = 0

    def __str__(self):
        return self.__class__.__name__

    def __iter__(self):
        return self

    def change(self):
        return self.__next__()

    def set(self, state):
        """ Set a state """

        if self.index < len(self.next_states):
            if state in self.next_states:
                # Set index
                self.index = self.next_states.index(state)
                self.__class__ = eval(state)
                return self.__class__
            else:
                # Raise an exception for invalid state change    
              current = self.__class__
                new = eval(state)
                raise Exception('Illegal transition from %s to %s' % (current, new))
        else:
            self.index = 0
            if state in self.random_states:
                self.__class__ = eval(state)
                return self.__class__

    def __next__(self):
        """ Switch to next state """

        if self.index < len(self.next_states):
            # Always move to next state first
            self.__class__ = eval(self.next_states[self.index])
            # Keep track of the iterator position
            self.index += 1
            return self.__class__
        else:
             # Can switch to a random state once it completes
            # list of mandatory next states.
            # Reset index
            self.index = 0
            if len(self.random_states):
                state = random.choice(self.random_states)
                self.__class__ = eval(state)
                return self.__class__
            else:
                raise StopIteration
```

现在让我们定义`ComputerState`类的一些具体子类。

每个类都可以定义一个`next_states`列表，其中包含当前状态可以切换到的合法状态集。它还可以定义一个随机状态列表，这些是它可以切换到的随机合法状态，一旦它切换到下一个状态。

例如，这里是第一个状态，即计算机的`off`状态。下一个强制状态当然是`on`状态。一旦计算机开启，这个状态可以转移到任何其他随机状态。

因此，定义如下：

```py
class ComputerOff(ComputerState):
    next_states = ['ComputerOn']
    random_states = ['ComputerSuspend', 'ComputerHibernate', 'ComputerOff']
```

同样，这里是其他状态类的定义：

```py
class ComputerOn(ComputerState):
    # No compulsory next state    
    random_states = ['ComputerSuspend', 'ComputerHibernate', 'ComputerOff']

class ComputerWakeUp(ComputerState):
    # No compulsory next state
    random_states = ['ComputerSuspend', 'ComputerHibernate', 'ComputerOff']

class ComputerSuspend(ComputerState):
    next_states = ['ComputerWakeUp']  
    random_states = ['ComputerSuspend', 'ComputerHibernate', 'ComputerOff']

class ComputerHibernate(ComputerState):
    next_states = ['ComputerOn']  
    random_states = ['ComputerSuspend', 'ComputerHibernate', 'ComputerOff']
```

最后，这是使用状态类设置其内部状态的计算机类。

```py
class Computer(object):
    """ A class representing a computer """

    def __init__(self, model):
        self.model = model
        # State of the computer - default is off.
        self.state = ComputerOff()

    def change(self, state=None):
        """ Change state """

        if state==None:
            return self.state.change()
        else:
            return self.state.set(state)

    def __str__(self):
        """ Return state """
        return str(self.state)
```

这个实现的一些有趣方面：

+   **状态作为迭代器**：我们将`ComputerState`类实现为迭代器。这是因为状态自然地具有可以切换到的即时未来状态列表，没有其他内容。例如，处于“关闭”状态的计算机只能转移到下一个“打开”状态。将其定义为迭代器使我们能够利用迭代器从一个状态自然地进展到下一个状态。

+   **随机状态**：我们在这个例子中实现了随机状态的概念。一旦计算机从一个状态移动到其强制的下一个状态（从打开到关闭，从暂停到唤醒），它有一个可以移动到的随机状态列表。处于打开状态的计算机不一定总是要关闭。它也可以进入睡眠（暂停）或休眠。

+   **手动更改**：计算机可以通过`change`方法的第二个可选参数移动到特定状态。但是，只有在状态更改有效时才可能，否则会引发异常。

现在我们将看到我们的状态模式在实际中的应用。

计算机开始关闭，当然：

```py
>>> c = Computer('ASUS')
>>> print(c)
ComputerOff
```

让我们看一些自动状态更改：

```py
>>> c.change()
<class 'state.ComputerOn'>
```

现在，让状态机决定它的下一个状态——注意这些是随机状态，直到计算机进入必须移动到下一个状态的状态为止：

```py
>>> c.change()
<class 'state.ComputerHibernate'>
```

现在状态是休眠，这意味着下一个状态必须是打开，因为这是一个强制的下一个状态：

```py
>>> c.change()
<class 'state.ComputerOn'>
>>> c.change()
<class 'state.ComputerOff'>
```

现在状态是关闭，这意味着下一个状态必须是打开：

```py
>>> c.change()
<class 'state.ComputerOn'>
```

以下是所有随机状态更改：

```py
>>> c.change()
<class 'state.ComputerSuspend'>
>>> c.change()
<class 'state.ComputerWakeUp'>
>> c.change()
<class 'state.ComputerHibernate'>
```

现在，由于底层状态是一个迭代器，因此可以使用 itertools 等模块对状态进行迭代。

这是一个例子——迭代计算机的下一个五个状态：

```py
>>> import itertools
>>> for s in itertools.islice(c.state, 5):
... print (s)
... 
<class 'state.ComputerOn'>
<class 'state.ComputerOff'>
<class 'state.ComputerOn'>
<class 'state.ComputerOff'>
<class 'state.ComputerOn'>
```

现在让我们尝试一些手动状态更改：

```py
>>> c.change('ComputerOn')
<class 'state.ComputerOn'>
>>> c.change('ComputerSuspend')
<class 'state.ComputerSuspend'>

>>> c.change('ComputerHibernate')
Traceback (most recent call last):
  File "state.py", line 133, in <module>
      print(c.change('ComputerHibernate'))        
  File "state.py", line 108, in change
      return self.state.set(state)
  File "state.py", line 45, in set
      raise Exception('Illegal transition from %s to %s' % (current, new))
Exception: Illegal transition from <class '__main__.ComputerSuspend'> to <class '__main__.ComputerHibernate'>
```

当我们尝试无效的状态转换时，我们会得到一个异常，因为计算机不能直接从暂停转换到休眠。它必须先唤醒！

```py
>>> c.change('ComputerWakeUp')
<class 'state.ComputerWakeUp'>
>>> c.change('ComputerHibernate')
<class 'state.ComputerHibernate'>
```

现在一切都很好。

我们讨论了 Python 中设计模式的讨论到此结束，现在是总结我们迄今为止学到的东西的时候了。

# 总结

在本章中，我们详细介绍了面向对象设计模式，并发现了在 Python 中实现它们的新方法和不同方法。我们从设计模式及其分类（创建型、结构型和行为型模式）开始。

我们继续看了一个策略设计模式的例子，并看到如何以 Python 的方式实现它。然后我们开始正式讨论 Python 中的模式。

在创建型模式中，我们涵盖了单例、Borg、原型、工厂和生成器模式。我们看到了为什么 Borg 通常比单例在 Python 中更好，因为它能够在类层次结构中保持状态。我们看到了生成器、原型和工厂模式之间的相互作用，并看到了一些例子。在可能的情况下，引入了元类讨论，并使用元类实现了模式。

在结构型模式中，我们的重点是适配器、facade 和代理模式。我们通过适配器模式看到了详细的例子，并讨论了通过继承和对象组合的方法。当我们通过`__getattr__`技术实现适配器和代理模式时，我们看到了 Python 中魔术方法的威力。

在 Facade 中，使用`Car`类，我们看到了一个详细的例子，说明了 Facade 如何帮助程序员征服复杂性，并在子系统上提供通用接口。我们还看到许多 Python 标准库模块本身就是 facade。

在行为部分，我们讨论了迭代器、观察者和状态模式。我们看到迭代器是 Python 的一部分。我们实现了一个迭代器作为生成器来构建素数。

我们通过使用`Alarm`类作为发布者和时钟类作为订阅者，看到了观察者模式的一个简单例子。我们还看到了在 Python 中使用 asyncio 模块的异步观察者模式的例子。

最后，我们以状态模式结束了模式的讨论。我们讨论了通过允许的状态更改来切换计算机状态的详细示例，以及如何使用 Python 的`__class__`作为动态属性来更改实例的类。在状态的实现中，我们借鉴了迭代器模式的技术，并将状态示例类实现为迭代器。

在我们的下一章中，我们从设计转向软件架构中模式的下一个更高范式，即架构模式。
