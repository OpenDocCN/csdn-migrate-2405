# BurpSuite 应用渗透测试实用指南（二）

> 原文：[`annas-archive.org/md5/854BB45B5601AD5131BDF5E0A2CF756B`](https://annas-archive.org/md5/854BB45B5601AD5131BDF5E0A2CF756B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：使用 Burp Suite 利用漏洞 - 第 2 部分

正如我们在上一章中看到的，Burp Suite 是一个灵活的工具，用于检测和利用漏洞。在本章中，我们将利用其他类型的漏洞，展示 Burp Suite 的更多选项和功能。

在本章中，我们将涵盖以下主题：

+   使用 SSRF/XSPA 执行内部端口扫描

+   使用 SSRF/XSPA 从内部机器提取数据

+   使用不安全的直接对象引用（IDOR）漏洞提取数据

+   利用安全配置错误

+   使用不安全的反序列化来执行操作系统命令

+   利用加密漏洞

+   暴力破解 HTTP 基本身份验证

+   暴力破解表单

+   绕过文件上传限制

# 使用 SSRF/XSPA 执行内部端口扫描

**服务器端请求伪造**（SSRF）是一种漏洞，恶意用户可以向托管应用程序的服务器发送手动请求，通常是从用户角度无法直接访问的服务器。

目前，这是一个备受欢迎的漏洞，因为它对使用 Elasticsearch 和 NoSQL 数据库等技术的云基础设施产生了巨大影响。

在以下代码片段中，我们可以看到它的效果：

```
<?php 
   if (isset($_GET['url'])){ 
         $url = $_GET['url']; 
         $image = fopen($url, 'rb'); 
         header("Content-Type: image/png"); 
         fpassthru($image); 
   } 
```

这段代码是有漏洞的，因为它在没有验证的情况下接收`url`参数，然后...

# 执行对后端的内部端口扫描

端口扫描是在评估网络时进行网络发现的最基本和最有用的活动之一。在应用程序中，安全评估受到评估范围的限制，但 SSRF 和 XSPA 允许用户从应用程序中执行端口扫描。为了演示您如何执行此技术，我们将使用 Acunetix 创建的一个有漏洞的测试应用程序，您可以在[`testphp.vulnweb.com/`](http://testphp.vulnweb.com/)找到。

这是一个有漏洞的应用程序，您可以用来学习一些攻击和测试脚本或工具，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/b7194d52-807a-4f01-a610-0e6048023915.png)

1.  打开 Burp Suite 的仪表板，然后点击新扫描。将 Acunetix 的 URL 添加到范围中，然后点击开始，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/3a756b75-6dc6-406d-bdf1-cee5b2bfe41d.png)

1.  扫描应用程序后，Burp Suite 检测到 URL（[`testphp.vulnweb.com/showimage.php`](http://testphp.vulnweb.com/showimage.php)）对 SSRF 存在漏洞。这个 PHP 文件接受 URL 作为参数，如下行所示：

```
http://testphp.vulnweb.com/showimage.php?file=http://192.168.0.1:80
```

1.  要执行自动端口扫描，我们可以使用 Intruder。首先，停止请求，并将其发送到 Intruder，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/66226f38-91db-48dd-9b1d-1464636571f5.png)

1.  清除默认创建的通配符，并按照您自己的方式添加一个新的，如下面的屏幕截图所示：

```
GET /showimage.php?file=http://192.168.0.1:port HTTP/1.1 
Host: testphp.vulnweb.com 
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 
Accept-Language: en-US,en;q=0.5 
Accept-Encoding: gzip, deflate 
Connection: close 
Cookie: login=test%2Ftest 
Upgrade-Insecure-Requests: 1 
```

现在，您可以将您的有效负载定义为一个列表，从 0 到 65,535，并选择随机选项。为什么？因为一些**入侵防护系统**（IPS）会检测对同一 IP 的顺序请求，因此通过使用随机选项，我们可以尝试避免被检测到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/b7eba87e-7db4-4b2e-9e06-876df72faf7f.png)

1.  现在，启动攻击，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/29ada021-e7e8-4e43-a64c-a20747811370.png)

为什么有效？如果您查看响应，就可以看到连接是否成功，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/7eb1282c-cb77-404e-8a32-fbcaed7f5adc.png)

当端口打开时，响应不会显示任何错误。作为提示，您可以分析长度列，以检测响应何时发生变化，并查看错误是否出现。

# 使用 SSRF/XSPA 从内部机器提取数据

SSRF 和 XSPA 漏洞也可以用于其他操作，例如从服务器中提取信息到后端所在的网络，或从托管应用程序的服务器中提取信息。让我们分析以下请求：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/3ced569c-8afd-4646-b71f-2b49aa0a716a.png)

在这里，`filehookURL`参数是易受攻击的，因此将其发送到 Repeater 工具，使用鼠标的辅助按钮，修改参数以提取一个文件，如`/etc/passwd`，如下所示：

```
action=handleWidgetFiles&type=delete&file=1&filehookURL=file:///etc/passwd 
```

将其发送到应用程序。如果有效，应用程序将显示...

# 利用不安全的直接对象引用（IDOR）漏洞提取数据

IDOR 是一种漏洞，允许恶意用户访问托管应用程序的服务器中的文件、数据库或敏感文件。

要识别易受 IDOR 攻击的应用程序，需要测试每个管理应用程序路径的变量。让我们看一个如何利用这种漏洞的例子。

# 利用 Burp Suite 的 IDOR

在以下的截图中，你有一个易受攻击的应用程序，并且你已经拦截了下一个请求：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/19761a53-0504-4c29-9984-ac5c63ac67e1.png)

我们在这个请求中有它们的参数；登录、操作和秘密。这里易受攻击的参数是登录。`secret`变量是用户在注册时分配的数据；存在的漏洞是，如果恶意用户修改了登录参数，应用程序会在不经过验证的情况下更改用户指定的秘密值。因此，我们创建了另一个名为**vendetta2**的用户，试图修改与该个人相关的秘密值，如下所示...

# 利用安全配置错误

“配置错误”这个术语是如此开放，它可能意味着与安全相关的许多事情。同时，确定这些漏洞的影响是如此困难；其中一些漏洞可能只是信息性的，显示有关用于构建应用程序的技术的信息，而其他一些可能非常关键，提供对服务器或应用程序的访问，从而暴露所有内容。

因此，在本节中，我们将展示不同的常见错误，以及如何使用 Burp Suite 来利用它们。

# 默认页面

通常，服务器管理员安装 Web 服务器或其他应用程序时，他们没有配置它们以避免显示默认页面，因此，通常会发现以下页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/fc8d3fb5-35f5-43e4-add7-7415e547a647.png)

这个默认页面可能是通用的，但它显示了信息，根据环境的不同，可能会很有用。例如，在这种情况下，我们看到了 Apache Tomcat 的默认页面。Tomcat 是一个应用服务器，有一个管理部分，Tomcat 有一个默认的用户名和密码。因此，如果您检测到这个默认页面，您只需要输入`tomcat`凭据，就可以看到所有选项。一个常见的攻击包括...

# 目录列表

系统管理员和开发人员通常会在文件系统中分配不正确的访问权限，允许用户访问敏感文件，如备份、配置文件、源代码文件，或者只是一个允许用户了解服务器和应用程序所在位置的目录。

为了发现所有这些结构，我们可以使用三种主要方法，如下所示：

+   扫描

+   映射应用程序

+   入侵者

让我们详细探讨每种方法。

# 扫描

扫描器，包括 Burp Suite 扫描器，具有检测敏感路径和常见文件的算法；实际上，常见文件可以用作横幅抓取，以检测潜在的漏洞。

如果检测到敏感文件，它将在扫描结果中显示为一个问题，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/ea91811c-7536-4fcd-8616-0d981234efee.png)

# 映射应用程序

在 Burp Suite 中，您可以在目标工具中找到所有不同的文件，它会创建一个包含所有网站结构的树。如果您点击一个文件，它将在右侧详细显示，详细说明它是否可访问，以及它是什么类型的文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/80f192be-9241-40e2-8350-01e1fc47c26d.png)

这种映射基本上是自动的；您只需在应用程序中工作，而 Burp Suite 会缓存所有请求并创建这个树，但 Burp Suite 也有一个专门用于此目的的工具。

在目标工具中，有一个名为 Scope 的选项卡；在这里，可以定义 URL 或路径作为范围，以便进行深度映射。当您发出请求时，该请求会有许多链接到其他资源的资源。Burp Suite 分析请求和响应，寻找这些链接，并使用它们可以检索到的信息来映射站点，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/6b948f96-fa82-496f-994a-bc7da71beb83.png)

如果应用程序有经过身份验证的部分，建议您提供凭据，因为每次 Burp Suite 尝试访问经过身份验证的部分时，代理都会弹出一个可能会让人讨厌的弹窗。当这种情况发生时，只需输入凭据，代理将保存它们以备将来使用。

# 使用 Intruder

我认为 Intruder 是 Burp Suite 工具中最灵活的。您可以用它做任何事情。在使用 Burp Suite 社区版时，您没有高级选项和工具，Intruder 可以提供所有这些功能，但有一些限制，这意味着执行任务需要更多时间，但它可以执行任何类型的任务。

因此，为了检测目录列表和敏感文件，我们将使用常见的列表。例如，我们可以有一个包含常见目录的列表，例如**内容管理系统**（**CMS**）、电子商务应用程序中的常用路径，以及自制应用程序中使用的常规路径，例如`/users/`、`/admin/`、`/administrator/`、`process.php`、`/config/`等等。

另一方面，我们需要有一个包含常见……

# 默认凭据

如前所述，在本节中，有些应用程序在安装时具有默认凭据。其中一些是因为它们不是直接安装的，而是使用操作系统的软件包，或者是其他应用程序的一部分。例如，一些**集成开发环境**（**IDE**）在其安装中具有 Web 或应用程序服务器，用于测试目的。

此外，还有一些测试工具或包使用**数据库管理系统**（**DBMS**），但这些系统存在漏洞或默认访问权限暴露它们。

经过一些侦察之后，您将能够了解应用程序、服务器和技术背后的应用程序，并且只需搜索默认密码一词即可找到正确的凭据，或者访问存储它们的网站，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/61fd3d16-a956-4669-9a34-660beeaeaea5.png)

要识别正确的内容，您只需将它们作为 Intruder 中的有效负载加载并启动应用程序，我们将在本章中更详细地介绍。

# 不受信任的 HTTP 方法

HTTP 协议有不同的方法，通常我们用来了解`GET`、`POST`和`CONNECT`方法，因为它们是最常用的。然而，还有其他方法可以用来获取有关服务器的信息，上传和删除文件到应用程序中，或者获取调试信息。

使用 Burp Suite 测试这些方法很容易。只需从代理中修改请求如下：

```
OPTIONS / HTTP/1.1 
```

实际上，`OPTIONS`是一种方法，允许我们知道 Web 服务器上允许使用哪些方法。可能出现的方法有`PUT`、`DELETE`、`TRACE`、`TRACK`和`HEAD`。利用这些方法超出了本书的范围，因为很多事情取决于应用程序的环境。

# 使用不安全的反序列化来执行操作系统命令

序列化是一种过程，在一些编程语言中，用于将对象的状态转换为字节流，这意味着 0 和 1。反序列化过程将字节流转换为内存中的对象。

在 Web 技术中，还有更简单的情况，例如，常见的反序列化是将 JSON 格式转换为 XML 格式。这很简单，但真正的问题在于使用本机对象的技术，例如 Java，在这些技术中，我们可以直接在内存中进行调用。

事实上，漏洞发生在应用程序对无效输入进行反序列化时，创建了一个可能对应用程序有潜在风险的新对象。

# 利用漏洞

想象一下，您有一个使用 pickle 库的易受攻击的应用程序。这是一个实现不同函数进行序列化和反序列化的 Python 模块。然而，这个模块本身并没有实现保护。它需要开发人员进行验证实现。看看以下易受攻击的代码片段：

```
import yaml 
with open('malicious.yml') as yaml_file: 
contents = yaml.load(yaml_file) 
print(contents['foo'])
```

这段代码读取一个 YAML 文件而没有任何验证。恶意用户可以输入一个可能执行其他操作的输入，例如一个命令，如下所示：

```
POST /api/system/user_login HTTP/1.1 Host: 192.168.1.254 User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) ...
```

# 利用加密漏洞

除了利用与加密相关的漏洞外，Burp Suite 还允许用户进行分析以检测弱算法。

要执行此分析，我们需要创建一个捕获。这个捕获只是一个导航，我们在应用程序中登录和注销，以创建会话、令牌和 ID。想法是尽可能创建最大的捕获，以便有一个样本。

创建捕获后，在 Burp Suite 中使用正常历史记录，转到 Sequencer 工具，然后点击“立即分析”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/03e9e9b1-b2a1-4ef3-84fd-73d24a87557d.png)

在这里，您可以看到最终分析，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/710838f0-a0b1-499e-b00c-b48997aba3b8.png)

最终分析

现在，您可以根据熵、字符集和概率来确定所使用的算法是否弱。

# 暴力破解 HTTP 基本身份验证

基本身份验证是一种在内部环境中广泛使用的访问控制类型，用于限制网站中受限区域的访问。它有很多弱点，包括以下内容：

+   基本身份验证以明文发送信息。这意味着恶意用户可以拦截客户端发送到服务器的信息并提取凭据。

+   密码受 Base64 编码保护。这并不意味着密码被加密；任何人都可以使用解码器获取明文密码，就像 Burp Suite 中包含的解码器一样，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/85bb0cab-7106-4191-8568-83344cce6d0c.png)

# 使用 Burp Suite 进行暴力破解

我们将展示如何使用 Burp Suite 攻击基本身份验证。想象一下，我们有一个用于在家中提供互联网的家用路由器。这些设备中的大多数使用基本身份验证。因此，访问 URL 路由器和 Web 浏览器将显示一个窗口，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/9786bec3-220c-4572-a1f3-8f62a11a0628.png)

现在，配置 Burp Suite 以拦截发送到服务器的凭据，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/84489aa7-dd9e-45af-a60a-7740e03e0967.png)

在这里，您可以看到标头中的参数授权。因此，复制分配给参数的值，并将其粘贴到解码器部分以了解其含义。请记住，基本身份验证使用 Base64 编码来保护信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/cade33a9-097a-4b08-98c7-bff5620e4eae.png)

现在，我们知道基本身份验证使用的结构是`user:password`，因此为了暴力破解控制，我们需要按照这个结构发送凭据。我们将使用潜在用户和密码的列表，并将它们存储在 TXT 文件中，以便将它们用作有效负载。我建议您在常见服务中寻找泄露的密码，如 Facebook、LinkedIn 和 Yahoo，因为它们是真实的密码，而不仅仅是常见的词典，所以您更有可能能够访问受限区域。这里有一个小例子列表如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/2d9616fc-e501-42e8-b841-0f126bd9f903.png)

现在我们有了密码和用户列表，点击鼠标的辅助按钮，将原始请求发送到入侵者工具：

1.  首先，我们将选择“集群炸弹”选项来发送我们的请求。由于我们只有一个列表，我们希望 Burp Suite 测试列表中的所有可能组合，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/58ed6b25-9667-41f6-8847-73ea5952a0ee.png)

1.  然后，我们将选择授权参数分配的值作为通配符。然而，诀窍是在同一个参数上创建通配符，因为我们必须为密码和用户插入值，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/0efb4232-4d7f-4ab6-afc6-ca48a1fd02e8.png)

1.  然后，转到有效负载选项卡，在这里，我们将选择我们的列表。然而，最重要的一步是，我们需要使用基本身份验证的结构对我们的输入进行 Base64 编码。首先，在有效负载集部分，选择使用两个有效负载集。我们将使用相同的列表并不重要，但我们需要将它们用作单独的有效负载，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/30b18b92-3434-4471-9fad-3e86092271d5.png)

1.  然后，选择第一个有效负载列表，在第 1 个位置的文本框分隔符中添加`:`字符。这将在第一个值之后插入，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/3f342fc1-fea5-4b0e-9685-7db3a6d3a056.png)

1.  然后，点击“添加有效负载处理规则”来对有效负载进行编码。在这里，选择列表中的“编码”选项，然后选择 Base64 编码。通过这种配置，我们所有的有效负载都将以 Base64 编码发送，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/2864f3a8-aed5-4db2-8b07-84dbe5c089de.png)

1.  现在，返回到有效负载集部分，并选择第二个位置。在这里，选择用户和密码列表，但在文本框中留空第 2 个位置的文本框分隔符。还要创建规则来对有效负载进行编码。返回到位置选项卡，然后点击开始攻击，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/4b901b74-620c-4ad4-916d-fbd1089a08fa.png)

当入侵者显示 HTTP 错误代码 200 时，这意味着组合是正确的。

# 暴力破解表单

如前所述，基本身份验证由于其安全问题而不可取。更常见的是使用身份验证表单。这些身份验证表单包括 HTML 或其他客户端技术表单，将其传递到后端，那里处理凭据以确定用户是否有权访问资源。

重要的是要注意，确定用户是否有效的所有处理都将在后端进行。有时，在客户端使用结构验证是可取的，只是为了限制错误尝试的次数。

# 使用 Burp Suite 进行自动化

要在表单上执行暴力破解，我们将停止上传凭据到应用程序的请求，如下面的代码块所示，用户正在访问登录部分：

```
POST /api/system/user_login HTTP/1.1 
Host: 192.168.1.254 
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0 
Accept: application/json, text/javascript, */*; q=0.01 
Accept-Language: en-US,en;q=0.5 
Accept-Encoding: gzip, deflate 
Referer: http://192.168.1.254/ 
Content-Type: application/x-www-form-urlencoded; charset=UTF-8 
X-Requested-With: XMLHttpRequest 
Content-Length: 210 
Connection: close 
Cookie: SessionID_R3=CZY02VcjdwIxtH3ouqkBUrgg7Zu2FICRqkEP5A0ldSiF5FQ67nioWM30PzyYGv9jMQk0a1lvs2lrv1fMX3wqGXSZu176PYZeEDCDxbA0rbAESGMeXNw0PEc0GZ7n2h0; username=admin 

{"csrf":{"csrf_param":"ugObcytxp0houtiW8fxOsDYc074OxoV","csrf_token":"nOyb061GDehdAk04E1PG8qBGWTNwNr0"},"data":{"UserName":"admin","Password":"admin"}}
```

在这个请求中，我们可以确定应用程序接收用户名和密码的参数。因此，使用鼠标的辅助按钮，点击弹出菜单，并选择发送到 Intruder。在这里，我们将在参数所在的位置创建通配符。请注意，这不是一个常见的`POST`请求，其中参数被分配为值。在这里，我们有一个不同的结构，但它的工作方式相同。

在这种情况下，应用程序没有使用任何编码。我们只需将负载配置为正常列表，选择集群炸弹作为攻击类型，并使用我们之前的列表，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/0dd09b83-fee8-4b1e-b9dd-5ea9572a6971.png)

最后，点击开始攻击。Intruder 将启动一个窗口，我们可以在其中看到结果。有一些应用程序，当凭据不正确时，会以 302 错误代码响应，将用户重定向到登录页面。在这种情况下，应用程序总是以 200 错误代码响应，因此需要详细分析响应。为了简单起见，我们可以检查列长度，并寻找指示不同结果的值的变化，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/30af46b5-ca2e-440b-8951-c5d8f2bb8488.png)

# 绕过文件上传限制

许多应用程序允许用户上传文件。管理这些文件有不同的方式：一些应用程序直接将文件作为二进制文件上传，而其他应用程序对文件进行编码以减小大小并在数据库中进行管理。让我们探讨如何修改应用程序建立的文件限制。

# 绕过类型限制

当一个应用程序允许您上传文件时，通常开发人员知道允许上传哪种类型的文件，因此验证恶意用户不能上传其他类型的文件非常重要。验证这一点的常见方法是使用文件扩展名。因此，如果一个应用程序管理文档，也许开发人员允许 PDF 文件和 DOCX 文档，但这安全吗？

文件扩展名不是应用程序需要进行的唯一验证。恶意用户可以上传带有有效扩展名的恶意文件；例如，传播恶意软件。

首先，我们将使用一个名为 Metasploit 的工具创建一个恶意 PDF。Metasploit 是一个利用框架，允许攻击漏洞，主要是基础设施；但它也有辅助模块来执行一些任务，比如创建带有嵌入恶意代码的二进制文件。您可以在[`www.metasploit.com/`](https://www.metasploit.com/)上获取 Metasploit 的副本。

要安装它，您只需要在一个目录中解压文件。要创建 PDF，请按照以下步骤操作：

1.  使用`adobe_utilprintf`工具，它将把我们的 PDF 转换为恶意 PDF。您可以使用任何 PDF 来做到这一点。

1.  选择要使用的 PDF 来使用指令集。

1.  选择要使用的负载。Metasploit 有不同的负载来执行文件执行时的操作，或者在这种情况下，打开时的操作。最简单的负载是从打开文件的计算机到远程计算机创建连接。这是一个反向 shell。

1.  设置远程 IP 地址和端口，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/6394fa52-92a2-4751-a5c5-e9bb597acd5f.png)

1.  选择所有选项后，使用 exploit 指令创建文件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/4daf1e92-6adf-48a8-8cfd-21cc4f2f3e09.png)

打开您正在使用 Burp Suite 评估的应用程序，并拦截一个用户被允许上传文件的部分的请求。想象一下我们有以下易受攻击的请求：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/12f9c3dc-896d-4d5d-824b-cd472e6dc290.png)

一个易受攻击的请求示例

在这个请求中，我们可以看到有两个限制。首先，我们有一个大小限制，这是为了避免上传最大的文件。我们可以在以下行中看到这个限制：

```
Content-Type: multipart/form-data; boundary=---------------------------12057503491 

-----------------------------12057503491 
Content-Disposition: form-data; name="name" 
```

因此，如果我们修改这些值，就有可能上传比用户预期的更大的文件。

另一个限制是文件，如下所示：

```
test_by_destron23.pdf 
-----------------------------12057503491 
```

该应用程序正在等待特定的扩展名，如果我们上传另一个文件，比如我们修改过的 PDF 文件，看看会发生什么。

您将看到文件是以二进制方式上传到服务器的。在这一点上，服务器有一个恶意的 PDF 文件，其他用户可以下载，这将导致感染。为了确认文件是否相同，您可以下载它并将下载的文件与您自己的文件进行比较。

对于这一点的结论是，文件只是应用程序中的另一种输入类型，您可以像表单中的输入一样使用 Burp Suite 来修改它。

# 总结

在本章中，我们学习了 Burp Suite 用于利用不同类型漏洞的常规工具。特别是，我们利用 SSRF 和 XSPA 来执行命令，提取信息并在内部网络中执行任务。此外，我们还回顾了这些漏洞的起源。我们回顾了 IDOR 漏洞，学会了如何手动利用它，以及如何使用 Intruder 自动化其利用。接下来，我们回顾了一些与配置相关的漏洞；它们可能是关键的，也可能不是关键的，以及我们如何自动化其中一些漏洞。

我们还进行了暴力破解，以寻找两种不同类型认证的有效凭据。我们创建了一个恶意的 PDF 文件，并学会了如何将其上传到网站上...


# 第十章：编写 Burp Suite 扩展

其他 HTTP 代理提供了良好的性能，但是 Burp Suite 无疑是最好的工具，因为它具有扩展功能。正如我们在前面的章节中所看到的，扩展添加了许多功能，因此它们可以专注于特定的问题。

创建扩展的能力为用户在自动化测试活动中提供了极大的帮助。Burp Suite 支持 Java、Python 和 Ruby 来开发扩展，因此它在为开发人员提供便捷访问方面非常灵活。

在本章中，我们将回顾新扩展的开发过程，并提供一些在我们的 Burp Suite 安装中进行此操作的技巧和提示。

在本章中，我们将涵盖以下主题：

+   设置开发环境

+   编写 Burp Suite 扩展

+   执行扩展

# 设置开发环境

要开发自己的扩展，可以使用 NetBeans 或 Eclipse 等开源**集成开发环境**（**IDE**）。选择最适合自己的 IDE。在这种情况下，我们将使用 NetBeans：

1.  转到 NetBeans 网站（[`netbeans.org/`](https://netbeans.org/)）并下载最新版本。不需要安装，因为 NetBeans 是用 Java 开发并作为 JAR 文件分发的；只需解压下载文件并单击 netbeans-bin 图标，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/18960f26-1eda-4543-82e8-4e5ca45ced02.png)

1.  在开始使用 NetBeans 之前，转到[`www.oracle.com/technetwork/java/javase/downloads/`](https://www.oracle.com/technetwork/java/javase/downloads/)并...

# 编写 Burp Suite 扩展

Burp Suite 扩展的基本类结构如下代码所示，由 PortSwigger 提供：

```
package burp; 

public class BurpExtender implements IBurpExtender{ 
    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks){ 
        // your extension code here 
    } 
} 
```

这基本上是用于创建所有 Burp Suite 扩展的类定义。现在，让我们开始修改代码。

# Burp Suite 的 API

请记住，所有扩展都是通过采用 PortSwigger 提供的结构（如前所示）作为代码基础来开发的，您的扩展的入口点如下：

```
void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks); 
```

如果要调用自己的扩展，需要使用以下方法：

```
callbacks.setExtensionName (Your extension name); 
```

以下代码显示了字节实用程序。它们对于管理字符串、搜索子字符串、编码、解码等非常有用：

```
int indexOf (byte[] data, byte[] pattern, boolean caseSensitive, int from, int to); String bytesToString(byte[] data); byte[] stringToBytes(String data); String urlDecode(String data); String urlEncode(String ...
```

# 使用扩展修改用户代理

现在让我们分析一下扩展的代码，以修改 HTTP 请求中的用户代理，使用 PortSwigger 提供的基本结构。

# 创建用户代理（字符串）

我们需要修改用户代理的第一件事是使用替代用户代理。在代码的下一部分中，我们创建了一个默认用户代理列表，用于在扩展中使用；扩展还提供了使用包含字符串的 XML 文件的选项，如下所示：

```
 public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) { extCallbacks = callbacks; extHelpers = extCallbacks.getHelpers(); extCallbacks.setExtensionName("Burp UserAgent"); extCallbacks.registerSessionHandlingAction(this); printOut = new PrintWriter(extCallbacks.getStdout(), true); printHeader(); /* Create the default User-Agent */ bUserAgents.add("Current Browser"); bUserAgentNames.put("Current Browser", "Current Browser"); /* ...
```

# 创建 GUI

PortSwigger 简化了将扩展与 Burp Suite 集成以创建新的 Burp Suite 选项卡的方式，这些元素只需要几行代码。

首先，我们需要在 Burp Suite 窗口中为我们的扩展定义一个新选项卡，如下所示：

```
bUAPanel = new JPanel(null); 
JLabel bUALabel = new JLabel(); 
final JComboBox bUACbx = new JComboBox(bUserAgents.toArray()); 
JButton bUASetHeaderBtn = new JButton("Set Configuration"); 
```

我们还需要创建一个框，用于放置所有选项，以及每个选项的标签，如下所示：

```
bUALabel.setText("User-Agent:"); 
bUALabel.setBounds(16, 15, 75, 20); 
bUACbx.setBounds(146, 12, 310, 26); 
bUASetHeaderBtn.setBounds(306, 50, 150, 20); 

bUASetHeaderBtn.addActionListener(new ActionListener() { 
    public void actionPerformed(ActionEvent e) { 
    newUA = bUserAgentNames.get(bUACbx.getItemAt(bUACbx.getSelectedIndex())); 
    printOut.println("User-Agent header set to: " + newUA + "\n"); 
    } 
}); 
```

此外，需要补充说明的是，没有默认值的应用程序或扩展在打开时无法向用户呈现，如下所示：

```
bUALabel.setText("User-Agent:"); 
bUALabel.setBounds(16, 15, 75, 20); 
bUACbx.setBounds(146, 12, 310, 26); 
bUASetHeaderBtn.setBounds(306, 50, 150, 20); 

bUASetHeaderBtn.addActionListener(new ActionListener() { 
    public void actionPerformed(ActionEvent e) { 
    newUA = bUserAgentNames.get(bUACbx.getItemAt(bUACbx.getSelectedIndex())); 
    printOut.println("User-Agent header set to: " + newUA + "\n"); 
    } 
}); 
```

# 操作

前面的代码块显示了所有扩展内容和图形界面，但以下行显示了扩展本身的操作：

首先，我们设置初始变量和组件，如下所示：

```
 @Override public String getTabCaption() { return "Burp UserAgent"; } @Override public Component getUiComponent() { return bUAPanel; } @Override public String getActionName(){ return "Burp UserAgent"; } @Override public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) { IRequestInfo requestInfo = extHelpers.analyzeRequest(currentRequest); List<String> headers = requestInfo.getHeaders(); String reqRaw = new String(currentRequest.getRequest()); String reqBody = ...
```

# 发现认证弱点

在服务、端口和技术检测之后，下一步是导航和了解应用程序的流程。在这里，我们将重点放在认证部分。

1.  因此，打开 Burp Suite，并在配置 Web 浏览器后，转到[`www.mercadolibre.com.mx/`](https://www.mercadolibre.com.mx/)。

1.  正如我们之前提到的，Mercado Libre 是一个大型在线零售商，是卖家和买家之间的中间商，提供包裹服务和金融服务。

1.  在登录部分输入有效的凭据，以了解其工作原理。

1.  关于认证流程的简要介绍在这里：

+   用户输入电子邮件地址或用户名和密码

+   用户已登录

+   如果用户关闭会话，下次进入登录部分时，他们只需要输入密码，因为他们的用户名已经被占用。

1.  让我们检查登录请求：

```
POST /jms/mlm/lgz/msl/login/H4sIAAAAAAAEAzWNQQ7DIAwE_-JzFO4c-xHkEidBxQUZR6SK8veaSj3ueHd8QS5begf9VAIPdNacYlKYoGbUtQiHtNiBs6GWlP6RRwUFmZSkgb-GaKPlQTYaKpWDrIOH7mHNpRv6vTK2FQu7am3eud77zCQRl5LTU2iOhWc-HdwTrNg0qGB8gR---wvSIukMrwAAAA/enter-pass HTTP/1.1
    Host: www.mercadolibre.com
    User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Referer: https://www.mercadolibre.com/jms/mlm/lgz/login?platform_id=ml&go=https%3A%2F%2Fwww.mercadolibre.com.mx%2F&loginType=explicit
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 655
    Connection: close
    Cookie: msl_tx=1UqiRoqpEUxsLE3lBOswwkkNK9jF03Mi; _ml_ci=923720559.1550729012; orguseridp=21657778; _d2id=9db3c122-55e2-4c10-b17c-b06211ac246f-n; ftid=8MoAWQIdUk07TQENB2UnuCGnB5WY5qMo-1550733044507; dsid=e71d14ce-5128-453c-b586-60e5212fa4cf-1550733049231
    Upgrade-Insecure-Requests: 1

    user_id=vendetta%40gmail.com&password=H3r3154p4555w0rd&action=complete&dps=armor.bdecc76bc2e60160f1d8464959d69f4d2d9119c3f039ee75cb69bd697920e46f90877723d71324ebedade124738cd189e161d2b655c7fa985521cc6e4c2ccdc75231619b1a24f5e526cee284f62d303f.86588a3c22fdc3e5adde058557e1028e&rbms=1UqiRoqpEUxsLE3l&gctkn=03AOLTBLQTrF3tOZ-Md6XA6e3MFfVpMq2U2eZ1MOnZMtRddlltoxecbHaOtRdLrSPRUXTVGmJQ3nRRhvIcZa_4fY1KhgJ4vN2xg5DaG5ZeXjWuC-KIg59R0WDaRU9cyX7Nz1yaQOgVfvCGqf-buiapfJ5cVN3uureFwrxgegqBZwHAsHQBwOxSQ9hXZlU0V6ZHpWV7PwH_1N65MlH4HhvjGOgaBPPG5XJ69Nsa1eErb1KZG5s5ByeMbOeCgX6uTJzglJYzpxUmygRJpiIvN7ypFLdgnKNC7UuemvkGZwcOgbDQgmjdx5vifkJmlmNIsT2tEoXJw2wWJlBfi0cBkReEX61RoA4C91heOQ&kstrs=  
```

让我们也来看看这个登录请求的响应：

```
    HTTP/1.1 302 Found
    Content-Type: text/html; charset=utf-8
    Content-Length: 328
    Connection: close
    Date: Thu, 21 Feb 2019 07:13:56 GMT
    Server: Tengine
    Cache-Control: private, max-age=0, no-store
    Location: https://auth.mercadolibre.com.mx/session/replicator/1550733236355-bqp0ov4guqf0rkcp9qjp34r63e61r6r6?go=https%3A%2F%2Fwww.mercadolibre.com.mx%2F
    Set-Cookie: ssid=ghy-022103-1lPFbjVoxrDURTxzC3azejgqjE9O3a-__-21657778-__-1645341236209--RRR_0-RRR_0; Max-Age=94607999; Domain=.mercadolibre.com; Path=/jms/mlm/; Expires=Sun, 20 Feb 2022 07:13:55 GMT; HttpOnly; Secure
    Set-Cookie: orgid=CS-022103-03c45ab2ac839ae3d7083c377cdce53010e242e00d3b5fd587459dcdb9c93fa8-21657778; Max-Age=94607999; Domain=.mercadolibre.com; Path=/jms/mlm/; Expires=Sun, 20 Feb 2022 07:13:55 GMT
    Set-Cookie: orghash=022103-MLMw1s3mS30KNKIoHNpkHJpGxvOlzu__RRR_0__RRR_0-21657778; Max-Age=94607999; Domain=.mercadolibre.com; Path=/jms/mlm/; Expires=Sun, 20 Feb 2022 07:13:55 GMT; HttpOnly
    Set-Cookie: orgapi=CS-022103-69fb38cb3696712af34d6ddd57dc20cfb93a9a77a8d4d2490c82c20d7b7ff6ebc6b411d78e3f5f633a6e653efdd84859895e27e3d79c1da956c6649264d08370-21657778; Max-Age=94607999; Domain=.mercadolibre.com; Path=/jms/mlm/; Expires=Sun, 20 Feb 2022 07:13:55 GMT
    Set-Cookie: orguserid=0Z07t79hhh7; Max-Age=94607999; Domain=.mercadolibre.com; Path=/jms/mlm/; Expires=Sun, 20 Feb 2022 07:13:55 GMT
    Set-Cookie: orguseridp=21657778; Max-Age=94607999; Domain=.mercadolibre.com; Path=/jms/mlm/; Expires=Sun, 20 Feb 2022 07:13:55 GMT
    Set-Cookie: orgnickp=AUGUSTO_VENDETTA; Max-Age=94607999; Domain=.mercadolibre.com; Path=/jms/mlm/; Expires=Sun, 20 Feb 2022 07:13:55 GMT
    Set-Cookie: uuid=0; Max-Age=0; Domain=.mercadolibre.com; Path=/jms/mlm/; Expires=Thu, 21 Feb 2019 07:13:56 GMT
    Set-Cookie: sid=0; Max-Age=0; Domain=.mercadolibre.com; Path=/jms/mlm/; Expires=Thu, 21 Feb 2019 07:13:56 GMT; HttpOnly
    Vary: Accept, Accept-Encoding
    X-Content-Type-Options: nosniff
    X-DNS-Prefetch-Control: on
    X-Download-Options: noopen
    X-XSS-Protection: 1; mode=block
    X-Request-Id: 445dd144-db49-404e-83e9-7e081487326c
    X-D2id: 9db3c122-55e2-4c10-b17c-b06211ac246f
    Content-Security-Policy: frame-ancestors 'self'
    X-Frame-Options: SAMEORIGIN
    X-Cache: Miss from cloudfront
    Via: 1.1 ae22d429a3be7ab1d9089446772f27a7.cloudfront.net (CloudFront)
    X-Amz-Cf-Id: RyU3aIakL8jke184nvlIt6Ghu0-MfmJLlVYXBw9BxivAF3F9yH9_Mg==

    <p>Found. Redirecting to <a href="https://auth.mercadolibre.com.mx/session/replicator/1550733236355-bqp0ov4guqf0rkcp9qjp34r63e61r6r6?go=https%3A%2F%2Fwww.mercadolibre.com.mx%2F">https://auth.mercadolibre.com.mx/session/replicator/1550733236355-bqp0ov4guqf0rkcp9qjp34r63e61r6r6?go=https%3A%2F%2Fwww.mercadolibre.com.mx%2F</a></p>

```

使用上述代码块，我们可以检测到以下内容：

+   该应用程序正在使用负载均衡器或反 DDoS 服务。我们可以在响应中看到请求是如何被重定向到一个确定的服务器的。

+   该应用程序使用令牌来跟踪请求；可能无法利用 CSRF 等漏洞。

+   该应用程序具有 XSS 保护，可以避免信息的提取。例如，使用 JavaScript 提取用户的会话。

+   该应用程序包括一个 SAMEORIGIN 策略。在本书中，我们还没有涉及这个。这个控制用于避免来自外部实体的执行操作。

+   用户凭据被发送到请求的主体中。

+   该应用程序使用 XML 格式。这意味着该应用程序正在使用内部 API。

现在，我们有一些关于认证流程的信息。在实际评估中，您需要映射整个应用程序和完整的应用程序流程。

现在，我们将审查与认证相关的问题。

# 执行扩展

在编写完扩展后，启动 Burp Suite 应用程序，然后单击 Run | Run Project。应用程序将启动，并在其中运行我们的扩展。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/efaae54f-63b4-4347-990e-5ea069a60fb0.png)

对于这个扩展，您需要创建一个会话处理并在用户代理选项卡中配置选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/b44c15c5-2c28-487b-9a4b-0542cd7963e8.png)

如您在以下截图中所见，该应用程序运行时没有出现错误：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/f3c97148-1ff9-4b05-98d4-f5159f0f97aa.png)

如果您想要...

# 总结

在本章中，我们分析了如何创建我们自己的扩展以及 PortSwigger 提供的不同函数和方法，这不仅帮助我们创建了一个新的扩展，还向我们展示了如何修改现有的扩展，以适应我们的要求。

下一章将介绍一个真实案例，说明一个大型在线零售商是如何因为认证实现的破坏而受到影响的。


# 第十一章：突破大型在线零售商的身份验证

在之前的章节中，我们回顾了如何检测许多类型的漏洞，以及如何利用它们。我们还回顾了如何使用各种扩展，以及如何开发我们自己的扩展。在本章中，我们将总结前几章的所有概念，以评估正在生产中的应用程序，并尝试突破其身份验证。

我们将在本章中涵盖以下主题：

+   关于身份验证的事项

+   大型在线零售商

+   执行信息收集

# 关于身份验证的事项

正如你在第七章中所记得的，*使用 Burp Suite 检测漏洞*，影响身份验证控制的问题如下：

+   凭证的弱存储

+   可预测的登录凭证

+   会话 ID 暴露在 URL 中

+   会话 ID 容易受到会话固定攻击的影响

+   错误的超时实现

+   会话在注销后没有被销毁

+   通过不安全的通道发送敏感信息

现在，使用 Burp Suite，我们将分析所有这些。

# 大型在线零售商

在线零售商的列表很长，但以下是一些较受欢迎的：

+   eBay（所有地区变体）

+   Mercado Libre

+   亚马逊

我们将以其中一个作为例子进行分析。请记住，本章中使用的所有信息都是公开的；我们不会公开这些应用程序的任何公开或私人漏洞，解释也不会影响应用程序的功能。

# 执行信息收集

我们将开始收集有关目标的信息。检测特定应用程序中使用的技术以及确定潜在的安全问题的最基本方法是首先浏览整个应用程序，使用正常流程，检测并记录应用程序的每个入口点，并将我们感兴趣的不同 URL 添加到**目标**工具中的**范围**选项中。

# 端口扫描

在真实的评估中，评估应用的人或公司与应用的所有者之间建立了一项协议。这是检测服务所涉及的第一步。

通常使用 Nmap（[`nmap.org/`](https://nmap.org/)）来执行此任务，这是一个用于检测远程主机上运行的端口和服务的命令行工具。使用 Nmap 并不复杂；你只需在命令行上输入`nmap`，就可以看到我们有哪些不同的选项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/a52f2146-d715-4574-bebf-643722baa56a.png)

要对主机执行标准扫描，我们可以使用以下命令：

```
nmap -vv -sV -O -Pn -p0-65535 -oA nmap_[IP] ...
```

# 身份验证方法分析

你应该逐个分析应用程序的问题，以确定它是否容易受到攻击，就像下面的章节中所解释的那样。

# 凭证的弱存储

应用程序以加密的方式存储会话 ID，因此不容易被提取。此外，会话 ID 与一个以上的令牌结合，cookie 也受到保护，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/9fd5d310-2548-47ff-8295-2f3fef7b6293.png)

# 发现盲目 SQL 注入

我们将要分析的 URL 是[www.dhl.com](http://www.dhl.com)。这是国际页面，但如果你查看地区网站，它们是相似的，所以可能一个网站的漏洞会复制到其他网站。这经常发生在许多在不同国家有业务的公司。有时候公司在不同国家有不同的代表，但是网站应用是一样的。

为了确定[dhl.com](http://dhl.com)是否存在 SQL 注入，我们将进行三种不同的分析：

+   自动扫描

+   SQLMap 检测

+   入侵检测

# 可预测的登录凭证

用户使用用户名或电子邮件登录应用程序，因此凭证是不可预测的。

# 会话 ID 暴露在 URL 中

通过查看历史工具，我们可以看到 URL 中暴露了一些令牌和会话，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/50d480e0-6c02-47b1-8575-27a66ed8213a.png)

然而，该应用程序并不仅仅使用一个令牌，因此仅有一个令牌是没有用的。实际上，在 URL 中发送的令牌之一是一个请求跟踪器，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/97a734de-9032-42d4-a691-12d57cb44fad.png)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/f348b9a0-bfaf-43ad-ad49-934269eff7b0.png)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/38d2a7f7-cf3d-4bda-9163-10d3ead5edde.png)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/1d89c217-a584-410b-b1d2-6092cc19732f.png)

结论是，尽管 URL 中暴露了令牌，但它们是不可利用的。

# 会话 ID 容易受到会话固定攻击的影响

1.  以正常方式在浏览器中打开用户会话。

1.  然后，为完全不同的用户打开另一个会话。

1.  现在，使用**代理**工具拦截一个请求，并修改用户信息以尝试访问第二个用户的信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/1cd10312-3a41-4268-b0a6-69058ee9a794.png)

当您打开[`www.mercadolibre.com.mx/`](https://www.mercadolibre.com.mx/)网页时，您会注意到应用程序显示了用户的第一条信息。因此，它不容易受到会话固定攻击。

# 注销后会话并没有被销毁。

使用注销选项关闭会话，然后转到**历史记录**，查找用户登录时进行的请求。右键单击**发送到重复器**，然后在不修改任何值的情况下，单击**Go**重新发送请求，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/84d70dbf-a882-4b31-8a4b-76bbbc0ac643.png)

结果是应用程序显示出未登录用户的状态。因此，该应用程序不容易受到攻击。

由于我们使用了一个墨西哥的网站进行身份验证，所以截图中的一些文本是西班牙语。

# 通过不受保护的通道发送的敏感信息

仅使用被动扫描，也就是没有侵略性的操作，Burp Suite 就检测到用户可以强制应用程序在不受保护的通道中使用。这意味着用户可以强制使用 HTTP 协议而不是 HTTPS 协议，并以明文发送信息。这可能会被恶意用户利用，结合其他漏洞来窃取用户信息，如下例所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/d6ba5748-8939-42a3-b7ac-dee9ff803d3e.png)

这个漏洞得到了确认。

# 总结

在本章中，我们展示了对一个真实应用程序的分析。执行的任务包括协议和服务检测、请求和提交分析以及漏洞检测。

在下一章中，我们将使用最流行的快递公司之一：DHL，执行与本章讨论的相同活动。


# 第十二章：从大型航运公司中利用和外泄数据

所有公司、企业和行业都使用技术，以及他们使用技术的方式是不同的。对于零售商来说，他们的网站应用程序与在线银行应用程序不同，零售商的网站有着持续服务和高性能等优先事项，而在线银行应用程序需要高度安全。当然，所有这些应用程序都有共同点，但是由于不可能应用所有的控制，最重要的是优先考虑真正的需求。

在本章中，我们将讨论另一个场景，一个航运公司。我们将执行与过去示例中相同的活动，但这次使用最受欢迎的航运公司之一：DHL。

我们将涵盖...

# 自动扫描

检测 SQL 注入等漏洞的最简单方法是使用 Burp Suite 的扫描器：

1.  要启动扫描，打开 Burp Suite，转到主仪表板，然后单击新扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/a5bf5de4-3054-4c13-96c6-ccd5b5821134.png)

有一个我们之前没有探索的选项，用于在扫描期间控制范围。想象一下，您的范围不是整个 DHL 网站——只是[www.dhl.com](http://www.dhl.com)，但还有其他应用程序，比如[mydhl.dhl.com](http://mydhl.dhl.com)和[intranet.dhl.com](http://intranet.dhl.com)，等等。

1.  为了避免这种情况，Burp Suite 可以扫描这些其他应用程序；点击详细范围配置。在这里，我们将看到两个名为包括前缀选项和排除前缀选项的选项卡。转到第二个选项卡，排除前缀选项，并输入我们不想测试的应用程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/27828ec0-db85-461d-a85d-f977eaf5e85d.png)

正如我们在前面的屏幕截图中所看到的，不需要添加所有的 URL。

1.  如果我们想对范围进行更精确的选择，我们可以选择单个 URL，并通过单击使用高级范围控制，在范围中添加我们想要测试或不想测试的每个 URL，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/423fc0e5-ba34-4295-bc19-79ae0274c648.png)

Burp Suite 的扫描器为我们提供了更多控制扫描的选项。

1.  点击扫描配置。在这里，您可以配置有关扫描器如何执行应用程序发现以及如何执行安全测试的选项。

1.  点击添加新的，Burp Suite 将启动一个新窗口，可以在其中创建一个新规则，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/39959ffd-2ca7-4918-9f4a-eb6d02cd6c04.png)

1.  在审计优化中，我们可以定义评估的速度。我建议选择低速。这是为了避免入侵检测系统、负载均衡器和其他可能阻止扫描器的安全和网络设备。如果您在一个 QA 环境中进行测试，在这种环境中，您可以完全控制并直接访问应用程序服务器，而没有任何网络安全控制，您可以选择快速。

1.  下一部分，报告的问题，是用于选择扫描策略。Burp Suite 默认情况下已经按类别划分了可能的问题。但是，您也可以按类型选择。例如，对于这个练习，我们只选择 SQL 注入漏洞。这对于修复或验证错误非常有用，例如：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/6638210a-8da9-4588-8c81-468cf17a18b4.png)

1.  在测试期间处理应用程序错误选项卡中，可以配置 Burp Suite 在检测到错误时采取的操作。这些选项可以帮助我们在必要时停止扫描。例如，目前通常有一些应用程序托管在云服务中。云服务非常擅长阻止扫描活动，因此很可能如果我们正在测试托管在云中的网站，在测试几分钟后，我们的 IP 地址将被阻止，Burp Suite 只会收到超时错误。我们可以在出现这种类型的错误时停止扫描。

1.  在插入点类型中，可以定义要注入测试字符串的位置。例如，您可以将测试限制在 URL 参数、cookies 等。根据我的经验，最好测试所有可能的入口点。

1.  忽略插入点是一个有趣的选项，当我们想要限制应用程序生成的噪音或者减少测试数量时，这个选项可能会很有用。

您还记得在 Intruder 中可以选择要测试的参数吗？嗯，这与那个类似。如果我们有跟踪令牌或会话 ID 存储在变量中，那么测试它并不是一个好主意，因此我们可以使用这个选项来跳出范围：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/c5f01202-9d19-4a93-8e83-de51f20a0438.png)

配置选项后，点击“保存”，然后点击“确定”开始扫描。如果您认为这可能是一个需要应用并且将需要更多类型的应用程序的策略，您可以将其保存为库并重复使用。扫描结果将显示在右侧部分。

# SQLMap 检测

现在，我们将使用 SQLMap 来检测和利用 DHL 网站中的 SQL 注入。

# 寻找入口点

DHL 应用程序看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/fc284b05-f4ed-440d-9892-f8dac76fb9ec.png)

我们可以立即看到不同的输入要测试，例如搜索栏和跟踪框，但是看一下以下请求：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/60420cc8-e828-4d9a-b3d1-e39c80df46b0.png)

在这个请求中，我们可以看到一些变量，但要确定哪些可以用作注入点，我们需要分析它们的行为，如下所示：

+   `brand`：看起来应用程序支持一些公司，所以也许“DHL”是目录的一部分，可能容易受到注入攻击。

+   `AWB`：这个变量是一个跟踪号码，用于查找包裹的位置。很明显这是一个很好的入口点。

+   `AWBS_crossrefpar1_taskcenter_taskcentertabs_item1229046233349_par_expandablelink_insideparsys_fasttrack`：它看起来也像是一个 ID，所以可能是一个注入点。

减少要测试的点很重要，因为在一个生产应用程序中，测试越多，产生的噪音就越多。

# 使用 SQLMap

使用鼠标的辅助按钮，点击“发送到 SQLMapper”，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/764bd46d-e88c-480b-be1f-f68eb4a48a51.png)

要限制要测试的参数，转到“注入”选项卡，输入参数，用逗号分隔，然后点击“运行”按钮。

SQLMap 将被启动，如果这些参数中有任何一个是有漏洞的，SQLMap 将检测并利用注入。当 SQLMap 检测到您正在利用盲目的 SQL 注入时，它会要求您继续。只需按*Y*。

# Intruder 检测

使用手动请求来检测 SQL 注入也是一个选项。我建议在审查应用程序时进行，而没有成功检测到漏洞。

首先，我们要检测入口点，就像我们在前一节中审查的那样。要检测与盲目 SQL 注入相关的易受攻击的点，您可以使用以下测试字符串：

```
' waitfor delay '0:0:30'—
```

我们还可以使用它在 DBMS 中的对应项。但是为什么要这样做呢？嗯，您可能记得，盲目 SQL 注入最重要的特征是它们不会直接向用户返回错误或输出。因此，通过使用这个字符串，我们期待看到响应的延迟：

1.  为了覆盖更多的参数，我们需要 Intruder 工具。对参数行为进行相同的分析，以确定哪个请求可能容易受到攻击，并使用鼠标的辅助按钮，点击“发送到 Intruder”，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/4f318829-40cd-4a1b-991e-8ed5d02a40ce.png)

1.  在 Intruder 中，为了快速测试，将延迟查询添加为唯一的有效负载，然后启动到所有参数，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/20e3a4d2-2931-41bb-9f26-fa5293f8e869.png)

1.  回到“位置”选项卡，点击“开始攻击”。如果你认为已经发现了可能的漏洞，右键点击请求，选择“发送到重复器”。一旦进入重复器，修改测试字符串以增加延迟时间，如下所示：

```
' waitfor delay '0:0:10'—
' waitfor delay '0:0:20'—
' waitfor delay '0:0:30'—
' waitfor delay '0:0:40'—
' waitfor delay '0:0:50'—
' waitfor delay '0:0:59'—
```

这个想法是确定何时使用时间来接收响应，以确定漏洞是否真实存在。

可以使用 Burp Suite Collaborator。在这些情况下使用它是一个很好的技巧，因为 Collaborator 是一个外部实体，作为接收器与数据库交互，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/0520e5d1-2139-454c-9e9a-7bcd6c7a6cf6.png)

# 利用

一旦你发现了一个有漏洞的变量，在入侵工具中用通配符标记它。

想象一下，你想要在运输网站上知道一个包裹的追踪号码。点击“有效载荷”选项卡，选择“数字”选项作为有效载荷类型。我们需要注入一系列数字，从 0000000000 到 9999999999，依次注入，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/8a714039-80a1-4ffa-bc42-858978fd218f.png)

由于无法转储存储在数据库中的寄存器，我们将使用布尔值来找到追踪号码。通过我们的入侵攻击发送一个使用正确追踪号码的请求；应用程序将返回一个`True`值作为响应：

为了方便检测，...

# 总结

在这最后一章中，我们回顾了其他可以用来评估应用程序的场景。在这一章中，我们寻找了 SQL 注入，并利用了其中的一种方法。

对于应用程序安全评估，我建议避免手动利用方法，因为我们将有更少的时间来使用它们。当使用其他方法无法找到漏洞时，它们是有用的。

在这一章中，你学会了如何分析请求中参数的行为，以推断可能存在漏洞并减少时间分析。之后，我们使用 Burp Suite 的扫描器、SQLMap 和入侵工具来检测盲目 SQL 注入漏洞。最后，我们学会了如何使用入侵工具猜测追踪号码来利用盲目 SQL 注入。
