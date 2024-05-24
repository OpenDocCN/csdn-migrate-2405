# BurpSuite 秘籍（二）

> 原文：[`annas-archive.org/md5/F5CEDF1B62C77ADA57A482FA32099322`](https://annas-archive.org/md5/F5CEDF1B62C77ADA57A482FA32099322)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：评估业务逻辑

在本章中，我们将涵盖以下内容：

+   测试业务逻辑数据验证

+   无限制的文件上传 - 绕过弱验证

+   执行进程时间攻击

+   测试工作流的规避

+   上传恶意文件 - 多语言

# 介绍

本章介绍了**业务逻辑测试**的基础知识，包括对该领域中一些常见测试的解释。Web 渗透测试涉及对业务逻辑的关键评估，以确定应用程序设计在执行完整性检查方面的表现如何，特别是在连续的应用程序功能步骤中，我们将学习如何使用 Burp 执行此类测试。

# 软件工具要求

要完成本章的练习，您将需要以下内容：

+   OWASP Broken Web Applications (VM)

+   OWASP Mutillidae 链接

+   Burp Proxy Community 或 Professional ([`portswigger.net/burp/`](https://portswigger.net/burp/))

# 测试业务逻辑数据验证

业务逻辑数据验证错误是由于缺乏服务器端检查，特别是在一系列事件中，如购物车结账。如果存在设计缺陷，如线程问题，这些缺陷可能允许攻击者在购买之前修改或更改其购物车内容或价格，以降低支付的价格。

# 准备工作

使用**OWASP WebGoat**应用程序和 Burp，我们将利用业务逻辑设计缺陷，以非常便宜的价格购买许多大额商品。

# 如何操作...

1.  确保**owaspbwa**虚拟机正在运行。从虚拟机的初始登陆页面选择 OWASP WebGoat 应用程序。登陆页面将配置为与您的机器特定的 IP 地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00237.jpeg)

1.  点击 OWASP WebGoat 链接后，将提示您输入一些登录凭据。使用以下凭据：用户名：`guest`密码：`guest`。

1.  认证后，点击**开始 WebGoat**按钮以访问应用程序练习：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00238.jpeg)

1.  从左侧菜单中点击**并发性** | **购物车并发性缺陷**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00239.jpeg)

练习解释了购物车设计中存在线程问题，将允许我们以较低的价格购买商品。让我们利用这个设计缺陷！

1.  将`1`添加到`数量`框中的`Sony - Vaio with Intel Centrino`项目。点击更新购物车按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00240.jpeg)

1.  切换到 Burp Proxy | HTTP 历史选项卡。找到购物车请求，右键单击，点击发送到 Repeater：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00241.jpeg)

1.  在 Burp 的 Repeater 选项卡中，将`QTY3`参数从`1`更改为`10`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00242.jpeg)

1.  留在 Burp Repeater 中，在请求窗格中，右键单击并选择**在浏览器中请求** | **在当前浏览器会话中**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00243.jpeg)

1.  弹出窗口显示修改后的请求。点击**复制**按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00244.jpeg)

1.  在包含购物车的同一 Firefox 浏览器中，打开一个新标签，并粘贴上一步中复制到剪贴板中的 URL：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00245.jpeg)

1.  按下*Enter*键，查看修改后的数量为`10`的请求重新提交：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00246.jpeg)

1.  切换到包含您购物车的原始标签（原始数量为`1`的购物车）。点击购买按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00247.jpeg)

1.  在下一个屏幕上，在点击确认按钮之前，切换到第二个标签，并再次更新购物车，但这次使用我们的新数量`10`，然后点击更新购物车：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00248.jpeg)

1.  返回第一个标签，并点击确认按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00249.jpeg)

注意我们能够以一个商品的价格购买 10 台 Sony Vaio 笔记本电脑！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00250.jpeg)

# 工作原理...

线程安全问题可能会产生意外结果。对于许多语言，开发人员对如何将变量和方法声明为线程安全的了解至关重要。未被隔离的线程，例如本教程中显示的购物车内容，可能导致用户获得意外的产品折扣。

# 无限制文件上传-绕过弱验证

许多应用程序允许上传文件以各种原因。服务器端的业务逻辑必须包括检查可接受的文件；这被称为**白名单**。如果此类检查薄弱或仅涉及文件属性的一个方面（例如，仅限于文件扩展名），攻击者可以利用这些弱点并上传可能在服务器上可执行的意外文件类型。

# 做好准备

使用**Damn Vulnerable Web Application**（**DVWA**）应用程序和 Burp，我们将利用文件上传页面中的业务逻辑设计缺陷。

# 如何做...

1.  确保 owaspbwa VM 正在运行。从 VM 的初始登陆页面选择 DVWA。登陆页面将配置为与您的计算机特定的 IP 地址。

1.  在登录页面，使用以下凭据：用户名：`user`；密码：`user`。

1.  从左侧菜单中选择 DVWA 安全选项。将默认设置从低更改为中，然后单击提交：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00251.jpeg)

1.  从左侧菜单中选择“上传”页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00252.jpeg)

1.  注意页面指示用户只能上传图像。如果我们尝试上传除 JPG 图像以外的其他类型的文件，我们将在左上角收到错误消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00253.jpeg)

1.  在本地计算机上创建任何类型的文件，除了 JPG。例如，创建一个名为`malicious_spreadsheet.xlsx`的 Microsoft Excel 文件。出于本教程的目的，它不需要任何内容。

1.  切换到 Burp 的代理|拦截选项卡。使用“拦截器”按钮打开拦截器。

1.  返回到 Firefox，并使用浏览按钮在系统上找到`malicious_spreadsheet.xlsx`文件，然后单击上传按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00254.jpeg)

1.  在 Burp 的代理|拦截器中暂停请求，将**Content-type**从`application/vnd.openxmlformats-officedocument.spreadsheet.sheet`更改为`image/jpeg`。

+   这是原始版本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00255.jpeg)

+   +   这是修改后的版本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00256.jpeg)

1.  单击前进按钮。现在通过单击拦截器上的切换按钮将拦截器关闭。

1.  注意文件上传成功！我们能够绕过弱数据验证检查并上传除图像以外的文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00257.jpeg)

# 它是如何工作的...

由于服务器端检查薄弱，我们能够轻松规避仅限于图像的限制并上传我们选择的文件类型。应用程序代码仅检查与`image/jpeg`匹配的内容类型，这很容易通过 Burp 等拦截代理进行修改。开发人员需要同时在应用程序代码中将内容类型和文件扩展名列入白名单，以防止此类利用发生。

# 执行过程时间攻击

通过监视应用程序完成任务所需的时间，攻击者可以收集或推断有关应用程序编码的信息。例如，使用有效凭据的登录过程比使用无效凭据的登录过程更快地收到响应。响应时间的延迟泄漏了与系统进程相关的信息。攻击者可以使用响应时间执行帐户枚举，并根据响应时间确定有效用户名。

# 做好准备

对于此教程，您将需要来自`wfuzz`的`common_pass.txt`单词列表：

+   [`github.com/xmendez/wfuzz`](https://github.com/xmendez/wfuzz)

+   路径：`wordlists` | `other` | `common_pass.txt`

使用 OWASP Mutillidae II，我们将确定应用程序是否基于强制登录的响应时间提供信息泄漏。

# 如何做...

确保 Burp 正在运行，并确保 owaspbwa VM 正在运行，并且已经在用于查看 owaspbwa 应用程序的 Firefox 浏览器中配置了 Burp。

1.  从 owaspbwa 登陆页面，单击链接到 OWASP Mutillidae II 应用程序。

1.  打开 Firefox 浏览器，转到 OWASP Mutillidae II 的主页（URL：`http://<your_VM_assigned_IP_address>/mutillidae/`）。

1.  转到登录页面，使用用户名`ed`和密码`pentest`登录。

1.  切换到 Burp 的代理|HTTP 历史选项卡，找到刚刚执行的登录，右键单击，并选择发送到入侵者：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00258.jpeg)

1.  转到入侵者|位置选项卡，并清除所有有效负载标记，使用右侧的清除§按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00259.jpeg)

1.  选择密码字段，并单击“添加§”按钮以在该字段周围添加有效负载标记：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00260.jpeg)

1.  还要删除`PHPSESSID`令牌。删除此令牌中的值（等号后面的内容），并将其留空。这一步非常重要，因为如果您不小心在请求中留下此令牌，您将无法看到时间差异，因为应用程序会认为您已经登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00261.jpeg)

1.  转到入侵者|有效负载选项卡。在有效负载选项[简单列表]中，我们将使用来自`wfuzz`的`wordlist`添加一些无效值，其中包含常见密码：`wfuzz` | `wordlists` | `other` | `common_pass.txt`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00262.jpeg)

1.  滚动到底部，取消“有效负载编码”的复选框：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00263.jpeg)

1.  单击“开始攻击”按钮。将显示一个攻击结果表。让攻击完成。从攻击结果表中，选择列并选中“接收响应”。选中“完成响应”以将这些列添加到攻击结果表中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00264.jpeg)

1.  分析提供的结果。虽然并非在每个响应中都明显，但请注意当使用无效密码（如`administrator`）时的延迟。`接收响应`时间为`156`，但`完成响应`时间为`166`。然而，有效密码`pentest`（仅`302`）会立即收到响应：`50`（接收），和`50`（完成）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00265.jpeg)

# 工作原理...

在处理错误消息或无效编码路径时，可能会发生信息泄露，这比有效的编码路径花费更长的时间。开发人员必须确保业务逻辑不会向攻击者透露这些线索。

# 测试工作流的规避

必须由 Web 应用程序渗透测试人员测试购物车到支付网关的交互，以确保工作流程不能按顺序执行。除非在服务器端首先验证了购物车内容，否则不应进行付款。如果缺少此检查，攻击者可以在实际购买之前更改价格、数量或两者。

# 准备就绪

使用 OWASP WebGoat 应用程序和 Burp，我们将利用业务逻辑设计缺陷，在购买之前没有服务器端验证。

# 如何做...

1.  确保 owaspbwa VM 正在运行。从 VM 的初始登陆页面选择 OWASP WebGoat 应用程序。登陆页面将配置为特定于您的计算机的 IP 地址。

1.  单击 OWASP WebGoat 链接后，将提示您输入登录凭据。使用以下凭据：用户名：`guest`；密码：`guest`。

1.  认证后，单击“开始 WebGoat”按钮以访问应用程序练习。

1.  单击左侧菜单中的 AJAX 安全性|不安全的客户端存储。您将看到一个购物车：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00266.jpeg)

1.  切换到 Burp 的**代理**|**HTTP 历史**选项卡，单击“过滤”按钮，并确保您的“按 MIME 类型过滤”部分包括“脚本”。如果未选中“脚本”，请务必现在选中它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00267.jpeg)

1.  返回到 Firefox 浏览器，使用 WebGoat 并为“惠普 - 带英特尔 Centrino 的 Pavilion 笔记本”项目指定数量为`2`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00268.jpeg)

1.  切换回 Burp 的**代理**|**HTTP 历史**选项卡，并注意与您对数量所做的更改相关的 JavaScript（`*.js`）文件。注意一个名为`clientSideValiation.js`的脚本。确保状态码为`200`而不是`304`（未修改）。只有*200*状态码才会显示脚本的源代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00269.jpeg)

1.  选择`clientSideValidation.js`文件，并在响应选项卡中查看其源代码。

1.  请注意，优惠码在 JavaScript 文件中是硬编码的。但是，如果按照它们的字面意思使用，它们将不起作用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00270.jpeg)

1.  继续查看源代码，并注意在 JavaScript 文件中找到了一个`decrypt`函数。我们可以通过这个函数测试其中一个优惠码。让我们在 Firefox 浏览器中尝试这个测试：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00271.jpeg)

1.  在浏览器中打开开发者工具（*F12*），转到控制台选项卡。在控制台中粘贴（查找`>>`提示）以下命令：

```
decrypt('emph');
```

1.  您可以使用此命令对数组中声明的任何优惠码调用`decrypt`函数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00272.jpeg)

1.  按下*Enter*键后，您将看到优惠码被解密为单词`GOLD`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00273.jpeg)

1.  在“输入您的优惠码”框中输入单词`GOLD`。注意金额现在要少得多。接下来，点击“购买”按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00274.jpeg)

1.  我们收到有关第 1 阶段完成的确认。现在让我们试着免费购买：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00275.jpeg)

1.  切换到 Burp 的**代理** | **拦截**选项卡，并使用**拦截器打开**按钮打开拦截器。

1.  返回到 Firefox 并按下**购买**按钮。在请求暂停时，将$1,599.99 的金额修改为$0.00。查找`GRANDTOT`参数以帮助您找到要更改的总金额：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00276.jpeg)

1.  点击**转发**按钮。现在通过单击拦截器关闭切换按钮来关闭拦截器。

1.  您应该收到一个成功的消息。请注意，现在收取的总费用为$0.00：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00277.jpeg)

# 工作原理...

由于在收取信用卡之前，未对优惠码和总金额进行服务器端检查，因此我们能够规避分配的价格并自行设置价格。

# 上传恶意文件 - 多语言

**多语言**是一个使用多种语言的术语。如果我们将这个概念引入黑客行为，它意味着通过使用不同的语言作为执行点来创建**跨站脚本**（**XSS**）攻击向量。例如，攻击者可以构造有效的图像并嵌入 JavaScript。 JavaScript 有效负载的放置通常在图像的注释部分。一旦图像在浏览器中加载，取决于 Web 服务器声明的内容类型的严格性以及浏览器对内容类型的解释，XSS 内容可能会执行。

# 准备工作

+   从 PortSwigger 博客页面下载一个包含跨站脚本漏洞的 JPG 文件：[`portswigger.net/blog/bypassing-csp-using-polyglot-jpegs`](https://portswigger.net/blog/bypassing-csp-using-polyglot-jpegs)

+   这是一个多语言图像的直接链接：[`portswigger-labs.net/polyglot/jpeg/xss.jpg`](http://portswigger-labs.net/polyglot/jpeg/xss.jpg)

+   使用 OWASP WebGoat 文件上传功能，我们将在应用程序中植入一个包含 XSS 有效负载的图像。

# 如何做...

1.  确保 owaspbwa 虚拟机正在运行。从虚拟机的初始登陆页面选择 OWASP WebGoat 应用程序。登陆页面将配置为与您的机器特定的 IP 地址。

1.  点击 OWASP WebGoat 链接后，将提示您输入登录凭据。使用以下凭据：用户名：`guest`*；*密码：`guest`*。*

1.  经过身份验证后，单击“启动 WebGoat”按钮以访问应用程序练习。

1.  从左侧菜单中点击**恶意执行** | **恶意文件执行**。您将看到一个文件上传功能页面。说明中指出，只允许上传图像：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00278.jpeg)

1.  浏览到您从本食谱开头提到的 PortSwigger 博客页面下载的`xss.jpg`图像所保存的位置。

1.  以下是图像的屏幕截图。正如你所看到的，很难检测到图像中包含的任何 XSS 漏洞。它被隐藏得很隐蔽。

1.  点击**浏览**按钮选择`xss.jpg`文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00279.jpeg)

1.  切换到 Burp 的**代理** | **选项**。确保你正在捕获**客户端响应**并且已启用以下设置。这将允许我们捕获修改或拦截的 HTTP 响应：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00280.jpeg)

1.  切换到 Burp 的**代理** | **拦截**选项卡。通过单击拦截器打开按钮打开拦截器。

1.  返回到 Firefox 浏览器，然后点击**开始上传**按钮。消息应该在 Burp 的拦截器中暂停。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00281.jpeg)

1.  在请求暂停时的拦截窗口中，在底部的搜索框中键入`Burp rocks`。你应该在图像中间看到一个匹配项。这是我们的多语言有效负载。它是一张图片，但它包含了图像注释中的隐藏 XSS 脚本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00282.jpeg)

1.  点击**转发**按钮。现在通过单击拦截器关闭按钮关闭拦截器。

1.  使用记事本或你喜欢的文本编辑器，创建一个名为`poly.jsp`的新文件，并在文件中写入以下代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00283.gif)

1.  返回到**恶意文件执行**页面，并浏览到你创建的`poly.jsp`文件，然后点击**开始上传**按钮。`poly.jsp`是一个可以在这个 Web 服务器上执行的 Java 服务器页面文件。根据说明，我们必须在提供的路径中创建一个`guest.txt`文件。此代码在 JSP 脚本标记代码中创建该文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00284.jpeg)

1.  右键单击未识别的图像，然后选择**复制图像位置**。

1.  在与 WebGoat 相同的 Firefox 浏览器中打开一个新标签，并在新标签中粘贴图像位置。按*Enter*执行脚本，并在转到下一步之前给脚本几秒钟在后台运行。

1.  切换回第一个标签，*F5*，刷新页面，你应该收到成功完成的消息。如果你的脚本运行缓慢，尝试在上传页面上再次上传`poly.jsp`。成功消息应该出现：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00285.jpeg)

# 它是如何工作的...

由于不受限制的文件上传漏洞，我们可以上传恶意文件，如多语言文件，而不会被 Web 服务器检测到。许多网站允许上传图片，因此开发人员必须确保这些图片不携带其中的 XSS 有效负载。在这方面的保护可以采用魔术数字检查或特殊代理服务器筛选所有上传。

# 还有更多...

要了解更多关于多语言的信息，请参考 Portswigger 博客：[`portswigger.net/blog/bypassing-csp-using-polyglot-jpegs`](https://portswigger.net/blog/bypassing-csp-using-polyglot-jpegs)。


# 第八章：评估输入验证检查

在本章中，我们将涵盖以下操作步骤：

+   测试反射型跨站脚本

+   测试存储型跨站脚本

+   测试 HTTP 动词篡改

+   测试 HTTP 参数污染

+   测试 SQL 注入

+   测试命令注入

# 介绍

在使用应用程序代码之前未验证从客户端接收的任何输入，是在 Web 应用程序中发现的最常见的安全漏洞之一。这个缺陷是导致主要安全问题的根源，比如 SQL 注入和跨站脚本（XSS）。Web 渗透测试人员必须评估并确定应用程序是否反射回任何输入或执行。我们将学习如何使用 Burp 来执行这样的测试。

# 软件工具要求

为了完成本章的操作步骤，您需要以下内容：

+   OWASP Broken Web Applications（VM）

+   OWASP Mutillidae 链接

+   Burp Proxy Community 或 Professional ([`portswigger.net/burp/`](https://portswigger.net/burp/))

# 测试反射型跨站脚本

当恶意 JavaScript 被注入到输入字段、参数或标头中，并在从 Web 服务器返回后在浏览器中执行时，就会发生反射型跨站脚本。反射型 XSS 发生在 JavaScript 的执行仅在浏览器中反映，而不是网页的永久部分。渗透测试人员需要测试发送到 Web 服务器的所有客户端值，以确定是否可能发生 XSS。

# 准备工作

使用 OWASP Mutillidae II，让我们确定应用程序是否防范了反射型跨站脚本（XSS）。

# 操作步骤...

1.  从 OWASP Mutilliae II 菜单中，通过导航到 OWASP 2013 | A3 - 跨站脚本（XSS）| 反射（一级）| 渗透测试工具查找，选择登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00286.jpeg)

1.  从下拉列表中选择一个工具，然后点击查找工具按钮。下拉列表中的任何值都适用于此操作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00287.jpeg)

1.  切换到 Burp Proxy | HTTP 历史记录，并通过选择查找工具来找到您刚刚创建的 HTTP 消息。请注意，在请求中有一个名为`ToolID`的参数。在下面的示例中，值为`16`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00288.jpeg)

1.  切换到响应选项卡，并注意从请求返回的 JSON。您可以通过在底部的搜索框中输入`PenTest`来更容易地找到响应中的 JavaScript 函数。请注意，`tool_id`在名为`toolIDRequested`的响应参数中反射。这可能是 XSS 的攻击向量：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00289.jpeg)

1.  将请求发送到 Repeater。在数字后面的`ToolID`参数中添加一个 XSS 有效负载。使用一个简单的有效负载，比如`<script>alert(1);</script>`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00290.jpeg)

1.  点击“Go”并检查返回的 JSON 响应，搜索`PenTest`。注意我们的有效负载正好如输入的那样返回。看起来开发人员在使用之前没有对任何输入数据进行消毒。让我们利用这个缺陷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00291.jpeg)

1.  由于我们使用的是 JSON 而不是 HTML，我们需要调整有效负载以匹配返回的 JSON 的结构。我们将欺骗 JSON，使其认为有效负载是合法的。我们将原始的`<script>alert(1);</script>`有效负载修改为`"}} )%3balert(1)%3b//`。

1.  切换到 Burp Proxy | 拦截选项卡。通过打开“拦截器打开”按钮打开拦截器。

1.  返回到 Firefox，从下拉列表中选择另一个工具，然后点击查找工具按钮。

1.  在代理|拦截器暂停请求时，在“工具 ID”号之后立即插入新的有效负载`"}} )%3balert(1)%3b//`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00292.jpeg)

1.  点击前进按钮。通过切换到拦截器关闭拦截器。

1.  返回到 Firefox 浏览器，查看弹出的警报框。您已成功展示了反射型 XSS 漏洞的概念证明（PoC）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00293.jpeg)

# 工作原理...

由于在使用来自客户端接收的数据之前未进行充分的输入清理。在这种情况下，渗透测试工具标识符会在从客户端接收到的响应中反射，为 XSS 攻击提供了攻击向量。

# 测试存储的跨站脚本

存储的跨站脚本发生在恶意 JavaScript 被注入输入字段、参数或标头后，从 Web 服务器返回后在浏览器中执行并成为页面的永久部分。当恶意 JavaScript 存储在数据库中并稍后用于填充网页的显示时，就会发生存储的 XSS。渗透测试人员需要测试发送到 Web 服务器的所有客户端值，以确定是否可能发生 XSS。

# 准备工作

使用 OWASP Mutillidae II，让我们确定应用程序是否防范存储的跨站脚本。

# 如何做...

1.  从 OWASP Mutilliae II 菜单中，通过导航到 OWASP 2013 | A3 - 跨站脚本（XSS）| 持久（一级）| 添加到您的博客，选择登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00294.jpeg)

1.  在文本区域中放入一些文字。在点击保存博客条目按钮之前，让我们尝试一个带有该条目的有效负载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00295.jpeg)

1.  切换到 Burp 代理|拦截选项卡。使用拦截器按钮打开拦截器。

1.  在代理|拦截器暂停请求时，立即插入新的有效负载`<script>alert(1);</script>`，并将其放在您添加到博客的文字后面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00296.jpeg)

1.  单击转发按钮。通过切换到拦截器关闭拦截器。

1.  返回到 Firefox 浏览器，查看显示的弹出警报框：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00297.jpeg)

1.  单击“确定”按钮关闭弹出窗口。重新加载页面，您将再次看到警报弹出窗口。这是因为您的恶意脚本已成为页面的永久部分。您已成功展示了存储 XSS 漏洞的概念证明（PoC）！

# 它是如何工作的...

存储型或持久型 XSS 之所以会发生，是因为应用程序不仅忽略对输入的消毒，而且还将输入存储在数据库中。因此，当重新加载页面并用数据库数据填充页面时，恶意脚本将与数据一起执行。

# 测试 HTTP 动词篡改

HTTP 请求可以包括除 GET 和 POST 之外的方法。作为渗透测试人员，确定 Web 服务器允许哪些其他 HTTP 动词（即方法）是很重要的。对其他动词的支持可能会泄露敏感信息（例如 TRACE）或允许危险地调用应用程序代码（例如 DELETE）。让我们看看 Burp 如何帮助测试 HTTP 动词篡改。

# 准备工作

使用 OWASP Mutillidae II，让我们确定应用程序是否允许除 GET 和 POST 之外的 HTTP 动词。

# 如何做...

1.  导航到 OWASP Mutillidae II 的主页。

1.  切换到 Burp 代理|HTTP 历史记录，并查找您在浏览 Mutillidae 主页时创建的 HTTP 请求。注意使用的方法是 GET。右键单击并将请求发送到入侵者：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00298.jpeg)

1.  在入侵者|位置选项卡中，清除所有建议的有效负载标记。突出显示`GET`动词，并单击添加$按钮将有效负载标记放在动词周围：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00299.jpeg)

1.  在入侵者|有效负载选项卡中，将以下值添加到有效负载选项[简单列表]文本框中：

+   选项

+   头

+   发布

+   放置

+   删除

+   跟踪

+   跟踪

+   连接

+   PROPFIND

+   PROPPATCH

+   MKCOL

+   复制

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00300.jpeg)

1.  取消 Payloads 页面底部的 Payload Encoding 复选框，然后单击开始攻击按钮。

1.  当攻击结果表出现并攻击完成时，请注意所有返回状态码为 200 的动词。这是令人担忧的，因为大多数 Web 服务器不应该支持这么多动词。特别是对 TRACE 和 TRACK 的支持将包括在调查结果和最终报告中作为漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00301.jpeg)

# 它是如何工作...

测试 HTTP 动词篡改包括使用不同的 HTTP 方法发送请求并分析接收到的响应。测试人员需要确定是否对任何测试的动词返回了状态码 200，这表明 Web 服务器允许此动词类型的请求。

# 测试 HTTP 参数污染

**HTTP 参数污染**（**HPP**）是一种攻击，其中多个 HTTP 参数以相同的名称发送到 Web 服务器。其目的是确定应用程序是否以意想不到的方式响应，从而进行利用。例如，在 GET 请求中，可以向查询字符串添加额外的参数，如此：`“&name=value”`，其中 name 是应用程序代码已知的重复参数名称。同样，HPP 攻击也可以在 POST 请求中执行，方法是在 POST 主体数据中重复参数名称。

# 准备工作

使用 OWASP Mutillidae II，让我们确定应用程序是否容易受到 HPP 攻击。

# 如何做...

1.  从 OWASP Mutilliae II 菜单中，通过导航到 OWASP 2013 | A1 - Injection (Other) | HTTP Parameter Pollution | Poll Question 选择登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00302.jpeg)

1.  从单选按钮中选择一个工具，添加你的缩写，然后点击提交投票按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00303.jpeg)

1.  切换到 Burp 代理|HTTP 历史选项卡，并找到刚刚从用户投票页面执行的请求。注意名为`choice`的参数。该参数的值是 Nmap。右键单击并将此请求发送到 Repeater：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00304.jpeg)

1.  切换到 Burp Repeater 并在查询字符串中添加另一个具有相同名称的参数。让我们从用户投票列表中选择另一个工具，并将其附加到查询字符串，例如`“&choice=tcpdump”`。单击 Go 发送请求：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00305.jpeg)

1.  检查响应。应用程序代码接受了哪个选择？通过搜索`Your choice was`字符串很容易找到。显然，应用程序代码接受了重复的选择参数值来计入用户投票：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00306.jpeg)

# 它是如何工作的...

应用程序代码未能检查传递给函数的具有相同名称的多个参数。结果是应用程序通常对最后一个参数匹配进行操作。这可能导致奇怪的行为和意外的结果。

# 测试 SQL 注入

SQL 注入攻击涉及攻击者向数据库提供输入，而数据库在没有任何验证或净化的情况下接收和使用该输入。结果是泄露敏感数据，修改数据，甚至绕过身份验证机制。

# 准备工作

使用 OWASP Mutillidae II 登录页面，让我们确定应用程序是否容易受到**SQL 注入**（**SQLi**）攻击。

# 如何做...

1.  从 OWASP Mutilliae II 菜单中，通过导航到 OWASP 2013 | A1-Injection (SQL) | SQLi – Bypass Authentication | Login 选择登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00307.jpeg)

1.  在登录屏幕上，将无效的凭据放入`username`和`password`文本框中。例如，`username`是`tester`，`password`是`tester`。在点击登录按钮之前，让我们打开代理|拦截器。

1.  切换到 Burp 代理|拦截器选项卡。通过切换到拦截器打开拦截器。

1.  在代理|拦截器暂停请求时，在用户名参数中插入新的有效负载`' or 1=1--<space>`，然后点击登录按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00308.jpeg)

1.  点击前进按钮。通过切换到拦截器关闭拦截器。

1.  返回到 Firefox 浏览器，注意你现在已经以管理员身份登录！

# 它是如何工作的...

测试账户在数据库中不存在；然而，`' or 1=1--<space>`有效负载导致绕过身份验证机制，因为 SQL 代码基于未经净化的用户输入构造了查询。管理员账户是数据库中创建的第一个账户，因此数据库默认使用该账户。

# 还有更多...

我们在 Burp Intruder 中使用了 wfuzz 的 SQLi wordlist 来测试同一用户名字段中的许多不同 payloads。检查结果表中每次攻击的响应，以确定 payload 是否成功执行了 SQL 注入。

构建 SQL 注入 payload 需要一些对后端数据库和特定语法的了解。

# 测试命令注入

命令注入涉及攻击者尝试在 HTTP 请求中调用系统命令，通常在终端会话中执行。许多 Web 应用程序允许通过 UI 进行系统命令以进行故障排除。Web 渗透测试人员必须测试网页是否允许在通常应受限制的系统上执行进一步的命令。

# 准备工作

对于这个示例，您将需要 Unix 命令的 SecLists Payload：

+   SecLists-master | Fuzzing | `FUZZDB_UnixAttacks.txt`

+   从 GitHub 下载：[`github.com/danielmiessler/SecLists`](https://github.com/danielmiessler/SecLists)

使用 OWASP Mutillidae II DNS Lookup 页面，让我们确定应用程序是否容易受到命令注入攻击。

# 如何操作...

1.  从 OWASP Mutilliae II 菜单中，通过导航到 OWASP 2013 | A1-Injection (Other) | Command Injection | DNS Lookup 来选择 DNS Lookup：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00309.jpeg)

1.  在 DNS Lookup 页面，将 IP 地址`127.0.0.1`输入到文本框中，然后点击 Lookup DNS 按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00310.jpeg)

1.  切换到 Burp Proxy | HTTP history 标签，并查找您刚刚执行的请求。右键单击 Send to Intruder：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00311.jpeg)

1.  在 Intruder | Positions 标签中，使用 Clear $按钮清除所有建议的 payload 标记。在`target_host`参数中，在`127.0.0.1` IP 地址后面放置一个管道符号(`|`)。在管道符号后面放置一个`X`。突出显示`X`，然后点击 Add $按钮将`X`用 payload 标记包装起来：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00312.jpeg)

1.  在 Intruder | Payloads 标签中，点击 Load 按钮。浏览到您从 GitHub 下载 SecLists-master wordlists 的位置。导航到`FUZZDB_UnixAttacks.txt` wordlist 的位置，并使用以下内容填充 Payload Options [Simple list]框：SecLists-master | Fuzzing | `FUZZDB_UnixAttacks.txt`

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00313.jpeg)

1.  在 Payloads 标签页的底部取消选中 Payload Encoding 框，然后点击 Start Attack 按钮。

1.  允许攻击继续，直到达到 payload `50`。注意在 payload `45`左右的 Render 标签周围的响应。我们能够在操作系统上执行命令，比如`id`，它会在网页上显示命令的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00314.jpeg)

# 工作原理...

未能定义和验证用户输入是否符合可接受的系统命令列表可能导致命令注入漏洞。在这种情况下，应用程序代码未限制通过 UI 可用的系统命令，允许在操作系统上查看和执行应该受限制的命令。


# 第九章：攻击客户端

在本章中，我们将涵盖以下示例：

+   测试点击劫持

+   测试基于 DOM 的跨站脚本

+   测试 JavaScript 执行

+   测试 HTML 注入

+   测试客户端资源操纵

# 介绍

在浏览器中执行的客户端可用代码需要测试以确定是否存在敏感信息或允许用户输入而没有经过服务器端验证。学习如何使用 Burp 执行这些测试。

# 软件工具要求

要完成本章的示例，您需要以下内容：

+   OWASP 破损 Web 应用（VM）

+   OWASP Mutillidae 链接

+   Burp 代理社区或专业版（[`portswigger.net/burp/`](https://portswigger.net/burp/)）

# 测试点击劫持

**点击劫持**也被称为**UI 重定向攻击**。这种攻击是一种欺骗性技术，可以诱使用户与透明 iframe 进行交互，并可能向受攻击者控制的网站发送未经授权的命令或敏感信息。让我们看看如何使用 Burp Clickbandit 来测试网站是否容易受到点击劫持攻击。

# 做好准备

使用 OWASP Mutillidae II 应用程序和 Burp Clickbandit，让我们确定该应用程序是否能够防御点击劫持攻击。

# 如何做...

1.  导航到 OWASP Mutillidae II 的主页。

1.  切换到 Burp，并从顶级菜单中选择 Burp Clickbandit：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00315.jpeg)

1.  一个弹出框解释了该工具。单击名为复制 Clickbandit 到剪贴板的按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00316.jpeg)

1.  返回到 Firefox 浏览器，按下*F12*以打开开发者工具。从开发者工具菜单中，选择控制台，并查找底部的提示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00317.jpeg)

1.  在控制台提示（例如，`>>`），粘贴到提示中您复制到剪贴板的 Clickbandit 脚本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00318.jpeg)

1.  在提示中粘贴脚本后，按*Enter*键。您应该看到 Burp Clickbandit 记录模式。单击开始按钮开始：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00319.jpeg)

1.  出现后，开始在应用程序上四处点击。单击 Mutillidae 菜单顶部的可用链接，单击侧边菜单上的可用链接，或浏览 Mutillidae 内的页面。点击了一圈后，在 Burp Clickbandit 菜单上按完成按钮。

1.  您应该注意到大红色块透明地出现在 Mutillidae 网页的顶部。每个红色块表示恶意 iframe 可能出现的位置。随意单击每个红色块，以查看下一个红色块出现，依此类推：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00320.jpeg)

1.  一旦您希望停止并保存您的结果，请单击保存按钮。这将保存 Clickjacking PoC 在一个 HTML 文件中，供您放在您的渗透测试报告中。

# 它是如何工作的...

由于 Mutillidae 应用程序没有使用设置为`DENY`的 X-FRAME-OPTIONS 标头，因此可以将恶意 iframe 注入到 Mutillidae 网页中。Clickbandit 增加了 iframe 的不透明度，以便查看，并创建了一个**概念验证**（**PoC**）来说明漏洞如何被利用。

# 测试基于 DOM 的跨站脚本

**文档对象模型**（**DOM**）是浏览器中捕获的所有 HTML 网页的树状结构表示。开发人员使用 DOM 在浏览器中存储信息以方便使用。作为 Web 渗透测试人员，确定是否存在基于 DOM 的**跨站脚本**（**XSS**）漏洞非常重要。

# 做好准备

使用 OWASP Mutillidae II HTML5 Web 存储练习，让我们确定该应用程序是否容易受到基于 DOM 的 XSS 攻击。

# 如何做...

1.  导航到 OWASP 2013 | HTML5 Web Storage | HTML5 Storage：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00321.jpeg)

1.  注意使用 HTML5 Web 存储位置存储的 DOM 中的名称/值对。Web 存储包括会话和本地变量。开发人员使用这些存储位置方便地在用户的浏览器中存储信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00322.jpeg)

1.  切换到 Burp 代理拦截选项卡。通过点击拦截器打开按钮来打开拦截器。

1.  通过按下*F5*或点击重新加载按钮在 Firefox 浏览器中重新加载 HTML 5 Web 存储页面。

1.  切换到 Burp 代理 HTTP 历史选项卡。找到刚刚执行的重新加载创建的暂停请求。注意`User-Agent`字符串被高亮显示，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00323.jpeg)

1.  用以下脚本替换前面高亮显示的`User-Agent`：

```
<script>try{var m = "";var l = window.localStorage; var s = window.sessionStorage;for(i=0;i<l.length;i++){var lKey = l.key(i);m += lKey + "=" + l.getItem(lKey) + ";\n";};for(i=0;i<s.length;i++){var lKey = s.key(i);m += lKey + "=" + s.getItem(lKey) + ";\n";};alert(m);}catch(e){alert(e.message);}</script>
```

1.  点击“Forward”按钮。现在，通过点击拦截器关闭按钮来关闭拦截器。

1.  注意弹出的警报显示 DOM 存储的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00324.jpeg)

# 工作原理...

注入的脚本说明了跨站脚本漏洞的存在，结合 DOM 中存储的敏感信息，可以允许攻击者窃取敏感数据。

# 测试 JavaScript 执行

JavaScript 注入是跨站脚本攻击的一个子类型，特指对 JavaScript 的任意注入。该领域的漏洞可能影响浏览器中保存的敏感信息，如用户会话 cookie，或者可能导致页面内容的修改，允许来自攻击者控制站点的脚本执行。

# 准备工作

使用 OWASP Mutillidae II 密码生成器练习，让我们确定应用程序是否容易受到 JavaScript XSS 攻击。

# 如何操作...

1.  导航到 OWASP 2013 | A1 – 注入（其他）| JavaScript 注入 | 密码生成器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00325.jpeg)

1.  注意点击“生成密码”按钮后，会显示一个密码。还要注意 URL 中提供的用户名值*原样*反映在网页上：`http://192.168.56.101/mutillidae/index.php?page=password-generator.php&username=anonymous`。这意味着页面可能存在潜在的 XSS 漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00326.jpeg)

1.  切换到 Burp 代理 HTTP 历史选项卡，并找到与密码生成器页面相关的 HTTP 消息。切换到消息编辑器中的响应选项卡，并在字符串`catch`上执行搜索。注意返回的 JavaScript 具有一个 catch 块，其中显示给用户的错误消息。我们将使用这个位置来放置一个精心制作的 JavaScript 注入攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00327.jpeg)

1.  切换到 Burp 代理拦截选项卡。通过点击拦截器打开按钮来打开拦截器。

1.  通过按下*F5*或点击重新加载按钮在 Firefox 浏览器中重新加载密码生成器页面。

1.  切换到 Burp 代理拦截器选项卡。在请求暂停时，注意`username`参数值如下所示高亮显示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00328.jpeg)

1.  用以下精心制作的 JavaScript 注入脚本替换前面高亮显示的`anonymous`值：

```
canary";}catch(e){}alert(1);try{a="
```

1.  点击“Forward”按钮。现在，通过点击拦截器关闭按钮来关闭拦截器。

1.  注意弹出的警报。您已成功演示了 JavaScript 注入 XSS 漏洞的存在！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00329.jpeg)

# 工作原理...

```
canary and ending the statement with a semicolon, a specially crafted *new* catch block was created, which contained the malicious JavaScript payload.
```

# 测试 HTML 注入

HTML 注入是将任意 HTML 代码插入易受攻击的网页。该领域的漏洞可能导致敏感信息的泄露，或者出于社会工程目的修改页面内容。

# 准备工作

使用 OWASP Mutillidae II 捕获数据页面，让我们确定应用程序是否容易受到 HTML 注入攻击。

# 如何操作...

1.  导航到 OWASP 2013 | A1 – 注入（其他）| 通过 Cookie 注入的 HTMLi | 捕获数据页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00330.jpeg)

1.  注意攻击前页面的外观：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00331.jpeg)

1.  切换到 Burp 代理拦截选项卡，并通过点击拦截器打开按钮来打开拦截器。

1.  在请求暂停时，记下最后一个 cookie 的值，`acgroupswitchpersist=nada`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00332.jpeg)

1.  在请求暂停时，用这个 HTML 注入脚本替换最后一个 cookie 的值：

```
<h1>Sorry, please login again</h1><br/>Username<input type="text"><br/>Password<input type="text"><br/><input type="submit" value="Submit"><h1>&nbsp;</h1>
```

1.  点击“Forward”按钮。现在通过单击拦截器按钮将拦截器关闭。

1.  注意 HTML 现在包含在页面中！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00333.jpeg)

# 工作原理...

由于缺乏输入验证和输出编码，可能存在 HTML 注入漏洞。利用这个漏洞的结果是插入任意 HTML 代码，这可能导致 XSS 攻击或社会工程学方案，就像前面的示例中所看到的那样。

# 测试客户端资源操纵

如果应用程序根据客户端 URL 信息或资源路径执行操作（即，AJAX 调用，外部 JavaScript，iframe 源），则结果可能导致客户端资源操纵漏洞。这种漏洞涉及攻击者控制的 URL，例如 JavaScript 位置属性中找到的位置标头，或者控制重定向的 HTTP 响应中找到的位置标头，或者 POST 主体参数。这种漏洞的影响可能导致跨站脚本攻击。

# 准备工作

使用 OWASP Mutillidae II 应用程序，确定是否可能操纵客户端暴露的任何 URL 参数，以及操纵这些值是否会导致应用程序行为不同。

# 如何做...

1.  导航到 OWASP 2013 | A10 – 未经验证的重定向和转发 | Credits：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00334.jpeg)

1.  点击 Credits 页面上的 ISSA Kentuckiana 链接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00335.jpeg)

1.  切换到 Burp 代理 HTTP 历史选项卡，并找到您对 Credits 页面的请求。注意有两个查询字符串参数：`page`和`forwardurl`。如果我们操纵用户被发送的 URL 会发生什么？

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00336.jpeg)

1.  切换到 Burp 代理拦截选项卡。使用按钮“Intercept is on”打开拦截器。

1.  在请求暂停时，注意`fowardurl`参数的当前值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00337.jpeg)

1.  将`forwardurl`参数的值替换为`https://www.owasp.org`，而不是原始选择的`http://www.issa-kentuckiana.org`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00338.jpeg)

1.  点击“Forward”按钮。现在通过单击拦截器按钮将拦截器关闭。

1.  注意我们是如何被重定向到一个原本没有点击的网站！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00339.jpeg)

# 工作原理...

应用程序代码决策，例如将用户重定向到何处，不应依赖于客户端可用的值。这些值可能被篡改和修改，以将用户重定向到攻击者控制的网站或执行攻击者控制的脚本。


# 第十章：使用 Burp 宏和扩展

在本章中，我们将涵盖以下示例：

+   创建会话处理宏

+   被抓到手深处

+   添加优秀的渗透测试插件

+   通过手动扫描问题扩展创建新问题

+   使用 Active Scan++扩展

# 介绍

本章涵盖了两个可以混合在一起的独立主题：宏和扩展。Burp 宏使渗透测试人员能够自动化事件，例如登录或参数读取，以克服潜在的错误情况。扩展，也称为插件，扩展了 Burp 中找到的核心功能。

# 软件工具要求

为了完成本章的示例，您需要以下内容：

+   OWASP 破损的 Web 应用程序（VM）

+   OWASP Mutillidae (`http://<Your_VM_Assigned_IP_Address>/mutillidae`)

+   GetBoo (`http://<Your_VM_Assigned_IP_Address>/getboo`)

+   Burp Proxy Community or Professional ([`portswigger.net/burp/`](https://portswigger.net/burp/))

# 创建会话处理宏

在 Burp 中，项目选项卡允许测试人员设置会话处理规则。会话处理规则允许测试人员指定 Burp 在进行 HTTP 请求时将采取的一组操作。在范围内为 Spider 和 Scanner 设置了默认的会话处理规则。但是，在本示例中，我们将创建一个新的会话处理规则，并使用宏来帮助我们在使用 Repeater 时从未经认证的会话中创建一个经过认证的会话。

# 做好准备

使用 OWASP Mutilliae II 应用程序，我们将创建一个新的 Burp 会话处理规则，并使用相关的宏，在使用 Repeater 时从未经认证的会话中创建一个经过认证的会话。

# 如何做…

1.  在 Mutillidae 的登录页面中导航。使用用户名`ed`和密码`pentest`登录应用程序。

1.  立即点击“注销”按钮退出应用程序，并确保应用程序确认您已注销。

1.  切换到 Burp 代理 HTTP 历史选项卡。查找您刚刚进行的注销请求以及随后的未经认证的`GET`请求。选择未经认证的请求，即第二个`GET`。右键单击并将该请求发送到 Repeater，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00340.jpeg)

1.  切换到 Burp Repeater，然后单击“Go”按钮。在响应的渲染选项卡上，确保您收到“未登录”消息。我们将使用这种情况来构建一个会话处理规则，以解决未经认证的会话，并将其变为经过认证的会话，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00341.jpeg)

1.  切换到 Burp 项目选项卡，然后切换到会话选项卡，并在会话处理规则部分下单击“添加”按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00342.jpeg)

1.  单击“添加”按钮后，将弹出一个框。给您的新规则取一个名字，比如`LogInSessionRule`，在规则操作下选择运行宏，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00343.jpeg)

1.  另一个弹出框出现，这是会话处理操作编辑器。在“选择宏”下的第一部分，单击“添加”按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00344.jpeg)

1.  单击“添加”按钮后，宏编辑器将出现，同时还会出现另一个宏记录器的弹出框，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00345.jpeg)

注意：1.7.35 版本存在一个禁用宏记录器的错误。因此，在单击“添加”按钮后，如果记录器没有出现，请升级 Burp 版本至 1.7.36 或更高版本。

1.  在宏记录器中，查找您以 Ed 身份登录的`POST`请求以及以下的`GET`请求。在宏记录器窗口中突出显示这两个请求，然后单击“确定”，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00346.jpeg)

1.  在上一个对话框中突出显示的这两个请求现在出现在宏编辑器窗口中。给宏一个描述，比如`LogInMacro`，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00347.jpeg)

1.  单击“配置”按钮验证用户名和密码值是否正确。完成后单击“确定”，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00348.jpeg)

1.  单击“确定”关闭宏编辑器。您应该在会话处理操作编辑器中看到新创建的宏。单击“确定”关闭此对话框窗口，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00349.jpeg)

1.  关闭会话处理操作编辑器后，您将返回到会话处理规则编辑器，在那里您现在可以看到规则操作部分填充了您的宏名称。单击此窗口的范围选项卡，以定义哪个工具将使用此规则：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00350.jpeg)

1.  在会话处理规则编辑器的范围选项卡中，取消选中其他框，只保留 Repeater 选中。在 URL 范围下，单击“包括所有 URL”单选按钮。单击“确定”关闭此编辑器，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00351.jpeg)

1.  现在您应该在会话处理规则窗口中看到新的会话处理规则，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00352.jpeg)

1.  返回到 Repeater 选项卡，在那里您之前未登录到应用程序。单击“Go”按钮，以显示您现在以 Ed 的身份登录！这意味着您的会话处理规则和相关的宏起作用了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00353.jpeg)

# 它是如何工作的...

在这个示例中，我们看到如何通过重放登录过程将未经身份验证的会话更改为经过身份验证的会话。宏的创建允许手动步骤被脚本化并分配给 Burp 套件中的各种工具。

Burp 允许测试人员配置会话处理规则，以解决工具套件可能遇到的各种条件。当满足这些条件时，规则提供额外的操作。在这个示例中，我们通过创建一个新的会话处理规则来解决未经身份验证的会话，该规则调用了一个宏。我们将此规则的范围限定为仅用于 Repeater，仅用于演示目的。

# 陷入困境

在针对应用程序时，Burp 会捕获代理和爬虫 HTTP 流量时遇到的所有 cookie。Burp 将这些 cookie 存储在一个名为**cookie jar**的缓存中。这个 cookie jar 在默认会话处理规则中使用，并且可以在 Burp 工具套件中共享，比如 Proxy、Intruder 和 Spider。在 cookie jar 中，有一个请求的历史表。该表详细说明了每个 cookie 的域和路径。可以编辑或删除 cookie jar 中的 cookie。

# 准备就绪

我们将打开 Burp Cookie Jar 并查看内部。然后，使用 OWASP GetBoo 应用程序，我们将识别添加到 Burp Cookie Jar 的新 cookie。

# 如何做...

1.  关闭并重新启动 Burp，以清除任何历史记录。切换到 Burp 项目选项卡，然后切换到会话选项卡。在 Cookie Jar 部分，单击“打开 cookie jar”按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00354.jpeg)

1.  出现一个新的弹出框。由于我们还没有代理流量，cookie jar 是空的。让我们针对一个应用程序并捕获一些 cookie，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00355.jpeg)

1.  从 OWASP 登陆页面，单击链接以访问 GetBoo 应用程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00356.jpeg)

1.  单击“登录”按钮。在登录屏幕上，输入用户名和密码为`demo`，然后单击“登录”按钮。

1.  返回到 Burp Cookie Jar。现在有三个可用的 cookie。每个 cookie 都有一个域、路径、名称和值，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00357.jpeg)

1.  选择列表中的最后一个 cookie，然后单击“编辑 cookie”按钮。将值从`nada`修改为`thisIsMyCookie`，然后单击“确定”，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00358.jpeg)

1.  现在值已更改，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00359.jpeg)

1.  Burp Cookie Jar 的默认范围是 Proxy 和 Spider。但是，您可以扩展范围以包括其他工具。单击 Repeater 的复选框，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00360.jpeg)

现在，如果您创建一个新的会话处理规则并使用默认的 Burp Cookie Jar，您将看到该 cookie 的新值被用于请求。

# 它是如何工作的...

当自动化针对目标应用程序的请求时，Burp Cookie Jar 用于会话处理规则的 cookie 处理。在本教程中，我们查看了 Cookie Jar，了解了其内容，甚至修改了捕获的 cookie 值之一。使用默认的 Burp Cookie Jar 的任何后续会话处理规则都将在请求中看到修改后的值。

# 添加优秀的渗透测试插件

作为 Web 应用程序测试人员，您会发现一些方便的工具，可以增加到您的工具库中，使您的评估更加高效。Burp 社区提供了许多出色的扩展。在本教程中，我们将添加其中的一些，并解释它们如何使您的评估更好。Retire.js 和软件漏洞扫描器是两个插件，这两个插件与被动扫描器一起使用。

注意：这两个插件都需要 Burp 专业版。

# 准备工作

使用 OWASP Mutilliae II 应用程序，我们将添加两个方便的扩展，以帮助我们在目标中找到更多漏洞。

# 如何做…

1.  切换到 Burp 扩展选项卡。转到 BApp Store 并找到两个插件—`Retire.js`和“软件漏洞扫描器”。为每个插件单击“安装”按钮，如下所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00361.jpeg)

1.  安装这两个插件后，转到“扩展”选项卡，然后转到“扩展”，然后转到 Burp 扩展部分。确保两个插件都启用，并在复选框内有检查标记。还要注意，软件漏洞扫描器有一个新选项卡，如下所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00362.jpeg)

1.  返回到 Firefox 浏览器，浏览到 Mutillidae 首页。右键单击并选择“被动扫描此分支”，执行轻量级、非侵入式的被动扫描，如下所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00363.jpeg)

1.  注意从这两个插件创建的额外发现。软件漏洞扫描器插件发现了许多 CVE 问题，`Retire.js`识别了五个易受攻击版本的 jQuery 实例，如下所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00364.jpeg)

# 它是如何工作的…

通过 PortSwigger API 可以扩展 Burp 功能，以创建自定义扩展，也称为插件。在本教程中，我们安装了两个插件，用于识别应用程序中包含的已知漏洞的旧版本软件。

# 通过手动扫描问题扩展创建新问题

尽管 Burp 提供了许多常见的 Web 应用程序中发现的安全漏洞列表，但偶尔您会发现一个问题并需要创建一个自定义扫描发现。这可以使用手动扫描问题扩展来完成。

注意：此插件需要 Burp 专业版。

# 准备工作

使用 OWASP Mutillidae II 应用程序，我们将添加手动扫描问题扩展，创建显示发现的步骤，然后使用扩展创建自定义问题。

# 如何做…

1.  切换到 Burp 扩展选项卡。转到 BApp Store 并找到标有“手动扫描问题”的插件。单击“安装”按钮：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00365.jpeg)

1.  返回到 Firefox 浏览器，浏览到 Mutillidae 首页。

1.  切换到 Burp 代理| HTTP 历史选项卡，并找到您刚刚浏览到首页的请求。单击“响应”选项卡。注意过于冗长的服务器标头，指示所使用的 Web 服务器类型和版本以及操作系统和编程语言。攻击者可以利用这些信息来识别技术堆栈并确定可利用的漏洞：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00366.jpeg)

1.  由于这是一个发现，我们需要手动创建一个新问题，以便在报告中捕获它。在查看请求时，右键单击并选择“添加问题”，如下所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00367.jpeg)

1.  弹出对话框出现。在“常规”选项卡中，我们可以创建一个名为“服务器响应中的信息泄露”的新问题名称。显然，您可以在问题详细信息、背景和补救领域添加更多措辞，如下所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00368.jpeg)

1.  如果我们切换到 HTTP 请求选项卡，我们可以复制并粘贴请求选项卡中消息编辑器中找到的内容到文本区域中，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00369.jpeg)

1.  如果我们切换到 HTTP 响应选项卡，我们可以复制并粘贴响应选项卡中消息编辑器中找到的内容到文本区域中。

1.  完成后，切换回“常规”选项卡，然后单击“导入发现”按钮。您应该看到新创建的扫描问题已添加到问题窗口，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00370.jpeg)

# 工作原理...

在 Burp 核心问题列表中没有可用问题的情况下，测试人员可以使用手动扫描问题扩展创建自己的问题。在这个示例中，我们为服务器响应中的信息泄露创建了一个问题。

# 另请参阅

要查看 Burp 识别的所有问题定义，请转到[`portswigger.net/kb/issues`](https://portswigger.net/kb/issues)。

# 使用 Active Scan++扩展

一些扩展可以帮助找到具有特定有效负载的漏洞，比如 XML，或者帮助找到隐藏的问题，比如缓存投毒和 DNS 重绑定。在这个示例中，我们将添加一个名为**Active Scan++**的主动扫描器扩展，它有助于识别这些更专业的漏洞。

注意：此插件需要 Burp 专业版。

# 准备工作

使用 OWASP Mutillidae II 应用程序，我们将添加 Active Scan++扩展，然后针对目标运行主动扫描。

# 操作步骤...

1.  切换到 Burp Extender | BApp Store 并选择`Active Scan++`扩展。单击“安装”按钮安装扩展，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00371.jpeg)

1.  返回到 Firefox 浏览器并浏览 Mutillidae 主页。

1.  切换到 Burp 目标选项卡，然后切换到站点地图选项卡，在`mutillidae`文件夹上右键单击，并选择“主动扫描此分支”，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00372.jpeg)

1.  当 Active 扫描向导出现时，您可以保留默认设置并单击“下一步”按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00373.jpeg)

按照提示点击“确定”开始扫描过程。

1.  在主动扫描器完成后，浏览到问题窗口。注意任何新添加的扩展发现的额外问题。您可以通过查找“This issue was generated by the Burp extension: Active Scan++”消息来确定扩展发现了哪些问题，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00374.jpeg)

# 工作原理...

Burp 功能可以通过使用扩展来扩展核心发现之外的功能。在这个示例中，我们安装了一个插件，它扩展了 Active Scanner 功能，以帮助识别额外的问题，比如任意头部注入，就像在这个示例中看到的那样。


# 第十一章：实施高级主题攻击

在本章中，我们将涵盖以下内容：

+   执行**XML 外部实体**（**XXE**）攻击

+   使用**JSON Web Token**（**JWT**）进行工作

+   使用 Burp Collaborator 来确定**服务器端请求伪造**（**SSRF**）

+   测试**跨源资源共享**（**CORS**）

+   执行 Java 反序列化攻击

# 介绍

本章涵盖了中级到高级的主题，如使用 JWT、XXE 和 Java 反序列化攻击，以及如何使用 Burp 来协助进行此类评估。对于一些高级攻击，Burp 插件在简化测试人员所需的任务方面提供了巨大的帮助。

# 软件工具要求

为了完成本章中的示例，您需要以下内容：

+   OWASP **Broken Web Applications**（**BWA**）

+   OWASP Mutillidae 链接

+   Burp 代理社区或专业版（[`portswigger.net/burp/`](https://portswigger.net/burp/)）

# 执行 XXE 攻击

XXE 是针对解析 XML 的应用程序的漏洞。攻击者可以使用任意命令操纵 XML 输入，并将这些命令作为 XML 结构中的外部实体引用发送。然后，由弱配置的解析器执行 XML，从而使攻击者获得所请求的资源。

# 准备工作

使用 OWASP Mutillidae II XML 验证器页面，确定应用程序是否容易受到 XXE 攻击。

# 如何做...

1.  导航到 XML 外部实体注入页面，即通过其他| XML 外部实体注入| XML 验证器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00375.jpeg)

1.  在 XML 验证器页面上，执行页面上提供的示例 XML。单击“验证 XML”按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00376.jpeg)

1.  切换到 Burp 代理| HTTP 历史选项卡，并查找您刚刚提交的用于验证 XML 的请求。右键单击并将请求发送到重复器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00377.jpeg)

1.  注意`xml`参数中提供的值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00378.jpeg)

1.  使用 Burp 代理拦截器，将此 XML 参数值替换为以下有效负载。这个新的有效负载将对操作系统上应该被限制查看的文件发出请求，即`/etc/passwd`文件：

```
<?xml version="1.0"?>
    <!DOCTYPE change-log[
        <!ENTITY systemEntity SYSTEM "../../../../etc/passwd">
    ]>
    <change-log>
        <text>&systemEntity;</text>
    </change-log>
```

由于新的 XML 消息中有奇怪的字符和空格，让我们在将其粘贴到`xml`参数之前，将此有效负载输入到解码器部分并进行 URL 编码。

1.  切换到解码器部分，输入或粘贴新的有效负载到文本区域。单击“编码为…”按钮，并从下拉列表中选择 URL 选项。然后，使用*Ctrl* + *C*复制 URL 编码的有效负载。确保通过向右滚动复制所有有效负载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00379.jpeg)

1.  切换到 Burp 代理拦截选项卡。使用“拦截已打开”按钮打开拦截器。

1.  返回到 Firefox 浏览器并重新加载页面。由于请求被暂停，将`xml`参数的当前值替换为新的 URL 编码的有效负载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00380.jpeg)

1.  点击“转发”按钮。通过切换按钮关闭拦截器，使拦截器处于关闭状态。

1.  请注意，返回的 XML 现在显示了`/etc/passwd`文件的内容！XML 解析器授予我们对操作系统上`/etc/passwd`文件的访问权限：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00381.jpeg)

# 工作原理...

在这个示例中，不安全的 XML 解析器接收了 XML 中对服务器上`/etc/passwd`文件的请求。由于由于弱配置的解析器未对 XML 请求执行验证，因此资源自由地提供给攻击者。

# 使用 JWT

随着越来越多的网站提供客户端 API 访问，JWT 通常用于身份验证。这些令牌包含与用户在目标网站上被授予访问权限的资源相关的身份和声明信息。Web 渗透测试人员需要读取这些令牌并确定它们的强度。幸运的是，有一些方便的插件可以使在 Burp 中处理 JWT 令牌变得更容易。我们将在本章中了解这些插件。

# 准备工作

在这个教程中，我们需要生成 JWT 令牌。因此，我们将使用 OneLogin 软件来协助完成这项任务。为了完成这个教程，请浏览 OneLogin 网站：[`www.onelogin.com/`](https://www.onelogin.com/)。点击顶部的开发人员链接，然后点击获取开发人员帐户链接（[`www.onelogin.com/developer-signup`](https://www.onelogin.com/developer-signup)）。

注册后，您将被要求验证您的帐户并创建密码。请在开始这个教程之前执行这些帐户设置任务。

使用 OneLogin SSO 帐户，我们将使用两个 Burp 扩展来检查网站分配的 JWT 令牌作为身份验证。

# 如何操作...

1.  切换到 Burp BApp Store 并安装两个插件—JSON Beautifier 和 JSON Web Tokens：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00382.jpeg)

1.  在 Firefox 浏览器中，转到您的 OneLogin 页面。URL 将特定于您创建的开发人员帐户。在开始这个教程之前，请使用您设置帐户时建立的凭据登录帐户：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00383.jpeg)

1.  切换到 Burp 代理 | HTTP 历史选项卡。找到 URL 为`/access/auth`的 POST 请求。右键单击并单击发送到 Repeater 选项。

1.  您的主机值将特定于您设置的 OneLogin 帐户：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00384.jpeg)

1.  切换到 Repeater 选项卡，注意您有两个与您安装的两个扩展相关的额外选项卡：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00385.jpeg)

1.  单击 JSON Beautifier 选项卡，以更可读的方式查看 JSON 结构：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00386.jpeg)

1.  单击 JSON Web Tokens 选项卡，以显示一个与[`jwt.io`](https://jwt.io)上可用的非常相似的调试器。此插件允许您阅读声明内容并操纵各种暴力测试的加密算法。例如，在下面的屏幕截图中，请注意您可以将算法更改为**nOnE**，以尝试创建一个新的 JWT 令牌放入请求中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00387.jpeg)

# 它是如何工作的...

两个扩展，JSON Beautifier 和 JSON Web Tokens，通过提供方便地与 Burp UI 一起使用的调试器工具，帮助测试人员更轻松地处理 JWT 令牌。

# 使用 Burp Collaborator 来确定 SSRF

SSRF 是一种漏洞，允许攻击者强制应用程序代表攻击者进行未经授权的请求。这些请求可以简单到 DNS 查询，也可以疯狂到来自攻击者控制的服务器的命令。

在这个教程中，我们将使用 Burp Collaborator 来检查 SSRF 请求的开放端口，然后使用 Intruder 来确定应用程序是否会通过 SSRF 漏洞向公共 Burp Collaborator 服务器执行 DNS 查询。

# 准备工作

使用 OWASP Mutillidae II DNS 查询页面，让我们确定应用程序是否存在 SSRF 漏洞。

# 如何操作...

1.  切换到 Burp 项目选项 | 杂项选项卡。注意 Burp Collaborator 服务器部分。您可以选择使用私人 Burp Collaborator 服务器的选项，您可以设置，或者您可以使用 PortSwigger 提供的公共互联网可访问的服务器。在这个教程中，我们将使用公共的。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00388.jpeg)

1.  勾选标有在未加密的 HTTP 上轮询并单击运行健康检查...按钮的框：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00389.jpeg)

1.  弹出框出现以测试各种协议，以查看它们是否会连接到互联网上可用的公共 Burp Collaborator 服务器。

1.  检查每个协议的消息，看看哪些是成功的。完成后，单击关闭按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00390.jpeg)

1.  从顶级菜单中，选择 Burp | Burp Collaborator 客户端：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00391.jpeg)

1.  弹出框出现。在标有生成协作者有效负载的部分，将 1 更改为 10：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00392.jpeg)

1.  单击复制到剪贴板按钮。保持所有其他默认设置不变。不要关闭 Collaborator 客户端窗口。如果关闭窗口，您将丢失客户端会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00393.jpeg)

1.  返回 Firefox 浏览器，并导航到 OWASP 2013 | A1 – Injection（其他）| HTML Injection（HTMLi）| DNS Lookup：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00394.jpeg)

1.  在 DNS Lookup 页面上，输入 IP 地址，然后单击查找 DNS 按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00395.jpeg)

1.  切换到 Burp Proxy | HTTP 历史选项卡，并找到刚刚在 DNS Lookup 页面上创建的请求。右键单击并选择发送到 Intruder 选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00396.jpeg)

1.  切换到 Burp Intruder |位置选项卡。清除所有建议的有效负载标记，并突出显示 IP 地址，单击*添加§*按钮，将有效负载标记放置在`target_host`参数的 IP 地址值周围：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00397.jpeg)

1.  切换到 Burp Intruder |有效负载选项卡，并使用粘贴按钮将从 Burp Collaborator 客户端复制到剪贴板的 10 个有效负载粘贴到有效负载选项[简单列表]文本框中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00398.jpeg)

确保取消选中有效负载编码复选框。

1.  单击开始攻击按钮。攻击结果表将在处理有效负载时弹出。允许攻击完成。请注意，`burpcollaborator.net` URL 放置在`target_host`参数的有效负载标记位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00399.jpeg)

1.  返回 Burp Collaborator 客户端，单击立即轮询按钮，查看是否有任何 SSRF 攻击成功通过任何协议。如果任何请求泄漏到网络之外，则这些请求将显示在此表中，并显示使用的特定协议。如果在此表中显示任何请求，则需要将 SSRF 漏洞报告为发现。从这里显示的结果可以看出，应用程序代表攻击者提供的有效负载进行了大量 DNS 查询：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00400.jpeg)

# 工作原理...

网络泄漏和过于宽松的应用程序参数可以允许攻击者代表应用程序通过各种协议进行未经授权的调用。在这个案例中，该应用程序允许 DNS 查询泄漏到本地机器之外并连接到互联网。

# 另请参阅

有关 SSRF 攻击的更多信息，请参阅 PortSwigger 博客条目[`portswigger.net/blog/cracking-the-lens-targeting-https-hidden-attack-surface`](https://portswigger.net/blog/cracking-the-lens-targeting-https-hidden-attack-surface)。

# 测试 CORS

实现 HTML5 CORS 的应用程序意味着该应用程序将与位于不同来源的另一个域共享浏览器信息。按设计，浏览器保护阻止外部脚本访问浏览器中的信息。此保护称为**同源策略**（**SOP**）。但是，CORS 是一种绕过 SOP 的手段。如果应用程序希望与完全不同的域共享浏览器信息，则可以通过正确配置的 CORS 标头实现。

网络渗透测试人员必须确保处理 AJAX 调用（例如 HTML5）的应用程序没有配置错误的 CORS 标头。让我们看看 Burp 如何帮助我们识别这种配置错误。

# 准备就绪

使用 OWASP Mutillidae II AJAX 版本的 Pen Test Tool Lookup 页面，确定应用程序是否包含配置错误的 CORS 标头。

# 如何做...

1.  导航到 HTML5 |异步 JavaScript 和 XML | Pen Test Tool Lookup（AJAX）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00401.jpeg)

1.  从列表中选择一个工具，然后单击查找工具按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00402.jpeg)

1.  切换到 Burp Proxy | HTTP 历史选项卡，并找到刚刚从 AJAX 版本 Pen Test Tool Lookup 页面进行的请求。切换到响应选项卡：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00403.jpeg)

1.  让我们通过选择相同响应选项卡的标题选项卡来更仔细地检查标题。虽然这是一个 AJAX 请求，但该调用是应用程序内部的，而不是跨源域的。因此，由于不需要，没有 CORS 标头。但是，如果对外部域进行调用（例如 Google APIs），则需要 CORS 标头：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00404.jpeg)

1.  在 AJAX 请求中，会调用外部 URL（例如，跨域）。为了允许外部域接收来自用户浏览器会话的 DOM 信息，必须存在 CORS 标头，包括`Access-Control-Allow-Origin: <跨域的名称>`。

1.  如果 CORS 标头未指定外部域的名称，而是使用通配符（`*`），则存在漏洞。Web 渗透测试人员应将此包括在其报告中，作为配置错误的 CORS 标头漏洞。

# 它是如何工作的...

由于此示例中使用的 AJAX 调用源自同一位置，因此无需 CORS 标头。但是，在许多情况下，AJAX 调用是向外部域进行的，并且需要通过 HTTP 响应`Access-Control-Allow-Origin`标头明确许可。

# 另请参阅

有关配置错误的 CORS 标头的更多信息，请参阅 PortSwigger 博客条目[`portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties`](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)。

# 执行 Java 反序列化攻击

**序列化**是各种语言中提供的一种机制，允许以二进制格式保存对象的状态。它用于加快速度和混淆。将对象从二进制转换回对象的过程称为反序列化。在使用用户输入创建对象并将该对象序列化后，会为任意代码注入和可能的远程代码执行创建攻击向量。我们将看一下 Burp 扩展，它将帮助 Web 渗透测试人员评估 Java 反序列化漏洞的应用程序。

# 准备工作

```
Java Serial Killer Burp extension to assist in performing Java deserialization attacks.
```

# 如何操作...

1.  切换到 Burp BApp Store 并安装 Java Serial Killer 插件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00405.jpeg)

为了创建一个使用序列化对象的场景，我们将采用标准请求，并向其添加一个序列化对象，以演示您如何使用扩展程序向序列化对象添加受攻击者控制的命令。

1.  请注意，您的 Burp UI 菜单顶部添加了一个新的选项卡，专门用于新安装的插件。

1.  导航到 Mutillidae 主页。

1.  切换到 Burp Proxy| HTTP 历史选项卡，并查找刚刚创建的请求，方法是浏览到 Mutillidae 主页：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00406.jpeg)

不幸的是，Mutillidae 中没有序列化对象，所以我们必须自己创建一个。

1.  切换到解码器选项卡并复制以下序列化对象的片段：

```
AC ED 00 05 73 72 00 0A 53 65 72 69 61 6C 54 65
```

1.  将十六进制数粘贴到解码器选项卡，单击“编码为...”按钮，然后选择 base 64：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00407.jpeg)

1.  从解码器选项卡复制 base-64 编码的值，并将其粘贴到您发送到 Java Serial Killer 选项卡底部的请求中。使用*Ctrl* + *C*从解码器复制，*Ctrl* + *V*粘贴到请求的白色空间区域中的任何位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00408.jpeg)

1.  在 Java Serial Killer 选项卡中，从下拉列表中选择一个 Java 库。对于这个示例，我们将使用 CommonsCollections1。勾选 Base64 编码框。添加一个命令嵌入到序列化对象中。在这个示例中，我们将使用 nslookup 127.0.0.1 命令。突出显示有效载荷并单击“序列化”按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00409.jpeg)

1.  单击“序列化”按钮后，注意有效载荷已更改，现在包含您的任意命令并且已进行 base-64 编码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/bpst-cb/img/00410.jpeg)

1.  单击 Java Serial Killer 选项卡中的“Go”按钮以执行有效载荷。即使您可能会收到响应中的错误，理想情况下，您将拥有一个侦听器，例如`tcpdump`，用于监听端口`53`上的任何 DNS 查询。从侦听器中，您将看到对 IP 地址的 DNS 查询，该 IP 地址是您在`nslookup`命令中指定的。

# 它是如何工作的...

在应用程序代码接收用户输入并将其直接放入对象而不对输入进行消毒的情况下，攻击者有机会提供任意命令。然后对输入进行序列化并在应用程序所在的操作系统上运行，从而为远程代码执行创建可能的攻击向量。

# 还有更多...

由于这个示例场景有点牵强，您可能无法在`nslookup`命令的网络监听器上收到响应。在下载已知存在 Java 反序列化漏洞的应用程序的易受攻击版本（即 Jenkins、JBoss）后，再尝试此示例。重复此处显示的相同步骤，只需更改目标应用程序。

# 另请参阅

+   有关真实世界的 Java 反序列化攻击的更多信息，请查看以下链接：

+   **赛门铁克**：[`www.symantec.com/security_response/attacksignatures/detail.jsp?asid=30326`](https://www.symantec.com/security_response/attacksignatures/detail.jsp?asid=30326)

+   福克斯格洛夫安全：[`foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/`](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/)

+   要了解有关这个 Burp 插件的更多信息，请访问[`blog.netspi.com/java-deserialization-attacks-burp/`](https://blog.netspi.com/java-deserialization-attacks-burp/)
