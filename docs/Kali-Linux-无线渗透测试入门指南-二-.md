# Kali Linux 无线渗透测试入门指南（二）



# 第八章：攻击企业级 WPA 和 RADIUS

> 作者：Vivek Ramachandran, Cameron Buchanan

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

> 个头越大，摔得越惨。

> -- 谚语

企业级 WPA 总是自带不可攻破的光环。多数网络管理员认为它对于无线安全问题是个银弹。在这一章中，我们会看到这个真理不再正确了。

这一章中，我们会了解如何使用多种 Kali 包含的工具和技巧，来攻击企业级 WPA。

## 8.1 配置 FreeRADIUS-WPE

我们需要 RADIUS 服务器来实施企业级 WPA 攻击。最广泛使用的开源 RADIUS 服务器时 FreeRADIUS。但是，它难于配置，并且为每次攻击而配置它十分无聊。

Joshua Wright 是一个知名的安全研究员，他写了一个 FreeRADIUS 的补丁使其易于配置和执行攻击。这个补丁以 FreeRADIUS-WPE 发布。Kali 没有自带 FreeRADIUS-WPE ，所以我们需要执行下列步骤来配置。

1.  访问` https://github.com/brad-anton/freeradius-wpe `并且你会找到下载连接：` https://github.com/brad-anton/ freeradius-wpe/raw/master/freeradius-server-wpe_2.1.12-1_i386. deb`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-1-1.jpg)
    
2.  下载完成之后，在`ldconfig`之后使用` dpkg –i freeradius-server-wpe_2.1.12-1_ i386.deb `来安装：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-1-2.jpg)
    
    我们现在需要快速在 Kali 上配置 Radius 服务器。
    
### 实战时间 -- 使用 FreeRADIUS-WPE  建立 AP

1.  将接入点的 LAN 端口之一连接到你的 Kali 主机的以太网端口。我们这里的接口是`eth0`。启动这个接口并通过运行 DHCP 获得 IP 地址，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-1-3.jpg)
    
2.  登录接入点，将安全模式设为 WPA/WPA2-Enterprise，将`Version`设为 WPA2，将`Encryption `设为 AES。之后，在` EAP (802.1x) `部分下面，输入 Radius 服务器 IP 地址，就是你的 Kali 的 IP 地址。 `Radius Password `是`test`，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-1-4.jpg)
    
3.  让我们现在打开新的终端，访问目录`/usr/local/etc/raddb`。这是所有 FreeRADIUS-WPE  配置文件存放的地方。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-1-5.jpg)
    
4.  让我们打开`eap.conf`。你会发现`default_eap_type`设为了 MD5，让我们将它改为`peap`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-1-6.jpg)
    
5.  让我们打开`clients.conf`。这就是我们定义客户端白名单的地方，它们能够连接到我们的 Radius 服务器。有趣的是，如果你浏览到下面，忽略设置示例，范围`192.168.0.0/16 `的`secret`默认设为`test`，这就是我们步骤 2 中所使用的。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-1-7.jpg)
    
6.  我们现在使用`radiusd –s –X `命令启动 RADIUS 服务器。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-1-8.jpg)
    
7.  一旦启动完毕，你会在屏幕上看到一堆调试信息，但是最后服务器会安顿下来并监听端口。太棒了！我们现在可以开始这一章的实验了。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-1-9.jpg)
    
### 刚刚发生了什么？

我们成功配置了 FreeRADIUS-WPE。我们会在这一章的实验的剩余部分使用它。

### 试一试 -- 玩转 RADIUS

FreeRADIUS-WPE  拥有大量选项。使你自己熟悉它们是个好的主意。花费时间来查看不同的配置文件，以及它们如何协同工作非常重要。

## 8.2 攻击 PEAP

受保护的可扩展的身份验证协议（PEAP）是 EAP 的最广泛使用的版本。这是 Windows 原生自带的 EAP 机制。

PEAP 拥有两个版本：

+   使用 EAP-MSCHAPv2  的 PEAPv0（最流行的版本，因为 Windows 原生支持）。
+   使用 EAP-GTC 的 PEAPv1。

PEAP 使用服务端的证书来验证 RADIUS 服务器。几乎所有 PEAP 的攻击都会利用证书验证的不当配置。

下一个实验中，我们会看一看如何在客户端关闭证书验证的时候破解 PEAP。

### 实战时间 -- 破解 PEAP

遵循以下指南来开始：

1.  再次检查` eap.conf `文件来确保开启了 PEAP：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-2-1.jpg)
    
2.  之后重启 RADIUS 服务器，使用`radiusd –s –X`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-2-2.jpg)
    
3.  监控由 FreeRADIUS-WPE 创建的日志文件：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-2-3.jpg)
    
4.  Windows 原生支持 PEAP。让我们确保关闭了证书验证：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-2-4.jpg)
    
5.  我们需要点击`Configure `标签页，它在`Secured password`的旁边，并告诉 Windows 不要自动使用我们的 Windows 登录名称和密码：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-2-5.jpg)
    
6.  我们也需要在`Advanced  Settings`对话框中选择`User authentication`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-2-6.jpg)
    
7.  一旦客户端连接到了接入点，客户端会提示输入用户名和密码。我们使用`Monster`作为用户名，`abcdefghi `作为密码：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-2-7.jpg)
    
8.  一旦我们完成了，我们就能在日志文件中看到 MSCHAP-v2 challenge 响应。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-2-8.jpg)
    
9.  我们现在使用`asleap`来破解它，使用包含`abcdefghi`的密码列表文件，我们能够破解它。（出于演示目的，我们只创建了单行的文件，叫做`list`，其中包含列表。）

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/8-2-9.jpg)
    
### 刚刚发生了什么？

我们使用 FreeRADIUS-WPE 建立了蜜罐。企业客户端配置不当，没有使用 PEAP 证书验证。这允许我们将我们的伪造证书展示给客户端，它被乐意接受了。一旦它发生了，内部验证协议 MSCHAP-v2 开始生效。由于客户端使用我们的伪造证书来解密数据，我们能够轻易读取用户名、challenge 和响应元组。

MSCHAP-v2 易于受到字典攻击。我们使用`asleap`来破解 challenge  和响应偶对，因为它看起来基于字典中的单词。

### 试一试 -- 攻击 PEAP 的变体

PEAP 可以以多种方式不当配置。即使打开了证书验证，如果管理员没有在连接到服务器列表中提到验证服务器，攻击者可以从任何列出的签证机构获得其他域的真实证书。这仍旧会被客户端接受。这个攻击的其他变体也是可能的。

我们推荐你探索这一章的不同可能性。

## EAP-TTLS

我们推荐你尝试攻击 EAP-TTLS，它类似于这一章我们对 PEAP 所做的事情。

## 企业安全最佳实践

我们意见看到了大量的对 WPA/WPA2 的攻击，有个人也有企业。基于我们的经验，我们推荐下列事情：

+   对于 SOHO 和中型公司，使用强密码的 WPA2，你总共能输入 63 个字符，好好利用它们。

+   对于大型企业，使用带有 EAP-TLS 的企业级 WPA2。这会同时在客户端和服务器使用证书来验证，目前没办法攻破。

+   如果你需要带有 PEAP 或者 EAP-TTLS 的 WPA2，确保你的证书验证打开，选择了正确的签发机构，RADIUS 服务器开启了授权，最后，关闭任何允许用户接受新的 RADIUS 服务器、证书或者签发机构的配置。

## 小测验 -- 攻击企业级 WPA 和 RADIUS

Q1 FreeRADIUS-WPE 是什么？

1.  从头开始编写的 RADIUS 服务器。
2.  FreeRADIUS 服务器的补丁。
3.  所有 Linux 默认自带的版本。
4.  以上都不是。

Q2 下列哪个可以用于攻击 PEAP？

1.  伪造验证信息
2.  伪造证书
3.  使用 WPA-PSK
4.  以上全部

Q3 EAP-TLS 使用了什么？

1.  客户端证书
2.  服务端证书
3.  1 或者 2
4.  1 和 2

Q4 EAP-TTLS 使用了什么？

1.  只有客户端证书
2.  服务端证书
3.  基于密码的验证
4.  LEAP

## 总结

这一章中，我们看到了如何攻破运行 PEAP 或者 EAP-TTLS 的企业级 WPA。它们是两个用于企业的最常见的验证机制。

下一章中，我们会看一看如何把我们学到的所有东西用于真实的渗透测试。


# 第九章：无线渗透测试方法论

> 作者：Vivek Ramachandran, Cameron Buchanan

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

> 空谈不如实干。

> -- 谚语

这一章会列出一些步骤，用于使用前几章所教授的技巧，并把它们变为完整的无线渗透测试。

## 无线渗透测试

为了进行无线渗透测试，遵循确定的方法论十分重要。仅仅执行`airbase `或`airodump`命令，并抱有乐观的心态并不满足测试目标。在作为渗透测试者工作的时候，你必须确保遵循为其工作的组织标准，并且如果它们没有的话，你应该遵循你自己的最高标准。

宽泛地说，我们可以将无线渗透测试划分为下列阶段：

1.  规划阶段
2.  探索阶段
3.  攻击阶段
4.  报告阶段

我们现在会分别观察这些阶段。

## 规划

在这个阶段，我们必须懂得下列事情：

+   评估范围：渗透测试者应该与客户端打交道，来定义所要到达的范围，并且同时获得网络安全的大量洞察。通常，需要收集下列信息：

    +   渗透测试的位置
    +   区域的全部覆盖范围
    +   所部署的接入点和无线客户端近似数量
    +   涉及到哪个无线网络
    +   是否存在利用
    +   是否需要针对用户的攻击
    +   是否需要拒绝服务
    
+   工作量估计：基于所定义的范围，测试者之后需要估算需要多少时间。要记住在此之后可能需要重新定义范围，因为组织可能在时间和金钱上只有有限的资源。

+   合法性：在执行测试之前，客户必须达成移植。这应该用于解释被涉及的测试，以及清晰定义补偿等级、保险和范围限制。如果你不确定，你需要和这个区域内的专家沟通。多数组织拥有他们自己的版本，也可能包含保密协议（NDA）。

一旦满足了所有先决条件，我们就可以开始了。

## 探索

这个阶段中，目标是识别和应用范围内无线设备和无线网络的特征。

所有用于完成它的技术已经在之前的章节中列出了，简单来说，目标就是：

+   枚举区域内所有可见和隐藏的无线网络。
+   枚举区域内的设备，以及连接到目标网络的设备。
+   映射区域内的网络，它们能够从哪里到达，以及是否有一个地方，恶意用户可以在这里执行攻击，例如咖啡厅。

所有这些信息应该被记录。如果测试仅限于侦查行为，测试在这里就结束了，测试者会试图基于这些信息作总结。一些语句对于客户可能有用，像这样：

+   连接到开放网络和公司网络的设备数量
+   拥有可以通过某个解决方案，例如 WiGLE ，连接到某个区域的网络的设备数量
+   存在弱加密
+   网络设置非常强大

## 攻击

一旦完成了侦查，就必须执行利用，用于证明概念。如果攻击作为红方或者更宽泛的评估的一部分，就应该尽可能秘密地执行利用来获得网络的访问权。

在我们的攻击阶段，我们会探索下列事情：

+   破解加密
+   攻击设施
+   入侵客户端
+   发现漏洞客户端
+   发现未授权的客户端

### 破解加密

第一步是获得所识别的任何漏洞网络的密钥。如果网络存在 WEP 加密，执行第四章中的 WEP 破解方法。如果它是 WPA2 加密的，你有两个选择。如果要秘密行动，在人们可能验证和解除验证的时间段，达到现场几次，这些时间段是：

+   一天的开始
+   午饭时间
+   一天的结束

这时，配置好你的 WPA 密钥检索器，像第四章那样。也可以执行解除验证攻击，就像第六章那样。

在成熟的组织中，这会产生噪声，并更容易被发现。

如果企业级 WPA 存在，要记住你需要使用侦查阶段收集的信息来定位正确的网络，并将你的伪造站点配置好，就像第八章那样。

你可以尝试破解所有密码，但是要记住有些是不能破解的。遵循测试的指南，检查无线管理员所使用的密码，看看密码是否足够安全。你作为测试者，不要由于工具或运气原因而失败。

### 攻击设施

如果网络访问由破解加密获得，如果允许的话，在范围内执行标准的网络渗透测试。至少应该执行下面这些：

+   端口扫描
+   识别运行的设备
+   枚举任何开放的服务，例如无验证的 FTP、SMB 或者 HTTP
+   利用任何识别的漏洞服务

### 入侵客户端

在枚举和测试所有无线系统之后，我们可以对客户端执行多种适合的攻击。

必要的话，在判断哪个客户端容易受到 Karma  攻击之后，创建蜜罐来迫使他们使用第八章中的方式连接。通过这种方式我们可以收集到多种有用的信息片段，但是要确保收集到的信息出于某个目的，并且以更安全的方式储存、传播和使用。

## 报告

最后，在测试的末尾，需要将你的发现报告给客户。确保报告符合测试的质量非常重要。由于客户仅仅会看到你的报告，你需要在执行测试的时候额外关注它。下面是报告大纲的指南：

+   管理总结
+   技术总结
+   发现：
    +   漏洞描述
    +   严重性
    +   受影响的设备
    +   漏洞类型 -- 软件/硬件/配置
    +   补救措施
+   附录

管理总结是为了汇报给非技术听众，应该专注于较高等级所需的影响和解决方案。避免太技术化的语言并确保涉及到了根本原因。

技术总结应该在管理总结和发现列表之间取得平衡。它的听众是开发者或者技术领导，专注于如何解决问题，和能够实现的更宽泛的解决方案。

发现列表应该在较低等级描述每个漏洞，解释用于识别、复制的方式，以及缺陷。

附录应该包含额外的信息，它们不能较短地描述。任何截图、POC、和窃取的数据应该展示在这里。

## 总结

这一章中，我们讨论了执行范围内的无线测试的方法论，并且引用了每一步的相关章节。我们也列出了用于报告错误的方法，以及使技术数据更加漂亮的技巧。下一章是最后一章，我们会涉及到自从这本书第一版发布以来的心肌桥，WPS，以及探针监控。


# 第十章：WPS 和 探针

> 作者：Vivek Ramachandran, Cameron Buchanan

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

> 太阳底下无新事。

> -- 谚语

这一章由新的技巧组成，包括攻击 WPS 和探针监控，也包含了使无线测试更简单的 pineapple 工具。这些攻击和工具在本书第一版的发布过程中出现，我们要确保这本书尽可能全面。

## 10.1 WPS 攻击

无线保护设置（WPS）在 2006 年被引入，用于帮助没有无线知识的用户保护网络。其原理是它们的 WIFI 拥有单一隐藏的硬编码值，它可以允许密钥记忆来访问。新的设备可以通过按下 WIFI 路由上的按钮来验证。在房子外面的人不能解除设备，就不能获得访问权。所以这个问题被降解为记住 WPA 密钥或者设置更短的密钥。

2011 年末，爆破 WPS 验证系统的安全漏洞被公开。协商 WPS 交换所需的流量易于被一篇，并且 WPS Pin 本身只有 0~9 的 8 个字符。最开始，这可以提供 100,000,000 中可能性，与之相比，8 个字符的 azAZ09 密码拥有 218,340,105,584,896 种组合。

但是，这里存在进一步的漏洞：

+   在 WPS Pin 的八个字符中，最后一个是前七个的校验和，所以它可以预测，选择就只剩下  10,000,000  种了。

+   此外，前四个和后三个字符分别验证，这意味着一共有 11,000 种选择。

虽然验证机制中要判断两次，但是我们已经从 100,000,000 个可能的组合降到了 11,000。这相当于爆破算法时的六个小时的差异。这些判断使 WPS 更易受攻击。

在下一个实验中，我们会使用 Wash 和 Reaver 识别和攻击 WPS 漏洞配置。

### 实战时间 -- WPS 攻击

遵循以下步骤来开始：

1.  在我们攻击开启了 WPS 的接入点之前：我们首先要创建它。我们所使用的 TP-LINK 拥有这个也行，默认开启，它非常麻烦还是便捷。为了再三检查它，我们可以登入我们的路由并点击 WPS。它看起来是这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/10-1-1.jpg)
    
2.  现在我们确认它准备好了。我们需要启动我们的目标。我们需要配置我们的测试环境。我们打算使用 Wash 工具，并且 Wash 需要监控器接口来生效。就像我们之前做的那样，我们需要使用下列命令来启动：

    ```
    airmon-ng start wlan0
    ```
    
    输出是这样：
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/10-1-2.jpg)
    
3.  我们拥有了监控接口，设置为`mon0`，我们可以使用下列命令调用 Wash：

    ```
    wash --ignore-fcs -i mon0
    ```
    
    `ignore fcs`选项是由于`wash`导致的已知请求格式的问题：
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/10-1-3.jpg)
    
4.  我们会展示所有附近 支持 WPS 的设备。以及它们是否开启或解锁了 WPS，以及它们的版本：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/10-1-4.jpg)
    
5.  我们可以看到`Wireless Lab `支持 WPS。它使用版本 1 并且没有锁住。太好了。我们注意到 MAC 地址，它在我这里是`E8:94:F6:62:1E:8E`，这会作为下一个工具`reaver`的目标。

6.  Reaver 尝试爆破给定 MAC 地址的 WPS Pin。启动它的语法如下：

    ```
    reaver -i mon0 -b <mac> -vv
    ```
    
    输出是这样：
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/10-1-5.jpg)
    
7.  启动之后，这个工具执行所有可能的 WPS 组合，并尝试验证。一旦它完成了，它会返回 WPS 码和密码，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/10-1-6.jpg)
    
8.  得到 WPA-PSK 之后，我们可以正常验证了。我把匹配 WPS Pin 的默认的 WPA-PSK 留给我的设备，你可以通过在`reaver`中指定 Pin 来实现，使用下列命令：

    ```
    reaver -i mon0 -b <mac> -vv -p 88404148
    ```
    
    将我的 Pin 换成你的。
    
### 刚刚发生了什么？

我们使用 Wash 成功识别了带有 WPS 漏洞实例的无线网络。之后我们使用 Reaver 来恢复 WPA 密钥和 WPS Pin。使用这个信息，我们之后能够验证网络并继续网络渗透测试。

### 试一试 -- 速率限制

在之前的联系中，我们攻击了整个未加密的 WPS 安装。我们可以使用多种方法来进一步探索安全的安装，不需要移除 WPS。

尝试将 WPS Pin 设置为任意值并再次尝试，来看看 Reaver 是否能够快速破解。

获得允许你限制 WPS 尝试速率的路由器。尝试和调整你的攻击来避免触发锁定。

## 10.2 探针嗅探

我们已经谈到了探针，以及如何使用它们来识别隐藏的网络，和执行有效的伪造接入点攻击。它们也可以将个体识别为目标，或者在大范围内以最少的努力识别它们。

当设备打算连接网路是，它会发送探测请求，包含它自己的 MAC 地址和想要连接的网络名称。我们可以使用工具，例如`airodump-ng`来跟踪它们。但是，如果我们希望识别个体是否在特定位置特定时间内出现，或者在 WIFI 使用中发现趋势，我们就需要不同的方式。

这一节中，我们会使用 tshark 和 Python 来收集数据。你会收到代码和完成了什么的解释。

### 实战时间 -- 收集数据

遵循下列指南来开始：

1.  首先，我们需要寻找多个网络的设备。通常，普通的安卓或者 iPhone 智能收集就足够了。台式机通常不是良好的目标，因为它们只能待在一个地方。新的 iPhone 或安卓设备可能禁用了探测请求，或者不清楚，所以在你放弃之前检查一下。

2.  一旦你搞定了设备，确保打开了 WIFI。

3.  之后启动你的监控接口，像之前那样。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/10-2-1.jpg)

4.  下面要完成的事情就是使用`tshark`寻找探测请求，通过下列命令：

    ```
    tshark -n -i mon0 subtype probereq
    ```
    
    命令的截图如下：
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/10-2-2.jpg)
    
5.  你这里的输出会有些混乱，因为`tshark`的默认输出没有为可读而涉及，只是尽可能展示很多信息。它看起来应该是这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/10-2-3.jpg)
    
6.  你已经可以看到 MAC 地址和探测请求的 SSID。但是，输出还可以更好。我们可以使用下列命令来使其更加可读取：

    ```
    tshark –n –i mon0 subtype probereq –T fields –e separator= -e wlan.sa –e wlan_mgt.ssid
    ```
    
    命令的截图如下：
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/10-2-4.jpg)
    
7.  输出会变得更加可读：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-bgd/img/10-2-5.jpg)
    
8.  所以现在我们获得了可读格式的输出，下面呢？我们要创建 Python 脚本，执行命令并记录输出用于之后的分析。在执行代码之前，你需要确保你准备好了监控接口，并在目录中创建了`results.txt `文件。Python 脚本如下：

    ```py
    import subprocess 
    import datetime 
    results = open("results.txt", "a") 
    while 1: 
        blah = subprocess.check_output(["tshark –n –i mon0 subtype probereq –T fields –e separator= -e wlan.sa –e wlan_mgt.ssid –c 100"], shell=True) 
        splitblah = blah.split("\n") 
        for value in splitblah[:-1]: 
            splitvalue = value.split("\t") 
            MAC = str(splitvalue[1]) 
            SSID = str(splitvalue[2]) 
            time = str(datetime.datetime.now()) 
            Results.write(MAC+" "+SSID+" "+time+"\r\n")
    ```

    让我们简单看一看 Python 脚本：
    
    +   `import subproces`库和`datetime `库：这允许我们引用子进程和日期时间库。`subprocess `允许我们从 Linux 命令行监控接口，而`datetime`库允许我们获得准确时间和日期。
    
    +   `while 1`：这行代码在停止之前一直执行。
    
    +   `results = open("results.txt", "a")`：这使用附加模式打开了文件，并将其赋给`results`。附加模式只允许脚本添加文件的内容，这会防止文件被覆写。
    
    +   `blah = subprocess.check_output(["tshark –n –I mon0 subtype probereq –T fields –e separator= -e wlan.sa –e wlan_mgt.ssid –c 100"], shell=True)`：这打开了 shell 来执行我们之前侧事故的`tshark`命令。这次唯一的区别就是`-c 100`。这个选项所做的就是将命令限制为 100 个查询。这允许我们将节骨哦返回给我们自己，而不需要停止程序。因为我们说过在写入结果之后永远运行，这个脚本会再次启动。
    
    +   这行代码从 shell 获得输出，并将其赋给变量`blah`。
    
    +   `splitblah = blah.split("\n")`：接收变量`blah`并按行分割。
    
    +   `for value in splitblah[:-1]`：对输入的每一行重复下面的操作，忽略包含头部的第一行。
    
    +   `splitvalue = value.split("\t")`：将每一行拆分成更小的片段，使用`tab`字符作为分隔符。
    
    +   下面的三行接收每个文本段并将其赋给变量：
    
        ```py
        MAC = str(splitvalue[1]) 
        SSID = str(splitvalue[2]) 
        time = str(datetime.datetime.now()
        ```
        
    +   `results.write(MAC+" "+SSID+" "+time+"\r\n")`：接收所有这些值，将其写到文件中，由空格分隔，为了整洁最后附带回车和换行符。
    
写到文件的输出是整洁的文本行。

## 刚刚发生了什么？

我们从探测请求接收输入，并将其使用 Python 输出到文件中。

你可能会问自己它的目的是什么。这可以仅仅通过执行原始的`tshark`命令并添加`>> results.txt`来完成。你是对的，但是，我们创建了集成其它工具，可视化平台，数据库，以及服务的框架。

例如，使用 WiGLE 数据库，将 SSID 映射为位置，你就可以添加新的代码行接受 SSID 变量并查询 WIGLE 数据库。

作为替代，你也可以建立 MySQL 数据库并将输出保存到这里来执行 SQL 命令。

这一节向你提供了创建你自己的探测监控攻击的第一步。通过这个实验，并使用这个简单的代码作为第一步，就可以创建多数实用的工具。

### 试一试 -- 扩展概念

研究什么工具可用于可视化和数据分析，并易于集成到 Python。例如 Maltego 的工具拥有免费版本，可以用于绘制信息。

为你自己建立 MySQL 数据库来记录数据和重新调整之前的 Python 脚本，将结果输出到数据库。之后，构建另一个脚本（或在相同文件中）来获得数据并输出到 Maltego。

重新调整脚本来查询 WIGLE，之后从探测请求中收集地理位置数据。通过 Maltego 来输出数据。

尝试通过 Flask、Django 或 PHP 建立 Web 前端来展示你的数据。为展示数据研究现有的解决方案，并尝试通过与它们的创建者交谈来模拟和改进它们。

## 总结

这一章中，我们谈论了针对 WPS 的攻击，它在本书第一版的发布过程中出现。同时也初步尝试了将无线工具使用 Python 集成。我们已经到达了本书的末尾，我希望它充实而又有趣。七年后的第三版再见吧。
