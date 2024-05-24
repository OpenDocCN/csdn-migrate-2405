# 精通 Kali Linux Web 渗透测试（二）

> 原文：[`annas-archive.org/md5/F7A8D19093C3DEFCEB9810DC24577B59`](https://annas-archive.org/md5/F7A8D19093C3DEFCEB9810DC24577B59)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：通过加密测试利用信任

商用加密和密码方法的发展对于互联网作为全球经济引擎的采用至关重要。网络已经走过了很长的路，从早期的浏览器如 Erwise 和 Mosaic 向主要教育用户提供静态、开放信息的日子。很难想象网络曾经是纯文本的时代，信息在没有任何防盗或窥探保护的情况下传输（以及存储）。现在，互联网促进的金融、个人和知识交易受到数学驱动算法的保护，如安全套接字层（SSL）/传输层安全性（TLS）、高级加密标准（AES）、安全散列算法（SHA）和 Diffie-Helman（DH）。这些标准以及更多，再加上用于共享密钥的广泛基础设施，使我们能够信任这些交易。这种信任是可以理解的；消费级电子产品和开源软件可以轻松实现加密技术，以提供信息安全的三个关键原则；保密性、完整性和可用性（CIA）。当然，这假设每个人都在使用正确的标准和协议，并且它们被正确配置。

针对加密方法（以及相关领域，如隐写术）的攻击通常避免尝试破解加密本身。苹果公司与美国司法部之间关于 iPhone 后门的战斗说明了这一点；加密通信是廉价且容易的，但要破解相同的加密却非常困难。攻击者可能会试图在加密之前拦截信息，或者在接收方解密后拦截信息。从技术上讲，这更容易，但从实际上讲，他们必须在这些主机上。欺骗发送方和接收方；源和目的地相信他们自己的系统是两个感兴趣的方之一会更容易吗？这本质上就是中间人攻击，其用途远不止拦截。

中间人攻击在许多形式的黑客攻击中很受欢迎；捕获凭据、导致恶意软件传递的污染的网络流量、重定向到恶意门户，或者收集和潜在操纵流本身都是可能的。防御这些恶意用途变得更加困难，因为相同的技术在企业中也有合法用途。Web 代理和防火墙使用 SSL/TLS 中间人攻击是有益的，帮助隐藏和保护最终用户和他们的客户端，允许进行全面检查和内容过滤，并确保免受拒绝服务攻击和隐私侵犯。只要这两种相反的用途存在，攻击者就可以利用它们来黑客我们的客户。

我们必须能够发现和验证所有可察觉的缺陷，无论是通过规避还是中间人攻击。在本章中，我们将看到加密是如何在 Web 应用程序通信中使用的，窥视加密会话，并使用中间人攻击规避加密或突破加密。在本章中，我们将讨论以下主题：

+   学习如何持久攻击者可以通过 OpenSSL，SSLyze 和 SSLscan 检测到弱密码的妥协以及我们如何检测它们

+   体验我们如何对安全连接执行中间人攻击，发现有趣的有效载荷，并使用 SSLsplit 和 SSLsniff 进行操纵。

+   通过充当中间人并使用 SSLstrip 从流中删除加密来完全击败 SSL

## 你的秘密有多保密？

* * *

据估计，SSL/TLS 在网络流量中的使用率超过 60％，并且由于公众对黑客和政府的窥探和拦截的看法，我们应该预计这一比例将继续上升。虽然在实践中很困难，但如果获取的数据价值足够大，攻击者的时间确实是值得的。OWASP 的十大威胁列表在多个周期中都将**敏感数据暴露**列为最严重的威胁，2013 年和 2017 年的版本都将其排名为第 6 位：对 Web 应用程序最令人担忧的威胁。

在他们的敏感数据暴露部分的总结中（如下图所示），如果 Web 开发人员正确配置并使用当前技术和模块版本来提供保护，那么将会更加困难。我们的测试中相当大一部分将围绕检查过时的软件包、不足的密钥强度和配置错误的端点展开。也就是说，如果所有这些事情都得到了正确的配置，我们将看到一些中间人攻击如何帮助克服这种保护。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_08_01.png)

OWASP 的破坏身份验证和会话劫持特征化

在开始之前，了解我们正在讨论的加密应用程序的类型是有帮助的。鉴于它在信息技术中的广泛应用，我们需要将此讨论范围限制在 Web 服务器及其服务器-客户端关系的范围内。即使在这种情况下，存在许多潜在的拓扑结构，但它们都有一些共同的元素，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_08_02.png)

基本 SSL/TLS 结构和攻击点

一种不断增长的攻击手段涉及利用 DNS 和 PKI 基础设施来增强中间人攻击，并欺骗警惕的客户端，使其相信它们确实连接到适当的服务器或合法的代理（未显示）。这里的每个元素都将有自己的能力。我们作为测试人员的工作是找出哪些元素正在损害端到端的完整性。

## 像专业人士一样评估加密

* * *

通过连接到应用程序并查看协商的内容，可以简单地识别和验证应用程序的加密配置和潜在缺陷。这可能是相当费力的，所以幸运的是我们有一些快速扫描工具，可以系统地协商服务器的所有潜在配置，以更好地帮助我们了解它们允许的内容。

我仍然建议花一些时间学习如何手动测试 SSL/TLS，因为随时进行快速检查以确保版本、密码偏好和类似内容是非常方便的。[`www.exploresecurity.com/wp-content/uploads/custom/SSL_manual_cheatsheet.html`](http://www.exploresecurity.com/wp-content/uploads/custom/SSL_manual_cheatsheet.html)提供了一份很好的说明和备忘录。

### SSLyze-它切片，它扫描â�¦

在这方面，我们的第一个工具可能是你唯一需要的工具。用 Python 编写的 SSLyze ([`github.com/iSECPartners/sslyze`](https://github.com/iSECPartners/sslyze))将使用几乎任何当前使用的传输协议与服务器进行通信，并且速度很快！通过在所有类型的协议上启动 StartTLS 握手与服务器进行通信，它可以扫描密码套件问题，协商缺陷，证书不一致以及许多在新闻中引起关注的 SSL 相关漏洞（Heartbleed，CRIME 等）。

使用 SSLyze 是小菜一碟；您可以选择一些选项进行传递，然后同时测试多个服务器。这些选项可以帮助细化被测试的版本，与连接相关的超时和重试，添加客户端证书或*cert*以进行相互认证测试，并测试压缩和恢复。我倾向于使用常规选项和 Heartbleed 模块，并将输出写入文本文件。在这个例子中，我们将针对网站[www.hackthissite.org](http://www.hackthissite.org)运行：

```
sslyze [Options] [host:port | host]
sslyze ; regular ; heartbleed www.hackthissite.org:443 >>hackthissite.txt
```

如您在下面的截图中所见，SSLyze 为我们提供了大量的测试。我将广泛的输入转储到文本文件中，以更好地剪裁空白部分，但它们提供的主要见解领域是对站点的完整健康检查。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_08_03-861x1024.png)

SSLyze 扫描输出

如您从输出中所见，有很多内容需要消化。第 1 部分概述了工具的实例化和基本连接。如果服务器输入不正确，脚本将在此退出。第 2 部分（为简洁起见剪裁）涵盖了使用已知的受信任的 PKI 证书颁发机构进行证书检查，以确保证书充分关联。证书存在问题可能会使攻击者假冒合法服务器的身份，从而劫持流量用于其自己的恶意需求。第 3 部分将帮助我们查看与插件相关的特殊压力测试的结果，例如 Heartbleed 模块和服务器的会话恢复能力。第 4 部分突出显示了可用的密码；支持较弱或已知易受攻击的密码套件的服务器只会招来麻烦。第 5 部分非常直接；扫描花了多长时间？过去，在测试 Cisco 防火墙时，推断启用和协商的密码套件的手动过程可能需要几个小时。还不错，但偶尔可能会提供不同的结果，因此让我们看看另一个工具，它可以帮助交叉检查并为我们提供另一个数据点。

### SSLscan 也可以！

SSLscan 是 Kali 中提供的另一个工具，擅长自动化扫描过程，帮助我们评估软件版本、使用的密码以及安全连接的许多其他方面。SSLscan 是用 C 语言构建的，利用了 OpenSSL 1.0.1 库，也是跨平台的，因此如果您需要 Microsoft Windows 或 Mac OS 版本的应用程序，它们是可用的。SSLscan 的选项更加简单直接，它们有助于文件简洁，虽然这使得它非常容易运行，但同时也有助于运行另一个具有更多 PKI 方面细节的工具。要运行 SSLscan，您可以简单地使用以下语法进行扫描：

```
sslscan [Options] [host:port | host]
sslscan www.hackthissite.org
```

如您从下面的截图中所见，它提供了更紧凑的输出，但其中一些是以牺牲证书检查和细节为代价的，这些在您的渗透测试中可能会有用。使用相同的颜色代码和编号方案来帮助与 SSLyze 输出形成对比：第 1 部分概述了工具的基本连接测试；第 2 部分显示了较少冗长的证书检查；第 3 部分仅限于 Heartbleed 扫描结果；第 4 部分突出显示了可用的密码。虽然没有包括计时器，但在对常见站点进行测试时，其时间与 SSLyze 相当。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_08_04.png)

SSLscan 扫描输出

在这种特殊情况下，两个工具都检测到了相同的首选密码套件**`ECDHE-RSA-AES128-SHA`**，但在一些测试中，人们报告了 SSLyze 正确解释或协商与 SSLscan 相同的密码套件时出现了一些问题。这样的问题需要运行两个工具并使用手动分析来解决任何冲突。 Kali 发行版中的另一个工具**tlssled**，根据底层 SSLscan 结果重新格式化输出为摘要样式视图，但除了 SSLscan 的功能外，几乎没有其他功能。

### Nmap 也具有 SSL 技能

我们将要研究的最后一个通用 SSL/TLS 扫描工具是备受推崇的**Nmap**。配备了一个特定于任务的脚本（`ssl-enum-ciphers`），Nmap 可以枚举主机上所有可用的密码，并根据当前最佳实践为每个密码提供评分。虽然它缺乏 SSLyze 和 SSLscan 的完整性，但这个功能使它成为向客户提出建议的有用且知名的引擎。

以下屏幕截图中的输出显示了针对 OWASP BWA 本身（主页，而不是特定应用程序）的扫描可能是什么样子：

```
nmap -sV ; script ssl-enum-ciphers -p 443 www.hackthissite.org 
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_08_05.png)

Nmap 与 ssl-enum-ciphers 扫描输出

## 利用漏洞

* * *

一旦您扫描了 SSL/TLS 密码问题或证书问题，就可以做很多工作来寻找攻击者将使用的特定弱点，这些攻击也可以通过我们已经在之前章节中访问过的一些工具来传递。让我们看看一些更著名的漏洞。

### POODLE â�� 只会吠，不会咬（通常）

**降级遗留加密的填充 Oracle**（**POODLE**）（CVE-2014-3566）是一种漏洞，它利用了对受影响的 SSLv3.0 **Cipher Block Chaining**（**CBC**）**Â **密码套件的向下协商，从而允许中间人利用。使用中间人攻击，POODLE 需要 256 个 SSL 请求来揭示每个数据字节，并且除非存在大规模、强大且持久的中间人代理，否则它不经常使用。尽管如此，这是一个敏感问题，如果 SSLscan 或 SSLyze 显示存在这种组合，或者您可以选择使用`nmap`和其`ssl-poodle`模块来验证条件是否存在，那么您可以推断这可能存在于主机上。以下脚本将在目标上检查它：

```
nmap -sV ; version-light ; script ssl-poodle -p 443 <host>
```

与`ssl-enum-ciphers`脚本的 Nmap 扫描不同，这个扫描停止并且只深入到围绕这个 CVE 的具体细节（如下图所示）。您还可以看到我们在`ssl-enum-ciphers`扫描中捕获了 CVE，但没有标记它的常用名称。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_08_06.png)

Nmap 与 SSL-poodle 模块扫描输出

OpenSSL 团队讨论了背景（[`www.openssl.org/~bodo/ssl-poodle.pdf`](https://www.openssl.org/~bodo/ssl-poodle.pdf)）和利用此漏洞的方法。我的朋友 Joey Muniz 也在他的*The Security Blogger*博客中写到了这个缺陷（[`www.thesecurityblogger.com/ssl-broken-again-in-poodle-attack/`](http://www.thesecurityblogger.com/ssl-broken-again-in-poodle-attack/)），并且在高层次上描述了它是如何实现的。

### 心脏出血

另一个引起大量媒体关注的漏洞是非常严重的**Heartbleed**漏洞（CVE-2014-0160，[`heartbleed.com`](http://heartbleed.com)）。与 POODLE 不同，这不能简单地通过配置来解决，而是需要对当时大约四分之三的互联网连接主机使用的基础 OpenSSL 软件进行修补。POODLE 允许攻击者一次一个字节地猜测会话 cookie，而 Heartbleed 是一种漏洞，允许攻击者读取所有私有加密密钥、用户名和密码、证书以及易受攻击主机上的所有受保护通信。尽管 POODLE 似乎是针对长期替换的密码类别的学术练习，但 Heartbleed 影响了全球绝大多数的网络设备。

我们已经看到 SSLyze 和 SSLscan 都能够检测到 Heartbleed 漏洞，但如果您想利用它作为更大的渗透测试的一部分，该怎么办？Metasploit 恰好能够提供，所以让我们来看看！

启动 Metasploit（使用`msfconsole`命令）后，我们可以使用`auxiliary/scanner/ssl/openssl_heartbleed`模块来支持我们利用 Heartbleed。

让我们继续查看选项（如下面的屏幕截图所示），我们需要考虑在配置利用时：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_08_07.png)

在 Metasploit 中的 Heartbleed 模块的配置选项

我们将研究 BeeBox VM（[`www.itsecgames.com`](http://www.itsecgames.com)）并在下拉列表中选择**`Heartbleed Vulnerability`**，如下面的屏幕截图所示。请注意，还有其他旧的攻击，如前面提到的**`POODLE`**，可供您练习。我们可以看到实验室希望我们在名为`8443`的端口上工作，我的**RHOSTS**只是单个服务器`172.16.30.134`。我还将**VERBOSE**（在选项中未显示，因为它是一个更全局的、模块不可知的设置）设置为*true*，这样我们就可以看到所有的交易。我也会将其余的设置保持为默认设置。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_08_08.png)

寻找一个受 Heartbleed 漏洞影响的服务器。

修改这些设置后，我们只需输入`run`或`exploit`，Metasploit 现在将尝试破坏服务器并获取它能找到的所有凭据和 cookie，如下面的屏幕截图所示。这么致命的东西不应该这么容易，您可以看到为什么我们需要测试和防范这些攻击。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_08_09.png)

Metasploit 的 Heartbleed 利用是成功的。

### 淹没 HTTPS

**DROWN**（CVE-2016-0800）漏洞识别了一个开放 SSLv2 支持的服务器，这使得至少三分之一的互联网服务器在 2016 年 3 月时是脆弱的。攻击者将利用应用程序支持的 SSLv2，使用与用于*盐*或帮助随机化 TLS（更近期的协议版本）相同的密钥。通过启动数以万计的 SSLv2 消息，他们能够获取更强大和当前版本的 TLS 中使用的密钥，从而使用窃取的私钥破解更高级别的加密。曾经被认为是不切实际的，因为需要大量消息；他们也称之为*百万消息攻击*；现在已经知道可以通过商业可用的资源在几小时内使用数以万计的消息来实现。

检测 DROWN 漏洞就像看看目标服务器或共享相同密钥的其他服务器是否支持 SSLv2 一样简单。还有另一个工具可以用来识别这个漏洞，它位于[`test.drownattack.com`](http://test.drownattack.com)网站上。

### 重温经典

随着时间的推移，SSL 和 TLS 都经历了各自的漏洞；这是不可避免的，因为它们对由一小群过度工作和得不到支持的志愿者维护的 OpenSSL 等模块的巨大依赖。我们应该了解和检查的其他一些漏洞在这里描述：

+   **BEAST**：我们的客户需要练习良好的补丁和配置卫生习惯，以避免像**浏览器针对 SSL/TLS 的利用**（CVE-2011-3389）攻击这样的攻击。BEAST 针对 TLSv1.0 的**初始化向量**（**IVs**），这些是用来帮助随机加密的种子值。猜测 IVs 有助于攻击者重构对话并揭示本应被掩盖的明文。他们可以通过更新的 TLS 版本避免这些问题。

+   **CRIME**：**压缩比例信息泄漏变得容易**（CVE-2012-4929）是在旧版本中使用 TLS 压缩时的一个漏洞。通过注入字节并比较响应的大小，黑客可以识别和推断出 cookie 本身，这可以让他们为自己的邪恶用途劫持会话。现代浏览器不容易受到攻击，所以客户应该始终保持更新。

+   **BREACH**：**通过对超文本进行自适应压缩的浏览器侦察和外泄**（CVE-2013-3587）使用类似的技术，但使用 HTTP 压缩，因此不依赖于 TLS 压缩来使用 BREACH。您可以建议客户阻止压缩，并在多个事务中分割和掩盖任何密码或认证值，或者还可以使用包装器和操作来掩盖请求。

## 中间人攻击

* * *

中间人攻击受到网络和应用安全供应商的高度关注，这是理所当然的。中间人攻击可以在应用服务器附近进行，但更常见的是在客户端附近。中间人攻击的等级会有很大的变化，从 passively 监视流量模式到主动干扰和凭证收集。鉴于可以产生相同信息的更高优先级的妥协的普遍存在（例如**跨站脚本**或**XSS**），Web 应用程序渗透测试人员需要评估追求中间人攻击的风险与回报。让我们详细了解一下最受欢迎的工具，并调查一些不同中间人攻击目标的类似工具。

### 使用 SSLstrip 刮取凭证

**SSLstrip**（[`moxie.org/software/sslstrip/`](https://moxie.org/software/sslstrip/)）是由一个名叫 Moxie Marlinspike 的黑客创建的中间人攻击工具，它可以透明地拦截 HTTPS 流量，并用 HTTP 的替代品替换任何 HTTPS 链接和重定向，我们可以看到这些完全没有保护。这种攻击就像对浏览器配置和用户勤勉的测试，但它也可以强调 DNS 安全、PKI、双向证书检查和双因素授权的重要性。

*Jason Beltrame*和我在我们的书*《使用树莓派进行渗透测试，第二版》*（[`www.packtpub.com/networking-and-servers/penetration-testing-raspberry-pi-second-edition`](https://www.packtpub.com/networking-and-servers/penetration-testing-raspberry-pi-second-edition)）中写到了这一点，但在这种情况下，我们将放弃物理内联配置，而是通过将流量通过我们的 Kali VM 进行中间人攻击（请注意，这是一种基于 LAN 的攻击，所以您需要在受害者的 LAN 上）。毫无戒心的受害者相信他/她确实是安全连接的。

以下截图显示了一个高层概述：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_08_10.png)

中间人攻击拓扑

首先，我们需要欺骗主机，让它认为我们是真正的默认网关。我们可以通过使用`route -n`确定段上的默认 GW 为什么使用，识别我们浏览受害者的 IP（我使用的是带有 IE9 的 Windows 7 虚拟机）。通过几个命令，我们可以打开 IP 转发并用我们的 MAC 地址对受害者进行`arpspoof`，如下所示：

```
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth0 -t 172.16.30.135 172.16.30.2 
```

现在我们需要修改我们的`iptables`配置。如果你之前没有遇到过 iptables，它是 Linux 内核基于主机的防火墙的接口，所以你可以想象我们需要一些魔法来允许流量进入和离开，这些流量实际上并不是为我们准备的。在我的例子中，我使用端口`80`用于 HTTP，端口`1111`用于 SSLstrip，但如有需要，可以随意修改后者：

```
iptables -t nat -A PREROUTING -p tcp ; destination-port 80 -j REDIRECT ; to-port 1111 
```

现在我们需要启动 SSLstrip，可以从命令行或 GUI 快捷方式启动：

```
sslstrip â��l 1111 
```

完成后，我通常会浏览一些网站，比如[`www.aol.com/`](https://www.aol.com/)，然后输入一些假证书，希望能在我的 SSLstrip 日志中捕获它们，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_08_11.png)

任何 SSL 网站都可以用来测试。

通常情况下，我会从上一个终端会话中的 Python 脚本中收到一堆错误，但它仍然像一个冠军一样工作。只需打开`ssltrip.log`文件（我的文件位于`root`目录中），并滚动到搜索的末尾，查找其中一个字段字符串；在我的情况下，我使用了密码。

以下截图显示了我希望看到的假证书：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_08_12.png)

SSLstrip 的日志和捕获的凭证。

### 使用 SSLsniff 和 SSLsplit 看起来很正规

我们希望我们的客户不会上当受骗，去除 SSL/TLS 保护的中间人攻击。更精明的客户将培训他们的用户并限制浏览器中的非 HTTPS 流量。对于这些情况，Moxie 再次使用 SSLsniff，就像 Daniel Roethlisberger 的**SSLsplit**（[`github.com/droe/sslsplit`](https://github.com/droe/sslsplit)）一样，可以通过充当透明代理并为服务器和客户端提供 SSL/TLS 连接来提供更高级别的中间人攻击。SSLsniff 和 SSLsplit 都将伪造 X.509 证书，并模仿服务器的大多数相关证书字段，因此这是一个适用于我们怀疑用户不注意他们的证书检查或执法可能较弱的环境的绝佳方法。这两个工具都依赖于伪造的证书，但使用相同的 IP 转发和`iptables`配置来传输流量。为了实现这一点，您需要运行证书颁发机构；如果您还没有建立自己的证书颁发机构，这是一个很棒的教程：[`jamielinux.com/docs/openssl-certificate-authority/`](https://jamielinux.com/docs/openssl-certificate-authority/)。

#### SSLsniff

我们先来看看 SSLsniff。然后，SSLsniff 要求您拥有目标 Web 应用程序的私钥和证书（不太可能），或者您生成伪造的证书，如下面的截图所示：

```
openssl req -config openssl.cnf -new -nodes -keyout <targetsite>.key -out <targetsite>.csr -days 365 
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_08_13.png)

为 SSLsniff 和 SSLsplit 伪造证书。

我们在**通用名称**（**CN**）中使用 Unicode `\x00`作为占位符，遵循优秀教程提供的指导，链接在这里：[`www.kimiushida.com/bitsandpieces/articles/attacking_ssl_with_sslsniff_and_null_prefixes/`](http://www.kimiushida.com/bitsandpieces/articles/attacking_ssl_with_sslsniff_and_null_prefixes/)。创建一个真正的欺骗证书作为后端编程是必要的，以创建允许受害者浏览器接受的空字符。创建`cert`和`key`后，我们需要使用自己的 CA 签署证书，连接`key`和`cert`，然后将其放置在我们假网站的目录中：

```
openssl ca -config openssl.cnf -policy policy_anything -out gmail.crt -infiles gmail.csr
cat paypal.crt gmail.key > gmail.pem
mkdir -p /usr/share/sslsniff/certs/fakegmail/
cp gmail.pem /usr/share/sslsniff/certs/fakegmail/ 
```

假设您已经正确配置了 IP 转发和`iptables`，SSLsniff 可以使用一个命令启动：

```
sslsniff -t -c /usr/share/sslsniff/certs/fakegmail -s 1111 -w /tmp/sslsniff.log -d â��p 
```

现在我们已经让 SSLsniff 等待我们受害者的流量，我们可以开始使用与 SSLstrip 中使用的相同类型的`arpspoof`来重定向来自客户端的流量：

```
arpspoof â��I eth0 â��t 172.16.30.135 172.16.30.2 
```

您可以查看`sslsniff.log`文件的内容并查看凭证（如下图所示）。这种攻击的成功可能性比 SSLstrip 更大，因为用户仍然会在其浏览器的地址栏中看到一个 HTTPS 会话；并且根据受信任的 CA 配置，他们可能很少意识到事情并不顺利。如果您使用真正的欺骗证书（查看此教程了解可能发生的情况：[`blog.leetsys.com/2012/01/18/insider-rogue-certification-authority-attack/`](https://blog.leetsys.com/2012/01/18/insider-rogue-certification-authority-attack/)），它甚至看起来是有效的。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_08_14.png)

查看 SSLsniff 的凭证抓取

#### SSLsplit

SSLsplit 采用类似的方法；首先，您需要确保启用了 IP 转发。通常会使用更多的`iptables`条目来拉取更多的端口，提供 NAT，并使用`80`、`8080`、`443`和`8443`的典型重新映射端口：

```
iptables -t nat -F
iptables -t nat -A PREROUTING -p tcp â��dport 80 -j REDIRECT â��to-ports 8080
iptables -t nat -A PREROUTING -p tcp â��dport 443 -j REDIRECT â��to-ports 8443
iptables -I INPUT -p tcp -m state â��state NEW -m tcp â��dport 80 -j ACCEPT
iptables -I INPUT -p tcp -m state â��state NEW -m tcp â��dport 443 -j ACCEPT
iptables -I INPUT -p tcp -m state â��state NEW -m tcp â��dport 8443 -j ACCEPT
iptables -I INPUT -p tcp -m state â��state NEW -m tcp â��dport 8080 -j ACCEPT
service iptables save 
```

现在我们可以使用一个命令启动 SSLsplit。请注意，与生成欺骗证书相关的繁重开销已经消除；这非常有帮助，因为我们可以部署它来收集多个站点的信息，而无需为每个站点生成假证书：

```
sslsplit -l connections.log -S ~/scrapes/ -k ~/sslsplit-keys/ca.key -c ~/sslsplit-keys/ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080 
```

与 SSLsniff 一样，输出指向一个日志文件，告诉您可以在`~/scrapes`文件夹中找到日志。

#### 替代中间人攻击动机

我们可以使用 Kali Linux 作为基础实施大量中间人攻击方法。如果您正在寻找仅限 HTTP 的中间人攻击（一些内部站点可能仍在使用不受保护的 HTTP），或者如果您正在寻找某些非常特定的东西，请查看**Driftnet**（[`www.ex-parrot.com/~chris/driftnet/`](http://www.ex-parrot.com/~chris/driftnet/)）和**Urlsnarf**。这两者都使用相同的 IP 转发和 arpspoof 配置，但提供了一些与 SSLstrip 不同的功能。Driftnet 专注于从通过您的 Kali VM 传递的 HTTP 流中提取图像和多媒体，这对拦截企业培训非常有帮助。Urlsnarf 只是拉取主机访问的所有网站，这可以帮助您映射明确访问的内部站点，并且可能不会出现在 DNS 侦察任务中。

## 摘要

* * *

尽管一些攻击受到了很多关注和荣耀，但推动社会对网络的依赖的信任关系至关重要。对这些信任机制的攻击非常令人担忧，因为它们经常让用户和应用程序开发人员对妥协毫不知情。本书涵盖的许多其他威胁以及 OWASP 十大威胁中所代表的威胁是网站应用程序所有者可以控制或有权利纠正的。然而，基于加密或 PKI 的攻击涉及到其他领域的方面，比如证书颁发机构的完整性，网络对 ARP 注入的容忍度，以及应用程序自身域之外的局域网的完整性。在 Heartbleed 和 POODLE 等攻击中，甚至提供这些服务的软件也可能会有最终妥协的问题：敏感数据和凭证的泄露。

在本章中，我们只是初步了解了如何扫描应用程序运行的软件中已知的漏洞。我们还看到了 SSLscan 和 SSLyze 在检测 PKI 细节方面的不同之处，以及如何使用它们和 Nmap 来识别弱点。我们还讨论了一些更常见的攻击方式，如如何利用 Heartbleed 以及如何以多种方式进行中间人攻击。

在第九章*，压力测试认证和会话管理*中，我们将假设加密技术非常完善，更容易的路径是在应用程序端破坏认证。这些认证和会话管理攻击更加关注特定应用程序配置和维护可能存在的缺陷，实际上，这些缺陷往往更容易受到攻击。这些攻击还具有利用与合法用户相同的安全通道进入环境的附加好处，这对于持续测试和对目标系统的深入分析至关重要。第九章*，压力测试认证和会话管理*，也将标志着我们回归到一些已经投资的工具集，所以拿杯饮料，让我们开始工作吧！


# 第九章：压力测试认证和会话管理

如果攻击者能够找到或表现得像合法用户，并且应用程序相信他，那么任何下游保护都无法阻止非法操作。在第八章 *通过加密测试利用信任*中，我们看到攻击者如何拦截并经过一些努力——代理或即时解密信息。要使这些攻击生效，需要发生很多事情，而攻击者可能会被网络防御或警觉的用户注意到。应用程序使用的认证是另一回事。用户不断向 Web 应用程序和安全团队施压，以简化和改进登录体验，而这种压力往往直接冲突于应用程序的安全性。因为应用程序所有者不愿意推动用户使用更新的硬件和软件，经历任何中断或冗长的登录过程，并放弃访问自由和多任务处理能力，他们通常设计应用程序以适应更不安全、更常见的客户端配置文件。应用程序登录和会话管理流程一直很慢地采用措施，以防止导致最近历史上一些最大的入侵事件的许多缺陷。

会话管理的诞生是为了使安全性更加灵活。用户不喜欢通过**虚拟专用网络（VPN）**隧道连接，因此 Web 应用程序已经从使用唯一的会话密钥发展到认证 cookie，现在是认证令牌，每个都允许用户持续访问和服务器跟踪有状态信息。这在初始认证后是一个巨大的帮助，因为它允许 HTTP 在不断证明其身份的麻烦下扩展其使用。对于黑客来说，会话管理方法现在是他们可以打败的机制——拥有凭据不再是劫持会话或冒充用户的必要条件。

认证和会话管理漏洞通常是协调的入侵行动的第二层。虽然其他妥协会在目标环境中启用初始的“海滩头”，但在环境中使用用户存储的暴力破解通常是允许攻击者通过横向移动和特权升级来保持访问的关键部分。与企业使用**轻量级目录访问协议（LDAP）**、微软**活动目录（AD）**或其他身份存储不同，Web 门户通常经过大量定制，购买时很少或从未得到适当的加固。这就是我们将要操作的地方——暴露目标环境认证的所有裂缝。在本章中，我们将看到各种形式的认证是如何执行的，以及如何最好地测试它们。在这个过程中，我们将了解以下主题：

+   学习基本、基于表单或摘要的 HTTP 认证是如何实现的，以及每种方法的优缺点

+   使用 Burp Suite 的 Intruder 模块来规避这些认证墙

+   讨论**双因素认证**（**2FA**）的影响以及克服它的方法

+   了解功能级访问控制的工作原理，如何可能被错误配置，以及如何通过伪造来利用

+   讨论暴力破解和字典攻击的可能性

## 敲敲，谁在那里？

* * *

认证是确定某人是谁的艺术，并且要有确定性地这样做。自从互联网出现以来，这个过程变得很危险，因为处理不当的后果可能会危及其他环境。尽管潜在影响很大，但这种风险通常被非安全人员忽视——用户的便利性再次导致了安全上的放松。OWASP 将其列为网络安全中最紧迫的威胁之一，并将威胁描述为具有严重影响，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_01.png)

OWASP 对破损的认证和会话管理的总结

### 认证必须很难吗？

大多数认证方法都以这样一个前提开始，即通常有不同特权级别的有效用户需要访问某些内容。现在，我们如何确认他们是他们所说的人？这些所谓的**凭据**在很大程度上类似于物理安全措施。正确的人既看起来像他们所说的人，而且希望有适当的钥匙或回答挑战的答案。过去，基于用户名和密码的认证是完全可以接受的，但现在我们已经到了这样一个程度，即这种有缺陷的单因素方法已经不能保证连接的客户是可信的。

近年来，网站和应用程序已经纳入了所谓的 2FA，以提高忠诚度。 2FA 在所需的认证检查中添加了第二因素，大大降低了窃取凭证成功获得非法访问的可能性。这些因素通常被描述为你是谁（例如用户名或电子邮件）、你知道的东西（密码或口令）和你拥有的东西（通常是软令牌、RSA 密钥或其他**一次性密码**（**OTP**））。在前提认证使用中，我们甚至看到指纹、视网膜扫描和其他生物识别技术的使用。再加上安全问题、**CAPTCHA**或其他图片验证技术，甚至证书，我们可以理解为什么这足以使寻求便利的用户不知所措，而不是进行测谎测试。

以下是一般认证方法的截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_02-1.png)

网站的一般认证方法

### 认证 2.0 - 抢夺一个金奖券

如果您熟悉罗尔德·达尔（Roald Dahl）的著作《查理和巧克力工厂》，您会知道孩子们在糖果中找到的**金奖券**为他们打开了一些非常独特的大门，并帮助查理·巴克特赢得了最终的奖品。虽然我们的目标可能不会给受害者糖果，但他们正在发放自己的*券—*提供持续和特权访问的令牌。对我们来说，诀窍在于了解如何利用这一点。

为了解决用户群体繁重的认证问题，需要不断发展解决方案。最初的尝试是将用户与会话关联起来，网页开发人员将唯一的会话 ID 代码嵌入后认证数据包中，以便记住用户、跟踪他们的活动并提供持续访问。这些有状态的密钥是不受保护的，有时仍然是不受保护的；黑客要么窃取和重复使用这些密钥，要么使用**会话固定**来欺骗用户，使其认可攻击者创建的会话 ID 或令牌，使用包含会话 ID 的恶意重定向，然后进行认证。保护这些 ID 的努力已经取得了长足的进步，我们现在看到使用加密令牌，这些令牌既模糊了令牌本身，甚至还使用客户端脚本来帮助确保关系的完整性。

### 注意

无论可用的对策如何，应用程序开发人员都是习惯动物，他们会使用 cookie 和令牌来携带各种敏感信息。听起来像是渗透测试员要解决的有趣问题！

通常使用三种方法来提取和传输凭据：基本身份验证、基于表单的身份验证和基于摘要的身份验证。下表帮助我们了解每种方法的优势、劣势、应用和特殊注意事项：

|  | **优势** | **劣势** | **典型应用** |
| --- | --- | --- | --- |
| **基本** | 通常是 SSL/TLS 加密的。 | 如果没有适当加密，容易受到客户端脚本的攻击和捕获 |

+   Web API

+   移动应用程序持久性

|

| **基于表单的** | 对用户干扰最小 | 这最有可能是不受保护的，推断数据库内容，或者暴露未使用的字段 |
| --- | --- | --- |

+   网站和门户的传统凭据挑战。

|

| **基于摘要的** | 基本 + 机器哈希 | 这相对安全 - 在当前技术水平下是最好的 |
| --- | --- | --- |

+   Web API

+   移动应用程序持久性

|

让我们看看用户在他们端看到的内容，然后我们可以开始攻击！

#### 基本身份验证

一些网站允许用户凭据通过 HTTP 请求本身中专门用于此目的的字段传递到认证的 Web 服务器。这被称为基本身份验证，可以通过用户输入或更常见的是通过在客户端脚本或浏览器插件中实现的预配置配置文件来配置。虽然这似乎是一种容易受到攻击的方式，但如果做得正确，该机制通常受到 TLS 加密的保护，并且实体都在利用证书来提供更大的确定性。这在**应用程序编程接口**（**API**）和操作员和支持人员使用的企业内部网络应用程序中非常常见，一些移动应用程序也会使用这种技术来保持对其服务器的安全访问。

#### 基于表单的身份验证

尽管存在基本身份验证，大多数用户将熟悉不同形式的默认用户界面。基于表单的身份验证对用户将会是相当直观的。向客户端发出的身份验证挑战是一个表单，通常需要用户名或电子邮件地址，至少需要一个密码或口令。在大多数情况下，没有对服务器进行验证和身份验证--基于表单的身份验证假设服务器是一个受信任的设备。这是攻击者倾向于利用的一个重大弱点。

用户提供的变量在提交时实际上是作为与 HTTP 请求本身相关的带外执行的，作为一些封装数据而不是使用内置的 HTTP 身份验证规定。黑客也会发现这些提交值值得攻击，因为单个用户的有效凭据可以提供足够的空间，使他们能够发起一系列其他攻击并避开几层保护，伪装成真正的经过身份验证的用户。

#### 基于摘要的身份验证

基于摘要的身份验证采用基本身份验证的基本原理，但应用 MD5 哈希和一个一次性码，希望比单独的基本身份验证提供更高的安全性。一次性码就像是一次性密码的机器版本--一个只能应用一次并且只有一次有效的数字，使哈希免受重放攻击的影响。

### 信任但要验证

公众对简单凭据身份验证的局限性的认识终于开始赶上，因为现在许多人现在需要在他们的身份验证过程中使用额外的因素。双因素认证现在已经成为主流，虽然它起初是在企业 VPN 使用中出现的，但现在已经传播到各种应用程序甚至是消费者产品和服务。谷歌、Dropbox、Facebook 以及它们的竞争对手--现在都提供不同形式的双因素认证来帮助保护他们的用户并减少公司的负面曝光。以下是一些额外因素（不仅仅是密码）：

+   硬件令牌：作为最早的措施之一，由几家公司提供的硬件令牌专门发放给员工或承包商，并显示出提供第二因素的时间代码。随着其他更容易部署的机制的兴起，这些硬件令牌已经逐渐减少了。

+   一次性密码（通过受信任的设备）：今天在消费者和企业应用程序中得到广泛使用（如下图中的 Dropbox），这种技术是硬件令牌的软件版本。除了通过短信、短信或电子邮件提供代码外，许多应用程序还允许将它们的一次性密码与 Google Authenticator、PingID 等应用程序同步。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_03.png)

Dropbox 2FA in action

+   智能卡：这些卡通常出现在更严格的环境中（政府、国防等），在这些环境中，不仅需要防止对应用程序的访问，还需要防止对运行该应用程序的工作站或设备的访问。通常情况下，使用智能芯片的卡，还有使用 USB dongles、磁性令牌和老式的机械钥匙的实现。

+   生物识别：作为 2FA 的最新补充，生物识别扫描和测试长期以来一直是物理访问控制的关键元素。常见的测试包括指纹或手印扫描、视网膜扫描、语音识别，现在甚至连面部识别也开始悄悄地出现。一些移动设备制造商和现在的金融应用程序正在利用面部和语音识别来解锁设备，并为移动应用程序提供额外的因素。

与前述方法相比，以下额外信息的安全性要低得多，这些信息通常被传统应用程序或自定义认证门户使用，以阻止暴力破解尝试或模糊测试。话虽如此，这些方法也经常受到攻击者的攻击，因为它们都是社会工程攻击的常见素材，很容易从相关信息泄漏中提炼出来，缺乏时间敏感性，有时在暗网上作为被破坏的账户列表的一部分可获得。如果正在使用这些方法，它们应该是前述更加严格的 2FA 方法的补充：

+   安全问题：通常来自常见选项列表的一个或多个问题是典型的，考虑到多年来这些问题已经被用于攻击验证，它们在暗网的泄漏中几乎和用户名本身一样普遍。用户经常在多个服务中类似地回答这些问题，这些问题通常是账户恢复过程的一部分。如果攻击者猜到答案或购买答案，就有很大可能发生重大的多站点违规行为。

+   图片回忆：一些应用程序将更传统的凭据与记忆图片结合起来，要求用户从随机场景或对象中进行选择，并期望用户记住这些内容以供将来登录。这种保护还可以防止自动暴力破解尝试和模糊测试，因为需要进行空间输入。人类行为是什么样子，用户会选择代表他们兴趣的图片。社会工程可以极大地提高猜测的机会。

+   账户信息：最早的*增强*认证形式之一是要求门户网站从账户号码、地址或电话号码中请求数字。我希望这是不言而喻的，但如果这是我们客户对 2FA 的理解，他们急需进行一些有效的渗透测试，并随后指导正确的安全性。

## 这就是你要找的会话

* * *

现在我们已经看到了 Web 应用程序开发人员试图让我们的工作变得困难的所有方法，让我们看看我们如何测试他们的工作。我们将看到我们可以攻击信任链的几个地方，测试会话管理机制的弹性，并学会克服它们。

### 吃点饼干？

大多数攻击者和渗透测试人员会发现，会话信息的松散管理通常是入侵应用程序的最简单途径。 Cookies 是会话信息的一个相当广泛的术语，拦截和篡改这些信息可能会带来意外收获。 Burp Suite 非常适合使用其**代理拦截**和**重复器**功能来帮助进行此操作。对于这个测试，我们将通过 Firefox 登录到我们的**Mutillidae**（OWASP Broken Web App VM）应用程序的**`A2 - Broken Authentication and Session Management`** | **`Privilege Escalation`** | **`Login`**页面（如下截图所示）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_04.png)

选择 Mutillidae 会话管理实验

对于这个测试，让我们继续使用我们之前刚好找到的一些凭据（通过社会工程或第七章中涵盖的各种方法，*注入和溢出测试*）并在用户名和密码中输入`user`。一旦我们经过身份验证，我们将打开**代理拦截**并刷新页面，允许我们捕获 HTTP 消息（如下截图所示）以及它们包含的 cookie 数据。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_05.png)

寻找模糊的 cookies

我们可以很清楚地看到，Web 开发人员试图在 cookie 中做很多事情，但不知何故忘记了保护它。我们可以看到我们会话的用户名、用户 ID（`uid`）和 PHP 会话 ID（`PHPSESSID`）都包括在内，而且似乎会话没有关联的超时（`max-age=0`）。让我们将这个请求传递给我们的 Burp Repeater，看看我们能造成什么样的破坏。右键单击事件，然后单击**`Send to Repeater`**将请求加载到**`Repeater`**工具中；单击它现在突出显示的选项卡，并选择**`Params`**选项卡，以显示以下截图中的选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_06.png)

使用 Repeater 工具进行 cookie 操作

正如你所希望的那样，cookie 本身的参数可以被改变（由橙色字段标出）。我们还可以添加或删除（使用绿色标出的适当按钮）cookie 的部分，以确定它们对会话完整性的重要性和影响。当我们逐步进行修改时，我们可以查看右侧（在**`Response`**部分的**`Render`**选项卡中）来查看我们操纵的最终结果（在这种情况下，登录状态和用户名的变化，用红色标出）。如果你走得太远，剥夺或改变太多，也不用担心-前进和后退按钮可以帮助你随时返回查看影响。

在这种情况下，UID 和 PHPSESSID 都能够独立地维护会话的状态（如下截图所示），这意味着只有当你同时从请求中删除这两个时，你才会失去会话并看到注销。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_07.png)

使用 cookie 的基本要素维护状态

这也意味着每个用户只有一个有效的会话，但如果需要的话，你可以很容易地创建自己的经过身份验证的会话。嗯，我想知道我们现在真的想成为哪个用户？嗯，假设默认的 SQL、XML 或其他用户表格式已经就位，而且没有采取加固措施，我们可以尝试在下面的截图中做一些更有抱负的事情：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_08.png)

模糊 UID 以提供管理员权限

正如你所看到的，这个简单的例子帮助你学会了通过使用 Burp Suite 的**`Repeater`**工具中的一些有趣的技巧来操纵 cookie 的组件从而获得 root 权限。当然，这需要我们捕获一个经过身份验证的会话。但是如果我们没有一个，或者我们想要欺骗用户解锁我们可能遇到的所有 2FA 陷阱呢？

### 不要吃模糊的 cookies

当一个单独的 Cookie 需要处理时，更加手动的**`Repeater`**过程可能是很有意义的。然而，当我们想要暴力破解 Cookie 时，使用 Burp Suite 的顺序器可能更能节省我们的时间，因为它可以帮助我们分析应用程序如何维护会话随机性。

为此，我们需要访问一个应用程序并捕获带有会话 ID 的请求。选择独立的**Damn Vulnerable Web**（**DVWA**）应用程序（独立的而不是 OWASP BWA 捆绑版本，后者无法适当地暴露 Cookie）。让我们选择一个合适的请求，右键单击事件，然后**`Send to Sequencer`**，就像我们在下面的截图中看到的那样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_09.png)

找到适合顺序的请求

在**`Sequencer`**选项卡中，我们可以开始突出显示我们想要使用**`Sequencer`**进行随机化的字段，如下截图所示。对于这个测试，我们真正关心的是应用程序如何随机化 PHPSESSID，因此我们将相应地选择它，然后点击**`Start Live Capture`**按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_10.png)

配置顺序器

这将弹出一个特殊窗口，允许您查看完成了多少次迭代。在至少运行了 100 次或更多次迭代之后，您可以选择停止该过程或继续迭代；与此同时，您还可以对随机性进行分析。如果一个应用在这方面得分较低，通常意味着我们有合理的机会对会话密钥进行模糊处理，并劫持与该会话关联的可怜用户的访问。我们可以看到当我让测试运行超过 5700 个会话时的情况（这只需要几分钟），如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_11.png)

会话随机性的顺序器分析

如果我们想要保存 Cookie 以备后续会话固定候选人使用，我们可以将它们放入文件并保存以备将来使用。

会话随机化是衡量应用程序构建得有多好以及客户开发人员有多注重安全性的重要指标。还记得我们讨论过的 Web 开发人员如何使用 Cookie 来存储会话 ID 以外的内容吗？顺序器在 Web 应用程序渗透测试中有很多其他应用，因为令牌用于远不止跟踪会话状态。Burp Suite 的文档在帮助理解工具的其他功能方面做得非常好（在**`Help`**菜单中可用），而 Packt 书籍*Burp Suite Essentials*（[`www.packtpub.com/hardware-and-creative/burp-suite-essentials`](https://www.packtpub.com/hardware-and-creative/burp-suite-essentials)）可能是一个很好的资源。

### 绝地会话技巧

黑客对自定义身份验证前端的常见攻击是会话固定。黑客依赖于开发人员没有考虑如何充分保护和排序他们的会话 ID。通过社会工程学（简单的电子邮件或即时消息就可以），黑客能够传递一个带有预置无效会话 ID 的 URL 字符串。如果这是我们的测试，我们肯定希望有其他流量用作模板或从扫描或秘密收集中了解应用程序，以便我们能够提供应用程序期望的会话 ID 格式和长度。配置不当的身份验证门户将允许我们的受害者携带自己的会话 ID（哈！BYOSID？），并通过验证自己的凭据甚至 2FA，使会话 ID 合法化。我们等待的测试人员随后可以使用这个新的合法会话 ID 肆意妄为，并冒充受害者。

一个安全的应用程序应该通过确保会话 ID 或 cookie 在认证时发生变化来防止造成损害，但事实证明，这并不像我们所希望的那样标准。这在在线购物网站中也很常见，这是非常危险的，因为合法用户可能只需进行一次快速的社交攻击就可以获取支付信息。进行会话固定攻击的常见方法如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_12-1.png)

会话固定的一般方法

当然，最容易使用这种攻击的网站可能是那些将会话 ID 或 cookie 作为 URL 字符串的一部分的网站。然而，我们通常需要通过一些巧妙的客户端脚本或元标签包含来设置 cookie。在 OWASP BWA VM 上包含的**WebGoat**应用程序是一个练习整个过程的好方法，从生成虚假链接欺骗用户进行认证，从而使其合法化，最终结果类似于以下截图，Joe Hacker 通过欺骗受害者 Jane，能够使用他的会话 ID 使她进行认证，然后跟在她后面获得完全的账户访问权限：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_13.png)

使用 WebGoat 练习会话固定

最可怕的部分实际上可能是一旦进入账户，Joe Hacker 实际上可以强制更改账户密码，重定银行交易，并锁定用户！许多保险、人力资源和金融网站很少被普通员工使用，因此黑客通常可以在账户通知提示受害者被骗之前有一个月甚至更长的时间来采取行动。

## 功能访问级别控制

* * *

到目前为止，我们讨论的大多数技术和问题都涉及到坏人（或我们）获取他们本不应该拥有的*信息*。在 OWASP 2013 年十大安全威胁中（[`www.owasp.org/index.php/Top_10_2013-A4-Insecure_Direct_Object_References`](https://www.owasp.org/index.php/Top_10_2013-A4-Insecure_Direct_Object_References)），这被称为**不安全的直接对象引用**（**IDOR**），排名第 4。然而，还有另一个问题，曾经是排名第 7 的，被称为**缺失的功能访问级别控制**（**[`www.owasp.org/index.php/Top_10_2013-A7-Missing_Function_Level_Access_Control`](https://www.owasp.org/index.php/Top_10_2013-A7-Missing_Function_Level_Access_Control)**），其 2013 年 OWASP 总结如下截图所示。这个类别意味着不小心或不适当地向攻击者披露*功能*而不是*信息*。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_14.png)

OWASP 2013 年第 7 号威胁：缺失的功能访问级别控制

在大多数情况下，当试图访问隐藏页面或在认证会话中尝试隐藏命令时，这种缺陷就会被注意到，这些命令本不应该具有这些特权。Web 开发人员可能会误将混淆视为安全，而不是与策略引擎搏斗，他们只是依靠隐藏功能或命令而不是明确地阻止它们的使用。使用 Burp Suite 或 OWASP ZAP 进行扫描可以快速找到目标站点值得测试的候选区域，并且扫描过程甚至可能提供问题的部分验证。

## 精炼暴徒的词汇

* * *

我们上面看到的许多攻击企图劫持会话，欺骗用户代表他们建立会话，或者利用应用程序无法强制执行规则的能力。最终，我们将找到一个需要解决的问题，那就是猜测密码。有大量的工具可以尝试这个非常基本的任务，但总的来说，它们的方法是一样的——通过使用通过全面暴力引擎生成的单词列表（例如使用**crunch**），精炼的单词列表和音节引擎（**John the Ripper**，**THC-Hydra**等），甚至通过使用预先计算的解决方案（使用彩虹表和类似的解决方案）进行迭代。

对于 Web 应用程序，Burp Suite 是一个用于暴力攻击的好工具，您可以参考第五章，***Â **使用 OWASP ZAP 和 Burp Suite 进行代理操作*，看看它可能如何使用，并仅将相同的模糊技术应用于密码字段。我们还可以使用 THC-Hydra 等工具对 Web 登录页面进行暴力攻击。当熟悉 THC-Hydra 的功能和格式时，练习使用**xHydra** GUI 前端是有帮助的。要使用 xHydra（也称为**hydra-gtk**），您可以使用下面截图中显示的菜单中的快捷方式调用该进程，或者在 CLI 中键入`xhydra`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_15.png)

寻找 Hydra 的 GUI 前端

一旦我们打开了 Hydra 的 GUI，我们就可以开始配置我们需要解决目标的选项。**`Target`**标签（如下截图所示）允许我们指向正确的 IP 或主机名，识别我们正在针对的请求提交类型（在本例中为`http-post-form`），甚至切换日志记录、调试和详细模式：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_16.png)

Hydra 目标信息

在**`Passwords`**标签中（如下截图所示），我们可以配置 hydra 使用单个提交或从用户名和密码列表中提取。许多应用程序缺乏密码复杂性规则，将允许用户在某些帐户中使用用户名或空格，因此提供了复选框，以允许我们检查这些内容。**反向登录**允许您尝试颠倒用户名的顺序并尝试将其作为密码。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_17.png)

设置用户名和密码列表

我们最后的调整将出现在**`Specific`**标签中（如下截图所示）。在这里，我们正在测试的所有重要 URL 模式被定义。我们填写的字段需要从浏览器的**`View Source`**，浏览器的插件，或者使用 Burp Suite 的 Proxy Intercept 中获取。无论哪种情况，由**`Passwords`**标签填充的变量将被标记为`^USER^`和`^PASS^`。最后一个字符串实际上是任何表示失败身份验证的标识字符串。在 DVWA 中，该字符串将在返回的结果中看到`login.php`，从而将我们推向相同的登录门户。如果我们将其应用于 Mutillidae，我们可以使用`Not Logged In`。

目标的适用 URL 答案会因网站而异，这些信息通常是通过扫描、蜘蛛爬行或传统的冲浪收集的。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_18.png)

指定评估的 URL

我们最后一步是实际从**`Start`**标签运行扫描（如下截图所示）。我们可以观察扫描的迭代——由于我们的详细标志，任何成功的结果都将在输出的底部说明。我们还可以看到我们的 GUI 配置的 CLI 等效，以便您可以重复这些扫描作为脚本的一部分或移动到 CLI 中进行调整。一个警告或澄清——我发现 CLI 很挑剔，它在使用的 URL 字符串的格式化方面存在问题，或者为选项添加的顺序标志有时会产生非常不同的结果。使用 GUI 工具可以消除很多不确定性，是避免这些相同陷阱的好方法。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_09_19.png)

查看 Hydra 的结果和命令行版本

Hydra 作为一个专门用于暴力破解的工具，是解决网络和非网络凭证黑客攻击的一种绝妙方式。老话说“垃圾进，垃圾出”在这里也适用——我们的结果只会和输入工具的密码和用户列表一样好，所以我建议探索更好地组织你的 OSINT 收集的方法。熟悉 Kali 中包含的各种工具中的字典，熟悉像 Crunch（https://sourceforge.net/projects/crunch-wordlist/）和 CeWL（https://digi.ninja/projects/cewl.php）这样的工具，以帮助生成字典。还值得调查基于哈希的攻击，这样我们就可以避免对密码进行加密哈希，并利用更多的单点登录（SSO）、开放认证（OAuth）和混合认证架构，这些架构通常在 Microsoft AD 环境中使用。这些基于哈希的方法（比如 Pass-the-hash：https://www.sans.org/reading-room/whitepapers/testing/pass-the-hash-attacks-tools-mitigation-33283）在全套渗透测试中更有意义，系统测试在范围内。

## 总结

* * *

认证是网络信任的基础。在这个领域的妥协可能不像应用程序的其他方面那样引人注目，但影响至关重要。认证或会话管理的破坏使所有其他安全措施都变得无效。教导客户理解这一点很重要，但我们需要倡导更广泛地采用临时 2FA，重复使用标准化和广为人知的框架，而不是自制门户，以及在软件开发生命周期的所有阶段持续进行渗透测试，以确保应用程序的成熟不会留下一个可信的、加固的认证未完成。

在本章中，我们看到了 Web 应用程序可以识别和验证用户并分配权限的许多方式。我们现在有了测试应用程序中会话管理的韧性以及直接获取凭证的工具。Burp Suite、Hydra、OWASP ZAP，当然还有你的浏览器和一些 OSINT，将对验证目标的加固非常有用。

在第十章，*启动客户端攻击*，我们将把客户端攻击提升到一个新的水平，并重新审视基于 DOM 的跨站脚本。您还将学习如何利用客户端发起攻击并提升我们的权限，代表您劫持通信，甚至了解神秘的跨站请求伪造。我们已经接近终点了，朋友们，我很高兴你们还和我在一起！让我们继续前进，攻击一些浏览器。


# 第十章：发动客户端攻击

Web 应用程序测试应该合理地关注我们正在测试的应用程序及其支持基础设施。到目前为止，我们关注的大多数攻击都对应用程序的前门进行了测试，或者利用客户端会话来获取非法访问。我们的客户将所有的安全预算都用于加固基础设施，其中一部分用于加固 Web 应用程序本身。也就是说，谁来照顾他们的客户端呢？

客户端本身的暴露以及用户的易受攻击性之间，我们将有多种测试向量。软件组合和用户行为的数量庞大，与其他服务和 Web 应用程序的重叠，以及访问方式的多样性（移动端与桌面端、漫游与代理、厚客户端与薄客户端与 Web 客户端等等），使得这对应用程序开发人员来说是一个极其艰巨的前线。他们最好的路径是加固应用程序本身，关闭任何漏洞，并确保应用程序关闭任何反射攻击向量和屏幕已经受到损害的主机。

大多数客户端渗透测试将以灰盒或白盒测试范围的形式出现，因为大部分攻击类型利用了应用程序自身的代码或脚本。这并不构成重大障碍，我们很快就会看到。在本章中，我们将看到多种方式，通过这些方式我们可以妥协终端点——无论是它们的通信还是主机本身。有了这些知识，就有了大量的 Web 应用程序攻击方式，可以降低目标服务的质量，这些必须进行彻底的调查。

本章将帮助您学习以下主题：

+   学习基于 DOM 的 XSS 攻击的工作原理以及如何实施它们

+   了解 JavaScript 嵌入如何被用来妥协客户端

+   学习如何使用客户端 URL 重定向和资源操纵

+   了解点击劫持和 Websockets 如何提供额外的进入客户端的途径

+   了解和实施执行跨站请求伪造和劫持通信的攻击

## 为什么客户端如此脆弱？

* * *

客户端攻击涵盖了 OWASP 2013 和 2017 年十大威胁类别中的几个。使用基于 DOM 的跨站脚本攻击（XSS）是一种利用验证中的弱点将脚本嵌入到 Web 响应中并将代码插入到客户端的强大方法。基于客户端的 DOM XSS 可以向客户端传递代码，以影响对 Web 应用程序所做的妥协，但黑客将利用各种漏洞来达到并影响客户端，例如未经验证的重定向和转发、Websockets 攻击或点击劫持。OWASP 十大 2013 年和 2017 年版本中的第三类漏洞是跨站请求伪造（CSRF），它利用受害者客户端作为枢纽，并利用其经过身份验证的状态来妥协其他站点。

还有其他攻击会渗透到 OWASP 十大中的其他领域，并且在之前的努力中已经涵盖过，但我们将在本章中重新讨论其中一些，以确保我们了解如何最好地测试和利用它们。这些威胁的共同点是它们利用了 Web 应用程序服务器端实现的问题，以影响客户端的行为或完整性。因为这些攻击通常意味着可以访问交付给客户端的代码，所以大多数这些技术在黑盒测试中不适用，而是在白盒或灰盒测试中使用。攻击者当然可能会从内部的角度使用这些技术，因此客户端攻击通常是从环境中的初始立足点到横向移动或特权升级攻击的一个组成部分。

### DOM，Duh-DOM DOM DOM!!

基于 DOM 的 XSS 应该让准备不足或未受保护的网络应用环境和负责团队感到恐慌。正如我们在第六章中讨论的*通过跨站脚本攻击渗透会话*，大多数 XSS 攻击利用了输入验证的缺失来插入脚本（通常是 JavaScript）以影响客户端如何解释或与网站交互。基于 DOM 的攻击是这些攻击的一个子集，它影响客户端的浏览器，其中 DOM 位于其中，以维护其对应用程序正在做什么和呈现什么的本地视图。通过嵌入脚本，用户当然可以影响客户端的行为，但目标和目的的多样性令人震惊，而且工具的强大（**浏览器利用框架**（**BeEF**）在协助 XSS 方面表现出色）。这些攻击主要集中在攻击客户端以黑客客户端并获取信息或专注于最终用户。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_01.png)

2013 OWASP 十大概要#3：XSS 攻击

### 恶意误导

**未经验证的重定向**和**转发**包括**开放重定向**、**UI 伪装**或**客户端 URL 重定向**的漏洞。这些攻击类型涉及将恶意链接放入用户的路径，强制连接到意外站点以进行额外攻击，无论是启动恶意软件下载还是拦截未来的通信或凭据。网络应用程序本身也参与其中，因为这意味着开发人员没有部署足够的代码验证、会话管理，或者依赖于有缺陷、因此容易受到攻击的框架或模块。

OWASP 2013 十大威胁将这一威胁排名为第 10 位（如下图所示），但 2017 年版本（在当前草案中）已将其换成了**应用程序接口**（**API**）漏洞。这并不意味着未经验证的重定向和转发不再构成威胁，而是最近它们并不像以前那样普遍和令人担忧。这些攻击，如基于 DOM 的 XSS，往往以黑客用户为最终目标。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_02.png)

2013 OWASP 十大概要#10：未经验证的重定向和转发

### 抓住我，如果你能！

1980 年的书籍和随后的 2002 年电影*抓住我，如果你能*是关于现实生活中的伪造者和骗子弗兰克·阿巴格内尔的一次伟大的冒险，他擅长操纵人们，让他们兑现伪造的支票或以其他方式代表他采取行动。黑客可以利用类似的社会工程技能和看起来真实的请求来将毫无戒心的客户端转向服务器，并利用他们的信任关系来传递恶意命令。**跨站请求伪造**（**CSRF**）是一种针对客户端使用应用程序漏洞的攻击，但实际上是为了将客户端转向其应用程序。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_03.png)

2013 OWASP 十大概要#7：跨站请求伪造

## 欺负小家伙

* * *

现在我们知道攻击的目的是什么，我们有特权来测试和验证这些漏洞是否存在。在本节中，我将提供一些关于如何最好地在扫描这些功能时实现全面覆盖的指导，但我们还将探讨如何利用它们进行黑盒攻击和系统性渗透测试范围。

### 在别人的板上冲浪

CSRF 攻击（有时发音为*sea-surf*）隐藏了引用操作的实际意图，并将其埋藏在伪造的请求中。用户希望相信页面是按照其呈现的样子（因为嘿，它来自我信任的网络应用！），因此没有理由调查隐藏在主体或标题中的底层隐藏字段或请求操作，实际上这些操作对服务器发起了恶意行动。通过这些攻击，黑客可以让用户在不知情的情况下利用其经过身份验证的会话对服务器发起攻击，就像是使用他们的身份验证会话作为特洛伊木马一样。

在大多数代理扫描仪的扫描和蜘蛛功能中，都包括了对 CSRF 漏洞的潜在存在进行扫描--Burp Suite、OWASP ZAP 和 Wapati。Burp 通常会标记为这样（如下面的屏幕截图所示），并提供关于攻击含义以及如何防止的链接和指导：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_04.png)

Burp Suite 的扫描显示 CSRF 漏洞

#### 简单的账户接管

然而，进行 CSRF 攻击通常不是使用这些工具进行的，而是使用浏览器和记事本。如果您发现在您的测试中进行 CSRF 攻击是有意义的，这里是一个执行这种攻击的示例。在这个练习中，我们将利用 OWASP BWA VM 和**Broken Web App**（BeeBox）再次导航到适当的页面（如下面的屏幕截图所示）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_05.png)

访问 bWAPP CSRF 练习链接

一旦我们进入门户，我们可以继续查看门户的源代码（在 Firefox 中，这涉及使用*Ctrl* + *U*或导航到**`工具`** | **`Web 开发人员`** | **`页面源`**）。这将显示页面上的 HTML（如下面的屏幕截图所示），但我们想要修改用户输入部分，以愚弄可怜的受害者改变他们的密码为我们所偏爱的密码。让我们继续复制这一部分（包括`<form`和`</form>`之间的所有内容）。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_06.png)

收获 HTML 以进行 CSRF 利用

我们的目标是让已经经过身份验证的用户允许我们借用他们的账户并将他们的凭据更改为我们所偏爱的密码（他们真是太好了！）。我们可以通过修改字段来实现这一点，如图所示，在这里插入我们所偏爱的密码（用粗体文本突出显示）。我还更改了按钮的名称，以帮助掩盖正在发生的变化--您可以将其设置为**`登录`**或其他他们更有可能想要点击的内容：

```
<form action="/bWAPP/csrf_1.php" method="GET">
    <p><label for="password_new">New password:</label><br />
    <input type="password" id="password_new" name="password_new" value="dude"></p>
    <p><label for="password_conf">Re-type new password:</label><br />
    <input type="password" id="password_conf" name="password_conf" value="dude"></p>
    <button type="submit" name="action" value="change">Click Here</button>
</form>
```

当我们保存这个文件（我选择了`pw.html`）并查看它时，我们应该看到一组填充的字段，类似于我们在下面的屏幕截图中看到的。当用户点击这些 CSRF 片段时，如果原因模糊且字段被隐藏，这有助于我们。我们不希望他们知道我们正在强制更改密码（或者我们可能正在设计 CSRF 攻击以实现其他目的）。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_07.png)

CSRF 修改的结果

```
<form action="/bWAPP/csrf_1.php" method="GET">) in the first line, which included a referential link to the referring page (/bWAPP/csrf_1.php). We need to replace that page with the full URL (as shown in the following screenshot) so that we can ensure that our form data is dropped into the real page's fields:
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_08.png)

我们的 HTML 中修改的字段

现在，我们修改后的 HTML 已经完成，但是我们如何将这份礼物送给我们的受害者呢？您可以将此攻击与 XSS 攻击相结合，通过电子邮件发送，或将其嵌入伪造的页面中。要测试代码本身，我们只需打开页面并单击**`点击这里`**按钮。幸运的话（在这些令人敬畏的黑客攻击中谁还需要运气？），您将看到与下面屏幕截图中所见类似的消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_09.png)

CSRF 执行将受害者带到真正的页面

正如我们所看到的，这是一个非常有帮助的工具，可以 compromise 客户。黑客们不仅使用这个来修改凭据，还用来将资金重定向到不同的账户，并交付其他攻击修改（使用经过身份验证的用户来交付 XSS 或注入攻击）。幸运的是，有方法可以消除这些漏洞，但是 Web 应用程序需要包含这些方法。一些**内容管理系统**（**CMS**s）在结构中构建了保护措施（如 Joomla！、Drupal 等）；但对于一些框架和从头编写的 PHP 和 ASP.NET 页面，开发人员可能需要添加保护措施或加固他们的交互页面，使用 OWASP（[`www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet`](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet)）或他们的 CMS 提供商的建议。

#### 你不知道我是谁吗？账户创建

接管一个账户可能在短期内奏效，但通常我们希望在应用程序上保持持久的存在，而不是让一个非常愤怒或沮丧的受害者试图夺回控制。如果我们能够访问管理员的账户或者愚弄管理员用户点击链接，有时我们可以让他们帮助我们自己创建一个账户！

诀窍是已经定位或准确猜测到新用户或账户创建页面的 URL。一旦我们做到了这一点，我们可以使用类似于我们第一次 CSRF 攻击的攻击来自动化账户创建，并将我们想要在其上使用的适当种子凭据传递给它。通过使用 bWAPP 再次进行演示，我们可以看到这是如何工作的，并从顶部菜单栏中选择**`创建用户`**。您将看到下面截图中显示的字段，我已经填写了我想要的账户信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_10-1.png)

我们需要填写的创建用户字段

当我创建一个账户时，Burp 可以帮助我捕获字符串，其中包括我们想要的所有信息（如下截图所示）。现在，我们有两个选项可以尝试利用：CSRF 和 HTMP 注入，这些在第七章中已经涵盖了，*注入和溢出测试*。假设出于论证的目的，注入不可行（也许目标的开发人员已经关闭了这个漏洞），我们将进行 CSRF 攻击。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_11.png)

为我们的伪造找到 URL 字符串

对于 CSRF 攻击，我可以从类似我捕获的 HTML 文件开始：

```
<form action="/bWAPP/user_extra.php" method="POST">
    <table>
    <tr><td>
        <p><label for="login">Login:</label><br />
        <input type="text" id="login" name="login"></p>
    </td>    
    <td width="5"></td>
    <td>
        <p><label for="email">E-mail:</label><br />
        <input type="text" id="email" name="email" size="30"></p>
    </td></tr>
    <tr><td>
        <p><label for="password">Password:</label><br />
        <input type="password" id="password" name="password"></p>
    </td>
    <td width="25"></td>
    <td>
        <p><label for="password_conf">Re-type password:</label><br />
        <input type="password" id="password_conf" name="password_conf"></p>
    </td></tr>
    <tr><td colspan="3">
        <p><label for="secret">Secret:</label><br />
        <input type="text" id="secret" name="secret" size="40"></p>        
    </td></tr>
    <tr><td>
        <p><label for="mail_activation">E-mail activation:</label>
        <input type="checkbox" id="mail_activation" name="mail_activation" value="">
    </td></tr>
    </table>
    <button type="submit" name="action" value="create">Create</button>
</form>
```

现在，为了特别隐秘，我们需要确保接收此页面的人不理解我们让他们做什么。诀窍是隐藏字段并利用隐藏属性来使我们的请求通过他们的好奇检查。我可以通过修改源代码来消除所有标签并隐藏所有用户输入，除了一个`submit`按钮，同时嵌入我想要的凭据而不让用户知道：

```
<form action="http://172.16.30.129/bWAPP/user_extra.php" method="GET">
        <input type="hidden" id="login" name="login" value="test1"></p>
        <input type="hidden" id="email" name="email" value="test1@example.com"></p>
        <input type="hidden" id="password" name="password" value="dude"></p>
        <input type="hidden" id="password_conf" name="password_conf" value="dude"></p>
        <input type="hidden" id="secret" name="secret" size="40" value="Hello Hackers"></p>
        <input type="hidden" id="mail_activation" name="mail_activation" value="">
        <button type="submit" name="action" value="create">Log In Here</button>
</form>
```

当受害者加载时，这将导致页面看起来像以下截图所示的页面。我们可以使该按钮看起来像任何东西（“赢得 100 万美元！”、“验证电子邮件”和“注册研讨会”都是可行的选项）。我们甚至可以将其嵌入到图片中作为链接；我们的目标是制作一个看起来无害且与用户预期行为相关的东西。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_12.png)

简单的登录页面，对吧？

当用户点击这个按钮时，我们会看到可怜的认证受害者具有创建账户的权限，就像下面的截图中所示！关键在于知道预期的字段是什么。OSINT 可以帮助，因为通常新员工的说明和帮助门户会毫不保留地透露这一点。我们还可以根据组织内的其他趋势做出一些合理的猜测。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_13-1.png)

账户已创建，谢谢！

应该注意的是，CSRF 是黑客和防御者之间非常活跃的猫鼠游戏创新领域。反 CSRF 令牌已经成为保护用户的手段；但是，就像所有漏洞一样，正如我们在本书中所看到的，执行通常是最薄弱的环节。如果使用了反 CSRF 令牌，黑客（和我们）可以尝试在我们的 CSRF 页面中使用 JavaScript 来捕获客户端的任何反 CSRF 令牌，并将其滑入我们的 GET 或 POST 请求中，以确保我们规避这种保护。更好的反 CSRF 实现将通过实施临时和上下文驱动的令牌来防止这种情况，但如果他们没有这样做，那么规避这些控制的可能性是相当大的。

### 相信我，我知道路！

对于这样一个长的名称，未经验证的重定向和转发漏洞使网站面临着极小的努力即可进行攻击，使攻击者能够将用户重定向到恶意网站或至少是意外的网站。我们可以使用自动化工具（如 Burp 或 ZAP）扫描网站，这些工具将通过一些线索来发现潜在的问题，例如使用完整站点路径或长重定向响应的页面，这两者都在此网站上看到（如下图所示），或者尝试在浏览器中指定扩展名或修改 URL：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_14.png)

Burp Suite 扫描显示未经验证的重定向和转发漏洞

大多数网站在您在页面上悬停在链接上时仍然允许查看 URL，相关链接为*here*如下截图所示。这是在 OSINT 努力中直观发现此类风险的简单方法。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_15.png)

识别候选超链接

作为替代，一些网站会隐藏超链接，但**`页面源代码`**应该向我们显示这一点，如下图所示。对于这个网站，我们可以看到他们正在使用前面提到的相对链接，如果网站验证只返回相对链接，通常会提供更好的保护。如果他们使用显式的完整链接或允许它们代替站点范围的相对链接，这通常会表明一些不太严格编码的验证。这也是发现任何其他相关脚本或非明显超链接的好方法，这些也可能是先前讨论的 CSRF，隐藏字段利用等的潜在线索：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_16.png)

查看源代码通常会显示更多

要注意的部分是 URL 中`?`之后的部分。正如我们以前所见，直接包含命令、脚本、字段，现在又是另一个页面链接，为黑客提供了许多途径来插入他们自己的调整，启动命令，甚至引导客户端到站点的**完全合格域名**（**FQDN**）。对于这种攻击，我们可以简单地开始调整 URL 字符串，并尝试添加我们自己的重定向。显然，这可能是试图欺骗用户访问我们的恶意门户或启动恶意软件下载的更大尝试的一部分，但现在，让我们只用一个良性的重定向来证明它，方法如下：

```
http://172.16.30.129/bWAPP/unvalidated_redir_fwd_2.php?ReturnUrl=https://www.hackthissite.org/
```

看哪！我们已经把用户重定向到我们的恶意网站，这种情况下，只是我们最喜欢的练习网站[www.hackthissite.org](http://www.hackthissite.org)（如图所示）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_17.png)

重定向成功！

这种简单的方法经常被忽视，但当 URL 作为电子邮件中的超链接隐藏时，无论是完全隐藏还是只显示 URL 的预期部分，用户都很有可能点击它。如果 URL 之后的操作包括让用户访问具有他们可以提供的身份验证的站点，这可以为黑客提供足够大的立足点来利用。很少有这种攻击单独存在；通常用于协助横向移动或在更全面的攻击生命周期早期劫持会话。

## 我不需要你的验证

* * *

在 Web 应用程序中进行验证是消除或减少威胁的重要步骤。 XSS，注入，CSRF，未经验证的重定向和转发攻击都利用了应用程序中的缺陷，允许对字段进行操纵，暴露先前隐藏的功能或未使用的组件，并且缺乏语法强制执行。这里列出了一些附加的验证样式攻击，并且通常可以通过全功能扫描和代理工具很好地检测到：

+   CSS 注入：CSS 注入寻找常见样式表中容易受到操纵或注入攻击的代码（不要与 XSS 或跨站点脚本混淆）。与 XSS 和 CSRF 一样，这可以用于插入脚本或引起流量重定向，从而导致数据外泄或凭据、令牌和其他敏感信息的捕获。在极端情况下，可以通过这种方式传递持久性。

+   客户端资源操纵：实际上是 XSS 的一个变种，这些攻击侧重于请求或响应中各种用户可控元素，这些元素可以导致客户端在浏览器内执行恶意命令或进程。CSS 注入是这种攻击的一种变体，但其他常见的目标是网页中的 iFrames 和其他链接对象（图像、引用、脚本、对象等）。iFrames 是提供单个页面多个内容来源的常见方式，在许多新闻和电子商务网站中使用。

+   Web 套接字：Web 套接字攻击并没有像预期的那样普遍，因为你有多少次看到应用程序在 URL 中使用`ws://`或`wss://`而不是 HTTP 调用？Web 套接字被设想为一种方式，可以在客户端和服务器之间提供全双工、异步通信链接，能够承载多个 TCP 连接。嗯，它们并没有完全起飞，但如果它们真的流行起来，你可以使用 Google Chrome 的扩展或 OWASP 的 ZAP 工具来测试它们的问题。与 HTTP 一样，我们希望我们的 Web 套接字受到当前版本的 TLS 的保护，因此许多常见的 OpenSSL 或基于加密的攻击都是公平的游戏。它们还应该在其标头中有严格的来源标签规则，以便可以测试客户端资源操纵和各种注入攻击。

+   跨站点闪烁：跨站点闪烁与 XSS 非常相似，只是它针对 Adobe Flash 嵌入，这与 PDF、Java jar 文件和生产软件一样，是恶意软件的常见传递机制。通过更改嵌入文件，黑客可以植入恶意软件或实现更多面向网络的目标，例如收集凭据和 Cookie。

+   跨域资源共享（CORS）：这利用了本章涵盖的许多攻击中缺乏验证的特点。大多数应用程序将确保标头使用多个参数进行通信，我们需要测试在请求超出原始域的范围之前需要多少额外的验证。如果 Web 开发人员允许这些标头使用通配符或禁用这些检查，那么这提供了攻击的手段。标头检查是主要的测试方法，但如果存在漏洞，它可以通过类似 CSRF 的代码操纵来利用。

## 时尚的黑客技术来来去去

* * *

最近客户端攻击的趋势集中在规避许多受信任的保护机制并提高用户意识。虽然我不会详细介绍这些内容，但值得注意它们的潜力，并考虑如何在自己的测试中评估和利用这些漏洞。

### 点击劫持（bWAPP）

**点击劫持**曾是几年前一种普遍的攻击方法，以其在 Facebook、Twitter、亚马逊和其他知名网站上的使用而引人注目。在所有这些攻击中，黑客们诱使用户点击伪装或隐藏的链接，以启动恶意页面或脚本。简单的 HTML 可以提供重叠的 iFrame 或其他机制，用户无法清楚地看到其存在，黑客可以利用这一点在合法网站组件的顶部覆盖一个按钮，使他们认为他们点击的是一个控件，实际上他们点击的是一个恶意操作，通常是为了获取他们的凭证、窃取 cookie，甚至钩住浏览器。这些技术在现代浏览器版本中已经得到解决，但值得注意的是这种技术曾经存在。

### Punycode

大多数使用英语的网络用户并不知道世界各地的 DNS 中使用了许多不同的字母表。虽然英语、日耳曼语和罗曼语键盘可能不知道这一点，但浏览器完全能够渲染这些字符以适应使用亚洲、非洲和中东更广泛字母表的用户和公司。妥协的方法是实施一种编码方案，以便浏览器和其他应用程序能够准确地引用其他字符，这就是**Punycode**。这确实会引起一些混淆，因为不同语言中有一些看起来几乎相同但实际上是不同的字母或符号。2017 年 4 月，研究人员发布了警告（[`www.xudongz.com/blog/2017/idn-phishing/`](https://www.xudongz.com/blog/2017/idn-phishing/)），警告黑客试图利用这些相似之处。苹果（Safari）、Mozilla（Firefox）和谷歌（Chrome）等浏览器制造商正在努力提供额外的保护，但这证明了需要更高级别的基于 DNS 的保护。预计在本书出版时，大多数浏览器都将采取缓解措施，但当然，我们需要验证这些更新是否已经到位。

### 伪造或劫持证书

证书和**公钥基础设施**（**PKI**）是网络和企业信任的基础。这种安排的前提是，如果双方都使用受信任的第三方进行相互认证，会出现什么问题？嗯，黑客们一直在尝试伪造证书，依赖于配置错误的证书、浏览器和松散的服务器端实现。这些都相当容易暴露和防御，但一些新的动态正在计划中。

据称针对伊朗离心机的**Stuxnet**恶意软件活动（[`www.wired.com/2014/11/countdown-to-zero-day-stuxnet/`](https://www.wired.com/2014/11/countdown-to-zero-day-stuxnet/)）在攻击期间做了许多具有指导意义和前所未有的事情。作为一种蠕虫，它通过隐藏在.LNK 文件中的脚本在目标环境中传播，特别阴险的是这些文件会自动打开并渲染以显示文件类型的图标。一旦进入机器，它建立了内核级别的访问和持久性，同时掩盖了其他帮助传播和执行蠕虫的进程。最令人震惊的发现是它使用了经过签名的软件，使用了真实硬件供应商的证书和私钥进行验证。这种情况对 PKI 社区来说是一个巨大的打击，许多公司开始确保这种情况不会再次发生。

快进几年，现在恶意软件供应商和网络黑客发现，现在可以免费或廉价获得证书颁发机构，这可以帮助他们为其恶意软件或恶意网络门户获得合法证书。再加上 punycode 或其他域名**恶作剧**，我们现在看到 XSS 将用户引导到恶意门户，这些门户通过 Firefox 中的明显*受信任站点*图标欺骗用户。值得注意的是，这些攻击仍然很少见，但我们应该期望更多的黑客将尝试在未来利用它们，作为对网络上 TLS 使用的普及和浏览器默认设置的反制措施，这些设置阻止接受自签名、过期或伪造证书，除非明确绕过。作为测试人员，我们将希望确保我们的扫描显示适当的 PKI 配置，仅使用最新版本的 TLS，并且企业浏览器标准不会妥协证书验证，甚至决定采用明确的证书配置，以避免签名恶意软件或重定向：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_10_18.png)

证书信任不再是过去的样子

## 摘要

* * *

客户端漏洞及其利用暴露了大多数 Web 开发人员的盲点；他们不习惯拥有客户端平台上的安全性，并且可能会陷入只保护他们的框架或应用程序的陷阱。黑客将这视为一个巨大的机会。他们可以妥协最终用户，同时从他们那里转移，利用他们的经过身份验证或缓存状态，从而妥协 Web 服务器。作为一个社区，我们需要确保应用程序所有者明白，加强网站防范客户端漏洞的利益最大化，因为改进客户端安全性会显著减少应用程序本身的攻击面。

这并不容易——操作系统、浏览器、补丁级别、访问模式和其他因素的近乎无限的组合可能会影响客户端的暴露。基于最佳实践的设计、打补丁和对细节的关注是对这些潜在致命缺陷的最好防御。我们还应努力鼓励在可能的情况下使用经过充分测试的框架，而不是自定义组件。与第九章 *压力测试身份验证和会话管理*中讨论的身份验证和会话管理漏洞一样，我们更愿意从这些广泛可用的组件的更大足迹和广泛审查和审查中受益，而不是发现我们的目标的独特实现存在漏洞，直到被黑客利用。

在下一章中，我们将通过测试来看一下如何对应用程序的业务逻辑进行测试。这最后的纪律真正关注应用程序层的设计和错误处理，虽然我们会看到一些主题重现（比如注入和模糊测试），但我们真的希望确保即使经过身份验证的用户也无法*破坏*目标并引起问题或访问意外的数据或功能。虽然本章重点是 HTML，并且只是少量使用了我们的工具集，第十一章 *破解应用程序逻辑*将会重新使用 Burp 和 ZAP，因为它们的自动化能力将对覆盖网站可能期望的所有迭代起到巨大的帮助。我们几乎到了尽头，但希望您仍在建立您的武器库，并看到网络应用程序渗透测试的规模和乐趣有多大！


# 第十一章：打破应用逻辑

应用程序的业务逻辑不仅对向应用程序的用户呈现准确和预期的信息至关重要，而且实际上有助于维护对某些人来说是业务状态真相的东西。考虑这一点：我们经济的数字化导致大多数财富 500 强公司完全数字化，那些仍然标榜有形产品或提供服务的公司完全依赖于他们处理数据和信息的能力。IT 已经从必要的恶变成了业务的重要推动者，并且在金融、制造业、政府和医疗保健等各种行业中甚至具有竞争优势。灾难恢复和业务连续性项目的激增以及对网络事件的高度恐惧是企业和社会终于意识到这种依赖有多深的症状。

Web 应用程序提供了一些这些应用程序的窥视。一旦用户可以访问应用程序，他们通常会希望代表他们采取一些行动。在前几章中，我们看到了确保用户是正确的用户（而不是黑客）以及安全控件得到正确实施的重要性。这确保了向用户提供的数据既有效又没有恶意。跨站脚本、注入和其他形式的误导可能会从易受攻击的站点反射到客户端和最终用户，但有一类攻击是真正打破应用程序的业务规则。如果攻击者能够利用应用程序中的任何软肋，他们可能会对企业或组织造成严重破坏，并使噩梦变得非常真实。这些漏洞对黑客来说很难——在网络犯罪行为中并不常见——因为它们需要对业务有更深入的了解。这需要时间、坚持和技术之外的维度。

我们可能会遇到的潜在系统差异很大，从人力资源（HR）和客户资源管理（CRM）到工作流程、供应和物流以及企业资源规划（ERP）工具。无论应用程序的类型如何，我们已经看到它们不能盲目地信任这些应用程序来保护数据，即使是通过经过身份验证和加密的渠道。在本章中，您将了解测试人员如何进行逻辑验证，并测试我们的目标是否能够辨别虚假或恶意数据、文件或操作。您还可以了解 Web 应用程序如何确保正确使用，并对可能使站点完全开放于攻击的常见缺陷进行测试。在本章中，我们将介绍以下主题：

+   学习如何检查不当的功能和 URL 访问

+   使用 Burp Suite 自动化检查以确保适当的控件

+   在各个层面探索访问控件，以确保适当和预期的操作

+   执行文件上传以确保错误处理、有效性检查和恶意软件保护已经就位

## 与目标进行快速约会

* * *

最好通过发现应用程序本身试图做什么、评估预期行为，然后寻找预期行为出现问题的方式来理解业务逻辑。其中一些问题实际上可能是由于软件问题或支持应用程序的模块的错误配置。虽然有时界限模糊，但我们将专注于行为缺陷，这些缺陷更容易通过对应用程序目的、公司目标以及目标开发人员认为他们正在交付的流程的洞察力来发现。

那么，OWASP 如何定义这些漏洞呢？实际上，这些缺陷比我们迄今为止一起看到的其他缺陷要复杂得多。它们也经常被错误地分类，但我们主要关注的应该是应用程序的完整性，而不是主观分类。重要的是确保我们测试代码和逻辑缺陷，并向赞助组织提出适当的建议，以确保利用不会达到目标。对这些缺陷的测试要求更高的知识水平通常将业务逻辑测试限制在灰盒或白盒测试中，因为在黑盒渗透测试中熟悉并进行这些缺陷的测试太耗时了。

在第九章，*压力测试身份验证和会话管理*中，我们讨论了 2013 年 OWASP 十大风险中提名的一种漏洞类别，***缺失的功能级访问控制***。为了参考，我在下面的屏幕截图中再次包含了他们的摘要。虽然这些原则的许多方面在第九章中已经讨论过，*压力测试身份验证和会话管理*，但是这一类别中的一些缺陷实际上是由于业务逻辑缺陷或业务流程到应用程序规范的要求分解不当。我们几乎不能责怪软件团队不是心灵读者。我知道，这是很诱人的！其他漏洞超出了功能访问控制领域，而是涉及交易处理的不当。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03198_11_01.png)

OWASP 对缺失功能级访问控制的风险摘要

我们将在一些更相关的领域中研究一些这些问题，以确保我们像猎物一样思考，并更好地适应他们遇到的业务问题。

### 利用电子商务

如果一个网站专注于电子商务，很可能会有一个购物车。如果我们考虑一个现代购物车可能具有的功能，通常包括购物车中产品的列表，修改每个产品数量的方法，输入优惠券和折扣代码的字段，通常还有一个付款或运输流程，类似于 Packt 网站上看到的[`www.packtpub.com/`](https://www.packtpub.com/)的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_11_02.png)

Packt 自己的购物车/电子商务网站

除了购买一个很棒的产品之外，在购物应用中可能出现很多问题。即使我们可以证明它没有编码错误，仍然可能存在工作流程或流程的问题，这些流程用于驱动实施却没有得到适当的验证。以下是一些业务逻辑缺陷的例子，我们可能会失去对购物车的控制：

+   **折扣异常**：一些网站在删除产品或修改数量后，未能重新计算订单的折扣。一些精明的购物者甚至发现了一些允许在特定产品上应用优惠券，然后删除这些产品但保留优惠券优势的网站。

+   **价格操纵**：一些早期的旅行网站没有对应用程序返回的定价进行验证，而是相信客户端的浏览器准确报告所见的价格。在足够多的人能够以远低于实际成本的价格购买航班之后，你可以打赌那些开发人员开始验证一切。

+   **购物车交换**：一些网站过去在将购物车与经过身份验证的会话关联方面做得不好，当与朋友和亲戚共享购物车时，可能会在一个用户的付款上购买购物车内容，而在第二个用户的地址上进行配送。黑客已经利用了这个漏洞。

+   **礼品卡伪造**：也许没有任何一个缺陷能更好地证明业务逻辑漏洞远不止局限于数字领域。黑客和欺诈者已经开始利用现在无处不在的礼品卡领域。由于许多卖家通常不追踪礼品卡，而且在事后对账户的余额应用了最少的跟踪，黑客已经开始通过模糊潜在未兑现的卡号并猜测流通中的卡存在来获取礼品卡余额。利用 Burp Suite 的模糊能力，磁卡条编写器和一些耐心，恶意欺诈者可以生成大量带有余额的卡。更多信息可以在[`www.solutionary.com/resource-center/blog/2015/12/hacking-gift-cards/`](https://www.solutionary.com/resource-center/blog/2015/12/hacking-gift-cards/)找到。

针对这些缺陷的测试可以涉及对各种参数进行模糊测试 - 包括用户输入部分中明确列出的参数，以及隐藏字段和 cookie 范围中的参数。Burp 和 ZAP 非常适合这个角色。也就是说，许多真正的流程问题将需要由知识渊博的人来发现。OWASP**破损的 Web 应用程序**（**BWA**）**虚拟机**（**VM**）提供了一个**BodgeIt** Web 应用程序，可以帮助练习一些与购物相关的问题。

### 金融应用程序 - 给我看钱

金融门户网站，如电子商务中的门户网站，直接影响着各种金融状态的用户。银行和投资公司往往对技术方面的网络安全非常关注，但这并不意味着所有的业务逻辑都已经得到了正确的转化，或者所有的规则都已经通过了每一次迭代或使用案例。当它们专注于一个特定的服务或故意远离标准的银行惯例时，这些网站特别容易出现业务逻辑问题，比如下面截图中显示的练习网站：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_11_03.png)

金融业务逻辑的练习网站，Cyclone Transfers

过去最常见或臭名昭著的缺陷列在这里：

+   **账户恢复**：不仅适用于金融机构，而且在这里非常值得努力的是，对银行或公司的账户恢复流程进行攻击。通过暴力破解或更好地说，社会工程学，黑客可以通过安全问题满足门槛，实际上劫持账户用于自己的用途，通常在用户意识到之前就已经将其清空。

+   **分布式拒绝支付攻击**：当臭名昭著的海盗湾网站的创始人因分发非法获取的内容和软件而被罚款时，其中一位（Gottfrid Svartholm，[`news.hitb.org/content/pirate-bay-proposes-distributed-denial-dollars-attack-ddo`](https://news.hitb.org/content/pirate-bay-proposes-distributed-denial-dollars-attack-ddo)）设计了一个计划来攻击追究责任的法律团队。通过要求活动支持者每人捐赠一分钱，他们希望迫使起诉团队承担每笔交易 1 美元的交易费。如果规模扩大，这将达到数百万美元，而他们只能收到资金的 1/100。金融机构的验证肯定可以帮助及早制止这些攻击。

+   **账户链接问题**：如今，几乎任何机构都需要允许他们的客户将金融账户与其他机构链接。这不仅仅是方便 - 没有这个功能，根本不可能在他们的网站上加载余额。也就是说，利用漏洞继续影响金融世界，利用链条中的弱机构。用户输入的不充分验证可以允许黑客转移资金并更改自动付款方式。

OWASP BWA VM 上的**Cyclone transfers**应用程序可以帮助演示上述问题，还可以从[www.vulnhub.com](http://www.vulnhub.com)下载大量的虚拟机来演示。

### 黑客人力资源

人力资源门户正在成为黑客的热门目标。提供灵活工作安排或依赖远程用户的公司现在正在扩展人力资源门户访问以提供公共云访问。他们提供的服务和吸收的信息构成了一个不可抗拒的目标。类似类型的网站和工作流程也在政府社会计划中发现，例如美国退伍军人事务部或社会保障管理局门户。在这些网站上，我们看到个人信息和银行信息的融合，通常会泄露机密信息（薪酬标准、薪酬结构、绩效评估等），这些信息在暗网上或作为勒索活动的一部分可能非常有价值。

### 注意

学习人力资源和应用安全交汇的一个很好的资源可以在***国际标准化组织（ISO）27002:2013 信息安全管理，第七章，人力资源安全***中找到。

人力资源应用程序中的常见风险集中在敏感信息披露，但也可能影响工资单和评估工具集。一些最令人担忧的风险包括：

+   **个人数据曝光**：在人事数据库中不当使用基于角色的访问控制可能会允许用户意外（或攻击者故意）访问其他员工的信息，而这些员工没有合法的权限。一旦访问，数据可能容易遭到篡改、删除或外泄。

+   **工作流程操纵**：调动、加薪、降职、解雇——如果这些工作流程被不当访问，可能引起的混乱是不容小觑的。幸运的是（目前为止），还没有公开宣布发生这种类型的违规事件，但没有人想成为第一个。

+   **员工流动性**：许多客户的人力资源组织和员工群体都使用临时、合同和永久员工。此外，许多人在雇佣前后（招聘、退休、家庭等）与员工进行一定程度的互动，这进一步复杂化了**基于角色的访问控制**（**RBAC**）。确保这些不同的角色被明确定义和实施，以确保在员工状态发生变化时及时进行调整至关重要。

### 邪恶的复活节彩蛋

世界上一些地区的孩子们通过寻找隐藏的糖果和彩蛋来庆祝春天的基督教节日复活节。虽然这些**复活节彩蛋**与节日的意义关系微弱，但这个术语在视频游戏中流传开来，Atari 的一些程序员是第一批有意隐藏代码和有趣响应的人，只有在特定的按键组合或事件解锁隐藏事件时才能访问。一些有趣的彩蛋仍然存在于现代操作系统上（[`www.businessinsider.com/mac-windows-easter-eggs-2013-2`](http://www.businessinsider.com/mac-windows-easter-eggs-2013-2)）。黑客已经开始使用类似的方法，因为正常的软件验证工具可能会忽略这些事件，或者无法看到它们之间的关系。

避免这些漏洞产生影响，我们的首要任务应该是确保黑客无法在不符合严格验证的输入字段中植入信息，或者剥离或筛选任何嵌入式代码片段或片段中的任何恶意内容。虽然以这种方式传递的代码通常无法执行，但应用程序中其他攻击（缓冲区溢出和代码注入）可能会引用这些字段并重新组装可执行文件或脚本。完全自动化的安全漏洞扫描器将忽略这些实例的潜力，因为它们无法正确模拟将代码重新组合的条件。它们最好的防御措施，也是我们应该测试的最重要的事情，是确保用户输入经过验证，以确保它们是完全相关的。在地址字段中，不可打印的字符或编程语法是不合适的。Unicode 在数字字段中也是不合适的。

### 这么多应用程序可供选择...

正如你所看到的，这只是皮毛。虽然工具可以帮助渗透测试这些应用程序的业务逻辑，但是适当地限定这些目标范围是至关重要的，因为要完全测试它们将需要对应用程序以及组织实施的定制进行详细了解。无论应用程序是什么，它们都会接收和处理数据。一旦我们确定了在哪里以及如何，我们就有一些基本的检查项目，可以防止常见的漏洞利用。

## 功能风水

* * *

在渗透测试应用程序中，到目前为止，我们在如何处理这里使用的每种技术方面已经非常有条理。自动化工具，如我们的代理扫描器、暴力破解应用程序以及许多枚举和扫描工具，已经帮助我们做到了这一点，并且可能使新的渗透测试人员能够成功地识别出许多漏洞，而无需对环境有详细的了解。这是因为许多测试与不正确的编码、技术缺陷或配置错误有关，它们在性质上更加具体。

然而，业务逻辑测试完全是关于理解网站试图表达或执行的工作流程。现在，我们可能仍在使用工具，但只有在具有实际知识的情况下才会使用。在许多情况下，将工具调整到特定的业务逻辑测试可能远远超过手动扫描本身所需的时间。将其视为更加明智的测试，这样的时间在灰盒或白盒范围内是完全合理的，以确保应用程序所有者和开发人员的意图得到正确实施。让我们看看如何使用我们之前已经介绍的工具来解决这些问题。

### 基本验证检查

对于大量的业务应用程序，我们需要成为操作的大脑，并帮助工具理解应用程序预期的工作方式。代理工具可以帮助我们聚焦传递的变量，向我们展示客户端和服务器之间的交接点在哪里。大多数应用程序开发人员只会考虑在一端或另一端进行验证，因此，通过在这些交接点中捕捉它们，我们通常可以找到一些麻烦的空间。如果是电子商务网站，我们需要验证应用程序不会让代理设置自己的价格。如果是人力资源网站或医疗保健门户网站，我们需要确保故意提交的无效信息不能代替有效的姓名、个人信息、地址和电话号码。

我们可以使用 Burp Suite 的 Proxy Intercept 和 Intruder 功能来检查这些，其中您可以在尝试向每个字段提交*越界*字符串的同时测试输入验证。为此，我们可以从 OWASP BWA VM 中包含的 OWASP Security Shepherd Application 等内容中提取适当的用户输入页面，并进入 Poor Data Validation Lesson，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_11_04.png)

OWASP 安全牧羊人应用程序

如果你一开始就输入一个负数，你会注意到它返回一个消息，说**`发生错误：无效数字：数字必须大于 0`**，如下面的截图所示。有趣的是，当我查看 Burp 的代理拦截时，没有 GET 或 POST 等待转发。这表明存在客户端验证。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_11_05.png)

尝试无效输入

当提交一个有效数字时，我们可以通过客户端验证，并在 Burp 代理的 HTTP 历史记录中看到 POST 消息。在下面的截图中，我们可以看到`userdata`字段，它被提交为`1234`，但我已经修改为负数。如果应用程序只依赖于客户端验证，这应该可以绕过。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_11_06.png)

修改客户端验证的输入

在**安全牧羊人**网站的这节课中，我们将在下面的截图中看到成功。在对生产应用程序进行真正的测试时，我们的结果会有所不同：我们可能会看到混乱的输出作为存储元素重复返回，或者我们可能会看到对账户余额或其他可衡量实体的调整。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_11_07.png)

成功利用了不良验证

在任何情况下，只要活动的客户端进程进行输入验证，HTTP 消息是不受保护的，服务器端不会对输入进行二次检查，都可以使用相同的方法。在这个用例中，它是一个数字，但是我们可以想象，我们可以将其应用于地址字段、评论区域、个人信息、银行信息等。使用 Burp 的 Intruder，我们可以模糊多个参数并使用有效载荷生成器（更多信息请参阅：[`portswigger.net/burp/help/intruder_payloads_types.html`](https://portswigger.net/burp/help/intruder_payloads_types.html)），可以来自 BurpSuite 自己的第三方来源，也可以是我们自己制作的。许多渗透测试人员将使用 Java、Python 或 Ruby 开发自己的生成器，以便与 Burp Suite 集成，这是一个完美的应用场景。一个很好的例子是我们如何探索 Burp 提供的 API 并开发模糊器的详细信息，请参阅[`apprize.info/python/black/6.html`](http://apprize.info/python/black/6.html)。

### 有时，少即是多？

每当我在解释某事时变得啰嗦时，我的同事们会温柔地提醒我“少即是多”。在 Web 交易中，通常情况下，HTTP 请求和响应会透露多个可追踪的元素，而不是为会话状态增加清晰度，反而会削弱其安全性。我们在前几章中看到，多个应用程序使用**`PHPSESSID`**或**`JSESSID`**、用户名、用户编号、会话令牌等组合来跟踪同一对话。虽然我一直致力于提供某种程度的保证，表明某些东西被很好地跟踪，但如果应用程序仍然允许只使用部分会话管理参数来维护状态，那么找出哪些参数实际上可以在没有其他参数的情况下传递会话，可以为我们了解如何模糊或更改应用程序的行为提供重要的见解。这可以在 Intruder 中进行一次性测试，但为了获得最佳结果，我建议使用 Repeater 来确保可以进行回放和文档记录。

我可以向**`Repeater`**发送任何合适的 POST 或 GET 消息，并系统地删除、修改、添加或更改请求中的所有参数的顺序，这些参数是应用程序似乎正在使用的许多字段，以维护会话状态。在下面的截图中，我们可以看到有大量的会话 ID 和令牌在使用中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_11_08.png)

空白的 cookies 和参数

通过一些试错，我发现`JSESSIONID`和`userdata`字段是我们需要维护状态的全部内容。知道了这一点，我可以将定制的请求再次发送给 Intruder（如下图所示），从而可以集中精力对关键字段进行模糊测试。如果我们感兴趣，我们也可以将其发送给许多第三方扩展程序之一，这些扩展程序可以篡改各种会话 ID，并尝试利用弱会话管理。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_11_09.png)

将关键字段发送回 Intruder

业务逻辑测试的关键在于结合应用程序应该做什么以及如何提供服务的见解，以及适当的工具和调整，以帮助加快测试速度。

### 伪造恶作剧

一旦您了解了 Web 应用程序的合法请求是如何格式化和填充的，以进行合法流程，同样的方法和工具可以用来制作您自己的请求，而无需客户端浏览器。黑客可能使用这种方法对 Web 应用程序进行大规模操作，但我们作为测试人员也可以使用这种方法更全面地测试可能的字段验证缺陷，这些字段通常不会被提交。一个例子可能是在动态表单页面上，客户端验证通常会根据先前的选择、复选框等上下文隐藏字段。伪造请求可以让我们提交递增字段或构建参数组合。这些缺陷在不在事务的两端（客户端和服务器）进行验证的应用程序中很常见。

可能属于这一类的其他功能包括可以打开调试或详细消息的隐藏开关。如果黑客能够切换这些开关，应用程序返回的消息可能会产生不利影响。调试信息通常包含应用程序内部工作的高度详细清单；如果它们落入错误的手中，可能会向攻击者透露太多信息。其他字段可能通常是不可访问的，并且可能会影响权限或访问权限。测试伪造的可能性有助于确保它们不会在应用程序内部引起问题，也不会导致意外披露或权限升级。

### 这个按钮是做什么的？

许多内部网络应用程序都会整合多个功能，或者作为许多团队的共同门户，通常会在某些字段中使用选项列表，以便让用户帮助确定他们感兴趣的页面、项目、共享或子功能。我曾在一家雇主那里工作，他们在早期大量使用**Microsoft SharePoint**，他们会为每个提案、开发工作或我们启动的集成工作建立一个新的项目门户。虽然我可能同时参与了五个项目，但在那个门户上我可能看到了四十个或更多的项目。在大多数情况下，我被拒绝进入，但在几个情况下，我是被意外地允许进入的。

作为测试人员，我们需要确保这样的控件不会提供无效选项，或者向用户提供太多关于目标环境中可能存在的其他内容的信息。一个应用程序的攻击面（潜在向量的数量）会随着每个添加的功能或组而扩大。Web 开发人员应该考虑从一开始就删除无效选项，或者至少确保向特定用户呈现的选项不会透露太多关于*底层内容*的信息。如前所述，这种测试最适合在白盒测试范围内进行大量实验，并且应该在**软件开发生命周期**（**SDLC**）的所有阶段都进行。

### 时机很重要

基于时间的功能是电子商务网站和银行应用程序中的重要功能，希望超时工作流以防止无人看管的会话。这个功能对于任何使用在线旅行预订网站或票务交换（例如下面屏幕截图中的 Fandango）的人来说也是熟悉的，公司试图防止机器人或霸占者占据首选座位并锁定其他有效用户。这些规定需要起作用，否则这里的问题可能会允许攻击者的客户拒绝产品或销售，劫持会话，或者在帮助开放交易期间利用受信任的连接。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_11_10-1-1024x598.png)

基于时间的交易验证

基于时间的验证测试只能手动尝试，并且只能在对设计或代码进行广泛审查之后进行。测试应验证刷新、会话劫持和参数的模糊化无法影响应用程序的计数，并阻止时间限制的操作。

### 达到您的功能极限

一些 Web 应用程序需要限制事务执行的次数或每个工作流中调用函数的次数。正如本章前面的电子商务部分所讨论的，执行不良的购物车已经被发现接受了相同折扣券的多个应用。机票网站可能会试图将购买的机票限制为一次性交易，但已经出现了在相同的一次性交易成本下购买重复机票订单的情况，从而规避了适当的收费。

一些应用程序将放弃他们自己的工作流程，与经过验证的第三方集成，特别是与**PayPal**或**Google 支付中心**等服务进行交易集成。但是，正如我们在下面的屏幕截图中可以看到的，在一个沙盒化的 PayPal 环境中，有很多移动的部分，应用团队需要正确理解和适应，否则黑客会利用。幸运的是，许多最好的金融处理页面供应商都提供工具、培训和最佳实践，以确保正确的实施和减少威胁。请记住，如果集成的应用程序安全性不当，可能会对更大的支付处理应用程序构成风险。正是出于这些原因，大型支付处理和交易辅助服务不仅提供一流的启用功能，还提供严格的分割、验证服务、可撤销的 API 密钥和其他快速消除从租户服务中溢出到其领域的任何攻击的对策。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_11_11-1.png)

PayPal 的开发功能拓扑

功能限制需要与人类一起进行测试，就像本章的其他方面一样。也就是说，测试人员必须要么有设计文档和代码，要么与产品开发团队进行互动，以确保在测试之前充分理解正确的行为，并且任何问题都能得到迅速解决。

### 我们敢接受文件吗？

一些 Web 应用程序，如费用报告工具、在线图形或图片库或保险公司，可能需要在工作流程中上传文件的能力。由于大多数这些文件是为了与公司员工共享或在其他用户之间传播而需要的，因此这些文件类型必须得到适当的门控，并且文件本身必须没有恶意软件或可疑材料。在欢迎这些文件进入他们的工作流程之前，公司应确定是否有必要，并就他们对其他利益相关者的责任作出明智的决定。他们需要知道是否需要完成防病毒或反恶意软件扫描吗？他们需要监管潜在的知识产权或个人信息吗？是否应允许带有宏或加密的文件，如果是，如何处理？

### 注意

在生产环境上线之前，所有这些问题都需要得到解答。对这些政策的深入了解和由此产生的控制可以帮助我们测试任何边界条件，当部署可能被接受并随后被他人查看的测试有效负载时，我们肯定需要明确的许可。

## 摘要

* * *

Web 应用程序可能在技术上是健全的，但如果开发人员没有准确地执行公司运营门户、应用程序或服务的意图，就会存在风险。这些业务逻辑问题是难以捉摸但重要的。客户通常会对在生产环境中测试它们所需的额外开销感到不安。这种恐惧或焦虑应该帮助我们强调在 SDLC 中整合渗透测试的必要性，并帮助我们证明应用程序和支持环境中所有元素的组织良好和最新的文档。事后测试是昂贵且耗时的，事后发现的任何问题通常会导致门户的某部分或支持它们的工作流程的彻底重新设计。

业务逻辑测试对我们来说是一个新的尝试，因为它几乎完全依赖于手动的网页交互。时间上的准确性，更不用说为了进行充分测试所需的细节，意味着应用程序渗透测试的这一部分将与更常见的黑盒测试分开。在大多数情况下，业务逻辑测试将由具有丰富经验并与开发人员长期合作的承包商或顾问在内部进行。与测试合作并学会自我检查以更好地指导开发对于应用程序开发团队来说可能是非常值得的。独立测试应该始终受到鼓励，但发现的影响可以更早地在开发过程中得到解决。

现在我们已经完成了适当的 Web 渗透测试的大部分测试类别，我们要做的是向客户传达好（或坏）消息并结束测试。我们将看看任何客户都可以如何改善他们的地位，无论结果如何。我们还将审视一些良好的最佳实践建议，这些建议可以帮助我们表达我们的发现，无论是在测试过程中还是在测试结束时。在一天结束时，我们还需要能够撰写一份可以交付并展示客户价值的报告；如果没有这一点，我们将很难找到后续业务或推荐。我们几乎到达目标了，让我们坚持到底！


# 第十二章：教育客户和结束

如果你已经读到这里，谢谢！你已经学会了如何处理 Web 渗透测试，以及如何专注和细节来改善客户的安全状况。Web 渗透测试是一种野兽，值得专门化和精通。正如我们在本书中所看到的，存在着令人困惑的各种漏洞类型，而它们易于利用的事实使它们很容易被利用。企业在整个企业范围内都存在重大问题，但从某种意义上说，它们的 Web 应用程序必然是最脆弱的方面。他们如何最好地保护与他们无法控制的用户进行最多互动的工具？

许多 Web 应用程序开发人员及其雇主已购买工具，以提供安全和可靠的运营。良好的意图经常会遇到现实世界的压力和限制，而工具在适当的操作、维护和保养之前就已经被抛在一边。业务速度--业务适应和提供新能力的速度--给 IT 组织和应用团队带来了压力；而在安全实践不足的情况下，通常会出现一种错误的选择：安全还是高效。企业通常会选择后者，因为这是支付账单的方式。安全成为错误抉择的受害者。除非我们能说服团队将安全融入其中，而不是后期添加，否则我们将继续以惊人的速度阅读失败案例。

有些人愤世嫉俗地认为这就是让我们生意兴隆的原因。如果用户及其雇主从不点击可疑链接，始终修补和维护他们的系统，并且只与经过验证的合作伙伴、客户和供应商进行有效业务，我们将看到更少的行动。我们都知道这是一个白日梦。互联网是很多东西，但整洁、有序和安全不是其中之一。作为渗透测试人员，我们独特地适合帮助推动更全面的安全策略。我们既可以确定当前状态，又可以提供建议和指导，以实现更安全的结果。这并不容易，它迫使我们运用许多技能，我们都更愿意忘记，但沟通技能，口头和书面，是传达发现和建议的关键。

最终报告无疑是我们大多数人关注的重点，但向客户提供可预测和信息丰富的状态报告是成功与否的关键。我将尽力为您提供一些资源，帮助构建最佳实践并制定您的报告。我们将讨论如何使用状态报告和可交付成果来讲述正确的故事，并帮助我们的客户找到平静。我们还将涵盖其他一些方面，比如提供建议、传递坏消息，甚至何时重复这些评估或如何推动渗透测试计划以进行勤奋的持续改进。在本章中，我们将讨论以下主题：

+   权衡验证配置的方法，并在业务需求不断变化的情况下保持其相关性。

+   提供如何审计代码版本和配置健康的指导。

+   讨论分割、基于角色的访问控制和变更管理。

+   讨论任何良好的 Web 渗透测试的演示和后续步骤。我们还将讨论与 Kali Linux 相关的竞争格局和互补工具。

+   比较一些竞争产品与 Kali Linux，这些产品实际上可能有助于评估 Web 应用程序安全性。

## 结束

* * *

世界上最好的工作对客户来说意味着什么，除非它被转化为全面的、可操作的和有见地的指导。许多技术职业由于无法沟通工作而过早结束或受到限制。除了许可和意图，另一件事将我们与黑帽黑客区分开来，那就是我们与客户的沟通。我们必须成为老师和教练-对于我们的许多客户来说，这将是一个可怕和令人心烦的过程，但我们需要提供他们可以用来改进的指导。

### 注

清理呢？嗯，Web 应用程序渗透测试（在大多数情况下）不会对环境进行永久性更改。在我们使用的大多数利用中，简单地清除浏览器的缓存或清除 Web 前端的字段将使应用程序恢复到正常运行状态。

每个父母都会对他们的孩子说“重要的不是你说了什么，而是你怎么说的”至少每周说几次。孩子们需要调整他们的直觉以适应人群，而父母则是调音者。非常类似地，我们必须“了解我们的受众”。大部分内容和细节水平将不仅由**工作声明**（SOW）中概述的范围所决定，还将由客户自己团队的能力所决定。对他们的头脑说话会疏远和冒犯他们的员工，并使您进行后续测试或重复业务的机会渺茫。一些客户也可能非常防御或不可信任，我们必须记住他们自己的职业生涯可能取决于这些发现。因此，我们希望确保最终报告中没有任何意外。我们希望我们的客户和利益相关者对发现做好充分准备，并准备接受建设性的批评而不感到恐惧。我们可以通过几种不同的方式和整个过程来传递好坏消息。

渗透测试人员最好提供一个审慎和冷静的方法。有些人可能会试图在可能不存在问题的地方找到问题，以显示增加价值。其他人可能会试图增加紧急性，以在客户心中灌输恐惧，并使自己显得不可或缺。我鼓励您专注于真正的问题，表现出冷静和一贯的态度，并在向目标客户报告时努力追求质量发现而不是数量。最终，这种审慎和有意义的互动将帮助客户，增强信心并获得对您能力的信任。

### 避免意外的持续联系

我们应该计划并承诺与客户一起进行状态报告和标记会议的节奏。即使在黑盒测试中，我们通常也可以提供进展报告，以帮助他们了解我们的进展情况。这可以根据 SOW 中包括的里程碑来呈现，也可以根据目标环境的要求进行任何转变或调整。无论如何，报告都应包括重要的结果或印象，无论好坏。特别是在黑盒测试中，整个利益相关者社区（我们和他们）都应该为一些变化做好准备，因为测试的每个先前阶段通常会决定下一个阶段的范围。

一般来说，您应该考虑计划好的和未经计划的沟通，理想情况下，制定模板并建立传递每种沟通的渠道。就像医生的后续电话一样，我们希望客户知道您和您的团队将在设定的时间联系他们，并披露目标环境的任何重要和赞美的发现。一旦他们知道可以期待什么，这可以帮助他们理解这个过程，并鼓励他们的参与和审查。

组织内进行的白盒测试可能没有明确定义的合同文件，但这并不意味着沟通就应该中断。在整个软件开发生命周期（SDLC）中进行的内部测试可能会揭示关键的漏洞、活动攻击或违规行为。管理层提供一个可信且客观的流程，供内部测试人员提出这些问题至关重要。保持这种渠道的畅通可以维持开放的文化，并使应用程序更加安全和稳健。

#### 建立定期更新

定期更新对于我们建立与客户的关系和构建积极的、建设性的叙述至关重要。我们的重点应该是帮助他们保护他们的网络应用程序，等到流程结束可能会使客户的利益相关者处于防御状态。我们需要接受他们在最终报告中将看到的内容，寻求即时的指导和价值。如果领导层已经准备好定期报告，让他们了解主要发现，他们将有时间克服可能存在的防御本能，而是期待报告的下一步。这些报告不需要非常详细，而应该突出主要发现，与 SOW 的状态相对比，总结我们为关键发现生成的任何临时报告，并提供展望。这个流程的大致轮廓可能包括以下部分：

+   突出的发现

+   测试进展/进度更新

+   表扬（客户做得对的地方）

+   建议（让他们意识到问题）

+   进度和预算状态

+   前进/预期的方式

### 注意

您团队的模板可能会有所不同，甚至可能会根据客户的需求进行定制，但以易于理解的形式向他们呈现这些信息有助于他们看到测试的价值，开始规划修复计划，并有助于避免任何意外情况 - 最终审查和总结应该只是审查。

白盒测试报告通常会作为正式交付物的一部分，就像任何其他验证和验证测试成果一样。如果这些交付物不是已经建立的标准，那么应该创建一个标准，以确保一致应用测试原则。在所有形式的渗透测试和报告中保持一致性对于帮助培训资助组织及其开发人员如何对待和回应发现至关重要。

#### 何时按下大红按钮

即使向客户提供定期报告，仍会有时候发现或结果需要立即披露并停止工作，直到得到许可。可能会立即披露的关键缺陷包括可能导致数据外泄、发现活动攻击，甚至与人力资源相关的事件（发现间谍、内部威胁、不当内容等）。在制定约定规则的过程中，您或客户可能会根据目标环境的重要性或角色添加额外的条件，这也会触发立即通知。

保密协议要求您严格保守测试结果，但正是这些关键的、实时的通知需要您发挥最佳和最勤奋的作用。可能会触发披露和停止测试的问题通常足够严重，保密性是至关重要的。虽然计划的通讯可能通过电子邮件和安全文件共享提供，但根据客户的业务，可能需要与他们建立更安全的流程。我建议在最终获得批准之前建立这个流程，以帮助所有方面安全地传递这类消息，无论是通过面对面会议、加密电子邮件或消息传递，还是保密信使。

责任是我们接下来要考虑的。及时而完整地向赞助客户披露信息很重要，因为其影响往往对他们的业务、员工或客户构成威胁或损害。在紧急情况下，您的客户可能也在寻找理由来表达他们的恐惧或追究他人的责任。即时、完整和周到的披露确保我们在法律上不承担责任。他们可能会发火，但冷静和一贯的态度可以帮助化解这些情况。我们需要清楚地传达事实和陈述的观点之间的区别，在这些情况下，更多地关注已知的事实而不是我们自己的观点。一旦客户冷静下来或吸收了信息，他们可以促使我们提供我们的解释和专家意见。

### 将乐观情绪与行动计划结合起来

撰写关于您对 Web 应用程序的评估的顶级渗透测试报告是工作中最重要的阶段。您可能会想，“但是迈克，你刚告诉我们不应该有任何意外，还有什么可以留下的呢？”虽然您是正确的，没有重大影响的发现应该不是新闻；但在这份报告中，您团队的建议最终可以被记录下来。这些建议是您对风险和优先事项的评估，这不仅在这里受到欢迎，而且是预期的。您的专业知识是您被聘用的原因，理所当然地，这种见解将帮助他们进入更成熟、更严格的安全实践。

关于最终报告内容应该是什么样的良好指导可以通过查看一些公开可用的 Pen 测试报告存储库来获得。虽然在网站上列出的大多数报告（如[`github.com/juliocesarfort/public-pentesting-reports`](https://github.com/juliocesarfort/public-pentesting-reports)）并不是专门针对 Web 应用程序的，但这些部分和一般流程是有启发性的，并且可以帮助准备您自己团队的模板。一些特定于 Web 应用程序的报告是由**动态应用安全测试**（**DAST**）供应商**Veracode**（[www.veracode.com](http://www.veracode.com)）提供的自动测试报告，以及咨询公司如**CST**（[`www.cstl.com/CST/Penetration-Test/CST-Web-Application-Testing-Report.pdf`](http://www.cstl.com/CST/Penetration-Test/CST-Web-Application-Testing-Report.pdf)）。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_12_01.png)

样本 Web 应用程序 Pen 测试报告

报告中的部分可能是来自扫描仪（如**Arachni**、**Burp Suite**或**OWASP ZAP**）的自动输出的捆绑；或者它们可能是来自多个测试人员及其合作的输出的混合。像 Apache OpenOffice 和 Microsoft Office 这样的工具仍然是汇集输入的标准。Â

典型的大纲可能如下所示：

+   封面

+   执行摘要

+   目录

+   介绍

+   测试背景

+   方法论

+   测试团队

+   亮点、评分和风险总结

+   风险登记

+   指导/行动计划

+   详细发现

+   附录

+   定义

+   漏洞参考

+   工具和资源

+   侦察、扫描和枚举数据

+   使用的代码

+   链接文件

#### 执行摘要

执行摘要应该很好地提供高层次的、可量化的评估（总体得分和主要指标），同时给管理层提供高层次的、有影响的摘要，以便向所有非技术人员传达测试结果和未来方向。

#### 介绍

测试方法的信息可以帮助客户框定发现，并强化您团队的测试是符合 SOW 和在合同阶段更明确捕捉的参与规则的。这是一个总结和概述范围的任何偏差或扩展的机会，有助于确保他们理解实际执行了什么。

### 注

这也是一个很好的地方来讨论团队（如果适用的话），确保客户知道谁参与了测试和报告，以及谁受到合同条款的约束。

#### 重点、评分和风险总结

我们讨论过的一些工具将会很好地评估漏洞的严重程度，与常见的测试框架或排名列表（例如 OWASP 前 10 名，它已经帮助我们指导工作）相比。一些这样的工件，比如下面截图中显示的样本 Arachni 报告输出，可以帮助提供漏洞的客观排名并指导进一步的测试。然而，这些排名无法提供目标环境的背景。例如，一些评分很高的风险可能在特定目标中影响有限，因为该技术的使用很少，或者它只在低权限功能或子门户中部署。虽然使用这些现成的工件可能很诱人，但应该做更多的工作来确保客户理解它们对他们情况的重要性。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_12_02.png)

样本 Arachni 输出 - 良好的起点

##### 风险的更多信息

呈现风险和风险管理本身就是一个话题。我曾经在美国国防部的开发项目中帮助实施风险管理工作，并且我们遵循了国防采办项目的副助理部长办公室的风险、问题和机会管理指南（[`bbp.dau.mil/docs/RIO-Guide-Jun2015.pdf`](http://bbp.dau.mil/docs/RIO-Guide-Jun2015.pdf)）。这远非唯一可接受的方法论 - 存在许多方法，你最好研究一种风险管理方法，它类似于你典型客户的共识。美国国防部使用的一般流程如下截图所示，我们作为测试人员，无论是内部还是外部，都有机会影响循环的部分：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_12_03.png)

美国国防部风险管理流程

如果有什么，我已经学到了风险管理是值得许多大学现在给予关注的。在管理风险（以及问题或机会），有一个明确定义的每个潜在影响和可能性等级是有益的。也就是说，大多数 IT 和应用程序中的风险方法主要关注两个主要标准：

+   **潜在影响**：一些组织将以损害、减轻成本、受影响成本的百分比或其他可量化的影响来衡量这一点。这是大多数没有风险管理经验的人关注的。这是事件发生时所涉及的痛苦，比如：*被闪电击中可能会非常有害，通常是致命的 - 疼！*

+   **发生概率**：许多人忽视了适当的关注和意识过程，实际上感受到痛苦的机会就是它发生的概率。这可以用百分比或频率（每次发生的机会）来衡量（每 *x* 连接、每个账户等）。

在客户眼中理解风险管理不仅是一种表现关心的好方式，而且是理解如何构建报告的关键。如果你能帮助以客户理解的语言和背景呈现调查结果，他们就更有可能接受建设性的批评，并将输入视为有帮助。

#### 指导 - 赚取你的报酬

专业的渗透测试可能在我们攻击目标并在特别具有挑战性的环境中进行转移时更有趣，但我们并不是为了乐趣而得到报酬。我们得到报酬是为了提供指导和可操作的情报。客户雇佣我们是因为他们或者有人强迫他们雇佣我们意识到，他们无法在没有独立验证的情况下保持安全。我们提供的指导应该有事实根据，并且最好以印象总结后的行动计划形式呈现。一些客户可能会规定应该如何呈现，但在没有规定的情况下，您需要考虑如何最好地呈现调查结果。

对于具有大量漏洞的新客户进行更全面的测试可能会受益于一个分阶段的行动计划，该计划建议按照最需要的顺序处理应用程序的各个领域。在这些情况下，有助于将他们指向补救选项和预期的努力水平。客户会有很大的差异，但一般来说，您应该避免推荐与人员相关的问题，除非它们可以被视为建设性的，或者将有助于更好地准备员工。然而，一些客户可能要求员工参与评估，因此您的情况可能会有所不同。

轻量或定期测试可能只是按照最高感知严重性到最低的顺序呈现结果，而不考虑它们之间的相互依存关系。在这种情况下，这可能更容易接受，因为这是对先前测试的后续，或者结果将被纳入另一个规划工作。白盒测试结果通常会直接匹配到更大的验证和验证方法或文档，因此在这种情况下，只有在针对渗透测试的总体规范需要修改或澄清时，才有可能提供指导。

#### 详细调查结果

根据报告的范围，这一部分可能存在，也可能不存在，但对于黑盒测试或红队测试几乎是必须的。您需要确保解释所选择的向量、获得的结果以及与给定评分的相关性。对于希望重复测试和验证补救措施的客户，可能需要屏幕截图和代码片段，因此您需要确保捕获大量日志、屏幕截图，并对任何脚本和配置进行编目。为此，有一些工具可以帮助您，并且已经内置到 Kali 的发行映像中，或者可以通过最小的努力获得。

类似 Evernote 或包含的 Keepnote 的良好笔记应用程序将大大帮助您记录其他工具遗漏的任何内容。我发现这些工具选择和它们支持的工作流程与部署它们的人一样多样化，因此我绝不会判断您是否决定选择其他工具。最重要的是报告最终可以以我们的客户可以消化的格式打印和电子交付。因此，大多数测试人员仍然会发现，Apache OpenOffice（https://www.openoffice.org/download/other.html）适用于 Kali，或者 Mac 或 Windows PC 上的 Microsoft Office 套件最适合组装最终报告，并且可以使用 Adobe 或用户喜爱的办公套件打印为 PDF。

### Dradis 框架

协作和文档工具，如基于 Ruby 的 Dradis 框架，如下图所示（https://dradisframework.com/ce/）。Dradis 可以帮助我们将测试中使用的所有工具集结在一起，并提供类似 Evernote 的文档界面。使用这样的工具可以使我们保持有条理，从而确保完整覆盖并帮助制作专业报告。

社区版是免费的，而且功能强大，但专业版（在撰写本文时的价格为每月 79 美元）包括一些出色的功能，可帮助管理多个项目，利用模板和自动化工具导入，并提供技术支持（可以在此处比较免费和高级版本之间的差异：[`dradisframework.com/pro/editions.html`](https://dradisframework.com/pro/editions.html)）。 Dradis 提供了 OSCP、OWASP、PTES 和 HIPAA 的模板、方法和示例报告，其中一些功能只能在专业版中使用：[`dradisframework.com/academy/industry/compliance/`](https://dradisframework.com/academy/industry/compliance/)。

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_12_04.png)

Dradis Framework with OWASP Template

Dradis 是一个很棒的选择，但在 Kali 中还有其他可用的工具！

### MagicTree

与 Dradis 类似的是一个名为**MagicTree**（[`www.gremwell.com/magictreedoc`](http://www.gremwell.com/magictreedoc)）的 Java 应用程序，来自 Gremwell。MagicTree 实际上是一个很棒的工具，可以从一个中央数据收集应用程序中提供您在早期章节中学到的许多测试。作为一个工具，MagicTree 有很多出色的功能，但我发现它在传递通常在外部运行的命令时可能有点挑剔。它还需要导出才能看到产生的工件的样子，因此，除非您能直观地理解 X-Path 变量插入和原始数据收集将会是什么样子，否则您将需要使用试错来确定 MagicTree 中对您最有效的方法。与 Dradis 不同，MagicTree 不是开源的，但可以免费获得完整功能：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_12_05.png)

Gremwell 的 MagicTree

### 其他文档和组织工具

其他利基甚至手动的文档方法当然也存在，我鼓励您尝试使用其中的一些方法来完善您的报告和文档流程。例如，我一直喜欢使用**Maltego**，我发现它对于帮助组织和展示我在报告中提供的**开源情报**（**OSINT**）是不可或缺的。**Maltego Casefile**是呈现融合的 OSINT 和社会工程结果的绝妙方式，甚至提供了捕获可能密码和类似密码的字段。在下面的截图中，我们可以看到我正在突出显示公司内的一个人，并查看他们与其他实体（位置、主机、其他人等）的关联。就像犯罪电影中的线图表显示了黑手党士兵如何向老板汇报一样，这可以帮助我们的客户快速地可视化黑客如何轻松准确地绘制组织的地图。

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_12_06.png)

Maltego Casefile 组织 SET 和 OSINT 输出。

### 报告的图形

您可能会将 Kali 用作虚拟机，但万一您安装了裸机系统，您可能需要查看截图工具，以帮助您收集渗透测试中征服的视觉证据。

Kali Linux 内置了有限的选项，包括**recordmydesktop**和**cutycapt**。我更喜欢使用**Screenshot**和**Shutter**等工具。Screenshot 或类似工具如**Scrot**相当基本，但 Shutter 提供了一些选项和更高级的管理界面。如果我需要处理图片，我会使用 GIMP（[`www.gimp.org)`](https://www.gimp.org)是一个功能齐全的编辑器，适用于大多数平台，包括 Kali。同样，这取决于您自己的背景和风格，因此请尽管制定自己的计划！

### 注意

请记住，这些技能也将在制作您的流氓蜜罐和水冷攻击时发挥作用，使您能够打造逼真而恶意的门户，以帮助您 compromise targeted users and further your testing - 谈论双重用途！

## 带来最佳实践

* * *

参与网络安全，尤其是攻击性的最好部分之一是，我们可以从我们的培训和过去的工作经验中带来经验和专业知识。所有的辛劳和泪水都不是白费的；这些伤疤实际上会派上用场。我们测试的赞助商处境艰难。在目标环境中工作，他们往往没有跨行业、架构类型和规模的环境视角。在许多情况下，他们的员工没有当前的应用安全培训，无法帮助他们跟上趋势和即将到来的威胁。

因此，现在，有趣的部分来了，我们需要保持我们的认证，不断更新我们的知识库，并找到方法从早期的参与中汲取经验教训。通过 SANS、ISSA、OWASP 等会议绝对值得参加——大多数提供培训和许多新工具和技术的曝光。在线保持更新应该是理所当然的：Twitter、LinkedIn 和大量的博客可以成为零日漏洞和最紧迫的新闻的情报来源，这些新闻会让我们的客户感到不安，并证明我们的存在是有必要的。

那么我们如何提供他们所寻求的帮助呢？我们在哪里介入我们被聘用的经验？让我们看看一些关于如何使我们的报告和简报对团队更有用的想法。

### 融入安全性

应用团队和 IT 组织一般面临着一个不可能的折衷：要么安全，要么高效。这在很大程度上源自过去，安全是在架构或应用程序开发和部署之后才被添加上去的。随着应用程序变得更加复杂，其重要性急剧上升，后期添加的安全方法已经不再适用。当应用程序对安全毫无意识，而安全解决方案只是简单地叠加在顶部时，这种脱节会妨碍可见性，并迫使某人在调整之前手动识别问题。如下截图所示（来源于[`blogs.msdn.microsoft.com/usisvde/2012/03/09/windows-azure-security-best-practices-part-3-identifying-your-security-frame/`](https://blogs.msdn.microsoft.com/usisvde/2012/03/09/windows-azure-security-best-practices-part-3-identifying-your-security-frame/)），即使是一个简单的 Web 应用程序也有太多的执行点，以至于应用程序的安全性必须融入到架构中。这个插图没有显示的是同时需要在每一步实际感知和相关事件，并将其与从架构中其他组件中获得的情报相结合，以确定何时发生攻击。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_12_07-1.png)

根据微软，应用程序的执行点

不同的框架和托管范式将有不同的需求和优势，但客户应该了解需要在业务需求旁边开发的额外措施，以解决覆盖范围中的任何差距。根据您与客户的关系，可能需要引导他们达到这种理解，或者在他们的理解范围内工作，帮助他们客观地看待他们的应用程序。

#### 完善 SDLC

白盒测试可以并且应该在**软件开发生命周期**（**SDLC**）的各个阶段进行，早期发现的问题可以比在 SDLC 后期更便宜、更快速地得到纠正，在某些程序中，纠正成本可能增加 100 倍。与前面讨论的 RM 过程密切相关，OWASP 在下面的截图中提出并记录了安全 SDLC（[`www.owasp.org/index.php/Secure_SDLC_Cheat_Sheet`](https://www.owasp.org/index.php/Secure_SDLC_Cheat_Sheet)）[并应该成为标准做法：](https://www.owasp.org/index.php/Secure_SDLC_Cheat_Sheet)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_12_08.png)

OWASP 的安全 SDLC

显然，这需要不仅仅是一份书面政策；它要求有专注于安全的开发人员，或者更好的是渗透测试人员，协助进行。安全 SDLC 可以阐明白盒测试覆盖的程度，并且应该包括任何外部灰盒或黑盒测试*门*，以确保安全性被驱动到应用程序中。

最成熟的流程甚至可以在更大的开发环境中集成连续测试和始终开启的仪表板。我们还应该记住，我们作为潜在的外部顾问使用的工具可能与他们的开发团队或内部渗透测试人员使用的工具不同，而且这几乎总是件好事。

一些公司，如 Veracode（[`www.veracode.com`](http://www.veracode.com)），提供了关于他们如何在其产品工作流程中进行最佳测试的详细信息。在下面的高级方法论截图中，你可以看到他们试图整合培训的各个方面--人员、开发阶段、角色、应用程序的组件等等。虽然这些模板在你的实践早期确实提供了一些价值，但它们绝不是穷尽和强制性的；你可以制定和修改自己的内部流程，而且很可能你的客户也已经这样做了，以保持我们的警惕。关键在于将我们的客户流程与他们部署的工具相匹配。他们会发现，当工具按照开发人员的意图运行时，它们的工具集会更加高效。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_12_09.png)

Veracode 自己的测试生命周期

#### 角色扮演 - 启用团队

在测试和教育客户的过程中，你还有机会指导和分享见解。开发、维护和操作应用程序的员工通常没有接受承担这样负担所需的培训。角色可能也不清晰，我经常遇到一些客户，尽管在环境中运营多年，仍然没有明确的权力分离和责任。这最后一点远远是我遇到的系统效率低下和安全漏洞的最大指标。因此，重要的是你理解今天存在的层次结构，并帮助客户填补这些空白，同时识别需要他们关注的其他领域或学科。

他们对事件的自己的反应是有帮助的，理解这一点很重要。我在帮助客户理解事件或流程可能出现问题的地方时，从**RACI 矩阵**（**负责人**，**负有责任的**，**征询意见的**和**知情的** - [`racichart.org`](http://racichart.org)）中获得了很多收益。我们最关心的是对我们发现的问题进行纠正，但我们可以为任何 IT 流程部署这种技术，以帮助他们理解一般流程和角色。在下面的截图中，我们看到了一个事件响应流程，但业务连续性、灾难恢复、漏洞纠正等许多其他流程也可以使用这种快速而简单的练习来表达：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_12_10.png)

IR 的样本 RACI 矩阵

还需要角色来确保环境内定义和执行适当的管理、审计和用户访问。你将揭示的许多发现可以通过谨慎的**基于角色的访问控制**（**RBAC**）和责任分割来减轻。如果客户的环境尚未实施 RBAC，这应该始终作为你的建议中的最佳实践提供。

#### 挑选一个赢家

我们的每个建议都需要让我们远离模棱两可，否则我们就不应该提供它。这些建议可以来自我们的经验，但我们应该尽可能地加强它们，包括软件组件的创建者、权威人士以及提供同行评审指导的安全分析师的建议。安全研究团队的数量可能令人困惑，但最受尊敬的团队具有全球范围和良好的知名度，有助于引导行业朝着更好的政策和架构发展。一些在遭受侵犯时监视和检查的最佳网站如下：

+   NIST: [`nvd.nist.gov`](https://nvd.nist.gov)

+   MITRE: [`cve.mitre.org`](https://cve.mitre.org)

+   US CERT: [`www.us-cert.gov/ncas`](https://www.us-cert.gov/ncas)

+   Google: [`research.google.com/pubs/SecurityPrivacyandAbusePrevention.html`](https://research.google.com/pubs/SecurityPrivacyandAbusePrevention.html)

+   Dark Reading: [`www.darkreading.com/vulnerabilities-threats.asp`](http://www.darkreading.com/vulnerabilities-threats.asp)

+   ThreatPost: [`threatpost.com/category/web-security/`](https://threatpost.com/category/web-security/)

在向客户提出解决方案时，我们应该尽量明确。特别是在架构变更方面，需要清晰简明的理由和行动计划。您可能会发现您的客户更希望得到更少的建议，而更多的是意识；您应该在一开始就澄清所需的响应。我还建议在适用的情况下，与您的团队一起对报告进行内部同行评审，因为越多的人看最终产品，最终结果就会更好。

### 计划和程序

我们的客户都会因为拥有一个所有人都理解的标准流程而受益匪浅，这个流程不仅可以帮助他们测试和检测漏洞，还可以让他们对漏洞进行优先级排序、解决和记录响应。较小的应用程序组将无法将资源专门用于这个特定的努力，因此，在许多方面，他们需要寻找方法将几个必要但需求资源的过程合并为一个单一的程序。OWASP 通过其名为**全面、轻量级应用安全流程**（**CLASP**，[`www.owasp.org/index.php/CLASP_Concepts`](https://www.owasp.org/index.php/CLASP_Concepts)）的程序来解决这个问题。OWASP 将其设想为*一组以活动驱动、基于角色的流程组件，其核心包含了将安全性规范化地纳入现有或新启动的软件开发生命周期的最佳实践*。

正如下面的截图所示，这个过程是围绕着对公司 SDLC 各个方面的深入视图构建的，并整合了风险管理、变更管理、资源规划和角色分配。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_12_11.png)

OWASP 的漏洞管理 CLASP 框架

OWASP 最近更多地关注了通用指南的制定，而不是规范性的程序，指出更详细和严格的程序可能更难被采纳，并忽视了已经存在的安装程序。CISO 的**应用安全指南**（[`www.owasp.org/index.php/Application_Security_Guide_For_CISOs`](https://www.owasp.org/index.php/Application_Security_Guide_For_CISOs)）是这些努力的成果，它为更注重安全的企业提供了跨人员、流程和技术的指导。除了这些指南，**软件工程研究所的能力成熟度模型**（**SEI CMM**，[`cmmiinstitute.com`](https://www.sei.cmu.edu/cmmi/)）、**构建安全成熟度模型**（**BSIMM**，[`www.bsimm.com`](https://www.bsimm.com)）和**开放软件保障成熟度模型**（**SAMM**，[`www.opensamm.org`](http://www.opensamm.org)）都与新指南兼容，为 CISO 及其应用程序、网络和安全团队提供了自由，以实施这些最佳实践并根据需要吸收这些想法。

#### 更多关于变更管理

**变更管理**（**CM**）是 IT 中任何人都喜欢讨厌的那些流程之一，但它起着至关重要的作用。CM 提供了一个结构，所有对运营或生产环境的变更都必须在其中进行。有了这个流程，理论上所有利益相关者都能意识到变更并适当地权衡。我们都曾处于流程过于松散（导致遗漏）或过于严格（人们试图避开或进展停滞）的情况下。我认为我们都可以同意 CM 是必要的，漏洞修复和违规响应也不例外。也就是说，我们需要确保 CM 流程足够灵活，以便在安全的名义下采取果断行动，同时确保所有受影响的方都已经接受。

#### 自动化和适应

积极的安全策略是我们应该鼓励的，但还没有得到足够客户的认可。这是一个小客户群体的问题。投资于自动化工具集和漏洞修复的组织领先一步，许多商业供应商提供可以自动集成到应用环境中的解决方案集，并提供带有情报源的持续分析。

开源工具在这方面也有帮助，但实际上有几种自动化工具的部署方式：

+   **静态应用安全测试**（**SAST**）通常侧重于 SDLC 的早期阶段，并集中于代码和模块使用，更像是一个白盒测试工具。源代码分析是 SAST 方法中最普遍的，因为它与代码本身紧密相关，这些工具通常集成在开发环境中，有时由同一软件供应商提供。这些工具实际上检查已知漏洞和最佳实践的代码，标记出问题的代码片段。再次，像 IBM、HPE 和 Veracode 这样的重量级公司有助于更早地发现问题，从而使修复更便宜更快。可以在[`www.owasp.org/index.php/Source_Code_Analysis_Tools`](https://www.owasp.org/index.php/Source_Code_Analysis_Tools)找到一个很好的列表。

+   **动态应用程序安全测试**（**DAST**）侧重于 SDLC 的后期阶段，在这个阶段，一个接近代表性的应用程序已经建立起来，可以像我们用 Arachni 进行黑盒测试一样进行探测和评估。这些工具，就像我们基于 Kali 的套件的大部分工具一样，工作在应用程序的边缘，扫描、枚举和操纵请求和响应来诊断问题。因此，这些工具没有像 SAST 那样有捕捉的潜力，但它们更好地模拟了外部威胁。我们已经使用了一些这样的工具；Tenable 和 Rapid7 似乎是市场领导者，但在[`www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools`](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools)上列出了一些其他选项。

+   **交互式应用程序安全测试**（**IAST**）是竞技场上的一个相对新手，它使用应用程序中的代理来帮助实时识别漏洞。工具的独特定位使其能够在一个套件中解决 SAST 和 DAST 所做的大部分事情。DAST 和 SAST 在使用时通常一起使用，以确保揭示两个方面的缺陷，而 IAST 已经在做到这一点。许多已经建立起来的 SAST/DAST 供应商正在进入这个市场，或者迅速迁移他们的解决方案以提供这种能力，同时试图最小化运行这些代理所隐含的性能影响。

+   **移动应用程序安全测试**（**MAST**）类似于移动设备的 IAST，代理分布在一些或所有移动客户端中，以帮助提供遥测。

+   **运行时应用程序安全保护**（**RASP**）也类似于 IAST，只是代理实际上充当实时分布式执行点，帮助实时修复或补丁被侵犯的系统。这项技术非常新颖，人们对它们是否总体上是一件好事还有疑虑，或者它们是否会造成一种虚假的安全感。像 HPE、Whitehat Security、Veracode 和 IBM 这样的老牌公司在这里提供服务，但新公司如 Immunio 和 Contrast 也在这一领域崭露头角。

我们的测试不应该对这些工具视而不见，而应该补充它们，并在正确实施两种工具集时验证它们的有效性。一些供应商甚至正在扩展到与环境中的其他元素自动化，像 Imperva 这样的公司现在宣称他们的**Web 应用程序过滤**（**WAF**）产品可以与漏洞扫描器实时工作，阻止威胁。

## 评估竞争

* * *

我们讨论过的许多 DAST 工具都可以挑战我们在 Kali 中使用的工具（如 Arachni、Nikto、Burp、ZAP 等），用于我们首选的渗透测试工具包。我假设每个阅读本书的人都习惯于根据自己最喜欢的工作方式做出自己的选择，因此除了所有的工具选项之外，我认为讨论一些备选操作系统和工具套件可能会有所帮助，这样你在回到 Kali 之前可能会想要评估一下。毕竟，看到我们拥有多么好的东西总是很好的。

### Backbox Linux

Backbox ([`backbox.org/linux`](https://backbox.org/linux)，如下图所示)是一个基于 Ubuntu 的渗透测试和安全发行版，来自一些意大利人，可能比 Kali 更容易使用，作为一个带有安全倾向的通用桌面。它包括许多相同的工具，因此真正的问题在于你是更喜欢 Kali 的 Debian/XFCE 外观和感觉，还是 Backbox 更加精致的 Ubuntu 布局。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_12_12.png)

Backbox Linux 主屏幕

### 武士网页测试框架

武士 WFT，如所知（如下图所示，[`samurai.inguardians.com`](http://samurai.inguardians.com)）是基于 Ubuntu Linux 的 Live-CD 版本，专注于他们的四阶段方法（侦察，映射，发现和利用）对 Web 应用程序进行渗透测试。其他功能被搁置，他们将整个过程编织到他们内置的维基中，这在很大程度上就像他们的 Dradis 替身。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_12_13.png)

武士 WTF 菜单

### Fedora Security Spin

在渗透测试领域，很多关注都集中在 Ubuntu/Debian 的 Linux 分支上，这可能是因为它们是最广泛使用的桌面 Linux 发行版。这并不意味着你不能使用一些经典的 Red Hat/Fedora 的东西！Fedora Security Lab 是 Fedora 的一个 Spin（定制分支），它融合了我们在 Kali 中喜爱和珍视的许多工具，但是在基于 RPM 的世界中重新编译和管理。如果 Red Hat、Centos 或 Fedora 是你的菜，你可以轻松地在 Fedora Security Spin 上运行起来（[`labs.fedoraproject.org/en/security/`](https://labs.fedoraproject.org/en/security/)，如下所示）。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-web-pentest/img/B03918_12_14.png)

Fedora Security Spin/Lab

### 其他 Linux 渗透测试发行版

如果前面的选项不符合您的需求，还有许多其他选择。以下是一个小列表：

+   Knoppix-STD: [`s-t-d.org`](https://s-t-d.org)

+   Bugtraq: [`archiveos.org/bugtraq/`](https://archiveos.org/bugtraq/)

+   Weakerth4n: [`www.weaknetlabs.com`](http://www.weaknetlabs.com)

+   CAINE: [`www.caine-live.net`](http://www.caine-live.net)

### Windows 和 macOS 怎么样？

嗯，这本书主要讲的是使用 Kali 进行 Web 应用程序渗透测试，但是如果我不提到 Windows 和 macOS 平台都能够运行我们讨论过的许多工具，或者运行类似的工具，那就不够完整了。Burp Suite，Metasploit，Arachni 等等，都有适用于这两个平台的版本，标准工具如 Nmap 和 Nikto 也是如此。简而言之，如果你实在无法忍受运行 Linux，或者需要临时解决方案，这些操作系统也可以。不过，不要指望在 Defcon 或 Blackhat 会议上受到太多关注，因为他们往往是纯粹主义者。

## 总结

* * *

Web 应用程序渗透测试是深入、复杂且不断变化的。另一方面，它对于部署 Web 应用程序的所有企业（也就是所有企业）来说也是至关重要且具有很高的价值。正是因为这些原因，我们必须准备好帮助我们的客户解决其应用程序的安全性问题，避免成为头条新闻。记住，我们不仅要测试平台，而且我们经常是其他应用程序的客户，我希望我使用的 Web 应用程序经过了严格的测试，并且发现得到了适当的处理。

在本章中，我们从测试本身退后一步，讨论了如何呈现发现结果，使我们的客户更接近那个最高贵的目标，即*安全*。我们看到，不仅我们的报告和沟通可以帮助，而且建立一个明确定义*那么，现在发生了什么？*的安全程序和流程也可以帮助。通过做好我们的工作，我们可以帮助避免困扰当今社会的侵犯和妥协。世界上没有人能够逃脱潜在的危害，所以我们有责任产生影响，当涉及到保护时。

不用说，但是您在本书中学到的工具和技术以及您的持续练习有两种截然相反的用途。我们需要确保我们使用我们的技能和资源来改善我们客户的环境，而不是为了造成伤害或恶意攻击。权限和意图都应该清晰、明确并有记录。

我真的很享受与你们一起阅读这本书的过程——这是一次美妙的学习经历，我们从进行一般的渗透测试到深入研究 Web 应用程序学科。正如我们所看到的，这是一项值得的和高尚的事业，我希望这本书能帮助你们提高甚至掌握可以使用的技能。如果有什么，我希望你们都对学习和掌握更多知识充满好奇，并且积极行动，成为你们领域的倡导者。祝你们愉快地黑客，好运！
