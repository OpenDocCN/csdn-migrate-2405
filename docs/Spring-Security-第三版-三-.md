# Spring Security 第三版（三）

> 原文：[`zh.annas-archive.org/md5/3E3DF87F330D174DBAF9E13DAE6DC0C5`](https://zh.annas-archive.org/md5/3E3DF87F330D174DBAF9E13DAE6DC0C5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 TLS 的客户端证书认证

尽管用户名和密码认证极其普遍，正如我们在第一章《不安全应用程序的剖析》和第二章《Spring Security 入门》中讨论的，存在允许用户呈现不同类型凭证的认证形式。Spring Security 也迎合了这些要求。在本章中，我们将超越基于表单的认证，探索使用可信客户端证书的认证。

在本章的进程中，我们将涵盖以下主题：

+   学习客户端证书认证是如何在用户的浏览器和符合要求的服器之间进行协商的。

+   配置 Spring Security 以使用客户端证书认证用户

+   了解 Spring Security 中客户端证书认证的架构

+   探索与客户端证书认证相关的高级配置选项

+   回顾客户端证书认证的优点、缺点和常见故障排除步骤

# 客户端证书认证是如何工作的？

客户端证书认证需要服务器请求信息以及浏览器响应，以协商客户端（即用户的浏览器）与服务器应用程序之间的可信认证关系。这种信任关系是通过使用可信和可验证凭据的交换建立起来的，这些凭据被称为**证书**。

与我们迄今为止所看到的大部分内容不同，在客户端证书认证中，Servlet 容器或应用服务器本身通常负责通过请求证书、评估它并接受它作为有效认证来协商浏览器与服务器之间的信任关系。

客户端证书认证也被称为**相互认证**，是**安全套接层**（**SSL**）协议及其继承者**传输层安全**（**TLS**）协议的一部分。由于相互认证是 SSL 和 TLS 协议的一部分，因此需要一个 HTTPS 连接（使用 SSL 或 TLS 加密）才能使用客户端证书认证。有关 Spring Security 中 SSL/TLS 支持的详细信息，请参阅我们在附录*附加参考资料*中的讨论和 SSL/TLS 的实现。在 Tomcat（或您一直用来跟随示例的应用服务器）中设置 SSL/TLS 是实现客户端证书认证的必要条件。与附录*附加参考资料*中的内容一样，在本章剩余部分我们将 SSL/TLS 简称为 SSL。

下面的序列图说明了客户端浏览器与 Web 服务器协商 SSL 连接并验证用于相互认证的客户端证书的信任时的交互：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/0ddcd0e7-34ef-4a68-b891-1191cd9d6418.png)

我们可以看到，两个证书（服务器和客户端证书）的交换为双方提供了认证，证明双方是已知的并且可以被信任继续安全地对话。为了清晰起见，我们省略了 SSL 握手的一些细节和证书本身的检查；然而，我们鼓励你进一步阅读有关 SSL 和 TLS 协议以及证书的一般内容，因为这些主题有很多很好的参考指南。关于客户端证书展示，可以阅读*RFC 5246*，*传输层安全（TLS）协议版本 1.2*（[`tools.ietf.org/html/rfc5246`](http://tools.ietf.org/html/rfc5246)），如果你想要了解更多细节，*SL 和 TLS：设计和管理安全系统，Eric Rescorla，Addison-Wesley*（[`www.amazon.com/SSL-TLS-Designing-Building-Systems/dp/0201615983`](https://www.amazon.com/SSL-TLS-Designing-Building-Systems/dp/0201615983)）对协议及其实现有非常详细的回顾。

客户端证书认证的另一个名称是 X.509 认证。术语 X.509 来源于 ITU-T 组织最初发布的 X.509 标准，用于基于 X.500 标准的目录（你可能还记得第六章，*LDAP 目录服务*中提到的 LDAP 的起源）。后来，这个标准被修改用于保护互联网通信。

我们在这里提到这一点是因为 Spring Security 中与这个问题相关的许多类都提到了 X.509。记住 X.509 本身并没有定义相互认证协议，而是定义了证书的格式和结构以及包括受信任的证书颁发机构在内的内容。

# 设置客户端证书认证基础架构

遗憾的是，对于你这样的个人开发者来说，能够实验性地使用客户端证书认证需要一些复杂的配置和设置，这在前期的集成中相对容易与 Spring Security 结合。由于这些设置步骤经常给第一次开发者带来很多问题，所以我们觉得带你走过这些步骤是很重要的。

我们假设你正在使用一个本地的、自签名的服务器证书、自签名的客户端证书和 Apache Tomcat。这符合大多数开发环境；然而，你可能有访问有效的服务器证书、证书颁发机构（CA）或其他应用服务器的权限。如果是这种情况，你可以将这些设置说明作为指导，并类似地配置你的环境。请参考附录中的 SSL 设置说明，*附加参考材料*，以获得在独立环境中配置 Tomcat 和 Spring Security 以使用 SSL 的帮助。

# 理解公钥基础设施的目的

本章主要关注于设置一个自包含的开发环境，用于学习和教育目的。然而，在大多数情况下，当你将 Spring Security 集成到现有的基于客户端证书的安全环境中时，将会有大量的基础设施（通常是硬件和软件的组合）已经到位，以提供诸如证书发放和管理、用户自我服务以及吊销等功能。这种类型的环境定义了一个公钥基础设施——硬件、软件和安全策略的组合，结果是一个高度安全的以认证为驱动的网络生态系统。

除了用于 Web 应用程序认证之外，这些环境中的证书或硬件设备还可以用于安全的、不可撤回的电子邮件（使用 S/MIME）、网络认证，甚至物理建筑访问（使用基于 PKCS 11 的硬件设备）。

尽管这种环境的运维开销可能很高（并且需要 IT 和流程卓越才能实施良好），但可以说这是技术专业人员可能使用的最安全的运行环境之一。

# 创建客户端证书密钥对

自签名客户端证书的创建方式与自签名服务器证书的创建方式相同——通过使用`keytool`命令生成密钥对。客户端证书密钥对的区别在于，它需要密钥库对浏览器可用，并需要将客户端的公钥加载到服务器的信任库中（我们稍后会解释这是什么）。

如果你现在不想生成自己的密钥，你可以跳到下一节，并使用示例章节中的`./src/main/resources/keys`文件夹中的示例证书。否则，按照如下方式创建客户端密钥对：

```java
keytool -genkeypair -alias jbcpclient -keyalg RSA -validity 365 -keystore jbcp_clientauth.p12 -storetype PKCS12
```

你可以在 Oracle 的网站上找到关于`keytool`的额外信息，以及所有的配置选项，链接在这里 [`docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html/keytool.html`](http://docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html/keytool.html)。

`keytool`的大部分参数对于这个用例来说是相当任意的。然而，当提示设置客户端证书的第一个和最后一个名字（所有者的 DN 的部分，即 common name）时，请确保第一个提示的答案与我们在 Spring Security JDBC 存储中设置的用户相匹配。例如，`admin1@example.com`是一个合适的值，因为我们已经在 Spring Security 中设置了`admin1@example.com`用户。命令行交互的示例如下：

```java
What is your first and last name?
[Unknown]: admin1@example.com
... etc
Is CN=admin1@example.com, OU=JBCP Calendar, O=JBCP, L=Park City, ST=UT, C=US correct?
[no]: yes
```

我们将看到为什么这是重要的，当我们配置 Spring Security 以从证书认证的用户那里获取信息。在我们可以在 Tomcat 中设置证书认证之前，还有最后一个步骤，将在下一节中解释。

# 配置 Tomcat 信任库

回想一下，密钥对定义包括一个私钥和一个公钥。就像 SSL 证书验证并确保服务器通信的有效性一样，客户端证书的有效性需要由创建它的认证机构来验证。

因为我们已经使用`keytool`命令创建了自己的自签名客户端证书，Java 虚拟机不会默认信任它，因为它并非由可信的证书机构分配。

让我们来看看以下步骤：

1.  我们需要迫使 Tomcat 识别证书为可信证书。我们通过导出密钥对的公钥并将其添加到 Tomcat 信任库来实现。

1.  如果你现在不想执行这一步，你可以使用`.src/main/resources/keys`中的现有信任库，并跳到本节后面的`server.xml`配置部分。

1.  我们将公钥导出到一个名为`jbcp_clientauth.cer`的标准证书文件中，如下所示：

```java
 keytool -exportcert -alias jbcpclient -keystore jbcp_clientauth.p12 
      -storetype PKCS12 -storepass changeit -file jbcp_clientauth.cer
```

1.  接下来，我们将把证书导入信任库（这将创建信任库，但在典型的部署场景中，你可能已经在信任库中有一些其他证书）：

```java
 keytool -importcert -alias jbcpclient -keystore tomcat.truststore 
      -file jbcp_clientauth.cer
```

前面的命令将创建一个名为`tomcat.truststore`的信任库，并提示你输入密码（我们选择了密码`changeit`）。你还将看到一些关于证书的信息，并最终被要求确认你是否信任该证书，如下所示：

```java
 Owner: CN=admin1@example.com, OU=JBCP Calendar, O=JBCP, L=Park City,
      ST=UT, C=US Issuer: CN=admin1@example.com, OU=JBCP Calendar, O=JBCP, L=Park City,
      ST=UT, C=US Serial number: 464fc10c Valid from: Fri Jun 23 11:10:19 MDT 2017 until: Thu Feb 12 10:10:19 
      MST 2043      //Certificate fingerprints:

 MD5: 8D:27:CE:F7:8B:C3:BD:BD:64:D6:F5:24:D8:A1:8B:50 SHA1: C1:51:4A:47:EC:9D:01:5A:28:BB:59:F5:FC:10:87:EA:68:24:E3:1F SHA256: 2C:F6:2F:29:ED:09:48:FD:FE:A5:83:67:E0:A0:B9:DA:C5:3B:
      FD:CF:4F:95:50:3A:
      2C:B8:2B:BD:81:48:BB:EF Signature algorithm name: SHA256withRSA Version: 3      //Extensions

 #1: ObjectId: 2.5.29.14 Criticality=false
 SubjectKeyIdentifier [
 KeyIdentifier [
 0000: 29 F3 A7 A1 8F D2 87 4B   EA 74 AC 8A 4B BC 4B 5D 
      )......K.t..K.K]
 0010: 7C 9B 44 4A                                       ..DJ
 ]
 ]
 Trust this certificate? [no]: yes
```

记住新`tomcat.truststore`文件的位置，因为我们将需要在 Tomcat 配置中引用它。

密钥库和信任库之间有什么区别？

**Java 安全套接字扩展**（**JSSE**）文档将密钥库定义为私钥及其对应公钥的存储机制。密钥库（包含密钥对）用于加密或解密安全消息等。信任库旨在存储验证身份时信任的通信伙伴的公钥（与证书认证中使用的信任库类似）。然而，在许多常见的管理场景中，密钥库和信任库被合并为单个文件（在 Tomcat 中，这可以通过使用连接器的`keystoreFile`和`truststoreFile`属性来实现）。这些文件本身的格式可以完全相同。实际上，每个文件可以是任何 JSSE 支持的密钥库格式，包括**Java 密钥库**（**JKS**）、PKCS 12 等。

1.  如前所述，我们假设您已经配置了 SSL 连接器，如附录*附加参考材料*中所概述。如果您在`server.xml`中看不到`keystoreFile`或`keystorePass`属性，这意味着您应该访问附录*附加参考材料*来设置 SSL。

1.  最后，我们需要将 Tomcat 指向信任库并启用客户端证书认证。这通过在 Tomcat `server.xml`文件中的 SSL 连接器添加三个附加属性来完成，如下所示：

```java
//sever.xml

<Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true"
maxThreads="150" scheme="https" secure="true"
sslProtocol="TLS"
keystoreFile="<KEYSTORE_PATH>/tomcat.keystore"
keystorePass="changeit"
truststoreFile="<CERT_PATH>/tomcat.truststore"
truststorePass="changeit"
clientAuth="true"
/>
```

`server.xml`文件可以在`TOMCAT_HOME/conf/server.xml`找到。如果你使用 Eclipse 或 Spring Tool Suite 与 Tomcat 交互，你会找到一个名为`Servers`的项目，包含`server.xml`。例如，如果你使用的是 Tomcat 8，你 Eclipse 工作区中的路径可能类似于`/Servers/Tomcat v7.0 Server`在`localhost-config/server.xml`。

1.  这应该是触发 Tomcat 在建立 SSL 连接时请求客户端证书的剩余配置。当然，你希望确保你用完整的路径替换了`<CERT_PATH>`和`<KEYSTORE_PATH>`。例如，在基于 Unix 的操作系统上，路径可能看起来像这样：`/home/mickknutson/packt/chapter8/keys/tomcat.keystore`。

1.  大胆尝试启动 Tomcat，确保服务器在日志中没有错误地启动。

还有方法可以配置 Tomcat，使其可选地使用客户端证书认证——我们将在本章后面启用这个功能。现在，我们要求使用客户端证书才能甚至连接到 Tomcat 服务器。这使得诊断你是否正确设置了这一点变得更容易！

# 在 Spring Boot 中配置 Tomcat

我们还可以配置 Spring Boot 中的内嵌 Tomcat 实例，这是我们本章剩余时间将如何与 Tomcat 工作的方式。

配置 Spring Boot 使用我们新创建的证书，就像 YAML 条目的属性一样简单，如下面的代码片段所示：

```java
    server:
    port: 8443
    ssl:
       key-store: "classpath:keys/jbcp_clientauth.p12"
       key-store-password: changeit
       keyStoreType: PKCS12
       keyAlias: jbcpclient
       protocol: TLS
```

最后一步是将证书导入客户端浏览器。

# 将证书密钥对导入浏览器

根据你使用的浏览器，导入证书的过程可能会有所不同。我们将为 Firefox、Chrome 和 Internet Explorer 的安装提供说明，但如果您使用的是其他浏览器，请查阅其帮助部分或您最喜欢的搜索引擎以获得帮助。

# 使用 Firefox

执行以下步骤，在 Firefox 中导入包含客户端证书密钥对的密钥库：

1.  点击编辑|首选项。

1.  点击高级按钮。

1.  点击加密标签。

1.  点击查看证书按钮。证书管理器窗口应该打开。

1.  点击您的证书标签。

1.  点击导入...按钮。

1.  浏览到你保存`jbcp_clientauth.p12`文件的位置并选择它。你将需要输入你创建文件时使用的密码（即`changeit`）。

客户端证书应该被导入，你会在列表上看到它。

# 使用 Chrome

执行以下步骤，在 Chrome 中导入包含客户端证书密钥对的密钥库：

1.  点击浏览器工具栏上的扳手图标。

1.  选择设置。

1.  点击显示高级设置...。

1.  在 HTTPS/SSL 部分，点击管理证书...按钮。

1.  在您的证书标签中，点击导入...按钮。

1.  浏览到您保存`jbcp_clientauth.p12`文件的位置并选择它。

1.  您需要输入创建文件时使用的密码（即`changeit`）。

1.  点击确定。

# 使用 Internet Explorer

由于 Internet Explorer 与 Windows 操作系统紧密集成，因此导入密钥库稍微容易一些。让我们来看看以下步骤：

1.  在 Windows 资源管理器中双击`jbcp_clientauth.p12`文件。证书导入向导窗口应该会打开。

1.  点击下一步，接受默认值，直到您需要输入证书密码为止。

1.  输入证书密码（即`changeit`）并点击下一步。

1.  接受默认的自动选择证书存储选项并点击下一步。

1.  点击完成。

为了验证证书是否正确安装，您需要执行另一系列步骤：

1.  在 Internet Explorer 中打开工具菜单 (*Alt* + *X*)。

1.  点击互联网选项菜单项。

1.  点击内容标签。

1.  点击证书按钮。

1.  如果还没有选择，点击个人标签。您应该在这里看到证书列表。

# 完成测试

现在，您应该能够使用客户端证书连接到 JBCP 日历网站。导航到`https://localhost:8443/`，注意使用 HTTPS 和`8443`。如果一切设置正确，当您尝试访问网站时，应该会提示您输入证书——在 Firefox 中，证书显示如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/258c434d-cf14-459d-9507-fabe1c485e7c.png)

然而，您会发现，如果您尝试访问网站的保护区域，例如我的活动部分，您会被重定向到登录页面。这是因为我们还没有配置 Spring Security 来识别证书中的信息——在这个阶段，客户端和服务器之间的协商已经在 Tomcat 服务器本身停止了。

您应该从`chapter08.00-calendar`开始编写代码。

# 解决客户端证书认证问题

不幸的是，如果我们说第一次正确配置客户端证书认证很容易，没有出错，那就是在骗您。事实是，尽管这是一个非常强大且优秀的的安全装置，但浏览器和 web 服务器制造商的文档都很差，而且当出现错误信息时，充其量是令人困惑，最差的情况是具有误导性。

请记住，到目前为止，我们根本没有让 Spring Security 参与进来，所以调试器很可能帮不了您（除非您手头有 Tomcat 源代码）。有一些常见的错误和需要检查的事情。

当您访问网站时，没有提示您输入证书。这可能有多种可能的原因，这也是最难解决的问题之一。以下是一些需要检查的内容：

1.  确保证书已安装在您正在使用的浏览器客户端中。有时，如果您之前尝试访问该网站并被拒绝，您可能需要重启整个浏览器（关闭所有窗口）。

1.  确保你正在访问服务器的 SSL 端口（在开发环境中通常是`8443`），并且在你的 URL 中选择了 HTTPS 协议。在不安全的浏览器连接中不会呈现客户端证书。确保浏览器也信任服务器的 SSL 证书，即使你不得不强制它信任自签名的证书。

1.  确保您已在您的 Tomcat 配置中添加了`clientAuth`指令（或您正在使用的任何应用程序服务器的等效配置）。

1.  如果其他方法都失败了，请使用网络分析器或包嗅探器，如 Wireshark ([`www.wireshark.org/`](http://www.wireshark.org/)) 或 Fiddler2 ([`www.fiddler2.com/`](http://www.fiddler2.com/))，以查看通过网络的流量和 SSL 密钥交换（首先与您的 IT 部门确认-许多公司不允许在他们的网络上使用这类工具）。

1.  如果您使用的是自签名的客户端证书，请确保公钥已导入服务器的信任存储中。如果您使用的是 CA 分配的证书，请确保 CA 被 JVM 信任，或者 CA 证书已导入服务器的信任存储中。

1.  特别是，Internet Explorer 根本不报告客户端证书失败的详细信息（它只报告一个通用的“页面无法显示”错误）。如果您看到的问题可能与客户端证书有关，请使用 Firefox 进行诊断。

# 在 Spring Security 中配置客户端证书认证

与迄今为止我们使用的认证机制不同，使用客户端证书认证会导致服务端预先对用户的请求进行认证。由于服务器（Tomcat）已经确认用户提供了有效且可信赖的证书，Spring Security 可以简单地信任这一有效性的断言。

安全登录过程中的一个重要组件仍然缺失，那就是认证用户的授权。这就是我们的 Spring Security 配置发挥作用的地方-我们必须向 Spring Security 添加一个组件，该组件将识别用户 HTTP 会话（由 Tomcat 填充）中的证书认证信息，然后将呈现的凭据与 Spring Security `UserDetailsService`的调用进行验证。`UserDetailsService`的调用将导致确定证书中声明的用户是否对 Spring Security 已知，然后根据通常的登录规则分配`GrantedAuthority`。

# 使用安全命名空间配置客户端证书认证

尽管 LDAP 配置的复杂性令人望而却步，但配置客户端证书认证却是一种受欢迎的解脱。如果我们使用安全命名空间配置方式，在`HttpSecurity`声明中添加客户端证书认证只需简单的一行配置更改。接着，你可以对提供的`SecurityConfig.java`配置文件进行以下修改：

```java
//src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java
    http.x509().userDetailsService(userDetailsService);
```

请注意`.x509()`方法引用了我们现有的`userDetailsService()`配置。为了简单起见，我们使用了在第五章中介绍的`UserDetailsServiceImpl`实现，关于*使用 Spring Data 进行认证*。然而，我们很容易用其他任何实现来替换它（即在第四章中介绍的基于 LDAP 或 JDBC 的实现，关于*基于 JDBC 的认证*）。

重启应用程序后，系统会再次提示您提供客户端证书，但这次，您应该能够访问需要授权的网站区域。如果您启用了日志（如果有），从日志中可以看到您已以`admin1@example.com`用户身份登录。

你的代码应该看起来像`chapter08.01-calendar`。

# **Spring Security**是如何使用证书信息的？

如前所述，Spring Security 在证书交换中的作用是提取 presented certificate 中的信息，并将用户的凭据映射到用户服务。我们在使用`.x509()`方法时没有看到使其成为可能的精灵。回想一下，当我们设置客户端证书时，与证书关联的类似 LDAP DN 的 DN 如下所示：

```java
    Owner: CN=admin@example.com, OU=JBCP Calendar, O=JBCP, L=Park City, ST=UT, C=US
```

Spring Security 使用 DN 中的信息来确定主体的实际用户名，并将在`UserDetailsService`中查找此信息。特别是，它允许指定一个正则表达式，用于匹配与证书建立的 DN 的一部分，并使用这部分 DN 作为主体名称。`.x509()`方法的隐式默认配置如下：

```java
  http.x509()
   .userDetailsService(userDetailsService)
 .subjectPrincipalRegex("CN=(.*?),");
```

我们可以看到，这个正则表达式会将`admin1@example.com`值作为主体名称匹配。这个正则表达式必须包含一个匹配组，但可以配置以支持您应用程序的用户名和 DN 发行需求。例如，如果您组织证书的 DN 包括`email`或`userid`字段，正则表达式可以修改为使用这些值作为认证主体的名称。

# **Spring Security**客户端证书认证是如何工作的

让我们通过以下图表回顾一下涉及客户端证书评审和评估的各种参与者，以及将之转化为 Spring Security 认证会话的过程：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/3aab8775-aafc-4781-891a-8e2680fc0d53.png)

我们可以看到`o.s.s.web.authentication.preauth.x509.X509AuthenticationFilter`负责检查未经认证用户的请求以查看是否提交了客户端证书。如果它看到请求包括有效的客户端证书，它将使用`o.s.s.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor`提取主题，使用与证书所有者 DN 匹配的正则表达式，如前所述。

请注意，尽管前面的图表显示未经认证的用户会检查证书，但在呈现的证书标识的用户与先前认证的用户不同时，也会执行检查。这将导致使用新提供的凭据发起新的认证请求。这个原因应该很清楚-任何时候用户呈现一组新的凭据，应用程序都必须意识到这一点，并负责任地做出反应，确保用户仍然能够访问它。

一旦证书被接受（或被拒绝/忽略），与其他认证机制一样，将构建一个`Authentication`令牌并传递给`AuthenticationManager`进行认证。现在我们可以回顾一下`o.s.s.web.authentication.preauth.PreAuthenticatedAuthenticationProvider`处理认证令牌的非常简短的说明：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/0703ce2b-53ab-47d8-870d-00788fe453ea.png)

虽然我们不会详细介绍它们，但 Spring Security 支持许多其他预认证机制。一些例子包括 Java EE 角色映射（`J2eePreAuthenticatedProcessingFilter`），WebSphere 集成（`WebSpherePreAuthenticatedProcessingFilter`）和 Site Minder 风格认证（`RequestHeaderAuthenticationFilter`）。如果你理解了客户端证书认证的流程，理解这些其他认证类型要容易得多。

# 处理未经认证请求的`AuthenticationEntryPoint`

由于`X509AuthenticationFilter`如果在认证失败将继续处理请求，我们需要处理用户未能成功认证并请求受保护资源的情况。Spring Security 允许开发人员通过插入自定义`o.s.s.web.AuthenticationEntryPoint`实现来定制这种情况。在默认的表单登录场景中，`LoginUrlAuthenticationEntryPoint`用于将用户重定向到登录页面，如果他们被拒绝访问受保护的资源且未经认证。

相比之下，在典型的客户端证书认证环境中，其他认证方法根本不被支持（记住 Tomcat 在任何 Spring Security 表单登录发生之前都会期望证书）。因此，保留重定向到表单登录页面的默认行为是没有意义的。相反，我们将修改入口点，简单地返回一个`HTTP 403 Forbidden`消息，使用`o.s.s.web.authentication.Http403ForbiddenEntryPoint`。在你的`SecurityConfig.java`文件中，进行以下更新：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Autowired
 private Http403ForbiddenEntryPoint forbiddenEntryPoint;    http.exceptionHandling()
 .authenticationEntryPoint(forbiddenEntryPoint)       .accessDeniedPage("/errors/403");
    ...
    @Bean
    public Http403ForbiddenEntryPoint forbiddenEntryPoint(){
       return new Http403ForbiddenEntryPoint();
    }
```

现在，如果一个用户尝试访问一个受保护的资源并且无法提供有效的证书，他们将看到以下页面，而不是被重定向到登录页面：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/27b77e5f-5478-4833-aa29-439e54efd47c.png)

你的代码现在应该看起来像`chapter08.02-calendar`。

其他常见于客户端证书认证的配置或应用程序流程调整如下：

+   彻底移除基于表单的登录页面。

+   移除登出链接（因为浏览器总是会提交用户的证书，所以没有登出的理由）。

+   移除重命名用户账户和更改密码的功能。

+   移除用户注册功能（除非你能够将其与发放新证书相关联）。

# 支持双模式认证。

也有可能一些环境同时支持基于证书和基于表单的认证。如果你们环境是这样的，用 Spring Security 支持它是可能的（并且很简单）。我们只需保留默认的`AuthenticationEntryPoint`接口（重定向到基于表单的登录页面）不变，如果用户没有提供客户端证书，就允许用户使用标准的登录表单登录。

如果你选择以这种方式配置你的应用程序，你将需要调整 Tomcat 的 SSL 设置（根据你的应用程序服务器适当更改）。将`clientAuth`指令更改为`want`，而不是`true`：

```java
   <Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true"
       maxThreads="150" scheme="https" secure="true"
       sslProtocol="TLS"
       keystoreFile="conf/tomcat.keystore"
       keystorePass="password"
       truststoreFile="conf/tomcat.truststore"
       truststorePass="password"
       clientAuth="want"
       />
```

我们还需要移除上一次练习中我们配置的`authenticationEntryPoint()`方法，这样如果用户在浏览器首次查询时无法提供有效的证书，标准的基于表单的认证工作流程就会接管。

虽然这样做很方便，但是关于双模式（基于表单和基于证书）认证还有几件事情需要记住，如下：

+   大多数浏览器如果一次证书认证失败，将不会重新提示用户输入证书，所以要确保你的用户知道他们可能需要重新进入浏览器以再次提交他们的证书。

+   回想一下，使用证书认证用户时不需要密码；然而，如果您仍在使用`UserDetailsService`来支持您的表单认证用户，这可能就是您用来向`PreAuthenticatedAuthenticationProvider`提供关于您用户信息的同一个`UserDetailsService`对象。这可能带来潜在的安全风险，因为您打算仅使用证书登录的用户可能会潜在地使用表单登录凭据进行认证。

解决此问题有几种方法，它们如下列所示：

+   确保使用证书进行身份验证的用户在您的用户存储中有适当强度的密码。

+   考虑自定义您的用户存储，以清楚地标识出可以使用表单登录的用户。这可以通过在持有用户账户信息的表中添加一个额外字段来跟踪，并对`JpaDaoImpl`对象使用的 SQL 查询进行少量调整。

+   为使用证书认证的用户配置一个单独的用户详细信息存储，以完全将他们与可以使用表单登录的用户隔离开来。

+   双重认证模式可以成为您网站的强大补充，并且可以有效地和安全地部署，前提是您要牢记在哪些情况下用户将被授予访问权限。

# 使用 Spring Bean 配置客户端证书认证

在本章的早些时候，我们回顾了参与客户端证书认证的类的流程。因此，使用显式 Bean 配置 JBCP 日历对我们来说应该是直接的。通过使用显式配置，我们将有更多的配置选项可供使用。让我们看看如何使用显式配置：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Bean
    public X509AuthenticationFilter x509Filter(AuthenticationManager  
    authenticationManager){
       return new X509AuthenticationFilter(){{
           setAuthenticationManager(authenticationManager);
       }};
    }
   @Bean
    public PreAuthenticatedAuthenticationProvider    
    preauthAuthenticationProvider(AuthenticationUserDetailsService   
    authenticationUserDetailsService){
       return new PreAuthenticatedAuthenticationProvider(){{
         setPreAuthenticatedUserDetailsService(authenticationUserDetailsService);
       }};
    }
    @Bean
    public UserDetailsByNameServiceWrapper   
    authenticationUserDetailsService(UserDetailsService userDetailsService){
       return new UserDetailsByNameServiceWrapper(){{
           setUserDetailsService(userDetailsService);
       }};
    }
```

我们还需要删除`x509()`方法，将`x509Filter`添加到我们的过滤器链中，并将我们的`AuthenticationProvider`实现添加到`AuthenticationManger`中：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Override
    protected void configure(HttpSecurity http) throws Exception {
       http.x509()
 //.userDetailsService(userDetailsService)           .x509AuthenticationFilter(x509Filter());
    ...
    }
    @Override
    public void configure(AuthenticationManagerBuilder auth)
    throws Exception {
       auth
 .authenticationProvider(preAuthAuthenticationProvider)         .userDetailsService(userDetailsService)
         .passwordEncoder(passwordEncoder());
    }
```

现在，尝试一下应用程序。从用户的角度来看，并没有发生太多变化，但作为开发者，我们已经为许多额外的配置选项打开了大门。

您的代码现在应该看起来像`chapter08.03-calendar`。

# 基于 Bean 配置的其他功能

使用基于 Spring Bean 的配置提供了通过暴露未通过安全命名空间样式配置的 bean 属性而获得的其他功能。

`X509AuthenticationFilter`上可用的额外属性如下：

| **属性** | **描述** | **默认值** |
| --- | --- | --- |
| `continueFilterChainOnUnsuccessfulAuthentication` | 如果为 false，失败的认证将抛出异常，而不是允许请求继续。这通常会在预期并且需要有效证书才能访问受保护的站点时设置。如果为 true，即使认证失败，过滤器链也将继续。 | `true` |
| `checkForPrincipalChanges` | 如果为真，过滤器将检查当前认证的用户名是否与客户端证书中呈现的用户名不同。如果是这样，将执行新的证书的认证，并使 HTTP 会话无效（可选，参见下一个属性）。如果为假，一旦用户认证成功，他们即使提供不同的凭据也将保持认证状态。 | `false` |
| `invalidateSessionOn PrincipalChange` | 如果为真，且请求中的主体发生变化，将在重新认证之前使用户的 HTTP 会话无效。如果为假，会话将保持不变——请注意这可能引入安全风险。 | `true` |

`PreAuthenticatedAuthenticationProvider`实现有几个有趣的属性可供我们使用，如下表所示：

| **属性** | **描述** | **默认值** |
| --- | --- | --- |
| `preAuthenticatedUser` `DetailsService` | 此属性用于从证书中提取的用户名构建完整的`UserDetails`对象。 | 无 |
| `throwExceptionWhen` `TokenRejected` | 如果为真，当令牌构建不正确（不包含用户名或证书）时，将抛出`BadCredentialsException`异常。在仅使用证书的环境中通常设置为`true`。 | 无 |

除了这些属性，还有许多其他机会可以实现接口或扩展与证书认证相关的类，以进一步自定义您的实现。

# 实现客户端证书认证时的考虑

客户端证书认证虽然非常安全，但并不适合所有人，也不适用于每种情况。

以下是客户端证书认证的优点：

+   证书建立了一个双方（客户端和服务器）互相信任和可验证的框架，以确保双方都是他们所说的自己。

+   如果正确实现，基于证书的认证比其他形式的认证更难伪造或篡改。

+   如果使用得到良好支持的浏览器并正确配置，客户端证书认证可以有效地作为单点登录解决方案，实现对所有基于证书的安全应用的透明登录。

以下是客户端证书认证的缺点：

+   证书的使用通常要求整个用户群体都拥有证书。这可能导致用户培训负担和行政负担。大多数在大规模部署基于证书的认证的组织必须为证书维护、过期跟踪和用户支持提供足够的自助和帮助台支持。

+   使用证书通常是一个要么全部要么全无的事务，这意味着由于 web 服务器配置的复杂性或应用程序支持不足，不提供混合模式认证和支持非证书用户。

+   证书的使用可能不会得到您用户群体中所有用户的支持，包括使用移动设备的用户。

+   正确配置支持基于证书认证的基础设施可能需要高级的 IT 知识。

正如你所见，客户端证书认证既有优点也有缺点。当正确实现时，它可以为用户提供非常方便的访问方式，并具有极具吸引力的安全性和不可否认性属性。你需要确定你的具体情况以判断这种认证方式是否合适。

# 摘要

在本章中，我们研究了客户端基于证书认证的架构、流程以及 Spring Security 的支持。我们涵盖了客户端证书（相互）认证的概念和总体流程。我们探讨了配置 Apache Tomcat 以支持自签名的 SSL 和客户端证书场景的重要步骤。

我们还学习了如何配置 Spring Security 以理解客户端呈现的基于证书的凭据。我们涵盖了与证书认证相关的 Spring Security 类的架构。我们还知道如何配置 Spring bean 风格的客户端证书环境。我们还讨论了这种认证方式的优缺点。

对于不熟悉客户端证书的开发人员来说，他们可能会对这种环境中的许多复杂性感到困惑。我们希望这一章节使得这个复杂主题变得更容易理解和实现！在下一章节中，我们将讨论如何使用 OpenID 实现单点登录。


# 第九章：向 OAuth 2 敞开大门

**OAuth 2** 是一种非常流行的可信身份管理形式，允许用户通过一个可信的提供商来管理他们的身份。这一方便的功能为用户提供了将密码和个人信息存储在可信的 OAuth 2 提供商处的安全性，必要时可以披露个人信息。此外，支持 OAuth 2 的网站提供了用户提供的 OAuth 2 凭据确实是他们所说的那个人的信心。

在本章中，我们将涵盖以下主题：

+   学习在 5 分钟内设置自己的 OAuth 2 应用程序

+   配置 JBCP 日历应用程序，实现 OAuth 2 的快速实施

+   学习 OAuth 2 的概念架构以及它如何为你的网站提供可信的用户访问

+   实现基于 OAuth 2 的用户注册

+   实验 OAuth 2 属性交换以实现用户资料功能

+   展示我们如何触发与先前 OAuth 2 提供商的自动认证

+   检查基于 OAuth 2 的登录所提供的安全性

# 充满希望的 OAuth 2 世界

作为应用程序开发者，你可能经常听到 OAuth 2 这个词。OAuth 2 已在全球 Web 服务和软件公司中得到广泛采用，是这些公司互动和共享信息方式的核心部分。但它到底是什么呢？简而言之，OAuth 2 是一个允许不同方以安全和可靠的方式共享信息和资源的协议。

那么 OAuth 1.0 呢？

出于同样的动机，OAuth 1.0 在 2007 年被设计和批准。然而，它因过于复杂而受到批评，并且由于不精确的规范导致实现不安全。所有这些问题都导致了 OAuth 1.0 采用率低下，最终导致了 OAuth 2 的设计和创建。OAuth 2 是 OAuth 1.0 的继承者。

值得注意的是，OAuth 2 与 OAuth 1.0 不兼容，因此 OAuth 2 应用程序无法与 OAuth 1.0 服务提供商集成。

这种通过可信第三方登录的方式已经存在很长时间了，以许多不同的形式存在（例如，**Microsoft Passport** 在网上成为一段时间内较为知名的集中登录服务）。OAuth 2 的显著优势在于，OAuth 2 提供商只需实现公开的 OAuth 2 协议，即可与任何寻求与 OAuth 2 集成登录的网站兼容。

你可以参考 OAuth 2.0 规范：[`tools.ietf.org/html/rfc6749`](https://tools.ietf.org/html/rfc6749)。

以下图表说明了网站在登录过程中集成 OAuth 2 与例如 Facebook OAuth 2 提供商之间的高级关系：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/9724fa6b-4a4a-48bd-81f4-2e23851bb241.png)

我们可以看到，提交表单 POST 将启动对 OAuth 提供者的请求，导致提供者显示一个授权对话框，询问用户是否允许`jbcpcalendar`从您的 OAuth 提供者账户中获取特定信息的权限。这个请求包含一个名为`code`的`uri`参数。一旦授权，用户将被重定向回`jbcpcalendar`，`code`参数将包含在`uri`参数中。然后，请求再次重定向到 OAuth 提供者，以授权`jbcpcalendar`。OAuth 提供者随后响应一个`access_token`，该`access_token`可用于访问`jbcpcalendar`被授予访问权的用户 OAuth 信息。

不要盲目信任 OAuth 2 ！

在这里，你可以看到一个可能会误导系统用户的根本假设。我们可以注册一个 OAuth 2 提供者的账户，这样我们就可以假装是 James Gosling，尽管显然我们不是。不要错误地假设，仅仅因为一个用户有一个听起来令人信服的 OAuth 2（或 OAuth 2 代理提供者），就不需要额外的身份验证方式，认为他就是那个真实的人。换一种方式考虑，如果有人来到你的门前，只是声称他是 James Gosling，你会不会在核实他的身份证之前就让他进来？

启用了 OAuth 2 的应用程序然后将用户重定向到 OAuth 2 提供者，用户向提供者展示他的凭据，提供者负责做出访问决定。一旦提供者做出了访问决定，提供者将用户重定向到原始网站，现在可以确信用户的真实性。一旦尝试过，OAuth 2 就很容易理解了。现在让我们把 OAuth 2 添加到 JBCP 日历登录屏幕上！

# 注册 OAuth 2 应用程序

为了充分利用本节中的练习（并能够测试登录），您需要创建一个具有服务提供者的应用程序。目前，Spring Social 支持 Twitter、Facebook、Google、LinkedIn 和 GitHub，而且支持列表还在增加。

为了充分利用本章中的练习，我们建议您至少拥有 Twitter 和 GitHub 的账户。我们已经为`jbcpcalendar`应用设置了账户，我们将在本章剩余时间里使用它。

# 使用 Spring Security 启用 OAuth 认证

我们可以看到，在接下来的几章中，外部认证提供者之间有一个共同的主题。Spring Security 为实际开发在 Spring 生态系统之外的提供者集成提供了方便的包装器。

在这种情况下，Spring Social 项目（[`projects.spring.io/spring-social/`](http://projects.spring.io/spring-social/)）为 Spring Security OAuth 2 功能提供了基础的 OAuth 2 提供者发现和请求/响应协商。

# 额外的必需依赖

让我们来看看以下步骤：

1.  为了使用 OAuth，我们需要包含特定提供者的依赖及其传递依赖。这可以通过更新`build.gradle`文件在 Gradle 中完成，如下代码片段所示：

```java
        //build.gradle

        compile("org.springframework.boot:spring-boot-starter-
        social-facebook")
        compile("org.springframework.boot:spring-boot-starter-
        social-linkedin")
        compile("org.springframework.boot:spring-boot-starter-
        social-twitter")
```

1.  使用 Spring Boot 包括了对 Facebook、Twitter 和 LinkedIn 启动依赖的引用，如前文代码片段所示。要添加其他提供者，我们必须包含提供者的依赖并指定版本。这可以通过更新`build.gradle`文件在 Gradle 中完成，如下代码片段所示：

```java
        //build.gradle

        compile("org.springframework.social:spring-social-google:
        latest.release ")
        compile("org.springframework.social:spring-social-github:
        latest.release ")
        compile("org.springframework.social:spring-social-linkedin:
        latest.release ")
```

你应该从`chapter09.00-calendar`的源代码开始。

1.  当编写 OAuth 登录表单时，我们需要将`username`和`password`字段替换为 OAuth 字段。现在请对您的`login.html`文件进行以下更新：

```java
        //src/main/resources/templates/login.html

         <div class="form-actions">
            <input id="submit" class="btn" name="submit" type="submit" 
            value="Login"/>
           </div>
         </form>
       <br/>
         <h3>Social Login</h3>
       <br />
        <form th:action="@{/signin/twitter}" method="POST"
        class="form-horizontal">
         <input type="hidden" name="scope" value="public_profile" />
        <div class="form-actions">
        <input id="twitter-submit" class="btn" type="submit" 
        value="Login using  
        Twitter"/>
         </div>
        </form>
       </div>
```

1.  我们可以对注册表单进行类似的编辑，如下代码片段所示：

```java
         //src/main/resources/templates/signup/form.html

        </fieldset>
        </form>
         <br/>
           <h3>Social Login</h3>
         <br/>
 <form th:action="@{/signin/twitter}" method="POST" 
           class="form-horizontal">
 <input type="hidden" name="scope" value="public_profile" />        <div class="form-actions">
         <input id="twitter-submit" class="btn" type="submit" 
         value="Login using Twitter"/>
        </div>
        </form>
         </div>
```

你会注意到我们已经添加了一个范围字段来定义我们在认证过程中感兴趣的 OAuth 2 详细信息。

**OAuth 2.0 API 范围：**范围允许提供商定义客户端应用程序可访问的 API 数据。当提供商创建一个 API 时，他们会为每个表示的 API 定义一个范围和动作。一旦创建了 API 并定义了范围，客户端应用程序在启动授权流程时可以请求这些定义的权限，并将它们作为范围请求参数的一部分包含在访问令牌中。

每个提供商可能有略有不同的 API 范围，例如`r_basicprofile`和`r_emailaddress`，但 API 范围也限于应用程序配置。因此，一个应用程序可能只请求访问电子邮件或联系人，而不是整个用户资料或如发帖到用户墙等提供商动作。

你会注意到我们没有为 OAuth 2 登录提供**记住我**选项。这是由于事实，从提供商到网站以及返回的重定向会导致**记住我**复选框值丢失，因此当用户成功认证后，他们不再有**记住我**选项被标记。这虽然不幸，但最终增加了 OAuth 2 作为我们网站登录机制的安全性，因为 OAuth 2 强制用户在每次登录时与提供商建立一个可信关系。

# 在 Spring Security 中配置 OAuth 2 支持

使用**Spring Social**，我们可以为拦截提供商表单提交启用 OAuth 2 特定的提供商端点。

# 本地用户连接存储库（UserConnectionRepository）

`UsersConnectionRepository`接口是用于管理用户与服务提供商连接的全球存储的数据访问接口。它提供了适用于多个用户记录的数据访问操作，如下代码片段所示：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SocialConfig.java

    @Autowired

    private UsersConnectionRepository usersConnectionRepository;

    @Autowired

     private ProviderConnectionSignup providerConnectionSignup;

    @Bean

    public ProviderSignInController providerSignInController() {

       ((JdbcUsersConnectionRepository) usersConnectionRepository)

       .setConnectionSignUp(providerConnectionSignup);

       ...

    }

```

# 为提供商详情创建本地数据库条目

Spring Security 提供了支持，将提供者详情保存到一组单独的数据库表中，以防我们想在本地数据存储中保存用户，但不想将那些数据包含在现有的`User`表中：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/
    SocialDatabasePopulator.java

    @Component
    public class SocialDatabasePopulator
    implements InitializingBean {
       private final DataSource dataSource;
       @Autowired
    public SocialDatabasePopulator(final DataSource dataSource) {
    this.dataSource = dataSource;
     }
    @Override
    public void afterPropertiesSet() throws Exception {
       ClassPathResource resource = new ClassPathResource(
       "org/springframework/social/connect/jdbc/
       JdbcUsersConnectionRepository.sql");
       executeSql(resource);
     }
    private void executeSql(final Resource resource) {
     ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
     populator.setContinueOnError(true);
     populator.addScript(resource);
     DatabasePopulatorUtils.execute(populator, dataSource);
     }
  }
```

这个`InitializingBean`接口在加载时执行，并将执行位于类路径中的`spring-social-core-[VERSION].jar`文件内的`JdbcUsersConnectionRepository.sql`，将以下模式种子到我们的本地数据库中：

```java
    spring-social-core-  [VERSION].jar#org/springframework/social/connect/jdbc/
    JdbcUsersConnectionRepository.sql

    create table UserConnection(
      userId varchar(255) not null,
      providerId varchar(255) not null,
      providerUserId varchar(255),
      rank int not null,
      displayName varchar(255),
      profileUrl varchar(512),
      imageUrl varchar(512),
      accessToken varchar(512) not null,
      secret varchar(512),
      refreshToken varchar(512),
      expireTime bigint,
      primary key (userId, providerId, providerUserId));

      create unique index UserConnectionRank on UserConnection(userId, providerId,  
      rank);
```

现在我们已经有一个表来存储提供者详情，我们可以配置`ConnectionRepository`在运行时保存提供者详情。

# 自定义 UserConnectionRepository 接口

我们需要创建一个`UserConnectionRepository`接口，我们可以利用`JdbcUsersConnectionRepository`作为实现，它是基于我们加载时生成的`JdbcUsersConnectionRepository.sql`模式：

```java
      //src/main/java/com/packtpub/springsecurity/configuration/

      DatabaseSocialConfigurer.java

      public class DatabaseSocialConfigurer extends SocialConfigurerAdapter {

        private final DataSource dataSource;

        public DatabaseSocialConfigurer(DataSource dataSource) {

         this.dataSource = dataSource;

       }

      @Override

      public UsersConnectionRepository getUsersConnectionRepository(

      ConnectionFactoryLocator connectionFactoryLocator) {

          TextEncryptor textEncryptor = Encryptors.noOpText();

          return new JdbcUsersConnectionRepository(

          dataSource, connectionFactoryLocator, textEncryptor);

     }

      @Override

     public void addConnectionFactories(ConnectionFactoryConfigurer config,

     Environment env) {

          super.addConnectionFactories(config, env);

       }

   }

```

现在，每次用户连接到注册的提供者时，连接详情将被保存到我们的本地数据库中。

# 连接注册流程

为了将提供者详情保存到本地存储库，我们创建了一个`ConnectionSignup`对象，这是一个命令，在无法从`Connection`映射出`userid`的情况下注册新用户，允许在提供者登录尝试期间从连接数据隐式创建本地用户配置文件：

```java
    //src/main/java/com/packtpub/springsecurity/authentication/
    ProviderConnectionSignup.java

    @Service
     public class ProviderConnectionSignup implements ConnectionSignUp {
        ...; 
    @Override
    public String execute(Connection<?> connection) {
       ...
     }
    }
```

# 执行 OAuth 2 提供商连接工作流

为了保存提供者详情，我们需要从提供者获取可用细节，这些细节通过 OAuth 2 连接可用。接下来，我们从可用细节创建一个`CalendarUser`表。注意我们需要至少创建一个`GrantedAuthority`角色。在这里，我们使用了`CalendarUserAuthorityUtils#createAuthorities`来创建`ROLE_USER` `GrantedAuthority`：

```java
    //src/main/java/com/packtpub/springsecurity/authentication/
    ProviderConnectionSignup.java

    @Service
    public class ProviderConnectionSignup implements ConnectionSignUp {
         ...
    @Override
    public String execute(Connection<?> connection) {
        UserProfile profile = connection.fetchUserProfile();
        CalendarUser user = new CalendarUser();
        if(profile.getEmail() != null){
             user.setEmail(profile.getEmail());
          }
        else if(profile.getUsername() != null){
             user.setEmail(profile.getUsername());
         }
        else {
             user.setEmail(connection.getDisplayName());
         }
             user.setFirstName(profile.getFirstName());
             user.setLastName(profile.getLastName());
             user.setPassword(randomAlphabetic(32));
             CalendarUserAuthorityUtils.createAuthorities(user);
             ...
         }
      }

```

# 添加 OAuth 2 用户

既然我们已经从我们的提供者详情中创建了`CalendarUser`，我们需要使用`CalendarUserDao`将那个`User`账户保存到我们的数据库中。然后我们返回`CalendarUser`的电子邮件，因为这是我们一直在 JBCP 日历中使用的用户名：

```java
//src/main/java/com/packtpub/springsecurity/authentication/
ProviderConnectionSignup.java

@Service
public class ProviderConnectionSignup
implements ConnectionSignUp {
 @Autowired private CalendarUserDao calendarUserDao;  @Override
 public String execute(Connection<?> connection) {...
calendarUserDao.createUser(user); return user.getEmail();
   }
}
```

现在，我们已经根据提供者详情在数据库中创建了一个本地`User`账户。

这是一个额外的数据库条目，因为我们已经在之前的`UserConnection`表中保存了提供者详情。

# OAuth 2 控制器登录流程

现在，为了完成`SocialConfig.java`配置，我们需要构建`ProviderSignInController`，它使用`ConnectionFactoryLocator`、`usersConnectionRepository`和`SignInAdapter`进行初始化。`ProviderSignInController`接口是一个用于处理提供者用户登录流程的 Spring MVC 控制器。对`/signin/{providerId}`的 HTTP `POST`请求会使用`{providerId}`启动用户登录。提交对`/signin/{providerId}?oauth_token&oauth_verifier||code`的 HTTP `GET`请求将接收`{providerId}`身份验证回调并建立连接。

`ServiceLocator`接口用于创建`ConnectionFactory`实例。此工厂支持通过`providerId`和`apiType`查找，基于 Spring Boot 的`AutoConfiguration`中包含的服务提供商：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SocialConfig.java

    @Autowired
    private ConnectionFactoryLocator connectionFactoryLocator;
    @Bean
    public ProviderSignInController providerSignInController() {
        ...
        return new ProviderSignInController(connectionFactoryLocator,
        usersConnectionRepository, authSignInAdapter());
    }
```

这将允许拦截特定提供商`uri`的提交，并开始 OAuth 2 连接流程。

# 自动用户认证

让我们来看看以下步骤：

1.  `ProviderSignInController`控制器使用一个认证`SignInAdapter`进行初始化，该适配器用于通过使用指定 ID 登录本地用户账户来完成提供商登录尝试：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SocialConfig.java

        @Bean
        public SignInAdapter authSignInAdapter() {
           return (userId, connection, request) -> {
             SocialAuthenticationUtils.authenticate(connection);
             return null;
           };
         }
```

1.  在前面的代码片段中，在`SingInAdapter`bean 中，我们使用了一个自定义认证工具方法，以`UsernamePasswordAuthenticationToken`的形式创建了一个`Authentication`对象，并基于 OAuth 2 提供商返回的详情将其添加到`SecurityContext`中：

```java
        //src/main/java/com/packtpub/springsecurity/authentication/
        SocialAuthenticationUtils.java

        public class SocialAuthenticationUtils {
       public static void authenticate(Connection<?> connection) {
         UserProfile profile = connection.fetchUserProfile();
         CalendarUser user = new CalendarUser();
         if(profile.getEmail() != null){
             user.setEmail(profile.getEmail());
           }
         else if(profile.getUsername() != null){
             user.setEmail(profile.getUsername());
          }
         else {
             user.setEmail(connection.getDisplayName());
           }
             user.setFirstName(profile.getFirstName());
             user.setLastName(profile.getLastName());
             UsernamePasswordAuthenticationToken authentication = new  
             UsernamePasswordAuthenticationToken(user, null,        
             CalendarUserAuthorityUtils.createAuthorities(user));
             SecurityContextHolder.getContext()
             .setAuthentication(authentication);
           }
        }
```

连接到提供商所需的最详细信息是创建提供商应用时获得的应用程序 ID 和密钥：

```java
        //src/main/resources/application.yml:

        spring
        ## Social Configuration:
        social:
        twitter:
 appId: cgceheRX6a8EAE74JUeiRi8jZ
 appSecret: XR0J2N0Inzy2y2poxzot9oSAaE6MIOs4QHSWzT8dyeZaaeawep
```

1.  现在我们有了连接到 Twitter JBCP 日历所需的所有详细信息，我们可以启动 JBCP 日历并使用 Twitter 提供商登录。

您的代码现在应该看起来像`chapter09.01-calendar`。

1.  在此阶段，您应该能够使用 Twitter 的 OAuth 2 提供商完成完整的登录。发生的重定向如下，首先，我们启动以下屏幕快照所示的 OAuth 2 提供商登录：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/0187934f-9625-4fe9-a1c3-e5ff87e30f25.png)

我们随后被重定向到服务提供商授权页面，请求用户授予`jbcpcalendar`应用以下屏幕快照所示的权限：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/c837c1db-7c10-4400-9560-63441a2d743a.png)

1.  授权`jbcpcalendar`应用后，用户被重定向到`jbcpcalendar`应用，并使用提供商显示名称自动登录：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/f04b6a3f-70e6-4239-8e71-beecfd6af9de.png)

1.  在此阶段，用户存在于应用程序中，并且具有单个`GrantedAuthority`的`ROLE_USER`认证和授权，但如果导航到我的事件，用户将被允许查看此页面。然而，`CalendarUser`中不存在任何事件：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/5aaa1cee-f870-4307-bdb5-a707d9a4475e.png)

1.  尝试为该用户创建事件，以验证用户凭据是否正确创建在`CalendarUser`表中。

1.  为了验证提供商详情是否正确创建，我们可以打开 H2 管理控制台并查询`USERCONNECTION`表，以确认已保存以下屏幕快照所示的标准连接详情：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/088cc488-6004-466e-9862-4412e0a538aa.png)

1.  此外，我们还可以验证已填充了服务提供商详情的`CALENDAR_USERS`表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/7442542f-e849-49b4-b10d-7985c7428b7d.png)

现在我们已经在本地数据库中注册了用户，并且我们还可以根据对特定提供者详细信息的授权访问与注册提供者进行交互。

# 额外的 OAuth 2 提供者

我们已经成功集成了一个 OAuth 2 提供者，使用 Spring Social 当前支持的三个当前提供者之一。还有几个其他提供者可用；我们将添加更多提供者，以便用户有多一个选择。Spring Social 目前原生支持 Twitter，Facebook 和 LinkedIn 提供者。包括其他提供者将需要额外的库来实现此支持，这将在本章后面部分介绍。

让我们看看以下步骤：

1.  为了将 Facebook 或 LinkedIn 提供者添加到 JBCP 日历应用程序中，需要设置其他应用程序属性，并且每个配置的提供者将自动注册：

# OAuth 2 用户注册问题

如果在支持多个提供者的情况下，需要解决的一个问题是在各个提供者返回的详细信息之间的用户名冲突。

如果您使用列表中的每个提供者登录到 JBCP 日历应用程序，然后查询存储在 H2 中的数据，您会发现基于用户账户详细信息，数据可能相似，如果不是完全相同。

在下面的`USERCONNECTION`表中，我们可以看到来自每个提供者的`USERID`列数据是相似的：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/7f7a6efe-34ba-48c1-b81c-33d59e7eddb7.png)

在`CALENDARUSER`表中，我们有两个可能的问题。首先，用于`EMAIL`的用户详细信息对于某些提供者来说并不是电子邮件。其次，两个不同提供者的用户标识符仍然可能相同：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/b72f5a6e-04aa-4585-977b-d8cda1c13d17.png)

我们不会深入探讨检测和解决这个可能问题的各种方法，但值得在未来参考中注意。

# 注册非标准 OAuth 2 提供者

为了包括其他提供者，我们需要执行一些额外的步骤来将自定义提供者包括到登录流程中，如下所示：

1.  对每个提供者，我们需要在我们的`build.gradle`文件中包括提供者依赖项，如下所示：

```java
        //build.gradle

        dependencies {
          ...
          compile("org.springframework.social:spring-social-google:
          ${springSocialGoogleVersion}")
          compile("org.springframework.social:spring-social-github:
          ${springSocialGithubVersion}")
        }
```

1.  接下来，我们将使用以下为每个提供者的`appId`和`appSecret`键将提供者注册到 JBCP 日历应用程序：

```java
        //src/main/resources/application.yml

        spring:
          social:
            # Google
 google:
 appId: 947438796602-uiob88a5kg1j9mcljfmk00quok7rphib.apps.
                 googleusercontent.com
 appSecret: lpYZpF2IUgNXyXdZn-zY3gpR
           # Github
 github:
 appId: 71649b756d29b5a2fc84
 appSecret: 4335dcc0131ed62d757cc63e2fdc1be09c38abbf
```

1.  每个新提供者必须通过添加相应的`ConnectionFactory`接口进行注册。我们可以为每个新提供者添加一个新的`ConnectionFactory`条目到自定义的`DatabaseSocialConfigurer.java`文件中，如下所示：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        DatabaseSocialConfigurer.java

        public class DatabaseSocialConfigurer 
        extends SocialConfigurerAdapter {
           ...
        @Override
        public void addConnectionFactories(
        ConnectionFactoryConfigurer config, Environment env) {
               super.addConnectionFactories(config, env);

            // Adding GitHub Connection with properties
           // from application.yml
 config.addConnectionFactory(
 new GitHubConnectionFactory(
 env.getProperty("spring.social.github.appId"),
 env.getProperty("spring.social.github.appSecret")));
          // Adding Google Connection with properties
```

```java
         // from application.yml
 config.addConnectionFactory(
 new GoogleConnectionFactory(
 env.getProperty("spring.social.google.appId"),
 env.getProperty("spring.social.google.appSecret")));
             }
         }
```

1.  现在我们可以将新的登录选项添加到我们的`login.html`文件和`form.html`注册页面，为每个新提供者包括一个新的`<form>`标签：

```java
        //src/main/resources/templates/login.html

        <h3>Social Login</h3>
        ...
 <form th:action="@{/signin/google}" method="POST"        class="form-horizontal">
        <input type="hidden" name="scope" value="profile" />
        <div class="form-actions">
           <input id="google-submit" class="btn" type="submit" 
           value="Login using  
           Google"/>
        </div>
      </form>
     <br />

 <form th:action="@{/signin/github}" method="POST"       class="form-horizontal">
       <input type="hidden" name="scope" value="public_profile" />
       <div class="form-actions">
         <input id="github-submit" class="btn" type="submit"
         value="Login using  
         Github"/>
       </div>
     </form&gt;
```

1.  现在，我们有了连接到 JBCP 日历额外提供者的所需详细信息。我们可以重新启动 JBCP 日历应用程序，并尝试使用额外的 OAuth 2.0 提供商登录。现在登录时，我们应该会看到额外的提供商选项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/8c68d305-cdd4-4a20-9c1e-bfde59e40702.png)

# OAuth 2.0 安全吗？

由于 OAuth 2.0 支持依赖于 OAuth 2.0 提供者的可信度以及提供者响应的可验证性，因此安全性是至关重要的，以便应用程序对用户的 OAuth 2.0 登录有信心。

幸运的是，OAuth 2.0 规范的设计者非常清楚这个担忧，并实施了一系列验证步骤，以防止响应伪造、重放攻击和其他类型的篡改，如下所述：

+   **响应伪造**由于结合了由 OAuth 2.0 启用的网站在初始请求之前创建的共享密钥，以及响应本身的一路哈希消息签名而得以防止。没有访问共享密钥-和签名算法的恶意用户-篡改任何响应字段中的数据将生成无效的响应。

+   **重放攻击**由于包括了 nonce（一次性使用的随机密钥）而得以防止，该密钥应该被 OAuth 2.0 启用的网站记录，因此它永远不能被重新使用。这样，即使用户试图重新发行响应 URL，也会失败，因为接收网站会确定 nonce 已经被先前使用，并将请求无效。

+   可能导致用户交互被破坏的最有可能的攻击形式是一个中间人攻击，在这种攻击中，恶意用户可以拦截用户与他们计算机和 OAuth 2.0 提供商之间的交互。在这种情况下的假设攻击者可能处于记录用户浏览器与 OAuth 2.0 提供商之间的对话，以及当请求发起时记录密钥的立场。在这种情况下，攻击者需要非常高的复杂性水平，以及 OAuth 2.0 签名规范的相对完整的实现-简而言之，这不太可能以任何常规性发生。

# 总结

在本章中，我们回顾了 OAuth 2.0，这是一种相对较新的用户认证和凭据管理技术。OAuth 2.0 在网络上有非常广泛的应用，并且在过去的两年内在可用性和接受度上取得了很大的进步。大多数现代网络上的面向公众的网站都应该计划支持某种形式的 OAuth 2.0，JBCP 日历应用程序也不例外！

在本书中，我们学习了 OAuth 2.0 认证机制及其高级架构和关键术语。我们还了解了 JBCP 日历应用程序中的 OAuth 2.0 登录和自动用户注册。

我们还介绍了使用 OAuth 2.0 的自动登录以及 OAuth 2.0 登录响应的安全性。

我们介绍了使用 Spring Security 实现的最简单的单点登录机制之一。其中一个缺点是它不支持单点登出标准的机制。在下一章中，我们将探讨 CAS，另一种支持单点登出的标准单点登录协议。


# 第十章：使用中央认证服务的单点登录

在本章中，我们将探讨如何使用**中央认证服务**（**CAS**）作为 Spring Security 基础应用程序的单点登录门户。

在本章中，我们将涵盖以下主题：

+   学习关于 CAS，其架构以及它如何使系统管理员和任何大小的组织受益

+   了解如何重新配置 Spring Security 以处理认证请求的拦截并重定向到 CAS

+   配置 JBCP 日历应用程序以使用 CAS 单点登录

+   了解如何执行单一登出，并配置我们的应用程序以支持它

+   讨论如何使用 CAS 代理票证认证服务，并配置我们的应用程序以利用代理票证认证

+   讨论如何使用推荐的 war 覆盖方法定制**JA-SIG CAS**服务器

+   将 CAS 服务器与 LDAP 集成，并通过 CAS 将数据从 LDAP 传递到 Spring Security

# 介绍中央认证服务

CAS 是一个开源的单点登录服务器，为组织内的基于 web 的资源提供集中访问控制和认证。对于管理员来说，CAS 的好处是显而易见的，它支持许多应用程序和多样化的用户社区。好处如下：

+   资源（应用程序）的个人或组访问可以在一个位置进行配置

+   对各种认证存储（用于集中用户管理）的广泛支持，为广泛的跨机器环境提供单一的认证和控制点

+   通过 CAS 客户端库为基于 web 和非基于 web 的 Java 应用程序提供广泛的认证支持

+   通过 CAS 提供单一引用点用户凭据（ via CAS），因此 CAS 客户端应用程序无需了解用户的凭据，或知道如何验证它们

在本章中，我们将不太多关注 CAS 的管理，而是关注认证以及 CAS 如何为我们的网站用户充当认证点。尽管 CAS 通常在企业或教育机构的内部网络环境中看到，但它也可以在诸如 Sony Online Entertainment 公共面向网站等高知名度位置找到使用。

# 高级 CAS 认证流程

在较高层次上，CAS 由 CAS 服务器组成，这是确定认证的中心 web 应用程序，还有 CAS 服务，这是使用 CAS 服务器进行认证的不同的 web 应用程序。CAS 的基本认证流程通过以下动作进行：

1.  用户尝试访问网站上的受保护资源。

1.  用户通过浏览器从 CAS 服务请求登录到 CAS 服务器。

1.  CAS 服务器负责用户认证。如果用户尚未认证到 CAS 服务器，它会请求用户提供凭证。在下面的图中，用户被呈现一个登录页面。

1.  用户提交凭证（即用户名和密码）。

1.  如果用户的凭证有效，CAS 服务器将通过浏览器重定向一个服务票证。服务票证是一次性使用的令牌，用于标识用户。

1.  CAS 服务调用 CAS 服务器来验证票证是否有效，是否已过期等。注意这一步不是通过浏览器进行的。

1.  CAS 服务器回应一个断言，表示信任已经建立。如果票证可以接受，信任已经建立，用户可以通过正常的授权检查继续操作。

视觉上，它表现为以下 diagram:

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/93089ee8-4fe7-41ea-8a0c-1bbda83dbb11.png)

我们可以看到，CAS 服务器与安全应用程序之间有很高的交互性，在建立用户的信任之前需要进行几次数据交换握手。这种复杂性的结果是一个相当难以通过常见技术进行欺骗的单点登录协议（假设已经实施了其他网络安全措施，如使用 SSL 和网络监控）。

既然我们已经了解了一般情况下 CAS 认证是如何工作的，现在让我们看看它如何应用于 Spring Security。

# Spring Security 和 CAS

Spring Security 与 CAS 有很强的集成能力，尽管它不像我们在这本书的后半部分所探讨的 OAuth2 和 LDAP 集成那样紧密地集成在安全命名空间配置风格中。相反，大部分配置依赖于从安全命名空间元素到 bean 声明的 bean 导线和引用配置。

使用 Spring Security 进行 CAS 认证的两个基本部分包括以下内容：

+   替换标准的`AuthenticationEntryPoint`实现，该实现通常处理将未认证的用户重定向到登录页面的操作，改为将用户重定向到 CAS 服务器。

+   处理服务票证，当用户从 CAS 服务器重定向回受保护的资源时，通过使用自定义 servlet 过滤器

关于 CAS 的一个重要理解是，在典型的部署中，CAS 旨在替代您应用程序的所有其他登录机制。因此，一旦我们为 Spring Security 配置了 CAS，我们的用户必须将 CAS 作为唯一身份验证机制来使用。在大多数情况下，这并不是问题；如我们在上一节中讨论的，CAS 旨在代理身份验证请求到一个或多个身份验证存储（类似于 Spring Security 委托数据库或 LDAP 进行身份验证时）。从之前的图表中，我们可以看到，我们的应用程序不再检查其自己的身份验证存储来验证用户。相反，它通过使用服务票证来确定用户。然而，如我们稍后讨论的，最初，Spring Security 仍然需要一个数据存储来确定用户的授权。我们将在本章后面讨论如何移除这个限制。

在完成与 Spring Security 的基本 CAS 集成后，我们可以从主页上删除登录链接，并享受自动重定向到 CAS 登录界面的便利，在此界面中我们尝试访问受保护的资源。当然，根据应用程序的不同，允许用户明确登录（以便他们可以看到自定义内容等）也可能很有好处。

# 必需的依赖项

在我们进展太远之前，我们应该确保我们的依赖项已经更新。我们可以看到，以下是我们添加的依赖项列表，以及关于何时需要它们的注释：

```java
    //build.gradle

    dependencies {
    // CAS:
    compile('org.springframework.security:spring-security-cas')
    ...
    }
```

# 安装和配置 CAS

CAS 的好处之一是有一个非常 dedicated 的团队，他们为开发高质量的软件和准确、简洁的文档做出了出色的 job。如果您选择跟随本章中的示例，建议您阅读适合您 CAS 平台的入门手册。您可以在[`apereo.github.io/cas/5.1.x/index.html`](https://apereo.github.io/cas/5.1.x/index.html)找到此手册。

为了使集成尽可能简单，我们为本章 included 了一个 CAS 服务器应用程序，可以在 Spring Tool Suite 或 IntelliJ 中部署，还可以附带日历应用程序。本章中的示例将假设 CAS 部署在`https://localhost:9443/cas/`，日历应用程序部署在`https://localhost:8443/`。为了使 CAS 正常工作，必须使用 HTTPS。关于设置 HTTPS 的详细说明，请参阅附录*附加参考资料*。

本章中的示例是使用最新的 CAS 服务器版本（写作时为 5.1.2）编写的。请注意，在 5.x 版本中，对 CAS 的某些后端类进行了重大更改。因此，如果您使用的是服务器的前一个版本，这些说明可能会有所不同或显著不同。

接下来，我们配置用于 CAS 认证的组件。

你应该从`chapter10.00-calendar`和`chapter10.00-cas-server`开始章节，引入源代码。

# 配置基本的 CAS 集成

由于 Spring Security 命名空间不支持 CAS 配置，我们需要实现很多步骤才能让基本设置工作。为了了解发生了什么，你可以参考以下图表。

不用担心现在就理解整个图表，因为我们将其分解成小块，以便更容易消化：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/414892bb-05b4-4d94-9cf5-79ef506f42ac.png)

# 创建 CAS ServiceProperties 对象

Spring Security 设置依赖于一个`o.s.s.cas.ServiceProperties`bean 来存储关于 CAS 服务的常见信息。`ServiceProperties`对象在协调各种 CAS 组件之间的数据交换中扮演角色-它被用作一个数据对象来存储共享的（并且预期是匹配的）Spring CAS 堆栈中的各个参与者的 CAS 配置设置。你可以查看以下代码段中包含的配置：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/CasConfig.java

    static{
    System.setProperty("cas.server", "https://localhost:9443/cas");
     System.setProperty("cas.server.login", 
     "https://localhost:9443/cas/login");
    System.setProperty("cas.service", 
     "https://localhost:8443");
    System.setProperty("cas.service.login", 
    "https://localhost:8443/login");
     }
    @Value("#{systemProperties['cas.service.login']}")
    private String calendarServiceLogin;
    @Bean
    public ServiceProperties serviceProperties(){
     return new ServiceProperties(){{
    setService(calendarServiceLogin);
     }};
    }
```

你可能注意到了，我们利用系统属性使用了名为`${cas.service}`和`${cas.server}`的变量。这两个值都可以包含在你的应用程序中，Spring 会自动将它们替换为在`PropertySources`配置中提供的值。这是一种常见的策略，当部署 CAS 服务时，由于 CAS 服务器很可能从开发环境过渡到生产环境，所以 CAS 服务器可能会发生变化。在这个实例中，我们默认使用`localhost:9443`作为 CAS 服务器，`localhost:8443`作为日历应用程序。当应用程序部署到生产环境时，可以通过系统参数来覆盖这个配置。另外，配置可以外部化到一个 Java 属性文件中。任一机制都允许我们适当外部化配置。

# 添加 CasAuthenticationEntryPoint 对象

如本章开头简要提到的，Spring Security 使用一个`o.s.s.web.AuthenticationEntryPoint`接口来请求用户的凭据。通常，这涉及到将用户重定向到登录页面。对于 CAS，我们需要将用户重定向到 CAS 服务器以请求登录。当我们重定向到 CAS 服务器时，Spring Security 必须包含一个`service`参数，指示 CAS 服务器应该发送服务票证的位置。幸运的是，Spring Security 提供了`o.s.s.cas.web.CasAuthenticationEntryPoint`对象，专门为此目的设计。示例应用程序中的配置如下：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/CasConfig.java

    @Value("#{systemProperties['cas.server.login']}")
    private String casServerLogin;
    @Bean
    public CasAuthenticationEntryPoint casAuthenticationEntryPoint(){
     return new CasAuthenticationEntryPoint(){{
     setServiceProperties(serviceProperties());
     setLoginUrl(casServerLogin);
     }};
    }
```

`CasAuthenticationEntryPoint`对象使用`ServiceProperties`类来指定用户认证后要发送服务票据的位置。CAS 允许根据配置对每个用户、每个应用程序进行选择性授权。我们将在配置处理该 URL 的 servlet 过滤器时立即检查这个 URL 的详细信息。接下来，我们需要更新 Spring Security 以使用具有`casAuthenticationEntryPoint` ID 的 bean。将以下内容更新到我们的`SecurityConfig.java`文件中：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/
    SecurityConfig.java

    @Autowired
    private CasAuthenticationEntryPoint casAuthenticationEntryPoint;
    @Override
    protected void configure(HttpSecurity http) throws Exception {
      ...
    // Exception Handling
     http.exceptionHandling()
     .authenticationEntryPoint(casAuthenticationEntryPoint)
     .accessDeniedPage("/errors/403");
    ...
```

最后，我们需要确保`CasConfig.java`文件被 Spring 加载。更新`SecurityConfig.java`文件，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/
    SecurityConfig.java

    @Configuration
    @EnableWebSecurity(debug = true)
    @EnableGlobalAuthentication
    @Import(CasConfig.class)
    public class SecurityConfig extends WebSecurityConfigurerAdapter {
```

你需要做的最后一件事是删除现有的`UserDetailsService`对象作为`AuthenticationManager`的`userDetailsService`实现，因为它不再需要，因为`CasAuthenticationEntryPoint`在`SecurityConfig.java`文件中取代了它：

```java
    src/main/java/com/packtpub/springsecurity/configuration/
    SecurityConfig.java
    @Override
    public void configure(AuthenticationManagerBuilder auth)
    throws Exception {
    super.configure(auth);
    //auth.userDetailsService(userDetailsService)
     // .passwordEncoder(passwordEncoder());
    }
```

如果你在这个时候启动应用程序并尝试访问“我的事件”页面，你将会立即被重定向到 CAS 服务器进行认证。CAS 的默认配置允许任何用户名与密码相等的用户进行认证。所以，你应该能够使用用户名`admin1@example.com`和密码`admin1@example.com`（或`user1@example.com`/`user1@example.com`）登录。

然而，你会注意到，即使在登录之后，你也会立即被重定向回 CAS 服务器。这是因为尽管目标应用程序能够接收到票据，但它无法进行验证，因此 CAS 将`AccessDeniedException`对象处理为对票据的拒绝。

# 使用 CasAuthenticationProvider 对象证明真实性

如果你一直跟随本书中 Spring Security 的逻辑流程，那么你应该已经知道接下来会发生什么——`Authentication`令牌必须由一个适当的`AuthenticationProvider`对象进行检查。CAS 也不例外，因此，这个谜题的最后一片拼图就是在`AuthenticationManager`内部配置一个`o.s.s.cas.authentication.CasAuthenticationProvider`对象。

让我们来看看以下步骤：

1.  首先，我们将在`CasConfig.java`文件中声明 Spring bean，如下所示：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        CasConfig.java

        @Bean
        public CasAuthenticationProvider casAuthenticationProvider() {
           CasAuthenticationProvider casAuthenticationProvider = new
           CasAuthenticationProvider();
           casAuthenticationProvider.setTicketValidator(ticketValidator());
           casAuthenticationProvider.setServiceProperties
           (serviceProperties());
           casAuthenticationProvider.setKey("casJbcpCalendar");
           casAuthenticationProvider.setAuthenticationUserDetailsService(
             userDetailsByNameServiceWrapper);
             return casAuthenticationProvider;
        }
```

1.  接下来，我们将在`SecurityConfig.java`文件中配置对新`AuthenticationProvider`对象的引用，该文件包含我们的`AuthenticationManager`声明：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

        @Autowired
        private CasAuthenticationProvider casAuthenticationProvider;
        @Override
        public void configure(final AuthenticationManagerBuilder auth)
        throws Exception   
        {
         auth.authenticationProvider(casAuthenticationProvider);
        }
```

1.  如果你之前练习中有任何其他`AuthenticationProvider`引用，请记得将它们与 CAS 一起移除。所有这些更改都在前面的代码中有所展示。现在，我们需要处理`CasAuthenticationProvider`类中的其他属性和 bean 引用。`ticketValidator`属性指的是`org.jasig.cas.client.validation.TicketValidator`接口的实现；由于我们使用的是 CAS 3.0 认证，我们将声明一个`org.jasig.cas.client.validation.Cas30ServiceTicketValidator`实例，如下所示：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        CasConfig.java

        @Bean
        public Cas30ProxyTicketValidator ticketValidator(){
         return new Cas30ProxyTicketValidator(casServer);
        }
```

这个类提供的构造参数应该（再次）指的是访问 CAS 服务器的 URL。你会注意到，在这个阶段，我们已经从`org.springframework.security`包中移出，进入到`org.jasig`，这是 CAS 客户端 JAR 文件的一部分。在本章后面，我们将看到`TicketValidator`接口也有实现（仍在 CAS 客户端的 JAR 文件中），支持使用 CAS 的其他认证方法，例如代理票和 SAML 认证。

接下来，我们可以看到`key`属性；这个属性仅用于验证`UsernamePasswordAuthenticationToken`的完整性，可以任意定义。

正如我们在第八章《使用 TLS 的客户端证书认证》中所看到的，`authenticationUserDetailsService`属性指的是一个`o.s.s.core.userdetails.AuthenticationUserDetailsService`对象，该对象用于将`Authentication`令牌中的用户名信息转换为完全填充的`UserDetails`对象。当前实现通过查找 CAS 服务器返回的用户名并使用`UserDetailsService`对象查找`UserDetails`来实现这一转换。显然，这种技术只有在确认`Authentication`令牌的完整性未被破坏时才会使用。我们将此对象配置为对我们`CalendarUserDetailsService`实现的`UserDetailsService`接口的引用：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/CasConfig.java

    @Bean
    public UserDetailsByNameServiceWrapper
    authenticationUserDetailsService(
      final UserDetailsService userDetailsService){
      return new UserDetailsByNameServiceWrapper(){{
      setUserDetailsService(userDetailsService);
      }};
    }
```

你可能会好奇为什么没有直接引用`UserDetailsService`接口；原因在于，正如 OAuth2 一样，之后将会有额外的先进配置选项，这将允许使用 CAS 服务器的信息来填充`UserDetails`对象。

你的代码应该看起来像`chapter10.01-calendar`和`chapter10.01-cas-server`。

此时，我们应该能够启动 CAS 服务器和 JBCP 日历应用程序。然后你可以访问`https://localhost:8443/`，并选择所有事件，这将引导你到 CAS 服务器。之后你可以使用用户名`admin1@example.com`和密码`admin1@example.com`登录。验证成功后，你将被重定向回 JBCP 日历应用程序。干得好！

如果您遇到问题，很可能是由于不正确的 SSL 配置。请确保您已经按照附录中的*附加参考材料*所述设置了信任库文件为`tomcat.keystore`。

# 单点登出

您可能会注意到，如果您从应用程序中登出，会得到登出确认页面。然而，如果您点击受保护的页面，比如我的事件页面，您仍然会被认证。问题在于，登出仅在本地发生。所以，当您请求 JBCP 日历应用程序中的另一个受保护资源时，会从 CAS 服务器请求登录。由于用户仍然登录到 CAS 服务器，它会立即返回一个服务票据，并将用户重新登录到 JBCP 日历应用程序。

这也就意味着，如果用户已经通过 CAS 服务器登录了其他应用程序，由于我们的日历应用程序不知道其他应用程序的情况，他们仍然会对那些应用程序进行身份验证。幸运的是，CAS 和 Spring Security 为这个问题提供了一个解决方案。正如我们可以从 CAS 服务器请求登录一样，我们也可以请求登出。您可以看到以下关于在 CAS 中登出工作方式的的高级示意图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/987b97c6-e600-405e-a800-648ca3f400c4.png)

以下步骤解释了单点登出是如何进行的：

1.  用户请求从 Web 应用程序登出。

1.  然后 Web 应用程序通过浏览器重定向到 CAS 服务器，请求登出 CAS。

1.  CAS 服务器识别用户，然后向每个已认证的 CAS 服务发送登出请求。请注意，这些登出请求不是通过浏览器发生的。

1.  CAS 服务器通过提供原始的服务票据来指示哪个用户应该登出，该票据用于登录用户。然后应用程序负责确保用户登出。

1.  CAS 服务器向用户显示登出成功页面。

# 配置单点登出

单点登出的配置相对简单：

1.  第一步是在我们的`SecurityConfig.java`文件中指定一个`logout-success-url`属性，该属性是 CAS 服务器的登出 URL。这意味着在本地登出后，我们将自动将用户重定向到 CAS 服务器的登出页面：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

        @Value("#{systemProperties['cas.server']}/logout")
        private static String casServerLogout;
        @Override
        protected void configure(final HttpSecurity http)
        throws Exception {
         ...
         http.logout()
        .logoutUrl("/logout")
        .logoutSuccessUrl(casServerLogout)
        .permitAll();
        }
```

由于我们只有一个应用程序，所以这是我们需要的，以使看起来像是在发生单点登出。这是因为我们在重定向到 CAS 服务器登出页面之前已经从我们的日历应用程序中登出。这意味着当 CAS 服务器将登出请求发送给日历应用程序时，用户已经登出了。

1.  如果有多个应用程序，用户从另一个应用程序登出，CAS 服务器会将登出请求发送给我们的日历应用程序，而不会处理登出事件。这是因为我们的应用程序没有监听这些登出事件。解决方案很简单；我们必须创建一个`SingleSignoutFilter`对象，如下所示：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        CasConfig.java

        @Bean
        public SingleSignOutFilter singleSignOutFilter() {
           return new SingleSignOutFilter();
        }
```

1.  接下来，我们需要让 Spring Security 意识到我们`SecurityCOnfig.java`文件中的`singleLogoutFilter`对象，通过将其作为`<custom-filter>`元素包括在内。将单次登出过滤器放在常规登出之前，以确保它接收到登出事件，如下所示：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

        @Autowired
        private SingleSignOutFilter singleSignOutFilter;
        @Override
        protected void configure(HttpSecurity http) throws Exception {
          ...
         http.addFilterAt(casFilter, CasAuthenticationFilter.class);
         http.addFilterBefore(singleSignOutFilter, LogoutFilter.class);
        // Logout
        http.logout()
         .logoutUrl("/logout")
         .logoutSuccessUrl(casServerLogout)
         .permitAll();
        }
```

1.  在正常情况下，我们需要对`web.xml`或`ApplicationInitializer`文件进行一些更新。然而，对于我们的日历应用程序，我们已经对我们的`CasConfig.java`文件进行了更新，如下所示：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        CasConfig.java

        @Bean
        public ServletListenerRegistrationBean
        <SingleSignOutHttpSessionListener>
        singleSignOutHttpSessionListener() {
          ServletListenerRegistrationBean<SingleSignOutHttpSessionListener> 
          listener = new     
          ServletListenerRegistrationBean<>();
          listener.setEnabled(true);
          listener.setListener(new SingleSignOutHttpSessionListener());
          listener.setOrder(1);
          return listener;
        }
        @Bean
        public FilterRegistrationBean 
        characterEncodingFilterRegistration() {
          FilterRegistrationBean registrationBean = 
          new FilterRegistrationBean
          (characterEncodingFilter());
          registrationBean.setName("CharacterEncodingFilter");
          registrationBean.addUrlPatterns("/*");
          registrationBean.setOrder(1);
          return registrationBean;
        }
        private CharacterEncodingFilter characterEncodingFilter() {
           CharacterEncodingFilter filter = new CharacterEncodingFilter(
             filter.setEncoding("UTF-8");
             filter.setForceEncoding(true);
             return filter;
        }
```

首先，我们添加了`SingleSignoutHttpSessionListener`对象，以确保删除服务票证与`HttpSession`的映射。我们还添加了`CharacterEncodingFilter`，正如 JA-SIG 文档所推荐的那样，以确保在使用`SingleSignOutFilter`时字符编码正确。

1.  继续启动应用程序并尝试登出。你会观察到你实际上已经登出了。

1.  现在，尝试重新登录并直接访问 CAS 服务器的登出 URL。对于我们设置，URL 是`https://localhost:9443/cas/logout`。

1.  现在，尝试访问 JBCP 日历应用程序。你会观察到，在没有重新认证的情况下，你无法访问该应用程序。这证明了单次登出是有效的。

你的代码应该看起来像`chapter10.02-calendar`和`chapter10.02-cas-server`。

# 集群环境

我们没有在单次登出初始图中提到的一件事是如何执行登出。不幸的是，它是通过将服务票证与`HttpSession`的映射作为内存映射存储来实现的。这意味着在集群环境中，单次登出将无法正确工作：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/20770234-2dc4-410c-9237-c5481f56a004.png)

考虑以下情况：

+   用户登录到**集群成员 A**

+   **集群成员 A**验证服务票证

+   然后，在内存中记住服务票证与用户会话的映射

+   用户请求从**CAS 服务器**登出

**CAS 服务器**向 CAS 服务发送登出请求，但**集群成员 B**接到了登出请求。它在它的内存中查找，但没有找到**服务票证 A**的会话，因为它只存在于**集群成员 A**中。这意味着，用户没有成功登出。

寻求此功能的用户可能需要查看 JA-SIG JIRA 队列和论坛中解决此问题的方案。实际上，一个工作补丁已经提交到了[`issues.jasig.org/browse/CASC-114`](https://issues.jasig.org/browse/CASC-114)。记住，论坛和 JA-SIG JIRA 队列中有许多正在进行讨论和提案，所以在决定使用哪个解决方案之前，你可能想要四处看看。关于与 CAS 的集群，请参考 JA-SIG 在[`wiki.jasig.org/display/CASUM/Clustering+CAS`](https://wiki.jasig.org/display/CASUM/Clustering+CAS)的集群文档。

# 无状态服务的代理票证认证

使用 CAS 集中我们的认证似乎很适合 web 应用程序，但如果我们想使用 CAS 调用 web 服务呢？为了支持这一点，CAS 有一个代理票证（**PT**）的概念。以下是它如何工作的图表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/21b96476-c1df-42b1-8cc2-01f250b3fe4a.png)

流程与标准的 CAS 认证流程相同，直到以下事情发生：

1.  当包含一个额外参数时，**服务票证**被验证，这个参数叫做代理票证回调 URL（**PGT URL**）。

1.  **CAS 服务器**通过**HTTPS**调用**PGT URL**来验证**PGT URL**是否如它所声称的那样。像大多数 CAS 一样，这是通过与适当 URL 执行 SSL 握手来完成的。

1.  **CAS 服务器**提交**代理授权票**（**PGT**）和**代理授权票我欠你**（**PGTIOU**）到**PGT URL**，通过**HTTPS**确保票证提交到它们声称的来源。

1.  **PGT URL**接收到两个票证，并必须存储**PGTIOU**与**PGT**的关联。

1.  **CAS 服务器**最终在*步骤 1*中返回一个响应，其中包括用户名和**PGTIOU**。

1.  CAS 服务可以使用**PGTIOU**查找**PGT**。

# 配置代理票证认证

既然我们已经知道 PT 认证是如何工作的，我们将更新我们当前的配置，通过执行以下步骤来获取 PGT：

1.  第一步是添加一个对`ProxyGrantingTicketStorage`实现的引用。接着，在我们的`CasConfig.java`文件中添加以下代码：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        CasConfig.java

       @Bean
       public ProxyGrantingTicketStorage pgtStorage() {
        return new ProxyGrantingTicketStorageImpl();
        }
        @Scheduled(fixedRate = 300_000)
        public void proxyGrantingTicketStorageCleaner(){
          pgtStorage().cleanUp();
        }
```

1.  `ProxyGrantingTicketStorageImpl`实现是一个内存中映射，将 PGTIOU 映射到 PGT。正如登出时一样，这意味着在集群环境中使用此实现会有问题。参考 JA-SIG 文档，确定如何在集群环境中设置：`[`wiki.jasig.org/display/CASUM/Clustering+CAS`](https://wiki.jasig.org/display/CASUM/Clustering+CAS)`

1.  我们还需要定期通过调用其`cleanUp()`方法来清理`ProxyGrantingTicketStorage`。正如你所看到的，Spring 的任务抽象使这非常简单。你可以考虑调整配置，清除`Ticket`在一个适合你环境的单独线程池中。更多信息，请参考 Spring 框架参考文档中*任务执行*和*调度*部分：[`static.springsource.org/spring/docs/current/spring-framework-reference/html/scheduling.html`](http://static.springsource.org/spring/docs/current/spring-framework-reference/html/scheduling.html)。

1.  现在我们需要使用我们刚刚创建的`ProxyGrantingTicketStorage`。我们只需要更新`ticketValidator`方法，使其引用我们的存储并知道 PGT URL。对`CasConfig.java`进行以下更新：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        CasConfig.java

        @Value("#{systemProperties['cas.calendar.service']}/pgtUrl")
        private String calendarServiceProxyCallbackUrl;
        @Bean
        public Cas30ProxyTicketValidator ticketValidator(){
          Cas30ProxyTicketValidator tv = new 
          Cas30ProxyTicketValidator(casServer);
          tv.setProxyCallbackUrl(calendarServiceProxyCallbackUrl);
          tv.setProxyGrantingTicketStorage(pgtStorage());
          return tv;
            }
```

1.  我们需要做的最后更新是我们的`CasAuthenticationFilter`对象，当 PGT URL 被调用时，将 PGTIOU 存储到 PGT 映射中我们的`ProxyGrantingTicketStorage`实现。确保`proxyReceptorUrl`属性与`Cas20ProxyTicketValidator`对象的`proxyCallbackUrl`属性相匹配，以确保 CAS 服务器将票证发送到我们的应用程序正在监听的 URL。在`security-cas.xml`中进行以下更改：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        CasConfig.java

        @Bean
        public CasAuthenticationFilter casFilter() {
           CasAuthenticationFilter caf = new CasAuthenticationFilter();
        caf.setAuthenticationManager(authenticationManager);
        caf.setFilterProcessesUrl("/login");
        caf.setProxyGrantingTicketStorage(pgtStorage());
        caf.setProxyReceptorUrl("/pgtUrl");
         return caf;
        }
```

既然我们已经有了一个 PGT，我们该怎么办呢？服务票证是一次性使用的令牌。然而，PGT 可以用来生成 PT。让我们看看我们可以如何使用 PGT 创建一个 PT。

您会注意到`proxyCallBackUrl`属性与我们的上下文相关`proxyReceptorUrl`属性的绝对路径相匹配。由于我们将我们的基本应用程序部署到`https://${cas.service }/`，我们`proxyReceptor` URL 的完整路径将是`https://${cas.service }/pgtUrl`。

# 使用代理票证

我们现在可以使用我们的 PGT 创建一个 PT 来验证它对一个服务。这个操作在本书中包含的`EchoController`类中非常简单地演示了。您可以在以下代码片段中看到相关的部分。有关更多详细信息，请参阅示例的源代码：

```java
    //src/main/java/com/packtpub/springsecurity/web/controllers/
    EchoController.java

    @ResponseBody
   @RequestMapping("/echo")
    public String echo() throws UnsupportedEncodingException {
      final CasAuthenticationToken token = (CasAuthenticationToken)
     SecurityContextHolder.getContext().getAuthentication();
    final String proxyTicket = token.getAssertion().getPrincipal()
    .getProxyTicketFor(targetUrl);
    return restClient.getForObject(targetUrl+"?ticket={pt}",
    String.class, proxyTicket);
    }
```

这个控制器是一个构造的例子，它将获取一个 PT，用于验证对当前登录用户的所有事件进行 RESTful 调用的请求。然后它将 JSON 响应写入页面。让一些用户感到困惑的是，`EchoController`对象实际上正在对同一应用程序中的`MessagesController`对象进行 RESTful 调用。这意味着日历应用程序对自己进行 RESTful 调用[。](https://localhost:8443/calendar/rest-client)

大胆地访问`https://localhost:8443/echo`来看它的实际效果。这个页面看起来很像 CAS 登录页面（除了 CSS）。这是因为控制器试图回显我们的“我的事件”页面，而我们的应用程序还不知道如何验证 PT。这意味着它被重定向到 CAS 登录页面。让我们看看我们如何可以验证代理票证。

您的代码应该看起来像`chapter10.03-calendar`和`chapter10.03-cas-server`。

# 验证代理票证

让我们来看看以下步骤，了解验证代理票证的方法：

1.  我们首先需要告诉`ServiceProperties`对象我们希望验证所有票证，而不仅仅是那些提交到`filterProcessesUrl`属性的票证。对`CasConfig.java`进行以下更新：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        CasConfig.java

        @Bean
        public ServiceProperties serviceProperties(){
          return new ServiceProperties(){{
             setService(calendarServiceLogin);
             setAuthenticateAllArtifacts(true);
          }};
        }
```

1.  然后我们需要更新我们的`CasAuthenticationFilter`对象，使其知道我们希望认证所有工件（即，票证）而不是只监听特定的 URL。我们还需要使用一个`AuthenticationDetailsSource`接口，当在任意 URL 上验证代理票证时，可以动态提供 CAS 服务 URL。这是因为当一个 CAS 服务询问票证是否有效时，它也必须提供创建票证所用的 CAS 服务 URL。由于代理票证可以发生在任何 URL 上，我们必须能够动态发现这个 URL。这是通过利用`ServiceAuthenticationDetailsSource`对象来完成的，它将提供 HTTP 请求中的当前 URL：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        CasConfig.java

        @Bean
        public CasAuthenticationFilter casFilter() {
          CasAuthenticationFilter caf = new CasAuthenticationFilter();
          caf.setAuthenticationManager(authenticationManager);
          caf.setFilterProcessesUrl("/login");
          caf.setProxyGrantingTicketStorage(pgtStorage());
          caf.setProxyReceptorUrl("/pgtUrl");
          caf.setServiceProperties(serviceProperties());
          caf.setAuthenticationDetailsSource(new        
          ServiceAuthenticationDetailsSource(serviceProperties())
        );
         return caf;
        }
```

1.  我们还需要确保我们使用的是`Cas30ProxyTicketValidator`对象，而不是`Cas30ServiceTicketValidator`实现，并指出我们想要接受哪些代理票证。我们将配置我们的接受来自任何 CAS 服务的代理票证。在生产环境中，您可能希望考虑只限制那些可信的 CAS 服务：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        CasConfig.java

        @Bean
        public Cas30ProxyTicketValidator ticketValidator(){
          Cas30ProxyTicketValidator tv = new 
          Cas30ProxyTicketValidator(casServer);
          tv.setProxyCallbackUrl(calendarServiceProxyCallbackUrl);
```

```java
          tv.setProxyGrantingTicketStorage(pgtStorage());
          tv.setAcceptAnyProxy(true);
          return tv;
        }
```

1.  最后，我们希望能够为我们的`CasAuthenticationProvider`对象提供一个缓存，这样我们就不需要为每个服务调用而访问 CAS 服务：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        CasConfig.java

        @Bean
        public CasAuthenticationProvider casAuthenticationProvider() {
         CasAuthenticationProvider cap = new CasAuthenticationProvider();
         cap.setTicketValidator(ticketValidator());
         cap.setServiceProperties(serviceProperties());
         cap.setKey("casJbcpCalendar");
         cap.setAuthenticationUserDetailsService
         (userDetailsByNameServiceWrapper);
         cap.setStatelessTicketCache(ehCacheBasedTicketCache());
         return cap;
       }
      @Bean
      public EhCacheBasedTicketCache ehCacheBasedTicketCache() {
        EhCacheBasedTicketCache cache = new EhCacheBasedTicketCache();
        cache.setCache(ehcache());
        return cache;
      }
     @Bean(initMethod = "initialise", destroyMethod = "dispose")
     public Cache ehcache() {
       Cache cache = new Cache("casTickets", 50, true, false, 3_600,  900);
       return cache;
     }
```

1.  正如您可能已经猜到的那样，缓存需要我们章节开头提到的`ehcache`依赖。接着重新启动应用程序，并再次访问`https://localhost:8443/echo`。这次，您应该看到一个 JSON 响应，响应我们的事件页面调用。

您的代码应该看起来像`chapter10.04-calendar`和`chapter10.04-cas-server`。

# 定制 CAS 服务器

本节中的所有更改都将是针对 CAS 服务器，而不是日历应用程序。本节仅旨在介绍配置 CAS 服务器的入门，因为详细的设置确实超出了本书的范围。正如日历应用程序的更改一样，我们鼓励您跟随本章中的更改。更多信息，您可以参考 JA-SIG CAS 维基百科页面在[`wiki.jasig.org/display/CAS/Home`](https://wiki.jasig.org/display/CAS/Home)。

# CAS WAR 覆盖

定制 CAS 的首选方式是使用 Maven 或 Gradle War 覆盖。通过这种机制，您可以从 UI 到认证 CAS 服务的方法改变一切。WAR 覆盖的概念很简单。您添加一个 WAR 覆盖`cas-server-webapp`作为一个依赖，然后提供额外的文件，这些文件将与现有的 WAR 覆盖合并。有关关于 CAS WAR 覆盖的更多信息，请参考 JA-SIG 文档在[`wiki.jasig.org/display/CASUM/Best+Practice+-+Setting+Up+CAS+Locally+using+the+Maven2+WAR+Overlay+Method`](https://wiki.jasig.org/display/CASUM/Best+Practice+-+Setting+Up+CAS+Locally+using+the+Maven2+WAR+Overlay+Method)。

# CAS 内部认证是如何工作的？

在我们深入讨论 CAS 配置之前，我们将简要说明 CAS 认证处理的标准行为。以下图表应帮助你理解允许 CAS 与我们的内置 LDAP 服务器通信所需的配置步骤：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/90ac09bd-55dd-43ed-bc1d-5d6ce644b782.png)

虽然之前的图表描述了 CAS 服务器本身内部认证的流程，但如果你正在实现 Spring Security 和 CAS 之间的集成，你可能需要调整 CAS 服务器的配置。因此，理解 CAS 认证的高级工作原理是很重要的。

CAS 服务器的`org.jasig.cas.authentication.AuthenticationManager`接口（不要与 Spring Security 中同名的接口混淆）负责根据提供的凭据对用户进行认证。与 Spring Security 类似，凭据的实际处理委托给一个（或多个）实现`org.jasig.cas.authentication.handler.AuthenticationHandler`接口的处理类（我们认识到 Spring Security 中相应的接口是`AuthenticationProvider`）。

最后，`org.jasig.cas.authentication.principal.CredentialsToPrincipalResolver`接口用于将传入的凭据转换为完整的`org.jasig.cas.authentication.principal.Principal`对象（在 Spring Security 中实现`UserDetailsService`时，会有类似的行为）。

虽然这不是对 CAS 服务器后台功能的全面回顾，但这应该能帮助你理解接下来的几个练习中的配置步骤。我们鼓励你阅读 CAS 的源代码，并参考在 JA-SIG CAS 维基百科页面上的网络文档，网址为[`www.ja-sig.org/wiki/display/CAS`](http://www.ja-sig.org/wiki/display/CAS)。

# 配置 CAS 以连接到我们的内置 LDAP 服务器。

默认配置的`org.jasig.cas.authentication.principal.UsernamePasswordCredentialsToPrincipalResolver`对象不允许我们返回属性信息并展示 Spring Security CAS 集成的这一特性，因此我们建议使用一个允许这样做的实现。

如果你已经完成了上一章的 LDAP 练习，那么配置和使用一个简单的认证处理程序（尤其是`org.jasig.cas.adaptors.ldap.BindLdapAuthenticationHandler`）会很容易，它与我们在上一章中使用的内置 LDAP 服务器通信。我们将引导你通过配置 CAS，使其在以下指南中返回用户 LDAP 属性。

所有的 CAS 配置都将在 CAS 安装的`WEB-INF/deployerConfigContext.xml`文件中进行，通常涉及将类声明插入到已经存在的配置文件段中。我们已经从`cas-server-webapp`中提取了默认的`WEB-INF/deployerConfigContext.xml`文件，并将其放在了`cas-server/src/main/webapp/WEB-INF`中。

如果这份文件的内容对你来说很熟悉，那是因为 CAS 像 JBCP 日历一样，也是使用 Spring 框架来进行配置的。我们建议如果你想要深入理解这些配置设置是如何工作的，最好使用一个好的 IDE 并且有一个方便的 CAS 源代码参考。记住，在本节以及所有引用到`WEB-INF/deployerConfigContext.xml`的部分，我们指的是 CAS 安装，而不是 JBCP 日历。

让我们来看看以下步骤：

1.  首先，我们将在`SimpleTestUsernamePasswordAuthenticationHandler`对象的位置添加一个新的`BindLdapAuthenticationHandler`对象，该对象将尝试将用户绑定到 LDAP（正如我们在第六章，*LDAP 目录服务*中所做的那样）。

1.  `AuthenticationHandler`接口将被放置在`authenticationManager`bean 的`authenticationHandlers`属性中：

```java
        //cas-server/src/main/webapp/WEB-INF/deployerConfigContext.xml

        <property name="authenticationHandlers">
        <list>
         ... remove ONLY
        SimpleTestUsernamePasswordAuthenticationHandler ...
        <bean class="org.jasig.cas.adaptors
        .ldap.BindLdapAuthenticationHandler">
        <property name="filter" value="uid=%u"/>
        <property name="searchBase" value="ou=Users"/>
        <property name="contextSource" ref="contextSource"/>
         </bean>
        </list>
        </property>
```

别忘了删除对`SimpleTestUsernamePasswordAuthenticationHandler`对象的引用，或者至少将其定义移到`BindLdapAuthenticationHandler`对象之后，否则，你的 CAS 认证将不会使用 LDAP，而是使用代理处理器！

1.  你会注意到对一个`contextSource`bean 的引用；这定义了`org.springframework.ldap.core.ContextSource`实现，CAS 将使用它来与 LDAP 进行交互（是的，CAS 也使用 Spring LDAP）。我们将在文件的末尾使用 Spring Security 命名空间来简化其定义，如下所示：

```java
    //cas-server/src/main/webapp/WEB-INF/deployerConfigContext.xml

    <sec:ldap-server id="contextSource"  
     ldif="classpath:ldif/calendar.ldif" root="dc=jbcpcalendar,dc=com" />
    </beans>
```

这创建了一个使用随本章提供的`calendar.ldif`文件的嵌入式 LDAP 实例。当然，在生产环境中，你希望指向一个真实的 LDAP 服务器。

1.  最后，我们需要配置一个新的`org.jasig.cas.authentication.principal.CredentialsToPrincipalResolver`对象。这个对象负责将用户提供的凭据（CAS 已经使用`BindLdapAuthenticationHandler`对象进行认证的）翻译成一个完整的`org.jasig.cas.authentication.principal.Principal`认证主体。你会注意到这个类中有许多配置选项，我们将略过它们。当你深入探索 CAS 时，你可以自由地研究它们。

1.  删除`UsernamePasswordCredentialsToPrincipalResolver`，并向 CAS`authenticationManager`bean 的`credentialsToPrincipalResolvers`属性中添加以下内联 bean 定义：

```java
        //cas-server/src/main/webapp/WEB-INF/deployerConfigContext.xml

       <property name="credentialsToPrincipalResolvers">
        <list>
        <!-- REMOVE UsernamePasswordCredentialsToPrincipalResolver -->
        <bean class="org.jasig.cas.authentication.principal
        .HttpBasedServiceCredentialsToPrincipalResolver" />
        <bean class="org.jasig.cas.authentication.principal
        .CredentialsToLDAPAttributePrincipalResolver">
        <property name="credentialsToPrincipalResolver">
        <bean class="org.jasig.cas.authentication.principal
        .UsernamePasswordCredentialsToPrincipalResolver"/>
        </property>
        <property name="filter" value="(uid=%u)"/>
        <property name="principalAttributeName" value="uid"/>
        <property name="searchBase" value="ou=Users"/>
        <property name="contextSource" ref="contextSource"/>
        <property name="attributeRepository" ref="attributeRepository"/>
        </bean>
        </list>
        </property>
```

你会注意到，与 Spring Security LDAP 配置一样，CAS 中有很多同样的行为，原则是基于 DN 在目录的子树下基于属性匹配进行搜索。

请注意，我们尚未亲自为 ID 为`attributeRepository`的 bean 配置，这应该指的是`org.jasig.services.persondir.IPersonAttributeDao`的一个实现。CAS 随带有一个默认配置，其中包括这个接口的一个简单实现`org.jasig.services.persondir.support.StubPersonAttributeDao`，这将足以直到我们在后面的练习中配置基于 LDAP 的属性。

您的代码应该看起来像`chapter10.05-calendar`和`chapter10.05-cas-server`。

所以，现在我们已经在大 CAS 中配置了基本的 LDAP 身份验证。在这个阶段，您应该能够重新启动 CAS，启动 JBCP 日历（如果它还没有运行），并使用`admin1@example.com`/`admin`或`user1@example.com/user1`对它进行身份验证。去尝试看看它是否有效。如果它不起作用，尝试检查日志并将您的配置与示例配置进行比较。

如第五章中所讨论的，*使用 Spring Data 进行身份验证*，您可能会遇到启动应用程序时出现问题，无论临时目录`apacheds-spring-security`是否仍然存在。如果应用程序似乎不存在，检查日志并查看是否需要删除`apacheds-spring-security`目录。

# 从 CAS 断言获取 UserDetails 对象

直到这一点，我们一直通过从我们的`InMemoryUserDetailsManager`对象获取角色来使用 CAS 进行身份验证。然而，我们可以像对待 OAuth2 一样，从 CAS 断言中创建`UserDetails`对象。第一步是配置 CAS 服务器以返回附加属性。

# 在 CAS 响应中返回 LDAP 属性

我们知道 CAS 可以在 CAS 响应中返回用户名，但它也可以在 CAS 响应中返回任意属性。让我们看看我们如何更新 CAS 服务器以返回附加属性。再次强调，本节中的所有更改都在 CAS 服务器中，而不是在日历应用程序中。

# 将 LDAP 属性映射到 CAS 属性

第一步需要我们将 LDAP 属性映射到 CAS 断言中的属性（包括我们期望包含用户`GrantedAuthority`的`role`属性）。

我们将在 CAS 的`deployerConfigContext.xml`文件中添加另一段配置。这一新的配置是必需的，以指导 CAS 如何将来自 CAS`Principal`对象的属性映射到 CAS`IPersonAttributes`对象，这最终将作为票证验证的一部分序列化。这个 bean 配置应该替换相同名称的 bean-即`attributeRepository`-如下所示：

```java
    //cas-server/src/main/webapp/WEB-INF/deployerConfigContext.xml

    <bean id="attributeRepository" class="org.jasig.services.persondir
    .support.ldap.LdapPersonAttributeDao">
    <property name="contextSource" ref="contextSource"/>
    <property name="requireAllQueryAttributes" value="true"/>
    <property name="baseDN" value="ou=Users"/>
    <property name="queryAttributeMapping">
    <map>
     <entry key="username" value="uid"/>
    </map>
     </property>
    <property name="resultAttributeMapping">
    <map>
    <entry key="cn" value="FullName"/>
    <entry key="sn" value="LastName"/>
    <entry key="description" value="role"/>
    </map>
    </property>
    </bean>
```

这里的幕后功能确实令人困惑——本质上，这个类的目的是将`Principal`映射回 LDAP 目录。（这是`queryAttributeMapping`属性，它将`Principal`的`username`字段映射到 LDAP 查询中的`uid`属性。）提供的`baseDN`Java Bean 属性使用 LDAP 查询（`uid=user1@example.com`）进行搜索，并从匹配的条目中读取属性。这些属性使用`resultAttributeMapping`属性中的键/值对映射回`Principal`。我们认识到，LDAP 的`cn`和`sn`属性被映射到有意义的名称，并且`description`属性被映射到用于确定我们用户角色的属性。

复杂性的一部分源于这样一个事实：这部分功能被包装在一个名为`Person Directory`的单独项目中（[`www.ja-sig.org/wiki/display/PD/Home`](http://www.ja-sig.org/wiki/display/PD/Home)），该项目旨在将关于一个人的多个信息源聚合到一个单一的视图中。`Person Directory`的设计如此，它并不直接与 CAS 服务器绑定，并且可以作为其他应用程序的一部分被复用。这种设计选择的一个缺点是，它使得 CAS 配置的一些方面比最初看起来要复杂。

排查 CAS 中的 LDAP 属性映射问题

我们很想设置与第六章中使用的 Spring Security LDAP 相同的查询类型（*LDAP 目录服务*），以便能够将`Principal`映射到完整的 LDAP 别名，然后使用该 DN 通过匹配`groupOfUniqueNames`条目的`uniqueMember`属性来查找组成员。不幸的是，CAS LDAP 代码目前还没有这种灵活性，导致结论，更高级的 LDAP 映射将需要对 CAS 的基本类进行扩展。

# 授权 CAS 服务访问自定义属性

接下来，我们将需要授权任何通过 HTTPS 访问这些属性的 CAS 服务。为此，我们可以更新`RegisteredServiceImpl`，其描述为`仅允许 HTTPS URL`（在`InMemoryServiceRegistryDaoImpl`中），如下所示：

```java
    //cas-server/src/main/webapp/WEB-INF/deployerConfigContext.xml

    <bean class="org.jasig.cas.services.RegisteredServiceImpl">
      <property name="id" value="1" />
      <property name="name" value="HTTPS" />
      <property name="description" value="Only Allows HTTPS Urls" />
      <property name="serviceId" value="https://**" />
      <property name="evaluationOrder" value="10000002" />
      <property name="allowedAttributes">
      <list>
        <value>FullName</value>
        <value>LastName</value>
        <value>role</value>
     </list>
    </property>
    </bean>
```

# 从 CAS 获取 UserDetails

当我们第一次将 CAS 与 Spring Security 集成时，我们配置了`UserDetailsByNameServiceWrapper`，它简单地将呈现给 CAS 的用户名转换为从`UserDetailsService`获取的`UserDetails`对象，我们所引用的（在我们的案例中，它是`InMemoryUserDetailsManager`）。现在既然 CAS 正在引用 LDAP 服务器，我们可以设置`LdapUserDetailsService`，正如我们在第六章末尾讨论的那样（*LDAP 目录服务*），并且一切都会正常工作。请注意，我们已经回到修改日历应用程序，而不是 CAS 服务器。

# `GrantedAuthorityFromAssertionAttributesUser`对象

现在我们已经修改了 CAS 服务器以返回自定义属性，接下来我们将尝试 Spring Security CAS 集成的另一个功能-从 CAS 断言本身填充`UserDetails`的能力！实际上，这就像将`AuthenticationUserDetailsService`实现更改为`o.s.s.cas.userdetails.GrantedAuthorityFromAssertionAttributesUserDetailsService`对象一样简单，该对象的任务是读取 CAS 断言，查找某个属性，并将该属性的值直接映射到用户的`GrantedAuthority`对象。假设有一个名为 role 的属性将随断言返回。我们只需在`CaseConfig.xml`文件中配置一个新的`authenticationUserDetailsService` bean（确保替换之前定义的`authenticationUserDetailsService` bean）：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/CasConfig.java

    @Bean
    public AuthenticationUserDetailsService userDetailsService(){
       GrantedAuthorityFromAssertionAttributesUserDetailsService uds
       = new GrantedAuthorityFromAssertionAttributesUserDetailsService(
       new String[]{"role"}
    );
     return uds;
    }
```

你还需要将从`SecurityConfig.java`文件中的`userDetailsService` bean 删除，因为现在它不再需要了。

# 使用 SAML 1.1 的替代票证认证。

**安全断言标记语言**（**SAML**）是一个使用结构化 XML 断言的标准、跨平台身份验证协议。SAML 被许多产品支持，包括 CAS（实际上，我们将在后面的章节中查看 Spring Security 本身对 SAML 的支持）。

虽然标准的 CAS 协议可以扩展以返回属性，但 SAML 安全断言 XML 方言解决了属性传递的一些问题，使用了我们之前描述的 CAS 响应协议。幸运的是，在`CasSecurity.java`中配置的`TicketValidator`实现从 CAS 票证验证切换到 SAML 票证验证就像改变以下`ticketValidator`一样简单：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/CasConfig.java

    @Bean
    public Saml11TicketValidator ticketValidator(){
      return new Saml11TicketValidator(casServer);
    }
```

你会注意到再也没有对 PGT URL 的引用。这是因为`Saml11TicketValidator`对象不支持 PGT。虽然两者都可以存在，但我们选择删除任何对代理票证认证的引用，因为我们不再使用代理票证认证。如果你不想在本练习中删除它，不用担心；只要你的`ticketValidator` bean ID 与之前的代码片段相似，它就不会阻止我们的应用程序运行。

通常，建议使用 SAML 票证验证而不是 CAS 2.0 票证验证，因为它增加了更多的非否认功能，包括`timestamp`验证，并以标准方式解决了属性问题。

重新启动 CAS 服务器和 JBCP 日历应用程序。然后你可以访问`https://localhost:8443`，并看到我们的日历应用程序可以从 CAS 响应中获取`UserDetails`。

你的代码现在应该看起来像`chapter10.06-calendar`和`chapter10.06-cas-server`。

# 属性检索有什么用？

记住，CAS 为我们的应用程序提供了一层抽象，消除了我们应用程序直接访问用户存储库的能力，而是强制所有此类访问通过 CAS 作为代理进行。

这非常强大！这意味着我们的应用程序不再关心用户存储在什么类型的存储库中，也不必担心如何访问它们——这进一步证实了通过 CAS 进行身份验证足以证明用户应该能够访问我们的应用程序。对于系统管理员来说，这意味着如果 LDAP 服务器被重新命名、移动或进行其他调整，他们只需要在单一位置——CAS 中重新配置它。通过 CAS 集中访问允许在组织的整体安全架构中具有高度的灵活性和适应性。

这个故事讲述了从 CAS 获取属性的有用性；现在所有通过 CAS 验证的应用程序对用户有相同的视图，并且可以在任何 CAS 启用的环境中一致地显示信息。

请注意，一旦验证通过，Spring Security CAS 不再需要 CAS 服务器，除非用户需要重新验证。这意味着存储在应用程序中用户`Authentication`对象中的属性和其他用户信息可能会随时间变得过时，并且可能与源 CAS 服务器不同步。请注意适当地设置会话超时，以避免这个潜在的问题！

# 额外的 CAS 功能

CAS 提供了通过 Spring Security CAS 包装器暴露之外的高级配置功能。其中一些包括以下功能：

+   为在 CAS 服务器上配置的时间窗口内访问多个 CAS 安全应用程序的用户提供透明的单点登录。应用程序可以通过在`TicketValidator`上设置`renew`属性为`true`来强制用户向 CAS 进行身份验证；在用户试图访问应用程序的受保护区域时，您可能希望在自定义代码中有条件地设置此属性。

+   获取服务票证的 RESTful API。

+   JA-SIG 的 CAS 服务器也可以作为 OAuth2 服务器。如果你想想，这是有道理的，因为 CAS 与 OAuth2 非常相似。

+   为 CAS 服务器提供 OAuth 支持，以便它可以获取委派 OAuth 提供者（即 Google）的访问令牌，或者使 CAS 服务器本身成为 OAuth 服务器。

我们鼓励您探索 CAS 客户端和服务器的全部功能，并向 JA-SIG 社区论坛中的热心人士提问！

# 总结

在本章中，我们学习了关于 CAS 单点登录门户的知识，以及它是如何与 Spring Security 集成的，我们还涵盖了 CAS 架构以及在 CAS 启用环境中参与者之间的通信路径。我们还看到了 CAS 启用应用程序对应用开发人员和系统管理员的益处。我们还学习了如何配置 JBCP 日历与基本 CAS 安装进行交互。我们还涵盖了 CAS 的单一登出支持的用途。

我们同样了解了代理票证认证是如何工作的，以及如何利用它来认证无状态服务。

我们还涵盖了更新 CAS 以与 LDAP 交互，以及将 LDAP 数据与我们的 CAS 启用应用程序共享的任务。我们还学习了如何使用行业标准的 SAML 协议实现属性交换。

我们希望这一章是对单点登录世界的一个有趣的介绍。市场上还有许多其他单点登录系统，大部分是商业的，但 CAS 无疑是开源 SSO 世界中的领导者之一，是任何组织构建 SSO 能力的一个优秀平台。

在下一章中，我们将学习更多关于 Spring Security 授权的内容。
