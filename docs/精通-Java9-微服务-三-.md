# 精通 Java9 微服务（三）

> 原文：[`zh.annas-archive.org/md5/EB1A7415EF02ADBBA3AE87C35F6AF10F`](https://zh.annas-archive.org/md5/EB1A7415EF02ADBBA3AE87C35F6AF10F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：保护微服务

正如您所知，微服务是我们部署在本地或云基础设施上的组件。微服务可能提供 API 或网络应用程序。我们的示例应用程序 OTRS 提供 API。本章将重点介绍如何使用 Spring Security 和 Spring OAuth2 保护这些 API。我们还将重点介绍 OAuth 2.0 基本原理，使用 OAuth 2.0 保护 OTRS API。要了解更多关于保护 REST API 的信息，您可以参考*RESTful Java Web Services Security,* *Packt Publishing* 书籍。您还可以参考*Spring Security*, *Packt Publishing*视频以获取有关 Spring Security 的更多信息。我们还将学习跨源请求站点过滤器和跨站脚本阻止器。

在本章中，我们将涵盖以下主题：

+   启用安全套接层（SSL）

+   身份验证和授权

+   OAuth 2.0

# 启用安全套接层

到目前为止，我们一直使用**超文本传输协议**（**HTTP**）。HTTP 以明文形式传输数据，但在互联网上以明文形式传输数据是一个非常糟糕的主意。这使得黑客的工作变得容易，允许他们使用数据包嗅探器轻松获取您的私人信息，例如您的用户 ID、密码和信用卡详细信息。

我们绝对不希望妥协用户数据，因此我们将提供访问我们网络应用的最安全方式。因此，我们需要加密终端用户与应用之间交换的信息。我们将使用**安全套接层**（**SSL**）或**传输安全层**（**TSL**）来加密数据。

安全套接层（SSL）是一种旨在为网络通信提供安全（加密）的协议。HTTP 与 SSL 关联，以提供安全实现 HTTP，称为**安全超文本传输协议**，或**通过 SSL 的 HTTP**（**HTTPS**）。HTTPS 确保交换数据的隐私和完整性得到保护。它还确保访问的网站的真实性。这种安全性围绕在托管应用程序的服务器、终端用户的机器和第三方信任存储服务器之间分发签名的数字证书。让我们看看这个过程是如何进行的：

1.  终端用户使用网络浏览器向网络应用发送请求，例如[`twitter.com`](http://twitter.com)

1.  在接收到请求后，服务器使用 HTTP 代码 302 将浏览器重定向到[`twitter.com`](https://twitter.com)

1.  终端用户的浏览器连接到[`twitter.com`](https://twitter.com)，作为回应，服务器向终端用户的浏览器提供包含数字签名的证书

1.  终端用户的浏览器接收到这个证书，并将其与可信的**证书授权机构**（**CA**）列表进行比对以进行验证

1.  一旦证书验证到根 CA，终端用户的浏览器与应用托管服务器之间就建立了加密通信：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/a03a2790-bdc3-48ec-8ce6-d59edc13a93a.jpg)

安全的 HTTP 通信

尽管 SSL 在加密和 Web 应用真实性方面确保了安全，但它并不能防止钓鱼和其他攻击。专业的黑客可以解密通过 HTTPS 发送的信息。

现在，在了解了 SSL 的基本知识之后，让我们为我们的示例 OTRS 项目实现它。我们不需要为所有微服务实现 SSL。所有微服务都将通过我们的代理或 Edge 服务器访问；Zuul-Server 由外部环境访问，除了我们将在本章中介绍的新微服务 security-service，用于认证和授权。

首先，我们将在一个 Edge 服务器上设置 SSL。我们需要一个用于在嵌入式 Tomcat 中启用 SSL 的 keystore。我们将使用自签名证书进行演示。我们将使用 Java keytool 生成 keystore，使用以下命令。您也可以使用其他任何工具：

```java
keytool -genkey -keyalg RSA -alias selfsigned -keystore keystore.jks -ext san=dns:localhost -storepass password -validity 365 -keysize 2048 
```

它要求提供诸如姓名、地址详情、组织等信息（见下面的屏幕截图）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/bcd90065-6c21-4b90-b5e8-baa0af4d1e09.png)

keytool 生成密钥

为确保自签名证书的正常工作，请注意以下几点：

+   使用`-ext`定义**主题备用名称**（**SANs**）。您还可以使用 IP（例如，`san=ip:190.19.0.11`）。以前，通常使用应用程序部署机器的主机名作为最常见的名称（**CN**）。它防止了`java.security.cert.CertificateException`返回`No name matching localhost found`。

+   您可以使用浏览器或 OpenSSL 下载证书。使用`keytool -importcert`命令，将新生成的证书添加到位于活动`JDK/JRE`主目录内的`jre/lib/security/cacerts`的`cacerts` keystore 中。注意`changeit`是`cacerts` keystore 的默认密码。运行以下命令：

```java
keytool -importcert -file path/to/.crt -alias <cert alias> -  keystore <JRE/JAVA_HOME>/jre/lib/security/cacerts -storepass changeit 
```

自签名证书只能用于开发和测试目的。在生产环境中使用这些证书并不能提供所需的安全性。在生产环境中总是使用由可信签名机构提供和签名的证书。妥善保管您的私钥。

现在，在将生成的`keystore.jks`放入 OTRS 项目的`src/main/resources`目录中，与`application.yml`一起，我们可以像以下这样更新 Edge 服务器的`application.yml`信息：

```java
server: 
    ssl: 
        key-store: classpath:keystore.jks 
        key-store-password: password 
        key-password: password 
    port: 8765 
```

重建 Zuul-Server JAR 以使用 HTTPS。

在 Tomcat 7.0.66+和 8.0.28+版本中，可以将 keystore 文件存储在之前的类路径中。对于旧版本，您可以使用 keystore 文件的路径作为`server:ssl:key-store`的值。

同样，您可以为其他微服务配置 SSL。

# 认证和授权

提供认证和授权是网络应用程序的默认行为。我们将在本节讨论认证和授权。过去几年发展起来的新范例是 OAuth。我们将学习和使用 OAuth 2.0 进行实现。OAuth 是一个开放授权机制，在每一个主要网络应用程序中都有实现。通过实现 OAuth 标准，网络应用程序可以访问彼此的数据。它已经成为各种网络应用程序认证自己的最流行方式。例如，在[`www.quora.com/`](https://www.quora.com/)上，你可以使用你的 Google 或 Twitter 登录 ID 进行注册和登录。这也更用户友好，因为客户端应用程序（例如[`www.quora.com/`](https://www.quora.com/)）不需要存储用户的密码。最终用户不需要记住另一个用户 ID 和密码。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/9ba38134-b0a2-45eb-93b0-1908e43f3234.jpg)

OAuth 2.0 示例使用

# OAuth 2.0

**互联网工程任务组**（**IETF**）管理 OAuth 的标准和规格。OAuth 1.0a 是在 OAuth 2.0 之前的最新版本，它解决了 OAuth 1.0 中的会话固定安全漏洞。OAuth 1.0 和 1.0a 与 OAuth 2.0 非常不同。OAuth 1.0 依赖于安全证书和通道绑定，而 OAuth 2.0 不支持安全证书和通道绑定。它完全基于**传输层安全**（**TLS**）。因此，OAuth 2.0 不提供向后兼容性。

# 使用 OAuth

OAuth 的各种用途如下：

+   正如讨论的那样，它可以用于身份验证。你可能在各种应用程序中看到过它，比如显示“使用 Facebook 登录”或“使用 Twitter 登录”的消息。

+   应用程序可以利用它来读取其他应用程序的数据，例如通过在应用程序中集成 Facebook 小部件，或者在博客上拥有 Twitter 源。

+   或者，与前面一点相反的情况也是正确的：你允许其他应用程序访问最终用户的数据。

# OAuth 2.0 规格说明 - 简洁的细节

我们将尝试以简洁的方式讨论和理解 OAuth 2.0 规格说明。首先让我们看看使用 Twitter 登录是如何工作的。

请注意，这里提到的过程是在写作时使用的，未来可能会有所变化。然而，这个过程正确地描述了 OAuth 2.0 的其中一个过程：

1.  用户访问 Quora 主页，上面显示各种登录选项。我们将探讨点击“继续使用 Twitter”链接的过程。

1.  当用户点击“继续使用 Twitter”链接时，Quora 在一个新窗口（在 Chrome 中）中打开，该窗口将用户重定向到[www.twitter.com](http://www.twitter.com)应用程序。在这个过程中，一些网络应用程序将用户重定向到同一个已打开的标签/窗口。

1.  在这个新窗口/标签中，用户使用他们的凭据登录[www.twitter.com](http://www.twitter.com)。

1.  如果用户尚未授权 Quora 应用使用他们的数据，Twitter 会请求用户授权 Quora 访问用户的信息。如果用户已经授权 Quora，则跳过此步骤。

1.  经过适当的认证后，Twitter 会将用户重定向到 Quora 的重定向 URI，并附带一个认证码。

1.  当在浏览器中输入 Quora 的重定向 URI 时，Quora 发送客户端 ID、客户端密钥令牌和认证码（由 Twitter 在第五步发送）。

1.  在验证这些参数后，Twitter 将访问令牌发送给 Quora。

1.  用户在成功获取访问令牌后登录到 Quora。

1.  Quora 可能使用此访问令牌从 Twitter 检索用户信息。

你可能想知道 Twitter 是如何获得 Quora 的重定向 URI、客户端 ID 和密钥令牌的。Quora 作为客户端应用程序，Twitter 作为授权服务器。Quora 作为客户端，在注册时使用 Twitter 的 OAuth 实现来使用资源所有者（最终用户）的信息。Quora 在注册时提供一个重定向 URI。Twitter 向 Quora 提供客户端 ID 和密钥令牌。在 OAuth 2.0 中，用户信息被称为用户资源。Twitter 提供一个资源服务器和一个授权服务器。我们将在接下来的章节中讨论更多关于这些 OAuth 术语的内容。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/b0c76112-52d8-4051-9e33-442567eee985.jpg)

使用 Twitter 登录的 OAuth 2.0 示例过程

# OAuth 2.0 角色

OAuth 2.0 规范中定义了四个角色：

+   资源所有者

+   资源服务器

+   客户端

+   授权服务器

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/7b76513b-0a74-4b4f-bbf6-b09037f4983e.jpg)

OAuth 2.0 角色

# 资源所有者

以 Quora 使用 Twitter 登录为例，Twitter 用户是资源所有者。资源所有者是拥有要共享的受保护资源（例如，用户处理、推文等）的实体。这个实体可以是应用程序或个人。我们称这个实体为资源所有者，因为它只能授予对其资源的访问权限。规范还定义，当资源所有者是个人时，它们被称为最终用户。

# 资源服务器

资源服务器托管受保护的资源。它应该能够使用访问令牌服务于这些资源。以 Quora 使用 Twitter 登录为例，Twitter 是资源服务器。

# 客户端

以 Quora 使用 Twitter 登录为例，Quora 是客户端。客户端是代表资源所有者向资源服务器请求受保护资源的应用程序。

# 授权服务器

授权服务器在资源所有者身份验证后，才向客户端应用程序提供不同的令牌，例如访问令牌或刷新令牌。

OAuth 2.0 没有为资源服务器与授权服务器之间的交互提供任何规范。因此，授权服务器和资源服务器可以在同一服务器上，也可以在不同的服务器上。

一个授权服务器也可以用于为多个资源服务器颁发访问令牌。

# OAuth 2.0 客户端注册

客户端与授权服务器通信以获取资源访问密钥时，应首先向授权服务器注册。OAuth 2.0 规范没有指定客户端如何向授权服务器注册的方式。注册不需要客户端与授权服务器之间直接通信。注册可以使用自发行或第三方发行的断言完成。授权服务器使用其中一个断言获取所需的客户端属性。让我们看看客户端属性是什么：

+   客户端类型（在下一节中讨论）。

+   客户端重定向 URI，正如我们在使用 Twitter 登录 Quora 的示例中讨论的那样。这是用于 OAuth 2.0 的端点之一。我们将在*端点*部分讨论其他端点。

+   授权服务器可能需要的任何其他信息，例如客户端名称、描述、标志图像、联系详情、接受法律条款和条件等。

# 客户端类型

规范中描述了两种客户端类型，根据它们保持客户端凭据保密的能力：保密和公共。客户端凭据是由授权服务器颁发给客户端的秘密令牌，以便与它们通信。客户端类型如下所述：

+   **保密客户端类型：** 这是一个保持密码和其他凭据安全或保密的客户端应用程序。在使用 Twitter 登录 Quora 的示例中，Quora 应用服务器是安全的，并且实现了受限的访问。因此，它属于保密客户端类型。只有 Quora 应用管理员才能访问客户端凭据。

+   **公共客户端类型：** 这些客户端应用程序不*保持*密码和其他凭据的安全或保密。任何移动或桌面上的本地应用，或者在浏览器上运行的应用，都是公共客户端类型的完美示例，因为这些应用中嵌入了客户端凭据。黑客可以破解这些应用，从而暴露客户端凭据。

客户端可以是分布式组件基础应用程序，例如，它可能同时具有网络浏览器组件和服务器端组件。在这种情况下，两个组件将具有不同的客户端类型和安全上下文。如果授权服务器不支持此类客户端，则此类客户端应将每个组件注册为单独的客户端。

# 客户端配置文件

根据 OAuth 2.0 客户端类型，客户端可以有以下配置文件：

+   **网络应用：** 在 Quora 使用 Twitter 登录的示例中使用的 Quora 网络应用是 OAuth 2.0 网络应用客户端配置文件的完美示例。Quora 是一个运行在网络服务器上的机密客户端。资源所有者（最终用户）通过他们设备上的 HTML 用户界面在浏览器（用户代理）上访问 Quora 应用（OAuth 2.0 客户端）。资源所有者无法访问客户端（Quora OAuth 2.0 客户端）凭据和访问令牌，因为这些是存储在网络服务器上的。您可以在 OAuth 2.0 示例流程图中看到此行为，具体在以下步骤六到八中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/c9133c30-f9be-4f91-a386-04f8f57aa134.jpg)

OAuth 2.0 客户端网络应用配置文件

+   **基于用户代理的应用：** 基于用户代理的应用是公共客户端类型。在这种情况下，应用位于网络服务器上，但资源所有者将其下载到用户代理（例如，网络浏览器）上，然后在该设备上执行。在这里，下载并驻留在资源所有者设备上的用户代理中的应用与授权服务器通信。资源所有者可以访问客户端凭据和访问令牌。游戏应用是此类应用配置的一个很好的例子。用户代理应用流程如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/4d954ef4-70f8-468d-8564-c67d37a3bb74.jpg)

OAuth 2.0 客户端基于用户代理的应用配置文件

+   **原生应用：** 原生应用与基于用户代理的应用类似，不同之处在于这些应用是安装在资源所有者的设备上并原生执行的，而不是从网络服务器下载并在用户代理中执行。您在手机上下载的许多原生应用都属于原生应用类型。在这里，平台确保设备上的其他应用不能访问其他应用的凭据和访问令牌。此外，原生应用不应与与原生应用通信的服务器共享客户端凭据和 OAuth 令牌，如下面的图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/5ee3ee45-fea2-4a0a-b0f6-e3455073aa14.jpg)

OAuth 2.0 客户端原生应用配置文件

# 客户端标识符

授权服务器的责任是向注册客户端提供一个唯一标识符。此客户端标识符是注册客户端提供的信息的字符串表示。授权服务器需要确保此标识符是唯一的，并且授权服务器本身不应使用它进行身份验证。

OAuth 2.0 规范没有指定客户端标识符的大小。授权服务器可以设置客户端标识符的大小，并且应该文档化其发行的大小。

# 客户端认证

授权服务器应根据客户端类型验证客户端。授权服务器应确定适合并满足安全要求的认证方法。它应在每个请求中只使用一种认证方法。

通常，授权服务器使用一组客户端凭据，例如客户端密码和一些密钥令牌，来认证保密客户端。

授权服务器可能与公共客户端建立客户端认证方法。然而，出于安全原因，它不能依赖这种认证方法来识别客户端。

拥有客户端密码的客户端可以使用基本 HTTP 认证。OAuth 2.0 建议不要在请求体中发送客户端凭据，但建议在需要身份验证的端点上使用 TLS 和暴力攻击保护。

# OAuth 2.0 协议端点

端点不过是我们在 REST 或网络组件中使用的 URI，例如 Servlet 或 JSP。OAuth 2.0 定义了三种端点类型。其中两个是授权服务器端点，一个是客户端端点：

+   授权端点（授权服务器端点）

+   令牌端点（授权服务器端点）

+   重定向端点（客户端端点）

# 授权端点

这个端点负责验证资源所有者的身份，并在验证后获取授权许可。我们在下一节讨论授权许可。

授权服务器要求对授权端点使用 TLS。端点 URI 必须不包含片段组件。授权端点必须支持 HTTP `GET`方法。

规范没有指定以下内容：

+   授权服务器认证客户端的方式。

+   客户端如何接收授权端点的 URI。通常，文档包含授权端点的 URI，或者在注册时客户端获取它。

# 令牌端点

客户端调用令牌端点，通过发送授权许可或刷新令牌来接收访问令牌。除了隐式授权外，所有授权许可都使用令牌端点。

像授权端点一样，令牌端点也需要 TLS。客户端必须使用 HTTP `POST`方法对令牌端点提出请求。

像授权端点一样，规范没有指定客户端如何接收令牌端点的 URI。

# 重定向端点

授权服务器使用重定向端点将资源所有者的用户代理（例如，网络浏览器）回退到客户端，一旦资源所有者和授权服务器之间的授权端点的交互完成。客户端在注册时提供重定向端点。重定向端点必须是绝对 URI，并且不包含片段组件。OAuth 2.0 端点如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/91a2c588-bc2c-4ce5-8168-df96b8956dbf.jpg)

OAuth 2.0 端点

# OAuth 2.0 授权类型

客户端基于从资源所有者获得的授权，请求授权服务器授予访问令牌。资源所有者以授权授予的形式给予授权。OAuth 2.0 定义了四种授权授予类型：

+   授权码授予

+   隐式授予

+   资源所有者密码凭证授予

+   客户端凭据授予

OAuth 2.0 还提供了一种扩展机制来定义其他授予类型。你可以在官方 OAuth 2.0 规范中探索这一点。

# 授权码授予

我们在 OAuth 2.0 登录 Twitter 的示例流程中讨论的第一个样本流程显示了一个授权码授予。我们会在完整的流程中添加一些更多步骤。正如你所知，在第 8 步之后，最终用户登录到 Quora 应用。假设用户第一次登录到 Quora 并请求他们的 Quora 资料页面：

1.  登录后，Quora 用户点击他们的 Quora 资料页面。

1.  OAuth 客户端 Quora 请求 Twitter 资源服务器中 Quora 用户（资源所有者）的资源（例如，Twitter 资料照片等），并发送在上一步中收到的访问令牌。

1.  Twitter 资源服务器使用 Twitter 授权服务器来验证访问令牌。

1.  在成功验证访问令牌后，Twitter 资源服务器向 Quora（OAuth 客户端）提供所请求的资源。

1.  Quora 使用这些资源并显示最终用户的 Quora 资料页面。

**授权码请求和响应**

如果你查看全部的 13 个步骤（如下图中所示）的授权码授予流程，你可以看到客户端总共向授权服务器发起了两请求，授权服务器提供两个响应：一个用于认证令牌的请求-响应和一个用于访问令牌的请求-响应。

让我们讨论一下这些请求和响应中使用的参数：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/1f9ef543-affa-4dc3-b2d0-a753398f89bc.jpg)

OAuth 2.0 授权码授予流程

授权请求（第四步）到授权端点 URI：

| **参数** | **必需**/**可选** | **描述** |
| --- | --- | --- |
| `response_type` | 必需 | 代码（必须使用此值）。 |
| `client_id` | 必需 | 它代表授权服务器在注册时颁发的客户端 ID。 |
| `redirect_uri` | 可选 | 它代表客户端在注册时提供的重定向 URI。 |
| `scope` | 可选 | 请求的范围。如果没有提供，则授权服务器根据定义的策略提供范围。 |
| `state` | 推荐 | 客户端使用此参数在请求和回调（从授权服务器）之间保持客户端状态。规范推荐此参数以防止跨站请求伪造攻击。 |

授权响应（第五步）：

| `Parameter` | 必填/可选 | 描述 |
| --- | --- | --- |
| `code` | 必填 | 授权服务器生成的授权码。授权码应在生成后过期；最大推荐生存期为 10 分钟。客户端不得使用代码超过一次。如果客户端使用它超过一次，则必须拒绝请求，并撤销基于代码发行的所有先前令牌。代码与客户端 ID 和重定向 URI 绑定。 |
| `state` | 必填 | 代表授权服务器在注册时颁发给客户端的 ID。 |

令牌请求（第七步）至令牌端点 URI： |

| `Parameter` | 必填/可选 | 描述 |
| --- | --- | --- |
| `---` | --- | --- |
| `grant_type` | 必填 | 授权码（此值必须使用）。 |
| `code` | 必填 | 从授权服务器接收的授权码。 |
| `redirect_uri` | 必填 | 如果包含在授权码请求中，则必须匹配。 |
| `client_id` | 必填 | 代表授权服务器在注册时颁发给客户端的 ID。 |

令牌响应（第八步）： |

| `Parameter` | 必填/可选 | 描述 |
| --- | --- | --- |
| `access_token` | 必填 | 授权服务器颁发的访问令牌。 |
| `token_type` | 必填 | 授权服务器定义的令牌类型。根据此，客户端可以使用访问令牌。例如，Bearer 或 Mac。 |
| `refresh_token` | 可选 | 客户端可以使用此令牌使用相同的授权授予获取新的访问令牌。 |
| `expires_in` | 推荐 | 表示访问令牌的生存期，以秒为单位。600 的值表示访问令牌的 10 分钟生存期。如果此参数未包含在响应中，则文档应突出显示访问令牌的生存期。 |
| `scope` | 可选/必填 | 如果与客户端请求的 scope 相同，则为可选。如果访问令牌的 scope 与客户端在其请求中提供的 scope 不同，则为必填，以通知客户端实际授予的访问令牌的 scope。如果客户端在请求访问令牌时未提供 scope，则授权服务器应提供默认 scope，或拒绝请求，指示无效 scope。 |

错误响应： |

| `Parameter` | 必填/可选 | 描述 |
| --- | --- | --- |
| `error` | 必填 | 指定中的错误代码之一，例如 `unauthorized_client` 或 `invalid_scope`。 |
| `error_description` | 可选 | 错误简短描述。 |
| `error_uri` | 可选 | 描述错误的页面 URI。 |

如果客户端授权请求中传递了状态，则在错误响应中也发送一个附加的错误参数状态。 |

# 隐式授权 |

隐式许可流中不涉及授权码步骤。它提供隐式授权码。如果你比较隐式许可流与授权码许可流，除了授权码步骤，一切都是一样的。因此，它被称为隐式许可。让我们找出它的流程：

1.  客户端应用程序（例如，Quora）将访问令牌请求发送给资源服务器（例如，Facebook、Twitter 等），附带客户端 ID、重定向 URI 等。

1.  如果用户尚未认证，可能需要进行认证。在成功认证和其他输入验证后，资源服务器发送访问令牌。

1.  OAuth 客户端请求用户（资源所有者）的资源（例如，Twitter 个人资料照片等）从资源服务器，并发送在上一步收到的访问令牌。

1.  资源服务器使用授权服务器来验证访问令牌。

1.  在成功验证访问令牌后，资源服务器将请求的资源提供给客户端应用程序（OAuth 客户端）。

1.  客户端应用程序使用这些资源。

**隐式许可请求和响应**

如果你查看了隐式许可流的所有步骤（总共六个），你可以看到客户端向授权服务器发出了总共两个请求，授权服务器提供两个响应：一个用于访问令牌的请求-响应和一个用于访问令牌验证的请求-响应。

让我们讨论这些请求和响应中使用的参数。

向授权端点 URI 的授权请求：

| `**参数**` | `**必需**/**可选**` | `**描述**` |
| --- | --- | --- |
| `response_type` | 必需 | 令牌（必须使用此值）。 |
| `client_id` | 必需 | 它代表授权服务器在注册时发给客户端的 ID。 |
| `redirect_uri` | 可选 | 它代表客户端在注册时提供的重定向 URI。 |
| `scope` | 可选 | 请求的范围。如果没有提供，则授权服务器根据定义的策略提供范围。 |
| `state` | 推荐 | 客户端使用此参数在请求和回调（从授权服务器）之间维护客户端状态。规范建议使用它以防止跨站请求伪造攻击。 |

访问令牌响应：

| `**参数**` | `**必需**/**可选**` | `**描述**` |
| --- | --- | --- |
| `---` | `---` | `---` |
| `access_token` | 必需 | 授权服务器发行的访问令牌。 |
| `token_type` | 必需 | 授权服务器定义的令牌类型。根据此类型，客户端可以利用访问令牌。例如，Bearer 或 Mac。 |
| `refresh_token` | 可选 | 客户端可以使用该令牌来使用相同的授权许可获取新的访问令牌。 |
| `expires_in` | 推荐 | 表示访问令牌的生存期，以秒为单位。600 的值表示访问令牌的 10 分钟生存期。如果这个参数在响应中没有提供，那么文档应该强调访问令牌的生存期。 |
| `scope` | 可选/必填 | 如果与客户端请求的 scope 相同，则为可选。如果授予的访问令牌 scope 与客户端在请求中提供的 scope 不同，则为必填，以通知客户端授予的访问令牌的实际 scope。如果客户端在请求访问令牌时没有提供 scope，则授权服务器应提供默认 scope，或拒绝请求，指示无效 scope。 |
| `state` | 可选/必填 | 如果客户端授权请求中传递了状态，则为必填。 |

错误响应：

| **参数** | **必填**/**可选** | **描述** |
| --- | --- | --- |
| `error` | 必填 | 定义在规范中的错误代码之一，例如 `unauthorized_client` 或 `invalid_scope`。 |
| `error_description` | 可选 | 错误的精简描述。 |
| `error_uri` | 可选 | 描述错误的错误页面的 URI。 |

在错误响应中还发送了一个额外的状态参数，如果客户端授权请求中传递了状态。

# 资源所有者密码凭证授权

这种流程通常用于移动或桌面应用程序。在这个授权流程中，只发起两个请求：一个用于请求访问令牌，另一个用于访问令牌验证，类似于隐式授权流程。唯一的区别是访问令牌请求中附带了资源所有者的用户名和密码。（在隐式授权中，通常在浏览器中，将用户重定向到认证页面。）让我们来看看它的流程：

1.  客户端应用程序（例如，Quora）将访问令牌请求发送到资源服务器（例如，Facebook、Twitter 等），其中包括客户端 ID、资源所有者的用户名和密码等。在成功验证参数后，资源服务器发送访问令牌。

1.  OAuth 客户端请求资源服务器上的用户（资源所有者）的资源（例如，Twitter 个人资料照片等），并发送在上一步收到的访问令牌。

1.  资源服务器使用授权服务器验证访问令牌。

1.  在成功验证访问令牌后，资源服务器向客户端应用程序（OAuth 客户端）提供所请求的资源。

1.  客户端应用程序使用这些资源。

资源所有者的密码凭证用于授权请求和响应。

如前所述，在资源所有者密码凭据授予流程的所有步骤（共五个步骤）中，您可以看到客户端向授权服务器发出了两个请求，并且授权服务器提供了两个响应：一个用于访问令牌的请求-响应，一个用于资源所有者资源的请求-响应。

让我们讨论每个请求和响应中使用的参数。

访问令牌请求到令牌端点 URI：

| **参数** | **必需**/**可选** | **描述** |
| --- | --- | --- |
| `grant_type` | 必需 | 密码（必须使用此值）。 |
| `username` | 必需 | 资源所有者的用户名。 |
| `password` | 必需 | 资源所有者的密码。 |
| `scope` | 可选 | 请求的范围。如果未提供，则授权服务器根据定义的策略提供范围。 |

访问令牌响应（第一步）：

| **参数** | **必需**/**可选** | **描述** |
| --- | --- | --- |
| `access_token` | 必需 | 授权服务器颁发的访问令牌。 |
| `token_type` | 必需 | 授权服务器定义的令牌类型。基于此，客户端可以利用访问令牌。例如，Bearer 或 Mac。 |
| `refresh_token` | 可选 | 客户端可以使用此令牌使用相同的授权授予获取新的访问令牌。 |
| `expires_in` | 建议 | 以秒为单位表示访问令牌的生命周期。600 的值表示访问令牌的生命周期为 10 分钟。如果响应中未提供此参数，则文档应突出显示访问令牌的生命周期。 |
| 可选参数 | 可选 | 额外参数。 |

# 客户端凭据授予

正如其名称所示，在这里，使用客户端凭据而不是用户（资源所有者）的凭据。除了客户端凭据，它与资源所有者密码凭据授予流程非常相似：

1.  客户端应用程序（例如 Quora）使用授予类型和范围将访问令牌请求发送到资源服务器（例如 Facebook、Twitter 等）。客户端 ID 和密码添加到授权标头。验证成功后，资源服务器发送访问令牌。

1.  OAuth 客户端从资源服务器请求用户（资源所有者）的资源（例如 Twitter 个人资料照片等），并发送上一步收到的访问令牌。

1.  资源服务器使用授权服务器验证访问令牌。

1.  验证访问令牌成功后，资源服务器将所请求的资源提供给客户端应用程序（OAuth 客户端）。

1.  客户端应用程序使用这些资源。

客户端凭据授予请求和响应。

如果您查看了客户端凭据授予流程的所有步骤（共五个步骤），您可以

可以看到客户端总共向授权服务器发出了两个请求，授权服务器提供了两个响应：一个请求-响应用于访问令牌和一个请求-响应用于涉及访问令牌验证的资源。

让我们讨论一下每个这些请求和响应中使用的参数。

访问令牌请求到令牌端点的 URI：

| `Parameter` | `Required`/**optional** | `Description` |
| --- | --- | --- |
| `grant_type` | 必需 | `client_credentials`（必须使用此值）。 |
| `scope` | 可选 | 请求的范围。如果没有提供，则授权服务器根据定义的策略提供范围。 |

访问令牌响应：

| `Parameter` | `Required`/**optional** | `Description` |
| --- | --- | --- |
| `access_token` | 必需 | 授权服务器颁发的访问令牌。 |
| `token_type` | 必需 | 授权服务器定义的令牌类型。根据此，客户端可以利用访问令牌。例如，Bearer 或 Mac。 |
| `expires_in` | 推荐 | 表示访问令牌的生存期，以秒为单位。600 的值表示访问令牌的 10 分钟生存期。如果没有在响应中提供此参数，则文档应突出显示访问令牌的生存期。 |

# OAuth 使用 Spring Security 实现

OAuth 2.0 是一种保护 API 的方法。Spring Security 提供了 Spring Cloud Security 和 Spring Cloud OAuth2 组件来实现我们之前讨论的授权流。

我们将再创建一个服务，一个安全服务，它将控制认证和授权。

创建一个新的 Maven 项目，并按照以下步骤操作：

1.  在`pom.xml`中添加 Spring Security 和 Spring Security OAuth 2 依赖项：

```java
 <dependency> 
   <groupId>org.springframework.cloud</groupId> 
   <artifactId>spring-cloud-starter-security</artifactId> 
</dependency> 
<dependency> 
   <groupId>org.springframework.cloud</groupId> 
   <artifactId>spring-cloud-starter-oauth2</artifactId> 
</dependency> 
```

1.  在您的应用程序类中使用`@EnableResourceServer`注解。这将允许此应用程序作为资源服务器运行。`@EnableAuthorizationServer`注解是我们将使用以根据 OAuth 2.0 规范启用授权服务器的另一个注解：

```java
@SpringBootApplication 
@RestController 
@EnableResourceServer 
public class SecurityApp { 

    @RequestMapping("/user") 
    public Principal user(Principal user) { 
        return user; 
    } 

    public static void main(String[] args) { 
        SpringApplication.run(SecurityApp.class, args); 
    } 

    @Configuration 
    @EnableAuthorizationServer 
    protected static class OAuth2Config extends AuthorizationServerConfigurerAdapter { 

        @Autowired 
        private AuthenticationManager authenticationManager; 

        @Override 
        public void configure(AuthorizationServerEndpointsConfigurer endpointsConfigurer) throws Exception { 
            endpointsConfigurer.authenticationManager(authenticationManager); 
        } 

        @Override 
        public void configure(ClientDetailsServiceConfigurer clientDetailsServiceConfigurer) throws Exception { 
  // Using hardcoded inmemory mechanism because it is just an example 
            clientDetailsServiceConfigurer.inMemory() 
             .withClient("acme") 
             .secret("acmesecret") 
             .authorizedGrantTypes("authorization_code", "refresh_token", "implicit", "password", "client_credentials") 
             .scopes("webshop"); 
        } 
    } 
}
```

1.  更新`application.yml`中的安全服务配置，如下代码所示：

+   `server.contextPath`：这表示上下文路径

+   `security.user.password`: 本示例将使用硬编码的密码。您可以为其真实应用重新配置：

```java
application.yml 
info: 
    component: 
        Security Server 

server: 
    port: 9001 
    ssl: 
        key-store: classpath:keystore.jks 
        key-store-password: password 
        key-password: password 
    contextPath: /auth 

security: 
    user: 
        password: password 

logging: 
    level: 
        org.springframework.security: DEBUG 
```

现在我们已经有了我们的安全服务器，我们将使用新的`api-service`微服务暴露我们的 API，该服务将用于与外部应用程序和 UI 通信。

我们将修改 Zuul-Server 模块，使其也成为资源服务器。这可以通过以下步骤完成：

1.  添加 Spring Security 和 Spring Security OAuth 2 依赖项：

    到`pom.xml`。在此，最后两个依赖项是启用 Zuul-Server 作为资源服务器所需的：

```java
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-starter-zuul</artifactId> 
</dependency> 
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-starter-eureka</artifactId> 
</dependency> 
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-starter-feign</artifactId> 
</dependency> 
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-netflix-hystrix-stream</artifactId> 
</dependency> 
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-starter-bus-amqp</artifactId> 
</dependency> 
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-starter-stream-rabbit</artifactId> 
</dependency> 
<dependency> 
    <groupId>org.springframework.boot</groupId> 
    <artifactId>spring-boot-starter-web</artifactId> 
</dependency> 
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-starter-security</artifactId> 
</dependency> 
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-starter-oauth2</artifactId>         </dependency>
```

1.  在您的应用程序类中使用`@EnableResourceServer`注解。这将允许此应用程序作为资源服务器运行：

```java
@SpringBootApplication 
@EnableZuulProxy 
@EnableEurekaClient 
@EnableCircuitBreaker 
@Configuration 
@EnableFeignClients 
@EnableResourceServer 
public class EdgeApp { 

    private static final Logger LOG = LoggerFactory.getLogger(EdgeApp.class); 

    static { 
        // for localhost testing only 
        LOG.warn("Will now disable hostname check in SSL, only to be used during development"); 
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, sslSession) -> true); 
    } 

    @Value("${app.rabbitmq.host:localhost}") 
    String rabbitMqHost; 

    @Bean 
    public ConnectionFactory connectionFactory() { 
        LOG.info("Create RabbitMqCF for host: {}", rabbitMqHost); 
        CachingConnectionFactory connectionFactory = new CachingConnectionFactory(rabbitMqHost); 
        return connectionFactory; 
    } 

    public static void main(String[] args) { 
        SpringApplication.run(EdgeApp.class, args); 
    } 
} 
```

1.  更新`Zuul-Server`配置文件中的`application.yml`，如下所示的代码。`application.yml`文件看起来可能会像这样：

```java
info: 
    component: Zuul Server 

spring: 
  application: 
     name: zuul-server  # Service registers under this name 
  # Added to fix -  java.lang.IllegalArgumentException: error at ::0 can't find referenced pointcut hystrixCommandAnnotationPointcut 
  aop: 
      auto: false 

zuul: 
    ignoredServices: "*" 
    routes: 
        restaurantapi: 
            path: /api/** 
            serviceId: api-service 
            stripPrefix: true 

server: 
    ssl: 
        key-store: classpath:keystore.jks 
        key-store-password: password 
        key-password: password 
    port: 8765 
    compression: 
        enabled: true 

security: 
  oauth2: 
    resource: 
     userInfoUri: https://localhost:9001/auth/user 

management: 
  security: 
    enabled: false 
## Other properties like Eureka, Logging and so on 
```

这里，`security.oauth2.resource.userInfoUri`属性表示安全服务用户 URI。API 通过指向 API 服务的路由配置暴露给外部世界。

现在我们已经有了安全服务器，我们通过`api-service`微服务暴露我们的 API，该服务将用于与外部应用程序和 UI 通信。

现在，让我们测试并探索不同 OAuth 2.0 授予类型的运作方式。

我们将使用 Postman 浏览器扩展来测试不同的流程。

# 授权码授予

我们将在浏览器中输入以下 URL。请求授权码如下：

```java
https://localhost:9001/auth/oauth/authorize?response_type=code&client_id=client&redirect_uri=http://localhost:7771/1&scope=apiAccess&state=1234
```

在这里，我们提供客户端 ID（默认情况下，我们在安全服务中注册了硬编码的客户端）、重定向 URI、范围（在安全服务中硬编码的`apiAccess`值）和状态。您可能会想知道`state`参数。它包含了一个我们在响应中重新验证的随机数，以防止跨站请求伪造。

如果资源所有者（用户）尚未经过身份验证，它会要求输入用户名和密码。输入用户名`username`和密码`password`；我们在安全服务中硬编码了这些值。

登录成功后，它会要求您提供您的（资源所有者）批准：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/c1420332-d7fe-4fdb-8283-dda0ddcce291.png)

OAuth 2.0 授权码授予 - 资源授予批准

选择批准并点击授权。这个操作会将应用程序重定向到`http://localhost:7771/1?code=o8t4fi&state=1234`。

正如你所看到的，它返回了授权代码和状态。

现在，我们将使用这个代码来检索访问代码，使用 Postman Chrome 扩展。首先，我们将使用用户名作为客户端，密码作为`clientsecret`来添加授权头，如下所示的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/78666832-c5a5-4bc3-add2-f7288380f37c.png)

OAuth 2.0 授权码授予 - 访问令牌请求 - 添加身份验证

这会将`Authorization`头添加到请求中，值为`Basic Y2xpZW50OmNsaWVudHNlY3JldA==`，这是'client client-secret'的 base-64 编码。

现在，我们将向请求中添加几个其他参数，如下的屏幕截图，然后提交请求：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/f80b3537-1b8e-4e59-8993-ca06c5b9197a.png)

OAuth 2.0 授权码授予 - 访问令牌请求和响应

根据 OAuth 2.0 规范，这会返回以下响应：

```java
{
  "access_token": "6a233475-a5db-476d-8e31-d0aeb2d003e9",
  "token_type": "bearer", 
  "refresh_token": "8d91b9be-7f2b-44d5-b14b-dbbdccd848b8", 
  "expires_in": 43199, 
  "scope": "apiAccess" 
} 
```

现在，我们可以使用这些信息来访问资源拥有者的资源。例如，如果`https://localhost:8765/api/restaurant/1`代表 ID 为`1`的餐厅，那么它应该返回相应的餐厅详情。

没有访问令牌，如果我们输入 URL，它会返回错误`Unauthorized`，消息为`Full authentication is required to access this resource`。

现在，让我们使用访问令牌访问这个网址，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/7ad7dda0-294b-4576-a9b4-832beb4312e8.png)

OAuth 2.0 授权码授权 - 使用访问令牌访问 API

正如您所看到的，我们添加了带有访问令牌的授权头。

现在，我们将探讨隐式授权实现的实现。

# 隐式授权

隐式授权与授权码授权非常相似，除了授权码步骤之外。如果您移除授权码授权的第一个步骤（客户端应用程序从授权服务器接收授权令牌的步骤），其余步骤都相同。让我们来查看一下。

在浏览器中输入以下 URL 和参数并按 Enter。同时，请确保如果需要，添加基本认证，将客户端作为`username`，将密码作为`password`：

```java
https://localhost:9001/auth/oauth/authorize?response_type=token&redirect_uri=https://localhost:8765&scope=apiAccess&state=553344&client_id=client
```

在这里，我们使用以下请求参数调用授权端点：响应类型、客户端 ID、重定向 URI、范围和状态。

当请求成功时，浏览器将被重定向到以下 URL，带有新的请求参数和值：

```java
https://localhost:8765/#access_token=6a233475-a5db-476d-8e31-d0aeb2d003e9&token_type=bearer&state=553344&expires_in=19592
```

在这里，我们接收到`access_token`、`token_type`、状态和令牌的过期持续时间。现在，我们可以利用这个访问令牌来访问 API，就像在授权码授权中使用一样。

# 资源所有者密码凭据授权

在这个授权中，我们请求访问令牌时提供`username`和`password`作为参数，以及`grant_type`、`client`和`scope`参数。我们还需要使用客户端 ID 和密钥来验证请求。这些授权流程使用客户端应用程序代替浏览器，通常用于移动和桌面应用程序。

在下面的 Postman 工具截图中，已使用`client_id`和`password`进行基本认证，并添加了授权头：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/72fb8839-d705-47f9-84ea-8890276bfc61.png)

OAuth 2.0 资源所有者密码凭据授权 - 访问令牌请求和响应

一旦客户端接收到访问令牌，它可以用类似的方式使用，就像在授权码授权中使用一样。

# 客户端凭据授权

在这个流程中，客户端提供自己的凭据以获取访问令牌。它不使用资源所有者的凭据和权限。

正如您在下面的截图中看到的，我们直接输入只有两个参数的令牌端点：`grant_type`和`scope`。授权头使用`client_id`和`client secret`添加：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/972a2e60-28b1-423a-adde-38c2fa61afc2.png)

OAuth 2.0 客户端凭据授权 - 访问令牌请求和响应

您可以像授权码授权中解释的那样使用访问令牌。

# 参考文献

更多信息，您可以参考以下链接：

+   《RESTful Java Web Services Security》，*René Enríquez, Andrés Salazar C*，*Packt Publishing*: [`www.packtpub.com/application-development/restful-java-web-services-security`](https://www.packtpub.com/application-development/restful-java-web-services-security)

+   《Spring Security [Video]》，*Packt Publishing*: [`www.packtpub.com/application-development/spring-security-video`](https://www.packtpub.com/application-development/spring-security-video)

+   OAuth 2.0 授权框架：[`tools.ietf.org/html/rfc6749`](https://tools.ietf.org/html/rfc6749)

+   春安全: [`projects.spring.io/spring-security`](http://projects.spring.io/spring-security)

+   春 auth2: [`projects.spring.io/spring-security-oauth/`](http://projects.spring.io/spring-security-oauth/)

# 摘要

在本章中，我们了解到拥有 TLS 层或 HTTPS 对所有网络流量的重要性。我们已经向示例应用程序添加了自签名的证书。我想再次强调，对于生产应用程序，您必须使用证书授权机构提供的证书。我们还探讨了 OAuth 2.0 的基本原理和各种 OAuth 2.0 授权流。不同的 OAuth 2.0 授权流是使用 Spring Security 和 OAuth 2.0 实现的。在下一章中，我们将实现示例 OTRS 项目的 UI，并探讨所有组件是如何一起工作的。


# 第八章：使用微服务网络应用程序消费服务

现在，在开发了微服务之后，将很有趣地看看在线表格预订系统（OTRS）提供的服务如何被网络或移动应用程序消费。我们将使用 AngularJS/Bootstrap 开发网络应用程序（UI）的原型。这个示例应用程序将显示这个示例项目的数据和流程——一个小型实用程序项目。这个网络应用程序也将是一个示例项目，并可以独立运行。以前，网络应用程序是在单个网络归档（具有 `.war` 扩展名的文件）中开发的，其中包含 UI 和服务器端代码。这样做的原因相当简单，因为 UI 也是使用 Java、JSP、servlet、JSF 等开发的。现在，UI 是独立使用 JavaScript 开发的。因此，这些 UI 应用程序也作为单个微服务部署。在本章中，我们将探讨这些独立 UI 应用程序是如何开发的。我们将开发并实现没有登录和授权流的 OTRS 示例应用程序。我们将部署一个功能非常有限的应用程序，并涵盖高级 AngularJS 概念。有关 AngularJS 的更多信息，请参考《AngularJS 示例》、《Chandermani》、《Packt Publishing》。

在本章中，我们将涵盖以下主题：

+   AngularJS 框架概述

+   OTRS 功能的开发

+   设置网络应用程序（UI）

# AngularJS 框架概述

现在，既然我们已经完成了 HTML5 网络应用程序的设置，我们可以了解 AngularJS 的基础知识。这将帮助我们理解 AngularJS 代码。本节描述了你可以利用的高级理解水平，以理解示例应用程序并进一步使用 AngularJS 文档或参考其他 Packt Publishing 资源。

AngularJS 是一个客户端 JavaScript 框架。它足够灵活，可以作为**模型-视图-控制器**（**MVC**）或**模型-视图-视图模型**（**MVVM**）使用。它还提供内置服务，如使用依赖注入模式的 `$http` 或 `$log`。

# MVC

模型-视图-控制器（MVC）是一种众所周知的设计模式。Struts 和 Spring MVC 是流行的例子。让我们看看它们如何适用于 JavaScript 世界：

+   **模型**：模型是包含应用程序数据的 JavaScript 对象。它们还表示应用程序的状态。

+   **视图**：视图是由 HTML 文件组成的表示层。在这里，你可以显示来自模型的数据并提供用户交互界面。

+   **控制器**：你可以在 JavaScript 中定义控制器，其中包含应用程序逻辑。

# MVVM

MVVM 是一种针对 UI 开发的设计模式。MVVM 旨在使双向数据绑定变得更容易。双向数据绑定提供了模型和视图之间的同步。当模型（数据）发生变化时，它立即反映在视图上。类似地，当用户在视图上更改数据时，它也会反映在模型上：

+   **模型**：这与 MVC 非常相似，包含业务逻辑和数据。

+   **视图**：与 MVC 类似，它包含呈现逻辑或用户界面。

+   **视图模型**：视图模型包含视图和模型之间的数据绑定。因此，它是视图和模型之间的接口。

# 模块

模块是我们为任何 AngularJS 应用程序定义的第一个东西。模块是一个包含应用程序不同部分的容器，如控制器、服务、过滤器等。AngularJS 应用程序可以写在一个单一的模块中，也可以写在多个模块中。AngularJS 模块也可以包含其他模块。

许多其他 JavaScript 框架使用`main`方法来实例化和连接应用程序的不同部分。AngularJS 没有`main`方法。它由于以下原因使用模块作为入口点：

+   **模块化**：你可以根据应用程序功能或可重用组件来划分和创建应用程序。

+   **简洁性**：你可能遇到过复杂且庞大的应用程序代码，这使得维护和升级成为头疼的事。不再如此：AngularJS 使代码变得简单、可读且易于理解。

+   **测试**：它使单元测试和端到端测试变得容易，因为你可以覆盖配置并只加载所需的模块。

每个 AngularJS 应用程序需要有一个单一的模块来启动 AngularJS 应用程序。启动我们的应用程序需要以下三个部分：

+   **应用程序模块**：一个包含 AngularJS 模块的 JavaScript 文件（`app.js`），如下所示：

```java
var otrsApp = AngularJS.module('otrsApp', [ ]) 
// [] contains the reference to other modules 
```

+   **加载 Angular 库和应用程序模块**：一个包含对其他 AngularJS 库的 JavaScript 文件的引用和一个`index.html`文件：

```java
<script type="text/javascript" src="img/angular.min.js"></script> 
<script type="text/javascript" src="img/app.js"></script>
```

+   **应用程序 DOM 配置**：这告诉 AngularJS 应用程序的 DOM 元素的启动位置。它可以以两种方式之一完成：

1.  一个`index.html`文件，其中还包含一个 HTML 元素（通常是`<html>`）和一个具有在`app.js`中给出的值的`ng-app`（AngularJS 指令）属性：`<html lang="zh" ng-app="otrsApp" class="no-js">`。AngularJS 指令前缀为`ng`（AngularJS）：`<html lang="en" ng-app="otrsApp" class="no-js">`。

1.  或者，如果你是以异步方式加载 JavaScript 文件的话，请使用这个命令：`AngularJS.bootstrap(document.documentElement, ['otrsApp']);`。

一个 AngularJS 模块有两个重要的部分，`config()`和`run()`，除了控制器、服务、过滤器等其他组件：

+   `config()`用于注册和配置模块，并只处理使用`$injector`的提供者和常量。`$injector`是 AngularJS 服务。我们在下一节介绍提供者和`$injector`。在这里不能使用实例。它防止在完全配置之前使用服务。

+   `run()`方法用于在通过前面的`config()`方法创建`$injector`之后执行代码。它只处理实例和常量。在这里不能使用提供商，以避免在运行时进行配置。

# 提供商和服务

让我们看一下以下的代码：

```java
.controller('otrsAppCtrl', function ($injector) { 
var log = $injector.get('$log'); 
```

`$log`是一个内置的 AngularJS 服务，提供了日志 API。在这里，我们使用了另一个内置服务——`$injector`，它允许我们使用`$log`服务。`$injector`是控制器的一个参数。AngularJS 使用函数定义和正则表达式为调用者（即控制器）提供`$injector`服务，这正是 AngularJS 有效使用依赖注入模式的示例。

AngularJS 大量使用依赖注入模式，使用注入器服务（`$injector`）来实例化和连接我们用在 AngularJS 应用程序中的大多数对象。这个注入器创建了两种类型的对象——服务和特殊对象。

为了简化，你可以认为我们（开发者）定义服务。相反，特殊对象是 AngularJS 项目，如控制器、过滤器、指令等。

AngularJS 提供了五种告诉注入器如何创建服务对象的食谱类型——**提供商**、**值**、**工厂**、**服务**和**常量**。

+   提供商是核心且最复杂的食谱类型。其他的食谱都是建立在其上的合成糖。我们通常避免使用提供商，除非我们需要创建需要全局配置的可重用代码。

+   值和常量食谱类型正如其名称所暗示的那样工作。它们都不能有依赖关系。此外，它们之间的区别在于它们的用法。在配置阶段你不能使用值服务对象。

+   工厂和服务是最常用的服务类型。它们属于相似的类型。当我们想要生产 JavaScript 原始值和函数时，我们使用工厂食谱。另一方面，当我们要生产自定义定义的类型时，我们使用服务。

由于我们现在对服务有一定的了解，我们可以认为服务有两个常见的用途——组织代码和跨应用程序共享代码。服务是单例对象，由 AngularJS 服务工厂延迟实例化。我们已经看到了一些内置的 AngularJS 服务，比如`$injector`、`$log`等。AngularJS 服务前缀为`$`符号。

# 作用域

在 AngularJS 应用程序中，广泛使用了两种作用域——`$rootScope`和`$scope`：

+   `$rootScope` 是作用域层次结构中最顶层的对象，与全局作用域相关联。这意味着您附加上它的任何变量都将无处不在可用，因此，使用 `$rootScope` 应该是一个经过深思熟虑的决定。

+   控制器在回调函数中有一个 `$scope` 作为参数。它用于将控制器中的数据绑定到视图。其作用域仅限于与它关联的控制器使用。

# 控制器

控制器通过 JavaScript 的 `constructor` 函数定义，拥有 `$scope` 作为参数。控制器的主要目的是将数据绑定到视图。控制器函数也用于编写业务逻辑——设置 `$scope` 对象的初始状态和向 `$scope` 添加行为。控制器签名如下：

```java
RestModule.controller('RestaurantsCtrl', function ($scope, restaurantService) { 
```

在这里，控制器是 `RestModule` 的一部分，控制器的名称是 `RestaurantCtrl`，`$scope` 和 `restaurantService` 被作为参数传递。

# 过滤器

过滤器的目的是格式化给定表达式的值。在以下代码中，我们定义了 `datetime1` 过滤器，它接受日期作为参数并将其值更改为 `dd MMM yyyy HH:mm` 格式，例如 `04 Apr 2016 04:13 PM`：

```java
.filter('datetime1', function ($filter) { 
    return function (argDateTime) { 
        if (argDateTime) { 
            return $filter('date')(new Date(argDateTime), 'dd MMM yyyy HH:mm a'); 
        } 
        return ""; 
    }; 
});
```

# 指令

正如我们在*模块*部分所看到的，AngularJS 指令是带有 `ng` 前缀的 HTML 属性。一些常用的指令包括：

+   `ng-app`：这个指令定义了 AngularJS 应用程序

+   `ng-model`：这个指令将 HTML 表单输入绑定到数据

+   `ng-bind`：这个指令将数据绑定到 HTML 视图

+   `ng-submit`：这个指令提交 HTML 表单

+   `ng-repeat`：这个指令遍历集合：

```java
<div ng-app=""> 
    <p>Search: <input type="text" ng-model="searchValue"></p> 
    <p ng-bind="searchedTerm"></p> 
</div>
```

# UI-Router

在**单页应用程序**（**SPA**）中，页面只加载一次，用户通过不同的链接进行导航，而无需刷新页面。这都是因为路由。路由是一种使 SPA 导航感觉像正常网站的方法。因此，路由对 SPA 非常重要。

AngularUI 团队开发了 UI-Router，这是一个 AngularJS 的路由框架。UI-Router 并不是 AngularJS 核心的一部分。当用户在 SPA 中点击任何链接时，UI-Router 不仅会改变路由 URL，还会改变应用程序的状态。由于 UI-Router 也可以进行状态更改，因此您可以在不改变 URL 的情况下更改页面的视图。这是因为在 UI-Router 的管理下实现了应用程序状态管理。

如果我们把 SPA 看作是一个状态机，那么状态就是应用程序的当前状态。当我们创建路由链接时，我们会在 HTML 链接标签中使用 `ui-sref` 属性。链接中的 `href` 属性由此生成，并指向在 `app.js` 中创建的应用程序的某些状态。

我们使用 HTML `div` 中的 `ui-view` 属性来使用 UI-Router。例如，

`<div ui-view></div>`。

# 开发 OTRS 功能

正如您所知，我们正在开发 SPA。因此，一旦应用程序加载，您可以在不刷新页面的情况下执行所有操作。所有与服务器的交互都是通过 AJAX 调用完成的。现在，我们将利用我们在第一部分中介绍的 AngularJS 概念。我们将涵盖以下场景：

+   一个将显示餐厅列表的页面。这也将是我们的主页。

+   搜索餐厅。

+   带有预订选项的餐厅详情。

+   登录（不是从服务器上，而是用于显示流程）。

+   预订确认。

对于主页，我们将创建一个`index.html`文件和一个模板，该模板将包含中间部分（或内容区域）的餐厅列表。

# 主页/餐厅列表页

主页是任何网络应用程序的主要页面。为了设计主页，我们将使用 Angular-UI Bootstrap，而不是实际的 Bootstrap。Angular-UI 是 Bootstrap 的 Angular 版本。主页将分为三个部分：

+   头部部分将包含应用程序名称、搜索餐厅表单以及顶部右角的用户名。

+   内容或中间部分将包含餐厅列表，这些列表将使用餐厅名称作为链接。此链接将指向餐厅详情和预订页面。

+   页脚部分将包含带有版权标志的应用程序名称。

您可能对在设计或实现之前查看主页感兴趣。因此，让我们首先看看一旦我们的内容准备就绪，它将看起来如何：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/43192e48-94ba-4302-b413-5182d9d1da4f.png)

OTRS 主页带有餐厅列表

现在，为了设计我们的主页，我们需要添加以下四个文件：

+   `index.html`：我们的主 HTML 文件

+   `app.js`：我们的主 AngularJS 模块

+   `restaurants.js`：包含餐厅 Angular 服务的餐厅模块

+   `restaurants.html`：将显示列表的 HTML 模板

    餐厅

# `index.html`

首先，我们将`./app/index.html`添加到我们的项目工作区。`index.html`文件的内容将从这里开始解释。

我在代码之间添加了注释，以使代码更具可读性，更容易理解。

`index.html`文件分为许多部分。在这里我们将讨论一些关键部分。首先，我们将了解如何解决旧版本的 Internet Explorer。如果您想针对大于八版的 Internet Explorer 浏览器或 IE 九版及以后的版本，那么我们需要添加以下代码块，这将阻止 JavaScript 渲染并给最终用户输出`no-js`：

```java
<!--[if lt IE 7]>      <html lang="en" ng-app="otrsApp" class="no-js lt-ie9 lt-ie8 lt-ie7"> <![endif]--> 
<!--[if IE 7]>         <html lang="en" ng-app="otrsApp" class="no-js lt-ie9 lt-ie8"> <![endif]--> 
<!--[if IE 8]>         <html lang="en" ng-app="otrsApp" class="no-js lt-ie9"> <![endif]--> 
<!--[if gt IE 8]><!--> <html lang="en" ng-app="otrsApp" class="no-js"> <!--<![endif]--> 
```

然后，在添加几个`meta`标签和应用程序的标题之后，我们还将定义重要的`meta`标签`viewport`。`viewport`用于响应式 UI 设计。

在内容属性中定义的`width`属性控制`viewport`的大小。它可以设置为特定的像素值，例如`width = 600`，或者设置为特殊的`device-width`值，该值在 100%的缩放比例下是屏幕的宽度。

`initial-scale`属性控制页面首次加载时的缩放级别。`max-scale`、`min-scale`和`user-scalable`属性控制用户如何允许缩放页面：

```java
<meta name="viewport" content="width=device-width, initial-scale=1"> 
```

在接下来的几行中，我们将定义我们应用程序的样式表。我们从 HTML5 模板代码中添加了`normalize.css`和`main.css`。我们还添加了我们应用程序的自定义 CSS`app.css`。最后，我们添加了 Bootstrap 3 的 CSS。除了自定义的`app.css`之外，其他 CSS 都在其中引用。这些 CSS 文件没有变化：

```java
<link rel="stylesheet" href="bower_components/html5-boilerplate/dist/css/normalize.css"> 
<link rel="stylesheet" href="bower_components/html5-boilerplate/dist/css/main.css"> 
<link rel="stylesheet" href="public/css/app.css"> 
<link data-require="bootstrap-css@*" data-server="3.0.0" rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.0.0/css/bootstrap.min.css" /> 
```

然后，我们将使用`script`标签定义脚本。我们添加了现代 izer、Angular、Angular-route 和`app.js`，我们自己的开发的定制 JavaScript 文件。

我们已经讨论了 Angular 和 Angular-UI。`app.js`将在

下一节。

现代 izer 允许网络开发者在维持对不支持它们的浏览器的精细控制的同时使用新的 CSS3 和 HTML5 功能。基本上，现代 izer 在页面在浏览器中加载时执行下一代特性检测（检查这些特性的可用性）并报告结果。根据这些结果，您可以检测到浏览器中最新可用的特性，根据这些特性，您可以为最终用户提供一个界面。如果浏览器不支持一些特性，那么将向最终用户提供替代流程或 UI。

我们还将添加 Bootstrap 模板，这些模板是用 JavaScript 编写的，使用`ui-bootstrap-tpls javascript`文件：

```java
<script src="img/modernizr-2.8.3.min.js"></script> 
<script src="img/angular.min.js"></script> 
<script src="img/angular-route.min.js"></script> 
<script src="img/app.js"></script> 
<script data-require="ui-bootstrap@0.5.0" data-semver="0.5.0" src="img/ui-bootstrap-tpls-0.6.0.js"></script> 
```

我们还可以向`head`标签添加样式，如下面的代码所示。这些样式允许下拉菜单正常工作：

```java
<style> 
    div.navbar-collapse.collapse { 
      display: block; 
      overflow: hidden; 
      max-height: 0px; 
      -webkit-transition: max-height .3s ease; 
      -moz-transition: max-height .3s ease; 
      -o-transition: max-height .3s ease; 
      transition: max-height .3s ease; 
      } 
    div.navbar-collapse.collapse.in { 
      max-height: 2000px; 
      } 
</style> 
```

在`body`标签中，我们使用

`ng-controller`属性。在页面加载时，它告诉控制器将应用程序名称告诉 Angular，如下所示：

```java
<body ng-controller="otrsAppCtrl"> 
```

然后，我们定义主页的`header`部分。在`header`部分，我们将定义应用程序标题`在线餐桌预订系统`。此外，我们还将定义搜索餐厅的搜索表单：

```java
<!-- BEGIN HEADER --> 
        <nav class="navbar navbar-default" role="navigation"> 

            <div class="navbar-header"> 
                <a class="navbar-brand" href="#"> 
                    Online Table Reservation System 
                </a> 
            </div> 
            <div class="collapse navbar-collapse" ng-class="!navCollapsed && 'in'" ng-click="navCollapsed = true"> 
                <form class="navbar-form navbar-left" role="search" ng-submit="search()"> 
                    <div class="form-group"> 
                        <input type="text" id="searchedValue" ng-model="searchedValue" class="form-control" placeholder="Search Restaurants"> 
                    </div> 
                    <button type="submit" class="btn btn-default" ng-click="">Go</button> 
                </form> 
        <!-- END HEADER --> 
```

然后，下一节，中间部分，包括我们实际绑定了不同的视图，用实际的内容注释标记。`div`中的`ui-view`属性动态地从 Angular 获取其内容，例如餐厅详情、餐厅列表等。我们还为中间部分添加了警告对话框和加载动画，根据需要显示：

```java
<div class="clearfix"></div> 
    <!-- BEGIN CONTAINER --> 
    <div class="page-container container"> 
        <!-- BEGIN CONTENT --> 
        <div class="page-content-wrapper"> 
            <div class="page-content"> 
                <!-- BEGIN ACTUAL CONTENT --> 
                <div ui-view class="fade-in-up"></div> 
                <!-- END ACTUAL CONTENT --> 
            </div> 
        </div> 
        <!-- END CONTENT --> 
    </div> 
    <!-- loading spinner --> 
    <div id="loadingSpinnerId" ng-show="isSpinnerShown()" style="top:0; left:45%; position:absolute; z-index:999"> 
        <script type="text/ng-template" id="alert.html"> 
            <div class="alert alert-warning" role="alert"> 
            <div ng-transclude></div> 
            </div> 
        </script> 
        <uib-alert type="warning" template-url="alert.html"><b>Loading...</b></uib-alert> 
    </div> 
        <!-- END CONTAINER --> 
```

`index.html`的最后一部分是页脚。在这里，我们只是添加了静态内容和版权文本。您可以在這裡添加任何您想要的内容：

```java
        <!-- BEGIN FOOTER --> 
        <div class="page-footer"> 
            <hr/><div style="padding: 0 39%">&copy; 2016 Online Table Reservation System</div> 
        </div> 
        <!-- END FOOTER --> 
    </body> 
</html> 
```

# app.js

`app.js`是我们的主应用程序文件。因为我们已经在`index.html`中定义了它，

它在我们的`index.html`被调用时就已经加载。

我们需要注意不要将路由（URI）与 REST 端点混合。路由代表了 SPA 的状态/视图。

由于我们使用边缘服务器（代理服务器），一切都可以通过它访问，包括我们的 REST 端点。外部应用程序（包括 UI）将使用边缘服务器的宿主来访问应用程序。您可以在全局常量文件中配置它，然后在需要的地方使用它。这将允许您在单一位置配置 REST 主机并在其他地方使用它：

```java
'use strict'; 
/* 
This call initializes our application and registers all the modules, which are passed as an array in the second argument. 
*/ 
var otrsApp = angular.module('otrsApp', [ 
    'ui.router', 
    'templates', 
    'ui.bootstrap', 
    'ngStorage', 
    'otrsApp.httperror', 
    'otrsApp.login', 
    'otrsApp.restaurants' 
]) 
/* 
  Then we have defined the default route /restaurants 
*/ 
        .config([ 
            '$stateProvider', '$urlRouterProvider', 
            function ($stateProvider, $urlRouterProvider) { 
                $urlRouterProvider.otherwise('/restaurants'); 
            }]) 
/* 
   This functions controls the flow of the application and handles the events. 
*/ 
        .controller('otrsAppCtrl', function ($scope, $injector, restaurantService) { 
            var controller = this; 

            var AjaxHandler = $injector.get('AjaxHandler'); 
            var $rootScope = $injector.get('$rootScope'); 
            var log = $injector.get('$log'); 
            var sessionStorage = $injector.get('$sessionStorage'); 
            $scope.showSpinner = false; 
/* 
   This function gets called when the user searches any restaurant. It uses the Angular restaurant service that we'll define in the next section to search the given search string. 
*/ 
            $scope.search = function () { 
                $scope.restaurantService = restaurantService; 
                restaurantService.async().then(function () { 
                    $scope.restaurants = restaurantService.search($scope.searchedValue); 
                }); 
            } 
/* 
   When the state is changed, the new controller controls the flows based on the view and configuration and the existing controller is destroyed. This function gets a call on the destroy event. 
*/ 
            $scope.$on('$destroy', function destroyed() { 
                log.debug('otrsAppCtrl destroyed'); 
                controller = null; 
                $scope = null; 
            }); 

            $rootScope.fromState; 
            $rootScope.fromStateParams; 
            $rootScope.$on('$stateChangeSuccess', function (event, toState, toParams, fromState, fromStateParams) { 
                $rootScope.fromState = fromState; 
                $rootScope.fromStateParams = fromStateParams; 
            }); 

            // utility method 
            $scope.isLoggedIn = function () { 
                if (sessionStorage.session) { 
                    return true; 
                } else { 
                    return false; 
                } 
            }; 

            /* spinner status */ 
            $scope.isSpinnerShown = function () { 
                return AjaxHandler.getSpinnerStatus(); 
            }; 

        }) 
/* 
   This function gets executed when this object loads. Here we are setting the user object which is defined for the root scope. 
*/ 
        .run(['$rootScope', '$injector', '$state', function ($rootScope, $injector, $state) { 
                $rootScope.restaurants = null; 
                // self reference 
                var controller = this; 
                // inject external references 
                var log = $injector.get('$log'); 
                var $sessionStorage = $injector.get('$sessionStorage'); 
                var AjaxHandler = $injector.get('AjaxHandler'); 

                if (sessionStorage.currentUser) { 
                    $rootScope.currentUser = $sessionStorage.currentUser; 
                } else { 
                    $rootScope.currentUser = "Guest"; 
                    $sessionStorage.currentUser = "" 
                } 
            }]) 
```

# restaurants.js

`restaurants.js`代表了我们应用程序中一个用于餐厅的 Angular 服务，我们将在搜索、列表、详情等不同模块间使用它。我们知道服务的两个常见用途是组织代码和跨应用程序共享代码。因此，我们创建了一个餐厅服务，它将在不同的模块（如搜索、列表、详情等）间使用。

服务是单例对象，由 AngularJS 服务工厂延迟实例化。

以下部分初始化了餐厅服务模块并加载了所需的依赖项：

```java
angular.module('otrsApp.restaurants', [ 
    'ui.router', 
    'ui.bootstrap', 
    'ngStorage', 
    'ngResource' 
]) 
```

在配置中，我们使用 UI-Router 定义了`otrsApp.restaurants`模块的路线和状态：

首先，我们通过传递包含指向路由 URI 的 URL、指向显示`restaurants`状态的 HTML 模板的 URL 以及将处理`restaurants`视图上事件的路由器来定义`restaurants`状态。

在`restaurants`视图（`route - /restaurants`）之上，还定义了一个嵌套的`restaurants.profile`状态，它将代表特定的餐厅。例如，`/restaurant/1`会打开并显示代表`Id 1`的餐厅的概要（详情）页面。当在`restaurants`模板中点击链接时，这个状态会被调用。在这个`ui-sref="restaurants.profile({id: rest.id})"`中，`rest`代表了从`restaurants`视图中检索到的`restaurant`对象。

请注意，状态名是`'restaurants.profile'`，这告诉 AngularJS UI-Router `restaurants`状态的概要是一个嵌套状态：

```java
        .config([ 
            '$stateProvider', '$urlRouterProvider', 
            function ($stateProvider, $urlRouterProvider) { 
                $stateProvider.state('restaurants', { 
                    url: '/restaurants', 
                    templateUrl: 'restaurants/restaurants.html', 
                    controller: 'RestaurantsCtrl' 
                }) 
                        // Restaurant show page 
                        .state('restaurants.profile', { 
                            url: '/:id', 
                            views: { 
                                '@': { 
                                    templateUrl: 'restaurants/restaurant.html', 
                                    controller: 'RestaurantCtrl' 
                                } 
                            } 
                        }); 
            }]) 
```

在下一个代码部分，我们使用 Angular 工厂服务类型定义了餐厅服务。这个餐厅服务在加载时通过 REST 调用从服务器获取餐厅列表。它提供了餐厅操作的列表和搜索餐厅数据：

```java
        .factory('restaurantService', function ($injector, $q) { 
            var log = $injector.get('$log'); 
            var ajaxHandler = $injector.get('AjaxHandler'); 
            var deffered = $q.defer(); 
            var restaurantService = {}; 
            restaurantService.restaurants = []; 
            restaurantService.orignalRestaurants = []; 
            restaurantService.async = function () { 
                ajaxHandler.startSpinner(); 
                if (restaurantService.restaurants.length === 0) { 
                    ajaxHandler.get('/api/restaurant') 
                            .success(function (data, status, headers, config) { 
                                log.debug('Getting restaurants'); 
                                sessionStorage.apiActive = true; 
                                log.debug("if Restaurants --> " + restaurantService.restaurants.length); 
                                restaurantService.restaurants = data; 
                                ajaxHandler.stopSpinner(); 
                                deffered.resolve(); 
                            }) 
                            .error(function (error, status, headers, config) { 
                                restaurantService.restaurants = mockdata; 
                                ajaxHandler.stopSpinner(); 
                                deffered.resolve(); 
                            }); 
                    return deffered.promise; 
                } else { 
                    deffered.resolve(); 
                    ajaxHandler.stopSpinner(); 
                    return deffered.promise; 
                } 
            }; 
            restaurantService.list = function () { 
                return restaurantService.restaurants; 
            }; 
            restaurantService.add = function () { 
                console.log("called add"); 
                restaurantService.restaurants.push( 
                        { 
                            id: 103, 
                            name: 'Chi Cha\'s Noodles', 
                            address: '13 W. St., Eastern Park, New County, Paris', 
                        }); 
            }; 
            restaurantService.search = function (searchedValue) { 
                ajaxHandler.startSpinner(); 
                if (!searchedValue) { 
                    if (restaurantService.orignalRestaurants.length > 0) { 
                        restaurantService.restaurants = restaurantService.orignalRestaurants; 
                    } 
                    deffered.resolve(); 
                    ajaxHandler.stopSpinner(); 
                    return deffered.promise; 
                } else { 
                    ajaxHandler.get('/api/restaurant?name=' + searchedValue) 
                            .success(function (data, status, headers, config) { 
                                log.debug('Getting restaurants'); 
                                sessionStorage.apiActive = true; 
                                log.debug("if Restaurants --> " + restaurantService.restaurants.length); 
                                if (restaurantService.orignalRestaurants.length < 1) { 
                                    restaurantService.orignalRestaurants = restaurantService.restaurants; 
                                } 
                                restaurantService.restaurants = data; 
                                ajaxHandler.stopSpinner(); 
                                deffered.resolve(); 
                            }) 
                            .error(function (error, status, headers, config) { 
                                if (restaurantService.orignalRestaurants.length < 1) { 
                                    restaurantService.orignalRestaurants = restaurantService.restaurants; 
                                } 
                                restaurantService.restaurants = []; 
                                restaurantService.restaurants.push( 
                                        { 
                                            id: 104, 
                                            name: 'Gibsons - Chicago Rush St.', 
                                            address: '1028 N. Rush St., Rush & Division, Cook County, Paris' 
                                        }); 
                                restaurantService.restaurants.push( 
                                        { 
                                            id: 105, 
                                            name: 'Harry Caray\'s Italian Steakhouse', 
                                            address: '33 W. Kinzie St., River North, Cook County, Paris', 
                                        }); 
                                ajaxHandler.stopSpinner(); 
                                deffered.resolve(); 
                            }); 
                    return deffered.promise; 
                } 
            }; 
            return restaurantService; 
        }) 
```

在`restaurants.js`模块的下一部分，我们将添加两个控制器，我们在路由配置中为`restaurants`和`restaurants.profile`状态定义了这两个控制器。这两个控制器分别是`RestaurantsCtrl`和`RestaurantCtrl`，它们分别处理`restaurants`状态和`restaurants.profiles`状态。

`RestaurantsCtrl`控制器相当简单，它使用餐厅服务列表方法加载餐厅数据：

```java
        .controller('RestaurantsCtrl', function ($scope, restaurantService) { 
            $scope.restaurantService = restaurantService; 
            restaurantService.async().then(function () { 
                $scope.restaurants = restaurantService.list(); 
            }); 
        }) 
```

`RestaurantCtrl`控制器负责显示给定 ID 的餐厅详情。这也负责对显示的餐厅执行预订操作。当设计带有预订选项的餐厅详情页面时，将使用这个控制器：

```java
        .controller('RestaurantCtrl', function ($scope, $state, $stateParams, $injector, restaurantService) { 
            var $sessionStorage = $injector.get('$sessionStorage'); 
            $scope.format = 'dd MMMM yyyy'; 
            $scope.today = $scope.dt = new Date(); 
            $scope.dateOptions = { 
                formatYear: 'yy', 
                maxDate: new Date().setDate($scope.today.getDate() + 180), 
                minDate: $scope.today.getDate(), 
                startingDay: 1 
            }; 

            $scope.popup1 = { 
                opened: false 
            }; 
            $scope.altInputFormats = ['M!/d!/yyyy']; 
            $scope.open1 = function () { 
                $scope.popup1.opened = true; 
            }; 
            $scope.hstep = 1; 
            $scope.mstep = 30; 

            if ($sessionStorage.reservationData) { 
                $scope.restaurant = $sessionStorage.reservationData.restaurant; 
                $scope.dt = new Date($sessionStorage.reservationData.tm); 
                $scope.tm = $scope.dt; 
            } else { 
                $scope.dt.setDate($scope.today.getDate() + 1); 
                $scope.tm = $scope.dt; 
                $scope.tm.setHours(19); 
                $scope.tm.setMinutes(30); 
                restaurantService.async().then(function () { 
                    angular.forEach(restaurantService.list(), function (value, key) { 
                        if (value.id === parseInt($stateParams.id)) { 
                            $scope.restaurant = value; 
                        } 
                    }); 
                }); 
            } 
            $scope.book = function () { 
                var tempHour = $scope.tm.getHours(); 
                var tempMinute = $scope.tm.getMinutes(); 
                $scope.tm = $scope.dt; 
                $scope.tm.setHours(tempHour); 
                $scope.tm.setMinutes(tempMinute); 
                if ($sessionStorage.currentUser) { 
                    console.log("$scope.tm --> " + $scope.tm); 
                    alert("Booking Confirmed!!!"); 
                    $sessionStorage.reservationData = null; 
                    $state.go("restaurants"); 
                } else { 
                    $sessionStorage.reservationData = {}; 
                    $sessionStorage.reservationData.restaurant = $scope.restaurant; 
                    $sessionStorage.reservationData.tm = $scope.tm; 
                    $state.go("login"); 
                } 
            } 
        }) 
```

我们还在`restaurants.js`模块中添加了几个筛选器来格式化日期和时间。这些筛选器对输入数据执行以下格式化：

+   `date1`：返回输入日期，格式为`dd MMM yyyy`，例如，`13-Apr-2016`

+   `time1`：返回输入时间，格式为 HH:mm:ss，例如，`11:55:04`

+   `dateTime1`：返回输入日期和时间，格式为`dd MMM yyyy HH:mm:ss`，例如，`13-Apr-2016 11:55:04`

在下面的代码片段中，我们应用了这三个筛选器：

```java
        .filter('date1', function ($filter) { 
            return function (argDate) { 
                if (argDate) { 
                    var d = $filter('date')(new Date(argDate), 'dd MMM yyyy'); 
                    return d.toString(); 
                } 
                return ""; 
            }; 
        }) 
        .filter('time1', function ($filter) { 
            return function (argTime) { 
                if (argTime) { 
                    return $filter('date')(new Date(argTime), 'HH:mm:ss'); 
                } 
                return ""; 
            }; 
        }) 
        .filter('datetime1', function ($filter) { 
            return function (argDateTime) { 
                if (argDateTime) { 
                    return $filter('date')(new Date(argDateTime), 'dd MMM yyyy HH:mm a'); 
                } 
                return ""; 
            }; 
        }); 
```

# restaurants.html

我们需要添加为`restaurants.profile`状态定义的模板。正如你所见，在模板中，我们使用`ng-repeat`指令来遍历由`restaurantService.restaurants`返回的对象列表。`restaurantService`作用域变量在控制器中定义。`'RestaurantsCtrl'`与这个模板在`restaurants`状态中相关联：

```java
<h3>Famous Gourmet Restaurants in Paris</h3> 
<div class="row"> 
    <div class="col-md-12"> 
        <table class="table table-bordered table-striped"> 
            <thead> 
                <tr> 
                    <th>#Id</th> 
                    <th>Name</th> 
                    <th>Address</th> 
                </tr> 
            </thead> 
            <tbody> 
                <tr ng-repeat="rest in restaurantService.restaurants"> 
                    <td>{{rest.id}}</td> 
                    <td><a ui-sref="restaurants.profile({id: rest.id})">{{rest.name}}</a></td> 
                    <td>{{rest.address}}</td> 
                </tr> 
            </tbody> 
        </table> 
    </div> 
</div> 
```

# 搜索餐厅

在主页`index.html`中，我们在`header`部分添加了搜索表单，用于搜索餐厅。搜索餐厅功能将使用前面描述的相同文件。它使用`app.js`（搜索表单处理程序）、`restaurants.js`（餐厅服务）和`restaurants.html`来显示搜索到的记录：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/b40a4348-76e8-435b-a8cb-384039b8b5a8.png)

OTRS 主页带餐厅列表

# 带有预订选项的餐厅详情

带有预订选项的餐厅详情将作为内容区域（页面中间部分）的一部分。这部分将包含一个顶部面包屑，带有餐厅链接至餐厅列表页面，随后是餐厅的名称和地址。最后部分将包含预订部分，包含日期和时间选择框和一个预订按钮。

此页面将如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/efbae38e-baf9-455f-8379-4b5cdd67bf1b.png)

餐厅详情页面带预订选项

在这里，我们将使用在`restaurants.js`中声明的相同的餐厅服务。

唯一的变化将是模板，正如为`restaurants.profile`状态描述的那样。这个模板将使用`restaurant.html`定义。

# restaurant.html

正如你所见，面包屑正在使用`restaurants`路由，这是使用`ui-sref`属性定义的。在这个模板中设计的预订表单在表单提交时使用`ng-submit`指令调用控制器`RestaurantCtrl`中的`book()`函数：

```java
<div class="row"> 
<div class="row"> 
    <div class="col-md-12"> 
        <ol class="breadcrumb"> 
            <li><a ui-sref="restaurants">Restaurants</a></li> 
            <li class="active">{{restaurant.name}}</li> 
        </ol> 
        <div class="bs-docs-section"> 
            <h1 class="page-header">{{restaurant.name}}</h1> 
            <div> 
                <strong>Address:</strong> {{restaurant.address}} 
            </div> 
            </br></br> 
            <form ng-submit="book()"> 
                <div class="input-append date form_datetime"> 
                    <div class="row"> 
                        <div class="col-md-7"> 
                            <p class="input-group"> 
                                <span style="display: table-cell; vertical-align: middle; font-weight: bolder; font-size: 1.2em">Select Date & Time for Booking:</span> 
                                <span style="display: table-cell; vertical-align: middle"> 
                                    <input type="text" size=20 class="form-control" uib-datepicker-popup="{{format}}" ng-model="dt" is-open="popup1.opened" datepicker-options="dateOptions" ng-required="true" close-text="Close" alt-input-formats="altInputFormats" /> 
                                </span> 
                                <span class="input-group-btn"> 
                                    <button type="button" class="btn btn-default" ng-click="open1()"><i class="glyphicon glyphicon-calendar"></i></button> 
                                </span> 
                            <uib-timepicker ng-model="tm" ng-change="changed()" hour-step="hstep" minute-step="mstep"></uib-timepicker> 
                            </p> 
                        </div> 
                    </div></div> 
                <div class="form-group"> 
                    <button class="btn btn-primary" type="submit">Reserve</button> 
                </div> 
            </form></br></br> 
        </div> 
    </div> 
</div> 
```

# 登录页面

当用户在选择预订日期和时间后点击餐厅详情页面上的“预订”按钮时，餐厅详情页面会检查用户是否已经登录。如果用户没有登录，那么将显示登录页面。它的样子如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/829ecbf3-dbee-4ed3-80f4-653c622b1671.png)

登录页面

我们不是从服务器上验证用户。相反，我们只是将用户名填充到会话存储和根作用域中，以实现流程。

一旦用户登录，他们将被重定向回带有持久状态的同一预订页面。然后，用户可以继续预订。登录页面基本上使用两个文件：`login.html`和`login.js`。

# 登录.html

`login.html`模板只包含两个输入字段，分别是用户名和密码，以及登录按钮和取消链接。取消链接重置表单，登录按钮提交登录表单。

在这里，我们使用`LoginCtrl`与`ng-controller`指令。登录表单使用`ng-submit`指令提交，该指令调用`LoginCtrl`的`submit`函数。首先使用`ng-model`指令收集输入值，然后使用它们的相应属性 - `_email`和`_password`提交：

```java
<div ng-controller="LoginCtrl as loginC" style="max-width: 300px"> 
    <h3>Login</h3> 
    <div class="form-container"> 
        <form ng-submit="loginC.submit(_email, _password)"> 
            <div class="form-group"> 
                <label for="username" class="sr-only">Username</label> 
                <input type="text" id="username" class="form-control" placeholder="username" ng-model="_email" required autofocus /> 
            </div> 
            <div class="form-group"> 
                <label for="password" class="sr-only">Password</label> 
                <input type="password" id="password" class="form-control" placeholder="password" ng-model="_password" /> 
            </div> 
            <div class="form-group"> 
                <button class="btn btn-primary" type="submit">Login</button> 
                <button class="btn btn-link" ng-click="loginC.cancel()">Cancel</button> 
            </div> 
        </form> 
    </div> 
</div> 
```

# 登录.js

登录模块定义在`login.js`文件中，该文件使用`module`函数包含和加载依赖项。使用`config`函数定义登录状态，该函数接收包含`url`、`控制器`和`templateUrl`属性的 JSON 对象。

在`controller`内部，我们定义了`取消`和`提交`操作，这些操作是从`login.html`模板中调用的：

```java
angular.module('otrsApp.login', [ 
    'ui.router', 
    'ngStorage' 
]) 
        .config(function config($stateProvider) { 
            $stateProvider.state('login', { 
                url: '/login', 
                controller: 'LoginCtrl', 
                templateUrl: 'login/login.html' 
            }); 
        }) 
        .controller('LoginCtrl', function ($state, $scope, $rootScope, $injector) { 
            var $sessionStorage = $injector.get('$sessionStorage'); 
            if ($sessionStorage.currentUser) { 
                $state.go($rootScope.fromState.name, $rootScope.fromStateParams); 
            } 
            var controller = this; 
            var log = $injector.get('$log'); 
            var http = $injector.get('$http'); 

            $scope.$on('$destroy', function destroyed() { 
                log.debug('LoginCtrl destroyed'); 
                controller = null; 
                $scope = null; 
            }); 
            this.cancel = function () { 
                $scope.$dismiss; 
                $state.go('restaurants'); 
            } 
            console.log("Current --> " + $state.current); 
            this.submit = function (username, password) { 
                $rootScope.currentUser = username; 
                $sessionStorage.currentUser = username; 
                if ($rootScope.fromState.name) { 
                    $state.go($rootScope.fromState.name, $rootScope.fromStateParams); 
                } else { 
                    $state.go("restaurants"); 
                } 
            }; 
        });
```

# 预订确认

一旦用户登录并点击了预订按钮，餐厅控制器将显示带有确认信息的弹窗，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/dfa8dc28-1080-49fa-aa56-86c3ca29acb2.png)

餐厅详情页面带预订确认

# 设置网络应用程序

因为我们计划使用最新的技术堆栈来开发我们的 UI 应用程序，我们将使用 Node.js 和**npm**（**Node.js 包管理器**），它们为开发服务器端 JavaScript 网络应用程序提供了开源运行环境。

我建议您浏览这一部分。它将向您介绍 JavaScript 构建工具和堆栈。然而，如果您已经了解 JavaScript 构建工具，或者不想探索它们，您可以跳过这一部分。

Node.js 基于 Chrome 的 V8 JavaScript 引擎，并使用事件驱动、非阻塞 I/O，使其轻量级且高效。Node.js 的默认包管理器 npm 是最大的开源库生态系统。它允许安装 Node.js 程序，并使指定和链接依赖项变得更容易：

1.  首先，如果尚未安装，我们需要安装 npm。这是一个先决条件。你可以通过访问链接来安装 npm：[`docs.npmjs.com/getting-started/installing-node`](https://docs.npmjs.com/getting-started/installing-node)。

1.  要检查 npm 是否正确设置，请在命令行界面（CLI）上执行`npm -v`命令。它应该在输出中返回已安装的 npm 版本。我们可以切换到 NetBeans 来创建一个新的 AngularJS JS HTML5 项目。在本章撰写之时，我使用的是 NetBeans 8.1。

1.  导航到文件|新建项目。一个新项目对话框应该会出现。选择“HTML5/JavaScript”在类别列表中，以及“HTML5/JS 应用程序”在项目选项中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/c5bce51d-efdb-40ce-b615-50fe03a9b569.png)

NetBeans - 新 HTML5/JavaScript 项目

1.  点击“下一步”按钮。然后，在“名称和位置”对话框中输入项目名称、项目位置、

    和在项目文件夹中点击

    下一步按钮：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/3c602ecc-b62d-4a0a-95a6-da19f131c495.png)

NetBeans 新项目 - 名称和位置

1.  在“网站模板”对话框中，选择“下载在线模板”选项下的 AngularJS Seed 项目，然后点击“下一步”按钮。AngularJS Seed 项目可在以下网址找到：[`github.com/angular/angular-seed`](https://github.com/angular/angular-seed)：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/4a404d56-6b00-4c9e-89cf-b2b2b2297910.png)

NetBeans 新项目 - 网站模板

1.  在“工具”对话框中，选择创建`package.json`、创建`bower.json`和创建`gulpfile.js`。我们将使用 gulp 作为我们的构建工具。Gulp 和 Grunt 是 JS 最流行的构建框架之二。作为一个 Java 程序员，你可以将这些工具与 Ant 相关联。两者都有自己的优点。如果你愿意，你也可以使用`Gruntfile.js`作为构建工具：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/976ef34a-cba5-492c-8002-d218f577e5d6.png)

Netbeans 新项目 - 工具

1.  现在，一旦你点击完成，你就可以看到 HTML5/JS 应用程序目录和文件。目录结构将如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/d648df11-ae57-4cdb-9c23-1df565f87006.png)

AngularJS 种子目录结构

1.  如果你的项目中所有必需的依赖项都没有正确配置，你还会看到一个感叹号。你可以通过右键点击项目，然后选择“解决项目问题”选项来解决项目问题：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/8f574c16-80be-4778-be6f-f3c5173b582a.png)

解决项目问题对话框

1.  理想情况下，NetBeans 会在你点击“解决...”按钮时解决项目问题。

1.  你还可以通过为一些 JS 模块（如 Bower、gulp 和 Node）提供正确的路径来解决几个问题：

+   **Bower**：用于管理 OTRS 应用程序的 JavaScript 库

+   **Gulp**：任务运行器，用于构建我们的项目，如 ANT

+   **Node**：用于执行我们的服务器端 OTRS 应用程序

Bower 是一个依赖管理工具，它像 npm 一样工作。npm 用于安装 Node.js 模块，而 Bower 用于管理您的网络应用程序的库/组件。

1.  点击工具菜单并选择选项。现在，设置 Bower、gulp 和 Node.js 的路径，如以下屏幕截图所示。要设置 Bower 路径，请点击 Bower 标签，如下面的屏幕截图所示，并更新路径：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/d5186eb3-34cf-4f81-9a39-88fcba50a37f.png)

设置 Bower 路径

1.  要设置 Gulp 路径，请点击 Gulp 标签，如下面的屏幕截图所示，并更新路径：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/6319ca05-d1a5-4538-927e-44b41c22b949.png)

设置 Gulp 路径

1.  设置 Node 路径，请点击 Node.js 标签，如以下屏幕截图所示，并更新路径：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/7cc72097-0710-483a-9b83-d04b9a095ff8.png)

设置 Node 路径

1.  完成后，package.json 将如下所示。我们对一些条目的值进行了修改，如名称、描述、依赖项等：

```java
{ 
  "name": "otrs-ui", 
  "private": true, 
  "version": "1.0.0", 
  "description": "Online Table Reservation System", 
  "main": "index.js", 
  "license": "MIT", 
  "dependencies": { 
    "coffee-script": "¹.10.0", 
    "del": "¹.1.1", 
    "gulp-angular-templatecache": "¹.9.1", 
    "gulp-clean": "⁰.3.2", 
    "gulp-connect": "³.2.3", 
    "gulp-file-include": "⁰.13.7", 
    "gulp-sass": "².3.2", 
    "gulp-util": "³.0.8", 
    "run-sequence": "¹.2.2" 
  }, 
  "devDependencies": { 
    "coffee-script": "*", 
    "gulp-sass": "*", 
    "bower": "¹.3.1", 
    "http-server": "⁰.6.1", 
    "jasmine-core": "².3.4", 
    "karma": "~0.12", 
    "karma-chrome-launcher": "⁰.1.12", 
    "karma-firefox-launcher": "⁰.1.6", 
    "karma-jasmine": "⁰.3.5", 
    "karma-junit-reporter": "⁰.2.2", 
    "protractor": "².1.0", 
    "shelljs": "⁰.2.6" 
  }, 
  "scripts": { 
    "postinstall": "bower install", 
    "prestart": "npm install", 
    "start": "http-server -a localhost -p 8000 -c-1", 
    "pretest": "npm install", 
    "test": "karma start karma.conf.js", 
    "test-single-run": "karma start karma.conf.js  --single-run", 
    "preupdate-webdriver": "npm install", 
    "update-webdriver": "webdriver-manager update", 
    "preprotractor": "npm run update-webdriver", 
    "protractor": "protractor e2e-tests/protractor.conf.js", 
    "update-index-async": "node -e \"require('shelljs/global'); sed('-i', /\\/\\/@@NG_LOADER_START@@[\\s\\S]*\\/\\/@@NG_LOADER_END@@/, '//@@NG_LOADER_START@@\\n' + sed(/sourceMappingURL=angular-loader.min.js.map/,'sourceMappingURL=bower_components/angular-loader/angular-loader.min.js.map','app/bower_components/angular-loader/angular-loader.min.js') + '\\n//@@NG_LOADER_END@@', 'app/index-async.html');\"" 
  } 

}
```

1.  然后，我们将更新`bower.json`，如下面的代码片段所示：

```java
{ 
    "name": "OTRS-UI", 
    "description": "OTRS-UI", 
    "version": "0.0.1", 
    "license": "MIT", 
    "private": true, 
    "dependencies": { 
        "AngularJS": "~1.5.0", 
        "AngularJS-ui-router": "~0.2.18", 
        "AngularJS-mocks": "~1.5.0", 
        "AngularJS-bootstrap": "~1.2.1", 
        "AngularJS-touch": "~1.5.0", 
        "bootstrap-sass-official": "~3.3.6", 
        "AngularJS-route": "~1.5.0", 
        "AngularJS-loader": "~1.5.0", 
        "ngstorage": "⁰.3.10", 
        "AngularJS-resource": "¹.5.0", 
        "html5-boilerplate": "~5.2.0" 
    } 
} 
```

1.  接下来，我们将修改`.bowerrc`文件，如下面的代码所示，以指定 Bower 将在其中存储`bower.json`中定义的组件的目录。我们将 Bower 组件存储在应用程序目录下：

```java
{ 
  "directory": "app/bower_components" 
} 
```

1.  接下来，我们将设置`gulpfile.js`。我们将使用`CoffeeScript`定义`gulp`任务。因此，我们只需在`gulpfile.js`中定义`CoffeeScript`，实际的任务将在`gulpfile.coffee`文件中定义。让我们看看`gulpfile.js`文件的内容：

```java
require('coffee-script/register'); 
require('./gulpfile.coffee'); 
```

1.  在此步骤中，我们将定义`gulp`配置。我们使用`CoffeeScript`定义`gulp`文件。用`CoffeeScript`编写的`gulp`文件的名称是`gulpfile.coffee`。默认任务定义为`default_sequence`：

```java
default_sequence = ['connect', 'build', 'watch']
```

让我们了解`default_sequence`任务执行的内容：

+   根据定义的`default_sequence`任务，首先它会连接到服务器，然后构建网络应用程序，并监视更改。监视将帮助我们在代码中做出更改并在 UI 上立即显示。

+   此脚本中最重要的任务是`connect`和`watch`。其他任务不言自明。所以，让我们深入了解一下它们。

+   `gulp-connect`：这是一个`gulp`插件，用于运行网络服务器。它还支持实时重新加载。

+   `gulp-watch`：这是一个文件监视器，使用 chokidar，并发出 vinyl 对象（描述文件的路径和内容的对象）。简而言之，我们可以说`gulp-watch`监视文件更改并触发任务。

`gulpfile.coffee`可能看起来像这样：

```java
gulp          = require('gulp') 
gutil         = require('gulp-util') 
del           = require('del'); 
clean         = require('gulp-clean') 
connect       = require('gulp-connect') 
fileinclude   = require('gulp-file-include') 
runSequence   = require('run-sequence') 
templateCache = require('gulp-AngularJS-templatecache') 
sass          = require('gulp-sass') 

paths = 
  scripts: 
    src: ['app/src/scripts/**/*.js'] 
    dest: 'public/scripts' 
  scripts2: 
    src: ['app/src/views/**/*.js'] 
    dest: 'public/scripts' 
  styles: 
    src: ['app/src/styles/**/*.scss'] 
    dest: 'public/styles' 
  fonts: 
    src: ['app/src/fonts/**/*'] 
    dest: 'public/fonts' 
  images: 
    src: ['app/src/images/**/*'] 
    dest: 'public/images' 
  templates: 
    src: ['app/src/views/**/*.html'] 
    dest: 'public/scripts' 
  html: 
    src: ['app/src/*.html'] 
    dest: 'public' 
  bower: 
    src: ['app/bower_components/**/*'] 
    dest: 'public/bower_components' 

#copy bower modules to public directory 
gulp.task 'bower', -> 
  gulp.src(paths.bower.src) 
  .pipe gulp.dest(paths.bower.dest) 
  .pipe connect.reload() 

#copy scripts to public directory 
gulp.task 'scripts', -> 
  gulp.src(paths.scripts.src) 
  .pipe gulp.dest(paths.scripts.dest) 
  .pipe connect.reload() 

#copy scripts2 to public directory 
gulp.task 'scripts2', -> 
  gulp.src(paths.scripts2.src) 
  .pipe gulp.dest(paths.scripts2.dest) 
  .pipe connect.reload() 

#copy styles to public directory 
gulp.task 'styles', -> 
  gulp.src(paths.styles.src) 
  .pipe sass() 
  .pipe gulp.dest(paths.styles.dest) 
  .pipe connect.reload() 

#copy images to public directory 
gulp.task 'images', -> 
  gulp.src(paths.images.src) 
  .pipe gulp.dest(paths.images.dest) 
  .pipe connect.reload() 

#copy fonts to public directory 
gulp.task 'fonts', -> 
  gulp.src(paths.fonts.src) 
  .pipe gulp.dest(paths.fonts.dest) 
  .pipe connect.reload() 

#copy html to public directory 
gulp.task 'html', -> 
  gulp.src(paths.html.src) 
  .pipe gulp.dest(paths.html.dest) 
  .pipe connect.reload() 

#compile AngularJS template in a single js file 
gulp.task 'templates', -> 
  gulp.src(paths.templates.src) 
  .pipe(templateCache({standalone: true})) 
  .pipe(gulp.dest(paths.templates.dest)) 

#delete contents from public directory 
gulp.task 'clean', (callback) -> 
  del ['./public/**/*'], callback; 

#Gulp Connect task, deploys the public directory 
gulp.task 'connect', -> 
  connect.server 
    root: ['./public'] 
    port: 1337 
    livereload: true 

gulp.task 'watch', -> 
  gulp.watch paths.scripts.src, ['scripts'] 
  gulp.watch paths.scripts2.src, ['scripts2'] 
  gulp.watch paths.styles.src, ['styles'] 
  gulp.watch paths.fonts.src, ['fonts'] 
  gulp.watch paths.html.src, ['html'] 
  gulp.watch paths.images.src, ['images'] 
  gulp.watch paths.templates.src, ['templates'] 

gulp.task 'build', ['bower', 'scripts', 'scripts2', 'styles', 'fonts', 'images', 'templates', 'html'] 

default_sequence = ['connect', 'build', 'watch'] 

gulp.task 'default', default_sequence 

gutil.log 'Server started and waiting for changes' 
```

1.  一旦我们准备好前面的更改，我们将使用以下命令安装`gulp`：

```java
npm install --no-optional gulp
```

要在 Windows 环境中安装 Windows 构建工具，请运行以下命令：

```java
npm install --global --production windows-build-tools 
```

1.  此外，我们将使用以下命令安装其他`gulp`库，如`gulp-clean`、`gulp-connect`等：

```java
npm install --save --no-optional gulp-util gulp-clean gulp-connect gulp-file-include run-sequence gulp-angular-templatecache gulp-sass del coffee-script
```

1.  - 现在，我们可以使用以下命令安装`bower.json`文件中定义的 Bower 依赖项：

```java
bower install --s
```

- 如果尚未安装 Bower，请使用以下命令安装：

```java
npm install -g bower
```

- 前一条命令的输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/c00982cc-fe4d-4411-bcf5-a890c3a7ceeb.jpg)

- 示例输出 - bower install --s

1.  - 这里是设置的最后一步。在这里，我们将确认目录结构应如下所示。我们将把`src`和`published`构件（在`./public`目录中）作为独立的目录保存。因此，下面的目录结构与默认的 AngularJS 种子项目不同：

```java
+---app 
|   +---bower_components 
|   |   +---AngularJS 
|   |   +---AngularJS-bootstrap 
|   |   +---AngularJS-loader 
|   |   +---AngularJS-mocks 
|   |   +---AngularJS-resource 
|   |   +---AngularJS-route 
|   |   +---AngularJS-touch 
|   |   +---AngularJS-ui-router 
|   |   +---bootstrap-sass-official 
|   |   +---html5-boilerplate 
|   |   +---jquery 
|   |   \---ngstorage 
|   +---components 
|   |   \---version 
|   +---node_modules 
|   +---public 
|   |   \---css 
|   \---src 
|       +---scripts 
|       +---styles 
|       +---views 
+---e2e-tests 
+---nbproject 
|   \---private 
+---node_modules 
+---public 
|   +---bower_components 
|   +---scripts 
|   +---styles 
\---test
```

# - 参考资料

- 以下是一些推荐阅读的参考资料：

+   - 《AngularJS by Example》，Packt Publishing: [`www.packtpub.com/web-development/angularjs-example`](https://www.packtpub.com/web-development/angularjs-example)

+   - Angular Seed Project: [`github.com/angular/angular-seed`](https://github.com/angular/angular-seed)

+   - Angular UI: [`angular-ui.github.io/bootstrap/`](https://angular-ui.github.io/bootstrap/)

+   - Gulp: [`gulpjs.com/`](http://gulpjs.com/)

# - 摘要

- 在本章中，我们了解到了新的动态网络应用开发。

- 多年来，它已经发生了彻底的变化。网络应用的前端完全使用纯 HTML 和 JavaScript 开发，而不是使用任何服务器端技术，如 JSP、servlets、ASP 等。使用 JavaScript 开发的 UI 应用程序现在有其自己的开发环境，如 npm、Bower 等。我们探讨了 AngularJS 框架来开发我们的网络应用程序。它通过提供内置特性和对 Bootstrap 以及处理 AJAX 调用的`$http`服务的支持，使事情变得更容易。

- 我希望您已经掌握了 UI 开发的概述以及现代应用程序是如何与服务器端微服务集成开发的。在下一章中，我们将学习微服务设计的最优实践和常见原则。本章将提供有关使用行业实践和示例进行微服务开发的详细信息。它还将包含微服务实施出错的示例以及如何避免这些问题。
