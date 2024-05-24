# Kubernetes 和 Docker 企业级指南（三）

> 原文：[`zh.annas-archive.org/md5/9023162EFAC3D4D142381E2C55E3B624`](https://zh.annas-archive.org/md5/9023162EFAC3D4D142381E2C55E3B624)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三部分：在企业中运行 Kubernetes

在本节的最后部分，我们将深入探讨集群在企业中所需的附加组件。第一个主题将解释如何使用企业目录集成身份和访问管理。然后，我们将专注于保护集群，首先是如何部署安全的 Kubernetes 仪表板，这通常被视为安全问题。以仪表板为例，我们将解释如何使用身份提供者使用基于角色的访问控制（RBAC）来保护集群。

超越基本的 RBAC，我们将看到如何使用 Pod 安全策略和 Open Policy Agent 来保护集群。最后，我们将通过实施 Falco 和 EFK 来解释如何关闭集群中常被忽视的审计点，即 Pod 级别的审计。

本节的最后部分将详细介绍如何为灾难恢复和集群迁移备份工作负载。最后，我们将通过使用各种 CI/CD 工具来解释如何配置平台来关闭本书。

本书的这一部分包括以下章节：

+   第七章，将身份验证集成到您的集群中

+   第八章，部署安全的 Kubernetes 仪表板

+   第九章，RBAC 策略和审计

+   第十章，创建 Pod 安全策略

+   第十一章，使用 Open Policy Agent 扩展安全性

+   第十二章，使用 Falco 和 EFK 进行审计

+   第十三章，备份工作负载

+   第十四章，平台配置


# 第七章：将身份验证集成到您的集群中

一旦集群建立完成，用户将需要安全地与之交互。对于大多数企业来说，这意味着对个别用户进行身份验证，并确保他们只能访问他们工作所需的内容。在 Kubernetes 中，这可能是具有挑战性的，因为集群是一组 API，而不是具有可以提示进行身份验证的前端的应用程序。

在本章中，您将学习如何使用 OpenID Connect 协议和 Kubernetes 模拟将企业身份验证集成到您的集群中。我们还将涵盖几种反模式，并解释为什么您应该避免使用它们。

在本章中，我们将涵盖以下主题：

+   了解 Kubernetes 如何知道你是谁

+   了解 OpenID Connect

+   其他选项是什么？

+   配置 KinD 以进行 OpenID Connect

+   云 Kubernetes 如何知道你是谁

+   配置您的集群以进行模拟

+   在没有 OpenUnison 的情况下配置模拟

+   让我们开始吧！

# 技术要求

要完成本章的练习，您将需要以下内容：

+   一个拥有 8GB RAM 的 Ubuntu 18.04 服务器

+   使用*第五章*中的配置运行的 KinD 集群，*使用 KinD 部署集群*

您可以在以下 GitHub 存储库中访问本章的代码：[`github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide/tree/master/chapter7`](https://github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide/tree/master/chapter7)。

# 了解 Kubernetes 如何知道你是谁

没有勺子

- 《黑客帝国》，1999

在 1999 年的科幻电影《黑客帝国》中，尼奥在等待见奥拉克时与一个孩子谈论矩阵。孩子向他解释，操纵矩阵的诀窍是意识到“没有勺子”。

这是查看 Kubernetes 中的用户的绝佳方式，因为他们并不存在。除了我们稍后将讨论的服务账户之外，在 Kubernetes 中没有称为“用户”或“组”的对象。每个 API 交互必须包含足够的信息，以告诉 API 服务器用户是谁以及用户是哪些组的成员。这种断言可以采用不同的形式，具体取决于您计划如何将身份验证集成到您的集群中。

在本节中，我们将详细介绍 Kubernetes 可以将用户与集群关联的不同方式。

## 外部用户

从集群外部访问 Kubernetes API 的用户通常会使用两种认证方法之一：

+   证书：您可以使用包含有关您的信息的客户端证书来断言您的身份，例如您的用户名和组。该证书用作 TLS 协商过程的一部分。

+   Bearer token：嵌入在每个请求中，Bearer token 可以是一个自包含的令牌，其中包含验证自身所需的所有信息，或者可以由 API 服务器中的 webhook 交换该信息的令牌。

您还可以使用服务账户来访问集群外的 API 服务器，尽管这是强烈不建议的。我们将在“还有哪些选项？”部分讨论使用服务账户的风险和关注点。

## Kubernetes 中的组

不同的用户可以被分配相同的权限，而无需为每个用户单独创建 RoleBinding 对象，通过组来实现。Kubernetes 包括两种类型的组：

+   系统分配的：这些组以 system:前缀开头，并由 API 服务器分配。一个例子是 system:authenticated，它被分配给所有经过认证的用户。系统分配的其他示例包括 system:serviceaccounts:namespace 组，其中 Namespace 是包含命名组中命名的命名空间的名称。

+   用户断言的组：这些组是由认证系统在提供给 API 服务器的令牌中断言的，或者通过认证 webhook 进行断言的。对于这些组的命名没有标准或要求。就像用户一样，组在 API 服务器中并不存在为对象。组是由外部用户在认证时断言的，并且对于系统生成的组在本地进行跟踪。在断言用户的组时，用户唯一 ID 和组之间的主要区别在于唯一 ID 预期是唯一的，而组不是。

您可能被授权访问组，但所有访问仍然基于您的用户唯一 ID 进行跟踪和审计。

## 服务账户

服务账户是存在于 API 服务器中的对象，用于跟踪哪些 pod 可以访问各种 API。服务账户令牌称为 JSON Web Tokens，或 JWTs。根据令牌生成的方式，有两种获取服务账户的方式：

+   第一种是来自 Kubernetes 在创建服务账户时生成的一个密钥。

+   第二种方法是通过**TokenRequest** API，该 API 用于通过挂载点将秘钥注入到 Pod 中，或者从集群外部使用。所有服务账户都是通过在请求中将令牌作为标头注入到 API 服务器中来使用的。API 服务器将其识别为服务账户并在内部进行验证。

与用户不同，服务账户**不能**分配给任意组。服务账户是预先构建的组的成员，但您不能创建特定服务账户的组以分配角色。

现在我们已经探讨了 Kubernetes 如何识别用户的基本原理，我们将探讨这个框架如何适用于**OpenID Connect**（**OIDC**）协议。OIDC 提供了大多数企业需要的安全性，并且符合标准，但 Kubernetes 并不像许多网络应用程序那样使用它。了解这些差异以及 Kubernetes 为何需要它们是将集群整合到企业安全环境中的重要步骤。

# 了解 OpenID Connect

OpenID Connect 是一种标准的身份联合协议。它建立在 OAuth2 规范之上，并具有一些非常强大的功能，使其成为与 Kubernetes 集群交互的首选选择。

OpenID Connect 的主要优势如下：

+   **短期令牌**：如果令牌泄露，比如通过日志消息或违规行为，您希望令牌尽快过期。使用 OIDC，您可以指定令牌的生存时间为 1-2 分钟，这意味着令牌在攻击者尝试使用时很可能已经过期。

+   **用户和组成员资格**：当我们开始讨论授权时，我们很快就会发现按组管理访问权限比直接引用用户进行访问权限管理更为重要。OIDC 令牌可以嵌入用户的标识符和他们的组，从而更容易进行访问管理。

+   刷新令牌受到超时策略的限制：使用短期令牌时，您需要能够根据需要刷新它们。刷新令牌的有效时间可以根据企业的网络应用程序空闲超时策略进行限定，从而使您的集群符合其他基于网络的应用程序的规定。

+   **kubectl**不需要插件：**kubectl**二进制文件原生支持 OpenID Connect，因此不需要任何额外的插件。如果您需要从跳板机或虚拟机访问集群，但无法直接在工作站上安装**命令行界面**（**CLI**）工具，这将非常有用。

+   **更多多因素身份验证选项**：许多最强大的多因素身份验证选项需要使用 Web 浏览器。例如，使用硬件令牌的 FIDO U2F 和 WebAuth。

OIDC 是一个经过同行评审的标准，已经使用了几年，并迅速成为身份联合的首选标准。

重要提示

身份联合是用来描述断言身份数据和认证的术语，而不共享用户的机密密码。身份联合的经典示例是登录到员工网站并能够访问您的福利提供者，而无需再次登录。您的员工网站不会与福利提供者共享您的密码。相反，您的员工网站*断言*您在特定日期和时间登录，并提供一些关于您的信息。这样，您的帐户就可以在两个独立的系统（您的员工网站和福利门户）之间*联合*，而无需让您的福利门户知道您的员工网站密码。

## OpenID Connect 协议

正如您所看到的，OIDC 有多个组件。为了充分理解 OIDC 的工作原理，让我们开始 OpenID 连接协议。

我们将重点关注 OIDC 协议的两个方面：

+   使用**kubectl**和 API 服务器的令牌

+   刷新令牌以保持令牌的最新状态

我们不会过多关注获取令牌。虽然获取令牌的协议遵循标准，但登录过程并不是。根据您选择实现 OIDC**身份提供者**（**IdP**）的方式，从身份提供者获取令牌的方式会有所不同。

OIDC 登录过程生成了三个令牌：

+   **access_token**：此令牌用于向身份提供者提供的 Web 服务进行经过身份验证的请求，例如获取用户信息。它**不**被 Kubernetes 使用，可以丢弃。

+   **id_token**：这是一个 JWT 令牌，包含您的身份信息，包括您的唯一标识（sub）、组和关于您的到期信息，API 服务器可以使用它来授权您的访问。JWT 由您的身份提供者的证书签名，并且可以通过 Kubernetes 简单地检查 JWT 的签名来验证。这是您传递给 Kubernetes 以进行身份验证的令牌。

+   **refresh_token**：**kubectl**知道如何在令牌过期后自动为您刷新**id_token**。为此，它使用**refresh_token**调用您的 IdP 的令牌端点以获取新的**id_token**。**refresh_token**只能使用一次，是不透明的，这意味着作为令牌持有者的您无法看到其格式，对您来说并不重要。它要么有效，要么无效。*refresh_token 永远不会传递到 Kubernetes（或任何其他应用程序）。它只在与 IdP 的通信中使用。*

一旦您获得了您的令牌，您可以使用它们来与 API 服务器进行身份验证。使用您的令牌的最简单方法是将它们添加到**kubectl**配置中，使用命令行参数：

kubectl config set-credentials username --auth-provider=oidc --auth-provider-arg=idp-issuer-url=https://host/uri --auth-provider-arg=client-id=kubernetes --auth-provider-arg=refresh-token=$REFRESH_TOKEN --auth-provider-arg=id-token=$ID_TOKEN

**config set-credentials**有一些需要提供的选项。我们已经解释了**id-token**和**refresh_token**，但还有两个额外的选项：

+   **idp-issuer-url**：这与我们将用于配置 API 服务器的 URL 相同，并指向用于 IdP 发现 URL 的基本 URL。

+   **客户端 ID**：这是由您的 IdP 用于识别您的配置。这是 Kubernetes 部署中的唯一标识，不被视为机密信息。

OpenID Connect 协议有一个可选元素，称为**client_secret**，它在 OIDC 客户端和 IdP 之间共享。它用于在进行任何请求之前“验证”客户端，例如刷新令牌。虽然 Kubernetes 支持它作为一个选项，但建议不使用它，而是配置您的 IdP 使用公共端点（根本不使用密钥）。

客户端密钥没有实际价值，因为您需要与每个潜在用户共享它，并且由于它是一个密码，您企业的合规框架可能要求定期轮换，这会导致支持方面的麻烦。总的来说，它不值得在安全方面承担任何潜在的不利影响。

重要说明

Kubernetes 要求您的身份提供者支持发现 URL 端点，这是一个 URL，提供一些 JSON 告诉您可以在哪里获取用于验证 JWT 的密钥和各种可用的端点。取任何发行者 URL 并添加**/.well-known/openid-configuration**以查看此信息。

## 遵循 OIDC 和 API 的交互

一旦**kubectl**被配置，所有 API 交互将遵循以下顺序：

![图 7.1 - Kubernetes/kubectl OpenID Connect 序列图](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_7.1_B15514.jpg)

图 7.1 - Kubernetes/kubectl OpenID Connect 序列图

上述图表来自 Kubernetes 的认证页面，网址为[`kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens`](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens)。认证请求涉及以下操作：

1.  **登录到您的身份提供者（IdP）**：对于每个 IdP 都会有所不同。这可能涉及在 Web 浏览器中向表单提供用户名和密码，多因素令牌或证书。这将针对每个实现具体实现。

1.  **向用户提供令牌**：一旦经过身份验证，用户需要一种方式来生成**kubectl**访问 Kubernetes API 所需的令牌。这可以是一个应用程序，使用户可以轻松地将它们复制并粘贴到配置文件中，或者可以是一个新的可下载文件。

1.  这一步是将**id_token**和**refresh_token**添加到**kubectl**配置中。如果令牌在浏览器中呈现给用户，它们可以手动添加到配置中。如果提供了新的配置以便下载，也可以这样做。还有**kubectl**插件，将启动一个 Web 浏览器来开始认证过程，并在完成后为您生成配置。

1.  **注入 id_token**：一旦调用了**kubectl**命令，每个 API 调用都包括一个额外的标头，称为**Authorization**标头，其中包括**id_token**。

1.  JWT 签名验证：一旦 API 服务器从 API 调用接收到 id_token，它将使用身份提供者提供的公钥验证签名。API 服务器还将验证发行者是否与 API 服务器配置的发行者匹配，以及接收者是否与 API 服务器配置的客户端 ID 匹配。

1.  检查 JWT 的过期时间：令牌只在有限的时间内有效。API 服务器确保令牌尚未过期。

1.  授权检查：现在用户已经通过身份验证，API 服务器将确定由提供的 id_token 标识的用户是否能够执行所请求的操作，方法是将用户的标识符和断言的组与内部策略进行匹配。

1.  执行 API：所有检查都已完成，API 服务器执行请求，生成一个将发送回 kubectl 的响应。

1.  用户的响应格式：一旦 API 调用完成（或一系列 API 调用），JSON 将由 kubectl 为用户格式化。

重要提示

一般来说，身份验证是验证您的过程。当我们在网站上输入用户名和密码时，大多数人都会遇到这种情况。我们在证明我们是谁。在企业世界中，授权随后成为我们是否被允许做某事的决定。首先，我们进行身份验证，然后进行授权。围绕 API 安全构建的标准并不假设身份验证，而是直接基于某种令牌进行授权。不假设调用者必须被识别。例如，当您使用物理钥匙打开门时，门不知道您是谁，只知道您有正确的钥匙。这些术语可能会变得非常令人困惑，所以如果您有点迷茫，不要感到难过。您并不孤单！

id_token 是自包含的；API 服务器需要了解有关您的所有信息都包含在该令牌中。API 服务器使用身份提供者提供的证书验证 id_token，并验证令牌是否已过期。只要一切都符合，API 服务器将根据其自身的 RBAC 配置继续授权您的请求。我们将在稍后介绍该过程的详细信息。最后，假设您已获得授权，API 服务器将提供响应。

请注意，Kubernetes 从不会看到您的密码或任何其他只有您知道的秘密信息。唯一共享的是**id_token**，而且它是短暂的。这导致了几个重要的观点：

+   由于 Kubernetes 从不会看到您的密码或其他凭据，它无法 compromise 它们。这可以节省您与安全团队合作的大量时间，因为所有与保护密码相关的任务都可以跳过！

+   **id_token**是自包含的，这意味着如果它被 compromise，除非重新生成您的身份提供者密钥，否则无法阻止它被滥用。这就是为什么您的**id_token**的寿命如此重要。在 1-2 分钟内，攻击者能够获取**id_token**，意识到它是什么，并滥用它的可能性非常低。

如果在执行其调用时，**kubectl**发现**id_token**已过期，它将尝试通过调用 IdP 的令牌端点使用**refresh_token**来刷新它。如果用户的会话仍然有效，IdP 将生成新的**id_token**和**refresh_token**，**kubectl**将为您存储在 kubectl 配置中。这将自动发生，无需用户干预。此外，**refresh_token**只能使用一次，因此如果有人尝试使用先前使用过的**refresh_token**，您的 IdP 将失败刷新过程。

重要提示

这是不可避免的。有人可能需要立即被锁定。可能是因为他们被走出去了，或者他们的会话已经被 compromise。这取决于您的 IdP，因此在选择 IdP 时，请确保它支持某种形式的会话撤销。

最后，如果**refresh_token**已过期或会话已被撤销，API 服务器将返回**401 Unauthorized**消息，表示它将不再支持该令牌。

我们花了大量时间研究 OIDC 协议。现在，让我们深入了解**id_token**。

### id_token

**id_token**是一个经过 base64 编码和数字签名的 JSON web token。JSON 包含一系列属性，称为 claims，在 OIDC 中。**id_token**中有一些标准的 claims，但大部分时间您最关心的 claims 如下：

+   **iss**：发行者，必须与 kubectl 配置中的发行者一致

+   **aud**：您的客户端 ID

+   **sub**：您的唯一标识符

+   **groups**：不是标准声明，但应填充与您的 Kubernetes 部署相关的组

重要提示

许多部署尝试通过您的电子邮件地址来识别您。这是一种反模式，因为您的电子邮件地址通常基于您的姓名，而姓名会发生变化。sub 声明应该是一个不可变的唯一标识符，永远不会改变。这样，即使您的电子邮件地址发生变化，也不重要，因为您的姓名发生了变化。这可能会使调试“cd25d24d-74b8-4cc4-8b8c-116bf4abbd26 是谁？”变得更加困难，但会提供一个更清晰、更易于维护的集群。

还有其他一些声明，指示**id_token**何时不再被接受。这些声明都是以秒为单位从纪元时间（1970 年 1 月 1 日）的 UTC 时间计算的：

+   **exp**：**id_token**过期时间

+   **iat**：**id_token**创建时间

+   **nbf**：**id_token**允许的绝对最早时间

为什么令牌不只有一个过期时间？

创建**id_token**的系统上的时钟不太可能与评估它的系统上的时钟完全相同。通常会有一些偏差，取决于时钟的设置，可能会有几分钟。除了过期时间之外，还有一个不早于时间，可以为标准时间偏差提供一些余地。

**id_token**中还有其他一些声明，虽然并不重要，但是为了提供额外的上下文。例如，您的姓名、联系信息、组织等。

尽管令牌的主要用途是与 Kubernetes API 服务器进行交互，但它们不仅限于 API 交互。除了访问 API 服务器，webhook 调用也可能接收您的**id_token**。

您可能已经在集群上部署了 OPA 作为验证 webhook。当有人提交 pod 创建请求时，webhook 将接收用户的**id_token**，这可以用于其他决策。

一个例子是，您希望确保 PVC 基于提交者的组织映射到特定的 PV。组织包含在**id_token**中，传递给 Kubernetes，然后传递到 OPA webhook。由于令牌已传递到 webhook，因此信息可以在您的 OPA 策略中使用。

## 其他身份验证选项

在这一部分，我们专注于 OIDC，并提出了它是身份验证的最佳机制的原因。当然，这并不是唯一的选择，我们将在本节中涵盖其他选项以及它们的适用性。

### 证书

这通常是每个人第一次对 Kubernetes 集群进行身份验证的经历。

一旦 Kubernetes 安装完成，将创建一个预先构建的 kubectl **config**文件，其中包含证书和私钥，并准备好使用。此文件应仅在“紧急情况下打破玻璃”情况下使用，在其他形式的身份验证不可用时。它应受到组织对特权访问的标准控制。当使用此配置文件时，它不会识别用户，并且很容易被滥用，因为它不允许轻松的审计跟踪。

虽然这是证书认证的标准用例，但并不是证书认证的唯一用例。当正确使用时，证书认证是行业中公认的最强凭据之一。

美国联邦政府在其最重要的任务中使用证书认证。在高层次上，证书认证涉及使用客户端密钥和证书来协商与 API 服务器的 HTTPS 连接。API 服务器可以获取您用于建立连接的证书，并根据**证书颁发机构**（**CA**）证书对其进行验证。验证后，它将证书中的属性映射到 API 服务器可以识别的用户和组。

为了获得证书认证的安全性好处，私钥需要在隔离的硬件上生成，通常以智能卡的形式，并且永远不离开该硬件。生成证书签名请求并提交给签署公钥的 CA，从而创建一个安装在专用硬件上的证书。在任何时候，CA 都不会获得私钥，因此即使 CA 被 compromise，也无法获得用户的私钥。如果需要撤销证书，它将被添加到一个吊销列表中，可以从 LDAP 目录、文件中提取，或者可以使用 OCSP 协议进行检查。

这可能看起来是一个吸引人的选择，那么为什么不应该在 Kubernetes 中使用证书呢？

+   智能卡集成使用一个名为 PKCS11 的标准，**kubectl**或 API 服务器都不支持。

+   API 服务器无法检查证书吊销列表或使用 OCSP，因此一旦证书被颁发，就无法撤销，以便 API 服务器可以使用它。

此外，正确生成密钥对的过程很少使用。它需要构建一个复杂的接口，用户很难使用，结合需要运行的命令行工具。为了解决这个问题，证书和密钥对是为您生成的，您可以下载它或者通过电子邮件发送给您，从而抵消了该过程的安全性。

您不应该为用户使用证书身份验证的另一个原因是很难利用组。虽然您可以将组嵌入到证书的主题中，但无法撤销证书。因此，如果用户的角色发生变化，您可以给他们一个新的证书，但无法阻止他们使用旧的证书。

在本节的介绍中提到，使用证书在“紧急情况下打破玻璃”的情况下进行身份验证是证书身份验证的一个很好的用途。如果所有其他身份验证方法都出现问题，这可能是进入集群的唯一方法。

### 服务帐户

服务帐户似乎提供了一种简单的访问方法。创建它们很容易。以下命令创建了一个服务帐户对象和一个与之配套的密钥，用于存储服务帐户的令牌：

kubectl create sa mysa -n default

接下来，以下命令将以 JSON 格式检索服务帐户的令牌，并仅返回令牌的值。然后可以使用此令牌访问 API 服务器：

kubectl get secret $(kubectl get sa mysa -n default -o json | jq -r '.secrets[0].name') -o json | jq -r '.data.token' | base64 -d

为了展示这一点，让我们直接调用 API 端点，而不提供任何凭据：

curl -v --insecure https://0.0.0.0:32768/api

您将收到以下内容：

.

.

.

{

“kind”: “状态”，

“apiVersion”: “v1”，

“metadata”:{

},

“status”: “失败”,

“message”: “禁止：用户“system:anonymous”无法获取路径“/api””,

“原因”:“禁止”，

“details”:{

},

“code”: 403

*连接到主机 0.0.0.0 的连接已保持不变

默认情况下，大多数 Kubernetes 发行版不允许匿名访问 API 服务器，因此我们收到了*403 错误*，因为我们没有指定用户。

现在，让我们将我们的服务帐户添加到 API 请求中：

export KUBE_AZ=$(kubectl get secret $(kubectl get sa mysa -n default -o json | jq -r '.secrets[0].name') -o json | jq -r '.data.token' | base64 -d)

curl -H“Authorization: Bearer $KUBE_AZ” --insecure https://0.0.0.0:32768/api

{

“kind”: “APIVersions”，

“versions”:[

“v1”

],

“serverAddressByClientCIDRs”:[

{

“clientCIDR”: “0.0.0.0/0”，

“serverAddress”: “172.17.0.3:6443”

}

]

}

成功！这是一个简单的过程，所以您可能会想，“为什么我需要担心所有复杂的 OIDC 混乱呢？”这个解决方案的简单性带来了多个安全问题：

+   **令牌的安全传输**：服务账户是自包含的，不需要任何内容来解锁它们或验证所有权，因此如果令牌在传输中被获取，您无法阻止其使用。您可以建立一个系统，让用户登录以下载其中包含令牌的文件，但现在您拥有的是一个功能较弱的 OIDC 版本。

+   **无过期时间**：当您解码服务账户令牌时，没有任何告诉您令牌何时过期的信息。这是因为令牌永远不会过期。您可以通过删除服务账户并重新创建来撤销令牌，但这意味着您需要一个系统来执行此操作。再次，您构建了一个功能较弱的 OIDC 版本。

+   **审计**：一旦所有者检索到密钥，服务账户就可以轻松地被分发。如果有多个用户使用单个密钥，很难审计账户的使用情况。

除了这些问题，您无法将服务账户放入任意组中。这意味着 RBAC 绑定要么直接绑定到服务账户，要么使用服务账户是成员的预建组之一。当我们谈论授权时，我们将探讨为什么这是一个问题，所以现在只需记住这一点。

最后，服务账户从未设计用于在集群外部使用。这就像使用锤子来打螺丝。通过足够的力量和激怒，您可以将其打入，但这不会很漂亮，也不会有人对结果感到满意。

### TokenRequest API

在撰写本文时，**TokenRequest** API 仍然是一个**beta**功能。

**TokenRequest** API 允许您请求特定范围的短期服务账户。虽然它提供了稍微更好的安全性，因为它将会过期并且范围有限，但它仍然绑定到服务账户，这意味着没有组，并且仍然存在安全地将令牌传递给用户并审计其使用的问题。

由**TokenRequest** API 生成的令牌是为其他系统与您的集群通信而构建的；它们不是用于用户使用的。

### 自定义认证 webhook

如果你已经有一个不使用现有标准的身份平台，那么自定义身份验证 webhook 将允许你集成它，而无需定制 API 服务器。这个功能通常被托管托管 Kubernetes 实例的云提供商所使用。

你可以定义一个身份验证 webhook，API 服务器将使用令牌调用它来验证并获取有关用户的信息。除非你管理一个具有自定义 IAM 令牌系统的公共云，你正在构建一个用于 Kubernetes 分发的，不要这样做。编写自己的身份验证就像编写自己的加密 - 不要这样做。我们看到的每个自定义身份验证系统最终都归结为 OIDC 的苍白模仿或“传递密码”。就像用锤子拧螺丝的类比一样，你可以这样做，但这将非常痛苦。这主要是因为你更有可能把螺丝钉拧进自己的脚而不是木板。

### Keystone

熟悉 OpenStack 的人会认识 Keystone 这个身份提供者的名字。如果你不熟悉 Keystone，它是 OpenStack 部署中使用的默认身份提供者。

Keystone 托管处理身份验证和令牌生成的 API。OpenStack 将用户存储在 Keystone 的数据库中。虽然使用 Keystone 更常与 OpenStack 相关联，但 Kubernetes 也可以配置为使用 Keystone 进行用户名和密码身份验证，但有一些限制：

+   将 Keystone 作为 Kubernetes 的 IdP 的主要限制是它只能与 Keystone 的 LDAP 实现一起使用。虽然你可以使用这种方法，但你应该考虑只支持用户名和密码，因此你正在创建一个使用非标准协议进行身份验证的身份提供者，而任何 OIDC IdP 都可以直接执行此操作。

+   你不能利用 Keystone 使用 SAML 或 OIDC，尽管 Keystone 支持 OpenStack 的这两种协议，这限制了用户的身份验证方式，因此使你无法使用多种多因素选项。

+   很少有应用程序知道如何在 OpenStack 之外使用 Keystone 协议。你的集群将有多个应用程序组成你的平台，而这些应用程序不知道如何与 Keystone 集成。

使用 Keystone 当然是一个吸引人的想法，特别是如果您正在部署 OpenStack，但最终，它非常有限，您可能需要花费与使用 OIDC 一样多的工作来集成 Keystone。

下一节将把我们在这里探讨的细节应用到集成身份验证的集群中。当您在实施过程中，您将看到**kubectl**、API 服务器和您的身份提供者是如何相互作用以提供对集群的安全访问的。我们将把这些特性与常见的企业需求联系起来，以说明理解 OpenID Connect 协议的细节为什么重要。

# 配置 KinD 以进行 OpenID Connect

对于我们的示例部署，我们将使用我们客户 FooWidgets 的一个场景。FooWidgets 有一个 Kubernetes 集群，他们希望使用 OIDC 进行集成。提出的解决方案需要满足以下要求：

+   Kubernetes 必须使用我们的中央身份验证系统 Active Directory 联合身份验证服务。

+   我们需要能够将 Active Directory 组映射到我们的 RBAC **RoleBinding**对象。

+   用户需要访问 Kubernetes 仪表板。

+   用户需要能够使用 CLI。

+   必须满足所有企业合规性要求。

让我们详细探讨每一个，并解释我们如何满足客户的需求。

## 满足需求

我们企业的需求需要多个内部和外部的组件。我们将检查每个组件以及它们与构建经过身份验证的集群的关系。

### 使用 Active Directory 联合身份验证服务

今天，大多数企业都使用微软™的 Active Directory 来存储有关用户及其凭据的信息。根据您企业的规模，拥有多个用户所在的域或森林并不罕见。如果您的 IdP 与微软的 Kerberos 环境很好地集成在一起，它可能知道如何浏览这些不同的系统。大多数非微软应用程序不是这样的，包括大多数身份提供者。**Active Directory 联合身份验证服务**（**ADFS**）是微软的 IdP，支持 SAML2 和 OpenID Connect，并且知道如何浏览企业实施的域和森林。在许多大型企业中很常见。

与 ADFS 相关的下一个决定是是否使用 SAML2 还是 OpenID Connect。在撰写本文时，SAML2 更容易实现，并且大多数使用 ADFS 的企业环境更喜欢使用 SAML2。SAML2 的另一个好处是它不需要我们的集群与 ADFS 服务器之间建立连接；所有重要信息都通过用户的浏览器传输。这减少了需要实施的潜在防火墙规则，以便让我们的集群正常运行。

重要提示

不用担心-你不需要 ADFS 准备好就可以运行这个练习。我们有一个方便的 SAML 测试身份提供者，我们将使用它。您不需要安装任何东西来在您的 KinD 集群中使用 SAML2。

### 将 Active Directory 组映射到 RBAC RoleBindings

当我们开始讨论授权时，这将变得重要。这里要指出的重要一点是，ADFS 有能力将用户的组成员资格放入 SAML 断言中，然后我们的集群可以消耗它。

### Kubernetes 仪表板访问

仪表板是一种快速访问集群信息并进行快速更新的强大方式。正确部署时，仪表板不会创建任何安全问题。部署仪表板的正确方式是不赋予任何特权，而是依赖用户自己的凭据。我们将通过一个反向代理来实现这一点，该代理会在每个请求中注入用户的 OIDC 令牌，仪表板在调用 API 服务器时将使用该令牌。使用这种方法，我们将能够以与任何其他 Web 应用程序相同的方式限制对我们仪表板的访问。

有几个原因说明为什么使用 kubectl 内置代理和端口转发不是访问仪表板的好策略。许多企业不会在本地安装 CLI 实用程序，迫使您使用跳板机来访问诸如 Kubernetes 之类的特权系统，这意味着端口转发不起作用。即使您可以在本地运行 kubectl，打开回环（127.0.0.1）上的端口意味着您的系统上的任何东西都可以使用它，而不仅仅是您从浏览器中。虽然浏览器有控件可以阻止您使用恶意脚本访问回环上的端口，但这不会阻止您的工作站上的其他任何东西。最后，这只是一个不太好的用户体验。

我们将深入探讨这是如何以及为什么工作的细节，详情请参阅*第九章**，部署安全的 Kubernetes 仪表板*。

### Kubernetes CLI 访问

大多数开发人员希望能够访问**kubectl**和其他依赖**kubectl**配置的工具。例如，Visual Studio Code Kubernetes 插件不需要任何特殊配置。它只使用**kubectl**内置配置。大多数企业严格限制您能够安装的二进制文件，因此我们希望尽量减少我们想要安装的任何额外工具和插件。

### 企业合规要求

成为云原生并不意味着您可以忽视企业的合规要求。大多数企业都有要求，例如 20 分钟的空闲超时，可能需要特权访问的多因素身份验证等。我们提出的任何解决方案都必须通过控制电子表格才能上线。另外，毋庸置疑，但一切都需要加密（我是指一切）。

### 将所有内容整合在一起

为了满足这些要求，我们将使用 OpenUnison。它具有预构建的配置，可与 Kubernetes、仪表板、CLI 和 SAML2 身份提供者（如 ADFS）一起使用。部署速度也相当快，因此我们不需要专注于特定提供程序的实现细节，而是专注于 Kubernetes 的配置选项。我们的架构将如下所示：

![图 7.2 – 认证架构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_7.2_B15514.jpg)

图 7.2 – 认证架构

对于我们的实现，我们将使用两个主机名：

+   **k8s.apps.X-X-X-X.nip.io**：访问 OpenUnison 门户，我们将在那里启动登录并获取我们的令牌

+   **k8sdb.apps.X-X-X-X.nip.io**：访问 Kubernetes 仪表板

重要提示

作为一个快速提醒，**nip.io**是一个公共 DNS 服务，将返回嵌入在您主机名中的 IP 地址。在实验环境中，设置 DNS 可能很麻烦，这真的很有用。在我们的示例中，X-X-X-X 是您的 Docker 主机的 IP。

当用户尝试访问 https://k8s.apps.X-X-X-X.nip.io/时，他们将被重定向到 ADFS，ADFS 将收集他们的用户名和密码（甚至可能是多因素身份验证令牌）。 ADFS 将生成一个断言，该断言将被数字签名并包含我们用户的唯一 ID，以及他们的组分配。这个断言类似于我们之前检查的 id_token，但它不是 JSON，而是 XML。这个断言被发送到用户的浏览器中的一个特殊网页中，该网页包含一个表单，该表单将自动将断言提交回 OpenUnison。在那时，OpenUnison 将在 OpenUnison 命名空间中创建用户对象以存储用户信息并创建 OIDC 会话。

早些时候，我们描述了 Kubernetes 没有用户对象。Kubernetes 允许您使用自定义资源定义（CRD）扩展基本 API。OpenUnison 定义了一个用户 CRD，以帮助实现高可用性，并避免需要在数据库中存储状态。这些用户对象不能用于 RBAC。

一旦用户登录到 OpenUnison，他们可以获取他们的 kubectl 配置，以使用 CLI 或使用 Kubernetes 仪表板来从浏览器访问集群。一旦用户准备好，他们可以注销 OpenUnison，这将结束他们的会话并使他们的 refresh_token 失效，从而使他们无法再次使用 kubectl 或仪表板，直到他们再次登录。如果他们离开桌子吃午饭而没有注销，当他们回来时，他们的 refresh_token 将会过期，因此他们将无法再与 Kubernetes 交互而不重新登录。

现在我们已经了解了用户如何登录并与 Kubernetes 交互，我们将部署 OpenUnison 并将其集成到集群中进行身份验证。

## 部署 OIDC

我们已经包含了两个安装脚本来自动化部署步骤。这些脚本 install-oidc-step1.sh 和 install-oidc-step2.sh 位于本书的 GitHub 存储库中的 chapter7 目录中。

本节将解释脚本自动化的所有手动步骤。

重要提示

如果您使用脚本安装 OIDC，您必须遵循这个过程才能成功部署：

步骤 1：运行./install-oidc-step1.sh 脚本。

第 2 步：按照*注册 SAML2 测试实验室*部分的步骤注册 SAML2 测试实验室。

第 3 步：运行**./install-oidc-step2.sh**脚本完成 OIDC 部署。

使用 OpenUnison 在 Kubernetes 集群中部署 OIDC 是一个五步过程：

1.  部署仪表板。

1.  部署 OpenUnison 运算符。

1.  创建一个秘密。

1.  创建一个**values.yaml**文件。

1.  部署图表。

让我们一步一步地执行这些步骤。

### 部署 OpenUnison

仪表板是许多用户喜欢的功能。它提供了资源的快速视图，而无需使用 kubectl CLI。多年来，它因不安全而受到一些负面评价，但是当正确部署时，它是非常安全的。您可能读过或听过的大多数故事都来自未正确设置的仪表板部署。我们将在*第九章**，保护 Kubernetes 仪表板*中涵盖这个主题：

1.  首先，我们将从 https://github.com/kubernetes/dashboard 部署仪表板：

**kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.0.0/aio/deploy/recommended.yaml**

**namespace/kubernetes-dashboard created**

**serviceaccount/kubernetes-dashboard created**

**service/kubernetes-dashboard created**

**secret/kubernetes-dashboard-certs created**

**secret/kubernetes-dashboard-csrf created**

**secret/kubernetes-dashboard-key-holder created**

**configmap/kubernetes-dashboard-settings created**

**role.rbac.authorization.k8s.io/kubernetes-dashboard created**

**clusterrole.rbac.authorization.k8s.io/kubernetes-dashboard created**

**rolebinding.rbac.authorization.k8s.io/kubernetes-dashboard created**

**clusterrolebinding.rbac.authorization.k8s.io/kubernetes-dashboard created**

**deployment.apps/kubernetes-dashboard created**

**service/dashboard-metrics-scraper created**

**deployment.apps/dashboard-metrics-scraper created**

1.  接下来，我们需要将包含 OpenUnison 的存储库添加到我们的 Helm 列表中。要添加 Tremolo 图表存储库，请使用**Helm repo add**命令：

Helm repo add tremolo https://nexus.tremolo.io/repository/Helm/

**https://nexus.tremolo.io/repository/Helm/"tremolo"已添加到您的存储库**

重要提示

Helm 是 Kubernetes 的包管理器。Helm 提供了一个工具，可以将“Chart”部署到您的集群，并帮助您管理部署的状态。我们正在使用 Helm v3，它不需要您在集群中部署任何组件，如 Tiller，才能工作。

1.  添加后，您需要使用**Helm repo update**命令更新存储库：

**helm repo update**

在我们从图表存储库中获取最新信息时，请稍等片刻...

...成功从“tremolo”图表存储库获取更新

更新完成。祝您使用 Helm 愉快！

现在，您可以使用 Helm 图表部署 OpenUnison 运算符。

1.  首先，我们希望在一个名为**openunison**的新命名空间中部署 OpenUnison。在部署 Helm 图表之前，我们需要创建命名空间：

**kubectl create ns openunison**

**namespace/openunison created**

1.  有了创建的命名空间，您可以使用 Helm 将图表部署到命名空间中。要使用 Helm 安装图表，请使用**Helm install <name> <chart> <options>**：

**helm install openunison tremolo/openunison-operator --namespace openunison**

**NAME: openunison**

**LAST DEPLOYED: Fri Apr 17 15:04:50 2020**

**NAMESPACE: openunison**

**STATUS: deployed**

**REVISION: 1**

**TEST SUITE: None**

运算符将需要几分钟来完成部署。

重要提示

运算符是由 CoreOS 首创的一个概念，旨在封装管理员可能执行的许多可以自动化的任务。运算符通过观察特定 CRD 的更改并相应地采取行动来实现。OpenUnison 运算符寻找 OpenUnison 类型的对象，并将创建所需的任何对象。一个包含 PKCS12 文件的密钥被创建；还创建了 Deployment、Service 和 Ingress 对象。当您对 OpenUnison 对象进行更改时，运算符会根据需要更新 Kubernetes 对象。例如，如果您更改了 OpenUnison 对象中的图像，运算符会更新 Deployment，从而触发 Kubernetes 滚动部署新的 pod。对于 SAML，运算符还会监视元数据，以便在更改时导入更新的证书。

1.  一旦运算符部署完成，我们需要创建一个存储 OpenUnison 内部使用的密码的密钥。确保在此密钥中使用您自己的键的值（记得对它们进行 base64 编码）：

**kubectl create -f - <<EOF**

**apiVersion: v1**

**type: Opaque**

**metadata:**

**name: orchestra-secrets-source**

**namespace: openunison**

**data:**

**K8S_DB_SECRET: cGFzc3dvcmQK**

**unisonKeystorePassword: cGFzc3dvcmQK**

**kind: Secret**

**EOF**

**secret/orchestra-secrets-source created**

重要提示

从现在开始，我们将假设您正在使用 Tremolo Security 的测试身份提供者。该工具将允许您自定义用户的登录信息，而无需搭建目录和身份提供者。注册，请访问 https://portal.apps.tremolo.io/并单击**注册**。

为了提供 OIDC 环境的帐户，我们将使用 SAML2 测试实验室，因此请确保在继续之前注册。

1.  首先，我们需要通过访问[`portal.apps.tremolo.io/`](https://portal.apps.tremolo.io/)并单击**SAML2 测试实验室**徽章来登录测试身份提供者：![图 7.3 – SAML2 测试实验徽章](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_7.3_B15514.jpg)

图 7.3 – SAML2 测试实验徽章

1.  点击徽章后，将显示一个屏幕，显示您的测试 IdP 元数据 URL：![图 7.4 – 测试身份提供者页面，突出显示 SAML2 元数据 URL](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_7.4_B15514.jpg)

图 7.4 – 测试身份提供者页面，突出显示 SAML2 元数据 URL

复制此值并将其存储在安全的地方。

1.  现在，我们需要创建一个**values.yaml**文件，用于在部署 OpenUnison 时提供配置信息。本书的 GitHub 存储库中包含**chapter7**目录中的基本文件：

网络：

openunison_host："k8sou.apps.XX-XX-XX-XX.nip.io"

dashboard_host："k8sdb.apps.XX-XX-XX-XX.nip.io"

api_server_host：""

session_inactivity_timeout_seconds：900

k8s_url：https://0.0.0.0:6443

cert_template：

ou："Kubernetes"

o："MyOrg"

l："我的集群"

st："集群状态"

c："MyCountry"

镜像："docker.io/tremolosecurity/openunison-k8s-login-saml2:latest"

myvd_config_path："WEB-INF/myvd.conf"

k8s_cluster_name：kubernetes

enable_impersonation：false

仪表板：

命名空间："kubernetes-dashboard"

cert_name："kubernetes-dashboard-certs"

标签："k8s-app=kubernetes-dashboard"

service_name：kubernetes-dashboard

证书：

use_k8s_cm：false

trusted_certs：[]

监控：

prometheus_service_account：system:serviceaccount:monitoring:prometheus-k8s

saml：

idp_url：https://portal.apps.tremolo.io/idp-test/metadata/dfbe4040-cd32-470e-a9b6-809c840

metadata_xml_b64：""

您需要更改部署的以下值：

+   **网络：openunison_host：**此值应使用集群的 IP 地址，即 Docker 主机的 IP 地址；例如，**k8sou.apps.192-168-2=131.nip.io**。

+   **网络：dashboard_host**：此值应使用集群的 IP 地址，即 Docker 主机的 IP 地址；例如，**k8sdb.apps.192-168-2-131.nip.io**。

+   **saml：idp url**：此值应该是您从上一步中的 SAML2 实验室页面检索到的 SAML2 元数据 URL。

在使用您自己的条目编辑或创建文件后，保存文件并继续部署您的 OIDC 提供者。

1.  要使用您的**values.yaml**文件部署 OpenUnison，执行一个使用**-f**选项指定**values.yaml**文件的**Helm install**命令：

**helm install orchestra tremolo/openunison-k8s-login-saml2 --namespace openunison -f ./values.yaml**

**名称：管弦乐队**

**上次部署：2020 年 4 月 17 日星期五 16:02:00**

**命名空间：openunison**

**状态：已部署**

**修订版本：1**

**测试套件：无**

1.  几分钟后，OpenUnison 将启动并运行。通过获取**openunison**命名空间中的 pod 来检查部署状态：

**kubectl get pods -n openunison**

**名称                                    准备就绪    状态    重启次数    年龄**

**openunison-operator-858d496-zzvvt       1/1    运行中   0          5d6h**

**openunison-orchestra-57489869d4-88d2v   1/1     运行中   0          85s**

您还需要执行一步才能完成 OIDC 部署：您需要更新 SAML2 实验室的依赖方以完成部署。

1.  现在 OpenUnison 正在运行，我们需要使用**values.yaml**文件中的**network.openunison_host**主机和**/auth/forms/saml2_rp_metadata.jsp**路径从 OpenUnison 获取 SAML2 元数据：

**curl --insecure https://k8sou.apps.192-168-2-131.nip.io/auth/forms/saml2_rp_metadata.jsp**

**<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="fc334f48076b7b13c3fcc83d1d116ac2decd7d665" entityID="https://k8sou.apps.192-168-2-131.nip.io/auth/SAML2Auth">**

**.**

**.**

**.**

1.  复制输出，粘贴到测试身份提供者的“元数据”处，然后点击“更新依赖方”：![图 7.5-使用依赖方元数据测试身份提供者](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_7.5_B15514.jpg)

图 7.5-使用依赖方元数据测试身份提供者

1.  最后，我们需要为我们的测试用户添加一些属性。添加以下截图中显示的属性：![图 7.6-身份提供者测试用户配置](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_7.6_B15514.jpg)

图 7.6-身份提供者测试用户配置

1.  接下来，点击**更新测试用户数据**以保存您的属性。有了这个，你就可以登录了。

1.  您可以使用分配的 nip.io 地址在网络上的任何计算机上登录 OIDC 提供程序。由于我们将使用仪表板进行访问测试，您可以使用任何带有浏览器的计算机。在**values.yaml**文件中将您的浏览器导航到**network.openunison_host**。如果需要，输入您的测试身份提供者凭据，然后在屏幕底部点击**完成登录**。您现在应该已经登录到 OpenUnison：![图 7.7 - OpenUnison 主屏幕](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_7.7_B15514.jpg)

图 7.7 - OpenUnison 主屏幕

1.  让我们通过点击**Kubernetes 仪表板**链接来测试 OIDC 提供程序。当您查看初始仪表板屏幕时不要惊慌 - 您会看到类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_7.8_B15514.jpg)

图 7.8 - 在 API 服务器完成 SSO 集成之前的 Kubernetes 仪表板

看起来像是很多错误！我们在仪表板上，但似乎没有被授权。这是因为 API 服务器尚不信任 OpenUnison 生成的令牌。下一步是告诉 Kubernetes 信任 OpenUnison 作为其 OpenID Connect 身份提供者。

### 配置 Kubernetes API 使用 OIDC

此时，您已经部署了 OpenUnison 作为 OIDC 提供程序，并且它正在工作，但是您的 Kubernetes 集群尚未配置为使用它作为提供程序。要配置 API 服务器使用 OIDC 提供程序，您需要向 API 服务器添加 OIDC 选项，并提供 OIDC 证书，以便 API 信任 OIDC 提供程序。

由于我们正在使用 KinD，我们可以使用一些**kubectl**和**docker**命令添加所需的选项。

要向 API 服务器提供 OIDC 证书，我们需要检索证书并将其复制到 KinD 主服务器上。我们可以在 Docker 主机上使用两个命令来完成这个任务：

1.  第一个命令从其密钥中提取 OpenUnison 的 TLS 证书。这是 OpenUnison 的 Ingress 对象引用的相同密钥。我们使用**jq**实用程序从密钥中提取数据，然后对其进行 base64 解码：

**kubectl get secret ou-tls-certificate -n openunison -o json | jq -r '.data["tls.crt"]' | base64 -d > ou-ca.pem**

1.  第二个命令将把证书复制到主服务器的**/etc/Kubernetes/pki**目录中：

**docker cp ou-ca.pem cluster01-control-plane:/etc/kubernetes/pki/ou-ca.pem**

1.  正如我们之前提到的，要将 API 服务器与 OIDC 集成，我们需要为 API 选项准备 OIDC 值。要列出我们将使用的选项，请在 **openunison** 命名空间中描述 **api-server-config** ConfigMap：

**kubectl describe configmap api-server-config -n openunison**

**名称:         api-server-config**

**命名空间:    openunison**

**标签:       <无>**

**注释:  <无>**

**数据**

**====**

**oidc-api-server-flags:**

**----**

**--oidc-issuer-url=https://k8sou.apps.192-168-2-131.nip.io/auth/idp/k8sIdp**

**--oidc-client-id=kubernetes**

--oidc-username-claim=sub

**--oidc-groups-claim=groups**

**--oidc-ca-file=/etc/kubernetes/pki/ou-ca.pem**

1.  接下来，编辑 API 服务器配置。通过更改 API 服务器上的标志来配置 OpenID Connect。这就是为什么托管的 Kubernetes 通常不提供 OpenID Connect 作为选项，但我们将在本章后面介绍。每个发行版处理这些更改的方式都不同，因此请查阅您供应商的文档。对于 KinD，请进入控制平面并更新清单文件：

**docker exec -it cluster-auth-control-plane bash**

**apt-get update**

**apt-get install vim**

**vi /etc/kubernetes/manifests/kube-apiserver.yaml**

1.  在 **command** 下查找两个选项，分别为 **--oidc-client** 和 **–oidc-issuer-url**。用前面命令产生的 API 服务器标志的输出替换这两个选项。确保在前面加上空格和破折号（**-**）。完成后应该看起来像这样：

- --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname

- --oidc-issuer-url=https://k8sou.apps.192-168-2-131.nip.io/auth/idp/k8sIdp

- --oidc-client-id=kubernetes

- --oidc-username-claim=sub

- --oidc-groups-claim=groups

- --oidc-ca-file=/etc/kubernetes/pki/ou-ca.pem

- --proxy-client-cert-file=/etc/kubernetes/pki/front-proxy-client.crt

1.  退出 vim 和 Docker 环境（*ctl+d*），然后查看 **api-server** pod：

kubectl get pod kube-apiserver-cluster-auth-control-plane -n kube-system

名称                      准备   状态    重启  年龄 kube-apiserver-cluster-auth-control-plane   1/1  运行中 0 73 秒

注意它只有 **73 秒**。这是因为 KinD 看到清单有变化，所以重新启动了 API 服务器。

重要提示

API 服务器 pod 被称为“静态 pod”。这个 pod 不能直接更改；它的配置必须从磁盘上的清单中更改。这为您提供了一个由 API 服务器作为容器管理的过程，但如果出现问题，您不需要直接在 EtcD 中编辑 pod 清单。

### 验证 OIDC 集成

一旦 OpenUnison 和 API 服务器集成完成，我们需要测试连接是否正常：

1.  要测试集成，请重新登录 OpenUnison，然后再次单击**Kubernetes 仪表板**链接。

1.  单击右上角的铃铛，您会看到一个不同的错误：![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_7.9_B15514.jpg)

图 7.9 - 启用 SSO，但用户未被授权访问任何资源

OpenUnison 和您之间的 SSO，您会发现 Kubernetes 正在工作！但是，新错误**service is forbidden: User https://...**是一个授权错误，**而不是**身份验证错误。API 服务器知道我们是谁，但不允许我们访问 API。

1.  我们将在下一章详细介绍 RBAC 和授权，但现在，请创建此 RBAC 绑定：

**kubectl create -f - <<EOF**

api 版本：rbac.authorization.k8s.io/v1

类型：ClusterRoleBinding

元数据：

   名称：ou-cluster-admins

主题：

- 类型：组

   名称：k8s-cluster-admins

   api 组：rbac.authorization.k8s.io

角色引用：

   类型：ClusterRole

   名称：cluster-admin

   api 组：rbac.authorization.k8s.io

EOF

clusterrolebinding.rbac.authorization.k8s.io/ou-cluster-admins 已创建

1.  最后，返回仪表板，您会发现您对集群拥有完全访问权限，所有错误消息都已消失。

API 服务器和 OpenUnison 现在已连接。此外，已创建了一个 RBAC 策略，以使我们的测试用户能够作为管理员管理集群。通过登录 Kubernetes 仪表板验证了访问权限，但大多数交互将使用**kubectl**命令进行。下一步是验证我们能够使用**kubectl**访问集群。

### 使用您的令牌与 kubectl

重要说明

本节假定您的网络中有一台计算机，上面有一个浏览器和正在运行的**kubectl**。

使用仪表板有其用例，但您可能会在大部分时间内使用**kubectl**与 API 服务器进行交互，而不是使用仪表板。在本节中，我们将解释如何检索您的 JWT 以及如何将其添加到 Kubernetes 配置文件中：

1.  您可以从 OpenUnison 仪表板中检索令牌。转到 OpenUnison 主页，单击标有**Kubernetes Tokens**的密钥。您将看到以下屏幕：![图 7.10 – OpenUnison kubectl 配置工具](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_7.10_B15514.jpg)

图 7.10 – OpenUnison kubectl 配置工具

OpenUnison 提供了一个命令行，您可以将其复制并粘贴到主机会话中，以将所有必需的信息添加到您的配置中。

1.  首先，点击**kubectl**命令旁边的双文档按钮，将**kubectl**命令复制到缓冲区中。将网页浏览器保持在后台打开。

1.  在从 OpenUnison 粘贴**kubectl**命令之前，您可能希望备份原始配置文件：

cp .kube/config .kube/config.bak

export KUBECONFIG=/tmp/k

kubectl get nodes

**W0423 15:46:46.924515    3399 loader.go:223] Config not found: /tmp/k error: no configuration has been provided, try setting KUBERNETES_MASTER environment variable**

1.  然后，转到主机控制台，并将命令粘贴到控制台中（以下输出已经被缩短，但您的粘贴将以相同的输出开头）：

export TMP_CERT=$(mktemp) && echo -e "-----BEGIN CER. . .

已设置集群"kubernetes"。

上下文"kubernetes"已修改。

**用户"mlbiamext"已设置。**

已切换到上下文"kubernetes"。

1.  现在，验证您是否可以使用**kubectl get nodes**查看集群节点：

kubectl get nodes

**名称                         状态   角色    年龄   版本**

**cluster-auth-control-plane   就绪    主节点   47 分钟   v1.17.0**

**cluster-auth-worker          就绪    <none>   46 分钟   v1.17.0**

1.  您现在使用登录凭据而不是主证书！在您工作时，会话将会刷新。注销 OpenUnison 并观察节点列表。一两分钟内，您的令牌将过期并且不再起作用：

**$ kubectl get nodes**

**无法连接到服务器：无法刷新令牌：oauth2：无法获取令牌：401 未经授权**

恭喜！您现在已设置好您的集群，使其可以执行以下操作：

+   使用 SAML2 进行身份验证，使用您企业现有的身份验证系统。

+   使用来自集中式身份验证系统的组来授权对 Kubernetes 的访问（我们将在下一章中详细介绍）。

+   使用集中式凭据为用户提供对 CLI 和仪表板的访问权限。

+   通过提供一种超时的方式，维护企业的合规性要求，以提供短暂的令牌。

+   从用户的浏览器到 Ingress Controller，再到 OpenUnison、仪表板，最后到 API 服务器，所有内容都使用 TLS。

接下来，您将学习如何将集中身份验证集成到托管的集群中。

# 引入冒充以将身份验证与云托管集群集成

使用来自谷歌、亚马逊、微软和 DigitalOcean 等云供应商的托管 Kubernetes 服务非常受欢迎（还有许多其他供应商）。在使用这些服务时，通常非常快速启动，并且它们都有一个共同的特点：它们不支持 OpenID Connect。

在本章的前面，我们谈到了 Kubernetes 通过 webhook 支持自定义身份验证解决方案，并且除非您是公共云提供商或其他 Kubernetes 系统的主机，否则绝对不要使用这种方法。事实证明，几乎每个云供应商都有自己的方法来使用这些 webhook，使用他们自己的身份和访问管理实现。在这种情况下，为什么不使用供应商提供的呢？有几个原因您可能不想使用云供应商的 IAM 系统：

+   **技术**：您可能希望以安全的方式支持云供应商未提供的功能，比如仪表板。

+   **组织**：将对托管的 Kubernetes 的访问与云的 IAM 紧密耦合会给云团队增加额外负担，这意味着他们可能不想管理对您的集群的访问。

+   **用户体验**：您的开发人员和管理员可能需要跨多个云进行工作。提供一致的登录体验可以让他们更容易，并且需要学习更少的工具。

+   **安全和合规性**：云实施可能不提供符合企业安全要求的选择，比如短暂的令牌和空闲超时。

尽管如此，可能有理由使用云供应商的实现。但您需要权衡需求。如果您想继续在托管的 Kubernetes 中使用集中身份验证和授权，您需要学习如何使用冒充。

## 什么是冒充？

Kubernetes 模拟登录是一种告诉 API 服务器您是谁的方式，而不知道您的凭据或强制 API 服务器信任 OpenID Connect IdP。当您使用**kubectl**时，API 服务器不会直接接收您的**id_token**，而是会接收一个服务账户或标识证书，该证书将被授权模拟用户，以及一组标头，告诉 API 服务器代理是代表谁在操作：

![图 7.11 – 用户在使用模拟登录时与 API 服务器交互的示意图](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_7.11_B15514.jpg)

图 7.11 – 用户在使用模拟登录时与 API 服务器交互的示意图

反向代理负责确定如何从用户提供的**id_token**（或者其他任何令牌）映射到**模拟用户**和**模拟组**HTTP 标头。仪表板永远不应该部署具有特权身份，模拟登录的能力属于特权。要允许 2.0 仪表板进行模拟登录，使用类似的模型，但是不是直接到 API 服务器，而是到仪表板：

![图 7.12 – 使用模拟登录的 Kubernetes 仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_7.12_B15514.jpg)

图 7.12 – 带有模拟登录的 Kubernetes 仪表板

用户与反向代理的交互就像任何 Web 应用程序一样。反向代理使用自己的服务账户并添加模拟登录标头。仪表板通过所有请求将此信息传递给 API 服务器。仪表板从不具有自己的身份。

## 安全考虑

服务账户具有某种超级权限：它可以被用来模拟**任何人**（取决于您的 RBAC 定义）。如果您从集群内部运行反向代理，那么服务账户是可以的，特别是如果与**TokenRequest** API 结合使用以保持令牌的短暂性。在本章的前面，我们谈到**ServiceAccount**对象没有过期时间。这里很重要，因为如果您将反向代理托管在集群外部，那么如果它被 compromise，某人可以使用该服务账户以任何人的身份访问 API 服务。确保您经常更换该服务账户。如果您在集群外运行代理，最好使用较短寿命的证书而不是服务账户。

在集群上运行代理时，您希望确保它被锁定。至少应该在自己的命名空间中运行。也不是**kube-system**。您希望最小化谁有访问权限。使用多因素身份验证进入该命名空间总是一个好主意，以及控制哪些 Pod 可以访问反向代理的网络策略。

根据我们刚刚学到的有关模拟的概念，下一步是更新我们集群的配置，以使用模拟而不是直接使用 OpenID Connect。您不需要云托管的集群来使用模拟。

# 为模拟配置您的集群

让我们为我们的集群部署一个模拟代理。假设您正在重用现有的集群，我们首先需要删除我们的 orchestra Helm 部署（这不会删除操作员；我们要保留 OpenUnison 操作员）。所以，让我们开始：

1.  运行以下命令以删除我们的**orchestra** Helm 部署：

**$ helm delete orchestra --namespace openunison**

**释放"orchestra"已卸载**

**openunison**命名空间中唯一运行的 Pod 是我们的操作员。请注意，当 orchestra Helm 图表部署时，操作员创建的所有 Secrets、Ingress、Deployments、Services 和其他对象都已消失。

1.  接下来，重新部署 OpenUnison，但这次更新我们的 Helm 图表以使用模拟。编辑**values.yaml**文件，并添加以下示例文件中显示的两行粗体线：

网络：

openunison_host："k8sou.apps.192-168-2-131.nip.io"

dashboard_host："k8sdb.apps.192-168-2-131.nip.io"

** api_server_host："k8sapi.apps.192-168-2-131.nip.io"**

会话不活动超时秒数：900

k8s_url：https://192.168.2.131:32776

cert_template：

ou："Kubernetes"

o："我的组织"

l："我的集群"

st："集群状态"

c："我的国家"

image："docker.io/tremolosecurity/openunison-k8s-login-saml2:latest"

myvd_config_path："WEB-INF/myvd.conf"

k8s_cluster_name：kubernetes

**enable_impersonation：true**

仪表板：

命名空间："kubernetes-dashboard"

cert_name："kubernetes-dashboard-certs"

标签："k8s-app=kubernetes-dashboard"

service_name："kubernetes-dashboard"

证书：

use_k8s_cm：false

trusted_certs：[]

监控：

prometheus_service_account：system:serviceaccount:monitoring:prometheus-k8s

saml：

idp_url：https://portal.apps.tremolo.io/idp-test/metadata/dfbe4040-cd32-470e-a9b6-809c8f857c40

metadata_xml_b64：""

我们在这里做了两个更改：

+   为 API 服务器代理添加一个主机

+   启用模拟

这些更改启用了 OpenUnison 的冒充功能，并生成了一个额外的 RBAC 绑定，以在 OpenUnison 的服务帐户上启用冒充。

1.  使用新的**values.yaml**文件运行 Helm 图表：

**helm install orchestra tremolo/openunison-k8s-login-saml2 –namespace openunison -f ./values.yaml**

**名称：orchestra**

**上次部署：2020 年 4 月 23 日星期四 20:55:16**

**命名空间：openunison**

**状态：已部署**

**修订版：1**

**测试套件：无**

1.  就像我们与 Kubernetes 的 OpenID Connect 集成一样，完成与测试身份提供者的集成。首先，获取元数据：

**$ curl --insecure https://k8sou.apps.192-168-2-131.nip.io/auth/forms/saml2_rp_metadata.jsp**

**<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="f4a4bacd63709fe486c30ec536c0f552a506d0023" entityID="https://k8sou.apps.192-168-2-131.nip.io/auth/SAML2Auth">**

**<md:SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:**

**协议">**

**。**

**。**

**。**

1.  接下来，登录到[`portal.apps.tremolo.io/`](https://portal.apps.tremolo.io/)，选择测试身份提供者，并将生成的元数据复制并粘贴到测试身份提供者的**元数据**位置。

1.  最后，点击**更新 Relying Party**以更新更改。

新的 OpenUnison 部署配置为 API 服务器的反向代理，并已重新集成到我们的 SAML2 身份提供者。没有需要设置的集群参数，因为冒充不需要任何集群端配置。下一步是测试集成。

## 测试冒充

现在，让我们测试我们的冒充设置。按照以下步骤进行：

1.  在浏览器中输入您的 OpenUnison 部署的 URL。这是您用于初始 OIDC 部署的相同 URL。

1.  登录到 OpenUnison，然后单击仪表板。您应该记得，第一次打开初始 OpenUnison 部署的仪表板时，直到创建了新的 RBAC 角色，才能访问集群，您会收到很多错误。

启用冒充并打开仪表板后，即使提示了新证书警告并且没有告诉 API 服务器信任您在仪表板上使用的新证书，您也不应该看到任何错误消息。

1.  单击右上角的小圆形图标，查看您登录的身份。

1.  接下来，返回到主 OpenUnison 仪表板，然后单击**Kubernetes Tokens**徽章。

请注意，传递给 kubectl 的**--server**标志不再具有 IP。相反，它具有**values.yaml**文件中**network.api_server_host**的主机名。这就是模拟。现在，您不再直接与 API 服务器交互，而是与 OpenUnison 的反向代理进行交互。

1.  最后，让我们将**kubectl**命令复制并粘贴到 shell 中：

export TMP_CERT=$(mktemp) && echo -e "-----BEGIN CERTIFI...

**集群"kubernetes"设置。**

**上下文"kubernetes"已创建。**

**用户"mlbiamext"设置。**

**切换到上下文"kubernetes"。**

1.  要验证您是否有访问权限，请列出集群节点：

kubectl get nodes

**名称                         状态   角色    年龄    版本**

**cluster-auth-control-plane   Ready    master   6h6m   v1.17.0**

**cluster-auth-worker          Ready    <none>   6h6m   v1.17.0**

1.  就像当您集成原始的 OpenID Connect 部署时一样，一旦您登出 OpenUnison 页面，一两分钟内，令牌将过期，您将无法刷新它们：

kubectl get nodes

**无法连接到服务器：刷新令牌失败：oauth2：无法获取令牌：401 未经授权**

您现在已经验证了您的集群是否正确地使用模拟工作。现在，模拟反向代理（OpenUnison）将所有请求转发到具有正确模拟标头的 API 服务器，而不是直接进行身份验证。通过提供登录和注销过程以及集成您的 Active Directory 组，您仍然满足企业的需求。

# 在没有 OpenUnison 的情况下配置模拟

OpenUnison 运算符自动化了一些关键步骤，使得模拟工作起来更加容易。还有其他专门为 Kubernetes 设计的项目，比如 JetStack 的 OIDC 代理（[`github.com/jetstack/kube-oidc-proxy`](https://github.com/jetstack/kube-oidc-proxy)），旨在使模拟更加容易。您可以使用任何能够生成正确标头的反向代理。在自己进行此操作时，有两个关键要理解的项目。

## 模拟 RBAC 策略

RBAC 将在下一章中介绍，但目前，授权服务帐户进行模拟的正确策略如下：

apiVersion：rbac.authorization.k8s.io/v1

种类：ClusterRole

元数据：

名称：模拟器

规则：

- apiGroups：

- ""

资源：

- 用户

- 组

动词：

- 模拟

为了限制可以模拟的帐户，将**resourceNames**添加到您的规则中。

## 默认组

当模拟用户时，Kubernetes 不会将默认组**system:authenticated**添加到模拟组列表中。当使用不知道如何为该组添加标头的反向代理时，需要手动配置代理以添加它。否则，简单的操作，如调用**/api**端点，将对除集群管理员之外的任何人都是未经授权的。

# 摘要

本章详细介绍了 Kubernetes 如何识别用户以及他们的成员所在的组。我们详细介绍了 API 服务器如何与身份交互，并探讨了几种身份验证选项。最后，我们详细介绍了 OpenID Connect 协议以及它如何应用于 Kubernetes。

学习 Kubernetes 如何认证用户以及 OpenID Connect 协议的细节是构建集群安全性的重要部分。了解细节以及它们如何适用于常见的企业需求将帮助您决定最佳的集群身份验证方式，并提供关于为什么应该避免我们探讨的反模式的理由。

在下一章中，我们将将我们的身份验证流程应用于授权访问 Kubernetes 资源。知道某人是谁并不足以保护您的集群。您还需要控制他们可以访问什么。

## 问题

1.  OpenID Connect 是一个标准协议，经过广泛的同行评审和使用。

A. 正确

B. 错误

1.  Kubernetes 使用哪个令牌来授权您访问 API？

A. **access_token**

B. **id_token**

C. **refresh_token**

D. **certificate_token**

1.  在哪种情况下，证书身份验证是一个好主意？

A. 管理员和开发人员的日常使用

B. 来自外部 CI/CD 流水线和其他服务的访问

C. 紧急情况下打破玻璃，当所有其他身份验证解决方案不可用时

1.  您应该如何识别访问您的集群的用户？

A. 电子邮件地址

B. Unix 登录 ID

C. Windows 登录 ID

D. 不基于用户名称的不可变 ID

1.  在 Kubernetes 中，OpenID Connect 配置选项设置在哪里？

A. 取决于发行版

B. 在 ConfigMap 对象中

C. 在一个 Secret 中

D. 设置为 Kubernetes API 服务器可执行文件的标志

1.  在使用模拟与您的集群时，您的用户带来的组是唯一需要的组。

A. 正确

B. 错误

1.  仪表板应该有自己的特权身份才能正常工作。

A. 正确

B. 错误


# 第八章：RBAC 策略和审计

认证只是集群访问管理的第一步。一旦集群访问权限被授予，限制账户的操作是很重要的，这取决于账户是用于自动化系统还是用户。授权访问资源是保护集群免受意外问题和恶意行为者滥用的重要部分。

在本章中，我们将详细介绍 Kubernetes 如何通过其基于角色的访问控制（RBAC）模型授权访问。本章的第一部分将深入探讨 Kubernetes RBAC 的配置方式，可用的选项以及将理论映射到实际示例中。调试和故障排除 RBAC 策略将是第二部分的重点。

在本章中，我们将涵盖以下主题：

+   RBAC 简介

+   将企业身份映射到 Kubernetes 以授权访问资源

+   命名空间多租户

+   Kubernetes 审计

+   使用**audit2rbac**调试策略

# 技术要求

本章具有以下技术要求：

+   使用*第七章*的配置运行的 KinD 集群，*将身份验证集成到您的集群*

+   从*第六章*的 SAML2 实验室访问，*服务、负载均衡和外部 DNS*

您可以在以下 GitHub 存储库中访问本章的代码：[`github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide`](https://github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide)。

# RBAC 简介

在我们深入研究 RBAC 之前，让我们快速了解一下 Kubernetes 和访问控制的历史。

在 Kubernetes 1.6 之前，访问控制是基于基于属性的访问控制（ABAC）的。顾名思义，ABAC 通过将规则与属性进行比较来提供访问权限，而不是角色。分配的属性可以分配任何类型的数据，包括用户属性、对象、环境、位置等。

过去，要为 ABAC 配置 Kubernetes 集群，您必须在 API 服务器上设置两个值：

+   **--authorization-policy-file**

+   **--authorization-mode=ABAC**

**authorization-policy-file** 是 API 服务器上的本地文件。由于它是每个 API 服务器上的本地文件，对文件的任何更改都需要对主机进行特权访问，并且需要重启 API 服务器。可以想象，更新 ABAC 策略的过程变得困难，任何即时更改都将需要短暂的停机，因为 API 服务器正在重新启动。

从 Kubernetes 1.6 开始，**RBAC** 成为授权访问资源的首选方法。与**ABAC** 不同，**RBAC** 使用 Kubernetes 本机对象，更新可以在不重启 API 服务器的情况下反映出来。**RBAC** 也与不同的身份验证方法兼容。从这里开始，我们的重点将放在如何开发 RBAC 策略并将其应用到您的集群上。

# 什么是角色？

在 Kubernetes 中，角色是将权限绑定到可以描述和配置的对象的一种方式。角色有规则，这些规则是资源和动词的集合。往回推，我们有以下内容：

+   **动词**：可以在 API 上执行的操作，例如读取（**get**），写入（**create**，**update**，**patch**和**delete**），或列出和监视。

+   **资源**：要对其应用动词的 API 名称，例如**services**，**endpoints**等。也可以列出特定的子资源。可以命名特定资源以在对象上提供非常具体的权限。

角色并不说明谁可以在资源上执行动词，这由**RoleBindings**和**ClusterRoleBindings**处理。我们将在*RoleBindings 和 ClusterRoleBindings*部分了解更多信息。

重要提示

术语“角色”可能有多重含义，并且 RBAC 经常在其他上下文中使用。在企业世界中，“角色”一词通常与业务角色相关联，并用于传达该角色的权限，而不是特定的个人。例如，企业可能会为所有应付账款人员分配发放支票的权限，而不是为应付账款部门的每个成员创建特定的分配以发放支票的特定权限。当某人在不同角色之间移动时，他们会失去旧角色的权限，并获得新角色的权限。例如，从应付账款到应收账款的转移中，用户将失去支付的能力并获得接受付款的能力。通过将权限与角色而不是个人绑定，权限的更改会随着角色更改而自动发生，而不必为每个用户手动切换权限。这是术语 RBAC 的更“经典”用法。

每个规则将构建的资源由以下内容标识：

+   **apiGroups**：资源所属的组列表

+   **resources**：资源的对象类型的名称（可能还包括子资源）

+   **resourceNames**：要应用此规则的特定对象的可选列表

每个规则*必须*有一个**apiGroups**和**resources**的列表。**resourceNames**是可选的。

重要提示

如果您发现自己从命名空间内部授权对特定对象的访问权限，那么是时候重新思考您的授权策略了。Kubernetes 的租户边界是命名空间。除非有非常特定的原因，否则在 RBAC 角色中命名特定的 Kubernetes 对象是一种反模式，应该避免。当 RBAC 角色命名特定对象时，请考虑分割它们所在的命名空间以创建单独的命名空间。

一旦在规则中标识了资源，就可以指定动词。动词是可以在资源上执行的操作，从而在 Kubernetes 中提供对对象的访问权限。

如果对对象的期望访问应为**all**，则无需添加每个动词；相反，可以使用通配符字符来标识所有**动词**、**资源**或**apiGroups**。

## 识别角色

Kubernetes 授权页面（[`kubernetes.io/docs/reference/access-authn-authz/rbac/`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)）使用以下角色作为示例，允许某人获取 pod 及其日志的详细信息：

apiVersion: rbac.authorization.k8s.io/v1

种类：角色

元数据：

命名空间：默认

名称：pod-and-pod-logs-reader

规则：

- apiGroups: [""]

资源：["pods", "pods/log"]

动词：["get", "list"]

逆向确定此角色是如何定义的，我们将从**资源**开始，因为这是最容易找到的方面。Kubernetes 中的所有对象都由 URL 表示。如果要获取默认命名空间中有关 pod 的所有信息，您将调用**/api/v1/namespaces/default/pods** URL，如果要获取特定 pod 的日志，您将调用**/api/v1/namespaces/default/pods/mypod/log** URL。

此 URL 模式适用于所有命名空间范围的对象。**pods**与**资源**对齐，**pods/log**也是如此。在尝试确定要授权的资源时，请使用 Kubernetes API 文档中的**api-reference**文档[`kubernetes.io/docs/reference/#api-reference`](https://kubernetes.io/docs/reference/#api-reference)。

如果您尝试在对象名称之后访问其他路径组件（例如在 pod 上的状态和日志），则需要明确授权。授权 pod 并不立即授权日志或状态。

基于使用 URL 映射到**资源**，你可能会认为**动词**将是 HTTP 动词。但事实并非如此。在 Kubernetes 中没有**GET**动词。动词是由 API 服务器中对象的模式定义的。好消息是，HTTP 动词和 RBAC 动词之间有静态映射（https://kubernetes.io/docs/reference/access-authn-authz/authorization/#determine-the-request-verb）。查看此 URL 时，请注意**PodSecurityPolicies**和模拟的 HTTP 动词之上有动词。这是因为**RBAC**模型不仅用于授权特定 API，还用于授权谁可以模拟用户以及如何分配**PodSecurityPolicy**对象。本章重点将放在标准 HTTP 动词映射上。

最后一个要识别的组件是 **apiGroups**。这是来自 URL 模型的另一个不一致的地方。**pods** 是“core”组的一部分，但 **apiGroups** 列表只是一个空字符串（**""**）。这些是最初 Kubernetes 的一部分的传统 API。大多数其他 API 将在 API 组中，并且该组将成为它们的 URL 的一部分。您可以通过查看要授权的对象的 API 文档来找到该组。

RBAC 模型中的不一致性可能会使调试变得困难，至少可以这么说。本章的最后一个实验将介绍调试过程，并消除定义规则时的大部分猜测。

现在我们已经定义了 Role 的内容以及如何定义特定权限，重要的是要注意，Role 可以应用于命名空间和集群级别。

## 角色与 ClusterRoles

RBAC 规则可以针对特定命名空间或整个集群进行范围限定。以前面的示例为例，如果我们将其定义为 ClusterRole 而不是 Role，并移除命名空间，我们将得到一个授权某人获取整个集群中所有 pod 的详细信息和日志的 Role。这个新角色也可以用于单独的命名空间，以将权限分配给特定命名空间中的 pod：

apiVersion: rbac.authorization.k8s.io/v1

种类：ClusterRole

元数据：

名称：cluster-pod-and-pod-logs-reader

规则：

- apiGroups: [""]

资源：["pods", "pods/log"]

动词：["get", "list"]

这个权限是全局应用于集群还是在特定命名空间范围内取决于它绑定到的主体。这将在 *RoleBindings 和 ClusterRoleBindings* 部分进行介绍。

除了在集群中应用一组规则外，ClusterRoles 也用于将规则应用于未映射到命名空间的资源，例如 PersistentVolume 和 StorageClass 对象。

在了解了如何定义 Role 之后，让我们了解一下为特定目的设计 Role 的不同方式。在接下来的部分中，我们将看看定义 Role 和它们在集群中的应用的不同模式。

## 负面角色

授权的最常见请求之一是“*我能否编写一个让我做除 xyz 之外的所有事情的 Role*？”在 RBAC 中，答案是*不行*。RBAC 要求要么允许每个资源，要么枚举特定资源和动词。这在 RBAC 中有两个原因：

+   **通过简单实现更好的安全性**：能够执行一条规则，说*每个秘密除了这一个*，需要比 RBAC 提供的更复杂的评估引擎。引擎越复杂，测试和验证就越困难，破坏的可能性就越大。一个更简单的引擎只是更容易编码和保持安全。

+   意想不到的后果：允许某人做任何事情，*除了* xyz，会在集群不断增长并添加新功能时以意想不到的方式留下问题的可能性。

在第一点上，构建具有这种功能的引擎很难构建和维护。这也使规则更难以跟踪。要表达这种类型的规则，你不仅需要授权规则，还需要对这些规则进行排序。例如，要说*我想允许一切，除了这个秘密*，你首先需要一个规则，说*允许一切*，然后一个规则，说*拒绝这个秘密*。如果你把规则改成*拒绝这个秘密*然后*允许一切*，第一个规则将被覆盖。你可以为不同的规则分配优先级，但这会使事情变得更加复杂。

有多种方法可以实现这种模式，可以使用自定义授权 webhook 或使用控制器动态生成 RBAC **Role**对象。这两种方法都应被视为安全反模式，因此本章不涉及这些内容。

第二点涉及意想不到的后果。支持使用操作员模式支持不是 Kubernetes 的基础设施的供应变得越来越流行，其中自定义控制器寻找**CustomResourceDefinition**（**CRD**）的新实例来供应基础设施，如数据库。亚马逊网络服务为此目的发布了一个操作员（[`github.com/aws/aws-controllers-k8s`](https://github.com/aws/aws-controllers-k8s)）。这些操作员在其自己的命名空间中以其云的管理凭据运行，寻找其对象的新实例来供应资源。如果你有一个允许一切“除了…”的安全模型，那么一旦部署，你集群中的任何人都可以供应具有实际成本并可能造成安全漏洞的云资源。从安全的角度来枚举你的资源是了解正在运行的内容和谁有访问权限的重要部分。

Kubernetes 集群的趋势是通过自定义资源 API 在集群外提供对基础设施的更多控制。您可以为 VM、额外节点或任何类型的 API 驱动云基础设施提供任何内容。除了 RBAC 之外，您还可以使用其他工具来减轻某人创建不应该创建的资源的风险，但这些应该是次要措施。

## 聚合的 ClusterRoles

ClusterRoles 可能会很快变得令人困惑并且难以维护。最好将它们分解为较小的 ClusterRoles，以根据需要进行组合。以管理员 ClusterRole 为例，它旨在让某人在特定命名空间内做任何事情。当我们查看管理员 ClusterRole 时，它列举了几乎所有资源。您可能会认为有人编写了这个 ClusterRole，以便它包含所有这些资源，但那将非常低效，而且随着新的资源类型被添加到 Kubernetes，会发生什么？管理员 ClusterRole 是一个聚合的 ClusterRole。看一下**ClusterRole**：

种类：ClusterRole

apiVersion：rbac.authorization.k8s.io/v1

元数据：

名称：admin

标签：

kubernetes.io/bootstrapping：rbac-defaults

注释：

rbac.authorization.kubernetes.io/autoupdate：'true'

规则：

。

。

。

aggregationRule：

clusterRoleSelectors：

- 匹配标签：

rbac.authorization.k8s.io/aggregate-to-admin：'true'

关键是**aggregationRule**部分。该部分告诉 Kubernetes 将所有具有**rbac.authorization.k8s.io/aggregate-to-admin**标签为 true 的 ClusterRoles 的规则合并起来。当创建新的 CRD 时，管理员无法创建该 CRD 的实例，而不添加包含此标签的新 ClusterRole。为了允许命名空间管理员用户创建新的**myapi**/**superwidget**对象的实例，创建一个新的**ClusterRole**：

apiVersion：rbac.authorization.k8s.io/v1

种类：ClusterRole

元数据：

名称：aggregate-superwidget-admin

标签：

# 将这些权限添加到“admin”默认角色。

rbac.authorization.k8s.io/aggregate-to-admin："true"

规则：

- apiGroups：["myapi"]

资源：["superwidgets"]

动词：["get"，"list"，"watch"，"create"，"update"，"patch"，"delete"]

下次您查看管理员 ClusterRole 时，它将包括**myapi**/**superwidgets**。您还可以直接引用此 ClusterRole 以获取更具体的权限。

## RoleBindings 和 ClusterRoleBindings

一旦权限被定义，就需要将其分配给某个东西以启用它。这个“东西”可以是用户、组或服务账户。这些选项被称为主题。与角色和 ClusterRoles 一样，RoleBinding 将一个角色或 ClusterRole 绑定到特定的命名空间，而 ClusterRoleBinding 将在整个集群中应用一个 ClusterRole。一个绑定可以有多个主题，但只能引用一个单一的角色或 ClusterRole。为了将本章前面创建的**pod-and-pod-logs-reader**角色分配给默认命名空间中名为**mysa**的服务账户、名为**podreader**的用户，或者拥有**podreaders**组的任何人，创建一个**RoleBinding**：

api 版本：rbac.authorization.k8s.io/v1

类型：RoleBinding

元数据：

名称：pod-and-pod-logs-reader

命名空间：默认

主题：

- 类型：ServiceAccount

名称：mysa

命名空间：默认

api 组：rbac.authorization.k8s.io

- 类型：用户

名称：podreader

- 类型：组

名称：podreaders

roleRef：

类型：角色

名称：pod-and-pod-logs-reader

api 组：rbac.authorization.k8s.io

前面的**RoleBinding**列出了三个不同的主题：

+   **ServiceAccount**：集群中的任何服务账户都可以被授权为 RoleBinding。必须包含命名空间，因为 RoleBinding 可以授权任何命名空间中的服务账户，而不仅仅是定义 RoleBinding 的命名空间。

+   **用户**：用户是由认证过程断言的。请记住来自*第七章*，*将认证集成到您的集群中*，在 Kubernetes 中没有代表用户的对象。

+   **组**：与用户一样，组也是认证过程的一部分，并与一个对象相关联。

最后，我们引用了之前创建的角色。类似地，为了将相同的主题赋予在整个集群中读取 pod 及其日志的能力，可以创建一个 ClusterRoleBinding 来引用本章前面创建的**cluster-pod-and-pod-logs-reader** ClusterRole：

api 版本：rbac.authorization.k8s.io/v1

类型：ClusterRoleBinding

元数据：

名称：cluster-pod-and-pod-logs-reader

主题：

- 类型：ServiceAccount

名称：mysa

命名空间：默认

api 组：rbac.authorization.k8s.io

- 类型：用户

名称：podreader

- 类型：组

名称：podreaders

roleRef：

类型：ClusterRole

名称：cluster-pod-and-pod-logs-reader

api 组：rbac.authorization.k8s.io

**ClusterRoleBinding**绑定到相同的主体，但是绑定到一个 ClusterRole 而不是命名空间绑定的 Role。现在，这些用户可以读取所有命名空间中的所有 pod 详情和 pod/logs，而不是只能读取默认命名空间中的 pod 详情和 pod/logs。

### 结合 ClusterRoles 和 RoleBindings

我们有一个使用案例，日志聚合器希望从多个命名空间中的 pod 中拉取日志，但不是所有命名空间。ClusterRoleBinding 太宽泛了。虽然 Role 可以在每个命名空间中重新创建，但这样做效率低下且维护困难。相反，定义一个 ClusterRole，但在适用的命名空间中从 RoleBinding 中引用它。这允许重用权限定义，同时仍将这些权限应用于特定的命名空间。一般来说，请注意以下内容：

+   ClusterRole + ClusterRoleBinding = 集群范围的权限

+   ClusterRole + RoleBinding = 特定于命名空间的权限

要在特定命名空间中应用我们的 ClusterRoleBinding，创建一个 Role，引用**ClusterRole**而不是命名空间的**Role**对象：

apiVersion：rbac.authorization.k8s.io/v1

种类：RoleBinding

元数据：

名称：pod-and-pod-logs-reader

命名空间：默认

主体：

- 种类：ServiceAccount

名称：mysa

命名空间：默认

apiGroup：rbac.authorization.k8s.io

- 种类：用户

名称：podreader

- 种类：组

名称：podreaders

角色引用：

种类：ClusterRole

名称：cluster-pod-and-pod-logs-reader

apiGroup：rbac.authorization.k8s.io

前面的**RoleBinding**让我们重用现有的**ClusterRole**。这减少了需要在集群中跟踪的对象数量，并且使得在 ClusterRole 权限需要更改时更容易更新权限。

在构建了我们的权限并定义了如何分配它们之后，接下来我们将看看如何将企业身份映射到集群策略中。

# 将企业身份映射到 Kubernetes 以授权对资源的访问

集中身份验证的好处之一是利用企业现有的身份，而不是必须创建用户需要记住的新凭据。重要的是要知道如何将您的策略映射到这些集中的用户。在*第七章*中，*将身份验证集成到您的集群*，您创建了一个集群，并将其与**Active Directory 联合服务**（**ADFS**）或 Tremolo Security 的测试身份提供者集成。为了完成集成，创建了以下**ClusterRoleBinding**：

apiVersion：rbac.authorization.k8s.io/v1

类型：ClusterRoleBinding

元数据：

名称：ou-cluster-admins

主题：

- 类型：组

名称：k8s-cluster-admins

apiGroup：rbac.authorization.k8s.io

roleRef：

类型：ClusterRole

名称：cluster-admin

apiGroup：rbac.authorization.k8s.io

这个绑定允许所有属于**k8s-cluster-admins**组的用户拥有完整的集群访问权限。当时，重点是身份验证，所以并没有提供太多关于为什么创建这个绑定的细节。

如果我们想直接授权我们的用户会怎样？这样，我们就可以控制谁可以访问我们的集群。我们的 RBAC **ClusterRoleBinding**会有所不同：

apiVersion：rbac.authorization.k8s.io/v1

类型：ClusterRoleBinding

元数据：

名称：ou-cluster-admins

主题：

- 类型：用户

名称：https://k8sou.apps.192-168-2-131.nip.io/auth/idp/k8sIdp#mlbiamext

apiGroup：rbac.authorization.k8s.io

roleRef：

类型：ClusterRole

名称：cluster-admin

apiGroup：rbac.authorization.k8s.io

使用与之前相同的 ClusterRole，这个 ClusterRoleBinding 将仅将**cluster-admin**权限分配给我的测试用户。

首先要指出的问题是用户在用户名前面有我们的 OpenID Connect 发行者的 URL。当 OpenID Connect 首次引入时，人们认为 Kubernetes 将与多个身份提供者和不同类型的身份提供者集成，因此开发人员希望您能够轻松区分来自不同身份来源的用户。例如，域 1 中的**mlbiamext**与域 2 中的**mlbiamext**是不同的用户。为确保用户的身份不会与来自身份提供者的另一个用户发生冲突，Kubernetes 要求在用户之前添加身份提供者的发行者。如果在 API 服务器标志中定义的用户名声明是邮件，则不适用此规则。如果您使用证书或模拟，则也不适用此规则。

除了不一致的实施要求，这种方法还可能在几个方面引起问题：

+   **更改您的身份提供者 URL**：今天，您在一个 URL 上使用一个身份提供者，但明天您决定将其移动。现在，您需要查看每个 ClusterRoleBinding 并对其进行更新。

+   **审计**：您无法查询与用户关联的所有 RoleBindings。您需要枚举每个绑定。

+   **大型绑定**：根据您拥有的用户数量，您的绑定可能会变得非常庞大且难以跟踪。

虽然有一些工具可以帮助您管理这些问题，但将绑定与组关联起来要比将其与个人用户关联起来容易得多。您可以使用**mail**属性来避免 URL 前缀，但这被认为是一种反模式，如果出于任何原因更改了电子邮件地址，将导致对集群的同样困难的更改。

在本章中，我们已经学会了如何定义访问策略并将这些策略映射到企业用户。接下来，我们需要确定如何将集群划分为租户。

# 实施命名空间多租户

为多个利益相关者或租户部署的集群应该按命名空间划分。这是 Kubernetes 从一开始就设计的边界。在部署命名空间时，通常会为命名空间中的用户分配两个 ClusterRoles：

+   **管理员**：这个聚合的 ClusterRole 提供了对 Kubernetes 提供的几乎每个资源的每个动词的访问权限，使管理员用户成为其命名空间的统治者。唯一的例外是可能影响整个集群的命名空间范围对象，例如**ResourceQuotas**。

+   **编辑**：类似于**admin**，但没有创建 RBAC 角色或 RoleBindings 的能力。

需要注意的是，**admin** ClusterRole 本身不能对命名空间对象进行更改。命名空间是集群范围的资源，因此只能通过 ClusterRoleBinding 分配权限。

根据您的多租户策略，**admin** ClusterRole 可能不合适。生成 RBAC Role 和 RoleBinding 对象的能力意味着命名空间管理员可以授予自己更改资源配额或运行提升的 PodSecurityPolicy 权限的能力。这就是 RBAC 倾向于崩溃并需要一些额外选项的地方：

+   **不要授予对 Kubernetes 的访问权限**：许多集群所有者希望让他们的用户远离 Kubernetes，并将其互动限制在外部 CI/CD 工具上。这对于微服务来说效果很好，但在多条线上开始出现问题。首先，将更多的传统应用程序移入 Kubernetes 意味着需要更多的传统管理员直接访问其命名空间。其次，如果 Kubernetes 团队让用户远离集群，他们现在就要负责了。拥有 Kubernetes 的人可能不想成为应用程序所有者希望的事情没有发生的原因，而且通常，应用程序所有者希望能够控制自己的基础设施，以确保他们能够处理任何影响其性能的情况。

+   将访问视为特权：大多数企业都需要特权用户才能访问基础设施。这通常是使用特权访问模型来完成的，其中管理员有一个单独的帐户，需要“签出”才能使用，并且只在“变更委员会”或流程批准的特定时间内获得授权。对这些帐户的使用受到严格监控。如果您已经有一个系统，特别是一个与企业的中央身份验证系统集成的系统，这是一个很好的方法。

+   **为每个租户提供一个集群**：这种模式将多租户从集群移动到基础设施层。您并没有消除问题，只是移动了解决问题的地方。这可能导致无法管理的蔓延，并且根据您如何实施 Kubernetes，成本可能会飙升。

+   **准入控制器**：这些通过限制可以创建哪些对象来增强 RBAC。例如，准入控制器可以决定阻止创建 RBAC 策略，即使 RBAC 明确允许。这个主题将在 *第十一章*，*使用 Open Policy Agent 扩展安全性* 中介绍。

除了授权访问命名空间和资源外，多租户解决方案还需要知道如何提供租户。这个主题将在最后一章，*第十四章*，*提供平台* 中介绍。

现在我们已经有了实施授权策略的策略，我们需要一种方法来调试这些策略，以及在创建它们时知道何时违反这些策略。Kubernetes 提供了审计功能，这将是下一节的重点，我们将在其中将审计日志添加到我们的 KinD 集群并调试 RBAC 策略的实施。

# Kubernetes 审计

Kubernetes 审计日志是您从 API 视角跟踪集群中发生的事情的地方。它以 JSON 格式呈现，这使得直接阅读变得更加困难，但使用诸如 Elasticsearch 等工具解析变得更加容易。在 *第十二章*，*使用 Falco 和 EFK 进行 Pod 审计* 中，我们将介绍如何使用 **Elasticsearch、Fluentd 和 Kibana (EFK)** 堆栈创建完整的日志系统。

## 创建审计策略

策略文件用于控制记录哪些事件以及在哪里存储日志，可以是标准日志文件或 Webhook。我们在 GitHub 存储库的 **chapter8** 目录中包含了一个示例审计策略，并将其应用于我们在整本书中一直在使用的 KinD 集群。

审计策略是一组规则，告诉 API 服务器要记录哪些 API 调用以及如何记录。当 Kubernetes 解析策略文件时，所有规则都按顺序应用，只有初始匹配的策略事件才会应用。如果对某个事件有多个规则，可能无法在日志文件中收到预期的数据。因此，您需要小心确保事件被正确创建。

策略使用 **audit.k8s.io** API 和 **Policy** 的清单类型。以下示例显示了策略文件的开头：

apiVersion: audit.k8s.io/v1beta1

kind: Policy

规则：

- level: Request

userGroups: ["system:nodes"]

动词：["update","patch"]

资源：

- group: "" # core

resources: ["nodes/status", "pods/status"]

omitStages:

- "RequestReceived"

重要提示

虽然策略文件看起来像标准的 Kubernetes 清单，但您不使用 **kubectl** 应用它。策略文件与 API 服务器上的 **--audit-policy-file** API 标志一起使用。这将在 *在集群上启用审计* 部分进行解释。

为了理解规则及其将记录的内容，我们将详细介绍每个部分。

规则的第一部分是 **level**，它确定将为事件记录的信息类型。可以为事件分配四个级别：

![表 8.1 – Kubernetes 审计级别](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/B15514_table_8.1.jpg)

表 8.1 – Kubernetes 审计级别

**userGroups**、**verbs** 和 **resources** 值告诉 API 服务器将触发审计事件的对象和操作。在这个例子中，只有来自 **system:nodes** 的请求，尝试在 **core** API 上的 **node/status** 或 **pod/status** 上执行 **update** 或 **patch** 操作才会创建事件。

**omitStages** 告诉 API 服务器在 *stage* 期间跳过任何日志记录事件，这有助于限制记录的数据量。API 请求经历四个阶段：

![表 8.2 – 审计阶段](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/B15514_table_8.2.jpg)

表 8.2 – 审计阶段

在我们的例子中，我们设置了事件忽略 **RequestReceived** 事件，这告诉 API 服务器不要记录任何传入 API 请求的数据。

每个组织都有自己的审计政策，政策文件可能会变得又长又复杂。不要害怕设置一个记录所有内容的策略，直到您掌握了可以创建的事件类型。记录所有内容并不是一个好的做法，因为日志文件会变得非常庞大。调整审计策略是一个随着时间学习的技能，随着您对 API 服务器的了解越来越多，您将开始了解哪些事件对审计最有价值。

策略文件只是启用集群审计的开始，现在我们已经了解了策略文件，让我们解释如何在集群上启用审计。

## 在集群上启用审计

启用审计对于每个 Kubernetes 发行版都是特定的。在本节中，我们将在 KinD 中启用审计日志以了解低级步骤。作为一个快速提醒，上一章的最终产品是一个启用模拟的 KinD 集群（而不是直接集成 OpenID Connect）。本章中的其余步骤和示例假定正在使用此集群。

您可以手动按照本节中的步骤操作，也可以在 GitHub 存储库的**chapter8**目录中执行包含的脚本**enable-auditing.sh**：

1.  首先，将示例审计策略从**chapter8**目录复制到 API 服务器：

k8s@book:~/kind-oidc-ldap-master$ docker cp k8s-audit-policy.yaml cluster01-control-plane:/etc/kubernetes/audit/

1.  接下来，在 API 服务器上创建存储审计日志和策略配置的目录。我们将进入容器，因为我们需要在下一步中修改 API 服务器文件：

k8s@book:~/kind-oidc-ldap-master$ docker exec -ti cluster01-control-plane bash

root@cluster01-control-plane:/# mkdir /var/log/k8s

root@cluster01-control-plane:/# mkdir /etc/kubernetes/audit

root@cluster01-control-plane:/# exit

此时，您已经在 API 服务器上有了审计策略，并且可以启用 API 选项以使用该文件。

1.  在 API 服务器上，编辑**kubeadm**配置文件**/etc/kubernetes/manifests/kube-apiserver.yaml**，这是我们更新以启用 OpenID Connect 的相同文件。要启用审计，我们需要添加三个值。需要注意的是，许多 Kubernetes 集群可能只需要文件和 API 选项。由于我们正在使用 KinD 集群进行测试，我们需要第二和第三步。

1.  首先，为启用审计日志的 API 服务器添加命令行标志。除了策略文件，我们还可以添加选项来控制日志文件的轮换、保留和最大大小：

- --tls-private-key-**file=/etc/kubernetes/pki/apiserver.key**

**    - --audit-log-path=/var/log/k8s/audit.log**

**    - --audit-log-maxage=1**

**    - --audit-log-maxbackup=10**

**    - --audit-log-maxsize=10**

**    - --audit-policy-file=/etc/kubernetes/audit/k8s-audit-policy.yaml**

请注意，该选项指向您在上一步中复制的策略文件。

1.  接下来，在**volumeMounts**部分添加存储策略配置和生成日志的目录：

- mountPath: /usr/share/ca-certificates

name: usr-share-ca-certificates

readOnly: true

- mountPath：/var/log/k8s

名称：var-log-k8s

只读：false

- mountPath：/etc/kubernetes/audit

名称：etc-kubernetes-audit

只读：true

1.  最后，将 **hostPath** 配置添加到 **volumes** 部分，以便 Kubernetes 知道在哪里挂载本地路径：

- hostPath：

路径：/usr/share/ca-certificates

类型：目录或创建

名称：usr-share-ca-certificates

- hostPath：

路径：/var/log/k8s

类型：目录或创建

名称：var-log-k8s

- hostPath：

路径：/etc/kubernetes/audit

类型：目录或创建

名称：etc-kubernetes-audit

1.  保存并退出文件。

1.  与所有 API 选项更改一样，您需要重新启动 API 服务器才能使更改生效；但是，KinD 将检测到文件已更改并自动重新启动 API 服务器的 pod。

退出附加的 shell 并检查 **kube-system** 命名空间中的 pods：

k8s@book:~/kind-oidc-ldap-master$ kubectl get pods -n kube-system

名称：READY STATUS RESTARTS AGE

calico-kube-controllers-5b644bc49c-q68q7 1/1 Running 0 28m

calico-node-2cvm9 1/1 Running 0 28m

calico-node-n29tl 1/1 Running 0 28m

coredns-6955765f44-gzvjd 1/1 Running 0 28m

coredns-6955765f44-r567x 1/1 Running 0 28m

etcd-cluster01-control-plane 1/1 Running 0 28m

kube-apiserver-cluster01-control-plane 1/1 Running 0 14s

kube-controller-manager-cluster01-control-plane 1/1 Running 0 28m

kube-proxy-h62mj 1/1 Running 0 28m

kube-proxy-pl4z4 1/1 Running 0 28m

kube-scheduler-cluster01-control-plane 1/1 Running 0 28m

API 服务器被强调仅运行了 14 秒，显示其成功重新启动。

1.  已验证 API 服务器正在运行，让我们查看审计日志以验证其是否正常工作。要检查日志，您可以使用 **docker exec** 来查看 **audit.log**：

$ docker exec cluster01-control-plane tail /var/log/k8s/audit.log

此命令生成以下日志数据：

**{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"473e8161-e243-4c5d-889c-42f478025cc2","stage":"ResponseComplete","requestURI":"/apis/crd.projectcalico.org/v1/clusterinformations/default","verb":"get","user":{"usernam**

**e":"system:serviceaccount:kube-system:calico-kube-controllers","uid":"38b96474-2457-4ec9-a146-9a63c2b8182e","groups":["system:serviceaccounts","system:serviceaccounts:kube-system","system:authenticated"]},"sourceIPs":["172.17.0.2"],"userAgent":"**

**Go-http-client/2.0","objectRef":{"resource":"clusterinformations","name":"default","apiGroup":"crd.projectcalico.org","apiVersion":"v1"},"responseStatus":{"metadata":{},"code":200},"requestReceivedTimestamp":"2020-05-20T00:27:07.378345Z","stageT**

**imestamp":"2020-05-20T00:27:07.381227Z","annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by ClusterRoleBinding \"calico-kube-controllers\" of ClusterRole \"calico-kube-controllers\" to ServiceAc**

**计数\"calico-kube-controllers/kube-system\""}}**

这个 JSON 中包含了大量信息，直接查看日志文件可能会很具有挑战性地找到特定事件。幸运的是，现在您已经启用了审计，可以将事件转发到中央日志服务器。我们将在*第十二章**，使用 Falco 和 EFK 进行审计*中进行此操作，我们将部署一个 EFK 堆栈。

现在我们已经启用了审计，下一步是练习调试 RBAC 策略。

# 使用 audit2rbac 调试策略

有一个名为**audit2rbac**的工具，可以将审计日志中的错误反向工程成 RBAC 策略对象。在本节中，我们将使用这个工具在发现我们的一个用户无法执行他们需要执行的操作后生成一个 RBAC 策略。这是一个典型的 RBAC 调试过程，学会使用这个工具可以节省您花费在隔离 RBAC 问题上的时间：

1.  在上一章中，创建了一个通用的 RBAC 策略，允许**k8s-cluster-admins**组的所有成员成为我们集群中的管理员。如果您已登录 OpenUnison，请注销。

1.  现在，再次登录，但在屏幕底部点击**完成登录**按钮之前，删除**k8s-cluster-admins**组，并添加**cn=k8s-create-ns,cn=users,dc=domain,dc=com**：![图 8.1 – 更新的登录属性](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_8.1_B15514.jpg)

图 8.1 – 更新的登录属性

1.  接下来，点击**完成登录**。登录后，转到仪表板。就像当 OpenUnison 首次部署时一样，因为集群管理员的 RBAC 策略不再适用，所以不会有任何命名空间或其他信息。

重要提示

**memberOf**属性的格式已从简单名称更改为 LDAP 专有名称，因为这是 ADFS 或 Active Directory 最常呈现的格式。**专有名称**或**DN**从左到右读取，最左边的组件是对象的名称，其右边的每个组件是其在 LDAP 树中的位置。例如，**name cn=k8s-create-ns,cn=users,dc=domain,dc=com**组被读作"在**domain.com**域（**dc**）的**users**容器（**cn**）中的**k8s-create-ns**组。"虽然 ADFS 可以生成更用户友好的名称，但这需要特定的配置或脚本编写，因此大多数实现只是添加**memberOf**属性，列出用户所属的所有组。

1.  接下来，从令牌屏幕上复制您的**kubectl**配置，确保将其粘贴到不是您的主 KinD 终端的窗口中，以免覆盖您的主配置。

1.  一旦您的令牌设置好，尝试创建一个名为**not-going-to-work**的命名空间：

**PS C:\Users\mlb> kubectl create ns not-going-to-work**

**服务器错误（禁止）：命名空间被禁止：用户"mlbiamext"无法在集群范围的 API 组""中创建资源"namespaces"**

这里有足够的信息来反向工程一个 RBAC 策略。

1.  为了消除此错误消息，创建一个带有**"namespaces"**资源的**ClusterRole**，**apiGroups**设置为**""**，动词为**"create"**：

apiVersion: rbac.authorization.k8s.io/v1

kind: ClusterRole

metadata:

name: cluster-create-ns

rules:

- apiGroups: [""]

resources: ["namespaces"]

verbs: ["create"]

1.  接下来，为用户和这个 ClusterRole 创建一个**ClusterRoleBinding**：

apiVersion: rbac.authorization.k8s.io/v1

kind: ClusterRoleBinding

metadata:

name: cluster-create-ns

subjects:

- kind: User

name: mlbiamext

apiGroup: rbac.authorization.k8s.io

roleRef:

kind: ClusterRole

name: cluster-create-ns

apiGroup: rbac.authorization.k8s.io

1.  创建了 ClusterRole 和 ClusterRoleBinding 后，尝试再次运行命令，它将起作用：

**PS C:\Users\mlb> kubectl create ns not-going-to-work namespace/not-going-to-work created**

不幸的是，这不太可能是大多数 RBAC 调试的情况。大多数情况下，调试 RBAC 不会如此清晰或简单。通常，调试 RBAC 意味着在系统之间收到意外的错误消息。例如，如果您正在部署 **kube-Prometheus** 项目进行监控，通常希望通过 **Service** 对象进行监控，而不是通过显式命名的 pods。为了做到这一点，Prometheus ServiceAccount 需要能够列出要监控的服务所在命名空间中的 **Service** 对象。Prometheus 不会告诉您需要发生这种情况；您只会看不到列出的服务。更好的调试方法是使用一个知道如何读取审计日志并且可以根据日志中的失败来逆向工程一组角色和绑定的工具。

**audit2rbac** 工具是这样做的最佳方式。它将读取审计日志并为您提供一组可行的策略。它可能不是确切所需的策略，但它将提供一个良好的起点。让我们试一试：

1.  首先，将 shell 附加到集群的 **control-plane** 容器上，并从 GitHub 下载工具（[`github.com/liggitt/audit2rbac/releases`](https://github.com/liggitt/audit2rbac/releases)）：

**root@cluster01-control-plane:/# curl -L https://github.com/liggitt/audit2rbac/releases/download/v0.8.0/audit2rbac-linux-amd64.tar.gz 2>/dev/null > audit2rbac-linux-amd64.tar.gz**

**root@cluster01-control-plane:/# tar -xvzf audit2rbac-linux-amd64.tar.gz**

1.  在使用该工具之前，请确保关闭包含 Kubernetes 仪表板的浏览器，以免污染日志。此外，删除之前创建的 **cluster-create-ns** ClusterRole 和 ClusterRoleBinding。最后，尝试创建 **still-not-going-to-work** 命名空间：

**PS C:\Users\mlb> kubectl create ns still-not-going-to-work**

**服务器错误（禁止）：用户“mlbiamext”无法在集群范围的 API 组中创建“namespaces”资源**

1.  接下来，使用 **audit2rbac** 工具查找测试用户的任何失败： 

**root@cluster01-control-plane:/# ./audit2rbac --filename=/var/log/k8s/audit.log  --user=mlbiamext**

**打开审计源...**

**加载事件...**

**评估 API 调用...**

**生成角色...**

**apiVersion: rbac.authorization.k8s.io/v1**

**kind: ClusterRole**

**metadata:**

**  annotations:**

**    audit2rbac.liggitt.net/version: v0.8.0**

**  labels:**

**    audit2rbac.liggitt.net/generated: "true"**

**    audit2rbac.liggitt.net/user: mlbiamext**

**  名称：audit2rbac:mlbiamext**

**规则：**

**- apiGroups:**

**  - ""**

**  资源：**

**  - 命名空间**

**  动词：**

**  - 创建**

**---**

**apiVersion: rbac.authorization.k8s.io/v1**

**种类：ClusterRoleBinding**

**元数据：**

**  注释：**

**    audit2rbac.liggitt.net/version: v0.8.0**

**  标签：**

**    audit2rbac.liggitt.net/generated: "true"**

**    audit2rbac.liggitt.net/user: mlbiamext**

**  名称：audit2rbac:mlbiamext**

**roleRef:**

**  apiGroup: rbac.authorization.k8s.io**

**  种类：ClusterRole**

**  名称：audit2rbac:mlbiamext**

主题：

**- apiGroup: rbac.authorization.k8s.io**

**  种类：用户**

**  名称：mlbiamext**

**完成！**

这个命令生成了一个策略，确切地允许测试用户创建命名空间。然而，这成为了一个反模式，明确授权用户访问。

1.  为了更好地利用这个策略，最好使用我们的组：

apiVersion: rbac.authorization.k8s.io/v1

种类：ClusterRole

元数据：

名称：create-ns-audit2rbac

规则：

- apiGroups:

- ""

资源：

- 命名空间

动词：

- 创建

---

apiVersion: rbac.authorization.k8s.io/v1

种类：ClusterRoleBinding

元数据：

名称：create-ns-audit2rbac

roleRef:

apiGroup: rbac.authorization.k8s.io

种类：ClusterRole

名称：create-ns-audit2rbac

主题：

- apiGroup: rbac.authorization.k8s.io

**种类：组**

**  名称：cn=k8s-create-ns,cn=users,dc=domain,dc=com**

主要变化已经突出显示。现在，**ClusterRoleBinding**不再直接引用用户，而是引用**cn=k8s-create-ns,cn=users,dc=domain,dc=com**组，以便该组的任何成员现在都可以创建命名空间。

# 摘要

本章重点是 RBAC 策略的创建和调试。我们探讨了 Kubernetes 如何定义授权策略以及如何将这些策略应用于企业用户。我们还看了这些策略如何用于在集群中启用多租户。最后，我们在 KinD 集群中启用了审计日志，并学习了如何使用**audit2rbac**工具来调试 RBAC 问题。

使用 Kubernetes 内置的 RBAC 策略管理对象可以让您在集群中启用操作和开发任务所需的访问权限。了解如何设计策略可以帮助限制问题的影响，从而让用户更有信心自行处理更多事务。

在下一章中，我们将学习如何保护 Kubernetes 仪表板，以及如何处理组成您集群的其他基础设施应用程序的安全性。您将学习如何将我们对认证和授权的学习应用到组成您集群的应用程序中，为您的开发人员和基础设施团队提供更好、更安全的体验。

# 问题

1.  真或假 - ABAC 是授权访问 Kubernetes 集群的首选方法。

A. 正确

B. 错误

1.  角色的三个组成部分是什么？

A. 主题，名词和动词

B. 资源，动作和组

C. **apiGroups**，资源和动词

D. 组，资源和子资源

1.  你可以去哪里查找资源信息？

A. Kubernetes API 参考

B. 这个库

C. 教程和博客文章

1.  如何在命名空间之间重用角色？

A. 你不能；你需要重新创建它们。

B. 定义一个 ClusterRole，并在每个命名空间中引用它作为 RoleBinding。

C. 在一个命名空间中引用角色，使用其他命名空间的 RoleBindings。

D. 以上都不是

1.  绑定应该如何引用用户？

A. 直接，列出每个用户。

B. RoleBindings 应该只引用服务账户。

C. 只有 ClusterRoleBindings 应该引用用户。

D. 在可能的情况下，RoleBindings 和 ClusterRoleBindings 应该引用组。

1.  真或假 - RBAC 可以用于授权访问除一个资源之外的所有内容。

A. 正确

B. 错误

1.  真或假 - RBAC 是 Kubernetes 中唯一的授权方法。

A. 正确

B. 错误
