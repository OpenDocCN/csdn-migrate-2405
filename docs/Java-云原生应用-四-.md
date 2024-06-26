# Java 云原生应用（四）

> 原文：[`zh.annas-archive.org/md5/3AA62EAF8E1B76B168545ED8887A16CF`](https://zh.annas-archive.org/md5/3AA62EAF8E1B76B168545ED8887A16CF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：API 设计最佳实践

本章讨论如何设计以消费者为中心的 API，这些 API 是细粒度的，以功能为导向的。它还讨论了 API 设计关注的各种最佳实践，例如如何识别将用于形成 API 的资源，如何对 API 进行分类，API 错误处理，API 版本控制等。我们将通过 Open API 和 RAML 来描述 API 的模型。

我们将涵盖以下主题：

+   API 设计关注点

+   API 网关部署

# API 设计关注点

API 旨在被消费并定义了 API 如何被消费。API 指定了所需与 API 交互的命令/操作列表以及这些命令的格式/模式。

在定义 REST API 时，信息的关键抽象是资源。资源被定义为对一组实体的概念映射。API 设计围绕着构成设计核心的资源。**统一资源标识符**（**URI**），操作（使用 HTTP 方法）和资源表示（JSON 模式）都是以资源为中心构建的。拥有正确的资源抽象对于启用 API 的消费、可重用性和可维护性非常重要。

资源可以指向单个实体或一组实体。例如，产品是一个单一的资源，而产品是一组资源。我们将在两个层面上介绍设计准则：

+   如何确定正确的资源粒度水平

+   如何围绕已识别的资源设计 API

# API 资源识别

API 的设计与问题域的基础业务领域模型相关联。API 需要以消费者为中心，关注消费者的需求。领域驱动设计原则被应用于确定正确的粒度。有界上下文模式是帮助将问题领域划分为不同有界上下文并明确它们关系的中心模式。对于企业，资源识别也受到中央/组架构团队定义的规范模型的驱动。

此外，根据 API 的定义位置和其暴露的功能/功能，API 可以分为三个广泛的类别：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/105a7699-7bf2-4e86-8fc5-57dd56a50515.jpg)

让我们在接下来的章节中详细讨论这些类别。

# 系统 API

关键企业资源或记录系统需要作为一组 API 对所有下游系统开放或暴露，以便这些服务周围构建逻辑/体验。对于绿地项目，系统 API 通常代表作为功能的一部分开发的记录系统或数据存储。当涉及企业时，系统 API 代表所有企业系统，例如核心企业资源规划（ERP）系统、运营数据存储、主机应用程序，或许多商业现成产品，例如客户关系管理（CRM）等，这些产品运行企业的核心流程。系统 API 的一些显著特点如下：

+   领域驱动设计的起源源于查看核心系统领域，并创建有界上下文来定义系统 API。

+   这些记录系统通常映射到 HTTP 资源类型—名词—并提供实体服务。例如，在银行账户的情况下，抵押贷款、证券和卡片是构建系统 API 的核心实体或名词。

+   有界上下文模型定义了服务拥有其数据存储。但在现有系统的情况下，例如企业资源规划（ERP），服务可能共享相同的基础系统。这需要对基础业务流程进行仔细研究，识别领域（也称为名词），并将其作为系统 API 公开。账户可以是一个系统 API，但账户转账将是一个利用基础账户系统 API 提供服务的过程 API。

+   系统 API 传统上非常稳定，并且不受渠道或过程 API 层变化的影响。这些是核心、稳定的企业端的一部分。

+   企业系统的组合和集成机制定义了系统 API 如何与基础系统集成。例如，一个主机可能会规定使用 MQ 作为集成机制，从而使系统 API 实现 MQ 以将主机功能暴露为 API。

+   系统 API 最大的问题是它们的正常运行时间和弹性与基础系统的稳定性相关联。如果核心应用程序频繁崩溃或出现问题，这些问题往往会传递到系统 API 层。

# 过程 API

纯粹主义者会说，系统 API 暴露了系统的核心功能，应用程序应该从系统 API 中整合功能，以向最终客户提供所需的功能。这对于较小的应用程序或应用程序的初始迭代可能效果很好。随着应用程序变得更大，或者开始在多个渠道或设备上公开功能，您开始看到功能开始复制的情况，这意味着缺乏重用，导致系统难以维护。过程 API 的一些显着特点如下：

+   过程 API 提供了在系统 API 基础上构建的更丰富的功能。例如，我们可以将账户转账功能编写为过程 API，而不是每个渠道都编写账户转账功能，以便在各个渠道之间提供一致且可重用的模型。

+   从消费者的角度来看，过程 API 提供了一个更简单的模型来访问功能，而不是尝试编排多个系统 API。这有助于改善客户端的易用性，并有助于减少 API 网关层的流量。

+   过程 API 还可以用于为应用程序提供跨渠道/全渠道功能。此级别可以处理诸如渠道上下文切换等问题。

+   应用程序倾向于引入过程 API 以改善整体系统的性能。如果系统 API 与速度慢或只能处理有限吞吐量的系统相关联，可以使用过程 API 来缓存来自系统 API 的数据，以避免每次都访问基础系统。如果系统记录不可用，随后系统 API 也不可用，过程 API 可以用于处理此类请求，提供替代的功能流程。

+   过程 API 也可以充当适配器，用于外部第三方调用，而不是应用程序直接进行第三方调用。使用过程 API 可以处理第三方 API 失败不影响应用程序其余部分的情况。过程 API 可以应用模式，例如断路器和限流对外部请求进行处理以处理多种情况。

# 渠道 API

最终的 API 分类是通道 API。顾名思义，这些 API 是特定于通道的，并映射到作为应用程序一部分构建的客户旅程。这些也被称为体验 API 或旅程 API。例如，如果您正在使用 Angular 或 React 构建应用程序，则需要将**单页应用程序**（**SPA**）的客户旅程映射到通道 API 可以提供的底层服务。通道 API 的一些显着特点如下：

+   通道 API 映射到与通道不可避免地相关的客户旅程。有时也称为体验 API。这些 API 可以是有状态的，因为它们在客户旅程中为客户提供服务，并且需要携带会话上下文。人们可以通过将状态外部化到诸如 Redis 之类的会话存储中来构建无状态服务。

+   每当客户旅程发生变化时，通道 API 将发生变化。通道 API 之间的可重用性系数并不是很高。通常在 10-15%之间。例如，如果类似的客户旅程映射到 Android 和 iOS 应用程序，则有可能重用相同的 API。

+   通道 API 通常不具有业务逻辑或任何服务编排逻辑，因为这些问题通常由过程 API 层处理。

+   诸如安全性（CQRS，CORS）、身份验证、授权、节流等问题是在 API 网关层处理的，而不是传递到通道 API 层。

+   有时，在 API 开发过程中，人们可能对 API 进行了严格的区分和定义。但在许多应用程序迭代过程中，这些区分开始出现在 API 中，人们可以开始看到应用程序朝着这些分类发展。

+   接下来，我们将介绍适用于我们看到的三种分类的 API 设计指南。

# API 设计指南

一旦确定了正确的资源粒度级别，API 设计指南的其余部分将帮助制定合适的合同/接口，以实现可消费性、可重用性和可维护性。

RESTful 客户端应能够通过访问 URI 路径发现所有可用的操作和资源。客户端应能够处理以下内容：

+   **请求**：处理发送到服务器端的入站处理消息

+   **响应**：服务器提供的封装信息

+   **路径**：所请求资源的唯一标识符

+   **参数**：作为键/值对添加到请求中以指定操作（如过滤器、子集等）的元素

当我们开始设计 API 时，我们分享了多年来遇到的一些最佳实践。

# 命名和关联

资源名称通常指的是从业务领域提取的名词。一旦确定了名词，API 合同就可以被建模为针对这些名词的 HTTP 动词：

+   资源的选择需要考虑细粒度与粗粒度模型。过于细粒度意味着过于啰嗦，而粗粒度意味着过于狭窄的焦点，导致对变化的支持。人们可以通过在一定程度上使用系统与过程 API 模型来推理。但问题在于，如果资源过于细粒度，系统 API 的数量会增加，导致难以维护的复杂性。

+   API 是通过查看消费者的需求来设计的。根据客户旅程和它们如何映射到底层数据存储来推导您的 API 需求。这意味着，使用顶层设计方法来查看 API 设计。首先进行数据建模的底层模型可能不会产生正确的平衡。如果您有现有的企业资产，您将需要执行一种中间相遇的方法，通过编写帮助弥合差距的过程 API 来平衡客户的需求。

# 资源的基本 URL

这取决于您如何处理资源——作为单例还是作为集合。因此，理想情况下，您将得到一个资源的两个基本 URL，一个用于集合，另一个用于实体。例如：

| **资源** | `POST`(**创建**) | `GET`(**读取**) | `PUT`(**更新**) | `DELETE`(**删除**) |
| --- | --- | --- | --- | --- |
| `/orders` | 创建新订单 | 订单列表 | 替换为新订单 | 错误（不想删除所有订单） |
| `/orders/1234` | 错误 | 显示 ID 为`1234`的订单 | 如果存在则更新订单；如果不存在则创建新订单 | 删除 ID 为`1234`的订单 |

# 处理错误

利用标准 HTTP 状态代码指示问题/错误：

+   如果使用 JSON，错误应该是一个顶级属性

+   在出现错误时，要描述清楚、正确和有信息性

以下是一个示例错误消息片段：

```java
{ 
   "type": "error", 
   "status":400, 
   "code": "bad_request", 
   "context_info": { 
         "errors": [ 
         { 
               "reason": "missing_argument", 
               "message": "order_id is required", 
               "name": "order_id", 
               "location": "query_param" 
         } 
         ] 
   }, 
   "help_url": "http://developers.some.com/api/docs/#error_code", 
   "message": "Bad Request" 
   "request_id": "8233232980923412494933" 
} 
```

以下是 HTTP 代码使用的一些示例：

+   400 错误的请求

+   401 未经授权

+   403 禁止

+   404 未找到

+   409 冲突

+   429 请求过多

+   5xx API 有故障

# 版本控制

有多种服务版本模型：

+   **URL**：您只需将 API 版本添加到 URL 中，例如：`https://getOrder/order/v2.0/sobjects/Account`。经常使用，但不是良好的实践。

+   **接受标头**：您可以修改接受标头以指定版本，例如：`Accept: application/vnd.getOrders.v2+json`。客户端很少使用，且繁琐。

+   **模式级别**：使用模式强制执行验证，难以强制执行 JSON，与 XML 配合效果很好。良好的实践/罕见。

+   **API 外观层**：使用外观层来隐藏客户端的版本复杂性。

请记住，资源是一个语义模型；资源的表现形式和状态可能随时间变化，但标识符必须始终指向相同的资源。因此，只有在概念发生根本变化时才应使用新的 URI。API 外观层可以将北向 API 与底层服务和模式版本抽象出来。API 管理平台支持创建 API 外观层。

# 分页

使用带有分页信息的 URL 来处理结果的偏移和限制。例如，`/orders?limit=25&offset=50`。

# 属性

API 应支持使用查询参数模型由消费者请求的数据属性。例如，`/orders?fields=id,orderDate,total`。

# 数据格式

API 应根据消费者的要求提供多种数据格式的支持。例如，`/orders/1234.json`以 JSON 格式返回数据。

# 客户端支持有限的 HTTP 方法

根据设备及其有限的支持 HTTP 动词的能力，您可能希望使用以下方法来提供对 HTTP 方法的支持：

+   **创建**：`/orders?method=post`

+   **读取**：`/orders`

+   **更新**：`/orders/1234?method=put&location=park`

+   **删除** `/orders/1234?method=delete`

# 身份验证和授权

REST 服务在适当时使用基于角色的成员资格，并提供独立启用`GET`、`POST`、`PUT`和`DELETE`的能力。

通常，这个问题应该在 API 网关级别处理。您不应该将其作为服务的一部分处理。

# 端点重定向

服务清单可能会因业务或技术原因随时间变化。可能无法立即替换所有对旧端点的引用。

通过采用这种设计实践，服务端点的消费者在服务清单重组时会自动适应。它会自动将访问过时端点标识符的服务消费者引用到当前标识符：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/af4ea0b7-d13a-46fd-a7d2-d3e5990d80b6.jpg)

HTTP 原生支持使用 3xx 状态代码和标准标头的端点重定向模式：

+   301 永久移动

+   307 临时重定向

+   位置/新 URI

# 内容协商

服务消费者可能会以不向后兼容的方式更改其要求。一个服务可能需要支持旧的和新的消费者，而不必为每种消费者引入特定的能力。

服务可以指定特定的内容和数据表示格式，以便在运行时作为其调用的一部分接受或返回。服务合同涉及多种标准化媒体类型。

# 安全

始终使用 SSL 来保护您的 URI。SSL 确保了加密通信，从而简化了身份验证的工作——不需要为每个 API 请求签名。

这涵盖了一些与 API 设计相关的最佳实践。可以从谷歌、Facebook 和亚马逊是如何定义他们的公共 API 中学习，并将其作为 API 设计的基础。

# API 建模

有两种标准在竞相描述 API——开放 API 和 RESTful API。我们将在以下部分更详细地讨论它们。

# 开放 API

开放 API 倡议旨在创建和推广基于 Swagger 规范的供应商中立的 API 描述格式。开放 API 规范允许我们为 REST API 定义一个标准的、与语言无关的接口，这使得人类和计算机都能够在没有访问源代码的情况下发现和理解服务的能力。

在下图中，我们描述了一个基于开放 API 的示例 API 定义以及各个部分：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/44109d4d-7d5b-4fe3-8a9a-4397dfba17e6.jpg)

代码在下图中继续：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/b70bd4dd-d2e9-42cd-ad0f-9e1f48d9bb96.jpg)

代码在下图中继续：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/a66becbc-6580-4d77-bacc-d5ecc9ade2ca.jpg)

# RESTful API 建模语言（RAML）

**RESTful API 建模语言**（**RAML**）是一种描述 RESTful API 的标准语言。RAML 以与 YAML 相同的方式编写，YAML 是一种人类可读的数据序列化语言。RAML 的目标是提供描述 API 所需的所有必要信息。RAML 提供了一种可供各种 API 管理工具读取的机器可读的 API 设计。

在下图中，我们描述了一个示例 RAML 以及各个部分：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/22192408-6050-466b-9aa6-aab8c5e6ab51.jpg)

RAML 映射到完整的 API 设计生命周期，可以分为以下几类：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/05a2aabd-5ec8-474c-967f-8add021bf9dc.jpg)

让我们来看一下流程：

1.  **设计**：API 供应商提供编辑器作为 API 开发套件的一部分，以帮助设计/编写 API/RAML 定义，从而实现更快的开发和更少的错误。生成的 RAML 可以用模拟数据进行增强，并允许与业务所有者/消费者进行迭代，以进行验证和正确性。

1.  **构建**：生成的 RAML 提供了 API 构建的规范。开发套件可以基于 RAML 生成存根，以便插入逻辑。

1.  **测试**：RAML 可以用于生成测试脚本。诸如 Postman 和 Abao 之类的工具允许导入 RAML 规范并生成用于验证 API 的测试。此外，诸如 API Fortress 和 SmartBear 之类的工具还可以测试响应延迟、有效负载和错误。

1.  **文档**：RAML 规范可以转换为基于 HTML 的模型。诸如 RAML2HTML for PHP、API Console 等工具提供了一种将 RAML 指定的文档公开的简单方法。该模型允许在规范中进行任何更改，并将其反映在文档中并保持同步。

1.  **集成**：API 生命周期的最后阶段是能够集成或消费 API。使用 RAML，供应商/工具可以创建多种集成和消费 API 的方式。使用 RAML，可以构建特定于 API 的 SDK。供应商还提供可以利用 RAML 与客户端逻辑集成的工具。

两种标准之间的选择取决于组织选择的 API 网关产品堆栈。大多数产品都更偏好一种标准，尽管每个产品都声称支持两种标准。

# API 网关部署模型

API 网关提供了一个外观模式，封装了系统的内部工作，为所有传入客户端提供了一个统一的入口点。API 网关可以为每种类型的客户端提供定制的 API，同时解决诸如安全性、身份验证、授权、限流、负载平衡等问题。

让我们来看看影响 API 如何部署在 API 网关上的因素。

+   **客户端或通道类型**：根据请求的设备或通道的不同，API 可能需要为不同的数据子集提供服务。例如，服务的桌面版本可能需要更多的细节，而移动客户端则需要更少。甚至手机和平板之间的数据也可能有差异。我们如何确保同一个微服务可以为所有设备类型的请求提供服务，并且仍然处理这些变化？在这种情况下，我们为不同的设备类型创建多个 API，以满足客户端的特定需求，而不会打扰微服务。

+   **数据转换**：有时，后端的服务是构建为提供 JSON 内容的。有一个要求要求提供 XML 响应或反之。在这种情况下，API 网关在网关级别进行数据转换，同时提供一个提供 XML 响应的 API，使服务能够在不改变或了解客户端需求的情况下工作。

+   **版本控制**：对于公共 API 或与未在 URI 中添加版本控制的资源相关的 API，API 网关可以根据客户端和使用的版本将传入的请求路由到正确的服务。在这种情况下，API 网关可以使用多种技术解析服务版本：

+   客户端标识符可用于识别它们是否已切换到新版本或正在使用旧版本。

+   根据 SLA 将客户端分为多个类别。当新版本发布时，较低的类别或低使用率的客户端可以被要求切换到新版本。随着客户端升级，API 网关可以将它们重定向到正确的服务版本。

+   **编排**：有时，API 可能需要调用多个后端服务并聚合结果。在这种情况下，API 网关必须同时调用多个服务并聚合结果。有时，服务调用之间可能存在依赖关系。例如，传入请求可能需要在实际服务调用之前进行身份验证，或者可能需要提取额外的客户端或会话信息以调用该调用。可以在 API 网关层编写整个编排逻辑，因为一些产品提供了运行时支持。另一个选择可能是编写一个执行跨其他服务的编排并提供一个整合 API 供消费的过程 API。这有助于减少交互并从客户端的角度提高整体性能。

我们在第三章《设计您的云原生应用程序》中介绍了编排模式。

+   **服务发现**：随着服务实例的上下，服务注册表是关于服务端点在任何给定时间可用的唯一真实数据源。API 网关应该能够在运行时调用服务注册表以获取服务端点，并使用它来调用服务。服务注册表可以用作跨注册服务实例的负载平衡机制。

+   **处理超时**：对于在合理时间内没有响应的服务，API 网关允许您设置超时请求。这使得网关可以处理超时失败，并为客户端提供故障模式。其中一种选择可以是提供缓存数据（如果适用并根据服务类型），或者快速失败模式，其中网关可以立即返回错误或失败，而不调用服务。

+   **数据缓存**：API 网关还可以为提供静态数据或不经常更改的数据的服务调用缓存数据。这种模式可以减少服务实例上的流量，提高整体响应延迟和整体系统的弹性。缓存的数据也可以用作次要故障流程，以防主要流程失败。

+   **服务调用**：部署的服务可以使用多个接口或协议。例如，您可能有使用异步消息传递机制（如 JMS、MQ、Kafka 等）的服务，或者其他服务可能使用 HTTP 或 Thrift 等同步模型。API 网关应该能够支持多种服务调用模型，并在这些调用方法之上提供编排模型。

+   **服务计量/限流**：对于某些类别的客户，您可能希望限制他们可以进行的服务调用次数。例如，如果您提供了一个功能减少的免费模式服务，以及在一定时间内可以进行的调用次数限制。根据客户类型（免费或付费）对传入请求进行计量和限流的能力有助于围绕您的 API 和基础服务提供商业模式。如果您正在对另一个 SaaS 提供商进行外部 API 调用，通过 API 网关路由这些调用可以帮助预测/管理外部调用的数量，并在使用账单出现时避免不必要的冲击。

+   **API 监控**：另一个重要问题是监控 API 调用是否有任何偏差，无论是在各种百分位数的响应延迟、失败率、API 可用性等方面。这些指标需要在仪表板上绘制，并配备适当的警报和通知系统。根据失败类型，可以自动化恢复脚本以克服它们。

这些是可以应用于 API 网关的各种使用场景和模式，以将您的服务作为 API 向消费者公开。

# 总结

在本章中，我们看到了 API 如何根据其主要用途和基础资源进行分类。我们了解了关于整体 API 设计的最佳实践以及通过 Open API 或 RAML 规范对 API 进行建模的标准。接下来，我们看到了 API 网关如何利用来解决服务层未处理的问题。

在下一章中，我们将介绍云开发对企业现有格局的影响，以及它如何实现向数字化企业转型。


# 第十三章：数字化转型

云计算的出现正在影响企业景观的各个方面。从核心基础设施到面向客户的应用程序，企业景观正在受到变革力量的影响。一些企业是这些转型的领先者，而其他一些企业仍在努力弄清楚从何处开始以及该做什么。根据行业领域的成熟度，转型之旅可能大相径庭。一些领域是首批采纳技术趋势的（如金融服务业），而其他领域则等待技术过时后采纳新技术（制造业、公用事业）。在本章中，我们将涵盖以下内容：

+   映射应用程序组合以进行数字化转型

+   将现有的单片应用程序分解为分布式云原生应用程序

+   在流程、人员和技术层面上需要的变更

+   构建自己的平台服务（控制与委托）

# 应用程序组合合理化

数字化转型的决定通常与更大的应用程序组合相关联。在客户为中心、提供更好的客户体验、合规性/监管、云计算的出现、开源等外部力量的影响下，企业开始审视他们的整个应用程序景观，并确定需要改进、增强和重塑的领域。

最初的步骤是确定需要转型为云部署的机会或应用程序。在这一步中，我们通常会通过业务和技术参数进行整体组合分析。这些参数有助于提供组合的加权得分。利用这些得分，我们可以将应用程序映射到四个象限。这些象限有助于我们确定在哪里集中精力以及我们将看到最大价值的地方。

# 组合分析 - 业务和技术参数

应用程序根据业务和技术参数进行测量和评分。

技术价值的参数如下：

+   IT 标准合规性

+   架构标准合规性

+   服务质量

+   可维护性

+   运营考虑

+   许可证/支持成本

+   基础设施成本

+   项目/变更成本

+   应用程序维护成本

+   采购（内部采购/外包）

业务价值的参数如下：

+   财务影响

+   应用用户影响

+   客户影响

+   关键性

+   业务对齐

+   功能重叠/冗余

+   监管/合规风险

+   服务故障风险

+   产品/供应商稳定性

您可以按 1-5 的比例对这些参数进行评分（1 表示最低，5 表示最高）。

通过映射这些参数，我们可以确定成本和复杂性的热点，并根据业务能力领域对应用程序进行分类。这些应用程序类别进一步分析其相互依赖性、接触点、集成点和基础设施。利用所有这些，我们可以分析收益并为转型路线图提供建议。下一步基于业务价值和技术价值；我们将应用程序绘制到以下四个象限之一：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/74c6700a-b4de-41c3-9191-68a0df37c21b.jpg)

这些得分有助于我们在应用程序和组合级别提供成本效益分析。它还有助于确定功能重叠的地方（由于合并和收购活动），了解业务和 IT 的不一致之处，以及业务优先级所在。这些可以帮助确定投资机会所在以及潜在的非核心领域。

利用上述基础，每个象限中的应用程序可以进一步映射到以下图表中所示的倾向之一：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/52b5ea01-ecdf-48e4-b449-9269a51bd586.jpg)

这些倾向为我们提供了在我们将在以下部分讨论的领域内的应用的合理机会。

# 退役

所有属于低商业价值和低技术价值的应用程序都可以被标记为退役。这些通常是在不同的商业环境中失去了相关性或实施了新功能的应用程序。

这些应用程序的使用率低，商业风险非常低。也可以通过对这些应用程序的工单和使用量进行汇总来确定这类应用程序。使用率低、工单数量较少的应用程序通常是退役的候选者。

# 保留

所有具有低技术价值和高商业价值的应用程序都属于这一类。技术成熟度可能较低，但它们为业务提供了重大价值。从 IT 角度来看，这些应用程序的运行成本并不高。我们可以保持这些应用程序的运行，因为它们仍然为业务提供了重大价值。

# 整合

所有具有高技术价值和低商业价值的应用程序都属于这一类。高技术价值可能是由于技术支持成本高、缺乏技术技能的人员、缺乏文档等。业务可以阐明这些应用程序的价值，但目前对这些应用程序的支出可能无法证明合理。这些应用程序需要迁移和整合以升级技术水平。

# 转换

这些是具有高技术价值和高商业价值的应用程序。这意味着这些应用程序拥有大量用户、多次发布、大量工单和高基础设施支持成本，但仍然为业务提供了重大优势。这些应用程序是需要付出努力的地方，因为它们为组织提供了重大的差异化。

使用上述方法，我们可以确定哪些应用程序适合进行转换。例如，我们可以采取一个目前在本地运行并需要转换为分布式应用程序设计模型的现有 Java/JEE 应用程序。

# 单片应用程序转换为分布式云原生应用程序

J2EE 规范的出现，加上应用服务器提供的必要服务，导致了单片应用程序的设计和开发：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/8e333613-c3c5-4408-bf91-506c0c9a7944.png)

单片应用程序及其生态系统的一些特征是：

+   所有内容都打包到一个单一的`.ear`文件中。 单一的`.ear`文件需要进行为期数月的测试周期，这导致了生产中变更速度的降低。通常一年或两年进行一次*大规模*的生产推动。

+   应用程序构建复杂性非常高，跨各种模块存在依赖关系。有时，应用程序使用的 JAR 文件版本之间会发生冲突。

+   应用程序之间的重复使用主要通过共享`.JAR`文件来实现。

+   庞大的错误和功能数据库——从积压的角度来看，各种应用程序模块中存在许多功能集/错误。有时，一些积压可能会相互冲突。

+   用户验收标准通常未定义。有一些冒烟测试，但大多数新功能和集成大多只在生产中可见。

+   需要多个团队的参与和重大监督（业务团队、架构团队、开发团队、测试团队、运营团队等）进行设计、开发和运营管理。在发布周期中，协调各个团队之间是一项艰巨的工作。

+   随着时间的推移，技术债务不断积累——随着新功能/功能添加到应用程序中，原始设计从未进行任何更改/重构以适应新的需求。这导致应用程序中积累了大量死代码和重复代码。

+   过时的运行时环境（许可证、复杂的更新）——应用程序可能在较旧版本的 JVM、较旧的应用服务器和/或数据库上运行。升级成本高且通常非常复杂。规划升级意味着在该开发周期内放弃任何功能发布。多个团队的参与需要复杂的项目管理模型。缺乏回归测试脚本使情况变得更糟。

+   团队采用了技术设计导向的方法。架构和设计在开发开始之前就已经确定。随着应用程序的增长，新的功能/功能被添加，不再重新审视应用程序架构/设计。

+   几乎没有使用业务组件或域。应用程序设计通常是根据层（表示层、业务层、集成层和数据库层）和客户/应用程序流程切片，进入特定的模块/模式。例如，使用 MVC 模式的应用程序将创建类似于模型、视图和控制器的包，还有值和常用包。

+   通常，整个应用程序只有一个数据库模式。在数据库级别没有功能的分离。域通过外键相互连接，数据库遵循第三范式。应用程序设计通常是自下而上的，数据库模式决定了应用程序数据库层的设计。

+   平均企业应用程序将有超过 50 万行代码，其中有大量样板代码。随着应用程序的增长，源代码库中将有大量死代码和重复代码。

+   应用程序通常由笨重的基础设施支持——通过增加更多硬件来管理应用程序的能力。服务器集群用于扩展应用程序。

+   成千上万的测试用例导致回归测试套件运行时间增加。有时，发布将跳过回归测试套件以加快周期。

+   大多数这类项目的团队规模超过 20 人。

我们可以看到，在单片应用程序的情况下，业务速度和变化速度非常低。这种模式可能在 10-15 年前有效。在当今竞争激烈的市场中，以令人难以置信的速度发布功能/功能的能力至关重要。你不仅仅是在与其他大型企业竞争，还要与许多没有传统应用程序、技术和流程包袱的更灵活的初创企业竞争。

开源的兴起、消费者公司的增长以及移动设备的增多等因素导致了应用程序架构领域的创新，以及更多由微服务和反应性模型驱动的分布式应用程序。单片应用程序被分解成更小的应用程序/服务集。

接下来，我们将探讨与分布式应用程序相关的关键架构问题。我们将看到这些关键问题如何映射到整体应用程序的技术能力，以及应该雇用哪些能力，应该建立哪些能力。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/cc6c12b2-74b7-46b6-ba1e-f5c665efba34.png)

分布式应用程序及其生态系统的一些特征包括：

+   轻量级运行时容器：微服务的出现与笨重的 JEE 容器的消亡相关。随着应用程序变成具有单一目的和松散耦合的微服务，有必要简化管理组件生命周期的容器。Netty 的出现导致了反应性框架的发展，正好符合这一目的。

+   **事务管理**：应用简化的另一个牺牲品是事务管理。有界上下文意味着服务不会与多个资源交互，并尝试进行两阶段提交事务。诸如 CQRS、事件存储、多版本并发控制（MVCC）、最终一致性等模式有助于简化并将应用程序移动到不需要锁定资源的模型。

+   **服务扩展**：拆分应用程序允许单独扩展各个服务。使用帕累托法则，80%的流量由 20%的服务处理。扩展这 20%的服务的能力成为更高可用性 SLA 的重要驱动因素。

+   **负载均衡**：与单体应用程序不同，单体应用程序的负载均衡是在应用服务器集群节点之间进行的，而在分布式应用程序的情况下，负载均衡是跨服务实例（在类似 Docker 的容器中运行）进行的。这些服务实例是无状态的，通常会频繁上下线。发现活动实例和非活动实例的能力成为负载均衡的关键特性。

+   **灵活部署**：分布式架构的一个关键能力是从严格的集群部署模型转变为更灵活的部署模型（牛群与宠物），其中部署实例被部署为不可变实例。诸如 Kubernetes 之类的编排引擎允许最佳利用底层资源，并消除了管理/部署数百个实例的痛苦。

+   **配置**：随着服务实例变得不可变，服务配置被抽象出来并保存在中央存储库（配置管理服务器）中。服务在启动时，或作为服务初始化的一部分，获取配置并以可用模式启动。

+   **服务发现**：使用无状态不可变服务实例在通用硬件上运行意味着服务可以随时上下线。调用这些服务的客户端应能够在运行时发现服务实例。这一特性，连同负载均衡，有助于维护服务的可用性。一些新产品（如 Envoy）已将服务发现与负载均衡合并。

+   **服务版本**：随着服务开始获得消费者，将需要升级服务契约以适应新功能/变更。在这种情况下，运行多个版本的服务变得至关重要。您需要担心将现有消费者迁移到新的服务版本。

+   **监控**：与传统的单体监控侧重于基础设施和应用服务器监控不同，分布式架构需要在事务级别进行监控，因为它流经各种服务实例。应用性能管理（APM）工具如 AppDynamics、New Relic 等用于监控事务。

+   **事件处理/消息传递/异步通信**：服务不是基于点对点进行通信的。服务利用事件作为一种异步通信的手段来解耦。一些关键的消息传递工具，如 RabbitMQ、Kafka 等，用于在服务之间进行异步通信。

+   **非阻塞 I/O**：服务本身利用非阻塞 I/O 模型从底层资源中获得最大性能。反应式架构正在被微服务框架追求（如 Play 框架、Dropwizard、Vert.x、Reactor 等）用于构建底层服务。

+   **多语言服务**：分布式应用的出现以及使用 API 作为集成允许使用最先进的技术构建服务实例。由于集成模型是 JSON over HTTP，服务可以是多语言的，允许使用正确的技术构建服务。服务还可以根据服务需求的类型使用不同的数据存储。

+   高性能持久性：由于服务拥有自己的数据存储，读/写服务需要处理大量并发请求。诸如**命令查询请求分离**（**CQRS**）的模式使我们能够分离读/写请求，并将数据存储迁移到最终一致性模型。

+   **API 管理**：分布式架构的另一个关键要素是能够将服务限流、身份验证/授权、转换、反向代理等问题抽象出来，并移到称为 API 管理的外部层。

+   **健康检查和恢复**：服务实现健康检查和恢复，以便负载均衡器发现健康的服务实例并删除不健康的实例。服务实现心跳机制，该机制由服务发现机制用于跟踪应用程序景观中的健康/不健康服务。

+   **跨服务安全性**：服务对服务的调用需要得到保护。数据在传输过程中可以通过安全通信（HTTPS）或通过加密数据来保护。服务还可以使用公钥/私钥来匹配哪些客户服务可以调用其他服务。

我们看到了构建分布式应用所需的一些架构问题。为了覆盖整体应用程序的范围，构建为一堆微服务，我们正在关注以下各个领域的关键架构问题：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/ac53a31f-61c7-4325-b819-738e65b2f28f.jpg)

为了使应用成为云原生，重要的是使用云供应商提供的 SaaS/PaaS 构建应用。这种模式使您能够专注于业务功能的转变，提高创新速度，并改善客户体验。除非技术不是组织的关键差异化因素，否则核心基础设施和平台服务的运行应该留给专家。在需求存在巨大变化的情况下，云弹性规模模型提供了一种推动力。我不想为云供应商做营销，但除非基础设施对您的业务不重要，否则您不应该运行基础设施。

唯一的缺点是您会受到云供应商提供的服务的限制。组织正在采用多云供应商策略，他们将应用程序分散开来，并利用云供应商的关键差异化因素。例如，GCP 提供了丰富的分析和机器学习功能库，具有运行分析工作负载和解密意义洞察的能力，**机器学习**（**ML**）模型是使用最先进功能的一种方式。同样，对于面向消费者的应用程序，AWS 提供了丰富的 PaaS 服务集，可用于推出和转向以客户为中心的解决方案。

# 将单体应用转换为分布式应用

在本节中，我们将以单体应用为例，看看需要哪些步骤才能将其架构为分布式应用。

我们假设一个典型的 Java 应用在应用服务器上运行，通过集群模型进行扩展，并使用典型的关系型数据库管理系统（RDBMS）。该应用已经投入生产，并需要重构/迁移到分布式架构。

我们将讨论需要共同工作以重构/推出分布式应用程序的多个并行轨道。我们将首先涵盖各个轨道，然后看到它们如何结合在一起。在您的组织中，您可能选择为每个轨道拥有单独的团队，或者一个团队管理多个轨道。这个想法是为您提供一个实际转型单体应用程序所涉及的活动的一瞥。

# 客户旅程映射到领域驱动设计

开始数字化转型的关键驱动因素是定义新的客户旅程并构建新的客户体验。这种以客户为中心的方式推动业务资助数字化转型计划。对于我们的情况，我们可以假设业务已经批准了数字化转型计划，然后我们从那里开始。

从服务分解的角度来看，我们需要遵循这里提到的步骤：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/40b2159c-2db2-4bb6-8961-45f4bc9a67a3.jpg)

+   **客户体验旅程映射**：数字化转型的一个关键驱动因素是定义新的客户旅程。客户体验旅程是客户初始接触点的地图，通过过程参与模型。这个练习通常由专家完成，涉及客户关注研究、接触点、涉及的参与者/系统、业务需求和竞争分析等内容。客户旅程通常以信息图的形式创建。

客户旅程有助于确定客户互动在设备、渠道或流程之间移动时的差距。它有助于填补这些差距，并确定增强整体客户体验的手段和方法。

+   **推导领域模型**：客户体验旅程地图被映射到当前和未来的需求。这些需求然后形成用户故事的基础。对于新应用程序，需求可以形成系统的功能分解的基础。在现有应用程序的情况下，系统可能已经分解为可识别的领域/子领域。

一旦我们有了需求，我们就可以开始识别系统内的各个子领域。领域模型使用普遍语言进行记录。整个想法是使用业务和技术团队都能理解的语言。

领域围绕实体及其功能进行建模。我们还考虑在这些功能之间相互操作的依赖关系。通常，首次尝试时，我们得到一个大块泥巴，其中已经识别出所有已知的实体和功能。对于较小的应用程序，领域模型可能是合适的大小，但对于较大的应用程序，大块泥巴需要进一步分解，这就是有界上下文发挥作用的地方。

+   **定义有界上下文**：大块泥巴需要分解成更小的块，以便更容易采用。每个这些更小的块或有界上下文都有其围绕特定责任构建的业务上下文。上下文也可以围绕团队的组织方式或现有应用程序代码库的结构进行建模。

定义上下文的规则没有固定的定义，但非常重要的是每个人都理解边界条件。您可以创建上下文地图来绘制领域景观，并确保有界上下文得到清晰定义和映射。有各种模式（例如，共享内核、顺应者、生产者/供应者等），可以应用于绘制有界上下文。

+   **服务分解**：使用有界上下文，我们可以确定将作为一个有界上下文部分工作的团队。他们将专注于需要生产/消费以作为有界上下文一部分提供功能的服务。业务能力被分解为单独的微服务。服务可以根据以下原则进行分解：

+   **单一责任**：首先是服务的范围和服务将公开的能力

+   **独立**：功能/特性需求的更改应该限制在一个服务中，允许一个团队拥有并完成相同的需求。

+   **松耦合**：服务应该松散耦合，允许它们独立演进

+   **映射上/下游服务依赖**：随着在每个领域中识别出的服务，这些服务可以根据依赖关系进行映射。封装记录系统的核心实体服务是上游服务。来自上游服务的更改被发布为事件，由下游服务订阅或消费。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/37965ca6-ac3c-49c6-b243-1a2fce68eb0c.jpg)

# 定义架构跑道

业务应用程序需要建立在一个平台之上。平台可以根据业务和应用程序的需求进行构建或购买。组织需要定义一个有意识的架构模型，并定义铁路护栏，以确保团队在给定的技术约束条件下构建服务。平台团队拥有这个全面的架构，选择架构和技术组件，并帮助构建应用服务成功运行所需的任何共同关注点。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/1e693cdb-0ced-4d43-b5b6-8d74f605d328.jpg)

+   **平台架构**：成功的分布式架构的关键要素之一是底层平台。可以选择使用现成的、开源/商业软件（如 Red Hat OpenStack、Cloud Foundry 等）来构建平台，也可以选择战略性的云提供商（如 AWS、Azure）来开始构建平台。底层基础设施（计算、网络和存储）的弹性特性为平台提供了基本的构建模块。

+   **技术选择、验证和集成**：为了构建平台服务，您可能希望评估多组技术，以确定在您的生态系统中哪种技术最有效。技术堆栈评估通常是一个多步骤的过程，其中需求被映射到可用的技术/产品，并进行详细的验证步骤，最终形成一个关于技术集成的矩阵。

+   **设计决策**：技术评估的结果被映射到基本需求，形成一个矩阵。这个矩阵用于确定最佳匹配，并帮助做出设计决策。这一步与前一步密切配合。

+   **环境设置**：一旦关键的设计决策就位，我们需要开始进行环境设置。根据选择是在本地还是云端，设置和相关步骤会有所不同。您可以从开发、测试、预生产和生产环境的设置开始。环境按复杂性顺序构建，并经历多次迭代（从手动到脚本/自动化）。

+   **DevOps/Maven 原型**：接下来，我们开始着手应用构建和部署的**持续集成**（**CI**）/ **持续部署**（**CD**）部分。对于在敏捷模型中开发的应用程序，CI/CD 模型有助于一天内进行多次发布，并为整个流程带来更高的速度。我们还可以开发加速器来辅助 CI/CD 流程。例如，Maven 原型带有用于创建可部署构件的必要绑定。

+   **平台服务构建**：接下来是需要构建/提供给平台用户的一系列平台服务。

服务包括应用程序开发（例如排队、工作流、API 网关、电子邮件服务等）、数据库（例如 NoSQL、RDBMS、缓存等）、DevOps 工具（例如 CI/CD 工具、服务注册表、代码存储库等）、安全性（例如目录服务、密钥管理服务、证书管理服务、硬件安全模块（HSM）等）、数据分析（例如认知服务、数据管道、数据湖等）。

您可以从多个供应商那里购买这些服务（例如，作为 Pivotal Cloud Foundry（PCF）的一部分提供的 Tiles，Iron.io 平台），或者订阅云供应商提供的服务，或者在产品的基础上创建自己的平台服务。

+   **非功能性需求（NFR）问题**：一旦关键平台服务就位，并且第一批应用程序开始接入平台，我们需要开始担心如何处理应用程序的 NFR 问题。应用程序如何根据传入负载进行扩展，如何检测故障，如何保持应用程序的最低阈值等等。同样，您可能希望将现有产品集成到您的平台，以提供/支持这些 NFR 问题。

+   **生产问题**：最后，我们需要开始担心生产问题，如服务管理、监控、安全等。我们需要从运营角度构建服务和必要的门户，以监视、检测并在偏离/定义规则的情况下采取适当的行动。这些服务通常是根据组织标准构建的。随着更多用例的识别，服务会不断成熟。其目的是自动化所有可能的操作，以确保平台始终运行，无需任何人为干预。

# 开发人员构建

数字转型的另一个关键方面是专注于您现有团队管理/维护现有应用程序。团队需要在技能和技术方面进行升级，以便能够重构/构建/部署现有应用程序为分布式应用程序。我们将介绍重新培训团队处理分布式应用程序故事所需的步骤。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/bbf06227-fa6f-48b5-ac1d-7941939a775d.jpg)

+   **开发人员再培训/培训**：首要任务是教导开发人员新的应用架构技术和设计模式。这意味着课堂培训、在线技术培训、供应商产品会议/培训等等。提升团队技能的另一种方法是雇佣具有相关技能的人，并让他们在现有开发团队的支持下带头进行整体开发。

有时，您可能希望有两个团队——一个改变业务，另一个运行业务。在这种情况下，第一个业务团队为团队带来新的技能。另一个业务团队在转型期间管理和操作现有应用程序。

+   **开发机器升级和设置**：新的技术栈需要升级开发人员的机器。如果机器运行在 4GB RAM 上，我们可能需要将它们升级到至少 8GB RAM，最好是 16GB RAM。新的技术栈需要虚拟机、Docker 引擎、集成开发环境和其他开发和单元测试软件。较慢的机器会增加构建/测试代码的时间。没有足够的性能，开发人员就无法高效工作。

+   **实验室/概念验证**：一旦机器升级和开发人员培训完成，开发人员可以开始使用新技术栈进行实验室操作和/或概念验证，以熟悉新的开发技术。开发人员可以被分配小项目，或者参与技术栈评估的一部分，以使他们熟悉技术栈。

开发团队完成的工作应该由该领域的 SME 评估，以指出他们做错了什么以及正确的做法。拥有外部顾问（无论是 SME 还是供应商顾问团队）有助于弥合这一差距。

+   代码分支和配置：一旦开发团队准备开始开发分布式应用程序，下一步就是从单体应用程序中分支出代码。您可能还希望分支配置数据。

请记住，即使进行了分支，现有的应用程序维护也会继续在主代码主干上进行。分支版本用于重构代码。我们将在下一节中看到更多细节。

+   开发/构建微服务：一旦代码分支和重构完成，开发人员应该开始将它们打包为微服务。团队还可以开始创建新的微服务，以满足应用程序的新需求。

分支上的代码定期与主干同步，以确保对主干进行的更改在分支代码中可用。

移动到云供应商提供的特定 PaaS 服务也是这个阶段的一部分。如果您想使用诸如排队或通知等服务，或者任何其他服务，那么这个阶段就是您进行相关更改的阶段。

+   微服务的 CI/CD 流程：开发人员将开始为微服务创建持续集成和部署的流水线。服务依赖关系被映射出并考虑在内。各种代码分析检查作为 CI 流程的一部分运行，以确保代码的生产准备性。额外的服务治理流程可以内置到流水线的各个阶段中。

+   功能/集成测试：最后，开发人员将编写功能和集成测试套件，以验证服务的正确性。这些测试套件作为 CI 流水线的一部分进行集成。在部署新代码时，这些测试作为回归的一部分运行，以确保功能的正确性。

# 打破单体应用

数字化转型的关键步骤之一是实际重构单体应用程序。在这种情况下，我们假设需要将基于 Java 的应用程序重构/拆分为分布式应用程序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/0b7e7f94-e74a-438c-9f26-96673d1305c4.jpg)

+   初始状态：在我们开始之前，我们先了解一下单体应用的初始状态。在这种状态下，应用由部署单元（如 WAR 文件）组成，内部由多个 JAR 文件组成。代码以逻辑方式布局，跨展示、业务和数据层具有一定的逻辑结构。每个层次都根据模块或基于模块的子包进行了进一步的分叉。如果没有，也可以根据类名的区别来识别模块。配置存储为一组外部属性文件。代码覆盖率不错（超过 60%），有潜力编写更多的测试用例。

+   代码重构：下一步是从单体应用程序中切割出可能一起的代码片段。例如，跨模块的类可以打包为单独的 Java 项目。常见文件或实用程序类可以打包为单独的 JAR 文件。在从单一代码项目重构代码时，将创建多个相互依赖的 Java 项目。将 JAR 文件打包为更大的 WAR 或 EAR 文件的一部分。请记住，我们正在处理代码基础的主干。更改被集成并同步回分支代码。

除了代码，您还需要重构应用程序配置。在重构代码的同时，需要将配置映射到相应的 Java 项目。配置可能特定于项目/模块，跨模块共享，或者是全局的，用于整个应用程序。

+   构建过程更新：在进行代码重构的过程中，创建较小的独立 Java 项目，您需要更新项目构建过程。Java 项目需要按照它们相互依赖的顺序进行构建。随着项目的划分，构建过程不断进行迭代。构建过程与代码重构步骤一起更新。

随着代码的重构，更新的 WAR/EAR 需要部署到生产环境。这确保了代码重构的有效性，并考虑了其他指标——代码覆盖率、单元测试、回归测试等。这确保了您的工作每天都会被纳入生产。

+   Java 版本更新：我们多次看到项目中使用的 JVM 版本可能不是最新的。一些较新的响应式框架通常需要 Java 1.7 及更高版本。这意味着基本的 JVM 版本需要升级。这可能需要对应用程序代码进行重构，以适应已弃用的功能。某些代码片段可能需要升级以适应新功能。重构后的代码需要与升级后的 JVM 版本一起投入生产。

+   引入断路器/响应式模式：代码重构的下一步是升级代码以实现弹性模式。您可以通过实现 Java 库（如 Hystrix）引入断路器等模式。您还可以通过实现异步消息传递、引入响应式框架（如 Spring Boot、Vert.x、Dropwizard 等）以及改进并发性（如 Akka、RxJava 等）来改进模块间的代码，并将所有更改应用到生产代码并与分支代码集成。

+   特性标志实施：有时，您可能正在集成来自分支的代码。在这种情况下，您可能不希望某些代码立即上线。您可以在代码中引入特性标志，并通过配置进行控制。因此，您可以将可能在特性准备上线之前处于停用状态的代码投入生产。

+   持续的功能更新：应用程序将不断进行功能性的更改/更新。更改将应用到代码中，并定期与分支代码同步。

# 将所有内容整合在一起

我们看到四个轨道在各自的能力上在应用程序中运作。现在我们以协作的方式将所有四个轨道结合起来。随着单片应用程序的转变，其他轨道为划分界限上下文和相关微服务奠定了基础平台：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/906a6786-8fe8-4162-b8b2-891586ae1516.jpg)

我们可以看到两个轨道如何改变业务，运行业务重叠，并为从单片模型迁移到分布式应用程序模型提供完美的平衡。

这类似于在行驶中更换汽车轮胎。

# 构建自己的平台服务（控制与委托）

企业面临的另一个关键决定是如何选择平台：

+   我应该构建自己的平台吗？

+   我应该订阅现有平台并在其上开发我的应用程序吗？

这个决定归结为如何看待技术，是作为一种促进因素（控制）还是作为一种差异化因素（委托）？

从根本上讲，所有公司都是科技公司。但问题是，控制技术是否能为您提供与竞争对手的额外优势，或者帮助构建一个可能阻止新参与者加入的壕沟。让我们举几个例子，看看它是如何发挥作用的：

+   如果您计划在零售领域与亚马逊等公司竞争，您需要有雄厚的资金实力。亚马逊零售的低利润业务是由 AWS 的盈利业务支持的。因此，除非您有一个资金雄厚的支持者或替代收入模式，与亚马逊竞争将不会容易。但是假设您有雄厚的资金实力，您可以开始在 AWS 或任何云提供商上建模您的零售平台吗？是的！您可以从任何公共云平台开始，一旦您有可预测的需求，您可以转向私有云模型。这种模型可以节省您的前期资本支出。

+   让我们以销售实体产品的制造领域为例。他们可以潜在地利用物联网设备来增强他们的产品，这些设备提供关于产品性能和使用情况的定期数据流。公司收集这些数据，并提供围绕这些产品的数字服务（如预测性维护）的分析服务。现在，您可以在任何云提供商上建模和构建分析模型。平台的选择可以由认知或数据处理能力的选择来确定。您可以从平台选择认知服务，甚至创建您自己的认知服务。基础平台能力委托给云提供商。您专注于构建正确的模型来进行预测。

没有正确或错误的模型。您可以从代表（选择公共云提供商）开始，然后转向控制模型（私有云），在那里您可以完全控制应用程序的功能/功能。在没有大量前期投资和锁定的情况下，很容易在云提供商模型上进行转变。关键是要确定您的差异化所在！

# 总结

这就结束了数字转型。我们看到了我们需要评估应用程序组合以寻找转型机会。我们看到了单片应用程序对实现业务目标的阻碍原因。

一旦确定了转型机会，我们可以将现有的单片应用程序转移到分布式应用程序模型。我们看到需要在人员、流程和技术层面采取各种步骤。

这也结束了在 Java 中构建云原生应用程序的整体旅程。我们看到了构建基于微服务的新时代应用程序的各种工具/技术，如何构建它们，如何将这些应用程序投入生产，如何监视它们，以及我们如何将这些应用程序用于 AWS 和 Azure 等云提供商。我们还看到了构建基于 API 的平台的一些最佳实践，以及如何将现有的单片应用程序转变为分布式微服务应用程序。
