# C# 代码整洁指南（四）

> 原文：[`zh.annas-archive.org/md5/0768F2F2E3C709CF4014BAB4C5A2161B`](https://zh.annas-archive.org/md5/0768F2F2E3C709CF4014BAB4C5A2161B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：设计和开发 APIs

**应用程序编程接口**（**APIs**）在如今的许多方面从未像现在这样重要。APIs 用于连接政府和机构共享数据，并以协作的方式解决商业和政府问题。它们用于医生诊所和医院实时共享患者数据。当您连接到您的电子邮件并通过 Microsoft Teams、Microsoft Azure、Amazon Web Services 和 Google Cloud Platform 等平台与同事和客户进行协作时，您每天都在使用 APIs。

每次您使用计算机或手机与某人聊天或进行视频通话时，您都在使用 API。当流媒体视频会议、进入网站技术支持聊天或播放您喜爱的音乐和视频时，您都在使用 API。因此，作为程序员，了解 API 是什么以及如何设计、开发、保护和部署它们是至关重要的。

在本章中，我们将讨论 API 是什么，它们如何使您受益，以及为什么有必要了解它们。我们还将讨论 API 代理、设计和开发指南，如何使用 RAML 设计 API 以及如何使用 Swagger 文档 API。

本章涵盖以下主题：

+   什么是 API？

+   API 代理

+   API 设计指南

+   使用 RAML 进行 API 设计

+   Swagger API 开发

本章将帮助您获得以下技能：

+   了解 API 以及为什么您需要了解它们

+   了解 API 代理以及我们为什么使用它们

+   在设计自己的 API 时了解设计指南

+   使用 RAML 设计自己的 API

+   使用 Swagger 来记录您的 API

通过本章结束时，您将了解良好 API 设计的基础，并掌握推动 API 能力所需的知识。了解 API 是什么很重要，因此我们将从这一点开始本章。但首先，请确保您实现以下技术要求，以充分利用本章。

# 技术要求

我们将在本章中使用以下技术来创建 API：

+   Visual Studio 2019 社区版或更高版本

+   Swashbuckle.AspNetCore 5 或更高版本

+   Swagger ([`swagger.io`](https://swagger.io))

+   Atom ([`atom.io`](http://atom.io))

+   MuleSoft 的 API Workbench

# 什么是 API？

**APIs**是可重用的库，可以在不同应用程序之间共享，并可以通过 REST 服务提供（在这种情况下，它们被称为**RESTful APIs**）。

**表述状态转移**（**REST**）由 Roy Fielding 于 2000 年引入。

REST 是一种由*约束*组成的架构风格。总共有六个约束在编写 REST 服务时应该考虑。这些约束如下：

+   **统一接口**：用于识别资源，并通过*表示*来操作这些资源。消息使用超媒体并且是自描述的。**超媒体作为应用程序状态的引擎**（**HATEOAS**）被用来包含关于客户端可以执行的下一步操作的信息。

+   **客户端-服务器**：这个约束通过*封装*利用信息隐藏。因此，只有客户端将要使用的 API 调用将是可见的，所有其他 API 将被保持隐藏。RESTful API 应该独立于系统的其他部分，使其松散耦合。

+   **无状态**：这表示 RESTful API 没有会话或历史。如果客户端需要会话或历史，那么客户端必须在请求中提供所有相关信息给服务器。

+   **可缓存**：这个约束意味着资源必须声明自己是可缓存的。这意味着资源可以被快速访问。因此，我们的 RESTful API 变得更快，服务器负载减少。

+   **分层系统**：分层系统约束规定每个层必须只做一件事。每个组件只应知道它需要使用的内容以便进行功能和任务的执行。组件不应该了解它不使用的系统部分。

+   **可选的可执行代码**：可执行代码约束是可选的。此约束确定服务器可以临时扩展或自定义客户端的功能，通过传输可执行代码。

因此，在设计 API 时，最好假设最终用户是具有任何经验水平的程序员。他们应该能够轻松获取 API，阅读相关信息，并立即投入使用。

不要担心创建完美的 API。API 通常会随着时间的推移而不断发展，如果您曾经使用过 Microsoft 的 API，您会知道它们经常进行升级。将来将删除的功能通常会用注释标记，告知用户不要使用特定的属性或方法，因为它们将在将来的版本中被删除。然后，当它们不再被使用时，通常会在最终删除之前用过时的注释标记进行标记。这告诉 API 的用户升级使用过时功能的任何应用程序。

为什么要使用 REST 服务进行 API 访问？嗯，许多公司通过在线提供 API 并对其收费而获得巨大利润。因此，RESTful API 可以是一项非常有价值的资产。Rapid API ([`rapidapi.com/`](https://rapidapi.com/))提供免费和付费的 API 供使用。

您的 API 可以永久保持在原位。如果您使用云提供商，您的 API 可以具有高度可扩展性，并且您可以通过免费或订阅的方式使其普遍可用。您可以通过简单的接口封装所有复杂的工作，并暴露所需的内容，因为您的 API 将是小型且可缓存的，所以非常快速。现在让我们来看看 API 代理以及为什么要使用它们。

# API 代理

**API 代理**是位于客户端和您的 API 之间的类。它本质上是您和将使用您的 API 的开发人员之间的 API 合同。因此，与其直接向开发人员提供 API 的后端服务（随着您对其进行重构和扩展，可能会发生故障），不如向 API 的使用者提供保证，即使后端服务发生变化，API 合同也将得到遵守。

以下图表显示了客户端、API 代理、实际访问的 API 以及 API 与数据源之间的通信：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/ac1cf264-d3a0-461d-9552-f325c10357bd.png)

本节将编写一个演示实现代理模式的控制台应用程序。我们的示例将具有一个接口，该接口将由 API 和代理实现。API 将返回实际消息，代理将从 API 获取消息并将其传递给客户端。代理还可以做的远不止简单调用 API 方法并返回响应。它们可以执行身份验证、授权、基于凭据的路由等等。但是，我们的示例将保持在绝对最低限度，以便您可以看到代理模式的简单性。

启动一个新的.NET Framework 控制台应用程序。添加`Apis`、`Interfaces`和`Proxies`文件夹，并将`HelloWorldInterface`接口放入`Interfaces`文件夹中：

```cs
public interface HelloWorldInterface
{
    string GetMessage();
}
```

我们的接口方法`GetMessage()`以字符串形式返回一条消息。代理和 API 类都将实现这个接口。`HelloWorldApi`类实现了`HelloWorldInterface`，所以将其添加到`Apis`文件夹中：

```cs
internal class HelloWorldApi : HelloWorldInterface
{
    public string GetMessage()
    {
        return "Hello World!";
    }
}
```

正如您所看到的，我们的 API 类实现了接口并返回了一个`"Hello World!"`的消息。我们还将类设置为内部类。这可以防止外部调用者访问此类的内容。现在，我们将`HelloWorldProxy`类添加到`Proxies`文件夹中：

```cs
    public class HelloWorldProxy : HelloWorldInterface
    {
        public string GetMessage()
        {
            return new HelloWorldApi().GetMessage();
        }
    }
```

我们的代理类设置为`public`，因为此类将由客户端调用。代理类将调用 API 类中的`GetMessage()`方法，并将响应返回给调用者。现在剩下的事情就是修改我们的`Main()`方法：

```cs
static void Main(string[] args)
{
    Console.WriteLine(new HelloWorldProxy().GetMessage());
    Console.ReadKey();
}
```

我们的`Main()`类调用`HelloWorldProxy`代理类的`GetMessage()`方法。我们的代理类调用 API 类，并将返回的方法打印在控制台窗口中。然后控制台等待按键后退出。

运行代码并查看输出；您已成功实现了 API 代理类。您可以使代理尽可能简单或复杂，但您在这里所做的是成功的基础。

在本章中，我们将构建一个 API。因此，让我们讨论一下我们将要构建的内容，然后开始着手处理它。完成项目后，您将拥有一个可以生成 JSON 格式的月度股息支付日历的工作 API。

# API 设计指南

有一些基本的指南可供遵循，以编写有效的 API—例如，您的资源应使用复数形式的名词。因此，例如，如果您有一个批发网站，那么您的 URL 将看起来像以下虚拟链接：

+   `http://wholesale-website.com/api/customers/1`

+   `http://wholesale-website.com/api/products/20`

上述 URL 将遵循`api/controller/id`的控制器路由。在业务域内的关系方面，这些关系也应反映在 URL 中，例如`http://wholesale-website.com/api/categories/12/products`—此调用将返回类别`12`的产品列表。

如果您需要将动词用作资源，则可以这样做。在进行 HTTP 请求时，使用`GET`检索项目，`HEAD`仅检索标头，`POST`插入或保存新资源，`PUT`替换资源，`DELETE`删除资源。通过使用查询参数使资源保持精简。

在分页结果时，应向客户端提供一组现成的链接。RFC 5988 引入了**链接标头**。在规范中，**国际资源标识符（IRI）**是两个资源之间的类型化连接。有关更多信息，请参阅[`www.greenbytes.de/tech/webdav/rfc5988.html`](https://www.greenbytes.de/tech/webdav/rfc5988.html)。链接标头请求的格式如下：

+   `<https://wholesale-website.com/api/products?page=10&per_page=100>; rel="next"`

+   `<https://wholesale-website.com/api/products?page=11&per_page=100>; rel="last"`

您的 API 的版本可以在 URL 中进行版本控制。因此，每个资源将具有相同资源的不同 URL，如以下示例：

+   `https://wholesale-website.com/api/v1/cart`

+   `https://wholesale-website.com/api/v2/cart`

这种版本控制方式非常简单，可以轻松找到正确的 API 版本。

JSON 是首选的资源表示。它比 XML 更易于阅读，而且体积更小。当您使用`POST`、`PUT`和`PATCH`动词时，还应要求将内容类型标头设置为 application/JSON，或抛出`415`HTTP 状态码（表示不支持的媒体类型）。Gzip 是一种单文件/流无损数据压缩实用程序。默认使用 Gzip 可以节省带宽的很大比例，并始终将 HTTP `Accept-Encoding`标头设置为`gzip`。

始终为您的 API 使用 HTTPS（TLS）。调用者的身份验证应始终在标头中完成。我们在设置 API 时看到了这一点，当我们使用 API 访问密钥设置了`x-api-key`标头。每个请求都应进行身份验证和授权。未经授权的访问应导致`HTTP 403 Forbidden`响应。还应使用正确的 HTTP 响应代码。因此，如果请求成功，请使用`200`状态代码，如果找不到资源，请使用`404`，依此类推。有关 HTTP 状态代码的详尽列表，请访问[`httpstatuses.com/`](https://httpstatuses.com/)。OAuth 2.0 是授权的行业标准协议。您可以在[`oauth.net/2/`](https://oauth.net/2/)上阅读有关它的所有信息。

API 应提供有关其使用的文档和示例。文档应始终与当前版本保持最新，并且应具有视觉吸引力和易于阅读。我们将在本章后面看一下 Swagger，以帮助我们创建文档。

您永远不知道您的 API 何时需要扩展。因此，这应该从一开始就考虑进去。在下一章的*股息日历 API*项目中，您将看到我们如何实现限流，每月只能调用一次 API，在特定日期。但是，根据您自己的需求，您可以有效地想出 1001 种不同的方法来限制您的 API，但这应该在项目开始时完成。因此，一旦开始新项目，就要考虑*可扩展性*。

出于安全和性能原因，您可能决定实现 API 代理。API 代理将客户端与直接访问您的 API 断开连接。代理可以访问同一项目中的 API 或外部 API。通过使用代理，您可以避免暴露数据库架构。

对客户端的响应不应与数据库的结构匹配。这可能会成为黑客的绿灯。因此，应避免数据库结构和发送回客户端的响应之间的一对一映射。您还应该向客户端隐藏标识符，因为客户端可以使用它们手动访问数据。

API 包含资源。**资源**是可以以某种方式操作的项目。资源可以是文件或数据。例如，学校数据库中的学生是可以添加、编辑或删除的资源。视频文件可以被检索和播放，音频文件也可以。图像也是资源，报告模板也是，它们将在呈现给用户之前被打开、操作和填充数据。

通常，资源形成项目的集合，例如学校数据库中的学生。`Students`是`Student`类型的集合的名称。可以通过 URL 访问资源。URL 包含到资源的路径。

URL 被称为**API 端点**。API 端点是资源的地址。可以通过带有一个或多个参数的 URL 或不带任何参数的 URL 访问此资源。URL 应该只包含复数名词（资源的名称），不应包含动词或操作。参数可用于标识集合中的单个资源。如果数据集将非常庞大，则应使用分页。对于超出 URI 长度限制的带参数的请求，可以将参数放在`POST`请求的正文中。

动词是 HTTP 请求的一部分。`POST`动词用于添加资源。要检索一个或多个资源，您可以使用`GET`动词。`PUT`更新或替换一个或多个资源，`PATCH`更新或修改一个资源或集合。`DELETE`删除一个资源或集合。

您应该始终确保适当地提供和响应 HTTP 状态代码。有关完整的 HTTP 状态代码列表，请访问[`httpstatuses.com/`](https://httpstatuses.com/)。

至于字段、方法和属性名称，您可以使用任何您喜欢的约定，但必须保持一致并遵循公司的指南。在 JSON 中通常使用驼峰命名约定。由于您将在 C#中开发 API，最好遵循行业标准的 C#命名约定。

由于您的 API 将随着时间的推移而发展，最好采用某种形式的版本控制。版本控制允许消费者使用特定版本的 API。当 API 的新版本实施破坏性更改时，这可能非常重要以提供向后兼容性。通常最好在 URL 中包含版本号，如 v1 或 v2。无论您使用什么方法来为 API 版本，只需记住要保持*一致*。

如果您将使用第三方 API，您需要保持 API 密钥的机密性。实现这一点的一种方法是将密钥存储在诸如 Azure Key Vault 之类的密钥库中，该库需要进行身份验证和授权。您还应该使用您选择的方法保护自己的 API。如今一个常见的方法是通过使用 API 密钥。在下一章中，您将看到如何使用 API 密钥和 Azure Key Vault 来保护第三方密钥和您自己的 API。

## 明确定义的软件边界

理智的人都不喜欢意大利面代码。它很难阅读、维护和扩展。因此，在设计 API 时，您可以通过明确定义的软件边界来解决这个问题。在**领域驱动设计**（**DDD**）中，一个明确定义的软件边界被称为**有界上下文**。在业务术语中，有界上下文是业务运营单位，如人力资源、财务、客户服务、基础设施等。这些业务运营单位被称为**领域**，它们可以被分解成更小的子领域。然后，这些子领域可以被进一步分解成更小的子领域。

通过将业务分解为业务运营单位，领域专家可以在这些特定领域受雇。在项目开始时可以确定一个共同的语言，以便业务了解 IT 术语，IT 员工了解业务术语。如果业务和 IT 员工的语言是一致的，由于双方的误解，错误的余地就会减少。

将一个重大项目分解为子领域意味着您可以让较小的团队独立地在项目上工作。因此，大型开发团队可以分成较小的团队，同时在各种项目上并行工作。

DDD 是一个很大的主题，本章不涉及。然而，更多信息的链接已经发布在本章的*进一步阅读*部分。

API 应该暴露的唯一项目是形成合同和 API 端点的接口。其他所有内容都应该对订阅者和消费者隐藏。这意味着即使是大型数据库也可以被分解，以便每个 API 都有自己的数据库。鉴于如今标准的网站可以是多么庞大和复杂，我们甚至可以拥有微服务、微数据库和微前端。

微前端是网页的一个小部分，根据用户交互动态检索和修改。该前端将与一个 API 进行交互，而该 API 将访问一个微数据库。这在**单页应用程序**（**SPAs**）方面是理想的。

单页应用是由单个页面组成的网站。当用户发起操作时，只更新网页的必需部分；页面的其余部分保持不变。例如，网页有一个 aside。这个 aside 显示广告。这些广告以 HTML 的形式存储在数据库中。aside 被设置为每 5 秒自动更新一次。当 5 秒时间到时，aside 请求 API 分配一个新的广告。然后 API 使用任何已经存在的算法从数据库中获取要显示的新广告。然后 HTML 文档被更新，aside 也被更新为新的广告。下图显示了典型的单页应用程序生命周期：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/52b9aa3b-83f9-42c3-91f9-090c0663f494.png)

这个 aside 是一个明确定义的软件边界。它不需要知道显示在其中的页面的任何内容。它所关心的只是每 5 秒显示一个新的广告：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/5031ec6d-2f95-4332-a93f-474caa205164.png)

先前的图表显示了一个单页应用通过 API 代理与一个 RESTful API 进行通信，API 能够访问文档和数据库。

组成 aside 的唯一组件是 HTML 文档片段、微服务和数据库。这些可以由一个小团队使用他们喜欢和熟悉的任何技术来处理。完整的单页应用程序可能由数百个微文档、微服务和微数据库组成。关键点在于这些服务可以由任何技术组成，并且可以由任何团队独立工作。也可以同时进行多个项目。

在我们的边界上下文中，我们可以使用以下软件方法来提高我们代码的质量：

+   **单一职责**、**开闭**、**里氏替换**、**接口隔离**和**依赖反转**（**SOLID**）原则

+   **不要重复自己**（**DRY**）

+   **你不会需要它**（**YAGNI**）

+   **保持简单，愚蠢**（**KISS**）

这些方法可以很好地协同工作，消除重复代码，防止编写不需要的代码，并保持对象和方法的简洁。我们为类和方法开发的原因是它们应该只做一件事，并且做得很好。

命名空间用于执行逻辑分组。我们可以使用命名空间来定义软件边界。命名空间越具体，对程序员越有意义。有意义的命名空间帮助程序员分割代码，并轻松找到他们正在寻找的内容。使用命名空间来逻辑分组接口、类、结构和枚举。

在接下来的部分，您将学习如何使用 RAML 设计 API。然后，您将从 RAML 文件生成一个 C# API。

## 理解良好质量 API 文档的重要性

在项目中工作时，有必要了解已经使用的所有 API。这是因为您经常会写已经存在的代码，这显然会导致浪费。不仅如此，通过编写自己版本的已经存在的代码，现在您有两份做同样事情的代码。这增加了软件的复杂性，并增加了维护开销，因为必须维护两个版本的代码。这也增加了错误的可能性。

在跨多个技术和存储库的大型项目中，团队人员流动性高，尤其是没有文档存在的情况下，代码重复成为一个真正的问题。有时，可能只有一两个领域专家，大多数团队根本不了解系统。我以前就曾参与过这样的项目，它们真的很难维护和扩展。

这就是为什么 API 文档对于任何项目都是至关重要的，无论其大小如何。在软件开发领域，人们会离开，尤其是在其他地方提供更有利可图的工作时。如果离开的人是领域专家，那么他们将带走他们的知识。如果没有文档存在，那么新加入项目的开发人员将不得不通过阅读代码来陡峭地学习项目。如果代码混乱复杂，这可能会给新员工带来真正的头痛。

因此，由于缺乏系统知识，程序员倾向于或多或少地从头开始编写他们需要的代码以按时交付给业务。这通常会导致重复的代码和未被利用的代码重用。这会导致软件变得复杂且容易出错，这种软件最终变得难以扩展和维护。

现在，您了解了为什么 API 必须进行文档化。良好文档化的 API 将使程序员更容易理解，并更有可能被重复使用，从而减少了代码重复的可能性，并产生了难以扩展或维护的代码。

您还应该注意任何标记为弃用或过时的代码。弃用的代码将在未来版本中被移除，而过时的代码已不再使用。如果您正在使用标记为弃用或过时的 API，则应优先处理此代码。

现在您了解了良好质量 API 文档的重要性，我们将看一下一个名为 Swagger 的工具。Swagger 是一个易于使用的工具，用于生成外观漂亮、高质量的 API 文档。

### Swagger API 开发

Swagger 提供了一套围绕 API 开发的强大工具。使用 Swagger，您可以做以下事情：

+   **设计**：设计您的 API 并对其进行建模，以符合基于规范的标准。

+   **构建**：构建一个稳定且可重用的 C# API。

+   **文档**：为开发人员提供可以交互的文档。

+   **测试**：轻松测试您的 API。

+   **标准化**：使用公司指南对 API 架构应用约束。

我们将在 ASP.NET Core 3.0+项目中启动 Swagger。因此，请在 Visual Studio 2019 中创建项目。选择 Web API 和无身份验证设置。在我们继续之前，值得注意的是，Swagger 会自动生成外观漂亮且功能齐全的文档。设置 Swagger 所需的代码非常少，这就是为什么许多现代 API 使用它的原因。

在我们可以使用 Swagger 之前，我们首先需要在项目中安装对其的支持。要安装 Swagger，您必须安装`Swashbuckle.AspNetCore`依赖包的 5 版或更高版本。截至撰写本文时，NuGet 上可用的版本是 5.3.3。安装完成后，我们需要将要使用的 Swagger 服务添加到服务集合中。在我们的情况下，我们只会使用 Swagger 来记录我们的 API。在`Startup.cs`类中，将以下行添加到`ConfigureServices()`方法中：

```cs
services.AddSwaggerGen(swagger =>
{
    swagger.SwaggerDoc("v1", new OpenApiInfo { Title = "Weather Forecast API" });
});
```

在我们刚刚添加的代码中，Swagger 文档服务已分配给了服务集合。我们的 API 版本是`v1`，API 标题是`Weather Forecast API`。现在我们需要更新`Configure()`方法，在`if`语句之后立即添加我们的 Swagger 中间件，如下所示：

```cs
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Weather Forecast API");
});
```

在我们的`Configure()`方法中，我们正在通知我们的应用程序使用 Swagger 和 Swagger UI，并为`Weather Forecast API`分配我们的 Swagger 端点。接下来，您需要安装`Swashbuckle.AspNetCore.Newtonsoft`NuGet 依赖包（截至撰写本文时的版本为 5.3.3）。然后，将以下行添加到您的`ConfigureServices()`方法中：

```cs
services.AddSwaggerGenNewtonsoftSupport();
```

我们为我们的 Swagger 文档生成添加了 Newtonsoft 支持。这就是使 Swagger 运行起来的全部内容。因此，运行你的项目，然后导航到`https://localhost:PORT_NUMBER/swagger/index.html`。你应该看到以下网页：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/4628e779-2c78-41dc-acad-7caea58b65fa.png)

现在我们将看一下为什么我们应该传递不可变的结构而不是可变的对象。

## 传递不可变的结构而不是可变的对象

在这一部分，你将编写一个计算机程序，处理 100 万个对象和 100 万个不可变的结构。你将看到在性能方面，结构比对象更快。我们将编写一些代码，处理 100 万个对象需要 1440 毫秒，处理 100 万个结构需要 841 毫秒。这是 599 毫秒的差异。这样一个小的时间单位听起来可能不多，但当处理大型数据集时，使用不可变的结构而不是可变的对象将会带来很大的性能改进。

可变对象中的值也可以在线程之间修改，这对业务来说可能非常糟糕。想象一下你的银行账户里有 15000 英镑，你支付房东 435 英镑的房租。你的账户有一个可以透支的限额。现在，在你支付 435 英镑的同时，另一个人正在支付 23000 英镑给汽车公司买一辆新车。汽车购买者的线程修改了你账户上的值。因此，你最终支付给房东 23000 英镑，使你的银行余额欠 8000 英镑。我们不会编写一个可变数据在线程之间被修改的示例，因为这在第八章中已经涵盖过了，*线程和并发*。

本节的要点是，结构比对象更快，不可变的结构是线程安全的。

在创建和传递对象时，结构比对象更高效。你也可以使结构不可变，这样它们就是线程安全的。在这里，我们将编写一个小程序。这个程序将有两个方法——一个将创建 100 万个人对象，另一个将创建 100 万个人结构。

添加一个新的.NET Framework 控制台应用程序，名为`CH11_WellDefinedBoundaries`，以及以下`PersonObject`类：

```cs
public class PersonObject
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
}
```

这个对象将用于创建 100 万个人对象。现在，添加`PersonStruct`：

```cs
    public struct PersonStruct
    {
        private readonly string _firstName;
        private readonly string _lastName;

        public PersonStruct(string firstName, string lastName)
        {
            _firstName = firstName;
            _lastName = lastName;
        }

        public string FirstName => _firstName;
        public string LastName => _lastName;
    }
```

这个结构是不可变的，`readonly`属性是通过构造函数设置的，并用于创建我们的 100 万个结构。现在，我们可以修改程序来显示对象和结构创建之间的性能。添加`CreateObject()`方法：

```cs
private static void CreateObjects()
{
    Stopwatch stopwatch = new Stopwatch();
    stopwatch.Start();
    var people = new List<PersonObject>();
    for (var i = 1; i <= 1000000; i++)
    {
        people.Add(new PersonObject { FirstName = "Person", LastName = $"Number {i}" });
    }
    stopwatch.Stop();
    Console.WriteLine($"Object: {stopwatch.ElapsedMilliseconds}, Object Count: {people.Count}");
    GC.Collect();
}
```

正如你所看到的，我们启动了一个秒表，创建了一个新列表，并向列表中添加了 100 万个人对象。然后我们停止了秒表，将结果输出到窗口，然后调用垃圾收集器来清理我们的资源。现在让我们添加我们的`CreateStructs()`方法：

```cs
private static void CreateStructs()
{
    Stopwatch stopwatch = new Stopwatch();
    stopwatch.Start();
    var people = new List<PersonStruct>();
    for (var i = 1; i <= 1000000; i++)
    {
        people.Add(new PersonStruct("Person", $"Number {i}"));
    }
    stopwatch.Stop();
    Console.WriteLine($"Struct: {stopwatch.ElapsedMilliseconds}, Struct Count: {people.Count}");
    GC.Collect();
}
```

我们的结构在这里做了与`CreateObjects()`方法类似的事情，但是创建了一个结构列表，并向列表中添加了 100 万个结构。最后，修改`Main()`方法，如下所示：

```cs
static void Main(string[] args)
{
    CreateObjects();
    CreateStructs();
    Console.WriteLine("Press any key to exit.");
    Console.ReadKey();
}
```

我们调用我们的两种方法，然后等待用户按任意键退出。运行程序，你应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/e5264597-6436-4a94-8ef7-6175e9f9350d.png)

正如你从之前的截图中所看到的，创建 100 万个对象并将它们添加到对象列表中花费了 1,440 毫秒，而创建 100 万个结构并将它们添加到结构列表中只花费了 841 毫秒。

因此，不仅可以使结构不可变和线程安全，因为它们不能在线程之间修改，而且与对象相比，它们的性能也更快。因此，如果你正在处理大量数据，结构可以节省大量处理时间。不仅如此，如果你的云计算服务按执行时间计费，那么使用结构而不是对象将为你节省金钱。

现在让我们来看看为将要使用的 API 编写第三方 API 测试。

## 测试第三方 API

为什么我应该测试第三方 API 呢？这是一个很好的问题。你应该测试第三方 API 的原因是，就像你自己的代码一样，第三方代码也容易出现编程错误。我记得曾经在为一家律师事务所建立的文件处理网站上遇到了一些真正困难。经过多次调查，我发现问题是由于我使用的 Microsoft API 中嵌入的有错误的 JavaScript 导致的。下面的截图是 Microsoft 认知工具包的 GitHub Issues 页面，其中有 738 个未解决的问题：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/140266fd-a189-4b3a-8816-e41df0518541.png)

正如你从 Microsoft 认知工具包中看到的，第三方 API 确实存在问题。这意味着作为程序员，你有责任确保你使用的第三方 API 能够正常工作。如果遇到任何 bug，那么告知第三方是一个良好的做法。如果 API 是开源的，并且你可以访问源代码，甚至可以检查代码并提交你自己的修复。

每当你在第三方代码中遇到 bug，而这些 bug 又无法及时解决以满足你的截止日期时，你可以选择编写一个**包装类**，该类具有与第三方类相同的构造函数、方法和属性，并使它们调用第三方类上的相同构造函数、方法和属性，但你需要编写第三方属性或方法的无 bug 版本。第十一章，“解决横切关注点”，提供了关于代理模式和装饰器模式的部分，这将帮助你编写包装类。

## 测试你自己的 API

在第六章，“单元测试”，和第七章，“端到端系统测试”中，你看到了如何测试你自己的代码，还有代码示例。你应该始终测试自己的 API，因为对 API 的质量完全信任是很重要的。因此，作为程序员，你应该在交付给质量保证之前对代码进行单元测试。质量保证应该进行集成和回归测试，以确保 API 达到公司约定的质量水平。

你的 API 可能完全符合业务要求，没有 bug；但当它与系统集成时，在某些情况下会发生你无法测试的奇怪情况吗？在开发团队中，我经常遇到这样的情况，代码在一个人的电脑上可以工作，但在其他电脑上却不能。然而，这似乎并没有逻辑上的原因。这些问题可能会非常令人沮丧，甚至需要花费大量时间才能找到问题的根源。但你希望在将代码交给质量保证之前解决这些问题，而且在发布到生产环境之前更是如此。处理客户 bug 并不总是一种愉快的经历。

测试你的程序应该包括以下内容：

+   当给定正确的值范围时，被测试的方法会输出正确的结果。

+   当给定不正确的值范围时，该方法会提供适当的响应而不会崩溃。

记住，你的 API 应该只包括业务要求，并且不应该使内部细节对客户可见。这就是 Scrum 项目管理方法中的产品积压的用处。

产品积压是你和你的团队将要处理的新功能和技术债务的列表。产品积压中的每个项目都将有描述和验收标准，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/550047ec-c17e-4810-9076-a1eb5ea19ee0.png)

你的单元测试是围绕验收标准编写的。你的测试将包括正常执行路径和异常执行路径。以这个截图为例，我们有两个验收标准：

+   成功从第三方 API 获取数据。

+   数据已成功存储在 Cosmos DB 中。

在这两个验收标准中，我们知道我们将调用获取数据的 API。这些数据将来自第三方。一旦获取，数据将存储在数据库中。从表面上看，我们必须处理的这个规范相当模糊。在现实生活中，我发现这种情况经常发生。

鉴于规范的模糊性，我们将假设规范是通用的，并适用于不同的 API 调用，并且我们可以假设返回的数据是 JSON 数据。我们还假设返回的 JSON 数据将以其原始形式存储在 Cosmos DB 数据库中。

那么，我们可以为我们的第一个验收标准写什么测试？嗯，我们可以写以下测试用例：

1.  当给定一个带参数列表的 URL 时，断言当提供所有正确的信息时，我们会收到`200`的状态和`GET`请求返回的 JSON。

1.  当未经授权的`GET`请求被发出时，我们会收到`401`的状态。

1.  断言当经过身份验证的用户被禁止访问资源时，我们会收到`403`的状态。

1.  当服务器宕机时，我们会收到`500`的状态。

我们可以为我们的第二个验收标准写什么测试？嗯，我们可以写以下测试用例：

1.  断言拒绝对数据库的未经授权访问。

1.  断言 API 在数据库不可用的情况下能够优雅地处理。

1.  断言授予对数据库的授权访问。

1.  断言 JSON 插入数据库成功。

因此，即使从如此模糊的规范中，我们已经能够获得八个测试用例。在它们之间，所有这些情况都测试了成功地往返到第三方服务器，然后进入数据库。它们还测试了过程可能失败的各个点。如果所有这些测试都通过，我们对我们的代码完全有信心，并且在离开我们作为开发人员的手时，它将通过质量控制。

在下一节中，我们将看看如何使用 RAML 设计 API。

# 使用 RAML 进行 API 设计

在这一部分，我们将讨论使用 RAML 设计 API。你可以从 RAML 网站([`raml.org/developers/design-your-api`](https://raml.org/developers/design-your-api))获得关于 RAML 各个方面的深入知识。我们将通过在 Atom 中使用 API Workbench 设计一个非常简单的 API 来学习 RAML 的基础知识。我们将从安装开始。

第一步是安装软件包。

## 安装 Atom 和 MuleSoft 的 API Workbench

让我们看看如何做到这一点：

1.  从[`atom.io`](http://atom.io)安装 Atom。

1.  然后，点击`Install a Package`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/84999249-f95c-43c6-8dc7-293851edc1a8.png)

1.  然后搜索`api-workbench by mulesoft`并安装它：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/a16b724d-e6d1-46b8-8733-c5a57095c552.png)

1.  如果你在`Packages`|`Installed Packages`下找到它，安装就成功了。

现在我们已经安装了软件包，让我们继续创建项目。

## 创建项目

让我们看看如何做到这一点：

1.  点击`File`|`Add Project Folder`。

1.  创建一个新文件夹或选择一个现有的文件夹。我将创建一个名为`C:\Development\RAML`的新文件夹并打开它。

1.  在你的项目文件夹中添加一个名为`Shop.raml`的新文件。

1.  右键单击文件，然后选择`Add New`|`Create New API`。

1.  给它任何你想要的名字，然后点击`Ok`。你现在刚刚创建了你的第一个 API 设计。

如果你看一下 RAML 文件，你会发现它的内容是人类可读的文本。我们刚刚创建的 API 包含一个简单的`GET`命令，返回一个包含单词`"Hello World"`的字符串：

```cs
#%RAML 1.0
title: Pet Shop
types:
  TestType:
    type: object
    properties:
      id: number
      optional?: string
      expanded:
        type: object
        properties:
          count: number
/helloWorld:
  get:
    responses:
      200:
        body:
          application/json:
            example: |
              {
                "message" : "Hello World"
              }
```

这是 RAML 代码。您会看到它与 JSON 非常相似，因为代码是简单的、可读的代码，它是缩进的。删除文件。从“包”菜单中，选择“API Workbench | 创建 RAML 项目”。填写“创建 RAML 项目”对话框，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/cdb8093f-1fe4-48c7-a255-488bffe88415.png)

此对话框中的设置将生成以下 RAML 代码：

```cs
#%RAML 1.0
title: Pet Shop
version: v1
baseUri: /petshop
types:
  TestType:
    type: object
    properties:
      id: number
      optional?: string
      expanded:
        type: object
        properties:
          count: number
/helloWorld:
  get:
    responses:
      200:
        body:
          application/json:
            example: |
              {
                "message" : "Hello World"
              }
```

您查看的最后一个 RAML 文件和第一个 RAML 文件之间的主要区别是插入了`version`和`baseUri`属性。这些设置还会更新您的“Project”文件夹的内容，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/edc9a28c-8900-4cb1-b1e7-2f21a28d954f.png)

有关此主题的非常详细的教程，请访问[`apiworkbench.com/docs/`](http://apiworkbench.com/docs/)。此 URL 还提供了如何添加资源和方法、填写方法体和响应、添加子资源、添加示例和类型、创建和提取资源类型、添加资源类型参数、方法参数和特性、重用特性、资源类型和库、添加更多类型和资源、提取库等详细信息，远远超出了本章的范围。

既然我们有了一个与语言实现无关的设计，那么我们如何在 C#中生成我们的 API 呢？

## 从我们的通用 RAML 设计规范生成我们的 C# API

您至少需要安装 Visual Studio 2019 社区版。然后确保关闭 Visual Studio。还要下载并安装 Visual Studio 的`MuleSoftInc.RAMLToolsforNET`工具。安装了这些工具后，我们现在将按照生成我们先前指定的 API 的骨架框架所需的步骤进行。这将通过添加 RAML/OAS 合同并导入我们的 RAML 文件来实现：

1.  在 Visual Studio 2019 中，创建一个新的.NET Framework 控制台应用程序。

1.  右键单击项目，选择“添加 RAML/OAS 合同”。这将打开以下对话框：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/bacd4cb7-ca52-41c2-904c-35491f7cd8bf.png)

1.  点击“上传”，然后选择您的 RAML 文件。然后将呈现“导入 RAML/OAS”对话框。填写对话框如下所示，然后点击“导入”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/5944bca4-a050-46f6-880f-d0ee6aefb58d.png)

您的项目现在将使用所需的依赖项进行更新，并且新的文件夹和文件将被添加到您的控制台应用程序中。您将注意到三个根文件夹，称为`Contracts`、`Controllers`和`Models`。在`Contracts`文件夹中，我们有我们的 RAML 文件和`IV1HelloWorldController`接口。它包含一个方法：`Task<IHttpActionResult> Get()`。v1HelloWorldController 类实现了 Iv1HelloWorldController 接口。让我们来看看控制器类中实现的`Get()`方法：

```cs
/// <summary>
/// /helloWorld
/// </summary>
/// <returns>HelloWorldGet200</returns>
public async Task<IHttpActionResult> Get()
{
    // TODO: implement Get - route: helloWorld/helloWorld
    // var result = new HelloWorldGet200();
    // return Ok(result);
    return Ok();
}
```

在上面的代码中，我们可以看到代码注释掉了`HelloWorldGet200`类的实例化和返回结果。`HelloWorldGet200`类是我们的模型类。我们可以更新我们的模型，使其包含我们想要的任何数据。在我们的简单示例中，我们不会太过于烦恼；我们只会返回`"Hello World!"`字符串。将取消注释的行更新为以下内容：

```cs
return Ok("Hello World!");
```

“Ok()`方法返回`OkNegotiatedContentResult<T>`类型。我们将从`Program`类中的`Main()`方法中调用此`Get()`方法。更新`Main()`方法，如下所示：

```cs
static void Main(string[] args)
{
    Task.Run(async () =>
    {
        var hwc = new v1HelloWorldController();
        var response = await hwc.Get() as OkNegotiatedContentResult<string>;
        if (response is OkNegotiatedContentResult<string>)
        {
            var msg = response.Content;
            Console.WriteLine($"Message: {msg}");
        }
    }).GetAwaiter().GetResult();
    Console.ReadKey();
}
```

由于我们在静态方法中运行异步代码，因此我们必须将工作添加到线程池队列中。然后执行我们的代码并等待结果。一旦代码返回，我们只需等待按键，然后退出。

我们在控制台应用程序中创建了一个 MVC API，并根据我们导入的 RAML 文件执行了 API 调用。这个过程对于 ASP.NET 和 ASP.NET Core 网站也适用。现在我们将从现有 API 中提取 RAML。

从本章前面的股息日历 API 项目中加载。然后，右键单击该项目并选择提取 RAML。然后，一旦提取完成，运行您的项目。将 URL 更改为`https://localhost:44325/raml`。提取 RAML 时，代码生成过程会向您的项目添加一个`RamlController`类，以及一个 RAML 视图。您将看到您的 API 现在已经记录在案，如 RAML 视图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/dccb261d-f9c4-4b26-b0ed-5ac073ed5dd3.png)

通过使用 RAML，您可以设计一个 API，然后生成结构，也可以反向工程一个 API。RAML 规范帮助您设计 API，并通过修改 RAML 代码进行更改。如果您想了解更多信息，可以查看[`raml.org`](http://raml.org)网站，以了解如何充分利用 RAML 规范。现在，让我们来看看 Swagger 以及如何在 ASP.NET Core 3+项目中使用它。

好了，我们现在已经到了本章的结尾。现在，我们将总结我们所取得的成就和所学到的知识。

# 总结

在本章中，我们讨论了 API 是什么。然后，我们看了如何使用 API 代理作为我们和 API 使用者之间的合同。这可以保护我们的 API 免受第三方的直接访问。接下来，我们看了一些改进 API 质量的设计准则。

然后，我们讨论了 Swagger，并了解了如何使用 Swagger 记录天气 API。然后介绍了测试 API，并看到了为什么测试您的代码以及您在项目中使用的任何第三方代码是有益的。最后，我们看了如何使用 RAML 设计一个与语言无关的 API，并将其翻译成一个使用 C#的工作项目。

在下一章中，我们将编写一个项目来演示如何使用 Azure Key Vault 保护密钥，并使用 API 密钥保护我们自己的 API。但在那之前，让我们让您的大脑运转一下，看看您学到了什么。

# 问题

1.  API 代表什么？

1.  REST 代表什么？

1.  REST 的六个约束是什么？

1.  HATEOAS 代表什么？

1.  RAML 是什么？

1.  Swagger 是什么？

1.  术语“良好定义的软件边界”是什么意思？

1.  为什么您应该了解您正在使用的 API？

1.  结构体和对象哪个性能更好？

1.  为什么应该测试第三方 API？

1.  为什么应该测试您自己的 API？

1.  您如何确定要为您的代码编写哪些测试？

1.  列举三种将代码组织成良好定义的软件边界的方法。

# 进一步阅读

+   [`weblogs.asp.net/sukumarraju/asp-net-web-api-testing-using-nunit-framework`](https://weblogs.asp.net/sukumarraju/asp-net-web-api-testing-using-nunit-framework)提供了使用 NUnit 测试 Web API 的完整示例。

+   [`raml.org/developers/design-your-api`](https://raml.org/developers/design-your-api)展示了如何使用 RAML 设计您的 API。

+   [`apiworkbench.com/docs/`](http://apiworkbench.com/docs/)提供了在 Atom 中使用 RAML 设计 API 的文档。

+   [`dotnetcoretutorials.com/2017/10/19/using-swagger-asp-net-core/`](https://dotnetcoretutorials.com/2017/10/19/using-swagger-asp-net-core/)是使用 Swagger 的很好的介绍。

+   [`swagger.io/about/`](https://swagger.io/about/)带您到 Swagger 关于页面。

+   [`httpstatuses.com/`](https://httpstatuses.com/)是 HTTP 状态代码列表。

+   [`www.greenbytes.de/tech/webdav/rfc5988.html`](https://www.greenbytes.de/tech/webdav/rfc5988.html)是 RFC 5988 的 Web 链接规范。

+   [`oauth.net/2/`](https://oauth.net/2/)带您到 OAuth 2.0 主页。

+   [`en.wikipedia.org/wiki/Domain-driven_design`](https://en.wikipedia.org/wiki/Domain-driven_design)是领域驱动设计的维基百科页面。

+   [`www.packtpub.com/gb/application-development/hands-domain-driven-design-net-core`](https://www.packtpub.com/gb/application-development/hands-domain-driven-design-net-core)提供了关于《Hands-On Domain-Driven Design with .NET Core》一书的信息。

+   [`www.packtpub.com/gb/application-development/test-driven-development-c-and-net-core-mvc-video`](https://www.packtpub.com/gb/application-development/test-driven-development-c-and-net-core-mvc-video) 提供了关于使用 C#和.NET Core 以及 MVC 进行测试驱动开发的信息。


# 第十章：使用 API 密钥和 Azure Key Vault 保护 API

在本章中，我们将看到如何在 Azure Key Vault 中保存秘密。我们还将研究如何使用 API 密钥来通过身份验证和基于角色的授权保护我们自己的密钥。为了获得 API 安全性的第一手经验，我们将构建一个完全功能的 FinTech API。

我们的 API 将使用私钥（在 Azure Key Vault 中安全保存）提取第三方 API 数据。然后，我们将使用两个 API 密钥保护我们的 API；一个密钥将在内部使用，第二个密钥将由外部用户使用。

本章涵盖以下主题：

+   访问 Morningstar API

+   将 Morningstar API 存储在 Azure Key Vault 中

+   在 Azure 中创建股息日历 ASP.NET Core Web 应用程序

+   发布我们的 Web 应用程序

+   使用 API 密钥保护我们的股息日历 API

+   测试我们的 API 密钥安全性

+   添加股息日历代码

+   限制我们的 API

您将了解良好 API 设计的基础知识，并掌握推动 API 能力所需的知识。本章将帮助您获得以下技能：

+   使用客户端 API 密钥保护 API

+   使用 Azure Key Vault 存储和检索秘密

+   使用 Postman 执行发布和获取数据的 API 命令

+   在 RapidAPI.com 上申请并使用第三方 API

+   限制 API 使用

+   编写利用在线财务数据的 FinTech API

在继续之前，请确保您实施以下技术要求，以充分利用本章。

# 技术要求

在本章中，我们将使用以下技术编写 API：

+   Visual Studio 2019 社区版或更高版本

+   您自己的个人 Morningstar API 密钥来自[`rapidapi.com/integraatio/api/morningstar1`](https://rapidapi.com/integraatio/api/morningstar1)

+   RestSharp ([`restsharp.org/`](http://restsharp.org/))

+   Swashbuckle.AspNetCore 5 或更高版本

+   Postman ([`www.postman.com/`](https://www.postman.com/))

+   Swagger ([`swagger.io`](https://swagger.io))

# 进行 API 项目-股息日历

学习的最佳方式是通过实践。因此，我们将构建一个可用的 API 并对其进行安全保护。API 不会完美无缺，还有改进的空间。但是，您可以自由地实施这些改进，并根据需要扩展项目。这里的主要目标是拥有一个完全运作的 API，只做一件事：返回列出当前年度将支付的所有公司股息的财务数据。

我们将在本章中构建的股息日历 API 是一个使用 API 密钥进行身份验证的 API。根据使用的密钥，授权将确定用户是内部用户还是外部用户。然后，控制器将根据用户类型执行适当的方法。只有内部用户方法将被实现，但您可以自由地实施外部用户方法，作为训练练习。

内部方法从 Azure Key Vault 中提取 API 密钥，并执行对第三方 API 的各种 API 调用。数据以**JavaScript 对象表示法**（**JSON**）格式返回，反序列化为对象，然后处理以提取未来的股息支付，并将其添加到股息列表中。然后将此列表以 JSON 格式返回给调用者。最终结果是一个 JSON 文件，其中包含当前年度的所有计划股息支付。然后，最终用户可以将这些数据转换为可以使用 LINQ 查询的股息列表。

我们将在本章中构建的项目是一个 Web API，它从第三方金融 API 返回处理过的 JSON。我们的项目将从给定的股票交易所获取公司列表。然后，我们将循环遍历这些公司以获取它们的股息数据。然后将处理股息数据以获取当前年份的数据。因此，我们最终将返回给 API 调用者的是 JSON 数据。这些 JSON 数据将包含公司列表及其当前年份的股息支付预测。然后，最终用户可以将 JSON 数据转换为 C#对象，并对这些对象执行 LINQ 查询。例如，可以执行查询以获取下个月的除权支付或本月到期的支付。

我们将使用的 API 将是 Morningstar API 的一部分，该 API 可通过 RapidAPI.com 获得。您可以注册一个免费的 Morningstar API 密钥。我们将使用登录系统来保护我们的 API，用户将使用电子邮件地址和密码登录。您还需要 Postman，因为我们将使用它来发出 API 的`POST`和`GET`请求到股息日历 API。

我们的解决方案将包含一个项目，这将是一个 ASP.NET Core 应用程序，目标是.NET Framework Core 3.1 或更高版本。现在我们将讨论如何访问 Morningstar API。

# 访问 Morningstar API

转到[`rapidapi.com/integraatio/api/morningstar1`](https://rapidapi.com/integraatio/api/morningstar1)并请求 API 访问密钥。该 API 是 Freemium API。这意味着您可以在有限的时间内免费使用一定数量的调用，之后需要支付使用费用。花些时间查看 API 及其文档。当您收到密钥时，注意定价计划并保持密钥的机密性。

我们感兴趣的 API 如下：

+   `GET /companies/list-by-exchange`：此 API 返回指定交易所的国家列表。

+   `GET /dividends`：此 API 获取指定公司的所有历史和当前股息支付信息。

API 请求的第一部分是`GET` HTTP 动词，用于检索资源。API 请求的第二部分是要`GET`的资源，在这种情况下是`/companies/list-by-exchange`。正如我们在前面列表的第二个项目符号中所看到的，我们正在获取`/dividends`资源。

您可以在浏览器中测试每个 API，并查看返回的数据。我建议您在继续之前先这样做。这将帮助您对我们将要处理的内容有所了解。我们将使用的基本流程是获取属于指定交易所的公司列表，然后循环遍历它们以获取股息数据。如果股息数据有未来的支付日期，那么股息数据将被添加到日历中；否则，它将被丢弃。无论公司有多少股息数据，我们只对第一条记录感兴趣，这是最新的记录。

现在您已经拥有 API 密钥（假设您正在按照这些步骤进行），我们将开始构建我们的 API。

## 在 Azure Key Vault 中存储 Morningstar API 密钥

我们将使用 Azure Key Vault 和**托管服务标识**（MSI）与 ASP.NET Core Web 应用程序。因此，在继续之前，您将需要 Azure 订阅。对于新客户，可在[`azure.microsoft.com/en-us/free`](https://azure.microsoft.com/en-us/free/)上获得免费 12 个月的优惠。

作为 Web 开发人员，不将机密存储在代码中非常重要，因为代码可以被*反向工程*。如果代码是开源的，那么上传个人或企业密钥到公共版本控制系统存在危险。解决这个问题的方法是安全地存储机密，但这会引发一个困境。要访问机密密钥，我们需要进行身份验证。那么，我们如何克服这个困境呢？

我们可以通过为我们的 Azure 服务启用 MSI 来克服这一困境。因此，Azure 会生成一个服务主体。用户开发的应用程序将使用此服务主体来访问 Microsoft Azure 上的资源。对于服务主体，您可以使用证书或用户名和密码，以及任何您选择的具有所需权限集的角色。

控制 Azure 帐户的人控制每项服务可以执行的具体任务。通常最好从完全限制开始，只有在需要时才添加功能。以下图表显示了我们的 ASP.NET Core Web 应用程序、MSI 和 Azure 服务之间的关系：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/98b01f77-0e13-4266-9d5e-de1621a12700.png)

**Azure Active Directory**（**Azure AD**）被 MSI 用于注入服务实例的服务主体。一个名为**本地元数据服务**的 Azure 资源用于获取访问仁牌，并将用于验证服务访问 Azure 密钥保管库。

然后，代码调用可用于获取访问令牌的 Azure 资源上的本地元数据服务。然后，我们的代码使用从本地 MSI 端点提取的访问令牌来对 Azure 密钥保管库服务进行身份验证。

打开 Azure CLI 并输入`az login`以登录到 Azure。一旦登录，我们就可以创建一个资源组。Azure 资源组是逻辑容器，用于部署和管理 Azure 资源。以下命令在`East US`位置创建一个资源组：

```cs
az group create --name "<YourResourceGroupName>" --location "East US"
```

在本章的其余部分中都使用此资源组。现在我们将继续创建我们的密钥保管库。创建密钥保管库需要以下信息：

+   密钥保管库的名称，这是一个 3 到 24 个字符长的字符串，只能包含`0-9`、`a-z`、`A-Z`和`-`（连字符）字符

+   资源组的名称

+   位置——例如，`East US`或`West US`

在 Azure CLI 中，输入以下命令：

```cs
az keyvault create --name "<YourKeyVaultName>" --resource-group "<YourResourceGroupName> --location "East US"
```

目前只有您的 Azure 帐户被授权在新的保管库上执行操作。如有必要，您可以添加其他帐户。

我们需要添加到项目中的主要密钥是`MorningstarApiKey`。要将 Morningstar API 密钥添加到您的密钥保管库中，请输入以下命令：

```cs
az keyvault secret set --vault-name "<YourKeyVaultName>" --name "MorningstarApiKey" --value "<YourMorningstarApiKey>"
```

您的密钥保管库现在存储了您的 Morningstar API 密钥。要检查该值是否正确存储，请输入以下命令：

```cs
az keyvault secret show --name "MorningstarApiKey" --vault-name "<YourKeyVaultName>"
```

现在您应该在控制台窗口中看到您的密钥显示，显示存储的密钥和值。

# 在 Azure 中创建股息日历 ASP.NET Core Web 应用程序

要完成项目的这一阶段，您需要安装了 ASP.NET 和 Web 开发工作负载的 Visual Studio 2019：

1.  创建一个新的 ASP.NET Core Web 应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/83a0ae31-6cad-493c-8818-9b2c23ebe9c1.png)

1.  确保 API 选择了`No Authentication`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/f1d634c9-d3d2-44d9-9003-6b2a961c0d8a.png)

1.  单击“创建”以创建您的新项目。然后运行您的项目。默认情况下，定义了一个示例天气预报 API，并在浏览器窗口中输出以下 JSON 代码：

```cs
[{"date":"2020-04-13T20:02:22.8144942+01:00","temperatureC":0,"temperatureF":32,"summary":"Balmy"},{"date":"2020-04-14T20:02:22.8234349+01:00","temperatureC":13,"temperatureF":55,"summary":"Warm"},{"date":"2020-04-15T20:02:22.8234571+01:00","temperatureC":3,"temperatureF":37,"summary":"Scorching"},{"date":"2020-04-16T20:02:22.8234587+01:00","temperatureC":-2,"temperatureF":29,"summary":"Sweltering"},{"date":"2020-04-17T20:02:22.8234602+01:00","temperatureC":-13,"temperatureF":9,"summary":"Cool"}]
```

接下来，我们将发布我们的应用程序到 Azure。

## 发布我们的 Web 应用程序

在我们可以发布我们的 Web 应用程序之前，我们将首先创建一个新的 Azure 应用服务来发布我们的应用程序。我们将需要一个资源组来包含我们的 Azure 应用服务，以及一个指定托管位置、大小和特性的新托管计划，用于托管我们的应用程序的 Web 服务器群。因此，让我们按照以下要求进行处理：

1.  确保您从 Visual Studio 登录到 Azure 帐户。要创建应用服务，请右键单击刚创建的项目，然后从菜单中选择“发布”。这将显示“选择发布目标”对话框，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/bb8f7ab3-0071-4ef9-972a-6499efb8f6e4.png)

1.  选择 App Service | 创建新的，并点击创建配置文件。创建一个新的托管计划，如下例所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/73abd32c-f8df-4d10-82d4-73fc691a21d3.png)

1.  然后，确保您提供一个名称，选择一个订阅，并选择您的资源组。建议您还设置“应用程序洞察”设置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/35f10e70-0b39-4035-973a-6ea031b28dc8.png)

1.  点击“创建”以创建您的应用服务。创建完成后，您的“发布”屏幕应如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/82f95f6e-c959-43fd-89ba-b2bd2ac7e14f.png)

1.  在这个阶段，您可以点击站点 URL。这将在浏览器中加载您的站点 URL。如果您的服务成功配置并运行，您的浏览器应该显示以下页面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/e45fb271-cba1-45ba-9150-e5fdf60cf2a5.png)

1.  让我们发布我们的 API。点击“发布”按钮。当网页运行时，它将显示一个错误页面。修改 URL 为`https://dividend-calendar.azurewebsites.net/weatherforecast`。网页现在应该显示天气预报 API 的 JSON 代码：

```cs
[{"date":"2020-04-13T19:36:26.9794202+00:00","temperatureC":40,"temperatureF":103,"summary":"Hot"},{"date":"2020-04-14T19:36:26.9797346+00:00","temperatureC":7,"temperatureF":44,"summary":"Bracing"},{"date":"2020-04-15T19:36:26.9797374+00:00","temperatureC":8,"temperatureF":46,"summary":"Scorching"},{"date":"2020-04-16T19:36:26.9797389+00:00","temperatureC":11,"temperatureF":51,"summary":"Freezing"},{"date":"2020-04-17T19:36:26.9797403+00:00","temperatureC":3,"temperatureF":37,"summary":"Hot"}]
```

我们的服务现在已经上线。如果您登录到 Azure 门户并访问您的托管计划的资源组，您将看到四个资源。这些资源如下：

+   **应用服务**：`dividend-calendar`

+   **应用程序洞察**：`dividend-calendar`

+   **应用服务计划**：``DividendCalendarHostingPlan``

+   **密钥保管库**：无论你的密钥保管库叫什么。在我的案例中，它叫`Keys-APIs`，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/4ece03d9-20f5-4014-b1bf-1d03e363bb20.png)

如果您从 Azure 门户主页([`portal.azure.com/#home`](https://portal.azure.com/#home))点击您的应用服务，您将看到您可以浏览到您的服务，以及停止、重新启动和删除您的应用服务：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/8ba4b623-0f35-4f20-bd5b-526ef3b17ef3.png)

现在我们已经在应用程序中使用了应用程序洞察，并且我们的 Morningstar API 密钥已经安全存储，我们可以开始构建我们的股息日历。

# 使用 API 密钥保护我们的股息日历 API

为了保护我们的股息日历 API 的访问，我们将使用客户端 API 密钥。有许多方法可以与客户共享客户端密钥，但我们将不在这里讨论它们。你可以想出自己的策略。我们将专注于如何使客户能够经过身份验证和授权访问我们的 API。

为了保持简单，我们将使用**存储库模式**。存储库模式有助于将我们的程序与底层数据存储解耦。这种模式提高了可维护性，并允许您更改底层数据存储而不影响程序。对于我们的存储库，我们的密钥将在一个类中定义，但在商业项目中，您可以将密钥存储在数据存储中，如 Cosmos DB、SQL Server 或 Azure 密钥保管库。您可以决定最适合您需求的策略，这也是我们使用存储库模式的主要原因，因为您可以控制自己需求的底层数据源。

## 设置存储库

我们将从设置我们的存储库开始：

1.  在您的项目中添加一个名为`Repository`的新文件夹。然后，添加一个名为`IRepository`的新接口和一个将实现`IRepository`的类，名为`InMemoryRepository`。修改您的接口，如下所示：

```cs
using CH09_DividendCalendar.Security.Authentication;
using System.Threading.Tasks;

namespace CH09_DividendCalendar.Repository
{
    public interface IRepository
    {
        Task<ApiKey> GetApiKey(string providedApiKey);
    }
}
```

1.  这个接口定义了一个用于检索 API 密钥的方法。我们还没有定义`ApiKey`类，我们将在稍后进行。现在，让我们实现`InMemoryRepository`。添加以下`using`语句：

```cs
using CH09_DividendCalendar.Security.Authentication;
using CH09_DividendCalendar.Security.Authorisation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
```

1.  当我们开始添加身份验证和授权类时，将创建`security`命名空间。修改`Repository`类以实现`IRepository`接口。添加将保存我们的 API 密钥的成员变量，然后添加`GetApiKey()`方法：

```cs
    public class InMemoryRepository : IRepository
    {
        private readonly IDictionary<string, ApiKey> _apiKeys;

        public Task<ApiKey> GetApiKey(string providedApiKey)
        {
            _apiKeys.TryGetValue(providedApiKey, out var key);
            return Task.FromResult(key);
        }
    }
```

1.  `InMemoryRepository`类实现了`IRepository`的`GetApiKey()`方法。这将返回一个 API 密钥的字典。这些密钥将存储在我们的`_apiKeys`字典成员变量中。现在，我们将添加我们的构造函数：

```cs
public InMemoryRepository()
{
    var existingApiKeys = new List<ApiKey>
    {
        new ApiKey(1, "Internal", "C5BFF7F0-B4DF-475E-A331-F737424F013C", new DateTime(2019, 01, 01),
            new List<string>
            {
                Roles.Internal
            }),
        new ApiKey(2, "External", "9218FACE-3EAC-6574-C3F0-08357FEDABE9", new DateTime(2020, 4, 15),
            new List<string>
            {
                Roles.External
            })
        };

    _apiKeys = existingApiKeys.ToDictionary(x => x.Key, x => x);
}
```

1.  我们的构造函数创建了一个新的 API 密钥列表。它为内部使用创建了一个内部 API 密钥，为外部使用创建了一个外部 API 密钥。然后将列表转换为字典，并将字典存储在`_apiKeys`中。因此，我们现在已经有了我们的存储库。

1.  我们将使用一个名为`X-Api-Key`的 HTTP 标头。这将存储客户端的 API 密钥，该密钥将传递到我们的 API 进行身份验证和授权。在项目中添加一个名为`Shared`的新文件夹，然后添加一个名为`ApiKeyConstants`的新文件。使用以下代码更新文件：

```cs
namespace CH09_DividendCalendar.Shared
{
    public struct ApiKeyConstants
    {
        public const string HeaderName = "X-Api-Key";
        public const string MorningstarApiKeyUrl 
            = "https://<YOUR_KEY_VAULT_NAME>.vault.azure.net/secrets/MorningstarApiKey";
    }
}
```

这个文件包含两个常量——标头名称，用于建立用户身份的时候使用，以及 Morningstar API 密钥的 URL，它存储在我们之前创建的 Azure 密钥保管库中。

1.  由于我们将处理 JSON 数据，我们需要设置我们的 JSON 命名策略。在项目中添加一个名为`Json`的文件夹。然后，添加一个名为`DefaultJsonSerializerOptions`的类：

```cs
using System.Text.Json;

namespace CH09_DividendCalendar.Json
{
    public static class DefaultJsonSerializerOptions
    {
        public static JsonSerializerOptions Options => new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            IgnoreNullValues = true
        };
    }
}
```

`DefaultJsonSerializerOptions`类将我们的 JSON 命名策略设置为忽略空值并使用驼峰命名法。

我们现在将开始为我们的 API 添加身份验证和授权。

## 设置身份验证和授权

我们现在将开始为身份验证和授权的安全类工作。首先澄清一下我们所说的身份验证和授权的含义是很好的。身份验证是确定用户是否被授权访问我们的 API。授权是确定用户一旦获得对我们的 API 的访问权限后拥有什么权限。

### 添加身份验证

在继续之前，将一个`Security`文件夹添加到项目中，然后在该文件夹下添加`Authentication`和`Authorisation`文件夹。我们将首先添加我们的`Authentication`类；我们将添加到`Authentication`文件夹的第一个类是`ApiKey`。向`ApiKey`添加以下属性：

```cs
public int Id { get; }
public string Owner { get; }
public string Key { get; }
public DateTime Created { get; }
public IReadOnlyCollection<string> Roles { get; }
```

这些属性存储与指定 API 密钥及其所有者相关的信息。这些属性是通过构造函数设置的：

```cs
public ApiKey(int id, string owner, string key, DateTime created, IReadOnlyCollection<string> roles)
{
    Id = id;
    Owner = owner ?? throw new ArgumentNullException(nameof(owner));
    Key = key ?? throw new ArgumentNullException(nameof(key));
    Created = created;
    Roles = roles ?? throw new ArgumentNullException(nameof(roles));
}
```

构造函数设置 API 密钥属性。如果一个人身份验证失败，他们将收到一个`Error 403 Unauthorized`的消息。因此，现在让我们定义我们的`UnauthorizedProblemDetails`类：

```cs
public class UnauthorizedProblemDetails : ProblemDetails
{
    public UnauthorizedProblemDetails(string details = null)
    {
        Title = "Forbidden";
        Detail = details;
        Status = 403;
        Type = "https://httpstatuses.com/403";
    }
}
```

这个类继承自`Microsoft.AspNetCore.Mvc.ProblemDetails`类。构造函数接受一个`string`类型的单个参数，默认为`null`。如果需要，您可以将详细信息传递给这个构造函数以提供更多信息。接下来，我们添加`AuthenticationBuilderExtensions`：

```cs
public static class AuthenticationBuilderExtensions
{
    public static AuthenticationBuilder AddApiKeySupport(
        this AuthenticationBuilder authenticationBuilder, 
        Action<ApiKeyAuthenticationOptions> options
    )
    {
        return authenticationBuilder
            .AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>            
                (ApiKeyAuthenticationOptions.DefaultScheme, options);
    }
}
```

这个扩展方法将 API 密钥支持添加到身份验证服务中，在`Startup`类的`ConfigureServices`方法中设置。现在，添加`ApiKeyAuthenticationOptions`类：

```cs
public class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions
{
    public const string DefaultScheme = "API Key";
    public string Scheme => DefaultScheme;
    public string AuthenticationType = DefaultScheme;
}
```

`ApiKeyAuthenticationOptions`类继承自`AuthenticationSchemeOptions`类。我们将默认方案设置为使用 API 密钥身份验证。我们授权的最后一部分是构建我们的`ApiKeyAuthenticationHandler`类。顾名思义，这是用于验证 API 密钥，确保客户端被授权访问和使用我们的 API 的主要类：

```cs
public class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
{
    private const string ProblemDetailsContentType = "application/problem+json";
    private readonly IRepository _repository;
}
```

我们的`ApiKeyAuthenticationHandler`类继承自`AuthenticationHandler`并使用`ApiKeyAuthenticationOptions`。我们将问题详细信息（异常信息）的内容类型定义为`application/problem+json`。我们还使用`_repository`成员变量提供了 API 密钥存储库的占位符。下一步是声明我们的构造函数：

```cs
public ApiKeyAuthenticationHandler(
    IOptionsMonitor<ApiKeyAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ISystemClock clock,
    IRepository repository
) : base(options, logger, encoder, clock)
{
    _repository = repository ?? throw new ArgumentNullException(nameof(repository));
}
```

我们的构造函数将`ApiKeyAuthenticationOptions`、`ILoggerFactory`、`UrlEncoder`和`ISystemClock`参数传递给基类。明确地，我们设置了存储库。如果存储库为空，我们将抛出一个带有存储库名称的空参数异常。让我们添加我们的`HandleChallengeAsync()`方法：

```cs
protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
{
    Response.StatusCode = 401;
    Response.ContentType = ProblemDetailsContentType;
    var problemDetails = new UnauthorizedProblemDetails();
    await Response.WriteAsync(JsonSerializer.Serialize(problemDetails, 
        DefaultJsonSerializerOptions.Options));
}
```

当用户挑战失败时，`HandleChallengeAsync()`方法返回一个`Error 401 Unauthorized`的响应。现在，让我们添加我们的`HandleForbiddenAsync()`方法：

```cs
protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
{
    Response.StatusCode = 403;
    Response.ContentType = ProblemDetailsContentType;
    var problemDetails = new ForbiddenProblemDetails();
    await Response.WriteAsync(JsonSerializer.Serialize(problemDetails, 
        DefaultJsonSerializerOptions.Options));
}
```

当用户权限检查失败时，`HandleForbiddenAsync()`方法返回`Error 403 Forbidden`响应。现在，我们需要添加一个最终的方法，返回`AuthenticationResult`：

```cs
protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
{
    if (!Request.Headers.TryGetValue(ApiKeyConstants.HeaderName, out var apiKeyHeaderValues))
        return AuthenticateResult.NoResult();
    var providedApiKey = apiKeyHeaderValues.FirstOrDefault();
    if (apiKeyHeaderValues.Count == 0 || string.IsNullOrWhiteSpace(providedApiKey))
        return AuthenticateResult.NoResult();
    var existingApiKey = await _repository.GetApiKey(providedApiKey);
    if (existingApiKey != null) {
        var claims = new List<Claim> {new Claim(ClaimTypes.Name, existingApiKey.Owner)};
        claims.AddRange(existingApiKey.Roles.Select(role => new Claim(ClaimTypes.Role, role)));
        var identity = new ClaimsIdentity(claims, Options.AuthenticationType);
        var identities = new List<ClaimsIdentity> { identity };
        var principal = new ClaimsPrincipal(identities);
        var ticket = new AuthenticationTicket(principal, Options.Scheme);
        return AuthenticateResult.Success(ticket);
    }
    return AuthenticateResult.Fail("Invalid API Key provided.");
}
```

我们刚刚编写的代码检查我们的标头是否存在。如果标头不存在，则`AuthenticateResult()`返回`None`属性的布尔值`true`，表示此请求未提供任何信息。然后我们检查标头是否有值。如果没有提供值，则`return`值表示此请求未提供任何信息。然后我们使用客户端密钥从我们的存储库中获取我们的服务器端密钥。

如果服务器端的密钥为空，则返回一个失败的`AuthenticationResult()`实例，表示提供的 API 密钥无效，如`Exception`类型的`Failure`属性中所标识的那样。否则，用户被视为真实，并被允许访问我们的 API。对于有效的用户，我们为他们的身份设置声明，然后返回一个成功的`AuthenticateResult()`实例。

所以，我们已经解决了我们的身份验证问题。现在，我们需要处理我们的授权。

### 添加授权

我们的授权类将被添加到`Authorisation`文件夹中。使用以下代码添加`Roles`结构：

```cs
public struct Roles
{
    public const string Internal = "Internal";
    public const string External = "External";
}
```

我们期望我们的 API 在内部和外部都可以使用。但是，对于我们的最小可行产品，只实现了内部用户的代码。现在，添加`Policies`结构：

```cs
public struct Policies
{
    public const string Internal = nameof(Internal);
    public const string External = nameof(External);
}
```

在我们的`Policies`结构中，我们添加了两个将用于内部和外部客户端的策略。现在，我们将添加`ForbiddenProblemDetails`类：

```cs
public class ForbiddenProblemDetails : ProblemDetails
{
    public ForbiddenProblemDetails(string details = null)
    {
        Title = "Forbidden";
        Detail = details;
        Status = 403;
        Type = "https://httpstatuses.com/403";
    }
}
```

如果一个或多个权限对经过身份验证的用户不可用，这个类提供了禁止的问题详细信息。如果需要，您可以将一个字符串传递到这个类的构造函数中，提供相关信息。

对于我们的授权，我们需要为内部和外部客户端添加授权要求和处理程序。首先，我们将添加`ExternalAuthorisationHandler`类：

```cs
public class ExternalAuthorisationHandler : AuthorizationHandler<ExternalRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context, 
        ExternalRequirement requirement
    )
    {
        if (context.User.IsInRole(Roles.External))
            context.Succeed(requirement);
        return Task.CompletedTask;
}
 public class ExternalRequirement : IAuthorizationRequirement
 {
 }
```

`ExternalRequirement`类是一个空类，实现了`IAuthorizationRequirement`接口。现在，添加`InternalAuthorisationHandler`类：

```cs
public class InternalAuthorisationHandler : AuthorizationHandler<InternalRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context, 
        InternalRequirement requirement
    )
    {
        if (context.User.IsInRole(Roles.Internal))
            context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
```

`InternalAuthorisationHandler`类处理内部要求的授权。如果上下文用户被分配到内部角色，则授予权限。否则，将拒绝权限。让我们添加所需的`InternalRequirement`类：

```cs
public class InternalRequirement : IAuthorizationRequirement
{
}
```

在这里，`InternalRequirement`类是一个空类，实现了`IAuthorizationRequirement`接口。

现在我们已经将我们的身份验证和授权类放在了适当的位置。所以，现在是时候更新我们的`Startup`类，将`security`类连接起来。首先修改`Configure()`方法：

```cs
public void Configure(IApplicationBuilder app, IHostEnvironment env)
{
    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
    }
    app.UseRouting();
    app.UseAuthentication();
 app.UseAuthorization();
    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllers();
    });
}
```

`Configure()`方法将异常页面设置为开发人员页面（如果我们处于开发中）。然后请求应用程序使用*routing*将 URI 与我们的控制器中的操作匹配。然后通知应用程序应该使用我们的身份验证和授权方法。最后，从控制器映射应用程序端点。

我们需要更新的最后一个方法来完成我们的 API 密钥身份验证和授权是`ConfigureServices()`方法。我们需要做的第一件事是添加我们的具有 API 密钥支持的身份验证服务：

```cs
services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = ApiKeyAuthenticationOptions.DefaultScheme;
    options.DefaultChallengeScheme = ApiKeyAuthenticationOptions.DefaultScheme;
}).AddApiKeySupport(options => { });
```

在这里，我们设置了默认的身份验证方案。我们使用我们的扩展密钥`AddApiKeySupport()`，如在我们的`AuthenticationBuilderExtensions`类中定义的那样，返回`Microsoft.AspNetCore.Authentication.AuthenticationBuilder`。我们的默认方案设置为 API 密钥，如在我们的`ApiKeyAuthenticationOptions`类中配置的那样。API 密钥是一个常量值，通知身份验证服务我们将使用 API 密钥身份验证。现在，我们需要添加我们的授权服务：

```cs
services.AddAuthorization(options =>
{
    options.AddPolicy(Policies.Internal, policy => policy.Requirements.Add(new InternalRequirement()));
    options.AddPolicy(Policies.External, policy => policy.Requirements.Add(new ExternalRequirement()));
});
```

在这里，我们正在设置我们的内部和外部策略和要求。这些定义在我们的`Policies`、`InternalRequirement`和`ExternalRequirement`类中。

好了，我们已经添加了所有的 API 密钥安全类。因此，我们现在可以使用 Postman 测试我们的 API 密钥身份验证和授权是否有效。

# 测试我们的 API 密钥安全性

在本节中，我们将使用 Postman 测试我们的 API 密钥身份验证和授权。在您的`Controllers`文件夹中添加一个名为`DividendCalendar`的类。更新类如下：

```cs
[ApiController]
[Route("api/[controller]")]
public class DividendCalendar : ControllerBase
{
    [Authorize(Policy = Policies.Internal)]
    [HttpGet("internal")]
    public IActionResult GetDividendCalendar()
    {
        var message = $"Hello from {nameof(GetDividendCalendar)}.";
        return new ObjectResult(message);
    }

    [Authorize(Policy = Policies.External)]
    [HttpGet("external")]
    public IActionResult External()
    {
        var message = "External access is currently unavailable.";
        return new ObjectResult(message);
    }
}
```

这个类将包含我们的股息日历 API 代码功能。尽管在我们的最小可行产品的初始版本中不会使用外部代码，但我们将能够测试我们的内部和外部身份验证和授权。

1.  打开 Postman 并创建一个新的`GET`请求。对于 URL，请使用`https://localhost:44325/api/dividendcalendar/internal`。点击发送：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/cb86a829-e085-40e4-a8e8-222ddf94a65a.png)

1.  如您所见，在 API 请求中没有 API 密钥，我们得到了预期的`401 未经授权`状态，以及我们在`ForbiddenProblemDetails`类中定义的禁止 JSON。现在，添加`x-api-key`头，并使用`C5BFF7F0-B4DF-475E-A331-F737424F013C`值。然后，点击发送：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/d2968005-7ae2-4e3f-8c33-cdae1e1fcc44.png)

1.  现在您将获得一个`200 OK`的状态。这意味着 API 请求已成功。您可以在正文中看到请求的结果。内部用户将看到`Hello from GetDividendCalendar`。再次运行请求，但更改 URL，使路由为外部而不是内部。因此，URL 应为`https://localhost:44325/api/dividendcalendar/external`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/70e85d72-8e5f-4e57-b678-fb074a597962.png)

1.  您应该收到一个`403 禁止`的状态和禁止的 JSON。这是因为 API 密钥是有效的 API 密钥，但路由是为外部客户端而设，外部客户端无法访问内部 API。将`x-api-key`头值更改为`9218FACE-3EAC-6574-C3F0-08357FEDABE9`。然后，点击发送：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/222f0de1-53d5-4a1a-bd17-86c1dc9b7158.png)

您将看到您的状态是`200 OK`，并且正文中有`当前无法访问外部`的文本。

好消息！我们使用 API 密钥身份验证和授权的基于角色的安全系统已经经过测试并且有效。因此，在我们实际添加我们的 FinTech API 之前，我们已经实施并测试了我们的 API 密钥，用于保护我们的 FinTech API。因此，在编写我们实际 API 的一行代码之前，我们已经将 API 的安全性放在首位。现在，我们可以认真开始构建我们的股息日历 API 功能，知道它是安全的。

# 添加股息日历代码

我们的内部 API 只有一个目的，那就是建立今年要支付的股息数组。然而，您可以在此项目的基础上构建，将 JSON 保存到文件或某种类型的数据库中。因此，您只需要每月进行一次内部调用，以节省 API 调用的费用。然而，外部角色可以根据需要从您的文件或数据库中访问数据。

我们已经为我们的股息日历 API 准备好了控制器。这个安全性是为了防止未经身份验证和未经授权的用户访问我们的内部`GetDividendCalendar()`API 端点。因此，现在我们所要做的就是生成股息日历 JSON，我们的方法将返回。

为了让您看到我们将要努力实现的目标，请查看以下截断的 JSON 响应：

```cs
[{"Mic":"XLON","Ticker":"ABDP","CompanyName":"AB Dynamics PLC","DividendYield":0.0,"Amount":0.0279,"ExDividendDate":"2020-01-02T00:00:00","DeclarationDate":"2019-11-27T00:00:00","RecordDate":"2020-01-03T00:00:00","PaymentDate":"2020-02-13T00:00:00","DividendType":null,"CurrencyCode":null},

...

{"Mic":"XLON","Ticker":"ZYT","CompanyName":"Zytronic PLC","DividendYield":0.0,"Amount":0.152,"ExDividendDate":"2020-01-09T00:00:00","DeclarationDate":"2019-12-10T00:00:00","RecordDate":"2020-01-10T00:00:00","PaymentDate":"2020-02-07T00:00:00","DividendType":null,"CurrencyCode":null}]
```

这个 JSON 响应是一个股息数组。股息由`Mic`、`Ticker`、`CompanyName`、`DividendYield`、`Amount`、`ExDividendDate`、`DeclarationDate`、`RecordDate`、`PaymentDate`、`DividendType`和`CurrencyCode`字段组成。在您的项目中添加一个名为`Models`的新文件夹，然后添加以下代码的`Dividend`类：

```cs
public class Dividend
{
    public string Mic { get; set; }
    public string Ticker { get; set; }
    public string CompanyName { get; set; }
    public float DividendYield { get; set; }
    public float Amount { get; set; }
    public DateTime? ExDividendDate { get; set; }
    public DateTime? DeclarationDate { get; set; }
    public DateTime? RecordDate { get; set; }
    public DateTime? PaymentDate { get; set; }
    public string DividendType { get; set; }
    public string CurrencyCode { get; set; }
}
```

让我们看看每个字段代表什么：

+   `Mic`: **ISO 10383 市场识别代码**（**MIC**），这是股票上市的地方。有关更多信息，请参阅[`www.iso20022.org/10383/iso-10383-market-identifier-codes`](https://www.iso20022.org/10383/iso-10383-market-identifier-codes)。

+   `Ticker`: 普通股的股票市场代码。

+   `CompanyName`: 拥有该股票的公司的名称。

+   `DividendYield`: 公司年度股利与股价的比率。股利收益率以百分比计算，并使用*股利收益率=年度股利/股价*公式计算。

+   `Amount`: 每股支付给股东的金额。

+   `ExDividendDate`: 在此日期之前，您必须购买股票才能收到下一个股利支付。

+   `DeclarationDate`: 公司宣布支付股利的日期。

+   `RecordDate`: 公司查看其记录以确定谁将收到股利的日期。

+   `PaymentDate`: 股东收到股利支付的日期。

+   `DividendType`: 这可以是，例如，`现金股利`，`财产股利`，`股票股利`，`分红股`或`清算股利`。

+   `CurrencyCode`: 金额将支付的货币。

我们在`Models`文件夹中需要的下一个类是`Company`类：

```cs
public class Company
    {
        public string MIC { get; set; }
        public string Currency { get; set; }
        public string Ticker { get; set; }
        public string SecurityId { get; set; }
        public string CompanyName { get; set; }
    }
```

`Mic`和`Ticker`字段与我们的`Dividend`类相同。在不同的 API 调用之间，API 使用不同的货币标识符名称。这就是为什么我们在`Dividend`中有`CurrencyCode`，在`Company`中有`Currency`。这有助于 JSON 对象映射过程，以便我们不会遇到格式化异常。

这些字段分别代表以下内容：

+   `Currency`: 用于定价股票的货币

+   `SecurityId`: 普通股的股票市场安全标识符

+   `CompanyName`: 拥有该股票的公司的名称

我们接下来的`Models`类称为`Companies`。这个类用于存储在初始 Morningstar API 调用中返回的公司。我们将循环遍历公司列表，以进行进一步的 API 调用，以获取每家公司的记录，以便我们随后进行 API 调用以获取公司的股利：

```cs
 public class Companies
 {
     public int Total { get; set; }
     public int Offset { get; set; }
     public List<Company> Results { get; set; }
     public string ResponseStatus { get; set; }
 }
```

这些属性分别定义以下内容：

+   `Total`: 从 API 查询返回的记录总数

+   `Offset`: 记录偏移量

+   `Results`: 返回的公司列表

+   `ResponseStatus`: 提供详细的响应信息，特别是如果返回错误的话

现在，我们将添加`Dividends`类。这个类保存了股利的列表，这些股利是通过股利的 Morningstar API 响应返回的：

```cs
public class Dividends
{
        public int Total { get; set; }
        public int Offset { get; set; }
        public List<Dictionary<string, string>> Results { get; set; }
        public ResponseStatus ResponseStatus { get; set; }
    }
```

这些属性与之前定义的相同，除了`Results`属性，它定义了返回指定公司的股利支付列表。

我们需要添加到我们的`Models`文件夹中的最后一个类是`ResponseStatus`类。这主要用于存储错误信息：

```cs
public class ResponseStatus
{
    public string ErrorCode { get; set; }
    public string Message { get; set; }
    public string StackTrace { get; set; }
    public List<Dictionary<string, string>> Errors { get; set; }
    public List<Dictionary<string, string>> Meta { get; set; }
}
```

该类的属性如下：

+   `ErrorCode`: 错误的编号

+   `Message`: 错误消息

+   `StackTrace`: 错误诊断

+   `Errors`: 错误列表

+   `Meta`: 错误元数据列表

我们现在已经准备好了所有需要的模型。现在，我们可以开始进行 API 调用，以建立我们的股利支付日历。在控制器中，添加一个名为`FormatStringDate()`的新方法，如下所示：

```cs
private DateTime? FormatStringDate(string date)
{
    return string.IsNullOrEmpty(date) ? (DateTime?)null : DateTime.Parse(date);
}
```

该方法接受一个字符串日期。如果字符串为 null 或空，则返回 null。否则，解析字符串并传回一个可空的`DateTime`值。我们还需要一个方法，从 Azure 密钥保管库中提取我们的 Morningstar API 密钥：

```cs
private async Task<string> GetMorningstarApiKey()
{
    try
    {
        AzureServiceTokenProvider azureServiceTokenProvider = new AzureServiceTokenProvider();
        KeyVaultClient keyVaultClient = new KeyVaultClient(
            new KeyVaultClient.AuthenticationCallback(
                azureServiceTokenProvider.KeyVaultTokenCallback
            )
        );
        var secret = await keyVaultClient.GetSecretAsync(ApiKeyConstants.MorningstarApiKeyUrl)
                                         .ConfigureAwait(false);
        return secret.Value;
    }
    catch (KeyVaultErrorException keyVaultException)
    {
        return keyVaultException.Message;
    }
}
```

`GetMorningstarApiKey()`方法实例化`AzureServiceTokenProvider`。然后，它创建一个新的`KeyVaultClient`对象类型，执行加密密钥操作。然后，该方法等待从 Azure 密钥保管库获取 Morningstar API 密钥的响应。然后，它传回响应值。如果在处理请求时发生错误，则返回`KeyVaultErrorException.Message`。

在处理股息时，我们首先从证券交易所获取公司列表。然后，我们循环遍历这些公司，并对该证券交易所中的每家公司进行另一个调用以获取每家公司的股息。因此，我们将从通过 MIC 获取公司列表的方法开始。请记住，我们使用`RestSharp`库。因此，如果您还没有安装它，现在是一个很好的时机。

```cs
private Companies GetCompanies(string mic)
{
    var client = new RestClient(
        $"https://morningstar1.p.rapidapi.com/companies/list-by-exchange?Mic={mic}"
    );
    var request = new RestRequest(Method.GET);
    request.AddHeader("x-rapidapi-host", "morningstar1.p.rapidapi.com");
    request.AddHeader("x-rapidapi-key", GetMorningstarApiKey().Result);
    request.AddHeader("accept", "string");
    IRestResponse response = client.Execute(request);
    return JsonConvert.DeserializeObject<Companies>(response.Content);
}
```

我们的`GetCompanies()`方法创建一个新的 REST 客户端，指向检索上市公司列表的 API URL。请求的类型是`GET`请求。我们为`GET`请求添加了三个头部，分别是`x-rapidapi-host`，`x-rapidapi-key`和`accept`。然后，我们执行请求并通过`Companies`模型返回反序列化的 JSON 数据。

现在，我们将编写返回指定交易所和公司的股息的方法。让我们从添加`GetDividends()`方法开始：

```cs
private Dividends GetDividends(string mic, string ticker)
{
    var client = new RestClient(
        $"https://morningstar1.p.rapidapi.com/dividends?Ticker={ticker}&Mic={mic}"
    );
    var request = new RestRequest(Method.GET);
    request.AddHeader("x-rapidapi-host", "morningstar1.p.rapidapi.com");
    request.AddHeader("x-rapidapi-key", GetMorningstarApiKey().Result);
    request.AddHeader("accept", "string");
    IRestResponse response = client.Execute(request);
    return JsonConvert.DeserializeObject<Dividends>(response.Content);
}
```

`GetDividends()`方法与`GetCompanies()`方法相同，只是请求返回指定股票交易所和公司的股息。 JSON 反序列化为`Dividends`对象的实例并返回。

对于我们的最终方法，我们需要将我们的最小可行产品构建到`BuildDividendCalendar()`方法中。这个方法是构建股息日历 JSON 的方法，将返回给客户端：

```cs
private List<Dividend> BuildDividendCalendar()
{
    const string MIC = "XLON";
    var thisYearsDividends = new List<Dividend>();
    var companies = GetCompanies(MIC);
    foreach (var company in companies.Results) {
        var dividends = GetDividends(MIC, company.Ticker);
        if (dividends.Results == null)
            continue;
        var currentDividend = dividends.Results.FirstOrDefault();
        if (currentDividend == null || currentDividend["payableDt"] == null)
            continue;
        var dateDiff = DateTime.Compare(
            DateTime.Parse(currentDividend["payableDt"]), 
            new DateTime(DateTime.Now.Year - 1, 12, 31)
        );
        if (dateDiff > 0) {
            var payableDate = DateTime.Parse(currentDividend["payableDt"]);
            var dividend = new Dividend() {
                Mic = MIC,
                Ticker = company.Ticker,
                CompanyName = company.CompanyName,
                ExDividendDate = FormatStringDate(currentDividend["exDividendDt"]),
                DeclarationDate = FormatStringDate(currentDividend["declarationDt"]),
                RecordDate = FormatStringDate(currentDividend["recordDt"]),
                PaymentDate = FormatStringDate(currentDividend["payableDt"]),
                Amount = float.Parse(currentDividend["amount"])
            };
            thisYearsDividends.Add(dividend);
        }
    }
    return thisYearsDividends;
}
```

在这个 API 的版本中，我们将 MIC 硬编码为`"XLON"`——**伦敦证券交易所**。然而，在未来的版本中，这个方法和公共端点可以更新为接受`request`参数的 MIC。然后，我们添加一个`list`变量来保存今年的股息支付。然后，我们执行我们的 Morningstar API 调用，以提取当前在指定 MIC 上市的公司列表。一旦列表返回，我们循环遍历结果。对于每家公司，我们然后进行进一步的 API 调用，以获取指定 MIC 和股票的完整股息记录。如果公司没有列出股息，那么我们继续下一个迭代并选择下一个公司。

如果公司有股息记录，我们获取第一条记录，这将是最新的股息支付。我们检查可支付日期是否为`null`。如果可支付日期为`null`，那么我们继续下一个迭代，选择下一个客户。如果可支付日期不为`null`，我们检查可支付日期是否大于上一年的 12 月 31 日。如果日期差大于 1，那么我们将向今年的股息列表添加一个新的股息对象。一旦我们遍历了所有公司并建立了今年的股息列表，我们将列表传回给调用方法。

在运行项目之前的最后一步是更新`GetDividendCalendar()`方法以调用`BuildDividendCalendar()`方法：

```cs
[Authorize(Policy = Policies.Internal)]
[HttpGet("internal")]
public IActionResult GetDividendCalendar()
{
    return new ObjectResult(JsonConvert.SerializeObject(BuildDividendCalendar()));
}
```

在`GetDividendCalendar()`方法中，我们从今年的股息序列化列表返回一个 JSON 字符串。因此，如果您在 Postman 中使用内部`x-api-key`变量运行项目，那么大约 20 分钟后，将返回以下 JSON：

```cs
[{"Mic":"XLON","Ticker":"ABDP","CompanyName":"AB Dynamics PLC","DividendYield":0.0,"Amount":0.0279,"ExDividendDate":"2020-01-02T00:00:00","DeclarationDate":"2019-11-27T00:00:00","RecordDate":"2020-01-03T00:00:00","PaymentDate":"2020-02-13T00:00:00","DividendType":null,"CurrencyCode":null},

...

{"Mic":"XLON","Ticker":"ZYT","CompanyName":"Zytronic PLC","DividendYield":0.0,"Amount":0.152,"ExDividendDate":"2020-01-09T00:00:00","DeclarationDate":"2019-12-10T00:00:00","RecordDate":"2020-01-10T00:00:00","PaymentDate":"2020-02-07T00:00:00","DividendType":null,"CurrencyCode":null}]
```

这个查询确实需要很长时间才能运行，大约 20 分钟左右，结果会在一年的时间内发生变化。因此，我们可以使用的一种策略是限制 API 每月运行一次，然后将 JSON 存储在文件或数据库中。然后，这个文件或数据库记录就是您要更新的外部方法调用并传回给外部客户端。让我们将 API 限制为每月运行一次。

# 限制我们的 API

在暴露 API 时，您需要对其进行节流。有许多可用的方法来做到这一点，例如限制同时用户的数量或限制在给定时间内的调用次数。

在这一部分，我们将对我们的 API 进行节流。我们将用来节流 API 的方法是限制我们的 API 每月只能在当月的 25 日运行一次。将以下一行添加到您的`appsettings.json`文件中：

```cs
"MorningstarNextRunDate":  null,
```

这个值将包含下一个 API 可以执行的日期。现在，在项目的根目录添加`AppSettings`类，然后添加以下属性：

```cs
public DateTime? MorningstarNextRunDate { get; set; }
```

这个属性将保存`MorningstarNextRunDate`键的值。接下来要做的是添加我们的静态方法，该方法将被调用以在`appsetting.json`文件中添加或更新应用程序设置：

```cs
public static void AddOrUpdateAppSetting<T>(string sectionPathKey, T value)
{
    try
    {
        var filePath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        string json = File.ReadAllText(filePath);
        dynamic jsonObj = Newtonsoft.Json.JsonConvert.DeserializeObject(json);
        SetValueRecursively(sectionPathKey, jsonObj, value);
        string output = Newtonsoft.Json.JsonConvert.SerializeObject(
            jsonObj, 
            Newtonsoft.Json.Formatting.Indented
        );
        File.WriteAllText(filePath, output);
    }
    catch (Exception ex)
    {
        Console.WriteLine("Error writing app settings | {0}", ex.Message);
    }
}
```

`AddOrUpdateAppSetting()`尝试获取`appsettings.json`文件的文件路径。然后从文件中读取 JSON。然后将 JSON 反序列化为`dynamic`对象。然后我们调用我们的方法递归设置所需的值。然后，我们将 JSON 写回同一文件。如果遇到错误，则将错误消息输出到控制台。让我们编写我们的`SetValueRecursively()`方法：

```cs
private static void SetValueRecursively<T>(string sectionPathKey, dynamic jsonObj, T value)
{
    var remainingSections = sectionPathKey.Split(":", 2);
    var currentSection = remainingSections[0];
    if (remainingSections.Length > 1)
    {
        var nextSection = remainingSections[1];
        SetValueRecursively(nextSection, jsonObj[currentSection], value);
    }
    else
    {
        jsonObj[currentSection] = value;
    }
}
```

`SetValueRecursively()`方法在第一个撇号字符处拆分字符串。然后递归处理 JSON，向下移动树。当它到达需要的位置时，也就是找到所需的值时，然后设置该值并返回该方法。将`ThrottleMonthDay`常量添加到`ApiKeyConstants`结构中：

```cs
public const int ThrottleMonthDay = 25;
```

当 API 请求发出时，此常量用于我们的日期检查。在`DividendCalendarController`中，添加`ThrottleMessage()`方法：

```cs
private string ThrottleMessage()
{
    return "This API call can only be made once on the 25th of each month.";
}
```

`ThrottleMessage()`方法只是返回消息，`"此 API 调用只能在每月的 25 日进行一次。"`。现在，添加以下构造函数：

```cs
public DividendCalendarController(IOptions<AppSettings> appSettings)
{
    _appSettings = appSettings.Value;
}
```

这个构造函数为我们提供了访问`appsettings.json`文件中的值。将以下两行添加到您的`Startup.ConfigureServices()`方法的末尾：

```cs
var appSettingsSection = Configuration.GetSection("AppSettings");
services.Configure<AppSettings>(appSettingsSection);
```

这两行使`AppSettings`类能够在需要时动态注入到我们的控制器中。将`SetMorningstarNextRunDate()`方法添加到`DividendCalendarController`类中：

```cs
private DateTime? SetMorningstarNextRunDate()
{
    int month;
    if (DateTime.Now.Day < 25)
        month = DateTime.Now.Month;
    else
        month = DateTime.Now.AddMonths(1).Month;
    var date = new DateTime(DateTime.Now.Year, month, ApiKeyConstants.ThrottleMonthDay);
    AppSettings.AddOrUpdateAppSetting<DateTime?>(
        "MorningstarNextRunDate",
        date
    );
    return date;
}
```

`SetMorningstarNextRunDate()`方法检查当前月份的日期是否小于`25`。如果当前月份的日期小于`25`，则将月份设置为当前月份，以便 API 可以在当月的 25 日运行。否则，对于大于或等于`25`的日期，月份将设置为下个月。然后组装新日期，然后更新`appsettings.json`的`MorningstarNextRunDate`键，返回可空的`DateTime`值：

```cs
private bool CanExecuteApiRequest()
{
    DateTime? nextRunDate = _appSettings.MorningstarNextRunDate;
    if (!nextRunDate.HasValue) 
        nextRunDate = SetMorningstarNextRunDate();
    if (DateTime.Now.Day == ApiKeyConstants.ThrottleMonthDay) {
        if (nextRunDate.Value.Month == DateTime.Now.Month) {
            SetMorningstarNextRunDate();
            return true;
        }
        else {
            return false;
        }
    }
    else {
        return false;
    }
}
```

`CanExecuteApiRequest()`从`AppSettings`类中获取`MorningstarNextRunDate`值的当前值。如果`DateTime?`没有值，则将该值设置并分配给`nextRunDate`本地变量。如果当前月份的日期不等于`ThrottleMonthDay`，则返回`false`。如果当前月份不等于下次运行日期的月份，则返回`false`。否则，我们将下一个 API 运行日期设置为下个月的 25 日，并返回`true`。

最后，我们更新我们的`GetDividendCalendar()`方法，如下所示：

```cs
[Authorize(Policy = Policies.Internal)]
[HttpGet("internal")]
public IActionResult GetDividendCalendar()
{
    if (CanExecuteApiRequest())
        return new ObjectResult(JsonConvert.SerializeObject(BuildDividendCalendar()));
    else
        return new ObjectResult(ThrottleMessage());
}
```

现在，当内部用户调用 API 时，他们的请求将被验证，以查看是否可以运行。如果运行，则返回股息日历的序列化 JSON。否则，我们返回`throttle`消息。

这就完成了我们的项目。

好了，我们完成了我们的项目。它并不完美，还有我们可以做的改进和扩展。下一步是记录我们的 API 并部署 API 和文档。我们还应该添加日志记录和监控。

日志记录对于存储异常详细信息以及跟踪我们的 API 的使用方式非常有用。 监控是一种监视我们的 API 健康状况的方法，这样我们可以在出现问题时收到警报。 这样，我们可以积极地保持我们的 API 正常运行。 我将让您根据需要扩展 API。 这对您来说将是一个很好的学习练习。

下一章将涉及横切关注点。 它将让您了解如何使用方面和属性来处理日志记录和监视。

让我们总结一下我们学到的东西。

# 总结

在本章中，您注册了一个第三方 API 并收到了自己的密钥。 API 密钥存储在您的 Azure 密钥保险库中，并且不被未经授权的客户端访问。 然后，您开始创建了一个 ASP.NET Core Web 应用程序并将其发布到 Azure。 然后，您开始使用身份验证和基于角色的授权来保护 Web 应用程序。

我们设置的授权是使用 API 密钥执行的。 在这个项目中，您使用了两个 API 密钥——一个用于内部使用，一个用于外部使用。 我们使用 Postman 应用程序进行了 API 和 API 密钥安全性的测试。 Postman 是一个非常好的有用的工具，用于测试各种 HTTP 谓词的 HTTP 请求和响应。

然后，您添加了股息日历 API 代码，并基于 API 密钥启用了内部和外部访问。 项目本身执行了许多不同的 API 调用，以建立一份预计向投资者支付股息的公司列表。 项目然后将对象序列化为 JSON 格式，返回给客户端。 最后，该项目被限制为每月运行一次。

因此，通过完成本章，您已经创建了一个 FinTech API，可以每月运行一次。 该 API 将为当年提供股息支付信息。 您的客户可以对此数据进行反序列化，然后对其执行 LINQ 查询，以提取满足其特定要求的数据。

在下一章中，我们将使用 PostSharp 来实现**面向方面的编程**（**AOP**）。 通过我们的 AOP 框架，我们将学习如何在应用程序中管理常见功能，如异常处理，日志记录，安全性和事务。 但在那之前，让我们让您的大脑思考一下您学到了什么。

# 问题

1.  哪个 URL 是托管您自己的 API 并访问第三方 API 的良好来源？

1.  保护 API 所需的两个必要部分是什么？

1.  声明是什么，为什么应该使用它们？

1.  您用 Postman 做什么？

1.  为什么应该使用存储库模式来管理数据存储？

# 进一步阅读

+   [`docs.microsoft.com/en-us/aspnet/web-api/overview/security/individual-accounts-in-web-api`](https://docs.microsoft.com/en-us/aspnet/web-api/overview/security/individual-accounts-in-web-api) 是微软关于 Web API 安全的深入指南。

+   [`docs.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-security/membership/creating-the-membership-schema-in-sql-server-vb`](https://docs.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-security/membership/creating-the-membership-schema-in-sql-server-vb) 讲解了如何创建 ASP.NET 成员数据库。

+   [`www.iso20022.org/10383/iso-10383-market-identifier-codes`](https://www.iso20022.org/10383/iso-10383-market-identifier-codes) 是关于 ISO 10383 MIC 的链接。

+   [`docs.microsoft.com/en-gb/azure/key-vault/vs-key-vault-add-connected-service`](https://docs.microsoft.com/en-gb/azure/key-vault/vs-key-vault-add-connected-service) 讲解了如何使用 Visual Studio Connected Services 将密钥保险库添加到您的 Web 应用程序。

+   [`aka.ms/installazurecliwindows`](https://aka.ms/installazurecliwindows) 是关于 Azure CLI MSI 安装程序的链接。

+   [`docs.microsoft.com/en-us/azure/key-vault/service-to-service-authentication`](https://docs.microsoft.com/en-us/azure/key-vault/service-to-service-authentication) 是 Azure 服务到服务认证的文档。

+   [`azure.microsoft.com/en-gb/free/?WT.mc_id=A261C142F`](https://azure.microsoft.com/en-gb/free/?WT.mc_id=A261C142F) 是您可以注册免费 12 个月 Azure 订阅的地方，如果您是新客户。

+   [`docs.microsoft.com/en-us/azure/key-vault/basic-concepts`](https://docs.microsoft.com/en-us/azure/key-vault/basic-concepts) 介绍了 Azure Key Vault 的基本概念。

+   [`docs.microsoft.com/en-us/azure/app-service/app-service-web-get-started-dotnet`](https://docs.microsoft.com/en-us/azure/app-service/app-service-web-get-started-dotnet) 介绍了在 Azure 中创建.NET Core 应用程序。

+   [`docs.microsoft.com/en-gb/azure/app-service/overview-hosting-plans`](https://docs.microsoft.com/en-gb/azure/app-service/overview-hosting-plans) 提供了 Azure 应用服务计划的概述。

+   [`docs.microsoft.com/en-us/azure/key-vault/tutorial-net-create-vault-azure-web-app`](https://docs.microsoft.com/en-us/azure/key-vault/tutorial-net-create-vault-azure-web-app) 是一个关于在.NET 中使用 Azure Key Vault 与 Azure Web 应用程序的教程。


# 第十一章：解决横切关注点

在编写清晰代码时，您需要考虑两种类型的关注点-核心关注点和横切关注点。**核心关注点**是软件的原因以及为什么开发它。**横切关注点**是不属于业务需求的关注点，但必须在代码的所有区域中进行处理，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/5a4fd4a9-d664-4351-985d-fc1b37687b68.png)

正是横切关注点，我们将在本章中通过构建一个可重用的类库来进行覆盖，您可以修改或扩展它以满足您的需求。横切关注点包括配置管理、日志记录、审计、安全、验证、异常处理、仪表、事务、资源池、缓存以及线程和并发。我们将使用装饰者模式和 PostSharp Aspect Framework 来帮助我们构建我们的可重用库，该库在编译时注入。

当您阅读本章时，您将看到**属性编程**如何导致使用更少的样板代码，以及更小、更可读、更易于维护和扩展的代码。这样，您的方法中只留下了所需的业务代码和样板代码。

我们已经讨论了许多这些想法。然而，它们在这里再次提到，因为它们是横切关注点。

在本章中，我们将涵盖以下主题：

+   装饰者模式

+   代理模式

+   使用 PostSharp 应用 AOP。

+   项目-横切关注点可重用库

通过本章结束时，您将具备以下技能：

+   实现装饰者模式。

+   实现代理模式。

+   使用 PostSharp 应用 AOP。

+   构建您自己的可重用 AOP 库，以解决您的横切关注点。

# 技术要求

要充分利用本章，您需要安装 Visual Studio 2019 和 PostSharp。有关本章的代码文件，请参阅[`github.com/PacktPublishing/Clean-Code-in-C-/tree/master/CH11`](https://github.com/PacktPublishing/Clean-Code-in-C-/tree/master/CH11)。让我们从装饰者模式开始。

# 装饰者模式

装饰者设计模式是一种结构模式，用于在不改变其结构的情况下向现有对象添加新功能。原始类被包装在装饰类中，并在运行时向对象添加新的行为和操作：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/adc0e574-a40d-4c5f-b12b-397bf35ff3b9.png)

`Component`接口及其包含的成员由`ConcreteComponent`类和`Decorator`类实现。`ConcreteComponent`实现了`Component`接口。`Decorator`类是一个实现`Component`接口并包含对`Component`实例的引用的抽象类。`Decorator`类是组件的基类。`ConcreteDecorator`类继承自`Decorator`类，并为组件提供装饰器。

我们将编写一个示例，将一个操作包装在`try`/`catch`块中。`try`和`catch`都将向控制台输出一个字符串。创建一个名为`CH10_AddressingCrossCuttingConcerns`的新.NET 4.8 控制台应用程序。然后，添加一个名为`DecoratorPattern`的文件夹。添加一个名为`IComponent`的新接口：

```cs
public interface IComponent {
   void Operation();
}
```

为了保持简单，我们的接口只有一个`void`类型的操作。现在我们已经有了接口，我们需要添加一个实现接口的抽象类。添加一个名为`Decorator`的新抽象类，它实现了`IComponent`接口。添加一个成员变量来存储我们的`IComponent`对象：

```cs
private IComponent _component;
```

存储`IComponent`对象的`_component`成员变量是通过构造函数设置的，如下所示：

```cs
public Decorator(IComponent component) {
    _component = component;
}
```

在上述代码中，构造函数设置了我们将要装饰的组件。接下来，我们添加我们的接口方法：

```cs
public virtual void Operation() {
    _component.Operation();
}
```

我们将`Operation()`方法声明为`virtual`，以便可以在派生类中重写它。现在，我们将创建我们的`ConcreteComponent`类，它实现`IComponent`：

```cs
public class ConcreteComponent : IComponent {
    public void Operation() {
        throw new NotImplementedException();
    }
}
```

如您所见，我们的类包括一个操作，它抛出`NotImplementedException`。现在，我们可以写关于`ConcreteDecorator`类：

```cs
public class ConcreteDecorator : Decorator {
    public ConcreteDecorator(IComponent component) : base(component) { }
}
```

`ConcreteDecorator`类继承自`Decorator`类。构造函数接受一个`IComponent`参数，并将其传递给基类构造函数，然后设置成员变量。接下来，我们将重写`Operation()`方法：

```cs
public override void Operation() {
    try {
        Console.WriteLine("Operation: try block.");
        base.Operation();
    } catch(Exception ex)  {
        Console.WriteLine("Operation: catch block.");
        Console.WriteLine(ex.Message);
    }
}
```

在我们重写的方法中，我们有一个`try`/`catch`块。在`try`块中，我们向控制台写入一条消息，并执行基类的`Operation()`方法。在`catch`块中，当遇到异常时，会写入一条消息，然后是错误消息。在我们可以使用我们的代码之前，我们需要更新`Program`类。将`DecoratorPatternExample()`方法添加到`Program`类中：

```cs
private static void DecoratorPatternExample() {
    var concreteComponent = new ConcreteComponent();
    var concreteDecorator = new ConcreteDecorator(concreteComponent);
    concreteDecorator.Operation();
}
```

在我们的`DecoratorPatternExample()`方法中，我们创建一个新的具体组件。然后，我们将其传递给一个新的具体装饰器的构造函数。然后，我们在具体装饰器上调用`Operation()`方法。将以下两行添加到`Main()`方法中：

```cs
DecoratorPatternExample();
Console.ReadKey();
```

这两行执行我们的示例，然后等待用户按键退出。运行代码，您应该看到与以下截图相同的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/664bec75-738c-4c02-b795-f06f6e2d0a52.png)

这就结束了我们对装饰器模式的讨论。现在，是时候来看看代理模式了。

# 代理模式

代理模式是一种结构设计模式，提供作为客户端使用的真实服务对象的替代对象。代理接收客户端请求，执行所需的工作，然后将请求传递给服务对象。代理对象可以与服务对象互换，因为它们共享相同的接口：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/7a2acc31-3b52-44c5-8ddf-421e7e7aba54.png)

您希望使用代理模式的一个例子是当您有一个您不想更改的类，但您需要添加额外的行为时。代理将工作委托给其他对象。除非代理是服务的派生类，否则代理方法应最终引用`Service`对象。

我们将看一个非常简单的代理模式实现。在您的`Chapter 11`项目的根目录下添加一个名为`ProxyPattern`的文件夹。添加一个名为`IService`的接口，其中包含一个处理请求的方法：

```cs
public interface IService {
    void Request();
}
```

`Request()`方法执行执行请求的工作。代理和服务都将实现这个接口来使用`Request()`方法。现在，添加`Service`类并实现`IService`接口：

```cs
public class Service : IService {
    public void Request() {
        Console.WriteLine("Service: Request();");
    }
}
```

我们的`Service`类实现了`IService`接口，并处理实际的服务`Request()`方法。这个`Request()`方法将被`Proxy`类调用。实现代理模式的最后一步是编写`Proxy`类：

```cs
public class Proxy : IService {
    private IService _service;

    public Proxy(IService service) {
        _service = service;
    }

    public void Request() {
        Console.WriteLine("Proxy: Request();");
        _service.Request();
    }
}
```

我们的`Proxy`类实现了`IService`，并具有一个接受单个`IService`参数的构造函数。客户端调用`Proxy`类的`Request()`方法。`Proxy.Request()`方法将执行所需的操作，并负责调用`_service.Request()`。为了看到这一点，让我们更新我们的`Program`类。在`Main()`方法中添加`ProxyPatternExample()`调用。然后，添加`ProxyPatternExample()`方法：

```cs
private static void ProxyPatternExample() {
    Console.WriteLine("### Calling the Service directly. ###");
    var service = new Service();
    service.Request();
    Console.WriteLine("## Calling the Service via a Proxy. ###");
    new Proxy(service).Request();
}
```

我们的测试方法运行`Service`类的`Request()`方法。然后，通过`Proxy`类的`Request()`方法运行相同的方法。运行项目，您应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/ff58bd4b-08a3-41b8-bdba-bef5e252a020.png)

现在您已经对装饰器和代理模式有了工作理解，让我们来看看使用 PostSharp 的 AOP。

# 使用 PostSharp 的 AOP

AOP 可以与 OOP 一起使用。**方面**是应用于类、方法、参数和属性的属性，在编译时，将代码编织到应用的类、方法、参数或属性中。这种方法允许程序的横切关注从业务源代码移动到类库中。关注点在需要时作为属性添加。然后编译器在运行时编织所需的代码。这使得您的业务代码保持简洁和可读。在本章中，我们将使用 PostSharp。您可以从[`www.postsharp.net/download`](https://www.postsharp.net/download)下载它。

那么，AOP 如何与 PostSharp 一起工作呢？

您需要将 PostSharp 包添加到项目中。然后，您可以使用属性对代码进行注释。C#编译器将您的代码构建成二进制代码，然后 PostSharp 分析二进制代码并注入方面的实现。尽管二进制代码在编译时被修改并注入了代码，但您的项目源代码保持不变。这意味着您可以保持代码的整洁、简洁，从而使长期内维护、重用和扩展现有代码库变得更加容易。

PostSharp 有一些非常好的现成模式供您利用。这些模式涵盖了**Model-View-ViewModel**（**MVVM**）、缓存、多线程、日志和架构验证等。但好消息是，如果没有符合您要求的内容，那么您可以通过扩展方面框架和/或架构框架来自动化自己的模式。

使用方面框架，您可以开发简单或复合方面，将其应用于代码，并验证其使用。至于架构框架，您可以开发自定义的架构约束。在我们深入研究横切关注之前，让我们简要地看一下如何扩展方面和架构框架。

在编写方面和属性时，您需要添加`PostSharp.Redist` NuGet 包。完成后，如果发现您的属性和方面不起作用，那么右键单击项目并选择添加 PostSharp 到项目。完成此操作后，您的方面应该可以工作。

## 扩展方面框架

在本节中，我们将开发一个简单的方面并将其应用于一些代码。然后，我们将验证我们方面的使用。

### 开发我们的方面

我们的方面将是一个由单个转换组成的简单方面。我们将从原始方面类派生我们的方面。然后，我们将重写一些称为**建议**的方法。如果您想知道如何创建复合方面，可以在[`doc.postsharp.net/complex-aspects`](https://doc.postsharp.net/complex-aspects)上阅读如何做到这一点。

#### 在方法执行前后注入行为

`OnMethodBoundaryAspect`方面实现了装饰器模式。您已经在本章前面看到了如何实现装饰器模式。通过这个方面，您可以在目标方法执行前后执行逻辑。以下表格提供了`OnMethodBoundaryAspect`类中可用的建议方法列表：

| **建议** | **描述** |
| --- | --- |
| `OnEntry(MethodExecutionArgs)` | 在方法执行开始时使用，用户代码之前。 |
| `OnSuccess(MethodExecutionArgs)` | 在方法执行成功（即没有异常返回）后使用，用户代码之后。 |
| `OnException(MethodExecutionArgs)` | 在方法执行失败并出现异常后使用，用户代码之后。相当于`catch`块。 |
| `OnExit(MethodExecutionArgs)` | 在方法执行退出时使用，无论成功与否或出现异常。此建议在用户代码之后以及当前方面的`OnSuccess(MethodExecutionArgs)`或`OnException(MethodExecutionArgs)`方法之后运行。相当于`finally`块。 |

对于我们简单的方面，我们将查看所有正在使用的方法。在开始之前，将 PostSharp 添加到您的项目中。如果您已经下载了 PostSharp，可以右键单击您的项目，然后选择添加 PostSharp 到项目。之后，添加一个名为`Aspects`的新文件夹到您的项目中，然后添加一个名为`LoggingAspect`的新类：

```cs
[PSerializable]
public class LoggingAspect : OnMethodBoundaryAspect { }
```

`[PSerializeable]`属性是一个自定义属性，当应用于类型时，会导致 PostSharp 生成一个供`PortableFormatter`使用的序列化器。现在，重写`OnEntry()`方法：

```cs
public override void OnEntry(MethodExecutionArgs args) {
    Console.WriteLine("The {0} method has been entered.", args.Method.Name);
}
```

`OnEntry()`方法在任何用户代码之前执行。现在，重写`OnSuccess()`方法：

```cs
public override void OnSuccess(MethodExecutionArgs args) {
    Console.WriteLine("The {0} method executed successfully.", args.Method.Name);
}
```

`OnSuccess()`方法在用户代码完成时执行。重写`OnExit()`方法：

```cs
public override void OnExit(MethodExecutionArgs args) {
    Console.WriteLine("The {0} method has exited.", args.Method.Name);
} 
```

`OnExit()`方法在用户方法成功或失败完成并退出时执行。它相当于一个`finally`块。最后，重写`OnException()`方法：

```cs
public override void OnException(MethodExecutionArgs args) { 
    Console.WriteLine("An exception was thrown in {0}.", args.Method.Name); 
}
```

`OnException()`方法在方法执行失败并出现异常时执行，执行在任何用户代码之后。它相当于一个`catch`块。

下一步是编写两个可以应用`LoggingAspect`的方法。我们将添加`SuccessfulMethod()`：

```cs
[LoggingAspect]
private static void SuccessfulMethod() {
    Console.WriteLine("Hello World, I am a success!");
}
```

`SuccessfulMethod()`使用`LoggingAspect`并在控制台上打印一条消息。现在，让我们添加`FailedMethod()`：

```cs
[LoggingAspect]
private static void FailedMethod() {
    Console.WriteLine("Hello World, I am a failure!");
    var x = 1;
    var y = 0;
    var z = x / y;
}
```

`FailedMethod()`使用`LoggingAspect`并在控制台上打印一条消息。然后，它执行了一个除零操作，导致`DivideByZeroException`。从您的`Main()`方法中调用这两种方法，然后运行您的项目。您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/2169d706-6075-45f7-a0c7-668e69855318.png)

此时，调试器将导致程序退出。就是这样。正如您所看到的，创建自己的 PostSharp 方面以满足您的需求是一个简单的过程。现在，我们将看看如何添加我们自己的架构约束。

## 扩展架构框架

架构约束是采用必须在所有模块中遵守的自定义设计模式。我们将实现一个标量约束，用于验证代码的元素。

我们的标量约束，称为`BusinessRulePatternValidation`，将验证从`BusinessRule`类派生的任何类必须具有名为`Factory`的嵌套类。首先添加`BusinessRulePatternValidation`类：

```cs
[MulticastAttributeUsage(MulticastTargets.Class, Inheritance = MulticastInheritance.Strict)] 
public class BusinessRulePatternValidation : ScalarConstraint { }
```

`MulticastAttributeUsage`指定此验证方面只能与允许类和继承的类一起使用。让我们重写`ValidateCode()`方法：

```cs
public override void CodeValidation(object target)  { 
    var targetType = (Type)target; 
    if (targetType.GetNestedType("Factory") == null) { 
        Message.Write( 
            targetType, SeverityType.Warning, 
            "10", 
            "You must include a 'Factory' as a nested type for {0}.", 
            targetType.DeclaringType, 
            targetType.Name); 
    } 
} 
```

我们的`ValidateCode()`方法检查目标对象是否具有嵌套的`Factory`类型。如果`Factory`类型不存在，则会向输出窗口写入异常消息。添加`BusinessRule`类：

```cs
 [BusinessRulePatternValidation]
 public class BusinessRule  { }
```

`BusinessRule`类是空的，没有`Factory`。它有我们分配给它的`BusinessRulePatternValidation`属性，这是一个架构约束。构建您的项目，您将在输出窗口中看到消息。我们现在将开始构建一个可重用的类库，您可以在自己的项目中扩展和使用它来解决横切关注点，使用 AOP 和装饰器模式。

# 项目-横切关注点可重用库

在本节中，我们将通过编写一个可重用库来解决各种横切关注点的问题。它的功能有限，但它将为您提供进一步扩展项目所需的知识。您将创建的类库将是一个.NET 标准库，以便可以用于同时针对.NET Framework 和.NET Core 的应用程序。您还将创建一个.NET Framework 控制台应用程序，以查看库的运行情况。

首先创建一个名为`CrossCuttingConcerns`的新.NET 标准类库。然后，在解决方案中添加一个名为`TestHarness`的.NET Framework 控制台应用程序。我们将添加可重用的功能来解决各种问题，从缓存开始。

## 添加缓存关注点

**缓存**是一种用于提高访问各种资源时性能的存储技术。使用的缓存可以是内存、文件系统或数据库。您使用的缓存类型将取决于项目的需求。为了演示，我们将使用内存缓存来保持简单。

在`CrossCuttingConcerns`项目中添加一个名为`Caching`的文件夹。然后，添加一个名为`MemoryCache`的类。向项目添加以下 NuGet 包：

+   `PostSharp`

+   `PostSharp.Patterns.Common`

+   `PostSharp.Patterns.Diagnostics`

+   `System.Runtime.Caching`

使用以下代码更新`MemoryCache`类：

```cs
public static class MemoryCache {
    public static T GetItem<T>(string itemName, TimeSpan timeInCache, Func<T> itemCacheFunction) {
        var cache = System.Runtime.Caching.MemoryCache.Default;
        var cachedItem = (T) cache[itemName];
        if (cachedItem != null) return cachedItem;
        var policy = new CacheItemPolicy {AbsoluteExpiration = DateTimeOffset.Now.Add(timeInCache)};
        cachedItem = itemCacheFunction();
        cache.Set(itemName, cachedItem, policy);
        return cachedItem;
    }
}
```

“GetItem（）”方法接受缓存项的名称`itemName`，缓存项保留在缓存中的时间长度`timeInCache`，以及在将项目放入缓存时调用的函数`itemCacheFunction`。在`TestHarness`项目中添加一个新类，命名为`TestClass`。然后，添加“GetCachedItem（）”和“GetMessage（）”方法，如下所示：

```cs
public string GetCachedItem() {
    return MemoryCache.GetItem<string>("Message", TimeSpan.FromSeconds(30), GetMessage);
}

private string GetMessage() {
    return "Hello, world of cache!";
}
```

“GetCachedItem（）”方法从缓存中获取名为`"Message"`的字符串。如果它不在缓存中，那么它将由“GetMessage（）”方法存储在缓存中 30 秒。

在`Program`类中更新您的“Main（）”方法，调用“GetCachedItem（）”方法，如下所示：

```cs
var harness = new TestClass();
Console.WriteLine(harness.GetCachedItem());
Console.WriteLine(harness.GetCachedItem());
Thread.Sleep(TimeSpan.FromSeconds(1));
Console.WriteLine(harness.GetCachedItem());
```

第一次调用“GetCachedItem（）”将项目存储在缓存中，然后返回它。第二次调用从缓存中获取项目并返回它。睡眠线程使缓存无效，因此最后一次调用在返回项目之前将项目存储在缓存中。

## 添加文件日志功能

在我们的项目中，日志记录、审计和仪表化过程将它们的输出发送到文本文件。因此，我们需要一个类来管理如果文件不存在则添加文件，然后将输出添加到这些文件并保存它们。在类库中添加一个名为`FileSystem`的文件夹。然后，添加一个名为`LogFile`的类。将该类设置为`public static`，并添加以下成员变量：

```cs
private static string _location = string.Empty;
private static string _filename = string.Empty;
private static string _file = string.Empty;
```

_location 变量被分配为条目程序集的文件夹。_filename 变量被分配为带有文件扩展名的文件名。我们需要在运行时添加`Logs`文件夹（如果不存在）。因此，我们将在`FileSystem`类中添加“AddDirectory（）”方法：

```cs
private static void AddDirectory() {
    if (!Directory.Exists(_location))
        Directory.CreateDirectory("Logs");
}
```

“AddDirectory（）”方法检查位置是否存在。如果不存在，则创建该目录。接下来，我们需要处理如果文件不存在则添加文件的情况。因此，添加“AddFile（）”方法：

```cs
private static void AddFile() {
    _file = Path.Combine(_location, _filename);
    if (File.Exists(_file)) return;
    using (File.Create($"Logs\\{_filename}")) {

    }
}
```

在“AddFile（）”方法中，我们将位置和文件名组合在一起。如果文件名已经存在，那么我们退出方法；否则，我们创建文件。如果我们不使用`using`语句，当我们创建我们的第一条记录时，我们将遇到`IOException`，但随后的保存将会很好。因此，通过使用`using`语句，我们避免了异常并记录了数据。现在我们可以编写一个实际将数据保存到文件的方法。添加“AppendTextToFile（）”方法：

```cs
public static void AppendTextToFile(string filename, string text) {
    _location = $"{Path.GetDirectoryName(Assembly.GetEntryAssembly()?.Location)}\\Logs";
    _filename = filename;
    AddDirectory();
    AddFile();
    File.AppendAllText(_file, text);
}
```

“AppendTextToFile（）”方法接受文件名和文本，并将位置设置为条目程序集的位置。然后，它确保文件和目录存在。然后，它将文本保存到指定的文件中。现在我们已经处理了文件日志功能，现在我们可以继续查看我们的日志关注。

## 添加日志关注

大多数应用程序都需要某种形式的日志记录。通常的日志记录方法是控制台、文件系统、事件日志和数据库。在我们的项目中，我们只关注控制台和文本文件日志记录。在类库中添加一个名为`Logging`的文件夹。然后，添加一个名为`ConsoleLoggingAspect`的文件，并更新如下：

```cs
[PSerializable]
public class ConsoleLoggingAspect : OnMethodBoundaryAspect { }
```

`[PSerializable]` 属性通知 PostSharp 生成一个供 `PortableFormatter` 使用的序列化器。`ConsoleLoggingAspect` 继承自 `OnMethodBoundaryAspect`。`OnMethodBoundaryAspect` 类有我们可以重写的方法，以在方法主体执行之前、之后、成功执行时以及遇到异常时添加代码。我们将重写这些方法以向控制台输出消息。当涉及调试时，这可能是一个非常有用的工具，以查看代码是否实际被调用，以及它是否成功完成或遇到异常。我们将从重写 `OnEntry()` 方法开始：

```cs
public override void OnEntry(MethodExecutionArgs args) {
    Console.WriteLine($"Method: {args.Method.Name}, OnEntry().");
}
```

`OnEntry()` 方法在我们的方法体执行之前执行，并且我们的重写打印出已执行的方法的名称和它自己的名称。接下来，我们将重写 `OnExit()` 方法：

```cs
public override void OnExit(MethodExecutionArgs args) {
    Console.WriteLine($"Method: {args.Method.Name}, OnExit().");
}
```

`OnExit()` 方法在我们的方法体执行完成后执行，并且我们的重写打印出已执行的方法的名称和它自己的名称。现在，我们将添加 `OnSuccess()` 方法：

```cs
public override void OnSuccess(MethodExecutionArgs args) {
    Console.WriteLine($"Method: {args.Method.Name}, OnSuccess().");
}
```

`OnSuccess()` 方法在应用于方法的主体完成并且没有异常返回后执行。当我们的重写执行时，它打印出已执行的方法的名称和它自己的名称。我们将要重写的最后一个方法是 `OnException()` 方法：

```cs
public override void OnException(MethodExecutionArgs args) {
    Console.WriteLine($"An exception was thrown in {args.Method.Name}. {args}");
}
```

`OnException()` 方法在遇到异常时执行，在我们的重写中，我们打印出方法的名称和参数对象的名称。要应用属性，请使用 `[ConsoleLoggingAspect]`。要添加文本文件日志记录方面，添加一个名为 `TextFileLoggingAspect` 的类。`TextFileLoggingAspect` 与 `ConsoleLoggingAspect` 相同，除了重写方法的内容。`OnEntry()`、`OnExit()` 和 `OnSuccess()` 方法调用 `LogFile.AppendTextToFile()` 方法，并将内容附加到 `Log.txt` 文件中。`OnException()` 方法也是一样，只是它将内容附加到 `Exception.log` 文件中。这是 `OnEntry()` 的示例：

```cs
public override void OnEntry(MethodExecutionArgs args) {
    LogFile.AppendTextToFile("Log.txt", $"\nMethod: {args.Method.Name}, OnEntry().");
}
```

这就是我们的日志记录处理完毕。现在，我们将继续添加我们的异常处理关注。

## 添加异常处理关注

在软件中，用户将不可避免地遇到异常。因此，需要一些方法来记录它们。记录异常的常规方式是将错误存储在用户系统上的文件中，例如 `Exception.log`。这就是我们将在本节中做的。我们将继承自 `OnExceptionAspect` 类，并将我们的异常数据写入 `Exception.log` 文件中，该文件将位于我们应用程序的 `Logs` 文件夹中。`OnExceptionAspect` 将标记的方法包装在 `try`/`catch` 块中。在类库中添加一个名为 `Exceptions` 的新文件夹，然后添加一个名为 `ExceptionAspect` 的文件，其中包含以下代码：

```cs
[PSerializable]
public class ExceptionAspect : OnExceptionAspect {
    public string Message { get; set; }
    public Type ExceptionType { get; set; }
    public FlowBehavior Behavior { get; set; }

    public override void OnException(MethodExecutionArgs args) {
        var message = args.Exception != null ? args.Exception.Message : "Unknown error occured.";
        LogFile.AppendTextToFile(
            "Exceptions.log", $"\n{DateTime.Now}: Method: {args.Method}, Exception: {message}"
        );
        args.FlowBehavior = FlowBehavior.Continue;
    }

    public override Type GetExceptionType(System.Reflection.MethodBase targetMethod) {
        return ExceptionType;
    }
}
```

`ExceptionAspect` 类被分配了 `[PSerializable]` 方面，并继承自 `OnExceptionAspect`。我们有三个属性：`message`、`ExceptionType` 和 `FlowBehavior`。`message` 包含异常消息，`ExceptionType` 包含遇到的异常类型，`FlowBehavior` 决定异常处理后是否继续执行或者进程是否终止。`GetExceptionType()` 方法返回抛出的异常类型。`OnException()` 方法首先构造错误消息。然后通过调用 `LogFile.AppendTextToFile()` 将异常记录到文件中。最后，异常行为的流程被设置为继续。

要使用 `[ExceptionAspect]` 方面的唯一要做的就是将其作为属性添加到您的方法中。我们现在已经涵盖了异常处理。所以，我们将继续添加我们的安全性关注。

## 添加安全性关注

安全需求将针对正在开发的项目而具体。最常见的问题是用户是否经过身份验证并获得授权访问和使用系统的各个部分。在本节中，我们将使用装饰器模式实现具有基于角色的方法的安全组件。

安全本身是一个非常庞大的主题，超出了本书的范围。有许多优秀的 API，例如各种 Microsoft API。有关更多信息，请参阅[`docs.microsoft.com/en-us/dotnet/standard/security/`](https://docs.microsoft.com/en-us/dotnet/standard/security/)，有关 OAuth 2.0，请参阅[`oauth.net/code/dotnet/`](https://oauth.net/code/dotnet/)。我们将让您选择并实现自己的安全方法。在本章中，我们只是使用装饰器模式添加了我们自己定义的安全性。您可以将其用作实现任何前述安全方法的基础。

新增一个名为`Security`的文件夹，并为其添加一个名为`ISecureComponent`的接口：

```cs
public interface ISecureComponent {
    void AddData(dynamic data);
    int EditData(dynamic data);
    int DeleteData(dynamic data);
    dynamic GetData(dynamic data);
}
```

我们的安全组件接口包含前面的四种方法，这些方法都是不言自明的。`dynamic`关键字意味着可以将任何类型的数据作为参数传递，并且可以从`GetData()`方法返回任何类型的数据。接下来，我们需要一个实现接口的抽象类。添加一个名为`DecoratorBase`的类，如下所示：

```cs
public abstract class DecoratorBase : ISecureComponent {
    private readonly ISecureComponent _secureComponent;

    public DecoratorBase(ISecureComponent secureComponent) {
        _secureComponent = secureComponent;
    }
}
```

`DecoratorBase`类实现了`ISecureComponent`。我们声明了一个`ISecureComponent`类型的成员变量，并在默认构造函数中设置它。我们需要添加`ISecureComponent`的缺失方法。添加`AddData()`方法：

```cs
public virtual void AddData(dynamic data) {
    _secureComponent.AddData(data);
}
```

此方法将接受任何类型的数据，然后将其传递给`_secureComponent`的`AddData()`方法。为`EditData()`、`DeleteData()`和`GetData()`添加缺失的方法。现在，添加一个名为`ConcreteSecureComponent`的类，该类实现了`ISecureComponent`。对于每个方法，向控制台写入一条消息。对于`DeleteData()`和`EditData()`方法，还返回一个值`1`。对于`GetData()`，返回`"Hi!"`。`ConcreteSecureComponent`类是执行我们感兴趣的安全工作的类。

我们需要一种验证用户并获取其角色的方法。在执行任何方法之前，将检查角色。因此，添加以下结构：

```cs
public readonly struct Credentials {
    public static string Role { get; private set; }

    public Credentials(string username, string password) {
        switch (username)
        {
            case "System" when password == "Administrator":
                Role = "Administrator";
                break;
            case "End" when password == "User":
                Role = "Restricted";
                break;
            default:
                Role = "Imposter";
                break;
        }
    }
}
```

为了保持简单，该结构接受用户名和密码，并设置适当的角色。受限用户的权限比管理员少。我们安全问题的最终类是`ConcreteDecorator`类。添加如下类：

```cs
public class ConcreteDecorator : DecoratorBase {
    public ConcreteDecorator(ISecureComponent secureComponent) : base(secureComponent) { }
}
```

`ConcreteDecorator`类继承自`DecoratorBase`类。我们的构造函数接受`ISecureComponent`类型，并将其传递给基类。添加`AddData()`方法：

```cs
public override void AddData(dynamic data) {
    if (Credentials.Role.Contains("Administrator") || Credentials.Role.Contains("Restricted")) {
        base.AddData((object)data);
    } else {
        throw new UnauthorizedAccessException("Unauthorized");
    }
}
```

`AddMethod()`检查用户的角色是否与允许的`Administrator`和`Restricted`角色匹配。如果用户属于这些角色之一，则在基类中执行`AddData()`方法；否则，抛出`UnauthorizedAccessException`。其他方法遵循相同的模式。重写其他方法，但确保`DeleteData()`方法只能由管理员执行。

现在，让我们开始处理安全问题。在`Program`类的顶部添加以下行：

```cs
private static readonly ConcreteDecorator ConcreteDecorator = new ConcreteDecorator(
    new ConcreteSecureComponent()
);
```

我们声明并实例化一个具体的装饰器对象，并传入具体的安全对象。此对象将在我们的数据方法中引用。更新`Main()`方法，如下所示：

```cs
private static void Main(string[] _) {
    // ReSharper disable once ObjectCreationAsStatement
    new Credentials("End", "User");
    DoSecureWork();
    Console.WriteLine("Press any key to exit.");
    Console.ReadKey();
}
```

我们将用户名和密码分配给`Credentials`结构。这将导致设置`Role`。然后调用`DoWork()`方法。`DoWork()`方法将负责调用数据方法。然后暂停等待用户按任意键并退出。添加`DoWork()`方法：

```cs
private static void DoSecureWork() {
    AddData();
    EditData();
    DeleteData();
    GetData();
}
```

`DoSecureWork()`方法调用每个调用具体装饰器上的数据方法的数据方法。添加`AddData()`方法：

```cs
[ExceptionAspect(consoleOutput: true)]
private static void AddData() {
    ConcreteDecorator.AddData("Hello, world!");
}
```

`[ExceptionAspect]`应用于`AddData()`方法。这将确保任何错误都被记录到`Exceptions.log`文件中。参数设置为`true`，因此错误消息也将打印在控制台窗口中。方法本身调用`ConcreteDecorator`类的`AddData()`方法。按照相同的步骤添加其余的方法。然后运行你的代码。你应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/847bde47-fa68-4381-aba1-0c89cd4987ae.png)

现在我们有一个可以工作的基于角色的对象，包括异常处理。我们的下一步是实现验证关注点。

## 添加验证关注点

所有用户输入的数据都应该经过验证，因为它可能是恶意的、不完整的或格式错误的。您需要确保您的数据是干净的，不会造成伤害。对于我们的演示关注点，我们将实现空值验证。首先，在类库中添加一个名为`Validation`的文件夹。然后，添加一个名为`AllowNullAttribute`的新类：

```cs
[AttributeUsage(AttributeTargets.Parameter | AttributeTargets.ReturnValue | AttributeTargets.Property)]
public class AllowNullAttribute : Attribute { }
```

该属性允许参数、返回值和属性上的空值。现在，将`ValidationFlags`枚举添加到同名的新文件中：

```cs
[Flags]
public enum ValidationFlags {
    Properties = 1,
    Methods = 2,
    Arguments = 4,
    OutValues = 8,
    ReturnValues = 16,
    NonPublic = 32,
    AllPublicArguments = Properties | Methods | Arguments,
    AllPublic = AllPublicArguments | OutValues | ReturnValues,
    All = AllPublic | NonPublic
}
```

这些标志用于确定方面可以应用于哪些项。接下来，我们将添加一个名为`ReflectionExtensions`的类：

```cs
public static class ReflectionExtensions {
    private static bool IsCustomAttributeDefined<T>(this ICustomAttributeProvider value) where T 
        : Attribute  {
        return value.IsDefined(typeof(T), false);
    }

    public static bool AllowsNull(this ICustomAttributeProvider value) {
        return value.IsCustomAttributeDefined<AllowNullAttribute>();
    }

    public static bool MayNotBeNull(this ParameterInfo arg) {
        return !arg.AllowsNull() && !arg.IsOptional && !arg.ParameterType.IsValueType;
    }
}
```

`IsCustomAttributeDefined()`方法在该成员上定义了该属性类型时返回`true`，否则返回`false`。`AllowsNull()`方法在已应用`[AllowNull]`属性时返回`true`，否则返回`false`。`MayNotBeNull()`方法检查是否允许空值，参数是否可选，以及参数的值类型。然后通过对这些值进行逻辑`AND`操作来返回一个布尔值。现在是时候添加`DisallowNonNullAspect`了：

```cs
[PSerializable]
public class DisallowNonNullAspect : OnMethodBoundaryAspect {
    private int[] _inputArgumentsToValidate;
    private int[] _outputArgumentsToValidate;
    private string[] _parameterNames;
    private bool _validateReturnValue;
    private string _memberName;
    private bool _isProperty;

    public DisallowNonNullAspect() : this(ValidationFlags.AllPublic) { }

    public DisallowNonNullAspect(ValidationFlags validationFlags) {
        ValidationFlags = validationFlags;
    }

    public ValidationFlags ValidationFlags { get; set; }
}
```

该类应用了`[PSerializable]`属性，以通知 PostSharp 为`PortableFormatter`生成序列化程序。它还继承了`OnMethodBoundaryAspect`类。然后，我们声明变量来保存经过验证的参数名称、返回值验证和成员名称，并检查被验证的项是否是属性。默认构造函数配置为允许验证器应用于所有公共成员。我们还有一个构造函数，它接受一个`ValidationFlags`值和一个`ValidationFlags`属性。现在，我们将重写`CompileTimeValidate()`方法：

```cs
public override bool CompileTimeValidate(MethodBase method) {
    var methodInformation = MethodInformation.GetMethodInformation(method);
    var parameters = method.GetParameters();

    if (!ValidationFlags.HasFlag(ValidationFlags.NonPublic) && !methodInformation.IsPublic) return false;
    if (!ValidationFlags.HasFlag(ValidationFlags.Properties) && methodInformation.IsProperty) 
        return false;
    if (!ValidationFlags.HasFlag(ValidationFlags.Methods) && !methodInformation.IsProperty) return false;

    _parameterNames = parameters.Select(p => p.Name).ToArray();
    _memberName = methodInformation.Name;
    _isProperty = methodInformation.IsProperty;

    var argumentsToValidate = parameters.Where(p => p.MayNotBeNull()).ToArray();

    _inputArgumentsToValidate = ValidationFlags.HasFlag(ValidationFlags.Arguments) ? argumentsToValidate.Where(p => !p.IsOut).Select(p => p.Position).ToArray() : new int[0];

    _outputArgumentsToValidate = ValidationFlags.HasFlag(ValidationFlags.OutValues) ? argumentsToValidate.Where(p => p.ParameterType.IsByRef).Select(p => p.Position).ToArray() : new int[0];

    if (!methodInformation.IsConstructor) {
        _validateReturnValue = ValidationFlags.HasFlag(ValidationFlags.ReturnValues) &&
                                            methodInformation.ReturnParameter.MayNotBeNull();
    }

    var validationRequired = _validateReturnValue || _inputArgumentsToValidate.Length > 0 || _outputArgumentsToValidate.Length > 0;

    return validationRequired;
}
```

该方法确保在编译时正确应用了该方面。如果该方面应用于错误类型的成员，则返回`false`。否则，返回`true`。现在我们将重写`OnEntry()`方法：

```cs
public override void OnEntry(MethodExecutionArgs args) {
    foreach (var argumentPosition in _inputArgumentsToValidate) {
        if (args.Arguments[argumentPosition] != null) continue;
        var parameterName = _parameterNames[argumentPosition];

        if (_isProperty) {
            throw new ArgumentNullException(parameterName, 
                $"Cannot set the value of property '{_memberName}' to null.");
        } else {
            throw new ArgumentNullException(parameterName);
        }
    }
}
```

该方法检查*输入参数*进行验证。如果任何参数为`null`，则会抛出`ArgumentNullException`；否则，该方法将在不抛出异常的情况下退出。现在让我们重写`OnSuccess()`方法：

```cs
public override void OnSuccess(MethodExecutionArgs args) {
    foreach (var argumentPosition in _outputArgumentsToValidate) {
        if (args.Arguments[argumentPosition] != null) continue;
        var parameterName = _parameterNames[argumentPosition];
        throw new InvalidOperationException($"Out parameter '{parameterName}' is null.");
    }

    if (!_validateReturnValue || args.ReturnValue != null) return;

    if (_isProperty) {
        throw new InvalidOperationException($"Return value of property '{_memberName}' is null.");
    }
    throw new InvalidOperationException($"Return value of method '{_memberName}' is null.");
}
```

`OnSuccess()`方法验证*输出参数*。如果任何参数为 null，则会抛出`InvalidOperationException`。接下来我们需要做的是添加一个用于提取方法信息的`private class`。在`DisallowNonNullAspect`类的结束大括号之前，添加以下类：

```cs
private class MethodInformation { }
```

将以下三个构造函数添加到`MethodInformation`类中：

```cs
 private MethodInformation(ConstructorInfo constructor) : this((MethodBase)constructor) {
     IsConstructor = true;
     Name = constructor.Name;
 }

 private MethodInformation(MethodInfo method) : this((MethodBase)method) {
     IsConstructor = false;
     Name = method.Name;
     if (method.IsSpecialName &&
     (Name.StartsWith("set_", StringComparison.Ordinal) ||
     Name.StartsWith("get_", StringComparison.Ordinal))) {
         Name = Name.Substring(4);
         IsProperty = true;
     }
     ReturnParameter = method.ReturnParameter;
 }

 private MethodInformation(MethodBase method)
 {
     IsPublic = method.IsPublic;
 }
```

这些构造函数区分构造函数和方法，并对方法进行必要的初始化。添加以下方法：

```cs
private static MethodInformation CreateInstance(MethodInfo method) {
    return new MethodInformation(method);
}
```

`CreateInstance()`方法根据传入的方法的`MethodInfo`数据创建`MethodInformation`类的新实例，并返回该实例。添加`GetMethodInformation()`方法：

```cs
public static MethodInformation GetMethodInformation(MethodBase methodBase) {
    var ctor = methodBase as ConstructorInfo;
    if (ctor != null) return new MethodInformation(ctor);
    var method = methodBase as MethodInfo;
    return method == null ? null : CreateInstance(method);
}
```

该方法将`methodBase`转换为`ConstructorInfo`并检查是否为`null`。如果`ctor`不为`null`，则基于构造函数生成一个新的`MethodInformation`类。但是，如果`ctor`为`null`，则将`methodBase`转换为`MethodInfo`。如果方法不为`null`，则调用`CreateInstance()`方法，传入该方法。否则，返回`null`。最后，将以下属性添加到类中：

```cs
public string Name { get; private set; }
public bool IsProperty { get; private set; }
public bool IsPublic { get; private set; }
public bool IsConstructor { get; private set; }
public ParameterInfo ReturnParameter { get; private set; }
```

这些属性是应用了该方面的方法的属性。我们现在已经完成了编写验证方面。您现在可以使用验证器通过附加`[AllowNull]`属性来允许空值。您可以通过附加`[DisallowNonNullAspect]`来禁止空值。现在，我们将添加事务关注点。

## 添加事务关注点

事务是必须要完成或回滚的过程。在类库中添加一个名为`Transactions`的新文件夹，然后添加`RequiresTransactionAspect`类：

```cs
[PSerializable]
[AttributeUsage(AttributeTargets.Method)]
public sealed class RequiresTransactionAspect : OnMethodBoundaryAspect {
    public override void OnEntry(MethodExecutionArgs args) {
        var transactionScope = new TransactionScope(TransactionScopeOption.Required);
        args.MethodExecutionTag = transactionScope;
    }

    public override void OnSuccess(MethodExecutionArgs args) {
        var transactionScope = (TransactionScope)args.MethodExecutionTag;
        transactionScope.Complete();
    }

    public override void OnExit(MethodExecutionArgs args) {
        var transactionScope = (TransactionScope)args.MethodExecutionTag;
        transactionScope.Dispose();
    }
}
```

`OnEntry()`方法启动事务，`OnSuccess()`方法完成异常，`OnExit()`方法处理事务。要使用该方面，请在您的方法中添加`[RequiresTransactionAspect]`。要记录任何阻止事务完成的异常，还可以分配`[ExceptionAspect(consoleOutput: false)]`方面。接下来，我们将添加资源池关注点。

## 添加资源池关注点

资源池是在创建和销毁对象的多个实例昂贵时提高性能的好方法。我们将为我们的需求创建一个非常简单的资源池。添加一个名为`ResourcePooling`的文件夹，然后添加`ResourcePool`类：

```cs
public class ResourcePool<T> {
    private readonly ConcurrentBag<T> _resources;
    private readonly Func<T> _resourceGenerator;

    public ResourcePool(Func<T> resourceGenerator) {
        _resourceGenerator = resourceGenerator ??
                                 throw new ArgumentNullException(nameof(resourceGenerator));
        _resources = new ConcurrentBag<T>();
    }

    public T Get() => _resources.TryTake(out T item) ? item : _resourceGenerator();
    public void Return(T item) => _resources.Add(item);
}
```

该类创建一个新的资源生成器，并将资源存储在`ConcurrentBag`中。当请求项目时，它会从池中发出一个资源。如果不存在，则会创建一个并将其添加到池中，并发放给调用者：

```cs
var pool = new ResourcePool<Course>(() => new Course()); // Create a new pool of Course objects.
var course = pool.Get(); // Get course from pool.
pool.Return(course); // Return the course to the pool.
```

您刚刚看到的代码向您展示了如何使用`ResourcePool`类来创建资源池，获取资源并将其返回到资源池中。

## 添加配置设置关注点

配置设置应始终集中。由于桌面应用程序将其设置存储在`app.config`文件中，而 Web 应用程序将其设置存储在`Web.config`文件中，因此我们可以使用`ConfigurationManager`来访问应用程序设置。将`System.Configuration.Configuration` NuGet 库添加到您的类库中并测试测试工具。然后，添加一个名为`Configuration`的文件夹和以下`Settings`类：

```cs
public static class Settings {
    public static string GetAppSetting(string key) {
        return System.Configuration.ConfigurationManager.AppSettings[key];
    }

    public static void SetAppSettings(this string key, string value) {
        System.Configuration.ConfigurationManager.AppSettings[key] = value;
    }
}
```

该类将在`Web.config`文件和`App.config`文件中获取和设置应用程序设置。要在您的文件中包含该类，请添加以下`using`语句：

```cs
using static CrossCuttingConcerns.Configuration.Settings;
```

以下代码向您展示了如何使用这些方法：

```cs
Console.WriteLine(GetAppSetting("Greeting"));
"Greeting".SetAppSettings("Goodbye, my friends!");
Console.WriteLine(GetAppSetting("Greeting"));
```

使用静态导入，您无需包含`class`前缀。您可以扩展`Settings`类以获取连接字符串或在应用程序中执行所需的任何配置。

## 添加仪器化关注点

我们的最终横切关注点是仪器化。我们使用仪器化来分析我们的应用程序，并查看方法执行所需的时间。在类库中添加一个名为`Instrumentation`的文件夹，然后添加`InstrumentationAspect`类，如下所示：

```cs

[PSerializable]
[AttributeUsage(AttributeTargets.Method)]
public class InstrumentationAspect : OnMethodBoundaryAspect {
    public override void OnEntry(MethodExecutionArgs args) {
        LogFile.AppendTextToFile("Profile.log", 
            $"\nMethod: {args.Method.Name}, Start Time: {DateTime.Now}");
        args.MethodExecutionTag = Stopwatch.StartNew();
    }

    public override void OnException(MethodExecutionArgs args) {
        LogFile.AppendTextToFile("Exception.log", 
            $"\n{DateTime.Now}: {args.Exception.Source} - {args.Exception.Message}");
    }

    public override void OnExit(MethodExecutionArgs args) {
        var stopwatch = (Stopwatch)args.MethodExecutionTag;
        stopwatch.Stop();
        LogFile.AppendTextToFile("Profile.log", 
            $"\nMethod: {args.Method.Name}, Stop Time: {DateTime.Now}, Duration: {stopwatch.Elapsed}");
    }
}
```

正如您所看到的，仪器化方面仅适用于方法，记录方法的开始和结束时间，并将配置文件信息记录到`Profile.log`文件中。如果遇到异常，则将异常记录到`Exception.log`文件中。

我们现在拥有一个功能齐全且可重用的横切关注点库。让我们总结一下本章学到的内容。

# 总结

我们学到了一些宝贵的信息。我们首先看了装饰器模式，然后是代理模式。代理模式提供了作为客户端使用的真实服务对象的替代品。代理接收客户端请求，执行必要的工作，然后将请求传递给服务对象。由于代理与它们替代的服务共享相同的接口，它们是可互换的。

在介绍了代理模式之后，我们转向了使用 PostSharp 进行 AOP。我们看到了如何将切面和属性一起使用来装饰代码，以便在编译时注入代码来执行所需的操作，例如异常处理、日志记录、审计和安全性。我们通过开发自己的切面来扩展了切面框架，并研究了如何使用 PostSharp 和装饰器模式来解决配置管理、日志记录、审计、安全性、验证、异常处理、仪器化、事务、资源池、缓存、线程和并发的横切关注点。

在下一章中，我们将看看使用工具来帮助您提高代码质量。但在那之前，测试一下您的知识，然后继续阅读。

# 问题

1.  什么是横切关注点，AOP 代表什么？

1.  什么是切面，如何应用切面？

1.  什么是属性，如何应用属性？

1.  切面和属性如何一起工作？

1.  切面如何与构建过程一起工作？

# 进一步阅读

+   PostSharp 主页：[`www.postsharp.net/`](https://www.postsharp.net/download)
