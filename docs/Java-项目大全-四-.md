# Java 项目大全（四）

> 原文：[JAVA PROJECTS](https://libgen.rs/book/index.php?md5=C751311C3F308045737DA4CD071BA359)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 七、使用 REST 构建商业 Web 应用

我们一直在玩，但 Java 不是玩具。我们希望使用 Java 来实现真正的、严肃的、商业的和专业的。在这一章中，我们将这样做。我们将要看的例子不是我们在前三章中所看到的，只是有趣的东西，比如 Mastermind，而是一个真正的商业应用。实际上，这不是一个真实的应用。你不应该指望书中有这样的东西。它太长了，教育不够。但是，我们将在本章中开发的应用可以扩展，并且可以作为实际应用的核心，以防您决定这样做。

在上一章中，我们创建了 Servlet。为此，我们使用了 Servlet 规范，并手工实现了 Servlet。这是你现在很少做的事。在本章中，我们将使用一个现成的框架。这次，我们将使用 Spring，它是 Java 商业应用中使用最广泛的框架，我敢说它是事实上的标准。它将完成上一章中我们必须完成的所有繁琐工作（至少是为了理解和学习 Servlet 的工作原理）。我们还将使用 Spring 进行依赖注入（为什么要使用两个框架，而一个框架可以完成所有工作？），还有 Tomcat。

在前一章中，我们使用 Guice 作为 DI 框架，Jetty 作为 Servlet 容器。对于一些项目，这些都是非常好的选择。对于其他项目，其他框架做得更好。为了有机会查看本书中的不同工具，我们将使用不同的框架，尽管我们将展示的所有示例都可以通过仅使用 Tomcat 和 Spring 来创建。

我们将开发的商业应用将是一个针对经销商的订购系统。我们将提供给用户的界面将不是一个 Web 浏览器可消费的 HTML/JavaScript/CSS 界面。相反，它将是一个 REST 接口。用户将自行开发与我们的系统通信的应用，并为不同的产品下订单。应用的结构将是一个微服务架构，除了标准的 Chrome 开发工具特性之外，我们还将使用 SoapUI 来测试应用。

# MyBusiness 网上商店

想象一下，我们有一个庞大的贸易和物流公司。货架上有上万种不同的产品；数百辆卡车带着新的货物来到我们的仓库，数百辆卡车为我们的客户送货。为了管理这些信息，我们有一个库存系统，它每分钟、每小时、每天跟踪货物，以便我们知道仓库里实际有什么。我们为客户提供服务，而无需人工管理仓库信息。以前，有电话，传真机，甚至电传。今天，我们使用的只是互联网和网络服务。我们不为客户提供网站。我们从未在想象中的业务中直接为最终用户服务，但现在，我们有一个子公司，我们作为一个独立的公司开始这样做。他们有一个网站，完全独立于我们。他们只是我们数百个注册合作伙伴中的一个，他们每个人都使用 Web 服务接口/界面来查看我们拥有的产品、订购产品和跟踪订单状态。

# 业务架构示例

我们的合作伙伴也是具有自动化管理的大型公司，在多台机器上运行多个程序。我们对他们的架构和使用的技术不感兴趣，但我们希望与他们的业务相结合。我们希望以一种不需要任何人际互动的方式为他们提供服务，以便政府向我们任何一方订货。为此，提供了一个 Web 服务接口，无论他们使用什么 IT 基础设施，都可以使用它。

在我们这边，正如我们想象的例子，我们最近用 microservice 架构替换了我们的单片应用，尽管系统中仍然有一些基于 SOAP 的解决方案，但是大多数后端模块使用 HTTPS 和 REST 协议进行通信。一些模块仍然依赖于每天使用 FTP 进行的异步文件传输，FTP 是从 Unix 作业开始的。总账系统是用 COBOL 语言编写的。幸运的是，我们不需要对付这些恐龙。

这个结构是一个虚构的设置，但一个现实的。我编写并描述这些部分是为了让您了解如何在大型企业中看到混合技术。我在这里描述的是一个非常简单的设置。有些公司的系统中有一千多个软件模块，使用不同的技术和完全不同的接口，所有这些模块都相互连接。这并不是因为他们喜欢这种混乱，而是因为经过 30 年的持续发展，这种混乱才变得如此。新技术来了，旧技术也消失了。业务发生了变化，如果你想保持竞争力，就不能固守旧技术。同时，您无法立即替换整个基础结构。其结果是，我们看到相当老的技术仍然在运行，而且主要是新技术。旧技术得到及时推广。它们不会永远呆在这里，而且，当恐龙出现在我们面前时，我们有时会感到惊讶。

我们必须处理我们将要开发的两个前端组件。具体如下：

*   **产品信息**
*   **下单跟踪**

在下面的图片中，您可以看到我们将要看到的结构的架构 UML 图。我们将只与前端组件进行交互，但如果我们有更大的了解，这有助于了解它们的功能和作用：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/6b6b271c-bbbd-4792-a49e-1911d61f150f.png)

**产品信息**提供单个产品的信息，也可以根据查询条件提供产品列表。**下单跟踪**提供了客户下单的功能，也可以让我们的客户查询过去订单的状态。

要提供产品信息，我们需要访问保存实际产品详细信息的**产品目录**模块。

**产品目录**可以执行许多其他任务，这就是为什么它是一个单独的模块。例如，它可以有一个工作流和批准引擎，让产品管理员输入产品数据，让经理检查和批准数据。审批通常是一个复杂的过程，考虑到打字错误和法律问题（我们不想交易未经许可的毒品、爆炸物等），并检查货物来源的质量和审批状态。许多复杂的任务使它成为后端模块。在大型企业应用中，前端系统除了为外部服务的基本功能外，很少做其他任何事情。但这对我们有好处；我们可以专注于我们必须提供的服务。这对架构也有好处。这与面向对象编程中的单一责任原则相同。

**产品信息**模块还要咨询**门禁**模块，看某个产品能不能送到实际客户手中，再跟库存一起看有没有剩余的产品，这样我们才不会提供一个缺货的产品。

**下单跟踪**模块还需要访问**产品库存**和**访问控制**模块，检查订单是否可以完成。同时，它还需要来自**定价**模块的服务，该模块可以计算订单的价格，以及来自**物流**模块的服务，该模块触发从库存位置收集货物并将货物发送给客户。**物流**也与发票有关联，发票与**总账**有关联，但这些只是在图片上显示信息的旅行并没有到此为止。有许多其他模块运行公司，所有这些都不是我们目前感兴趣的。

# 微服务

上一章中描述的架构不是一个干净的微服务架构。在任何事业中，你都不会遇到一个纯粹的人。它更像是我们在一个真正的公司里遇到的东西，从单片到微服务。

当应用以许多小型服务的形式开发时，我们将讨论微服务架构，这些服务使用一些简单的 API（通常通过 HTTP 和 REST）相互通信。这些服务实现业务功能，可以独立部署。在大多数情况下，希望服务部署是自动化的。

各个服务可以使用不同的编程语言开发，可以使用不同的数据存储，并且可以在不同的操作系统上运行；因此，它们彼此高度独立。它们可以而且通常是由不同的团队开发的。重要的要求是它们相互协作；因此，一个服务实现的 API 可以被构建在它之上的其他服务使用。

微服务架构并不是所有架构中的圣杯。它对单片架构的一些问题给出了不同的答案，在大多数情况下，这些答案在使用现代工具时效果更好。这些应用还需要测试和调试。性能必须得到管理，错误和问题必须得到解决。不同之处在于，各个组件之间没有强耦合，这样，开发、部署和测试就可以沿着不同的技术进行分离。由于微服务架构在实践中沿着网络协议将模块分开，调试可能需要更多与网络相关的工作。这可能是好的，也可能是坏的，或者两者兼而有之。然而，对于开发商来说，优势是显而易见的。他们可以独立地在较小的单元上工作，并且可以更快地看到工作的结果。

在开发单片应用的单个模块时，只有在部署整个应用时才能看到结果。在大型应用的情况下，这可能很少见。在开发单片电路的大型公司中，一个典型的部署周期是每隔几个月，比如说三个月，但是一年只发布两次甚至一次的情况并不少见。开发微服务时，只要新模块没有破坏它提供给我们的网络接口和其他模块使用的网络接口，只要它准备好并经过测试，就可以部署它。

如果你想阅读更多关于微服务的文章，第一个也是最真实的来源是 [martinfowler 的文章](http://www.martinfowler.com/articles/microservices.html)。请注意，此页面引用了微服务资源指南，其中列出了许多微服务信息资源。

# 服务接口设计

在本节中，我们将设计要实现的两个接口。在设计接口时，我们首先关注功能。格式和协议稍后提供。接口，一般来说，应该是简单的，同时，适应未来的变化。这是一个困难的问题，因为我们看不到未来。商业、物流和所有其他专家可能会看到未来世界的某些部分将如何变化，以及它将对公司的运营，特别是我们为合作伙伴提供的接口带来什么影响。

接口的稳定性是最重要的，因为合作伙伴是外部实体。我们无法重构它们使用的代码。当我们在代码中更改 Java 接口时，编译器将在所有应该遵循更改的代码位置抱怨。如果是在我们的领域之外使用的接口，情况并非如此。即使我们在 *GitHub* 上发布为开源的 Java 接口，我们也应该做好准备，如果我们以不兼容的方式更改库，用户也会面临问题。在这种情况下，他们的软件将不会编译和与我们的库一起工作。如果是订购系统，这意味着他们不会从我们那里订购，我们很快就会倒闭。

这就是为什么接口应该简单的原因之一。虽然这通常适用于生活中的大多数事情，但对于接口来说却是极其重要的。为合作伙伴提供方便的特性是很有诱惑力的，因为它们易于实现。但是，从长远来看，这些特性可能会变得非常昂贵，因为它们需要维护；它们应该保持向后兼容。从长远来看，他们可能得不到成本那么多。

要访问产品信息，我们需要两个函数。其中一个列出特定产品，另一个返回特定产品的详细信息。如果它是 Java API，则如下所示：

```java
List<ProductId> query(String query);
ProductInformation byId(ProductId id);
```

类似地，订单安排可能类似于以下代码所示：

```java
OrderId placeOrder(Order order);
```

我们通过 Web 服务接口在应用中提供这些函数；更具体地说，REST 使用 JSON。我们将更详细地讨论这些技术，以及 Spring 框架和模型-视图-控制器设计模式，但首先，让我们看看产品信息控制器，以了解我们的程序将是什么样子：

```java
package packt.java11.mybusiness.productinformation;
import ...
@RestController
public class ProductInformationController {
    private final ProductLookup lookup;

    public ProductInformationController(
            @Autowired ProductLookup lookup) {
        this.lookup = lookup;
    }

    @RequestMapping("/pi/{productId}")
    public ProductInformation getProductInformation(
            @PathVariable String productId) {
        return lookup.byId(productId);
    }

    @RequestMapping("/query/{query}")
    public List<String> lookupProductByTitle(
            @PathVariable String query,
            HttpServletRequest request) {
        return lookup.byQuery(query)
                .stream().map(s -> "/pi/" + s)
                .collect(Collectors.toList());
    }
}
```

如果将 Servlet 的代码与前面的代码进行比较，您会发现这要简单得多。我们不需要处理`HttpServletRequest`对象，不需要调用 API 来获取参数，也不需要创建 HTML 输出并将其写入响应。框架就是这样做的。我们对`@RestController`类进行注解，告诉 Spring 这是一个利用 RESTWeb 服务的控制器；因此，它将从我们默认返回的对象创建一个 **JSON** 响应。我们不需要关心对象到 *JSON* 的转换，尽管如果确实需要的话我们可以。对象将使用类中使用的字段名和返回的实例的字段值自动转换为 *JSON*。如果对象包含比普通的`String`、`int`和`double`值更复杂的结构，那么转换器将为嵌套结构和最常见的数据类型做好准备。

为了在 Servlet 上有不同的代码处理和不同的 URL，我们需要做的就是用`@RequestMapping`注解方法，提供 URL 的路径部分。映射字符串中的`{productId}`符号可读且易于维护。Spring 只是从那里切下值，然后按照`@PathVariable`注解的要求，将其放入`productId`变量中。

控制器中未实现产品的实际查找。这不是控制器的功能。控制器只决定调用什么业务逻辑和使用什么视图。业务逻辑在服务类中实现。这个服务类的一个实例被注入到`lookup`字段中。这种注射也是由 Spring 完成的。我们要做的实际工作是调用业务逻辑，这一次，因为我们只有一个，是相当容易的。

如果没有更多关于框架为我们做了什么的细节，大多数这些东西看起来都很神奇。因此，在继续之前，我们将先看看构建块 JSON、REST、MVC 和一些 Spring 框架。

# JSON 文件

**JSON** 代表 **JavaScript 对象表示法**。在[官方 JSON 网站](http://www.json.org/)上定义。这是一种文本表示法，与 JavaScript 中定义对象文本的方式相同。对象表示以`{`字符开始，以`}`字符结束。中间的文本定义了表单`string : value`中对象的字段。字符串是字段的名称，由于 JSON 希望语言不可知，因此它允许任何字符作为字段名称的一部分，因此该字符串（以及 JSON 中的任何字符串）应以`"`字符开头和结尾。

这可能看起来很奇怪，在大多数情况下，当您开始使用 JSON 时，很容易忘记并编写`{ myObject : "has a string"}`而不是正确的`{ "myObject" : "has a string" }`符号。

逗号分隔字段。也可以使用 JSON 格式的数组。它们分别以`[`和`]`字符开头和结尾，并且包含逗号分隔的值。对象字段或数组中的值可以是字符串、数字、对象、数组或常量之一，`true`、`false`和`null`。

一般来说，JSON 是一种非常简单的表示法，用于描述可以存储在对象中的数据。使用文本编辑器编写和阅读都很容易，因此调试使用 JSON 的通信比调试使用复杂格式的通信更容易。在我们将在本章中使用的库中，可以很容易地找到将 JSON 转换为 Java 对象的方法，反之亦然。程序的源代码中还提供了一个示例 JSON 对象，该对象描述了我们示例代码中的产品，如下所示：

```java
{"id":"125","title":"Bar Stool",
 "description":"another furniture",
 "size":[20.0,2.0,18.0],"weight":300.0}
```

请注意，JSON 的格式化不需要新行，但同时，这也是可能的。程序生成的 JSON 对象通常是紧凑的，没有格式化。当我们使用文本编辑器编辑一个对象时，我们倾向于像在 Java 编程中一样格式化字段的缩进。

# REST

**REST** 协议没有确切的定义。它代表**表述性状态转移**，对于一个从未听说过它的人来说，这可能并不意味着什么。当我们编写 RestAPI 时，我们使用 HTTP（S）协议。我们向服务器发送简单的请求，然后得到我们编写的简单答案。这样，Web 服务器的客户端也是一个程序（顺便说一下，浏览器也是一个程序），它使用来自服务器的响应。因此，响应的格式不是使用 CSS 的 HTML 格式，也不是通过 **JavaScript** 的客户端函数来丰富的，而是一些数据描述格式，比如 JSON。REST 没有对实际的格式设置限制，但是现在，JSON 是使用最广泛的格式。

描述 REST 的 wiki 页面位于[这个页面](https://en.wikipedia.org/wiki/Representational_state_transfer)。

REST 接口通常很简单。HTTP 请求几乎总是使用`GET`方法。它还使 REST 服务的测试变得简单，因为没有什么比从浏览器发出一个`GET`请求更容易的了。幼儿能做到。`POST`只有当服务在服务器上执行某些事务或更改时，才使用请求，这样，请求是向服务器发送数据，而不是获取一些数据。

在我们的应用中，我们将使用`GET`方法来查询产品列表并获取有关产品的信息，并且我们将只使用`POST`来订购产品。为这些请求提供服务的应用将在 Servlet 容器中运行。您已经学习了如何在不使用框架的情况下创建裸 Servlet。在本章中，我们将使用 Spring 框架，它从开发人员那里卸载了许多任务。Servlet 编程中有许多程序构造在大多数情况下都是相同的。它们被称为样板代码。Spring 框架使用模型-视图-控制器设计模式来开发 Web 应用；因此，在讨论 Spring 之前，我们将对其进行简要介绍。

# 模型视图控制器

**模型视图控制器**（**MVC**）是一种设计模式。设计模式是编程构造的简单结构，给出如何解决特定问题的提示。设计模式一词是在 Erich Gamma、Richard Helm、Ralph Johnson 和 John Vlissides 所著的《设计模式，可重用面向对象软件的元素》一书中提出并正式描述的。本书将设计模式定义为具有*名称*、*问题*和*解决方案*的结构。*名称*描述了模式，并给出了开发人员社区在谈论这些模式时可以使用的词汇表。不同的开发人员使用相同的语言术语以便相互理解是很重要的。*问题*描述了这种情况，即可以应用模式的设计问题。*解决方案*描述类和对象以及它们之间的关系，这有助于一个好的设计。

其中之一是 MVC，它适用于 Web 应用的编程，但通常可以用于任何具有用户界面的应用。在我们的例子中，我们没有经典的用户界面，因为客户端也是一个程序；不过，MVC 可以而且是一个很好的选择：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/394a6111-5277-4b1d-93c0-c1334912bd78.png)

MVC 模式，顾名思义，有三个部分：模型、视图和控制器。这种分离遵循单一责任原则，要求每个不同的责任有一个部分。控制器负责处理系统的输入，并决定使用什么模型和视图。它控制执行，但通常不执行任何业务逻辑。模型执行业务逻辑并包含数据。视图将模型数据转换为客户端可以使用的表示形式。

MVC 是一种广泛使用的设计模式，它直接由 Spring 支持。当您创建一个 Web 应用时，您可以通过使用注解对框架中内置的控制器进行编程。基本上就是配置它。您可以对视图进行编程，但更有可能使用内置到框架中的视图。您将希望以 **XML**、**JSON** 或 **HTML** 格式向客户端发送数据。如果你很有异国情调，你可能会想发送 **YAML**，但一般来说，就是这样。您不希望实现需要在服务器上编程的新格式，因为它是新的，所以也需要在客户端上编程。

我们创建了模型，这一次，我们还编写了程序。毕竟，这是业务逻辑。框架可以为我们做很多事情，主要是对大多数应用来说都是一样的，但对业务逻辑来说却不一样。业务逻辑是将我们的代码与其他程序区别开来的代码。这就是我们要规划的。

另一方面，这正是我们喜欢做的，关注业务代码，避免框架提供的所有样板文件。

既然我们知道了什么是 **JSON**、**REST**，以及通用的模型-视图-控制器设计模式，那么让我们看看 Spring 是如何管理它们的，以及如何将这些技术付诸实现。

# Spring 框架

Spring 框架是一个包含多个模块的巨大框架。该框架的第一个版本是在 2003 年发布的，从那时起，已经有四个主要版本提供了新的和增强的特性。目前，Spring 是实际使用的企业框架，可能比法律标准 EJB3.0 更广泛。

Spring 支持依赖注入、**面向切面编程**（**AOP**）、对 **SQL** 和 **NoSQL** 数据库的持久化等传统方式和对象关系映射方式。它具有事务支持、消息传递、Web 编程和许多其他特性。您可以使用 **XML** 配置文件、注解或 Java 类来配置它。

# Spring 的架构

Spring 不是整体的。你可以使用它的一部分，或者只使用一些功能。您可以包含一些您需要的 Spring 模块，而忽略其他模块。一些模块依赖于其他模块，Gradle、Maven 或其他一些构建工具处理依赖关系。

下图显示了版本 4 的 Spring 框架的模块：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/26140f41-bd71-4b94-9c60-624ad141a68a.png)

Spring 自第一次发布以来一直在不断发展，它仍然被认为是一个现代框架。框架的核心是一个依赖注入容器，类似于我们在前面一章中看到的容器。随着框架的发展，它还支持 AOP 和许多其他企业功能，例如面向消息的模式和通过模型视图控制器实现的 Web 编程，不仅支持 Servlet，还支持 Portlet 和 WebSocket。由于 Spring 针对企业应用领域，因此它还支持以多种不同的方式处理数据库。支持 JDBC 使用模板、**对象关系映射**（**ORM**），以及事务管理。

在这个示例程序中，我们将使用一个相当新的模块 SpringBoot。这个模块使得编写和运行应用非常容易，假设许多程序的配置通常是相同的。它包含一个嵌入的 Servlet 容器，它为默认设置进行配置，并在可能的情况下配置 Spring，以便我们可以关注编程方面，而不是 Spring 配置。

# Spring 核心

核心模块的中心元素是上下文。当 Spring 应用启动时，容器需要一个上下文，容器可以在其中创建不同的 bean。这对于任何依赖注入容器来说都是非常普遍和正确的。如果我们以编程方式创建两个不同的上下文，它们可能在同一个 JVM 中彼此独立地存在。如果有一个 bean 被声明为单例，因此它应该只有一个实例，那么当我们需要它时，容器将为上下文创建一个实例。表示上下文的对象引用了我们已经创建的对象。但是，如果有多个上下文，他们将不知道 JVM 中有另一个已经有实例的上下文，容器将为另一个上下文创建一个新的单例 bean 实例。

通常，我们不会在一个程序中使用多个上下文，但是在一个 JVM 中存在多个上下文的例子有很多。当不同的 Servlet 运行在同一个 Servlet 容器中时，它们运行在同一个 JVM 中，由类加载器分隔，并且它们可以各自使用 Spring。在这种情况下，上下文将属于 Servlet，并且每个 Servlet 都有一个新的上下文。

在上一章中，我们使用了 Guice。Spring 上下文类似于 Guice 注入器。在上一章中，我有点作弊，因为我正在编程 Guice 为每个请求创建一个新的注入器。这远不是最佳的，Guice 提供了一个可以处理 Servlet 环境的注入器实现。作弊的原因是我想把更多的精力放在 DI 架构的基础上，我不想通过引入一个复杂的（更复杂的）注入器实现来使代码复杂化。

Spring 上下文行为由接口`ApplicationContext`定义。这个接口有两个扩展和许多实现。`ConfigurableApplicationContext`扩展`ApplicationContext`，定义设置器，`ConfigurableWebApplicationContext`定义 Web 环境中需要的方法。当我们编写 Web 应用时，通常不需要直接干扰上下文。该框架以编程方式配置 Servlet 容器，它包含用于创建上下文和调用方法的 Servlet。这是为我们创建的所有样板代码。

上下文跟踪已创建的 bean，但不创建它们。要创建 bean，我们需要 bean 工厂或至少一个工厂。Spring 中的 bean 工厂是实现接口`BeanFactory`的类。这是 Spring 中 bean 工厂类型层次结构的最顶层接口。bean 只是一个对象，所以 bean 工厂只是创建一个类的新实例。但是，它还必须将这个新对象注册到上下文中，bean 还应该有一个名称，即`String`。这样，程序和其中的 Spring 就可以通过名称引用 bean。

在 Spring 中，可以用几种不同的方式配置不同的 bean。最古老的方法是创建一个描述不同 bean 的 XML 文件，指定名称、创建 bean 必须实例化的类，以及 bean 需要注入其他 bean 才能创建的字段。

这种方法背后的动机是，通过这种方式，bean 布线和配置可以完全独立于应用代码。它成为一个可以单独维护的配置文件。

例如，我们可能有一个在多个不同环境中工作的大型应用。在我们的示例中，可以通过多种方式访问库存数据。在一种环境中，清单可以通过调用 SOAP 服务来获得。在另一个环境中，可以在 SQL 数据库中访问数据。在第三种环境中，它可以在一些 NoSQL 存储中使用。这些访问中的每一个都实现为一个单独的类，实现一个公共的库存访问接口。应用代码只依赖于接口，而容器提供了一个或另一个实现。

当 bean 连接的配置是 XML 格式时，那么只需要编辑这个 XML 文件，并且代码可以从实现适合特定环境的接口开始。

下一种可能是使用注解配置 bean。在大多数情况下，使用 Spring 的原因是将对象创建与功能分离。在这种情况下，bean 可能只有一个实现。仍然使用 Spring，实际代码使用为依赖注入提供的框架更干净。另一方面，外部 XML 将将配置从需要配置的代码中移开。在这种情况下，可以控制 bean 创建和注入的注解作为代码中的声明工作。

当只有一个实现是冗余的时，XML 配置。为什么我要在 XML 配置中指定我希望通过实现该接口的程序的单个类获得该接口的实例？这是非常明显的，而且不能以任何其他方式，因此这是实现接口的唯一类。我们不喜欢键入不提供新信息的内容。

为了表示类可以用作 bean，并可能提供名称，我们可以使用`@Component`注解。我们不需要提供名称作为参数。在这种情况下，名称将是一个空字符串，但是如果我们不引用它，为什么还要有一个名称呢？Spring 扫描类路径上的所有类并识别已注解的类，它知道这些类是用于 bean 创建的候选类。当一个组件需要注入另一个 bean 时，可以使用`@Autowired`或`@Inject`对该字段进行注解。`@Autowired`注解是 Spring 注解，在`@Inject`注解标准化之前就已经存在。如果要在 Spring 容器之外使用代码，建议使用标准注解。在功能上，它们是等价的。

在我们的代码中，当 Spring 创建一个`ProductInformationController`组件的实例时，它似乎需要一个`ProductLookup`的实例。这是一个接口，因此，Spring 开始寻找实现这个接口的类，然后创建它的一个实例，可能首先创建其他 bean，然后容器注入它，设置字段。您可以决定注解字段的设置器而不是字段本身。在这种情况下，Spring 将调用设置器，即使设置器是`private`。可以通过构造器参数注入依赖项。设置器、字段注入和构造器注入之间的主要区别在于，在使用构造器注入的情况下，不能创建没有依赖关系的 bean。当 bean 被实例化时，它应该并且将要注入所有其他 bean，以便它依赖于使用构造器注入。同时，需要通过设置器注入或直接注入到字段中的依赖项可以稍后由容器在实例化类和准备 bean 之间的某个时间实例化。

在构造器代码变得比简单的依赖项设置更复杂之前，或者在依赖项变得更复杂之前，这种细微的差异可能看起来并不有趣或重要。对于复杂的构造器，代码应该注意对象没有完全创建。这通常适用于任何构造器代码，但对于依赖项注入容器创建的 bean，通过直接字段访问或通过设置器注入注入依赖项，这一点更为重要。建议使用构造器注入来确保存在依赖项。如果程序员犯了一个错误，忘记了对象没有完全初始化，并在构造器或方法中使用它，而方法本身是从构造器中调用的，那么依赖关系就已经存在了。此外，使用构造器初始化依赖项并声明那些字段`final`更简洁、结构更完善。

另一方面，构造器注入也有其缺点。

如果不同的对象相互依赖，并且依赖关系图中有一个环，那么如果使用构造器依赖关系，Spring 将很困难。当类`A`需要类`B`反过来作为最简单的圆时，如果依赖注入是构造器依赖，那么`A`和`B`都不能没有他者而创建。在这样的情况下，不能使用构造器注入，应该将循环分解为至少一个依赖项。在这种情况下，塞特注射是不可避免的。

当存在可选依赖项时，设置器注入也可能更好。在大多数情况下，一个类可能不需要同时使用它的所有依赖项。有些类可以使用数据库连接或 NoSQL 数据库句柄，但不能同时使用两者。尽管这也可能是一种代码味道，可能是 OO 设计糟糕的标志，但它可能会发生。这可能是一个深思熟虑的决定，因为纯 OO 设计会导致太深的对象层次结构和太多的类，超出可维护的限制。如果是这种情况，那么使用设置器注入可以更好地处理可选的依赖关系。有的配置设置，有的留有默认值，通常是`null`。

最后但同样重要的是，我们可以使用 Java 类来配置容器，以防注解不够。例如，在我们的代码库中，`ProductLookup`接口有多种实现。（如果您不知道，请不要担心；我还没有告诉您）有一个`ResourceBasedProductLookup`类从包中读取属性文件，主要用于测试应用，还有一个`RestClientProductLookup`，它是一个类似于产品的接口实现。如果我除了用`@Autowired`注解`lookup`字段外，没有其他配置，Spring 将不知道使用哪个实现，并在启动时向用户奖励以下错误消息：

```java
Error starting ApplicationContext. To display the auto-configuration report re-run your application with 'debug' enabled.
2023-11-03 07:25:01.217 ERROR 51907 --- [  restartedMain] o.s.b.d.LoggingFailureAnalysisReporter   :  

***************************
APPLICATION FAILED TO START
***************************

Description:

Parameter 0 of constructor in packt.java9.by.example.mybusiness.productinformation.ProductInformationController required a single bean, but 2 were found:
        - resourceBasedProductLookup: defined in file [/.../sources/ch07/productinformation/build/classes/main/packt/java9/by/example/mybusiness/productinformation/lookup/ResourceBasedProductLookup.class]
        - restClientProductLookup: defined in file [/.../sources/ch07/productinformation/build/classes/main/packt/java9/by/example/mybusiness/productinformation/lookup/RestClientProductLookup.class]

Action:

Consider marking one of the beans as @Primary, updating the consumer to accept multiple beans, or using @Qualifier to identify the bean that should be consumed
```

这是一个相当不言自明的错误消息；它告诉我们很多。现在，我们可以用 XML 来配置 bean，但同时，我们也可以用 Java 来配置它。

许多开发人员并不是第一次明白这一点。我也不明白。整个 XML 配置是将配置与代码分开。它创造了这样一种可能性：系统管理员更改配置，可以自由选择某个接口的一个或其他实现，将应用连接在一起。现在，Spring 告诉我最好还是回到编程方式？

同时，多年来我都听到有人担心 XML 实际上并不比 Java 代码好。XML 编写本质上是编程，除了工具和 IDE 支持对 XML 的支持不如对 Java 代码的支持（后者近年来开发了很多，尽管这是针对 SpringXML 配置的）。

要理解从 XML 返回 Java 代码的概念，我们必须回到 XML 配置方式的纯粹原因和目的。

SpringXML 配置的主要优点不是格式不是编程的，而是配置代码与应用代码分离。如果我们用 Java 编写配置，并将这些配置类保持在最低限度，并且它们保持原样，那么应用与配置代码的分离仍然存在。我们只是将配置的格式从 XML 更改为 Java。优点很多。其中一个是，在编辑时，IDE 可以识别类的名称，我们可以用 Java 自动补全（注意，在一些 IDE 中使用 XML 来利用插件的一些扩展时，这也起作用）。对于 Java，IDE 支持无处不在。Java 比 XML 更具可读性。好吧，这是一个品味的问题，但是我们大多数人更喜欢 Java 而不是 XML。

系统管理员还可以编辑 Java 代码。当他们编辑 XML 配置时，通常必须从 JAR 或 WAR 文件中提取它，编辑它，然后再次打包存档。在 Java 编辑的情况下，他们还必须发出一个`gradle war`命令或类似的命令。对于在服务器上运行 Java 应用的系统管理员来说，这不应该是一个阻碍。再说一遍，这不是 Java 编程。它只是编辑一些 Java 代码文件并替换一些类名文本和字符串常量。

我们在示例应用代码中遵循这种方法。我们在应用中有两个配置文件：一个用于本地部署和测试，另一个用于生产。`@Profile`注解指定配置应该使用哪个概要文件。在执行代码时，可以在命令行上将概要文件指定为系统属性，如下所示：

```java
$ gradle -Dspring.profiles.active=local bootRun
```

配置类用`@Configuration`注解。豆子工厂的方法被注解为`@Bean`：

```java
package packt.java11.mybusiness.productinformation;

import ...

@Configuration
@Profile("local")
public class SpringConfigurationLocal {

    @Bean
    @Primary
    public ProductLookup productLookup() {
        return new ResourceBasedProductLookup();
    }

    @Bean
    public ProductInformationServiceUrlBuilder urlBuilder() {
        return null;
    }
}
```

bean 工厂只返回实现了`ProductLookup`接口的`ResourceBasedProductLookup`类的一个新实例。当没有可依赖的外部服务时，此实现可用于运行应用进行本地测试。这个实现从打包到 JAR 应用的本地资源文件中读取产品数据。

配置的生产版本差别不大，但正如预期的那样，还有一些东西需要配置：

```java
package packt.java11.mybusiness.productinformation;
import ...
@Configuration
@Profile("production")
public class SpringConfiguration {

    @Bean
    @Primary
    public ProductLookup productLookup() {
        return new RestClientProductLookup(urlBuilder());
    }

    @Bean
    public ProductInformationServiceUrlBuilder urlBuilder() {
        return new ProductInformationServiceUrlBuilder("http://localhost");
    }
}
```

这个版本的`ProductLookup`服务类使用外部 REST 服务来检索它将呈现给客户端的数据。为此，它需要这些服务的 URL。通常应该配置这样的 URL。在我们的示例中，我们实现了一个可以动态计算这些 URL 的解决方案。我试图虚构一个现实生活中可能需要的情境，但所有的推理都被扭曲了，我放弃了。真正的原因是，通过这种方式，我们可以看到包含需要注入另一个 bean 的 bean 的代码。现在需要注意的是，`ProductInformationServiceUrlBuilder`实例 bean 的定义方式与`ProductLookup`bean 相同，当需要注入`ProductLookup`bean 的构造器时，使用的是它的定义 bean 方法，而不是直接使用下面的表达式：

```java
new ProductInformationServiceUrlBuilder("http://localhost");
```

后者可能有效，但不是在所有情况下都有效，我们不应该使用它。基于这些原因，我们将在下一节讨论 AOP 和 Spring 时返回。

另外，请注意，不需要定义接口来定义 bean。bean 方法返回的类型也可以是类。上下文将使用适合所需类型的方法，如果有多个合适的类型，并且配置不够精确，正如我们所看到的，容器将记录一个错误，并且不会工作。

在服务于本地概要文件的配置中，我们将为`ProductInformationServiceBuilder`创建一个`null`值。这是因为当我们使用本地测试时不需要它。另外，如果调用这个类中的任何方法，它将是一个错误。应尽快检测到错误；因此，`null`值是一个简单合理的选择。一个更好的选择是，如果调用了任何方法，bean 都会抛出一个特定的异常。这样，您就可以看到一个特定的异常，以及被测试代码想要调用的方法，而不是空指针异常。

`ProductInformationServiceUrlBuilder`类非常简单：

```java
package packt.java11.mybusiness.productinformation;

public class ProductInformationServiceUrlBuilder {
    private final String baseUrl;

    public ProductInformationServiceUrlBuilder(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String url(String service) {
        final String serviceUrl;
        switch (service) {
            case "pi":
                serviceUrl = baseUrl + ":8081/product/{id}";
                break;
            case "query":
                serviceUrl = baseUrl + ":8081/query/{query}";
                break;
            case "inventory":
                serviceUrl = baseUrl + ":8083/inventory/{id}";
                break;
            default:
                serviceUrl = null;
                break;
        }
        return serviceUrl;
    }
}
```

这个 bean 还需要一个构造器参数，我们在配置中使用了字符串常量。这清楚地表明，可以使用一个简单的对象初始化一些依赖项（什么会阻止我们？毕竟它是纯 Java，但它可能会阻碍某些 Spring 特性的工作。

# 服务类

我们有两个服务类。这些类为控制器提供数据并实现业务逻辑，不管它们有多简单。其中一个服务类实现对基于 REST 的服务的调用，而另一个服务类从属性文件中读取数据。后者可用于在应用脱机时对其进行测试。在生产环境中使用调用 REST 服务的服务。它们都实现了`ProductLookup`接口：

```java
package packt.java11.mybusiness.productinformation;
import java.util.List;
public interface ProductLookup {
    ProductInformation byId(String id);
    List<String> byQuery(String query);
}
```

`ResourceBasedProductLookup`将整个数据库存储在一个名为`products`的映射中。当调用其中一个服务方法时，它将从属性文件中填充。`private`方法`loadProducts`在每个服务方法启动时都会被调用，但只有在尚未加载的情况下才会加载数据：

```java
package packt.java11.mybusiness.productinformation.lookup;
import ...

@Service
public class ResourceBasedProductLookup implements ProductLookup {
```

该类使用`@Service`进行注解。此注解实际上等同于`@Component`注解。这只是同一注解的替代名称。Spring 还处理`@Component`注解，因此，如果使用`@Component`注解对注解接口进行注解，那么该注解还可以用来表示类是 Spring 组件。如果您想要更好的可读性，您可以编写自己的注解接口，声明类不是简单的组件，而是其他一些特殊类型。

例如，启动 IDE 并导航到`ResourceBasedProductLookup`类中的`fromProperties()`方法：

```java
private ProductInformation fromProperties(Properties properties) {
    final ProductInformation pi = new ProductInformation();
    pi.setTitle(properties.getProperty("title"));
    pi.setDescription(properties.getProperty("description"));
    pi.setWeight(Double.parseDouble(properties.getProperty("weight")));
    pi.getSize()[0] = Double.parseDouble(properties.getProperty("width"));
    pi.getSize()[1] = Double.parseDouble(properties.getProperty("height"));
    pi.getSize()[2] = Double.parseDouble(properties.getProperty("depth"));
    return pi;
}
```

`fromProperties()`方法创建`ProductInformation`实例，并用`Properties`对象中给出的参数填写。

`Properties`类是一种古老而广泛使用的类型。虽然有更多的现代格式和类，但它仍然被广泛使用，您很可能会遇到这个类。这就是我们在这里使用它的原因。

`ProductInformation`是一个简单的“数据传输对象”（DTO），其中不包含逻辑-仅包含字段，设置器和获取器。 它还包含一个常量`emptyProductInformation`，其中包含对具有空值的类的实例的引用。

`Properties`对象类似于`Map`对象。它包含分配给`String`键的`String`值。我们将在示例中看到，有一些方法可以帮助程序员从所谓的属性文件中加载一个`Properties`对象。这样的文件通常有`.properties`扩展名，它包含以下格式的键值对：

```java
key=value
```

例如，`123.properties`文件包含以下内容：

```java
id=123
title=Fundamentals of Java18.9
description=a new book to learn Java11
weight=300
width=20
height=2
depth=18
```

`properties`文件用于存储简单的配置值，并且几乎只用于包含特定于语言的常量。这是一个非常扭曲的用法，因为`properties`文件是 **ISO Latin-1** 编码的文件，如果您需要使用一些特殊的 UTF-8 字符，您必须使用`uXXXX`格式或使用 native2ascii 转换器程序来键入它们。不能简单地将它们保存为 UTF-8。不过，这是该格式用于程序国际化的特定于语言的字符串的文件（也缩写为 i18n，因为国际化一词的起始 i 和最后 n 之间有 18 个字符）。

为了得到`Properties`对象，我们必须读取项目中的文件，并将它们打包成 JAR 文件。Spring 类`PathMatchingResourcePatternResolver`帮助我们这样做。

天哪，是的，我知道！当我们使用 Spring 时，我们必须习惯这些长名称。无论如何，这种长而描述性的名称在企业环境中被广泛使用，并且需要它们来解释类的功能。

我们声明在测试期间包含所有产品的映射：

```java
final private Map<String, ProductInformation> products = new HashMap<>();
```

关键是产品 ID，在我们的示例中是一个字符串。这些值是我们使用`fromProperties`方法填充的`ProductInformation`对象。

下一个字段表示产品未加载：

```java
private boolean productsAreNotLoaded = true;
```

新手程序员通常使用名为`productsAreLoaded`的相反值，默认设置为`false`。在这种情况下，我们将读取一个值的唯一位置将否定该值，`if`命令的主分支将成为不执行任何操作部分。两者都不是最佳实践。

```java
private void loadProducts() {
    if (productsAreNotLoaded) {
        try {
            Resource[] resources =
                new PathMatchingResourcePatternResolver()
                    .getResources("classpath:products/*.properties");
            for (Resource resource : resources) {
                loadResource(resource);
            }
            productsAreNotLoaded = false;
        } catch (IOException ex) {
            log.error("Test resources can not be read", ex);
        }
    }
}
```

`getResources()`方法返回`products`目录下类路径上的所有资源（文件），扩展名为`.properties`

```java
private void loadResource(Resource resource) throws IOException {
    final int dotPos = resource.getFilename().lastIndexOf('.');
    final String id = resource.getFilename().substring(0, dotPos);
    Properties properties = new Properties();
    properties.load(resource.getInputStream());
    final ProductInformation pi = fromProperties(properties);
    pi.setId(id);
    products.put(id, pi);
}
```

产品 ID 由文件名提供。这是使用简单的字符串操作计算的，切断了扩展名。`Resource`还可以提供一个输入流，`Properties`类的`load`方法可以使用它一次加载所有属性。最后，我们将新的`ProductInformation`对象保存在映射中。

我们还有一个特别的`noProduct`列表是空的。当我们要搜索产品时，如果没有用于查询的产品，则返回：

```java
private static final List<String> noProducts = new LinkedList<>();
```

产品查找服务只是从`Map`中获取一个产品并返回它，如果它不存在，则返回一个空产品：

```java
@Override
public ProductInformation byId(String id) {
    loadProducts();
    if (products.containsKey(id)) {
        return products.get(id);
    } else {
        return ProductInformation.emptyProductInformation;
    }
}
```

查询要复杂一些。它实现了按标题搜索产品。现实生活中的实现可能实现更复杂的逻辑，但此版本仅用于本地测试；因此，按标题搜索就足够了：

```java
@Override
public List<String> byQuery(String query) {
    loadProducts();
    List<String> pis = new LinkedList<>();
    StringTokenizer st = new StringTokenizer(query, "&=");
    while (st.hasMoreTokens()) {
        final String key = st.nextToken();
        if (st.hasMoreTokens()) {
            final String value = st.nextToken();
            log.debug("processing {}={} query", key, value);
            if (!"title".equals(key)) {
                log.error("Search by title is allowed only");
                return noProducts;
            }
            for (String id : products.keySet()) {
                log.error("key: {} value:{} id:{}", key, value, id);
                ProductInformation pi = products.get(id);
                if (pi.getTitle().startsWith(value)) {
                    pis.add(id);
                }
            }
        }
    }
    return pis;
}
```

实现生产函数的服务类要简单得多。奇怪，但在大多数情况下，测试代码比生产代码更复杂：

```java
package packt.java11.mybusiness.productinformation.lookup;

import ...
@Component
public class RestClientProductLookup implements ProductLookup {
    private static Logger log = LoggerFactory.getLogger(RestClientProductLookup.class);

    final private ProductInformationServiceUrlBuilder piSUBuilder;

    public RestClientProductLookup(ProductInformationServiceUrlBuilder piSUBuilder) {
        this.piSUBuilder = piSUBuilder;
    }
```

构造器用于注入 URL 构建器 bean，这是该类的所有辅助代码。其余为`byId()`和`byQuery()`两种服务方式。首先，我们看一下`byId()`方法：

```java
@Override
public ProductInformation byId(String id) {
    var uriParameters = new HashMap<String, String>();
    uriParameters.put("id", id);
    var rest = new RestTemplate();
    var amount =
        rest.getForObject(piSUBuilder.url("inventory"),
            InventoryItemAmount.class,
            uriParameters);
    log.info("amount {}.", amount);
    if (amount.getAmount() > 0) {
        log.info("There items from {}. We are offering", id);
        return rest.getForObject(piSUBuilder.url("pi"),
            ProductInformation.class,
            uriParameters);
    } else {
        log.info("There are no items from {}. Amount is {}", id, amount);
        return ProductInformation.emptyProductInformation;
    }
}
```

`byId()`方法首先调用库存服务，查看库存中是否有产品。这个 REST 服务返回一个格式为`{ amount : nnn }`的 JSON；因此，我们需要一个具有`int amount`字段、一个设置器和一个获取器的类（非常简单，这里不列出它）。

Spring`RestTemplate`提供了一种方便的方式访问休息服务。它所需要的只是 URL 模板，一种用于转换结果的类型，以及一个包含参数的`Map`对象。URL 模板字符串可以以与 Spring 控制器中的请求映射相同的方式包含参数，参数的名称介于`{`和`}`字符之间。模板类提供了访问 REST 服务的简单方法。它自动执行封送、发送参数和取消封送，接收响应。如果是`GET`请求，则不需要封送。数据位于请求 URL 中，并且`{xxx}`占位符被映射中的值替换，这些值作为第三个参数提供。大多数格式都可以随时使用联合国封送。在我们的应用中，REST 服务发送 JSON 数据，并在响应`Content-Type`HTTP 头中指示。`RestTemplate`将 JSON 转换为作为参数提供的类型。如果服务器决定以 XML 发送响应，也会在 HTTP 头`RestTemplate`中显示，该消息头将自动处理这种情况。事实上，看看代码，我们无法分辨响应是如何编码的。这也是一个好的，因为它使客户灵活，同时，我们不需要处理这样的技术细节。我们可以集中精力于业务逻辑。

同时，该类还提供封送处理或其他一些功能的配置参数，以便它自动需要这些参数。例如，您可以提供封送处理方法，但我建议您使用默认情况下可用的方法。在大多数情况下，当开发人员认为需要这些函数的特殊版本时，他们的代码的原始设计是有缺陷的。

业务逻辑非常简单。我们首先询问存货是否有某种产品在库存。如果有（大于零），则查询产品信息服务并返回详细信息。如果没有，则返回一个空记录。

另一项服务更简单。它只调用基础服务并返回结果：

```java
@Override
public List<String> byQuery(String query) {
    var uriParameters = new HashMap<String, String>();
    uriParameters.put("query", query);
    var rest = new RestTemplate();
    return rest.getForObject(piSUBuilder.url("query"), List.class, uriParameters);
}
```

# 编译和运行应用

我们使用`gradle`编译并运行应用。由于应用没有任何特定的配置，这些配置不会出现在大多数类似的应用中，因此使用 Spring 引导是明智的。SpringBoot 使创建和运行 Web 应用变得非常简单。我们需要一个 Java 标准的`public static void main`方法，通过 Spring 启动应用：

```java
package packt.java11.mybusiness.productinformation;

import ...

@SpringBootApplication(scanBasePackageClasses = SpringScanBase.class)
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

这个方法除了启动`StringApplication`类的`run`方法外什么都不做。它传递原始参数和应用所在的类。Spring 使用这个类来读取注解。`@SpringBootApplication`注解表示该类是一个 Spring 引导应用，并提供参数来配置包含该应用的包。为此，您可以提供包含类的包的名称，但也可以在基包中提供包含 Spring 必须知道的所有类的类。您可能无法使用注解参数的类版本，因为根包不能包含任何类，只能包含子包。同时，将根包的名称提供为`String`不会在编译期间显示任何打字错误或未对齐。一些 *IDE* 可能会识别出参数应该是一个包名，或者在重构或重命名包时，它可能会扫描程序的字符串以查找包名，并为您提供支持，但这只是更多的启发式方法。通常的做法是创建一个占位符类，如果根包中没有类，则该类不在根包中执行任何操作。此类可用于指定`scanBasePackageClasses`作为注解参数，而不是需要`String`的`scanBasePackages`。在我们的示例中，有一个空接口`SpringScanBase`作为占位符。

Spring 扫描类路径上的所有类，识别它可以解释的组件和字段注解，并在需要时使用这些知识来创建 bean 而不进行配置。

注意，JDK 中包含的抽象类`ClassLoader`没有提供任何类扫描方法。由于 Java 环境和框架可以实现它们自己的`ClassLoaders`，所以一些实现可能（但不太可能）不提供`URLClassLoader`提供的扫描功能。`URLClassLoader`是类加载功能的非抽象实现，是 *JDK* 和`ClassLoader`的一部分。我们将在后面的章节中讨论类加载机制的复杂性。

`gradle`构建文件包含通常的内容。它指定了存储库、Java 插件和 Spring 引导的 IDE。它还指定在构建期间生成的 JAR 文件的名称。最重要的部分是依赖项列表：

```java
buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath("org.springframework.boot:spring-boot-gradle-plugin:1.4.1.RELEASE")
    }
}

apply plugin: 'java'
apply plugin: 'eclipse'
apply plugin: 'idea'
apply plugin: 'spring-boot'

jar {
    baseName = 'packt-ch07-microservice'
    version =  '1.0.0'
}

repositories {
    mavenCentral()
}

bootRun {
    systemProperties System.properties
}

sourceCompatibility = 1.10
targetCompatibility = 1.10

dependencies {
    compile("org.springframework.boot:spring-boot-starter-web")
    compile("org.springframework.boot:spring-boot-devtools")
    compile("org.springframework:spring-aop")
    compile("org.springframework:spring-aspects")
    testCompile("org.springframework.boot:spring-boot-starter-test")
}
```

我们依赖于 Spring 引导包、一些测试包、AOP 支持（我们很快就会看到这些），以及 Spring 引导开发工具。

SpringBootDevTools 使 Web 应用在重新编译时可以重新启动，而无需重新启动内置的 Tomcat 服务器。假设我们使用以下命令行启动应用：

```java
gradle -Dspring.profiles.active=production bootRun
```

Gradle 启动应用。每当它看到它运行的类被修改时，就会重新加载它们，我们可以在几秒钟内测试修改后的应用。

`-Dspring.profiles.active=production`参数指定生产配置文件应该是活动的。为了能够使用这个命令行参数，我们还需要构建文件中的`bootRun{}`配置闭包。

# 测试应用

应用应该为它所拥有的每个类都进行单元测试，可能除了不包含任何功能的 DTO 类。设置器和获取器是由 IDE 创建的，而不是由程序员输入的，因此不太可能出现任何错误。如果存在与这些类相关的错误，则更可能是无法通过使用单元测试发现的集成问题。由于我们在前面的章节中详细讨论了单元测试，因此我们将在这里更多地关注集成测试和应用测试。

# 集成测试

集成测试与单元测试非常相似，在大多数情况下，新手程序员声称他们在实际执行集成测试时执行单元测试。

集成测试驱动代码，但不要单独测试单个类（单元），模拟类可能使用的所有内容。相反，它们测试了执行测试所需的大多数类的功能。这样，集成测试将测试这些类是否能够协同工作，不仅满足它们自己的规范，而且还确保这些规范能够一起工作。

在集成测试中，模拟外部世界（如外部服务）和对数据库的访问。这是因为集成测试应该在集成服务器上运行，在执行单元测试的同一环境中，这些外部接口可能不可用。在大多数情况下，使用内存中的 SQL 模拟数据库，使用一些模拟类模拟外部服务。

Spring 提供了一个很好的环境来执行这样的集成测试。在我们的项目中，我们有一个示例集成测试：

```java
package packt.java11.mybusiness.productinformation;

import ...

@RunWith(SpringRunner.class)
@SpringBootTest(classes = Application.class)
@AutoConfigureMockMvc
@ActiveProfiles("local")
public class ProductInformationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void noParamGreetingShouldReturnDefaultMessage() throws Exception {

        this.mockMvc.perform(get("/pi")).andDo(print())
            .andExpect(status().isNotFound());
    }

    @Test
    public void paramGreetingShouldReturnTailoredMessage() throws Exception {

        this.mockMvc.perform(get("/pi/123"))
            .andDo(print()).andExpect(status().isOk())
            .andExpect(jsonPath("$.title").value("Book Java9 by Example"));
    }

}
```

这远不是一个完整和成熟的集成测试。有很多情况还没有经过测试，但在这里，这是一个很好的例子。为了获得对 Spring 环境的所有支持，我们必须使用`SpringRunner`类。`@RunWith`注解由 JUnit 框架处理；所有其他注解都是针对 Spring 的。当 JUnit 框架看到有一个`@RunWith`注解和一个指定的运行器类时，它将启动该类而不是标准的运行器。`SpringRunner`为测试设置 Spring 上下文并处理注解。

`@SpringBootTest`指定我们需要测试的应用。这有助于 Spring 读取该类和该类上的注解，识别要扫描的包。

`@AutoConfigureMockMvc`告诉 Spring 配置模型-视图-控制器框架的一个模拟版本，它可以在没有 Servlet 容器和 Web 协议的情况下执行。使用它，我们可以测试我们的 REST 服务，而不必真正进入网络。

`@ActiveProfiles`告诉 Spring 活动的配置文件是本地的，Spring 必须使用注解`@Profile("local")`所表示的配置。这是一个使用`.properties`文件而不是外部 HTTP 服务的版本；因此，这适合于集成测试。

测试在模拟框架内执行`GET`请求，在控制器中执行代码，并使用模拟框架和 Fluent API 以非常可读的方式测试返回值。

请注意，使用属性文件并基于属性文件实现服务有点过分。我创建它是为了能够在没有任何真正的备份服务的情况下以交互方式启动应用。考虑以下命令-`gradle -Dspring.profiles.active=local bootRun`。如果我们发出前面的命令，那么服务器将使用此本地实现启动。如果我们只以集成测试为目标，那么服务类的本地实现应该在`test`目录下，并且应该简单得多，主要是对任何预期的请求只返回常量响应，如果出现任何非预期的请求则抛出错误。

# 应用测试

考虑以下命令：

```java
gradle -Dspring.profiles.active=production bootRun
```

如果我们启动应用，发出前面的命令并启动浏览器到 URL`http://localhost:8080/pi/123`，我们将在浏览器屏幕上得到一条庞大的错误消息。哎哟。。。

上面写着类似的东西。这是因为我们的代码想连接到备份服务，但我们还没有。要在这个级别上测试应用，我们应该创建备份服务，或者至少创建一些模拟它们的东西。最简单的方法是使用 SoapUI 程序。

SoapUI 是一个 Java 程序，可从[这个页面](https://www.soapui.org/)获得。有一个开源版本和免费版本，还有一个商业版本。就我们而言，免费版本就足够了。我们可以用最简单的单击转发方式安装它，因为它有一个安装向导。之后，我们可以启动它并使用图形用户界面。

我们将创建一个新的测试项目 CatalogAndInventory，并在其中设置两个 REST 模拟服务 CatalogAndInventory，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/b22c4714-a394-43ff-85bd-1691e0f356ff.png)

对于每个模拟服务，我们设置要匹配的请求以及响应。响应的内容是文本，可以在用户界面的文本字段中键入。重要的是不要忘记将响应的媒体类型设置为`application/json`（默认为 XML）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/6855ce94-37aa-4059-be2a-0a5666ceaad0.png)

在启动服务之前，我们必须将端口号（通过单击齿轮）设置为服务器上可用的端口号。由于 8080 由 Tomcat 服务器使用并由 Gradle 执行，而 8082 由 SoapUI 用于列出当前正在运行的模拟服务，因此我将目录设置为监听端口 8081，清单设置为监听端口 8083。您还可以在`ProductInformationServiceUrlBuilder`类的列表中看到这些端口号。

soapUI 将项目保存在一个 XML 文件中，您可以在 GitHub 的`project`目录中使用它。

启动模拟服务后，按“刷新”时，浏览器屏幕上的错误消息将消失：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/9685b294-4d1e-4a29-be6b-728d3b021bb2.png)

我们看到的正是我们在 SoapUI 中输入的内容。

现在，如果我将库存模拟服务更改为返回 0 而不是 100，就像在原始版本中一样，我得到的是以下空记录：

```java
{"id":"","title":"","description":"","size":[0.0,0.0,0.0],"weight":0.0}
```

即使在这个级别上，测试也可以自动化。现在，我们在玩，用浏览器，这是一个很好的东西。不知何故，当有一个程序真的在做某件事的时候，我感觉自己在做某件事，我可以看到浏览器窗口中有一些响应。然而，过了一段时间，这会变得很无聊，手动测试应用是否仍在工作是很麻烦的。对于那些没有改变的功能来说，这尤其令人厌烦。事实上，它们确实奇迹般地改变了多次，即使我们不去碰影响它们的代码。我们确实接触了影响函数的代码，但我们没有意识到。糟糕的设计，糟糕的编码，也许我们只是忘记了，但它发生了。回归检验是不可避免的。

虽然浏览器测试用户界面也可以自动化，但这次，我们使用的是一个 REST 服务，我们可以测试 SoapUI 的用途。我们已经安装了这个工具，我们已经启动了它，并且在其中运行了一些模拟服务。下一步是将一个新的 REST 服务从 URI 添加到项目中，并指定 URL`http://localhost:8080/pi/{id}`，方法与我们为 Spring 所做的完全相同：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/c7c80404-b7bd-4eeb-86ab-4a4ae09c562d.png)

当我们在项目中定义了 REST 服务时，我们可以在套件中创建一个新的测试套件和一个测试用例。然后，我们可以在测试用例中添加一个步骤，使用参数`123`调用 REST 服务，如果我们修改默认值，它与参数的名称相同，在本例中为`id`。我们可以使用窗口左上角的绿色三角形运行测试步骤，因为我们已经运行了测试应用和 SoapUI 模拟服务，所以我们应该得到 JSON 的答案。我们必须在响应端选择 JSON；否则，SoapUI 会尝试将响应解释为 XML，而且由于我们有一个 JSON 响应，因此不会产生太多的结果。我们看到的是以下窗口：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/b5eca71b-76b5-4757-afb6-a001dee1b1a0.png)

这和我们在浏览器中看到的反应是一样的。当我们给计算机编程时，没有奇迹。有时，我们不明白发生了什么，有些事情是如此复杂，他们似乎是一个奇迹，但他们实际上不是。对我们所不知道的一切都有一个解释。在这种情况下，我们当然知道发生了什么，但是为什么在 SoapUI 的屏幕上看到 JSON 比在浏览器上看到更好呢？原因是 SoapUI 可以执行断言，在某些情况下，还可以根据 REST 调用的结果执行进一步的测试步骤，最终结果是简单的 YES 或 NO。测试正常，或者失败。

要添加断言，请单击窗口左下角的断言文本。正如您在前面的屏幕截图中看到的，我已经添加了一个将返回的 JSON 的`"title"`字段与文本`"Bar Stool"`进行比较的截图。当我们添加断言时，它建议的默认值是实际返回的值，这只是一个非常方便的特性。

在此之后，再次运行整个测试套件将运行所有测试用例（我们只有一个）和所有测试步骤，一个接一个（同样，我们只有一个），最后它将在 UI 上显示一个绿色的完成条，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/75473ec9-e153-482c-9be7-f96cddd0486b.png)

这不是 SoapUI 所能做的一切。这是一个开发良好的测试工具，已经在市场上多年。SoapUI 可以测试 SOAP 服务和 REST 服务，并且可以处理 JMS 消息。您可以在调用或单独的测试中使用这些调用、循环和断言创建多个步骤的测试，如果其他所有操作都失败，您可以通过使用 Groovy 语言创建编程步骤或使用 Java 创建扩展来做任何事情。

# Servlet 过滤器

到现在为止，服务应该很好，任何人都可以查询我们产品的详细信息。这可能是个问题。产品的细节不一定是公开信息。我们必须确保只向有资格查看数据的合作伙伴提供数据。

为了确保这一点，我们在请求中需要一些东西来证明请求来自合作伙伴。这些信息通常是密码或其他一些秘密。它可以放入`GET`请求参数或 HTTP 请求头中。最好把它放在标题里，因为信息是保密的，任何人都看不见。

GET 参数是 URL 的一部分，浏览器历史会记住这一点。将这些信息输入浏览器位置窗口、复制/粘贴并通过聊天频道或电子邮件发送也非常容易。这样，应用的用户如果没有受过这样的教育，也不关心安全性，可能会泄露机密信息。尽管对 HTTP 标头中发送的信息进行同样的处理并非不可能，但这种情况不太可能发生。如果信息在邮件头中，并且有人通过电子邮件发送了这些信息，他们可能知道自己在做什么；他们是自愿跨越安全边界的，而不是简单的疏忽。

为了沿着 HTTP 请求发送认证信息，Spring 提供了一个安全模块，可以使用注解和配置 XML 和/或类轻松配置该模块。这一次，我们将以不同的方式引入 Servlet 过滤器。

我们将要求供应商将`X-PartnerSecret`标题插入请求。这是一个非标准头，因此必须有`X-`前缀。遵循此方法还提供了额外的安全特性。这样，我们可以防止用户使用简单的浏览器访问服务。至少，需要额外的插件，可以插入自定义头或其他程序，如 SoapUI。这样，它将确保我们的合作伙伴将以编程方式使用接口，或者如果他们需要临时测试接口，只有具有一定技术水平的用户才能这样做。这对于控制支持成本非常重要。

由于每个服务都必须检查这个秘密，所以最好不要在每个服务控制器中插入检查代码。即使我们正确地创建代码，并将对机密的检查考虑到一个单独的类中，断言机密存在并且正确的方法调用也必须插入到每个控制器中。控制器执行服务；检查客户端的真实性是一个基础设施问题。它们是不同的关注点，因此，它们必须分开。

Servlet 标准为我们提供的最好的方法是通过 Servlet 过滤器。如果配置了过滤器，Servlet 过滤器是由 Servlet 容器在 Servlet 自身之前调用的类。过滤器可以在 Servlet 容器的`web.xml`配置文件中配置，也可以在使用 SpringBoot 时使用注解进行配置。过滤器不仅获取作为参数的请求和响应，而且还获取第三个`FilterChain`类型的参数，该参数应用于调用 Servlet 或链中的下一个过滤器。

可以定义多个过滤器，它们会被链接起来。过滤器可自行决定是否调用链中的下一个过滤器：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/2210c89d-4730-403a-bc2c-593cc1f85534.png)

我们将 Servlet 过滤器放入应用的`auth`子包中：

```java
package packt.java11.mybusiness.productinformation.auth;

import ...

@Component
public class AuthFilter implements Filter {
    public static final int NOT_AUTHORIZED = 401;
    private static Logger log = LoggerFactory.getLogger(AuthFilter.class);

    @Override
    public void init(FilterConfig filterConfig)
        throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain chain)
        throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        final String secret = httpRequest.getHeader("X-PartnerSecret");
        log.info("Partner secret is {}", secret);
        if (true || "packt".equals(secret)) {
            chain.doFilter(request, response);
        } else {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            httpResponse.sendError(NOT_AUTHORIZED);
        }
    }

    @Override
    public void destroy() {
    }
}
```

过滤器实现了`Filter`接口，定义了三种方法。在我们的例子中，我们没有在过滤器中考虑任何参数，也没有分配任何要释放的资源；因此，`init`和`destroy`方法都是空的。滤波器的主要工作是`doFilter`方法。它有三个参数，其中两个与 Servlet 的参数相同，第三个是`FilterChain`。

请求转换为`HttpServletRequest`，通过`getHeader`方法可以访问`X-PartnerSecret`头。如果在这个头字段中发送的值是好的，我们将调用链中的下一个值。在我们的应用中，没有更多的过滤器被配置；因此，链中的下一个过滤器是 Servlet。如果秘密是不可接受的，那么我们就不打电话给下一个。相反，我们将未授权的 HTTP 错误返回给客户端。

在这个应用中，秘密非常简单。这是常量字符串`packt`。这其实不是什么大秘密，尤其是现在这本书已经出版了。一个真实的应用需要一些更隐秘、更鲜为人知的东西。很可能每个合伙人都会使用不同的秘密，而且秘密必须不时地改变。

当我们的程序处理的 Servlet 中存在错误条件时，使用 HTTP 错误处理机制是一种很好的做法。我们不需要发回状态码为 *200 OK* 的消息，例如用 JSON 格式解释认证不成功，而是发回 *401*。这由标准定义，不需要任何进一步的解释或文件。

我们的程序还剩下一件事，那就是审计日志记录。

# 审计日志和 AOP

我们已经登录了我们的示例代码，为此，我们使用了 slf4j，我们在上一章中介绍了它。日志记录或多或少是开发人员的决定，支持技术级别的操作。在这里，我们还谈到了一些句子审计日志。这种类型的日志记录通常在功能需求中明确要求。

通常，AOP 将代码功能的不同切面分离为单独的代码片段，并相互独立地实现它们。这是一个非常单一的责任原则。这次，它的实现方式不仅是不同功能单独实现的，而且我们可以将它们连接在一起。这是单独定义的。在其他部分分别编码并获得 Spring 配置之前和之后执行什么？我们已经看到类似的东西了。类需要正确操作的依赖关系在单独的段（XML 或 Java 代码）中定义。对于 AOP，同样使用 Spring 也不奇怪。切面在配置文件或类中配置。

审计日志记录是一个典型的切面，我们将以它为例。有许多主题可以使用切面来实现，其中一些甚至值得通过这种方式实现。

我们不希望在每个需要审计日志的业务方法或类中实现审计日志代码。相反，我们实现了一个通用切面并配置了连接，以便每当调用需要审计日志记录的 bean 方法时，Spring 就会调用审计日志记录。

对于 AOP，我们还应该了解其他一些重要的术语，特别是如何在 Spring 中配置 AOP。

首先也是最重要的是切面。这是我们想要实现的功能，在我们的示例中是审计日志记录。

连接点是调用切面时的执行点。在 Java 中全面使用切面解决方案修改生成的类的字节码时，连接点几乎可以是任何东西。它可以是对字段的访问，读或写；它可以是对方法的调用或异常抛出。在 Spring 的情况下，不会修改类字节码；因此，Spring 无法识别对字段的访问或抛出的异常。使用 Spring，调用方法时总是使用连接点。

一条建议是如何在连接点调用切面。它可以在建议前，建议后，或周围的建议。如果通知在前面，则在调用方法之前调用切面。当通知在之后时，在调用方法之后调用切面。Around 意味着在方法调用之前调用切面，切面也有一个参数来调用方法，并且在方法调用之后仍然执行一些操作。这样，环绕建议与 Servlet 过滤器非常相似。

在方法调用之前调用事先通知，在它返回之后，框架将调用该方法。切面无法阻止调用原始方法。唯一的例外是当切面抛出异常时。

事后通知也受异常的影响。返回后的通知可以在方法返回时调用。只有当方法抛出异常时才调用抛出后通知。最后，在异常或返回的情况下调用事后通知。

切入点是一个特殊的字符串表达式，用于标识连接点。切入点表达式可以匹配零个、一个或多个连接点。当切面与切入点表达式相关联时，框架将知道连接点以及何时何地调用切面。换句话说，切入点是一个字符串，它告诉您何时以及为哪个方法调用切面。

尽管 AOP 的 Spring 实现不使用 AspectJ，也不修改为类创建的字节码，但它支持切入点表达式语言。尽管这种表达式语言提供了比 Spring 实现的更多的特性，但它是一种成熟的、广泛使用和接受的用于描述切入点的表达式语言，发明新的东西是没有意义的。

*序言*是向已经存在的类型添加方法或字段，并在运行时添加。Spring 允许此 AOP 功能向现有类型添加接口，并以建议类的形式添加接口的实现。在我们的示例中，我们不使用此功能。

*目标对象*是切面建议的对象。这是包含关于切面的方法的 bean，即在调用切面之前或之后。

那只是一组浓缩的定义，就像在数学书中一样。如果你读到这篇文章还没明白，别担心。我第一次读的时候也不明白。这就是为什么我们有下面的例子，在这些例子之后，我们刚刚讨论的内容将更有意义：

```java
package packt.java11.mybusiness.productinformation;

import ...
@Configuration
@Aspect
public class SpringConfigurationAspect {
    private static Logger log = LoggerFactory.getLogger("AUDIT_LOG");

    @Around("execution(* byId(..))")
    public ProductInformation byIdQueryLogging(ProceedingJoinPoint jp) throws Throwable {
        log.info("byId query is about to run");
        ProductInformation pi = (ProductInformation) jp.proceed(jp.getArgs());
        log.info("byId query was executed");
        return pi;
    }

    @Around("execution(* url(..))")
    public String urlCreationLogging(ProceedingJoinPoint jp) throws Throwable {
        log.info("url is to be created");
        var url = (String) jp.proceed(jp.getArgs());
        log.info("url created was " + url);
        return url;
    }
}
```

该类用`@Configuration`注解进行注解，以便 Spring 知道该类包含配置。`@Aspect`注解表示此配置还可以包含切面定义。方法上的`@Around`注解给出了通知的类型，注解的参数字符串是切入点表达式。如果通知类型不同，则应使用注解之一，`@Before`、`@After`、`@AfterReturning`或`@AfterThrowing`。

在我们的示例中，我们使用`@Around`切面来演示最复杂的场景。我们记录了目标方法在方法执行前后的执行情况，还通过`ProceedingJoinPoint`对象调用了原始方法。因为这两个对象返回了不同的类型，并且我们希望以不同的方式记录，所以我们定义了两个切面方法。

建议注解的参数是切入点字符串。在这种情况下，它是一个简单的。第一个`execution(* byId(..))`表示，对于任何名为`byId`且具有任何参数的方法的任何执行，都应该调用切面。第二种方法非常相似，只是方法的名称不同。这些是简单的切入点表达式，但在大量使用 AOP 的大型应用中，它们可能非常复杂。

Spring 中的切入点表达式语法主要遵循 AspectJ 使用的语法。该表达式采用**切点指示符**（**PCD**）的概念，通常执行。后面是定义要截取的方法的模式。一般格式如下：

```java
execution(modifiers-pattern? ret-type-pattern declaring-type-pattern?name-pattern(param-pattern) throws-pattern?)
```

除返回型部件外，所有其他部件都是可选的。例如，我们可以编写以下内容：

```java
execution(public * *(..))
```

这将拦截所有的`public`方法。以下表达式截取名称以`set`字符开头的所有方法：

```java
execution(* set*(..))
```

我们可以用`*`这个字符来开玩笑，就像在 Windows 的命令行或 Unix Shell 中使用它一样。参数匹配定义要复杂一些。`(..)`表示任何参数，`()`表示没有参数，`(*)`表示任何类型的参数。最后一个参数也可以在参数较多时使用，例如，`(*,Integer)`表示有两个参数，第二个参数是`Integer`，我们只是不关心第一个参数的类型。

切入点表达式可以更复杂，将匹配表达式与`&&`（and）和`||`（or）逻辑运算符连接在一起，或者使用`!`（否定）一元运算符。

使用`@Pointcut()`注解，配置可以定义切入点，将注解放在方法上。例如，考虑以下因素：

```java
@Pointcut("execution(* packt.java.9.by.example.service.*.*(..))")  
public void businessService() {}
```

它将为在`packt.java.9.by.example.service`包的任何类中实现的任何方法定义一个连接点。这只是定义切入点表达式并将其赋给名称`businessService`，该名称由方法的名称给出。稍后，我们可以在切面注解中引用此表达式，例如：

```java
@After("businessService()")
```

请注意，使用此方法纯粹是为了它的名称。Spring 不调用此方法。它仅用于借用其上定义的表达式的名称，该表达式使用了`@Pointcut`注解。需要某种东西（例如方法）来放置此注解，既然方法有名称，为什么不使用它呢？Spring 来了。当它扫描配置类并看到注解时，它会在其内部结构中将其分配给方法的名称，当使用该名称（连同括号，以使模仿方法调用的新手程序员感到困惑）时，它会查找该名称的表达式。

AspectJ 定义了其他指示符。Spring AOP 可以识别其中的一些，但是它抛出了`IllegalArgumentException`，因为 Spring 只实现方法执行切入点。另一方面，AspectJ 还可以拦截 PCD 正在初始化的对象创建，例如。除了执行之外，一些其它 PCD 可以限制执行 PCD。例如，PCD，`within`可以用来限制切面连接属于某些包中类的点，或者`@target`PCD 可以用来限制对象中的方法匹配，这些对象的注解在切入点表达式中的关键字`@target`之后在`(`和`)`之间给出。

Spring 使用的 PCD 在 AspectJ 中并不存在。这是一颗豆子。您可以定义一个包含`bean(name pattern)`的切入点表达式，将连接点限制为指定 bean 中的方法执行。模式可以是全名，也可以像几乎所有匹配的 PCD 表达式一样，`*`可以是小丑角色。

# 基于动态代理的 AOP

当 SpringAOP 第一次出现在 Java 程序员面前时，它看起来很神奇。我们如何有一个变量`classX`并调用该对象上的方法？相反，它在方法执行之前或之后执行某些切面，甚至在其周围执行某些切面，以拦截调用。

Spring 使用的技术称为动态代理。当我们有一个实现接口的对象时，我们可以创建另一个对象——代理对象——也实现该接口，但是每个方法实现都调用一个名为处理器的不同对象，实现 JDK 接口`InvocationHandler`。当代理对象上调用接口方法时，它将在处理器对象上调用以下方法：

```java
public Object invoke(Object target, Method m, Object[] args)
```

此方法可以自由执行任何操作，甚至可以使用原始或修改的参数调用目标对象上的原始方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/c4e38441-1a7a-4ad1-870b-07e36fec3902.png)

当我们手头没有要代理的类实现的接口时，我们不能使用 JDK 方法。幸运的是，有广泛使用的库，比如`cglib`，Spring 也使用这些库来做类似的事情。`Cglib`可以创建一个代理对象来扩展原始类并实现其方法，以类似于 JDK 版本对接口方法的方式调用 handler 对象的 invoke 方法。

这些技术在运行时创建类并将其加载到 Java 内存中，它们是非常深入的技术工具。它们是高级主题。我并不是说当我还是一个 Java 程序员新手的时候不要玩它们。毕竟，会发生什么？Java 不是一把上膛的枪。然而，重要的是，当你不了解一些细节或者一开始有些东西不起作用时，不要失去兴趣。或者第二个。或者第三。。。继续游泳。

Spring 中的 AOP 实现通过为目标对象生成代理对象来工作，处理器调用我们在 Spring 配置中定义的切面。这就是您不能将切面放在`final`类或`final`方法上的原因。此外，您不能在`private`或`protected`方法上配置切面。原则上，`protected`方法可以被代理，但这不是一个好的实践，因此 Spring AOP 不支持它。类似地，不能将切面放在不是 SpringBean 的类上。它们是由代码直接创建的，而不是通过 Spring 创建的，并且在创建对象时没有机会返回代理而不是原始对象。简单地说，如果不要求 Spring 创建对象，它就不能创建自定义对象。我们最不想做的就是执行这个程序，看看切面是如何执行的。审计日志的实现非常简单。我们使用标准日志，这对于审计日志的实际应用来说是不够的。我们所做的唯一特殊的事情是使用一个由名称`AUDIT_LOG`而不是类名称标识的记录器。在大多数日志框架中，这是对日志记录器的合法使用。尽管我们通常使用类来标识记录器，但是使用字符串来标识记录器是绝对可能的。在我们的日志记录中，这个字符串也将被打印在控制台的日志行中，并且它将在视觉上突出。

考虑以下命令：

```java
gradle -Dspring.profiles.active=production bootRun
```

如果我们用前面的命令启动应用，为项目启动 SoapUI，启动模拟服务，并执行测试，我们将看到 Aspects 在控制台上打印的以下日志行：

```java
2023-10-07 23:42:07.559  INFO 74643 --- [nio-8080-exec-1] o.a.c.c.C.[Tomcat].[localhost].[/]       : Initializing Spring FrameworkServlet 'dispatcherServlet'
2023-10-07 23:42:07.567  INFO 74643 --- [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet        : FrameworkServlet 'dispatcherServlet': initialization started
2023-10-07 23:42:07.626  INFO 74643 --- [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet        : FrameworkServlet 'dispatcherServlet': initialization completed in 59 ms
2023-10-07 23:42:07.629  INFO 74643 --- [nio-8080-exec-1] p.j.b.e.m.p.auth.AuthFilter              : Partner secret is packt
2023-10-07 23:42:07.655  INFO 74643 --- [nio-8080-exec-1] AUDIT_LOG                                : byId query is about to run
2023-10-07 23:42:07.666  INFO 74643 --- [nio-8080-exec-1] AUDIT_LOG                                : url is to be created
2023-10-07 23:42:07.691  INFO 74643 --- [nio-8080-exec-1] AUDIT_LOG                                : url created was http://localhost:8083/inventory/{id}
2023-10-07 23:42:07.715  INFO 74643 --- [nio-8080-exec-1] p.j.b.e.m.p.l.RestClientProductLookup    : amount {id: 123, amount: 100}.
2023-10-07 23:42:07.716  INFO 74643 --- [nio-8080-exec-1] p.j.b.e.m.p.l.RestClientProductLookup    : There items from 123\. We are offering
2023-10-07 23:42:07.716  INFO 74643 --- [nio-8080-exec-1] AUDIT_LOG                                : url is to be created
2023-10-07 23:42:07.716  INFO 74643 --- [nio-8080-exec-1] AUDIT_LOG                                : url created was http://localhost:8081/product/{id}
2023-10-07 23:42:07.725  INFO 74643 --- [nio-8080-exec-1] AUDIT_LOG                                : byId query was executed
```

# 总结

在本章中，我们构建了一个支持企业对企业事务的简单业务应用。我们使用事实上的标准企业框架 Spring 提供的特性，在微服务（几乎）架构中实现了 REST 服务。回顾这一章，令人惊讶的是，我们编写的代码很少，实现了所有的功能，这是很好的。开发所需的代码越少越好。这证明了框架的威力。

我们讨论了微服务、HTTP、REST、JSON，以及如何使用 MVC 设计模式使用它们。我们学习了 Spring 是如何构建的，有哪些模块，依赖注入在 Spring 中是如何工作的，甚至还涉及了 AOP。这一点非常重要，因为与 AOP 一起，我们发现了 Spring 是如何使用动态代理对象工作的，当您需要调试 Spring 或其他使用类似解决方案的框架时，这一点非常有价值（还有一些是经常使用的）。

我们开始用一个简单的浏览器来测试我们的代码，但是在那之后，我们意识到使用一个专业的测试工具来测试 REST 服务更好，为此，我们使用了 SoapUI，并用 REST 测试步骤和模拟服务构建了一个简单的 REST 测试套件。

了解到所有这些之后，没有什么可以阻止我们使用非常现代和先进的 Java 技术来扩展这个应用，例如反射（我们在讨论 JDK 动态代理时已经讨论过反射）、Java 流、Lambda 表达式和服务器端的脚本。

# 八、扩展我们的电子商务应用

在上一章中，我们开始开发一个电子商务应用，并创建了基于产品 ID 和几个参数来查找产品的功能。在本章中，我们将扩展此功能，以便我们也可以订购所选的产品。在此过程中，我们将学习新技术，重点关注 Java 中的函数式编程和其他一些语言特性，如运行时的反射和注解处理，以及脚本接口。

如前几章所述，我们将逐步开发应用。当我们发现新学到的技术时，我们将重构代码以加入新的工具和方法，从而产生更可读和更有效的代码。我们也会模仿现实项目的开发，一开始我们会有简单的需求，后来随着我们想象中的业务发展和销售越来越多的产品，会有新的需求。我们将成为想象中的百万富翁。

我们将使用前一章的代码库，我们将进一步开发它，但是，对于一个新的项目。我们将使用 Spring、Gradle、Tomcat 和 SoapUI，这不是新的，因为我们在前一章中已经了解了这些。在本章中，您将了解以下主题：

*   注解处理
*   使用反射
*   Java 函数式编程
*   Lambda 表达式
*   流
*   从 Java 调用脚本

# 我的业务订单

订购过程比仅仅查找产品要复杂一些。订单表单本身列出产品和金额，并标识该订单的客户。我们所要做的就是检查产品是否在我们的商店有售，以及我们是否可以将它们交付给特定的客户。这是最简单的方法；但是，对于某些产品，有更多的限制。例如，当有人订购台灯时，我们会单独提供电源线。这是因为电源线是特定于国家的。我们向英国和德国提供不同的电源线。一种可能的方法是确定客户的国家。但这种方法没有考虑到我们的客户是转售商这一事实。所有的客户都可以在英国，同时，他们可能希望将灯与电力电缆一起运送到德国。为了避免这种情况和模棱两可，我们的客户最好将台灯和电源线作为单独的项目在同一订单中订购。在某些情况下，我们提供的台灯没有电源线，但这是一个特殊的情况。我们需要一定程度的逻辑来识别这些特殊情况。因此，我们必须执行逻辑，看看是否有一个台灯电源线，如果没有自动处理的命令，它被拒绝。这并不意味着我们将不交付产品。我们只需将订单放入队列中，运算符就必须查看它。

这种方法的问题在于，台灯只是一种需要配置支持的产品。我们拥有的产品越多，他们可能拥有的专业性就越强，检查订单一致性的代码也变得越来越复杂，直到达到无法管理的复杂程度。当一个类或方法变得太复杂时，程序员会对其进行重构，将该方法或类拆分为更小的部分。我们在产品检验方面也必须这样做。我们不应该试图创建一个庞大的类来检查产品和所有可能的订单星座，而是应该有许多较小的检查，以便每个检查只检查一个小集合。

在某些情况下，检查一致性比较简单。检查灯是否有电源线对于任何一个新手程序员来说都很复杂。我们在代码中使用这个示例是因为我们希望关注代码的实际结构，而不是检查本身的复杂性质。然而，在现实生活中，检查可能相当复杂。想象一下一家卖电脑的商店。它将一个配置放在一起：电源、图形卡、主板、适当的 CPU 和内存。有很多选择，其中一些可能无法协同工作。在现实生活中，我们需要检查主板是否与所选内存兼容，是否有按顺序排列的尽可能多的内存组，它们是否正确配对（有些内存只能成对安装），是否有图形卡的兼容插槽，而且电源有足够的瓦特来可靠地运行整个配置。这非常复杂，最好不要与检查灯是否有电源线的代码混淆。

# 设置项目

由于我们仍在使用 SpringBoot，构建文件不需要任何修改；我们将使用与上一章相同的文件。然而，包的结构有点不同。这一次，我们做的事情比获取请求和响应后端服务提供给我们的任何内容都要复杂。现在，我们必须实现复杂的业务逻辑，正如我们将看到的，它需要许多类。当我们在一个特定的包中有 10 个以上的类时，是时候考虑把它们放在不同的包中了。相互关联并具有类似功能的类应该放在一个包中。这样，我们就有了以下产品的包装：

*   控制器（虽然在本例中我们只有一个，但通常有更多）
*   数据存储 bean，除了存储数据之外没有其他功能，因此是字段、设置器和获取器
*   检查器，将帮助我们在订购桌面台灯时检查电源线
*   为控制器执行不同服务的服务
*   我们程序的主包，包含`Application`类、`SpringConfiguration`和几个接口

# 订单控制器和 DTO

当服务器请求订购一系列产品时，它会收到 HTTPS`POST`请求。请求的主体是用 JSON 编码的。到目前为止，我们有控制器在处理`GET`参数。当我们可以依赖 Spring 的数据封送时，处理`POST`请求就不难了。控制器代码本身很简单：

```java
package packt.java11.bulkorder.controllers;

import ...

@RestController
public class OrderController {
    private static final Logger log = LoggerFactory.getLogger((OrderController.class));
    private final Checker checker;

    public OrderController(@Autowired Checker checker) {
        this.checker = checker;
    }

    @RequestMapping("/order")
    public Confirmation getProductInformation(@RequestBody Order order) {
        if (checker.isConsistent(order)) {
            return Confirmation.accepted(order);
        } else {
            return Confirmation.refused(order);
        }
    }
}
```

我们在这个控制器`order`中只处理一个请求。这被映射到 URL，`/order`。订单从 JSON 自动转换为请求体中的订单对象。这就是`@RequestBody`注解要求 Spring 为我们做的事情。控制器的功能只是检查顺序的一致性。如果订单一致，那么我们接受订单；否则，我们拒绝订单。实际例子还将检查订单是否不仅一致，而且是否来自有资格购买这些产品的客户，以及根据生产者的承诺和交货期，产品是否在仓库中可用，或者至少可以交货。

为了检查订单的一致性，我们需要一些能帮我们完成这项工作的东西。因为我们知道我们必须模块化代码，并且不能在一个类中实现太多的东西，所以我们需要一个检查器对象。这是根据类上的注解以及`@Autowired`对控制器的构造器自动提供的。

`Order`类是一个简单的 bean，只列出以下项：

```java
package packt.java11.bulkorder.dtos;

import ...

public class Order {
    private String orderId;
    private List<OrderItem> items;
    private String customerId;

    // ... setters and getters ...
}
```

包的名称为`dtos`，代表**数据传输对象**（**DTO**）的复数形式。DTO 是用于在不同组件（通常通过网络）之间传输数据的对象。由于另一方可以用任何语言实现，封送可以是 JSON、XML 或其他一些只能传递数据的格式。这些类没有真正的方法。DTO 通常只有字段、设置器和获取器。

以下是包含订单中一个项目的类：

```java
package packt.java11.bulkorder.dtos;

public class OrderItem {
    private double amount;
    private String unit;
    private String productId;

    // ... setters and getters ...
}
```

订单确认也在这个包中，虽然这也是一个真正的 DTO，但它有几个简单的辅助方法：

```java
package packt.java11.bulkorder.dtos;

public class Confirmation {
    private final Order order;
    private final boolean accepted;

    private Confirmation(Order order, boolean accepted) {
        this.order = order;
        this.accepted = accepted;
    }

    public static Confirmation accepted(Order order) {
        return new Confirmation(order, true);
    }

    public static Confirmation refused(Order order) {
        return new Confirmation(order, false);
    }

    public Order getOrder() {
        return order;
    }

    public boolean isAccepted() {
        return accepted;
    }
}
```

我们为类提供了两个工厂方法。这有点违反了纯粹主义者痛恨的单一责任原则。大多数时候，当代码变得更复杂时，这样的快捷方式会起反作用，代码必须重构才能更干净。纯粹的解决方案是创建一个单独的工厂类。使用工厂方法，无论是从这个类还是从一个分离的类，都可以使控制器的代码更具可读性。

我们的主要任务是一致性检查。到目前为止，代码几乎是微不足道的。

# 一致性检查器

我们有一个一致性检查器类，它的一个实例被注入到控制器中。这个类用于检查一致性，但实际上它本身并不执行检查。它只控制我们提供的不同的检查器，并逐个调用它们来完成真正的工作。

我们要求一致性检查器（例如在订购台灯时检查订单是否包含电源线的检查器）实现`ConsistencyChecker`接口：

```java
package packt.java11.bulkorder;

import packt.java11.bulkorder.dtos.Order;

public interface ConsistencyChecker {

    boolean isInconsistent(Order order);
}
```

如果顺序不一致，方法`isInconsistent`应该返回`true`。如果不知道订单是否不一致，则返回`false`，但从实际检查者检查订单的角度来看，不存在不一致。有几个`ConsistencyChecker`类，我们必须一个接一个地调用，直到其中一个返回`true`，否则我们就没有这些类了。如果没有一个返回`true`，那么我们可以安全地假设，至少从自动检查器的角度来看，顺序是一致的。

我们知道，在开发之初，我们将有很多一致性检查，并不是所有的订单都相关。我们希望避免为每个订单调用每个检查器。为此，我们实现了一些过滤。我们让产品指定他们需要什么类型的检查。这是一段产品信息，如尺寸或描述。为了适应这种情况，我们需要扩展`ProductInformation`类。

我们将创建每个`ConsistencyChecker`接口，将类实现为一个 SpringBean（用`@Component`注解进行注解），同时，我们将用一个注解对它们进行注解，该注解指定它们实现的检查类型。同时，`ProductInformation`被扩展，包含一组`Annotation`类对象，这些对象指定要调用哪些检查器。我们可以简单地列出检查器类，而不是注解，但是这给了我们在配置产品和注解之间的映射时更多的自由。注解指定产品的性质，并对检查器类进行注解。台灯是`PoweredDevice`类型，检查器类`NeedPowercord`用`@PoweredDevice`注解。如果有任何其他类型的产品也需要电源线，那么该类型的注解应该添加到`NeedPowercord`类中，我们的代码就可以工作了。既然我们开始深入研究注解和注解处理，我们就必须首先了解注解到底是什么。我们从第 3 章“优化专业排序代码”开始就已经使用了注解，但我们所知道的只是如何使用它们，如果不了解我们所做的事情，这通常是危险的。

# 注解

注解前面带有`@`字符，可以附加到包、类、接口、字段、方法、方法参数、泛型类型声明和用法，最后附加到注解。注解几乎可以在任何地方使用，它们被用来描述一些程序元信息。例如，`@RestController`注解不会直接改变`OrderController`类的行为。类的行为由其内部的 Java 代码描述。注解有助于 Spring 理解类是什么以及如何使用它。当 Spring 扫描所有包和类以发现不同的 SpringBean 时，它会看到类上的注解并将其考虑在内。这个类上可能还有 Spring 不理解的其他注解。它们可能被其他框架或程序代码使用。Spring 将它们视为任何行为良好的框架。例如，正如我们稍后将看到的，在我们的代码库中，我们有一个`NeedPowercord`类，它是一个 SpringBean，因此用`@Component`注解进行了注解。同时，还附有`@PoweredDevice`注解。Spring 不知道什么是电动设备。这是我们定义和使用的东西。Spring 忽略了这一点。

包、类、接口、字段等可以附加许多注解。这些注解应该简单地写在它们所附加的语法单元声明的前面。

对于包，注解必须写在`package-info.java`文件中包名的前面。这个文件可以放在包的目录中，可以用来编辑包的*JavaDoc*，也可以给包添加注解。此文件不能包含任何 Java 类，因为名称`package-info`不是有效的标识符。

我们不能在任何东西前面写任何东西作为注解。应声明注解。它们在 Java 特殊接口的运行时。例如，声明`@PoweredDevice`注解的 Java 文件如下所示：

```java
package packt.java11.bulkorder.checkers;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface PoweredDevice {
}
```

`interface`关键字前面的`@`字符表示这是一种特殊的注解类型。有一些特殊的规则；例如，注解接口不应扩展任何其他接口，甚至注解接口也不应扩展。另一方面，编译器会自动生成注解接口，从而扩展 JDK 接口`java.lang.annotation.Annotation`。

注解在源代码中，因此，它们在编译过程中可用。它们还可以由编译器保留并放入生成的类文件中，当类加载器加载类文件时，它们也可以在运行时使用。默认的行为是编译器将注解与注解元素一起存储在类文件中，但类加载器不会使其在运行时可用。

为了在编译过程中处理注解，必须使用注解处理器扩展 Java 编译器。这是一个相当高级的主题，在使用 Java 时只能遇到几个例子。注解处理器是一个 Java 类，它实现了一个特殊的接口，当编译器处理声明处理器感兴趣的源文件中的注解时，编译器会调用它。

# 注解保留

Spring 和其他框架通常在运行时处理注解。必须指示编译器和类加载器在运行时保持注解可用。为此，必须使用`@Retention`注解对注解接口本身进行注解。此注解有一个参数为`RetentionPolicy`类型，即`enum`。我们将很快讨论如何定义注解参数。

有趣的是，注解接口上的`@Retention`注解必须在类文件中可用；否则，类装入器将不知道如何处理注解。在编译过程结束后，我们如何表示编译器将保留注解？我们对注解接口声明进行注解。因此，`@Retention`的声明被自己注解并声明在运行时可用。

注解声明可以使用`@Retention(RetentionPolicy.SOURCE)`、`@Retention(RetentionPolicy.CLASS)`或`@Retention(RetentionPolicy.RUNTIME)`进行注解。

# 注解目标

最后的保留类型将是最常用的保留类型。还有其他注解可以用于注解声明。`@Target`注解可用于限制注解在特定位置的使用。此注解的参数是单个`java.lang.annotation.ElementType`值或这些值的数组。有充分的理由限制注解的使用。当我们将注解放置在错误的地方时，获得编译时间错误比在运行时搜索框架为什么忽略注解要好得多。

# 注解参数

正如我们前面看到的，注解可以有参数。在注解的`@interface`声明中声明这些参数，我们使用方法。这些方法有名称和返回值，但它们不应该有参数。您可能尝试声明一些参数，但是 Java 编译器将是严格的，不会编译代码。

这些值可以在使用注解的地方定义，使用方法的名称和`=`字符，给它们分配一个与方法类型兼容的值。例如，假设我们将`PoweredDevice`注解的声明修改为：

```java
public @interface ParameteredPoweredDevice { 
    String myParameter(); 
}
```

在这种情况下，在使用注解时，我们应该为参数指定一个值，如下所示：

```java
@Component 
@ParameteredPoweredDevice(myParameter = "1966") 
public class NeedPowercord implements ConsistencyChecker { 
...
```

如果参数的名称是一个值，并且在注解的使用位置没有定义其他参数，则可以跳过名称`value`。例如，当我们只有一个参数时，按以下方式修改代码是一种方便的速记：

```java
public @interface ParameteredPoweredDevice{ 
    String value(); 
} 
... 
@Component 
@ParameteredPoweredDevice("1966") 
public class NeedPowercord implements ConsistencyChecker { 
...
```

我们还可以使用方法声明后面的`default`关键字来定义可选参数。在这种情况下，我们必须为参数定义一个默认值。进一步修改示例注解，我们仍然可以（但不需要）指定值。在后一种情况下，它将是一个空字符串：

```java
public @interface ParameteredPoweredDevice { 
    String value() default ""; 
}
```

由于我们指定的值应该是常量并且在编译时是可计算的，所以复杂类型的使用并不多。注解参数通常是字符串、整数，有时还包括`double`或其他基本类型。语言规范给出的确切类型列表如下：

*   原始类型（`double`、`int`等）
*   字符串
*   类
*   枚举
*   另一个注解
*   上述任何一种类型的数组

我们已经看到了`String`的例子，而且`enum`：`Retention`和`Target`都有`enum`参数。我们要关注的有趣部分是前面列表中的最后两项。

当参数的值是数组时，该值可以指定为在`{`和`}`字符之间用逗号分隔的值。例如：

```java
String[] value();
```

然后可以将其添加到`@interface`注解中，我们可以编写以下内容：

```java
@ParameteredPoweredDevice({"1966","1967","1991"})
```

但是，如果只有一个值要作为参数值传递，我们仍然可以使用以下格式：

```java
@ParameteredPoweredDevice("1966")
```

在这种情况下，属性的值将是长度为`1`的数组。当注解的值是注解类型的数组时，事情会变得更复杂一些。我们创建一个`@interface`注解（注意名称中的复数）：

```java
@Retention(RetentionPolicy.RUNTIME) 
public @interface PoweredDevices { 
ParameteredPoweredDevice[] value() default {}; 
}
```

此注解的用法如下：

```java
@PoweredDevices( 
        {@ParameteredPoweredDevice("1956"), @ParameteredPoweredDevice({"1968", "2018"})} 
)
```

注意，这与具有三个参数的`ParameteredPoweredDevice`注解不同。这是一个具有两个参数的注解。每个参数都是一个注解。第一个有一个字符串参数，第二个有两个。

正如您所看到的，注解可能相当复杂，一些框架（或者更确切地说是创建它们的程序员）在使用它们时乱作一团。在开始编写框架之前，先进行研究，看看是否已经有了一个可以使用的框架。另外，检查是否有其他方法来解决你的问题。99% 的注解处理代码可以避免，并且变得更简单。我们为相同功能编写的代码越少，我们就越高兴。美国程序员是懒惰的，这是必须的。

最后一个例子，注解的参数是注解数组，对于理解如何创建可重复的注解非常重要。

# 可重复注解

用`@Repeatable`注解注解的声明，表示注解可以在一个地方多次应用。此注解的参数是注解类型，该类型应具有类型为的参数，该参数是此注解的数组。不要试图理解！我来举个例子。我已经有了，事实上我们有`@PoweredDevices`。它有一个参数是一个数组`@ParameteredPoweredDevice`。我们现在把这个`@interface`注解如下：

```java
... 
@Repeatable(PoweredDevices.class) 
public @interface ParameteredPoweredDevice { 
...
```

然后，我们可以简化`@ParameteredPoweredDevice`的使用。我们可以多次重复注解，Java 运行时会自动将其括在包装类中，在本例中，包装类是`@PoweredDevices`。在这种情况下，以下两个将是等效的：

```java
... 
@ParameteredPoweredDevice("1956") 
@ParameteredPoweredDevice({"1968", "2018"}) 
public class NeedPowercord implements ConsistencyChecker { 
... 

@PoweredDevices( 
        {@ParameteredPoweredDevice("1956"), @ParameteredPoweredDevice({"1968", "2018"})} 
) 
public class NeedPowercord implements ConsistencyChecker { 
...
```

这种复杂方法的原因同样是 Java 严格遵循的向后兼容性的一个例子。注解是在 Java1.5 中引入的，可重复的注解只有在 1.8 版本之后才可用。我们将很快讨论在运行时用于处理注解的反射 API。`java.lang.reflect.AnnotatedElement`接口中的这个 API 有一个`getAnnotation(annotationClass)`方法，它返回一个注解。如果单个注解可以在一个类、方法等上出现多次，则无法调用此方法来获取具有所有不同参数的所有不同实例。通过引入包装多个注解的包含类型，确保了向后兼容性。

# 注解继承

注解，就像方法或字段一样，可以在类层次结构之间继承。如果一个注解声明被标记为`@Inherited`，那么用这个注解扩展另一个类的类可以继承它。如果子类具有注解，则可以覆盖注解。因为 Java 中没有多重继承，所以不能继承接口上的注解。即使继承了注解，检索特定元素注解的应用代码也可以区分继承的注解和在实体本身上声明的注解。有两种方法可以获取注解，另外两种方法可以获取在实际元素上声明的、未继承的已声明注解。

# `@Documented`注解

`@Documented`注解表示注解是实体合同的一部分的意图，因此必须进入文档。这是一个注解，当为引用`@Documented`注解的元素创建文档时，*JavaDoc* 生成器将查看该注解。

# JDK 注解

除了用于定义注解的注解外，JDK 中还定义了其他注解。我们已经看到了其中的一些。最常用的是`@Override`注解。当编译器看到此注解时，它会检查该方法是否确实覆盖了继承的方法。否则将导致一个错误，使我们免于痛苦的运行时调试。

方法、类或其他元素的文档中的注解信号，表示不使用该元素。代码中仍然存在，因为有些用户可能仍然使用它，但是如果是依赖于包含元素的库的新开发，新开发的代码不应该使用它。注解有两个参数。一个参数是`since`，它可以有字符串值，可以传递关于方法或类的版本的过期时间或版本信息。另一个参数为`forRemoval`，如果元素在库的未来版本中不出现，则为`true`。有些方法可能会被否决，因为有更好的替代方案，但是开发人员不打算从库中删除该方法。在这种情况下，`forRemoval`可以设置为`false`。

`@SuppressWarning`注解也是一个常用的注解，尽管它的用法值得怀疑。它可以用来抑制编译器的某些警告。如果可能的话，建议编写代码，可以在没有任何警告的情况下编译。

`@FunctionalInterface`注解声明一个接口只打算有一个方法。这样的接口可以实现为 Lambda 表达式。您将在本章后面学习 Lambda 表达式。当此注解应用于接口并且接口中声明了多个方法时，编译器将发出编译错误信号。这将防止任何开发人员在早期将另一个方法添加到与函数式编程和 Lambda 表达式一起使用的接口中。

# 使用反射

既然您已经学会了如何声明注解，以及如何将它们附加到类和方法中，我们可以返回到我们的`ProductInformation`类。您可能会记得，我们想指定此类中的产品类型，并且每个产品类型都用`@interface`注解表示。我们已经在前面的几页中列出了它，这是我们在`@PoweredDevice`示例中实现的一个。我们将开发代码，假设以后会有许多这样的注解、产品类型和一致性检查程序，这些注解都用`@Component`和一个或多个注解进行注解。

# 获取注解

我们将用以下字段扩展`ProductInformation`类：

```java
private List<Class<? extends Annotation>> check;
```

因为这是一个 DTO，而且 Spring 需要设置器和获取器，所以我们还将向它添加一个新的设置器和获取器。该字段将包含每个类为我们的一个注解实现的类的列表，以及内置的 JDK 接口`Annotation`，因为 Java 编译器是通过这种方式生成它们的。在这一点上，这可能有点模糊，但我保证黎明将破晓，隧道尽头将有光明。

为了获得产品信息，我们必须根据 ID 进行查找。这是我们在上一章中开发的接口和服务，只是这次我们有了另一个新领域。事实上，这是一个显著的差异，尽管`ProductLookup`接口根本没有改变。在最后一章中，我们开发了两个版本。其中一个版本正在从属性文件读取数据，而另一个版本正在连接到 REST 服务。

属性文件很难看，而且是一项古老的技术，但是如果你想通过 Java 面试或者在 21 世纪初开发的企业应用上工作，那么属性文件是必须的。我不得不把它写进最后一章。在我的坚持下，这本书收录了这本书。同时，在为本章编写代码时，我没有勇气继续使用它。我还想向您展示同样的内容可以用 JSON 格式管理。

现在，我们将扩展`ResourceBasedProductLookup`的实现，从 JSON 格式的资源文件中读取产品信息。大多数代码在类中保持不变；因此，我们仅在此处列出差异：

```java
package packt.java11.bulkorder.services;
import ...

@Service
public class ResourceBasedProductLookup implements ProductLookup {
    private static final Logger log =
        LoggerFactory.getLogger(ResourceBasedProductLookup.class);

    private ProductInformation fromJSON(InputStream jsonStream) throws IOException {
        final var mapper = new ObjectMapper();
        return mapper.readValue(jsonStream, ProductInformation.class);
    }

// ...
    private void loadProducts() {
        if (productsAreNotLoaded) {
            try {
                final var resources = new PathMatchingResourcePatternResolver().
                        getResources("classpath:products/*.json");
                for (final var resource : resources) {
                    loadResource(resource);
                }
                productsAreNotLoaded = false;
            } catch (IOException ex) {
                log.error("Test resources can not be read", ex);
            }
        }
    }

    private void loadResource(Resource resource) throws IOException {
        final var dotPos = resource.getFilename().lastIndexOf('.');
        final var id = resource.getFilename().substring(0, dotPos);
        final var pi = fromJSON(resource.getInputStream());
        pi.setId(id);
        products.put(id, pi);
        if( pi.getCheck() != null )
        log.info("Product {} check is {}",id,pi.getCheck().get(0));
    }
// ...
```

在`project resources/products`目录中，我们有一些 JSON 文件。其中一个包含台灯产品信息：

```java
{ 
  "id" : "124", 
  "title": "Desk Lamp", 
  "check": [ 
    "packt.java11.bulkorder.checkers.PoweredDevice" 
  ], 
  "description": "this is a lamp that stands on my desk", 
  "weight": "600", 
  "size": [ "300", "20", "2" ] 
}
```

产品的类型是在 JSON 数组中指定的。在本例中，此数组只有一个元素，该元素是表示产品类型的注解接口的完全限定名。当 JSON Marshaller 将 JSON 转换为 Java 对象时，它会识别出需要此信息的字段是一个`List`，因此它会将数组转换为一个列表，以及从`String`到`Class`对象中表示注解接口的元素。

现在我们已经从 JSON 格式的资源中加载了资源，并且我们已经看到了在使用 Spring 时读取 JSON 数据是多么容易，我们可以回到顺序一致性检查。`Checker`类实现了收集可插入检查器并调用它们的逻辑。它还实现了基于注解的过滤，以避免调用我们在实际订单中实际产品并不需要的检查：

```java
package packt.java11.bulkorder.services;

import ...

@Component()
@RequestScope
public class Checker {
    private static final Logger log = LoggerFactory.getLogger(Checker.class);

    private final Collection<ConsistencyChecker> checkers;
    private final ProductInformationCollector piCollector;
    private final ProductsCheckerCollector pcCollector;

    public Checker(@Autowired Collection<ConsistencyChecker> checkers,
                   @Autowired ProductInformationCollector piCollector,
                   @Autowired ProductsCheckerCollector pcCollector
    ) {
        this.checkers = checkers;
        this.piCollector = piCollector;
        this.pcCollector = pcCollector;
    }

    public boolean isConsistent(Order order) {
        final var map = piCollector.collectProductInformation(order);
        if (map == null) {
            return false;
        }
        final var annotations = pcCollector.getProductAnnotations(order);
        for (final var checker : checkers) {
            for (final var annotation : checker.getClass().getAnnotations()) {
                if (annotations.contains(annotation.annotationType())) {
                    if (checker.isInconsistent(order)) {
                        return false;
                    }
                    break;
                }
            }
        }
        return true;
    }
}
```

其中一件有趣的事情是，Spring 自动布线是非常聪明的。我们有一个`Collection<ConsistencyChecker>`类型的字段。通常，如果只有一个类与要连接的资源具有相同的类型，则自动连接可以工作。在我们的例子中，因为这是一个集合，所以我们没有任何这样的候选者，但是我们有许多`ConsistencyChecker`类。我们所有的检查器都实现了这个接口，Spring 识别它，实例化它们，神奇地创建它们的集合，并将集合注入这个字段。

通常，一个好的框架在逻辑上工作。我不知道 Spring 的这个特征，但我认为这是合乎逻辑的，而且神奇地，它起作用了。如果事情是合乎逻辑的，并且只是工作的话，你不需要阅读和记住文档。不过，稍微小心一点也不会有任何危害。在我意识到这个功能是这样工作的之后，我在文档中查阅了它，以看到这确实是 Spring 的一个保证特性，而不是仅仅发生在工作中的特性，而是在未来版本中可能会发生更改而不需要注意。仅使用保证功能是非常重要的，但在我们的行业中经常被忽略。

调用`isConsistent()`方法时，首先将产品信息收集到`HashMap`中，为每个`OrderItem`分配一个`ProductInformation`实例。这是在一个单独的类里完成的。在此之后，`ProductsCheckerCollector`收集一个或多个产品项所需的`ConsistencyChecker`实例。当我们拥有这个集合时，我们只需要调用那些用这个集合中的注解之一进行注解的检查器。我们循环着做。

在这段代码中，我们使用反射。我们循环每个检查器都有的注解。为了获取注解集合，我们调用`checker.getClass().getAnnotations()`。此调用返回对象集合。每个对象都是一些 JDK 运行时生成的类的实例，这些类实现了我们在其源文件中声明为注解的接口。但是，没有保证动态创建的类只实现我们的`@interface`，而不是其他接口。因此，要获得实际的注解类，必须调用`annotationType()`方法。

`ProductCheckerCollector`和`ProductInformationCollector`类非常简单，我们将在稍后学习流时讨论它们。在这一点上，当我们使用循环实现它们时，它们将成为一个很好的例子，紧接着，使用流。

拥有它们，我们最终可以创建实际的检查器类。帮助我们看到我们的灯有一根电源线的命令如下：

```java
package packt.java11.bulkorder.checkers;

//SNIPPET SKIL TILL "import ..."

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import packt.java11.bulkorder.ConsistencyChecker;
import packt.java11.bulkorder.dtos.Order;

import ...
@Component
@PoweredDevice
public class NeedPowercord implements ConsistencyChecker {
    private static final Logger log = LoggerFactory.getLogger(NeedPowercord.class);

    @Override
    public boolean isInconsistent(Order order) {
        log.info("checking order {}", order);
        var helper = new CheckHelper(order);
        return !helper.containsOneOf("126", "127", "128");
    }
}
```

助手类包含许多检查器需要的简单方法，例如：

```java
public boolean containsOneOf(String... ids) {
    for (final var item : order.getItems()) {
        for (final var id : ids) {
            if (item.getProductId().equals(id)) {
                return true;
            }
        }
    }
    return false;
}
```

# 调用方法

在本例中，我们仅使用一个反射调用来获取附加到类的注解。反思可以做更多的事情。处理注解是这些调用最重要的用途，因为注解没有自己的功能，在运行时不能以任何其他方式处理。然而，反射并没有停止告诉我们一个类或任何其他包含注解的元素有什么注解。反射可以用来获取一个类的方法列表、作为字符串的方法名称、类的实现接口、它扩展的父类、字段、字段类型等等。反射通常提供方法和类，以编程方式遍历实际的代码结构直至方法级别。

本演练不仅允许读取类型和代码结构，还允许在编译时设置字段值和调用方法，而不必知道方法的名称。我们甚至可以设置`private`字段，这些字段通常是外部世界无法访问的。还应该注意，通过反射访问方法和字段通常比通过编译代码访问慢，因为它总是涉及根据代码中元素的名称进行查找。

经验法则是，如果您看到必须使用反射来创建代码，那么就要意识到您可能正在创建一个框架（或者写一本关于 Java 的书来详细介绍反射）。这听起来熟悉吗？

Spring 还使用反射来发现类、方法和字段，并注入对象。它使用 URL 类加载器列出类路径上的所有 JAR 文件和目录，加载它们，并检查类。

举一个人为的例子，为了演示，我们假设`ConsistencyChecker`实现是由许多外部软件供应商编写的，而最初设计程序结构的架构师只是忘记在接口中包含`isConsistent()`方法。（同时，为了保护我们的心理健康，我们还可以想象这个人已经不再在公司工作了。）因此，不同的供应商提供了“实现”这个接口的 Java 类，但是我们不能调用这个方法，这不仅是因为我们没有一个拥有这个方法的公共父接口，但也因为供应商只是碰巧对他们的方法使用了不同的名称。

在这种情况下我们能做什么？从商业角度来看，要求所有供应商重写他们的跳棋是不可能的，因为他们知道我们有麻烦了，这会给任务贴上一个很高的价格标签。我们的管理者希望避免这一成本，而我们的开发人员也希望表明，我们能够纠正这种情况，创造奇迹（我稍后将对此发表评论）。

我们可以有一个类，它知道每个检查器以及如何以多种不同的方式调用它们。这将要求我们在系统中引入新检查器时维护所述类，我们希望避免这种情况。我们使用的整个插件架构最初就是为了这个目的而发明的。

如果我们知道一个对象只有一个声明的方法，而这个方法接受一个命令作为参数，那么我们如何调用这个对象上的方法呢？这就是反射进入画面的地方。我们没有调用`checker.isInconsistent(order)`，而是实现了一个小的`private`方法`isInconsistent()`，通过反射调用这个方法，不管它叫什么名字：

```java
private boolean isInconsistent(ConsistencyChecker checker, Order order) {
    final var methods = checker.getClass().getDeclaredMethods();
    if (methods.length != 1) {
        log.error("The checker {} has zero or more than one methods",
            checker.getClass());
        return false;
    }
    final var method = methods[0];
    final boolean inconsistent;
    try {
        inconsistent = (boolean) method.invoke(checker, order);
    } catch (InvocationTargetException |
        IllegalAccessException |
        ClassCastException e) {
        log.error("Calling the method {} on class {} threw exception",
            method, checker.getClass());
        log.error("The exception is ", e);
        return false;
    }
    return inconsistent;
}
```

通过调用`getClass()`方法可以得到对象的类，在表示类本身的对象上，可以调用`getDeclaredMethods`。幸运的是，检查器类没有被很多方法乱放，因此我们检查检查器类中声明的方法是否只有一个。注意，反射库中也有一个`getMethods()`方法，但它将始终返回多个方法。它返回声明的和继承的方法。因为每个类都继承了`java.lang.Object`，所以至少会有`Object`类的方法。

之后，我们尝试使用表示反射类中方法的`Method`对象来调用该类。请注意，这个`Method`对象并没有直接连接到实例。我们从类中检索该方法，因此，当我们调用它时，应该将它应该处理的对象作为第一个参数传递。这样，`x.y(z)`就变成了`method.invoke(x,z)`。`invoke()`的最后一个参数是作为`Object`数组传递的变量数。在大多数情况下，当我们调用一个方法时，我们知道代码中的参数，即使我们不知道方法的名称并且必须使用反射。当连参数都不知道，但作为计算的问题是可用的时，我们必须将它们作为一个`Object`数组传递。

通过反射调用方法是一个危险的调用。如果我们尝试以正常方式调用一个方法，即`private`，那么编译器将发出错误信号。如果参数或类型的数目不合适，编译器将再次给我们一个错误。如果返回值不是`boolean`，或者根本没有返回值，那么我们再次得到一个编译器错误。在反射的情况下，编译器是无知的。它不知道在代码执行时我们将调用什么方法。另一方面，`invoke()`方法在被调用时可以并且将会注意到所有这些失败。如果出现上述任何问题，那么我们将得到异常。如果`invoke()`方法本身发现它不能执行我们对它的要求，那么它将抛出`InvocationTargetException`或`IllegalAccessException`。如果无法将实际返回值转换为`boolean`，则得到`ClassCastException`。

关于表演魔术，这是一种自然的冲动，我们觉得要做一些非凡的东西，一些杰出的。当我们尝试一些事情，做一些有趣的事情时，这是可以的，但是当我们从事专业工作时，这绝对是不可以的。一般的程序员，如果不了解您的优秀解决方案，就会在企业环境中维护代码。他们会在修复一些 bug 或实现一些小的新特性的同时，把你精心梳理的代码变成草堆。即使你是编程界的莫扎特，他们充其量也只是无名歌手。在企业环境中，一个优秀的代码可以是一首安魂曲，包含了隐喻所包含的所有含义。

最后但同样重要的是，可悲的现实是，我们通常不是编程的莫扎特。

请注意，如果原始值的返回值是原始类型，那么它将通过反射转换为对象，然后我们将它转换回原始值。如果方法没有返回值，换句话说，如果它是`void`，那么反射将返回`java.lang.Void`对象。`Void`对象只是一个占位符。我们不能将它转换为任何原始类型值或任何其他类型的对象。它是必需的，因为 Java 是严格的，`invoke`必须返回一个`Object`，所以运行时需要一些它可以返回的东西。我们所能做的就是检查返回值类是否真的是`Void`。

让我们继续我们的故事和解决方案。我们提交了代码，它在生产中运行了一段时间，直到一个软件供应商的新更新打破它。我们在测试环境中调试代码，发现类现在包含多个方法。我们的文档清楚地说明了他们应该只有一个`public`方法，并且他们提供了一个代码，这个代码有……嗯……我们意识到其他方法是`private`。他们是对的，根据合同他们可以有`private`方法，所以我们必须修改代码。我们替换查找唯一方法的行：

```java
final var methods = checker.getClass().getDeclaredMethods(); 
if (methods.length != 1) { 
... 
} 
final var method = methods[0];
```

新代码如下：

```java
final var method = getSingleDeclaredPublicMethod(checker); 
if (method == null) { 
    log.error( 
            "The checker {} has zero or more than one methods", 
            checker.getClass()); 
    return false; 

}
```

我们编写的新方法用于查找唯一的`public`方法如下：

```java
private Method getSingleDeclaredPublicMethod(
    ConsistencyChecker checker) {
    final var methods = checker.getClass().getDeclaredMethods();
    Method singleMethod = null;
    for (final var method : methods) {
        if (Modifier.isPublic(method.getModifiers())) {
            if (singleMethod != null) {
                return null;
            }
            singleMethod = method;
        }
    }
    return singleMethod;
}
```

为了检查方法是否为`public`，我们使用了`Modifier`类中的`static`方法。有一些方法可以检查所有可能的修饰符。`getModifiers()`方法返回的值是`int`位字段。不同的位有不同的修饰符，有常量定义这些修饰符。只可用于其他类型反射对象的位永远不会被设置。

有一个例外，那就是`volatile`。该位被重新用于信号桥方法。桥接方法是由编译器自动创建的，并且可能有一些我们在本书中没有讨论的深层次和复杂的问题。重复使用同一位不会造成混淆，因为字段可以是`volatile`，但作为字段，它不能是桥接方法。显然，字段是字段而不是方法。同样地，方法不能是`volatile`字段。一般规则如下：不要在反射对象没有意义的地方使用方法；否则，要知道你在做什么。

一个新版本的检查器意外地将`check`方法实现为一个`private`包，这使得故事情节更加复杂，程序员只是忘记了使用`public`关键字。为了简单起见，让我们假设类再次只声明一个方法，但它不是公共的。我们如何使用反射来解决这个问题？

显然，最简单的解决方案是要求供应商解决问题-这是他们的错。然而，在某些情况下，我们必须为某些问题创建一个解决方案。另一种解决方案是在同一个包中创建一个具有`public`方法的类，从另一个类调用`private`包方法，从而中继另一个类。事实上，这个解决方案，作为这样一个 bug 的解决方案，似乎更符合逻辑，更清晰，但是这次，我们希望使用反射。

为了避免`java.lang.IllegalAccessException`，我们必须将`method`对象设置为可访问。为此，我们必须在调用前插入以下行：

```java
method.setAccessible(true);
```

注意，这不会将方法更改为`public`。它只会通过我们设置为可访问的`method`对象的实例来访问调用方法。

我见过这样的代码：通过调用`isAccessible()`方法检查方法是否可访问，并保存此信息；如果方法不可访问，则将其设置为可访问，并在调用后恢复原始的可访问性。这完全没用。一旦`method`变量超出范围，并且没有对设置可访问性标志的对象的引用，设置的效果就会消失。另外，设置一个`public`或一个其他可调用方法的可访问性也不会受到惩罚。

# 设置字段

我们还可以对`Field`对象调用`setAccessible`，然后我们甚至可以使用反射设置私有字段的值。没有更多的假故事，就为了这个例子，让我们制作一个名为`SettableChecker`的`ConsistencyChecker`：

```java
@Component 
@PoweredDevice 
public class SettableChecker implements ConsistencyChecker { 
    private static final Logger log = LoggerFactory.getLogger(SettableChecker.class); 

    private boolean setValue = false; 

    public boolean isInconsistent(Order order) { 
        return setValue; 
    } 
}
```

此检查器将返回`false`，除非我们使用反射将字段设置为`true`。我们是这样设定的。我们在`Checker`类中创建一个方法，并从每个检查器的检查过程中调用它：

```java
private void setValueInChecker(ConsistencyChecker checker) { 
    Field[] fields = checker.getClass().getDeclaredFields(); 
    for( final Field field : fields ){ 
        if( field.getName().equals("setValue") && 
            field.getType().equals(boolean.class)){ 
            field.setAccessible(true); 
            try { 
                log.info("Setting field to true"); 
                field.set(checker,true); 
            } catch (IllegalAccessException e) { 
                log.error("SNAFU",e); 
            } 
        } 
    } 
}
```

方法遍历所有声明的字段，如果名称为`setValue`，类型为`boolean`，则设置为`true`。这基本上会导致所有包含通电设备的订单被拒绝。

注意，尽管`boolean`是一个内置的语言原始类型，它无论如何都不是一个类，但它仍然有一个类，以便反射可以将字段的类型与`boolean`人工拥有的类进行比较。现在，`boolean.class`是语言中的一个类文本，对于每个原始类型，可以使用一个类似的常量。编译器将它们标识为类文本，并在字节码中创建适当的伪类引用，以便也可以通过这种方式检查原始类型，如在`setValueInChecker()`方法的示例代码中所示。

我们检查了字段是否具有适当的类型，并在字段上调用了`setAccessible()`方法。尽管编译器不知道我们真的做了所有的事情来避免`IllegalAccessException`，但它仍然相信调用`field`上的`set`会抛出这样一个异常，正如它声明的那样。然而，我们知道它不应该发生（著名的程序员遗言？）。为了处理这种情况，我们用一个`try`块包围方法调用，并在`catch`分支中记录异常。

# Java 函数式编程

由于我们在本章的示例中创建了大量代码，我们将研究 Java 的函数式编程特性，这将帮助我们从代码中删除许多行。我们拥有的代码越少，维护应用就越容易；因此，程序员喜欢函数式编程。但这并不是函数式编程如此流行的唯一原因。与传统循环相比，它也是一种以可读性更强、更不易出错的方式描述某些算法的极好方法。

函数式编程不是什么新鲜事。它的数学背景是在 20 世纪 30 年代发展起来的，最早（如果不是最早）的函数式编程语言之一是 LISP。它是在 20 世纪 50 年代开发的，现在仍在使用，以至于有一个版本的语言在 JVM 上实现（Clojure）。

简而言之，函数式编程就是用函数来表示程序结构。从这个意义上说，我们应该把函数看作是数学中的函数，而不是编程语言（如 C）中使用的术语。在 Java 中，我们有方法，当我们遵循函数编程范式时，我们创建和使用的方法的行为类似于数学函数。如果一个方法无论调用多少次都给出相同的结果，那么它就是函数性的，就像`sin(0)`总是零一样。函数式编程避免了改变对象的状态，因为状态没有改变，所以结果总是一样的。这也简化了调试。

如果函数曾经为给定的参数返回了某个值，它将始终返回相同的值。我们还可以将代码作为计算的声明来读取，而不是作为一个接一个执行的命令来读取。如果执行顺序不重要，那么代码的可读性也可能增加。

Java 通过 Lambda 表达式和流帮助实现函数式编程风格。请注意，这些流不是 I/O 流，并且实际上与这些流没有任何关系。

我们将首先简要介绍 Lambda 表达式以及流是什么，然后，我们将转换程序的某些部分以使用这些编程结构。我们还将看到这些代码变得更可读。

可读性是一个值得商榷的话题。代码对一个开发人员来说可能可读，并且对另一个开发人员可能不太可读。这很大程度上取决于他们习惯了什么。根据我的经验，我知道开发人员经常被流分散注意力。当开发人员第一次遇到流时，思考它们的方式和他们的外观只是奇怪。但这和开始学骑自行车一样。当你还在学习如何骑车，你摔倒的次数比你实际前进的要多，但它绝对比走路慢。另一方面，一旦你学会了如何骑。。。

# Lambda

在编写异常抛出测试时，我们已经在第 3 章中使用了 Lambda 表达式，“优化专业排序代码”。在该代码中，我们将比较器设置为一个特殊值，该值在每次调用时抛出`RuntimeException`：

```java
sort.setComparator((String a, String b) -> { 
        throw new RuntimeException(); 
    });
```

参数类型是`Comparator`，因此我们要设置的应该是实现`java.util.Comparator`接口的类的实例。该接口只定义了一个实现必须定义的方法-`compare.`，因此，我们可以将其定义为 Lambda 表达式。没有 Lambda，如果我们需要一个实例，我们必须输入很多。我们需要创建一个类，命名它，在其中声明`compare()`方法，并编写方法体，如下代码段所示：

```java
public class ExceptionThrowingComparator implements Comparator { 
  public int compare(T o1, T o2){ 
    throw new RuntimeException(); 
  } 
}
```

在使用它的地方，我们应该实例化类并将其作为参数传递：

```java
sort.setComparator(new ExceptionThrowingComparator());
```

如果我们将类定义为匿名类，我们可能会节省一些字符，但是开销仍然存在。我们真正需要的是我们必须定义的单一方法的主体。这就是 Lambda 出现的地方。

我们可以在任何地方使用 Lambda 表达式，否则我们需要一个只有一个方法的类的实例。定义并继承自`Object`的方法不计算在内，我们也不关心接口中定义为`default`方法的方法。他们在那里。Lambda 定义了一个尚未定义的。换句话说，Lambda 清楚地描述了这个值是一个函数，我们将它作为一个参数传递，而匿名类的开销要少得多。

Lambda 表达式的简单形式如下：

```java
parameters -> body
```

参数可以用括号括起来，如果只有一个参数，则可以不用括号。同样地，正文可以括在`{`和`}`字符之间，也可以是一个简单的表达式。通过这种方式，Lambda 表达式可以将开销降到最低，只在真正需要的地方使用括号。

这也是 Lambda 表达式的一个非常有用的特性，即我们不需要指定参数的类型，以防从我们使用表达式的上下文中显而易见。因此，前面的代码段甚至可以更短，如下所示：

```java
sort.setComparator((a, b) -> { 
    throw new RuntimeException(); 
});
```

或者，我们可以这样写：

```java
sort.setComparator((var a, var b) -> { 
    throw new RuntimeException(); 
});
```

参数`a`和`b`将具有所需的类型。为了更简单，如果只有一个参数，我们还可以省略参数周围的`(`和`)`字符。

如果有多个参数，则括号不是可选的。这是为了避免在某些情况下出现歧义。例如，方法调用`f(x,y->x+y)`可能是一个具有两个参数的方法—`x`，以及一个具有一个参数`y`的 Lambda 表达式。同时，它也可以是一个具有 Lambda 表达式的方法调用，Lambda 表达式有两个参数，`x`和`y`。当有多个参数并且编译器可以计算参数的类型时，自 Java11 发布以来就可以使用`var`关键字。

当我们想将函数作为参数传递时，Lambda 表达式非常方便。方法声明处参数类型的声明应为函数式接口类型。这些接口可以选择使用`@FunctionalInterface`进行注解。Java 运行时在`java.util.function`包中定义了许多这样的接口。我们将在下一节讨论其中的一些，以及它们在流中的使用。对于其余部分，标准 Java 文档可从 Oracle 获得。

# 流

流在 Java8 中也是新的，就像 Lambda 表达式一样。他们一起工作非常强烈，所以他们的出现在同一时间并不令人惊讶。Lambda 表达式以及流都支持函数式编程风格。

首先要澄清的是，流与输入和输出流没有任何关系，除了名称。它们是完全不同的东西。流更像是具有一些显著差异的集合。（如果没有区别，它们就只是集合。）流本质上是可以顺序或并行运行的操作管道。他们从收集或其他来源获得数据，包括动态制造的数据。

流支持对多个数据执行相同的计算。该结构称为**单指令多数据**（**SIMD**）。别害怕这个表情。这是一件非常简单的事情。这本书我们已经做了很多次了。循环也是一种 SIMD 结构。当我们循环检查类以查看其中是否有一个反对该顺序时，我们对每个和每个检查程序执行相同的指令。多个检查器意味着多个数据。

循环的一个问题是，我们定义了不需要的执行顺序。在跳棋的情况下，我们并不关心跳棋的执行顺序。我们关心的是，所有人都同意这个命令。在编程循环时，我们仍然指定一些顺序。这来自循环的本质，我们无法改变这一点。他们就是这样工作的。然而，如果我们能，不知何故，说“对每个检查者做这个和那个”，那就太好了。这就是流发挥作用的地方。

另一点是，使用循环的代码更重要，而不是描述性的。当我们阅读循环构造的程序时，我们将重点放在各个步骤上。我们首先看到循环中的命令是做什么的。这些命令作用于数据的单个元素，而不是整个集合或数组。

当我们在大脑中把各个步骤放在一起时，我们就会意识到什么是大局，什么是循环。在流的情况下，操作的描述更高一级。一旦我们学习了流方法，就更容易阅读了。流方法作用于整个流而不是单个元素，因此更具描述性。

`java.lang.Stream`是一个接口。具有实现此接口的类型的对象表示许多对象，并提供可用于对这些对象执行指令的方法。当我们开始对其中一个对象执行操作时，这些对象可能不可用，也可能不可用，或者只在需要时创建。这取决于`Stream`接口的实际实现。例如，假设我们使用以下代码生成一个包含`int`值的流：

```java
IntStream.iterate( 0, (s) -> s+1 )
```

在前面的代码段中，无法生成所有元素，因为流包含无限个元素。此示例将返回数字 0、1、2 等，直到其他流操作（此处未列出）终止计算。

当我们编程`Stream`时，我们通常从`Collection`创建一个流—不总是，但经常。在 Java8 中扩展了`Collection`接口，提供了`stream`和`parallelStream()`方法。它们都返回表示集合元素的流对象。当`stream`返回元素时，如果存在自然顺序，`parallelStream`会创建一个可以并行处理的流。在这种情况下，如果我们在流上使用的某些方法是以这种方式实现的，那么代码可以使用计算机中可用的多个处理器。

一旦我们有了一个流，我们就可以使用`Stream`接口定义的方法。首先是`forEach()`。此方法有一个参数，通常作为 Lambda 表达式提供，并将为流的每个元素执行 Lambda 表达式。

在`Checker`类中，我们有`isConsistent()`方法。在这个方法中，有一个循环遍历检查器类的注解。如果要记录循环中注解实现的接口，可以添加以下内容：

```java
for (ConsistencyChecker checker :checkers) { 
  for (Annotation annotation : checker.getClass().getAnnotations()) { 
    Arrays.stream(annotation.getClass().getInterfaces()).forEach( 
      t ->log.info("annotation implemented interfaces {}",t)); 
...
```

在本例中，我们使用`Arrays`类中的工厂方法从数组创建流。数组包含反射方法返回的接口`getInterfaces()`。Lambda 表达式只有一个参数；因此，不需要在其周围使用括号。表达式的主体是一个不返回值的方法调用；因此，我们也省略了`{`和`}`字符。

为什么这么麻烦？有什么好处？为什么我们不能写一个简单的循环来记录数组的元素呢？其好处是可读性和可维护性。当我们创建一个程序时，我们必须关注程序应该做什么，而不是它应该如何做。在一个理想的世界里，规范只是可执行的。当编程工作被人工智能所取代的时候，我们也许真的能达到目的。（虽然不是程序员）我们还没到。我们必须告诉计算机如何做我们想做的事。我们过去必须在 PDP-11 的控制台上输入二进制代码，以便将机器代码部署到内存中执行。后来，我们有了汇编器；后来，我们有了 FORTRAN 和其他高级编程语言，它们取代了 40 年前的大部分编程工作。所有这些编程的发展都从*如何*转向*什么*。今天，我们用 Java11 编程，这条路还有很长的路要走。我们越能表达我们该做什么，而不是如何做，我们的程序就越短，也越容易理解。它将包含本质，而不是一些人造垃圾，是机器所需要的只是做我们想要的。当我在我必须维护的代码中看到一个循环时，我假设循环的执行顺序有一定的重要性。可能根本不重要。几秒钟后可能很明显。可能需要几分钟或更长时间才能意识到订购并不重要。这种时间是浪费的，可以通过更好地表达*要做什么*部分而不是*如何做**部分*的编程构造来节省时间。

# 函数式接口

方法的参数应该是`java.util.function.Consumer`。这个接口需要定义`accept()`方法，这个方法是`void`。实现此接口的 Lambda 表达式或类将使用方法 T3 的参数而不产生任何结果。

该包中还定义了其他几个接口，每个接口都用作函数式接口，用于描述一些方法参数，这些参数可以在实际参数中作为 Lambda 表达式给出。

例如，`Consumer`的对立面是`Supplier`。这个接口有一个名为`get()`的方法，它不需要任何参数，但是它给出了一些`Object`作为返回值。

如果有一个参数和一个返回值，则该接口称为`Function`。如果返回值必须与参数的类型相同，那么`UnaryOperator`接口就是我们的朋友。类似地，还有一个`BinaryOperator`接口，它返回一个与参数类型相同的对象。正如我们从`Function`到`UnaryOperator`一样，我们可以看到在另一个方向上，也有`BiFunction`，以防参数和返回值不共享类型。

这些接口不是相互独立定义的。如果一个方法需要`Function`，而我们有`UnaryOperator`要通过，那应该不是问题。`UnaryOperator`与`Function`基本相同，参数类型相同。一个可以与接受一个对象并返回一个对象的`Function`一起工作的方法，如果它们具有相同的类型，应该不会有问题。这些可以是，但不一定是，不同的。为了实现这一点，`UnaryOperator`接口扩展了`Function`，因此可以用来代替`Function`。

到目前为止，我们遇到的这个类中的接口是使用泛型定义的。因为泛型类型不能是原始类型，所以操作原始值的接口应该单独定义。例如，`Predicate`是定义`booleantest(T t)`的接口。它是一个返回`boolean`值的函数，常用于流方法。

还有一些接口，例如`BooleanSupplier`、`DoubleConsumer`、`DoubleToIntFunction`等等，它们与原始类型`boolean`、`double`和`int`一起工作。不同参数类型和返回值的可能组合的数量是无限的。。。几乎。

**有趣的事实**：确切地说，它不是无限的。 一个方法最多可以有 254 个参数。 此限制是在 JVM 中指定的，而不是在 Java 语言规范中指定的。 当然，一个没有另一个就没有用。 有 8  种原始类型（加上“对象”，再加上少于 254 个参数的可能性），这意味着可能的函数时接口总数为`10 ** 254`，给出或取几个幅度。 几乎是无限的！

我们不应该期望在这个包的 JDK 中定义所有可能的接口。这些只是最有用的接口。例如，没有使用`short`或`char`的接口。如果我们需要这样的东西，那么我们可以在代码中定义`interface`。或者只是仔细想想，找出如何使用一个已经定义好的。（我在职业生涯中从未使用过`short`型号。从来就不需要它。）

这些函数式接口是如何在流中使用的？`Stream`接口定义了一些函数式接口类型作为参数的方法。例如，`allMatch()`方法有一个`Predicate`参数并返回一个`Boolean`值，如果流中的所有元素都匹配`Predicate`，则返回的值就是`true`。换句话说，当且仅当作为参数提供的`Predicate`为流的每个元素返回`true`时，此方法才返回`true`。

在下面的代码中，我们将重写我们在示例代码中使用循环来使用流实现的一些方法，并且通过这些示例，我们将讨论流提供的最重要的方法。我们保存了两个类，`ProductsCheckerCollector`和`ProductInformationCollector`来演示流的用法。我们可以从这些开始。`ProductsCheckerCollector`遍历`Order`中包含的所有产品，并收集产品中列出的注解。每个产品可能包含零个、一个或多个注解。这些在列表中提供。同一注解可以多次引用。为了避免重复，我们使用`HashSet`，它只包含元素的一个实例，即使产品中有多个实例：

```java
public class ProductsCheckerCollector {
    private static final Logger log =
            LoggerFactory.getLogger(ProductsCheckerCollector.class);

    private final ProductInformationCollector pic;

    public ProductsCheckerCollector
            (@Autowired ProductInformationCollector pic) {
        this.pic = pic;
    }

    public Set<Class<? extends Annotation>> getProductAnnotations(Order order) {
        var piMap = pic.collectProductInformation(order);
        final var annotations = new HashSet<Class<? extends Annotation>>();
        for (var item : order.getItems()) {
            final var pi = piMap.get(item);
            if (pi != null && pi.getCheck() != null) {
                for (final var check : pi.getCheck()) {
                    annotations.addAll(pi.getCheck());
                }
            }
        }
        return annotations;
    }
```

现在，让我们看看当我们使用流重新编码时，这个方法是如何看待的：

```java
public Set<Class<? extends Annotation>> getProductAnnotations(Order order) {
    var piMap = pic.collectProductInformation(order);
    return order.getItems().stream()
            .map(piMap::get)
            .filter(Objects::nonNull)
            .peek(pi -> {
                if (pi.getCheck() == null) {
                    log.info("Product {} has no annotation", pi.getId());
                }
            })
            .filter(ProductInformation::hasCheck)
            .peek(pi -> log.info("Product {} is annotated with class {}", pi.getId(), pi.getCheck()))
            .flatMap(pi -> pi.getCheck().stream())
            .collect(Collectors.toSet());
}
```

该方法的主要工作是进入一个单一的，虽然庞大，流表达式。我们将在接下来的几页中介绍这个表达式的元素。

`order.getItems`返回的`List`调用`stream()`方法进行转换：

```java
return order.getItems().stream()
```

我们已经简单地提到过，`stream()`方法是`Collection`接口的一部分。任何实现`Collection`接口的类都会有这个方法，即使是那些在 Java8 中引入流之前实现的类。这是因为`stream()`方法在接口中实现为`default`方法。这样，如果我们碰巧实现了一个实现这个接口的类，即使我们不需要流，我们也可以免费获得它。

为了支持接口的向后兼容性，引入了 Java8 中的`default`方法。JDK 的一些接口将被修改以支持 Lambda 和函数式编程。一个例子是`stream()`方法。在 Java8 之前的特性集中，实现一些修改过的接口的类应该已经被修改过了。他们将被要求实现新方法。这样的变化是不向后兼容的，Java 作为一种语言和 JDK 非常关注向后兼容。为此，介绍了`default`方法。这使得开发人员可以扩展接口并保持其向后兼容，从而为新方法提供默认实现。与此相反，java8JDK 的全新函数式接口也有`default`方法，尽管 JDK 中没有以前的版本，它们没有什么可兼容的。在 Java9 中，接口也被扩展，现在它们不仅可以包含`default`和`static`方法，还可以包含`private`方法。这样，接口就相当于抽象类，尽管接口中除了常量`static`字段外没有其他字段。这个接口功能扩展是一个备受批评的特性，它只会带来允许多类继承的其他语言所面临的编程风格和结构问题。Java 一直在避免这种情况，直到 Java8 和 Java9 出现。
这有什么好处？注意接口中的`default`方法和`private`方法。明智地使用它们，如果有的话。

这个流的元素是`OrderItem`对象。我们需要为每个`OrderItem`设置`ProductInformation`。

# 方法引用

幸运的是我们有`Map`，它将订单项目与产品信息配对，所以我们可以在`Map`上调用`get()`：

```java
.map(piMap::get)
```

`map()`方法与 Java 中的其他方法同名，不应混淆。当`Map`类是数据结构时，`Stream`接口中的`map()`方法执行流元素的映射。该方法的参数是一个`Function`（回想一下，这是我们最近讨论的一个函数式接口）。此函数将值`T`转换为值`R`，`map()`方法的返回值为`Stream<R>`，该值可用作原始流的元素（`Stream<T>`）。`map()`方法使用给定的`Function<T,R>`将`Stream<T>`转换为`Stream<R>`，为原始流的每个元素调用它，并从转换后的元素创建一个新流。

可以说，`Map`接口以静态方式将键映射到数据结构中的值，流方法`map()`动态地将一种值映射到另一种（或相同）类型的值。

我们已经看到可以以 Lambda 表达式的形式提供函数式接口的实例。此参数不是 Lambda 表达式。这是一个方法引用。它说`map()`方法应该调用`Map piMap`上的`get()`方法，使用实际的流元素作为参数。我们很幸运`get()`也需要一个参数，不是吗？我们也可以这样写：

```java
.map( orderItem ->piMap.get(orderItem))
```

然而，这与`piMap::get`完全相同。

这样，我们就可以引用在某个实例上工作的实例方法。在我们的示例中，实例是由`piMap`变量引用的实例。也可以引用`static`方法。在这种情况下，类的名称应该写在`::`字符前面。当我们使用来自`Objects`类的`static`方法`nonNull`时，我们很快就会看到这样一个例子（注意类名是复数形式的，它在`java.util`包中，而不是`java.lang`）。

也可以引用实例方法，而不给出应该调用它的引用。这可以在函数式接口方法有一个额外的第一个参数的地方使用，这个参数将用作实例。我们已经在第 3 章中使用过了，“优化专业排序代码”，当我们通过`String::compareTo`时，当期望的参数是`Comparator`时。`compareTo()`方法需要一个参数，而`Comparator`接口中的`compare()`方法需要两个参数。在这种情况下，第一个参数将用作必须调用`compare()`的实例，第二个参数将传递给`compare()`。在这种情况下，`String::compareTo`与写入 Lambda 表达式`(String a, String b) -> a.compareTo(b)`相同。

最后但并非最不重要的一点，我们可以使用构造器的方法引用。当我们需要`Supplier`的`Object`时，我们可以写`Object::new`。

下一步是从流中过滤出`null`元素。注意，此时流有`ProductInformation`个元素：

```java
.filter(Objects::nonNull)
```

`filter()`方法使用`Predicate`并创建一个只包含与谓词匹配的元素的流。在本例中，我们使用了对`static`方法的引用。`filter()`方法不会改变流的类型。它只过滤掉元素。

我们应用的下一种方法是有点反功能。纯函数流方法不会改变对象的状态。它们创建返回的新对象，但除此之外，没有副作用。`peek()`它本身没有什么不同，因为它只返回一个与应用的元素相同的流。然而，这种*无操作*功能，诱使新手程序员做一些非函数式的事情，编写带有副作用的代码。毕竟，如果调用它没有（副作用）的话，为什么要使用它？

```java
.peek(pi -> { 
    if (pi.getCheck() == null) { 
        log.info("Product {} has no annotation", pi.getId()); 
    } 
})
```

虽然`peek()`方法本身没有任何副作用，但是 Lambda 表达式的执行可能会有副作用。但是，对于其他任何方法也是如此。事实上，在这种情况下，做一些不适当的事情更具诱惑力。不要。我们是有纪律的成年人。正如该方法的名称所示，我们可以窥视流，但我们不应该做任何其他事情。由于编程是一项特殊的活动，在这种情况下，窥视就足够了。这就是我们在代码中实际做的：我们记录一些东西。

在此之后，我们去掉了没有`ProductInformation`的元素；我们也想去掉有`ProductInformation`的元素，但是没有定义检查器：

```java
.filter(pi -> pi.getCheck() != null)
```

在这种情况下，我们不能使用方法引用。相反，我们使用 Lambda 表达式。作为替代方案，我们可以在`ProductInformation`中创建`boolean hasCheck()`方法，如果`private`字段检查不是`null`，则返回`true`。其内容如下：

```java
.filter(ProductInformation::hasCheck)
```

尽管这个类没有实现任何函数式接口，并且有很多方法，而不仅仅是这个方法，但是这个方法是完全有效的。但是，方法引用是显式的，并指定要调用的方法。

在第二个过滤器之后，我们再次记录元素：

```java
.peek(pi -> log.info( 
     "Product {} is annotated with class {}", pi.getId(), 
                                            pi.getCheck()))
```

下一种方法是`flatMap`，这是一种特殊的、不易理解的方法。至少对我来说，当我学习函数式编程时，这比理解`map()`和`filter()`要困难一些：

```java
.flatMap(pi ->pi.getCheck().stream())
```

此方法期望 Lambda、方法引用或作为参数传递给它的任何内容为调用该方法的原始流的每个元素创建一个全新的对象流。然而，结果不是流的流，这也是可能的，而是返回的流被连接成一个巨大的流。

如果我们应用它的流是一个整数流，比如 1，2，3，…，并且每个数的函数`n`返回一个包含三个元素的流`n`、`n+1`和`n+2`，那么得到的流`flatMap()`生成一个包含 1，2，3，2，3，4，4，5、6 等等。

最后，我们的流应该被收集到一个`Set`。这是通过调用`collector()`方法完成的：

```java
.collect(Collectors.toSet());
```

`collector()`方法的参数是（同样，一个过度使用的表达式）`Collector`。它可以用于将流的元素收集到集合中。注意，`Collector`不是函数式接口。你不能仅仅用 Lambda 或者简单的方法来收集一些东西。为了收集元素，我们肯定需要一个地方来收集元素，因为不断更新的元素来自流。`Collector`接口不简单。幸运的是，`java.util.streams.Collectors`类（同样注意复数形式）有许多`static`方法创建并返回`Object`字段，这些字段反过来又创建并返回`Collector`对象。

其中之一是`toSet()`，它返回一个`Collector`，帮助将流中的元素收集到一个`Set`中。当所有元素都存在时，`collect()`方法将返回`Set`。还有其他一些方法可以帮助收集流元素，方法是将元素相加，计算平均值，或将其转换为`List`、`Collection`或`Map`。将元素收集到`Map`是一件特殊的事情，因为`Map`的每个元素实际上是一个键值对。当我们看`ProductInformationCollector`时，我们将看到这个例子。

`ProductInformationCollector`类代码包含`collectProductInformation()`方法，我们将从`Checker`类和`ProductsCheckerCollector`类中使用该方法：

```java
private Map<OrderItem, ProductInformation> map = null;

public Map<OrderItem, ProductInformation> collectProductInformation(Order order) {
    if (map == null) {
        log.info("Collecting product information");
        map = new HashMap<>();
        for (OrderItem item : order.getItems()) {
            final ProductInformation pi = lookup.byId(item.getProductId());
            if (!pi.isValid()) {
                map = null;
                return null;
            }
            map.put(item, pi);
        }
    }
    return map;
}
```

简单的技巧是将收集到的值存储在`Map`中，如果不是`null`，则只返回已经计算的值，这样在处理同一 HTTP 请求时，如果多次调用此方法，可能会节省大量服务调用。

这种结构有两种编码方式。一种是检查`Map`的非空性，如果`Map`已经存在则返回。这种模式被广泛使用，并有一个名字，称为保护。在这种情况下，方法中有多个`return`语句，这可能被视为一个弱点或反模式。另一方面，该方法的制表法是一个标签浅。这是一个品味的问题，如果你发现自己正处于一个或另一个解决方案的争论中，那么就帮自己一个忙，让你的同伴在这个话题上获胜，并为更重要的问题节省精力，例如，你应该使用流还是简单的旧循环。

现在，让我们看看如何将此解决方案转换为函数式：

```java
public Map<OrderItem, ProductInformation> collectProductInformation(Order order) {
    if (map == null) {
        log.info("Collecting product information");
        map =
        order.getItems()
                .stream()
                .map(item -> tuple(item, item.getProductId()))
                .map(t -> tuple(t.r, lookup.byId((String) t.s)))
                .filter(t -> ((ProductInformation)t.s).isValid())
                .collect(Collectors.toMap(t -> (OrderItem)t.r, t -> (ProductInformation)t.s));
        if (map.keySet().size() != order.getItems().size()) {
            log.error("Some of the products in the order do " +
                            "not have product information, {} != {} ",
                    map.keySet().size(),order.getItems().size());
            map = null;
        }
    }
    return map;
}
```

我们使用一个助手类`Tuple`，它只不过是两个`Object`实例，分别命名为`r`和`s`。稍后我们将列出这个类的代码。这很简单。

在流表达式中，我们首先从集合中创建流，然后将`OrderItem`元素映射到一个由`OrderItem`和`productId`元组组成的流。然后，我们将这些元组映射到现在包含`OrderItem`和`ProductInformation`的元组。这两个映射可以在一个映射调用中完成，该调用将在一个映射调用中执行这两个步骤。我决定在每一行中创建两个简单的步骤，希望得到的代码更容易理解。

过滤步骤也不是什么新鲜事。它只是过滤掉无效的产品信息元素。实际上应该没有。如果订单包含不存在产品的订单 ID，则会发生这种情况。在下一个语句中，当我们查看收集的产品信息元素的数量，以确定所有项目都具有适当的信息时，就会检查这一点。

有趣的代码是我们如何将流的元素收集到一个`Map`中。为此，我们再次使用`collect()`方法和`Collectors`类。这次，`toMap()`方法创建`Collector`。这需要两个结果表达式。第一个应该将流的元素转换为键，第二个应该生成要在`Map`中使用的值。因为键和值的实际类型是从传递的 Lambda 表达式的结果计算出来的，所以我们必须显式地将元组的字段转换为所需的类型。

最后，简单的`Tuple`类如下：

```java
public class Tuple<R, S> {
    final public R r;
    final public S s;

    private Tuple(R r, S s) {
        this.r = r;
        this.s = s;
    }

    public static <R, S> Tuple tuple(R r, S s) {
        return new Tuple<>(r, s);
    }
}
```

我们的代码中仍有一些类需要转换为函数式风格。这些是`Checker`和`CheckerHelper`类。

在`Checker`类中，我们可以覆盖`isConsistent()`方法：

```java
public boolean isConsistent(Order order) {
    var map = piCollector.collectProductInformation(order);
    if (map == null) {
        return false;
    }
    final var as = pcCollector.getProductAnnotations(order);
    return !checkers.stream().anyMatch(
            c -> Arrays.stream(c.getClass().getAnnotations()
            ).filter(a -> as.contains(a.annotationType())
            ).anyMatch(x -> c.isInconsistent(order)
            ));
}
```

因为您已经学习了大多数重要的流方法，所以这里几乎没有什么新问题。我们可以提到`anyMatch()`方法，如果至少有一个元素，则返回`true`，这样传递给`anyMatch()`的`Predicate`参数就是`true`。它可能还需要一些住宿，这样我们就可以使用另一条流中的一条流。这很可能是一个例子，当一个流表达式过于复杂，需要使用局部变量分解成更小的片段。

最后，在离开函数样式之前，我们覆盖了`CheckHelper`类中的`containsOneOf()`方法。这不包含新元素，将帮助您检查您对`map()`、`filter()`、`flatMap()`和`Collector`的了解。请注意，如我们所讨论的，如果`order`至少包含一个以字符串形式给出的订单 ID，则此方法返回`true`：

```java
public boolean containsOneOf(String... ids) {
    return order.getItems().parallelStream()
        .map(OrderItem::getProductId)
        .flatMap(itemId -> Arrays.stream(ids)
            .map(id -> tuple(itemId, id)))
        .filter(t -> Objects.equals(t.s, t.r))
        .collect(Collectors.counting()) > 0;
}
```

我们创建了`OrderItem`对象流，然后将其映射到流中包含的产品的 ID 流。然后，我们为每个 ID 创建另一个流，其中 ID 元素和作为参数的字符串 ID 之一。然后，我们将这些子流扁平成一个流。此流将包含`order.getItems().size()`次`ids.length`元素：所有可能的对。我们将过滤两次包含相同 ID 的对，最后，我们将计算流中的元素数。

# JavaScript

我们已经准备好了本章的示例程序。有一个问题，尽管它不专业。当我们有一个新产品需要一个新的检查器时，我们必须创建一个新的代码版本。

专业环境中的程序有版本。当修改代码、修复 bug 或实现新功能时，在应用投入生产之前，组织需要执行许多步骤。这些步骤包括释放过程。一些环境具有轻量级的发布过程；另一些环境需要严格且昂贵的检查。然而，这并不取决于组织中人员的偏好。当一个非工作的生产代码的成本很低，并且不管程序中是否有中断或不正确的功能时，那么发布过程可以很简单。这样，发布速度更快，成本更低。一个例子可以是用户用来取乐的聊天程序。在这种情况下，发布新的花哨特性可能比确保无 bug 工作更重要。另一方面，如果你创建了控制原子能发电厂的代码，那么失败的代价可能相当高。对所有特性进行认真的测试和仔细的检查，即使是在最小的更改之后，也会有回报。

在我们的示例中，简单的跳棋可能是一个不太可能导致严重错误的区域。这不是不可能的，但代码是如此简单…是的，我知道这样的论点有点可疑，但让我们假设，这些小例程可以用更少的测试和更简单的方式比其他部分的代码来改变。那么，如何将这些小脚本的代码分离开来，使它们不需要技术版本、应用的新版本，甚至不需要重新启动应用？我们有一个新产品，需要一个新的检查，我们希望有一些方法，注入这个检查到应用环境中，没有任何服务中断。

我们选择的解决方案是脚本。Java 程序可以执行用 *JavaScript*、*Groovy*、*Jython*（即 *JVM* 版本的 *Python* 语言）等多种语言编写的脚本。除了 *JavaScript* 之外，这些语言的语言解释器都不是 JDK 的一部分，但是它们都提供了一个标准接口，这个接口在 JDK 中定义。结果是，我们可以在代码中实现脚本执行，提供脚本的开发人员可以自由选择任何可用的语言；我们不需要关心执行一个 *JavaScript* 代码。我们将使用与执行 *Groovy* 或*Jython*相同的 API。我们唯一应该知道的是剧本是用什么语言写的。这通常很简单，我们可以从文件扩展名猜测，如果猜测不够，我们可以要求脚本开发人员将 *JavaScript* 放入扩展名为`.js`的文件中，*Jython* 放入扩展名为`.jy`或`.py`的文件中，*Groovy* 放入扩展名为`.groovy`的文件中，等等。同样重要的是要注意，如果我们希望我们的程序执行这些语言之一，我们应该确保解释器在类路径上。在 *JavaScript* 的情况下，这是给定的，因此，通过本章的演示，我们将用 *JavaScript* 来编写我们的脚本。不会有太多；毕竟，这是一本 Java 书，而不是一本 *JavaScript* 书。

当我们想通过编程方式配置或扩展应用时，脚本通常是一个很好的选择。这是我们的案子。

我们要做的第一件事是扩展生产信息。如果有一个脚本检查产品订单的一致性，我们需要一个字段来指定脚本的名称：

```java
private String checkScript;

public String getCheckScript() {
    return checkScript;
}

public void setCheckScript(String checkScript) {
    this.checkScript = checkScript;
}
```

我们不希望为每个产品指定多个脚本；因此，我们不需要脚本名称列表。我们只有一个由名称指定的脚本。

老实说，检查器类和注解的数据结构，允许每个产品以及每个检查器类都有多个注解，这太复杂了。然而，我们无法避免拥有一个足够复杂的结构，可以证明流表达式的能力和能力。既然我们已经讨论了这个主题，我们可以继续使用更简单的数据结构，重点关注脚本执行。

我们还必须修改`Checker`类，以便不仅使用检查器类，而且使用脚本。我们不能扔掉检查器类，因为当我们意识到我们需要更好的脚本时，我们已经有很多检查器类，我们没有资金将它们重写为脚本。嗯，是的，我们是在书中，而不是在现实生活中，但在一个企业，这将是事实。这就是为什么在为企业设计解决方案时你应该非常小心的原因。结构和解决方案将存在很长一段时间，仅仅因为一段代码在技术上不是最好的，就很难抛出它。如果它能够工作并且已经存在，那么企业将非常不愿意在代码维护和重构上花钱。

总之，我们修改了`Checker`类。我们需要一个新类来执行我们的脚本；因此，我们必须插入一个新的`final`字段，如下所示：

```java
private final CheckerScriptExecutor executor; 
```

我们还必须通过添加一个新参数来初始化`final`字段来修改构造器。

我们还必须在`isConsistent()`方法中使用此`executor`：

```java
public boolean isConsistent(Order order) {
    final var map = piCollector.collectProductInformation(order);
    if (map == null) {
        return false;
    }
    final var annotations = pcCollector.getProductAnnotations(order);
    var needAnntn = (Predicate<Annotation>) an ->
            annotations.contains(an.annotationType());
    var consistent = (Predicate<ConsistencyChecker>) c ->
            Arrays.stream(c.getClass().getAnnotations())
                    .parallel()
                    .unordered()
                    .filter(needAnntn)
                    .anyMatch(x -> c.isInconsistent(order));
    final var checkersOK = !checkers.stream().anyMatch(consistent);
    final var scriptsOK = !map.values().parallelStream().
            map(ProductInformation::getCheckScript).
            filter(Objects::nonNull).
            anyMatch(s -> executor.notConsistent(s, order));
    return checkersOK && scriptsOK;
}
```

注意，在这段代码中，我们使用并行流，因为，为什么不呢？只要有可能，我们就可以使用并行流（即使是无序的）来告诉底层系统，以及维护代码的程序员，顺序并不重要。

我们还修改了一个产品 JSON 文件，通过一些注解引用脚本而不是检查器类：

```java
{ 
  "id" : "124", 
  "title": "Desk Lamp", 
  "checkScript" : "powered_device", 
  "description": "this is a lamp that stands on my desk", 
  "weight": "600", 
  "size": [ "300", "20", "2" ] 
}
```

即使是 JSON 也更简单。注意，当我们决定使用 JavaScript 时，命名脚本时不需要指定文件扩展名。

我们以后可能会考虑进一步的开发，允许产品检查器脚本维护人员使用不同的脚本语言。在这种情况下，我们可能仍然要求他们指定扩展名，如果没有扩展名，我们的程序会将其添加为`.js`。在我们当前的解决方案中，我们不检查这一点，但是我们可以花几秒钟来考虑它，以确保解决方案可以进一步开发。重要的是，我们不要为了进一步的开发而开发额外的代码。开发人员不是算命师，也不能可靠地判断未来需要什么。这是商界人士的任务。

我们把脚本放到`scripts`目录下的`resource`目录中。文件名必须为`powered_device.js`，因为这是我们在 JSON 文件中指定的名称：

```java
function isInconsistent(order){
    isConsistent = false
    items = order.getItems()
    for( i in items ){
    item = items[i]
    print( item )
        if( item.getProductId() == "126" ||
            item.getProductId() == "127" ||
            item.getProductId() == "128"  ){
            isConsistent = true
            }
    }
    return ! isConsistent
}
```

这是一个非常简单的 JavaScript 程序。另请注意，在 JavaScript 中迭代列表或数组时，循环变量将迭代集合或数组的索引。由于我很少用 JavaScript 编程，我陷入了这个陷阱，花了半个多小时来调试我犯的错误。

我们已经准备好了所有我们需要的东西。我们还得调用它。为此，我们使用 JDK 脚本 API。首先，我们需要一个`ScriptEngineManager`。此管理器用于访问 JavaScript 引擎。尽管 JavaScript 解释器自 Java7 以来一直是 JDK 的一部分，但它仍然以抽象的方式进行管理。它是 Java 程序可以用来执行脚本的许多可能的解释器之一。它正好在 JDK 中，所以我们不需要将解释器 JAR 添加到类路径中。`ScriptEngineManager`发现类路径上的所有解释器并注册它们。

它使用服务提供者规范来实现这一点，服务提供者规范很长时间以来一直是 JDK 的一部分，而且通过 Java9，它还获得了模块处理方面的额外支持。这要求脚本解释器实现`ScriptEngineFactory`接口，并在`META-INF/services/javax.script.ScriptEngineFactory`文件中列出执行该接口的类。这些文件，从属于类路径的所有 JAR 文件中，作为资源被`ScriptEngineManager`读取，通过它，它知道哪些类实现了脚本解释器。`ScriptEngineFactory`接口要求解释器提供`getNames()`、`getExtensions()`、`getMimeTypes()`等方法。管理器调用这些方法来收集有关解释器的信息。当我们询问 JavaScript 解释器时，管理器会返回工厂创建的名称，其中一个名称是`JavaScript`。

为了通过名称访问解释器，文件扩展名或 MIME 类型只是`ScriptEngineManager`的函数之一。另一个是管理`Bindings`。

当我们在 Java 代码中执行一个脚本时，我们不会这样做，因为我们想增加多巴胺的水平。在脚本的情况下，它不会发生。我们想要一些结果。我们希望传递参数，并且在脚本执行之后，我们希望从脚本中获得可以在 Java 代码中使用的值。这可以通过两种方式实现。一种是将参数传递给脚本中实现的方法或函数，并从脚本中获取返回值。这通常是可行的，但有些脚本语言甚至可能没有函数或方法的概念。在这种情况下，这是不可能的。可以将环境传递给脚本，并在脚本执行后从环境中读取值。这个环境用`Bindings`表示。

`Bindings`是具有`String`键和`Object`值的映射。

在大多数脚本语言的情况下，例如，在 JavaScript 中，`Bindings`连接到我们执行的脚本中的全局变量。换句话说，如果我们在调用脚本之前在 Java 程序中执行以下命令，那么 JavaScript 全局变量`globalVariable`将引用`myObject`对象：

```java
myBindings.put("globalVariable",myObject)
```

我们可以创建`Bindings`并将其传递给`ScriptEngineManager`，但也可以使用它自动创建的方法，并可以直接调用引擎对象上的`put()`方法。

当我们执行脚本时，有两个`Bindings`。一个设置在`ScriptEngineManager`层。这称为全局绑定。还有一个是由`ScriptEngine`自己管理的。这是当地的`Bindings`。从剧本的角度看，没有区别。从嵌入的角度看，存在一定程度的差异。如果我们使用相同的`ScriptEngineManager`来创建多个`ScriptEngine`实例，那么全局绑定将由它们共享。如果一个人得到一个值，所有人都会看到相同的值；如果一个人设置了一个值，其他人都会看到更改后的值。本地绑定特定于它所管理的引擎。由于本书只介绍了 Java 脚本 API，所以我们不做详细介绍，也不使用`Bindings`。我们擅长调用 JavaScript 函数并从中获得结果。

实现脚本调用的类是`CheckerScriptExecutor`。它从以下几行开始：

```java
package packt.java11.bulkorder.services;
import ...

@Component
public class CheckerScriptExecutor {
    private static final Logger log =
            LoggerFactory.getLogger(CheckerScriptExecutor.class);

    private final ScriptEngineManager manager = new ScriptEngineManager();

    public boolean notConsistent(String script, Order order) {

        try {
            final var scriptReader = getScriptReader(script);
            final var result = evalScript(script, order, scriptReader);
            assertResultIsBoolean(script, result);
            log.info("Script {} was executed and returned {}", script, result);
            return (boolean) result;

        } catch (Exception wasAlreadyHandled) {
            return true;
        }
    }
```

唯一的`public`方法`notConsistent()`获取要执行的脚本的名称以及`order`。后者必须传递给脚本。首先得到`Reader`，可以读取脚本文本，对其进行求值，最后返回结果，如果是`boolean`或者至少可以转换成`boolean`。如果我们在这个类中实现的从这里调用的任何方法是错误的，它将抛出一个异常，但只有在适当地记录它之后。在这种情况下，安全的方法是拒绝命令。

实际上，这是企业应该决定的。如果存在无法执行的检查脚本，则显然是错误的情况。在这种情况下，接受订单并随后手动处理问题会产生一定的成本。由于某些内部错误而拒绝订单或确认对订单流程来说也不是一条愉快的道路。我们必须检查哪种方法对公司造成的损害最小。这当然不是程序员的职责。我们的处境很容易。

我们假设业务代表说在这种情况下订单应该被拒绝。在现实生活中，类似的决策被业务代表拒绝，他们说这不应该发生，IT 部门必须确保程序和整个操作完全没有 bug。这种反应是有心理原因的，但这确实使我们离 Java 编程非常遥远。

引擎可以执行通过`Reader`或作为`String`传递的脚本。因为现在我们在资源文件中有了脚本代码，所以让引擎读取资源似乎是一个更好的主意，而不是将其读取到一个`String`：

```java
private Reader getScriptReader(String script) throws IOException {
    final Reader scriptReader;
    try (final var scriptIS = new ClassPathResource(
            "scripts/" + script + ".js").getInputStream()) {
        scriptReader = new InputStreamReader(scriptIS);
    } catch (IOException ioe) {
        log.error("The script {} is not readable", script);
        log.error("Script opening exception", ioe);
        throw ioe;
    }
    return scriptReader;
}
```

为了从资源文件中读取脚本，我们使用 Spring`ClassPathResource`类。脚本的名称前面有`scripts`目录，后面有`.js`扩展名。其余的是相当标准的，没有什么我们在这本书中没有看到。下一个求值脚本的方法更有趣：

```java
private Object evalScript(String script, Order order, Reader scriptReader)
        throws ScriptException, NoSuchMethodException {
    final Object result;
    final var engine = manager.getEngineByName("JavaScript");
    try {
        engine.eval(scriptReader);
        final var inv = (Invocable) engine;
        result = inv.invokeFunction("isInconsistent", order);
    } catch (ScriptException | NoSuchMethodException se) {
        log.error("The script {} thruw up", script);
        log.error("Script executing exception", se);
        throw se;
    }
    return result;
}
```

要在脚本中执行该方法，首先，我们需要一个能够处理 JavaScript 的脚本引擎。我们从管理器那里得到了发动机的名字。如果不是 JavaScript，需要检查返回的`engine`不是`null`。在 JavaScript 的情况下，解释器是 JDK 的一部分，检查 JDK 是否符合标准将是偏执的。

如果我们想要扩展这个类来处理 JavaScript，以及其他类型的脚本，那么就必须完成这个检查，并且脚本引擎可能应该根据文件扩展名从管理器请求，而我们在这个方法中没有访问这个文件扩展名的权限。但这是未来的发展，不是本书的一部分。

当我们有了引擎，我们必须求值脚本。这将在脚本中定义函数，以便我们以后可以调用它。为了调用它，我们需要一些对象。对于 JavaScript，引擎还实现了一个`Invocable`接口。并非所有脚本引擎都实现此接口。有些脚本没有函数或方法，也没有可调用的内容。同样，当我们希望不仅允许 JavaScript 脚本，而且还允许其他类型的脚本时，这是以后要做的事情。

为了调用这个函数，我们将它的名称传递给`invokeFunction()`方法，同时传递我们想要传递的参数。在本例中，这是`order`。就 JavaScript 而言，两种语言之间的集成已经相当成熟。在我们的示例中，我们可以访问作为参数传递的 Java 对象的字段和方法，并且返回的 JavaScript`true`或`false`值也被神奇地转换为`Boolean`。但在有些情况下，访问并不是那么简单：

```java
private void assertResultIsBoolean(String script, Object result) {
    if (!(result instanceof Boolean)) {
        log.error("The script {} returned non boolean", script);
        if (result == null) {
            log.error("returned value is null");
        } else {
            log.error("returned type is {}", result.getClass());
        }
        throw new IllegalArgumentException();
    }
}
```

该类的最后一个方法检查返回值（可以是任何值，因为这是一个脚本引擎）是否可以转换为一个`boolean`。

需要注意的是，有些功能是在脚本中实现的，这并不能保证应用能够无缝地工作。可能有几个问题，脚本可能会影响整个应用的内部工作。一些脚本引擎提供了保护应用不受坏脚本影响的特殊方法，而另一些则没有。事实上，我们不传递，但给予命令，脚本并不保证脚本不能访问其他对象。使用反射、`static`方法和其他技术，可以访问 Java 程序中的任何内容。当我们的代码库中只有一个脚本发生变化时，我们的测试周期可能会简单一些，但这并不意味着我们应该盲目地信任任何脚本。

在我们的示例中，让产品的生产者将脚本上传到我们的系统可能是一个非常糟糕的主意。它们可以提供自己的检查脚本，但在部署到系统中之前，必须从安全角度对这些脚本进行检查。如果这是正确的，那么脚本是 Java 生态系统的一个非常强大的扩展，为我们的程序提供了极大的灵活性。

# 总结

在本章中，我们开发了我们企业应用的订购系统。随着代码的开发，我们遇到了很多新的东西。您了解了注解以及如何通过反射处理它们。虽然没有很强的相关性，但是您学习了如何使用 Lambda 表达式和流来表示比常规循环更简单的几个编程构造。在本章的最后一部分，我们通过从 Java 调用 JavaScript 函数和从 JavaScript 调用 Java 方法，使用脚本扩展了应用。

事实上，有了这些知识，我们已经成熟到了企业编程所需的 Java 级别。这本书其余的主题都是为王牌而写的。但你想成为一个，不是吗？这就是我为什么写剩下的章节。继续读！