# 使用 PHP7 构建 REST Web 服务（一）

> 原文：[`zh.annas-archive.org/md5/0741f77c4686cccb7feaca7feda46f8b`](https://zh.annas-archive.org/md5/0741f77c4686cccb7feaca7feda46f8b)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Web 服务一直是一个重要的话题。有了 REST，事情变得更简单更好。如今，RESTful web 服务被广泛使用。十年前它很重要，但是单页应用（SPAs）和移动应用程序大大增加了它的使用。本书的目的是教育 PHP 开发人员有关 RESTful web 服务架构、有效创建 RESTful web 服务的当前工具，如一个名为 Lumen 的微框架、自动化 API 测试、API 测试框架、安全性和微服务架构。

尽管这本书是针对 PHP 的，因为我们将在 PHP7 中构建 RESTful web 服务，但它既不仅仅是关于 PHP7，也不仅仅是关于 REST。RESTful web 服务和在 PHP 中的实现是我们在这本书中要做的。然而，你将学到比这更多。你将了解一些在 PHP7 中是新的 PHP 特性。我们将讨论我们应该如何构建我们的应用程序以及与 web 和 web 服务相关的一些常见威胁。你将学习如何改进基本的 RESTful web 服务，并了解测试的重要性和不同类型的测试。因此，这不仅仅是关于 REST 或 PHP，还涉及一些次要但重要的与编程相关的东西，这些东西简单但在现实世界中能够让事情变得更好。在本书的结尾，你将了解到一个名为微服务的架构。

换句话说，尽管这本书是为 PHP 开发人员而写的，但它将使他们受益不仅仅是在 PHP 方面。因此，这本书不是一本食谱，而是一个旅程，在这个旅程中，你将开始学习关于 RESTful web 服务和 PHP7，然后开始构建 RESTful web 服务。然后，你可以通过了解其中的问题并加以修复来不断改进你的 RESTful web 服务。在这样的改进过程中，你将学到 PHP 中的不同东西，甚至超越 PHP。

# 本书涵盖的内容

第一章《RESTful Web 服务，介绍和动机》向你介绍了 web 服务、REST 架构、RESTful web 服务，以及它与其他 web 服务的比较，如 HTTP 动词和 RESTful 端点。它还通过博客的例子解释了 web 服务，然后讨论了响应格式和响应代码。

第二章《PHP7，更好地编码》包括 PHP7 中的新特性和变化，我们将在本书中使用或者非常重要并值得讨论。

第三章《创建 RESTful 端点》是关于在 Vanilla PHP 中为博客文章的 CRUD 操作创建 REST API 端点。它还解释了通过名为 Postman 的 REST 客户端手动测试 API 端点的方法。

第四章《审查设计缺陷和安全威胁》审查了我们在前一章中构建的内容，并强调其中的问题和缺陷，以便我们以后可以改进。

第五章《使用 Composer 进行加载和解析》，一个进化，是关于 PHP 生态系统中的一个进化工具：composer。这不仅仅是一个自动加载程序或包安装程序，而是一个依赖管理器。因此，你将在本章中了解 composer。

第六章《用 Lumen 照亮 RESTful Web 服务》向你介绍了一个名为 Lumen 的微框架，在这个框架中，我们将重写我们的 RESTful web 服务端点，并审查这个工具将如何显著改进我们的速度和应用程序结构。

第七章《改进 RESTful Web 服务》使我们能够改进前一章中所做的事情；你将学习如何改进 RESTful web 服务。我们将创建身份验证并制作一个转换器来分离 JSON 结构应该如何看起来。此外，我们将在安全性方面进行改进，并了解 SSL。

第八章，API 测试-门上的守卫，介绍了自动化测试的需求。将介绍不同类型的测试，然后专注于 API 测试。然后我们将介绍一个名为 CodeCeption 的自动化测试框架，并在其中编写 API 测试。

第九章，微服务，是关于微服务架构的。我们将了解微服务的好处和挑战，并研究一些可能的解决方案和权衡。

# 你需要为这本书做好准备

尽管我使用了 Ubuntu，但任何安装了 PHP7 的操作系统都可以正常工作。除了 PHP7 之外，唯一需要的是关系型数据库管理系统。本书在连接数据库时使用了与 MySQL 相关的设置，因此 MySQL 是理想的选择，但 MariaDB 或 PostgreSQL 也可以。

# 这本书适合谁

这本书是为以下受众编写的：

+   任何有一些基本 PHP 知识并且想要构建 RESTful 网络服务的人。

+   懂得基本 PHP 并且已经开发了一个基本的动态网站，想要构建 RESTful 网络服务的开发人员。

+   学习了 PHP 并且大部分时间在开源 CMS 中工作，比如 WordPress，并且希望转向开发需要构建网络服务的自定义应用程序的开发人员。

+   被困在 Code Igniter 中的传统系统中，并希望探索 PHP 现代生态系统的开发人员。

+   使用过现代框架如 Yii 或 Laravel，但不确定构建 REST API 所需的关键部分，这些 API 不仅能够实现目的，而且在长期运行中表现良好，不总是需要手动测试，并且易于维护和扩展的开发人员。

+   有经验的 PHP 开发人员，已经创建了一个返回数据的基本 API，但希望熟悉 REST 标准下的 API 构建方式，以及在身份验证出现时的工作方式，以及如何为其编写测试。

# 约定

在这本书中，你会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的例子以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“`randGen()`方法接受两个参数，定义返回值的范围。”

代码块设置如下：

```php
<?php
function add($num1, $num2):int{
    return ($num1+$num2);
}

echo add(2,4); //6
echo add(2.5,4); //6
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```php
<?php
function add($num1, $num2):int{
    return ($num1+$num2);
}

echo add(2,4); //6
echo add(2.5,4); //6
```

任何命令行输入或输出都以以下方式书写：

```php
sudo add-apt-repository ppa:ondrej/php
```

新术语和重要单词以粗体显示。例如，屏幕上看到的单词，比如菜单或对话框中的单词，会出现在文本中。

警告或重要提示会出现在这样的地方。提示和技巧会出现在这样的地方。


# 第一章：RESTful 网络服务，介绍和动机

RESTful 网络服务现在被广泛使用。RESTful 是简单的，也是其他网络服务中最广泛使用的。事实上，它的简单性也是它出名的原因。如果你正在阅读这本书，那么你很可能对 RESTful 网络服务有所了解。你可能已经使用过它，或者只是听说过。但即使你对 RESTful 网络服务不太了解，也不用担心，因为我们首先在这里对它进行了定义。所以首先，让我们列出本章将涵盖的高层主题：

+   网络服务，什么是网络服务？

+   REST 架构（REST 的约束）

+   RESTful 网络服务

+   RESTful 网络服务的约定

+   HTTP 动词（方法）

+   为什么要使用 RESTful 网络服务？

+   响应类型和响应代码

+   案例研究-博客的 RESTful 网络服务端点

然而，关于 RESTful 网络服务有很多误解。例如，有些人认为任何返回 JSON 的网络上的东西都是 RESTful 网络服务，而 RESTful 网络服务只返回 JSON。这是不正确的。

事实上，RESTful 网络服务支持多种格式，并不是所有返回 JSON 的东西都是 RESTful 网络服务。为了避免混淆，让我们了解一下什么是 RESTful 网络服务。

基于 REST 架构的网络服务是 RESTful 网络服务。那么，到底什么是网络服务和 REST 架构呢？让我们先了解网络服务，然后再了解 REST 架构。

# 网络服务

网络服务在不同的地方有不同的定义。逐字翻译的定义是，包括网页在内的任何在网上提供的服务都是网络服务，但是如果指的是技术术语*网络服务*，这并不正确。

为了定义网络服务，我们将从 W3C 词汇表中查看网络服务的定义：

“网络服务是一种旨在支持网络上可互操作的机器对机器交互的软件系统。它具有用机器可处理的格式（特别是 WSDL）描述的接口。其他系统按照其描述的方式使用 SOAP 消息与网络服务进行交互，通常使用 HTTP 与其他与 Web 相关的标准一起进行 XML 序列化。”-W3C，网络服务词汇表。

这个定义同样并不完全正确，因为它更具体地适用于基于 SOAP 和 WSDL 的网络服务。事实上，在 2004 年 2 月 11 日的 W3C 工作组说明中，它指出：

“我们可以确定两类主要的网络服务：

*-符合 REST 的网络服务，*其中服务的主要目的是使用一组统一的“无状态”操作来操作 Web 资源的 XML 表示；

-和*任意网络服务*，其中服务可能公开一组任意操作。”

因此，对于网络服务的一个更一般和更好的定义是，来自前面提到的 W3C 网络服务词汇表的定义：

“网络服务是一种旨在支持网络上可互操作的机器对机器交互的软件系统。”

# 为什么要使用网络服务？

现在，我们知道了什么是网络服务。所以在继续讨论 REST 之前，了解网络服务的需求是很重要的。网络服务可以在哪里使用？

正如刚刚定义的，Web 服务是支持网络上机器对机器的可互操作通信的系统。它对于不同系统或设备之间的通信非常有用。在我们的情况下，我们将使用 Web 服务来提供一个接口，通过这个接口，移动应用程序或 Web 应用程序将能够与服务器通信以获取和存储数据。这将使客户端应用程序与服务器端逻辑分离。如今，单页应用程序（SPA）和移动应用程序需要独立，与服务器端逻辑分离，并且只通过 Web 服务与服务器端逻辑交互。因此，Web 服务如今非常重要。然而，Web 服务的使用不仅限于客户端应用程序的使用，而且在服务器之间的通信中也很有用，其中一个服务器充当客户端。

# REST 架构

REST 代表表述性状态转移。这是由 Roy Fielding 在 2000 年创立的架构风格，并在他的博士论文中阐述。他指出 REST <q>“提供了一组架构约束，当作为一个整体应用时，强调组件交互的可扩展性，接口的通用性，组件的独立部署，以及中间组件来减少交互延迟，强制安全性，并封装遗留系统。”</q>。

REST 是基于网络应用的架构风格，而 HTTP 1.1 就是基于它开发的。

一个符合 RESTful 或 REST 的网络服务必须遵守以下六个约束；否则，它将不被视为 RESTful 或 REST 兼容。在阅读和理解以下提到的约束时，可以将现代网络视为 REST 架构的一个例子。

# 客户端服务器

REST 是关于分离客户端和服务器的。这个约束是关于“关注点分离”。这意味着服务器和客户端有各自的责任，因此一个不负责另一个的职责。例如，客户端不负责服务器上的数据存储，因为这是服务器的责任。同样，服务器不需要了解用户界面。因此，服务器和客户端都执行自己的任务并履行自己的责任，这使得他们的工作更容易。因此，服务器可以更具可扩展性，客户端上的用户界面可以是独立的和更具交互性。

# 无状态

客户端服务器通信是无状态的。来自客户端的每个请求都将包含提供请求所需的所有信息。这意味着在这种通信中除了请求中的信息之外，没有其他状态。客户端将收到的响应将基于请求而不查看除请求中的信息之外的任何状态。

如果需要维护会话，会话将基于请求中的令牌或标识符进行存储。因此，如果我们看一个 Web 请求的例子，那么 HTTP 的流程不过是一个请求由**客户端**发送到**服务器**，然后服务器发送一个响应回到**客户端**，如下图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bd-rst-websvc-php7/img/74c3c7ee-f037-4b40-aa87-03cb16a3c8a8.png)

如果需要维护会话，会话数据将存储在服务器上，而会话标识符将发送回客户端。在随后的请求中，客户端将在每个请求中包含该会话标识符，服务器将通过此标识符识别客户端并加载相关会话数据，如下图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bd-rst-websvc-php7/img/61eb3fc0-43b0-4370-b2f3-5af39dcb72ed.png)

在随后的请求中：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bd-rst-websvc-php7/img/57cdc659-e497-496c-83e9-17613a213282.png)

因此，REST 是无状态的。为了维护状态，需要传递标识符或任何其他信息，以逻辑上分组不同的请求以在请求中维护会话。如果在请求中没有传递这样的标识符，服务器将永远不知道这两个请求是否来自同一个客户端。

无状态性的优势在于简单性。相同的请求不会产生不同的响应，除非请求参数发生了变化。它将根据不同的请求参数返回不同的结果，而不是由于某种状态。即使状态取决于请求，如前面的例子所示。因此，会话标识符在请求中，这可能导致不同的状态，因此导致不同的响应。

# 可缓存

这个约束规定 RESTful Web 服务的响应必须定义自身是否可缓存，以便客户端知道是否应该缓存。如果正确定义，它可以减少开销并提高性能，因为如果能够使用缓存版本，客户端就不会去服务器。

# 统一接口

统一接口是最具区别性的约束。它基本上解耦了架构，使接口与实现分离，就像任何良好的系统一样。

这类似于面向对象编程中的情况：接口分离了实现和声明。这类似于操作系统将用户界面与复杂的实现逻辑分离开来，以保持软件的运行。

统一接口有四个约束。为了理解统一接口，我们需要理解这些约束。

# 资源标识

资源将在请求中被标识。例如，在基于 Web 的 REST 系统中，资源将由 URI 标识。无论资源在服务器上如何存储，它都将与响应中返回给客户端的内容分开。

实际上，服务器上的资源存储是一种实现，但请求和响应是客户端与之交互的方式，因此它就像是对客户端的接口。客户端可以通过这个接口识别资源。客户端所知道的就是它请求和得到的响应。

例如，客户端通常会向 URI 发送请求，并以 HTML、JSON 或 XML 的形式获得响应。这些格式都不是服务器在数据库内部或其他地方存储数据的方式。但对于客户端来说，重要的是它将要访问的 URI 以及它得到的 HTML、JSON 和 XML。

这是客户端的资源，无论它在服务器上如何存储。这就是好处，因为无论服务器的内部逻辑或表示如何更改，对于客户端来说它都将保持不变，因为客户端将请求发送到 URI 并以 HTML、JSON 或 XML 的形式获得响应，而不是它在服务器上的存储方式。这个约束导致资源标识和表示的松散耦合。

# 通过表示来操作资源

这个约束规定客户端应该持有足够的信息来修改或删除资源的表示。例如，在基于 Web 的 REST 系统中，可以使用 HTTP 方法和 URI 对资源执行任何操作。这使得事情变得容易跟踪，因为 API 开发人员不需要为与资源相关的每个端点提供文档。

# 自描述消息

请注意，根据需要向客户端发送代码是可选的，如果不想扩展客户端的功能，则不需要。

# 超媒体作为应用状态的引擎（HATEOAS）

这个约束规定，基于服务器向 REST 客户端提供的内容，REST 客户端应该能够发现所有可用的操作和资源。换句话说，它指出，如果客户端知道一个入口点，那么从第一个端点开始，它应该能够发现与该资源相关的其他相关端点。例如，如果客户端转到资源的列表端点，那应该包括该列表中资源的链接。如果应用了分页或限制，它应该有链接以转到列表中其余的项目。

如果客户端创建了一个新资源，新资源的链接也应该包含在响应中，这个链接可以用于使用不同的 HTTP 动词进行对该资源的读取、更新和删除操作。对于除了典型的 CRUD 之外的操作，显然会有更多的 URL，因此这些操作的 URL 也应该在响应中，以便从一个入口点发现与资源相关的所有端点。

由于 HATEOAS，一个端点会暴露出与其相关的链接。这减少了对全面 API 文档的需求，尽管不是完全减少，但不需要查看已经暴露的链接的 API 文档。

# 按需发送代码（可选）

这表明服务器可以通过发送可由客户端执行的代码，为 REST 客户端添加更多功能。在网络环境中，一个这样的例子是服务器发送给浏览器的 JavaScript 代码。

让我们举个例子来更好地理解这一点。

例如，Web 浏览器就像一个 REST 客户端，服务器传递 HTML 内容，浏览器呈现。在服务器端，有一些服务器端语言在服务器端执行一些逻辑工作。但是，如果我们想要在浏览器中添加一些逻辑，那么我们（作为服务器端开发人员）将不得不向客户端发送一些 JavaScript 代码，然后执行该 JavaScript 代码。因此，JavaScript 代码是服务器发送给客户端的按需代码，它扩展了 REST 客户端的功能。

由于我们已经定义了 REST 和网络服务，现在我们可以说 RESTful 网络服务是符合 REST 的任何网络服务。

# 分层系统

REST 系统的多层约束

# REST 系统可以有多个层，并且如果客户端请求响应并获得响应，无法区分它是从服务器返回的还是从另一个中间件服务器返回的。因此，如果一个服务器层被另一个替换，除非提供了预期的内容，否则不会影响客户端。简而言之，一个层与其直接交互的下一层之外没有知识。

RESTful 网络服务

现在，我们已经定义了 RESTful 网络服务，我们需要了解 RESTful 网络服务是如何工作的，以及 RESTful 网络服务基于什么，以及为什么它们比其他网络服务（如 SOAP）更受欢迎。

# RESTful 网络服务的约定

RESTful web 服务是基于 RESTful 资源的。RESTful 资源是一个实体/资源，通常存储在服务器上，并且客户端使用 RESTful web 服务请求它。以下是关于 RESTful web 服务中资源的一些特征：

+   它通常被称为 URL 中的名词实体

+   它是唯一的

+   它与数据相关联

+   它至少有一个 URI

如果你还在疑惑什么是资源，可以考虑博客的例子。在博客系统中，**帖子**，**用户**，**类别**或**评论**都可以是资源。在购物车中，**产品**，**类别**或**订单**可以是资源。事实上，任何客户从服务器请求的实体都是资源。

最常见的是，可以对资源执行五种典型操作：

+   列表

+   创建

+   读取

+   更新

+   删除

对于每个操作，我们需要两样东西：URI 和 HTTP 方法或动词。

URI 包含一个名词资源和一个动词 HTTP 方法。要对实体执行某些操作，我们需要一个名词，告诉我们需要执行某些操作的实体是什么。我们还需要指定一个动词，告诉我们要执行什么操作。

对于前面提到的操作，我们使用 HTTP 动词和资源名称的 URL 约定。在下一节中，我们将审查每个操作的 URL 结构和 HTTP 动词。

# HTTP 动词和 URL 结构

以下是如何使用 URI 和 HTTP 动词在资源上执行这些操作的。请注意，在下面提到的操作的 URI 中，您需要用资源名称替换`{resource}`。

# 列表操作

+   **HTTP 方法：**`GET`

+   **URI：**`/{resource}`

+   **结果：**它返回所提到资源类型的列表。在该列表中，它将为资源提供唯一标识符，这些标识符可以用于对特定资源执行其他操作。

# 创建操作

+   **HTTP 方法：**`POST`

+   **URI：**`/{resource}`

+   **参数：**可以在`POST`主体中有多个参数

+   **结果：**这应该在主体中使用参数创建一个新的资源。

+   正如你所看到的，创建和列表的 URI 没有区别，但这两个操作是通过 HTTP 方法区分的，这导致了不同的操作。事实上，HTTP 方法和 URI 的组合告诉我们应该执行哪种操作。

# 读取操作

**HTTP 方法：**`GET`

**URI：**`/{resource}/{resource_id}`

**结果：**这应该根据资源的 ID 返回记录。

这里，`resource_id`将是可以从列表操作结果中找到的资源的 ID。

# 更新操作

可以有两种类型的更新操作：

+   更新特定记录的一些属性

+   用新的完全替换特定记录

执行这两个操作的唯一变化是 HTTP 方法。

使用更新操作，更新资源的一些属性：

**HTTP 方法：**`PATCH`

当要替换整个资源时使用：

**HTTP 方法：**`PUT`

URI 和参数将保持不变：

**URI：**`/{resource}/{resource_id}`

**参数：**可以在查询字符串中有多个参数。最初，人们尝试在主体中传递这些参数，但实际上，使用查询字符串传递`PATCH`和`PUT`参数。

**结果：**这应该根据 HTTP 方法更新或替换资源。

在这里，`resource_id`将是可以从列表操作结果中找到的资源的 ID。实际上，使用`PATCH`或`PUT`不会有任何区别，但基于 REST 标准，应该使用`PATCH`来更新记录的不同属性，而应该使用`PUT`来替换整个资源。

# 删除操作

+   **HTTP 方法：**``DELETE``

+   **URI：**`/{resource}/{resource_id}`

+   **结果：**这应该根据 URI 中的资源 ID 删除资源

如果你现在感到不知所措，不要担心，因为我们刚刚看到了哪种 HTTP 方法和 URI 的组合用于哪些操作。很快，我们将讨论一个案例研究，并看到一些不同资源上的操作以及示例。

在任何其他事情之前，既然我们现在了解了 RESTful 网络服务以及它们的工作原理，现在是了解为什么我们更喜欢使用 RESTful 网络服务而不是其他网络服务的好时机。

# 为什么要使用 RESTful 网络服务？

事实上，RESTful 网络服务并不是我们唯一可以编写的网络服务类型。我们也有其他编写网络服务的方式。还有一些更早的编写网络服务的方式以及一些更近期的方式。我们不会详细讨论其他网络服务，因为这超出了本书的范围，重点在于 RESTful 网络服务以及如何构建它们。

# REST 与 SOAP

REST 的一个旧的替代方案是 SOAP。事实上，当 REST 作为一种替代方案出现时，SOAP 已经存在。一个关键的区别是 SOAP 没有告诉消费者如何访问的特定约定。SOAP 使用 WSDL 来公开其服务。将 WSDL 视为 SOAP 提供的服务的定义。这就是消费者知道 SOAP 基于网络服务提供了什么以及如何消费它们的方式。

另一方面，REST 强调“约定优于配置”。如果你像我们之前所做的那样看 RESTful 网络服务的 URL 结构和 HTTP 动词，你会发现有一个固定的约定。例如，如果你在客户端并且想要创建一个产品，如果你知道它将需要哪些参数，那么你可以通过向`example.com/product`发送`POST`请求来创建它，资源将被创建。如果你想列出所有产品，你可以使用相同的 URL 和`GET`请求。如果你从列表操作中获取产品 ID，你可以简单地使用它们来通过`example.com/product/{product_id}`分别使用`PATCH`和`PUT`或`DELETE`来更新或删除产品。要知道使用哪种 URL 和 HTTP 方法来执行某种操作是如此简单，因为这些是 RESTful 网络服务遵循的一些约定。因此，客户端端只需遵循这些约定，对于简单的任务就不需要大量的文档。

除此之外，无状态性的简单性、关注点的分离和可缓存性是我们已经详细了解的 RESTful 网络服务的其他优点之一。

# HTTP 方法的性质

由于我们将主要处理 HTTP 上的 URL 和使用 HTTP 方法，最好花一些时间了解 HTTP 方法的性质。

我们还应该了解，HTTP 方法实际上并不是通过自身进行任何类型的列举、创建或修改。这只是一种约定，使用特定的 HTTP 方法和 URL 模式进行特定的操作。这些方法本身并不执行任何操作，而是取决于服务器端开发人员。这些方法可以根据开发人员编写的代码进行任何操作。

当我们谈论 HTTP 方法的性质时，这是关于遵循的约定和标准。毕竟，RESTful 网络服务是关于优先选择约定而不是配置。今天的 HTTP 和 REST 的基础就在于这些约定，而在编写 RESTful 网络服务时，我们将遵循这些约定。

# 安全/不安全的 HTTP 方法

HTTP 方法可以是安全的或不安全的。安全的意思是这些方法不会改变服务器上的任何资源，而不安全的意思是这些方法预期会改变服务器上的一些资源。因此，我们有`GET`作为唯一的安全方法，因为它不预期在服务器上做任何改变，而其他方法如`PUT`、`POST`、`PATCH`和`DELETE`被认为是不安全的方法，因为它们预期在服务器上做一些改变。

# 幂等和非幂等方法

有些方法可以实现相同的结果，无论我们重复相同的操作多少次。我们认为`GET`、`PUT`、`PATCH`和`DELETE`是幂等方法，因为无论我们重复调用这些方法多少次，结果总是相同的。例如，如果您使用`GET example.com/books`，它将始终返回相同的书籍列表，无论您用`GET`方法调用这个 URL 多少次。然而，如果用户在数据库中放入其他东西，那么在列出中可能会有不同的结果，但为了声明某些方法是否幂等，我们不考虑由于外部因素而导致结果的变化，而是考虑方法调用本身。同样，如果您使用`PUT`或`PATCH`，比如`PATCH example.com/books/2?author=Ali`，无论您用相同的参数多少次调用这个方法，结果始终相同。

对于`DELETE`也是一样的。无论您多少次在相同的资源上调用`DELETE`，它只会被删除一次。然而，对于`DELETE`，它也可能基于实现而有所不同。这取决于您作为程序员想要如何实现。您可能希望第一次`DELETE`并给出成功的响应，而在后续调用中，您可以简单地给出 404，因为资源已经不存在。

`POST`是非幂等的，因为它在服务器上创建一个新资源，响应至少有一个唯一的属性（通常是资源的 ID），即使在相同的请求参数的情况下，所有其他属性都相同。

到目前为止，我们已经了解了 RESTful web 服务的约定、URL 模式、HTTP 方法和 HTTP 方法的性质。然而，这主要是关于请求。URL 和 HTTP 方法都是与请求相关的点。我们还没有看过响应，所以现在让我们来看一下。

# HTTP 响应

请求的目的是获得响应，否则就没有用处，考虑到我们还需要了解对请求期望的响应类型。在这个上下文中，有两件事情我们将讨论：

+   响应类型

+   响应代码

# 响应类型

在当前世界中，许多人认为 RESTful web 服务的响应必须是 JSON 或包含 JSON 字符串的文本。然而，我们也可以在 RESTful web 服务请求的响应中使用 XML。许多人使用 JSON 作为响应，因为它轻量且易于解析。但与此同时，这只是一种偏好，取决于需求，与 REST 标准无关。

XML 和 JSON 都是格式化数据的方式。XML 代表可扩展标记语言，具有标记语法。而 JSON 代表 JavaScript 对象表示法，具有类似 JavaScript 对象的语法。要更好地理解 JSON，请查看[`www.json.org/`](http://www.json.org/)

我们将很快看一个博客的案例研究，并看到请求和响应的例子。在这本书中，我们将使用 JSON 作为响应类型，因为 JSON 比 XML 更简单。在开发新应用程序时，我们大多使用 JSON，因为它轻量且易于理解。正如您在以下示例中所看到的，JSON 中的相同数据比 XML 简单得多，只包含重要的内容。

在这里，我们试图展示具有一个或多个作者的书籍的数据：

XML：

```php
<books>
  <book>
    <name>Learning Neo4J</name>
    <authors>
      <author>Rik Van Bruggen</author>
    </authors>
  </book>
  <book>
    <name>
     Kali Linux – Assuring Security by Penetration Testing
    </name>
    <authors> 
      <author>Lee Allen</author>
      <author>Tedi Heriyanto</author>
      <author>Shakeel Ali</author>
    </authors>
 </book>
</books>
```

现在，让我们在 JSON 中看同样的例子：

```php
{
books: [
  {
    name:"Learning Neo4J",
    authors:["Rik Van Bruggen"]
  },
  {
    name:"Kali Linux – Assuring Security by Penetration Testing",
    authors:["Lee Allen", "Tedi Heriyanto", "Shakeel Ali"]
  }
 ]
}
```

您可以清楚地从前面的例子中看到，XML 和 JSON 都传达相同的信息。然而，在 JSON 中，这更容易，而且需要更少的词来显示相同的信息。

因此，在本书的其余部分，我们将使用 JSON 作为我们的 RESTful web 服务的响应类型。

# 响应代码

响应代码，更为人所知的是 HTTP 状态代码，告诉我们请求的状态。如果 HTTP 请求成功，HTTP 状态代码是 200，表示 OK。如果有服务器错误，它返回 500 状态代码，表示内部服务器错误。如果请求中有任何问题，HTTP 状态代码是 400 及以上，其中 400 状态代码表示错误的请求。在重定向的情况下，响应代码是 300 及以上。

要查看完整的响应代码列表及其用法，请参见[`en.wikipedia.org/wiki/List_of_HTTP_status_codes`](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes)

我不会详细介绍，因为这将是多余的，因为所有这些信息已经在前面提到的维基百科链接中都可以找到。然而，我们将在后续讨论不同的状态代码。

# 案例研究 - 博客的 RESTful web 服务端点

为了理解 RESTful web 服务，让我们以博客为案例研究，在博客中讨论资源/实体。我们将开始定义博客资源的要求和端点 URL，然后定义我们应该对这些请求做出怎样的响应。因此，这些端点和响应定义将帮助我们理解 RESTful web 服务端点应该是什么样子，以及响应应该是什么样子。在后面的章节中，我们将更多地讨论这些端点的实现，因此这些定义将作为下一章的 API 文档。然而，为了简单起见，我们现在将保持最小限度，并在以后添加更多属性。

尽管基于 HATEOAS，RESTful web 服务应该返回到下一个端点的链接，并且有一些约定告诉我们其他端点的信息，但 API 文档仍然很重要。API 消费者（客户端开发人员）和 API 提供者（服务器端开发人员）应该就此达成一致，以便两者可以并行工作，而不必等待对方。然而，在现实世界中，我们不必为基本的 CRUD 操作编写 API 文档。

在典型的博客中，最常见的资源是文章和评论。还有其他资源，但现在我们将讨论这两个资源，以便理解 RESTful web 服务。请注意，我们不考虑与身份验证相关的内容，但将在后面的章节中进行讨论。

如果客户端和服务器端团队属于同一组织，共同开发一个应用程序，那么由客户端团队创建这样的文档是个好主意，因为服务器端团队只是为客户端提供服务。

# 博客文章

在这里，我们列出了博客文章及其端点的要求。对于这些端点，我们将编写一个请求和一个响应。

# 要求

可以创建、修改、访问和删除博客文章。还应该有一种方法列出所有博客文章。因此，我们将列出博客文章的端点。

# 端点

以下是博客文章的端点：

# 创建博客文章

+   **请求**：`POST /posts HTTP/1.1`

+   **主体参数**：

内容：这是一篇很棒的文章

标题：很棒的文章

+   **回应**：

```php
{id:1, title:"Awesome Post", content:"This is an awesome post", link: "/posts/1" }
```

+   **响应代码**：201 Created

这里`POST`是方法，`/posts`是 URL（服务器名称后的路径），HTTP 1.1 是协议。我们将继续以相同的方式提及后续示例中的请求。因此，请求的第一部分是 HTTP 方法，第二部分是 URL，第三部分是协议。

响应代码告诉客户端资源已成功创建。如果请求参数被错误地省略，响应代码应为**400**，表示错误的请求。

# 阅读博客文章

+   **请求**：`GET /posts/1 HTTP/1.1`

+   **回应**：

```php
{id:1, title:"Awesome Post", content:"This is an awesome post", link: "/posts/1" }
```

+   **响应代码**：200 OK

注意，如果提供的 ID 对应的博客文章不存在（在当前情况下为 1），它应该返回**404**，表示资源未找到。

# 更新博客文章

+   **请求**：`PATCH /posts/1?title=Modified%20Post HTTP/1.1`

+   **回应**：

```php
{id:1, title:"Modified Post", content:"This is an awesome post", link:"posts/1" }
```

+   **响应代码**：200 OK

请注意，如果提供的帖子 ID（在本例中为 1）不存在，应返回响应代码**404**，表示资源未找到。

此外，由于 PATCH 用于修改记录的所有或一些属性，而 PUT 用于修改整个记录，就像用新记录替换旧记录一样。因此，如果我们使用 PUT 并且只传递一个属性，其他属性将变为空。在 PATCH 的情况下，它只会更新传递的属性，其他属性保持不变。

# 删除博客帖子

+   **请求**：`DELETE /posts/1 HTTP/1.1`

+   **响应**：

```php
{success:"True", deleted_id:1 }
```

+   **响应代码**：`200 OK`

请注意，如果提供的博客帖子 ID（在当前情况下为 1）不存在，应返回**404**，表示资源未找到。

# 列出所有博客帖子

+   **请求**：`GET /posts HTTP/1.1`

+   **响应**：

```php
{
data:[
  {
   id:1, title:"Awesome Post", content:"This is an awesome post", link: "/posts/1" 
  },  
  {
   id:2, title:"Amazing one", content:"This is an amazing post", link: "/posts/2"
  }
 ],
total_count: 2,
limit:10,
pagination: {
    first_page: "/posts?page=1",
    last_page: "/posts?page=1",
    page=1
 }
}
```

+   **响应代码**：`200 OK`

在这里，数据是对象数组，因为有多个记录返回。除了`total_count`之外，还有一个分页对象，目前显示第一页和最后一页，因为记录的`total_count`只有 2。因此，没有下一页或上一页。否则，我们还应该在分页中显示下一页和上一页。

正如您所看到的，分页中也有链接，以及帖子对象中的帖子链接。我们在响应中包含了这些链接，以符合 HATEOAS 约束，该约束规定如果客户端知道入口点，那么应该足以发现相关的端点。

在这里，我们探讨了博客帖子的要求，并定义了它们的端点的请求和响应。在下一个实体/资源中，我们将定义评论的端点和响应。

# 博客帖子评论

在这里，我们列出了博客帖子评论的要求，然后是它们的端点。对于这些端点，我们将编写`请求`和`响应`。

# 要求

帖子上可能有一个、多个或没有评论。因此，可以在博客帖子上创建评论。可以列出博客帖子的评论。可以阅读、修改或删除评论。

让我们为这些要求定义端点。

# 端点

以下是帖子评论的端点：

# 创建帖子的评论

+   **请求**：`POST /posts/1/comments HTTP/1.1`

+   **主体参数**：`comment: An Awesome Post`

+   **响应**：

```php
{id:1, post_id:1, comment:"An Awesome Post", link: "/comments/1"}
```

+   **响应代码**：`201 Created`

在评论的情况下，评论是针对某篇博客文章创建的。因此，请求 URL 也包括`post_id`。

# 阅读评论

+   **请求**：`GET /posts/1/comment/1 HTTP/1.1` 或 `GET /comment/1 HTTP/1.1`

第二个看起来更合理，因为只需要有一个评论的 ID，而不用担心评论的帖子 ID。而且由于评论的 ID 是唯一的，我们不需要有帖子的 ID 来获取评论。因此，我们将继续使用第二个 URL，即`GET /comment/1 HTTP/1.1`。

+   **响应**：

```php
{id:1, post_id:1, comment:"An Awesome Post", link: "/comments/1"}
```

+   **响应代码**：`200 OK`

由于任何评论只能存在于某个帖子中，因此响应也包括`post_id`。

# 更新评论

+   **请求**：`PATCH /comment/1?comment="Modified%20Awesome%20Comment' HTTP/1.1`

+   **响应**：

```php
{id:1, post_id:1, comment:"Modified Awesome Comment", link: "/comments/1"}
```

+   **响应代码**：`200 OK`

在这里，我们使用 PATCH，因为我们想要更新评论的单个属性。此外，您可以看到在新评论中传递了`%20`。因此，`%20`只是空格的替换，因为 URL 不能包含空格。因此，在 URL 编码中，空格应始终被`%20`替换。

# 删除帖子评论

+   **请求**：`DELETE /comments/1 HTTP/1.1`

+   **响应**：

```php
{success:"True", deleted_id:1 }
```

+   **响应代码**：`200 OK`

请注意，如果提供的帖子评论 ID（在当前情况下为 1）不存在，应返回**404 Not Found**。

# 列出特定帖子的所有评论

+   **请求**：`GET /posts/1/comments HTTP/1.1`

+   **响应**：

```php
{
data:[
  {
   id:1, comment:"Awesome Post", post_id:1, link: "/comments/1" 
  }, {
   id:2, comment:"Another post comment", post_id:1, link: "/comments/2"
  } 
 ], 
 total_count: 2,
 limit: 10,
 pagination: {
 first_page: "/posts/1/comments?page=1",
 last_page: "/posts/1/comments?page=1",
 page=1 
 } 
}
```

+   **响应代码**：`200 OK`

正如你所看到的，帖子的评论列表与博客帖子的列表非常相似。它以相同的方式显示`total_count`和分页。它现在显示第一页和最后一页，因为记录的`total_count`只有 2。所以没有下一页或上一页。否则，我们还应该在分页中显示下一页和上一页的链接。

通常，在博客上看不到评论的分页，但最好保持一致，在列表中加入分页。因为一篇帖子可能有很多评论，我们应该对其进行一些限制，所以我们需要分页。

# 更多资源

虽然我们已经尝试以实例的方式了解 RESTful 网络服务，但这里还有一些其他有趣的资源。

Roy Fielding 介绍 REST 的论文：

[`www.ics.uci.edu/~fielding/pubs/dissertation/top.htm`](http://www.ics.uci.edu/~fielding/pubs/dissertation/top.htm)

Roy Fielding 的回应的小组讨论：

[`groups.yahoo.com/neo/groups/rest-discuss/conversations/topics/6735`](https://groups.yahoo.com/neo/groups/rest-discuss/conversations/topics/6735)

这是一个关于 REST 与 SOAP 的有趣讨论：[stackoverflow.com](http://stackoverflow.com)

[`stackoverflow.com/questions/19884295/soap-vs-rest-differences`](http://stackoverflow.com/questions/19884295/soap-vs-rest-differences)

Roy Fielding 谈论 REST：

[`www.youtube.com/watch?v=w5j2KwzzB-0`](https://www.youtube.com/watch?v=w5j2KwzzB-0)

REST 的另一种看法：

[`www.youtube.com/watch?v=RY_kMXEJZfk`](https://www.youtube.com/watch?v=RY_kMXEJZfk)

# 总结

在这一章中，我们了解了什么是 RESTful 网络服务。我们看了应该满足的约束条件，才能称为 RESTful 网络服务。然后我们了解到 REST 是一种架构，是一种构建东西的方式，它更青睐约定而不是配置。我们看了 HTTP 动词（方法）并看了 URL 约定。我们了解到这些只是约定。HTTP 动词和 URL 在 RESTful 网络服务中使用；否则，开发人员始终可以提供预期的行为，因为 REST 有约定，这些约定只是被视为标准，但它不提供任何实现。

在这一章中，我们没有讨论 RESTful 网络服务的实现。我们只考虑了一个典型博客的案例研究，并且以博客的两个资源为例，定义了它们的端点和预期的响应。我们还看了 HTTP 响应代码，但我们没有编写实际的代码来实现这些 RESTful 网络服务。我们定义了这些端点，所以我们将在下一章看到它们的实现。

由于这本书是关于在 PHP7 中构建 RESTful 网络服务，下一章我们将看一下 PHP7 中的新功能。PHP7 并没有提供任何特定于 RESTful 网络服务的功能，但我们将利用 PHP7 中的一些新功能来编写更好、更干净的代码来构建 RESTful 网络服务。

如果你已经很了解 PHP7，并且不想此刻深入研究，你可以跳过第二章，*PHP7，编写更好的代码*，并开始第三章，*创建 RESTful 端点*，在那里我们将构建 RESTful 网络服务。


# 第二章：PHP7，编写更好的代码

PHP7 带来了许多新功能和变化。然而，它们中没有一个是专门针对 REST 或 Web 服务的。事实上，REST 与语言结构没有直接关系。这是因为 REST 是一种架构，而语言是为了提供实现而存在的构造。那么，这是否意味着 PHP7 有一些构造或功能可以使这种实现更好？是和否。这取决于我们对实现的理解。

如果我们的意思只是获取一个请求并返回一个响应，那么不，没有这样的特定功能。但是，任何 RESTful Web 服务都与一个实体相关联，而一个实体可以有自己的逻辑。因此，为了为该实体提供 RESTful Web 服务，我们还需要编写该逻辑。为此，我们需要编写更多的 PHP 代码，而不仅仅是获取请求并返回响应。因此，为了保持代码简单和清晰，是的，PHP7 为我们提供了许多东西。

我假设你已经掌握了 PHP 的基础知识，因为了解 PHP 基础知识是本书的先决条件。因此，我们不会看 PHP5。在本章中，我们将看一下许多 PHP7 的功能和变化，这些功能和变化要么非常重要，要么我们将在我们的代码中使用。我们将直接进入这些功能。我们不会详细介绍安装或升级到 PHP7，因为互联网上有数十个教程可供参考。以下是我们将讨论的功能和变化的列表：

+   标量类型声明

+   返回类型声明

+   空合并运算符

+   太空船运算符

+   组使用语句

+   与生成器相关的新功能

+   生成器返回表达式

+   生成器委托

+   匿名类

+   `Closure::call()`函数

+   错误和异常

+   PHP7.1 功能

+   可空类型

+   对称数组解构

+   `list()`中支持键

+   多捕获异常处理

# 标量类型声明

在 PHP7 中，我们现在可以声明传递给函数的参数的类型。在以前的版本中，它们只能是用户定义的类，但现在它们也可以是标量类型。通过标量类型，我们指的是基本的原始类型，比如`int`、`string`和`float`。

以前，要验证传递给函数的参数，我们需要使用某种`if-else`。因此，我们过去会这样做：

```php
<?php
function add($num1, $num2){
    if (!is_int($num1)){
        throw new Exception("$num1 is not an integer");
    }
    if (!is_int($num2)){
        throw new Exception("$num2 is not an integer");
    }

    return ($num1+$num2);
}

echo add(2,4);  // 6
echo add(1.5,4); //Fatal error:  Uncaught Exception: 1.5 is not an integer
```

在这里，我们使用`if`来确保变量`$num1`和`$num2`的类型是`int`，否则我们会抛出异常。如果你是一个喜欢尽可能少写代码的早期 PHP 开发人员，那么你甚至可能根本不检查参数的类型。然而，如果你不检查参数类型，这可能导致运行时错误。因此，为了避免这种情况，应该检查参数类型，这就是 PHP7 所做的事情。

这是我们现在在 PHP7 中验证参数类型的方式：

```php
<?php
function add(int $num1,int $num2){
    return ($num1+$num2);
}
echo add(2,4); //6
echo add("2",4); //6
echo add("something",4); 
//Fatal error:  Uncaught TypeError: Argument 1 passed to add() must be of the type integer, string given

```

正如你现在所看到的，我们只需将`int`作为类型提示，而不需要单独验证每个参数。如果参数不是整数，它应该抛出异常。然而，你可以看到，当`2`作为字符串传递时，它并没有显示`TypeError`，而是进行了隐式转换，并将其视为`int 2`。这是因为，默认情况下，PHP 代码是在强制模式下运行的。如果启用了严格模式，写`"2"`而不是 2 将导致`TypeError`而不是隐式转换。要启用严格模式，我们需要在 PHP 代码的开头使用`declare`函数。

这是我们可以这样做的方式：

```php
<?php
declare(strict_types=1); 

function add(int $num1,int $num2){
    return ($num1+$num2);
}

echo add(2,4); //6
echo add("2",4); //Fatal error:  Uncaught TypeError: Argument 1 passed to add() must be of the type integer, string given,

echo add("something",4); // Fatal error:  Uncaught TypeError: Argument 1 passed to add() must be of the type integer, string given
```

# 返回类型声明

就像参数类型一样，还有一个返回类型；它也是可选的，但指定返回类型是一种安全的做法。

这是我们可以声明返回类型的方式：

```php
<?php
function add($num1, $num2):int{
    return ($num1+$num2);
}

echo add(2,4); //6
echo add(2.5,4); //6
```

正如你在`2.5`和`4`的情况下所看到的，它应该是`6.5`，但由于我们指定了`int`作为返回类型，它执行了隐式类型转换。为了避免这种情况，以及获得隐式转换而不是错误，我们可以简单地启用严格类型，如下所示：

```php
<?php
declare(strict_types=1);
function add($num1, $num2):int{
    return ($num1+$num2);
}

echo add(2,4); //6
echo add(2.5,4); //Fatal error:  Uncaught TypeError: Return value of add() must be of the type integer, float returned
```

# 空合并运算符

`Null`合并操作符(`??`)是一种语法糖，但非常重要。在 PHP5 中，当我们有一些可能未定义的变量时，我们使用三元运算符如下：

```php
$username = isset($_GET['username']) ? $_GET['username'] : '';
```

然而，现在在 PHP7 中，我们可以简单地写：

```php
$username = $_GET['username'] ?? '';
```

尽管这只是一种语法糖，但它可以节省时间，使代码更清晰。

# 太空船操作符

太空船操作符也是比较的快捷方式，在用户定义的排序函数中非常有用。我不会详细介绍这个，因为它在文档中已经有足够的解释：[`php.net/manual/en/migration70.new-features.php#migration70.new-features.spaceship-op`](http://php.net/manual/en/migration70.new-features.php#migration70.new-features.spaceship-op)。

# 组合使用声明

现在可以在单个`use`语句中导入相同命名空间中的类、函数和常量。以前需要多个`use`语句。以下是一个例子，以便更好地理解它：

```php
<?php
// use statement in Pre-PHP7 code
use abc\namespace\ClassA;
use abc\namespace\ClassB;
use abc\namespace\ClassC as C;

use function abc\namespace\funcA;
use function abc\namespace\funcB;
use function abc\namespace\funcC;

use const abc\namespace\ConstA;
use const abc\namespace\ConstB;
use const abc\namespace\ConstC;

// PHP 7+ code
use abc\namespace\{ClassA, ClassB, ClassC as C};
use function abc\namespace\{funcA, funcB, funcC};
use const abc\namespace\{ConstA, ConstB, ConstC};
```

从这个例子中可以看出，组合使用语句有多么方便，这是显而易见的。使用大括号和逗号分隔的值来组合值，比如`{classA, classB, classC as C}`，这样就可以得到组合的`use`语句，而不是分别为这三个类使用`use`语句，每个类使用三次。

# 与生成器相关的功能

尽管生成器在 PHP5.5 中出现，但大多数 PHP 开发人员不使用它们，很可能也不了解生成器。因此，让我们首先讨论生成器。

# 生成器是什么？

如 PHP 手册所述：

生成器提供了一种简单的方法来实现简单的迭代器，而不需要实现实现迭代器接口的类的开销或复杂性。

好的，这里有一个更详细和易于理解的定义，来自同一来源，[php.net](http://php.net)：

生成器允许您编写使用 foreach 来迭代一组数据的代码，而无需在内存中构建数组，这可能会导致超出内存限制，或需要大量的处理时间来生成。相反，您可以编写一个生成器函数，它与普通函数相同，只是它不是一次返回，而是生成器可以 yield 多次，以便提供要迭代的值。

例如，您可以简单地编写一个返回许多不同数字或值的函数。但问题是，如果许多不同的值意味着数百万个值，那么制作并返回一个包含这些值的数组是不高效的，因为它将消耗大量内存。因此，在这种情况下，使用`generator`更有意义。

要了解，请参阅此示例：

```php
/* function to return generator */
function getValues($max){
    for($i=0; $i<$max; $i++ ){
        yield $i*2;
    }
}

// Using generator
foreach(getValues(99999) as $value){
    echo "Values: $value <br>";
}
```

正如你所看到的，代码中有一个`yield`语句。它就像 return 语句一样，但在生成器中，`yield`不会一次返回所有的值。它只会在每次 yield 执行时返回一个值，并且只有在调用`generator`函数时才会调用 yield。此外，每次 yield 执行时，它都会从上次停止的地方恢复代码执行。

现在我们了解了生成器，让我们看看与生成器相关的 PHP7 功能。

# 生成器返回表达式

正如我们之前所看到的，在调用生成器函数时，它返回的是由 yield 表达式返回的值。在 PHP7 之前，它没有`return`关键字返回一个值。但自 PHP7.0 以来，也可以使用 return 表达式。在这里，我使用了 PHP 文档中的一个例子，因为它解释得很好：

```php
<?php

$gen = (function() {
    yield "First Yield";
    yield "Second Yield";

    return "return Value";
})();

foreach ($gen as $val) {
    echo $val, PHP_EOL;
}

echo $gen->getReturn(), PHP_EOL;
```

它将输出为：

```php
First Yield
Second Yield
return Value
```

因此，它清楚地显示，在`foreach`中调用生成器函数不会返回`return`语句。相反，它只会在每次 yield 时返回。要获取`return Value`，可以使用这个语法：`$gen->getReturn()`。

# 生成器委托

函数可以互相调用，同样，生成器也可以委托给另一个生成器。以下是生成器的委托方式：

```php
<?php
function gen()
{
    yield "yield 1 from gen1";
    yield "yield 2 from gen1";
    yield from gen2();
}

function gen2()
{
    yield "yield 1 from gen2";
    yield "yield 2 from gen2";
}

foreach (gen() as $val)
{
    echo $val, PHP_EOL;
}

/* above will result in output:
yield 1 from gen1
yield 2 from gen1
yield 1 from gen2
yield 2 from gen2 
*/

```

在这里，`gen2()`是在`gen()`中调用的另一个生成器，因此在`gen()`中的第三个 yield，即`yield from gen2();`，将控制转移到`gen2()`。因此，它将开始使用`gen2()`的 yield。

请注意，`yield from`只能与数组、可遍历对象或生成器一起使用。在`yield from`中使用另一个函数（而不是生成器）将导致致命错误。

您可以将其视为在另一个函数中调用函数的方式。

# 匿名类

就像匿名函数一样，现在 PHP 中也有匿名类。请注意，如果需要对象，则很可能我们需要某种特定类型的对象，而不仅仅是随机的，例如：

```php
<?php
class App
{
    public function __construct()
    {
        //some code here
    }
}

function useApp(App $app)
{
    //use app somewhere
}

$app = new App();
useApp($app);
```

请注意，在`useApp()`函数中需要一个特定类型的对象，并且如果它不是一个类，那么这个类型`App`就无法定义。那么我们在哪里以及为什么要使用一个具有特定功能的匿名类？我们可能需要它，以防我们需要传递一个实现某个特定接口或扩展某个父类的类，但只想在一个地方使用这个类。在这种情况下，我们可以使用匿名类。

这是 PHP7 文档中给出的相同示例，这样您就可以更容易地跟进：

```php
<?php
interface Logger {
    public function log(string $msg);
}

class Application {
    private $logger;

    public function getLogger(): Logger {
         return $this->logger;
    }

    public function setLogger(Logger $logger) {
         $this->logger = $logger;
    }
}

$app = new Application;
$app->setLogger(new class implements Logger {
    public function log(string $msg) {
        echo $msg;
    }
});

var_dump($app->getLogger()); //object(class@anonymous)#2 (0) {}
```

正如您所看到的，尽管在`$app->setLogger()`中传递了一个匿名类对象，但它也可以是一个命名类对象。因此，匿名类对象可以被命名类对象替换。但是，当我们不想再次使用同一类的对象时，最好使用匿名类对象。

# Closure::call()

将对象范围与闭包绑定是使用不同对象的闭包的有效方法。同时，它也是在不同位置为对象使用具有不同行为的不同闭包的简单方法。这是因为它在运行时绑定了对象范围与闭包，而不需要继承、组合等。

然而，以前我们没有`Closure::call()`方法；我们有类似于这样的东西：

```php
<?php
// Pre PHP 7 code
class Point{
    private $x = 1; 
    private $y = 2;
}

$getXFn = function() {return $this->x;};
$getX = $getXFn->bindTo(new Point, 'Point');//intermediate closure
echo $getX(); // will output 1
```

但现在有了`Closure::call()`，可以将相同的代码编写如下：

```php
<?php
//  PHP 7+ code
class Point{
    private $x = 1; 
    private $y = 2;
}

// PHP 7+ code
$getX = function() {return $this->x;};
echo $getX->call(new Point); // outputs 1 as doing same thing
```

这两个代码片段执行相同的操作。但是，PHP7+代码是简写的。如果需要将一些参数传递给闭包函数，可以在对象之后传递它们，如下所示：

```php
<?php
// PHP 7+ closure call with parameter and binding

class Point{
 private $x = 1; 
 private $y = 2;
}

$getX = function($margin) {return $this->x + $margin;};
echo $getX->call(new Point, 2); //outputs 3 by ($margin + $this->x)
```

# 错误和异常

在 PHP7 中，大多数错误现在被报告为错误异常。只有少数致命错误会停止脚本执行；否则，如果进行错误或异常处理，它不会停止脚本。这是因为现在`Errors`类实现了`Throwable`接口，就像`Exception`类一样，它也实现了`Throwable`。因此，现在在大多数情况下，通过异常处理可以避免致命错误。

以下是错误类的一些子类：

+   `TypeError`

+   `ParseError`

+   `ArithmeticError`

+   `DivisionByZeroError`

+   `AssertionError`

这是您可以简单捕获错误并处理它的方式：

```php
try {
    fn();
} catch(Throwable $error){
    echo $error->getMessage(); //Call to undefined function fn()
}
```

在这里，`$error->getMessage()`是一个实际返回此消息作为字符串的方法。在我们之前的示例中，消息将类似于：`Call to undefined function fn()`.

这不是您可以使用的唯一方法。以下是在`Throwable`接口中定义的方法列表；您可以在错误/异常处理期间相应地使用它们。毕竟，`Exception`和`Error`类都实现了相同的`Throwable`接口：

```php
interface Throwable
{
    public function getMessage(): string;
    public function getCode(): int;
    public function getFile(): string;
    public function getLine(): int;
    public function getTrace(): array;
    public function getTraceAsString(): string;
    public function getPrevious(): Throwable;
    public function __toString(): string;
}
```

# PHP7.1

到目前为止，我们讨论的前面的功能都是与 PHP7.0 相关的。然而，PHP7 的最新版本是 PHP7.1，因此讨论 PHP7.1 的重要功能也是值得的，至少是我们将在工作中使用的功能，或者是值得知道并在某个地方使用的功能。

要运行以下代码，您需要安装 PHP7.1，因此，您可以使用以下命令：

```php
sudo add-apt-repository ppa:ondrej/php
```

```php
sudo apt-get update
```

```php
(optional) sudo apt-get remove php7.0
```

```php
sudo apt-get install php7.1 (from comments)
```

请记住，这不是官方的升级路径。PPA 是众所周知的，并且相对安全。

# 可空类型

如果我们对参数的数据类型或函数的返回类型进行类型提示，那么重要的是应该有一种方法来传递或返回`NULL`数据类型，而不是作为参数或返回类型进行类型提示。

可能会有不同的情况需要这样做，但我们总是需要在数据类型之前放置一个`?`。假设我们想要对`string`进行类型提示；如果我们想要使其可为空，也就是允许`NULL`，我们只需将其类型提示为`?` string。

例如：

```php
<?php

function testReturn(): ?string
{
    return 'testing';
}

var_dump(testReturn());
// string(10) "testing"

function testReturn2(): ?string
{
    return null;
}

var_dump(testReturn2());
//NULL

function test(?string $name)
{
    var_dump($name);
}

test('testing');
//string(10) "testing"

test(null);
//NULL

test();
// Fatal error:  Uncaught ArgumentCountError: Too few arguments // to function test(),
```

# 对称数组解构

这不是一个重大的功能，但它是`list()`的方便缩写。因此，可以在以下示例中快速看到：

```php
<?php
$records = [
    [7, 'Haafiz'],
    [8, 'Ali'],
];

// list() style
list($firstId, $firstName) = $records[0];

// [] in PHP7.1 is having same result
[$firstId, $firstName] = $records[0];

```

# 对`list()`中的键的支持

正如您在前面的例子中所看到的，`list()`与数组一起工作，并按相同的顺序分配给变量。但是，根据 PHP7.1，`list()`现在支持键。由于`[]`是`list()`的缩写，`[]`也支持键。

以下是前述描述的一个示例：

```php
<?php
$records = [
    ["id" => 7, "name" => 'Haafiz'],
    ["id" => 8, "name" => 'Ali'],
];

// list() style
list("id" => $firstId, "name" => $firstName) = $records[0];

// [] style
["id" => $firstId, "name" => $firstName] = $records[0];
```

在这里，ID`$firstId`在前面的代码执行后将具有`7`，而`$firstName`将具有`Haafiz`，无论是使用`list()`样式还是`[]`样式。

# 多异常捕获处理

这是 PHP7.1 中一个有趣的功能。以前是可能的，但是需要多个步骤来执行。现在，不仅仅是捕获一个异常并处理它，还可以使用多异常捕获处理功能。语法可以在这里看到：

```php
<?php
try {
    // some code
} catch (FirstException | SecondException $e) {
    // handle first and second exceptions
}
```

正如您在这里所看到的，有一个管道符号分隔这两个异常。因此，这个管道符号`|`分隔多个异常。在这个例子中只有两个异常，但可能会有更多。

# 更多资源

我们讨论了 PHP7 和 PHP 7.1（PHP7 的最新版本）的新功能，这些功能我们要么认为很重要要讨论，要么我们将在本书的其余部分中使用。但是，我们没有完全讨论 PHP7 的功能。您可以在[php.net](http://php.net)上找到 PHP7 功能列表：[`php.net/manual/en/migration70.new-features.php`](http://php.net/manual/en/migration70.new-features.php)。

在这里，您可以找到 PHP 7.1 的所有新功能：[`php.net/manual/en/migration71.new-features.php`](http://php.net/manual/en/migration71.new-features.php)。

# 总结

在本章中，我们讨论了重要的 PHP7 功能。此外，我们还介绍了新的 PHP7.1 功能。本章涵盖了本书其余部分将使用的基础知识。请注意，使用 PHP7 功能并不是必需的，但它可以帮助我们高效地编写简化的代码。

在下一章中，我们将开始在 PHP 中创建一个 RESTful API，就像我们在第一章中讨论的那样，*RESTful Web Services, Introduction and Motivation*，同时利用一些 PHP7 的功能。


# 第三章：创建 RESTful 端点

到目前为止，我们已经了解了什么是 RESTful 网络服务。我们还看到了 PHP7 中的新功能，这将使我们的代码更好，更清晰。现在，是时候在 PHP 中实现 RESTful 网络服务了。因此，本章就是关于实现的。

我们已经看到了一个具有博客帖子和评论端点的博客示例。在本章中，我们将实现这些端点。以下是我们将涵盖的主题：

+   在 PHP 中为博客创建 REST API

+   创建数据库模式

+   博客用户/作者表模式

+   博客帖子表模式

+   博客帖子评论模式

+   创建 REST API 的端点

+   代码结构

+   常见组件

+   创建博客文章端点

+   要做

+   可见的缺陷

+   验证

+   认证

+   正确的 404 页面

+   摘要

# 在 PHP 中为博客创建 REST API

要为博客创建 REST API 或 RESTful 网络服务，我们首先需要有博客实体。由于我们将在数据库中存储博客实体并从数据库中获取数据，因此我们首先需要为这些实体创建数据库模式。

# 创建数据库模式

我们将为两个资源/实体创建端点，它们是：

+   博客帖子

+   帖子评论

因此，我们将为这两个资源创建数据库模式。

这是我们为具有帖子和评论的博客设计数据库模式的方式。一个帖子可以有多个评论，评论始终属于帖子。在这里，我们有数据库模式的 SQL。您首先需要创建一个数据库，并且需要运行以下 SQL 来拥有帖子和评论表。如果您还没有创建数据库，请立即创建。您可以通过一些 DB UI 工具创建它，或者您可以运行以下 SQL 查询：

```php
create DATABASE blog;
```

这将创建一个名为`blog`的数据库。

在创建博客帖子表和博客帖子评论表之前，我们需要创建一个*用户*表，该表将存储帖子或评论作者的信息。因此，首先让我们创建一个用户表。

# 博客用户/作者表模式

用户表可以具有以下字段：

+   `id`：它将具有整数类型，将是唯一的，并且将具有自动增量值。 `id`将是用户表的主键。

+   `name`：它将具有`VARCHAR`类型，长度为 100 个字符。在`VARCHAR` 100 的情况下，100 个字符是限制。如果一个条目中的标题少于 100 个字符，比如只有 13 个字符，那么它将占用 14 个字符的空间。这就是`VARCHAR`的工作原理。它占用的空间比值中的实际字符多一个。

+   `email`：电子邮件地址将具有`VARCHAR`类型，长度为 50。电子邮件字段将是唯一的。

+   `password`：密码将具有`VARCHAR`类型，长度为 50。我们将拥有`password`字段，因为稍后，在某个阶段，我们将使用户使用`email`和`password`登录。

可能会有更多字段，但为简单起见，我们现在只保留这些字段。

# 用户表的 SQL

以下是`users`表的 SQL。请注意，我们在示例中使用 MySQL 作为 RDBMS。其他数据库的查询可能会有轻微变化：

```php
CREATE TABLE `blog`.`users` (
 `id` INT NOT NULL AUTO_INCREMENT ,
 `name` VARCHAR(100) NOT NULL ,
 `email` VARCHAR(50) NOT NULL ,
 `password` VARCHAR(50) NOT NULL ,
 PRIMARY KEY (`id`), 
 UNIQUE `email_unique` (`email`))
ENGINE = InnoDB;
```

此查询将创建一个如上所述的帖子表。我们尚未讨论的唯一事情是数据库引擎。此查询的最后一行`ENGINE = InnoDB`将数据库引擎设置为`InnoDB`。此外，在第 1 行，``blog``表示数据库的名称。如果您将数据库命名为除 blog 之外的任何其他名称，请将其替换为您的数据库名称。

我们只会为帖子和评论编写 API 的端点，并不会为用户编写端点，因此我们将使用 SQL 插入查询手动向用户表添加数据。

以下是用于填充`users`表的 SQL 插入查询：

```php
INSERT INTO `users` (`id`, `name`, `email`, `password`)
 VALUES 
(NULL, 'Haafiz', 'kaasib@gmail.com', '$2y$10$ZGZkZmVyZXJlM2ZkZjM0Z.rUgJrCXgyCgUfAG1ds6ziWC8pgLiZ0m'), 
(NULL, 'Ali', 'abc@email.com', '$2y$10$ZGZkZmVyZXJlM2ZkZjM0Z.rUgJrCXgyCgUfAG1ds6ziWC8pgLiZ0m');
```

由于我们正在插入两条记录，包括`name`，`email`和`password`，我们将`id`设置为`null`。由于它是自动递增的，它将自动设置。此外，您可以在两条记录中看到一个长随机字符串。这个随机字符串是密码。我们为两个用户设置了相同的密码。但是，用户不会输入这个随机字符串作为密码。这个随机字符串是用户实际密码的加密版本。用户的密码是`qwerty`。这个密码是使用以下 PHP 代码加密的：

```php
password_hash("qwerty", PASSWORD_DEFAULT, ['salt'=>'dfdferere3fdf34dfdfdsfdnuJ$er']);
/* returns $2y$10$ZGZkZmVyZXJlM2ZkZjM0Z.rUgJrCXgyCgUfAG1ds6ziWC8pgLiZ0m
*/
```

`password_hash()` 函数是 PHP 推荐的加密密码函数。第一个参数是`password`字符串。第二个参数是加密算法。而第三个参数是一个选项数组，我们在其中设置一个随机字符串作为盐。您也可以添加不同的盐。

然而，这个盐需要固定以加密密码，因为这种加密是单向加密。这意味着密码无法解密。因此，每次您需要匹配密码时，您都必须加密用户提供的密码，并将其与数据库中的密码进行匹配。为了匹配用户提供的密码和数据库中的密码，我们需要使用相同的密码函数和相同的参数。

我们现在不会制作用户登录功能，但是以后我们会做。

# 博客文章表模式

博客文章可以有以下字段：

+   `id`：它将是整数类型。它将是唯一的，并且具有自动递增的值。`id`将是博客文章的主键。

+   `title`：它将是`varchar`类型，长度为 100 个字符。在`varchar` 100 的情况下，100 个字符是限制。如果一个帖子标题少于 100 个字符，比如说一个帖子的标题只有 13 个字符，那么它将占用 14 个字符的空间。这就是`varchar`的工作原理。它占用的空间比字段中实际字符多一个字符。

+   `status`：状态将是已发布或草稿。我们将使用`enum`。它有两个可能的值，`published`和`draft`。

+   `content`：内容将是帖子的正文。我们将使用`text`数据类型来存储内容。

+   `user_id`：`user_id`将是整数类型。它将是一个外键，并将与用户表中的`id`相关联。这个用户将是博客文章的作者。

为了简单起见，我们只有这五个字段。 `user_id` 将包含发布者的用户信息。

以下是用于创建帖子表的 SQL 查询：

以下是用于帖子表的 SQL。请注意，我们在示例中使用 MySQL 作为 RDBMS。其他数据库的查询可能会有轻微变化：

```php
CREATE TABLE `blog`.`posts` ( 
 `id` INT NOT NULL AUTO_INCREMENT ,
 `title` VARCHAR(100) NOT NULL , 
 `status` ENUM('draft', 'published') NOT NULL DEFAULT 'draft' ,
 `content` TEXT NOT NULL ,
 `user_id` INT NOT NULL ,
 PRIMARY KEY (`id`), INDEX('user_id')
) 
ENGINE = InnoDB;

```

此查询将创建一个如前所述的帖子表。

现在，我们添加外键来限制`user_id`只能有用户表中存在的值。以下是我们将添加该约束的方式：

```php
ALTER TABLE `posts` 
ADD CONSTRAINT `user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE RESTRICT ON UPDATE RESTRICT;
```

# 博客文章评论模式

博客文章评论可以有以下字段：

+   `id`：它将是`整数`类型。它将是唯一的，并且将具有自动递增的值。`id`将是博客文章的主键。

+   `comment`：它将是`varchar`类型，长度为`250`个字符。

+   `post_id`：`post_id`将是整数类型。它将是与帖子表中的`id`相关联的外键。

+   `user_id`：`user_id` 将是`整数`类型，它将是外键，并将与用户表中的`id`相关联。

在这里，`user_id`是评论的作者/写作者的 ID，而`post_id`是评论所在的帖子的 ID。

以下是用于创建`comments`表的 SQL 查询：

```php
CREATE TABLE `blog`.`comments` ( 
 `id` INT NOT NULL AUTO_INCREMENT ,
 `comment` VARCHAR(250) NOT NULL ,
 `post_id` INT NOT NULL ,
 `user_id` INT NOT NULL ,
 PRIMARY KEY (`id`), INDEX(`post_id`), INDEX(`user_id`)
) ENGINE = InnoDB;
```

为`user_id`和`post_id`添加外键约束：

```php
ALTER TABLE `comments` ADD CONSTRAINT `post_id_comment_foreign` FOREIGN KEY (`post_id`) REFERENCES `posts`(`id`) ON DELETE RESTRICT ON UPDATE RESTRICT; 

ALTER TABLE `comments` ADD CONSTRAINT `user_id_comment_foreign` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE RESTRICT ON UPDATE RESTRICT;
```

通过运行所有这些 SQL 查询，您将设置好大部分 DB 结构，以便继续创建 PHP 中的 RESTful API 端点。

# 创建 RESTful API 端点

在创建特定于资源的 RESTful API 端点之前，让我们首先创建我们将放置代码的目录。在某个地方创建一个`blog`目录，你的`home`目录，在 Linux 中更可取。然后，在`blog`目录中创建一个`api`目录。我们将把所有的代码放在`api`目录中。如果你是一个命令行爱好者或一个经验丰富的 Ubuntu 用户，只需运行以下命令来创建这些目录：

```php
$ mkdir ~/blog //create blog directory
$ cd ~/blog //chang directory to blog directory
$ mkdir api //create api directory inside blog directory ~/blog
$ cd api //change directory to api directory
```

因此，`api`是我们将放置代码的目录。正如你所知，我们将编写与两个资源相关的端点的代码：博客文章和文章评论。在继续编写特定于博客文章的代码之前，让我们首先看看我们将如何构建我们的代码结构。

# 代码结构

代码可以以许多方式编写。我们可以创建不同的文件用于文章和评论，比如`posts.php`和`comments.php`，并让用户从 URL 访问它们；例如，用户可以输入：[`localhost:8000/posts.php`](http://localhost:8000/posts.php)，这将执行`posts.php`中的代码。在`comments.php`中也可以做同样的事情。

这是一个非常简单的方法，但它有两个问题：

+   第一个问题是`posts.php`和`comments.php`将有不同的代码。这意味着，如果我们必须在这些不同的文件中使用相同的代码，我们将需要在这两个文件中写入或包含所有共同的东西。实际上，如果将会有更多的资源，那么我们将需要为每个资源创建一个不同的文件，并且在每个新文件中，我们将需要包含所有共同的代码。尽管现在只有两个资源，但我们也需要考虑可扩展性。因此，在这种方法中，我们将需要在所有文件中具有相同的代码。即使我们只是在所有文件中进行包含或需要，我们也需要这样做。但是，通过最小化要包含或需要的文件，可以解决或减轻这个问题。

+   第二个问题与它在 URL 中的显示方式有关。在 URL 中，提到要使用的事实文件，所以如果在完成我们的端点并且将 API 提供给前端开发人员后，我们需要在服务器上更改文件名怎么办？前端应用程序的网络服务将无法正常工作，除非我们在前端应用程序中更改 URL 中的文件名。这指向了关于我们的请求以及服务器上存储的东西的一个重要问题。这意味着我们的代码将紧密耦合。这不应该发生，因为我们在第一章中所述的 REST 的约束中已经说明了。这个`.php`扩展名不仅暴露了我们在服务器端使用 PHP，而且我们的文件结构也暴露给了所有知道端点 URL 的人。

问题一的解决方案可以是包含和需要语句。尽管，所有文件仍然需要包含或需要语句，如果一个包含语句需要在一个文件中更改，我们将需要在所有文件中进行更改。因此，这不是一个好方法，但第一个问题可以解决。然而，第二个问题更为关键。一些使用 Apache 的`.htaccess`文件进行 URL 重写的人可能会认为 URL 重写可以解决问题。是的，它可以解决请求 URL 和文件系统上文件之间的紧密耦合的问题，但只有在我们使用 Apache 作为服务器时才能起作用。

然而，随着时间的推移，你会看到越来越多的用例，你会意识到这种方式并不是非常可扩展的。在这种情况下，我们没有遵循任何模式，除了在所有资源文件中包含相同的代码。此外，使用`.htaccess`进行 URL 重写可能有效，但不建议将其用作完整的路由器，因为它会有自己的局限性。

那么这个问题的解决方案是什么呢？如果我们可以有一个单一的入口点怎么办？如果所有请求都通过同一个入口点，然后路由到适当的代码呢？那将是一个更好的方法。请求将与帖子或评论相关联，它必须通过同一个单一入口点，而在该入口点，我们可以包含任何我们想要的代码。然后，该入口点将路由请求到适当的代码。这将解决两个问题。此外，事情将按照一种模式进行，因为每个资源的代码将遵循相同的模式。我们刚讨论的这种模式也被称为前端控制器。您可以在 wiki 上阅读有关前端控制器的更多信息：[`en.wikipedia.org/wiki/Front_controller`](https://en.wikipedia.org/wiki/Front_controller)。

现在我们知道我们将使用前端控制器模式，因此我们的入口点将是`index.php`文件。因此，让我们在`api`目录中创建`index.php`。现在，让我们放置一个 echo 语句，以便我们可以测试和运行，并至少使用 PHP 内置服务器看到`hello world`。稍后，我们将在`index.php`文件中添加适当的内容。因此，现在将这放入`index.php`中：

```php
<?php

echo "hello World through PHP built-in server";
```

要测试它，您需要运行 PHP 内置服务器。请注意，您不需要 Apache 或 NGINX 来运行 PHP 代码。PHP 有一个内置服务器，尽管这对测试和开发环境很好，但不建议用于生产。因为我们在本地机器上的开发环境中，让我们运行它：

```php
~/blog/api$ php -S localhost:8000
```

这将使您能够通过 PHP 内置服务器访问`http://localhost:8000`，并输出`hello World`。因此，现在我们准备开始编写实际的代码，使我们的 RESTful 端点正常工作。

# 常见组件

在继续处理端点之前，让我们首先确定并解决在服务所有端点时需要的事情。以下是这些事情：

+   错误报告设置

+   数据库连接

+   路由

打开`index.php`，删除旧的 hello world 代码，并将此代码放入`index.php`文件中：

```php
<?php   ini_set('display_errors', 1); error_reporting(E_ALL);   require __DIR__."/../core/bootstrap.php";
```

在前两行，我们基本上是在确保我们能够看到代码中的错误。真正的魔法发生在最后一条语句中，我们在那里需要`bootstrap.php`。

这只是另一个文件，我们将在`~/blog/core`目录中创建。在博客目录中，我们将创建一个核心目录，因为我们将保留与核心目录中代码执行流程和模式相关的代码部分。这将是与 API 的端点或逻辑无关的代码。这个核心代码将被创建一次，我们可以在不同的应用程序中使用相同的核心。

因此，让我们在`blog/core`目录中创建`bootstrap.php`。以下是我们将在`bootstrap.php`中编写的内容：

```php
<?php   require __DIR__.'/DB.php'; require __DIR__.'/Router.php'; require __DIR__.'/../routes.php';
require __DIR__ .'/../config.php';   $router = new Router; $router->setRoutes($routes);   $url = $_SERVER['REQUEST_URI']; require __DIR__."/../api/".$router->direct($url); 
```

基本上，这将加载所有内容并执行。`bootstrap.php`是我们的应用程序运行的结构。所以让我们深入了解一下。

第一条语句从同一目录（即 core 目录）中需要一个`DB`类。`DB`类也是一个核心类，它将负责与数据库相关的事务。第二条语句需要一个路由器，它将把 URL 定向到适当的文件。第三条需要路由，告诉在哪种 URL 情况下提供哪个文件。

我们将逐一查看`DB`和`Router`类，但让我们首先查看指定路由的`routes.php`。请注意，`routes.php`是特定于应用程序的，因此其内容将根据我们的应用程序 URL 而变化。

以下是`blog/routes.php`的内容：

```php
<?php   $routes = [
  'posts' => 'posts.php',
  'comments' => 'comments.php' ]; 
```

您可以看到它只是填充了一个`$routes`数组。在这里，帖子和评论是我们期望的 URL 的一部分，如果 URL 中有帖子，它将提供`posts.php`文件，如果 URL 中有评论，它将提供`comments.php`。

`bootstrap.php`中的第四个要求是具有应用程序配置，例如`DB`设置。以下是`blog/config.php`的示例内容：

```php
<?php /**
 * Config File */ $db = [
  'host' => 'localhost',
  'username' => 'root',
  'password' => '786' ];
```

现在，让我们逐个查看`DB`和`Router`类，这样我们就可以理解`blog/core/bootstrap.php`中到底发生了什么。

# DB 类

这是`blog/core/DB.php`中`DB`类的代码：

```php
<?php   class DB {    function connect($db)
 {  try {
  $conn = new PDO("mysql:host={$db['host']};dbname=blog", $db['username'], $db['password']);    // set the PDO error mode to exception
  $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);    return $conn;
 } catch (PDOException $exception) {
  exit($exception->getMessage());
 } }  }
```

这个类与数据库相关。现在，我们有一个构造函数，实际上是使用`blog/config.php`中定义的`PDO`和`$db`数组连接到数据库。但是，我们以后会在这个类中添加更多内容。

你可以看到我们在这里使用了一个`PDO`对象：**PDO**（**PHP 数据对象**）。它用于与数据库交互，是一个推荐的方法，因为无论我们想使用哪个数据库，我们只需要更改连接字符串，其余的都会正常工作。这个字符串：`"mysql:host=$host;dbname=blog"`是连接字符串。`DB.php`中的这段代码将创建与数据库的连接，并且这个连接将在脚本结束时关闭。我们在这里使用`try catch`，因为当我们的代码外部触发任何东西时，使用异常处理是很好的。

到目前为止，我们已经查看了`DB`类，`routes.php`（路由关联数组）和`config.php`（设置关联数组）的内容。现在我们需要查看`Router`类的内容。

# 路由器类

这是`blog/core/Router.php`中`Router`类的实现：

```php
<?php   class Router {    private $routes = [];    function setRoutes(Array $routes) {
  $this->routes = $routes;
 }    function getFilename(string $url) {
  foreach($this->routes as $route => $file) {
  if(strpos($url, $route) !== false){
  return $file;
 } } } }
```

`Router`有两个方法，`Router::setRoutes(Array $routes)`和`Router::getFilename()`。`setRoutes()`接受一个路由数组并将其存储。然后，`getFilename()`方法负责决定对哪个 URL 提供哪个文件。我们不是比较整个 URL，而是使用`strpos()`来检查`$route`中的字符串是否存在于`$url`中，如果存在，则返回适当的文件名。

# 代码同步

为了确保我们在同一个页面上，这是你的`blog`目录中应该有的内容：

+   `blog`

+   `blog/config.php`

+   `blog/routes.php`

+   `blog/core`

+   `blog/core/DB.php`

+   `blog/core/Router.php`

+   `blog/core/bootstrap.php`

+   `blog/api`

+   `blog/api/index.php`

+   `blog/api/posts.php`

注意，`blog/api/posts.php`到目前为止还没有任何适当的内容，所以你可以保留任何可以在浏览器中查看的内容，这样你就知道这个内容来自`posts.php`。除此之外，如果你缺少任何东西，那么就将它与本书提供给你的`book.boostrap.php`进行比较。

无论如何，你已经看到了`bootstrap.php`中包含的所有文件的内容，所以现在你可以回头看`bootstrap.php`的代码，以更好地理解事情。这些内容再次放在这里，以便你可以看到：

```php
<?php   require __DIR__ . '/DB.php'; require __DIR__.'/Router.php'; require __DIR__.'/../routes.php';   $router = new Router; $router->setRoutes($routes);   $url = $_SERVER['REQUEST_URI']; require __DIR__."/../api/".$router->getFilename($url);
```

正如你所看到的，这只是包含`config`和`routes`文件以及包含`Router`和`DB`类。在这里，它正在设置`$routes`中传入的路由，就像`routes.php`中写的那样。然后，根据 URL，它获取将提供该 URL 的文件名，并要求该文件。我们使用`$_SERVER['REQUEST_URI']`；它是一个超级全局变量，包含主机名之后的 URL 路径。

到目前为止，我们已经完成了制作应用程序结构的通用代码。现在，如果你的`blog/api/posts.php`包含了像我的`posts.php`一样的代码：

```php
<?php   echo "Posts will come here"; 
```

通过说：`php -S localhost:8000`来启动 PHP 服务器，然后在浏览器中输入：`http://localhost:8000/posts`，你应该会看到：*帖子将在这里显示*。

如果你无法运行它，我建议你回去检查你漏掉了什么。你也可以使用本书提供给你的代码。无论如何，现在有必要在这一点上成功地编写和运行这段代码，因为仅仅阅读是不够的，实践会让你变得更好。

# 创建博客文章端点

到目前为止，我们已经完成了大部分通用代码。所以让我们来看看博客文章端点。在博客文章端点中，第一个是博客文章列表。

博客文章列表端点：

+   URI：`/api/posts`

+   方法：`GET`

因此，让我们用适当的代码替换`posts.php`中的先前代码来提供帖子。为了提供这个，将以下代码放入`posts.php`文件中：

```php
<?php   $url = $_SERVER['REQUEST_URI'];

// checking if slash is first character in route otherwise add it if(strpos($url,"/") !== 0){
  $url = "/$url"; }    if($url == '/posts' && $_SERVER['REQUEST_METHOD'] == 'GET') {
  $posts = getAllPosts();
  echo json_encode($posts); }   function getAllPosts() {
  return [
 [  'id' => 1,
  'title' => 'First Post',
  'content' => 'It is all about PHP'
  ],
 [  'id' => 2,
  'title' => 'Second Post',
  'content' => 'RESTful web services'
  ],
 ]; }
```

在这里，我们正在检查方法是否为`GET`，URL 是否为`/posts`，并且我们正在从名为`getAllPosts()`的函数中获取数据。为了简单起见，我们从一个硬编码的数组中获取数据，而不是从数据库中获取数据。但是，实际上我们需要从数据库中获取数据。让我们添加从数据库获取数据的代码。它将如下所示：

```php
<?php   $url = $_SERVER['REQUEST_URI']; // checking if slash is first character in route otherwise add it  if(strpos($url,"/") !== 0){
  $url = "/$url"; }   $dbInstance = new DB();
$dbConn = $dbInstance->connect($db**);**   if($url == '/posts' && $_SERVER['REQUEST_METHOD'] == 'GET') {
  $posts = getAllPosts($dbConn);
  echo json_encode($posts); }   ;;
function getAllPosts($db) {
 $statement = $db->prepare("SELECT * FROM posts");
 $statement->execute();
 $result = $statement->setFetchMode(PDO::FETCH_ASSOC);
 return $statement->fetchAll();
}
```

如果执行此代码，您将以 JSON 格式获得一个空数组，这是可以的。由于目前在帖子表中没有记录，因此显示为空数组。让我们创建并使用添加帖子端点。

博客帖子创建端点：

+   URI：`/api/posts`

+   方法：`POST`

+   参数：`title`，`status`，`content`，`user_id`

现在，我们只是让这些端点在没有用户身份验证的情况下工作，所以我们自己传递`user_id`。因此，它应该是来自用户表的`id`。

为了使其工作，我们需要在`posts.php`中添加。然后新代码以粗体字显示：

```php
<?php   $url = $_SERVER['REQUEST_URI'];  // checking if slash is first character in route otherwise add it  if(strpos($url,"/") !== 0){
  $url = "/$url"; }    $dbInstance = new DB(); $dbConn = $dbInstance->connect($db);   if($url == '/posts' && $_SERVER['REQUEST_METHOD'] == 'GET') {
  $posts = getAllPosts($dbConn);
  echo json_encode($posts); }   if($url == '/posts' && $_SERVER['REQUEST_METHOD'] == 'POST') {
 $input = $_POST;
 $postId = addPost($input, $dbConn);
 if($postId){
     $input['id'] = $postId;
     $input['link'] = "/posts/$postId";
 }

 echo json_encode($input); **}**     function getAllPosts($db) {
  $statement = $db->prepare("SELECT * FROM posts");
  $statement->execute();
  $result = $statement->setFetchMode(PDO::FETCH_ASSOC);
  return $statement->fetchAll(); }  function addPost($input, $db){
 $sql = "INSERT INTO posts 
 (title, status, content, user_id) 
 VALUES 
 (:title, :status, :content, :user_id)";

 $statement = $db->prepare($sql);

 $statement->bindValue(':title', $input['title']);
 $statement->bindValue(':status', $input['status']);
 $statement->bindValue(':content', $input['content']);
 $statement->bindValue(':user_id', $input['user_id']);

 $statement->execute();

 return $db->lastInsertId();
}
```

正如您所看到的，我们已经放置了另一个检查，因此如果方法是`POST`，它将运行`addPost()`方法。在`addPost()`方法中，正在添加`POST`。我们使用了相同的`PDO`准备和执行语句。

但是，这一次我们也使用了`bindValue()`。首先，在`INSERT`语句中添加一个带有冒号的静态字符串，例如`:title, :status`，然后使用绑定语句将变量与这些静态字符串绑定。那么这样做的目的是什么呢？原因是我们不能信任用户输入。直接将用户输入添加到 SQL 查询中可能导致 SQL 注入。因此，为了避免 SQL 注入，我们可以使用`PDO::prepare()`函数与`PDOStatement::bindValue()`。在`prepare()`函数中，我们提供一个字符串，而`bindValue()`将用户输入与该字符串绑定。因此，这个`PDOStatement::bindValue()`不仅会用输入参数替换这些字符串，还会确保不会发生 SQL 注入。

我们还使用了`PDO::lastInsertId()`。这是为了返回刚刚创建的记录的自增`id`。

在`addPost()`方法中，我们反复使用`bindValue()`方法来处理不同的字段。如果有更多字段，那么我们可能需要反复写更多次。为了避免这种情况，我们将`addPost()`方法的代码更改为：

```php
function addPost($input, $db){    $sql = "INSERT INTO posts 
          (title, status, content, user_id) 
          VALUES 
          (:title, :status, :content, :user_id)";    $statement = $db->prepare($sql);   bindAllValues($statement, $input**);**    $statement->execute();    return $db->lastInsertId(); }
```

您可以看到`PDOStatement::bindValue()`调用被替换为一个`bindAllValues()`函数调用，该函数以`PDOStatement`作为第一个参数，以用户输入作为第二个参数。`bindAllValues()`是我们编写的一个自定义函数，因此这是我们将在同一个`posts.php`文件中编写的`bindAllValues()`方法的实现： 

```php
function bindAllValues($statement, $params){
  $allowedFields = ['title', 'status', 'content', 'user_id'];    foreach($params as $param => $value){
  if(in_array($param, $allowedFields)){
  $statement->bindValue(':'.$param, $value);
 } }    return $statement; }
```

由于我们将其编写为一个单独的通用函数，因此我们可以在多个地方使用它。此外，无论在帖子表中有多少字段，我们都不需要在代码中反复调用相同的`PDOStatement::bindValue()`方法。我们只需在`$allowedFields`数组中添加更多字段，`bindValue()`方法将自动调用。

为了测试`POST`请求，我们不能简单地从浏览器中访问 URL。要测试`POST`请求，我们需要使用某种 REST 客户端或创建并提交一个带有`POST`的表单。REST 客户端是一种更好、更简单的方式。

# REST 客户端

非常流行的 REST 客户端之一是 Postman。Postman 是一个谷歌 Chrome 应用程序。如果您使用 Chrome，那么您可以从这里安装此应用程序：[`chrome.google.com/webstore/detail/postman/fhbjgbiflinjbdggehcddcbncdddomop/related?hl=en`](https://chrome.google.com/webstore/detail/postman/fhbjgbiflinjbdggehcddcbncdddomop/related?hl=en)。

一旦您打开 Postman，您就可以选择方法为 POST 或任何其他方法，然后在选择 Body 选项卡时，您可以设置字段名称和值，然后点击发送。检查 Postman 的以下屏幕截图，其中设置了字段和响应。这将让您了解 Postman 如何用于发送请求：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bd-rst-websvc-php7/img/f2c4dc92-00bf-4465-b0c6-2b8aa9f8ae90.png)

您可以看到通过 Postman 发送了 POST 请求，并且结果成功，正如我们所期望的那样。对于所有端点测试，可以使用 Postman。

在运行基于 POST 的帖子创建端点之后，我们可以再次测试帖子端点的列表，这次它将返回数据，因为现在有一个帖子了。

让我们来看看获取单个帖子、更新帖子和删除帖子的端点。

获取单个帖子端点：

+   URI：`/api/posts/{id}`

+   方法：`GET`

这个带有`GET`方法的 URL 应该根据提供的 ID 返回单个帖子。

为了实现这一点，我们需要做两件事：

+   在这种模式的情况下，添加一个条件和代码，其中方法是`GET`，URL 是这种模式。

+   我们需要编写并调用`getPost()`方法，从数据库中获取单个帖子。

我们需要在`posts.php`中添加以下代码。

首先，我们将添加一个条件和代码来返回单个帖子：

```php
if(preg_match("/posts\/([0-9])+/", $url, $matches) && $_SERVER['REQUEST_METHOD'] == 'GET'){
  $postId = $matches[1];
  $post = getPost($dbConn, $postId);    echo json_encode($post); }
```

在这里，我们正在检查模式是否为`/posts/{id}`，其中`id`可以是任何数字。然后我们调用我们的自定义函数`getPost()`，它将从数据库中获取帖子记录。因此，这是我们将在同一`posts.php`文件中添加的`getPost()`实现：

```php
function getPost($db, $id) {
  $statement = $db->prepare("SELECT * FROM posts where id=:id");
  $statement->bindValue(':id', $id);
  $statement->execute();    return $statement->fetch(PDO::FETCH_ASSOC); }
```

这段代码只是从数据库中获取单个记录作为关联数组，可以从最后一行清楚地看出。除此之外，`SELECT`查询及其执行都足够简单。

更新帖子端点：

+   URI：`/api/posts/{id}`

+   方法：`PATCH`

+   参数：`title`，`status`，`content`，`user_id`

这里的`{id}`将被实际帖子的 ID 替换。请注意，由于我们使用了`PATCH`方法，因此只应更新输入方法中存在的属性。

在这里，我们将`user_id`作为参数传递，但这只是因为我们没有进行身份验证，否则严格禁止将`user_id`作为参数传递。`user_id`应该是经过身份验证的用户的 ID，并且应该在参数中使用而不是获取`user_id`。因为它可以让任何用户通过在参数中传递另一个`user_id`来假装成其他人。

请注意，在使用`PUT`或`PATCH`时，参数应通过查询字符串传递，只有`POST`在正文中有参数。

让我们更新我们的`posts.php`代码以支持更新操作，然后我们将更深入地研究。

以下是要添加到`posts.php`中的代码：

```php
//Code to update post, if /posts/{id} and method is PATCH

if(preg_match("/posts\/([0-9])+/", $url, $matches) && $_SERVER['REQUEST_METHOD'] == 'PATCH'){
  $input = $_GET;
  $postId = $matches[1];
 updatePost($input, $dbConn, $postId);    $post = getPost($dbConn, $postId);
  echo json_encode($post); }

/**
 * Get fields as parameters to set in record * * @param $input
 * @return string
 */ function getParams($input) {
  $allowedFields = ['title', 'status', 'content', 'user_id'];    $filterParams = [];
  foreach($input as $param => $value){
  if(in_array($param, $allowedFields)){
  $filterParams[] = "$param=:$param";
 } }    return implode(", ", $filterParams); }     /**
 * Update Post * * @param $input
 * @param $db
 * @param $postId
 * @return integer
 */ function updatePost($input, $db, $postId){    $fields = getParams($input);    $sql = "
 UPDATE postsSET $fields           WHERE id=':postId'
 ";    $statement = $db->prepare($sql);
 $statement->bindValue(':id', $id); bindAllValues($statement, $input);    $statement->execute();   return $postId;  }
```

首先，它检查 URL 是否符合格式：`/posts/{id}`，然后检查`Request`方法是否为`PATCH`。在这种情况下，它调用`updatePost()`方法。`updatePost()`方法通过`getParams()`方法以逗号分隔的字符串形式获取键值对。然后进行查询，绑定值和`postId`。这与`INSERT`方法非常相似。然后在条件块中，我们回显更新的记录的 JSON 编码形式。这与我们在创建帖子和获取单个帖子的情况下所做的非常相似。

您应该注意的一件事是，我们正在从`$_GET`中获取查询字符串的参数。这是因为在`PATCH`和`PUT`的情况下，参数是通过查询字符串传递的。因此，在通过 Postman 或任何其他 REST 客户端进行测试时，我们需要在查询字符串中传递参数，而不是在正文中传递。

删除帖子端点：

+   URI：`/api/posts/{id}`

+   方法：`DELETE`

这与获取单个博客帖子端点非常相似，但这里的方法是`DELETE`，因此记录将被删除而不是被查看。

以下是要添加到`posts.php`中以删除博客帖子记录的代码：

```php
//if url is like /posts/{id} (id is integer) and method is DELETE

if(preg_match("/posts\/([0-9])+/", $url, $matches) && $_SERVER['REQUEST_METHOD'] == 'DELETE'){
  $postId = $matches[1];
 deletePost($dbConn, $postId);    echo json_encode([
  'id'=> $postId,
  'deleted'=> 'true'
  ]); }

/**
 * Delete Post record based on ID * * @param $db
 * @param $id
 */ function deletePost($db, $id) { $statement = $db->prepare("DELETE FROM posts where id=':id'");
    $statement->bindValue(':id', $id);
    $statement->execute(); }
```

在查看插入、获取和更新帖子端点的代码之后，这段代码非常简单。在这里，主要工作在于`deletePost()`方法，但它也与其他方法非常相似。

有了这个，我们现在已经完成了与端点相关的帖子。然而，现在我们返回的所有数据都不是真正的 JSON，对于客户端（浏览器或 Postman）来说，它仍然被视为字符串，并被视为 HTML。这是因为我们返回的是 JSON，但它仍然是一个字符串。为了告诉客户端将其视为 JSON，我们需要在任何输出之前在标头中指定`Content-Type`。

```php
header("Content-Type:application/json");
```

只是为了确保我们的`posts.php`文件是相同的，这里是`posts.php`的完整代码：

```php
<?php

$url = $_SERVER['REQUEST_URI'];
if(strpos($url,"/") !== 0){
    $url = "/$url";
}
$urlArr = explode("/", $url);

$dbInstance = new DB();
$dbConn = $dbInstance->connect($db);

header("Content-Type:application/json");

if($url == '/posts' && $_SERVER['REQUEST_METHOD'] == 'GET') {
    $posts = getAllPosts($dbConn);
    echo json_encode($posts);
}

if($url == '/posts' && $_SERVER['REQUEST_METHOD'] == 'POST') {
    $input = $_POST;
    $postId = addPost($input, $dbConn);
    if($postId){
        $input['id'] = $postId;
        $input['link'] = "/posts/$postId";
    }

    echo json_encode($input);

}

if(preg_match("/posts\/([0-9])+/", $url, $matches) && $_SERVER['REQUEST_METHOD'] == 'PUT'){
    $input = $_GET;
    $postId = $matches[1];
    updatePost($input, $dbConn, $postId);

    $post = getPost($dbConn, $postId);
    echo json_encode($post);
}

if(preg_match("/posts\/([0-9])+/", $url, $matches) && $_SERVER['REQUEST_METHOD'] == 'GET'){
    $postId = $matches[1];
    $post = getPost($dbConn, $postId);

    echo json_encode($post);
}

if(preg_match("/posts\/([0-9])+/", $url, $matches) && $_SERVER['REQUEST_METHOD'] == 'DELETE'){
    $postId = $matches[1];
    deletePost($dbConn, $postId);

    echo json_encode([
        'id'=> $postId,
        'deleted'=> 'true'
    ]);
}

/**
 * Get Post based on ID
 *
 * @param $db
 * @param $id
 *
 * @return Associative Array
 */
function getPost($db, $id) {
    $statement = $db->prepare("SELECT * FROM posts where id=:id");
    $statement->bindValue(':id', $id);
    $statement->execute();

    return $statement->fetch(PDO::FETCH_ASSOC);
}

/**
 * Delete Post record based on ID
 *
 * @param $db
 * @param $id
 */
function deletePost($db, $id) {
    $statement = $db->prepare("DELETE FROM posts where id=':id'");
    $statement->bindValue(':id', $id);
    $statement->execute();
}

/**
 * Get all posts
 *
 * @param $db
 * @return mixed
 */
function getAllPosts($db) {
    $statement = $db->prepare("SELECT * FROM posts");
    $statement->execute();
    $statement->setFetchMode(PDO::FETCH_ASSOC);

    return $statement->fetchAll();
}

/**
 * Add post
 *
 * @param $input
 * @param $db
 * @return integer
 */
function addPost($input, $db){

    $sql = "INSERT INTO posts 
          (title, status, content, user_id) 
          VALUES 
          (:title, :status, :content, :user_id)";

    $statement = $db->prepare($sql);

    bindAllValues($statement, $input);

    $statement->execute();

    return $db->lastInsertId();
}

/**
 * @param $statement
 * @param $params
 * @return PDOStatement
 */
function bindAllValues($statement, $params){
    $allowedFields = ['title', 'status', 'content', 'user_id'];

    foreach($params as $param => $value){
        if(in_array($param, $allowedFields)){
            $statement->bindValue(':'.$param, $value);
        }
    }

    return $statement;
}

/**
 * Get fields as parameters to set in record
 *
 * @param $input
 * @return string
 */
function getParams($input) {
    $allowedFields = ['title', 'status', 'content', 'user_id'];

    $filterParams = [];
    foreach($input as $param => $value){
        if(in_array($param, $allowedFields)){
            $filterParams[] = "$param=:$param";
        }
    }

    return implode(", ", $filterParams);
}

/**
 * Update Post
 *
 * @param $input
 * @param $db
 * @param $postId
 * @return integer
 */
function updatePost($input, $db, $postId){

    $fields = getParams($input);
    $input['postId'] = $postId;

    $sql = "
          UPDATE posts 
          SET $fields 
          WHERE id=':postId'
           ";

    $statement = $db->prepare($sql);

    bindAllValues($statement, $input);

    $statement->execute();

    return $postId;

}
```

请注意，这段代码非常基础，它有许多缺陷，我们将在接下来的章节中看到。这只是为了给你一个方向，告诉你如何在核心 PHP 中做到这一点，但这并不是最佳方法。

# 要做的事情

由于我们已经完成了 Post CRUD 端点，你需要创建 Comments CRUD 端点。这不应该很困难，因为我们已经在路由中放置了评论，你知道我们将添加`comments.php`类似于`posts.php`。你也可以在`posts.php`文件中查看逻辑，因为`comments.php`将具有相同的操作和类似的代码。所以现在，是你编写`comments.php` CRUD 相关端点的时候了。

# 可见的缺陷

尽管我们在前面的章节中讨论的代码将起作用，但其中存在许多漏洞。我们将在接下来的章节中探讨不同的问题，然而在这里让我们看看其中的三个问题，以及如何解决它们：

+   验证

+   认证

+   404 的情况下没有响应

# 验证

现在在我们的代码中，虽然我们使用了`PDO`准备和`bindValue()`方法，它只是保存了我们免受 SQL 注入的影响。然而，在插入和更新的情况下，我们没有验证所有字段。我们需要验证标题应该是特定限制的，状态应该是草稿或已发布，`user_id`应该始终是用户表中的 ID 之一。

# 解决方案

第一个简单的解决方案是放置手动检查来验证来自用户端的数据。这很简单，但是工作量很大。这意味着它会起作用，但我们可能会漏掉一些东西，如果我们没有漏掉任何检查，那将是很多低级别的细节要处理。

因此，更好的方法是利用社区中已经可用的一些开源包或工具。我们将在接下来的章节中寻找并使用这样的工具或包。我们还将在接下来的章节中使用这样的包来验证数据。

事实上，这不仅仅是关于验证的问题，而且在本章中我们仍然在做很多低级别的工作。因此，我们将看看如何通过使用 PHP 社区中可用的不同工具来最小化我们在低级别工作上的努力。

# 认证

现在，我们让任何人都可以添加、读取、更新和删除任何记录。这是因为没有经过身份验证的用户。一旦有了经过身份验证的用户，我们可以放置不同的约束，比如用户不应该能够删除或更新不同用户的内容等等。

那么为什么我们不简单地使用基于会话的身份验证，将**Session ID**放在 HTTP Only cookie 中呢？这在传统网站上是这样做的。我们启动会话，将用户数据放入会话变量中，会话 ID 存储在 HTTPOnly cookie 中。服务器总是读取那个 HTTP Only cookie，并获取会话 ID 来知道这个用户的会话数据属于哪个用户。这是在 PHP 开发的典型网站中发生的情况。那么为什么在 RESTful web 服务的情况下，我们不简单地使用相同的方法进行身份验证呢？

因为 RESTful web 服务并不仅仅是通过 web 浏览器调用。它可以是任何东西，比如移动设备、另一个服务器，或者可以是 SPA（单页应用）。因此，我们需要一种可以与任何这些东西一起工作的方式。

# 解决方案

一个解决方案是，我们将使用一个简单的令牌，而不是会话 ID。而且，这个令牌将只被发送给客户端，而不是存储在 cookies 中，客户端将始终在每个请求中携带该令牌以识别客户端。一旦客户端在每个请求中携带令牌，无论客户端是移动应用程序、SPA 还是其他任何东西，都不重要。我们将根据令牌简单地识别用户。

现在的问题是如何创建并发送一个令牌？这可以手动完成，但为什么要创建它，如果这已经在开源中可用并由社区测试过呢？事实上，在后面的章节中，我们将使用这样一个包，并使用令牌进行身份验证。

# 适当的 404 页面

现在如果我们要查找的页面或记录不存在，我们没有一个合适的 404 页面。这是因为我们在我们的路由器中没有处理这个问题。路由器非常基础，但同样，这是低级的东西，我们可以在开源中找到这样的路由器。我们在后面的章节中也会使用它。

# 总结

我们创建了一个基本的 RESTful web 服务，并提供了基本的 CRUD 操作。然而，当前代码中存在许多问题，我们将在接下来的章节中看到并解决这些问题。

在本章中，我们编写了 PHP 代码来创建一个基本的 RESTful web 服务，尽管这不是最好的方法--这只是为了给你一个方向。以下是一些资源，你可以从中学习如何编写更好的 PHP 代码。这是 PHP 最佳实践的快速参考：[`www.phptherightway.com/`](http://www.phptherightway.com/)。

为了采用标准的编码风格和实践，你可以阅读 PHP 编码标准和风格：[`www.php-fig.org/`](http://www.php-fig.org/)。

我建议你花一些时间在这两个 URL 上，这样你就可以写出更好的代码。

在下一章中，我们将详细研究这个问题，并识别这段代码中的不同缺陷，包括安全和设计缺陷。同时，我们也会看不同的解决方案。
