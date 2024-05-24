# 使用 PHP7 构建 REST Web 服务（二）

> 原文：[`zh.annas-archive.org/md5/0741f77c4686cccb7feaca7feda46f8b`](https://zh.annas-archive.org/md5/0741f77c4686cccb7feaca7feda46f8b)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：审查设计缺陷和安全威胁

在本章中，我们将回顾我们的工作，我们实现的端点，并将探讨我们当前工作可以改进和应该改进的两个不同方面。我们还将看到：

+   我们的代码结构和设计缺陷

+   安全威胁以及我们如何减轻它们

然后，我们将探讨如何继续实现一个 RESTful API，并对前两节讨论的改进进行深入研究。

# 找出当前代码中的问题

到目前为止，我们已经编写了与博客文章端点相关的代码，并且我让你自己来处理评论相关的端点。如果你还没有做到这一点，那么我坚持你首先这样做，或者至少尝试这样做，因为没有实践，知识不会持续很长时间，所以至少在提供一些代码示例或有一些任务要做时保持练习。

无论如何，在上一章中，我们已经编写了实现 RESTful Web 服务端点的代码，我们将深入研究并确定缺少什么以及需要哪些改进。

# 结构和设计缺陷

现在在我们的代码中，有一些明显的缺陷我们可以确定。

# 缺少查询构建器层

尽管我们使用 PDO，但我们仍然需要编写查询并需要执行许多低级操作，比如意识到 SQL 注入（因此我们必须使用准备语句，然后绑定值）来执行与数据库相关的操作。我们应该使用某种查询构建器层，它可以为我们生成查询。因此，一旦我们有了这个层，我们就不需要一遍又一遍地编写 SQL 查询。

尽管 PDO 使得很容易将一个数据库连接换成另一个，但仍然有一些 SQL 查询需要针对不同的数据库进行更改。事实上，不仅对于更改 DBMS 有好处，而且，拥有一种查询构建器也是节省时间的，因为使用查询构建器，我们不总是处理字符串来构建查询，而是可以使用数组或关联数组来构建查询。

# 不完整的路由器

我们实现的路由器只是路由不同的文件，比如`/posts`是通过`posts.php`来提供的。我们的路由器没有指定`posts.php`的哪个函数将处理该请求。我们是根据 URL 模式从`posts.php`内部指定的。提醒一下，这是`posts.php`中的条件部分：

```php
if($url == '/posts' && $_SERVER['REQUEST_METHOD'] == 'GET') {
    $posts = getAllPosts($dbConn);
    echo json_encode($posts);
}
```

这并不难。我们可以简单地在`router.php`中设置这样的条件，并在`posts.php`中调用适当的函数。然而，如果你还记得我们的`routes.php`文件，它是一个非常简单的文件，包含键值对。为了方便起见，我再次放在这里：

```php
<?php

$routes = [
    'posts' => 'posts.php',
    'comments' => 'comments.php'
];
```

正如你所看到的，我们没有在`routes.php`中指定请求方法，所以我们也需要在`routes.php`中指定。除此之外，我们还需要在`routes.php`中使用正则表达式而不是普通的 URL。在`routes.php`中做到这一点很容易，但我们需要添加实现的实际位置将是`core/router.php`。这是可以做到的，但我们不会这样做。我们不会从头开始制作诸如路由器之类的组件，因为这不是世界上第一次做的事情。那我们该怎么办呢？我们可以使用已经可用的开源组件或包中的路由器。稍后，我们将看到如何重用已经存在的开源包或组件。

# 面向对象编程的使用

我们应该使用面向对象的范式，因为这不仅有助于使代码更好、更清晰，而且随着时间的推移，它还可以使开发更快，因为干净的代码减少了我们编写更多功能或修改代码的摩擦。

# 将配置与实现分开

配置应该更好。我们有一个包含数据库连接信息的`config`文件，这很好，但还有许多其他东西应该在配置中，例如，是否显示错误应该通过`config`文件来控制。

因此，经验法则是我们应该将配置与实现分开。这很重要，这样我们就可以随时更改配置，而不必担心与逻辑等代码实现相关的问题。

# 应该写测试

无论您是编写 RESTful Web 服务还是制作网站，编写测试用例都是非常重要的。为此，代码也必须是可测试的。因此，测试（单元测试）不仅测试代码是否符合要求，还检查代码是否足够灵活和松散耦合。与松散耦合的代码相比，紧密耦合的代码不能那么容易地进行测试。

在代码中编写测试用例也使代码更清晰、更灵活，可以轻松修改。在 Web 服务的情况下，API 测试也很方便。

# 输入验证

如上一章所述，尽管我们使用 PDO 的`prepare()`和`bindValue()`方法避免了 SQL 注入，但我们并没有验证来自输入源的数据。这是因为我们在上一章只是为了理解和学习而编写代码。否则，没有输入验证不仅不方便，而且对应用程序也不安全。

要应用验证，我们可以使用手动检查，或者编写一个验证器，我们可以简单地传递输入参数并根据特定规则进行检查。这种类型的验证器非常方便，但编写一个好的验证器也需要时间，因此最好使用已经存在的开源验证器。正如您所看到的，我们试图编写一个路由器，然后发现了问题。这些问题可以解决，但我们需要编写更多的代码，编写更多的代码需要时间。

在后面的章节中，我们将看到如何使用别人编写的验证器，并将其用于创建 RESTful Web 服务端点。我们不仅试图节省编写代码的时间，而且还试图避免有更多的代码，其维护将成为我们的责任。

# 处理 404 和其他错误

现在，如果博客文章或评论的 URL 或 ID 错误，我们还没有处理 404，所以我们需要处理这个问题，不仅发送未找到的错误，还要发送 HTTP 状态码 404。因此，对于不同的响应，我们需要发送不同的 HTTP 状态码。

# 元信息缺失

现在，没有记录计数，也没有分页。所有记录都显示出来了。所以如果有很多记录，比如说几百万条记录，那么返回所有记录就没有意义了。在这种情况下，我们应该应用分页，并且在响应中应该有一个适当的位置显示元信息。

# 数据库字段抽象

目前，从数据库中获取的所有数据都原样显示给用户。如果字段名称发生变化，客户端开发人员正在使用该数据库字段会怎么样？这也会在客户端出现错误。

如果您记得的话，REST 的一个重要约束是服务器返回给客户端的内容与服务器实际存储数据的方式之间的抽象。因此，我们需要保持这种抽象。在接下来的章节中，我们将看到如何保持这种抽象。

# 安全性

正如你所看到的，我们根本没有应用任何类型的安全性。事实上，我们还没有使所有端点都受到登录保护。但是，在现实世界中，不可能没有登录或身份验证。因此，我们需要使一些端点受到登录保护。

在本章中，我们只会看到如何为我们的端点实现安全性，但我们还不会实现，将在后面的章节中实现。现在我们正在研究如何使一些资源受到登录保护，因为基于此，我们将能够识别其他安全风险。因此，在本章的下一节中，我们将看到身份验证的工作原理。

# 保护 API 端点

首先，我们需要了解身份验证和登录的工作原理。客户端应用程序首次发送登录凭据（通常是电子邮件地址和密码）。基于这些凭据，服务器端的登录端点进行用户登录并返回针对经过身份验证的用户的令牌。该令牌存储在客户端。在每个请求中，客户端都会在请求体或请求头中携带该令牌。可以在以下图表中更清楚地看到。

首先，客户端将使用登录凭据访问服务器上的登录端点：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bd-rst-websvc-php7/img/4c7cf776-46b5-4f69-9ee1-e0d5b2b5d8c1.png)

客户端获得令牌后，将其存储以备后用。然后，每次请求时，客户端都会发送相同的令牌，以便服务器可以将客户端视为经过身份验证的：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bd-rst-websvc-php7/img/6e2fc7a8-9cce-4453-b4f5-a143317c9d10.png)

当服务器发现客户端经过身份验证时，它将返回基于经过身份验证的用户的数据。

如果请求中没有发送令牌，而只允许经过身份验证的用户，则服务器应返回 401 HTTP 状态码，表示未经身份验证或未经授权。

例如，考虑**POST**端点。有一些端点，如创建帖子、修改帖子和删除帖子；这些需要受到保护，因此应该有**Auth 中间件**来保护这些端点，而其他一些**GET**端点，如显示帖子和列出帖子等端点不需要登录保护，因此应该有**Auth 中间件**来保护受保护的端点。具体如下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bd-rst-websvc-php7/img/9f27415b-6938-483e-ad41-e743cec4b566.png)

正如您在此图表中所看到的，服务器将根据提供的身份验证令牌做出响应，**Auth 中间件**只是为了从身份验证令牌中解析用户。但是，如果**Auth 中间件**无法从身份验证令牌中解析用户，它将简单地返回 401 未经授权的错误。

# 什么是身份验证中间件？

Auth 中间件将不过是一小段代码，用于验证身份验证令牌，并尝试解析该身份验证令牌的用户。它只是一小段代码，将附加到路由中的某些端点或返回端点数据的位置。在任何情况下，它都会在端点的实际代码之前执行，并验证并解析来自请求的`auth`令牌的用户。

在第六章中，*用 Lumen 照亮 RESTful Web 服务*，我们将研究中间件，在第七章中，*改进 RESTful Web 服务*，我们将编写身份验证中间件的代码。

# RESTful Web 服务中的常见安全威胁

既然我们已经看到了当前代码中的问题以及我们将如何在一些端点中实现安全性并使用身份验证中间件，现在是时候看看在构建 RESTful Web 服务时需要考虑的常见安全威胁了。

# 使用 HTTPS

HTTPS 是带有 SSL 的 HTTP。由于我们的数据正在互联网上传输，我们需要确保我们的连接是安全的；因此，我们应该使用 HTTPS。HTTPS 的目的是确保服务器是其所声称的，并且数据以加密形式在客户端和服务器之间的安全连接中传输。

如果您不想购买 SSL 证书，因为对您来说成本太高，那么您可以简单地选择[`letsencrypt.org/.`](https://letsencrypt.org/) Let's Encrypt 是一个免费的证书颁发机构。因此，您可以在不支付 SSL 证书费用的情况下使用它。

# 保护 API 密钥/令牌

由于我们的会话将基于令牌，因此我们需要保护认证令牌。有一些需要做的不同的事情：

1.  不要在 URL 中传递访问令牌。

1.  访问令牌过期。

# 不要在 URL 中传递访问令牌

应该将需要发送到服务器的 API 密钥、令牌或其他敏感信息传递到 POST 主体或请求头中，而不是在 URL 中传递，因为这样可以被 Web 服务器日志捕获。

# 访问令牌过期

访问令牌应该在两种情况下过期。首先，注销时应该过期。其次，访问令牌应该在固定的时间后过期，且这段时间不应该太长。令牌过期的原因是，让访问令牌的有效时间更短更安全。如果我们有许多未使用的访问令牌，那么这些令牌被滥用的可能性就更大。

过期时间大约为两个小时或更短。虽然这取决于您想要如何实现，但较短的过期时间更安全。过期并不意味着用户需要重新登录，而是会有一个令牌刷新端点。将使用最后一个过期的令牌针对特定用户来获取新的令牌。请注意，最后一个令牌应该在有限的时间内可用于刷新令牌端点，之后最后一个令牌不应该可用于刷新令牌。否则，令牌过期有何意义。请记住，两种方式之间存在权衡。每次请求都刷新令牌更安全，但会给服务器带来更多开销。因此，您可以根据自己的情况选择哪种方式。

过期令牌的另一种方法是不通过时间来过期，而是在每次请求时刷新令牌。例如，如果使用一个令牌发送请求，服务器将验证该令牌，刷新令牌，并在响应中发送一个新的令牌。因此，旧令牌将不可用。令牌将在每次请求时刷新。可以用两种方式来实现；这取决于您如何偏好。

# 有限范围的访问令牌

限制访问令牌的范围也是一个好主意，以避免未经授权的人获得令牌时出现问题。此外，如果向客户端应用程序提供的服务不针对特定用户或访问权限，那么它仍应该具有某种 API 密钥，以便我们可以确定谁在请求信息。因此，如果有可疑的尝试使用某个 API 密钥访问 API 端点，我们可以简单地撤销特定的 API 密钥，这样它将不再对未来的请求有效。只有当有多个 API 密钥具有有限的访问级别时才可能实现这一点。

# 公共和私有端点

就像公共网页一样，我们也可以为 RESTful 网络服务设置公共端点。在身份验证之前对用户可用的所有端点都不是公共的。有时，我们创建的端点在登录之前或者无需登录即可使用，但它们只能通过我们的应用程序访问。这些端点不是公共的，因此我们不希望其他应用程序可以访问这些端点。为此，我们将使用一些 API 密钥，如前面讨论的那样。

我们可以使用基于`oauth2`的访问令牌。使用`oauth2`访问令牌的一个重要优势是，如果我们正在创建不同的应用程序来访问相似的端点，那么我们可以为不同的应用程序使用不同的访问令牌。

**示例：**我们可以将在线书店 API 公开为 RESTful 网络服务，并且我们可以有两个应用程序：

+   图书销售`app`。给顾客。

+   图书选择`app.`给老师。

现在通过客户端的应用程序，用户可以浏览不同的书籍，加入购物车并购买。而在教师的应用程序中，用户可以浏览和选择不同的书籍，以便稍后购买书籍的人。这两个不同的应用程序将有一些共同的端点和一些不同的端点。但是，我们不希望任何端点对每个人都是公开的。因此，我们可以有两个不同的访问级别，并制作两个不同的移动应用程序，每个应用程序都有不同的 API 密钥，每个应用程序都有不同的访问级别。当用户登录时，我们将返回一个具有有限访问权限的访问令牌。不同的令牌可以根据用户角色具有不同的访问级别。

假设在教师的应用程序中，有些教师只能选择书籍，而另一些教师，比如**HOD**（系主任）也可以购买书籍。因此，在登录后，这两个用户可以具有不同的访问令牌，转换为不同的访问级别。这个访问级别将基于访问令牌，将被转换为已登录的用户，并且我们将根据用户的角色决定访问级别。

# 公共 API 端点

因此，即使在登录之前，这些端点也是私有的。如果我们有一些公共的 API 端点，比如天气预报向每个人提供预报数据。最好还是有一个 API 密钥来跟踪谁在向服务器获取数据，但如果不是这种情况，我们只是在没有任何 API 密钥的情况下提供数据呢？这是否意味着我们是公开提供这些数据，所以我们不需要担心任何事情？实际上，不是。

如果客户端向服务器传递任何信息，最好使用 TLS 来加密数据。除此之外，我们也不能允许任何人不断地命中一个端点；为了公平使用，我们需要应用节流，这意味着 API 端点只能在特定时间段内被一个客户端命中有限次数。

# 不安全的直接对象引用

不安全的直接对象引用是指根据来自请求的数据获取或提供敏感信息。这不仅是 RESTful Web 服务的问题，也是网站的问题。为了理解这一点，让我们举个例子：

假设我们要更改用户的名字或账单地址。最好是将其引用到一个端点，比如：“PATCH /api/users/me?fist_name=Ali（在标头中具有令牌）”，而不是“PATCH /api/users/2?fist_name=Ali（在标头中具有令牌）”。

为了让用户修改自己的数据，它将在标头中具有一个令牌，服务器将确保该用户可以修改记录。但是，哪条记录？在具有“我”的端点中，它将根据令牌获取用户，并修改其`first_name`。

在第二种情况下，我们有用户的`id=2`，因此可以根据用户`id=2`获取或更新用户，这是不安全的，因为用户可以在 URL 中传递任何用户 ID。因此，问题不在于这种类型的 URL，问题在于根据用户输入或客户端请求直接获取或更新记录。无论提供什么用户 ID，如果我们打算修改已登录用户的名字，那么它应该根据令牌获取或更新用户，而不是 URL 中的用户 ID。

# 限制允许的动词

我们需要限制允许的动词。例如，如果 Web 服务端点仅用于读取目的而不用于修改，则在 URL`/api/post/3`上，我们应该只允许“GET 方法/动词”，而不应该允许“PATCH、PUT”、`DELETE`或`POST`。如果有人使用`PATCH`、`PUT`、`DELETE`或`POST`命中`/api/post/3`，它不应该提供服务，而应该返回“405 方法不允许”错误。

然而，如果他们的客户端有访问令牌，并且基于此，用户只被允许使用`GET`方法（尽管还有其他方法可用），而不是其他方法，那么具有该用户的客户端使用其他方法访问相同的 URL，那么应该出现“403 禁止”错误，因为虽然有允许的方法，但基于其角色或权限，当前用户只是不被允许使用。

# 输入验证

似乎输入验证可能与技术无关，但验证输入非常重要，因为在数据库中拥有干净的数据不仅有益，而且还有助于防范诸如 XSS 和 SQL 注入等不同威胁。

实际上，XSS 预防和不同的输入验证是输入验证的重要部分，而 SQL 注入主要是在向数据库输入数据时防止的。另一种需要防范的威胁是 CSRF，但这将通过 API 密钥或身份验证令牌的使用已经得到防范。然而，也可以使用单独的 CSRF 令牌。

# 可重用的代码

我们没有讨论每一个安全威胁，但我们使用了一些需要注意的东西，以避免与安全相关的问题。我们已经讨论了如何保护我们的端点以及如何为 RESTful Web 服务实施身份验证。我们还讨论了我们在上一章中编写的当前代码中的缺陷。

然而，我们还没有编写代码来使我们的代码更好、更安全。我们可以做到这一点，但我们应该明白，已经有很多东西可以利用，而不是从头开始做一切。因此，我们将使用可用的代码，而不是自己用纯 PHP 编写一切。这不仅是为了节省时间，而且是为了使用社区中可用的东西，经过社区的时间测试。

因此，如果我们已经决定使用第三方代码片段、包或类，那么我们应该明白，在 PHP 中没有一个开发人员组在一个框架中编写代码。有许多 PHP 类作为独立类可用。有些是为某些框架编写的。有些是为 WordPress 等开源 CMS 编写的。还有一些包可在 PEAR（PHP 扩展和应用程序存储库）中找到。因此，一个地方可用的代码可能对其他代码无用或不兼容。

事实上，加载不同的代码片段在一起也可能是一个问题，特别是当有很多依赖关系时。

因此，PHP 社区迎来了革命。这不是一个框架、CMS 或开源类或扩展，而是 PHP 的依赖管理器，称为 Composer。我们可以以标准方式安装 Composer 包，Composer 已成为大多数 PHP 流行框架的标准。我们在这里不会更多地讨论 Composer，因为 Composer 是下一章的主题，所以我们将详细讨论它，因为我们将大量使用 Composer 进行包安装、依赖管理、自动加载等。不仅在本书中，而且如果您要在 PHP 中制作任何适当的应用程序，您都需要一个 composer。因此，我们将主要通过 Composer 包使用可重用的代码。

# 总结

我们已经讨论了当前代码中的问题和缺失部分以及安全威胁，并讨论了我们将如何实施身份验证。我们还讨论了我们将使用可重用组件或代码来节省时间和精力。此外，因为代码将由我们自己编写，我们将负责其维护和测试，因此使用开源的东西，这些东西不仅可用，而且在许多情况下经过测试，以及由社区维护，更有意义。出于这个目的，我们将主要使用 Composer，因为它已成为 PHP 中打包和使用可重用包的标准工具。

在下一章中，您将了解更多关于 Composer 的信息。它是什么，它是如何工作的，以及我们如何将其用于不同的目的。

在本章中，我们已经讨论了安全威胁，但我们并没有详细地涵盖它们，因为我们只有一个章节来讨论。但是，Web 应用程序和 RESTful Web 服务的安全性是一个广泛的话题。关于这个话题还有很多东西需要学习。我建议你去查看[`www.owasp.org/index.php/Category:OWASP_Top_Ten_Project`](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)作为一个起点。那里有很多东西可以学到，你也会从不同的角度学到东西。


# 第五章：使用 Composer 进行加载和解析，一个进化

Composer 不仅是一个包管理器，也是 PHP 中的依赖管理器。在 PHP 中，如果你想要重用一个开源组件，标准的做法是通过 Composer 使用开源包，因为 Composer 已经成为了制作包、安装包和自动加载的标准。在这里，我们讨论了一些新术语，比如包管理器、依赖管理器和自动加载。在本章中，我们将详细讨论它们是什么，以及 Composer 为它们提供了什么。

前面的段落解释了 Composer 主要的功能，但 Composer 不仅仅是这样。

在本章中，我们将看到以下内容：

+   Composer 简介

+   安装

+   使用 Composer

+   Composer 作为包和依赖管理器

+   安装包

+   Composer 的工作原理

+   Composer 命令

+   `composer.json`文件

+   `composer.lock`文件

+   Composer 作为自动加载程序

# Composer 简介

PHP 社区有点分裂，有很多不同的框架和库。由于有不同的框架可用，为一个框架编写的插件或包不能在另一个框架中使用。因此，应该有一种标准的方法来编写和安装包。这就是 Composer 的作用。Composer 是编写、分发和安装包的标准方法。Composer 受到了`node.js`生态系统中的**npm**（**Node Package Manager**）的启发。

事实上，大多数开发人员使用 Composer 来安装他们使用的不同包。这也是因为使用 Composer 安装包很方便，因为通过 Composer 安装的包也可以很容易地通过 Composer 进行自动加载。我们将在本章后面讨论自动加载。

如前所述，Composer 不仅是一个包管理器，也是一个依赖管理器。这意味着如果一个包需要某些东西，Composer 将为其安装这些依赖项，然后相应地进行自动加载。

# 安装

Composer 需要 PHP 5.3.2+才能运行。以下是你可以在不同平台上安装 Composer 的方法。

# 在 Windows 上安装

在 Windows 上，安装 Composer 非常容易，所以我们不会详细介绍。你只需要从[getcomposer.org](http://getcomposer.org)下载并执行 Composer 安装程序。这是链接：[`getcomposer.org/Composer-Setup.exe`](https://getcomposer.org/Composer-Setup.exe)。

# 在 Linux/Unix/OS X 上安装

安装 Composer 有两种方式，分别是本地安装和全局安装。你可以通过以下命令简单地安装 Composer：

```php
$ php -r "copy('https://getcomposer.org/installer', 'Composer-setup.php');"
$ php -r "if (hash_file('SHA384', 'composer-setup.php') === '669656bab3166a7aff8a7506b8cb2d1c292f042046c5a994c43155c0be6190fa0355160742ab2e1c88d40d5be660b410') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;"
$ php composer-setup.php
$ php -r "unlink('composer-setup.php');"
```

前面的四个命令分别执行以下任务：

1.  下载 Composer 安装 PHP 文件

1.  通过检查 SHA-384 验证安装程序

1.  运行 Composer 安装程序安装 Composer

1.  删除已下载的 Composer 安装文件

如果你对这个 Composer 安装做了什么很好奇，那就留下第四个命令。你可以看到，安装文件是一个名为`composer-setup.php`的 PHP 文件；你可以简单地打开这个文件并阅读代码。它主要是检查几个 PHP 扩展和设置，并创建`composer.phar`文件。这个`composer.phar`将负责执行 Composer 的任务。我们将很快在本章中看一下 Composer 的功能以及它执行的操作或任务。

使用上述命令，我们已经在本地安装了 Composer。默认情况下，它会在当前目录安装 Composer，这意味着通过安装 Composer 来放置`composer.phar`文件，因为这个`composer.phar`文件执行 Composer 功能。

如果你希望在特定目录中安装 Composer（放置`composer.phar`）或将`composer.phar`名称更改为其他名称，你可以简单地使用不同的参数运行安装，比如：

```php
php composer-setup.php --install-dir=bin --filename=composer
```

还有许多其他参数，你可以在[`getcomposer.org/download/`](https://getcomposer.org/download/)的“安装程序选项”下看到。

如果您已经在本地安装了 Composer，并且文件名为`composer.phar`，您可以通过以下方式简单地通过 PHP 运行它：

```php
php composer.phar
```

这将运行 Composer。如果`composer.phar`不在之前`composer.phar`的相同目录中，则需要附加`composer.phar`文件所在目录的路径。这是因为我们已经在本地安装了 Composer。因此，让我们看看如何全局安装它。

# 全局安装

要在任何地方安装和访问 Composer，我们需要将其放在系统的`PATH`目录中添加的目录中。

为此，我们可以运行以下命令将`composer.phar`移动到一个我们可以全局访问的位置：

```php
sudo mv composer.phar /usr/local/bin/Composer
```

现在，您只需通过运行命令`composer`就可以访问 Composer，并且它将正常工作；不需要其他任何东西。所以，如果您说：

```php
composer -V
```

它将返回类似以下的内容：

```php
composer version 1.4.2 2017-05-17 08:17:52
```

您可以从任何地方运行此命令，因为我们已经全局安装了 Composer。

# Composer 的用法

Composer 是一个依赖管理器，还有其他不同的用途。Composer 用于在解决依赖关系的同时安装软件包。Composer 在自动加载方面也非常出色。Composer 还有更多的用途。在这里，我们将讨论 Composer 的不同用途。

# Composer 作为依赖管理器

Composer 是一个依赖管理器。现在，您可以以一种不需要将第三方依赖项与其一起提供的方式打包您的代码。您只需要告诉它的依赖关系。实际上，您的软件包依赖关系可能有更多的依赖关系，而这些依赖关系也可能有更多的依赖关系。因此，在制作软件包或捆绑包时解决所有这些依赖关系可能会非常繁琐。但是，由于 Composer 的存在，这并不是问题。

由于 Composer 也是一个依赖管理器，因此依赖关系不再是问题。我们只需在一个 JSON 文件中指定依赖关系，Composer 就会解决这些依赖关系。我们将很快看一下该 JSON 文件。

# 安装软件包

如果我们在名为`composer.json`的 JSON 文件中有依赖关系（我们的工作依赖或将要依赖的其他软件包），那么我们可以通过 Composer 安装它们。

PHP 中有很多好的软件包，我们日常工作相关的大部分内容都是可用的，那么谁会想要重新发明轮子并重新创建所有东西呢？因此，要启动一个项目，我们可以通过 Composer 简单地安装不同的软件包，并重用已经存在的大量代码。

现在，问题是，Composer 可以从哪里安装？它可以是互联网上的任何地方吗？还是有一些固定的地方可以安装 Composer 软件包？实际上，可以有多个来源。Composer 安装软件包的一个默认位置是 Packagist [`packagist.org/`](https://packagist.org/)。

因此，我们将从 Packagist 安装一个软件包。假设我们想要从 Packagist 安装一个 PHP 单元测试框架软件包。它在这里可用：[`packagist.org/packages/phpunit/phpunit`](https://packagist.org/packages/phpunit/phpunit)。

因此，让我们使用以下命令进行安装：

```php
composer require phpunit/phpunit
```

您将看到此软件包安装还将导致许多依赖项的安装。在这里，`require`是 Composer 命令，而`phpunit/phpunit`是此软件包在 Packagist 上注册的名称。请注意，我们刚刚讨论了`composer.json`文件，但我们不需要`composer.json`文件来安装此 PHP 单元软件包。实际上，如果我们已经有一些依赖关系，`composer.json`文件是有用的。如果我们现在只需要安装一些软件包，那么我们可以简单地使用`composer require`命令。而且这个`composer require`还会创建一个`composer.json`文件，并将其更新为`phpunit/phpunit`软件包。

这是在运行上述命令后将创建的`composer.json`文件的内容：

```php
{
    "require": {
        "phpunit/phpunit": "⁶.2"
    }
}
```

您可以在 require 对象中看到，它具有包名称的键，然后在冒号后面是 `"⁶.2"`，表示包版本。在这里，包版本以正则表达式给出，表示包版本从 6.2 开始，但这并不是实际安装的版本。安装包及其依赖项后，它们的确切版本将写入 `composer.lock` 文件中。这个文件 `composer.lock` 具有重要意义，所以我们很快将详细了解它。

运行此命令后，您将能够在运行 Composer require 命令的目录中看到另一个目录。这个目录是 `vendor` 目录。在 vendor 目录中，安装了所有的包。如果您查看它，您会发现不仅 PHP 单元存在于 vendor 目录中，而且所有的依赖项和依赖项的依赖项都安装在 vendor 目录中。

# 使用 composer.json 进行安装

除了使用 `composer require`，如果有一个 `composer.json` 文件，我们还可以通过另一个命令安装包。为此，进入另一个目录。我们可以简单地创建一个包含以下内容的 `composer.json` 文件：

```php
{
    "require": {
        "phpunit/phpunit": "⁶.2",
        "phpspec/phpspec": "³.2"

    }
}
```

因此，一旦您有一个名为 `composer.json` 的文件，并且其中包含这些内容，您可以通过运行此命令根据这些版本信息安装这两个包及其依赖项：

```php
composer install
```

这将执行与 Composer require 相同的操作。但是，如果同时存在 `composer.json` 和 `composer.lock` 文件，它将从 `composer.lock` 文件中读取信息，并安装该确切版本，忽略 `composer.json`。

如果要忽略 `composer.lock` 文件并根据 `composer.json` 文件中的信息进行安装，可以删除 `composer.lock` 文件并使用 `composer install`，或者运行：

```php
composer update
```

注意，`composer update` 命令也会更新 `composer.lock` 文件。

如果一个包或库在 Packagist 上不可用，您仍然可以通过其他来源安装该包，为此，您需要在 `composer.json` 文件中输入不同的信息。您可以在这里阅读有关其他来源的详细信息 [`getcomposer.org/doc/05-repositories.md`](https://getcomposer.org/doc/05-repositories.md)。但是，请注意，由于其便利性，Packagist 是推荐的来源。

# 详细了解 composer.json

我们看到的 `composer.json` 文件是最小的。要了解典型的 `composer.json` 文件是什么样的，这里是我最喜欢的 PHP MVC 框架 Laravel 的 `composer.json` 文件：

```php
{
    "name": "laravel/laravel",
    "description": "The Laravel Framework.",
    "keywords": ["framework", "laravel"],
    "license": "MIT",
    "type": "project",
    "require": {
        "php": ">=5.6.4",
        "laravel/framework": "5.4.*",
        "laravel/tinker": "~1.0"
    },
    "require-dev": {
        "fzaninotto/faker": "~1.4",
        "mockery/mockery": "0.9.*",
        "phpunit/phpunit": "~5.7"
    },
    "autoload": {
        "classmap": [
            "database"
        ],
        "psr-4": {
            "App\\": "app/"
        }
    },
    "autoload-dev": {
        "psr-4": {
            "Tests\\": "tests/"
        }
    },
    "scripts": {
        "post-root-package-install": [
            "php -r \"file_exists('.env') || copy('.env.example', '.env');\""
        ],
        "post-create-project-cmd": [
            "php artisan key:generate"
        ],
        "post-install-cmd": [
            "Illuminate\\Foundation\\ComposerScripts::postInstall",
            "php artisan optimize"
        ],
        "post-update-cmd": [
            "Illuminate\\Foundation\\ComposerScripts::postUpdate",
            "php artisan optimize"
        ]
    },
    "config": {
        "preferred-install": "dist",
        "sort-packages": true,
        "optimize-autoloader": true
    }
}
```

我们不会深入研究此文件的明显部分，比如名称、描述等。我们将研究复杂和更重要的属性。

# require 对象

您已经看到 `require` 具有依赖项和版本信息，这些信息由 `composer install` 命令安装。

# require-dev 对象

在 `require-dev` 中，只列出了在开发阶段需要的那些包。在 Composer install 示例中，我们使用了 `phpunit/phpunit` 的示例，但实际上，像 `phpunit` 和 `phpspec` 这样的包只在开发阶段需要，而不是在生产中需要。此外，如果有任何与调试相关的包需要，也可以包含在 `require-dev` 对象中。`composer install` 命令将安装所有在 `require-dev` 中以及 `require` 对象下的包。

但是，如果我们只想安装生产环境中需要的包，可以使用以下命令进行安装：

```php
composer install --no-dev
```

在上述示例中，`composer.json` 中的 `laravel/tinker` 和 `laravel/laravel` 在 `require` 对象中，但 `phpunit`、`mockery` 和 `faker` 是在 `require-dev` 对象中提到的包，因此它们不会被安装。

# autoload 和 autoload-dev

这个 autoload 选项是用来自动加载一个命名空间或一组类到一个目录下，或者简单地加载一个类。这是 Composer 提供的 PHP 自动加载程序的替代方案。这告诉 Composer 在自动加载类时要查找哪个目录。

自动加载属性还有两个属性，即`classmap`和`psr-4`。PSR-4 是一种描述从文件路径自动加载类的规范。您可以在[`www.php-fig.org/psr/psr-4/.`](http://www.php-fig.org/psr/psr-4/)上阅读更多信息。

在这里，PSR-4 指定了一个命名空间，以及这个命名空间应该从哪里加载。在前面的示例中，`App`命名空间应该从`app`目录获取内容。

另一个属性是`classmap`。这用于自动加载不支持 PSR-4 或 PSR-0 的库。PSR-0 是另一种自动加载的标准，但是 PSR-4 是更新的，是推荐的。PSR-0 已经被弃用。

就像`require-dev`类似于`require`一样，`autoload-dev`类似于`autoload`。

# 脚本

脚本基本上在不同事件的数组中具有脚本。脚本对象的所有这些属性都是事件，以及在特定事件上执行的值指定的脚本。不同的属性代表不同的事件，例如`post-install-cmd`表示在安装包后，它将执行`post-install-cmd`属性下的数组中的脚本。其他事件也是一样。在 Composer 文档的此 URL 中，您可以找到所有这些事件的详细信息：[`getcomposer.org/doc/articles/scripts.md#command-events`](https://getcomposer.org/doc/articles/scripts.md#command-events)。

# composer.lock

`composer.lock`的主要目的是锁定依赖项。

正如讨论的那样，`composer.lock`文件非常重要。这是因为当`composer.json`中没有指定特定的确切版本，或者通过`composer require`安装包时没有版本信息时，Composer 会安装该包，并在安装后添加关于该包安装的信息，包括确切的版本。

如果包已经在`composer.lock`中，那么很可能您也在`composer.json`中列出了该包。在这种情况下，您通常通过`composer install`安装该包，Composer 将从`composer.lock`中读取包详细信息和版本信息，并安装确切的版本，因为这就是 Composer 锁定依赖项的方式。

如果您的代码库中没有`composer.lock`文件，`composer install`或`composer require`将安装包，这些包将创建`composer.lock`文件。

如果`composer.lock`文件已经存在，那么 Composer 安装将确保安装`composer.lock`文件中写入的确切版本，并且它将忽略`composer.json`。然而，如前所述，如果您想要更新依赖项并想要在`composer.lock`文件中更新它，那么您可以运行`composer update`。这是不推荐的，因为一旦您的应用程序在特定的依赖项上运行，并且您不想更新，那么`composer.lock`文件就很有用。因此，如果您想锁定依赖项，请不要运行`composer update`命令。

如果您在团队中工作，您必须提交`composer.lock`文件，以便您的团队中的其他成员可以拥有完全相同的包和版本。因此，强烈建议提交`composer.lock`文件，这不是讨论的问题。

我们不会详细讨论`composer.lock`，因为这就是我们需要了解的大部分内容。但是，我建议您打开并阅读一次`composer.lock`。不必理解所有内容，但这会给您一些想法。

它基本上包含已安装的包信息及其依赖项的确切版本。

# Composer 作为自动加载程序

正如您所见，`composer.json`文件中有与自动加载相关的信息，因为 Composer 也负责自动加载。实际上，即使没有指定自动加载属性，Composer 也可以用于自动加载文件。

以前，我们使用`require`或`include`来单独加载每个文件。您不需要单独`require`或`include`每个文件。您只需要要求或包含一个文件，即`./vendor/autoload.php`。这个`vendor`目录是 Composer 的供应商目录，所有的包都放在那里。因此，这个`autoload.php`文件将自动加载所有内容，而不必担心按顺序包含所有文件及其依赖关系。

# 例子

假设我们有一个像这样的`composer.json`文件：

```php
{
  "name": "laravel/laravel",
  "description": "The Laravel Framework.",
  "keywords": [
    "framework",
    "laravel"
  ],
  "license": "MIT",
  "type": "project",
  "require": {
    "php": ">=5.6.4",
    "twilio/sdk": "5.9.1",
    "barryvdh/laravel-debugbar": "².3",
    "barryvdh/laravel-ide-helper": "².3",
    "cartalyst/sentinel": "2.0.*",
    "gocardless/gocardless-pro": "¹.0",
    "intervention/image": "².3",
    "laravel/framework": "5.3.*",
    "laravelcollective/html": "⁵.3.0",
    "lodge/postcode-lookup": "dev-master",
    "nahid/talk": "².0",
    "predis/predis": "¹.1",
    "pusher/pusher-php-server": "².6",
    "thujohn/twitter": "².2",
    "vinkla/pusher": "².4"
  },
  "require-dev": {
    "fzaninotto/faker": "~1.4",
    "mockery/mockery": "0.9.*",
    "phpunit/phpunit": "~5.0",
    "symfony/css-selector": "3.1.*",
    "symfony/dom-crawler": "3.1.*"
  },
  "autoload": {
    "classmap": [
      "app/Models",
      "app/Traits"
    ],
    "psr-4": {
      "App\\": "app/"
    }
  },
  "autoload-dev": {
    "classmap": [
      "tests/TestCase.php"
    ]
  }
}
```

有了那个`composer.json`文件，如果我们运行`composer install`，它将安装所有这些包，然后加载所有这些包和所有类：

```php
      "app/Models",
      "app/Traits"
```

我们只需要包含一个文件，就像这样：

```php
require __DIR__.'/vendor/autoload.php';
```

这将使所有这些包在您的代码中可用。因此，所有这些包，以及我们自己在`app/Models`和`app/Traits`中的`classes/traits`，即使我们没有单独包含所有这些包，也将可用。因此，Composer 也可以作为自动加载程序。

# 用于创建项目的 Composer

我们还可以使用 Composer 从现有包创建一个新项目。这相当于执行两个步骤：

+   克隆存储库

+   在那里运行`composer install`

这意味着它将克隆一个项目并安装它的依赖项。可以使用以下命令完成：

```php
composer create-project <package name> <path on file system> <version info>
```

如果我们想要从一个代码库开始一个项目，这是非常有用的。请注意，文件系统上的路径和版本号不是必需的，但是可选的。

# 例子

要安装一个名为 Laravel 的框架，您可以简单地运行：

```php
composer create-project laravel/laravel
```

在这里，`laravel/laravel`是包。从这可以看出，文件系统上的路径或版本在这里没有提到。这是因为这些参数是可选的。

使用这些参数，该命令将如下所示：

```php
composer create-project laravel/laravel ./exampleproject 5.3
```

# 摘要

Composer 是一种制作和使用可重用组件的标准方法。如今，已经做了很多事情，可以被重用。因此，在 PHP 中，Composer 是一种标准方法。在本章中，我们已经看到了 Composer 的工作原理，它的用途是什么，如何通过它安装包等等。然而，在本章中我们没有涉及的一件事是如何为 Composer 制作包。这是因为我们的重点是如何重用已经可用的 Composer 包。如果您想学习如何创建 Composer 包，那么就从这里开始：[`getcomposer.org/doc/02-libraries.md`](https://getcomposer.org/doc/02-libraries.md)。

如果您想了解更多关于 Composer 的信息，您可以：

1.  去阅读 Composer 文档[`getcomposer.org/doc/`](https://getcomposer.org/doc/)。

1.  打开并开始阅读重要文件。您可以打开并阅读不同的 Composer 文件，比如`composer.json`和`composer.lock`，来自不同的包。

到目前为止，我们已经看到了如何重用 Composer 组件，以避免自己编写所有内容。在下一章中，我们将开始使用这些组件或项目来使我们的 RESTful web 服务更好。


# 第六章：使用 Lumen 照亮 RESTful Web 服务

到目前为止，我们已经在核心 PHP 中创建了一个非常基本的 RESTful Web 服务，并发现了设计和安全方面的缺陷。我们还看到，为了改进，我们不需要从头开始创建所有东西。事实上，使用经过时间考验的开源代码更有意义，以基于更干净的代码构建更好的 Web 服务。

在上一章中，我们已经看到 Composer 是 PHP 项目的依赖管理器。在本章中，我们将使用一个开源的微框架来编写 RESTful Web 服务。我们将在一个活跃开发、经过时间考验并在 PHP 社区中广为人知的开源微框架中完成相同的工作。使用框架而不是几个组件的原因是，一个合适的框架可以为我们的代码提供良好的结构，并且它带有一些基本所需的组件。我们选择的微框架是 Lumen，它是全栈框架 Laravel 的微框架版本。

这是我们打算在本章中涵盖的内容：

+   介绍 Lumen

+   Lumen 提供了什么

+   Lumen 与 Laravel 有什么共同之处

+   Lumen 与 Laravel 有何不同

+   安装和配置

+   数据库迁移

+   在 Lumen 中编写 REST API

+   路由

+   控制器

+   REST 资源

+   Eloquent（模型）

+   关系

+   用户访问和基于令牌的身份验证和会话

+   API 版本控制

+   速率限制

+   用户的数据库种子

+   使用 Lumen 包进行 REST API

+   审查基于 Lumen 的 REST API

+   加密的需求

+   不同的 SSL 选项

+   总结和更多资源

# 介绍 Lumen

Lumen 是全栈框架 Laravel 的微框架版本。在 PHP 社区中，Laravel 是一个非常知名的框架。因此，通过使用 Lumen，我们可以随时将我们的项目转换为 Laravel，并开始使用其全栈功能。

# 为什么使用微框架？

一切都有代价。我们选择了微框架而不是全栈框架，因为尽管全栈框架提供了更多的功能，但为了拥有这些功能，它必须加载更多的东西。因此，为了提供更多功能的奢侈，与微框架相比，全栈框架在性能上必须做出一些妥协。另一方面，微框架放弃了一些构建 Web 服务所不需要的功能，比如视图等，这使得它更快。

# 为什么选择 Lumen？

Lumen 并不是 PHP 社区中唯一的微框架。那么为什么选择 Lumen？有三个主要原因：

+   Lumen 是 Laravel 的微框架，因此我们可以通过一点努力将其转换为 Laravel，并利用其全栈功能。

+   由于 Lumen 是 Laravel 的微框架，它像 Laravel 一样拥有出色的社区支持。一个良好的社区总是一个非常重要的因素。同时，Lumen 能够使用许多与 Laravel 相同的包。

+   除了与 Laravel 的关系，Lumen 在性能方面也非常出色。基于性能，其他替代的微框架可能是 Slim 和 Selex。

# Lumen 提供了什么

正如我们所知，Lumen 是 Laravel 的微框架版本，它提供了许多 Laravel 提供的功能。例如，它是一个 MVC 框架。然而，了解 Lumen 和 Laravel 的共同之处以及 Lumen 没有或具有不同的地方是很重要的。这将让我们对 Lumen 为我们提供了什么有一个很好的了解。

# Lumen 与 Laravel 有什么共同之处

在这里，我没有说 Laravel 和 Lumen 之间的相似之处，因为 Lumen 并不是一个完全不同的框架。我说的是它们之间的共同之处，因为它们有共同的包和组件：这意味着它们在许多情况下共享相同的代码库。

实际上，Lumen 是一种小型、精简的 Laravel。它只是放弃了一些组件，并对一些任务使用不同的组件，比如路由。然而，你总是可以在同一个安装中打开很多组件。有时，甚至不需要在配置中编写一些代码。相反，你只需转到配置文件，取消注释一些代码行，它就开始使用这些组件。

事实上，Lumen 具有相同的版本。例如，如果有 Laravel 的 5.4 版本，Lumen 将具有相同的版本。因此，这些不是两个不同的东西。它们彼此之间有很多相似之处。Lumen 只是为了性能而放弃了一些不必要的东西。然而，如果你只想将为 Lumen 编写的应用程序代码转换为 Laravel，你只需将该代码放入 Laravel 安装中，它应该大部分工作。不需要对应用程序代码进行重大更改。

# Lumen 与 Laravel 有何不同

由于 Lumen 是为微服务和 API 构建的，与前端相关的组件，如 elixir、身份验证 bootstrap、会话和视图等，不是 Lumen 的默认组件，但如果需要的话，可以稍后包含：它在这方面非常灵活。

Lumen 中的路由不同。事实上，它不使用 Symfony 路由器；而是使用一个速度更快但功能较少的不同路由器。这是因为 Lumen 为了速度而牺牲了功能。同样，像 Laravel 一样，没有单独的配置文件。相反，一些配置在`.env`文件中完成，而其他与注册提供程序或别名等相关的配置在`bootstrap/app.php`文件中完成，可能是为了避免为了速度而加载不同的文件。

Lumen 和 Laravel 都有很多包，其中很多都适用于两者。但仍然有一些包主要是为 Laravel 构建的，如果没有一些更改，就无法在 Lumen 中使用。因此，如果你打算安装一个包，请确保它支持 Lumen。对于 Laravel，大多数包都适用于 Laravel，因为 Laravel 更受欢迎，大多数包都是为 Laravel 构建的。

# Lumen 到底提供了什么

你可能认为这就是 Lumen 和 Laravel 之间的区别，但 Lumen 到底提供了什么，让我们能够构建 API？我们将研究一下，但不会详细讨论，因为 Lumen 的文档[`lumen.laravel.com/docs/5.4`](https://lumen.laravel.com/docs/5.4)已经涵盖了这一目的。文档中没有涵盖的是我们如何使用 Lumen 制作 RESTful Web 服务，以及我们可以利用哪些包来使我们的工作和生活更轻松。我们将深入研究这一点。

首先，我们将讨论 Lumen 提供了什么，以便我们了解其不同的组件和工作方式。

# 良好的结构

Lumen 具有良好的结构。由于它源自 Laravel，后者遵循 MVC（模型视图控制器）模式，Lumen 也有模型和控制器层。它没有视图层，因为它不需要视图：它是用于 Web 服务的。如果你不知道什么是 MCV，可以将其视为一种架构模式，其中责任分布在三个层中。模型是一个数据库层，有时也用作业务逻辑层（我们将在后面的章节中讨论模型中应该包含什么）。视图层用于模板相关的内容。控制器可以被认为是一个处理请求的层，同时从模型获取数据并渲染视图。在 Lumen 的情况下，只有模型和控制器层。

Lumen 为我们提供了一个良好的结构，因此我们不需要自己制作。事实上，Laravel 不仅提供 MVC 结构，还提供了**服务容器**，可以很好地解决依赖关系。Lumen 和 Laravel 的结构不仅仅是一个设计模式，而是很好地利用了不同的设计模式。因此，让我们看看 Lumen 还提供了什么，并深入了解服务容器和许多其他主题。

# 单独的配置

在第四章中，*审查设计缺陷和安全威胁*，我们看到配置应该与实现分开，所以 Lumen 为我们做到了这一点。它有单独的配置文件。事实上，它有一个单独的`.env`文件，可以在不同的环境中不同。除了`.env`文件，还有一个配置文件，其中存储了与不同包相关的配置，比如包注册或别名等。

请注意，你可能一开始在 Mac 或 Linux 上看不到`.env`文件，因为它以点开头，所以它会被隐藏。你需要显示隐藏文件，然后你就会看到`.env`文件。

# 路由器

Lumen 具有更好的路由能力。它不仅可以让你告诉哪些 URL 应该由哪个控制器提供，还可以让你告诉哪些 URL 以及使用哪种 HTTP 方法应该由哪个控制器的哪个方法提供。事实上，Lumen 可以指定 RESTful 约定中大多数我们使用的 HTTP 方法。

在为我们的博客示例创建 RESTful web 服务时，我们将看到代码示例。

# 中间件

中间件是在控制器提供请求之前或之后执行的一些操作。中间件可以执行许多任务，比如身份验证中间件、验证中间件等。

Lumen 自带一些中间件，同时我们也可以编写自己的中间件来实现我们的目的。

# 服务容器和依赖注入

服务容器是一个用于依赖注入和依赖解析的工具。开发人员只需告诉哪个类应该在哪里注入，服务容器就会解析并注入该依赖。

如果通过应用程序服务容器创建对象，而不是通过应用程序中的`new`关键字，依赖注入可以用于解析类的任何依赖关系。

例如，Lumen 服务容器用于解析所有 Lumen 控制器。因此，如果它们需要任何依赖项，服务容器负责解析它们。为了更好地理解，考虑以下示例：

```php
class PostController extends Post
{
    public function __construct(Post $post){
        //do something with $post
    }
}
```

在前面的示例中，我只是提到了简单的`Controller`类，在`PostController`构造函数中注入了`Post`类。如果我们已经有另一个对象，我们希望注入而不是实际的`Post`对象，我们也可以这样做。

你可以在解析依赖项之前的任何地方使用以下代码来简单地做到这一点：

```php
$ourCustomerPost = new OurCustomPost();
$this->app->instance("\Post", $ourCustomerPost);
```

现在，如果在类的构造函数或方法中对`Post`进行类型提示，那么`OurCustomPost`类的对象将被注入其中。这是因为`$this->app->instance("\Post", $ourCustomerPost)`告诉服务容器，如果有人要求一个`\Post`的实例，就给他们`$ourCustomerPost`。

请注意，除了控制器解析，如果我们希望服务容器注入依赖项，我们还可以以以下方式创建对象：

```php
$postController = $this->app->make('PostController');
```

因此，在这里，`PostController`将以与 Lumen 本身解析控制器相同的方式解析。请注意，我们使用术语*Lumen*，因为我们正在谈论 Lumen，但大部分内容在 Lumen 和 Laravel 中都是相同的。

如果这听起来有点令人不知所措，不要担心，一旦你开始使用 Lumen 或 Laravel 并在其中进行实际工作，你就会开始理解这一点。

# HTTP 响应

Lumen 内置支持发送不同类型的响应、HTTP 状态码和响应头。这是我们之前讨论过的重要内容。对于 Web 服务来说，这更加重要，因为 Web 服务是由机器使用的，而不是人类。机器应该能够知道响应类型和状态码是什么。这不仅有助于判断是否出现错误或成功，还有助于判断发生了什么类型的错误。您可以在[`lumen.laravel.com/docs/5.4/responses`](https://lumen.laravel.com/docs/5.4/responses)中更详细地了解这一点。

# 验证

Lumen 还提供了对验证的支持；不仅是验证支持，还有内置的验证规则可以开始使用。但是，如果您需要为某个字段编写一些自定义验证逻辑，也可以随时进行编写。在创建我们的 RESTful Web 服务时，我们将深入研究这一点。

# Eloquent ORM

Lumen 带有一个名为 Eloquent 的 ORM 工具。为了便于理解，您可以将其视为与数据库相关的高级库，通过它可以在不涉及关系的大量细节的情况下获取数据。在我们使用它时，我们将很快详细了解它。

# 数据库迁移和填充

如今，开发人员并不总是应该使用 SQL 或数据库工具来创建数据库。代码中应该有一些东西可以在版本控制系统下运行，并且团队中的每个开发人员都可以在自己的系统或服务器上运行。这个东西现在被称为迁移。编写迁移的另一个好处是它不是针对一个特定的数据库。相同的迁移可以在 MySQL 和 PostgreSQL 上工作。迁移涉及数据库的结构变化。

迁移是用于创建或修改数据库表，或创建不同的约束或索引。同样，种子数据用于向数据库中插入数据。

# 单元测试

单元测试也是确保代码质量的非常重要的部分，Lumen 也提供了对此的支持。我们不会在本章中编写测试，但我们将在以后的章节中编写测试。

请注意，我们还没有看到 Lumen 提供的每一项功能，我们只看到了一些我们可能需要了解的组件，以便在 Lumen 中创建 RESTful Web 服务。有关 Lumen 的更多详细信息，您可以简单地查阅其文档：[`lumen.laravel.com/docs/5.4`](https://lumen.laravel.com/docs/5.4)。

# Lumen 的安装

要安装 Lumen，如果您已经安装了 composer，只需运行以下命令：

```php
composer create-project --prefer-dist laravel/lumen blog
```

这将创建一个名为`blog`的目录，其中包含 Lumen 的安装。如果您遇到任何困难，请参阅此处的 Lumen 安装文档：[`lumen.laravel.com/docs/5.4`](https://lumen.laravel.com/docs/5.4)。

我建议在安装后，您去查看名为 blog 的这个 Lumen 项目的目录结构，因为当我们执行不同的任务时，这将更有意义。

# 配置

如果您查看我们安装 Lumen 的安装目录，在我们的案例中是`blog`，您会看到一个`.env`文件。Lumen 将配置保存在`.env`文件中。您可以看到有一个选项`APP_KEY=`，如果在`.env`文件中尚未设置，请设置它。这只需要设置为一个具有 32 个字符长度的随机字符串。

由于`.env`文件以点开头，在 Linux 或 Mac 中，此文件可能是隐藏的。为了查看此文件，您需要查看隐藏文件。

然后，要运行 Lumen，只需使用以下命令：

```php
php -S localhost:8000 -t public
```

如您所见，我们正在使用 PHP 内置服务器，并在项目中给出`public`目录的路径。这是因为入口点是`public/index.php`。然后，在[`localhost:8000/`](http://_wp_link_placeholder/)上，您应该看到`Lumen (5.4.6) (Laravel Components 5.4.*)`。

如果您看到错误`Class 'Memcached' not found`，这意味着您没有安装 Memcached，而 Lumen 正在尝试在某个地方使用它。如果您不需要 Memcached，您可以简单地转到`.env`文件并更改`CACHE_DRIVER=file`。

现在我们已经安装和配置了 Lumen，我们将在 Lumen 中为博客示例创建相同的 RESTful Web 服务。

您还需要在`bootstrap/app.php`中取消注释以下内容。

```php
//$app->withFacades();   //$app->withEloquent();
```

正如先前所述，Lumen 在这些功能不可用时可能会更快。但我们取消了注释，因为我们还需要利用 Lumen 的一些功能。那么，这两行代码到底是做什么的呢？第一行代码启用了 Facades 的使用。我们启用它是因为我们将需要一些需要 Facade 的包。第二行代码启用了 Laravel 和 Lumen 附带的 Eloquent ORM 的使用。出于性能考虑，默认情况下不启用 Eloquent。但是，Eloquent 是一个非常重要的组件，我们不应该忽视它，即使是出于性能考虑，除非性能对我们非常重要并且由于 Eloquent 而变慢。在我看来，除非情况紧急，否则我们不应该为了性能而牺牲清晰度。

# 设置数据库

我们需要为博客设置数据库。实际上，我们在第三章中已经设置了这一点，*创建 RESTful 端点*。我们可以在这里使用该数据库。实际上，我们将拥有相同的数据库结构，因此我们可以轻松地使用相同的数据库，但这并不推荐。在 Lumen 中，我们使用迁移来创建数据库结构。这不是强制性的，但很有用，因此您可以编写一次迁移并在任何地方使用它来创建数据库结构。SQL 文件也可以实现这个目的，但是迁移的美妙之处在于它也可以跨不同的关系型数据库管理系统工作。因此，手动创建一个名为`blog`的数据库。现在，我们将为结构编写迁移。

# 编写迁移

要在 Lumen 中创建迁移文件，我们可以在`blog`目录中使用以下命令创建迁移文件：

```php
php artisan make:migration create_users_table
```

您将看到类似于这样的内容：

```php
Created Migration: 2017_06_23_180043_create_users_table
```

并且将在`/blog/database/migrations`目录中创建一个具有此名称的文件。在此文件中，我们可以为用户表编写迁移代码。如果您打开文件并查看其中，您会发现其中有两个方法：`up()`和`down()`。`up()`方法在运行迁移时执行，而`down()`在回滚迁移时执行。

这是用户表创建迁移文件的内容：

```php
<?php   use Illuminate\Database\Migrations\Migration; use Illuminate\Database\Schema\Blueprint;   class CreateUsersTable extends Migration {    /**
 * Run the migrations. * * @return void
 */  public function up()
 { Schema::create('users', function(Blueprint $table)
 {  $table->integer('id', true);
  $table->string('name', 100);
  $table->string('email', 50)->unique('email_unique');
  $table->string('password', 100);
 $table->timestamps();  }); }      /**
 * Reverse the migrations. * * @return void
 */  public function down()
 { Schema::drop('users');
 }   } 
```

在`up()`方法中，我们调用了 create 方法，并传递了一个函数。该函数包含添加字段的代码。如果您想了解有关通过迁移创建字段和表的更多信息，可以查看[`laravel.com/docs/5.4/migrations#tables`](https://laravel.com/docs/5.4/migrations#tables)。

但是，在运行从数据库生成迁移的命令之前，您应该转到`.env`文件并添加您的数据库名称和凭据。为了运行迁移，请运行以下命令：

```php
php artisan migrate
```

这将运行迁移，并创建两个表：迁移表和用户表。用户表是由先前提到的代码创建的，而迁移表是由 Laravel/Lumen 创建的，用于记录运行的迁移。这个表是第一次创建的，每次运行迁移时都会有更多的数据。

请注意，在运行迁移之前，您应该在`.env`文件中安装和配置 MySQL 或其他数据库。否则，如果没有安装或设置数据库，则迁移将无法工作。

现在，您可以以相同的方式创建帖子和评论表创建迁移文件。以下是帖子和评论表创建迁移文件的内容。

帖子迁移文件内容：

```php
<?php   use Illuminate\Database\Migrations\Migration; use Illuminate\Database\Schema\Blueprint;   class CreatePostsTable extends Migration {    /**
 * Run the migrations. * * @return void
 */  public function up()
 { Schema::create('posts', function(Blueprint $table)
 {  $table->integer('id', true);
  $table->string('title', 100);
  $table->enum('status', array('draft','published'))->default('draft');
  $table->text('content', 65535);
  $table->integer('user_id')->index('user_id_foreign');

         $table->timestamps();
 }); }      /**
 * Reverse the migrations. * * @return void
 */  public function down()
 { Schema::drop('posts');
 }   } 
```

这是评论表创建迁移文件：

```php
<?php   use Illuminate\Database\Migrations\Migration; use Illuminate\Database\Schema\Blueprint;   class CreateCommentsTable extends Migration {    /**
 * Run the migrations. * * @return void
 */  public function up()
 { Schema::create('comments', function(Blueprint $table)
 {  $table->integer('id', true);
  $table->string('comment', 250);
  $table->integer('post_id')->index('post_id');
  $table->integer('user_id')->index('user_id');

         $table->timestamps();
 }); }      /**
 * Reverse the migrations. * * @return void
 */  public function down()
 { Schema::drop('comments');
 }   } 
```

在拥有上述两个文件之后，再次运行以下命令：

```php
php artisan migrate
```

上述命令将只执行尚未执行的新迁移文件。有了这样，你将在数据库中拥有这三个表。而且，由于我们也将有这些迁移，所以只需再次运行迁移，就可以在数据库中拥有这个模式。你可能会想，“编写迁移有什么好处呢？”。好处在于，迁移使得在任何 RDBMS 上部署变得更容易，因为代码是 Laravel 迁移代码，而不是 SQL 代码。此外，将这样的东西放在代码中总是更容易的，这样多个开发人员就可以获取彼此的迁移并立即运行它们。

如果你还记得，我们还做了一些索引和外键约束。所以，这就是我们如何在迁移中做到的。

使用与之前相同的命令创建一个新的迁移文件：

```php
php artisan make:migration add_foreign_keys_to_comments_table
```

这将为评论表索引创建一个迁移文件。让我们给这个文件添加内容：

```php
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;

class AddForeignKeysToCommentsTable extends Migration {

    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('comments', function(Blueprint $table)
        {
            $table->foreign('post_id', 'post_id_comment_foreign')->references('id')->on('posts')->onUpdate('RESTRICT')->onDelete('RESTRICT');
            $table->foreign('post_id', 'post_id_foreign')->references('id')->on('posts')->onUpdate('RESTRICT')->onDelete('RESTRICT');
            $table->foreign('user_id', 'user_id_comment_foreign')->references('id')->on('users')->onUpdate('RESTRICT')->onDelete('RESTRICT');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('comments', function(Blueprint $table)
        {
            $table->dropForeign('post_id_comment_foreign');
            $table->dropForeign('post_id_foreign');
            $table->dropForeign('user_id_comment_foreign');
        });
    }

}
```

同样地，为帖子索引创建一个迁移文件。以下是文件的内容：

```php
<?php   use Illuminate\Database\Migrations\Migration; use Illuminate\Database\Schema\Blueprint;   class AddForeignKeysToPostsTable extends Migration {    /**
 * Run the migrations. * * @return void
 */  public function up()
 { Schema::table('posts', function(Blueprint $table)
 {  $table->foreign('user_id', 'user_id_foreign')->references('id')->on('users')->onUpdate('RESTRICT')->onDelete('RESTRICT');
 }); }      /**
 * Reverse the migrations. * * @return void
 */  public function down()
 { Schema::table('posts', function(Blueprint $table)
 {  $table->dropForeign('user_id_foreign');
 }); }   } 
```

在上述索引文件代码中，有一些代码有点复杂，需要我们的注意：

```php
  $table->foreign('user_id', 'user_id_foreign')->references('id')->on('users')->onUpdate('RESTRICT')->onDelete('RESTRICT');
```

在这里，`foreign()` 方法接受字段名和索引的名称。然后，`references()` 方法接受父表中外键字段的名称，`on()` 方法的参数是被引用的表名（在我们的例子中，是用户表）。然后，另外两个方法 `onUpdate()` 和 `onDelete()` 告诉用户在更新和删除时该做什么。如果你对迁移语法不太熟悉，没关系；你只需要查看 Lumen/Laravel 迁移文档。事实上，我建议你停下来，看一下与迁移相关的文档：[`laravel.com/docs/5.4/migrations`](https://laravel.com/docs/5.4/migrations)。

现在，为了使这些迁移在数据库中生效，我们需要再次运行迁移，以便新的迁移可以执行，并且我们可以在数据库中看到变化。所以运行：

```php
php artisan migrate
```

有了这个，我们就完成了迁移。现在我们可以通过种子在这些表中插入一些数据，但现在我们不需要，所以暂时跳过编写种子。

# 编写 RESTful web service 端点

现在，是时候真正开始编写我们在第一章“RESTful Web Services, Introduction and Motivation”中讨论过的端点，并在第三章中用纯粹的 Vanilla PHP 编写的端点了。所以让我们开始吧。

由于它有控制器和模型层，我们将从控制器层开始编写 API，该层将为不同的端点提供服务。对于第一个控制器，我们要编写的是 `PostController`。

# 编写第一个控制器

从技术上讲，这不是第一个控制器，因为 Lumen 自带了 2 个控制器，你可以在 `/<our blog project path>/app/Http/Controllers/` 目录中找到。但这是我们要编写的第一个控制器。在 Laravel（Lumen 的大哥）中，我们不需要去创建控制器，因为有相应的命令，但是在 Lumen 中这些命令是不可用的。由于这些命令不是强制性的，但非常方便，最好是让这些命令可用。

为了使用我们在 Lumen 中没有的额外功能（其中一些已经包含在 Laravel 中），我们需要安装一个包。现在，我们需要安装的包是 `flipbox/lumen-generator`。关于这个包的更多信息可以在 [`packagist.org/packages/flipbox/lumen-generator`](https://packagist.org/packages/flipbox/lumen-generator) 找到。

正如我们在前一章中所看到的，我们通过 composer 安装包，所以让我们安装它：

```php
composer require --dev flipbox/lumen-generator
```

你可以看到我在那里添加了一个 `--dev` 标志。我这样做是为了避免在生产环境中使用它，因为这样它将被添加到 `composer.json` 中的 `require --dev` 部分。

无论如何，一旦安装了这个，你可以在 `bootstrap/app.php` 中注册它的 `ServiceProvider`。

```php
if ($app->environment() !== 'production') {
  $app->register(Flipbox\LumenGenerator\LumenGeneratorServiceProvider::class); }
```

现在，你可以看到我们有更多的命令可用。你可以通过运行以下命令来查看：

```php
php artisan migrate
```

因此，让我们使用命令创建一个控制器。请注意，我们不仅仅是为了创建控制器而安装它，但当你使用它时，它将非常方便。无论如何，让我们使用以下命令创建一个控制器：

```php
php artisan make:controller PostController --resource
```

它将在`app/Http/Controllers/PostController.php`创建一个控制器。这个命令不仅会创建`PostController`，还会添加与 REST 资源相关的方法。打开一个文件并查看它。

这是它生成的内容：

```php
<?php   namespace App\Http\Controllers;   use Illuminate\Http\Request;   class PostController extends Controller {
  /**
 * Display a listing of the resource. * * @return \Illuminate\Http\Response
 */  public function index()
 {  //
  }    /**
 * Store a newly created resource in storage. * * @param \Illuminate\Http\Request  $request
 * @return \Illuminate\Http\Response
 */  public function store(Request $request)
 {  //
  }    /**
 * Display the specified resource. * * @param int  $id
 * @return \Illuminate\Http\Response
 */  public function show($id)
 {  //
  }    /**
 * Update the specified resource in storage. * * @param \Illuminate\Http\Request  $request
 * @param int  $id
 * @return \Illuminate\Http\Response
 */  public function update(Request $request, $id)
 {  //
  }    /**
 * Remove the specified resource from storage. * * @param int  $id
 * @return \Illuminate\Http\Response
 */  public function destroy($id)
 {  //
  } } 
```

这些方法是因为我们添加了`--resource`标志而生成的。如果你想知道我是从哪里获取到这个标志的知识，因为它没有列在包页面上，我是从 Laravel 的控制器文档中获取的[`laravel.com/docs/5.4/controllers#resource-controllers`](https://laravel.com/docs/5.4/controllers#resource-controllers)。然而，由于这些命令是由第三方包工作的，所以 Laravel 文档和这些命令的实际行为可能会有所不同，但由于这些是为了复制 Laravel 命令而在 Lumen 中完成的，它们很可能会非常相似。

无论如何，我们有`PostController`及其方法。让我们逐个实现这些方法。

但是，请注意，在 Lumen 和 Laravel 中，与其他 PHP MVC 框架不同，每个 URL 都应该在路由中告知，否则它将无法访问。路由是一种唯一的入口点，不像其他框架如`CodeIgniter`，路由是可选的。在 Lumen 中，路由是必需的。换句话说，控制器的每个方法只能通过路由访问。

因此，在继续使用`PostController`之前，让我们为帖子端点添加路由，否则`PostController`将毫无用处。

# Lumen 路由

在 Lumen 中，默认情况下，路由位于`/routes/web.php`。我说默认是因为这个路径可以更改。无论如何，进入`routes/web.php`并查看它。你会看到它自己返回一个响应，而不是指向任何控制器。所以，你应该知道它是由路由决定是否返回响应或使用控制器。但是，请注意，只有在路由闭包中返回响应才有意义，如果涉及的逻辑不多。在我们的情况下，我们将主要使用控制器。

当我们添加第一个路由时，我们的路由将如下所示：

```php
<?php   /* |---------------------------------------------------------------- | Application Routes |---------------------------------------------------------------- | | Here is where you can register all of the routes for an application. | It is a breeze. Simply tell Lumen the URIs it should respond to | and give it the Closure to call when that URI is requested. | */   $app->get('/', function () use ($app) {
  return $app->version(); });  $app->get('/api/posts', [
    'uses' => 'PostController@index',
    'as' => 'list_posts'
]);
```

粗体字中的代码是我们编写的。在这里，`$app->get()`中的`get`用于指定 HTTP 方法。它可以是`$app->post()`，但我们使用了`$app->get()`来指定接受`GET`方法。然后，在这个方法中有 2 个参数，你可以在前面的代码中看到。第一个是路由模式，而第二个参数是一个关联数组，其中`uses`键中有控制器和方法，`as`键中有路由名称：意味着在域或项目 URL 之后，如果`api/posts/`是一个 URL，它应该由`PostController`的`index()`方法提供服务。而路由名称只是在那里，如果你想在代码中按名称指定路由 URL，那么它是有用的。

现在，为了检查我们的路由是否正确，并从控制器的`index`方法获取响应，让我们向`PostController`的`index`方法添加一些内容。这是我们现在添加的内容，只是为了测试我们的路由：

```php
public function index() {
 return ['response' =>
        [
            'id' => 1,
            'title' => 'Some Post',
            'body' => 'Here is post body'
        ] **];** }
```

现在，尝试运行这段代码。在任何其他操作之前，你需要使用 PHP 内置服务器。进入整个代码所在的`blog`目录并运行：

```php
php -S localhost:8000 -t public
```

然后，从浏览器中输入：`http://localhost:8000/api/posts`，你将看到以下响应：

```php
{"response":{"id":1,"title":"Some Post","body":"Here is post body"}}
```

正如你所看到的，我们的路由起作用并从`PostController`的`index()`方法提供服务，如果你返回一个数组，Lumen 会将其转换为 JSON 并作为 JSON 返回。

要进一步查看特定 URL 映射到特定控制器特定方法的路由列表，只需运行：

```php
php artisan route:list
```

你将看到路由的详细信息，告诉你哪个 URL 模式与哪段代码相关联。

# REST 资源

这是一个非常基本的路由示例，由 `PostController` 方法提供。然而，如果你查看 `PostController`，它还有 4 个方法，我们需要为第一章中讨论的 4 个端点提供服务，并在第三章中实现*创建 RESTful 端点*。因此，我们需要在 Lumen 中为其他 4 个方法做同样的事情。为了将这 4 个方法映射到 4 个端点，我们不需要再添加 4 个路由。我们可以简单地添加一个基于资源的路由，它将将 REST 基础的 URL 模式映射到`PostController`的所有方法。

通过命令行创建`PostController`时，它创建了一个资源控制器，这意味着它具有提供 RESTful 端点所需的方法。因此，在`routes/web.php`文件中，我们应该用资源路由替换之前编写的代码。现在，我们应该能够通过在路由文件中添加这个语句来将所有 RESTful 端点映射到`PostController`的方法：

```php
$app->resource('api/posts', 'PostController');
```

不幸的是，这个资源路由在 Laravel 中可用，但在 Lumen 中不可用。Lumen 使用不同的路由器以获得更好的性能。然而，这个资源方法也非常方便，如果我们有 4-5 个以上的 RESTful 资源，我们可以只用 4-5 个语句来映射它们的所有端点，而不是 16-20 个语句。因此，这里有一个小技巧，可以在 Lumen 中使用这种资源路由的方法。你可以将这个自定义方法添加到同一个路由文件中。

```php
function resource($uri, $controller) {
  //$verbs = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];
  global $app;

  $app->get($uri, $controller.'@index');
  $app->post($uri, $controller.'@store');

  $app->get($uri.'/{id}', $controller.'@show');
  $app->put($uri.'/{id}', $controller.'@update');
  $app->patch($uri.'/{id}', $controller.'@update');

  $app->delete($uri.'/{id}', $controller.'@destroy'); }  
```

因此，我们的路由文件将如下所示：

```php
<?php   /* |---------------------------------------------------------------- | Application Routes |---------------------------------------------------------------- | | Here is where you can register all of the routes for an application. | It is a breeze. Simply tell Lumen the URIs it should respond to | and give it the Closure to call when that URI is requested. | */    function resource($uri, $controller)
{
    //$verbs = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];

    global $app;

    $app->get($uri, $controller.'@index');
    $app->post($uri, $controller.'@store');

    $app->get($uri.'/{id}', $controller.'@show');
    $app->put($uri.'/{id}', $controller.'@update');
    $app->patch($uri.'/{id}', $controller.'@update');

    $app->delete($uri.'/{id}', $controller.'@destroy'); **}**     $app->get('/', function () use ($app) {
  return $app->version(); });   resource('api/posts', 'PostController'**);** 
```

粗体字中的代码是我们添加的。因此，你可以看到我们在路由文件中一次定义了`resource()`函数，并且我们可以将其用于所有 REST 资源路由。然后在最后一行，我们使用资源函数将所有`api/posts`端点映射到`PostController`的相应方法。

现在你可以通过访问 `http://localhost:8000/api/posts` 来测试它。我们现在无法测试其他端点，因为我们还没有在 `PostController` 的其他方法中编写任何代码。但是，你可以使用以下命令来查看存在的路由：

```php
php artisan route:list
```

在我们的情况下，这个命令将在命令行上产生类似这样的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bd-rst-websvc-php7/img/d2d15438-6b99-4d46-9620-e339b0e5651f.png)

在这里，我们可以看到这是根据我们在[第一章](https://cdp.packtpub.com/building_restful_web_services_with_php_7/wp-admin/post.php?post=260&action=edit&save=save#post_412)中讨论的 RESTful 资源约定将路径映射到`PostController`方法。因此，对于帖子端点，我们已经完成了路由。现在我们需要在控制器中添加代码，以便它可以向数据库添加数据并从数据库中获取数据。下一步是创建一个模型层，并在控制器中使用它并返回适当的响应。

# Eloquent ORM（模型层）

Eloquent 是 Laravel 和 Lumen 附带的 ORM。它负责数据库相关操作以及数据库关系。**ORM**（**对象关系映射**）基本上将对象与数据库中的关系（表）进行映射。不仅如此，基于关系，你可以在不涉及底层细节的情况下获取另一个表的数据。这不仅节省了我们的时间，还使我们的代码更加清晰。

# 创建模型

我们现在要创建模型。模型层与数据库相关，因此我们也会在其中提及数据库关系。让我们为我们拥有的三个表创建模型。模型名称将是`User`、`Post`和`Comment`，分别对应`users`、`posts`和`comments`表。

我们不需要创建一个用户模型，因为它已经包含在 Lumen 中。要创建帖子和评论模型，让我们运行以下命令，这些命令是通过使用`flipbox/lumen-generator`包而变得可用的。运行以下命令来创建模型：

这将在`app`目录中创建一个`Post`模型：

```php
php artisan make:model Post
```

这将在`app`目录中创建一个`Comment`模型：

```php
php artisan make:model Comment
```

如果你查看这些模型文件，你会发现这些都是继承自 Eloquent Model 的类；因此，这些模型都是基于 Eloquent Model 的模型，并具有 Eloquent Model 的特性。

注意，根据 Eloquent 的约定，如果模型的名称是 Post，表的名称将是 posts，即模型名称的复数形式。同样，对于 Comment 模型，它将是 comments 表。如果我们的表名不同，我们可以覆盖这一点，但我们没有这样做，因为在我们的情况下，我们的表和模型名称都符合相同的约定。

Eloquent 是一个大的讨论话题，但我们只是用它来制作我们的 API，所以我将限制讨论 Eloquent 在服务我们目的方面的使用。我认为这是有道理的，因为 Eloquent 的文档中已经有很多细节，所以有关 Eloquent 的更多细节，请参阅这里的 Eloquent 文档：[`laravel.com/docs/5.4/eloquent`](https://laravel.com/docs/5.4/eloquent)。

# Eloquent 关系

在模型层，特别是在从 ORM 继承时，有两个重要的事情：

+   我们应该有模型，这样我们可以通过它们访问数据

+   我们应该指定关系，这样我们可以利用 ORM 的全部功能

只需访问数据而不编写查询，我们也可以使用查询构建器。但是，关系的优势在于它仅与 ORM 使用一起出现。因此，让我们指定所有模型的关系。

首先，让我们指定用户的关系。由于用户可以有多篇帖子和多条评论，用户模型将与帖子和评论模型都有`hasMany`关系。在指定关系后，用户模型将如下所示：

```php
<?php   namespace App;   use Illuminate\Auth\Authenticatable; use Laravel\Lumen\Auth\Authorizable; use Illuminate\Database\Eloquent\Model; use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract; use Illuminate\Contracts\Auth\Access\Authorizable as AuthorizableContract;   class User extends Model implements AuthenticatableContract, AuthorizableContract {
  use Authenticatable, Authorizable;    /**
 * The attributes that are mass assignable. * * @var array
 */  protected $fillable = [
  'name', 'email',
 ];    /**
 * The attributes excluded from the model's JSON form. * * @var array
 */  protected $hidden = [
  'password',
 ]; public function posts(){
        return $this->hasMany('App\Post');
    }

    public function comments(){
        return $this->hasMany('App\Comment'); **}** } 
```

我们在 User Model 中添加的唯一的东西是这两个用粗体标出的方法，它们是`posts()`和`comments()`，指定了关系。基于这些方法，我们可以访问用户的帖子和评论数据。这两个方法告诉我们，用户与`Post`和`Comment`模型都有多对多的关系。

现在，让我们在`Post`模型中添加一个关系。由于帖子可以有多条评论，`Post`模型与`Comment`模型有多个关系。同时，`Post`模型与用户模型有多个反向关系，该反向关系是`belongsTo`关系。在添加关系信息后，`Post`模型代码如下。

```php
<?php   namespace App;   use Illuminate\Database\Eloquent\Model;   class Post extends Model {
 public function comments(){
        return $this->hasMany('App\Comment');
    }

    public function user(){
        return $this->belongsTo('App\User'); **}** } 
```

正如你所看到的，我们已经指定了帖子与`User`和`Comment`模型的关系。现在，这是带有关系的`Comment`模型。

```php
<?php   namespace App;   use Illuminate\Database\Eloquent\Model;   class Comment extends Model {
 public function post(){
        return $this->belongsTo("App\Post");
    }

    public function user(){
        return $this->belongsTo("App\User"); **}** } 
```

正如你所看到的，对于`Post`和`User`模型，评论都有一个`belongsTo`关系，这是`hasMany()`的反向关系。

所以，现在我们已经指定了关系。是时候实现`PostController`的方法了。

# 控制器实现

让我们首先在`PostController`的`index()`方法中添加适当的代码，以返回实际数据。但是为了查看响应中的数据，最好在用户、帖子和评论表中插入一些虚拟数据。更好的方法是为此编写种子。但是，如果你不想了解如何编写种子，那么现在可以手动插入。

以下是`index()`方法的实现：

```php
public function index(\App\Post $post) {
  return $post->paginate(20); }
```

在这里，`paginate(20)`表示它将返回一个带有 20 个限制的分页结果。正如你所看到的，我们使用了依赖注入来获取`Post`对象。这是我们在本章中已经讨论过的内容。

同样，我们将在这里实现`PostController`的其他方法。`PostController`代码将如下所示：

```php
<?php   namespace App\Http\Controllers;   use Illuminate\Http\Request;   class PostController extends Controller {   public function __construct(\App\Post $post)
    {
        $this->post = $post; **}**    /**
 * Display a listing of the resource. * * @return \Illuminate\Http\Response
 */  public function index()
 { return $this->post->paginate(20**);**
 }    /**
 * Store a newly created resource in storage. * * @param \Illuminate\Http\Request  $request
 * @return \Illuminate\Http\Response
 */  public function store(Request $request)
 { $input = $request->all();
        $this->post->create($input);

        return [
            'data' => $input **];**
 }    /**
 * Display the specified resource. * * @param int  $id
 * @return \Illuminate\Http\Response
 */  public function show($id)
 {  return $this->post->find($id**);**
 }    /**
 * Update the specified resource in storage. * * @param \Illuminate\Http\Request  $request
 * @param int  $id
 * @return \Illuminate\Http\Response
 */  public function update(Request $request, $id)
 { $input = $request->all();
        $this->post->where('id', $id)->update($input);

        return $this->post->find($id**);**
 }    /**
 * Remove the specified resource from storage. * * @param int  $id
 * @return \Illuminate\Http\Response
 */  public function destroy($id)
 { $post = $this->post->destroy($id);

        return ['message' => 'deleted successfully', 'post_id' => $post**];**
 } } 
```

正如你所看到的，我们正在使用 Post 模型并使用它的方法执行不同的操作。Lumen 的变量和函数名称使我们更容易理解发生了什么，但如果你想知道可以使用哪些 Eloquent 方法，请查看 Eloquent：[`laravel.com/docs/5.4/eloquent`](https://laravel.com/docs/5.4/eloquent)。

如果您在那里找不到 Eloquent 方法的文档，请注意，我们使用的许多函数都是查询构建器的函数。因此，还要查看查询构建器的文档，网址为[`laravel.com/docs/5.4/queries`](https://laravel.com/docs/5.4/queries)。

由于`CommentController`的实现将类似，我建议您自己实现`CommentController`，因为您只有自己动手才能真正学会。

# 我们错过了什么？

我们是否已经创建了为 RESTful 资源端点提供服务的控制器？实际上没有，我们错过了很多东西。我们只是创建了基本的 RESTful 网络服务，可以让您了解如何使用 Lumen 制作它，但我们错过了很多东西。因此，让我们看看它们，逐个完成它们。

# 验证和负面情况？

首先，我们只处理积极的情况：这意味着我们不考虑如果请求不符合我们的假设会发生什么。如果用户使用错误的方法发送数据会发生什么？如果用户传递的 ID 不存在记录会发生什么？

简而言之，我们还没有处理所有这些，但是 Lumen 已经为我们处理了一些事情。

如果您尝试使用`POST`方法命中端点 URL，`http://localhost:8000/api/posts/1`，那么这是一种无效的方法。在这些 URL 上，我们只能使用`GET`，`PUT`或`PATCH`发送请求。使用`GET`将触发`PostController`的`show()`方法，而`PUT`或`PATCH`将触发`update()`方法。但是不应该允许使用`POST`方法。实际上，如果您尝试使用`POST`方法在这些 URL 上发送请求，它将不起作用，您还将收到`Method Not Allowed`错误，就像应该的那样。因此，通过一次定义我们的路由，Lumen 将自行处理此类错误。

同样，Lumen 将使错误的 URL 或错误的 HTTP 方法和 URL 组合无效。

除此之外，我们不打算处理每一种情况，但让我们看看我们必须处理的重要事情；如果没有这些东西，我们的工作就无法完成。

因此，让我们看看`PostController`每个方法中我们错过了什么关于验证或缺失的用例。

# 使用 GET 方法的/api/posts

以下是`/api/posts`端点的响应（在我的情况下，数据库中只有一条记录）：

```php
{
   "current_page":1,
   "data":[
      {
         "id":1,
         "title":"test",
         "status":"draft",
         "content":"test post",
         "user_id":2
      }
   ],
   "from":1,
   "last_page":1,
   "next_page_url":null,
   "path":"http:\/\/localhost:8000\/api\/posts",
   "per_page":20,
   "prev_page_url":null,
   "to":1,
   "total":1
}
```

如果您回忆一下我们在第一章中看到的响应，*RESTful Web Services, Introduction and Motivation*，您会发现我们得到了我们讨论的大部分信息，但是以不同的格式得到了。尽管这完全没问题，因为它提供了足够的信息，但是这是如何使其与我们决定的内容相似。

以下是`index()`方法将变成什么样子：

```php
public function index() {
 $posts = $this->post->paginate(20);
    $data = $posts['data'];

    $response = [
        'data' => $data,
        'total_count' => $posts['total'],
        'limit' => $posts['per_page'],
        'pagination' => [
            'next_page' => $posts['next_page_url'],
            'current_page' => $posts['current_page']
        ]
    ];

    return $response**;** }
```

最重要的是，响应的根级别的所有信息都不清晰。我们应该消除损害清晰度的内容，因为如果程序员需要花更多时间才能理解某些内容，程序员的生产力可能会受到影响。我们应该将分页相关的信息放在一个单独的属性下，可以是 pagination 或 meta，这样程序员就可以轻松地查看数据和其他属性。

我们做到了，但是我们是手动做的。现在，让我们暂时告一段落。在下一章中，我们将看看这其中有什么问题，为什么我们要手动调用它，以及我们可以做些什么。

# 使用 POST 方法的/api/posts

这将触发`PostController::store()`方法。我们错过的是验证。实际上，Lumen 还为我们提供了验证支持以及一些内置的验证规则。Lumen 的验证与 Laravel 非常相似，但也有一些不同之处。我建议您查看 Laravel 的验证文档，网址为[`laravel.com/docs/5.4/validation`](https://laravel.com/docs/5.4/validation)，以及 Lumen 与 Laravel 的验证差异：[`lumen.laravel.com/docs/5.4/validation`](https://lumen.laravel.com/docs/5.4/validation)。

在这里，我们在`store()`中添加了验证，因此在添加验证后查看代码，然后我们将讨论它：

```php
public function store(Request $request) {
  $input = $request->all();   $validationRules = [
        'content' => 'required|min:1',
        'title' => 'required|min:1',
        'status' => 'required|in:draft,published',
        'user_id' => 'required|exists:users,id'
    ];

    $validator = \Validator::make($input, $validationRules);
    if ($validator->fails()) {
        return new \Illuminate\Http\JsonResponse(
            [
                'errors' => $validator->errors()
            ], \Illuminate\**Http\**Response::HTTP_BAD_REQUEST
        );
 **}**   $post = $this->post->create($input);    return [
  'data' => $post
  ]; }
```

在这里，我们正在做 3 件事：

1.  首先，我们设置了以下验证规则：

1.  对于`content`和`title`，这些字段将是必需的，并且至少为 1 个字符长。

1.  对于`status`，它是必需的，其值可以是已发布或草稿，因为它在数据库中设置为 ENUM。

1.  `user_id`是必需的，并且应存在于`users`表的`id`字段中。

1.  然后，我们根据验证规则和输入创建了一个验证器对象，并检查验证器是否失败。否则，我们将继续进行。

1.  如果验证器失败，它将手动返回错误。它返回与验证器获得的相同错误描述，同时手动返回适当的响应代码。这就是为什么我们使用了`\Illuminate\Http\JsonResponse`。第一个参数是响应主体，而第二个参数是响应代码。而不是编写 400 错误代码，我们可以在`\Illuminate\Http\Response`中使用一个常量。因此，我们将不需要记住响应代码，阅读我们的代码的人也不需要知道 400 状态代码是什么。

请注意，错误代码、响应代码和 HTTP 代码表示相同的事情。因此，如果您看到它们，不要感到困惑，它们在本书中是可以互换使用的。

# 使用 GET 方法的/api/posts/1

这将由`show($id)`方法提供。在我们的 show 方法中，我们只是获取记录并返回，但是如果传递给 URL 中的`show()`方法的 ID 不正确，或者记录表明该 ID 不存在，该怎么办？因此，我们只需要放置一个检查以确保它返回 404 错误，如果找不到具有该 ID 的帖子。我们的`show()`方法的代码将如下所示：

```php
public function show($id) {
  $post = $this->post->find($id);
 if(!$post) {
        abort(404);
    }

    return $post**;** }
```

`abort()`方法将使用传递给它的错误代码停止执行。在这种情况下，它将简单地给出 404 Not Found 错误。

# 使用 PATCH/PUT 方法的/api/posts/1

它将由`update()`方法提供。同样，它是基于提供的 ID，因此我们需要检查该 ID 是否有效。因此，这就是我们将要做的事情：

```php
public function update(Request $request, $id) {
  $input = $request->all();    $post = $this->post->find($id);    if(!$post) {
 abort(404);
 }   $post->fill($input);
  $post->save();    return $post; }
```

在这里，我们使用了模型的`fill()`方法，它将使用$input 中的字段和值分配给 Post 模型，然后使用`save()`方法保存它。在 Laravel 文档中，您可以看到使用 Eloquent 以不同方式插入和更新的方法，这在不同的地方可能很方便：[`laravel.com/docs/5.4/eloquent#inserting-and-updating-models`](https://laravel.com/docs/5.4/eloquent#inserting-and-updating-models)。

有时，您会看到 Laravel 文档链接，而不是 Lumen。这是因为 Lumen 大多使用与 Laravel 相同的代码。所有这些组件的文档大多是在 Laravel 的文档中编写的，并且没有在 Lumen 文档中复制，因此 Lumen 文档在 Lumen 与 Laravel 不同的地方是很好的。

这就是我们在`update()`方法中要做的事情。

# 使用 DELETE 方法的/api/posts/1

删除操作将由`destroy($id)`提供。同样，它取决于来自 API 用户的 ID，因此我们需要放置与我们为`update()`和`show()`放置的类似检查。它将如下所示：

```php
public function destroy($id) {
 $post = $this->post->find($id);

    if(!$post) {
        abort(404);
    }

    $post**->delete();**    return ['message' => 'deleted successfully', 'post_id' => $id]; }
```

有了这个，我们的`PostController`将如下所示：

```php
<?php   namespace App\Http\Controllers;   use Illuminate\Http\Request; use Illuminate\Http\Response; use Illuminate\Http\JsonResponse;   class PostController extends Controller {    public function __construct(\App\Post $post)
 {  $this->post = $post;
 }    /**
 * Display a listing of the resource. * * @return \Illuminate\Http\Response
 */  public function index()
 {  $posts = $this->post->paginate(20);
  $data = $posts['data'];    $response = [
  'data' => $data,
  'total_count' => $posts['total'],
  'limit' => $posts['per_page'],
  'pagination' => [
  'next_page' => $posts['next_page_url'],
  'current_page' => $posts['current_page']
 ] ];    return $response;
 }    /**
 * Store a newly created resource in storage. * * @param \Illuminate\Http\Request  $request
 * @return \Illuminate\Http\Response
 */  public function store(Request $request)
 {  $input = $request->all();    $validationRules = [
  'content' => 'required|min:1',
  'title' => 'required|min:1',
  'status' => 'required|in:draft,published',
  'user_id' => 'required|exists:users,id'
  ];    $validator = \Validator::make($input, $validationRules);
  if ($validator->fails()) {
  return new JsonResponse(
 [  'errors' => $validator->errors()
 ], Response::HTTP_BAD_REQUEST
  );
 }   $post = $this->post->create($input);    return [
  'data' => $post
  ];
 }    /**
 * Display the specified resource. * * @param int  $id
 * @return \Illuminate\Http\Response
 */  public function show($id)
 {  $post = $this->post->find($id);    if(!$post) {
 abort(404);
 }    return $post;
 }    /**
 * Update the specified resource in storage. * * @param \Illuminate\Http\Request  $request
 * @param int  $id
 * @return \Illuminate\Http\Response
 */  public function update(Request $request, $id)
 {  $input = $request->all();    $post = $this->post->find($id);    if(!$post) {
 abort(404);
 }    $post->fill($input);
  $post->save();    return $post;
 }    /**
 * Remove the specified resource from storage. * * @param int  $id
 * @return \Illuminate\Http\Response
 */  public function destroy($id)
 {  $post = $this->post->find($id);    if(!$post) {
 abort(404);
 }    $post->delete();    return ['message' => 'deleted successfully', 'post_id' => $id];
 } } 
```

我们现在已经完成了返回适当的响应代码和验证等工作。

# 用户身份验证

到目前为止，我们还缺少用户身份验证。我们在输入中传递了`user_id`，这是错误的。我们之所以这样做是因为我们没有用户身份验证。因此，我们需要有一个身份验证机制。但是，除了身份验证之外，我们还需要有一个令牌生成机制。实际上，我们还需要刷新令牌。虽然我们可以自己做到这一点，但我们将安装另一个外部包。

在本章末尾开始用户身份验证并没有太多意义，因此我们将在下一章中处理用户身份验证，因为与之相关的事情有很多。

# 其他缺失的元素

我们现在缺少的其他东西如下：

+   API 版本控制

+   速率限制或节流

+   加密的需求

+   转换器或序列化

（这是为了避免在控制器内部进行硬编码手动返回格式）

在下一章中，我们将处理用户认证和前面提到的元素，并进行一些其他改进。

# 评论资源实现

我把评论端点的实现留给了你，因为它与帖子端点的实现非常相似。但是，由于评论的两个路由与其他路由不同，为了让你了解你需要实现什么，我将告诉你在`routes`文件中添加什么，以便你可以相应地实现`CommentController`。这是`routes/web.php`文件：

```php
<?php   /* |---------------------------------------------------------------- | Application Routes |---------------------------------------------------------------- | | Here is where you can register all of the routes for an application. | It is a breeze. Simply tell Lumen the URIs it should respond to | and give it the Closure to call when that URI is requested. | */     function resource($uri, $controller, $except **= []**) {
  //$verbs = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];    global $app;     if(!in_array('index', $except**)){**
  $app->get($uri, $controller.'@index');
 **}**   if(!in_array('store', $except)) {        $app->post($uri, $controller . '@store'); }

    if(!in_array('show', $except)) {        $app->get($uri . '/{id}', $controller . '@show'); };

    if(!in_array('udpate', $except)) {
        $app->put($uri . '/{id}', $controller . '@update');
        $app->patch($uri . '/{id}', $controller . '@update'); }

    if(!in_array('destroy', $except)) {        $app->delete($uri . '/{id}', $controller . '@destroy'); **}** }     $app->get('/', function () use ($app) {
  return $app->version(); });     resource('api/posts', 'PostController');  resource('api/comments', 'CommentController', ['store','index'**]);**   $app->post('api/posts/{id}/comments', $controller . '@store');
$app->get('api/posts/{id}/comments', $controller . '@index'**);**  
```

正如你所看到的，我们在`resource()`中添加了`$except`数组作为可选的第三个参数，这样如果我们不想为某个资源生成特定的路由，我们可以将其传递给`$except`数组。

在`CommentController`中，代码将与`PostController`非常相似，只是对于`store()`和`index()`，`post_id`将是第一个参数并将被使用。

# 总结

到目前为止，我们在一个名为 Lumen 的微框架中创建了 RESTful web 服务端点。我们创建了迁移、模型和路由。我实现了`PostController`，但留下了`CommentController`的实现给你。因此，我们可以看到，我们在第三章中讨论的许多与实现相关的问题，*创建 RESTful 端点*，已经得到解决，因为使用了一个框架。我们能够很容易地解决许多其他问题。因此，使用正确的框架和包，我们能够工作得更快。

我们还确定了一些缺失的元素，包括用户认证。我们将在下一章中解决它们。在下一章中，我们还将从代码方面改进我们的工作。

在本章中，我们主要使用 Lumen。我们看了它，但我们试图继续制作我们的 API，所以我们无法详细查看 Lumen 及其代码的每一个部分。因此，查看 Lumen 的文档是一个好主意：[`lumen.laravel.com/docs/5.4/validation`](https://lumen.laravel.com/docs/5.4)。

为了更好地理解，您应该查看 Laravel 的文档，因为一些常见组件在 Laravel 的文档中有详细解释：[`laravel.com/docs/5.4`](https://laravel.com/docs/5.4)。除了 Laravel 和 Lumen 的文档之外，建议去[`laracasts.com/`](http://laracasts.com/)观看关于 Laravel 的视频。如果在 Lumen 上找不到太多内容，不要担心，它与 Laravel 非常相似。除了一些变化，它们基本上是一样的。要了解 Laravel 和/或 Lumen，Lara casts 是一个非常好的资源，在 Laravel 社区非常受欢迎。Lara casts 主要由 Jeffrey Way 制作。我从他那里学到了很多东西，希望你也能学到。它不仅会教你 Laravel，还会教你如何开发，以及你应该如何进行开发。


# 第七章：改进 RESTful Web 服务

在上一章中，我们在 Lumen 中创建了 RESTful web 服务，并且确定了一些缺失的元素或需要改进的地方。在本章中，我们将致力于改进并完成一些缺失的元素。我们将改进某些元素，以满足漏洞和代码质量的要求。

我们将在本章中涵盖以下主题，以改进我们的 RESTful web 服务：

+   Dingo，简化 RESTful API 开发：

+   安装和配置 Dingo API 软件包

+   简化路由

+   API 版本控制

+   速率限制

+   内部请求

+   身份验证和中间件

+   转换器

+   加密的需求：

+   SSL，不同的选项

+   总结

# Dingo，简化 RESTful API 开发

是的，你没听错。我没说 bingo。是 Dingo。实际上，Dingo API 是 Laravel 和 Lumen 的一个软件包，它使开发 RESTful web 服务变得更简单。它提供了许多开箱即用的功能，其中许多是我们在上一章中看到的。这些功能中的许多将使我们现有的代码更好，更容易理解和维护。您可以在[`github.com/dingo/api`](https://github.com/dingo/api)上查看 Dingo API 软件包。

让我们首先安装它，然后在使用它的同时，我们将继续查看其好处和特性。

# 安装和配置

只需通过 composer 安装它：

```php
composer require dingo/api:1.0.x@dev
```

也许您想知道这个`@dev`是什么。因此，这是 Dingo 文档中的内容：

目前，该软件包仍处于开发阶段，因此没有稳定版本。您可能需要将最低稳定性设置为 dev。

如果您仍然不确定为什么需要设置最低稳定性，那是因为每个软件包的默认最低稳定性设置为`stable`。因此，如果您依赖于`dev`软件包，则应明确指定，否则它可能不会安装，因为最低稳定性与软件包的实际稳定性状态不匹配。

安装后，您需要注册它。转到`bootstrap/app.php`并在`return $app;`之前的某个地方放入此语句：

```php
$app->register(Dingo\Api\Provider\LumenServiceProvider::class);
```

完成后，您需要在`.env`文件的末尾设置一些变量。在`.env`文件的末尾添加它们：

```php
API_PREFIX=api
API_VERSION=v1
API_DEBUG=true
API_NAME="Blog API"
API_DEFAULT_FORMAT=json
```

配置是不言自明的。现在，让我们继续。

# 简化路由

如果您查看我们放置路由的`routes/web.php`文件，您会发现我们为帖子和评论端点编写了 54 行代码。使用 Dingo API，我们可以用只有 10 行代码来替换这 54 行代码，而且它会更加简洁。所以让我们这样做。您的`routes/web.php`文件应该如下所示：

```php
<?php   /* |---------------------------------------------------------------- | Application Routes |---------------------------------------------------------------- | | Here is where you can register all of the routes for an application. | It is a breeze. Simply tell Lumen the URIs it should respond to | and give it the Closure to call when that URI is requested. | */ $api = app('Dingo\Api\Routing\Router');

$api->version('v1', function ($api) {

    $api->resource('posts', "App\Http\Controllers\PostController");
    $api->resource('comments', "App\Http\Controllers\CommentController", [
        'except' => ['store', 'index']
    ]); 
 $api->post('posts/{id}/comments', 'App\Http\Controllers\CommentController@store');

 $api->get('posts/{id}/comments', 'App\Http\Controllers\CommentController@index'); **});** $app->get('/', function () use ($app) {
  return $app->version(); });  
```

如您所见，我们刚刚在`$api`中得到了路由的对象。但是，这是 Dingo API 路由，而不是 Lumen 的默认路由。正如您所见，它具有我们想要的`resource()`方法，并且我们可以在`except`数组中提及不需要的方法。因此，总的来说，我们的路由现在变得非常简化。

要查看应用程序的确切路由，请运行以下命令：

```php
php artisan route:list
```

# API 版本控制

也许您已经注意到，在我们的路由文件中的上一个代码示例中，我们已经将 API 版本指定为`v1`。这是因为 API 版本控制很重要，而 Dingo 为我们提供了这样的功能。它有助于从不同版本提供不同的端点。您可以有另一个版本组，并且可以提供相同端点的不同内容。如果在不同版本下有相同的端点，则它将选择在您的`.env`文件中提到的版本。

但是，在 URI 中包含版本号会更好。为此，我们可以简单地使用以下前缀：

```php
$api->version('v1', ['prefix' => 'api/v1'], function ($api) {

     $api->resource('posts', "App\Http\Controllers\PostController");
     $api->resource('comments', "App\Http\Controllers\CommentController", [
 'except' => ['store', 'index']
 ]);

     $api->post('posts/{id}/comments', 'App\Http\Controllers\CommentController@store');

     $api->get('posts/{id}/comments', 'App\Http\Controllers\CommentController@index');
});
```

现在，我们的路由将在 URI 中包含版本信息。这是一种推荐的方法。因为如果有人正在使用版本 1，并且我们将在版本 2 中进行更改，那么使用版本 1 的客户端在其请求中明确指定版本号时将不受影响。因此，我们的端点 URL 将如下所示：

```php
http://localhost:8000/api/v1/posts
http://localhost:8000/api/v1/posts/1
http://localhost:8000/api/v1/posts/1/comments
```

但是，请注意，如果我们的 URI 和路由中有版本，那么最好在我们的控制器中实际应用该版本。如果没有，版本实现将非常有限。为此，我们应该为控制器设置基于版本的命名空间。在我们的控制器（`PostController`和`CommentController`）中，命名空间将更改为以下代码行：

```php
namespace App\Http\Controllers**\V1**;
```

现在，控制器目录结构也应该与命名空间匹配。因此，让我们在`Controllers`目录中创建一个名为`V1`的目录，并将我们的控制器移动到`app\Http\Controllers**\V1**`目录中。当我们有下一个版本时，我们将在`app\Http\Controllers`中创建另一个名为`V2`的目录，并在其中添加新的控制器。这也将导致一个新的命名空间`App\Http\Controllers**\V2**`。随着命名空间和目录的更改，`routes/web.php`中的控制器路径也需要相应地进行更改。

通过这个改变，你很可能会看到以下错误：

```php
Class 'App\Http\Controllers\V1\Controller' not found
```

因此，要么将`Controller.php`从 controllers 目录移动到`V1`目录，要么像这样使用完整的命名空间访问它：`\App\Http\Controllers\Controller`

```php
class PostController extends **\App\Http\Controllers\Controller**  {..
```

这取决于你如何做。

# 速率限制

速率限制也被称为节流。这意味着应该限制特定客户端在特定时间间隔内能够访问 API 端点的次数。要启用它，我们必须启用`api.throttling`中间件。您可以在所有路由或特定路由上应用节流。您只需在特定路由上应用中间件，如下所示。在我们的情况下，我们希望为所有端点启用它，所以让我们将其放在一个版本组中：

```php
$api->version('v1', ['middleware' => 'api.throttle','prefix' => 'api/v1']**,** function ($api) {   $api->resource('posts', "App\Http\Controllers\V1\PostController");
  $api->resource('comments', "App\Http\Controllers\V1\CommentController", [
  'except' => ['store', 'index']
 ]);  $api->post('posts/{id}/comments', 'App\Http\V1\Controllers\CommentController@store'); $api->get('posts/{id}/comments', 'App\Http\V1\Controllers\CommentController@index');  });
```

为了简单起见，让我们在路由中进行一些更改。我们可以在版本组中使用命名空间，而不是在每个控制器的名称中指定命名空间，如下所示：

`$api->version('v1', ['middleware' => 'api.throttle', 'prefix' => 'api/v1', **namespace => "App\HttpControllers\V1"** **]**`

现在，我们可以简单地从控制器路径中删除它。

您还可以在分钟内提及限制和时间间隔：

```php
$api->version('v1', [
  'middleware' => 'api.throttle',
 'limit' => 100,
    'expires' => 5**,**
  'prefix' => 'api/v1',
  'namespace' => 'App\Http\Controllers\V1'
  ], function ($api) {
  $api->resource('posts', "PostController");
  $api->resource('comments', "CommentController", [
  'except' => ['store', 'index']
 ]);    $api->post('posts/{id}/comments', 'CommentController@store');
  $api->get('posts/{id}/comments', 'CommentController@index');   });
```

在这里，`expires`是时间间隔，而`limit`是路由可以被访问的次数。

# 内部请求

我们大多数情况下是制作一个 API，由外部客户端作为 Web 服务访问，而不是从同一应用程序访问。但是，有时我们处于需要在同一应用程序内进行内部请求并希望以与返回给外部客户端相同的格式返回数据的情况。

假设现在您希望从 API 中的`PostController`获取评论数据，因为它返回一个响应而不是内部函数调用。我们希望在 Postman 或其他客户端访问时，获得与`/api/posts/{postId}/comments`端点返回的相同数据。在这种情况下，Dingo API 包可以帮助我们。以下是它的简单用法：

```php
use  Illuminate\Http\Request; use Illuminate\Http\Response; use Illuminate\Http\JsonResponse; use **Dingo\Api\Routing\Helpers;**   class PostController extends Controller {
 use **Helpers;**    public function __construct(\App\Post $post)
 {  $this->post = $post;
 }
.... /**
 * Display the specified resource. * * @param int  $id
 * @return \Illuminate\Http\Response
 */ public function show($id) {
 $comments = $this->api->get("api/posts/$id/comments"**);**    $post = $this->post->find($id); ....
 }
....
} 
```

在前面的代码片段中，加粗的语句是不同的，它有助于进行内部请求。正如您所看到的，我们已经对端点进行了`GET`请求：

```php
 $comments = $this->api->get("api/posts/$id/comments");
```

我们也可以通过使用不同的方法使其成为基于`POST`的请求，如下所示：

```php
$this->api->post("api/v1/posts/$id/comments", ['comment' => 'a nice post']);
```

# 响应

Dingo API 包为不同类型的响应提供了更多的支持。由于我们不会详细介绍 Dingo API 提供的每一件事情，您可以在其文档中查看：[`github.com/dingo/api/wiki/Responses`](https://github.com/dingo/api/wiki/Responses)。

然而，在本章的后面，我们将详细了解响应和格式。

我们将在其他方面使用 Dingo API 包，但现在让我们转向其他概念，我们将继续同时使用 Dingo API 包。

# 身份验证和中间件

我们已经多次讨论过，对于 RESTful Web 服务，会话是通过存储在客户端的身份验证令牌来维护的。因此，服务器可以查找身份验证令牌，并且可以在服务器上找到用户的会话。

有几种生成令牌的方式。在我们的情况下，我们将使用**JWT**（**JSON Web Tokens**）。如在`jwt.io`上所述：

JSON Web Tokens 是一种开放的、行业标准的 RFC 7519 方法，用于在两个方之间安全地表示声明。

我们不会详细讨论 JWT，因为 JWT 是在两个方之间传输信息的一种方式（在我们的情况下是客户端和服务器），因为 JWT 可以用于许多目的。相反，我们将使用它来进行访问/身份验证令牌以维护无状态会话。因此，我们将坚持从 JWT 中获取我们需要的内容。我们需要它来维护身份验证目的的会话，并且这也是 Dingo API 包将帮助我们解决的问题。

事实上，Dingo API 在撰写本书时支持三种身份验证提供者。默认情况下启用了 HTTP 基本身份验证。另外两种是 JWT Auth 和 OAuth 2.0。我们将使用 JWT Auth。

# JWT Auth 设置

Dingo API 用于集成 JWT 身份验证的包可以在[`github.com/tymondesigns/jwt-auth`](https://github.com/tymondesigns/jwt-auth)找到。

[﻿](https://github.com/tymondesigns/jwt-auth)

有两种设置 JWT Auth 的方式：

1.  我们可以简单地按照 JWT Auth 包的说明进行配置，并手动修复一个接一个的问题。

1.  我们可以简单地安装另一个包，帮助我们安装和设置 Dingo API 和 JWT Auth，并进行一些基本配置。

在这里，我们将看到两种方式。然而，使用手动方式可能会因不同包的不同版本和 Lumen 本身而变得模糊。因此，尽管我将展示手动方式，但我建议您使用集成包，这样您就不需要手动处理每个低级别的事情。我将向您展示手动方式，只是为了让您对底层包含的内容有一些了解。

# 手动方式

让我们按照[`github.com/tymondesigns/jwt-auth/wiki/Installation`](https://github.com/tymondesigns/jwt-auth/wiki/Installation)安装页面上提到的包进行安装。

首先，我们需要安装 JWT Auth 包：

```php
 composer require tymon/jwt-auth 1.0.0-beta.3
```

请注意，此版本适用于 Laravel 5.3。对于旧版本，您可能需要使用不同版本的 JWT Auth 包，很可能是版本 0.5。

要在`bootstrap/app.php`文件中注册服务提供者，请添加以下代码行：

```php
$app->register(Tymon\JWTAuth\Providers\JWTAuthServiceProvider::class);
```

然后，在同一个`bootstrap/app.php`文件中添加这两个类别名：

```php
class_alias('Tymon\JWTAuth\Facades\JWTAuth', 'JWTAuth'); class_alias('Tymon\JWTAuth\Facades\JWTFactory', 'JWTFactory');
```

然后，您需要生成一个用于签署我们令牌的随机密钥。要这样做，请运行此命令：

```php
php artisan jwt:generate
```

这将生成一个随机密钥。

您可能会看到一些错误，如下所示：

`[Illuminate\Contracts\Container\BindingResolutionException] Unresolvable dependency resolving [Parameter #0 [ <required> $app ]] in class Illuminate\Cache\CacheManager`

在这种情况下，在`bootstrap/app.php`中的`$app->withEloquent();`之后添加以下行。这样就可以解决问题，您可以尝试生成一个随机密钥：

```php
$app->alias('cache', 'Illuminate\Cache\CacheManager'); $app->alias('auth', 'Illuminate\Auth\AuthManager');
```

然而，您可能想知道这个随机密钥将在哪里设置。实际上，有些包并不是为 Lumen 构建的，而是需要更像 Laravel 的结构。`tymondesigns/jwt-auth`包就是其中之一。它需要一种发布配置的方式。虽然 Lumen 没有为不同的包单独的配置文件，但我们需要它，我们可以让 Lumen 为这个包拥有这样一个`config`文件。要这样做，如果您在`app/`目录下没有`helpers.php`，那么创建它并添加以下内容：

```php
<?php if ( ! function_exists('config_path')) {
  /**
 * Get the configuration path. * * @param string $path
 * @return string
 */  function config_path($path = '')
 {  return app()->basePath() . '/config' . ($path ? '/' . $path : $path);
 } }
```

然后，在自动加载数组的`composer.json`中添加`helpers.php`：

```php
"autoload": {
  "psr-4": {
    "App\\": "app/"
  },
  "files": [
    "app/helpers.php"
  ]
},
```

运行以下命令：

```php
composer dump-autoload
```

一旦你拥有了它，运行以下命令：

```php
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\JWTAuthServiceProvider"
```

在这一点上，您将收到另一个错误消息：

```php
[Symfony\Component\Console\Exception\CommandNotFoundException]
 There are no commands defined in the "vendor" namespace.
```

不用担心，这是正常的。这是因为 Lumen 没有`vendor:publish`命令。所以，我们需要安装一个小包来执行这个命令：

```php
composer require laravelista/lumen-vendor-publish
```

由于这个命令将有一个新的命令，为了使用该命令，我们需要在`app/Console/Kernel.php`的`$commands`数组中放入以下内容。

现在，尝试再次运行相同的命令，如下所示：

```php
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\JWTAuthServiceProvider"
```

这一次，你会看到类似这样的东西：

```php
Copied File [/vendor/tymon/jwt-auth/src/config/config.php] To [/config/jwt.php]
Publishing complete for tag []!
```

现在，我们有`blog/config/jwt.php`，我们可以在这个文件中存储与`jwt-auth`包相关的配置。

我们需要做的第一件事是重新运行这个命令来设置随机密钥签名：

```php
php artisan jwt:generate
```

这一次，你可以在`config/jwt.php`文件的返回数组中看到这个密钥设置：

```php
'secret' => env('JWT_SECRET', 'RusJ3fiLAp4DmUNNzqGpC7IcQI8bfar7'),
```

接下来，你需要按照[`github.com/tymondesigns/jwt-auth/wiki/Configuration`](https://github.com/tymondesigns/jwt-auth/wiki/Configuration)中所示的进行配置。

然而，你也可以将`config/jwt.php`中的其他设置保持为默认。

接下来要做的事情是告诉 Dingo API 使用 JWT 作为认证方法。所以在`bootstrap/app.php`中添加这个：

```php
app('Dingo\Api\Auth\Auth')->extend('jwt', function ($app) {
 return new Dingo\Api\Auth\Provider\JWT($app['Tymon\JWTAuth\JWTAuth']);
});
```

根据 JWT Auth 文档，我们大部分配置都已经完成了，但请注意，你可能会遇到与版本相关的小问题。如果你使用的版本早于 Lumen 5.3，那么请注意，基于不同的 Laravel 版本，需要使用不同版本的 JWT Auth。对于版本 5.2，你应该使用 JWT Auth 版本 0.5。所以，如果你在低于 Laravel 5.2 的版本中仍然遇到任何错误，那么请注意，可能是因为版本差异导致的错误，所以你需要在互联网上搜索。

正如你所看到的，为了同时使用两个包来实现一些功能，我们必须花费一些时间进行配置，就像最近的几个步骤建议的那样。即使这样，由于版本差异，仍然有可能出现错误。因此，一个简单的方法是不要手动安装 Dingo API 包和 JWT Auth 包。还有另一个包，安装它将安装 Dingo API 包、Lumen 生成器、CORS（跨域资源共享）支持、JWTAuth，并使其可用，而不需要那么多的配置。现在，让我们来看看。

# 通过 Lumen JWT 认证集成包的更简单方式

更简单的方法是自己安装 Dingo API 包和 JWT Auth，只需安装[`packagist.org/packages/krisanalfa/lumen-dingo-adapter.`](https://packagist.org/packages/krisanalfa/lumen-dingo-adapter)

它将在你的基于 Lumen 的应用程序中添加 Dingo 和 JWT。只需安装这个包：

```php
composer require krisanalfa/lumen-dingo-adapter
```

然后，在`bootstrap/app.php`中，添加以下代码行：

```php
$app->register(Zeek\LumenDingoAdapter\Providers\LumenDingoAdapterServiceProvider::class);
```

现在，我们正在使用`LumenDingoAdapter`包，所以这是我们将使用的`bootstrap/app.php`文件，这样你就可以与你的文件进行比较：

```php
<?php   require_once __DIR__.'/../vendor/autoload.php';   try {
 (new Dotenv\Dotenv(__DIR__.'/../'))->load(); } catch (Dotenv\Exception\InvalidPathException $e) {
  // }   /* |-------------------------------------------------------------------------- | Create The Application |-------------------------------------------------------------------------- | | Here we will load the environment and create the application instance | that serves as the central piece of this framework. We'll use this | application as an "IoC" container and router for this framework. | */   $app = new Laravel\Lumen\Application(
  realpath(__DIR__.'/../') );     $app->withFacades();

 $app**->withEloquent();**   /* |-------------------------------------------------------------------------- | Register Container Bindings |-------------------------------------------------------------------------- | | Now we will register a few bindings in the service container. We will | register the exception handler and the console kernel. You may add | your own bindings here if you like or you can make another file. | */   $app->singleton(
 Illuminate\Contracts\Debug\ExceptionHandler::class,
 App\Exceptions\Handler::class );   $app->singleton(
 Illuminate\Contracts\Console\Kernel::class,
 App\Console\Kernel::class );   $app->register(Zeek\LumenDingoAdapter\Providers\LumenDingoAdapterServiceProvider::class);     /* |-------------------------------------------------------------------------- | Register Middleware |-------------------------------------------------------------------------- | | Next, we will register the middleware with the application. These can | be global middleware that run before and after each request into a | route or middleware that'll be assigned to some specific routes. | */   // $app->middleware([ //    App\Http\Middleware\ExampleMiddleware::class // ]);   // $app->routeMiddleware([ //     'auth' => App\Http\Middleware\Authenticate::class, // ]);   /* |-------------------------------------------------------------------------- | Register Service Providers |-------------------------------------------------------------------------- | | Here we will register all of the application's service providers which | are used to bind services into the container. Service providers are | totally optional, so you are not required to uncomment this line. | */   // $app->register(App\Providers\AppServiceProvider::class); // $app->register(App\Providers\AuthServiceProvider::class); // $app->register(App\Providers\EventServiceProvider::class);   /* |-------------------------------------------------------------------------- | Load The Application Routes |-------------------------------------------------------------------------- | | Next we will include the routes file so that they can all be added to | the application. This will provide all of the URLs the application | can respond to, as well as the controllers that may handle them. | */   $app->group(['namespace' => 'App\Http\Controllers'], function ($app) {
  require __DIR__.'/../routes/web.php'; });   return $app; 
```

如果你想知道`$app->withFacades()`到底是做什么的，那么请注意，这将在应用程序中启用门面。门面是一种设计模式，用于将复杂的事物抽象化，同时提供简化的接口进行交互。在 Lumen 中，正如 Laravel 文档所述：<q>门面为应用程序服务容器中可用的类提供了一个“静态”接口。</q>

使用门面的好处是它提供了易记的语法。我们不会经常使用门面，并且会尽量避免使用它，因为我们更倾向于使用依赖注入。然而，一些包可能会使用门面，所以为了让它们工作，我们已经启用了门面。

# 认证

现在，我们可以使用`api.auth`中间件来保护我们的端点。这个中间件检查用户认证并从 JWT 中获取用户。然而，首先要做的是让用户登录，根据用户信息创建一个令牌，并将签名令牌返回给客户端。

为了使认证工作，我们首先需要创建一个与认证相关的控制器。这个控制器不仅会根据用户登录创建令牌，还会使用户令牌过期并刷新令牌。为了做到这一点，我们可以将这个开源的`AuthController`放在`app/Http/Controllers/Auth/`目录下

[`github.com/Haafiz/REST-API-for-basic-RPG/blob/master/app/Http/Controllers/Auth/AuthController.php.`](https://github.com/Haafiz/REST-API-for-basic-RPG/blob/master/app/Http/Controllers/Auth/AuthController.php)

为了给予信用，我想告诉你，我们使用的`AuthController`版本是[`github.com/krisanalfa/lumen-jwt/blob/develop/app/Http/Controllers/Auth/AuthController.php`](https://github.com/krisanalfa/lumen-jwt/blob/develop/app/Http/Controllers/Auth/AuthController.php)的修改版本。

无论如何，如果你在阅读本书时没有看到`AuthController`在线上可用，这里是`AuthController`的内容：

```php
<?php   namespace App\Http\Controllers\Auth;   use Illuminate\Http\Request; use Illuminate\Http\Response; use Illuminate\Http\JsonResponse; use Tymon\JWTAuth\Facades\JWTAuth; use App\Http\Controllers\Controller; use Tymon\JWTAuth\Exceptions\JWTException; use Illuminate\Http\Exception\HttpResponseException;   class AuthController extends Controller {
  /**
 * Handle a login request to the application. * * @param \Illuminate\Http\Request $request
 * * @return \Illuminate\Http\Response;
 */  public function login(Request $request)
 {  try {
  $this->validateLoginRequest($request);
 } catch (HttpResponseException $e) {
  return $this->onBadRequest();
 }    try {
  // Attempt to verify the credentials and create a token for the user
  if (!$token = JWTAuth::attempt(
  $this->getCredentials($request)
 )) {  return $this->onUnauthorized();
 } } catch (JWTException $e) {
  // Something went wrong whilst attempting to encode the token
  return $this->onJwtGenerationError();
 }    // All good so return the token
  return $this->onAuthorized($token);
 }    /**
 * Validate authentication request. * * @param Request $request
 * @return void
 * @throws HttpResponseException
 */  protected function validateLoginRequest(Request $request)
 {  $this->validate(
  $request, [
  'email' => 'required|email|max:255',
  'password' => 'required',
 ] ); }    /**
 * What response should be returned on bad request. * * @return JsonResponse
 */  protected function onBadRequest()
 {  return new JsonResponse(
 [  'message' => 'invalid_credentials'
  ], Response::HTTP_BAD_REQUEST
  );
 }    /**
 * What response should be returned on invalid credentials. * * @return JsonResponse
 */  protected function onUnauthorized()
 {  return new JsonResponse(
 [  'message' => 'invalid_credentials'
  ], Response::HTTP_UNAUTHORIZED
  );
 }    /**
 * What response should be returned on error while generate JWT. * * @return JsonResponse
 */  protected function onJwtGenerationError()
 {  return new JsonResponse(
 [  'message' => 'could_not_create_token'
  ], Response::HTTP_INTERNAL_SERVER_ERROR
  );
 }    /**
 * What response should be returned on authorized. * * @return JsonResponse
 */  protected function onAuthorized($token)
 {  return new JsonResponse(
 [  'message' => 'token_generated',
  'data' => [
  'token' => $token,
 ] ] ); }    /**
 * Get the needed authorization credentials from the request. * * @param \Illuminate\Http\Request $request
 * * @return array
 */  protected function getCredentials(Request $request)
 {  return $request->only('email', 'password');
 }    /**
 * Invalidate a token. * * @return \Illuminate\Http\Response
 */  public function invalidateToken()
 {  $token = JWTAuth::parseToken();    $token->invalidate();    return new JsonResponse(['message' => 'token_invalidated']);
 }    /**
 * Refresh a token. * * @return \Illuminate\Http\Response
 */  public function refreshToken()
 {  $token = JWTAuth::parseToken();    $newToken = $token->refresh();    return new JsonResponse(
 [  'message' => 'token_refreshed',
  'data' => [
  'token' => $newToken
  ]
 ] ); }    /**
 * Get authenticated user. * * @return \Illuminate\Http\Response
 */  public function getUser()
 {  return new JsonResponse(
 [  'message' => 'authenticated_user',
  'data' => JWTAuth::parseToken()->authenticate()
 ] ); } } 
```

这个控制器有三个主要任务：

+   登录`login()`方法

+   使令牌失效

+   刷新令牌

# 登录

登录是在`login()`方法中完成的，并且它尝试使用`JWTAuth::attempt($this->getCredentials($request))`进行登录。如果凭据无效或者出现其他问题，它将返回一个错误。然而，要访问这个`login()`方法，我们需要为它添加一个路由。这是我们将在`routes/web.php`中添加的内容：

```php
$api->post(
  '/auth/login', [
  'as' => 'api.auth.login',
  'uses' => 'Auth\AuthController@login',
 ] );
```

# 使令牌失效

为了使令牌失效，换句话说，注销用户，将使用`invalidateToken()`方法。这个方法将通过一个路由来调用。我们将添加以下路由，使用删除请求方法，它将从路由文件中调用`AuthController::invalidateToken()`：

```php
$api->delete(
  '/', [
  'uses' => 'Auth/AuthController@invalidateToken',
  'as' => 'api.auth.invalidate'
  ] );
```

# 刷新令牌

当令牌根据到期时间过期时，将调用刷新令牌。为了刷新令牌，我们还需要添加以下路由：

```php
$api->patch(
  '/', [
  'uses' => 'Auth/AuthController@refreshToken',
  'as' => 'api.auth.refresh'
  ] );
```

请注意，所有这些端点都将添加在版本 v1 下。

一旦我们有了`AuthController`并且路由设置好了，用户可以使用以下端点进行登录：

```php
POST /api/v1/auth/login
Params: email, passsword
```

尝试一下，你将获得基于 JWT 的访问令牌。

**Lumen、Dingo、JWT Auth 和 CORS 样板**：

如果你在配置 Lumen 与 Dingo 和 JWT 时遇到困难，那么你可以简单地使用[`github.com/krisanalfa/lumen-jwt.`](https://github.com/Haafiz/lumen-jwt)这个存储库将为你提供使用 Dingo API 和 JWT 设置你的 Lumen 进行 API 开发的样板代码。你可以克隆它并开始使用。这只是一个 Lumen 与 JWT、Dingo API 和 CORS 支持的集成。因此，如果你要开始一个新的 RESTful web 服务项目，你可以直接使用这个样板代码开始。

在继续之前，让我们看一下我们的路由文件，确保我们在同一个页面上：

```php
<?php   /* |-------------------------------------------------------------------------- | Application Routes |-------------------------------------------------------------------------- | | Here is where you can register all of the routes for an application. | It is a breeze. Simply tell Lumen the URIs it should respond to | and give it the Closure to call when that URI is requested. | */ $api = app('Dingo\Api\Routing\Router');     $api->version('v1', [
  'middleware' => ['api.throttle'],
  'limit' => 100,
  'expires' => 5,
  'prefix' => 'api/v1',
  'namespace' => 'App\Http\Controllers\V1' ],
  function ($api) {
 $api->group(['middleware' => 'api.auth'], function ($api) {
            //Posts protected routes
            $api->resource('posts', "PostController", [
                'except' => ['show', 'index']
            ]);

            //Comments protected routes
            $api->resource('comments', "CommentController", [
                'except' => ['show', 'index']
            ]);

            $api->post('posts/{id}/comments', 'CommentController@store'**);**      // Logout user by removing token
  $api->delete(
  '/', [
  'uses' => 'Auth/AuthController@invalidateToken',
  'as' => 'api.Auth.invalidate'
  ]
 );      // Refresh token
  $api->patch(
  '/', [
  'uses' => 'Auth/AuthController@refreshToken',
  'as' => 'api.Auth.refresh'
  ]
 ); **});**  $api->get('posts', 'PostController@index');
 $api->get('posts/{id}', 'PostController@show'**);**

  $api->get('posts/{id}/comments', 'CommentController@index');
 $api->get('comments/{id}', 'CommentController@show'**);**    $api->post(
  '/auth/login', [
  'as' => 'api.Auth.login',
  'uses' => 'Auth\AuthController@login',
 ] );  });    $app->get('/', function () use ($app) {
  return $app->version(); });   
```

正如你所看到的，我们已经创建了一个路由组。路由组只是一种将相似的路由分组的方式，我们可以在其中应用相同的中间件、命名空间或前缀等，就像我们在`v1`组中所做的那样。

在这里，我们创建了另一个路由组，以便我们可以在其中添加`api.auth`中间件。还要注意的一点是，我们已经将一些帖子路由从帖子资源路由中拆分出来，以便在没有登录的情况下有一些可用的路由。我们也对评论路由做了同样的处理。

请注意，如果你不想将一些路由从资源路由中拆分出来，那么你也可以这样做。你只需在控制器中添加`api.auth`中间件，而不是在路由文件中。两种方式都是正确的；这只是一个偏好问题。我之所以这样做，是因为我发现从相同的路由文件而不是不同控制器的构造函数中知道哪些路由受保护更容易。但再次强调，这取决于你。

我们只允许已登录的用户创建、更新和删除帖子。但是，我们需要确保已登录的用户只能更新或删除自己的帖子。虽然这也可以通过创建另一个中间件来实现，但在控制器中实现会更简单。

这就是我们在 `PostController` 中的做法：

```php
<?php   namespace App\Http\Controllers\V1;   use Illuminate\Http\Request; use Illuminate\Http\Response; use Illuminate\Http\JsonResponse; use Tymon\JWTAuth\Facades\JWTAuth; use Dingo\Api\Routing\Helpers;   class PostController extends Controller {
  use Helpers;    public function __construct(\App\Post $post)
 {     $this->post = $post;   }    /**
 * Display a listing of the resource. * * @return \Illuminate\Http\Response
 */  public function index(Request $request)
 {  $posts = $this->post->paginate(20);    return $posts;
 }    /**
 * Store a newly created resource in storage. * * @param \Illuminate\Http\Request  $request
 * @return \Illuminate\Http\Response
 */  public function store(Request $request)
 {    $input = $request->all();
 $input['user_id'] = $this->user->id**;**    $validationRules = [
  'content' => 'required|min:1',
  'title' => 'required|min:1',
  'status' => 'required|in:draft,published',
  'user_id' => 'required|exists:users,id'
  ];    $validator = \Validator::make($input, $validationRules);
  if ($validator->fails()) {
  return new JsonResponse(
 [  'errors' => $validator->errors()
 ], Response::HTTP_BAD_REQUEST
  );
 }    $this->post->create($input);    return [
  'data' => $input
  ];
 }    /**
 * Display the specified resource. * * @param int  $id
 * @return \Illuminate\Http\Response
 */  public function show($id)
 {  $post = $this->post->find($id);    if(!$post) {
 abort(404);
 }    return $post;
 }    /**
 * Update the specified resource in storage. * * @param \Illuminate\Http\Request  $request
 * @param int  $id
 * @return \Illuminate\Http\Response
 */  public function update(Request $request, $id)
 {  $input = $request->all();    $post = $this->post->find($id);    if(!$post) {
 abort(404);
 } if($this->user->id != $post->user_id){
            return new JsonResponse(
                [
                    'errors' => 'Only Post Owner can update it'
                ], Response::HTTP_FORBIDDEN
            ); **}**    $post->fill($input);
  $post->save();    return $post;
 }    /**
 * Remove the specified resource from storage. * * @param int  $id
 * @return \Illuminate\Http\Response
 */  public function destroy($id)
 {  $post = $this->post->find($id);    if(!$post) {
 abort(404);
 } if($this->user->id != $post->user_id){
            return new JsonResponse(
                [
                    'errors' => 'Only Post Owner can delete it'
                ], Response::HTTP_FORBIDDEN
            ); **}**    $post->delete();    return ['message' => 'deleted successfully', 'post_id' => $id];
 } } 
```

正如您所看到的，我在三个地方都突出显示了代码。在 `store()` 方法中，我们从中获取了用户 ID，并将其放入输入数组中，以便帖子的 `user_id` 基于令牌。同样，在 `update()` 和 `delete()` 中，我们使用了该用户的 ID，并放置了一个检查，以确保帖子所有者正在删除或更新帖子记录。您可能会想知道，当我们没有在任何地方定义 `$this->user` 属性时，我们是如何访问它的？实际上，我们正在使用 Helpers trait，所以 `$this->user` 来自该 trait。

注意，为了访问受保护的资源，您应该从登录端点获取令牌，并将其放在标头中，如下所示：`Authentication: bearer <token grabbed from login>`

同样，`CommentController` 将进行检查，以确保评论修改将仅限于评论所有者，并且删除将仅限于评论或帖子所有者。它将具有类似的检查和用户 ID 通过令牌的方式。因此，我将留给您实现评论控制器以进行这些检查。

# 转换器

在全栈 MVC 框架中，我们有模型视图控制器。在 Lumen 或 API 中，我们没有视图，因为我们只返回一些数据。但是，我们可能希望以与通常不同的方式显示数据。我们可能希望使用不同的格式，或者我们可能希望限制具有特定格式的对象。在所有这些情况下，我们需要一个处理格式相关任务的地方，一个可以包含不同格式相关内容的地方。我们可以在控制器中实现。但是，我们需要在不同的地方定义相同的格式。在这种情况下，我们可以在模型中添加一个方法。例如，帖子模型可以有一种特定的方式来格式化帖子对象。因此，我们可以在帖子模型中定义另一个方法。

它会很好地工作，但是如果你仔细看，它与格式有关，而不是模型。因此，我们有另一层叫做序列化或转换器。有时，我们需要嵌套对象，所以我们不希望一遍又一遍地做同样的嵌套。

Lumen 提供了一种将数据序列化为 JSON 的方法。在 Eloquent 对象中，有一个名为 `toJson()` 的方法；这个方法可以被重写以达到目的。但是，最好有一个单独的层用于格式化和序列化数据，而不是在同一个类中只有一个方法来实现。然后就是转换器；转换器只是另一层。您可以将转换器视为 API 或 web 服务的视图层。

# 理解和设置转换器

实际上，我们使用的包名为 Dingo API 包含了创建 RESTful web 服务所需的许多内容。同样，Dingo API 包还提供了对转换器的支持。

在做任何事情之前，我们需要了解转换器层由转换器组成。转换器是负责数据呈现的类。Dingo API 转换器支持转换器，对于转换器，API 依赖于另一个负责转换器功能的库。由我们决定使用哪个转换层或库。默认情况下，它使用 Fractal，一个默认的转换层。

我们不需要做任何其他与设置相关的事情。让我们开始使用转换器来处理我们的对象。但是，在那之前，让自己熟悉 Fractal。我们至少需要知道 Fractal 是什么以及它提供了什么。Fractal 的文档可以在 [`fractal.thephpleague.com/`](http://fractal.thephpleague.com/) 找到。

# 使用转换器

有两种方法可以告诉 Lumen 要使用哪个转换器类。为此，我们需要创建一个转换器类。让我们首先为我们的`Post`对象创建一个转换器，并将其命名为`PostTransformer`。首先，创建一个名为`app/Transformers`的目录，在该目录中，创建一个名为`PostTransformer`的类，内容如下：

```php
<?php   namespace App\Transformers;   use League\Fractal;   class PostTransformer extends Fractal\TransformerAbstract {   public function transform(\App\Post $post)
 {   return $post->toArray();
 } }
```

您可以在`transform()`方法中对 Post 响应进行任何想要的操作。请注意，我们在这里不是可选地重写`transform()`方法，而是提供了`transform()`的实现。您始终需要在转换器类中添加该方法。但是，如果没有从任何地方使用该类，则该类将毫无用处。因此，让我们在我们的`PostController`中使用它。让我们在`index()`方法中使用它：

```php
public function index(**\App\Transformers\PostTransformer** $postTransformer) {
  $posts = $this->post->paginate(20);   return $this->response->paginator($posts, $postTransformer**);** } 
```

正如您所看到的，我们已经将`PostTransformer`对象注入到`$this->response->paginator()`方法中。这里我们需要注意的第一件事是`$this->response->paginator()`方法和`$this->response`对象。我们现在需要知道`$this->response`对象最初是从哪里来的。我们得到它是因为我们在`PostController`中使用了`Helpers` trait。无论如何，现在让我们看看它是如何工作的。使用以下端点击中`PostController`的`index()`方法：

```php
http://localhost:8000/api/v1/posts
```

它会返回类似这样的东西：

```php
{ "data": [
 { "id": 1,
 "title": "test",
 "status": "draft",
 "content": "test post",
 "user_id": 2,
 "created_at": null,
 "updated_at": "2017-06-28 00:47:50"
 }, {  "id": 3,
  "title": "test",
  "status": "published",
  "content": "test post",
  "user_id": 2,
 "created_at": "2017-06-28 00:00:44",
  "updated_at": "2017-06-28 00:00:44"
  },
 {  "id": 4,
  "title": "test",
  "status": "published",
  "content": "test post",
  "user_id": 2,
  "created_at": "2017-06-28 03:21:36",
  "updated_at": "2017-06-28 03:21:36"
  },
 {  "id": 5,
  "title": "test post",
  "status": "draft",
  "content": "This is yet another post for testing purpose",
  "user_id": 8,
  "created_at": "2017-07-15 00:45:29",
  "updated_at": "2017-07-15 00:45:29"
  },
 {  "id": 6,
  "title": "test post",
  "status": "draft",
  "content": "This is yet another post for testing purpose",
  "user_id": 8,
  "created_at": "2017-07-15 23:53:23",
  "updated_at": "2017-07-15 23:53:23"
  } ], "meta": {
    "pagination": {
        "total": 5,
            "count": 5,
            "per_page": 20,
            "current_page": 1,
            "total_pages": 1,
            "links": []
        }
    }
}
```

如果您仔细观察，您会看到一个单独的元数据部分，其中包含与分页相关的内容。这是 Fractal 转换器本身提供的一个小功能。实际上，Fractal 可以为我们提供更多。

我们可以包含嵌套对象。例如，如果我们在`Post`中有`user_id`，并且我们希望`User`对象嵌套在同一个`Post`对象中，那么它也可以提供更简单的方法来实现。尽管转换器层就像 API 响应数据的视图层一样，但它提供的远不止于此。现在，我将向您展示当我们从`show()`和其他方法中返回`PostTransformer`后，我们的`PostController`方法将会是什么样子。有关 Fractal 的详细信息，我建议您查看 Fractal 文档，以便充分利用它，网址为[`fractal.thephpleague.com/`](http://fractal.thephpleague.com/)。

以下是我们的`PostController`方法的样子：

```php
<?php   namespace App\Http\Controllers\V1;   use Illuminate\Http\Request; use Illuminate\Http\Response; use Illuminate\Http\JsonResponse;  use **Dingo\Api\Routing\Helpers;** use App\Transformers\PostTransformer;   class PostController extends Controller {
 use **Helpers;**    public function __construct(\App\Post $post, \App\Transformers\PostTransformer $postTransformer)
 {   $this->post = $post;    $this->transformer = $postTransformer;   }    /**
 * Display a listing of the resource. * * @return \Illuminate\Http\Response
 */  public function index()
 {  $posts = $this->post->paginate(20);   return $this->response->paginator($posts, $this->transformer**);**
 }    /**
 * Store a newly created resource in storage. * * @param \Illuminate\Http\Request  $request
 * @return \Illuminate\Http\Response
 */  public function store(Request $request)
 {    $input = $request->all();
  $input['user_id'] = $this->user->id;    $validationRules = [
  'content' => 'required|min:1',
  'title' => 'required|min:1',
  'status' => 'required|in:draft,published',
  'user_id' => 'required|exists:users,id'
  ];    $validator = \Validator::make($input, $validationRules);
  if ($validator->fails()) {
  return new JsonResponse(
 [  'errors' => $validator->errors()
 ], Response::HTTP_BAD_REQUEST
  );
 }   $post = $this->post->create($input);   return $this->response->item($post, $this->transformer**);**
 }    /**
 * Display the specified resource. * * @param int  $id
 * @return \Illuminate\Http\Response
 */  public function show($id)
 {  $post = $this->post->find($id);    if(!$post) {
 abort(404);
 }   return $this->response->item($post, $this->transformer**);**
 }    /**
 * Update the specified resource in storage. * * @param \Illuminate\Http\Request  $request
 * @param int  $id
 * @return \Illuminate\Http\Response
 */  public function update(Request $request, $id)
 {  $input = $request->all();    $post = $this->post->find($id);    if(!$post) {
 abort(404);
 }    if($this->user->id != $post->user_id){
  return new JsonResponse(
 [  'errors' => 'Only Post Owner can update it'
  ], Response::HTTP_FORBIDDEN
  );
 }    $post->fill($input);
  $post->save();   return $this->response->item($post, $this->transformer**);**
 }    /**
 * Remove the specified resource from storage. * * @param int  $id
 * @return \Illuminate\Http\Response
 */  public function destroy($id)
 {  $post = $this->post->find($id);    if(!$post) {
 abort(404);
 }    if($this->user->id != $post->user_id){
  return new JsonResponse(
 [  'errors' => 'Only Post Owner can delete it'
  ], Response::HTTP_FORBIDDEN
  );
 }    $post->delete();    return ['message' => 'deleted successfully', 'post_id' => $id];
 } } 
```

从前面的代码片段中突出显示的行中，您可以看到我们在构造函数中添加了`PostTransformer`对象，并将其放置在`$this->transformer`中，我们在其他方法中使用了它。您还可以看到，在一个地方，我们在`index()`方法中使用了`$this->response->paginator()`方法，而在其他方法中我们使用了`$this->response->item()`。这是因为当有一个对象时，我们使用`$this->response->item()`方法，而在`index()`方法中有`paginator`对象时，我们使用`paginator`。请注意，如果您有一个集合并且没有`paginator`对象，则应该使用`$this->response->collection()`。

如前所述，Fractal 具有更多功能，这些功能在其文档中有所介绍。因此，您需要暂停一下，并在[`fractal.thephpleague.com/`](http://fractal.thephpleague.com/)上探索其文档。

# 加密

我们缺少的下一件事是加密客户端和服务器之间的通信，以便没有人可以在网络上嗅探和读取数据。为此，我们将使用**SSL**（**安全套接字层**）。由于本书不涉及加密、密码学或服务器设置，我们不会详细介绍这些概念，但重要的是我们在这里谈论加密。如果有人能够在网络上嗅探数据，那么我们的网站或网络服务就不安全。

为了保护我们的 Web 服务，我们将使用 HTTPS 而不是 HTTP。HTTPS 中的“S”代表安全。现在，问题是我们如何使它安全。你可能会说我们将使用 SSL，就像我们之前说的那样。那么 SSL 是什么？SSL 是安全套接字层，是服务器和浏览器之间安全通信的标准方式。SSL 指的是安全协议。实际上 SSL 协议有三个版本，它们对一些攻击是不安全的。所以我们实际使用的是 TLS（传输层安全）。然而，当我们提到 TLS 时，我们仍然使用 SSL 术语。如果你想使用 SSL 证书和 SSL 来使 HTTP 安全，实际上底层使用的是比原始 SSL 协议更好的 TLS。

当建立连接时，服务器会将 SSL 证书的副本与公钥一起发送给浏览器，以便浏览器也可以对与服务器之间的通信进行编码或解码。我们不会深入讨论加密细节；然而，我们需要知道如何获得 SSL 证书。

# SSL 证书，不同的选项

通常，SSL 证书是从证书提供商那里购买的。然而，你也可以从[letsencrypt.org](http://letsencrypt.org)获得免费证书。所以，如果有免费证书可用，那为什么还要购买证书呢？实际上，有时从某些机构购买证书更多的是为了保险而不是安全。如果你正在建立一个电子商务网站或者接受付款或者非常关键的金融信息等非常重要的数据，那么你需要有人在你的网站用户面前承担责任。

也许从[letsencrypt.org](http://letsencrypt.org)获得的证书与以较低价格出售的提供商的证书之间存在一些微小的差异（我不知道），但通常，购买证书更多的是为了保险而不是安全。

你将从你获得证书的地方得到安装说明。如果你选择使用[letsencrypt.org](https://letsencrypt.org/)，那么我建议你使用 certbot。请按照[`certbot.eff.org/`](https://certbot.eff.org/)上的说明进行操作。

# 总结

在本章中，我们讨论了在上一章中我们在 Lumen 中实现 RESTful Web 服务端点时所缺少的内容。我们讨论了限流（请求速率限制）以防止 DoS 或暴力破解。我们还使用了一些软件包实现了基于令牌的身份验证。请注意，我们只在这里保护了端点，我们不希望在用户未登录的情况下留下可访问的端点。如果有其他端点，你不希望公开访问，但它们不需要用户登录，那么你可以在这些端点上使用某种密钥或基本身份验证。

除此之外，我们讨论并使用了一些用于 Web 服务的视图层的转换器。然后，我们简要讨论了加密和 SSL 的重要性，然后讨论了 SSL 证书的可用选项。

在本章中，我不会给你更多资源的 URL 列表，因为我们在本章中讨论了很多不同的事情，所以我们无法深入了解每一件事的细节。要完全吸收它，你应该首先查看我们在这里讨论的每一件事的文档，然后进行实践。当你在实践中遇到问题并尝试解决它们时，你才会真正学到东西。

在下一章中，我们将讨论测试，并使用自动化测试工具为我们的端点和代码编写测试用例。
