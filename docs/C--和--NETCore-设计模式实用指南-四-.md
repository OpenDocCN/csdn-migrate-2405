# C# 和 .NETCore 设计模式实用指南（四）

> 原文：[`zh.annas-archive.org/md5/99BBE5B6F8F1801CD147129EA46FD82D`](https://zh.annas-archive.org/md5/99BBE5B6F8F1801CD147129EA46FD82D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：高级数据库设计和应用技术

在上一章中，我们通过讨论其原则和模型来了解了响应式编程。我们还讨论并查看了响应式编程如何处理数据流的示例。

数据库设计是一项复杂的任务，需要很多耐心。在本章中，我们将讨论高级数据库和应用技术，包括应用 CQRS 和分类账式数据库。

与以前的章节类似，将进行需求收集会话，以确定最小可行产品（MVP）。在本章中，将使用几个因素来引导设计到 CQRS。我们将使用分类账式方法，其中包括增加对库存水平变化的跟踪，以及希望提供用于检索库存水平的公共 API。本章将介绍开发人员为什么使用分类账式数据库以及为什么我们应该专注于 CQRS 实现。在本章中，我们将看到为什么我们要采用 CQRS 模式。

本章将涵盖以下主题：

+   用例讨论

+   数据库讨论

+   库存的分类账式数据库

+   实施 CQRS 模式

# 技术要求

本章包含各种代码示例，以解释概念。代码保持简单，仅用于演示目的。大多数示例涉及使用 C#编写的.NET Core 控制台应用程序。

要运行和执行代码，Visual Studio 2019 是必需的（您也可以使用 Visual Studio 2017 来运行应用程序）。

# 安装 Visual Studio

要运行这些代码示例，您需要安装 Visual Studio（首选 IDE）。要做到这一点，请按照以下说明进行操作：

1.  从以下下载链接下载 Visual Studio 2017（或 2019 版本）：[`docs.microsoft.com/en-us/visualstudio/install/install-visual-studio`](https://docs.microsoft.com/en-us/visualstudio/install/install-visual-studio)。

1.  按照上述链接可访问的安装说明。可用多种选项进行 Visual Studio 安装。在这里，我们使用 Visual Studio for Windows。

# 设置.NET Core

如果您尚未安装.NET Core，则需要按照以下说明进行操作：

1.  下载.NET Core for Windows：[`www.microsoft.com/net/download/windows`](https://www.microsoft.com/net/download/windows)。

1.  对于多个版本和相关库，请访问[`dotnet.microsoft.com/download/dotnet-core/2.2`](https://dotnet.microsoft.com/download/dotnet-core/2.2)。

# 安装 SQL Server

如果您尚未安装 SQL Server，则需要按照以下说明进行操作：

1.  从以下链接下载 SQL Server：[`www.microsoft.com/en-in/download/details.aspx?id=1695`](https://www.microsoft.com/en-in/download/details.aspx?id=1695)。

1.  您可以在[`docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017`](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017)找到安装说明。

有关故障排除和更多信息，请参阅以下链接：[`www.blackbaud.com/files/support/infinityinstaller/content/installermaster/tkinstallsqlserver2008r2.htm`](https://www.blackbaud.com/files/support/infinityinstaller/content/installermaster/tkinstallsqlserver2008r2.htm)。

# 用例讨论

在本章中，我们将继续使用我们的 FlixOne 库存应用程序。在本章中，我们将讨论 CQRS 模式，并扩展我们在以前章节中开发的 Web 应用程序。

本章将继续讨论上一章中开发的 Web 应用程序。如果您跳过了上一章，请重新阅读以帮助您理解当前章节。

在本节中，我们将通过需求收集过程，然后讨论我们的 Web 应用程序的各种挑战。

# 项目启动

在第七章中，*为 Web 应用程序实现设计模式-第二部分*，我们扩展了 FlixOne 库存，并为 Web 应用程序添加了身份验证和授权。我们在考虑以下几点后扩展了应用程序：

+   当前应用程序对所有用户开放；因此，任何用户都可以访问任何页面，甚至是受限制的页面。

+   用户不应该访问需要访问或特殊访问权限的页面；这些页面也被称为受限制的页面或有限访问权限的页面。

+   用户应能够根据其角色访问页面/资源。

在第十章中，*响应式编程模式和技术*，我们进一步扩展了我们的 FlixOne 库存应用程序，并为显示列表的所有页面添加了分页、过滤和排序。在扩展应用程序时考虑了以下几点：

+   **项目过滤**：目前，用户无法按照它们的类别对项目进行过滤。为了扩展此功能，用户应能够根据类别对产品项目进行过滤。

+   **项目排序**：目前，项目按照它们被添加到数据库的顺序出现。没有任何机制可以使用户根据类别（如项目名称或价格）对项目进行排序。

# 需求

经过多次会议和与管理层、**业务分析师**（**BA**）和售前人员的讨论后，管理层决定着手处理以下高层要求：业务需求和技术需求。

# 业务需求

根据与利益相关者和最终用户的讨论，以及市场调查的结果，我们的业务团队列出了以下要求：

+   **产品扩展**：产品正在接触到不同的用户。现在是扩展应用程序的好时机。扩展后的应用程序将更加强大。

+   **产品模型**：作为库存管理应用程序，用户应该感到自由（这意味着在模型级别没有限制，没有复杂的验证），并且在用户与应用程序交互时不应有任何限制。每个屏幕和页面都应该是自解释的。

+   **数据库设计**：应用程序的数据库应设计成扩展不需要花费太多时间的方式。

# 技术要求

满足业务需求的实际要求现已准备好进行开发。经过与业务人员的多次讨论后，我们得出以下要求：

+   以下是**首页**或**主页**的要求：

+   应该有包含各种小部件的仪表板

+   应该显示商店的一览图片

+   以下是**产品页面**的要求：

+   应具有添加、更新和删除产品的功能

+   应具有添加、更新和删除产品类别的功能

FlixOne 库存管理 Web 应用程序是一个虚构的产品。我们正在创建此应用程序来讨论 Web 项目中所需/使用的各种设计模式。

# 挑战

尽管我们扩展了现有的 Web 应用程序，但对开发者和企业都存在各种挑战。在本节中，我们将讨论这些挑战，然后找出克服这些挑战的解决方案。

# 开发者面临的挑战

以下是由应用程序的重大变化引起的挑战。这也是将控制台应用程序升级为 Web 应用程序的主要扩展的结果：

+   **不支持 RESTful 服务**：目前，没有支持 RESTful 服务，因为没有开发 API。

+   **有限的安全性**：在当前应用程序中，只有一种机制可以限制/允许用户访问特定屏幕或应用程序模块：即登录。

# 企业面临的挑战

在我们采用新技术栈时，会出现以下挑战，并且代码会发生许多变化。因此，要实现最终输出需要时间，这延迟了产品，导致业务损失：

+   客户流失：在这里，我们仍处于开发阶段，但对我们业务的需求非常高。然而，开发团队花费的时间比预期的要长，以交付产品。

+   发布生产更新需要更多时间：目前开发工作非常耗时，这延迟了后续活动，导致生产延迟。

# 提供解决问题/挑战的解决方案

经过几次会议和头脑风暴，开发团队得出结论，我们必须稳定我们的基于 Web 的解决方案。为了克服这些挑战并提供解决方案，技术团队和业务团队汇聚在一起，确定了各种解决方案和要点。

以下是解决方案支持的要点：

+   发展 RESTful web 服务——应该有一个 API 仪表板

+   严格遵循测试驱动开发（TDD）

+   重新设计用户界面（UI）以满足用户体验期望

# 数据库讨论

在开始数据库讨论之前，我们必须考虑以下几点——FlixOne 网站应用程序的整体情况：

+   我们应用程序的一部分是库存管理，但另一部分是电子商务网站应用程序。

+   具有挑战性的部分是我们的应用程序还将作为销售点（POS）提供服务。在这个部分/模块中，用户可以支付他们从离线柜台/门店购买的物品。

+   对于库存部分，我们需要解决我们将采取哪种方法来计算和维护账户和交易，并确定出售任何物品的成本。

+   为了维护库存，有各种选项可用，其中最常用的两个选项是先进先出（FIFO）和后进先出（LIFO）。

+   大部分交易涉及财务数据，因此这些交易需要历史数据。每条记录应包含以下信息：当前值，当前更改之前的值，以及所做的更改。

+   在维护库存的同时，我们还需要维护购买的物品。

在为任何电子商务网站应用程序设计数据库时，还有更多重要的要点。我们将限制我们的范围，以展示 FlixOne 应用程序的库存和库存管理。

# 数据库处理

与本书中涵盖的其他主题类似，有许多数据库，涵盖了从数据库模式的基本模式到管理数据库系统如何组合的模式。本节将涵盖两种系统模式，即在线事务处理（OLTP）和在线分析处理（OLAP）。为了进一步了解数据库设计模式，我们将更详细地探讨一种特定模式，即分类账式数据库。

数据库模式是数据库中表、视图、存储过程和其他组件的集合的另一个词。可以将其视为数据库的蓝图。

# OLTP

已设计 OLTP 数据库以处理导致数据库更改的大量语句。基本上，INSERT、UPDATE 和 DELETE 语句都会导致更改，并且与 SELECT 语句的行为非常不同。OLTP 数据库已经考虑到了这一点。因为这些数据库记录更改，它们通常是主数据库或主数据库，这意味着它们是保存当前数据的存储库。

`MERGE`语句也被视为引起变化的语句。这是因为它提供了一个方便的语法，用于在行不存在时插入记录，并在行存在时插入更新。当行存在时，它将进行更新。`MERGE`语句并非所有数据库提供程序或版本都支持。

OLTP 数据库通常被设计为快速处理变更语句。这通常是通过精心规划表结构来实现的。一个简单的观点是考虑数据库表。这个表可以有用于存储数据的字段，用于高效查找数据的键，指向其他表的索引，用于响应特定情况的触发器，以及其他表结构。每一个这些结构都有性能惩罚。因此，OLTP 数据库的设计是在表上使用最少数量的结构与所需行为之间的平衡。

让我们考虑一张记录库存系统中书籍的表。每本书可能记录名称、数量、出版日期，并引用作者信息、出版商和其他相关表。我们可以在所有列上放置索引，甚至为相关表中的数据添加索引。这种方法的问题在于，每个索引都必须为引起变化的每个语句存储和维护。因此，数据库设计人员必须仔细规划和分析数据库，以确定向表中添加和不添加索引和其他结构的最佳组合。

表索引可以被视为一种虚拟查找表，它为关系数据库提供了一种更快的查找数据的方式。

# OLAP

使用 OLAP 模式设计的数据库预计会有比引起变化的语句更多的`SELECT`语句。这些数据库通常具有一个或多个数据库的数据的综合视图。因此，这些数据库通常不是主数据库，而是用于提供与主数据库分开的报告和分析的数据库。在某些情况下，这是在与其他数据库隔离的基础设施上提供的，以便不影响运营数据库的性能。这种部署方式通常被称为**数据仓库**。

数据仓库可以用来提供企业系统或系统集合的综合视图。传统上，数据通常通过较慢的周期性作业进行输入，以从其他系统刷新数据，但是使用现代数据库系统，这种趋势正在向近实时的整合发展。

OLTP 和 OLAP 之间的主要区别在于数据的存储和组织方式。在许多情况下，这将需要在支持特定报告场景的 OLAP 数据库中创建表或持久视图（取决于所使用的技术），并复制数据。在 OLTP 数据库中，数据的复制是不希望的，因为这样会引入需要为单个引起变化的语句维护的多个表。

# 分类账式数据库

会强调分类账式数据库设计，因为这是几十年来许多金融数据库中使用的模式，而且可能并不为一些开发人员所知。分类账式数据库源自会计分类账，交易被添加到文档中，并且数量和/或金额被合计以得出最终数量或金额。下表显示了苹果销售的分类账：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/f1a0135c-e2a0-406c-8ce9-2c20c019ee12.png)

关于这个例子有几点需要指出。购买者信息是分别写在不同的行上，而不是擦除他们的金额并输入新的金额。以 West Country Produce 的两次购买和一次信用为例。这通常与许多数据库不同，许多数据库中单个行包含购买者信息，并有用于金额和价格的单独字段。

类似账簿的数据库通过每个交易都有单独的一行来实现这一概念，因此删除`UPDATE`和`DELETE`语句，只依赖`INSERT`语句。这有几个好处。与账簿类似，一旦每笔交易被写入，就不能被移除或更改。如果出现错误或更改，比如对 West Country Produce 的信用，需要写入新的交易以达到期望的状态。这样做的一个有趣好处是源表现在立即提供了详细的活动日志。如果我们添加一个*modified by*列，我们就可以有一个全面的日志，记录是谁或什么做出了更改以及更改是什么。

这个例子是针对单条目账簿的，但在现实世界中，会使用双重账簿。不同之处在于，在双重账簿中，每笔交易都记录为一张表中的信用和另一张表中的借记。

下一个挑战是捕获表的最终或汇总版本。在这个例子中，这是已购买的苹果数量和价格。第一种方法可以使用一个`SELECT`语句，只需对购买者执行`GROUP BY`，如下所示：

```cs
SELECT Purchaser, SUM(Amount), SUM(Price)
FROM Apples
GROUP BY Purchaser
```

虽然这对于较小的数据大小来说是可以的，但问题在于随着行数的增加，查询的性能会随着时间的推移而下降。另一种选择是将数据聚合成另一种形式。有两种主要的方法可以实现这一点。第一种方法是在将账簿表中的信息写入另一张表（或者如果支持的话，持久视图）时同时执行这个活动，这张表以聚合形式保存数据。

**持久**或**物化视图**类似于数据库视图，但视图的结果被缓存。这使我们不需要在每个请求上重新计算视图的好处，它要么定期刷新，要么在基础数据更改时刷新。

第二种方法依赖于与`INSERT`语句分开的另一个机制，在需要时检索聚合视图。在一些系统中，向表中写入更改并检索结果的主要场景发生得不太频繁。在这种情况下，优化数据库使得写入速度比读取速度更快，从而限制插入新记录时所需的处理量会更有意义。

下一节将讨论一个有趣的模式 CQRS，可以应用在数据库层面。这可以用在类似账簿的数据库设计中。

# 实施 CQRS 模式

CQRS 简单地在查询（读取）和命令（修改）之间进行分离。**命令-查询分离**（**CQS**）是一种**面向对象设计**（**OOD**）的方法。

CQRS 是由 Bertrand Meyer 首次提出的（[`en.wikipedia.org/wiki/Bertrand_Meyer`](https://en.wikipedia.org/wiki/Bertrand_Meyer)）。他在 20 世纪 80 年代晚期的著作《面向对象的软件构造》中首次提到了这个术语：[`www.amazon.in/Object-Oriented-Software-Construction-Prentice-hall-International/dp/0136291554`](https://www.amazon.in/Object-Oriented-Software-Construction-Prentice-hall-International/dp/0136291554)。

CQRS 在某些场景下非常适用，并具有一些有用的因素：

+   **模型分离**：在建模方面，我们能够为我们的数据模型有多个表示。清晰的分离允许选择不同的框架或技术，而不是更适合查询或命令的其他框架。可以说，这可以通过**创建、读取、更新和删除**（**CRUD**）风格的实体来实现，尽管单一的数据层组件经常会出现。

+   **协作**：在一些企业中，查询和命令之间的分离将有利于参与构建复杂系统的团队，特别是当一些团队更适合处理实体的不同方面时。例如，一个更关注展示的团队可以专注于查询模型，而另一个更专注于数据完整性的团队可以维护命令模型。

+   **独立可伸缩性**：许多解决方案往往要求根据业务需求对模型进行更多读取或写入。

对于 CQRS，请记住命令更新数据，查询读取数据。

在使用 CQRS 时需要注意的一些重要事项如下：

+   命令应该以异步方式放置，而不是同步操作。

+   数据库不应该通过查询进行修改。

CQRS 通过使用单独的命令和查询简化了设计。此外，我们可以在物理上将读取数据与写入数据操作分开。在这种安排中，读取数据库可以使用单独的数据库架构，或者换句话说，我们可以说它可以使用一个专门用于查询的只读数据库。

由于数据库采用了物理分离的方法，我们可以将应用程序的 CQRS 流程可视化，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/a303ee36-9fb8-411d-a49c-26b3f526b63d.png)

上述图表描述了 CQRS 应用程序的想象工作流程，其中应用程序具有用于写操作和读操作的物理分离数据库。这个想象中的应用程序是基于 RESTful Web 服务（.NET Core API）的。没有 API 直接暴露给使用这些 API 的客户端/最终用户。有一个 API 网关暴露给用户，任何应用程序的请求都将通过 API 网关进行。

API 网关为具有类似类型服务的组提供了一个入口点。你也可以使用外观模式来模拟它，这是分布式系统的一部分。

在上一个图表中，我们有以下内容：

+   **用户界面**：这可以是任何客户端（使用 API 的人），Web 应用程序，桌面应用程序，移动应用程序，或者任何其他应用程序。

+   **API 网关**：来自用户界面的任何请求和向用户界面的任何响应都是通过 API 网关传递的。这是 CQRS 的主要部分，因为业务逻辑可以通过使用命令和持久层来合并。

+   **数据库**：图表显示了两个物理分离的数据库。在实际应用中，这取决于产品的需求，你可以使用数据库进行写入和读取操作。

+   查询是通过`Read`操作生成的，这些操作是**数据传输对象**（**DTOs**）。

现在你可以回到*用例*部分，在那里我们讨论了我们的 FlixOne 库存应用程序的新功能/扩展。在这一部分，我们将使用 CQRS 模式创建一个新的 FlixOne 应用程序，其中包括之前讨论的功能。请注意，我们将首先开发 API。如果你没有安装先决条件，我建议重新访问*技术要求*部分，收集所有所需的软件，并将它们安装到你的机器上。如果你已经完成了先决条件，那么让我们开始按照以下步骤进行：

1.  打开 Visual Studio。

1.  单击文件|新建项目来创建一个新项目。

1.  在新项目窗口中，选择 Web，然后选择 ASP.NET Core Web 应用程序。

1.  给你的项目取一个名字。我已经为我们的项目命名为`FlixOne.API`，并确保解决方案名称为`FlixOne`。

1.  选择你的`解决方案`文件夹的位置，然后点击*确定*按钮，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/914c131b-65df-48fc-8f20-228eee0db8f6.png)

1.  现在你应该在新的 ASP.NET Web Core 应用程序 - FlixOne.API 屏幕上。确保在此屏幕上，选择 ASP.NET Core 2.2。从可用模板中选择 Web 应用程序（模型-视图-控制器），并取消选择 HTTPS 复选框，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/90477786-80eb-41aa-b030-2bf74fa836dd.png)

1.  您将看到一个默认页面出现，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/193efeb2-573e-4ed9-a6d9-49ec51d1d571.png)

1.  展开“解决方案资源管理器”，单击“显示所有文件”。您将看到 Visual Studio 创建的默认文件夹/文件。参考以下截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/40563f44-0662-4c1b-aa6e-4901e13813ae.png)

我们选择了 ASP.NET Core Web（Model-View-Controller）模板。因此，我们有默认的文件夹 Controllers，Models 和 Views。这是 Visual Studio 提供的默认模板。要检查此默认模板，请按*F5*并运行项目。然后，您将看到以下默认页面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/61edea34-6458-48cb-b002-75bcbfa738a9.png)

上一个截图是我们的 Web 应用程序的默认主屏幕。您可能会想*这是一个网站吗？*并期望在这里看到 API 文档页面而不是网页。这是因为当我们选择模板时，Visual Studio 默认添加 MVC Controller 而不是 API Controller。请注意，在 ASP.NET Core 中，MVC Controller 和 API Controller 都使用相同的 Controller Pipeline（参见 Controller 类：[`docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.controller?view=aspnetcore-2.2`](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.controller?view=aspnetcore-2.2)）。

在详细讨论 API 项目之前，让我们首先向我们的 FlixOne 解决方案添加一个新项目。要这样做，请展开“解决方案资源管理器”，右键单击解决方案名称，然后单击“添加新项目”。参考以下截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/8b9834e5-e012-4982-932b-057a6510b41e.png)

在“新建项目”窗口中，添加新的`FlixOne.CQRS`项目，然后单击`OK`按钮。参考以下截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/87ee0e48-d801-44b4-9c68-6e9201eb48e5.png)

上一个截图是“添加新项目”窗口。在其中，选择.NET Core，然后选择 Class Library(.NET Core)项目。输入名称`FlixOne.CQRS`，然后单击“OK”按钮。已将新项目添加到解决方案中。然后，您可以添加文件夹到新解决方案，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/cb3a872f-4b1b-486f-b858-b04df8b0855e.png)

上一个截图显示我已添加了四个新文件夹：`Commands`，`Queries`，`Domain`和`Helper`。在`Commands`文件夹中，我有`Command`和`Handler`子文件夹。同样，对于`Queries`文件夹，我添加了名为`Handler`和`Query`的子文件夹。

要开始项目，让我们首先在项目中添加两个领域实体。以下是所需的代码：

```cs
public class Product
{
    public Guid Id { get; set; }
    public string Name { get; set; }
    public string Description { get; set; }
    public string Image { get; set; }
    public decimal Price { get; set; }
}
```

上述代码是一个`Product`领域实体，具有以下属性：

+   `Id`：一个唯一标识符

+   `Name`：产品名称

+   `Description`：产品描述

+   `Image`：产品的图像

+   `Price`：产品的价格

我们还需要添加`CommandResponse`数据库。在与数据库/存储库交互时，这在确保系统获得响应方面起着重要作用。以下是`CommandResponse`实体模型的代码片段：

```cs
public class CommandResponse
{
    public Guid Id { get; set; }
    public bool Success { get; set; }
    public string Message { get; set; }

}
```

上述`CommandResponse`类包含以下属性：

+   `Id`：唯一标识符。

+   `Success`：具有`True`或`False`的值，告诉我们操作是否成功。

+   `Message`：作为操作响应的消息。如果`Success`为 false，则此消息包含`Error`。

现在是时候为查询添加接口了。要添加接口，请按照以下步骤进行：

1.  从“解决方案资源管理器”中，右键单击`Queries`文件夹，单击“添加”，然后单击“新建项”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/c7b79ebb-67b7-49ff-a003-26a089491ba5.png)

1.  从“添加新项”窗口中，选择接口，命名为`IQuery`，然后单击“添加”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/e055b30e-23f0-49bd-b246-49d682935ed7.png)

1.  按照上述步骤，还要添加`IQueryHandler`接口。以下是`IQuery`接口的代码：

```cs
public interface IQuery<out TResponse>
{
}
```

1.  上一个接口作为查询任何类型操作的骨架。这是使用`TResponse`类型的`out`参数的通用接口。

以下是我们的`ProductQuery`类的代码：

```cs
public class ProductQuery : IQuery<IEnumerable<Product>>
{
}

public class SingleProductQuery : IQuery<Product>
{
    public SingleProductQuery(Guid id)
    {
        Id = id;
    }

    public Guid Id { get; }

}
```

以下是我们的`ProductQueryHandler`类的代码：

```cs
public class ProductQueryHandler : IQueryHandler<ProductQuery, IEnumerable<Product>>
{
    public IEnumerable<Product> Get()
    {
        //call repository
        throw new NotImplementedException();
    }
}
public class SingleProductQueryHandler : IQueryHandler<SingleProductQuery, Product>
{
    private SingleProductQuery _productQuery;
    public SingleProductQueryHandler(SingleProductQuery productQuery)
    {
        _productQuery = productQuery;
    }

    public Product Get()
    {
        //call repository
        throw new NotImplementedException();
    }
}
```

以下是我们的`ProductQueryHandlerFactory`类的代码：

```cs
public static class ProductQueryHandlerFactory
{
    public static IQueryHandler<ProductQuery, IEnumerable<Product>> Build(ProductQuery productQuery)
    {
        return new ProductQueryHandler();
    }

    public static IQueryHandler<SingleProductQuery, Product> Build(SingleProductQuery singleProductQuery)
    {
        return  new SingleProductQueryHandler(singleProductQuery);
    }
}
```

类似于`Query`接口和`Query`类，我们需要为命令及其类添加接口。

在我们为产品领域实体创建了 CQRS 的时候，您可以按照这个工作流程添加更多的实体。现在，让我们继续进行`FlixOne.API`项目，并按照以下步骤添加一个新的 API 控制器：

1.  从解决方案资源管理器中，右键单击`Controllers`文件夹。

1.  选择添加|新项目。

1.  选择 API 控制器类，并将其命名为`ProductController`；参考以下截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/b9088f70-6e1b-4b33-a49f-2cff8620875d.png)

1.  在 API 控制器中添加以下代码：

```cs
[Route("api/[controller]")]
public class ProductController : Controller
{
    // GET: api/<controller>
    [HttpGet]
    public IEnumerable<Product> Get()
    {
        var query = new ProductQuery();
        var handler = ProductQueryHandlerFactory.Build(query);
        return handler.Get();
    }

    // GET api/<controller>/5
    [HttpGet("{id}")]
    public Product Get(string id)
    {
        var query = new SingleProductQuery(id.ToValidGuid());
        var handler = ProductQueryHandlerFactory.Build(query);
        return handler.Get();
    }
```

以下代码是用于保存产品的：

```cs

    // POST api/<controller>
    [HttpPost]
    public IActionResult Post([FromBody] Product product)
    {
        var command = new SaveProductCommand(product);
        var handler = ProductCommandHandlerFactory.Build(command);
        var response = handler.Execute();
        if (!response.Success) return StatusCode(500, response);
        product.Id = response.Id;
        return Ok(product);

    }
```

以下代码是用于删除产品的：

```cs

    // DELETE api/<controller>/5
    [HttpDelete("{id}")]
    public IActionResult Delete(string id)
    {
        var command = new DeleteProductCommand(id.ToValidGuid());
        var handler = ProductCommandHandlerFactory.Build(command);
        var response = handler.Execute();
        if (!response.Success) return StatusCode(500, response);
        return Ok(response);
    }

```

我们已经创建了产品 API，并且在本节中不会创建 UI。为了查看我们所做的工作，我们将为我们的 API 项目添加**Swagger**支持。

Swagger 是一个用于文档目的的工具，并在一个屏幕上提供有关 API 端点的所有信息，您可以可视化 API 并通过设置参数进行测试。

要开始在我们的 API 项目中实现 Swagger，按照以下步骤进行：

1.  打开 Nuget 包管理器。

1.  转到 Nuget 包管理器|浏览并搜索`Swashbuckle.ASPNETCore`；参考以下截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/1704e800-d6c6-4e30-b6aa-ff6e38bde866.png)

1.  打开`Startup.cs`文件，并将以下代码添加到`ConfigureService`方法中：

```cs
//Register Swagger
            services.AddSwaggerGen(swagger =>
            {
                swagger.SwaggerDoc("v1", new Info { Title = "Product APIs", Version = "v1" });
            });
```

1.  现在，将以下代码添加到`Configure`方法中：

```cs
// Enable middleware to serve generated Swagger as a JSON endpoint.
app.UseSwagger();

// Enable middleware to serve swagger-ui (HTML, JS, CSS, etc.), specifying the Swagger JSON endpoint.
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Product API V1");
});
```

我们现在已经完成了展示应用程序中 CQRS 的强大功能的所有更改。在 Visual Studio 中按下*F5*，并通过访问以下 URL 打开 Swagger 文档页面：[`localhost:52932/swagger/`](http://localhost:52932/swagger/)（请注意，端口号`52932`可能会根据项目设置而有所不同）。您将看到以下 Swagger 文档页面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/2a67a98c-096c-4475-8258-7a0ace3abfbd.png)

在这里，您可以测试产品 API。

# 摘要

本章介绍了 CQRS 模式，然后我们将其实现到我们的应用程序中。本章的目的是通过数据库技术，并查看分类账式数据库如何用于库存系统。为了展示 CQRS 的强大功能，我们创建了产品 API，并添加了对 Swagger 文档的支持。

在下一章中，我们将讨论云服务，并详细了解微服务和无服务器技术。

# 问题

以下问题将帮助您巩固本章中包含的信息：

1.  什么是分类账式数据库？

1.  什么是 CQRS？

1.  我们何时应该使用 CQRS？


# 第十二章：为云端编码

之前的章节探讨了模式，从较低级别的概念，如单例和工厂模式，到特定技术的模式，如数据库和 Web 应用程序的模式。这些模式对于确保解决方案的良好设计以确保可维护性和高效实施至关重要。这些模式提供了一个坚实的基础，使应用程序能够在需求变化和添加新功能时得到增强和修改。

本章从更高层次的视角来看待解决方案，以解决设计实施可靠、可扩展和安全的问题。本章中的模式通常涉及包含多个应用程序、存储库和各种可能的基础设施配置的环境。

软件行业不断发展，随之而来的是新的机遇和新的挑战。在本章中，我们将探讨云端的不同软件模式。这些模式中许多并非新鲜事物，在本地环境中已经存在。随着云优先解决方案变得普遍，这些模式由于实施不依赖本地基础设施的便利性而变得更加普遍。

云优先或云原生解决方案旨在针对云计算资源，而混合解决方案则旨在同时使用云计算资源和私人数据中心的资源。

本章定义了在构建云端解决方案时的五个关键考虑因素：

+   可扩展性

+   可用性

+   安全性

+   应用设计

+   DevOps

我们将讨论这些关键考虑因素以及它们对构建云解决方案的重要性。随着讨论这些问题，将描述不同的模式，以应对这些问题。

# 技术要求

本章不需要任何特殊的技术要求或源代码，因为它主要是理论性的。

# 在构建云端解决方案时的关键考虑因素

决定转移到云端会带来一系列问题和挑战。在本节中，我们将涵盖构建基于云的解决方案的五个关键考虑领域。虽然这些问题并非云端独有，但在转向云端时需要特别关注，因为有各种技术和解决方案可供选择。

五个主要考虑因素如下：

+   **可扩展性**：这允许适应不断增长的业务的负载或流量。

+   **弹性/可用性**：这确保系统在发生故障时能够优雅地处理，对用户的影响尽可能小。

+   **安全性**：这确保私人和专有数据保持原样，并且免受黑客和攻击的威胁。

+   **应用设计**：这指的是专门考虑云端解决方案的应用设计。

+   **DevOps**：这是一套支持云端解决方案开发和运行的工具和实践集合。

根据您的业务需求，您可能需要寻找一些或所有这些考虑因素的解决方案。对于您的业务来说，采用能够解决您未预料到但会成为良好备用计划的问题的解决方案提供商也是最为有利的。

在接下来的章节中，我们将详细讨论这些考虑因素以及针对它们的可用解决方案模式。

这些模式涵盖了从技术类型到架构和业务流程的各种问题，一个单一模式可能涉及多个问题。

# 可扩展性

可扩展性指的是为了应用程序在给定的工作负载下保持可接受的质量水平而分配和管理资源的能力。大多数云服务提供机制来增加应用程序使用的资源的质量和数量。例如，Azure 应用服务允许扩展应用服务的大小和应用服务的实例数量。

可扩展性可以被视为对有限资源的需求。资源可以是磁盘空间、RAM、带宽或软件的另一个可以量化的方面。需求可以涵盖用户数量、并发连接数量或会对资源产生约束的其他需求。随着需求的增加，应用程序需要提供资源。当需求影响应用程序的性能时，这被称为资源瓶颈。

例如，一个度量标准可能是在应用程序性能开始恶化之前可以访问应用程序的用户数量。性能可以设置为请求的平均延迟小于 2 秒。随着用户数量的增加，可以查看系统的负载，并识别影响性能的特定资源瓶颈。

# 工作负载

为了确定如何有效地解决扩展性问题，了解系统将承受的工作负载是很重要的。有四种主要类型的工作负载：静态、周期性、一次性和不可预测的。

静态工作负载表示系统上的持续活动水平。由于工作负载不波动，这种类型的系统不需要非常弹性的基础设施。

具有可预测工作负载变化的系统具有周期性工作负载。例如，系统在周末或应交所得税的月份周围经历活动激增。这些系统可以进行扩展以在负载增加时保持所需的质量水平，并在负载减少时进行缩减以节省成本。

一次性工作负载表示围绕特定事件设计的系统。这些系统被配置为处理事件周围的工作负载，并在不再需要时取消配置。

不可预测的工作负载通常受益于前面提到的自动扩展功能。这些系统的活动波动很大，要么业务尚未理解，要么受其他因素影响。

理解和设计基于云的应用程序以适应其工作负载类型对于保持高性能水平和降低成本都至关重要。

# 解决方案模式

我们有三种设计模式和一种架构模式可供选择，以使我们的系统具有可扩展性：

+   垂直扩展

+   水平扩展

+   自动扩展

+   微服务

让我们更详细地审查每一种。

# 垂直扩展

虽然可以向本地服务器添加物理 RAM 或额外的磁盘驱动器，但大多数云提供商支持轻松增加或减少系统的计算能力。这通常是在系统扩展时几乎没有或没有停机时间。这种类型的扩展称为垂直扩展，指的是改变资源，如 CPU 类型、RAM 的大小和质量，或磁盘的大小和质量。

垂直扩展通常被称为“扩展”，而水平扩展通常被称为“扩展”。在这种情况下，“扩展”指的是资源的大小，“扩展”指的是实例的数量。

# 水平扩展

水平扩展与垂直扩展不同，因为水平扩展改变的是系统的数量，而不是系统的大小。例如，Web 应用程序可能在一台具有 4GB RAM 和 2 个 CPU 的单个服务器上运行。如果将服务器的大小增加到 8GB RAM 和 4 个 CPU，那么这将是垂直扩展。但是，如果增加了两台具有相同配置的 4GB RAM 和 2 个 CPU 的服务器，那么这将是水平扩展。

水平扩展可以通过使用某种形式的负载平衡来实现，该负载平衡将请求重定向到一组系统，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/1248ceaf-6ac8-4e3c-b613-ad243ecee78e.png)

水平扩展通常比垂直扩展更受云解决方案的青睐。这是因为一般来说，使用多个较小的虚拟机来提供相同性能的服务比使用单个大型服务器更具成本效益。

要使水平扩展最有效，确实需要支持这种类型扩展的系统设计。例如，设计时没有粘性会话和/或状态存储在服务器上的 Web 应用程序更适合水平扩展。这是因为粘性会话会导致用户的请求被路由到同一台虚拟机进行处理，随着时间的推移，虚拟机之间的路由平衡可能变得不均匀，因此效率可能不尽如人意。

有状态应用程序

*有状态*应用程序在服务器或存储库上维护有关活动会话的信息。

无状态应用程序

*无状态*应用程序设计为不需要在服务器或存储库上存储有关活动会话的信息。这允许将单个会话中的后续请求发送到任何服务器进行处理，而不仅仅是发送到整个会话的同一服务器。

有状态的 Web 应用程序需要在共享存储库中维护会话或信息。无状态的 Web 应用程序支持更具弹性的模式，因为 Web garden 或 Web farm 中的任何服务器都可以失败而不会丢失会话信息。

Web *garden*是一种模式，其中同一 Web 应用程序的多个副本托管在同一台服务器上，而 Web *farm*是一种模式，其中同一 Web 应用程序的多个副本托管在不同的服务器上。在这两种模式中，路由用于将多个副本公开为单个应用程序。

# 自动扩展

使用云提供商而不是本地解决方案的优势是内置的自动扩展支持。作为水平扩展的附加好处，自动扩展应用程序的能力通常是云服务的可配置功能。例如，Azure 应用服务提供了设置自动扩展配置文件的功能，允许应用程序对条件做出反应。例如，以下屏幕截图显示了一个自动扩展配置文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/9d5b1f53-4831-473c-af9e-263e3667205e.png)

为工作日设计的配置文件将根据服务器负载增加或减少应用服务实例的数量。负载以 CPU 百分比来衡量。如果 CPU 百分比平均超过 60％，则实例数量增加到最多 10 个。同样，如果 CPU 百分比低于 30％，实例数量将减少到最少 2 个。

弹性基础设施允许资源在不需要重新部署或停机的情况下进行垂直或水平扩展。该术语实际上更多地是弹性程度，而不是指系统是否具有*弹性*或*非弹性*。例如，弹性服务可以允许在不需要重新启动服务实例的情况下进行垂直和水平扩展。较不具弹性的服务可以允许在不重新启动的情况下进行水平扩展，但在更改服务器大小时需要重新启动服务。

# 微服务

对于微服务的含义以及它与面向服务的架构（SOA）的关系有不同的解释。在本节中，我们将微服务视为 SOA 的一种完善，而不是一种新的架构模式。微服务架构通过添加一些额外的关键原则来扩展 SOA，要求服务必须：

+   规模小 - 因此称为*微*

+   围绕业务能力构建

+   与其他服务松散耦合

+   可以独立维护

+   具有隔离状态

# 规模小

微服务将 SOA 中的服务缩小到最小可能的规模。这与我们之前看到的一些其他模式非常契合，比如《保持简单愚蠢》（KISS）和《你不会需要它》（YAGNI）来自[第二章]，*现代软件设计模式和原则*。微服务应该只满足其要求，而不多做其他事情。

# 业务能力

通过围绕业务能力构建服务，我们以一种使得当业务需求发生变化时，我们的服务也会以类似的方式进行变更的方式来实现我们的实现。因此，较少可能会导致业务的一个领域的变化影响其他领域。

# 松散耦合

微服务应该使用技术无关的协议（如 HTTP）跨服务边界与其他服务进行交互。这使得微服务更容易集成，更重要的是，当另一个服务发生变化时，不需要重建微服务。这确实需要存在一个已知的*服务合同*。

服务合同

*服务合同*是分发给其他开发团队的服务定义。Web 服务描述语言（WSDL）是一种广为人知的基于 XML 的描述服务的语言，但其他语言，如 Swagger，也非常流行。

在实施微服务时，重要的是要有一个管理变更的策略。通过具有版本化的服务合同，可以清晰地向服务的客户传达变更。

例如，用于存储图书库存的微服务的策略可能如下：

+   每个服务将被版本化并包括 Swagger 定义。

+   每个服务将从版本 1 开始。

+   当进行需要更改服务合同的更改时，版本将增加 1。

+   服务将维护最多三个版本。

+   对服务的更改必须确保所有当前版本的行为都合适。

前面的基本策略确实有一些有趣的含义。首先，维护服务的团队必须确保更改不会破坏现有服务。这确保了新部署不会破坏其他服务，同时允许部署新功能。合同允许最多同时有三个服务处于活动状态，因此可以独立更新可靠的服务。

# 可以独立维护

这是微服务最显著的特点之一。使得一个微服务能够独立于其他微服务进行维护，使得企业能够在不影响其他服务的情况下管理该服务。通过管理服务，我们既包括服务的开发，也包括服务的部署。根据这一原则，微服务可以更新和部署，减少对其他服务的影响，并且以不同的变化速率进行部署。

# 隔离状态

隔离状态包括数据和其他可能共享的资源，包括数据库和文件。这也是微服务架构的一个显著特点。通过拥有独立的状态，我们减少了支持一个服务的数据模型的变化会影响其他服务的机会。

下图展示了更传统的 SOA 方法，多个服务使用单个数据库：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/d160a26b-1edb-470c-91ef-e87a93b40e64.png)

通过要求微服务具有隔离状态，我们将要求每个服务都有一个数据库，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/6b3b7c88-5528-4c3a-8215-2f707c7365f4.png)

这样做的好处在于每个服务可以选择最适合服务要求的技术。

# 优势

微服务架构确实代表了传统服务设计的转变，并且它在基于云的解决方案中表现良好。微服务的优势以及它们为什么越来越受欢迎可能并不立即明显。我们已经提到了微服务设计如何提供处理变化的优势。从技术角度来看，微服务可以在服务级别和数据库级别独立扩展。

也许不清楚的是微服务架构对业务的好处。通过拥有小型独立服务，业务可以以不同的方式来维护和开发微服务。业务现在可以选择以不同的方式托管服务，包括不同的云提供商，以最适合独立服务的方式。同样，服务的隔离性允许在开发服务时具有更大的灵活性。随着变化的发生，资源（即开发团队成员）可以根据需要分配到不同的服务，由于服务范围较小，所需的业务知识量也减少了。

# 弹性/可用性

弹性是应用程序处理失败的能力，而可用性是应用程序工作的时间的度量。如果一个应用程序拥有一组资源，并且即使其中一个资源变得无法操作或不可用，它仍然保持可用。

如果一个应用程序被设计成可以处理一个或多个资源失败而不会导致整个系统无法操作，这被称为**优雅降级**。

模式既适用于隔离应用程序的元素，也适用于处理元素之间的交互，以便在发生故障时限制影响。许多与弹性相关的模式侧重于应用程序内部或与其他应用程序之间的消息传递。例如，Bulkhead 模式将流量隔离成池，以便当一个池被压倒或失败时，其他池不会受到不利影响。其他模式应用特定技术来处理消息传递，如重试策略或补偿事务。

可用性对许多基于云的应用程序来说是一个重要因素，通常可用性是根据**服务级别协议**（**SLA**）来衡量的。在大多数情况下，SLA 规定了应用程序必须保持可操作的时间百分比。模式既涉及允许组件冗余，又使用技术来限制活动增加的影响。例如，基于队列的负载平衡模式使用队列来限制活动增加可能对应用程序的影响，充当调用者或客户端与应用程序或服务之间的缓冲。

弹性和可用性被确定为相关的云解决方案因素，因为通常一个具有弹性的应用程序可以实现严格的可用性 SLA。

# 解决方案模式

为了确保我们拥有一个具有弹性和可用性的系统，我们最好寻找一个具有特定架构的提供商。进入**事件驱动架构**（**EDA**）。

EDA 是一种使用*事件*来驱动系统行为和活动的架构模式。它下面提供的解决方案模式将帮助我们实现预期的解决方案。

# EDA

EDA 推广了松散连接的生产者和消费者的概念，其中生产者不直接了解消费者。在这种情况下，事件是指任何变化，从用户登录系统，到下订单，到进程无法成功完成。EDA 非常适合分布式系统，并允许高度可扩展的解决方案。

与 EDA 相关的模式和方法有很多，本节介绍的以下模式与 EDA 直接相关：

+   基于队列的负载平衡

+   发布者-订阅者

+   优先队列

+   补偿事务

# 基于队列的负载平衡

基于队列的负载平衡是一种有效的方式，可以最小化高需求对可用性的影响。通过在客户端和服务之间引入队列，我们能够限制或限制服务一次处理的请求数量。这可以实现更流畅的用户体验。以以下图表为例：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/80878957-90a5-47bd-a052-acb18a6d198c.png)

上图显示了客户端向队列提交请求进行处理，并将结果保存到表中。队列可以防止函数被突然的活动激增所压倒。

# 发布者-订阅者

发布者-订阅者模式指出有事件发布者和事件消费者。基本上，这是 EDA 的核心，因为发布者与消费者解耦，不关心将事件传递给消费者，只关心发布事件。事件将包含信息，用于将事件路由到感兴趣的消费者。然后消费者将注册或订阅对特定事件感兴趣：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/93444369-0f06-4847-b5ec-f974300ac2cd.png)

上图显示了一个客户服务和一个订单服务。客户服务充当发布者，并在添加客户时提交事件。订单服务已订阅了新客户事件。当接收到新客户事件时，订单服务将客户信息插入其本地存储。

通过将发布者-订阅者模式引入架构中，订单服务与客户服务解耦。这样做的一个优点是它为变更提供了更灵活的架构。例如，可以引入一个新服务来向不需要添加到客户服务使用的相同存储库的解决方案添加新客户。此外，可以有多个服务订阅新客户事件。添加欢迎电子邮件可以更容易地作为新的订阅者添加，而不必将此功能构建到单个的单片解决方案中。

# 优先队列

另一个相关的模式是优先队列，它提供了一种处理类似事件的不同机制。使用上一节中的新客户示例，可能会有两个订阅者对新客户事件感兴趣。一个订阅者可能对大多数新客户感兴趣，而另一个订阅者可能会识别应该以不同方式处理的客户子集。例如，来自农村地区的新订阅者可能会收到一封电子邮件，其中包含有关专门的运输提供商的额外信息。

# 补偿事务

在分布式系统中，将命令作为事务发出并不总是切实可行或可取的。在这种情况下，事务是指管理一个或多个命令的较低级别的编程构造，将它们作为单个操作来处理，要么全部成功，要么全部失败。在某些情况下，不支持分布式事务，或者使用分布式事务的开销超过了好处。补偿事务模式是为处理这种情况而开发的。让我们以 BizTalk 协调为例：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/e76b66c8-dbb6-4406-abf7-ff38d425fd48.png)

该图显示了一个过程中的两个步骤：在订单服务中创建订单和从客户服务中扣款。该图显示了首先创建订单，然后扣除资金。如果资金扣除不成功，则订单将从订单服务中移除。

# 安全

安全确保应用程序不会错误地披露信息或提供超出预期使用范围的功能。安全包括恶意和意外行为。随着云应用程序的增加以及广泛使用各种身份提供者，通常很难将访问权限限制为仅批准的用户。

最终用户身份验证和授权需要设计和规划，因为较少的应用程序是独立运行的，通常会使用多个身份提供者，如 Facebook、Google 和 Microsoft。在某些情况下，模式用于直接为改进性能和可伸缩性而提供对资源的访问。此外，其他模式涉及在客户端和应用程序之间创建虚拟墙壁。

# 解决方案模式

随着行业的日益互联，使用外部方来对用户进行身份验证的模式变得更加普遍。联合安全模式被选择用于讨论，因为它是确保系统安全的最佳方式之一，大多数**软件即服务（SaaS）**平台都提供此功能。

# 联合安全

联合安全将用户或服务（消费者）的身份验证委托给称为**身份提供者**（**IdP**）的外部方。使用联合安全的应用程序将信任 IdP 正确地对消费者进行身份验证并准确提供有关消费者或声明的详细信息。有关消费者的这些信息被呈现为令牌。这种情况的常见场景是使用 Google、Facebook 或 Microsoft 等社交 IdP 的 Web 应用程序。

联合安全可以处理各种场景，从交互式会话到身份验证后端服务或非交互式会话。另一个常见的场景是能够在一套分别托管的应用程序中提供单一的身份验证体验或**单点登录**（**SSO**）。这种情况允许从**安全令牌服务**（**STS**）获取单个令牌，并且在不需要重复登录过程的情况下将相同的令牌用于多个应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/8b8e558d-26c7-47d9-b3b8-1bdc16566e6f.png)

联合安全有两个主要目的。首先，通过拥有单一身份存储库，简化身份管理。这允许以集中和统一的方式管理身份，使得执行管理任务（如提供登录体验、忘记密码管理以及一致地撤销密码）更容易。其次，通过为用户提供类似的体验跨多个应用程序，以及只需要记住单个密码而不是多个密码，提供更好的用户体验。

有几种联合安全标准，其中两种广泛使用的是**安全断言标记语言**（**SAML**）和**OpenId Connect**（**OIDC**）。SAML 比 OIDC 更早，允许使用 XML SAML 格式交换消息。OIDC 建立在 OAuth 2.0 之上，通常使用**JSON Web Token**（**JWT**）来描述安全令牌。这两种格式都支持联合安全、单点登录（SSO），许多公共 IdP（如 Facebook、Google 和 Microsoft）都支持这两种标准。

# 应用程序设计

应用程序的设计可以有很大的变化，并受到许多因素的影响。这些因素不仅仅是技术上的，而且受到参与构建、管理和维护应用程序的团队的影响。例如，一些模式最适合小型专门团队，而不适合较大数量的地理分散的团队。其他与设计相关的模式更好地处理不同类型的工作负载，并在特定场景中使用。其他模式是围绕变更的频率设计的，以及如何限制应用程序发布后的变更中断。

# 解决方案模式

几乎所有的本地模式都适用于基于云的解决方案，可以涵盖的模式范围令人震惊。缓存和 CQRS 模式之所以被选择，是因为前者是大多数 Web 应用程序采用的非常常见的模式，而后者改变了设计者构建解决方案的方式，并且非常适合其他架构模式，如 SOA 和微服务。

# 缓存

将从较慢的存储中检索的信息存储到更快的存储中，或者进行缓存，是几十年来编程中使用的一种技术，可以在浏览器缓存等软件和 RAM 等硬件中看到。在本章中，我们将看到三个例子：缓存旁路、写入穿透缓存和静态内容托管。

# 缓存旁路

缓存旁路模式可以通过在本地或更快的存储中加载频繁引用的数据来提高性能。使用此模式，应用程序负责维护缓存的状态。如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/0fd306bb-6874-4916-83c7-54ffcdd30e3f.png)

首先，应用程序从缓存中请求信息。如果信息丢失，则从数据存储中请求。然后，应用程序使用信息更新缓存。一旦信息存储，它将从缓存中检索并在不引用较慢的数据存储的情况下使用。使用此模式，应用程序负责维护缓存，无论是在缓存未命中时，还是在数据更新时。

术语*缓存未命中*指的是在缓存中找不到数据。换句话说，它在缓存中丢失了。

# 写入穿透缓存

写入穿透缓存模式也可以像缓存旁路模式一样用于提高性能。其方法不同之处在于将缓存内容的管理从应用程序移动到缓存本身，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/2b8f50a0-1ebe-44cd-943e-2011381bb41e.png)

在缓存中请求一条信息。如果数据尚未加载，则从数据存储中检索信息，将其放入缓存，然后返回。如果数据已经存在，则立即返回。这种模式支持通过缓存服务传递信息的写入来更新缓存。然后，缓存服务更新保存的信息，无论是在缓存中还是在数据存储中。

# 静态内容托管

静态内容托管模式将媒体图像、电影和其他非动态文件等静态内容移动到专门用于快速检索的系统中。这样的专门服务称为**内容传递网络**（**CDN**），它可以管理跨多个数据中心的内容分发，并将请求定向到最接近调用者的数据中心，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/d72bd427-be1a-4e5b-b152-8c8bc6e0ec2d.png)

静态内容托管是 Web 应用程序的常见模式，其中从 Web 应用程序请求动态页面，页面包含静态内容的集合，例如 JavaScript 和图像，然后浏览器直接从 CDN 中检索。这是减少 Web 应用程序流量的有效方法。

# 命令和查询责任分离

**命令和查询职责分离**（CQRS）是一个很好的软件模式，我们将在更多细节上讨论它，因为它在概念上很简单，相对容易实现，但对应用程序和涉及的开发人员有着巨大的影响。该模式清晰地将影响应用程序状态的命令与仅检索数据的查询分开。简而言之，更新、添加和删除等命令在不同的服务中提供，而不会改变任何数据的查询则在不同的服务中提供。

你可能会说*又是 CQRS*！我们意识到我们在面向对象编程和数据库设计中使用了 CQRS 的示例。同样的原则也适用于软件开发的许多领域。我们在本节中提出 CQRS 作为服务设计的一种模式，因为它带来了一些有趣的好处，并且与微服务和反应式应用程序设计等现代模式非常契合。

CQRS 基于贝尔特兰·梅耶（Bertrand Meyer）在上世纪 80 年代末出版的《面向对象的软件构造》一书中提出的面向对象设计：[`se.ethz.ch/~meyer/publications/`](http://se.ethz.ch/~meyer/publications/)。

如果我们重新访问第五章：*实现设计模式-.NET Core*，我们通过将库存上下文拆分为两个接口：`IInventoryReadContext`和`IInventoryWriteContext`来说明这种模式。作为提醒，这些是接口：

```cs
public interface IInventoryContext : IInventoryReadContext, IInventoryWriteContext { }

public interface IInventoryReadContext
{
    Book[] GetBooks();
}

public interface IInventoryWriteContext
{
    bool AddBook(string name);
    bool UpdateQuantity(string name, int quantity);
}
```

正如我们所看到的，`GetBooks`方法与修改库存状态的`AddBook`和`UpdateQuantity`方法分开。这在代码解决方案中展示了 CQRS。

相同的方法也可以应用在服务层。举例来说，如果我们使用一个用于维护库存的服务，我们会将服务分为一个用于更新库存的服务和另一个用于检索库存的服务。下图展示了这一点：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/54d55117-1d9a-43ec-85f4-67b74384663e.png)

让我们首先通过探讨 CQRS 来看看在基于云的解决方案中应用时所面临的挑战。

# CQRS 的挑战

使用 CQRS 模式的挑战很大：

+   一致性

+   采用

陈旧性是数据反映已提交数据版本的程度。在大多数情况下，数据可能会发生变化，因此，一旦读取了一部分数据，就有可能更新数据，使读取的数据与源数据不一致。这是所有分布式系统都面临的挑战，因为不可能保证向用户显示的值反映源值。当数据直接反映存储的内容时，我们可以称数据是一致的；当数据不是这样时，就被视为不一致。

在分布式系统中常用的一个术语是*最终一致性*。最终一致性用于表示系统最终会变得一致。换句话说，它最终会变得一致。

另一个更微妙的挑战是采用。将 CQRS 引入已建立的开发团队可能会遇到抵制，无论是来自不熟悉该模式的开发人员和设计师，还是来自业务方面对偏离当前设计模式的支持不足。

那么有什么好处呢？

# 为什么选择 CQRS？

以下是使用 CQRS 的三个引人注目的因素：

+   **协作**

+   **模型分离**

+   **独立扩展性**

通过分开的服务，我们可以独立地维护、部署和扩展这些服务。这增加了开发团队之间可以实现的协作水平。

通过拥有独立的服务，我们可以使用最适合我们服务的模型。命令服务可能直接使用简单的 SQL 语句针对数据库，因为这是负责团队最熟悉的技术，而构建查询服务的团队可能会使用一个处理复杂语句针对数据库的框架。

大多数解决方案往往具有更高的读取量而不是写入量（或反之），因此根据这一标准将服务进行拆分在许多情况下是有意义的。

# DevOps

通过基于云的解决方案，数据中心是远程托管的，通常您无法完全控制或访问应用程序的所有方面。在某些情况下，例如无服务器服务，基础架构被抽象化了。应用程序仍然必须公开有关运行应用程序的信息，以便用于管理和监视应用程序。用于管理和监视的模式对于应用程序的成功至关重要，因为它们既能够保持应用程序的健康运行，又能够为业务提供战略信息。

# 解决方案模式

随着与监控和管理解决方案相关的商业软件包的可用性，许多企业已经更好地控制和了解了他们的分布式系统。遥测和持续交付/持续集成已被选择进行更详细的覆盖，因为它们在基于云的解决方案中具有特殊价值。

# 遥测

随着软件行业的发展和分布式系统涉及更多的服务和应用程序，能够对系统进行集体和一致的视图已经成为一项巨大的资产。由 New Relic 和 Microsoft Application Insights 等服务推广，应用程序性能管理（APM）系统使用记录的有关应用程序和基础设施的信息，即遥测，来监视、管理性能和查看系统的可用性。在基于云的解决方案中，通常无法或不实际直接访问系统的基础设施，APM 允许将遥测发送到中央服务，然后呈现给运营和业务，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/3799f3e4-3f09-45ba-b16e-43093c14d35c.png)

上图摘自 Microsoft Application Insights，提供了一个正在运行的 Web 应用程序的高层快照。一眼就可以看出，运营人员可以识别系统行为的变化并做出相应反应。

# 持续集成/持续部署

持续集成/持续部署（CI/CD）是一种现代开发流程，旨在通过频繁合并更改并经常部署这些更改来简化软件交付产品生命周期。CI 解决了企业软件开发中出现的问题，即多个程序员正在同一代码库上工作，或者单个产品由多个代码分支管理。

看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/242a34d7-263b-49fd-bcbd-c06e5fe5d85c.png)

在上面的示例中，有三个目标环境：开发、用户验收测试（UAT）和生产。开发环境是最初的环境，所有对应用程序的更改都在此进行测试。UAT 环境由质量保证（QA）团队用于在将更改移至面向客户的环境之前验证系统是否按预期工作，如图中所示的生产环境。代码库已分为三个匹配的分支：主干，开发团队将所有更改合并到其中，UAT 用于部署到 UAT 环境，生产代码库用于部署到生产环境。

CI 模式是通过在代码库更改时创建新构建来应用的。成功构建后，会对构建运行一系列单元测试，以确保现有功能未被破坏。如果构建不成功，开发团队会进行调查，然后修复代码库或单元测试，使构建通过。

成功的构建然后被推送到目标环境。主干可能被设置为每天自动将新构建推送到集成环境，而 QA 团队要求环境中的干扰更少，因此新构建仅在办公时间结束后每周推送一次。生产可能需要手动触发以协调新版本的发布，以宣布新功能和错误修复的正式发布。

关于“持续部署”和“持续交付”这两个术语存在混淆。许多来源区分这两个术语，即部署过程是自动化的还是手动的。换句话说，持续部署需要自动化的持续交付。

导致环境之间合并的触发器，从而推送到环境中进行构建，或者发布，可能会有所不同。在我们对开发环境的示例中，有一组自动化测试会自动运行对新构建进行测试。如果测试成功，那么就会自动从主干合并到 UAT 代码库。只有在 QA 团队在 UAT 环境中签署或接受更改后，才会在 UAT 和生产代码库之间执行合并。

每个企业都会根据其特定的 SDLC 和业务需求来定制 CI/CD 流程。例如，一个面向公众的网站可能需要快速的 SDLC 以保持市场竞争力，而内部应用可能需要更保守的方法，以限制由于功能变更而导致的员工培训。

尽管如此，已经开发了一套工具套件来管理组织内的 CI/CD 流程。例如，Azure DevOps 可以通过允许构建管道来处理构建何时创建以及何时发布到环境中，包括手动和自动触发器。

# 总结

云开发需要仔细的规划、维护和监控，模式可以帮助实现高度可扩展、可靠和安全的解决方案。本章讨论的许多模式适用于本地应用程序，并且在云解决方案中至关重要。云优先应用程序的设计应考虑许多因素，包括可扩展性、可用性、维护、监控和安全性。

可扩展的应用程序允许在系统负载波动时保持可接受的性能水平。负载可以通过用户数量、并发进程、数据量和软件中的其他因素来衡量。横向扩展解决方案的能力需要特定类型的应用程序开发，并且是云计算中特别重要的范例。诸如基于队列的负载平衡之类的模式是确保解决方案在负载增加时保持响应的重要技术。

本章涵盖的许多模式是互补的。例如，遵循命令和查询责任分离的应用程序可能利用联合安全来提供单一登录体验，并使用事件驱动架构来处理应用程序不同组件之间的一致性。

在基于云的解决方案中，有一个几乎无穷无尽的适用模式集合，用于解决分布式系统中的不同挑战。本章介绍的模式代表了因其广度以及它们如何相互补充而被选择的一部分。请参阅参考资料，以探索适用于基于云的解决方案的其他模式。

多么不容易啊！我们已经涵盖了从面向对象编程中使用的软件设计模式到基于云的解决方案中使用的架构模式，再到用于构建成功应用程序的更高效团队和模式。尽管我们尽力涵盖了各种模式，但肯定还有一些模式可能本该被添加进来。

谢谢，Gaurav 和 Jeffrey，希望您喜欢并从阅读*使用 C#和.NET Core 进行设计模式实践*中获得了一些收获。请告诉我们您的想法，并与我们分享您最喜欢的模式。

# 问题

以下问题将让您巩固本章中包含的信息：

1.  大多数模式是最近开发的，只适用于基于云的应用程序。真还是假？

1.  ESB 代表什么，并且可以在哪种类型的架构中使用：EDA、SOA 还是单片？

1.  队列负载平衡主要用于 DevOps、可伸缩性还是可用性？

1.  CI/CD 的好处是什么？在全球分散的大量团队还是一个小型的本地开发团队中，它会更有益？

1.  在遵循静态内容托管的网站中，浏览器是直接通过 CDN 检索图像和静态内容，还是 Web 应用程序代表浏览器检索信息？

# 进一步阅读

要了解本章涵盖的主题，请参考以下书籍。这些书籍将为您提供有关本章涵盖的各种主题的深入和实践性练习：

+   *Azure 无服务器计算食谱*，作者*Praveen Kumar Sreeram*，由*Packt Publishing*出版：[`www.packtpub.com/in/virtualization-and-cloud/azure-serverless-computing-cookbook`](https://www.packtpub.com/in/virtualization-and-cloud/azure-serverless-computing-cookbook)

+   *使用 Azure 的微服务*，作者*Namit Tanasseri*和*Rahul Rai*，由*Packt Publishing*出版：[`www.packtpub.com/in/virtualization-and-cloud/microservices-azure`](https://www.packtpub.com/in/virtualization-and-cloud/microservices-azure)

+   *面向开发人员的 Azure 实践*，作者*Kamil Mrzygłód*，由*Packt Publishing*出版：[`www.packtpub.com/virtualization-and-cloud/hands-azure-developers`](https://www.packtpub.com/virtualization-and-cloud/hands-azure-developers)

+   *使用.NET Core 2.0 构建微服务-第二版*，作者*Gaurav Aroraa*，由*Packt Publishing*出版：[`www.packtpub.com/application-development/building-microservices-net-core-20-second-edition`](https://www.packtpub.com/application-development/building-microservices-net-core-20-second-edition)。


# 第十三章：其他最佳实践

到目前为止，我们已经讨论了各种模式、风格和代码。在这些讨论中，我们的目标是理解编写整洁、清晰和健壮代码的模式和实践。本附录主要将专注于实践。实践对于遵守任何规则或任何编码风格都非常重要。作为开发人员，您应该每天练习编码。根据古老的谚语，*熟能生巧*。

这表明技能，比如玩游戏、开车、阅读或写作，并不是一下子就能掌握的。相反，我们应该随着时间和实践不断完善这些技能。例如，当你开始学开车时，你会慢慢来。你需要记住何时踩离合器，何时踩刹车，转动方向盘需要多远，等等。然而，一旦司机熟悉了开车，就不需要记住这些步骤了；它们会自然而然地出现。这是因为实践。

在本附录中，我们将涵盖以下主题：

+   用例讨论

+   最佳实践

+   其他设计模式

# 技术要求

本附录包含各种代码示例，以解释所涵盖的概念。代码保持简单，仅用于演示目的。本章中的大多数示例涉及使用 C#编写的.NET Core 控制台应用程序。

要运行和执行代码，需要满足以下先决条件：

+   Visual Studio 2019（但是，您也可以使用 Visual Studio 2017 运行应用程序）

# 安装 Visual Studio

要运行本章中包含的代码示例，您需要安装 Visual Studio 或更高版本。请按照以下说明操作：

1.  从以下下载链接下载 Visual Studio：[`docs.microsoft.com/en-us/visualstudio/install/install-visual-studio`](https://docs.microsoft.com/en-us/visualstudio/install/install-visual-studio)。

1.  按照安装说明操作。

1.  Visual Studio 有多个版本可供选择。我们正在使用 Windows 版的 Visual Studio。

本章的示例代码文件可在以下链接找到：[`github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Appendix`](https://github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Appendix)。

# 用例讨论

简而言之，用例是业务场景的预创建或符号表示。例如，我们可以用图示/符号表示来表示我们的登录页面用例。在我们的例子中，用户正在尝试登录系统。如果登录成功，他们可以进入系统。如果失败，系统会通知用户登录尝试失败。参考以下**登录**用例的图表：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/e8594ebb-7aa1-4044-8605-a1fb0732da21.png)

在上图中，用户称为**User1**、**User2**和**User3**正在尝试使用应用程序的登录功能进入系统。如果登录尝试成功，用户可以访问系统。如果不成功，应用程序会通知用户登录失败，用户无法访问系统。上图比我们实际的冗长描述要清晰得多，我们在描述这个图表。图表也是不言自明的。

# UML 图

在前一节中，我们用符号表示来讨论了登录功能。您可能已经注意到了图表中使用的符号。在前一个图表中使用的符号或符号是统一建模语言的一部分。这是一种可视化我们的程序、软件甚至类的方式。

UML 中使用的符号或符号已经从 Grady Booch、James Rumbaugh、Ivar Jacobson 和 Rational Software Corporation 的工作中发展而来。

# UML 图的类型

这些图表分为两个主要组：

+   **结构化 UML 图**：这些强调了系统建模中必须存在的事物。该组进一步分为以下不同类型的图表：

+   类图

+   包图

+   对象图

+   组件图

+   组合结构图

+   部署图

+   **行为 UML 图**：用于显示系统功能，包括用例、序列、协作、状态机和活动图。该组进一步分为以下不同类型的图表：

+   活动图

+   序列图

+   用例图

+   状态图

+   通信图

+   交互概述图

+   时序图

# 最佳实践

正如我们所建立的，实践是我们日常活动中发生的习惯。在软件工程中——在这里软件是被设计而不是制造的——我们必须练习以编写高质量的代码。在软件工程中可能有更多解释最佳实践的要点。让我们讨论一下：

+   **简短但简化的代码**：这是一个非常基本的事情，需要练习。开发人员应该每天使用简短但简化的代码来编写简洁的代码，并在日常生活中坚持这种实践。代码应该清晰，不重复。清晰的代码和代码简化在前几章已经涵盖过；如果您错过了这个主题，请重新查看第二章，*现代软件设计模式和原则*。看一下以下简洁代码的示例：

```cs
public class Math
{
    public int Add(int a, int b) => a + b;
    public float Add(float a, float b) => a + b;
    public decimal Add(decimal a, decimal b) => a + b;
}
```

前面的代码片段包含一个`Math`类，其中有三个`Add`方法。这些方法被编写来计算两个整数的和以及两个浮点数和十进制数的和。`Add(float a, float b)`和`Add(decimal a, decimal b)`方法是`Add(int a, int b)`的重载方法。前面的代码示例代表了一个场景，其中要求是制作一个具有 int、float 或 decimal 数据类型输出的单个方法。

+   **单元测试**：这是开发的一个组成部分，当我们想要通过编写代码来测试我们的代码时。**测试驱动开发**（**TDD**）是一个应该遵循的最佳实践。我们已经在第七章中讨论了 TDD，*为 Web 应用程序实现设计模式-第二部分*。

+   **代码一致性**：如今，开发人员很少有机会独自工作。开发人员大多在团队中工作，这意味着团队中的代码一致性非常重要。代码一致性可以指代码风格。在编写程序时，开发人员应该经常使用一些推荐的实践和编码转换。

声明变量的方法有很多种。以下是变量声明的最佳示例之一：

```cs
namespace Implement
{
    public class Consume
    {
        BestPractices.Math math = new BestPractices.Math();
    }
}
```

在前面的代码中，我们声明了一个`math`变量，类型为`BestPractices.Math`。这里，`BestPractices`是我们的命名空间，`Math`是类。如果在代码中没有使用`using`指令，那么完全命名空间限定的变量是一个很好的实践。

C#语言的官方文档非常详细地描述了这些约定。您可以在这里参考：[`docs.microsoft.com/en-us/dotnet/csharp/programming-guide/inside-a-program/coding-conventions`](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/inside-a-program/coding-conventions)。

+   **代码审查**：犯错误是人的天性，这也会发生在开发中。代码审查是练习编写无错代码和发现代码中不可预测错误的第一步。

# 其他设计模式

到目前为止，我们已经涵盖了各种设计模式和原则，包括编写代码的最佳实践。本节将总结以下模式，并指导您编写高质量和健壮的代码。这些模式的详细信息和实现超出了本书的范围。

我们已经涵盖了以下模式：

+   GoF 模式

+   设计原则

+   软件开发生命周期模式

+   测试驱动开发

在本书中，我们涵盖了许多主题，并开发了一个示例应用程序（控制台和 Web）。这不是世界的尽头，世界上还有更多的东西可以学习。

我们可以列出更多的模式：

+   **基于空间的架构模式**：**基于空间的模式**（**SBP**）是通过最小化限制应用程序扩展的因素来帮助应用程序可扩展性的模式。这些模式也被称为**云架构模式**。我们在第十二章中已经涵盖了其中的许多内容，*云编程*。

+   **消息模式**：这些模式用于基于消息的连接两个应用程序（以数据包的形式发送）。这些数据包或消息使用逻辑路径进行传输，各种应用程序连接在这些逻辑路径上（这些逻辑路径称为通道）。可能存在一种情况，其中一个应用程序有多个消息；在这种情况下，不是所有消息都可以一次发送。在存在多个消息的情况下，一个通道可以被称为队列，并且可以在通道中排队多个消息，并且可以在同一时间点从各种应用程序中访问。

+   **领域驱动设计的其他模式-分层架构**：这描述了关注点的分离，分层架构的概念就是从这里来的。在幕后，开发应用程序的基本思想是应该将其结构化为概念层。一般来说，应用程序有四个概念层：

+   **用户界面**：这一层包含了用户最终交互的所有内容，这一层接受命令，然后相应地提供信息。

+   **应用层**：这一层更多地涉及事务管理、数据转换等。

+   **领域层**：这一层专注于领域的行为和状态。

+   **基础设施层**：与存储库、适配器和框架相关的所有内容都在这里发生。

+   **容器化应用模式**：在我们深入研究之前，我们应该知道容器是什么。容器是轻量级、便携的软件；它定义了软件可以运行的环境。通常，运行在容器内的软件被设计为单一用途的应用程序。对于容器化应用程序，最重要的模式如下：

+   **Docker 镜像构建模式**：这种模式基于 GoF 设计模式中的生成器模式，我们在第三章中讨论过，*实现设计模式-基础部分 1*。它只描述了设置，以便用于构建容器。除此之外，还有一种多阶段镜像构建模式，可以从单个 Dockerfile 构建多个镜像。

# 总结

本附录的目的是强调实践的重要性。在本章中，我们讨论了如何通过实践提高我们的技能。一旦我们掌握了这些技能，就不需要记住实现特定任务的步骤。我们涵盖并讨论了一些来自现实世界的用例，讨论了我们日常代码的最佳实践，以及可以在我们日常实践中使用的其他设计模式，以提高我们的技能。最后，我们结束了本书的最后一章，并了解到通过实践和采用各种模式，开发人员可以提高其代码质量。

# 问题

以下问题将帮助您巩固本附录中包含的信息：

1.  什么是实践？从我们的日常生活和例行公事中举几个例子。

1.  我们可以通过实践获得特定的编码技能。解释一下。

1.  什么是测试驱动开发，它如何帮助开发人员进行实践？

# 进一步阅读

我们几乎已经到达了本书的结尾！在这个附录中，我们涵盖了许多与实践相关的内容。这并不是学习的终点，而只是一个开始，您还可以参考更多的书籍来进行学习和知识积累：

+   《.NET Core 领域驱动设计实战》由 Alexey Zimarev 撰写，由 Packt Publishing 出版：[`www.packtpub.com/in/application-development/hands-domain-driven-design-net-core`](https://www.packtpub.com/in/application-development/hands-domain-driven-design-net-core)。

+   《C#和.NET Core 测试驱动开发》，由 Ayobami Adewole 撰写，由 Packt Publishing 出版：[`www.packtpub.com/in/application-development/c-and-net-core-test-driven-development`](https://www.packtpub.com/in/application-development/c-and-net-core-test-driven-development)。

+   《架构模式》，由 Pethuru Raj, Harihara Subramanian 等人撰写，由 Packt Publishing 出版：[`www.packtpub.com/in/application-development/architectural-patterns`](https://www.packtpub.com/in/application-development/architectural-patterns)。

+   《并发模式和最佳实践》，由 Atul S. Khot 撰写，由 Packt Publishing 出版：[`www.packtpub.com/in/application-development/concurrent-patterns-and-best-practices`](https://www.packtpub.com/in/application-development/concurrent-patterns-and-best-practices)。


# 第十四章：评估

# 第一章 - .NET Core 和 C#中的面向对象编程概述

1.  晚期和早期绑定这两个术语是指什么？

早期绑定是在源代码编译时建立的，而晚期绑定是在组件运行时建立的。

1.  C#支持多重继承吗？

不支持。原因是多重继承会导致源代码更复杂。

1.  在 C#中，可以使用什么封装级别防止类被库外访问？

`internal`访问修饰符可用于将类的可见性限制为仅在库内部。

1.  聚合和组合之间有什么区别？

两者都是关联的类型，最容易区分的方法是涉及的类是否可以在没有关联的情况下存在。在组合关联中，涉及的类具有紧密的生命周期依赖性。这意味着当一个类被删除时，相关的类也被删除。

1.  接口可以包含属性吗？（这是一个有点棘手的问题）

接口可以定义属性，但是接口没有主体...

1.  狗吃鱼吗？

狗很可爱，但它们吃它们能够放进嘴里的大多数东西。

# 第二章 - 现代软件设计模式和原则

1.  在 SOLID 中，S 代表什么？责任是什么意思？

单一责任原则。责任可以被视为变更的原因。

1.  围绕循环构建的 SDLC 方法是瀑布还是敏捷？

敏捷是围绕开发过程在一系列周期中进行的概念构建的。

1.  装饰者模式是创建模式还是结构模式？

装饰者模式是一种结构模式，允许功能在类之间分配，并且特别适用于在运行时增强类。

1.  pub-sub 集成代表什么？

发布-订阅是一种有用的模式，其中进程发布消息，其他进程订阅以接收消息。

# 第三章 - 实现设计模式 - 基础部分 1

1.  在为组织开发软件时，有时很难确定需求的原因是什么？

为组织开发软件存在许多挑战。例如，组织行业的变化可能导致当前需求需要进行修改。

1.  瀑布式软件开发与敏捷软件开发相比的两个优点和缺点是什么？

瀑布式软件开发相对于敏捷软件开发提供了优势，因为它更容易理解和实现。在某些情况下，当项目的复杂性和规模较小时，瀑布式软件开发可能是比敏捷式软件开发更好的选择。然而，瀑布式软件开发不擅长处理变化，并且由于范围更大，项目完成之前需求变化的可能性更大。

1.  在编写单元测试时，依赖注入如何帮助？

通过将依赖项注入类，类变得更容易测试，因为依赖项是明确已知且更容易访问的。

1.  为什么以下陈述是错误的？使用 TDD，您不再需要人员测试新软件部署。

测试驱动开发通过将清晰的测试策略纳入软件开发生命周期中来提高解决方案的质量。然而，定义的测试可能不完整，因此仍然需要额外的资源来验证交付的软件。

# 第四章 - 实现设计模式 - 基础部分 2

1.  提供一个示例，说明为什么使用单例不是限制对共享资源访问的好机制？

单例有意在应用程序中创建瓶颈。它也是开发人员学习使用的第一个模式之一，因此通常在不需要限制对共享资源访问的情况下使用。

1.  以下陈述是否正确？为什么？`ConcurrentDictionary` 防止集合中的项目被多个线程同时更新。

对于许多 C# 开发人员来说，意识到 `ConcurrentDictionary` 不能防止集合中的项目被多个线程同时更新是一个痛苦的教训。`ConcurrentDictionary` 保护共享字典免受同时访问和修改。

1.  什么是竞争条件，为什么应该避免？

竞争条件是指多个线程的处理顺序可能导致不同的结果。

1.  工厂模式如何帮助简化代码？

工厂模式是在应用程序内部创建对象的有效方式。

1.  .NET Core 应用程序需要第三方 IoC 容器吗？

.NET Core 具有强大的控制反转内置到框架中。在需要时可以通过其他 IoC 容器进行增强，但不是必需的。

# 第五章 - 实现设计模式 - .NET Core

1.  如果不确定要使用哪种类型的服务生命周期，最好将类注册为哪种类型？为什么？

瞬态生命周期服务在每次请求时创建。大多数类应该是轻量级、无状态的服务，因此这是最好的服务生命周期。

1.  在 .NET Core ASP .NET 解决方案中，范围是定义为每个 Web 请求还是每个会话？

一个范围是每个 Web 请求（连接）。

1.  在 .NET Core DI 框架中将类注册为单例会使其线程安全吗？

不，框架将为后续请求提供相同的实例，但不会使类线程安全。

1.  .NET Core DI 框架只能被其他由微软提供的 DI 框架替换是真的吗？

是的，有许多 DI 框架可以用来替代原生 DI 框架。

# 第六章 - 实现 Web 应用程序的设计模式 - 第一部分

1.  什么是 Web 应用程序？

这是一个使用 Web 浏览器的程序，如果在公共网络上可用，可以从任何地方访问。它基于客户端/服务器架构，通过接收 HTTP 请求并提供 HTTP 响应来为客户端提供服务。

1.  制作您选择的 Web 应用程序，并描述 Web 应用程序的工作的图像。

参考 FlixOne 应用程序。

1.  什么是控制反转？

控制反转（IoC）是一个容器，用于反转或委托控制。它基于 DI 框架。.NET Core 具有内置的 IoC 容器。

1.  什么是 UI/架构模式？您想使用哪种模式，为什么？

UI 架构模式旨在创建强大的用户界面，以使用户更好地体验应用程序。从开发人员的角度来看，MVC、MVP 和 MVVM 是流行的模式。

# 第七章 - 实现 Web 应用程序的设计模式 - 第二部分

1.  认证和授权是什么？

认证是一个系统通过凭据（通常是用户 ID 和密码）验证或识别传入请求的过程。如果系统发现提供的凭据错误，那么它会通知用户（通常通过 GUI 屏幕上的消息）并终止授权过程。

授权始终在认证之后。这是一个过程，允许经过验证的用户在验证他们对特定资源或数据的访问权限后访问资源或数据。

1.  在请求的第一级使用认证，然后允许进入受限区域的传入请求安全吗？

这并不总是安全的。作为开发人员，我们应该采取一切必要的步骤，使我们的应用程序更安全。在第一级请求认证之后，系统还应检查资源级别的权限。

1.  您将如何证明授权始终在认证之后？

在 Web 应用程序的简单场景中，它首先通过请求登录凭据来验证用户，然后根据角色授权用户访问特定资源。

1.  什么是测试驱动开发，为什么开发人员关心它？

测试驱动开发是一种确保代码经过测试的方法；这就像通过编写代码来测试代码。TDD 也被称为红/蓝/绿概念。开发人员应该遵循它，使他们的代码/程序在没有任何错误的情况下工作。

1.  定义 TDD Katas。它如何帮助我们改进我们的 TDD 方法？

TDD Katas 是帮助通过实践学习编码的小场景或问题。您可以参考 Fizz Buzz Kata 的例子，开发人员应该应用编码来学习和练习 TDD。如果您想练习 TDD Katas，请参考此存储库：[`github.com/garora/TDD-Katas.`](https://github.com/garora/TDD-Katas)

# 第八章 – .NET Core 中的并发编程

1.  什么是并发编程？

每当事情/任务同时发生时，我们说任务是同时发生的。在我们的编程语言中，每当程序的任何部分同时运行时，它就是并发编程。

1.  真正的并行是如何发生的？

在单个 CPU 机器上不可能实现真正的并行，因为任务不可切换，它只在具有多个 CPU（多个核心）的机器上发生。

1.  什么是竞争条件？

更多线程可以访问相同的共享数据并以不可预测的结果进行更新的潜力可以称为竞争条件。

1.  为什么我们应该使用`ConcurrentDictionary`？

并发字典是一个线程安全的集合类，它存储键值对。这个类有锁语句的实现，并提供了一个线程安全的类。

# 第九章 – 函数式编程实践 – 一种方法

1.  什么是函数式编程？

函数式编程是一种符号计算的方法，就像我们解决数学问题一样。任何函数式编程都是基于数学函数的。任何函数式编程风格的语言都是通过两个术语来解决问题的：要解决什么和如何解决？

1.  函数式编程中的引用透明度是什么？

在函数式程序中，一旦我们定义了变量，它们在整个程序中不会改变其值。由于函数式程序没有赋值语句，如果我们需要存储值，就没有其他选择；相反，我们定义新变量。

1.  什么是`Pure`函数？

`Pure`函数是通过说它们是纯净的来加强函数式编程的函数。这些函数满足两个条件：

+   +   提供的参数的最终结果/输出将始终保持不变。

+   即使调用了一百次，这些都不会影响程序的行为或应用程序的执行路径。

# 第十章 – 响应式编程模式和技术

1.  什么是流？

一系列事件称为流。流可以发出三种东西：一个值，一个错误和一个完成信号。

1.  什么是响应式属性？

当事件触发时，响应式属性是会做出反应的绑定属性。

1.  什么是响应式系统？

根据响应式宣言，我们可以得出结论，响应式系统如下：

+   +   **响应式**：响应式系统是基于事件的设计系统，因此这种设计方法使得这些系统能够快速响应任何请求。

+   **可扩展**：响应式系统具有响应性。这些系统可以通过扩展或减少分配的资源来对可扩展性进行调整。

+   **弹性**：弹性系统是指即使出现任何故障/异常，也不会停止的系统。响应式系统是以这样的方式设计的，即使出现任何异常或故障，系统也不会死掉；它仍然在工作。

+   **基于消息**：任何项目的数据都代表一条消息，可以发送到特定的目的地。当消息或数据到达给定状态时，会发出一个信号事件来通知消息已经被接收。响应式系统依赖于这种消息传递。

1.  **合并两个响应流是什么意思？**

合并两个响应流实际上是将两个相似或不同的响应流的元素组合成一个新的响应流。例如，如果你有`stream1`和`stream2`，那么`stream3 = stream1.merge(stream2)`，但`stream3`的顺序不会按顺序排列。

1.  **什么是 MVVM 模式？**

**模型-视图-视图模型**（MVVM）是**模型-视图-控制器**（MVC）的变体之一，以满足现代 UI 开发方法，其中 UI 开发是设计师/UI 开发人员的核心责任，而不是应用程序开发人员。在这种开发方法中，一个更注重图形的设计师专注于使用户界面更具吸引力，可能并不关心应用程序的开发部分。通常，设计师（UI 人员）使用各种工具使用户界面更具吸引力。MVVM 的定义如下：

+   +   **模型**：也称为领域对象，它只保存数据；没有业务逻辑、验证等。

+   **视图**：这是为最终用户表示数据。

+   **视图模型**：这将视图和模型分开；它的主要责任是为最终用户提供更好的东西。

# 第十一章 - 高级数据库设计和应用技术

1.  **什么是分类账式数据库？**

这个数据库只用于插入操作；没有更新。然后，你创建一个视图，将插入聚合在一起。

1.  **什么是 CQRS？**

命令查询责任分离是一种将查询（插入）和命令（更新）之间的责任分离的模式。

1.  **何时使用 CQRS？**

CQRS 可以是一个适用于基于任务或事件驱动系统的良好模式，特别是当解决方案由多个应用程序组成而不是单个单片网站或应用程序时。它是**一种模式而不是一种架构**，因此应该在特定情况下应用，而不是在所有业务场景中应用。

# 第十二章 - 云编码

1.  **这是一个真实的陈述吗？大多数模式是最近开发的，只适用于基于云的应用。**

不，这不是真的。随着软件开发的变化，模式一直在不断发展，但许多核心模式已存在几十年。

1.  **ESB 代表什么？它可以用于哪种架构：EDA、SOA 还是单片？**

它代表企业服务总线。它可以有效地用于事件驱动架构和面向服务的架构。

1.  **基于队列的负载平衡主要用于 DevOps、可伸缩性还是可用性？**

可用性。基于队列的负载平衡主要用于处理负载的大幅波动，作为缓冲以减少应用程序变得不可用的机会。

1.  **CI/CD 的好处是什么？在全球分散团队的大量还是单个小型团队的共同开发人员中更有益？**

一般来说，CI/CD 有助于通过频繁执行合并和部署来及早识别开发生命周期中的问题。更大、更复杂的解决方案往往比更小、更简单的解决方案更有益。

1.  **在遵循静态内容托管的网站中，浏览器是直接通过 CDN 检索图像和静态内容，还是 Web 应用程序代表浏览器检索信息？**

内容交付网络可以通过在多个数据中心缓存静态资源来提高性能和可用性，从而使浏览器可以直接从最近的数据中心检索内容。

# 附录 A - 杂项最佳实践

1.  **什么是实践？从我们的日常生活中举几个例子。**

练习可能是一个或多个日常活动。要学会开车，我们应该练习驾驶。练习是一种不需要记忆的活动。我们日常生活中有很多练习的例子：一边看电视节目一边吃饭，等等。在你观看最喜欢的电视节目时吃东西并不会打乱你的节奏。

1.  **我们可以通过练习来掌握特定的编码技能。解释一下。**

是的，我们可以通过练习来掌握特定的编码技能。练习需要注意力和一贯性。例如，你想学习测试驱动开发。为了做到这一点，你需要先学会它。你可以通过练习 TDD-Katas 来学习它。

1.  **什么是测试驱动开发，它如何帮助开发者练习？**

测试驱动开发是一种确保代码经过测试的方法；就好像我们通过编写代码来测试代码一样。TDD 也被称为红/蓝/绿概念。开发者应该遵循它，使他们的代码/程序能够在没有任何错误的情况下运行。
