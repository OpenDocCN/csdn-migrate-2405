# Laravel 设计模式最佳实践（一）

> 原文：[`zh.annas-archive.org/md5/c21d87a1a56234879b851abfda164e5a`](https://zh.annas-archive.org/md5/c21d87a1a56234879b851abfda164e5a)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书介绍了如何使用 Laravel 4 设计模式开发不同的应用程序并解决重复出现的问题。它将引导您了解广泛使用的设计模式——生成器（管理器）模式、工厂模式、存储库模式和策略模式，并将使您能够在使用 Laravel 开发各种应用程序时使用这些模式。本书将帮助您找到稳定和可接受的解决方案，从而提高应用程序的质量。

在本书的过程中，您将了解到关于 PHP 设计模式及其在各种项目中的使用的一些清晰实用的示例。您还将熟悉 Laravel 的最佳实践，这将极大地减少引入错误到您的 Web 应用程序中的可能性。

到本书结束时，您将习惯于 Laravel 最佳实践和重要的设计模式，以创建一个出色的网站。

# 本书涵盖的内容

第一章 ，*设计和架构模式基础*，解释了设计和架构模式术语，并解释了这些设计模式及其元素的分类。本章提供了 Laravel 核心代码中的一些示例，其中包含了框架中使用的设计模式。在本章末尾，将解释模型-视图-控制器（MVC）架构模式及其优势。

第二章 ，*MVC 中的模型*，介绍了 MVC 架构模式中模型层的功能、结构、目的、在 SOLID 设计模式中的作用、Laravel 如何使用它以及 Laravel 模型层和 Eloquent ORM 的优势。还讨论了处理数据的 Laravel 类。

第三章 ，*MVC 中的视图*，介绍了 MVC 架构模式中视图层的功能、结构、目的以及 Laravel 视图层和 Blade 模板引擎的优势。还涵盖了视图在 MVC 模式中的作用以及 Laravel 对此的处理方式。

第四章 ，*MVC 中的控制器*，介绍了 MVC 架构模式中控制器层的功能、结构、目的以及在 Laravel 结构中的使用。

第五章 ，*Laravel 中的设计模式*，讨论了 Laravel 中使用的设计模式。我们还将看到它们如何以及为什么被使用，以及示例。

第六章 ，*Laravel 中的最佳实践*，将介绍 Laravel 中的基本和高级实践，以及在先前章节中描述的 Laravel 中使用的设计模式的示例以及使用这些模式的原因。

# 您需要什么

这些章节中编写的应用程序都基于 Laravel v4，因此您将需要 Laravel v4 标准要求列表中列出的内容，该列表可在[`laravel.com/docs/installation`](http://laravel.com/docs/installation)找到。要求如下：

+   PHP v5.4 或更高版本

+   MCrypt PHP 扩展

# 这本书适合谁

本书适用于使用 Laravel 开发 Web 应用程序的开发人员，他们希望提高 Web 应用程序的效率。假设您对 Laravel PHP 框架有一些经验，并且熟悉编写面向对象的编程方法。

# Take a break when you're tired~

**公众号：古德猫宁李**

+   电子书搜索下载

+   书单分享

+   书友学习交流

**网站：**[沉金书屋 https://www.chenjin5.com](https://www.chenjin5.com)

+   电子书搜索下载

+   电子书打包资源分享

+   分享学习资源

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："`where()`方法使用给定参数过滤查询。"

代码块设置如下：

```php
$users = DB::table('users')->get();
foreach ($users as $user)
{
    var_dump($user->name);
}
```

### 注意

警告或重要提示会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：设计和架构模式基础知识

编程实际上是一种生活方式，而不仅仅是一份工作。这是一种强烈的精神活动。世界上最优秀的开发人员 24/7 都在思考他们的工作。他们在工作桌前不在时想出最好的想法。通常，他们最好的工作是在键盘之外完成的。

由于开发人员需要从不同的角度看待问题，软件项目不能通过在办公室花更多时间或增加项目人员来加速。开发不仅仅是关于时间表和分配的任务。如果你访问谷歌和 IBM 等世界著名软件公司的开发中心，你会发现开发人员有很多机会远离键盘。编程问题必须在现实世界的背景下考虑。因此，面向对象编程是为了使我们的狩猎采集大脑更本能地编写软件而发明的；也就是说，软件组件具有现实世界中对象的属性和行为。当寻找问题的解决方案或实现我们想要的方式时，我们通常希望找到一种可重用、优化和廉价的方式。作为开发人员，我们有一些标准的方法来解决编程中一些常见的重复问题，这些方法被称为**设计模式**。

当你遇到一些经常出现的问题时，你会尝试找到解决方案，以便任何人都可以使用。这个概念无处不在 - 无论是机械、建筑，甚至是人类行为。编程绝对不例外。

编程解决方案取决于问题的需求，并相应地进行修改，因为每个问题都有其独特的条件。常见的重复问题存在于现实生活和编程生活中。因此，设计模式被赋予我们来实现我们的项目。这些模式已经被许多其他开发人员测试和使用，成功地解决了类似的问题。使用设计模式还可以使我们使用干净、标准化和可读的代码。决定编写一个使用模式 Y 的程序来执行 X 的程序是一种灾难的做法。它可能适用于演示模式的代码构造的程序，比如`hello world`，但不适用于其他大部分情况。

通过模式，我们还可以找到一种解决语言可能存在的低效性的方法。还有一点要注意的是，低效性通常与负面联系在一起，但并不一定总是不好的。

在本书中，我们将使用 Laravel PHP 框架来介绍 PHP 设计模式。在前几章中，我们还将从 Laravel 核心代码中给出例子。在接下来的章节中，我们将介绍 MVC 模式的基础知识。然后，我们将尝试分析 MVC 模式在 Laravel 和常见 MVC 方法之间的区别。我们希望本书能帮助您提高代码质量。

请注意，找到最稳定、高质量的解决方案直接取决于你对平台和语言的了解。我们强烈建议您熟悉 PHP 和 Laravel 框架中的数据类型和面向对象编程的基础知识。

在本章中，我们将解释设计模式术语，并学习这些设计模式及其元素的分类。我们将从 Laravel 核心代码中给出一些例子，其中包含了框架中使用的设计模式。最后，我们将解释**模型-视图-控制器**（**MVC**）架构模式及其优势。

# 设计模式

设计模式最早是由 Eric Gamma 和他的三个朋友在 1994 年首次提出的。设计模式基本上是在多个项目上实施的软件设计模式，并且其预期成功给出了一个想法，证明这种模式是解决常见重复问题的解决方案。

设计模式是解决问题的方式，也是以最佳方式获得预期结果的方式。因此，设计模式不仅是创建大型和健壮系统的方式，还以友好的方式提供了出色的架构。

在软件工程中，设计模式是软件设计中常见问题的一般可重复和优化解决方案。它是如何解决问题的描述或模板，解决方案可以在不同的实例中使用。以下是使用设计模式的一些好处：

+   维护

+   文档

+   可读性

+   轻松找到合适的对象

+   轻松确定对象的粒度

+   轻松指定对象接口

+   即使对于大型软件项目，实现起来也很容易

+   实现代码的可重用性概念

如果您不熟悉设计模式，了解的最佳方法是观察我们用于常见的日常生活问题的解决方案。

让我们看一下下面的图片：

![设计模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-dsn-ptn-best-prac/img/Image00001.jpg)

世界上存在许多不同类型的电源插头。因此，我们需要一个可重复使用、优化且比购买新设备更便宜的解决方案，以适应不同的电源插头类型。简而言之，我们需要一个适配器。看一下适配器的下面图片：

![设计模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-dsn-ptn-best-prac/img/Image00002.jpg)

在这种情况下，适配器是最佳解决方案，它是可重复使用、优化且便宜的。但是当我们的汽车轮胎爆胎时，适配器并不能为我们提供解决方案。

在面向对象的语言中，我们程序员使用对象来实现我们想要的结果。因此，我们有许多类型的对象、情况和问题。这意味着我们需要不止一种方法来解决不同类型的问题。

## 设计模式的元素

以下是设计模式的元素：

+   **名称**：这是我们用来描述问题的句柄

+   **问题**：这描述了何时应用模式

+   **解决方案**：这描述了元素、关系、责任和协作的方式，我们遵循这种方式来解决问题

+   **结果**：这详细说明了应用模式的结果和权衡

## 设计模式的分类

设计模式通常分为三个基本组：

+   创建模式

+   结构模式

+   行为模式

让我们在以下小节中进行检查。

### 创建模式

创建模式是软件开发领域中设计模式的一个子集；它们用于创建对象。它们将对象的设计与其表示分离。对象创建被封装和外包（例如，在工厂中），以保持对象创建的上下文独立于具体实现。这符合规则：“基于接口编程，而不是实现。”

创建模式的一些特点如下：

+   **通用实例化**：这允许在系统中创建对象，而无需在代码中标识特定的类类型（抽象工厂和工厂模式）

+   **简单性**：一些模式使对象创建变得更容易，因此调用者不必编写大量复杂的代码来实例化对象（生成器（管理器）和原型模式）

+   **创建约束**：创建模式可以限制谁可以创建对象，它们如何创建对象以及何时创建对象

以下模式被称为创建模式：

+   抽象工厂模式

+   工厂模式

+   生成器（管理器）模式

+   原型模式

+   单例模式

### 结构模式

在软件工程中，设计模式结构模式为各种实体之间的通信提供了简单的方式。

一些示例的结构如下：

+   组合：这将对象组合成树形结构（整个层次结构）。组合允许客户根据其组合统一对待为个体对象。

+   装饰器：这动态地向对象添加选项。装饰器是扩展功能的灵活替代实现。

+   飞行：这是一种小对象的共享（没有条件的对象），可以防止过度生产。

+   适配器：这将类的接口转换为客户端期望的另一个接口。适配器让那些由于不同接口而通常无法一起工作的类能够一起工作。

+   外观：这提供了符合子系统各种接口的统一接口。外观定义了一个更容易使用的子系统的高级接口。

+   代理：这实现了另一个对象的替代（代理），控制对原始对象的访问。

+   桥接：这将抽象与其实现分离，然后可以独立地进行更改。

### 行为模式

行为模式主要涉及类对象之间的通信。行为模式是最关注对象之间通信的模式。以下是行为模式的列表：

+   责任链模式

+   命令模式

+   解释器模式

+   迭代器模式

+   中介者模式

+   备忘录模式

+   观察者模式

+   状态模式

+   策略模式

+   模板模式

+   访问者模式

我们将在接下来的章节中介绍这些模式。如果您想查看 Laravel 核心中某些模式的用法，请查看以下列表：

+   生成器（管理器）模式：`Illuminate\Auth\AuthManager`和`Illuminate\Session\SessionManager`

+   工厂模式：`Illuminate\Database\DatabaseManager`和`Illuminate\Validation\Factory`

+   存储库模式：`Illuminate\Config\Repository`和`Illuminate\Cache\Repository`

+   策略模式：`IIlluminate\Cache\StoreInterface`和`Illuminate\Config\LoaderInterface`

+   提供程序模式：`IIlluminate\Auth\AuthServiceProvider`和`Illuminate\Hash\HashServiceProvider`

# 什么是 MVC？

1988 年，MVC 类三合一被用于构建 Smalltalk-80 中的用户界面。MVC 是一种软件工程中使用的架构模式，其基本原则是应用程序的逻辑应与其表示分离。它将给定的软件应用程序分为三个相互连接的部分，以便将信息的内部表示与信息呈现或用户接受的方式分离开来。参考以下图：

![什么是 MVC？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-dsn-ptn-best-prac/img/Image00003.jpg)

在上图中，您将看到 MVC 的元素。它显示了基于 MVC 的应用程序请求的一般生命周期。如您所见，在项目中使用 MVC 架构模式允许您将应用程序的不同层分离开，例如数据库层和 UI 层。

使用 MVC 模式的好处如下：

+   不同的视图和控制器可以替换，为同一模型提供替代用户界面。

+   它提供了同一模型的多个同时视图。

+   变更传播机制确保所有视图同时反映模型的当前状态。

+   更改只影响应用程序的用户界面变得更容易。

+   通过模型封装，更容易测试应用程序的核心。

+   MVC 模式的一个巨大好处是，当您使用不同的模板时，它允许您重复使用应用程序的逻辑。例如，当您想要在应用程序的某个部分内实现外部 API 时，重用应用程序的逻辑将非常有帮助。如果严格遵循 Laravel 的 MVC 方法，您只需要修改控制器以呈现许多不同的模板/视图。

# 摘要

在本章中，我们已经解释了设计模式的基础知识。我们还介绍了一些在 Laravel 框架中使用的设计模式。最后，我们解释了 MVC 架构模式的概念及其好处。

在下一章中，我们将深入介绍 MVC 概念及其在 Laravel 中的使用。在继续学习设计模式及其在 Laravel 中的实际代码使用之前，最重要的是理解框架对 MVC 概念的处理方式。


# 第二章：MVC 中的模型

在本章中，我们将讨论 MVC 结构中的模型是什么，它的目的是什么，它在 SOLID 设计模式中的作用是什么，Laravel 如何定义它，以及 Laravel 的模型层和 Eloquent ORM 的优势。我们还将讨论处理数据的 Laravel 类。

以下是本章将涵盖的主题列表：

+   模型的含义

+   在坚实的 MVC 设计模式中的模型角色

+   模型和模型实例

+   Laravel 如何定义模型

+   Laravel 的与数据库相关的类

# 什么是模型？

模型是模型-视图-控制器设计模式的一部分，我们可以简单地描述为处理从相应层接收的数据并将其发送回这些层的设计模式的层。这里需要注意的一点是，模型不知道数据来自何处以及如何接收数据。

简而言之，我们可以说模型实现了应用程序的业务逻辑。模型负责获取数据并将其转换为其他应用程序层可以管理的更有意义的数据，并将其发送回相应层。模型是应用程序的域层或业务层的另一个名称。

！[什么是模型？]（Image00004.jpg）

# 模型的目的

应用程序中的模型管理所有动态数据（不是硬编码的并来自数据库驱动程序的任何数据），并让应用程序的其他相关组件了解更改。例如，假设您的数据库中有一篇新闻文章。如果您手动从数据库更改它，当调用路由时 - 由于此请求 - 控制器在路由处理程序的请求后请求模型上的数据，并且控制器从模型接收更新后的数据。结果，它将此更新后的数据发送到视图，最终用户从响应中看到更改。所有这些与数据相关的交互都是模型的任务。模型处理的这个“数据”并不总是与数据库相关。在某些实现中，模型还可以用于处理一些临时会话变量。

在一般 MVC 模式中，模型的基本目的如下：

+   使用指定（数据库）驱动程序获取数据

+   验证数据

+   存储数据

+   更新数据

+   删除数据

+   创建条件关系

+   监视文件 I / O

+   与第三方网络服务交互

+   处理缓存和会话

如您所见，如果您始终遵循 MVC 模式，模型将涵盖应用程序逻辑的很大一部分。在现代框架中，有一个常见的错误是用户在学习设计模式时常犯的错误。他们通常会混淆模型与模型实例。尽管它们非常相似，但它们有不同的含义。

# 模型实例

在您的应用程序中，通常会有多个数据结构需要管理。例如，假设您正在运行一个博客。在一个简单的博客系统中，有作者、博客文章、标签和评论。假设您想要更新一篇博客文章；您如何定义要更新的数据是针对博客文章的？这就是模型实例派上用场的地方。

模型实例是大多数情况下从应用程序的模型层扩展的简单类。这些实例将应用程序的每个部分的数据逻辑分离开来。在我们的示例中，我们有四个部分要处理（用户、帖子、标签和评论）。如果我们要使用模型来处理这些，我们至少要创建四个实例（我们将在本章的* Eloquent ORM *下的*关系*部分中解释为什么至少是四个而不是确切的四个）。

！[模型实例]（Image00005.jpg）

从图中可以看出，控制器与模型实例交互以获取数据。由于模型实例是从模型本身扩展而来的，因此控制器可以自定义它或向过程添加其他层（如验证），而不是使用原始模型输出。

假设您想获取用户名为`George`的用户。如果没有从模型实例到数据库添加验证层，则`username`参数将直接传递到数据库，这可能是有害的。如果您在模型实例上添加了验证层（检查`username`参数是否为干净的字符串），即使参数是 SQL 注入代码，它也将首先通过验证层进行过滤，而不是直接传递到数据库，然后被检测为有害代码。然后，模型实例将向控制器返回一个消息或异常，指出参数无效。然后，控制器将向视图发送相应的消息，然后消息将显示给最终用户。在此过程中，应用程序甚至可以触发事件以记录此尝试。

# Laravel 中的模型

如果您还记得，我们在本章前面提到模型需要处理许多重要的工作。Laravel 4 不直接使用 MVC 模式，而是进一步扩展了该模式。例如，验证——在坚实的 MVC 模式中是模型的一部分——有它自己的类，但它并不是模型本身的一部分。数据库连接层为每个数据库驱动程序都有自己的类，但它们并没有直接打包在模型中。这为模型带来了可测试性、模块化和可扩展性。

Laravel 模型结构更专注于直接处理数据库过程，并与其他目的分开。其他目的被归类为门面。

要访问数据库，Laravel 有两个类。第一个是流畅的查询构建器，第二个是 Eloquent ORM。

## 流畅的查询构建器

流畅是 Laravel 4 的查询构建器类。流畅的查询构建器使用后端的 PHP 数据对象处理基本的数据库查询操作，并且可以与几乎任何数据库驱动程序一起使用。假设您需要将数据库驱动程序从 SQLite 更改为 MySQL；如果您使用流畅编写了查询，那么除非您使用了`DB::raw()`编写了原始查询，否则您大多数情况下不需要重写或更改代码。流畅在幕后处理这个。

让我们快速看一下 Laravel 4 的 Eloquent 模型（可以在`Vendor\Laravel\Framework\src\Illuminate\Database\Query`文件夹中找到）：

```php
<?php namespace Illuminate\Database\Query;

use Closure;
use Illuminate\Support\Collection;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Grammars\Grammar;
use Illuminate\Database\Query\Processors\Processor;

class Builder {
    //methods and variables come here
}
```

如您所见，Eloquent 模型使用一些类，如`Database`、`ConnectionInterface`、`Collection`、`Grammar`和`Processor`。所有这些都是为了在后端标准化数据库查询，如果需要，缓存查询，并将输出作为集合对象返回。

以下是一些基本示例，展示了查询的外观：

+   要从`users`表中获取所有名称并逐个显示它们，使用以下代码：

```php
$users = DB::table('users')->get();
foreach ($users as $user)
{
    var_dump($user->name);
}
```

`get()`方法以集合的形式从表中获取所有记录。通过`foreach()`循环，记录被循环，然后我们使用`->name`（一个对象）访问每个名称列。如果要访问的列是电子邮件，则会像`$user->email`一样。

+   要从`users`表中获取名为`Arda`的第一个用户，使用以下代码：

```php
$user = DB::table('users')->where('name', 'Arda')->first();
var_dump($user->name);
```

`where()`方法使用给定参数过滤查询。`first()`方法直接从第一个匹配的元素中返回单个项目的集合对象。如果有两个名为`Arda`的用户，则只会捕获第一个并将其设置为`$user`变量。

+   如果要在`where`子句中使用`OR`语句，可以使用以下代码：

```php
$user = DB::table('users')
->where('name', 'Arda')
->orWhere('name', 'Ibrahim')
->first();
var_dump($user->name);
```

+   要在`where`子句中使用操作符，应在要过滤的列名和变量之间添加以下第三个参数：

```php
$user = DB::table('users')->where('id', '>', '2')->get();
foreach ($users as $user)
{
    var_dump($user->email);
}
```

+   如果你使用偏移和限制，执行以下查询：

```php
$users = DB::table('users')->skip(10)->take(5)->get();
```

这在 MySQL 中产生了`SELECT` `* FROM` users `LIMIT 10,5`。`skip($integer)`方法将为查询设置一个偏移量，`take($ integer)`将限制输出为已设置为参数的自然数。

+   你还可以使用`select()`方法限制要获取的内容，并在 Fluent Query Builder 中轻松使用以下`join`语句：

```php
DB::table('users')
   ->join('contacts', 'users.id', '=', 'contacts.user_id')
   ->join('orders', 'users.id', '=', 'orders.user_id')
   ->select('users.id', 'contacts.phone', 'orders.price');
```

这些方法简单地将`users`表与 contacts 连接，然后将 orders 与 users 连接，然后获取`contacts`表中的用户 ID 和电话列，以及`orders`表中的价格列。

+   你可以使用闭包函数轻松地按参数分组查询。这将使您能够轻松编写更复杂的查询，如下所示：

```php
DB::table('users')
    ->where('name', '=', 'John')
    ->orWhere(function($query)
    {
        $query->where('votes', '>', 100)
              ->where('title', '<>', 'Admin');
    })
    ->get();
```

这将产生以下 SQL 查询：

```php
select * from users 
   where name = 'John' 
   or 
   (votes > 100 and title <> 'Admin')
```

+   你还可以在查询构建器中使用聚合（如`count`、`max`、`min`、`avg`和`sum`）：

```php
$users = DB::table('users')->count();
$price = DB::table('orders')->max('price');
```

+   有时，这样的构建器可能不够，或者你可能想要运行原始查询。你也可以将原始查询包装在 Fluent 中，如下所示：

```php
$users = DB::table('users')
     ->select(
array(
DB::raw('count(*) as user_count'),
'status',
)
)
     ->where('status', '<>', 1)
     ->groupBy('status')
     ->get();
```

+   要将新数据插入表中，请使用`insert()`方法：

```php
DB::table('users')->insert(
    array('email' => 'me@ardakilicdagi.com', 'points' => 100)
); 
```

+   要从表中更新行，请使用`update()`方法：

```php
DB::table('users')
->where('id', 1)
->update(array('votes' => 100)); 
```

+   要从表中删除行，请使用`delete()`方法：

```php
DB::table('users')
->where('last_login', '2013-01-01 00:00:00')
->delete(); 
```

+   利用`CachingIterator`，它使用`Collection`类，Fluent Query Builder 也可以在调用`remember()`方法时缓存结果：

```php
$user = DB::table('users')
->where('name', 'Arda')
->remember(10)
->first();
```

一旦调用了这个查询，它就会被缓存 10 分钟；如果再次调用这个查询，它将直接从缓存中获取，而不是从数据库中获取，直到 10 分钟过去。

## Eloquent ORM

Eloquent ORM 是 Laravel 中的 Active Record 实现。它简单、强大，易于处理和管理。

对于每个数据库表，你都需要一个新的 Model Instance 来从 Eloquent 中受益。

假设你有一个`posts`表，并且你想要从 Eloquent 中受益；你需要导航到`app/models`，并将此文件保存为`Post.php`（表名的单数形式）：

```php
<?php class Post extends Eloquent {}
```

就是这样！你已经准备好从 Eloquent 方法中受益了。

Laravel 允许你将任何表分配给任何 Eloquent Model Instance。这不是必需的，但以相应表的单数形式命名 Model Instances 是一个好习惯。这个名字应该是它所代表的表名的单数形式。如果你必须使用不遵循这个一般规则的名字，你可以通过在 Model Instance 内部设置受保护的`$table`变量来这样做。

```php
<?php Class Post Extends Eloquent {

   protected $table = 'my_uber_posts_table';

}
```

通过这种方式，你可以将表分配给任何所需的 Model Instance。

### 注意

不需要将实例添加到`app`中的`models`文件夹中。只要在`composer.json`中设置了`autoload`路径，你可以完全摆脱这个文件夹，并将其添加到任何你喜欢的地方。这将在编程过程中为你的架构带来灵活性。

让我们快速看一下 Laravel 4 的以下`Model`类，我们刚刚从中扩展出来的（位于`Vendor\Laravel\Framework\src\Illuminate\Database\Eloquent`文件夹中）：

```php
<?php namespace Illuminate\Database\Eloquent;

use DateTime;
use ArrayAccess;
use Carbon\Carbon;
use LogicException;
use JsonSerializable;
use Illuminate\Events\Dispatcher;
use Illuminate\Database\Eloquent\Relations\Pivot;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Contracts\JsonableInterface;
use Illuminate\Support\Contracts\ArrayableInterface;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Eloquent\Relations\MorphOne;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasManyThrough;
use Illuminate\Database\ConnectionResolverInterface as Resolver;

abstract class Model implements ArrayAccess, ArrayableInterface, JsonableInterface, JsonSerializable {
   //Methods and variables come here
}
```

Eloquent 使用`Illuminate\Database\Query\Builder`，这是我们之前描述的 Fluent Query Builder，它的方法在其中定义。由于这一点，所有可以在 Fluent Query Builder 中定义的方法也可以在 Eloquent ORM 中使用。

如你所见，所有使用的类都根据其目的进行了拆分。这为架构带来了更好的**抽象**和**可重用性**。

### 关系

Eloquent ORM 除了 Fluent Query Builder 之外还有其他好处。主要好处是 Model Instance Relations，它允许 Fluent Query Builder 轻松地与其他 Model Instances 建立关系。假设你有`users`和`posts`表，并且你想要获取 ID 为`5`的用户发布的帖子。关系建立后，可以轻松地使用以下代码获取这些帖子的集合：

```php
User::find(5)->posts;
```

这难道不是更容易了吗？有三种主要的关系类型：一对一，一对多和多对多。除了这些，Laravel 4 还有 has-many-through 和 morph-to-many（多对多多态）关系：

+   **一对一关系**：当两个模型彼此只有一个元素时使用。比如你有一个`User`模型，它应该只有一个元素在你的`Phone`模型中。在这种情况下，关系将被定义如下：

```php
//User.php model
Class User Extends Eloquent {

   public function phone() {
      return $this->hasOne('Phone'); //Phone is the name of Model Instance here, not a table or column name
   }

}

//Phone.php model
Class Phone Extends Eloquent {

   public function user() {
      return $this->hasOne('User');
   }

}
```

+   **一对多关系**：当一个模型有另一个模型的多个元素时使用。比如你有一个带有分类的新闻系统。一个分类可以有多个项目。在这种情况下，关系将被定义如下：

```php
//Category.php model
class Category extends Eloquent {

   public function news() {
      return $this->hasMany('News'); //News is the name of Model Instance here
   }

}

//News.php model
class News extends Eloquent {

   public function categories() {
      return $this->belongsTo('Category');
   }

}
```

+   **多对多关系**：当两个模型彼此有多个元素时使用。比如你有`Blog`和`Tag`模型。一篇博客文章可能有多个标签，一个标签可能被分配给多篇博客文章。对于这种情况，需要使用一个中间表和多对多关系来定义关系：

```php
//Blog.php Model
Class Blog Extends Eloquent {

   public function tags() {
      return $this->belongsToMany('Tag', 'blog_tag'); //blog_tag is the name of the pivot table
   }

}

//Tag.php model
Class Tag Extends Eloquent {

   public function blogs() {
      return $this->belongsToMany('Blog', 'blog_tag');
   }

}
```

Laravel 4 为这些已知的关系添加了一些灵活性和额外的关系。它们是“has-many-through”和“多态关系”。

+   **Has-many-through 关系**：这更像是快捷方式。比如你有一个`Country`模型，`User`模型和`Post`模型。一个国家可能有多个用户，一个用户可能有多个帖子。如果你想访问特定国家的用户创建的所有帖子，你需要定义关系如下：

```php
//Country.php Model
Class Country Extends Eloquent {

   public function posts() {
      return $this->hasManyThrough('Post', 'User');
   }

}
```

+   **多态关系**：这在 Laravel v4.1 中有。比如你有一个`News`模型，`Blog`模型和`Photo`模型。这个`Photo`模型为`News`和`Blog`都保存了图片，但是如何关联或识别特定的照片是为博客还是帖子？这可以很容易地完成。需要设置如下：

```php
//Photo.php Model
Class Photo Extends Eloquent {

   public function imageable() {
      return $this->morphTo(); //This method doesn't take any parameters, Eloquent will understand what will be morphed by calling this method
   }

}

//News.php Model
Class News Extends Eloquent {

   public function photos() {
      return $this->morphMany('Photo', 'imageable');
   }

}

//Blog.php Model
Class Blog Extends Eloquent {

   public function photos() {
      return $this->morphMany('Photo', 'imageable');
   }

}
```

关键字`imageable`，用来描述图片的所有者，不是必须的；它可以是任何东西，但你需要将它设置为一个方法名，并将它作为`morphMany`关系定义的第二个参数。这有助于我们理解我们将如何访问照片的所有者。这样，我们可以轻松地从`Photo`模型中调用它，而不需要了解它的所有者是`Blog`还是`News`：

```php
$photo = Photo::find(1);
$owner = $photo->imageable; //This brings either a blog collection or News according to its owner.
```

### 注意

在这个例子中，你需要在`Photo`模型的表中添加两个额外的列。这些列是`imageable_id`和`imageable_type`。`imageable`部分是变形方法的名称，后缀的 ID 和类型是将定义它将变形为的项目的确切 ID 和类型的键。

### 批量赋值

在创建新的模型实例（插入或更新数据时），我们传递一个变量，它被设置为一个带有属性名称和值的数组。然后这些属性通过批量赋值分配给模型。如果我们盲目地将所有输入添加到批量赋值中，这将成为一个严重的安全问题。除了查询方法，Eloquent ORM 还帮助我们进行批量赋值。比如你不希望`User`模型（`Object`）中的电子邮件列被以任何方式更改（黑名单），或者你只希望`Post`模型中的标题和正文列被更改（白名单）。这可以通过在你的模型中设置受保护的`$fillable`和`$guarded`变量来完成：

```php
//User.php model
Class User Extends Eloquent {
   //Disable the mass assignment of the column email 
   protected $guarded = array('email');

}

//Blog.php model
Class User Extends Eloquent {
   //Only allow title and body columns to be mass assigned
   protected $fillable = array('title', 'body');

}
```

### 软删除

假设你有一个`posts`表，假设这个表中的数据很重要。即使从模型运行`delete`命令，你也希望保留已删除的数据在你的数据库中以防万一。在这种情况下，你可以使用 Laravel 的软删除。

软删除实际上并不从表中删除行；相反，它在数据实际删除时添加一个键。当进行软删除时，一个名为`deleted_at`的新列将填充一个时间戳。

要启用软删除，您需要首先在表中添加一个名为`deleted_at`的时间戳列（您可以通过在迁移中添加`$table->softDeletes()`来完成），然后在您的模型实例中将一个名为`$softDelete`的变量设置为`true`。

以下是软删除的示例模型实例：

```php
//Post.php model
Class Post Extends Eloquent {
   //Allow Soft Deletes
   protected $softDelete = true;

}
```

现在，当您在此模型中运行`delete()`方法时，它将不会实际删除该列，而是会向其添加一个`deleted_at`时间戳。

现在，当您运行`all()`或`get()`方法时，软删除的列将不会被列出，就好像它们实际上已被删除一样。

在这种删除后，您可能希望获取包括软删除行在内的结果。要做到这一点，请使用`withTrashed()`方法如下：

```php
$allPosts = Post::withTrashed()->get(); //These results will include both soft-deleted and non-soft-deleted posts.
```

在某些情况下，您可能只想获取软删除的行。要做到这一点，使用`onlyTrashed()`方法如下：

```php
$onlySoftDeletedPosts = Post::onlyTrashed()->get();
```

要恢复软删除的行，请使用`restore()`方法。要恢复所有软删除的帖子，请运行以下代码：

```php
$restoreAllSoftDeletedPosts = Post::onlyTrashed()->restore();
```

要彻底删除表中的软删除行，请使用`forceDelete()`方法如下：

```php
$forceDeleteSoftDeletedPosts = Post::onlyTrashed()->forceDelete();
```

从表中获取行（包括软删除）时，您可能想要检查它们是否已被软删除。通过在集合行上运行`trashed()`方法来进行此检查。此方法将返回一个布尔值。如果为 true，则表示该行已被软删除。

```php
//Let's fetch a post without the soft-delete checking:
$post = Post::withTrashed()->find(1);
//Then let's check whether it's soft deleted or now if($post->trashed()) {
return 'This post is soft-deleted'; } else {
   return 'This post is not soft-deleted';
}
```

### 急切加载

Eloquent ORM 还通过**急切加载**为 N+1 查询问题提供了一个简洁的解决方案。假设您有一个查询和循环，如下所示：

```php
$blogs = Blog::all();
foreach($blogs as $blog) {
   var_dump($blog->images());
}
```

在这种情况下，为了访问这些图片，在后端的每个循环中执行一个查询。这将极大地耗尽数据库，为了防止这种情况，我们将在查询中使用`with()`方法。这将在后端获取所有的博客和图片，将它们关联起来，并直接作为一个集合提供。参考以下代码：

```php
$blogs = Blog::with('images')->get();
foreach($blogs as $blog) {
   var_dump($blog->images);
}
```

这样，查询速度将会更快，使用的资源也会更少。

### 时间戳

Eloquent ORM 的主要优势在于将`$timestamps`设置为`true`（这是默认值）；您将有两列，第一列是`created_at`，第二列是`updated_at`。这两列将数据的创建和最后更新时间作为时间戳，并在每行的创建或更新时自动更新它们。

### 查询范围

假设您因为它是您的应用程序中常用的子句之一而多次重复一个`where`条件，并且这个条件有意义。假设您想要获取所有具有超过 100 次浏览的博客文章（我们将其称为热门帖子）。如果不使用范围，您将以以下格式获取帖子：

```php
$popularBlogPosts = Blog::where('views', '>', '100')->get();
```

然而，在这个例子中，您将一遍又一遍地在应用程序中重复这个过程。那么，为什么不将其设置为一个范围呢？您可以使用 Laravel 的查询范围功能轻松实现这一点。

将以下代码添加到您的`Blog`模型中：

```php
public function scopePopular($query) {
   return $query->where('views', '>', '100');
}
```

完成这些操作后，您可以使用以下代码轻松使用您的范围：

```php
$popularBlogPosts = Blog::popular()->get();
```

您还可以将帖子链接如下：

```php
$popularBlogPosts = Blog::recent()->popular()->get();
```

### 访问器和修改器

Eloquent ORM 的一个特性是访问器和修改器。假设您的表上有一个名为`name`的列，并且在调用这个列时，您想要传递 PHP 的`ucfirst()`方法来将其名称大写。只需将以下代码添加到模型中即可完成：

```php
public function getNameAttribute($value) {
    return ucfirst($value);
}
```

现在，让我们考虑相反的情况。每次保存或更新名称列时，您都希望将 PHP 的`strtolower()`函数传递给该列（您希望修改输入）。只需将以下代码添加到模型中即可完成：

```php
public function setNameAttribute($value) {
    return strtolower($value);
}
```

请注意，方法名称应该是驼峰式命名，即使列名是`snake_cased`。如果您的列名是`first_name`，则 getter 方法名称应该是`getFirstNameAttribute`。

### 模型事件

模型事件在 Laravel 设计模式中扮演着重要的角色。使用模型事件，您可以在事件触发后立即调用任何方法。

假设您为评论设置了缓存，并且希望在每次删除评论时刷新缓存。您如何捕获评论的删除事件并在那里执行某些操作？应用程序中是否有多个地方可以删除此类评论？是否有一种方法可以精确捕获“删除”或“已删除”事件？在这种情况下，模型事件非常有用。

模型包含以下方法：`creating`、`created`、`updating`、`updated`、`saving`、`saved`、`deleting`、`deleted`、`restoring` 和 `restored`。

每当第一次保存新项目时，将触发创建和已创建事件。如果您正在更新模型上的当前项目，则将触发 `updating` / `updated` 事件。无论您是创建新项目还是更新当前项目，都将触发 `saving` / `saved` 事件。

如果从 `creating`、`updating`、`saving` 或 `deleting` 事件中返回 `false`，则操作将被取消。

例如，让我们检查用户是否已创建。如果其名字是 `Hybrid`，我们将取消创建。要添加此条件，请在您的 `User` 模型中包含以下代码行：

```php
User::creating(function($user){
    if ($user->first_name == 'Hybrid') return false;
});
```

### 模型观察者

模型观察者与模型事件非常相似，但方法略有不同。它不是在模型内部定义所有事件（`creating`、`created`、`updating`、`updated`、`saving`、`saved`、`deleting`、`deleted`、`restoring` 和 `restored`），而是将事件的逻辑“抽象”到不同的类中，并使用 `observe()` 方法“观察”它。假设我们有一个如下所示的模型事件：

```php
User::creating(function($user){
    if ($user->first_name == 'Hybrid') return false;
});
```

为了保持抽象，最好将所有这些事件封装起来，并将它们的逻辑与模型分开。在观察者中，这些事件将如下所示：

```php
class UserObserver {

   public function creating($model){
       if ($model->first_name == 'Hybrid') return false;
    }

    public function saving($model)
    {
        //Another model event action here
    }

}
```

您可以想象，您可以将这个类放在应用程序的任何位置。您甚至可以将所有这些事件分组在一个单独的文件夹中，以获得更好的架构模式。

现在，您需要将此事件 `Observer` 类注册到模型。可以使用以下简单命令完成：

```php
 **User::observe(new UserObserver);** 

```

这种方法的主要优势是您可以在多个模型中使用观察者，并以这种方式向一个模型注册多个观察者。

## 迁移

迁移是管理数据库版本控制的简单工具。假设有一个地方需要向表中添加新列，或者回滚到以前的状态，因为您做错了事情或应用程序的链接断开了。没有迁移，这些都是繁琐的任务，但有了迁移，您的生活将变得更加轻松。

使用迁移的各种原因如下：

+   您将受益于这种版本控制系统。如果出现错误或需要回滚到以前的状态，您只需使用迁移的一个命令即可完成。

+   使用迁移进行更改将带来灵活性。编写的迁移将适用于所有支持的数据库驱动程序，因此您无需为不同的驱动程序重写数据库代码。Laravel 将在后台处理这一切。

+   它们非常容易生成。使用 Laravel `php` 客户端的迁移命令，称为 `artisan`，您可以管理应用程序的所有迁移。

以下是迁移文件的样子：

```php
<?php

use Illuminate\Database\Migrations\Migration;

class CreateNewsTable extends Migration {

        /**
        * Run the migrations.
        */
        public function up()
        {
                //
        }

        /**
        * Reverse the migrations.
        */
        public function down()
        {
                //
        }

}
```

`up()` 方法在向前运行迁移时运行（新迁移）。`down()` 方法在向后运行迁移时运行，意味着它会反转或重置（反转并重新运行）迁移。

通过 `artisan` 命令触发这些方法后，它会运行 `up` 或 `down` 方法，与 `artisan` 命令的参数相对应，并返回消息的状态。

## 数据库种子数据填充器

假设您编写了一个博客应用程序。您需要展示它的功能，但没有示例博客文章来展示您编写的出色博客。这就是种子数据填充器派上用场的地方。

数据库 seeder 是一些简单的类，它们在指定的表中填充随机数据。seeder 类有一个简单的方法叫做`run()`来进行这种填充。以下是 seeder 的样子：

```php
<?php

class BlogTableSeeder extends Seeder {

  public function run()
  {
    DB::table('blogs')->insert(array(
      array('title' => 'My Title'),
      array('title' => 'My Second Title'),
      array('title' => 'My Third Title')
    ));
  }

}
```

当您使用`artisan`命令从终端调用这个类时，它会连接到数据库并用给定的数据填充它。尝试完成后，它会通过终端向用户返回有关填充状态的命令消息。

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，直接将文件发送到您的电子邮件。

# 读累了记得休息一会哦~

**公众号：古德猫宁李**

+   电子书搜索下载

+   书单分享

+   书友学习交流

**网站：**[沉金书屋 https://www.chenjin5.com](https://www.chenjin5.com)

+   电子书搜索下载

+   电子书打包资源分享

+   学习资源分享

# 总结

在本章中，我们已经了解了 MVC 模式中模型的作用，以及 Laravel 4 如何通过扩展其角色到各种类来“定义”模型。我们还通过示例看到了 Laravel 4 的模型组件的功能。

在下一章中，我们将学习视图的作用，以及它如何在 Laravel 4 中使用 MVC 模式与最终用户和应用程序的其他方面进行交互。


# 第三章：MVC 中的视图

在本章中，我们将讨论视图是什么，它的结构，它的目的，以及 Laravel 的视图层和 Blade 模板引擎的优势。

# 什么是视图？

Laravel 中的 View 指的是 MVC 中的 V。视图包括演示逻辑方面，如模板和缓存，以及涉及演示的代码。准确地说，视图定义了向用户呈现的内容。通常，控制器将数据传递给每个视图以某种格式呈现。视图也从用户那里收集数据。这是你可能在 MVC 应用程序中找到 HTML 标记的地方。

大多数现代 MVC，如 Laravel 框架，实现了一种模板语言，从 PHP 中添加了一个抽象层。添加层意味着增加了开销。在这里，我们坚持在模板中使用 PHP 的速度，但所有逻辑都留在外面。这使得用户界面（UI）设计师可以开发主题/模板，而无需学习任何编程语言。

在许多 MVC 实现中，视图层与控制器和模型进行通信。这种方法在以下图中得到了很好的解释：

![什么是视图？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-dsn-ptn-best-prac/img/Image00006.jpg)

正如你在上图中所看到的，视图与控制器和模型都有通信。乍一看，这似乎是一种使用面向对象编程语言开发应用程序的非常灵活的方法。在 MVC 的所有对象之间共享数据，并在应用程序的任何层中访问它们听起来非常酷。不幸的是，这种方法会导致一些依赖于项目规模的问题。

最主要的问题是在团队/开发人员之间分配开发任务的复杂性。如果你不设定开发规则，就会导致混乱的情况，比如无法管理的意大利面代码。此外，我们还必须考虑开发的额外成本，比如培训开发人员和相对较长的开发过程，这直接影响项目的成本。

正如我们在本书开头提到的，开发不仅涉及编码或共享任务，还包括规划和推广项目开发方法的过程。

Laravel 采用了一种不同的 MVC 方法。根据 Laravel，视图层应该只与控制器通信。模型与控制器通信。让我们看一下以下图：

![什么是视图？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-dsn-ptn-best-prac/img/Image00007.jpg)

正如你在上图中所看到的，应用程序的层完全分离。因此，你可以轻松地管理代码和开发团队。通常，我们在 MVC 中至少需要三个文件：模型文件、控制器文件和视图文件。让我们通过视图文件来解释视图。

# 视图对象

在你的应用程序中，通常会有多个包含表单、资产引用等的 HTML 页面；例如，如果你正在开发一个电子商务应用程序。在一个简单的电子商务系统中，有产品列表、类别、购物车和产品详细页面。这意味着我们需要四个模板和太多的数据呈现给用户。我们可以将视图层的对象分组如下：

+   HTML 元素（div、header、section 等）

+   HTML 表单元素（输入、选择等）

+   资产和 JavaScript 引用（.css 和.js）

当你在处理具有动态数据的项目时，分离模板文件并不能简化问题，因为你仍然需要编程语言函数来处理对象。这会导致我们不想面对的“意大利面代码”。当项目中的 HTML 文档中有内联 PHP 代码时，你将面临保持代码简单的问题。让我们来看一下以下代码中没有使用任何模板语言实现的通用模板文件内容：

```php
<!DOCTYPE html> 
<html lang="en"> 
<head> 
<title><?php echo $title; ?></title> 
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" /> 
<meta http-equiv="x-ua-compatible" content="chrome=1" /> 
<meta name="description" content="<?php echo $meta_desc; ?>" /> 
<meta name="keywords" content="<?php echo $meta_keys; ?>" /> 
<meta name="robots" content="index,follow" /> 
<meta property="og:title" content="<?php echo $title; ?>" /> 
<meta property="og:site_name" content="<?php echo $site_name; ?>" /> 
<meta property="og:image" content="http://www.example.com/images/"<?php echo $thumbnail; ?> /> 
<meta property="og:type" content="product" /> 
<meta property="og:description" content="<?php echo $meta_desc; ?>" /> 
</head> 
<body> 
<?php 
if($user_name){ 
?>
<div class="username">Welcome <?php echo strtoupper($user_name); ?> !</div> 
<?php 
}else{ 

echo '<div class="username">Welcome Guest!</div>'; 

} 
?> 
</body> 
```

作为 UI 开发人员，你需要对 PHP 语言有一定的了解（至少要了解语言的语法）才能理解你看到的代码。正如我们在第一章中提到的，*设计和架构模式基础*，大多数现代 MVC 框架都附带了一个模板语言，用于在视图中使用。Laravel 附带了一个实现的模板语言用于视图；这就是 Blade 模板引擎，或者简称 Blade。

# 在 Laravel 中的视图

根据 Laravel 的 MVC 方法，视图处理来自控制器的数据。这意味着视图获取的数据通常已经按我们的需要格式化了。如果视图直接与模型通信，我们必须在视图层格式化、验证或过滤数据，就像前面示例代码中所示的那样。因此，让我们看看 Blade 模板文件在下面的代码中是什么样子的：

```php
<!DOCTYPE html> 
<html lang="en"> 
<head> 
<title>{{$title}}</title> 
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" /> 
<meta http-equiv="x-ua-compatible" content="chrome=1" /> 
<meta name="description" content="{{$meta_desc}}" /> 
<meta name="keywords" content="{{$meta_keys}}" /> 
<meta name="robots" content="index,follow" /> 
<meta property="og:title" content="{{$title}}" />
<meta property="og:site_name" content="{{$site_name}}" /> 
<meta property="og:image" content="http://www.example.com/images/"{{$thumbnail}} /> 
<meta property="og:type" content="product" /> 
<meta property="og:description" content="{{$meta_desc}}" /> 

</head> 

<body> 
@if($user_name) 

<div class="username">Welcome {{$user_name}} !</div> 

@else 

<div class="username">Welcome Guest !</div> 

@endif 
</body>
```

没有 PHP 语法问题，也没有未闭合的括号问题。因此，我们有一个更清晰的模板文件。由于 Blade 内置的功能，我们可以得到更清晰的视图文件。通常，头部和底部部分在我们应用程序的所有页面中都是通用的。有两种方法可以添加它们。第一种不推荐的方法是将头部、底部和主体部分分别放在三个文件中，类似于下面的示例：

```php
@include('header')
<body> 
@if($user_name) 

<div class="username">Welcome {{Str::upper($user_name)}} !</div> 

@else 

<div class="username">Welcome Guest !</div> 

@endif 
</body>

@include('footer')
```

这种方式不推荐，因为它要求每个页面都包括头部和底部。这也意味着，如果我们添加右侧或左侧栏，我们将需要更改应用程序的所有视图。在 Blade 中实现这一点的最佳方式如下所示：

```php
<!D       OCTYPE html> 
<html lang="en"> 
<head> 
<title>{{$title}}</title> 
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" /> 
<meta http-equiv="x-ua-compatible" content="chrome=1" /> 
<meta name="description" content="{{$meta_desc}}" /> 
<meta name="keywords" content="{{$meta_keys}}" /> 
<meta name="robots" content="index,follow" /> 
<meta property="og:title" content="{{$title}}" /> 
<meta property="og:site_name" content="{{$site_name}}" /> 
<meta property="og:image" content="http://www.example.com/images/"{{$thumbnail}} /> 
<meta property="og:type" content="product" /> 
<meta property="og:description" content="{{$meta_desc}}" /> 

</head> 

<body> 

   @yield('content')

</body>
```

上面的文件是我们的布局视图，例如，`master_layout.blade.php`。正如你所看到的，这里有一个用到`yield()`函数的内容函数。这是一个占位符；因此，当任何视图文件扩展了这个文件，名为`content`的部分将显示在`yield()`函数的位置。你可以在你的主布局中定义尽可能多的部分。所以，当我们想在一个视图文件中使用这个布局时，我们应该像下面的代码一样使用它：

```php
@extends('master_layout')

@section(''content')
<body> 
@if($user_name) 

<div class="username">Welcome {{Str::upper($user_name)}} !</div> 

@else 

<div class="username">Welcome Guest !</div> 

@endif 
</body>

@stop
```

就是这样！你可以在需要的视图中扩展主布局，并根据应用程序的需要创建多个布局。

# 总结

在这一章中，我们学习了 MVC 模式中视图的角色，以及 Laravel 对视图的处理方式。我们了解了 Blade 模板引擎函数的基础知识。更多信息，请参考 Laravel 的在线文档[`laravel.com/`](http://laravel.com/)。

在下一章中，我们将介绍控制器的角色，即 Laravel MVC 哲学中的主角。


# 第四章：MVC 中的控制器

在本章中，我们将讨论控制器是什么，它的结构是什么，它在 MVC 模式中的作用是什么，以及它在 Laravel 的扩展设计模式和结构中的使用。

本章将讨论以下主题：

+   什么是控制器？

+   控制器在 MVC 设计模式中的作用

+   控制器与 MVC 设计模式的其他组件的交互

+   Laravel 如何处理其设计模式中的控制器

# 什么是控制器？

控制器是模型-视图-控制器（MVC）设计模式的一部分，我们可以简单地描述它为应用程序的逻辑层。它理解来自另一端（用户或 API 请求）的请求，调用相应的方法，执行主要检查，处理请求的逻辑，然后将数据返回给相应的视图或将最终用户重定向到另一个路由。

# 控制器的目的

以下是控制器在 MVC 结构中的一些主要角色：

+   控制应用程序的逻辑并定义在操作时应该触发哪个事件

+   作为模型、视图和应用程序的其他组件之间的中间步骤

+   翻译来自视图和模型的动作和响应，使它们可以理解，并将它们发送到其他层

+   在应用程序的其他组件之间建立桥梁，并促进它们之间的通信

+   在执行任何操作之前，在构造方法中进行主要权限检查

这可以通过一个现实世界的例子来最好地解释。

假设我们有一个用户管理网站，在管理面板中，管理员试图删除一个用户。在遵循 SOLID 原则的设计模式中，如果管理员点击删除用户按钮，将发生以下事情：

1.  从视图中，管理员发送请求到相应的控制器以删除新闻项目。

1.  控制器理解这个请求并进行主要检查。首先，它检查请求者（在我们的例子中是管理员）是否真的是管理员，并且有权限删除这个用户。

1.  在进行主要检查后，控制器告诉模型删除用户。

1.  模型进行了一些自己的检查，要么删除了用户并告诉控制器用户已被删除，要么告诉控制器用户不可用（也许用户已经被删除）。

1.  从模型得到响应后，控制器要么告诉视图告诉管理员用户已被删除，要么重定向到另一个页面，比如 404 页面未找到。

从前面的例子中可以看出，对于所有的交互，控制器在应用程序的组件之间起着重要的沟通作用。在遵循 SOLID 原则的 MVC 模式中，没有控制器，视图无法与模型进行交互，反之亦然。虽然有一些对这种架构模式的派生，比如视图直接与模型进行交互，在一个完美的 SOLID 设计架构中，控制器应该始终是所有交互的中间元素。

控制器也可以被视为一个翻译器。它以各种方式从视图中获取输入，并将其转换为模型可以理解的请求，反之亦然。

![控制器的目的](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-dsn-ptn-best-prac/img/Image00008.jpg)

# Laravel 中的控制器

在 Laravel 4 中，控制器是简单的 PHP 类，它们的文件名和类名以后缀`Controller`结尾（不是强制的，但强烈建议；这是开发人员之间的标准），它们扩展了`BaseController`类，并存储在`app/controllers`文件夹中。这个文件夹结构在`composer.json`文件的`classmap`键中定义，不是强制的。由于 Composer，只要你定义了控制器存储在应用程序结构中的位置，你可以把它们放在任何你喜欢的文件夹中。

以下是 Laravel 4 的一个非常简单的控制器：

```php
<?php

class UserController extends BaseController {

    public function showProfile($id)
    {
        $user = User::find($id);

        return View::make('user.profile', array('user' => $user));
    }

}
```

控制器保存了在 `routes.php` 中定义的所有动作方法，其中在 Laravel 4 中设置了所有动作（用户与之交互的每个链接）。

在 Laravel 3 中，开发人员必须使用 `GET` 或 `POST` 作为前缀来理解相应请求的类型。如果您的请求是 `GET` 请求，您的方法名称必须是 `get_profile`，如果请求是 `POST` 请求，它必须类似于 `post_profile`。感谢 Laravel 4，现在不再强制，您可以按自己的喜好命名方法。

现在出现了一个问题。我们如何访问控制器的这个方法？正如我们之前提到的，我们将使用路由来做到这一点。

## 路由

路由是在 `app/routes.php` 中定义的一组规则，告诉 Laravel 在收到传入请求时，根据请求的 URL 调用哪些闭包函数和/或控制器方法。有多种定义路由的方法。其中三种如下所述：

+   您可以使用闭包函数并直接从 `app/routes.php` 设置动作的逻辑。看一下以下代码：

```php
Route::get('hello', function(){
   return 'Ahoy, everyone!';
});
```

在这里，我们调用了 `get()` 方法，因为我们希望此路由成为 `GET` 请求。第一个参数是动作的路径，因此如果我们调用 `http://ourwebsite.com/hello`，将调用此路由动作。第二个参数可以来自各种选择。它可以是一个包含名称、过滤器和动作的数组，一个定义控制器方法的字符串，或者直接包含逻辑的闭包函数。在我们的示例中，我们放置了一个闭包函数并直接向最终用户返回了一个字符串。因此，如果用户导航到 `http://ourwebsite.com/hello`，最终用户将直接看到消息**Ahoy, everyone!**。

+   设置路由的第二种方法是将第二个参数作为字符串传递，定义它传递到哪个控制器，并调用哪个动作。看一下以下代码：

```php
Route::get('hello', 'ProfileController@hello'); 
```

在这里，字符串 `ProfileController@hello` 告诉 Laravel 方法 `hello` 将从名为 `ProfileController` 的控制器中调用。我们使用字符 `@` 将它们分开。

+   第三种方法是将数组作为第二个参数，其中包含各种键和值。看一下以下代码：

```php
Route::get('hello', array(
   'before'   => 'member',
   'as'       => 'our_hello_page'
   'uses'     => 'ProfileController@hello'
));
```

数组可以有多个参数，定义路由的名称、在调用动作之前将应用的过滤器，以及将使用哪个控制器及其方法。以下是三个不同的键：

+   `before` 键定义了在调用动作之前的过滤器，因此您可以在调用每个动作之前设置一些过滤参数。例如，如果您有一个仅限会员的区域，您不希望访客访问该资源，您可以使用路由中的 `before` 参数传递过滤器。

+   `as` 键定义了路由的名称。这非常有益。假设您需要更改应用程序的 URL 结构。传统上，如果更改路由的动作路径，您需要更改应用程序中此动作的每个 URL 或重定向。相反，如果使用名称设置链接和重定向，您只需要更改一次路径，所有链接和重定向都会神奇地修复。

+   `uses` 键的结构与我们的第二个示例完全相同。它保存了调用时控制器的名称和方法。

在所有这些示例中，路由没有获取任何参数，我们也没有传递任何参数。想象一下：我们通过路由访问了配置文件区域，但在这些示例中，我们没有设置访问特定用户的方式。我们如何为这些路由设置参数？为此，我们必须在花括号中设置参数。

运行以下代码以为路由设置参数：

```php
Route::get('users/{id}', function($id){
   return 'Hello, the user with ID of '.$id;
});
```

花括号中的参数会直接成为闭包方法中的变量名。这种方法还为我们提供了一种在控制器方法运行之前过滤这些参数的方式。使用`where()`，您可以过滤这些参数。看一下以下代码：

```php
Route::get('users/{id}', function($id){
        return 'Hello, the user with ID of '.$id;
})->where(array('id' => '[0-9]+'));
```

`where()`方法可以是一个带有键和值的数组，也可以是两个参数，其中第一个是花括号中的名称，第二个是用于过滤参数的正则表达式。

在我们的示例中，我们使用正则表达式过滤参数 ID，以匹配仅数字，因此，这样，我们将区分不同类型的数据以重载端点。

此方法还有另一个好处。如果有人尝试导航到`http://ourwebsite.com/users/xssSqlInjection`，Laravel 甚至在转到控制器方法之前就会抛出 404 错误。

如果我们遵循这种结构，我们需要为每个`GET`，`POST`，`PUT`和`DELETE`请求设置每个操作。如果您想为您的操作使用 RESTful 结构，而不是逐个设置每个路由，您可以使用`Route`类的`controller()`方法。

需要遵循一定的步骤来设置 RESTful 控制器的路由。对于用户控制器，以下是步骤：

1.  首先，您需要创建一个名为`UserController`的新控制器，并设置您的 RESTful 方法，如`index()`，`create()`，`store()`，`show($id)`，`edit($id)`，`update($id)`和`destroy($id)`。

1.  然后，您需要在`app/routes.php`中设置 RESTful 控制器，方法是运行以下命令：

```php
Route::controller('users', 'UserController');
```

Laravel 提供了一种更快的方法来创建资源控制器。这些被 Laravel 称为资源控制器。遵循以下步骤来设置资源控制器的路由：

1.  首先，您需要使用 Laravel 的 PHP 客户端`artisan`创建一个具有资源方法的新控制器。看一下以下代码：

```php
php artisan controller:make NewsController
```

使用此命令，将在`app/controllers`文件夹中自动生成一个名为`NewsController.php`的新文件，并在其中已经定义了所有资源方法。

1.  然后，您需要通过运行以下命令在`app/routes.php`中设置资源控制器：

```php
Route::resource('news', 'NewsController');
```

在设置资源控制器时，您可以通过将第三个参数设置为此`Route`定义来设置要包含或排除的操作。

1.  要包含将在资源控制器中定义的操作（类似于白名单），您可以使用`only`键，如下所示：

```php
Route::resource(
   'news', 
   'NewsController',
   array('only' => array('index', 'show'))
);
```

1.  要排除将在资源控制器中定义的操作（类似于黑名单），您可以使用`except`键，如下所示：

```php
Route::resource(
   'news', 
   'NewsController',
   array('except' => array('create', 'store', 'update', 'destroy'))
);
```

1.  所有资源控制器操作都有定义的路由名称。在某些情况下，您可能还想覆盖操作名称，可以通过设置第三个参数`names`来实现，如下所示：

```php
Route::resource(
   'news', 
   'NewsController',
   array('names' => array('create' => 'news.myCoolCreateAction')
);
```

如果您已经阅读了上一章，您可能还记得我们在路由中有过滤器，但我们没有在 RESTful 和资源控制器中使用`before`键。要使用`before`键，我们可以执行之前遵循的步骤或在控制器中设置过滤器。这些可以在控制器的`__construct()`方法中设置（如果没有，则创建一个），如下所示：

```php
class NewsController extends BaseController {

    public function __construct()
    {

        $this->beforeFilter('csrf', array('on' => 'post'));

        $this->beforeFilter(function(){
           //my custom filter codes in closure function
        });

        $this->afterFilter('log', 
           array('only' => array('fooAction', 'barAction'))
        );
    }

}
```

正如您所看到的，我们使用`beforeFilter()`和`afterFilter()`方法设置了过滤器。这些方法可以接受闭包函数或过滤器名称作为第一个参数，以及一个可选的第二个参数，作为数组，用于定义这些过滤器的工作位置。

在这个例子中，我们首先为所有`POST`操作设置了 CSRF（跨站点请求伪造，这是一种通过伪造请求来注入恶意代码到应用程序中的方法）保护过滤器；之后，我们在闭包函数中定义了一个过滤器，并使用`afterFilter`方法记录了所有`fooAction`和`barAction`事件的状态。

以下表格是 Laravel 的资源控制器处理的操作列表：

| 动词 | 路径 | 操作 | 路由名称 |
| --- | --- | --- | --- |
| `GET` | `/resource` | Index | `resource.index` |
| `GET` | `/resource/create` | Create | `resource.create` |
| `POST` | `/resource` | Store | `resource.store` |
| `GET` | `/resource/{resource}` | Show | `resource.show` |
| `GET` | `/resource/{resource}/edit` | Edit | `resource.edit` |
| `PUT` /`PATCH` | `/resource/{resource}` | Update | `resource.update` |
| `DELETE` | `/resource/{resource}` | Destroy | `resource.destroy` |

# 在文件夹中使用控制器

在某些情况下，您可能希望将控制器分组到一个文件夹中，并以更具层次结构的方式进行组织。有两种方法可以实现这一点。

在解释这些方法之前，让我们假设我们在`app/controllers/admin`文件夹中有一个`UserController.php`文件，我们刚刚为管理相关的控制器文件创建了这个文件夹。这里出现了一个问题：我们如何让 Laravel 和控制器文件知道控制器在哪里？命名空间用于这样的需求。命名空间是封装和分组项目的简单方式。

假设你有`app/controllers/UserController.php`和`app/controllers/admin/UserController.php`文件。我们如何调用特定的文件？命名空间在这里很方便。将以下文件保存为`app/controllers/admin/UserController.php`：

```php
<?php namespace admin; //The definition of namespace

use View; //What will be used

Class UserController Extends \BaseController {

   public function index() {
      return View::make('hello');
   }

}
```

现在我们按照以下方式定义路由：

```php
Route::get('my/admin/users/index', 'Admin\UserController@index');
```

在这里，我们为这个控制器添加了一些新的内容。它们如下：

+   第一种是`namespace admin;`。这简单地定义了这个文件在一个名为`admin`的文件夹中。

+   第二个是`use View;`。如果我们的控制器在一个文件夹或一个定义的`namespace`下，除非我们导入它们，否则我们调用的所有类都将像`namespace\class`一样。如果我们没有添加这一行，`View::make()`函数将会抛出一个错误，说`Class admin\View not found`。为了更好地理解这一点，你可以把它想象成 HTML 的资源调用。假设你正在浏览`admin/users.html`，里面有一张图片，其路径定义为这种格式：`<img src= "assets/img/avatar.png" />`。正如你可以想象的那样，图片将被请求从`admin/assets/img/avatar.png`，因为它在一个名为`assets`的文件夹中。这正是同样的情况。

+   当我们从`BaseController`类继承时，我们添加了一个`\`（反斜杠）字符。这将表示它将从根目录调用。如果我们没有在我们的类中添加`use View;`并且想要使`View::make()`工作，我们应该将它修改为`\View::make()`（带有一个前导反斜杠），这样正确的类将被请求。

如果有一个全新的文件夹结构，可以通过两种方式来定义。要么将每个文件夹路径添加到`composer.json`文件中的`autoload/classmap`对象中，要么定义一个`psr-0`自动加载。假设我们有一个新的`app/myApp`文件夹，里面有一个位于`app/myApp/controllers/admin/UserController.php`的控制器。

向控制器添加一个`classmap`对象，如下所示：

```php
"autoload": {
      "classmap": [
         "app/commands",
         "app/controllers",
          "app/models",
          "app/database/migrations",
          "app/database/seeds",
          "app/tests/TestCase.php",

          "app/myApp/controllers/admin",
      ]
}
```

现在按照以下方式向代码添加`psr-0`自动加载：

```php
"autoload": {
      "classmap": [
         "app/commands",
         "app/controllers",
         "app/models",
         "app/database/migrations",
         "app/database/seeds",
         "app/tests/TestCase.php",

      ],

       "psr-0": {
         "myApp", "app/"
      }

}
```

然后从终端运行`composer dump-autoload`来重新生成自动加载类。通过这种`psr-0`自动加载，我们教会了我们的 Composer 项目递归地自动加载`app`文件夹中的`myApp`文件夹内的所有内容。另一种方法是在类名前缀中添加命名空间文件夹，并在每个文件夹之间使用`underscores (_)`。

假设我们有一个控制器，`app/controllers/foo/bar/BazController.php`。将以下内容保存在这个文件夹中：

```php
<?php

Class foo_bar_BazController extends BaseController {

   public function index() {
      return View::make('hello');
   }

}
```

现在我们按照以下方式定义路由：

```php
Route::get('foobarbaz', ' foo_bar_BazController@index');
```

然后，我们导航到`http://yourwebsite/foobarbaz`。即使没有使用命名空间或包含`use`来包含类，它也会自动工作。

# 总结

在这一章中，我们学习了 MVC 模式中控制器的角色，以及如何在 Laravel 4 中使用控制器和设置路由。我们还学习了过滤器、RESTful 和 Resourceful 控制器。

更多信息，请参考位于[`laravel.com/docs/controllers`](http://laravel.com/docs/controllers)的官方文档页面。在下一章中，我们将学习关于 Laravel 独特的设计模式，以及它如何使用 Repositories、Facades 和工厂模式。


# 第五章：Laravel 中的设计模式

在本章中，我们将讨论 Laravel 使用的设计模式，以及它们的使用方式和原因，以示例说明。

本章将讨论以下主题：

+   Laravel 中使用的设计模式

+   Laravel 中使用这些模式的原因

# 建造者（管理者）模式

这种设计模式旨在获得更简单、可重用的对象。其目标是将更大、更复杂的对象构建层与其余部分分离，以便分离的层可以在应用程序的不同层中使用。

## 建造者（管理者）模式的需求

在 Laravel 中，`AuthManager`类需要创建一些安全元素，以便与选定的身份验证存储驱动程序（如 cookie、会话或自定义元素）重用。为了实现这一点，`AuthManager`类需要使用`Manager`类的存储函数，如`callCustomCreator()`和`getDrivers()`。

让我们看看建造者（管理者）模式在 Laravel 中的使用。要查看此模式中发生了什么，请导航到`vendor/Illuminate/Support/Manager.php`和`vendor/Illuminate/Auth/AuthManager.php`文件，如下面的代码所示：

```php
   public function driver($driver = null)
   {
      ...

   }

   protected function createDriver($driver)
   {
      $method = 'create'.ucfirst($driver).'Driver';

      ...
   }

   protected function callCustomCreator($driver)
   {
      return $this->customCreators$driver;
   }

   public function extend($driver, Closure $callback)
   {
      $this->customCreators[$driver] = $callback;

      return $this;
   }
   public function getDrivers()
   {
      return $this->drivers;
   }

   public function __call($method, $parameters)
   {
      return call_user_func_array(array($this->driver(), $method), $parameters);
   }
```

现在，导航到`/vendor/Illuminate/Auth/AuthManager.php`文件，如下面的代码所示：

```php
   protected function createDriver($driver)
   {

      ....
   }

   protected function callCustomCreator($driver)
   {

   }

   public function createDatabaseDriver()
   {

   }

   protected function createDatabaseProvider()
   {

      ....
   }

   public function createEloquentDriver()
   {
      ...

   }

   protected function createEloquentProvider()
   {
      ...

   }

   public function getDefaultDriver()
   {
      ...
   }

   public function setDefaultDriver($name)
   {
      ...
   }
```

正如我们在前面的代码中所看到的，`AuthManager`类是从`Manager`类继承而来的。Laravel 自带基本的身份验证机制。因此，我们需要将身份验证凭据存储在数据库中。首先，该类使用`AuthManager::setDefaultDriver()`函数检查我们的默认数据库配置。这个函数实际上使用`Manager`类进行 eloquent 操作。除了身份验证模型表名，所有数据库和身份验证选项（如 cookie 名称）都是从应用程序的配置文件中获取的。

为了更好地理解这种建造者（管理者）模式，我们可以以以下演示为例：

![建造者（管理者）模式的需求](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-dsn-ptn-best-prac/img/Image00009.jpg)

在前面的示例图中，我们假设我们想要从前面的示例中获取比萨等数据。客户点了两份比萨：一份亚洲比萨和/或一份中国比萨。这个比萨是通过`Waiter`类请求的。`PizzaBuilder`类（在我们的例子中是`Manager`类）根据`AuthRequest`请求制作了一份比萨，并通过服务员将比萨送到了客户那里。

此外，您可以导航到`vendor/Illuminate/Session/SessionManage.php`，查看在 Laravel 框架中使用此模式。

# 读累了记得休息一会哦~

**公众号：古德猫宁李**

+   电子书搜索下载

+   书单分享

+   书友学习交流

**网站：**[沉金书屋 https://www.chenjin5.com](https://www.chenjin5.com)

+   电子书搜索下载

+   电子书打包资源分享

+   学习资源分享

# 工厂模式

在这一小节中，我们将研究工厂模式及其在 Laravel 框架中的使用。工厂模式是基于创建模板方法对象的，这是基于在子类中定义类的算法来实现算法。在这种模式结构中，有一个从大的超类派生出来的子类。主类，我们可以称之为超类，只包含主要和通用的逻辑；子类是从这个超类派生出来的。因此，可能会有多个子类从这个超类中继承，这些子类旨在不同的目的。

与 Laravel 中使用的其他设计模式不同，`Factory`方法更具可定制性。对于扩展的子类加上主类，您不需要设置一个新的类，只需要一个新的操作。如果类或其组件通常发生变化，或者需要重写方法，就像初始化一样，这种方法是有益的。

在创建设计时，开发人员通常从在其应用程序中使用工厂模式开始。这种模式会转变为抽象工厂、建造者或原型模式。与工厂模式不同，原型模式需要初始化一次。由于模式的架构，工厂模式的方法（工厂方法）通常在模板方法内部调用。

工厂模式与抽象工厂或原型模式之间存在一些差异。它们如下：

+   与抽象工厂模式不同，工厂模式不能使用原型模式实现。

+   与原型模式不同，工厂模式不需要初始化，但需要子类化。与其他模式相比，这是一个优势。由于这种方法，工厂模式可以返回一个注入的子类而不是一个对象。

+   由于使用工厂模式设计的类可能直接返回子类给其他组件，因此不需要其他类或组件知道和访问构造方法。因此，建议所有构造方法和变量都应该是受保护的或私有的。

+   还有一件事需要考虑。由于这种模式可能返回针对确切需求的子类，因此不建议使用关键字 new 使用此模式的类创建新实例。

## 工厂模式的需求

Laravel 使用`Validation`类提供各种类型的验证规则。当我们开发应用程序时，通常需要在进行过程中验证数据。为了做到这一点，一个常见的方法是在模型中设置验证规则，并从控制器中调用它们。这里所说的“规则”既指验证类型又指其范围。

有时，我们需要设置自定义规则和自定义错误消息来验证数据。让我们看看它是如何工作的，以及我们如何能够扩展`Validation`类来创建自定义规则。MVC 模式中的控制器也可以被描述为模型和视图之间的桥梁。这可以通过一个现实世界的例子来最好地解释。

假设我们有一个新闻聚合网站。在管理面板中，管理员试图删除新闻项目。在 SOLID 设计模式中，如果管理员点击**删除新闻**按钮，就会发生这种情况。

首先，作为一个检查的例子，让我们打开`vendor/Illuminate/Validation/Factory.php`文件，如下所示：

```php
<?php namespace Illuminate\Validation;

use Closure;
use Illuminate\Container\Container;
use Symfony\Component\Translation\TranslatorInterface;

class Factory {

   protected $translator;

   protected $verifier;

   protected $container;

   protected $extensions = array();

   protected $implicitExtensions = array();

   protected $replacers = array();

   protected $fallbackMessages = array();

   protected $resolver;

   public function __construct(TranslatorInterface $translator, Container $container = null)
   {
      $this->container = $container;
      $this->translator = $translator;
   }

   public function make(array $data, array $rules, array $messages = array(), array $customAttributes = array())
   {

      $validator = $this->resolve($data, $rules, $messages, $customAttributes);

      if ( ! is_null($this->verifier))
      {
         $validator->setPresenceVerifier($this->verifier);
      }

      if ( ! is_null($this->container))
      {
         $validator->setContainer($this->container);
      }

      $this->addExtensions($validator);

      return $validator;
   }

      protected function addExtensions(Validator $validator)
   {
      $validator->addExtensions($this->extensions);

      $implicit = $this->implicitExtensions;

      $validator->addImplicitExtensions($implicit);

      $validator->addReplacers($this->replacers);

      $validator->setFallbackMessages($this->fallbackMessages);
   }

   protected function resolve(array $data, array $rules, array $messages, array $customAttributes)
   {
      if (is_null($this->resolver))
      {
         return new Validator($this->translator, $data, $rules, $messages, $customAttributes);
      }
      else
      {
         return call_user_func($this->resolver, $this->translator, $data, $rules, $messages, $customAttributes);
      }
   }

      public function extend($rule, $extension, $message = null)
   {
      $this->extensions[$rule] = $extension;

      if ($message) $this->fallbackMessages[snake_case($rule)] =  $message;
   }

   public function extendImplicit($rule, $extension, $message =  null)
   {
      $this->implicitExtensions[$rule] = $extension;

      if ($message) $this->fallbackMessages[snake_case($rule)] =  $message;
   }

   public function replacer($rule, $replacer)
   {
      $this->replacers[$rule] = $replacer;
   }

   public function resolver(Closure $resolver)
   {
      $this->resolver = $resolver;
   }

   public function getTranslator()
   {
      return $this->translator;
   }

   public function getPresenceVerifier()
   {
      return $this->verifier;
   }

   public function setPresenceVerifier(PresenceVerifierInterface $presenceVerifier
   {
      $this->verifier = $presenceVerifier;
   }

}
```

正如我们在前面的代码中所看到的，`Validation Factory`类是使用`Translator`类和一个 IoC 容器构建的。在此之后设置了`addExtensions()`函数。这个方法包括用户定义的扩展到`Validator`实例，从而允许我们编写创建`Validator`类的扩展的模板（结构）。这些公共函数允许我们实现`Translator`类，也就是说它们允许我们编写自定义验证规则和消息。参考以下**CarFactory**图表：

![工厂模式的需求](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-dsn-ptn-best-prac/img/Image00010.jpg)

在上图中，你可以看到所有的汽车都是基于**CarFactory**（所有汽车的基础）的，无论品牌如何。对于所有品牌，主要过程是相同的（所有汽车都有发动机、轮胎、刹车、灯泡、齿轮等等）。你可能想要一辆**Suzuki**汽车或一辆**Toyota**汽车，根据这个选择，**SuzukiFactory**或**ToyotaFactory**从**CarFactory**创建一个**Suzuki**汽车或**Toyota**汽车。

# 存储库模式

存储库模式通常用于在应用程序的两个不同层之间创建接口。在我们的情况下，Laravel 的开发人员使用这种模式来在`NamespaceItemResolver`（解析命名空间并了解哪个文件在哪个命名空间中）和`Loader`（需要并将另一个类加载到应用程序中的类）之间创建一个抽象层。`Loader`类简单地加载给定命名空间的配置组。正如你可能知道的，几乎所有的 Laravel 框架代码都是使用命名空间开发的。

## 存储库模式的需求

假设您正在尝试使用 Eloquent ORM 从数据库中获取产品。在您的控制器中，该方法将是`Product::find(1)`。出于抽象目的，这种方法并不理想。如果您现在放置这样的代码，您的控制器知道您正在使用 Eloquent，这在一个良好和抽象的结构中理想情况下不应该发生。如果您想要包含对数据库方案所做的更改，以便类外的调用不直接引用字段而是通过存储库，您必须逐个查找所有代码。

现在，让我们为用户创建一个`imaginart`存储库接口（将在模式中使用的方法列表）。让我们称之为`UserRepository.php`。

```php
<?php namespace Arda\Storage\User;

interface UserRepository {

   public function all();

   public function get();

   public function create($input);

   public function update($input);

   public function delete($input);

   public function find($id);

}
```

在这里，您可以看到模型中使用的所有方法名称都是逐个声明的。现在，让我们创建存储库并将其命名为`EloquentUserRepository.php`：

```php
<?php namespace Arda\Storage\User;

use User;

class EloquentUserRepository implements UserRepository {

  public function all()
  {
    return User::all();
  }

  public function get()
  {
    return User::get();
  }

  public function create($input)
  {
    return User::create($input);
  }

  public function update($input)
  {
    return User::update($input);
  }

  public function delete($input)
  {
    return User::delete($input);
  }

  public function find($input)
  {
    return User::find($input);
  }

}
```

正如您所看到的，这个存储库类实现了我们之前创建的`UserRepository`。现在，您需要绑定这两个，这样当调用`UserRepositoryInterface`接口时，我们实际上获得了`EloquentUserRepository`。

这可以通过服务提供商或 Laravel 中的简单命令来完成，例如：

```php
App:bind(
   'Arda\Storage\User\UserRepository',
   'Arda\Storage\User\EloquentUserRepository'
);
```

现在，在您的控制器中，您可以简单地使用存储库作为`Use Arda\Storage\User\UserRepository as User`。

每当控制器使用`User::find($id)`代码时，它首先进入接口，然后进入绑定的存储库，这在我们的情况下是 Eloquent 存储库。通过这种方式，它进入 Eloquent ORM。这样，控制器就不可能知道数据是如何获取的。

# 策略模式

描述策略模式的最佳方法是通过一个问题。

## 策略模式的需求

在这种设计模式中，逻辑从复杂的类中提取到更简单的组件中，以便它们可以轻松地用更简单的方法替换。例如，您想在您的网站上显示热门博客文章。在传统方法中，您将计算受欢迎程度，进行分页，并列出与当前分页偏移和受欢迎程度相关的项目，并在一个简单的类中进行所有计算。这种模式旨在将每个算法分离成单独的组件，以便它们可以轻松地在应用程序的其他部分中重用或组合。这种方法还带来了灵活性，并使全局系统中更改算法变得容易。

为了更好地理解这一点，让我们来看一下位于`vendor/Illuminate/Config/LoaderInterface`的以下加载器接口：

```php
<?php namespace Illuminate\Config;

interface LoaderInterface {

   public function load($environment, $group, $namespace = null);

   public function exists($group, $namespace = null);

    public function addNamespace($namespace, $hint);

   public function getNamespaces();

   public function cascadePackage($environment, $package, $group, $items);

}
```

当我们查看代码时，`LoaderInterface`的工作将遵循一定的结构。`getNamespaces()`函数加载`app\config\app.php`文件中定义的所有命名空间。`addNamespace()`方法将命名空间作为分组传递给`load()`函数。如果`exist()`函数返回`true`，则至少有一个配置组属于给定命名空间。有关完整结构，您可以参考本章的存储库部分。因此，您可以通过`Loader`类的接口轻松调用您需要的方法，以加载各种配置选项。如果我们通过 composer 下载一个包，或者将一个包实现到正在编写的应用程序中，该模式使所有这些包都可用，并且可以从它们自己的命名空间中加载，而不会发生冲突，尽管它们位于不同的命名空间或具有相同的文件名。

# 提供程序模式

提供程序模式是由微软为在 ASP.NET Starter Kits 中使用而制定的，并在.NET 版本 2.0 中正式化（[`en.wikipedia.org/wiki/Provider_model`](http://en.wikipedia.org/wiki/Provider_model)）。它是 API 类和应用程序的业务逻辑/数据抽象层之间的中间层。提供程序是 API 的实现与 API 本身分离开来的。

这种模式及其目标和用法与策略模式非常相似。这就是为什么许多开发人员已经在讨论是否接受这种方法作为一种设计模式。

为了更好地理解这些模式，让我们打开`vendor/Illuminate/Auth/AuthServiceProvider.php`和`vendor/Illuminate/Hashing/HashServiceProvider.php`：

```php
<?php namespace Illuminate\Auth;

use Illuminate\Support\ServiceProvider;

class AuthServiceProvider extends ServiceProvider {

   protected $defer = true;

   public function register()
   {
      $this->app->bindShared('auth', function($app)
      {
           // Once the authentication service has actually been requested by the developer
          // we will set a variable in the application indicating this, which helps us
          // to know that we need to set any queued cookies in the after event later.
         $app['auth.loaded'] = true;

          return new AuthManager($app);
      });
   }

   public function provides()
   {
      return array('auth');
   }

}

<?php namespace Illuminate\Hashing;

use Illuminate\Support\ServiceProvider;

class HashServiceProvider extends ServiceProvider {

   protected $defer = true;

   public function register()
   {
      $this->app->bindShared('hash', function() { return new BcryptHasher; });
   }

   public function provides()
   {
      return array('hash');
   }

}
```

正如您所看到的，这两个类都扩展了`ServiceProvider`。`AuthServiceProvider`类允许我们在进行身份验证请求时向`AuthManager`提供所有服务，比如检查是否创建了 cookie 和会话，或者内容是否无效。在请求身份验证服务之后，开发人员可以通过`AuthDriver`来定义是否通过响应设置会话或 cookie。

然而，`HashServiceProvider`在进行安全哈希请求时为我们提供了相关的方法，这样我们就可以使用、获取、检查或对这些哈希进行其他操作。这两个提供者都将值作为数组返回。

# 外观模式

外观（façade）模式允许开发人员将各种复杂的接口统一到一个单一的类接口中。这种模式还允许您将来自各种类的各种方法包装成一个单一的结构。

![外观模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-dsn-ptn-best-prac/img/Image00011.jpg)

在 Laravel 4 中，你可能已经知道，几乎每个方法都看起来像一个静态方法，例如，`Input::has()`，`Config::get()`，`URL::route()`，`View::make()`和`HTML::style()`。然而，它们并不是静态方法。如果它们是静态方法，那么对它们进行测试将会非常困难。它们实际上是这种行为的模拟。在后台，借助于 IoC 容器（一种将依赖项注入到类中的方法），Laravel 实际上通过`Facade`类调用另一个类（们）。Facade 基类受益于 PHP 自己的`__callStatic()`魔术方法来调用所需的方法，比如静态方法。

例如，假设我们有一个名为`URL::to('home')`的方法。让我们检查一下 URL 是什么，它指的是什么。首先，让我们打开`app/config/app.php`。在别名数组中，有一行如下：

```php
'URL' => 'Illuminate\Support\Facades\URL',
```

因此，如果我们调用`URL::to('home')`，我们实际上调用的是`Illuminate\Support\Facades\URL::to('home')`。

现在，让我们来看看文件里面有什么。打开`vendor/Illuminate/Support/Facades/URL.php`文件：

```php
<?php namespace Illuminate\Support\Facades;

class URL extends Facade {

   protected static function getFacadeAccessor() { return 'url'; }

}
```

正如您所看到的，该类实际上是从`Facade`类继承而来的，并且没有名为`to()`的静态方法。相反，有一个名为`getFacadeAccessor()`的方法，它返回字符串`url`。`getFacadeAccessor()`方法的目的是定义要注入什么。这样，Laravel 就明白了这个类正在寻找`$app['url']`。

这是在`vendor/Illuminate/Routing/RoutingServiceProvider.php`中定义的，如下所示：

```php
protected function registerUrlGenerator()
{
   $this->app['url'] = $this->app->share(function($app)
      {

      $routes = $app['router']->getRoutes();

      return new UrlGenerator($routes, $app->rebinding('request', function($app, $request)
      {
         $app['url']->setRequest($request);
      }));
   });
}
```

正如您所看到的，它返回了同一命名空间中`UrlGenerator`类的一个新实例，其中包含我们正在寻找的`to()`方法：

```php
//Illuminate/Routing/UrlGenerator.php
public function to($path, $extra = array(), $secure = null)
{
   //...
}
```

因此，每次你使用这样的方法时，Laravel 首先去检查 facade，然后检查通过注入的内容，然后通过`injected`类调用真正的方法。

# 总结

在本章中，我们了解了 Laravel PHP 框架中各种设计模式的用法，以及它们为什么被使用，它们可以解决什么问题。

在下一章中，我们将学习使用设计模式在 Laravel 项目中的最佳实践来创建应用程序。
