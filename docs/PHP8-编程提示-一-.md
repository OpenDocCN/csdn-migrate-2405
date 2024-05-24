# PHP8 编程提示（一）

> 原文：[`zh.annas-archive.org/md5/7838a031e7678d26b84966d54ffa29dd`](https://zh.annas-archive.org/md5/7838a031e7678d26b84966d54ffa29dd)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

PHP 8 代表了 PHP 核心开发团队为最大化提高核心语言效率所做的工作的巅峰。只要迁移到 PHP 8，您的应用程序代码将立即看到速度提升，同时内存占用也会更小。此外，在 PHP 8 中，开发人员会注意到大量的工作已经投入到规范语法和语言使用上。简而言之，在 PHP 8 中编程对于那些重视良好编码实践的开发人员来说是一种乐趣。

然而，这不可避免地引出了一个问题：PHP 语言未来的发展方向是什么？PHP 8 也提供了这个问题的答案，即即时编译器和对 fibers 的支持。后者构成了异步编程的基础，并已宣布将在 PHP 8.1 中推出。PHP 8 让您一窥语言的未来，而这个未来看起来非常光明！

综合起来，可以清楚地看出，理解和掌握 PHP 8 中实施的新功能和更严格的编码实践对于那些希望追求 PHP 开发人员职业生涯的人来说是至关重要的。这本书正是您快速上手并运用 PHP 8 所需的工具。我们不仅介绍了新功能，还向您展示了如何避免在 PHP 8 迁移后可能导致代码失败的陷阱。此外，我们通过全面介绍 JIT 编译器和 PHP 异步编程，让您一窥 PHP 的未来。

# 这本书是为谁准备的

这本书适用于所有经验水平的 PHP 开发人员，他们具有 PHP 5 或更高版本的经验。如果您刚开始学习 PHP，您会发现代码示例对于更有效地学习使用该语言非常有用。在一个或多个 PHP 项目上工作了几个月的开发人员将能够将这些技巧和技术应用到手头的代码中，而那些具有多年 PHP 经验的开发人员肯定会欣赏对 PHP 8 新功能的简明介绍。

# 这本书涵盖了什么

[*第一章*]，*介绍新的 PHP 8 面向对象编程特性*，向您介绍了针对面向对象编程（OOP）的新 PHP 8 特性。本章包含大量简短的代码示例，清晰地说明了新特性和概念。这一章对于帮助您快速利用 PHP 8 的强大功能并将代码示例适应到您自己的实践中至关重要。

[*第二章*]，*了解 PHP 8 的功能增强*，涵盖了 PHP 8 在过程级别引入的重要增强和改进。它包括大量的代码示例，展示了新的 PHP 8 特性和技术，以便促进过程式编程。本章教会您如何编写更快、更干净的应用程序代码。

[*第三章*]，*利用错误处理增强功能*，探讨了 PHP 8 中的一个关键改进，即其先进的错误处理能力。在本章中，您将了解哪些通知已升级为警告，以及哪些警告现在已经升级为错误。本章将帮助您更好地了解安全增强的背景和意图，从而更好地控制代码的使用。此外，了解以前只生成警告但现在生成错误的错误条件是至关重要的，这样您就可以采取措施防止在升级到 PHP 8 后应用程序失败。

第四章《进行直接的 C 语言调用》帮助您了解外部函数接口（FFI）的全部内容，它的作用以及如何使用它。本章的信息对于对使用直接 C 语言调用进行快速自定义原型设计感兴趣的开发人员非常重要。本章向您展示如何直接将 C 语言结构和函数合并到您的代码中，打开了一个迄今为止对 PHP 不可用的整个功能世界的大门。

第五章《发现潜在的面向对象编程向后兼容性破坏》向您介绍了针对面向对象编程的新 PHP 8 功能。本章包含大量清晰说明新功能和概念的简短代码示例。本章对于帮助您快速利用 PHP 8 的强大功能，并将代码示例调整到您自己的实践中非常关键。此外，本章还强调了在 PHP 8 迁移后可能导致面向对象代码中断的情况。

第六章《理解 PHP 8 的功能差异》涵盖了在 PHP 8 命令或功能级别可能出现的向后不兼容性破坏。本章提供了重要信息，突出了将现有代码迁移到 PHP 8 时可能出现的潜在陷阱。本章中提供的信息使您能够编写可靠的 PHP 代码。通过学习本章中的概念，您将更有能力编写能够产生精确结果并避免不一致性的代码。

第七章《在使用 PHP 8 扩展时避免陷阱》带您了解了对扩展所做的主要更改以及在将现有应用程序更新到 PHP 8 时如何避免陷阱。一旦您完成了对示例代码和主题的审阅，您将能够为将任何现有的 PHP 代码准备好迁移到 PHP 8。除了学习各种扩展的变化之外，您还将深入了解它们的运作方式。这将使您能够在 PHP 8 中使用扩展时做出明智的决策。

第八章《了解 PHP 8 中已弃用或移除的功能》带您了解了在 PHP 8 中已经弃用或移除的功能。在阅读了本章的材料并跟随示例应用代码之后，您将能够检测和重写已经弃用的代码。您还将学习如何为已经移除的功能开发解决方案，以及如何重构使用已移除功能的涉及扩展的代码。本章中您还将学习如何通过重写依赖于在 PHP 8 中已完全移除的功能的代码来提高应用程序的安全性。

第九章《掌握 PHP 8 最佳实践》介绍了在 PHP 8 中现在强制执行的最佳实践。它涵盖了许多重要的方法签名更改以及它们的新用法如何延续了 PHP 的一般趋势，帮助您编写更好的代码。您还将了解到关于私有方法、接口、特征和匿名类的使用变化，以及现在如何解析命名空间。掌握本章涵盖的最佳实践不仅会使您更接近编写更好的代码，还将帮助您避免可能出现的代码中断，如果您没有掌握这些新实践的话。

*第十章*，*性能改进*，向您介绍了一些对性能有积极影响的新 PHP 8 功能，特别关注新的即时编译器。本章还包括对弱引用的全面介绍，正确使用弱引用可以大大减少应用程序的内存使用。通过仔细审阅本章涵盖的内容并学习代码示例，您将能够编写更快速和更高效的代码。

*第十一章*，*将现有 PHP 应用迁移到 PHP 8*，介绍了一组类，这些类构成了 PHP 8 向后兼容断点扫描器的基础。在整本书中，您将看到可能在 PHP 8 更新后出现的潜在代码断点。此外，您将了解将现有客户 PHP 应用程序迁移到 PHP 8 的推荐流程。本章将使您更好地准备处理 PHP 8 迁移，让您能够更有信心地执行 PHP 8 迁移，并最大程度地减少问题。

*第十二章*，*使用异步编程创建 PHP 8 应用程序*，解释了传统同步和异步编程模型之间的区别。近年来，一种令人兴奋的新技术席卷了 PHP 社区：异步编程，也称为 PHP async。此外，还涵盖了流行的 PHP 异步扩展和框架，包括 Swoole 扩展和 ReactPHP，并提供了大量示例供您开始使用。通过完成本章的学习，您将能够提高应用程序的性能，使其速度提高 5 倍甚至惊人的 40 倍！

# 要充分利用本书

要充分利用本书，您必须对 PHP 语法、变量、控制结构（例如，`if {} else {}`）、循环结构（例如，`for () {}`）、数组和函数有基本了解。您还必须对 PHP 面向对象编程有基本了解：类、继承和命名空间。

如果您没有接受过正式的 PHP 培训，或者不确定自己是否具备必要的知识，请查阅在线 PHP 参考手册的以下两个部分：

+   PHP 语言参考：

[`www.php.net/manual/en/langref.php`](https://www.php.net/manual/en/langref.php)

+   PHP 面向对象编程：

[`www.php.net/manual/en/language.oop5.php`](https://www.php.net/manual/en/language.oop5.php)

以下是本书涵盖的软件摘要：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/B16992_Preface_Table1.jpg)

注意

如果您使用的是本书的数字版本，我们建议您自己输入代码，或者从书的 GitHub 存储库中访问代码（下一节中提供了链接）。这样做将帮助您避免与复制和粘贴代码相关的潜在错误。

# 下载示例代码文件

您可以从 GitHub 上下载本书的示例代码文件：[`github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices`](https://github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices)。如果代码有更新，将在 GitHub 存储库中更新。

我们还有来自丰富图书和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图和图表的彩色图像。您可以在这里下载：[`static.packt-cdn.com/downloads/9781801071871_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781801071871_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。这是一个例子：“本章还教会了您如何将新的`Attribute`类用作 PHP DocBlocks 的最终替代品。”

代码块设置如下：

```php
// /repo/ch01/php7_prop_reduce.php
declare(strict_types=1);
class Test {
 protected $id = 0;
 protected $token = 0;
 protected $name = '';o
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```php
$result = match(<EXPRESSION>) {
    <ITEM> => <EXPRESSION>,
   [<ITEM> => <EXPRESSION>,]
    default => <DEFAULT EXPRESSION>
};
```

任何命令行输入或输出都将按以下方式编写：

```php
Fatal error: Uncaught TypeError: Cannot assign string to property Test::$token of type int in /repo/ch01/php8_prop_danger.php:12
```

提示或重要说明

显示如此。


# 第一部分：PHP 8 提示

本部分介绍了以前从未见过的很酷的东西，是 PHP 8 的新功能。这些章节讨论了面向对象编程中的新特性，接着是功能和扩展级别的新东西。本部分的最后一章涵盖了直接的 C 语言原型设计。

本部分包括以下章节：

+   [*第一章*]，*介绍新的 PHP 8 面向对象编程功能*

+   [*第二章*]，*了解 PHP 8 的功能增强*

+   [*第三章*]，*利用错误处理增强功能*

+   [*第四章*]，*进行直接的 C 语言调用*


# 第一章：介绍新的 PHP 8 OOP 特性

在本章中，您将了解到针对**面向对象编程**（**OOP**）的**PHP: Hypertext Preprocessor 8**（**PHP 8**）的新特性。本章介绍了一组类，可用于生成 CAPTCHA 图像（**CAPTCHA**是**Completely Automated Public Turing test to tell Computers and Humans Apart**的缩写），清晰地说明了新的 PHP 8 特性和概念。本章对于帮助您快速将新的 PHP 8 特性纳入到您自己的实践中至关重要。这样做，您的代码将运行得更快、更高效，bug 更少。

本章涵盖以下主题：

+   使用构造函数属性提升

+   使用属性

+   将匹配表达式纳入您的程序代码

+   理解命名参数

+   探索新的数据类型

+   使用类型属性改进代码

# 技术要求

要检查和运行本章提供的代码示例，以下是最低推荐的硬件要求：

+   基于 x86_64 的台式 PC 或笔记本电脑

+   1 GB 的可用磁盘空间

+   4 GB 的**随机存取存储器**（**RAM**）

+   500 **千位每秒**（**Kbps**）或更快的互联网连接

此外，您需要安装以下软件：

+   Docker

+   Docker Compose

本书使用一个预构建的 Docker 镜像，其中包含创建和运行本书中涵盖的 PHP 8 代码示例所需的所有软件。您不需要在计算机上安装 PHP、Apache 或 MySQL：只需使用 Docker 和提供的镜像即可。

要设置一个用于运行代码示例的测试环境，请按照以下步骤进行：

1.  安装 Docker。

如果您正在运行 Windows，请从这里开始：

[`docs.docker.com/docker-for-windows/install/`](https://docs.docker.com/docker-for-windows/install/ )

如果您使用 Mac，请从这里开始：

[`docs.docker.com/docker-for-mac/install/`](https://docs.docker.com/docker-for-mac/install/ )

如果您使用 Linux，请看这里：

[`docs.docker.com/engine/install/`](https://docs.docker.com/engine/install/ )

1.  安装 Docker Compose。对于所有操作系统，请从这里开始：

[`docs.docker.com/compose/install/`](https://docs.docker.com/compose/install/ )

1.  将与本书相关的源代码安装到您的本地计算机上。

如果您已安装 Git，请使用以下命令：

```php
git clone https://github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices.git ~/repo
```

否则，您可以直接从以下**统一资源定位器**（**URL**）下载源代码：[`github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices/archive/main.zip`](https://github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices/archive/main.zip)。然后解压到一个您创建的文件夹中，在本书中我们将其称为`/repo`。

1.  您现在可以启动 Docker 守护程序。对于 Windows 或 Mac，您只需要激活 Docker Desktop 应用程序。

如果您正在运行 Ubuntu 或 Debian Linux，请发出以下命令：

`sudo service docker start`

对于 Red Hat、Fedora 或 CentOS，请使用以下命令：

使用`sudo systemctl start docker`命令启动 Docker。

1.  构建与本书相关的 Docker 容器并将其上线。要做到这一点，请按照以下步骤进行。

从您的本地计算机，打开命令提示符（终端窗口）。将目录更改为`/repo`。仅首次，发出`docker-compose build`命令来*构建*环境。请注意，您可能需要`root`（管理员）权限来运行 Docker 命令。如果是这种情况，要么以管理员身份运行（对于 Windows），要么在命令前加上`sudo`。根据您的连接速度，初始构建可能需要相当长的时间才能完成！

1.  要启动容器，请按照以下步骤进行

1.  从您的本地计算机，打开命令提示符（终端窗口）。将目录更改为`/repo`。通过运行以下命令以后台模式启动 Docker 容器：

```php
docker-compose up -d
```

请注意，实际上您不需要单独构建容器。如果在发出`docker-compose up`命令时容器尚未构建，它将自动构建。另一方面，单独构建容器可能很方便，这种情况下只需使用`docker build`即可。

这是一个确保所有容器都在运行的有用命令：

```php
docker-compose ps
```

1.  要访问运行中的 Docker 容器 Web 服务器，请按照以下步骤进行。

在您的本地计算机上打开浏览器。输入此 URL 以访问 PHP 8 代码：

`http://localhost:8888`

输入此 URL 以访问 PHP 7 代码：

`http://localhost:7777`

1.  要打开运行中的 Docker 容器的命令行，按照以下步骤进行。

从您的本地计算机上，打开命令提示符（终端窗口）。发出此命令以访问 PHP 8 容器：

```php
docker exec -it php8_tips_php8 /bin/bash 
```

发出此命令以访问 PHP 7 容器：

```php
docker exec -it php8_tips_php7 /bin/bash
```

1.  当您完成与容器的工作后，要将其脱机，请从您的本地计算机上打开命令提示符（终端窗口）并发出此命令：

```php
docker-compose down 
```

本章的源代码位于此处：

[`github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices`](https://github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices )

重要提示

如果您的主机计算机使用**高级精简指令集**（**ARM**）架构（例如，树莓派），您将需要使用修改后的 Dockerfile。

提示

通过查看这篇文章，快速了解 Docker 技术和术语是一个很好的主意：[`docs.docker.com/get-started/.`](https://docs.docker.com/get-started/ )

我们现在可以通过查看构造函数属性提升来开始我们的讨论。

# 使用构造函数属性提升

除了**即时**（**JIT**）编译器之外，PHP 8 中引入的最大的新功能之一是**构造函数属性提升**。这个新功能将属性声明和`__construct()`方法签名中的参数列表以及赋默认值结合在一起。在本节中，您将学习如何大大减少属性声明和`__construct()`方法签名和主体中所需的编码量。

## 属性提升语法

调用构造函数属性提升所需的语法与 PHP 7 和之前使用的语法相同，有以下区别：

+   您需要定义一个**可见级别**

+   您不必事先显式声明属性。

+   您不需要在`__construct()`方法的主体中进行赋值

这是一个使用构造函数属性提升的代码的简单示例：

```php
// /repo/ch01/php8_prop_promo.php
declare(strict_types=1);
class Test {
    public function __construct(
        public int $id,
        public int $token = 0,
        public string $name = '')
    { }
}
$test = new Test(999);
var_dump($test);
```

当执行前面的代码块时，这是输出：

```php
object(Test)#1 (3) {
  ["id"]=> int(999)
  ["token"]=> int(0)
  ["name"]=> string(0) ""
}
```

这表明使用默认值创建了`Test`类型的实例。现在，让我们看看这个功能如何可以节省大量的编码。

## 使用属性提升来减少代码

在传统的 OOP PHP 类中，需要完成以下三件事：

1.  声明属性，如下所示：

```php
/repo/src/Php8/Image/SingleChar.php
namespace Php7\Image;
class SingleChar {
    public $text     = '';
    public $fontFile = '';
    public $width    = 100;
    public $height   = 100;
    public $size     = 0;
    public $angle    = 0.00;
    public $textX    = 0;
    public $textY    = 0;
```

1.  在`__construct()`方法签名中标识属性及其数据类型，如下所示：

```php
const DEFAULT_TX_X = 25;
const DEFAULT_TX_Y = 75;
const DEFAULT_TX_SIZE  = 60;
const DEFAULT_TX_ANGLE = 0;
public function __construct(
    string $text,
    string $fontFile,
    int $width  = 100,
    int $height = 100,
    int $size   = self::DEFAULT_TX_SIZE,
    float $angle = self::DEFAULT_TX_ANGLE,
    int $textX  = self::DEFAULT_TX_X,
    int $textY  = self::DEFAULT_TX_Y)   
```

1.  在`__construct()`方法的主体中，为属性赋值，就像这样：

```php
{   $this->text     = $text;
    $this->fontFile = $fontFile;
    $this->width    = $width;
    $this->height   = $height;
    $this->size     = $size;
    $this->angle    = $angle;
    $this->textX    = $textX;
    $this->textY    = $textY;
    // other code not shown 
}
```

随着构造函数参数的增加，您需要做的工作量也会显著增加。当应用构造函数属性提升时，以前所需的相同代码量减少到原来的三分之一。

现在让我们看一下之前显示的同一段代码块，但是使用这个强大的新 PHP 8 功能进行重写：

```php
// /repo/src/Php8/Image/SingleChar.php
// not all code shown
public function __construct(
    public string $text,
    public string $fontFile,
    public int    $width    = 100,
    public int    $height   = 100,
    public int    $size     = self::DEFAULT_TX_SIZE,
    public float   $angle    = self::DEFAULT_TX_ANGLE,
    public int    $textX    = self::DEFAULT_TX_X,
    public int    $textY    = self::DEFAULT_TX_Y)
    { // other code not shown }
```

令人惊讶的是，在 PHP 7 和之前的版本中需要 24 行代码，而使用这个新的 PHP 8 功能可以缩减为 8 行代码！

您完全可以在构造函数中包含其他代码。然而，在许多情况下，构造函数属性提升会处理`__construct()`方法中通常完成的所有工作，这意味着您可以将其留空（`{ }`）。

现在，在下一节中，您将了解一个称为属性的新功能。

提示

在这里查看 PHP 7 的完整 SingleChar 类的更多信息：

[`github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices/tree/main/src/Php7/Image`](https://github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices/tree/main/src/Php7/Image)

此外，等效的 PHP 8 类可以在这里找到：

[`github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices/tree/main/src/Php8/Image`](https://github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices/tree/main/src/Php8/Image)

有关此新功能的更多信息，请参阅以下内容：

[`wiki.php.net/rfc/constructor_promotion`](https://wiki.php.net/rfc/constructor_promotion)

# 使用 attributes

PHP 8 的另一个重要补充是全新的类和语言构造，称为**attributes**。简而言之，attributes 是传统 PHP 注释块的替代品，遵循规定的语法。当 PHP 代码编译时，这些 attributes 会在内部转换为`Attribute`类实例。

这个新功能不会立即影响您的代码。然而，随着各种 PHP 开源供应商开始将 attributes 纳入其代码中，它将开始变得越来越有影响力。

`Attribute`类解决了我们在本节讨论的一个潜在重要的性能问题，即滥用传统 PHP 注释块提供元指令。在我们深入讨论这个问题以及`Attribute`类实例如何解决问题之前，我们首先必须回顾一下 PHP 注释。

## PHP 注释概述

这种语言构造的需求是随着对普通 PHP 注释的使用（和滥用！）的增加而产生的。正如您所知，注释有许多形式，包括以下所有形式：

```php
# This is a "bash" shell script style comment
// this can either be inline or on its own line
/* This is the traditional "C" language style */
/**
 * This is a PHP "DocBlock"
 */
```

最后一项，著名的 PHP `DocBlock`，现在被广泛使用，已成为事实上的标准。使用 DocBlocks 并不是一件坏事。相反，这往往是开发人员能够传达有关属性、类和方法的信息的*唯一* *方式*。问题只在于它在 PHP 解释过程中的处理方式。

## PHP DocBlock 注意事项

**PHP DocBlock**的原始意图已经被一些非常重要的 PHP 开源项目所拉伸。一个鲜明的例子是 Doctrine **对象关系映射**（**ORM**）项目。虽然不是强制的，但许多开发人员选择使用嵌套在 PHP DocBlocks 中的**annotations**来定义 ORM 属性。

看一下这个部分代码示例，它定义了一个与名为`events`的数据库表交互的类：

```php
namespace Php7\Entity;
use Doctrine\ORM\Mapping as ORM;
/**
 * @ORM\Table(name="events")
 * @ORM\Entity("Application\Entity\Events")
 */
class Events {
    /**
     * @ORM\Column(name="id",type="integer",nullable=false)
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="IDENTITY")
     */
    private $id;
    /**
     * @ORM\Column(name="event_key", type="string", 
          length=16, nullable=true, options={"fixed"=true})
     */
    private $eventKey;
    // other code not shown
```

如果您要将此类用作 Doctrine ORM 实现的一部分，Doctrine 将打开文件并解析 DocBlocks，搜索`@ORM`注释。尽管对解析 DocBlocks 所需的时间和资源有一些担忧，但这是一种非常方便的方式来定义对象属性和数据库表列之间的关系，并且受到使用 Doctrine 的开发人员的欢迎。

提示

Doctrine 提供了许多替代方案来实现 ORM，包括**可扩展标记语言**（**XML**）和本机 PHP 数组。有关更多信息，请参阅[`www.doctrine-project.org/projects/doctrine-orm/en/latest/reference/annotations-reference.html#annotations-reference`](https://www.doctrine-project.org/projects/doctrine-orm/en/latest/reference/annotations-reference.html#annotations-reference)。

## 与滥用 DocBlocks 相关的潜在危险

与滥用 DocBlock 的原始目的相关的另一个危险是。在`php.ini`文件中，有一个名为`opcache.save_comments`的设置。如果禁用，这将导致 OpCode 缓存引擎（**OPcache**）*忽略*所有注释，包括 DocBlocks。如果此设置生效，使用`@ORM`注释的基于 Doctrine 的应用程序将发生故障。

另一个问题与注释的解析有关，或者更准确地说，与注释的*不*解析有关。为了使用注释的内容，PHP 应用程序需要逐行打开文件并解析它。这在时间和资源利用方面是一个昂贵的过程。

## 属性类

为了解决隐藏的危险，在 PHP 8 中提供了一个新的`Attribute`类。开发人员可以定义等效的属性形式，而不是使用带注释的 DocBlocks。使用属性而不是 DocBlocks 的优势在于它们是语言的*正式部分*，因此它们与代码的其余部分一起被标记化和编译。

重要提示

在本章中，以及在 PHP 文档中，*属性*的引用指的是`Attribute`类的实例。

目前尚无实际的性能指标可比较包含 DocBlocks 的 PHP 代码的加载与包含属性的代码的加载。

尽管这种方法的好处尚未显现，但随着各种开源项目供应商开始将属性纳入其产品中，您将开始看到速度和性能的提高。

这是`Attribute`类的定义：

```php
class Attribute {
    public const int TARGET_CLASS = 1;
    public const int TARGET_FUNCTION = (1 << 1);
    public const int TARGET_METHOD = (1 << 2);
    public const int TARGET_PROPERTY = (1 << 3);
    public const int TARGET_CLASS_CONSTANT = (1 << 4);
    public const int TARGET_PARAMETER = (1 << 5);
    public const int TARGET_ALL = ((1 << 6) - 1);
    public function __construct(
        int $flags = self::TARGET_ALL) {}
}
```

从类定义中可以看出，这个类在 PHP 8 内部使用的主要贡献是一组类常量。这些常量代表可以使用位运算符组合的位标志。

## 属性语法

属性使用了从**Rust**编程语言借鉴的特殊语法。方括号内的内容基本上由开发人员决定。以下代码段中可以看到一个示例：

```php
#[attribute("some text")] 
// class, property, method or function (or whatever!)
```

回到我们的`SingleChar`类的示例，这是如何在传统的 DocBlocks 中出现的：

```php
// /repo/src/Php7/Image/SingleChar.php
namespace Php7\Image;
/**
 * Creates a single image, by default black on white
 */
class SingleChar {
    /**
     * Allocates a color resource
     *
     * @param array|int $r,
     * @param int $g
     * @param int $b]
     * @return int $color
     */
    public function colorAlloc() 
    { /* code not shown */ } 
```

现在，看看使用属性的相同内容：

```php
// /repo/src/Php8/Image/SingleChar.php
namespace Php8\Image;
#[description("Creates a single image")]
class SingleChar {
    #[SingleChar\colorAlloc\description("Allocates color")]
    #[SingleChar\colorAlloc\param("r","int|array")]
    #[SingleChar\colorAlloc\param("g","int")]
    #[SingleChar\colorAlloc\param("b","int")]
    #[SingleChar\colorAlloc\returns("int")]
    public function colorAlloc() { /* code not shown */ }
```

如您所见，除了提供更强大的编译和避免上述隐藏危险之外，它在空间使用方面也更有效。

提示

方括号内的内容确实有一些限制；例如，虽然允许`#[returns("int")]`，但不允许这样做：`#[return("int")`。原因是`return`是一个关键字。

另一个例子涉及**联合类型**（在*探索新数据类型*部分中解释）。您可以在属性中使用`#[param("int|array test")]`，但不允许这样做：`#[int|array("test")]`。另一个特殊之处是类级别的属性必须放在`class`关键字之前，并在任何`use`语句之后。

### 使用 Reflection 查看属性

如果您需要从 PHP 8 类获取属性信息，`Reflection`扩展已更新以包括属性支持。添加了一个新的`getAttributes()`方法，返回一个`ReflectionAttribute`实例数组。

在以下代码块中，显示了`Php8\Image\SingleChar::colorAlloc()`方法的所有属性：

```php
<?php
// /repo/ch01/php8_attrib_reflect.php
define('FONT_FILE', __DIR__ . '/../fonts/FreeSansBold.ttf');
require_once __DIR__ . '/../src/Server/Autoload/Loader.php';
$loader = new \Server\Autoload\Loader();
use Php8\Image\SingleChar;
$char    = new SingleChar('A', FONT_FILE);
$reflect = new ReflectionObject($char);
$attribs = $reflect->getAttributes();
echo "Class Attributes\n";
foreach ($attribs as $obj) {
    echo "\n" . $obj->getName() . "\n";
    echo implode("\t", $obj->getArguments());
}
echo "Method Attributes for colorAlloc()\n";
$reflect = new ReflectionMethod($char, 'colorAlloc');
$attribs = $reflect->getAttributes();
foreach ($attribs as $obj) {
    echo "\n" . $obj->getName() . "\n";
    echo implode("\t", $obj->getArguments());
}
```

以下是前面代码段中显示的输出：

```php
<pre>Class Attributes
Php8\Image\SingleChar
Php8\Image\description
Creates a single image, by default black on whiteMethod
Attributes for colorAlloc()
Php8\Image\SingleChar\colorAlloc\description
Allocates a color resource
Php8\Image\SingleChar\colorAlloc\param
r    int|array
Php8\Image\SingleChar\colorAlloc\param
g    int
Php8\Image\SingleChar\colorAlloc\param
b    int
Php8\Image\SingleChar\colorAlloc\returns
int
```

前面的输出显示了可以使用`Reflection`扩展类检测属性。最后，这段代码示例展示了实际的方法：

```php
namespace Php8\Image;use Attribute;
use Php8\Image\Strategy\ {PlainText,PlainFill};
#[SingleChar]
#[description("Creates black on white image")]
class SingleChar {
    // not all code is shown
    #[SingleChar\colorAlloc\description("Allocates color")]
    #[SingleChar\colorAlloc\param("r","int|array")]
    #[SingleChar\colorAlloc\param("g","int")]
    #[SingleChar\colorAlloc\param("b","int")]
    #[SingleChar\colorAlloc\returns("int")]    
    public function colorAlloc(
         int|array $r, int $g = 0, int $b = 0) {
        if (is_array($r))
            [$r, $g, $b] = $r;
        return \imagecolorallocate(
              $this->image, $r, $g, $b);
    }
}
```

现在，您已经了解了属性的使用方式，让我们继续讨论`match`表达式，然后是命名参数的新功能。

提示

有关此新功能的更多信息，请查看以下网页：

[`wiki.php.net/rfc/attributes_v2`](https://wiki.php.net/rfc/attributes_v2 )

另请参阅此更新：

[`wiki.php.net/rfc/shorter_attribute_syntax_change`](https://wiki.php.net/rfc/shorter_attribute_syntax_change )

有关 PHP DocBlocks 的信息可以在这里找到：

[`phpdoc.org/`](https://phpdoc.org/ )

有关 Doctrine ORM 的更多信息，请查看这里：

[`www.doctrine-project.org/projects/orm.html`](https://www.doctrine-project.org/projects/orm.html )

有关`php.ini`文件设置的文档可以在这里找到：

[`www.php.net/manual/en/ini.list.php`](https://www.php.net/manual/en/ini.list.php)

在这里阅读有关 PHP 反射的信息：

[`www.php.net/manual/en/language.attributes.reflection.php`](https://www.php.net/manual/en/language.attributes.reflection.php)

有关 Rust 编程语言的信息可以在这本书中找到：[`www.packtpub.com/product/mastering-rust-second-edition/9781789346572`](https://www.packtpub.com/product/mastering-rust-second-edition/9781789346572)

# 将 match 表达式合并到程序代码中

在 PHP 8 中引入的许多非常有用的功能中，**match 表达式**绝对脱颖而出。`Match`表达式是一种更准确的简写语法，可以潜在地取代直接来自 C 语言的老旧`switch`语句。在本节中，您将学习如何通过用`match`表达式替换`switch`语句来生成更清晰和更准确的程序代码。

## Match 表达式的一般语法

`Match`表达式语法非常类似于数组，其中键是要匹配的项，值是一个表达式。以下是`match`的一般语法：

```php
$result = match(<EXPRESSION>) {
    <ITEM> => <EXPRESSION>,
   [<ITEM> => <EXPRESSION>,]
    default => <DEFAULT EXPRESSION>
};
```

表达式必须是有效的 PHP 表达式。表达式的示例可以包括以下任何一种：

+   一个特定的值（例如，`"一些文本"`）

+   一个操作（例如，`$a + $b`）

+   匿名函数或类

唯一的限制是表达式必须在一行代码中定义。`match`和`switch`之间的主要区别在这里总结：

![表 1.1 - match 和 switch 之间的区别](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Table_1.1_B16992.jpg)

表 1.1 - match 和 switch 之间的区别

除了上述区别之外，`match`和`switch`都允许案例聚合，并提供对*default*案例的支持。

### switch 和 match 示例

这是一个简单的示例，使用`switch`来渲染货币符号：

```php
// /repo/ch01/php7_switch.php
function get_symbol($iso) {
    switch ($iso) {
        case 'CNY' :
            $sym = '¥';
            break;
        case 'EUR' :
            $sym = '€';
            break;
        case 'EGP' :
        case 'GBP' :
            $sym = '£';
            break;
        case 'THB' :
            $sym = '฿';
            break;
        default :
            $sym = '$';
    }
    return $sym;
}
$test = ['CNY', 'EGP', 'EUR', 'GBP', 'THB', 'MXD'];
foreach ($test as $iso)
    echo 'The currency symbol for ' . $iso
         . ' is ' . get_symbol($iso) . "\n";
```

当执行此代码时，您会看到`$test`数组中每个**国际标准化组织**（**ISO**）货币代码的货币符号。在 PHP 8 中可以获得与前面代码片段中显示的相同结果，使用以下代码：

```php
// /repo/ch01/php8_switch.php
function get_symbol($iso) {
    return match ($iso) {
        'EGP','GBP' => '£',
        'CNY'       => '¥',
        'EUR'       => '€',
        'THB'       => '฿',
        default     => '$'
    };
}
$test = ['CNY', 'EGP', 'EUR', 'GBP', 'THB', 'MXD'];
foreach ($test as $iso)
    echo 'The currency symbol for ' . $iso
         . ' is ' . get_symbol($iso) . "\n";
```

两个示例产生相同的输出，如下所示：

```php
The currency symbol for CNY is ¥
The currency symbol for EGP is £
The currency symbol for EUR is €
The currency symbol for GBP is £
The currency symbol for THB is ฿
The currency symbol for MXD is $
```

如前所述，这两个代码示例都会为存储在`$test`数组中的 ISO 货币代码列表产生货币符号列表。

### 复杂的 match 示例

回到我们的验证码项目，假设我们希望引入扭曲以使验证码字符更难阅读。为了实现这个目标，我们引入了许多**策略**类，每个类产生不同的扭曲，如下表所总结的：

![表 1.2 - 验证码扭曲策略类](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Table_1.2_B16992.jpg)

表 1.2 - 验证码扭曲策略类

在随机排列要使用的策略列表之后，我们使用`match`表达式来执行结果，如下所示：

1.  首先我们定义一个**自动加载程序**，导入要使用的类，并列出要使用的潜在策略，如下所示：

```php
// /repo/ch01/php8_single_strategies.php
// not all code is shown
require_once __DIR__ . '/../src/Server/Autoload/Loader.php';
$loader = new \Server\Autoload\Loader();
use Php8\Image\SingleChar;
use Php8\Image\Strategy\ {LineFill,DotFill,Shadow,RotateText};
$strategies = ['rotate', 'line', 'line',
               'dot', 'dot', 'shadow'];
```

1.  接下来，我们生成验证码短语，如下所示：

```php
$phrase = strtoupper(bin2hex(random_bytes(NUM_BYTES)));
$length = strlen($phrase);
```

1.  然后我们循环遍历验证码短语中的每个字符，并创建一个`SingleChar`实例。对`writeFill()`的初始调用创建了白色背景画布。我们还需要调用`shuffle()`来随机排列扭曲策略的列表。该过程在以下代码片段中说明：

```php
$images = [];
for ($x = 0; $x < $length; $x++) {
    $char = new SingleChar($phrase[$x], FONT_FILE);
    $char->writeFill();
    shuffle($strategies);
```

1.  然后我们循环遍历策略并在原始图像上叠加扭曲。这就是`match`表达式发挥作用的地方。请注意，一个策略需要额外的代码行。因为`match`只能支持单个表达式，所以我们简单地将多行代码包装到一个**匿名函数**中，如下所示：

```php
foreach ($strategies as $item) {
    $func = match ($item) {    
        'rotate' => RotateText::writeText($char),
        'line' => LineFill::writeFill(
            $char, rand(1, 10)),
        'dot' => DotFill::writeFill($char, rand(10, 20)),
        'shadow' => function ($char) {
            $num = rand(1, 8);
            $r   = rand(0x70, 0xEF);
            $g   = rand(0x70, 0xEF);
            $b   = rand(0x70, 0xEF);
            return Shadow::writeText(
                $char, $num, $r, $g, $b);},
        'default' => TRUE
    };
    if (is_callable($func)) $func($char);
}
```

1.  现在要做的就是通过不带参数调用`writeText()`来覆盖图像。之后，我们将扭曲的图像保存为**便携式网络图形**（**PNG**）文件以供显示，如下面的代码片段所示：

```php
    $char->writeText();
    $fn = $x . '_' 
         . substr(basename(__FILE__), 0, -4) 
         . '.png';
    $char->save(IMG_DIR . '/' . $fn);
    $images[] = $fn;
}
include __DIR__ . '/captcha_simple.phtml';
```

这是从指向本书关联的 Docker 容器的浏览器中运行前面示例的结果：

![图 1.1 - 使用匹配表达式扭曲的验证码](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_1.1_B16992.jpg)

图 1.1 - 使用匹配表达式扭曲的验证码

接下来，我们将看一下另一个非常棒的功能：命名参数。

提示

您可以在这里看到`match`表达式的原始提案：[`wiki.php.net/rfc/match_expression_v2`](https://wiki.php.net/rfc/match_expression_v2)

# 理解命名参数

**命名参数**代表一种避免在调用具有大量参数的函数或方法时产生混淆的方法。这不仅有助于避免参数以不正确的顺序提供的问题，还有助于您跳过具有默认值的参数。在本节中，您将学习如何应用命名参数来提高代码的准确性，减少未来维护周期中的混淆，并使您的方法和函数调用更加简洁。我们首先来看一下使用命名参数所需的通用语法。

## 命名参数通用语法

要使用命名参数，您需要知道函数或方法签名中使用的变量的名称。然后，您可以指定该名称，不带美元符号，后跟冒号和要提供的值，如下所示：

`$result = function_name( arg1 : <VALUE>, arg2 : <value>);`

当调用`function_name()`函数时，值将传递给与`arg1`、`arg2`等对应的参数。

## 使用命名参数调用核心函数

使用命名参数的最常见原因之一是调用具有大量参数的核心 PHP 函数。例如，这是`setcookie()`的函数签名：

```php
setcookie ( string $name [, string $value = "" 
    [, int $expires = 0 [, string $path = "" 
    [, string $domain = "" [, bool $secure = FALSE 
    [, bool $httponly = FALSE ]]]]]] ) : bool
```

假设您真正想要设置的只是`name`、`value`和`httponly`参数。在 PHP 8 之前，您需要查找默认值并按顺序提供它们，直到您到达要覆盖的值。在下面的情况下，我们希望将`httponly`设置为`TRUE`：

`setcookie('test',1,0,0,'','',FALSE,TRUE);`

使用命名参数，在 PHP 8 中的等效方式如下：

`setcookie('test',1,httponly: TRUE);`

请注意，我们不需要为前两个参数命名，因为它们是按顺序提供的。

提示

在 PHP 扩展中，命名参数并不总是与您在 PHP 文档中看到的函数或方法签名的变量名称匹配。例如，函数`imagettftext()`在其函数签名中显示一个变量`$font_filename`。然而，如果您再往下滚动一点，您会在*参数*部分看到，命名参数是`fontfile`。

如果遇到致命错误：`未知命名参数$NAMED_PARAM`。始终使用文档中*参数*部分列出的名称，而不是函数或方法签名中变量的名称。

## 顺序独立和文档

命名参数的另一个用途是提供**顺序独立**。此外，对于某些核心 PHP 函数来说，参数的数量之多构成了文档的噩梦。

例如，看一下`imagefttext()`的函数签名（请注意，这个函数是生成安全验证码图像的章节项目的核心）：

```php
imagefttext ( object $image , float $size , float $angle , 
    int $x , int $y , int $color , string $fontfile , 
    string $text [, array $extrainfo ] ) : array 
```

正如你可以想象的那样，在 6 个月后回顾你的工作时，试图记住这些参数的名称和顺序可能会有问题。

重要提示

在 PHP 8 中，图像创建函数（例如`imagecreate()`）现在返回一个`GdImage`对象实例，而不是一个资源。GD 扩展中的所有图像函数都已经重写以适应这一变化。没有必要重写您的代码！

因此，在 PHP 8 中，使用命名参数，以下函数调用将是可接受的：

```php
// /repo/ch01/php8_named_args.php
// not all code is shown
$rotation = range(40, -40, 10);
foreach ($rotation as $key => $offset) {
    $char->writeFill();
    [$x, $y] = RotateText::calcXYadjust($char, $offset);
    $angle = ($offset > 0) ? $offset : 360 + $offset;
    imagettftext(
        angle        : $angle,
        color        : $char->fgColor,
        font_filename : FONT_FILE,
        image        : $char->image,
        size         : 60,                
        x            : $x,
        y            : $y,
        text         : $char->text);
    $fn = IMG_DIR . '/' . $baseFn . '_' . $key . '.png';
    imagepng($char->image, $fn);
    $images[] = basename($fn);
}
```

刚才显示的代码示例将一串扭曲字符写成一组 PNG 图像文件。每个字符相对于其相邻图像顺时针旋转 10 度。请注意，命名参数的应用使`imagettftext()`函数的参数更容易理解。

命名参数也可以应用于您自己创建的函数和方法。在下一节中，我们将介绍新的数据类型。

提示

关于命名参数的详细分析可以在这里找到：

[`wiki.php.net/rfc/named_params`](https://wiki.php.net/rfc/named_params )

# 探索新的数据类型

任何初级 PHP 开发人员学到的一件事是 PHP 有哪些可用的**数据类型**以及如何使用它们。基本数据类型包括`int`（整数）、`float`、`bool`（布尔值）和`string`。复杂数据类型包括`array`和`object`。此外，还有其他数据类型，如`NULL`和`resource`。在本节中，我们将讨论 PHP 8 中引入的一些新数据类型，包括联合类型和混合类型。

重要说明

非常重要的一点是不要混淆**数据类型**和**数据格式**。本节描述了数据类型。另一方面，数据格式将是用作传输或存储的数据的*表示*方式。数据格式的示例包括 XML，**JavaScript 对象表示**（**JSON**）和**YAML 不是标记语言**（**YAML**）。

## 联合类型

与`int`或`string`等其他数据类型不同，重要的是要注意，没有一个名为*union*的数据类型。相反，当你看到**联合类型**的引用时，意思是 PHP 8 引入了一种新的语法，允许您指定多种类型，而不仅仅是一种。现在让我们来看一下联合类型的通用语法。

### 联合类型语法

联合类型的通用语法如下：

`function ( type|type|type $var) {}`

在`type`的位置，您可以提供任何现有的数据类型（例如`float`或`string`）。然而，有一些限制，大部分都是完全有道理的。这张表总结了更重要的限制：

![表 1.3 - 不允许的联合类型](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Table_1.3_B16992.jpg)

表 1.3 - 不允许的联合类型

从这个例外列表中可以看出，定义联合类型主要是常识问题。

提示

**最佳实践**：在使用联合类型时，如果不强制执行严格类型检查，**类型强制转换**（PHP 内部转换数据类型以满足函数要求的过程）可能会成为一个问题。因此，最佳实践是在使用联合类型的任何文件顶部添加以下内容：`declare(strict_types=1);`。

有关更多信息，请参阅此处的文档参考：

[`www.php.net/manual/en/language.types.declarations.php#language.types.declarations.strict`](https://www.php.net/manual/en/language.types.declarations.php#language.types.declarations.strict )

### 联合类型示例

为了简单说明，让我们回到本章中使用的`SingleChar`类作为示例。其中的一个方法是`colorAlloc()`。该方法从图像中分配颜色，利用了`imagecolorallocate()`函数。它接受表示红色、绿色和蓝色的整数值作为参数。

为了论证，假设第一个参数实际上可以是表示三个值的数组——分别是红色、绿色和蓝色。在这种情况下，第一个值的参数类型不能是`int`，否则，如果提供了一个数组，并且打开了严格类型检查，将会抛出错误。

在 PHP 的早期版本中，唯一的解决方案是从第一个参数中删除任何类型检查，并指示在相关的 DocBlock 中接受多种类型。以下是在 PHP 7 中该方法可能的样子：

```php
/**
 * Allocates a color resource
 *
 * @param array|int $r
 * @param int $g
 * @param int $b]
 * @return int $color
 */
public function colorAlloc($r, $g = 0, $b = 0) {
    if (is_array($r)) {
        [$r, $g, $b] = $r;
    }
    return \imagecolorallocate($this->image, $r, $g, $b);
}
```

第一个参数`$r`的数据类型唯一的指示是`@param array|int $r`的 DocBlock 注释和没有与该参数关联的数据类型提示。在 PHP 8 中，利用联合类型，注意这里的区别：

```php
#[description("Allocates a color resource")]
#[param("int|array r")]
#[int("g")]
#[int("b")]
#[returns("int")]
public function colorAlloc(
    int|array $r, int $g = 0, int $b = 0) {
    if (is_array($r)) {
        [$r, $g, $b] = $r;
    }
    return \imagecolorallocate($this->image, $r, $g, $b);
}
```

在前面的示例中，除了`attribute`的存在表明第一个参数可以接受`array`或`int`类型之外，在方法签名本身中，`int|array`联合类型清楚地说明了这个选择。

## 混合类型

`mixed`是 PHP 8 中引入的另一种新类型。与联合类型不同，`mixed`是一个实际的数据类型，代表了所有类型的最终联合。它用于表示接受任何和所有数据类型。在某种意义上，PHP 已经具有了这个功能：简单地省略数据类型，它就是一个隐含的`mixed`类型！

提示

您将在 PHP 文档中看到对`mixed`类型的引用。PHP 8 通过将其作为实际数据类型来正式表示这种表示。

### 为什么使用混合类型？

等一下——你可能会想到：为什么要使用`mixed`类型呢？放心，这是一个很好的问题，没有强制使用这种类型的理由。

然而，通过在函数或方法签名中使用`mixed`，您清楚地*表明了您对该参数的使用意图。如果您只是留空数据类型，其他开发人员在以后使用或审查您的代码时可能会认为您忘记添加类型。至少，他们会对未命名参数的性质感到不确定。

## 混合类型对继承的影响

作为`mixed`类型代表**扩宽**的最终示例，它可以用于在一个类继承另一个类时*扩宽*数据类型定义。以下是使用`mixed`类型的示例，说明了这个原则：

1.  首先，我们用更严格的数据类型`object`定义父类，如下所示：

```php
// /repo/ch01/php8_mixed_type.php
declare(strict_types=1);
class High {
    const LOG_FILE = __DIR__ . '/../data/test.log';  
    protected static function logVar(object $var) {     
        $item = date('Y-m-d') . ':'
              . var_export($var, TRUE);
        return error_log($item, 3, self::LOG_FILE);
    }
}
```

1.  接下来，我们定义一个`Low`类，它继承自`High`，如下所示：

```php
class Low extends High {
    public static function logVar(mixed $var) {
        $item = date('Y-m-d') . ':'
            . var_export($var, TRUE);
        return error_log($item, 3, self::LOG_FILE);
    }
}
```

请注意，在`Low`类中，`logVar()`方法的数据类型已经*扩宽*为`mixed`。

1.  最后，我们创建了一个`Low`的实例，并用测试数据执行它。从下面的代码片段中显示的结果可以看出，一切都运行正常：

```php
if (file_exists(High::LOG_FILE)) unlink(High::LOG_FILE)
$test = [
    'array' => range('A', 'F'),
    'func' => function () { return __CLASS__; },
    'anon' => new class () { 
        public function __invoke() { 
            return __CLASS__; } },
];
foreach ($test as $item) Low::logVar($item);
readfile(High::LOG_FILE);
```

以下是前面示例的输出：

```php
2020-10-15:array (
  0 => 'A',
  1 => 'B',
  2 => 'C',
  3 => 'D',
  4 => 'E',
  5 => 'F',
)2020-10-15:Closure::__set_state(array(
))2020-10-15:class@anonymous/repo/ch01/php8_mixed_type.php:28$1::__set_state(array())
```

前面的代码块记录了各种不同的数据类型，然后显示了日志文件的内容。在这个过程中，这向我们展示了在 PHP 8 中，当子类覆盖父类方法并用`mixed`代替更严格的数据类型，如`object`时，不存在继承问题。

接下来，我们来看一下如何使用有类型的属性。

提示

**最佳实践**：在定义函数或方法时，为所有参数分配特定的数据类型。如果接受几种不同的数据类型，定义一个联合类型。否则，如果没有适用上述情况，退而使用`mixed`类型。

关于联合类型的信息，请参阅此文档页面：

[`wiki.php.net/rfc/union_types_v2`](https://wiki.php.net/rfc/union_types_v2 )

有关`mixed`类型的更多信息，请查看这里：[`wiki.php.net/rfc/mixed_type_v2.`](https://wiki.php.net/rfc/mixed_type_v2 )

# 改进使用有类型属性的代码

在本章的第一部分，*使用构造函数属性提升*，我们讨论了如何使用数据类型来控制提供给函数或类方法的参数的数据类型。然而，这种方法未能保证数据类型永远不会改变。在本节中，您将学习如何在属性级别分配数据类型，从而更严格地控制 PHP 8 中变量的使用。

## 有类型属性是什么？

这个非常重要的特性是在 PHP 7.4 中引入的，并在 PHP 8 中继续。简而言之，**有类型属性**是一个预先分配数据类型的类属性。以下是一个简单的例子：

```php
// /repo/ch01/php8_prop_type_1.php
declare(strict_types=1)
class Test {
    public int $id = 0;
    public int $token = 0;
    public string $name = '';
}
$test = new Test();
$test->id = 'ABC';
```

在这个例子中，如果我们尝试将代表`int`以外的数据类型的值分配给`$test->id`，将会抛出`Fatal error`。以下是输出：

```php
Fatal error: Uncaught TypeError: Cannot assign string to property Test::$id of type int in /repo/ch01/php8_prop_type_1.php:11 Stack trace: #0 {main} thrown in /repo/ch01/php8_prop_type_1.php on line 11 
```

如您从上面的输出中所见，当错误的数据类型分配给类型化属性时，将会抛出`Fatal error`。

您已经接触过一种属性类型化的形式：**构造函数属性提升**。使用构造函数属性提升定义的所有属性都会自动进行属性类型化！

### 为什么属性类型化很重要？

类型化属性是 PHP 中首次出现的一般趋势的一部分，该趋势是朝着限制和加强代码使用的语言细化发展。这导致更好的代码，意味着更少的错误。

以下示例说明了仅依赖属性类型提示来控制属性数据类型的危险：

```php
// /repo/ch01/php7_prop_danger.php
declare(strict_types=1);
class Test {
    protected $id = 0;
    protected $token = 0;
    protected $name = '';
    public function __construct(
        int $id, int $token, string $name) {
        $this->id = $id;
        $this->token = md5((string) $token);
        $this->name = $name;
    }
}
$test = new Test(111, 123456, 'Fred');
var_dump($test);
```

在上面的例子中，注意在`__construct()`方法中，`$token`属性被意外转换为字符串。以下是输出：

```php
object(Test)#1 (3) {
  ["id":protected]=>  int(111)
  ["token":protected]=>
  string(32) "e10adc3949ba59abbe56e057f20f883e"
  ["name":protected]=>  string(4) "Fred"
}
```

任何后续的代码如果期望`$token`是一个整数，可能会失败或产生意外的结果。现在，让我们看一下在 PHP 8 中使用类型化属性的相同情况：

```php
// /repo/ch01/php8_prop_danger.php
declare(strict_types=1);
class Test {
    protected int $id = 0;
    protected int $token = 0;
    protected string $name = '';
    public function __construct(
        int $id, int $token, string $name) {        
        $this->id = $id;
        $this->token = md5((string) $token);
        $this->name = $name;
    }
}
$test = new Test(111, 123456, 'Fred');
var_dump($test);
```

属性类型化可以防止预分配的数据类型发生任何更改，如您在此处所见的输出所示：

```php
Fatal error: Uncaught TypeError: Cannot assign string to property Test::$token of type int in /repo/ch01/php8_prop_danger.php:12
```

如您从上面的输出中所见，当错误的数据类型分配给类型化属性时，将会抛出`Fatal error`。这个例子表明，不仅将数据类型分配给属性可以防止在进行直接赋值时的误用，而且还可以防止在类方法中误用属性！

## 属性类型化可以导致代码量的减少

引入属性类型化到您的代码中的另一个有益的副作用是可能减少所需的代码量。例如，考虑当前的做法，即将属性标记为`private`或`protected`的可见性，然后创建一系列用于控制访问的`get`和`set`方法（也称为*getters*和*setters*）。

这可能如下所示：

1.  首先，我们定义一个带有受保护属性的`Test`类，如下所示：

```php
// /repo/ch01/php7_prop_reduce.php
declare(strict_types=1);
class Test {
 protected $id = 0;
 protected $token = 0;
 protected $name = '';o
```

1.  接下来，我们定义一系列用于控制对受保护属性的访问的`get`和`set`方法，如下所示：

```php
    public function getId() { return $this->id; }
    public function setId(int $id) { $this->id = $id; 
    public function getToken() { return $this->token; }
    public function setToken(int $token) {
        $this->token = $token;
    }
    public function getName() {
        return $this->name;
    }
    public function setName(string $name) {
        $this->name = $name;
    }
}
```

1.  然后，我们使用`set`方法来分配值，如下所示：

```php
$test = new Test();
$test->setId(111);
$test->setToken(999999);
$test->setName('Fred');
```

1.  最后，我们使用`get`方法以表格形式显示结果，如下所示：

```php
$pattern = '<tr><th>%s</th><td>%s</td></tr>';
echo '<table width="50%" border=1>';
printf($pattern, 'ID', $test->getId());
printf($pattern, 'Token', $test->getToken());
printf($pattern, 'Name', $test->getName());
echo '</table>';
```

这可能如下所示：

![表 1.4 - 使用 Get 方法输出](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_1.2_B16992.jpg)

表 1.4 - 使用 Get 方法输出

通过将属性标记为`protected`（或`private`）并定义*getters*和*setters*来实现的主要目的是控制访问。通常，这意味着希望阻止属性数据类型的更改。如果是这种情况，整个基础设施可以通过分配属性类型来替换。

将可见性简单地更改为`public`可以减轻对`get`和`set`方法的需求；但是，它并不能防止属性数据被更改！使用 PHP 8 属性类型既实现了这两个目标：它消除了`get`和`set`方法的需求，也防止了数据类型被意外更改。

注意在 PHP 8 中使用属性类型化实现相同结果所需的代码量大大减少了：

```php
// /repo/ch01/php8_prop_reduce.php
declare(strict_types=1);
class Test {
    public int $id = 0;
    public int $token = 0;
    public string  $name = '';
}
// assign values
$test = new Test();
$test->id = 111;
$test->token = 999999;
$test->name = 'Fred';
// display results
$pattern = '<tr><th>%s</th><td>%s</td></tr>';
echo '<table width="50%" border=1>';
printf($pattern, 'ID', $test->id);
printf($pattern, 'Token', $test->token);
printf($pattern, 'Name', $test->name);
echo '</table>';
```

上面显示的代码示例产生了与前一个示例完全相同的输出，并且还实现了对属性数据类型的更好控制。在这个例子中，使用类型化属性，我们实现了*50%的代码减少*来产生相同的结果！

提示

**最佳实践**：尽可能在可能的情况下使用类型化属性，除非您明确希望允许数据类型更改。

# 总结

在本章中，您学习了如何使用新的 PHP 8 数据类型：混合类型和联合类型来编写更好的代码。您还了解到使用命名参数不仅可以提高代码的可读性，还可以帮助防止意外误用类方法和 PHP 函数，同时提供了一个很好的方法来跳过默认参数。

本章还教会了您如何使用新的`Attribute`类作为 PHP DocBlocks 的潜在替代品，以改善代码的整体性能，同时提供了一种可靠的方式来记录类、方法和函数。

此外，我们还看到 PHP 8 如何通过利用构造函数参数提升和类型化属性大大减少了早期 PHP 版本所需的代码量。

在下一章中，您将学习有关功能和过程级别的新 PHP 8 功能。


# 第二章：学习 PHP 8 的功能增强

本章将带您了解在程序级别引入的**PHP 8**的重要增强和改进。使用的代码示例展示了新的 PHP 8 功能和技术，以便促进程序化编程。

掌握本章中新函数和技术的使用将帮助您编写更快、更干净的应用程序。尽管本章重点介绍命令和函数，但在开发类方法时，所有这些技术也很有用。

本章涵盖以下主题：

+   使用新的 PHP 8 操作符

+   使用箭头函数

+   理解统一变量语法

+   学习新的数组和字符串处理技术

+   使用 authorizer 保护 SQLite 数据库

# 技术要求

要检查和运行本章提供的代码示例，以下是最低推荐的硬件要求：

+   基于 x86_64 的台式机或笔记本电脑

+   1 千兆字节（GB）的可用磁盘空间

+   4 GB 的随机存取存储器（RAM）

+   每秒 500 千位（Kbps）或更快的互联网连接

+   另外，您需要安装以下软件：

+   Docker

+   Docker Compose

有关 Docker 和 Docker Compose 安装的更多信息，请参阅*第一章*的*技术要求*部分，介绍了如何构建用于演示本书中代码的 Docker 容器。在整个过程中，我们将参考您恢复本书示例代码的目录为`/repo`。

本章的源代码位于此处：[`github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices`](https://github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices)。

我们现在可以开始讨论新的 PHP 8 操作符了。

# 使用新的 PHP 8 操作符

PHP 8 引入了许多新的**操作符**。此外，PHP 8 通常引入了一种统一和一致的方式来使用这些操作符。在本节中，我们将讨论以下操作符：

+   variadics 操作符

+   Nullsafe 操作符

+   连接操作符

+   三元操作符

让我们从讨论 variadics 操作符开始。

## 使用 variadics 操作符

**variadics**操作符由三个前导点（`...`）组成，位于普通 PHP 变量（或对象属性）之前。这个操作符实际上从 PHP 5.6 版本开始就存在了。它也被称为以下内容：

+   Splat 操作符

+   散列操作符

+   扩展操作符

在我们深入研究 PHP 8 使用这个操作符的改进之前，让我们快速看一下这个操作符通常的用法。

### 未知数量的参数

variadics 操作符最常见的用途之一是在定义具有未知数量参数的函数的情况下。

在以下代码示例中，`multiVardump()`函数能够接受任意数量的变量。然后连接`var_export()`的输出并返回一个字符串：

```php
// /repo/ch02/php7_variadic_params.php
function multiVardump(...$args) {
    $output = '';
    foreach ($args as $var)
        $output .= var_export($var, TRUE);
    return $output;
}
$a = new ArrayIterator(range('A','F'));
$b = function (string $val) { return str_rot13($val); };
$c = [1,2,3];
$d = 'TEST';
echo multiVardump($a, $b, $c);
echo multiVardump($d);
```

第一次调用函数时，我们提供了三个参数。第二次调用时，我们只提供了一个参数。由于我们使用了 variadics 操作符，所以无需重写函数来适应更多或更少的参数。

提示

有一个`func_get_args()` PHP 函数，可以将所有函数参数收集到一个数组中。但是，variadics 操作符更受青睐，因为它必须在函数签名中声明，从而使程序开发人员的意图更加清晰。更多信息，请参阅[`php.net/func_get_args`](https://php.net/func_get_args)。

### 吸入剩余参数

variadics 操作符的另一个用途是**吸入**任何剩余参数。这种技术允许您将强制参数与未知数量的可选参数混合使用。

在这个例子中，`where()`函数生成一个要添加到**结构化查询语言**（**SQL**）`SELECT`语句中的`WHERE`子句。前两个参数是必需的：没有理由生成没有参数的`WHERE`子句！看一下这里的代码：

```php
// ch02/includes/php7_sql_lib.php
// other functions not shown
function where(stdClass $obj, $a, $b = '', $c = '', 
        $d = '') {
    $obj->where[] = $a;
    $obj->where[] = $b;
    $obj->where[] = $c;
    $obj->where[] = $d;
}
```

使用此函数的调用代码可能如下所示：

```php
// /repo/ch02/php7_variadics_sql.php
require_once __DIR__ . '/includes/php7_sql_lib.php';
$start = '2021-01-01';
$end   = '2021-04-01';
$select = new stdClass();
from($select, 'events');
cols($select, ['id', 'event_key', 
    'event_name', 'event_date']);
limit($select, 10);
where($select, 'event_date', '>=', "'$start'");
where($select, 'AND');
where($select, 'event_date', '<', "'$end'");
$sql = render($select);
// remaining code not shown
```

您可能已经注意到，由于参数数量有限，必须多次调用`where()`。这是可变参数运算符的一个完美应用场景！以下是重写的`where()`函数可能会看起来：

```php
// ch02/includes/php8_sql_lib.php
// other functions not shown
function where(stdClass $obj, ...$args) {
    $obj->where = (empty($obj->where))
                ? $args
                : array_merge($obj->where, $args);
}
```

因为`...$args`始终作为数组返回，为了确保对函数的任何额外调用不会丢失子句，我们需要执行一个`array_merge()`操作。以下是重写的调用程序：

```php
// /repo/ch02/php8_variadics_sql.php
require_once __DIR__ . '/includes/sql_lib2.php';
$start = '2021-01-01';
$end   = '2021-04-01';
$select = new stdClass();
from($select, 'events');
cols($select, ['id', 'event_key', 
    'event_name', 'event_date']);
limit($select, 10);
where($select, 'event_date', '>=', "'$start'", 
    'AND', 'event_date', '<', "'$end'");
$sql = render($select);
// remaining code not shown
```

生成的 SQL 语句如下所示：

```php
SELECT id,event_key,event_name,event_date 
FROM events 
WHERE event_date >= '2021-01-01' 
    AND event_date <= '2021-04-01' 
LIMIT 10
```

前面的输出显示了我们的 SQL 生成逻辑生成了一个有效的语句。

### 使用可变参数运算符作为替代

到目前为止，对于有经验的 PHP 开发人员来说，这些都不是陌生的。在 PHP 8 中的不同之处在于，可变参数运算符现在可以在可能涉及*扩展*的情况下使用。

为了正确描述可变参数运算符的使用方式的不同之处，我们需要简要回顾一下**面向对象编程**（**OOP**）。如果我们将刚才描述的`where()`函数重写为类方法，它可能会像这样：

```php
// src/Php7/Sql/Where.php
namespace Php7\Sql;
class Where {
    public $where = [];
    public function where($a, $b = '', $c = '', $d = '') {
        $this->where[] = $a;
        $this->where[] = $b;
        $this->where[] = $c;
        $this->where[] = $d;
        return $this;
    }
    // other code not shown
}
```

现在，假设我们有一个`Select`类，它扩展了`Where`，但使用可变参数运算符重新定义了方法签名。它可能如下所示：

```php
// src/Php7/Sql/Select.php
namespace Php7\Sql;
class Select extends Where {
    public function where(...$args)    {
        $this->where = (empty($obj->where))
                    ? $args
                    : array_merge($obj->where, $args);
    }
    // other code not shown
}
```

使用可变参数运算符是合理的，因为提供给`WHERE`子句的参数数量是未知的。以下是使用面向对象编程重写的调用程序：

```php
// /repo/ch02/php7_variadics_problem.php
require_once __DIR__ . '/../src/Server/Autoload/Loader.php'
$loader = new \Server\Autoload\Loader();
use Php7\Sql\Select;
$start = "'2021-01-01'";
$end   = "'2021-04-01'";
$select = new Select();
$select->from($select, 'events')
       ->cols($select, ['id', 'event_key', 
              'event_name', 'event_date'])
       ->limit($select, 10)
       ->where($select, 'event_date', '>=', "'$start'",
               'AND', 'event_date', '<=', "'$end'");
$sql = $select->render();
// other code not shown
```

然而，当您尝试在 PHP 7 下运行此示例时，会出现以下警告：

```php
Warning: Declaration of Php7\Sql\Select::where(...$args) should be compatible with Php7\Sql\Where::where($a, $b = '', $c = '', $d = '') in /repo/src/Php7/Sql/Select.php on line 5 
```

请注意，代码仍然有效；但是，PHP 7 不认为可变参数运算符是一个可行的替代方案。以下是在 PHP 8 下运行相同代码的情况（使用`/repo/ch02/php8_variadics_no_problem.php`）：

![图 2.1-可接受扩展类中的可变参数运算符](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_2.1_B16992.jpg)

图 2.1-可接受扩展类中的可变参数运算符

提示

以下是两个 PHP 文档引用，解释了 PHP 可变参数运算符背后的原因：

[`wiki.php.net/rfc/variadics`](https://wiki.php.net/rfc/variadics)

[`wiki.php.net/rfc/argument_unpacking`](https://wiki.php.net/rfc/argument_unpacking)

现在让我们来看看 nullsafe 运算符。

## 使用 nullsafe 运算符

nullsafe 运算符用于对象属性引用链。如果链中的某个属性不存在（换句话说，它被视为`NULL`），该运算符会安全地返回一个`NULL`值，而不会发出警告。

举个例子，假设我们有以下**扩展标记语言**（**XML**）文件：

```php
<?xml version='1.0' standalone='yes'?>
<produce>
      <file>/repo/ch02/includes/produce.xml</file>
    <dept>
        <fruit>
            <apple>11</apple>
            <banana>22</banana>
            <cherry>33</cherry>
        </fruit>
        <vegetable>
            <artichoke>11</artichoke>
            <beans>22</beans>
            <cabbage>33</cabbage>
        </vegetable>
    </dept>
</produce>
```

以下是一个扫描 XML 文档并显示数量的代码片段：

```php
// /repo/ch02/php7_nullsafe_xml.php
$xml = simplexml_load_file(__DIR__ . 
        '/includes/produce.xml');
$produce = [
    'fruit' => ['apple','banana','cherry','pear'],
    'vegetable' => ['artichoke','beans','cabbage','squash']
];
$pattern = "%10s : %d\n";
foreach ($produce as $type => $items) {
    echo ucfirst($type) . ":\n";
    foreach ($items as $item) {
        $qty = getQuantity($xml, $type, $item);
        printf($pattern, $item, $qty);
    }
}
```

我们还需要定义一个`getQuantity()`函数，首先检查该属性是否不为空，然后再进行下一级的操作，如下所示：

```php
function getQuantity(SimpleXMLElement $xml, 
        string $type, string $item {
    $qty = 0;
    if (!empty($xml->dept)) {
        if (!empty($xml->dept->$type)) {
            if (!empty($xml->dept->$type->$item)) {
                $qty = $xml->dept->$type->$item;
            }
        }
    }
    return $qty;
}
```

当您开始处理更深层次的嵌套级别时，需要检查属性是否存在的函数变得更加复杂。这正是 nullsafe 运算符可以发挥作用的地方。

看一下相同的程序代码，但不需要`getQuantity()`函数，如下所示：

```php
// /repo/ch02/php8_nullsafe_xml.php
$xml = simplexml_load_file(__DIR__ . 
        '/includes/produce.xml'
$produce = [
    'fruit' => ['apple','banana','cherry','pear']
    'vegetable' => ['artichoke','beans','cabbage','squash']
];
$pattern = "%10s : %d\n";
foreach ($produce as $type => $items) {
    echo ucfirst($type) . ":\n";
    foreach ($items as $item) {
        printf($pattern, $item, 
            $xml?->dept?->$type?->$item);
    }
}
```

现在让我们来看看 nullsafe 运算符的另一个用途。

### 使用 nullsafe 运算符来短路链

nullsafe 运算符在连接的操作链中也很有用，包括对对象属性的引用、数组元素方法调用和静态引用。

举个例子，这里有一个配置文件，返回一个匿名类。它定义了根据文件类型提取数据的不同方法：

```php
// ch02/includes/nullsafe_config.php
return new class() {
    const HEADERS = ['Name','Amt','Age','ISO','Company'];
    const PATTERN = "%20s | %16s | %3s | %3s | %s\n";
    public function json($fn) {
        $json = file_get_contents($fn);
        return json_decode($json, TRUE);
    }
    public function csv($fn) {
        $arr = [];
        $fh = new SplFileObject($fn, 'r');
        while ($node = $fh->fgetcsv()) $arr[] = $node;
        return $arr;            
    }
    public function txt($fn) {
        $arr = [];
        $fh = new SplFileObject($fn, 'r');
        while ($node = $fh->fgets())
            $arr[] = explode("\t", $node);
        return $arr;
    }
    // all code not shown
};
```

该类还包括一个显示数据的方法，如下面的代码片段所示：

```php
    public function display(array $data) {
        $total  = 0;
        vprintf(self::PATTERN, self::HEADERS);
        foreach ($data as $row) {
            $total += $row[1];
            $row[1] = number_format($row[1], 0);
            $row[2] = (string) $row[2];
            vprintf(self::PATTERN, $row);
        }
        echo 'Combined Wealth: ' 
            . number_format($total, 0) . "\n"
    }    
```

在调用程序中，为了安全地执行 `display()` 方法，我们需要在执行回调之前添加一个 `is_object()` 的额外安全检查，以及 `method_exists()`，如下面的代码片段所示：

```php
// /repo/ch02/php7_nullsafe_short.php
$config  = include __DIR__ . 
        '/includes/nullsafe_config.php';
$allowed = ['csv' => 'csv','json' => 'json','txt'
                  => 'txt'];
$format  = $_GET['format'] ?? 'txt';
$ext     = $allowed[$format] ?? 'txt';
$fn      = __DIR__ . '/includes/nullsafe_data.' . $ext;
if (file_exists($fn)) {
    if (is_object($config)) {
        if (method_exists($config, 'display')) {
            if (method_exists($config, $ext)) {
                $config->display($config->$ext($fn));
            }
        }
    }
}
```

与前面的例子一样，空安全运算符可以用来确认 `$config` 是否为对象。通过简单地在第一个对象引用中使用空安全运算符，如果对象或方法不存在，运算符将 *短路* 整个链并返回 `NULL`。

以下是使用 PHP 8 空安全运算符重写的代码：

```php
// /repo/ch02/php8_nullsafe_short.php
$config  = include __DIR__ . 
        '/includes/nullsafe_config.php';
$allowed = ['csv' => 'csv','json' => 'json',
                     'txt' => 'txt'];
$format  = $_GET['format'] ?? $argv[1] ?? 'txt';
$ext     = $allowed[$format] ?? 'txt';
$fn      = __DIR__ . '/includes/nullsafe_data.' . $ext;
if (file_exists($fn)) {
    $config?->display($config->$ext($fn));
}
```

如果 `$config` 返回为 `NULL`，则整个操作链将被取消，不会生成任何警告或通知，并且返回值（如果有）为 `NULL`。最终结果是我们省去了编写三个额外的 `if()` 语句！

提示

有关使用此运算符时的其他注意事项，请查看这里：[`wiki.php.net/rfc/nullsafe_operator`](https://wiki.php.net/rfc/nullsafe_operator)。

重要提示

为了将格式参数传递给示例代码文件，您需要从浏览器中运行以下代码：`http://localhost:8888/ch02/php7_nullsafe_short.php?format=json`。

接下来，我们将看看连接运算符的更改。

## 连接运算符已经被降级

尽管 **连接** 运算符的精确用法（例如，句号（.）在 PHP 8 中没有改变，但在其 **优先级顺序** 中发生了极其重要的变化。在早期版本的 PHP 中，连接运算符在优先级方面被认为与较低级别的算术运算符加号（`+`）和减号（`-`）相等。接下来，让我们看看传统优先级顺序可能出现的问题：令人费解的结果。

### 处理令人费解的结果

不幸的是，这种安排会产生意想不到的结果。以下代码片段在使用 PHP 7 时执行时呈现出令人费解的输出：

```php
// /repo/ch02/php7_ops_concat_1.php
$a = 11;
$b = 22;
echo "Sum: " . $a + $b;
```

仅仅看代码，您可能期望输出类似于 `"Sum:33"`。但事实并非如此！在 PHP 7.1 上运行时，请查看以下输出：

```php
root@php8_tips_php7 [ /repo/ch02 ]# php php7_ops_concat_1.php
PHP Warning:  A non-numeric value encountered in /repo/ch02/php7_ops_concat_1.php on line 5
PHP Stack trace:
PHP   1\. {main}() /repo/ch02/php7_ops_concat_1.php:0
Warning: A non-numeric value encountered in /repo/ch02/php7_ops_concat_1.php on line 5
Call Stack:
  0.0001     345896   1\. {main}()
22
```

此时，您可能会想，*因为代码从不说谎*，那么 `11` + `22` 的和为 `22`，正如我们在前面的输出（最后一行）中看到的那样？

答案涉及优先级顺序：从 PHP 7 开始，它始终是从左到右。因此，如果我们使用括号来使操作顺序更清晰，实际发生的情况是这样的：

`echo ("Sum: " . $a) + $b;`

`11` 被连接到 `"Sum: "`，结果为 `"Sum: 11"`。作为字符串。然后将字符串转换为整数，得到 `0` + `22` 表达式，这给我们了结果。

如果您在 PHP 8 中运行相同的代码，请注意这里的区别：

```php
root@php8_tips_php8 [ /repo/ch02 ]# php php8_ops_concat_1.php 
Sum: 33
```

正如您所看到的，算术运算符优先于连接运算符。使用括号，这实际上是 PHP 8 中代码的处理方式：

`echo "Sum: " . ($a + $b);`

提示

**最佳实践**：使用括号来避免依赖优先级顺序而产生的复杂性。有关降低连接运算符优先级背后的原因的更多信息，请查看这里：[`wiki.php.net/rfc/concatenation_precedence`](https://wiki.php.net/rfc/concatenation_precedence)。

现在我们将注意力转向三元运算符。

## 使用嵌套的三元运算符

**三元运算符** 对于 PHP 语言来说并不新鲜。然而，在 PHP 8 中，它们的解释方式有一个重大的不同。这种变化与该运算符的传统 **左关联行为** 有关。为了说明这一点，让我们看一个简单的例子，如下所示：

1.  在这个例子中，假设我们正在使用 `RecursiveDirectoryIterator` 类与 `RecursiveIteratorIterator` 类结合扫描目录结构。起始代码可能如下所示：

```php
// /repo/ch02/php7_nested_ternary.php
$path = realpath(__DIR__ . '/..');
$searchPath = '/ch';
$searchExt  = 'php';
$dirIter    = new RecursiveDirectoryIterator($path);
$itIter     = new RecursiveIteratorIterator($dirIter);
```

1.  然后我们定义一个函数，匹配包含`$searchPath`搜索路径并以`$searchExt`扩展名结尾的文件，如下所示：

```php
function find_using_if($iter, $searchPath, $searchExt) {
    $matching  = [];
    $non_match = [];
    $discard   = [];
    foreach ($iter as $name => $obj) {
        if (!$obj->isFile()) {
            $discard[] = $name;
        } elseif (!strpos($name, $searchPath)) {
            $discard[] = $name;
        } elseif ($obj->getExtension() !== $searchExt) {
            $non_match[] = $name;
        } else {
            $matching[] = $name;
        }
    }
    show($matching, $non_match);
}
```

1.  然而，一些开发人员可能会诱惑重构此函数，而不是使用`if / elseif / else`，而是使用嵌套三元运算符。以下是在前一步骤中使用的相同代码可能的样子：

```php
function find_using_tern($iter, $searchPath, 
        $searchExt){
    $matching  = [];
    $non_match = [];
    $discard   = [];
    foreach ($iter as $name => $obj) {
        $match = !$obj->isFile()
            ? $discard[] = $name
            : !strpos($name, $searchPath)
                ? $discard[] = $name
                : $obj->getExtension() !== $searchExt
                    ? $non_match[] = $name
                    : $matching[] = $name;
    }
    show($matching, $non_match);
}
```

两个函数的输出在 PHP 7 中产生相同的结果，如下截图所示：

![图 2.2 - 使用 PHP 7 进行嵌套三元输出](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_2.2_B16992.jpg)

图 2.2 - 使用 PHP 7 进行嵌套三元输出

然而，在 PHP 8 中，不再允许使用没有括号的嵌套三元操作。运行相同代码块时的输出如下：

![图 2.3 - 使用 PHP 8 进行嵌套三元输出](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_2.3_B16992.jpg)

图 2.3 - 使用 PHP 8 进行嵌套三元输出

提示

**最佳实践**：使用括号避免嵌套三元操作的问题。有关三元运算符嵌套差异的更多信息，请参阅此文章：[`wiki.php.net/rfc/ternary_associativity`](https://wiki.php.net/rfc/ternary_associativity)。

您现在对新的 nullsafe 运算符有了一个概念。您还学习了三个现有运算符——可变参数、连接和三元运算符——它们的功能略有修改。您现在可以避免升级到 PHP 8 时可能出现的潜在危险。现在让我们来看看另一个新功能，*箭头函数*。

# 使用箭头函数

**箭头函数**实际上是在 PHP 7.4 中首次引入的。然而，由于许多开发人员并不关注每个发布更新，因此在本书中包含这一出色的新功能是很重要的。

在本节中，您将了解箭头函数及其语法，以及与匿名函数相比的优缺点。

## 通用语法

箭头函数是传统匿名函数的简写语法，就像三元运算符是`if(){} else{}`的简写语法一样。箭头函数的通用语法如下：

`fn(<ARGS>) => <EXPRESSION>`

`<ARGS>`是可选的，包括任何其他用户定义的 PHP 函数中看到的内容。`<EXPRESSION>`可以包括任何标准的 PHP 表达式，如函数调用、算术运算等。

现在让我们来看看箭头函数和匿名函数之间的区别。

## 箭头函数与匿名函数

在本小节中，您将学习**箭头函数**和**匿名函数**之间的区别。为了成为一个有效的 PHP 8 开发人员，了解箭头函数何时何地可能取代匿名函数并提高代码性能是很重要的。

在进入箭头函数之前，让我们看一个简单的匿名函数。在下面的示例中，分配给`$addOld`的匿名函数产生了两个参数的和：

```php
// /repo/ch02/php8_arrow_func_1.php
$addOld = function ($a, $b) { return $a + $b; };
```

在 PHP 8 中，您可以产生完全相同的结果，如下所示：

`$addNew = fn($a, $b) => $a + $b;`

尽管代码更易读，但这一新功能有其优点和缺点，总结如下表所示：

![表 2.1 - 匿名函数与箭头函数](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Table_2.1_B16992.jpg)

表 2.1 - 匿名函数与箭头函数

从上表中可以看出，箭头函数比匿名函数更高效。然而，缺乏间接性和不支持多行意味着您仍然需要偶尔使用匿名函数。

## 变量继承

匿名函数，就像任何标准的 PHP 函数一样，只有在将值作为参数传递、使用全局关键字或添加`use()`修饰符时，才能识别其范围外的变量。

以下是一个`DateTime`实例通过`use()`方式继承到匿名函数中的示例：

```php
// /repo/ch02/php8_arrow_func_2.php
// not all code shown
$old = function ($today) use ($format) {
    return $today->format($format);
};
```

这里使用箭头函数完全相同的东西：

`$new = fn($today) => $today->format($format);`

正如您所看到的，语法非常易读和简洁。现在让我们来看一个结合箭头函数的实际例子。

## 实际例子：使用箭头函数

回到生成难以阅读的 CAPTCHA 的想法（首次在*第一章*中介绍，*介绍新的 PHP 8 OOP 功能*），让我们看看如何结合箭头函数可能提高效率并减少所需的编码量。现在我们来看一个生成基于文本的 CAPTCHA 的脚本，如下所示：

1.  首先，我们定义一个生成由字母、数字和特殊字符随机选择组成的字符串的函数。请注意在以下代码片段中，使用了新的 PHP 8 `match`表达式结合箭头函数（高亮显示）：

```php
// /repo/ch02/php8_arrow_func_3.php
function genKey(int $size) {
    $alpha1  = range('A','Z');
    $alpha2  = range('a','z');
    $special = '!@#$%^&*()_+,./[]{}|=-';
    $len     = strlen($special) - 1;
    $numeric = range(0, 9);
    $text    = '';
    for ($x = 0; $x < $size; $x++) {
        $algo = rand(1,4);
        $func = match ($algo) {
            1 => fn() => $alpha1[array_rand($alpha1)],
            2 => fn() => $alpha2[array_rand($alpha2)]
            3 => fn() => $special[rand(0,$len)],
            4 => fn() => 
                       $numeric[array_rand($numeric)],
            default => fn() => ' '
        };
        $text .= $func();            
    }
    return $text;
}
```

1.  然后，我们定义一个`textCaptcha()`函数来生成文本 CAPTCHA。我们首先定义代表算法和颜色的两个数组。然后对它们进行*洗牌*以进一步随机化。我们还定义**超文本标记语言**（**HTML**）`<span>`元素来产生大写和小写字符，如下面的代码片段所示：

```php
function textCaptcha(string $text) {
    $algos = ['upper','lower','bold',
              'italics','large','small'];
    $color = ['#EAA8A8','#B0F6B0','#F5F596',
              '#E5E5E5','white','white'];
    $lgSpan = '<span style="font-size:32pt;">';
    $smSpan = '<span style="font-size:8pt;">';
    shuffle($algos);
    shuffle($color);
```

1.  接下来，我们定义一系列`InfiniteIterator`实例。这是一个有用的**标准 PHP 库**（**SPL**）类，允许您继续调用`next()`，而无需检查您是否已经到达迭代的末尾。这个迭代器类的作用是自动将指针移回数组的顶部，允许您无限迭代。代码可以在以下片段中看到：

```php
    $bkgTmp = new ArrayIterator($color);
    $bkgIter = new InfiniteIterator($bkgTmp);
    $algoTmp = new ArrayIterator($algos);
    $algoIter = new InfiniteIterator($algoTmp);
    $len = strlen($text);
```

1.  然后，我们逐个字符构建文本 CAPTCHA，应用适当的算法和背景颜色，如下所示：

```php
    $captcha = '';
    for ($x = 0; $x < $len; $x++) {
        $char = $text[$x];
        $bkg  = $bkgIter->current();
        $algo = $algoIter->current();
        $func = match ($algo) {
            'upper'   => fn() => strtoupper($char),
            'lower'   => fn() => strtolower($char),
            'bold'    => fn() => "<b>$char</b>",
            'italics' => fn() => "<i>$char</i>",
            'large'   => fn() => $lgSpan 
                         . $char . '</span>',
            'small'   => fn() => $smSpan 
                         . $char . '</span>',
            default   => fn() => $char
        };
        $captcha .= '<span style="background-color:' 
            . $bkg . ';">' 
            . $func() . '</span>';
        $algoIter->next();
        $bkgIter->next();
    }
    return $captcha;
}
```

再次注意混合使用`match`和`arrow`函数以实现期望的结果。

脚本的其余部分只是调用这两个函数，如下所示：

```php
$text = genKey(8);
echo "Original: $text<br />\n";
echo 'Captcha : ' . textCaptcha($text) . "\n";
```

以下是从浏览器中`/repo/ch02/php8_arrow_func_3.php`输出的样子：

![图 2.4 - 来自 php8_arrow_func_3.php 的输出](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_2.4_B16992.jpg)

图 2.4 - 来自 php8_arrow_func_3.php 的输出

提示

有关箭头函数的更多背景信息，请查看这里：[`wiki.php.net/rfc/arrow_functions_v2`](https://wiki.php.net/rfc/arrow_functions_v2)。

有关`InfiniteIterator`的信息，请查看 PHP 文档：[`www.php.net/InfiniteIterator`](https://www.php.net/InfiniteIterator)。

现在让我们来看一下*统一变量语法*。

# 理解统一变量语法

PHP 7.0 中引入的最激进的举措之一是努力规范化 PHP 语法。早期版本的 PHP 存在的问题是，在某些情况下，操作是从左到右解析的，而在其他情况下是从右到左解析的。这种不一致性是许多编程漏洞和困难的根本原因。因此，PHP 核心开发团队发起了一项名为**统一变量语法**的举措。但首先，让我们定义形成统一变量语法举措的关键要点。

## 定义统一变量语法

统一变量语法既不是协议也不是正式的语言构造。相反，它是一个指导原则，旨在确保所有操作以统一和一致的方式执行。

以下是这项举措的一些关键要点：

+   变量的顺序和引用的统一性

+   函数调用的统一性

+   解决数组解引用问题

+   提供在单个命令中混合函数调用和数组解引用的能力

提示

有关 PHP 7 统一变量语法的原始提案的更多信息，请查看这里：[`wiki.php.net/rfc/uniform_variable_syntax`](https://wiki.php.net/rfc/uniform_variable_syntax)。

现在让我们来看一下统一变量语法举措如何影响 PHP 8。

## 统一变量语法如何影响 PHP 8？

统一变量语法倡议在所有 PHP 7 的版本中都取得了极大的成功，过渡相对顺利。然而，有一些领域没有升级到这个标准。因此，提出了一个新的提案来解决这些问题。在 PHP 8 中，以下内容已经实现了统一性：

+   解引用插入字符串

+   魔术常量的不一致解引用

+   类常量解引用的一致性

+   增强了`new`和`instanceof`的表达式支持

在进入每个这些领域的示例之前，我们必须首先定义*解引用*的含义。

### 定义解引用

**解引用**是提取数组元素或对象属性的值的过程。它还指获取对象方法或函数调用的返回值的过程。这里有一个简单的例子：

```php
// /repo/ch02/php7_dereference_1.php
$alpha = range('A','Z');
echo $alpha[15] . $alpha[7] . $alpha[15];
// output: PHP
```

`$alpha`包含 26 个元素，代表字母`A`到`Z`。这个例子解引用了数组，提取了第 7 和第 15 个元素，产生了`PHP`的输出。解引用函数或方法调用简单地意味着执行函数或方法并访问结果。

### 解引用插入字符串

下一个例子有点疯狂，请仔细跟随。以下示例在 PHP 8 中有效，但在 PHP 7 或之前的版本中无效：

```php
// /repo/ch02/php8_dereference_2.php
$alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
$num   = '0123456789';
$test  = [15, 7, 15, 34];
foreach ($test as $pos)
    echo "$alpha$num"[$pos];
```

在这个例子中，两个字符串`$alpha`和`$num`在`foreach()`循环内使用双引号进行插值。以下是 PHP 7 的输出：

```php
root@php8_tips_php7 [ /repo/ch02 ]# php php7_dereference_2.php 
PHP Parse error:  syntax error, unexpected '[', expecting ',' or ';' in /repo/ch02/php7_dereference_2.php on line 7
Parse error: syntax error, unexpected '[', expecting ',' or ';' in /repo/ch02/php7_dereference_2.php on line 7
```

在 PHP 8 中相同的代码产生以下输出：

```php
root@php8_tips_php8 [ /repo/ch02 ]# php php8_dereference_2.php 
PHP8
```

结论是，PHP 7 在解引用插入字符串方面不一致，而 PHP 8 展现了改进的一致性。

### 魔术常量的不一致解引用

在 PHP 7 和之前的版本中，常量可以被解引用，而魔术常量则不行。下面是一个简单的例子，它产生了当前文件的最后三个字母：

```php
// /repo/ch02/php8_dereference_3.php
define('FILENAME', __FILE__);
echo FILENAME[-3] . FILENAME[-2] . FILENAME[-1];
echo __FILE__[-3] . __FILE__[-2] . __FILE__[-1];
```

以下是 PHP 7 的结果：

```php
root@php8_tips_php7 [ /repo/ch02 ]# php php7_dereference_3.php
PHP Parse error:  syntax error, unexpected '[', expecting ',' or ';' in /repo/ch02/php7_dereference_3.php on line 7
Parse error: syntax error, unexpected '[', expecting ',' or ';' in /repo/ch02/php7_dereference_3.php on line 7
```

以下是 PHP 8 的结果：

```php
root@php8_tips_php8 [ /repo/ch02 ]# php php8_dereference_3.php
phpphp
```

再次强调的是，PHP 8 中的解引用操作是一致的（这是一件好事！）。

### 类常量解引用的一致性

当尝试解引用类常量时会出现相关问题。为了最好地说明问题，想象一下我们有三个类。第一个类`JsonResponse`以**JavaScript 对象表示法**（**JSON**）格式产生数据，如下面的代码片段所示：

```php
class JsonResponse {
    public static function render($data) {
        return json_encode($data, JSON_PRETTY_PRINT);
    }
}
```

第二个类`SerialResponse`使用内置的 PHP `serialize()`函数产生响应，如下面的代码片段所示：

```php
class SerialResponse {
    public static function render($data) {
        return serialize($data);
    }
}
```

最后，一个`Test`类能够产生任何一个响应，如下面的代码片段所示：

```php
class Test {
    const JSON = ['JsonResponse'];
    const TEXT = 'SerialResponse';
    public static function getJson($data) {
        echo self::JSON[0]::render($data);
    }
    public static function getText($data) {
        echo self::TEXT::render($data);
    }
}
```

正如你在本节的早期示例中所看到的，PHP 早期版本的结果是不一致的。调用`Test::getJson($data)`可以正常工作。然而，调用`Test::getText($data)`会产生错误：

```php
root@php8_tips_php7 [ /repo/ch02 ]# php php7_dereference_4.php PHP Parse error:  syntax error, unexpected '::' (T_PAAMAYIM_NEKUDOTAYIM), expecting ',' or ';' in /repo/ch02/php7_dereference_4.php on line 26
Parse error: syntax error, unexpected '::' (T_PAAMAYIM_NEKUDOTAYIM), expecting ',' or ';' in /repo/ch02/php7_dereference_4.php on line 26
```

在 PHP 8 下，与之前显示的类中定义的方法调用产生了一致的结果，如下所示：

```php
root@php8_tips_php8 [ /repo/ch02 ]# php php8_dereference_4.php
{
    "A": 111,
    "B": 222,
    "C": 333}
a:3:{s:1:"A";i:111;s:1:"B";i:222;s:1:"C";i:333;}
```

总之，在 PHP 8 中，类常量现在以统一的方式进行解引用，使您能够产生更清晰的代码。现在，让我们看看 PHP 8 如何允许您在更多地方使用表达式。

### 增强了`new`和`instanceof`的表达式支持

与 PHP 7 编程相关的乐趣之一是能够在几乎任何地方使用任意 PHP 表达式。在这个简单的例子中，注意在引用`$nav`数组的方括号内使用了一个`$_GET['page'] ?? 'home'`任意表达式：

```php
// /repo/ch02/php7_arbitrary_exp.php
$nav = [
    'home'     => 'home.html',
    'about'    => 'about.html',
    'services' => 'services/index.html',
    'support'  => 'support/index.html',
];
$html = __DIR__ . '/../includes/'
      . $nav[$_GET['page'] ?? 'home'];
```

在 PHP 7 和之前的版本中，如果表达式涉及`new`或`instanceof`关键字，则不可能做到这一点。正如你可能已经猜到的那样，这种不一致性已经在 PHP 8 中得到解决。现在可以实现以下操作：

```php
// /repo/ch02/php8_arbitrary_exp_new.php
// definition of the JsonRespone and SerialResponse
// classes are shown above
$allowed = [
    'json' => 'JsonResponse',
    'text' => 'SerialResponse'
];
$data = ['A' => 111, 'B' => 222, 'C' => 333];
echo (new $allowed[$_GET['type'] ?? 'json'])
        ->render($data);
```

这个代码示例展示了在数组引用内使用任意表达式，与`new`关键字一起使用。

提示

有关 PHP 8 中统一变量语法更新的更多信息，请参阅此文章：[`wiki.php.net/rfc/variable_syntax_tweaks`](https://wiki.php.net/rfc/variable_syntax_tweaks)。

现在让我们来看看 PHP 8 中可用的新的字符串和数组处理技术。

# 学习新的数组和字符串处理技术

PHP 8 中的数组和字符串处理技术有许多改进。虽然本书中没有足够的空间来涵盖每一个增强功能，但我们将在本节中检查更重要的改进。

## 使用 `array_splice()`

`array_splice()` 函数是 `substr()` 和 `str_replace()` 的混合体：它允许您用另一个数组替换一个数组的子集。然而，当您只需要用不同的内容替换数组的最后部分时，它的使用会变得麻烦。快速查看语法会让人觉得开始变得不方便——`replacement` 参数在 `length` 参数之前，如下所示：

`array_splice(&$input,$offset[,$length[,$replacement]]):array`

传统上，开发人员首先在原始数组上运行 `count()`，然后将其用作 `length` 参数，如下所示：

`array_splice($arr, 3, count($arr), $repl);`

在 PHP 8 中，第三个参数可以是 `NULL`，省去了对 `count()` 的额外调用。如果您利用 PHP 8 的**命名参数**特性，代码会变得更加简洁。下面是为 PHP 8 编写的相同代码片段：

`array_splice($arr, 3, replacement: $repl);`

这里有另一个例子清楚地展示了 PHP 7 和 PHP 8 之间的差异：

```php
// /repo/ch02/php7_array_splice.php
$arr  = ['Person', 'Camera', 'TV', 'Woman', 'Man'];
$repl = ['Female', 'Male'];
$tmp  = $arr;
$out  = array_splice($arr, 3, count($arr), $repl);
var_dump($arr);
$arr  = $tmp;
$out  = array_splice($arr, 3, NULL, $repl);
var_dump($arr);
```

如果您在 PHP 7 中运行代码，请注意最后一个 `var_dump()` 实例的结果，如下所示：

```php
repo/ch02/php7_array_splice.php:11:
array(7) {
  [0] =>  string(6) "Person"
  [1] =>  string(6) "Camera"
  [2] =>  string(2) "TV"
  [3] =>  string(6) "Female"
  [4] =>  string(4) "Male"
  [5] =>  string(5) "Woman"
  [6] =>  string(3) "Man"
}
```

在 PHP 7 中，将 `NULL` 值提供给 `array_splice()` 的第三个参数会导致两个数组简单合并，这不是期望的结果！

现在，让我们来看一下最后一个 `var_dump()` 的输出，但这次是在 PHP 8 下运行的：

```php
root@php8_tips_php8 [ /repo/ch02 ]# php php8_array_splice.php
// some output omitted
array(5) {
  [0]=>  string(6) "Person"
  [1]=>  string(6) "Camera"
  [2]=>  string(2) "TV"
  [3]=>  string(6) "Female"
  [4]=>  string(4) "Male"
}
```

如您所见，在 PHP 8 下，将第三个参数设为 `NULL` 与在运行时将数组 `count()` 作为第三个参数提供给 `array_splice()` 具有相同的功能。您还会注意到在 PHP 8 中，数组元素的总数为 `5`，而在 PHP 7 中，相同代码的运行结果为 `7`。

## 使用 `array_slice()`

`array_slice()` 函数在数组上的操作与 `substr()` 在字符串上的操作一样。PHP 早期版本的一个大问题是，在内部，PHP 引擎会顺序地遍历整个数组，直到达到所需的偏移量。如果偏移量很大，性能会直接与数组大小成正比地受到影响。

在 PHP 8 中，使用了一种不需要顺序数组迭代的不同算法。随着数组大小的增加，性能改进变得越来越明显。

1.  在这个示例中，我们首先构建了一个大约有 600 万条目的大数组：

```php
// /repo/ch02/php8_array_slice.php
ini_set('memory_limit', '1G');
$start = microtime(TRUE);
$arr   = [];
$alpha = range('A', 'Z');
$beta  = $alpha;
$loops = 10000;     // size of outer array
$iters = 500;       // total iterations
$drip  = 10;        // output every $drip times
$cols  = 4;
for ($x = 0; $x < $loops; $x++)
    foreach ($alpha as $left)
        foreach ($beta as $right)
            $arr[] = $left . $right . rand(111,999);
```

1.  接下来，我们遍历数组，取大于 `999,999` 的随机偏移量。这会迫使 `array_slice()` 艰苦工作，并显示出 PHP 7 和 8 之间的显著性能差异，如下面的代码片段所示：

```php
$max = count($arr);
for ($x = 0; $x < $iters; $x++ ) {
    $offset = rand(999999, $max);
    $slice  = array_slice($arr, $offset, 4);
    // not all display logic is shown
}
$time = (microtime(TRUE) - $start);
echo "\nElapsed Time: $time seconds\n";
```

在 PHP 7 下运行代码时的输出如下：

![图 2.5 – 使用 PHP 7 的 array_slice() 示例](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_2.5_B16992.jpg)

图 2.5 – 使用 PHP 7 的 array_slice() 示例

请注意，在 PHP 8 下运行相同代码时的显著性能差异：

![图 2.6 – 使用 PHP 8 的 array_slice() 示例](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_2.6_B16992.jpg)

图 2.6 – 使用 PHP 8 的 array_slice() 示例

重要提示

新算法只在数组不包含 `NULL` 值的情况下有效。如果数组包含 `NULL` 元素，则会触发旧算法，并进行顺序迭代。

现在让我们转向一些出色的新字符串函数。 

## 检测字符串的开头、中间和结尾

PHP 开发人员经常需要处理的一个问题是检查字符串的开头、中间或结尾是否出现一组字符。当前一组字符串函数的问题在于它们*不是设计*来处理子字符串的存在或不存在。相反，当前一组函数是设计来确定子字符串的*位置*。然后，可以以布尔方式插值来确定子字符串的存在或不存在。

这种方法的问题可以用温斯顿·丘吉尔爵士的一句著名的引语来概括： 

“高尔夫是一个旨在用极不适合这一目的的武器将一个非常小的球打入一个更小的洞的游戏。”

– *温斯顿·丘吉尔*

现在让我们来看看三个非常有用的新字符串函数，它们解决了这个问题。

### str_starts_with()

我们要检查的第一个函数是`str_starts_with()`。为了说明它的用法，考虑一个代码示例，我们要在开头找到`https`，在结尾找到`login`，如下面的代码片段所示：

```php
// /repo/ch02/php7_starts_ends_with.php
$start = 'https';
if (substr($url, 0, strlen($start)) !== $start) 
    $msg .= "URL does not start with $start\n";
// not all code is shown
```

正如我们在本节的介绍中提到的，为了确定一个字符串是否以`https`开头，我们需要调用`substr()`和`strlen()`。这两个函数都不是设计来给我们想要的答案的。而且，使用这两个函数会在我们的代码中引入低效，并导致不必要的资源利用增加。

相同的代码可以在 PHP 8 中编写如下：

```php
// /repo/ch02/php8_starts_ends_with.php
$start = 'https';
if (!str_starts_with($url, $start))
    $msg .= "URL does not start with $start\n";
// not all code is shown
```

### str_ends_with()

与`str_starts_with()`类似，PHP 8 引入了一个新函数`str_ends_with()`，用于确定字符串的结尾是否与某个值匹配。为了说明这个新函数的用处，考虑使用`strrev()`和`strpos()`的旧 PHP 代码，可能如下所示：

```php
$end = 'login';
if (strpos(strrev($url), strrev($end)) !== 0)
    $msg .= "URL does not end with $end\n";
```

在一个操作中，`$url`和`$end`都需要被反转，这个过程会随着字符串长度的增加而变得越来越昂贵。而且，正如前面提到的，`strpos()`的目的是返回子字符串的*位置*，而不是确定其存在与否。

在 PHP 8 中，可以通过以下方式实现相同的功能：

```php
if (!str_ends_with($url, $end))
    $msg .= "URL does not end with $end\n";
```

### str_contains()

在这个上下文中的最后一个函数是`str_contains()`。正如我们讨论过的，在 PHP 7 及更早版本中，除了`preg_match()`之外，没有特定的 PHP 函数告诉你一个子字符串是否存在于一个字符串中。

使用`preg_match()`的问题，正如我们一再被警告的那样，是性能下降。为了处理*正则表达式*，`preg_match()`首先需要分析模式。然后，它必须执行第二次扫描，以确定字符串的哪个部分与模式匹配。这在时间和资源利用方面是一个极其昂贵的操作。

重要提示

当我们提到一个操作在时间和资源方面是*昂贵*时，请记住，如果您的脚本只包含几十行代码和/或您在循环中没有重复操作数千次，那么使用本节中描述的新函数和技术可能不会带来显著的性能提升。

在下面的例子中，一个 PHP 脚本使用`preg_match()`来搜索*GeoNames*项目数据库中人口超过`15,000`的城市，以查找包含对`London`的引用的任何列表：

```php
// /repo/ch02/php7_str_contains.php
$start    = microtime(TRUE);
$target   = '/ London /';
$data_src = __DIR__ . '/../sample_data
                      /cities15000_min.txt';
$fileObj  = new SplFileObject($data_src, 'r');
while ($line = $fileObj->fgetcsv("\t")) {
    $tz     = $line[17] ?? '';
    if ($tz) unset($line[17]);
    $str    = implode(' ', $line);
    $city   = $line[1] ?? 'Unknown';
    $local1 = $line[10] ?? 'Unknown';
    $iso    = $line[8] ?? '??';
    if (preg_match($target, $str))
        printf("%25s : %12s : %4s\n", $city, $local1, 
                $iso);
}
echo "Elapsed Time: " . (microtime(TRUE) - $start) . "\n";
```

在 PHP 7 中运行时的输出如下：

![图 2.7 - 使用 preg_match()扫描 GeoNames 文件](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_2.7_B16992.jpg)

图 2.7 - 使用 preg_match()扫描 GeoNames 文件

在 PHP 8 中，可以通过用以下代码替换`if`语句来实现相同的输出：

```php
// /repo/ch02/php8_str_contains.php
// not all code is shown
    if (str_contains($str, $target))
        printf("%25s : %12s : %4s\n", $city, $local1, 
               $iso);
```

以下是来自 PHP 8 的输出：

![图 2.8 - 使用 str_contains()扫描 GeoNames 文件](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_2.8_B16992.jpg)

图 2.8 - 使用 str_contains()扫描 GeoNames 文件

从两个不同的输出屏幕可以看出，PHP 8 代码运行大约需要`0.14`微秒，而 PHP 7 需要`0.19`微秒。这本身并不是一个巨大的性能提升，但正如本节前面提到的，更多的数据、更长的字符串和更多的迭代会放大你所获得的任何小的性能提升。

提示

**最佳实践**：实现小的代码修改可以带来小的性能提升，最终积少成多，带来整体性能的大幅提升！

有关*GeoNames*开源项目的更多信息，请访问他们的网站：[`www.geonames.org/`](https://www.geonames.org/)。

现在你知道了如何以及在哪里使用三个新的字符串函数。你还可以编写更高效的代码，使用专门设计用于检测目标字符串开头、中间或结尾的子字符串存在与否的函数。

最后，我们以查看新的 SQLite3 授权回调结束本章。

# 使用授权回调保护 SQLite 数据库

许多 PHP 开发人员更喜欢使用**SQLite**作为他们的数据库引擎，而不是像 PostgreSQL、MySQL、Oracle 或 MongoDB 这样的独立数据库服务器。使用 SQLite 的原因有很多，但通常归结为以下几点：

+   **SQLite 是基于文件的数据库**：你不需要安装单独的数据库服务器。

+   **易于分发**：唯一的要求是目标服务器需要安装`SQLite`可执行文件。

+   **SQLite 轻量级**：由于没有不断运行的服务器，所需资源更少。

尽管如此，缺点是它的可扩展性不是很好。如果你有相当大量的数据要处理，最好安装一个更强大的数据库服务器。另一个潜在的主要缺点是 SQLite 没有安全性，下一小节将介绍。

提示

有关 SQLite 的更多信息，请访问他们的主要网页：[`sqlite.org/index.html`](https://sqlite.org/index.html)。

## 等等...没有安全性？

是的，你听对了：默认情况下，按照其设计，SQLite 没有安全性。当然，这就是许多开发人员喜欢使用它的原因：没有安全性使得它非常容易使用！

以下是一个连接到 SQLite 数据库并对`geonames`表进行简单查询的示例代码块。它返回了印度人口超过 200 万的城市列表：

```php
// /repo/ch02/php8_sqlite_query.php
define('DB_FILE', __DIR__ . '/tmp/sqlite.db');
$sqlite = new SQLite3(DB_FILE);
$sql = 'SELECT * FROM geonames '
      . 'WHERE country_code = :cc AND population > :pop';
$stmt = $sqlite->prepare($sql);
$stmt->bindValue(':cc', 'IN');
$stmt->bindValue(':pop', 2000000);
$result = $stmt->execute();
while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
    printf("%20s : %2s : %16s\n", 
        $row['name'], $row['country_code'],
        number_format($row['population']));
}  // not all code is shown
```

大多数其他数据库扩展在建立连接时至少需要用户名和密码。如前面的代码片段所示，`$sqlite`实例是完全没有安全性的：没有用户名或密码。

## 什么是 SQLite 授权回调？

SQLite3 引擎现在允许你向 SQLite 数据库连接注册一个**授权回调**。当向数据库发送**预编译语句**进行编译时，将调用回调例程。以下是在`SQLite3`实例上设置授权回调的通用语法：

`$sqlite3->setAuthorizer(callable $callback);`

回调函数应该返回三个`SQLite3`类常量中的一个，每个代表一个整数值。如果回调函数返回除这三个值之外的任何值，就假定为`SQLite3::DENY`，操作将不会继续进行。下表列出了三个期望的返回值：

![表 2.2 - 有效的 SQLite 授权回调返回值](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Table_2.2_B16992.jpg)

表 2.2 - 有效的 SQLite 授权回调返回值

现在你对回调有了一些了解，让我们看看它是如何被调用的。

## 回调函数会接收到什么？

当您执行`$sqlite->prepare($sql)`时，回调被调用。在那时，SQLite3 引擎将在回调中传递一个到五个参数。第一个参数是一个**操作代码**，确定剩余参数的性质。因此，以下可能是您最终定义的回调的适当通用函数签名：

```php
function NAME (int $actionCode, ...$params) 
{ /* callback code */ };
```

大部分情况下，操作代码与要准备的 SQL 语句相对应。以下表总结了一些更常见的操作代码：

![表 2.3 – 发送到回调的常见操作代码](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Table_2.3_B16992.jpg)

表 2.3 – 发送到回调的常见操作代码

现在是时候看一个使用示例了。

## 授权使用示例

在下面的示例中，我们被允许从 SQLite `geonames`表中读取，但不能插入、删除或更新：

1.  我们首先在`/repo/ch02/includes/`目录中定义一个`auth_callback.php`包含文件。在`include`文件中，我们首先定义在回调中使用的常量，如下面的代码片段所示：

```php
// /repo/ch02/includes/auth_callback.php
define('DB_FILE', '/tmp/sqlite.db');
define('PATTERN', '%-8s | %4s | %-28s | %-15s');
define('DEFAULT_TABLE', 'Unknown');
define('DEFAULT_USER', 'guest');
define('ACL' , [
    'admin' => [
        'users' => [SQLite3::READ, SQLite3::SELECT,
            SQLite3::INSERT, SQLite3::UPDATE,
            SQLite3::DELETE],
        'geonames' => [SQLite3::READ, SQLite3::SELECT,
            SQLite3::INSERT, SQLite3::UPDATE, 
            SQLite3::DELETE],
    ],
    'guest' => [
        'geonames' => [SQLite3::READ, 
                       SQLite3::SELECT],
    ],
]);
```

**访问控制列表**（**ACL**）的工作方式是，主要外键是用户（例如`admin`或`guest`）；次要键是表（例如`users`或`geonames`）；值是允许该用户和表的`SQLite3`操作代码的数组。

在先前显示的示例中，`admin`用户对两个表都有所有权限，而`guest`用户只能从`geonames`表中读取。

1.  接下来，我们定义实际的授权回调函数。函数中我们需要做的第一件事是将默认返回值设置为`SQLite3::DENY`。我们还检查操作代码是否为`SQLite3::SELECT`，如果是，则简单地返回`OK`。当首次处理`SELECT`语句并且不提供有关表或列的任何信息时，将发出此操作代码。代码可以在以下片段中看到：

```php
function auth_callback(int $code, ...$args) {
    $status = SQLite3::DENY;
    $table  = DEFAULT_TABLE;
    if ($code === SQLite3::SELECT) {
        $status = SQLite3::OK;
```

1.  如果操作代码不是`SQLite3::SELECT`，我们需要首先确定涉及哪个表，然后才能决定允许还是拒绝该操作。表名作为提供给我们回调的第二个参数报告。

1.  现在是使用*variadics operator*的绝佳时机，因为我们不确定可能传递多少参数。但是，对于关注的主要操作（例如`INSERT`、`UPDATE`或`DELETE`），放入`$args`的第一个位置的是表名。否则，我们从会话中获取表名。

代码显示在以下片段中：

```php
    } else {
        if (!empty($args[0])) {
            $table = $args[0];
        } elseif (!empty($_SESSION['table'])) {
            $table = $_SESSION['table'];
        }
```

1.  同样地，我们从会话中检索用户名，如下所示：

```php
        $user  = $_SESSION['user'] ?? DEFAULT_USER;
```

1.  接下来，我们检查用户是否在 ACL 中定义，然后检查表是否为该用户分配了权限。如果给定的操作代码在与用户和表组合关联的数组中，返回`SQLite3::OK`。

代码显示在以下片段中：

```php
    if (!empty(ACL[$user])) {
        if (!empty(ACL[$user][$table])) {
            if (in_array($code, ACL[$user][$table])) {
                $status = SQLite3::OK;
            }
        }
    }
```

1.  然后我们将表名存储在会话中并返回状态代码，如下面的代码片段所示：

```php
  } // end of "if ($code === SQLite3::SELECT)"
  $_SESSION['table'] = $table;
  return $status;
} // end of function definition
```

现在我们转向调用程序。

1.  在包含定义授权回调的 PHP 文件之后，我们通过接受命令行参数、**统一资源定位符**（**URL**）参数或简单地分配`admin`来模拟获取用户名，如下面的代码片段所示：

```php
// /repo/ch02/php8_sqlite_auth_admin.php
include __DIR__ . '/includes/auth_callback.php';
// Here we simulate the user acquisition:
session_start();
$_SESSION['user'] = 
    $argv[1] ?? $_GET['usr'] ?? DEFAULT_USER;
```

1.  接下来，我们创建两个数组并使用`shuffle()`使它们的顺序随机。我们从随机数组中构建用户名、电子邮件和 ID 值，如下面的代码片段所示：

```php
$name = ['jclayton','mpaulovich','nrousseau',
         'jporter'];
$email = ['unlikelysource.com',
          'lfphpcloud.net','phptraining.net'];
shuffle($name);
shuffle($email);
$user_name = $name[0];
$user_email = $name[0] . '@' . $email[0];
$id = md5($user_email . rand(0,999999));
```

1.  然后，我们创建`SQLite3`实例并分配授权回调，如下所示：

```php
$sqlite = new SQLite3(DB_FILE);
$sqlite->setAuthorizer('auth_callback');
```

1.  现在 SQL `INSERT`语句已经定义并发送到 SQLite 进行准备。请注意，这是调用授权回调的时候。

代码显示在以下片段中：

```php
$sql = 'INSERT INTO users '
     . 'VALUES (:id, :name, :email, :pwd);';
$stmt = $sqlite->prepare($sql);
```

1.  如果授权回调拒绝操作，则语句对象为`NULL`，因此最好使用`if()`语句来测试其存在。如果是这样，我们然后继续绑定值并执行语句，如下面的代码片段所示：

```php
if ($stmt) {
    $stmt->bindValue(':id', $id);
    $stmt->bindValue(':name', $user_name);
    $stmt->bindValue(':email', $user_email);
    $stmt->bindValue(':pwd', 'password');
    $result = $stmt->execute();
```

1.  为了确认结果，我们定义了一个 SQL `SELECT`语句，以显示`users`表的内容，如下所示：

```php
    $sql = 'SELECT * FROM users';
    $result = $sqlite->query($sql);
    while ($row = $result->fetchArray(SQLITE3_ASSOC))
        printf("%-10s : %-  10s\n",
            $row['user_name'], $row['user_email']);
}
```

重要提示

这里没有显示所有代码。有关完整代码，请参考`/repo/ch02/php8_sqlite_auth_admin.php`。

如果我们运行调用程序，并将用户设置为`admin`，则结果如下：

![图 2.9 – SQLite3 授权回调：admin 用户](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_2.9_B16992.jpg)

图 2.9 – SQLite3 授权回调：admin 用户

前面截图的输出显示，由于我们以`admin`用户身份运行，并具有足够的授权权限，操作成功。当用户设置为`guest`时，输出如下：

![图 2.10 – SQLite3 授权回调：guest 用户](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_2.10_B16992.jpg)

图 2.10 – SQLite3 授权回调：guest 用户

输出显示，由于我们以权限不足的用户身份运行，尝试运行`prepare()`是不成功的。

这就结束了我们对这一期待已久的功能的讨论。您现在知道如何向一个否则不安全的数据库技术添加授权。

提示

描述添加 SQLite 授权回调的原始拉取请求：[`github.com/php/php-src/pull/4797`](https://github.com/php/php-src/pull/4797)

有关官方 SQLite 文档的授权回调：[`www.sqlite.org/c3ref/set_authorizer.html`](https://www.sqlite.org/c3ref/set_authorizer.html)

传递给回调函数的操作代码：[`www.sqlite.org/c3ref/c_alter_table.html`](https://www.sqlite.org/c3ref/c_alter_table.html)

结果代码的完整列表：[`www.sqlite.org/rescode.html`](https://www.sqlite.org/rescode.html)

`SQLite3`类的文档：[`www.php.net/sqlite3`](https://www.php.net/sqlite3)

# 总结

在本章中，您了解了 PHP 8 在过程级别引入的一些更改。您首先了解了新的 nullsafe 运算符，它允许您大大缩短可能失败的对象引用链的任何代码。您还了解了三元运算符和可变参数运算符的使用已经得到了加强和改进，以及连接运算符在优先级顺序中已经降级。本章还涵盖了箭头函数的优缺点，以及它们如何作为匿名函数的清晰简洁的替代方案。

本章的后续部分向您展示了 PHP 8 如何继续沿着在 PHP 7 中首次引入的统一变量语法的趋势发展。您了解了 PHP 8 中如何解决剩余的不一致之处，包括插值字符串和魔术常量的解引用，以及在数组和字符串处理方面的改进，这些改进承诺使您的 PHP 8 更清洁、更简洁和更高性能。

最后，在最后一节中，您了解了一个新功能，它提供了对 SQLite 授权回调的支持，允许您在使用 SQLite 作为数据库时最终提供一定程度的安全性。

在下一章中，您将了解 PHP 8 的错误处理增强功能。
