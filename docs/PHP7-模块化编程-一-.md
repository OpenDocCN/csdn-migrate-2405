# PHP7 模块化编程（一）

> 原文：[`zh.annas-archive.org/md5/ff0acc039cf922de0886cd9283ec3d9f`](https://zh.annas-archive.org/md5/ff0acc039cf922de0886cd9283ec3d9f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

构建模块化应用程序是一项具有挑战性的任务。它涉及广泛的知识领域，从设计模式和原则到所选择技术栈的方方面面。PHP 生态系统有相当多的工具、库、框架和平台，可以帮助我们实现模块化应用程序开发的目标。

PHP 7 带来了许多改进，可以进一步帮助实现这一目标。我们将从这些改进中开始我们的旅程。在本书结束时，我们的最终交付物将是一个由 Symfony 框架构建的模块化网络商店应用程序。

# 本书内容

第一章，生态系统概述，对 PHP 生态系统的当前状态进行了简要介绍。它探讨了 PHP 7 的最新功能，其中一些功能为模块化开发中的新概念打开了大门。此外，本章还概述了流行的 PHP 框架。

第二章，GoF 设计模式，描述了软件设计中常见问题的重复解决方案。为以下每种模式提供了实际的 PHP 示例：创建模式类型、结构模式和行为模式。

第三章，SOLID 设计原则，深入探讨了面向对象编程和设计的五个基本原则，这些原则使用 SOLID（单一责任、开闭原则、里氏替换、接口隔离和依赖反转）的首字母缩写。它提供了实际示例，并解释了这些原则在模块化开发中的重要性。

第四章，模块化网络商店应用的需求规范，指导读者定义整体应用程序需求的过程。它从定义实际应用程序功能需求开始，并逐步进行技术栈选择。

第五章，Symfony 概述，对 Symfony 作为框架、一组工具和开发方法论进行了高层次的概述。它侧重于我们构建模块化应用程序所需的构建模块。

第六章，构建核心模块，指导您通过基于 Symfony 捆绑包设置核心模块。然后，核心模块用于为其他模块设置结构和依赖关系。

第七章，构建目录模块，指导我们通过构建一个与网络商店仅目录功能集相匹配的自给模块。它向我们展示了如何设置与模块功能相关的实体，以及如何使用现有框架管理这些实体及其交互。

第八章，构建客户模块，指导我们通过构建一个与网络商店客户相关的功能集相匹配的自给模块。它向我们展示了如何设置与模块功能相关的实体，以及如何使用现有框架管理这些实体及其交互。它进一步向我们展示了如何创建注册和登录系统。

第九章，构建支付模块，指导我们通过构建一个与网络商店支付相关的功能集相匹配的自给模块。它向我们展示了如何与第三方支付提供商集成。它进一步向我们展示了如何将支付提供商作为服务提供给其他模块使用。

第十章，“构建发货模块”，指导我们构建一个自给自足的模块，与网店的发货相关功能相匹配。它向我们展示了如何定义几个扁平方法，根据不同的购物车产品属性产生不同的发货定价。它进一步向我们展示了如何将发货方法公开为其他模块使用的服务。

第十一章，“构建销售模块”，指导我们构建一个自给自足的模块，与网店仅销售相关的功能集相匹配。它向我们展示了如何设置与模块功能相关的购物车、购物车项目、订单和订单项目实体，以及如何使用现有框架管理这些实体及其交互。

第十二章，“集成和分发模块”，将前几章中构建的所有模块集成到一个单一的功能应用程序中。接下来，它指导我们通过现代 PHP 模块分发技术。这些技术包括 Git 和 Composer，间接包括 GitHub 和 Packagist。

# 您需要什么

为了成功运行本书提供的所有示例，您需要自己的 Web 服务器或第三方 Web 托管解决方案。高级技术栈包括 PHP 7.0 或更高版本，Apache/Nginx 和 MySQL。

Symfony 框架本身带有详细的系统要求列表，可以在[`symfony.com/doc/current/reference/requirements.html`](http://symfony.com/doc/current/reference/requirements.html)找到。

本书假设读者熟悉设置完整的开发环境。

# 本书的受众

本书主要面向中级 PHP 开发人员，他们对模块化编程几乎没有了解，希望了解设计模式和原则，以更好地利用现有框架进行模块化应用程序开发。

本书开发的模块化网店应用程序使用 Symfony 框架。但是，不需要假设或要求对 Symfony 框架有任何先前的了解。

# 约定

在本书中，您会发现一些区分不同类型信息的文本样式。以下是一些这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“我们可以通过使用`include`指令包含其他上下文。”

代码块设置如下：

```php
function hint (int $A, float $B, string $C, bool $D)
{
    var_dump($A, $B, $C, $D);
}
```

任何命令行输入或输出都以以下形式编写：

```php
**sudo curl -LsS https://symfony.com/installer -o /usr/local/bin/symfony**
**sudo chmod a+x /usr/local/bin/symfony**

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会出现在文本中，如：“单击**下一步**按钮将您移至下一个屏幕。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

技巧和窍门会以这种方式出现。


# 第一章：生态系统概述

自 PHP 诞生以来已经过去了二十多年。最初由 Rasmus Lerdorf 于 1994 年创建，PHP 首字母缩略词最初代表**个人主页**。当时，PHP 只是用于支持简单网页的几个**公共网关接口**（**CGI**）程序。

尽管 PHP 并不打算成为一种新的编程语言，但这个想法却得到了认可。在 90 年代末，Zend Technologies 的联合创始人 Zeev Suraski 和 Andi Gutmans 通过重写整个解析器继续了 PHP 的工作，从而诞生了 PHP 3。PHP 语言名称首字母缩略词现在代表**PHP：超文本预处理器**。

PHP 将自己定位在世界前十大编程语言之中。根据软件质量公司 TIOBE 的数据，它目前排名第六。特别是自 2004 年 7 月发布 PHP 5 以来的最后十年中，PHP 一直被认为是构建 Web 应用程序的热门解决方案。

尽管 PHP 仍然表现为一种脚本语言，但可以肯定的是，自 PHP 5 以来，它已经远远超出了这一范畴。像 WordPress、Drupal、Magento 和 PrestaShop 等世界上最受欢迎的平台都是用 PHP 构建的。正是这些项目进一步提高了 PHP 的受欢迎程度。其中一些项目通过实现其他编程语言（如 Java、C＃）和它们的框架中找到的复杂 OOP（面向对象编程）设计模式来拓展 PHP 的边界。

尽管 PHP 5 具有不错的面向对象编程（OOP）支持，但仍有许多事情有待实现。PHP 6 的工作计划是为 PHP Unicode 字符串提供更多支持。遗憾的是，它的开发停滞不前，PHP 6 在 2010 年被取消了。

同年，Facebook 宣布了他们的 HipHop 编译器。他们的编译器将 PHP 代码转换为 C++代码。然后通过 C++编译器将 C++代码进一步编译成本机代码。这个概念为 PHP 带来了重大的性能改进。然而，这种方法并不是很实用，因为将 PHP 脚本编译成本机代码太耗时。

不久之后，Zend Technologies 首席性能工程师 Dmitry Stogov 宣布了一个名为**PHPNG**的项目，这成为了下一个 PHP 版本 PHP 7 的基础。

2015 年 12 月，PHP 7 发布，带来了许多改进和新功能：

+   Zend Engine 的新版本

+   性能提升（比 PHP 5.6 快两倍）

+   显著减少的内存使用

+   抽象语法树

+   一致的 64 位支持

+   改进的异常层次结构

+   许多致命错误转换为异常

+   安全随机数生成器

+   删除了旧的和不受支持的 SAPI 和扩展

+   空合并运算符

+   返回和标量类型声明

+   匿名类

+   零成本断言

在本章中，我们将讨论以下主题：

+   为 PHP 7 做好准备

+   框架

# 为 PHP 7 做好准备

PHP 7 带来了一系列重大变化。这些变化影响了 PHP 解释器以及各种扩展和库。尽管大多数 PHP 5 代码在 PHP 7 解释器上仍将继续正常运行，但了解新提供的功能是值得的。

接下来，我们将研究其中一些功能及其提供的好处。

## 标量类型提示

标量类型提示在 PHP 中并不是一个全新的功能。随着 PHP 5.0 的引入，我们获得了对类和接口的类型提示的能力。PHP 5.1 通过引入数组类型提示来扩展了这一功能。随后，PHP 5.4 还额外增加了对可调用类型的提示。最后，PHP 7 引入了标量类型提示。将类型提示扩展到标量使得这可能是 PHP 7 中添加的最令人兴奋的功能之一。

现在可用的标量类型提示如下：

+   `string`：字符串（例如，`hello`，`foo`和`bar`）

+   `int`：整数（例如，`1`，`2`和`3`）

+   `float`：浮点数（例如，`1.2`，`2.4`和`5.6`）

+   `bool`：布尔值（例如，`true`或`false`）

默认情况下，PHP 7 以弱*类型检查*模式工作，并将尝试转换为指定类型而不投诉。我们可以使用`strict_typesdeclare()`指令来控制这种模式。

`declare(strict_types=1);`指令必须是文件中的第一条语句，否则会生成编译器错误。它只影响它所在的特定文件，并不影响其他包含的文件。该指令完全是编译时的，不能在运行时控制。

```php
declare(strict_types=0); //weak type-checking
declare(strict_types=1); // strict type-checking
```

假设以下是一个接受标量类型提示的简单函数。

```php
function hint (int $A, float $B, string $C, bool $D)
{
    var_dump($A, $B, $C, $D);
}
```

新标量类型声明的弱类型检查规则大多与扩展和内置 PHP 函数的规则相同。由于这种自动转换，当将数据传递给函数时，我们可能会不知不觉地丢失数据。一个简单的例子是将浮点数传递给需要整数的函数；在这种情况下，转换将简单地去掉小数部分。

假设弱类型检查是打开的，默认情况下，可以观察到以下情况：

```php
hint(2, 4.6, 'false', true); 
/* int(2) float(4.6) string(5) "false" bool(true) */

hint(2.4, 4, true, 8);
/* int(2) float(4) string(1) "1" bool(true) */
```

我们可以看到第一个函数调用按照提示传递参数。第二个函数调用并没有传递确切类型的参数，但函数仍然能够执行，因为参数经过了转换。

假设弱类型检查关闭，通过使用`declare(strict_types=1);`指令，可以观察到以下情况：

```php
hint(2.4, 4, true, 8);

Fatal error: Uncaught TypeError: Argument 1 passed to hint() must be of the type integer, float given, called in php7.php on line 16 and defined in php7.php:8 Stack trace: #0 php7.php(16): hint(2.4, 4, true, 8) #1 {main} thrown in php7.php on line 8
```

函数调用在第一个参数上中断，导致`\TypeError`异常。`strict_types=1`指令不允许任何类型转换。参数必须与函数定义提示的类型相同。

## 返回类型提示

除了类型提示，我们还可以对返回*值*进行类型提示。所有可以应用于函数参数的类型提示都可以应用于函数返回值。这也适用于弱类型检查规则。

要添加返回类型提示，只需在参数列表后面加上冒号和返回类型，如下例所示：

```php
function divide(int $A, int $B) : int
{
    return $A / $B;
}
```

前面的函数定义表示`divide`函数期望两个`int`类型的参数，并且应该返回一个`int`类型的参数。

假设*弱类型检查*是打开的，默认情况下，可以观察到以下情况：

```php
var_dump(divide(10, 2)); // int(5)
var_dump(divide(10, 3)); // int(3)
```

虽然`divide(10, 3)`的实际结果应该是一个浮点数，但返回类型提示会触发转换为整数。

假设弱类型检查关闭，通过使用`declare(strict_types=1);`指令，可以观察到以下情况：

```php
int(5) 
Fatal error: Uncaught TypeError: Return value of divide() must be of the type integer, float returned in php7.php:10 Stack trace: #0php7.php(14): divide(10, 3) #1 {main} thrown in php7.php on line 10
```

在放置`strict_types=1`指令的情况下，`divide(10, 3)`会失败并抛出`\TypeError`异常。

### 提示

使用标量类型提示和返回类型提示可以提高我们的代码可读性，以及像 NetBeans 和 PhpStorm 这样的 IDE 编辑器的自动完成功能。

## 匿名类

随着匿名类的添加，PHP 对象获得了类似闭包的能力。我们现在可以通过无名类实例化对象，这使我们更接近其他语言中的对象文字语法。让我们看一个简单的例子：

```php
$object = new class {
    public function hello($message) {
        return "Hello $message";
    }
};

echo$object->hello('PHP');
```

前面的例子显示了一个`$object`变量存储了一个匿名类实例的引用。更可能的用法是直接将新类传递给函数参数，而不将其存储为变量，如下所示：

```php
$helper->sayHello(new class {
    public function hello($message) {
        return "Hello $message";
    }
});
```

与任何普通类一样，匿名类可以将参数传递给它们的构造函数，扩展其他类，实现接口，并使用特征：

```php
class TheClass {}
interface TheInterface {}
trait TheTrait {}

$object = new class('A', 'B', 'C') extends TheClass implements TheInterface {

    use TheTrait;

    public $A;
    private $B;
    protected $C;

    public function __construct($A, $B, $C)
    {
        $this->A = $A;
        $this->B = $B;
        $this->C = $C;
    }
};

var_dump($object);
```

上面的例子将输出：

```php
object(class@anonymous)#1 (3) { ["A"]=> string(1) "A"["B":"class@anonymous":private]=> string(1) "B"["C":protected]=> string(1) "C" }
```

匿名类的内部名称是根据其地址生成的唯一引用。

关于何时使用匿名类并没有明确的答案。这几乎完全取决于我们正在构建的应用程序，以及对象，根据它们的视角和用法。

使用匿名类的一些好处如下：

+   模拟应用程序测试变得微不足道。我们可以为接口创建临时实现，避免使用复杂的模拟 API。

+   避免为了更简单的实现而经常调用自动加载程序。

+   清楚地告诉任何阅读代码的人，这个类在这里使用，而不是其他地方。

匿名类，或者说从匿名类实例化的对象，不能被序列化。尝试对它们进行序列化会导致致命错误，如下所示：

```php
Fatal error: Uncaught Exception: Serialization of 'class@anonymous' is not allowed in php7.php:29 Stack trace: #0 php7.php(29): serialize(Object(class@anonymous)) #1 {main} thrown in php7.php on line 29
```

嵌套的匿名类不能访问外部类的私有或受保护的方法和属性。为了使用外部类的受保护方法和属性，匿名类可以扩展外部类。忽略方法，外部类的私有或受保护属性可以在匿名类中使用，如果通过其构造函数传递：

```php
class Outer
{
    private $prop = 1;
    protected $prop2 = 2;

    protected function outerFunc1()
    {
        return 3;
    }

    public function outerFunc2()
    {
        return new class($this->prop) extends Outer
        {
            private $prop3;

            public function __construct($prop)
            {
                $this->prop3 = $prop;
            }

            public function innerFunc1()
            {
                return $this->prop2 + $this->prop3 + $this->outerFunc1();
            }
        };
    }
}

echo (new Outer)->outerFunc2()->innerFunc1(); //6
```

尽管我们将它们标记为匿名类，但从这些类实例化的对象的内部名称实际上并不是匿名的。匿名类的内部名称是根据其地址生成的唯一引用。

语句`get_class(new class{});`将导致类似`class@anonymous/php7.php0x7f33c22381c8`的结果，其中`0x7f33c22381c8`是内部地址。如果我们在代码的其他地方定义完全相同的匿名类，它的类名将不同，因为它将分配不同的内存地址。在这种情况下，结果对象可能具有相同的属性值，这意味着它们将相等（`==`）但不是相同的（`===`）。

## Closure::call()方法

PHP 在 5.3 版本中引入了 Closure 类。Closure 类用于表示匿名函数。在 PHP 5.3 中实现的匿名函数产生了这种类型的对象。从 PHP 5.4 开始，Closure 类获得了几种方法（`bind`、`bindTo`），允许在创建匿名函数后进一步控制匿名函数。这些方法基本上是使用特定绑定对象和类范围复制闭包。PHP 7 在 Closure 类上引入了`call`方法。`call`方法不会复制闭包，它会临时将闭包绑定到新的 this（`$newThis`），并使用任何给定的参数调用它。然后返回闭包的返回值。

`call`函数签名如下：

```php
function call ($newThis, ...$parameters) {}
```

$newThis 是绑定闭包的对象，在`call`期间持续绑定。将作为$parameters 给闭包的参数是可选的，意味着可以是零个或多个。

让我们看一个简单的`Customer`类和一个`$greeting`闭包的以下示例：

```php
class Customer {
    private $firstname;
    private $lastname;

    public function __construct($firstname, $lastname)
    {
        $this->firstname = $firstname;
        $this->lastname = $lastname;
    }
}

$customer = new Customer('John', 'Doe');

$greeting = function ($message) {
    return "$message $this->firstname $this->lastname!";
};

echo **$greeting->call($customer, 'Hello');**

```

在实际的`$greeting`闭包中，没有`$this`，直到实际绑定发生之前它都不存在。我们可以通过直接调用像`$greeting('Hello');`这样的闭包来轻松确认这一点。但是，我们假设当我们通过其`call`函数将闭包绑定到给定对象实例时，`$this`将出现。在这种情况下，闭包中的`$this`变成了`customer`对象实例的`$this`。前面的示例显示了使用`call`方法调用将`$customer`绑定到闭包的绑定。生成的输出显示**Hello John Doe!**

## 生成器委托

生成器提供了一种简单的方法来实现*迭代器*，而无需实现实现**Iterator**接口的类的开销。它们允许我们编写使用`foreach`来迭代一组数据的代码，而无需在内存中构建数组。这消除了超出内存限制的错误。它们对于 PHP 并不是新的，因为它们是在 PHP 5.5 中添加的。

然而，PHP 7 为生成器带来了几项新的改进，其中之一是生成器委托。

生成器委托允许生成器产生其他生成器、数组或实现**Traversable**接口的对象。换句话说，我们可以说生成器委托是产生**子生成器**。

让我们看一个带有三个生成器类型函数的以下示例：

```php
function gen1() {
    yield '1';
    yield '2';
    yield '3';
}

function gen2() {
    yield '4';
    yield '5';
    yield '6';
}

function gen3() {
    yield '7';
    yield '8';
 **yield from gen1();**
    yield '9';
 **yield from gen2();**
    yield '10';
}

// output of the below code: 123
foreach (gen1() as $number) {
echo $number;
}

//output of the below code: 78123945610
foreach (gen3() as $number) {
    echo $number;
}
```

产生其他生成器需要使用`yield from <expression>`语法。

## 生成器返回表达式

在 PHP 7 之前，生成器函数无法返回表达式。生成器函数无法指定返回值的能力限制了它们在协程上下文中的实用性。

PHP 7 使生成器能够返回表达式。现在我们可以调用 `$generator->getReturn()` 来检索 `return` 表达式。当生成器尚未返回或抛出未捕获的异常时调用 `$generator->getReturn()` 将抛出异常。

如果生成器没有定义返回表达式并且已经完成了产出，将返回 null。

让我们看下面的例子：

```php
function gen() {
    yield 'A';
    yield 'B';
    yield 'C';

    return 'gen-return';
}

$generator = gen();

//output of the below code: object(Generator)#1 (0) { }
var_dump($generator);

// output of the below code: Fatal error
// var_dump($generator->getReturn());

// output of the below code: ABC
foreach ($generator as $letter) {
    echo $letter;
}

// string(10) "gen-return"
var_dump($generator->getReturn());
```

看看 `gen()` 函数定义及其 `return` 表达式，人们可能期望 `$generator` 变量的值等于 `gen-return` 字符串。然而，情况并非如此，因为 `$generator` 变量变成了 `\Generator` 类的实例。在生成器仍然打开（未迭代）时调用生成器上的 `getReturn()` 方法将导致致命错误。

如果代码的结构使得不明显生成器是否已关闭，我们可以使用 `valid` 方法在获取返回值之前进行检查：

```php
if ($generator->valid() === false) {
    var_dump($generator->getReturn());
}
```

## 空合并运算符

在 PHP 5 中，我们有三元运算符，它测试一个值，然后如果该值为 `true`，则返回第二个元素，如果该值为 `false`，则返回第三个元素，如下面的代码块所示：

```php
$check = (5 > 3) ? 'Correct!' : 'Faulty!'; // Correct!
$check = (5 < 3) ? 'Correct!' : 'Faulty!'; // Faulty!
```

在处理 PHP 等网络中心语言中的用户提供的数据时，通常会检查变量是否存在。如果变量不存在，则将其设置为某个默认值。三元运算符为我们提供了这种便利，如下所示：

```php
$role = isset($_GET['role']) ? $_GET['role'] : 'guest';
```

然而，简单并不总是快速或优雅。考虑到这一点，PHP 7 旨在解决最常见的用法模式之一，引入了空合并运算符(`??`)。

空合并运算符使我们能够编写更短的表达式，如下面的代码块中所示：

```php
$role = $_GET['role'] **??**'guest';
```

合并运算符(`??`)被添加到 `$_GET['role']` 变量之后，如果第一个操作数存在且不为 `NULL`，则返回第一个操作数的结果，否则返回第二个操作数的结果。这意味着 `$_GET['role'] ?? 'guest'` 是完全安全的，不会引发 `E_NOTICE`。

我们还可以嵌套使用合并运算符：

```php
$A = null; // or not set
$B = 10;

echo $A ?? 20; // 20
echo $A ?? $B ?? 30; // 10
```

从左到右阅读，存在且不为 null 的第一个值将被返回。这种构造的好处在于它能够以一种清晰有效的方式实现对所需值的安全回退。

### 提示

该书的代码包也托管在 GitHub 上，网址为 [`github.com/PacktPublishing/Modular-Programming-with-PHP7`](https://github.com/PacktPublishing/Modular-Programming-with-PHP7)。我们还有其他丰富的书籍和视频代码包可供查阅，网址为 [`github.com/PacktPublishing/`](https://github.com/PacktPublishing)。欢迎查看！

## 太空船运算符

三向比较运算符，也称为太空船运算符，是在 PHP 7 中引入的。其语法如下：

```php
(expr) <=> (expr)
```

如果两个操作数相等，则运算符返回 `0`，如果左边大，则返回 `1`，如果右边大，则返回 `-1`。

它使用与其他现有比较运算符相同的比较规则：`<`、`<=`、`==`、`>=` 和 `>`。

```php
operator<=> equivalent
$a < $b($a <=> $b) === -1
$a <= $b($a <=> $b) === -1 || ($a <=> $b) === 0
$a == $b($a <=> $b) === 0
$a != $b($a <=> $b) !== 0
$a >= $b($a <=> $b) === 1 || ($a <=> $b) === 0
$a > $b($a <=> $b) === 1
```

以下是一些太空船运算符行为的示例：

```php
// Floats
echo 1.5 <=> 1.5; // 0
echo 1.5 <=> 2.5; // -1
echo 2.5 <=> 1.5; // 1

// Strings
echo "a"<=>"a"; // 0
echo "a"<=>"b"; // -1
echo "b"<=>"a"; // 1

echo "a"<=>"aa"; // -1
echo "zz"<=>"aa"; // 1

// Arrays
echo [] <=> []; // 0
echo [1, 2, 3] <=> [1, 2, 3]; // 0
echo [1, 2, 3] <=> []; // 1
echo [1, 2, 3] <=> [1, 2, 1]; // 1
echo [1, 2, 3] <=> [1, 2, 4]; // -1

// Objects
$a = (object) ["a" =>"b"]; 
$b = (object) ["a" =>"b"]; 
echo $a <=> $b; // 0

$a = (object) ["a" =>"b"]; 
$b = (object) ["a" =>"c"]; 
echo $a <=> $b; // -1

$a = (object) ["a" =>"c"]; 
$b = (object) ["a" =>"b"]; 
echo $a <=> $b; // 1

// only values are compared
$a = (object) ["a" =>"b"]; 
$b = (object) ["b" =>"b"]; 
echo $a <=> $b; // 0
```

这个运算符的一个实际用例是编写在排序函数中使用的回调，比如 `usort`、`uasort` 和 `uksort`：

```php
$letters = ['D', 'B', 'A', 'C', 'E'];

usort($letters, function($a, $b) {
return $a <=> $b;
});

var_dump($letters);

// array(5) { [0]=> string(1) "A" [1]=> string(1) "B" [2]=>string(1) "C" [3]=> string(1) "D" [4]=> string(1) "E" }
```

## 可抛出对象

尽管 PHP 5 引入了异常模型，但整体错误和错误处理仍然有些粗糙。基本上，PHP 有两种错误处理系统。传统错误仍然会弹出，并且不会被 `try…catch` 块处理。

以 `E_RECOVERABLE_ERROR` 为例：

```php
class Address
{
    private $customer;
    public function __construct(Customer $customer)
    {
        $this->customer = $customer;
    }
}

$customer = new stdClass();

try {
    $address = new Address($customer);
} catch (\Exception $e) {
    echo 'handling';
} finally {
echo 'cleanup';
}
```

在这里，`try…catch` 块没有效果，因为错误不被解释为异常，而是可捕获的致命错误：

```php
Catchable fatal error: Argument 1 passed to Address::__construct() must be an instance of Customer, instance of stdClass given, called in script.php on line 15 and defined in script.php on line 6.
```

一种可能的解决方法是使用 `set_error_handler` 函数设置用户定义的错误处理程序，如下所示：

```php
set_error_handler(function($code, $message) {
    throw new \Exception($message, $code);
});
```

如上所述，错误处理程序现在会将每个错误转换为异常，因此可以通过`try…catch`块捕获。

PHP 7 将致命错误和可捕获的致命错误作为引擎异常的一部分，因此可以通过`try…catch`块捕获。这不包括警告和通知，它们仍然不通过异常系统，这对于向后兼容性是有意义的。

它还通过`\Throwable`接口引入了一个新的异常层次结构。`\Exception`和`\Error`实现了`\Throwable`接口。

标准的 PHP 致命错误和可捕获的致命错误现在作为`\Error`异常抛出，尽管如果它们未被捕获，它们仍将继续触发传统的致命错误。

在整个应用程序中，我们必须使用`\Exception`和`\Error`，因为我们不能直接实现`\Throwable`接口。但是，我们可以使用以下块来捕获所有错误，无论是`\Exception`还是`\Error`类型：

```php
try {
// statements
} catch (**\Throwable $t**) {
    // handling
} finally {
// cleanup
}
```

## \ParseError

**ParseError**是 PHP 7 对错误处理的一个很好的补充。我们现在可以处理由`eval()`、`include`和`require`语句触发的解析错误，以及由`\ParseError`异常抛出的解析错误。它扩展了`\Error`，而`\Error`又实现了`\Throwable`接口。

以下是一个破损的 PHP 文件的示例，因为数组项之间缺少“`,`”：

```php
<?php

$config = [
'host' =>'localhost'
'user' =>'john'
];

return $config;
```

以下是包括`config.php`的文件的示例：

```php
<?php 

try {
include 'config.php';
} catch (\ParseError $e) {
// handle broken file case
}
```

我们现在可以安全地捕获可能的解析错误。

## dirname()函数的级别支持

`dirname`函数自 PHP 4 以来一直存在。这可能是 PHP 中最常用的函数之一。直到 PHP 7，此函数只接受`path`参数。在 PHP 7 中，添加了新的 levels 参数。

让我们看下面的例子：

```php
// would echo '/var/www/html/app/etc'
echo dirname('/var/www/html/app/etc/config/');

// would echo '/var/www/html/app/etc'
echo dirname('/var/www/html/app/etc/config.php');

// would echo '/var/www/html/app'
echo dirname('/var/www/html/app/etc/config.php', 2);

// would echo '/var/www/html'
echo dirname('/var/www/html/app/etc/config.php', 3);
```

通过分配`levels`值，我们指示从分配的路径值向上移动多少级。虽然很小，但`levels`参数的添加肯定会使处理路径的某些代码更容易编写。

## 整数除法函数

`intdiv`是 PHP 7 引入的新的整数除法函数。该函数接受被除数和除数作为参数，并返回它们的商的整数部分，如下面的函数描述所示：

```php
int intdiv(int $dividend, int $divisor)
```

让我们看下面的几个例子：

```php
intdiv(5, 3); // int(1)
intdiv(-5, 3); // int(-1)
intdiv(5, -2); // int(-2)
intdiv(-5, -2); // int(2)
intdiv(PHP_INT_MAX, PHP_INT_MAX); // int(1)
intdiv(PHP_INT_MIN, PHP_INT_MIN); // int(1)

// following two throw error
intdiv(PHP_INT_MIN, -1); // ArithmeticError
intdiv(1, 0); // DivisionByZeroError
```

如果`dividend`是`PHP_INT_MIN`，而除数是`-1`，那么会抛出`ArithmeticError`异常。如果除数是`0`，那么会抛出`DivisionByZeroError`异常。

## 常量数组

在 PHP 7 之前，使用`define()`定义的常量只能包含标量表达式，而不能包含数组。从 PHP 5.6 开始，可以使用`const`关键字定义数组常量，从 PHP 7 开始，也可以使用`define()`定义数组常量：

```php
// the define() example
define('FRAMEWORK', [
'version' => 1.2,
'licence' =>'enterprise'
]);

echo FRAMEWORK['version']; // 1.2
echo FRAMEWORK['licence']; // enterprise

// the class const example
class App {
    const FRAMEWORK = [
'version' => 1.2,
'licence' =>'enterprise'
    ];
}

echo App::FRAMEWORK['version']; // 1.2
echo App::FRAMEWORK['licence']; // enterprise
```

常量一旦设置后就不能重新定义或取消定义。

## 统一的变量语法

为了使 PHP 的解析器更完整，PHP 7 引入了统一的变量语法。使用统一的变量语法，所有变量都是从左到右进行评估的。

与删除各种函数、关键字或设置不同，像这样的语义变化对现有代码库的影响可能相当大。以下代码演示了语法、其旧含义和新含义：

```php
// Syntax
$$foo['bar']['baz']
// PHP 5.x:
// Using a multidimensional array value as variable name
${$foo['bar']['baz']}
// PHP 7:
// Accessing a multidimensional array within a variable-variable
($$foo)['bar']['baz']

// Syntax
$foo->$bar['baz']
// PHP 5.x:
// Using an array value as a property name
$foo->{$bar['baz']}
// PHP 7:
// Accessing an array within a variable-property
($foo->$bar)['baz']

// Syntax
$foo->$bar['baz']()
// PHP 5.x:
// Using an array value as a method name
$foo->{$bar['baz']}()
// PHP 7:
// Calling a closure within an array in a variable-property
($foo->$bar)['baz']()

// Syntax
Foo::$bar['baz']()
// PHP 5.x:
// Using an array value as a static method name
Foo::{$bar['baz']}()
// PHP 7:
// Calling a closure within an array in a static variable
(Foo::$bar)['baz']()
```

除了以前重写的旧到新语法示例之外，现在还支持一些新的语法组合。

PHP 7 现在支持嵌套双冒号`::`，以下是一个示例：

```php
// Access a static property on a string class name
// or object inside an array
$foo['bar']::$baz;
// Access a static property on a string class name or object
// returned by a static method call on a string class name
// or object
$foo::bar()::$baz;
// Call a static method on a string class or object returned by
// an instance method call
$foo->bar()::baz();
```

我们还可以通过在括号中加倍来嵌套方法和函数调用，或者任何可调用的内容，如下面的代码示例所示：

```php
// Call a callable returned by a function
foo()();
// Call a callable returned by an instance method
$foo->bar()();
// Call a callable returned by a static method
Foo::bar()();
// Call a callable return another callable
$foo()();
```

此外，我们现在可以对任何用括号括起来的有效表达式进行解引用：

```php
// Access an array key
(expression)['foo'];
// Access a property
(expression)->foo;
// Call a method
(expression)->foo();
// Access a static property
(expression)::$foo;
// Call a static method
(expression)::foo();
// Call a callable
(expression)();
// Access a character
(expression){0};
```

## 安全的随机数生成器

PHP 7 引入了两个新的**CSPRNG**函数。CSPRNG 是**密码学安全伪随机数生成器**的缩写。

第一个`random_bytes`生成一个任意长度的加密随机字节字符串，适用于加密用途，比如生成*盐*、*密钥*或*初始化*向量。该函数只接受一个（`length`）参数，表示应以字节返回的随机字符串的长度。它返回一个包含请求的数量的密码安全随机字节的字符串，或者在找不到适当的随机源时，它会抛出一个异常。

以下是`random_bytes`的使用示例：

```php
$bytes = random_bytes(5);
```

第二个`random_int`生成适用于需要无偏结果的密码随机整数，比如在为扑克游戏洗牌时。该函数接受两个（`min`，`max`）参数，表示要返回的最小值（必须是`PHP_INT_MIN`或更高）和要返回的最大值（必须小于或等于`PHP_INT_MAX`）。它返回范围在 min 到 max（包括 min 和 max）之间的密码安全随机整数。

以下是`random_int`的使用示例：

```php
$int = random_int(1, 10);
$int = random_int(PHP_INT_MIN, 500);
$int = random_int(20, PHP_INT_MAX);
$int = random_int(PHP_INT_MIN, PHP_INT_MAX);
```

## 过滤反序列化()

序列化数据可以包括对象。这些对象还可以包括析构函数、`__toString`和`__call`等函数。为了在对非结构化数据上反序列化对象时提高安全性，PHP 7 引入了现有`unserialize`函数的可选`options`参数。

`options`参数是一个数组类型，目前只接受`allowed_classes`键。

`allowed_classes`可以有三个值之一：

+   `true`：这是默认值，和以前一样允许所有对象

+   `false`：这里不允许对象

+   允许的类名数组，列出了未序列化对象的允许类

以下是使用`allowed_classes`选项的示例：

```php
class Customer{
    public function __construct(){
        echo '__construct';
    }

    public function __destruct(){
        echo '__destruct';
    }

    public function __toString(){
        echo '__toString';
        return '__toString';
    }

    public function __call($name, $arguments) {
        echo '__call';
    }
}

$customer = new Customer();

$s = serialize($customer); // triggers: __construct, __destruct

$u = unserialize($s); // triggers: __destruct
echo get_class($u); // Customer

$u = unserialize($s, ['allowed_classes'=>false]); // does not trigger anything
echo get_class($u); // __PHP_Incomplete_Class
```

我们可以看到，该类的对象如果不被接受，则被实例化为`__PHP_Incomplete_Class`。

## 上下文敏感的词法分析器

根据[`php.net/manual/en/reserved.keywords.php`](http://php.net/manual/en/reserved.keywords.php)列表，PHP 有 60 多个保留关键字。这些构成了语言结构，比如类、接口和特征中的属性、方法、常量的名称。

有时这些保留字最终会与用户定义的 API 声明发生冲突。

为了解决这个问题，PHP 7.0 引入了上下文敏感的词法分析器。有了上下文敏感的词法分析器，我们现在可以在我们的代码中使用关键字来表示属性、函数和常量的名称。

以下是与上下文敏感的词法分析器的影响相关的一些实际示例： 

```php
class ReportPool {
    public function include(Report $report) {
//
    }
}

$reportPool = new ReportPool();
$reportPool->include(new Report());

class Collection extends \ArrayAccess, \Countable, \IteratorAggregate {

    public function forEach(callable $callback) {
//
    }

    public function list() {
//
    }

    public static function new(array $items) {
        return new self($items);
    }
}

Collection::new(['var1', 'var2'])
->forEach(function($index, $item){ /* ... */ })
->list();
```

唯一的例外是`class`关键字，在*类常量上下文*中仍然保留，如下所示：

```php
class Customer {
  const class = 'Retail'; // Fatal error
}
```

## 组使用声明

*组使用声明*在 PHP 7 中引入，用于从公共命名空间导入多个类时减少冗长。它们启用了如下的简写语法：

```php
use Library\Group1\Group2\{ ClassA, ClassB, ClassC as Classy };
```

让我们看一下下面的例子，其中*相同命名空间*内的类名被组合使用：

```php
// Current use syntax
use Doctrine\Common\Collections\Expr\Comparison;
use Doctrine\Common\Collections\Expr\Value;
use Doctrine\Common\Collections\Expr\CompositeExpression;

// Group use syntax
use Doctrine\Common\Collections\Expr\{ Comparison, Value, CompositeExpression };
```

我们还可以在部分命名空间上使用*组使用声明*，如下面的示例所示：

```php
// Current use syntax
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\NullOutput;
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ChoiceQuestion as Choice;
use Symfony\Component\Console\Question\ConfirmationQuestion;

// Group use syntax
use Symfony\Component\Console\{
  Helper\Table,
  Input\ArrayInput,
  Input\InputInterface,
  Output\NullOutput,
  Output\OutputInterface,
  Question\Question,
  Question\ChoiceQuestion as Choice,
  Question\ConfirmationQuestion,
};
```

我们还可以像下面的代码行一样进一步使用`group use`来导入函数和常量：

```php
use Framework\Component\{
SubComponent\ClassA,
function OtherComponent\someFunction,
const OtherComponent\SOME_CONSTANT
};
```

## Unicode 增强

Unicode，特别是 UTF-8，在 PHP 应用程序中越来越受欢迎。

PHP 7 为*双引号字符串*和*heredocs*添加了新的转义序列，语法如下：

```php
\u{code-point}
```

它产生了一个 Unicode 代码点的 UTF-8 编码，用十六进制数字指定。值得注意的是，花括号中的代码点长度是任意的。这意味着我们可以使用`\u{FF}`或更传统的`\u{00FF}`。

以下是四种最常用货币、它们的符号和它们的 UTF-8 代码点的简单列表：

```php
Euro€U+20AC
Japanese Yen¥U+00A5
Pound sterling£U+00A3
Australian dollar$U+0024
```

其中一些符号通常直接存在于键盘上，所以很容易像这里显示的那样写下来：

```php
echo "the € currency";
echo "the ¥ currency";
echo "the £ currency";
echo "the $ currency";
```

然而，大多数其他符号不像单个按键那样容易访问，因此需要以代码点的形式编写，如下所示：

```php
echo "the \u{1F632} face";
echo "the \u{1F609} face";
echo "the \u{1F60F} face";
```

在较早版本的 PHP 中，前面语句的输出将如下所示：

```php
the \u{1F632} face
the \u{1F609} face
the \u{1F60F} face
```

显然，这并没有解析代码点，因为它会直接输出它们。

PHP 7 引入了 Unicode 代码点转义序列语法到字符串文字中，使以前的语句产生以下输出：

```
the 😉 face
the 😉 face
the 😉 face
```php

## 断言

断言是一种调试功能，用于检查给定的断言，并在其结果为`false`时采取适当的操作。它们一直是 PHP 的一部分，自 PHP 4 以来就一直存在。

断言与错误处理的不同之处在于，断言涵盖了不可能的情况，而错误是可能的并且需要被处理。

应避免将断言用作通用错误处理机制。断言不允许从错误中恢复。断言失败通常会停止程序的执行。

使用现代调试工具如 Xdebug，不多的开发人员会使用断言进行调试。

断言可以通过`assert_options`函数或`assert.active INI`设置轻松启用和禁用。

要使用断言，我们可以传入一个表达式或字符串，如下面的函数签名所示：

```
// PHP 5
bool assert ( mixed $assertion [, string $description ] )

// PHP 7
bool assert ( mixed $assertion [, Throwable $exception ] )
```php

这两个签名在第二个参数上有所不同。PHP 7 可以接受字符串`$description`或`$exception`。

如果表达式的结果或字符串的求值结果为`false`，则会发出警告。如果第二个参数传递为`$exception`，则会抛出异常而不是失败。

关于`php.ini`配置选项，`assert`函数已扩展以允许所谓的*零成本断言*：

```
zend.assertions = 1 // Enable
zend.assertions = 0 // Disable
zend.assertions = -1 // Zero-cost
```php

使用零成本设置，断言对性能和执行没有任何影响，因为它们不会被编译。

最后，**INI**设置中添加了`Boolean assert.exception`选项。将其设置为`true`，会导致失败的断言引发`AssertionError`异常。

## 对`list()`构造的更改

在 PHP 5 中，`list()`从最右边的参数开始分配值。在 PHP 7 中，`list()`从最左边的参数开始。基本上，现在的值按照它们被定义的顺序分配给变量。

然而，这只影响了`list()`与`array []`操作符一起使用的情况，如下面的代码块中所讨论的：

```
<?php

list($color1, $color2, $color3) = ['green', 'yellow', 'blue'];
var_dump($color1, $color2, $color3);

list($colors[], $colors[], $colors[]) = ['green', 'yellow', 'blue'];
var_dump($colors);
```php

在 PHP 5 中，前面代码的输出将如下所示：

```
string(5) "green"
string(6) "yellow"
string(4) "blue"

array(3) { 
[0]=> string(5) "blue"
[1]=> string(6) "yellow"
[2]=> string(4) "green"
}
```php

在 PHP 7 中，前面代码的输出将如下所示：

```
string(5) "green"
string(6) "yellow"
string(4) "blue"

array(3) { 
[0]=> string(5) "green"
[1]=> string(6) "yellow"
[2]=> string(4) "blue"
}
```php

分配顺序可能会在将来再次改变，因此我们不应过分依赖它。

## 会话选项

在 PHP 7 之前，`session_start()`函数并不直接接受任何配置选项。我们想要在会话中设置的任何配置选项都需要来自`php.ini`：

```
// PHP 5
ini_set('session.name', 'THEAPP');
ini_set('session.cookie_lifetime', 3600);
ini_set('session.cookie_httponly', 1);
session_start();

// PHP 7
session_start([
'name' =>'THEAPP',
'cookie_lifetime' => 3600,
'cookie_httponly' => 1
]);
```php

受性能优化目标的驱动，PHP 7 中添加了一个新的`lazy_write`运行时配置。当`lazy_write`设置为`1`时，只有在会话数据发生变化时才会重新写入。这是默认行为：

```
session_start([
'name' =>'THEAPP',
'cookie_lifetime' => 3600,
'cookie_httponly' => 1,
'lazy_write' => 1
]);
```php

尽管这里列出的更改一开始可能看起来并不令人印象深刻，但通过`session_start`函数直接覆盖会话选项的能力为我们的代码提供了一定的灵活性。

## 弃用的功能

全球通用的软件主要版本有打破向后兼容性的奢侈。理想情况下，不会有太多，但为了使软件向前发展，一些旧的想法需要被抛弃。这些变化不是一夜之间发生的。某些功能首先被标记为弃用，以警告开发人员它将在未来版本的语言中被移除。有时，这种弃用期可能需要数年。

在整个 PHP 5.x 中，许多功能已被标记为弃用，在 PHP 7.0 中，它们都已被移除。

**POSIX 兼容**的正则表达式在 PHP 5.3 中已被弃用，现在在 PHP 7 中完全移除。

以下函数不再可用：

+   ereg_replace

+   ereg

+   eregi_replace

+   eregi

+   `split`

+   spliti

+   sql_regcase

我们应该使用**Perl 兼容正则表达式**（**PCRE**）。[`php.net/manual/en/book.pcre.php`](http://php.net/manual/en/book.pcre.php)是这些函数的一个很好的文档来源。

在 PHP 5.5 中已经弃用的`mysql`扩展现在已经被移除。不再有任何`mysql_*`函数可用。我们应该使用`mysqli`扩展。好消息是，从`mysql`到`mysqli`函数的转换大多是简单的，因为在我们的代码中添加`i`时，`mysql_*`函数调用并将数据库句柄（由`mysqli_connect`返回）作为第一个参数传递。[`php.net/manual/en/book.mysqli.php`](http://php.net/manual/en/book.mysqli.php)是这些函数的一个很好的文档来源。

PHP 脚本和 ASP 标签已不再可用：

```
<!-- PHP script tag example -->
<script language="php">
// Code here
</script>

<!-- PHP ASP tag example -->
<%
// Code here
%>
<%=$varToEcho; %>
```

## 框架

应用框架是一组函数、类、配置和约定，旨在支持 Web 应用程序、服务和 API 的开发。一些应用程序正在采用 API 优先的方法，而服务器端的 REST 和 SOAP API 是通过 PHP 构建的，客户端使用其他技术如 JavaScript。

构建 Web 应用程序时，通常有三个明显的选择：

+   我们可以从头开始构建所有东西。这种方式可能会使我们的开发过程变慢，但我们可以实现完全符合我们标准的架构。不用说，这是一种非常低效的方法。

+   我们可以使用现有的框架。这样，我们的开发过程会很快，但我们需要满意我们的应用是建立在其他东西之上的。

+   我们可以使用现有的框架，但也可以尝试将其抽象到应用程序看起来独立于它的级别。这是一个痛苦而缓慢的方法，至少可以这么说。它涉及编写大量的适配器、包装器、接口等。

简而言之，框架的存在是为了让我们更容易更快地构建软件。许多编程语言都有流行的框架，PHP 也不例外。

鉴于 PHP 作为首选的 Web 编程语言的普及度，数十个框架在多年来已经涌现出来，这并不奇怪。选择“正确”的框架是一项艰巨的任务，尤其是对于新手来说更是如此。对于一个项目或团队来说合适的框架可能对另一个项目或团队来说并不合适。

然而，每个现代框架应该包括一些一般的高级部分。这些部分包括：

+   **模块化**：支持模块化应用程序开发，允许我们将代码整齐地分成功能性的构建块，而它是以模块化的方式构建的。

+   **安全**：提供现代 Web 应用程序所期望的各种加密和其他安全工具。提供对身份验证、授权和数据加密等功能的无缝支持。

+   **可扩展**：能够轻松地满足我们的应用程序需求，使我们能够根据我们的应用程序需求进行扩展。

+   **社区**：它由充满活力和积极的社区积极开发和支持。

+   **高性能**：以性能为重点构建。许多框架都吹嘘性能，但其中有许多变量。我们需要明确我们在这里评估什么。对缓存性能与原始性能进行测量通常是误导性的评估，因为缓存代理可以放在许多框架的前面。

+   **企业就绪**：根据手头项目的类型，我们很可能希望选择一个标志自己为企业就绪的框架。这让我们足够自信地在其上运行关键和高使用率的业务应用程序。

虽然完全可以使用纯 PHP 编写整个 Web 应用程序而不使用任何框架，但今天的大多数项目确实使用了框架。

使用框架的好处超过了从头开始做所有事情的纯度。框架通常得到很好的支持和文档，这使得团队更容易掌握库、项目结构、约定和其他事项。

在谈到 PHP 框架时，值得指出一些流行的框架：

+   **Laravel**：[`laravel.com`](https://laravel.com)

+   **Symfony**：[`symfony.com`](http://symfony.com)

+   **Zend Framework**：[`framework.zend.com`](http://framework.zend.com)

+   **CodeIgniter**：[`www.codeigniter.com`](https://www.codeigniter.com)

+   **CakePHP**：[`cakephp.org`](http://cakephp.org)

+   **Slim**：[`www.slimframework.com`](http://www.slimframework.com)

+   **Yii**：[`www.yiiframework.com`](http://www.yiiframework.com)

+   **Phalcon**：[`phalconphp.com`](https://phalconphp.com)

这绝不是一个完整或甚至是按流行程度排序的列表。

### Laravel 框架

Laravel 是根据 MIT 许可发布的，可以从[`laravel.com/`](https://laravel.com/)下载。

除了常规的路由、控制器、请求、响应、视图和（blade）模板之外，Laravel 还提供了大量额外的服务，如身份验证、缓存、事件、本地化等。

Laravel 的另一个很棒的功能是**Artisan**，这是一个命令行工具，提供了许多在开发过程中可以使用的有用命令。Artisan 还可以通过编写自己的控制台命令进行扩展。

Laravel 拥有一个非常活跃和充满活力的社区。它的文档简单清晰，使得新手很容易上手。此外，还有[`laracasts.com`](https://laracasts.com)，它在文档和其他内容方面超越了 Laravel。Laracasts 是一个提供一系列专家录屏的网络服务，其中一些是免费的。

所有这些特性使得 Laravel 成为在选择框架时值得评估的选择。

### Symfony

Symfony 是根据 MIT 许可发布的，可以从[`symfony.com`](http://symfony.com)下载。

随着时间的推移，Symfony 引入了**长期支持**（LTS）版本的概念。这个发布过程从 Symfony 2.2 开始被采用，并严格遵循从 Symfony 2.4 开始。标准版本的 Symfony 维护八个月。长期支持版本支持三年。

关于新版本的另一个有趣的事情是基于时间的发布模型。所有新版本的 Symfony 发布都是每六个月一次：五月和十一月各一个。

Symfony 通过邮件列表、IRC 和 StackOverflow 拥有很好的社区支持。此外，SensioLabs 专业支持提供了从咨询、培训、辅导到认证的全方位解决方案。

许多 Symfony 组件被用于其他 Web 应用程序和框架，如 Laravel、Silex、Drupal 8、Sylius 等。

Symfony 之所以成为如此受欢迎的框架，是因为它的互操作性。"不要将自己锁在 Symfony 中！"的理念使其受到开发人员的欢迎，因为它允许构建精确满足我们需求的应用程序。

通过拥抱"不要重复造轮子"的理念，Symfony 本身大量使用现有的 PHP 开源项目作为框架的一部分，包括：

+   Doctrine（或 Propel）：对象关系映射层

+   PDO 数据库抽象层（Doctrine 或 Propel）

+   PHPUnit：一个单元测试框架

+   Twig：一个模板引擎

+   Swift Mailer：一个电子邮件库

根据我们的项目需求，我们可以选择使用全栈 Symfony 框架，Silex 微框架，或者只是一些单独的组件。

Symfony 开箱即用为新的 Web 应用程序提供了大量的结构基础。它通过其 bundle 系统实现。Bundle 类似于主应用程序中的微应用程序。在其中，整个应用程序被很好地结构化为模型、控制器、模板、配置文件和其他构建块。能够完全将不同领域的逻辑分离开有助于我们保持关注点的清晰分离，并独立开发我们领域的每个功能。

Symfony 是 PHP 在采用依赖注入方面的先驱之一，这使得它能够实现解耦的组件，并保持代码的高灵活性。

文档化、模块化、高度灵活、高性能、受支持，这些属性使 Symfony 成为值得评估的选择。

### Zend Framework

Zend Framework 是根据新的 BSD 许可证发布的，可以从[`framework.zend.com`](http://framework.zend.com)下载。

Zend Framework 的特点包括：

+   完全面向对象的 PHP 组件

+   松散耦合的组件

+   可扩展的 MVC 支持布局和模板

+   支持多个数据库系统 MySQL、Oracle、MS SQL 等

+   通过 mbox、Maildir、POP3 和 IMAP4 处理电子邮件

+   灵活的缓存系统

除了免费的 Zend Framework 外，Zend Technologies Ltd 还提供了自己的商业版本的 PHP 堆栈，称为 Zend Server，以及包含专门与 Zend Framework 集成的功能的 Zend Studio IDE。虽然 Zend Framework 可以在任何 PHP 堆栈上运行，但 Zend Server 被宣传为运行 Zend Framework 应用程序的优化解决方案。

根据其架构设计，Zend Framework 仅仅是一组类。我们的应用程序不需要遵循严格的结构。这是使其对某一范围的开发人员如此吸引人的特点之一。我们可以利用 Zend MVC 组件创建一个完全功能的 Zend Framework 项目，或者只需加载我们需要的组件。

所谓的全栈框架会将结构、ORM 实现、代码生成等固定内容强加到项目中。另一方面，Zend Framework 以其解耦的特性，被归类为一种粘合型框架。我们可以轻松地将其粘合到现有应用程序中，或者用它来构建一个新的应用程序。

最新版本的 Zend Framework 遵循**SOLID 面向对象设计**原则。所谓的“随意使用”设计允许开发人员使用他们想要的任何组件。

尽管 Zend Framework 的主要推动力是 Zend Technologies，但许多其他公司也为该框架贡献了重要特性。

此外，Zend Technologies 提供了出色的 Zend Certified PHP Engineer 认证。优质的社区、官方公司支持、教育、托管和开发工具使 Zend Framework 成为值得评估的选择。

### CodeIgniter

CodeIgniter 是根据 MIT 许可证发布的，可以从[`www.codeigniter.com`](https://www.codeigniter.com)下载。

CodeIgniter 以其轻量级而自豪。核心系统只需要少量的小型库，这在其他框架中并不总是如此。

该框架采用简单的**模型-视图-控制**方法，允许在逻辑和呈现之间进行清晰分离。视图层不会强加任何特殊的模板语言，因此可以直接使用原生 PHP。

以下是 CodeIgniter 的一些突出特点：

+   基于模型-视图-控制的系统

+   极其轻量级

+   具有对多个平台的支持的全功能数据库类

+   查询构建器数据库支持

+   表单和数据验证

+   安全和 XSS 过滤

+   本地化

+   数据加密

+   完整页面缓存

+   单元测试类

+   搜索引擎友好的 URL

+   灵活的 URI 路由

+   支持钩子和类扩展

+   大量的辅助函数库

CodeIgniter 拥有一个活跃的社区，聚集在[`forum.codeigniter.com`](http://forum.codeigniter.com)。

小的占用空间、灵活性、出色的性能、接近零的配置和详尽的文档是使这个框架值得评估的选择。

### CakePHP

CakePHP 是根据 MIT 许可发布的，可以从[`cakephp.org`](http://cakephp.org)下载。

CakePHP 框架受到**Ruby on Rails**的极大启发，使用了许多它的概念。它重视约定胜过配置。

它是“一应俱全”的。对于现代 Web 应用程序，我们大多数需要的东西都已经内置了。翻译、数据库访问、缓存、验证、身份验证等等都已经内置了。

安全性是 CakePHP 哲学的另一个重要部分。CakePHP 带有用于输入验证、CSRF 保护、表单篡改保护、SQL 注入预防和 XSS 预防的内置工具，帮助我们保护我们的应用程序。

CakePHP 支持各种数据库存储引擎，如 MySQL、PostgreSQL、Microsoft SQL Server 和 SQLite。内置的 CRUD 功能对数据库交互非常方便。

它依靠一个庞大的社区支持。它还有一个大型的插件列表，可在[`plugins.cakephp.org`](http://plugins.cakephp.org)上找到。

CakePHP 提供了认证考试，开发人员在 CakePHP 框架、MVC 原则和 CakePHP 内部使用的标准方面接受考验。认证面向真实场景和 CakePHP 特定内容。

Cake Development Corporation 提供商业支持、咨询、代码审查、性能分析、安全审计，甚至开发服务，网址为[`www.cakedc.com`](http://www.cakedc.com)。Cake Development Corporation 是该框架背后的商业实体，由 CakePHP 的创始人之一 Larry Masters 于 2007 年成立。

### Slim

Slim 是根据 MIT 许可发布的，可以从[`www.slimframework.com`](http://www.slimframework.com)下载。

虽然“一应俱全”思维的框架提供了强大的库、目录结构和配置，微框架只需几行代码就能让我们开始。

微框架通常甚至缺乏基本的框架功能，如：

+   身份验证和授权

+   ORM 数据库抽象

+   输入验证和净化

+   模板引擎

这限制了它们的使用，但也使它们成为快速原型设计的强大工具。

Slim 支持任何 PSR-7 HTTP 消息实现。HTTP 消息可以是客户端到服务器的请求，也可以是服务器到客户端的响应。Slim 的功能类似于一个分发器，接收 HTTP 请求，调用适当的回调例程，并返回 HTTP 响应。

Slim 的好处在于它与中间件很好地配合。中间件基本上是一个可调用的函数，接受三个参数：

+   `\Psr\Http\Message\ServerRequestInterface`: PSR7 请求对象

+   `\Psr\Http\Message\ResponseInterface`: PSR7 响应对象

+   `callable`: 下一个中间件可调用

中间件可以自由地操作请求和响应对象，只要它们返回`\Psr\Http\Message\ResponseInterface`的实例。此外，每个中间件都需要调用下一个中间件，并将请求和响应对象作为参数传递给它。

这个简单的概念赋予了 Slim 可扩展性的能力，通过各种可能的第三方中间件。

尽管 Slim 提供了良好的文档、活跃的社区，并且项目目前正在积极开发，但它的使用是有限的。微框架几乎不是健壮企业应用的选择。不过，它们在开发中有它们的位置。

### Yii

Yii 是根据 BSD 许可发布的，可以从[`www.yiiframework.com`](http://www.yiiframework.com)下载。

Yii 对性能优化的关注使其成为几乎任何类型项目的完美选择，包括企业类型的应用程序。

一些杰出的 Yii 特性包括：

+   MVC 设计模式

+   自动生成复杂服务 WSDL

+   日期、时间和数字的翻译、本地化、区域敏感格式化

+   数据缓存、片段缓存、页面缓存和 HTTP 缓存

+   基于错误的性质和应用程序运行模式显示错误的错误处理程序

+   安全措施，以帮助防止 SQL 注入、跨站脚本（XSS）、跨站请求伪造（CSRF）和 Cookie 篡改

+   基于 PHPUnit 和 Selenium 的单元和功能测试

Yii 的一个很棒的功能是一个名为 Gii 的工具。它是一个提供基于 Web 的代码生成器的扩展。我们可以使用 Gii 的图形界面快速设置生成模型、表单、模块、CRUD 等。还有一个 Gii 的命令行版本，适合喜欢控制台的人使用。

Yii 的架构使其能够与 PEAR 库、Zend Framework 等第三方代码很好地配合。它采用了 MVC 架构，允许清晰地分离关注点。

Yii 提供了一个令人印象深刻的扩展库，可在[`www.yiiframework.com/extensions`](http://www.yiiframework.com/extensions)找到。大多数扩展都是作为 composer 包分发的。它们为我们提供了加速开发的能力。我们可以轻松地将我们的代码打包为扩展并与他人分享。这使得 Yii 对于模块化应用程序开发更加有趣。

官方文档非常全面。还有几本书可供参考。

丰富的文档、充满活力的社区、活跃的发布、性能优化、安全强调、功能丰富和灵活性使 Yii 成为值得评估的选择。

### Phalcon

Phalcon 是根据 BSD 许可发布的，可以从[`phalconphp.com`](https://phalconphp.com)下载。

Phalcon 最初是由 Andres Gutierrez 和合作者于 2012 年发布的。该项目的目标是找到一种新的方法来编写 PHP 的传统 Web 应用程序框架。这种新方法以 C 语言扩展的形式出现。整个 Phalcon 框架都是作为 C 扩展开发的。

基于 C 的框架的好处在于在运行时加载整个 PHP 扩展。这极大地减少了 I/O 操作，因为不再需要加载`.php`文件。此外，编译的 C 语言代码比 PHP 字节码执行速度更快。由于 C 扩展与 PHP 一起在 Web 服务器守护进程启动过程中加载一次，它们的内存占用量很小。基于 C 的框架的缺点是代码是编译的，因此我们不能像使用 PHP 类一样轻松地调试和修补它。

低级架构和优化使 Phalcon 成为基于 MVC 的应用程序中开销最低的之一。

Phalcon 是一个全栈、松散耦合的框架。虽然它为我们的应用程序提供了完整的 MVC 结构，但它也允许我们根据应用程序的需求将其对象用作粘合组件。我们可以选择是创建一个完整的 MVC 应用程序，还是最小化的微型应用程序。微型应用程序适合以实际方式实现小型应用程序、API 和原型。

到目前为止，我们提到的所有框架都支持某种形式的扩展，我们可以向框架添加新的库或整个包。由于 Phalcon 是一个 C 代码框架，对框架的贡献不是以 PHP 代码的形式出现。另一方面，编写和编译 C 语言代码对于普通的 PHP 开发人员来说可能有些具有挑战性。

**Zephir**项目[`zephir-lang.com`](http://zephir-lang.com)通过引入高级 Zephir 语言来解决这些挑战。Zephir 旨在简化为 PHP 创建和维护 C 扩展，重点放在类型和内存安全上。

在与数据库通信时，Phalcon 使用**Phalcon 查询语言**，**PhalconQL**，或简称**PHQL**。PHQL 是一种高级的、面向对象的 SQL 方言，允许我们使用类似 SQL 的语言编写查询，该语言与对象而不是表一起使用。

视图模板由 Volt 处理，这是 Phalcon 自己的模板引擎。它与其他组件高度集成，可以在我们的应用程序中独立使用。

Phalcon 相当容易上手。它的文档涵盖了使用框架的 MVC 和微型应用程序样式，还有实际的例子。框架本身足够丰富，可以支持我们大多数今天的应用程序所需的结构和库。此外，还有一个名为**Phalconist** [`phalconist.com`](https://phalconist.com)的官方 Phalcon 网站，提供了框架的额外资源。

尽管没有官方公司支持，也没有认证、商业支持等类似的企业外观，Phalcon 在定位自己作为一个值得评估的选择方面做得很好，即使是在健壮的企业应用程序开发中也是如此。

# 总结

回顾一下 PHP 5 的发布及其对面向对象编程的支持，我们可以看到它对 PHP 生态系统产生的巨大积极影响。大量的框架和库已经涌现出来，为 Web 应用程序开发提供了企业级解决方案。

PHP 7 的发布很可能是 PHP 生态系统的又一个飞跃。虽然新功能中没有一项是革命性的，因为它们可以在其他编程语言中找到，但它们对 PHP 的影响很大。我们还没有看到它的新功能将如何重塑现有和未来的框架以及我们编写应用程序的方式。

引入更高级的*错误到异常*处理、标量类型提示和函数返回类型提示，肯定会为使用它们的应用程序和框架带来期待已久的稳定性。与 PHP 5.6 相比的速度改进足以显著降低高负载站点的托管成本。值得庆幸的是，PHP 开发团队最小化了向后不兼容的更改，因此它们不应该妨碍 PHP 7 的迅速采用。

选择合适的框架绝非易事。将框架分类为企业级框架的标准不仅仅是一堆类的集合。它有一个完整的生态系统。

在评估项目的框架时，不应受到炒作的影响。应该考虑以下问题：

+   它是由公司还是社区驱动的？

+   它提供质量的文档吗？

+   它有稳定且频繁的发布周期吗？

+   它提供某种官方形式的认证吗？

+   它提供免费和商业支持吗？

+   它有我们可以参加的偶尔研讨会吗？

+   它对社区参与开放吗，这样我们就可以提交功能和补丁？

+   它是一个全栈还是粘合类型的框架？

+   它是按照惯例还是配置驱动的？

+   它提供足够的库来让您开始（安全性、验证、模板化、数据库抽象、ORM、路由、国际化等）吗？

+   核心框架是否可以进行足够的扩展和重写，以使其更具未来性，以适应可能的变化？

有许多成熟的 PHP 框架和库，因此选择并不容易。这些框架和库中的大多数仍然需要完全跟上 PHP 7 中添加的最新功能。

在接下来的章节中，我们将探讨常见的设计模式以及如何在 PHP 中集成它们。


# 第二章：GoF 设计模式

有一些因素使得一个优秀的软件开发者。设计模式的知识和使用就是其中之一。设计模式使开发者能够使用众所周知的名称来进行各种软件交互。无论是 PHP、Python、C#、Ruby 还是其他任何语言的开发者，设计模式都为经常发生的软件问题提供了与语言无关的解决方案。

设计模式的概念于 1994 年出现，作为《可重用面向对象软件的元素》一书的一部分。该书详细介绍了 23 种不同的设计模式，由 Erich Gamma、Richard Helm、Ralph Johnson 和 John Vlissides 四位作者撰写。这些作者通常被称为**四人帮**（**GoF**），所提出的设计模式有时被称为 GoF 设计模式。如今，两十多年后，设计可扩展、可重用、可维护和可适应的软件几乎不可能不将设计模式作为实现的一部分。

本章将介绍三种设计模式：

+   创造性

+   结构性

+   行为

在本章中，我们不会深入研究每一个模式的理论，因为单独讨论这些内容就是一本完整的书。接下来，我们将更多地关注每种模式的简单 PHP 实现示例，以便更直观地了解事物。

# 创建型模式

创建型模式，顾名思义，为我们创建*对象*，因此我们不必直接实例化它们。实现创建模式为我们的应用程序提供了一定程度的灵活性，应用程序本身可以决定在特定时间实例化哪些对象。以下是我们归类为创建型模式的模式列表：

+   抽象工厂模式

+   建造者模式

+   工厂方法模式

+   原型模式

+   单例模式

### 注意

有关创建型设计模式的更多信息，请参见[`en.wikipedia.org/wiki/Creational_pattern`](https://en.wikipedia.org/wiki/Creational_pattern)。

## 抽象工厂模式

构建可移植应用程序需要很高的依赖封装级别。抽象工厂通过*抽象化相关或依赖对象的创建*来实现这一点。客户端永远不会直接创建这些平台对象，工厂会为他们创建，使得可以在不改变使用它们的代码的情况下交换具体实现，甚至在运行时。

以下是可能的抽象工厂模式实现示例：

```php
interface Button {
    public function render();
}

interface GUIFactory {
    public function createButton();
}

class SubmitButton implements Button {
    public function render() {
        echo 'Render Submit Button';
    }
}

class ResetButton implements Button {
    public function render() {
        echo 'Render Reset Button';
    }
}

class SubmitFactory implements GUIFactory {
    public function createButton() {
        return new SubmitButton();
    }
}

class ResetFactory implements GUIFactory {
    public function createButton() {
        return new ResetButton();
    }
}

// Client
$submitFactory = new SubmitFactory();
$button = $submitFactory->createButton();
$button->render();

$resetFactory = new ResetFactory();
$button = $resetFactory->createButton();
$button->render();
```

我们首先创建了一个接口`Button`，然后由我们的`SubmitButton`和`ResetButton`具体类来实现。`GUIFactory`和`ResetFactory`实现了`GUIFactory`接口，该接口指定了`createButton`方法。然后客户端简单地实例化工厂并调用`createButton`，返回一个适当的按钮实例，我们称之为`render`方法。

## 建造者模式

建造者模式将复杂对象的构建与其表示分离，使得相同的构建过程可以创建不同的表示。虽然一些创造模式在一次调用中构造产品，但建造者模式在主管的控制下逐步进行。

以下是建造者模式实现的示例：

```php
class Car {
    public function getWheels() {
        /* implementation... */
    }

    public function setWheels($wheels) {
        /* implementation... */
    }

    public function getColour($colour) {
        /* implementation... */
    }

    public function setColour() {
        /* implementation... */
    }
}

interface CarBuilderInterface {
    public function setColour($colour);
    public function setWheels($wheels);
    public function getResult();
}

class CarBuilder implements CarBuilderInterface {
    private $car;

    public function __construct() {
        $this->car = new Car();
    }

    public function setColour($colour) {
        $this->car->setColour($colour);
        return $this;
    }

    public function setWheels($wheels) {
        $this->car->setWheels($wheels);
        return $this;
    }

    public function getResult() {
        return $this->car;
    }
}

class CarBuildDirector {
    private $builder;

    public function __construct(CarBuilder $builder) {
        $this->builder = $builder;
    }

    public function build() {
        $this->builder->setColour('Red');
        $this->builder->setWheels(4);

        return $this;
    }

    public function getCar() {
        return $this->builder->getResult();
    }
}

// Client
$carBuilder = new CarBuilder();
$carBuildDirector = new CarBuildDirector($carBuilder);
$car = $carBuildDirector->build()->getCar();
```

我们首先创建了一个具体的`Car`类，其中包含定义汽车一些基本特征的几种方法。然后我们创建了一个`CarBuilderInterface`，它将控制其中一些特征并获得最终结果（`car`）。具体类`CarBuilder`然后实现了`CarBuilderInterface`，接着是具体的`CarBuildDirector`类，它定义了构建和`getCar`方法。客户端只需实例化一个新的`CarBuilder`实例，并将其作为构造函数参数传递给一个新的`CarBuildDirector`实例。最后，我们调用`CarBuildDirector`的`build`和`getCar`方法来获得实际的汽车`Car`实例。

## 工厂方法模式

`工厂`方法模式处理创建对象的问题，而无需指定将要创建的对象的确切类。

以下是工厂方法模式实现的示例：

```php
interface Product {
    public function getType();
}

interface ProductFactory {
    public function makeProduct();
}

class SimpleProduct implements Product {
    public function getType() {
        return 'SimpleProduct';
    }
}

class SimpleProductFactory implements ProductFactory {
    public function makeProduct() {
        return new SimpleProduct();
    }
}

/* Client */
$factory = new SimpleProductFactory();
$product = $factory->makeProduct();
echo $product->getType(); //outputs: SimpleProduct
```

我们首先创建了一个`ProductFactory`和`Product`接口。`SimpleProductFactory`实现了`ProductFactory`并通过其`makeProduct`方法返回新的`product`实例。`SimpleProduct`类实现了`Product`，并返回产品类型。最后，客户端创建了`SimpleProductFactory`的实例，并在其上调用`makeProduct`方法。`makeProduct`返回`Product`的实例，其`getType`方法返回`SimpleProduct`字符串。

## 原型模式

原型模式通过克隆来复制其他对象。这意味着我们不是使用`new`关键字来实例化新对象。PHP 提供了一个`clone`关键字，它可以对对象进行浅复制，从而提供了非常直接的原型模式实现。浅复制不会复制引用，只会将值复制到新对象。我们还可以利用我们的类上的魔术`__clone`方法来实现更健壮的克隆行为。

以下是原型模式实现的示例：

```php
class User {
    public $name;
    public $email;
}

class Employee extends User {
    public function __construct() {
        $this->name = 'Johhn Doe';
        $this->email = 'john.doe@fake.mail';
    }

    public function info() {
        return sprintf('%s, %s', $this->name, $this->email);
    }

    public function __clone() {
        /* additional changes for (after)clone behavior? */
    }
}

$employee = new Employee();
echo $employee->info();

$director = clone $employee;
$director->name = 'Jane Doe';
$director->email = 'jane.doe@fake.mail';
echo $director->info(); //outputs: Jane Doe, jane.doe@fake.mail
```

我们首先创建了一个简单的`User`类。然后`Employee`类扩展了`User`类，并在其构造函数中设置了`name`和`email`。客户端通过`new`关键字实例化了`Employee`，并将其克隆到`director`变量中。`$director`变量现在是一个新实例，不是通过`new`关键字创建的，而是通过克隆使用`clone`关键字创建的。在`$director`上更改`name`和`email`不会影响`$employee`。

## 单例模式

单例模式的目的是限制类的实例化为*单个*对象。它通过在类中创建一个方法来实现，如果不存在对象实例，则创建该类的新实例。如果对象实例已经存在，则该方法简单地返回对现有对象的引用。

以下是单例模式实现的示例：

```php
class Logger {
    private static $instance;

    public static function getInstance() {
        if (!isset(self::$instance)) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    public function logNotice($msg) {
        return 'logNotice: ' . $msg;
    }

    public function logWarning($msg) {
        return 'logWarning: ' . $msg;
    }

    public function logError($msg) {
        return 'logError: ' . $msg;
    }
}

// Client
echo Logger::getInstance()->logNotice('test-notice');
echo Logger::getInstance()->logWarning('test-warning');
echo Logger::getInstance()->logError('test-error');
// Outputs:
// logNotice: test-notice
// logWarning: test-warning
// logError: test-error
```

我们首先创建了一个带有静态`$instance`成员和`getInstance`方法的`Logger`类，该方法始终返回类的单个实例。然后我们添加了一些示例方法，以演示客户端在单个实例上执行各种方法。

# 结构模式

结构模式处理类和对象的组合。使用接口或抽象类和方法，它们定义了组合对象的方式，从而获得新功能。以下是我们将作为结构模式进行分类的模式列表：

+   适配器模式

+   桥接模式

+   组合模式

+   装饰器

+   外观模式

+   享元模式

+   代理

### 注意

有关结构设计模式的更多信息，请参阅[`en.wikipedia.org/wiki/Structural_pattern`](https://en.wikipedia.org/wiki/Structural_pattern)。

## 适配器模式

适配器模式允许使用现有类的接口来自另一个接口，基本上通过将一个类的接口转换为另一个类期望的接口，帮助两个不兼容的接口一起工作。

以下是适配器模式实现的示例：

```php
class Stripe {
    public function capturePayment($amount) {
        /* Implementation... */
    }

    public function authorizeOnlyPayment($amount) {
        /* Implementation... */
    }

    public function cancelAmount($amount) {
        /* Implementation... */
    }
}

interface PaymentService {
    public function capture($amount);
    public function authorize($amount);
    public function cancel($amount);
}

class StripePaymentServiceAdapter implements PaymentService {
    private $stripe;

    public function __construct(Stripe $stripe) {
        $this->stripe = $stripe;
    }

    public function capture($amount) {
        $this->stripe->capturePayment($amount);
    }

    public function authorize($amount) {
        $this->stripe->authorizeOnlyPayment($amount);
    }

    public function cancel($amount) {
        $this->stripe->cancelAmount($amount);
    }
}

// Client
$stripe = new StripePaymentServiceAdapter(new Stripe());
$stripe->authorize(49.99);
$stripe->capture(19.99);
$stripe->cancel(9.99);
```

我们首先创建了一个具体的`Stripe`类。然后定义了`PaymentService`接口，其中包含一些基本的支付处理方法。`StripePaymentServiceAdapter`实现了`PaymentService`接口，提供了支付处理方法的具体实现。最后，客户端实例化了`StripePaymentServiceAdapter`并执行了支付处理方法。

## 桥接模式

桥接模式用于当我们想要将类或抽象与其实现解耦时，允许它们独立变化。当类和其实现经常变化时，这是很有用的。

以下是桥接模式实现的示例：

```php
interface MailerInterface {
    public function setSender(MessagingInterface $sender);
    public function send($body);
}

abstract class Mailer implements MailerInterface {
    protected $sender;

    public function setSender(MessagingInterface $sender) {
        $this->sender = $sender;
    }
}

class PHPMailer extends Mailer {
    public function send($body) {
        $body .= "\n\n Sent from a phpmailer.";
        return $this->sender->send($body);
    }
}

class SwiftMailer extends Mailer {
    public function send($body) {
        $body .= "\n\n Sent from a SwiftMailer.";
        return $this->sender->send($body);
    }
}

interface MessagingInterface {
    public function send($body);
}

class TextMessage implements MessagingInterface {
    public function send($body) {
        echo 'TextMessage > send > $body: ' . $body;
    }
}

class HtmlMessage implements MessagingInterface {
    public function send($body) {
        echo 'HtmlMessage > send > $body: ' . $body;
    }
}

// Client
$phpmailer = new PHPMailer();
$phpmailer->setSender(new TextMessage());
$phpmailer->send('Hi!');

$swiftMailer = new SwiftMailer();
$swiftMailer->setSender(new HtmlMessage());
$swiftMailer->send('Hello!');
```

我们首先创建了一个`MailerInterface`。具体的`Mailer`类然后实现了`MailerInterface`，为`PHPMailer`和`SwiftMailer`提供了一个基类。然后我们定义了`MessagingInterface`，它由`TextMessage`和`HtmlMessage`类实现。最后，客户端实例化`PHPMailer`和`SwiftMailer`，在调用`send`方法之前传递`TextMessage`和`HtmlMessage`的实例。

## 组合模式

组合模式是关于将对象的层次结构视为单个对象，通过一个公共接口。对象被组合成三个结构，客户端对底层结构的更改毫不知情，因为它只消耗公共接口。

以下是组合模式实现的示例：

```php
interface Graphic {
    public function draw();
}

class CompositeGraphic implements Graphic {
    private $graphics = array();

    public function add($graphic) {
        $objId = spl_object_hash($graphic);
        $this->graphics[$objId] = $graphic;
    }

    public function remove($graphic) {
        $objId = spl_object_hash($graphic);
        unset($this->graphics[$objId]);
    }

    public function draw() {
        foreach ($this->graphics as $graphic) {
            $graphic->draw();
        }
    }
}

class Circle implements Graphic {
    public function draw()
    {
        echo 'draw-circle';
    }
}

class Square implements Graphic {
    public function draw() {
        echo 'draw-square';
    }
}

class Triangle implements Graphic {
    public function draw() {
        echo 'draw-triangle';
    }
}

$circle = new Circle();
$square = new Square();
$triangle = new Triangle();

$compositeObj1 = new CompositeGraphic();
$compositeObj1->add($circle);
$compositeObj1->add($triangle);
$compositeObj1->draw();

$compositeObj2 = new CompositeGraphic();
$compositeObj2->add($circle);
$compositeObj2->add($square);
$compositeObj2->add($triangle);
$compositeObj2->remove($circle);
$compositeObj2->draw();
```

我们首先创建了一个`Graphic`接口。然后创建了`CompositeGraphic`、`Circle`、`Square`和`Triangle`，它们都实现了`Graphic`接口。除了实现`Graphic`接口的`draw`方法之外，`CompositeGraphic`还添加了另外两个方法，用于跟踪添加到其中的图形的内部集合。然后客户端实例化所有这些`Graphic`类，将它们全部添加到`CompositeGraphic`中，然后调用`draw`方法。

## 装饰器模式

装饰器模式允许向单个对象实例添加行为，而不影响同一类的其他实例的行为。我们可以定义多个装饰器，每个装饰器都添加新功能。

以下是装饰器模式实现的示例：

```php
interface LoggerInterface {
    public function log($message);
}

class Logger implements LoggerInterface {
    public function log($message) {
        file_put_contents('app.log', $message, FILE_APPEND);
    }
}

abstract class LoggerDecorator implements LoggerInterface {
    protected $logger;

    public function __construct(Logger $logger) {
        $this->logger = $logger;
    }

    abstract public function log($message);
}

class ErrorLoggerDecorator extends LoggerDecorator {
    public function log($message) {
        $this->logger->log('ERROR: ' . $message);
    }

}

class WarningLoggerDecorator extends LoggerDecorator {
    public function log($message) {
        $this->logger->log('WARNING: ' . $message);
    }
}

class NoticeLoggerDecorator extends LoggerDecorator {
    public function log($message) {
        $this->logger->log('NOTICE: ' . $message);
    }
}

$logger = new Logger();
$logger->log('Resource not found.');

$logger = new Logger();
$logger = new ErrorLoggerDecorator($logger);
$logger->log('Invalid user role.');

$logger = new Logger();
$logger = new WarningLoggerDecorator($logger);
$logger->log('Missing address parameters.');

$logger = new Logger();
$logger = new NoticeLoggerDecorator($logger);
$logger->log('Incorrect type provided.');
```

我们首先创建了一个`LoggerInterface`，其中包含一个简单的`log`方法。然后定义了`Logger`和`LoggerDecorator`，它们都实现了`LoggerInterface`。然后是`ErrorLoggerDecorator`、`WarningLoggerDecorator`和`NoticeLoggerDecorator`，它们实现了`LoggerDecorator`。最后，客户端部分实例化了`logger`三次，并传递了不同的装饰器。

## 外观模式

外观模式用于通过一个更简单的接口简化大型系统的复杂性。它通过为客户端提供方便的方法来执行大多数常见任务，通过一个单一的包装类来实现。

以下是外观模式实现的示例：

```php
class Product {
    public function getQty() {
        // Implementation
    }
}

class QuickOrderFacade {
    private $product = null;
    private $orderQty = null;

    public function __construct($product, $orderQty) {
        $this->product = $product;
        $this->orderQty = $orderQty;
    }

    public function generateOrder() {
        if ($this->qtyCheck()) {
            $this->addToCart();
            $this->calculateShipping();
            $this->applyDiscount();
            $this->placeOrder();
        }
    }

    private function addToCart() {
        // Implementation...
    }

    private function qtyCheck() {
        if ($this->product->getQty() > $this->orderQty) {
            return true;
        } else {
            return true;
        }
    }

    private function calculateShipping() {
        // Implementation...
    }

    private function applyDiscount() {
        // Implementation...
    }

    private function placeOrder() {
        // Implementation...
    }
}

// Client
$order = new QuickOrderFacade(new Product(), $qty);
$order->generateOrder();
```

我们首先创建了一个`Product`类，其中包含一个`getQty`方法。然后创建了一个`QuickOrderFacade`类，它通过`constructor`接受`product`实例和数量，并进一步提供了`generateOrder`方法，该方法汇总了所有生成订单的操作。最后，客户端实例化了`product`，将其传递给`QuickOrderFacade`的实例，并调用了其上的`generateOrder`。

## 享元模式

享元模式关乎性能和资源的减少，在相似对象之间尽可能共享数据。这意味着相同的类实例在实现中是共享的。当预计会创建大量相同类的实例时，这种方法效果最佳。

以下是享元模式实现的示例：

```php
interface Shape {
    public function draw();
}

class Circle implements Shape {
    private $colour;
    private $radius;

    public function __construct($colour) {
        $this->colour = $colour;
    }

    public function draw() {
        echo sprintf('Colour %s, radius %s.', $this->colour, $this->radius);
    }

    public function setRadius($radius) {
        $this->radius = $radius;
    }
}

class ShapeFactory {
    private $circleMap;

    public function getCircle($colour) {
        if (!isset($this->circleMap[$colour])) {
            $circle = new Circle($colour);
            $this->circleMap[$colour] = $circle;
        }

        return $this->circleMap[$colour];
    }
}

// Client
$shapeFactory = new ShapeFactory();
$circle = $shapeFactory->getCircle('yellow');
$circle->setRadius(10);
$circle->draw();

$shapeFactory = new ShapeFactory();
$circle = $shapeFactory->getCircle('orange');
$circle->setRadius(15);
$circle->draw();

$shapeFactory = new ShapeFactory();
$circle = $shapeFactory->getCircle('yellow');
$circle->setRadius(20);
$circle->draw();
```

我们首先创建了一个`Shape`接口，其中包含一个`draw`方法。然后我们定义了实现`Shape`接口的`Circle`类，接着是`ShapeFactory`类。在`ShapeFactory`中，`getCircle`方法根据`color`选项返回一个新的`Circle`实例。最后，客户端实例化了几个`ShapeFactory`对象，并传入不同的颜色到`getCircle`方法中。

## 代理模式

代理设计模式作为原始对象的接口在后台运行。它可以充当简单的转发包装器，甚至在包装的对象周围提供额外的功能。额外添加的功能示例可能是懒加载或缓存，可以弥补原始对象的资源密集操作。

以下是代理模式实现的示例：

```php
interface ImageInterface {
    public function draw();
}

class Image implements ImageInterface {
    private $file;

    public function __construct($file) {
        $this->file = $file;
        sleep(5); // Imagine resource intensive image load
    }

    public function draw() {
        echo 'image: ' . $this->file;
    }
}

class ProxyImage implements ImageInterface {
    private $image = null;
    private $file;

    public function __construct($file) {
        $this->file = $file;
    }

    public function draw() {
        if (is_null($this->image)) {
            $this->image = new Image($this->file);
        }

        $this->image->draw();
    }
}

// Client
$image = new Image('image.png'); // 5 seconds
$image->draw();

$image = new ProxyImage('image.png'); // 0 seconds
$image->draw();
```

我们首先创建了一个`ImageInterface`，其中包含一个`draw`方法。然后我们定义了`Image`和`ProxyImage`类，它们都扩展了`ImageInterface`。在`Image`类的`__construct`中，我们使用`sleep`方法模拟了**资源密集**的操作。最后，客户端实例化了`Image`和`ProxyImage`，展示了两者之间的执行时间差异。

# 行为模式

行为模式解决了各种对象之间通信的挑战。它们描述了不同对象和类如何相互发送消息以实现事情发生。以下是我们归类为行为模式的模式列表：

+   责任链

+   命令

+   解释器

+   迭代器

+   中介者

+   备忘录

+   观察者

+   状态

+   策略

+   模板方法

+   访问者

## 责任链模式

责任链模式通过以链式方式启用多个对象处理请求，将请求的发送者与接收者解耦。各种类型的处理对象可以动态添加到链中。使用递归组合链允许无限数量的处理对象。

以下是责任链模式实现的示例：

```php
abstract class SocialNotifier {
    private $notifyNext = null;

    public function notifyNext(SocialNotifier $notifier) {
        $this->notifyNext = $notifier;
        return $this->notifyNext;
    }

    final public function push($message) {
        $this->publish($message);

        if ($this->notifyNext !== null) {
            $this->notifyNext->push($message);
        }
    }

    abstract protected function publish($message);
}

class TwitterSocialNotifier extends SocialNotifier {
    public function publish($message) {
        // Implementation...
    }
}

class FacebookSocialNotifier extends SocialNotifier {
    protected function publish($message) {
        // Implementation...
    }
}

class PinterestSocialNotifier extends SocialNotifier {
    protected function publish($message) {
        // Implementation...
    }
}

// Client
$notifier = new TwitterSocialNotifier();

$notifier->notifyNext(new FacebookSocialNotifier())
    ->notifyNext(new PinterestSocialNotifier());

$notifier->push('Awesome new product available!');
```

我们首先创建了一个抽象的`SocialNotifier`类，其中包含抽象方法`publish`，`notifyNext`和`push`方法的实现。然后我们定义了`TwitterSocialNotifier`，`FacebookSocialNotifier`和`PinterestSocialNotifier`，它们都扩展了抽象的`SocialNotifier`。客户端首先实例化了`TwitterSocialNotifier`，然后进行了两次`notifyNext`调用，传递了两种其他`notifier`类型的实例，然后调用了最终的`push`方法。

## 命令模式

命令模式将执行特定操作的对象与知道如何使用它的对象解耦。它通过封装后续执行某个动作所需的所有相关信息来实现。这意味着关于对象、方法名称和方法参数的信息。

以下是命令模式的实现示例：

```php
interface LightBulbCommand {
    public function execute();
}

class LightBulbControl {
    public function turnOn() {
        echo 'LightBulb turnOn';
    }

    public function turnOff() {
        echo 'LightBulb turnOff';
    }
}

class TurnOnLightBulb implements LightBulbCommand {
    private $lightBulbControl;

    public function __construct(LightBulbControl $lightBulbControl) {
        $this->lightBulbControl = $lightBulbControl;
    }

    public function execute() {
        $this->lightBulbControl->turnOn();
    }
}

class TurnOffLightBulb implements LightBulbCommand {
    private $lightBulbControl;

    public function __construct(LightBulbControl $lightBulbControl) {
        $this->lightBulbControl = $lightBulbControl;
    }

    public function execute() {
        $this->lightBulbControl->turnOff();
    }
}

// Client
$command = new TurnOffLightBulb(new LightBulbControl());
$command->execute();
```

我们首先创建了一个`LightBulbCommand`接口。然后我们定义了`LightBulbControl`类，提供了两个简单的`turnOn` / `turnOff`方法。然后我们定义了实现`LightBulbCommand`接口的`TurnOnLightBulb`和`TurnOffLightBulb`类。最后，客户端实例化了`TurnOffLightBulb`对象，并在其上调用了`execute`方法。

## 解释器模式

解释器模式指定了如何评估语言语法或表达式。我们定义了语言语法的表示以及解释器。语言语法的表示使用复合类层次结构，其中规则映射到类。然后解释器使用表示来解释语言中的表达式。

以下是解释器模式实现的示例：

```php
interface MathExpression
{
    public function interpret(array $values);
}

class Variable implements MathExpression {
    private $char;

    public function __construct($char) {
        $this->char = $char;
    }

    public function interpret(array $values) {
        return $values[$this->char];
    }
}

class Literal implements MathExpression {
    private $value;

    public function __construct($value) {
        $this->value = $value;
    }

    public function interpret(array $values) {
        return $this->value;
    }
}

class Sum implements MathExpression {
    private $x;
    private $y;

    public function __construct(MathExpression $x, MathExpression $y) {
        $this->x = $x;
        $this->y = $y;
    }

    public function interpret(array $values) {
        return $this->x->interpret($values) + $this->y->interpret($values);
    }
}

class Product implements MathExpression {
    private $x;
    private $y;

    public function __construct(MathExpression $x, MathExpression $y) {
        $this->x = $x;
        $this->y = $y;
    }

    public function interpret(array $values) {
        return $this->x->interpret($values) * $this->y->interpret($values);
    }
}

// Client
$expression = new Product(
    new Literal(5),
    new Sum(
        new Variable('c'),
        new Literal(2)
    )
);

echo $expression->interpret(array('c' => 3)); // 25
```

我们首先创建了一个`MathExpression`接口，具有一个`interpret`方法。然后添加了`Variable`、`Literal`、`Sum`和`Product`类，它们都实现了`MathExpression`接口。然后客户端从`Product`类实例化，将`Literal`和`Sum`的实例传递给它，并最后调用`interpret`方法。

## 迭代器模式

迭代器模式用于遍历容器并访问其元素。换句话说，一个类变得能够遍历另一个类的元素。PHP 原生支持迭代器，作为内置的`\Iterator`和`\IteratorAggregate`接口的一部分。

以下是迭代器模式实现的示例：

```php
class ProductIterator implements \Iterator {
    private $position = 0;
    private $productsCollection;

    public function __construct(ProductCollection $productsCollection) {
        $this->productsCollection = $productsCollection;
    }

    public function current() {
        return $this->productsCollection->getProduct($this->position);
    }

    public function key() {
        return $this->position;
    }

    public function next() {
        $this->position++;
    }

    public function rewind() {
        $this->position = 0;
    }

    public function valid() {
        return !is_null($this->productsCollection->getProduct($this->position));
    }
}

class ProductCollection implements \IteratorAggregate {
    private $products = array();

    public function getIterator() {
        return new ProductIterator($this);
    }

    public function addProduct($string) {
        $this->products[] = $string;
    }

    public function getProduct($key) {
        if (isset($this->products[$key])) {
            return $this->products[$key];
        }
        return null;
    }

    public function isEmpty() {
        return empty($products);
    }
}

$products = new ProductCollection();
$products->addProduct('T-Shirt Red');
$products->addProduct('T-Shirt Blue');
$products->addProduct('T-Shirt Green');
$products->addProduct('T-Shirt Yellow');

foreach ($products as $product) {
    var_dump($product);
}
```

我们首先创建了一个实现标准 PHP`\Iterator`接口的`ProductIterator`。然后添加了实现标准 PHP`\IteratorAggregate`接口的`ProductCollection`。客户端创建了一个`ProductCollection`的实例，通过`addProduct`方法调用将值堆叠到其中，并循环遍历整个集合。

## 中介者模式

我们的软件中有更多的类，它们的通信变得更加复杂。中介者模式通过将复杂性封装到中介者对象中来解决这个问题。对象不再直接通信，而是通过中介者对象，从而降低了整体耦合度。

以下是中介者模式实现的示例：

```php
interface MediatorInterface {
    public function fight();
    public function talk();
    public function registerA(ColleagueA $a);
    public function registerB(ColleagueB $b);
}

class ConcreteMediator implements MediatorInterface {
    protected $talk; // ColleagueA
    protected $fight; // ColleagueB

    public function registerA(ColleagueA $a) {
        $this->talk = $a;
    }

    public function registerB(ColleagueB $b) {
        $this->fight = $b;
    }

    public function fight() {
        echo 'fighting...';
    }

    public function talk() {
        echo 'talking...';
    }
}

abstract class Colleague {
    protected $mediator; // MediatorInterface
    public abstract function doSomething();
}

class ColleagueA extends Colleague {

    public function __construct(MediatorInterface $mediator) {
        $this->mediator = $mediator;
        $this->mediator->registerA($this);
    }

public function doSomething() {
        $this->mediator->talk();
}
}

class ColleagueB extends Colleague {

    public function __construct(MediatorInterface $mediator) {
        $this->mediator = $mediator;
        $this->mediator->registerB($this);
    }

    public function doSomething() {
        $this->mediator->fight();
    }
}

// Client
$mediator = new ConcreteMediator();
$talkColleague = new ColleagueA($mediator);
$fightColleague = new ColleagueB($mediator);

$talkColleague->doSomething();
$fightColleague->doSomething();
```

我们首先创建了一个具有多个方法的`MediatorInterface`，由`ConcreteMediator`类实现。然后我们定义了抽象类`Colleague`，强制在以下`ColleagueA`和`ColleagueB`类上实现`doSomething`方法。客户端首先实例化`ConcreteMediator`，然后将其实例传递给`ColleagueA`和`ColleagueB`的实例，然后调用`doSomething`方法。

## 备忘录模式

备忘录模式提供了对象恢复功能。实现是通过三个不同的对象完成的；原始者、caretaker 和 memento，其中原始者是保留内部状态以便以后恢复的对象。

以下是备忘录模式实现的示例：

```php
class Memento {
    private $state;

    public function __construct($state) {
        $this->state = $state;
    }

    public function getState() {
        return $this->state;
    }
}

class Originator {
    private $state;

    public function setState($state) {
        return $this->state = $state;
    }

    public function getState() {
        return $this->state;
    }

    public function saveToMemento() {
        return new Memento($this->state);
    }

    public function restoreFromMemento(Memento $memento) {
        $this->state = $memento->getState();
    }
}

// Client - Caretaker
$savedStates = array();

$originator = new Originator();
$originator->setState('new');
$originator->setState('pending');
$savedStates[] = $originator->saveToMemento();
$originator->setState('processing');
$savedStates[] = $originator->saveToMemento();
$originator->setState('complete');
$originator->restoreFromMemento($savedStates[1]);
echo $originator->getState(); // processing
```

我们首先创建了一个`Memento`类，它通过`getState`方法提供对象的当前状态。然后我们定义了`Originator`类，将状态推送到`Memento`。最后，客户端通过实例化`Originator`来扮演`caretaker`的角色，在其少数状态之间进行切换，保存并从`memento`中恢复它们。

## 观察者模式

观察者模式实现了对象之间的一对多依赖关系。持有依赖项列表的对象称为**subject**，而依赖项称为**observers**。当主题对象改变状态时，所有依赖项都会被通知并自动更新。

以下是观察者模式实现的示例：

```php
class Customer implements \SplSubject {
    protected $data = array();
    protected $observers = array();

    public function attach(\SplObserver $observer) {
        $this->observers[] = $observer;
    }

    public function detach(\SplObserver $observer) {
        $index = array_search($observer, $this->observers);

        if ($index !== false) {
            unset($this->observers[$index]);
        }
    }

    public function notify() {
        foreach ($this->observers as $observer) {
            $observer->update($this);
            echo 'observer updated';
        }
    }

    public function __set($name, $value) {
        $this->data[$name] = $value;

        // notify the observers, that user has been updated
        $this->notify();
    }
}

class CustomerObserver implements \SplObserver {
    public function update(\SplSubject $subject) {
        /* Implementation... */
    }
}

// Client
$user = new Customer();
$customerObserver = new CustomerObserver();
$user->attach($customerObserver);

$user->name = 'John Doe';
$user->email = 'john.doe@fake.mail';
```

我们首先创建了一个实现标准 PHP`\SplSubject`接口的`Customer`类。然后定义了一个实现标准 PHP`\SplObserver`接口的`CustomerObserver`类。最后，客户端实例化了`Customer`和`CustomerObserver`对象，并将`CustomerObserver`对象附加到`Customer`上。然后`observer`捕捉到`name`和`email`属性的任何更改。

## 状态模式

状态模式封装了基于其内部状态的相同对象的不同行为，使对象看起来好像已经改变了它的类。

以下是状态模式实现的示例：

```php
interface Statelike {
    public function writeName(StateContext $context, $name);
}

class StateLowerCase implements Statelike {
    public function writeName(StateContext $context, $name) {
        echo strtolower($name);
        $context->setState(new StateMultipleUpperCase());
    }
}

class StateMultipleUpperCase implements Statelike {
    private $count = 0;

    public function writeName(StateContext $context, $name) {
        $this->count++;
        echo strtoupper($name);
        /* Change state after two invocations */
        if ($this->count > 1) {
            $context->setState(new StateLowerCase());
        }
    }
}

class StateContext {
    private $state;

    public function setState(Statelike $state) {
        $this->state = $state;
    }

    public function writeName($name) {
        $this->state->writeName($this, $name);
    }
}

// Client
$stateContext = new StateContext();
$stateContext->setState(new StateLowerCase());
$stateContext->writeName('Monday');
$stateContext->writeName('Tuesday');
$stateContext->writeName('Wednesday');
$stateContext->writeName('Thursday');
$stateContext->writeName('Friday');
$stateContext->writeName('Saturday');
$stateContext->writeName('Sunday');
```

我们首先创建了一个`Statelike`接口，然后是实现该接口的`StateLowerCase`和`StateMultipleUpperCase`。`StateMultipleUpperCase`在其`writeName`中添加了一些计数逻辑，因此在两次调用后会启动新状态。然后我们定义了`StateContext`类，我们将使用它来切换上下文。最后，客户端实例化了`StateContext`，并通过`setState`方法将`StateLowerCase`的实例传递给它，然后调用了几次`writeName`方法。

## 策略模式

策略模式定义了一组算法，每个算法都被封装并与该组内的其他成员交换使用。

以下是策略模式实现的示例：

```php
interface PaymentStrategy {
    public function pay($amount);
}

class StripePayment implements PaymentStrategy {
    public function pay($amount) {
        echo 'StripePayment...';
    }

}

class PayPalPayment implements PaymentStrategy {
    public function pay($amount) {
        echo 'PayPalPayment...';
    }
}

class Checkout {
    private $amount = 0;

    public function __construct($amount = 0) {
        $this->amount = $amount;
    }

    public function capturePayment() {
        if ($this->amount > 99.99) {
            $payment = new PayPalPayment();
        } else {
            $payment = new StripePayment();
        }

        $payment->pay($this->amount);
    }
}

$checkout = new Checkout(49.99);
$checkout->capturePayment(); // StripePayment...

$checkout = new Checkout(199.99);
$checkout->capturePayment(); // PayPalPayment...
```

我们首先创建了一个`PaymentStrategy`接口，然后是实现它的具体类`StripePayment`和`PayPalPayment`。然后我们定义了`Checkout`类，在`capturePayment`方法中加入了一些决策逻辑。最后，客户端通过构造函数传递一定金额来实例化`Checkout`。根据金额，`Checkout`在调用`capturePayment`时内部触发一个或另一个`payment`。

## 模板模式

模板设计模式定义了算法在方法中的程序骨架。它让我们通过类覆盖的方式重新定义算法的某些步骤，而不真正改变算法的结构。

以下是模板模式实现的示例：

```php
abstract class Game {
    private $playersCount;

    abstract function initializeGame();
    abstract function makePlay($player);
    abstract function endOfGame();
    abstract function printWinner();

    public function playOneGame($playersCount)
    {
        $this->playersCount = $playersCount;
        $this->initializeGame();
        $j = 0;
        while (!$this->endOfGame()) {
            $this->makePlay($j);
            $j = ($j + 1) % $playersCount;
        }
        $this->printWinner();
    }
}

class Monopoly extends Game {
    public function initializeGame() {
        // Implementation...
    }

    public function makePlay($player) {
        // Implementation...
    }

    public function endOfGame() {
        // Implementation...
    }

    public function printWinner() {
        // Implementation...
    }
}

class Chess extends Game {
    public function  initializeGame() {
        // Implementation...
    }

    public function  makePlay($player) {
        // Implementation...
    }

    public function  endOfGame() {
        // Implementation...
    }

    public function  printWinner() {
        // Implementation...
    }
}

$game = new Chess();
$game->playOneGame(2);

$game = new Monopoly();
$game->playOneGame(4);
```

我们首先创建了一个提供了封装游戏玩法的所有抽象方法的抽象`Game`类。然后我们定义了`Monopoly`和`Chess`类，它们都是从`Game`类继承的，为每个游戏实现了特定的游戏玩法方法。客户端只需实例化`Monopoly`和`Chess`对象，然后在每个对象上调用`playOneGame`方法。

## 访问者模式

访问者设计模式是一种将算法与其操作的对象结构分离的方法。因此，我们能够向现有的对象结构添加新的操作，而不实际修改这些结构。

以下是访问者模式实现的示例：

```php
interface RoleVisitorInterface {
    public function visitUser(User $role);
    public function visitGroup(Group $role);
}

class RolePrintVisitor implements RoleVisitorInterface {
    public function visitGroup(Group $role) {
        echo 'Role: ' . $role->getName();
    }

    public function visitUser(User $role) {
        echo 'Role: ' . $role->getName();
    }
}

abstract class Role {
    public function accept(RoleVisitorInterface $visitor) {
        $klass = get_called_class();
        preg_match('#([^\\\\]+)$#', $klass, $extract);
        $visitingMethod = 'visit' . $extract[1];

        if (!method_exists(__NAMESPACE__ . '\RoleVisitorInterface', $visitingMethod)) {
            throw new \InvalidArgumentException("The visitor you provide cannot visit a $klass instance");
        }

        call_user_func(array($visitor, $visitingMethod), $this);
    }
}

class User extends Role {
    protected $name;

    public function __construct($name) {
        $this->name = (string)$name;
    }

    public function getName() {
        return 'User ' . $this->name;
    }
}

class Group extends Role {
    protected $name;

    public function __construct($name) {
        $this->name = (string)$name;
    }

    public function getName() {
        return 'Group: ' . $this->name;
    }
}

$group = new Group('my group');
$user = new User('my user');

$visitor = new RolePrintVisitor;

$group->accept($visitor);
$user->accept($visitor);
```

我们首先创建了一个`RoleVisitorInterface`，然后是实现`RoleVisitorInterface`的`RolePrintVisitor`。然后我们定义了抽象类`Role`，其中包含一个接受`RoleVisitorInterface`参数类型的方法。我们进一步定义了具体的`User`和`Group`类，它们都是从`Role`继承的。客户端实例化了`User`、`Group`和`RolePrintVisitor`，并将`visitor`传递给`User`和`Group`实例的`accept`方法调用。

# 摘要

设计模式是开发人员的一种常见的高级语言。它们使团队成员之间能够以简化的方式交流应用程序设计。了解如何识别和实现设计模式将我们的重点转移到解决业务需求，而不是在代码层面上如何将解决方案粘合在一起。

编码，就像大多数手工制作的学科一样，是你得到你所付出的。虽然实现一些设计模式需要一定的时间，但在较大的项目中不这样做可能会在未来以某种方式追上我们。与“使用框架还是不使用框架”辩论类似，实现正确的设计模式会影响我们代码的*可扩展性*、*可重用性*、*适应性*和*可维护性*。因此，使其更具未来性。

在接下来的章节中，我们将深入研究 SOLID 设计原则及其在软件开发过程中的作用。
