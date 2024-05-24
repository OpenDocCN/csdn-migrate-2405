# 精通 PHP7（一）

> 原文：[`zh.annas-archive.org/md5/c80452b19d206124b22230f7a590b2c3`](https://zh.annas-archive.org/md5/c80452b19d206124b22230f7a590b2c3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

PHP 语言已经存在了相当长的时间。最初只是一组简单的脚本，很快就变成了一种强大的脚本语言。各种框架和平台的崛起为许多开发人员打开了大门。随着时间的推移，PHP 编码标准和众多测试解决方案也应运而生，这使得它在企业中拥有了坚实的立足点。

最新的 PHP 7.1 版本带来了大量的改进，无论是从语法还是整体性能的角度来看。现在是深入了解 PHP 的最佳时机。

在整本书中，我们将涵盖各种主题。这些主题起初可能看起来似乎毫无关联，但它们反映了现今 PHP 开发人员所需具备的最低技能水平。

# 本书涵盖的内容

第一章《全新的 PHP》讨论了引入到 PHP 7.1 语言中的最新变化，其中大部分直接改善了编写代码的质量和优雅。

《第二章》《拥抱标准》向您介绍了 PHP 生态系统中的重要标准。这些标准影响着代码的质量和优雅，使您更接近真正掌握 PHP。

《第三章》《错误处理和日志记录》强调了健壮的错误处理和有效的日志记录的重要性。您将学习如何处理错误和记录真正重要的信息——这两个学科在日常 PHP 编码中经常缺乏适当的关注。

《第四章》《魔术方法背后的魔术》讨论了 PHP 类中可用的魔术函数及其美丽和重要性。您将通过实际示例学习每个 PHP 魔术方法及其含义和用途。

《第五章》《CLI 的领域》探讨了命令行 PHP 及其工具和流程。您将学习如何使用 Symfony 的控制台组件，处理输入/输出流和处理进程。

《第六章》《突出的面向对象编程特性》探讨了将 PHP 转变为强大面向对象编程语言的一些特性。您将学习 PHP 面向对象编程特性背后的重要概念，其中一些可能会逃离日常代码库，因为它们更多地被用作各种框架的构建模块。

《第七章》《优化高性能》讨论了性能优化的重要性，并提供了实用的解决方案。您将了解 PHP 性能优化的细节，其中小的配置更改可能会影响整体应用程序的性能。

《第八章》《无服务器化》概述了使用 PHP 及其在无服务器基础架构中的应用。您将深入了解新兴的无服务器架构，以及通过市场上两种主要 PaaS（平台即服务）解决方案之一来利用它。

《第九章》《响应式编程》涵盖了新兴的响应式编程范式，它已经进入了 PHP 生态系统。您将学习使用同步编码技术编写异步代码的响应式编程的基本原理，通过 icicle 这个生态系统中最主要的库之一。

《第十章》《常见设计模式》专注于设计模式的子集，以及 PHP 编程中最常用的设计模式。您将学习几种重要设计模式的实际实现，这将导致更加优雅、可读、可管理和可测试的代码。

第十一章，“构建服务”，带您了解 REST、SOAP 和 RPC 风格的服务，以及微服务架构。您将学习如何创建 SOAP 和 REST Web 服务器，以及它们各自的客户端对应物。

第十二章，“与数据库一起工作”，解释了 PHP 程序员需要与之交互的几种数据库类型，例如事务 SQL、NoSQL、键值和搜索数据库。您将学习如何查询 MySQL、Mongo 和 Redis 数据库。

第十三章，“解决依赖关系”，探讨了依赖问题以及解决它的方法。您将学习如何使用依赖注入和依赖容器技术解决依赖问题。

第十四章，“使用软件包”，涵盖了 PHP 软件包周围的生态系统，以及它们的创建和分发。您将学习如何查找和使用第三方软件包来丰富应用程序，以及可能创建和分发自己的软件包的简要概述。

第十五章，“测试重要部分”，深入探讨了几种测试类型，强调了其中一种可能比其他更重要的地方。您将学习为 PHP Web 应用程序进行的几种最常见的测试类型。

第十六章，“调试、跟踪和性能分析”，教你使用最常见的工具来调试、跟踪和性能分析 PHP 应用程序。您将学习如何利用多种工具来实现应用程序的有效调试、跟踪和性能分析。

第十七章，“托管、配置和部署”，讨论了为应用程序选择托管方案的决策，以及配置、部署和持续集成流程。您将了解托管解决方案和将代码从本地部署到生产机器的自动化过程之间的区别。

# 本书所需的内容

在本书中，有许多简单而独立的代码和配置示例。要成功运行这些示例，我们可以轻松地使用 Ubuntu 桌面（[`www.ubuntu.com/desktop`](https://www.ubuntu.com/desktop)）和服务器（[`www.ubuntu.com/server`](https://www.ubuntu.com/server)）机器。使用 Windows 或 OSX 机器的人可以在 VirtualBox 中轻松安装 Ubuntu。VirtualBox 的安装说明可以在官方 VirtualBox 页面（[`www.virtualbox.org/`](https://www.virtualbox.org/)）上找到。

# 这本书适合谁

目标读者被假定为中级 PHP 开发人员。本书将带领您踏上成为 PHP 大师的旅程。对 PHP 的扎实知识涵盖了基本语法、类型、变量、常量、表达式、运算符、控制结构和函数等领域。

# 约定

在本书中，您将找到许多区分不同信息类型的文本样式。以下是一些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“对象可能利用 PHP`Serializable`接口，`__sleep()`或`__wakeup()`魔术方法。”

代码块设置如下：

```php
interface RequestInterface extends MessageInterface
{
  public function getRequestTarget();
  public function withRequestTarget($requestTarget);
}

```

任何命令行输入或输出都以以下方式编写：

```php
php index.php
serverless invoke local --function hello 

```

新术语和重要单词以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，会出现在文本中，如：“我们首先点击 Iron.io 仪表板下的新项目按钮。”

警告或重要提示出现在这样的框中。提示和技巧看起来像这样。


# 第一章：全新的 PHP

如今编程语言不胜枚举。新的语言不时地出现。选择适合工作的语言远不止是其功能清单的一部分。有些针对特定的问题领域，其他则试图定位更广泛的使用。这说明软件开发是一个动态的生态系统，语言需要不断适应不断变化的行业，以保持对其消费者的相关性。这些变化对于已经建立的语言（如 PHP）尤其具有挑战性，因为向后兼容性是一个重要的考虑因素。

PHP 最初由 Rasmus Lerdorf 于 1995 年左右创建，起初只是用 C 语言编写的一些 CGI 程序。那时，它是一个简单的脚本解决方案，使开发人员能够轻松构建动态 HTML 页面。无需编译，开发人员可以轻松地将几行代码放入文件中，并在浏览器中查看结果。这使得它早期非常受欢迎。二十年后，PHP 发展成为一个适用于 Web 开发的丰富通用脚本语言。在这些年里，PHP 成功地在每个新版本中提供了令人印象深刻的功能集，同时保持了可靠的向后兼容性水平。如今，其大量的核心扩展最终简化了与文件、会话、Cookie、数据库、Web 服务、加密和许多其他 Web 开发常见功能的工作。它对面向对象编程（OOP）范式的出色支持使其真正与其他领先的行业语言竞争。

PHP 5 十年的统治在 2015 年 12 月 PHP 7 的发布中被推翻。它带来了全新的执行引擎 Zend Engine 3.0，显著提高了性能并减少了内存消耗。这个简单的软件更新现在使我们能够为更多并发用户提供服务，而无需添加任何物理硬件。开发者的接受程度几乎是瞬间的，尤其是因为向后不兼容性很小，使得迁移尽可能轻松。

在本章中，我们将详细了解 PHP 7 和 7.1 版本中引入的一些新功能：

+   标量类型提示

+   返回类型提示

+   匿名类

+   生成器委托

+   生成器返回表达式

+   空合并运算符

+   太空船操作符

+   常量数组

+   统一的变量语法

+   可抛出的

+   组使用声明

+   类常量可见性修饰符

+   捕获多个异常类型

+   可迭代伪类型

+   可空类型

+   无返回类型

正是这些特性注定会在下一代 PHP 框架和库以及我们编写自己的代码的方式上留下深刻印记。

# 标量类型提示

按分类，PHP 是一种动态类型和弱类型的语言。这是两个经常混在一起的不同概念。动态类型的语言不需要在使用之前显式声明变量。弱类型的语言是指变量不属于任何特定的数据类型，也就是说，它的类型可以通过不同的值类型重新分配而改变。

让我们看看以下例子：

```php
// dynamic typed (no specific type defined, directly assigning value)
$name = "Branko"; // string
$salary = 4200.00; // float
$age = 33; // int

// weak typed (variable value reassigned into different type)
$salary = 4200.00; // float
$salary = $salary + "USD"; // float
$salary = $salary . "USD"; // string

```

在上述代码中，我们看到使用了三个不同的变量，其中没有一个预定义为特定类型。我们只是将值声明到它们中。PHP 然后在运行时确定类型。即使确定了变量类型，也可以通过简单地分配另一种类型的值来更改它。这是两个非常强大的概念，当明智地使用时，可以为我们节省大量代码行。

然而，这些强大的特性往往间接地鼓励了不良设计。这在编写函数时特别明显，要么是通过强制函数设计者进行多个数据类型检查，要么是强制他们进行多个函数返回类型。

让我们看看以下例子：

```php
function addTab($tab) {
  if (is_array($tab)) {

  } elseif (is_object($tab)) {

  } elseif (is_string($tab)) {

  } else {

  } 
}

```

考虑到输入参数的类型不确定性，`addTab`函数被迫分支其逻辑。同样，同一个函数可能决定根据逻辑分支返回不同类型的数据。这样的设计通常是因为函数试图做太多事情。真正的问题甚至不在函数本身，而是在使用函数的开发人员那一边。如果发生开发人员对传递参数类型不够了解，可能会导致意外的结果。

为了帮助我们编写更正确和自我描述的程序，PHP 引入了**类型提示**。

PHP 从 5.0 版本开始支持函数参数类型提示，但仅限于对象，从 5.1 版本开始也支持数组。PHP 7 开始，标量类型也可以进行类型提示，这使其成为该版本中更令人兴奋的功能之一。以下是 PHP 支持的标量类型提示：

+   `int`

+   `float`

+   `string`

+   `bool`

现在我们可以以以下两种方式编写函数：

+   可以是`function register($email, $age, $notify) { /* ... */}`

+   可以是`function register($email, int $age, $notify) { /* ... */}`

+   可以是`function register(string $email, int $age, bool $notify) { /* ... */}`

然而，仅仅对标量类型进行提示是不够的，因为类型声明默认情况下不会被强制执行。PHP 会尝试将其转换为指定的类型而不会抱怨。通过在 PHP 文件的第一条语句中添加`declare(strict_types=1);`指令，我们可以强制执行严格的类型检查行为。值得注意的是，该指令只影响它所在的特定文件，并不影响其他包含的文件。**文件级别**指令用于保持与众多扩展和内置 PHP 函数的向后兼容性。

让我们看下面的例子：

```php
declare(strict_types=1);

function register(string $email, int $age, bool $notify) {
 // body
}

register('user@mail.com', '33', true);

```

打开严格类型指令后，尝试将不正确的数据类型传递给提示的标量参数将导致`\TypeError`异常，如下所示：

```php
Fatal error: Uncaught TypeError: Argument 2 passed to register() must be of the type integer, string given, called in /test.php on line 11 and defined in /test.php:5 Stack trace: #0 /test.php(11): register('user@mail.co...', '33', true) #1 {main} thrown in /test.php on line 5.

```

标量类型提示是 PHP 语言的一个强大的新功能。它们在运行时为开发人员提供了额外的保护层，而不会真正牺牲一般的弱类型系统。

# 返回类型提示

类型提示功能不仅限于函数参数；从 PHP 7 开始，它们还扩展到函数返回值。适用于函数参数提示的规则也适用于函数返回类型提示。要指定函数返回类型，我们只需在参数列表后面加上冒号和返回类型，如下例所示：

```php
function register(string $user, int $age) : bool {
  // logic ...
  return true;
}

```

开发人员仍然可以编写带有多个条件`return`语句的函数；只是在这种情况下，每个达到的`return`语句都必须匹配提示的返回类型，否则会抛出`\TypeError`。

函数返回类型提示与超类型很好地配合。让我们看下面的例子：

```php
class A {}
class B extends A {}
class C extends B {}

function getInstance(string $type) : A {
    if ($type == 'A') {
       return new A();
       } elseif ($type == 'B') {
           return new B();
       } else {
           return new C();
       }
  }

getInstance('A'); #object(A)#1 (0) { }
getInstance('B'); #object(B)#1 (0) { }
getInstance('XYZ'); #object(C)#1 (0) { }

```

我们看到该函数对所有三种类型都执行得很好。鉴于`B`直接扩展了`A`，而`C`又扩展了`B`，该函数接受它们作为返回值。

考虑到 PHP 的动态特性，函数返回类型可能一开始看起来似乎是朝错误的方向迈出的一步，更何况因为很多 PHP 代码已经使用了 PHPDoc 的`@return`注释，这与现代 IDE 工具（如 PhpStorm）很好地配合。然而，`@return`注释只是提供信息，它在运行时并不强制实际返回类型，而且只有在强大的 IDE 中才有意义。使用函数返回类型提示可以确保我们的函数返回我们打算返回的内容。它们并不妨碍 PHP 的动态特性；它们只是从函数使用者的角度丰富了它。

# 匿名类

从类中实例化对象是一个非常简单的操作。我们使用`new`关键字，后面跟着类名和可能的构造函数参数。类名部分意味着之前定义的类的存在。虽然很少见，但有些情况下类只在执行期间使用。这些罕见的情况使得在我们知道类只被使用一次时，强制单独定义一个类变得冗长。为了解决这种冗长的挑战，PHP 引入了一个名为**匿名类**的新功能。虽然匿名类的概念在其他语言中已经存在了相当长的时间，但 PHP 在 PHP 7 版本中才引入了它。

匿名类的语法非常简单，如下所示：

```php
$obj = new class() {};
$obj2 = new class($a, $b) {
   private $a;
   private $b;
   public function __construct($a, $b) {
     $this->a = $a;
     $this->b = $b;
   }
};

```

我们使用`new`关键字，后面跟着`class`关键字，然后是可选的构造函数参数，最后是用大括号包裹的类体。两个对象都被实例化为`class@anonymous`类型。通过匿名类实例化的对象的功能与通过命名类实例化的对象没有区别。

与命名类相比，匿名类几乎是相等的，它们可以传递构造函数参数，扩展其他类，实现接口，并使用特性。然而，匿名类不能被序列化。尝试序列化匿名类的实例，如下面的代码片段所示，会抛出一个致命的`Serialization of class@anonymous is not allowed…`错误。

在使用匿名类时，需要牢记一些注意事项。在另一个类中嵌套匿名类会隐藏该外部类的私有和受保护的方法或属性。为了规避这个限制，我们可以将外部类的私有和受保护的属性传递到匿名类的构造函数中，如下所示：

```php
interface Salary {
      public function pay();
   }

   trait Util {
      public function format(float $number) {
         return number_format($number, 2);
      }
   }

   class User {
      private $IBAN;
      protected $salary;
      public function __construct($IBAN, $salary) {
         $this->IBAN = $IBAN;
         $this->salary = $salary;
      }

      function salary() {
       return new class($this->IBAN, $this->salary) implements Salary {
         use Util;
         private $_IBAN;
         protected $_salary;

         public function __construct($IBAN, $salary) {
            $this->_IBAN = $IBAN;
            $this->_salary = $salary;
         }

        public function pay() {
           echo $this->_IBAN . ' ' . $this->format($this->_salary);
        }
     };
   } 
 }
 $user = new User('GB29NWBK60161331926819', 4500.00);
 $user->salary()->pay();

```

在这个简化的`User`类示例中，我们有一个返回匿名类的`salary`方法。为了展示匿名类更强大的用法，我们让它实现`Salary`接口并使用`Util`特性。`Salary`接口强制匿名类实现`pay`方法。我们的`pay`方法的实现需要外部类的`IBAN`和`salary`成员值。由于匿名类不允许访问外部类的私有和受保护成员，我们通过匿名类构造函数传递这些值。虽然整体示例当然不反映出良好的类设计概念，但它展示了如何绕过成员可见性限制。

匿名类还有一个选项，可以通过扩展外部类本身来获取外部类的私有和受保护成员。然而，这需要匿名类的构造函数正确实例化外部类；否则，我们可能会遇到警告，比如`User::__construct()`缺少参数。

尽管它们没有名字，匿名类仍然有一个内部名称。在匿名类的实例上使用核心 PHP `get_class`方法，可以得到这个名称，如下面的例子所示：

```php
class User {}
class Salary {}

function gen() {
  return new class() {};
}

$obj = new class() {};
$obj2 = new class() {};
$obj3 = new class() extends User {};
$obj4 = new class() extends Salary {};
$obj5 = gen();
$obj6 = gen();

echo get_class($obj); // class@anonymous/var/www/index.php0x27fe03a
echo get_class($obj2); // class@anonymous/var/www/index.php0x27fe052
echo get_class($obj3); // class@anonymous/var/www/index.php0x27fe077
echo get_class($obj4); // class@anonymous/var/www/index.php0x27fe09e
echo get_class($obj5); // class@anonymous/var/www/index.php0x27fe04f
echo get_class($obj6); // class@anonymous/var/www/index.php0x27fe04f

for ($i=0; $i<=5; $i++) {
  echo get_class(new class() {}); // 5 x   
    class@anonymous/var/www/index.php0x27fe2d3
}

```

观察这些输出，我们可以看到在相同位置（函数或循环）创建的匿名类将产生相同的内部名称。具有相同名称的匿名类对等号（`==`）运算符返回`true`，对身份运算符（`===`）返回`false`，这是一个重要的考虑因素，以避免潜在的错误。

对匿名类的支持为一些有趣的用例打开了大门，比如模拟测试和进行内联类覆盖，这两者在明智使用时可以提高代码质量和可读性。

# 生成器委托

在任何编程语言中，遍历项目列表是最常见的事情之一。PHP 通过`foreach`结构使得遍历各种数据集合变得容易。许多语言区分各种类型的集合数据，如字典、列表、集合、元组等。然而，PHP 并不过多关注数据结构，大多数情况下简单地使用`array()`或`[]`结构来表示集合。这反过来可能会对创建大型数组在内存中产生负面影响，可能导致超出内存限制甚至增加处理时间。

除了原始的*array*类型外，PHP 还提供了`ArrayObject`和`ArrayIterator`类。这些类将数组转变为面向对象应用程序中的一等公民。

生成器允许我们编写使用`foreach`来遍历一组数据而无需构建数组的代码。它们就像一个产出尽可能多值的函数，而不是只返回一个值，这使它们具有类似迭代器的行为。虽然生成器从 PHP 5.5 就存在，但它们缺乏更高级的功能。**生成器委托**是 PHP 7 发布后提供的改进之一。

让我们看下面的例子：

```php
function even() {
   for ($i = 1; $i <= 10; $i++) {
     if ($i % 2 == 0) {
        yield $i;
     }
   }
}

function odd() {
    for ($i = 1; $i <= 10; $i++) {
       if ($i % 2 != 0) {
          yield $i;
       }
    }
}

function mix() {
   yield -1;
   yield from odd();
   yield 17;
   yield from even();
   yield 33;
}

// 2 4 6 8 1 0
foreach (even() as $even) {
  echo $even;
}

// 1 3 5 7 9
foreach (odd() as $odd) {
  echo $odd;
}

// -1 1 3 5 7 9 17 2 4 6 8 10 33
foreach (mix() as $mix) {
  echo $mix;
}

```

在这里，我们定义了三个生成器函数：`even`、`odd`和`mix`。`mix`函数通过使用`yield` from `<expr>`演示了生成器委托的概念。而`<expr>`是任何评估为可遍历对象或数组的表达式。我们可以看到通过循环遍历`mix`函数的结果，会输出它自身以及`even`和`odd`函数的所有产出值。

生成器委托语法允许将`yield`语句分解为更小的概念单元，使生成器具有类似方法对类的组织功能。谨慎使用时，这可以提高我们的代码质量和可读性。

# 生成器返回表达式

尽管 PHP 5.5 通过引入生成器函数功能丰富了语言，但它缺乏`return`表达式以及它们的产出值。生成器函数无法指定返回值的能力限制了它们在协程中的实用性。PHP 7 版本通过添加对`return`表达式的支持解决了这个限制。生成器基本上是可中断的函数，其中`yield`语句标志着中断点。让我们来看一个简单的生成器，以自调用匿名函数的形式编写：

```php
$letters = (function () {
  yield 'A';
  yield 'B';
  return 'C';
})();

// Outputs: A B
foreach ($letters as $letter) {
  echo $letter;
}

// Outputs: C
echo $letters->getReturn();

```

尽管`$letters`变量被定义为自调用匿名函数，但`yield`语句阻止了立即函数执行，将函数转变为生成器。生成器本身保持静止，直到我们尝试对其进行迭代。一旦迭代开始，生成器产出值`A`，然后是值`B`，但不是`C`。这意味着在`foreach`结构中使用时，迭代将仅包括产出值，而不是返回值。一旦迭代完成，我们可以调用`getReturn()`方法来检索实际的返回值。在迭代生成器结果之前调用`getReturn()`方法无法获取未返回异常的生成器的返回值。

生成器的好处在于它们不是单向通道；它们不仅限于产出值，还可以接受值。作为`\Generator`类的实例，它们可以使用几个有用的方法，其中两个是`getReturn`和`send`。`send`方法使我们能够将值发送回生成器，将生成器与调用者之间的单向通信转变为双向通道，有效地将生成器转变为协程。添加`getReturn`方法赋予生成器`return`语句，为协程提供更灵活的功能。

# 空合并运算符

在 PHP 中使用变量非常容易。变量的声明和初始化是通过单个表达式完成的。例如，表达式`$user['name'] = 'John';`将自动声明类型为数组的变量`$user`，并初始化该数组，其中包含一个键名为`name`，值为`John`。

日常开发通常包括检查各种分支决策的变量值的存在，比如`if ($user['name'] =='John') { … } else { … }`。当我们自己编写代码时，我们倾向于确保我们的代码不使用未声明的变量和未初始化的数组键。然而，有时变量来自外部，因此我们无法保证它们在运行时的存在。在`$user`未设置或设置但键不是 name 时调用`$user['name']`将导致未定义索引的通知--`name`。像代码中的任何意外状态一样，通知是不好的，更糟糕的是它们实际上不会破坏你的代码，而是允许它继续执行。当发生通知时，除非我们将`display_errors`配置设置为`true`，并配置错误报告以显示`E_ALL`，否则我们甚至不会在浏览器中看到通知。

这是不好的，因为我们可能依赖不存在的变量和它们的值。这种依赖甚至可能没有在我们的代码中处理，我们甚至不会注意到，因为代码将继续执行，除非放置了特定的变量检查。

PHP 语言有一定数量的预定义变量，称为**超全局变量**，我们可以从任何函数、类或文件中使用它们，而不受范围的限制。最常用的可能是`$_POST`和`$_GET`超全局变量，它们用于获取通过表单或 URL 参数提交的数据。由于我们无法保证在这种情况下`$_GET['name']`的存在，因此我们需要检查它。通常，这是通过 PHP 中的`isset`和`empty`函数来完成的，如下面的代码块所示：

```php
// #1
if (isset($_GET['name']) && !empty($_GET['name'])) 
   {
     $name = $_GET['name'];
   } 
else {
     $name = 'N/A';
     }

// #2
if (!empty($_GET['name'])) 
   {
     $name = $_GET['name'];
   } 
else {
       $name = 'N/A';
     }

// #3

$name = ((isset($_GET['name']) && !empty($_GET['name']))) ? $_GET['name'] : 'N/A';

// #4
$name = (!empty($_GET['name'])) ? $_GET['name'] : 'N/A';

```

第一个示例是最健壮的，因为它同时使用了`isset`和`empty`函数。这些函数并不相同，因此了解它们各自的功能是很重要的。`empty`函数的好处是，如果我们尝试传递一个可能未设置的变量给它，比如`$_GET['name']`，它不会触发通知，而是简单地返回`true`或`false`。这使得`empty`函数在大多数情况下都是一个不错的辅助工具。然而，即使是第四个示例，通过使用三元运算符编写，也是相当健壮的。

PHP 7 引入了一种新类型的运算符，称为**null coalesce**（`??`）运算符。它赋予我们编写更短表达式的能力。下面的示例演示了它的使用优雅之处：

```php
$name = $_GET['name'] ?? 'N/A';

```

如果第一个操作数存在且不为 null，则返回其结果，否则返回第二个操作数。换句话说，从左到右读取，将返回第一个存在且不为 null 的值。

# 太空船操作符

比较两个值是任何编程语言中频繁的操作。我们使用各种语言运算符来表示我们希望在两个变量之间执行的比较类型。在 PHP 中，这些运算符包括相等（`$a == $b`），全等（`$a === $b`），不相等（`$a != $b`或`$a <> $b`），不全等（`$a !== $b`），小于（`$a < $b`），大于（`$a > $b`），小于或等于（`$a <= $b`），和大于或等于（`$a >= $b`）比较。

所有这些比较运算符的结果都是布尔值`true`或`false`。然而，有时候存在需要进行三路比较的情况，在这种情况下，比较的结果不仅仅是布尔值`true`或`false`。虽然我们可以通过各种表达式使用各种运算符来实现三路比较，但解决方案却并不优雅。

随着 PHP 7 的发布，引入了一个新的太空船`<=>`运算符，其语法如下：

```php
(expr) <=> (expr)

```

太空船`<=>`运算符提供了组合比较。比较后，它遵循以下条件：

+   如果两个操作数相等，则返回`0`

+   如果左操作数大，则返回`1`

+   如果右操作数大，则返回`-1`

用于产生上述结果的比较规则与现有比较运算符使用的规则相同：`<`、`<=`、`==`、`>=`和`>`。

新运算符的实用性在排序函数中尤为明显。没有它，排序函数就会变得相当复杂，如下例所示：

```php
$users = ['branko', 'ivana', 'luka', 'ivano'];

usort($users, function ($a, $b) {
  return ($a < $b) ? -1 : (($a > $b) ? 1 : 0);
});

```

我们可以通过应用新的运算符来缩短上面的例子，如下所示：

```php
$users = ['branko', 'ivana', 'luka', 'ivano'];

usort($users, function ($a, $b) {
  return $a <=> $b;
});

```

应用太空船`<=>`运算符（如果适用）可以使表达式简洁而优雅。

# 常量数组

PHP 中有两种常量，**常量**和**类常量**。常量可以在几乎任何地方使用定义构造定义，而`class`常量是使用`const`关键字在各个类或接口中定义的。

虽然我们不能说一种常量类型比另一种更重要，但 PHP 5.6 通过允许具有数组数据类型的类常量来区分这两种类型。除了这种差异，这两种类型的常量都支持标量值（整数、浮点数、字符串、布尔值或 null）。

PHP 7 发布通过将数组数据类型添加到常量中来解决了这种不平等，使以下表达式成为有效表达式：

```php
// The class constant - using 'const' keyword
class Rift {
  const APP = [
    'name' => 'Rift',
    'edition' => 'Community',
    'version' => '2.1.2',
    'licence' => 'OSL'
  ];
}

// The class constant - using 'const' keyword
interface IRift {
  const APP = [
    'name' => 'Rift',
    'edition' => 'Community',
    'version' => '2.1.2',
    'licence' => 'OSL'
  ];
}

// The constant - using 'define' construct
define('APP', [
  'name' => 'Rift',
  'edition' => 'Community',
  'version' => '2.1.2',
  'licence' => 'OSL'
]);

echo Rift::APP['version'];
echo IRift::APP['version'];
echo APP['version'];

```

尽管具有数组数据类型的常量可能不是一种令人兴奋的功能，但它为整体常量使用增添了一定的风味。

# 统一变量语法

新的变量语法可能是 PHP 7 发布中最具影响力的功能之一。它为变量解引用带来了更大的秩序。然而，影响部分不仅对更好的变化产生影响，它还引入了某些**向后兼容性**（**BC**）破坏。这些变化的主要原因之一是与*变量变量*语法的不一致性。

观察`$foo['bar']->baz`表达式，首先获取一个名为`$foo`的变量，然后从结果中取出`bar`偏移量，最后访问`baz`属性。这是正常的变量访问解释，从左到右。然而，*变量变量*语法违反了这个原则。观察`$$foo['baz']`变量，首先获取`$foo`，然后是它的`baz`偏移量，最后查找结果名称的变量。

新引入的统一变量语法解决了这些不一致性，如下例所示：

```php
/*** expression syntax ***/
$$foo['bar']['baz']

// PHP 5.x meaning
${$foo['bar']['baz']}

// PHP 7.x meaning
($$foo)['bar']['baz']

/*** expression syntax ***/
$foo->$bar['baz']

// PHP 5.x meaning
$foo->{$bar['baz']}

// PHP 7.x meaning
($foo->$bar)['baz']

/*** expression syntax ***/
$foo->$bar['baz']()

// PHP 5.x meaning
$foo->{$bar['baz']}()

// PHP 7.x meaning
($foo->$bar)['baz']()

/*** expression syntax ***/
Foo::$bar['baz']()

// PHP 5.x meaning
Foo::{$bar['baz']}()

// PHP 7.x meaning
(Foo::$bar)['baz']()

```

除了解决上述的不一致性，还添加了几种新的语法组合，使以下表达式现在有效：

```php
$foo()['bar']();
[$obj1, $obj2][0]->prop;
getStr(){0}
$foo['bar']::$baz;
$foo::$bar::$baz;
$foo->bar()::baz()
// Assuming extension that implements actual toLower behavior
"PHP"->toLower();
[$obj, 'method']();
'Foo'::$bar;

```

这里有很多不同的语法。虽然其中一些可能看起来令人不知所措，难以找到用途，但它为新的思维方式和代码使用打开了一扇门。

# 可抛出的

PHP 中的异常并不是一个新概念。自从 PHP 5 发布以来，它们一直存在。然而，它们并没有包括 PHP 所有的错误处理，因为错误并不被视为异常。当时的 PHP 有两种错误处理系统。这使得处理起来很棘手，因为传统错误无法通过`try...catch`块捕获异常。某些技巧是可能的，其中一个可以使用`set_error_handler()`函数来设置一个用户定义的错误处理程序函数，基本上监听错误并将其转换为异常。

让我们看下面的例子：

```php
<?php class Mailer {
  private $transport;

  public function __construct(Transport $transport)
 {  $this->transport = $transport;
 } } $transport = new stdClass();  try {
  $mailer = new Mailer($transport); } catch (\Exception  $e) {
  echo 'Caught!'; } finally {
  echo 'Cleanup!'; }

```

PHP 5 将无法捕获这个错误，而是抛出`可捕获的致命错误`，如下所示：

```php
Catchable fatal error: Argument 1 passed to Mailer::__construct() must be an instance of Transport, instance of stdClass given, called in /index.php on line 18 and defined in /index.php on line 6.

```

通过在此代码之前添加`set_error_handler()`的实现，我们可以将致命错误转换为异常：

```php
set_error_handler(function ($errno, $errstr) {
  throw new \Exception($errstr, $errno);
});

```

有了上述代码，`try...catch...finally`块现在会按预期启动。然而，有一些错误类型无法通过`set_error_handler`捕获，例如`E_ERROR`、`E_PARSE`、`E_CORE_ERROR`、`E_CORE_WARNING`、`E_COMPILE_ERROR`、`E_COMPILE_WARNING`，以及在调用`set_error_handler`的文件中引发的大多数`E_STRICT`。

PHP 7 发布通过引入`Throwable`接口和将错误和异常移至其下，改进了整体的错误处理系统。它现在是通过`throw`语句抛出的任何对象的基本接口。虽然我们不能直接扩展它，但我们可以扩展`\Exception`和`\Error`类。`\Exception`是所有 PHP 和用户异常的基类，`\Error`是所有内部 PHP 错误的基类。

我们现在可以轻松地将我们之前的`try...catch...finally`块重写为以下之一：

```php
<?php   // Case 1 try {
  $mailer = new Mailer($transport); } catch (\Throwable $e) {
  echo 'Caught!'; } finally {
  echo 'Cleanup!'; }   // Case 2 try {
  $mailer = new Mailer($transport); } catch (\Error $e) {
  echo 'Caught!'; } finally {
  echo 'Cleanup!'; }

```

注意在第一个示例的`catch`块中使用了`\Throwable`。尽管我们不能扩展它，但我们可以将其用作在单个`catch`语句中捕获`\Error`和`\Exception`的简写。

实现`\Throwable`带来了非常需要的错误和异常之间的对齐，使得它们更容易理解。

# 组使用声明

PHP 在 5.3 版本中引入了命名空间。它提供了一种将相关类、接口、函数和常量分组的方式，从而使我们的代码库更有组织和可读。然而，处理现代库通常涉及大量冗长的`use`语句，用于从各种命名空间导入类，如下例所示：

```php
use Magento\Backend\Block\Widget\Grid;
use Magento\Backend\Block\Widget\Grid\Column;
use Magento\Backend\Block\Widget\Grid\Extended;

```

为了解决这种冗长，PHP 7 发布引入了组使用声明，允许以下语法：

```php
use Magento\Backend\Block\Widget\Grid;
use Magento\Backend\Block\Widget\Grid\{
  Column,
  Extended
};

```

在这里，我们将`Column`和`Extend`压缩到一个声明下。我们可以进一步使用以下复合命名空间来压缩这个：

```php
use Magento\Backend\Block\Widget\{
  Grid
  Grid\Column,
  Grid\Extended
};

```

组使用声明充当缩写，使得以简洁的方式导入类、常量和函数稍微更容易。尽管它们的好处似乎有些边缘，但它们的使用是完全可选的。

# 捕获多个异常类型

引入了可抛出对象后，PHP 基本上围绕错误检测、报告和处理进行了调整。开发人员可以使用`try...catch...finally`块根据自己的意愿处理异常。使用多个`catch`块可以更好地控制对某些类型异常的响应。然而，有时我们希望对一组异常做出相同的响应。在 PHP 7.1 中，异常处理进一步得到了改进以适应这一挑战。

让我们看一下以下的 PHP 5.x 示例：

```php
try {
      // ...
    } 
catch (\InvalidArgumentException $e) 
    {
      // ...
    } 
catch (\LengthException $e)
    {
      // ...
    }
catch (Exception $e) 
   {
     // ...
   } 
finally 
  {
    // ...
  }

```

在这里，我们处理了三种异常，其中两种异常非常具体，第三种异常是在前两种异常不匹配时捕获。`finally`块只是一个清理，如果需要的话。现在想象一下，对于`\InvalidArgumentException`和`\LengthException`块，需要相同的响应。解决方案要么是将一个异常块中的整个代码块复制到另一个异常块中，要么是最好的情况下编写一个包装响应代码的函数，然后在每个异常块中调用该函数。

新增的异常处理语法可以捕获多个异常类型。通过使用单个竖线(`|`)，我们可以为`catch`参数定义多个异常类型，如下所示的 PHP 7.x 示例：

```php
try {
      // ...
    } 
catch (\InvalidArgumentException | \LengthException $e)
   {
     // ...
   }  
catch (\Exception $e) 
   {
     // ...
   }
 finally 
   {
     // ...
   }

```

除了一丝优雅外，新的语法直接影响了代码重用的效果更好。

# 类常量可见性修饰符

PHP 中有五种访问修饰符：`public`、`private`、`protected`、`abstract`和`final`。通常称为**可见性修饰符**，它们并非都同样适用。它们的使用分布在类、函数和变量之间，如下所示：

+   **函数**：`public`、`private`、`protected`、`abstract`和`final`

+   **类**：`abstract`和`final`

+   **变量**：`public`、`private`和`protected`

然而，类常量不在此列表中。PHP 的旧版本不允许在类常量上使用可见性修饰符。默认情况下，类常量仅被分配为公共可见性。

PHP 7.1 版本通过引入`public`、`private`和`protected`类常量可见性修饰符来解决了这个限制，如下例所示：

```php
class Visibility 
 {
   // Constants without defined visibility
   const THE_DEFAULT_PUBLIC_CONST = 'PHP';

   // Constants with defined visibility
   private const THE_PRIVATE_CONST = 'PHP';
   protected const THE_PROTECTED_CONST = 'PHP';
   public const THE_PUBLIC_CONST = 'PHP';
 }

```

与旧行为类似，没有明确可见性的类常量默认为`public`。

# 可迭代伪类型

在 PHP 中，函数通常接受或返回一个数组或实现`\Traversable`接口的对象。虽然这两种类型都可以在`foreach`结构中使用，但从根本上说，数组是一种原始类型；对象不是。这使得函数难以理解这些类型的迭代参数和返回值。

PHP 7.1 通过引入可迭代伪类型来解决这个问题。其想法是在参数或返回类型上使用它作为类型声明，以指示该值是`iterable`。`iterable`类型接受任何数组，任何实现 Traversable 的对象和生成器。

以下示例演示了将`iterable`用作函数参数的用法：

```php
function import(iterable $users) 
 {
   // ...
 }

function import(iterable $users = null) 
 {
   // ...
 }

function import(iterable $users = []) 
 {
   // ...
 }

```

尝试将值传递给前面的`import`函数，而不是 Traversable 的数组实例或生成器，会抛出`\TypeError`。然而，如果分配了默认值，无论是 null 还是空数组，函数都会起作用。

以下示例演示了将`iterable`用作函数返回值的用法：

```php
 function export(): iterable {
   return [
     'Johny',
     'Tom',
     'Matt'
   ];
 }

 function mix(): iterable {
   return [
     'Welcome',
      33,
      4200.00
   ];
 }

 function numbers(): iterable {
    for ($i = 0; $i <= 5; $i++) {
       yield $i;
    }
 }

```

需要注意的一点是，在 PHP 中，`iterable`被实现为一个保留的类名。这意味着任何名为`iterable`的用户类、接口或特性都会抛出错误。

# 可空类型

许多编程语言允许某种可选或可空类型，具体取决于术语。PHP 动态类型已经通过内置的 null 类型支持了这个概念。如果变量被赋予了常量值 null，它没有被赋予任何值，或者使用`unset()`构造函数取消了赋值，那么变量被认为是 null 类型。除了变量，null 类型也可以用于函数参数，通过将它们赋予 null 的默认值。

然而，这带来了一定的限制，因为我们无法声明一个可能为 null 的参数，而不同时将其标记为可选。

PHP 7.1 通过在类型前加上一个问号符号(`?`)来解决了这个限制，以指示类型可以为 null，除非明确赋予其他值。这也意味着类型可以同时为 null 和必需。这些可空类型现在几乎可以在任何允许类型声明的地方使用。

以下是带有强制参数值的可空类型的示例：

```php
function welcome(?string $name) {
   echo $name;
}

welcome(); // invalid
welcome(null); // valid

```

对`welcome`函数的第一次调用会抛出`\Error`，因为它的声明使参数成为了必需的。这说明可空类型不应该被误解为将`null`作为值传递。

以下是一个带有可选参数值的可空类型的示例，可选的意思是它已经被赋予了默认值`null`：

```php
function goodbye(?string $name = null)
 {
   if (is_null($name)) 
     {
       echo 'Goodbye!';
     } 
   else
     { 
       echo "Goodbye $name!";
     }
 }

goodbye(); // valid
goodbye(null); // valid
goodbye('John'); // valid

```

以下是使用可空返回类型声明函数的示例：

```php
function welcome($name): ?string 
  {
    return null; // valid
  }

function welcome($name): ?string 
  {
    return 'Welcome ' . $name; // valid
  }

function welcome($name): ?string 
 {
   return 33; // invalid
 }

```

可空类型适用于标量类型（布尔值、整数、浮点数、字符串）和复合类型（数组、对象、可调用）。

# Void 返回类型

在 PHP 7 中引入的函数参数类型和函数返回类型的强大功能中，`mix`函数中缺少了一件事。虽然函数返回类型允许指定所需的返回类型，但它们不允许指定缺少返回值。为了解决这一不一致性，PHP 7.1 版本引入了`void`返回类型功能。

为什么这很重要，我们可能会问自己？与前面提到的函数返回类型一样，这个特性对于文档和错误检查目的非常有用。由于 PHP 的性质，它在函数定义中不需要`return`语句，因此一开始不清楚函数是执行某些操作还是返回一个值。使用`void`返回类型使得函数的目的更清晰，即执行一个动作，而不是产生一个结果。

让我们看下面的例子：

```php
function A(): void {
   // valid
}

function B(): void {
   return; // valid
}

function C(): void {
   return null; // invalid
}

function D(): void {
   return 1; // invalid
}

```

`function A`和`function B`方法展示了`void`类型参数的有效用法。`function A`方法没有明确设置返回值，但这没关系，因为 PHP 隐式地总是返回`null`。`function B`方法简单地使用了`return`语句，后面没有任何类型，这也是有效的。`function C`方法有点奇怪，乍看起来可能是有效的，但实际上不是。为什么`function C`无效，而`function A`方法却有效，即使它们做的事情是一样的？尽管在 PHP 中，`return`和`return null`在技术上是等价的，但它们并不完全相同。返回类型的存在或缺失表示了函数的意图。指定返回值，即使是`null`，都意味着这个值是重要的。对于 void 返回类型，返回值是无关紧要的。因此，使用`void`返回类型表示一个不重要的返回值，在函数调用后不会在任何地方使用。

显式 void 和隐式 null 返回之间的区别可能有些模糊。这里的要点是，使用 void 返回类型传达了函数不应该返回任何类型的值。虽然它们对代码本身没有什么重大影响，它们的使用是完全可选的，但它们确实为语言带来了一定的丰富性。

# 总结

PHP 7 和 7.1 版本引入了许多变化。其中一些变化使语言超越了 PHP 曾经的样子。虽然仍然保持动态类型系统，但现在可以严格定义函数参数和返回类型。这改变了我们查看和处理函数的方式。在与函数相关的变化中，还有其他一些针对改进 PHP 5 十多年历史的变化。整个生态系统需要一些时间来适应。对于有 PHP 5 经验的开发人员来说，这些变化不仅仅是技术上的，它们需要改变思维方式，以成功应用现在可能的东西。

接下来，我们将研究 PHP 标准的当前状态，由谁定义它们，它们描述了什么，以及我们如何从中受益。


# 第二章：接受标准

每个行业都有自己的一套标准。无论是正式还是非正式，它们都规范着事物的做法。软件行业倾向于将标准规范化为文件，以确保产品和服务的质量和可靠性。它们进一步激发了兼容性和互操作性的过程，否则可能无法实现。

将代码放入产品的背景中，多年来出现了各种编码标准。它们的使用可以提高代码质量，减少我们代码库中的认知摩擦。代码质量是可持续软件开发的支柱之一，因此标准对于任何专业开发人员都非常重要，这并不奇怪。

在涉及 PHP 时，我们需要考虑几个层面的标准。有一些是特定于语言本身的编码标准，还有一些是特定于个别库、框架或平台的标准。虽然其中一些标准是相互兼容的，但有些时候它们会发生冲突。通常，这种冲突是关于一些小事情，比如将开放函数括号放在新行上还是保留在同一行上。在这种情况下，特定的库、框架和平台标准应优先于纯语言标准。

2009 年，在芝加哥的**php[tek]**会议上，许多开发人员联合起来成立了*PHP 标准组*。组织在`standards@lists.php.net`的邮件列表周围，最初的目标是建立适当的自动加载标准。自动加载对框架和平台开发人员来说是一个严峻的挑战。不同的开发人员在为其类文件命名时使用了不同的约定。这对互操作性产生了严重影响。**PHP 标准建议**，代号**PSR-0**，旨在通过概述必须遵循的自动加载器互操作性实践和约束来解决这个问题。在早期阶段，组织被 PHP 社区保留。他们还没有赢得社区的认可。两年后，该组织将自己改名为**框架互操作性组**，缩写为**PHP-FIG**。迄今为止，PHP-FIG 已经制定了几个 PSR，用每一个都重新确立了自己在开发人员中的地位。

PHP-FIG 及其 PSR 是由 PEAR 编码标准先于的，这在今天仍然相当占主导地位。它主要关注 PHP 语言本身的元素。这些元素涉及我们编写函数、变量、类等的方式。另一方面，PSR 主要关注互操作性方面。PHP-FIG 和 PEAR 在 PSR-1 和 PSR-2 的范围内交叉；这使开发人员现在可以自由遵循 PHP-FIG 组提供的一套标准。

在本章中，我们将详细了解当前发布和接受的 PSR 标准：

+   PSR-1 - 基本编码标准

+   PSR-2 - 编码风格指南

+   PSR-3 - 记录器接口

+   PSR-4 - 自动加载标准

+   PSR-6 - 缓存接口

+   PSR-7 - HTTP 消息接口

+   PSR-13 - 超媒体链接

在 PSR 中，广泛使用了**MUST**、**MUST NOT**、**REQUIRED**、**SHALL**、**SHALL NOT**、**SHOULD**、**SHOULD NOT**、**RECOMMENDED**、**MAY**和**OPTIONAL**等关键字。这些关键字的含义在 RFC 2119 ([`www.ietf.org/rfc/rfc2119.txt`](http://www.ietf.org/rfc/rfc2119.txt))中有更详细的描述。

# PSR-1 - 基本编码标准

PSR-1 是基本的编码标准。它概述了我们的代码应该遵循的规则，这是 PHP-FIG 成员的看法。标准本身非常简短。

*文件必须仅使用<?php 和<?=标签。* 一度，PHP 支持几种不同的标签（`<?php ?>`，`<? ?>`，`<?= ?>`，`<% %>`，`<%= %>`，`<script language="php"></script>`）。其中一些的使用取决于配置指令`short_open_tag`（`<? ?>`）和`asp_tags`（`<% %>`，`<%= %>`）。PHP 7 版本移除了 ASP 标签（`<%`，`<%=`），以及脚本标签（`<script language="php">`）。现在建议只使用`<?php ?>`和`<?= ?>`标签，以最大程度地提高兼容性。

*文件必须仅使用 UTF-8 而不带 BOM 的 PHP 代码。* **字节顺序标记**（**BOM**）是一个 Unicode 字符，U+FEFF 字节顺序标记（BOM），出现在文档的开头。正确使用时，BOM 是不可见的。HTML5 浏览器需要识别 UTF-8 BOM，并使用它来检测页面的编码。另一方面，PHP 可能会遇到 BOM 的问题。位于文件开头的 BOM 会导致页面在解释头命令之前开始输出，从而与 PHP 头部发生冲突。

*文件应该声明符号（类、函数、常量等），或者引起副作用（例如生成输出、更改.ini 设置等），但不应该两者兼而有之。* PHP 的简单性往往成为其弊端。在使用时，这种语言非常宽松。我们可以轻松地从一个空白文件开始，在其中编写整个应用程序。这意味着有数十个不同的类、函数、常量、变量、包含、需要和其他指令，都堆叠在一起。虽然这对于快速原型设计可能会很方便，但在构建应用程序时绝不是一个应该采取的方法。

以下代码行演示了一个要避免的示例：

```php
<?php

// side effect: change ini settings
ini_set('error_reporting', E_ALL);

// side effect: loads a file
include 'authenticate.php';

// side effect: generates output
echo "<h1>Hello</h1>";

// declaration
function log($msg)
{
  // body
}

```

以下代码行演示了一个要遵循的示例：

```php
<?php

// declaration
function log()
{
  // body
}

// conditional declaration is *not* a side effect
if (!function_exists('hello')) {
 function hello($msg)
 {
   // body
 }
}

```

*命名空间和类必须遵循自动加载 PSR：[PSR-0，PSR-4]。* 自动加载在 PHP 中扮演着重要的角色。这个概念通过从各种文件中自动拉入我们的类和函数，减少了对 require 结构的使用。默认情况下，语言本身提供了`__autoload()`和`spl_autoload_register()`函数来协助实现这一点。PHP-FIG 小组制定了两个自动加载标准。PSR-0 标准是第一个发布的 PSR，很快就被许多 PHP 框架广泛采用。截至 2014 年 10 月，PSR-0 已被标记为弃用，留下 PSR-4 作为替代方案。我们将在稍后更详细地介绍 PSR-4。目前，可以说，从 PHP 5.3 开始编写的代码必须使用正式的命名空间。

以下代码行演示了一个要避免的示例：

```php
<?php

class Foggyline_User_Model
{
  // body
}

```

以下代码行演示了一个要遵循的示例：

```php
<?php

namespace Foggyline\Model;

class User 
{
  // body
}

```

*类名必须使用* **StudlyCaps***.* 类名，有时包括多个单词。例如，负责 XML 解析的类。合理地，我们可能称之为`Xml_Parser`，`XmlParser`，`XML_Parser`，`XMLParser`或类似的组合。有许多不同的规则用于将多个单词压缩在一起，以提高代码的可读性，例如驼峰命名法、短横线命名法、下划线命名法等。这个标准提倡使用 StudlyCaps，其中字母的大写方式是任意的。它们类似于，但可能以更随机的方式进行。

以下代码行演示了一个要避免的示例：

```php
<?php

class xmlParser 
{
  // body
}

class XML_Parser 
{
  // body
}

```

以下代码行演示了一个要遵循的示例：

```php
<?php

class XmlParser 
{
  // body
}

class XMLParser 
{
  // body
}

```

类常量必须以大写字母和下划线分隔符声明。PHP 系统有两种常量，一种是在类外部定义的，使用 define 结构定义，另一种是在类内部定义的。鉴于常量代表不可变的变量，它们的名称应该突出显示。这个标准明确规定任何类常量名称都应该完全大写。然而，它避免了对属性名称的任何建议。只要我们保持一致，我们可以自由使用以下任何组合（$StudlyCaps，$camelCase 或$under_score）。

以下代码行演示了一个要避免的例子：

```php
<?php

class XmlParser 
{
  public const APPVERSION = 1.2;
  private const app_package = 'net.foggyline.xml.parser';
  protected const appLicence = 'OSL';
}

```

以下代码行演示了一个要避免的例子：

```php
<?php

class XmlParser 
{
  public const APP_VERSION = 1.2;
  private const APP_PACKAGE = 'net.foggyline.xml.parser';
  protected const APP_LICENCE = 'OSL';
}

```

方法名必须以 camelCase 声明。类中的函数称为方法。这里的命名模式与前面提到的 StudlyCaps 不同，它使用较少武断的 camelCase。更具体地说，使用小写的 camelCase，这意味着方法名以小写字母开头。

以下代码行演示了一个要避免的例子：

```php
<?php

class User 
{
  function say_hello($name) { /* … */ }
  function Pay($salary) { /* … */ }
  function RegisterBankAccount($account) { /* … */ }
}

```

以下代码行演示了一个要避免的例子：

```php
<?php

class User 
{
  function sayHello($name) { /* … */ }
  function pay($salary) { /* … */ }
  function registerBankAccount($account) { /* … */ }
}

```

官方的完整的 PSR-1 基本编码标准指南可在[`www.php-fig.org/psr/psr-1/`](http://www.php-fig.org/psr/psr-1/)上找到。

# PSR-2 - 编码风格指南

PSR-2 是 PSR-1 的扩展。这意味着在谈论 PSR-2 时，PSR-1 标准在某种程度上是隐含的。不同之处在于，PSR-2 扩展了基本的类和函数格式，通过列举一组规则来格式化 PHP 代码。所述的样式规则源自 PFP-FIG 成员项目之间的共同相似之处。

代码必须遵循编码风格指南 PSR（PSR-1）。可以说每个 PSR-2 代码都隐含地符合 PSR-1。

代码必须使用 4 个空格进行缩进，而不是制表符。空格与制表符的困境在编程世界中已经存在很久了。有些人 PHP-FIG 组投票使用空格，而 4 个空格代表通常的单个制表符缩进。空格胜过制表符的好处在于一致性。而制表符可能会根据环境显示为不同数量的列，单个空格始终是一个列。虽然这可能不是最令人信服的论点，但标准继续说 4 个空格构成一个单独的缩进。可以将其视为曾经单个缩进的 4 个空格。大多数现代 IDE 编辑器，如 PhpStorm，现在都会自动处理这个问题。

行长度不得有硬限制；软限制必须为 120 个字符；行应为 80 个字符或更少。80 个字符的行长度论点与编程本身一样古老。1928 年设计的 IBM 穿孔卡每行有 80 列，每列有 12 个穿孔位置，每列一个字符。这种每行 80 个字符的设计选择后来传递给基于字符的终端。尽管显示设备的进步远远超出了这些限制，但即使在今天，一些命令提示仍然设置为 80 列。这个标准基本上是说，虽然我们可以使用任何长度，但最好保持在 80 个字符以下。

在命名空间声明后必须有一个空行，并且在使用声明块后必须有一个空行。虽然这不是语言本身强加的技术要求，但标准要求如此。这个要求本身更多是为了美观。结果使用对代码可读性更好。

以下代码行演示了一个要避免的例子：

```php
<?php
namespace Foggyline\User\Model;
use Foggyline\User\Model\Director;

class Employee 
{
}

```

以下代码行演示了一个要避免的例子：

```php
<?php
namespace Foggyline\User\Model;
use Foggyline\User\Model\Director;

class Employee 
{
}

```

类的大括号必须放在下一行，而右括号必须放在主体的下一行。同样，这不是语言的技术要求，而是美学上的要求。

以下代码行演示了一个要避免的例子：

```php
<?php

class Employee {
  // body
}

```

以下代码行演示了一个要避免的示例：

```php
<?php

class Employee 
{
  // body
}

```

*方法的左花括号必须放在下一行，右花括号必须放在主体的下一行。*再次强调，这只是一种对代码格式的要求，实际上并不是语言本身强加的。

以下代码行演示了一个要避免的示例：

```php
<?php

class Employee {
  public function pay() {
    // body
  }
}

```

以下代码行演示了一个要避免的示例：

```php
<?php

class Employee 
{
  public function pay()
  {
    // body
  }
}

```

*所有属性和方法都必须声明可见性；抽象和最终必须在可见性之前声明；静态必须在可见性之后声明。*可见性只是官方称为**访问修饰符**的一种简写。PHP 中的类方法可以使用多个访问修饰符。在这种情况下，访问修饰符的顺序并不重要；我们可以轻松地说`abstract public function`和`public abstract function`或`final public function`和`public final function`。当我们将`static`访问修饰符添加到混合中时，情况也是一样的，我们实际上可能在单个方法上有三种不同的访问修饰符。这个标准明确规定了如果使用`abstract`和`final`修饰符，需要首先设置它们，而如果使用`static`修饰符，需要跟在`public`和`private`修饰符后面。

以下代码块演示了一个要避免的示例：

```php
<?php

abstract class User
{
  public function func1()
  {
    // body
  }

  private function func2()
  {
    // body
  }

  protected function func3()
  {
    // body
  }

  public static abstract function func4();

  static public final function func5()
  {
    // body
  }
}

class Employee extends User
{
  public function func4()
  {
    // body
  }
}

```

以下代码块演示了一个要避免的示例：

```php
<?php

abstract class User
{
  public function func1()
  {
    // body
  }

  private function func2()
  {
    // body
  }

  protected function func3()
  {
    // body
  }

  abstract public static function func4();

  final public static function func5()
  {
    // body
  }
}

class Employee extends User
{
  public static function func4()
  {
    // body
  }
}

```

*控制结构关键字后必须有一个空格；方法和函数调用不得有。*这只是一种对代码可读性的影响较大的要求。

以下代码行演示了一个要避免的示例：

```php
<?php

class Logger
{
  public function log($msg, $code)
  {
    if($code >= 500) {
      // logic
    }
  }
}

```

以下代码行演示了一个要避免的示例：

```php
<?php

class Logger
{
  public function log($msg, $code)
  {
    if ($code >= 500)
    {

    }
  }
}

```

*控制结构的左花括号必须放在同一行，右花括号必须放在主体的下一行。*

以下代码块演示了一个要避免的示例：

```php
<?php

class Logger
{
  public function log($msg, $code)
  {
    if ($code === 500)
    {
      // logic
    }
    elseif ($code === 600)
    {
      // logic
    }
    elseif ($code === 700)
    {
      // logic
    }
    else
    {
      // logic
    }
  }
}

```

以下代码块演示了一个要避免的示例：

```php
<?php

class Logger
{
  public function log($msg, $code)
  {
    if ($code === 500) {
      // logic
    } elseif ($code === 600) {
      // logic
    } elseif ($code === 700) {
      // logic
    } else {
      // logic
    }
  }
}

```

*控制结构的左括号后面不得有空格，控制结构的右括号前面不得有空格。*这里可能有点令人困惑，因为之前我们看到标准强制使用空格来缩进而不是制表符。这意味着我们将在右括号之前有空格。然而，在右括号处应该只有足够的空格来表示实际的缩进，而不是更多。

演示了一个要避免的示例（注意第 7 行，在左花括号后面有一个空格）：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/2aab1815-76f4-4efd-8201-1109cdbd24ff.png)

演示了一个要避免的示例：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/a86bc8b6-a227-41b7-aaf3-520416bc1094.png)官方的完整*PSR-2 编码风格*指南可在[`www.php-fig.org/psr/psr-2/`](http://www.php-fig.org/psr/psr-2/)上找到。

# PSR-3 - 记录器接口

记录不同类型的事件是应用程序的常见做法。虽然一个应用程序可能将这些类型的事件分类为错误、信息事件和警告，但其他应用程序可能会引入更复杂的严重性级别记录。日志消息本身的实际格式也是如此。可以说每个应用程序可能都有自己的日志记录机制。这阻碍了互操作性。

PSR-3 标准旨在通过定义实际记录器接口的标准来解决这个问题。这样一个标准化的接口使我们能够以简单和通用的方式编写 PHP 应用程序日志。

*syslog 协议*（RFC 5424），由**互联网工程任务组**（**IETF**）定义，区分了以下八个严重级别：

+   `紧急`：这表示系统无法使用

+   `警报`：这表示必须立即采取行动

+   `严重`：这表示严重条件

+   `错误`：这表示错误条件

+   `警告`：这表示警告条件

+   `注意`：这表示正常但重要的条件

+   `信息`：这表示信息消息

+   `调试`：这表示调试级别的消息

PSR-3 标准建立在 RFC 5424 之上，通过指定`LoggerInterface`，为八个严重级别中的每一个公开了一个特殊方法，如下所示：

```php
<?php

interface LoggerInterface
{
  public function emergency($message, array $context = array());
  public function alert($message, array $context = array());
  public function critical($message, array $context = array());
  public function error($message, array $context = array());
  public function warning($message, array $context = array());
  public function notice($message, array $context = array());
  public function info($message, array $context = array());
  public function debug($message, array $context = array());
  public function log($level, $message, array $context = array());
}

```

我们还可以注意到第九个`log()`方法，其签名与前八个不同。`log()`方法更像是一个便利方法，其级别参数需要指示八个严重级别中的一个。调用此方法必须与调用特定级别的方法具有相同的结果。每个方法都接受一个字符串作为`$message`，或者具有`__toString()`方法的对象。尝试使用未知严重级别调用这些方法必须抛出`Psr\Log\InvalidArgumentException`。

`$message`字符串可能包含一个或多个占位符，接口实现者可能将其与传递到`$context`字符串中的键值参数进行插值，如下面的抽象示例所示：

```php
<?php

//...
$message = "User {email} created, with role {role}.";
//...
$context = array('email' => ‘john@mail.com', ‘role’ => 'CUSTOMER');
//...

```

不需要深入实现细节，可以说 PSR-3 是一个简单的标准，用于对记录器机制的重要角色进行排序。使用记录器接口，我们不必依赖特定的记录器实现。我们可以在应用程序代码中对`LoggerInterface`进行类型提示，以获取符合 PSR-3 的记录器。

如果我们在项目中使用**Composer**，我们可以很容易地将`psr/log`包包含到其中。这将使我们能够以以下一种方式之一将符合 PSR 标准的记录器集成到我们的项目中：

+   实现`LoggerInterface`接口并定义其所有方法

+   继承`AbstractLogger`类并定义`log`方法

+   使用`LoggerTrait`并定义`log`方法

然而，使用现有的 Composer 包，如`monolog/monolog`或`katzgrau/klogger`，并完全避免编写自己的记录器实现会更容易。

*Monolog*项目是一个流行且强大的 PHP 库的很好的例子，它实现了 PSR-3 记录器接口。它可以用于将日志发送到文件、套接字、收件箱、数据库和各种网络服务。官方的完整的*PSR-3: Logger Interface*指南可在[`www.php-fig.org/psr/psr-3/`](http://www.php-fig.org/psr/psr-3/)上找到。

# PSR-4 - 自动加载标准

迄今为止，PHP-FIG 小组已发布了两个自动加载标准。在 PSR-4 之前是 PSR-0。这是 PHP-FIG 小组发布的第一个标准。其类命名具有与更旧的 PEAR 标准对齐的某些向后兼容特性。而每个层次的分隔符都是用单个下划线，表示伪命名空间和目录结构。然后，PHP 5.3 发布了官方的命名空间支持。PSR-0 允许同时使用旧的 PEAR 下划线模式和新的命名空间表示法。允许一段时间使用下划线来进行过渡，促进了命名空间的采用。很快，Composer 出现了。

Composer 是一个流行的 PHP 依赖管理器，通过将包和库安装在项目的`vendor/`目录中来处理它们。

使用 Composer 的`vendor/`目录哲学，没有像 PEAR 那样的单一主目录用于 PHP 源代码。PSR-0 成为瓶颈，并于 2014 年 10 月被标记为废弃。

PSR-4 是目前推荐的自动加载标准。

根据 PSR-4，完全限定的类名现在具有如下示例所示的形式：

```php
\<NamespaceName>(\<SubNamespaceNames>)*\<ClassName>

```

这里的术语*class*不仅指类。它还指*interfaces*、*traits*和其他类似的结构。

为了将其放入上下文中，让我们来看一下从*Magento 2*商业平台中摘取的部分类代码，如下所示：

```php
<?php

namespace Magento\Newsletter\Model;

use Magento\Customer\Api\AccountManagementInterface;
use Magento\Customer\Api\CustomerRepositoryInterface;

class Subscriber extends \Magento\Framework\Model\AbstractModel
{
  // ...

  public function __construct(
    \Magento\Framework\Model\Context $context,
    \Magento\Framework\Registry $registry,
    \Magento\Newsletter\Helper\Data $newsletterData,
    \Magento\Framework\App\Config\ScopeConfigInterface $scopeConfig,
    \Magento\Framework\Mail\Template\TransportBuilder
      $transportBuilder,
    \Magento\Store\Model\StoreManagerInterface $storeManager,
    \Magento\Customer\Model\Session $customerSession,
    CustomerRepositoryInterface $customerRepository,
      AccountManagementInterface $customerAccountManagement,
    \Magento\Framework\Translate\Inline\StateInterface
      $inlineTranslation,
    \Magento\Framework\Model\ResourceModel\AbstractResource
      $resource = null,
    \Magento\Framework\Data\Collection\AbstractDb
      $resourceCollection = null,
    array $data = []
  ) {
   // ...
  }

  // ...
}

```

前面的`Subscriber`类定义在`vendor\Magento\module-newsletter\Model\`中的`Subscriber.php`文件中，相对于*Magento*项目的根目录。我们可以看到`__construct`使用了各种完全分类的类名。Magento 平台在其代码库中到处都有这种强大的构造函数，这是因为它处理依赖注入的方式。我们可以想象，如果没有统一的自动加载标准，需要手动单独`require`所有这些类所需的额外代码量。

PSR-4 标准还规定，自动加载程序实现不能抛出异常或引发任何级别的错误。这是为了确保可能的多个自动加载程序不会相互破坏。

官方的完整*PSR-4：自动加载程序标准*指南可在[`www.php-fig.org/psr/psr-4/`](http://www.php-fig.org/psr/psr-4/)上找到。

# PSR-6 - 缓存接口

性能问题一直是应用程序开发中的热门话题。性能不佳的应用程序可能会对财务产生严重影响。早在 2007 年，亚马逊报告称[`www.amazon.com/`](https://www.amazon.com/)加载时间增加了 100 毫秒，销售额减少了 1%。几项研究还表明，将近一半的用户可能会在页面加载时间超过 3 秒时放弃网站。为了解决性能问题，我们需要研究缓存解决方案。

浏览器和服务器都允许缓存各种资源，如图像、网页、CSS/JS 文件。然而，有时这还不够，因为我们需要能够在应用程序级别控制各种其他位的缓存，比如对象本身。随着时间的推移，各种库推出了它们自己的缓存解决方案。这让开发人员感到困难，因为他们需要在其代码中实现特定的缓存解决方案。这使得以后很难轻松更改缓存实现。

为了解决这些问题，PHP-FIG 小组提出了 PSR-6 标准。

该标准定义了两个主要接口，`CacheItemPoolInterface`和`CacheItemInterface`，用于处理**Pool**和**Items**。池表示缓存系统中的项目集合。而项目表示存储在池中的单个**键**/值对。键部分充当唯一标识符，因此必须是不可变的。

以下代码片段反映了 PSR-6 `CacheItemInterface` 的定义：

```php
<?php

namespace Psr\Cache;

interface CacheItemInterface
{
  public function getKey();
  public function get();
  public function isHit();
  public function set($value);
  public function expiresAt($expiration);
  public function expiresAfter($time);
}

```

以下代码片段反映了 PSR-6 `CacheItemPoolInterface` 的定义：

```php
<?php

namespace Psr\Cache;

interface CacheItemPoolInterface
{
  public function getItem($key);
  public function getItems(array $keys = array());
  public function hasItem($key);
  public function clear();
  public function deleteItem($key);
  public function deleteItems(array $keys);
  public function save(CacheItemInterface $item);
  public function saveDeferred(CacheItemInterface $item);
  public function commit();
}

```

实现 PSR-6 标准的库必须支持以下可序列化的 PHP 数据类型：

+   字符串

+   整数

+   浮点数

+   布尔值

+   空值

+   数组

+   对象

复合结构，如数组和对象，总是棘手的。标准规定，必须支持任意深度的索引、关联和多维数组。由于 PHP 中的数组不一定是单一数据类型，这是需要小心的地方。对象可能利用 PHP 的`Serializable`接口、`__sleep()`或`__wakeup()`魔术方法，或类似的语言功能。重要的是，传递给实现 PSR-6 的库的任何数据都应该如传递时一样返回。

通过 Composer 可以获得几种 PSR-6 缓存实现，它们都支持标签。以下是最受欢迎的一些缓存实现的部分列表：

+   `cache/filesystem-adapter`：使用文件系统

+   `cache/array-adapter`：使用 PHP 数组

+   `cache/memcached-adapter`：使用 Memcached

+   `cache/redis-adapter`：使用 Redis

+   `cache/predis-adapter`：使用 Redis（Predis）

+   `cache/void-adapter`：使用 Void

+   `cache/apcu-adapter`：使用 APCu

+   `cache/chain-adapter`：使用链

+   `cache/doctrine-adapter`：使用 Doctrine

我们可以通过使用`Composer require new/package`轻松地将这些缓存库中的任何一个添加到我们的项目中。PSR-6 的兼容性使我们能够在项目中轻松地交换这些库，而无需更改任何代码。

*Redis*是一个开源的内存数据结构存储，用作数据库、缓存和消息代理。它在 PHP 开发人员中非常受欢迎作为缓存解决方案。官方*Redis*页面可在[`redis.io/`](https://redis.io/)找到。官方的完整*PSR-6：缓存接口*指南可在[`www.php-fig.org/psr/psr-6/`](http://www.php-fig.org/psr/psr-6/)找到。

# PSR-7 - HTTP 消息接口

HTTP 协议已经存在了相当长的时间。它的发展始于 1989 年，由 CERN 的 Tim Berners-Lee 发起。多年来，**互联网工程任务组**（**IETF**）和**万维网联盟**（**W3C**）为其定义了一系列标准，称为**请求评论**（**RFCs**）。HTTP/1.1 的第一个定义出现在 1997 年的 RFC 2068 中，后来在 1999 年被 RFC 2616 废弃。十多年后，HTTP/2 在 2015 年被标准化。尽管 HTTP/2 现在得到了主要 Web 服务器的支持，但 HTTP/1.1 仍然被广泛使用。

底层的 HTTP 通信归结为请求和响应，通常称为**HTTP 消息**。这些消息被抽象出来，形成了 Web 开发的基础，因此对每个 Web 应用程序开发人员都很重要。虽然 RFC 7230、RFC 7231 和 RFC 3986 规定了 HTTP 本身的细节，但 PSR-7 描述了根据这些 RFC 表示 HTTP 消息的常见接口。

PSR-7 总共定义了以下七个接口：

+   `Psr\Http\Message\MessageInterface`

+   `Psr\Http\Message\RequestInterface`

+   `Psr\Http\Message\ServerRequestInterface`

+   `Psr\Http\Message\ResponseInterface`

+   `Psr\Http\Message\StreamInterface`

+   `Psr\Http\Message\UriInterface`

+   `Psr\Http\Message\UploadedFileInterface`

它们可以通过 Composer 作为`psr/http-message`包的一部分获取。

以下代码块反映了 PSR-7 `Psr\Http\Message\MessageInterface` 的定义：

```php
<?php   namespace Psr\Http\Message;   interface MessageInterface {
  public function getProtocolVersion();
  public function withProtocolVersion($version);
  public function getHeaders();
  public function hasHeader($name);
  public function getHeader($name);
  public function getHeaderLine($name);
  public function withHeader($name, $value);
  public function withAddedHeader($name, $value);
  public function withoutHeader($name);
  public function getBody();
  public function withBody(StreamInterface $body); }

```

前面的`MessageInterface`方法适用于请求和响应类型的消息。消息被认为是不可变的。实现`MessageInterface`接口的类需要通过为每个改变消息状态的方法调用返回一个新的消息实例来确保这种不可变性。

以下代码块反映了 PSR-7 `Psr\Http\Message\RequestInterface` 的定义：

```php
<?php namespace Psr\Http\Message; interface RequestInterface extends MessageInterface {
  public function getRequestTarget();
  public function withRequestTarget($requestTarget);
  public function getMethod();
  public function withMethod($method);
  public function getUri();
  public function withUri(UriInterface $uri, $preserveHost = false); }

```

`RequestInterface`接口扩展了`MessageInterface`，作为对外的客户端请求的表示。与前面提到的消息一样，请求也被认为是不可变的。这意味着相同的类行为适用。如果类方法要改变请求状态，需要为每个这样的方法调用返回新的请求实例。

以下`Psr\Http\Message\ServerRequestInterface`定义反映了 PSR-7 标准：

```php
<?php

namespace Psr\Http\Message;

interface ServerRequestInterface extends RequestInterface
{
  public function getServerParams();
  public function getCookieParams();
  public function withCookieParams(array $cookies);
  public function getQueryParams();
  public function withQueryParams(array $query);
  public function getUploadedFiles();
  public function withUploadedFiles(array $uploadedFiles);
  public function getParsedBody();
  public function withParsedBody($data);
  public function getAttributes();
  public function getAttribute($name, $default = null);
  public function withAttribute($name, $value);
  public function withoutAttribute($name);
}

```

`ServerRequestInterface`的实现作为对内的服务器端 HTTP 请求的表示。它们也被认为是不可变的；这意味着与前面提到的状态改变方法相同的规则适用。

以下代码片段反映了 PSR-7 `Psr\Http\Message\ResponseInterface` 的定义：

```php
<?php

namespace Psr\Http\Message;

interface ResponseInterface extends MessageInterface
{
  public function getStatusCode();
  public function withStatus($code, $reasonPhrase = '');
  public function getReasonPhrase();
}

```

只定义了三种方法，`ResponseInterface`的实现作为对外的服务器端响应的表示。这些类型的消息也被认为是不可变的。

以下代码片段反映了 PSR-7 `Psr\Http\Message\StreamInterface` 的定义：

```php
<?php

namespace Psr\Http\Message;

interface StreamInterface
{
  public function __toString();
  public function close();
  public function detach();
  public function getSize();
  public function tell();
  public function eof();
  public function isSeekable();
  public function seek($offset, $whence = SEEK_SET);
  public function rewind();
  public function isWritable();
  public function write($string);
  public function isReadable();
  public function read($length);
  public function getContents();
  public function getMetadata($key = null);
}

```

`StreamInterface`提供了一个包装器，包括对整个流进行序列化为字符串的常见 PHP 流操作。

以下代码片段反映了 PSR-7 `Psr\Http\Message\UriInterface` 的定义：

```php
<?php

namespace Psr\Http\Message;

interface UriInterface
{
  public function getScheme();
  public function getAuthority();
  public function getUserInfo();
  public function getHost();
  public function getPort();
  public function getPath();
  public function getQuery();
  public function getFragment();
  public function withScheme($scheme);
  public function withUserInfo($user, $password = null);
  public function withHost($host);
  public function withPort($port);
  public function withPath($path);
  public function withQuery($query);
  public function withFragment($fragment);
  public function __toString();
}

```

这里的`UriInterface`接口表示了根据 RFC 3986 的 URI。接口方法强制实现者提供 URI 对象的大多数常见操作的方法。URI 对象的实例也被认为是不可变的。

以下代码片段反映了 PSR-7 `Psr\Http\Message\UploadedFileInterface` 的定义：

```php
<?php

namespace Psr\Http\Message;

interface UploadedFileInterface
{
  public function getStream();
  public function moveTo($targetPath);
  public function getSize();
  public function getError();
  public function getClientFilename();
  public function getClientMediaType();
}

```

`UploadedFileInterface` 接口代表通过 HTTP 请求上传的文件，这是 Web 应用程序的常见角色。少数方法强制类实现覆盖文件上执行的最常见操作。与之前的所有接口一样，类的实现需要确保对象的不可变性。

*Guzzle* 是一个流行的符合 PSR-7 标准的 HTTP 客户端库，它可以轻松处理请求、响应和流。它可以在[`github.com/guzzle/guzzle`](https://github.com/guzzle/guzzle)获取，也可以作为 Composer `guzzlehttp/guzzle` 包获取。官方的完整的*PSR-7: HTTP 消息接口*指南可以在[`www.php-fig.org/psr/psr-7/`](http://www.php-fig.org/psr/psr-7/)获取。

# PSR-13 - 超媒体链接

超媒体链接是任何 Web 应用程序的重要组成部分，无论是 HTML 还是 API 格式。至少，每个超媒体链接都包括一个代表目标资源的 URI 和一个定义目标资源与源资源关系的关系。目标链接必须是绝对 URI 或相对 URI，由 RFC 5988 定义，或者可能是由 RFC 6570 定义的 URI 模板。

PSR-13 标准定义了一系列接口，概述了一个常见的超媒体格式以及表示这些格式之间链接的方法：

+   `Psr\Link\LinkInterface`

+   `Psr\Link\EvolvableLinkInterface`

+   `Psr\Link\LinkProviderInterface`

+   `Psr\Link\EvolvableLinkProviderInterface`

这些接口可以通过 Composer 作为`psr/link`包的一部分获取。

以下代码片段反映了 PSR-13 `Psr\Link\LinkInterface` 的定义，代表了一个单一的可读链接对象：

```php
<?php

namespace Psr\Link;

interface LinkInterface
{
  public function getHref();
  public function isTemplated();
  public function getRels();
  public function getAttributes();
}

```

以下代码片段反映了 PSR-13 `Psr\Link\LinkProviderInterface` 的定义，代表了一个单一的链接提供者对象：

```php
<?php

namespace Psr\Link;

interface LinkProviderInterface
{
  public function getLinks();
  public function getLinksByRel($rel);
}

```

以下代码片段反映了 PSR-13 `Psr\Link\EvolvableLinkInterface` 的定义，代表了一个单一的可发展链接值对象：

```php
<?php

namespace Psr\Link;

interface EvolvableLinkInterface extends LinkInterface
{
  public function withHref($href);
  public function withRel($rel);
  public function withoutRel($rel);
  public function withAttribute($attribute, $value);
  public function withoutAttribute($attribute);
}

```

以下代码片段反映了 PSR-13 `Psr\Link\EvolvableLinkProviderInterface` 的定义，代表了一个单一的可发展链接提供者值对象：

```php
<?php

namespace Psr\Link;

interface EvolvableLinkProviderInterface extends LinkProviderInterface
{
  public function withLink(LinkInterface $link);
  public function withoutLink(LinkInterface $link);
}

```

这意味着这些接口的对象实例表现出与 PSR-7 相同的行为。默认情况下，对象需要是不可变的。当对象状态需要改变时，该变化应该反映到一个新的对象实例中。由于 PHP 的写时复制行为，这对类来说很容易实现。

PHP 代码的写时复制行为是一个内置机制，PHP 会避免不必要的变量复制。直到一个或多个字节的变量被改变，变量才会被复制。

官方的完整的*PSR-13: 超媒体链接*指南可以在[`www.php-fig.org/psr/psr-13/`](http://www.php-fig.org/psr/psr-13/)获取。

# 总结

PHP-FIG 组通过其 PSR 解决了各种问题。其中一些关注代码的结构和可读性，其他则通过定义众多接口来增加互操作性。这些 PSR，直接或间接地，有助于提高我们项目和我们可能使用的第三方库的质量。RFC 2119 标准是每个 PSR 的共同基础。它消除了围绕 may、must、should 等词语描述标准的任何歧义。这确保了文档被阅读时与 PHP-FIG 的意图一致。虽然我们可能不会每天都接触到这些标准中的每一个，但在选择项目的库时，注意它们是值得的。符合标准的库，比如 Monolog，通常意味着更多的灵活性，因为我们可以在项目的后期轻松地在不同的库之间切换。

接下来，我们将研究错误处理和日志记录背后的配置选项、机制和库。


# 第三章：错误处理和日志记录

有效的错误处理和日志记录是应用程序的重要部分。早期版本的 PHP 缺乏对异常的支持，只使用错误来标记有缺陷的应用程序状态。PHP 5 版本为语言带来了面向对象的特性，以及异常模型。这使 PHP 具有了像其他编程语言一样的`try...catch`块。后来，PHP 5.5 版本增加了对`finally`块的支持，无论是否抛出异常，它始终在`try...catch`块之后执行。

如今，PHP 语言将错误和异常区分为应用程序的故障状态。两者都被视为应用程序逻辑的意外情况。有许多类型的错误，比如`E_ERROR`、`E_WARNING`、`E_NOTICE`等。当谈到错误时，我们默认为`E_ERROR`类型，它往往表示应用程序的结束，这是一个意外的状态，应用程序不应该尝试捕获并继续执行。这可能是由于内存不足、IO 错误、TCP/IP 错误、空引用错误等。另一方面，异常表示应用程序可能希望捕获并继续执行的意外状态。这可能是由于在给定时间无法保存数据库中的条目，意外的电子邮件发送失败等。这有助于将异常视为错误的面向对象概念。

PHP 有自己的机制，允许与一些错误类型和异常进行交互。使用`set_error_handler`，我们可以定义自定义错误处理程序，可能记录或向用户显示适当的消息。使用`try...catch...finally`块，我们可以安全地捕获可能的异常并继续执行应用程序。我们没有自动捕获的异常会自动转换为标准错误，并中断应用程序的执行。

处理错误如果没有适当的日志记录机制，就不会真正完整。虽然 PHP 本身提供了一个有趣和有用的`error_log()`函数，但在社区库中还有更强大的日志记录解决方案，比如 Mongo。

接下来，我们将详细研究以下错误处理和日志记录领域：

+   错误处理

+   错误

+   算术错误

+   `DivisionByZeroError`

+   `AssertionError`

+   `ParseError`

+   `TypeError`

+   异常

+   日志记录

+   本机日志记录

+   使用 Monolog 进行日志记录

NASA 在 1999 年 9 月丢失了一枚价值 1.25 亿美元的火星轨道器，因为工程师未能将单位从英制转换为公制。虽然这个系统与 PHP 或致命的运行时错误无关，但它表明了一个有缺陷的软件可能在现实生活中产生多大的影响。

# 错误处理

将错误和异常作为两种不同的错误处理系统引入了一定程度的混乱。早期版本的 PHP 使得很难理解`E_ERROR`，因为它们无法被自定义错误处理程序捕获。PHP 7 版本试图通过引入`Throwable`接口来解决这种混乱，总结如下：

```php
Throwable { 
  abstract public string getMessage (void) 
  abstract public int getCode (void) 
  abstract public string getFile (void) 
  abstract public int getLine (void) 
  abstract public array getTrace (void) 
  abstract public string getTraceAsString (void) 
  abstract public Throwable getPrevious (void) 
  abstract public string __toString (void) 
}

```

`Throwable`接口现在是`Error`、`Exception`和通过`throw`语句抛出的任何其他对象的基本接口。该接口中定义的方法几乎与`Exception`的方法相同。PHP 类本身不能直接实现`Throwable`接口或扩展自`Error`；它们只能扩展`Exception`，如下例所示：

```php
<?php

  class Glitch extends \Error
  {
  }

  try {
    throw new Glitch('Glitch!');
  } 
  catch (\Exception $e) {
    echo 'Caught ' . $e->getMessage();
  }

```

前面的代码将产生以下输出：

```php
PHP Fatal error: Uncaught Glitch: Glitch! in index.php:7
Stack trace:
#0 {main}
thrown in /root/app/index.php on line 7

```

这里发生的情况是`Glitch`类试图扩展`Error`类，这是不允许的，导致了一个致命错误，我们的`try...catch`块无法捕获到：

```php
<?php

  class Flaw extends \Exception
  {
  }

  try {
    throw new Flaw('Flaw!');
  } 
  catch (\Exception $e) {
    echo 'Caught ' . $e->getMessage();
  }

```

前面的例子是 PHP `Throwable`的有效用法，而我们的自定义`Flaw`类扩展了`Exception`类。触发`catch`块，导致以下输出消息：

```php
Caught Flaw!

```

PHP 7 中的新异常层次结构如下：

```php
interface Throwable
 | Error implements Throwable
   | TypeError extends Error
   | ParseError extends Error
   | ArithmeticError extends Error
     | DivisionByZeroError extends ArithmeticError
   | AssertionError extends Error
 | Exception implements Throwable
   | ...

```

新的`Throwable`接口的明显好处是我们现在可以在单个`try...catch`块中轻松捕获`Exception`和`Error`对象，如下例所示：

```php
<?php

try {
  throw new ArithmeticError('Missing numbers!');
} 
catch (Throwable $t) {
  echo $t->getMessage();
}

```

`AssertionError`扩展了`Error`，而`Error`又实现了`Throwable`接口。上面的`catch`块的签名针对`Throwable`接口，因此抛出的`ArithmeticError`将被捕获，并显示`Missing numbers!`的输出。

虽然我们的类不能实现`Throwable`接口，但我们可以定义扩展它的接口。这样的接口只能由扩展`Exception`或`Error`的类来实现，如下例所示：

```php
<?php   interface MyThrowable extends Throwable
 {  //...
 } class MyException extends Exception implements MyThrowable
 {  //...
 } throw new MyException();

```

虽然这可能不是常见的做法，但这种方法可能对特定于包的接口有用。

# 错误

`Error`类是 PHP 7 中内部 PHP 错误的基类。现在，PHP 5.x 中几乎所有致命和可恢复的致命错误都会抛出`Error`对象的实例，从而可以通过`try...catch`块捕获。

`Error`类根据以下类概要实现了`Throwable`接口：

```php
Error implements Throwable {
   /* Properties */
   protected string $message ;
   protected int $code ;
   protected string $file ;
   protected int $line ;

   /* Methods */
   public __construct (
     [ string $message = "" 
     [, int $code = 0 
     [, Throwable $previous = NULL ]]]
    )

    final public string getMessage (void)
    final public Throwable getPrevious (void)
    final public mixed getCode (void)
    final public string getFile (void)
    final public int getLine (void)
    final public array getTrace (void)
    final public string getTraceAsString (void)
    public string __toString (void)
    final private void __clone (void)
}

```

以下示例演示了在`catch`块中使用`Error`实例：

```php
<?php

class User
{
  function hello($name)
  {
    return 'Hello ' . $name;
  }
}

// Case 1 - working
try {
  $user = new User();
  $user->greeting('John');
} 
catch (Error $e) {
  echo 'Caught: ' . $e->getMessage();
}

// Case 2 - working
try {
  $user = new User();
  $user->greeting('John');
} 
catch (Throwable $t) {
  echo 'Caught: ' . $t->getMessage();
}

```

然而，仍然有一些情况下一些错误是无法捕获的：

```php
<?php

ini_set('memory_limit', '1M');

try {
  $content = '';
  while (true) {
    $content .= 'content';
  }
} 
catch (\Error $e) {
  echo 'Caught ' . $e->getMessage();
}

```

上面的例子触发了`PHP Fatal error: Allowed memory size of 2097152 bytes exhausted...`错误。

此外，即使警告也会被忽略，如下例所示：

```php
    <?php

    error_reporting(E_ALL);
    ini_set('display_errors', 1);
    ini_set('memory_limit', '1M');

    try {
      str_pad('', PHP_INT_MAX);
    } 
    catch (Throwable $t) {
      echo 'Caught ' . $t->getMessage();
    }

```

上面的例子触发了`PHP Warning:  str_pad(): Padding length is too long...`错误。

可以说，我们应该谨慎对待捕获核心语言错误的期望，因为有些错误可能会漏掉。那些被捕获的通常是基类`Error`。然而，一些错误会抛出更具体的`Error`子类：`ArithmeticError`、`DivisionByZeroError`、`AssertionError`、`ParseError`和`TypeError`。

# ArithmeticError

`ArithmeticError`类解决了执行数学运算可能出现错误结果的情况。PHP 将其用于两种情况——通过负数进行位移或者使用`intdiv()`时被除数为`PHP_INT_MIN`，除数为`-1`。

`ArithmeticError`类没有自己的方法，它们都是从父类`Error`类继承而来，如下类概要所示：

```php
     ArithmeticError extends Error {
       final public string Error::getMessage (void)
       final public Throwable Error::getPrevious (void)
       final public mixed Error::getCode (void)
       final public string Error::getFile (void)
       final public int Error::getLine (void)
       final public array Error::getTrace (void)
       final public string Error::getTraceAsString (void)
       public string Error::__toString (void)
       final private void Error::__clone (void)
     }

```

以下示例演示了使用负数进行位移时抛出`ArithmeticError`的`try...catch`块：

```php
    <?php

    try {
      $value = 5 << -1;
    } 
    catch (ArithmeticError $e) {
      echo 'Caught: ' . $e->getMessage();
    }

```

结果输出如下：

```php
 Caught: Bit shift by negative number 

```

以下示例演示了使用`intdiv()`调用时抛出`ArithmeticError`的`try...catch`块，被除数为`PHP_INT_MIN`，除数为`-1`：

```php
    <?php

    try {
      intdiv(PHP_INT_MIN, -1);
    } 
    catch (ArithmeticError $e) {
      echo 'Caught: ' . $e->getMessage();
    }

```

结果输出如下：

```php
 Caught: Division of PHP_INT_MIN by -1 is not an integer

```

# DivisionByZeroError

在基本算术中，除以零是一个未定义的数学表达式；因此，PHP 需要一种方式来应对这种情况。当我们尝试除以零时，将抛出`DivisionByZeroError`。

`DivisionByZeroError`类没有自己的方法，它们都是从父类`ArithmeticError`继承而来，如下类概要所示：

```php
    DivisionByZeroError extends ArithmeticError {
      final public string Error::getMessage (void)
      final public Throwable Error::getPrevious (void)
      final public mixed Error::getCode (void)
      final public string Error::getFile (void)
      final public int Error::getLine (void)
      final public array Error::getTrace (void)
      final public string Error::getTraceAsString (void)
      public string Error::__toString (void)
      final private void Error::__clone (void)
    }

```

我们需要注意我们使用什么表达式进行除法。仅使用`/`运算符将被除数数字除以`0`除数数字将不会产生与使用`intdiv()`函数相同的结果。考虑以下代码片段：

```php
    <?php

    try {
      $x = 5 / 0;
    } 
    catch (DivisionByZeroError $e) {
      echo 'Caught: ' . $e->getMessage();
    }

```

上面的例子不会触发`DivisionByZeroError`的 catch 块。相反，会引发以下警告。

```php
PHP Warning: Division by zero

```

使用`intdiv()`函数而不是`/`运算符将触发`catch`块，如下面的代码片段所示：

```php
    <?php

    try {
      $x = intdiv(5, 0);
    } 
    catch (DivisionByZeroError $e) {
      echo 'Caught: ' . $e->getMessage();
    }

```

如果除数为`0`，`intdiv()`函数会抛出`DivisionByZeroError`异常。如果被除数是`PHP_INT_MIN`，除数是`-1`，那么会抛出`ArithmeticError`异常，如前面的部分所示。

# AssertionError

断言是作为调试功能使用的运行时检查。使用 PHP 7 的`assert()`语言结构，我们可以确认某些 PHP 表达式是真还是假。每当断言失败时，就会抛出`AssertionError`。

`AssertionError`类没有自己的方法，它们都是从父类`Error`继承而来，如下类概要所示：

```php
    AssertionError extends Error {
      final public string Error::getMessage (void)
      final public Throwable Error::getPrevious (void)
      final public mixed Error::getCode (void)
      final public string Error::getFile (void)
      final public int Error::getLine (void)
      final public array Error::getTrace (void)
      final public string Error::getTraceAsString (void)
      public string Error::__toString (void)
      final private void Error::__clone (void)
    }

```

PHP 7 提供了两个配置指令来控制`assert()`的行为--`zend.assertions`和`assert.exception`。只有当`zend.assertions = 1`和`assert.exception = 1`时，`assert()`函数才会被执行并可能抛出`AssertionError`，如下例所示：

```php
    <?php

    try {
      assert('developer' === 'programmer');
    } 
    catch (AssertionError $e) {
      echo 'Caught: ' . $e->getMessage();
    }

```

假设配置指令都已设置，上述代码将输出`Caught: assert('developer' === 'programmer')`消息。如果只有`zend.assertions = 1`但`assert.exception = 0`，那么`catch`块将没有效果，并且会引发以下警告：`Warning: assert(): assert('developer' === 'programmer') failed`。

`zend.assertions`派生可能在`php.ini`文件中完全启用或禁用。

# ParseError

`eval()`语言结构使我们能够执行任意的 PHP 代码。唯一的要求是代码不能包含在开头和结尾的 PHP 标记中。除此之外，传递的代码本身必须是有效的 PHP 代码。如果传递的代码无效，那么就会抛出`ParseError`。

`ParseError`类没有自己的方法，它们都是从父类`Error`继承而来，如下类概要所示：

```php
    ParseError extends Error {
      final public string Error::getMessage (void)
      final public Throwable Error::getPrevious (void)
      final public mixed Error::getCode (void)
      final public string Error::getFile (void)
      final public int Error::getLine (void)
      final public array Error::getTrace (void)
      final public string Error::getTraceAsString (void)
      public string Error::__toString (void)
      final private void Error::__clone (void)
    }

```

以下代码片段演示了有效的`eval()`表达式：

```php
    <?php

    try {
      $now = eval("return date('D, d M Y H:i:s');");
      echo $now;
    } 
    catch (ParseError $e) {
      echo 'Caught: ' . $e->getMessage();
    }

```

以下代码块演示了在评估代码中的解析错误：

```php
    <?php

    try {
      $now = eval("return date(D, d M Y H:i:s);");
      echo $now;
    } 
    catch (ParseError $e) {
      echo 'Caught: ' . $e->getMessage();
    }

```

几乎与一个正常工作的例子相同，你会注意到在日期函数参数周围缺少开头和结尾的(`'`)字符。这会破坏 eval 函数，触发`ParseError` catch 块，并输出以下内容：

```php
Caught: syntax error, unexpected 'M' (T_STRING), expecting ',' or ')'

```

现在，让我们看一下以下代码片段：

```php
    <?php

    try {
      $now = date(D, d M Y H:i:s);
      echo $now;
    }
    catch (ParseError $e) {
      echo 'Caught: ' . $e->getMessage();
    }

```

在这里，我们没有使用`eval()`表达式，而是故意破坏了代码。结果输出触发了解析错误，但这次不是通过对`catch`块的反应，这有点意料之中。在现代 IDE 环境中，如 PhpStorm、Netbeans 等，这种特定情况几乎不太可能发生，因为它们会自动警告我们有损坏的语法。

# TypeError

PHP 7 引入了*函数类型参数*和*函数返回类型*。这反过来意味着需要正确处理它们的误用错误。`TypeError`被引入来解决这些错误。

`TypeError`类没有自己的方法，它们都是从父类`Error`继承而来，如下类概要所示：

```php
    ParseError extends Error {
      final public string Error::getMessage (void)
      final public Throwable Error::getPrevious (void)
      final public mixed Error::getCode (void)
      final public string Error::getFile (void)
      final public int Error::getLine (void)
      final public array Error::getTrace (void)
      final public string Error::getTraceAsString (void)
      public string Error::__toString (void)
      final private void Error::__clone (void)
    } 

```

有至少三种可能的错误场景会引发`TypeError`，如下所示：

+   传递给函数的参数类型与声明的类型不匹配

+   函数返回值与声明的函数返回类型不匹配

+   传递给内置 PHP 函数的参数数量无效

以下代码演示了错误的函数参数类型：

```php
    <?php

    declare(strict_types = 1);

    function hello(string $name) {
      return "Hello $name!";
    }
    try {
      echo hello(34);
    } 
    catch (TypeError $e) {
      echo 'Caught: ' . $e->getMessage();
    }

```

在这里，我们定义了`hello()`函数，它期望接收一个字符串参数。然而，函数被传递了整数值。如果我们希望`catch`块实际上捕获`TypeError`，则需要`declare(strict_types = 1);`表达式。上述例子的结果如下输出：

```php
Caught: Argument 1 passed to hello() must be of the type string, integer given, called in...

```

以下代码演示了错误的函数返回类型：

```php
    <?php

    declare(strict_types = 1);

    function hello($name): string {
      return strlen($name);
    }

    try {
      echo hello('branko');
    } 
    catch (TypeError $e) {
      echo 'Caught: ' . $e->getMessage();
    }

```

在这里，定义的`hello()`函数没有定义特定的参数类型，但确实定义了函数返回类型。为了模拟错误的情况，我们将函数体改为返回整数值而不是字符串。与前面的例子一样，需要声明`strict_types = 1`来触发`TypeError`，结果如下输出：

```php
Caught: Return value of hello() must be of the type string, integer returned

```

以下代码演示了传递给内置 PHP 函数的无效参数数量：

```php
    <?php

    declare(strict_types = 1);

    try {
      echo strlen('test', 'extra');
    } 
    catch (TypeError $e) {
      echo 'Caught: ' . $e->getMessage();
    }

```

在这里，我们使用两个参数调用`strlen()`函数。虽然这个核心 PHP 函数本身是定义为只接受一个参数，但`strict_types = 1`声明将标准警告转换为`TypeError`，从而触发`catch`块。

# 未捕获的错误处理程序

虽然现在可以通过`try...catch`捕获大量的`Error`，但也有一种额外的机制来处理错误。PHP 提供了一种机制，即`set_error_handler()`函数，允许我们为所有未捕获的错误定义一个自定义处理程序函数。`set_error_handler()`函数接受两个参数，如下面的描述所示：

```php
    mixed set_error_handler ( 
      callable $error_handler 
      [, int $error_types = E_ALL | E_STRICT ] 
    )

```

`$error_handler`函数可以是作为字符串传递的处理程序函数名称，也可以是整个匿名处理程序函数，而`$error_types`是一个或多个（用`|`分隔）指定错误类型的掩码。处理程序函数本身也接受几个参数，如下面的描述所示：

```php
    bool handler ( 
      int $errno , 
      string $errstr 
      [, string $errfile 
        [, int $errline 
          [, array $errcontext ]]] 
    )

```

让我们看看以下两个例子：

```php
    <?php

    function handler($errno, $errstr, $errfile, $errline, $errcontext)

    {
      echo 'Handler: ' . $errstr;
    }

    set_error_handler('handler', E_USER_ERROR | E_USER_WARNING);

    echo 'start';
      trigger_error('Ups!', E_USER_ERROR);
    echo 'end';

```

```php
    <?php

    set_error_handler(function ($errno, $errstr, $errfile, $errline,
      $errcontext) {
      echo 'Handler: ' . $errstr;
    }, E_USER_ERROR | E_USER_WARNING);

    echo 'start';
      trigger_error('Ups!', E_USER_WARNING);
    echo 'end';

```

这些例子几乎是相同的。第一个例子使用了一个单独定义的处理程序函数，然后将其作为字符串参数传递给`set_error_handler()`。第二个例子使用了相同定义的匿名函数。这两个例子都使用`trigger_error()`函数，一个触发`E_USER_ERROR`，另一个触发`E_USER_WARNING`。执行时，两个输出都将包含`end`字符串。

虽然自定义处理程序函数使我们能够处理各种运行时错误，但有一些错误是我们无法处理的。以下错误类型无法使用用户定义的函数处理：`E_ERROR`、`E_PARSE`、`E_CORE_ERROR`、`E_CORE_WARNING`、`E_COMPILE_ERROR`、`E_COMPILE_WARNING`，以及在调用`set_error_handler()`的文件中引发的大多数`E_STRICT`。

# 触发错误

PHP 的`trigger_error()`函数提供了一种触发用户级错误/警告/通知消息的方法。它可以与内置错误处理程序一起使用，也可以与用户定义的错误处理程序一起使用，就像我们在前一节中看到的那样。

`trigger_error()`函数接受两个参数，如下面的描述所示：

```php
    bool trigger_error ( 
      string $error_msg 
      [, int $error_type = E_USER_NOTICE ] 
    )

```

`$error_msg`参数的限制为 1024 字节，而`$error_type`限制为`E_USER_ERROR`、`E_USER_WARNING`、`E_USER_NOTICE`和`E_USER_DEPRECATED`常量。

让我们看看以下例子：

```php
    <?php

    set_error_handler(function ($errno, $errstr) {
      echo 'Handler: ' . $errstr;
    });

    echo 'start';
    trigger_error('E_USER_ERROR!', E_USER_ERROR);
    trigger_error('E_USER_ERROR!', E_USER_WARNING);
    trigger_error('E_USER_ERROR!', E_USER_NOTICE);
    trigger_error('E_USER_ERROR!', E_USER_DEPRECATED);
    echo 'end';

```

在这里，我们有四个不同的`trigger_error()`函数调用，每个函数接受不同的错误类型。自定义错误处理程序对所有四个错误都起作用，我们的代码继续执行，最终输出`end`。

**错误模型**（`set_error_handler`和`trigger_error`）和**可抛出模型**（`try...catch`和`throw new ...`）之间存在某些概念上的相似之处。看起来，两者都可以捕获和触发错误。主要区别在于可抛出模型是一种更现代、面向对象的方式。也就是说，我们应该限制使用`trigger_error()`，只在绝对需要时才使用。

# 异常

异常最初是在 PHP 5 中引入的，它也带来了面向对象的模型。它们在整个时间内基本保持不变。PHP 5.5 添加了`finally`块，PHP 7 添加了使用`|`运算符以便通过单个`catch`块捕获多个异常类型的可能性，这是其中的重大变化。

`Exception`是 PHP 7 中所有用户异常的基类。与`Error`一样，`Exception`实现了`Throwable`接口，如下面的类概要所示：

```php
    Exception implements Throwable {
      /* Properties */
      protected string $message ;
      protected int $code ;
      protected string $file ;
      protected int $line ;

      /* Methods */
      public __construct (
        [ string $message = "" 
         [, int $code = 0 
          [, Throwable $previous = NULL ]]]
      )

      final public string getMessage (void)
      final public Throwable getPrevious (void)
      final public mixed getCode (void)
      final public string getFile (void)
      final public int getLine (void)
      final public array getTrace (void)
      final public string getTraceAsString (void)
      public string __toString (void)
      final private void __clone (void)
    }

```

异常仍然是面向对象错误处理的支柱。扩展、抛出和捕获异常的简单性使它们易于处理。

# 创建自定义异常处理程序

通过扩展内置的`Exception`类，PHP 让我们可以像抛出异常一样抛出任何对象。让我们看下面的例子：

```php
    <?php

    class UsernameException extends Exception {}

    class PasswordException extends Exception {}

    $username = 'john';
    $password = '';

    try {
      if (empty($username)) {
        throw new UsernameException();
      }
      if (empty($password)) {
        throw new PasswordException();
      }
      throw new Exception();
    } 
    catch (UsernameException $e) {
      echo 'Caught UsernameException.';
    } 
    catch (PasswordException $e) {
      echo 'Caught PasswordException.';
    } 
    catch (Exception $e) {
      echo 'Caught Exception.';
    } 
    finally {
      echo 'Finally.';
    }

```

在这里，我们定义了两个自定义异常，`UsernameException`和`PasswordException`。它们只是扩展了内置的`Exception`，并没有真正引入任何新的方法或功能。然后，我们定义了两个变量，`$username`和`$password`。`$password`变量被设置为空字符串。最后，我们设置了`try...catch...finally`块，其中包含三个不同的`catch`块。前两个`catch`块针对我们的自定义异常，第三个针对内置的`Exception`。由于密码为空，前面的例子将抛出`new PasswordException`，因此输出`Caught PasswordException. Finally.`字符串。

# 重新抛出异常

重新抛出异常在开发中是一种相对常见的做法。有时，我们希望捕获异常，查看一下，进行一些额外的逻辑，然后重新抛出异常，以便父`catch`块可以进一步处理它。

让我们看下面的例子：

```php
    <?php

    class FileNotExistException extends Exception {}

    class FileReadException extends Exception {}

    class FileEmptyException extends Exception {}

    $file = 'story.txt';

    try {
      try {
        $content = file_get_contents($file);
        if (!$content) {
          throw new Exception();
        }
      } 
      catch (Exception $e) {
        if (!file_exists($file)) {
          throw new FileNotExistException();
        } 
        elseif (!is_readable($file)) {
          throw new FileReadException();
        } 
        elseif (empty($content)) {
          throw new FileEmptyException();
        } 
        else {
          throw new Exception();
        }
      }
    }

    catch (FileNotExistException $e) {
      echo 'Caught FileNotExistException.';
    } 
    catch (FileReadException $e) {
      echo 'Caught FileReadException.';
    } 
    catch (FileEmptyException $e) {
      echo 'Caught FileEmptyException.';
    } 
    catch (Exception $e) {
      echo 'Caught Exception.';
    } 
    finally {
      echo 'Finally.';
    }

```

在这里，我们定义了三个简单的异常--`FileNotExistException`，`FileReadException`和`FileEmptyException`。这对应于我们在处理文件时可能遇到的三种不同的故障结果。然后，我们在`file_get_contents`函数调用周围添加了一些逻辑，尝试将其包装在`try...catch`块中。如果文件无法读取，`file_get_contents`函数的结果是布尔值`false`。知道这一点，并且知道`empty`函数调用在文件为空时结果为`false`，我们可以很容易地通过单个`if (!$content)`语句来检查文件是否正常。一旦抛出一般的`Exception`，就会有几种可能的情况。最明显的是缺少文件。令人惊讶的是，即使有`try...catch`块，如果文件丢失，PHP 也会输出以下内容：

```php
Warning: file_get_contents(story.txt): failed to open stream: No such file or directory in /index.php on line 13
Caught FileNotExistException.Finally.

```

我们可以清楚地看到，核心 PHP 语言引发了`Warning`，并触发了适当的`catch`和`finally`块。理想情况下，我们希望摆脱警告输出。一种可能的方法是使用错误控制运算符--at 符号（`@`）。它可以抑制错误和警告。这是非常危险的，应该非常小心使用。一般来说，错误和警告是触发处理的，而不是被抑制的。然而，在这种情况下，我们可能认为是合理的，因为我们将所有内容都包裹在`try...catch`块中。最后一个一般的`catch`块只是用来捕获未预料到的故障状态，这些状态不被我们的三个自定义异常所覆盖。

# 未捕获异常处理程序

PHP 提供了一种机制，即`set_exception_handler`函数，允许我们为所有未捕获的可抛出对象（包括异常）定义自定义处理程序函数。`set_exception_handler`函数接受一个可调用参数--可以是*作为字符串传递的函数名*，也可以是*整个匿名函数*。

让我们看下面的*作为字符串传递的函数名*示例：

```php
    <?php

    function throwableHandler(Throwable $t)
    {
      echo 'Throwable Handler: ' . $t->getMessage();
    }

    set_exception_handler('throwableHandler');

    echo 'start';
      throw new Exception('Ups!');
    echo 'end';

```

让我们看下面的*匿名函数*示例：

```php
    <?php

    set_exception_handler(function (Throwable $t) {
      echo 'Throwable Handler: ' . $t->getMessage();
    });

    echo 'start';
     throw new Exception('Ups!');
    echo 'end';

```

这两个代码示例做的事情是一样的，它们之间没有区别。除了第二个示例更美观外，因为不需要定义一个单独的函数，比如`throwableHandler()`，它只会在一个地方使用。这里需要注意的重要一点是，与`try...catch`块不同，对处理程序函数的调用是我们的应用程序执行的最后一件事情，这意味着在这种情况下，我们永远不会在屏幕上看到`end`字符串。

# 日志记录

日志记录是每个应用程序的重要方面。知道如何捕获错误并不一定意味着我们处理故障情况的方式是最好的。如果我们没有记录正确的细节，并将它们传递给正确的消费者，那么我们实际上并没有正确处理这种情况。

让我们考虑以下捕获和生成用户消息的示例：

```php
    try {
      //...
    } 
    catch (\Exception $e) {
      $messages[] = __('We can't add this item to your shopping cart right now.');
    }

```

让我们考虑以下示例：

```php
<?php try {
  //... } catch (\Exception $e) {
  $this->logger->critical($e);
  $messages[] = __("We can't add this item to your shopping cart right now . "); }

```

这两个示例都通过将消息存储到`$messages`变量中来响应异常，稍后将其显示给当前用户。这很好，因为应用程序不会崩溃，用户会看到发生了什么，并且应用程序被允许执行。但是，这真的很好吗？这两个示例几乎完全相同，除了一个细微的细节。第一个示例仅在错误发生时做出响应并立即做出反应。第二个示例使用`$this->logger->critical($e);`表达式来记录错误，可能是，但不一定是，记录到文件中。通过记录错误，我们使得消费者有可能稍后进行审查。消费者很可能是开发人员，他们可能会不时地查看日志文件。请注意，`$messages`数组并未直接传递给`$e`变量，而是适合用户情况的自定义消息。这是因为用户不应该看到我们可能传递给日志的详细级别。我们传递给日志的细节越多，就越容易排除应用程序的故障。通过记录整个异常实例对象，在这种情况下，我们基本上提供了开发人员需要了解的所有细节，以便尝试并防止将来的错误。

经过深思熟虑的使用，日志记录可以提供质量分析洞察，我们可以定期重复我们的代码库，并防止在初始开发过程中可能看不到的问题。除了记录错误，我们还可以轻松记录其他分析或其他重要的部分。

开源的 Elastic stack，可在[`www.elastic.co`](https://www.elastic.co)上获得，使我们能够可靠且安全地从任何来源以任何格式获取数据，并实时搜索、分析和可视化数据。Kibana 产品，可在[`www.elastic.co/products/kibana`](https://www.elastic.co/products/kibana)上获得，通过其交互式可视化为我们的数据赋予形状。

# 本地记录

PHP 具有内置的`error_log()`函数，它将错误消息发送到定义的错误处理程序；因此，为简单的记录提供了开箱即用的解决方案。

以下代码片段描述了`error_log()`函数的定义：

```php
    bool error_log ( 
       string $message 
      [, int $message_type = 0 
        [, string $destination 
          [, string $extra_headers ] ]] 
    )

```

参数定义如下：

+   `$message`：这是一个字符串类型的值，是我们想要记录的消息

+   `$message_type`：这是一个整数类型的值；它有四个可能的值，如下所示：

+   `0`：这是一个操作系统日志记录机制

+   `1`：这通过电子邮件发送到目标参数中的地址

+   `2`：这不再是一个选项

+   `3`：此消息附加到文件目的地

+   `4`：这直接发送到 SAPI 日志处理程序

+   `$destination`：这是一个字符串类型的值，仅在`$message_type = 1`时起作用，并表示电子邮件地址

+   `$extra_headers`：这是一个字符串类型的值，仅在`$message_type = 1`时起作用，并表示电子邮件头

`error_log()`函数与`php.ini`中定义的`log_errors`和`error_log`配置选项密切相关：

+   `log_errors`：这是一个布尔类型的配置选项。它告诉我们是否应该将错误消息记录到服务器错误日志或`error_log`。要记录到使用`error_log`配置选项指定的文件，请将其设置为`1`。

+   `error_log`：这是一个字符串类型的配置选项。它指定应将错误记录到的文件的名称。如果使用`syslog`，则将错误记录到系统记录器。如果未设置任何值，则将错误发送到 SAPI 错误记录器，这很可能是 Apache 中的错误日志或 CLI 中的 stderr。

以下示例演示了记录到文件中：

```php
    <?php

    ini_set('log_errors', 1);
    ini_set('error_log', dirname(__FILE__) . '/app-error.log');

    error_log('Test!');

```

`log_errors`和`error_log`选项可以在`.php`文件中定义；然而，建议在`php.ini`中这样做，否则，如果脚本有解析错误或根本无法运行，日志将不会记录任何错误。上面示例的结果输出将是一个`app-error.log`文件，位于执行脚本本身相同的目录中，内容如下：

```php
    [26-Dec-2016 08:11:32 UTC] Test!
    [26-Dec-2016 08:11:39 UTC] Test!
    [26-Dec-2016 08:11:42 UTC] Test!

```

以下示例演示了如何记录日志到电子邮件：

```php
    <?php

    ini_set('log_errors', 1);
    ini_set('error_log', dirname(__FILE__) . '/app-error.log');

    $headers = "From: john@server.loc\r\n";
    $headers .= "Subject: My PHP email logger\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=ISO-8859-1\r\n";

    error_log('<html><h2>Test!</h2></html>', 1, 'john@mail.com', $headers);

```

在这里，我们首先构建原始的`$headers`字符串，然后将其传递给`error_log()`函数，以及目标电子邮件地址。这是`error_log()`函数的一个明显缺点，因为我们需要熟悉电子邮件消息头的标准。

`error_log()`函数不是二进制安全的，这意味着`$message`参数不应包含空字符，否则它将被截断。为了避开这个限制，我们可以在调用`error_log()`之前使用一个转换/转义函数，比如`base64_encode()`、`rawurlencode()`或`addslashes()`。以下 RFC 可能对处理电子邮件消息头很有用：RFC 1896、RFC 2045、RFC 2046、RFC 2047、RFC 2048、RFC 2049 和 RFC 2822。

了解`error_log()`函数后，我们可以很容易地将其封装成我们自己的自定义函数，比如`app_error_log()`，从而抽象出整个电子邮件的样板，比如地址和头部。我们还可以使我们的`app_error_log()`函数同时记录到文件和电子邮件，从而实现一个简单的、一行的日志记录表达式，比如下面的例子，可能在我们的应用程序中使用：

```php
    try {
      //...
    } 
    catch (\Exception $e) {
      app_error_log($e);
    }

```

编写这样简单的日志记录器非常容易。然而，开发中的简单通常伴随着降低模块化的成本。幸运的是，有一些第三方库在日志记录功能方面非常强大。最重要的是，它们符合某种日志记录标准，我们将在下一节中看到。

# 使用 Monolog 进行日志记录

PHP 社区为我们提供了几个日志记录库可供选择，比如 Monolog、Analog、KLogger、Log4PHP 等。选择合适的库可能是一项艰巨的任务。尤其是因为我们可能决定以后更改日志记录机制，这可能会导致我们需要改变大量的代码。这就是 PSR-3 日志记录标准的作用。选择一个符合标准的库可以更容易地进行推理。

Monolog 是最受欢迎的 PHP 日志记录库之一。它是一个免费的、MIT 许可的库，实现了 PSR-3 日志记录标准。它允许我们轻松地将日志发送到文件、套接字、收件箱、数据库和各种网络服务。

我们可以通过在项目文件夹中运行以下控制台命令轻松安装 Monolog 库作为`composer`包：

```php
composer require monolog/monolog

```

如果`composer`不是一个选择，我们可以从 GitHub 上下载 Monolog，网址为[`github.com/Seldaek/monolog`](https://github.com/Seldaek/monolog)。那些使用主要 PHP 框架，比如 Symfony 或 Laravel 的人，可以直接使用 Monolog。

符合 PSR-3 日志记录标准也意味着 Monolog 支持 RFC 5424 描述的日志级别，如下所示：

+   `DEBUG (100)`: 调试级别消息

+   `INFO (200)`: 信息消息

+   `NOTICE (250)`: 正常但重要的条件

+   `WARNING (300)`: 警告条件

+   `ERROR (400)`: 错误条件

+   `CRITICAL (500)`: 临界条件

+   `ALERT (550)`: 必须立即采取行动

+   `EMERGENCY (600)`: 系统不可用

这些常量定义在`vendor/monolog/monolog/src/Monolog/Logger.php`文件中，大部分都有一个实际的用例示例。

每个 Monolog 记录器实例的核心概念是实例本身具有一个通道（名称）和一组处理程序。我们可以实例化多个记录器，每个定义一个特定的通道（db，request，router 等）。每个通道可以组合各种处理程序。处理程序本身可以在通道之间共享。通道反映在日志中，并允许我们轻松查看或过滤记录。最后，每个处理程序还有一个格式化器。格式化器对传入的记录进行规范化和格式化，以便处理程序输出有用的信息。

以下图表展示了这个记录器-通道-格式化器的结构：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/097c18e6-815f-427d-8fe3-96e011f9a995.png)

Monolog 提供了相当丰富的记录器和格式化器列表。

+   记录器：

+   记录到文件和系统日志（`StreamHandler`，`RotatingFileHandler`，`SyslogHandler`，...）

+   发送警报和电子邮件（`SwiftMailerHandler`，`SlackbotHandler`，`SendGridHandler`，...）

+   特定于日志的服务器和网络日志（`SocketHandler`，`CubeHandler`，`NewRelicHandler`，...）

+   开发中的日志记录（`FirePHPHandler`，`ChromePHPHandler`，`BrowserConsoleHandler`，...）

+   记录到数据库（`RedisHandler`，`MongoDBHandler`，`ElasticSearchHandler`，...）

+   格式化器：

+   `LineFormatter`

+   `HtmlFormatter`

+   `JsonFormatter`

+   ...

可以通过官方的 Monolog 项目页面获取完整的 Monolog 记录器和格式化器列表 [`github.com/Seldaek/monolog`](https://github.com/Seldaek/monolog)。

让我们看一个简单的例子：

```php
    <?php

    require 'vendor/autoload.php';

    use Monolog\Logger;
    use Monolog\Handler\RotatingFileHandler;
    use Monolog\Handler\BrowserConsoleHandler;

    $logger = new Logger('foggyline');

    $logger->pushHandler(new RotatingFileHandler(__DIR__ .  
      '/foggyline.log'), 7);
    $logger->pushHandler(new BrowserConsoleHandler());

    $context = [
      'user' => 'john',
      'salary' => 4500.00
    ];

    $logger->addDebug('Logging debug', $context);
    $logger->addInfo('Logging info', $context);
    $logger->addNotice('Logging notice', $context);
    $logger->addWarning('Logging warning', $context);
    $logger->addError('Logging error', $context);
    $logger->addCritical('Logging critical', $context);
    $logger->addAlert('Logging alert', $context);
    $logger->addEmergency('Logging emergency', $context);

```

在这里，我们创建了一个 `Logger` 实例，并将其命名为 `foggyline`。然后我们使用 `pushHandler` 方法推送内联实例化的两个不同处理程序的实例。

`RotatingFileHandler` 将记录日志到文件，并每天创建一个日志文件。它还会删除早于 `$maxFiles` 参数的文件，而在我们的示例中，该参数设置为 `7`。不管日志文件名是否设置为 `foggyline.log`，由 `RotatingFileHandler` 创建的实际日志文件中包含了时间戳，因此会得到一个名为 `foggyline-2016-12-26.log` 的文件。当我们考虑这一点时，这个处理程序的作用是非常显著的。除了创建新的日志条目之外，它还负责删除旧的日志。

以下是我们的 `foggyline-2016-12-26.log` 文件的输出：

```php
    [2016-12-26 12:36:46] foggyline.DEBUG: Logging debug {"user":"john","salary":4500} []
    [2016-12-26 12:36:46] foggyline.INFO: Logging info {"user":"john","salary":4500} []
    [2016-12-26 12:36:46] foggyline.NOTICE: Logging notice {"user":"john","salary":4500} []
    [2016-12-26 12:36:46] foggyline.WARNING: Logging warning {"user":"john","salary":4500} []
    [2016-12-26 12:36:46] foggyline.ERROR: Logging error {"user":"john","salary":4500} []
    [2016-12-26 12:36:46] foggyline.CRITICAL: Logging critical {"user":"john","salary":4500} []
    [2016-12-26 12:36:46] foggyline.ALERT: Logging alert {"user":"john","salary":4500} []
    [2016-12-26 12:36:46] foggyline.EMERGENCY: Logging emergency  {"user":"john","salary":4500} []

```

我们推送到堆栈的第二个处理程序 `BrowserConsoleHandler`，将日志发送到浏览器的 JavaScript 控制台，无需浏览器扩展。这适用于大多数支持控制台 API 的现代浏览器。该处理程序的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/464af28d-9107-4de6-9c85-dae25805202e.png)

通过这几行简单的代码，我们为我们的应用程序添加了相当令人印象深刻的日志功能。`RotatingFileHandler` 似乎非常适合用于生产运行应用程序的后续状态分析，而 `BrowserConsoleHandler` 可能作为加快持续开发的便捷方式。可以说，日志的作用远不止于记录错误。通过在各种日志级别记录各种信息，我们可以轻松地将 Monolog 库用作一种分析桥梁。只需将适当的处理程序推送到堆栈，然后将日志推送到各种目的地，例如 Elasticsearch 等。

# 总结

在本章中，我们详细研究了 PHP 的错误处理机制。PHP 7 通过将大部分错误处理模型包装在`Throwable`接口下，对其进行了相当大的清理。这使得可以通过`try...catch`块捕获核心错误，而在 PHP 7 之前，这些错误只能保留给`Exception`。现在，当我们遇到`Throwable`、`Error`、`Exception`、系统错误、用户错误、通知、警告等术语时，可能会有一些术语上的混淆需要消化。从高层次来说，我们可以说任何错误状态都是错误。更具体地说，现在我们有可抛出的错误，另一方面有错误。可抛出的错误包括`Error`和`Exception`的抛出和可捕获的实例，而错误基本上包括任何不可捕获为`Throwable`的东西。

处理错误状态如果没有适当的日志记录就不会真正完整。虽然内置的`error_log()`函数提供了足够的功能让我们开始，但更健壮的解决方案可以通过各种第三方库来实现。Monolog 库是最受欢迎的库之一，被用于数十个社区项目中。

在向前迈进时，我们将深入研究魔术方法及其为 PHP 语言带来的巨大力量。
