# 函数式 PHP（一）

> 原文：[`zh.annas-archive.org/md5/542d15e7552f9c0cf0925a989aaf5fc0`](https://zh.annas-archive.org/md5/542d15e7552f9c0cf0925a989aaf5fc0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

函数式编程是每年会议上都会出现的范式。JavaScript 社区可能是最早接触这个主题的社区之一，但现在这个主题也在使用其他各种语言的开发人员中讨论，比如 Ruby，Python 和 Java。

PHP 具有大多数开发所需的功能，可以开始使用函数式方法。你没有理由被置于一边，这本书旨在教授函数式编程的基础知识。

如果你完全是函数式编程的新手，或者想要复习基础知识并了解一些历史和好处，我建议你从附录开始。虽然它不是本书的第一章，因为内容与 PHP 没有直接关系，但它将帮助你将各种主题放入上下文，并更好地了解本书涵盖的主题。

# 本书涵盖的内容

第一章，“PHP 中的函数作为一等公民”，讨论了函数式编程，正如其名称所暗示的那样，围绕函数展开。在本章中，你将学习它们在 PHP 中可以被声明和使用的各种方式。

第二章，“纯函数，引用透明度和不可变性”，涵盖了任何函数式代码库的基石。你将学习它们的含义以及如何应用它们来获益。

第三章，“PHP 中的函数式基础”，讨论了函数式编程，就像任何范式一样，依赖于一些核心概念。本章将以简单的方式呈现它们，然后进一步讨论。

第四章，“组合函数”，描述了函数如何经常被用作构建块，使用函数组合。在这一章中，你将学习如何在 PHP 中进行函数组合，以及在这样做时需要牢记的重要性。

第五章，“函子，应用函子和单子”，从更简单的概念开始，如函子和应用函子，然后逐渐建立我们的知识，最终介绍单子的概念，消除一些围绕这个术语的恐惧。

第六章，“现实生活中的单子”，帮助你了解单子抽象的一些实际用法，以及如何使用它来编写更好的代码。

第七章，“函数式技术和主题”，涉及类型系统、模式匹配、无点风格等来自函数式编程广阔领域的主题。

第八章，“测试”，教你函数式编程不仅有助于编写更易理解和维护的代码，而且还有助于简化测试。

第九章，“性能效率”，让你知道在 PHP 中使用函数式技术是有成本的。我们将首先讨论它，然后看看它如何在其他与性能相关的主题中发挥作用。

第十章，“PHP 框架和 FP”，介绍了一种可以应用于改进任何项目中代码的技术，因为目前 PHP 中没有专门的函数式编程框架。

第十一章，“设计一个函数式应用程序”，将为你提供一些建议，如果你想使用尽可能多的函数式代码来开发整个应用程序。你还将了解函数式响应式编程和 RxPHP 库。

`附录`，*我们谈论函数式编程时在谈论什么？*，是关于函数式编程的介绍和历史，以及它的好处和术语表。这实际上是你应该阅读的书的第一部分，但由于我们不是从 PHP 的角度来探讨这个主题，所以它被呈现为附录。

# 本书需要什么

你需要有一台安装了 PHP 的电脑。如果你知道如何使用命令行，那会更容易，但所有的例子也应该在浏览器中运行，也许需要做一些小的调整。

在学习函数式编程的同时，我还推荐使用一个 REPL（Read-Eval-Print-Loop）。在写这本书时，我个人使用了**Boris**。你可以在[`github.com/borisrepl/boris`](https://github.com/borisrepl/boris)找到它。另一个很好的选择是**PsySH**（[`psysh.org`](http://psysh.org)）。

虽然不是必需的，但 REPL 将允许你快速测试你的想法，并在不必在编辑器和命令行之间切换的情况下玩弄本书中将介绍的各种概念。

我也假设你已经安装了 Composer，并且知道如何使用它来安装新的包；如果没有，你可以在[`getcomposer.org`](https://getcomposer.org)找到它。本书将介绍多个库，并且推荐使用 Composer 来安装它们。

本书中的所有代码都在 PHP 7.0 上进行了测试，这是推荐的版本。然而，它也应该在任何更新的版本上运行。在进行一些小的调整后，大多数示例也应该在 PHP 5.6 上运行。我们将在整本书中使用 PHP 7.0 引入的新标量类型提示功能，但如果你移除它们，代码应该可以轻松兼容较低版本。

# 这本书是为谁准备的

这本书不需要对函数式编程有任何了解；但需要有先前的编程经验。另外，面向对象编程的基本概念不会被深入讨论。

深入了解 PHP 语言并不是必需的，因为不常见的语法将会被解释。这本书应该可以被理解为一个从未写过一行 PHP 代码的人，只要付出一些努力。

这本书可以被视为一本关于 PHP 函数式编程的入门书，这意味着我们将逐步建立知识。然而，由于主题非常广泛，而且页面有限，我们有时会快速移动。这就是为什么我鼓励你在学习这些概念时玩一下，并在每章结束时花一些时间确保你正确理解了它。

# 约定

在本书中，你会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的例子和它们含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名都显示如下：“下面的代码行读取链接并将其分配给`BeautifulSoup`函数。”

代码块设置如下：

```php
<?php
function getPrices(array $products) {
  $prices = [];
  foreach($products as $p) {
    if($p->stock > 0) {
      $prices[] = $p->price;
    }
  }
  return $prices;
}
```

当我们希望引起你对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```php
<?php
function getPrices(array $products) {
  $prices = [];
  foreach($products as $p) {
    **if($p->stock > 0) {**
**      $prices[] = $p->price;**
**    }** }
  return $prices;
}
```

**任何命令行输入或输出都是这样写的：**

```php
**composer require rx/stream** 
```

**新术语**和**重要单词**以粗体显示。在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中以这种方式出现：“点击**下一步**按钮会将你移动到下一个屏幕。”

### **注意**

**警告或重要提示会以这样的方式出现。**

### **提示**

**提示和技巧会以这种形式出现。**


# 第一章：PHP 中的函数作为一等公民

函数式编程，顾名思义，围绕函数展开。为了有效地应用函数式技术，语言必须支持函数作为一等公民，也称为**第一类函数**。

这意味着函数被视为任何其他值。它们可以被创建并作为参数传递给其他函数，并且它们可以作为返回值使用。幸运的是，PHP 就是这样一种语言。本章将演示函数可以被创建和使用的各种方式。

在这一章中，我们将涵盖以下主题：

+   声明函数和方法

+   标量类型提示

+   匿名函数

+   闭包

+   将对象用作函数

+   高阶函数

+   可调用类型提示

# 开始之前

由于 PHP 7 的首次发布发生在 2015 年 12 月，因此本书中的示例将使用该版本。

然而，由于这是一个相当新的版本，每次使用新功能时，都将清楚地概述和解释。此外，由于并非每个人都能立即迁移，我们将尽可能提出在 PHP 5 上运行代码所需的更改。

撰写时可用的最新版本是 7.0.9。所有代码和示例都经过了这个版本的验证。

## 编码标准

本书中的示例将遵守**PSR**-**2**（**PHP 标准推荐 2**）及其父推荐标准 PSR-1 的编码风格，大多数所介绍的库也应该如此。对于不熟悉它们的人，以下是最重要的部分：

+   类位于命名空间中，使用首字母大写的驼峰命名法

+   方法使用驼峰命名法，首字母不大写

+   常量使用全大写字母书写

+   类和方法的大括号在新行上，其他大括号在同一行上

此外，尽管没有在 PSR-2 中定义，但做出了以下选择：

+   函数名称使用蛇形命名法

+   参数、变量和属性名称使用蛇形命名法

+   属性尽可能是私有的

## 自动加载和 Composer

示例还将假定存在一个符合 PSR-4 的自动加载器。

由于我们将使用 Composer 依赖管理器来安装所介绍的库，我们建议将其用作自动加载器。

# 函数和方法

尽管本书不是为 PHP 初学者设计的，但我们将快速介绍一些基础知识，以确保我们共享一个共同的词汇。

在 PHP 中，通常使用`function`关键字声明函数：

```php
<?php 

function my_function($parameter, $second_parameter) 
{ 
    // [...] 
} 
```

在类内声明的函数称为**方法**。它与传统函数不同，因为它可以访问对象属性，具有可见性修饰符，并且可以声明为静态的。由于我们将尽量编写尽可能纯净的代码，我们的属性将是`private`类型：

```php
<?php 

class SomeClass 
{ 
   private $some_property; 

   // a public function 
   public function some_function() 
   { 
       // [...] 
   } 

   // a protected static function 
   static protected function other_function() 
   { 
       // [...] 
   } 
} 
```

# PHP 7 标量类型提示

在 PHP 5 中，您已经可以为类、可调用函数和数组声明类型提示。PHP 7 引入了标量类型提示的概念。这意味着您现在可以声明您想要`string`、`int`、`float`或`bool`数据类型，无论是参数还是返回类型。语法与其他语言中的语法大致相似。

与类类型提示相反，您还可以在**严格**模式和**非严格**模式之间进行选择，后者是默认模式。这意味着 PHP 将尝试将值转换为所需的类型。如果没有信息丢失，转换将会悄无声息地发生，否则将引发警告。这可能导致与字符串到数字转换或 true 和 false 值相同的奇怪结果。

以下是一些此类强制转换的示例：

```php
<?php 

function add(float $a, int $b): float { 
    return $a + $b; 
} 

echo add(3.5, 1); 
// 4.5 
echo add(3, 1); 
// 4 
echo add("3.5", 1); 
// 4.5 
echo add(3.5, 1.2); // 1.2 gets casted to 1 
// 4.5 
echo add("1 week", 1); // "1 week" gets casted to 1.0 
// PHP Notice:  A non well formed numeric value encountered 
// 2 
echo add("some string", 1); 
// Uncaught TypeError Argument 1 passed to add() must be of the type float, string given 

function test_bool(bool $a): string { 
    return $a ? 'true' : 'false'; 
} 

echo test_bool(true); 
// true 
echo test_bool(false); 
// false 
echo test_bool(""); 
// false 
echo test_bool("some string"); 
// true 
echo test_bool(0); 
// false 
echo test_bool(1); 
// true 
echo test_bool([]); 
// Uncaught TypeError: Argument 1 passed to test_bool() must be of the type Boolean 
```

如果您想避免强制转换的问题，可以选择启用严格模式。这样，PHP 将在值不完全符合所需类型时引发错误。为此，必须在文件的第一行之前添加`declare(strict_types=1)`指令。它之前不能有任何内容。

PHP 允许的唯一转换是从`int`到`float`，通过添加`.0`来实现，因为绝对不会有数据丢失的风险。

以下是与之前相同的示例，但启用了严格模式：

```php
<?php 

declare(strict_types=1); 

function add(float $a, int $b): float { 
    return $a + $b; 
} 

echo add(3.5, 1); 
// 4.5 
echo add(3, 1); 
// 4 
echo add("3.5", 1); 
// Uncaught TypeError: Argument 1 passed to add() must be of the type float, string given 
echo add(3.5, 1.2); // 1.2 gets casted to 1 
// Uncaught TypeError: Argument 2 passed to add() must be of the type integer, float given 
echo add("1 week", 1); // "1 week" gets casted to 1.0 
// Uncaught TypeError: Argument 1 passed to add() must be of the type float, string given 
echo add("some string", 1); 
// Uncaught TypeError: Argument 1 passed to add() must be of the type float, string given 

function test_bool(bool $a): string { 
    return $a ? 'true' : 'false'; 
} 

echo test_bool(true); 
// true 
echo test_bool(false); 
// false 
echo test_bool(""); 
// Uncaught TypeError: Argument 1 passed to test_bool() must be of the type boolean, string given 
echo test_bool(0); 
// Uncaught TypeError: Argument 1 passed to test_bool() must be of the type boolean, integer given 
echo test_bool([]); 
// Uncaught TypeError: Argument 1 passed to test_bool() must be of the type boolean, array given 
```

尽管此处未进行演示，但返回类型也适用相同的转换规则。根据模式的不同，PHP 将愉快地执行相同的转换，并显示与参数提示相同的警告和错误。

另一个微妙之处是应用的模式是在进行函数调用的文件顶部声明的模式。这意味着当您调用在另一个文件中声明的函数时，不会考虑该文件的模式。只有当前文件顶部的指令才重要。

关于类型引发的错误，我们将在第三章中看到，*PHP 中的函数基础*，PHP 7 中的异常和错误处理发生了变化，您可以使用它来捕获这些错误。

从现在开始，只要有意义，我们的示例将使用标量类型提示，以使代码更健壮和可读。

强制类型可以被视为繁琐，并且在开始使用时可能会导致一些恼人的问题，但从长远来看，我可以向您保证，它将使您免受一些讨厌的错误。解释器可以执行的所有检查都是您无需自行测试的内容。

这也使得你的函数更容易理解和推理。查看你的代码的人不必问自己一个值可能是什么，他们确切地知道他们必须传递什么样的数据作为参数，以及他们将得到什么。结果是认知负担减轻了，你可以利用时间思考解决问题，而不是记住代码的琐碎细节。

# 匿名函数

您可能已经很熟悉我们看到的声明函数的语法。您可能不知道的是，函数不一定需要有名称。

匿名函数可以分配给变量，用作回调并具有参数。

在 PHP 文档中，匿名函数一词与*闭包*一词可以互换使用。正如我们将在下面的代码片段中看到的，匿名函数甚至是`Closure`类的一个实例，我们将讨论这一点。根据学术文献，尽管这两个概念相似，但有些不同。闭包一词的第一个用法是在 1964 年 Peter Landin 的《表达式的机械评估》中。在这篇论文中，闭包被描述为具有环境部分和控制部分。我们将在本节中声明的函数不会有任何环境，因此严格来说，它们不是闭包。

为了避免阅读其他作品时产生混淆，本书将使用*匿名函数*一词来描述没有名称的函数，就像本节中所介绍的那样：

```php
<?php 

$add = function(float $a, float $b): float { 
    return $a + $b; 
}; 
// since this is an assignment, you have to finish the statement with a semicolon 
```

前面的代码片段声明了一个匿名函数，并将其分配给一个变量，以便我们稍后可以将其重用为另一个函数的参数或直接调用它：

```php
$add(5, 10); 
$sum = array_reduce([1, 2, 3, 4, 5], $add, 0); 
```

如果您不打算重复使用，也可以直接将匿名函数声明为参数：

```php
<?php 
$uppercase = array_map(function(string $s): string { 
  return strtoupper($s); 
}, ['hello', 'world']); 
```

或者您可以像返回任何其他类型的值一样返回一个函数：

```php
<?php 

function return_new_function() 
{ 
  return function($a, $b, $c) { /* [...] */}; 
} 
```

# 闭包

正如我们之前所看到的，闭包的学术描述是指具有对外部环境的访问权限的函数。在本书中，尽管 PHP 使用后一种术语来称呼匿名函数和闭包，但我们将坚持这种语义。

您可能熟悉 JavaScript 的闭包，其中您可以简单地使用外部范围的任何变量而无需进行任何特殊操作。在 PHP 中，您需要使用`use`关键字将现有变量导入匿名函数的范围内：

```php
<?php 

$some_variable = 'value'; 

$my_closure = function() use($some_variable) 
{ 
  // [...] 
}; 
```

PHP 闭包使用早期绑定方法。这意味着闭包内的变量将具有闭包创建时变量的值。如果之后更改变量，则闭包内将看不到更改：

```php
<?php 

$s = 'orange'; 

$my_closure = function() use($s) { echo $s; }; 
$my_closure(); // display 'orange' 

$a = 'banana'; 
$my_closure(); // still display 'orange' 
```

你可以通过引用传递变量，以便变量的更改在闭包内部传播，但由于这是一本关于函数式编程的书，在这本书中我们尝试使用不可变数据结构并避免状态，因此如何做到这一点留给读者作为练习。

请注意，当你将对象传递给闭包时，对对象属性的任何修改都将在闭包内部可访问。PHP 在将对象传递给闭包时不会复制对象。

## 类内的闭包

如果你在类内声明任何匿名函数，它将自动通过通常的`$this`变量获得实例引用。为了保持词汇的一致性，该函数将自动变成一个闭包：

```php
<?php 

class ClosureInsideClass 
{ 
    public function testing() 
    { 
        return function() { 
            var_dump($this); 
        }; 
    } 
} 

$object = new ClosureInsideClass(); 
$test = $object->testing(); 

$test(); 
```

如果你想避免这种自动绑定，你可以声明一个静态匿名函数：

```php
<?php 

class ClosureInsideClass 
{ 
    public function testing() 
    { 
        return (static function() { 
            // no access to $this here, the following line 
            // will result in an error. var_dump($this); 
        }); 
    } 
}; 

$object = new ClosureInsideClass(); 
$test = $object->testing(); 

$test(); 
```

# 使用对象作为函数

有时，你可能希望将函数分成更小的部分，但这些部分不对所有人都可见。在这种情况下，你可以利用任何对象上的`__invoke`魔术方法，让你将实例作为函数使用，并将那个辅助函数隐藏为对象内部的私有方法：

```php
<?php 

class ObjectAsFunction 
{ 
    private function helper(int $a, int $b): int 
    { 
        return $a + $b; 
    } 

    public function __invoke(int $a, int $b): int 
    { 
      return $this->helper($a, $b); 
    } 
} 

$instance = new ObjectAsFunction(); 
echo $instance(5, 10); 
```

`__invoke`方法将使用你传递给实例的任何参数进行调用。如果你愿意，你也可以为你的对象添加一个构造函数，并使用它包含的任何方法和属性。只需尽量保持纯净，因为一旦使用可变属性，你的函数将变得更难理解。

# `Closure`类

所有匿名函数实际上都是`Closure`类的实例。然而，正如文档中所述（[`php.net/manual/en/class.closure.php`](http://php.net/manual/en/class.closure.php)），这个类不使用前面提到的`__invoke`方法；这是 PHP 解释器中的一个特例：

> *除了这里列出的方法，这个类还有一个`__invoke`方法。这是为了与实现调用魔术的其他类保持一致，因为这个方法不用于调用函数。*

类上的这个方法允许你更改`$this`变量在闭包内部绑定到哪个对象。你甚至可以将一个对象绑定到类外创建的闭包上。

如果你开始使用`Closure`类的特性，请记住`call`方法是在 PHP 7 中才被添加的。

# 高阶函数

PHP 函数可以将函数作为参数并返回函数作为返回值。执行任何这些操作的函数称为高阶函数。就是这么简单。

实际上，如果你阅读以下代码示例，你会很快发现我们已经创建了多个高阶函数。你还会发现，毫不奇怪，你将学到的大多数函数式技术都围绕着高阶函数。

# 什么是可调用？

`callable`是一种类型提示，可以用来强制函数的参数是可以调用的东西，比如一个函数。从 PHP 7 开始，它也可以用作返回值的类型提示：

```php
<?php 

function test_callable(callable $callback) : callable { 
    $callback(); 
    return function() { 
        // [...] 
    }; 
} 
```

然而，类型提示无法强制可调用的参数数量和类型。但能够保证有可调用的东西已经很好了。

可调用可以采用多种形式：

+   用于命名函数的字符串

+   用于类方法或静态函数的数组

+   匿名函数或闭包的变量

+   带有`__invoke`方法的对象

让我们看看如何使用所有这些可能性。让我们从按名称调用一个简单的函数开始：

```php
$callback = 'strtoupper'; 
$callback('Hello World !'); 
```

我们也可以对类内的函数做同样的操作。让我们声明一个带有一些函数的`A`类，并使用数组来调用它。

```php
class A { 
    static function hello($name) { return "Hello $name !\n"; } 
    function __invoke($name) { return self::hello($name); } 
} 

// array with class name and static method name 
$callback = ['A', 'hello']; 
$callback('World'); 
```

使用字符串只对静态方法有效，因为其他方法将需要一个对象作为它们的上下文。对于静态方法，你也可以直接使用一个简单的字符串，但这只适用于 PHP 7 及更高版本；之前的版本不支持这种语法：

```php
$callback = 'A::hello'; 
$callback('World'); 
```

您也可以轻松地在类实例上调用方法：

```php
$a = new A(); 

$callback = [$a, 'hello']; 
$callback('World'); 
```

由于我们的`A`类具有`__invoke`方法，因此我们可以直接将其用作`callable`：

```php
$callback = $a; 
$callback('World'); 
```

您还可以使用任何变量，其中分配了一个匿名函数作为`callable`：

```php
$callback = function(string s) { 
    return "Hello $s !\n"; 
} 
$callback('World'); 
```

PHP 还为您提供了两个助手来调用函数，即`call_user_func_array`和`call_user_func`。它们将可调用作为参数，并且您还可以传递参数。对于第一个助手，您传递一个包含所有参数的数组；对于第二个助手，您分别传递它们：

```php
call_user_func_array($callback, ['World']); 
```

最后要注意的一点是，如果您使用了`callable`类型提示：任何包含已声明的函数名称的字符串都被视为有效；这有时会导致一些意外的行为。

一个有些牵强的例子是一个测试套件，您可以通过传递一些字符串来检查某些函数是否只接受有效的可调用对象，并捕获结果异常。在某个时候，您引入了一个库，现在这个测试失败了，尽管两者应该是无关的。发生的情况是，所涉及的库声明了一个与您的字符串完全相同的函数名称。现在，该函数存在，不再引发异常。

# 总结

在本章中，我们发现了如何创建新的匿名函数和闭包。您现在也熟悉了传递它们的各种方式。我们还了解了新的 PHP 7 标量类型提示，这有助于使我们的程序更加健壮，以及`callable`类型提示，这样我们就可以强制参数或返回值为有效函数。

对于那些已经使用 PHP 一段时间的人来说，本章可能没有什么新鲜的内容。但现在我们有了一个共同的基础，这将帮助我们进入函数式世界。

在 PHP 函数的基础知识介绍完毕后，我们将在下一章中了解有关函数式编程的基本概念。我们将看到，您的函数必须遵守某些规则，才能真正在函数式代码库中发挥作用。


# 第二章：纯函数、引用透明度和不可变性

阅读有关函数式编程的附录的人会发现，它围绕纯函数展开，换句话说，只使用其输入来产生结果的函数。

确定一个函数是否是纯的似乎很容易。只需检查是否调用了任何全局状态，对吗？遗憾的是，事情并不那么简单。函数产生副作用的方式也有多种。有些很容易发现，而其他一些则更难。

本章不会涵盖使用函数式编程的好处。如果您对好处感兴趣，我建议您阅读附录，其中深入讨论了这个主题。然而，我们将讨论不可变性和引用透明性所提供的优势，因为它们相当具体，并且在附录中只是粗略地提到。

在本章中，我们将涵盖以下主题：

+   隐藏的输入和输出

+   函数纯度

+   不可变性

+   引用透明度

# 两组输入和输出

让我们从一个简单的函数开始：

```php
<?php 

function add(int $a, int $b): int 
{ 
    return $a + $b; 
} 
```

这个函数的输入和输出很容易发现。我们有两个参数和一个返回值。毫无疑问，这个函数是纯的。

参数和返回值是函数可能具有的第一组输入和输出。但还有第二组，通常更难发现。看看以下两个函数：

```php
<?php 

function nextMessage(): string 
{ 
    return array_pop($_SESSION['message']); 
} 

// A simple score updating method for a game 
function updateScore(Player $player, int $points) 
{ 
    $score = $player->getScore(); 
    $player->setScore($score + $points); 
} 
```

第一个函数没有明显的输入。然而，很明显我们从`$_SESSION`变量中获取一些数据来创建输出值，所以我们有一个隐藏的输入。我们还对会话产生了隐藏的副作用，因为`array_pop`方法从消息列表中删除了我们刚刚得到的消息。

第二种方法没有明显的输出。但是，更新玩家的得分显然是一个副作用。此外，我们从玩家那里得到的`$score`可能被视为函数的第二个输入。

在这样简单的代码示例中，隐藏的输入和输出很容易发现。然而，随着时间的推移，尤其是在面向对象的代码库中，情况很快变得更加困难。不要误解，任何隐藏的东西，即使以最明显的方式隐藏，都可能产生后果，比如：

+   增加认知负担。现在你必须考虑`Session`或`Player`类中发生了什么。

+   相同的输入参数可能导致测试结果不同，因为软件的某些其他状态已经改变，导致难以理解的行为。

+   函数签名或 API 并不清楚您可以从函数中期望什么，这使得有必要阅读它们的代码或文档。

这两个看起来简单的函数的问题在于它们需要读取和更新程序的现有状态。本章的主题还不是向您展示如何更好地编写它们，我们将在第六章《真实生活中的单子》中讨论这个问题。

对于习惯于依赖注入的读者来说，第一个函数使用了静态调用，可以通过注入 Session 变量的实例来避免。这样做将解决隐藏输入的问题，但我们修改`$_SESSION`变量的事实仍然是副作用。

本章的其余部分将尝试教会您如何发现不纯的函数以及它们对函数式编程和代码质量的重要性。

在本书的其余部分，我们将使用术语“副作用”来表示隐藏的输入，以及“副作用”来表示隐藏的输出。这种二分法并不总是被使用，但我认为它有助于更准确地描述我们讨论的代码中的隐藏依赖或隐藏输出。

尽管是一个更广泛的概念，可用的功能性文献可能会使用术语“自由变量”来指代副作用。维基百科关于这个主题的文章陈述如下：

> *在计算机编程中，自由变量是指在函数中使用的不是局部变量也不是该函数的参数的变量。在这个上下文中，非局部变量通常是一个同义词。*

根据这个定义，使用`use`关键字传递给 PHP 闭包的变量可以被称为自由变量；这就是为什么我更喜欢使用副作用这个术语来清楚地区分这两者。

# 纯函数

假设你有一个函数签名`getCurrentTvProgram (Channel $channel)`。在没有函数纯度的指示的情况下，你无法知道这样一个函数背后可能隐藏的复杂性。

你可能会得到实际播放在给定频道的节目。但你不知道函数是否检查了你是否已登录系统。也许有一些用于分析目的的数据库更新。也许函数会因为日志文件处于只读状态而返回异常。你无法确定，所有这些都是副作用或者副作用。

考虑到所有与这些隐藏依赖关系相关的复杂性，你面临三个选择：

+   深入文档或代码，了解所有正在发生的事情

+   让依赖关系显而易见

+   什么都不做，祈求最好的结果

最后一个选项在短期内显然更好，但你可能会受到严重的打击。第一个选项可能看起来更好，但你的同事在应用程序的其他地方也需要使用这个函数，他们需要像你一样遵循相同的路径吗？

第二个选项可能是最困难的，因为一开始需要付出巨大的努力，因为我们根本不习惯这样做。但一旦你完成了，好处就会开始积累。并且随着经验的增加，这将变得更容易。

## 封装呢？

封装是为了隐藏实现细节。纯度是为了让隐藏的依赖关系变得明显。这两者都是有用的，是良好的实践，它们并不冲突。如果你足够小心，你可以同时实现这两者，这通常是函数式程序员所追求的。他们喜欢简洁、简单的解决方案。

简单来说，这就是解释：

+   封装是为了隐藏内部实现

+   避免副作用是为了让外部输入变得明显

+   避免副作用是为了让外部变化变得明显

## 发现副作用的原因

让我们回到我们的`getCurrentTvProgram`函数。接下来的实现并不纯净，你能发现原因吗？

为了帮助你一点，我会告诉你到目前为止我们所学到的关于纯函数的东西意味着当使用相同的参数调用时，它们总是返回相同的结果：

```php
<?php 

function getCurrentTvProgram(Channel $channel ): string 

{ 
    // let's assume that getProgramAt is a pure method. return $channel->getProgramAt(time()); 
} 
```

明白了吗？我们的嫌疑对象是对`time()`方法的调用。因为如果你在不同的时间调用该函数，你会得到不同的结果。让我们来修复这个问题：

```php
<?php 

functiongetTvProgram(Channel $channel, int $when): string 
{ 
    return $channel->getProgramAt($when); 
} 
```

我们的函数不仅是纯净的，这本身就是一个成就，我们还获得了两个好处：

+   现在我们可以根据名称更改隐含的意思来获取任何时间的节目

+   现在可以测试该函数，而无需使用某种魔术技巧来改变当前时间

让我们快速看一些其他副作用的例子。在阅读之前，尝试自己找出问题：

```php
<?php 

$counter = 0; 

function increment() 
{ 
    global $counter; 
    return ++$counter; 
} 

function increment2() 
{ 
    static $counter = 0;
    return ++$counter; 
} 

function get_administrators(EntityManager $em) 
{ 
    // Let's assume $em is a Doctrine EntityManager allowing 
    // to perform DB queries 
    return $em->createQueryBuilder() 
              ->select('u') 
              ->from('User', 'u') 
              ->where('u.admin = 1') 
              ->getQuery()->getArrayResult(); 
} 

function get_roles(User $u) 
{ 
    return array_merge($u->getRoles(), $u->getGroup()->getRoles()); 
} 
```

使用`global`关键字很明显地表明第一个函数使用了全局范围的某个变量，因此使函数不纯。从这个例子中可以得出的关键点是 PHP 作用域规则对我们有利。任何你能发现这个关键字的函数很可能是不纯的。

第二个示例中的静态关键字是一个很好的指示，表明我们可能会尝试在函数调用之间存储状态。在这个例子中，它是一个在每次运行时递增的计数器。该函数显然是不纯的。然而，与`global`变量相反，使用`static`关键字可能只是一种在调用之间缓存数据的方式，因此在得出结论之前，您将不得不检查为什么使用它。

第三个函数毫无疑问是不纯的，因为进行了一些数据库访问。如果您只允许使用纯函数，您可能会问自己如何从数据库或用户那里获取数据。如果您想编写纯函数式代码，第六章将更深入地探讨这个主题。如果您无法或不愿意完全使用函数式编程，我建议您尽可能将不纯的调用分组，然后尝试从那里仅调用纯函数，以限制产生副作用的地方。

关于第四个函数，仅仅通过查看它，您无法确定它是否是纯的。您将不得不查看被调用的方法的代码。在大多数情况下，您将遇到这种情况，一个函数调用其他函数和方法，您也将不得不阅读以确定纯度。

## 发现副作用

通常，发现副作用比发现副因更容易。每当您更改一个将对外部产生可见影响的值，或者在这样做时调用另一个函数，您都会产生副作用。

如果我们回到之前定义的两个`increment`函数，您对它们有什么看法？考虑以下代码：

```php
<?php 

$counter = 0; 

function increment() 
{ 
    global $counter; 
    return ++$counter; 
} 

function increment2() 
{ 
    static $counter = 0; 
    return ++$counter; 
} 
```

第一个函数显然对全局变量产生了副作用。但第二个版本呢？变量本身无法从外部访问，所以我们能认为该函数是没有副作用的吗？答案是否定的。因为更改意味着对函数的后续调用将返回另一个值，这也属于副作用。

让我们看一些函数，看看您是否能发现副作用：

```php
<?php 

function set_administrator(EntityManager $em, User $u) 
{ 
    $em->createQueryBuilder() 
       ->update('models\User', 'u') 
       ->set('u.admin', 1) 
       ->where('u.id = ?1') 
       ->setParameter(1, $u->id) 
       ->getQuery()->execute(); 
} 

function log_message($message) 
{ 
    echo $message."\n"; 
} 

function updatePlayers(Player $winner, Player $loser, int $score) 
{ 
    $winner->updateScore($score); 
    $loser->updateScore(-$score); 
} 
```

第一个函数显然有副作用，因为我们更新了数据库中的值。

第二个方法向屏幕打印了一些内容。通常这被认为是一个副作用，因为该函数对其范围之外的东西产生了影响，也就是我们的情况下，屏幕。

最后，最后一个函数可能会产生副作用。这是一个很好的、基于方法名称的猜测。但在我们看到方法的代码以验证之前，我们不能确定。当发现副作用时，通常需要深入挖掘，而不仅仅是一个函数，以确定它是否会产生副作用。

## 对象方法呢？

在一个纯粹的函数式语言中，一旦需要更改对象、数组或任何类型的集合中的值，实际上会返回一个具有新值的副本。这意味着任何方法，例如`updateScore`方法，都不会修改对象的内部属性，而是会返回一个具有新分数的新实例。

这可能看起来一点也不实用，鉴于 PHP 本身提供的可能性，我同意。然而，我们将看到一些真正有助于管理这一点的函数式技术。

另一个选择是决定实例在更改后不是相同的值。在某种程度上，这已经是 PHP 的情况。考虑以下示例：

```php
<?php 
class Test 
{ 
    private $value; 
    public function __construct($v) 
    { 
        $this->set($v); 
    } 

    public function set($v) { 
        $this->value = $v; 
    } 
} 

function compare($a, $b) 
{ 
    echo ($a == $b ? 'identical' : 'different')."\n"; 
} 

$a = new Test(2); 
$b = new Test(2); 

compare($a, $b); 
// identical 

$b->set(10); 
compare($a, $b); 
// different 

$c = clone $a; 
$c->set(5); 
compare($a, $c); 
```

在进行简单的对象相等比较时，PHP 考虑的是内部值而不是实例本身来进行比较。重要的是要注意，一旦使用严格比较（例如使用`===`运算符），PHP 会验证两个变量是否持有相同的实例，在所有三种情况下返回`'different'`字符串。

然而，这与引用透明的概念是不兼容的，我们将在本章后面讨论。

## 结束语

正如我们在前面的例子中所尝试展示的，尝试确定一个函数是否是纯函数可能在开始时会有些棘手。但是当你开始对此有所感觉时，你会变得更快更舒适。

检查函数是否是纯函数的最佳方法是验证以下内容：

+   使用全局关键字是一个明显的暴露

+   检查是否使用了任何不是函数本身参数的值

+   验证你的函数调用的所有函数也都是纯函数

+   任何对外部存储的访问都是不纯的（数据库和文件）

+   特别注意那些返回值依赖于外部状态（`time`，`random`）的函数

现在你知道如何发现那些不纯的函数了，你可能想知道如何使它们成为纯函数。遗憾的是，对于这个请求并没有简单的答案。接下来的章节将尝试提供避免不纯性的配方和模式。

# 不可变性

我们说一个变量是不可变的，如果它一旦被赋值，就不能改变其内容。在函数纯度之后，这是函数式编程中第二重要的事情。

在一些学术语言中，比如**Haskell**，你根本无法声明变量。一切都必须是函数。由于所有这些函数也都是纯函数，这意味着你可以免费获得不可变性。其中一些语言提供了一些类似变量声明的语法糖，以避免总是声明函数可能带来的繁琐。

大多数函数式语言只允许声明不可变变量或具有相同目的的构造。这意味着你有一种存储数值的方式，但是在初始赋值后无法更改数值。也有一些语言让你为每个变量选择你想要的方式。例如，在 Scala 中，你可以使用`var`关键字声明传统的可变变量，使用`val`关键字声明不可变变量。

然而，大多数语言，比如 PHP，对变量没有不可变性的概念。

## 为什么不可变性很重要？

首先，它有助于减少认知负担。在算法中记住所有涉及的变量已经相当困难了。没有不可变性，你还需要记住所有值的变化。对于人类大脑来说，将一个值与特定标签（即变量名）关联起来要容易得多。如果你能确信数值不会改变，推理发生的事情就会容易得多。

另外，如果你有一些全局状态是无法摆脱的，只要它是不可变的，你可以在你附近的一张纸上记录数值并保留以供参考。无论执行过程中发生了什么，所写的内容始终是程序的当前状态，这意味着你不必启动调试器或回显变量来确保数值没有改变。

想象一下，你将一个对象传递给一个函数。你不知道这个函数是否是纯函数，也就是说对象的属性可能会被改变。这会让你感到担忧，分散你的思绪。你必须问自己内部状态是否改变，这降低了你推理代码的能力。如果你的对象是不可变的，你可以百分之百地确信它和以前一样，加快你对发生的事情的理解。

你还可以获得与线程安全和并行化相关的优势。如果你的所有状态都是不可变的，那么确保你的程序能够在多个核心或多台计算机上同时运行就会更容易得多。大多数并发问题发生在某个线程在没有正确与其他线程同步的情况下修改了一个值。这导致它们之间的不一致，通常会导致计算错误。如果你的变量是不可变的，只要所有线程都收到了相同的数据，这种情况发生的可能性就会小得多。然而，由于 PHP 主要用于非线程场景，这并不是真正有用的。

## 数据共享

不可变性的另一个好处是，当语言本身强制执行时，编译器可以执行一种称为**数据共享**的优化。由于 PHP 目前还不支持这一点，我只会简单介绍一下。

数据共享是共享一个公共内存位置，用于包含相同数据的多个变量。这允许更小的内存占用，并且几乎没有成本地将数据从一个变量复制到另一个变量。

例如，想象一下以下代码片段：

```php
<?php 

//let's assume we have some big array of data 
$array= ['one', 'two', 'three', '...']; 

$filtered = array_filter($array, function($i) { /* [...] */ }); 
$beginning = array_slice($array, 0, 10); 
$final = array_map(function($i) { /* [...] */ }, $array); 
```

在 PHP 中，每个新变量都将是数据的一个新副本。这意味着我们有一个内存和时间成本，当我们的数组越大时，这可能会成为一个问题。

使用巧妙的技术，函数式语言可能只在内存中存储一次数据，然后使用另一种方式描述每个变量包含的数据部分。这仍然需要一些计算，但对于大型结构，你将节省大量内存和时间。

这样的优化也可以在非不可变语言中实现。但通常不这样做，因为你必须跟踪每个变量的每次写访问，以确保数据的一致性。编译器的隐含复杂性被认为超过了这种方法的好处。

然而，在 PHP 中，时间和内存开销并不足以避免使用不可变性。PHP 有一个相当不错的垃圾收集器，这意味着当对象不再使用时，内存会被清理得相当有效。而且我们通常使用相对较小的数据结构，这意味着几乎相同数据的创建速度相当快。

## 使用常量

你可以使用常量和类常量来实现某种不可变性，但它们只适用于标量值。目前，你无法将它们用于对象或更复杂的数据结构。由于这是唯一可用的选项，让我们还是来看一下吧。

你可以声明包含任何标量值的全局可用常量。从 PHP 5.6 开始，当使用`const`关键字时，你还可以在常量中存储标量值的数组，并且自 PHP 7 开始，使用定义语法也可以。

常量名称必须以字母或下划线开头，不能以数字开头。通常，常量都是大写的，这样它们就很容易被发现。以下划线开头也是不鼓励的，因为它可能与 PHP 核心定义的任何常量发生冲突：

```php
<?php 

define('FOO', 'something'); 
const BAR=42; 

//this only works since PHP 5.6 
const BAZ = ['one', 'two', 'three']; 

// the 'define' syntax for array work since PHP 7 
define('BAZ7', ['one', 'two', 'three']); 

// names starting and ending with underscores are discouraged 
define('__FOO__', 'possible clash'); 
```

你可以使用函数的结果来填充常量。但这只在使用定义的语法时才可能。如果你使用`const`关键字，你必须直接使用标量值：

```php
<?php 

define('UPPERCASE', strtoupper('Hello World !')); 
```

如果你尝试访问一个不存在的常量，PHP 将假定你实际上是在尝试将该值用作字符串：

```php
<?php 

echo UPPERCASE; 
//display 'HELLO WORLD !' echo I_DONT_EXISTS; 
//PHPNotice:  Use of undefined constant 

I_DONT_EXISTS
//- assumed'I_DONT_EXISTS' 
//display 'I_DONT_EXISTS'anyway 
```

这可能会非常误导，因为假定的字符串将计算为`true`，如果你期望你的常量保存一个`false`值，这可能会破坏你的代码。

如果你想避免这种陷阱，你可以使用 defined 或 constant 函数。遗憾的是，这将增加很多冗余性：

```php
<?php 

echo constant('UPPERCASE'); 
// display 'HELLO WORLD !' echo defined('UPPERCASE') ? 'true' : 'false'; 
// display 'true' 

echo constant('I_DONT_EXISTS'); 
// PHP Warning:  constant(): Couldn't find constant I_DONT_EXISTS 
// display nothings as 'constant' returns 'null' in this case 

echo defined('I_DONT_EXISTS') ? 'true' : 'false'; 
// display 'false' 
```

PHP 还允许在类内部声明常量：

```php
<?php 

class A 
{ 
    const FOO='some value'; 

    public static function bar() 
    { 
        echo self::FOO; 
    } 
} 

echo A::FOO; 
// display 'some value' 

echo constant('A::FOO'); 
// display 'some value' 

echo defined('A::FOO') ? 'true' : 'false'; 
// display 'true' 

A::bar(); 
// display 'some value' 
```

遗憾的是，当这样做时，你只能直接使用标量值；无法使用函数的返回值，就像`define`关键字一样：

```php
<?php 

class A 
{ 
    const FOO=uppercase('Hello World !'); 
} 

// This will generate an error when parsing the file : 
// PHP Fatal error:  Constant expression contains invalid operations 
```

然而，从 PHP 5.6 开始，你可以使用任何标量表达式或先前声明的常量与`const`关键字一起使用：

```php
<?php 

const FOO=6; 

class B 
{ 
    const BAR=FOO*7; 
    const BAZ="The answer is ": self::BAR; 
} 
```

除了它们的不可变性之外，常量和变量之间还有另一个基本区别。通常的作用域规则不适用。只要常量被声明，你就可以在代码中的任何地方使用它：

```php
<?php 

const FOO='foo'; 
$bar='bar'; 

function test() 
{ 
    // here FOO is accessible 
    echo FOO; 

    // however, if you want to access $bar, you have to use 
    // the 'global' keyword. global $bar; 
    echo $bar; 
}
```

在撰写本文时，PHP 7.1 仍处于测试阶段。发布计划于 2016 年秋末。这个新版本将引入类常量可见性修饰符：

```php
<?php 

class A 
{ 
    public const FOO='public const'; 
    protected const BAR='protected const'; 
    private const BAZ='private const'; 
} 

// public constants are accessible as always 
echo A::FOO; 

// this will however generate an error 
echo A::BAZ; 
// PHP Fatal error: Uncaught Error: Cannot access private const A::BAR 
```

最后警告一句。尽管它们是不可变的，但常量是全局的，这使它们成为你的应用程序的状态。任何使用常量的函数实际上都是不纯的，因此你应该谨慎使用它们。

## RFC 正在进行中。

正如我们刚才看到的，常量在不可变性方面充其量只是一个木腿。它们非常适合存储诸如我们希望每页显示的项目数量之类的简单信息。但是一旦您想要有一些复杂的数据结构，您将会陷入困境。

幸运的是，PHP 核心团队的成员们都很清楚不可变性的重要性，目前正在进行一项 RFC 的工作，以在语言级别包含它（[`wiki.php.net/rfc/immutability`](https://wiki.php.net/rfc/immutability)）。

对于不了解新 PHP 功能涉及的流程的人来说，**请求评论**（**RFC**）是核心团队成员提出向 PHP 添加新内容的建议。该建议首先经过草案阶段，在此阶段编写并进行了一些示例实现。之后，进行讨论阶段，其他人可以提供建议和建议。最后，进行投票决定是否将该功能包含在下一个 PHP 版本中。

在撰写本文时，*不可变类和属性* RFC 仍处于草案阶段。对此既没有真正的赞成意见，也没有反对意见。只有时间会告诉我们它是否被接受。

## 值对象

来自[`en.wikipedia.org/wiki/Value_object`](https://en.wikipedia.org/wiki/Value_object)：

> *在计算机科学中，值对象是表示简单实体的小对象，其相等性不是基于标识的：即两个值对象在具有相同值时是相等的，不一定是相同的对象。*
> 
> *[...]*
> 
> *值对象应该是不可变的：这是两个相等的值对象的隐式契约所要求的，应该保持相等。值对象不可变也是有用的，因为客户端代码不能在实例化后将值对象置于无效状态或引入错误行为。*

由于在 PHP 中无法获得真正的不可变性，通常通过在类上具有私有属性和没有 setter 来实现。因此，当开发人员想要修改值时，强制他们创建一个新对象。该类还可以提供实用方法来简化新对象的创建。让我们看一个简短的例子：

```php
<?php 

class Message 
{ 
    private $message; 
    private $status; 

    public function __construct(string $message, string $status) 
    { 
        $this->status = $status; 
        $this->message = $message; 
    } 

    public function getMessage() 
    { 
        return $this->message; 
    } 

    public function getStatus() 
    { 
        return $this->status; 
    } 

    public function equals($m) 
    { 
        return $m->status === $this->status && 
               $m->message === $this->message; 
    } 

    public function withStatus($status): Message 
    { 
        $new = clone $this; 
        $new->status = $status; 
        return $new; 
    } 
} 
```

这种模式可以用于创建从数据使用者的角度来看是不可变的数据实体。但是，您必须特别小心，以确保类上的所有方法都不会破坏不可变性；否则，您所有的努力都将是徒劳的。

除了不可变性之外，使用值对象还有其他好处。您可以在对象内部添加一些业务或领域逻辑，从而将所有相关内容保持在同一位置。此外，如果您使用它们而不是数组，您可以：

+   将它们用作类型提示，而不仅仅是数组

+   避免由于拼写错误的数组键而导致任何可能的错误

+   强制存在或格式化某些项目

+   提供格式化值以适应不同上下文的方法

值对象的常见用途是存储和操作与货币相关的数据。您可以查看[`money.rtfd.org`](http://money.rtfd.org)，这是一个很好的如何有效使用它们的示例。

另一个对于真正重要的代码片段使用值对象的例子是**PSR-7: "HTTP 消息接口"**。这个标准引入并规范了一种框架和应用程序以可互操作的方式管理 HTTP 请求和响应的方法。所有主要的框架都有核心支持或可用的插件。我邀请您阅读他们为什么应该在 PHP 生态系统的如此重要的部分使用不可变性的完整理由：[`www.php-fig.org/psr/psr-7/meta/#why-value-objects`](http://www.php-fig.org/psr/psr-7/meta/#why-value-objects)。

从本质上讲，将 HTTP 消息建模为值对象可以确保消息状态的完整性，并且可以避免双向依赖的需要，这往往会导致不同步或导致调试或性能问题。

总的来说，值对象是在 PHP 中获得某种不可变性的好方法。您不会获得所有的好处，特别是与性能相关的好处，但大部分认知负担都被移除了。进一步探讨这个话题超出了本书的范围；如果您想了解更多，可以访问专门的网站：[`www.phpvalueobjects.info/`](http://www.phpvalueobjects.info/)。

## 不可变集合的库

如果您想进一步走向不可变性之路，至少有两个库提供不可变集合：**Laravel 集合**和**immutable.php**。

这两个库都协调了与数组相关的 PHP 函数的参数顺序的差异，比如`array_map`和`array_filter`。它们还提供了与大多数 PHP 函数相反的工作任何类型的`Iterable`或`Traversable`的可能性；这些函数通常需要一个真正的数组。

本章将只是快速介绍这些库。示例用法将在第三章中给出，*PHP 中的功能基础*，以便它们可以与允许执行相同任务的其他库一起显示。此外，我们还没有详细介绍诸如映射或折叠等技术，因此示例可能不够清晰。

### Laravel 集合

Laravel 框架包含一个名为`Collection`的类，用于取代 PHP 数组。这个类在内部使用一个简单的数组，但可以使用 collect 辅助函数从任何集合类型的变量创建。然后，它提供了许多非常有用的方法来处理数据，主要以一种功能性的方式。这也是 Laravel 的一个核心部分，因为**Eloquent**，ORM，将数据库实体作为`Collection`实例返回。

如果您不使用 Laravel，但仍希望从这个优秀的库中受益，您可以使用[`github.com/tightenco/collect`](https://github.com/tightenco/collect)，这只是从 Laravel 支持包的其余部分中分离出来的 Collection 部分，以保持小巧。您也可以参考 Laravel 集合的官方文档([`laravel.com/docs/5.3/collections`](https://laravel.com/docs/5.3/collections))。

### Immutable.php

这个库定义了`ImmArray`类，它实现了一个类似数组的不可变集合。

`ImmArray`类是`SplFixedArray`类的包装器，用于修复其 API 的一些缺陷，提供了通常希望在集合上执行的性能操作的方法。在幕后使用`SplFixedArray`类的优势在于其实现是用 C 编写的，性能非常高且内存效率高。您可以参考 GitHub 存储库以获取有关 Immutable.php 的更多信息：[`github.com/jkoudys/immutable.php`](https://github.com/jkoudys/immutable.php)。

# 引用透明度

如果您的代码库中的所有表达式都可以在任何时候用其输出替换而不改变程序的行为，则该表达式被称为引用透明。为了做到这一点，您的所有函数都必须是纯函数，所有变量都必须是不可变的。

我们从引用透明性中获得了什么？再一次，它有助于减少认知负担。让我们想象一下我们有以下函数和数据：

```php
<?php 

// The Player implementation is voluntarily simple for brevity. // Obviously you would use immutable.php in a real project. class Player 
{ 
    public $hp; 
    public $x; 
    public $y; 

    public function __construct(int $x, int $y, int $hp) { 
        $this->x = $x; 
        $this->y = $y; 
        $this->hp = $hp; 
    } 
} 

function isCloseEnough(Player $one, Player $two): boolean 
{ 
    return abs($one->x - $two->x) < 2 && 
           abs($one->y - $two->y) < 2; 
} 

function loseHitpoint(Player $p): Player 
{ 
    return new Player($p->x, $p->y, $p->hp - 1); 
} 

function hit(Player $p, Player $target): Player 
{ 
    return isCloseEnough($p, $target) ? loseHitpoint($target) : 
        $target; 
} 
```

现在让我们模拟两个人之间的一场非常简单的争吵：

```php
<?php 

$john=newPlayer(8, 8, 10); 
$ted =newPlayer(7, 9, 10); 

$ted=hit($john, $ted); 
```

上面定义的所有函数都是纯函数，由于我们没有可变的数据结构，它们也是引用透明的。现在，为了更好地理解我们的代码片段，我们可以使用一种称为**等式推理**的技术。这个想法非常简单，你只需要用*等于替换等于*来推理代码。在某种程度上，这就像手动评估代码。

让我们首先将我们的`isCloseEnough`函数内联。这样做，我们的 hit 函数可以被转换为如下形式：

```php
<?php 

return abs($p->x - $target->x) < 2 && abs($p->y - $target->y) < 2 ? loseHitpoint($target) : 
    $target; 
```

我们的数据是不可变的，现在我们可以简单地使用以下值：

```php
<?php 

return abs(8 - 7) < 2 && abs(8 - 8) < 2 ? loseHitpoint($target) : 
    $target; 
```

让我们做一些数学：

```php
<?php 

return 1<2 && 0<2 ? loseHitpoint($target) : 
    $target; 
```

条件显然评估为 true，所以我们只保留右分支：

```php
<?php 

return loseHitpoint($target); 
```

让我们继续进行剩余的函数调用：

```php
<?php 

return newPlayer($target->x, $target->y, $target->hp-1); 
```

再次替换值：

```php
<?php 

return newPlayer(8, 7, 10-1); 
```

最后，我们的初始函数调用变成了：

```php
<?php 

$ted = newPlayer(8, 7, 9); 
```

通过使用可以用其结果值替换引用透明表达式的事实，我们能够将一个相对冗长的代码片段减少到一个简单的对象创建。

这种能力应用于重构或理解代码非常有用。如果你在理解一些代码时遇到困难，并且你知道其中的一部分是纯的，你可以在尝试理解它时简单地用结果替换它。这可能会帮助你找到问题的核心。

## 非严格性或惰性评估

引用透明性的一个巨大好处是编译器或解析器可以惰性地评估值的可能性。例如，Haskell 允许你通过数学函数定义无限列表。语言的惰性特性确保列表的值只在需要值时才计算。

在术语表中，我们将非严格语言定义为评估发生惰性的语言。事实上，惰性和非严格性之间有一些细微差别。如果你对细节感兴趣，你可以访问[`wiki.haskell.org/Lazy_vs._non-strict`](https://wiki.haskell.org/Lazy_vs._non-strict)并阅读相关内容。在本书的目的上，我们将这些术语互换使用。

你可能会问自己这有什么用。让我们简单地看一下用例。

### 性能

通过使用惰性评估，你确保只有需要的值才会被有效计算。让我们看一个简短而天真的例子来说明这个好处：

```php
<?php 

function wait(int $value): int 
{ 
    // let's imagine this is a function taking a while 
    // to compute a value 
    sleep(10); 
    return $value; 
} 

function do_something(bool $a, int $b, int $c): int 
{ 
    if($a) { 
        return $b; 
    } else { 
        return $c; 
    } 
} 

do_something(true, sleep(10), sleep(8)); 
```

由于 PHP 在函数参数上不执行惰性评估，当调用`do_something`时，你首先必须等待两次 10 秒，然后才能开始执行函数。如果 PHP 是一种非严格语言，只有我们需要的值才会被计算，从而将所需的时间减少了一半。情况甚至更好，因为返回值甚至没有保存在一个新变量中，可能根本不需要执行函数。

PHP 有一种情况下执行一种惰性评估：布尔运算符短路。当你有一系列布尔操作时，只要 PHP 能够确定结果，它就会停止执行：

```php
<?php 

// 'wait' will never get called as those operators are short- circuited 

$a= (false && sleep(10));   
$b = (true  || sleep(10)); 
$c = (false and sleep(10)); 
$d = (true  or  sleep(10)); 
```

我们可以重写我们之前的例子以利用这一点。但正如你在下面的例子中看到的，这是以可读性为代价的。此外，我们的例子真的很简单，不是你在现实生活应用代码中会遇到的东西。想象一下为具有多个可能分支的复杂函数做同样的事情？这在下面的片段中显示：

```php
<?php 

($a && sleep(10)) || sleep(8); 
```

前面的代码还有两个更大的问题：

+   如果由于任何原因，第一次调用 sleep 返回 false 值，第二次调用也将被执行

+   你的方法的返回值将自动转换为布尔值

### 代码可读性

当你的变量和函数评估是惰性的时，你可以花更少的时间考虑声明的最佳顺序，甚至你计算的数据是否会被使用。相反，你可以专注于编写可读的代码。想象一个博客应用程序有很多帖子、标签、类别，并按年份存档。你是想为每个页面编写自定义查询，还是使用惰性评估，如下所示：

```php
<?php 

// let's imagine $blogs is a lazily evaluated collection 
// containing all the blog posts of your application order by date 
$posts = [ /* ... */ ]; 

// last 10 posts for the homepage 
return $posts->reverse()->take(10); 

// posts with tag 'functional php' 
return $posts->filter(function($b) { 
    return $b->tags->contains('functional-php'); 
})->all(); 

// title of the first post from 2014 in the category 'life' 
return $posts->filter(function($b) { 
    return $b->year == 2014; 
})->filter(function($b) { 
    return $b->category == 'life'; 
})->pluck('title')->first(); 
```

清楚地说，如果我们将所有帖子加载到`$posts`中，这段代码可能会工作得很好，但性能会非常糟糕。然而，如果我们有惰性评估和足够强大的 ORM，数据库查询可以延迟到最后一刻。那时，我们将确切地知道我们需要的数据，SQL 将自动为这个确切的页面定制，使我们拥有易于阅读的代码和出色的性能。

据我所知，这个想法纯粹是假设的。我目前并不知道有任何 ORM 足够强大，即使在最功能强大的语言中，也无法达到这种程度的懒惰。但如果可以的话，那不是很好吗？

如果你对示例中使用的语法感到困惑，那是受到了我们之前讨论的 Laravel 的 Collection 的 API 的启发。

### 无限列表或流

惰性求值允许你创建无限列表。在 Haskell 中，要获取所有正整数的列表，你可以简单地使用`[1..]`。然后，如果你想要前十个数字，你可以取`10 [1..]`。我承认这个例子并不是很令人兴奋，但更复杂的例子更难理解。

PHP 自版本 5.5 起支持生成器。你可以通过使用它们来实现类似无限列表的东西。例如，我们所有正整数的列表如下：

```php
<?php 

function integers() 
{ 
    $i=0; 
    while(true) yield $i++; 
} 
```

然而，懒惰无限列表和我们的生成器之间至少有一个显著的区别。你可以对 Haskell 版本执行任何你通常对集合执行的操作-例如计算其长度和对其进行排序。而我们的生成器是一个`Iterator`，如果你尝试在其上使用`iterator_to_array`，你的 PHP 进程很可能会一直挂起，直到内存耗尽。

你问我如何计算无限列表的长度或对其进行排序？实际上很简单；Haskell 只会计算列表值，直到它有足够的值来执行计算。比如我们在 PHP 中有条件`count($list) < 10`，即使你有一个无限列表，Haskell 会在达到 10 时停止计数，因为它在那时就会有一个比较的答案。

## 代码优化

看一下下面的代码，然后尝试决定哪个更快：

```php
<?php 

$array= [1, 2, 3, 4, 5, 6 /* ... */]; 

// version 1 
for($i = 0; $i < count($array); ++$i) { 
    // do something with the array values 
} 

// version 2 
$length = count($array); 
for($i = 0; $i < $length; ++$i) { 
    // do something with the array values 
} 
```

版本 2 应该快得多。因为你只计算数组的长度一次，而在版本 1 中，PHP 必须在每次验证 for 循环的条件时计算长度。这个例子很简单，但有些情况下这样的模式更难发现。如果你有引用透明性，这并不重要。编译器可以自行执行这种优化。任何引用透明的计算都可以在不改变程序结果的情况下移动。这是可能的，因为我们保证每个函数的执行不依赖于全局状态。因此，移动计算以实现更好的性能是可能的，而不改变结果。

另一个可能的改进是执行常见子表达式消除或 CSE。编译器不仅可以更自由地移动代码的一部分，还可以将一些共享公共计算的操作转换为使用中间值。想象一下以下代码：

```php
<?php 

$a= $foo * $bar + $u; 
$b = $foo * $bar * $v; 
```

如果计算`$foo * $bar`的成本很高，编译器可以决定通过使用中间值来转换它：

```php
<?php 

$tmp= $foo * $bar; 
$a = $tmp + $u; 
$b = $tmp * $v; 
```

再次强调，这只是一个很简单的例子。这种优化可以在整个代码库的范围内进行。

## 记忆化

记忆化是一种技术，它可以缓存给定参数集的函数的结果，这样你就不必在下一次调用时再次执行它。我们将在第八章*性能效率*中详细讨论这个问题。现在，让我只说一下，如果你的语言只具有引用透明表达式，它可以在需要时自动执行记忆化。

这意味着它可以根据调用的频率和其他各种参数来决定是否值得自动记忆函数，而无需开发人员的干预或提示。

# PHP 中的一切？

如果 PHP 开发人员只能从其中的一小部分优势中受益，那么为什么要费心纯函数、不可变性，最终是引用透明呢？

首先，就像不可变性的 RFC 一样，事情正在朝着正确的方向发展。这意味着，最终，PHP 引擎将开始纳入一些先进的编译器技术。当这发生时，如果你的代码库已经使用了这些函数式技术，你将获得巨大的性能提升。

其次，在我看来，所有这些的主要好处是减少认知负担。当然，要适应这种新的编程风格需要一些时间。但一旦你练习了一下，你很快就会发现你的代码更容易阅读和理解。其结果是你的应用程序将包含更少的错误。

最后，如果你愿意使用一些外部库，或者如果你能够应对语法并不总是很完善的情况，你现在就可以从其他改进中受益了。显然，我们无法改变 PHP 的核心以添加我们之前谈到的编译器优化，但在接下来的章节中，我们将看到一些引用透明性的好处是如何被模拟的。

# 总结

这一章包含了很多理论。希望你不会介意太多。这是必要的，以奠定我们共同词汇的基础，并解释为什么这些概念很重要。你现在很清楚纯度和不可变性是什么，也学会了一些识别不纯函数的技巧。我们还讨论了这两个属性如何导致了所谓的引用透明性以及好处是什么。

我们也了解到，遗憾的是，PHP 并不原生支持大部分的好处。然而，关键的收获是使用函数式方法减少了理解代码的认知负担，从而使其更容易阅读。最终的好处是现在你的代码将更容易维护和重构，你可以快速找到并修复错误。通常，纯函数也更容易测试，这也会导致更少的错误。

现在我们已经很好地讨论了理论基础，接下来的章节将专注于帮助我们在软件中实现纯度和不可变性的技术。


# 第三章：PHP 中的功能基础

在第一章中介绍了 PHP 中的函数，接着是第二章中的函数式编程的理论方面，我们最终将开始编写真正的代码。我们将从 PHP 中可用的函数开始，这些函数允许我们编写功能性代码。一旦基本技术得到很好的理解，我们将转向各种库，这些库将在整本书中帮助我们。

在本章中，我们将涵盖以下主题：

+   映射、折叠、减少和压缩

+   递归

+   为什么异常会破坏引用透明度

+   使用 Maybe 和 Either 类型更好地处理错误的方法

+   PHP 中可用的功能性库

# 一般建议

在前几章中，我们描述了功能应用程序必须具有的重要属性。然而，我们从未真正讨论过如何实现它。除了我们将在以后学习的各种技术之外，还有一些简单的建议可以立即帮助您。

## 使所有输入明确

我们在上一章中大量讨论了纯度和隐藏输入，或者副作用。现在，应该很清楚，函数的所有依赖关系都应该作为参数传递。然而，这个建议还要进一步。

避免将对象或复杂数据结构传递给您的函数。尽量限制输入到必要的内容。这样做将使您的函数范围更容易理解，并且将有助于确定函数的操作方式。它还具有以下好处：

+   调用将更容易

+   测试它将需要较少的数据存根

## 避免临时变量

正如您可能已经了解的那样，状态是邪恶的，特别是全局状态。然而，局部变量是一种局部状态。一旦您开始在代码中频繁使用它们，您就慢慢地打开了潘多拉的魔盒。这在 PHP 这样的语言中尤其如此，因为所有变量都是可变的。如果值在途中发生变化会发生什么？

每次声明一个变量，你都必须记住它的值，才能理解代码的其余部分是如何工作的。这大大增加了认知负担。此外，由于 PHP 是动态类型的，一个变量可以被完全不同的数据重复使用。

使用临时变量时，总会存在某种方式修改或重复使用的风险，导致难以调试的错误。

在几乎所有情况下，使用函数比使用临时变量更好。函数允许获得相同的好处：

+   通过命名中间结果来提高可读性

+   避免重复自己

+   缓存冗长操作的结果（这需要使用备忘录，我们将在第八章中讨论，*性能效率*）

调用函数的额外成本通常是微不足道的，不会打破平衡。此外，使用函数而不是临时变量意味着您可以在其他地方重用这些函数。它们还可以使未来的重构更容易，并且可以改善关注点的分离。

正如最佳实践所期望的那样，有时使用临时变量会更容易一些。例如，如果您需要在一个短函数中存储一个返回值，以便在之后立即使用，以便保持行长度舒适，请毫不犹豫地这样做。唯一严格禁止的是使用相同的临时变量来存储各种不同的信息。

## 更小的函数

我们已经提到函数就像积木一样。通常，您希望您的积木多才多艺且坚固。如果您编写只专注于做一件事情的小函数，那么这两个属性都会得到更好的强化。

如果您的函数做得太多，很难重用。我们将在下一章中讨论如何组合函数，以及如何利用所有小型实用函数来创建具有更大影响力的新函数。

此外，阅读较小的代码片段并对其进行推理更容易。相关的影响更容易理解，通常情况下边界情况更少，使函数更容易测试。

## 参数顺序很重要

选择函数参数的顺序似乎并不重要，但实际上它很重要。高阶函数是函数式编程的核心特性；这意味着你将会传递很多函数。

这些函数可以是匿名的，这种情况下，出于可读性的考虑，你可能希望避免将函数声明作为中间参数。在 PHP 中，可选参数也受到签名末尾的限制。正如我们将看到的，一些函数构造可以接受具有默认值的函数。

我们还将在第四章*组合函数*中进一步讨论这个话题。当你将多个函数链接在一起时，每个函数的第一个参数是前一个函数的返回值。这意味着在选择哪些参数先传递时，你需要特别小心。

# 映射函数

在 PHP 中，map 或`array_map`方法是一个高阶函数，它将给定的回调应用于集合的所有元素。`return`值是按顺序排列的集合。一个简单的例子是：

```php
<?php 

function square(int $x): int 
{ 
    return $x * $x; 
} 
$squared = array_map('square', [1, 2, 3, 4]); 
// $squared contains [1, 4, 9, 16] 
```

我们创建一个计算给定整数的平方的函数，然后使用`array_map`函数来计算给定数组的所有平方值。`array_map`函数的第一个参数可以是任何形式的 callable，第二个参数必须是一个*真实的数组*。你不能传递一个迭代器或一个 Traversable 的实例。

你也可以传递多个数组。你的回调将从每个数组中接收一个值：

```php
<?php 

$numbers = [1, 2, 3, 4]; 
$english = ['one', 'two', 'three', 'four']; 
$french = ['un', 'deux', 'trois', 'quatre']; 

function translate(int $n, string $e, string $f): string 
{ 
    return "$n is $e, or $f in French."; 
} 
print_r(array_map('translate', $numbers, $english, $french)); 
```

这段代码将显示：

```php
Array 
( 
    [0] => 1 is one, or un in French. [1] => 2 is two, or deux in French. [2] => 3 is three, or trois in French. [3] => 4 is four, or quatre in French. ) 
```

最长的数组将决定结果的长度。较短的数组将用 null 值扩展，以使它们的长度相匹配。

如果你将 null 作为函数传递，PHP 将合并这些数组：

```php
<?php 

print_r(array_map(null, [1, 2], ['one', 'two'], ['un', 'deux'])); 
```

结果是：

```php
Array 
( 
    [0] => Array 
        ( 
            [0] => 1 
            [1] => one 
            [2] => un 
        ) 
    [1] => Array 
        ( 
            [0] => 2 
            [1] => two 
            [2] => deux 
        ) 
) 
```

如果你只传递一个数组，键将被保留；但如果你传递多个数组，它们将丢失：

```php
<?php 
  function add(int $a, int $b = 10): int 
  { 
      return $a + $b; 
  } 

  print_r(array_map('add', ['one' => 1, 'two' => 2])); 
  print_r(array_map('add', [1, 2], [20, 30])); 
```

结果是：

```php
Array 
( 
    [one] => 11 
    [two] => 12 
) 
Array 
( 
    [0] => 21 
    [1] => 32 
) 
```

最后要注意的是，很遗憾，无法轻松访问每个项目的键。然而，你的回调可以是一个闭包，因此你可以使用来自你上下文的任何变量。利用这一点，你可以在数组的键上进行映射，并使用闭包来检索值：

```php
$data = ['one' => 1, 'two' => 2];

array_map(function to_string($key) use($data) {
    return (str) $data[$key];
}, 
array_keys($data);
```

# 过滤函数

在 PHP 中，filter 或`array_filter`方法是一个高阶函数，它基于布尔谓词仅保留集合的某些元素。`return`值是仅包含谓词函数返回 true 的元素的集合。一个简单的例子是：

```php
<?php

function odd(int $a): bool
{
    return $a % 2 === 1;
}

$filtered = array_filter([1, 2, 3, 4, 5, 6], 'odd');
/* $filtered contains [1, 3, 5] */
```

我们首先创建一个接受值并返回布尔值的函数。这个函数将是我们的谓词。在我们的例子中，我们检查一个整数是否是奇数。与`array_map`方法一样，谓词可以是任何`callable`，集合必须是一个数组。然而，请注意参数顺序是相反的；集合首先出现。

回调是可选的；如果你不提供一个，PHP 将过滤掉所有会被评估为 false 的元素，比如空字符串和数组：

```php
<?php

$filtered = array_filter(["one", "two", "", "three", ""]); 
/* $filtered contains ["one", "two", "three"] */

$filtered = array_filter([0, 1, null, 2, [], 3, 0.0]); 
/* $filtered contains [1, 2, 3] */
```

你也可以传递第三个参数，作为一个标志，确定你想要接收键还是值，或者两者都要：

```php
<?php

$data = [];
function key_only($key) { 
    // [...] 
}

$filtered = array_filter($data, 'key_only', ARRAY_FILTER_USE_KEY);

function both($value, $key) { 
    // [...] 
}

$filtered = array_filter($data, 'both', ARRAY_FILTER_USE_BOTH);
```

# 折叠或减少函数

折叠是指使用组合函数将集合减少为返回值的过程。根据语言的不同，这个操作可能有多个名称，如 fold、reduce、accumulate、aggregate 或 compress。与与数组相关的其他函数一样，在 PHP 中的版本是`array_reduce`函数。

你可能熟悉`array_sum`函数，它计算数组中所有值的总和。实际上，这是一种折叠操作，可以很容易地使用`array_reduce`函数来实现：

```php
<?php

function sum(int $carry, int $i): int
{
    return $carry + $i;
}

$summed = array_reduce([1, 2, 3, 4], 'sum', 0);
/* $summed contains 10 */
```

像`array_filter`方法一样，首先是集合；然后传递一个回调，最后是一个可选的初始值。在我们的情况下，我们被迫传递初始值 0，因为默认的 null 对于我们的 int 类型函数签名是无效的类型。

回调函数有两个参数。第一个是基于所有先前项目的当前减少值，有时称为**carry**或**accumulator**。第二个是当前正在处理的数组元素。在第一次迭代中，carry 等于初始值。

您不一定需要使用元素本身来生成值。例如，您可以使用 fold 实现`in_array`的简单替代：

```php
<?php

function in_array2(string $needle, array $haystack): bool
{
    $search = function(bool $contains, string $item) use ($needle):bool 
    {
        return $needle == $item ? true : $contains;
    };
    return array_reduce($haystack, $search, false);
}

var_dump(in_array2('two', ['one', 'two', 'three']));
// bool(true)
```

reduce 操作从初始值 false 开始，因为我们假设数组不包含我们要找的项目。这也使我们能够很好地处理数组为空的情况。

对于每个项目，如果项目是我们正在搜索的项目，我们返回 true，这将是新的传递值。如果不匹配，我们只需返回累加器的当前值，它将是`true`（如果我们之前找到了项目）或`false`（如果我们没有找到）。

我们的实现可能比官方的慢一点，因为无论如何，我们都必须在返回结果之前遍历整个数组，而不能在遇到搜索项目时立即退出函数。

然而，我们可以实现一个 max 函数的替代方案，性能应该是相当的，因为任何实现都必须遍历所有值：

```php
<?php

function max2(array $data): int
{
    return array_reduce($data, function(int $max, int $i) : int 
    {
        return $i > $max ? $i : $max;
    }, 0);
}

echo max2([5, 10, 23, 1, 0]);
// 23
```

这个想法和之前一样，只是使用数字而不是布尔值。我们从初始值`0`开始，我们的当前最大值。如果我们遇到更大的值，我们返回它，以便传递。否则，我们继续返回我们当前的累加器，已经包含到目前为止遇到的最大值。

由于 max PHP 函数适用于数组和数字，我们可以重用它来进行减少。然而，这将带来没有意义，因为原始函数已经可以直接在数组上操作：

```php
<?php

function max3(array $data): int
{
    return array_reduce($data, 'max', 0);
}
```

只是为了明确起见，我不建议在生产中使用这些。语言中已经有更好的函数。这些只是为了教育目的，以展示折叠的各种可能性。

我完全理解，这些简短的示例可能不比`foreach`循环或其他更命令式的方法更好，来实现这两个函数。但是它们有一些优点：

+   如果您使用 PHP 7 标量类型提示，每个项目的类型都会被强制执行，使您的软件更加健壮。您可以通过将字符串放入用于`max2`方法的数组来验证这一点。

+   您可以对传递给`array_reduce`方法的函数进行单元测试，或者对`array_map`和`array_filter`函数进行测试，以确保其正确性。

+   如果您有这样的架构，您可以在多个线程或网络节点之间分发大数组的减少。这在`foreach`循环中将会更加困难。

+   正如`max3`函数所示，这种方法允许您重用现有方法，而不是编写自定义循环来操作数据。

## 使用 fold 的 map 和 filter 函数

目前，我们的`fold`只返回简单的标量值。但没有什么能阻止我们构建更复杂的数据结构。例如，我们可以使用`fold`来实现 map 和 filter 函数：

```php
<?php 

function map(array $data, callable $cb): array 
{ 
    return array_reduce($data, function(array $acc, $i) use ($cb) { 
        $acc[] = $cb($i); 
        return $acc; 
    }, []);     
} 

function filter(array $data, callable $predicate): array 
{ 
  return array_reduce($data, function(array $acc, $i)  use($predicate) { 
      if($predicate($i)) { 
          $acc[] = $i; 
      } 
      return $acc; 
  }, []); 
} 
```

再次强调，这些大部分是为了演示使用折叠返回数组是可能的。如果您不需要操作更复杂的集合，原生函数就足够了。

作为读者的练习，尝试实现`map_filter`或`filter_map`函数，如果您愿意，还可以尝试编写 head 和 tail 方法，它们分别返回数组的第一个和最后一个元素，并且通常在函数式语言中找到。

正如您所看到的，折叠是非常强大的，其背后的思想对许多函数式技术至关重要。这就是为什么我更喜欢谈论折叠而不是缩减，我觉得这有点简化，双关语。

在继续之前，请确保您了解折叠的工作原理，因为这将使其他所有事情都变得更容易。

## 左折叠和右折叠

函数式语言通常实现了两个版本的折叠，`foldl`和`foldr`。区别在于第一个从左边折叠，第二个从右边折叠。

例如，如果你有数组`[1, 2, 3, 4, 5]`，你想计算它的总和，你可以有`(((1 + 2) + 3) + 4) + 5`或`(((5 + 4) + 3) + 2) + 1`。如果有一个初始值，它将始终是计算中使用的第一个值。

如果您应用于值的操作是可交换的，左右两个变体都将产生相同的结果。可交换操作的概念来自数学，在第七章 *Functional Techniques and Topics*中有解释。

对于允许无限列表的语言，比如 Haskell，取决于列表是如何生成的，两种折叠中的一种可能能够计算一个值并停止。此外，如果语言实现了尾递归消除，一个正确的折叠起始点可能会避免堆栈溢出并允许操作完成。

由于 PHP 不执行无限列表或尾递归消除，我认为没有理由去区分。如果您感兴趣，`array_reduce`函数从左边折叠，实现一个从右边折叠的函数不应该太复杂。

## MapReduce 模型

你可能已经听说过**MapReduce**编程模型的名字。起初，它指的是 Google 开发的专有技术，但如今在各种语言中有多种实现。

尽管 MapReduce 背后的思想受到我们刚讨论的 map 和 reduce 函数的启发，但这个概念更广泛。它描述了使用并行和分布式算法在集群上处理大型数据集的整个模型。

本书中学到的每一种技术都可以帮助您实现 MapReduce 来分析数据。然而，这个话题超出了范围，所以如果您想了解更多，可以从维基百科页面开始访问[`en.wikipedia.org/wiki/MapReduce`](https://en.wikipedia.org/wiki/MapReduce)。

# 卷积或 zip

卷积，或更常见的 zip 是将所有给定数组的每个第 n 个元素组合在一起的过程。事实上，这正是我们之前通过向`array_map`函数传递 null 值所做的：

```php
<?php 

print_r(array_map(null, [1, 2], ['one', 'two'], ['un', 'deux'])); 
```

输出为：

```php
Array 
( 
    [0] => Array 
        ( 
            [0] => 1 
            [1] => one 
            [2] => un 
        ) 
    [1] => Array 
        ( 
            [0] => 2 
            [1] => two 
            [2] => deux 
        ) 
) 
```

重要的是要注意，如果数组的长度不同，PHP 将使用 null 作为填充值：

```php
<?php 

$numerals = [1, 2, 3, 4]; 
$english = ['one', 'two']; 
$french = ['un', 'deux', 'trois']; 

print_r(array_map(null, $numerals, $english, $french)); 
Array 
( 
    [0] => Array 
        ( 
            [0] => 1 
            [1] => one 
            [2] => un 
        ) 
    [1] => Array 
        ( 
            [0] => 2 
            [1] => two 
            [2] => deux 
        ) 
    [2] => Array 
        ( 
            [0] => 3 
            [1] => 
            [2] => trois 
        ) 
    [3] => Array 
        ( 
            [0] => 4 
            [1] => 
            [2] => 
        ) 
) 
```

请注意，在大多数编程语言中，包括 Haskell、Scala 和 Python，在 zip 操作中，将停止在最短的数组处，而不会填充任何值。您可以尝试在 PHP 中实现类似的功能，例如使用`array_slice`函数将所有数组减少到相同的大小，然后调用`array_merge`函数。

我们还可以通过从数组中创建多个数组来执行反向操作。这个过程有时被称为**unzip**。这里是一个天真的实现，缺少了很多检查，使其足够健壮用于生产：

```php
<?php 

function unzip(array $data): array 
{ 
    $return = []; 

    $data = array_values($data); 
    $size = count($data[0]); 

    foreach($data as $child) { 
        $child = array_values($child); 
        for($i = 0; $i < $size; ++$i) { 
            if(isset($child[$i]) && $child[$i] !== null) { 
                $return[$i][] = $child[$i]; 
            } 
        } 
    } 

    return $return; 
} 
```

你可以像这样使用它：

```php
$zipped = array_map(null, $numerals, $english, $french); 

list($numerals2, $english2, $french2) = unzip($zipped); 

var_dump($numerals == $numerals2); 
// bool(true) 
var_dump($english == $english2); 
// bool(true) 
var_dump($french == $french2); 
// bool(true) 
```

# 递归

在学术意义上，递归是将问题分解为相同问题的较小实例的想法。例如，如果您需要递归扫描一个目录，您首先扫描起始目录，然后扫描其子目录和子目录的子目录。大多数编程语言通过允许函数调用自身来支持递归。这个想法通常被描述为递归。

让我们看看如何使用递归扫描目录：

```php
<?php 

function searchDirectory($dir, $accumulator = []) { 
    foreach (scandir($dir) as $path) { 
        // Ignore hidden files, current directory and parent directory 
        if(strpos($path, '.') === 0) { 
            continue; 
        } 

        $fullPath = $dir.DIRECTORY_SEPARATOR.$path; 

        if(is_dir($fullPath)) { 
            $accumulator = searchDirectory($path, $accumulator); 
        } else { 
            $accumulator[] = $fullPath; 
        } 
    } 
    return $accumulator; 
} 
```

我们首先使用`scandir`函数获取所有文件和目录。然后，如果遇到子目录，我们再次调用该函数。否则，我们只需将文件添加到累加器中。这个函数是递归的，因为它调用自身。

您可以使用控制结构来编写这个函数，但是由于您无法预先知道文件夹层次结构的深度，代码可能会变得更加混乱和难以理解。

有些书籍和教程使用斐波那契数列，或计算阶乘作为递归示例，但公平地说，这些示例相当差，因为最好使用传统的`for`循环来实现第二个示例，并且对于第一个示例，提前计算项更好。

相反，让我们思考一个更有趣的挑战，*Hanoi Towers*。对于不了解这个游戏的人来说，传统版本的游戏包括三根杆，上面堆叠着不同大小的圆盘，最小的在顶部。在游戏开始时，所有圆盘都在最左边的杆上，目标是将它们移到最右边的杆上。游戏遵循以下规则：

+   一次只能移动一个圆盘

+   只能移动杆的顶部圆盘

+   不能将一个圆盘放在较小的圆盘上方

这个游戏的设置如下：

![递归](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/fn-php/img/image_03_001.jpg)

如果我们想解决这个游戏，较大的圆盘必须首先放在最后一个杆上。为了做到这一点，我们需要先将所有其他圆盘移到中间的杆上。沿着这种推理方式，我们可以得出我们必须实现的三个大步骤：

1.  将所有的圆盘移动到中间，除了最大的一个。

1.  将大圆盘移到右边。

1.  将所有圆盘移动到最大的圆盘上方。

*步骤 1*和*3*是初始问题的较小版本。这些步骤中的每一个又可以被缩小为更小的版本，直到我们只有一个圆盘需要移动-递归函数的完美情况。让我们尝试实现这一点。

为了避免在我们的函数中使用与杆和圆盘相关的变量，我们将假设计算机会向某人发出移动的命令。在我们的代码中，我们还将假设最大的圆盘是编号 1，较小的圆盘编号较大：

```php
<?php 

function hanoi(int $disc, string $source, string $destination,  string $via) 
{ 
    if ($disc === 1) { 
        echo("Move a disc from the $source rod to the $destination  rod\n"); 
    } else { 
        // step 1 : move all discs but the first to the "via" rod         hanoi($disc - 1, $source, $via, $destination); 
        // step 2 : move the last disc to the destination 
        hanoi(1, $source, $destination, $via); 
        // step 3 : move the discs from the "via" rod to the  destination 
        hanoi($disc - 1, $via, $destination, $source); 
    } 
} 
```

使用`hanoi(3, 'left', 'right', 'middle')`输入进行三个圆盘的移动，我们得到以下输出：

```php
Move a disc from the left rod to the right rod 
Move a disc from the left rod to the middle rod 
Move a disc from the right rod to the middle rod 
Move a disc from the left rod to the right rod 
Move a disc from the middle rod to the left rod 
Move a disc from the middle rod to the right rod 
Move a disc from the left rod to the right rod 
```

想要以递归的方式思考而不是使用更传统的循环需要一段时间，显然递归并不是解决您尝试解决的所有问题的银弹。

一些函数式语言根本没有循环结构，强制您使用递归。PHP 不是这种情况，所以让我们使用正确的工具来解决问题。如果您能将问题视为较小类似问题的组合，通常使用递归会很容易。例如，尝试找到*Towers of Hanoi*的迭代解决方案需要仔细思考。或者您可以尝试仅使用循环来重写目录扫描函数，以说服自己。

递归有用的其他领域包括：

+   生成具有多个级别的菜单的数据结构

+   遍历 XML 文档

+   渲染一系列可能包含子组件的 CMS 组件

一个很好的经验法则是，当您的数据具有树状结构，具有根节点和子节点时，尝试使用递归。

尽管阅读起来通常更容易，但一旦您掌握了它，递归就会带来内存成本。在大多数应用程序中，您不应遇到任何困难，但我们将在第十章中进一步讨论这个话题，*PHP 框架和 FP*，并提出一些避免这些问题的方法。

## 递归和循环

一些函数式语言，如 Haskell，没有任何循环结构。这意味着迭代数据结构的唯一方法是使用递归。虽然在函数世界中不鼓励使用 for 循环，因为当您可以修改循环索引时会出现所有问题，但使用`foreach`循环等并没有真正的危险。

为了完整起见，以下是一些替换循环为递归调用的方法，如果您想尝试或需要理解用另一种没有循环结构的语言编写的代码。

替换`while`循环：

```php
<?php 

function while_iterative() 
{ 
    $result = 1; 
    while($result < 50) { 
        $result = $result * 2; 
    } 
    return $result; 
} 

function while_recursive($result = 1, $continue = true) 
{ 
    if($continue === false) { 
        return $result; 
    } 
    return while_recursive($result * 2, $result < 50); 
} 
```

或者`for`循环：

```php
<?php 

function for_iterative() 
{ 
    $result = 5; 

    for($i = 1; $i < 10; ++$i) { 
        $result = $result * $i; 
    } 

    return $result; 
} 

function for_recursive($result = 5, $i = 1) 
{ 
    if($i >= 10) { 
        return $result; 
    } 

    return for_recursive($result * $i, $i + 1); 
} 
```

如您所见，诀窍在于使用函数参数将循环的当前状态传递给下一个递归。在 while 循环的情况下，您传递条件的结果，当您模拟 for 循环时，您传递循环计数器。显然，计算的当前状态也必须始终传递。

通常，递归本身是在辅助函数中完成的，以避免在签名中使用可选参数来执行循环。为了保持全局命名空间的清洁，这个辅助函数在原始函数内声明。以下是一个示例：

```php
<?php 

function for_with_helper() 
{ 
    $helper = function($result = 5, $i = 1) use(&$helper) { 
        if($i >= 10) { 
            return $result; 
        } 

        return $helper($result * $i, $i + 1); 
    }; 

    return $helper(); 
} 
```

请注意，您需要使用`use`关键字通过引用传递包含函数的变量。这是由于我们已经讨论过的一个事实。传递给闭包的变量在声明时绑定，但当函数声明时，赋值尚未发生，变量为空。但是，如果我们通过引用传递变量，它将在赋值完成后更新，我们将能够在匿名函数内部使用它作为回调。

# 异常

错误管理是编写软件时面临的最棘手的问题之一。很难决定哪段代码应该处理错误。在低级函数中执行，您可能无法访问显示错误消息的设施或足够的上下文来决定最佳操作。在更高层次上执行可能会在数据中造成混乱或使应用程序陷入无法恢复的状态。

在面向对象编程代码库中管理错误的常规方法是使用异常。您在库或实用程序代码中抛出异常，并在准备好按照您的意愿处理它时捕获它。

抛出异常和捕获是否可以被视为副作用或副原因，甚至在学术界也是一个有争议的问题。有各种观点。我不想用修辞论证来使您感到厌烦，所以让我们坚持一些几乎每个人都同意的观点：

+   由任何**外部来源**（数据库访问，文件系统错误，不可用的外部资源，无效的用户输入等）引发的异常本质上是不纯的，因为访问这些来源已经是一个副原因。

+   由于**逻辑错误**（索引超出范围，无效类型或数据等）引发的异常通常被认为是纯的，因为它可以被视为函数的有效`return`值。但是，异常必须清楚地记录为可能的结果。

+   捕获异常会破坏引用透明性，因此任何带有 catch 块的函数都会变得不纯。

前两个语句应该很容易理解，但第三个呢？让我们从一小段代码开始演示：

```php
<?php 
function throw_exception() 
{ 
    throw new Exception('Message'); 
} 

function some_function($x) 
{ 
    $y = throw_exception(); 
    try { 
        $z = $x + $y; 
    } catch(Exception $e) { 
        $z = 42; 
    } 

    return $z; 
} 

echo some_function(42); 
// PHP Warning: Uncaught Exception: Message 
```

很容易看出，我们对`some_function`函数的调用将导致未捕获的异常，因为对`throw_exception`函数的调用位于`try ... catch`块之外。现在，如果我们应用引用透明性的原则，我们应该能够用其值替换加法中的`$y`参数。让我们试试看：

```php
<?php 

try { 
    $z = $x + throw_exception(); 
} catch(Exception $e) { 
    $z = 42; 
} 
```

现在`$z`参数的值是多少，我们的函数将返回什么？与以前不同，我们现在将返回值为`42`，显然改变了调用我们的函数的结果。通过简单地尝试应用等式推理，我们刚刚证明了捕获异常可能会破坏引用透明性。

如果你无法捕获异常，那么异常有什么用呢？不多；这就是为什么在整本书中我们都会避免使用它们。然而，你可以将它们视为副作用，然后应用我们将在第六章中看到的技术，*真实的 Monad*，来管理它们。例如，Haskell 允许抛出异常，只要它们使用 IO Monad 捕获。

另一个问题是认知负担。一旦你使用它们，你就无法确定它们何时会被捕获；它们甚至可能直接显示给最终用户。这破坏了对代码片段本身进行推理的能力，因为现在你必须考虑更高层发生的事情。

这通常是你听到诸如*仅将异常用于错误，而不是流程控制*之类的建议的原因。这样，你至少可以确定你的异常将被用来显示某种错误，而不是想知道你将应用程序置于哪种状态。

## PHP 7 和异常

即使我们大多数时候在负面情况下讨论异常，让我趁此机会介绍一下在新的 PHP 版本中关于这个主题所做的改进。

以前，某些类型的错误会生成致命错误或错误，这些错误会停止脚本的执行并显示错误消息。你可以使用`set_error_handler`异常来定义一个自定义处理程序来处理非致命错误，并最终继续执行。

PHP 7.0 引入了一个`Throwable`接口，它是异常的新父类。`Throwable`类还有一个新的子类叫做`Error`类，你可以用它来捕获以前无法处理的大多数错误。仍然有一些错误，比如解析错误，显然是无法捕获的，因为这意味着你的整个 PHP 文件在某种程度上是无效的。

让我们用一段代码来演示这一点，试图在对象上调用一个不存在的方法：

```php
<?php 
class A {} 

$a = new A(); 

$a->invalid_method(); 

// PHP Warning: Uncaught Error: Call to undefined method  A::invalid_method() 
```

如果你使用的是 PHP 5.6 或更低版本，消息将会说类似于：

```php
Fatal error: Call to undefined method A::invalid_method()
```

然而，使用 PHP 7.0，消息将是（重点是我的）：

```php
Fatal error: **Uncaught Error**: Call to undefined method A::invalid_method()
```

区别在于 PHP 通知你这是一个未捕获的错误。这意味着你现在可以使用通常的`try ... catch`语法来捕获它。你可以直接捕获`Error`类，或者如果你想更广泛地捕获任何可能的异常，你可以使用`Throwable`接口。然而，我不建议这样做，因为你将失去关于你究竟有哪种错误的信息：

```php
<?php class B {} 

$a = new B(); 

try { 
    $a->invalid_method(); 
} catch(Error $e) { 
    echo "An error occured : ".$e->getMessage(); 
} 
// An error occured : Call to undefined method B::invalid_method() 
```

对我们来说也很有趣的是，`TypeError`参数是`Error`类的子类，当使用错误类型的参数调用函数或返回类型错误时会引发它：

```php
<?php 
function add(int $a, int $b): int 
{ 
    return $a + $b; 
} 

try { 
    add(10, 'foo'); 
} catch(TypeError $e) { 
    echo "An error occured : ".$e->getMessage(); 
} 
// An error occured : Argument 2 passed to add() must be of the type integer, string given 
```

对于那些想知道为什么在新的`Error`类旁边创建了一个新的接口，主要是出于两个原因：

+   清楚地将`Exception`接口与以前的内部引擎错误分开

+   为了避免破坏现有代码捕获`Exception`接口，让开发人员选择是否也要开始捕获错误

# 异常的替代方案

正如我们刚才看到的，如果我们想保持代码的纯净，我们就不能使用异常。那么我们有哪些选择来确保我们可以向我们函数的调用者表示错误呢？我们希望我们的解决方案具有以下特点：

+   强制错误管理，以便没有错误会冒泡到最终用户

+   避免样板或复杂的代码结构

+   在我们函数的签名中宣传

+   避免任何将错误误认为是正确结果的风险

在本章的下一节中，我们将介绍一个具有所有这些好处的解决方案，让我们先看看命令式语言中是如何进行错误管理的。

为了测试各种方式，我们将尝试实现我们之前已经使用过的`max`函数：

```php
<?php 
function max2(array $data): int 
{ 
    return array_reduce($data, function(int $max, int $i) : int { 
        return $i > $max ? $i : $max; 
    }, 0); 
} 
```

因为我们选择了初始值 0，如果我们用一个空数组调用函数，我们将得到结果 0。0 真的是一个空数组的最大值吗？如果我们调用与 PHP 捆绑的版本，`max([])`方法会发生什么？

```php
**Warning: max(): Array must contain at least one element**

```

此外，还返回了 false 值。我们的版本使用值 0 作为默认值，我们可以将 false 视为错误代码。PHP 版本还会显示警告。

既然我们有一个可以改进的函数，让我们尝试一下我们可以使用的各种选项。我们将从最差的选项到最好的选项。

## 记录/显示错误消息

正如我们刚才看到的，PHP 可以显示警告消息。我们也可以选择通知或错误级别的消息。这可能是您可以做的最糟糕的事情，因为调用您的函数的人无法知道发生了错误。消息只会在日志中或在应用程序运行时显示在屏幕上。

此外，在某些情况下，错误是可以恢复的。由于您不知道发生了什么，因此在这种情况下无法做到这一点。

更糟糕的是，PHP 允许您配置显示哪个错误级别。在大多数情况下，通知只是隐藏的，所以没有人会看到应用程序中发生了错误。

公平地说，PHP 有一种方法可以在运行时捕获这些警告和通知，即使用`set_error_handler`参数声明自定义错误处理程序。但是，为了正确管理错误，您必须找到一种方法在处理程序内部确定生成错误的函数，并相应地采取行动。

如果您有多个函数使用这些类型的消息来表示错误，您很快要么会有一个非常大的错误处理程序，要么会有很多较小的错误处理程序，这使整个过程容易出错且非常繁琐。

## 错误代码

错误代码是 C 语言的遗产，它没有任何异常的概念。这个想法是一个函数总是返回一个代码来表示计算的状态，并找到其他一些方法来传递返回值。通常，代码 0 表示一切顺利，其他任何代码都是错误。

在涉及数字错误代码时，PHP 没有使用它们作为返回值的函数，据我所知。然而，该语言有很多函数在发生错误时返回`false`值，而不是预期的值。只有一个潜在值来表示失败可能会导致传递有关发生了什么的信息的困难。例如，`move_uploaded_file`的文档说明：

> *成功返回 TRUE。*
> 
> *如果文件名不是有效的上传文件，则不会发生任何操作，move_uploaded_file()将返回 False。*
> 
> *如果文件名是有效的上传文件，但由于某种原因无法移动，则不会发生任何操作，move_uploaded_file()将返回 False。此外，将发出警告。*

这意味着当您发生错误时会收到通知，但是除非阅读错误消息，否则您无法知道它属于哪个错误类别。即使这样，您也会缺少重要信息，例如为什么上传的文件无效。

如果我们想更好地模仿 PHP 的`max`函数，我们可以这样做：

```php
<?php 
function max3(array $data) 
{ 
    if(empty($data)) { 
        trigger_error('max3(): Array must contain at least one  element', E_USER_WARNING); 
        return false; 
    } 

    return array_reduce($data, function(int $max, int $i) : int { 
        return $i > $max ? $i : $max; 
    }, 0); 
} 
```

由于现在我们的函数需要在发生错误时返回 false 值，我们不得不删除返回值的类型提示，从而使我们的签名不太自我说明。

其他函数，通常是包装外部库的函数，也会在发生错误时返回`false`值，但是在形式上具有`X_errno`和`X_error`的伴随函数，它们返回有关上次执行的函数的错误的更多信息。一些示例包括`curl_exec`、`curl_errno`和`curl_error`函数。

这些辅助程序允许更精细的错误处理，但代价是您必须考虑它们。错误管理不是强制的。为了进一步证明我的观点，让我们注意一下官方文档中`curl_exec`函数的示例甚至没有设置检查返回值的最佳实践：

```php
<?php 

/* create a new cURL resource */ 
$ch = curl_init(); 

/* set URL and other appropriate options */ 
curl_setopt($ch, CURLOPT_URL, "http://www.example.com/"); 
curl_setopt($ch, CURLOPT_HEADER, 0); 

/* grab URL and pass it to the browser */ 
curl_exec($ch); 

/* close cURL resource, and free up system resources */ 
curl_close($ch); 
```

在像 PHP 这样执行松散类型转换的语言中，将`false`值用作失败的标记也会产生另一个后果。正如前面的文档中所述，如果您不执行严格的相等比较，您可能会将一个作为 false 的有效返回值误认为是错误：

> *警告：此函数可能返回布尔值 FALSE，但也可能返回一个非布尔值，该值会被视为假。请阅读布尔值部分以获取更多信息。使用===运算符来测试此函数的返回值。*

PHP 仅在出现错误时使用 false 错误代码，但不像 C 语言通常情况下会返回`true`或`0`。您不必找到一种方法将返回值传递给用户。

但是，如果您想要使用数字错误代码来实现自己的函数，以便有可能对错误进行分类，您必须找到一种方法来同时返回代码和值。通常，您可以使用以下两种选项之一：

+   使用通过引用传递的参数来保存结果；例如，`preg_match`参数就是这样做的，即使出于不同的原因。只要参数明确标识为返回值，这并不严格违背函数的纯度。

+   返回一个数组或其他可以容纳两个或更多值的数据结构。这个想法是我们将在下一节中作为我们的函数解决方案的开端。

## 默认值/空值

在认知负担方面，与错误代码相比，默认值要好一点。如果您的函数只有一组可能导致错误的输入，或者如果错误原因不重要，您可以考虑返回一个默认值，而不是通过错误代码指定错误原因。

然而，这将引发新的问题。确定一个好的默认值并不总是容易的，在某些情况下，您的默认值也将是一个有效值，这将使确定是否存在错误变得不可能。例如，如果在调用我们的`max2`函数时得到 0 作为结果，您无法知道数组是空的还是只包含值为 0 和负数。

默认值也可能取决于上下文，这种情况下，您将不得不向函数添加一个参数，以便在调用时也可以指定默认值。除了使函数签名变得更大之外，这也会破坏我们稍后将学习的一些性能优化，并且，尽管完全纯净和引用透明，但会增加认知负担。

让我们向我们的`max`函数添加一个默认值参数：

```php
<?php 

function max4(array $data, int $default = 0): int 
{ 
    return empty($data) ? $default : 
      array_reduce($data, function(int $max, int $i) : int 
      { 
          return $i > $max ? $i : $max; 
      }, 0); 
} 
```

由于我们强制默认值的类型，我们能够恢复返回值的类型提示。如果您想将任何东西作为默认值传递，您还必须删除类型提示。

为了避免讨论的一些问题，有时会使用 null 值作为默认返回值。尽管 null 并不是一个真正的值，但在某些情况下，它并不属于*错误代码*类别，因为在某些情况下它是一个完全有效的值。比如说，如果你在一个集合中搜索一个项目，如果什么都没找到，你会返回什么？

然而，使用 null 值作为可能的返回值有两个问题：

+   您不能将返回类型提示为 null，因为 null 不会被视为正确类型。此外，如果您计划将该值用作参数，它也不能被类型提示，或者必须是带有 null 值作为默认值的可选参数。这将迫使您要么删除类型提示，要么将参数设为可选的。

+   如果您的函数通常返回对象，您将不得不检查 null 值，否则您将面临托尼·霍尔所说的*十亿美元错误*，即空指针引用。或者，如 PHP 中所述，*在 null 上调用成员函数 XXX()*。

顺便说一句，Tony Hoare 是在 1965 年引入空值的人，因为它很容易实现。后来，他非常后悔这个决定，并决定这是他的十亿美元错误。如果你想了解更多原因，我邀请你观看他在[`www.infoq.com/presentations/Null-References-The-Billion-Dollar-Mistake-Tony-Hoare`](https://www.infoq.com/presentations/Null-References-The-Billion-Dollar-Mistake-Tony-Hoare)上的演讲。

## 错误处理程序

最后一种方法在 JavaScript 世界中被广泛使用，因为回调函数随处可见。这个想法是每次调用函数时传递一个错误回调。如果允许调用者传递多个回调，每种错误都可以有一个回调，那么它甚至可以更加强大。

尽管它缓解了默认值的一些问题，比如可能将有效值与默认值混淆，但你仍然需要根据上下文传递不同的回调，使得这种解决方案只能略微好一些。

这种方法对我们的函数会是什么样子呢？考虑以下实现：

```php
<?php 

function max5(array $data, callable $onError): int 
{ 
    return empty($data) ? $onError() : 
      array_reduce($data, function(int $max, int $i) : int { 
          return $i > $max ? $i : $max; 
      }, 0); 
} 

max5([], function(): int { 
    // You are free to do anything you want here. // Not really useful in such a simple case but 
    // when creating complex objects it can prove invaluable. return 42; 
}); 
```

同样，我们保留了返回类型提示，因为我们与调用者的契约是返回一个整数值。正如评论中所述，在这种特殊情况下，参数的默认值可能就足够了，但在更复杂的情况下，这种方法提供了更多的功能。

我们还可以想象将初始参数传递给回调，同时传递有关失败的信息，以便错误处理程序可以相应地采取行动。在某种程度上，这种方法有点像我们之前看到的所有东西的组合，因为它允许你：

+   指定你选择的默认返回值

+   显示或记录任何你想要的错误消息

+   如果你愿意，可以返回一个更复杂的数据结构和错误代码

# Option/Maybe 和 Either 类型

如前所述，我们的解决方案是使用一个包含所需值或在出现错误时包含其他内容的返回类型。这种数据结构称为**联合类型**。联合可以包含不同类型的值，但一次只能包含一个。

让我们从本章中将要看到的两种联合类型中最简单的开始。一如既往，命名在计算机科学中是一件困难的事情，人们提出了不同的名称来指代基本上相同的结构：

+   Haskell 称之为 Maybe 类型，**Idris**也是如此

+   Scala 称之为 Option 类型，**OCaml**、**Rust**和**ML**也是如此

+   自 Java 8 以来，Java 就有了 Optional 类型，Swift 和下一个 C++规范也是如此

就个人而言，我更喜欢称之为 Maybe，因为我认为选项是另一回事。因此，本书的其余部分将使用这个术语，除非特定的库有一个名为**Option**的类型。

Maybe 类型在某种意义上是特殊的，它可以保存特定类型的值，也可以是*nothing*的等价物，或者如果你愿意的话，是空值。在 Haskell 中，这两种可能的值被称为`Just`和`Nothing`。在 Scala 中，它是`Some`和`None`，因为`Nothing`已经被用来指定值 null 的类型等价物。

只实现了 Maybe 或 Option 类型的库存在于 PHP 中，本章后面介绍的一些库也带有这些类型。但为了正确理解它们的工作原理和功能，我们将实现自己的类型。

让我们首先重申我们的目标：

+   强制错误管理，以便没有错误会冒泡到最终用户

+   避免样板代码或复杂的代码结构

+   在我们函数的签名中进行广告

+   避免任何错误被误认为是正确的结果

如果您使用我们将在接下来创建的类型对函数返回值进行类型提示，那么您已经照顾到了我们的第三个目标。`Just`和`Nothing`值的存在确保您不会将有效结果误认为错误。为了确保我们不会在某个地方得到错误的值，我们必须确保在没有指定默认值的情况下，不能从我们的新类型中获取值。关于我们的第二个目标，我们将看到我们是否可以写出一些好东西：

```php
<?php 

abstract class Maybe 
{ 
    public static function just($value): Just 
    { 
        return new Just($value); 
    } 

    public static function nothing(): Nothing 
    { 
        return Nothing::get(); 
    } 

    abstract public function isJust(): bool; 

    abstract public function isNothing(): bool; 

    abstract public function getOrElse($default); 
} 
```

我们的类有两个静态辅助方法，用于创建我们即将到来的子类的两个实例，代表我们的两种可能状态。`Nothing`值将作为单例实现，出于性能原因；因为它永远不会持有任何值，这样做是安全的。

我们类中最重要的部分是一个抽象的`getOrElse`函数，它将强制任何想要获取值的人也传递一个默认值，如果我们没有值则返回该默认值。这样，我们可以强制在错误的情况下返回一个有效的值。显然，您可以将 null 值作为默认值传递，因为 PHP 没有强制执行其他机制，但这就像是在自己的脚上开枪：

```php
<?php 
final class Just extends Maybe 
{ 
    private $value; 

    public function __construct($value) 
    { 
        $this->value = $value; 
    } 

    public function isJust(): bool 
    { 
        return true; 
    } 

    public function isNothing(): bool 
    { 
        return false; 
    } 

    public function getOrElse($default) 
    { 
        return $this->value; 
    } 
} 
```

我们的`Just`类非常简单；一个构造函数和一个 getter：

```php
<?php 
final class Nothing extends Maybe 
{ 
    private static $instance = null; 
    public static function get() 
    { 
        if(is_null(self::$instance)) { 
            self::$instance = new static(); 
        } 

        return self::$instance; 
    } 

    public function isJust(): bool 
    { 
        return false; 
    } 

    public function isNothing(): bool 
    { 
        return true; 
    } 

    public function getOrElse($default) 
    { 
        return $default; 
    } 
} 
```

如果您不考虑成为单例的部分，`Nothing`类甚至更简单，因为`getOrElse`函数将始终返回默认值。对于那些好奇的人，保持构造函数公开是一个有意为之的选择。如果有人想直接创建`Nothing`实例，这绝对没有任何后果，那又何必费心呢？

让我们测试一下我们的新的`Maybe`类型：

```php
<?php 

$hello = Maybe::just("Hello World !"); 
$nothing = Maybe::nothing(); 

echo $hello->getOrElse("Nothing to see..."); 
// Hello World ! var_dump($hello->isJust()); 
// bool(true) 
var_dump($hello->isNothing()); 
// bool(false) 

echo $nothing->getOrElse("Nothing to see..."); 
// Nothing to see... var_dump($nothing->isJust()); 
// bool(false) 
var_dump($nothing->isNothing()); 
// bool(true) 
```

一切似乎都运行得很顺利。尽管需要样板代码，但可以改进。在这一点上，每当您想要实例化一个新的`Maybe`类型时，您需要检查您拥有的值，并在`Some`和`Nothing`值之间进行选择。

还可能会出现这样的情况，您需要在将值传递给下一个步骤之前对其应用一些函数，但在这一点上不知道最佳的默认值是什么。由于在创建新的`Maybe`类型之前，使用一些临时默认值获取值会很麻烦，让我们也尝试解决这个方面：

```php
<?php 

abstract class Maybe 
{ 
    // [...] 

    public static function fromValue($value, $nullValue = null) 
    { 
        return $value === $nullValue ? self::nothing() : 
            self::just($value); 
    } 

    abstract public function map(callable $f): Maybe; 
} 

final class Just extends Maybe 
{ 
    // [...] 

    public function map(callable $f): Maybe 
    { 
        return new self($f($this->value)); 
    } 
} 

final class Nothing extends Maybe 
{ 
    // [...] 

    public function map(callable $f): Maybe 
    { 
        return $this; 
    } 
} 
```

为了使实用方法的命名有些连贯性，我们使用与处理集合的函数相同的名称。在某种程度上，您可以将`Maybe`类型视为一个只有一个或没有值的列表。让我们基于相同的假设添加一些其他实用方法：

```php
<?php abstract class Maybe 
{ 
    // [...] 
    abstract public function orElse(Maybe $m): Maybe; 
    abstract public function flatMap(callable $f): Maybe;
    abstract public function filter(callable $f): Maybe;
} 

final class Just extends Maybe 
{ 
    // [...] 

    public function orElse(Maybe $m): Maybe 
    { 
        return $this; 
    } 

    public function flatMap(callable $f): Maybe 
    { 
        return $f($this->value); 
    } 

    public function filter(callable $f): Maybe 
    { 
        return $f($this->value) ? $this : Maybe::nothing(); 
    } 
} 

final class Nothing extends Maybe 
{ 
    // [...] 

    public function orElse(Maybe $m): Maybe 
    { 
        return $m; 
    } 

    public function flatMap(callable $f): Maybe 
    { 
        return $this; 
    } 

    public function filter(callable $f): Maybe 
    { 
        return $this; 
    } 
  } 
```

我们已经向我们的实现添加了三个新方法：

+   `orElse`方法如果有值则返回当前值，如果是`Nothing`则返回给定值。这使我们能够轻松地从多个可能的来源获取数据。

+   `flatMap`方法将一个可调用对象应用于我们的值，但不会将其包装在 Maybe 类中。可调用对象有责任自己返回一个 Maybe 类。

+   `filter`方法将给定的断言应用于值。如果断言返回 true 值，我们保留该值；否则，我们返回`Nothing`值。

现在我们已经实现了一个可工作的`Maybe`类型，让我们看看如何使用它轻松摆脱错误和空值管理。假设我们想要在应用程序的右上角显示有关已连接用户的信息。如果没有`Maybe`类型，您可能会做以下操作：

```php
<?php 
$user = getCurrentUser(); 

$name = $user == null ? 'Guest' : $user->name; 

echo sprintf("Welcome %s", $name); 
// Welcome John 
```

在这里，我们只使用名称，因此我们可以限制自己只进行一次空值检查。如果我们需要从用户那里获取更多信息，通常的方法是使用一种有时被称为**空对象**模式的模式。在我们的情况下，我们的空对象将是`AnonymousUser`方法的一个实例：

```php
<?php 

$user = getCurrentUser(); 

if($user == null) { 
   $user = new AnonymousUser(); 
} 

echo sprintf("Welcome %s", $user->name); 
// Welcome John 
```

现在让我们尝试使用我们的`Maybe`类型做同样的事情：

```php
<?php 

$user = Maybe::fromValue(getCurrentUser()); 

$name = $user->map(function(User $u) { 
  return $u->name; 
})->getOrElse('Guest'); 

echo sprintf("Welcome %s", $name); 
// Welcome John 

echo sprintf("Welcome %s", $user->getOrElse(new AnonymousUser())->name); 
// Welcome John 
```

第一个版本可能不会好多少，因为我们不得不创建一个新的函数来提取名称。但让我们记住，在需要提取最终值之前，你可以对对象进行任意数量的处理。此外，我们稍后介绍的大多数函数库都提供了更简单地从对象中获取值的辅助方法。

你还可以轻松地调用一系列方法，直到其中一个返回一个值。比如你想显示一个仪表板，但这些可以根据每个组和每个级别重新定义。让我们比较一下我们的两种方法的表现。

首先，空值检查方法：

```php
<?php 

$dashboard = getUserDashboard(); 
if($dashboard == null) { 
    $dashboard = getGroupDashboard(); 
} 
if($dashboard == null) { 
    $dashboard = getDashboard(); 
} 
```

现在，使用`Maybe`类型：

```php
<?php 

/* We assume the dashboards method now return Maybe instances */ 
$dashboard = getUserDashboard() 
             ->orElse(getGroupDashboard()) 
             ->orElse(getDashboard()); 
```

我认为更易读的那个更容易确定！

最后，让我们演示一个小例子，说明我们如何可以在`Maybe`实例上链式调用多个调用，而无需检查我们当前是否有值。所选择的例子可能有点愚蠢，但它展示了可能的情况：

```php
<?php 

$num = Maybe::fromValue(42); 

$val = $num->map(function($n) { return $n * 2; }) 
         ->filter(function($n) { return $n < 80; }) 
         ->map(function($n) { return $n + 10; }) 
         ->orElse(Maybe::fromValue(99)) 
         ->map(function($n) { return $n / 3; }) 
         ->getOrElse(0); 
echo $val; 
// 33 
```

我们的`Maybe`类型的强大之处在于，我们从未考虑过实例是否包含值。我们只能将函数应用于它，直到最后，使用`getOrElse`方法提取最终值。

## 提升函数

我们已经看到了我们新的`Maybe`类型的强大之处。但事实是，你要么没有时间重写所有现有的函数来支持它，要么根本无法这样做，因为它们是外部第三方的。

幸运的是，你可以**提升**一个函数，创建一个新的函数，它以`Maybe`类型作为参数，将原始函数应用于其值，并返回修改后的`Maybe`类型。

为此，我们将需要一个新的辅助函数。为了保持事情相对简单，我们还将假设，如果提升函数的任何参数的值评估为`Nothing`，我们将简单地返回`Nothing`：

```php
<?php 

function lift(callable $f) 
{ 
    return function() use ($f) 
    { 
        if(array_reduce(func_get_args(), function(bool $status, Maybe $m) { 
            return $m->isNothing() ? false : $status; 
        }, true)) { 
            $args = array_map(function(Maybe $m) { 
                // it is safe to do so because the fold above  checked 
                // that all arguments are of type Some 
                return $m->getOrElse(null); 
            }, func_get_args()); 
            return Maybe::just(call_user_func_array($f, $args)); 
        } 
        return Maybe::nothing(); 
    }; 
} 
```

让我们试试：

```php
<?php 
function add(int $a, int $b) 
{ 
    return $a + $b; 
} 

$add2 = lift('add'); 

echo $add2(Maybe::just(1), Maybe::just(5))->getOrElse('nothing'); 
// 6 

echo $add2(Maybe::just(1), Maybe::nothing())- >getOrElse('nothing'); 
// nothing 
```

现在你可以提升任何函数，以便它可以接受我们的新`Maybe`类型。唯一需要考虑的是，如果你想依赖函数的任何可选参数，它将不起作用。

我们可以使用反射或其他手段来确定函数是否具有可选值，或者将一些默认值传递给提升的函数，但这只会使事情变得更加复杂，并使我们的函数变得更慢。如果你需要使用带有可选参数和`Maybe`类型的函数，你可以重写它或为它制作一个自定义包装器。

最后，提升的过程并不局限于 Maybe 类型。你可以提升任何函数以接受任何类型的容器。我们的辅助程序更好的名称可能是**liftMaybe**，或者我们可以将其添加为`Maybe`类的静态方法，以使事情更清晰。

## Either 类型

`Either`类型是我们`Maybe`类型的泛化。与其有值和无值不同，你有左值和右值。由于它也是一个联合类型，这两种可能的值中只能有一个在任何给定时间被设置。

当只有少数错误来源或错误本身并不重要时，`Maybe`类型的工作效果很好。使用`Either`类型，我们可以通过左值提供任何我们想要的错误信息。右值用于成功，因为这是一个明显的双关语。

这是`Either`类型的一个简单实现。由于代码本身相当无聊，书中只介绍了基类。你可以在 Packt 网站上访问两个子类：

```php
<?php 
abstract class Either 
{ 
    protected $value; 

    public function __construct($value) 
    { 
        $this->value = $value; 
    } 

    public static function right($value): Right 
    { 
        return new Right($value); 
    } 

    public static function left($value): Left 
    { 
        return new Left($value); 
    } 

    abstract public function isRight(): bool; 
    abstract public function isLeft(): bool; 
    abstract public function getRight(); 
    abstract public function getLeft(); 
    abstract public function getOrElse($default); 
    abstract public function orElse(Either $e): Either; 
    abstract public function map(callable $f): Either; 
    abstract public function flatMap(callable $f): Either; 
    abstract public function filter(callable $f, $error): Either; 
} 
```

该实现提议与我们为`Maybe`类提供的 API 相同，假设右值是有效的。你应该能够在不改变逻辑的情况下，到处使用`Either`类而不是`Maybe`类。唯一的区别是检查我们处于哪种情况的方法，并将方法更改为新的`getRight`或`getLeft`方法。

也可以为我们的新类型编写提升：

```php
<?php 
function liftEither(callable $f, $error = "An error occured") 
{ 
    return function() use ($f) 
    { 
        if(array_reduce(func_get_args(), function(bool $status, Either $e) { 
            return $e->isLeft() ? false : $status; 
        }, true)) { 
            $args = array_map(function(Either $e) { 
                // it is safe to do so because the fold above  checked 
                // that all arguments are of type Some 
                return $e->getRight(null); 
            }, func_get_args()); 
            return Either::right(call_user_func_array($f, $args)); 
        } 
        return Either::left($error); 
    }; 
} 
```

然而，这个函数比自定义包装器要少一些用处，因为你无法指定一个特定于可能的错误的错误消息。

# 图书馆

现在我们已经介绍了 PHP 中已有的各种功能性技术的基础知识，是时候看看各种库了，这些库将使我们能够专注于我们的业务代码，而不是编写辅助函数和实用程序函数，就像我们使用新的`Maybe`和`Either`类型一样。

## 功能性 PHP 库

`functional-php`库可能是与 PHP 相关的功能性编程中最古老的库之一，因为它的第一个版本可以追溯到 2011 年 6 月。它与最新的 PHP 版本良好地发展，并且甚至去年切换到了 Composer 进行分发。

该代码可在 GitHub 上找到[`github.com/lstrojny/functional-php`](https://github.com/lstrojny/functional-php)。如果您习惯使用 Composer，安装应该非常容易，只需写入以下命令：

```php
**composer require lstrojny/functional-php.**

```

该库曾经在 PHP 中实现，并作为 C 扩展的一部分出于性能原因。但是，由于 PHP 核心在速度方面的最新改进以及维护两个代码库的负担，该扩展已经过时。

实现了许多辅助函数-我们现在没有足够的空间详细介绍每一个。如果您感兴趣，可以查看文档。但是，我们将快速介绍重要的函数，本书的其余部分将包含更多的示例。

此外，我们还没有讨论库相关函数涵盖的一些概念，我们将在处理这些主题时进行介绍。

### 如何使用这些函数

正如在第一章中已经讨论的那样，自 PHP 5.6 以来，您可以从命名空间导入函数。这是使用该库的最简单方法。您还可以导入整个命名空间，并在调用函数时添加前缀：

```php
<?php 
require_once __DIR__.'/vendor/autoload.php'; 

use function Functional\map; 

map(range(0, 4), function($v) { return $v * 2; }); 

use Functional as F; 

F\map(range(0, 4), function($v) { return $v * 2; }); 
```

还要注意的是，大多数函数接受数组和实现`Traversable`接口的任何内容，例如迭代器。

### 通用辅助函数

这些函数可以帮助您在各种情境下，而不仅仅是在功能性方面：

+   `true`和`false`函数检查集合中的所有元素是否严格为 True 或严格为 False。

+   `truthy`和`falsy`函数与以前相同，但比较不是严格的。

+   `const_function`函数返回一个新函数，该函数将始终返回给定值。这可以用于模拟不可变数据。

### 扩展 PHP 函数

PHP 函数倾向于仅在*真实*数组上工作。以下函数将它们的行为扩展到任何可以使用`foreach`循环进行迭代的内容。所有函数的参数顺序也保持一致：

+   `contains`方法检查给定集合中是否包含该值。第三个参数控制比较是否应该是严格的。

+   `sort`方法对集合进行排序，但返回一个新数组，而不是通过引用进行排序。您可以决定是否保留键。

+   `map`方法将`array_map`方法的行为扩展到所有集合。

+   `sum`、`maximum`和`minimum`方法在任何类型的集合上执行与它们的 PHP 对应方法相同的工作。除此之外，该库还包含 product、ratio、difference 和 average。

+   当您不传递函数时，`zip`方法执行与`array_map`方法相同的工作。但是，您也可以传递回调函数来确定如何合并各个项目。

+   `reduce_left`和`reduce_right`方法从左侧或右侧折叠集合。

### 使用谓词

在处理集合时，通常希望检查某些、全部或没有元素是否满足某个条件，并相应地采取行动。为了做到这一点，您可以使用以下函数：

+   `every`函数如果集合的所有元素都对谓词有效，则返回 true 值

+   `some`函数如果至少有一个元素对谓词有效，则返回 true 值

+   `none`函数如果没有元素对于谓词有效，则返回 true

这些函数不会修改集合。它们只是检查元素是否符合某个条件。如果需要过滤一些元素，可以使用以下辅助函数：

+   `select`或`filter`函数仅返回对于谓词有效的元素。

+   `reject`函数仅返回对于谓词无效的元素。

+   `head`函数返回对于谓词有效的第一个元素。

+   最后一个函数返回对于谓词有效的最后一个元素。

+   `drop_first`函数从集合的开头删除元素，直到给定的回调为`true`。一旦回调返回 false，停止删除元素。

+   `drop_last`函数与上一个函数相同，但是从末尾开始。

所有这些函数都返回一个新的数组，原始集合保持不变。

### 调用函数

当您想在回调中调用函数时，声明匿名函数是很麻烦的。这些辅助函数将为您提供更简单的语法：

+   `invoke`辅助函数在集合中的所有对象上调用方法，并返回具有结果的新集合

+   `invoke_first`和`invoke_last`辅助函数分别在集合的第一个和最后一个对象上调用方法

+   `invoke_if`辅助函数如果第一个参数是有效对象，则调用给定的方法。您可以传递方法参数和默认值。

+   `invoker`辅助函数返回一个新的可调用对象，它使用给定的参数调用给定的方法。

您可能还希望调用函数，直到获得一个值或达到某个阈值。该库已经为您做好了准备：

+   `retry`库调用函数，直到它停止返回异常或达到尝试次数

+   `poll`库调用函数，直到它返回真值或达到给定的超时时间

### 操作数据

之前的函数组是关于使用辅助函数调用函数；这个函数组是关于获取和操作数据，而不必每次都求助于匿名函数：

+   `pluck`函数从给定集合中的所有对象中提取属性，并返回具有这些值的新集合。

+   `pick`函数根据给定的键从数组中选择一个元素。如果元素不存在，可以提供默认值。

+   `first_index_of`和`last_index_of`函数分别返回匹配给定值的元素的第一个和最后一个索引。

+   `indexes_of`函数返回所有匹配给定值的索引。

+   `flatten`函数将嵌套集合的深度减少为单个平面集合。

有时，您也希望根据谓词或某个分组值将集合分成多个部分：

+   `partition`方法接受一组谓词-根据第一个谓词的有效性，将集合的每个项目放入给定的组中。

+   `group`方法根据每个元素的回调返回的每个不同值创建多个组

### 总结

正如您所看到的，`functional-php`库提供了许多不同的辅助函数和实用函数。现在可能不明显您如何充分利用它们，但我希望本书的剩余部分能让您一窥您可以实现的内容。

另外，不要忘记我们没有介绍所有的函数，因为其中一些需要一点理论解释。一切都在适当的时间。

## php-option 库

我们之前创建了自己版本的`Maybe`类型。这个库提出了一个更完整的实现。选择了 Scala 使用的命名，然而。源代码在 GitHub 上[`github.com/schmittjoh/php-option`](https://github.com/schmittjoh/php-option)。最简单的安装方法是使用 Composer 写入以下命令：

```php
**composer require phpoption/phpoption**

```

一个有趣的补充是`LazyOption`方法，它接受一个回调而不是一个值。只有在需要值时才会执行回调。当您使用`orElse`方法为前一个无效值提供替代时，这是特别有趣的。在这种情况下使用`LazyOption`方法，可以避免在一个值有效时进行不必要的计算。

您还可以使用各种辅助程序来帮助您仅在值有效时调用方法，例如，还提供了多种实例化可能性。该库还提供了一个 API，更类似于您习惯于集合的 API。

## Laravel 集合

如第一章所述，Laravel 提供了一个很好的库来管理集合。它声明了一个名为`Collection`的类，该类在其 ORM **Eloquent**和大多数其他依赖于集合的部分内部使用。

在内部，使用了一个简单的数组，但以一种促进数据的不可变性和功能性方法来包装它。为了实现这个目标，为开发人员提供了 60 到 70 种方法。

如果您已经在使用 Laravel，您可能已经熟悉此支持类提供的可能性。如果您正在使用其他任何框架，仍然可以从中受益，方法是从[`github.com/tightenco/collect`](https://github.com/tightenco/collect)获取提取的部分。

文档可在 Laravel 官方网站[`laravel.com/docs/collections`](https://laravel.com/docs/collections)上找到。我们不会详细描述每个方法，因为它们有很多。如果您正在使用 Laravel 并想了解其集合提供的所有可能性，可以前往[`adamwathan.me/refactoring-to-collections/`](https://adamwathan.me/refactoring-to-collections/)。

### 使用 Laravel 的集合

第一步是使用 collect 实用程序函数将数组或`Traversable`接口转换为`Collection`类的实例。然后您将可以访问类提供的各种方法。让我们快速列出到目前为止我们已经以另一种形式遇到的那些方法：

+   `map`方法将函数应用于所有元素并返回新值

+   `filter`方法使用谓词过滤集合

+   `reduce`方法使用给定的回调函数折叠集合

+   `pluck`方法从所有元素中获取给定的属性

+   `groupBy`方法使用每个元素的给定值对集合进行分区

所有这些方法都返回`Collection`类的新实例，保留原始实例的值。

完成操作后，您可以使用 all 方法将当前值作为数组获取。

## immutable-php 库

这个提出不可变数据结构的库是由于对**标准 PHP**库中的`SplFixedArray`方法的各种抱怨，主要是其难以使用的 API。在其核心，`immutable-php`库使用前面提到的数据结构，但使用一组很好的方法来包装它。

`SplFixedArray`方法是一个具有固定大小并且只允许数字索引的数组的特定实现。这些约束允许实现一个非常快速的数组结构。

您可以在 GitHub 项目页面[`github.com/jkoudys/immutable.php`](https://github.com/jkoudys/immutable.php)上查看或通过使用 Composer 编写以下命令来安装它：

```php
**composer require qaribou/immutable.php.**

```

### 使用 immutable.php

使用专用的静态助手`fromArray`或`fromItems`为`Traversable`类的任何实例创建新实例非常容易。您新创建的`ImmArray`实例可以像任何数组一样访问，使用`foreach`循环进行迭代，并使用`count`方法进行计数。但是，如果尝试设置一个值，将会收到异常。

一旦你有了不可变数组，你可以使用各种方法来应用你现在应该习惯的转换：

+   `map` 方法将函数应用于所有项目并返回新值

+   `filter` 方法创建仅包含谓词有效项目的新数组

+   `reduce` 方法使用回调折叠项目

你还有其他帮手：

+   `join` 方法连接字符串集合

+   `sort` 方法使用给定的回调返回排序后的集合

你的数据也可以很容易地以传统数组形式检索或编码为 JSON 格式。

总的来说，这个库提供的方法比 Laravel 的 Collection 更少，但性能更好，内存占用更低。

## 其他库

由于 PHP 核心缺乏很多实用函数和功能来进行适当的函数式编程，很多人开始致力于实现缺失部分的库。这就是为什么如果你开始寻找，你会发现很多这样的库。

以下是一份不完整且无序的库列表，如果之前介绍的那些不符合你的需求。

### Underscore.php 库

基于 `Underscore.js` 库的 API 存在多种用于 PHP 的端口。我个人不太喜欢 `Underscore.js` 库，因为函数参数经常顺序错误，无法有效地进行函数组合。这一点在这个视频中有很好的解释：[`www.youtube.com/watch?v=m3svKOdZijA`](https://www.youtube.com/watch?v=m3svKOdZijA)。

然而，如果你习惯使用它，这是一个各种端口的简短列表：

+   [`github.com/brianhaveri/Underscore.php`](https://github.com/brianhaveri/Underscore.php)：据我所知，这是最古老的端口。自 2012 年以来就没有任何活动，但存在很多分支来改进与新版本 PHP 的兼容性并修复错误。

+   [`github.com/wikiHow/Underscore.php`](https://github.com/wikiHow/Underscore.php)：前述库中最受维护的分支之一。

+   [`github.com/Anahkiasen/underscore-php`](https://github.com/Anahkiasen/underscore-php)：最初是其 JS 对应的一个端口。现在它包含一些不同的功能，试图尊重原始的哲学。

+   [`github.com/Im0rtality/Underscore`](https://github.com/Im0rtality/Underscore)：更近期的尝试，类似于 `Underscore.js` 库。在撰写本文时，文档缺少一些重要主题，而且该库在很多地方与 JavaScript 版本不同。

### Saber

**Saber** 严格遵循最新的 PHP 版本作为要求。它使用强类型、不可变对象和惰性求值。为了使用它的各种方法，你必须将你的值*装箱*到库提供的类中。这可能有些麻烦，但它提供了安全性并减少了错误。

它似乎受到 C# 和主要是 F# 的启发，后者是在 .NET 虚拟机上运行的函数语言，或者用其真实名称 **`CLR`** 来称呼它。你可以在 GitHub 上找到源代码和文档：[`github.com/bluesnowman/fphp-saber`](https://github.com/bluesnowman/fphp-saber)。

### Rawr

**Rawr** 不仅仅是一个函数库。它试图以更一般的方式修复 PHP 语言的缺陷。与 Saber 一样，它提供了一个新类来装箱你的标量值；然而，类型的使用更接近 Haskell。你还可以将你的匿名函数包装在一个类中，以在其周围获得更好的类型安全性。

该库还添加了更多 **Smalltalk** 风格的面向对象、单子，并允许你执行一些类似 JavaScript 的基于原型的编程。

遗憾的是，该库似乎停滞不前，文档与源代码不同步。然而，您可以在那里找到一些灵感。您可以在 GitHub 上找到代码[`github.com/haskellcamargo/rawr`](https://github.com/haskellcamargo/rawr)。

### PHP 功能性

这个库主要围绕我们将在第五章中看到的 Monad 的概念。承认的灵感来自 Haskell，该库实现了：

+   State Monad

+   IO Monad

+   集合 Monad

+   Either Monad

+   Maybe Monad

通过`Collection` Monad，该库提供了我们期望的各种方法`map`、`reduce`和`filter`方法。

由于受 Haskell 的启发，您可能会发现在开始时使用它有点困难。然而，最终它应该会更加强大。您可以在 GitHub 上找到代码[`github.com/widmogrod/php-functional`](https://github.com/widmogrod/php-functional)。

### 功能性

最初创建为一个学习游乐场，这个库已经发展成为一个相对小型但有用的东西。主要的想法是提供一个框架，以便您可以在代码中删除所有循环。

最有趣的特点是所有函数都可以部分应用而无需进行任何特殊操作。部分应用对于函数组合非常重要。我们将在第四章中发现这两个主题，*组合函数*。

该库还具有所有传统的竞争者，如映射和减少。代码和文档可在 GitHub 上找到[`github.com/sergiors/functional`](https://github.com/sergiors/functional)。

### PHP 函数式编程工具

这个库试图走与我们在前几页中介绍的`functional-php`库相同的道路。据我所知，它目前的功能略少。对于想要更小、可能更容易学习的人来说，这可能是一个有趣的库。代码在 GitHub 上[`github.com/daveross/functional-programming-utils`](https://github.com/daveross/functional-programming-utils)。

### 非标准 PHP 库

这个库并不严格是一个功能性的库。这个想法更多的是通过各种辅助和实用函数来扩展标准库，以使处理集合更加容易。

它包含一些有用的功能，例如帮助轻松验证函数参数，无论是使用已定义的约束还是自定义的约束。它还扩展了现有的 PHP 函数，以便它们可以处理任何`Traversable`接口的内容，而不仅仅是数组。

该库创建于 2014 年，但直到 2015 年底工作再次开始才几乎停滞不前。现在它可能是我们之前介绍的任何库的替代品。如果您感兴趣，请在 GitHub 上获取代码[`github.com/ihor/Nspl`](https://github.com/ihor/Nspl)。

# 总结

在这一长章节中，我们介绍了我们将在整本书中使用的所有实用构建块。希望这些例子不会显得太枯燥。有很多内容要涵盖，而页面数量有限。接下来的章节将在我们学到的基础上进行更好的示例。

您首先阅读了一些关于编程的一般建议，这对于功能代码库尤其重要。然后，我们发现了基本的功能技术，如映射、折叠、过滤和压缩，所有这些都可以直接在 PHP 中使用。

接下来是对递归的简要介绍，这是一种解决特定问题集的技术，也是避免使用循环的方法。在一本关于功能性语言的书中，这个主题可能值得一整章，但由于 PHP 有各种循环结构，它的重要性稍低一些。此外，我们将在接下来的章节中看到更多的递归示例。

我们还讨论了异常以及它们在功能代码库中引发的问题，并在讨论其他方法的利弊后，编写了 Maybe 和 Either 类型的实现，作为更好地管理错误的方法。

最后，我们介绍了一些提供功能构造和辅助功能的库，这样我们就不必自己编写了。
