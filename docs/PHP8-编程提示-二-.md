# PHP8 编程提示（二）

> 原文：[`zh.annas-archive.org/md5/7838a031e7678d26b84966d54ffa29dd`](https://zh.annas-archive.org/md5/7838a031e7678d26b84966d54ffa29dd)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：利用错误处理增强功能

如果您是 PHP 开发人员，您会注意到随着语言不断成熟，越来越多的保障措施被制定出来，最终强制执行良好的编码实践。在这方面，PHP 8 的一个关键改进是其先进的错误处理能力。在本章中，您将了解哪些`Notices`已升级为`Warnings`，哪些`Warnings`已升级为`Errors`。

本章让您对安全增强的背景和意图有了很好的理解，从而使您更好地控制代码的使用。此外，了解以前只生成`Warnings`但现在也生成`Errors`的错误条件，以采取措施防止在升级到 PHP 8 后应用程序失败，也是至关重要的。

本章涵盖以下主题：

+   理解 PHP 8 错误处理

+   处理现在是错误的警告

+   理解提升为警告的通知

+   处理`@`错误控制运算符

# 技术要求

为了检查和运行本章提供的代码示例，以下是最低推荐的硬件要求：

+   基于 x86_64 桌面 PC 或笔记本电脑

+   1 **千兆字节**（**GB**）的可用磁盘空间

+   4 GB 的**随机存取存储器**（**RAM**）

+   500 **千比特每秒**（**Kbps**）或更快的互联网连接

此外，您还需要安装以下软件：

+   Docker

+   Docker Compose

有关 Docker 和 Docker Compose 安装的更多信息，请参阅*第一章*的*技术要求*部分，介绍新的 PHP 8 OOP 功能，以及如何构建用于演示本书中所解释的代码的 Docker 容器。在本书中，我们将恢复本书示例代码的目录称为`/repo`。

本章的源代码位于此处：

[`github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices`](https://github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices)

我们现在可以通过检查新的 PHP 8 运算符来开始我们的讨论。

# 理解 PHP 8 错误处理

从历史上看，许多 PHP 错误条件被分配了远低于其实际严重性的错误级别。这给开发人员一种错误的安全感，因为他们只看到一个`Notice`，就认为他们的代码没有问题。许多情况以前只生成`Notice`或`Warning`，而实际上它们的严重性值得更多的关注。

在本节中，我们将看看 PHP 8 中一些错误处理的增强功能，这些功能继续执行强制执行良好编码实践的总体趋势。本章的讨论将帮助您重新审视您的代码，以便更高效地进行编码，并减少未来的维护问题。

在接下来的几个小节中，我们将看看对某些可能影响您的代码的`Notice`和`Warning`错误条件的更改。让我们首先看看 PHP 8 如何处理未定义变量的更改。

## 未定义变量处理

PHP 的一个臭名昭著的特性是它如何处理**未定义的变量**。看一下这个简单的代码块。请注意，`$a`和`$b`变量没有被定义：

```php
// /repo/ch03/php8_undef_var.php
$c = $a + $b;
var_dump($c);
```

在 PHP 7 下运行，这是输出：

```php
PHP Notice:  Undefined variable: a in
/repo/ch03/php7_undef_var.php on line 3
PHP Notice:  Undefined variable: b in /repo/ch03/php7_undef_var.php on line 3
int(0)
```

从输出中可以看出，PHP 7 发出了一个`Notice`，让我们知道我们正在使用未定义的变量。如果我们使用 PHP 8 运行完全相同的代码，您可以快速看到以前的`Notice`已经提升为`Warning`，如下所示：

```php
PHP Warning:  Undefined variable $a in /repo/ch03/php8_undef_var.php on line 3
PHP Warning:  Undefined variable $b in /repo/ch03/php8_undef_var.php on line 3
int(0)
```

PHP 8 中错误级别提升背后的推理是，许多开发人员认为使用未定义变量是一种无害的做法，实际上却是非常危险的！ 你可能会问为什么？答案是，PHP 在没有明确指示的情况下，会将任何未定义的变量赋值为 `NULL`。 实际上，您的程序依赖于 PHP 的默认行为，这在将来的语言升级中可能会发生变化。

我们将在本章的接下来几节中介绍其他错误级别的提升。 但是，请注意，将 `Notices` 提升为 `Warnings` 的情况 *不会影响代码的功能*。 但是，它可能会引起更多潜在问题的注意，如果是这样，它就达到了产生更好代码的目的。 与未定义变量不同，未定义常量的错误现在已经进一步提升，您将在下一小节中看到。

## 未定义常量处理

在 PHP 8 中运行时，**未定义常量**的处理方式已经发生了变化。 但是，在这种情况下，以前是 `Warning` 的现在在 PHP 8 中是 `Error`。 看看这个看似无害的代码块：

```php
// /repo/ch03/php7_undef_const.php
echo PHP_OS . "\n";
echo UNDEFINED_CONSTANT . "\n";
echo "Program Continues ... \n";
```

第一行回显了一个标识操作系统的 `PHP_OS` **预定义常量**。 在 PHP 7 中，会生成一个 `Notice`；然而，输出的最后一行是 `Program Continues ...`，如下所示：

```php
PHP Notice:  Use of undefined constant UNDEFINED_CONSTANT - assumed 'UNDEFINED_CONSTANT' in /repo/ch03/php7_undef_const.php on line 6
Program Continues ... 
```

同样的代码现在在 PHP 8 中运行时会产生*致命错误*，如下所示：

```php
PHP Fatal error:  Uncaught Error: Undefined constant "UNDEFINED_CONSTANT" in /repo/ch03/php8_undef_const.php:6
```

因此，在 PHP 8 中，任何未在使用之前首先定义任何常量的糟糕代码都将崩溃和燃烧！一个好习惯是在应用程序代码的开头为所有变量分配默认值。 如果您计划使用常量，最好尽早定义它们，最好在一个地方。

重要提示

一个想法是在一个*包含的文件*中定义所有常量。 如果是这种情况，请确保使用这些常量的任何程序脚本已加载包含常量定义的文件。

提示

**最佳实践**：在程序代码使用之前，为所有变量分配默认值。 确保在使用之前定义任何自定义常量。 如果是这种情况，请确保使用这些常量的任何程序脚本已加载包含常量定义的文件。

## 错误级别默认值

值得注意的是，在 PHP 8 中，`php.ini` 文件 `error_reporting` 指令分配的错误级别默认值已经更新。 在 PHP 7 中，默认的 `error_reporting` 级别如下：

```php
error_reporting=E_ALL & ~E_NOTICE & ~E_STRICT & ~E_DEPRECATED
```

在 PHP 8 中，新级别要简单得多，您可以在这里看到：

```php
error_reporting=E_ALL
```

值得注意的是，`php.ini` 文件设置 `display_startup_errors` 现在默认启用。 这可能会成为生产服务器的问题，因为您的网站可能会在 PHP 启动时意外地显示错误信息。

本节的关键要点是，过去，PHP 允许您通过只发出 `Notices` 或 `Warnings` 来逃脱某些不良实践。 但是，正如您在本节中所学到的，不解决 `Warning` 或 `Notice` 生成背后的问题的危险在于 PHP 在您的代表上悄悄采取的行动。 不依赖 PHP 代表您做决定会减少隐藏的逻辑错误。 遵循良好的编码实践，例如在使用之前为所有变量分配默认值，有助于避免此类错误。 现在让我们更仔细地看看在 PHP 8 中将 `Warnings` 提升为 `Errors` 的错误情况。

# 处理现在是错误的警告

在本节中，我们将研究升级的 PHP 8 错误处理，涉及对象、数组和字符串。我们还将研究过去 PHP 发出“警告”的情况，而在 PHP 8 中现在会抛出“错误”。你必须意识到本节中描述的任何潜在错误情况。原因很简单：如果你没有解决本节描述的情况，当你的服务器升级到 PHP 8 时，你的代码将会出错。

开发人员经常时间紧迫。可能有一大堆新功能或其他必须进行的更改。在其他情况下，资源已经被调走到其他项目，意味着可用于维护的开发人员更少。由于应用程序继续运行，很多开发人员经常忽略“警告”，所以他们只是关闭错误显示，希望一切顺利。

多年来，堆积如山的糟糕代码已经积累起来。不幸的是，PHP 社区现在正在付出代价，以神秘的运行时错误的形式，需要花费数小时来追踪。通过将之前只引发“警告”的某些危险做法提升为“错误”，在 PHP 8 中很快就能显现出糟糕的编码实践，因为“错误”是致命的，会导致应用程序停止运行。

让我们从对象错误处理中的错误提升开始。

重要提示

一般来说，在 PHP 8 中，当尝试*写入*数据时，“警告”会升级为“错误”。另一方面，对于相同的一般情况（例如，尝试读/写不存在对象的属性），在 PHP 8 中，当尝试*读取*数据时，“通知”会升级为“警告”。总体上的理由是，写入尝试可能导致数据的丢失或损坏，而读取尝试则不会。

## 对象错误处理中的警告提升

这里是现在被视为对象处理的“警告”现在变成了“错误”的简要总结。如果你尝试做以下操作，PHP 8 会抛出一个“错误”：

+   增加/减少非对象的属性

+   修改非对象的属性

+   给非对象的属性赋值

+   从空值创建默认对象

让我们看一个简单的例子。在下面的代码片段中，一个值被赋给了一个不存在的对象`$a`。然后对这个值进行了递增：

```php
// /repo/ch03/php8_warn_prop_nobj.php
$a->test = 0;
$a->test++;
var_dump($a);
```

这是 PHP 7 的输出：

```php
PHP Warning:  Creating default object from empty value in /repo/ch03/php8_warn_prop_nobj.php on line 4
class stdClass#1 (1) {
  public $test =>
  int(1)
}
```

正如你所看到的，在 PHP 7 中，一个`stdClass()`实例被默默创建，并发出一个“警告”，但操作是允许继续的。如果我们在 PHP 8 下运行相同的代码，注意这里输出的差异：

```php
PHP Fatal error:  Uncaught Error: Attempt to assign property "test" on null in /repo/ch03/php8_warn_prop_nobj.php:4
```

好消息是在 PHP 8 中，会抛出一个“错误”，这意味着我们可以通过实现一个`try()/catch()`块轻松地捕获它。例如，这里是之前显示的代码可能如何重写的示例：

```php
try {
    $a->test = 0;
    $a->test++;
    var_dump($a);
} catch (Error $e) {
    error_log(__FILE__ . ':' . $e->getMessage());
}
```

正如你所看到的，这三行中的任何问题现在都安全地包裹在一个`try()/catch()`块中，这意味着可以进行恢复。我们现在将注意力转向数组错误处理的增强。

## 数组处理中的警告提升

关于数组的一些不良实践，在 PHP 7 及更早版本中是允许的，现在会抛出一个“错误”。正如前一小节所讨论的，PHP 8 数组错误处理的变化旨在对我们描述的错误情况给出更有力的响应。这些增强的最终目标是推动开发人员朝着良好的编码实践方向发展。

这是数组处理中的警告提升为错误的简要列表：

+   无法将元素添加到数组中，因为下一个元素已经被占用

+   无法取消非数组变量中的偏移量

+   只有`array`和`Traversable`类型可以被解包

+   非法偏移类型

现在让我们逐一检查这个列表中的每个错误条件。

### 下一个元素已经被占用

为了说明一个可能的情况，即下一个数组元素无法被分配，因为它已经被占用，请看这个简单的代码示例：

```php
// ch03/php8_warn_array_occupied.php
$a[PHP_INT_MAX] = 'This is the end!';
$a[] = 'Off the deep end';
```

假设由于某种原因，对一个数组元素进行赋值，其数字键是可能的最大大小的整数（由`PHP_INT_MAX`预定义常量表示）。如果随后尝试给下一个元素赋值，就会出现问题！

在 PHP 7 中运行此代码块的结果如下：

```php
PHP Warning:  Cannot add element to the array as the next element is already occupied in
/repo/ch03/php8_warn_array_occupied.php on line 7
array(1) {
  [9223372036854775807] =>
  string(16) "This is the end!"
}
```

然而，在 PHP 8 中，`Warning`已经升级为`Error`，导致了这样的输出：

```php
PHP Fatal error:  Uncaught Error: Cannot add element to the
array as the next element is already occupied in
/repo/ch03/php8_warn_array_occupied.php:7
```

接下来，我们将注意力转向在非数组变量中使用偏移量的情况。

### 非数组变量中的偏移量

将非数组变量视为数组可能会产生意外结果，但某些实现了`Traversable`（例如`ArrayObject`或`ArrayIterator`）的对象类除外。一个例子是在字符串上使用类似数组的偏移量。

使用数组语法访问字符串字符在某些情况下可能很有用。一个例子是检查**统一资源定位符**（**URL**）是否以逗号或斜杠结尾。在下面的代码示例中，我们检查 URL 是否以斜杠结尾。如果是的话，我们使用`substr()`将其截断：

```php
// ch03/php8_string_access_using_array_syntax.php
$url = 'https://unlikelysource.com/';
if ($url[-1] == '/')
    $url = substr($url, 0, -1);
echo $url;
// returns: "https://unlikelysource.com"
```

在先前显示的示例中，`$url[-1]`数组语法使您可以访问字符串中的最后一个字符。

提示

您还可以使用新的 PHP 8 `str_ends_with()`函数来执行相同的操作！

然而，字符串绝对**不是**数组，也不应该被视为数组。为了避免糟糕的代码可能导致意外结果，PHP 8 中已经限制了使用数组语法引用字符串字符的滥用。

在下面的代码示例中，我们尝试在字符串上使用`unset()`：

```php
// ch03/php8_warn_array_unset.php
$alpha = 'ABCDEF';
unset($alpha[2]);
var_dump($alpha);
```

上面的代码示例实际上会在 PHP 7 和 8 中生成致命错误。同样，不要将非数组（或非`Traversable`对象）用作`foreach()`循环的参数。在接下来显示的示例中，将字符串作为`foreach()`的参数：

```php
// ch03/php8_warn_array_foreach.php
$alpha = 'ABCDEF';
foreach ($alpha as $letter) echo $letter;
echo "Continues ... \n";
```

在 PHP 7 和早期版本中，会生成一个`Warning`，但代码会继续执行。在 PHP 7.1 中运行时的输出如下：

```php
PHP Warning:  Invalid argument supplied for foreach() in /repo/ch03/php8_warn_array_foreach.php on line 6
Continues ... 
```

有趣的是，PHP 8 也允许代码继续执行，但`Warning`消息略有详细，如下所示：

```php
PHP Warning:  foreach() argument must be of type array|object, string given in /repo/ch03/php8_warn_array_foreach.php on line 6
Continues ... 
```

接下来，我们将看看过去可以使用非数组/非`Traversable`类型进行展开的情况。

### 数组展开

看到这个小节标题后，您可能会问：*什么是数组展开？* 就像解引用的概念一样，**展开**数组只是一个从数组中提取值到离散变量的术语。例如，考虑以下简单的代码：

1.  我们首先定义一个简单的函数，用于将两个数字相加，如下所示：

```php
// ch03/php8_array_unpack.php
function add($a, $b) { return $a + $b; }
```

1.  为了说明，假设数据以数字对的形式存在数组中，每个数字对都要相加：

```php
$vals = [ [18,48], [72,99], [11,37] ];
```

1.  在循环中，我们使用可变操作符（`...`）来展开对`add()`函数的调用中的数组对，如下所示：

```php
foreach ($vals as $pair) {
    echo 'The sum of ' . implode(' + ', $pair) . 
         ' is ';
    echo add(...$pair);
}
```

刚才展示的示例演示了开发人员如何使用可变操作符来强制展开。然而，许多 PHP 数组函数在内部执行展开操作。考虑以下示例：

1.  首先，我们定义一个由字母组成的数组。如果我们输出`array_pop()`的返回值，我们会看到输出的是字母`Z`，如下面的代码片段所示：

```php
// ch03/php8_warn_array_unpack.php
$alpha = range('A','Z');
echo array_pop($alpha) . "\n";
```

1.  我们可以使用`implode()`将数组展平为字符串来实现相同的结果，并使用字符串解引用来返回最后一个字母，如下面的代码片段所示：

```php
$alpha = implode('', range('A','Z'));
echo $alpha[-1];
```

1.  然而，如果我们尝试在字符串上使用`array_pop()`，就像这里所示，在 PHP 7 和早期版本中我们会得到一个`Warning`：

`echo array_pop($alpha);`

1.  在 PHP 7.1 下运行时的输出如下：

```php
ZZPHP Warning:  array_pop() expects parameter 1 to be array, string given in /repo/ch03/php8_warn_array_unpack.php on line 14
```

1.  以下是在相同的代码文件下在 PHP 8 下运行时的输出：

```php
ZZPHP Fatal error:  Uncaught TypeError: array_pop(): Argument #1 ($array) must be of type array, string given in /repo/ch03/php8_warn_array_unpack.php:14
```

正如我们已经提到的，这里是另一个例子，以前会导致`Warning`的情况现在在 PHP 8 中导致`TypeError`。然而，这两组输出也说明了，尽管你可以像操作数组一样对字符串进行解引用，但字符串不能以与数组相同的方式进行解包。

接下来，我们来检查非法偏移类型。

### 非法偏移类型

根据 PHP 文档（[`www.php.net/manual/en/language.types.array.php`](https://www.php.net/manual/en/language.types.array.php)），数组是键/值对的有序列表。数组键，也称为**索引**或**偏移**，可以是两种数据类型之一：`integer`或`string`。如果一个数组只包含`integer`键，通常被称为**数字数组**。另一方面，**关联数组**是一个术语，用于使用`string`索引。**非法偏移**是指数组键的数据类型不是`integer`或`string`的情况。

重要提示

有趣的是，以下代码片段不会生成`Warning`或`Error`：`$x = (float) 22/7; $arr[$x] = 'Value of Pi';`。在进行数组赋值之前，变量`$x`的值首先被转换为`integer`，截断任何小数部分。

举个例子，看看这段代码片段。请注意，最后一个数组元素的索引键是一个对象：

```php
// ch03/php8_warn_array_offset.php
$obj = new stdClass();
$b = ['A' => 1, 'B' => 2, $obj => 3];
var_dump($b);
```

在 PHP 7 下运行的输出产生了`Warning`的`var_dump()`输出，如下所示：

```php
PHP Warning:  Illegal offset type in /repo/ch03/php8_warn_array_offset.php on line 6
array(2) {
  'A' =>  int(1)
  'B' =>  int(2)
}
```

然而，在 PHP 8 中，`var_dump()`永远不会被执行，因为会抛出`TypeError`，如下所示：

```php
PHP Fatal error:  Uncaught TypeError: Illegal offset type in /repo/ch03/php8_warn_array_offset.php:6
```

使用`unset()`时，与非法数组偏移相同的原则存在，如下面的代码示例所示：

```php
// ch03/php8_warn_array_offset.php
$obj = new stdClass();
$b = ['A' => 1, 'B' => 2, 'C' => 3];
unset($b[$obj]);
var_dump($b);
```

在使用`empty()`或`isset()`中的非法偏移时，对数组索引键的更严格控制也可以看到，如下面的代码片段所示：

```php
// ch03/php8_warn_array_empty.php
$obj = new stdClass();
$obj->c = 'C';
$b = ['A' => 1, 'B' => 2, 'C' => 3];
$message =(empty($b[$obj])) ? 'NOT FOUND' : 'FOUND';
echo "$message\n";
```

在前面的两个代码示例中，在 PHP 7 及更早版本中，代码示例完成时会产生一个`Warning`，而在 PHP 8 中会抛出一个`Error`。除非捕获到这个`Error`，否则代码示例将无法完成。

提示

**最佳实践**：在初始化数组时，确保数组索引数据类型是`integer`或`string`。

接下来，我们来看一下字符串处理中的错误提升。

## 字符串处理中的提升警告

关于对象和数组的提升警告也适用于 PHP 8 字符串错误处理。在这一小节中，我们将检查两个字符串处理`Warning`提升为`Errors`，如下所示：

+   偏移不包含在字符串中

+   空字符串偏移

+   让我们首先检查不包含在字符串中的偏移。

### 偏移不包含在字符串中。

作为第一种情况的例子，看看下面的代码示例。在这里，我们首先将一个字符串分配给包含所有字母的字符串。然后，我们使用`strpos()`返回字母`Z`的位置，从偏移`0`开始。在下一行，我们做同样的事情；然而，偏移`27`超出了字符串的末尾：

```php
// /repo/ch03/php8_error_str_pos.php
$str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
echo $str[strpos($str, 'Z', 0)];
echo $str[strpos($str, 'Z', 27)];
```

在 PHP 7 中，如预期的那样，返回了`Z`的输出，`strpos()`产生了一个`Warning`，并且产生了一个`Notice`，说明进行了偏移转换（关于这一点，我们将在下一节中详细介绍）。以下是 PHP 7 的输出：

```php
Z
PHP Warning:  strpos(): Offset not contained in string in /repo/ch03/php8_error_str_pos.php on line 7
PHP Notice:  String offset cast occurred in /repo/ch03/php8_error_str_pos.php on line 7
```

然而，在 PHP 8 中，会抛出致命的`ValueError`，如下所示：

```php
Z
PHP Fatal error:  Uncaught ValueError: strpos(): Argument #3 ($offset) must be contained in argument #1 ($haystack) in /repo/ch03/php8_error_str_pos.php:7
```

在这种情况下我们需要传达的关键点是，以前允许这种糟糕的编码保留在一定程度上是可以接受的。然而，在进行 PHP 8 升级后，正如你可以清楚地从输出中看到的那样，你的代码将失败。现在，让我们来看一下空字符串偏移。

### 空字符串偏移错误处理

信不信由你，在 PHP 7 之前的版本中，开发人员可以通过将空值赋给目标偏移来从字符串中删除字符。例如，看看这段代码：

```php
// /repo/ch03/php8_error_str_empty.php
$str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
$str[5] = '';
echo $str . "\n";
```

这个代码示例的目的是从由`$str`表示的字符串中删除字母`F`。令人惊讶的是，在 PHP 5.6 中，你可以从这个截图中看到，尝试是完全成功的：

![图 3.1 - PHP 5.6 输出显示成功删除字符](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_3.1_B16992.jpg)

图 3.1 - PHP 5.6 输出显示成功删除字符

请注意，我们用来演示本书中的代码的虚拟环境允许访问 PHP 7.1 和 PHP 8。为了正确展示 PHP 5 的行为，我们挂载了一个 PHP 5.6 的 Docker 镜像，并对结果进行了截图。

然而，在 PHP 7 中，这种做法是被禁止的，并且会发出一个`Warning`，如下所示：

```php
PHP Warning:  Cannot assign an empty string to a string offset in /repo/ch03/php8_error_str_empty.php on line 5
ABCDEFGHIJKLMNOPQRSTUVWXYZ
```

正如您从前面的输出中所看到的，脚本被允许执行；然而，尝试删除字母`F`是不成功的。在 PHP 8 中，正如我们所讨论的，`Warning`被提升为`Error`，整个脚本中止，如下所示：

```php
PHP Fatal error:  Uncaught Error: Cannot assign an empty string to a string offset in /repo/ch03/php8_error_str_empty.php:5
```

接下来，我们将研究在 PHP 8 中，以前的`Notices`被提升为`Warnings`的情况。

# 理解被提升为警告的通知

有许多情况被认为对 PHP 引擎在运行时的稳定性不太重要，在 PHP 7 之前的版本中被低估了。不幸的是，新的（或者可能是懒惰的！）PHP 开发人员通常会忽略`Notices`，以便匆忙将他们的代码投入生产。

多年来，PHP 标准已经大大收紧，这导致 PHP 核心团队将某些错误条件从`Notice`升级为`Warning`。任何错误报告级别都不会导致代码停止工作。然而，PHP 核心团队认为*Notice-to-Warning*的提升将使糟糕的编程实践变得更加明显。`Warnings`不太可能被忽视，最终会导致更好的代码。

以下是在早期版本的 PHP 中发出`Notice`的一些错误条件的简要列表，在 PHP 8 中，相同的条件现在会生成一个`Warning`：

+   尝试访问不存在的对象属性

+   尝试访问不存在的静态属性

+   尝试使用一个不存在的键来访问数组元素

+   错误地将资源用作数组偏移

+   模棱两可的字符串偏移转换

+   不存在或未初始化的字符串偏移

首先让我们来看一下涉及对象的`Notice`促销活动。

## 不存在的对象属性访问处理

在早期的 PHP 版本中，尝试访问不存在的属性时会发出一个`Notice`。唯一的例外是当它是一个自定义类，你在那里定义了魔术`__get()`和/或`__set()`方法。

在下面的代码示例中，我们定义了一个带有两个属性的`Test`类，其中一个被标记为`static`：

```php
// /repo/ch03/php8_warn_undef_prop.php
class Test {
    public static $stat = 'STATIC';
    public $exists = 'NORMAL';
}
$obj = new Test();
```

然后我们尝试`echo`存在和不存在的属性，如下所示：

```php
echo $obj->exists;
echo $obj->does_not_exist;
```

毫不奇怪，在 PHP 7 中，当尝试访问不存在的属性`echo`时，会返回一个`Notice`，如下所示：

```php
NORMAL
PHP Notice:  Undefined property: Test::$does_not_exist in
/repo/ch03/php8_warn_undef_prop.php on line 14
```

同样的代码文件，在 PHP 8 中，现在返回一个`Warning`，如下所示：

```php
NORMAL
PHP Warning:  Undefined property: Test::$does_not_exist in /repo/ch03/php8_warn_undef_prop.php on line 14
```

重要提示

`Test::$does_not_exist`错误消息并不意味着我们尝试了静态访问。它只是意味着`Test`类关联了一个`$does_not_exist`属性。

现在我们添加了尝试访问不存在的静态属性的代码行，如下所示：

```php
try {
    echo Test::$stat;
    echo Test::$does_not_exist;
} catch (Error $e) {
    echo __LINE__ . ':' . $e;
}
```

有趣的是，PHP 7 和 PHP 8 现在都会发出致命错误，如下所示：

```php
STATIC
22:Error: Access to undeclared static property Test::$does_not_exist in /repo/ch03/php8_warn_undef_prop.php:20
```

任何以前发出`Warning`的代码块现在发出`Error`都是值得关注的。如果可能的话，扫描你的代码，查找对静态类属性的静态引用，并确保它们被定义。否则，在 PHP 8 升级后，你的代码将失败。

现在让我们来看一下不存在的偏移处理。

## 不存在的偏移处理

如前一节所述，一般来说，在读取数据的地方，`Notices`已经被提升为`Warnings`，而在写入数据的地方，`Warnings`已经被提升为`Errors`（并且可能导致*丢失*数据）。不存在的偏移处理遵循这个逻辑。

在下面的例子中，一个数组键是从一个字符串中提取出来的。在这两种情况下，偏移量都不存在：

```php
// /repo/ch03/php8_warn_undef_array_key.php
$key  = 'ABCDEF';
$vals = ['A' => 111, 'B' => 222, 'C' => 333];
echo $vals[$key[6]];
```

在 PHP 7 中，结果是一个`Notice`，如下所示：

```php
PHP Notice:  Uninitialized string offset: 6 in /repo/ch03/php8_warn_undef_array_key.php on line 6
PHP Notice:  Undefined index:  in /repo/ch03/php8_warn_undef_array_key.php on line 6
```

在 PHP 8 中，结果是一个`Warning`，如下所示：

```php
PHP Warning:  Uninitialized string offset 6 in /repo/ch03/php8_warn_undef_array_key.php on line 6
PHP Warning:  Undefined array key "" in /repo/ch03/php8_warn_undef_array_key.php on line 6
```

这个例子进一步说明了 PHP 8 错误处理增强的一般原理：如果你的代码*写入*数据到一个不存在的偏移，以前是一个`警告`在 PHP 8 中是一个`错误`。前面的输出显示了在 PHP 8 中尝试*读取*不存在偏移的数据时，现在会发出一个`警告`。下一个要检查的`通知`提升涉及滥用资源 ID。

## 滥用资源 ID 作为数组偏移

当创建到应用程序代码外部的服务的连接时，会生成一个**资源**。这种数据类型的一个典型例子是文件句柄。在下面的代码示例中，我们打开了一个文件句柄（从而创建了`资源`）到一个`gettysburg.txt`文件：

```php
// /repo/ch03/php8_warn_resource_offset.php
$fn = __DIR__ . '/../sample_data/gettysburg.txt';
$fh = fopen($fn, 'r');
echo $fh . "\n";
```

请注意，我们在最后一行直接输出了`资源`。这显示了资源 ID 号。然而，如果我们现在尝试使用资源 ID 作为数组偏移，PHP 7 会生成一个`通知`，如下所示：

```php
Resource id #5
PHP Notice:  Resource ID#5 used as offset, casting to integer (5) in /repo/ch03/php8_warn_resource_offset.php on line 9
```

如预期的那样，PHP 8 生成了一个`警告`，如下所示：

```php
Resource id #5
PHP Warning:  Resource ID#5 used as offset, casting to integer (5) in /repo/ch03/php8_warn_resource_offset.php on line 9
```

请注意，在 PHP 8 中，许多以前生成`资源`的函数现在生成对象。这个主题在*第七章**，避免在使用 PHP 8 扩展时陷阱*中有所涉及。

提示

**最佳实践**：不要使用资源 ID 作为数组偏移！

现在我们将注意力转向与模糊的字符串偏移相关的`通知`在模糊的字符串偏移的情况下提升为`警告`。

## 模糊的字符串偏移转换

将注意力转向字符串处理，我们再次回顾使用数组语法在字符串中识别单个字符的想法。如果 PHP 必须执行内部类型转换以评估字符串偏移，但在这种类型转换中并不清楚，就可能发生**模糊的字符串偏移转换**。

在这个非常简单的例子中，我们定义了一个包含字母表中所有字母的字符串。然后我们用这些值定义了一个键的数组：`NULL`；一个布尔值，`TRUE`；和一个浮点数，`22/7`（*Pi*的近似值）。然后我们循环遍历这些键，并尝试将键用作字符串偏移，如下所示：

```php
// /repo/ch03/php8_warn_amb_offset.php
$str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
$ptr = [ NULL, TRUE, 22/7 ];
foreach ($ptr as $key) {
    var_dump($key);
    echo $str[$key];
}
```

正如你可能预料的那样，在 PHP 7 中运行的输出产生了输出`A`，`B`和`D`，以及一系列的`通知`，如下所示：

```php
NULL
PHP Notice:  String offset cast occurred in /repo/ch03/php8_warn_amb_offset.php on line 8
A
/repo/ch03/php8_warn_amb_offset.php:7:
bool(true)
PHP Notice:  String offset cast occurred in /repo/ch03/php8_warn_amb_offset.php on line 8
B
/repo/ch03/php8_warn_amb_offset.php:7:
double(3.1428571428571)
PHP Notice:  String offset cast occurred in /repo/ch03/php8_warn_amb_offset.php on line 8
D
```

PHP 8 始终产生相同的结果，但在这里，一个`警告`取代了`通知`：

```php
NULL
PHP Warning:  String offset cast occurred in /repo/ch03/php8_warn_amb_offset.php on line 8
A
bool(true)
PHP Warning:  String offset cast occurred in /repo/ch03/php8_warn_amb_offset.php on line 8
B
float(3.142857142857143)
PHP Warning:  String offset cast occurred in /repo/ch03/php8_warn_amb_offset.php on line 8
D
```

现在让我们来看看不存在偏移的处理。

## 未初始化或不存在的字符串偏移

这种类型的错误旨在捕获使用偏移访问字符串的情况，其中偏移超出了边界。下面是一个非常简单的代码示例，说明了这种情况：

```php
// /repo/ch03/php8_warn_un_init_offset.php
$str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
echo $str[27];
```

在 PHP 7 中运行这段代码会产生一个`通知`。以下是 PHP 7 的输出：

```php
PHP Notice:  Uninitialized string offset: 27 in /repo/ch03/php8_warn_un_init_offset.php on line 5
```

可以预见的是，PHP 8 的输出产生了一个`警告`，如下所示：

```php
PHP Warning:  Uninitialized string offset 27 in /repo/ch03/php8_warn_un_init_offset.php on line 5
```

本节中的所有示例都证实了 PHP 8 朝着强制执行最佳编码实践的一般趋势。

提示

有关推广的“通知”和“警告”的更多信息，请查看这篇文章：[`wiki.php.net/rfc/engine_warnings`](https://wiki.php.net/rfc/engine_warnings)。

现在，我们将注意力转向（臭名昭著的）`@`警告抑制器。

# 处理@错误控制运算符

多年来，许多 PHP 开发人员一直使用`@`**错误控制运算符**来掩盖错误。当使用编写不良的 PHP 库时，这一点尤为真实。不幸的是，这种用法的净效果只会传播糟糕的代码！

许多 PHP 开发人员都在进行“一厢情愿的思考”，他们认为当他们使用`@`运算符来阻止错误显示时，问题似乎神奇地消失了！相信我，当我说这个时候：*并没有！*在这一部分，我们首先研究了`@`运算符的传统用法，之后我们研究了 PHP 8 中的`@`运算符的变化。

提示

有关传统`@`操作符的语法和用法的更多信息，请参阅此文档参考页面：[`www.php.net/manual/en/language.operators.errorcontrol.php`](https://www.php.net/manual/en/language.operators.errorcontrol.php)。

## @操作符用法

在呈现代码示例之前，再次强调非常重要的一点是我们**不**推广使用这种机制！相反，你应该在任何情况下避免使用它。如果出现错误消息，最好的解决方案是*修复错误*，而不是将其消音！

在下面的代码示例中，定义了两个函数。`bad()`函数故意触发错误。`worse()`函数包含一个文件，其中存在解析错误。请注意，当调用这些函数时，`@`符号在函数名之前，导致错误输出被抑制：

```php
// /repo/ch03/php8_at_silencer.php
function bad() {
    trigger_error(__FUNCTION__, E_USER_ERROR);
}
function worse() {
    return include __DIR__ .  '/includes/
                               causes_parse_error.php';
}
echo @bad();
echo @worse();
echo "\nLast Line\n";
```

在 PHP 7 中，根本没有输出，如下所示：

```php
root@php8_tips_php7 [ /repo/ch03 ]# php php8_at_silencer.php 
root@php8_tips_php7 [ /repo/ch03 ]# 
```

有趣的是，在 PHP 7 中程序实际上是不允许继续执行的：我们从未看到`Last Line`的输出。这是因为，尽管被掩盖了，但仍然生成了一个致命错误，导致程序失败。然而，在 PHP 8 中，致命错误没有被掩盖，如下所示：

```php
root@php8_tips_php8 [ /repo/ch03 ]# php8 php8_at_silencer.php 
PHP Fatal error:  bad in /repo/ch03/php8_at_silencer.php on line 5
```

现在让我们来看一下 PHP 8 中关于`@`操作符的另一个不同之处。

## @操作符和 error_reporting()

`error_reporting()`函数通常用于覆盖`php.ini`文件中设置的`error_reporting`指令。然而，这个函数的另一个用途是返回最新的错误代码。然而，在 PHP 8 之前的版本中存在一个奇怪的例外，即如果使用了`@`操作符，`error_reporting()`返回值为`0`。

在下面的代码示例中，我们定义了一个错误处理程序，当它被调用时报告接收到的错误编号和字符串。此外，我们还显示了`error_reporting()`返回的值：

```php
// /repo/ch03/php8_at_silencer_err_rep.php
function handler(int $errno , string $errstr) {
    $report = error_reporting();
    echo 'Error Reporting : ' . $report . "\n";
    echo 'Error Number    : ' . $errno . "\n";
    echo 'Error String    : ' . $errstr . "\n";
    if (error_reporting() == 0) {
        echo "IF statement works!\n";
    }
}
```

与以前一样，我们定义了一个`bad()`函数，故意触发错误，然后使用`@`操作符调用该函数，如下所示：

```php
function bad() {
    trigger_error('We Be Bad', E_USER_ERROR);
}
set_error_handler('handler');
echo @bad();
```

在 PHP 7 中，你会注意到`error_reporting()`返回`0`，因此导致`IF statement works!`出现在输出中，如下所示：

```php
root@root@php8_tips_php7 [ /repo/ch03 ] #
php php8_at_silencer_err_rep.php
Error Reporting : 0
Error Number    : 256
Error String    : We Be Bad
IF statement works!
```

另一方面，在 PHP 8 中运行，`error_reporting()`返回最后一个错误的值——在这种情况下是`4437`。当然，`if()`表达式失败，导致没有额外的输出。以下是在 PHP 8 中运行相同代码的结果：

```php
root@php8_tips_php8 [ /repo/ch03 ] #
php php8_at_silencer_err_rep.php
Error Reporting : 4437
Error Number    : 256
Error String    : We Be Bad
```

这结束了对 PHP 8 中`@`操作符用法的考虑。

提示

**最佳实践**：不要使用`@`错误控制操作符！`@`操作符的目的是抑制错误消息的显示，但你需要考虑为什么这个错误消息首先出现。通过使用`@`操作符，你只是避免提供问题的解决方案！

# 总结

在本章中，你了解了 PHP 8 中错误处理的重大变化概述。你还看到了可能出现错误条件的情况示例，并且现在知道如何正确地管理 PHP 8 中的错误。你现在有了一个坚实的路径，可以重构在 PHP 8 下现在产生错误的代码。如果你的代码可能导致任何前述的条件，其中以前的“警告”现在是“错误”，你就有可能使你的代码崩溃。

同样地，虽然过去描述的第二组错误条件只会产生“通知”，但现在这些相同的条件会引发“警告”。新的一组“警告”给了你一个机会来调整错误的代码，防止你的应用程序陷入严重的不稳定状态。

最后，你学会了强烈不推荐使用`@`操作符。在 PHP 8 中，这种语法将不再掩盖致命错误。在下一章中，你将学习如何在 PHP 8 中创建 C 语言结构并直接调用 C 语言函数。


# 第四章：进行直接的 C 语言调用

本章介绍了**外部函数接口**（FFI）。在本章中，您将了解 FFI 的全部内容，它的作用以及如何使用它。本章的信息对于对使用直接 C 语言调用进行快速自定义原型设计感兴趣的开发人员非常重要。

在本章中，您不仅了解了将 FFI 引入 PHP 语言背后的背景，还学会了如何直接将 C 语言结构和函数合并到您的代码中。尽管——正如您将了解的那样——这并不是为了实现更快的速度，但它确实使您能够直接将任何 C 语言库合并到您的 PHP 应用程序中。这种能力为 PHP 打开了一个以前无法实现的功能世界。

本章涵盖的主题包括以下内容：

+   理解 FFI

+   学会何时使用 FFI

+   检查 FFI 类

+   在应用程序中使用 FFI

+   使用 PHP 回调函数

# 技术要求

为了检查和运行本章提供的代码示例，以下是最低推荐的硬件要求：

+   基于 X86_64 的台式 PC 或笔记本电脑

+   1 千兆字节（GB）的可用磁盘空间

+   4 GB 的随机存取内存（RAM）

+   500 千位每秒（Kbps）或更快的互联网连接

此外，您需要安装以下软件：

+   Docker

+   Docker Compose

请参考*第一章*的*技术要求*部分，了解有关 Docker 和 Docker Compose 安装的更多信息，以及如何构建用于演示本书中代码的 Docker 容器。在本书中，我们将恢复示例代码的目录称为`/repo`。

本章的源代码位于此处：

https://github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices

现在我们可以开始讨论 FFI 的理解。

# 理解 FFI

FFI 的主要目的是允许任何给定的编程语言能够将来自其他语言编写的外部库的代码和函数调用合并到其中。早期的一个例子是 20 世纪 80 年代微型计算机能够使用`PEEK`和`POKE`命令将汇编语言合并到否则笨拙的**通用符号指令代码**（BASIC）编程语言脚本中。与许多其他语言不同，PHP 在 PHP 7.4 之前没有这种能力，尽管自 2004 年以来一直在讨论中。

为了全面了解 PHP 8 中的 FFI，有必要偏离一下，看看为什么 FFI 在 PHP 语言中被完全采用花了这么长时间。还有必要快速了解一下 PHP 扩展，以及与 C 语言代码的工作能力。我们首先研究 PHP 和 C 语言之间的关系。

## PHP 和 C 语言之间的关系

**C 语言**是由丹尼斯·里奇在 1972 年末在贝尔实验室开发的。自那时起，尽管引入了其面向对象的表亲 C++，这种语言仍然主导着编程语言领域。PHP 本身是用 C 编写的；因此，直接加载 C 共享库并直接访问 C 函数和数据结构的能力对于 PHP 语言来说是一个非常重要的补充。

将 FFI 扩展引入 PHP 语言使 PHP 能够加载并直接使用 C 结构和 C 函数。为了能够明智地决定何时何地使用 FFI 扩展，让我们先看一下一般的 PHP 扩展。

## 理解 PHP 扩展

**PHP 扩展**，顾名思义，*扩展*了 PHP 语言。每个扩展都可以添加**面向对象编程**（**OOP**）类以及过程级函数。每个扩展都有一个独特的逻辑目的，例如，`GD`扩展处理图形图像处理，而`PDO`扩展处理数据库访问。

类比一下，考虑一家医院。在医院里，您有急诊、外科、儿科、骨科、心脏科、X 光等科室。每个科室都是独立的，有着不同的目的。这些科室共同构成了医院。同样地，PHP 就像医院，它的扩展就像各种科室。

并非所有扩展都是相同的。一些扩展，称为**核心扩展**，在安装 PHP 时始终可用。其他扩展必须手动下载、编译和启用。现在让我们来看看核心扩展。

### 访问 PHP 核心扩展

PHP 核心扩展直接包含在主 PHP 源代码存储库中，位于此处：https://github.com/php/php-src/tree/master/ext。如果您转到此网页，您将看到一个子目录列表，如下面的屏幕截图所示。每个子目录包含特定扩展的 C 语言代码：

![图 4.1-在 GitHub 上看到的 PHP 核心扩展](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_4.1_B16992.jpg)

图 4.1-在 GitHub 上看到的 PHP 核心扩展

因此，当 PHP 安装在服务器上时，所有核心扩展都会被编译和安装。现在我们来简要看看不属于核心的扩展。

### 检查非核心 PHP 扩展

不属于核心的 PHP 扩展通常由特定供应商（**Microsoft**就是一个例子）维护。非核心扩展通常被认为是可选的，并且使用不广泛。

一旦非核心扩展开始被越来越频繁地使用，它很可能最终会被迁移到核心中。这方面的例子很多。最近的一个是`JSON`扩展：它现在不仅是核心的一部分，而且在 PHP 8 中这个扩展不能再被禁用。

核心扩展也可能被移除。其中一个例子是`mcrypt`扩展。这在 PHP 7.1 中被弃用，因为该扩展依赖的基础库已经*被遗弃*了 9 年以上。在 PHP 7.2 中，它正式从核心中移除。现在我们考虑在哪里找到非核心扩展。

### 查找非核心扩展

在这一点上，您可能会问一个合乎逻辑的问题：*您从哪里获取非核心扩展？*一般来说，非核心扩展可以直接从供应商、[github.com](http://github.com)或此网站：http://pecl.php.net/获取。多年来一直有人抱怨[pecl.php.net](http://pecl.php.net)包含过时和未维护的代码。尽管这在一定程度上是真的，但同样也存在最新的、积极维护的代码在这个网站上。

例如，如果您查看 MongoDB 的 PHP 扩展，您会发现最新版本是在 2020 年 11 月底发布的。以下屏幕截图显示了此扩展的**PHP 扩展社区库**（**PECL**）网站页面：

![图 4.2-用于 PHP MongoDB 扩展的 pecl.php.net 页面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_4.2_B16992.jpg)

图 4.2-用于 PHP MongoDB 扩展的 pecl.php.net 页面

在许多情况下，供应商更倾向于保留对扩展的完全控制。这意味着您需要去他们的网站获取 PHP 扩展。一个例子是 Microsoft SQL Server 的 PHP 扩展，可以在此**统一资源定位符**（**URL**）找到：https://docs.microsoft.com/en-us/sql/connect/php/download-drivers-php-sql-server?view=sql-server-ver15.

本小节的关键要点是，PHP 语言通过其扩展进行增强。这些扩展是用 C 语言编写的。因此，在 PHP 脚本中直接建模原型扩展的逻辑能力非常重要。现在让我们把注意力转向应该在哪里使用 FFI。

# 学习何时使用 FFI

直接将 C 库导入到 PHP 中的潜力真是令人震惊。PHP 核心开发人员中的一位实际上使用 FFI 扩展将 PHP 绑定到 C 语言**TensorFlow**机器学习平台！

提示

有关 TensorFlow 机器学习平台的信息，请访问此网页：https://www.tensorflow.org/。要了解 PHP 如何与此库绑定，请查看这里：[`github.com/dstogov/php-tensorflow`](https://github.com/dstogov/php-tensorflow)。

正如我们在本节中所展示的，FFI 扩展并不是解决所有需求的神奇解决方案。本节讨论了 FFI 扩展的主要优势和劣势，并为您提供了使用指南。我们在本节中揭穿的一个神话是，使用 FFI 扩展直接调用 C 语言来加速 PHP 8 程序执行。首先，让我们看看将 FFI 扩展纳入 PHP 中花费了这么长时间。

## 将 FFI 引入 PHP

实际上，第一个 FFI 扩展是由 PHP 核心开发人员**Wez Furlong**和**Ilia Alshanetsky**于 2004 年 1 月在 PECL 网站（https://pecl.php.net/）上为 PHP 5 引入的。然而，该项目从未通过 Alpha 阶段，并在一个月内停止了开发。

随着 PHP 在接下来的 14 年中的发展和成熟，人们开始意识到 PHP 将受益于在 PHP 脚本中快速原型化潜在扩展的能力。如果没有这种能力，PHP 有可能落后于其他语言，比如 Python 和 Ruby。

过去，由于缺乏快速原型能力，扩展开发人员被迫在能够在 PHP 脚本中测试之前编译完整的扩展并使用`pecl`安装它。在某些情况下，开发人员甚至不得不*重新编译 PHP 本身*来测试他们的新扩展！相比之下，FFI 扩展允许开发人员*直接在*PHP 脚本中放置 C 函数调用以进行即时测试。

从 PHP 7.4 开始，并持续到 PHP 8，核心开发人员 Dmitry Stogov 提出了改进版本的 FFI 扩展。在令人信服的概念验证之后（请参阅有关 PHP 绑定到 TensorFlow 机器学习平台的前面的*提示*框），这个 FFI 扩展版本被纳入了 PHP 语言中。

提示

原始的 FFI PHP 扩展可以在这里找到：http://pecl.php.net/package/ffi。有关修订后的 FFI 提案的更多信息，请参阅以下文章：https://wiki.php.net/rfc/ffi。

现在让我们来看看为什么不应该使用 FFI 来提高速度。

## 不要使用 FFI 来提高速度

因为 FFI 扩展允许 PHP 直接访问 C 语言库，人们很容易相信你的 PHP 应用程序会突然以机器语言速度运行得非常快。不幸的是，事实并非如此。FFI 扩展需要首先打开给定的 C 库，然后在执行之前解析和伪编译`FFI`实例。然后 FFI 扩展充当 C 库代码和 PHP 脚本之间的桥梁。

对一些读者来说，相对缓慢的 FFI 扩展性能不仅限于 PHP 8。其他语言在使用自己的 FFI 实现时也会遇到相同的限制效果。这里有一个基于*Ary 3 基准*的优秀性能比较，可以在这里找到：https://wiki.php.net/rfc/ffi#php_ffi_performance。

如果您查看刚刚引用的网页上显示的表格，您会发现 Python FFI 实现在 0.343 秒内完成了基准测试，而仅使用本机 Python 代码运行相同的基准测试只需 0.212 秒。

查看相同的表，PHP 7.4 FFI 扩展在 0.093 秒内运行了基准测试（比 Python 快 30 倍！），而仅使用本机 PHP 代码运行的相同基准测试在 0.040 秒内执行。

下一个逻辑问题是：*为什么你应该使用 FFI 扩展？* 这将在下一节中介绍。

## 为什么要使用 FFI 扩展？

对上一个问题的答案很简单：这个扩展主要是为了快速**PHP 扩展原型**。PHP 扩展是语言的命脉。没有扩展，PHP 只是*另一种编程语言*。

当高级开发人员首次着手进行编程项目时，他们需要确定项目的最佳语言。一个关键因素是可用的扩展数量以及这些扩展的活跃程度。通常，活跃维护的扩展数量与使用该语言的项目的长期成功潜力之间存在直接关系。

因此，如果有一种方法可以加快扩展开发的速度，那么 PHP 语言本身的长期可行性就得到了改善。FFI 扩展为 PHP 语言带来的价值在于，它能够在不必经历整个编译-链接-加载-测试周期的情况下，直接在 PHP 脚本中测试扩展原型。

FFI 扩展的另一个用例，除了快速原型设计之外，是允许 PHP 直接访问模糊或专有的 C 代码的一种方式。一个例子是编写用于控制工厂机器的自定义 C 代码。为了让 PHP 运行工厂，可以使用 FFI 扩展将 PHP 直接绑定到控制各种机器的 C 库。

最后，这个扩展的另一个用例是用它来*预加载* C 库，可能会减少内存消耗。在我们展示使用示例之前，让我们来看看`FFI`类及其方法。

# 检查 FFI 类

正如您在本章中所学到的，不是每个开发人员都需要使用 FFI 扩展。直接使用 FFI 扩展可以加深您对 PHP 语言内部的理解，这种加深的理解对您作为 PHP 开发人员的职业生涯可能会产生积极影响：很可能在将来的某个时候，您将被一家开发了自定义 PHP 扩展的公司雇佣。在这种情况下，了解如何操作 FFI 扩展可以让您为自定义 PHP 扩展开发新功能，同时帮助您解决扩展问题。

`FFI`类包括 20 个方法，分为四个广泛的类别，如下所述：

+   **创建性**：此类别中的方法创建了 FFI 扩展**应用程序编程接口**（**API**）中可用的类的实例。

+   **比较**：比较方法旨在比较 C 数据值。

+   **信息性**：这组方法为您提供有关 C 数据值的元数据，包括大小和*对齐*。

+   **基础设施**：基础设施方法用于执行后勤操作，如复制、填充和释放内存。

提示

完整的 FFI 类文档在这里：[`www.php.net/manual/en/class.ffi.php`](https://www.php.net/manual/en/class.ffi.php)。

有趣的是，所有`FFI`类方法都可以以静态方式调用。现在是时候深入了解与 FFI 相关的类的细节和用法了，首先是*创建性*方法。

## 使用 FFI 创建方法

属于*创建*类别的 FFI 方法旨在直接产生`FFI`实例或 FFI 扩展提供的类的实例。在使用 FFI 扩展提供的 C 函数时，重要的是要认识到不能直接将本地的 PHP 变量传递给函数并期望它能工作。数据必须首先被创建为`FFI`数据类型或导入到`FFI`数据类型中，然后才能将`FFI`数据类型传递给 C 函数。要创建`FFI`数据类型，请使用下面总结的函数之一，如下所示：

![表 4.1 – FFI 类创建方法总结](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Table_4.1_B16992.jpg)

表 4.1 – FFI 类创建方法总结

`cdef()`和`scope()`方法都会产生一个直接的`FFI`实例，而其他方法会产生可以用来创建`FFI`实例的对象实例。`string()`用于从本地 C 变量中提取给定数量的字节。让我们来看看如何创建和使用`FFI\CType`实例。

### 创建和使用 FFI\CType 实例

非常重要的一点是，一旦创建了`FFI\CType`实例，*不要*简单地将一个值赋给它，就像它是一个本地的 PHP 变量一样。这样做只会由于 PHP 是弱类型语言而简单地覆盖`FFI\CType`实例。相反，要将标量值赋给`FFI\CType`实例，使用它的`cdata`属性。

下面的例子创建了一个`$arr` C 数组。然后用值填充本地 C 数组，直到达到最大大小，之后我们使用一个简单的`var_dump()`来查看它的内容。我们将按照以下步骤进行：

1.  首先，我们使用`FFI::arrayType()`来创建数组。作为参数，我们提供了一个`FFI::type()`方法和维度。然后我们使用`FFI::new()`来创建`FFI\Ctype`实例。代码如下所示：

```php
// /repo/ch04/php8_ffi_array.php
$type = FFI::arrayType(FFI::type("char"), [3, 3]);
$arr  = FFI::new($type);
```

1.  或者，我们也可以将操作合并成一个单一的语句，如下所示：

`$arr = FFI::new(FFI::type("char[3][3]"));`

1.  然后我们初始化了三个提供测试数据的变量，如下面的代码片段所示。请注意，本地的 PHP`count()`函数适用于`FFI\CData`数组类型：

```php
$pos   = 0;
$val   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
$y_max = count($arr);
```

1.  现在我们可以用值填充它，就像用 PHP 数组一样，只是我们需要使用`cdata`属性来保留元素作为`FFI\CType`实例。代码如下所示：

```php
for ($y = 0; $y < $y_max; $y++) {
    $x_max = count($arr[$y]);
    for ($x = 0; $x < $x_max; $x++) {
        $arr[$y][$x]->cdata = $val[$pos++];
    }
}
var_dump($arr)
```

在前面的例子中，我们使用嵌套的`for()`循环来填充二维的 3 x 3 数组，用字母表的字母。如果我们现在执行一个简单的`var_dump()`，我们会得到以下结果：

```php
root@php8_tips_php8 [ /repo/ch04 ]# php 
php8_ffi_array.php 
object(FFI\CData:char[3][3])#2 (3) {
  [0]=> object(FFI\CData:char[3])#3 (3) {
    [0]=> string(1) "A"
    [1]=> string(1) "B"
    [2]=> string(1) "C"
  }
  [1]=> object(FFI\CData:char[3])#1 (3) {
    [0]=> string(1) "D"
    [1]=> string(1) "E"
    [2]=> string(1) "F"
  }
  [2]=> object(FFI\CData:char[3])#4 (3) {
    [0]=> string(1) "G"
    [1]=> string(1) "H"
    [2]=> string(1) "I"
}
```

从输出中要注意的第一件重要的事情是，索引都是整数。从输出中得到的第二个要点是，这显然不是一个本地的 PHP 数组。`var_dump()`告诉我们，每个数组元素都是一个`FFI\CData`实例。还要注意的是，C 语言字符串被视为数组。

因为数组的类型是`char`，我们可以使用`FFI::string()`来显示其中一行。下面是一个产生*ABC*响应的命令：

`echo FFI::string($arr[0], 3);`

任何尝试将`FFI\CData`实例提供给一个以数组作为参数的 PHP 函数都注定失败，即使它被定义为数组类型。在下面的代码片段中，注意如果我们将这个命令添加到前面的代码块中的输出：

`echo implode(',', $arr);`

从下面的输出中可以看到，因为数据类型不是`array`，`implode()`会发出致命错误。以下是结果输出：

```php
PHP Fatal error:  Uncaught TypeError: implode(): Argument #2 ($array) must be of type ?array, FFI\CData given in /repo/ch04/php8_ffi_array.php:25
```

现在你知道如何创建和使用`FFI\CType`实例了。现在让我们转向创建`FFI`实例。

### 创建和使用 FFI 实例

如章节介绍中所述，FFI 扩展有助于快速原型设计。因此，使用 FFI 扩展，你可以逐个开发设计用于新扩展的 C 函数，并立即在 PHP 应用程序中进行测试。

重要提示

FFI 扩展不会编译 C 代码。为了在 FFI 扩展中使用 C 函数，您必须首先使用 C 编译器将 C 代码编译成共享库。您将在本章的最后一节“在应用程序中使用 FFI”中学习如何做到这一点。

为了在 PHP 和本地 C 库函数调用之间建立桥梁，您需要创建一个`FFI`实例。FFI 扩展需要您提供一个定义了 C 函数签名和您计划使用的 C 库的 C 定义。`FFI::cdef()`和`FFI::scope()`都可以直接创建`FFI`实例。

以下示例使用`FFI::cdef()`绑定了两个本地 C 库函数。具体操作如下：

1.  第一个本地方法`srand()`用于初始化随机化序列。另一个本地 C 函数`rand()`调用序列中的下一个数字。`$key`变量保存了随机化的最终产品。`$size`表示要调用的随机数的数量。代码如下所示：

```php
// /repo/ch04/php8_ffi_cdef.php
$key  = '';
$size = 4;
```

1.  然后，我们通过调用`cdef()`并在字符串`$code`中标识本地 C 函数来创建`FFI`实例，该字符串取自`libc.so.6`本地 C 库，如下所示：

```php
$code = <<<EOT
    void srand (unsigned int seed);
    int rand (void);
EOT;
$ffi = FFI::cdef($code, 'libc.so.6');
```

1.  然后我们通过调用`srand()`来初始化随机化。然后，在循环中，我们调用`rand()`本地 C 库函数来生成一个随机数。我们使用`sprintf()`本地 PHP 函数将生成的整数转换为十六进制，然后将其附加到`$key`，并将其输出。代码如下所示：

```php
$ffi->srand(random_int(0, 999));
for ($x = 0; $x < $size; $x++)
    $key .= sprintf('%x', $ffi->rand());
echo $key
```

以下是前面代码片段的输出。请注意，生成的值可以用作随机密钥：

```php
root@php8_tips_php8 [ /repo/ch04 ]# php php8_ffi_cdef.php
23f306d51227432e7d8d921763b7eedf
```

在输出中，您会看到一串连接的随机整数转换为十六进制的字符串。请注意，每次调用脚本时，结果值都会发生变化。

提示

对于真正的随机化，最好只使用`random_int()`本地 PHP 函数。`openssl`扩展中还有出色的密钥生成函数。这里展示的示例主要是为了让您熟悉 FFI 扩展的用法。

重要提示

FFI 扩展还包括两种额外的创建方法：`FFI::load()`和`FFI::scope()`。`FFI::load()`用于在**预加载**过程中直接从 C 头文件（`*.h`）加载 C 函数定义。`FFI::scope()`使预加载的 C 函数可通过 FFI 扩展使用。有关预加载的更多信息，请查看 FFI 文档中的完整预加载示例：[`www.php.net/manual/en/ffi.examples-complete.php`](https://www.php.net/manual/en/ffi.examples-complete.php)。

现在让我们来看看用于比较本地 C 数据类型的 FFI 扩展函数。

## 使用 FFI 比较数据

请记住，使用 FFI 扩展创建 C 语言数据结构时，它存在于 PHP 应用程序之外。正如您在前面的示例中看到的（请参阅*创建和使用 FFI\CType 实例*部分），PHP 可以在一定程度上与 C 数据交互。但是，为了比较目的，最好使用`FFI::memcmp()`，因为本地 PHP 函数可能返回不一致的结果。

FFI 扩展中提供的两个比较函数在*表 4.2*中总结如下：

![表 4.2 – FFI 类比较方法总结](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Table_4.2_B16992.jpg)

表 4.2 – FFI 类比较方法总结

`FFI::isNull()`可用于确定`FFI\CData`实例是否为`NULL`。更有趣的是`FFI::memcmp()`。虽然这个函数的操作方式与**太空船操作符**（`<=>`）相同，但它接受一个*第三个参数*，表示您希望在比较中包含多少字节。以下示例说明了这种用法：

1.  首先定义一组代表`FFI\CData`实例的四个变量，这些实例可以包含多达六个字符，并使用示例数据填充这些实例，如下所示：

```php
// /repo/ch04/php8_ffi_memcmp.php
$a = FFI::new("char[6]");
$b = FFI::new("char[6]");
$c = FFI::new("char[6]");
$d = FFI::new("char[6]");
```

1.  请记住，C 语言将字符数据视为数组，因此即使使用`cdata`属性，我们也不能直接分配字符串。因此，我们需要定义一个匿名函数，用字母填充实例。我们使用以下代码来实现这一点：

```php
$populate = function ($cdata, $start, $offset, $num) {
    for ($x = 0; $x < $num; $x++)
        $cdata[$x + $offset] = chr($x + $offset + 
                                   $start);
    return $cdata;
};
```

1.  接下来，我们使用该函数将四个`FFI\CData`实例填充为不同的字母集，如下所示：

```php
$a = $populate($a, 65, 0, 6);
$b = $populate($b, 65, 0, 3);
$b = $populate($b, 85, 3, 3);
$c = $populate($c, 71, 0, 6);
$d = $populate($d, 71, 0, 6);
```

1.  现在我们可以使用`FFI::string()`方法来显示到目前为止的内容，如下所示：

```php
$patt = "%2s : %6s\n";
printf($patt, '$a', FFI::string($a, 6));
printf($patt, '$b', FFI::string($b, 6));
printf($patt, '$c', FFI::string($c, 6));
printf($patt, '$d', FFI::string($d, 6));
```

1.  这是`printf()`语句的输出：

```php
$a : ABCDEF
$b : ABCXYZ
$c : GHIJKL
$d : GHIJKL
```

1.  从输出中可以看出，`$c`和`$d`的值是相同的。`$a`和`$b`的前三个字符相同，但最后三个字符不同。

1.  此时，如果我们尝试使用太空船操作符（`<=>`）进行比较，结果将如下：

```php
PHP Fatal error:  Uncaught FFI\Exception: Comparison of incompatible C types
```

1.  同样，尝试使用`strcmp()`，即使数据是字符类型，结果如下：

```php
PHP Warning:  strcmp() expects parameter 1 to be string, object given
```

1.  因此，我们唯一的选择是使用`FFI::memcmp()`。在这组比较中，注意第三个参数是`6`，表示 PHP 应该比较最多六个字符：

```php
$p = "%20s : %2d\n";
printf($p, 'memcmp($a, $b, 6)', FFI::memcmp($a, 
        $b, 6));
printf($p, 'memcmp($c, $a, 6)', FFI::memcmp($c, 
        $a, 6));
printf($p, 'memcmp($c, $d, 6)', FFI::memcmp($c, 
        $d, 6));
```

1.  如预期的那样，输出与在原生 PHP 字符串上使用太空船操作符的输出相同，如下所示：

```php
   memcmp($a, $b, 6) : -1
   memcmp($c, $a, 6) :  1
   memcmp($c, $d, 6) :  0
```

1.  请注意，如果将比较限制为仅三个字符，会发生什么。这是添加到代码块中的另一个`FFI::memcmp()`比较，将第三个参数设置为`3`：

```php
echo "\nUsing FFI::memcmp() but not full length\n";
printf($p, 'memcmp($a, $b, 3)', FFI::memcmp($a, 
        $b, 3));
```

1.  从这里显示的输出中可以看出，通过将`memcmp()`限制为仅三个字符，`$a`和`$b`被视为相等，因为它们都以相同的三个字符`a`、`b`和`c`开头：

```php
Using FFI::memcmp() but not full length
   memcmp($a, $b, 3) :  0
```

从这个例子中最重要的是，您需要在要比较的字符数和要比较的数据性质之间找到平衡。比较的字符数越少，整体操作速度越快。然而，如果数据的性质可能导致错误的结果，您必须增加字符数，并在性能上稍微损失。

现在让我们来看看如何从 FFI 扩展数据中收集信息。

### 从 FFI 扩展数据中提取信息

当您使用`FFI`实例和原生 C 数据结构时，原生 PHP 信息方法（如`strlen()`和`ctype_digit()`）无法提供有用的信息。因此，FFI 扩展包括三种方法，旨在生成有关 FFI 扩展数据的信息。这三种方法在*表 4.3*中总结如下：

![表 4.3 - FFI 类信息方法总结](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Table_4.3_B16992.jpg)

表 4.3 - FFI 类信息方法总结

首先我们看看`FFI::typeof()`，然后再深入了解其他两种方法。

### 使用 FFI::typeof()确定 FFI 数据的性质

这是一个示例，说明了如何使用`FFI::typeof()`。该示例还演示了处理 FFI 数据时，原生 PHP 信息函数无法产生有用的结果。我们这样做：

1.  首先，我们定义一个`$char` C 字符串，并用字母表的前六个字母填充它，如下所示：

```php
// /repo/ch04/php8_ffi_typeof.php
$char = FFI::new("char[6]");
for ($x = 0; $x < 6; $x++)
    $char[$x] = chr(65 + $x);
```

1.  然后我们尝试使用`strlen()`来获取字符串的长度。在下面的代码片段中，请注意使用`$t::class`：这相当于`get_class($t)`。此用法仅适用于 PHP 8 及以上版本：

```php
try {
    echo 'Length of $char is ' . strlen($char);
} catch (Throwable $t) {
    echo $t::class . ':' . $t->getMessage();
}
```

1.  在 PHP 7.4 中的结果是一个`Warning`消息。然而，在 PHP 8 中，如果将除字符串以外的任何内容传递给`strlen()`，将抛出致命的`Error`消息。这是此时的 PHP 8 输出：

```php
TypeError:strlen(): Argument #1 ($str) must be of type string, FFI\CData given
```

1.  类似地，尝试使用`ctype_alnum()`，如下所示：

```php
echo '$char is ' .
    ((ctype_alnum($char)) ? 'alpha' : 'non-alpha');
```

1.  以下是在*步骤 4*中显示的`echo`命令的输出：

```php
$char is non-alpha
```

1.  显然，我们无法使用原生 PHP 函数获取有关 FFI 数据的有用信息！然而，使用`FFI::typeof()`，如下所示，会返回更好的结果：

```php
$type = FFI::typeOf($char);
var_dump($type);
```

1.  这是`var_dump()`的输出：

```php
object(FFI\CType:char[6])#3 (0) {}
```

从最终输出中可以看出，我们现在有了有用的信息！现在让我们来看看另外两种 FFI 信息方法。

### 利用 FFI::alignof()和 FFI::sizeof()

在进入展示这两种方法的实际示例之前，重要的是要理解**对齐**的确切含义。为了理解对齐，您需要对大多数计算机中内存的组织方式有基本的了解。

RAM 仍然是在程序运行周期内临时存储信息的最快方式。您计算机的**中央处理单元**（**CPU**）在程序执行时将信息从内存中移入和移出。内存以并行数组的形式组织。`alignof()`返回的对齐值将是可以一次从对齐内存数组的并行切片中获取多少字节。在旧计算机中，值为 4 是典型的。对于大多数现代微型计算机，常见的值为 8 或 16（或更大）。

现在让我们来看一个示例，说明了这两种 FFI 扩展信息方法的使用以及这些信息如何产生性能改进。我们将按照以下步骤进行：

1.  首先，我们创建一个`FFI`实例`$ffi`，在其中定义了两个标记为`Good`和`Bad`的 C 结构。请注意，在下面的代码片段中，这两个结构具有相同的属性；然而，这些属性的排列顺序不同。

```php
$struct = 'struct Bad { char c; double d; int i; }; '
        . 'struct Good { double d; int i; char c; }; 
          ';
$ffi = FFI::cdef($struct);
```

1.  然后我们从`$ffi`中提取这两个结构，如下所示：

```php
$bad = $ffi->new("struct Bad");
$good = $ffi->new("struct Good");
var_dump($bad, $good);
```

1.  `var_dump()`输出如下所示：

```php
object(FFI\CData:struct Bad)#2 (3) {
  ["c"]=> string(1) ""
  ["d"]=> float(0)
  ["i"]=> int(0)
}
object(FFI\CData:struct Good)#3 (3) {
  ["d"]=> float(0)
  ["i"]=> int(0)
  ["c"]=> string(1) ""
}
```

1.  然后我们使用这两个信息方法来报告这两个数据结构，如下所示：

```php
echo "\nBad Alignment:\t" . FFI::alignof($bad);
echo "\nBad Size:\t" . FFI::sizeof($bad);
echo "\nGood Alignment:\t" . FFI::alignof($good);
echo "\nGood Size:\t" . FFI::sizeof($good);
```

这个代码示例的最后四行输出如下所示：

```php
Bad Alignment:  8
Bad Size:       24
Good Alignment: 8
Good Size:      16
```

从输出中可以看出，`FFI::alignof()`的返回告诉我们对齐块的宽度为 8 字节。然而，您还可以看到，`Bad`结构占用的字节数比`Good`结构所需的空间大 50%。由于这两个数据结构具有完全相同的属性，任何理智的开发人员都会选择`Good`结构。

从这个例子中，您可以看到 FFI 扩展信息方法能够让我们了解如何最有效地构造我们的 C 数据。

提示

关于 C 语言中`sizeof()`和`alignof()`的区别的出色讨论，请参阅这篇文章：https://stackoverflow.com/questions/11386946/whats-the-difference-between-sizeof-and-alignof。

现在您已经了解了 FFI 扩展信息方法是什么，并且已经看到了它们的使用示例。现在让我们来看看与基础设施相关的 FFI 扩展方法。

## 使用 FFI 基础设施方法

FFI 扩展基础类别方法可以被视为支持 C 函数绑定所需的*幕后*组件。正如我们在本章中一直强调的那样，如果您希望直接从 PHP 应用程序中访问 C 数据结构，则需要 FFI 扩展。因此，如果您需要执行类似于 PHP `unset()`语句以释放内存，或者 PHP `include()`语句以包含外部程序代码，FFI 扩展基础方法提供了本地 C 数据和 PHP 之间的桥梁。

*表 4.4*，如下所示，总结了这个类别中的方法：

![表 4.4 – FFI 类基础方法](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Table_4.4_B16992.jpg)

表 4.4 – FFI 类基础方法

首先，让我们先看看`FFI::addr()`、`free()`、`memset()`和`memcpy()`。

### 使用 FFI::addr()、free()、memset()和 memcpy()

PHP 开发人员经常通过**引用**给变量赋值。这允许一个变量的更改自动反映在另一个变量中。当传递参数给需要返回多个值的函数或方法时，引用的使用尤其有用。通过引用传递允许函数或方法返回无限数量的值。

`FFI::addr()`方法创建一个指向现有`FFI\CData`实例的 C 指针。就像 PHP 引用一样，对指针关联的数据所做的任何更改也将被更改。

在使用`FFI::addr()`方法构建示例的过程中，我们还向您介绍了`FFI::memset()`。这个函数很像`str_repeat()`PHP 函数，因为它（`FFI::memset()`）用特定值填充指定数量的字节。在这个例子中，我们使用`FFI::memset()`来用字母表的字母填充 C 字符字符串。

在本小节中，我们还将介绍`FFI::memcpy()`。这个函数用于将数据从一个`FFI\CData`实例复制到另一个实例。与`FFI::addr()`方法不同，`FFI::memcpy()`创建一个克隆，与复制数据源没有任何连接。此外，我们介绍了`FFI::free()`，这是一个用于释放使用`FFI::addr()`创建的指针的方法。

让我们看看这些 FFI 扩展方法如何使用，如下所示：

1.  首先，创建一个`FFI\CData`实例`$arr`，由六个字符的 C 字符串组成。请注意，在下面的代码片段中，使用了`FFI::memset()`，另一个基础设施方法，用**美国信息交换标准代码**（**ASCII**）码 65：字母`A`填充字符串：

```php
// /repo/ch04/php8_ffi_addr_free_memset_memcpy.php
$size = 6;
$arr  = FFI::new(FFI::type("char[$size]"));
FFI::memset($arr, 65, $size);
echo FFI::string($arr, $size);
```

1.  使用`FFI::string()`方法的`echo`结果如下所示：

```php
AAAAAA
```

1.  从输出中可以看到，出现了六个 ASCII 码 65（字母`A`）的实例。然后我们创建另一个`FFI\CData`实例`$arr2`，并使用`FFI::memcpy()`将一个实例中的六个字符复制到另一个实例中，如下所示：

```php
$arr2  = FFI::new(FFI::type("char[$size]"));
FFI::memcpy($arr2, $arr, $size);
echo FFI::string($arr2, $size);
```

1.  毫不奇怪，输出与*步骤 2*中的输出完全相同，如下所示：

```php
AAAAAA
```

1.  接下来，我们创建一个指向`$arr`的 C 指针。请注意，当指针被赋值时，它们会出现在本机 PHP `var_dump()`函数中作为数组元素。然后我们可以改变数组元素`0`的值，并使用`FFI::memset()`将其填充为字母`B`。代码如下所示：

```php
$ref = FFI::addr($arr);
FFI::memset($ref[0], 66, 6);
echo FFI::string($arr, $size);
var_dump($ref, $arr, $arr2);
```

1.  以下是*步骤 5*中剩余代码的输出：

```php
BBBBBB
object(FFI\CData:char(*)[6])#2 (1) {
  [0]=>   object(FFI\CData:char[6])#4 (6) {
    [0]=>  string(1) "B"
    [1]=>  string(1) "B"
    [2]=>  string(1) "B"
    [3]=>  string(1) "B"
    [4]=>  string(1) "B"
    [5]=>  string(1) "B"
  }
}
object(FFI\CData:char[6])#3 (6) {
  [0]=>  string(1) "B"
  [1]=>  string(1) "B"
  [2]=>  string(1) "B"
  [3]=>  string(1) "B"
  [4]=>  string(1) "B"
  [5]=>  string(1) "B"
}
object(FFI\CData:char[6])#4 (6) {
  [0]=>  string(1) "A"
  [1]=>  string(1) "A"
  [2]=>  string(1) "A"
  [3]=>  string(1) "A"
  [4]=>  string(1) "A"
  [5]=>  string(1) "A"
}
```

从输出中可以看到，我们首先有一个`BBBBBB`字符串。您可以看到指针的形式是一个 PHP 数组。原始的`FFI\CData`实例`$arr`现在已经改变为字母`B`。然而，前面的输出也清楚地显示了复制的`$arr2`不受对`$arr`或其`$ref[0]`指针所做的更改的影响。

1.  最后，为了释放使用`FFI::addr()`创建的指针，我们使用`FFI::free()`。这个方法很像本机 PHP 的`unset()`函数，但是设计用于处理 C 指针。这是我们添加到示例的最后一行代码：

`FFI::free($ref);`

现在您已经了解了如何使用 C 指针以及如何使用信息填充 C 数据，让我们看看如何使用`FFI\CData`实例进行类型转换。

### 学习关于 FFI::cast()

在 PHP 中，**类型转换**的过程经常发生。当 PHP 被要求执行涉及不同数据类型的操作时，就会使用它。下面是一个经典的例子：

```php
$a = 123;
$b = "456";
echo $a + $b;
```

在这个微不足道的例子中，`$a`被分配了`int`（整数）的数据类型，`$b`被分配了`string`的类型。`echo`语句要求 PHP 首先将`$b`强制转换为`int`，执行加法，然后将结果强制转换为`string`。

本机 PHP 还允许开发人员通过在变量或表达式前面的括号中添加所需的数据类型来强制数据类型。从前面代码片段的重写示例可能如下所示：

```php
$a = 123;
$b = "456";
echo (string) ($a + (int) $b);
```

强制类型转换使您的意图对其他使用您代码的开发人员非常清晰。它还保证了结果，因为强制类型转换对代码流的控制更大，并且不依赖于 PHP 的默认行为。

FFI 扩展具有类似的功能，即`FFI::cast()`方法。正如您在本章中看到的，FFI 扩展数据与 PHP 隔离，并且不受 PHP 类型转换的影响。为了强制数据类型，您可以使用`FFI::cast()`返回所需的并行`FFI\CData`类型。让我们看看如何在以下步骤中做到这一点：

1.  在这个例子中，我们创建了一个`int`类型的`FFI\CData`实例`$int1`。我们使用它的`cdata`属性来赋值`123`，如下所示：

```php
// /repo/ch04/php8_ffi_cast.php
// not all lines are shown
$patt = "%2d : %16s\n";
$int1 = FFI::new("int");
$int1->cdata = 123;
$bool = FFI::cast(FFI::type("bool"), $int1);
printf($patt, __LINE__, (string) $int1->cdata);
printf($patt, __LINE__, (string) $bool->cdata);
```

1.  正如您从这里显示的输出中看到的，将`123`的整数值强制转换为`bool`（布尔值），在输出中显示为`1`：

```php
 8 :                  123
 9 :                    1
```

1.  接下来，我们创建了一个`int`类型的`FFI\CData`实例`$int2`，并赋值`123`。然后我们将其强制转换为`float`，再转回`int`，如下面的代码片段所示：

```php
$int2 = FFI::new("int");
$int2->cdata = 123;
$float1 = FFI::cast(FFI::type("float"), $int2);
$int3   = FFI::cast(FFI::type("int"), $float1);
printf($patt, __LINE__, (string) $int2->cdata);
printf($patt, __LINE__, (string) $float1->cdata);
printf($patt, __LINE__, (string) $int3->cdata);
```

1.  最后三行的输出非常令人满意。我们看到我们的原始值`123`被表示为`1.7235971111195E-43`。当强制转换回`int`时，我们的原始值被恢复。以下是最后三行的输出：

```php
15 :                 123
16 : 1.7235971111195E-43
17 :                 123
```

1.  FFI 扩展与 C 语言一般一样，不允许所有类型进行转换。例如，在上一段代码中，我们尝试将类型为`float`的`FFI\CData`实例`$float2`强制转换为`char`类型，如下所示：

```php
try {
    $float2 = FFI::new("float");
    $float2->cdata = 22/7;
    $char1   = FFI::cast(FFI::type("char[20]"), 
        $float2);
    printf($patt, __LINE__, (string) $float2->cdata);
    printf($patt, __LINE__, (string) $char1->cdata);
} catch (Throwable $t) {
    echo get_class($t) . ':' . $t->getMessage();
}
```

1.  结果是灾难性的！正如您从这里显示的输出中看到的，抛出了一个`FFI\Exception`：

```php
FFI\Exception:attempt to cast to larger type
```

在本节中，我们介绍了一系列 FFI 扩展方法，这些方法创建了 FFI 扩展对象实例，比较值，收集信息，并处理所创建的 C 数据基础设施。您了解到有一些 FFI 扩展方法在本机 PHP 语言中具有相同的功能。在下一节中，我们将回顾一个实际的例子，将一个 C 函数库整合到 PHP 脚本中，使用 FFI 扩展。

# 在应用程序中使用 FFI

任何共享的 C 库（通常具有`*.so`扩展名）都可以使用 FFI 扩展包含在 PHP 应用程序中。如果您计划使用任何核心 PHP 库或在安装 PHP 扩展时生成的库，重要的是要注意您有能力修改 PHP 语言本身的行为。

在我们研究它是如何工作之前，让我们首先看看如何将外部 C 库整合到 PHP 脚本中，使用 FFI 扩展。

## 将外部 C 库整合到 PHP 脚本中

为了举例说明，我们使用了一个简单的函数，可能源自**计算机科学 101**（**CS101**）课程：著名的**冒泡排序**。这个算法在初学者的计算机科学课程中被广泛使用，因为它很容易理解。

重要提示

**冒泡排序**是一种极其低效的排序算法，长期以来一直被更快的排序算法（如**希尔排序**、**快速排序**或**归并排序**算法）所取代。虽然没有冒泡排序算法的权威参考，但您可以在这里阅读到一个很好的一般讨论：[`en.wikipedia.org/wiki/Bubble_sort`](https://en.wikipedia.org/wiki/Bubble_sort)。

在这个小节中，我们不会详细介绍算法。相反，这个小节的目的是演示如何将现有的 C 库并入到 PHP 脚本中的一个函数。我们现在向您展示原始的 C 源代码，如何将其转换为共享库，最后如何使用 FFI 将库整合到 PHP 中。我们将做以下事情：

1.  当然，第一步是将 C 代码编译为对象代码。以下是本例中使用的冒泡排序 C 代码：

```php
#include <stdio.h>
void bubble_sort(int [], int);
void bubble_sort(int list[], int n) {
    int c, d, t, p;
    for (c = 0 ; c < n - 1; c++) {
        p = 0;
        for (d = 0 ; d < n - c - 1; d++) {
            if (list[d] > list[d+1]) {
                t = list[d];
                list[d] = list[d+1];
                list[d+1] = t;
                p++;
            }
        }
        if (p == 0) break;
    }
}
```

1.  然后，我们使用 GNU C 编译器（包含在本课程使用的 Docker 镜像中）将 C 代码编译为对象代码，如下所示：

`gcc -c -Wall -Werror -fpic bubble.c`

1.  接下来，我们将对象代码合并到一个共享库中。这一步是必要的，因为 FFI 扩展只能访问共享库。我们运行以下代码来完成这一步：

`gcc -shared -o libbubble.so bubble.o`

1.  现在我们准备定义使用我们新共享库的 PHP 脚本。我们首先定义一个函数，该函数显示来自`FFI\CData`数组的输出，如下所示：

```php
// /repo/ch04/php8_ffi_using_func_from_lib.php
function show($label, $arr, $max) 
{
    $output = $label . "\n";
    for ($x = 0; $x < $max; $x++)
        $output .= $arr[$x] . ',';
    return substr($output, 0, -1) . "\n";
}
```

1.  接下来是关键部分：定义`FFI`实例。我们使用`FFI::cdef()`来完成这个任务，并提供两个参数。第一个参数是函数签名，第二个参数是我们新创建的共享库的路径。这两个参数都可以在以下代码片段中看到：

```php
$bubble = FFI::cdef(
    "void bubble_sort(int [], int);",
    "./libbubble.so");
```

1.  然后，我们创建了一个`FFI\CData`元素，作为一个包含 16 个随机整数的整数数组，使用`rand()`函数进行填充。代码如下所示：

```php
$max   = 16;
$arr_b = FFI::new('int[' . $max . ']');
for ($i = 0; $i < $max; $i++)
    $arr_b[$i]->cdata = rand(0,9999);
```

1.  最后，我们显示了排序之前数组的内容，执行了排序，并显示了排序后的内容。请注意，在以下代码片段中，我们使用`FFI`实例调用`bubble_sort()`来执行排序：

```php
echo show('Before Sort', $arr_b, $max);
$bubble->bubble_sort($arr_b, $max);
echo show('After Sort', $arr_b, $max);
```

1.  输出，正如您所期望的那样，在排序之前显示了一组随机整数。排序后，数值是有序的。以下是*步骤 7*中代码的输出：

```php
Before Sort
245,8405,8580,7586,9416,3524,8577,4713,
9591,1248,798,6656,9064,9846,2803,304
After Sort
245,304,798,1248,2803,3524,4713,6656,7586,
8405,8577,8580,9064,9416,9591,9846
```

既然您已经了解了如何使用 FFI 扩展将外部 C 库集成到 PHP 应用程序中，我们转向最后一个主题：PHP 回调。

## 使用 PHP 回调

正如我们在本节开头提到的，可以使用 FFI 扩展来整合实际 PHP 语言（或其扩展）中的共享 C 库。这种整合很重要，因为它允许您通过访问 PHP 共享 C 库中定义的 C 数据结构来读取和写入本机 PHP 数据。

然而，本小节的目的并不是向您展示如何创建 PHP 扩展。相反，在本小节中，我们向您介绍了 FFI 扩展覆盖本机 PHP 语言功能的能力。这种能力被称为**PHP 回调**。在我们深入实现细节之前，我们必须首先检查与这种能力相关的潜在危险。

### 理解 PHP 回调的潜在危险

重要的是要理解，PHP 共享库中定义的 C 函数通常被多个 PHP 函数使用。因此，如果您在 C 级别覆盖了其中一个低级函数，您可能会在 PHP 应用程序中遇到意外行为。

另一个已知问题是，覆盖本机 PHP C 函数很有可能会产生**内存泄漏**。随着时间的推移，使用这种覆盖的长时间运行的应用程序可能会失败，并且有可能导致服务器崩溃！

最后要考虑的是，PHP 回调功能并非在所有 FFI 平台上都受支持。因此，尽管代码可能在 Linux 服务器上运行，但在 Windows 服务器上可能无法运行（或可能无法以相同的方式运行）。

提示

与其使用 FFI PHP 回调来覆盖本机 PHP C 库功能，也许更容易、更快速、更安全的方法是只定义自己的 PHP 函数！

既然您已经了解了使用 PHP 回调涉及的危险，让我们来看一个示例实现。

### 实现 PHP 回调

在下面的示例中，使用回调覆盖了`zend_write`内部 PHP 共享库的 C 函数，该回调在输出末尾添加了**换行符**（**LF**）。请注意，此覆盖会影响任何依赖它的本机 PHP 函数，包括`echo`、`print`、`printf`：换句话说，任何产生直接输出的 PHP 函数。要实现 PHP 回调，请按照以下步骤进行：

1.  首先，我们使用`FFI::cdef()`定义了一个`FFI`实例。第一个参数是`zend_write`的函数签名。代码如下所示：

```php
// /repo/ch04/php8_php_callbacks.php
$zend = FFI::cdef("
    typedef int (*zend_write_func_t)(
        const char *str,size_t str_length);
    extern zend_write_func_t zend_write;
");
```

1.  然后，我们添加了代码来确认未经修改的`echo`不会在末尾添加额外的换行符。您可以在这里看到代码：

```php
echo "Original echo command does not output LF:\n";
echo 'A','B','C';
echo 'Next line';
```

1.  毫不奇怪，输出产生了`ABCNext line`。输出中没有回车或换行符，如下所示：

```php
Original echo command does not output LF:
ABCNext line
```

1.  然后，我们将指向`zend_write`的指针克隆到`$orig_zend_write`变量中。如果我们不这样做，我们将无法使用原始函数！代码如下所示：

$orig_zend_write = clone $zend->zend_write;

1.  接下来，我们以匿名函数的形式生成一个 PHP 回调，覆盖原始的`zend_write`函数。在函数中，我们调用原始的`zend_write`函数并在其输出中添加一个 LF，如下所示：

```php
$zend->zend_write = function($str, $len) {
    global $orig_zend_write;
    $ret = $orig_zend_write($str, $len);
    $orig_zend_write("\n", 1);
    return $ret;
};
```

1.  剩下的代码重新运行了前面步骤中显示的`echo`命令，如下所示：

```php
echo 'Revised echo command adds LF:';
echo 'A','B','C';
```

1.  以下输出演示了 PHP `echo` 命令现在在每个命令的末尾产生一个 LF：

```php
Revised echo command adds LF:
A
B
C
```

还要注意的是，修改 PHP 库 C 语言`zend_write`函数会影响使用这个 C 语言函数的所有 PHP 本机函数。这包括`print()`，`printf()`（及其变体）等。

这结束了我们对在 PHP 应用程序中使用 FFI 扩展的讨论。您现在知道如何将外部共享库中的本机 C 函数整合到 PHP 中。您还知道如何用 PHP 回调替换本机 PHP 核心或扩展共享库，从而有可能改变 PHP 语言本身的行为。

# 总结

在本章中，您了解了 FFI 及其历史，以及如何使用它来促进快速的 PHP 扩展原型设计。您还了解到，虽然 FFI 扩展不应该用于提高速度，但它也可以让您的 PHP 应用程序直接调用外部 C 库的本机 C 函数。这种能力的强大之处通过一个调用外部 C 库的冒泡排序函数的示例得到了展示。这种能力也可以扩展到包括机器学习、光学字符识别、通信、加密等成千上万个 C 库，*无穷无尽*。

在本章中，您将更深入地了解 PHP 本身在 C 语言级别的运行方式。您将学习如何创建并直接使用 C 语言数据结构，使您能够与 PHP 语言本身进行交互，甚至覆盖 PHP 语言本身。此外，您现在已经知道如何将任何 C 语言库的功能直接整合到 PHP 应用程序中。这种知识的另一个好处是，如果您找到一家计划开发自己的自定义 PHP 扩展或已经开发了自定义 PHP 扩展的公司，它将有助于增强您的职业前景。

下一章标志着书的新部分*PHP 8 技巧*的开始。在下一节中，您将学习升级到 PHP 8 时的向后兼容性问题。下一章具体讨论了面向对象编程方面的向后兼容性问题。


# 第二部分：PHP 8 的技巧

在这一部分，您将进入 PHP 8 的黑暗角落：那些存在向后兼容性破坏的地方。本部分将指导您完成将现有应用程序迁移到 PHP 8 的关键过程。

本节包括以下章节：

+   第五章，发现潜在的面向对象编程向后兼容性破坏

+   第六章，理解 PHP 8 的功能差异

+   第七章，使用 PHP 8 扩展时避免陷阱

+   第八章，了解 PHP 8 的已弃用或移除功能


# 第五章：发现潜在的面向对象编程向后兼容性问题

本章标志着本书第 2 部分*PHP 8 技巧*的开始。在这一部分，您将发现 PHP 8 的黑暗角落：**向后兼容性问题**存在的地方。本部分将让您了解如何在将现有应用程序迁移到 PHP 8 之前避免问题。您将学会如何查找现有代码中可能导致其在 PHP 8 升级后停止工作的问题。一旦掌握了本书这一部分介绍的主题，您将能够很好地修改现有代码，使其在 PHP 8 升级后继续正常运行。

在本章中，您将介绍与**面向对象编程（OOP）**相关的新的 PHP 8 特性。本章提供了大量清晰说明新特性和概念的简短代码示例。本章对帮助您快速利用 PHP 8 的强大功能至关重要，因为您可以将代码示例调整为自己的实践。本章的重点是在 PHP 8 迁移后，面向对象的代码可能会出现问题的情况。

本章涵盖的主题包括以下内容：

+   发现核心面向对象编程的差异

+   导航魔术方法的更改

+   控制序列化

+   理解扩展的 PHP 8 变异支持

+   处理**标准 PHP 库**（**SPL**）的更改

# 技术要求

要查看和运行本章提供的代码示例，建议的最低硬件要求如下：

+   基于 x86_64 的台式 PC 或笔记本电脑

+   1 千兆字节(GB)的可用磁盘空间

+   4GB 的 RAM

+   每秒 500 千位(Kbps)或更快的互联网连接

此外，您需要安装以下软件：

+   Docker

+   Docker Compose

有关 Docker 和 Docker Compose 的安装以及如何构建用于演示本书中解释的代码的 Docker 容器的更多信息，请参阅*第一章*的*技术要求*部分，*介绍新的 PHP 8 面向对象编程特性*。在本书中，我们将您为本书恢复的示例代码的目录称为`/repo`。

本章的源代码位于此处：https://github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices。

我们现在可以开始讨论核心面向对象编程的差异。

# 发现核心面向对象编程的差异

在 PHP 8 中，您可以以不同的方式编写面向对象的代码。在本节中，我们重点关注可能会导致潜在向后兼容性问题的三个关键领域。本节我们将讨论与进行静态方法调用、处理对象属性和 PHP 自动加载相关的常见不良实践。

阅读本节并完成示例后，您将更好地发现面向对象的不良实践，并了解 PHP 8 如何对此类用法进行限制。在本章中，您将学习良好的编码实践，这将最终使您成为更好的程序员。您还将能够解决 PHP 自动加载中的更改，这可能会导致迁移到 PHP 8 的应用程序失败。

让我们首先看看 PHP 8 如何加强静态调用。

## 在 PHP 8 中处理静态调用

令人惊讶的是，PHP 7 及以下版本允许开发人员对未声明为`static`的类方法进行静态调用。乍一看，任何未来审查您代码的开发人员立即会假设该方法已被定义为`static`。这可能会导致意外行为，因为未来的开发人员在错误的假设下开始误用您的代码。

在这个简单的例子中，我们定义了一个带有`nonStatic()`方法的`Test`类。在类定义后的程序代码中，我们输出了这个方法的返回值，然而，在这样做时，我们进行了一个静态调用：

```php
// /repo/ch05/php8_oop_diff_static.php
class Test {
    public function notStatic() {
        return __CLASS__ . PHP_EOL;
    }
}
echo Test::notStatic();
```

当我们在 PHP 7 中运行此代码时，结果如下：

```php
root@php8_tips_php7 [ /repo/ch05 ]# 
php php8_oop_diff_static.php
PHP Deprecated:  Non-static method Test::notStatic() should not be called statically in /repo/ch05/php8_oop_diff_static.php on line 11
Test
```

从输出中可以看出，PHP 7 会发出弃用通知，但允许调用！然而，在 PHP 8 中，结果是致命的`Error`，如下所示：

```php
root@php8_tips_php8 [ /repo/ch05 ]#
php php8_oop_diff_static.php
PHP Fatal error:  Uncaught Error: Non-static method Test::notStatic() cannot be called statically in /repo/ch05/php8_oop_diff_static.php:11
```

使用静态方法调用非静态方法的语法是一种不良实践，因为良好编写的代码使代码开发人员的意图变得清晰明了。如果您没有将方法定义为静态，但后来以静态方式调用它，未来负责维护您代码的开发人员可能会感到困惑，并可能对代码的原始意图做出错误的假设。最终结果将是更糟糕的代码！

在 PHP 8 中，您不能再使用静态方法调用非静态方法。现在让我们再看看另一个涉及将对象属性视为键的不良实践。

## 处理对象属性处理的变化

数组一直是 PHP 的一个核心特性，一直延续到最早的版本。另一方面，面向对象编程直到 PHP 4 才被引入。在面向对象编程的早期，数组函数经常被扩展以适应对象属性。这导致对象和数组之间的区别变得模糊，从而产生了一些不良实践。

为了保持数组处理和对象处理之间的清晰分离，PHP 8 现在限制`array_key_exists()`函数只接受数组作为参数。为了说明这一点，考虑以下示例：

1.  首先，我们定义一个带有单个属性的简单匿名类：

```php
// /repo/ch05/php8_oop_diff_array_key_exists.php
$obj = new class () { public $var = 'OK.'; };
```

1.  然后我们运行三个测试，分别使用`isset()`、`property_exists()`和`array_key_exists()`来检查`$var`的存在：

```php
// not all code is shown
$default = 'DEFAULT';
echo (isset($obj->var)) 
    ? $obj->var : $default;
echo (property_exists($obj,'var')) 
    ? $obj->var : $default;
echo (array_key_exists('var',$obj)) 
    ? $obj->var : $default;
```

当我们在 PHP 7 中运行这段代码时，所有测试都成功，如下所示：

```php
root@php8_tips_php7 [ /repo/ch05 ]# 
php php8_oop_diff_array_key_exists.php
OK.OK.OK.
```

然而，在 PHP 8 中，会发生致命的`TypeError`，因为`array_key_exists()`现在只接受数组作为参数。PHP 8 的输出如下所示：

```php
root@php8_tips_php8 [ /repo/ch05 ]# 
php php8_oop_diff_array_key_exists.php
OK.OK.PHP Fatal error:  Uncaught TypeError: array_key_exists(): Argument #2 ($array) must be of type array, class@anonymous given in /repo/ch05/php8_oop_diff_array_key_exists.php:10
```

最佳实践是使用`property_exists()`或`isset()`。现在我们将注意力转向 PHP 自动加载的变化。

## 使用 PHP 8 自动加载

在 PHP 8 中首次引入的基本**自动加载**类机制与 PHP 8 中的工作方式相同。主要区别在于，全局函数`__autoload()`在 PHP 7.2 中已弃用，并在 PHP 8 中已完全删除。从 PHP 7.2 开始，开发人员被鼓励使用`spl_autoload_register()`注册其自动加载逻辑，该函数自 PHP 5.1 起可用于此目的。另一个主要区别是如果无法注册自动加载程序，`spl_autoload_register()`的反应方式。

了解使用`spl_autoload_register()`时自动加载过程的工作原理对于作为开发人员的工作至关重要。不理解 PHP 如何自动定位和加载类将限制您作为开发人员的能力，并可能对您的职业道路产生不利影响。

在深入研究`spl_autoload_register()`之前，让我们先看一下`__autoload()`函数。

### 理解 __autoload()函数

`__autoload()`函数被许多开发人员用作自动加载逻辑的主要来源。这个函数的行为方式类似于*魔术方法*，这就是为什么它根据上下文自动调用。会触发自动调用`__autoload()`函数的情况包括创建新类实例时，但类定义尚未加载的时刻。此外，如果类扩展另一个类，则还会调用自动加载逻辑，以便在创建扩展它的子类之前加载超类。

使用`__autoload()`函数的优点是它非常容易定义，并且通常在网站的初始`index.php`文件中定义。缺点包括以下内容：

+   `__autoload()`是一个 PHP 过程函数；不是使用面向对象编程原则定义或控制的。例如，在为应用程序定义单元测试时，这可能会成为一个问题。

+   如果你的应用程序使用命名空间，`__autoload()`函数必须在全局命名空间中定义；否则，在定义`__autoload()`函数的命名空间之外的类将无法加载。

+   `__autoload()`函数与`spl_autoload_register()`不兼容。如果你同时使用`__autoload()`函数和`spl_autoload_register()`定义自动加载逻辑，`__autoload()`函数的逻辑将被完全忽略。

为了说明潜在的问题，我们将定义一个`OopBreakScan`类，更详细地讨论在*第十一章**，将现有的 PHP 应用迁移到 PHP 8*中：

1.  首先，我们定义并添加一个方法到`OopBreakScan`类中，该方法扫描文件内容以查找`__autoload()`函数。请注意，错误消息是在`Base`类中定义的一个类常量，只是警告存在`__autoload()`函数：

```php
namespace Migration;
class OopBreakScan extends Base {
    public static function scanMagicAutoloadFunction(
        string $contents, array &$message) : bool {
        $found  = 0;
        $found += (stripos($contents, 
            'function __autoload(') !== FALSE);
        $message[] = ($found)
                   ? Base::ERR_MAGIC_AUTOLOAD
                   : sprintf(Base::OK_PASSED,
                       __FUNCTION__);
        return (bool) $found;
    }
    // remaining methods not shown
```

这个类扩展了一个`Migration\Base`类（未显示）。这很重要，因为任何自动加载逻辑都需要找到子类和它的超类。

1.  接下来，我们定义一个调用程序，在其中定义了一个魔术`__autoload()`函数：

```php
// /repo/ch05/php7_autoload_function.php
function __autoLoad($class) {
    $fn = __DIR__ . '/../src/'
        . str_replace('\\', '/', $class)
        . '.php';
    require_once $fn;
}
```

1.  然后我们通过让调用程序扫描自身来使用这个类：

```php
use Migration\OopBreakScan;
$contents = file_get_contents(__FILE__);
$message  = [];
OopBreakScan::
    scanMagicAutoloadFunction($contents, $message);
var_dump($message);
```

以下是在 PHP 7 中运行的输出：

```php
root@php8_tips_php7 [ /repo/ch05 ]# 
php php7_autoload_function.php
/repo/ch05/php7_autoload_function.php:23:
array(1) {
  [0] =>  string(96) "WARNING: the "__autoload()" function is removed in PHP 8: replace with "spl_autoload_register()""
}
```

从输出中可以看到，`Migration\OopBreakScan`类被自动加载了。我们知道这是因为`scanMagicAutoloadFunction`方法被调用了，我们有它的结果。此外，我们知道`Migration\Base`类也被自动加载了。我们知道这是因为输出中出现的错误消息是超类的常量。

然而，在 PHP 8 中运行相同的代码会产生这样的结果：

```php
root@php8_tips_php8 [ /repo/ch05 ]# 
php php7_autoload_function.php 
PHP Fatal error:  __autoload() is no longer supported, use spl_autoload_register() instead in /repo/ch05/php7_autoload_function.php on line 4
```

这个结果并不奇怪，因为在 PHP 8 中移除了对魔术`__autoload()`函数的支持。在 PHP 8 中，你必须使用`spl_autoload_register()`。现在我们转向`spl_autoload_register()`。

### 学习使用 spl_autoload_register()

`spl_autoload_register()`函数的主要优点是它允许你注册多个自动加载器。虽然这可能看起来有些多余，但想象一下一个噩梦般的情景，你正在使用许多不同的开源 PHP 库...它们都定义了自己的*自动加载器*！只要所有这些库都使用`spl_autoload_register()`，拥有多个自动加载器回调就不会有问题。

使用`spl_autoload_register()`注册的每个自动加载器都必须是可调用的。以下任何一种都被认为是`可调用`：

+   一个 PHP 过程函数

+   一个匿名函数

+   一个可以以静态方式调用的类方法

+   定义了`__invoke()`魔术方法的任何类实例

+   一个这样的数组：`[$instance, 'method']`

提示

*Composer*维护着自己的自动加载器，它又依赖于`spl_autoload_register()`。如果你正在使用 Composer 来管理你的开源 PHP 包，你可以简单地在应用程序代码的开头包含`/path/to/project/vendor/autoload.php`来使用 Composer 的自动加载器。要让 Composer 自动加载你的应用程序源代码文件，可以在`composer.json`文件的`autoload : psr-4`键下添加一个或多个条目。更多信息，请参见[`getcomposer.org/doc/04-schema.md#psr-4`](https://getcomposer.org/doc/04-schema.md#psr-4)。

一个相当典型的自动加载器类可能如下所示。请注意，这是我们在本书中许多 OOP 示例中使用的类：

1.  在`__construct()`方法中，我们分配了源目录。随后，我们使用上面提到的数组可调用语法调用`spl_auto_register()`：

```php
// /repo/src/Server/Autoload/Loader.php
namespace Server\Autoload;
class Loader {
    const DEFAULT_SRC = __DIR__ . '/../..';
    public $src_dir = '';
    public function __construct($src_dir = NULL) {
        $this->src_dir = $src_dir 
            ?? realpath(self::DEFAULT_SRC);
        spl_autoload_register([$this, 'autoload']);
    }
```

1.  实际的自动加载代码与我们上面`__autoload()`函数示例中显示的类似。以下是执行实际自动加载的方法：

```php
    public function autoload($class) {
        $fn = str_replace('\\', '/', $class);
        $fn = $this->src_dir . '/' . $fn . '.php';
        $fn = str_replace('//', '/', $fn);
        require_once($fn);
    }
}
```

现在你已经了解了如何使用`spl_auto_register()`函数，我们必须检查在运行 PHP 8 时可能出现的代码中断。

### PHP 8 中潜在的 spl_auto_register()代码中断

`spl_auto_register()`函数的第二个参数是一个可选的布尔值，默认为`FALSE`。如果将第二个参数设置为`TRUE`，则在 PHP 7 及以下版本中，如果自动加载程序注册失败，`spl_auto_register()`函数会抛出一个`Exception`。然而，在 PHP 8 中，如果第二个参数的数据类型不是`callable`，则无论第二个参数的值如何，都会抛出致命的`TypeError`！

下面显示的简单程序示例说明了这种危险。在这个例子中，我们使用`spl_auto_register()`函数注册一个不存在的 PHP 函数。我们将第二个参数设置为`TRUE`：

```php
// /repo/ch05/php7_spl_spl_autoload_register.php
try {
    spl_autoload_register('does_not_exist', TRUE);
    $data = ['A' => [1,2,3],'B' => [4,5,6],'C' => [7,8,9]];
    $response = new \Application\Strategy\JsonResponse($data);
    echo $response->render();
} catch (Exception $e) {
    echo "A program error has occurred\n";
}
```

如果我们在 PHP 7 中运行这个代码块，这是结果：

```php
root@php8_tips_php7 [ /repo/ch05 ]# 
php php7_spl_spl_autoload_register.php 
A program error has occurred
```

从输出中可以确定，抛出了一个`Exception`。`catch`块被调用，出现了消息**发生了程序错误**。然而，当我们在 PHP 8 中运行相同的程序时，会抛出一个致命的`Error`：

```php
root@php8_tips_php8 [ /repo/ch05 ]# 
php php7_spl_spl_autoload_register.php 
PHP Fatal error:  Uncaught TypeError: spl_autoload_register(): Argument #1 ($callback) must be a valid callback, no array or string given in /repo/ch05/php7_spl_spl_autoload_register.php:12
```

显然，`catch`块被绕过，因为它设计用于捕获`Exception`，而不是`Error`。简单的解决方法是让`catch`块捕获`Throwable`而不是`Exception`。这允许相同的代码在 PHP 7 或 PHP 8 中运行。

重写后的代码可能如下所示。输出没有显示，因为它与在 PHP 7 中运行相同的示例相同：

```php
// /repo/ch05/php8_spl_spl_autoload_register.php
try {
    spl_autoload_register('does_not_exist', TRUE);
    $data = ['A' => [1,2,3],'B' => [4,5,6],'C' => [7,8,9]];
    $response = new \Application\Strategy\JsonResponse($data);
    echo $response->render();
} catch (Throwable $e) {
    echo "A program error has occurred\n";
}
```

现在您对 PHP 8 自动加载有了更好的理解，以及如何发现和纠正潜在的自动加载向后兼容性问题。现在让我们来看看 PHP 8 中与魔术方法相关的变化。

# 导航魔术方法的变化

PHP 的**魔术方法**是预定义的钩子，它们中断了 OOP 应用程序的正常流程。每个魔术方法，如果定义了，都会改变应用程序的行为，从对象实例创建的那一刻开始，直到实例超出范围的那一刻。

重要提示

对象实例在被取消或被覆盖时会*超出范围*。当在函数或类方法中定义对象实例时，对象实例也会超出范围，并且该函数或类方法的执行结束。最终，如果没有其他原因，当 PHP 程序结束时，对象实例会超出范围。

本节将让您充分了解 PHP 8 中引入的魔术方法使用和行为的重要变化。一旦您了解了本节描述的情况，您就能够进行适当的代码修改，以防止您的应用程序代码在迁移到 PHP 8 时失败。

让我们首先看一下对象构造方法的变化。

## 处理构造函数的变化

理想情况下，**类构造函数**是一个在对象实例创建时自动调用的方法，用于执行某种对象初始化。这种初始化通常涉及使用作为参数提供给该方法的值填充对象属性。初始化还可以执行任何必要的任务，如打开文件句柄、建立数据库连接等。

在 PHP 8 中，类构造函数被调用的方式发生了一些变化。这意味着当您将应用程序迁移到 PHP 8 时，可能会出现向后兼容性问题。我们将首先检查的变化与使用与类相同名称的方法作为类构造函数的方法有关。

### 处理具有相同名称的方法和类的变化

在 PHP 4 版本中引入的第一个 PHP OOP 实现中，确定了与类相同名称的方法将承担类构造函数的角色，并且在创建新对象实例时将自动调用该方法。

鲜为人知的是，即使在 PHP 8 中，函数、方法甚至类名都是*不区分大小写*的。因此`$a = new ArrayObject();`等同于`$b = new arrayobject();`。另一方面，变量名是区分大小写的。

从 PHP 5 开始，随着一个新的更加健壮的 OOP 实现，魔术方法被引入。其中之一是`__construct()`，专门用于类构造，旨在取代旧的用法。通过 PHP 5 的剩余版本，一直到所有的 PHP 7 版本，都支持使用与类同名的方法作为构造函数。

在 PHP 8 中，删除了与类本身相同名称的类构造方法的支持。如果也定义了`__construct()`方法，你就不会有问题：`__construct()`优先作为类构造函数。如果没有`__construct()`方法，并且检测到一个与`class` `()`相同名称的方法，你就有可能失败。请记住，方法和类名都是不区分大小写的！

看一下以下的例子。它在 PHP 7 中有效，但在 PHP 8 中无效：

1.  首先，我们定义了一个`Text`类，它有一个同名的类构造方法。构造方法基于提供的文件名创建了一个`SplFileObject`实例：

```php
// /repo/ch05/php8_oop_bc_break_construct.php
class Text {
    public $fh = '';
    public const ERROR_FN = 'ERROR: file not found';
    public function text(string $fn) {
        if (!file_exists($fn))
            throw new Exception(self::ERROR_FN);
        $this->fh = new SplFileObject($fn, 'r');
    }
    public function getText() {
        return $this->fh->fpassthru();
    }
}
```

1.  然后我们添加了三行过程代码来使用这个类，提供一个包含葛底斯堡演说的文件的文件名：

```php
$fn   = __DIR__ . '/../sample_data/gettysburg.txt';
$text = new Text($fn);
echo $text->getText();
```

1.  首先在 PHP 7 中运行程序会产生一个弃用通知，然后是预期的文本。这里只显示了输出的前几行：

```php
root@php8_tips_php7 [ /repo/ch05 ]# 
php php8_bc_break_construct.php
PHP Deprecated:  Methods with the same name as their class will not be constructors in a future version of PHP; Text has a deprecated constructor in /repo/ch05/php8_bc_break_construct.php on line 4
Fourscore and seven years ago our fathers brought forth on this continent a new nation, conceived in liberty and dedicated to the proposition that all men are created equal. ... <remaining text not shown>
```

1.  然而，在 PHP 8 中运行相同的程序会抛出一个致命的`Error`，如你从这个输出中看到的：

```php
root@php8_tips_php8 [ /repo/ch05 ]# php php8_bc_break_construct.php 
PHP Fatal error:  Uncaught Error: Call to a member function fpassthru() on string in /repo/ch05/php8_bc_break_construct.php:16
```

重要的是要注意，在 PHP 8 中显示的错误并没有告诉你程序失败的真正原因。因此，非常重要的是要扫描你的 PHP 应用程序，特别是旧的应用程序，看看是否有一个与类同名的方法。因此，**最佳实践**就是简单地将与类同名的方法重命名为`__construct()`。

现在让我们看看在 PHP 8 中如何解决类构造函数中处理`Exception`和`exit`的不一致性。

### 解决类构造函数中的不一致性

PHP 8 中解决的另一个问题与类构造方法中抛出`Exception`或执行`exit()`有关。在 PHP 8 之前的版本中，如果在类构造函数中抛出`Exception`，则*不会调用*`__destruct()`方法（如果定义了）。另一方面，如果在构造函数中使用`exit()`或`die()`（这两个 PHP 函数是等效的），则会调用`__destruct()`方法。在 PHP 8 中，这种不一致性得到了解决。现在，在任何情况下，`__destruct()`方法都*不会*被调用。

你可能想知道为什么这很重要。你需要意识到这个重要的改变的原因是，你可能有逻辑存在于`__destruct()`方法中，而这个方法在你可能调用`exit()`或`die()`的情况下被调用。在 PHP 8 中，你不能再依赖这段代码，这可能导致向后兼容性的破坏。

在这个例子中，我们有两个连接类。`ConnectPdo`使用 PDO 扩展来提供查询结果，而`ConnectMysqli`使用 MySQLi 扩展：

1.  我们首先定义一个接口，指定一个查询方法。这个方法需要一个 SQL 字符串作为参数，并且期望返回一个数组作为结果：

```php
// /repo/src/Php7/Connector/ConnectInterface.php
namespace Php7\Connector;
interface ConnectInterface {
    public function query(string $sql) : array;
}
```

1.  接下来，我们定义一个基类，其中定义了一个`__destruct()`魔术方法。因为这个类实现了`ConnectInterface`但没有定义`query()`，所以它被标记为`abstract`：

```php
// /repo/src/Php7/Connector/Base.php
namespace Php7\Connector;
abstract class Base implements ConnectInterface {
    const CONN_TERMINATED = 'Connection Terminated';
    public $conn = NULL;
    public function __destruct() {
        $message = get_class($this)
                 . ':' . self::CONN_TERMINATED;
        error_log($message);
    }
}
```

1.  接下来，我们定义`ConnectPdo`类。它继承自`Base`，它的`query()`方法使用`PDO`语法来产生结果。`__construct()`方法如果创建连接时出现问题，则抛出`PDOException`：

```php
// /repo/src/Php7/Connector/ConnectPdo.php
namespace Php7\Connector;
use PDO;
class ConnectPdo extends Base {
    public function __construct(
        string $dsn, string $usr, string $pwd) {
        $this->conn = new PDO($dsn, $usr, $pwd);
    }
    public function query(string $sql) : array {
        $stmt = $this->conn->query($sql);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}
```

1.  以类似的方式，我们定义了`ConnectMysqli`类。它继承自`Base`，它的`query()`方法使用`MySQLi`语法来产生结果。`__construct()`方法如果创建连接时出现问题，则执行`die()`：

```php
// /repo/src/Php7/Connector/ConnectMysqli.php
namespace Php7\Connector;
class ConnectMysqli extends Base {
    public function __construct(
        string $db, string $usr, string $pwd) {
        $this->conn = mysqli_connect('localhost', 
            $usr, $pwd, $db) 
            or die("Unable to Connect\n");
    }
    public function query(string $sql) : array {
        $result = mysqli_query($this->conn, $sql);
        return mysqli_fetch_all($result, MYSQLI_ASSOC);
    }
}
```

1.  最后，我们定义一个调用程序，使用先前描述的两个连接类，并为连接字符串、用户名和密码定义无效值：

```php
// /repo/ch05/php8_bc_break_destruct.php
include __DIR__ . '/../vendor/autoload.php';
use Php7\Connector\ {ConnectPdo,ConnectMysqli};
$db  = 'test';
$usr = 'fake';
$pwd = 'xyz';
$dsn = 'mysql:host=localhost;dbname=' . $db;
$sql = 'SELECT event_name, event_date FROM events';
```

1.  接下来，在调用程序中，我们调用两个类，并尝试执行查询。连接故意失败，因为我们提供了错误的用户名和密码：

```php
$ptn = "%2d : %s : %s\n";
try {
    $conn = new ConnectPdo($dsn, $usr, $pwd);
    var_dump($conn->query($sql));
} catch (Throwable $t) {
    printf($ptn, __LINE__, get_class($t), 
           $t->getMessage());
}
$conn = new ConnectMysqli($db, $usr, $pwd);
var_dump($conn->query($sql));
```

1.  正如您从上面的讨论中所了解的，PHP 7 中运行的输出显示了在创建`ConnectPdo`实例时从类构造函数抛出`PDOException`。另一方面，当`ConnectMysqli`实例失败时，将调用`die()`，并显示消息**无法连接**。您还可以在输出的最后一行看到来自`__destruct()`方法的错误日志信息。以下是该输出：

```php
root@php8_tips_php7 [ /repo/ch05 ]# 
php php8_bc_break_destruct.php 
15 : PDOException : SQLSTATE[28000] [1045] Access denied for user 'fake'@'localhost' (using password: YES)
PHP Warning:  mysqli_connect(): (HY000/1045): Access denied for user 'fake'@'localhost' (using password: YES) in /repo/src/Php7/Connector/ConnectMysqli.php on line 8
Unable to Connect
Php7\Connector\ConnectMysqli:Connection Terminated
```

1.  在 PHP 8 中，`__destruct()`方法在任何情况下都不会被调用，导致如下所示的输出。正如您在输出中所看到的，`PDOException`被捕获，然后发出`die()`命令。`__destruct()`方法没有任何输出。PHP 8 的输出如下：

```php
root@php8_tips_php8 [ /repo/ch05 ]# 
php php8_bc_break_destruct.php 
15 : PDOException : SQLSTATE[28000] [1045] Access denied for user 'fake'@'localhost' (using password: YES)
PHP Warning:  mysqli_connect(): (HY000/1045): Access denied for user 'fake'@'localhost' (using password: YES) in /repo/src/Php7/Connector/ConnectMysqli.php on line 8
Unable to Connect
```

现在您已经知道如何发现与`__destruct()`方法以及对`die()`或`exit()`的调用有关的潜在代码中断，让我们将注意力转向`__toString()`方法的更改。

## 处理对 __toString()的更改

当对象被用作字符串时，将调用`__toString()`魔术方法。一个经典的例子是当您简单地 echo 一个对象时。`echo`命令期望一个字符串作为参数。当提供非字符串数据时，PHP 执行类型转换将数据转换为`string`。由于对象不能直接转换为`string`，因此 PHP 引擎会查看是否定义了`__toString()`，如果定义了，则返回其值。

这个魔术方法的主要变化是引入了`Stringable`，一个全新的接口。新接口定义如下：

```php
interface Stringable {
   public function __toString(): string;
}
```

在 PHP 8 中运行的任何类，如果定义了`__toString()`魔术方法，都会静默实现`Stringable`接口。这种新行为并不会导致严重的潜在代码中断。然而，由于类现在实现了`Stringable`接口，您将不再允许修改`__toString()`方法的签名。

以下是一个简短的示例，揭示了与`Stringable`接口的新关联：

1.  在这个例子中，我们定义了一个定义了`__toString()`的`Test`类：

```php
// /repo/ch05/php8_bc_break_magic_to_string.php
class Test {
    public $fname = 'Fred';
    public $lname = 'Flintstone';
    public function __toString() : string {
        return $this->fname . ' ' . $this->lname;
    }
}
```

1.  然后我们创建类的一个实例，然后是一个`ReflectionObject`实例：

```php
$test = new Test;
$reflect = new ReflectionObject($test);
echo $reflect;
```

在 PHP 7 中运行的输出的前几行（如下所示）只是显示它是`Test`类的一个实例：

```php
root@php8_tips_php7 [ /repo/ch05 ]# 
php php8_bc_break_magic_to_string.php
Object of class [ <user> class Test ] {
  @@ /repo/ch05/php8_bc_break_magic_to_string.php 3-12
```

然而，在 PHP 8 中运行相同的代码示例，揭示了与`Stringable`接口的静默关联：

```php
root@php8_tips_php8 [ /repo/ch05 ]# 
php php8_bc_break_magic_to_string.php
Object of class [ <user> class Test implements Stringable ] {
  @@ /repo/ch05/php8_bc_break_magic_to_string.php 3-12
```

输出显示，即使您没有显式实现`Stringable`接口，也会在运行时创建关联，并由`ReflectionObject`实例显示。

提示

有关魔术方法的更多信息，请参阅此文档页面：[`www.php.net/manual/en/language.oop5.magic.php`](https://www.php.net/manual/en/language.oop5.magic.php)。

现在您已经了解了 PHP 8 代码涉及魔术方法可能导致代码中断的情况，让我们来看看序列化过程中的更改。

# 控制序列化

有许多时候，需要将本机 PHP 数据存储在文件中，或者存储在数据库表中。当前技术的问题在于，直接存储复杂的 PHP 数据，如对象或数组，是不可能的，除了一些例外。

克服这种限制的一种方法是将对象或数组转换为字符串。**JSON**（JavaScript 对象表示）通常因此而被选择。一旦数据被转换为字符串，它就可以轻松地存储在任何文件或数据库中。然而，使用 JSON 格式化对象存在问题。尽管 JSON 能够很好地表示对象属性，但它无法直接恢复原始对象的类和方法。

为了解决这个缺陷，PHP 语言包括两个原生函数`serialize()`和`unserialize()`，可以轻松地将对象或数组转换为字符串，并将它们恢复到原始状态。尽管听起来很棒，但与原生 PHP 序列化相关的问题有很多。

在我们能够正确讨论现有 PHP 序列化架构的问题之前，我们需要更仔细地了解原生 PHP 序列化的工作方式。

## 了解 PHP 序列化

当 PHP 对象或数组需要保存到非面向对象编程环境（如平面文件或关系数据库表）时，可以使用`serialize()`将对象或数组“扁平化”为适合存储的字符串。相反，`unserialize()`会恢复原始对象或数组。

以下是演示这个概念的一个简单示例：

1.  首先，我们定义一个具有三个属性的类：

```php
// /repo/ch05/php8_serialization.php
class Test  {
    public $name = 'Doug';
    private $key = 12345;
    protected $status = ['A','B','C'];
}
```

1.  然后我们创建一个实例，对该实例进行序列化，并显示生成的字符串：

```php
$test = new Test();
$str = serialize($test);
echo $str . "\n";
```

1.  以下是序列化对象的样子：

```php
O:4:"Test":3:{s:4:"name";s:4:"Doug";s:9:"Testkey"; i:12345;
s:9:"*status";a:3:{i:0;s:1:"A";i:1;s:1:"B";i:2;s:1:"C";}}
```

从序列化字符串中可以看出，字母`O`代表*对象*，`a`代表*数组*，`s`代表*字符串*，`i`代表*整数*。

1.  然后我们将对象反序列化为一个新变量，并使用`var_dump()`来检查这两个变量：

```php
$obj = unserialize($str);
var_dump($test, $obj);
```

1.  将`var_dump()`的输出并排放置，您可以清楚地看到恢复的对象与原始对象是相同的：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/B16992_05_table_1.1.jpg)

现在让我们来看一下支持旧版 PHP 序列化的魔术方法：`__sleep()`和`__wakeup()`。

## 了解`__sleep()`魔术方法

`__sleep()`魔术方法的目的是提供一个过滤器，用于防止某些属性出现在序列化字符串中。以用户对象为例，您可能希望排除敏感属性，如国民身份证号码、信用卡号码或密码。

以下是使用`__sleep()`魔术方法来排除密码的示例：

1.  首先，我们定义一个具有三个属性的`Test`类：

```php
// /repo/ch05/php8_serialization_sleep.php
class Test  {
    public $name = 'Doug';
    protected $key = 12345;
    protected $password = '$2y$10$ux07vQNSA0ctbzZcZNA'
         . 'lxOa8hi6kchJrJZzqWcxpw/XQUjSNqacx.';
```

1.  然后我们定义一个`__sleep()`方法来排除`$password`属性：

```php
    public function __sleep() {
        return ['name','key'];
    }
}
```

1.  然后我们创建这个类的一个实例并对其进行序列化。最后一行输出序列化字符串的状态：

```php
$test = new Test();
$str = serialize($test)
echo $str . "\n";
```

1.  在输出中，您可以清楚地看到`$password`属性不存在。以下是输出：

```php
O:4:"Test":2:{s:4:"name";s:4:"Doug";s:6:"*key";i:12345;}
```

这一点很重要，因为在大多数情况下，您需要对对象进行序列化的原因是希望将其存储在某个地方，无论是在会话文件中还是在数据库中。如果文件系统或数据库随后受到损害，您就少了一个安全漏洞需要担心！

## 了解`__sleep()`方法中潜在的代码中断

`__sleep()`魔术方法涉及潜在的代码中断。在 PHP 8 之前的版本中，如果`__sleep()`返回一个包含不存在属性的数组，它们仍然会被序列化并赋予一个`NULL`值。这种方法的问题在于，当对象随后被反序列化时，会出现一个额外的属性，这不是设计时存在的属性！

在 PHP 8 中，`__sleep()`魔术方法中不存在的属性会被静默忽略。如果您的旧代码预期旧的行为并采取步骤*删除*不需要的属性，或者更糟糕的是，如果您的代码假设不需要的属性存在，最终会出现错误。这样的假设非常危险，因为它们可能导致意外的代码行为。

为了说明问题，让我们看一下以下代码示例：

1.  首先，我们定义一个`Test`类，该类定义了`__sleep()`来返回一个不存在的变量：

```php
class Test {
    public $name = 'Doug';
    public function __sleep() {
        return ['name', 'missing'];
    }
}
```

1.  接下来，我们创建一个`Test`的实例并对其进行序列化：

```php
echo "Test instance before serialization:\n";
$test = new Test();
var_dump($test);
```

1.  然后我们将字符串反序列化为一个新实例`$restored`：

```php
echo "Test instance after serialization:\n";
$stored = serialize($test);
$restored = unserialize($stored);
var_dump($restored);
```

1.  理论上，两个对象实例`$test`和`$restored`应该是相同的。然而，看一下在 PHP 7 中运行的输出：

```php
root@php8_tips_php7 [ /repo/ch05 ]#
php php8_bc_break_sleep.php
Test instance before serialization:
/repo/ch05/php8_bc_break_sleep.php:13:
class Test#1 (1) {
  public $name =>  string(4) "Doug"
}
Test instance after serialization:
PHP Notice:  serialize(): "missing" returned as member variable from __sleep() but does not exist in /repo/ch05/php8_bc_break_sleep.php on line 16
class Test#2 (2) {
  public $name =>  string(4) "Doug"
  public $missing =>  NULL
}
```

1.  从输出中可以看出，这两个对象显然*不*相同！然而，在 PHP 8 中，不存在的属性被忽略。看一下在 PHP 8 中运行相同脚本的情况：

```php
root@php8_tips_php8 [ /repo/ch05 ]# php php8_bc_break_sleep.php 
Test instance before serialization:
object(Test)#1 (1) {
  ["name"]=>  string(4) "Doug"
}
Test instance after serialization:
PHP Warning:  serialize(): "missing" returned as member variable from __sleep() but does not exist in /repo/ch05/php8_bc_break_sleep.php on line 16
object(Test)#2 (1) {
  ["name"]=>  string(4) "Doug"
}
```

您可能还注意到，在 PHP 7 中，会发出一个`Notice`，而在 PHP 8 中，相同的情况会产生一个`Warning`。在这种情况下，对潜在代码中断的预迁移检查是困难的，因为您需要确定魔术方法`__sleep()`是否被定义，以及是否在列表中包含了一个不存在的属性。

现在让我们来看看对应的方法`__wakeup()`。

## 学习 __wakeup()

`__wakeup()`魔术方法的目的主要是在反序列化对象时执行额外的初始化。例如，恢复数据库连接或恢复文件句柄。下面是一个使用`__wakeup()`魔术方法重新打开文件句柄的非常简单的例子：

1.  首先，我们定义一个在实例化时打开文件句柄的类。我们还定义一个返回文件内容的方法：

```php
// /repo/ch05/php8_serialization_wakeup.php
class Gettysburg {
    public $fn = __DIR__ . '/gettysburg.txt';
    public $obj = NULL;
    public function __construct() {
        $this->obj = new SplFileObject($this->fn, 'r');
    }
    public function getText() {
        $this->obj->rewind();
        return $this->obj->fpassthru();
    }
}
```

1.  要使用这个类，创建一个实例，并运行`getText()`。（这假设`$this->fn`引用的文件存在！）

```php
$old = new Gettysburg();
echo $old->getText();
```

1.  输出（未显示）是葛底斯堡演说。

1.  如果我们现在尝试对这个对象进行序列化，就会出现问题。下面是一个可能序列化对象的代码示例：

`$str = serialize($old);`

1.  到目前为止，在原地运行代码，这是输出：

```php
PHP Fatal error:  Uncaught Exception: Serialization of 'SplFileObject' is not allowed in /repo/ch05/php8_serialization_wakeup.php:19
```

1.  为了解决这个问题，我们返回到类中，添加一个`__sleep()`方法，防止`SplFileObject`实例被序列化：

```php
    public function __sleep() {
        return ['fn'];
    }
```

1.  如果我们重新运行代码来序列化对象，一切都很好。这是反序列化和调用`getText()`的代码：

```php
$str = serialize($old);
$new = unserialize($str);
echo $new->getText();
```

1.  然而，如果我们尝试对对象进行反序列化，就会出现另一个错误：

```php
PHP Fatal error:  Uncaught Error: Call to a member function rewind() on null in /repo/ch05/php8_serialization_wakeup.php:13
```

问题当然是，在序列化过程中文件句柄丢失了。当对象被反序列化时，`__construct()`方法没有被调用。

1.  这正是`__wakeup()`魔术方法存在的原因。为了解决错误，我们定义一个`__wakeup()`方法，调用`__construct()`方法：

```php
    public function __wakeup() {
        self::__construct();
    }
```

1.  如果我们重新运行代码，现在我们会看到葛底斯堡演说出现两次（未显示）。

现在您已经了解了 PHP 原生序列化的工作原理，也了解了`__sleep()`和`__wakeup()`魔术方法，以及潜在的代码中断。现在让我们来看一下一个旨在促进对象自定义序列化的接口。

## 介绍 Serializable 接口

为了促进对象的序列化，从 PHP 5.1 开始，语言中添加了`Serializable`接口。这个接口的想法是提供一种识别具有自我序列化能力的对象的方法。此外，该接口指定的方法旨在在对象序列化过程中提供一定程度的控制。

只要一个类实现了这个接口，开发人员就可以确保两个方法被定义：`serialize()`和`unserialize()`。这是接口定义：

```php
interface Serializable {
    public serialize () : string|null
    public unserialize (string $serialized) : void
}
```

任何实现了这个接口的类，在本地序列化或反序列化过程中，其自定义`serialize()`和`unserialize()`方法会自动调用。为了说明这种技术，考虑以下示例：

1.  首先，我们定义一个实现`Serializable`接口的类。该类定义了三个属性 - 两个是字符串类型，另一个表示日期和时间：

```php
// /repo/ch05/php8_bc_break_serializable.php
class A implements Serializable {
    private $a = 'A';
    private $b = 'B';
    private $u = NULL;
```

1.  然后我们定义一个自定义的`serialize()`方法，在序列化对象的属性之前初始化日期和时间。`unserialize()`方法将值恢复到所有属性中：

```php
    public function serialize() {
        $this->u = new DateTime();
        return serialize(get_object_vars($this));
    }
    public function unserialize($payload) {
        $vars = unserialize($payload);
        foreach ($vars as $key => $val)
            $this->$key = $val;
    }
}
```

1.  然后我们创建一个实例，并使用`var_dump()`检查其内容：

```php
$a1 = new A();
var_dump($a1);
```

1.  `var_dump()`的输出显示`u`属性尚未初始化：

```php
object(A)#1 (3) {
  ["a":"A":private]=> string(1) "A"
  ["b":"A":private]=> string(1) "B"
  ["u":"A":private]=> NULL
}
```

1.  然后我们对其进行序列化，并将其恢复到一个变量`$a2`中：

```php
$str = serialize($a1);
$a2 = unserialize($str);
var_dump($a2);
```

1.  从下面的`var_dump()`输出中，您可以看到对象已经完全恢复。此外，我们知道自定义的`serialize()`方法被调用，因为`u`属性被初始化为日期和时间值。以下是输出：

```php
object(A)#3 (3) {
  ["a":"A":private]=> string(1) "A"
  ["b":"A":private]=> string(1) "B"
  ["u":"A":private]=> object(DateTime)#4 (3) {
    ["date"]=> string(26) "2021-02-12 05:35:10.835999"
    ["timezone_type"]=> int(3)
    ["timezone"]=> string(3) "UTC"
  }
}
```

现在让我们来看一下实现`Serializable`接口的对象在序列化过程中可能出现的问题。

## 检查 PHP 可序列化接口问题

早期序列化方法存在一个整体问题。如果要序列化的类定义了一个`__wakeup()`魔术方法，它不会立即在反序列化时被调用。相反，任何定义的`__wakeup()`魔术方法首先被排队，整个对象链被反序列化，然后才执行队列中的方法。这可能导致对象的`unserialize()`方法看到的与其排队的`__wakeup()`方法看到的不一致。

这种架构缺陷可能导致处理实现`Serializable`接口的对象时出现不一致的行为和模棱两可的结果。许多开发人员认为`Serializable`接口由于在嵌套对象序列化时需要创建反向引用而严重破损。这种需要出现在**嵌套序列化调用**的情况下。

例如，当一个类定义了一个方法，该方法反过来调用 PHP 的`serialize()`函数时，可能会发生这样的嵌套调用。在 PHP 8 之前，PHP 序列化中预设了创建反向引用的顺序，可能导致一系列级联的失败。

解决方案是使用两个新的魔术方法来完全控制序列化和反序列化的顺序，接下来将进行描述。

## 控制 PHP 序列化的新魔术方法

控制序列化的新方法首先在 PHP 7.4 中引入，并在 PHP 8 中继续使用。为了利用这项新技术，您只需要实现两个魔术方法：`__serialize()`和`__unserialize()`。如果实现了，PHP 将完全将序列化的控制权交给`__serialize()`方法。同样，反序列化完全由`__unserialize()`魔术方法控制。如果定义了`__sleep()`和`__wakeup()`方法，则会被忽略。

作为一个进一步的好处，PHP 8 完全支持以下 SPL 类中的两个新的魔术方法：

+   `ArrayObject`

+   `ArrayIterator`

+   `SplDoublyLinkedList`

+   `SplObjectStorage`

最佳实践

为了完全控制序列化，实现新的`__serialize()`和`__unserialize()`魔术方法。您不再需要实现`Serializable`接口，也不需要定义`__sleep()`和`__wakeup()`。有关`Serializable`接口最终停用的更多信息，请参阅此 RFC：[`wiki.php.net/rfc/phase_out_serializable`](https://wiki.php.net/rfc/phase_out_serializable)。

作为新的 PHP 序列化用法的示例，请考虑以下代码示例：

1.  在示例中，一个`Test`类在实例化时使用一个随机密钥进行初始化：

```php
// /repo/ch05/php8_bc_break_serialization.php
class Test extends ArrayObject {
    protected $id = 12345;
    public $name = 'Doug';
    private $key = '';
    public function __construct() {
        $this->key = bin2hex(random_bytes(8));
    }
```

1.  我们添加一个`getKey()`方法来显示当前的关键值：

```php
    public function getKey() {
        return $this->key;
    }
```

1.  在序列化时，关键点被过滤出结果字符串：

```php
    public function __serialize() {
        return ['id' => $this->id, 
                'name' => $this->name];
    }
```

1.  在反序列化时，生成一个新的关键点：

```php
    public function __unserialize($data) {
        $this->id = $data['id'];
        $this->name = $data['name'];
        $this->__construct();
    }
}
```

1.  现在我们创建一个实例，并揭示关键点：

```php
$test = new Test();
echo "\nOld Key: " . $test->getKey() . "\n";
```

关键点可能会出现如下：

```php
Old Key: mXq78DhplByDWuPtzk820g==
```

1.  我们添加代码来序列化对象并显示字符串：

```php
$str = serialize($test);
echo $str . "\n";
```

这是序列化字符串可能的样子：

```php
O:4:"Test":2:{s:2:"id";i:12345;s:4:"name";s:4:"Doug";}
```

从输出中可以看到，秘密不会出现在序列化的字符串中。这很重要，因为如果序列化字符串的存储位置受到损害，可能会暴露安全漏洞，使攻击者有可能侵入您的系统。

1.  然后我们添加代码来反序列化字符串并显示关键点：

```php
$obj = unserialize($str);
echo "New Key: " . $obj->getKey() . "\n";
```

这是最后一部分输出。请注意，生成了一个新的关键点：

```php
New Key: kDgU7FGfJn5qlOKcHEbyqQ==
```

正如您所看到的，使用新的 PHP 序列化功能并不复杂。任何时间问题现在完全在您的控制之下，因为新的魔术方法是按照对象序列化和反序列化的顺序执行的。

重要说明

PHP 7.4 及以上版本*能够*理解来自旧版本 PHP 的序列化字符串，但是由 PHP 7.4 或 8.x 序列化的字符串可能无法被旧版本的 PHP 正确反序列化。

提示

有关完整讨论，请参阅有关自定义序列化的 RFC：

https://wiki.php.net/rfc/custom_object_serialization

您现在已经完全了解了 PHP 序列化和两种新的魔术方法提供的改进支持。现在是时候转变思路，看看 PHP 8 如何扩展方差支持了。

# 理解 PHP 8 扩展的方差支持

方差的概念是面向对象编程的核心。**方差**是一个涵盖各种**子类型**相互关系的总称。大约 20 年前，早期计算机科学家 Wing 和 Liskov 提出了一个重要的定理，它是面向对象编程子类型的核心，现在被称为**Liskov 替换原则**。

不需要进入精确的数学，这个原则可以被解释为：

*如果您能够在类 Y 的实例的位置替换 X 的实例，并且应用程序的行为没有任何改变，那么类 X 可以被认为是类 Y 的子类型。*

提示

首次描述并提供了 Liskov 替换原则的精确数学公式定义的实际论文可以在这里找到：*子类型的行为概念*，ACM 编程语言和系统交易，由 B. Liskov 和 J. Wing，1994 年 11 月（https://dl.acm.org/doi/10.1145/197320.197383）。

在本节中，我们将探讨 PHP 8 如何以**协变返回**和**逆变参数**的形式提供增强的方差支持。对协变和逆变的理解将增强您编写良好稳固代码的能力。如果没有这种理解，您的代码可能会产生不一致的结果，并成为许多错误的根源。

让我们首先讨论协变返回。

## 理解协变返回

PHP 中的协变支持旨在保留从最具体到最一般的类型的顺序。这在`try / catch`块的构造中经典地体现出来：

1.  在这个例子中，`PDO`实例是在`try`块内创建的。接下来的两个`catch`块首先寻找`PDOException`。接着是一个第二个`catch`块，它捕获任何实现`Throwable`的类。因为 PHP 的`Exception`和`Error`类都实现了`Throwable`，所以第二个`catch`块最终成为除了`PDOException`之外的任何错误的后备：

```php
try {
    $pdo = new PDO($dsn, $usr, $pwd, $opts);
} catch (PDOException $p) {
    error_log('Database Error: ' . $p->getMessage());
} catch (Throwable $t) {
    error_log('Unknown Error: ' . $t->getMessage());
}
```

1.  在这个例子中，如果`PDO`实例由于无效参数而失败，错误日志将包含条目**数据库错误**，后面跟着从`PDOException`中获取的消息。

1.  另一方面，如果发生了其他一般错误，错误日志将包含条目**未知错误**，后面跟着来自其他`Exception`或`Error`类的消息。

1.  然而，在这个例子中，`catch`块的顺序是颠倒的：

```php
try {
    $pdo = new PDO($dsn, $usr, $pwd, $opts);
} catch (Throwable $t) {
    error_log('Unknown Error: ' . $t->getMessage());
} catch (PDOException $p) {
    error_log('Database Error: ' . $p->getMessage());
}
```

1.  由于 PHP 协变支持的工作方式，第二个`catch`块永远不会被调用。相反，所有源自此代码块的错误日志条目将以**未知错误**开头。

现在让我们看看 PHP 协变支持如何适用于对象方法返回数据类型：

1.  首先，我们定义一个接口`FactoryIterface`，它标识一个`make()`方法。此方法接受一个`array`作为参数，并且预期返回一个`ArrayObject`类型的对象：

```php
interface FactoryInterface {
    public function make(array $arr): ArrayObject;
}
```

1.  接下来，我们定义一个`ArrTest`类，它扩展了`ArrayObject`：

```php
class ArrTest extends ArrayObject {
    const DEFAULT_TEST = 'This is a test';
}
```

1.  `ArrFactory`类实现了`FactoryInterface`并完全定义了`make()`方法。但是，请注意，此方法返回`ArrTest`数据类型而不是`ArrayObject`：

```php
class ArrFactory implements FactoryInterface {
    protected array $data;
    public function make(array $data): ArrTest {
        $this->data = $data;
        return new ArrTest($this->data);
    }
}
```

1.  在程序调用代码块中，我们创建了一个`ArrFactory`的实例，并两次运行其`make()`方法，理论上产生了两个`ArrTest`实例。然后我们使用`var_dump()`来显示所产生的两个对象的当前状态：

```php
$factory = new ArrFactory();
$obj1 = $factory->make([1,2,3]);
$obj2 = $factory->make(['A','B','C']);
var_dump($obj1, $obj2);
```

1.  在 PHP 7.1 中，由于它不支持协变返回数据类型，会抛出致命的`Error`。下面显示的输出告诉我们，方法返回类型声明与`FactoryInterface`中定义的不匹配：

```php
root@php8_tips_php7 [ /repo/ch05 ]# 
php php8_variance_covariant.php
PHP Fatal error:  Declaration of ArrFactory::make(array $data): ArrTest must be compatible with FactoryInterface::make(array $arr): ArrayObject in /repo/ch05/php8_variance_covariant.php on line 9
```

1.  当我们在 PHP 8 中运行相同的代码时，您会看到对返回类型提供了协变支持。执行继续进行，如下所示：

```php
root@php8_tips_php8 [ /repo/ch05 ]# 
php php8_variance_covariant.php
object(ArrTest)#2 (1) {
  ["storage":"ArrayObject":private]=>
  array(3) {
    [0]=>    int(1)
    [1]=>    int(2)
    [2]=>    int(3)
  }
}
object(ArrTest)#3 (1) {
  ["storage":"ArrayObject":private]=>
  array(3) {
    [0]=>    string(1) "A"
    [1]=>    string(1) "B"
    [2]=>    string(1) "C"
  }
}
```

`ArrTest`扩展了`ArrayObject`，是一个明显符合里氏替换原则定义的条件的子类型。正如您从最后的输出中看到的那样，PHP 8 比之前的 PHP 版本更全面地接受了真正的面向对象编程原则。最终结果是，在使用 PHP 8 时，您的代码和应用架构可以更直观和逻辑合理。

现在让我们来看看逆变参数。

## 使用逆变参数

而协变关注的是从一般到特定的子类型的顺序，**逆变**关注的是相反的顺序：从特定到一般。在 PHP 7 及更早版本中，对逆变的完全支持是不可用的。因此，在 PHP 7 中，实现接口或扩展抽象类时，参数类型提示是**不变**的。

另一方面，在 PHP 8 中，由于对逆变参数的支持，您可以在顶级超类和接口中自由地具体化。只要子类型是兼容的，您就可以修改扩展或实现类中的类型提示为更一般的类型。

这使您在定义整体架构时更自由地定义接口或抽象类。在使用您的接口或超类的开发人员在实现后代类逻辑时，PHP 8 在实现时提供了更多的灵活性。

让我们来看看 PHP 8 对逆变参数的支持是如何工作的：

1.  在这个例子中，我们首先定义了一个`IterObj`类，它扩展了内置的`ArrayIterator PHP 类`：

```php
// /repo/ch05/php8_variance_contravariant.php
class IterObj extends ArrayIterator {}
```

1.  然后我们定义一个抽象的`Base`类，规定了一个`stringify()`方法。请注意，它唯一参数的数据类型是`IterObj`：

```php
abstract class Base {
    public abstract function stringify(IterObj $it);
}
```

1.  接下来，我们定义一个`IterTest`类，它扩展了`Base`并为`stringify()`方法提供了实现。特别值得注意的是，我们覆盖了数据类型，将其更改为`iterable`：

```php
class IterTest extends Base {
    public function stringify(iterable $it) {
        return implode(',', 
            iterator_to_array($it)) . "\n";
    }
}
class IterObj extends ArrayIterator {}
```

1.  接下来的几行代码创建了`IterTest`、`IterObj`和`ArrayIterator`的实例。然后我们调用`stringify()`方法两次，分别将后两个对象作为参数提供：

```php
$test  = new IterTest();
$objIt = new IterObj([1,2,3]);
$arrIt = new ArrayIterator(['A','B','C']);
echo $test->stringify($objIt);
echo $test->stringify($arrIt);
```

1.  在 PHP 7.1 中运行此代码示例会产生预期的致命`Error`，如下所示：

```php
root@php8_tips_php7 [ /repo/ch05 ]#
php php8_variance_contravariant.php
PHP Fatal error:  Declaration of IterTest::stringify(iterable $it) must be compatible with Base::stringify(IterObj $it) in /repo/ch05/php8_variance_contravariant.php on line 11
```

因为 PHP 7.1 不支持逆变参数，它将其参数的数据类型视为不变，并简单地显示一条消息，指示子类的数据类型与父类中指定的数据类型不兼容。

1.  另一方面，PHP 8 提供了对逆变参数的支持。因此，它认识到`IterObj`，在`Base`类中指定的数据类型，是与`iterable`兼容的子类型。此外，提供的两个参数也与`iterable`兼容，允许程序执行继续进行。以下是 PHP 8 的输出：

```php
root@php8_tips_php8 [ /repo/ch05 ]# php php8_variance_contravariant.php
1,2,3
A,B,C
```

PHP 8 对协变返回和逆变参数的支持带来的主要优势是能够覆盖方法逻辑以及**方法签名**。您会发现，尽管 PHP 8 在执行良好的编码实践方面要严格得多，但增强的变异支持使您在设计继承结构时拥有更大的自由度。在某种意义上，至少在参数和返回值数据类型方面，PHP 8 是*更*不受限制的！

提示

要了解 PHP 7.4 和 PHP 8 中如何应用方差支持的完整解释，请查看这里：https://wiki.php.net/rfc/covariant-returns-and-contravariant-parameters。

现在我们将看一下 SPL 的更改以及这些更改如何影响迁移到 PHP 8 后的应用程序性能。

# 处理标准 PHP 库（SPL）更改

**SPL**是一个包含实现基本数据结构和增强面向对象功能的关键类的扩展。它首次出现在 PHP 5 中，现在默认包含在所有 PHP 安装中。涵盖整个 SPL 超出了本书的范围。相反，在本节中，我们讨论了在运行 PHP 8 时 SPL 发生了重大变化的地方。此外，我们还为您提供了有可能导致现有应用程序停止工作的 SPL 更改的提示和指导。

我们首先检查`SplFileObject`类的更改。

## 了解 SplFileObject 的更改

`SplFileObject`是一个很好的类，它将大部分独立的`f*()`函数（如`fgets()`，`fread()`，`fwrite()`等）合并到一个类中。`SplFileObject ::__construct()`方法的参数与`fopen()`函数提供的参数相同。

PHP 8 中的主要区别是，一个相对不常用的方法`fgetss()`已从`SplFileObject`类中删除。`SplFileObject::fgetss()`方法在 PHP 7 及以下版本中可用，它将`fgets()`与`strip_tags()`结合在一起。

为了举例说明，假设您已经创建了一个网站，允许用户上传文本文件。在显示文本文件内容之前，您希望删除任何标记。以下是使用`fgetss()`方法实现此目的的示例：

1.  我们首先定义一个获取文件名的代码块：

```php
// /repo/ch05/php7_spl_splfileobject.php
$fn = $_GET['fn'] ?? '';
if (!$fn || !file_exists($fn))
    exit('Unable to locate file');
```

1.  然后我们创建`SplFileObject`实例，并使用`fgetss()`方法逐行读取文件。最后，我们输出安全内容：

```php
$obj = new SplFileObject($fn, 'r');
$safe = '';
while ($line = $obj->fgetss()) $safe .= $line;
echo '<h1>Contents</h1><hr>' . $safe;
```

1.  假设要读取的文件是这个：

```php
<h1>This File is Infected</h1>
<script>alert('You Been Hacked');</script>
<img src="http://very.bad.site/hacked.php" />
```

1.  以下是在 PHP 7.1 中使用此 URL 运行的输出：

`http://localhost:7777/ch05/php7_spl_splfileobject.php? fn=includes/you_been_hacked.html`

从接下来显示的输出中可以看出，所有 HTML 标记都已被删除：

![图 5.1 - 使用 SplFileObject::fgetss()读取文件后的结果](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_5.1_B6992.jpg)

图 5.1 - 使用 SplFileObject::fgetss()读取文件后的结果

在 PHP 8 中实现相同的功能，之前显示的代码需要通过用`fgets()`替换`fgetss()`来进行修改。我们还需要在连接到`$safe`的行上使用`strip_tags()`。修改后的代码可能如下所示：

```php
// /repo/ch05/php8_spl_splfileobject.php
$fn = $_GET['fn'] ?? '';
if (!$fn || !file_exists($fn))
    exit('Unable to locate file');
$obj = new SplFileObject($fn, 'r');
$safe = '';
while ($line = $obj->fgets())
    $safe .= strip_tags($line);
echo '<h1>Contents</h1><hr>' . $safe;
```

修改后的代码的输出与*图 5.1*中显示的相同。现在我们将注意力转向另一个 SPL 类的更改：`SplHeap`。

## 检查 SplHeap 的更改

`SplHeap`是一个基础类，用于表示**二叉树**结构的数据。另外还有两个类建立在`SplHeap`基础上。`SplMinHeap`将树组织为顶部是最小值。`SplMaxHeap`则相反，将最大值放在顶部。

堆结构在数据无序到达的情况下特别有用。一旦插入堆中，项目会自动按正确的顺序放置。因此，在任何给定时刻，您可以显示堆，确保所有项目都按顺序排列，而无需运行 PHP 排序函数之一。

保持自动排序顺序的关键是定义一个抽象方法`compare()`。由于这个方法是抽象的，`SplHeap`不能直接实例化。相反，您需要扩展该类并实现`compare()`。

在 PHP 8 中，使用`SplHeap`可能会导致向后兼容的代码中断，因为`compare()`的方法签名必须完全如下：`SplHeap::compare($value1, $value2)`。

让我们现在来看一个使用`SplHeap`构建按姓氏组织的亿万富翁列表的代码示例：

1.  首先，我们定义一个包含亿万富翁数据的文件。在这个例子中，我们只是从这个来源复制并粘贴了数据：https://www.bloomberg.com/billionaires/。

1.  然后，我们定义一个`BillionaireTracker`类，从粘贴的文本中提取信息到有序对的数组中。该类的完整源代码（未在此处显示）可以在源代码存储库中找到：`/repo/src/Services/BillionaireTracker.php`。

这是该类生成的数据的样子：

```php
array(20) {
  [0] =>  array(1) {
    [177000000000] =>    string(10) "Bezos,Jeff"
  }
  [1] =>  array(1) {
    [157000000000] =>    string(9) "Musk,Elon"
  }
  [2] =>  array(1) {
    [136000000000] =>    string(10) "Gates,Bill"
  }
  ... remaining data not shown
```

正如你所看到的，数据以降序呈现，其中键表示净值。相比之下，在我们的示例程序中，我们计划按姓氏的升序产生数据。

1.  然后，我们定义一个常量，用于标识亿万富翁数据源文件，并设置一个自动加载程序：

```php
// /repo/ch05/php7_spl_splheap.php
define('SRC_FILE', __DIR__ 
    . '/../sample_data/billionaires.txt');
require_once __DIR__ 
    . '/../src/Server/Autoload/Loader.php';
$loader = new \Server\Autoload\Loader();
```

1.  接下来，我们创建一个`BillionaireTracker`类的实例，并将结果赋给`$list`：

```php
use Services\BillionaireTracker;
$tracker = new BillionaireTracker();
$list = $tracker->extract(SRC_FILE);
```

1.  现在来看最感兴趣的部分：创建堆。为了实现这一点，我们定义了一个扩展`SplHeap`的匿名类。然后，我们定义了一个`compare()`方法，执行必要的逻辑将插入的元素放在适当的位置。PHP 7 允许你改变方法签名。在这个例子中，我们以数组的形式提供参数：

```php
$heap = new class () extends SplHeap {
    public function compare(
        array $arr1, array $arr2) : int {
        $cmp1 = array_values($arr2)[0];
        $cmp2 = array_values($arr1)[0];
        return $cmp1 <=> $cmp2;
    }
};
```

你可能还注意到`$cmp1`的值是从第二个数组中赋值的，而`$cmp2`的值是从第一个数组中赋值的。这种切换的原因是因为我们希望按升序产生结果。

1.  然后，我们使用`SplHeap::insert()`将元素添加到堆中：

```php
foreach ($list as $item)
    $heap->insert($item);
```

1.  最后，我们定义了一个`BillionaireTracker::view()`方法（未显示）来遍历堆并显示结果：

```php
$patt = "%20s\t%32s\n";
$line = str_repeat('-', 56) . "\n";
echo $tracker->view($heap, $patt, $line);
```

1.  以下是我们在 PHP 7.1 中运行的小程序产生的输出：

```php
root@php8_tips_php7 [ /repo/ch05 ]# 
php php7_spl_splheap.php
--------------------------------------------------------
           Net Worth                                Name
--------------------------------------------------------
      84,000,000,000                       Ambani,Mukesh
     115,000,000,000                     Arnault,Bernard
      83,600,000,000                       Ballmer,Steve
      ... some lines were omitted to save space ...
      58,200,000,000                          Walton,Rob
     100,000,000,000                     Zuckerberg,Mark
--------------------------------------------------------
                                       1,795,100,000,000
--------------------------------------------------------
```

然而，当我们尝试在 PHP 8 中运行相同的程序时，会抛出错误。以下是在 PHP 8 中运行相同程序的输出：

```php
root@php8_tips_php8 [ /repo/ch05 ]# php php7_spl_splheap.php 
PHP Fatal error:  Declaration of SplHeap@anonymous::compare(array $arr1, array $arr2): int must be compatible with SplHeap::compare(mixed $value1, mixed $value2) in /repo/ch05/php7_spl_splheap.php on line 16
```

因此，为了使其正常工作，我们必须重新定义扩展`SplHeap`的匿名类。以下是代码的部分修改版本：

```php
$heap = new class () extends SplHeap {
    public function compare($arr1, $arr2) : int {
        $cmp1 = array_values($arr2)[0];
        $cmp2 = array_values($arr1)[0];
        return $cmp1 <=> $cmp2;
    }
};
```

唯一的变化在于`compare()`方法的签名。执行时，结果（未显示）是相同的。PHP 8 的完整代码可以在`/repo/ch05/php8_spl_splheap.php`中查看。

这结束了我们对`SplHeap`类的更改的讨论。请注意，相同的更改也适用于`SplMinHeap`和`SplMaxHeap`。现在让我们来看看`SplDoublyLinkedList`类中可能有重大变化的地方。

## 处理`SplDoublyLinkedList`中的更改

`SplDoublyLinkedList`类是一个迭代器，能够以**FIFO**（先进先出）或**LIFO**（后进先出）的顺序显示信息。然而，更常见的是说你可以以正向或反向顺序遍历列表。

这是任何开发者库中非常强大的一个补充。要使用`ArrayIterator`做同样的事情，例如，至少需要十几行代码！因此，PHP 开发者喜欢在需要随意在列表中导航的情况下使用这个类。

不幸的是，由于`push()`和`unshift()`方法的返回值不同，可能会出现潜在的代码中断。`push()`方法用于在列表的*末尾*添加值。另一方面，`unshift()`方法则在列表的*开头*添加值。

在 PHP 7 及以下版本中，如果成功，这些方法返回布尔值`TRUE`。如果方法失败，它返回布尔值`FALSE`。然而，在 PHP 8 中，这两种方法都不返回任何值。如果你查看当前文档中的方法签名，你会看到返回数据类型为`void`。可能会出现代码中断的情况，即在继续之前检查返回`push()`或`unshift()`的值。

让我们看一个简单的例子，用一个简单的五个值的列表填充一个双向链表，并以 FIFO 和 LIFO 顺序显示它们：

1.  首先，我们定义一个匿名类，它继承了`SplDoublyLinkedList`。我们还添加了一个`show()`方法来显示列表的内容：

```php
// /repo/ch05/php7_spl_spldoublylinkedlist.php
$double = new class() extends SplDoublyLinkedList {
    public function show(int $mode) {
        $this->setIteratorMode($mode);
        $this->rewind();
        while ($item = $this->current()) {
            echo $item . '. ';
            $this->next();
        }
    }
};
```

1.  接下来，我们定义一个样本数据的数组，并使用`push()`将值插入到链表中。请注意，我们使用`if()`语句来确定操作是否成功或失败。如果操作失败，将抛出一个`Exception`：

```php
$item = ['Person', 'Woman', 'Man', 'Camera', 'TV'];
foreach ($item as $key => $value)
    if (!$double->push($value))
        throw new Exception('ERROR');
```

这是潜在代码中断存在的代码块。在 PHP 7 及更低版本中，`push()`返回`TRUE`或`FALSE`。在 PHP 8 中，没有返回值。

1.  然后我们使用`SplDoublyLinkedList`类的常量将模式设置为 FIFO（正向），并显示列表：

```php
echo "**************** Foward ********************\n";
$forward = SplDoublyLinkedList::IT_MODE_FIFO
         | SplDoublyLinkedList::IT_MODE_KEEP;
$double->show($forward);
```

1.  接下来，我们使用`SplDoublyLinkedList`类的常量将模式设置为 LIFO（反向），并显示列表：

```php
echo "\n\n************* Reverse *****************\n";
$reverse = SplDoublyLinkedList::IT_MODE_LIFO
         | SplDoublyLinkedList::IT_MODE_KEEP;
$double->show($reverse);
```

这是在 PHP 7.1 中运行的输出：

```php
root@php8_tips_php7 [ /repo/ch05 ]# 
php php7_spl_spldoublylinkedlist.php
**************** Foward ********************
Person. Woman. Man. Camera. TV. 
**************** Reverse ********************
TV. Camera. Man. Woman. Person. 
```

1.  如果我们在 PHP 8 中运行相同的代码，这是结果：

```php
root@php8_tips_php8 [ /home/ch05 ]# 
php php7_spl_spldoublylinkedlist.php 
PHP Fatal error:  Uncaught Exception: ERROR in /home/ch05/php7_spl_spldoublylinkedlist.php:23
```

如果`push()`没有返回任何值，在`if()`语句中 PHP 会假定为`NULL`，然后被插入为布尔值`FALSE`！因此，在第一个`push()`命令之后，`if()`块会导致抛出一个`Exception`。因为`Exception`没有被捕获，会生成一个致命的`Error`。

要将这个代码块重写为在 PHP 8 中工作，您只需要删除`if()`语句，并且不抛出`Exception`。重写后的代码块（在*步骤 2*中显示）可能如下所示：

```php
$item = ['Person', 'Woman', 'Man', 'Camera', 'TV'];
foreach ($item as $key => $value)
    $double->push($value);
```

现在，如果我们执行重写后的代码，结果如下所示：

```php
root@php8_tips_php7 [ /home/ch05 ]# 
php php8_spl_spldoublylinkedlist.php 
**************** Foward ********************
Person. Woman. Man. Camera. TV. 
**************** Reverse ********************
TV. Camera. Man. Woman. Person. 
```

现在您已经了解如何使用`SplDoublyLinkedList`，并且也知道关于`push()`或`unshift()`可能出现的潜在代码中断。您还了解了在 PHP 8 中使用各种 SPL 类和函数可能出现的潜在代码中断。这就结束了本章的讨论。

# 总结

在本章中，您学到了在迁移到 PHP 8 时面向对象编程代码可能出现的问题。在第一节中，您了解到在 PHP 7 和之前的版本中允许许多不良实践，但现在在 PHP 8 中可能导致代码中断。有了这些知识，您将成为一个更好的开发人员，并能够提供高质量的代码来造福您的公司。

在下一节中，您学到了在使用魔术方法时的良好习惯。由于 PHP 8 现在强制实施了在早期版本中没有看到的一定程度的一致性，因此可能会出现代码中断。这些不一致性涉及类构造函数的使用和魔术方法使用的某些方面。接下来的部分教会了您关于 PHP 序列化以及 PHP 8 中所做的更改如何使您的代码更具弹性，并在序列化和反序列化过程中更不容易出现错误或受攻击。

在本章中，您还了解了 PHP 8 对协变返回类型和逆变参数的增强支持。了解了协变的知识，以及在 PHP 8 中支持的改进，使您在开发 PHP 8 中的类继承结构时更具创造性和灵活性。现在您知道如何编写在早期版本的 PHP 中根本不可能的代码。

最后一节涵盖了 SPL 中的许多关键类。您学到了关于如何在 PHP 8 中实现基本数据结构，比如堆和链表的重要知识。该部分的信息对帮助您避免涉及 SPL 的代码问题至关重要。

下一章将继续讨论潜在的代码中断。然而，下一章的重点是*过程式*而不是对象代码。
