# PHP 入门指南（一）

> 原文：[`zh.annas-archive.org/md5/d36bde355b2574844946c8150420db7b`](https://zh.annas-archive.org/md5/d36bde355b2574844946c8150420db7b)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

开发网站是当今的优先事项，以便您的业务在互联网上有所存在。设计和开发是任何网站的基础步骤。PHP 通常用于网站和 Web 应用程序开发。PHP 是一种通用的服务器端脚本语言，旨在创建动态页面和应用程序。PHP 作为 Web 开发选项是安全、快速、可靠的，还提供了许多其他优势，使其可以被许多人接受。我们应该考虑是什么使 PHP 成为 Web 行业中最广泛使用的编程语言之一。

本书通过从变量、数据类型、数组和循环等基本概念开始，使您迅速掌握基本概念。然后逐渐进展到更高级的概念，如构建自己的框架和创建应用程序。

本书旨在缩小学习和实施之间的差距。它提供了许多真实的业务案例场景，这将帮助您理解概念，并在完成本书后立即开始编写 PHP 程序。

# 本书涵盖内容

第一章，“PHP 入门”，介绍了使用 PHP 编程语言的基本知识。在本章中，您将学习基本的 PHP 语法和程序结构。您还将学习如何使用变量、数据类型、运算符和条件语句。

第二章，“数组和循环”，向您展示如何使用流程控制结构。本章将特别介绍循环和数组。

第三章，“函数和类”，教你如何定义和调用函数。我们还将介绍如何创建类，以及如何将类和函数一起使用。

第四章，“数据操作”，教你如何处理用户输入并将结果返回给他们，优雅地处理错误，并学习使用 MySQL 数据库的基础知识。

第五章，“构建 PHP Web 应用程序”，教你在框架中应用面向对象的概念。我们将介绍使用 Whoops 库进行错误报告，并学习如何处理这些错误。我们还将介绍如何在框架中管理和构建我们的应用程序。

第六章，“构建 PHP 框架”，教你从零开始构建一个 MVC 框架。从一个空目录开始，我们将构建一个完整的工作框架，作为更复杂应用程序的起点。

第七章，“身份验证和用户管理”，教你项目的安全方面，即身份验证。我们将构建登录表单，与数据库交互以验证用户的身份。我们还将介绍如何在我们的应用程序中设置密码恢复机制。

第八章，“构建联系人管理系统”，教你构建一个联系人 CRUD（创建、读取、更新和删除）部分，其中将有一个查看页面来查看单个联系人。我们还将为我们的联系人应用程序构建评论系统。

# 本书所需内容

## 硬件

最低硬件要求如下：

+   Windows 7 64 位

+   处理器：英特尔酷睿处理器

+   内存：1GB RAM

+   互联网连接

## 软件

+   Windows 的 WAMP 服务器

+   Linux 的 LAMP 服务器

+   Mac 的 MAMP 服务器

+   浏览器：一个或多个浏览器的最新版本（推荐使用 Internet Explorer 11 或 Chrome 54.0.2840 或更新版本）

+   诸如记事本或 Notepad++之类的文本编辑器

# 本书适合人群

本书适用于任何有兴趣学习 PHP 编程基础知识的人。为了获得最佳体验，您应该具备 HTML、CSS、JavaScript 和 MySQL 的基本知识。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义解释。

文本中的代码词、数据库表名、文件夹名称、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下："创建一个新文件并将其命名为 syntax.php。"

文件夹名称、文件名、文件扩展名、路径名、文本中包含的包含文件名显示如下："要从数组中删除一个元素，请使用 unset 函数。

一段代码设置如下：

```php
<?php  
  echo "Hello World"; 
?> 
```

任何命令行输入或输出都以以下方式书写：

```php
php syntax.php
```

新术语和重要词汇以粗体显示。屏幕上看到的词语，例如菜单或对话框中的词语，会以这种方式出现在文本中："因此，当我们点击**提交**按钮时，数据将被提交。"

重要的新**编程术语**以粗体显示。*概念术语*以斜体显示。

### 注意

警告或重要提示会以这种方式出现在一个框中。

### 提示

提示和技巧会以这种方式出现。

# 安装和设置

在开始阅读本书之前，我们将安装一个 PHP 服务器，比如 WAMP，以及一个文本编辑器，比如 Atom。

# 在 Windows 上安装 WAMP

1.  在浏览器中访问[`www.wampserver.com/en/`](http://www.wampserver.com/en/)。

1.  点击**WAMP SERVER 64 位或 WAMP SERVER 32 位**，根据您的系统选择。

1.  接下来，将会弹出一个窗口，其中会出现一些警告。点击**直接下载**。

1.  下载后打开安装程序。

1.  按照安装程序中的步骤，就完成了！您的 WAMP 服务器已经准备就绪。

# 在 Linux 上安装 LAMP

1.  在浏览器中访问[`bitnami.com/stack/lamp/installer`](https://bitnami.com/stack/lamp/installer)。

1.  在**Linux**下，点击**下载**按钮。

1.  接下来，将会弹出一个窗口，其中会给您一些登录选项。只需点击**不，谢谢，直接带我去下载**选项。

1.  下载后打开安装程序。

1.  按照安装程序中的步骤，就完成了！您的 LAMP 服务器已经准备就绪。

# 在 MAC OS 上安装 MAMP

1.  在浏览器中访问[`www.mamp.info/en/`](https://www.mamp.info/en/)。

1.  在 MAMP 下，点击**下载**按钮。

1.  在下一页，点击**macOS**，然后点击**下载**按钮。

1.  下载后打开安装程序。

1.  按照安装程序中的步骤，就完成了！您的 MAMP 服务器已经准备就绪。

# 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载示例代码文件，用于您购买的所有 Packt Publishing 图书。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

本书的代码包也托管在 GitHub 上，网址为[`github.com/TrainingByPackt/Beginning-PHP/`](https://github.com/TrainingByPackt/Beginning-PHP/)。如果代码有更新，将在现有的 GitHub 存储库中进行更新。


# 第一章：PHP 入门

PHP，或者预处理超文本，是一种用于设计网页应用程序并使网站看起来更直观和有趣的编程语言。多年来，PHP 也在服务器端脚本语言方面获得了很大的流行。PHP 是一种易于使用但功能强大的语言。PHP 可以在多个操作系统上运行，并支持多个服务器。PHP 的所有这些特性使其成为网页设计语言的理想选择。

本书将带你了解 PHP 的基础知识，包括声明语法、声明和使用变量和数据类型、运算符和条件语句。然后，它将涵盖构建 PHP 框架的原则以及构建自己的 PHP 网页应用程序。

在本章中，你将开始学习 PHP 编程语言的基本知识。我们将涵盖语法以及如何在 PHP 中声明和使用变量。我们还将看看如何使用`if`语句控制执行流程。

在本章结束时，你应该能够使用这些元素编写简单的程序。

在本章结束时，你将能够：

+   使用 PHP 的基本语法编写简单的程序

+   使用变量存储不同的数据，并使用不同的运算符进行操作

+   使用条件语句来控制执行流程

# 基础知识

我们将从查看 PHP 语法和执行我们的第一个文件开始。让我们开始吧。

在 PHP 中，语法非常重要；你需要适当的语法让你的服务器知道它应该从哪里开始解析 PHP，并且你必须通过开放和关闭 PHP 标签来显示它，如下所示：

```php
<?php

?>
```

通过使用 PHP 标签，你可以在文档的任何地方添加你的代码。这意味着如果你有一个 HTML 网站，你可以添加标签以及一些 PHP 代码，它就会被处理。除了使用开放和关闭 PHP 标签，你还必须在文件中使用`.php`扩展名。

让我们从一个快速示例开始。

## 使用 PHP 显示"Hello World"

在本节中，我们将利用我们到目前为止学到的知识来向用户显示一个字符串：

1.  打开你的代码编辑器。

1.  创建一个新文件并命名为`syntax.php`。

1.  输入以下内容，并保存你的文档：

```php
<?php

?>
```

1.  在**终端**中打开你的工作目录。

1.  输入以下命令：

```php
php syntax.php
```

![使用 PHP 显示"Hello World"](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/1_01.jpg)

1.  切换回你的文档并输入以下内容：

```php
<?php 
     echo "Hello World";
?>
```

1.  回到终端并输入以下内容：

```php
php syntax.php
```

现在你应该在屏幕上看到字符串"Hello World"被打印出来。

## 变量和数据类型

为了开始学习 PHP，我们必须首先看一下将用于构建每个项目的核心构建块。在我们的应用程序中，我们总是需要一种临时存储数据的方法（在我们的情况下，我们称之为存储方法变量）。

变量定义如下：

```php
$VARIABLENAME = "VALUE";
```

如你在上面的例子中所见，变量以`$`符号开头，后面跟着变量名，使用赋值运算符赋值。在这里，我们有一个名为`VARIABLENAME`的变量，其字符串值为`VALUE`。

### 注意

变量名不能以数字或特殊符号开头，除了用于定义变量本身的`$`符号。

PHP 是少数几种不需要在赋值之前声明数据类型的语言之一。

| **类型** | **示例** |
| --- | --- |
| 字符串 | "Hello World" |
| 数字 | 123 |
| 浮点数 | 1.095 |
| 布尔值 | TRUE 或 FALSE |

我们现在将尝试在 PHP 中实现变量。

## 使用变量

在本节中，我们将举例说明在程序中使用变量的真实例子。我们将首先创建一个变量来存储用户的姓名：

1.  打开你的代码编辑器。

1.  创建一个新文件并命名为`variables.php`。

1.  输入以下内容，并保存你的文档：

```php
<?php
	$name = "John Doe";
	$age = 25;
	$hourlyRate = 10.50;
	$hours = 40;
	echo $name . " is " . $age . " years old.\n";
	echo $name . " makes $" . $hourlyRate . " an hour. \n";
	echo $name . " worked " . $hours . " this week. \n";
?>

```

1.  在终端中打开你的工作目录。

1.  输入以下命令，然后按*Enter*：![使用变量](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/1_02.jpg)

### 注意

将变量的值插入字符串的另一种方法是使用特殊的语法：

```php
<?php
echo "My name is ${$name}.";
?>
```

## 运算符

我们现在将看一下 PHP 中可用的各种运算符。

### 比较运算符

在变量部分，我们看到了=符号，在 PHP 中被称为赋值运算符。这个运算符正如其名，允许您给变量赋值。首先是比较运算符。比较运算符允许您在给定的条件情况下比较两个值。

在比较运算符集合中包括等于、相同、不等、不相同、小于和大于运算符。

| 用法 | 名称 | 描述 |
| --- | --- | --- |
| `$a == $b` | 等于 | 如果`$a`等于`$b`，则为 TRUE。 |
| `$a === $b` | 相同 | 如果`$a`等于`$b`，并且它们是相同类型，则为 TRUE。 |
| `$a!= $b` | 不等 | 如果`$a`不等于`$b`，则为 TRUE。 |
| `$a!== $b` | 不相同 | 如果`$a`不等于`$b`，或它们不是相同类型，则为 TRUE。 |
| `$a < $b` | 小于 | 如果`$a`严格小于`$b`，则为 TRUE。 |
| `$a > $b` | 大于 | 如果`$a`严格大于`$b`，则为 TRUE。 |
| `$a <= $b` | 小于或等于 | 如果`$a`小于或等于`$b`，则为 TRUE。 |
| `$a >= $b` | 大于或等于 | 如果`$a`大于或等于`$b`，则为 TRUE。 |

### 逻辑运算符

接下来是逻辑运算符。逻辑运算符用于一次检查多个情况。逻辑运算符集合包括`NOT`、`AND`和`OR`运算符。

| 用法 | 名称 | 描述 |
| --- | --- | --- |
| `! $a` | NOT | 如果`$a`不为 TRUE，则为 TRUE。 |
| `$a && $b` | AND | 如果`$a`和`$b`都为 TRUE，则为 TRUE。 |
| `$a &#124;&#124; $b` | OR | 如果`$a`或`$b`中的一个为 TRUE，则为 TRUE。 |

### 数学运算符

在您的程序中，有时需要进行一些数学运算；这就是数学运算符发挥作用的地方。它们使您能够对两个数进行加法、减法、乘法、除法，并得到两个数相除的余数。

| 用法 | 名称 | 描述 |
| --- | --- | --- |
| `$a + $b` | 加法 | `$a`和`$b`的和 |
| `$a - $b` | 减法 | `$a`和`$b`的差 |
| `$a * $b` | 乘法 | `$a`和`$b`的乘积 |
| `$a / $b` | 除法 | `$a`和`$b`的商 |
| `$a % $b` | 模数 | `$a`除以`$b`的余数 |

让我们尝试在 PHP 中使用这些运算符。

## 组合变量和运算符

在本节中，我们将扩展我们之前的示例，计算用户的年薪。以下是步骤：

1.  打开您的代码编辑器。

1.  创建一个新文件，并将其命名为`operators.php`。

1.  要开始，请复制我们的`variables.php`文档中的内容。

1.  现在，我们将在文档中添加一个额外的变量，用于保存周数：

```php
$weeks = 52;
```

1.  接下来，我们将使用乘法运算符来计算我们的周薪，并将其赋值给一个新变量：

```php
$weeklyPay = $hourlyRate * $hours;
```

1.  现在，有了我们的周薪率，我们可以计算我们的工资：

```php
$salary = $weeks * $weeklyPay;
```

1.  我们的最后一步是显示我们的最终计算：

```php
echo $name . " will make $" . $salary . " this year.\n";
```

您的最终文档应如下所示：

```php
<?php
$name = "John Doe";
$age = 25;
$hourlyRate = 10.50;
$hours = 40;
echo $name . " is " . $age . " years 01d.\n";
echo $name . " makes $" . $hourlyRate . " an hour. \n";
echo $name . " worked " . $hours . " this week.\n";
$weeks = 52;
$weeklypay = $hourlyRate * $hours;
$salary = $weeks * $weeklyPay;
echo $name . " will make $" . $salary . "this year";
?>
```

1.  接下来，我们将在我们的`终端`中打开我们的目录，并运行以下命令：

```php
php operators.php
```

1.  现在我们应该看到我们的数据被显示出来：![组合变量和运算符](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/1_03.jpg)

## 条件语句

现在我们已经掌握了运算符的基础，我们可以开始在所谓的条件语句中使用它们。条件语句允许您控制程序的流程，它们采用`if`语句的形式。

基本的`if`语句表示如下：

```php
if (conditional){

}
```

在括号内，您将保存激活大括号内代码所需的条件。

此外，您可以添加一个`else`语句，这将允许您在条件不满足时运行替代代码：

```php
if(conditional){

}
else{
}
```

![条件语句](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/1_04.jpg)

### 注意

与条件语句一起使用的一个有用的函数是`empty`函数。`empty`函数用于检查变量是否为空

### 使用条件语句

在本节中，我们将实现条件语句，我们将检查动物的名称，如果匹配，我们将打印特定动物的声音。

1.  打开您的代码编辑器。

1.  创建一个新文件并命名为`conditionals.php`。

1.  我们将从添加我们的开放和关闭`php`标签开始：

```php
<?php
?>
```

1.  然后，我们将创建一个新函数来保存我们的动物名称：

```php
<?php
$animal = "cat";
?>
```

1.  现在，我们可以编写我们的第一个条件语句；在这里，我们要检查动物是否是猫，如果是，我们将向用户打印 meow：

```php
<?php
	$animal = "cat";
	if($animal == "cat"){
	echo "meow\n";
	}
?>
```

1.  保存文件并在终端中打开您的工作目录。

1.  运行以下命令，查看结果：

```php
php conditionals.php
```

![使用条件语句](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/1_05.jpg)

1.  现在，我们将进一步扩展我们的条件语句，添加其他动物的声音，并将我们的动物更改为狮子：

```php
$animal = "lion";
if($animal == "cat"){
echo "meow\n";

}
else if ($anima == "dog"){
echo "woof\n";
}

else if($animal == "lion"){
echo "roar\n";

}

else {
echo "What does the fox say?\n";
}

?>
```

1.  现在，让我们再次保存并在终端中运行命令；您应该会得到以下结果：![使用条件语句](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/1_06.jpg)

## 活动：构建员工工资计算器

想象一下，您是一家百货商店连锁店的 PHP 开发人员，该商店正在为即将到来的黑色星期五大甩卖做准备。在大甩卖期间工作的员工将获得加班工资，以及所有销售额的 10%提成。此外，如果他们的总销售额超过 1000 美元，他们将获得 1000 美元的奖金。管理层希望您创建一个计算器，使员工能够轻松计算他们赚了多少钱。

这项活动的目的是帮助您了解变量和条件语句。

按照以下步骤操作：

1.  创建一个新目录并命名为`salary_calculator`。

1.  在新目录中创建一个`index.php`文件。

1.  定义占位符变量：

```php
<?php

    $hourlyRate = 10.00;
    $hoursWorked = 12;
    $rateMultiplier = 1.5;
    $commissionRate = 0.10;
    $grossSales = 25.00;
    $bonus = 0;
```

1.  我们的下一步将是定义我们的计算并将结果分配给它们各自的变量：

```php
$holidayRate = $hourlyRate * $rateMultiplier;
    $holidayPay = $holidayRate * $hoursWorked;
    $commission = $commissionRate * $grossSales;
$salary = $holidayPay + $commission;
```

1.  接下来，我们需要检查总销售额变量，看看员工是否超过了 1000 美元，以获得奖金：

```php
if($grossSales >= 1000){
        $bonus = 1000;
}
```

1.  现在我们有了默认费率和计算器，我们可以向用户显示结果：

```php
echo "Salary $" . $salary . "\n";
    echo "Bonus +\$" . $commission . "\n";
    echo "-------------------------------\n";
    echo "Total  $" . ($salary + $commission) . "\n";
```

1.  现在，员工只需更改其小时工资和总销售额的值，并运行程序以获取其总工资金额。

# 总结

我们现在已经到达了本章的结尾。在本章中，我们从 PHP 语法开始。然后，我们转向变量和在 PHP 中使用的不同运算符。最后，我们看到了如何实现条件语句并控制执行流程。

现在，您应该清楚地了解了变量、数据类型和条件语句，以及它们如何一起使用。在下一章中，您将了解 PHP 中如何实现数组和循环。


# 第二章：数组和循环

在上一章中，我们讨论了变量和数据类型以及不同的运算符。我们还讨论了如何使用条件控制程序的流程。在本章中，我们将重点讨论如何使用数组存储多个值以及如何使用循环控制流程。数组的基本思想是它是一种变量类型，允许将多个项目存储在一个“容器”中。

例如，如果您想要将公司中所有员工的姓名存储在同一个变量下，数组将帮助您实现这一点。当我们想要多次运行相同的代码块时，使用循环。这通过重用预定义的代码块为开发人员节省了大量工作。这两个概念几乎是今天几乎每个基于 PHP 的 Web 应用程序和网站的核心。

在本章结束时，您将能够：

+   实现一维和多维数组

+   识别索引数组和关联数组之间的区别

+   对数组执行不同的操作

+   实现各种类型的循环

# 数组

在本节中，我们将讨论各种类型的数组，然后查看一些常见的操作。

## 索引数组

索引数组是您将看到的最常见的数组类型，它们可以被定义为预填充或空的。

可以按以下方式定义空数组：

```php
<?php

    $the_array = array();

?>
```

### 注意

请注意，`$the_array`是一个变量。您可以使用任何其他变量。

使用快捷语法的另一种方法：

```php
<?php
    $the_array = [];
?>
```

如果要使用值初始化数组，可以按以下方式执行：

```php
<?php

    $students = array("Jill", "Michael", "John", "Sally");

?>
```

当您使用预填充值初始化数组时，每个元素都会获得一个数字索引，从 0 开始。因此，在前面的例子中，Jill 的索引将为 0，Michael 的索引将为 1，John 的索引将为 2，Sally 的索引将为 3。

要打印`students`数组的第一个索引，可以使用以下代码：

```php
<?php

    echo $students[0];    

?>
```

通常，当您使用数组时，希望在程序运行过程中添加到数组中。可以通过以下两种方式之一完成：

`append`快捷方式：

```php
<?php

    $students[] = "Tom";

?>
```

或`array_push`函数：

```php
<?php

    array_push($students, "Tom", "Joey");

?>
```

通常，开发人员使用快捷方法；如果要一次将多个记录推送到数组中，可以使用`array_push`函数。

有时，您可能需要从数组中删除一个元素。要从数组中删除一个元素，使用`unset`函数。在下面的例子中，我们从数组中删除了“Tom”：

```php
<?php

    unset($students[4]);

?>
```

在继续之前，我们将讨论最后一个部分，即更新一个元素。要这样做，请执行以下操作：

```php
<?php

    $students[0] = "Jessie";

?>
```

## 关联数组

接下来是关联数组，也称为键值对。使用关联数组，您可以使用基于文本的键来存储值，这在特定情况下可能会有所帮助。例如，如果我们从前面的例子中取一个学生（在这种情况下是 Michael），我们可以存储他的`age`，`gender`和`favorite color`，如下所示：

```php
<?php
    $michael = array(
    "age" => 20,
    "gender" => "male",
    "favorite_color" => "blue"
);
?>
```

如果需要访问数组中的特定值，可以使用`key`。例如，如果我们想打印 Michael 的年龄，可以这样做：

```php
<?php

    echo $michael['age'];
?>
```

向`associative`数组添加数据与向索引数组添加数据一样简单。您只需使用键并分配一个值。假设我们要向 Michael 的数组添加一个职业：

```php
<?php
    $michael["occupation"] = "sales associate";
?>
```

要从关联数组中删除一个元素，请按照我们在`indexed`数组中所做的相同步骤，但这次使用键。

让我们删除我们在上一步中添加的职业：

```php
<?php
    unset($michael['occupation']);
?>
```

## 使用数组

在本节中，我们将包括`name`，`age`，`location`和`education level`。请按照以下步骤：

1.  打开您的代码编辑器并创建一个新文件`arrays.php`。

1.  在新文件中，创建您的`php`标签：

```php
<?php
?>
```

1.  现在，我们将创建一个新变量，称为`$myinfo`，并用一个新数组初始化它：

```php
<?php
	$myinfo = array();
?>

```

1.  然后，我们将使用我们的`name`，`age`，`location`和`education level`填充新数组。

1.  接下来，我们将打印我们的数据：

```php
<?php
	$myinfo = array("John", 25, "USA", "College");
	echo "My name is " . $myinfo[0] . "\n";
	echo "I am ". $myinfo[1] . " years old. \n";
    echo "I live in " . $myinfo[2] . "\n";
	echo "My latest education level is " . $myinfo[3];
?>

```

1.  在终端中打开您的工作目录，并键入以下命令：

```php
php arrays.php
```

您将获得如下输出所示的结果：

```php
My name is John.
I am 25 years old.
I live in USA.
My latest education level is College.
```

## 将字符串转换为数组

有时，在构建基于 PHP 的应用程序时，您不会使用预定义的数据集来实例化数组-例如在构建实用程序脚本时。假设您有一个包含文件名字符串版本的变量，并且希望获取不带扩展名的文件名。通过使用`explode`函数，可以轻松完成此任务。`explode`函数接受两个参数：分隔符和要转换为数组的字符串。`Explode`函数接受两个参数：

```php
<?php
    $filename = "myexamplefile.txt";
    $filename_parts = explode(".", $filename);

    echo "Your filename is " . $filename_parts[0];
?>
```

在前面的例子中，我们定义了一个文件名变量，然后使用 explode 函数，使用句点分隔符将字符串分解为其部分。`$filename_parts`变量包含两个元素的数组，第一个是字符串`myexamplefile`，第二个包含字符串`txt`。

知道这一点，我们可以通过访问字符串部分的 0 索引来打印出文件名。

## 将数组合并为字符串

除了`explode`函数之外，PHP 还为我们提供了一个允许我们执行完全相反操作的函数：`implode`函数。当您想要获取现有数组并将其转换为字符串时，可以使用 implode 函数来定义分隔符并将其传递给数组；您将获得一个单个字符串作为结果。

让我们回到`explode`的例子。假设我们有一个文件名，并希望在将其保存回字符串之前在其末尾附加一些其他字符串：

```php
<?php
    $filename = "myexamplefile.txt";
    $filename_parts = explode(".", $filename);
    $filename_parts[0] .= "_v1";

    $filename = implode(".", $filename_parts);
    echo "Your new filename is " . $filename;    

?>
```

在前面的代码示例中，我们首先使用 explode 函数将原始文件名分解为其部分。然后，我们访问文件名部分并在其末尾附加字符串 _v1。使用 implode 函数，我们使用其部分重新组合文件名，最后，我们将其打印回屏幕供用户查看。

## 切片数组

另一个`array_slice`函数；默认情况下，该函数只需要两个参数，但可以接受四个。两个必需的参数是数组本身和新数组的起始点。两个可选参数是新数组的长度（或要包含的元素数）和保留选项。保留选项允许您决定当前数组元素是保持不变还是在拆分后重新排序。以下是一个基本的使用示例：

```php
<?php
    $fruit = array("apples","grapes", "oranges", "lemons","limes");
    $smallerFruitArray = array_slice($fruit, 2);
?>
```

在前面的例子中，当我们通过`array_slice`运行水果数组时，我们将获得一个包含橙子、柠檬和酸橙的数组。

## 对数组进行排序

排序是构建某些类型的程序的另一个重要工具。您经常在 PHP 中看到的排序函数之一是`ksort`函数。`ksort`允许您将数组作为参数传递，然后按升序对其进行排序。

如何使用的示例如下：

```php
<?php

    $people = array("Jessica" => "35", "April" => "37", "John" => "43", "Tom" => 25);
ksort($people);

?>
```

在前面的例子中，我们有一个人的数组。一旦您将人们数组通过`ksort`函数，您应该会看到按字母顺序排列的名称。

## 多维数组

下一个类型是`多维`数组。多维数组只是数组中的数组。在我们之前的数组示例中，我们存储了一个学生的名字。当我们想要为特定学生存储多个详细信息时会发生什么？这就是多维数组发挥作用的地方。让我们看看如何定义一个还存储学生的`性别`和`最喜欢的` `颜色`的学生数组：

### 注意

要查看完整的代码片段，请打开代码文件中的`Lesson 2.php`。

```php
<?php

    $students = array(
    "Jill" => array(
    "age" => 20,
    "gender" => "female",
....
"Amy" => array(
   "age" => 25,
   "gender" => "female",
   "favorite_color" => "green"
),

);
?>
```

如果我们想要访问学生的信息，我们可以使用以下键：

```php
    <?php 

        echo $students['Jill']['age'];

?>
```

前面的例子将打印出 Jill 的年龄。对于多维数组，我们更新元素值的方式基本上与使用一维数组时相同。

例如，如果我们想将 Jill 的年龄更改为`21`，我们执行以下操作：

```php
<?php

        $students['Jill']['age'] = 21;
    ?>
```

## 在我们现有项目中包含一个爱好数组

在这一部分，我们将扩展前面的例子，包括一个爱好数组：

1.  打开你的代码编辑器并创建一个新文件`multidimensional.php`。

1.  在新文件中，创建你的开启和关闭`php`标签。

1.  创建一个名为`$user`的新变量，并用一个新数组进行初始化：

```php
<?php
	?>
<?php
	$user = array();
?>
```

1.  用两个主要部分填充新数组：`info`和`hobbies`。在 info 数组中，存储`name`，`age`，`location`和`education level`，在`hobbies`数组中，我们将存储三个爱好。

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 2.php`文件。

```php
<?php    $user = array(
        "info" => array(
            "name" => "john",
            "age" => 27,
...
        )
    );
?>
```

1.  接下来我们将打印我们的数据：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 2.php`文件。

```php
<?php$user = array(
        "info" => array(
            "name" => "john",
            "age" => 27,
            "location" => "USA",
.....
   echo "I live in " . $user["info"]['location'] . ".\n";
   echo "My latest education level is " .   
   $user['info']['education_level']. ".\n";

echo "I enjoy " . $user["hobbies"][0] . ", "  . 
$user["hobbies"]

[1] . ", " . $user["hobbies"][2].".\n";

?>
```

1.  在终端中打开你的工作目录，并输入以下命令：

```php
php multidimensional.php
```

你将得到一个基于我们在前面数组中提供的输入的结果。

# 循环

循环是任何编程语言中强大的工具。它们允许你编写可以根据给定条件执行特定次数的代码。在本节中，你将学习到各种可用的循环，如 for 循环、foreach 循环、`while`循环和`do-while`循环。

## for 循环

我们将从`for`循环开始探索循环。它被认为是最复杂的循环结构，当你知道需要一段代码运行多少次时就会使用它。for 循环的结构如下：

```php
<?php

    for(initialized counter; test if true; increment counters){

}

?>
```

创建`for`循环的步骤如下：

1.  初始化起始计数变量 - 通常会从`0`开始。

1.  提供一个解析为`true`或`false`的评估条件。如果条件为`true`，循环将继续，如果条件为`false`，循环将退出（或中断）。

1.  按照特定数字递增值。通常，它会递增`1`。

这里有一个完整的例子：

```php
<?php
        for($i = 0; $i < 5; $i++) {
            echo "Current Count: " . $i; 
}
?>
```

## 结合循环和数组

在这一部分，我们将探索如何结合循环和数组。以下是实现它的步骤：

1.  打开你的代码编辑器并创建一个新文件`forloop.php`。

1.  在新文件中，创建你的开启和关闭`php`标签：

```php
<?php
?>
```

1.  现在，我们创建一个名为`$food`的新变量，并用一个新数组进行初始化：

```php
<?php
	$food = array();
?>
```

1.  然后，我们用食物名称填充新数组：

```php
<?php    $food = array("turkey", "milk", "apples");
?>
```

1.  接下来，我们循环遍历我们的数组并打印我们的数据：

```php
<?php
	$food = array("turkey", "milk", "apples");

           for($i = 0; $i < count($food); $i++){
        echo $food[$i] . "\n";
 }
?>
```

### 注意

count 函数返回数组中的元素数。

在终端中打开你的工作目录，并输入以下命令：

```php
php forloops.php
```

## while 循环

我们将要探索的下一个循环是 while 循环。当你想要循环执行一段代码直到满足特定条件时，就会使用 while 循环。while 循环的定义如下：

```php
<?php

    while(condition) {
}

?>
```

while 循环非常简单，因为它只需要一个条件来运行。循环将一直持续，直到条件为 false。

![while 循环](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/2_01.jpg)

这里有一个简单的例子：

```php
<?php
    $count = 1;
    while($count < 25){
        echo "Count: " . $count . "\n";

        $count += 1;
}

?>
```

我们取前面的`count`变量并赋值为 1。`while`条件检查`count`变量是否小于 25，并且一旦`counter`变量等于 25，就会中断。在 while 函数内部，我们输出当前计数，然后递增`count`变量 1。

## 使用 while 函数

在这一部分，我们将构建一个`while`函数，它将在`counter`小于 30 的情况下进行迭代。按照以下步骤进行：

1.  打开你的代码编辑器并创建一个新文件`while.php`。

1.  在新文件中，创建你的开启和关闭`php`标签：

```php
<?php
?>
```

1.  接下来，我们定义一个`counter`函数，并用数字 1 进行初始化：

```php
<?php
$count = 1;
?>
```

1.  然后，我们可以创建一个`while`循环，它将输出当前计数，然后将`counter`增加 1：

```php
<?php

        $count = 1;

        while($count <= 30){
            echo "Count " . $count . "\n";
            $count++;
        }
?>
```

1.  在终端中打开你的工作目录，并输入以下命令：

```php
php while.php
```

## do-while 循环

do-while 循环与 while 循环类似，但它不是在循环开始时运行条件，而是在内部代码块运行后检查条件。其思想是，如果你需要至少运行一次代码块，就使用这个循环而不是 while 循环。

### 注意

do-while 循环也称为退出控制循环。

do-while 循环的表示如下：

```php
<?php

    do{

}while(condition);

?>
```

我们将修改之前的 while 循环：

```php
<?php
    $count = 1;
    do{
        echo "Count: " . $count . "\n";

}while($count <= 25);
?>
```

## 将 while 循环转换为 do-while 循环

在本节中，我们将复制前面的示例，但将 while 循环转换为 do-while 循环，以便您可以看到它们的功能差异。按照以下步骤进行：

1.  创建一个新文件并将其命名为`dowhile.php`。

1.  接下来，打开`while.php`文件，并将内容复制到`dowhile.php`文件中。

1.  现在，我们将修改`while`函数以使其类似于以下代码：

```php
<?php

        $count = 1;

        do{
            echo "Count " . $count . "\n";
            $count++;
        }while($count <= 30);
?>
```

1.  在终端中打开您的工作目录，并输入以下命令：

```php
php dowhile.php
```

## foreach 循环

接下来是 foreach 循环。foreach 循环旨在为程序员提供一种简单的方法来遍历数组。这个循环只能用于数组和对象，这些您将在本书后面学习。这个循环有两种语法：

```php
<?php

    foreach($array as $value){

    }

?>
```

第一个语法接受一个给定的数组，并遍历数组中的每个元素，将其分配给次要变量。例如：

```php
<?php
        $students = array("Jill", "John", "Tom", "Amy");

        foreach($students as $student){
            echo $student . "\n";
}
?>
```

在前面的示例中，我们定义了一个填充有学生姓名的数组。然后，我们使用 foreach 循环遍历我们的`students`数组，并`echo`出每个姓名。

第二种语法写成如下：

```php
<?php
    foreach($array as $key => $value){

}
?>
```

在这个版本的`for each`函数中，给定的数组被遍历，但不是给出单个元素，而是同时给出`key`和`element`本身。以下是我们将如何使用它的示例：

### 注意

有关完整的代码片段，请参阅代码文件夹中的`Lesson 2.php`文件。

```php
<?php

    $students = array(
    "Jill" => array(
    "age" => 20,
    "favorite_color" => "blue"
),
.....
);

   foreach($students as $name => $info){
    echo $name . "'s is " . $info['age'] . " years old\n";
}
?>
```

在此示例中，我们定义了一个存储每个学生年龄和最喜欢的颜色的多维数组，并使用学生的姓名作为索引。然后，我们使用`foreach`函数遍历`students`数组，并将每个元素的键分配给`name`变量，将学生的信息分配给`info`变量。在循环内，我们`echo`出学生的姓名，以及他们的年龄。

## 活动：使用 foreach 循环

让我们将对于每个循环的理解付诸实践。

您的经理要求您创建一个 PHP 脚本，根据他们的工资计算每个员工每月赚多少钱。

您要做的是：

1.  创建一个新目录并命名为`monthly_payment`。

1.  在新目录中，创建一个`index.php`文件。

1.  首先，您将定义一个多维数组，用于存储员工的姓名、职称和工资：

```php
<?php

$employees = array(
    array( 
       "name" => "John Doe",
        "title" => "Programmer",
        "salary" => 60000
....
        "title" => "Manager",
        "salary" => 132000
    )
);
?>
```

1.  接下来，定义`foreach`循环，它将遍历`employee`数组：

```php
foreach($employees as $employee){
}
```

1.  最后，添加一个`echo`语句，用于打印姓名、职称和计算出的月薪：

```php
foreach($employees as $employee){
     echo $employee['name'] . "(" . $employee['title'] . ") annual salary is $" .  
     $employee['salary'] . " and earns $" . ($employee['salary'] / 12) . "/mo. \n";
       }
```

计算器脚本现在已经完成。如果您需要添加额外的员工，只需添加一个带有员工信息的额外关联数组即可。

# 总结

我们已经到了第二章的结尾。在这一章中，我们看到了如何声明和定义数组，并涵盖了不同类型的数组。我们看到了可以对数组执行的各种操作。我们还涵盖了诸如 for 循环、while 循环和 do while 循环之类的控制流语句。

在下一章中，我们将学习如何使用函数和类实现代码的可重用性，让您离构建自己的定制应用程序更近一步。


# 第三章：函数和类

在上一章中，我们看到了如何声明和定义数组，并涵盖了多种类型的数组，如索引数组、关联数组等。我们还看到了可以对数组执行的各种操作。

在本章中，我们将了解如何定义和调用函数。我们还将学习如何创建类，以及如何将类和函数一起使用。

函数是打包成可重复使用代码的代码块。函数是一段代码，通过进行一些处理，获取一个或多个输出来返回一个值。

类是对象的蓝图。类形成数据的结构和利用信息创建对象的操作。

在本章结束时，您将能够：

+   定义和调用函数

+   定义类并使用`new`关键字创建类的实例

+   实现和调用`public`和`static`类函数

# 函数

函数就像一个具有固定定义逻辑的机器。在一端，它接受一个参数，对其进行处理，并根据输入和函数定义返回一个值。

函数用于重复使用特定的代码块，而不是在需要时一直定义它：

![函数](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/3_01.jpg)

要定义函数，我们使用关键字`function`，后跟我们要给函数的名称；在花括号内，我们定义函数的操作。例如，如果我们想创建一个打印“Hello World”的函数，我们写如下：

```php
<?php
    function HelloWorld(){
        echo "Hello World";
    }
?>
```

如果我们将这个函数写在一个新文件中并运行它，它不会显示任何内容，这是因为我们还没有调用函数；我们只是定义了它。

要调用函数，我们添加以下代码行：

```php
<?php
HelloWorld();
?>
```

在创建函数时，有时需要将附加参数传递给您的函数；这可以在定义新函数时完成。

让我们修改前面的示例以接受一个`name`参数：

```php
<?php
    function HelloWorld($name){
        echo "Hello World, " . $name;
}
?>
```

要传递名称，我们在函数名后面的括号内定义一个变量。

现在，当我们调用函数时，我们可以通过该变量传递任何值，并且它将被打印出来。

```php
<?php
    HelloWorld("John");
?>
```

有时，当我们创建一个函数时，我们知道会有一些情况下我们不会传递一个值。在这些情况下，我们希望自动传递一个默认值。

要设置默认值，您应该在设置变量时将其分配给指定的变量，如下所示：

```php
<?php
    function displayMessage($message = "World"){
        echo "Hello " . $message;
}
displayMessage();
displayMessage("Greg");
?>
```

函数不仅可以用于将消息打印到屏幕上，还可以返回一个值，该值可以存储在变量中或用于另一个函数。例如，如果您创建一个加法函数，您可能希望返回总和：

```php
<?php
    function addNumbers($a, $b){
        return $a + $b;
}
echo addNumbers(5,6);
?>
```

现在我们有一个可以返回值的函数，让我们看看如何使用它来存储一个值：

```php
<?php
    $sum = addNumbers(1,2);
?>
```

### 注意

在您的程序中，您有时可能需要以高效的方式动态调用函数。PHP 为您提供了一个有用的工具来做到这一点-`call_user_func_array`。`call_user_func_array`函数允许您通过将其名称作为第一个参数传递来调用函数，并通过第二个参数以数组的形式提供参数。

# 创建一个简单的函数

在本节中，我们将创建一个简单的函数，用于计算给定百分比的折扣。要做到这一点，请按照以下步骤进行：

1.  打开您的代码编辑器并创建一个新文件，`function.php`。

1.  在新文件中，创建您的打开和关闭 php 标记：

```php
<?php
?>
```

1.  现在，我们将创建两个新变量：`$sweaterPrice`和`$precentOff`。它们将存储产品的原始价格以及折扣百分比。

```php
<?php
$sweaterPrice = 50;
$percentOff = 0.25;
?>
```

1.  现在我们有了变量，我们可以定义我们的函数。我们的函数很简单；它接受一个价格和折扣百分比。在函数内部，我们将价格乘以折扣百分比并返回乘积。

```php
<?php
   $sweaterPrice = 50;
    $percentOff = 0.25;

    function couponCode($price, $discount){
        return $price * $discount;
    }
?>
```

1.  最后，我们可以继续向我们的用户打印关于折扣的消息，使用我们新创建的函数：

```php
<?php

    $sweaterPrice = 50;
    $percentOff = 0.25;

    function couponCode($price, $discount){
        return $price * $discount;
    }
    echo "The sweater originally costs $" . $sweaterPrice . " with the discount you'll pay $" . ($sweaterPrice - couponCode($sweaterPrice, $percentOff)) . "\n";
?>
```

现在您已经了解了函数，应该可以轻松地开发可重用的代码并应用它们。在下一节中，我们将学习有关类的知识。类将使我们更好地理解如何将代码和属性结构化为一个整洁的包。

# 类

在本节中，您将学习有关类的知识。类属于一种称为面向对象编程的编程类型，简单地意味着将代码组织成所谓的对象。对象允许您创建一个具有自己变量和方法的基本包，专属于该对象。

### 注意

把类想象成一个对象的蓝图。只有一个类，但可以有许多实例。这可以与房子的蓝图相比。许多新房子可以根据相同的蓝图建造。

假设我们想创建一个保存学生信息的类。我们可以定义如下：

```php
<?php

    class Student {

    }

?>
```

这是基本的学生类，以其最简单的形式。我们首先使用关键字`class`，然后是我们类的名称，这种情况下是`Student`。接下来，我们创建一个带有开放和关闭括号的代码块。在开放和关闭括号内，我们添加我们类的内容。

这导致了类的下一部分：成员变量。我们在本书的第一章中使用变量。作为一个复习，变量充当一个容器，允许您暂时存储数据。成员变量具有相同的功能，但其作用范围仅限于给定类或类实例的边界内。

我们将扩展我们的`Student`类来存储学生的`姓名`、`年龄`和`专业`：

```php
<?php

    class Student {
        public $name;
        public $age;
        public $major;
    }

?>
```

您应该注意到我们在定义变量时使用的`public`关键字。这很重要，因为它告诉程序如何访问数据。`public`关键字简单地表示您可以直接访问这些数据。

现在我们的类已经准备好了，我们可以创建一个类的新实例，并将其赋给一个变量，我们可以用这个变量来与类的属性进行交互：

```php
<?php

    $michael = new Student();

    $michael->name = "Michael John";
    $michael->age = 27;
    $michael->major = "Computer Science";
?>
```

在这个例子中，我们使用`new`关键字创建了一个学生类的新实例，并将其赋给一个我们称之为`Michael`的变量。然后，使用箭头语法，我们可以访问公共值来设置姓名、年龄和专业。

有时候我们想要用值实例化一个类的新实例。我们可以使用一个称为构造函数的函数来实现这一点：

```php
public function __construct(){

}
```

这个函数是使用`new`关键字实例化一个新类时调用的默认函数。要传递值，我们将在构造函数中定义这些值。

例如，如果我们想设置学生的信息，我们可以这样做：

```php
<?php

    class Student {
        public $name;
        public $age;
        public $major;
        public function __construct($name, $age, $major){
            $this->name = $name;
            $this->age = $age;
            $this->major = $major;
        }
    }

?>
```

现在，我们可以提供学生的信息：

```php
    <?php
        $michael = new Student("Michael John", 27, "Computer Science");
    ?> 
```

除了`public`变量，您还可以定义`private`变量。`private`关键字使变量只能由方法本身访问。这意味着您只能通过`constructor`、`getter`函数和`setter`函数访问这些类型的变量，这让我们对类函数有了很好的了解。

类函数允许您为类创建本地功能，以`set`、`get`和改变类本身中保存的数据。例如，如果我们采用先前的类定义，并用`private`变量替换`public`变量，它将如下所示：

```php
<?php

    class Student {
        private $name;
        private $age;
        private $major;

        public function __construct($name, $age, $major){
            $this->name = $name;
            $this->age = $age;
            $this->major = $major;
        }
    }

?>
```

如果我们想要更改这些值，或者将这些值放在程序的其他位置，我们当然要定义函数：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 3.php`文件。

```php
<?php

    class Student {
        private $name;
        private $age;
        private $major;
....
        }
public function getName(){
            return $this->name;
}

public function getAge(){
    return $this->age;
}
public function getMajor(){
    return $this->major;
}
    }

?>
```

请记住，在函数的名称中使用`set`和`get`并不是必需的；您可以使用任何您想要的名称 - 一些可以让您轻松记住每个函数的作用。正如您在代码示例中所看到的，您可以使用相应的`set`函数更新`private`值，并使用相应的`get`函数检索这些值。

例如，假设 Michael 改变了他的专业：

```php
<?php

    …
    $michael->setMajor("Engineering");

?>
```

如果我们想知道他的专业是什么，我们可以使用以下代码：

```php
<?php

    echo "Michael's major is " . $michael->getMajor();

?>
```

类是任何类型的编程中非常强大的工具，主要是由于继承的概念。继承允许您创建一个定义一般函数和变量的`base`类，并将被类的所有子类使用。

举个简单的例子，让我们定义一个`Animal`类：

```php
<?php

    class Animal{
          public $sound;
          public $name;

          public function speak(){
            echo $this->name . " says " . $this->sound;
        }
    }

?>
```

这个基类有一个变量，保存动物的名称和动物发出的声音。此外，它有一个`public`函数，`speak`，将打印动物发出的声音。

我们可以从`base`类中扩展不同类型的动物。

假设我们想定义一个`Dog`类：

```php
<?php
    class Dog extends Animal {
        public $name = "Dog";
        public $sound = "Woof! Woof!";
}

?>
```

我们只需更改名称和声音变量的值，就可以得到我们的`dog`类：

```php
<?php

    $dog = new Dog();

    $dog->speak();

?>
```

在开发子类时，要记住的一件事是，您可以通过以下方式扩展基类构造函数：

```php
<?php
    class Dog extends Animal {
        public $name = "Dog";
        public $sound = "Woof! Woof!";

        public function __construct(){
            parent::__construct();
        }
}

?>
```

另一个有用的部分，当涉及到类时，是`static`函数。静态函数不需要创建类的实例就可以使用。当您构建一个包含实用函数的类时，这将非常方便。要创建一个`static`函数，您只需使用`static`关键字：

```php
<?php

    class Animal{
        public $sound;
        public $name;
public function speak(){
            echo $this->name . " says " . $this->sound;
        }

        public static function about(){
            echo "This is the animal base class.";
        }
    }

?>
```

在上面的例子中，我们创建了一个静态的 about 函数，当调用时会给出类的简短描述。您可以按照以下方式使用此函数：

```php
<?php
    echo Animal::about();
?>
```

# 活动：计算员工的月工资

您被指派计算员工的月工资。工资应该被计算并显示在屏幕上。

这个活动的目的是让您学会如何从给定的百分比中计算折扣。

按照以下步骤执行此活动：

1.  打开您的代码编辑器并创建一个新文件，`class.php`。

1.  在新文件中，创建您的`php`标签：

```php
<?php

?>
```

1.  接下来，定义一个基本的员工类：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 3.php`文件。

```php
<?php

    class BaseEmployee {
        private $name;
        private $title;
        private $salary;

        function __construct($name, $title, $salary){
            $this->name = $name;
            $this->title = $title;
            $this->salary = $salary;
 }

        public function setName($name){
            $this->name = $name;
......
        }
        public function getTitle(){
            return $this->title;
        }

        public function getSalary(){
            return $this->salary;
        }
    }

?>
```

1.  从这个基类中，我们可以继续创建一个扩展基类的`employee`类。在这个扩展类中，我们将添加一个额外的函数，用于计算员工的月工资：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 3.php`文件。

```php
<?php
    class BaseEmployee {
        private $name;
        private $title;
        private $salary;

        function __construct($name, $title, $salary){
...

        public function getSalary(){
        return $this->salary;
        }
    }

    class Employee extends BaseEmployee{
        public function calculateMonthlyPay(){
            return $this->salary / 12;
        }
    }
?>
```

1.  最后，我们将使用新类来打印月工资：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 3.php`文件。

```php
<?php

    class BaseEmployee {
        private $name;
        private $title;
        private $salary;
......
    class Employee extends BaseEmployee{
        public function calculateMonthlyPay(){
            return $this->salary / 12;
        }
    }

    $markus = new Employee("Markus Gray", "CEO", 100000);

    echo "Monthly Pay is " . $markus->calculateMonthlyPay();

?>
```

# 摘要

在本章中，我们学习了函数和类。我们讲解了如何定义和调用函数。我们还讲解了如何定义类并将类和函数一起使用。随着我们开始构建更大更复杂的项目，函数和类将帮助我们创建高度组织的代码并保持最佳实践。

在下一章中，我们将涵盖数据操作，如输入和输出数据，使用错误处理捕获和处理错误，我们还将介绍 MySQL 的基础知识。


# 第四章：数据操作

在上一章中，我们学习了函数和类。我们讨论了如何定义和调用函数。我们还讨论了如何定义类并将类和函数一起使用。

在本章中，我们将专注于处理用户的输入并将结果打印回给他们，优雅地处理错误，并学习使用 MySQL 数据库的基础知识。

在本章结束时，您将能够：

+   确定如何接受用户输入并将其打印到屏幕上

+   实现使用 MySQL 的基础知识

# 输入和输出数据

能够接受用户输入是从使用 PHP 构建网站转向使用 PHP 构建 Web 应用程序时的一个主要要求。通常，输入来自 HTML 表单。

让我们创建一个简单的联系表单：

```php
<html>
<body>
    <form action="index.php" method="POST">
        <input type="text" name="name" />
        <input type="text" name="email" />
        <textarea name="message"></textarea>
        <button type="submit">Send</button>
    </form>
</body>
</html>
```

在上述联系表单中，我们看到了用户姓名、电子邮件和消息的输入。我们将使用的提交此表单的方法称为`POST`请求。

为了读取正在提交的数据，我们将在表单顶部添加一些 PHP 代码，这些代码将从我们的`POST`请求中读取并呈现数据：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 4.php`文件。

```php
<?php
    if($_POST){
        echo "Name: " . $_POST['name'] . "\n";
        echo "Email: " . $_POST['email'] . "\n";
......
        <input type="text" name="email" />
        <textarea name="message"></textarea>
        <button type="submit">Send</button>
    </form>
</body>
</html>
```

如您所见，接受应用程序用户的输入很容易。在上面的代码示例中，我们使用了一个特殊变量`$_POST`数组，来访问通过`POST`请求提交的所有数据。`$_POST`变量是一个关联数组，可以通过您在输入元素中指定的名称来访问内容。

您可以使用的另一种请求类型是`GET`请求。`GET`请求比您想象的更常用；当您导航到网站或在 Google 上进行搜索时，就会使用`GET`请求。`GET`请求的输入是通过查询字符串完成的。

查询字符串是附加到 URL 末尾的字符串，以问号开头，如下所示：[`www.example.com?name=Michael&age=12`](https://www.example.com?name=Michael&age=12)：

![输入和输出数据](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/4_01.jpg)

在上面的例子中，您可以看到我们有两个用和号分隔的键。就像在`POST`方法中一样，`GET`请求也有一个特殊的变量，那就是`$_GET`变量（它是一个关联数组）。

如果我们想要从之前的查询字符串中获取名称，可以使用这行代码：

```php
<?php

    $name = $_GET['name'];

?>
```

您也可以在表单中使用`GET`请求。让我们重新访问之前看到的表单元素：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 4.php`文件。

```php
<?php
    if($_GET){
        echo "Name: " . $_GET['name'] . "\n";
        echo "Email: " . $_GET['email] . "\n";
......
        <button type="submit">Send</button>
    </form>
</body>
</html>
```

在表单的方法属性中，我们将其更改为`GET`，用`$_GET`变量替换了`$_POST`变量。

### 注意

在接受用户输入时，有时需要在对其进行任何操作之前清理输入。某些输入需要清除开头和结尾的任何空格。这就是 PHP 的`trim`函数发挥作用的地方。`trim`函数将清除用户输入的两侧的空格和其他类似字符。如果要从左侧或右侧删除，可以分别使用`ltrim`和`rtrim`函数。

## 为我们的用户列表构建一个表单

我们将首先构建一个用户列表的表单。在本节结束时，您将拥有一个表单，可以接受您的`firstname`、`lastname`和`email`。它将在最后有一个提交按钮，用于提交信息：

1.  创建一个名为`users_list`的新目录。

1.  在新目录中创建一个`index.php`文件。

1.  在文本编辑器中打开`index.php`文件，并添加表单代码：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 4.php`文件。

```php
<html>
    <body>
        <form action="index.php" method="post">
......
        </form>
    </body>
</html>
```

1.  现在我们有了表单，我们希望能够查看提交给表单的数据：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 4.php`文件。

```php
<?php
    if($_POST){
        echo "First Name: " . $_POST['firstname'] . "\n";
        echo "Last Name: " . $_POST['lastname'] . "\n";
......
id="email"/>
            <br>
            <button type="submit">Save</button>
        </form>
    </body>
</html>
```

1.  现在，为了看到我们的表单起作用，我们将在终端中打开工作目录并运行以下命令：

```php
php -S localhost:8000 -t
```

对于任何 Web 应用程序，您都需要一种存储数据的方式。允许您将当前状态持久保存在 MySQL 数据库中的服务称为持久性。如果变量允许您暂时存储数据，持久性允许您长期存储数据在数据库中。

PHP 中主要使用的数据库类型是 MySQL。MySQL 数据库被称为关系型数据库，它们被组织成表格。

在本节中，我们将介绍如何在 PHP 中使用 MySQL 数据库以及如何执行各种操作。

## 连接到数据库

使用数据库的第一步是连接到数据库。在本章中，我们将专注于使用 PDO（PHP 数据对象）风格的用法。

要连接到数据库，请使用以下代码行：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 4.php`文件。

# MySQL 基础知识

```php
<?php
    $host = "DATABASE_HOST";
    $username = "DATABASE_USERNAME";
    $password = "DATABASE_PASSWORD";
    $database = "DATABASE_NAME";
......

            echo "Connected successfully"; 
        }
    catch(PDOException $e)
        {    

            echo "Connection failed: " . $e->getMessage();
}
?>
```

在上述代码中，您可以看到我们有一大块新代码。我们首先定义四个新变量来保存数据库的凭据值：一个用于主机 URL，一个用于用户名，一个用于密码，最后一个用于我们连接的数据库的名称。接下来，我们将数据库连接代码包装在`try`块中；这将在连接到数据库并运行查询时`catch`任何错误。在`try`块中，我们通过使用我们之前定义的凭据变量来初始化 PDO 类的新实例，将其分配给`$conn`变量。然后，我们设置错误模式以确保如果出现任何错误，它会触发我们的`catch`块。最后，在`try`部分，我们`echo`出一个成功的连接消息。在 try/catch 块的`catch`部分中，我们只是`echo`出触发的错误消息。

## 创建数据库表

我们现在将使用 SQL 查询创建一个表：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 4.php`文件。

```php
<?php
    $host = "DATABASE_HOST";
    $username = "DATABASE_USERNAME";
    $password = "DATABASE_PASSWORD";
......

    }
    catch(PDOException $e)
    {

        echo "Connection failed: " . $e->getMessage();

    }
    }
?>
```

创建表格时，我们使用`CREATE TABLE`命令，后面跟着表格的名称。然后，在一对括号内，我们定义表格的字段。我们在查询中创建的表将创建一个用户表，其中将保存用户的 ID（此表的主键），并将自动递增用户名称，类型为`varchar`，最多 60 个字符。表还将保存一个电子邮件地址，类型为`varchar`，最多 30 个字符。

## 向数据库插入记录

现在我们的数据库中有一个表，我们可以向其中添加数据。我们使用`insert`查询添加数据。连接到数据库并设置错误模式后，我们可以定义我们的查询。`Insert`查询以`INSERT INTO`命令开始，后面跟着我们要插入数据的表的名称。在一对括号内，我们定义要写入的字段。在字段之后，我们定义要输入表格的值：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 4.php`文件。

```php
<?php
    $host = "DATABASE_HOST";
    $username = "DATABASE_USERNAME";
    $password = "DATABASE_PASSWORD";
    $database = "DATABASE_NAME";

    try {
        $conn = new PDO("mysql:host=$host;dbname=$database", $username, $password);

    ......

    }
    catch(PDOException $e)
    {

        echo "Connection failed: " . $e->getMessage();

    }
?>
```

## 从数据库表中获取单行数据

如果要从数据库中获取用户，可以使用`SELECT`查询。在这种情况下，我们要获取前一个代码块中插入的新用户。我们将使用以下代码：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 4.php`文件。

```php
<?php
    $host = "DATABASE_HOST";
    $username = "DATABASE_USERNAME";
    $password = "DATABASE_PASSWORD";
    $database = "DATABASE_NAME";

    try {
        $conn = new PDO("mysql:host=$host;dbname=$database", $username, $password);
......

    }
    catch(PDOException $e)
    {

        echo "Connection failed: " . $e->getMessage();

    }
?>
```

使用`$conn`变量，我们准备一个`SELECT`查询，指示我们要从用户表中提取信息；然后我们使用`WHERE`子句来定义所需信息的条件。最后，我们执行准备好的语句，传递一个带有所需电子邮件地址的`array`。由于我们希望得到一个关联数组返回给我们，我们将获取模型设置为`FETCH_ASSOC`，通过使用 fetch 方法获取单个记录。

渲染用户数组，我们在开放和关闭的`pre`标签之间使用`PRINT`命令。

### 注意

`pre`标签美化了已打印的数组。这通常用于调试数组中包含的内容。

## 从数据库表中获取多行

如果我们想要获取表中的所有用户，我们可以放弃准备好的语句并直接运行查询。这一次，我们去掉了`WHERE`子句。我们不再使用 fetch 函数，而是使用`fetch_all`函数：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 4.php`文件。

```php
<?php
    $host = "DATABASE_HOST";
    $username = "DATABASE_USERNAME";
    $password = "DATABASE_PASSWORD";
    $database = "DATABASE_NAME";

    try {
        $conn = new PDO("mysql:host=$host;dbname=$database", $username, $password);
......
        echo "</pre>";

    }
<?php
    $host = "DATABASE_HOST";
    $username = "DATABASE_USERNAME";
    $password = "DATABASE_PASSWORD";
    $database = "DATABASE_NAME";

    try {
        $conn = new PDO("mysql:host=$host;dbname=$database", $username, $password);
......
        echo "</pre>";

    }
    catch(PDOException $e)
    {

        echo "Connection failed: " . $e->getMessage();

    }
?>
```

## 更新数据库表中的记录

现在我们了解了如何向数据库表中添加和获取数据，我们可以开始编辑单个记录。在 MySQL 中，我们使用`UPDATE`查询来更新数据。要运行`UPDATE`查询，我们回到我们的准备好的语句，并以`UPDATE`命令开头，后跟表的名称（在本例中为用户表）。接下来，我们使用`SET`命令开始定义需要更新的字段和值的过程，然后我们添加`WHERE`子句来隔离我们希望具有新值的特定记录。为了对查询的执行情况进行一些反馈，通过行计数函数回显计数。

让我们将用户的电子邮件地址更改为`test123@email.com`：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 4.php`文件。

```php
<?php
    $host = "DATABASE_HOST";
    $username = "DATABASE_USERNAME";
    $password = "DATABASE_PASSWORD";
    $database = "DATABASE_NAME";

    try {
        $conn = new PDO("mysql:host=$host;dbname=$database", $username, $password);
......
          echo $statement->rowCount() . "(s) rows affected.";
    }
    catch(PDOException $e)
    {

        echo "Connection failed: " . $e->getMessage();

    }
?>
```

## 从数据库表中删除记录

我们在 MySQL 中的最后一部分将是从数据库中删除数据。要删除数据，我们使用`DELETE`查询。`DELETE`查询以`DELETE FROM`开头，后跟您要从中删除数据的表的名称；使用`WHERE`子句完成查询，以进一步指定要删除的记录。我们将此查询放在准备好的语句中，然后通过传递`WHERE`子句的值来执行它：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 4.php`文件。

```php
<?php
    $host = "DATABASE_HOST";
    $username = "DATABASE_USERNAME";
    $password = "DATABASE_PASSWORD";
    $database = "DATABASE_NAME";

    try {
        $conn = new PDO("mysql:host=$host;dbname=$database", $username, $password);
......
          echo $statement->rowCount() . "(s) rows deleted.";
    }
    catch(PDOException $e)
    {
        echo "Connection failed: " . $e->getMessage();

    }
?>
```

## 创建员工表

我们的最终项目将是将我们从用户那里获得的输入存储在数据库表中。在编写将数据添加到数据库的代码之前，我们需要创建一个数据库，如下所示：

1.  打开终端。

1.  使用以下命令连接到 MySQL：

```php
mysql –u root –p
```

1.  接下来，创建`packt_database`数据库：

```php
create database packt_database;
```

1.  告诉 MySQL 使用新创建的数据库：

```php
use packt_database;
```

1.  最后，创建用户表：

```php
CREATE TABLE users (
            id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY,
            firstname VARCHAR(30) NOT NULL,
           lastname VARCHAR(30) NOT NULL,
email VARCHAR(30) NOT NULL
);
```

1.  现在，我们可以关闭我们的终端并开始完成我们的应用程序。

## 向数据库添加用户

在本节中，我们将使用 PHP 向数据库添加用户。然后，我们创建一个表单，接受用户的`INSERT`查询。

要执行此操作，请执行以下步骤：

1.  在文本编辑器中重新打开`users_list`目录。

1.  在第二个`if`语句中，连接到您的数据库：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 4.php`文件。

```php
<?php

    if($_POST){
        if(!$_POST['firstname'] || !$_POST['lastname'] || !$_POST['email']){
            exit("All fields are required.");
        }

        $host = "DATABASE_HOST";
        $username = "DATABASE_USERNAME";
        $password = "DATABASE_PASSWORD";
        $database = "packt_database";

        try {
            $conn = new PDO("mysql:host=$host;dbname=$database", $username, $password);
......
  <button type="submit">Save</button>
        </form>
    </body>
</html>
```

1.  接下来，继续使用`INSERT`查询将用户输入添加到数据库中：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 4.php`文件。

```php
<?php

    if($_POST){
        if(!$_POST['firstname'] || !$_POST['lastname'] || !$_POST['email']){
            exit("All fields are required.");
        }

.......
            <br>
            <label>Email</label>
            <input type="text" name="email" id="email"/>
            <br>
            <button type="submit">Save</button>
        </form>
    </body>
</html>
```

1.  现在，您已经准备好测试简单的应用程序。在终端中打开`user_list`目录，并使用以下命令来启动您的应用程序：

```php
php -S localhost:8000 -t .
```

# 总结

我们已经到达了本章的结尾。在本章中，我们学习了如何接受用户的输入，以及如何通过 PHP 访问它。最后，我们学习了使用 MySQL 数据库的基础知识，并将所有原则应用到一个通过 Web 表单向数据库添加用户的迷你应用程序中。

在下一章中，我们将介绍使用面向对象编程原则构建 PHP Web 应用程序的基础知识，例如命名空间、使用语句、访问修饰符等。我们还将介绍如何使用 MVC 设计概念正确地构建应用程序。
