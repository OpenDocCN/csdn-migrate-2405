# PHP 入门指南（二）

> 原文：[`zh.annas-archive.org/md5/d36bde355b2574844946c8150420db7b`](https://zh.annas-archive.org/md5/d36bde355b2574844946c8150420db7b)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：构建 PHP Web 应用程序

在上一章中，我们学习了如何接受用户的输入，以及如何通过 PHP 访问它。我们还学习了使用 MySQL 数据库的基础知识，并将之前章节的原则应用到一个小型应用程序中，通过 Web 表单将用户添加到数据库中。

在本章中，我们将学习并应用框架中的面向对象编程概念。我们将使用 Whoops 库来进行错误报告，并学习如何处理这些错误。我们还将介绍如何在框架中管理和构建我们的应用程序。

在本章结束时，您将能够：

+   在框架环境中应用面向对象编程概念

+   结构文件和文件夹以构建框架

+   描述框架如何与数据源交互

+   使用 MVC 设计模式构建框架

+   构建一个 CRM 应用程序来管理您的框架上的联系人

构建一个应用程序将需要我们了解底层框架以及如何使用 MVC 架构风格来创建应用程序。PHP 框架是一个设计用来促进代码重用组织的文件夹和文件集合；这些文件夹和文件提供了一个通用的代码基础，用于构建应用程序。通过这些章节，您将学习如何构建这样一个框架。

我们将在本书中使用的一个常见设计模式称为 CRUD - 一个缩写，意思是：

+   **创建**：创建一个新的 MySQL 记录

+   **读取**：从数据库中读取记录

+   **更新**：更新 MySQL 记录

+   **删除**：删除 MySQL 记录

CRUD 是在框架中构建的任何实际应用程序的核心。几乎所有内容都可以分解为 CRUD。

CRUD 的示例将涉及创建新内容，读取内容，并提供提示来更新和删除内容。

我们将使用一种称为模型视图控制器（MVC）的设计模式，这是一种用于构建框架的目录和文件结构的方式。将使用 MVC 结构来展示结构和示例：

![构建 PHP Web 应用程序](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/5_01.jpg)

模型视图控制器（MVC）的表示

PHP 标准建议（PSR）为代码格式设置了一个样式指南，允许与您可能接触到的其他代码最大的兼容性：[`www.php-fig.org/psr/`](http://www.php-fig.org/psr/)。

# 框架环境中的面向对象编程概念

在开始学习框架构建之前，对 PHP 面向对象编程（OOP）概念有一个扎实的理解是一个好主意。所有 PHP 框架共同的一点是，它们首先是建立在 OOP PHP 之上的；本质上，它们只是一种组织文件的方式。

我们将学习以下面向对象编程概念：

+   命名空间

+   使用语句

+   类和对象

+   方法

+   访问修饰符

## 命名空间

命名空间可以与文件夹结构进行比较。命名空间的主要目的是允许类具有相同的名称，但在不同的命名空间下。

命名空间是区分大小写的。命名空间应该以大写字母开头，之后使用驼峰命名法 - 每个单词的开头应该是小写，后面的单词应该是大写。

例如：`mySpace`

例如，如果您有一个名为`Post`的类，并且在另一个文件夹中，您有一个名为`Post`的类。通常情况下，您将无法在同一文件中使用它们，因为这些类会相互冲突；但是，如果每个类都有它们存储的文件夹的命名空间，那么您可以在同一文件中使用它们。

文件 file1.txt 可以存在于目录`/home/packt`和`/home/other`中，但是两个 file1.txt 的副本不能同时存在于同一个目录中。此外，要在`/home/packt`目录之外访问`file1.txt`，我们必须在文件名之前加上目录名，使用目录分隔符来获取`/home/packt/file1.txt`。这个原则在编程世界中也适用于命名空间。

您不能在同一个文件中使用两个类，因为它们会互相冲突。为了解决这个问题，您可以给其中一个类起一个别名。将别名视为该类的昵称。

命名空间是对`app/controllers`目录中的位置的引用：命名空间`App\Controllers`是其位置的路径。注意在编写命名空间时使用反斜杠字符：

```php
//valid namespace
namespace App\Controllers;
```

## 命名空间 App，Controllers 和 Use 语句

`Use`语句是一种导入类的方式，而不是手动包含它们。`use`语句与 composer 一起使用。

作为在类中使用`use`语句的示例，如果我们想要使用`Contact`模型，可以将以下代码放在类的顶部：

```php
use App\Models\Contact;
```

当您有一个名为`Contact`的类，其命名空间为`App\Models`时，要导入它，您可以使用`App\Models\Contact`。然后，您可以通过调用`Contact`来引用这个类；您不必引用其完整的命名空间，因为它已经被导入：

### 注意

我们使用 composer 根据其命名空间自动加载文件，并将在后面的章节中详细介绍这一点。

```php
//start with the namespace
namespace App\Controllers;
//add the use statement
use App\Models\Contact;
//make the call
$contact = new Contact();
```

## 使用命名空间定义类和对象

我们在上一章学习了如何创建类和对象。现在我们将看到如何使用命名空间创建类和对象。

对象是已经实例化的类；例如，如果您看最后一个示例的最后一行，一个名为`contact`的类已经被实例化，使用了`new`运算符，后跟类名。这创建了一个新对象；这意味着新对象可以访问类的所有方法和公共属性：

```php
//start with the namespace
namespace App\Controllers;

//add the use statement
use App\Models\Contact;

//make the call
$contact = new Contact();

//make a call to a getContacts method that exists within the contact class
$contact->getContacts();
```

## 方法

方法是驻留在类内部的函数。实际上，方法和函数之间唯一的区别是命名约定，以及方法碰巧驻留在类内部。

方法用于检索和传递信息到类中，或从类中传递信息到文件中，该文件中实例化了该类：

```php
//start with a namespace
namespace App\Models;

//here is an example of a method being defined, in the previous example the method was being called.
class Contact
{
    public function getContacts()
{
                        //get data here
    }
}
```

## 访问修饰符

访问修饰符是授予和限制类的属性和方法访问权限的一种方式。有三种访问修饰符：`public`，`protected`和`private`。这可以与门卫进行比较，允许数据进入或阻止数据进入：

+   **Public**

将属性或方法定义为`public`意味着类，扩展类和实例化类的文件都可以读取和写入该方法或属性。

+   **Protected**

`protected`方法或属性只能被类或扩展类访问。

+   **Private**

`private`属性或方法只能从定义它的类内部访问。

### 注意

`private`属性无法从该类的外部访问，也无法从扩展类访问。

以下是如何使用各种访问修饰符的示例。在定义名为`$token`的属性时，您将看到`public`，`protected`和`private`属性的使用：

```php
public $token;
protected $token;
private $token;

```

![访问修饰符](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/5_02.jpg)

文件夹结构

**解释：**

这里是我们将在接下来的几章中构建的框架的文件结构：

+   **app**文件夹是您的应用程序所在的位置。**app**包含您的控制器，模型和视图。正如先前提到的，这是 MVC 结构的一部分。

+   **config**文件是存储站点名称和数据库凭据的位置。

+   **system**文件夹包含框架的核心文件。

+   **vendor**目录是一个 composer 目录，包含通过 composer 安装的任何第三方包。它还存储了 composer 本身。

+   **webroot**文件夹是您的文档根目录；这是您的浏览器所读取的内容。

在本章的后面，我们将介绍一个名为 MVC 的设计模式。

以下示例使用了这种设计模式，这只是一种组织文件结构的方式。

在此示例中，我们将从已实例化的类中传递单个联系人的详细信息，并在浏览器中显示它们。

目前，请注意每个面向对象编程原则在每个文件中的应用，并看看您是否能识别出来。

### 注意

此代码将无法作为纯 PHP 工作，因为需要框架的结构。本书将教您这些组件如何（以及为什么）以它们目前的方式一起工作。展示此示例的目的是在框架环境中看到面向对象编程概念的实际应用。

以下是一个控制器的示例：

![访问修饰符](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/5_03.jpg)

联系人控制器

首先是`namespace`，这是 composer 知道如何加载文件的方式。没有 composer，将需要手动包含，使用`include`或`require`，称为惰性加载，以防止加载不相关的文件并提高性能。

在`namespace`和`use`语句之后是类定义（类的蓝图）。在这里，我们将类命名为`Contacts`，并扩展了已经存在的`BaseController`类的功能：

![访问修饰符](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/5_04.jpg)

联系人模型

**解释：**

在这里看到的文件是模型；在前面的示例中实例化了`Contact`模型。

再次，模型包含了`namespace`。

在此示例中，不需要`use`语句，因为数据包含在类定义中。

如果数据存储在数据库或其他数据源中，则该类需要扩展`BaseModel`：

![访问修饰符](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/5_05.jpg)

联系人视图

PHP 视图中使用最少的 PHP；数据通常以数组或变量的形式传递给视图，并且样式是由其决定的：

![访问修饰符](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/5_06.jpg)

浏览器视图

### 注意

作为开发人员的早期阶段，您可能会发现自己经常忘记使用分号；事实上，我们的一位书籍作者大卫经常回忆起他曾经花了将近两天的时间来解决他的第一个项目中的一个错误，结果发现问题是缺少了一个分号。

在框架环境中工作时，忘记使用正确的大小写可能会像忘记使用分号一样麻烦。

这并非一定要这样；您可以利用软件专家附加组件，即 PHP linters，它们将检查问题，如忘记使用正确的大小写。 PHP linters 在运行脚本之前突出显示代码。您将在诸如 PHP Storm 之类的 IDE 中找到此类附加组件，或者在 Sublime Text 或 Atom 等文本编辑器中找到：

+   [`www.jetbrains.com/phpstorm/`](https://www.jetbrains.com/phpstorm/) 由 Jet Brains 制作

+   [`www.sublimetext.com/`](https://www.sublimetext.com/) 由 Sublime HQ 制作

+   [`atom.io/`](https://atom.io/) 由 Atom 制作

# 框架的结构

在其核心，MVC 是关注点分离，因此所有数据源都来自模型或数据库资源。您的控制器控制应用程序的流程，并驻留在控制器目录中。所有标记都位于所谓的视图中。它们一起形成了模型视图控制器（MVC）设计模式。

![框架的结构](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/5_07.jpg)

框架文件夹和文件结构

如果您需要修改数据源，您知道要去模型进行操作；如果您想要更改外观，您知道要去视图；要更改应用程序的控制，您去控制器。

### 注意

请注意，模型并不局限于从数据库中提取数据；这是一个常见的误解。我们之前的示例突出了这一点。

模型中的其他数据源可能是静态数据或从文件或外部源（如 RSS）读取的数据。

**解释：**

在使用框架时，您的应用程序的大部分将使用 MVC 设计模式构建。

模型和控制器都将从系统目录中存储的`BaseModel`和`BaseController`扩展功能。您可能不经常需要更改这些。建立在框架之上的任何应用程序将主要包含在`App`目录中存储的模型、控制器和视图目录中：

![框架结构](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/5_03.jpg)

联系人控制器

在这里，控制器正在与模型通信。模型为控制器提供了数据源。控制器是结构的大脑，在这里，它是一系列指令，用于何时提供数据源以及在什么条件下如何行为。

当用户访问特定 URI 时，联系人类将调用一个函数（这是如何工作以及为什么工作将在后面的章节中介绍）；这将启动与模型的联系。

在这个例子中，控制器不关心数据源中包含什么；但是，它可以被编程来检查这些数据。

在控制器获取数据后，数据被存储并传递给视图：

![框架结构](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/5_04.jpg)

联系人模型

**解释：**

联系人模型具有包含应用程序知识的数据源，但它本身不能利用这些知识。它只能给出管理知识的指示。CRUD 原则在模型中发挥作用，其中有创建、读取、更新和删除模型知识源的方法。

在这种情况下，数据源是一个名字数组：

![框架结构](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/5_05.jpg)

联系人视图

在视图文件中，您将看到数据是按原样提供的；在这种情况下，视图被提供了一个名字数组。这些名字是详尽的，并且带有任何标记和样式。

在框架中，视图是一个更广泛结构的一部分，它在您的 Web 应用程序中应用全局元素，如标题和页脚，以及 CSS 和 JavaScript 文件。

可以循环遍历数组，但尽可能在控制器中完成所有处理。

![框架结构](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/5_06.jpg)

浏览器视图

您现在已经确定了如何在 MVC 框架示例中使用面向对象编程原则。

现在，让我们将这些原则付诸实践。

## 活动：向目录添加联系人

您需要将联系人添加到您正在创建的目录中，以名字数组的形式存储。当请求时，应用程序应返回一个联系人数组。

这样做的原因是为了更好地全面了解如何在实际应用中使用面向对象编程。

按照以下步骤执行此活动：

1.  创建一个目录结构。

1.  创建一个名为`Contacts`的目录。

1.  在这个目录中，创建一个名为`App`的目录。

1.  在`App`目录中，创建三个更多的目录：

+   `模型`

+   `视图`

+   `控制器`

1.  在模型目录中，创建一个名为`Contact.php`的文件。

1.  在`Contact.php`文件中，打开 PHP，并创建一个命名空间：

```php
<?php namespace App\Models;
```

1.  定义一个名为`Contact`的类：

```php
class Contact 
{
}
```

1.  在这个类中，定义一个名为`getContacts()`的公共方法；它应该返回一个名字数组：

```php
class Contact
{
    public function getContacts()
{
        return ['joe', 'bob', 'kerry', 'dave'];
    }
}
```

1.  在 Controllers 目录中，创建一个名为`Contacts.php`的文件。

1.  在`Contacts.php`文件中，打开 PHP，并添加一个`namespace`：

```php
<?php namespace App\Controllers;
```

1.  用`use`语句导入联系人模型：

```php
use App\Models\Contact;
```

1.  在这种情况下，可以使用别名，写成如下形式（假设 Contact 的别名为`Name`）：

```php
Use App\Models\Contact as Name;
```

定义一个名为 Contacts 的类：

```php
class Contacts 
{
}
```

1.  创建一个名为`index()`的公共函数，在该方法中，创建一个名为`contacts`的局部变量，并创建`contact`类的一个新实例（这被称为类的实例化）：

```php
class Contacts 
{
    public function index()
    {
        $contact = new Contact();
    }
}
```

1.  使用赋值运算符创建一个名为`contacts`的局部变量，在前一步创建的`contacts`对象实例后调用`getContacts()`方法（这被称为箭头符号）：

```php
public function index()
{
    $contact = new Contact();
    $contacts = $contact->getContacts();
}
```

# 总结

在本章中，我们创建了一个模型和一个控制器，其中控制器`Contacts`类实例化了模型`Contact`类。为了实现这一点，我们创建了一个基本的 MVC 文件夹结构，将控件与数据源分开。我们成功地使用了`namespace`、`use`语句、方法、访问修饰符、对象和类。我们现在见识到了框架的力量。

在下一章中，您将创建自己的工作框架。我们将学习如何设置项目开发环境、优雅的错误报告以及使用 Whoops 库进行处理。我们还将实现配置类、默认类以及如何设置路由。


# 第六章：构建 PHP 框架

在上一章中，我们创建了一个模型和一个控制器，其中控制器`Contacts`类实例化模型`Contact`类。我们成功使用了`namespace`，`use`语句，方法，访问修饰符，对象和类。我们在上一章中见证了框架的力量。

在本章中，我们将从头开始构建一个 MVC 框架。框架实际上只是一种组织代码和结构代码的方式。从一个空目录开始，我们将构建一个完整的工作框架，作为更复杂应用程序的起点。

### 注意

在上一章中，我们从数组中检索数据。在本课程中，我们将从数据库中检索数据。

到本章结束时，您将能够：

+   构建一个基本的 PHP MVC 框架

+   实施在以前章节中涵盖的面向对象的概念

+   确定如何将控制器路由到指定的 URI

+   使用 PHP 数据对象（PDO）与数据库交互

+   使用 HTML 构建和创建可重用的页面（视图）

我们还将实施我们在以前章节中涵盖的面向对象的概念，包括但不限于命名空间，`use`语句，对象和类，访问修饰符和方法。

我们将学习如何将控制器路由到指定的 URL，并使用 HTML 构建和创建可重用的页面（视图）。最后，我们将使用 PDO 与数据库交互。

# 设置项目开发环境

本节涉及设置项目开发环境。

这一切都是关于设置索引，`.htaccess`文件，创建 Web 根目录，设置 Composer 和设置`app`目录。

+   **索引**是框架的引导文件；这最终是所有请求接收的地方。例如，当用户在地址栏中输入 URL 时，就会发出请求。

+   **.htaccess**是 mod rewrite 引擎，将所有请求传递给索引文件。

+   **Web 根目录**是公共文件夹，可以被浏览器访问，也用于存储 Web 应用程序的所有资产的索引和.htaccess。这将包括图像，CSS 和 JavaScript 文件。

+   **Composer**是用于管理系统依赖库的包管理器。

+   **应用程序目录**是您的应用程序；这是您的视图，模型，控制器和助手将存储的地方。助手是帮助开发人员经常遇到的单个常见任务的紧凑方法。开发人员可能发现自己重复执行相同的任务，并将创建一个帮助程序类，其中包含一个或多个方法来帮助完成此任务。这可能是格式化日期，执行特定计算等等。

### 注意

引导符号象征着设置框架的过程通常被称为引导。这不应与流行的 CSS Grid 命名为 Bootstrap 混淆。这本质上紧密地将框架的所有核心部分联系在一起。

# 使用 Composer 和 Whoops 进行错误报告

对于这个项目，我们将使用 Whoops 库来处理错误。Whoops 库是用于检查项目中可能发生的错误的工具。这个库已经打包并提供给其他开发人员在他们的项目中使用。

使用 Whoops，当 PHP 发生错误时，您将能够看到显示信息，而不是来自服务器的标准单调的错误报告：

![使用 Composer 和 Whoops 进行错误报告](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/6_01.jpg)

Composer 将管理此依赖的使用，因为它被认为是 PHP 开发人员非常广泛使用和非常受欢迎的包管理器之一。

Composer 是 PHP 中的依赖管理工具。它允许您声明项目所依赖的库，并且会为您管理（安装/更新）它们。要安装 Composer，请访问[`getcomposer.org/download/`](https://getcomposer.org/download/)。

想象一种情况，您必须为 PHP 安装一个依赖项，为了安装该依赖项，您需要安装其他额外的依赖项。Composer 帮助您处理这个问题。它用于为您处理所有工作，以安装一个库，因为它会一起下载所有库和依赖项。

## 设置 Composer

我们将在本节中设置 Composer。要做到这一点，请按照以下步骤操作：

1.  创建一个文件夹来存储框架文件。

### 注意

随意为您的文件夹命名，只要全部小写且没有空格即可。

1.  +   `app`保存应用程序文件

+   `system`保存核心框架文件

+   `webroot`将保存公开访问的文件

1.  接下来，我们将设置 Composer。在框架文件夹的根目录中创建一个名为`composer.json`的文件。

该文件包含一个 JSON 对象，将根据需要自动加载类。我们将使用 PSR-4 自动加载。

### 注意

PSR-4 自动加载将根据其命名空间加载类在使用时。例如，新的`App\Models\Contact()`将告诉 Composer 自动加载名为`Contact`的文件，该文件存储在文件夹`app\Models`中。

1.  打开`composer.json`并创建一个`App`和`System`定义。

1.  这将告诉 Composer，我们称为命名空间的一切，无论是`App`还是`System`，都要在`app`或`system`文件夹中查找类。

1.  我们还加载了一个名为`Whoops`的第三方包。我们通过在`require`块中将其包含为依赖项来加载此包：

```php
{
    "autoload": {
        "psr-4": {
            "App\\" : "app/",
            "System\\" : "system/"
        }
    },
    "require": {
        "filp/whoops": "².1"
    }
}
```

1.  保存`composer.json`。现在，在`webroot`中，创建两个文件：`index.php`和`.htaccess`。

1.  打开`.htaccess`。

1.  出于安全原因，如果一个文件夹不包含`index`文件，我们不希望其内容显示在浏览器中。要禁用目录浏览，请输入：

```php
Options –Indexes
```

1.  接下来，将检查是否启用了 mod rewrite：

```php
<IfModule mod_rewrite.c>
//more code
</IfModule>
```

### 注意

`mod` rewrite 提供了一个基于规则的重写引擎，可以实时重写请求的 URL。它有助于使 URL，因此`index.php?page`可以变成`/`page。

1.  接下来，打开重写引擎并将基础设置为此文件夹的根目录：

```php
RewriteEngine On
RewriteBase /
```

1.  要强制使用 HTTPS，可以取消下面的`#`，但只能在启用了 HTTP 的服务器上这样做。

1.  接下来，定义重写条件。

### 注意

这是为了忽略尾随斜杠和存在的文件夹和文件。只有动态文件应该被路由，例如，不存在作为物理文件的 URL。

最后的规则将所有请求传递到`index.php?$1`。`$1`是请求 URL 中第一个`/`之后的请求。

`RewriteCond`基本上意味着“只有在这是真的时候才执行下一个`RewriteRule`”。

`RewriteRule`基本上意味着，如果请求匹配`^(.+)$`（匹配除服务器根目录之外的任何 URL），它将被重写为`index.php?$1`，这意味着对联系人的请求将被重写为`index.php?contact:`

RewriteRule ^(.*)$ index.php?$1 [QSA,L]

QSA 表示此标志强制重写引擎将查询字符串部分附加到现有字符串中，而不是替换它。

安全套接字层（SSL）在您的 Web 服务器和 Web 浏览器之间创建加密连接。这样可以阻止任何数据从您的计算机被拦截到 Web 服务器。建议使用 HTTPS。

完整的文件应该如下所示：

```php
# Disable directory snooping
Options -Indexes

<IfModule mod_rewrite.c>

    # Uncomment the rule below to force HTTPS (SSL)
………..
    RewriteRule ^(.*)$ index.php?$1 [QSA,L]
</IfModule>
```

### 注意

有关完整的代码片段，请参阅代码文件夹中的 Lesson 6.php 文件。

1.  保存文件。现在，打开`index.php`。

1.  首先，启动 php，然后进行检查以确定`vendor/autoload.php`是否存在（它尚不存在），并要求该文件。

### 注意

这是一个重要的步骤。只有在初始化 Composer 后，autoload.php 文件才会存在。在要求文件之前进行检查是一种预防措施，用于避免致命错误。

1.  我们应该通知用户 Composer 正在请求什么以及去哪里获取它。我们通过使用`else`子句来做到这一点：

```php
if(file_exists('../vendor/autoload.php')){
    require '../vendor/autoload.php';
} else {
    echo "<h1>Please install via composer.json</h1>";
    echo "<p>Install Composer instructions: <a href='https://getcomposer.org/doc/00-intro.md#globally'>https://getcomposer.org/doc/00-intro.md#globally</a></p>";
    echo "<p>Once composer is installed navigate to the working directory in your terminal/command prompt and enter 'composer install'</p>";
    exit;
}
```

1.  接下来，我们将设置我们的环境。

1.  我们将定义一个名为`ENVIRONMENT`的常量，并给它一个开发的值。当进入`production`时，将`environment`设置为`production`。

### 注意

在生产环境中，您不希望显示错误。拥有一个环境常量是设置应用程序环境的好方法：

```php
define('ENVIRONMENT', 'development');
```

1.  现在，根据`environment`常量，我们可以设置适当的错误报告级别：

```php
if (defined('ENVIRONMENT')){
    switch (ENVIRONMENT){
        case 'development':
            error_reporting(E_ALL);
        break;
        case 'production':
            error_reporting(0);
        break;
        default:
            exit('The application environment is not set correctly.');
    }
}
```

### 注意

在开发模式下，将显示所有错误，但在生产模式下，将不显示任何错误。

完整的文件看起来像这样：

```php
<?php
if(file_exists('../vendor/autoload.php')){
    require '../vendor/autoload.php';
} else {
……
            error_reporting(0);
        break;
default:
            exit('The application environment is not set correctly.');
    }

}
```

### 注意

有关完整的代码片段，请参阅代码文件夹中的 Lesson 6.php 文件。

### 注意

现在将创建一个名为 vendor 的新文件夹。这个文件夹是 Composer 安装其所需文件和任何第三方依赖项的位置。

1.  现在您可以返回浏览器并重新加载页面。现在应该看到一个空白页面。

### 注意

这意味着 Composer 正在工作，但我们还没有请求加载任何内容。

当打开 Whoops 包时，视图中的错误将在屏幕上显示代码的完整堆栈跟踪，以显示框架如何执行代码的路径。这可以帮助开发人员通过跟踪其代码的路径来隔离问题。

# 活动：使用 Composer 安装依赖项

假设您正在开发一个 PHP 项目，并且您的项目需要很多依赖项。您有严格的截止日期，但是在添加这些依赖项之前，您无法继续。您发现可以使用 Composer 自动安装依赖项。现在您需要安装 Composer。

这项活动的目的是让您熟悉 Composer 安装。

要执行此活动，请按照以下步骤进行：

1.  通过打开终端或命令提示符来运行框架。

1.  如果在 Windows 上，导航到`framework`文件夹并启动 php 服务器：

```php
php –S localhost:8000 –t Webroot
```

### 注意

`-S`表示运行服务器并使用 localhost:8000 作为其地址，`-t Webroot`将文档`root`设置为`Webroot`文件夹。

终端输出将如下所示（您的系统上的某些细节可能会有所不同）：

```php
PHP 7.1.4 Development Server started at Wed Nov 29 20:37:27 2017
Listening on http://localhost:8000
Document root is /Users/davidcarr/Dropbox /projects/localsites/framework/webroot
Press Ctrl-C to quit.
```

1.  现在，转到`http://localhost:8000`，您将看到我们在`index.php`的`else`语句中编写的 Composer 说明。

1.  这是因为我们还没有设置 Composer。我们可以在终端中输入以下内容来完成这一步：

```php
composer install

```

输出将如下所示：

```php
Loading composer repositories with package information
Updating dependencies (including require-dev)
Package operations: 2 installs, 0 updates, 0 removals
  - Installing psr/log (1.0.2) Loading from cache
  - Installing filp/whoops (2.1.14) Downloading: 100%
filp/whoops suggests installing symfony/var-dumper (Pretty print complex values better with var-dumper available)
filp/whoops suggests installing whoops/soap (Formats errors as SOAP responses)
Writing lock file
Generating autoload files
```

1.  请注意，现在将创建一个名为`vendor`的新文件夹。这个文件夹是 Composer 安装其所需文件和任何第三方依赖项的位置。

1.  现在，返回浏览器并重新加载页面。

### 注意

现在应该看到一个空白页面。

这意味着 Composer 正在工作，但我们还没有请求加载任何内容。

1.  回到编辑器中的 index.php，在文件底部添加以下行：

```php
//initiate config
$config = App\Config::get();

new System\Route($config);
```

这将加载我们的`config`类并设置我们的路由。

1.  保存`index.php`并在`app`文件夹中创建一个名为`Config.php`的新文件。

### 注意

请注意将文件命名为`Config`而不是`config`。在基于 Unix 的系统（如 Mac 和 Linux）上，大小写敏感。

我们已经到达了本节的末尾。我们学会了如何引导应用程序，这允许单一入口点，并且学会了如何使用 Composer 自动加载类。我们讨论了如何处理错误，最后，我们讨论了框架的构建过程。

在下一节中，我们将设置配置类并设置路由。

# 配置类、默认类和路由

在本节中，我们将学习`configuration`类，并且我们还将设置路由。

我们将设置`config`类。这将位于`app`文件夹的根目录下。`config`类存储默认控制器，要加载的`default`方法以及数据库凭据。在`index`文件的开头，您将把`config`类传递给`route`类。`route`类控制何时加载以及何时加载。现在的重点是`configuration`类和路由。其他组件将在后面的章节中更详细地讨论。

`configuration`类是框架选项的数组，包括以下内容：

+   数据库源凭据

+   默认控制器的路径

+   默认方法的路径

在本节中，我们还将创建一个负责加载视图的视图类，这使得可以显示表示层的位置。

在设置路由时，我们正在告知框架在文件系统中查找与 URL 匹配的位置。

在加载正确的文件时，这将是所需的控制器类。我们将激活所需的方法、所需的模型和所需的视图。

我们将做所有这些，以便用户可以在他们的浏览器中看到他们通过简单点击链接请求的内容，这又称为向服务器发出请求。

然后，我们将创建`route`类，它从 URL 中获取段，以便知道要加载哪个控制器和方法以及要传递的参数。

例如，URL `http://localhost:8000/contacts/view/2` 表示*转到 contacts 控制器的 view 方法*。在这种情况下，数字 2 表示传递给 view 方法的参数。

### 注意

`configuration`类更常被开发人员称为配置类。

配置是用户可能寻求帮助以了解如何记住其框架项目的重要细节的自然位置。建议开发人员开发一个系统来记住其项目的细节。

如果他们计划将其项目开源，这可能会有所帮助。对于开发人员来说，如果他们需要在以后的某个日期记住项目的细节，这也可能会有所帮助，因为可能会有几个月甚至几年的时间过去，开发人员需要重新访问该项目。

这些可能是什么样的细节？

+   **版本号** - 随着时间的推移，开发人员可能会进行添加和改进，这可能会影响代码基础的核心。知道你正在使用的版本可以帮助你在以后选择适当的编程方法。

+   **鸣谢** - 为使用其他开发人员的工作给予信用是一个好习惯。如果你未能这样做，你可能会收到一个不愉快的未署名开发人员的电子邮件。

+   **作者详情** - 开源项目的用户可能会从原始开发人员的联系方式中受益。不愉快的未署名开发人员需要一个地方发送不愉快的电子邮件。![配置类、默认类和路由](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/6_02.jpg)

以下是一个 Config 类的示例

## 加载视图文件

完成本节后，我们将查看一个示例，以演示加载视图文件的能力。但是，在此阶段尚未创建任何视图，因此使用自定义的 404 页面代替。

本节的示例在浏览器中加载了框架。最初，您将在浏览器中看到一个 404 消息，因为找不到视图。这是因为默认控制器不存在。

`views`文件夹中存在一个名为`404.php`的示例文件，其中包含消息“找不到文件”。保存文件并刷新新创建的 404 页面的浏览器。

1.  打开 php 并为文件设置一个`namespace`为 App。

### 注意

该类属于 App 命名空间，因为它存储在**app**文件夹中。

1.  接下来，定义一个名为`Config`的类，并创建一个名为`get`的方法。

### 注意

`get`方法需要返回一个数组。数组的键将是用于路由和数据库凭据的设置：

有关完整的代码片段，请参阅代码文件夹中的`Lesson 6.php`文件。

```php
<?php namespace App;

class Config {
……
    public static function get()
            'db_name'     => 'mini',
            'db_username' => 'root',
            'db_password' => '',
        ];
    }
}
```

### 注意

前面的命名空间定义保存了`App\Controllers`的路径。请注意双反斜杠 - 这是因为反斜杠经常被转义，因此使用双反斜杠可以阻止其被转义。

当我们编写路由时，命名空间定义、默认控制器和默认方法将变得清晰。

1.  最后，设置数据库属性。

1.  设置要使用的数据库类型及其位置的数据库属性，然后是数据库名称以及访问数据库的用户名和密码。

1.  您需要访问 MySQL 数据库以创建数据库。为了设置本地数据库，建议使用 MariaDB。要下载 MariaDB，请按照[`mariadb.com/downloads/mariadb-tx`](https://mariadb.com/downloads/mariadb-tx)上的说明进行操作。

### 注意

在这个例子中，我们有一个名为 mini 的数据库，我的用户名是 root。我们没有密码，所以我们将其留空。

1.  保存`Config.php`文件。

1.  在`routing`类设置之前，我们需要创建一个`View`类。这个类将负责加载`view`文件，当找不到 URL 时还会显示 404 页面。

1.  在 system 中，创建一个名为`View.php`的新文件。

1.  打开 php 并将命名空间设置为`System.`接下来，定义一个名为`View`的类，并创建一个名为`render`的方法，该方法接受两个参数，`$path`和`$data`。

### 注意

`$path`将保存请求文件的路径。

`$data`将保存要传递给`view`文件的内容。

`$data`是可选的；请注意它的默认值是`false`。这意味着如果只传递一个参数给`render`方法，那么数据将不会被使用。

在方法 ID 内，一个布尔值检查`$data`。如果它是`false`，则忽略；否则，使用`foreach`循环遍历数据。在每次循环中，数据都会提取到一个本地变量中。

1.  循环结束后，设置视图文件将存储的相对路径，本例中为`app/views/`，后跟请求的视图。

1.  最后，进行检查以确保`view`文件存在并且需要它，否则会生成错误：

### 注意

有关完整的代码片段，请参阅代码文件夹中的`Lesson 6.php`文件。

```php
<?php
namespace System;

/*
 * View - load template pages
 *
 */
class View {
…….
        } else {
            die("View: $path not found!");
        }

    }
}
```

1.  保存文件并在`system`文件夹内创建一个名为`Route.php`的新文件。

1.  打开 php 并将命名空间设置为`System.`。

1.  我们刚刚创建的`View`类需要对这个类可用。要导入它，请添加：

```php
use System\View;
```

### 注意

这加载了`View`文件。PHP 之所以知道在哪里找到文件，是因为命名空间，这是 Composer 在起作用。以这种方式导入类非常有帮助。

1.  现在，创建一个名为`Route`的类和一个名为`__construct`的方法，该方法期望一个名为`$config`的参数：

```php
<?php namespace System;

use System\View;
class Route
{
    public function __construct($config)
    {
```

1.  现在，设置以下变量：

```php
$url        = explode('/', trim($_SERVER['REQUEST_URI'], '/'));
$controller = !empty($url[0]) ? $url[0] : $config['default_controller'];
$method     = !empty($url[1]) ? $url[1] : $config['default_method'];
$args       = !empty($url[2]) ? array_slice($url, 2) : array();
$class      = $config['namespace'].$controller;0
```

### 注意

`$url`将保存请求路由的数组形式，如/page/requested。工作原理是：当运行 explode 时，它会在请求的 URI 中找到一个斜杠，$_SERVER 使其可用。

接下来，`$controller`方法使用三元运算符来检查$url 的第 0 个索引是否存在，否则使用 Config 类中定义的 default_controller。

`$method`检查是否存在`$url[1]`，否则从 config 类中读取。

$args 将获取$url 的第一个 2 个索引之后的所有其他索引。

`$class`保存在`Config`类中设置的控制器的路径。

这些参数的作用是从请求的 URL 中获取控制器、方法和参数。例如：

`http://localhost:8000/contacts/view/2`

这导致：

联系人 = 联系人类。

视图 = 联系类内的视图方法。

2 = 传递给方法的参数。

如果请求的 URL 是 http:://localhost:8000/，则不需要请求控制器或方法，因此将使用默认控制器和方法，如在`system\Config.php`中设置的那样。

1.  设置这些变量后，进行检查，即如果类不存在，则调用`Route`类中存在的`not_found`方法（尚未设置）：

```php
//check the class exists
if (! class_exists($class)) {
    return $this->not_found();
}
```

1.  接下来，检查方法以确保它存在：

```php
//check the method exists
if (! method_exists($class, $method)) {
    return $this->not_found();
}
```

1.  接下来，设置一个类的实例：

```php
//create an instance of the controller
$classInstance = new $class;
```

1.  通过调用`call_user_func_array`并将类实例和方法的数组以及任何参数作为第二个参数传递来运行该类：

```php
//call the controller and its method and pass in any arguments
call_user_func_array(array($classInstance, $method), $args);
```

1.  如果调用了一个不存在的`route`，则需要一个`not_found`方法。这将调用`render`方法并将`404`作为参数传递。这将尝试加载`app/view/404.php`，如果存在的话：

```php
//class or method not found return a 404 view
public function not_found()
{
    $view = new View();
    return $view->render('404');
}
```

完整的类如下所示：

### 注意

有关完整的代码片段，请参阅代码文件夹中的`Lesson 6.php`文件。

```php
<?php namespace System;

use System\View;

class Route
…….
    {
        $view = new View();
        return $view->render('404');
    }
 }
}
```

## 操纵输出

本节向您展示了如何操纵上一个示例的输出。以下是操作步骤：

1.  加载框架`http://localhost:8000`，你会看到以下输出：

```php
View: 404 not found!
```

### 注意

这是因为默认控制器还不存在，app/views/404.php 也不存在。

1.  在`app`文件夹中创建一个`views`文件夹，并创建一个名为`404.php`的文件。输入消息，比如`'文件找不到。'`，然后保存文件。

1.  重新加载框架在你的浏览器中，你现在会看到你的消息。

在本节中，我们涵盖了`configuration`类，我们看到了配置类如何位于`root`文件夹的顶部。我们还看到了如何设置路由，其中我们执行了`view`页面的加载。

在下一节中，我们将介绍基础控制器，它定义了 MVC 框架的主要功能。

### 基础控制器、默认状态和路由

基础控制器类——因为 MVC 框架的性质——需要一个默认状态。

默认视图是由默认控制器类中的默认方法加载的。

从这个默认控制器类中，加载系统中的所有其他控制器。

默认的`Controller`类和默认方法的创建将是我们在本节中构建的重点。

### 注意

模型不一定要包含在控制器中，视图也可以独立于数据源工作。

### 设置基础控制器、默认状态和路由

在本节中，我们将看到如何设置基础控制器、默认状态和路由。以下是步骤：

**视图:**

1.  现在，让我们设置默认视图。在`app\views`中创建一个名为`default.php`的文件，并写入内容``Hello from default view``或其他消息。

这将在框架的主页上显示。

**控制器:**

在我们开始构建应用程序控制器之前，我们需要一个所有其他控制器都可以继承的基础控制器。这样做的原因是控制器可以使用基础控制器中定义的任何属性或方法。

1.  创建一个名为`BaseController.php`的新文件，并将其保存在`system`文件夹中。

1.  打开 php 并将命名空间设置为`System`。定义一个名为`BaseController`的类。

1.  定义两个名为`$view`和`$url`的类属性。这两个属性都将具有公共的访问修饰符，这意味着在使用`BaseController`的任何地方，这些属性都将可用。

1.  接下来，创建一个`construct`方法，然后设置一个`View`类的新实例。这样`$this->view`就可以用来调用`extended`控制器中的`view`的`render`方法。

1.  接下来，将`getUrl()`方法分配给`$this->url`属性。这将调用另一个方法来获取当前的 URL。

1.  现在，对环境模式进行检查。如果设置为开发模式，那么将创建一个新的 Whoops 错误处理程序的实例。这个 Whoops 类是由 Composer 引入的，如 composer.json 文件中所定义的。

当在浏览器中运行代码时，`Whoops`类将提供丰富的错误堆栈跟踪。

1.  最后，定义一个`getUrl`()方法，它将返回请求的 URL：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 6.php`文件。

```php
<?php namespace System;

use System\View;

class BaseController
{

  public $view;
………
    $url = isset($_SERVER['REQUEST_URI']) ? rtrim($_SERVER['REQUEST_URI'], '/') : NULL;
    $url = filter_var($url, FILTER_SANITIZE_URL);
    return $this->url = $url;
  }

}
```

**Home 控制器:**

1.  在`app/Config.php`中，我们将`default_controller`设置为`home`:

```php
//set default controller
'default_controller' => 'Home',

//set default method
'default_method' => 'index',
```

1.  现在让我们创建它。在`app`文件夹中创建一个`Controllers`文件夹，并创建一个名为`Home.php`的文件。

### 注意

所有类都应该以大写字母开头，每个后续的单词都应该大写。

1.  打开 php 并将命名空间设置为`App\Controllers`。这个命名空间引用了文件夹结构。

1.  接下来，通过调用其命名空间和名称来导入`BaseController`。

1.  定义一个名为`Home`的类，并扩展`BaseController`。

这将允许`Home`控制器访问`$this->view`并加载视图。

1.  创建一个名为`index`的方法，然后返回`$this->view->render`并传递要加载的文件名。

1.  在这种情况下，传递默认值，将加载`app\views\default.php`：

```php
<?php
namespace App\Controllers;

use System\BaseController;

class Home extends BaseController
{
  public function index()
  {
    return $this->view->render('default');
  }
}
```

## 活动：探索结果

现在我们将能够看到任务的输出，就像在演示文件中看到的那样。按照以下步骤来做：

1.  在浏览器中打开你的框架`http://localhost:8000`，你将看到你的默认视图文件被加载。

1.  记得那个 Whoops 类吗？好吧，让我们看看它的作用。打开你的`default.php`视图文件，在文件末尾添加这段代码。打开 php 并写点东西，但不是在一个字符串中。代码应该如下所示：

```php
Hello from default view.
<?php ohno!
```

1.  现在，在浏览器中保存并重新加载页面，你会看到：![活动：探索结果](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/6_03.jpg)

这个页面告诉你错误是什么，但也显示了问题所在的代码片段和完整的堆栈跟踪，这样你就可以追踪从执行到失败的过程：

1.  现在，从`default.php`中删除你的修改，使它只包含你的原始内容，保存并重新加载页面。你将再次看到你的页面正常加载。

1.  现在，让我们看看如何访问一个新的方法。在你的 Home 控制器中，创建一个名为`packt`的新方法，加载一个名为`packt`的视图。

1.  在 app\views 中创建一个名为`packt.php`的新视图文件，并输入文本'`Hello from Pack!'`

1.  通过转到`home/packt http://localhost:8000/home/packt`来加载页面。

现在，你将看到你的`packt`视图文件的内容。

在这一部分，我们对默认状态在我们的项目中扮演的角色有了更好的理解。这个项目需要这些基本方法来最初运行和扩展。

我们通过构建默认状态，包括`baseController`和`baseMethod`，获得了经验。

在下一节中，我们将学习 PDO，这是一个轻量级的接口，用于在 PHP 中访问数据库。

# 使用 PDO

在这一部分，我们将创建 PDO 包装器，并使用数据库作为我们模型的数据源。

从这一部分开始，我们将能够在我们的框架项目中使用数据库。

这里将涵盖六种方法。

我们有一个`get`方法——这是用于创建与数据库的连接，并确保它是一个单例实例，这意味着它只能有一个实例：

+   我们有一个`raw`方法来运行原始的、不安全的查询

+   一个`select`方法，用于运行安全查询，从数据库中选择记录

+   一个`insert`方法来创建新的记录

+   一个`update`方法来更新记录

+   一个`delete`方法来删除记录

+   一个`truncate`方法来清空一个表

这样做的目的是让你的 CRUD 工作。没有这个类，CRUD 功能将不可能实现。

基本模型是我们使用数据库助手创建数据库连接的地方。

这将允许其他模型类从这个模型扩展并使用数据库连接。这只包括一个单一的方法：

**构造：**

这个方法负责将配置传递给数据库助手，以创建数据库连接。

现在，我们准备开始使用数据库。

### 注意

数据库访问：如果你发现你没有访问数据库客户端或 PHP 管理网页界面的权限，那么一个备用选项被包括在内，所有学生都可以使用它来创建数据库和插入数据。

接下来的部分是关于在 apps 文件夹中创建第一个模型的。我们将创建模型`contact.php`，并讨论最佳实践和命名约定，以及从之前创建的基本模型中扩展，以及设置一个从数据库中显示记录的方法。

接下来，我们将创建一个`contact`控制器，它继承自基本控制器。在调用索引方法之前导入联系人模型，并将记录从模型传递到视图。在那个视图中，我们将浏览记录并逐行显示它们。

然后我们打开浏览器，转到联系人控制器，看到联系人显示在页面上。

要加载不同的控制器，过程与前一个子主题中描述的相同。创建一个控制器，设置其命名空间，并定义存在于基本控制器中的类，要么有一个在调用控制器名称时加载的索引方法，要么使用不同的名称并通过调用您的控制器名称/方法名称来访问它。

我们几乎已经完成了框架的设置。现在，我们可以创建控制器和方法来加载页面并将数据传递给视图。对于静态站点来说，这很棒 - 它将保持您的代码有组织并且运行速度快 - 但缺少的一个重要组件是使用数据库的能力。

在这一点上，我们将创建一个数据库助手。这是一个存储在名为`helpers`的公共文件夹中的类的花哨名称。助手是不适合控制器或模型的类，而是独立的类来扩展功能。

数据库助手将有六种方法：

+   `get()` - 设置数据库连接

+   `raw()` - 运行原始的、不安全的查询

+   `select()` - 运行查询以从数据库中选择记录

+   `insert()` - 创建新记录

+   `update()` - 更新现有记录

+   `delete()` - 删除现有记录

+   `truncate()` - 清空表

## 创建联系人控制器并查看记录

在本节中，我们将开始创建我们的联系人控制器。按照以下步骤进行操作：

1.  首先，在`app`文件夹内创建一个名为`Helpers`的文件夹，并创建一个名为`Database.php`的新文件。

1.  打开 php 并将命名空间设置为`App\Helpers。`

1.  接下来，我们需要导入 PDO。

### 注意

PDO 是一个数据库抽象层；它是一个支持 12 种不同数据库引擎的包装器，包括 MySQL。这是我们将用来与数据库交互的工具。

1.  要导入 PDO，请使用`use`语句：

```php
<?php
namespace App\Helpers;

use PDO;
```

1.  接下来，定义一个名为`Database`的类，它扩展了`PDO`。在类内部创建一个名为`$instances`的属性，并将其设置为数组数据类型。

1.  `$instances`属性将用于确保只有一个数据库连接在使用：

```php
class Database extends PDO
{
protected static $instances = array();
```

1.  接下来，创建一个名为`get()`的方法，接受一个名为`$config`的参数。这将是在`app\Config.php`中设置的`Config`。

1.  在这个方法中，设置本地变量以保存数据库凭据。这些值将从`$config`数组中提取。

1.  然后，创建一个名为`$id`的变量。这将保存所有数据库本地变量以创建标识符。接下来，执行一个检查，检查`$instance`属性是否已经有了这个`$id`。

1.  如果`$instances`确实有`$id`，那么它将返回`$instance`，否则将尝试新的 PDO 连接。

### 注意

连接到 PDO 时，传递数据库凭据并将字符集设置为 UTF-8。

1.  在下一行，错误模式设置为异常。这意味着任何异常都将被引发和显示。

1.  现在，将`$instance`设置为当前连接并返回`$instance：`

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 6.php`文件。

```php
GET method

public static function get($config)
{
  // Group information
…….
  // Setting Database into $instances to avoid duplication
  self::$instances[$id] = $instance;

  //return the pdo instance
  return $instance;

}
```

**RAW 方法**

1.  创建一个名为`raw`的方法。这是一个非常简单的方法。它接受一个参数，即 SQL 语句。`$sql`传递给`$this->query`，然后直接运行查询：

### 注意

这对于执行不需要安全的查询非常有用。如果没有进行检查，查询将按原样执行，并返回结果。

```php
public function raw($sql)
{
  return $this->query($sql);
}
```

**SELECT 方法：**

1.  接下来，创建一个名为`select()`的方法。这将接受四个参数：

+   `$sql` - SQL 查询

+   `$array` - 要绑定到查询的任何键（可选）

+   `$fetchMode` - 设置 PDO 提取模式，默认为对象（可选）

+   `$class` - 用于指定与提取模式一起使用的类

### 注意

在方法内部，这样您就不必编写`$this->db->select('SELECT * FROM table') w`e 将向 SQL 查询添加 select，前提是它还没有。这是通过将大小写更改为小写，然后使用`substr`来检查`$sql`的前七个字母。如果不等于 select，则在开头添加 select。

1.  接下来，准备查询。这将设置 SQL 查询而不运行它。接下来，循环遍历$array，并将任何值分配给特定的数据类型。如果值是 INT，则使用 PARAM_INT 数据类型，否则数据类型将使用字符串。

1.  最后，执行运行。这将$SQL 传递到服务器，并将绑定的$array 键分开，这意味着永远不会发生 SQL 注入，从而产生安全的查询。

查询执行后，然后返回响应。默认情况下，返回一个对象：

### 注意

有关完整的代码片段，请参阅代码文件夹中的`Lesson 6.php`文件。

```php
public function select($sql, $array = array(), $fetchMode = PDO::FETCH_OBJ, $class = '')
{
……
    return $stmt->fetchAll($fetchMode);
  }
}
```

**插入方法**

1.  要向数据库插入新记录，需要插入查询。创建一个名为 insert 的新方法，带有两个参数：

+   $table - 表的名称

+   $data - 要插入到$table 中的键和值的数组

1.  使用 ksort($data)对$data 数组进行排序。

1.  接下来，将所有数组键提取到名为`$fieldNames`的变量中。这是使用 implode 完成的，设置每个键之间的逗号，并对$data 运行`array_keys()`。

1.  现在，再做一次相同的操作，这次添加`,` `:`作为 implode 选项，并将其保存到名为$fieldValues 的变量中。

1.  然后，使用`$this->prepare`，可以编写一个 SQL 命令，将`$fieldNames`设置为`$fieldValues`的值，用于`$table`。循环遍历`$data`并绑定值。

1.  最后，返回最后插入记录的 ID。当您需要主键在记录插入后立即使用时，这将非常有用：

```php
public function insert($table, $data)
{
  ksort($data);
  $fieldNames = implode(',', array_keys($data));
  $fieldValues = ':'.implode(', :', array_keys($data));

  $stmt = $this->prepare("INSERT INTO $table ($fieldNames) VALUES ($fieldValues)");

  foreach ($data as $key => $value) {
    $stmt->bindValue(":$key", $value);
  }
  $stmt->execute();
 return $this->lastInsertId();
}
```

**更新方法**

1.  接下来，创建一个名为 update 的方法，带有三个参数：

+   `$table` - 表的名称

+   `$data` - 要更新的数据的数组

+   `$where` - 一个键和值的数组，用于设置条件，例如，['id' => 2]，其中 id 等于 2

1.  对`$data`进行排序，然后提取`$data`。

1.  在循环内，附加到名为`$fieldData`的变量。添加`$key = :$key`。接下来，通过调用`trim()`删除任何右侧的空格。

1.  接下来，循环遍历`$where`数组。在每次循环中，分配`$key = :$key`。这将创建一个占位符列表，以便稍后捕获绑定。

1.  再次，删除任何右侧的空格，然后使用`$this->prepare`并编写更新 SQL，传递表名，后跟`fieldDetails`和`WhereDetails`。

1.  接下来，将键绑定到:`$key`占位符并执行查询。

1.  最后一步是返回`rowCount()`。这是已更新的记录数：

### 注意

有关完整的代码片段，请参阅代码文件夹中的`Lesson 6.php`文件。

```php
public function update($table, $data, $where)

{

  ksort($data);

  $fieldDetails = null;
…….
  }
  $stmt->execute();
  return $stmt->rowCount();
}
```

**删除方法**

1.  创建一个名为 delete 的新方法，带有三个参数：

+   `$table` - 表的名称

+   `$where` - 用于确定 where 条件的键值数组

+   `$limit` - 要删除的记录数，默认值为 1，传递 null 以删除数字限制

1.  在方法内部，对`$where`进行排序循环，并从数组的键和值设置占位符。

1.  准备查询并编写 SQL 命令，传递`$table`，`$where`和`$limit`。

1.  最后一步是返回 rowCount()。这是已删除的记录数：

### 注意

有关完整的代码片段，请参阅代码文件夹中的`Lesson 6.php`文件。

```php
public function delete($table, $where, $limit = 1)
{
  ksort($where);

……..
  $stmt->execute();
  return $stmt->rowCount();
}
```

**截断方法**

1.  最后要创建的方法称为 truncate，它接受一个参数，$table：

+   `$table` - 表的名称

1.  在方法内部，调用$this->exec 和 SQL 命令 TRUNCATE TABLE $table。这将清空表，导致没有记录。所有主键将被重置为 0，就好像从未使用过表一样：

```php
public function truncate($table)
{
  return $this->exec("TRUNCATE TABLE $table");
}
```

完整的类如下所示：

### 注意

有关完整的代码片段，请参阅代码文件夹中的`Lesson 6.php`文件。

```php
<?php namespace App\Helpers;

use PDO;
class Database extends PDO
{
  /**
   * @var array Array of saved databases for reusing
   */
   */
……
  {
    return $this->exec("TRUNCATE TABLE $table");
  }
}
```

1.  保存这个类。这是一个复杂的类，我们将要编写的其余代码要简单得多。在接下来的几页中，我们将使用数据库助手，并且随着使用方法的目的和用途，它们将变得清晰。

**基本模型**

1.  我们的下一个任务是创建一个`basemodel`类，它将使用数据库助手连接到数据库并返回实例。这将允许其他模型类从这个类扩展并使用数据库连接。

1.  在系统文件夹内创建一个名为`BaseModel.php`的文件。

1.  打开 php 并将命名空间设置为 System。

1.  通过调用它们的命名空间在 use 语句中导入 Config 类和 Database 助手类。

1.  定义类并调用 BaseModel，然后创建一个受保护的属性叫做`$db`。这是其他模型将用来与数据库交互的。 

1.  创建一个`__construct()`方法。这将在类被实例化时立即运行。在这个方法内，创建一个名为`$config`的本地变量，并将其赋值为`Config::get()`。

1.  接下来，创建一个 Database 助手的新实例并调用`get`方法并传入`$config`。

这个类看起来像这样：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 6.php`文件。

```php
<?php namespace System;
/*
 * model - the base model
 *
……..
//connect to PDO here.
$this->db = Database::get($config);
}
}
```

1.  现在，我们准备开始使用数据库。在继续我们的代码库之前，打开你之前连接的数据库，可以使用 phpmyadmin 或 MySQL 客户端，也可以使用终端。

1.  创建一个数据库——我们将其称为 mini——并创建一个名为`contacts`的表，其中包含两列：ID 和 name。

### 注意

如果你没有 MySQL 客户端，你可以通过终端来使用：

mysql -u root

用你的数据库用户名替换 root。Root 是默认值。我默认安装了 MariaDB。没有密码，但如果你需要输入密码，传递密码标志-p：

mysql -u root -p

1.  创建一个新的数据库。

1.  创建数据库`mini`。

1.  选择那个数据库：

```php
use mini
```

### 注意

现在使用名为 mini 的数据库。

1.  数据库是空的，所以让我们创建一个名为 contacts 的表：

```php
create table contacts ( `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
`name` varchar(255) DEFAULT NULL,
PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
```

要查看你的表的列表：

```php
show tables;

+-----------------+
| Tables_in_mini |
+-----------------+
| contacts    |
+-----------------+
1 row in set (0.00 sec)

Insert data into the table
insert into contacts (name) values('Dave');
insert into contacts (name) values('Markus');

this will insert the records to see the contents of the table:
select * from contacts;

+----+--------+
| id | name  |
+----+--------+
|  1 | Dave  |
|  2 | Markus |
+----+--------+
2 rows in set (0.00 sec)
```

通过这几个命令，数据库已经创建，表也已经被创建，并且已经填充了两条记录。

## 活动：创建和执行模型

我们已经创建了 contact 控制器并查看了结果。现在我们需要为我们的应用程序实现模型。

这个活动的目的是为我们的应用程序实现模型。

回到框架，我们现在准备创建我们的第一个模型。按照以下步骤进行：

1.  在`app`文件夹中，创建一个名为`Models`的新文件夹。这是所有模型将被存储的地方。现在，创建一个名为 Contact.php 的新文件。

### 注意

将你的模型命名为单数记录是最佳实践，所以在这种情况下，Contact 代表一个联系人表。

1.  在`Contact.php`中，打开`php`并将命名空间设置为`App\Models`。

1.  导入`BaseModel`并创建一个名为 Contact 的类，并扩展`BaseModel`。

1.  创建一个名为`getContacts()`的方法。这个方法将用于获取数据库中存储的所有联系人。

1.  调用`$this->db->select()`来调用数据库助手的`select`方法，并编写`SQL * FROM contacts`。

### 注意

最佳实践是将命令如`SELECT`，`FROM`，`WHERE`，`GROUP BY`和`ORDER BY`写成大写，这样在你的代码中清楚地表明这些命令。

这个模型看起来像这样：

```php
<?php
namespace App\Models;
use System\BaseModel;

class Contact extends BaseModel
{
  public function getContacts()
  {
    return $this->db->select('* FROM contacts);
  }
}
```

1.  现在，我们需要运行这个模型。这个最好的地方是在一个控制器内。在`app\Controllers`文件夹内创建一个名为`Contacts`的新控制器。

这个类扩展自`BaseController`，并有一个名为`index`的方法：

```php
<?php
namespace App\Controllers;

use System\BaseController;

class Contacts extends BaseController
{
  public function index()
  {

  }
}
```

让`index`方法加载一个名为`contacts/index`的视图：

```php
public function index()
{
  return $this->view->render('contacts/index');
}
```

1.  在`app\views`中创建一个名为`contacts`的文件夹，并创建一个名为`index.php`的文件。

如果你现在运行这个并转到`localhost:8000/contacts`，你会得到一个空白页面或者看到`contacts/index.php`的内容，只要你输入了一些内容。

1.  回到`contacts` `controller`，我们需要导入`contact`模型。我们通过使用`use`语句并设置命名空间到模型来做到这一点：

```php
use App\Models\Contact;

```

1.  在`index`方法内，创建一个`contact`模型的新实例，并调用`getContacts()`方法。将其赋值给一个名为`$records`的变量：

```php
$contacts = new Contact();
$records = $contacts->getContacts();
```

1.  接下来，将`$records`传递给`view:`

```php
return $this->view->render('contacts/index', compact('records'));
```

### 注意

使用`compact()`是一个干净的方法来放置一个表示变量的字符串名称。这将读取`$records`并将其传递给视图：

在 app\views\contacts\index.php

1.  打开`php`并检查`$records`是否存在，然后进行`foreach`循环并循环遍历每条记录。从`$row`对象中`echo`出`name`键。添加一个包含`<br>`标签的字符串-这将导致每次循环都在新行上：

```php
<?php
if (isset($records)) {
  foreach ($records as $row) {
    echo $row->name.'<br>';
  }
}
```

1.  保存并在浏览器中运行，转到`http://localhost:8000/contacts`。您将看到数据库中存储的`contacts`表中的联系人列表。

# 总结

在本章中，我们对数据库类在项目中的作用有了更好的理解，这在开发人员与数据库交互时被使用。它是 PDO 查询的包装器。他们不需要直接调用它，因为他们是从中扩展的。

我们使用的唯一库叫做 Whoops，它将以可读的格式显示错误。

我们还获得了构建默认状态的经验，包括`baseController`和`baseMethod`。

在下一章中，我们将构建一个登录系统和用户登录和退出的身份验证。这将扩展我们到目前为止所涵盖的内容，并引入新的概念。我们还将在下一章中构建密码恢复系统。


# 第七章：身份验证和用户管理

在上一章中，我们更好地理解了`数据库`类在项目中的作用，这在开发人员与数据库交互时使用。

我们使用的唯一库叫做 Whoops，它将以可读格式显示错误。我们还获得了构建默认状态的经验，包括`baseController`和`baseMethod`。

在本章中，我们将专注于项目的安全方面，即身份验证。我们将构建登录表单，该表单与数据库交互以验证用户的身份。最后，我们将介绍如何在我们的应用程序中设置密码恢复机制。

在本章结束时，您将能够：

+   为他们的应用程序构建默认视图

+   构建密码管理和重置系统

+   为系统应用程序中的模块构建 CRUD

# 设置路径和包含 Bootstrap

在本节中，我们将继续在框架的基础上构建功能。核心框架系统文件已经就位。这个设置用于在此基础上构建有用的功能。

我们将构建身份验证系统并完成应用程序构建。身份验证是必需的，以防止未经授权的用户访问。这确保只有具有有效用户名和密码的用户才能登录到我们的应用程序中。

### 注意

在本章中，我们将涵盖身份验证。请注意，本课程中使用的所有示例的登录用户名和密码如下：

用户名：`演示`

密码：`演示`

## 设置路径和创建文件目录的绝对路径

相对路径是相对于当前文件夹路径的路径，例如，`./css`指向一个相对路径，向上一个文件夹并进入`css`文件夹。

绝对路径是文件或文件夹的完整路径，例如`/user/projects/mvc/css`。

这一点很重要，因为这将允许在框架系统的任何地方使用绝对路径包含文件。这是对系统中现有代码的调整。

例如：

```php
$filepath = "../app/views/$path.php";
```

这变成了：

```php
$filepath = APPDIR."views/$path.php";
```

这在当前概念的基础上构建，并允许视图组织到子文件夹中。没有这种适应，将无法将任何内容组织到子文件夹中，并且会干扰代码的整洁组织。

没有这些更改也可以继续构建系统，但确保代码整洁有序总是一个好主意。

## 创建布局文件

布局文件是必需的，以便显示任何错误。

此外，`页眉`、`页脚`和`导航`需要布局文件。创建后，这些文件将提供应该在整个应用程序中引入的元素。这将包括全局元素。

![创建布局文件](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/7_01.jpg)

### 注意

错误用于验证，这将在进一步的子部分中进行介绍，不要与先前看到的错误中的解析错误或类似错误混淆。这些步骤涉及的错误与表单验证相关的错误，其中用户将不正确的信息输入到表单字段中。

## 包含 Bootstrap

Bootstrap 是一个 HTML、CSS 和 JavaScript 库，将在本章中包含，以提供基本的样式。对开发人员很有用，因为它可以帮助他们在设计师添加设计元素到应用程序之前，原型和可视化他们的应用程序将如何看起来。

在这个项目中，Bootstrap 将作为**内容传送网络**（**CDN**）包含在页眉中。CDN 获取在网络上非常常见的资源并对其进行缓存，以帮助提高性能。

### 注意

这很容易与引导框架混淆。

Bootstrap，HTML、CSS 和 JavaScript 库以及引导概念是两个不同的东西，它们有相似的名称。

您可以通过访问以下链接找到有关 Bootstrap 的更多信息：[`getbootstrap.com/`](https://getbootstrap.com/)。

# 引入 Bootstrap 和 HTML 标记

该部分的目的是实现我们已经实现的通用样式，显示了引入 bootstrap 和 HTML 标记：

![引入 Bootstrap 和 HTML 标记](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/7_02.jpg)

尚未解决的问题是路径。到目前为止，我们一直在使用相对路径来包括`system/View.php`中的视图文件。让我们解决这个问题：

1.  打开`webroot/index.php`，并在第 9 行后添加以下行：

```php
defined('DS') || define('DS', DIRECTORY_SEPARATOR);
define('APPDIR', realpath(__DIR__.'/../app/') .DS);
define('SYSTEMDIR', realpath(__DIR__.'/../system/') .DS);
define('PUBLICDIR', realpath(__DIR__) .DS);
define('ROOTDIR', realpath(__DIR__.'/../') .DS);
```

这些是可以在框架中的任何地方调用的常量。第一行定义了目录分隔符，例如`/`或`\`，具体取决于机器：

+   `APPDIR` – 指向`app`文件夹

+   `SYSTEMDIR` – 指向`system`文件夹

+   `PUBLICDIR` – 指向`webroot`文件夹

+   `ROOTDIR` – 指向`root`项目路径

每个都创建到其终点的绝对路径。

1.  现在，让我们修复`View`类。打开`system/View.php`，在第 24 行，替换：

```php
$filepath = "../app/views/$path.php";
```

使用：

```php
$filepath = APPDIR."views/$path.php";
```

### 注意

这允许视图从父文件夹或子文件夹中包含其他视图，而不会出现问题。

1.  接下来，在`app/views`文件夹内创建一个名为`layouts`的文件夹。在`app/views/layouts`内创建以下文件：

+   `errors.php`

+   `footer.php`

+   `header.php`

+   `nav.php`

+   `errors.php`

1.  打开`errors.php`并输入以下代码：

```php
<?php
use App\Helpers\Session;

if (isset($errors)) {
    foreach($errors as $error) {
        echo "<div class='alert alert-danger'>$error</div>";
    }
}

if (Session::get('success')) {
    echo "<div class='alert alert-success'>".Session::pull('success')."</div>";
}
```

### 注意

这包括一个 Session 助手，我们将很快创建。

第一个`if`语句检查`$errors`是否存在，如果存在，则退出循环并显示警报。这些类是`Bootstrap`类（我们将在`header.php`中有这些）。

接下来的`if`语句检查是否存在名为`success`的会话，并且如果存在，则显示其内容。这用于向用户提供反馈。

1.  打开`header.php`并输入以下代码：

```php
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title><?=(isset($title) ? $title.' - ' : '');?> Demo</
title>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css">
<link rel="stylesheet" href="/css/style.css">

<script src="https://code.jquery.com/jquery-2.2.4.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js"></script>
</head>
<body>

<div class="container">
```

### 注意

这将设置 HTML 文档，并在必要时使用`$title`，如果存在的话。还包括 Bootstrap CDN CSS 和 JavaScript，以及 jQuery 和位于`webroot/css/style.css`的自定义 style.css 文件 - 创建此文件。

1.  现在，打开`footer.php`，关闭容器`div`和`body`和`html`标签：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
</div>
</body>
</html>
```

1.  现在，打开`nav.php`并输入以下代码：

```php
<nav class="navbar navbar-default">
……
      </div><!--/.nav-collapse -->
    </div><!--/.container-fluid -->
</nav>
```

### 注意

这是 Bootstrap 的导航组件。这是一种为我们的管理页面引入响应式菜单的干净方式。注意两个页面链接，分别是管理和用户。我们还将提供一个注销链接。

1.  现在，打开`app/views/404.php`并包含布局文件：

```php
<?php include(APPDIR.'views/layouts/header.php');?>
404!
<?php include(APPDIR.'views/layouts/footer.php');?>
```

### 注意

这将引入页眉并显示页面内容，并以包括页脚结束。

不要在这里包括`nav`。即使用户未登录，也可以显示 404。

这样可以以非常干净的方式将常见的布局组织到视图中，这样当您需要更改全局元素时，布局视图就是它们存储的地方。

1.  如果框架尚未运行，请在浏览器中打开框架。在根目录时，从终端运行以下命令：

```php
php –S localhost:8000 –t webroot
```

### 注意

您不会注意到任何不同，但您将被重定向到一个不存在的页面：`http://localhost:8000/example`。

1.  您将看到一个包含页眉和页脚布局的 404 页面。查看页面源代码 - 右键单击并单击“查看页面源代码”。您应该看到以下输出：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
<!doctype html>
<html lang="en">
<head>
……
404!
</div>
</body>
</html>
```

随着我们进入本章的深入，这些布局将变得更加明显。

在本节中，我们已经介绍了如何正确设置文件路径。我们介绍了如何正确设置 Bootstrap，并最终为错误和页眉、页脚、导航和错误设置了视图。

在下一节中，我们将介绍如何向我们的应用程序添加安全性并设置密码恢复。

# 向项目添加安全性

在本节中，我们将继续在框架之上构建功能。核心框架系统文件已经就位。

本节的目标是构建功能，以增强项目的安全性。我们将涵盖需要在应用程序中保持良好安全性的各个方面。

## 帮助程序

在本小节中，我们将涵盖`helpers`。

我们将创建一个`URL` `helper`和一个`session` `helper`。这对身份验证以及系统的任何其他方面都很有用，但并不直接相关。

会话助手是 PHP 会话的“包装器”，包括对开发人员有用的各种方法，用于处理会话。

`URL` `helper`在某种意义上与`session`类似，它是处理 URL 的有用方法。但是，在本书中，它要短得多，只限于单个方法。

### 注意

`session`是一种存储临时数据的方法，比如用户是否已登录。

## 身份验证

现在，我们将构建身份验证功能。身份验证是一种只允许具有正确凭据的人访问受限部分的方法。

这将涉及创建一个数据库表和一个模型：

+   在数据库中创建用户表

+   在 app 模型中创建一个用户模型

+   添加插入、更新、删除方法

然后，我们将创建一个管理员控制器，并导入 URL 和`session`帮助程序以及`user`模型。

最后，我们将创建相关的视图。

### 仪表板

项目将需要一个仪表板；这就像一个需要登录的项目的主页，通常包括指向项目经常访问内容的链接。在这个项目中，我们只需要确保仪表板有一个存在的文件，以便可以将其定向到它。您将创建仪表板视图，并包括布局文件以及页眉、页脚、导航和错误。您将为页面结构添加 HTML。

### 登录

创建登录页面也是本节的一部分。

在登录视图中，您将创建一个登录表单，并包括布局文件。

然后，他们将创建一个登录方法来处理登录过程：

+   部分过程是使用密码哈希和 bcrypt 对密码进行哈希处理

+   使用设计用于返回数据的 Get data 方法

+   除了创建视图和登录方法，我们还将创建`logout`方法，并修改配置，以便默认情况下主页将是管理员仪表板

### 密码哈希

密码哈希使用 bcrypt，这是目前最强大的算法。目前，一台普通计算机需要 12 年才能破解一个密码哈希。

部分过程是验证数据，检查用户名和密码是否与数据库中存储的内容匹配。

密码哈希是从您的密码创建一个单向哈希的字符串，没有用户应该能够确定哈希的原始内容。

### 注意

密码哈希不应与加密混淆。区别在于，在密码哈希中，您可以将哈希密码解密为其原始状态。

# 在 PHP 中实现验证

在本节中，我们将看到以下结果。

![在 PHP 中实现验证](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/7_03.jpg)

### 注意

本节展示了如何在 PHP 中实现验证，尽管它目前无法正常工作，因为我们尚未创建和提供构成系统知识的数据源。

为了解决这个部分，我们将手动创建一个用户。

按照以下步骤在 PHP 中实现验证：

**创建帮助程序：**

1.  在我们开始构建身份验证之前，我们需要两个新的帮助程序。在`app/Helpers`中创建一个名为`Url.php`的新文件，并输入：

```php
<?php namespace App\Helpers;

class Url
{
    public static function redirect($path = '/')
   {
        header('Location: '.$path);
        exit();
    }
}
```

### 注意

这提供了一个名为 redirect 的单一方法，默认情况下为/，当没有传递参数时。这是重定向到我们应用程序的另一个页面的简单方法。

在将类包含到页面后，使用：`Url::redirect('url/to/redirect/to')`

要重定向到主页，请使用：

`Url::redirect()`

接下来，我们需要一种使用会话的方法。会话是 PHP 跟踪页面数据的一种方式，这非常适合我们的需求，例如能够通过读取会话数据来检测用户是否已登录。

我们可以使用普通的$_SESSION 调用，但由于我们正在使用 OOP，让我们利用它来构建一个会话助手。

1.  在`app/Helpers`中创建一个名为`Session.php`的文件。

1.  首先，设置命名空间和类定义：

### 注意

需要的第一个方法是确定会话是否已启动。如果更新了`sessionStarted`参数，它将将其设置为`false。这`将告诉`init`方法打开会话：

```php
<?php namespace App\Helpers;

class Session
{
    private static $sessionStarted = false;
/**
 * if session has not started, start sessions
 */
public static function init()
{
    if (self::$sessionStarted == false) {
        session_start();
        self::$sessionStarted = true;
    }
}
```

1.  接下来，创建一个名为`set`的方法，接受两个参数`$key`和`$value`。这用于向会话添加一个`$key`并将`$value`设置为`$key`：

```php
public static function set($key, $value = false)
{
    /**
     * Check whether session is set in array or not
     * If array then set all session key-values in foreach loop
     */
    if (is_array($key) && $value === false) {
        foreach ($key as $name => $value) {
            $_SESSION[$name] = $value;
        }
    } else {
        $_SESSION[$key] = $value;
    }
}
```

1.  接下来，创建一个名为`pull`的方法，带有一个参数。这将从会话中提取`key`并在从会话中删除它后返回它，这对于一次性消息非常有用：

```php
public static function pull($key)
{
    $value = $_SESSION[$key];
    unset($_SESSION[$key]);
    return $value;
}
```

1.  接下来，创建一个 get 方法。这将从提供的键返回一个会话：

```php
public static function get($key)
{
    if (isset($_SESSION[$key])) {
        return $_SESSION[$key];
    }

    return false;
}
```

### 注意

有时，您希望查看会话的内容。创建一个名为`display`的方法，返回`$_SESSION`对象：

```php
public static function display()
{
    return $_SESSION;
}
```

1.  最后一个方法用于在提供`$key`时销毁会话密钥，否则将销毁整个会话：

```php
public static function destroy($key = '')
{
    if (self::$sessionStarted == true) {
        if (empty($key)) {
            session_unset();
            session_destroy();
        } else {
            unset($_SESSION[$key]);
        }
    }
}
```

完整的类如下所示：

### 注意

有关完整的代码片段，请参阅代码文件夹中的`Lesson 7.php`文件。

```php
<?php namespace App\Helpers;

class Session
{
    private static $sessionStarted = false;
……..
    }

}
```

1.  现在，我们需要在应用程序运行时自动设置会话。我们通过在`app/Config.php`中添加`Session::init()`来实现这一点：

### 注意

这使用了一个`Use`语句，并包括对`session's` `helper`类的调用。在这个阶段突出显示这些 OOP 特性可能是有益的。

有关完整的代码片段，请参阅代码文件夹中的`Lesson 7.php`文件。

```php
<?php namespace App;

use App\Helpers\Session;

class Config {
…….
        ];
    }
}
```

**构建身份验证：**

我们现在准备开始构建 admin Controller 和 users Model，这将是用户登录的入口点。

1.  在数据库中创建一个名为 users 的新表：

```php
CREATE TABLE `users` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `reset_token` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```

### 注意

ID 是`primary`键，并将设置为自动递增，这意味着每个记录都将有一个唯一的 ID。

`reset`_token 仅在需要重置密码过程时使用。

1.  让我们从 Model 开始。在`app/Models`中创建一个名为`User.php`的文件。

1.  设置命名空间并导入基本 Model 并设置类定义。

### 注意

随着需要，我们将回到这个模型中添加必要的方法。

1.  添加用于插入、更新和删除记录的方法：

### 注意

有关完整的代码片段，请参阅代码文件夹中的`Lesson 7.php`文件。

```php
<?php namespace App\Models;
…….
    {
        $this->db->delete('users', $where);
    }
}
```

**创建 Admin Controller：**

1.  现在，在`app/Controllers`中创建一个名为`Admin.php`的新文件。

这将是登录和退出 admin 仪表板的入口点。

1.  设置命名空间并导入`baseController`和`Session`和`URL` `helpers`以及`User` Model。

1.  设置类定义并创建一个名为`$user`的属性。然后，在`__construct`方法中，通过调用`new User()`来初始化`User` Model。

### 注意

这意味着可以使用`$this->user`来访问 User Model 的任何方法。

下一个方法是`index()`。只要用户已登录，它就会加载仪表板视图。

1.  为了确保用户已登录，会运行一个`if`语句来检查名为`logged_jn`的会话密钥是否存在，该密钥仅在登录后设置。如果用户未登录，则将其重定向到`login`方法：

### 注意

有关完整的代码片段，请参阅代码文件夹中的`Lesson 7.php`文件。

```php
<?php namespace App\Controllers;

use System\BaseController;
……..
        $this->view->render('admin/index', compact('title'));
    }

}
```

1.  如果用户已登录，则将加载`admin/index`视图。创建视图`app/views/admin/index.php`和入口：

```php
<?php
include(APPDIR.'views/layouts/header.php');
include(APPDIR.'views/layouts/nav.php');
include(APPDIR.'views/layouts/errors.php');
?>

<h1>Dashboard</h1>
<p>This is the application dashboard.</p>

<?php include(APPDIR.'views/layouts/footer.php');?>
```

现在，我们需要创建一个`login`视图。在`app/views/admin`中创建一个名为`auth`的文件夹，并创建`login.php`。

1.  首先，包含`header`布局，然后创建一个调用`wrapper`和`well`的`div`。`well`类是一个 Bootstrap 类，它提供了灰色方形样式。`wrapper`类将用于定位`div`。

1.  接下来，包含`errors`布局以捕获任何错误或消息。

1.  现在，我们将创建一个表单，该表单的方法为`post`，以将其内容发布到`ACTION URL`，在本例中为`/admin/login`。

1.  然后，为`username`和`password`创建两个输入。确保密码的输入类型设置为`password`。

### 注意

将输入类型设置为`password`可以阻止密码在屏幕上显示。

当表单提交时，输入的命名属性是 PHP 如何知道数据是什么的。

还需要一个提交按钮来提交表单。一个好的做法是在用户无法记住他们的登录详细信息时提供重置选项。我们将创建一个指向`/admin/reset`的链接。

1.  最后，关闭表单并包含页脚布局：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
<?php include(APPDIR.'views/layouts/header.php');?>

<div class="wrapper well">

    <?php include(APPDIR.'views/layouts/errors.php');?>
…….
.wrapper h1 {
    margin-top: 0px;
    font-size: 25px;
}
```

1.  现在，回到 admin 控制器并创建一个`login`方法：

### 注意

设置一个检查，如果用户已登录，则重定向用户。当他们已经登录时，他们不应该能够看到登录页面。

1.  在`login`方法中，创建一个空的`$errors`数组，并设置页面的`$title`和`load`一个调用`admin/auth/login`的视图，通过使用`compact`函数传递`$title`和`$errors`变量。

### 注意

`compact()`使得可以通过简单输入它们的名称而使用变量，而不需要`$`：

```php
public function login()
{
    if (Session::get('logged_in')) {
        Url::redirect('/admin');
    }

    $errors = [];

    $title = 'Login';

    $this->view->render('admin/auth/login', compact('title', 'errors'));
}
```

这将加载`login`视图，并在按下提交时实际上不会执行任何操作。我们需要检查表单是否已提交，但在这之前，我们需要向`user`模型添加两个方法：

```php
public function get_hash($username)
{
    $data = $this->db->select('password FROM users WHERE username = :username', [':username' => $username]);
   return (isset($data[0]->password) ? $data[0]->password : null);
}
```

`get_hash($username)`将从`users`表中选择`password`，其中`username`与提供的用户名匹配。

设置`username = :username`创建一个占位符。然后，['`:username' => $username`]将使用该占位符，以便知道值将是什么。

然后，检查`$data[0]->password`是否设置并返回它。否则，返回`null`。

1.  对于`get_data()`，做同样的事情，只是这次返回的是一个数据数组，而不是单个列：

```php
public function get_data($username)
{
    $data = $this->db->select('* FROM users WHERE username = :username', [':username' => $username]);
    return (isset($data[0]) ? $data[0] : null);
}
```

1.  现在，在我们的`login`方法中，我们可以通过检查`$_POST`数组是否包含名为`submit`的对象来检查表单是否已提交。

1.  然后，收集表单数据并将其存储在本地变量中。使用`htmlspecialchars()`是一种安全措施，因为它可以阻止脚本标记能够被执行，并将它们呈现为纯文本。

### 注意

接下来，运行一个`if`语句，调用`password_verify()`，这是一个内置函数，返回`true`或`false`。第一个参数是用户提供的`$password`，第二个是通过调用`$this->user->get_hash($username)`从数据库返回的哈希密码。只要`password_verify`等于`false`，登录检查就失败了。

1.  设置一个`$errors`变量来包含一个`errors`消息。接下来，计算`$errors`，如果等于`0`，这意味着没有错误，所以从`$this->user->get_data($username)`获取用户数据。然后，使用会话助手创建一个名为`logged_in`的会话键，其值为`true`，以及另一个以用户 ID 作为其值的会话键。

1.  最后，将用户重定向到 admin `index`页面：

```php
if (isset($_POST['submit'])) {
            $username = htmlspecialchars($_POST['username']);
           $password = htmlspecialchars($_POST['password']);
           if (password_verify($password, $this->user->get_hash($username)) == false) {
                $errors[] = 'Wrong username or password';
            }
            if (count($errors) == 0) {
                //logged in
                $data = $this->user->get_data($username);
                Session::set('logged_in', true);
                Session::set('user_id', $data->id);

                Url::redirect('/admin');
            }
        }
```

完整的方法看起来像这样：

```php
public function login()
{
    if (Session::get('logged_in')) {
        Url::redirect('/admin');
    }
……
    $this->view->render('admin/auth/login', compact('title', 'errors'));
}
```

1.  如果框架尚未运行，请运行框架：

```php
php –S localhost:8000 –t webroot
```

1.  转到`http://localhost:8000/admin/login`。

### 注意

您将看到一个登录页面。按下登录将显示一个错误消息“`用户名或密码错误`”，无论您输入什么，因为目前数据库中没有用户。

1.  让我们创建我们的登录。我们需要一个哈希密码来存储在数据库中。要在`login`方法中创建一个哈希密码，请输入：

```php
echo password_hash('demo', PASSWORD_BCRYPT);
```

第一个参数是您想要的`密码`，在本例中是`demo`。第二个参数是要使用的`PASSWORD`函数的类型。使用默认的`PASSWORD_ BCRYPT`意味着 PHP 将使用可能的最强版本。

1.  当您刷新页面时，您将看到以下类似的哈希：

```php
$2y$10$OAZK6znqAvV2fXS1BbYoVet3pC9dStWVFQGlrgEV4oz2GwJi0nKtC
```

1.  复制这个并将一个新记录插入到数据库客户端中，并将 ID 列留空。它将自动填充。

1.  创建一个`用户名和电子邮件`，并将它们粘贴到`hash. F`中，对于密码，输入一个有效的`datetime`，例如 2017-12-04 23:04:00。

1.  保存记录。现在，您将能够设置登录。

1.  登录后，您将被重定向到`/admin`。

### 注意

记得注释掉或删除`echo password_hash('demo', PASSWORD_BCRYPT),`，否则哈希将始终显示。

1.  趁热打铁，让我们继续添加注销的功能。注销是销毁已登录和`user_id`会话的情况。在`Admin` Controller 中，创建一个名为`logout`的新方法。

1.  在方法内部，销毁会话`object`，然后重定向到`login`页面：

```php
public function logout()
{
    Session::destroy();
    Url::redirect('/admin/login');
}
```

1.  现在，返回应用程序并点击右上角的`logout`。您将被注销并带回`login`页面。

1.  现在，重新登录。如果您点击`Admin`链接，您将被带到默认页面。在这种情况下，最好在加载应用程序时立即加载管理员。我们可以通过将`Admin` Controller 设置为默认`app/Config.php`来实现这一点。

找到以下内容：

```php
'default_controller' => 'Home'
```

用以下内容替换它：

```php
'default_controller' => Admin,
```

1.  现在，如果您点击`Admin`（重新加载页面后），您将看到管理员仪表板。

### 注意

曾经有一段时间，某些密码哈希标准被认为是互联网安全的最高级别。但是，像大多数技术一样，它不可避免地变得可用，这削弱了其前身的有效性。

### 注意

尽一切可能避免以下哈希系统，因为它们不安全：

+   MD5

+   Shar 1

+   Shar 2 56

这些密码哈希函数很弱，计算机现在如此强大，只需几秒钟就能破解它们。

当开发人员在规划新项目时，建议仔细检查代码，以查找诸如使用这些代码的安全漏洞。

在本节中，我们学习了认证过程。我们已经了解了如何进行登录过程。我们已经学习了密码哈希的过程。现在，我们已经有了构建、配置和路由功能到框架的经验。

在下一节中，我们将介绍密码恢复的概念，在其中我们将设置在我们的应用程序中重置密码的功能。

# 密码恢复

本节是关于设置重置密码的能力。密码重置非常重要，因为可能会出现用户忘记密码的情况。我们现在将构建一个类似以下图片的密码恢复过程：

![密码恢复](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/7_04.jpg)

在网上找到的通用密码恢复示例

我们将在 admin Controller 中创建一个名为 reset 的方法。该过程会加载一个视图，用户将在其中输入他们的电子邮件地址以请求一封电子邮件。当这个过程被处理时，它将验证电子邮件地址是否有效，并且实际上存在于系统中。

这将检查电子邮件，确保它的格式正确，并检查提供的电子邮件地址是否存在于名为 users 的数据库表中。

## 介绍第三方依赖 PHP Mailer

![介绍第三方依赖 PHP Mailer](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/7_05.jpg)

PHP Mailer 的图片：https://github.com/PHPMailer

我们将通过包含 PHP Mailer 来添加第三方依赖，用于发送电子邮件。

PHP Mailer 的工作原理如下：

1.  只要验证通过，我们将使用 PHP Mailer 发送带有令牌的电子邮件。令牌稍后将通过电子邮件接收，并作为表单的一部分输入到隐藏字段中，满足验证过程的要求。

### 注意

令牌只是一串随机的字母和数字。其想法是为该用户生成一个唯一的东西，以识别该请求来自他们。

1.  流程的下一部分是向用户发送电子邮件，当用户点击时，创建一个处理该请求的方法。这涉及创建一个接受电子邮件提供的令牌的更改密码方法，然后在其中显示包含表单的视图。

1.  接下来，在视图中，令牌在一个隐藏字段中重新发送。此外，用户可以输入新密码并确认此密码。提交后，控制器将处理数据并验证数据。这涉及确保令牌与用户帐户匹配，并且密码足够长且两个密码匹配。

1.  创建后，当更新投入实践时，用户将能够自动登录到管理系统，而无需重新输入密码。

这样可以节省用户在重置密码后无需登录。从技术上讲，这是用户体验设计的更新，尽管您可以在这里看到 UX 更改不仅仅局限于设计师领域。

### 注意

PHP Mailer 检查格式是否正确。在电子邮件的情况下，这将期望@符号存在。这只是一个验证检查的例子。PHP 内置了方法，以便它可以确定正确的格式是有效的格式。

# 为我们的应用程序构建密码重置机制

要完成认证系统，我们需要能够重置密码，以防忘记密码。以下是这样做的步骤：

1.  在`Admin`控制器中创建一个名为`reset`的新方法。

1.  再次检查用户是否已登录，如果是，则将其重定向回管理界面。

1.  在加载名为`reset:`的视图之前，设置一个`errors`数组并设置页面标题。

```php
public function reset()
{
    if (Session::get('logged_in')) {
        Url::redirect('/admin');
    }

    $errors = [];

    $title = 'Reset Account';

    $this->view->render('admin/auth/reset', compact('title', 'errors'));
}
```

1.  现在，在`app/views/admin/auth`中创建一个名为`reset.php`的视图并输入：

```php
<?php include(APPDIR.'views/layouts/header.php');?>

<div class="wrapper well">

    <?php include(APPDIR.'views/layouts/errors.php');?>

    <h1>Reset Account</h1>

    <form method="post">
…
…
    </div>

<?php include(APPDIR.'views/layouts/footer.php');?>
```

### 注意

表单将发布到相同的`url /admin/reset`。我们收集的唯一数据是电子邮件地址。电子邮件地址将用于在继续之前验证用户是否存在。

1.  现在，返回到`Admin`控制器上的重置方法。

1.  首先，检查表单是否已使用`isset`提交，并传递提交按钮名称：

```php
if (isset($_POST['submit'])) {
```

1.  接下来，确保电子邮件地址已`isset`，否则默认为`null`。检查电子邮件地址是否处于正确的格式中：

```php
$email = (isset($_POST['email']) ? $_POST['email'] : null);

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

    $errors[] = 'Please enter a valid email address';
} else {
    if ($email != $this->user->get_user_email($email)){
        $errors[] = 'Email address not found';
    }
}
```

1.  最后，检查电子邮件地址是否属于现有用户。为此，在用户模型中创建一个名为`get_user_email($email)`的新方法：

### 注意

如果存在，这将返回电子邮件地址，否则将返回`null`。

```php
public function get_user_email($email)
{
    $data = $this->db->select('email from users where email = :email', [':email' => $email]);
    return (isset($data[0]->email) ? $data[0]->email : null);
}
```

在前面的控制器中，我们有：

```php
if ($email != $this->user->get_user_email($email)){
```

### 注意

检查表单中提供的电子邮件地址是否与数据库中的不匹配，如果是，则创建一个新错误。

1.  在验证检查之后，没有错误：

```php
if (count($errors) == 0) {
```

1.  保存文件；到目前为止，该方法看起来像这样：

### 注意

有关完整的代码片段，请参阅代码文件夹中的`Lesson 7.php`文件。

```php
public function reset()
{
…….

    $this->view->render('admin/auth/reset', compact('title', 'errors'));
}
```

此时，除其他事项外，需要发送电子邮件。

### 注意

最佳做法是不使用 PHP 的内置`mail（）`函数，而是使用诸如`phpmailer`（[`github.com/PHPMailer/`](https://github.com/PHPMailer/)）之类的库。

1.  打开`composer.json`和`phpmailer`在要求列表中：

```php
{
    "autoload": {
        "psr-4": {
            "App\\" : "app/",
            "System\\" : "system/"
        }
    },
    "require": {
        "filp/whoops": "².1",
        "phpmailer/phpmailer": "~6.0"
    }
}
```

1.  保存文件并在终端中键入`composer update`。这将拉取`phpmailer`，使其可用于我们的应用程序。

1.  在`Admin`控制器的顶部，导入`phpmailer`：

```php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
```

1.  接下来，转到以下`if`语句内的`reset`方法。这是我们将恢复的地方：

```php
if (count($errors) == 0) {

}
```

1.  现在，我们需要生成一个随机令牌。为此，使用`md5`，`uniqid`和`rand`来生成一个随机令牌。

1.  然后，设置一个`data`和`where`数组。`$data`将指定`reset_token`的值为`$token`，而`$where`将是电子邮件地址。将它们传递给用户模型的`update()`方法以更新用户。

这将在数据库中存储`$token`与用户记录：

```php
$token = md5(uniqid(rand(),true));
$data  = ['reset_token' => $token];
$where = ['email' => $email];
$this->user->update($data, $where);
```

1.  现在，我们通过创建`phpmailer`的新实例来设置要发送的电子邮件，然后设置电子邮件的发送者。根据需要更改这一点。

1.  传递`$email`地址，这将被发送到，并通过将 true 传递给 isHTML()来设置 HTML 模式：

```php
$mail = new PHPMailer(true);
$mail->setFrom('noreply@domain.com');
$mail->addAddress($email);
$mail->isHTML(true);
```

1.  设置主题和电子邮件正文。我们提供两种正文：HTML 和纯文本。纯文本用于用户的电子邮件客户端无法呈现 HTML 的情况。

1.  创建一个指向`admin/change/password_token`的链接，当使用`localhost:`时

### 注意

重要的是要记住`http://localhost:8000`的 URL 只适用于您的计算机。

```php
$mail->Subject = 'Reset you account';
$mail->Body    = "<p>To change your password please click <a 
href='http://localhost:8000/admin/change_password/$token'>this link</a></p>";
$mail->AltBody = "To change your password please go to this address: http://localhost:8000/admin/change_password/$token";
```

1.  现在，一切都设置好了。发送电子邮件：

```php
$mail->send();
```

1.  创建一个会话来通知用户并重定向管理员/重置：

```php
Session::set('success', "Email sent to ".htmlentities($email));
Url::redirect('/admin/reset');
```

完成的方法看起来像这样：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
public function reset()
{
    if (Session::get('logged_in')) {
        Url::redirect('/admin');
    }
…….
    $title = 'Reset Account';

    $this->view->render('admin/auth/reset', compact('title', 'errors'));
}
```

1.  当用户点击电子邮件中的链接时，我们需要处理请求。为此，创建另一个名为`change_password`的方法，接受一个名为`$token`的参数：

### 注意

该方法获取`$token`，将其传递给`users`模型中的一个方法`get_user_reset_token($token)`，并返回用户对象。如果令牌与数据库不匹配，则返回 null。

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
$user = $this->user->get_user_reset_token($token);
if ($user == null) {
       $errors[] = 'user not found.';
}
```

该方法看起来像这样：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
$title = 'Change Password';

    $this->view->render('admin/auth/change_password', compact('title', 'token', 'errors'));
}
```

### 注意

`render`方法将`$title`，`$token`和`$errors`传递给视图。

1.  需要另一个视图。在`app/views/admin/auth`中创建一个名为`change_password.php`的视图：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
<?php include(APPDIR.'views/layouts/header.php');?>

……
    </div>

<?php include(APPDIR.'views/layouts/footer.php');?>
```

### 注意

表单有一个名为`$token`的隐藏输入。它的值是从控制器传递的`$token`，这将用于验证请求。

还有两个输入：`密码`和`确认密码`。这些用于收集所需的密码。

当提交表单并收集表单数据时，再次调用`get_user_reset_token($token)`方法来验证提供的令牌是否有效。

此外，密码必须匹配并且长度必须超过三个字符。

1.  如果没有错误，则通过将数组传递给`$this->user->update`来更新数据库中用户的记录以清除`reset_token`。使用`password_hash()`对密码进行哈希处理，其中 ID 与用户对象匹配，令牌与提供的令牌匹配：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
if (isset($_POST['submit'])) {

    $token = htmlspecialchars($_POST['token']);
……..
    }

}
```

1.  更新后，记录用户并将其重定向到管理员仪表板。

完整的方法看起来像这样：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
public function change_password($token)
{
…….

    $title = 'Change Password';

    $this->view->render('admin/auth/change_password', compact('title', 'token', 'errors'));
}
```

这结束了认证部分。现在我们可以登录、登出，并在忘记密码时重置密码。

我们现在已经到达了本节的结束。在这里，我们学会了如何构建密码重置系统，并进一步学习了使用第三方工具的经验。

在下一节中，我们将看到如何为用户管理添加 CRUD 功能。

# 为用户管理构建 CRUD

## CRUD

`users`部分允许创建和管理应用程序的用户。

我们将创建 CRUD 以启用：

+   创建用户

+   显示现有用户

+   更新现有用户

+   删除不需要的用户

在本节中，我们将创建用户控制器中的不同方法。

我们还将在用户模型中创建更多方法，以便检索所有用户或检索特定用户所需的新查询。

该过程将如下进行：

1.  这个过程的一部分是创建一个`construct`方法，它允许我们保护所有未经授权的用户的方法。这意味着要能够访问部分内的任何方法，您必须首先登录。`index`方法列出所有用户，并提供编辑和删除用户的选项。

1.  在删除时，首先会出现确认。

1.  下一步是创建一个`add`视图。在这个视图中，将有一个表单，供应用程序的用户创建他们的应用程序的新用户记录。在提交表单时，将收集数据并开始验证过程。

1.  这将检查提交的数据是否适合其目的，并且可能是预期的数据。

例如，将检查用户名是否超过三个字符的长度，并且在数据库中不存在。

### 注意

这个过程对于电子邮件也是一样的，在电子邮件的情况下，要确保它是有效的并且不存在。

1.  在验证通过后，用户将被创建，并且成功消息将被记录并显示给用户。应用程序用户然后被重定向到用户视图。

1.  然后我们将创建一个`update`方法和`view`，这与创建用户的方法和视图非常相似。关键区别在于，表单在加载到页面上时会预先填充用户的详细信息，当表单提交时，会更新特定的用户而不是创建新记录。

1.  最后要创建的方法是`delete`方法，它检查用户的 ID 是否为数字，并且不与已登录用户的 ID 相同，以防止他们删除自己。

### 注意

这是开发人员低估用户可能会做的事情。令人惊讶的是，用户可能有意或无意地做的事情，以及如果应用程序不采取措施来防止这种情况，他们可能会删除自己。

在记录被删除后，会创建一个成功消息，并将用户重定向回用户页面。

# 构建用户管理的 CRUD

在这一部分，我们将看到以下输出显示在我们的屏幕上：

![构建用户管理的 CRUD](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/bg-php/img/7_06.jpg)

### 注意

在读取用户时，要知道在这个表中可以控制显示什么。并不是所有关于该用户的信息都需要显示出来。

在这一部分，我们将构建我们的用户部分来`创建`，`读取`，`更新`和`删除`用户。

按照以下步骤构建用户管理的 CRUD：

1.  首先，我们需要更多的查询。打开`app/Models/User.php.`

1.  创建以下方法：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
get_users() – returns all users ordered by username
    $data = $this->db->select('username from users where username = :username', [':username' => $username]);
    return (isset($data[0]->username) ? $data[0]->username : null);
}
```

1.  现在，在`app/Controllers`中创建一个`Users`控制器。创建`Users.php.`

1.  设置命名空间并导入帮助程序和`User`模型：

```php
use System\BaseController;
use App\Helpers\Session;
use App\Helpers\Url;
use App\Models\User;
class Users extends BaseController
{
```

1.  接下来，创建一个名为`$user`的类属性和一个`__construct`方法。然后，检查用户是否已登录，如果没有，将其重定向到登录页面。

1.  创建一个新的用户实例：

```php
$this->user = new User()
```

### 注意

在构造函数中进行这个检查意味着这个类的所有方法都将受到未经授权用户的保护。

```php
protected $user;

public function __construct()
{
    parent::__construct();

    if (! Session::get('logged_in')) {
        Url::redirect('/admin/login');
    }

    $this->user = new User();
}
```

1.  接下来，创建一个`index`方法。这将调用`get_users()`并加载一个视图并传入用户对象：

```php
public function index()
{
    $users = $this->user->get_users();
    $title = 'Users';

    $this->view->render('admin/users/index', compact('users', 'title'));
}
```

1.  为了视图，创建`app/views/admin/users/index.php.`

1.  包括布局文件并创建一个表格来显示用户列表：

```php
foreach($users as $user)
```

1.  循环遍历所有用户记录。作为安全措施，当从数据库中打印数据时，我们将使用`htmlentities()`。这将把所有标签转换为它们的 HTML 对应项，这意味着如果任何代码被注入到数据库中，它将简单地被打印为文本，使其无用。

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
<?php
include(APPDIR.'views/layouts/header.php');
include(APPDIR.'views/layouts/nav.php');
……
    </table>
</div>

<?php include(APPDIR.'views/layouts/footer.php');?>
```

1.  在循环内部，我们有两个用于编辑和删除的操作链接。请注意，用户的 ID 被传递到`href`值的末尾。这是为了将 ID 传递到 URL 中。

1.  此外，我们有一个指向`/users/add`的`添加用户`按钮。让我们创建这个。在你的`Users`控制器中，创建一个名为`add()`的新方法：

```php
public function add()
    {
        $errors = [];

        $title = 'Add User';
        $this->view->render('admin/users/add', compact('errors', 'title'));
    }
```

1.  现在，在`app/views/admin/users`中创建一个名为`add.php`的视图。

1.  包括布局文件并设置页面标题。接下来，创建一个方法设置为`post`的表单。

1.  您需要`username`、`email`、`password`和`confirm password`四个输入。确保每个输入都有一个名称。

### 注意

粘性表单在出现错误时非常有用。

粘性表单是在出现错误时保留其数据的表单。输入仍将显示其中输入的值。

1.  要在用户名和电子邮件上实现粘性表单，使用三元运算符：

```php
(isset($_POST['username']) ? $_POST['username'] : '')
```

这表示如果`$_POST['username']`已设置，则打印它，否则打印空字符串：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
<?php
include(APPDIR.'views/layouts/header.php');
include(APPDIR.'views/layouts/nav.php');
include(APPDIR.'views/layouts/errors.php');
……..
</form>

<?php include(APPDIR.'views/layouts/footer.php');?>
```

1.  提交后，表单数据将被发布到`/users/add`。这需要在`Users`控制器的`add`方法中处理。

1.  检查表单提交：

```php
if (isset($_POST['submit'])) {
```

1.  接下来，收集表单数据：

```php
$username            = (isset($_POST['username']) ? $_POST['username'] : null);
$email                    = (isset($_POST['email']) ? $_POST['email'] : null);
$password            = (isset($_POST['password']) ? $_POST['password'] : null);
$password_confirm    = (isset($_POST['password_confirm']) ? $_POST['password_confirm'] : null);
```

1.  然后，开始验证过程。

1.  检查`username`的长度是否超过 3 个字符：

```php
if (strlen($username) < 3) {
    $errors[] = 'Username is too short';
}
```

1.  接下来，通过将`$username`传递给 Model 上的`get_user_username($username)`方法来检查`$username`是否已经存在于数据库中。如果结果与`$username`相同，则它已经存在，因此创建一个错误：

```php
else {
    if ($username == $this->user->get_user_username($username)){
        $errors[] = 'Username address is already in use';
    }
}
```

1.  对于电子邮件验证，请使用`filter_var`和`FILTER_VALIDATE_EMAIL`检查电子邮件格式是否有效。如果这不返回 true，则创建一个错误。

1.  就像`username`一样，检查`$email`是否已经存在于数据库中：

```php
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'Please enter a valid email address';
} else {
    if ($email == $this->user->get_user_email($email)){
        $errors[] = 'Email address is already in use';
    }
}
```

1.  对于密码，检查`$password`是否与`$password_confirm`匹配或创建错误。否则，检查密码的长度是否超过 3 个字符：

```php
if ($password != $password_confirm) {
    $errors[] = 'Passwords do not match';
} elseif (strlen($password) < 3) {
    $errors[] = 'Password is too short';
}
```

1.  如果没有错误，继续并设置一个包含要插入数据库的数据的`$data`数组。

### 注意

注意使用`password_hash()`函数来存储密码。这是使用 PHP 内置的密码函数，默认情况下将使用`bcrypt`，这是编写时最安全的哈希技术。

1.  通过调用`$this->insert($data)`创建用户并在重定向回/users 之前设置消息：

```php
if (count($errors) == 0) {

    $data = [
        'username' => $username,
        'email' => $email,
        'password' => password_hash($password, PASSWORD_BCRYPT)
    ];

    $this->user->insert($data);

    Session::set('success', 'User created');
    Url::redirect('/users');

}
```

完整的方法如下所示：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
public function add()
    {
        $errors = [];
…….
        $title = 'Add User';
        $this->view->render('admin/users/add', compact('errors', 'title'));
    }
```

1.  要编辑用户，URL 结构是`/users/edit/1`。末尾的数字是用户的 ID。

1.  创建一个名为`edit($id)`的方法，接受一个名为`$id`的参数。

1.  首先，检查`$id`是否为数字，否则重定向回`/users`。

1.  通过调用`$this>user->get_user($id)`获取用户数据，并将 ID 传递给`users`模型方法。这将返回一个用户对象或`null`（如果未找到记录）。

1.  如果`$user`等于`null`，则重定向到`404`页面。否则，设置一个`$errors`数组，`$title`，并加载视图，将用户、错误和标题传递给`compact()`：

```php
public function edit($id)
{
    if (! is_numeric($id)) {
 Url::redirect('/users');
    }
    $user = $this->user->get_user($id);
    if ($user == null) {
        Url::redirect('/404');
    }

    $errors = [];

    $title = 'Edit User';
    $this->view->render('admin/users/edit', compact('user', 'errors', 'title'));
}
```

1.  现在，在`app/views/admin/users`中创建一个名为`edit.php`的视图：

### 注意

这几乎与`add.php`视图相同。主要区别在于用户名和电子邮件输入。它们将使用用户对象进行预填充：

<input class="form-control" id="username" type="text" name="username" value="<?=$user->username;?>" required />

`<?=$user->username;?>`是使用`$user`后的`->`操作的用户对象。您可以指定要从中获取的列。

重要的是不要预先填充密码字段；只有在用户想要更改密码时才应填写。因此，放置一条消息通知用户，只有在他们想要更改现有密码时才应输入密码：

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
<?php
include(APPDIR.'views/layouts/header.php');
include(APPDIR.'views/layouts/nav.php');
include(APPDIR.'views/layouts/errors.php');
……
</form>

<?php include(APPDIR.'views/layouts/footer.php');?>
```

### 注意

提交后，`edit($id)`方法将处理请求。

1.  就像`add()`方法一样，检查表单提交，收集表单数据，并完善表单验证。

1.  这次，我们不会检查用户名或电子邮件是否已经存在于数据库中，只会检查它们是否已提供并且有效：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
if (isset($_POST['submit'])) {
    $username            = (isset($_POST['username']) ? $_POST['username'] : null);
……
            $errors[] = 'Password is too short';
        }
    }
```

1.  接下来，检查是否有错误：

```php
if (count($errors) == 0) {
```

1.  将`$data`数组设置为更新用户记录。这次，只提供了用户名和电子邮件：

```php
$data = [
    'username' => $username,
    'email' => $email
];
```

1.  如果密码已更新，则将密码添加到`$data`数组中：

```php
if ($password != null) {
    $data['password'] = password_hash($password, PASSWORD_BCRYPT);
}
```

1.  `where`语句表示 ID 与`$id`匹配。运行`update()`并设置消息并重定向到用户页面：

```php
$where = ['id' => $id];

$this->user->update($data, $where);

Session::set('success', 'User updated');

Url::redirect('/users');
```

完整的`update`方法如下：

### 注意

有关完整的代码片段，请参考代码文件夹中的`Lesson 7.php`文件。

```php
public function edit($id)
{
    if (! is_numeric($id)) {
……
    }
    $title = 'Edit User';
    $this->view->render('admin/users/edit', compact('user', 'errors', 'title'));
}
```

1.  完成用户控制器的最后一步是添加删除用户的功能。

1.  与编辑一样，URL 结构将在 URL 的格式中传递一个`$id`，如`/users/delete/2`。

1.  创建一个名为`delete($id)`的方法。

1.  检查`$id`是否为数字，并检查`$id`是否与会话`$_SESSION['user_id']`匹配，否则终止页面。您不希望允许用户删除自己的记录。

1.  接下来，通过调用`$this->user->get_user($id)`来获取用户，并检查`$user`对象是否不等于`null`。否则，重定向到`404`页面。

1.  接下来，创建一个`$where`数组，指出`$id`与数据库中的 ID 匹配。请注意，我们不使用`$data`数组。在这种情况下，我们只传递一个`$where`。这是因为您不能选择列，只能选择行，所以`$data`将是无意义的。

1.  最后，设置消息并重定向回`/users`：

```php
public function delete($id)
    {
        if (! is_numeric($id)) {
            Url::redirect('/users');
        }
        if (Session::get('user_id') == $id) {
            die('You cannot delete yourself.');
        }
        $user = $this->user->get_user($id);
        if ($user == null) {
            Url::redirect('/404');
        }
        $where = ['id' => $user->id];
        $this->user->delete($where);
        Session::set('success', 'User deleted');
        Url::redirect('/users');
    }
```

1.  现在运行应用程序：

```php
php –S localhost:8000 –t webroot
```

1.  转到`http://localhost:8000/users`，点击`Add User`，然后填写表单。

1.  首先，如果您尝试在没有任何数据的情况下提交表单，您将看到来自在输入上放置了一个必填属性的 HTML 客户端验证。

1.  尝试填写与您已经创建的用户名相同的用户，您将看到服务器验证规则正在运行。

1.  最后，完整填写表单与新用户详细信息，您将被重定向到`/users`，并看到新用户，以及确认消息。

1.  点击要编辑的用户旁边的`Edit`。然后，您将看到带有用户名和电子邮件填写的编辑表单。点击提交将带您返回到用户页面。

1.  点击`delete`将立即删除用户（如果用户不是您），而无需确认。让我们修复这个问题！

1.  我们的要求规定，当用户按下`delete`时，应显示确认窗口。如果点击确定，将调用删除 URL，如果点击取消，则不会发生任何事情。

1.  打开`app/views/admin/users/index.php`，并在`footer.php`代码块之前放置此 JavaScript：

```php
<script language="JavaScript" type="text/javascript">
function del(id, title) {
    if (confirm("Are you sure you want to delete '" + title + "'?")) {
        window.location.href = '/users/delete/' + id;
    }
}
</script>
```

1.  这定义了一个 JavaScript 函数，它接受一个 ID 和一个`username`。当`confirm()`通过`window.location.href`时，它将运行，将页面重定向到删除 URL，然后将 ID `var`传递到 URL 的末尾。

1.  在您看到删除链接的循环中：

```php
<a href="/users/delete/<?=$row->id;?>" class="btn btn-xs btn-danger">Delete</a>
```

替换为：

```php
<a href="javascript:del('<?=$row->id;?>','<?=$row->username;?>')" class="btn btn-xs btn-danger">Delete</a>
```

这调用`javascript:del()`，触发确认弹出窗口并传递用户的`ID`和`username`。

1.  保存文件并运行页面。当您点击删除时，现在将看到一个确认提示。点击确定将允许删除继续进行，而点击取消将阻止重定向运行。

## 可选活动

1.  添加关于用户的其他字段，也许是他们的地址，年龄，爱好，眼睛颜色，或者你选择的任何内容。

1.  确保这些在`Method`和`Controller`中进行处理，并确保数据库表准备好接受它们。

1.  确保这些包含在视图中。

1.  在`index`视图中，学生可以选择他们选择的信息来帮助在表中识别用户。

# 总结

在本课程中，我们已经完成了对框架的功能进行构建，允许对用户进行管理。我们已经执行了引入 Bootstrap，为我们的应用程序提供了一些基本级别的样式。我们还在应用程序中实现了密码恢复机制。

这完成了联系人应用程序的最基本要求。然而，所有这些都涉及到登录到一个包含应用程序的区域，如果没有正确的用户名和密码凭据，是受限制的。目前，这只是一个空的仪表板页面。一切就绪后，我们现在可以继续构建应用程序来存储用户的联系人。

在下一章中，我们将讨论如何在当前应用程序的基础上构建一个联系人管理系统，其中将包括在联系人应用程序中创建、阅读、更新、删除和使用联系人。
