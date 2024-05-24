# FuelPHP 高效开发学习手册（二）

> 原文：[`zh.annas-archive.org/md5/8172c4d143a13bc077eabf0b73cc7f19`](https://zh.annas-archive.org/md5/8172c4d143a13bc077eabf0b73cc7f19)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：高级主题

在前几章中，我们已经介绍了在 FuelPHP 中创建项目的基础知识。我们已经提到了包可以有多大的用处，但它们不能直接匹配 URL。在本章中，我们将介绍模块，与包不同，模块可以直接从 URL 访问。我们还将介绍与 FuelPHP 相关的一些更高级的主题。

本章涵盖的主题如下：

+   模块-它们是什么以及如何使用它们

+   任务

+   路由

+   单元测试

+   分析

# 模块是什么以及如何使用它们

在上一章中，我们提到了包与 URL 没有直接关联；它们需要应用程序中的控制器和视图来完成这一点。另一方面，模块是一组可以独立于项目应用程序运行的 MVC 元素。它们允许封装和重用代码，因此您可以在项目之间共享模块，而无需编写应用程序代码来充分利用功能。

模块应位于应用程序中的模块文件夹中。如果您希望将它们存储在其他位置，可以在应用程序配置中更改此路径和文件夹。建议在由大量代码组成的较大项目中使用模块，因为它们可以帮助保持代码有序。

模块可以独立使用，它们不需要访问全局应用程序代码。可以创建路由以允许通过 URL 直接访问模块。由于模块可以包含视图和控制器，因此可以将它们视为自己的小型应用程序。

默认情况下，模块应位于应用程序中的模块文件夹中；例如，`[rootOfProject]/fuel/app/modules`。这可以在应用程序的`config.php`文件中更改-它出现在名为`module_paths`的部分中。如果需要更改模块的路径，您需要确保路径的末尾包含 DS 全局变量。例如：

```php
'module_paths' => array(
    APPPATH.'journal_modules'.DS, // path to application modules
    APPPATH.'..'.DS.'globalmods'.DS, // path to our global modules
),
```

## 命名空间

从历史上看，命名类和函数是一项困难的工作。我们通常希望类名具有意义并指示类的功能；这可能会导致我们的代码与我们在项目上可能还在使用的第三方代码之间发生冲突。在 PHP 版本 5.3 中，我们已经能够（可选地）使用命名空间来避免这些冲突，在 FuelPHP 中，所有模块都需要有自己的命名空间来避免这种冲突。命名空间必须与模块的文件夹名称相同。例如，`Examplemodule`文件夹中的模块将具有以下控制器：

```php
<?php
/**
 * Module controller in the Examplemodule module
 */
 namespace Examplemodule;

 class Controller_Example
 {
     // Add your code here
 }   
```

除了命名空间和控制器名称之外，模块文件夹名称也会影响 URL 中的名称，如果要路由到模块中的控制器。因此，选择正确的名称很重要；但即使没有完美的名称，我们仍然可以从主应用程序中更改 URL 路由。

## 模块文件夹结构

谈到模块的文件夹名称，我们应该将模块视为一个独立的应用程序，具有预期的文件夹结构。以下是任何模块的预期文件夹结构：

```php
**/classes**
 **/controller**
 **/model**
 **/view**
**/config**
**/lang**
**/tasks**
**/views** 

```

如您所见，文件夹结构类似于完整应用程序文件夹结构。

## 使用主应用程序中的模块

有时，我们可能希望从主应用程序中使用模块中的一些函数。在这些情况下，我们需要在代码中引用模块之前自动加载类。可以通过以下两种方式完成：

+   首先是在应用程序的`config.php`文件中自动加载模块，就像我们在示例包中所做的那样

在`config.php`文件中的`'always_load'`数组中，您会注意到有一个模块部分：

```php
'always_load' => array(
      'modules' => array('examplemodule'), 
```

+   加载模块的另一种方法是仅在需要时自动加载它，在需要模块功能的类中。

可以使用以下代码来完成：

```php
Module::load('examplemodule');
```

加载模块后，可以按以下方式调用模块中的函数：

```php
\Examplemodule\Exampleclass::examplemethod( 'params' );
```

由于模块往往是自包含的应用程序，每个模块都有特定的用途，它们不像包那样广泛开源。

# 任务

有时，我们会希望发生后台进程、周期性任务或维护任务。这就是 FuelPHP 任务派上用场的地方。它们可以通过命令行工具运行，或者在 Windows 上设置为周期性任务，或者在 Mac OSX 和*nix 上设置为**cron**作业。它们可以调用模块和其他类，就像控制器一样。

任务应放置在`fuel/app/tasks`文件夹中，默认情况下，类中只需要定义一个`run()`方法。如果需要其他方法，可以像 PHP 类一样添加。

使用 Oil `refine`命令调用任务。FuelPHP 附带一个名为`robots`的示例任务，并将包含在`fuel/app/tasks`文件夹中。

要调用机器人任务的主要方法，可以运行以下命令：

```php
**$ php oil refine robot**

```

`robot`任务中的`run()`方法有一个定义的变量，允许您通过`oil refine`命令传递一个字符串。输入以下命令行将更改任务中的消息：

```php
**$ php oil refine robots "Kill all mice"**

```

如果查看`robots.php`文件，您会注意到一个名为`protect()`的第二个方法，可以使用以下代码调用它：

```php
**$ php oil r robots:protect**

```

FuelPHP 中的任务对于周期性操作非常有用，并且与控制器非常相似，因此编写起来很简单。它们还具有与核心 FuelPHP 功能相同的访问权限的优势。

# 路由

与其他框架一样，FuelPHP 具有相当广泛的路由功能。在本节中，我们将介绍基础知识。

首先，有一些保留路由；它们是：`_root_`和`_404_`。当没有指定 URL 时，`_root_`键用于例如主页或根页面。第二个(`_404_`)是当无法找到请求的内容控制器或视图时使用的。

路由存在于应用程序的`config`文件夹中，文件名为`routes.php`。让我们从以下路径加载`routes.php`文件，其中包含以下代码：

`[rootOfProject]/fuel/app/config/routes.php`

```php
<?php
return array(
    '_root_'  => 'welcome/index',  // The default route
    '_404_'   => 'welcome/404',    // The main 404 route
);
```

从`routes`配置文件中可以看出，路由被存储为数组。左侧的键与 URL 匹配，然后右侧的项目由 FuelPHP 执行。这相当简单，但可以用于复杂的 URL 和关键字匹配。

最简单的路由是直接将 URL 字符串与控制器和操作匹配。它们可以如下所示：

```php
return array(
    'about'  => 'welcome/about',  // The action method in the welcome controller
    'contact'   => 'about/contact',    // The contact method in the about controller
);
```

我们的应用程序往往具有相当动态的特性，因此在应用程序中指定所有可能的路由将是一项繁琐的工作。这就是更高级的路由派上用场的地方。为此，我们可以使用关键字和基本正则表达式来匹配 URL 中的字符串，并将它们转换为控制器方法。这些表达式使用冒号前面的关键字，如下所示：

+   `:any`：此关键字匹配从该点开始的任何内容。

+   `:segment`：此关键字匹配 URL 中的单个段。段可以是任何内容。这对 URL 中的语言字符串很有用。

+   `:num`：此关键字匹配 URL 中的数字值。

+   `:alpha`：此关键字匹配任何字母字符。

+   `:alnum`：此关键字匹配任何字母数字字符。

使用以下代码，路由器将匹配*任何*日志条目，然后将条目名称发送到`journal`控制器中的`entry`方法：

```php
'journal/(:any)' => 'journal/entry/$1',
```

以下示例中的代码将允许任何前面的段用于像`/en/contact`这样的 URL，并将语言标志作为变量发送到站点控制器中的`contact`方法。最终的 URL 将类似于`/site/contact/en`：

```php
'(:segment)/contact' => 'site/contact/$1',
```

作为开发人员，我们经常尝试通过选择清晰和描述性的变量名使我们的代码更易读。在 FuelPHP 中，更高级的路由也可以做到这一点，因为它允许您在路由中使用命名参数。然后可以从您的方法或操作中访问这些命名段。例如：

```php
return array(
    'journal/:year/:month/:day/:id' => 'journal/entry', 
);
```

在这个路由中，`/journal/2013/11/5/name`将路由到日志控制器中的 entry 方法。在 entry 方法中，我们可以以以下方式获取命名段：

```php
$this->param('year');
$this->param('month');
$this->param('day');
$this->param('id');
```

FuelPHP 使用正则表达式来使命名段在路由中工作。每个段都算作一个反向引用，例如，`$1`和`$2`正则表达式占位符——我们在 PHP 中经常使用这些当使用正则表达式时。反向引用是一个正则表达式术语，更多信息可以在以下网站找到：

[`www.regular-expressions.info/brackets.html#usebackrefinregex`](http://www.regular-expressions.info/brackets.html#usebackrefinregex)

在`:name/(\d{2}`的路由中，数字（`d{2}`）将使用变量`$2`找到，变量`$1`将返回`:name`段的值。

我们在前几章中提到了 RESTful 控制器模板。这些可以与基于动词的路由一起使用，将请求定向到 RESTful 控制器中的正确方法。这允许将某个 URL 的路由通过不同的方法和控制器以适应功能。

例如：

+   对`/journal`的`POST`请求可以路由到日志控制器中的`create`方法。

+   对`/journal`的`GET`请求可以路由到日志控制器中的`index`方法

这些请求都遵循 HTTP 动词的推荐用法，以执行应用程序中的操作，`routes.php`文件中的路由看起来会像以下内容：

```php
return array(
    'journal' => array( 
        array('GET', new Route('journal/index')),
        array('POST', new Route('journal/create')),
    )
);
```

我们可以对`PUT`和`DELETE`动词做类似的事情，并使用正则表达式和命名参数使得从 URL 中获取相关信息更容易。

如果您正在处理用户配置文件信息和数据，我们将寻求使用 HTTPS 或安全连接；同样，FuelPHP 中的路由支持这一点。以下示例只会在通过 HTTPS 发送请求时加载路由，而不仅仅是 HTTP：

```php
return array(
    'user/(:any)' => array( 
            array( 'GET', new Route( 'user/view/$1' ), true ) 
        ),
); 
```

第三个参数确保命名路由仅在使用 HTTPS 时使用。

在开发过程中，我们经常重新排列应用程序的结构以反映不断变化的功能。FuelPHP 中使路由更容易的一个特性是命名路由和反向路由。有了这个特性，我们可以简单地在主`routes.php`文件中更改命名路由，而不是编辑所有的视图。为了使其工作，我们需要在视图中使用路由的名称。在以下示例中，我们将`'admin/app/dashboard'`更改为`'admin/dashboard'`：

```php
return array(
    'admin/app/dashboard' => array('admin/dashboard', 'name' => 'admin_dashboard'),
);
```

在需要链接到仪表板的视图中，我们将使用以下`anchor`代码：

```php
echo Html::anchor(Router::get('admin_dashboard'), 'Dashboard');
```

### 注意

这仅适用于应用程序代码，不适用于模块路由。

# 单元测试

没有现代框架会完整而没有测试应用程序代码和功能的能力。FuelPHP 已经考虑到了这一点，因此包括基于 PHPUnit 测试框架的测试和测试用例。

## 那么什么是单元测试？

单元测试是自动化测试，用于检查功能单元（方法和函数）是否按预期工作。这些测试通常测试给定输入时输出是否正确，将函数视为黑盒以确保内部逻辑工作。

由于单元测试是自动化的，很容易确保最近的代码更改不会破坏其他功能。它还允许使用持续集成服务器，如 Jenkins（[`jenkins-ci.org`](http://jenkins-ci.org)）。持续集成服务器将在代码通过单元测试后自动部署您的代码，让您可以专注于实际的代码。

## PHPUnit

PHP 中有几种单元测试工具，但事实上的标准是 Sebastian Bergmann 的 PHPUnit。这是 FuelPHP 支持的测试框架，并且可以使用 Oil 命令行工具运行。但在使用之前，您需要确保已安装 PHPUnit。有关最新的安装说明，我建议浏览以下链接提供的官方文档：

[`www.phpunit.de/manual/current/en/installation.html`](http://www.phpunit.de/manual/current/en/installation.html)

## 运行单元测试

使用 FuelPHP Oil 命令行工具运行单元测试，可以使用`php oil test`：

```php
**$ php oil test**
**$ Tests Running...This may take a few moments.**
**$ PHPUnit 3.7.21 by Sebastian Bergmann.**
**$** 
**$ Configuration read from /home/user/sites/journal/fuel/core/phpunit.xml**

**$ ..................................................  63 / 251 ( 25%)**
**$ .................................................. 126 / 251 ( 50%)**
**$ .................................................. 189 / 251 ( 75%)**
**$ ..................................................** 
**$ Time: 6 seconds, Memory: 22.25Mb**
**$** 
**$ OK (251 tests, 206 assertions)**

```

## 创建单元测试

测试位于应用程序的`fuel/app/tests`文件夹中，并将读取其子文件夹中的任何测试。测试文件应该遵循与它们正在测试的类相似的结构。因此，如果您要测试类别模型(`/fuel/app/classes/model/category.php`)，它将在`fuel/app/tests/model/category.php`中找到一个测试文件。测试用例应该扩展`TestCase`类，这是`PHPUnit_Framework_TestCase`类的扩展。这意味着您将能够在测试中使用通常的 PHPUnit 断言和方法。

类的名称应该以`Test_`为前缀。同样，类别测试应该被命名为`Test_Model_Category`。类应该看起来像下面这样：

```php
<?php
class Test_Model_Category extends TestCase
{
    public function test_category()
    {
       // Add your code here
    }
}
```

官方文档列出了许多断言和编写单元测试的推荐方法。文档可以在以下链接找到：

[`www.phpunit.de/manual/current/en/writing-tests-for-phpunit.html`](http://www.phpunit.de/manual/current/en/writing-tests-for-phpunit.html)

## 分组单元测试

随着应用程序的增长，有时运行所有单元测试可能会耗费时间；因此，我们可以将测试分组在一起，然后只测试某些组。这是通过在通常的`test`命令的末尾使用`--group=`命令来完成的。因此，可以使用以下代码运行`User`组的测试：

```php
**$ php oil test --group=User**

```

分组是在每个测试类的`docbloc`注释中完成的，每个测试用例可以分配给多个组。以下代码片段将类别模型`Test`分配给`Blog`和`App`组：

```php
<?php
/**
 * @group Blog
 * @group App
 */
 class Test_Model_Category extends TestCase
{
    public function test_category()
    {
       // Add your code here
    }
}
```

## 配置和模块测试

FuelPHP 使用`phpunit.xml`文件中的配置，该文件包含在`fuel/core/`文件夹中。要自定义配置，我们需要将此文件复制到我们的应用程序，然后在那里进行更改。FuelPHP 将加载应用程序`phpunit.xml`以取代核心版本。

如前所述，模块是自己的应用程序，就像单元测试一样。单元测试应该包含在每个模块顶层的`test`文件夹中。为了使 FuelPHP 运行模块中的测试，它需要知道它们的存在。这是通过在`phpunit.xml`文件中包含模块文件夹来完成的。一旦您复制了核心 FuelPHP`phpunit.xml`文件，就可以添加以下代码片段：

```php
<testsuite name="modules">
    <directory suffix=".php">../app/modules/*/tests</directory>
</testsuite>
```

现在您对 FuelPHP 中的单元测试有了一点了解，让我们来介绍开发的另一个方面——对应用程序进行分析的能力。

# 分析

FuelPHP 包括一个基于**PHP Quick Profiler**的**profiler**。这允许您对代码进行分析和调试，而无需在应用程序中编写额外的函数。通过应用程序的`config.php`文件可以打开和关闭 profiler。要启用 profiler，只需将`'profiling'`变量更改为`true`，并将其设置为`false`以禁用 profiler。

profiler 还包括一个数据库分析工具，但由于所需的资源，它默认情况下是禁用的。数据库分析器将需要根据使用的环境进行启用，以便开发环境可以在不影响其他环境的情况下启用它。它可以在环境的`db.php`文件中使用`true`值进行启用，如下面的代码所示：

```php
'profiling' => true,
```

![Profiling](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-fuelphp-eff-php-dev/img/0366_06_01.jpg)

分析器具有选项卡界面，包括以下选项卡：

+   控制台：这是默认选项卡，提供有关错误、日志条目和内存使用情况以及执行时间的信息

+   加载时间：此选项卡显示请求加载时间

+   数据库：此选项卡显示执行时间和执行的数据库查询数量

+   内存使用：这是页面加载时使用的峰值内存

+   包括：此选项卡显示加载的文件列表及其文件名和大小

+   加载的项目：此选项卡显示页面加载结束时的最终配置变量

+   加载的变量：此选项卡显示页面加载结束时会话的内容

+   GET：此选项卡显示`$_GET`数组的内容

+   POST：此选项卡显示`$_POST`数组的内容

分析器提供了许多信息，可以帮助您优化应用程序。

# 摘要

在本章中，我们介绍了模块以及如何使用它们快速构建我们的应用程序。我们已经涉及单元测试以及如何启用分析器来优化我们的代码。

我们已经配置了一些基本路由，并详细说明了需要放置任何更改的位置。命名路由是一个非常强大的工具，可以用来应对项目和客户需求的变化。它们使我们能够减少需要进行的更改数量。

任务是在我们的应用程序中构建后台或周期功能的一种很好的方式，并且使用 FuelPHP Oil 命令行实用程序非常容易运行。

在下一章中，我们将介绍一些在 FuelPHP 社区内宣传我们的应用程序、包或模块的方法。


# 第七章：欢迎来到社区

正如您从前面的章节中所看到的，FuelPHP 提供了许多功能，并且不断以新功能和工作方式进行演进。它处理耗时的任务，使我们能够集中精力在编码的更有趣的方面。由于有大量的开发人员社区，我们有大量的软件包和模块可供选择，为我们的项目奠定基础并开发出优秀的应用程序和项目。

# FuelPHP 和 GitHub

主要网站是[`fuelphp.com`](http://fuelphp.com)，这是主要文档的存放地。由于该框架是开源的，真正的活动中心是 GitHub 页面，可以在[`github.com/fuel/`](https://github.com/fuel/)找到。

# 获取帮助和支持

有时，我们需要一些在文档中并不总是涵盖的额外帮助。为此，有主要的 FuelPHP 论坛[`fuelphp.com/forums/`](http://fuelphp.com/forums/)。当您需要一些额外的帮助时，这通常是一个很好的起点。论坛分为几个组，如一般、软件包和开发。这是宣传您的新软件包或简单分享您所创建的东西的好地方。

除了论坛，您还会发现一个活跃的**Internet Relay Chat** (**IRC**)频道，`#fuelphp`。

# FuelPHP 在社交媒体上

社交媒体使得向社区传播信息更加迅速，FuelPHP 同时使用 Twitter 和 Facebook 来实现这一目的。

## Twitter

核心 FuelPHP 团队在 Twitter 上非常活跃，可以在[`twitter.com/FuelPHP`](https://twitter.com/FuelPHP)找到。这是宣传您构建的应用程序的好方法，因为他们经常会转发给他们的关注者。

## Facebook

尽管不如 FuelPHP 论坛或 Twitter 活跃，但 FuelPHP 的 Facebook 页面[`www.facebook.com/pages/FuelPHP/120778634657454`](https://www.facebook.com/pages/FuelPHP/120778634657454)是受监控的，所有问题都会得到回答。

# 告别的话

希望您发现这本入门书对进入 FuelPHP 世界有所帮助。我始终相信学习一门新语言或框架的最佳方法是将其用于项目或想法。

FuelPHP Oil 工具是快速原型设计想法进行测试或演示的好方法。考虑可以构建的最小可行产品来测试这个想法。这将给您动力来开始。

如果您想了解更多信息或在本书中遇到任何问题，请不要忘记与我们联系。
