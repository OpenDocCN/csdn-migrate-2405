# 精通 Laravel（一）

> 原文：[`zh.annas-archive.org/md5/d10bf45da1cebf8f2b06a9600172079d`](https://zh.annas-archive.org/md5/d10bf45da1cebf8f2b06a9600172079d)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

PHP 是一种免费开源的编程语言，正在持续复兴，而 Laravel 处于前沿。Laravel 5 被证明是最适合新手和专家程序员的可用框架。遵循现代 PHP 的面向对象最佳实践，可以减少上市时间，并构建强大的 Web 和 API 驱动的移动应用程序，可以自动测试和部署。

您将学习如何使用 Laravel 5 PHP 框架快速开发软件应用程序。

# 这本书涵盖了什么

第一章，*使用 phpspec 进行正确设计*，讲述了如何配置 Laravel 5 以使用 phpspec 进行现代单元测试，如何使用 phpspec 设计类，以及执行单元和功能测试。

第二章，*自动化测试-迁移和填充数据库*，涵盖了数据库迁移，其背后的机制以及如何为测试创建种子。

第三章，*构建服务、命令和事件*，讨论了 Model-View-Controller 以及它如何演变为服务、命令和事件，以解耦代码并实践关注点分离。

第四章，*创建 RESTful API*，带您了解如何创建 RESTful API：基本的 CRUD 操作（创建、读取、更新和删除），以及讨论一些最佳实践和超媒体控制（HATEOAS）。

第五章，*使用表单生成器*，带您进入 Web 界面的一面，展示如何利用 Laravel 5 的一些最新功能来创建 Web 表单。这里还将讨论反向路由。

第六章，*使用注解驯服复杂性*，专注于注解。当应用程序变得复杂时，`routes.php`文件很容易变得混乱。在控制器内部使用注解，可以大大提高代码的可读性；然而，除了优点之外，还存在一些缺点。

第七章，*使用中间件过滤请求*，向您展示如何创建可在控制器之前或之后调用的可重用过滤器。

第八章，*使用 Eloquent ORM 查询数据库*，帮助您学习如何以一种方式使用 ORM 来减少编码错误的概率，增加安全性并减少 SQL 注入的可能性，以及学习如何处理 Eloquent ORM 的限制。

第九章，*扩展 Laravel*，讲述了如何将应用程序扩展到基于云的架构。讨论了读写主/从配置，并引导读者进行配置。

第十章，*使用 Elixir 构建、编译和测试*，介绍了 Elixir。Elixir 基于 gulp，是一个任务运行器，是一系列构建脚本，可以自动化 Laravel 软件开发工作流程中的常见任务。

# 这本书需要什么

我们需要以下软件：

+   Apache/Nginx

+   PHP 5.4 或更高版本

+   MySQL 或类似软件

+   Composer

+   phpspec

+   Node.js

+   npm

# 这本书适合谁

如果您是一位经验丰富的新手或者是一位有能力的 PHP 程序员，对现代 PHP（至少版本 5.4）的概念有基本的了解，那么这本书非常适合您。

需要基本的面向对象编程和数据库知识。您应该已经熟悉 Laravel，或者至少已经尝试过这个框架。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些示例以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“新的`artisan`命令如下运行”

代码块设置如下：

```php
protected function schedule(Schedule $schedule)
    {
        $schedule->command('inspire')
             ->hourly();
        $schedule->command('manage:waitinglist')
            ->everyFiveMinutes();

    }
```

任何命令行输入或输出都是这样写的：

```php
**$ php artisan schedule:run**

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“如下截图所示，**迁移**表现在这里。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会出现在这样。


# 第一章：使用 phpspec 正确设计

自 2011 年 Laravel 谦虚的开始以来，发生了许多事情。Taylor Otwell，一名.NET 程序员，寻求使用 PHP 来进行一项副业项目，因为他被告知托管 PHP 便宜且无处不在。最初作为 CodeIgniter 的扩展开始，最终成为自己的代码。将代码库从 CodeIgniter 的 PHP 5.2 的限制中释放出来，可以使用 PHP 5.3 提供的所有新功能，如命名空间和闭包。版本 1 和 3 之间的时间跨度仅为一年。版本 3 后，事情发生得非常迅速。在其爆炸式的流行之后，即版本 4 发布时，它迅速开始从其他流行框架（如 CodeIgniter、Zend、Symfony、Yii 和 CakePHP）那里夺取市场份额，最终占据了领先地位。除了其表达性语法、出色的文档和充满激情的创始人外，还有大型社区的主要支柱 IRC 和 Slack 聊天室、Laravel 播客和 Laracasts 教学视频网站。此外，新创建的商业支持，如提供*100%正常运行时间*的 Envoyer，也意味着 Laravel 也受到了企业的欢迎。随着 Laravel 4.2 的发布，最低要求的 PHP 版本提高到了 5.4，以利用现代 PHP 特性，如*traits*。

使用 Laravel 的特性以及新的语法，比如[]数组快捷方式，使编码变得轻松。Laravel 的表达性语法，再加上这些现代 PHP 特性，使它成为任何希望构建强大应用的开发者的绝佳选择。

![使用 phpspec 正确设计](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_01_01.jpg)

Laravel 在 Google 趋势报告中的成功崛起

# 一个新时代

2014 年底，Laravel 历史上第二个最重要的时刻发生了。原定的 4.3 版本改变了许多 Laravel 的核心原则，社区决定将其成为 5.0 版本。

Laravel 5 的到来带来了许多在构建软件时使用它的方式的变化。从诸如 CodeIgniter 等框架继承的内置 MVC 架构已被放弃，以更具动态性、模块化甚至大胆的框架不可知性为代价。许多组件已尽可能解耦。Laravel 历史上最重要的部分将是 Laravel 5.1 版本的到来，它将有**长期支持**（**LTS**）。因此，Laravel 在企业中的地位将更加稳固。此外，最低的 PHP 要求将更改为 5.5 版本。因此，对于任何新项目，建议使用 PHP 5.5，甚至 PHP 5.6，因为升级到 PHP 7 版本将更加容易。

## 一个更精简的应用程序

`/app`目录变得更加精简，只留下了应用程序中最基本的部分。诸如`config`、`database`、`storage`和`tests`等目录已经从`app`目录中移出，因为它们是辅助应用程序本身的。最重要的是，测试工具的集成已经大大成熟。

## PSR

由于**框架互操作性组**（**PHP-FIG**）的努力，**PHP 标准推荐**（**PSR**）的开发者，框架代码的阅读、编写和格式化变得更加容易。它甚至允许开发者更容易地在多个框架中工作。Laravel 是 FIG 的一部分，并继续将其建议纳入框架中。例如，Laravel 5.1 将采用 PSR-2 标准。有关 PHP FIG 和 PSR 的更多信息，请访问 PHP-FIG 网站[`www.php-fig.org`](http://www.php-fig.org)。

# 安装和配置 Laravel

安装 Laravel 的最新更新说明始终可以在 Laravel 网站[`laravel.com`](http://laravel.com)找到。要在开发环境中开始使用 Laravel，当前的最佳实践建议使用以下方法：

+   Vagrant：这提供了一种方便的方式来管理虚拟机，如 Virtualbox。

+   PuPHPet：这是一个可以用来创建各种类型虚拟机的优秀工具。有关 PuPHPet 的更多信息，请访问[`puphpet.com`](https://puphpet.com)。

+   Phansible：这是 PuPHPet 的另一种选择。有关 Phansible 的信息，请访问[`phansible.com`](http://phansible.com)。

+   Homestead：这是由 Laravel 社区维护的，是专门为 Laravel 创建的虚拟机，使用的是 NGINX 而不是 Apache。有关 Homestead 的更多信息，请访问[`github.com/laravel/homestead`](https://github.com/laravel/homestead)。

## 安装

基本过程涉及下载和安装 Composer，然后将 Laravel 添加为依赖项。一个重要的细节是，存储目录，它位于`/app`目录的平行位置，需要以可写的方式设置，以便允许 Laravel 5 执行诸如写日志文件之类的操作。还很重要的是确保使用`$ php artisan key:generate`生成一个用于哈希的 32 字符密钥，因为自 PHP 5.6 发布以来，Mcrypt 对其要求更为严格。对于 Laravel 5.1，OpenSSL 将取代 Mcrypt。

## 配置

在 Laravel 4 中，环境是以服务器或开发机器的主机名配置的，这相当牵强。相反，Laravel 5 使用一个`.env`文件来设置各种环境。该文件包含在`.gitignore`中。因此，每台机器都应该从源代码控制之外的源接收其配置。

因此，例如，可以使用以下代码来设置本地开发：

```php
APP_ENV=local
APP_DEBUG=true
APP_KEY=SomeRandomString
DB_HOST=localhost
DB_DATABASE=example
DB_USERNAME=DBUser
DB_PASSWORD=DBPass
CACHE_DRIVER=file
SESSION_DRIVER=file
```

## 命名空间

Laravel 的一个很好的新功能是，它允许您将最高级别的命名空间设置为诸如`MyCompany`之类的内容，通过`app:name`命令。这个命令实际上会将`/app`目录中所有相关文件的命名空间从 App 更改为`MyCompany`，例如。然后，这个命名空间存在于`/app`目录中。这将命名空间化到几乎每个文件中，而在之前的 4.x 版本中，这是可选的。

# 正确的 TDD

测试驱动开发的文化并不新鲜。相反，甚至在肯特·贝克（Kent Beck）在 1990 年代编写 SUnit 之前就已经存在。源自 SUnit 的 xUNIT 系列单元测试框架已经发展成为为 PHP 提供测试解决方案。

## PHPUnit

PHP 端口的 PHP 测试软件名为 PHPUnit。然而，在 PHP 语言中进行测试驱动开发是一个相当新的概念。例如，在他的书《*The Grumpy Programmer's Guide To Building Testable PHP Applications*》中，*Chris Hartjes*在 2012 年底出版，写道“我开始研究围绕 CodeIgniter 的测试文化。它比新生儿还弱。”

自 Laravel 3 版本以来，测试一直是 Laravel 框架的一部分，使用 PHPUnit 单元测试工具，因此 Laravel 包含`phpunit.xml`文件是在努力鼓励开发人员接受测试驱动开发的努力中迈出的重要一步。

# phpspec

另一个测试工具 RSpec 在 2007 年出现在 Ruby 社区，并对测试驱动开发进行了改进。它具有**行为驱动开发**（**BDD**）。phpspec 工具将 RSpec 的 BDD 移植到 PHP 中，正在迅速增长。它的共同创始人 Marcello Duarte 多次表示“BDD 是正确的 TDD”。因此，BDD 只是对 TDD 的*改进*或演变。Laravel 5 现在巧妙地将 phpspec 包含为一种突出*按规范设计*行为驱动开发范式的方式。

由于在构建 Laravel 5 应用程序的基本步骤是指定要创建的实体，因此在安装和配置 Laravel 5 后，开发人员可以立即通过运行 phpspec 作为设计工具开始设计。

# 实体创建

让我们创建一个示例 Web 应用程序。如果客户要求我们为旅游结构构建预订系统，那么系统可能包含诸如住宿（例如酒店和早餐客栈）、房间、价格和预订等实体。

简化的数据库架构如下所示：

![实体创建](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_01_02.jpg)

# MyCompany 数据库架构

数据库架构有以下假设：

+   一个住宿有很多房间

+   预订仅适用于单个用户

+   预订可能包括多个房间

+   预订有一个开始日期和一个结束日期

+   价格从开始日期到结束日期对一个房间有效

+   一个房间有很多设施

+   预订的开始日期必须在结束日期之前

+   预订不能超过十五天

+   预订不能包括超过四个房间

# 使用 phpspec 进行设计

现在，让我们开始使用 phpspec 作为设计工具来构建我们的实体。

如果顶级命名空间是`MyCompany`，那么使用 phpspec，只需输入以下命令：

```php
**# phpspec describe MyCompany/AccommodationRepository**

```

在输入上述命令后，将创建`spec/AccommodationSpecRepository.php`：

```php
<?php

namespace spec\MyCompany;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class AccommodationRepositorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('MyCompany\AccommodationRepository');
    }
<?php

namespace MyCompany;

class AccommodationRepository
{
}
```

### 提示

应将 phpspec 的路径添加到`.bashrc`或`.bash_profile`文件中，以便可以直接运行 phpspec。

然后，输入以下命令：

```php
**# phpspec run**

```

在输入上述命令后，开发人员将显示如下：

```php
**class MyCompany\AcccommodationRepository does not exist.**
**Do you want me to create 'MyCompany\AccommodationRepository' for you? [Y/n]**

```

输入*Y*后，将创建`AccommodationRepository.php`类，如下所示：

```php
<?php

namespace MyCompany;

class AccommodationRepository
{}
```

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载示例代码文件，用于您购买的所有 Packt Publishing 图书。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

phpspec 的美妙之处在于其简单性和加速类的创建，这些类与规范一起。

![使用 phpspec 进行设计](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_01_03.jpg)

使用 phpspec 描述和创建类的基本步骤

# 使用 phpspec 进行规范说明

phpspec 的核心在于允许我们指定实体的行为并同时对其进行测试。通过简单地指定客户给出的业务规则，我们可以轻松为每个业务规则创建测试。然而，phpspec 的真正力量在于它如何使用表达自然语言的语法。让我们来看看之前给我们关于预订的业务规则：

+   预订的开始日期必顶在结束日期之前

+   预订不能超过十五天

+   预订不能包括超过四个房间

运行以下命令：

```php
**# phpspec describe**
 **MyCompany/Accommodation/ReservationValidator**

```

phpspec 将为上述命令产生以下输出：

```php
<?php

namespace spec\MyCompany\Accommodation;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ReservationSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('MyCompany\Accommodation\Reservation');
    }
}
```

然后，使用以下命令运行 phpspec：

```php
**# phpspec run**

```

phpspec 将像往常一样以以下输出做出响应：

```php
**Do you want me to create** 
 **'MyCompany\Accommodation\ReservationValidator' for you?**

```

然后，phpspec 将创建`ReservationValidator`类，如下所示：

```php
<?php namespace MyCompany\Accommodation;

 class ReservationValidator {
 }
```

让我们创建一个`validate()`函数，它将采用以下参数： 

+   确定预订开始的开始日期字符串

+   确定预订结束的结束日期字符串

+   要添加到预订的`room`对象数组

以下是创建`validate()`函数的代码片段：

```php
<?php
namespace MyCompany\Accommodation;

use Carbon\Carbon;

class ReservationValidator
{

    public function validate($start_date, $end_date, $rooms)
    {
    }
}
```

我们将包括`Carbon`类，这将帮助我们处理日期。对于第一个业务规则，即预订的开始日期必须在结束日期之前，我们现在可以在`ReservationValidatorSpec`类中创建我们的第一个规范方法，如下所示：

```php
function its_start_date_must_come_before_the_end_date ($start_date,$end_date,$room)
{
    $rooms = [$room];
    $start_date = '2015-06-03';
    $end_date = '2015-06-03';
    $this->shouldThrow('\InvalidArgumentException')->duringValidate( $start_date, $end_date, $rooms);
}
```

在前面的函数中，phpspec 以`it`或`its`开始规范。phpspec 使用蛇形命名法以提高可读性，而`start_date_must_be_less_than_the_end_date`则是规范的精确副本。这不是很棒吗？

当传入`$start_date`，`$end_date`和`room`时，它们会自动被模拟。不需要其他任何东西。我们将创建一个有效的`$rooms`数组。然而，我们将设置`$start_date`和`$end_date`，使它们具有相同的值，以导致测试失败。表达式语法如前面的代码所示。`shouldThrow`出现在`during`之前，然后采用方法名`Validate`。

我们已经给了 phpspec 自动为我们创建`validate()`方法所需的东西。我们将指定`$this`，即`ReservationValidator`类，将抛出`InvalidArgumentException`。运行以下命令：

```php
**# phpspec run**

```

再次，phpspec 问我们以下问题：

```php
 **Do you want me to create 'MyCompany\Accommodation\Reservation::validate()'** 
 **for you?**

```

只需在提示处简单地输入*Y*，方法就会在`ReservationValidator`类中创建。就是这么简单。当再次运行 phpspec 时，它会因为方法尚未抛出异常而失败。所以现在需要编写代码。在函数内部，我们将从格式为"2015-06-02"的字符串创建两个`Carbon`对象，以便能够利用 Carbon 强大的日期比较功能。在这种情况下，我们将使用`$date1->diffInDays($date2);`方法来测试`$end`和`$start`之间的差异是否小于一。如果是这样，我们将抛出`InvalidArgumentException`并显示用户友好的消息。现在，当我们重新运行 phpspec 时，测试将通过：

```php
$end = Carbon::createFromFormat('Y-m-d', $end_date);
$start = Carbon::createFromFormat('Y-m-d', $start_date);

        if ($end->diffInDays($start)<1) {
            throw new \InvalidArgumentException('Requires end date to be greater than start date.');
        }
```

## 红，绿，重构

测试驱动开发的规则要求*红*，*绿*，*重构*，这意味着一旦测试通过（绿色），我们应该尝试重构或简化方法内的代码，而不改变功能。

看一下`if`测试：

```php
if ( $end->diffInDays($start) < 1 ) {
```

前面的代码不太可读。我们可以以以下方式重构它：

```php
if (!$end->diffInDays($start)>0)
```

然而，即使前面的代码也不太易读，我们还在代码中直接使用整数。

将`0`移入一个常量中。为了提高可读性，我们将其更改为预订所需的最少天数，如下所示：

```php
 const MINIMUM_STAY_LENGTH = 1;
```

让我们将比较提取到一个方法中，如下所示：

```php
    /**
     * @param $end
     * @param $start
     * @return bool
     */
    private function endDateIsGreaterThanStartDate($end, $start)
    {
        return $end->diffInDays($start) >= MINIMUM_STAY_LENGTH;
    }
```

我们现在可以这样写`if`语句：

```php
if (!$this->endDateIsGreaterThanStartDate($end, $start))
```

前面的陈述更加表达和可读。

现在，对于下一个规则，即预订不能超过十五天，我们需要以以下方式创建方法：

```php
function it_cannot_be_made_for_more_than_fifteen_days(User $user, $start_date, $end_date, Room $room)
{
        $start_date = '2015-06-01';
        $end_date = '2015-07-30';
        $rooms = [$room];
        $this->shouldThrow('\InvalidArgumentException')
        ->duringCreateNew( $user,$start_date,$end_date,$rooms);
}
```

在这里，我们设置`$end_date`，使其被分配一个比`$start_date`晚一个月以上的日期，以导致方法抛出`InvalidArgumentException`。再次执行`phpspec`命令后，测试将失败。让我们修改现有方法来检查日期范围。我们将向方法添加以下代码：

```php
  if ($end->diffInDays($start)>15) {
       throw new \InvalidArgumentException('Cannot reserve a room
       for more than fifteen (15) days.');
  }
```

再次，phpspec 愉快地成功运行所有测试。重构后，我们将再次提取`if`条件并创建常量，如下所示：

```php
   const MAXIMUM_STAY_LENGTH = 15;
   /**
     * @param $end
     * @param $start
     * @return bool
     */
    private function daysAreGreaterThanMaximumAllowed($end, $start)
    {
        return $end->diffInDays($start) > self::MAXIMUM_STAY_LENGTH;
    }

   if ($this->daysAreGreaterThanMaximumAllowed($end, $start)) {
            throw new \InvalidArgumentException ('Cannot reserve a room for more than fifteen (15) days.');
   }
```

## 整理一下

我们可以把事情留在这里，但是让我们清理一下，因为我们有测试。由于`endDateIsGreaterThanStartDate($end, $start)`和`daysAreGreaterThanMaximumAllowed($end, $start)`函数分别检查最小和最大允许的停留时间，我们可以从另一个方法中调用它们。

我们将`endDateIsGreaterThanStartDate()`重构为`daysAreLessThanMinimumAllowed($end, $start)`，然后创建另一个方法来检查最小和最大停留长度，如下所示：

```php
private function daysAreWithinAcceptableRange($end, $start)
    {
        if ($this->daysAreLessThanMinimumAllowed($end, $start)
            || $this->daysAreGreaterThanMaximumAllowed($end, $start)) {
           return false;
        } else {
           return true;
        }
    }
```

这样我们只剩下一个函数，而不是两个，在`createNew`函数中，如下所示：

```php
if (!$this->daysAreWithinAcceptableRange($end, $start)) {
            throw new \InvalidArgumentException('Requires a stay length from '
                . self::MINIMUM_STAY_LENGTH . ' to '. self::MAXIMUM_STAY_LENGTH . ' days.');
        }
```

对于第三条规则，即预订不能包含超过四个房间，流程是一样的。创建规范，如下：

```php
it_cannot_contain_than_four_rooms
```

这里的改变将在参数中。这次，我们将模拟五个房间，以便测试失败，如下所示：

```php
function it_cannot_contain_than_four_rooms(User $user, $start_date, $end_date, Room $room1, Room $room2, Room $room3, Room $room4, Room $room5)
```

五个房间对象将被加载到`$rooms`数组中，测试将会失败，如下所示：

```php
$rooms = [$room1, $room2, $room3, $room4, $room5];
    $this->shouldThrow('\InvalidArgumentException')->duringCreateNew($user,$start_date,$end_date,$rooms);
    }
```

在添加代码以检查数组大小后，最终类将如下所示：

```php
<?php

namespace MyCompany\Accommodation;

use Carbon\Carbon;
class ReservationValidator
{

    const MINIMUM_STAY_LENGTH = 1;
    const MAXIMUM_STAY_LENGTH = 15;
    const MAXIMUM_ROOMS = 4;

    /**
     * @param $start_date
     * @param $end_date
     * @param $rooms
     * @return $this
     */
    public function validate($start_date, $end_date, $rooms)
    {
        $end = Carbon::createFromFormat('Y-m-d', $end_date);
        $start = Carbon::createFromFormat('Y-m-d', $start_date);

        if (!$this->daysAreWithinAcceptableRange($end, $start)) {
            throw new \InvalidArgumentException('Requires a stay length from '
                . self::MINIMUM_STAY_LENGTH . ' to '. self::MAXIMUM_STAY_LENGTH . ' days.');
        }
        if (!is_array($rooms)) {
            throw new \InvalidArgumentException('Requires last parameter rooms to be an array.');
        }
        if ($this->tooManyRooms($rooms)) {
            throw new \InvalidArgumentException('Cannot reserve more than '. self::MAXIMUM_ROOMS .' rooms.');
        }

        return $this;

    }

    /**
     * @param $end
     * @param $start
     * @return bool
     */
    private function daysAreLessThanMinimumAllowed($end, $start)
    {
        return $end->diffInDays($start) < self::MINIMUM_STAY_LENGTH;
    }

    /**
     * @param $end
     * @param $start
     * @return bool
     */
    private function daysAreGreaterThanMaximumAllowed($end, $start)
    {
        return $end->diffInDays($start) > self::MAXIMUM_STAY_LENGTH;
    }

    /**
     * @param $end
     * @param $start
     * @return bool
     */
    private function daysAreWithinAcceptableRange($end, $start)
    {
        if ($this->daysAreLessThanMinimumAllowed($end, $start)
            || $this->daysAreGreaterThanMaximumAllowed($end, $start)) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * @param $rooms
     * @return bool
     */
    private function tooManyRooms($rooms)
    {
        return count($rooms) > self::MAXIMUM_ROOMS;
    }

    public function rooms(){
        return $this->belongsToMany('MyCompany\Accommodation\Room')->withTimestamps();
    }

}
```

这种方法非常干净。只有两个`if`语句——第一个用于验证日期范围是否有效，另一个用于验证房间数量是否在有效范围内。常量很容易访问，并且可以根据业务需求进行更改。显然，将 phpspec 添加到开发工作流程中，将之前需要两个步骤——使用 PHPUnit 编写断言，然后编写代码——合并在一起。现在，我们将离开 phpspec，转而使用 Artisan，开发人员对此很熟悉，因为它是 Laravel 先前版本的一个特性。

# 控制器

接下来，我们将创建一些示例控制器。在撰写本书时，我们需要同时使用 Artisan 和 phpspec。让我们为`room`实体创建一个控制器，如下所示：

```php
$ php artisan make:controller RoomController

<?php namespace MyCompany\Http\Controllers;

use MyCompany\Http\Requests;
use MyCompany\Http\Controllers\Controller;

use Illuminate\Http\Request;
class RoomController extends Controller {

        /**
        * Display a listing of the resource.
        *
        * @return Response
        */
        public function index()
        {}

        /**
        * Show the form for creating a new resource.
        *
        * @return Response
        */
        public function create()
        {}

        /**
        * Store a newly created resource in storage.
        *
        * @return Response
        */
        public function store()
        {}
….

}
```

### 注意

请注意，这将在`app/Http/Controllers`目录中创建，这是 Laravel 5 的新位置。新的 HTTP 目录包含控制器、中间件和请求目录，将与 HTTP 请求或实际请求相关的文件分组在一起。此外，此目录配置是可选的，路由可以调用任何自动加载的位置，通常通过命名空间 PSR-4 结构。

## 命令总线

Laravel 5 采用了命令总线模式，创建的命令存储在`app/Commands`目录中。而在 Laravel 4 中，命令被认为是命令行工具，而在 Laravel 5 中，命令被认为是一个类，其方法可以在应用程序内部使用，从而实现代码的优秀重用。这里的命令概念是需要完成的任务，或者在我们的例子中，是为用户预订的房间。总线的范式然后使用新的`DispatchesCommands`特性传输命令，该特性用于基本控制器类中。Artisan 创建的每个控制器都扩展了这个类到一个处理程序方法，实际工作在其中执行。

为了使用 Laravel 的命令总线设计模式，我们现在将使用 Artisan 创建一些命令。我们将在未来的章节中详细介绍命令，但首先，我们将输入以下命令：

```php
**$ php artisan make:commandReserveRoomCommand --handler**

```

输入此命令将创建一个用于预订房间的命令，可以从代码的任何位置调用，将业务逻辑与控制器和模型隔离，并允许以异步模式执行命令。

```php
<?php namespace MyCompany\Commands;

use MyCompany\Commands\Command;

class ReserveRoomCommand extends Command {

    /**
    * Create a new command instance.
    *
    * @return void
    */
    public function __construct()
    {
        //
    }

}
```

填写完命令的细节后，该类现在看起来是这样的：

```php
<?php namespace MyCompany\Commands;

use MyCompany\Commands\Command;
use MyCompany\User;

class ReserveRoomCommand extends Command {

    public $user;
    public $rooms;
    public $start_date;
    public $end_date;

    /**
    * Create a new command instance.
    *
    * @return void
    */
    public function __construct(User $user, $start_date, $end_date, $rooms)
    {
        $this->rooms = $rooms;
        $this->user = $user;
        $this->start_date = $start_date;
        $this->end_date = $end_date;
    }

}
```

`--handler`参数创建了一个额外的类`ReserveRoomCommandHandler`，其中包含一个构造函数和一个 handle 方法，该方法注入了`ReserveRoomCommand`。此文件将存在于`app/Handlers/Commands`目录中。如果未使用`--handler`标志，则`ReserveRoomCommand`类将包含自己的`handler`方法，并且不会创建单独的处理程序类：

```php
<?php namespace MyCompany\Handlers\Commands;

use MyCompany\Commands\ReserveRoomCommand;

use Illuminate\Queue\InteractsWithQueue;

class ReserveRoomCommandHandler {

    /**
    * Create the command handler.
    *
    * @return void
    */
    public function __construct()
    {
        //
    }

    /**
    * Handle the command.
    *
    * @paramReserveRoomCommand  $command
    * @return void
    */
    public function handle(ReserveRoomCommand $command)
    {
        //
    }

}
```

我们将填写处理预订验证的 handle 方法，如下所示：

```php
public function handle(ReserveRoomCommand $command)
    {
        $reservation = new \MyCompany\Accommodation\ReservationValidator();
        $reservation->validate(
        $command->start_date, $command->end_date, $command->rooms);
    } 
```

# 总结

phpspec 为软件的业务逻辑方面添加了成熟、健壮、测试驱动和示例驱动的规范方法。再加上模型、控制器、命令、事件和事件处理程序的轻松创建，使得 Laravel 成为 PHP 框架竞争中的佼佼者。此外，它还采用了许多行业最佳程序员使用的最佳实践。

在本章中，我们学习了如何使用 phpspec 轻松地从命令行设计类及其相应的测试。这种工作流程，加上 Artisan，使得设置 Laravel 5 应用程序的基本结构变得非常容易。

在下一章中，我们将介绍数据库迁移、其背后的机制以及创建用于测试的种子的方法。


# 第二章：自动化测试-迁移和种子数据库

到目前为止，我们已经创建了一些基本模型和数据库的概要。现在，我们需要创建数据库迁移和种子。传统上，数据库“dump”文件被用作传递表结构和数据的方式，包括初始或预定义记录，如默认值；不变的列表，如城市或国家；以及用户，如“admin”。这些包含 SQL 的转储文件可以提交到源代码控制。这并不总是维护数据库完整性的最佳方式；因为每当开发人员添加记录或修改数据库时，团队中的所有开发人员都需要手动添加或删除数据、表、行、列或索引，或者删除并重新创建数据库。迁移允许数据库以代码形式存在，实际上驻留在 Laravel 项目内，并在源代码控制中进行版本控制。

迁移是从命令行运行的，也可以自动化，以在需要时自动创建数据库（如果不存在），或删除并重新创建表并填充表（如果已存在）。迁移在 Laravel 中已经存在一段时间，因此它们在 Laravel 5 中的存在并不令人惊讶。

# 使用 Laravel 的迁移功能

第一步是运行`artisan`命令：

```php
**$ php artisan migrate:install**

```

这将创建一个名为`migration`的表，其中包含两列：`migration`是 MySQL 中的 varchar 255，`batch`是整数。这个表将被 Laravel 用来跟踪已运行的迁移。换句话说，它维护了所有已执行操作的历史记录。以下是主要操作的列表：

+   `install`：如前所述，此操作安装

+   `refresh`：此操作重置并重新运行所有迁移

+   `reset`：此操作回滚所有迁移

+   `rollback`：此操作是一种“撤消”类型，只是回滚上一个操作

+   `status`：此操作生成迁移的类似表格的输出，并指出它们是否已运行

## 迁移示例

Laravel 5 在`/database/migrations`目录中包含两个迁移。

第一个迁移创建了`users`表。

第二个创建`password_resets`表，正如你可能已经猜到的，用于恢复丢失的密码。除非指定，迁移操作的是在`/config/database.php`配置文件中配置的数据库：

```php
<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateUsersTable extends Migration {

  /**
   * Run the migrations.
   *
   * @return void
   */
  public function up()
  {
    Schema::create('users', function(Blueprint $table)
    {
      $table->smallIncrements('id')->unsigned();
      $table->string('name');
      $table->string('email')->unique();
      $table->string('password', 60);
      $table->rememberToken();
      $table->timestamps();
      $table->softDeletes();
    });
  }

  /**
   * Reverse the migrations.
   *
   * @return void
   */
  public function down()
  {
    Schema::drop('users');
  }

}
```

迁移扩展了`Migration`类并使用`Blueprint`类。

有两种方法：`up`和`down`，分别在使用`migrate`命令和`rollback`命令时使用。`Schema::create()`方法以表名作为第一个参数调用，并以函数回调作为第二个参数，接受`Blueprint`对象的实例作为参数。

## 创建表

`$table`对象有一些方法，执行任务，如创建索引，设置自增字段，指定应创建的字段类型，并将字段名称作为参数传递。

第一个命令用于创建自增字段`id`，这将是表的主键。然后，创建字符串字段，如`name`、`email`和`password`。请注意，`unique`方法链接到`email`字段的`create`语句，说明`email`字段将用作登录名/用户 ID，这是大多数现代 Web 应用程序的常见做法。`rememberToken`用于允许用户在每个会话中保持身份验证。此令牌在每次登录和注销时重置，保护用户免受潜在的恶意劫持尝试。

## Laravel 迁移魔法

Laravel 迁移还能够创建时间戳字段，用于自动存储每个模型的创建和更新信息。

## $table->timestamps();

以下代码告诉迁移自动在表中创建两列，即 `created_at` 和 `updated_at`，这是 Laravel 的 Eloquent **对象关系映射** (**ORM**) 自动使用的，以便应用程序知道对象何时创建和何时更新：

`$table->timestamps()`

在下面的示例中，字段更新如下：

```php
/*
*   created_at is set with timestamps
*/
$user = new User();
$user->email = "johndoe@acmewidgets.com";
$user->name = "John Doe";
$user->save(); // created_at is set with timestamps

/*
*   updated_at is set with timestamps
*/
$user = User::find(1); //where 1 is the $id
$user->email = "johndoe@acmeenterprise.com";
$user->save(); //updated_at is updated
```

另一个很棒的 Laravel 功能是软删除字段。这提供了一种**回收站**，允许数据在以后可选地恢复。

这个功能简单地向表中添加了另一列，以允许软删除数据。要添加到迁移中的代码如下所示：

```php
$table->softDeletes();
```

这在 `数据库, deleted_at,` 中添加了一列，它的值可以是 `null`，也可以是一个时间戳，表示记录被删除的时间。这在您的数据库应用程序中构建了一个回收站功能。

运行以下命令：

```php
**$ php artisan migrate**

```

迁移已启动并创建了表。现在出现了**迁移**表，如下截图所示：

![$table->timestamps();](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_02_01.jpg)

`users` 表的结构如下截图所示：

![$table->timestamps();](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_02_02.jpg)

要回滚迁移，请运行以下命令：

```php
**$ php artisan migrate:rollback**

```

`rollback` 命令使用迁移表来确定要回滚的操作。在这种情况下，运行后的 `migrations` 表现在是空的。

# 从模式到迁移

在开发过程中经常发生的一种情况是创建了一个模式，然后我们需要从该模式创建一个迁移。在撰写本文时，Laravel 核心中没有官方工具可以做到这一点，但有几个可用的包。

其中一个这样的包是 `migrations-generator` 包。

首先，在 `composer.json` 文件的 `require-dev` 部分中添加以下行，以在 `composer.json` 文件中要求 `migrations-generator` 依赖项：

```php
"require-dev": {
    "phpunit/phpunit": "~4.0",
    "phpspec/phpspec": "~2.1",
    "xethron/migrations-generator": "dev-feature/laravel-five-stable",
    "way/generators": "dev-feature/laravel-five-stable"
  },
```

还需要在根级别的 `composer.json` 文件中添加以下文本：

```php
"repositories": [
  {
    "type": "git",
    "url": "git@github.com:jamisonvalenta/Laravel-4-Generators.git"
  }],
```

## Composer 的 require-dev 命令

`require-dev` 命令与 `require` 相反，是 composer 的一种机制，允许只在开发阶段需要的某些包。大多数测试工具和迁移工具只会在本地开发机器、QA 机器和/或持续集成环境中使用，而不会在生产环境中使用。这种机制可以使您的生产安装不受不必要的包的影响。

## Laravel 的提供者数组

Laravel 的 `providers` 数组在 `config/app.php` 文件中列出了 Laravel 随时可用的提供者。

我们将添加 `way generator` 和 `Xethron migration` 服务提供者：

```php
'providers' => [

        /*
         * Laravel Framework Service Providers...
         */
          Illuminate\Foundation\Providers\ArtisanServiceProvider::class,
          Illuminate\Auth\AuthServiceProvider::class,
          Illuminate\Broadcasting\BroadcastServiceProvider::class,
        ...
    'Way\Generators\GeneratorsServiceProvider',
    'Xethron\MigrationsGenerator\MigrationsGeneratorServiceProvider'
]
```

## composer update 命令

`composer update` 命令是一种简单而强大的方式，确保一切都在适当的位置，并且没有错误。运行此命令后，我们现在准备运行迁移。

## 生成迁移

只需输入以下命令：

```php
**$ php artisan**

```

`artisan` 命令将显示所有可能的命令列表。`migrate:generate` 命令应该包含在有效命令列表中。如果此命令不在列表中，则说明某些配置不正确。

确认 `migrate:generate` 命令存在于列表中后，只需运行以下命令：

```php
**$ php artisan migrate:generate**

```

这将启动该过程。

在这个例子中，我们使用了 MySQL 数据库。在提示时输入 `Y`，进程将开始，输出应该显示为数据库中的每个表创建了一个迁移文件。

这是您的命令提示符在最后应该显示的样子：

```php
**Using connection: mysql**

**Generating migrations for: accommodations, amenities, amenity_room, cities, countries, currencies, locations, rates, reservation_room, reservations, rooms, states, users**
**Do you want to log these migrations in the migrations table? [Y/n] Y**
**Migration table created successfully.**
**Next Batch Number is: 1\. We recommend using Batch Number 0 so that it becomes the "first" migration [Default: 0]** 
**Setting up Tables and Index Migrations**
**Created: /var/www/laravel.example/database/migrations/2015_02_07_170311_create_accommodations_table.php**
**Created: /var/www/laravel.example/database/migrations/2015_02_07_170311_create_amenities_table.php**
**Created: /var/www/laravel.example/database/migrations/2015_02_07_170311_create_amenity_room_table.php**
**Created: /var/www/laravel.example/database/migrations/2015_02_07_170311_create_cities_table.php**
**Created: /var/www/laravel.example/database/migrations/2015_02_07_170311_create_countries_table.php**
**Created: /var/www/laravel.example/database/migrations/2015_02_07_170311_create_currencies_table.php**
**Created: /var/www/laravel.example/database/migrations/2015_02_07_170311_create_locations_table.php**
**Created: /var/www/laravel.example/database/migrations/2015_02_07_170311_create_rates_table.php**
**Created: /var/www/laravel.example/database/migrations/2015_02_07_170311_create_reservation_room_table.php**
**Created: /var/www/laravel.example/database/migrations/2015_02_07_170311_create_reservations_table.php**
**Created: /var/www/laravel.example/database/migrations/2015_02_07_170311_create_rooms_table.php**
**Created: /var/www/laravel.example/database/migrations/2015_02_07_170311_create_states_table.php**
**Created: /var/www/laravel.example/database/migrations/2015_02_07_170311_create_users_table.php**

**Finished!**

```

# 迁移解剖

考虑迁移文件中的一行的示例；我们可以看到表对象在一系列方法中使用。迁移文件的以下行设置了位置优雅属性中的状态属性在`locations`表中：

```php
$table->smallInteger('state_id')->unsigned()->index('state_id');
```

## 列出表

通常需要创建或导入通常保持不变的有限项目列表，例如城市、州、国家和类似项目。让我们称这些列表表或查找表。在这些表中，ID 通常应为正数。这些列表可能会增长，但通常不会删除或更新任何数据。`smallInteger`类型用于保持表的小型，并且表示属于有限列表的值，这些值不会自然增长。下一个方法`unsigned`表示限制将为 65535。这个值应该足以表示大多数州、省或类似类型的地理区域，酒店可能位于其中。链中的最后一个方法向数据库列添加索引。这在这样的列表表中是必不可少的，这些列表表用于`select`语句或`read`语句中。`Read`语句将在第九章*扩展 Laravel*中讨论。使用 unsigned 很重要，因为它将正限制加倍，否则将是 32767。使用索引，我们可以加快查找时间并访问表中数据的缓存版本。

## 软删除和时间戳属性

关于列表表的`softDeletes`和`timestamps`，这取决于。如果表不是很大，跟踪更新、插入或删除不会太有害；但是，如果列表包含国家，其中更改不经常发生且非常小，最好省略`softDeletes`和`timestamps`。因此，整个表可能适合内存，并且速度非常快。要省略时间戳，需要添加以下代码行：

```php
public $timestamps = false;
```

# 创建种子

要创建我们的数据库 seeder，我们将修改扩展`Seeder`的`DatabaseSeeder`类。文件的名称是`database/seeds/DatabaseSeeder.php`。文件的内容将如下所示：

```php
<?php

use Illuminate\Database\Seeder;
use Illuminate\Database\Eloquent\Model;

class DatabaseSeeder extends Seeder {

    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        Model::unguard();

        //create a user
        $user = new \MyCompany\User();
        $user->id=1;
        $user->email = "testing@tester.com";
        $user->password = Hash::make('p@ssw0rd');
        $user->save();

        //create a country
        $country = new \MyCompany\Accommodation\Location\State;
        $country->name = "United States";
        $country->id = 236;
        $country->save();

        //create a state
        $state = new \MyCompany\Accommodation\Location\State;
        $state->name = "Pennsylvania";
        $state->id = 1;
        $state->save();

        //create a city
        $city = new \MyCompany\Accommodation\Location\City;
        $city->name = "Pittsburgh";
        $city->save();

        //create a location
        $location = new \MyCompany\Accommodation\Location;
        $location->city_id = $city->id;
        $location->state_id = $state->id;
        $location->country_id = 236;
        $location->latitude = 40.44;
        $location->longitude = 80;
        $location->code = '15212';
        $location->address_1 = "100 Main Street";
        $location->save();

        //create a new accommodation
        $accommodation = new \MyCompany\Accommodation;
        $accommodation->name = "Royal Plaza Hotel";
        $accommodation->location_id = $location;
        $accommodation->description = "A modern, 4-star hotel";
        $accommodation->save();

        //create a room
        $room1 = new \MyCompany\Accommodation\Room;
        $room1->room_number= 'A01';
        $room1->accommodation_id = $accommodation->id;
        $room1->save();

        //create another room
        $room2 = new \MyCompany\Accommodation\Room;
        $room2->room_number= 'A02';
        $room2->accommodation_id = $accommodation->id;
        $room2->save();

        //create the room array
        $rooms = [$room1,$room2];

    }

}
```

seeder 文件设置了可能的最基本的场景。对于初始测试，我们不需要将每个国家、州、城市和可能的位置都添加到数据库中；我们只需要添加必要的信息来创建各种场景。例如，要创建一个新的预订；我们将创建每个用户、国家、州、城市、位置和住宿模型的实例，然后创建两个房间，这些房间将添加到房间数组中。

让我们为预订创建一个实现非常简单的存储库接口的存储库：

```php
<?php

namespace MyCompany\Accommodation;

interface RepositoryInterface {
    public function create($attributes);
}
```

现在让我们创建`ReservationRepository`，它实现`RepositoryInterface`：

```php
<?php

namespace MyCompany\Accommodation;

class ReservationRepository implements RepositoryInterface {
    private $reservation;

    function __construct($reservation)
    {
        $this->reservation = $reservation;
    }

    public function create($attributes)
    {
        $this->reservation->create($attributes);
        return $this->reservation;
    }
}
```

现在，我们将创建所需的方法来创建预订，并填充`reservation_room`的中间表：

```php
public function create($attributes)
{

    $modelAttributes= array_except($attributes, ['rooms']);

    $reservation = $this->reservationModel->create($modelAttributes);
    if (isset($attributes['rooms']) ) {
        $reservation->rooms()->sync($attributes['rooms']);
    }
    return $reservation;
}
```

### 提示

`array_except()` Laravel 助手用于返回`attributes`数组，除了`$rooms`数组之外，该数组将用于`sync()`函数。

在这里，我们将模型的每个属性设置为方法中设置的属性。我们需要添加将建立预订和房间之间多对多关系的方法：

```php
public function rooms(){
    return $this->belongsToMany('MyCompany\Accommodation\Room')->withTimestamps();
}
```

在这种情况下，我们需要向关系添加`withTimestamps()`，以便时间戳将被更新，指示关系何时保存在`reservation_room`中。

# 使用 PHPUnit 进行数据库测试

PHPUnit 与 Laravel 5 集成良好，就像与 Laravel 4 一样，因此设置测试环境相当容易。测试的一个好方法是使用 SQLite 数据库，并将其设置为驻留在内存中，但是您需要修改`config/database.php`文件，如下所示：

```php
    'default' => 'sqlite',
       'connections' => array(
        'sqlite' => array(
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ),
    ),
```

然后，我们需要修改`phpunit.xml`文件以设置`DB_DRIVER`环境变量：

```php
<php>
        <env name="APP_ENV" value="testing"/>
        <env name="CACHE_DRIVER" value="array"/>
        <env name="SESSION_DRIVER" value="array"/>
        <env name="DB_DRIVER" value="sqlite"/>
</php>
```

然后，我们需要修改`config/database.php`文件中的以下行：

```php
'default' => 'mysql',
```

我们修改前面的行以匹配以下行：

```php
'default' => env('DB_DRIVER', 'mysql'),
```

现在，我们将设置 PHPUnit 在内存中的`sqlite`数据库上运行我们的迁移。

在`tests`目录中，有两个类：一个`TestCase`类，继承了`LaravelTestCase`类，和一个`ExampleTest`类，继承了`TestCase`类。

我们需要向`TestCase`添加两个方法来执行迁移，运行 seeder，然后将数据库恢复到其原始状态：

```php
<?php

class TestCase extends Illuminate\Foundation\Testing\TestCase {

    public function setUp()
    {
        parent::setUp();
        Artisan::call('migrate');
        Artisan::call('db:seed');
    }

    /**
    * Creates the application.
    *
    * @return \Illuminate\Foundation\Application
    */
    public function createApplication()
    {
        $app = require __DIR__.'/../bootstrap/app.php';
        $app->make('Illuminate\Contracts\Console\Kernel')->bootstrap();
        return $app;
    }

    public function tearDown()
    {
        Artisan::call('migrate:rollback');
    }
}
```

现在，我们将创建一个 PHPUnit 测试来验证数据是否正确保存在数据库中。我们需要将`tests/ExampleTest.php`修改为以下代码：

```php
<?php

class ExampleTest extends TestCase {

    /**
    * A basic functional test example.
    *
    * @return void
    */

public function testReserveRoomExample()
    {

        $reservationRepository = new \MyCompany\Accommodation\ReservationRepository(
            new \MyCompany\Accommodation\Reservation());
        $reservationValidator = new \MyCompany\Accommodation\ReservationValidator();
        $start_date = '2015-10-01';
        $end_date = '2015-10-10';
        $rooms = \MyCompany\Accommodation\Room::take(2)->lists('id')->toArray();
        if ($reservationValidator->validate($start_date,$end_date,$rooms)) {
            $reservation = $reservationRepository->create(['date_start'=>$start_date,'date_end'=>$end_date,'rooms'=>$rooms,'reservation_number'=>'0001']);
        }

        $this->assertInstanceOf('\MyCompany\Accommodation\Reservation',$reservation);
        $this->assertEquals('2015-10-01',$reservation->date_start);
        $this->assertEquals(2,count($reservation->rooms));
}
```

## 运行 PHPUnit

要启动 PHPUnit，只需输入以下命令：

```php
**$ phpunit**

```

测试将会运行。由于`Reservation`类的`create`方法返回一个预订，我们可以使用 PHPUnit 的`assertInstanceOf`方法来确定数据库中是否创建了预订。我们可以添加任何其他断言来确保保存的值正是我们想要的。例如，我们可以断言开始日期等于`'2015-10-01'`，`room`数组的大小等于`two`。与`testBasicExample()`方法一起，我们可以确保对`"/"`的`GET`请求返回`200`。PHPUnit 的结果将如下所示：

运行 PHPUnit

请注意，有两个点表示测试。**OK**表示没有失败，我们再次被告知有两个测试和四个断言；一个是在示例中的断言，另外三个是我们添加到`testReserveRoomExample`测试中的。如果我们测试了三个房间而不是两个，PHPUnit 将产生以下输出：

```php
**$ phpunit**
**PHPUnit 4.5.0 by Sebastian Bergmann and contributors.**

**Configuration read from /var/www/laravel.example/phpunit.xml**

**.**
**F**

**Time: 1.59 seconds, Memory: 10.75Mb**

**There was 1 failure:**

**1) ExampleTest::testReserveRoomExample**
**Failed asserting that 2 matches expected 3.**

**/var/www/laravel.example/tests/ExampleTest.php:24**

**FAILURES!** 
**Tests: 2, Assertions: 4, Failures: 1.**

```

请注意，我们有一个`F`表示失败，而不是第二个点，而不是`OK`，我们被告知有`1`个失败。然后 PHPUnit 列出了哪些测试失败，并很好地告诉我们我故意修改为不正确的行。

```php
   $this->assertEquals(3,count($reservationResult->rooms));
```

前面的行确实是不正确的：

```php
**Failed asserting that 2 matches expected 3.**

```

请记住，`2`是`($reservationResult->rooms)`的计数值。

# 使用 Behat 进行功能测试

虽然 phpspec 遵循 BDD 的规范，并且在隔离中很有用于规范和设计，但它的补充工具 Behat 用于集成和功能测试。由于 phpspec 建议对所有内容进行模拟，数据库查询实际上不会被执行，因为数据库在该方法的上下文之外。Behat 是一个在某个功能上执行行为测试的好工具。虽然 phpspec 已经包含在 Laravel 5 的依赖项中，但 Behat 将作为外部模块安装。

应该运行以下命令来安装并使 Behat 与 Laravel 5 一起工作：

```php
**$ composer require behat/behat behat/mink behat/mink-extension laracasts/behat-laravel-extension --dev**

```

运行 composer update 后，Behat 的功能将添加到 Laravel 中。接下来，应在 Laravel 项目的根目录中添加一个`behat.yaml`文件，以指定要使用哪些扩展。

接下来，运行以下命令：

```php
**$ behat --init**

```

这将创建一个`features`目录，里面有一个`bootstrap`目录。还将创建一个`FeaturesContext`类。`bootstrap`中的所有内容都将在每次运行`behat`时运行。这对于自动运行迁移和填充是有用的。

`features/bootstrap/FeaturesContext.php`文件如下：

```php
<?php

use Behat\Behat\Context\Context;
use Behat\Behat\Context\SnippetAcceptingContext;
use Behat\Gherkin\Node\PyStringNode;
use Behat\Gherkin\Node\TableNode;

/**
 * Defines application features from the specific context.
 */
class FeatureContext implements Context, SnippetAcceptingContext
{
    /**
     * Initializes context.
     *
     * Every scenario gets its own context instance.
     * You can also pass arbitrary arguments to the
     * context constructor through behat.yml.
     */
    public function __construct()
    {
    }
}
```

接下来，`FeatureContext`类需要扩展`MinkContext`类，因此类定义行需要修改如下：

```php
class FeatureContext implements Context, SnippetAcceptingContext
```

接下来，将在类中添加`prepare`和`cleanup`方法以执行迁移。我们将添加`@BeforeSuite`和`@AfterSuite`注释，告诉 Behat 在每个套件之前执行迁移和种子，并在每个套件之后回滚以将数据库恢复到其原始状态。将在文档块中使用注释将在第六章中讨论，*使用注释驯服复杂性*。我们的类现在结构如下：

```php
<?php

use Behat\Behat\Context\Context;
use Behat\Behat\Context\SnippetAcceptingContext;
use Behat\Gherkin\Node\PyStringNode;
use Behat\Gherkin\Node\TableNode;

/**
 * Defines application features from the specific context.
 */
class FeatureContext implements Context, SnippetAcceptingContext
{
    /**
     * Initializes context.
     *
     * Every scenario gets its own context instance.
     * You can also pass arbitrary arguments to the
     * context constructor through behat.yml.
     */
    public function __construct()
    {
    }
     /**
     * @BeforeSuite
     */
     public static function prepare(SuiteEvent $event)
     {
        Artisan::call('migrate');
        Artisan::call('db:seed');

     }

     /**
     * @AfterSuite 
     */
     public function cleanup(ScenarioEvent $event)
     {
        Artisan::call('migrate:rollback');
     }
}
```

现在，需要创建一个功能文件。在 room 目录中创建`reservation.feature`：

```php
Feature: Reserve Room
  In order to verify the reservation system
  As an accommodation reservation user
  I need to be able to create a reservation in the system
  Scenario: Reserve a Room
   When I create a reservation
         Then I should have one reservation
```

当运行`behat`如下时：

```php
**$ behat**

```

产生以下输出：

```php
**Feature: Reserve Room**
 **In order to verify the reservation system**
 **As an accommodation reservation user**
 **I need to be able to create a reservation in the system**

 **Scenario: List 2 files in a directory # features/reservation.feature:5**
 **When I create a reservation**
 **Then I should have one reservation**

**1 scenario (1 undefined)**
**2 steps (2 undefined)**
**0m0.10s (7.48Mb)**

**--- FeatureContext has missing steps. Define them with these snippets:**

 **/****
 *** @When I create a reservation**
 ***/**
 **public function iCreateAReservation()**
 **{**
 **throw new PendingException();**
 **}**

 **/****
 *** @Then I should have one reservation**
 ***/**
 **public function iShouldHaveOneReservation()**
 **{**
 **throw new PendingException();**
 **}**

```

Behat，就像 phpspec 一样，熟练地生成输出，向您显示需要创建的方法。请注意，此处使用驼峰命名法而不是蛇形命名法。此代码应复制到`FeatureContext`类中。请注意，默认情况下会抛出异常。

在这里，将调用 RESTful API，因此需要将 guzzle HTTP 包添加到项目中：

```php
**$ composer require guzzlehttp/guzzle**

```

接下来，向类添加一个属性来保存`guzzle`对象。我们将向 RESTful 资源控制器添加一个`POST`请求来创建预订，并期望获得 201 代码。请注意，返回代码是一个字符串，需要转换为整数。接下来，执行`get`以返回所有预订。

应该只创建一个预订，因为迁移和种子每次运行时都会运行：

```php
<?php

use Behat\Behat\Context\Context;
use Behat\Behat\Context\SnippetAcceptingContext;
use Behat\Gherkin\Node\PyStringNode;
use Behat\Gherkin\Node\TableNode;
use Behat\MinkExtension\Context\MinkContext;
use Behat\Testwork\Hook\Scope\BeforeSuiteScope;
use Behat\Testwork\Hook\Scope\AfterSuiteScope;
use GuzzleHttp\Client;

/**
 * Defines application features from the specific context.
 */
class FeatureContext extends MinkContext implements Context, SnippetAcceptingContext
{
    /**
     * Initializes context.
     *
     * Every scenario gets its own context instance.
     * You can also pass arbitrary arguments to the
     * context constructor through behat.yml.
     */
    protected $httpClient;

    public function __construct()
    {
        $this->httpClient = new Client();
    }
    /**
     * @BeforeSuite
     */
    public static function prepare(BeforeSuiteScope $scope)
    {
        Artisan::call('migrate');
        Artisan::call('db:seed');

    }

    /**
     * @When I create a reservation
     */
    public function iCreateAReservation()
    {
        $request = $this->httpClient->post('http://laravel.example/reservations',['body'=> ['start_date'=>'2015-04-01','end_date'=>'2015-04-04','rooms[]'=>'100']]);
        if ((int)$request->getStatusCode()!==201)
        {
            throw new Exception('A successfully created status code must be returned');
        }
    }

    /**
     * @Then I should have one reservation
     */
    public function iShouldHaveOneReservation()
    {
        $request = $this->httpClient->get('http://laravel.example/reservations');
        $arr = json_decode($request->getBody());
        if (count($arr)!==1)
        {
            throw new Exception('there must be exactly one reservation');
        }
    }

    /**
     * @AfterSuite
     */
    public static function cleanup(AfterSuiteScope $scope)
    {
        Artisan::call('migrate:rollback');
    }
}

    /**
     * @When I create a reservation
     */
    public function iCreateAReservation()
    {
        $request = $this->httpClient->post('http://laravel.example/reservations',['body'=> ['start_date'=>'2015-04-01','end_date'=>'2015-04-04','rooms[]'=>'100']]);
        if ((int)$request->getStatusCode()!==201)
        {
            throw new Exception('A successfully created status code must be returned');
        }
    }
```

现在，使用命令行中的 artisan 来创建`ReservationController`：

```php
**$ php artisan make:controller ReservationsController**

```

以下是预订控制器的内容：

```php
<?php namespace MyCompany\Http\Controllers;

use MyCompany\Http\Requests;
use MyCompany\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use MyCompany\Accommodation\ReservationRepository;
use MyCompany\Accommodation\ReservationValidator;
use MyCompany\Accommodation\Reservation;

class ReservationsController extends Controller {

    /**
    * Display a listing of the resource.
    *
    * @return Response
    */
    public function index()
    {
        return Reservation::all();
    }

    /**
    * Store a newly created resource in storage.
    *
    * @return Response
    */
    public function store()
    {
        $reservationRepository = new ReservationRepository(new Reservation());
        $reservationValidator = new ReservationValidator();
        if ($reservationValidator->validate(\Input::get('start_date'),
        \Input::get('end_date'),\Input::get('rooms')))
        {
        $reservationRepository->create(['date_start'=>\Input::get('start_date'),'date_end'=>\Input::get('end_date'),'rooms'=>\Input::get('rooms')]);
        return response('', '201');
        }
    }
}
```

最后，将`ReservationController`添加到`routes.php`文件中，该文件位于`app/Http/routes.php`中：

```php
**Route::resource('reservations','ReservationController');**

```

现在，当运行`behat`时，结果如下：

```php
**Feature: Reserve Room**
 **In order to verify the reservation system**
 **As an accommodation reservation user**
 **I need to be able to create a reservation in the system**

 **Scenario: Reserve a Room**
 **When I create a reservation         # FeatureContext::iCreateAReservation()**
 **Then I should have one reservation  # FeatureContext::iShouldHaveOneReservation()**

**1 scenario (1 passed)**
**2 steps (2 passed)**

```

# 总结

配置 Laravel 以从现有模式创建迁移文件也是非全新项目的一个有用框架。通过在测试环境中运行迁移和种子，每个测试都可以从数据库的完全干净版本中受益，并且可以通过初始数据最小地验证软件的执行是否符合需要。当需要将遗留代码移植到 Laravel 时，PHPUnit 可以用于测试任何现有功能。Behat 提供了一种基于行为的替代方案，可以熟练地执行端到端测试。

我们使用 phpspec 在一个独立的环境中设计了我们的类，只专注于业务规则和客户端的请求，同时模拟诸如实际实体（如房间）之类的事物。然后，我们通过使用功能测试工具 PHPUnit 验证了实际查询是否正确执行并保存在数据库中。最后，我们使用 Behat 执行端到端测试。

在下一章中，我们将看到 RESTful API 的创建，基本的 CRUD 操作（创建，读取，更新和删除），并讨论一些最佳实践。


# 第三章：构建服务、命令和事件

在前两章中，我们建立了我们的住宿预订系统的基本结构。我们设计了我们的类，创建了我们的数据库模式，并学会了如何测试它们。现在我们需要将业务需求转化为代码。

在本章中，我们将涵盖以下主题：

+   命令

+   事件

+   命令处理程序

+   事件处理程序

+   排队的事件处理程序

+   排队的命令

+   控制台命令

+   命令调度程序

# 请求路由

如前所述，Laravel 5 采用了*命令总线模式*。Laravel 4 将命令视为从命令行执行的内容，而在 Laravel 5 中，命令可以在任何上下文中使用，从而实现代码的优秀重用。

以下是 Laravel 4 的 HTTP 请求流程示例：

![请求路由](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_03_01.jpg)

以下是 Laravel 5 的 HTTP 请求流程示例：

![请求路由](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_03_02.jpg)

第一张图片说明了 Laravel 4 的请求流程。通过 HTTP 的请求由路由处理，然后发送到控制器，通常情况下，我们可以与存储库或模型的目录进行交互。在 Laravel 5 中，这仍然是可能的；然而，正如第二张图片所示，我们可以看到添加额外的块、层或模块的能力使我们能够将请求的生命周期分离成单独的部分。Laravel 4 允许我们将处理请求的所有代码放在控制器内，而在 Laravel 5 中，我们可以自由地做同样的事情，尽管现在我们也能够轻松地将请求分离成各种部分。其中一些概念源自**领域驱动设计**（**DDD**）。

在控制器内，使用**数据传输对象**（**DTO**）范例实例化命令。然后，命令被发送到命令总线，在那里由处理程序类处理，该类有两个方法：`__construct()`和`handle()`。在处理程序内部，我们触发或实例化一个事件。同样，事件也由事件处理程序方法处理，该方法有两个方法：`__construct()`和`handle()`。

目录结构非常清晰，如下所示：

```php
**/app/Commands**
**/app/Events/**
**/app/Handlers/**
**/app/Handlers/Commands**
**/app/Handlers/Events**
**/app/HTTP/Controllers**

```

这相当直观；命令和事件分别在它们各自的目录中，而每个处理程序都有自己的目录。

### 注意

Laravel 5.1 已将`app/Commands`目录的名称更改为`app/Jobs`，以确保程序员不会混淆命令总线和控制台命令的概念。

## 用户故事

命令组件的想法可以很容易地从用户故事或用户为实现目标而需要的任务中得出。最简单的例子是搜索一个房间：

```php
As a hotel website user,
I want to search for a room
so that I can select from a list of results.
```

源自敏捷方法论的用户故事保证编写的代码与业务需求紧密匹配。它们通常遵循“作为…我想要…以便…”的模式。这定义了`角色`、`意图`和`利益`。它帮助我们计划如何将每个任务转换为代码。在我们的例子中，用户故事可以转化为任务。

作为酒店网站用户，我会创建以下任务列表：

1.  作为酒店网站用户，我希望搜索房间，以便我可以从结果列表中选择一个房间。

1.  作为酒店网站用户，我希望预订一个房间，以便我可以住在酒店里。

1.  作为酒店网站用户，我希望收到包含预订详情的电子邮件，以便我可以拥有预订的副本。

1.  作为酒店网站用户，我希望在等候名单上，以便我可以在有房间可用时预订一个房间。

1.  作为酒店网站用户，我希望收到房间的可用性通知，以便我可以预订房间。

## 用户故事转换为代码

搜索房间的第一个任务很可能是来自用户或外部服务的 RESTful 调用，因此这个任务会暴露给我们的控制器，从而暴露给我们的 RESTful API。

第二个任务，预订房间，是由用户或其他服务发起的类似操作。这个任务可能需要用户登录。

第三个任务可能取决于第二个任务。这个任务需要与另一个过程进行交互，向用户发送包含预订详情的确认电子邮件。我们也可以这样写：*作为酒店网站，我想发送一封带有预订详情的电子邮件，以便他或她可以拥有预订的副本*。

第四个任务，加入等待列表，可能是在发出预订房间请求后执行的命令；如果另一个用户同时预订了房间。它很可能是从应用程序本身而不是用户那里调用的，因为用户对实时住宿库存没有了解。这可以帮助我们处理竞争条件。此外，我们应该假设当网站用户决定预订哪个房间时，该房间没有锁定机制来保证可用性。我们也可以这样写：*作为酒店网站，我想将用户放在等待列表中，以便在房间可用时通知他们*。

对于第五个任务，当用户被放在等待列表上时，用户也可以在房间可用时收到通知。此操作检查房间的可用性，然后检查等待列表上的任何用户。用户故事可以重写如下：*作为酒店网站，我想通知等待列表用户房间的可用性，以便他或她可以预订房间*。如果房间变得可用，等待列表上的第一个用户将通过电子邮件收到可用性通知。这个命令将经常执行，就像是一个定时任务。幸运的是，Laravel 5 有一种新的机制，允许命令以给定的频率执行。

很明显，如果用户故事必须以使用网站作为行动者（“作为酒店网站...”）或网站用户作为行动者（“作为酒店网站用户...”）来编写，命令是有用的，并且可以从 RESTful API（用户端）或 Laravel 应用程序内部启动。

由于我们的第一个任务很可能涉及外部服务，我们将创建一个路由和一个控制器来处理请求。

## 控制器

第一步涉及创建一个路由，第二步涉及创建一个控制器。

### 搜索房间

首先，在`routes.php`文件中创建一个路由，并将其映射到`controller`方法，如下所示：

```php
Route::get('search', 'RoomController@search');
```

请求参数，如开始/结束日期和位置详情将如下所示：

```php
{
  "start_date": "2015-07-10"
  "end_date": "2015-07-17"
  "city": "London"
  "country": "England"
}
```

搜索参数将以 JSON 编码的对象形式发送。它们将发送如下：

```php
http://websiteurl.com/search?query={%22start_date%22:%222015-07-10%22,%22end_date%22:%222015-07-17%22,%22city%22:%22London%22,%22country%22:%22England%22}
```

现在，让我们在我们的`room`控制器中添加一个`search`方法，以处理以对象形式输入的 JSON 请求，如下所示：

```php
/**
* Search for a room in an accommodation
*/
public function search()
{
      json_decode(\Request::input('query'));
}
```

请求外观处理输入变量查询，然后将其 JSON 结构解码为对象。

在第四章中，*创建 RESTful API*，我们将完成`search`方法的代码，但现在，我们将简单地创建我们的 RESTful API 系统的这一部分的架构。

### 控制器转命令

对于第二个任务，预订房间，我们将创建一个命令，因为我们很可能需要后续操作，我们将通过发布者订阅者模式启用。发布者订阅者模式用于表示发送消息的*发布者*和监听这些消息的*订阅者*。

将以下路由添加到`routes.php`中：

```php
**Route::post('reserve-room', 'RoomController@store');**

```

我们将 post 映射到 room 控制器的`store`方法；这将创建预订。记住我们创建了这样的命令：

```php
**$ php artisan make:commandReserveRoomCommand -–handler**

```

我们的`ReserveRoomCommand`类如下所示：

```php
<?php namespace MyCompany\Commands;

use MyCompany\Commands\Command;
use MyCompany\User;

class ReserveRoomCommand extends Command {

    public $user;
    public $rooms;
    public $start_date;
    public $end_date;

    /**
    * Create a new command instance.
    *
    * @return void
    */
    public function __construct(User $user, $start_date, $end_date, $rooms)
    {
        $this->rooms = $rooms;
        $this->user = $user;
        $this->start_date = $start_date;
        $this->end_date = $end_date;
     }

}
```

我们需要将以下属性添加到构造函数中：

```php
    public $user;
    public $rooms;
    public $start_date;
    public $end_date;
```

此外，将以下赋值添加到构造函数中：

```php
        $this->rooms = $rooms;
        $this->user = $user;
        $this->start_date = $start_date;
        $this->end_date = $end_date;
```

这使我们能够传递值。

### 命令转事件

现在让我们创建一个事件。使用`artisan`创建一个事件`RoomWasReserved`，当房间被创建时触发：

```php
**$ phpartisan make:eventRoomWasReserved**

```

`RoomWasReserved`事件类看起来像以下代码片段：

```php
<?php namespace MyCompany\Events;

use MyCompany\Accommodation\Reservation;
use MyCompany\Events\Event;
use MyCompany\User;

use Illuminate\Queue\SerializesModels;

class RoomWasReserved extends Event {

    use SerializesModels;

    private $user;
    private $reservation;

    /**
    * Create a new event instance.
    *
    * @return void
    */
    public function __construct(User $user, Reservation $reservation)
    {
        $this->user = $user;
        $this->reservation = $reservation;
    }
}
```

我们将告诉它使用`MyCompany\Accommodation\Reservation`和`MyCompany\User`实体，以便我们可以将它们传递给构造函数。在构造函数内部，我们将它们分配给`event`对象内的实体。

现在，让我们从命令处理程序内部触发事件。Laravel 为您提供了一个简单的`event()`方法作为一个方便/辅助方法，它将触发一个事件。我们将实例化的预订和`user`注入`RoomWasReserved`事件如下：

```php
**event(new RoomWasReserved($user, $reservation));**

```

### `ReserveRoomCommandHandler`类

我们的`ReserveRoomCommandHandler`类现在实例化一个新的预订，使用`createNew`工厂方法来注入依赖项，最后，触发`RoomWasReserved`事件如下：

```php
<?phpnamespace MyCompany\Handlers\Commands;

use MyCompany\Commands\ReserveRoomCommand;

use Illuminate\Queue\InteractsWithQueue;

class ReserveRoomCommandHandler {

    /**
    * Create the command handler.
    *
    * @return void
    */
    public function __construct()
    {
        //
    }

    /**
    * Handle the command.
    *
    * @paramReserveRoomCommand  $command
    * @return void
    */
    public function handle(ReserveRoomCommand $command)
    {

        $reservationValidator = new \MyCompany\Accommodation\ReservationValidator();

        if ($reservationValidator->validate($command->start_date,$command->end_date,$command->rooms)) {
              $reservation = 
                $reservationRepository->create(
                ['date_start'=>$command->$command→start_date,
                'date_end'=>$command->end_date,
                'rooms'=>$command->'rooms']);
        }
    $reservation = new 
      event(new RoomWasReserved($command->user,$reservation));
    }
}
```

### 事件到处理程序

现在，我们需要创建事件处理程序。正如您所期望的那样，Artisan 提供了一个方便的方法来做到这一点，尽管语法有点不同。这一次，奇怪的是，*make*这个词没有出现在短语中：

```php
**$ php artisan handler:eventRoomReservedEmail --event=RoomWasReserved**
 **<?php namespace MyCompany\Handlers\Events;**

 **use MyCompany\Events\RoomWasReserved;**

 **use Illuminate\Queue\InteractsWithQueue;**
 **use Illuminate\Contracts\Queue\ShouldBeQueued;**

 **class RoomReservedEmail {**

 **/****
 *** Create the event handler.**
 *** @return void**
 ***/**
 **public function __construct()**
 **{**
 **}**

 **public function handle(RoomWasReserved $event)**
 **{**
 **//TODO: send email to $event->user**
 **//TODO: with details about $event->reservation;**
 **}**
 **}**

```

现在我们需要将事件连接到其监听器。我们将编辑`app/Providers/EventServiceProvider.php`文件如下：

```php
protected $listen = [
    'MyCompany\Events\RoomWasReserved' => [
      'MyCompany\Handlers\Events\RoomReservedEmail',
      ],
    ];
```

如前面的代码片段所示，我们将向`$listen`数组添加键值对。如所示，需要完整路径作为键，事件名称和处理程序数组。在这种情况下，我们只有一个处理程序。

## 排队的事件处理程序

如果我们不希望事件立即处理，而是放入队列中，我们可以在创建命令中添加`-queued`如下：

```php
**$ php artisan handler:eventRoomReservedEmail --event=RoomWasReserved --queued**

```

```php
 **<?php namespace MyCompany\Handlers\Events;**

 **use MyCompany\Events\RoomWasReserved;**

 **use Illuminate\Queue\InteractsWithQueue;**
 **use Illuminate\Contracts\Queue\ShouldBeQueued;**

 **class RoomReservedEvent implements ShouldBeQueued {**

 **use InteractsWithQueue;**

 **public function __construct()**
 **{**
 **//**
 **}**

 **use Illuminate\Contracts\Queue\ShouldBeQueued;**

```

这个接口告诉 Laravel 事件处理程序应该被排队，而不是同步执行：

```php
use Illuminate\Queue\InteractsWithQueue;
```

这个 trait 允许我们与队列交互，以便执行任务，比如删除任务。

## 等待列表命令

对于第四个任务，被放置在等待列表中，我们需要创建另一个命令，该命令将从预订控制器内部调用。再次使用 Artisan，我们可以轻松地创建命令及其相应的事件如下：

```php
**$ php artisan make:commandPlaceOnWaitingListCommand**
**$ php artisan make:eventPlacedOnWaitinglist**

```

现在，在我们的预订控制器中，我们将添加`roomAvailability`的检查，然后按以下方式分派`PlaceOnWaitinglist`命令：

```php
public function store()
    {
    …
    …
        if ($roomAvailable) {
            $this->dispatch(
              new ReserveRoomCommand( $start_date, $end_date, $rooms)
            );
        } else {
            $this->dispatch(
              new PlaceOnWaitingListCommand($start_date, $end_date, $rooms)
            );
        }
    …
```

## 排队的命令

通过在`create`命令中添加`queued`，我们可以轻松地将命令加入队列：

```php
**$ php artisan make:commandReserveRoomCommand -–handler --queued**

```

这将使用可用的任何队列系统，比如 beanstalkd，并不会立即运行命令。相反，它将被放置在队列中，并稍后运行。我们需要为`Command`类添加一个接口：

```php
**Illuminate\Contracts\Queue\ShouldBeQueued**

```

在这种情况下，`ReserveRoomCommand`类将如下所示：

```php
<?php namespace MyCompany\Commands;

use MyCompany\Commands\Command;

use Illuminate\Queue\SerializesModels;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Contracts\Queue\ShouldBeQueued;

class MyCommand extends Command implements ShouldBeQueued {

	use InteractsWithQueue, SerializesModels;

	/**
	 * Create a new command instance.
	 *
	 * @return void
	 */
	public function __construct()
	{
		//
	}

}
```

在这里，我们可以看到`InteractsWithQueue`和`ShouldBeQueued`类已经被包含，`ReserveRoomCommand`类扩展了命令并实现了`ShouldBeQueued`类。另一个有趣的特性是`SerializesModels`。这将序列化传递的任何模型，以便稍后使用。

## 控制台命令

对于第五个任务，让我们创建一个`console`命令，这个命令将经常被执行：

```php
**$ php artisan make:consoleManageWaitinglist**

```

这将创建一个可以从 Artisan 命令行工具执行的命令。如果您使用过 Laravel 4，您可能对这种类型的命令很熟悉。这些命令存储在`Console/Commands/`目录中。

为了让 Laravel 知道这一点，我们需要将它添加到`app/Console/Kernel.php`中的`$commands`数组中：

```php
protected $commands = [
    'MyCompany\Console\Commands\Inspire',
    'MyCompany\Console\Commands\ManageWaitinglist',
    ];
```

内容如下：

```php
<?php namespace MyCompany\Console\Commands;

use Illuminate\Console\Command;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputArgument;

class ManageWaitinglist extends Command {

    /**
    * The console command name.
    *
    * @var string
    */
    protected $name = 'command:name';

    /**
    * The console command description.
    *
    * @var string
    */
    protected $description = 'Command description.';

    /**
    * Create a new command instance.
    *
    * @return void
    */
    public function __construct()
    {
        parent::__construct();
    }

    /**
    * Execute the console command.
    *
    * @return mixed
    */
    public function fire()
    {
        //
    }

    /**
    * Get the console command arguments.
    *
    * @return array
    */
    protected function getArguments()
    {
        return [
          ['example', InputArgument::REQUIRED, 'An example argument.'],
        ];
    }

    /**
    * Get the console command options.
    *
    * @return array
    */
    protected function getOptions()
    {
        return [
          ['example', null, InputOption::VALUE_OPTIONAL, 'An example option.', null],
        ];
    }
}
```

`$name`属性是从 Artisan 调用的名称。例如，如果我们设置如下：

```php
protected $name = 'manage:waitinglist';
```

然后，通过运行以下命令，我们可以管理等待列表：

```php
**$ php artisan manage:waitinglist**

```

`getArguments()`和`getOptions()`方法是具有相同签名的类似方法，但用途不同。

`getArguments()`方法指定了必须用于启动命令的参数数组。`getOptions()`方法用`-`指定，并且可以是`optional`、`repeated`，并且使用`VALUE_NONE`选项，它们可以简单地用作标志。

我们将在`fire()`方法中编写命令的主要代码。如果我们想要从该命令中调度一个命令，我们将在类中添加`DispatchesCommands` trait，如下所示：

```php
 **use DispatchesCommands;**

 **<?php namespace MyCompany\Console\Commands;**

 **use Illuminate\Console\Command;**
 **use Illuminate\Foundation\Bus\DispatchesCommands;**
 **use Symfony\Component\Console\Input\InputOption;**
 **use Symfony\Component\Console\Input\InputArgument;**

 **class ManageWaitinglist extends Command {**

 **use DispatchesCommands;**

 **/****
 *** The console command name.**
 *** @var string**
 ***/**
 **protected $name = 'manage:waitinglist';**

 **/****
 *** The console command description.**
 *** @var string**
 ***/**
 **protected $description = 'Manage the accommodation waiting list.';**

 **/****
 *** Create a new command instance.**
 *****
 *** @return void**
 ***/**
 **public function __construct()**
 **{**
 **parent::__construct();**
 **}**

 **/****
 *** Execute the console command.**
 *** @return mixed**
 ***/**
 **public function fire()**
 **{**
 **// TODO: write business logic to manage waiting list**
 **if ($roomIsAvailableFor($user)) {**
 **$this->dispatch(new ReserveRoomCommand());**
 **}**
 **}**

 **/****
 *** Get the console command arguments.**
 *** @return array**
 ***/**
 **protected function getArguments()**
 **{**
 **return [];**
 **}**

 **/****
 *** Get the console command options.**
 *** @return array**
 ***/**
 **protected function getOptions()**
 **{**
 **return [];**
 **}**
**}**

```

## 命令调度程序

现在，我们将安排此命令每 10 分钟运行一次。传统上，这是通过创建一个 cron 作业来执行 Laravel 控制台命令来完成的。现在，Laravel 5 提供了一个新的机制来做到这一点——命令调度程序。

新的`artisan`命令的运行方式如下：

```php
**$ php artisan schedule:run**

```

通过简单地将此命令添加到 cron 中，Laravel 将自动运行`Kernel.php`文件中的所有命令。

命令需要添加到`Schedule`函数中，如下所示：

```php
protected function schedule(Schedule $schedule)
    {
        $schedule->command('inspire')
             ->hourly();
        $schedule->command('manage:waitinglist')
            ->everyFiveMinutes();

    }
```

`inspire`命令是 Laravel 提供的一个示例命令，用于演示功能。我们将简单地添加我们的命令。这将每 5 分钟调用`manage:waitinglist`命令——比这更简单的方式都没有了。

现在我们需要修改`crontab`文件以使 Artisan 运行调度程序。

`crontab`是一个包含在特定时间运行的命令的文件。要修改此文件，请键入以下命令：

```php
**$ sudo crontab -e**

```

我们将使用`vi`或分配的编辑器来修改`cron`表。添加以下行将告诉`cron`每分钟运行调度程序：

```php
*** * * * * php /path/to/artisan schedule:run 1>> /dev/null 2>&1**

```

# 总结

Laravel 在短短两年内发生了变化，从 CodeIgniter 的模型-视图-控制器范式转变为采用现代领域驱动设计的命令总线和发布者-订阅者事件监听器模式。是否使用这些模式将取决于所需的每个层之间的分离程度。当然，即使使用自处理命令也是开始创建完全独立的代码块的一种方式，这将促使代码进入一个单独的处理程序类，进一步实现关注点分离原则。通过减少控制器内的代码量，命令变得更加重要。

我们甚至还没有为每个用户故事编写与数据库交互的代码，我们只是对数据库进行了种子和测试，但结构开始变得非常设计良好；每个类都有一个非常有意义的名称，并且组织成一个有用的目录结构。

在下一章中，我们将填写有关 RESTful 控制器如何接受来自另一个系统或网站前端的输入，以及模型属性如何返回给用户以创建界面的详细信息。
