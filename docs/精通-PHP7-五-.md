# 精通 PHP7（五）

> 原文：[`zh.annas-archive.org/md5/c80452b19d206124b22230f7a590b2c3`](https://zh.annas-archive.org/md5/c80452b19d206124b22230f7a590b2c3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：解决依赖关系

编写松散耦合的代码已经成为任何专业开发人员的必备技能。虽然传统应用程序倾向于将所有内容打包在一起，最终形成一个大的代码块，但现代应用程序采用了更渐进的方法，因为它们在很大程度上依赖于第三方库和其他组件。如今，几乎没有人会构建自己的邮件发送器、日志记录器、路由器、模板引擎等。这些组件中的大部分都可以通过 Composer 等方式被我们的应用程序使用。由于各个组件本身都是由各种社区或商业实体测试和维护的，因此我们的应用程序维护成本大大降低。整体代码质量本身也因为更专业的开发人员处理特定功能而得以提高，这些功能可能超出了我们的专业领域。通过松散耦合的代码实现的和谐。

松散耦合的代码有许多积极的副作用，其中包括以下几点：

+   更容易重构

+   提高代码可维护性

+   更容易跨平台利用

+   更容易跨框架利用

+   对单一职责原则的追求

+   更容易测试

通过利用各种语言特性（如接口）和设计模式（如依赖注入）轻松实现松散耦合的魔法。接下来，我们将通过以下部分来看一下依赖注入的基本方面：

+   减轻常见问题

+   理解依赖注入

+   理解依赖注入容器

# 减轻常见问题

依赖注入是一种既定的软件技术，处理对象依赖的问题，使我们能够编写松散耦合的类。虽然这种模式已经存在了相当长的时间，但 PHP 生态系统直到 Symfony 等主要框架开始实施它之前并没有真正采用它。如今，除了微不足道的应用类型之外，它已经成为事实上的标准。整个依赖问题可以通过一个简单的例子轻松观察到：

```php
<?php   class Customer {
  protected $name;    public function loadByEmail($email)
 {  $mysqli = new mysqli('127.0.0.1', 'foggy', 'h4P9niq5', 'sakila');    $statement = $mysqli->prepare('SELECT * FROM customer WHERE email = ?');
  $statement->bind_param('s', $email);
  $statement->execute();    $customer = $statement->get_result()->fetch_object();    $this->name = $customer->first_name . ' ' . $customer->last_name;    return $this;
 } }   $customer = new Customer(); $customer->loadByEmail('MARY.SMITH@sakilacustomer.org');

```

在这里，我们有一个简单的 `Customer` 类，其中有一个 `loadByEmail()` 方法。令人困扰的部分是 `loadByEmail()` 实例方法对数据库 `$mysqli` 对象的依赖。这导致了紧耦合，降低了代码的可重用性，并为后续代码更改可能引入可能的系统范围副作用打开了大门。为了减轻问题，我们需要将数据库 `$mysqli` 对象注入到 `$customer` 中。

可以从[`dev.mysql.com/doc/sakila/en/`](https://dev.mysql.com/doc/sakila/en/)获取 MySQL Sakila 数据库。

有三种方法可以将依赖注入到对象中*：*

+   通过实例方法

+   通过类构造函数

+   通过实例属性

而实例方法和类构造函数的方法似乎比实例属性注入更受欢迎。

以下示例演示了使用实例方法进行依赖注入的方法：

```php
<?php   class Customer {
  public function loadByEmail($email, $mysqli)
 {  // ...
  } }   $mysqli  = new mysqli('127.0.0.1', 'foggy', 'h4P9niq5', 'sakila');  $customer = new Customer(); $customer->loadByEmail('MARY.SMITH@sakilacustomer.org', $mysqli);

```

在这里，我们通过客户的 `loadByEmail()` 实例方法将 `$mysqli` 对象的实例注入到 `Customer` 对象中。虽然这肯定比在 `loadByEmail()` 方法内部实例化 `$mysqli` 对象的方式更好，但很容易想象，如果我们的类有十几种方法，每种方法都需要传递不同的对象，我们的客户端代码可能会变得笨拙。虽然这种方法似乎很诱人，但通过实例方法注入依赖违反了面向对象编程的封装原则。此外，为了依赖而向方法添加参数绝不是最佳实践的例子。

另一种方法是利用类构造函数方法，如下例所示：

```php
<?php   class Customer {
  public function __construct($mysqli)
 {  // ...
  }    public function loadByEmail($email)
 {  // ...
  } }   $mysqli = new mysqli('127.0.0.1', 'foggy', 'h4P9niq5', 'sakila');   $customer = new Customer($mysqli); $customer->loadByEmail('MARY.SMITH@sakilacustomer.org');

```

在这里，我们通过客户的`__constructor()`方法将`$mysqli`对象的实例注入到`Customer`对象的实例中。无论是注入一个对象还是十几个对象，构造函数注入在这里都是明显的赢家。客户端应用程序有一个单一的入口点用于所有注入，这样就很容易跟踪事物。

没有依赖注入的概念，松散耦合的代码是不可能实现的。

# 理解依赖注入

在介绍部分，我们提到通过类`__construct()`方法传递依赖项。除了传递依赖对象之外，还有更多内容。让我们考虑以下三个看似相似但不同的例子。

尽管 PHP 已经支持类型提示很长一段时间了，但并不罕见遇到以下代码片段：

```php
<?php   class App {
  protected $config;
  protected $logger;    public function __construct($config, $logger)
 {  $this->config = $config;
  $this->logger = $logger;
 }    public function run()
 {  $this->config->setValue('executed_at', time());
  $this->logger->log('executed');
 } }   class Config {
  protected $config = [];    public function setValue($path, $value)
 {  // implementation
  } }   class Logger {
  public function log($message)
 {  // implementation
  } }   $config = new Config(); $logger = new Logger();   $app = new App($config, $logger); $app->run();

```

我们可以看到`App`类的`__construct()`方法没有使用 PHP 类型提示功能。开发人员假定`$config`和`$logger`变量是某种类型。虽然这个例子可以正常工作，但它仍然使我们的类紧密耦合。这个例子和之前在`loadByEmail()`方法中有`$msqli`依赖的例子之间没有太大的区别。

将类型提示添加到混合中允许我们强制传递给`App`类`__construct()`方法的类型：

```php
<?php   class App {
  protected $config;
  protected $logger;    public function __construct(Config $config, Logger $logger)
 {  $this->config = $config;
  $this->logger = $logger;
 }    public function run()
 {  $this->config->setValue('executed_at', time());
  $this->logger->log('executed');
 } }   class Config {
  protected $config = [];    public function setValue($path, $value)
 {  // implementation
  } }   class Logger {
  public function log($message)
 {  // implementation
  } }   $config = new Config(); $logger = new Logger();   $app = new App($config, $logger); $app->run();

```

这个简单的举措使我们的代码松散耦合了一半。虽然我们现在指示我们的可注入对象是一个确切的类型，但我们仍然锁定在一个特定类型上，也就是实现。追求松散耦合不应该让我们锁定在特定的实现上；否则，依赖注入模式就没有太多用处了。

这第三个例子在第一个两个例子中设置了一个重要的区别：

```php
<?php   class App {
  protected $config;
  protected $logger;    public function __construct(ConfigInterface $config, LoggerInterface $logger)
 {  $this->config = $config;
  $this->logger = $logger;
 }    public function run()
 {  $this->config->setValue('executed_at', time());
  $this->logger->log('executed');
 } }   interface ConfigInterface {
  public function getValue($value);    public function setValue($path, $value); }   interface LoggerInterface {
  public function log($message); }   class Config implements ConfigInterface {
  protected $config = [];    public function getValue($value)
 {  // implementation
  }    public function setValue($path, $value)
 {  // implementation
  } }   class Logger implements LoggerInterface {
  public function log($message)
 {  // implementation
  } }   $config = new Config(); $logger = new Logger();   $app = new App($config, $logger); $app->run();

```

偏爱接口类型提示而不是具体类类型提示是编写松散耦合代码的关键要素之一。虽然我们仍然通过类`__construct()`注入依赖项，但现在我们是以*面向接口而不是实现*的方式来做。这使我们能够避免紧密耦合，使我们的代码更具可重用性。

显然，这些例子最终都很简单。我们可以想象当注入的对象数量增加时，事情会变得多么复杂，每个注入的对象可能需要一个、两个，甚至十几个`__construct()`参数本身。这就是依赖注入容器派上用场的地方。

# 理解依赖注入容器

依赖注入容器是一个知道如何自动将类组合在一起的对象。**自动装配**这个术语意味着实例化和正确配置对象。这绝不是一项容易的任务，这就是为什么有几个库在解决这个功能。

Symfony 框架提供的 DependencyInjection 组件是一个整洁的依赖注入容器，可以通过 Composer 轻松安装。

继续前进，让我们创建一个`di-container`目录，在那里我们将执行这些命令并设置我们的项目：

```php
composer require symfony/dependency-injection

```

结果输出表明我们应该安装一些额外的包：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/500c7447-11c1-4eb4-b1dd-54811758adb7.png)

我们需要确保通过运行以下控制台命令添加`symfony/yaml`和`symfony/config`包：

```php
composer require symfony/yaml
composer require symfony/config

```

`symfony/yaml`包安装了 Symfony Yaml 组件。该组件将 YAML 字符串解析为 PHP 数组，反之亦然。`symfony/config`包安装了 Symfony Config 组件。该组件提供了帮助我们从源中查找、加载、合并、自动填充和验证配置值的类，这些源可以是 YAML、XML、INI 文件，甚至是数据库本身。`symfony/dependency-injection`、`symfony/yaml`和`symfony/config`包本身就是松散耦合组件的一个很好的例子。虽然这三个组件共同工作以提供完整的依赖注入功能，但组件本身遵循松耦合的原则。

查看[`symfony.com/doc/current/components/dependency_injection.html`](http://symfony.com/doc/current/components/dependency_injection.html)了解更多关于 Symfony 的 DependencyInjection 组件的信息。

现在让我们继续在`di-container`目录中创建`container.yml`配置文件：

```php
services:
  config:
    class: Config
 logger:
    class: Logger
 app:
    class: App
 autowire: true

```

`container.yml`文件具有特定的结构，以关键字`services`开头。不深入研究，可以说服务容器是 Symfony 对依赖注入容器的称呼，而服务是执行某些任务的任何 PHP 对象--基本上是任何类的实例。

在`services`标签下面，我们有`config`、`logger`和`app`标签。这表示了三个独特服务的声明。我们可以轻松地将它们命名为`the_config`、`the_logger`、`the_app`，或者其他我们喜欢的名称。深入研究各个服务，我们看到`class`标签是所有三个服务共有的。`class`标签告诉容器在请求给定服务实例时实例化哪个类。最后，在`app`服务定义中使用的`autowire`功能允许自动装配子系统通过解析构造函数来检测`App`类的依赖关系。这使得客户端代码非常容易获取`App`类的实例，甚至不需要了解`App`类`__construct()`中的`$config`和`$logger`要求。

有了`container.yml`文件，让我们继续在`di-container`目录中创建`index.php`文件：

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   use Symfony\Component\DependencyInjection\ContainerBuilder; use Symfony\Component\Config\FileLocator; use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;   interface ConfigInterface { /* ... */}
interface LoggerInterface { /* ... */}
class Config implements ConfigInterface { /* ... */}
class Logger implements LoggerInterface { /* ... */}
class App { /* ... */}   // Bootstrapping $container = new ContainerBuilder();   $loader = new YamlFileLoader($container, new FileLocator(__DIR__)); $loader->load('container.yml');   $container->compile();   // Client code $app = $container->get('app'); $app->run();

```

确保用我们在理解依赖注入部分的第三个示例中的确切代码替换从`ConfigInterface`到`App`的所有内容。

我们首先包含了`autoload.php`文件，以便为我们的依赖容器组件实现自动加载。在`use`语句后面的代码与我们在理解依赖注入部分中的代码相同。有趣的部分在其后。创建了`ContainerBuilder`的实例，并传递给`YamlFileLoader`，后者加载了`container.yml`文件。文件加载后，我们在`$container`实例上调用`compile()`方法。运行`compile()`允许容器识别`autowire`服务标签，以及其他内容。最后，我们在`$container`实例上使用`get()`方法来获取`app`服务的实例。在这种情况下，客户端事先不知道传递给`App`实例的参数；依赖容器根据`container.yml`配置自行处理了所有内容。

使用接口类型提示和容器，我们能够编写更具可重用性、可测试性和解耦性的代码。

查看[`symfony.com/doc/current/service_container.html`](http://symfony.com/doc/current/service_container.html)了解更多关于 Symfony 服务容器的信息。

# 总结

依赖注入是一种简单的技术，它允许我们摆脱紧耦合的枷锁。结合接口类型提示，我们得到了一个强大的技术，可以编写松散耦合的代码。这样可以隔离和最小化可能的未来应用程序设计变化以及其缺陷的影响。如今，甚至在不采用这些简单技术的情况下编写模块化和大型代码库应用程序被认为是不负责任的。

展望未来，我们将更仔细地研究围绕 PHP 包的生态系统的状态，它们的创建和分发。


# 第十四章：使用包

现代 PHP 应用程序往往由大量文件组成。以 Magento 2 电子商务平台为例。一旦安装，其`vendor`目录包含超过三万个 PHP 类文件。它的庞大足以使任何人震惊。为什么会有这么多文件，人们可能会想？如今，使用其他开发人员在我们之前编写的现有库和包是流行的，甚至是强制性的。总是重新发明轮子并没有太多意义。这就是为什么像 Composer 这样的包管理器在 PHP 开发人员中如此受欢迎的原因。使用这些包管理器通常意味着将各种第三方包引入我们的项目。虽然这通常暗示着应用程序大小的增加，但它也允许我们快速启动应用程序开发。另一个好处是这些包由第三方持续维护，我们只需将其更新到我们的应用程序中。

在本章中，我们将研究 Composer，最受欢迎的 PHP 包管理器：

+   理解 Composer

+   理解 Packagist

+   使用第三方包

+   创建你自己的包

+   分发您的包

在前几章中，我们已经接触到了 Composer，因为我们使用了它的一些包。以下各节将在此基础上增加一些额外的清晰度，并展示我们如何创建自己的包。

# 理解 Composer

Composer 是 PHP 的*每个项目*包管理器。最初于 2011 年发布，它迅速赶上并成为 PHP 开发人员中最受欢迎的包管理器。仅仅通过查看其 GitHub 统计数据，我们就可以看到该项目正在由社区积极开发：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/e14d7ade-f249-4709-80cf-7a592d78176f.png)

如今，它几乎成为每个流行的 PHP 项目的一个组成部分。安装 Composer 是一个相当简单的任务。假设我们正在使用新的 Ubuntu 16.10（Yakkety Yak）安装，以下命令概述了我们如何安装 Composer：

```php
sudo apt-get -y install composer

```

安装后运行`composer -v`应该显示类似以下截图的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/cad1b44a-b5ed-49bd-aa8e-6a2db623e449.png)

现在我们已经安装了它，使用 Composer 非常简单。假设我们有一个现有项目，我们想要添加 Twig 库，我们只需在项目根目录中运行以下命令：

```php
composer require "twig/twig:².0"

```

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/b1e995de-1231-4e0e-9e21-c040d510ad87.png)

执行后，会创建/修改两个文件和一个目录：`composer.json`，`composer.lock`和`vendor`。`vendor`目录是 Composer 放置我们选择安装的包的物理位置。我们本可以通过手动创建相同的`composer.json`文件并运行`composer install`命令来开始，内容如下：

```php
{
  "require": {
    "twig/twig": "².0"
  }
}

```

查看[`getcomposer.org/doc/04-schema.md`](https://getcomposer.org/doc/04-schema.md)获取有关可能的`composer.json`内容的完整信息。

现在我们可以轻松修改`index.php`或任何其他入口文件到我们的根项目目录，并通过添加以下条目来包含所有已安装的 composer 包：

```php
require_once __DIR__ . '/vendor/autoload.php';

```

`vendor/autoload.php`文件是由 composer 工具创建的，它处理了我们通过 composer 拉入的所有包的自动加载，内容如下：

```php
<?php

// autoload.php @generated by Composer

require_once __DIR__ . '/composer/autoload_real.php';

return ComposerAutoloaderInitea5a081b69b5068b6eadbd8b638d57b2::getLoader();

```

这个文件并不是我们真正需要关心的东西，除了知道它在哪里。

支持 PSR-4 和 PSR-0 自动加载，尽管 PSR-4 是推荐的方式，因为它提供了更大的易用性。

一旦我们将`/vendor/autoload.php`包含到我们的脚本中，所有拉入的包都可以在我们的应用程序中使用。无论是新项目还是现有项目，Composer 都可以很容易地向其中添加包。

全面了解 Composer 超出了本节的范围。有关 Composer 的更多详细信息，请参阅原始文档([`getcomposer.org/`](https://getcomposer.org/))。

# 了解 Packagist

就像 Git 和 GitHub 的关系一样，我们有 Composer 和 Packagist 的关系。虽然**Composer**本身是实际工具，**Packagist**是为 Composer 提供包的默认存储库服务。服务足够简单，让我们找到我们想要为项目使用的包。不需要深入了解内部情况，可以说 composer 工具知道在 Packagist 上托管的每个包的代码在哪里获取。

Packagist 存储库服务托管在[`packagist.org`](https://packagist.org)上：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/06ab76e9-13ac-498e-9612-0c429beb57ab.png)

Composer 的受欢迎程度随时间的推移可以通过[`packagist.org/statistics`](https://packagist.org/statistics)页面轻松观察到，该页面显示了 Packagist 存储库中包的数量在几年内迅速增加的情况：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/e496c0dd-e78a-408c-a8c9-730d7d9f968a.png)

# 使用第三方包

我们已经看到了通过以下两种选项之一安装 composer 包是多么容易：

+   执行诸如`require vendor/package:2.* vendor/package2:dev-master`之类的命令

+   在`composer.json`的`require`下添加包链接信息，并在控制台上执行`composer install`

如果不知道我们可能需要哪个包，我们可以使用[`packagist.org`](https://packagist.org)搜索工具来查找。例如，假设我们正在寻找具有电子邮件发送功能的包。这就是 Packagist 存储库的庞大规模可能需要我们一些时间来找到合适的包的地方。幸运的是，我们可以使用下载量排序或收藏夹排序来帮助自己：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/857cc6de-49c9-441c-b7b8-5f67c1c7e198.png)

一旦单击单个包，我们就可以看到可以安装的可用版本：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/e5a96eb1-a05f-4c45-a099-3a39c6647999.png)

在这种情况下运行`composer require swiftmailer/swiftmailer`将为我们提供最新的稳定版本 5.4.6。

安装后，可以通过在项目根目录中运行`composer update`命令来将包稍后更新为可能的新稳定版本。

# 创建您自己的包

使用`composer init`命令，我们可以启动交互式`composer.json`生成器，稍后我们将使用它来分发我们的包。交互式生成器提出了几个问题，如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/ed12ecb8-3bdb-4ff8-afd7-0335ec6bb960.png)

我们在这里使用`foggyline`作为我们的供应商名称，而`mp7`（代表精通 PHP 7）被用作包名称。完成后，将生成具有以下内容的`composer.json`文件：

```php
{
"name": "foggyline/mp7",
"description": "Just a test package.",
"type": "library",
"license": "MIT",
"authors": [
    {
"name": "Branko Ajzele",
"email": "ajzele@gmail.com"
  }
  ],
"require": {}
}

```

现在，让我们继续创建相对于项目根目录的`src/Foggyline/MP7/Greeting/Goodbye.php`文件，其中包含以下内容：

```php
<?php   namespace FoggylineMP7Greeting;   class Welcome {
  public function generate($name)
 {  return 'Welcome ' . $name;
 } } 

```

这是我们即将分发为 composer 包的虚拟库类。在这样做之前，我们需要通过添加顶级`autoload`条目来修改`composer.json`，如下所示：

```php
"autoload": {
 "psr-4": {
 "FoggylineMP7": "src/Foggyline/MP7/"
  }
}

```

要测试`autoload`是否设置正确，我们运行`composer dump-autoload --optimize`控制台命令，并创建具有以下内容的`index.php`文件。我们故意使用完整路径到`MP7`目录，因为这将是我们的单独库，即包：

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   use FoggylineMP7GreetingWelcome;   $greeting = new Welcome();   echo $greeting->generate('John');

```

如果一切顺利，运行此脚本应该给我们一个欢迎约翰的输出。现在我们有了描述我们的项目的`composer.json`，以及包含我们的库代码的`src/Foggyline/MP7/`，我们可以继续并分发这个。

# 分发您的包

首先，我们需要将`composer.json`和我们的库代码从`src/Foggyline/MP7/`中推送到 GitHub 存储库。假设我们有一个空的 GitHub 存储库，比如`git@github.com:ajzele/foggyline_mp7.git`，等待我们，我们可以通过以下几个命令轻松地完成：

```php
git init
git remote add origin git@github.com:ajzele/foggyline_mp7.git
git add composer.json
git add src/Foggyline/MP7/
git commit -m "Initial commit"
git push origin master

```

这应该显示在 GitHub 上，如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/14d542f0-2be1-44b5-b8a8-b146219792b7.png)

有了 GitHub 存储库中的文件，我们现在可以访问[`packagist.org`](https://packagist.org)页面并提交我们的包：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/d39ee193-dbf3-4ca5-89d4-b45086c5ff40.png)

一旦检查完成，我们应该能够看到类似以下的屏幕：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/9d66c52e-1665-4599-9939-859311798b0f.png)

一旦我们点击提交按钮，我们应该能够看到类似以下的屏幕：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/f27f0f7d-a6b2-48e9-b585-64c8897a249d.png)

我们现在应该能够通过运行以下控制台命令在任何项目中使用`foggyline/mp7`包：

```php
composer require foggyline/mp7:dev-master

```

注意这里的`dev-master`后缀。我们的包只被标记为`dev-master`。这是因为我们的[`github.com/ajzele/foggyline_mp7`](https://github.com/ajzele/foggyline_mp7)存储库上没有定义标签。

让我们继续给我们的存储库添加一个`v1.5`标签。我们可以通过运行以下控制台命令来完成：

```php
git tag -a v1.5 -m "my version 1.4" 648e31cc4a
git push origin v1.5

```

由于我们要给已经提交的提交添加标签，我们使用提交 ID `648e31cc4a` 来附加标签。一旦标签被推送到 GitHub 存储库，我们可以回到 Packagist 并在包编辑屏幕上点击更新按钮。这应该立即更新包版本列表，显示`v1.5`：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/85531944-605f-43c7-ab7f-39865a1256e9.png)

假设我们有一个项目目录，里面只有一个`index.php`文件，我们应该能够通过运行以下控制台命令来使用`foggyline/mp7`包：

```php
composer require foggyline/mp7

```

这应该导致一个目录结构，如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/9a7b2a1d-4f9b-4334-9749-21b572c0d470.png)

然后，`index.php`脚本就可以通过包含`/vendor/autoload.php`来开始使用我们的 MP7 库。

# 摘要

在本章中，我们看了一下 PHP 最流行的包管理器 Composer。我们看到了如何轻松地向我们的应用程序添加第三方包，以及如何使用 Packagist 存储库分发我们自己的包。许多现代 PHP 应用程序依赖 Composer，这就是为什么了解如何充分利用它对我们日常开发工作至关重要。

接下来，我们将看一下适用于 PHP 应用程序的测试类型。


# 第十五章：测试重要部分

编写高质量的软件是一项技术上具有挑战性和昂贵的活动。技术上具有挑战性的部分来自于需要理解和实现多种类型的应用程序测试。而昂贵的部分来自于适当的测试通常产生的代码比我们正在测试的代码更多，这意味着需要更多的时间来完成工作。

与开发人员不同，企业不太关心技术细节，而更关心降低成本。这就是两个世界在质量的代价上发生冲突的地方。虽然两者都理解“技术债务”概念的影响，但很少有人认真对待。网页应用程序是这种冲突的一个很好的例子。足够好的用户体验和设计通常足以满足股东的需求，而软件的许多内部和远离视线的部分则被忽视。

查看有关技术债务概念的更多信息，请访问[`en.wikipedia.org/wiki/Technical_debt`](https://en.wikipedia.org/wiki/Technical_debt)。

我们可以对应用程序应用许多类型的测试，其中一些如下：

+   单元测试

+   功能测试

+   性能测试

+   可用性测试

+   验收测试

说一个比另一个更重要是不公平的，因为每个都涉及应用程序的一个非常不同的部分。PHP 生态系统和工具的当前状态表明“单元”、“功能”和“性能测试”是其中流行的一些。在本章中，我们将快速查看一些适应这些测试类型的工具和库：

+   PHPUnit

+   Behat

+   phpspec

+   jMeter

典型程序员认为经过彻底测试的软件通常只执行了大约 55 到 60％的逻辑路径。使用自动化支持，如覆盖分析器，可以将其提高到大约 85 到 90％。几乎不可能以 100％的逻辑路径测试软件。

- 《软件工程的事实与谬误》一书。

# PHPUnit

PHPUnit 是单元测试框架的代表，其总体思想是为必须满足的孤立代码提供严格的合同。这段代码就是我们所谓的“单元”，在 PHP 中对应于类及其方法。使用“断言”功能，PHPUnit 框架验证这些单元的行为是否符合预期。单元测试的好处在于，它早期发现问题有助于减轻可能不明显的“复合”或“下游”错误。程序的可能路径越多，单元测试覆盖的越好。

# 设置 PHPUnit

PHPUnit 可以作为一个临时命名的“工具”或“库”安装。实际上两者是相同的，只是在安装和使用方式上有所不同。“工具”版本实际上只是一个我们可以通过控制台运行的 PHP“phar”存档，然后提供一组我们可以全局执行的控制台命令。“库”版本则是一组作为 Composer 包打包的 PHPUnit 库，以及一个被转储到项目的`vendor/bin/`目录下的二进制文件。

假设我们正在使用 Ubuntu 16.10（Yakkety Yak）安装，通过以下命令安装 PHPUnit 作为工具非常容易：

```php
wget https://phar.phpunit.de/phpunit.phar
chmod +x phpunit.phar
sudo mv phpunit.phar /usr/local/bin/phpunit
phpunit --version

```

这应该给我们最终的输出，就像以下屏幕截图一样：

！[](assets/04a8301f-9170-475d-9cf6-9f06da6b1be5.png)

PHPUnit 成为一个系统范围内可访问的控制台工具，与任何特定项目无关。

将 PHPUnit 安装为库就像在项目根目录中运行以下控制台命令一样容易：

```php
composer require phpunit/phpunit

```

这应该给我们最终的输出，就像以下屏幕截图一样：

！[](assets/c9cf5e36-7f37-4e8f-be79-813ff7590a43.png)

这将在我们项目的`vendor/phpunit/`目录中安装所有 PHPUnit 库文件，以及在`vendor/bin/`目录下的`phpunit`可执行文件。

# 设置一个示例应用程序

在我们开始编写一些 PHPUnit 测试脚本之前，让我们继续创建一个非常简单的应用程序，仅由几个文件组成。这将使我们能够专注于稍后编写测试的本质。

**测试驱动开发**（**TDD**），例如使用 PHPUnit 进行的开发，鼓励在实现之前编写测试。这样，测试设置了功能的期望，而不是相反。这种方法需要一定水平的经验和纪律，这可能不适合 PHPUnit 的新手。

假设我们正在制作网购功能的一部分，因此首先处理产品和类别实体。我们首先要处理的类是`Product`模型。我们将通过创建`src\Foggyline\Catalog\Model\Product.php`文件来实现这一点，其内容如下：

```php
<?php declare(strict_types=1); namespace Foggyline\Catalog\Model; class Product {
  protected $id;
  protected $title;
  protected $price;
  protected $taxRate;    public function __construct(string $id, string $title, float $price, int $taxRate)
 {  $this->id = $id;
  $this->title = $title;
  $this->price = $price;
  $this->taxRate = $taxRate;
 }    public function getId(): string
 {  return $this->id;
 }  public function getTitle(): string
 {  return $this->title;
 }    public function getPrice(): float
 {  return $this->price;
 }    public function getTaxRate(): int
 {  return $this->taxRate;
 } }

```

`Product`类依赖于构造函数来设置产品的 ID、标题、价格和税率。除此之外，该类没有实际的逻辑，除了简单的 getter 方法。有了`Product`类，让我们继续创建一个`Category`类。我们将把它添加到`src\Foggyline\Catalog\Model\Category.php`文件中，其内容如下：

```php
<?php   declare(strict_types=1);   namespace Foggyline\Catalog\Model; class Category {
  protected $title;
  protected $products;    public function __construct(string $title, array $products)
 {  $this->title = $title;
  $this->products = $products;
 }  public function getTitle(): string
 {  return $this->title;
 }    public function getProducts(): array
  {
  return $this->products;
 } } 

```

`Category`类依赖于构造函数来设置类别标题及其产品。除此之外，它没有其他逻辑，除了两个 getter 方法，这些方法仅返回通过构造函数设置的值。

为了增加一些调味料，为了测试目的，让我们继续创建一个虚拟的`Layer`类，作为`src\Foggyline\Catalog\Model\Layer.php`文件的一部分，其内容如下：

```php
<?php namespace Foggyline\Catalog\Model;   // Just a dummy class, for testing purpose class Layer {
  public function dummy()
 {  $time = time();
  sleep(2);
  $time = time() - $time;
  return $time;
 } }

```

我们将仅将这个类用作示例，稍后进行代码覆盖分析。

有了`Product`和`Category`模型，让我们继续创建`Block\Category\View`类，作为`src\Foggyline\Catalog\Block\Category\View.php`文件的一部分，其内容如下：

```php
<?php   declare(strict_types=1);   namespace Foggyline\Catalog\Block\Category;   use Foggyline\Catalog\Model\Category; class View {
  protected $category;    public function __construct(Category $category)
 {  $this->category = $category;
 }    public function render(): string
 {  $products = '';

  foreach ($this->category->getProducts() as $product) {
  if ($product instanceof \Foggyline\Catalog\Model\Product) {
  $products .= '<div class="product">
 <h1 class="product-title">' . $product->getTitle() . '</h1>
 <div class="product-price">' . number_format($product->getPrice(), 2, ',', '.') . '</h1>
 </div>';
 } }    return '<div class="category">
 <h1 class="category-title">' . $this->category->getTitle() . '</h1>
 <div class="category-products">' . $products . '</div>
 </div>';
 } }

```

我们使用`render()`方法来渲染整个类别页面。页面本身包括类别标题，以及所有产品及其各自的标题和价格的容器。现在我们已经概述了我们真正基本的应用程序类，让我们在`autoload.php`文件中添加一个简单的 PSR4 类型加载器，其内容如下：

```php
<?php   $loader = require __DIR__ . '/vendor/autoload.php'; $loader->addPsr4('Foggyline\\', __DIR__ . '/src/Foggyline');

```

最后，我们将设置应用程序的入口点作为`index.php`文件的一部分，其内容如下：

```php
<?php   require __DIR__ . '/autoload.php';    use Foggyline\Catalog\Model\Product; use Foggyline\Catalog\Model\Category; use Foggyline\Catalog\Block\Category\View as CategoryView;   $category = new Category('Laptops', [
  new Product('RL', 'Red Laptop', 1499.99, 25),
  new Product('YL', 'Yellow Laptop', 2499.99, 25),
  new Product('BL', 'Blue Laptop', 3499.99, 25), ]);   $categoryView = new CategoryView($category); echo $categoryView->render();

```

我们将在其他类型的测试中使用这个非常简单的应用程序，因此值得记住它的文件和结构。

# 编写测试

开始编写 PHPUnit 测试需要掌握一些基本概念，例如以下内容：

+   **setUp()方法**：类似于构造函数，这是我们创建针对测试执行的对象的地方。

+   **tearDown()方法**：类似于析构函数，这是我们清理针对测试执行的对象的地方。

+   **test*()方法**：每个公共方法的名称以 test 开头，例如`testSomething()`，`testItAgain()`等，被视为单个测试。通过在方法的文档块中添加`@test`注释也可以实现相同的效果；尽管这似乎是一个不太常用的情况。

+   **@depends 注释**：这允许表达测试方法之间的依赖关系。

+   **断言**：这是 PHPUnit 的核心，这组方法允许我们推理正确性。

`vendor\phpunit\phpunit\src\Framework\Assert\Functions.php`文件包含了大量的`assert*`函数声明，例如`assertEquals()`，`assertContains()`，`assertLessThan()`等，总共超过 90 个不同的断言函数。

有了这些，让我们继续编写`src\Foggyline\Catalog\Test\Unit\Model\ProductTest.php`文件，其内容如下：

```php
<?php   namespace Foggyline\Catalog\Test\Unit\Model;   use PHPUnit\Framework\TestCase; use Foggyline\Catalog\Model\Product;   class ProductTest extends TestCase {
  protected $product;    public function setUp()
 {  $this->product = new Product('SL', 'Silver Laptop', 4599.99, 25);
 }    public function testTitle()
 {  $this->assertEquals(
  'Silver Laptop',
  $this->product->getTitle()
 ); }  public function testPrice()
 {  $this->assertEquals(
  4599.99,
  $this->product->getPrice()
 ); } }

```

我们的`ProductTest`类使用`setUp()`方法来设置`Product`类的实例。然后，两个`test*()`方法使用 PHPUnit 内置的`assertEquals()`方法来测试产品标题和价格的值。

然后，我们添加了`src\Foggyline\Catalog\Test\Unit\Model\CategoryTest.php`文件，其内容如下：

```php
<?php   namespace Foggyline\Catalog\Test\Unit\Model;   use PHPUnit\Framework\TestCase; use Foggyline\Catalog\Model\Product; use Foggyline\Catalog\Model\Category;   class CategoryTest extends TestCase {
  protected $category;    public function setUp()
 {  $this->category = new Category('Laptops', [
  new Product('TRL', 'Test Red Laptop', 1499.99, 25),
  new Product('TYL', 'Test Yellow Laptop', 2499.99, 25),
 ]); }    public function testTotalProductsCount()
 {  $this->assertCount(2, $this->category->getProducts());
 }  public function testTitle()
 {  $this->assertEquals('Laptops', $this->category->getTitle());
 } }

```

我们的`CategoryTest`类使用`setUp()`方法来设置`Category`类的实例，以及传递给`Category`类构造函数的两个产品。然后，两个`test*()`方法使用 PHPUnit 内置的`assertCount()`和`assertEquals()`方法来测试实例化的值。

然后，我们添加了`src\Foggyline\Catalog\Test\Unit\Block\Category\ViewTest.php`文件，其内容如下：

```php
<?php   namespace Foggyline\Catalog\Test\Unit\Block\Category;   use PHPUnit\Framework\TestCase; use Foggyline\Catalog\Model\Product; use Foggyline\Catalog\Model\Category; use Foggyline\Catalog\Block\Category\View as CategoryView;   class ViewTest extends TestCase {
  protected $category;
  protected $categoryView;    public function setUp()
 {  $this->category = new Category('Laptops', [
  new Product('TRL', 'Test Red Laptop', 1499.99, 25),
  new Product('TYL', 'Test Yellow Laptop', 2499.99, 25),
 ]);  $this->categoryView = new CategoryView($this->category);
 }  public function testCategoryTitle()
 {  $this->assertContains(
  '<h1 class="category-title">Laptops',
  $this->categoryView->render()
 ); }    public function testProductsContainer()
 {  $this->assertContains(
  '<h1 class="product-title">Test Yellow',
  $this->categoryView->render()
 ); } }

```

我们的`ViewTest`类使用`setUp()`方法来设置`Category`类的实例，以及传递给`Category`类构造函数的两个产品。然后，两个`test*()`方法使用 PHPUnit 内置的`assertContains()`方法来测试通过类别视图`render()`方法调用返回的值的存在。

然后，我们添加了`phpunit.xml`文件，其内容如下：

```php
<phpunit bootstrap="autoload.php">
 <testsuites>
 <testsuite name="foggyline">
 <directory>src/Foggyline/*/Test/Unit/*</directory>
 </testsuite>
 </testsuites>
</phpunit>

```

`phpunit.xml`配置文件支持相当丰富的选项列表。使用 PHPUnit 元素的 bootstrap 属性，我们指示 PHPUnit 工具在运行测试之前加载`autoload.php`文件。这确保我们的 PSR4 自动加载程序将启动，并且我们的测试类将在`src/Foggyline`目录中看到我们的类。我们在`testsuites`中定义的`foggyline`测试套件使用 directory 选项以正则表达式形式指定我们单元测试的路径。我们使用的路径是这样的，以便捡起`src/Foggyline/Catalog/Test/Unit/`和可能`src/Foggyline/Checkout/Test/Unit/`目录下的所有文件。

查看[`phpunit.de/manual/current/en/appendixes.configuration.html`](https://phpunit.de/manual/current/en/appendixes.configuration.html)以获取有关`phpunit.xml`配置选项的更多信息。

# 执行测试

运行我们刚刚编写的测试套件就像在项目根目录中执行`phpunit`命令一样简单。

执行时，`phpunit`将查找`phpunit.xml`文件并相应地采取行动。这意味着`phpunit`将知道在哪里查找测试文件。成功执行的测试显示如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/371e6760-3391-4cf7-9c0d-91f1ba2ae855.png)

然而，未成功执行的测试显示如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/e1bdf825-0c30-4e10-bdc1-a40343b12fb6.png)

我们可以轻松修改其中一个测试类，就像我们之前对`ViewTest`所做的那样，以触发并观察`phpunit`对失败的反应。

# 代码覆盖率

PHPUnit 的一个很棒的功能是其代码覆盖率报告功能。我们可以通过扩展`phpunit.xml`文件轻松地将代码覆盖率添加到我们的测试套件中，如下所示：

```php
<phpunit bootstrap="autoload.php">
 <testsuites>
 <testsuite name="foggyline">
 <directory>src/Foggyline/*/Test/Unit/*</directory>
 </testsuite>
 </testsuites>
 <filter>
 <whitelist>
 <directory>src/Foggyline/</directory>
 <exclude>
 <file>src/config.php</file>
 <file>src/auth.php</file>
 <directory>src/Foggyline/*/Test/</directory>
 </exclude> 
 </whitelist>
 <logging>
 <log type="coverage-html" target="log/report" lowUpperBound="50" 
        highLowerBound="80"/>
 </logging>
 </filter>
</phpunit>

```

在这里，我们添加了`filter`元素，还有额外的`whitelist`和`logging`元素。现在我们可以再次触发测试，但是，这次稍微修改了命令，如下所示：

```php
phpunit --coverage-html log/report

```

这应该给我们最终的输出，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/4d9fe7f1-a837-4d1c-b5c1-44817ffd4ced.png)

`log/report`目录现在应该填满了 HTML 报告文件。如果我们将其暴露给浏览器，我们可以看到一个生成良好的报告，其中包含有关我们代码库的有价值的信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/b05dae90-7045-4860-b173-4e4b77db6144.png)

前面的屏幕截图显示了`src/Foggyline/Catalog/`目录结构中的代码覆盖率百分比。进一步深入到`Model`目录，我们看到我们的`Layer`类的代码覆盖率为 0%，这是预期的，因为我们还没有为它编写任何测试：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/55600582-e0c2-488f-afd6-7a0f177a8f85.png)

进一步深入到实际的`Product`类本身，我们可以看到 PHPUnit 代码覆盖概述了我们的测试覆盖的每一行代码。

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/968f95fa-563d-412a-92c7-c1a14a8fe066.png)

直接查看实际的`Layer`类，我们可以清楚地看到这个类中没有任何代码覆盖：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/bdf1bb00-292b-4d00-b8a7-fd7356d68d5b.png)

代码覆盖提供了有关我们用测试覆盖的代码量的宝贵的视觉和统计信息。尽管这些信息很容易被误解，但拥有 100%的代码覆盖绝不是我们个别测试质量的衡量标准。编写质量测试需要编写者，也就是开发人员，清楚了解单元测试的确切内容。可以说，我们可以很容易地实现 100%的代码覆盖率，通过 100%的测试，但仍然未能解决某些测试用例或逻辑路径。

# Behat

Behat 是一个基于**行为驱动开发**（**BDD**）概念的开源免费测试框架。包括 Behat 在内的 BDD 框架的巨大好处是，大部分功能文档都被倾入到我们最终测试的实际用户故事中。也就是说，在某种程度上，文档本身就成为了测试。

# 设置 Behat

与 PHPUnit 类似，Behat 可以安装为工具和库。工具版本是`.phar`存档，我们可以从官方 GitHub 存储库下载，而库版本则打包为 Composer 包。

假设我们正在使用 Ubuntu 16.10（Yakkety Yak）安装，通过以下命令安装 Behat 作为工具很容易：

```php
wget https://github.com/Behat/Behat/releases/download/v3.3.0/behat.phar
chmod +x behat.phar
sudo mv behat.phar /usr/local/bin/behat
behat --version 

```

这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/5f379429-0c4c-42f1-ac5b-7c579c618288.png)

将 Behat 安装为库就像在项目的根目录中运行以下控制台命令一样简单：

```php
composer require behat/behat

```

这应该给我们最终的输出，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/43752f4f-bd6e-462d-a7d7-15ffa43ff2dc.png)

Behat 库现在可以在`vendor/behat`目录下使用，其控制台工具可执行文件在`vendor/bin/behat`文件下。

# 设置一个示例应用程序

Behat 测试的示例应用程序与我们用于 PHPUnit 测试的相同。我们只需通过添加一个额外的类来扩展它。鉴于我们的 PHPUnit 示例应用程序中没有任何真正的“行为”，我们的扩展将包括一个虚拟的购物车功能。

因此，我们将添加`src\Foggyline\Checkout\Model\Cart.php`文件，其内容如下：

```php
<?php declare(strict_types=1);   namespace Foggyline\Checkout\Model;   class Cart implements \Countable {
  protected $productQtyMapping = [];    public function addProduct(\Foggyline\Catalog\Model\Product $product, int $qty): self
  {
  $this->productQtyMapping[$product->getId()]['product'] = $product;
  $this->productQtyMapping[$product->getId()]['qty'] = $qty;
  return $this;
 }  public function removeProduct($productId): self
  {
  if (isset($this->productQtyMapping[$productId])) {
  unset($this->productQtyMapping[$productId]);
 }    return $this;
 }    public function getSubtotal()
 {  $subtotal = 0.0;    foreach ($this->productQtyMapping as $mapping) {
  $subtotal += ($mapping['qty'] * $mapping['product']->getPrice());
 }    return $subtotal;
 }    public function getTotal()
 {  $total = 0.0;    foreach ($this->productQtyMapping as $mapping) {
  $total += ($mapping['qty'] * ($mapping['product']->getPrice() + ($mapping['product']->getPrice() * ($mapping['product']->getTaxRate() / 100))));
 }    return $total;
 }    public function count()
 {  return count($this->productQtyMapping);
 } }

```

保留原始的`index.php`文件不变，让我们继续创建`index_2.php`文件，其内容如下：

```php
<?php   $loader = require __DIR__ . '/vendor/autoload.php'; $loader->addPsr4('Foggyline\\', __DIR__ . '/src/Foggyline'); use Foggyline\Catalog\Model\Product; use \Foggyline\Checkout\Model\Cart;   $cart = new Cart(); $cart->addProduct(new Product('RL', 'Red Laptop', 75.00, 25), 1); $cart->addProduct(new Product('YL', 'Yellow Laptop', 100.00, 25), 1); echo $cart->getSubtotal(), PHP_EOL; echo $cart->getTotal(), PHP_EOL;   $cart->removeProduct('YL'); echo $cart->getSubtotal(), PHP_EOL; echo $cart->getTotal(), PHP_EOL;

```

我们实际上不需要这个来进行测试，但这表明了我们的虚拟购物车如何被利用。

# 编写测试

开始编写 Behat 测试需要掌握一些基本概念，例如以下内容：

+   **Gherkin 语言**：这是一个空格、易读的、特定于业务的语言，用于描述行为，具有通过其*Given-When-Then*概念同时用于项目文档和自动化测试的能力。

+   **特性**：这是一个或多个场景的列表，保存在`*.feature`文件下。默认情况下，Behat 特性应存储在与我们的项目相关的`features/`目录中。

+   **场景**：这些是核心的 Gherkin 结构，由一个或多个步骤组成。

+   **步骤**：这些也被称为*Givens*、*Whens*和*Thens*。对于 Behat 来说，它们应该是不可区分的，但对于开发人员来说，它们应该是为了特定目的而精心选择的。*Given*步骤将系统置于已知状态，然后进行任何用户交互。*When*步骤描述用户执行的关键操作。*Then*步骤观察结果。

有了这些想法，让我们继续编写并启动我们的 Behat 测试。

`vendor\phpunit\phpunit\src\Framework\Assert\Functions.php`文件包含了大量的`asert*`函数声明，比如`assertEquals()`，`assertContains()`，`assertLessThan()`等，总共超过 90 个不同的断言函数。

在我们项目目录的根目录下，如果我们运行`behat --init`控制台命令，它将生成一个`features/`目录，并在其中生成一个`features/bootstrap/FeatureContext.php`文件，内容如下：

```php
<?php   use Behat\Behat\Context\Context; use Behat\Gherkin\Node\PyStringNode; use Behat\Gherkin\Node\TableNode; /**
 * Defines application features from the specific context. */ class FeatureContext implements Context {
  /**
 * Initializes context. * * Every scenario gets its own context instance. * You can also pass arbitrary arguments to the * context constructor through behat.yml. */  public function __construct()
 { } } 

```

新创建的`features/`目录是我们编写测试的地方。暂时忽略新生成的`FeatureContext`，让我们继续创建我们的第一个`.feature`。正如我们之前提到的，Behat 测试是用一种特殊格式称为**Gherkin**编写的。让我们继续编写我们的`features/checkout-cart.feature`文件如下：

```php
Feature: Checkout cart
  In order to buy products
  As a customer
  I need to be able to put products into a cart

  Rules:
  - Each product TAX rate is 25%
  - Delivery for basket under $100 is $10
  - Delivery for basket over $100 is $5

Scenario: Buying a single product under $100
Given there is a "Red Laptop", which costs $75.00 and has a tax rate of 25
When I add the "Red Laptop" to the cart
Then I should have 1 product in the cart
And the overall subtotal cart price should be $75.00
And the delivery cost should be $10.00
And the overall total cart price should be $103.75

Scenario: Buying two products over $100
Given there is a "Red Laptop", which costs $75.00 and has a tax rate of 25
And there is a "Yellow Laptop", which costs $100.00 and has a tax rate of 25
When I add the "Red Laptop" to the cart
And I add the "Yellow Laptop" to the cart
Then I should have 2 product in the cart
And the overall subtotal cart price should be $175.00
And the delivery cost should be $5.00
And the overall total cart price should be $223.75

```

我们可以看到`Given`，`When`和`Then`关键字被使用。然而，也有几个`And`的出现。当有几个`Given`，`When`和`Then`步骤时，我们可以自由使用额外的关键字，比如`And`或`But`来标记一个步骤，从而使我们的场景更流畅地阅读。Behat 不区分这些关键字；它们只是为了开发者进行区分和体验。

现在，我们可以更新我们的`FeatureContext`类与来自`checkout-cart.feature`的测试，也就是步骤。只需要运行以下命令，Behat 工具就会为我们完成这个过程：

```php
behat --dry-run --append-snippets

```

这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/2a34934f-93ba-4ab4-b84c-53f756ab8238.png)

执行此命令后，Behat 会自动将所有缺失的步骤方法附加到我们的`FeatureContext`类中，现在看起来像以下代码块：

```php
<?php   use Behat\Behat\Tester\Exception\PendingException; use Behat\Behat\Context\Context; use Behat\Gherkin\Node\PyStringNode; use Behat\Gherkin\Node\TableNode;   /**
 * Defines application features from the specific context. */ class FeatureContext implements Context {
  /**
 * Initializes context. * * Every scenario gets its own context instance. * You can also pass arbitrary arguments to the * context constructor through behat.yml. */  public function __construct()
 { }    /**
 * @Given there is a :arg1, which costs $:arg2 and has a tax rate of :arg3
 */  public function thereIsAWhichCostsAndHasATaxRateOf($arg1, $arg2, $arg3)
 {  throw new PendingException();
 }    /**
 * @When I add the :arg1 to the cart
 */  public function iAddTheToTheCart($arg1)
 {  throw new PendingException();
 }    /**
 * @Then I should have :arg1 product in the cart
 */  public function iShouldHaveProductInTheCart($arg1)
 {  throw new PendingException();
 }    /**
 * @Then the overall subtotal cart price should be $:arg1
 */  public function theOverallSubtotalCartPriceShouldBe($arg1)
 {  throw new PendingException();
 }    /**
 * @Then the delivery cost should be $:arg1
 */  public function theDeliveryCostShouldBe($arg1)
 {  throw new PendingException();
 }    /**
 * @Then the overall total cart price should be $:arg1
 */  public function theOverallTotalCartPriceShouldBe($arg1)
 {  throw new PendingException();
 } } 

```

现在，我们需要进入并编辑这些存根方法，以反映我们正在针对的类的行为。这意味着用适当的逻辑和断言替换所有的`throw new PendingException()`表达式：

```php
<?php $loader = require __DIR__ . '/../../vendor/autoload.php'; $loader->addPsr4('Foggyline\\', __DIR__ . '/../../src/Foggyline');   use Behat\Behat\Tester\Exception\PendingException; use Behat\Behat\Context\Context; use Behat\Gherkin\Node\PyStringNode; use Behat\Gherkin\Node\TableNode;   use Foggyline\Catalog\Model\Product; use \Foggyline\Checkout\Model\Cart; use \PHPUnit\Framework\Assert; /**
 * Defines application features from the specific context. */ class FeatureContext implements Context {
  protected $cart;
  protected $products = [];    /**
 * Initializes context. * * Every scenario gets its own context instance. * You can also pass arbitrary arguments to the * context constructor through behat.yml. */  public function __construct()
 {  $this->cart = new Cart();
 }    /**
 * @Given there is a :arg1, which costs $:arg2 and has a tax rate of :arg3
 */  public function thereIsAWhichCostsAndHasATaxRateOf($arg1, $arg2, $arg3)
 {  $this->products[$arg1] = new Product($arg1, $arg1, $arg2, $arg3);
 }    /**
 * @When I add the :arg1 to the cart
 */  public function iAddTheToTheCart($arg1)
 {  $this->cart->addProduct($this->products[$arg1], 1);
 }  /**
 * @Then I should have :arg1 product in the cart
 */  public function iShouldHaveProductInTheCart($arg1)
 { Assert::assertCount((int)$arg1, $this->cart);
 }    /**
 * @Then the overall subtotal cart price should be $:arg1
 */  public function theOverallSubtotalCartPriceShouldBe($arg1)
 { Assert::assertEquals($arg1, $this->cart->getSubtotal());
 }    /**
 * @Then the delivery cost should be $:arg1
 */  public function theDeliveryCostShouldBe($arg1)
 { Assert::assertEquals($arg1, $this->cart->getDeliveryCost());
 }    /**
 * @Then the overall total cart price should be $:arg1
 */  public function theOverallTotalCartPriceShouldBe($arg1)
 { Assert::assertEquals($arg1, $this->cart->getTotal());
 } } 

```

注意使用 PHPUnit 框架进行断言。使用 Behat 并不意味着我们必须停止使用 PHPUnit 库。不重用 PHPUnit 中可用的大量断言函数将是一种遗憾。将其添加到项目中很容易，如下代码所示：

```php
composer require phpunit/phpunit

```

# 执行测试

一旦我们解决了`features\bootstrap\FeatureContext.php`文件中的所有存根方法，我们只需在项目根目录中运行`behat`命令来执行测试。这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/44c110d7-c8bc-4560-9bbc-aec1b47d8a2f.png)

输出表明一共有 2 个场景和 14 个不同的步骤，所有这些步骤都经过确认是有效的。

# phpspec

像 Behat 一样，**phpspec**是一个基于 BDD 概念的开源免费测试框架。然而，它的测试方法与 Behat 大不相同；我们甚至可以说它处于 PHPUnit 和 Behat 之间的某个位置。与 Behat 不同，phpspec 不使用 Gherkin 格式的故事来描述它的测试。这样做，phpspec 将重点放在内部应用行为上，而不是外部行为。与 PHPUnit 类似，phpspec 允许我们实例化对象，调用它的方法，并对结果进行各种断言。它与其他地方的不同之处在于它的“考虑规范”，而不是“考虑测试”的方法。

# 设置 phpspec

与 PHPUnit 和 Behat 一样，phpspec 可以作为一个工具和一个库安装。工具版本是`.phar`存档，我们可以从官方 GitHub 存储库下载它，而库版本则打包为 Composer 包。

假设我们使用的是 Ubuntu 16.10（Yakkety Yak）安装，安装 phpspec 作为一个工具很容易，如下所示的命令：

```php
wget https://github.com/phpspec/phpspec/releases/download/3.2.3/phpspec.phar
chmod +x phpspec.phar
sudo mv phpspec.phar /usr/local/bin/phpspec
phpspec --version

```

这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/ef2066ec-088b-48de-b2a5-7206e8191db5.png)

将 phpspec 安装为库就像在项目的根目录中运行以下控制台命令一样容易：

```php
composer require phpspec/phpspec

```

这应该给我们最终的输出，看起来像以下的截图：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/24ee6529-fe86-49f2-9f22-3870641305eb.png)

phpspec 库现在可以在`vendor/phpspec`目录下使用，并且其控制台工具可以在`vendor/bin/phpspec`文件下执行。

# 编写测试

开始编写 phpspec 测试需要掌握一些基本概念，例如：

+   **it_*()和 its_*()方法**：这个对象行为由单个示例组成，每个示例都标有`it_*()`或`its_*()`方法。我们可以在单个规范中定义一个或多个这些方法。每个定义的方法在运行测试时都会触发。

+   **匹配器方法**：这些类似于 PHPUnit 中的断言。它们描述了对象应该如何行为。

+   **对象构造方法**：我们在 phpspec 中描述的每个对象都不是一个单独的变量，而是`$this`。然而，有时获取适当的`$this`变量需要管理构造函数参数。这就是`beConstructedWith()`、`beConstructedThrough()`、`let()`和`letGo()`方法派上用场的地方。

+   **let()方法**：这在每个示例之前运行。

+   **letGo()方法**：这在每个示例之后运行。

匹配器可能是我们接触最多的内容，因此值得知道 phpspec 中有几种不同的匹配器，它们都实现了`src\PhpSpec\Matcher\Matcher.php`文件中声明的`Matcher`接口：

```php
<?php namespace PhpSpec\Matcher; interface Matcher {
  public function supports($name, $subject, array $arguments);
  public function positiveMatch($name, $subject, array $arguments);
  public function negativeMatch($name, $subject, array $arguments);
  public function getPriority(); } 

```

使用`phpspec describe`命令，我们可以为我们即将编写的现有或新的具体类之一创建规范。由于我们已经设置了项目，让我们继续为我们的`Cart`和`Product`类生成规范。

我们将通过在项目的根目录中运行以下两个命令来实现：

```php
phpspec describe Foggyline/Checkout/Model/Cart
phpspec describe Foggyline/Catalog/Model/Product

```

第一条命令生成了`spec/Foggyline/Checkout/Model/CartSpec.php`文件，其初始内容如下：

```php
<?php namespace spec\Foggyline\Checkout\Model; use Foggyline\Checkout\Model\Cart; use PhpSpec\ObjectBehavior; use Prophecy\Argument;   class CartSpec extends ObjectBehavior {
  function it_is_initializable()
 {  $this->shouldHaveType(Cart::class);
 } }

```

第二条命令生成了`spec/Foggyline/Catalog/Model/ProductSpec.php`文件，其初始内容如下：

```php
<?php namespace spec\Foggyline\Catalog\Model;   use Foggyline\Catalog\Model\Product; use PhpSpec\ObjectBehavior; use Prophecy\Argument; class ProductSpec extends ObjectBehavior {
  function it_is_initializable()
 {  $this->shouldHaveType(Product::class);
 } }

```

生成的`CartSpec`和`ProductSpec`类几乎相同。区别在于它们通过`shouldHaveType()`方法调用引用的具体类。接下来，我们将尝试仅为`Cart`和`Product`模型编写一些简单的测试。也就是说，让我们继续修改我们的`CartSpec`和`ProductSpec`类，以反映匹配器的使用：`it_*()`和`its_*()`函数。

我们将使用以下内容修改`spec\Foggyline\Checkout\Model\CartSpec.php`文件：

```php
<?php   namespace spec\Foggyline\Checkout\Model;   use Foggyline\Checkout\Model\Cart; use PhpSpec\ObjectBehavior; use Prophecy\Argument; use Foggyline\Catalog\Model\Product;   class CartSpec extends ObjectBehavior {
  function it_is_initializable()
 {  $this->shouldHaveType(Cart::class);
 }    function it_adds_single_product_to_cart()
 {  $this->addProduct(
  new Product('YL', 'Yellow Laptop', 1499.99, 25),
  2
  );    $this->count()->shouldBeLike(1);
 }    function it_adds_two_products_to_cart()
 {  $this->addProduct(
  new Product('YL', 'Yellow Laptop', 1499.99, 25),
  2
  );

  $this->addProduct(
  new Product('RL', 'Red Laptop', 2499.99, 25),
  2
  );

  $this->count()->shouldBeLike(2);
 } } 

```

我们将修改`spec\Foggyline\Catalog\Model\ProductSpec.php`文件，内容如下：

```php
<?php   namespace spec\Foggyline\Catalog\Model;   use Foggyline\Catalog\Model\Product; use PhpSpec\ObjectBehavior; use Prophecy\Argument;   class ProductSpec extends ObjectBehavior {
  function it_is_initializable()
 {  $this->shouldHaveType(Product::class);
 }  function let()
 {  $this->beConstructedWith(
  'YL', 'Yellow Laptop', 1499.99, 25
  );
 }    function its_price_should_be_like()
 {  $this->getPrice()->shouldBeLike(1499.99);
 }    function its_title_should_be_like()
 {  $this->getTitle()->shouldBeLike('Yellow Laptop');
 } } 

```

在这里，我们正在使用`let()`方法，因为它会在任何`it_*()`或`its_*()`方法执行之前触发。在`let()`方法中，我们使用通常传递给`new Product(...)`表达式的参数调用`beConstructedWith()`。这样就构建了我们的产品实例，并允许所有`it_*()`或`its_*()`方法成功执行。

查看[`www.phpspec.net/en/stable/manual/introduction.html`](http://www.phpspec.net/en/stable/manual/introduction.html)以获取有关高级 phpspec 概念的更多信息。

# 执行测试

此时仅运行`phpspec run`命令可能会失败，并显示类...不存在的消息，因为 phpspec 默认假定存在 PSR-0 映射。为了能够使用到目前为止我们所做的应用程序，我们需要告诉 phpspec 包括我们的`src/Foggyline/*`类。我们可以通过`phpspec.yml`配置文件或使用`--bootstrap`选项来实现。由于我们已经创建了`autoload.php`文件，让我们继续通过引导该文件来运行 phpspec：

```php
phpspec run --bootstrap=autoload.php

```

这将生成以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/b59deaed-e5a6-4198-a326-81ec14e65c38.png)

我们已经使用`phpspec describe`命令涉及了这两个规范现有的类。我们可以轻松地将不存在的类名传递给相同的命令，如下例所示：

```php
phpspec describe Foggyline/Checkout/Model/Guest/Cart

```

`Guest\Cart`类实际上并不存在于我们的`src/`目录中。phpspec 创建`spec/Foggyline/Checkout/Model/Guest/CartSpec.php`规范文件时没有问题，就像它为`Cart`和`Product`做的那样。然而，现在运行 phpspec 描述会引发一个类...不存在的错误消息，以及交互式生成器，如下输出所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/eebb8e02-8603-49e6-83d0-34ea130bd066.png)

因此，`src\Foggyline\Checkout\Model\Guest\Cart.php`文件还会生成，内容如下：

```php
<?php   namespace Foggyline\Checkout\Model\Guest; class Cart { } 

```

虽然这些都是简单的例子，但它表明 phpspec 可以双向工作：

+   根据现有具体类创建规范

+   根据规范生成具体类

现在运行我们的测试应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/76813f42-6a63-4d83-8854-b19eb771672d.png)

现在，让我们故意通过将`spec\Foggyline\Catalog\Model\ProductSpec.php`的`its_title_should_be_like()`方法更改为以下代码来失败一个测试：

```php
$this->getTitle()->shouldBeLike('Yellow');

```

现在运行测试应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/1a5261f7-36c4-4c25-9872-1793b9ebed46.png)

关于 phpspec 还有很多要说的。像存根、模拟、间谍、模板和扩展等东西进一步丰富了我们的 phpspec 测试体验。然而，本节重点介绍了基础知识，以便让我们开始。

# jMeter

Apache jMeter 是一个用于负载和性能测试的免费开源应用程序。jMeter 的功能跨越了许多不同的应用程序、服务器和协议类型。在 Web 应用程序的上下文中，我们可能会倾向于将其与浏览器进行比较。然而，jMeter 在协议级别上使用 HTTP 和 https。它不渲染 HTML 或执行 JavaScript。虽然 jMeter 主要是一个 GUI 应用程序，但它可以轻松安装并在控制台模式下运行其测试。这使得它成为一个方便的选择工具，可以在 GUI 模式下快速构建我们的测试，然后稍后在服务器控制台上运行它们。

假设我们使用 Ubuntu 16.10（Yakkety Yak）安装，安装 jMeter 作为工具很容易，如下命令行所示：

```php
sudo apt-get -y install jmeter

```

然而，这可能不会给我们 jMeter 的最新版本，如果是这种情况，我们可以从官方 jMeter 下载页面([`jmeter.apache.org/download_jmeter.cgi`](http://jmeter.apache.org/download_jmeter.cgi))获取一个版本：

```php
wget http://ftp.carnet.hr/misc/apache//jmeter/binaries/apache-jmeter-3.2.tgz
tar -xf apache-jmeter-3.2.tgz

```

使用这种第二种安装方法，我们将在`apache-jmeter-3.2/bin/jmeter`找到 jMeter 可执行文件。

# 编写测试

在本章中，我们使用了一个简单的项目，在`src/Foggyline`目录中有几个类，以演示如何使用 PHPUnit、Behat 和 phpspec 进行测试。然而，这些测试无法完全满足这种类型的测试需求。由于我们没有任何 HTML 页面在浏览器中展示，我们使用 jMeter 的重点是启动一个简单的内置 Web 测试计划，以了解其组件以及如何稍后运行它。

为 Web 应用程序编写 jMeter 测试需要对几个关键概念有基本的理解，这些概念如下：

+   **线程组**：这定义了一组用户，他们针对我们的 Web 服务器执行特定的测试用例。GUI 允许我们控制几个线程组选项，如下截图所示：![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/2eea3707-2530-4ab6-951a-343829a39dbb.png)

+   **HTTP 请求默认值**：这设置了我们的 HTTP 请求控制器使用的默认值。GUI 允许我们控制几个 HTTP 请求默认选项，如下截图所示：![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/74b84049-bc01-4933-b3cb-206566e9b0bd.png)

+   **HTTP 请求**：这将 HTTP/HTTPS 请求发送到 Web 服务器。GUI 允许我们控制几个 HTTP 请求选项，如下截图所示：![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/3bcaef6d-9709-4d6a-a590-e845d143232f.png)

+   **HTTP Cookie 管理器**：这将存储和发送 cookie，就像 Web 浏览器一样。GUI 允许我们控制几个 HTTP Cookie 管理器选项，如下面的屏幕截图所示：![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/7e73cd63-0927-4f0e-8d4d-6d52285cd564.png)

+   **HTTP 头管理器**：这将添加或覆盖 HTTP 请求头。GUI 允许我们控制几个 HTTP 头管理器选项，如下面的屏幕截图所示：![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/4207e9af-8c39-469f-9d06-58d70086b159.png)

+   **图形结果**：这将生成一个图表，显示出所有样本时间。GUI 允许我们控制几个图形结果选项，如下面的屏幕截图所示：![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/6bb97a85-ff3e-46ab-ad0b-c237b2d243e8.png)

在生产负载测试期间，我们不应该使用图形结果监听器组件，因为它会消耗大量内存和 CPU 资源。

jMeter 的一个很棒的地方是它已经提供了几种不同的测试计划模板。我们可以通过以下步骤轻松生成 Web 测试计划：

1.  单击主应用程序菜单下的“文件” | “模板...”菜单，如下所示：![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/5bd910de-fbc2-4d8b-80cc-b51bac504e64.png)

这将触发“模板选择”屏幕：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/a8bf6e16-7286-4ceb-b0ec-d89552aaf584.png)

1.  单击“创建”按钮应该启动一个新的测试计划，如下面的屏幕截图所示：![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/56d47f1a-24c4-4d61-8e5e-2b150e90c8ed.png)

虽然测试本身已经很好了，但在运行之前让我们继续做一些修改：

1.  右键单击“查看结果树”，然后单击“删除”。

1.  右键单击“build-web-test-plan”，然后选择“添加” | “监听器” | “图形结果”，然后将“文件名”设置为`jmeter-result-tests.csv`，如下所示：![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/279110e8-eb42-481d-8e62-4de00d400eaf.png)

1.  单击“场景 1”，然后将“循环计数”编辑为值`2`：![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/0cbe46a8-b7b1-4dbf-8509-52a74c08acfa.png)

1.  在进行这些修改后，让我们单击主菜单下的“文件” | “保存”，并将我们的测试命名为`web-test-plan.jmx`。

我们的测试现在已经准备就绪。虽然这个测试本身不会在这种情况下对我们自己的服务器进行负载测试，而是[example.org](http://example.org)，但这个练习的价值在于理解如何通过 GUI 工具构建测试，通过控制台运行测试，并生成测试结果日志以供以后检查。

# 执行测试

通过控制台运行 jMeter 测试非常容易，如下命令所示：

```php
jmeter -n -t web-test-plan.jmx

```

`-n`参数，也适用于`--nongui`，表示在 nongui 模式下运行 JMeter。而`-t`参数，也适用于`--testfile`，表示要运行的 jmeter 测试(.jmx)文件。

生成的输出应该如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/6259fa47-a861-47f1-b4c5-bd77f2737c1f.png)

快速查看`jmeter-result-tests.csv`文件，可以看到捕获的结构和数据：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/7e4cb059-f943-48c3-8350-2ce468321f3c.png)

虽然这里演示的示例依赖于带有一些小修改的默认测试计划，但 Apache jMeter 的整体能力可以通过多种因素丰富整个测试体验。

# 摘要

在本章中，我们非常简要地涉及了一些最流行的 PHP 应用程序测试类型。测试驱动开发（TDD）和行为驱动开发包括其中非常重要的部分。幸运的是，PHP 生态系统提供了两个优秀的框架，PHPUnit 和 Behat，使这些类型的测试变得容易处理。尽管在根本上不同，PHPUnit 和 Behat 在某种意义上互补，它们确保我们的应用程序在从最小的功能单元到整体功能的逻辑结果方面都经过了测试。另一方面，phpspec 似乎处于这两者之间，试图以自己的统一方式解决这两个挑战。我们还简要介绍了 Apache jMeter，看到了使用简单的 Web 测试计划启动性能测试有多么容易。这使我们能够迈出重要的一步，并确认我们的应用程序不仅能够正常工作，而且能够快速到达用户的期望。

接下来，我们将更仔细地研究调试、跟踪和分析 PHP 应用程序。


# 第十六章：调试、跟踪和分析

诸如 PHPUnit 和 Behat 之类的工具采用自动化方法来测试软件。它们给了我们很大的保证，即我们的应用程序将按照测试结果交付。然而，测试本身，就像代码本身一样，也会存在缺陷。无论是错误的测试代码还是不完整的测试用例，为某些东西编写完整的测试并不一定意味着我们的代码在没有错误和性能优化的情况下是完美的。

往往在开发周期中会出现意想不到的错误和性能问题，只有偶尔在生产阶段才会重新出现。虽然完美的代码是一个遥不可及的概念，或者至少是一个有争议的话题，但我们确实可以做更多来提高软件的质量。为了完成软件测试的画布，需要在运行时对应用程序进行更系统的过程和深入的洞察。

这就是调试开始的地方。这个术语在开发人员中非常常见，通常指的是以下三个独特的过程：

+   调试：这是检测和修复应用程序错误的过程

+   跟踪：这是记录应用程序的时间顺序相关信息的过程

+   分析：这是记录应用程序性能相关信息的过程

虽然跟踪和分析过程在每次运行应用程序时会自动记录相关信息，但调试过程更多是手动进行的。

在本章中，我们将更仔细地看看处理调试、跟踪和分析功能的两个 PHP 扩展：

+   Xdebug

+   安装

+   调试

+   跟踪

+   分析

+   Zend Z-Ray

+   安装 Zend Server

+   设置虚拟主机

+   使用 Z-Ray

# Xdebug

Xdebug 是一个 PHP 扩展，提供了调试、跟踪和分析的功能。调试器组件使用 DBGp 调试协议来建立 PHP 脚本引擎和调试器 IDE 之间的通信。有几个 IDE 和文本编辑器支持 DBGp 调试协议；以下仅是一些较受欢迎的选择：

+   NetBeans：这是一个免费的跨平台 IDE，可以在[`netbeans.org/`](https://netbeans.org/)上找到

+   Eclipse PDT：这是一个免费的跨平台 IDE，可以在[`eclipse.org/pdt/`](https://eclipse.org/pdt/)上找到

+   PhpStorm：这是一个商业跨平台的 IDE，可以在[`www.jetbrains.com/phpstorm/`](https://www.jetbrains.com/phpstorm/)上找到

+   Zend Studio：这是一个商业跨平台的 IDE，可以在[`www.zend.com/en/products/studio`](http://www.zend.com/en/products/studio)上找到

+   Sublime Text 3：这是一个商业跨平台文本编辑器，可以在[`www.sublimetext.com/3`](https://www.sublimetext.com/3)上找到

+   Notepad++：这是一个免费的 Windows 平台文本编辑器，可以在[`notepad-plus-plus.org/`](https://notepad-plus-plus.org/)上找到

+   Vim：这是一个免费的跨平台文本编辑器，可以在[`www.vim.org/`](http://www.vim.org/)上找到

虽然 DBGp 调试协议支持可能看起来足够作为调试器选择因素，但真正区分这些 IDE 和文本编辑器的是它们对最新版本 PHP 的支持程度。

凭借其尖端的 PHP 支持和创新解决方案，PhpStorm 很可能是专业 PHP 开发人员中最受欢迎的商业选择。考虑到熟练的 PHP 开发人员的平均小时费率，工具的成本似乎并不昂贵，因为它拥有丰富的功能，可以加快开发工作。

为了更好地了解 Xdebug 的功能，让我们继续执行以下步骤：

1.  安装 LAMP 堆栈。

1.  安装 Xdebug 扩展。

1.  安装 NetBeans。

1.  拉取示例 PHP 应用程序作为我们调试的游乐场。

1.  配置调试。

1.  配置跟踪。

1.  配置分析。

# 安装

假设我们有一个全新的 Ubuntu 17.04（Zesty Zapus）安装，通过以下命令安装完整的 LAMP 堆栈和 Xdebug 扩展非常容易：

```php
apt-get update
apt-get -y install lamp-server^
apt-get -y install php-xdebug
sudo service apache2 restart

```

完成此过程后，打开浏览器中的[`localhost/index.html`](http://localhost/index.html)应该会给我们一个默认的 Apache 页面。现在，让我们继续进行一些权限更改：

```php
sudo adduser user_name www-data
sudo chown -R www-data:www-data /var/www
sudo chmod -R g+rwX /var/www

```

请确保将`user_name`替换为系统上实际用户的名称。

进行此权限更新的原因是为了使用户的 NetBeans IDE 能够访问`/var/www/html/`目录，这是我们项目将位于的地方。执行这些命令后，我们需要注销并重新登录，或者重新启动计算机以使权限生效。

现在我们可以在控制台上执行以下命令，然后打开`http://localhost/index.php`以确认 PHP 和 Xdebug 是否正常运行：

```php
rm /var/www/html/index.html
echo "<?php phpinfo(); ?>" > /var/www/html/index.php

```

这应该给我们一个输出，指示 Xdebug 扩展的存在，就像以下屏幕截图一样：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/eccf9606-0241-4f9e-96a6-fa9ecf9b0c0b.png)

到目前为止，我们只是安装了扩展，但实际上还没有启用其三个核心功能：调试、跟踪和分析。在进行调试之前，让我们快速安装 NetBeans IDE。这将使我们的调试工作更加容易。我们首先需要从[`netbeans.org/downloads/`](https://netbeans.org/downloads/)下载 PHP 的 NetBeans。下载并解压后，我们可以执行以下命令：

```php
chmod +x netbeans-8.2-php-linux-x64.sh
./netbeans-8.2-php-linux-x64.sh

```

值得注意的是，在这里使用 NetBeans IDE 是完全可选的。我们完全可以使用其他免费或商业解决方案。现在是打开 NetBeans IDE 的好时机；单击文件|新建项目|类别[PHP]|项目[具有现有源的 PHP 应用程序]，并将其指向我们的`/var/www/html/`目录，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/1318241c-5e05-4111-8605-f67714a168e9.png)

在“名称和位置”屏幕上填写所需数据后，单击“下一步”将我们带到“运行配置”设置：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/a010be45-cd7b-4363-a916-6f52df2e9012.png)

单击“完成”按钮完成项目设置，现在我们应该能够看到我们的`index.php`文件：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/b69cb494-43c0-499d-8ac6-50deeec4fac3.png)

最后，让我们执行以下控制台命令来引入我们的示例应用程序：

```php
rm /var/www/html/index.php
cd /var/www/html/
git init
git remote add origin git@github.com:ajzele/MPHP7-CH16.git
git pull origin master

```

NetBeans IDE 应该能够立即在其项目选项卡中捕捉到这些更改。到目前为止，我们实际上还没有进行任何与 Xdebug 的调试、跟踪或分析组件相关的配置或设置。我们只是安装了 LAMP 堆栈、Xdebug 本身、NetBeans IDE 并引入了示例应用程序。现在，让我们继续研究 Xdebug 的调试组件。

# 调试

Xdebug 的调试功能可以通过`xdebug.remote_enable=1`选项轻松启用。对于现代 PHP，通常会有一个特殊的`xdebug.ini`配置文件；否则，我们将编辑默认的`php.ini`文件。在我们的 Ubuntu 安装中，我们将其添加到`/etc/php/7.0/apache2/conf.d/20-xdebug.ini`文件中，如下所示：

```php
zend_extension=xdebug.so
xdebug.remote_enable=1

```

文件修改后，我们需要确保 Apache 服务器已重新启动：

```php
 service apache2 restart 

```

虽然`xdebug.remote_enable`是打开调试功能的必选项，但其他相关选项包括以下内容：

+   `xdebug.extended_info`

+   `xdebug.idekey`

+   `xdebug.remote_addr_header`

+   `xdebug.remote_autostart`

+   `xdebug.remote_connect_back`

+   `xdebug.remote_cookie_expire_time`

+   `xdebug.remote_enable`

+   `xdebug.remote_handler`

+   `xdebug.remote_host`

+   `xdebug.remote_log`

+   `xdebug.remote_mode`

+   `xdebug.remote_port`

有关各个调试器配置选项的补充信息可以在[`xdebug.org/docs/all_settings`](https://xdebug.org/docs/all_settings)下找到。

回到 NetBeans，我们可以把注意力转向调试工具栏：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/5339ee3b-1125-4ec1-a9bb-70729f9f2292.png)

当我们点击“调试项目”按钮时，NetBeans 会启动一个带有 URL `http://localhost/index.php?XDEBUG_SESSION_START=netbeans-xdebug` 的浏览器，并激活之前禁用的按钮。

“调试”工具栏上的按钮为我们提供了几个调试选项：

+   步入：这告诉调试器进入下一个函数调用并在那里中断。

+   步过：这告诉调试器执行下一个函数并在之后中断。

+   步出：这告诉调试器完成当前函数并在之后中断。

+   运行到光标：这有一点双重作用。当与启用的断点结合使用时，它会直接从一个断点跳转到另一个断点。当断点被禁用时，它会直接跳转到我们放置光标的行。因此，在调试过程开始后，我们可以自由地决定下一个断点的位置，只需将光标放在需要的地方。

“运行到光标”选项似乎是一个明智而直接的第一步。让我们继续并按照以下方式在我们的示例应用程序中设置几个断点：

+   `index.php`：这是六个断点的总数：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/383d01fb-eb1c-490c-8dbb-cf0755f27a14.png)

+   `src/Foggyline/Catalog/Model/Category.php`：这是一个断点的总数：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/d28d6691-ff54-4289-8b57-53baaaf0af70.png)

+   `src/Foggyline/Catalog/Block/Category/View.php`：这是一个断点的总数：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/1f760dfb-9037-4f75-adb2-39ff842b3c88.png)

以下步骤概述了仅使用“运行到光标”按钮进行调试的过程：

1.  点击“调试项目”。这会跳转到`index.php`的第 3 行，并记录以下内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/96a3c8a6-89c3-4e8d-b092-42f85d9758a4.png)

1.  点击“运行到光标”。这会跳转到`index.php`的第 11 行，并记录以下内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/60f7f629-e92e-46ed-ba8e-7ef2b068f307.png)

请注意，断点选项卡现在在`index.php:11`旁边显示了一个绿色箭头。

1.  点击“运行到光标”。这会跳转到`src/Foggyline/Catalog/Model/Category.php`的第 15 行，并记录以下内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/309c8e91-2001-4bde-863f-7ed7624fbfbe.png)

1.  点击“运行到光标”。这会跳转到`index.php`文件的第 15 行，并记录以下内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/160a741c-0c85-4cdf-b460-6a630ea7359d.png)

1.  点击“运行到光标”。这会跳转到`index.php`文件的第 18 行，并记录以下内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/1456b18b-d0bd-461d-b9aa-50d19a38e9f0.png)

1.  点击“运行到光标”。这会跳转到`index.php`文件的第 23 行，并记录以下内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/b881cbaa-6b2b-48b6-b1c0-df032f7d7569.png)

1.  点击“运行到光标”。这会跳转到`index.php`文件的第 25 行，并记录以下内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/f729916a-3732-4767-81fd-13cb4209bb1c.png)

1.  点击“运行到光标”。这会跳转到`src/Foggyline/Catalog/Block/Category/View.php`文件的第 22 行，并记录以下内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/f1db855c-81dc-4cd4-9a94-f36fe7d91391.png)

1.  点击“运行到光标”。这会跳转到`src/Foggyline/Catalog/Block/Category/View.php`文件的第 22 行，并记录以下内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/bbd40601-aad0-4028-aa27-c97b0cecf622.png)

1.  点击“运行到光标”。这会跳转到`src/Foggyline/Catalog/Block/Category/View.php`文件的第 22 行，并记录以下内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/b8aaa9d1-1405-4b1a-ae7c-85399275bfd3.png)

1.  点击“运行到光标”。这会跳转到`index.php`文件的第 27 行，并记录以下内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/bec133f0-fc15-430f-9d38-f8c6f1f213fa.png)

1.  点击“运行到光标”。这会在到达最后一个调试点时跳转到`index.php`文件的第 27 行，并记录以下内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/1814bfea-022c-4d64-ac2a-cee65048bf34.png)

现在我们可以点击“完成调试器会话”按钮。

在这个十二步过程中，我们可以清楚地观察到 IDE 的行为以及它成功记录的值。这使得我们可以轻松地针对代码的特定部分进行调试，并观察变量在调试过程中的变化。

请注意，在步骤 10 和 11 之间，我们从未看到变量标签记录第三个产品的值。这是因为变量在我们通过给定的调试断点之后记录，而在这种情况下，它将上下文从`View.php`类文件转移到`index.php`文件。这就是点击“步入”按钮可能会有用的地方，因为它可以使我们在第三个循环的执行期间在`while`的代码内部进一步深入，从而为第三个产品产生值。

我们应该鼓励混合使用所有调试选项，以便正确地达到并读取感兴趣的变量。

# 跟踪

Xdebug 的跟踪功能可以通过`xdebug.auto_trace=1`选项轻松启用。在我们的 Ubuntu 安装中，我们将其添加到`/etc/php/7.0/apache2/conf.d/20-xdebug.ini`文件中如下：

```php
zend_extension=xdebug.so
xdebug.remote_enable=1
xdebug.auto_trace=1

```

修改文件后，我们需要确保重新启动 Apache 服务器：

```php
 service apache2 restart 

```

`xdebug.auto_trace`是打开跟踪功能所需的选项，其他相关选项包括以下内容：

+   `xdebug.collect_assignments`

+   `xdebug.collect_includes`

+   `xdebug.collect_params`

+   `xdebug.collect_return`

+   `xdebug.show_mem_delta`

+   `xdebug.trace_enable_trigger`

+   `xdebug.trace_enable_trigger_value`

+   `xdebug.trace_format`

+   `xdebug.trace_options`

+   `xdebug.trace_output_dir`

+   `xdebug.trace_output_name`

+   `xdebug.var_display_max_children`

+   `xdebug.var_display_max_data`

+   `xdebug.var_display_max_depth`

有关个别*跟踪*配置选项的补充信息可以在[`xdebug.org/docs/execution_trace`](https://xdebug.org/docs/execution_trace)找到。

与我们从 IDE 或文本编辑器控制的调试功能不同，我们无法控制*跟踪*。默认情况下，每次运行应用程序时，*跟踪*功能会在`/tmp`目录下创建一个不同的`trace.%c`文件。在 Web 应用程序的上下文中，这意味着每次在浏览器中刷新页面时，跟踪功能都会为我们创建一个`trace.%c`文件。

我们特定的示例应用程序一旦执行，就会产生一个跟踪文件，就像以下截图一样：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/15d84c26-6ffa-4369-b0fa-e3f34da53eb9.png)

输出本身对于开发人员来说相对容易阅读和理解。当涉及到大型应用程序时，这可能会有些笨重，因为我们最终会得到一个大型的跟踪文件。但是，了解我们正在定位的代码部分，我们可以搜索文件并找到所需的代码出现。假设我们正在寻找代码中`number_format()`函数的使用。快速搜索`number_format`会指向`Category/View.php`的第 22 行，并附有执行时间。这对于整体调试工作是有价值的信息。

# 分析

Xdebug 的分析功能可以通过`xdebug.profiler_enable=1`选项轻松启用。在我们的 Ubuntu 安装中，我们将修改`/etc/php/7.0/apache2/conf.d/20-xdebug.ini`文件如下：

```php
zend_extension=xdebug.so
xdebug.remote_enable=1
xdebug.auto_trace=1
xdebug.profiler_enable=1

```

修改文件后，我们需要确保重新启动 Apache 服务器：

```php
 service apache2 restart 

```

`xdebug.profiler_enable`是打开分析功能所需的选项，其他相关选项包括以下内容：

+   `xdebug.profiler_aggregate`

+   `xdebug.profiler_append`

+   `xdebug.profiler_enable`

+   `xdebug.profiler_enable_trigger`

+   `xdebug.profiler_enable_trigger_value`

+   `xdebug.profiler_output_dir`

+   `xdebug.profiler_output_name`

有关个别分析器配置选项的补充信息可以在[`xdebug.org/docs/profiler`](https://xdebug.org/docs/profiler)找到。

与跟踪类似，我们无法从 IDE 或文本编辑器控制分析功能。默认情况下，每次执行应用程序时，分析功能会在`/tmp`目录下创建一个不同的`cachegrind.out.%p`文件。

我们特定的示例应用程序一旦执行，就会产生一个 cachegrind 文件，就像以下截图（部分输出）一样：

！[](assets/7994b47d-b7f8-41c6-aefa-dfff1832babd.png)

这里包含的信息远不如跟踪文件的可读性高，这没关系，因为两者针对不同类型的信息。cachegrind 文件可以被拉入到诸如 KCachegrind 或 QCacheGrind 之类的应用程序中，然后给我们提供了更加用户友好和可视化的捕获信息的表示：

！[](assets/b35fbde8-3648-4354-8feb-9a0519cc15f0.png)

cachegrind 文件输出提供了重要的与性能相关的信息。我们可以了解应用程序中使用的所有函数，按照在单个函数及其所有子函数中花费的时间进行排序。这使我们能够发现性能瓶颈，即使在毫秒级的时间范围内也是如此。

# Zend Z-Ray

*Rougue Wave Software*公司提供了一个名为 Zend Server 的商业 PHP 服务器。Zend Server 的一个突出特点是其**Z-Ray**扩展。Z-Ray 似乎类似于 Xdebug 的跟踪和分析功能，提供了全面的信息捕获和改进的用户体验。捕获的信息范围从执行时间、错误和警告、数据库查询和函数调用到请求信息。这些信息以一种类似于内置浏览器开发工具的形式提供，使开发人员能够在几秒钟内轻松地检索到关键的分析信息。

Z-Ray 扩展本身是免费的，可以独立于商业可用的 Zend Server 使用。我们可以像安装任何其他 PHP 扩展一样安装它。尽管在撰写本文时，独立的 Z-Ray 扩展仅适用于现在被认为过时的 PHP 5.5 和 5.6 版本。

# 安装 Zend Server

鉴于本书的目标是 PHP 7，我们将获取 Zend Server 的免费试用版本并安装。我们可以通过打开官方 Zend 页面并单击“下载免费试用”按钮来实现这一点：

！[](assets/78bc0714-fda2-4cc6-bc27-514b6edba1d2.png)

假设我们正在使用新的 Ubuntu 17.04 安装，Zend 的下载服务可能会为我们提供一个`tar.gz`存档下载：

！[](assets/5c77d43c-a0c3-46bb-9150-4ff70f482ff0.png)

下载并解压后，我们需要使用以下 PHP 版本参数触发`install_zs.sh`命令：

！[](assets/4a9e93ce-7098-4a5c-b9e5-91b87ae43cbf.png)

安装完成后，控制台会给出有关如何通过浏览器访问服务器管理界面的信息：

！[](assets/dbcbf25d-9fa9-4e37-9207-a732b8fe0d7e.png)

打开`https://localhost:10082/ZendServer`会触发启动 Zend Server 流程的许可协议步骤：

！[](assets/1b684742-0689-434e-ba02-6a91dece3d1c.png)

同意许可协议并单击“下一步”按钮将我们带到启动 Zend Server 流程的配置步骤：

！[](assets/b804dd91-9008-40be-8ae6-ad417d406653.png)

配置步骤提供了三个不同的选项：开发、生产（单服务器）和生产（创建或加入集群）。选择开发选项后，单击“下一步”按钮，将我们带到启动 Zend Server 流程的用户密码步骤：

！[](assets/711c548b-e761-4401-b191-bb96eae458c5.png)

在这里，我们提供管理员和开发者的用户密码。单击“下一步”按钮将我们带到启动 Zend Server 流程的摘要步骤：

！[](assets/454c67c5-5225-4b7e-97e0-e92390885e4e.png)

摘要步骤仅确认我们之前的选择和输入。单击“启动”按钮，我们完成了启动 Zend Server 流程，并进入了入门页面：

！[](assets/a6d9c047-c008-488c-a5b2-0293ad0df0b4.png)

Zend Server 提供了一个丰富的界面，用于管理运行服务器的几乎每个方面。从这里，我们可以管理虚拟主机、应用程序、作业队列、缓存、安全性和其他方面。在我们专注于 Z-Ray 功能之前，我们需要设置我们的测试应用程序。我们将使用与 Xdebug 相同的应用程序，映射到 `test.loc` 域上。

# 设置虚拟主机

我们首先通过在 `/etc/hosts` 文件中添加 `127.0.0.1 test.loc` 行来修改它。

现在将 `test.loc` 主机添加到 hosts 文件后，我们回到 Zend Server，并在应用程序 | 虚拟主机屏幕下点击“添加虚拟主机”按钮。这将带我们进入“添加虚拟主机”过程的“属性”步骤：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/25c18bc8-ea48-46cc-a414-0c26f7d68a9d.png)

在“虚拟主机名称”中输入 `test.loc`，在“端口”中输入 `80`。点击“下一步”按钮将带我们进入“添加虚拟主机”过程的“SSL 配置”步骤：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/b8d4b9cb-635d-4bca-a730-552deede5650.png)

为了简化操作，让我们只保留“此虚拟主机不使用 SSL”选项，并点击“下一步”按钮。这将带我们进入“添加虚拟主机”过程的“模板”步骤：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/f4785716-fab8-4310-ba39-3cecce5c75fa.png)

同样，让我们只保留“使用默认虚拟主机配置模板”选项，并点击“下一步”按钮。这将带我们进入“添加虚拟主机”过程的“摘要”步骤：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/20213edc-6f36-4a63-a667-c906062262d6.png)

完成虚拟主机设置后，我们点击“完成”按钮。我们的 `test.loc` 虚拟主机现在应该已经创建，显示如下细节：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/6b153af0-2a80-4500-a2fc-de9577bc6686.png)

我们新创建的虚拟主机使用的文档根目录指向 `/usr/local/zend/var/apps/http/test.loc/80/_docroot_` 目录。这就是我们将使用以下 `git clone` 命令转储我们的示例应用程序的地方：

```php
sudo git clone https://github.com/ajzele/MPHP7-CH16.git .

```

前面命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/40e9359f-ad68-4977-ab11-9afc62b6b9ca.png)

现在，如果我们在浏览器中访问 `http://test.loc` URL，应该会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/b552103b-6a82-4c6a-ad9e-27937067e63d.png)

# 使用 Z-Ray

现在我们的测试应用程序已经启动运行，我们终于可以专注于 Z-Ray 功能。在 Zend Server 管理界面中，在 Z-Ray | Mode 下，我们需要确保“Enabled”选项是活动的。现在，如果我们在浏览器中访问 `http://test.loc` URL，我们应该能够在页面底部看到 Z-Ray 工具栏：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/f6e9ff1c-9648-470b-b97b-8d189644520f.png)

工具栏本身由几个关键部分组成，每个部分都收集了特定的指标：

+   页面请求：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/f27eaf69-5749-4417-aa62-e75fd5f21d6a.png)

+   执行时间和内存峰值：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/5041377a-e48e-40a2-aba0-864b7fed093b.png)

+   监视事件：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/35ccd405-460d-4449-a77b-e0e2c18d4871.png)

+   错误和警告：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/011e3e78-50ba-4371-a845-dea83ae746c8.png)

+   数据库查询：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/ce9b1877-5521-4db0-b2cb-104b621cdeca.png)

虽然我们的具体示例应用程序没有数据库交互，但以下输出说明了 Z-Ray 捕获了来自资源密集型 Magento 电子商务平台的原始 SQL 数据库查询以及它们的执行时间：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/743fd037-ddcc-4e22-b9c3-2db841b2c586.png)

+   函数：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/d5e769dd-68b4-4199-8c15-a27702ae6155.png)

+   请求信息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/78345d2f-bf13-4fec-aee0-2277fbd45748.png)

Z-Ray 的作用类似于 Xdebug 的跟踪和性能分析功能，直接传递到浏览器中。这使得它对开发人员来说是一个非常方便的工具。捕获 rawSQL 查询为该工具增加了更多价值，因为通常这些查询往往是意想不到的性能瓶颈。

Z-Ray 功能可以轻松地仅针对特定主机启用。这样做的方法是在 Z-Ray | Mode 屏幕下激活选择性选项。这种设置使得对生产站点进行分析变得更加方便。

# 总结

在本节中，我们涉及了我们对整体应用程序测试的三种独特类型的过程。这些过程被称为调试、跟踪和分析，它们为我们提供了对应用程序内部细节的独特和非常信息丰富的视角。虽然跟踪和分析以一种类似无人驾驶的模式为我们收集应用程序性能和执行路径数据，调试则允许我们深入到特定的代码中。无论我们是季节性还是全职软件开发人员，调试、跟踪和分析都是必须掌握的技能。没有它们，解决真正讨厌的错误或编写性能优化的应用程序将成为一个全新的挑战。

前进，我们将更仔细地审视 PHP 应用程序托管、配置和部署的景观和可用选择。


# 第十七章：托管、配置和部署

托管、配置和部署无疑是三个非常不同的活动，通常与整个应用程序生命周期管理紧密相连。一些类型的托管解决方案几乎不可能实现无缝部署，而其他一些解决方案则使开发人员的体验变得愉快且节省时间。这带我们来到最重要的一点，那就是，*为什么开发人员要费心这些系统操作*？对于这个问题有很多答案。而真正的销售点很简单：市场需要。如今，开发人员陷入了一个超越编码技能本身的多学科活动网络中，甚至涉及到某种程度的系统操作。*不是我的工作*的口号几乎是为我们保留的，这其实没什么，因为对整个应用程序生命周期支持活动有很强的了解，使我们在可能的中断面前更加响应。

在本章中，我们将通过以下几个部分对一些活动进行高层次的概述：

+   选择正确的托管计划

+   自动化配置

+   自动化部署

+   持续集成

# 选择正确的托管计划

为我们的下一个项目选择正确的托管计划可能是一个繁琐的挑战。有许多类型的解决方案可供选择，其中包括以下内容：

+   共享服务器

+   虚拟专用服务器

+   专用服务器

+   PaaS

它们都有各自的*优点*和*缺点*。曾经决策因素主要是由内存、CPU、带宽和磁盘存储等功能主导，但这些功能随着时间的推移变得越来越*便宜*。如今，**自动扩展**和**部署的便利性**也成为同样重要的指标。尽管最终价格起着至关重要的作用，但现代托管解决方案提供了很多物有所值的价格。

# 共享服务器

共享网络托管服务是许多不同用户托管其应用程序的地方。托管提供商通常提供一个经过调整的 Web 服务器，带有 MySQL 或 PostgreSQL 数据库和 FTP 访问。此外，通常还有一个基于 Web 的控制面板系统，如 cPanel、Plesk、H-Sphere 或类似的系统。这使我们能够通过一个漂亮的图形界面，直接从我们的浏览器管理一组有限的功能。

流行的 PC Mag 杂志([`www.pcmag.com`](http://www.pcmag.com))列出了 2017 年最佳网络托管服务的清单如下：

+   HostGator 网络托管：[`www.hostgator.com`](http://www.hostgator.com)

+   1&1 网络托管：[`www.1and1.com`](https://www.1and1.com)

+   InMotion 网络托管：[`www.inmotionhosting.com/`](https://www.inmotionhosting.com/)

+   DreamHost 网络托管：[`www.dreamhost.com`](https://www.dreamhost.com)

+   Godaddy 网络托管：[`www.godaddy.com`](https://www.godaddy.com)

+   Bluehost 网络托管：[`www.bluehost.com`](https://www.bluehost.com)

+   Hostwinds 网络托管：[`www.hostwinds.com`](https://www.hostwinds.com)

+   Liquid 网络托管：[`www.liquidweb.com`](https://www.liquidweb.com)

+   A2 网络托管：[`www.a2hosting.com`](https://www.a2hosting.com)

+   阿维克斯网络托管：[`www.arvixe.com`](https://www.arvixe.com)

这些网络托管服务似乎提供了类似的功能，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/184cd2c3-4562-4178-b101-b2518c70154c.png)

虽然价格便宜的共享服务器可能看起来很诱人，但对服务器的控制不足限制了它在任何严肃应用中的使用。我们的应用程序与其他应用程序共享相同的 CPU、内存和存储空间。我们无法安装任何我们想要的软件，如果我们的应用程序需要一些花哨的 PHP 扩展，这甚至可能成为一个决定性因素，这种贫穷人的托管是我们除了名片或博客类型的应用程序之外，应该全心全意地避免的。

# 虚拟专用服务器

**虚拟专用服务器**（VPS）是由托管提供商提供的虚拟机器。然后，该机器运行其自己的操作系统，我们通常具有完整的超级用户访问权限。VPS 本身与其他 VPS 机器共享相同的物理硬件资源。这意味着我们的 VPS 性能很容易受到其他 VPS 机器进程的影响。

流行的 PCMag 杂志（[`www.pcmag.com`](http://www.pcmag.com)）分享了 2017 年最佳 VPS 网络托管服务的名单如下：

+   HostGator Web Hosting: [`www.hostgator.com`](http://www.hostgator.com)

+   InMotion Web Hosting: [`www.inmotionhosting.com/`](https://www.inmotionhosting.com/)

+   1&1 Web Hosting: [`www.1and1.com`](https://www.1and1.com)

+   DreamHost Web Hosting: [`www.dreamhost.com`](https://www.dreamhost.com)

+   Hostwinds Web Hosting: [`www.hostwinds.com`](https://www.hostwinds.com)

+   Liquid Web Hosting: [`www.liquidweb.com`](https://www.liquidweb.com)

+   GoDaddy Web Hosting: [`www.godaddy.com`](https://www.godaddy.com)

+   Bluehost Web Hosting: [`www.bluehost.com`](https://www.bluehost.com)

+   Media Temple Web Hosting: [`mediatemple.net`](https://mediatemple.net)

这些托管服务之间存在相当多的差异，主要是在内存和存储方面，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/91a06c56-f120-4c7b-b174-41d46c935157.png)

虽然 VPS 仍然是一种共享资源的形式，但它比传统的共享托管提供了更大程度的自由。拥有对机器的完全超级用户访问权限意味着我们几乎可以安装任何我们想要的软件。这也意味着我们承担了更大程度的责任。

# 专用服务器

专用服务器假定由托管提供商提供的真实物理机器。这样的机器除了我们之外不与任何其他人共享资源。这使得它成为高性能和关键任务应用的可行选择。

流行的 PCMag 杂志（[`www.pcmag.com`](http://www.pcmag.com)）分享了 2017 年最佳专用网络托管服务的名单如下：

+   HostGator Web Hosting: [`www.hostgator.com`](http://www.hostgator.com)

+   DreamHost Web Hosting: [`www.dreamhost.com`](https://www.dreamhost.com)

+   InMotion Web Hosting: [`www.inmotionhosting.com/`](https://www.inmotionhosting.com/)

+   1&1 Web Hosting: [`www.1and1.com`](https://www.1and1.com)

+   Liquid Web Hosting: [`www.liquidweb.com`](https://www.liquidweb.com)

+   Hostwinds Web Hosting: [`www.hostwinds.com`](https://www.hostwinds.com)

+   GoDaddy Web Hosting: [`www.godaddy.com`](https://www.godaddy.com)

+   Bluehost Web Hosting: [`www.bluehost.com`](https://www.bluehost.com)

+   SiteGround Web Hosting: [`www.siteground.com`](https://www.siteground.com)

+   iPage Web Hosting: [`www.ipage.com`](http://www.ipage.com)

这些托管服务之间存在相当多的差异，主要是在内存和存储方面，如此截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/da07ab44-f81e-475b-9912-7a51c6cfd3d1.png)

虽然价格更高，但专用服务器保证了一定的性能水平和对机器的完全控制。同时，管理可伸缩性和冗余性可能很容易成为一项挑战。

# PaaS

**平台即服务**（PaaS）是一种特殊类型的托管，其中提供商提供了加速应用程序开发所需的硬件和软件工具。我们甚至可以将 PaaS 与由数十个轻松连接的服务支持的专用服务器的强大和灵活性进行比较，这些服务支持可用性、可靠性、可伸缩性和应用程序开发活动。这使得它成为开发人员的热门选择。

IT Central Station 网站（[`www.itcentralstation.com`](https://www.itcentralstation.com)）分享了 2017 年最佳 PaaS 云供应商的名单如下：

+   Amazon AWS: [`aws.amazon.com`](https://aws.amazon.com)

+   Microsoft Azure: [`azure.microsoft.com`](https://azure.microsoft.com)

+   Heroku: [`www.heroku.com`](https://www.heroku.com)

+   Mendix: [`www.mendix.com`](https://www.mendix.com)

+   Salesforce App Cloud: [`www.salesforce.com`](https://www.salesforce.com)

+   Oracle Java Cloud Service: [`cloud.oracle.com/java`](https://cloud.oracle.com/java)

+   HPE Helion: [`www.hpe.com`](https://www.hpe.com)

+   Rackspace Cloud: [`www.rackspace.com`](https://www.rackspace.com)

+   Google App Engine: [`cloud.google.com`](https://cloud.google.com)

+   Oracle Cloud Platform: [`www.oracle.com/solutions/cloud/platform/`](http://www.oracle.com/solutions/cloud/platform/)

以下报告是 2017 年 4 月的：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/be1377b9-9681-4ac9-90a4-9cda5491dd3e.png)

虽然所有这些服务都有很多提供，但值得指出的是亚马逊 AWS，它被 Gartner 在 2016 年云基础设施即服务的魔力象限中评为具有最远见的完整性。评估标准基于几个关键因素：

+   市场理解

+   营销策略

+   销售策略

+   提供（产品）策略

+   商业模式

+   垂直/行业战略

+   创新

+   地理战略

亚马逊 AWS 的一个很好的起点是其 EC2 服务，它提供可调整大小的虚拟服务器。这些虚拟服务器在云中的作用类似于专用服务器，我们可以选择部署它们的世界各地的地区。除此之外，亚马逊 AWS 提供了数十种其他服务，丰富了整体应用管理：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/0c910bfa-97f3-4b82-9826-2c20bbdf02c9.png)

一个易于使用的界面，丰富的服务提供，价格实惠，文档齐全，认证和可用的工具是开发人员在使用亚马逊 AWS 时的一些*卖点*。

# 自动化配置

配置是最近在开发人员中引起了很大关注的一个术语。它指的是使用所需的软件设置和配置*服务器*的活动，使其准备好用于应用。虽然这听起来很像系统操作类型的工作，但随着云服务的兴起和围绕它的工具，开发人员发现这很有趣。

从历史上看，配置意味着很多手动工作。当时通用的自动配置工具并不像今天这样多。这意味着有时配置需要花费数天甚至数周的时间。从今天市场需求的角度来看，这样的情景几乎无法想象。如今，一个单一的应用通常由几个不同的服务器提供服务，每个服务器都针对单一功能，比如 Web（Apache，Nginx，...），存储（MySQL，Redis，...），会话（Redis，Memcached，...），静态内容（Nginx）等等。我们简直无法承受花费数天来设置每个服务器。

有几种流行的工具可以用来自动配置，其中包括这四种流行的工具：

+   Ansible: [`www.ansible.com`](https://www.ansible.com).

+   Chef: [`www.chef.io/chef/`](https://www.chef.io/chef/)

+   Puppet: [`puppet.com`](https://puppet.com)

+   SaltStack: [`saltstack.com`](https://saltstack.com)

像其他同类工具一样，所有这些工具都旨在使配置和维护数十、数百甚至数千台服务器变得更容易。虽然所有这些工具更有可能以同等效果完成任何配置工作，但让我们更仔细地看看其中一个。发布于 2012 年的**Ansible**是其中最年轻的。它是一个开源工具，可以自动化软件配置、配置管理和应用部署。该工具通过 SSH 执行所有功能，而无需在目标节点/服务器上安装任何代理软件。这一点使它成为开发人员中的首选。

围绕 Ansible 有几个关键概念，其中一些如下：

+   **清单**：这是 Ansible 管理的服务器列表

+   **Playbooks**：这是用 YAML 格式表达的 Ansible 配置

+   **角色**：这是基于文件结构的包含指令的自动化

+   **任务**：这是 Ansible 可以执行的可能操作

[`galaxy.ansible.com`](https://galaxy.ansible.com)服务充当了一个提供现成角色的中心。

为了对 Ansible 有一个非常基本的理解，让我们基于以下内容进行一个非常简单和快速的演示：

+   Ubuntu 工作站

+   Ubuntu 服务器

我们将使用`ansible`工具在服务器上部署软件。

# 设置工作站

使用 Ubuntu 工作站，我们可以通过运行以下一组命令轻松安装 Ansible 工具：

```php
sudo apt-get install software-properties-common
sudo apt-add-repository ppa:ansible/ansible
sudo apt-get update
sudo apt-get install ansible

```

如果一切顺利，`ansible --version`应该给我们一个类似这个截图的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/56100755-07ae-4070-a76c-5bb8d7660e9d.png)

Ansible 是一个用于运行临时任务的控制台工具。而临时意味着我们可以快速地做一些事情，而不需要为此编写整个 playbook。

同样，`ansible-galaxy --version`应该给我们一个类似以下截图的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/e46bcaf4-27a2-4508-b704-2e6a584a47ca.png)

`ansible-galaxy`是一个控制台工具，我们可以用它来安装、创建和删除角色，或在 Galaxy 网站上执行任务。默认情况下，该工具使用服务器地址[`galaxy.ansible.com`](https://galaxy.ansible.com)与 Galaxy 网站 API 通信。

同样，`ansible-playbook --version`应该给我们一个类似以下截图的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/ecde8c01-88b0-43c4-92f0-0f626e40808a.png)

`ansible-playbook`是一个用于配置管理和部署的控制台工具。

有了 Ansible 工具，让我们确保我们的工作站有一个适当的 SSH 密钥，我们稍后将用它连接到服务器。我们可以通过简单运行以下命令来轻松生成 SSH 密钥，然后在要求文件和密码时按下*Enter*键：

```php
ssh-keygen -t rsa

```

这应该给我们一个类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/3329b101-a613-4111-849d-ce5445e4f27d.png)

使用 Ansible 的 playbooks，我们可以以易于阅读的 YAML 格式定义各种配置步骤。

# 设置服务器

我们之前提到有几种托管解决方案可以完全控制服务器。这些解决方案以 VPS、专用和云服务的形式出现。在这个例子中，我们将使用**Vultr Cloud Compute**（**VC2**），它可以在[`www.vultr.com`](https://www.vultr.com)上找到。不深入讨论 Vultr 服务的细节，它提供了一个经济实惠的云计算服务，通过易于使用的管理界面。

假设我们已经创建了一个 Vultr 账户，现在我们要做的第一件事是将我们的工作站 SSH 公钥添加到其中。我们可以通过 Vultr 的 Servers | SSH Keys 界面轻松实现：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/b545e1ce-e654-4d46-ae8a-cb67b84f7227.png)

保存了 SSH 密钥后，我们可以返回到服务器界面，点击“部署新服务器”按钮。这将带我们进入“部署新实例”界面，其中呈现给我们几个步骤。我们关注的步骤是服务器类型和 SSH 密钥。

对于服务器类型，让我们继续选择 Ubuntu 16.04 x64：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/1ae8b244-c72a-41b9-ab0c-a9d61359c1e5.png)

对于 SSH 密钥，让我们继续选择我们刚刚添加到 Vultr 的 SSH 密钥：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/c7927438-9cfb-44cc-9e35-ec0df7f7bf81.png)

有了这两个选择，我们可以点击“立即部署”按钮，这应该触发我们服务器的部署。

到这一点，我们可能会想知道这个练习的目的是什么，因为我们已经相当手动地创建了一个服务器。毕竟，Ansible 有一个模块来管理 Vultr 上的服务器，所以我们本可以轻松使用它来创建服务器。然而，这里的练习是围绕着理解如何轻松地“连接”Ansible 到现有的服务器，并使用它来为其进一步配置软件。现在我们有一个运行的服务器，让我们继续进行工作站上 Ansible 的进一步配置。

# 配置 Ansible

回到我们的工作站机器，让我们继续创建一个项目目录：

```php
mkdir mphp7
cd mphp7/

```

现在，让我们继续创建一个`ansible.cfg`文件，内容如下：

```php
[defaults]
hostfile = hosts

```

接下来，让我们继续创建`hosts`文件，内容如下：

```php
[mphp7]
45.76.88.214 ansible_ssh_user=root

```

在上述代码行中，`45.76.88.214`是我们服务器机器的 IP 地址。

现在，我们应该能够运行`ansible`工具，如下所示：

```php
ansible mphp7 -m ping

```

理想情况下，这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/7a8dda31-5e3f-407d-bec1-a71d00875715.png)

如果我们的服务器机器上缺少 Python 安装，`ansible`工具可能会抛出 MODULE FAILURE 消息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/19345ad7-cc19-4387-bcc2-cfffee03a3ca.png)

如果发生这种情况，我们应该通过 SSH 登录到我们的服务器并按以下方式安装 Python：

```php
sudo apt-get -y install python

```

此时，我们的工作站`ansible`工具应该设置为与我们的*服务器*机器进行清晰的通信。

现在，让我们继续在 Galaxy hub 上快速查找 LAMP 服务器角色：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/839f6ee3-25ba-4c8a-94ac-ce15d32d08e3.png)

点击其中一个结果会给我们安装它的信息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/50e2500d-800f-4b9b-97a9-04e81d05ff3a.png)

通过在工作站上运行以下命令，我们安装现有的`fvarovillodres.lamp`规则：

```php
ansible-galaxy install fvarovillodres.lamp

```

# 配置 Web 服务器

有了新拉取的`fvarovillodres.lamp`规则，我们应该能够轻松部署一个新的 Web 服务器。为此，只需创建一个 playbook，比如`lamp.yaml`，内容如下：

```php
- hosts: mphp7
 roles:
 - role: fvarovillodres.lamp
 become: yes

```

现在，我们可以通过以下命令轻松运行我们的`lamp.yaml` playbook：

```php
ansible-playbook lamp.yml

```

这应该在完成后触发从 Galaxy hub 拉取的`fvarovillodres.lamp`规则中的任务：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/767386fe-8bb1-46d1-bad4-3be0cd3ba65b.png)

最后，在`http://45.76.88.214/` URL 上打开应该会给我们一个 Apache 页面。

配置的整体主题，甚至是 Ansible，都是一个值得一本书的广泛主题。这里给出的示例仅仅是为了展示可用工具的易用性，以便以自动化的方式解决配置问题。这里有一个重要的要点，就是我们需要完全控制服务器/节点才能利用配置。这就是为什么共享类型的主机被排除在任何这类讨论之外。

这里给出的确切示例使用了单个服务器框。然而，很容易想象如何通过修改 Ansible 配置来将这种方法扩展到十几甚至数百台服务器。我们本可以使用 Ansible 本身来自动化我们应用的部署，例如，每次部署可能会触发一个新的服务器创建过程，代码从某个 Git 存储库中拉取。然而，也有更简单的专门工具来处理自动化部署。

# 自动化部署

部署 PHP 应用程序主要意味着部署 PHP 代码。由于 PHP 是一种解释性语言而不是编译语言，PHP 应用程序将其代码原样部署在源文件中。这意味着在部署应用程序时没有真正的构建过程，这进一步意味着应用程序部署可以像在服务器 Web 目录中执行`git pull`一样简单。当然，事情永远不会那么简单，因为当代码部署时，我们通常还有各种其他需要适应的部分，比如数据库、挂载驱动器、共享文件、权限、连接到我们服务器的其他服务等等。

我们可以很容易地想象手动从单个 git 存储库部署代码到数十个位于负载均衡器后面的 Web 服务器的复杂性。这种手动部署肯定会产生负面影响，因为我们最终会在整体部署之间有一个时间差，其中一个服务器可能具有更新版本的应用程序代码，而其他服务器仍在提供旧应用程序。因此，缺乏一致性只是需要担心的影响挑战之一。

幸运的是，有数十种工具可以解决自动部署的挑战。虽然我们不会专门讨论它们的细节，但为了快速比较，让我们简要提到以下两个：

+   Deployer：这是一个开源的基于 PHP 的工具，适用于自动化部署，可在[`deployer.org`](https://deployer.org)获取。

+   AWS CodeDeploy：这是 AWS 提供的代码部署服务，可在[`aws.amazon.com/codedeploy/`](https://aws.amazon.com/codedeploy/)获取。

与 AWS CodeDeploy 不同，Deployer 工具是与服务无关的。也就是说，我们可以使用它将代码部署到我们有控制权的任何服务器，包括 AWS EC2 实例。另一方面，AWS CodeDeploy 是一个紧密集成到 AWS 本身的服务，这意味着我们无法在 AWS 之外使用它。这并不意味着在这种情况下 Deployer 比 AWS CodeDeploy 更好。这只是表明一些云和 PaaS 服务为自动部署提供了自己集成的解决方案。

接下来，让我们快速看一下如何轻松地设置 Deployer 来将代码部署到我们的服务器。

# 安装 Deployer

安装 Deployer 非常容易，只需使用以下几个命令：

```php
curl -LO https://deployer.org/releases/v4.3.0/deployer.phar
mv deployer.phar /usr/local/bin/dep 
chmod +x /usr/local/bin/dep

```

现在运行`dep`控制台命令将给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/f8658dbb-e27b-4db8-8939-841d1ef0cc88.png)

# 使用 Deployer

有几个构成 Deployer 应用程序的关键概念：

+   **配置**：使用`set()`和`get()`函数，我们设置和获取一个或多个配置选项：

```php
set('color', 'Yellow');
set('hello', function () {
  return run(...)->toString();
});

```

+   **任务**：这些是通过`task()`函数定义的工作单元，与设置任务描述的`desc()`方法一起使用。在任务中，通常有一个或多个函数，比如`run()`：

```php
desc('Foggyline task #1');
task('update', 'apt-get update');

desc('Foggyline task #2');
task('task_2', function () {
  run(...);
});

```

+   **服务器**：这是通过`server()`函数定义的服务器列表，如下面的代码片段所示：

```php
server('mphp7_staging', 'mphp7.staging.foggyline.net')
 ->user('user')
 ->password('pass')
 ->set('deploy_path', '/home/www')
 ->set('branch', 'stage')
 ->stage('staging');

server('mphp7_prod', 'mphp7.foggyline.net')
 ->user('user')
 ->identityFile()
 ->set('deploy_path', '/home/www')
 ->set('branch', 'master')
 ->stage('production');

```

+   **流程**：这代表一组任务。通用类型项目使用默认流程如下：

```php
task('deploy', [
  'deploy:prepare',
  'deploy:lock',
  'deploy:release',
  'deploy:update_code',
  'deploy:shared',
  'deploy:writable',
  'deploy:vendors',
  'deploy:clear_paths',
  'deploy:symlink',
  'deploy:unlock',
  'cleanup',
  'success' ]);

```

我们可以通过更改自动生成的`deploy.php`文件中的流程来轻松创建自己的流程。

+   **函数**：这是提供有用功能的一组实用函数，比如`run()`、`upload()`、`ask()`等。

使用 Deployer 工具非常简单。除非我们已经有一些先前创建的配方，否则我们可以通过运行以下控制台命令简单地创建一个配方：

```php
dep init

```

这将启动一个交互式过程，要求我们选择正在处理的项目类型。让我们继续考虑从[`github.com/ajzele/MPHP7-CH16`](https://github.com/ajzele/MPHP7-CH16)存储库部署我们的 MPHP7-CH16 应用程序的想法，并将其标记为[0] Common：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/02df8f41-0871-4578-85c3-2892313e2b4b.png)

此命令生成`deploy.php`文件及其内容如下：

```php
<?php namespace Deployer; require 'recipe/common.php';   // Configuration set('ssh_type', 'native'); set('ssh_multiplexing', true); set('repository', 'git@domain.com:username/repository.git'); set('shared_files', []); set('shared_dirs', []); set('writable_dirs', []);   // Servers   server('production', 'domain.com')
 ->user('username')
 ->identityFile() ->set('deploy_path', '/var/www/domain.com');   // Tasks   desc('Restart PHP-FPM service'); task('php-fpm:restart', function () {
  // The user must have rights for restart service
 // /etc/sudoers: username ALL=NOPASSWD:/bin/systemctl restart php-fpm.service  run('sudo systemctl restart php-fpm.service'); }); after('deploy:symlink', 'php-fpm:restart'); desc('Deploy your project'); task('deploy', [
  'deploy:prepare',
  'deploy:lock',
  'deploy:release',
  'deploy:update_code',
  'deploy:shared',
  'deploy:writable',
  'deploy:vendors',
  'deploy:clear_paths',
  'deploy:symlink',
  'deploy:unlock',
  'cleanup',
  'success' ]); // [Optional] if deploy fails automatically unlock. after('deploy:failed', 'deploy:unlock');

```

我们应该将这个文件视为需要调整到我们真实服务器的模板。假设我们希望将我们的 MPHP7-CH16 应用程序部署到我们之前配置的`45.76.88.214`服务器，我们可以通过调整`deploy.php`文件来实现：

```php
<?php namespace Deployer; require 'recipe/common.php';   set('repository', 'https://github.com/ajzele/MPHP7-CH16.git');   server('production', '45.76.88.214')
 ->user('root')
 ->identityFile() ->set('deploy_path', '/var/www/MPHP7')
 ->set('branch', 'master')
 ->stage('production');   desc('Symlink html directory'); task('web:symlink', function () {
 run('ln -sf /var/www/MPHP7/current /var/www/html'); }); desc('Restart Apache service'); task('apache:restart', function () {
 run('service apache2 restart'); }); after('deploy:symlink', 'web:symlink'); after('web:symlink', 'apache:restart');   desc('Deploy your project'); task('deploy', [
  'deploy:prepare',
  'deploy:lock',
  'deploy:release',
  'deploy:update_code',
  'deploy:shared',
  'deploy:writable',
  //'deploy:vendors',
  'deploy:clear_paths',
  'deploy:symlink',
  'deploy:unlock',
  'cleanup',
  'success' ]); after('deploy:failed', 'deploy:unlock');

```

我们使用`set()`函数来配置 git 存储库的位置。然后，`server()`函数定义了我们称之为`production`的单个服务器，位于 45.76.88.214 IP 地址后面。`identityFile()`只是告诉系统使用 SSH 密钥而不是密码进行 SSH 连接。在服务器旁边，我们定义了两个自定义任务，`web:symlink`和`apache:restart`。这些任务确保从 Deployer 的`/var/www/MPHP7/current/`目录到我们的`/var/www/html/`目录进行正确映射。`after()`函数调用只是定义了我们的两个自定义任务应该在 Deployer 的`deploy:symlink`事件之后执行的顺序。

要执行修改后的 deploy.php，我们使用以下控制台命令：

```php
dep deploy production

```

这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/c9c49579-6533-4918-a566-48ebbaf9bc77.png)

要确认部署成功，打开`http://45.76.88.214/`应该给我们以下页面：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/f90af051-6936-48f4-af14-49e7609bf3e7.png)

这个简单的 Deployer 脚本为我们提供了一个强大的方式，可以自动将代码从我们的存储库部署到服务器上。通过 Deployer 的`server()`函数，将其扩展到多个服务器是非常容易的。

# 持续集成

持续集成的理念是将构建、测试和发布过程以一种易于监督的方式绑定在一起。正如我们之前提到的，当涉及到 PHP 时，构建的概念有点特殊，因为语言本身的解释性；我们不是在谈论编译代码。对于 PHP，我们倾向于将其与应用程序所需的各种配置相关联。

话虽如此，持续集成的一些优点包括以下内容：

+   通过静态代码分析自动化代码覆盖和质量检查

+   每次开发人员推送代码后自动运行

+   通过单元和行为测试自动检测错误代码

+   减少应用程序发布周期

+   项目的可见性增加

有数十种持续集成工具可供选择，其中包括以下工具：

+   **PHPCI**：[`www.phptesting.org`](https://www.phptesting.org)

+   **Jenkins**：[`jenkins-php.org`](http://jenkins-php.org)

+   **Travis CI**：[`travis-ci.org`](https://travis-ci.org)

+   **TeamCity**：[`www.jetbrains.com/teamcity/`](https://www.jetbrains.com/teamcity/)

+   竹子：[`www.atlassian.com/software/bamboo`](https://www.atlassian.com/software/bamboo)

+   **AWS CodePipeline**：[`aws.amazon.com/codepipeline/`](https://aws.amazon.com/codepipeline/)

说其中一个工具比其他工具更好是不公平的。尽管在涉及 PHP 时，Jenkins 似乎比其他工具更常见。

# Jenkins

Jenkins 是一个开源的、自包含的、跨平台的、可运行的基于 Java 的自动化服务器。通常会发布两个版本的 Jenkins：**长期支持**（**LTS**）和每周发布的版本。LTS 版本使其具有一些企业友好的特性，除其他外：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/174cd357-c8e0-476b-8a75-7c85c2af7fde.png)

Jenkins 默认情况下并不真正针对 PHP 代码做任何事情，这就是插件发挥作用的地方。

丰富的 Jenkins 插件系统使我们能够轻松安装插件，以便与以下 PHP 工具一起使用：

+   PHPUnit：这是一个可在[`phpunit.de/`](https://phpunit.de/)找到的单元测试框架

+   PHP_CodeSniffer：这是一个检测违反一定编码标准的工具，可在[`github.com/squizlabs/PHP_CodeSniffer`](https://github.com/squizlabs/PHP_CodeSniffer)找到

+   PHPLOC：这是一个快速测量 PHP 项目大小的工具，可在[`github.com/sebastianbergmann/phploc`](https://github.com/sebastianbergmann/phploc)找到。

+   PHP_Depend：这显示了代码设计在可扩展性、可重用性和可维护性方面的质量，可在[`github.com/pdepend/pdepend`](https://github.com/pdepend/pdepend)找到。

+   PHPMD：这是 PHP 混乱检测器，可在[`phpmd.org/`](https://phpmd.org/)找到。

+   PHPCPD：这是用于 PHP 代码的复制/粘贴检测器，可在[`github.com/sebastianbergmann/phpcpd`](https://github.com/sebastianbergmann/phpcpd)找到。

+   phpDox：这是用于 PHP 项目的文档生成器，可在[`phpdox.de/`](http://phpdox.de/)找到。

这些工具的插件影响了 Jenkins 能够持续运行的自动化测试部分。关于代码部署的部分通常与语言无关。深入讨论插件安装和 Jenkins 的整体使用是一本书的话题。重点是要理解持续集成在应用程序生命周期中的重要性和作用，以及提高对可用工具的认识。

有关更多信息，请参阅[`jenkins.io/doc/`](https://jenkins.io/doc)和[`plugins.jenkins.io/`](https://plugins.jenkins.io/)。

# 总结

在本章中，我们涉及了围绕我们应用程序的一些非编码基本要素。虽然开发人员倾向于避免许多与系统操作相关的活动，但与服务器及其设置的实际经验在部署和快速故障响应方面具有巨大优势。在我们的工作中划定“不是我的工作”界限总是一个很棘手的问题。与系统操作紧密合作为我们的应用程序增加了一层质量。最终用户可能会将其视为应用程序本身的故障，而不是其基础架构。托管、配置和部署已成为每个开发人员都需要熟悉的主题。围绕这些活动的工具在可用性和易用性方面似乎相当令人满意。

在整本书中，我们涵盖了广泛且看似独立的一系列主题。这些向我们表明构建应用程序绝非易事。了解 PHP 语言本身的方方面面并不意味着质量软件。给我们的代码结构化是模块化的第一个迹象，这反过来减少了技术债务的影响。这就是标准和设计模式发挥重要作用的地方。毫无疑问，测试被证明是每个应用程序的重要组成部分。幸运的是，PHP 生态系统提供了丰富的测试框架，轻松覆盖 TDD 和 BDD 两种风格。在 PHP 7 中增加的出色新功能，编写高质量的 PHP 应用程序变得更加容易。

希望到现在为止，我们已经对 PHP 及其生态系统以及构成高质量应用程序的各种其他重要部分有足够的了解，以便能够熟练地开发它们。说了这么多，我们结束我们的旅程。
