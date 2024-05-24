# PHP7 模块化编程（二）

> 原文：[`zh.annas-archive.org/md5/ff0acc039cf922de0886cd9283ec3d9f`](https://zh.annas-archive.org/md5/ff0acc039cf922de0886cd9283ec3d9f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：SOLID 设计原则

构建模块化软件需要对类设计有很强的了解。有许多指南，涉及我们如何命名我们的类，它们应该有多少变量，方法的大小应该是多少等等。PHP 生态系统成功地将这些打包成官方的 PSR 标准，更确切地说是 PSR-1：基本编码标准和 PSR-2：编码风格指南。这些都是保持我们的代码可读、可理解和可维护的一般编程指南。

除了编程指南，我们还可以在类设计过程中应用更具体的设计原则。这些原则涉及低耦合、高内聚和强封装的概念。我们称之为 SOLID 设计原则，这是罗伯特·塞西尔·马丁在 21 世纪初提出的一个术语。

SOLID 是以下五个原则的首字母缩写：

+   S：单一职责原则（SRP）

+   O：开放/封闭原则（OCP）

+   L：里氏替换原则（LSP）

+   I：接口隔离原则（ISP）

+   D：依赖倒置原则（DIP）

十多年前，SOLID 原则的概念远未过时，因为它们是良好类设计的核心。在本章中，我们将深入研究这些原则，通过观察一些明显违反原则的违规行为来了解它们。

在本章中，我们将涵盖以下主题：

+   单一职责原则

+   开放/封闭原则

+   里氏替换原则

+   接口隔离原则

+   依赖倒置原则

# 单一职责原则

单一职责原则处理试图做太多事情的类。这里的责任指的是改变的原因。根据罗伯特·C·马丁的定义：

> “一个类应该只有一个改变的原因。”

以下是一个违反 SRP 的类的示例：

```php
class Ticket {
    const SEVERITY_LOW = 'low';
    const SEVERITY_HIGH = 'high';
    // ...
    protected $title;
    protected $severity;
    protected $status;
    protected $conn;

    public function __construct(\PDO $conn) {
        $this->conn = $conn;
    }

    public function setTitle($title) {
        $this->title = $title;
    }

    public function setSeverity($severity) {
        $this->severity = $severity;
    }

    public function setStatus($status) {
        $this->status = $status;
    }

    private function validate() {
        // Implementation...
    }

    public function save() {
        if ($this->validate()) {
            // Implementation...
        }
    }

}

// Client
$conn = new PDO(/* ... */);
$ticket = new Ticket($conn);
$ticket->setTitle('Checkout not working!');
$ticket->setStatus(Ticket::STATUS_OPEN);
$ticket->setSeverity(Ticket::SEVERITY_HIGH);
$ticket->save();
```

`Ticket`类处理`ticket`实体的验证和保存。这两个责任是它改变的原因。每当关于票证验证或保存的要求发生变化时，`Ticket`类都必须进行修改。为了解决这里的 SRP 违规问题，我们可以使用辅助类和接口来分割责任。

以下是符合 SRP 的重构实现的示例：

```php
interface KeyValuePersistentMembers {
    public function toArray();
}

class Ticket implements KeyValuePersistentMembers {
    const STATUS_OPEN = 'open';
    const SEVERITY_HIGH = 'high';
    //...
    protected $title;
    protected $severity;
    protected $status;

    public function setTitle($title) {
        $this->title = $title;
    }

    public function setSeverity($severity) {
        $this->severity = $severity;
    }

    public function setStatus($status) {
        $this->status = $status;
    }

    public function toArray() {
        // Implementation...
    }
}

class EntityManager {
    protected $conn;

    public function __construct(\PDO $conn) {
        $this->conn = $conn;
    }

    public function save(KeyValuePersistentMembers $entity)
    {
        // Implementation...
    }
}

class Validator {
    public function validate(KeyValuePersistentMembers $entity) {
        // Implementation...
    }
}

// Client
$conn = new PDO(/* ... */);

$ticket = new Ticket();
$ticket->setTitle('Payment not working!');
$ticket->setStatus(Ticket::STATUS_OPEN);
$ticket->setSeverity(Ticket::SEVERITY_HIGH);

$validator = new Validator();

if ($validator->validate($ticket)) {
    $entityManager = new EntityManager($conn);
    $entityManager->save($ticket);
}
```

在这里，我们引入了一个简单的`KeyValuePersistentMembers`接口，其中有一个`toArray`方法，然后将其用于`EntityManager`和`Validator`类，这两个类现在都承担了单一职责。`Ticket`类变成了一个简单的数据持有模型，而客户端现在控制*实例化*、*验证*和*保存*作为三个不同的步骤。虽然这当然不是如何分离责任的通用公式，但它提供了一个简单明了的例子来解决这个问题。

在考虑单一职责原则的情况下进行设计会产生更小、更易读和更易测试的代码。

# 开放/封闭原则

开放/封闭原则规定一个类应该对扩展开放，但对修改封闭，根据维基百科上的定义：

> “软件实体（类、模块、函数等）应该对扩展开放，但对修改封闭”

对于扩展开放的部分意味着我们应该设计我们的类，以便在需要时可以添加新功能。对于修改封闭的部分意味着这个新功能应该适合而不修改原始类。类只应在修复错误时进行修改，而不是添加新功能。

以下是一个违反开放/封闭原则的类的示例：

```php
class CsvExporter {
    public function export($data) {
        // Implementation...
    }
}

class XmlExporter {
    public function export($data) {
        // Implementation...
    }
}

class GenericExporter {
    public function exportToFormat($data, $format) {
        if ('csv' === $format) {
            $exporter = new CsvExporter();
        } elseif ('xml' === $format) {
            $exporter = new XmlExporter();
        } else {
            throw new \Exception('Unknown export format!');
        }
        return $exporter->export($data);
    }
}
```

在这里，我们有两个具体类，`CsvExporter`和`XmlExporter`，每个都有一个单一的职责。然后我们有一个`GenericExporter`，其`exportToFormat`方法实际上触发了适当实例类型上的`export`函数。问题在于我们无法在不修改`GenericExporter`类的情况下添加新类型的导出器。换句话说，`GenericExporter`对扩展不开放，对修改封闭。

以下是符合 OCP 的重构实现的一个例子：

```php
interface ExporterFactoryInterface {
    public function buildForFormat($format);
}

interface ExporterInterface {
    public function export($data);
}

class CsvExporter implements ExporterInterface {
    public function export($data) {
        // Implementation...
    }
}

class XmlExporter implements ExporterInterface {
    public function export($data) {
        // Implementation...
    }
}

class ExporterFactory implements ExporterFactoryInterface {
    private $factories = array();

    public function addExporterFactory($format, callable $factory) {
          $this->factories[$format] = $factory;
    }

    public function buildForFormat($format) {
        $factory = $this->factories[$format];
        $exporter = $factory(); // the factory is a callable

        return $exporter;
    }
}

class GenericExporter {
    private $exporterFactory;

    public function __construct(ExporterFactoryInterface $exporterFactory) {
        $this->exporterFactory = $exporterFactory;
    }

    public function exportToFormat($data, $format) {
        $exporter = $this->exporterFactory->buildForFormat($format);
        return $exporter->export($data);
    }
}

// Client
$exporterFactory = new ExporterFactory();

$exporterFactory->addExporterFactory(
'xml',
    function () {
        return new XmlExporter();
    }
);

$exporterFactory->addExporterFactory(
'csv',
    function () {
        return new CsvExporter();
    }
);

$data = array(/* ... some export data ... */);
$genericExporter = new GenericExporter($exporterFactory);
$csvEncodedData = $genericExporter->exportToFormat($data, 'csv');
```

在这里，我们添加了两个接口，`ExporterFactoryInterface`和`ExporterInterface`。然后修改了`CsvExporter`和`XmlExporter`以实现该接口。添加了`ExporterFactory`，实现了`ExporterFactoryInterface`。它的主要作用由`buildForFormat`方法定义，该方法返回导出器作为回调函数。最后，`GenericExporter`被重写以通过其构造函数接受`ExporterFactoryInterface`，其`exportToFormat`方法现在通过导出器工厂构建导出器并调用其`execute`方法。

客户端本身现在扮演了更加强大的角色，首先实例化了`ExporterFactory`并向其中添加了两个导出器，然后将其传递给`GenericExporter`。现在向`GenericExporter`添加新的导出格式不再需要修改它，因此使其对扩展开放，对修改封闭。这绝不是一个通用的公式，而是一种可能的满足 OCP 的方法概念。

# 里氏替换原则

**里氏替换原则**讨论了继承。它指定了我们应该如何设计我们的类，以便客户端依赖项可以被子类替换而客户端看不到差异，根据维基百科上的定义：

> “程序中的对象应该能够被其子类型的实例替换，而不会改变程序的正确性”

虽然子类可能添加了一些特定的功能，但它必须符合与其基类相同的行为。否则，违反了里氏原则。

在涉及 PHP 和子类化时，我们必须超越简单的具体类，并区分：具体类、抽象类和接口。这三者都可以放在基类的上下文中，而扩展或实现它的所有内容都可以被视为派生类。

以下是 LSP 违规的一个例子，派生类没有实现所有方法：

```php
interface User {
    public function getEmail();
    public function getName();
    public function getAge();
}

class Employee implements User {
    public function getEmail() {
        // Implementation...
    }

    public function getAge() {
        // Implementation...
    }
}
```

在这里，我们看到一个`employee`类，它没有实现接口强制执行的`getName`方法。我们本可以使用抽象类而不是接口和抽象方法类型来代替`getName`方法，效果将是相同的。幸运的是，在这种情况下，PHP 会抛出错误，警告我们并没有完全实现接口。

以下是违反里氏原则的一个例子，不同的派生类返回不同类型的东西：

```php
class UsersCollection implements \Iterator {
    // Implementation...
}

interface UserList {
    public function getUsers();
}

class Emloyees implements UserList {
    public function getUsers() {
        $users = new UsersCollection();
        //...
        return $users;
    }
}

class Directors implements UserList {
    public function getUsers() {
        $users = array();
        //...
        return $users;
    }
}
```

在这里，我们看到一个边缘案例的简单例子。在两个派生类上调用`getUsers`将返回一个我们可以循环遍历的结果。然而，PHP 开发人员倾向于经常在数组结构上使用`count`方法，并且在`Employees`实例上使用`getUsers`结果将不起作用。这是因为`Employees`类返回实现了`Iterator`的`UsersCollection`，而不是实际的数组结构。由于`UsersCollection`没有实现`Countable`，我们无法在其上使用`count`，这可能会导致潜在的错误。

我们还可以在派生类对方法参数的处理上发现 LSP 违规的情况。这些通常可以通过使用`type`运算符的实例来发现，如下例所示：

```php
interface LoggerProcessor {
    public function log(LoggerInterface $logger);
}

class XmlLogger implements LoggerInterface {
    // Implementation...
}

class JsonLogger implements LoggerInterface {
    // Implementation...
}

class FileLogger implements LoggerInterface {
    // Implementation...
}

class Processor implements LoggerProcessor {
    public function log(LoggerInterface $logger) {
        if ($logger instanceof XmlLogger) {
            throw new \Exception('This processor does not work with XmlLogger');
        } else {
            // Implementation...
        }
    }
}
```

在这里，派生类`Processor`对方法参数施加了限制，而它应该接受符合`LoggerInterface`的一切。通过变得不那么宽容，它改变了基类 implied 的行为，在这种情况下是`LoggerInterface`。

所述示例仅仅是构成 LSP 违规的一部分。为了满足这一原则，我们需要确保派生类不以任何方式改变基类所施加的行为。

# 接口隔离原则

**接口隔离原则**规定客户端只应实现它们实际使用的接口。它们不应被强制实现它们不使用的接口。根据维基百科上的定义：

> *"许多特定于客户端的接口比一个通用接口更好"*

这意味着我们应该将大而臃肿的接口分割成几个小而轻的接口，将其分离，使得较小的接口基于一组方法，每个方法提供一种特定的功能。

让我们来看一个违反 ISP 的漏洞抽象：

```php
interface Appliance {
    public function powerOn();
    public function powerOff();
    public function bake();
    public function mix();
    public function wash();

}

class Oven implements Appliance {
    public function powerOn() { /* Implement ... */ }
    public function powerOff() { /* Implement ... */ }
    public function bake() { /* Implement... */ }
    public function mix() { /* Nothing to implement ... */ }
    public function wash() { /* Cannot implement... */ }
}

class Mixer implements Appliance {
    public function powerOn() { /* Implement... */ }
    public function powerOff() { /* Implement... */ }
    public function bake() { /* Cannot implement... */ }
    public function mix() { /* Implement... */ }
    public function wash() { /* Cannot implement... */ }
}

class WashingMachine implements Appliance {
    public function powerOn() { /* Implement... */ }
    public function powerOff() { /* Implement... */ }
    public function bake() { /* Cannot implement... */ }
    public function mix() { /* Cannot implement... */ }
    public function wash() { /* Implement... */ }
}
```

在这里，我们有一个接口为几个与电器相关的方法设置要求。然后我们有几个实现该接口的类。问题是非常明显的；并非所有的电器都可以被挤进同一个接口。强迫洗衣机实现烘烤和混合方法是没有意义的。这些方法需要分别分成自己的接口。这样具体的电器类只需要实现实际有意义的方法。

# 依赖反转原则

**依赖反转原则**规定实体应该依赖于抽象而不是具体实现。也就是说，高级模块不应该依赖于低级模块，而应该依赖于抽象。根据维基百科上的定义：

> *"一个应该依赖于抽象。不要依赖于具体实现。"*

这个原则很重要，因为它在解耦我们的软件中起着重要作用。

以下是一个违反 DIP 的类的示例：

```php
class Mailer {
    // Implementation...
}

class NotifySubscriber {
    public function notify($emailTo) {
        $mailer = new Mailer();
        $mailer->send('Thank you for...', $emailTo);
    }
}
```

在这里，我们可以看到`NotifySubscriber`类中的`notify`方法编写了对`Mailer`类的依赖。这导致了紧密耦合的代码，这正是我们试图避免的。为了纠正问题，我们可以通过类构造函数传递依赖，或者可能通过其他方法。此外，我们应该远离具体类依赖，转向抽象类依赖，就像在这里所示的纠正示例中所示的那样：

```php
interface MailerInterface {
    // Implementation...
}

class Mailer implements MailerInterface {
    // Implementation...
}

class NotifySubscriber {
    private $mailer;

    public function __construct(MailerInterface $mailer) {
        $this->mailer = $mailer;
    }

    public function notify($emailTo) {
        $this->mailer->send('Thank you for...', $emailTo);
    }
}
```

在这里，我们看到一个依赖通过构造函数注入。注入是通过类型提示接口和实际的具体类来抽象的。这使得我们的代码耦合度较低。DIP 可以在任何时候使用，当一个类需要调用另一个类的方法，或者我们应该说向其发送消息时。

# 总结

在模块化开发方面，可扩展性是需要不断考虑的事情。编写一个将自己锁定的代码很可能会导致将来无法将其与其他项目或库集成。虽然 SOLID 设计原则可能看起来有些过分，但积极应用这些原则很可能会导致组件易于在时间上进行维护和扩展。

采用 SOLID 原则进行类设计，可以使我们的代码为未来的变化做好准备。它通过将这些变化局部化和最小化在我们的类中，使得使用它的任何集成都不会感受到变化的重大影响。

在接下来的章节中，我们将研究定义我们的应用程序规范，我们将在所有其他章节中构建它。


# 第四章：模块化网店应用的需求规范

从头开始构建软件应用程序需要多种技能，因为它不仅涉及编写代码。写下功能要求和勾画线框图通常是过程中的第一步，尤其是在我们处理客户项目时。这些步骤通常由开发人员以外的人员完成，因为它们需要对客户业务案例、用户行为等方面有一定的了解。作为一个更大的开发团队的一部分，我们作为开发人员通常会得到需求、设计和线框图，然后开始编码。独自完成项目，很容易忽略这些步骤，直接开始编码。然而，这种做法往往是低效的。制定功能要求和一些线框图是值得知道和遵循的技能，即使只是一个开发人员。

在本章后期，我们将讨论高级应用程序要求，以及一个粗略的线框图。

在本章中，我们将涵盖以下主题：

+   定义应用程序要求

+   线框图

+   定义技术栈：

+   Symfony 框架

+   基础框架

# 定义应用程序要求

我们需要构建一个简单但响应迅速的网店应用程序。为了做到这一点，我们需要列出一些基本要求。我们目前感兴趣的要求类型是那些涉及用户与系统之间互动的要求。在用户使用方面，最常见的两种规定要求的技术是用例和用户故事。用户故事是一种不太正式但足够描述要求的方式。使用用户故事，我们封装了客户和商店经理的行为，如下所述。

客户应该能够做到以下事情：

+   浏览静态信息页面（关于我们，客户服务）

+   通过联系表格联系店主

+   浏览商店分类

+   查看产品详情（价格，描述）

+   查看产品图片并放大查看（缩放）

+   查看特价商品

+   查看畅销产品

+   将产品添加到购物车

+   创建客户账户

+   更新客户账户信息

+   找回丢失的密码

+   结账

+   查看订单总成本

+   在几种付款方式中选择

+   在几种运输方式中选择

+   在下订单后收到电子邮件通知

+   检查订单状态

+   取消订单

+   查看订单历史

商店经理应该能够做到以下事情：

+   创建产品（至少包括以下属性：`标题`，`价格`，`sku`，`url-key`，`描述`，`数量`，`类别`和`图片`）

+   上传产品图片

+   更新和删除产品

+   创建分类（至少包括以下属性：`标题`，`url-key`，`描述`和`图片`）

+   上传图片到分类

+   更新和删除分类

+   在新的销售订单被创建时收到通知

+   在新的销售订单被取消时收到通知

+   按其状态查看现有销售订单

+   更新订单状态

+   禁用客户账户

+   删除客户账户

用户故事是一种方便的高级方式来记录应用程序要求。作为敏捷开发的一种特别有用的方式。

# 线框图

有了用户故事，让我们把重点转向实际的线框图。出于我们稍后会讨论的原因，我们的线框图工作将集中在客户的角度。

有许多线框工具，免费和商业化的都有。一些商业化的工具，比如[`ninjamock.com`](https://ninjamock.com)，我们将用于我们的示例，仍然提供免费计划。这对个人项目非常方便，因为它节省了我们很多时间。

每个网站应用程序的起点是它的主页。以下线框图说明了我们网店应用程序的主页：

![线框图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_04_01.jpg)

在这里，我们可以看到一些部分确定页面结构。页眉由标志、类别菜单和用户菜单组成。要求没有提到类别结构的任何内容，我们正在构建一个简单的网店应用，因此我们将坚持扁平的类别结构，没有任何子类别。用户菜单最初将显示**注册**和**登录**链接，直到用户实际登录，此时菜单将如下线框图所示更改。内容区域填充有畅销商品和特价商品，每个商品都有图像、标题、价格和定义的**添加到购物车**按钮。页脚区域包含链接到大多是静态内容页面和**联系我们**页面。

以下线框图展示了我们网店应用的分类页面：

![线框图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_04_02.jpg)

页眉和页脚区域在整个网站中概念上保持不变。内容区域现在已更改为列出任何给定类别内的产品。单个产品区域的呈现方式与主页上的方式相同。类别名称和图像呈现在产品列表上方。类别图像的宽度给出了我们应该准备和上传到我们类别的图像类型的一些提示。

以下线框图展示了我们网店应用的产品页面：

![线框图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_04_03.jpg)

这里的内容区域现在更改为列出单个产品信息。我们可以看到一个大的图像占位符、标题、sku、库存状态、价格、数量字段、**添加到购物车**按钮和产品描述。当商品可供购买时，将显示**有货**消息，当商品不再可用时将显示**缺货**。这与产品数量属性相关。我们还需要记住“查看具有大视图（放大）的产品图像”要求，点击图像将放大显示。

以下线框图展示了我们网店应用的注册页面：

![线框图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_04_04.jpg)

这里的内容区域现在更改为呈现注册表单。我们可以以许多方式实现注册系统。通常情况下，在注册屏幕上询问的信息量最少，因为我们希望尽快让用户进入。然而，让我们假设我们正在尝试在注册屏幕上获取更完整的用户信息。我们不仅要求电子邮件和密码，还要求整个地址信息。

以下线框图展示了我们网店应用的登录页面：

![线框图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_04_05.jpg)

这里的内容区域现在更改为呈现客户登录和忘记密码表单。我们为用户提供**电子邮件**和**密码**字段以进行登录，或者在重置密码操作时只提供**电子邮件**字段。

以下线框图展示了我们网店应用的客户账户页面：

![线框图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_04_06.jpg)

这里的内容区域现在更改为呈现仅对已登录客户可见的客户账户区域。在这里，我们看到了两个主要信息。一个是客户信息，另一个是订单历史。客户可以从此屏幕更改其电子邮件、密码和其他地址信息。此外，客户可以查看、取消和打印其以前的所有订单。**我的订单**表按从新到旧的顺序列出订单。尽管用户故事没有指定，但订单取消应仅适用于待处理订单。这是我们稍后将更详细地讨论的内容。

这也是第一个显示用户菜单状态的屏幕，当用户登录时。我们可以看到一个下拉菜单显示用户的全名，**我的账户**和**退出**链接。紧挨着它，我们有**购物车（%s）**链接，用于列出购物车中的确切数量。

以下线框图展示了我们网店应用的结账购物车页面：

![线框图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_04_07.jpg)

这里的内容区现在改变为呈现购物车的当前状态。如果客户已经向购物车中添加了任何商品，它们将在这里列出。每个商品应列出产品标题、单价、添加的数量和小计。客户应该能够更改数量并点击**更新购物车**按钮来更新购物车的状态。如果数量为`0`，点击**更新购物车**按钮将从购物车中移除该商品。购物车数量应始终反映页眉菜单中**购物车（%s）**链接的状态。屏幕右侧显示了当前订单总价的快速摘要，以及一个清晰的**去结账**按钮。

以下线框图展示了我们网店应用的结账购物车运输页面：

![线框图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_04_08.jpg)

这里的内容区现在改变为呈现结账流程的第一步，即收集运输信息。这个页面对未登录客户不可见。客户可以在这里提供他们的地址详细信息，以及选择运输方式。运输方式区列出了几种运输方式。在右侧，显示了可折叠的订单摘要部分，列出购物车中当前商品。在其下方，有购物车小计值和一个清晰的**下一步**按钮。只有在提供了所有必要信息时，**下一步**按钮才会触发，此时它应该将我们带到结账购物车付款页面上的付款信息。

以下线框图展示了我们网店应用的结账购物车付款页面：

![线框图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_04_09.jpg)

这里的内容区现在改变为呈现结账流程的第二步，即收集付款信息。这个页面对未登录客户不可见。客户将看到可用付款方式的列表。为了简化应用程序，我们将只关注固定付款，不会使用像 PayPal 或 Stripe 这样复杂的付款方式。在屏幕右侧，我们可以看到一个可折叠的**订单摘要**部分，列出购物车中当前商品。在其下方，有订单总额部分，分别列出**购物车小计**、**标准运费**、**订单总额**和一个清晰的**下订单**按钮。只有在提供了所有必要信息时，**下订单**按钮才会触发，此时它应该将我们带到结账成功页面。

以下线框图展示了我们网店应用的结账成功页面：

![线框图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_04_10.jpg)

这里的内容区现在改变为输出结账成功的消息。显然，这个页面只对刚刚完成结账流程的已登录客户可见。订单号可点击并链接到**我的账户**区域，重点关注具体订单。到达这个页面时，客户和商店经理都应该收到通知邮件，根据*下订单后收到邮件通知*和*新销售订单创建后收到通知*的要求。

通过这些，我们结束了面向客户的线框图。

关于商店经理用户故事需求，我们现在将简单定义一个管理界面，如下截图所示：

![线框图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_04_11.jpg)

稍后使用框架，我们将获得一个完整的自动生成的 CRUD 界面，用于多个**添加新**和**列表和管理**链接。对这个界面和其链接的访问将由框架的安全组件控制，因为这个用户不会是客户或数据库中的任何用户。

Symfony 框架

# 创建新记录

此外，在接下来的章节中，我们将把我们的应用程序分成几个模块。在这样的设置中，每个模块将负责各自的功能，处理客户、目录、结账和其他需求。

## Symfony 框架对我们的应用程序来说是一个不错的选择。它是一个企业级框架，已经存在多年，文档和支持非常完善。可以从官方网站[`symfony.com`](http://symfony.com)下载，如下所示：

编辑现有记录

![Symfony 框架](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_04_12.jpg)

将技术栈定义为

+   控制器

+   路由

+   ORM（通过 Doctrine）

+   表单

+   验证

+   安全

这些是我们应用程序所需的基本功能。ORM 特别在快速应用程序开发中起着重要作用。不用太担心编码，CRUD 的每个方面都可以将开发速度提高一倍或两倍。Symfony 在这方面的伟大之处在于，它允许通过执行两个简单的命令自动生成实体和围绕它们的 CRUD 操作：

```php
php bin/console doctrine:generate:entity
php app/console generate:doctrine:crud
```

通过这样做，Symfony 生成实体模型和必要的控制器，使我们能够执行以下操作：

+   列出所有记录

+   显示由其主键标识的给定记录

+   一旦需求和线框图确定，我们就可以将注意力集中在选择技术栈上。在第一章中，*生态系统概述*，我们简要介绍了几种最流行的 PHP 框架，并指出了它们的优势。在这种情况下，选择合适的框架更多地是一种偏好，因为大部分应用需求可以很容易地满足任何一个框架。然而，我们的选择落在了 Symfony 上。除了 PHP 框架，我们仍然需要一个 CSS 框架，在客户端浏览器中提供一些结构、样式和响应能力。由于本书的重点是 PHP 技术，我们选择了 Foundation CSS 框架来完成这项任务。

+   Foundation 框架

+   删除现有记录

基本上，我们免费获得了一个最小的商店经理界面。这本身就涵盖了商店经理角色的大部分 CRUD 相关需求。然后，我们可以轻松修改生成的模板，进一步整合剩余的功能。

此外，安全组件提供了身份验证和授权，我们可以用来满足客户和商店经理的登录需求。因此，商店经理将是 Symfony 防火墙固定的、预先创建的用户，是唯一可以访问 CRUD 控制器操作的用户。

## 基础框架

Foundation 框架由 Zurb 公司支持，是现代响应式 Web 应用程序的一个很好的选择。我们可以说它是一个企业级框架，提供了一套 HTML、CSS 和 JavaScript，我们可以构建在其上。可以从官方网站[`foundation.zurb.com`](http://foundation.zurb.com)下载，如下所示：

![Foundation 框架](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_04_13.jpg)

Foundation 有三种风格：

+   Foundation for sites

+   电子邮件基础

+   Foundation for apps

我们对网站版本感兴趣。除了一般的样式外，Foundation for sites 还提供了大量的控件、导航元素、容器、媒体元素和插件。这些在我们的应用程序中将特别有用，比如标题菜单、类别产品列表、响应式购物车表格等。

Foundation 是一个以移动设备为先的框架，我们首先为小屏幕编码，然后大屏幕继承这些样式。它的默认 12 列网格系统使我们能够快速轻松地创建强大的多设备布局。

我们将使用 Foundation 来提供结构、一些基本样式和响应性，而不需要自己编写一行 CSS。这样就足以使我们的应用在移动和桌面屏幕上看起来足够美观，同时仍然将我们大部分的编码技能集中在后端事务上。

除了提供强大的功能外，Foundation 背后的公司还提供优质的技术支持。虽然我们在本书中不需要它，但选择应用程序框架时，这些事情建立了信心。

# 摘要

创建 Web 应用程序可能是一项乏味且耗时的任务，Web 商店可能是最健壮和最密集的应用程序类型之一，因为它们涵盖了大量的功能。在交付最终产品时涉及许多组件；从数据库、服务器端（PHP）代码到客户端（HTML、CSS 和 JavaScript）代码。在本章中，我们首先通过定义一些基本用户故事来定义我们小型网店的高级应用程序要求。将线框图加入其中有助于我们可视化客户界面，而商店管理界面将由框架提供。

我们进一步概述了支持模块化应用程序设计的两个最流行的框架。我们将注意力转向 Symfony 作为服务器端技术和 Foundation 作为客户端响应式框架。

在接下来的章节中，我们将更深入地了解 Symfony。Symfony 不仅是一组可重用的组件，还是最健壮和最流行的全栈 PHP 框架之一。因此，它是快速 Web 应用程序开发的一个有趣选择。


# 第五章：一览 Symfony

像 Symfony 这样的全栈框架有助于通过提供所有必要的组件，从用户界面到数据存储，来简化构建模块化应用程序的过程。这使得在应用程序增长时能够更快地交付各个部分。我们将通过将应用程序分割为几个较小的模块或 Symfony 术语中的 bundle 来体验到这一点。

接下来，我们将安装 Symfony，创建一个空项目，并开始研究构建模块化应用程序所必需的各个框架特性：

+   控制器

+   路由

+   模板

+   表单

+   Bundle 系统

+   数据库和 Doctrine

+   测试

+   验证

# 安装 Symfony

安装 Symfony 非常简单。我们可以使用以下命令在 Linux 或 Mac OS X 上安装 Symfony：

```php
**sudo curl -LsS https://symfony.com/installer -o /usr/local/bin/symfony**
**sudo chmod a+x /usr/local/bin/symfony**

```

我们可以使用以下命令在 Windows 上安装 Symfony：

```php
**c:\> php -r "file_put_contents('symfony', file_get_contents('https://symfony.com/installer'));"**

```

执行该命令后，我们可以简单地将新创建的`symfony`文件移动到我们的项目目录，并在 Windows 中进一步执行它作为`symfony`或`php symfony`。

这应该触发以下输出：

![安装 Symfony](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_01.jpg)

前面的响应表明我们已经成功设置了 Symfony，现在准备开始创建新项目。

# 创建一个空项目

既然我们已经设置好了 Symfony 安装程序，让我们继续创建一个新的空项目。我们只需执行`symfony new test-app`命令，如下面的命令行示例所示：

![创建一个空项目](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_02.jpg)

在这里，我们正在创建一个名为`test-app`的新项目。我们可以看到 Symfony 安装程序正在从互联网下载最新的 Symfony 框架，并输出一个简要的指令，说明如何通过 Symfony 控制台应用程序运行内置的 PHP 服务器。整个过程可能需要几分钟。

新创建的`test-app`目录的结构与以下类似：

![创建一个空项目](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_03.jpg)

这里为我们创建了许多文件和目录。然而，我们感兴趣的是`app`和`src`目录。`app`目录是整个站点应用程序配置的所在地。在这里，我们可以找到数据库、路由、安全和其他服务的配置。此外，这也是默认布局和模板文件所在的地方，如下面的截图所示：

![创建一个空项目](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_04.jpg)

另一方面，`src`目录包含了已经模块化的代码，以`AppBundle`模块的形式，如下面的截图所示：

![创建一个空项目](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_05.jpg)

随着我们的进展，我们将更详细地讨论这些文件的作用。目前，值得注意的是，将我们的浏览器指向这个项目会使`DefaultController.php`实际上渲染输出。

# 使用 Symfony 控制台

Symfony 框架自带一个内置的控制台工具，我们可以通过在项目根目录中执行以下命令来触发它：

```php
**php bin/console**

```

这样做会在屏幕上显示一个可用命令的广泛列表，分为以下几组：

+   `资产`

+   `缓存`

+   `配置`

+   `调试`

+   `doctrine`

+   `生成`

+   `lint`

+   `orm`

+   `路由`

+   `安全`

+   `服务器`

+   `swiftmailer`

+   `翻译`

这些命令赋予我们各种功能。我们未来特别感兴趣的是`doctrine`和`generate`命令。`doctrine`命令，特别是`doctrine:generate:crud`，基于现有的 Doctrine 实体生成一个 CRUD。此外，`doctrine:generate:entity`命令在现有 bundle 中生成一个新的 Doctrine 实体。在我们需要快速轻松地创建实体以及围绕它的整个 CRUD 时，这些命令非常有用。同样，`generate:doctrine:entity`和`generate:doctrine:crud`也是如此。

在继续测试这些命令之前，我们需要确保我们的数据库配置参数已经设置好，以便 Symfony 可以看到并与我们的数据库进行通信。为此，我们需要在`app/config/parameters.yml`文件中设置适当的值。

为了本节的目的，让我们继续在默认的`AppBundle`包中创建一个简单的 Customer 实体，围绕它创建整个 CRUD，假设 Customer 实体具有以下属性：`firstname`、`lastname`和`e-mail`。我们首先在项目根目录中运行`php bin/console generate:doctrine:entity`命令，结果如下输出：

![使用 Symfony 控制台](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_12.jpg)

在这里，我们首先提供了`AppBundle:Customer`作为实体名称，并确认了注释作为配置格式的使用。

最后，我们被要求开始向我们的实体添加字段。输入名字并按回车键，将我们移动到一系列关于字段类型、长度、可空和唯一状态的简短问题，如下屏幕截图所示：

![使用 Symfony 控制台](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_11.jpg)

现在我们应该已经为我们的 Customer 实体生成了两个类。通过 Symfony 和 Doctrine 的帮助，这些类被放置在**对象关系映射器**（**ORM**）的上下文中，因为它们将 Customer 实体与适当的数据库表进行了关联。但是，我们还没有指示 Symfony 实际上为我们的实体创建表。为此，我们执行以下命令：

```php
**php bin/console doctrine:schema:update --force**

```

这应该会产生如下屏幕截图所示的输出：

![使用 Symfony 控制台](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_13.jpg)

如果我们现在查看数据库，应该会看到一个`customer`表，其中包含使用 SQL 创建 dsyntax 创建的所有正确列，如下所示：

```php
**CREATE TABLE `customer` (**
 **`id` int(11) NOT NULL AUTO_INCREMENT,**
 **`firstname` varchar(255) COLLATE utf8_unicode_ci NOT NULL,**
 **`lastname` varchar(255) COLLATE utf8_unicode_ci NOT NULL,**
 **`email`** **varchar(255) COLLATE utf8_unicode_ci NOT NULL,**
 **PRIMARY KEY (`id`),**
 **UNIQUE KEY `UNIQ_81398E09E7927C74` (`email`)**
**) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;**

```

此时，我们仍然没有实际的 CRUD 功能。我们只是有一个经过 ORM 授权的 Customer 实体类和适当的数据库表。以下命令将为我们生成实际的 CRUD 控制器和模板：

```php
**php bin/console generate:doctrine:crud**

```

这应该产生以下交互式输出：

![使用 Symfony 控制台](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_14.jpg)

通过提供完全分类的实体名称`AppBundle:Customer`，生成器将继续一系列附加输入，从生成写操作、读取的配置类型到路由前缀，如下屏幕截图所示：

![使用 Symfony 控制台](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_15.jpg)

完成后，我们应该能够通过简单打开类似`http://test.app/customer/`的 URL（假设`test.app`是我们设置的主机）来访问我们的 Customer CRUD 操作，如下所示：

![使用 Symfony 控制台](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_06.jpg)

如果我们单击**创建新条目**链接，我们将被重定向到`/customer/new/` URL，如下屏幕截图所示：

![使用 Symfony 控制台](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_07.jpg)

在这里，我们可以输入我们的 Customer 实体的实际值，并单击**Create**按钮，以将其持久化到数据库的`customer`表中。添加了一些实体后，初始的`/customer/` URL 现在能够列出它们所有，如下屏幕截图所示：

![使用 Symfony 控制台](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_08.jpg)

在这里，我们看到了**显示**和**编辑**操作的链接。**显示**操作是我们可能考虑的面向客户的操作，而**编辑**操作是面向管理员的操作。单击**编辑**操作，将我们带到表单的 URL`/customer/1/edit/`，而在这种情况下的数字`1`是数据库中客户实体的 ID：

![使用 Symfony 控制台](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_09.jpg)

在这里，我们可以更改属性值并单击**编辑**以将它们持久化到数据库中，或者我们可以单击**删除**按钮以从数据库中删除实体。

如果我们要创建一个具有已存在电子邮件的新实体，该电子邮件被标记为唯一字段，系统将抛出一个通用错误，如下所示：

![使用 Symfony 控制台](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_10.jpg)

这只是默认的系统行为，随着我们的进展，我们将探讨如何使其更加用户友好。到目前为止，我们已经看到了 Symfony 控制台的强大之处。通过几个简单的命令，我们能够创建实体及其整个 CRUD 操作。控制台还有很多功能。我们甚至可以创建自己的控制台命令，因为我们可以实现任何类型的逻辑。然而，就我们的需求而言，当前的实现暂时足够了。

# 控制器

控制器在 Web 应用程序中扮演着重要的角色，是任何应用程序输出的前沿。它们是端点，是在每个 URL 后面执行的代码。从技术上讲，我们可以说控制器是任何可调用的东西（函数、对象上的方法或闭包），它接受 HTTP 请求并返回 HTTP 响应。响应不限于单一格式，可以是 XML、JSON、CSV、图像、重定向、错误等任何东西。

让我们来看一下之前创建的（部分）`src/AppBundle/Controller/CustomerController.php`文件，更确切地说是它的`newAction`方法：

```php
/**
 * Creates a new Customer entity.
 *
 * @Route("/new", name="customer_new")
 * @Method({"GET", "POST"})
 */
public function newAction(Request $request)
{
  //...

  return $this->render('customer/new.html.twig', array(
    'customer' => $customer,
    'form' => $form->createView(),
  ));
}
```

如果我们忽略实际的数据检索部分（`//…`），在这个小例子中有三个重要的事情需要注意：

+   `@Route`：这是 Symfony 的注释方式来指定 HTTP 端点，我们将用它来访问。第一个`"/new"`参数表示实际的端点，第二个`name="customer_new"`参数设置了这个路由的名称，我们可以在模板中的 URL 生成函数中使用它作为别名。值得注意的是，这是建立在实际`CustomerController`类上的`@Route("/customer")`注释之上的，因此完整的 URL 可能是`http://test.app/customer/new`。

+   `@Method`：这里接受一个或多个 HTTP 方法的名称。这意味着`newAction`方法只会在 HTTP 请求与先前定义的`@Route`匹配并且是在`@Method`中定义的一个或多个 HTTP 方法类型时触发。

+   `$this->render`：这返回`Response`对象。`$this->render`调用`Symfony\Bundle\FrameworkBundle\Controller\Controller`类的`render`函数，它实例化新的`Response()`，设置其内容，并返回该对象的整个实例。

现在让我们来看一下我们控制器中的`editAction`方法，如下面的代码块所示：

```php
/**
 * Displays a form to edit an existing Customer entity.
 *
 * @Route("/{id}/edit", name="customer_edit")
 * @Method({"GET", "POST"})
 */
public function editAction(Request $request, Customer $customer)
{
  //...
}
```

在这里，我们看到一个路由接受一个单一的 ID，标记为第一个`@Route`注释参数中的`{id}`。方法的主体（在此处排除）不包含对获取`id`参数的直接引用。我们可以看到`editAction`函数接受两个参数，一个是`Request`，另一个是`Customer`。但是方法如何知道要接受`Customer`对象呢？这就是 Symfony 的`@ParamConverter`注释发挥作用的地方。它调用转换器将请求参数转换为对象。

`@ParamConverter`注释的好处在于我们可以明确或隐式地使用它。也就是说，如果我们不添加`@ParamConverter`注释，但在方法参数中添加类型提示，Symfony 将尝试为我们加载对象。这正是我们在上面的例子中的情况，因为我们没有明确地添加`@ParamConverter`注释。

术语上，控制器经常被用来交换路由。然而，它们并不是同一回事。

# 路由

简而言之，路由是将控制器与浏览器中输入的 URL 链接起来。现代的 Web 应用程序需要友好的 URL。这意味着从像`/index.php?product_id=23`这样的 URL 迁移到像`/catalog/product/t-shirt`这样的 URL。这就是路由发挥作用的地方。

Symfony 有一个强大的路由机制，使我们能够做到以下几点：

+   创建映射到控制器的复杂路由

+   在模板中生成 URL

+   在控制器内生成 URL

+   从各种位置加载路由资源

Symfony 中路由的工作方式是所有请求都通过`app.php`。然后，Symfony 核心要求路由器检查请求。路由器然后将传入的 URL 与特定路由匹配，并返回有关路由的信息。这些信息，除其他事项外，包括应执行的控制器。最后，Symfony 内核执行控制器，返回一个响应对象。

所有应用程序路由都从单个路由配置文件加载，通常是`app/config/routing.yml`文件，如我们的测试应用程序所示：

```php
app:
  resource: "@AppBundle/Controller/"
  type:     annotation
```

该应用程序只是许多可能输入之一。它的资源值指向`AppBundle`控制器目录，类型设置为注释，这意味着类注释将被读取以指定确切的路由。

我们可以定义具有多种变化的路由。其中一种如下所示：

```php
// Basic Route Configuration
/**
 * @Route("/")
 */
public function homeAction()
{
  // ...
}

// Routing with Placeholders
/**
 * @Route("/catalog/product/{sku}")
 */
public function showAction($sku)
{
  // ...
}

// >>Required<< and Optional Placeholders
/**
 * @Route("/catalog/product/{id}")
 */
public function indexAction($id)
{
  // ...
}
// Required and >>Optional<< Placeholders
/**
 * @Route("/catalog/product/{id}", defaults={"id" = 1})
 */
public function indexAction($id)
{
  // ...
}
```

前面的例子展示了我们可以定义路由的几种方式。有趣的是带有必需和可选参数的情况。如果我们考虑一下，从最新的例子中删除 ID 将匹配带有 sku 的前一个例子。Symfony 路由器总是选择它找到的第一个匹配路由。我们可以通过在`@Route`注释上添加正则表达式要求来解决这个问题，如下所示：

```php
@Route(
  "/catalog/product/{id}",
  defaults={"id": 1},
  requirements={"id": "\d+"}
)
```

关于控制器和路由还有更多要说的，一旦我们开始构建我们的应用程序，我们将会看到。

# 模板

之前我们说过控制器接受请求并返回响应。然而，响应往往可以是任何内容类型。实际内容的生成是控制器委托给模板引擎的。然后模板引擎有能力将响应转换为 HTML、JSON、XML、CSV、LaTeX 或任何其他基于文本的内容类型。

在过去，程序员将 PHP 与 HTML 混合到所谓的 PHP 模板（`.php`和`.phtml`）中。尽管在某些平台上仍在使用，但这种方法被认为是不安全的，并且在许多方面缺乏。其中之一是将业务逻辑塞入模板文件中。

为了解决这些缺点，Symfony 打包了自己的模板语言 Twig。与 PHP 不同，Twig 旨在严格表达演示文稿，而不是思考程序逻辑。我们不能在 Twig 中执行任何 PHP 代码。而 Twig 代码只不过是带有一些特殊语法类型的 HTML。

Twig 定义了三种特殊语法类型：

+   `{{ ... }}`：这将把变量或表达式的结果输出到模板中。

+   `{% ... %}`：这个标签控制模板的逻辑（`if`和`for`循环等）。

+   `{# ... #}`：它相当于 PHP 的`/* comment */`语法。注释内容不包括在渲染页面中。

过滤器是 Twig 的另一个很好的功能。它们就像对变量值进行链式方法调用一样，修改输出之前的内容，如下所示：

```php
<h1>{{ title|upper }}</h1>

{{ filter upper }}
<h1>{{ title }}</h1>
{% endfilter %}

<h1>{{ title|lower|escape }}</h1>

{% filter lower|escape %}
<h1>{{ title }}</h1>
{% endfilter %}
```

它还支持以下列出的函数：

```php
{{ random(['phone', 'tablet', 'laptop']) }}
```

前面的随机函数调用将从数组中返回一个随机值。除了内置的过滤器和函数列表外，Twig 还允许根据需要编写自己的过滤器和函数。

与 PHP 类继承类似，Twig 也支持模板和布局继承。让我们快速回顾一下`app/Resources/views/customer/index.html.twig`文件，如下所示：

```php
{% extends 'base.html.twig' %}

{% block body %}
<h1>Customer list</h1>
…
{% endblock %}
```

在这里，我们看到一个客户`index.html.twig`模板，使用`extends`标签来扩展另一个模板，这种情况下是在`app/Resources/views/`目录中找到的`base.html.twig`，内容如下：

```php
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <title>{% block title %}Welcome!{% endblock %}</title>
    {% block stylesheets%}{% endblock %}
    <link rel="icon" type="image/x-icon"href="{{ asset('favicon.ico') }}" />
  </head>
  <body>
    {% block body %}{% endblock %}
    {% block javascripts%}{% endblock %}
  </body>
</html>
```

在这里，我们看到几个块标签：`title`，`stylesheets`，`body`和`javascripts`。我们可以在这里声明任意数量的块，并以任何我们喜欢的方式命名它们。这使得`extend`标签成为模板继承的关键。它告诉 Twig 首先评估基础模板，设置布局并定义块，然后子模板如`customer/index.html.twig`填充这些块的内容。

模板存在于两个位置：

+   `app/Resources/views/`

+   `bundle-directory/Resources/views/`

这意味着为了`render/extend app/Resources/views/base.html.twig`，我们将在我们的模板文件中使用`base.html.twig`，而为了`render/extend app/Resources/views/customer/index.html.twig`，我们将使用`customer/index.html.twig`路径。

当与存储在 bundles 中的模板一起使用时，我们必须稍微不同地引用它们。在这种情况下，使用`bundle:directory:filename`字符串语法。以`FoggylineCatalogBundle:Product:index.html.twig`路径为例。这将是使用 bundles 模板文件的完整路径。这里`FoggylineCatalogBundle`是一个 bundle 名称，`Product`是该 bundle`Resources/views`目录中的一个目录名称，`index.html.twig`是`Product`目录中实际模板的名称。

每个模板文件名都有两个扩展名，首先指定格式，然后指定该模板的引擎；例如`*.html.twig`，`*.html.php`和`*.css.twig`。

一旦我们开始构建我们的应用程序，我们将更详细地了解这些模板。

# 表单

注册、登录、添加到购物车、结账，所有这些以及更多操作都在网店应用程序和其他地方使用 HTML 表单。构建表单是开发人员最常见的任务之一。通常需要时间来正确完成。

Symfony 有一个`form`组件，通过它我们可以以面向对象的方式构建 HTML 表单。这个组件本身也是一个独立的库，可以独立于 Symfony 使用。

让我们来看看`src/AppBundle/Entity/Customer.php`文件的内容，这是为我们自动生成的`Customer`实体类，当我们通过控制台定义它时：

```php
class Customer {
  private $id;
  private $firstname;
  private $lastname;
  private $email;

  public function getId() {
    return $this->id;
  }

  public function setFirstname($firstname) {
    $this->firstname = $firstname;
    return $this;
  }

  public function getFirstname() {
    return $this->firstname;
  }

  public function setLastname($lastname) {
    $this->lastname = $lastname;
    return $this;
  }

  public function getLastname() {
    return $this->lastname;
  }

  public function setEmail($email) {
    $this->email = $email;
    return $this;
  }

  public function getEmail() {
    return $this->email;
  }
}
```

在这里，我们有一个普通的 PHP 类，它既不继承任何东西，也不以任何其他方式与 Symfony 相关联。它代表一个单一的客户实体，为其设置和获取数据。有了实体类，我们想要渲染一个表单，该表单将获取我们类使用的所有相关数据。这就是`Form`组件的作用所在。

当我们之前通过控制台使用 CRUD 生成器时，它为我们的 Customer 实体创建了`Form`类，位于`src/AppBundle/Form/CustomerType.php`文件中，内容如下：

```php
namespace AppBundle\Form;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class CustomerType extends AbstractType
{
  public function buildForm(FormBuilderInterface $builder, array $options) {
    $builder
    ->add('firstname')
    ->add('lastname')
    ->add('email')
    ;
  }

  public function configureOptions(OptionsResolver $resolver) {
    $resolver->setDefaults(array(
      'data_class' =>'AppBundle\Entity\Customer'
    ));
  }
}
```

我们可以看到表单组件背后的简单性归结为以下几点：

+   **扩展表单类型**：我们从`Symfony\Component\Form\AbstractType`类继承

+   **实现 buildForm 方法**：这是我们添加要在表单上显示的实际字段的地方

+   **实现 configureOptions**：这至少指定了`data_class`配置，指向我们的 Customer 实体。

表单构建器对象在这里承担了大部分工作。它不需要太多的工作就可以创建一个表单。有了`form`类，让我们来看看负责向模板提供表单的`controller`动作。在这种情况下，我们将专注于`src/AppBundle/Controller/CustomerController.php`文件中的`newAction`，内容如下：

```php
$customer = new Customer();
$form = $this->createForm('AppBundle\Form\CustomerType', $customer);
$form->handleRequest($request);

if ($form->isSubmitted() && $form->isValid()) {
  $em = $this->getDoctrine()->getManager();
  $em->persist($customer);
  $em->flush();

  return $this->redirectToRoute('customer_show', array('id' =>$customer->getId()));
}

return $this->render('customer/new.html.twig', array(
  'customer' => $customer,
  'form' => $form->createView(),
));
```

上述代码首先实例化了`Customer`实体类。`$this->createForm(…)`实际上是调用了`$this->container->get('form.factory')->create(…)`，将我们的`form`类名和`customer`对象的实例传递给它。然后我们有`isSubmitted`和`isValid`检查，以查看这是 GET 请求还是有效的 POST 请求。根据这个检查，代码要么返回到客户列表，要么设置`form`和`customer`实例，以便与模板`customer/new.html.twig`一起使用。我们稍后会更详细地讨论实际的验证。

最后，让我们来看看`app/Resources/views/customer/new.html.twig`文件中的实际模板：

```php
{% extends 'base.html.twig' %}

{% block body %}
<h1>Customer creation</h1>

{{ form_start(form) }}
{{ form_widget(form) }}
<input type="submit" value="Create" />
{{ form_end(form) }}

<ul>
  <li>
    <a href="{{ path('customer_index') }}">Back to the list</a>
  </li>
</ul>
{% endblock %}
```

在这里我们看到了`extends`和`block`标签，以及一些相关的函数。Symfony 向 Twig 添加了几个表单渲染函数，如下所示：

+   `form(view, variables)`

+   `form_start(view, variables)`

+   `form_end(view, variables)`

+   `form_label(view, label, variables)`

+   `form_errors(view)`

+   `form_widget(view, variables)`

+   `form_row(view, variables)`

+   `form_rest(view, variables)`

我们的大多数应用程序表单将会像这样自动生成，因此我们能够获得一个完全功能的 CRUD，而不需要深入了解其他表单功能。

# 配置 Symfony

为了跟上现代需求，今天的框架和应用程序需要一个灵活的配置系统。Symfony 通过其强大的配置文件和环境概念很好地实现了这一角色。

默认的 Symfony 配置文件`config.yml`位于`app/config/`目录下，（部分）内容如下分段：

```php
imports:
  - { resource: parameters.yml }
  - { resource: security.yml }
  - { resource: services.yml }

framework:
…

# Twig Configuration
twig:
…

# Doctrine Configuration
doctrine:
…

# Swiftmailer Configuration
swiftmailer:
…
```

像`framework`、`twig`、`doctrine`和`swiftmailer`这样的顶级条目定义了单个 bundle 的配置。

可选地，配置文件可以是 XML 或 PHP 格式（`config.xml`或`config.php`）。虽然 YAML 简单易读，XML 更强大，而 PHP 更强大但不太易读。

我们可以使用控制台工具来转储整个配置，如下所示：

```php
**php bin/console config:dump-reference FrameworkBundle**

```

前面的示例列出了核心`FrameworkBundle`的配置文件。我们可以使用相同的命令来显示任何实现容器扩展的 bundle 的可能配置，这是我们稍后将要研究的内容。

Symfony 对环境概念有一个很好的实现。查看`app/config`目录，我们可以看到默认的 Symfony 项目实际上从三种不同的环境开始：

+   `config_dev.yml`

+   `config_prod.yml`

+   `config_test.yml`

每个应用程序可以在各种环境中运行。每个环境共享相同的代码，但不同的配置。开发环境可能会使用大量的日志记录，而生产环境可能会使用大量的缓存。

这些环境被触发的方式是通过前端控制器文件，如下面的部分示例所示：

```php
# web/app.php
…
$kernel = new AppKernel('prod', false);
…

# web/app_dev.php
…
$kernel = new AppKernel('dev', true);
…
```

测试环境在这里是缺失的，因为它只在运行自动化测试时使用，不能直接通过浏览器访问。

`app/AppKernel.php`文件实际上加载配置，无论是 YAML、XML 还是 PHP，如下面的代码片段所示：

```php
public function registerContainerConfiguration(LoaderInterface $loader)
{
  $loader->load($this->getRootDir().'/config/config_'.$this->getEnvironment().'.yml');
}
```

环境遵循相同的概念，每个环境导入基本配置文件，然后修改其值以满足特定环境的需求。

# bundle 系统

大多数流行的框架和平台都支持某种形式的模块、插件、扩展或 bundle。大多数情况下，区别实际上只是在命名上，而可扩展性和模块化的概念是相同的。在 Symfony 中，这些模块化块被称为 bundles。

bundles 在 Symfony 中是一等公民，因为它们支持其他组件可用的所有操作。在 Symfony 中，一切都是一个 bundle，甚至核心框架也是。bundles 使我们能够构建模块化的应用程序，其中给定功能的整个代码都包含在一个单独的目录中。

一个单一的 bundle 包含所有的 PHP 文件、模板、样式表、JavaScript 文件、测试以及其他任何内容在一个根目录中。

当我们首次设置我们的测试应用程序时，它为我们创建了一个`AppBundle`，位于`src`目录下。随着我们继续使用自动生成的 CRUD，我们看到我们的 bundle 获得了各种目录和文件。

要让 Symfony 注意到一个 bundle，需要将其添加到`app/AppKernel.php`文件中的`registerBundles`方法中，如下所示：

```php
public function registerBundles()
{
  $bundles = [
    new Symfony\Bundle\FrameworkBundle\FrameworkBundle(),
    new Symfony\Bundle\SecurityBundle\SecurityBundle(),
    new Symfony\Bundle\TwigBundle\TwigBundle(),
    new Symfony\Bundle\SwiftmailerBundle\SwiftmailerBundle(),
    new Doctrine\Bundle\DoctrineBundle\DoctrineBundle(),
    //…
    new AppBundle\AppBundle(),
  ];

  //…

  return $bundles;
}
```

创建一个新的 bundle 就像创建一个单个的 PHP 文件一样简单。让我们继续创建一个`src/TestBundle/TestBundle.php`文件，内容看起来像这样：

```php
namespace TestBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;

class TestBundle extends Bundle
{
  …
}
```

一旦文件就位，我们只需要通过`app/AppKernel.php`文件的`registerBundles`方法进行注册，如下所示：

```php
class AppKernel extends Kernel {
//…
  public function registerBundles() {
    $bundles = [
      // …
      new TestBundle\TestBundle(),
      // …
    ];
    return $bundles;
  }
  //…
}
```

创建 bundle 的更简单的方法是只需运行一个控制台命令，如下所示：

```php
**php bin/console generate:bundle --namespace=Foggyline/TestBundle**

```

这将触发一系列关于 bundle 的问题，最终导致 bundle 创建，看起来像下面的截图：

![bundle 系统](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_16.jpg)

一旦过程完成，将创建一个新的 bundle，其中包含几个目录和文件，如下面的截图所示：

![bundle 系统](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_17.jpg)

Bundle 生成器很友好地创建了控制器、依赖注入扩展、路由、准备服务配置、模板，甚至测试。由于我们选择共享我们的 bundle，Symfony 选择 XML 作为默认配置格式。依赖扩展简单地意味着我们可以通过在 Symfony 的主`config.yml`中使用`foggyline_test`作为根元素来访问我们的 bundle 配置。实际的`foggyline_test`元素在`DependencyInjection/Configuration.php`文件中定义。

# 数据库和 Doctrine

数据库几乎是每个 Web 应用程序的支柱。每当我们需要存储或检索数据时，我们都是通过数据库来实现的。在现代面向对象编程世界中的挑战是将数据库抽象化，以便我们的 PHP 代码与数据库无关。MySQL 可能是 PHP 世界中最知名的数据库。PHP 本身对与 MySQL 的工作有很好的支持，无论是通过`mysqli_*`扩展还是通过 PDO。然而，这两种方法都是针对 MySQL 特定的，离数据库太近。Doctrine 通过引入一层抽象解决了这个问题，使我们能够使用代表 MySQL 中的表、行及其关系的 PHP 对象进行工作。

Doctrine 完全与 Symfony 解耦，因此使用它完全是可选的。然而，它的一个很棒的地方是 Symfony 控制台提供了基于 Doctrine ORM 的自动生成 CRUD，就像我们在之前的示例中创建 Customer 实体时看到的那样。

一旦我们创建了项目，Symfony 就会为我们提供一个自动生成的`app/config/parameters.yml`文件。这个文件中，我们提供数据库访问信息，就像下面的示例中所示的那样。

```php
parameters:
database_host: 127.0.0.1
database_port: null
database_name: symfony
database_user: root
database_password: mysql
```

一旦我们配置了适当的参数，我们就可以使用控制台生成功能。

值得注意的是，该文件中的参数仅仅是一种约定，因为`app/config/config.yml`将它们拉入`doctrine dbal`配置，就像这里所示的那样。

```php
doctrine:
dbal:
  driver:   pdo_mysql
  host:     "%database_host%"
  port:     "%database_port%"
  dbname:   "%database_name%"
  user:     "%database_user%"
  password: "%database_password%"
  charset:  UTF8
```

Symfony 控制台工具允许我们根据这个配置来删除和创建数据库，在开发过程中非常方便，就像下面的代码块所示的那样。

```php
php bin/console doctrine:database:drop --force
php bin/console doctrine:database:create
```

我们之前看到控制台工具如何使我们能够创建实体并将它们映射到数据库表中。这将足够满足我们在本书中的需求。一旦我们创建了它们，我们需要能够对它们执行 CRUD 操作。如果我们忽略自动生成的 CRUD 控制器`src/AppBundle/Controller/CustomerController.php`文件，我们可以看到以下与 CRUD 相关的代码：

```php
// Fetch all entities
$customers = $em->getRepository('AppBundle:Customer')->findAll();

// Persist single entity (existing or new)
$em = $this->getDoctrine()->getManager();
$em->persist($customer);
$em->flush();

// Delete single entity
$em = $this->getDoctrine()->getManager();
$em->remove($customer);
$em->flush();
```

关于 Doctrine 还有很多要说的，这已经超出了本书的范围。更多信息可以在官方页面找到（[`www.doctrine-project.org`](http://www.doctrine-project.org)）。

# 测试

现在，测试已经成为每个现代 Web 应用程序的一个组成部分。通常，测试这个术语意味着单元测试和功能测试。单元测试是关于测试我们的 PHP 类。每个单独的 PHP 类被认为是一个单元，因此称为单元测试。另一方面，功能测试测试我们应用程序的各个层面，通常集中在测试整体功能，比如登录或注册过程。

PHP 生态系统有一个很棒的单元测试框架叫做**PHPUnit**，可以在[`phpunit.de`](https://phpunit.de)下载。它使我们能够编写主要是单元测试，但也包括功能类型测试。Symfony 的一个很棒的地方是它内置了对 PHPUnit 的支持。

在我们开始运行 Symfony 的测试之前，我们需要确保已安装 PHPUnit 并且可以作为控制台命令使用。当执行时，PHPUnit 会自动尝试从当前工作目录中的`phpunit.xml`或`phpunit.xml.dist`中读取测试配置，如果可用的话。默认情况下，Symfony 在其根文件夹中带有一个`phpunit.xml.dist`文件，因此`phpunit`命令可以获取其测试配置。

以下是默认`phpunit.xml.dist`文件的部分示例：

```php
<phpunit … >
  <php>
    <ini name="error_reporting" value="-1" />
    <server name="KERNEL_DIR" value="app/" />
  </php>

  <testsuites>
    <testsuite name="Project Test Suite">
      <directory>tests</directory>
    </testsuite>
  </testsuites>

  <filter>
    <whitelist>
      <directory>src</directory>
      <exclude>
        <directory>src/*Bundle/Resources</directory>
        <directory>src/*/*Bundle/Resources</directory>
        <directory>src/*/Bundle/*Bundle/Resources</directory>
      </exclude>
    </whitelist>
  </filter>
</phpunit>
```

`testsuites`元素定义了包含所有测试的目录 tests。`filter`元素及其子元素用于配置代码覆盖报告的白名单。`php`元素及其子元素用于配置 PHP 设置、常量和全局变量。

对于像我们这样的默认项目运行`phpunit`命令将产生以下输出：

![测试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_05_18.jpg)

请注意，bundle 测试不会自动被捡起。我们自动创建的`src/AppBundle/Tests/Controller/CustomerControllerTest.php`文件在我们使用自动生成的 CRUD 时自动创建，但没有被执行。这不是因为它的内容默认被注释掉，而是因为`bundle`测试目录对`phpunit`不可见。为了使其执行，我们需要通过以下方式扩展`phpunit.xml.dist`文件，将目录添加到`testsuite`：

```php
<testsuites>
  <testsuite name="Project Test Suite">
    <directory>tests</directory>
    <directory>src/AppBundle/Tests</directory>
  </testsuite>
</testsuites>
```

根据我们构建应用程序的方式，我们可能希望将所有 bundle 添加到`testsuite`列表中，即使我们计划独立分发 bundle。

关于测试还有很多要说的。随着我们进一步学习并覆盖各个 bundle 的需求，我们将逐步进行。目前，了解如何触发测试以及如何向测试配置添加新位置就足够了。

# 验证

验证在现代应用程序中起着至关重要的作用。谈到 Web 应用程序时，我们可以说我们区分两种主要类型的验证；表单数据和持久化数据验证。通过 Web 表单从用户那里获取输入应该进行验证，与进入数据库的任何持久化数据一样。

Symfony 通过提供基于 JSR 303 Bean Validation 的验证组件在这方面表现出色，该组件起草并可在[`beanvalidation.org/1.0/spec/`](http://beanvalidation.org/1.0/spec/)上找到。如果我们回顾一下我们的`app/config/config.yml`，在`framework`根元素下，我们可以看到`validation`服务默认已启用：

```php
framework:
  validation:{ enable_annotations: true }
```

我们可以通过简单地通过`$this->get('validator')`表达式调用任何控制器类中的验证服务，如下例所示：

```php
$customer = new Customer();

$validator = $this->get('validator');

$errors = $validator->validate($customer);

if (count($errors) > 0) {
  // Handle error state
}

// Handle valid state
```

上面示例的问题在于验证永远不会返回任何错误。原因是我们的类上没有设置任何断言。控制台自动生成的 CRUD 实际上没有在我们的`Customer`类上定义任何约束。我们可以通过尝试添加新客户并在电子邮件字段中输入任何文本来确认这一点，因为我们可以看到电子邮件不会被验证。

让我们继续编辑`src/AppBundle/Entity/Customer.php`文件，通过向`$email`属性添加`@Assert\Email`函数，就像这里所示的那样：

```php
//…
use Symfony\Component\Validator\Constraints as Assert;
//…
class Customer
{
  //…
  /**
  * @var string
  *
  * @ORM\Column(name="email", type="string", length=255, unique=true)
  * @Assert\Email(
    *      checkMX = true,
    *      message = "Email '{{ value }}' is invalid.",
    * )
    */
  private $email;
  //…
}
```

断言约束的好处是它们像函数一样接受参数。因此，我们可以根据特定需求对单个约束进行微调。如果我们现在尝试跳过或添加一个错误的电子邮件地址，我们将收到类似**Email "john@gmail.test" is invalid**的消息。

有许多可用的约束，我们可以在[`symfony.com/doc/current/book/validation.html`](http://symfony.com/doc/current/book/validation.html)页面上查阅完整列表。

约束可以应用于类属性或公共 getter 方法。虽然属性约束最常见且易于使用，但 getter 方法约束允许我们指定更复杂的验证规则。

让我们来看一下`src/AppBundle/Controller/CustomerController.php`文件中的`newAction`方法：

```php
$customer = new Customer();
$form = $this->createForm('AppBundle\Form\CustomerType', $customer);
$form->handleRequest($request);

if ($form->isSubmitted() && $form->isValid()) {
// …
```

在这里，我们看到一个`CustomerType`表单实例被绑定到`Customer`实例。实际的 GET 或 POST 请求数据通过`handleRequest`方法传递给表单的一个实例。现在，表单能够理解实体验证约束，并通过其`isValid`方法调用做出适当的响应。这意味着我们不必手动使用验证服务进行验证，表单可以为我们完成这项工作。

在我们逐个捆绑包进展的过程中，我们将继续扩展验证功能。

# 总结

在本章中，我们涉及了一些使 Symfony 如此出色的重要功能。控制器、模板、Doctrine、ORM、表单和验证构成了完整的数据呈现和持久化解决方案。我们已经看到了每个组件背后的灵活性和强大功能。捆绑包系统通过将这些组件封装成单独的小应用程序或模块，进一步提升了功能。现在，我们能够完全控制传入的 HTTP 请求，操作数据存储，并向用户呈现数据，所有这些都在一个捆绑包内完成。

在接下来的章节中，我们将利用前几章获得的见解和知识，最终根据要求开始构建我们的模块化应用程序。


# 第六章：构建核心模块

到目前为止，我们已经熟悉了 PHP 7 的最新变化，设计模式，设计原则和流行的 PHP 框架。我们还更详细地了解了 Symfony 作为我们未来的框架选择。现在我们终于达到了一个可以开始构建我们的模块化应用程序的地步。使用 Symfony 构建模块化应用程序是通过 bundles 机制完成的。从术语上讲，从这一点开始，我们将考虑 bundle 和模块是相同的东西。

在本章中，我们将涵盖以下与核心模块相关的主题：

+   要求

+   依赖关系

+   实施

+   单元测试

+   功能测试

# 要求

回顾第四章, *模块化网络商店应用的需求规范*，以及那里提出的线框图，我们可以概述这个模块将具有的一些要求。核心模块将用于设置通用的、应用程序范围的功能，如下：

+   将 Foundation CSS for sites 包含到项目中

+   构建主页

+   构建其他静态页面

+   构建一个联系我们页面

+   设置基本防火墙，其中管理员用户可以管理稍后其他模块生成的 CRUD

# 依赖关系

核心模块本身并不依赖于我们将作为本书一部分编写的其他模块，或者 Symfony 标准安装之外的任何第三方模块。

# 实施

我们首先创建一个全新的 Symfony 项目，运行以下控制台命令：

```php
**symfony new shop**

```

这将创建一个新的`shop`目录，其中包含在浏览器中运行我们的应用程序所需的所有文件。在这些文件和目录中，有一个`src/AppBundle`目录，实际上就是我们的核心模块。在我们可以在浏览器中运行应用程序之前，我们需要将新创建的`shop`目录映射到一个主机名，比如说`shop.app`，这样我们就可以通过`http://shop.app` URL 在浏览器中访问它。完成这一步后，如果我们打开`http://shop.app`，我们应该看到**欢迎来到 Symfony 3.1.0**的屏幕，如下所示：

![实现](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_06_05.jpg)

虽然我们目前还没有数据库的需求，但我们稍后将开发的其他模块将假定数据库连接，因此从一开始就进行设置是值得的。我们通过配置`app/config/parameters.yml`文件来配置正确的数据库连接参数。

然后我们从[`foundation.zurb.com/sites.html`](http://foundation.zurb.com/sites.html)下载 Foundation for Sites。下载完成后，我们需要解压并将`/js`和`/css`目录复制到`Symfony /web`目录中，如下面的屏幕截图所示：

![实现](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_06_06.jpg)

### 注意

值得注意的是，我们在模块中使用的 Foundation 是一个简化的设置，我们只是使用 CSS 和 JavaScript 文件，而没有设置任何与 Sass 相关的内容。

在 Foundation CSS 和 JavaScript 文件就位后，我们编辑`app/Resources/views/base.html.twig`文件如下：

```php
<!doctype html>
<html class="no-js"lang="en">
  <head>
    <meta charset="utf-8"/>
    <meta http-equiv="x-ua-compatible" content="ie=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>{% block title %}Welcome!{% endblock %}</title>
    <link rel="stylesheet"href="{{ asset('css/foundation.css') }}"/>
    {% block stylesheets%}{% endblock %}
  </head>
  <body>
    <!-- START BODY -->
    <!-- TOP-MENU -->
    <!-- SYSTEM-WIDE-MESSAGES -->
    <!-- PER-PAGE-BODY -->
    <!-- FOOTER -->
    <!-- START BODY -->
    <script src="{{ asset('js/vendor/jquery.js') }}"></script>
    <script src="{{ asset('js/vendor/what-input.js') }}"></script>
    <script src="{{ asset('js/vendor/foundation.js') }}"></script>
    <script>
      $(document).foundation();
    </script>
    {% block javascripts%}{% endblock %}
  </body>
</html>
```

在这里，我们设置整个头部和 body 结束区域，以及所有必要的 CSS 和 JavaScript 加载。Twig 的`asset`标签帮助我们构建 URL 路径，我们只需传递 URL 路径本身，它就会为我们构建一个完整的 URL。关于页面的实际内容，这里有几件事情需要考虑。我们将如何构建类别、客户和结账菜单？在这一点上，我们还没有这些模块，我们也不想让它们成为核心模块的必需品。那么我们如何解决还不存在的东西的挑战呢？

对于类别、客户和结账菜单，我们可以为每个菜单项定义全局 Twig 变量，然后用这些变量来渲染菜单。这些变量将通过适当的服务进行填充。由于核心包不知道未来的目录、客户和结账模块，我们将首先创建一些虚拟服务，并将它们连接到全局 Twig 变量。稍后，当我们开发目录、客户和结账模块时，这些模块将覆盖适当的服务，从而为菜单提供正确的值。

这种方法可能不完全符合模块化应用程序的概念，但对我们的需求来说已经足够了，因为我们并没有硬编码任何依赖关系。

我们首先在`app/config/config.yml`文件中添加以下条目：

```php
twig:
# ...
globals:
category_menu: '@category_menu'
customer_menu: '@customer_menu'
checkout_menu: '@checkout_menu'
products_bestsellers: '@bestsellers'
products_onsale: '@onsale'
```

`category_menu_items`、`customer_menu_items`、`checkout_menu_items`、`products_bestsellers`和`products_onsale`变量成为全局 Twig 变量，我们可以在任何 Twig 模板中使用，如下例所示：

```php
<ul>
  {% for category in category_menu.getItems() %}
  <li>{{ category.name }}</li>
  {% endfor %}
</ul>
```

Twig 全局变量`config`中的`@`字符用于表示服务名称的开始。这是将为我们的 Twig 变量提供值对象的服务。接下来，我们继续修改`app/config/services.yml`，创建`category_menu`、`customer_menu`、`checkout_menu`、`bestsellers`和`onsale`服务：

```php
services:
category_menu:
  class: AppBundle\Service\Menu\Category
customer_menu:
  class: AppBundle\Service\Menu\Customer
checkout_menu:
  class: AppBundle\Service\Menu\Checkout
bestsellers:
  class: AppBundle\Service\Menu\BestSellers
onsale:
  class: AppBundle\Service\Menu\OnSale
```

此外，我们在`src/AppBundle/Service/Menu/`目录下创建列出的每个服务类。我们首先从`src/AppBundle/Service/Menu/Bestsellers.php`文件开始，内容如下：

```php
namespace AppBundle\Service\Menu;

class BestSellers {
  public function getItems() {
    // Note, this can be arranged as per some "Product"interface, so to know what dummy data to return
    return array(
      ay('path' =>'iphone', 'name' =>'iPhone', 'img' =>'/img/missing-image.png', 'price' => 49.99, 'add_to_cart_url' =>'#'),
      array('path' =>'lg', 'name' =>'LG', 'img' =>
        '/img/missing-image.png', 'price' => 19.99, 'add_to_cart_url' =>'#'),
      array('path' =>'samsung', 'name' =>'Samsung', 'img'=>'/img/missing-image.png', 'price' => 29.99, 'add_to_cart_url' =>'#'),
      array('path' =>'lumia', 'name' =>'Lumia', 'img' =>'/img/missing-image.png', 'price' => 19.99, 'add_to_cart_url' =>'#'),
      array('path' =>'edge', 'name' =>'Edge', 'img' =>'/img/missing-image.png', 'price' => 39.99, 'add_to_cart_url' =>'#'),
    );
  }
}
```

然后，我们添加`src/AppBundle/Service/Menu/Category.php`文件，内容如下：

```php
class Category {
  public function getItems() {
    return array(
      array('path' =>'women', 'label' =>'Women'),
      array('path' =>'men', 'label' =>'Men'),
      array('path' =>'sport', 'label' =>'Sport'),
    );
  }
}
```

接下来，我们添加`src/AppBundle/Service/Menu/Checkout.php`文件，内容如下所示：

```php
class Checkout
{
  public function getItems()
  {
     // Initial dummy menu
     return array(
       array('path' =>'cart', 'label' =>'Cart (3)'),
       array('path' =>'checkout', 'label' =>'Checkout'),
    );
  }
}
```

完成后，我们将继续向`src/AppBundle/Service/Menu/Customer.php`文件添加以下内容：

```php
class Customer
{
  public function getItems()
  {
    // Initial dummy menu
    return array(
      array('path' =>'account', 'label' =>'John Doe'),
      array('path' =>'logout', 'label' =>'Logout'),
    );
  }
}
```

然后我们添加`src/AppBundle/Service/Menu/OnSale.php`文件，内容如下：

```php
class OnSale
{
  public function getItems()
  {
    // Note, this can be arranged as per some "Product" interface, so to know what dummy data to return
    return array(
      array('path' =>'iphone', 'name' =>'iPhone', 'img' =>'/img/missing-image.png', 'price' => 19.99, 'add_to_cart_url' =>'#'),
      array('path' =>'lg', 'name' =>'LG', 'img' =>'/img/missing-image.png', 'price'      => 29.99, 'add_to_cart_url' =>'#'),
      array('path' =>'samsung', 'name' =>'Samsung', 'img'=>'/img/missing-image.png', 'price' => 39.99, 'add_to_cart_url' =>'#'),
      array('path' =>'lumia', 'name' =>'Lumia', 'img' =>'/img/missing-image.png', 'price' => 49.99, 'add_to_cart_url' =>'#'),
      array('path' =>'edge', 'name' =>'Edge', 'img' =>'/img/missing-image.png', 'price' => 69.99, 'add_to_cart_url' =>'#'),
    ;
  }
}
```

我们现在已经定义了五个全局 Twig 变量，将用于构建我们的应用程序菜单。尽管变量现在连接到一个返回的虚拟数组的虚拟服务，但我们已经有效地将菜单项解耦到其他即将构建的模块中。当我们稍后开始构建我们的目录、客户和结账模块时，我们只需编写一个服务覆盖，并使用真实的项目填充菜单项数组。这将是理想的情况。

### 注意

理想情况下，我们希望我们的服务按照某种接口返回数据，以确保谁覆盖或扩展它都是通过接口来实现的。由于我们试图保持我们的应用程序最小化，我们将继续使用简单的数组。

现在我们可以回到我们的`app/Resources/views/base.html.twig`文件，用以下内容替换前面代码中的`<!-- TOP-MENU -->`：

```php
<div class="title-bar" data-responsive-toggle="appMenu" data-hide-for="medium">
  <button class="menu-icon" type="button" data-toggle></button>
  <div class="title-bar-title">Menu</div>
</div>

<div class="top-bar" id="appMenu">
  <div class="top-bar-left">
    {# category_menu is global twig var filled from service, and later overriden by another module service #}
    <ul class="menu">
      <li><a href="{{ path('homepage') }}">HOME</a></li>
        {% block category_menu %}
        {% for link in category_menu.getItems() %}
      <li><a href="{{ link.path }}">{{ link.label }}</li></a>
      {% endfor %}
      {% endblock %}
    </ul>
  </div>
  <div class="top-bar-right">
    <ul class="menu">
      {# customer_menu is global twig var filled from service, and later overriden by another module service #}
      {% block customer_menu %}
      {% for link in customer_menu.getItems() %}
      <li><a href="{{ link.path }}">{{ link.label }}</li></a>
      {% endfor %}
      {% endblock %}
      {# checkout_menu is global twig var filled from service, and later overriden by another module service #}
      {% block checkout_menu %}
      {% for link in checkout_menu.getItems() %}
      <li><a href="{{ link.path }}">{{ link.label }}</li></a>
      {% endfor %}
      {% endblock %}
    </ul>
  </div>
</div>
```

然后我们用以下内容替换`<!-- SYSTEM-WIDE-MESSAGES -->`：

```php
<div class="row column">
  {% for flash_message in app.session.flashBag.get('alert') %}
  <div class="alert callout">
    {{ flash_message }}
  </div>
  {% endfor %}
  {% for flash_message in app.session.flashBag.get('warning') %}
  <div class="warning callout">
    {{ flash_message }}
  </div>
  {% endfor %}
  {% for flash_message in app.session.flashBag.get('success') %}
  <div class="success callout">
    {{ flash_message }}
  </div>
  {% endfor %}
</div>
```

我们用以下内容替换`<!-- PER-PAGE-BODY -->`：

```php
<div class="row column">
  {% block body %}{% endblock %}
</div>
```

我们用以下内容替换`<!-- FOOTER -->`：

```php
<div class="row column">
  <ul class="menu">
    <li><a href="{{ path('about') }}">About Us</a></li>
    <li><a href="{{ path('customer_service') }}">Customer Service</a></li>
    <li><a href="{{ path('privacy_cookie') }}">Privacy and Cookie Policy</a></li>
    <li><a href="{{ path('orders_returns') }}">Orders and Returns</a></li>
    <li><a href="{{ path('contact') }}">Contact Us</a></li>
  </ul>
</div>
```

现在我们可以继续编辑`src/AppBundle/Controller/DefaultController.php`文件，并添加以下代码：

```php
/**
 * @Route("/", name="homepage")
 */
public function indexAction(Request $request)
{
  return $this->render('AppBundle:default:index.html.twig');
}

/**
 * @Route("/about", name="about")
 */
public function aboutAction()
{
  return $this->render('AppBundle:default:about.html.twig');
}

/**
 * @Route("/customer-service", name="customer_service")
 */
public function customerServiceAction()
{
  return $this->render('AppBundle:default:customer-service.html.twig');
}

/**
 * @Route("/orders-and-returns", name="orders_returns")
 */
public function ordersAndReturnsAction()
{
  return $this->render('AppBundle:default:orders-returns.html.twig');
}

/**
 * @Route("/privacy-and-cookie-policy", name="privacy_cookie")
 */
public function privacyAndCookiePolicyAction()
{
  return $this->render('AppBundle:default:privacy-cookie.html.twig');
}
```

位于`src/AppBundle/Resources/views/default`目录中的所有使用的模板文件（`about.html.twig`、`customer-service.html.twig`、`orders-returns.html.twig`、`privacy-cookie.html.twig`）可以类似地定义如下：

```php
{% extends 'base.html.twig' %}

{% block body %}
<div class="row">
  <h1>About Us</h1>
</div>
<div class="row">
  <p>Loremipsum dolor sit amet, consecteturadipiscingelit...</p>
</div>
{% endblock %}
```

在这里，我们只是将标题和内容包装到带有`row`类的`div`元素中，以便给它一些结构。结果应该是类似于这里显示的页面：

![实现](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_06_04.jpg)

**联系我们**页面需要不同的方法，因为它将包含一个表单。为了构建一个表单，我们使用 Symfony 的`Form`组件，通过向`src/AppBundle/Controller/DefaultController.php`文件添加以下内容：

```php
/**
 * @Route("/contact", name="contact")
 */
public function contactAction(Request $request) {

  // Build a form, with validation rules in place
  $form = $this->createFormBuilder()
  ->add('name', TextType::class, array(
    'constraints' => new NotBlank()
  ))
  ->add('email', EmailType::class, array(
    'constraints' => new Email()
  ))
  ->add('message', TextareaType::class, array(
    'constraints' => new Length(array('min' => 3))
  ))
   ->add('save', SubmitType::class, array(
    'label' =>'Reach Out!',
    'attr' => array('class' =>'button'),
  ))
  ->getForm();

  // Check if this is a POST type request and if so, handle form
  if ($request->isMethod('POST')) {
    $form->handleRequest($request);

    if ($form->isSubmitted() && $form->isValid()) {
      $this->addFlash(
        'success',
        'Your form has been submitted. Thank you.'
      );

      // todo: Send an email out...

      return $this->redirect($this->generateUrl('contact'));
    }
  }

  // Render "contact us" page
  return $this->render('AppBundle:default:contact.html.twig', array(
    'form' => $form->createView()
  ));
}
```

我们首先通过表单构建器构建了一个表单。`add`方法接受字段定义和字段约束，验证可以基于它们进行。然后我们添加了对 HTTP POST 方法的检查，如果是这种情况，我们将使用请求参数填充表单并对其进行验证。

通过`contactAction`方法，我们仍然需要一个模板文件来实际渲染表单。我们通过添加`src/AppBundle/Resources/views/default/contact.html.twig`文件并添加以下内容来实现：

```php
{% extends 'base.html.twig' %}

{% block body %}

<div class="row">
  <h1>Contact Us</h1>
</div>

<div class="row">
  {{ form_start(form) }}
  {{ form_widget(form) }}
  {{ form_end(form) }}
</div>
{% endblock %}
```

根据这些标签，Twig 为我们处理了表单渲染。结果的浏览器输出如下所示：

![实现](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_06_03.jpg)

我们几乎已经准备好所有的页面了。但是还有一件事缺失，就是我们主页的正文区域。与其他具有静态内容的页面不同，这个页面实际上是动态的，因为它列出了畅销书和特价商品。这些数据预计来自其他模块，目前还不可用。但是，这并不意味着我们不能为它们准备虚拟占位符。让我们继续编辑`app/Resources/views/default/index.html.twig`文件如下：

```php
{% extends 'base.html.twig' %}
{% block body %}
<!--products_bestsellers -->
<!--products_onsale -->
{% endblock %}
```

现在我们需要用以下内容替换`<!-- products_bestsellers -->`：

```php
{% if products_bestsellers %}
<h2 class="text-center">Best Sellers</h2>
<div class="row products_bestsellers text-center small-up-1 medium-up-3 large-up-5" data-equalizer data-equalize-by- row="true">
  {% for product in products_bestsellers.getItems() %}
  <div class="column product">
    <img src="{{ asset(product.img) }}" alt="missing image"/>
    <a href="{{ product.path }}">{{ product.name }}</a>
    <div>${{ product.price }}</div>
    <div><a class="small button"href="{{ product.add_to_cart_url }}">Add to Cart</a></div>
  </div>
  {% endfor %}
</div>
{% endif %}
```

现在我们需要用以下内容替换`<!-- products_onsale -->`：

```php
{% if products_onsale %}
<h2 class="text-center">On Sale</h2>
<div class="row products_onsale text-center small-up-1 medium-up-3 large-up-5" data-equalizer data-equalize-by-row="true">
  {% for product in products_onsale.getItems() %}
  <div class="column product">
    <img src="{{ asset(product.img) }}" alt="missing image"/>
    <a href="{{ product.path }}">{{ product.name }}</a>
  <div>${{ product.price }}</div>
  <div><a class="small button"href="{{ product.add_to_cart_url }}">Add to Cart</a></div>
  </div>
  {% endfor %}
</div>
{% endif %}
```

### 提示

[`dummyimage.com`](http://dummyimage.com)使我们能够为我们的应用程序创建占位图像。

此时，我们应该看到如下所示的主页：

![实现](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_06_02.jpg)

## 配置应用程序范围的安全性

作为应用程序范围安全的一部分，我们试图设置一些基本保护，防止未来的客户或任何其他用户能够访问和使用未来自动生成的 CRUD 控制器。我们通过修改`app/config/security.yml`文件来实现这一点。`security.yml`文件有几个组件需要处理：防火墙、访问控制、提供程序和编码器。如果我们观察先前测试应用程序中自动生成的 CRUD，就会清楚地看到我们需要保护以下内容，以防止客户访问：

+   `GET|POST /new`

+   `GET|POST /{id}/edit`

+   `DELETE /{id}`

换句话说，所有在 URL 中包含`/new`和`/edit`，以及所有使用`DELETE`方法的内容，都需要受到客户的保护。考虑到这一点，我们将使用 Symfony 安全功能创建一个具有`ROLE_ADMIN`角色的内存用户。然后，我们将创建一个访问控制列表，只允许`ROLE_ADMIN`访问我们刚刚提到的资源，并创建一个防火墙，当我们尝试访问这些资源时触发 HTTP 基本身份验证登录表单。

使用内存提供程序意味着在我们的`security.yml`文件中硬编码用户。对于我们应用程序的目的，我们将为管理员类型的用户这样做。然而，实际密码不需要硬编码。假设我们将使用`1L6lllW9zXg0`作为密码，让我们跳转到控制台并输入以下命令：

```php
**php bin/console security:encode-password**

```

这将产生以下输出。

![配置应用程序范围的安全性](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_06_01.jpg)

我们现在可以通过添加内存提供程序并将生成的编码密码复制粘贴到其中来编辑`security.yml`，如下所示：

```php
security:
    providers:
        in_memory:
            memory:
                users:
                    john:
                        password: $2y$12$DFozWehwPkp14sVXr7.IbusW8ugvmZs9dQMExlggtyEa/TxZUStnO
                        roles: 'ROLE_ADMIN'
```

在这里，我们定义了一个具有`ROLE_ADMIN`角色和编码`1L6lllW9zXg0`密码的用户`john`。

一旦我们有了提供程序，我们就可以继续在`security.yml`文件中添加编码器。否则 Symfony 将不知道如何处理分配给`john`用户的当前密码：

```php
security:
    encoders:
        Symfony\Component\Security\Core\User\User:
            algorithm: bcrypt
            cost: 12
```

然后我们添加防火墙如下：

```php
security:
    firewalls:
        guard_new_edit:
            pattern: /(new)|(edit)
            methods: [GET, POST]
            anonymous: ~
            http_basic: ~
       guard_delete:
           pattern: /
           methods: [DELETE]
           anonymous: ~
           http_basic: ~
```

`guard_new_edit`和`guard_delete`是我们两个应用程序防火墙的自由名称。`guard_new_edit`防火墙将拦截包含`/new`或`/edit`字符串的任何路由的所有 GET 和 POST 请求。`guard_delete`防火墙将拦截任何 URL 上的任何 HTTP `DELETE`方法。一旦这些防火墙启动，它们将显示一个 HTTP 基本身份验证表单，并且只有在用户登录后才允许访问。

然后我们按以下方式添加访问控制列表：

```php
security:
    access_control:
      # protect any possible auto-generated CRUD actions from everyone's access
      - { path: /new, roles: ROLE_ADMIN }
      - { path: /edit, roles: ROLE_ADMIN }
      - { path: /, roles: ROLE_ADMIN, methods: [DELETE] }
```

有了这些条目，任何试图访问任何 URL 的人，只要符合`access_control`下定义的任何模式，都将看到浏览器登录，如下所示：

![配置应用程序范围的安全性](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_06_07.jpg)

唯一可以登录的用户是`john`，密码是`1L6lllW9zXg0`。一旦认证，用户可以访问所有的 CRUD 链接。这对于我们简单的应用程序应该足够了。

# 单元测试

我们当前的模块除了控制器类和虚拟服务类之外没有特定的类。因此，我们不会在这里费心进行单元测试。

# 功能测试

在我们开始编写功能测试之前，我们需要通过将我们的 bundle `Tests`目录添加到`testsuite`路径中来编辑`phpunit.xml.dist`文件，如下所示：

```php
<testsuites>
  <testsuite name="Project Test Suite">
    <-- ... other elements ... -->
      <directory>src/AppBundle/Tests</directory>
    <-- ... other elements ... -->
  </testsuite>
</testsuites>
```

我们的功能测试将只覆盖一个控制器，因为我们没有其他控制器。我们首先创建一个`src/AppBundle/Tests/Controller/DefaultControllerTest.php`文件，内容如下：

```php
namespace AppBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class DefaultControllerTest extends WebTestCase
{
//…
}
```

下一步是测试我们的每一个控制器动作。至少我们应该测试页面内容是否被正确输出。

### 提示

为了在我们的 IDE 中获得自动完成，我们可以从官方网站[`phpunit.de`](https://phpunit.de)下载`PHPUnitphar`文件。下载后，我们可以简单地将其添加到项目的根目录，这样 IDE（如**PHPStorm**）就可以识别它。这样就可以轻松地跟踪所有`$this->assert`方法调用及其参数。

我们想要测试的第一件事是我们的主页。我们通过向`DefaultControllerTest`类的主体添加以下内容来实现这一点。

```php
public function testHomepage()
{
  // @var \Symfony\Bundle\FrameworkBundle\Client
  $client = static::createClient();
  /** @var \Symfony\Component\DomCrawler\Crawler */
  $crawler = $client->request('GET', '/');

  // Check if homepage loads OK
  $this->assertEquals(200, $client->getResponse()->getStatusCode());

  // Check if top bar left menu is present
  $this->assertNotEmpty($crawler->filter('.top-bar-left li')->count());

  // Check if top bar right menu is present
  $this->assertNotEmpty($crawler->filter('.top-bar-right li')->count());

  // Check if footer is present
  $this->assertNotEmpty($crawler->filter('.footer li')->children()->count());
}
```

在这里，我们一次检查了几件事。我们检查页面是否正常加载，HTTP 200 状态。然后我们抓取左右菜单并计算它们的项目数，以查看它们是否有任何项目。如果所有单独的检查都通过了，`testHomepage`测试就被认为是通过的。

我们通过向`DefaultControllerTest`类添加以下内容来进一步测试所有静态页面：

```php
public function testStaticPages()
{
  // @var \Symfony\Bundle\FrameworkBundle\Client
  $client = static::createClient();
  /** @var \Symfony\Component\DomCrawler\Crawler */

  // Test About Us page
  $crawler = $client->request('GET', '/about');
  $this->assertEquals(200, $client->getResponse()->getStatusCode());
  $this->assertContains('About Us', $crawler->filter('h1')->text());

  // Test Customer Service page
  $crawler = $client->request('GET', '/customer-service');
  $this->assertEquals(200, $client->getResponse()->getStatusCode());
  $this->assertContains('Customer Service', $crawler->filter('h1')->text());

  // Test Privacy and Cookie Policy page
  $crawler = $client->request('GET', '/privacy-and-cookie-policy');
  $this->assertEquals(200, $client->getResponse()->getStatusCode());
  $this->assertContains('Privacy and Cookie Policy', $crawler->filter('h1')->text());

  // Test Orders and Returns page
  $crawler = $client->request('GET', '/orders-and-returns');
  $this->assertEquals(200, $client->getResponse()->getStatusCode());
  $this->assertContains('Orders and Returns', $crawler->filter('h1')->text());

  // Test Contact Us page
  $crawler = $client->request('GET', '/contact');
  $this->assertEquals(200, $client->getResponse()->getStatusCode());
  $this->assertContains('Contact Us', $crawler->filter('h1')->text());
}
```

在这里，我们对所有页面运行相同的`assertEquals`和`assertContains`函数。我们只是试图确认每个页面是否以 HTTP 200 加载，并且页面标题的正确值是否返回，也就是`h1`元素。

最后，我们需要在`DefaultControllerTest`类中添加以下内容来处理表单提交测试：

```php
public function testContactFormSubmit()
{
  // @var \Symfony\Bundle\FrameworkBundle\Client
  $client = static::createClient();
  /** @var \Symfony\Component\DomCrawler\Crawler */
  $crawler = $client->request('GET', '/contact');

  // Find a button labeled as "Reach Out!"
  $form = $crawler->selectButton('Reach Out!')->form();

  // Note this does not validate form, it merely tests against submission and response page
  $crawler = $client->submit($form);
  $this->assertEquals(200, $client->getResponse()->getStatusCode());
}
```

在这里，我们通过其**Reach Out!**提交按钮抓取表单元素。一旦获取表单，我们就在客户端上触发`submit`方法，将元素实例传递给它。值得注意的是，这里并没有测试实际的表单验证。即使如此，提交的表单应该会导致 HTTP 200 状态。

这些测试是有说服力的。如果我们愿意，我们可以编写更加健壮的测试，因为有许多元素可以进行测试。

# 总结

在本章中，我们构建了我们的第一个模块，或者在 Symfony 术语中称为 bundle。该模块本身并不是真正松散耦合的，因为它依赖于`app`目录中的一些内容，比如`app/Resources/views/base.html.twig`布局模板。当涉及核心模块时，我们可以这样做，因为它们只是我们为其余模块设置的基础。

在接下来的章节中，我们将构建一个目录模块。这将是我们网店应用程序的基础。
