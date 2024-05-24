# 精通 PHP7（四）

> 原文：[`zh.annas-archive.org/md5/c80452b19d206124b22230f7a590b2c3`](https://zh.annas-archive.org/md5/c80452b19d206124b22230f7a590b2c3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：常见的设计模式

那些刚接触软件开发的人往往把精力集中在掌握编程语言上。一旦突破了这个障碍，就是时候拥抱**设计模式**了，因为写高质量和复杂的软件几乎不可能没有它们。设计模式主要是由经验丰富的开发者使用，它们代表了在我们的应用程序中面临的常见挑战的一种成熟的解决方案。成功应用设计模式很可能会导致更具可扩展性、可重用性、可维护性和可适应性的代码。

本章中的示例并不是要被复制粘贴的。它们只是用来代表设计模式的一种可能实现。毕竟，现实生活中的应用程序都是关于细节的。此外，还有许多其他设计模式，随着技术和编程范式的转变，还会不断有新的设计模式被发明出来。

在本章中，我们将看一下在 PHP 中设计模式的几种可能实现：

+   基本模式

+   注册表模式

+   创建模式

+   单例模式

+   原型模式

+   抽象工厂模式

+   建造者模式

+   对象池模式

+   行为模式

+   策略模式

+   观察者模式

+   懒初始化模式

+   责任链模式

+   结构模式

+   装饰者模式

# 基本模式

在接下来的部分，我们将看一下基本模式：注册表模式。

# 注册表模式

注册表模式是一个有趣的模式。它允许我们存储和检索对象以供以后使用。存储和检索的过程是基于我们定义的键。根据数据范围的不同，键和对象的关联是全局的，跨进程、线程或会话，允许我们在数据范围内的任何地方检索对象。

以下示例演示了可能的注册表模式实现：

```php
<?php   class Registry {
  private
  $registry = [];    public
 function get($key)
 {  if (isset($this->registry[$key])) {
  return $this->registry[$key];
 }  return null;
 }    public
 function set($key, $value, $graceful = false)
 {  if (isset($this->registry[$key])) {
  if ($graceful) {
  return;
 }  throw new \RuntimeException('Registry key "' . $key . '"already exists');
 }  $this->registry[$key] = $value;
 }    public
 function remove($key)
 {  if (isset($this->registry[$key])) {
  unset($this->registry[$key]);
 } }    public
 function __destruct()
 {  $keys = array_keys($this->registry);
  array_walk($keys, [$this, 'remove']);
 } }   // Client use class User {
  public $name; }   $user1 = new User(); $user1->name = 'John'; $user2 = new User(); $user2->name = 'Marc';   $registry = new Registry(); $registry->set('employee', $user1); $registry->set('director', $user2); echo $registry->get('director')->name; // Marc

```

我们的`Registry`类实现有三个关键方法：`get()`、`set()`、`remove()`。`set()`方法允许基于`$graceful`参数进行优雅的行为；否则，它会为现有的键触发`RuntimeException`。我们还定义了一个`__destruct`方法，作为一种清理机制，当`$registry`实例被销毁时，它会移除注册表中的每个项目。

# 创建模式

在这一部分，我们将看一下创建模式，比如单例、原型、抽象工厂和构建者模式。

# 单例模式

单例模式是大多数开发人员学习的第一个设计模式。这个设计模式的目标是将类实例化的次数限制为只有一个。这意味着对类使用`new`关键字将始终返回一个相同的对象实例。这是一个强大的概念，它允许我们实现各种应用程序范围的对象，比如记录器、邮件发送器、注册表和其他功能的单例。然而，正如我们很快会看到的，我们将完全避免使用`new`关键字，并通过静态类方法实例化对象。

以下示例演示了可能的单例模式实现：

```php
<?php   class Logger {
  private static $instance;    const TYPE_ERROR = 'error';
  const TYPE_WARNING = 'warning';
  const TYPE_NOTICE = 'notice';    protected function __construct()
 {  // empty?!
  }    private function __clone()
 {  // empty?!
  }    private function __wakeup()
 {  // empty?!
  }    public static function getInstance()
 {  if (!isset(self::$instance)) {
  // late static binding
  self::$instance = new self;
 }  return self::$instance;
 }    public function log($type, $message)
 {  return sprintf('Logging %s: %s', $type, $message);
 } }   // Client use echo Logger::getInstance()->log(Logger::TYPE_NOTICE, 'test');

```

`Logger`类使用静态成员`$instance`来保持一个`self`的实例，根据`getInstance()`方法的实现。我们将`__construct`定义为`protected`，以防止通过`new`操作符创建新实例。`__clone()`方法被定义为`private`，以防止通过`clone`操作符进行实例克隆。同样，`__wakeup()`方法也被定义为 private，以防止通过`unserialize()`函数进行实例反序列化。这些简单的限制使得该类作为单例。要获取一个实例，只需调用`getInstance()`类方法。

# 原型模式

原型模式是通过克隆来创建新对象的。这是一个相当有意思的概念，因为我们不再使用`new`关键字来创建新对象。PHP 语言提供了一个特殊的`clone`关键字来辅助对象克隆。

以下示例演示了可能的原型模式实现：

```php
<?php   class Logger {
  public $channel = 'N/A'; }   class SystemLogger extends Logger {
  public function __construct()
 {  $this->channel = 'STDIN';
 }    public function log($data)
 {  return sprintf('Logging %s to %s.', $data, $this->channel);
 }    public function __clone()
 {  /* additional changes for (after)clone behavior? */
  } }   // Client use $systemLogger = new SystemLogger(); echo $systemLogger->log('test');   $logger = clone $systemLogger; echo $logger->log('test2');   $logger->channel = 'mail'; echo $logger->log('test3');   // Logging test to STDIN. // Logging test2 to STDIN. // Logging test3 to mail.

```

通常，克隆对象只需使用表达式`$clonedObj = clone $obj;`。然而，这并不会让我们对克隆过程有任何控制。PHP 对象可能很重，有很多成员和引用。有时，我们希望对克隆对象施加一定的限制。这就是魔术`__clone()`方法派上用场的地方。`__clone()`方法在克隆过程完成后触发，这是可能清理代码实现时需要记住的事情。

# 抽象工厂模式

抽象工厂封装了具有共同功能的一组单独工厂，而不指定它们的具体类。这样可以更容易地编写可移植的代码，因为客户端可以在不更改代码的情况下交换具体实现。

以下示例演示了可能的抽象工厂模式实现：

```php
<?php   interface Button {
  public function render(); }   interface FormFactory {
  public function createButton(); }   class LoginButton implements Button {
  public function render()
 {  return '<button name="login">Login</button>';
 } }   class RegisterButton implements Button {
  public function render()
 {  return '<button name="register">Register</button>';
 } }   class LoginFactory implements FormFactory {
  public function createButton()
 {  return new LoginButton();
 } }   class RegisterFactory implements FormFactory {
  public function createButton()
 {  return new RegisterButton();
 } }   // Client $loginButtonFactory = new LoginFactory(); $button = $loginButtonFactory->createButton(); echo $button->render();   $registerButtonFactory = new RegisterFactory(); $button = $registerButtonFactory->createButton(); echo $button->render();

```

我们首先创建了两个简单的接口，`Button`和`FormFactory`。`Button`接口定义了一个`render()`方法，然后我们通过两个具体类实现`LoginButton`和`RegisterButton`来实现它。两个`FormFactory`实现，`LoginFactory`和`RegisterFactory`，然后在其`createButton()`方法实现中实例化相应的按钮类。客户端只使用`LoginFactory`和`RegisterFactory`实例，从而避免直接实例化具体按钮类。

# 建造者模式

建造者模式是一个非常方便的模式，特别是在处理大型应用程序时。它将复杂对象的构建与其表示分离。这使得相同的构建过程可以创建多种表示。

以下示例演示了可能的建造者模式实现，以`Image`类为例：

```php
<?php   class Image {
  private $width;
  private $height;    public function getWidth()
 {  return $this->width;
 }    public function setWidth($width)
 {  $this->width = $width;
  return $this;
 }    public function getHeight()
 {  return $this->height;
 }    public function setHeight($height)
 {  $this->height = $height;
  return $this;
 } }   interface ImageBuilderInterface {
  public function setWidth($width);    public function setHeight($height);    public function getResult(); }   class ImageBuilder implements ImageBuilderInterface {
  private $image;    public function __construct()
 {  $this->image = new Image();
 }    public function setWidth($width)
 {  $this->image->setWidth($width);
  return $this;
 }    public function setHeight($height)
 {  $this->image->setHeight($height);
  return $this;
 }    public function getResult()
 {  return $this->image;
 } }   class ImageBuildDirector {
  private $builder;    public function __construct(ImageBuilder $builder)
 {  $this->builder = $builder;
 }    public function build()
 {  $this->builder->setWidth(120);
  $this->builder->setHeight(80);
  return $this;
 }    public function getImage()
 {  return $this->builder->getResult();
 } }   // Client use $imageBuilder = new ImageBuilder(); $imageBuildDirector = new ImageBuildDirector($imageBuilder); $image = $imageBuildDirector->build()->getImage();   var_dump($image); // object(Image)#2 (2) { ["width":"Image":private]=> int(120) ["height":"Image":private]=> int(80) }

```

我们首先创建了一个简单的 Image 类，提供了宽度和高度属性以及相应的 getter 和 setter。然后创建了`ImageBuilderInterface`接口，定义了图像宽度和高度的 setter 方法，以及`getResult()`方法。然后创建了一个实现`ImageBuilderInterface`接口的`ImageBuilder`具体类。客户端实例化`ImageBuilder`类。另一个具体类`ImageBuildDirector`通过其`build()`方法将创建或构建代码包装在其构造函数中传递的`ImageBuilder`实例中。

# 对象池模式

对象池模式管理类实例--对象。它用于希望由于资源密集型操作而限制不必要的类实例化的情况。对象池的作用类似于对象的注册表，客户端可以随后获取必要的对象。

以下示例演示了可能的对象池模式实现：

```php
<?php     class ObjectPool {
  private $instances = [];    public function load($key)
 {  return $this->instances[$key];
 }    public function save($object, $key)
 {  $this->instances[$key] = $object;
 } }   class User {
  public function hello($name)
 {  return 'Hello ' . $name;
 } }   // Client use $pool = new ObjectPool();   $user = new User(); $key = spl_object_hash($user);   $pool->save($user, $key);   // code...   $user = $pool->load($key); echo $user->hello('John');

```

只使用数组和两种方法，我们就能够实现一个简单的对象池。`save()`方法将对象添加到`$instances`数组中，而`load()`方法将其返回给客户端。在这种情况下，客户端负责跟踪保存对象的键。对象本身在使用后并不被销毁，因为它们仍然留在池中。

# 行为模式

在这一部分，我们将介绍行为模式，如策略、观察者、延迟初始化和责任链。

# 策略模式

策略模式在我们有多个代码块执行类似操作的情况下非常有用。它定义了一组封装和可互换的算法。想象一下订单结账流程，我们想要实现不同的运输提供商，比如 UPS 和 FedEx。

以下示例演示了可能的策略模式实现：

```php
<?php   interface ShipmentStrategy {
  public function calculate($amount); }   class UPSShipment implements ShipmentStrategy {
  public function calculate($amount)
 {  return 'UPSShipment...';
 } }   class FedExShipment implements ShipmentStrategy {
  public function calculate($amount)
 {  return 'FedExShipment...';
 } }   class Checkout {
  private $amount = 0;    public function __construct($amount = 0)
 {  $this->amount = $amount;
 }    public function estimateShipment()
 {  if ($this->amount > 199.99) {
  $shipment = new FedExShipment();
 } else {
  $shipment = new UPSShipment();
 }    return $shipment->calculate($this->amount);
 } }   // Client use $checkout = new Checkout(19.99); echo $checkout->estimateShipment(); // UPSShipment...   $checkout = new Checkout(499.99); echo $checkout->estimateShipment(); // FedExShipment...

```

我们首先定义了一个带有`calculate()`方法的`ShipmentStrategy`接口。然后我们定义了`UPSShipment`和`FedExShipment`类，它们实现了`ShipmentStrategy`接口。有了这两个具体的运输类，我们创建了一个`Checkout`类，它在其`estimateShipment()`方法中封装了这两种运输选项。然后客户端调用`Checkout`实例的`estimateShipment()`方法。根据传递的金额，不同的运输计算会启动。使用这种模式，我们可以在不改变客户端的情况下自由添加新的运输计算。

# 观察者模式

观察者模式非常受欢迎。它允许事件订阅类型的行为。我们区分主题和观察者类型的对象。观察者是订阅主题对象状态变化的对象。当主题改变其状态时，它会自动通知所有观察者。

以下示例演示了可能的观察者模式实现：

```php
<?php   class CheckoutSuccess implements \SplSubject {
  protected $salesOrder;
  protected $observers;    public function __construct($salesOrder)
 {  $this->salesOrder = $salesOrder;
  $this->observers = new \SplObjectStorage();
 }    public function attach(\SplObserver $observer)
 {  $this->observers->attach($observer);
 }    public function detach(\SplObserver $observer)
 {  $this->observers->detach($observer);
 }    public function notify()
 {  foreach ($this->observers as $observer) {
  $observer->update($this);
 } }    public function getSalesOrder()
 {  return $this->salesOrder;
 } }   class SalesOrder { }   class Mailer implements \SplObserver {
  public function update(\SplSubject $subject)
 {  echo 'Mailing ', get_class($subject->getSalesOrder()), PHP_EOL;
 } }   class Logger implements \SplObserver {
  public function update(\SplSubject $subject)
 {  echo 'Logging ', get_class($subject->getSalesOrder()), PHP_EOL;
 } }   $salesOrder = new SalesOrder(); $checkoutSuccess = new CheckoutSuccess($salesOrder); // some code... $checkoutSuccess->attach(new Mailer()); // some code... $checkoutSuccess->attach(new Logger()); // some code... $checkoutSuccess->notify();

```

PHP 的`\SplSubject`和`\SplObserver`接口允许观察者模式的实现。我们的结账成功示例使用这些接口来实现`CheckoutSuccess`作为主题类型对象的类，以及`Mailer`和`Logger`作为观察者类型对象的类。使用`CheckoutSuccess`实例的`attach()`方法，我们将两个观察者附加到主题上。一旦调用主题的`notify()`方法，就会触发各个观察者的`update()`方法。在我们的示例中，`getSalesOrder()`方法的调用可能会让人感到意外，因为在`SplSubject`对象的直接实例上实际上没有`getSalesOrder()`方法。然而，在我们的示例中，两个`update(\SplSubject $subject)`方法调用将接收到一个`CheckoutSuccess`的实例。否则，直接将`$subject`参数强制转换为`CheckoutSuccess`将导致 PHP 致命错误。

```php
PHP Fatal error: Declaration of Logger::update(CheckoutSuccess $subject) must be compatible with SplObserver::update(SplSubject $SplSubject)

```

# 延迟初始化模式

延迟初始化模式对于处理实例化可能消耗大量资源的对象非常有用。其思想是延迟实际的资源密集型操作，直到实际需要其结果为止。PDF 生成是一个轻度到中度资源密集型操作的例子。

以下示例演示了基于 PDF 生成的可能的延迟初始化模式实现：

```php
<?php   interface PdfInterface {
  public function generate(); }   class Pdf implements PdfInterface {
  private $data;    public function __construct($data)
 {  $this->data = $data;
  // Imagine resource intensive pdf generation here
  sleep(3);
 }    public function generate()
 {  echo 'pdf: ' . $this->data;
 } }   class ProxyPdf implements PdfInterface {
  private $pdf = null;
  private $data;    public function __construct($data)
 {  $this->data = $data;
 }    public function generate()
 {  if (is_null($this->pdf)) {
  $this->pdf = new Pdf($this->data);
 }  $this->pdf->generate();
 } }   // Client $pdf = new Pdf('<h1>Hello</h1>'); // 3 seconds // Some other code ... $pdf->generate();   $pdf = new ProxyPdf('<h1>Hello</h1>'); // 0 seconds // Some other code ... $pdf->generate();

```

根据类的构造方式，它可能会在我们调用`new`关键字后立即触发实际的生成，就像我们使用`new Pdf(...)`表达式一样。`new ProxyPdf(...)`表达式的行为不同，因为它包装了实现相同`PdfInterface`的`Pdf`类，但提供了不同的`__construct()`方法实现。

# 责任链模式

责任链模式允许我们以发送者-接收者的方式链接代码，同时两者彼此解耦。这使得可以有多个对象处理传入的请求。

以下示例演示了使用日志记录功能作为示例的可能的责任链模式实现：

```php
<?php   abstract class Logger {
  private $logNext = null;    public function logNext(Logger $logger)
 {  $this->logNext = $logger;
  return $this->logNext;
 }    final public function push($message)
 {  $this->log($message);    if ($this->logNext !== null) {
  $this->logNext->push($message);
 } }    abstract protected function log($message); }   class SystemLogger extends Logger {
  public function log($message)
 {  echo 'SystemLogger log!', PHP_EOL;
 } }   class ElasticLogger extends Logger {
  protected function log($message)
 {  echo 'ElasticLogger log!', PHP_EOL;
 } }   class MailLogger extends Logger {
  protected function log($message)
 {  echo 'MailLogger log!', PHP_EOL;
 } }   // Client use $systemLogger  = new SystemLogger(); $elasticLogger = new ElasticLogger(); $mailLogger = new MailLogger();   $systemLogger   ->logNext($elasticLogger)
 ->logNext($mailLogger);   $systemLogger->push('Stuff to log...');   //SystemLogger log! //ElasticLogger log! //MailLogger log!

```

我们首先创建了一个抽象的`Logger`类，其中包含三个方法：`logNext()`、`push()`和`log()`。`log()`方法被定义为抽象，这意味着实现留给子类。`logNext()`方法是关键因素，因为它将对象传递到链中。然后我们创建了`Logger`类的三个具体实现：`SystemLogger`、`ElasticLogger`和`MailLogger`。然后我们实例化了其中一个具体的记录器类，并使用`logNext()`方法将另外两个实例传递到链中。最后，我们调用了`push()`方法来触发链。

# 结构模式

在这一部分，我们将看一下一个结构模式：装饰器模式。

# 装饰器模式

装饰器模式很简单。它允许我们在不影响同一类的其他实例的情况下，为对象实例添加新的行为。它基本上充当了我们对象的装饰包装器。我们可以想象一个简单的用例，使用 Logger 类的实例，我们有一个简单的记录器类，我们希望偶尔装饰，或者包装成更具体的错误、警告和通知级别的记录器。

以下示例演示了可能的装饰器模式实现：

```php
<?php   interface LoggerInterface {
  public function log($message); }   class Logger implements LoggerInterface {
  public function log($message)
 {  file_put_contents('app.log', $message . PHP_EOL, FILE_APPEND);
 } }   abstract class LoggerDecorator implements LoggerInterface {
  protected $logger;    public function __construct(Logger $logger)
 {  $this->logger = $logger;
 }    abstract public function log($message); }   class ErrorLogger extends LoggerDecorator {
  public function log($message)
 {  $this->logger->log('ErrorLogger: ' . $message);
 } }   class WarningLogger extends LoggerDecorator {
  public function log($message)
 {  $this->logger->log('WarningLogger: ' . $message);
 } }   class NoticeLogger extends LoggerDecorator {
  public function log($message)
 {  $this->logger->log('NoticeLogger: ' . $message);
 } }   // Client use (new Logger())->log('Test Logger.');   (new ErrorLogger(new Logger()))->log('Test ErrorLogger.');   (new WarningLogger(new Logger()))->log('Test WarningLogger.');   (new NoticeLogger(new Logger()))->log('Test NoticeLogger.');

```

在这里，我们首先定义了一个`LoggerInterface`接口和一个实现该接口的具体`Logger`类。然后我们创建了一个`abstract` `LoggerDecorator`类，它也实现了`LoggerInterface`。`LoggerDecorator`实际上并没有实现`log()`方法；它将其定义为`abstract`，以便未来的子类来实现。最后，我们定义了具体的错误、警告和通知装饰器类。我们可以看到它们的`log()`方法根据其角色装饰输出。结果输出如下：

```php
Test Logger.
ErrorLogger: Test ErrorLogger.
WarningLogger: Test WarningLogger.
NoticeLogger: Test NoticeLogger.

```

# 总结

在本章中，我们以实际操作的方式介绍了 PHP 应用程序中最常用的一些设计模式。这个列表还远未完成，因为还有其他设计模式可用。虽然有些设计模式非常通用，但其他可能更适合 GUI 或应用程序编程的其他领域。了解如何使用和应用设计模式使我们的代码更具可扩展性、可重用性、可维护性和适应性。

接下来，我们将更仔细地研究使用 SOAP、REST 和 Apache Thrift 构建 Web 服务。


# 第十一章：构建服务

现代应用程序大量使用**HTTP**（**超文本传输协议**）。这种无状态的应用层协议允许我们在分布式系统之间交换消息。消息交换过程可以通过客户端-服务器计算模型观察到，因为它以请求-响应类型的消息形式发生。这使我们能够轻松地编写一个服务，或者更具体地说，一个 Web 服务，触发服务器上的各种操作并将反馈数据返回给客户端。

在本章中，我们将通过以下部分更仔细地研究这种客户端-服务器关系：

+   理解客户端-服务器关系

+   使用 SOAP 进行工作：

+   XML 扩展

+   创建服务器

+   创建 WSDL 文件

+   创建客户端

+   使用 REST 进行工作：

+   JSON 扩展

+   创建服务器

+   创建客户端

+   使用 Apache Thrift（RPC）进行工作：

+   安装 Apache Thrift

+   定义服务

+   创建服务器

+   创建客户端

+   理解微服务

# 理解客户端-服务器关系

为了更容易地可视化客户端-服务器关系和请求-响应类型的消息传递，我们可以将一个移动货币应用程序视为客户端，而一些远程网站，比如`http://api.fixer.io/`，作为服务器。服务器公开一个或多个 URL 端点，允许通信交换，比如`http://api.fixer.io/latest?symbols=USD,GBP`。移动应用程序可以轻松发出 HTTP `GET http://api.fixer.io/latest?symbols=GBP,HRK,USD`请求，然后得到如下响应：

```php
{
 "base": "EUR",
 "date": "2017-03-10",
 "rates": {
 "GBP": 0.8725,
 "HRK": 7.419,
 "USD": 1.0606
  }
}

```

HTTP 的`GET`关键字用于表示我们要在通过 URL 联系的远程（服务器）系统上执行的操作类型。响应包含 JSON 格式的数据，我们的移动货币应用程序可以轻松解析和使用。这个特定的消息交换示例是我们所谓的**表述状态转移**（**REST**）或 RESTful 服务。

REST 服务本身不是一种协议；它是建立在 HTTP 无状态协议和标准操作（GET、POST、PUT、DELETE 等）之上的一种架构风格。在这个简单的例子中展示的只是冰山一角，我们将在*使用 REST*部分后面看到更多。

还有其他形式的服务，超越了仅仅是一种架构风格，比如 SOAP 服务和 Apache Thrift 服务。虽然它们有自己的协议集，但它们也可以与 HTTP 很好地配合。

# 使用 SOAP 进行工作

**SOAP**（**简单对象访问协议**）是一种基于 XML 的消息交换协议，依赖于应用层协议（如 HTTP）进行消息协商和传输。**万维网联盟**（**W3C**）维护 SOAP 规范。

SOAP 规范文档可在[`www.w3.org/TR/soap/`](https://www.w3.org/TR/soap/)找到。

SOAP 消息是由`Envelope`、`Header`、`Body`和`Fault`元素组成的 XML 文档：

```php
<?xml version="1.0" ?> <env:Envelope>
<env:Header>
<!-- ... -->
  </env:Header>
<env:Body>
<!-- ... -->
  <env:Fault>
<!-- ... -->
  </env:Fault>
</env:Body>
</env:Envelope>

```

`Envelope`是每个 SOAP 请求的必需元素，因为它包含整个 SOAP 消息。同样，`Body`元素也是必需的，因为它包含请求和响应信息。另一方面，`Header`和`Fault`是可选元素。仅使用基于 XML 的请求-响应消息，我们可以通过 HTTP 建立客户端-服务器通信。虽然交换 XML 消息看起来很简单，但当一个人必须处理大量的方法调用和数据类型时，这可能会变得繁琐。

这就是 WSDL 发挥作用的地方。WSDL 是一种接口定义语言，用于定义 Web 服务的数据类型和操作。W3C 维护 WSDL 规范。

WSDL 规范文档可在[`www.w3.org/TR/wsdl`](https://www.w3.org/TR/wsdl)找到。

根据以下部分示例，一共使用了六个主要元素来描述服务：

```php
<?xml version="1.0" ?> <definitions>
<types>
<!-- ... -->
  </types>
<message>
<!-- ... -->
  </message>
<portType>
<!-- ... -->
  </portType>
<binding>
<!-- ... -->
  </binding>
<port>
<!-- ... -->
  </port>
<service>
<!-- ... -->
  </service>
</definitions>

```

虽然 WSDL 对于我们的服务的运行并不是必需的，但对于使用我们的 SOAP 服务的客户端来说，它肯定很方便。遗憾的是，PHP 缺乏基于 SOAP 服务使用的 PHP 类轻松生成 WSDL 文件的官方工具。这使得 PHP 开发人员手动编写 WSDL 文件变得繁琐和耗时，这就是为什么一些开发人员倾向于完全忽略 WSDL。

暂时将 WSDL 文件生成放在一边，可以说 SOAP 服务中唯一真正具有挑战性的部分是编写和读取 XML 消息。这就是 PHP 扩展派上用场的地方。

# XML 扩展

在 PHP 中有几种读取和写入 XML 文档的方法，包括正则表达式和专门的类和方法。正则表达式方法容易出错，特别是对于复杂的 XML 文档，因此建议使用扩展。PHP 为此提供了几种扩展，最常见的是以下几种：

+   **XMLWriter**：这允许我们生成 XML 数据的流或文件

+   **XMLReader**：这允许读取 XML 数据

+   **SimpleXML**：这将 XML 转换为对象，并允许使用常规属性选择器和数组迭代器处理对象

+   **DOM**：这允许我们通过 DOM API 操作 XML 文档

处理 XML 文档的基础是正确读取和写入其元素和属性。让我们假设以下的`simple.xml`文档：

```php
<?xml version="1.0" encoding="UTF-8"?> <customer>
 <name type="string"><![CDATA[John]]></name>
 <age type="integer">34</age> 
 <addresses>
 <address><![CDATA[The Address #1]]></address>
 </addresses>
</customer>

```

使用`XMLWriter`，我们可以通过运行以下代码创建相同的文档：

```php
<?php $xml  = new XMLWriter(); $xml->openMemory(); $xml->setIndent(true); // optional formatting   $xml->startDocument('1.0', 'UTF-8'); $xml->startElement('customer');   $xml->startElement('name'); $xml->writeAttribute('type', 'string'); $xml->writeCData('John'); $xml->endElement(); // </name> $xml->startElement('age'); $xml->writeAttribute('type', 'integer'); $xml->writeRaw(34); $xml->endElement(); // </age> $xml->startElement('addresses'); $xml->startElement('address'); $xml->writeCData('The Address #1'); $xml->endElement(); // </address> $xml->endElement(); // </addresses>   $xml->endElement(); // </customer>   $document = $xml->outputMemory();

```

我们可以看到，使用`XMLWriter`写下必要的 XML 是一个相对简单的操作。`XMLWriter`扩展使我们的代码一开始有点难以阅读。所有这些`startElement()`和`endElement()`方法使得弄清楚 XML 中的每个元素有点乏味。需要一点时间来适应它。但是，它确实允许我们轻松生成简单的 XML 文档。使用`XMLReader`，我们现在可以根据给定 XML 文档中的数据输出`Customer John, at age 34, living at The Address #1`字符串，使用以下代码块：

```php
<?php $xml = new XMLReader(); $xml->open(__DIR__ . '/simple.xml');   $name = ''; $age = ''; $address = '';   while ($xml->read()) {   if ($xml->name == 'name') {
  $name = $xml->readString();
  $xml->next();
 } elseif ($xml->name == 'age') {
  $age = $xml->readString();
  $xml->next();
 } elseif ($xml->name == 'address') {
  $address = $xml->readString();
  $xml->next();
 } }   echo sprintf(
  'Customer %s, at age %s, living at %s',
  $name, $age, $address );

```

虽然代码本身看起来非常简单，但`while`循环揭示了`XMLReader`的一个有趣的特性。`XMLReader`从上到下读取 XML 文档。虽然这种方法对于以流为基础高效解析大型和复杂的 XML 文档是一个很好的选择，但对于更简单的 XML 文档来说似乎有点过度。

让我们看看`SimpleXML`如何处理写入相同的`simple.xml`文件。以下代码生成的 XML 内容几乎与`XMLWriter`相同：

```php
<?php   $document = new SimpleXMLElement(
  '<?xml version="1.0" encoding="UTF-8"?><customer></customer>' );   $name = $document->addChild('name', 'John'); $age = $document->addChild('age', 34); $addresses = $document->addChild('addresses'); $address = $addresses->addChild('address', 'The Address #1'); echo $document->asXML();

```

这里的区别在于我们无法将`<![CDATA[...]]>`直接传递给我们的元素。有一些使用`dom_import_simplexml()`函数的变通方法，但那是来自`DOM`扩展的函数。并不是说这有什么不好，但让我们保持我们的示例清晰分离。现在我们知道我们可以使用`SimpleXML`编写 XML 文档，让我们看看如何从中读取。使用`SimpleXML`，我们现在可以使用以下代码输出相同的`Customer John, at age 34, living at The Address #1`字符串：

```php
<?php   $document = new SimpleXMLElement(__DIR__ . '/simple.xml', null, true);   $name = (string)$document->name; $age = (string)$document->age; $address = (string)$document->addresses[0]->address; echo sprintf(
  'Customer %s, at age %s, living at %s',
  $name, $age, $address );

```

使用`SimpleXML`读取 XML 的过程似乎比使用`XMLReader`要短一些，尽管这些示例都没有任何错误处理。

让我们看看使用`DOMDocument`类来写下一个 XML 文档：

```php
<?php $document = new DOMDocument('1.0', 'UTF-8'); $document->formatOutput = true; // optional $customer = $document->createElement('customer'); $customer = $document->appendChild($customer); $name = $document->createElement('name'); $name = $customer->appendChild($name); $nameTypeAttr = $document->createAttribute('type'); $nameTypeAttr->value = 'string'; $name->appendChild($nameTypeAttr); $name->appendChild($document->createCDATASection('John')); $age = $document->createElement('age'); $age = $customer->appendChild($age); $ageTypeAttr = $document->createAttribute('type'); $ageTypeAttr->value = 'integer'; $age->appendChild($ageTypeAttr); $age->appendChild($document->createTextNode(34));   $addresses = $document->createElement('addresses'); $addresses = $customer->appendChild($addresses); $address = $document->createElement('address'); $address = $addresses->appendChild($address); $address->appendChild($document->createCDATASection('The Address #1')); echo $document->saveXML();

```

最后，让我们看看`DOMDocument`如何处理读取 XML 文档：

```php
<?php   $document = new DOMDocument(); $document->load(__DIR__ . '/simple.xml');   $name = $document->getElementsByTagName('name')[0]->nodeValue; $age = $document->getElementsByTagName('age')[0]->nodeValue; $address = $document->getElementsByTagName('address')[0]->nodeValue; echo sprintf(
  'Customer %s, at age %s, living at %s',
  $name, $age, $address );

```

`DOM`和`SimpleXMLElement`扩展使从 XML 文档中读取值变得非常容易，只要我们对其结构的完整性有信心。在处理 XML 文档时，我们应该根据诸如文档大小之类的因素评估我们的用例。虽然`XMLReader`和`XMLWriter`类在处理时更冗长，但在正确使用时它们往往更高效。

现在我们已经对在 PHP 中处理 XML 文档有了基本的了解，让我们创建我们的第一个 SOAP 服务器。

# 创建服务器

PHP `soap`扩展提供了`SoapClient`和`SoapServer`类。我们可以使用`SoapServer`类来设置具有或不具有 WSDL 服务描述文件的 SOAP 服务服务器。

在没有 WSDL（非 WSDL 模式）的情况下使用`SoapClient`和`SoapServer`使用一个常见的交换格式，这消除了对 WSDL 文件的需求。

在继续之前，我们应该确保已安装了`soap`扩展。我们可以通过观察`php -m`控制台命令的输出或查看`phpinfo()`函数的输出来实现：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/00c54baf-529e-4228-8d4d-cf18b4a4aefe.png)

有了可用和加载的 soap 扩展，我们可以按照以下结构准备我们的`soap-service`项目目录：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/c2b3e4f3-786f-49c3-9a32-a6643d21490a.png)

继续向前，我们将假设 Web 服务器配置为从`soap-service/server`目录提供内容到[`soap-service.server`](http://soap-service.server)请求，并从`soap-service/client`目录提供内容到[`soap-service.client`](http://soap-service.client)请求。

让我们创建一个小的 SOAP 服务，其中包含两个不同的类，每个类都有相同的`welcome()`方法。我们可以首先创建`soap-service/server/services/Foggyline/Customer.php`文件，内容如下：

```php
<?php namespace Foggyline;   class Customer {
  /**
 * Says "Welcome customer..." * @param $name
 * @return string
 */  function welcome($name)
 {  return 'Welcome customer: ' . $name;
 } } 

```

现在，让我们创建`soap-service/server/services/Foggyline/User.php`文件，内容如下：

```php
<?php namespace Foggyline;   class User {
  /**
 * Says "Welcome user..." * @param $name
 * @return string
 */  function welcome($name)
 {  return 'Welcome user: ' . $name;
 } } 

```

有了这两个类，让我们创建一个代理类来包装它们。我们通过创建`soap-service/server/ServiceProxy.php`文件来实现：

```php
<?php   require_once __DIR__ . '/services/Foggyline/Customer.php'; require_once __DIR__ . '/services/Foggyline/User.php'; class ServiceProxy {
  private $customerService;
  private $userService;    public function __construct()
 {  $this->customerService = new Foggyline\Customer();
  $this->userService = new Foggyline\User();
 }    /**
 * Says "Welcome customer..." * @soap
  * @param $name
 * @return string
 */  public function customerWelcome($name)
 {  return $this->customerService->welcome($name);
 }    /**
 * Says "Welcome user..." * @soap
  * @param $name
 * @return string
 */  public function userWelcome($name)
 {  return $this->userService->welcome($name);
 } }

```

现在我们有了代理类，我们可以创建实际的`SoapServer`实例。我们通过创建`soap-service/server/index.php`文件来实现：

```php
<?php require_once __DIR__ . '/ServiceProxy.php'; $options = [   'uri' => 'http://soap-service.server/index.php' ]; $server = new SoapServer(null, $options);   $server->setClass('ServiceProxy');   $server->handle(); 

```

在这里，我们实例化`SoapServer`实例，将 null 传递给`$wsdl`参数，并在`$options`参数下只传递一个`'uri'`选项。URI 必须在非 wsdl 模式下指定。然后我们使用`setClass()`实例方法来设置处理传入 SOAP 请求的类。不幸的是，我们不能传递一个类数组或多次调用`setClass()`方法一次添加多个不同的处理类，这就是为什么我们创建了`ServiceProxy`类来包装`Customer`和`User`类。最后，我们调用了`$server`实例的`handle()`方法，处理 SOAP 请求。此时，我们的 SOAP 服务服务器应该是完全可操作的。

# 创建 WSDL 文件

然而，在转向客户端之前，让我们快速看一下 WSDL。`ServiceProxy`类方法上使用的`@soap`标签与`SoapServer`的功能无关。我们之所以使用它，仅仅是因为 php2wsdl 库使我们能够根据提供的类自动生成 WSDL 文件。php2wsdl 库作为一个 composer 包提供，这意味着我们可以通过在`soap-service/server`目录中简单运行以下命令来安装它：

```php
composer require php2wsdl/php2wsdl

```

安装后，我们可以创建`soap-service\server\wsdl-auto-gen.php`文件，内容如下：

```php
<?php require_once __DIR__ . '/vendor/autoload.php'; require_once __DIR__ . '/ServiceProxy.php';   $class = 'ServiceProxy'; $serviceURI = 'http://soap-service.server/index.php';   $wsdlGenerator = new PHP2WSDL\PHPClass2WSDL($class, $serviceURI); $wsdlGenerator->generateWSDL(true); file_put_contents(__DIR__ . '/wsdl.xml', $wsdlGenerator->dump());

```

一旦我们在控制台或浏览器中执行`wsdl-auto-gen.php`，它将生成`soap-service/server/wsdl.xml`文件，内容如下：

```php
<?xml version="1.0"?> <definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="http://soap-service.server/index.php" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap-enc="http://schemas.xmlsoap.org/soap/encoding/" xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/" name="ServiceProxy" targetNamespace="http://soap-service.server/index.php">
<types>
<xsd:schema targetNamespace="http://soap-service.server/index.php">
<xsd:import namespace="http://schemas.xmlsoap.org/soap/encoding/"/>
</xsd:schema>
</types>
<portType name="ServiceProxyPort">
 <operation name="customerWelcome">
 <documentation>Says "Welcome customer..."</documentation>
 <input message="tns:customerWelcomeIn"/>
 <output message="tns:customerWelcomeOut"/>
 </operation>
 <operation name="userWelcome">
 <documentation>Says "Welcome user..."</documentation>
 <input message="tns:userWelcomeIn"/>
 <output message="tns:userWelcomeOut"/>
</operation>
</portType>
<binding name="ServiceProxyBinding" type="tns:ServiceProxyPort">
<soap:binding style="rpc" transport="http://schemas.xmlsoap.org/soap/http"/>
<operation name="customerWelcome">
<soap:operation soapAction="http://soap-service.server/index.php#customerWelcome"/>
<input>
<soap:body use="encoded" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" namespace="http://soap-service.server/index.php"/>
</input>
<output>
<soap:body use="encoded" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" namespace="http://soap-service.server/index.php"/>
</output>
</operation>
<operation name="userWelcome">
<soap:operation soapAction="http://soap-service.server/index.php#userWelcome"/>
<input>
<soap:body use="encoded" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" namespace="http://soap-service.server/index.php"/>
</input>
<output>
<soap:body use="encoded" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" namespace="http://soap-service.server/index.php"/>
</output>
</operation>
</binding>
<service name="ServiceProxyService">
<port name="ServiceProxyPort" binding="tns:ServiceProxyBinding">
 <soap:address location="http://soap-service.server/index.php"/>
</port>
</service>
<message name="customerWelcomeIn">
 <part name="name" type="xsd:anyType"/>
</message>
<message name="customerWelcomeOut">
 <part name="return" type="xsd:string"/>
</message>
<message name="userWelcomeIn">
  <part name="name" type="xsd:anyType"/>
</message>
<message name="userWelcomeOut">
 <part name="return" type="xsd:string"/>
</message>
</definitions>

```

这是一个相当长的文件需要手动编写。好处是一旦设置了 WSDL 文件，各种第三方工具和其他语言库就可以轻松消费我们的服务。例如，这是 Chrome 浏览器的 Wizdler 扩展的屏幕截图，解释了 WSDL 文件的内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/eb1e49d7-b0ef-4cba-9ae6-26abab4a028d.png)

有了 WSDL，我们现在可以轻松修改`soap-service/server/index.php`文件如下：

```php
// NON-WSDL MODE: $server = new SoapServer(null, $options);

// WSDL MODE: $server = new SoapServer('http://soap-service.server/wsdl.xml'); $server = new SoapServer('http://soap-service.server/wsdl.xml');

```

现在我们已经解决了 SOAP 服务器的问题，让我们创建一个客户端。

# 创建客户端

在 PHP 中创建 SOAP 客户端是一个相对简单的任务，当我们使用`SoapClient`类时。让我们创建`soap-service/client/index.php`文件，内容如下：

```php
<?php $options = [
  'location' => 'http://soap-service.server/index.php',
  'uri' => 'http://soap-service.server/index.php',
  'trace ' => true, ];   // NON-WSDL MODE: $client = new SoapClient($wsdl = null, $options); // WSDL MODE: $client = new SoapClient('http://soap-service.server/wsdl.xml', $options);   $client = new SoapClient('http://soap-service.server/wsdl.xml', $options);   echo $client->customerWelcome('John'); echo $client->userWelcome('Mariya');

```

执行客户端代码应该产生以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/f2a8a419-c30a-48d6-bf7f-00e5fab1e73d.png)

当发出 SOAP 请求时，底层发生了什么可以通过 Wireshark 等网络工具观察到：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/35adede7-01e3-4081-8bb7-24e7b29c231a.png)

这向我们展示了单个 SOAP 请求的确切内容，例如`$client->customerWelcome('John')`的请求：

```php
POST /index.php HTTP/1.1
Host: soap-service.server
Connection: Keep-Alive
User-Agent: PHP-SOAP/7.0.10
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://soap-service.server/index.php#customerWelcome"
Content-Length: 525

<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"

 xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
 SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
 <SOAP-ENV:Body>
 <ns1:customerWelcome>
 <name xsi:type="xsd:string">John</name>
 </ns1:customerWelcome>
 </SOAP-ENV:Body>
</SOAP-ENV:Envelope>

```

了解 SOAP 请求的结构和内容使得甚至可以使用`cURL`函数来处理请求-响应通信，尽管这比处理`SoapClient`和`SoapServer`类要困难得多且容易出错。

在本节中，我们已经触及了一些 SOAP 服务的关键点。虽然关于 SOAP 规范还有很多要说的，但这里呈现的示例是编写 SOAP 服务的一个不错的起点。

一个更简单的 Web 服务变体将是 REST。

# 使用 REST

与 SOAP 不同，REST 是一种架构风格。它没有自己的协议或标准。它依赖于 URL 和 HTTP 动词，如 POST、GET、PUT 和 DELETE，以建立消息交换过程。缺乏标准使得它在一定程度上具有挑战性，因为各种 REST 服务实现可能以不同的方式向客户端提供消费服务的途径。在来回搬运数据时，我们可以自由选择 JSON、XML 或其他任何我们喜欢的格式。JSON 的简单性和轻量性使其成为许多用户和框架中的热门选择。

宽泛地说，浏览器中打开网页的行为可以被解释为一个 REST 调用，其中浏览器充当客户端，服务器充当 REST 服务。与可能涉及 cookie 和会话的浏览器页面不同，REST 依赖于无状态操作。

继续向前，我们将假设我们的 Web 服务器配置为为[`rest-service.server`](http://rest-service.server)请求提供`rest-service/server`目录的内容，并为[`rest-service.client`](http://rest-service.client)请求提供`rest-service/client`目录的内容。

# JSON 扩展

多年来，JSON 数据格式已经成为 REST 的默认数据交换格式。JSON 的简单性使其在 PHP 开发人员中相当受欢迎。PHP 语言提供了`json_encode()`和`json_decode()`函数。使用这些函数，我们可以轻松地对 PHP 数组和对象进行编码，以及解码各种 JSON 结构。

以下示例演示了使用`json_encode()`函数的简单性：

```php
<?php   class User {
  public $name;
  public $age;
  public $salary; } $user = new User(); $user->name = 'John'; $user->age = 34; $user->salary = 4200.50;   echo json_encode($user); // {"name":"John","age":34,"salary":4200.5}   $employees = ['John', 'Mariya', 'Sarah', 'Marc'];   echo json_encode($employees); // ["John","Mariya","Sarah","Marc"]

```

以下示例演示了使用`json_decode()`函数的简单性：

```php
<?php   $user = json_decode('{"name":"John","age":34,"salary":4200.5}'); print_r($user); //    stdClass Object //    ( //        [name] => John //        [age] => 34 //        [salary] => 4200.5 //    )

```

这就是限制开始发挥作用的地方。请注意，JSON 对象在 PHP 中被转换为`stdClass`类型对象。没有直接的方法将其转换为`User`类型的对象。当然，如果需要，我们可以编写自定义功能，尝试将`stdClass`对象转换为`User`的实例。

# 创建服务器

简而言之，REST 服务器根据给定的 URL 和 HTTP 动词发送 HTTP 响应。牢记这一点，让我们从添加到`rest-service/server/customer/index.php`文件的以下代码块开始：

```php
<?php   if ('POST' == $_SERVER['REQUEST_METHOD']) {
  header('Content-type: application/json');
  echo json_encode(['data' => 'Triggered customer POST!']); }   if ('GET' == $_SERVER['REQUEST_METHOD']) {
  header('Content-type: application/json');
  echo json_encode(['data' => 'Triggered customer GET!']); }   if ('PUT' == $_SERVER['REQUEST_METHOD']) {
  header('Content-type: application/json');
  echo json_encode(['data' => 'Triggered customer PUT!']); }   if ('DELETE' == $_SERVER['REQUEST_METHOD']) {
  header('Content-type: application/json');
  echo json_encode(['data' => 'Triggered customer DELETE!']); }

```

看起来有趣的是，这里已经是一个简单的 REST 服务示例--一个处理单个资源的四种不同操作。使用诸如 Postman 之类的工具，我们可以触发对[`rest-service.server/customer/index.php`](http://rest-service.server/customer/index.php)资源的`DELETE`操作

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/7536b609-156c-4f4e-8799-304d281eabe8.png)

显然，这种简化的实现没有处理 REST 服务中通常会遇到的任何事情，比如版本控制、规范化、验证、跨域资源共享（CORS）、身份验证等。从头开始实现所有这些 REST 功能是一项耗时的任务，这就是为什么我们可能需要看看现有框架提供的解决方案。

Silex 微框架是快速开始 REST 服务的一个不错的解决方案。我们可以通过在`rest-service/server`目录中的控制台上运行以下命令来简单地将 Silex 添加到我们的项目中：

```php
composer require silex/silex "~2.0"

```

一旦安装好了，我们可以将以下代码转储到`rest-service/server/index.php`文件中：

```php
<?php require_once __DIR__ . '/vendor/autoload.php'; use Silex\Application; use Symfony\Component\HttpFoundation\Request; use Symfony\Component\HttpFoundation\Response;   $app = new Silex\Application();   // The "before" middleware, convenient for auth and request data check $app->before(function (Request $request, Application $app) {
  // Some auth token control
  if (!$request->headers->get('X-AUTH-TOKEN')) {
  // todo: Implement
  }
  // JSON content type control
  if ($request->headers->get('Content-Type') != 'application/json') {
  // todo: Implement
  } });   // The "error" middleware, convenient for service wide error handling $app->error(function (\Exception $e, Request $request, $code) {
  // todo: Implement });   // The "OPTIONS" route, set to trigger for any URL $app->options('{url}', function ($url) use ($app) {
  return new Response('', 204, ['Allow' => 'POST, GET, PUT, DELETE, OPTIONS']); })->assert('url', '.+');   // The "after" middleware, convenient for CORS control $app->after(function (Request $request, Response $response) {
  $response->headers->set('Access-Control-Allow-Headers', 'origin, content-type, accept, X-AUTH-TOKEN');
  $response->headers->set('Access-Control-Allow-Origin', '*');
  $response->headers->set('Access-Control-Allow-Methods', 'POST, GET, PUT, DELETE'); }); // The "POST /user/welcome" REST service endpoint $app->post('/user/welcome', function (Request $request, Application $app) {
  $data = json_decode($request->getContent(), true);
  return $app->json(['data' => 'Welcome ' . $data['name']]); })->bind('user_welcome');   $app->run();

```

这也是一个相对简单的 REST 服务示例，但比我们最初的示例做得更多。在这种情况下，Silex 框架引入了几个关键概念，我们可以利用这些概念来构建我们的 REST 服务器。`before`、`after`和`error`中间件使我们能够钩入请求处理过程的三个不同阶段。使用`before`中间件，我们可以注入身份验证代码，以及对传入数据的有效性进行各种检查。REST 服务通常围绕令牌构建其身份验证，然后将其传递给各个请求。一般的想法是有一个端点，比如`POST user/login`，用户使用用户名和密码登录，然后获得一个用于其余 REST 服务调用的身份验证令牌。然后，这个令牌通常作为请求头的一部分传递。现在，每当用户尝试访问受保护的资源时，都会从头部提取一个令牌，并在数据库（或任何其他可能存储它的地方）中查找令牌背后的用户。然后系统要么允许用户继续原始请求，要么将其阻止。这就是中间件派上用场的地方。

Web 服务身份验证本身就是一个庞大的话题，本书不会涉及。OAuth 是授权的行业标准协议，通常与 REST 风格的服务一起使用。有关 OAuth 的更多信息，请访问[`oauth.net`](https://oauth.net)。

我们包装响应的方式完全取决于我们自己。与 SOAP 不同，没有长期建立的标准来定义 REST 服务响应的数据结构。然而，在过去几年中，有几个倡议试图解决这一挑战。

JSON API 试图规范使用交换 JSON 数据的客户端-服务器接口；请访问[`jsonapi.org/format/`](http://jsonapi.org/format/)获取更多信息。

为了使服务器正常工作，我们还需要添加`rest-service\server\.htaccess`文件，内容如下：

```php
<IfModule mod_rewrite.c>
Options -MultiViews
  RewriteEngine On
  RewriteCond %{REQUEST_FILENAME} !-d
  RewriteCond %{REQUEST_FILENAME} !-f
  RewriteRule ^ index.php [QSA,L] </IfModule>

```

Silex 方便地支持几个关键的 HTTP 动词（GET、POST、PUT、DELETE、PATCH 和 OPTIONS），我们可以很容易地以*资源路径+回调函数*的语法实现逻辑：

```php
$app->get('/resource/path', function () { /* todo: logic */ }); $app->post('/resource/path', function () { /* todo: logic */ }); $app->put('/resource/path', function () { /* todo: logic */ }); $app->delete('/resource/path', function () { /* todo: logic */ }); $app->patch('/resource/path', function () { /* todo: logic */ }); $app->options('/resource/path', function () { /* todo: logic */ });

```

这使得快速起草 REST 服务变得容易，只需几行代码。我们的服务器示例在服务器安全方面几乎没有做任何事情。它的目的只是强调构建 REST 服务时中间件的有用性。安全方面，如身份验证、授权、CORS、HTTPS 等都应该引起极大的重视。

框架如[`silex.sensiolabs.org`](http://silex.sensiolabs.org)和[`apigility.org`](https://apigility.org/)提供了一个很好的解决方案，可以编写高质量、功能丰富的 REST 服务。

# 创建客户端

鉴于 REST 服务依赖于 HTTP，可以肯定地假设使用 PHP CURL 编写客户端应该是一个相当简单的过程。让我们创建一个`rest-service/client/index.php`文件，内容如下：

```php
<?php $ch = curl_init();   $headers = [
  'Content-Type: application/json',
  'X-AUTH-TOKEN: some-auth-token-here' ]; curl_setopt($ch, CURLOPT_URL, 'http://rest-service.server/user/welcome'); curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['name' => 'John'])); curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);   $result = curl_exec($ch);   curl_close($ch);   echo $result;

```

Wireshark 网络工具告诉我们，这段代码生成了以下 HTTP 请求到 REST 服务：

```php
POST /user/welcome HTTP/1.1
Host: rest-service.server
Accept: */*
Content-Type: application/json
X-AUTH-TOKEN: some-auth-token-here
Content-Length: 15

{"name":"John"}

```

虽然 CURL 方法运行良好，但很快就会变得繁琐且容易出错。这意味着必须处理各种类型的错误响应、SSL 证书等挑战。更优雅的解决方案是使用 HTTP 客户端库，比如 Guzzle。

Guzzle 是一个使用 PHP 编写的 MIT 许可的 HTTP 客户端。可以通过运行`composer require guzzlehttp/guzzle`命令轻松安装它。

我们的 REST 服务很可能会更频繁地受到非 PHP 客户端的联系，而不是 PHP 客户端。考虑到这一点，让我们看看一个简单的 HTML/jQuery 客户端如何与我们的 REST 服务进行通信。我们通过将以下代码添加到`rest-service/client/index.html`来实现：

```php
<!DOCTYPE html>
<html lang="en">
 <head>
 <meta charset="UTF-8">
 <title>Client App</title>
 <script  src="https://code.jquery.com/jquery-3.1.1.min.js"
  integrity="sha256-hVVnYaiADRTO2PzUGmuLJr8BLUSjGIZsDYGmIJLv2b8="
  crossorigin="anonymous"></script>
 </head>
<body>
 <script>
    jQuery.ajax({
 method: 'POST',
 url: 'http://rest-service.server/user/welcome',
 headers: {'X-AUTH-TOKEN': 'some-auth-token-here'},
 data: JSON.stringify({name: 'John'}),
 dataType: 'json',
 contentType: 'application/json',
 success: function (response) {
 console.log(response.data);
      }
    });
 </script>
 </body>
</html>

```

jQuery 的`ajax()`方法充当 HTTP 客户端。通过传递正确的参数值，它能够成功地与 REST 服务建立请求-响应通信。

在本节中，我们已经涉及了一些 REST 服务的关键点。虽然我们只是浅尝辄止 REST 架构的整体，但这里呈现的示例应该足以让我们开始。JSON 和 HTTP 的易于实现和简单性使得 REST 对于现代应用程序来说是一个相当吸引人的选择。

# 使用 Apache Thrift（RPC）

Apache Thrift 是一个构建可扩展跨语言服务的开源框架。它最初由 Facebook 开发，然后于 2008 年 5 月左右进入 Apache 孵化器。简单性、透明性、一致性和性能是该框架背后的四个关键价值观。

与 REST 和 SOAP 类型的服务不同，Thrift 服务使用二进制形式的通信。幸运的是，Thrift 提供了一个代码生成引擎来帮助我们入门。代码生成引擎可以从任何**接口定义语言**（IDL）文件中提取并生成 PHP 或其他语言的绑定。

在我们开始编写第一个服务定义之前，我们需要安装 Apache Thrift。

# 安装 Apache Thrift

Apache Thrift 可以从源文件安装。假设我们有一个全新的 Ubuntu 16.10 安装，我们可以使用以下一组命令启动 Apache Thrift 安装步骤：

```php
sudo apt-get update
sudo apt-get -y install php automake bison flex g++ git libboost-all-dev libevent-dev libssl-dev libtool make pkg-config

```

这两个命令应该为我们提供编译 Apache Thrift 源文件所需的工具。完成后，我们可以在我们的机器上拉取实际的源文件：

```php
wget http://apache.mirror.anlx.net/thrift/0.10.0/thrift-0.10.0.tar.gz
tar -xvf thrift-0.10.0.tar.gz
cd thrift-0.10.0/

```

解压源文件后，我们可以触发`configure`和`make`命令，如下所示：

```php
./configure
make
make install

```

最后，我们需要确保我们的`LD_LIBRARY_PATH`路径上有`/usr/local/lib/`目录：

```php
echo "export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/" >> ~/.bashrc

```

现在我们应该退出 shell，然后重新登录。使用以下命令，我们确认安装了 Apache Thrift：

```php
thrift -version

```

这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/bae82a87-22da-447b-b7a8-d6a90ab6c31e.png)

安装了`thrift`工具并且可以通过控制台使用后，我们可以准备我们的`thrift-service`项目：

```php
mkdir thrift-service
cd thrift-service/
mkdir client
mkdir server
mkdir vendor
cd vendor
git clone https://github.com/apache/thrift.git

```

继续前进，我们将假设 Web 服务器配置为将`thrift-service/client`目录的内容提供给[`thrift-service.client`](http://thrift-service.client)请求，并将`thrift-service/server`目录的内容提供给[`thrift-service.server`](http://thrift-service.server)请求。

# 定义服务

在 PHP 中使用 Apache Thrift 可以通过以下几个步骤描述：

+   通过 IDL 文件定义服务

+   自动生成语言绑定

+   提供已定义接口的 PHP 实现

+   通过服务器公开提供的服务实现

+   通过客户端使用暴露的服务

Thrift 服务以`.thrift`文件的形式开始它们的生命周期，也就是说，由 IDL 描述的文件。

IDL 文件支持定义多种数据类型：

+   `bool`：这是一个布尔值（true 或 false）

+   `byte`：这是一个 8 位有符号整数

+   `i16`：这是一个 16 位有符号整数

+   `i32`：这是一个 32 位有符号整数

+   `i64`：这是一个 64 位有符号整数

+   `double`：这是一个 64 位浮点数

+   `string`：这是一个 UTF-8 编码的文本字符串

+   `二进制`：这是一系列未编码的字节

+   `struct`：这在面向对象编程语言中基本上相当于类，但没有继承

+   容器（`list`，`set`，`map`）：这映射到大多数编程语言中的常见容器类型

为了保持简单，我们将专注于`string`类型的使用。让我们创建我们的第一个 Apache Thrift 服务。我们通过在`thrift-service/`目录中创建一个`Greeting.thrift`文件来实现：

```php
namespace php user

service GreetingService
{
  string hello(1: string name),
  string goodbye()
}

```

我们可以看到 Thrift 文件是一个纯接口--这里没有实现。`namespace php user`语法转换为*当代码生成引擎运行时，在用户命名空间内为生成的 PHP 代码生成 GreetingService*。如果我们在 PHP 之外使用另一种语言，比如 Java，我们可以轻松地添加另一行，说`namespace java customer`。这将在一个命名空间中生成 PHP 绑定，在另一个命名空间中生成 Java 绑定。

我们可以看到`service`关键字被用来指定`GreetingService`接口。在接口内，我们有两个方法定义。`hello(1: string name)`接收一个名字参数，而`goodbye()`不接收任何参数。

有关 IDL 语法的更多详细信息，请参见[`thrift.apache.org/docs/idl`](https://thrift.apache.org/docs/idl)。

有了`Greeting.thrift`文件，我们可以触发代码生成以获得必要的 PHP 绑定。我们可以通过在控制台上执行以下代码来实现：

```php
thrift -r -gen php:server Greeting.thrift

```

此时，我们的文件夹结构应该类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/1041c9b3-049f-4abd-aefe-340e33ca8799.png)

我们可以看到`thrift`命令在`gen-php/user`目录下为我们生成了两个文件。`GreetingService.php`是一个相当大的文件；几乎有 500 行代码，它定义了与我们的 Thrift 服务一起使用所需的各种辅助函数和结构：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/5f7da8de-b524-41ac-8719-a9f24a34aff5.png)

而`Types.php`文件定义了几种不同的类型供使用：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/40a4fc71-9e31-4be4-b5e7-5b89fc8134ed.png)

所有这些类型都驻留在`thrift-service/vendor/thrift/lib/php/lib/Thrift`中，这就是我们之前执行`git clone https://github.com/apache/thrift.git`命令的原因。到目前为止，我们的`thrift-service/gen-php/user/GreetingService.php`服务在`hello()`和`goodbye()`方法逻辑方面还没有真正做任何事情。

# 创建服务器

`thrift-service/server/`目录是我们将实现项目服务器部分的地方。让我们创建一个单一的`thrift-service/server/index.php`文件，实现`hello()`和`goodbye()`方法，并通过[`thrift-service.server/index.php`](http://thrift-service.server/index.php)将它们暴露给任何可能到来的 thrift 请求：

```php
<?php

require_once __DIR__ . '/../vendor/thrift/lib/php/lib/Thrift/ClassLoader/ThriftClassLoader.php';

use Thrift\ClassLoader\ThriftClassLoader;
use Thrift\Transport\TPhpStream;
use Thrift\Transport\TBufferedTransport;
use Thrift\Protocol\TBinaryProtocol;
use user\GreetingServiceProcessor;
use user\GreetingServiceIf;

$loader = new ThriftClassLoader();
$loader->registerNamespace('Thrift', __DIR__ . '/../vendor/thrift/lib/php/lib');
$loader->registerDefinition('user', __DIR__ . '/../gen-php');
$loader->register();

class GreetingServiceImpl implements GreetingServiceIf
{
  public function hello($name)
  {
    return 'Hello ' . $name . '!';
  }

  public function goodbye()
  {
    return 'Goodbye!';
  }
}

header('Content-Type', 'application/x-thrift');

$handler = new GreetingServiceImpl();
$processor = new GreetingServiceProcessor($handler);
$transport = new TBufferedTransport(new TPhpStream(TPhpStream::MODE_R | TPhpStream::MODE_W));
$protocol = new TBinaryProtocol($transport, true, true);

$transport->open();
$processor->process($protocol, $protocol);
$transport->close();

```

我们首先包含了`ThriftClassLoader`类。然后，这个加载器类使我们能够为整个`Thrift`和`user`命名空间设置自动加载。然后，我们通过`GreetingServiceImpl`类实现了`hello()`和`goodbye()`方法。最后，我们实例化了适当的*handler*、*processor*、*transport*和*protocol*，以便能够处理传入的请求。

# 创建客户端

`thrift-service/client/`目录是我们将实现项目客户端的地方。让我们创建一个单一的`thrift-service/client/index.php`文件，从 Thrift 服务上的[`thrift-service.server/index.php`](http://thrift-service.server/index.php)调用`hello()`和`goodbye()`方法：

```php
<?php

require_once __DIR__ . '/../vendor/thrift/lib/php/lib/Thrift/ClassLoader/ThriftClassLoader.php';

use Thrift\ClassLoader\ThriftClassLoader;
use Thrift\Transport\THttpClient;
use Thrift\Transport\TBufferedTransport;
use Thrift\Protocol\TBinaryProtocol;
use user\GreetingServiceClient;

$loader = new ThriftClassLoader();
$loader->registerNamespace('Thrift', __DIR__ . '/../vendor/thrift/lib/php/lib');
$loader->registerDefinition('user', __DIR__ . '/../gen-php');
$loader->register();

$socket = new THttpClient('thrift-service.server', 80, '/index.php');
$transport = new TBufferedTransport($socket);
$protocol = new TBinaryProtocol($transport);
$client = new GreetingServiceClient($protocol);

$transport->open();

echo $client->hello('John');
echo $client->goodbye();

$transport->close();

```

就像服务器示例一样，在这里，我们也首先包含了`ThriftClassLoader`类，这样就能够为整个`Thrift`和`user`命名空间设置自动加载。然后我们实例化了 socket、传输、协议和客户端，从而与 Thrift 服务建立了连接。客户端和服务器都使用相同的`thrift-service/gen-php/user/GreetingService.php`文件。鉴于`GreetingServiceClient`位于自动生成的`GreetingService.php`文件中，这使得客户端可以立即了解`GreetingService`可能公开的任何方法。

要测试我们的客户端，我们只需要在浏览器中打开[`thrift-service.client/index.php`](http://thrift-service.client/index.php)。这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/237508b6-9a68-44b0-bcdb-259fd4979808.png)

在本节中，我们触及了 Apache Thrift 服务的一些关键点。虽然关于 Thrift 的 IDL 和类型系统还有很多要说的，但这里呈现的示例是朝着正确方向迈出的一步。

# 理解微服务

术语“微服务”表示一种以松散耦合服务形式构建应用程序的架构风格。这些独立部署的服务通常是通过 Web 服务技术构建的微型应用程序。一个服务可以通过 SOAP 进行通信，另一个可以通过 REST、Apache Thrift 或其他方式进行通信。这里没有规定明确的要求。总体思想是将一个庞大的单体应用程序切割成几个更小的应用程序，即服务，但要以符合业务目标的方式进行切割。

以下图表试图可视化这个概念：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/3779faf8-7bb6-459d-86f0-e4a652e50c7d.png)

由 Netflix 和亚马逊等公司推广，微服务风格旨在解决现代应用开发的一些关键挑战，其中包括以下几点：

+   **开发团队规模**：这是一个可以由相对较小的团队开发的单个微服务

+   **开发技能的多样性**：这些是可以用不同编程语言编写的不同服务

+   **更改/升级**：这些更小的代码片段更容易更改或更新

+   **集成和部署**：这些更小的代码片段更容易部署

+   **对新手更容易**：这些更小的代码片段更容易跟上

+   **业务能力聚焦**：这个单独的服务代码是围绕特定的业务能力组织的

+   **可扩展性**：并非所有东西都能等比例扩展；更小的代码块可以更容易地扩展

+   **故障处理**：这个单个故障服务不会导致整个应用程序崩溃

+   **技术栈**：这减少了对快速链接技术栈的依赖

与此同时，它们也带来了一些新的挑战，其中包括以下几点：

+   **服务通信**：这是围绕服务通信涉及的额外工作

+   **分布式事务**：这些是由跨越多个服务的业务需求引起的挑战

+   **测试和监控**：这比单体应用程序更具挑战性

+   **网络延迟**：每个微服务都会引入额外的网络延迟

+   **容错性**：这些微服务必须从根本上设计为容错

也就是说，构建微服务绝非易事。首先采用*单体架构*，以精心解耦和模块化的结构作为大多数应用的更好起点。一旦单体应用增长到影响我们管理方式的复杂程度，那么就是考虑将其切分为微服务的时候了。

# 总结

在本章中，我们研究了两种最常见和成熟的网络服务：SOAP 和 REST。我们还研究了一个新兴的明星，叫做 Apache Thrift。一旦我们通过了初始的 Apache Thrift 安装和设置障碍，诸如简单性、可扩展性、速度和可移植性等特性就会成为焦点。正如我们在客户端示例中看到的，RPC 调用可以很容易地通过一个中央代码库来实现——在我们的情况下是`thrift-service/gen-php/`目录。

虽然 Apache Thrift 在流行度方面还有待赶上，但它被 Facebook、Evernote、Pinterest、Quora、Uber 等知名公司使用的事实，无疑说明了它的价值。这并不是说未来方面 SOAP 或 REST 就不重要。选择正确的服务类型是一种*谨慎规划*和*前瞻思维*的问题。

最后，我们简要介绍了一种新兴的架构风格，称为微服务的一些关键要点。

前进时，我们将更仔细地研究在 PHP 应用程序中使用的一些最常用的数据库：MySQL、Mongo、Elasticsearch 和 Redis。


# 第十二章：与数据库一起工作

PHP 语言对多种不同的数据库有很好的支持。自 PHP 语言早期以来，MySQL 一直被 PHP 开发人员视为首选数据库。虽然最初的重点主要是**关系型数据库管理系统**（**RDBMS**），但其他类型的数据库在现代应用程序中同样（或更）重要。自文档和数据键值数据库以来，它们的受欢迎程度一直在增长。

如今，看到一个 PHP 应用程序同时使用 MySQL、Mongo、Redis，可能还有其他几个数据库或数据存储是很常见的。

Mongo 的 NoSQL（“非 SQL”，“非关系”或“不仅仅是 SQL”）特性允许构建生成大量新数据类型的应用程序，这些数据类型可能会迅速变化。摆脱了**SQL**（**结构化查询语言**）的严格性，使用结构化、半结构化、非结构化和多态数据与 Mongo 数据库一起成为全新的体验。像 Redis 这样的内存数据结构存储器以速度为目标，这使它们非常适合缓存和消息代理系统。

在本章中，我们将通过以下部分更详细地了解 MySQL、Mongo 和 Redis：

+   使用 MySQL

+   安装 MySQL

+   设置示例数据

+   通过 mysqli 驱动程序扩展进行查询

+   通过 PHP 数据对象驱动程序扩展进行查询

+   使用 MongoDB

+   安装 MongoDB

+   设置示例数据

+   通过 MongoDB 驱动程序扩展进行查询

+   使用 Redis

+   安装 Redis

+   设置示例数据

+   通过 phpredis 驱动程序扩展进行查询

在本章中，我们为三个数据库服务器提供了快速安装说明。这些说明在相对基本的水平上给出，没有进行通常在生产类型机器上进行的任何后安装配置或调整。这里的一般想法只是让开发者的机器能够运行每个数据库服务器。

# 使用 MySQL

MySQL 是一个开源的关系型数据库管理系统，已经存在了 20 多年。最初由瑞典公司 MySQL AB 开发和拥有，现在由 Oracle Corporation 拥有。MySQL 的当前稳定版本是 5.7。

MySQL 的一些关键优势可以概括如下：

+   跨平台，在服务器上运行

+   可用于桌面和 Web 应用程序

+   快速、可靠且易于使用

+   适用于小型和大型应用程序

+   使用标准 SQL

+   支持查询缓存

+   支持 Unicode

+   在使用 InnoDB 时的 ACID 兼容性

+   在使用 InnoDB 时的事务

# 安装 MySQL

假设我们使用的是新的 Ubuntu 16.10（Yakkety Yak）安装，以下步骤概述了我们如何设置 MySQL：

1.  要安装 MySQL，我们执行以下控制台命令：

```php
sudo apt-get update
sudo apt-get -y install mysql-server

```

1.  安装过程会触发一个控制台 GUI 界面，要求我们输入`root`用户密码：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/7f664b9e-a662-4d17-9720-59a7faa92dcf.png)

1.  提供的密码需要重复以确认：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/15b71313-29a0-484f-a4dd-dfe8720e51b7.png)

1.  安装完成后，我们可以执行以下`mysql --version`命令来确认 MySQL 服务器是否正在运行：

```php
root@vultr:~# mysql --version
mysql Ver 14.14 Distrib 5.7.17, for Linux (x86_64) using EditLine wrapper

```

1.  服务器运行后，我们需要保护安装。通过运行以下命令来完成：

```php
sudo mysql_secure_installation

```

1.  安全安装过程会触发一个交互式 shell，要求提供以下信息：

+   输入 root 用户的密码：

+   是否要设置 VALIDATE PASSWORD 插件？

+   请输入 0 = 低，1 = 中等和 2 = 强：

+   新密码：

+   重新输入新密码：

+   删除匿名用户？

+   禁止远程 root 登录？

+   删除测试数据库和对其的访问？

+   现在重新加载权限表？

以下截图描述了这个过程：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/d8d43bee-0866-40bc-833e-396789e3bab1.png)查看[`dev.mysql.com/doc/refman/5.7/en/validate-password-plugin.html`](https://dev.mysql.com/doc/refman/5.7/en/validate-password-plugin.html)获取有关密码验证插件的更多信息。

1.  安装安全完成后，我们可以继续并使用`mysql`控制台工具连接到 MySQL，如下所示：

```php
// INSECURE WAY (bare passwords in a command)
mysql -uroot -p'mL08e!Tq'
mysql --user=root --password='mL08e!Tq'

// SECURE WAY (triggers "enter password" prompt)
mysql -uroot -p
mysql --user=root --password

```

请注意在密码周围使用单引号字符（`'`）。虽然通常我们可以使用`"`或`'`引号，但密码中使用的`!`字符强制我们使用`'`。在这种情况下，如果不用单引号括起密码，我们将看到类似于!Tq: event not found 的错误。这是因为感叹号（`!`）是 bash 中的历史扩展的一部分。为了将其用作密码的一部分，我们需要将其括在单引号中。此外，我们的密码可以包含`'`或`"`字符。为了转义密码中的这些引号，我们可以使用前导反斜杠（\），或者用相反样式的引号将整个参数括起来。然而，解决古怪密码字符的最简单和最安全的方法是避免使用`-p`或`--password`参数分配密码值，并通过`输入密码：`提示提供密码。

这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/ace8ab7e-822e-4aa2-aeee-6539546b5240.png)查看[`dev.mysql.com/doc/refman/5.7/en/mysql-shell.html`](https://dev.mysql.com/doc/refman/5.7/en/mysql-shell.html)获取有关 MySQL shell 的更多信息。

# 设置示例数据

在我们继续查询 MySQL 之前，让我们先设置一些示例数据。MySQL 提供了一个名为 Sakila 的示例数据库，我们可以从官方 MySQL 网站下载，如下所示：

```php
cd ~
wget http://downloads.mysql.com/docs/sakila-db.tar.gz
tar -xzf sakila-db.tar.gz
cd sakila-db/

```

下载并解压缩后，这应该给我们以下三个文件：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/ea9fa1b3-cc77-4f8b-be21-392a783d5243.png)

接下来，我们需要看看如何导入`sakila-schema.sql`和`sakila-data.sql`。幸运的是，MySQL 提供了几种方法来做到这一点。快速查看`sakila-schema.sql`文件显示了文件顶部的以下条目：

```php
DROP SCHEMA IF EXISTS sakila;
CREATE SCHEMA sakila;
USE sakila;

```

这意味着`sakila-schema.sql`文件将为我们创建一个模式（数据库），并将其设置为当前使用的数据库。这是一个重要的部分需要理解，因为并非所有的`.sql` / 备份文件都会有这个，我们将被迫手动执行这一部分。了解`sakila-schema.sql`如何处理我们需要导入的所有内容后，以下命令显示了我们可以使用的三种不同方法：

```php
// Either this command
mysql -uroot -p < sakila-schema.sql

// Either this command
mysql -uroot -p -e "SOURCE sakila-schema.sql" 

```

第二个命令使用`-e` (`--execute`)参数将 SQL 语句传递给服务器。我们本可以轻松地在交互式中使用`mysql`工具，然后在其中执行`SOURCE sakila-schema.sql`。有了架构，我们可以继续导入实际数据：

```php
// Either this command
mysql -uroot -p < sakila-data.sql

// Either this command
mysql -uroot -p -e "SOURCE sakila-data.sql" 

```

如果我们现在交互式使用`mysql`工具，我们可以检查数据库是否成功导入：

```php
show databases;
use sakila;
show tables;

```

这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/2b3df6df-212e-4f2d-919f-029daa68b9c7.png)查看[`dev.mysql.com/doc/sakila/en/`](https://dev.mysql.com/doc/sakila/en/)获取有关 Sakila 示例数据库的更多信息。

# 通过 MySQLi 驱动程序扩展查询

有几个驱动程序扩展允许我们查询 MySQL。MySQLi 是其中之一。为了在控制台上使用 MySQLi，我们需要确保已安装 PHP CLI 和`mysql`驱动程序扩展：

```php
sudo apt-get -y install php7.0-cli php7.0-mysql

```

请注意扩展名缺少`i`后缀。安装了`mysql`驱动程序扩展后，我们可以继续并开始查询 MySQL 服务器。

# 连接

我们可以使用 MySQLi 函数或类与 MySQL 交互。为了面向对象编程，我们将在所有示例中使用类方法。使用`mysqli`类，我们可以从 PHP 建立与 MySQL 的连接，如下所示：

```php
$mysqli = new mysqli('127.0.0.1', 'root', 'mL08e!Tq', 'sakila');

```

这一行表达式将在`127.0.0.1`主机上查找 MySQL，并尝试使用`root`用户名和`mL08e!Tq`作为密码连接到其`sakila`数据库。

# 错误处理

在处理`mysqli`的错误时相对容易，因为我们可以使用简单的`try...catch`块，如下所示：

```php
<?php

mysqli_report(MYSQLI_REPORT_ALL);   try {
  $mysqli = new mysqli('127.0.0.1', 'root', 'mL08e!Tq', 'sakila'); } catch (Throwable $t) {   exit($t->getMessage()); }

```

理想情况下，我们希望只针对 MySQL 异常使用`mysqli_sql_exception`进行处理：

```php
<?php

mysqli_report(MYSQLI_REPORT_ALL);

try {
  $mysqli = new mysqli('127.0.0.1', 'root', 'mL08e!Tq', 'sakila');
} catch (mysqli_sql_exception $e) {
  exit($e->getMessage());
}

```

我们可以将以下报告级别之一传递给`mysqli_report()`函数：

+   `MYSQLI_REPORT_INDEX`: 这报告查询中是否使用了错误的索引或根本没有使用索引

+   `MYSQLI_REPORT_ERROR`: 这报告来自 MySQL 函数调用的错误

+   `MYSQLI_REPORT_STRICT`: 这报告`mysqli_sql_exception`而不是可能的警告

+   `MYSQLI_REPORT_ALL`: 这报告所有内容

+   `MYSQLI_REPORT_OFF`: 这不报告任何内容

虽然`MYSQLI_REPORT_ALL`可能看起来有些过度，但使用它可以准确定位应用程序级别不明显的 MySQL 错误，比如某列缺乏索引。

# 选择

我们可以使用`mysqli`实例的`query()`方法从 MySQL 中选择数据，如下所示：

```php
<?php   try {
  // Report on all types of errors
  mysqli_report(MYSQLI_REPORT_ALL);    // Open a new connection to the MySQL server
  $mysqli = new mysqli('127.0.0.1', 'root', 'mL08e!Tq', 'sakila');    // Perform a query on the database
  $result = $mysqli->query('SELECT * FROM customer WHERE email LIKE "MARIA.MILLER@sakilacustomer.org"');    // Return the current row of a result set as an object
  $customer = $result->fetch_object();    // Close opened database connection
  $mysqli->close();    // Output customer info
  echo $customer->first_name, ' ', $customer->last_name, PHP_EOL; } catch (mysqli_sql_exception $e) {
  // Output error and exit upon exception
  echo $e->getMessage(), PHP_EOL;
  exit; }

```

上面的例子会产生以下错误：

```php
No index used in query/prepared statement SELECT * FROM customer WHERE email = "MARIA.MILLER@sakilacustomer.org"

```

如果我们使用`MYSQLI_REPORT_STRICT`而不是`MYSQLI_REPORT_ALL`，我们就不会得到错误。然而，使用较少限制的错误报告并不是解决错误的办法。即使我们可能不负责数据库架构和维护，作为开发人员，我们有责任报告这些问题，因为它们肯定会影响我们应用程序的性能。在这种情况下，解决方案是实际上在 email 列上创建一个索引。我们可以通过以下查询轻松实现：

```php
ALTER TABLE customer ADD INDEX idx_email (email);

```

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/03089aff-be4e-4585-965d-fe41c12c0b33.png)

`idx_email`是我们要创建的索引的自由给定名称，而`email`是我们要创建索引的列。`idx_`前缀只是一些开发人员使用的约定，索引可以轻松地命名为`xyz`或只是`email`。

有了索引之后，如果我们现在尝试执行之前的代码，它应该输出 MARIA MILLER，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/80f364e5-0d24-403b-85d8-5184b001d2f7.png)

`query()`方法根据以下类型返回`mysqli_result`对象或`True`和`False`布尔值：

+   `SELECT`类型的查询 - `mysqli_result`对象或布尔值`False`

+   `SHOW`类型的查询 - `mysqli_result`对象或布尔值`False`

+   `DESCRIBE`类型的查询 - `mysqli_result`对象或布尔值`False`

+   `EXPLAIN`类型的查询 - `mysqli_result`对象或布尔值`False`

+   其他类型的查询 - 布尔值`True`或`False`

`mysqli_result`对象的实例有几种不同的结果获取方法：

+   `fetch_object()`: 这将结果集的当前行作为对象获取，并允许重复调用

+   `fetch_all()`: 这将以`MYSQLI_ASSOC`、`MYSQLI_NUM`或`MYSQLI_BOTH`的形式获取所有结果行

+   `fetch_array()`: 这将以`MYSQLI_ASSOC`、`MYSQLI_NUM`或`MYSQLI_BOTH`的形式获取单个结果行

+   `fetch_assoc()`: 这将以关联数组的形式获取单个结果行，并允许重复调用

+   `fetch_field()`: 这获取结果集中的下一个字段，并允许重复调用

+   `fetch_field_direct()`: 这获取单个字段的元数据

+   `fetch_fields()`: 这获取整个结果集中字段的元数据

+   `fetch_row()`: 这以枚举数组的形式获取单个结果行，并允许重复调用

# 绑定参数

更多时候，查询数据都伴随着数据绑定。从安全角度来看，数据绑定是正确的做法，因为我们不应该自己将查询字符串与变量连接起来。这会导致 SQL 注入攻击。我们可以使用相应的`mysqli`和`mysqli_stmt`实例的`prepare()`和`bind_param()`方法将数据绑定到查询中，如下所示：

```php
<?php   try {
  // Report on all types of errors
  mysqli_report(MYSQLI_REPORT_ALL);    // Open a new connection to the MySQL server
  $mysqli = new mysqli('127.0.0.1', 'root', 'mL08e!Tq', 'sakila');    $customerIdGt = 100;
  $storeId = 2;
  $email = "%ANN%";    // Prepare an SQL statement for execution
  $statement = $mysqli->prepare('SELECT * FROM customer WHERE customer_id > ? AND store_id = ? AND email LIKE ?');    // Binds variables to a prepared statement as parameters
  $statement->bind_param('iis', $customerIdGt, $storeId, $email);    // Execute a prepared query
  $statement->execute();    // Gets a result set from a prepared statement
  $result = $statement->get_result();    // Fetch object from row/entry in result set
  while ($customer = $result->fetch_object()) {
  // Output customer info
  echo $customer->first_name, ' ', $customer->last_name, PHP_EOL;
 }    // Close a prepared statement
  $statement->close();    // Close database connection
  $mysqli->close(); } catch (mysqli_sql_exception $e) {
  // Output error and exit upon exception
  echo $e->getMessage();
  exit; }

```

这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/f135143d-8a93-4901-9830-db2de28fa206.png)

`bind_param()`方法有一个有趣的语法。它接受两个或更多参数。第一个参数——`$types`字符串——包含一个或多个字符。这些字符指定了相应绑定变量的类型：

+   `i`：这是一个整数类型的变量

+   `d`：这是一个双精度类型的变量

+   `s`：这是一个字符串类型的变量

+   `b`：这是一个 blob 类型的变量

第二个及其后的所有参数代表绑定变量。我们的示例使用`'iis'`作为`$types`参数，基本上读取`bind_param()`方法及其参数为：绑定整数类型（`$customerIdGt`）、整数类型（`$storeId`）和字符串类型（`$email`）。

# 插入

现在我们已经学会了如何准备查询并将数据绑定到它，插入新记录变得非常容易：

```php
<?php   try {
  // Report on all types of errors
  mysqli_report(MYSQLI_REPORT_ALL);    // Open a new connection to the MySQL server
 $mysqli = new mysqli('127.0.0.1', 'root', 'mL08e!Tq', 'sakila');     // Prepare some teat address data
  $address = 'The street';
  $district = 'The district';
  $cityId = 135; // Matches the Dallas city in Sakila DB
  $postalCode = '31000';
  $phone = '123456789';    // Prepare an SQL statement for execution
  $statement = $mysqli->prepare('INSERT INTO address (
 address, district, city_id, postal_code, phone ) VALUES ( ?, ?, ?, ?, ? ); ');    // Bind variables to a prepared statement as parameters
  $statement->bind_param('ssiss', $address, $district, $cityId, $postalCode, $phone);    // Execute a prepared Query
  $statement->execute();    // Close a prepared statement
  $statement->close();    // Quick & "dirty" way to fetch newly created address id
  $addressId = $mysqli->insert_id;    // Close database connection
  $mysqli->close(); } catch (mysqli_sql_exception $e) {
  // Output error and exit upon exception
  echo $e->getMessage();
  exit; }

```

这里的示例基本上遵循了之前介绍的绑定。明显的区别仅在于实际的`INSERT INTO` SQL 表达式。不用说，`mysqli`没有单独的 PHP 类或方法来处理选择、插入或任何其他操作。

# 更新

与选择和插入类似，我们也可以使用`prepare()`、`bind_param()`和`execute()`方法来处理记录更新，如下所示：

```php
<?php   try {
  // Report on all types of errors
  mysqli_report(MYSQLI_REPORT_ALL);    // Open a new connection to the MySQL server
 $mysqli = new mysqli('127.0.0.1', 'root', 'mL08e!Tq', 'sakila');     // Prepare some teat address data
  $address = 'The new street';
  $addressId = 600;    // Prepare an SQL statement for execution
  $statement = $mysqli->prepare('UPDATE address SET address = ? WHERE address_id = ?');    // Bind variables to a prepared statement as parameters
  $statement->bind_param('si', $address, $addressId);    // Execute a prepared Query
  $statement->execute();    // Close a prepared statement
  $statement->close();     // Close database connection
  $mysqli->close(); } catch (mysqli_sql_exception $e) {
  // Output error and exit upon exception
  echo $e->getMessage();
  exit; } 

```

# 删除

同样，我们可以使用`prepare()`、`bind_param()`和`execute()`方法来处理记录删除，如下所示：

```php
<?php   try {
  // Report on all types of errors
  mysqli_report(MYSQLI_REPORT_ALL);    // Open a new connection to the MySQL server
 $mysqli = new mysqli('127.0.0.1', 'root', 'mL08e!Tq', 'sakila');     // Prepare some teat address data
  $paymentId = 500;    // Prepare an SQL statement for execution
  $statement = $mysqli->prepare('DELETE FROM payment WHERE payment_id = ?');    // Bind variables to a prepared statement as parameters
  $statement->bind_param('i', $paymentId);    // Execute a prepared Query
  $statement->execute();    // Close a prepared statement
  $statement->close();    // Close database connection
  $mysqli->close(); } catch (mysqli_sql_exception $e) {
  // Output error and exit upon exception
  echo $e->getMessage();
  exit; }

```

# 事务

虽然`SELECT`、`INSERT`、`UPDATE`和`DELETE`方法允许我们逐步操纵数据，但 MySQL 的真正优势在于事务。使用`mysqli`实例的`begin_transaction()`、`commit()`、`commit()`和`rollback()`方法，我们能够控制 MySQL 的事务特性：

```php
<?php   mysqli_report(MYSQLI_REPORT_ALL); $mysqli = new mysqli('127.0.0.1', 'root', 'mL08e!Tq', 'sakila');   try {
  // Start new transaction
  $mysqli->begin_transaction(MYSQLI_TRANS_START_READ_WRITE);    // Create new address
  $result = $mysqli->query('INSERT INTO address (
 address, district, city_id, postal_code, phone ) VALUES ( "The street", "The district", 333, "31000", "123456789" ); ');    // Fetch newly created address id
  $addressId = $mysqli->insert_id;    // Create new customer
  $statement = $mysqli->prepare('INSERT INTO customer (
 store_id, first_name, last_name, email, address_id ) VALUES ( 2, "John", "Doe", "john@test.it", ? ) ');
  $statement->bind_param('i', $addressId);
  $statement->execute();    // Fetch newly created customer id
  $customerId = $mysqli->insert_id;    // Select newly created customer info
  $statement = $mysqli->prepare('SELECT * FROM customer WHERE customer_id = ?');
  $statement->bind_param('i', $customerId);
  $statement->execute();
  $result = $statement->get_result();
  $customer = $result->fetch_object();    // Commit transaction
  $mysqli->commit();    echo $customer->first_name, ' ', $customer->last_name, PHP_EOL; } catch (mysqli_sql_exception $t) {
  // We MUST be careful with non-db try block operations that throw exceptions
 // As they might cause a rollback inadvertently  $mysqli->rollback();
  echo $t->getMessage(), PHP_EOL; }   // Close database connection $mysqli->close();

```

有效的事务标志如下：

+   `MYSQLI_TRANS_START_READ_ONLY`：这与 MySQL 的`START TRANSACTION READ ONLY`查询相匹配

+   `MYSQLI_TRANS_START_READ_WRITE`：这与 MySQL 的`START TRANSACTION READ WRITE`查询相匹配

+   `MYSQLI_TRANS_START_WITH_CONSISTENT_SNAPSHOT`：这与 MySQL 的`START TRANSACTION WITH CONSISTENT SNAPSHOT`查询相匹配

查看[`dev.mysql.com/doc/refman/5.7/en/commit.html`](https://dev.mysql.com/doc/refman/5.7/en/commit.html)以获取有关 MySQL 事务语法和含义的更多信息。

# 通过 PHP 数据对象驱动扩展进行查询

**PHP 数据对象**（**PDO**）驱动扩展自 PHP 5.1.0 以来就默认包含在 PHP 中。

# 连接

使用 PDO 驱动扩展，我们可以使用`PDO`类从 PHP 连接到 MySQL 数据库，如下所示：

```php
<?php   $host = '127.0.0.1'; $dbname = 'sakila'; $username = 'root'; $password = 'mL08e!Tq';   $conn = new PDO(
  "mysql:host=$host;dbname=$dbname",
  $username,
  $password  );

```

这个简单的多行表达式将在`127.0.0.1`主机上查找 MySQL，并尝试使用`root`用户名和`mL08e!Tq`密码连接到其`sakila`数据库。

# 错误处理

在 PDO 周围处理错误可以使用特殊的`PDOException`类，如下所示：

```php
<?php   try {
  $host = '127.0.0.1';
  $dbname = 'sakila';
  $username = 'root';
  $password = 'mL08e!Tq';    $conn = new PDO(
  "mysql:host=$host;dbname=$dbname",
  $username,
  $password,
 [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
 ); } catch (PDOException $e) {
  echo $e->getMessage(), PHP_EOL; }

```

有三种不同的错误模式：

+   `ERRMODE_SILENT`

+   `ERRMODE_WARNING`

+   `ERRMODE_EXCEPTION`

在这里，我们使用`ERRMODE_EXCEPTION`来利用`try...catch`块。

# 选择

通过`PDO`查询记录与通过`mysqli`查询记录有些类似。在两种情况下，我们都使用原始的 SQL 语句。区别在于 PHP 方法的便利性和它们提供的微妙差异。以下示例演示了我们如何从 MySQL 表中选择记录：

```php
<?php   try {
  $conn = new PDO(
  "mysql:host=127.0.0.1;dbname=sakila", 'root', 'mL08e!Tq',
 [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
 );    $result = $conn->query('SELECT * FROM customer LIMIT 5');
  $customers = $result->fetchAll(PDO::FETCH_OBJ);    foreach ($customers as $customer) {
  echo $customer->first_name, ' ', $customer->last_name, PHP_EOL;
 } } catch (PDOException $e) {
  echo $e->getMessage(), PHP_EOL; }

```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/ba1f9b0a-105f-4977-9655-96ca820db1b1.png)

`PDOStatement`实例和`$result`对象有几种不同的结果提取方法：

+   `fetch()`：这从结果集中提取下一行，允许重复调用，并根据提取样式返回一个值

+   `fetchAll()`：这将结果集中的所有行作为数组提取出来，并根据提取样式返回一个值

+   `fetchObject()`：这从结果集中提取下一行作为对象，并允许重复调用

+   `fetchColumn()`：这从结果集的下一行中提取单个列，并允许重复调用

以下列表显示了可用的 PDO 获取样式：

+   `PDO::FETCH_LAZY`

+   `PDO::FETCH_ASSOC`

+   `PDO::FETCH_NUM`

+   `PDO::FETCH_BOTH`

+   `PDO::FETCH_OBJ`

+   `PDO::FETCH_BOUND`

+   `PDO::FETCH_COLUMN`

+   `PDO::FETCH_CLASS`

+   `PDO::FETCH_INTO`

+   `PDO::FETCH_FUNC`

+   `PDO::FETCH_GROUP`

+   `PDO::FETCH_UNIQUE`

+   `PDO::FETCH_KEY_PAIR`

+   `PDO::FETCH_CLASSTYPE`

+   `PDO::FETCH_SERIALIZE`

+   `PDO::FETCH_PROPS_LATE`

+   `PDO::FETCH_NAMED`

虽然大多数这些获取样式都相当不言自明，我们可以查阅[`php.net/manual/en/pdo.constants.php`](http://php.net/manual/en/pdo.constants.php)以获取更多细节。

以下示例演示了更为详细的选择方法，其中包含参数绑定：

```php
<?php   try {
  $conn = new PDO(
  "mysql:host=127.0.0.1;dbname=sakila", 'root', 'mL08e!Tq',
 [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
 );    $statement = $conn->prepare('SELECT * FROM customer        WHERE customer_id > :customer_id AND store_id = :store_id AND email LIKE :email');    $statement->execute([
  ':customer_id' => 100,
  ':store_id' => 2,
  ':email' => '%ANN%',
 ]);    $customers = $statement->fetchAll(PDO::FETCH_OBJ);    foreach ($customers as $customer) {
  echo $customer->first_name, ' ', $customer->last_name, PHP_EOL;
 } } catch (PDOException $e) {
  echo $e->getMessage(), PHP_EOL; }

```

这将给出以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/083fe023-37f4-4e94-b8c7-a181425e22ef.png)

使用`PDO`和`mysqli`绑定的最明显区别是`PDO`允许命名参数绑定。这使得查询更加可读。

# 插入

就像选择一样，插入涉及相同一组包裹在`INSERT INTO` SQL 语句周围的 PDO 方法：

```php
<?php   try {
  $conn = new PDO(
 "mysql:host=127.0.0.1;dbname=sakila", 'root', 'mL08e!Tq',  [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
 );    $statement = $conn->prepare('INSERT INTO address (
 address, district, city_id, postal_code, phone, location ) VALUES ( :address, :district, :city_id, :postal_code, :phone, POINT(:longitude, :latitude) ); ');    $statement->execute([
  ':address' => 'The street',
  ':district' => 'The district',
  ':city_id' => '537',
  ':postal_code' => '31000',
  ':phone' => '888777666333',
  ':longitude' => 45.55111,
  ':latitude' => 18.69389
  ]); } catch (PDOException $e) {
  echo $e->getMessage(), PHP_EOL; }

```

# 更新

就像选择和插入一样，更新涉及相同一组包裹在`UPDATE` SQL 语句周围的 PDO 方法：

```php
<?php   try {
  $conn = new PDO(
  "mysql:host=127.0.0.1;dbname=sakila", 'root', 'mL08e!Tq',
 [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
 );    $statement = $conn->prepare('UPDATE address SET phone = :phone WHERE address_id = :address_id');    $statement->execute([
  ':phone' => '888777666555',
  ':address_id' => 600,
 ]); } catch (PDOException $e) {
  echo $e->getMessage(), PHP_EOL; }

```

# 删除

就像选择、插入和更新一样，删除涉及相同一组包裹在`DELETE FROM` SQL 语句周围的 PDO 方法：

```php
<?php   try {
  $conn = new PDO(
  "mysql:host=127.0.0.1;dbname=sakila", 'root', 'mL08e!Tq',
 [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
 );  $statement = $conn->prepare('DELETE FROM payment WHERE payment_id = :payment_id');
  $statement->execute([
  ':payment_id' => 16046
  ]); } catch (PDOException $e) {
  echo $e->getMessage(), PHP_EOL; }

```

# 事务

与 MySQLi 一样，PDO 的事务与 MySQLi 的事务并没有太大不同。通过利用`PDO`实例的`beginTransaction()`、`commit()`和`rollback()`方法，我们能够控制 MySQLi 的事务特性：

```php
<?php   $conn = new PDO(
  "mysql:host=127.0.0.1;dbname=sakila", 'root', 'mL08e!Tq',
 [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION] );   try {
  // Start new transaction
  $conn->beginTransaction();    // Create new address
  $result = $conn->query('INSERT INTO address (
 address, district, city_id, postal_code, phone, location ) VALUES ( "The street", "The district", 537, "27107", "888777666555", POINT(45.55111, 18.69389) ); ');    // Fetch newly created address id
  $addressId = $conn->lastInsertId();    // Create new customer
  $statement = $conn->prepare('INSERT INTO customer (
 store_id, first_name, last_name, email, address_id ) VALUES ( 2, "John", "Doe", "john-pdo@test.it", :address_id ) ');    $statement->execute([':address_id' => $addressId]);    // Fetch newly created customer id
  $customerId = $conn->lastInsertId();    // Select newly created customer info
  $statement = $conn->prepare('SELECT * FROM customer WHERE customer_id = :customer_id');
  $statement->execute([':customer_id' => $customerId]);
  $customer = $statement->fetchObject();    // Commit transaction
  $conn->commit();    echo $customer->first_name, ' ', $customer->last_name, PHP_EOL; } catch (PDOException $e) {
  $conn->rollback();
  echo $e->getMessage(), PHP_EOL; }

```

# 使用 MongoDB

MongoDB 是由 MongoDB Inc.开发的免费开源 NoSQL 数据库。

MongoDB 的一些关键优势可以概括如下：

+   它是一个基于文档的数据库

+   它是跨平台的

+   它既可以在单个服务器上运行，也可以在分布式架构上运行

+   它可以用于桌面和 Web 应用程序

+   它使用 JSON 对象来存储数据

+   它可以在服务器端使用 JavaScript map-reduce 进行信息处理

+   它处理大量数据

+   它聚合计算

+   它支持字段、范围查询和正则表达式搜索

+   它是本地复制

# 安装 MongoDB

假设我们正在使用全新的 Ubuntu 16.10（Yakkety Yak）安装，以下步骤概述了我们如何设置 MongoDB：

1.  我们将使用以下控制台命令安装 MongoDB：

```php
sudo apt-get update
sudo apt-get install -y mongodb

```

1.  为了进一步检查 MongoDB 是否成功安装和运行，我们可以执行以下命令：

```php
sudo systemctl status mongodb.service

```

1.  这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/c1e47bda-507b-4206-bfcc-d595cda6935e.png)

# 设置示例数据

在 Ubuntu 终端上运行`mongo`命令可以进入 mongo 交互式 shell。从这里开始，只需简单的几个命令，我们就可以添加示例数据：

```php
use foggyline
db.products.insert({name: "iPhone 7", price: 650, weight: "138g"});
db.products.insert({name: "Samsung Galaxy S7", price: 670, weight: "152g" });
db.products.insert({name: "Motorola Moto Z Play", price: 449.99, weight: "165g" });
db.products.insert({name: "Google Pixel", price: 649.99, weight: "168g" });
db.products.insert({name: "HTC 10", price: 799, weight: "161g" });
show dbs
show collections

```

这应该给我们一个与以下截图类似的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/f83de627-4f06-4e31-acf9-62d4bf809f6f.png)

使用`use foggyline`和`db.products.find()`，我们现在可以列出添加到`products`集合中的所有条目：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/f077bd4e-6193-4bee-a8d0-2b4324c8b276.png)

# 通过 MongoDB 驱动程序扩展查询

我们需要确保已安装 PHP CLI 和 MongoDB 驱动程序扩展：

```php
sudo apt-get -y install php-pear
sudo apt-get -y install php7.0-dev
sudo apt-get -y install libcurl4-openssl-dev pkg-config libssl-dev libsslcommon2-dev
sudo pecl install mongodb

```

成功执行这些命令后，我们可以确认`mongodb`驱动程序扩展已安装，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/7f71d7c9-2572-404e-8bae-5b02547f3110.png)

除了驱动程序扩展，我们还需要在项目目录中添加`mongodb/mongodb`composer 包。我们可以通过运行以下控制台命令来实现：

```php
sudo apt-get -y install composer
composer require mongodb/mongodb

```

假设我们的项目目录中有`mongo.php`文件，只需加载 MongoDB 库，就可以开始使用 Mongo 数据库：

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   // Code...

```

# 连接

使用`mongodb`驱动程序扩展和`mongodb/mongodb` PHP 库，我们可以使用`MongoDBDriverManager`类从 PHP 连接到 Mongo 数据库，如下所示：

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   $manager = new MongoDBDriverManager('mongodb://localhost:27017');

```

这个单行表达式将在`localhost`的端口`27017`下寻找 MongoDB。

# 错误处理

使用`try...catch`块处理错误非常简单，因为每当发生错误时，都会抛出`MongoDBDriverExceptionException`：

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   try {
  $manager = new MongoDBDriverManager('mongodb://localhost:27017'); } catch (MongoDBDriverExceptionException $e) {
  echo $e->getMessage(), PHP_EOL;
  exit; }

```

# 选择

使用 MongoDB 获取数据涉及与三个不同类的工作，`MongoDBDriverManager`，`MongoDBDriverQuery`和`MongoDBDriverReadPreference`：

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   try {
  $manager = new MongoDBDriverManager('mongodb://localhost:27017');    /* Select only the matching documents */
  $filter = [
  'price' => [
  '$gte' => 619.99,
 ], ];    $queryOptions = [
  /* Return only the following fields in the matching documents */
  'projection' => [
  'name' => 1,
  'price' => 1,
 ],  /* Return the documents in descending order of price */
  'sort' => [
  'price' => -1
  ]
 ];    $query = new MongoDBDriverQuery($filter, $queryOptions);    $readPreference = new MongoDBDriverReadPreference(MongoDBDriverReadPreference::RP_PRIMARY);    $products = $manager->executeQuery('foggyline.products', $query, $readPreference);    foreach ($products as $product) {
  echo $product->name, ': ', $product->price, PHP_EOL;
 } } catch (MongoDBDriverExceptionException $e) {
  echo $e->getMessage(), PHP_EOL;
  exit; }

```

这会产生以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/8dc9e943-de05-44f8-8ddf-0a23749090bc.png)

我们可以传递给`$filter`的查询运算符列表非常广泛，但以下比较运算符可能是最有趣的：

+   `$eq`: 这些匹配所有等于指定值的值

+   `$gt`: 这些匹配所有大于指定值的值

+   `$gte`: 这些匹配所有大于或等于指定值的值

+   `$lt`: 这些匹配所有小于指定值的值

+   `$lte`: 这些匹配所有小于或等于指定值的值

+   `$ne`: 这些匹配所有不等于指定值的值

+   `$in`: 这些匹配数组中指定的所有值

+   `$nin`: 这些匹配数组中指定的无值

查看[ttps://docs.mongodb.com/manual/reference/operator/query/](https://docs.mongodb.com/manual/reference/operator/query/)，了解 MongoDB 查询和投影运算符的完整列表。

我们可以传递给`$queryOptions`的查询选项列表同样令人印象深刻，但以下选项可能是最重要的选项：

+   `collation`: 这些允许指定字符串比较的语言特定规则

+   `limit`: 这些允许指定要返回的文档的最大数量

+   `maxTimeMS`: 这些以毫秒为单位设置处理操作的时间限制

+   `projection`: 这些允许指定返回文档中包含哪些字段

+   `sort`: 这些允许指定结果的排序顺序

查看[`php.net/manual/en/mongodb-driver-query.construct.php`](http://php.net/manual/en/mongodb-driver-query.construct.php)，了解`MongoDBDriverQuery`查询选项的完整列表。

# 插入

使用 MongoDB 编写新数据涉及与三个不同类的工作，`MongoDBDriverManager`，`MongoDBDriverBulkWrite`和`MongoDBDriverWriteConcern`：

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   try {
  $manager = new MongoDBDriverManager('mongodb://localhost:27017');    $bulkWrite = new MongoDBDriverBulkWrite;    $bulkWrite->insert([
  'name' => 'iPhone 7 Black White',
  'price' => 650,
  'weight' => '138g'
  ]);    $bulkWrite->insert([
  'name' => 'Samsung Galaxy S7 White',
  'price' => 670,
  'weight' => '152g'
  ]);    $writeConcern = new MongoDBDriverWriteConcern(MongoDBDriverWriteConcern::MAJORITY, 1000);    $result = $manager->executeBulkWrite('foggyline.products', $bulkWrite, $writeConcern);    if ($result->getInsertedCount()) {
  echo 'Record(s) saved successfully.', PHP_EOL;
 } else {
  echo 'Error occurred.', PHP_EOL;
 } } catch (MongoDBDriverExceptionException $e) {
  echo $e->getMessage(), PHP_EOL;
  exit; } 

```

`BulkWrite`的实例可以通过`insert()`方法存储一个或多个插入语句。然后我们简单地将`$bulkWrite`和`$writeConcern`传递给`$manager`实例上的`executeBulkWrite()`。执行后，我们可以通过`mongo` shell 观察到新添加的记录：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/dca64ccf-a77c-4baf-8350-0a99565ef598.png)

# 更新

更新现有数据几乎与编写新数据的过程相同。明显的区别在于在`MongoDBDriverBulkWrite`实例上使用`update()`方法：

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   try {
  $manager = new MongoDBDriverManager('mongodb://localhost:27017');    $bulkWrite = new MongoDBDriverBulkWrite;    $bulkWrite->update(
 ['name' => 'iPhone 7 Black White'],
 ['$set' => [
  'name' => 'iPhone 7 Black Black',
  'price' => 649.99
  ]],
 ['multi' => true, 'upsert' => false]
 );    $bulkWrite->update(
 ['name' => 'Samsung Galaxy S7 White'],
 ['$set' => [
  'name' => 'Samsung Galaxy S7 Black',
  'price' => 669.99
  ]],
 ['multi' => true, 'upsert' => false]
 );    $writeConcern = new MongoDBDriverWriteConcern(MongoDBDriverWriteConcern::MAJORITY, 1000);    $result = $manager->executeBulkWrite('foggyline.products', $bulkWrite, $writeConcern);    if ($result->getModifiedCount()) {
  echo 'Record(s) saved updated.', PHP_EOL;
 } else {
  echo 'Error occurred.', PHP_EOL;
 } } catch (MongoDBDriverExceptionException $e) {
  echo $e->getMessage(), PHP_EOL;
  exit; } 

```

`update()`方法接受三个不同的参数：过滤器，新对象和更新选项。在更新选项下传递的`multi`选项告诉是否将更新所有文档的匹配条件。在更新选项下传递的`upsert`选项控制如果找不到现有记录，则创建新记录。通过`mongo` shell 可以观察到结果的更改：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/bef46af0-ec27-46f9-9912-9215f17ee3c7.png)

# 删除

删除类似于写入和更新的方式进行，它使用`MongoDBDriverBulkWrite`对象的实例。这次，我们使用`delete()`方法的实例，它接受过滤器和删除选项：

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   try {
  $manager = new MongoDBDriverManager('mongodb://localhost:27017');    $bulkWrite = new MongoDBDriverBulkWrite;    $bulkWrite->delete(
  // filter
  [
  'name' => [
  '$regex' => '^iPhone'
  ]
 ],  // Delete options
  ['limit' => false]
 );    $writeConcern = new MongoDBDriverWriteConcern(MongoDBDriverWriteConcern::MAJORITY, 1000);    $result = $manager->executeBulkWrite('foggyline.products', $bulkWrite, $writeConcern);    if ($result->getDeletedCount()) {
  echo 'Record(s) deleted.', PHP_EOL;
 } else {
  echo 'Error occurred.', PHP_EOL;
 } } catch (MongoDBDriverExceptionException $e) {
  echo $e->getMessage(), PHP_EOL;
  exit; } 

```

使用`false`值作为`limit`选项，我们实际上要求删除所有匹配的文档。使用`mongo` shell，我们可以观察到以下截图中显示的更改：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/75596302-1926-4aa5-a7ad-a598e97a3dde.png)

# 交易

MongoDB 在某种意义上不具有与 MySQL 相同的完整**ACID**（原子性、一致性、隔离性、持久性）支持。它仅在文档级别支持 ACID 事务。不支持多文档事务。ACID 合规性的缺失确实限制了它在依赖于此功能的平台上的使用。这并不是说 MongoDB 不能与这些平台一起使用。让我们考虑一个流行的 Magento 电子商务平台。没有什么可以阻止 Magento 将 MongoDB 添加到混合中。虽然 MySQL 功能可以保证与销售相关功能的 ACID 合规性，但 MongoDB 可以在其中使用以覆盖目录功能的部分。这种共生关系可以轻松地将两种数据库功能的最佳部分带到我们的平台上。

# 使用 Redis

Redis 是一个开源的内存数据结构存储，由 Redis Labs 赞助开发。其名称源自**REmote DIctionary Server**。它目前是最受欢迎的键值数据库之一。

Redis 的一些关键优势可以概括如下：

+   内存数据结构存储

+   键值数据存储

+   具有有限生存时间的键

+   发布/订阅消息

+   它可以用于缓存数据存储

+   事务

+   主从复制

# 安装 Redis

假设我们正在使用全新的 Ubuntu 16.10（Yakkety Yak）安装，以下步骤概述了我们如何设置 Redis 服务器：

1.  我们可以使用以下控制台命令安装 Redis 服务器：

```php
sudo apt-get update
sudo apt-get -y install build-essential tcl
wget http://download.redis.io/redis-stable.tar.gz
tar xzf redis-stable.tar.gz
cd redis-stable
make
make test
sudo make install
./src/redis-server

```

1.  这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/e171ce49-e5c7-4be9-9cef-c9d54b12f95e.png)

# 设置示例数据

在 Ubuntu 终端上运行`redis-cli`命令可以进入 Redis 交互式 shell。从这里开始，通过简单的几个命令，我们可以添加以下示例数据：

```php
SET Key1 10
SET Key2 20
SET Key3 30
SET Key4 40
SET Key5 50

```

这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/d182d03c-9f1a-4e64-a1c7-b1187fa08bbf.png)

使用`redis-cli` shell 中的`KEYS *`命令，我们现在可以列出 Redis 添加的所有条目：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/2264aaab-0740-45d0-b8d6-96a37f4e7146.png)

# 通过 phpredis 驱动程序扩展进行查询

在开始查询之前，我们需要确保已安装 PHP CLI 和`phpredis`驱动程序扩展：

```php
sudo apt-get -y install php7.0-dev
sudo apt-get -y install unzip
wget https://github.com/phpredis/phpredis/archive/php7.zip -O phpredis.zip
unzip phpredis.zip 
cd phpredis-php7/
phpize
./configure
make
sudo make install
echo extension=redis.so >> /etc/php/7.0/cli/php.ini

```

执行这些命令后，我们可以确认`phpredis`驱动程序扩展已安装如下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/6bcd8954-b17a-4e94-94cc-e53c94316c88.png)

# 连接

使用`phpredis`驱动程序扩展，我们可以使用`Redis`类从 PHP 连接到 Redis，如下所示：

```php
<?php   $client = new Redis();   $client->connect('localhost', 6379);

```

这个单行表达式将在本地主机的端口`6379`下查找 Redis。

# 错误处理

`phpredis`驱动程序扩展对使用`Redis`类时发生的每个错误都会抛出`RedisException`。这使得通过简单的`try...catch`块轻松处理错误：

```php
<?php   try {
  $client = new Redis();
  $client->connect('localhost', 6379);
  // Code... } catch (RedisException $e) {
  echo $e->getMessage(), PHP_EOL; } 

```

# 选择

鉴于 Redis 是一个键值存储，选择键就像使用`Redis`实例的单个`get()`方法一样容易：

```php
<?php   try {
  $client = new Redis();
  $client->connect('localhost', 6379);
  echo $client->get('Key3'), PHP_EOL;
  echo $client->get('Key5'), PHP_EOL; } catch (RedisException $e) {
  echo $e->getMessage(), PHP_EOL; } 

```

这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/61576137-5dfa-4782-8aa2-c02a063425cd.png)

`Redis`客户端类还提供了`mget()`方法，可以一次获取多个键值：

```php
<?php   try {
  $client = new Redis();
  $client->connect('localhost', 6379);    $values = $client->mget(['Key1', 'Key2', 'Key4']);
  print_r($values); } catch (RedisException $e) {
  echo $e->getMessage(), PHP_EOL; }

```

这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/82bc6db8-3fc6-4983-ac5b-7045e0e301c4.png)

# 插入

Redis 键值机制背后的简单性使得`set()`方法简单直接，通过它我们可以插入新条目，如下例所示：

```php
<?php   try {
  $client = new Redis();
  $client->connect('localhost', 6379);    $client->set('user', [
  'name' => 'John',
  'age' => 34,
  'salary' => 4200.00
  ]);    // $client->get('user');
 // returns string containing "Array" chars    $client->set('customer', json_encode([
  'name' => 'Marc',
  'age' => 43,
  'salary' => 3600.00
  ]));    // $client->get('customer');
 // returns json looking string, which we can simply json_decode() } catch (RedisException $e) {
  echo $e->getMessage(), PHP_EOL; }

```

这应该给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/50b0a300-61e0-4d2f-b323-84dc6a9ca282.png)

当使用非字符串结构的 set 方法时，我们需要小心。`user`键值导致存储在 Redis 中的是数组字符串，而不是实际的数组结构。通过在传递给`set()`方法之前使用`json_encode()`将数组结构转换为 JSON，可以轻松解决这个问题。

`set()`方法的一个很大的好处是它支持以秒为单位的超时，因此我们可以轻松地编写以下表达式：

```php
$client->set('test', 'test2', 3600);

```

虽然调用`setex()`方法是我们想要为键添加超时的首选方式：

```php
$client->setex('key', 3600, 'value');

```

在使用 Redis 作为缓存数据库时，超时是一个很好的功能。它们基本上为我们自动设置了缓存的生命周期。

# 更新

通过 Redis 客户端更新值与插入值相同。我们使用相同的`set()`方法，使用相同的键。如果存在先前的值，新值将简单地覆盖它：

```php
<?php   try {
  $client = new Redis();
  $client->connect('localhost', 6379);    $client->set('test', 'test1');
  $client->set('test', 'test2');    // $client->get('test');
 // returns string containing "test2" chars } catch (RedisException $e) {
  echo $e->getMessage(), PHP_EOL; }

```

# 删除

从 Redis 中删除记录就像调用 Redis 客户端的`del()`方法并传递要删除的键一样简单：

```php
<?php   try {
  $client = new Redis();
  $client->connect('localhost', 6379);
  $client->del('user'); } catch (RedisException $e) {
  echo $e->getMessage(), PHP_EOL; }

```

# 事务

与 MongoDB 类似，Redis 在某种意义上也没有像 MySQL 那样的 ACID 支持，这其实没关系，因为 Redis 只是一个键/值存储，而不是关系数据库。然而，Redis 提供了一定程度的原子性。使用`MULTI`、`EXEC`、`DISCARD`和`WATCH`，我们能够在单个步骤中执行一组命令，Redis 在此期间提供以下两项保证：

+   另一个客户端请求永远不会在我们的组命令执行过程中被服务

+   所有命令要么全部执行，要么全部不执行

让我们看一下以下示例：

```php
<?php   try {
  $client = new Redis();
  $client->connect('localhost', 6379);    $client->multi();    $result1 = $client->set('tKey1', 'Test#1'); // Valid command
  $result2 = $client->zadd('tKey2', null); // Invalid command    if ($result1 == false || $result2 == false) {
  $client->discard();
  echo 'Transaction aborted.', PHP_EOL;
 } else {
  $client->exec();
  echo 'Transaction commited.', PHP_EOL;
 } } catch (RedisException $e) {
  echo $e->getMessage(), PHP_EOL; }

```

`$result2`的值为`false`，触发了`$client->discard();`。虽然`result1`是一个有效的表达式，但它是在`$client->multi();`调用之后出现的，这意味着它的命令实际上并没有被处理；因此，我们看不到存储在 Redis 中的`Test#1`的值。虽然没有经典的回滚机制，就像我们在 MySQL 中看到的那样，但这为一个良好的事务模型。

# 总结

在本章中，我们涉及了查询三种非常不同的数据库系统的基础知识。

MySQL 数据库已经存在很长时间，很可能是大多数 PHP 应用程序的第一个数据库。其 ACID 兼容性使其在处理财务或其他敏感数据的应用程序中不可替代，其中原子性、一致性、隔离性和耐久性是关键因素。

另一方面，Mongo 通过无模式的方法处理数据存储。这使开发人员更容易加快应用程序的开发速度，尽管文档之间缺乏 ACID 兼容性限制了它在某些类型的应用程序中的使用。

最后，Redis 数据存储作为我们应用程序的一个很好的缓存，甚至是会话存储解决方案。

接下来，我们将更仔细地看一下依赖注入，它是什么，以及在模块化应用程序中扮演什么角色。
