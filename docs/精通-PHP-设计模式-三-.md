# 精通 PHP 设计模式（三）

> 原文：[`zh.annas-archive.org/md5/40e204436ec0fe9f5a036c3d1b49caeb`](https://zh.annas-archive.org/md5/40e204436ec0fe9f5a036c3d1b49caeb)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：行为设计模式

行为设计模式关乎对象之间的通信。

牢记单一责任原则，类只封装一个责任是至关重要的。鉴于此，显然有必要允许对象进行通信。

通过使用行为设计模式，我们能够增加进行这些通信的灵活性。

在本章中，我们将介绍以下模式：

+   观察者模式（SplObserver/SplSubject）

+   迭代器

+   PHP 的许多迭代器

+   生成器

+   模板模式

+   责任链模式

+   策略模式

+   规范模式

+   定时任务模式

# 热情程序员的个性特征

在我们开始讨论行为设计模式之前，让我们先谈谈你作为开发人员的行为。在本书的早些时候，我已经谈到开发失败经常是由于糟糕的管理实践而出现的。

让我们想象两种情景：

+   一家公司引入 Scrum 作为一种方法论（或者另一种缺乏技术知识的“敏捷”方法论），而他们的代码并不足够灵活以承受代码。在这些情况下，当代码被添加时，它经常被拼凑在一起，几乎可以肯定的是，代码的实现时间比没有技术债务时要长得多。这导致开发速度缓慢。

+   或者，一个公司遵循严格预定义的流程，而这种方法论是一成不变的。这些流程通常是不合理的，但开发人员经常遵循它们，因为他们没有接受更好流程的教育，不想卷入官僚纠纷来改变它们，甚至可能因试图改进流程而担心受到纪律处分。

在这两种情况下，一个糟糕的流程是问题的核心。即使你没有处理遗留项目，由于财产要求的变化，这也可能成为一个问题。软件的一个好特性是能够改变，甚至改变软件本身的设计（我们将在重构的最后一章讨论这个问题）。

Alastair Cockburn 指出，软件开发人员通常不适合预定义的生产线流程。人类是不可预测的，当他们是任何给定流程中的关键行为者时，流程也变得不可预测。人类容易出错，在软件开发中有很多错误的空间，他们在预定义流程中不会完美地行事。基本上，这就是为什么人必须高于流程，正如敏捷宣言中所述。开发人员必须高于流程。

一些管理职位的人想要购买所谓的敏捷。他们会雇佣一个不了解软件开发如何真正取得成功的顾问，而是作为销售敏捷的摇钱树运营实施一个荒谬的流程。我认为 Scrum 是这种情况的最糟糕的例子（部分原因是因为不准确的课程和伪资格的数量），但毫无疑问其他敏捷流程也可以被用作摇钱树。

我曾多次接触到声称“Scrum 说我们应该做…”或“敏捷说我们应该做…”的经理或 Scrum 大师。这在心理上是不合逻辑的，应该避免。当你说这句话时，你基本上没有理解敏捷方法论是基于灵活性原则的，因此，人必须高于流程。

让我们再次回顾第一个情景。请注意，争议主要是由于开发质量的缺乏而不是项目管理流程。Scrum 未能实施开发流程，因此，通过 Scrum 尝试的项目往往会失败。

极限编程（XP）包含这些开发规则，Scrum 缺乏这些规则。以下是一些例子：

+   编码标准（在 PHP 中，你可以选择我们在前几章讨论过的 PSR 标准）

+   首先编写单元测试，然后编写代码使其通过测试

+   所有的生产代码都是成对编程的

+   一个专用的集成服务器一次只集成一对代码，代码被频繁地集成

+   使用集体所有权；代码库的任何部分都不会对其他开发人员限制

这一切都是在修复 XP 的背景下完成的，使改进过程成为开发的常规部分。

引入技术标准和开发规则需要对开发有先验知识并对学习有热情；因此，逻辑和以证据为基础的思维过程至关重要。这些都是成为优秀软件工程师的关键要素。

配对编程不能成为辅导的一种努力，也不能成为学生和老师之间的关系；两个开发人员都必须愿意提出想法并接受这些想法的批评。事实上，能够互相学习是至关重要的。

在敏捷关系中，每个人都必须愿意理解和贡献规划过程，因此沟通是一项至关重要的技能。同样，彼此尊重是关键；从客户到开发人员，每个人都应该受到尊重。开发人员在许多方面都必须勇敢，尤其是在关于进展和估计的真实性方面，同时也必须适应变化。我们必须在处理或拒绝反馈之前努力理解我们收到的反馈。

这些技能不仅仅是开关，它们是开放式的技能和知识基础，我们必须努力维护和运用。事情会出错；通过使用反馈，我们能够确保我们的代码在部署之前具有足够高的质量。

# 观察者模式（SplObserver/SplSubject）

观察者设计模式本质上允许一个对象（主题）维护一个观察者列表，当该对象的状态发生变化时，这些观察者会自动收到通知。

这种模式应用于对象之间的一对多依赖关系；总是有一个主题更新多个观察者。

四人帮最初确定这种模式特别适用于抽象有两个方面，其中一个依赖于另一个的情况。除此之外，当对象的更改需要对其他对象进行更改，而你不知道需要更改多少其他对象时，这种模式也非常有用。最后，当一个对象应该通知其他对象而不做出关于这些对象是什么的假设时，这种模式也非常有用，因此这种模式非常适用于松散耦合的关系。

PHP 提供了一个非常有用的接口，称为`SplObserver`和`SplSubject`。这些接口提供了实现观察者设计模式的模板，但实际上并没有实现任何功能。

实质上，当我们实现这种模式时，我们允许无限数量的对象观察主题中的事件。

通过在`subject`对象中调用`attach`方法，我们可以将观察者附加到主题上。当主题发生变化时，主题的`notify`方法可以遍历观察者并多态地调用它们的`update`方法。

我们还可以在主题中调用一个未通知的方法，这将允许我们停止一个`观察者`对象观察一个`主题`对象。

鉴于此，`Subject`类包含了将观察者附加到自身和从自身分离的方法，该类还包含了一个`notify`方法来更新正在观察它的观察者。因此，PHP 的`SplSubject`接口如下：

```php
interface SplSubject  { 
  public function attach (SplObserver $observer); 
   public function detach (SplObserver $observer); 
   public function notify (); 
} 

```

与此相比，我们的`SplObserver`接口看起来更简单；它只需要实现一个允许主题更新观察者的方法：

```php
interface SplObserver  { 
  public function update (SplSubject $subject); 
} 

```

现在，让我们看看如何实现这两个接口来实现这个设计模式。在这个例子中，我们将有一个新闻订阅类，它将更新正在阅读这些类的各种读者。

让我们定义我们的`Feed`类，它将实现`SplSubject`接口：

```php
<?php 

class Feed implements SplSubject 
{ 
  private $name; 
  private $observers = array(); 
  private $content; 

  public function __construct($name) 
  { 
    $this->name = $name; 
  } 

  public function attach(SplObserver $observer) 
  { 
    $observerHash = spl_object_hash($observer); 
    $this->observers[$observerHash] = $observer; 
  } 

  public function detach(SplObserver $observer) 
  { 
    $observerHash = spl_object_hash($observer); 
    unset($this->observers[$observerHash]); 
  } 

  public function breakOutNews($content) 
  { 
    $this->content = $content; 
    $this->notify(); 
  } 

  public function getContent() 
  { 
    return $this->content . " on ". $this->name . "."; 
  } 

  public function notify() 
  { 
    foreach ($this->observers as $value) { 
      $value->update($this); 
    } 
  } 
} 

```

我们讨论的实现总体上相当简单。请注意，它使用了我们在本书中之前探讨过的`spl_object_hash`函数，以便让我们轻松地分离对象。通过使用哈希作为数组的键，我们能够快速找到给定的对象，而无需进行其他操作。

现在我们可以定义我们的`Reader`类，它将实现`SplObserver`接口：

```php
<?php 

class Reader implements SplObserver 
{ 
  private $name; 

  public function __construct($name) 
  { 
    $this->name = $name; 
  } 

  public function update(SplSubject $subject) 
  { 
    echo $this->name . ' is reading the article ' . $subject->getContent() . ' '; 
  } 
} 

```

让我们将所有这些内容放在我们的`index.php`文件中：

```php
<?php 

require_once('Feed.php'); 
require_once('Reader.php'); 

$newspaper = new  Feed('Junade.com'); 

$allen = new Reader('Mark'); 
$jim = new Reader('Lily'); 
$linda = new Reader('Caitlin'); 

//add reader 
$newspaper->attach($allen); 
$newspaper->attach($jim); 
$newspaper->attach($linda); 

//remove reader 
$newspaper->detach($linda); 

//set break outs 
$newspaper->breakOutNews('PHP Design Patterns'); 

```

在这个脚本中，我们首先用三个读者实例化一个订阅源。我们将它们全部附加，然后分离一个。最后，我们发送一个新的警报，产生以下输出：

![观察者模式（SplObserver/SplSubject）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_001.jpg)

这种设计模式的主要优势在于观察者和主题之间关系的松散耦合性。有更大的模块化，因为主题和观察者可以独立变化。除此之外，我们可以添加任意多的观察者，提供我们想要的任意多的功能。这种可扩展性和定制性通常是这种设计模式应用于应用程序视图上下文的原因，也经常在**模型-视图-控制器**（**MVC**）框架中实现。

使用这种模式的缺点在于当我们需要调试整个过程时会出现问题；流程控制可能会变得困难，因为观察者彼此之间并不知道对方的存在。除此之外，还存在更新开销，当处理特别大的观察者时，可能会使内存管理变得困难。

请记住，这种设计模式仅用于一个程序内部，不适用于进程间通信或消息系统。本书后面，我们将介绍如何使用消息模式来描述消息解析系统的不同部分如何相互连接，当我们想要允许不同进程之间的互通，而不仅仅是一个进程内的不同类时。

# 迭代器

迭代器设计模式是使用迭代器遍历容器的地方。在 PHP 中，如果最终继承了可遍历接口，类就可以使用`foreach`构造进行遍历。不幸的是，这是一个抽象基础接口，你不能单独实现它（除非你是在 PHP 核心中编写）。相反，你必须实现称为`Iterator`或`IteratorAggregate`的接口。通过实现这些接口中的任何一个，你可以使一个类可迭代，并可以使用`foreach`进行遍历。

`Iterator`和`IteratorAggregate`接口非常相似，除了`IteratorAggregate`接口创建一个外部迭代器。`IteratorAggregate`作为一个接口只需要定义一个方法`getIterator`。这个方法必须返回`ArrayIterator`接口的一个实例。

## IteratorAggregate

假设我们想要创建一个实现这个接口的实现，它将遍历各种时间。

首先，让我们从一个`IternatorAggregate`类的基本实现开始，以了解它是如何工作的：

```php
<?php 

class timeIterator implements IteratorAggregate { 

  public function getIterator() 
  { 
    return new ArrayIterator(array( 
      'property1' => 1, 
      'property2' => 2, 
      'property4' => 3 
    )); 
  } 
} 

```

我们可以按照以下方式遍历这个类：

```php
<?php 

$time = new timeIterator; 

foreach($time as $key => $value) { 
  var_dump($key, $value); 
  echo "n"; 
} 

```

这个输出如下：

![IteratorAggregate](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_002.jpg)

我修改了这个脚本，使它接受一个`time`值，并计算两侧的各种值，并使它们可迭代：

```php
<?php 

class timeIterator implements IteratorAggregate 
{ 

  public function __construct(int $time) 
  { 
    $this->weekAgo   = $time - 604800; 
    $this->yesterday = $time - 86400; 
    $this->now       = $time; 
    $this->tomorrow  = $time + 86400; 
    $this->nextWeek  = $time + 604800; 
  } 

  public function getIterator() 
  { 
    return new ArrayIterator($this); 
  } 
} 

$time = new timeIterator(time()); 

foreach ($time as $key => $value) { 
  var_dump($key, $value); 
  echo "n"; 
} 

```

此脚本的输出如下：

![IteratorAggregate](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_003.jpg)

## 迭代器

假设我们想要创建一个实现这个接口的实现，它将遍历各种时间。

## PHP 的许多迭代器

之前，我们已经探讨了**SPL（标准 PHP 库）**中的一些函数，这是一个解决常见问题的接口和类的集合。鉴于这个目标，它们与设计模式有着共同的目标，但它们都以不同的方式解决这些问题。构建这个扩展和在 PHP 7 中编译不需要外部库；事实上，你甚至不能禁用它。

作为这个库的一部分，在 SPL 中有很多迭代器。您可以在文档中找到它们的列表[`php.net/manual/en/spl.iterators.php`](http://php.net/manual/en/spl.iterators.php)。

以下是一些这些迭代器的列表，以便让您了解您可以利用它们的用途：

+   追加迭代器

+   数组迭代器

+   缓存迭代器

+   回调过滤迭代器

+   目录迭代器

+   空迭代器

+   文件系统迭代器

+   过滤迭代器

+   Glob 迭代器

+   无限迭代器

+   迭代器迭代器

+   限制迭代器

+   多重迭代器

+   无需倒带迭代器

+   父迭代器

+   递归数组迭代器

+   递归缓存迭代器

+   递归回调过滤迭代器

+   递归目录迭代器

+   递归过滤迭代器

+   递归迭代器迭代器

+   递归正则表达式迭代器

+   递归树迭代器

+   正则表达式迭代器

# 生成器

PHP 有一个很好的机制来以紧凑的方式创建迭代器。这种类型的迭代器有一些严重的限制；它们只能向前，不能倒带。事实上，即使只是从头开始一个迭代器，你也必须重新构建生成器。本质上，这是一个只能向前的迭代器。

一个使用`yield`关键字而不是`return`关键字的函数。这将像`return`语句一样工作，但不会停止该函数的执行。生成器函数可以`yield`数据，只要你愿意。

当您用值填充一个数组时，这些值必须存储在内存中，这可能导致您超出 PHP 内存限制，或者需要大量的处理时间来生成器。当您将逻辑放在生成器函数中时，这种开销就不存在了。生成器函数可能只产生它需要的结果；不需要先预先填充一个数组。

这是一个简单的生成器，将`var_dump`一个声明字符串，生成器已经启动。该函数将生成前五个平方数，同时输出它们在序列中的位置。然后最后指示生成器已结束：

```php
<?php 
function squaredNumbers() 
{ 
  var_dump("Generator starts."); 
  for ($i = 0; $i < 5; ++$i) { 
    var_dump($i . " in series."); 
    yield pow($i, 2); 
  } 
  var_dump("Generator ends."); 
} 

foreach (squaredNumbers() as $number) { 
  var_dump($number); 
} 

```

这个脚本的第二部分循环运行这个函数，并对每个数字运行一个`var_dump`字符串。这个输出如下：

![生成器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_004.jpg)

让我们稍微修改这个函数。

非常重要的一点是，如果你给变量添加了返回类型，你只能声明`Generator`，`Iterator`或`Traversable`，`integer`的返回类型。

这是代码：

```php
<?php 
function squaredNumbers(int $start, int $end): Generator 
{ 
  for ($i = $start; $i <= $end; ++$i) { 
    yield pow($i, 2); 
  } 
} 

foreach (squaredNumbers(1, 5) as $number) { 
  var_dump($number); 
} 

```

这个结果如下：

![生成器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_005.jpg)

如果我们想要产生一个键和一个值，那么这是相当容易的。

还有一些关于在 PHP 5 中使用生成器的事情要提及：在 PHP 5 中，当您想要同时产生一个变量并将其设置为一个变量时，必须将 yield 语句包装在括号中。这个限制在 PHP 7 中不存在。

这在 PHP 5 和 7 中有效：

```php
**$data = (yield $value);**

```

这只在 PHP 7 中有效：

```php
**$data = yield $value;**

```

假设我们想修改我们的生成器，使其产生一个键值结果。代码如下：

```php
<?php 

function squaredNumbers(int $start, int $end): Generator 
{ 
  for ($i = $start; $i <= $end; ++$i) { 
    yield $i => pow($i, 2); 
  } 
} 

foreach (squaredNumbers(1, 5) as $key => $number) { 
  var_dump([$key, $number]); 
} 

```

当我们测试这个时，我们将`var_dump`一个包含键值存储的二维数组，这个数组包含了生成器在给定迭代中产生的任何值。

这是输出：

![生成器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_006.jpg)

还有一些其他提示，一个没有变量的 yield 语句（就像在下面的命令中所示的那样）将简单地产生`null`：

```php
**yield;**

```

您还可以使用`yield from`，它将产生任何给定生成器的内部值。

假设我们有一个包含两个值的数组：

```php
[1, 2] 

```

当我们使用`yield from`来产生一个包含两个值的数组时，我们得到了数组的内部值。让我演示一下：

```php
<?php 

function innerGenerator() 
{ 
  yield from [1, 2]; 
} 

foreach (innerGenerator() as $number) { 
  var_dump($number); 
} 

```

这将显示以下输出：

![生成器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_007.jpg)

然而，现在让我们修改这个脚本，使其使用`yield`而不是`yield from`：

```php
<?php 

function innerGenerator() 
{ 
  yield [1, 2]; 
} 

foreach (innerGenerator() as $number) { 
  var_dump($number); 
} 

```

现在我们将看到，我们不仅仅得到了数组的内部值，还得到了外部容器：

![生成器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_008.jpg)

# 模板方法设计模式

模板方法设计模式用于创建一组必须执行类似行为的子类。

这种设计模式由模板方法组成，它是一个抽象类。具体的子类可以重写抽象类中的方法。模板方法包含算法的骨架；子类可以使用重写来改变算法的具体行为。

因此，这是一个非常简单的设计模式；它鼓励松散耦合，同时控制子类化的点。因此，它比简单的多态行为更精细。

考虑一个`Pasta`类的抽象：

```php
<?php 

abstract class Pasta 
{ 
  public function __construct(bool $cheese = true) 
  { 
    $this->cheese = $cheese; 
  } 

  public function cook() 
  { 

    var_dump('Cooked pasta.'); 

    $this->boilPasta(); 
    $this->addSauce(); 
    $this->addMeat(); 

    if ($this->cheese) { 
      $this->addCheese(); 
    } 
  } 

  public function boilPasta(): bool 
  { 
    return true; 
  } 

  public abstract function addSauce(): bool; 

  public abstract function addMeat(): bool; 

  public abstract function addCheese(): bool; 

} 

```

这里有一个简单的构造函数，用于确定意大利面是否应该包含奶酪，以及一个运行烹饪算法的`cook`函数。

请注意，添加各种配料的函数被抽象掉了；在子类中，我们使用所需的行为来实现这些方法。

假设我们想做肉丸意大利面。我们可以按照以下方式实现这个抽象类：

```php
<?php 

class MeatballPasta extends Pasta 
{ 

  public function addSauce(): bool 
  { 
    var_dump("Added tomato sauce"); 

    return true; 
  } 

  public function addMeat(): bool 
  { 
    var_dump("Added meatballs."); 

    return true; 

  } 

  public function addCheese(): bool 
  { 
    var_dump("Added cheese."); 

    return true; 
  } 

} 

```

我们可以使用以下脚本在我们的`index.php`文件中对这段代码进行测试：

```php
<?php 

require_once('Pasta.php'); 
require_once('MeatballPasta.php'); 

var_dump("Meatball pasta"); 
$dish = new MeatballPasta(true); 
$dish->cook(); 

```

感谢各种函数中的`var_dump`变量显示各种状态消息，我们可以看到如下输出：

![模板方法设计模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_009.jpg)

现在，假设我们想要制作一个素食食谱。我们可以在不同的上下文中利用相同的抽象。

这一次，在添加肉或奶酪时，这些函数什么也不做；它们可以返回`false`或`null`值：

```php
<?php 

class VeganPasta extends Pasta 
{ 

  public function addSauce(): bool 
  { 
    var_dump("Added tomato sauce"); 

    return true; 
  } 

  public function addMeat(): bool 
  { 
    return false; 
  } 

  public function addCheese(): bool 
  { 
    return false; 
  } 

} 

```

让我们修改我们的`index.php`文件以表示这种行为：

```php
<?php 

require_once('Pasta.php'); 
require_once('MeatballPasta.php'); 

var_dump("Meatball pasta"); 
$dish = new MeatballPasta(true); 
$dish->cook(); 

var_dump(""); 
var_dump("Vegan pasta"); 
require_once('VeganPasta.php'); 

$dish = new VeganPasta(true); 
$dish->cook(); 

```

输出如下：

![模板方法设计模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_010.jpg)

这种设计模式简单易用，但基本上允许您抽象化您的算法设计，并将责任委托给您想要的子类。

# 责任链

假设我们有一组对象，它们一起解决问题。当一个对象无法解决问题时，我们希望对象将任务发送给链中的另一个对象。这就是责任链设计模式的用途。

为了使这个工作起来，我们需要一个处理程序，这将是我们的`Chain`接口。链中的各个对象都将实现这个`Chain`接口。

让我们从一个简单的例子开始；一个助理可以为少于 100 美元购买资产，一个经理可以为少于 500 美元购买东西。

我们的`Purchaser`接口的抽象如下：

```php
<?php 

interface Purchaser 
{ 
  public function setNextPurchaser(Purchaser $nextPurchaser): bool; 

  public function buy($price): bool; 
} 

```

我们的第一个实现是`Associate`类。非常简单，我们实现`setNextPurchaser`函数，以便将`nextPurchaser`类属性设置为链中的下一个对象。

当我们调用`buy`函数时，如果价格在范围内，助理将购买它。如果不是，链中的下一个购买者将购买它：

```php
<?php 

class AssociatePurchaser implements Purchaser 
{ 
  public function setNextPurchaser(Purchaser $nextPurchaser): bool 
  { 
    $this->nextPurchaser = $nextPurchaser; 
    return true; 
  } 

  public function buy($price): bool 
  { 
    if ($price < 100) { 
      var_dump("Associate purchased"); 
      return true; 
    } else { 
      if (isset($this->nextPurchaser)) { 
        reurn $this->nextPurchaser->buy($price); 
      } else { 
        var_dump("Could not buy"); 
        return false; 
      } 
    } 
  } 
} 

```

我们的`Manager`类完全相同；我们只允许经理购买低于 500 美元的资产。实际上，当您应用这种模式时，您不会只是复制一个类，因为您的类会有不同的逻辑；这个例子只是一个非常简单的实现。

以下是代码：

```php
<?php 

class ManagerPurchaser implements Purchaser 
{ 
  public function setNextPurchaser(Purchaser $nextPurchaser): bool 
  { 
    $this->nextPurchaser = $nextPurchaser; 
    return true; 
  } 

  public function buy($price): bool 
  { 
    if ($price < 500) { 
      var_dump("Associate purchased"); 
      return true; 
    } else { 
      if (isset($this->nextPurchaser)) { 
        return $this->nextPurchaser->buy($price); 
      } else { 
        var_dump("Could not buy"); 
        return false; 
      } 
    } 
  } 
} 

```

让我们在我们的`index.php`文件中运行一个来自助理的基本购买。

首先，这是我们放在`index.php`文件中的代码：

```php
<?php 

require_once('Purchaser.php'); 
require_once('AssociatePurchaser.php'); 

$associate = new AssociatePurchaser(); 

$associate->buy(50); 

```

所有这些的输出如下：

![责任链](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_011.jpg)

接下来，让我们测试我们的`Manager`类。我们将在我们的`index.php`文件中修改购买价格，并将我们的`Manager`类添加到链中。

这是我们修改后的`index.php`：

```php
<?php 

require_once('Purchaser.php'); 
require_once('AssociatePurchaser.php'); 
require_once('ManagerPurchaser.php'); 

$associate = new AssociatePurchaser(); 
$manager = new ManagerPurchaser(); 

$associate->setNextPurchaser($manager); 

$associate->buy(400); 

```

这有以下输出：

![责任链](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_012.jpg)

让我们看看如果改变价格会发生什么导致购买失败。

我们在我们的`index.php`文件的最后一行进行更改，使购买价格现在为 600 美元：

```php
<?php 

require_once('Purchaser.php'); 
require_once('AssociatePurchaser.php'); 
require_once('ManagerPurchaser.php'); 

$associate = new AssociatePurchaser(); 
$manager = new ManagerPurchaser(); 

$associate->setNextPurchaser($manager); 

$associate->buy(600); 

```

这有以下输出：

![责任链](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_013.jpg)

现在我们可以扩展这个脚本。让我们添加`DirectorPurchaser`和`BoardPurchaser`，这样我们就可以以更高的成本进行购买。

我们将创建一个`DirectorPurchaser`，他可以在 10,000 美元以下购买。

这个类如下：

```php
<?php 

class DirectorPurchaser implements Purchaser 
{ 
  public function setNextPurchaser(Purchaser $nextPurchaser): bool 
  { 
    $this->nextPurchaser = $nextPurchaser; 
    return true; 
  } 

  public function buy($price): bool 
  { 
    if ($price < 10000) { 
      var_dump("Director purchased"); 
      return true; 
    } else { 
      if (isset($this->nextPurchaser)) { 
        return $this->nextPurchaser->buy($price); 
      } else { 
        var_dump("Could not buy"); 
        return false; 
      } 
    } 
  } 
} 

```

让我们为`BoardPurchaser`类做同样的事情，他可以在 10 万美元以下购买：

```php
<?php 

class BoardPurchaser implements Purchaser 
{ 
  public function setNextPurchaser(Purchaser $nextPurchaser): bool 
  { 
    $this->nextPurchaser = $nextPurchaser; 
    return true; 
  } 

  public function buy($price): bool 
  { 
    if ($price < 100000) { 
      var_dump("Board purchased"); 
      return true; 
    } else { 
      if (isset($this->nextPurchaser)) { 
        return $this->nextPurchaser->buy($price); 
      } else { 
        var_dump("Could not buy"); 
        return false; 
      } 
    } 
  } 
} 

```

现在我们可以更新我们的`index.php`脚本，需要新的类，实例化它们，然后将所有内容绑定在一起。最后，我们将尝试通过调用链中的第一个来运行购买。

以下是脚本：

```php
<?php 

require_once('Purchaser.php'); 
require_once('AssociatePurchaser.php'); 
require_once('ManagerPurchaser.php'); 
require_once('DirectorPurchaser.php'); 
require_once('BoardPurchaser.php'); 

$associate = new AssociatePurchaser(); 
$manager = new ManagerPurchaser(); 
$director = new DirectorPurchaser(); 
$board = new BoardPurchaser(); 

$associate->setNextPurchaser($manager); 
$manager->setNextPurchaser($director); 
$director->setNextPurchaser($board); 

$associate->buy(11000); 

```

以下是此脚本的输出：

![责任链](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_014.jpg)

这使我们能够遍历一系列对象来处理数据。当处理树数据结构（例如，XML 树）时，这是特别有用的。这可以以启动并离开的方式工作，我们可以降低处理遍历链的开销。

此外，链是松散耦合的，数据通过链传递直到被处理。任何对象都可以链接到任何其他对象，任何顺序。

# 策略设计模式

策略设计模式存在是为了允许我们在运行时改变对象的行为。

假设我们有一个类，将一个数字提高到一个幂，但在运行时我们想要改变是否平方或立方一个数字。

让我们首先定义一个接口，一个将数字提高到给定幂的函数：

```php
<?php 

interface Power 
{ 
  public function raise(int $number): int; 
} 

```

我们可以相应地定义`Square`和`Cube`一个给定数字的类，通过实现接口。

这是我们的`Square`类：

```php
<?php 

class Square implements Power 
{ 
  public function raise(int $number): int 
  { 
    return pow($number, 2); 
  } 
} 

```

让我们定义我们的`Cube`类：

```php
<?php 

class Cube implements Power 
{ 
  public function raise(int $number): int 
  { 
    return pow($number, 3); 
  } 
} 

```

我们现在可以构建一个类，它将基本上使用其中一个这些类来处理一个数字。

这是这个类：

```php
<?php 

class RaiseNumber 
{ 
  public function __construct(Power $strategy) 
  { 
    $this->strategy = $strategy; 
  } 

  public function raise(int $number) 
  { 
    return $this->strategy->raise($number); 
  } 
} 

```

现在我们可以使用`index.php`文件来演示整个设置：

```php
<?php 

require_once('Power.php'); 
require_once('Square.php'); 
require_once('Cube.php'); 
require_once('RaiseNumber.php'); 

$processor = new RaiseNumber(new Square()); 

var_dump($processor->raise(5)); 

```

输出如预期，5²是`25`。

以下是输出：

![策略设计模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_015.jpg)

我们可以在我们的`index.php`文件中用`Cube`对象替换`Square`对象：

```php
<?php 

require_once('Power.php'); 
require_once('Square.php'); 
require_once('Cube.php'); 
require_once('RaiseNumber.php'); 

$processor = new RaiseNumber(new Cube()); 

var_dump($processor->raise(5)); 

```

以下是更新脚本的输出：

![策略设计模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_016.jpg)

到目前为止一切顺利；但之所以伟大的原因是我们可以动态添加实际改变类操作的逻辑。

以下是所有这些的一个相当粗糙的演示：

```php
<?php 

require_once('Power.php'); 
require_once('Square.php'); 
require_once('Cube.php'); 
require_once('RaiseNumber.php'); 

if (isset($_GET['n'])) { 
  $number = $_GET['n']; 
} else { 
  $number = 0; 
} 

if ($number < 5) { 
  $power = new Cube(); 
} else { 
  $power = new Square(); 
} 

$processor = new RaiseNumber($power); 

var_dump($processor->raise($number)); 

```

所以为了演示这一点，让我们运行脚本，将*n*`GET`变量设置为`4`，这应该将数字`4`立方，得到一个输出`64`：

![策略设计模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_017.jpg)

现在如果我们通过数字`6`，我们期望脚本将数字`6`平方，得到一个输出`36`：

![策略设计模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_018.jpg)

在这种设计模式中，我们已经做了很多：

+   我们定义了一系列算法，它们都有一个共同的接口

+   这些算法是可以互换的；它们可以在不影响客户端实现的情况下进行交换

+   我们在一个类中封装了每个算法

现在我们可以独立于使用它的客户端来变化算法。

# 规范设计模式

规范设计模式非常强大。在这里，我将尝试对其进行高层概述，但还有很多可以探索；如果您有兴趣了解更多，我强烈推荐*Eric Evans*和*Martin Fowler*的论文*Specifications*。

这种设计模式用于编码关于对象的业务规则。它们告诉我们一个对象是否满足某些业务标准。

我们可以以以下方式使用它们：

+   对于*验证*一个对象，我们可以做出断言

+   从给定集合中获取*选择*的对象

+   为了指定如何通过*按订单制造*来创建对象

在这个例子中，我们将构建规范来查询

让我们看看以下对象：

```php
<?php 

$workers = array(); 

$workers['A'] = new StdClass(); 
$workers['A']->title = "Developer"; 
$workers['A']->department = "Engineering"; 
$workers['A']->salary = 50000; 

$workers['B'] = new StdClass(); 
$workers['B']->title = "Data Analyst"; 
$workers['B']->department = "Engineering"; 
$workers['B']->salary = 30000; 

$workers['C'] = new StdClass(); 
$workers['C']->title = "Personal Assistant"; 
$workers['C']->department = "CEO"; 
$workers['C']->salary = 25000; 

The workers array will look like this if we var_dump it: 
array(3) { 
  ["A"]=> 
  object(stdClass)#1 (3) { 
    ["title"]=> 
    string(9) "Developer" 
    ["department"]=> 
    string(11) "Engineering" 
    ["salary"]=> 
    int(50000) 
  } 
  ["B"]=> 
  object(stdClass)#2 (3) { 
    ["title"]=> 
    string(12) "Data Analyst" 
    ["department"]=> 
    string(11) "Engineering" 
    ["salary"]=> 
    int(30000) 
  } 
  ["C"]=> 
  object(stdClass)#3 (3) { 
    ["title"]=> 
    string(18) "Personal Assistant" 
    ["department"]=> 
    string(3) "CEO" 
    ["salary"]=> 
    int(25000) 
  } 
} 

```

让我们以一个`EmployeeSpecification`接口开始；这是我们所有规范都需要实现的接口。确保用您处理的对象类型（例如，员工，或您从实例化对象的类的名称）替换`StdClass`。

这是代码：

```php
<?php 

interface EmployeeSpecification 
{ 
  public function isSatisfiedBy(StdClass $customer): bool; 
} 

```

现在是时候编写一个名为`EmployeeIsEngineer`的实现了：

```php
<?php 

class EmployeeIsEngineer implements EmployeeSpecification 
{ 
  public function isSatisfiedBy(StdClass $customer): bool 
  { 
    if ($customer->department === "Engineering") { 
      return true; 
    } 

    return false; 
  } 
} 

```

然后，我们可以遍历我们的工作人员，检查哪些符合我们制定的标准：

```php
$isEngineer = new EmployeeIsEngineer(); 

foreach ($workers as $id => $worker) { 
  if ($isEngineer->isSatisfiedBy($worker)) { 
    var_dump($id); 
  } 
} 

```

让我们把这一切放在我们的`index.php`文件中：

```php
<?php 

require_once('EmployeeSpecification.php'); 
require_once('EmployeeIsEngineer.php'); 

$workers = array(); 

$workers['A'] = new StdClass(); 
$workers['A']->title = "Developer"; 
$workers['A']->department = "Engineering"; 
$workers['A']->salary = 50000; 

$workers['B'] = new StdClass(); 
$workers['B']->title = "Data Analyst"; 
$workers['B']->department = "Engineering"; 
$workers['B']->salary = 30000; 

$workers['C'] = new StdClass(); 
$workers['C']->title = "Personal Assistant"; 
$workers['C']->department = "CEO"; 
$workers['C']->salary = 25000; 

$isEngineer = new EmployeeIsEngineer(); 

foreach ($workers as $id => $worker) { 
  if ($isEngineer->isSatisfiedBy($worker)) { 
    var_dump($id); 
  } 
} 

```

这是此脚本的输出：

![规范设计模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_05_019.jpg)

组合规范允许您组合规范。通过使用`AND`、`NOT`、`OR`和`NOR`运算符，您可以将它们的各自功能构建到不同的规范类中。

同样，您也可以使用规范来获取对象。

随着代码的进一步复杂化，这段代码变得更加复杂，但是您理解了要点。事实上，我在本节开头提到的 Eric Evans 和 Martin Fowler 的论文涉及了一些更加复杂的安排。

无论如何，这种设计模式基本上允许我们封装业务逻辑以陈述关于对象的某些事情。这是一种非常强大的设计模式，我强烈鼓励更深入地研究它。

# 定期任务模式

定期任务基本上由三个部分组成：任务本身，通过定义任务运行的时间和允许运行的时间来进行调度的作业，最后是执行此作业的作业注册表。

通常，这些是通过在 Linux 服务器上使用 cron 来实现的。您可以使用以下配置语法向“配置”文件添加一行：

```php
 **# ┌───────────── min (0 - 59)
     # │ ┌────────────── hour (0 - 23)
     # │ │ ┌─────────────── day of month (1 - 31)
     # │ │ │ ┌──────────────── month (1 - 12)
     # │ │ │ │ ┌───────────────── day of week (0 - 6) (0 to 6 are Sunday to
     # │ │ │ │ │                  Saturday, or use names; 7 is also Sunday)
     # │ │ │ │ │
     # │ │ │ │ │
     # * * * * *  command to execute** 

```

通常可以通过在命令行中运行`crontab -e`来编辑`cron`文件。您可以使用此模式安排任何 Linux 命令。以下是一个 cron 作业，将在每天 20:00（晚上 8 点）运行一个 PHP 脚本：

```php
**0 20 * * * /usr/bin/php /opt/test.php**

```

这些实现起来非常简单，但是在创建它们时，以下是一些指导方针可以帮助您：

+   不要将您的 cron 作业暴露给互联网。

+   当运行任务时，任务不应检查是否需要运行的标准。这个测试应该在任务之外。

+   任务应该只执行其预期执行的计划活动，而不执行任何其他目的。

+   谨防我们在第七章中讨论的数据库作为 IPC 模式，重构。

您可以在任务中放入任何您想要的东西（在合理范围内）。您可能会发现异步执行是最佳路线。Icicle 是一个执行异步行为的出色的 PHP 库。您可以在[`icicle.io/`](https://icicle.io/)上找到在线文档。

当我们的任务需要按特定顺序完成几项任务时，您可能会从使用我们在结构设计模式部分讨论的组合设计模式中受益，并调用使用此模式调用其他任务的单个任务。

# 总结

在本章中，我们涵盖了一些识别对象之间常见通信模式的模式。

我们讨论了观察者模式如何用于更新观察者关于给定主题状态的。此外，我们还了解了标准 PHP 库包含的功能可以帮助我们实现这一点。

然后，我们继续讨论了如何在 PHP 中以许多不同的方式实现迭代器，使用 PHP 核心中的各种接口以及利用生成器函数。

我们继续讨论了模板模式如何定义算法骨架，我们可以以比标准多态性更严格的方式动态调整它。我们讨论了责任链模式，它允许我们将对象链接在一起以执行各种功能。策略模式教会了我们如何在运行时改变代码的行为。然后我介绍了规范模式的基础知识以及其中的高级功能。最后，我们复习了定期任务模式以及如何使用 Linux 上的 cron 来实现它。

这些设计模式对开发人员来说是一些最关键的设计模式。对象之间的通信在许多项目中至关重要，而这些模式确实可以帮助我们进行这种通信。

在下一章中，我们将讨论架构模式以及这些模式如何帮助您处理出现的软件架构任务，以及如何帮助您解决可能面临的更广泛的软件工程挑战（尽管它们在技术上可能不被认为是设计模式本身）。


# 第六章：架构模式

架构模式，有时被称为架构风格，为软件架构中的重复问题提供解决方案。

尽管与软件设计模式类似，但其范围更广，涉及软件工程中的各种问题，而不仅仅是软件本身的开发。

在本章中，我们将涵盖以下主题：

+   模型-视图-控制器（MVC）

+   面向服务的架构

+   微服务

+   异步排队

+   消息队列模式

# 模型-视图-控制器（MVC）

MVC 是 PHP 开发人员遇到的最常见类型的架构模式。基本上，MVC 是一种用于实现用户界面的架构模式。

它主要围绕以下方法论展开：

+   **模型**：为应用程序提供数据，无论是来自 MySQL 数据库还是其他任何数据存储。

+   **控制器**：控制器基本上是业务逻辑所在。控制器处理视图提供的任何查询，使用模型来协助其进行此行为。

+   **视图**：提供给最终用户的实际内容。这通常是一个 HTML 模板。

一个交互的业务逻辑并不严格分离于另一个交互。应用程序的不同类之间没有正式的分离。

需要考虑的关键是 MVC 模式主要是一种 UI 模式，因此在整个应用程序中无法很好地扩展。也就是说，UI 的呈现越来越多地通过 JavaScript 应用程序完成，即一个简单消耗 RESTful API 的单页面 JavaScript HTML 应用程序。

如果您使用 JavaScript，可以使用诸如 Backbone.js（模型-视图-控制器）、React.js 或 Angular 等框架与后端 API 进行通信，尽管这当然需要一个启用 JavaScript 的 Web 浏览器，这对我们的一些用户来说可能是理所当然的。

如果您处于无法使用 JavaScript 应用程序且必须提供渲染的 HTML 的环境中，对于您的 MVC 应用程序来说，将其简单地消耗 REST API 通常是一个好主意。REST API 执行所有业务逻辑，但标记的呈现是在 MVC 应用程序中完成的。尽管这增加了复杂性，但它提供了更大的责任分离，因此您不会将 HTML 与核心业务逻辑合并。也就是说，即使在这个 REST API 中，您也需要某种形式的关注点分离，您需要能够将标记的呈现与实际业务逻辑分开。

选择适合应用程序的架构模式的关键因素是复杂性是否适合应用程序的规模。因此，选择 MVC 框架也应基于应用程序本身的复杂性及其后续预期的复杂性。

鉴于基础设施即代码的增长，可以以完全编排的方式部署多个 Web 服务的基础设施。事实上，使用诸如 Docker 之类的容器化技术，可以以很小的开销（无需为每个服务启动新服务器）部署多个架构（例如具有单独 API 服务的 MVC 应用程序）。

在开发出色的架构时，关注点分离是一个重要特征，其中包括将 UI 与业务逻辑分离。

当以 MVC 模式思考时，重要的是要记住以下交互：

+   模型存储数据，根据模型提出的查询检索数据，并由视图显示

+   视图根据模型的更改生成输出

+   控制器发送命令以更新模型的状态；它还可以更新与之关联的视图，以改变给定模型的呈现方式

或者，通常使用以下图表表示：

![模型-视图-控制器（MVC）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_001.jpg)

不要仅仅为了使用而使用 MVC 框架，要理解它们存在的原因以及它们在特定用例中的适用性。记住，当你使用一个功能繁多的框架时，你要负责维护整个框架的运行。

根据需要引入组件（即通过 Composer）是开发具有相当多业务逻辑的软件的更实际的方法。

# 面向服务的架构

面向服务的架构主要由与数据存储库通信的服务中的业务逻辑组成。

这些服务可以以不同的形式衍生出来构建应用程序。这些应用程序以不同的格式采用这些服务来构建各种应用程序。将这些服务视为可以组合在一起以构建特定格式应用程序的乐高积木。

这个描述相当粗糙，让我进一步澄清：

+   服务的边界是明确的（它们可以将不同域上的 Web 服务分开，等等。）

+   服务可以使用共同的通信协议进行相互通信（例如都使用 RESTful API）

+   服务是自治的（它们是解耦的，与其他服务没有任何关联）

+   消息处理机制和架构对每个微服务都是可理解的（因此通常是相同的），但编程环境可以是不同的。

面向服务的架构本质上是分布式的，因此其初始复杂性可能比其他架构更高。

# 微服务

微服务架构可以被认为是面向服务的架构的一个子集。

基本上，微服务通过由小型独立进程组成的复杂应用程序，这些进程通过语言无关的 API 进行相互通信，使每个服务都可以相互访问。微服务可以作为单独的服务进行部署。

在微服务中，业务逻辑被分离成独立的、松耦合的服务。微服务的一个关键原则是每个数据库都应该有自己的数据库，这对确保微服务不会彼此紧密耦合至关重要。

通过减少单个服务的复杂性，我们可以减少该服务可能出现故障的点。理论上，通过使单个服务符合单一职责原则，我们可以更容易地调试和减少整个应用程序中出现故障的机会。

在计算机科学中，CAP 定理规定在给定的分布式计算机系统中不可能同时保证一致性、可用性和分区容错性。

想象一下，有两个分布式数据库都包含用户的电子邮件地址。如果我们想要更新这个电子邮件地址，没有办法可以在两个数据库中同时实时更新电子邮件地址，同时不将两个数据集重新合并。在分布式系统中，我们要么延迟访问数据以验证数据的一致性，要么呈现一个未更新的数据副本。

这使得传统的数据库事务变得困难。因此，在微服务架构中处理数据的最佳方式是使用一种最终一致的、事件驱动的架构。

每个服务在发生变化时都会发布一个事件，其他服务可以订阅此事件。当接收到事件时，数据会相应地更新。因此，应用程序能够在不需要使用分布式事务的情况下在多个服务之间保持数据一致性。

为了了解如何在微服务之间实现进程间通信的架构，请参阅本章节中的*消息队列模式（使用 RabbitMQ 入门）*部分。

在这种情况下，缓解这种限制的一种简单方法是通过使用时间验证系统来验证数据的一致性。因此，我们为一致性和分区容忍性而放弃了可用性。

如果您可以预见在给定的微服务架构中会出现这种问题，通常最好将需要满足 CAP 定理的服务分组到一个单一的服务中。

让我们考虑一个比萨外卖网站应用，它由以下微服务组成：

+   用户

+   优惠

+   食谱

+   购物车

+   计费

+   支付

+   餐厅

+   交付

+   比萨

+   评论

+   前端微服务

在这个例子中，我们可能会有以下用户旅程：

1.  用户通过用户微服务进行身份验证。

1.  用户可以使用优惠微服务选择优惠。

1.  用户使用食谱微服务选择他们想要订购的比萨。

1.  使用购物车微服务将所选的比萨添加到购物车中。

1.  计费凭据通过计费微服务进行优化。

1.  用户使用支付微服务进行支付。

1.  订单通过餐厅微服务发送到餐厅。

1.  当餐厅烹饪食物时，交付微服务会派遣司机去取食物并送达。

1.  一旦交付微服务表明食物已经送达，用户就会被邀请使用评论微服务完成评论（评论微服务通过用户微服务通知用户）。

1.  Web 前端使用前端微服务包装在一起。

前端微服务可以简单地是一个消费其他微服务并将内容呈现给 Web 前端的微服务。这个前端可以通过 REST 与其他微服务通信，可能在浏览器中实现为 JavaScript 客户端，或者仅作为其他微服务 API 的消费者的 PHP 应用。

无论哪种方式，将前端 API 消费者与后端之间放置一个网关通常是一个好主意。这使我们能够在确定与微服务的通信之前放置一些中间件；例如，我们可以使用网关查询用户微服务，以检查用户是否经过授权，然后允许访问购物车微服务。

如果您使用 JavaScript 直接与微服务通信，当您的 Web 前端尝试与不同主机名/端口上的微服务通信时，可能会遇到跨域问题；微服务网关可以通过将网关放置在与 Web 前端本身相同的源上来防止这种情况。

为了方便使用网关，您可能会感受到缺点，因为您将需要担心另一个系统和额外的响应时间（尽管您可以在网关级别添加缓存以改善性能）。

考虑到网关的添加，我们的架构现在可能看起来像这样：

![微服务](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_002.jpg)

在 PHP 中越来越多地出现微框架，比如 Lumen、Silex 和 Slim；这些都是面向 API 的框架，可以轻松构建支持我们应用的微服务。也就是说，您可能更好地采用更轻量级的方法，只需在需要时通过 Composer 引入所需的组件。

记住，添加另一种技术或框架会给整体情况增加额外的复杂性。不仅要考虑实施新解决方案的技术原因，还要考虑这将如何使客户和架构受益。微服务不是增加不必要复杂性的借口：*保持简单，愚蠢*。

# 异步排队

消息队列提供异步通信协议。在异步通信协议中，发送方和接收方不需要同时与消息队列交互。

另一方面，典型的 HTTP 是一种同步通信协议，这意味着客户端在操作完成之前被阻塞。

考虑一下；您给某人打电话，然后等待电话响起，您与之交谈的人立即倾听您要说的话。在通信结束时，您说“再见”，对方也会回答“再见”。这可以被认为是同步的，因为在您收到与您交流的人的响应以结束通信之前，您不会做任何事情。

但是，如果您要发送短信给某人，发送完短信后，您可以随心所欲地进行任何行为；当对方想要与您交流时，您可以收到对您发送的消息的回复。当某人正在起草要发送的回复时，您可以随心所欲地进行任何行为。虽然您不直接与发送方进行通信，但您仍然通过手机保持同步通信，当您收到新消息时通知您（或者每隔几分钟检查手机）；但与对方的通信本身是异步的。双方都不需要了解对方的任何信息，他们只是在寻找自己的短信以便彼此进行通信。

## 消息队列模式（使用 RabbitMQ）

RabbitMQ 是一个消息代理；它接受并转发消息。在这里，让我们配置它，以便我们可以从一个 PHP 脚本发送消息到另一个脚本。

想象一下，我们正在将一个包裹交给快递员，以便他们交给客户；RabbitMQ 就是快递员，而脚本是分别接收和发送包裹的个体。

作为第一步，让我们在 Ubuntu 14.04 系统上安装 RabbitMQ；我将在此演示。

首先，我们需要将 RabbitMQ APT 存储库添加到我们的`/etc/apt/sources.list.d`文件夹中。幸运的是，可以使用以下命令执行此操作：

```php
**echo 'deb http://www.rabbitmq.com/debian/ testing main' | sudo tee /etc/apt/sources.list.d/rabbitmq.list**

```

请注意，存储库可能会发生变化；如果发生变化，您可以在[`www.rabbitmq.com/install-debian.html`](https://www.rabbitmq.com/install-debian.html)找到最新的详细信息。

我们还可以选择将 RabbitMQ 公钥添加到受信任的密钥列表中，以避免在通过`apt`命令安装或升级软件包时出现未签名的警告：

```php
**wget -O- https://www.rabbitmq.com/rabbitmq-release-signing-key.asc | sudo apt-key add -**

```

到目前为止，一切都很好：

![消息队列模式（使用 RabbitMQ 入门）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_003.jpg)

接下来，让我们运行`apt-get update`命令，从我们包含的新存储库中获取软件包。完成后，我们可以使用`apt-get install rabbitmq-server`命令安装我们需要的软件包：

![消息队列模式（使用 RabbitMQ 入门）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_004.jpg)

在被询问时，请务必接受各种提示：

![消息队列模式（使用 RabbitMQ 入门）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_005.jpg)

安装后，您可以运行`rabbitmqctl status`来检查应用程序的状态，以确保它正常运行：

![消息队列模式（使用 RabbitMQ 入门）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_006.jpg)

让我们简化一下生活。我们可以使用 Web GUI 来管理 RabbitMQ；只需运行以下命令：

```php
**rabbitmq-plugins enable rabbitmq_management**

```

![消息队列模式（使用 RabbitMQ 入门）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_007.jpg)

我们现在可以在`<您的服务器 IP 地址>:15672`看到管理界面：

![消息队列模式（使用 RabbitMQ 入门）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_008.jpg)

但在我们登录之前，我们需要创建一些登录凭据。为了做到这一点，我们需要回到命令行。

首先，我们需要设置一个新帐户，用户名为`junade`，密码为`insecurepassword`：

```php
**rabbitmqctl add_user junade insecurepassword**

```

然后我们可以添加一些管理员权限：

```php
**rabbitmqctl set_user_tags junade administrator**
**rabbitmqctl set_permissions -p / junade ".*" ".*" ".*"**

```

返回登录页面后，我们现在可以在输入这些凭据后看到我们很酷的管理界面：

![消息队列模式（使用 RabbitMQ 入门）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_009.jpg)

这是 RabbitMQ 服务的 Web 界面，可通过我们的 Web 浏览器访问

现在我们可以测试我们安装的东西。让我们首先为这个新项目编写一个`composer.json`文件：

```php
{ 
  "require": { 
    "php-amqplib/php-amqplib": "2.5.*" 
  } 
} 

```

RabbitMQ 使用**高级消息队列协议**（**AMQP**），这就是为什么我们正在安装一个 PHP 库，它基本上将帮助我们通过这个协议与它进行通信。

接下来，我们可以编写一些代码来使用我们刚刚安装的 RabbitMQ 消息代理发送消息：

这假设端口是`5672`，安装在`localhost`上，这可能会根据您的情况而改变。

让我们写一个小的 PHP 脚本来利用这个：

```php
<?php 

require_once(__DIR__ . '/vendor/autoload.php'); 
use PhpAmqpLib\Connection\AMQPStreamConnection; 
use PhpAmqpLib\Message\AMQPMessage; 

$connection = new AMQPStreamConnection('localhost', 5672, 'junade', 'insecurepassword'); 
$channel    = $connection->channel(); 

$channel->queue_declare( 
  'sayHello',     // queue name 
  false,          // passive 
  true,           // durable 
  false,          // exclusive 
  false           // autodelete 
); 

$msg = new AMQPMessage("Hello world!"); 

$channel->basic_publish( 
  $msg,           // message 
  '',             // exchange 
  'sayHello'      // routing key 
); 

$channel->close(); 
$connection->close(); 

echo "Sent hello world message." . PHP_EOL; 

```

所以让我们来详细分析一下。在前几行中，我们只是从 Composer 的`autoload`中包含库，并且`state`了我们要使用的命名空间。当我们实例化`AMQPStreamConnection`对象时，我们实际上连接到了消息代理；然后我们可以创建一个新的通道对象，然后用它来声明一个新的队列。我们通过调用`queue_declare`消息来声明一个队列。持久选项允许消息在 RabbitMQ 重新启动时存活。最后，我们只需发送出我们的消息。

现在让我们运行这个脚本：

```php
**php send.php**

```

这个输出看起来像这样：

![消息队列模式（使用 RabbitMQ 入门）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_010.jpg)

如果现在转到 RabbitMQ 的 Web 界面，点击队列选项卡并切换到获取消息对话框；您应该能够拉取我们刚刚发送到代理的消息：

![消息队列模式（使用 RabbitMQ 入门）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_011.jpg)

在界面中使用这个网页，我们可以从队列中提取消息，这样我们就可以查看它们的内容

当然，这只是故事的一半。我们现在需要使用另一个应用程序实际检索这条消息。

让我们写一个`receive.php`脚本：

```php
<?php 

require_once(__DIR__ . '/vendor/autoload.php'); 
use PhpAmqpLib\Connection\AMQPStreamConnection; 
use PhpAmqpLib\Message\AMQPMessage; 

$connection = new AMQPStreamConnection('localhost', 5672, 'junade', 'insecurepassword'); 
$channel    = $connection->channel(); 

$channel->queue_declare( 
  'sayHello',     // queue name 
  false,          // passive 
  false,          // durable 
  false,          // exclusive 
  false           // autodelete 
); 

$callback = function ($msg) { 
  echo "Received: " . $msg->body . PHP_EOL; 
}; 

$channel->basic_consume( 
  'sayHello',                     // queue 
  '',                             // consumer tag 
  false,                          // no local 
  true,                           // no ack 
  false,                          // exclusive 
  false,                          // no wait 
  $callback                       // callback 
); 

while (count($channel->callbacks)) { 
  $channel->wait(); 
} 

```

请注意，前几行与我们的发送脚本是相同的；我们甚至重新声明队列，以防在运行`send.php`脚本之前运行此接收脚本。

让我们运行我们的`receive.php`脚本：

![消息队列模式（使用 RabbitMQ 入门）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_012.jpg)

在另一个 bash 终端中，让我们运行`send.php`脚本几次：

![消息队列模式（使用 RabbitMQ 入门）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_013.jpg)

因此，在`receive.php`终端选项卡中，我们现在可以看到我们已经收到了我们发送的消息：

![消息队列模式（使用 RabbitMQ 入门）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_014.jpg)

RabbitMQ 文档使用以下图表来描述消息的基本接受和转发：

![消息队列模式（使用 RabbitMQ 入门）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_015.jpg)

## 发布-订阅模式

发布-订阅模式（或简称 Pub/Sub）是一种设计模式，其中消息不是直接从发布者发送到订阅者；相反，发布者在没有任何知识的情况下推送消息。

在 RabbitMQ 中，*生产者*从不直接发送任何消息到队列。生产者甚至经常不知道消息是否最终会进入队列。相反，生产者必须将消息发送到*交换机*。它从生产者那里接收消息，然后将它们推送到队列。

*消费者*是将接收消息的应用程序。

必须告诉交换机如何处理给定的消息，以及应该将其附加到哪个队列。这些规则由*交换类型*定义。

RabbitMQ 文档描述了发布-订阅关系（连接发布者、交换机、队列和消费者）如下：

![发布-订阅模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_06_016.jpg)

*直接*交换类型根据路由键传递消息。它可以用于一对一和一对多形式的路由，但最适合一对一的关系。

*扇出*交换类型将消息路由到绑定到它的所有队列，并且路由键完全被忽略。实际上，您无法区分消息将基于路由键分发到哪些工作者。

*主题* 交换类型通过根据消息路由队列和用于将队列绑定到交换的模式来将消息路由到一个或多个队列。当有多个消费者/应用程序想要选择他们想要接收的消息类型时，这种交换有潜力很好地工作，通常是多对多的关系。

*headers* 交换类型通常用于根据消息头中更好地表达的一组属性进行路由。与使用路由键不同，路由的属性基于头属性。

为了测试发布/订阅队列，我们将使用以下脚本。它们与之前的示例类似，只是我修改了它们以便它们使用交换。这是我们的 `send.php` 文件：

```php
<?php 

require_once(__DIR__ . '/vendor/autoload.php'); 
use PhpAmqpLib\Connection\AMQPStreamConnection; 
use PhpAmqpLib\Message\AMQPMessage; 

$connection = new AMQPStreamConnection('localhost', 5672, 'junade', 'insecurepassword'); 
$channel    = $connection->channel(); 

$channel->exchange_declare( 
  'helloHello',   // exchange 
  'fanout',       // exchange type 
  false,          // passive 
  false,          // durable 
  false           // auto-delete 
); 

$msg = new AMQPMessage("Hello world!"); 

$channel->basic_publish( 
  $msg,           // message 
  'helloHello'    // exchange 
); 

$channel->close(); 
$connection->close(); 

echo "Sent hello world message." . PHP_EOL; 

```

这是我们的 `receive.php` 文件。和之前一样，我修改了这个脚本，以便它也使用交换：

```php
<?php 

require_once(__DIR__ . '/vendor/autoload.php'); 
use PhpAmqpLib\Connection\AMQPStreamConnection; 
use PhpAmqpLib\Message\AMQPMessage; 

$connection = new AMQPStreamConnection('localhost', 5672, 'junade', 'insecurepassword'); 
$channel    = $connection->channel(); 

$channel->exchange_declare( 
  'helloHello',   // exchange 
  'fanout',       // exchange type 
  false,          // passive 
  false,          // durable 
  false           // auto-delete 
); 

$callback = function ($msg) { 
  echo "Received: " . $msg->body . PHP_EOL; 
}; 

list($queueName, ,) = $channel->queue_declare("", false, false, true, false); 

$channel->queue_bind($queueName, 'helloHello'); 

$channel->basic_consume($queueName, '', false, true, false, false, $callback); 

while (count($channel->callbacks)) { 
  $channel->wait(); 
} 

$channel->close(); 
$connection->close(); 

```

现在，让我们测试这些脚本。我们首先需要运行我们的 `receive.php` 脚本，然后我们可以使用我们的 `send.php` 脚本发送消息。

首先，让我们触发我们的 `receive.php` 脚本，以便它开始运行：

*发布-订阅模式* 图片

完成后，我们可以通过运行我们的 `send.php` 脚本来发送消息：

*发布-订阅模式* 图片

这将在运行 `receive.php` 的终端中填充以下信息：

*发布-订阅模式* 图片

# 总结

在本章中，我们学习了架构模式。从 MVC 开始，我们学习了使用 UI 框架的好处和挑战，并讨论了如何以更严格的方式将我们的 UI 与业务逻辑解耦。

然后，我们转向了 SOA，并学习了它与微服务的比较，以及在分布式系统提出挑战的情况下，这样的架构在哪些情况下是合理的。

最后，我们深入了解了队列系统，它们适用的情况以及如何在 RabbitMQ 中实现它们。

在接下来的章节中，我们将介绍架构模式的最佳实践使用条件。


# 第七章：重构

在本书中，我主要关注使用设计模式来解决你编写的新代码；这是至关重要的，开发人员在批评他人的代码之前，必须首先改进自己的代码。开发人员必须首先努力理解如何编写代码，然后才能有效地重构代码。

本章将主要基于 Martin Fowler 等人的《重构：改善既有代码的设计》以及 Joshua Kerievsky 的《重构到模式》。如果您对此主题感兴趣，我强烈推荐阅读这些书籍。

# 什么是重构？

重构代码的一个关键主题是解决代码内部结构的问题，同时不改变被重构程序的外部行为。在某些情况下，这可能意味着在先前没有意图或考虑的地方引入内部结构。

重构作为一个过程，在编写代码后改进代码的设计。虽然设计是软件工程过程中的关键阶段，但通常被忽视（尤其是在 PHP 中）；除此之外，长期维护代码结构需要对软件设计的持续理解。如果开发人员在不了解原始设计的情况下接手项目，他们可能会以非常粗糙的方式进行开发。

在极限编程（XP）中，使用了一个被称为“无情重构”的短语，这是不言而喻的。在 XP 中，重构被提议作为保持软件设计尽可能简单并避免不必要复杂性的机制。正如 XP 的规则中所述：“确保一切只表达一次。最终，制作一个精心打理的系统需要更少的时间。”

重构的一个关键原则是将软件设计视为一种要发现而不是事先创建的东西。在开发系统时，我们可以使用开发作为找到良好设计解决方案的机制。通过使用重构，我们能够确保系统在开发过程中保持良好，从而我们能够降低技术债务。

重构并非总是可能的，您可能偶尔会遇到无法更改的“黑盒”系统，甚至可能需要封装系统以进行重写。然而，有许多情况下，我们可以简单地重构代码以改进设计。

# 测试，测试，再测试

没有办法绕过这一点，为了重构代码，您需要一套可靠的测试。重构代码可能会减少引入错误的机会，但改变代码的设计会引入大量引入新错误的机会。

在重构过程中会出现意外的副作用，当类紧密耦合时，您可能会发现对一个函数进行微小更改会导致完全不同类中的负面副作用。

良好的重构效果需要良好的测试。这是无法绕过的。

除此之外，从更政治的角度来看，一些公司遇到了重复糟糕的重构努力所带来的不良影响，可能会不愿意重构代码；确保有良好的测试可以确保重构不会破坏功能。

在本章中，我将展示重构工作，这应该伴随着使用单元测试的测试工作，而在本书的下一章（也是最后一章）中，我将讨论行为测试（用于 BDD）。单元测试是开发人员测试给定代码单元的最佳机制；单元测试补充了代码结构，证明方法是否按照预期工作，并测试代码单元之间的交互；在这个意义上，它们是开发人员在重构工作中最好的测试形式。然而，行为测试是用来测试代码行为的，因此在演示应用程序能够成功完成给定形式的行为方面是有用的。

每个经验丰富的开发人员都会记得痛苦的调试任务；有时候会持续到深夜。让我们想想大多数开发人员日常工作的方式。他们并不总是编写代码，他们的一些时间花在设计代码上，而相当多的时间花在调试他们已经编写的代码上。拥有自我测试的代码可以迅速减轻这种负担。

测试驱动开发围绕着在编写功能之前编写测试的方法论，确实，代码应该与测试相匹配。

在测试类时，确保测试类的`public`接口；确实，PHPUnit 不允许您在普通用法下测试`private`或`protected`方法。

# 代码异味

**代码异味**本质上是一些不良实践，使您的代码变得不必要地难以理解，可以使用本章中介绍的技术来重构不良代码。代码异味通常违反了一些基本的软件设计原则，因此可能会对整体代码的设计质量产生负面影响。

Martin Fowler 通过以下方式定义了代码异味：

> *“代码异味是通常对系统中更深层次问题的表面指示。”*

在本书的开头，我们讨论了*技术债务*这个术语，在这个意义上，代码异味可以作为*技术债务*的一部分。

代码异味可能不一定构成错误，它不会阻止程序的执行，但它可以帮助在以后引入错误的过程中，并使代码重构到适当的设计变得更加困难。

让我们来看看在处理传统 PHP 项目时可能遇到的一些基本代码异味。

我们将讨论一些代码异味以及如何以相当简单的方式解决它们，但现在让我们考虑一些稍微重要的、重复出现的模式，以及如何通过应用设计模式来简化代码的维护。

在这里，我们将具体讨论重构*到*模式，有些情况下，当简化代码设计时，您可能会从模式重构*到*模式。本章的重复主题围绕代码设计如何在代码的开发生命周期中存在，它不仅仅在任意设计阶段之后被丢弃。

模式可以用来传达意图，它们可以作为开发人员之间的语言；这就是为什么了解并继续使用大量模式在软件工程师的职业生涯中至关重要。

在书籍*重构到模式*中还有更多这样的方法，我在这里挑选了对 PHP 开发人员最合适的方法。

## 长方法和重复的代码

重复的代码是非常常见的代码异味。开发人员经常会复制和粘贴代码，而不是使用适当的控制结构来进行应用程序。如果相同的控制结构出现在多个地方，将两个结构合并成一个将使您的代码受益。

如果重复的代码是相同的，你可以使用提取方法。那么什么是提取方法？实质上，**提取方法**只是将长函数中的业务逻辑提取到更小的函数中。

假设有一个`dice`类，一旦掷骰子，它将以罗马数字返回 1 到 6 之间的随机数。

`Legacy`类可以是这样的：

```php
class LegacyDice 
{ 
  public function roll(): string 
  { 
    $rand = rand(1, 6); 

    // Switch statement to convert a number between 1 and 6 to a Roman Numeral. 
    switch ($rand) { 
      case 5: 
        $randString = "V"; 
        break; 
      case 6: 
        $randString = "VI"; 
        break; 
      default: 
        $randString = str_repeat("I", $rand); 
        break; 
    } 

    return $randString; 
  } 
} 

```

让我们提取一个方法，将随机数转换为罗马数字，并将其放入一个单独的函数中：

```php
class Dice 
{ 
  /** 
   * Roll the dice. 
   * @return string 
   */ 
  public function roll(): string 
  { 
    $rand = rand(1, 6); 

    return $this->numberToRomanNumeral($rand); 
  } 

  /** 
   * Convert a number between 1 and 6 to a Roman Numeral. 
   * 
   * @param int $number 
   * 
   * @return string 
   * @throws Exception 
   */ 
  public function numberToRomanNumeral(int $number): string 
  { 
    if (($number < 1) || ($number > 6)) { 
      throw new Exception('Number out of range.'); 
    } 

    switch ($number) { 
      case 5: 
        $randString = "V"; 
        break; 
      case 6: 
        $randString = "VI"; 
        break; 
      default: 
        $randString = str_repeat("I", $number); 
        break; 
    } 

    return $randString; 
  } 
} 

```

我们对原始代码块只进行了两个更改，我们将执行罗马数字转换的函数分离出来，并将其放入一个单独的函数中。我们用函数本身的 DocBlock 替换了内联注释。

如果重复存在于多个地方（且相同），则可以使用此方法进行复制，我们只需调用一个函数，而不是在多个地方重复代码。

如果代码在不相关的类中，看看它在逻辑上适合哪里（在这两个类中的任何一个或一个单独的类中），并将其提取到那里。

在本书的前面，我们已经讨论了保持函数小的必要性。这对于确保您的代码在长期内可读性非常重要。

我经常看到开发人员在函数内部注释代码块；相反，为什么不将这些方法拆分为它们自己的函数？通过 DocBlocks 可以添加可读的文档。因此，我们在这里使用的提取方法可以更简单地使用；拆分长方法。

处理较小的方法时，解决各种业务问题要容易得多。

## 大类

大类经常违反单一职责原则。在特定时间点上，您正在处理的类是否只有一个更改的原因？一个类应该只对功能的一个部分负责，而且该类应该完全封装该责任。

通过提取不严格符合单一职责的方法将类分成多个类，这是一种简单而有效的方法，可以帮助减轻这种代码异味。

## 用多态性或策略模式替换复杂的逻辑语句和 switch 语句

通过使用多态行为，可以大大减少 switch 语句（或者说无休止的大型 if 语句）；我在本书的早期章节中已经描述了多态性，并且它提供了一种比使用 switch 语句更优雅地处理计算问题的方式。

假设您正在根据国家代码进行切换；美国或英国，而不是以这种方式切换，通过使用多态性，您可以运行相同的方法。

在不可能进行多态行为的情况下（例如，没有共同的接口的情况下），在某些情况下，通过用策略替换类型代码甚至可能会受益；实际上，您可以将多个 switch 语句合并为仅将类注入到客户端的构造函数中，该类将处理与各个类的关系。

例如；假设我们有一个 Output 接口，这个接口由包含`load`方法的各种其他类实现。这个`load`方法允许我们注入一个数组，并且我们以所请求的格式获取一些数据。这些类是该行为的极其粗糙的实现：

```php
interface Output 
{ 
  public function load(array $data); 
} 

class Serial implements Output 
{ 
  public function load(array $data) 
  { 
    return serialize($data); 
  } 
} 

class JSON implements Output 
{ 
  public function load(array $data) 
  { 
    return json_encode($data); 
  } 
} 

class XML implements Output 
{ 
  public function load(array $data) 
  { 
    return xmlrpc_encode($data); 
  } 
} 

```

### 注意

在撰写本文时，PHP 仍然认为`xmlrpc_encode`函数是实验性的，因此，我建议不要在生产中使用它。这里纯粹是为了演示目的（为了保持代码简洁）。

一个极其粗糙的实现，带有`switch`语句，可能如下所示：

```php
$client = "JSON"; 

switch ($client) { 
  case "Serial": 
    $client = new Serial(); 
    break; 
  case "JSON": 
    $client = new JSON(); 
    break; 
  case "XML": 
    $client = new XML(); 
    break; 
} 

echo $client->load(array(1, 2)); 

```

但显然，我们可以通过实现一个允许我们将`Output`类注入到`Client`中的客户端来做很多事情，并相应地允许我们接收输出。这样的类可能是这样的：

```php
class OutputClient 
{ 
  private $output; 

  public function __construct(Output $outputType) 
  { 
    $this->output = $outputType; 
  } 

  public function loadOutput(array $data) 
  { 
    return $this->output->load($data); 
  } 
} 

```

现在我们可以非常简单地使用这个客户端：

```php
**$client = new OutputClient(new JSON());
echo $client->loadOutput(array(1, 2));**

```

## 在单一控制结构后复制代码

我不会在这里重申模板设计模式的工作原理，但我想解释的是，它可以用来帮助消除重复的代码。

我在本书中展示的模板设计模式有效地将程序的结构抽象化，然后我们只是填充了特定于实现的方法。这可以帮助我们通过避免一遍又一遍地重复单个控制结构来减少代码重复。

## 长参数列表和原始类型过度使用

原始类型过度使用是指开发人员过度使用原始数据类型而不是使用对象。

PHP 支持八种原始类型；这组可以进一步细分为标量类型、复合类型和特殊类型。

标量类型是保存单个值的数据类型。如果你问自己“这个值可以在一个范围内吗？”你可以识别它们。数字可以在*X*到*Y*的范围内，布尔值可以在 false 到 true 的范围内。以下是一些标量类型的例子：

+   布尔

+   整数

+   浮点数

+   字符串

复合类型由一组标量值组成：

+   数组

+   对象

特殊类型如下：

+   资源（引用外部资源）

+   NULL

假设我们有一个简单的`Salary`计算器类，它接受员工的基本工资、佣金率和养老金率；在发送了这些数据之后，可以使用`calculate`方法输入他们的销售额来计算他们的总工资：

```php
class Salary 
{ 
  private $baseSalary; 
  private $commission = 0; 
  private $pension = 0; 

  public function __construct(float $baseSalary, float $commission, float $pension) 
  { 
    $this->baseSalary = $baseSalary; 
    $this->commission = $commission; 
    $this->pension    = $pension; 
  } 

  public function calculate(float $sales): float 
  { 
    $base       = $this->baseSalary; 
    $commission = $this->commission * $sales; 
    $deducation = $base * $this->pension; 

    return $commission + $base - $deducation; 
  } 
} 

```

注意构造函数有多长。是的，我们可以使用生成器模式来创建一个对象，然后将其注入到构造函数中，但在这种情况下，我们能够特别地将复杂的信息抽象化。在这种情况下，如果我们将员工信息移到一个单独的类中，我们可以确保更好地遵守单一职责原则。

第一步是分离类的职责，以便我们可以分离类的职责：

```php
class Employee 
{ 
  private $name; 
  private $baseSalary; 
  private $commission = 0; 
  private $pension = 0; 

  public function __construct(string $name, float $baseSalary) 
  { 
    $this->name       = $name; 
    $this->baseSalary = $baseSalary; 
  } 

  public function getBaseSalary(): float 
  { 
    return $this->baseSalary; 
  } 

  public function setCommission(float $percentage) 
  { 
    $this->commission = $percentage; 
  } 

  public function getCommission(): float 
  { 
    return $this->commission; 
  } 

  public function setPension(float $rate) 
  { 
    $this->pension = $rate; 
  } 

  public function getPension(): float 
  { 
    return $this->commission; 
  } 
} 

```

从这一点上，我们可以简化`Salary`类的构造函数，以便它只需要输入`Employee`对象，我们就能够使用该类：

```php
class Salary 
{ 
  private $employee; 

  public function __construct(Employee $employee) 
  { 
    $this->employee = $employee; 
  } 

  public function calculate(float $sales): float 
  { 
    $base       = $this->employee->getBaseSalary(); 
    $commission = $this->employee->getCommission() * $sales; 
    $deducation = $base * $this->employee->getPension(); 

    return $commission + $base - $deducation; 
  } 
} 

```

## 不当暴露

假设我们有一个`Human`类如下：

```php
class Human 
{ 
  public $name; 
  public $dateOfBirth; 
  public $height; 
  public $weight; 
} 

```

我们可以随心所欲地设置值，没有验证，也没有统一的获取信息的方式。这有什么问题吗？嗯，在面向对象编程中，封装的原则至关重要；我们隐藏数据。换句话说，我们的数据不应该在没有拥有对象知道的情况下被公开。

相反，我们用`private`数据变量替换所有`public`数据变量。除此之外，我们还添加了适当的方法来获取和设置数据：

```php
class Human 
{ 
  private $name; 
  private $dateOfBirth; 
  private $height; 
  private $weight; 

  public function __construct(string $name, double $dateOfBirth) 
  { 
    $this->name        = $name; 
    $this->dateOfBirth = $dateOfBirth; 
  } 

  public function setWeight(double $weight) 
  { 
    $this->weight = $weight; 
  } 

  public function getWeight(): double 
  { 
    return $this->weight; 
  } 

  public function setHeight(double $height) 
  { 
    $this->height = $height; 
  } 

  public function getHeight(): double 
  { 
    return $this->height; 
  } 
} 

```

确保 setter 和 getter 是合乎逻辑的，不仅仅是因为类属性存在。完成后，您需要检查应用程序，并替换任何对变量的直接访问，以便它们首先通过适当的方法。

然而，这现在暴露了另一个代码异味；特征嫉妒。

## 特征嫉妒

松散地说，**特征嫉妒**是指我们不让一个对象计算自己的属性，而是将其偏移到另一个类。

所以在前面的例子中，我们有我们自己的`Salary`计算器类，如下：

```php
class Salary 
{ 
  private $employee; 

  public function __construct(Employee $employee) 
  { 
    $this->employee = $employee; 
  } 

  public function calculate(float $sales): float 
  { 
    $base       = $this->employee->getBaseSalary(); 
    $commission = $this->employee->getCommission() * $sales; 
    $deducation = $base * $this->employee->getPension(); 

    return $commission + $base - $deducation; 
  } 
} 

```

相反，让我们看看将这个函数实现到`Employee`类本身中，结果我们也可以忽略不必要的 getter 并将属性合理地内部化：

```php
class Employee 
{ 
  private $name; 
  private $baseSalary; 
  private $commission = 0; 
  private $pension = 0; 

  public function __construct(string $name, float $baseSalary) 
  { 
    $this->name       = $name; 
    $this->baseSalary = $baseSalary; 
  } 

  public function setCommission(float $percentage) 
  { 
    $this->commission = $percentage; 
  } 

  public function setPension(float $rate) 
  { 
    $this->pension = $rate; 
  } 

  public function calculate(float $sales): float 
  { 
    $base       = $this->baseSalary; 
    $commission = $this->commission * $sales; 
    $deducation = $base * $this->pension; 

    return $commission + $base - $deducation; 
  } 
} 

```

## 不当亲密关系

这在继承中经常发生；Martin Fowler 优雅地表达如下：

> “子类总是会比父类更了解他们的父类。”

更一般地说；当一个字段在另一个类中的使用比在类本身中更多时，我们可以使用移动字段方法在新类中创建一个字段，然后将该字段的用户重定向到新类。

我们可以将这与移动方法结合起来，将一个函数放在最常使用它的类中，并从原始类中删除它，如果这不可能，我们可以简单地在新类中引用该函数。

## 深度嵌套的语句

嵌套的 if 语句很混乱且丑陋。这会导致难以理解的意大利面逻辑；而是使用内联函数调用。

从最内部的代码块开始，试图将该代码提取到自己的函数中，让它可以幸福地存在。在第一章中，我们讨论了如何通过示例实现这一点，但如果您经常进行重构，您可能希望考虑投资一种可以帮助您的工具。

这里有一个提示，对于我们中的 PHPStorm 用户：在重构菜单中有一个很好的小选项，可以自动为您执行此操作。只需高亮显示您希望提取的代码块，转到菜单栏中的重构，然后单击提取>方法。然后会弹出一个对话框，允许您配置如何进行重构：

![深度嵌套语句](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_07_001.jpg)

## 删除对参数的赋值

尽量避免在函数体内设置参数：

```php
class Before 
{ 
  function deductTax(float $salary, float $rate): float 
  { 
    $salary = $salary * $rate; 

    return $salary; 
  } 
} 

```

这可以通过正确设置内部参数来实现：

```php
class After 
{ 
  function deductTax(float $salary, float $rate): float 
  { 
    $netSalary = $salary * $rate; 

    return $netSalary; 
  } 
} 

```

通过这样的行为，我们能够在前进时轻松识别和提取重复的代码，此外，它还可以在以后维护这段代码时更容易地替换代码。

这是一个简单的调整，允许我们识别代码中特定的参数在做什么。

## 注释

注释并不是一种代码气味，很多情况下，注释是非常有益的。正如 Martin Fowler 所说：

> “在我们的嗅觉类比中，注释不是一种难闻的气味；事实上，它们是一种甜美的气味。”

然而，Fowler 继续演示了注释如何被用作遮盖代码气味的除臭剂。当你发现自己在函数内部注释代码块时，你可以找到一个很好的机会使用提取方法。

如果注释隐藏了一种难闻的气味，重构掉这种气味，很快你就会发现原始注释变得多余了。这并不是不需要对函数进行 DocBlock 或不必要地寻找代码注释的借口，但重要的是要记住，当您重构设计变得更简单时，特定的注释可能变得无用。

## 用构建器封装组合

正如本书前面讨论的那样，构建器设计模式可以通过我们将一长串参数转换为一个单一对象来工作，然后我们可以将其抛入另一个类的构造函数中。

例如，我们有一个名为`APIBuilder`的类，这个构建器类可以用 API 的密钥和密钥本身来实例化，但一旦它被实例化为一个对象，我们就可以简单地将整个对象传递给另一个类的构造函数。

到目前为止，一切顺利；但我们可以使用这个构建器模式来封装组合模式。我们实际上只需创建一个构建器来创建我们的项目。通过这样做，我们可以更好地控制一个类，为我们提供了一个机会来导航和修改组合家族的整个树结构。

## 用观察者替换硬编码的通知

硬编码的通知通常是两个类紧密耦合在一起，以便一个能够通知另一个。相反，通过使用`SplObserver`和`SplSubject`接口，观察者可以使用更加可插拔的方式更新主题。在观察者中实现`update`方法后，主题只需要实现`Subject`接口：

```php
SplSubject { 
   /* Methods */ 
   abstract public void attach ( SplObserver $observer ) 
   abstract public void detach ( SplObserver $observer ) 
   abstract public void notify ( void ) 
} 

```

结果的架构是一个更加可插拔的通知系统，不再紧密耦合。

## 用组合替换一个/多个区别

当我们有单独的逻辑来处理个体到组的情况时，我们可以使用组合模式来 consolide 这些情况。这是本书早些时候介绍过的一种模式；为了将其合并到这种模式中，开发人员只需要修改他们的代码，使一个类可以处理两种形式的数据。

为了实现这一点，我们必须首先确保这两个区别实现了相同的接口。

当我最初演示这个模式时，我写了关于如何使用这个模式来处理将单个歌曲和播放列表视为一个的情况。假设我们的`Music`接口纯粹是以下内容：

```php
interface Music 
{ 
  public function play(); 
} 

```

关键任务就是确保这个接口对于单个和多个区分都得到遵守。你的`Song`类和`Playlist`类都必须实现`Music`接口。这基本上是让我们能够对待它们的行为。

## 使用适配器分离版本

我不会在这本书中长篇大论地讨论适配器，因为我之前已经非常详细地介绍过它们，但我只是想让你考虑一下，它们可以用来支持不同版本的 API。

确保不要将多个 API 版本的代码放在同一个类中，而是可以将这些版本之间的差异抽象到一个适配器中。在使用这种方法时，我建议你最初尝试使用封装方法，而不是基于继承的方法，因为这样可以为未来提供更大的自由度。

# 我应该告诉我的经理什么？

重构然后添加功能往往比仅仅添加功能更快，同时也为现有代码库增加了价值。许多了解软件及其开发方式的优秀经理都会理解这一点。

当然，有些经理对软件的实际情况一无所知，他们往往只受到最后期限的驱使，可能不愿意更多地了解自己的专业领域。我在本书中之前提到过的那些可怕的开发人员就是这样。有时，*Scrum Master*也会有这种情况，因为他们可能无法理解整个软件开发生命周期。

正如 Martin Fowler 所说：

> “当然，很多人说他们追求质量，但更多的是追求进度。在这些情况下，我给出了更具争议性的建议：不要说！”

不了解技术流程的经理可能会急于基于软件能够快速生产的基础上交付；重构可能是帮助生产软件最快速的方式。它提供了一种高效而彻底的方式来快速了解项目，并允许我们平稳地注入新功能的过程。

我们将在本书的下一章讨论管理以及项目如何有效地进行管理。

# 总结

在本章中，我们讨论了一些重构代码的方法，以确保设计始终保持良好的质量。通过重构代码，我们可以更好地理解我们的代码库，并为我们添加到软件中的额外功能未来做好准备。

简化和分解你面临的问题是重构代码时可以使用的两个最基本的工具。

如果你正在使用 CI 环境，让 PHP Mess Detector（PHPMD）在该环境中运行也可以帮助你编写更好的代码。

在下一章中，我将讨论如何适当地使用设计模式，首先快速介绍在网络环境中开发 API 的方法。
