# 精通 PHP 设计模式（二）

> 原文：[`zh.annas-archive.org/md5/40e204436ec0fe9f5a036c3d1b49caeb`](https://zh.annas-archive.org/md5/40e204436ec0fe9f5a036c3d1b49caeb)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：创建性设计模式

创建性设计模式是与四人帮经常相关的三种设计模式之一；它们是涉及对象创建机制的设计模式。

在没有控制这个过程的情况下实例化对象或基本类的创建，可能会导致设计问题，或者只是给过程增加额外的复杂性。

在这一章中，我们将涵盖以下主题：

+   软件设计过程

+   简单工厂

+   工厂方法

+   抽象工厂模式

+   延迟初始化

+   建造者模式

+   原型模式

在我们学习创建性设计模式之前，让我们稍微谈谈架构过程。

# 软件设计过程

*软件工程知识体系*是由*IEEE*出版的一本书，通常被称为**SWEBoK**，它总结了整个软件工程领域的通常被接受的知识体系。

在这本书中，软件设计的定义如下：

> “定义系统或组件的架构、组件、接口和其他特征的过程”和“[该]过程的结果”。

具体来说，软件设计可以分为两个层次的层次结构：

+   架构设计，描述软件如何分割成其组成部分

+   详细设计，描述每个组件的具体细节，以描述其组件。

组件是软件解决方案的一部分，具有接口，这些接口作为*所需接口*（软件需要的功能）和*提供的接口*（软件提供给其他组件的功能）。

这两个设计过程（架构设计和详细设计）应该产生一组记录主要决策的模型和工件，并解释为什么做出了非平凡决策。将来，开发人员可以很容易地参考这些文档，以了解架构决策背后的原理，通过确保决策经过深思熟虑，并将思考过程传递下去，使代码更易于维护。

这两个过程中的第一个，架构设计，可以对整个团队来说是相当有创意和吸引力的。这个过程的结果，无论你选择如何做，都应该是一个通过接口相互连接组件的组件图。

这个过程通常可以更倾向于一般开发人员的团队，而不是虎队。 *虎队*通常是在特定产品知识领域的专家小组，他们在一个时间限定的环境中聚集在一起，以解决特定问题，由架构师主持。通常，特别是涉及到遗留系统时，这样的设计工作可能需要广泛的知识来提取必要的架构约束。

有了这个说法，为了防止过程变成委员会设计或群体规则，你可能想要遵循一些基本规则：让架构师主持会议，并从组件级别图开始工作，不要深入到更深层次。在会议之前制作一个组件图通常会有所帮助，并在会议中根据需要进行编辑，这有助于确保团队保持在纠正图表的轨道上，而不深入到具体的操作。

在我曾经参与的一个环境中，有一个非常详细的工程师担任工程团队的负责人；他坚持立即深入组件的细节进行架构，这会迅速使流程瓦解和无组织；他会即兴开始*会议中的会议*。在这些架构会议上构建组件图在保持会议秩序和确保操作事项和详细设计事项都不会过早涉及方面起到了至关重要的作用。如何和在哪里托管某些东西的操作事项通常不在软件工程的权限范围内，除非它直接影响软件的创建方式。

下一步是详细设计；这解释了组件如何构建。在这一点上可以决定使用的构造中的设计模式、类图和必要的外部资源。无论设计有多好，都将在构建级别进行一些详细设计工作，软件开发人员将需要对设计进行微小的更改，以添加更多细节或弥补架构过程中的一些疏忽。在此设计之前的过程必须简单地指定组件的足够细节，以便促进其构建，并允许开发人员不必过多考虑架构细节。开发人员应该从与代码密切相关的构件（例如详细设计）中开发代码，而不是从高级需求、设计或计划中编写代码。

顺便说一句，让我们记住，单元测试可以成为设计的一部分（例如，在使用测试驱动开发时），每个单元测试都指定一个设计元素（类、方法和特定行为）。虽然将代码逆向工程到设计构件中并不现实（尽管有人会声称是），但可以将*架构表示为代码*；单元测试就是实现这一目标的一种方式。

正如本书前面提到的，设计模式在软件设计中起着至关重要的作用；它们允许设计更复杂的软件部分，而无需重新发明轮子。

好了，现在是创建型设计模式。

# 简单工厂

什么是工厂？让我们想象一下，您订购了一辆新车；经销商将您的订单发送到工厂，工厂建造您的汽车。您的汽车以组装好的形式发送给您，您不需要关心它是如何制造的。

同样，软件工厂为您生产对象。工厂接受您的请求，使用构造函数组装对象并将它们交还给您使用。其中一种工厂模式称为**简单工厂**。让我向您展示它是如何工作的。

首先，我们定义一个抽象类，我们希望用其他类扩展：

```php
<?php 

abstract class Notifier 
{ 
  protected $to; 

  public function __construct(string $to) 
  { 
    $this->to = $to; 
  } 

  abstract public function validateTo(): bool; 

  abstract public function sendNotification(): string; 

} 

```

这个类用于允许我们拥有共同的方法，并定义我们希望在工厂中构建的所有类中具有的任何共同功能。我们还可以使用接口而不是抽象类来实现，而不定义任何功能。

使用这个接口，我们可以构建两个通知器，`SMS`和`Email`。

`SMS`通知器在`SMS.php`文件中如下：

```php
<?php 

class SMS extends Notifier 
{ 
  public function validateTo(): bool 
  { 
    $pattern = '/^(\+44\s?7\d{3}|\(?07\d{3}\)?)\s?\d{3}\s?\d{3}$/'; 
    $isPhone = preg_match($pattern, $this->to); 

    return $isPhone ? true : false; 

  } 

  public function sendNotification(): string 
  { 

    if ($this->validateTo() === false) { 
      throw new Exception("Invalid phone number."); 
    } 

    $notificationType = get_class($this); 
    return "This is a " . $notificationType . " to " . $this->to . "."; 
  } 
} 

```

同样，让我们在`Email.php`文件中放出`Email`通知器：

```php
<?php 

class Email extends Notifier 
{ 

  private $from; 

  public function __construct($to, $from) 
  { 
    parent::__construct($to); 

    if (isset($from)) { 
      $this->from = $from; 
    } else { 
      $this->from = "Anonymous"; 
    } 
  } 

  public function validateTo(): bool 
  { 
    $isEmail = filter_var($this->to, FILTER_VALIDATE_EMAIL); 

    return $isEmail ? true : false; 

  } 

  public function sendNotification(): string 
  { 
    if ($this->validateTo() === false) { 
      throw new Exception("Invalid email address."); 
    } 

    $notificationType = get_class($this); 
    return "This is a " . $notificationType . " to " . $this->to . " from " . $this->from . "."; 
  } 
} 

```

我们可以按以下方式构建我们的工厂：

```php
<?php 

class NotifierFactory 
{ 
  public static function getNotifier($notifier, $to) 
  { 

    if (empty($notifier)) { 
      throw new Exception("No notifier passed."); 
    } 

    switch ($notifier) { 
      case 'SMS': 
        return new SMS($to); 
        break; 
      case 'Email': 
        return new Email($to, 'Junade'); 
        break; 
      default: 
        throw new Exception("Notifier invalid."); 
        break; 
    } 
  } 
} 

```

虽然我们通常会使用 Composer 进行自动加载，但为了演示这种方法有多简单，我将手动包含依赖项；因此，不多说了，这是我们的演示：

```php
<?php 

require_once('Notifier.php'); 
require_once('NotifierFactory.php'); 

require_once('SMS.php'); 
$mobile = NotifierFactory::getNotifier("SMS", "07111111111"); 
echo $mobile->sendNotification(); 

require_once('Email.php'); 
$email = NotifierFactory::getNotifier("Email", "test@example.com"); 
echo $email->sendNotification(); 

```

我们应该得到这样的输出：

![简单工厂](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_03_001.jpg)

# 工厂方法

工厂方法与普通简单工厂的不同之处在于，我们可以拥有多个工厂。

那么为什么要这样做呢？嗯，为了理解这一点，我们必须看看开闭原则（OCP）。Bertrand Meyer 通常被认为是在他的书《面向对象的软件构造》中首次提出了“开闭原则”这个术语。Meyer 说过以下话：

> “软件实体（类、模块、函数等）应该对扩展开放，但对修改关闭”

软件实体需要扩展时，应该可以在不修改其源代码的情况下进行。那些熟悉面向对象软件的**SOLID**（单一职责、开闭原则、里氏替换、接口隔离和依赖倒置）原则的人可能已经听说过这个原则。

工厂方法允许您将某些类组合在一起，并通过一个单独的工厂来处理它们。如果要添加另一组，只需添加另一个工厂即可。

那么，现在我们该怎么做呢？嗯，基本上我们要为每个工厂创建一个接口（或者抽象方法）；然后我们将该接口实现到我们想要构建的任何其他工厂中。

让我们克隆我们的简单工厂演示；我们要做的是让我们的`NotifierFactory`成为一个接口。然后我们可以重建工厂，为电子通知（电子邮件或短信）建立一个工厂，然后我们可以实现我们的接口来创建，比如说，一个邮政快递通知器工厂。

让我们从在`NotifierFactory.php`文件中创建接口开始：

```php
<?php 

interface NotifierFactory 
{ 
  public static function getNotifier($notifier, $to); 
} 

```

现在让我们构建我们的`ElectronicNotifierFactory`，它实现了我们的`NotifierFactory`接口：

```php
<?php 

class ElectronicNotifierFactory implements NotifierFactory 
{ 
  public static function getNotifier($notifier, $to) 
  { 

    if (empty($notifier)) { 
      throw new Exception("No notifier passed."); 
    } 

    switch ($notifier) { 
      case 'SMS': 
        return new SMS($to); 
        break; 
      case 'Email': 
        return new Email($to, 'Junade'); 
        break; 
      default: 
        throw new Exception("Notifier invalid."); 
        break; 
    } 
  } 
} 

```

我们现在可以重构我们的`index.php`来使用我们制作的新工厂：

```php
<?php 

require_once('Notifier.php'); 
require_once('NotifierFactory.php'); 
require_once('ElectronicNotifierFactory.php'); 

require_once('SMS.php'); 
$mobile = ElectronicNotifierFactory::getNotifier("SMS", "07111111111"); 
echo $mobile->sendNotification(); 

echo "\n"; 

require_once('Email.php'); 
$email = ElectronicNotifierFactory::getNotifier("Email", "test@example.com"); 
echo $email->sendNotification(); 

```

现在这与以前的输出相同：

```php
This is a SMS to 07111111111\. 
This is a Email to test@example.com from Junade. 

```

然而，现在的好处是，我们现在可以添加新类型的通知器，而无需打开工厂，所以让我们为邮政通信添加一个新的通知器：

```php
<?php 

class Post extends Notifier 
{ 
  public function validateTo(): bool 
  { 
    $address = explode(',', $this->to); 
    if (count($address) !== 2) { 
      return false; 
    } 

    return true; 
  } 

  public function sendNotification(): string 
  { 

    if ($this->validateTo() === false) { 
      throw new Exception("Invalid address."); 
    } 

    $notificationType = get_class($this); 
    return "This is a " . $notificationType . " to " . $this->to . "."; 
  } 
} 

```

然后我们可以引入`CourierNotifierFactory`：

```php
<?php 

class CourierNotifierFactory implements NotifierFactory 
{ 
  public static function getNotifier($notifier, $to) 
  { 

    if (empty($notifier)) { 
      throw new Exception("No notifier passed."); 
    } 

    switch ($notifier) { 
      case 'Post': 
        return new Post($to); 
        break; 
      default: 
        throw new Exception("Notifier invalid."); 
        break; 
    } 
  } 
} 

```

最后，我们现在可以修改我们的`index.php`文件以包含这种新格式：

```php
<?php 

require_once('Notifier.php'); 
require_once('NotifierFactory.php'); 
require_once('ElectronicNotifierFactory.php'); 

require_once('SMS.php'); 
$mobile = ElectronicNotifierFactory::getNotifier("SMS", "07111111111"); 
echo $mobile->sendNotification(); 

echo "\n"; 

require_once('Email.php'); 
$email = ElectronicNotifierFactory::getNotifier("Email", "test@example.com"); 
echo $email->sendNotification(); 

echo "\n"; 

require_once('CourierNotifierFactory.php'); 

require_once('Post.php'); 
$post = CourierNotifierFactory::getNotifier("Post", "10 Downing Street, SW1A 2AA"); 
echo $post->sendNotification(); 

```

`index.php`文件现在产生了这个结果：

![工厂方法](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_03_002.jpg)

在生产中，通常会将通知器放在不同的命名空间中，并将工厂放在不同的命名空间中。

# 抽象工厂模式

首先，如果你在阅读本书之前做了一些背景阅读，你可能已经听说过“具体类”这个词。这是什么意思？简单来说，它是抽象类的相反；它是一个可以实例化为对象的类。

抽象工厂由以下类组成：抽象工厂、具体工厂、抽象产品、具体产品和我们的客户端。

在工厂模式中，我们生成了特定接口的实现（例如，`notifier`是我们的接口，电子邮件、短信和邮件是我们的实现）。使用抽象工厂模式，我们将创建工厂接口的实现，每个工厂都知道如何创建它们的产品。

假设我们有两个玩具工厂，一个在旧金山，一个在伦敦。它们都知道如何为两个地点创建两家公司的产品。

考虑到这一点，我们的`ToyFactory`接口看起来是这样的：

```php
<?php 

interface ToyFactory { 
  function makeMaze(); 
  function makePuzzle(); 
} 

```

现在这样做了，我们可以建立我们的旧金山玩具工厂（`SFToyFactory`）作为我们的具体工厂：

```php
<?php 

class SFToyFactory implements ToyFactory 
{ 
  private $location = "San Francisco"; 

  public function makeMaze() 
  { 
    return new Toys\SFMazeToy(); 
  } 

  public function makePuzzle() 
  { 
    return new Toys\SFPuzzleToy; 
  } 
} 

```

现在我们可以添加我们的英国玩具工厂（`UKToyFactory`）：

```php
<?php 

class UKToyFactory implements ToyFactory 
{ 
  private $location = "United Kingdom"; 

  public function makeMaze() 
  { 
    return new Toys\UKMazeToy; 
  } 

  public function makePuzzle() 
  { 
    return new Toys\UKPuzzleToy; 
  } 
} 

```

正如你注意到的，我们正在在 Toys 命名空间中创建各种玩具，所以现在我们可以为我们的玩具组合起来的抽象方法。让我们从我们的`Toy`类开始。每个玩具最终都会扩展这个类：

```php
<?php 

namespace Toys; 

abstract class Toy 
{ 
  abstract public function getSize(): int; 
  abstract public function getPictureName(): string; 
} 

```

现在，对于我们在开始时在`ToyFactory`接口中声明的两种类型的玩具（迷宫和拼图），我们可以声明它们的抽象方法，从我们的`Maze`类开始：

```php
<?php 

namespace Toys; 

abstract class MazeToy extends Toy 
{ 
  private $type = "Maze"; 
} 

```

现在让我们来做我们的`Puzzle`类：

```php
<?php 

namespace Toys; 

abstract class PuzzleToy extends Toy 
{ 
  private $type = "Puzzle"; 
} 

```

现在是时候为我们的具体类做准备了，让我们从我们的旧金山实现开始。

`SFMazeToy`的代码如下：

```php
<?php 

namespace Toys; 

class SFMazeToy extends MazeToy 
{ 
  private $size; 
  private $pictureName; 

  public function __construct() 
  { 
    $this->size = 9; 
    $this->pictureName = "San Francisco Maze"; 
  } 

  public function getSize(): int 
  { 
    return $this->size; 
  } 

  public function getPictureName(): string 
  { 
    return $this->pictureName; 
  } 
} 

```

这是`SFPuzzleToy`类的代码，这是对`Maze`玩具类的不同实现：

```php
<?php 

namespace Toys; 

class SFPuzzleToy extends PuzzleToy 
{ 
  private $size; 
  private $pictureName; 

  public function __construct() 
  { 
    $rand = rand(1, 3); 

    switch ($rand) { 
      case 1: 
        $this->size = 3; 
        break; 
      case 2: 
        $this->size = 6; 
        break; 
      case 3: 
        $this->size = 9; 
        break; 
    } 

    $this->pictureName = "San Francisco Puzzle"; 
  } 

  public 
  function getSize(): int 
  { 
    return $this->size; 
  } 

  public function getPictureName(): string 
  { 
    return $this->pictureName; 
  } 
} 

```

现在，我们可以用我们的英国工厂实现来完成这一切。

让我们先为迷宫玩具制作一个，`UKMazeToy.php`：

```php
<?php 

namespace Toys; 

class UKMazeToy extends Toy 
{ 
  private $size; 
  private $pictureName; 

  public function __construct() 
  { 
    $this->size = 9; 
    $this->pictureName = "London Maze"; 
  } 

  public function getSize(): int 
  { 
    return $this->size; 
  } 

  public function getPictureName(): string 
  { 
    return $this->pictureName; 
  } 
} 

```

让我们也为拼图玩具制作一个类，`UKPuzzleToy.php`：

```php
<?php 

namespace Toys; 

class UKPuzzleToy extends PuzzleToy 
{ 
  private $size; 
  private $pictureName; 

  public function __construct() 
  { 
    $rand = rand(1, 2); 

    switch ($rand) { 
      case 1: 
        $this->size = 3; 
        break; 
      case 2: 
        $this->size = 9; 
        break; 
    } 

    $this->pictureName = "London Puzzle"; 
  } 

  public 
  function getSize(): int 
  { 
    return $this->size; 
  } 

  public 
  function getPictureName(): string 
  { 
    return $this->pictureName; 
  } 
} 

```

现在，让我们把所有这些放在我们的`index.php`文件中：

```php
<?php 

require_once('ToyFactory.php'); 
require_once('Toys/Toy.php'); 
require_once('Toys/MazeToy.php'); 
require_once('Toys/PuzzleToy.php'); 

require_once('SFToyFactory.php'); 
require_once('Toys/SFMazeToy.php'); 
require_once('Toys/SFPuzzleToy.php'); 

$sanFraciscoFactory = new SFToyFactory(); 
var_dump($sanFraciscoFactory->makeMaze()); 
echo "\n"; 
var_dump($sanFraciscoFactory->makePuzzle()); 
echo "\n"; 

require_once('UKToyFactory.php'); 
require_once('Toys/UKMazeToy.php'); 
require_once('Toys/UKPuzzleToy.php'); 

$britishToyFactory = new UKToyFactory(); 
var_dump($britishToyFactory->makeMaze()); 
echo "\n"; 
var_dump($britishToyFactory->makePuzzle()); 
echo "\n"; 

```

如果您运行给定的代码，输出应该看起来像以下截图中显示的输出：

![抽象工厂模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_03_003.jpg)

现在，假设我们想要添加一个新的工厂，带有一组新的产品（比如纽约），我们只需添加玩具`NYMazeToy`和`NYPuzzleToy`，然后我们可以创建一个名为`NYToyFactory`的新工厂（实现`ToyFactory`接口），然后就完成了。

现在，当您需要添加新的产品类时，这个类的缺点就会显现出来；抽象工厂需要更新，这违反了接口隔离原则。因此，如果您需要添加新的产品类，它就不严格符合 SOLID 原则。

这种设计模式可能需要一些时间才能完全理解，所以一定要尝试一下源代码，看看你能做些什么。

# 延迟初始化

Slappy Joe's 汉堡是一家高品质的餐厅，汉堡的价格是在制作后使用的肉的准确重量来计算的。不幸的是，由于制作时间的长短，让他们在订单之前制作每一种汉堡将会对资源造成巨大的消耗。

与其为每种类型的汉堡准备好让别人点餐，当有人点餐时，汉堡会被制作（如果还没有），然后他们会被收取相应的价格。

`Burger.php`类的结构如下：

```php
<?php 
class Burger 
{ 
  private $cheese; 
  private $chips; 
  private $price; 

  public function __construct(bool $cheese, bool $chips) 
  { 
    $this->cheese = $cheese; 
    $this->chips = $chips; 

    $this->price = rand(1, 2.50) + ($cheese ? 0.5 : 0) + ($chips ? 1 : 0); 
  } 

  public function getPrice(): int 
  { 
    return $this->price; 
  } 
} 

```

请注意，汉堡的价格只有在实例化后才计算，这意味着顾客在制作之前无法收费。类中的另一个函数只是返回汉堡的价格。

与直接从`Burger`类实例化不同，创建了一个懒初始化类`BurgerLazyLoader.php`，这个类存储了每个已制作的汉堡的实例列表；如果请求了一个尚未制作的汉堡，它将制作它。或者，如果已经存在特定配置的汉堡，那么返回该汉堡。

这是`LazyLoader`类，它根据需要实例化`Burger`对象：

```php
<?php 
class BurgerLazyLoader 
{ 
  private static $instances = array(); 

  public static function getBurger(bool $cheese, bool $chips): Burger 
  { 
    if (!isset(self::$instances[$cheese . $chips])) { 
      self::$instances[$cheese . $chips] = new Burger($cheese, $chips); 
    } 

    return self::$instances[$cheese . $chips]; 
  } 

  public static function getBurgerCount(): int 
  { 
    return count(self::$instances); 
  } 
} 

```

唯一添加的其他函数是`getBurgerCount`函数，它返回`LazyLoader`中所有实例的计数。

所以让我们把所有这些放在我们的`index.php`文件中：

```php
<?php 

require_once('Burger.php'); 
require_once('BurgerLazyLoader.php'); 

$burger = BurgerLazyLoader::getBurger(true, true); 
echo "Burger with cheese and fries costs: £".$burger->getPrice(); 

echo "\n"; 
echo "Instances in lazy loader: ".BurgerLazyLoader::getBurgerCount(); 
echo "\n"; 

$burger = BurgerLazyLoader::getBurger(true, false); 
echo "Burger with cheese and no fries costs: £".$burger->getPrice(); 

echo "\n"; 
echo "Instances in lazy loader: ".BurgerLazyLoader::getBurgerCount(); 
echo "\n"; 

$burger = BurgerLazyLoader::getBurger(true, true); 
echo "Burger with cheese and fries costs: £".$burger->getPrice(); 

echo "\n"; 
echo "Instances in lazy loader: ".BurgerLazyLoader::getBurgerCount(); 
echo "\n"; 

```

然后我们得到了这样的输出：

![延迟初始化](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_03_004.jpg)

由于价格是随机的，您会注意到数字会有所不同，但带奶酪和薯条的汉堡的价格在第一次和最后一次调用时保持不变。实例只创建一次；而且，它只在需要时才创建，而不是在想要时实例化。

假设汉堡店一边，当您需要时，这种创造性模式可以发挥一些很好的作用，比如当您需要延迟从一个类构造对象时。当构造函数是一个昂贵或耗时的操作时，通常会使用这种方法。

如果一个对象还不能被使用，就会以及时的方式创建一个。

# 建造者模式

当我们审查工厂设计模式时，我们看到它们对实现多态性是有用的。工厂模式和建造者模式之间的关键区别在于，建造者模式仅仅旨在解决一个反模式，并不寻求执行多态性。所涉及的反模式是望远镜构造函数。

望远镜构造函数问题实质上是指构造函数包含的参数数量增长到一定程度，使用起来变得不切实际，甚至不切实际地知道参数的顺序。

假设我们有一个`Pizza`类如下，它基本上包含一个构造函数和一个`show`函数，详细说明了披萨的大小和配料。类看起来像这样：

```php
<?php 

class Pizza 
{ 

  private $size; 
  private $cheese; 
  private $pepperoni; 
  private $bacon; 

  public function __construct($size, $cheese, $pepperoni, $bacon) 
  { 
    $this->size = $size; 
    $this->cheese = $cheese; 
    $this->pepperoni = $pepperoni; 
    $this->bacon = $bacon; 
  } 

  public function show() 
  { 
    $recipe = $this->size . " inch pizza with the following toppings: "; 
    $recipe .= $this->cheese ? "cheese, " : ""; 
    $recipe .= $this->pepperoni ? "pepperoni, " : ""; 
    $recipe .= $this->bacon ? "bacon, " : ""; 

    return $recipe; 
  } 

} 

```

注意构造函数包含多少参数，它实际上包含大小和每个配料。我们可以做得更好。事实上，让我们的目标是通过将所有参数添加到一个建造者对象中来构建披萨，然后我们可以使用它来创建披萨。这就是我们的目标：

```php
$pizzaRecipe = (new PizzaBuilder(9)) 
  ->cheese(true) 
  ->pepperoni(true) 
  ->bacon(true) 
  ->build(); 

$order = new Pizza($pizzaRecipe); 

```

这并不难做；实际上，您甚至可能会发现这是我们在这里学到的更容易的设计模式之一。让我们首先为我们的披萨制作一个建造者，让我们将这个类命名为`PizzaBuilder`：

```php
<?php 

class PizzaBuilder 
{ 
  public $size; 
  public $cheese; 
  public $pepperoni; 
  public $bacon; 

  public function __construct(int $size) 
  { 
    $this->size = $size; 
  } 

  public function cheese(bool $present): PizzaBuilder 
  { 
    $this->cheese = $present; 
    return $this; 
  } 

  public function pepperoni(bool $present): PizzaBuilder 
  { 
    $this->pepperoni = $present; 
    return $this; 
  } 

  public function bacon(bool $present): PizzaBuilder 
  { 
    $this->bacon = $present; 
    return $this; 
  } 

  public function build() 
  { 
    return $this; 
  } 
} 

```

这个类并不难理解，我们有一个设置大小的构造函数，对于我们想要添加的每个额外配料，我们可以调用相应的配料方法，并将参数设置为 true 或 false。如果没有调用配料方法，相应的配料就不会被设置为参数。

最后，我们有一个 build 方法，可以在将数据发送到`Pizza`类的构造函数之前调用以运行任何最后一刻的逻辑来组织数据。话虽如此，我通常不喜欢这样做，因为如果方法需要按特定顺序执行，这可能被认为是顺序耦合，这本质上会破坏我们制作建造者来执行这样的任务的一个目的。

因此，每个配料方法也返回它们正在创建的对象，允许任何函数的输出直接注入到我们想要用它来构造的任何类中。

接下来，让我们调整我们的`Pizza`类以利用这个建造者：

```php
<?php 

class Pizza 
{ 

  private $size; 
  private $cheese; 
  private $pepperoni; 
  private $bacon; 

  public function __construct(PizzaBuilder $builder) 
  { 
    $this->size = $builder->size; 
    $this->cheese = $builder->cheese; 
    $this->pepperoni = $builder->pepperoni; 
    $this->bacon = $builder->bacon; 
  } 

  public function show() 
  { 
    $recipe = $this->size . " inch pizza with the following toppings: "; 
    $recipe .= $this->cheese ? "cheese, " : ""; 
    $recipe .= $this->pepperoni ? "pepperoni, " : ""; 
    $recipe .= $this->bacon ? "bacon, " : ""; 

    return $recipe; 
  } 

} 

```

对于构造函数来说，这是相当简单的；我们只需在需要时访问建造者中的`public`属性。

请注意，我们可以在构造函数中添加对来自建造者的数据的额外验证，尽管您也可以根据所需的逻辑类型在建造者中设置方法时添加验证。

现在我们可以把所有这些放在我们的`index.php`文件中：

```php
<?php 

require_once('Pizza.php'); 
require_once('PizzaBuilder.php'); 

$pizzaRecipe = (new PizzaBuilder(9)) 
  ->cheese(true) 
  ->pepperoni(true) 
  ->bacon(true) 
  ->build(); 

$order = new Pizza($pizzaRecipe); 
echo $order->show(); 

```

我们应该得到的输出看起来像这样：

![建造者模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_03_005.jpg)

建造者设计模式非常容易采用，但在构建对象时可以节省很多麻烦。

这种方法的缺点是每个类都需要一个单独的建造者；这是对对象构建过程如此控制的代价。

在此之上，建造者设计模式允许您改变构造函数变量，并且还提供了对构造对象本身的代码进行良好封装。就像所有设计模式一样，由您决定在代码中何处最适合使用每个设计模式。

传统上，键值数组经常被用来替代建造者类。然而，建造者类可以更好地控制构建过程。

还有一件事我应该提一下；在这里，我们只是使用我们的`index.php`方法引用了这些方法；通常，我们在那里运行的方法被放置在一个可以称为*Director*类的类中。

在此之上，您还可以考虑在您的建造者中应用接口以实现大量逻辑。

# 原型模式

原型设计模式允许我们有效地复制对象，同时最小化重新实例化对象的性能影响。

如果您曾经使用过 JavaScript，您可能已经听说过原型语言。在这样的语言中，您通过克隆原型对象来创建新对象；反过来，创建新对象的成本降低了。

到目前为止，我们已经广泛讨论了`__construct magic`方法的使用，但我们还没有涉及`__clone magic`方法。`__clone magic`方法是在对象被克隆（如果可能的话）之前运行的；该方法不能直接调用，也不接受任何参数。

在使用这种设计模式时，您可能会发现使用`__clone`方法很有用；也就是说，根据您的用例，您可能不需要它。

非常重要的一点是要记住，当我们克隆一个对象时，`__construct`函数不会重新运行。对象已经被构造，因此 PHP 认为没有重新运行的理由，因此在使用这种设计模式时，最好避免在这里放置有意义的逻辑。

让我们首先定义一个基本的`Student`类：

```php
<?php 

class Student 
{ 
  public $name; 
  public $year; 
  public $grade; 

  public function setName(string $name) 
  { 
    $this->name = $name; 
  } 

  public function setYear(int $year) 
  { 
    $this->year = $year; 
  } 

  public function setGrade(string $grade) 
  { 
    $this->grade = $grade; 
  } 

} 

```

现在让我们开始构建我们的`index.php`文件，首先包括我们的`Student.php`类文件：

```php
require_once('Student.php'); 

```

然后，我们可以创建这个类的一个实例，设置各种变量，然后`var_dump`对象的内容，以便我们可以调试对象内部的细节，看看它是如何工作的：

```php
$prototypeStudent = new Student(); 
$prototypeStudent->setName('Dave'); 
$prototypeStudent->setYear(2); 
$prototypeStudent->setGrade('A*'); 

var_dump($prototypeStudent); 

```

此脚本的输出如下：

![原型模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_03_006.jpg)

到目前为止，一切都很好；我们基本上声明了一个基本类并设置了各种属性。对于我们的下一个挑战，让我们克隆这个脚本。我们可以通过将以下行添加到我们的`index.php`文件来实现这一点：

```php
$theLesserChild = clone $prototypeStudent; 
$theLesserChild->setName('Mike'); 
$theLesserChild->setGrade('B'); 

var_dump($theLesserChild); 

```

这是什么样子？好吧，看一下：

![原型模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_03_007.jpg)

看起来很简单；我们已经克隆了一个对象并成功更改了该对象的属性。我们的初始对象，原型，现在已经被克隆以构建一个新的学生。

是的，我们可以再次这样做，如下所示：

```php
$theChildProdigy = clone $prototypeStudent; 
$theChildProdigy->setName('Bob'); 
$theChildProdigy->setYear(3); 
$theChildProdigy->setGrade('A'); 

```

但我们也可以做得更好；通过使用匿名函数，也称为闭包，我们实际上可以动态地向这个对象添加额外的方法。

让我们为我们的对象定义一个匿名函数：

```php
$theChildProdigy->danceSkills = "Outstanding"; 
$theChildProdigy->dance = function (string $style) { 
  return "Dancing $style style."; 
}; 

```

最后，让我们同时输出新克隆对象的`var_dump`，但也执行我们刚刚创建的`dance`函数：

```php
var_dump($theChildProdigy); 
var_dump($theChildProdigy->dance->__invoke('Pogo')); 

```

您会注意到，实际上，我们不得不使用`__invoke`魔术方法来调用匿名函数。当脚本尝试将对象作为函数调用时，将调用此方法；在类变量中调用匿名函数时，这是至关重要的。

这是因为 PHP 类属性和方法都在不同的命名空间中；为了执行在类变量中的闭包，您需要使用`__invoke`；首先将其分配给一个类变量，使用`call_user_func`，或者使用`__call`魔术方法。

在这种情况下，我们只使用`__invoke`方法。

因此，脚本的输出如下：

![原型模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_03_008.jpg)

注意我们的函数是在最底部运行的？

因此，完成的`index.php`文件看起来像这样：

```php
<?php 

require_once('Student.php'); 

$prototypeStudent = new Student(); 
$prototypeStudent->setName('Dave'); 
$prototypeStudent->setYear(2); 
$prototypeStudent->setGrade('A*'); 

var_dump($prototypeStudent); 

$theLesserChild = clone $prototypeStudent; 
$theLesserChild->setName('Mike'); 
$theLesserChild->setGrade('B'); 

var_dump($theLesserChild); 

$theChildProdigy = clone $prototypeStudent; 
$theChildProdigy->setName('Bob'); 
$theChildProdigy->setYear(3); 
$theChildProdigy->setGrade('A'); 

$theChildProdigy->danceSkills = "Outstanding"; 
$theChildProdigy->dance = function (string $style) { 
  return "Dancing $style style."; 
}; 

var_dump($theChildProdigy); 
var_dump($theChildProdigy->dance->__invoke('Pogo')); 

```

这有一些很好的用例；假设您想执行事务。您可以取一个对象，克隆它，然后在所有查询成功并将克隆的对象提交到数据库中以替换原始对象。

这是一种非常有用且轻量级的方式，可以克隆一个对象，其中您知道克隆的对象需要与其父对象相同或几乎相同的内容。

# 总结

在本章中，我们开始学习与对象创建相关的一些关键 PHP 设计模式。我们了解了各种不同的工厂设计模式以及它们如何使您的代码更符合常见标准。我们还介绍了建造者设计模式如何帮助您避免在构造函数中使用过多参数。我们还学习了延迟实例化以及它如何帮助您的代码更加高效。最后，我们学习了如何使用原型设计模式从原型对象中复制对象。

继续设计模式，下一章我们将讨论结构设计模式。


# 第四章：结构设计模式

结构设计模式提供了创建类结构的不同方式；例如，这可以是我们如何使用封装来从较小的对象创建更大的对象。它们存在的目的是通过允许我们识别简单的方式来实现实体之间的关系，从而简化设计。

在上一章中，我们介绍了创造模式如何用于确定如何创建对象；而结构模式可以确定类之间的结构和关系。

在简短介绍了敏捷软件架构之后，本章将涵盖以下主题：

+   装饰者模式

+   类适配器模式

+   对象适配器模式

+   享元模式

+   组合模式

+   桥接模式

+   代理模式

+   外观模式

# 敏捷软件架构

许多组织正在倾向于采用敏捷形式的项目管理。这给架构师的角色带来了新的关注；事实上，一些人认为敏捷和架构是相互冲突的。敏捷宣言的最初签署者之一 Martin Fowler 和 Robert Cecil Martin 对这一观点持有强烈反对意见。事实上，福勒明确澄清了敏捷宣言虽然对大量的事先设计（例如 Prince2 中看到的类型）持敌对态度，但并不排斥事先设计本身。

计算机科学家 Allen Holub 也持有类似观点。敏捷侧重于做对用户有用的软件，而不是仅仅对销售人员有用的软件。为了使软件长期有用，它必须是可适应、可扩展和可维护的。

福勒还对软件开发团队中的架构师有了一个愿景。他指出，不可逆转的软件很可能会在以后带来最大的麻烦，这就是架构决策必须存在的地方。此外，他声称架构师的角色应该是寻求使这些决策可逆转，从而完全减轻问题。

在许多大规模软件部署中，可能会使用“我们已经到了无法回头的地步”的说法。在“无法回头”的地步之后，将部署恢复到原始状态变得不可行。软件有自己的“无法回头”的地步，当软件变得更难重写而不是简单重建时，就会成为事实。虽然软件可能不会达到这种“无法回头”的最坏情况，但随着可维护性困难的增加，会带来商业困难。

福勒还指出，在许多情况下，软件架构师甚至不检查软件是否符合其原始设计。通过与架构师进行配对编程，以及架构师审查代码更改（即拉取请求），他们可以获得理解，以便向开发人员提供反馈，并减轻进一步的技术债务。

在本书中，您可能会注意到缺少 UML；这是因为我认为这里不需要 UML。我的意思是，我们都在用 PHP 说话，对吧？不过你可能会发现 UML 在您的团队中很有用。

架构过程通常会产生可交付物；我们称这个可交付物为“工件”。在敏捷团队中，这些工件可能以渐进式方式开发，而不是事先产品，但在敏捷环境中完全可以进行架构设计。

事实上，我认为架构使在敏捷环境中工作变得更容易。当编程到接口或抽象层时，更容易替换类；在敏捷环境中，需求可能会发生变化，这意味着可能需要替换类。软件只有对最终客户有用时才有用。敏捷可以帮助实现这一点，但为了实现敏捷，您的代码必须是适应性的。拥有出色的架构对此至关重要。

当我们编写代码时，我们应该采取防御性的编码方式。然而，对手并不是敌人，而是我们自己。破坏可靠代码的最快方式之一是编辑它以使其变得脆弱。

# 装饰器

装饰器只是在不影响同一类的其他对象行为的情况下，为单个类添加额外功能的内容。

单一责任原则，由 Robert C. Martin（我在本章开头介绍过）简单地表述为“一个类应该只有一个改变的原因”。

该原则规定每个模块或类应该有一个单一的责任，并且该责任应该完全由该类封装。类的所有服务都应该与该责任保持一致。Martin 通过以下方式总结了这一责任：

> “指定给唯一的参与者的责任，表示其对于唯一的业务任务的责任。”

通过使用装饰器设计模式，我们能够确保功能在具有独特关注领域的类之间进行划分，从而遵守单一责任原则。

让我们首先声明我们的`Book`接口。这是我们期望我们的书能够产生的内容：

```php
<?php 

interface Book 
{ 
  public function __construct(string $title, string $author, string $contents); 

  public function getTitle(): string; 

  public function getAuthor(): string; 

  public function getContents(): string; 
} 

```

然后我们可以声明我们的`EBook.php`类。这是我们将用`PrintBook`类装饰的类：

```php
<?php 

class EBook implements Book 
{ 

  public $title; 
  public $author; 
  public $contents; 

  public function __construct(string $title, string $author, string $contents) 
  { 
    $this->title = $title; 
    $this->author = $author; 
    $this->contents = $contents; 
  } 

  public function getTitle(): string 
  { 
    return $this->contents; 
  } 

  public function getAuthor(): string 
  { 
    return $this->author; 
  } 

  public function getContents(): string 
  { 
    return $this->contents; 
  } 
} 

```

现在我们可以声明我们的`PrintBook`类。这是我们用来装饰`EBook`类的内容：

```php
<?php 

class PrintBook implements Book 
{ 

  public $eBook; 

  public function __construct(string $title, string $author, string $contents) 
  { 
    $this->eBook = new EBook($title, $author, $contents); 
  } 

  public function getTitle(): string 
  { 
    return $this->eBook->getTitle(); 
  } 

  public function getAuthor(): string 
  { 
    return $this->eBook->getAuthor(); 
  } 

  public function getContents(): string 
  { 
    return $this->eBook->getContents(); 
  } 

  public function getText(): string 
  { 
    $contents = $this->eBook->getTitle() . " by " . $this->eBook->getAuthor(); 
    $contents .= "\n"; 
    $contents .= $this->eBook->getContents(); 

    return $contents; 
  } 
} 

```

现在让我们用我们的`index.php`文件来测试所有这些。

```php
<?php 

require_once('Book.php'); 
require_once('EBook.php'); 
$PHPBook = new EBook("Mastering PHP Design Patterns", "Junade Ali", "Some contents."); 

require_once('PrintBook.php'); 
$PHPBook = new PrintBook("Mastering PHP Design Patterns", "Junade Ali", "Some contents."); 
echo $PHPBook->getText(); 

```

输出如下：

```php
Some contents. by Junade Ali 
Some contents. 

```

# 适配器

适配器模式有两种类型。在可能的情况下，我更偏向于对象适配器而不是类适配器；我稍后会详细解释这一点。

适配器模式允许现有的类与其不匹配的接口一起使用。它经常用于允许现有的类与其他类一起工作，而无需修改它们的源代码。

这在使用具有各自接口的第三方库的多态设置中可能非常有用。

基本上，适配器帮助两个不兼容的接口一起工作。通过将一个类的接口转换为客户端期望的接口，否则不兼容的类可以被使得一起工作。

## 类适配器

在类适配器中，我们使用继承来创建一个适配器。一个类（适配器）可以继承另一个类（被适配者）；使用标准继承，我们能够为被适配者添加额外功能。

假设我们有一个`ATM`类，在我们的`ATM.php`文件中：

```php
<?php 

class ATM 
{ 
  private $balance; 

  public function __construct(float $balance) 
  { 
    $this->balance = $balance; 
  } 

  public function withdraw(float $amount): float 
  { 
    if ($this->reduceBalance($amount) === true) { 
      return $amount; 
    } else { 
      throw new Exception("Couldn't withdraw money."); 
    } 
  } 

  protected function reduceBalance(float $amount): bool 
  { 
    if ($amount >= $this->balance) { 
      return false; 
    } 

    $this->balance = ($this->balance - $amount); 
    return true; 
  } 

  public function getBalance(): float 
  { 
    return $this->balance; 
  } 
} 

```

让我们创建我们的`ATMWithPhoneTopUp.php`来形成我们的适配器：

```php
<?php 

class ATMWithPhoneTopUp extends ATM 
{ 
  public function getTopUp(float $amount, int $time): string 
  { 
    if ($this->reduceBalance($amount) === true) { 
      return $this->generateTopUpCode($amount, $time); 
    } else { 
      throw new Exception("Couldn't withdraw money."); 
    } 
  } 

  private function generateTopUpCode(float $amount, int $time): string 
  { 
    return $amount . $time . rand(0, 10000); 
  } 
} 

```

让我们将所有这些内容包装在一个`index.php`文件中：

```php
<?php 

require_once('ATM.php'); 

$atm = new ATM(500.00); 
$atm->withdraw(50); 
echo $atm->getBalance(); 
echo "\n"; 

require_once('ATMWithPhoneTopUp.php'); 

$adaptedATM = new ATMWithPhoneTopUp(500.00); 
echo "Top-up code: " . $adaptedATM->getTopUp(50, time()); 
echo "\n"; 
echo $adaptedATM->getBalance(); 

```

现在我们已经将初始的`ATM`类调整为生成充值码，我们现在可以利用这个新的充值功能。所有这些的输出如下：

```php
450 
Top-up code: 5014606939121598 
450 

```

请注意，如果我们想要适应多个被适配者，这在 PHP 中将会很困难。

在 PHP 中，多重继承是不可能的，除非你使用 Traits。在这种情况下，我们只能使一个类适应另一个类的接口。

我们不使用这种方法的另一个关键架构原因是，通常更倾向于优先使用组合而不是继承（正如复用组合原则所描述的）。

为了更详细地探讨这一原则，我们需要看看对象适配器。

## 对象适配器

复用组合原则规定，类应该通过它们的组合实现多态行为和代码复用。

通过应用这一原则，当类想要实现特定功能时，应该包含其他类的实例，而不是从基类或父类继承功能。

因此，四人帮提出了以下观点：

> “更偏向于‘对象组合’而不是‘类继承’。”

为什么这个原则如此重要？考虑我们上一个例子，我们在那里使用了类继承；在这种情况下，我们无法保证我们的适配器是否符合我们想要的接口。如果父类暴露了我们不想要适配器的函数会怎么样？组合给了我们更多的控制。

通过组合而不是继承，我们能够更好地支持面向对象编程中如此重要的多态行为。

假设我们有一个生成保险费的类。它根据客户希望如何支付保险费提供月度保费和年度保费。通过年度支付，客户可以节省相当于半个月的金额：

```php
<?php 

class Insurance 
{ 
  private $limit; 
  private $excess; 

  public function __construct(float $limit, float $excess) 
  { 
    if ($excess >= $limit) { 
      throw New Exception('Excess must be less than premium.'); 
    } 

    $this->limit = $limit; 
    $this->excess = $excess; 
  } 

  public function monthlyPremium(): float 
  { 
    return ($this->limit-$this->excess)/200; 
  } 

  public function annualPremium(): float 
  { 
    return $this->monthlyPremium()*11.5; 
  } 
} 

```

假设市场比较工具多态地使用诸如前面提到的类来实际上计算来自多个不同供应商的保险报价；他们使用这个接口来做到这一点：

```php
<?php 

interface MarketCompare 
{ 
  public function __construct(float $limit, float $excess); 
  public function getAnnualPremium(); 
  public function getMonthlyPremium(); 
} 

```

因此，我们可以使用这个接口来构建一个对象适配器，以确保我们的`Insurance`类，我们的保费生成器，符合市场比较工具所期望的接口：

```php
<?php 

class InsuranceMarketCompare implements MarketCompare 
{ 
  private $premium; 

  public function __construct(float $limit, float $excess) 
  { 
    $this->premium = new Insurance($limit, $excess); 
  } 

  public function getAnnualPremium(): float 
  { 
    return $this->premium->annualPremium(); 
  } 

  public function getMonthlyPremium(): float 
  { 
    return $this->premium->monthlyPremium(); 
  } 
} 

```

注意类实际上是如何实例化自己的类以适应它所尝试适配的内容。

然后适配器将这个类存储在一个`private`变量中。然后我们使用这个对象在`private`变量中代理请求。

适配器，无论是类适配器还是对象适配器，都应该充当粘合代码。我的意思是适配器不应执行任何计算或计算，它们只是在不兼容的接口之间充当代理。

将逻辑保持在我们的粘合代码之外，并将逻辑留给我们正在适应的代码是标准做法。如果在这样做时，我们遇到单一责任原则，我们需要适应另一个类。

正如我之前提到的，在类适配器中适配多个类实际上是不可能的，所以你要么必须将这样的逻辑包装在一个 Trait 中，要么我们需要使用对象适配器，比如我们正在讨论的这个。

让我们试试这个适配器。我们将通过编写以下`index.php`文件来看看我们的新类是否符合预期的接口：

```php
<?php 

require_once('Insurance.php'); 

$quote = new Insurance(10000, 250); 
echo $quote->monthlyPremium(); 
echo "\n"; 

require_once('MarketCompare.php'); 
require_once('InsuranceMarketCompare.php'); 

$quote = new InsuranceMarketCompare(10000, 250); 
echo $quote->getMonthlyPremium(); 
echo "\n"; 
echo $quote->getAnnualPremium(); 

```

输出应该看起来像这样：

```php
48.75 
48.75 
560.625 

```

与类适配器方法相比，这种方法的主要缺点是，我们必须实现公共方法，即使这些方法只是转发方法。

# FlyWeight

就像在现实生活中，不是所有的对象都容易创建，有些可能会占用过多的内存。FlyWeight 设计模式可以通过尽可能与类似对象共享尽可能多的数据来帮助我们最小化内存使用。

这种设计模式在大多数 PHP 应用程序中的使用有限，但是了解它在极端有用的情况下仍然是值得的。

假设我们有一个带有`draw`方法的`Shape`接口：

```php
<?php 

interface Shape 
{ 
  public function draw(); 
} 

```

让我们创建一个实现这个接口的`Circle`类。在实现这个过程中，我们建立了设置圆的位置和半径以及绘制它（打印出这些信息）的能力。注意颜色特征是如何在类外设置的。

这有一个非常重要的原因。在我们的例子中，颜色是与状态无关的；它是圆的固有部分。然而，圆的位置和大小是与状态相关的，因此是外部的。当需要时，外部状态信息被传递给 FlyWeight 对象；然而，固有选项与 FlyWeight 的每个过程无关。当我们讨论这个工厂是如何制作的时，这将更有意义。

这是重要的信息：

+   **外部**：状态属于对象的外部上下文，并在使用对象时输入。

+   **内在**：自然属于对象的状态，因此应该是永久的、不可变的（内部）或与上下文无关的。

考虑到这一点，让我们组合一个实现我们的`Shape`接口的实现。这是我们的`Circle`类：

```php
<?php 

class Circle implements Shape 
{ 

  private $colour; 
  private $x; 
  private $y; 
  private $radius; 

  public function __construct(string $colour) 
  { 
    $this->colour = $colour; 
  } 

  public function setX(int $x) 
  { 
    $this->x = $x; 
  } 

  public function setY(int $y) 
  { 
    $this->y = $y; 
  } 

  public function setRadius(int $radius) 
  { 
    $this->radius = $radius; 
  } 

  public function draw() 
  { 
    echo "Drawing circle which is " . $this->colour . " at [" . $this->x . ", " . $this->y . "] of radius " . $this->radius . "."; 
    echo "\n"; 
  } 
} 

```

有了这个，我们现在可以构建我们的`ShapeFactory`，它实际上实现了 FlyWeight 模式。当需要时，会实例化一个具有我们选择的颜色的对象，然后将其存储以供以后使用：

```php
<?php 

class ShapeFactory 
{ 
  private $shapeMap = array(); 

  public function getCircle(string $colour) 
  { 
    $circle = 'Circle' . '_' . $colour; 

    if (!isset($this->shapeMap[$circle])) { 
      echo "Creating a ".$colour." circle."; 
      echo "\n"; 
      $this->shapeMap[$circle] = new Circle($colour); 
    } 

    return $this->shapeMap[$circle]; 
  } 
} 

```

让我们在我们的`index.php`文件中演示这是如何工作的。

为了使这个工作，我们创建`100`个带有随机颜色的对象，放在随机位置：

```php
require_once('Shape.php'); 
require_once('Circle.php'); 
require_once('ShapeFactory.php'); 

$colours = array('red', 'blue', 'green', 'black', 'white', 'orange'); 

$factory = new ShapeFactory(); 

for ($i = 0; $i < 100; $i++) { 
  $randomColour = $colours[array_rand($colours)]; 

  $circle = $factory->getCircle($randomColour); 
  $circle->setX(rand(0, 100)); 
  $circle->setY(rand(0, 100)); 
  $circle->setRadius(100); 

  $circle->draw(); 
} 

```

现在，让我们来看一下输出。您可以看到我们画了 100 个圆，但我们只需要实例化少量圆，因为我们正在缓存相同颜色的对象以供以后使用：

```php
Creating a green circle. 
Drawing circle which is green at [29, 26] of radius 100\. 
Creating a black circle. 
Drawing circle which is black at [17, 64] of radius 100\. 
Drawing circle which is black at [81, 86] of radius 100\. 
Drawing circle which is black at [0, 73] of radius 100\. 
Creating a red circle. 
Drawing circle which is red at [10, 15] of radius 100\. 
Drawing circle which is red at [70, 79] of radius 100\. 
Drawing circle which is red at [13, 78] of radius 100\. 
Drawing circle which is green at [78, 27] of radius 100\. 
Creating a blue circle. 
Drawing circle which is blue at [38, 11] of radius 100\. 
Creating a orange circle. 
Drawing circle which is orange at [43, 57] of radius 100\. 
Drawing circle which is blue at [58, 65] of radius 100\. 
Drawing circle which is orange at [75, 67] of radius 100\. 
Drawing circle which is green at [92, 59] of radius 100\. 
Drawing circle which is blue at [53, 3] of radius 100\. 
Drawing circle which is black at [14, 33] of radius 100\. 
Creating a white circle. 
Drawing circle which is white at [84, 46] of radius 100\. 
Drawing circle which is green at [49, 61] of radius 100\. 
Drawing circle which is orange at [57, 44] of radius 100\. 
Drawing circle which is orange at [64, 33] of radius 100\. 
Drawing circle which is white at [42, 74] of radius 100\. 
Drawing circle which is green at [5, 91] of radius 100\. 
Drawing circle which is white at [87, 36] of radius 100\. 
Drawing circle which is red at [74, 94] of radius 100\. 
Drawing circle which is black at [19, 6] of radius 100\. 
Drawing circle which is orange at [70, 83] of radius 100\. 
Drawing circle which is green at [74, 64] of radius 100\. 
Drawing circle which is white at [89, 21] of radius 100\. 
Drawing circle which is red at [25, 23] of radius 100\. 
Drawing circle which is blue at [68, 96] of radius 100\. 
Drawing circle which is green at [74, 6] of radius 100\. 

```

您可能已经注意到了一些事情。我们正在存储我们正在重用的 FlyWeight 对象的缓存的方式是通过连接*Circle*_ 和颜色，例如*Circle_green*。显然，在这种情况下这是有效的，但有更好的方法；在 PHP 中，实际上可以为给定的对象获取唯一 ID。我们将在下一个模式中介绍这个。

# 组合

想象一个由单独歌曲和歌曲播放列表组成的音频系统。是的，播放列表由歌曲组成，但我们希望两者都被单独对待。两者都是音乐类型，都可以播放。

组合设计模式可以帮助我们；它允许我们忽略对象组合和单个对象之间的差异。它允许我们用相同或几乎相同的代码来处理两者。

让我们举个小例子；一首歌是我们*叶子*的例子，而播放列表是*组合*。`Music`是我们对播放列表和歌曲的抽象；因此，我们可以称之为我们的*组件*。所有这些的*客户端*是我们的`index.php`文件。

通过不区分叶节点和分支，我们的代码变得不那么复杂，因此也不那么容易出错。

让我们首先为我们的`Music`定义一个接口：

```php
<?php 

interface Music 
{ 
  public function play(); 
} 

```

现在让我们组合一些实现，首先是我们的`Song`类：

```php
<?php 

class Song implements Music 
{ 
  public $id; 
  public $name; 

  public function  __construct(string $name) 
  { 
    $this->id = uniqid(); 
    $this->name = $name; 
  } 

  public function play() 
  { 
    printf("Playing song #%s, %s.\n", $this->id, $this->name); 
  } 
} 

```

现在我们可以开始组合我们的`Playlist`类。在这个例子中，您可能注意到我使用一个名为`spl_object_hash`的函数在歌曲数组中设置键。当处理对象数组时，这个函数绝对是一个祝福。

这个函数的作用是为每个对象返回一个唯一的哈希值，只要对象没有被销毁，无论类的属性如何改变，它都保持一致。它提供了一种稳定的方式来寻址任意对象。一旦对象被销毁，哈希值就可以被重用于其他对象。

这个函数不会对对象的内容进行哈希处理；它只是显示内部句柄和句柄表指针。这意味着如果您更改对象的属性，哈希值不会改变。也就是说，它并不保证唯一性。如果一个对象被销毁，然后立即创建一个相同类的对象，您将得到相同的哈希值，因为 PHP 将在第一个类被取消引用和销毁后重用相同的内部句柄。

这将是真的，因为 PHP 可以使用内部句柄：

```php
var_dump(spl_object_hash(new stdClass()) === spl_object_hash(new stdClass())); 

```

然而，这将是错误的，因为 PHP 必须创建一个新的句柄：

```php
$object = new StdClass(); 
var_dump(spl_object_hash($object) === spl_object_hash(new stdClass())); 

```

现在让我们回到我们的`Playlist`类。让我们用它实现我们的`Music`接口；所以，这是类：

```php
<?php 

class Playlist implements Music 
{ 
  private $songs = array(); 

  public function addSong(Music $content): bool 
  { 
    $this->songs[spl_object_hash($content)] = $content; 
    return true; 
  } 

  public function removeItem(Music $content): bool 
  { 
    unset($this->songs[spl_object_hash($content)]); 
    return true; 
  } 

  public function play() 
  { 
    foreach ($this->songs as $content) { 
      $content->play(); 
    } 
  } 
} 

```

现在让我们把这一切放在我们的`index.php`文件中。我们在这里所做的是创建一些歌曲对象，其中一些我们将使用它们的`addSong`函数分配给一个播放列表。

因为播放列表的实现方式与歌曲相同，我们甚至可以使用`addSong`函数与其他播放列表一起使用（在这种情况下，最好将`addSong`函数重命名为`addMusic`）。

然后我们播放父播放列表。这将播放子播放列表，然后播放这些播放列表中的所有歌曲：

```php
<?php 

require_once('Music.php'); 
require_once('Playlist.php'); 
require_once('Song.php'); 

$songOne = new Song('Lost In Stereo'); 
$songTwo = new Song('Running From Lions'); 
$songThree = new Song('Guts'); 
$playlistOne = new Playlist(); 
$playlistTwo = new Playlist(); 
$playlistThree = new Playlist(); 
$playlistTwo->addSong($songOne); 
$playlistTwo->addSong($songTwo); 
$playlistThree->addSong($songThree); 
$playlistOne->addSong($playlistTwo); 
$playlistOne->addSong($playlistThree); 
$playlistOne->play(); 

```

当我们运行这个脚本时，我们可以看到预期的输出：

```php
Playing song #57106d5adb364, Lost In Stereo. 
Playing song #57106d5adb63a, Running From Lions. 
Playing song #57106d5adb654, Guts. 

```

# 桥接

桥接模式可能非常简单；它有效地允许我们将抽象与实现解耦，以便两者可以独立变化。

当类经常变化时，通过桥接接口和具体类，开发人员可以更轻松地变化他们的类。

让我们提出一个通用的信使接口，具有发送某种形式消息的能力，`Messenger.php`：

```php
<?php 

interface Messenger 
{ 
  public function send($body); 
} 

```

这个接口的一个具体实现是一个`InstantMessenger`应用程序，`InstantMessenger.php`：

```php
<?php 

class InstantMessenger implements Messenger 
{ 
  public function send($body) 
  { 
    echo "InstantMessenger: " . $body; 
  } 
} 

```

同样，我们可以用一个`SMS`应用程序`SMS.php`来做同样的事情：

```php
<?php 

class SMS implements Messenger 
{ 
  public function send($body) 
  { 
    echo "SMS: " . $body; 
  } 
} 

```

我们现在可以为物理设备，即发射器，创建一个接口，`Transmitter.php`：

```php
<?php 

interface Transmitter 
{ 
  public function setSender(Messenger $sender); 

  public function send($body); 
} 

```

我们可以通过使用`Device`类将实现其方法的设备与发射器解耦。`Device`类将`Transmitter`接口桥接到物理设备，`Device.php`：

```php
<?php 

abstract class Device implements Transmitter 
{ 
  protected $sender; 

  public function setSender(Messenger $sender) 
  { 
    $this->sender = $sender; 
  } 
} 

```

所以让我们组合一个具体的类来表示手机，`Phone.php`：

```php
<?php 

class Phone extends Device 
{ 
  public function send($body) 
  { 
    $body .= "\n\n Sent from a phone."; 

    return $this->sender->send($body); 
  } 
} 

```

让我们对`Tablet`做同样的事情。`Tablet.php`是：

```php
<?php 

class Tablet extends Device 
{ 
  public function send($body) 
  { 
    $body .= "\n\n Sent from a Tablet."; 

    return $this->sender->send($body); 
  } 
} 

```

最后，让我们把这一切都包装在一个`index.php`文件中：

```php
<?php 

require_once('Transmitter.php'); 
require_once('Device.php'); 
require_once('Phone.php'); 
require_once('Tablet.php'); 

require_once('Messenger.php'); 
require_once('SMS.php'); 
require_once('InstantMessenger.php'); 

$phone = new Phone(); 
$phone->setSender(new SMS()); 

$phone->send("Hello there!"); 

```

这个输出如下：

```php
SMS: Hello there! 

 Sent from a phone. 

```

# 代理模式

代理是一个仅仅是与其他东西接口的类。它可以是任何东西的接口；从网络连接、文件、内存中的大对象，或者其他太难复制的资源。

在我们的例子中，我们将简单地创建一个简单的代理，根据代理的实例化方式转发到两个对象中的一个。

访问一个简单的代理类允许客户端从一个对象中访问猫和狗的喂食器，具体取决于它是否已被实例化。

让我们首先定义一个`AnimalFeeder`的接口：

```php
<?php 

namespace IcyApril\PetShop; 

interface AnimalFeeder 
{ 
  public function __construct(string $petName); 

  public function dropFood(int $hungerLevel, bool $water = false): string; 

  public function displayFood(int $hungerLevel): string; 
} 

```

然后我们可以为猫和狗定义两个动物喂食器：

```php
<?php 

namespace IcyApril\PetShop\AnimalFeeders; 

use IcyApril\PetShop\AnimalFeeder; 

class Cat implements AnimalFeeder 
{ 
  public function __construct(string $petName) 
  { 
    $this->petName = $petName; 
  } 

  public function dropFood(int $hungerLevel, bool $water = false): string 
  { 
    return $this->selectFood($hungerLevel) . ($water ? ' with water' : ''); 
  } 

  public function displayFood(int $hungerLevel): string 
  { 
    return $this->selectFood($hungerLevel); 
  } 

  protected function selectFood(int $hungerLevel): string 
  { 
    switch ($hungerLevel) { 
      case 0: 
        return 'lamb'; 
        break; 
      case 1: 
        return 'chicken'; 
        break; 
      case 3: 
        return 'tuna'; 
        break; 
    } 
  } 
} 

```

这是我们的`AnimalFeeder`：

```php
<?php 

namespace IcyApril\PetShop\AnimalFeeders; 

class Dog 
{ 

  public function __construct(string $petName) 
  { 
    if (strlen($petName) > 10) { 
      throw new \Exception('Name too long.'); 
    } 

    $this->petName = $petName; 
  } 

  public function dropFood(int $hungerLevel, bool $water = false): string 
  { 
    return $this->selectFood($hungerLevel) . ($water ? ' with water' : ''); 
  } 

  public function displayFood(int $hungerLevel): string 
  { 
    return $this->selectFood($hungerLevel); 
  } 

  protected function selectFood(int $hungerLevel): string 
  { 
    if ($hungerLevel == 3) { 
      return "chicken and vegetables"; 
    } elseif (date('H') < 10) { 
      return "turkey and beef"; 
    } else { 
      return "chicken and rice"; 
    } 
  } 
} 

```

有了这个定义，我们现在可以创建我们的代理类，一个基本上使用构造函数来解密需要实例化的类，然后将所有函数调用重定向到这个类。为了重定向函数调用，使用`__call magic`方法。

看起来像这样：

```php
<?php 

namespace IcyApril\PetShop; 

class AnimalFeederProxy 
{ 
  protected $instance; 

  public function __construct(string $feeder, string $name) 
  { 
    $class = __NAMESPACE__ . '\\AnimalFeeders' . $feeder; 
    $this->instance = new $class($name); 
  } 

  public function __call($name, $arguments) 
  { 
    return call_user_func_array([$this->instance, $name], $arguments); 
  } 
} 

```

你可能已经注意到，我们必须在构造函数中手动创建带有命名空间的类。我们使用`__NAMESPACE__ magic`常量来找到当前命名空间，然后将其连接到类所在的特定子命名空间。请注意，我们必须使用另一个`\`来转义`\`，以便允许我们指定命名空间，而不让 PHP 将`\`解释为转义字符。

让我们构建我们的`index.php`文件，并利用代理类来构建对象：

```php
<?php 

require_once('AnimalFeeder.php'); 
require_once('AnimalFeederProxy.php'); 

require_once('AnimalFeeders/Cat.php'); 
$felix = new \IcyApril\PetShop\AnimalFeederProxy('Cat', 'Felix'); 
echo $felix->displayFood(1); 
echo "\n"; 
echo $felix->dropFood(1, true); 
echo "\n"; 

require_once('AnimalFeeders/Dog.php'); 
$brian = new \IcyApril\PetShop\AnimalFeederProxy('Dog', 'Brian'); 
echo $brian->displayFood(1); 
echo "\n"; 
echo $brian->dropFood(1, true); 

```

输出如下：

```php
chicken 
chicken with water 
turkey and beef 
turkey and beef with water 

```

那么你如何在现实中使用它呢？假设你从数据库中得到了一个包含动物类型和名称的对象的记录；你可以将这个对象传递给代理类的构造函数，并将其作为创建你的类的机制。

在实践中，当支持资源密集型对象时，这是一个很好的用例，除非客户端真正需要它们，否则你不一定想要实例化它们；对于资源密集型网络连接和其他类型的资源也是如此。

# 外观

外观（也称为*Façade*）设计模式是一件奇妙的事情；它们本质上是一个复杂系统的简单接口。外观设计模式通过提供一个单一的类来工作，这个类本身实例化其他类并提供一个简单的接口来使用这些函数。

使用这种模式时的一个警告是，由于类是在外观中实例化的，你本质上是将它所使用的类紧密耦合在一起。有些情况下你希望这样做，但也有些情况下你不希望。在你不希望这种行为的情况下，最好使用依赖注入。

我发现这在将一组糟糕的 API 封装成一个统一的 API 时非常有用。它减少了外部依赖，允许复杂性内部化；这个过程可以使你的代码更易读。

我将在一个粗糙的例子中演示这种模式，但这将使机制变得明显。

让我提议三个玩具工厂的类。

制造商（制造玩具的工厂）是一个简单的类，它根据一次制造多少个玩具来实例化：

```php
<?php 

class Manufacturer 
{ 
  private $capacity; 

  public function __construct(int $capacity) 
  { 
    $this->capacity = $capacity; 
  } 

  public function build(): string 
  { 
    return uniqid(); 
  } 
} 

```

Post 类（运输快递员）是一个简单的函数，用于从工厂发货玩具：

```php
<?php 

class Post 
{ 
  private $sender; 

  public function __construct(string $sender) 
  { 
    $this->sender = $sender; 
  } 

  public function dispatch(string $item, string $to): bool 
  { 
    if (strlen($item) !== 13) { 
      return false; 
    } 

    if (empty($to)) { 
      return false; 
    } 

    return true; 
  } 
} 

```

一个`SMS`类通知客户他们的玩具已经从工厂发货：

```php
<?php 

class SMS 
{ 
  private $from; 

  public function __construct(string $from) 
  { 
    $this->from = $from; 
  } 

  public function send(string $to, string $message): bool 
  { 
    if (empty($to)) { 
      return false; 
    } 

    if (strlen($message) === 0) { 
      return false; 
    } 

    echo $to . " received message: " . $message; 
    return true; 
  } 
} 

```

这是我们的`ToyFactory`类，它充当一个外观，将所有这些类连接在一起，并允许操作按顺序发生：

```php
<?php 

class ToyShop 
{ 
  private $courier; 
  private $manufacturer; 
  private $sms; 

  public function __construct(String $factoryAdress, String $contactNumber, int $capacity) 
  { 
    $this->courier = new Post($factoryAdress); 
    $this->sms = new SMS($contactNumber); 
    $this->manufacturer = new Manufacturer($capacity); 
  } 

  public function processOrder(string $address, $phone) 
  { 
    $item = $this->manufacturer->build(); 
    $this->courier->dispatch($item, $address); 
    $this->sms->send($phone, "Your order has been shipped."); 
  } 
} 

```

最后，我们可以将所有这些内容包装在我们的`index.php`文件中：

```php
<?php 

require_once('Manufacturer.php'); 
require_once('Post.php'); 
require_once('SMS.php'); 
require_once('ToyShop.php'); 

$childrensToyFactory = new ToyShop('1 Factory Lane, Oxfordshire', '07999999999', 5); 
$childrensToyFactory->processOrder('8 Midsummer Boulevard', '07123456789'); 

```

一旦我们运行这段代码，我们会看到来自我们的`SMS`类的消息显示出短信已发送：

![Facade](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php-dsn-ptn/img/image_04_001.jpg)

在其他情况下，当各种类之间耦合较松时，我们可能会发现最好使用依赖注入。通过将执行各种操作的对象注入到`ToyFactory`类中，我们可以通过能够注入`ToyFactory`类可以操作的假类来使测试变得更容易。

就我个人而言，我非常相信尽可能使代码易于测试；这也是为什么我不喜欢这种方法的原因。

# 总结

本章通过引入结构设计模式扩展了我们在上一章开始学习的设计模式。

因此，我们学会了一些关键的模式来简化软件设计过程；这些模式确定了实现不同实体之间关系的简单方式：

+   我们学习了装饰器，如何包装类以向它们添加额外的行为，并且关键是，我们学会了这如何帮助我们遵守单一职责原则。

+   我们学习了类和对象适配器，以及它们之间的区别。这里的关键是为什么我们可能会选择组合而不是继承的论点。

+   我们复习了享元设计模式，它可以帮助我们以节省内存的方式执行某些过程。

+   我们学会了组合设计模式如何帮助我们将对象的组合与单个对象一样对待。

+   我们介绍了桥接设计模式，它让我们将抽象与实现解耦，使两者能够独立变化。

+   我们介绍了代理设计模式如何作为另一个类的接口，并且我们可以将其用作转发代理。

+   最后，我们学会了外观设计模式如何用于为复杂系统提供简单的接口。

在下一章中，我们将通过讨论行为模式来结束我们的设计模式部分，准备涉及架构模式。
