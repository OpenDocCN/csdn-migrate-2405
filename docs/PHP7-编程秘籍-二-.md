# PHP7 编程秘籍（二）

> 原文：[`zh.annas-archive.org/md5/2ddf943a2c311275def462dcde4895fb`](https://zh.annas-archive.org/md5/2ddf943a2c311275def462dcde4895fb)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 PHP 面向对象编程

在本章中我们将涵盖：

+   开发类

+   扩展类

+   使用静态属性和方法

+   使用命名空间

+   定义可见性

+   使用接口

+   使用 traits

+   实现匿名类

# 介绍

在本章中，我们将考虑利用 PHP 7.0、7.1 及以上版本中可用的**面向对象编程**（**OOP**）功能的相关内容。PHP 7.x 中大部分的 OOP 功能也适用于 PHP 5.6。PHP 7 引入的新功能是支持**匿名类**。在 PHP 7.1 中，您可以修改类常量的可见性。

### 注意

另一个全新的功能是**捕获**某些类型的错误。这在第十三章*最佳实践、测试和调试*中更详细地讨论。

# 开发类

传统的开发方法是将类放入自己的文件中。通常，类包含实现单一目的的逻辑。类进一步分解为自包含的函数，这些函数被称为**方法**。在类内定义的变量被称为**属性**。建议同时开发一个测试类，这是在第十三章*最佳实践、测试和调试*中更详细讨论的主题。

## 如何做...

1.  创建一个文件来包含类定义。为了自动加载的目的，建议文件名与类名匹配。在文件顶部，在关键字`class`之前，添加一个**DocBlock**。然后您可以定义属性和方法。在这个例子中，我们定义了一个类`Test`。它有一个属性`$test`和一个方法`getTest()`：

```php
<?php
declare(strict_types=1);
/**
 * This is a demonstration class.
 *
 * The purpose of this class is to get and set 
 * a protected property $test
 *
 */
class Test
{

  protected $test = 'TEST';

  /**
   * This method returns the current value of $test
   *
   * @return string $test
   */
  public function getTest() : string
  {
    return $this->test;
  }

  /**
   * This method sets the value of $test
   *
   * @param string $test
   * @return Test $this
   */
  public function setTest(string $test)
  {
    $this->test = $test;
    return $this;
  }
}
```

### 提示

**最佳实践**

将文件命名为类名被认为是最佳实践。虽然 PHP 中的类名不区分大小写，但进一步被认为是最佳实践的是使用大写字母作为类名的第一个字母。您不应该在类定义文件中放置可执行代码。

每个类都应该在关键字`class`之前包含一个**DocBlock**。在 DocBlock 中，您应该包括一个关于类目的简短描述。空一行，然后包括更详细的描述。您还可以包括`@`标签，如`@author`、`@license`等。每个方法也应该在之前包含一个标识方法目的的 DocBlock，以及它的传入参数和返回值。

1.  可以在一个文件中定义多个类，但这不被认为是最佳实践。在这个例子中，我们创建一个文件`NameAddress.php`，其中定义了两个类，`Name`和`Address`：

```php
<?php
declare(strict_types=1);
class Name
{

  protected $name = '';

  public function getName() : string
  {
    return $this->name;
  }

  public function setName(string $name)
  {
    $this->name = $name;

    return $this;
  }
}

class Address
{

  protected $address = '';

  public function getAddress() : string
  {
    return $this->address;
  }

  public function setAddress(string $address)
  {
    $this->address = $address;
    return $this;
  }
}
```

### 提示

虽然您可以在单个文件中定义多个类，如前面的代码片段所示，但这并不被认为是最佳实践。这不仅会使文件的逻辑纯度降低，而且会使自动加载变得更加困难。

1.  类名不区分大小写。重复将被标记为错误。在这个例子中，在一个名为`TwoClass.php`的文件中，我们定义了两个类，`TwoClass`和`twoclass`：

```php
<?php
class TwoClass
{
  public function showOne()
  {
    return 'ONE';
  }
}

// a fatal error will occur when the second class definition is parsed
class twoclass
{
  public function showTwo()
  {
    return 'TWO';
  }
}
```

1.  PHP 7.1 已解决了在使用关键字`$this`时的不一致行为。虽然在 PHP 7.0 和 PHP 5.x 中允许使用，但在 PHP 7.1 中，如果`$this`被用作：

+   一个参数

+   一个`static`变量

+   一个`global`变量

+   在`try...catch`块中使用的变量

+   在`foreach()`中使用的变量

+   作为`unset()`的参数

+   作为一个变量（即，`$a = 'this'; echo $$a`）

+   通过引用间接使用

1.  如果您需要创建一个对象实例，但不想定义一个离散的类，您可以使用内置于 PHP 中的通用`stdClass`。`stdClass`允许您在不必定义一个扩展`stdClass`的离散类的情况下*即兴*定义属性：

```php
$obj = new stdClass();
```

1.  这个功能在 PHP 的许多不同地方使用。例如，当您使用**PHP 数据对象**（**PDO**）来进行数据库查询时，其中的一个获取模式是`PDO::FETCH_OBJ`。这种模式返回`stdClass`的实例，其中的属性代表数据库表列：

```php
$stmt = $connection->pdo->query($sql);
$row  = $stmt->fetch(PDO::FETCH_OBJ);
```

## 它是如何工作的...

取出前面代码片段中的`Test`类的例子，并将代码放入一个名为`Test.php`的文件中。创建另一个名为`chap_04_oop_defining_class_test.php`的文件。添加以下代码：

```php
require __DIR__ . '/Test.php';

$test = new Test();
echo $test->getTest();
echo PHP_EOL;

$test->setTest('ABC');
echo $test->getTest();
echo PHP_EOL;
```

输出将显示`$test`属性的初始值，然后通过调用`setTest()`修改的新值：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_01.jpg)

下一个例子让您在一个名为`NameAddress.php`的单个文件中定义两个类，`Name`和`Address`。您可以使用以下代码调用和使用这两个类：

```php
require __DIR__ . '/NameAddress.php';

$name = new Name();
$name->setName('TEST');
$addr = new Address();
$addr->setAddress('123 Main Street');

echo $name->getName() . ' lives at ' . $addr->getAddress();
```

### 注意

虽然 PHP 解释器没有生成错误，但通过定义多个类，文件的逻辑纯度受到了损害。此外，文件名与类名不匹配，这可能会影响自动加载的能力。

接下来的例子的输出如下所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_02.jpg)

步骤 3 还展示了一个文件中的两个类定义。然而，在这种情况下，目标是演示 PHP 中的类名是不区分大小写的。将代码放入一个名为`TwoClass.php`的文件中。当您尝试包含该文件时，将生成一个错误：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_03.jpg)

为了演示直接使用`stdClass`，创建一个实例，为属性赋值，并使用`var_dump()`来显示结果。要查看`stdClass`在内部的使用方式，使用`var_dump()`来显示`PDO`查询的结果，其中获取模式设置为`FETCH_OBJ`。

输入以下代码：

```php
$obj = new stdClass();
$obj->test = 'TEST';
echo $obj->test;
echo PHP_EOL;

include (__DIR__ . '/../Application/Database/Connection.php');
$connection = new Application\Database\Connection(
  include __DIR__ . DB_CONFIG_FILE);

$sql  = 'SELECT * FROM iso_country_codes';
$stmt = $connection->pdo->query($sql);
$row  = $stmt->fetch(PDO::FETCH_OBJ);
var_dump($row);
```

以下是输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_04.jpg)

## 参见...

有关 PHP 7.1 中关键字`$this`的改进的更多信息，请参阅[`wiki.php.net/rfc/this_var`](https://wiki.php.net/rfc/this_var)。

# 扩展类

开发人员使用 OOP 的主要原因之一是因为它能够重用现有的代码，同时又能够添加或覆盖功能。在 PHP 中，关键字`extends`用于在类之间建立父/子关系。

## 如何做...

1.  在`child`类中，使用关键字`extends`来建立继承关系。在接下来的例子中，`Customer`类扩展了`Base`类。`Customer`的任何实例都将继承可见的方法和属性，这里是`$id`，`getId()`和`setId()`：

```php
class Base
{
  protected $id;
  public function getId()
  {
    return $this->id;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
}

class Customer extends Base
{
  protected $name;
  public function getName()
  {
    return $this->name;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
}
```

1.  您可以通过将其标记为`abstract`来强制任何使用您的类的开发人员定义一个方法。在这个例子中，`Base`类将`validate()`方法定义为`abstract`。它必须是抽象的原因是因为从父类`Base`的角度来确定子类如何被验证是不可能的：

```php
abstract class Base
{
  protected $id;
  public function getId()
  {
    return $this->id;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function validate();
}
```

### 注意

如果一个类包含一个**抽象方法**，那么这个类本身必须声明为`abstract`。

1.  PHP 只支持单一继承线。下一个例子展示了一个名为`Member`的类，它从`Customer`继承。`Customer`又从`Base`继承：

```php
class Base
{
  protected $id;
  public function getId()
  {
    return $this->id;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
}

class Customer extends Base
{
  protected $name;
  public function getName()
  {
    return $this->name;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
}

class Member extends Customer
{
  protected $membership;
  public function getMembership()
  {
    return $this->membership;
  }
  public function setMembership($memberId)
  {
    $this->membership = $memberId;
  }
}
```

1.  为了满足类型提示，目标类的任何子类都可以使用。下面的代码片段中显示的`test()`函数需要`Base`类的一个实例作为参数。继承线中的任何类都可以被接受为参数。传递给`test()`的任何其他内容都会引发`TypeError`：

```php
function test(Base $object)
{
  return $object->getId();
}
```

## 它是如何工作的...

在第一个要点中，定义了一个`Base`类和一个`Customer`类。为了演示，将这两个类定义放入一个名为`chap_04_oop_extends.php`的单个文件中，并添加以下代码：

```php
$customer = new Customer();
$customer->setId(100);
$customer->setName('Fred');
var_dump($customer);
```

请注意，`$id`属性和`getId()`和`setId()`方法从父类`Base`继承到子类`Customer`：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_06.jpg)

为了说明`abstract`方法的使用，想象一下你希望为任何扩展`Base`的类添加某种验证能力。问题是不知道在继承类中可能会验证什么。唯一确定的是你必须有验证能力。

使用前面解释中提到的相同的`Base`类，并添加一个新的方法`validate()`。将该方法标记为`abstract`，不定义任何代码。注意当子`Customer`类扩展`Base`时会发生什么。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_07.jpg)

如果你将`Base`类标记为`abstract`，但未在子类中定义`validate()`方法，将生成*相同的错误*。最后，继续在子`Customer`类中实现`validate()`方法：

```php
class Customer extends Base
{
  protected $name;
  public function getName()
  {
    return $this->name;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function validate()
  {
    $valid = 0;
    $count = count(get_object_vars($this));
    if (!empty($this->id) &&is_int($this->id)) $valid++;
    if (!empty($this->name) 
    &&preg_match('/[a-z0-9 ]/i', $this->name)) $valid++;
    return ($valid == $count);
  }
}
```

然后你可以添加以下过程代码来测试结果：

```php
$customer = new Customer();

$customer->setId(100);
$customer->setName('Fred');
echo "Customer [id]: {$customer->getName()}" .
     . "[{$customer->getId()}]\n";
echo ($customer->validate()) ? 'VALID' : 'NOT VALID';
$customer->setId('XXX');
$customer->setName('$%£&*()');
echo "Customer [id]: {$customer->getName()}"
  . "[{$customer->getId()}]\n";
echo ($customer->validate()) ? 'VALID' : 'NOT VALID';
```

这是输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_08.jpg)

展示单行继承，将一个新的`Member`类添加到前面步骤 1 中显示的`Base`和`Customer`的第一个示例中：

```php
class Member extends Customer
{
  protected $membership;
  public function getMembership()
  {
    return $this->membership;
  }
  public function setMembership($memberId)
  {
    $this->membership = $memberId;
  }
}
```

创建一个`Member`的实例，并注意在下面的代码中，所有属性和方法都可以从每个继承的类中使用，即使不是直接继承的。

```php
$member = new Member();
$member->setId(100);
$member->setName('Fred');
$member->setMembership('A299F322');
var_dump($member);
```

这是输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_09.jpg)

现在定义一个名为`test()`的函数，该函数以`Base`的实例作为参数：

```php
function test(Base $object)
{
  return $object->getId();
}
```

注意`Base`，`Customer`和`Member`的实例都是可以接受的参数：

```php
$base = new Base();
$base->setId(100);

$customer = new Customer();
$customer->setId(101);

$member = new Member();
$member->setId(102);

// all 3 classes work in test()
echo test($base)     . PHP_EOL;
echo test($customer) . PHP_EOL;
echo test($member)   . PHP_EOL;
```

这是输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_10.jpg)

然而，如果你尝试使用不在继承线上的对象实例运行`test()`，将抛出一个`TypeError`：

```php
class Orphan
{
  protected $id;
  public function getId()
  {
    return $this->id;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
}
try {
    $orphan = new Orphan();
    $orphan->setId(103);
    echo test($orphan) . PHP_EOL;
} catch (TypeError $e) {
    echo 'Does not work!' . PHP_EOL;
    echo $e->getMessage();
}
```

我们可以在下面的图片中观察到这一点：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_11.jpg)

# 使用静态属性和方法

PHP 允许你访问属性或方法，而不必创建类的实例。用于此目的的关键字是**static**。

## 如何做...

1.  最简单的方法是在声明普通属性或方法时，在声明可见级别后添加`static`关键字。使用`self`关键字在内部引用属性：

```php
class Test
{
  public static $test = 'TEST';
  public static function getTest()
  {
    return self::$test;
  }
}
```

1.  `self`关键字将会提前绑定，这会在访问子类中的静态信息时造成问题。如果你绝对需要访问子类的信息，使用`static`关键字代替`self`。这个过程被称为**后期静态绑定**。

1.  在下面的示例中，如果你输出`Child::getEarlyTest()`，输出将是**TEST**。另一方面，如果你运行`Child::getLateTest()`，输出将是**CHILD**。原因是当使用`self`时，PHP 将绑定到*最早*的定义，而对于`static`关键字，将使用*最新*的绑定：

```php
class Test2
{
  public static $test = 'TEST2';
  public static function getEarlyTest()
  {
    return self::$test;
  }
  public static function getLateTest()
  {
    return static::$test;
  }
}

class Child extends Test2
{
  public static $test = 'CHILD';
}
```

1.  在许多情况下，**工厂**设计模式与静态方法一起使用，以根据不同的参数生成对象的实例。在这个例子中，定义了一个静态方法`factory()`，它返回一个 PDO 连接：

```php
public static function factory(
  $driver,$dbname,$host,$user,$pwd,array $options = [])
  {
    $dsn = sprintf('%s:dbname=%s;host=%s', 
    $driver, $dbname, $host);
    try {
        return new PDO($dsn, $user, $pwd, $options);
    } catch (PDOException $e) {
        error_log($e->getMessage);
    }
  }
```

## 它是如何工作的...

你可以使用**类解析运算符**"`::"`来引用静态属性和方法。给定之前显示的`Test`类，如果你运行这段代码：

```php
echo Test::$test;
echo PHP_EOL;
echo Test::getTest();
echo PHP_EOL;
```

你会看到这个输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_13.jpg)

为了说明后期静态绑定，基于之前显示的`Test2`和`Child`类，尝试这段代码：

```php
echo Test2::$test;
echo Child::$test;
echo Child::getEarlyTest();
echo Child::getLateTest();
```

输出说明了`self`和`static`之间的区别。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_14.jpg)

最后，为了测试之前显示的`factory()`方法，将代码保存到`Application\Database\Connection`类中，保存在`Application\Database`文件夹中的`Connection.php`文件中。然后你可以尝试这样做：

```php
include __DIR__ . '/../Application/Database/Connection.php';
use Application\Database\Connection;
$connection = Connection::factory(
'mysql', 'php7cookbook', 'localhost', 'test', 'password');
$stmt = $connection->query('SELECT name FROM iso_country_codes');
while ($country = $stmt->fetch(PDO::FETCH_COLUMN)) 
echo $country . '';
```

你将看到从示例数据库中提取的国家列表：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_15.jpg)

## 另请参阅

有关后期静态绑定的更多信息，请参阅 PHP 文档中的解释：

[`php.net/manual/en/language.oop5.late-static-bindings.php`](http://php.net/manual/en/language.oop5.late-static-bindings.php)

# 使用命名空间

对于高级 PHP 开发来说，关键的一点是使用命名空间。任意定义的命名空间成为类名的前缀，从而避免了意外类重复的问题，并允许您在开发中拥有非凡的自由度。另一个使用命名空间的好处是，假设它与目录结构匹配，它可以促进自动加载，如第一章中所讨论的*构建基础*。

## 操作步骤...

1.  要在命名空间中定义一个类，只需在代码文件顶部添加关键字`namespace`：

```php
namespace Application\Entity;
```

### 注意

**最佳实践**

与每个文件只有一个类的建议类似，您应该每个文件只有一个命名空间。

1.  在关键字`namespace`之前应该只有一个注释和/或关键字`declare`。

```php
<?php
declare(strict_types=1);
namespace Application\Entity;
/**
 * Address
 *
 */
class Address
{
  // some code
}
```

1.  在 PHP 5 中，如果您需要访问外部命名空间中的类，可以添加一个只包含命名空间的`use`语句。然后，您需要使用命名空间的最后一个组件作为前缀来引用该命名空间内的任何类：

```php
use Application\Entity;
$name = new Entity\Name();
$addr = new Entity\Address();
$prof = new Entity\Profile();
```

1.  或者，您可以明确指定所有三个类：

```php
use Application\Entity\Name;
use Application\Entity\Address;
use Application\Entity\Profile;
$name = new Name();
$addr = new Address();
$prof = new Profile();
```

1.  PHP 7 引入了一种称为**group use**的语法改进，大大提高了代码的可读性：

```php
use Application\Entity\ {
  Name,
  Address,
  Profile
};
$name = new Name();
$addr = new Address();
$prof = new Profile();
```

1.  如第一章中所述，*构建基础*，命名空间是**自动加载**过程的一个组成部分。此示例显示了一个演示自动加载程序，它会回显传递的参数，然后尝试根据命名空间和类名包含一个文件。这假设目录结构与命名空间匹配：

```php
function __autoload($class)
{
  echo "Argument Passed to Autoloader = $class\n";
  include __DIR__ . '/../' . str_replace('\\', DIRECTORY_SEPARATOR, $class) . '.php';
}
```

## 工作原理...

为了举例说明，定义一个与`Application\*`命名空间匹配的目录结构。创建一个基础文件夹`Application`，以及一个子文件夹`Entity`。您还可以根据需要包含任何其他章节中使用的子文件夹，比如`Database`和`Generic`：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_16.jpg)

接下来，在`Application/Entity`文件夹下分别创建三个`entity`类，每个类都在自己的文件中：`Name.php`，`Address.php`和`Profile.php`。这里只展示`Application\Entity\Name`。`Application\Entity\Address`和`Application\Entity\Profile`将是相同的，只是`Address`有一个`$address`属性，而`Profile`有一个`$profile`属性，每个属性都有适当的`get`和`set`方法：

```php
<?php
declare(strict_types=1);
namespace Application\Entity;
/**
 * Name
 *
 */
class Name
{

  protected $name = '';

  /**
   * This method returns the current value of $name
   *
   * @return string $name
   */
  public function getName() : string
  {
    return $this->name;
  }

  /**
   * This method sets the value of $name
   *
   * @param string $name
   * @return name $this
   */
  public function setName(string $name)
  {
    $this->name = $name;
    return $this;
  }
}
```

然后，您可以使用第一章中定义的自动加载程序，或者使用之前提到的简单自动加载程序。将设置自动加载的命令放在一个文件`chap_04_oop_namespace_example_1.php`中。在此文件中，您可以指定一个`use`语句，只引用命名空间，而不是类名。通过使用命名空间的最后一部分`Entity`作为类名的前缀，创建三个实体类`Name`，`Address`和`Profile`的实例：

```php
use Application\Entity;
$name = new Entity\Name();
$addr = new Entity\Address();
$prof = new Entity\Profile();

var_dump($name);
var_dump($addr);
var_dump($prof);
```

输出如下：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_17.jpg)

接下来，使用**另存为**将文件复制到一个名为`chap_04_oop_namespace_example_2.php`的新文件中。将`use`语句更改为以下内容：

```php
use Application\Entity\Name;
use Application\Entity\Address;
use Application\Entity\Profile;
```

现在，您可以仅使用类名创建类实例：

```php
$name = new Name();
$addr = new Address();
$prof = new Profile();
```

当您运行此脚本时，输出如下：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_18.jpg)

最后，再次使用**另存为**创建一个新文件`chap_04_oop_namespace_example_3.php`。您现在可以测试 PHP 7 中引入的**group use**功能：

```php
use Application\Entity\ {
  Name,
  Address,
  Profile
};
$name = new Name();
$addr = new Address();
$prof = new Profile();
```

同样，当您运行此代码块时，输出将与前面的输出相同：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_19.jpg)

# 定义可见性

欺骗地，*可见性*一词与应用程序安全无关！相反，它只是一种控制代码使用的机制。它可以用来引导经验不足的开发人员远离应该仅在类定义内部调用的方法的*public*使用。

## 如何做...

1.  通过在任何属性或方法定义的前面添加`public`、`protected`或`private`关键字来指示可见性级别。您可以将属性标记为`protected`或`private`，以强制仅通过公共“getter”和“setter”访问。

1.  在此示例中，定义了一个带有受保护属性`$id`的`Base`类。为了访问此属性，定义了“getId（）”和“setId（）”公共方法。受保护方法“generateRandId（）”可以在内部使用，并且在`Customer`子类中继承。此方法不能直接在类定义之外调用。请注意使用新的 PHP 7“random_bytes（）”函数创建随机 ID。

```php
class Base
{
  protected $id;
  private $key = 12345;
  public function getId()
  {
    return $this->id;
  }
  public function setId()
  {
    $this->id = $this->generateRandId();
  }
  protected function generateRandId()
  {
    return unpack('H*', random_bytes(8))[1];
  }
}

class Customer extends Base
{
  protected $name;
  public function getName()
  {
    return $this->name;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
}
```

### 注意

**最佳实践**

将属性标记为`protected`，并定义“publicgetNameOfProperty（）”和“setNameOfProperty（）”方法来控制对属性的访问。这些方法被称为“getter”和“setter”。

1.  将属性或方法标记为`private`以防止其被继承或从类定义之外可见。这是创建类作为**单例**的好方法。

1.  下一个代码示例显示了一个名为`Registry`的类，其中只能有一个实例。因为构造函数标记为`private`，所以唯一可以创建实例的方法是通过静态方法“getInstance（）”：

```php
class Registry
{
  protected static $instance = NULL;
  protected $registry = array();
  private function __construct()
  {
    // nobody can create an instance of this class
  }
  public static function getInstance()
  {
    if (!self::$instance) {
      self::$instance = new self();
    }
    return self::$instance;
  }
  public function __get($key)
  {
    return $this->registry[$key] ?? NULL;
  }
  public function __set($key, $value)
  {
    $this->registry[$key] = $value;
  }
}
```

### 注意

您可以将方法标记为`final`以防止其被覆盖。将类标记为`final`以防止其被扩展。

1.  通常，类常量被认为具有`public`的可见性级别。从 PHP 7.1 开始，您可以将类常量声明为`protected`或`private`。在以下示例中，`TEST_WHOLE_WORLD`类常量的行为与 PHP 5 中完全相同。接下来的两个常量，`TEST_INHERITED`和`TEST_LOCAL`，遵循与任何`protected`或`private`属性或方法相同的规则：

```php
class Test
{

  public const TEST_WHOLE_WORLD  = 'visible.everywhere';

  // NOTE: only works in PHP 7.1 and above
  protected const TEST_INHERITED = 'visible.in.child.classes';

  // NOTE: only works in PHP 7.1 and above
  private const TEST_LOCAL= 'local.to.class.Test.only';

  public static function getTestInherited()
  {
    return static::TEST_INHERITED;
  }

  public static function getTestLocal()
  {
    return static::TEST_LOCAL;
  }

}
```

## 它是如何工作的...

创建一个名为`chap_04_basic_visibility.php`的文件，并定义两个类：`Base`和`Customer`。接下来，编写代码以创建每个实例：

```php
$base     = new Base();
$customer = new Customer();
```

请注意，以下代码可以正常工作，并且实际上被认为是最佳实践：

```php
$customer->setId();
$customer->setName('Test');
echo 'Welcome ' . $customer->getName() . PHP_EOL;
echo 'Your new ID number is: ' . $customer->getId() . PHP_EOL;
```

尽管`$id`是`protected`，但相应的方法“getId（）”和“setId（）”都是`public`，因此可以从类定义外部访问。以下是输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_20.jpg)

然而，以下代码行将无法工作，因为`private`和`protected`属性无法从类定义之外访问：

```php
echo 'Key (does not work): ' . $base->key;
echo 'Key (does not work): ' . $customer->key;
echo 'Name (does not work): ' . $customer->name;
echo 'Random ID (does not work): ' . $customer->generateRandId();
```

以下输出显示了预期的错误：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_21.jpg)

## 另请参阅

有关“getter”和“setter”的更多信息，请参见本章中标题为“使用 getter 和 setter”的配方。有关 PHP 7.1 类常量可见性设置的更多信息，请参见[`wiki.php.net/rfc/class_const_visibility`](https://wiki.php.net/rfc/class_const_visibility)。

# 使用接口

接口是系统架构师的有用工具，通常用于原型设计**应用程序编程接口**（**API**）。接口不包含实际代码，但可以包含方法的名称以及方法签名。

### 注意

所有在“接口”中标识的方法都具有`public`的可见性级别。

## 如何做...

1.  由接口标识的方法不能包含实际代码实现。但是，您可以指定方法参数的数据类型。

1.  在此示例中，`ConnectionAwareInterface`标识了一个方法“setConnection（）”，该方法需要一个`Connection`的实例作为参数：

```php
interface ConnectionAwareInterface
{
  public function setConnection(Connection $connection);
}
```

1.  要使用接口，请在定义类的开放行之后添加关键字`implements`。我们定义了两个类，`CountryList`和`CustomerList`，它们都需要通过`setConnection()`方法访问`Connection`类。为了识别这种依赖关系，这两个类都实现了`ConnectionAwareInterface`：

```php
class CountryList implements ConnectionAwareInterface
{
  protected $connection;
  public function setConnection(Connection $connection)
  {
    $this->connection = $connection;
  }
  public function list()
  {
    $list = [];
    $stmt = $this->connection->pdo->query(
      'SELECT iso3, name FROM iso_country_codes');
    while ($country = $stmt->fetch(PDO::FETCH_ASSOC)) {
      $list[$country['iso3']] =  $country['name'];
    }
    return $list;
  }

}
class CustomerList implements ConnectionAwareInterface
{
  protected $connection;
  public function setConnection(Connection $connection)
  {
    $this->connection = $connection;
  }
  public function list()
  {
    $list = [];
    $stmt = $this->connection->pdo->query(
      'SELECT id, name FROM customer');
    while ($customer = $stmt->fetch(PDO::FETCH_ASSOC)) {
      $list[$customer['id']] =  $customer['name'];
    }
    return $list;
  }

}
```

1.  接口可用于满足类型提示。以下类`ListFactory`包含一个`factory()`方法，该方法初始化任何实现`ConnectionAwareInterface`的类。接口是`setConnection()`方法被定义的保证。将类型提示设置为接口而不是特定类实例使`factory`方法更通用：

```php
namespace Application\Generic;

use PDO;
use Exception;
use Application\Database\Connection;
use Application\Database\ConnectionAwareInterface;

class ListFactory
{
  const ERROR_AWARE = 'Class must be Connection Aware';
  public static function factory(
    ConnectionAwareInterface $class, $dbParams)
  {
    if ($class instanceofConnectionAwareInterface) {
        $class->setConnection(new Connection($dbParams));
        return $class;
    } else {
        throw new Exception(self::ERROR_AWARE);
    }
    return FALSE;
  }
}
```

1.  如果一个类实现多个接口，如果方法签名不匹配，则会发生**命名冲突**。在这个例子中，有两个接口，`DateAware`和`TimeAware`。除了定义`setDate()`和`setTime()`方法之外，它们都定义了`setBoth()`。具有重复的方法名称不是问题，尽管这不被认为是最佳实践。问题在于方法签名不同：

```php
interface DateAware
{
  public function setDate($date);
  public function setBoth(DateTime $dateTime);
}

interface TimeAware
{
  public function setTime($time);
  public function setBoth($date, $time);
}

class DateTimeHandler implements DateAware, TimeAware
{
  protected $date;
  protected $time;
  public function setDate($date)
  {
    $this->date = $date;
  }
  public function setTime($time)
  {
    $this->time = $time;
  }
  public function setBoth(DateTime $dateTime)
  {
    $this->date = $date;
  }
}
```

1.  代码块的当前状态将生成致命错误（无法捕获！）。要解决问题，首选方法是从一个接口中删除`setBoth()`的定义。或者，您可以调整方法签名以匹配。

### 注意

**最佳实践**

不要定义具有重复或重叠方法定义的接口。

## 它是如何工作的...

在`Application/Database`文件夹中，创建一个文件`ConnectionAwareInterface.php`。插入前面步骤 2 中讨论的代码。

接下来，在`Application/Generic`文件夹中，创建两个文件，`CountryList.php`和`CustomerList.php`。插入步骤 3 中讨论的代码。

接下来，在与`Application`目录平行的目录中，创建一个源代码文件`chap_04_oop_simple_interfaces_example.php`，该文件初始化自动加载程序并包含数据库参数：

```php
<?php
define('DB_CONFIG_FILE', '/../config/db.config.php');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
$params = include __DIR__ . DB_CONFIG_FILE;
```

在这个例子中，假定数据库参数在由`DB_CONFIG_FILE`常量指示的数据库配置文件中。

现在，您可以使用`ListFactory::factory()`生成`CountryList`和`CustomerList`对象。请注意，如果这些类没有实现`ConnectionAwareInterface`，将会抛出错误：

```php
  $list = Application\Generic\ListFactory::factory(
    new Application\Generic\CountryList(), $params);
  foreach ($list->list() as $item) echo $item . '';
```

这是国家列表的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_22.jpg)

您还可以使用`factory`方法生成`CustomerList`对象并使用它：

```php
  $list = Application\Generic\ListFactory::factory(
    new Application\Generic\CustomerList(), $params);
  foreach ($list->list() as $item) echo $item . '';
```

这是`CustomerList`的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_23.jpg)

如果您想要检查实现多个接口但方法签名不同的情况发生了什么，请将步骤 4 中显示的代码输入到文件`chap_04_oop_interfaces_collisions.php`中。当您尝试运行该文件时，将生成错误，如下所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_24.jpg)

如果您在`TimeAware`接口中进行以下调整，将不会产生错误：

```php
interface TimeAware
{
  public function setTime($time);
  // this will cause a problem
  public function setBoth(DateTime $dateTime);
}
```

# 使用特征

如果您曾经进行过 C 编程，您可能熟悉宏。宏是预定义的代码块，在指定的行处*展开*。类似地，特征可以包含代码块，在 PHP 解释器指定的行处复制并粘贴到类中。

## 如何做...

1.  特征用关键字`trait`标识，可以包含属性和/或方法。在上一个示例中，当检查`CountryList`和`CustomerList`类时，您可能已经注意到代码的重复。在这个例子中，我们将重构这两个类，并将`list()`方法的功能移入`Trait`。请注意，`list()`方法在两个类中是相同的。

1.  特征在类之间存在代码重复的情况下使用。然而，请注意，使用传统的创建抽象类并扩展它的方法可能比使用特征具有某些优势。特征不能用于标识继承线，而抽象父类可以用于此目的。

1.  现在我们将`list()`复制到一个名为`ListTrait`的特征中：

```php
trait ListTrait
{
  public function list()
  {
    $list = [];
    $sql  = sprintf('SELECT %s, %s FROM %s', 
      $this->key, $this->value, $this->table);
    $stmt = $this->connection->pdo->query($sql);
    while ($item = $stmt->fetch(PDO::FETCH_ASSOC)) {
      $list[$item[$this->key]] = $item[$this->value];
    }
    return $list;
  }
}
```

1.  然后我们可以将`ListTrait`中的代码插入到一个新的类`CountryListUsingTrait`中，如下面的代码片段所示。现在可以从这个类中删除整个`list()`方法：

```php
class CountryListUsingTrait implements ConnectionAwareInterface
{

  use ListTrait;

  protected $connection;
  protected $key   = 'iso3';
  protected $value = 'name';
  protected $table = 'iso_country_codes';

  public function setConnection(Connection $connection)
  {
    $this->connection = $connection;
  }

}
```

### 注意

每当存在代码重复时，当您需要进行更改时，可能会出现潜在问题。您可能会发现自己需要进行太多的全局搜索和替换操作，或者剪切和粘贴代码，通常会导致灾难性的结果。特征是避免这种维护噩梦的好方法。

1.  特征受命名空间的影响。在第 1 步中所示的示例中，如果我们的新`CountryListUsingTrait`类放置在一个名为`Application\Generic`的命名空间中，我们还需要将`ListTrait`移动到该命名空间中：

```php
namespace Application\Generic;

use PDO;

trait ListTrait
{
  public function list()
  {
    // code as shown above
  }
}
```

1.  特征中的方法会覆盖继承的方法。

1.  在下面的示例中，您会注意到`setId()`方法的返回值在`Base`父类和`Test`特征之间不同。`Customer`类继承自`Base`，但也使用`Test`。在这种情况下，特征中定义的方法将覆盖`Base`父类中定义的方法：

```php
trait Test
{
  public function setId($id)
  {
    $obj = new stdClass();
    $obj->id = $id;
    $this->id = $obj;
  }
}

class Base
{
  protected $id;
  public function getId()
  {
    return $this->id;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
}

class Customer extends Base
{
  use Test;
  protected $name;
  public function getName()
  {
    return $this->name;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
}
```

### 注意

在 PHP 5 中，特征也可以覆盖属性。在 PHP 7 中，如果特征中的属性初始化值与父类中的不同，将生成致命错误。

1.  在类中直接定义使用特征的方法会覆盖特征中定义的重复方法。

1.  在这个例子中，`Test`特征定义了一个`$id`属性以及`getId()`方法和`setId()`。特征还定义了`setName()`，与`Customer`类中定义的相同方法冲突。在这种情况下，`Customer`中直接定义的`setName()`方法将覆盖特征中定义的`setName()`：

```php
trait Test
{
  protected $id;
  public function getId()
  {
    return $this->id;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function setName($name)
  {
    $obj = new stdClass();
    $obj->name = $name;
    $this->name = $obj;
  }
}

class Customer
{
  use Test;
  protected $name;
  public function getName()
  {
    return $this->name;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
}
```

1.  在使用多个特征时，使用`insteadof`关键字解决方法名称冲突。此外，使用`as`关键字为方法名称创建别名。

1.  在这个例子中，有两个特征，`IdTrait`和`NameTrait`。两个特征都定义了一个`setKey()`方法，但是以不同的方式表示键。`Test`类使用了这两个特征。请注意`insteadof`关键字，它允许我们区分冲突的方法。因此，当从`Test`类调用`setKey()`时，源将来自`NameTrait`。此外，`IdTrait`中的`setKey()`仍然可用，但是在别名`setKeyDate()`下：

```php
trait IdTrait
{
  protected $id;
  public $key;
  public function setId($id)
  {
    $this->id = $id;
  }
  public function setKey()
  {
    $this->key = date('YmdHis') 
    . sprintf('%04d', rand(0,9999));
  }
}

trait NameTrait
{
  protected $name;
  public $key;
  public function setName($name)
  {
    $this->name = $name;
  }
  public function setKey()
  {
    $this->key = unpack('H*', random_bytes(18))[1];
  }
}

class Test
{
  use IdTrait, NameTrait {
    NameTrait::setKeyinsteadofIdTrait;
    IdTrait::setKey as setKeyDate;
  }
}
```

## 它是如何工作的...

从第 1 步中，您了解到特征在存在代码重复的情况下使用。您需要评估是否可以简单地定义一个基类并扩展它，或者使用特征更好地满足您的目的。特征在逻辑上不相关的类中看到代码重复时特别有用。

为了说明特征方法如何覆盖继承的方法，请将第 7 步提到的代码块复制到一个单独的文件`chap_04_oop_traits_override_inherited.php`中。添加以下代码：

```php
$customer = new Customer();
$customer->setId(100);
$customer->setName('Fred');
var_dump($customer);
```

从输出中可以看到（如下所示），`$id`属性存储为`stdClass()`的实例，这是特征中定义的行为：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_28.jpg)

为了说明直接定义的类方法如何覆盖特征方法，请将第 9 步提到的代码块复制到一个单独的文件`chap_04_oop_trait_methods_do_not_override_class_methods.php`中。添加以下代码：

```php
$customer = new Customer();
$customer->setId(100);
$customer->setName('Fred');
var_dump($customer);
```

从下面的输出中可以看到，`$id`属性存储为整数，如`Customer`类中定义的那样，而特征将`$id`定义为`stdClass`的实例：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_29.jpg)

在第 10 步中，您学会了如何在使用多个特征时解决重复方法名称冲突。将步骤 11 中显示的代码块复制到一个单独的文件`chap_04_oop_trait_multiple.php`中。添加以下代码：

```php
$a = new Test();
$a->setId(100);
$a->setName('Fred');
$a->setKey();
var_dump($a);

$a->setKeyDate();
var_dump($a);
```

请注意，在下面的输出中，`setKey()`产生了从新的 PHP 7 函数`random_bytes()`（在`NameTrait`中定义）产生的输出，而`setKeyDate()`使用`date()`和`rand()`函数（在`IdTrait`中定义）产生一个密钥：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_30.jpg)

# 实现匿名类

PHP 7 引入了一个新特性，**匿名类**。就像匿名函数一样，匿名类可以作为表达式的一部分来定义，创建一个没有名称的类。匿名类用于需要*临时*创建并使用然后丢弃对象的情况。

## 如何做...

1.  与`stdClass`的替代方案是定义一个匿名类。

在定义中，您可以定义任何属性和方法（包括魔术方法）。在这个例子中，我们定义了一个具有两个属性和一个魔术方法`__construct()`的匿名类：

```php
$a = new class (123.45, 'TEST') {
  public $total = 0;
  public $test  = '';
  public function __construct($total, $test)
  {
    $this->total = $total;
    $this->test  = $test;
  }
};
```

1.  匿名类可以扩展任何类。

在这个例子中，一个匿名类扩展了`FilterIterator`，并覆盖了`__construct()`和`accept()`方法。作为参数，它接受了`ArrayIterator` `$b`，它代表了一个 10 到 100 的增量为 10 的数组。第二个参数作为输出的限制：

```php
$b = new ArrayIterator(range(10,100,10));
$f = new class ($b, 50) extends FilterIterator {
  public $limit = 0;
  public function __construct($iterator, $limit)
  {
    $this->limit = $limit;
    parent::__construct($iterator);
  }
  public function accept()
  {
    return ($this->current() <= $this->limit);
  }
};
```

1.  匿名类可以实现一个接口。

在这个例子中，一个匿名类用于生成 HTML 颜色代码图表。该类实现了内置的 PHP `Countable`接口。定义了一个`count()`方法，当这个类与需要`Countable`的方法或函数一起使用时调用：

```php
define('MAX_COLORS', 256 ** 3);

$d = new class () implements Countable {
  public $current = 0;
  public $maxRows = 16;
  public $maxCols = 64;
  public function cycle()
  {
    $row = '';
    $max = $this->maxRows * $this->maxCols;
    for ($x = 0; $x < $this->maxRows; $x++) {
      $row .= '<tr>';
      for ($y = 0; $y < $this->maxCols; $y++) {
        $row .= sprintf(
          '<td style="background-color: #%06X;"', 
          $this->current);
        $row .= sprintf(
          'title="#%06X">&nbsp;</td>', 
          $this->current);
        $this->current++;
        $this->current = ($this->current >MAX_COLORS) ? 0 
             : $this->current;
      }
      $row .= '</tr>';
    }
    return $row;
  }
  public function count()
  {
    return MAX_COLORS;
  }
};
```

1.  匿名类可以使用特征。

1.  这个最后的例子是对前面立即定义的修改。我们不是定义一个`Test`类，而是定义一个匿名类：

```php
$a = new class() {
  use IdTrait, NameTrait {
    NameTrait::setKeyinsteadofIdTrait;
    IdTrait::setKey as setKeyDate;
  }
};
```

## 它是如何工作的...

在匿名类中，您可以定义任何属性或方法。使用前面的例子，您可以定义一个接受构造函数参数的匿名类，并且可以访问属性。将步骤 2 中描述的代码放入一个名为`chap_04_oop_anonymous_class.php`的测试脚本中。添加这些`echo`语句：

```php
echo "\nAnonymous Class\n";
echo $a->total .PHP_EOL;
echo $a->test . PHP_EOL;
```

以下是匿名类的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_05.jpg)

为了使用`FilterIterator`，您*必须*覆盖`accept()`方法。在这个方法中，您定义了迭代的元素被包括在输出中的标准。现在继续并将步骤 4 中显示的代码添加到测试脚本中。然后您可以添加这些`echo`语句来测试匿名类：

```php
echo "\nAnonymous Class Extends FilterIterator\n";
foreach ($f as $item) echo $item . '';
echo PHP_EOL;
```

在这个例子中，建立了一个 50 的限制。原始的`ArrayIterator`包含一个值数组，从 10 到 100，增量为 10，如下面的输出所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_12.jpg)

要查看实现接口的匿名类，请考虑步骤 5 和 6 中显示的例子。将这段代码放入一个文件`chap_04_oop_anonymous_class_interfaces.php`中。

接下来，添加代码，让您可以通过 HTML 颜色图表进行分页：

```php
$d->current = $_GET['current'] ?? 0;
$d->current = hexdec($d->current);
$factor = ($d->maxRows * $d->maxCols);
$next = $d->current + $factor;
$prev = $d->current - $factor;
$next = ($next <MAX_COLORS) ? $next : MAX_COLORS - $factor;
$prev = ($prev>= 0) ? $prev : 0;
$next = sprintf('%06X', $next);
$prev = sprintf('%06X', $prev);
?>
```

最后，继续并将 HTML 颜色图表呈现为一个网页：

```php
<h1>Total Possible Color Combinations: <?= count($d); ?></h1>
<hr>
<table>
<?= $d->cycle(); ?>
</table>	
<a href="?current=<?= $prev ?>"><<PREV</a>
<a href="?current=<?= $next ?>">NEXT >></a>
```

请注意，您可以通过将匿名类的实例传递给`count()`函数（在`<H1>`标签之间显示）来利用`Countable`接口。以下是在浏览器窗口中显示的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_25.jpg)

最后，为了说明匿名类中使用特征，将前面一篇文章中提到的`chap_04_oop_trait_multiple.php`文件复制到一个新文件`chap_04_oop_trait_anonymous_class.php`中。删除`Test`类的定义，并用匿名类替换它：

```php
$a = new class() {
  use IdTrait, NameTrait {
    NameTrait::setKeyinsteadofIdTrait;
    IdTrait::setKey as setKeyDate;
  }
};
```

删除这一行：

```php
$a = new Test();
```

当您运行代码时，您将看到与前面截图中完全相同的输出，只是类引用将是匿名的：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_04_31.jpg)


# 第五章：与数据库交互

在本章中，我们将涵盖以下主题：

+   使用 PDO 连接到数据库

+   构建面向对象的 SQL 查询生成器

+   处理分页

+   定义实体以匹配数据库表

+   将实体类与 RDBMS 查询绑定

+   将辅助查找嵌入到查询结果中

+   实现 jQuery DataTables PHP 查找

# 介绍

在本章中，我们将介绍一系列利用**PHP 数据对象**（**PDO**）扩展的数据库连接配方。将解决常见的编程问题，如**结构化查询语言**（**SQL**）生成，分页和将对象与数据库表绑定。最后，我们将呈现处理嵌入式匿名函数形式的辅助查找的代码，并使用 jQuery DataTables 进行 AJAX 请求。

# 使用 PDO 连接到数据库

**PDO**是一个高性能且积极维护的数据库扩展，具有与特定供应商扩展不同的独特优势。它具有一个通用的**应用程序编程接口**（**API**），与几乎十几种不同的**关系数据库管理系统**（**RDBMS**）兼容。学习如何使用此扩展将节省您大量时间，因为您无需尝试掌握等效的各个特定供应商数据库扩展的命令子集。

PDO 分为四个主要类，如下表所示：

| 类 | 功能 |
| --- | --- |
| `PDO` | 维护与数据库的实际连接，并处理低级功能，如事务支持 |
| `PDOStatement` | 处理结果 |
| `PDOException` | 特定于数据库的异常 |
| `PDODriver` | 与实际特定供应商数据库通信 |

## 如何做...

1.  通过创建`PDO`实例建立数据库连接。

1.  您需要构建一个**数据源名称**（**DSN**）。DSN 中包含的信息根据使用的数据库驱动程序而变化。例如，这是一个用于连接到**MySQL**数据库的 DSN：

```php
$params = [
  'host' => 'localhost',
  'user' => 'test',
  'pwd'  => 'password',
  'db'   => 'php7cookbook'
];

try {
  $dsn  = sprintf(**'mysql:host=%s;dbname=%s',**
 **$params['host'], $params['db']);**
  $pdo  = new PDO($dsn, $params['user'], $params['pwd']);
} catch (PDOException $e) {
  echo $e->getMessage();
} catch (Throwable $e) {
  echo $e->getMessage();
}
```

1.  另一方面，**SQlite**，一个更简单的扩展，只需要以下命令：

```php
$params = [
  'db'   => __DIR__ . '/../data/db/php7cookbook.db.sqlite'
];
$dsn  = sprintf('sqlite:' . $params['db']);
```

1.  另一方面，**PostgreSQL**直接在 DSN 中包括用户名和密码：

```php
$params = [
  'host' => 'localhost',
  'user' => 'test',
  'pwd'  => 'password',
  'db'   => 'php7cookbook'
];
$dsn  = sprintf(**'pgsql:host=%s;dbname=%s;user=%s;password=%s',** 
               $params['host'], 
               $params['db'],
               $params['user'],
               $params['pwd']);
```

1.  DSN 还可以包括特定于服务器的指令，例如`unix_socket`，如下例所示：

```php
$params = [
  'host' => 'localhost',
  'user' => 'test',
  'pwd'  => 'password',
  'db'   => 'php7cookbook',
  'sock' => '/var/run/mysqld/mysqld.sock'
];

try {
  $dsn  = sprintf('mysql:host=%s;dbname=%s;**unix_socket=%s',** 
                  $params['host'], $params['db'], $params['sock']);
  $opts = [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION];
  $pdo  = new PDO($dsn, $params['user'], $params['pwd'], $opts);
} catch (PDOException $e) {
  echo $e->getMessage();
} catch (Throwable $e) {
  echo $e->getMessage();
}
```

### 注意

**最佳实践**

将创建 PDO 实例的语句包装在`try {} catch {}`块中。在发生故障时，捕获`PDOException`以获取特定于数据库的信息。捕获`Throwable`以处理错误或任何其他异常。将 PDO 错误模式设置为`PDO::ERRMODE_EXCEPTION`以获得最佳结果。有关错误模式的更多详细信息，请参见第 8 步。

在 PHP 5 中，如果无法构造 PDO 对象（例如，使用无效参数），则实例将被赋予`NULL`值。在 PHP 7 中，会抛出一个`Exception`。如果将 PDO 对象的构造包装在`try {} catch {}`块中，并且将`PDO::ATTR_ERRMODE`设置为`PDO::ERRMODE_EXCEPTION`，则可以捕获并记录此类错误，而无需测试`NULL`。

1.  使用`PDO::query()`发送 SQL 命令。返回一个`PDOStatement`实例，您可以针对其获取结果。在此示例中，我们正在查找按 ID 排序的前 20 个客户：

```php
$stmt = $pdo->query(
'SELECT * FROM customer ORDER BY id LIMIT 20');
```

### 注意

PDO 还提供了一个方便的方法`PDO::exec()`，它不返回结果迭代，只返回受影响的行数。此方法最适用于诸如`ALTER TABLE`，`DROP TABLE`等管理操作。

1.  迭代`PDOStatement`实例以处理结果。将**获取模式**设置为`PDO::FETCH_NUM`或`PDO::FETCH_ASSOC`，以返回以数字或关联数组形式的结果。在此示例中，我们使用`while()`循环处理结果。当获取到最后一个结果时，结果为布尔值`FALSE`，结束循环：

```php
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
  printf('%4d | %20s | %5s' . PHP_EOL, $row['id'], 
  $row['name'], $row['level']);
}
```

### 注意

PDO 获取操作涉及定义迭代方向（即向前或向后）的**游标**。`PDOStatement::fetch()`的第二个参数可以是`PDO::FETCH_ORI_*`常量中的任何一个。游标方向包括 prior、first、last、absolute 和 relative。默认游标方向是`PDO::FETCH_ORI_NEXT`。

1.  将获取模式设置为`PDO::FETCH_OBJ`以将结果作为`stdClass`实例返回。在这里，您会注意到`while()`循环利用了获取模式`PDO::FETCH_OBJ`。请注意，`printf()`语句引用了对象属性，与前面的示例相反，前者引用了数组元素。

```php
while ($row = $stmt->fetch(PDO::FETCH_OBJ)) {
  printf('%4d | %20s | %5s' . PHP_EOL, 
 **$row->id, $row->name, $row->level);**
}
```

1.  如果要在处理查询时创建特定类的实例，请将获取模式设置为`PDO::FETCH_CLASS`。您还必须有类定义可用，并且`PDO::query()`应该设置类名。如下面的代码片段中所示，我们定义了一个名为`Customer`的类，具有公共属性`$id`、`$name`和`$level`。属性需要是`public`，以使获取注入正常工作：

```php
class Customer
{
  public $id;
  public $name;
  public $level;
}

$stmt = $pdo->query($sql, PDO::FETCH_CLASS, 'Customer');
```

1.  在获取对象时，与步骤 5 中显示的技术相比，更简单的替代方法是使用`PDOStatement::fetchObject()`：

```php
while ($row = $stmt->**fetchObject('Customer')**) {
  printf('%4d | %20s | %5s' . PHP_EOL, 
  $row->id, $row->name, $row->level);
}
```

1.  您还可以使用`PDO::FETCH_INTO`，它本质上与`PDO::FETCH_CLASS`相同，但您需要一个活动对象实例，而不是一个类引用。通过循环的每次迭代，都会使用当前信息集重新填充相同的对象实例。此示例假定与步骤 5 中相同的类`Customer`，以及与步骤 1 中定义的相同的数据库参数和 PDO 连接：

```php
$cust = new Customer();
while ($stmt->fetch(**PDO::FETCH_INTO**)) {
  printf('%4d | %20s | %5s' . PHP_EOL, 
 **$cust**->id, **$cust**->name, **$cust**->level);
}
```

1.  如果您没有指定错误模式，默认的 PDO 错误模式是`PDO::ERRMODE_SILENT`。您可以使用`PDO::ATTR_ERRMODE`键设置错误模式，以及`PDO::ERRMODE_WARNING`或`PDO::ERRMODE_EXCEPTION`值。错误模式可以作为关联数组的第四个参数指定给 PDO 构造函数。或者，您可以在现有实例上使用`PDO::setAttribute()`。

1.  假设您有以下 DSN 和 SQL（在您开始认为这是一种新形式的 SQL 之前，请放心：这个 SQL 语句不起作用！）：

```php
$params = [
  'host' => 'localhost',
  'user' => 'test',
  'pwd'  => 'password',
  'db'   => 'php7cookbook'
];
$dsn  = sprintf('mysql:host=%s;dbname=%s', $params['host'], $params['db']);
$sql  = 'THIS SQL STATEMENT WILL NOT WORK';
```

1.  然后，如果您使用默认错误模式制定 PDO 连接，出现问题的唯一线索是，`PDO::query()`将返回一个布尔值`FALSE`，而不是生成`PDOStatement`实例：

```php
$pdo1  = new PDO($dsn, $params['user'], $params['pwd']);
$stmt = $pdo1->query($sql);
$row = ($stmt) ? $stmt->fetch(PDO::FETCH_ASSOC) : 'No Good';
```

1.  下一个示例显示了使用构造函数方法将错误模式设置为`WARNING`：

```php
$pdo2 = new PDO(
  $dsn, 
  $params['user'], 
  $params['pwd'], 
  [PDO::ATTR_ERRMODE => PDO::ERRMODE_WARNING]);
```

1.  如果您需要完全分离准备和执行阶段，请使用`PDO::prepare()`和`PDOStatement::execute()`。然后将语句发送到数据库服务器进行预编译。然后可以根据需要执行语句，很可能是在循环中。

1.  `PDO::prepare()`的第一个参数可以是带有占位符的 SQL 语句，而不是实际值。然后可以向`PDOStatement::execute()`提供值数组。PDO 自动提供数据库引用，有助于防止**SQL 注入**。

### 注意

**最佳实践**

任何应用程序中，如果外部输入（即来自表单提交）与 SQL 语句结合在一起，都会受到 SQL 注入攻击的影响。所有外部输入必须首先经过适当的过滤、验证和其他清理。不要直接将外部输入放入 SQL 语句中。而是使用占位符，并在执行阶段提供实际（经过清理的）值。

1.  要以相反的顺序迭代结果，可以更改**可滚动游标**的方向。或者，更简单地，将`ORDER BY`从`ASC`更改为`DESC`。以下代码行设置了一个请求可滚动游标的`PDOStatement`对象：

```php
$dsn  = sprintf('pgsql:charset=UTF8;host=%s;dbname=%s', $params['host'], $params['db']);
$opts = [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]; 
$pdo  = new PDO($dsn, $params['user'], $params['pwd'], $opts);
$sql  = 'SELECT * FROM customer '
    . 'WHERE balance > :min AND balance < :max '
    . 'ORDER BY id LIMIT 20';
$stmt = $pdo->prepare($sql, **[PDO::ATTR_CURSOR  => PDO::CURSOR_SCROLL]**);
```

1.  在执行获取操作期间，您还需要指定游标指令。此示例获取结果集中的最后一行，然后向后滚动：

```php
$stmt->execute(['min' => $min, 'max' => $max]);
$row = $stmt->fetch(PDO::FETCH_ASSOC, **PDO::FETCH_ORI_LAST**);
do {
  printf('%4d | %20s | %5s | %8.2f' . PHP_EOL, 
       $row['id'], 
       $row['name'], 
       $row['level'], 
       $row['balance']);
} while ($row = $stmt->fetch(PDO::FETCH_ASSOC, **PDO::FETCH_ORI_PRIOR**));
```

1.  MySQL 和 SQLite 都不支持可滚动的游标！要实现相同的结果，请尝试对上述代码进行以下修改：

```php
$dsn  = sprintf('mysql:charset=UTF8;host=%s;dbname=%s', $params['host'], $params['db']);
$opts = [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]; 
$pdo  = new PDO($dsn, $params['user'], $params['pwd'], $opts);
$sql  = 'SELECT * FROM customer '
    . 'WHERE balance > :min AND balance < :max '
    . 'ORDER BY id **DESC** 
       . 'LIMIT 20';
$stmt = $pdo->prepare($sql);
while ($row = $stmt->fetch(PDO::FETCH_ASSOC));
printf('%4d | %20s | %5s | %8.2f' . PHP_EOL, 
       $row['id'], 
       $row['name'], 
       $row['level'], 
       $row['balance']);
} 
```

1.  PDO 提供了对事务的支持。借用第 9 步的代码，我们可以将`INSERT`系列命令包装到一个事务块中：

```php
try {
    $pdo->beginTransaction();
    $sql  = "INSERT INTO customer ('" 
    . implode("','", $fields) . "') VALUES (**?,?,?,?,?,?**)";
    $stmt = $pdo->prepare($sql);
    foreach ($data as $row) $stmt->execute($row);
    $pdo->commit();
} catch (PDOException $e) {
    error_log($e->getMessage());
    $pdo->rollBack();
}
```

1.  最后，为了保持一切模块化和可重用，我们可以将 PDO 连接封装到一个单独的类`Application\Database\Connection`中。在这里，我们通过构造函数建立连接。另外，还有一个静态的`factory()`方法，让我们生成一系列 PDO 实例：

```php
namespace Application\Database;
use Exception;
use PDO;
class Connection
{
    const ERROR_UNABLE = 'ERROR: no database connection';
    public $pdo;
    public function __construct(array $config)
    {
        if (!isset($config['driver'])) {
            $message = __METHOD__ . ' : ' 
            . self::ERROR_UNABLE . PHP_EOL;
            throw new Exception($message);
        }
        $dsn = $this->makeDsn($config);        
        try {
            $this->pdo = new PDO(
                $dsn, 
                $config['user'], 
                $config['password'], 
                [PDO::ATTR_ERRMODE => $config['errmode']]);
            return TRUE;
        } catch (PDOException $e) {
            error_log($e->getMessage());
            return FALSE;
        }
    }

    public static function factory(
      $driver, $dbname, $host, $user, 
      $pwd, array $options = array())
    {
        $dsn = $this->makeDsn($config);

        try {
            return new PDO($dsn, $user, $pwd, $options);
        } catch (PDOException $e) {
            error_log($e->getMessage);
        }
    }
```

1.  这个`Connection`类的一个重要组成部分是一个通用方法，用于构造 DSN。我们需要的一切就是将`PDODriver`作为前缀，后面跟着“`:`”。之后，我们只需从配置数组中追加键值对。每个键值对之间用分号分隔。我们还需要使用`substr()`来去掉末尾的分号，为此目的使用了负限制：

```php
  public function makeDsn($config)
  {
    $dsn = $config['driver'] . ':';
    unset($config['driver']);
    foreach ($config as $key => $value) {
      $dsn .= $key . '=' . $value . ';';
    }
    return substr($dsn, 0, -1);
  }
}
```

## 它是如何工作...

首先，您可以将第 1 步中的初始连接代码复制到一个名为`chap_05_pdo_connect_mysql.php`的文件中。为了说明的目的，我们假设您已经创建了一个名为`php7cookbook`的 MySQL 数据库，用户名为 cook，密码为 book。接下来，我们使用`PDO::query()`方法向数据库发送一个简单的 SQL 语句。最后，我们使用生成的语句对象以关联数组的形式获取结果。不要忘记将您的代码放在`try {} catch {}`块中：

```php
<?php
$params = [
  'host' => 'localhost',
  'user' => 'test',
  'pwd'  => 'password',
  'db'   => 'php7cookbook'
];
try {
  $dsn  = sprintf('mysql:charset=UTF8;host=%s;dbname=%s',
    $params['host'], $params['db']);
  $pdo  = new PDO($dsn, $params['user'], $params['pwd']);
  $stmt = $pdo->query(
    'SELECT * FROM customer ORDER BY id LIMIT 20');
  printf('%4s | %20s | %5s | %7s' . PHP_EOL, 
    'ID', 'NAME', 'LEVEL', 'BALANCE');
  printf('%4s | %20s | %5s | %7s' . PHP_EOL, 
    '----', str_repeat('-', 20), '-----', '-------');
  while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    printf('%4d | %20s | %5s | %7.2f' . PHP_EOL, 
    $row['id'], $row['name'], $row['level'], $row['balance']);
  }
} catch (PDOException $e) {
  error_log($e->getMessage());
} catch (Throwable $e) {
  error_log($e->getMessage());
}
```

以下是生成的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_05_01.jpg)

将选项添加到 PDO 构造函数中，将错误模式设置为`EXCEPTION`。现在修改 SQL 语句并观察生成的错误消息：

```php
$opts = [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION];
$pdo  = new PDO($dsn, $params['user'], $params['pwd'], $opts);
$stmt = $pdo->query('THIS SQL STATEMENT WILL NOT WORK');
```

您会看到类似这样的东西：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_05_02.jpg)

占位符可以是命名的或位置的。**命名占位符**在准备的 SQL 语句中以冒号（`:`）开头，并且在提供给`execute()`的关联数组中作为键引用。**位置占位符**在准备的 SQL 语句中表示为问号（`?`）。

在以下示例中，使用命名占位符来表示`WHERE`子句中的值：

```php
try {
  $dsn  = sprintf('mysql:host=%s;dbname=%s', 
                  $params['host'], $params['db']);
  $pdo  = new PDO($dsn, 
                  $params['user'], 
                  $params['pwd'], 
                  [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
  $sql  = 'SELECT * FROM customer '
      . 'WHERE balance < **:val** AND level = **:level** '
      . 'ORDER BY id LIMIT 20'; echo $sql . PHP_EOL;
  $stmt = $pdo->prepare($sql);
  $stmt->execute(['**val**' => 100, '**level**' => 'BEG']);
  while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    printf('%4d | %20s | %5s | %5.2f' . PHP_EOL, 
      	$row['id'], $row['name'], $row['level'], $row['balance']);
  }
} catch (PDOException $e) {
  echo $e->getMessage();
} catch (Throwable $e) {
  echo $e->getMessage();
}
```

这个例子展示了在`INSERT`操作中使用位置占位符。请注意，要插入的作为第四个客户的数据包括潜在的 SQL 注入攻击。您还会注意到，需要对正在使用的数据库的 SQL 语法有一定的了解。在这种情况下，MySQL 列名使用反引号（`'`）引用：

```php
$fields = ['name', 'balance', 'email', 
           'password', 'status', 'level'];
$data = [
  ['Saleen',0,'saleen@test.com', 'password',0,'BEG'],
  ['Lada',55.55,'lada@test.com',   'password',0,'INT'],
  ['Tonsoi',999.99,'tongsoi@test.com','password',1,'ADV'],
  ['SQL Injection',0.00,'bad','bad',1,
   'BEG\';DELETE FROM customer;--'],
];

try {
  $dsn  = sprintf('mysql:host=%s;dbname=%s', 
    $params['host'], $params['db']);
  $pdo  = new PDO($dsn, 
                  $params['user'], 
                  $params['pwd'], 
                  [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
  $sql  = "INSERT INTO customer ('" 
   . implode("','", $fields) 
   . "') VALUES (**?,?,?,?,?,?**)";
  $stmt = $pdo->prepare($sql);
  foreach ($data as $row) $stmt->execute($row);
} catch (PDOException $e) {
  echo $e->getMessage();
} catch (Throwable $e) {
  echo $e->getMessage();
}
```

为了测试使用带有命名参数的准备语句，修改 SQL 语句以添加一个`WHERE`子句，检查余额小于某个特定金额的客户，以及级别等于`BEG`、`INT`或`ADV`（即初级、中级或高级）。不要使用`PDO::query()`，而是使用`PDO::prepare()`。在获取结果之前，您必须执行`PDOStatement::execute()`，提供余额和级别的值：

```php
$sql  = 'SELECT * FROM customer '
     . 'WHERE balance < :val AND level = :level '
     . 'ORDER BY id LIMIT 20';
$stmt = $pdo->prepare($sql);
$stmt->execute(['val' => 100, 'level' => 'BEG']);
```

以下是生成的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_05_03.jpg)

在调用`PDOStatement::execute()`时，您可以选择绑定参数。这允许您将变量分配给占位符。在执行时，将使用变量的当前值。

在这个例子中，我们将变量`$min`，`$max`和`$level`绑定到准备好的语句中：

```php
$min   = 0;
$max   = 0;
$level = '';

try {
  $dsn  = sprintf('mysql:host=%s;dbname=%s', $params['host'], $params['db']);
  $opts = [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION];
  $pdo  = new PDO($dsn, $params['user'], $params['pwd'], $opts);
  $sql  = 'SELECT * FROM customer '
      . 'WHERE balance > :min '
      . 'AND balance < :max AND level = :level '
      . 'ORDER BY id LIMIT 20';
  $stmt = $pdo->prepare($sql);
  **$stmt->bindParam('min',   $min);**
 **$stmt->bindParam('max',   $max);**
 **$stmt->bindParam('level', $level);**

  $min   =  5000;
  $max   = 10000;
  $level = 'ADV';
  $stmt->execute();
  showResults($stmt, $min, $max, $level);

  $min   = 0;
  $max   = 100;
  $level = 'BEG';
  $stmt->execute();
  showResults($stmt, $min, $max, $level);

} catch (PDOException $e) {
  echo $e->getMessage();
} catch (Throwable $e) {
  echo $e->getMessage();
}
```

当这些变量的值发生变化时，下一次执行将反映修改后的条件。

### 提示

**最佳实践**

对于一次性数据库命令，请使用`PDO::query()`。当您需要多次处理相同的语句但使用不同的值时，请使用`PDO::prepare()`和`PDOStatement::execute()`。

## 另请参阅

有关与不同供应商特定 PDO 驱动程序相关的语法和独特行为的信息，请参阅本文：

+   [`php.net/manual/en/pdo.drivers.php`](http://php.net/manual/en/pdo.drivers.php)

有关 PDO 预定义常量的摘要，包括获取模式、游标方向和属性，请参阅以下文章：

+   [`php.net/manual/en/pdo.constants.php`](http://php.net/manual/en/pdo.constants.php)

# 构建面向对象的 SQL 查询构建器

PHP 7 实现了一种称为**上下文敏感词法分析器**的东西。这意味着通常保留的单词可以在上下文允许的情况下使用。因此，当构建面向对象的 SQL 构建器时，我们可以使用命名为`and`、`or`、`not`等的方法。

## 如何做...

1.  我们定义一个`Application\Database\Finder`类。在这个类中，我们定义与我们喜欢的 SQL 操作相匹配的方法：

```php
namespace Application\Database;
class Finder
{
  public static $sql      = '';
  public static $instance = NULL;
  public static $prefix   = '';
  public static $where    = array();
  public static $control  = ['', ''];

    // $a == name of table
    // $cols = column names
    public static function select($a, $cols = NULL)
    {
      self::$instance  = new Finder();
      if ($cols) {
           self::$prefix = 'SELECT ' . $cols . ' FROM ' . $a;
      } else {
        self::$prefix = 'SELECT * FROM ' . $a;
      }
      return self::$instance;
    }

    public static function where($a = NULL)
    {
        self::$where[0] = ' WHERE ' . $a;
        return self::$instance;
    }

    public static function like($a, $b)
    {
        self::$where[] = trim($a . ' LIKE ' . $b);
        return self::$instance;
    }

    public static function and($a = NULL)
    {
        self::$where[] = trim('AND ' . $a);
        return self::$instance;
    }

    public static function or($a = NULL)
    {
        self::$where[] = trim('OR ' . $a);
        return self::$instance;
    }

    public static function in(array $a)
    {
        self::$where[] = 'IN ( ' . implode(',', $a) . ' )';
        return self::$instance;
    }

    public static function not($a = NULL)
    {
        self::$where[] = trim('NOT ' . $a);
        return self::$instance;
    }

    public static function limit($limit)
    {
        self::$control[0] = 'LIMIT ' . $limit;
        return self::$instance;
    }

    public static function offset($offset)
    {
        self::$control[1] = 'OFFSET ' . $offset;
        return self::$instance;
    }

  public static function getSql()
  {
    self::$sql = self::$prefix
       . implode(' ', self::$where)
               . ' '
               . self::$control[0]
               . ' '
               . self::$control[1];
    preg_replace('/  /', ' ', self::$sql);
    return trim(self::$sql);
  }
}
```

1.  用于生成 SQL 片段的每个函数都返回相同的属性`$instance`。这使我们能够使用流畅的接口来表示代码，例如：

```php
$sql = Finder::select('project')->where('priority > 9') ... etc.
```

## 它是如何工作的...

将前面定义的代码复制到`Application\Database`文件夹中的`Finder.php`文件中。然后，您可以创建一个调用程序`chap_05_oop_query_builder.php`，该程序初始化了第一章中定义的自动加载程序，*建立基础*。然后，您可以运行`Finder::select()`来生成一个对象，从中可以呈现 SQL 字符串：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Database\Finder;

$sql = Finder::select('project')
  ->where()
  ->like('name', '%secret%')
  ->and('priority > 9')
  ->or('code')->in(['4', '5', '7'])
  ->and()->not('created_at')
  ->limit(10)
  ->offset(20);

echo Finder::getSql();
```

这是上述代码的结果：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_05_04.jpg)

## 另请参阅

有关上下文敏感词法分析器的更多信息，请参阅本文：

[`wiki.php.net/rfc/context_sensitive_lexer`](https://wiki.php.net/rfc/context_sensitive_lexer)

# 处理分页

分页涉及提供数据库查询结果的有限子集。这通常是为了显示目的，但也可以轻松应用于其他情况。乍一看，似乎`LimitIterator`类非常适合分页的目的。然而，在潜在结果集可能非常庞大的情况下，`LimitIterator`并不是一个理想的选择，因为您需要提供整个结果集作为内部迭代器，这很可能会超出内存限制。`LimitIterator`类构造函数的第二个和第三个参数是偏移和计数。这表明我们将采用的分页解决方案，这是 SQL 本身的一部分：向给定的 SQL 语句添加`LIMIT`和`OFFSET`子句。

## 如何做...

1.  首先，我们创建一个名为`Application\Database\Paginate`的类来保存分页逻辑。我们添加属性来表示与分页相关的值，`$sql`、`$page`和`$linesPerPage`：

```php
namespace Application\Database;

class Paginate
{

  const DEFAULT_LIMIT  = 20;
  const DEFAULT_OFFSET = 0;

  protected $sql;
  protected $page;
  protected $linesPerPage;

}
```

1.  接下来，我们定义一个`__construct()`方法，它接受基本 SQL 语句、当前页码和每页行数作为参数。然后，我们需要重构 SQL 字符串，修改或添加`LIMIT`和`OFFSET`子句。

1.  在构造函数中，我们需要使用当前页码和每页行数来计算偏移量。我们还需要检查 SQL 语句中是否已经存在`LIMIT`和`OFFSET`。最后，我们需要使用每页行数作为我们的`LIMIT`，使用重新计算的`OFFSET`来修改语句：

```php
public function __construct($sql, $page, $linesPerPage)
{
  $offset = $page * $linesPerPage;
  switch (TRUE) {
    case (stripos($sql, 'LIMIT') && strpos($sql, 'OFFSET')) :
      // no action needed
      break;
    case (stripos($sql, 'LIMIT')) :
      $sql .= ' LIMIT ' . self::DEFAULT_LIMIT;
      break;
    case (stripos($sql, 'OFFSET')) :
      $sql .= ' OFFSET ' . self::DEFAULT_OFFSET;
      break;
    default :
      $sql .= ' LIMIT ' . self::DEFAULT_LIMIT;
      $sql .= ' OFFSET ' . self::DEFAULT_OFFSET;
      break;
  }
  $this->sql = preg_replace('/LIMIT \d+.*OFFSET \d+/Ui', 
     'LIMIT ' . $linesPerPage . ' OFFSET ' . $offset, 
     $sql);
}
```

1.  现在，我们已经准备好使用第一篇食谱中讨论的`Application\Database\Connection`类来执行查询。

1.  在我们的新分页类中，我们添加了一个`paginate()`方法，它以`Connection`实例作为参数。我们还需要 PDO 获取模式和可选的准备好的语句参数：

```php
use PDOException;
public function paginate(
  Connection $connection, 
  $fetchMode, 
  $params = array())
  {
  try {
    $stmt = $connection->pdo->prepare($this->sql);
    if (!$stmt) return FALSE;
    if ($params) {
      $stmt->execute($params);
    } else {
      $stmt->execute();
    }
    while ($result = $stmt->fetch($fetchMode)) yield $result;
  } catch (PDOException $e) {
    error_log($e->getMessage());
    return FALSE;
  } catch (Throwable $e) {
    error_log($e->getMessage());
    return FALSE;
  }
}
```

1.  为了提供对前面一篇食谱中提到的查询构建器类的支持可能是个好主意。这将使更新`LIMIT`和`OFFSET`变得更容易。我们需要做的就是为`Application\Database\Finder`提供支持，使用该类并修改`__construct()`方法以检查传入的 SQL 是否是这个类的实例：

```php
  if ($sql instanceof Finder) {
    $sql->limit($linesPerPage);
    $sql->offset($offset);
    $this->sql = $sql::getSql();
  } elseif (is_string($sql)) {
    switch (TRUE) {
      case (stripos($sql, 'LIMIT') 
      && strpos($sql, 'OFFSET')) :
          // remaining code as shown in bullet #3 above
      }
   }
```

1.  现在剩下要做的就是添加一个`getSql()`方法，以便在需要确认 SQL 语句是否正确形成时使用：

```php
public function getSql()
{
  return $this->sql;
}
```

## 它是如何工作的...

将上述代码复制到 `Application/Database` 文件夹中的 `Paginate.php` 文件中。然后可以创建一个 `chap_05_pagination.php` 调用程序，该程序初始化了第一章中定义的自动加载程序，*建立基础*：

```php
<?php
define('DB_CONFIG_FILE', '/../config/db.config.php');
define('LINES_PER_PAGE', 10);
define('DEFAULT_BALANCE', 1000);
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
```

接下来，使用 `Application\Database\Finder`、`Connection` 和 `Paginate` 类，创建一个 `Application\Database\Connection` 实例，并使用 `Finder` 生成 SQL：

```php
use Application\Database\ { Finder, Connection, Paginate};
$conn = new Connection(include __DIR__ . DB_CONFIG_FILE);
$sql = Finder::select('customer')->where('balance < :bal');
```

现在，我们可以从 `$_GET` 参数中获取页码和余额，并创建 `Paginate` 对象，结束 PHP 代码块：

```php
$page = (int) ($_GET['page'] ?? 0);
$bal  = (float) ($_GET['balance'] ?? DEFAULT_BALANCE);
$paginate = new Paginate($sql::getSql(), $page, LINES_PER_PAGE);
?>
```

在脚本的输出部分，我们只需使用简单的 `foreach()` 循环迭代通过分页：

```php
<h3><?= $paginate->getSql(); ?></h3>	
<hr>
<pre>
<?php
printf('%4s | %20s | %5s | %7s' . PHP_EOL, 
  'ID', 'NAME', 'LEVEL', 'BALANCE');
printf('%4s | %20s | %5s | %7s' . PHP_EOL, 
  '----', str_repeat('-', 20), '-----', '-------');
foreach ($paginate->paginate($conn, PDO::FETCH_ASSOC, 
  ['bal' => $bal]) as $row) {
  printf('%4d | %20s | %5s | %7.2f' . PHP_EOL, 
      $row['id'],$row['name'],$row['level'],$row['balance']);
}
printf('%4s | %20s | %5s | %7s' . PHP_EOL, 
  '----', str_repeat('-', 20), '-----', '-------');
?>
<a href="?page=<?= $page - 1; ?>&balance=<?= $bal ?>">
<< Prev </a>&nbsp;&nbsp;
<a href="?page=<?= $page + 1; ?>&balance=<?= $bal ?>">
Next >></a>
</pre>
```

以下是输出的第 3 页，余额小于 1,000：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_05_05.jpg)

## 另请参阅

有关 `LimitIterator` 类的更多信息，请参阅本文：

+   [`php.net/manual/en/class.limititerator.php`](http://php.net/manual/en/class.limititerator.php)

# 定义与数据库表匹配的实体

PHP 开发人员中非常常见的做法是创建代表数据库表的类。这些类通常被称为**实体**类，并且构成**领域模型**软件设计模式的核心。

## 如何做...

1.  首先，我们将确定一系列实体类的一些共同特征。这些可能包括共同的属性和共同的方法。我们将把这些放入 `Application\Entity\Base` 类中。然后，所有未来的实体类都将扩展 `Base`。

1.  为了说明的目的，让我们假设所有实体都有两个共同的属性：`$mapping`（稍后讨论）和 `$id`（及其相应的 getter 和 setter）：

```php
namespace Application\Entity;

class Base
{

  protected $id = 0;
  protected $mapping = ['id' => 'id'];

  public function getId() : int
  {
    return $this->id;
  }

  public function setId($id)
  {
    $this->id = (int) $id;
  }
}
```

1.  定义一个 `arrayToEntity()` 方法并不是一个坏主意，它将数组转换为实体类的实例，反之亦然（`entityToArray()`）。这些方法实现了一个经常被称为**水合**的过程。由于这些方法应该是通用的，因此最好将它们放在 `Base` 类中。

1.  在以下方法中，`$mapping` 属性用于在数据库列名和对象属性名之间进行转换。`arrayToEntity()` 从数组中填充此对象实例的值。我们可以定义此方法为静态方法，以防需要在活动实例之外调用它：

```php
public static function arrayToEntity($data, Base $instance)
{
  if ($data && is_array($data)) {
    foreach ($instance->mapping as $dbColumn => $propertyName) {
      $method = 'set' . ucfirst($propertyName);
      $instance->$method($data[$dbColumn]);
    }
    return $instance;
  }
  return FALSE;
}
```

1.  `entityToArray()` 从当前实例属性值生成数组：

```php
public function entityToArray()
{
  $data = array();
  foreach ($this->mapping as $dbColumn => $propertyName) {
    $method = 'get' . ucfirst($propertyName);
    $data[$dbColumn] = $this->$method() ?? NULL;
  }
  return $data;
}
```

1.  要构建特定的实体，您需要手头有要建模的数据库表的结构。创建映射到数据库列的属性。分配的初始值应反映数据库列的最终数据类型。

1.  在此示例中，我们将使用 `customer` 表。以下是来自 MySQL 数据转储的 `CREATE` 语句，说明了其数据结构：

```php
CREATE TABLE 'customer' (
  'id' int(11) NOT NULL AUTO_INCREMENT,
  'name' varchar(256) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
  'balance' decimal(10,2) NOT NULL,
  'email' varchar(250) NOT NULL,
  'password' char(16) NOT NULL,
  'status' int(10) unsigned NOT NULL DEFAULT '0',
  'security_question' varchar(250) DEFAULT NULL,
  'confirm_code' varchar(32) DEFAULT NULL,
  'profile_id' int(11) DEFAULT NULL,
  'level' char(3) NOT NULL,
  PRIMARY KEY ('id'),
  UNIQUE KEY 'UNIQ_81398E09E7927C74' ('email')
);
```

1.  现在我们可以填充类属性。这也是确定相应表的好地方。在这种情况下，我们将使用 `TABLE_NAME` 类常量：

```php
namespace Application\Entity;

class Customer extends Base
{
  const TABLE_NAME = 'customer';
  protected $name = '';
  protected $balance = 0.0;
  protected $email = '';
  protected $password = '';
  protected $status = '';
  protected $securityQuestion = '';
  protected $confirmCode = '';
  protected $profileId = 0;
  protected $level = '';
}
```

1.  将属性定义为 `protected` 被认为是最佳实践。为了访问这些属性，您需要设计 `public` 方法来 `get` 和 `set` 属性。这是一个很好的地方，可以利用 PHP 7 对返回值进行数据类型定义。

1.  在以下代码块中，我们已经为 `$name` 和 `$balance` 定义了 getter 和 setter。您可以想象其余这些方法将如何定义：

```php
  public function getName() : string
  {
    return $this->name;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getBalance() : float
  {
    return $this->balance;
  }
  public function setBalance($balance)
  {
    $this->balance = (float) $balance;
  }
}
```

### 提示

在 setter 中对传入值进行数据类型检查并不是一个好主意。原因是来自 RDBMS 数据库查询的返回值都将是 `string` 数据类型。

1.  如果属性名称与相应的数据库列不完全匹配，您应该考虑创建一个 `mapping` 属性，一个键/值对数组，其中键表示数据库列名，值表示属性名。

1.  您会注意到，三个属性`$securityQuestion`、`$confirmCode`和`$profileId`与它们对应的列名`security_question`、`confirm_code`和`profile_id`不对应。`$mapping`属性将确保适当的转换发生：

```php
protected $mapping = [
  'id'                => 'id',
  'name'              => 'name',
  'balance'           => 'balance',
  'email'             => 'email',
  'password'          => 'password',
  'status'            => 'status',
  'security_question' => 'securityQuestion',
  'confirm_code'      => 'confirmCode',
  'profile_id'        => 'profileId',
  'level'             => 'level'
];
```

## 它是如何工作的...

将步骤 2、4 和 5 中的代码复制到`Application/Entity`文件夹中的`Base.php`文件中。将步骤 8 到 12 中的代码复制到`Application/Entity`文件夹中的`Customer.php`文件中。然后，您需要为步骤 10 中未显示的剩余属性`email`、`password`、`status`、`securityQuestion`、`confirmCode`、`profileId`和`level`创建 getter 和 setter。

然后，您可以创建一个`chap_05_matching_entity_to_table.php`调用程序，该程序初始化了第一章中定义的自动加载程序，使用`Application\Database\Connection`和新创建的`Application\Entity\Customer`类：

```php
<?php
define('DB_CONFIG_FILE', '/../config/db.config.php');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Database\Connection;
use Application\Entity\Customer;
```

接下来，获取一个数据库连接，并使用连接随机获取一个客户的数据的关联数组：

```php
$conn = new Connection(include __DIR__ . DB_CONFIG_FILE);
$id = rand(1,79);
$stmt = $conn->pdo->prepare(
  'SELECT * FROM customer WHERE id = :id');
$stmt->execute(['id' => $id]);
$result = $stmt->fetch(PDO::FETCH_ASSOC);
```

最后，您可以从数组中创建一个新的`Customer`实体实例，并使用`var_dump()`查看结果：

```php
$cust = Customer::arrayToEntity($result, new Customer());
var_dump($cust);
```

以下是前面代码的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_05_06.jpg)

## 另请参阅

有许多描述领域模型的好作品。可能最有影响力的是 Martin Fowler 的*企业应用架构模式*（参见[`martinfowler.com/books/eaa.html`](http://martinfowler.com/books/eaa.html)）。还有一份很好的研究，也可以免费下载，名为*快速领域驱动设计*的 InfoQ（参见[`www.infoq.com/minibooks/domain-driven-design-quickly`](http://www.infoq.com/minibooks/domain-driven-design-quickly)）。

# 将实体类与 RDBMS 查询联系起来

大多数商业上可行的 RDBMS 系统是在过程式编程处于前沿时演变而来的。想象一下 RDBMS 世界是二维的、方形的、过程化的。相比之下，实体可以被认为是圆形的、三维的、面向对象的。这给了你一个关于我们想要通过将 RDBMS 查询的结果与实体实例的迭代联系起来实现的想法。

### 注意

**关系模型**，现代 RDBMS 系统所基于的模型，是由数学家 Edgar F. Codd 在 1969 年首次描述的。第一个商业上可行的系统是在 70 年代中期至 70 年代末期演变而来的。换句话说，RDBMS 技术已经有 40 多年的历史了！

## 如何做...

1.  首先，我们需要设计一个类，用于容纳我们的查询逻辑。如果你遵循领域模型，这个类可能被称为**存储库**。或者，为了保持简单和通用，我们可以简单地将新类称为`Application\Database\CustomerService`。该类将接受一个`Application\Database\Connection`实例作为参数：

```php
namespace Application\Database;

use Application\Entity\Customer;

class CustomerService
{

    protected $connection;

    public function __construct(Connection $connection)
    {
      $this->connection = $connection;
    }

}
```

1.  现在我们将定义一个`fetchById()`方法，它以客户 ID 作为参数，并在失败时返回单个`Application\Entity\Customer`实例或布尔值`FALSE`。乍一看，似乎很简单，只需简单地使用`PDOStatement::fetchObject()`并将实体类指定为参数：

```php
public function fetchById($id)
{
  $stmt = $this->connection->pdo
               ->prepare(Finder::select('customer')
               ->where('id = :id')::getSql());
  $stmt->execute(['id' => (int) $id]);
  return $stmt->fetchObject('Application\Entity\Customer');
}
```

### 注意

然而，这里的危险是`fetchObject()`实际上在调用构造函数之前填充属性（即使它们是受保护的）！因此，存在构造函数可能意外覆盖值的危险。如果你没有定义构造函数，或者如果你可以接受这种危险，那就完成了。否则，正确实现 RDBMS 查询和 OOP 结果之间的联系就开始变得更加困难。

1.  `fetchById()`方法的另一种方法是首先创建对象实例，从而运行其构造函数，并将获取模式设置为`PDO::FETCH_INTO`，如下例所示：

```php
public function fetchById($id)
{
  $stmt = $this->connection->pdo
               ->prepare(Finder::select('customer')
               ->where('id = :id')::getSql());
  $stmt->execute(['id' => (int) $id]);
  $stmt->setFetchMode(PDO::FETCH_INTO, new Customer());
  return $stmt->fetch();
}
```

1.  然而，我们在这里又遇到了一个问题：`fetch()`与`fetchObject()`不同，它无法覆盖受保护的属性；如果尝试覆盖，将生成以下错误消息。这意味着我们要么将所有属性定义为`public`，要么考虑另一种方法。![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_05_07.jpg)

1.  我们将考虑的最后一种方法是以数组形式获取结果，并手动*hydrate*实体。尽管这种方法在性能方面略微昂贵，但它允许任何潜在的实体构造函数正常运行，并且可以安全地将属性定义为`private`或`protected`：

```php
public function fetchById($id)
{
  $stmt = $this->connection->pdo
               ->prepare(Finder::select('customer')
               ->where('id = :id')::getSql());
  $stmt->execute(['id' => (int) $id]);
  return Customer::arrayToEntity(
    $stmt->fetch(PDO::FETCH_ASSOC));
}
```

1.  要处理产生多个结果的查询，我们只需要生成填充的实体对象的迭代。在这个例子中，我们实现了一个`fetchByLevel()`方法，它以`Application\Entity\Customer`实例的形式返回给定级别的所有客户：

```php
public function fetchByLevel($level)
{
  $stmt = $this->connection->pdo->prepare(
            Finder::select('customer')
            ->where('level = :level')::getSql());
  $stmt->execute(['level' => $level]);
  while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    yield Customer::arrayToEntity($row, new Customer());
  }
}
```

1.  我们希望实现的下一个方法是`save()`。然而，在我们继续之前，必须考虑如果发生`INSERT`，将返回什么值。

1.  通常，我们会在`INSERT`后返回新完成的实体类。有一个方便的`PDO::lastInsertId()`方法，乍一看似乎可以解决问题。然而，进一步阅读文档后发现，并非所有的数据库扩展都支持这个特性，而且支持的数据库扩展在实现上也不一致。因此，最好有一个除了`$id`之外的唯一列，可以用来唯一标识新客户。

1.  在这个例子中，我们选择了`email`列，因此需要实现一个`fetchByEmail()`服务方法：

```php
public function fetchByEmail($email)
{
  $stmt = $this->connection->pdo->prepare(
    Finder::select('customer')
    ->where('email = :email')::getSql());
  $stmt->execute(['email' => $email]);
  return Customer::arrayToEntity(
    $stmt->fetch(PDO::FETCH_ASSOC), new Customer());
}
```

1.  现在我们准备定义`save()`方法。我们不再区分`INSERT`和`UPDATE`，而是将这个方法设计为如果 ID 已经存在，则更新，否则进行插入。

1.  首先，我们定义一个基本的`save()`方法，它接受一个`Customer`实体作为参数，并使用`fetchById()`来确定此条目是否已经存在。如果存在，我们调用一个`doUpdate()`更新方法；否则，我们调用一个`doInsert()`插入方法：

```php
public function save(Customer $cust)
{
  // check to see if customer ID > 0 and exists
  if ($cust->getId() && $this->fetchById($cust->getId())) {
    return $this->doUpdate($cust);
  } else {
    return $this->doInsert($cust);
  }
}
```

1.  接下来，我们定义`doUpdate()`，它将`Customer`实体对象的属性提取到一个数组中，构建一个初始的 SQL 语句，并调用`flush()`方法，将数据推送到数据库。我们不希望 ID 字段被更新，因为它是主键。另外，我们需要指定要更新的行，这意味着要添加一个`WHERE`子句：

```php
protected function doUpdate($cust)
{
  // get properties in the form of an array
  $values = $cust->entityToArray();
  // build the SQL statement
  $update = 'UPDATE ' . $cust::TABLE_NAME;
  $where = ' WHERE id = ' . $cust->getId();
  // unset ID as we want do not want this to be updated
  unset($values['id']);
  return $this->flush($update, $values, $where);
}
```

1.  `doInsert()`方法类似，只是初始的 SQL 需要以`INSERT INTO ...`开头，并且需要取消`id`数组元素。后者的原因是我们希望这个属性由数据库自动生成。如果成功，我们使用我们新定义的`fetchByEmail()`方法查找新客户并返回一个完成的实例：

```php
protected function doInsert($cust)
{
  $values = $cust->entityToArray();
  $email  = $cust->getEmail();
  unset($values['id']);
  $insert = 'INSERT INTO ' . $cust::TABLE_NAME . ' ';
  if ($this->flush($insert, $values)) {
    return $this->fetchByEmail($email);
  } else {
    return FALSE;
  }
}
```

1.  最后，我们可以定义`flush()`，它执行实际的准备和执行：

```php
protected function flush($sql, $values, $where = '')
{
  $sql .=  ' SET ';
  foreach ($values as $column => $value) {
    $sql .= $column . ' = :' . $column . ',';
  }
  // get rid of trailing ','
  $sql     = substr($sql, 0, -1) . $where;
  $success = FALSE;
  try {
    $stmt = $this->connection->pdo->prepare($sql);
    $stmt->execute($values);
    $success = TRUE;
  } catch (PDOException $e) {
    error_log(__METHOD__ . ':' . __LINE__ . ':' 
    . $e->getMessage());
    $success = FALSE;
  } catch (Throwable $e) {
    error_log(__METHOD__ . ':' . __LINE__ . ':' 
    . $e->getMessage());
    $success = FALSE;
  }
  return $success;
}
```

1.  为了结束讨论，我们需要定义一个`remove()`方法，它可以从数据库中删除一个客户。与之前定义的`save()`方法一样，我们再次使用`fetchById()`来确保操作成功：

```php
public function remove(Customer $cust)
{
  $sql = 'DELETE FROM ' . $cust::TABLE_NAME . ' WHERE id = :id';
  $stmt = $this->connection->pdo->prepare($sql);
  $stmt->execute(['id' => $cust->getId()]);
  return ($this->fetchById($cust->getId())) ? FALSE : TRUE;
}
```

## 它是如何工作的...

将步骤 1 到 5 中描述的代码复制到`Application/Database`文件夹中的`CustomerService.php`文件中。定义一个`chap_05_entity_to_query.php`调用程序。让调用程序初始化自动加载器，使用适当的类：

```php
<?php
define('DB_CONFIG_FILE', '/../config/db.config.php');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Database\Connection;
use Application\Database\CustomerService;
```

现在，您可以创建一个服务的实例，并随机获取一个客户。然后服务将返回一个客户实体作为结果：

```php
// get service instance
$service = new CustomerService(new Connection(include __DIR__ . DB_CONFIG_FILE));

echo "\nSingle Result\n";
var_dump($service->fetchById(rand(1,79)));
```

这是输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_05_08.jpg)

现在将步骤 6 到 15 中显示的代码复制到服务类中。将要插入的数据添加到`chap_05_entity_to_query.php`调用程序中。然后使用这些数据生成一个`Customer`实体实例：

```php
// sample data
$data = [
  'name'              => 'Doug Bierer',
  'balance'           => 326.33,
  'email'             => 'doug' . rand(0,999) . '@test.com',
  'password'          => 'password',
  'status'            => 1,
  'security_question' => 'Who\'s on first?',
  'confirm_code'      => 12345,
  'level'             => 'ADV'
];

// create new Customer
$cust = Customer::arrayToEntity($data, new Customer());
```

然后我们可以在调用`save()`之前和之后检查 ID：

```php
echo "\nCustomer ID BEFORE Insert: {$cust->getId()}\n";
$cust = $service->save($cust);
echo "Customer ID AFTER Insert: {$cust->getId()}\n";
```

最后，我们修改余额，然后再次调用`save（）`，查看结果：

```php
echo "Customer Balance BEFORE Update: {$cust->getBalance()}\n";
$cust->setBalance(999.99);
$service->save($cust);
echo "Customer Balance AFTER Update: {$cust->getBalance()}\n";
var_dump($cust);
```

这是调用程序的输出：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_05_09.jpg)

## 还有更多...

有关关系模型的更多信息，请参阅[`en.wikipedia.org/wiki/Relational_model`](https://en.wikipedia.org/wiki/Relational_model)。有关 RDBMS 的更多信息，请参阅[`en.wikipedia.org/wiki/Relational_database_management_system`](https://en.wikipedia.org/wiki/Relational_database_management_system)。有关`PDOStatement::fetchObject（）`在构造函数之前插入属性值的信息，请查看 php.net 文档参考中关于`fetchObject（）`的"rasmus at mindplay dot dk"的评论（[`php.net/manual/en/pdostatement.fetchobject.php`](http://php.net/manual/en/pdostatement.fetchobject.php)）。

# 将辅助查找嵌入到查询结果中

在实现实体类之间的关系之路上，让我们首先看一下如何嵌入执行辅助查找所需的代码。这样一个查找的示例是，在显示客户信息时，视图逻辑执行第二次查找，获取该客户的购买列表。

### 注意

这种方法的优势在于，处理被推迟直到实际视图逻辑被执行。这将最终平滑性能曲线，工作负载在客户信息的初始查询和后来的购买信息查询之间更均匀地分布。另一个好处是避免了大量的`JOIN`及其固有的冗余数据。

## 如何做...

1.  首先，定义一个根据其 ID 查找客户的函数。为了说明这一点，我们将简单地使用`PDO::FETCH_ASSOC`的获取模式获取一个数组。我们还将继续使用第一章中讨论的`Application\Database\Connection`类，*建立基础*：

```php
function findCustomerById($id, Connection $conn)
{
  $stmt = $conn->pdo->query(
    'SELECT * FROM customer WHERE id = ' . (int) $id);
  $results = $stmt->fetch(PDO::FETCH_ASSOC);
  return $results;
}
```

1.  接下来，我们分析购买表，看看`customer`和`product`表是如何关联的。从这个表的`CREATE`语句中可以看出，`customer_id`和`product_id`外键形成了关系：

```php
CREATE TABLE 'purchases' (
  'id' int(11) NOT NULL AUTO_INCREMENT,
  'transaction' varchar(8) NOT NULL,
  'date' datetime NOT NULL,
  'quantity' int(10) unsigned NOT NULL,
  'sale_price' decimal(8,2) NOT NULL,
  'customer_id' int(11) DEFAULT NULL,
  'product_id' int(11) DEFAULT NULL,
  PRIMARY KEY ('id'),
  KEY 'IDX_C3F3' ('customer_id'),
  KEY 'IDX_665A' ('product_id'),
  CONSTRAINT 'FK_665A' FOREIGN KEY ('product_id') 
  REFERENCES 'products' ('id'),
  CONSTRAINT 'FK_C3F3' FOREIGN KEY ('customer_id') 
  REFERENCES 'customer' ('id')
);
```

1.  我们现在扩展原始的`findCustomerById（）`函数，定义形式为匿名函数的辅助查找，然后可以在视图脚本中执行。将匿名函数分配给`$results['purchases']`元素：

```php
function findCustomerById($id, Connection $conn)
{
  $stmt = $conn->pdo->query(
       'SELECT * FROM customer WHERE id = ' . (int) $id);
  $results = $stmt->fetch(PDO::FETCH_ASSOC);
  if ($results) {
    $results['purchases'] = 
      // define secondary lookup
 **function ($id, $conn) {**
 **$sql = 'SELECT * FROM purchases AS u '**
 **. 'JOIN products AS r '**
 **. 'ON u.product_id = r.id '**
 **. 'WHERE u.customer_id = :id '**
 **. 'ORDER BY u.date';**
 **$stmt = $conn->pdo->prepare($sql);**
 **$stmt->execute(['id' => $id]);**
 **while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {**
 **yield $row;**
 **}**
 **};**
  }
  return $results;
}
```

1.  假设我们已成功将客户信息检索到`$results`数组中，在视图逻辑中，我们所需要做的就是循环遍历匿名函数的返回值。在这个例子中，我们随机检索客户信息：

```php
$result = findCustomerById(rand(1,79), $conn);
```

1.  在视图逻辑中，我们循环遍历辅助查找返回的结果。嵌入的匿名函数的调用在以下代码中突出显示：

```php
<table>
  <tr>
<th>Transaction</th><th>Date</th><th>Qty</th>
<th>Price</th><th>Product</th>
  </tr>
<?php 
foreach (**$result'purchases' as $purchase) : ?>
  <tr>
    <td><?= $purchase['transaction'] ?></td>
    <td><?= $purchase['date'] ?></td>
    <td><?= $purchase['quantity'] ?></td>
    <td><?= $purchase['sale_price'] ?></td>
    <td><?= $purchase['title'] ?></td>
  </tr>
<?php endforeach; ?>
</table>
```

## 工作原理...

创建一个`chap_05_secondary_lookups.php`调用程序，并插入所需的代码以创建`Application\Database\Connection`的实例：

```php
<?php
define('DB_CONFIG_FILE', '/../config/db.config.php');
include __DIR__ . '/../Application/Database/Connection.php';
use Application\Database\Connection;
$conn = new Connection(include __DIR__ . DB_CONFIG_FILE);
```

接下来，在步骤 3 中显示的`findCustomerById（）`函数中添加。然后，您可以获取随机客户的信息，结束调用程序的 PHP 部分：

```php
function findCustomerById($id, Connection $conn)
{
  // code shown in bullet #3 above
}
$result = findCustomerById(rand(1,79), $conn);
?>
```

对于视图逻辑，您可以显示核心客户信息，就像在前面的几个示例中所示的那样：

```php
<h1><?= $result['name'] ?></h1>
<div class="row">
<div class="left">Balance</div>
<div class="right"><?= $result['balance']; ?></div>
</div>
<!-- etc.l -->
```

您可以这样显示购买信息：

```php
<table>
<tr><th>Transaction</th><th>Date</th><th>Qty</th>
<th>Price</th><th>Product</th></tr>
  <?php 
  foreach **($result'purchases' as $purchase)** : ?>
  <tr>
    <td><?= $purchase['transaction'] ?></td>
    <td><?= $purchase['date'] ?></td>
    <td><?= $purchase['quantity'] ?></td>
    <td><?= $purchase['sale_price'] ?></td>
    <td><?= $purchase['title'] ?></td>
  </tr>
<?php endforeach; ?>
</table>
```

关键的一点是，通过调用嵌入的匿名函数`$result'purchases'`，辅助查找作为视图逻辑的一部分执行。这是输出：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_05_10.jpg)

# 实现 jQuery DataTables PHP 查找

进行次要查找的另一种方法是让前端生成请求。在这个食谱中，我们将对前面食谱中介绍的次要查找代码进行轻微修改，将次要查找嵌入到 QueryResults 中。在以前的食谱中，即使视图逻辑执行查找，所有处理仍然在服务器上完成。但是，当使用**jQuery DataTables**时，次要查找实际上是由客户端直接执行的，以**异步 JavaScript 和 XML**（**AJAX**）请求的形式由浏览器发出。

## 如何做...

1.  首先，我们需要将上面讨论的次要查找逻辑（在上面的食谱中讨论）分离到一个单独的 PHP 文件中。这个新脚本的目的是执行次要查找并返回一个 JSON 数组。

1.  新的脚本我们将称之为`chap_05_jquery_datatables_php_lookups_ajax.php`。它寻找一个`$_GET`参数，`id`。请注意，`SELECT`语句非常具体，以确定传递了哪些列。您还会注意到，提取模式已更改为`PDO::FETCH_NUM`。您可能还会注意到，最后一行将结果取出并将其分配给 JSON 编码数组中的`data`键。

### 提示

在处理零配置 jQuery DataTables 时，非常重要的一点是只返回与标题匹配的确切列数。

```php
$id  = $_GET['id'] ?? 0;
sql = 'SELECT u.transaction,u.date, **u.quantity,u.sale_price,r.title '**
   . 'FROM purchases AS u '
   . 'JOIN products AS r '
   . 'ON u.product_id = r.id '
   . 'WHERE u.customer_id = :id';
$stmt = $conn->pdo->prepare($sql);
$stmt->execute(['id' => (int) $id]);
$results = array();
while ($row = $stmt->fetch(**PDO::FETCH_NUM**)) {
  $results[] = $row;
}
echo json_encode(['data' => $results]); 
```

1.  接下来，我们需要修改通过 ID 检索客户信息的函数，删除在前面食谱中嵌入的次要查找：

```php
function findCustomerById($id, Connection $conn)
{
  $stmt = $conn->pdo->query(
    'SELECT * FROM customer WHERE id = ' . (int) $id);
  $results = $stmt->fetch(PDO::FETCH_ASSOC);
  return $results;
}
```

1.  之后，在视图逻辑中，我们导入最少的 jQuery，DataTables 和样式表，以实现零配置。至少，您将需要 jQuery 本身（在本例中为`jquery-1.12.0.min.js`）和 DataTables（`jquery.dataTables.js`）。我们还添加了一个方便的与 DataTables 关联的样式表，`jquery.dataTables.css`：

```php
<!DOCTYPE html>
<head>
  <script src="https://code.jquery.com/jquery-1.12.0.min.js">
  </script>
    <script type="text/javascript" 
      charset="utf8" 
      src="//cdn.datatables.net/1.10.11/js/jquery.dataTables.js">
    </script>
  <link rel="stylesheet" 
    type="text/css" 
    href="//cdn.datatables.net/1.10.11/css/jquery.dataTables.css">
</head>
```

1.  然后我们定义一个 jQuery 文档`ready`函数，将一个表格与 DataTables 关联起来。在这种情况下，我们将 id 属性`customerTable`分配给将分配给 DataTables 的表元素。您还会注意到，我们将 AJAX 数据源指定为步骤 1 中定义的脚本`chap_05_jquery_datatables_php_lookups_ajax.php`。由于我们有`$id`可用，因此将其附加到数据源 URL 中：

```php
<script>
$(document).ready(function() {
  $('#customerTable').DataTable(
    { "ajax": '/chap_05_jquery_datatables_php_lookups_ajax.php?id=<?= $id ?>' 
  });
} );
</script>
```

1.  在视图逻辑的主体中，我们定义表格，确保`id`属性与前面的代码中指定的一致。我们还需要定义标题，以匹配响应 AJAX 请求呈现的数据：

```php
<table id="customerTable" class="display" cellspacing="0" width="100%">
  <thead>
    <tr>
      <th>Transaction</th>
      <th>Date</th>
      <th>Qty</th>
      <th>Price</th>
      <th>Product</th>
    </tr>
  </thead>
</table>
```

1.  现在，剩下的就是加载页面，选择客户 ID（在这种情况下是随机选择），并让 jQuery 发出次要查找的请求。

## 工作原理...

创建一个`chap_05_jquery_datatables_php_lookups_ajax.php`脚本，用于响应 AJAX 请求。在其中，放置初始化自动加载和创建`Connection`实例的代码。然后，您可以附加前面食谱中步骤 2 中显示的代码：

```php
<?php
define('DB_CONFIG_FILE', '/../config/db.config.php');
include __DIR__ . '/../Application/Database/Connection.php';
use Application\Database\Connection;
$conn = new Connection(include __DIR__ . DB_CONFIG_FILE);
```

接下来，创建一个`chap_05_jquery_datatables_php_lookups.php`调用程序，将随机客户的信息提取出来。添加前面代码中描述的步骤 3 中的函数：

```php
<?php
define('DB_CONFIG_FILE', '/../config/db.config.php');
include __DIR__ . '/../Application/Database/Connection.php';
use Application\Database\Connection;
$conn = new Connection(include __DIR__ . DB_CONFIG_FILE);
// add function findCustomerById() here
$id     = random_int(1,79);
$result = findCustomerById($id, $conn);
?>
```

调用程序还将包含导入最少 JavaScript 以实现 jQuery DataTables 的视图逻辑。您可以添加前面代码中显示的步骤 3 中的代码。然后，添加文档`ready`函数和显示逻辑，如步骤 5 和 6 中所示。这是输出：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_05_11.jpg)

## 还有更多...

有关 jQuery 的更多信息，请访问他们的网站[`jquery.com/`](https://jquery.com/)。要了解有关 jQuery 的 DataTables 插件的信息，请参阅此文章[`www.datatables.net/`](https://www.datatables.net/)。零配置数据表的讨论在[`datatables.net/examples/basic_init/zero_configuration.html`](https://datatables.net/examples/basic_init/zero_configuration.html)。有关 AJAX 数据来源的更多信息，请查看[`datatables.net/examples/data_sources/ajax.html`](https://datatables.net/examples/data_sources/ajax.html)。
