# 精通 PHP7（二）

> 原文：[`zh.annas-archive.org/md5/c80452b19d206124b22230f7a590b2c3`](https://zh.annas-archive.org/md5/c80452b19d206124b22230f7a590b2c3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：魔术方法背后的魔术

PHP 语言允许以过程化和**面向对象**（**OO**）的方式编写代码。虽然过程化方式更像是 PHP 初始版本的遗留物，但我们今天仍然可以编写完全过程化的应用程序。虽然两种方法都有各自的优缺点，但面向对象的方式如今是最主导的，其优势在健壮和模块化的应用程序中更加明显，而这些应用程序几乎不可能使用过程化风格进行工作。

了解 PHP OO 模型的各个特性对于理解、编写和调试现代应用程序至关重要。**魔术方法**是 PHP 语言中更有趣和常常神秘的特性之一。它们是预定义的类方法，PHP 编译器在某些事件下执行，比如对象初始化、对象销毁、对象转换为字符串、对象方法访问、对象属性访问、对象序列化、对象反序列化等等。

在本章中，我们将根据以下章节列表，介绍 PHP 中可用的每个魔术方法的使用：

+   使用 __construct()

+   使用 __destruct()

+   使用 __call()

+   使用 __callStatic()

+   使用 __set()

+   使用 __get()

+   使用 __isset()

+   使用 __unset()

+   使用 __sleep()

+   使用 __wakeup()

+   使用 __toString()

+   使用 __invoke()

+   使用 __set_state()

+   使用 __clone()

+   使用 __debugInfo()

+   跨流行平台的使用统计

PHP 语言将所有以`__`开头的函数名称保留为魔术函数。

# 使用 __construct()

`__construct()`魔术方法代表了 PHP 构造函数概念，类似于其他 OO 语言。它允许开发人员参与对象创建过程。具有`__construct()`方法声明的类，在每个新创建的对象上调用它。这使我们能够处理对象在使用之前可能需要的任何初始化。

以下代码片段显示了`__construct()`方法的最简单可能的用法：

```php
<?php

class User
{
  public function __construct()
  {
    var_dump('__construct');
  }
}

new User;
new User();

```

两个`User`实例将产生相同的`string(11) "__construct"`输出到屏幕上。更复杂的例子可能包括构造函数参数。考虑以下代码片段：

```php
<?php

class User
{
  protected $name;
  protected $age;

  public function __construct($name, $age)
  {
    $this->name = $name;
    $this->age = $age;
    var_dump($this->name);
    var_dump($this->age);
  }
}

new User; #1
new User('John'); #2
new User('John', 34); #3
new User('John', 34, 4200.00); #4

```

在这里，我们看到一个接受两个参数`$name`和`$age`的`__construct()`方法。在`User`类定义之后，我们有四个不同的对象初始化尝试。尝试`#3`是唯一有效的初始化尝试。尝试`#1`和`#2`触发以下错误：

```php
Warning: Missing argument 1 for User::__construct() // #1
Warning: Missing argument 2 for User::__construct() // #1 & #2

```

尝试`#4`，即使无效，也不会触发错误。与其他方法不同，当`__construct()`被额外参数覆盖时，PHP 不会生成错误消息。

`__construct()`方法的另一个有趣的案例是与父类一起使用。让我们考虑以下例子：

```php
<?php

class User
{
  protected $name;
  protected $age;

  public function __construct($name, $age)
  {
    $this->name = $name;
    $this->age = $age;
  }
}

class Employee extends User
{
  public function __construct($employeeName, $employeeAge)
  {
    var_dump($this->name);
    var_dump($this->age);
  }
}

new Employee('John', 34);

```

前面代码的输出如下：

```php
NULL NULL

```

原因是如果子类定义了构造函数，父构造函数不会被隐式调用。要触发父构造函数，我们需要在子构造函数中运行`parent::__construct()`。让我们修改我们的`Employee`类来做到这一点：

```php
class Employee extends User
{
 public function __construct($employeeName, $employeeAge)
 {
   parent::__construct($employeeName, $employeeAge);
   var_dump($this->name);
   var_dump($this->age);
 }
}

```

现在将输出如下：

```php
 string(4) "John" int(34)

```

让我们看下面的例子：

```php
<?php

class User
{
  public function __construct()
  {
    var_dump('__construct');
  }

  public static function hello($name)
  {
    return 'Hello ' . $name;
  }
}

echo User::hello('John');

```

在这里，我们有一个简单的`User`类，有一个魔术`__construct()`和一个静态`hello()`方法。在类定义之后，我们调用静态`hello()`方法。这不会触发`__construct()`方法。

前面例子的唯一输出如下：

```php
Hello John

```

`__construct()`方法只在通过`new`关键字初始化对象时触发。

我们希望保持我们的`__construct()`方法，以及其他魔术方法，只在`public`访问修饰符下。然而，如果情况需要，我们可以自由地将`finally`访问修饰符混合在一起

考虑以下例子：

```php
<?php

class User
{
 public final function __construct($name)
 {
 var_dump($name);
 }
}

class Director extends User
{

}

class Employee extends User
{
 public function __construct($name)
 {
 var_dump($name);
 }
}

new User('John'); #1
new Director('John'); #2
new Employee('John'); #3

```

因此，初始化尝试`#1`和`#2`即使使用`final`访问修饰符也会运行。这是因为`#1`实例化了定义了 final `__construct()`方法的原始`User`类，而`#2`实例化了不尝试实现自己的`__construct()`方法的空`Director`类。初始化尝试`#3`将失败，导致以下错误：

```php
Fatal error: Cannot override final method User::__construct()

```

这实际上是访问修饰符和覆盖的基础，而不是特定于`__construct()`魔术方法本身。然而，值得知道的是，可以使用`final`修饰符与构造函数，因为这可能会派上用场。

除了实例化简单对象外，面向对象编程中`__construct()`方法的实际用途以**依赖注入**的形式出现。如今，注入依赖关系通常被认为是处理依赖关系的一种方法。虽然依赖关系可以通过各种 setter 方法注入到对象中，但在一些主要的 PHP 平台上，如 Magento，使用`__construct()`方法作为主要方法仍然占主导地位。

以下代码块演示了 Magento 的`vendor/magento/module-gift-message/Model/Save.php`文件中的`__construct()`方法：

```php
 public function __construct(
   \Magento\Catalog\Api\ProductRepositoryInterface $productRepository,
   \Magento\GiftMessage\Model\MessageFactory $messageFactory,
   \Magento\Backend\Model\Session\Quote $session,
   \Magento\GiftMessage\Helper\Message $giftMessageMessage
 ) {
   $this->productRepository = $productRepository;
   $this->_messageFactory = $messageFactory;
   $this->_session = $session;
   $this->_giftMessageMessage = $giftMessageMessage;
 }

```

通过`__construct()`方法传递了几个依赖项，这似乎比以前的例子要复杂得多。即便如此，Magento 的大多数`__construct()`方法要比这个更加健壮，向对象传递了数十个参数。

我们可以轻松总结`__construct()`方法的作用，它是一种类签名，表示消费者应该如何完全实例化特定对象。

# 使用 __destruct()

除了构造函数，析构函数是面向对象语言的常见特性。`__destruct()`魔术方法代表了这个概念。一旦没有其他引用指向特定对象，该方法就会被触发。这可能是当 PHP 决定显式释放对象时，也可能是我们使用`unset()`语言构造强制释放对象时发生的。

与构造函数一样，父析构函数不会被 PHP 隐式调用。为了运行父析构函数，我们需要显式调用`parent::__destruct()`。此外，如果子类没有实现自己的析构函数，则子类继承父类的析构函数。

假设我们有一个以下简单的`User`类：

```php
<?php

class User
{
   public function __destruct()
   {
      echo '__destruct';
   }
}

```

有了`User`类，让我们继续查看实例创建示例：

```php
echo 'A';
new User();
echo 'B';

// outputs "A__destructB"

```

这里的`new User();`表达式将`User`类的一个实例实例化为*空气*，因为它没有将新实例化的对象分配给变量。这是 PHP 明确调用`__destruct()`方法的触发器，导致`A__destructB`字符串：

```php
echo 'A';
$user = new User();
echo 'B';

// outputs "AB__destruct"

```

这里的`new User();`表达式将`User`类的一个实例实例化为`$user`变量。这可以防止 PHP 立即触发，因为脚本可能会在路径的后面使用`$user`变量。尽管如此，PHP 在得出结论`$user`变量没有被引用时，会显式调用`__destruct()`方法，导致`AB__destruct`字符串。

```php
echo 'A';
$user = new User();
echo 'B';
unset($user);
echo 'C';

// outputs "AB__destructC"

```

在这里，我们稍微扩展了前面的例子。我们使用`unset()`语言构造来强制销毁表达式之间的`$user`变量。调用`unset()`基本上是 PHP 执行对象的`__destruct()`方法的隐式触发器，导致`AB__destructC`字符串。

```php
echo 'A';
$user = new User();
echo 'B';
exit;
echo 'C';

// outputs "AB__destruct"

```

在这里，我们在`C`字符串输出之前调用`exit()`语言构造。这作为 PHP 的隐式触发器，表明没有更多的引用指向`$user`变量，因此可以执行对象的`__destruct()`方法。结果输出是`AB__destruct`字符串。

某些情况可能会诱使我们从`__destruct()`方法中调用`exit()`构造函数，因为在`__destruct()`中调用`exit()`会阻止剩余的关闭例程执行。同样，从`__destruct()`方法抛出异常只会在脚本终止时触发致命错误。这绝不是处理应用程序状态的方法。

大多数情况下，析构函数不是我们想要或需要自己实现的东西。我们的大多数类可能不需要它，因为 PHP 本身在清理方面做得相当不错。然而，有些情况下，我们可能希望在对象不再被引用后立即释放对象消耗的资源。`__destruct()`方法允许在对象终止时进行某些后续操作。

# 使用 __call()

重载是面向对象编程中一个熟悉的术语。然而，并非所有编程语言都以相同的方式解释它。PHP 中的重载概念与其他面向对象语言大不相同。传统上，重载提供了使用相同名称但不同参数的多个方法的能力，而在 PHP 中，重载意味着动态创建方法和属性。

不幸的是，对术语重载的误用为一些开发人员增加了困惑，因为对于这种类型的功能，更合适的术语可能是*解释器挂钩*。

PHP 中支持方法重载的两个魔术方法是`__call()`和`__callStatic()`。在本节中，我们将更仔细地看看`__call()`方法。

在*对象上下文*中调用不可访问方法时，将触发`__call()`魔术方法。该方法接受两个参数，如下概要所示：

```php
public mixed __call(string $name, array $arguments)

```

然而，`__call()`方法的参数具有以下含义：

+   `$name`：这是被调用的方法的名称

+   `$arguments`：这是一个包含传递给`$name`方法的参数的枚举数组

以下示例演示了在对象上下文中使用`__call()`方法：

```php
<?php

class User
{
 public function __call($name, $arguments)
 {
 echo $name . ': ' . implode(', ', $arguments) . PHP_EOL;
 }

 public function bonus($amount)
 {
 echo 'bonus: ' . $amount . PHP_EOL;
 }
}

$user = new User();
$user->hello('John', 34);
$user->bonus(560.00);
$user->salary(4200.00);

```

`User`类本身只声明了`__call()`和`bonus()`方法。`$user`对象尝试调用`hello()`、`bonus()`和`salary()`方法。这实际上意味着对象试图调用两个缺失的方法：`hello()`和`salary()`。缺失的两个方法会触发`__call()`方法，从而产生以下输出：

```php
__call => hello: John, 34
bonus: 560
__call => salary: 4200

```

我们可以在 Magento 平台中找到`__call()`方法的一个很好的用例示例，如下面从`vendor/magento/framework/DataObject.php`类文件中摘取的条目：

```php
public function __call($method, $args)
{
   switch (substr($method, 0, 3)) {
     case 'get':
       $key = $this->_underscore(substr($method, 3));
       $index = isset($args[0]) ? $args[0] : null;
     return $this->getData($key, $index);
     case 'set':
       $key = $this->_underscore(substr($method, 3));
       $value = isset($args[0]) ? $args[0] : null;
     return $this->setData($key, $value);
     case 'uns':
       $key = $this->_underscore(substr($method, 3));
     return $this->unsetData($key);
     case 'has':
       $key = $this->_underscore(substr($method, 3));
     return isset($this->_data[$key]);
   }
   // ...
}

```

不需要深入了解 Magneto 本身，可以说他们的`DataObject`类在整个框架中充当根数据对象。`__call()`方法中的代码使其能够在对象实例上魔法地*获取*、*设置*、*取消设置*和*检查*属性的存在。这在后续表达式中使用，例如从`vendor/magento/module-checkout/Controller/Cart/Configure.php`文件中摘取的以下条目：

```php
$params = new \Magento\Framework\DataObject();
$params->setCategoryId(false);
$params->setConfigureMode(true);
$params->setBuyRequest($quoteItem->getBuyRequest());

```

好处在于我们可以轻松地为`DataObject`的实例赋予可能存在也可能不存在的魔术方法。例如，`setCategoryId()`是`DataObject`类上不存在的方法。由于它不存在，调用它会触发`__call()`方法。这一点一开始可能不太明显，因此让我们考虑另一个想象的例子，我们的自定义类从`DataObject`继承：

```php
<?php

class User extends \Magento\Framework\DataObject
{

}

$user = new User();

$user->setName('John');
$user->setAge(34);
$user->setSalary(4200.00);

echo $user->getName();
echo $user->getAge();
echo $user->getSalary();

```

注意我们通过`__call()`魔术方法在这里实现的*设置器*和*获取器*的*美丽和简单*。尽管我们的`User`类基本上是空的，但我们已经继承了父类`__call()`实现的魔术。

`__call()`方法赋予我们一些真正有趣的可能性，其中大部分将作为框架或库的一部分。

# 使用 __callStatic()

`__callStatic()`魔术几乎与`__call()`方法相同。`__call()`方法绑定到*对象上下文*，而`__callStatic()`方法绑定到*静态上下文*，这意味着在通过作用域解析运算符（`::`）调用不可访问的方法时会触发此方法。

该方法根据以下概要接受两个参数：

```php
public static mixed __callStatic (string $name, array $arguments)

```

请注意，在方法声明中使用静态访问修饰符，这是静态上下文所需的。以下示例演示了在静态上下文中使用`__callStatic()`方法：

```php
<?php

class User
{
  public static function __callStatic($name, $arguments)
  {
    echo '__callStatic => ' . $name . ': ' . implode(', ', $arguments)
      . PHP_EOL;
  }

  public static function bonus($amount)
  {
  echo 'bonus: ' . $amount . PHP_EOL;
  }
}

```

代码将产生以下输出：

```php
User::hello('John', 34);
User::bonus(560.00);
User::salary(4200.00);

```

`User`类本身只声明了`__callStatic()`和`bonus()`方法。`User`类尝试调用静态`hello()`，`bonus()`和`salary()`方法。这实际上意味着该类试图调用两个缺失的方法：`hello()`和`salary()`。对于缺失的两个方法，`__callStatic()`方法会启动，从而产生以下输出：

```php
__callStatic => hello: John, 34
bonus: 560
__callStatic => salary: 4200

```

在面向对象编程中，静态上下文比对象上下文更少见，这使得`__callStatic()`方法比`__call()`方法更少使用。

# 使用 __set()

除了*方法重载*之外，*属性重载*是 PHP 重载功能的另一个方面。 PHP 中有四个魔术方法支持属性重载：`__set()`，`__get()`，`__isset()`和`__unset()`。在本节中，我们将更仔细地看一下`__set()`方法。

尝试向不可访问的属性写入数据时，将触发`__set()`魔术方法。

该方法根据以下概要接受两个参数：

```php
public void __set(string $name, mixed $value)

```

而`__set()`方法的参数具有以下含义：

+   `$name`：这是正在交互的属性的名称

+   `$value`：这是`$name`属性应该设置的值

让我们看一下以下对象上下文示例：

```php
<?php

class User
{
  private $data = array();

  private $name;
  protected $age;
  public $salary;

  public function __set($name, $value)
  {
    $this->data[$name] = $value;
  }
}

$user = new User();
$user->name = 'John';
$user->age = 34;
$user->salary = 4200.00;
$user->message = 'hello';

var_dump($user);

```

`User`类声明了四个具有不同访问修饰符的属性。它进一步声明了`__set()`方法，该方法拦截对象上下文中的所有属性写入尝试。尝试设置不存在的（`$message`）或不可访问的（`$name`，`$age`）属性会触发`__set()`方法。`__set()`方法的内部工作将不可访问的数据推送到`$data`属性数组中，这在以下输出中可见：

```php
object(User)#1 (4) {
  ["data":"User":private]=> array(3) {
    ["name"]=> string(4) "John"
    ["age"]=> int(34)
    ["message"]=> string(5) "hello"
  }
  ["name":"User":private]=> NULL
  ["age":protected]=> NULL
  ["salary"]=> float(4200)
}

```

`__set()`方法的一个实际用途可能是允许在对象构造期间将属性设置为`true`；否则，抛出异常。

在静态上下文中尝试使用四种属性重载方法（`__set()`，`__get()`，`__isset()`和`__unset()`）将导致以下错误：

```php
PHP Warning: The magic method __set() must have public visibility and cannot be static...

```

# 使用 __get()

尝试从不可访问的属性中读取数据时，将触发`__get()`魔术方法。该方法根据以下概要接受一个参数：

```php
public mixed __get(string $name)

```

`$name`参数是正在交互的属性的名称。

让我们看一下以下对象上下文示例：

```php
<?php

class User
{
  private $data = [
    'name' => 'Marry',
    'age' => 32,
    'salary' => 5300.00,
  ];

  private $name = 'John';
  protected $age = 34;
  public $salary = 4200.00;

  public function __get($name)
  {
    if (array_key_exists($name, $this->data)) {
      echo '__get => ' . $name . ': ' . $this->data[$name] . PHP_EOL;
    } else {
      trigger_error('Undefined property: ' . $name, E_USER_NOTICE);
    }
  }
}

$user = new User();

echo $user->name . PHP_EOL;
echo $user->age . PHP_EOL;
echo $user->salary . PHP_EOL;
echo $user->message . PHP_EOL;

```

`User`类定义了四个不同的属性，跨越三种不同的可见性访问修饰符。由于我们没有获取器方法来访问所有单独的属性，唯一可直接访问的属性是`public $salary`。这就是`__get()`方法派上用场的地方，因为一旦我们尝试访问不存在或无法访问的属性，它就会启动。前面代码的结果输出为以下四行：

```php
__get => name: Marry

__get => age: 32

4200

PHP Notice: Undefined property: message in...

```

`age`和`name`的值是从`$data`属性中获取的，这是`__get()`方法内部工作的结果。

# 使用 __isset()

`__isset()`魔术方法是通过调用`isset()`或`empty()`语言结构来触发的。该方法根据以下概要接受一个参数：

```php
public bool __isset(string $name)

```

`$name`参数是正在交互的属性的名称。

让我们看一下以下对象上下文示例：

```php
<?php

class User
{
  private $data = [
    'name' => 'John',
    'age' => 34,
  ];

  public function __isset($name)
  {
    if (array_key_exists($name, $this->data)) {
      return true;
    }

    return false;
  }
}

$user = new User();

var_dump(isset($user->name));

```

`User`类定义了一个名为`$data`的单个受保护的数组属性，以及一个魔术`__isset()`方法。当前方法的内部工作只是针对`$data`数组键名进行查找，并在数组中找到键时返回`true`，否则返回`false`。示例的结果输出为`bool(true)`。

Magento 平台为`vendor/magento/framework/HTTP/PhpEnvironment/Request.php`类文件的`__isset()`方法提供了一个有趣且实用的用例：

```php
public function __isset($key)
{
  switch (true) {
    case isset($this->params[$key]):
    return true;

    case isset($this->queryParams[$key]):
    return true;

    case isset($this->postParams[$key]):
    return true;

    case isset($_COOKIE[$key]):
    return true;

    case isset($this->serverParams[$key]):
    return true;

    case isset($this->envParams[$key]):
    return true;

    default:
    return false;
  }
}

```

这里的`Magento\Framework\HTTP\PhpEnvironment\Request`类代表了 PHP 环境及其所有可能的请求数据。请求数据可以来自许多来源：查询字符串、`$_GET`、`$_POST`等。`switch`语句遍历了这些源数据变量（`$params`、`$queryParams`、`$postParams`、`$serverParams`、`$envParams`、`$_COOKIE`），以查找并确认请求参数的存在。

# 使用 __unset()

通过调用`unset()`语言构造函数来触发`__unset()`魔术方法，该方法接受一个参数，如下概要所示：

```php
public bool __unset(string $name)

```

`$name`参数是正在交互的属性的名称。

让我们看一下以下对象上下文示例：

```php
<?php

class User
{
  private $data = [
    'name' => 'John',
    'age' => 34,
  ];

  public function __unset($name)
  {
    unset($this->data[$name]);
  }
}

$user = new User();

var_dump($user);
unset($user->age);
unset($user->salary);
var_dump($user);

```

`User`类声明了一个单个私有的`$data`数组属性，以及`__unset()`魔术方法。这个方法本身非常简单；它只是调用`unset()`并传递给它给定数组键的值。我们正在尝试取消`$age`和`$salary`属性。`$salary`属性实际上并不存在，既不是类属性，也不是`data`数组的键。幸运的是，`unset()`不会抛出`Undefined index`类型的错误，因此我们不需要额外的`array_key_exists()`检查。以下的输出显示了从对象实例中删除了`$age`属性：

```php
object(User)#1 (1) {
  ["data":"User":private]=> array(2) {
    ["name"]=> string(4) "John"
    ["age"]=> int(34)
  }
}

object(User)#1 (1) {
  ["data":"User":private]=> array(1) {
    ["name"]=> string(4) "John"
  }
}

```

我们不应该混淆`unset()`构造与`(unset)`转换的用法。这两者是不同的操作，因此`(unset)`转换不会触发`__unset()`魔术方法。

```php
unset($user->age); // will trigger __unset()
((unset) $user->age); // won't trigger __unset()

```

# 使用 __sleep()

对象序列化是面向对象编程的另一个重要方面。PHP 提供了一个`serialize()`函数，允许我们对传递给它的值进行序列化。结果是一个包含可以存储在 PHP 中的任何值的字节流表示的字符串。对标量数据类型和简单对象进行序列化是非常简单的，如下例所示：

```php
<?php

$age = 34;
$name = 'John';

$obj = new stdClass();
$obj->age = 34;
$obj->name = 'John';

var_dump(serialize($age));
var_dump(serialize($name));
var_dump(serialize($obj));

```

结果输出如下：

```php
string(5) "i:34;"
string(11) "s:4:"John";"
string(56) "O:8:"stdClass":2:{s:3:"age";i:34;s:4:"name";s:4:"John";}"

```

即使是一个简单的自定义类也可以很容易地：

```php
<?php

class User
{
  public $name = 'John';
  private $age = 34;
  protected $salary = 4200.00;
}

$user = new User();

var_dump(serialize($user));

```

上述代码的结果如下：

```php
string(81) "O:4:"User":3:{s:4:"name";s:4:"John";s:9:"Userage";i:34;s:9:"*salary";d:4200;}"

```

当我们的类在大小上要么很重要，要么包含资源类型的引用时，就会出现问题。`__sleep()`魔术方法以一种方式解决了这些挑战。它的预期用途是提交未决数据或执行相关的清理任务。当我们有不需要完全序列化的大型对象时，该函数非常有用。

`serialize()`函数会在对象存在时触发对象的`__sleep()`方法。实际触发是在序列化过程开始之前完成的。这使对象能够明确列出它想要允许序列化的字段。`__sleep()`方法的返回值必须是一个包含我们想要序列化的所有对象属性名称的数组。如果该方法不返回可序列化的属性名称数组，则会序列化为`NULL`并发出`E_NOTICE`。

以下示例演示了一个简单的`User`类，其中包含一个简单的`__sleep()`方法的实现：

```php
<?php

class User
{
  public $name = 'John';
  private $age = 34;
  protected $salary = 4200.00;

  public function __sleep() 
  {
    // Cleanup & other operations???
    return ['name', 'salary'];
  }
}

$user = new User();

var_dump(serialize($user));

```

`__sleep()`方法的实现清楚地说明`User`类的唯一两个可序列化属性是`name`和`salary`。请注意，实际名称以字符串形式提供，没有`$`符号，这导致输出如下：

```php
string(60) "O:4:"User":2:{s:4:"name";s:4:"John";s:9:"*salary";d:4200;}"

```

将对象序列化以存储在数据库中是一种危险的做法，应尽可能避免。需要复杂对象序列化的情况很少。即使有这样的情况，也很可能是应用设计不当的标志。

# 使用 __wakeup()

关于可序列化对象的主题如果没有`serialize()`方法的对应方法--`unserialize()`方法，将不完整。如果`serialize()`方法调用触发对象的`__sleep()`魔术方法，那么可以合理地期望反序列化也有类似的行为。因此，在给定对象上调用`unserialize()`方法将触发其`__wakeup()`魔术方法。

`__wakeup()`的预期用途是重新建立在序列化过程中可能丢失的任何资源，并执行其他重新初始化任务。

让我们看下面的例子：

```php
<?php

class Backup
{
  protected $ftpClient;
  protected $ftpHost;
  protected $ftpUser;
  protected $ftpPass;

  public function __construct($host, $username, $password)
  {
    $this->ftpHost = $host;
    $this->ftpUser = $username;
    $this->ftpPass = $password;

    echo 'TEST!!!' . PHP_EOL;

    $this->connect();
  }

  public function connect()
  {
    $this->ftpClient = ftp_connect($this->ftpHost, 21, 5);
    ftp_login($this->ftpClient, $this->ftpUser, $this->ftpPass);
  }

  public function __sleep()
  {
    return ['ftpHost', 'ftpUser', 'ftpPass'];
  }

  public function __wakeup()
  {
    $this->connect();
  }
}

$backup = new Backup('test.rebex.net', 'demo', 'password');
$serialized = serialize($backup);
$unserialized = unserialize($serialized);

var_dump($backup);
var_dump($serialized);
var_dump($unserialized);

```

`Backup`类通过其构造函数接受主机、用户名和密码信息。在内部，它将核心 PHP 的`ftp_connect()`函数设置为建立与 FTP 服务器的连接。成功建立的连接返回一个资源，我们将其存储到类的受保护的`$ftpClient`属性中。由于资源不可序列化，我们确保将其从`__sleep()`方法返回数组中排除。这确保我们的序列化字符串不包含`$ftpHost`属性。我们进一步在`__wakeup()`方法中设置了`$this->connect();`调用，以重新初始化`$ftpHost`资源。整体示例结果如下输出：

```php
object(Backup)#1 (4) {
  ["ftpClient":protected]=> resource(4) of type (FTP Buffer)
  ["ftpHost":protected]=> string(14) "test.rebex.net"
  ["ftpUser":protected]=> string(4) "demo"
  ["ftpPass":protected]=> string(8) "password"
}

string(119) "O:6:"Backup":3:{s:10:"*ftpHost";s:14:"test.rebex.net";s:10:"*ftpUser";s:4:"demo";s:10:"*ftpPass";s:8:"password";}"

object(Backup)#2 (4) {
  ["ftpClient":protected]=> resource(5) of type (FTP Buffer)
  ["ftpHost":protected]=> string(14) "test.rebex.net"
  ["ftpUser":protected]=> string(4) "demo"
  ["ftpPass":protected]=> string(8) "password"
}

```

`__wakeup()`方法在`unserialize()`函数调用期间承担了构造函数的角色。因为对象的`__construct()`方法在反序列化期间不会被调用，所以我们需要小心地实现必要的`__wakeup()`方法逻辑，以便对象可以重建可能需要的任何资源。

# 使用 __toString()

`__toString()`魔术方法在我们将对象用于字符串上下文时触发。它允许我们决定对象在被视为字符串时的反应方式。

让我们看下面的例子：

```php
<?php

class User
{
  protected $name;
  protected $age;

  public function __construct($name, $age)
  {
    $this->name = $name;
    $this->age = $age;
  }
}

$user = new User('John', 34);
echo $user;

```

在这里，我们有一个简单的`User`类，通过其构造方法接受`$name`和`$age`参数。除此之外，没有其他内容表明类应如何响应尝试在字符串上下文中使用它，这正是我们在类声明后立即做的，因为我们试图`echo`对象实例本身。

在其当前形式下，生成的输出将如下所示：

```php
Catchable fatal error: Object of class User could not be converted to string in...

```

`__toString()`魔术方法允许我们简单而优雅地规避这个错误：

```php
<?php

class User
{
  protected $name;
  protected $age;

  public function __construct($name, $age)
  {
    $this->name = $name;
    $this->age = $age;
  }

  public function __toString()
  {
    return $this->name . ', age ' . $this->age;
  }
}

$user = new User('John', 34);
echo $user;

```

通过添加`__toString()`魔术方法，我们能够将对象的结果字符串表示定制为以下代码行：

```php
John, age 34

```

Guzzle HTTP 客户端通过其 PSR7 HTTP 消息接口实现提供了`__toString()`方法的实际用例示例；而一些实现使用了`__toString()`方法。以下代码片段是 Guzzle 的`vendor/guzzlehttp/psr7/src/Stream.php`类文件的部分提取，该文件实现了`Psr\Http\Message\StreamInterface`接口：

```php
 public function __toString()
 {
   try {
     $this->seek(0);
     return (string) stream_get_contents($this->stream);
   } catch (\Exception $e) {
     return '';
   }
 }

```

在逻辑丰富的`__toString()`实现中，`try...catch`块基本上是一种常态。这是因为我们不能从`__toString()`方法中抛出异常。因此，我们需要确保没有错误逃逸。

# 使用 __invoke()

`__invoke()`魔术方法在对象被调用为函数时触发。该方法接受可选数量的参数，并能够返回各种类型的数据，或者根本不返回数据，如下概要所示：

```php
mixed __invoke([ $... ])

```

如果对象类实现了`__invoke()`方法，我们可以通过在对象名称后面加上括号`()`来调用该方法。这种类型的对象称为函数对象或函数对象。

维基百科页面（[`en.wikipedia.org/wiki/Functor`](https://en.wikipedia.org/wiki/Functor)）提供了有关函数子的更多信息。

以下代码块演示了简单的`__invoke()`实现：

```php
<?php

class User
{
  public function __invoke($name, $age)
  {
    echo $name . ', ' . $age;
  }
}

```

`__invoke()`方法可以通过将对象实例作为函数使用或调用`call_user_func()`来触发。

```php
$user = new User();

$user('John', 34); // outputs: John, 34

call_user_func($user, 'John', 34); // outputs: John, 34

```

使用`__invoke()`方法，我们可以将我们的类伪装成。

```php
var_dump(is_callable($user)); // true

```

使用`__invoke()`的好处之一是，它可以创建一个跨语言的标准回调类型。这比在引用函数、对象实例方法或类静态方法时使用字符串、对象和数组的组合更方便，通过`call_user_func()`函数。

`__invoke()`方法作为强大的语言补充，我们认为它提供了新的开发模式的机会；尽管它的滥用可能会导致代码不清晰和混乱。

# 使用 __set_state()

`__set_state()`魔术方法被触发（实际上并没有）用于`var_export()`函数导出的类。该方法接受一个单一的数组类型参数，并返回一个对象，如下概要所示：

```php
static object __set_state(array $properties)

```

`var_export()`函数输出或返回给定变量的可解析字符串表示。它与`var_dump()`函数有些类似，不同之处在于返回的表示是有效的 PHP。

```php
<?php

class User
{
  public $name = 'John';
  public $age = 34;
  private $salary = 4200.00;
  protected $identifier = 'ABC';
}

$user = new User();
var_export($user); // outputs string "User::__set_state..."
var_export($user, true); // returns string "User::__set_state..."

```

这导致了以下输出：

```php
User::__set_state(array(
 'name' => 'John',
 'age' => 34,
 'salary' => 4200.0,
 'identifier' => 'ABC',
))

string(113) "User::__set_state(array(
 'name' => 'John',
 'age' => 34,
 'salary' => 4200.0,
 'identifier' => 'ABC',
))"

```

使用`var_export()`函数实际上不会触发我们的`User`类的`__set_state()`方法。它只产生一个`User::__set_state(array(...))`表达式的字符串表示，我们可以记录、输出或通过`eval()`语言结构进行执行。

以下代码片段是一个更健壮的示例，演示了`eval()`的使用：

```php
<?php

class User
{
  public $name = 'John';
  public $age = 34;
  private $salary = 4200.00;
  protected $identifier = 'ABC';

  public static function __set_state($properties)
  {
    $user = new User();

    $user->name = $properties['name'];
    $user->age = $properties['age'];
    $user->salary = $properties['salary'];
    $user->identifier = $properties['identifier'];

    return $user;
  }
}

$user = new User();
$user->name = 'Mariya';
$user->age = 32;

eval('$obj = ' . var_export($user, true) . ';');

var_dump($obj);

```

这导致了以下输出：

```php
object(User)#2 (4) {
  ["name"]=> string(6) "Mariya"
  ["age"]=> int(32)
  ["salary":"User":private]=> float(4200)
  ["identifier":protected]=> string(3) "ABC"
}

```

了解`eval()`语言结构非常危险，因为它允许执行任意的 PHP 代码，因此不建议使用。因此，除了调试目的之外，使用`__set_state()`本身就变得值得怀疑。

# 使用 __clone()

`__clone()`魔术方法在使用`clone`关键字进行克隆的新克隆对象上触发。该方法不接受任何参数，也不返回任何值，如下概要所示：

```php
void __clone(void)

```

在对象克隆方面，我们倾向于区分深拷贝和浅拷贝。深拷贝会复制所有对象可能指向的对象。浅拷贝尽可能少地复制，将对象引用留作引用。虽然浅拷贝可能对抗循环引用很有用，但不一定是期望的行为，因为它会复制所有属性，无论它们是引用还是值。

以下示例演示了`__clone()`方法的实现和`clone`关键字的使用：

```php
<?php

class User
{
  public $identifier;

  public function __clone()
  {
    $this->identifier = null;
  }
}

$user = new User();
$user->identifier = 'john';

$user2 = clone $user;

var_dump($user);
var_dump($user2);

```

这导致了以下输出：

```php
object(User)#1 (1) {
  ["identifier"]=> string(4) "john"
}

object(User)#2 (1) {
  ["identifier"]=> NULL
}

```

关于`__clone()`方法的重要要点是，它并不是克隆过程的覆盖。正常的克隆过程总是会发生。`__clone()`方法只是承担了修正错误的责任，我们可能对结果不满意时会使用它。

# 使用 __debugInfo()

当调用`var_dump()`函数时，`__debugInfo()`魔术方法会被触发。默认情况下，`var_dump()`函数显示对象的所有公共、受保护和私有属性。但是，如果对象类实现了`__debugInfo()`魔术方法，我们可以控制`var_dump()`函数的输出。该方法不接受任何参数，并返回一个要显示的键值数组，如下概要所示：

```php
array __debugInfo(void)

```

以下示例演示了`__debugInfo()`方法的实现：

```php
<?php

class User
{
  public $name = 'John';
  public $age = 34;
  private $salary = 4200.00;
  private $bonus = 680.00;
  protected $identifier = 'ABC';
  protected $logins = 67;

  public function __debugInfo()
  {
    return [
      'name' => $this->name,
      'income' => $this->salary + $this->bonus
    ];
  }
}

$user = new User();

var_dump($user);

```

这导致了以下输出：

```php
object(User)#1 (2) {
  ["name"]=> string(4) "John"
  ["income"]=> float(4880)
}

```

虽然`__debugInfo()`方法对于定制我们自己的`var_dump()`输出很有用，但这可能不是我们在日常开发中必须做的事情。

# 流行平台上的使用统计

PHP 生态系统可以说是非常庞大的。有数十个免费和开源的 CMS、CRM、购物车、博客和其他平台和库。WordPress、Drupal 和 Magento 可能是在博客、内容管理和购物车解决方案方面最受欢迎的平台之一。它们都可以从各自的网站上下载：

+   WordPress: [`wordpress.org`](https://wordpress.org)

+   Drupal: [`www.drupal.org`](https://www.drupal.org)

+   Magento: [`magento.com/`](https://magento.com/)

考虑到这些流行平台，以下表格对魔术方法的使用进行了一些说明：

| **魔术方法** | **WordPress 4.7****(702 .php files)** | **Drupal 8.2.4****(8199 .php files)** | **Magento CE 2.1.3****(29649 .php files)** |
| --- | --- | --- | --- |
| `__construct()` | 343 | 2547 | 12218 |
| `__destruct()` | 19 | 19 | 77 |
| `__call()` | 10 | 35 | 152 |
| `__callStatic()` | 1 | 2 | 4 |
| `__get()` | 23 | 31 | 125 |
| `__set()` | 15 | 24 | 86 |
| `__isset()` | 21 | 15 | 57 |
| `__unset()` | 11 | 13 | 34 |
| `__sleep()` | 0 | 46 | 103 |
| `__wakeup()` | 0 | 10 | 94 |
| `__toString()` | 15 | 181 | 460 |
| `__invoke()` | 0 | 27 | 112 |
| `__set_state()` | 0 | 3 | 5 |
| `__clone()` | 0 | 32 | 68 |
| `__debugInfo()` | 0 | 0 | 2 |

该表是对整个平台代码库中`function __[magic-method-name]`的粗略搜索结果。很难在此基础上得出任何结论，因为平台在`.php`文件数量上有显著差异。有一件事我们可以肯定——并非所有魔术方法都同样受欢迎。例如，WordPress 似乎甚至没有使用`__sleep()`、`__wakeup()`和`__invoke()`方法，这些方法在面向对象编程中很重要。这可能是因为 WordPress 处理的 OO 组件没有像 Magento 那样多，后者在架构上更多地是一个面向对象的平台。Drupal 在这里有点中庸，在总的`.php`文件数量和使用的魔术方法方面。无论是否有定论，上表概述了 PHP 提供的几乎每个魔术方法的活跃使用。

# 总结

在本章中，我们详细研究了 PHP 提供的每个魔术方法。它们的易用性和它们为语言带来的功能同样令人印象深刻。通过适当命名我们的类方法，我们能够利用对象状态和行为的几乎每个方面。虽然这些魔术方法大多数情况下不是我们日常使用的东西，但它们的存在赋予了我们一些巧妙的架构风格和解决方案，这些解决方案在其他语言中并不容易实现。

未来，我们将进入 CLI 领域和更难以捉摸的 PHP 使用。


# 第五章：CLI 的领域

现代应用程序开发涉及许多可见的部分。无论是服务器基础设施、开发工具还是最终的应用程序本身，图形界面都主导着我们的体验。虽然可用的 GUI 工具的多样性和整体列表似乎是无穷无尽的，但控制台仍然是开发中的一个重要部分，任何自尊的开发人员都应该熟悉。

有无数理由说明控制台只是工作的正确工具。以大型数据库备份为例。尝试通过 GUI 工具备份几 GB 的 MySQL 数据很可能会导致完全失败或损坏的备份文件，而基于控制台的`mysqldump`工具对备份的大小或执行所需的时间都是无所畏惧的。诸如大型和耗时的数据导入、数据导出、数据同步等操作是许多 PHP 应用程序的常见操作。这些只是我们希望从浏览器中移出并进入控制台的一些操作。

在本章中，我们将查看以下部分：

+   理解 PHP CLI

+   控制台组件

+   输入/输出流

+   进程控制：

+   滴答声

+   信号

+   警报

+   多处理

# 理解 PHP CLI

通过 PHP CLI SAPI 或简称 PHP CLI，通过 PHP CLI 在 PHP 中使用控制台非常容易。PHP CLI 首次在 PHP 4.2.0 中作为实验性功能引入，不久之后，在后续版本中成为完全支持并默认启用的功能。它的好处在于它在所有流行的操作系统（Linux、Windows、OSX、Solaris）上都可用。这使得编写几乎在任何平台上执行的控制台应用程序变得容易。

查看[`en.wikipedia.org/wiki/Command-line_interface`](https://en.wikipedia.org/wiki/Command-line_interface)和[`en.wikipedia.org/wiki/Server_Application_Programming_Interface`](https://en.wikipedia.org/wiki/Server_Application_Programming_Interface)以获取有关一般 CLI 和 SAPI 缩写的更详细描述。

PHP CLI 并不是 PHP 支持的唯一 SAPI 接口。使用`php_sapi_name()`函数，我们可以获得 PHP 正在使用的当前接口的名称。其他可能的接口包括 aolserver、apache、apache2handler、cgi、cgi-fcgi、cli、cli-server、continuity、embed、fpm-fcgi 等。

在我们的操作系统控制台中运行简单的`php -v`命令应该给我们一个类似以下的输出：

```php
PHP 7.1.0-3+deb.sury.org~yakkety+1 (cli) ( NTS )
Copyright (c) 1997-2016 The PHP Group
Zend Engine v3.1.0-dev, Copyright (c) 1998-2016 Zend Technologies
 with Zend OPcache v7.1.0-3+deb.sury.org~yakkety+1, Copyright (c) 1999-2016, by Zend Technologies

```

这应该作为 PHP CLI SAPI 正在运行的确认。PHP 的 CLI 版本有自己的`php.ini`配置，与其他 SAPI 接口分开。在控制台上运行`php --ini`命令将公开有关当前使用的`php.ini`文件的以下详细信息：

```php
Configuration File (php.ini) Path: /etc/php/7.1/cli
Loaded Configuration File: /etc/php/7.1/cli/php.ini
Scan for additional .ini files in: /etc/php/7.1/cli/conf.d
Additional .ini files parsed: /etc/php/7.1/cli/conf.d/10-opcache.ini,
/etc/php/7.1/cli/conf.d/10-pdo.ini,
/etc/php/7.1/cli/conf.d/20-calendar.ini,
/etc/php/7.1/cli/conf.d/20-ctype.ini,
...

```

在这里，我们可以看到主配置文件（`php.ini`）和特定于扩展的配置文件的位置。链接这些配置文件的配置会立即生效，因为它们在每次调用 PHP 时都会加载。

# 控制台组件

许多流行的 PHP 框架和平台利用某种控制台应用程序来协助开发、部署和维护我们的项目。例如，Symfony 框架自带自己的控制台应用程序，具有数十个巧妙的命令。这些可以通过在 Symfony 项目的根目录中执行`php bin/console`命令来访问：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/086af8a0-b484-4fb2-bec4-888e392047ae.png)

列出的每个命令都执行非常具体的目的；因此，在各种方式上协助我们的项目。虽然 Symfony 框架的安装和整体细节超出了本书的范围，但其中有一个我们感兴趣的组件。控制台组件，虽然是 Symfony 框架的一部分，但也可以作为独立组件来构建这些类型的控制台应用程序。

# 设置控制台组件

控制台组件有两种风格：

+   Composer 包（Packagist 上的`symfony/console`）

+   Git 存储库（[`github.com/symfony/console`](https://github.com/symfony/console)）

鉴于 Composer 在处理 PHP 组件时是事实上的标准，我们将使用`composer require`命令快速启动我们的第一个控制台应用程序，如下所示：

```php
mkdir foggyline
cd foggyline
composer require symfony/console

```

运行此命令会触发以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/b36d8c6f-3084-456e-b8b1-e3e52611e179.png)

完成后，Composer 在我们的`foggyline`目录中生成以下结构：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/395e36f6-a466-45c8-a0ee-8034db47b8f3.png)

现在我们只需要创建一个应用程序入口文件，比如`app.php`，并包含由 Composer 生成的`vendor/autoload.php`文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/af3d0eb5-355b-41f4-8a36-59865f0a107f.png)

文件的第一行，称为*shebang*，包含自动检测脚本类型所需的指令。虽然这行本身并不是必需的，但它使得在执行应用程序脚本时，`php app.php`和`./app.php`之间有所不同。在*shebang*行之后是处理`autoload.php`的 PHP 代码和实例化`Console\Application`类。`Console\Application`类接受两个参数：应用程序的名称和我们希望分配给它的版本。在实例化和运行应用程序之间，我们有一些被注释掉的行，仅仅是演示我们通常会注册个别应用程序命令的地方。

要了解更多关于*shebang*字符序列的信息，请查看维基百科文章[`en.wikipedia.org/wiki/Shebang_(Unix)`](https://en.wikipedia.org/wiki/Shebang_(Unix))。

要使*shebang*行生效，`app.php`文件需要标记为：

```php
$ chmod +x app.php
$ ./app.php

```

有了这四行 PHP 代码，我们已经有足够的条件来执行我们的

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/3c023b4e-5e48-4cb3-9f95-af17274c9224.png)

输出以彩色和良好的格式呈现，正如我们从现代控制台应用程序所期望的那样。这只是控制台组件为我们处理的一小部分。通过这个，我们完成了控制台组件的设置。现在我们可以继续使用`$app`实例的`add()`方法来注册我们的应用程序命令。

# 创建一个控制台命令

现在我们已经设置了*裸骨*控制台应用程序，让我们创建三个命令来处理以下虚构的操作：

+   客户注册

+   客户状态设置

+   客户导出

“虚构”一词只是表示我们实际上不会关注执行命令的内部细节，因为我们的重点是理解如何重用控制台组件。

我们首先在项目的`src/Foggyline/Console/Command/`目录中创建`CustomerRegisterCommand.php`，`CustomerStatusSetCommand.php`和`CustomerExportCommand.php`。

`CustomerRegisterCommand.php`文件的内容如下：

```php
<?php

namespace Foggyline\Console\Command;

use Symfony\Component\Console\{
  Command\Command,
  Input\InputInterface,
  Output\OutputInterface
};

class CustomerRegisterCommand extends Command
{
  protected function configure()
  {
    $this->setName('customer:register')
    ->setDescription('Registers new customer.');
  }

  protected function execute(InputInterface $input, OutputInterface
    $output)
  {
    // Some imaginary logic here...
    $output->writeln('Customer registered.');
  }
}

```

`CustomerStatusSetCommand.php`文件的内容如下：

```php
<?php

namespace Foggyline\Console\Command;

use Symfony\Component\Console\{
  Command\Command,
  Input\InputInterface,
  Output\OutputInterface
};

class CustomerStatusSetCommand extends Command
{
  protected function configure()
  {
    $this->setName('customer:status:set')
    ->setDescription('Enables of disables existing customer.');
  }

  protected function execute(InputInterface $input, OutputInterface
    $output)
  {
    // Some imaginary logic here...
    $output->writeln('Customer disabled.');
  }
}

```

`CustomerExportCommand.php`文件的内容如下：

```php
<?php

namespace Foggyline\Console\Command;

use Symfony\Component\Console\{
  Command\Command,
  Input\InputInterface,
  Output\OutputInterface
};

class CustomerExportCommand extends Command
{
  protected function configure()
  {
    $this->setName('customer:export')
    ->setDescription('Exports one or more customers.');
  }

  protected function execute(InputInterface $input, OutputInterface $output)
  {
    // Some imaginary logic here...
    $output->writeln('Customers exported.');
  }
}

```

我们可以看到所有三个命令都扩展了`Symfony\Component\Console\Command\Command`，并提供了它们自己的`configure()`和`execute()`方法的实现。`configure()`方法有点像构造函数，我们可以在其中放置我们的初始配置，比如命令的名称、描述、选项、参数等。`execute()`方法是我们需要实现的实际命令逻辑的地方，或者在其他地方实现了则调用它。有了这三个命令，我们需要回到`app.php`文件并修改其内容如下：

```php
#!/usr/bin/env php
<?php   $loader = require __DIR__ . '/vendor/autoload.php'; $loader->add('Foggyline', __DIR__ . '/src/');   use Symfony\Component\Console\Application; use Foggyline\Console\Command\{
 CustomerExportCommand, CustomerRegisterCommand, CustomerStatusSetCommand };   $app = new Application('Foggyline App', '1.0.0');   $app->add(new CustomerRegisterCommand()); $app->add(new CustomerStatusSetCommand()); $app->add(new CustomerExportCommand());   $app->run();

```

与我们最初的`app.php`文件相比，这里有一些变化。请注意我们需要`autoload.php`文件的行。如果我们实际查看该文件，我们会发现它返回`Composer\Autoload\ClassLoader`类的一个实例。这是 Composer 的 PSR-0、PSR-4 和 classmap 类加载器，我们可以利用它来加载我们的命令。这正是`$loader->add('Foggyline'...`行所做的。最后，我们使用应用程序的`add()`方法注册我们新创建的命令。

在进行这些更改后，执行我们的应用程序会产生以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/079ca9bf-07c3-4f8f-bcd3-5ad1163b7797.png)

我们的三个命令现在出现在可用命令列表中。我们在`configure()`方法中设置的`name`和`description`值显示在每个命令中。我们现在可以轻松地执行其中一个命令：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/7cdae145-6fd9-4045-8634-f60bddbda2b7.png)

`Customer disabled.`标签确认了我们的`CustomerStatusSetCommand`的`execute()`方法的执行。虽然到目前为止，我们的控制台应用程序及其命令的整体概念相当容易理解，但我们的命令目前几乎没有用处，因为我们没有向它们传递任何输入。

# 处理输入

制作实用和有用的命令通常需要能够将操作系统控制台的动态信息传递给我们的应用程序命令。控制台组件区分两种类型的输入--`arguments`和`options`：

+   参数是有序的，以空格分隔（`John Doe`），可选或必需，是字符串类型的信息。参数的分配在命令名称之后。我们使用`Symfony\Component\Console\Command\Command`实例的`addArgument()`方法来为我们的自定义命令分配参数。

+   选项是无序的，以双破折号分隔（`--name=John --surname=Doe`），始终是可选的，分配的信息类型。选项的分配在命令名称之后。我们使用`Symfony\Component\Console\Command\Command`实例的`addOption()`方法来为我们的自定义命令分配选项。

`addArgument()`方法接受四个参数，如下概要所示：

```php
public function addArgument(
  $name, 
  $mode = null, 
  $description = '', 
  $default = null
)

```

而`addArgument()`方法的参数具有以下含义：

+   `$name`: 这是参数名称

+   `$mode`: 这是参数模式，可以是`InputArgument::REQUIRED`或`InputArgument::OPTIONAL`

+   `$description`: 这是描述文本

+   `$default`: 这是默认值（仅适用于`InputArgument::OPTIONAL`模式）

`addOption()`方法接受五个参数，如下概要所示：

```php
public function addOption(
  $name, 
  $shortcut = null, 
  $mode = null, 
  $description = '', 
  $default = null
)

```

而`addOption()`方法的参数具有以下含义：

+   `$name`: 这是选项名称

+   `$shortcut`: 这是快捷方式（可以为`null`）

+   `$mode`: 这是选项模式，是`InputOption::VALUE_*`常量之一

+   `$description`: 这是描述文本

+   `$default`: 这是默认值（对于`InputOption::VALUE_NONE`必须为`null`）

我们可以轻松地构建我们的命令，使它们同时使用这两种输入类型，因为它们不互斥。

让我们继续修改我们的`src\Foggyline\Console\Command\CustomerRegisterCommand.php`文件，进行以下更改：

```php
<?php

namespace Foggyline\Console\Command;

use Symfony\Component\Console\{
  Command\Command,
  Input\InputInterface,
  Input\InputArgument,
  Input\InputOption,
  Output\OutputInterface
};

class CustomerRegisterCommand extends Command
{
  protected function configure()
  {
    $this->setName('customer:register')
    ->addArgument(
      'name', InputArgument::REQUIRED, 'Customer full name.'
    )
    ->addArgument(
      'email', InputArgument::REQUIRED, 'Customer email address.'
    )
    ->addArgument(
      'dob', InputArgument::OPTIONAL, 'Customer date of birth.'
    )
    ->addOption(
      'email', null, InputOption::VALUE_REQUIRED, 'Send email to  
      customer?'
    )
    ->addOption(
      'log', null, InputOption::VALUE_OPTIONAL, 'Log to event system?'
    )
    ->setDescription('Enables or disables existing customer.');
  }

  protected function execute(InputInterface $input, OutputInterface $output)
 {
    var_dump($input->getArgument('name'));
    var_dump($input->getArgument('email'));
    var_dump($input->getArgument('dob'));
    var_dump($input->getOption('email'));
    var_dump($input->getOption('log'));
  }
} 

```

我们的修改主要扩展了*group use*声明和`configure()`方法。在`configure()`方法中，我们利用`addArgument()`和`addOption()`实例方法来向我们的命令添加输入数量。

尝试现在执行我们的控制台命令，不带任何参数，将触发`RuntimaException`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/db5aefff-19f3-4d51-8cbf-ae4c4d7486b7.png)

错误足够描述，可以提供缺少参数的列表。但它不会触发我们自己的参数和选项描述。要显示这些内容，我们可以轻松运行`./app.php customer:register --help`命令。这告诉控制台组件显示我们指定的命令详情：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/40788798-82a1-4754-a4e8-6e6e03806baa.png)

现在我们看到了我们参数和选项背后的确切描述，我们可以发出一个更有效的命令，不会触发错误，例如`./app.php customer:register John Doe --log=true`。传递所有必需的参数使我们进入`execute()`方法，该方法已被修改以对我们传递的值进行原始转储，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/3b6b941a-3d2b-4c9c-b7a2-551bc977b841.png)

我们现在有一个简单但有效的命令版本，可以接受输入。`addArgument()`和`addOption()`方法使得通过单个表达式定义和描述这些输入变得非常容易。控制台组件已经证明是我们控制台应用程序的一个非常方便的补充。

# 使用控制台组件助手

理解参数和选项是利用控制台组件的第一步。一旦我们了解如何处理输入，我们就会转向其他更高级的功能。助手功能帮助我们轻松处理常见任务，如格式化输出，显示运行进程，显示可更新的进度信息，提供交互式问答过程，显示表格数据等。

以下是我们可以使用的几个控制台组件助手：

+   格式化助手

+   进程助手

+   进度条

+   问题助手

+   表格

+   调试格式化助手

您可以在我们项目的`vendor\symfony\console\Helper`目录中看到完整的助手实现。

为了展示这些助手的易用性，让我们继续在*customer export*命令中实现简单的*进度条*和*表格*助手。

我们通过修改`src\Foggyline\Console\Command\CustomerExportCommand.php`类文件的`execute()`方法来实现：

```php
protected function execute(InputInterface $input, OutputInterface $output)
{
  // Fake data source 
  $customers = [
    ['John Doe', 'john.doe@mail.loc', '1983-01-16'],
    ['Samantha Smith', 'samantha.smith@mail.loc', '1986-10-23'],
    ['Robert Black', 'robert.black@mail.loc', '1978-11-18'],
  ];

  // Progress Bar Helper
  $progress = new 
    \Symfony\Component\Console\Helper\ProgressBar($output,
    count($customers));

  $progress->start();

  for ($i = 1; $i <= count($customers); $i++) {
    sleep(5);
    $progress->advance();
  }

  $progress->finish();

  // Table Helper
  $table = new \Symfony\Component\Console\Helper\Table($output);
  $table->setHeaders(['Name', 'Email', 'DON'])
  ->setRows($customers)
  ->render();
}

```

我们首先通过添加虚假的客户数据来启动我们的代码。然后我们实例化`ProgressBar`，传递给它我们虚假客户数据数组中的条目数。进度条实例需要显式调用`start()`、`advance()`和`finish()`方法来实际推进进度条。一旦进度条完成，我们实例化`Table`，传递适当的标题和我们客户数据数组中的行数据。

控制台组件助手提供了大量的配置选项。要了解更多信息，请查看[`symfony.com/doc/current/components/console/helpers/index.html`](http://symfony.com/doc/current/components/console/helpers/index.html)。

通过进行上述更改，触发控制台上的`./app.php customer:export`命令现在应该在执行命令时给出以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/c98e8d9b-b290-41b5-904e-9914b59fbd21.png)

首先我们会看到进度条显示确切的进度。一旦进度条完成，表格助手开始工作，生成最终输出，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/23d67443-8fce-4e45-a208-fe95408d7e53.png)

使用助手可以改善我们的控制台应用程序用户体验。我们现在能够编写提供信息丰富和结构化反馈的应用程序。

# 输入/输出流

在开发的早期阶段，每个程序员都会遇到**流**这个术语。这个看似可怕的术语代表一种数据形式。与典型的有限数据类型不同，流代表一种潜在无限的数据*序列*。在 PHP 术语中，流是一种展现可流动行为的资源对象。使用各种包装器，PHP 语言支持各种流。`stream_get_wrappers()`函数可以检索当前运行系统上所有已注册的流包装器的列表，例如以下内容：

+   `php`

+   `file`

+   `glob`

+   `data`

+   `http`

+   `ftp`

+   `zip`

+   `compress.zlib`

+   `compress.bzip2`

+   `https`

+   `ftps`

+   `phar`

包装器的列表非常广泛，但并非无限。我们还可以使用`stream_wrapper_register()`函数注册自己的包装器。每个包装器告诉流如何处理特定的协议和编码。因此，每个流都是通过`scheme://target`语法访问的，例如以下内容：

+   `php://stdin`

+   `file:///path/to/file.ext`

+   `glob://var/www/html/*.php`

+   `data://text/plain;base64,Zm9nZ3lsaW5l`

+   `http://foggyline.net/`

语法的`scheme`部分表示要使用的包装器的名称，而`target`部分取决于所使用的包装器。作为本节的一部分，我们对`php`包装器及其目标值感兴趣，因为它们涉及标准流。

标准流是以下三个 I/O 连接，可供所有程序使用：

+   标准输入（`stdin`）- 文件描述符`0`

+   标准输出（`stdout`）- 文件描述符`1`

+   标准错误（`stderr`）- 文件描述符`2`

文件描述符是一个表示用于访问 I/O 资源的句柄的整数。作为 POSIX 应用程序编程接口的一部分，Unix 进程应该具有这三个文件描述符。知道文件描述符的值，我们可以使用`php://fd`来直接访问给定的文件描述符，例如`php://fd/1`。但是，还有一种更优雅的方法。

要了解更多关于 POSIX 的信息，请查看[`en.wikipedia.org/wiki/POSIX`](https://en.wikipedia.org/wiki/POSIX)。

PHP CLI SAPI 默认提供了这三个标准流的三个常量：

+   `define('STDIN', fopen('php://stdin', 'r'));`：这表示已经打开了一个到`stdin`的流

+   `define('STDOUT', fopen('php://stdout', 'w'));`：这表示已经打开了一个到`stdout`的流

+   `define('STDERR', fopen('php://stderr', 'w'));`：这表示已经打开了一个到`stderr`的流

以下简单的代码片段演示了这些标准流的使用：

```php
<?php   fwrite(STDOUT, "Type something: "); $line = fgets(STDIN); fwrite(STDOUT, 'You typed: ' . $line); fwrite(STDERR, 'Triggered STDERR!' . PHP_EOL);

```

执行它，我们首先会在屏幕上看到“输入一些内容：”，之后，我们需要提供一个字符串并按*Enter*，最后得到以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/d6efa063-fe02-445e-b39b-27e0de5ba669.png)

虽然示例本身最终是简化的，但它展示了获得流句柄的简便性。我们对这些流做什么取决于使用流的函数（`fopen()`，`fputs()`等）和实际的流函数。

PHP 提供了超过四十个流函数，以及`streamWrapper`类原型。这些为我们提供了一种以几乎任何想象得到的方式创建和操作流的方法。查看[`php.net/manual/en/book.stream.php`](http://php.net/manual/en/book.stream.php)了解更多详情。

# 进程控制

构建 CLI 应用程序往往意味着与系统进程一起工作。PHP 提供了一个称为**PCNTL**的**强大的进程控制扩展**。该扩展允许我们处理进程创建、程序执行、信号处理和进程终止。它仅在类 Unix 机器上工作，其中 PHP 是使用`--enable-pcntl`配置选项编译的。

要确认 PCNTL 在我们的系统上可用，我们可以执行以下控制台命令：

```php
php -m | grep pcntl

```

考虑到它的功能，不鼓励在生产 Web 环境中使用 PCNTL 扩展。编写 PHP 守护进程脚本用于命令行应用程序是我们想要使用它的方式。

为了开始有所了解，让我们继续看看如何使用 PCNTL 功能来处理进程信号。

# Ticks

PCNTL 依赖于 ticks 来进行信号处理回调机制。关于 tick 的官方定义（[`php.net/manual/en/control-structures.declare.php`](http://php.net/manual/en/control-structures.declare.php)）如下：

tick 是在`declare`块内由解析器执行的 N 个低级 tickable 语句的事件。N 的值是在`declare`块的指令部分使用`ticks=N`指定的。

为了详细说明，tick 是一个事件。使用`declare()`语言结构，我们控制了多少语句需要触发一个 tick。然后我们使用`register_ tick_ function()`在每个*触发的 tick*上执行我们的函数。Ticks 基本上是一系列被评估表达式的副作用；这是我们可以用我们的自定义函数来做出反应的副作用。虽然大多数语句是可 tick 的，但某些条件表达式和参数表达式是不可 tick 的。

执行一个*语句*，而*表达式*是被评估的。

除了`declare()`语言结构，PHP 还提供了以下两个函数来处理 ticks：

+   `register_ tick_ function()`：这将注册一个函数，在每个 tick 上执行

+   `unregister_ tick_ function()`：这将取消之前注册的函数

让我们看一下以下示例，在这个示例中，`declare()`结构使用`{}`块来包装表达式：

```php
<?php

echo 'started' . PHP_EOL;

function tickLogger()
{
  echo 'Tick logged!' . PHP_EOL;
}

register_tick_function('tickLogger');

declare (ticks = 2) {
  for ($i = 1; $i <= 10; $i++) {
    echo '$i => ' . $i . PHP_EOL;
  }
}

echo 'finished' . PHP_EOL;

```

这导致以下输出：

```php
started
$i => 1
$i => 2
Tick logged!
$i => 3
$i => 4
Tick logged!
$i => 5
$i => 6
Tick logged!
$i => 7
$i => 8
Tick logged!
$i => 9
$i => 10
Tick logged!
finished

```

这基本上是我们所期望的，基于`declare()`结构的`{}`块中精心包装的表达式。在循环的每秒迭代中，tick 被很好地触发了。

让我们看一下以下示例，在这个示例中，`declare()`结构被添加为 PHP 脚本的第一行，没有任何`{}`块来包装表达式：

```php
<?php

declare (ticks = 2);

echo 'started' . PHP_EOL;

function tickLogger()
{
  echo 'Tick logged!' . PHP_EOL;
}

register_tick_function('tickLogger');

for ($i = 1; $i <= 10; $i++) {
  echo '$i => ' . $i . PHP_EOL;
}

echo 'finished' . PHP_EOL;

```

这导致以下输出：

```php
started
Tick logged!
$i => 1
Tick logged!
$i => 2
Tick logged!
$i => 3
Tick logged!
$i => 4
Tick logged!
$i => 5
Tick logged!
$i => 6
Tick logged!
$i => 7
Tick logged!
$i => 8
Tick logged!
$i => 9
Tick logged!
$i => 10
Tick logged!
Tick logged!
finished
Tick logged!

```

这里的输出并不是我们一开始所期望的。`N`值，`ticks = 2`，似乎并没有被尊重，因为 tick 似乎在每个语句之后都被触发。即使最后完成的输出后面还跟着一个 tick。

Ticks 提供了一种可能有用的功能，用于运行监视、清理、通知、调试或其他类似任务。它们应该被非常小心地使用，否则我们可能会得到一些意想不到的结果，就像我们在前面的例子中看到的那样。

# 信号

信号是在 POSIX 兼容的操作系统中发送给运行中进程的异步消息。它们可以被程序的用户发送。以下是 Linux 支持的标准信号列表：

+   `SIGHUP`：挂断（POSIX）

+   `SIGINT`：终端中断（ANSI）

+   `SIGQUIT`：终端退出（POSIX）

+   `SIGILL`：非法指令（ANSI）

+   `SIGTRAP`：跟踪陷阱（POSIX）

+   `SIGIOT`：IOT 陷阱（4.2 BSD）

+   `SIGBUS`：总线错误（4.2 BSD）

+   `SIGFPE`：浮点异常（ANSI）

+   `SIGKILL`：杀死（无法被捕获或忽略）（POSIX）

+   `SIGUSR1`：用户定义信号 1（POSIX）

+   `SIGSEGV`：无效的内存段访问（ANSI）

+   `SIGUSR2`：用户定义信号 2（POSIX）

+   `SIGPIPE`：在没有读取器的管道上写入，管道中断（POSIX）

+   `SIGALRM`：闹钟（POSIX）

+   `SIGTERM`：终止（ANSI）

+   `SIGSTKFLT`：堆栈故障

+   `SIGCHLD`：子进程已停止或退出，已更改（POSIX）

+   `SIGCONT`：继续执行，如果停止（POSIX）

+   `SIGSTOP`：停止执行（无法被捕获或忽略）（POSIX）

+   `SIGTSTP`：终端停止信号（POSIX）

+   `SIGTTIN`：后台进程试图从 TTY 读取（POSIX）

+   `SIGTTOU`：后台进程试图写入 TTY（POSIX）

+   `SIGURG`：套接字上的紧急情况（4.2 BSD）

+   `SIGXCPU`：CPU 限制超过（4.2 BSD）

+   `SIGXFSZ`：文件大小限制超过（4.2 BSD）

+   `SIGVTALRM`：虚拟闹钟（4.2 BSD）

+   `SIGPROF`：性能分析闹钟（4.2 BSD）

+   `SIGWINCH`：窗口大小改变（4.3 BSD，Sun）

+   `SIGIO`：现在可以进行 I/O（4.2 BSD）

+   `SIGPWR`：电源故障重启（System V）

用户可以使用`kill`命令从控制台手动发出信号消息，比如`kill -SIGHUP 4321`。

`SIGKILL`和`SIGSTOP`信号是终极的关闭开关，因为它们无法被捕获、阻止或忽略。

PHP 提供了几个函数来处理信号，其中一些如下：

+   `pcntl_ signal()`：这将安装一个信号处理程序

+   `pcntl_signal_dispatch()`: 这个函数调用待处理信号的信号处理程序

+   `pcntl_sigprocmask()`: 这个函数设置和检索被阻塞的信号

+   `pcntl_sigtimedwait()`: 这个函数等待信号，带有超时

+   `pcntl_sigwaitinfo()`: 这个函数等待信号

`pcntl_signal()`函数是最有趣的一个。

让我们看一个使用`pcntl_signal()`函数的例子：

```php
#!/usr/bin/env php
<?php

declare(ticks = 1);

echo 'started' . PHP_EOL;

function signalHandler($signal)
{
  echo 'Triggered signalHandler: ' . $signal . PHP_EOL;
  // exit;
}

pcntl_signal(SIGINT, 'signalHandler');

$loop = 0;
while (true) {
  echo 'loop ' . (++$loop) . PHP_EOL;
  flush();
  sleep(2);
}

echo 'finished' . PHP_EOL;

```

我们从*declare ticks*定义开始我们的代码。如果没有它，通过`pcntl_signal()`函数安装我们自定义的`signalHandler`函数将不会生效。`pcntl_signal()`函数本身为`SIGINT`信号安装了`signalHandler()`函数。运行上述代码将产生以下输出：

```php
$ ./app.php
started
loop 1
loop 2
loop 3
^CTriggered signalHandler: 2
loop 4
loop 5
^CTriggered signalHandler: 2
loop 6
loop 7
loop 8
^CTriggered signalHandler: 2
loop 9
loop 10
...

```

`^C`字符串表示我们在键盘上按下*Ctrl* + *C*的时刻。我们可以看到紧接着就是来自我们自定义的`signalHandler()`函数的`Triggered signalHandler: *N*`输出。虽然我们成功捕获了`SIGINT`信号，但在完成`signalHandler()`函数后我们没有跟进并实际执行它，这导致信号被忽略，程序继续执行。事实证明，我们通过允许程序在按下*Ctrl* + *C*后继续执行，实际上破坏了默认的操作系统功能。

信号如何帮助我们？首先，在`signalHandler()`函数内部简单的`exit;`调用将解决这种情况下的破损功能。除此之外，我们还有一个强大的机制，可以让我们接触（几乎）任何系统信号，并执行我们选择的任意代码。

# 警报

`pcntl_alarm()`函数通过提供信号传递的闹钟来丰富 PHP 信号功能。简而言之，它创建一个定时器，在给定的秒数后向进程发送`SIGALRM`信号。

一旦警报触发，信号处理程序函数就会启动。一旦信号处理程序函数代码执行完毕，我们就会回到应用程序在跳转到信号处理程序函数之前停止的代码点。

让我们看下面的代码片段：

```php
#!/usr/bin/env php
<?php

declare(ticks = 1);

echo 'started' . PHP_EOL;

function signalHandler($signal)
{
  echo 'Triggered signalHandler: ' . $signal . PHP_EOL;
}

pcntl_signal(SIGALRM, 'signalHandler');
pcntl_alarm(7);

while (true) {
  echo 'loop ' . date('h:i:sa') . PHP_EOL;
  flush();
  sleep(2);
}

echo 'finished' . PHP_EOL;

```

我们使用`pcntl_signal()`函数将`signalHandler`注册为`SIGALRM`信号的信号处理函数。然后调用`pcntl_alarm()`函数，传递 7 秒的整数值。while 循环被设置为仅向控制台输出一些内容，以便更容易理解警报的行为。执行后，显示以下输出：

```php
$ ./app.php
started
loop 02:17:28pm
loop 02:17:30pm
loop 02:17:32pm
loop 02:17:34pm
Triggered signalHandler: 14
loop 02:17:35pm
loop 02:17:37pm
loop 02:17:39pm
loop 02:17:41pm
loop 02:17:43pm
loop 02:17:45pm
loop 02:17:47pm
loop 02:17:49pm
loop 02:17:51pm

```

我们可以看到`Triggered signalHandler: 14`字符串只显示了一次。这是因为警报只触发了一次。输出中显示的时间表明了第一次循环迭代和警报之间确切的七秒延迟。我们可以在`signalHandler()`函数内部轻松地再次调用`pcntl_alarm()`函数：

```php
function signalHandler($signal)
{
  echo 'Triggered signalHandler: ' . $signal . PHP_EOL;
  pcntl_alarm(3);
}

```

这将把我们的输出转换成这样：

```php
$ ./app.php
started
loop 02:20:46pm
loop 02:20:48pm
loop 02:20:50pm
loop 02:20:52pm
Triggered signalHandler: 14
loop 02:20:53pm
loop 02:20:55pm
Triggered signalHandler: 14
loop 02:20:56pm
loop 02:20:58pm
Triggered signalHandler: 14
loop 02:20:59pm
loop 02:21:01pm
Triggered signalHandler: 14
loop 02:21:02pm

```

虽然可以指定多个警报，但在到达上一个警报之前这样做会使新警报替换旧警报。在应用程序内执行非线性处理时，警报的用处变得明显。`pcntl_alarm()`函数是非阻塞的，可以轻松使用，而不用担心阻塞程序执行。

# 多进程

谈到**多进程**时，我们经常遇到两个看似冲突的术语：**进程**和**线程**。进程可以被视为应用程序的当前运行实例，而线程是进程内的执行路径。线程可以做几乎任何进程可以做的事情。然而，由于线程驻留在进程内，我们将它们视为轻量级任务的解决方案，或者至少比进程使用的任务更轻。

在多进程/多线程方面，PHP 语言还有很多需要改进的地方。以下两种解决方案最受欢迎：

+   `pcntl_fork()`：这是一个分叉当前运行进程的函数

+   `pthreads`：这是一个基于 Posix 线程提供多线程的面向对象 API

`pcntl_fork()`函数是 PCNTL 扩展的一部分，我们在之前的部分中也使用了它的函数。该函数只能分叉进程，不能创建线程。虽然`pthreads`是一种更现代和面向对象的解决方案，但在本节中我们将继续使用`pcntl_fork()`函数。

当我们运行`pcntl_fork()`函数时，它为我们创建了一个子进程。这个子进程与父进程的唯一区别在于它的`PID`和`PPID`：

+   `PID`：这是进程 ID

+   `PPID`：这是父进程 ID，启动此 PID 的进程

虽然使用`pcntl_fork()`函数进行实际进程分叉非常简单，但它给我们留下了一些挑战。诸如*进程间通信*和*僵尸子进程*之类的挑战使得交付稳定的应用程序变得繁琐。

让我们来看一下`pcntl_fork()`函数的以下用法：

```php
#!/usr/bin/env php
<?php

for ($i = 1; $i <= 5; $i++) {
  $pid = pcntl_fork();

  if (!$pid) {
    echo 'Child ' . $i . PHP_EOL;
    sleep(2);
    exit;
  }
}

```

上述代码的输出结果如下：

```php
$ time php ./app.php

real 0m0.031s
user 0m0.012s
sys 0m0.016s
$ Child 1
Child 4
Child 2
Child 3
Child 5

$

```

尽管有五个子进程在运行，但控制台立即返回了控制权。控制权首先在输出 Child 1 字符串之前返回，然后几秒钟后，所有 Child 字符串都被输出，控制台再次返回了控制权。输出清楚地显示子进程不一定按照它们被分叉的顺序执行。这由操作系统决定，而不是我们。我们可以进一步使用`pcntl_waitpid()`和`pcntl_wexitstatus()`函数来调整行为。

`pcntl_waitpid()`函数指示 PHP 等待子进程，而`pcntl_wexitstatus()`函数获取终止子进程返回的值。以下示例演示了这一点：

```php
#!/usr/bin/env php
<?php

function generatePdf($content, $size)
{
  echo 'Started PDF ' . $size . ' - ' . date('h:i:sa') . PHP_EOL;
  sleep(3); /* simulate PDF generating */
  echo 'Finished PDF ' . $size . ' - ' . date('h:i:sa') . PHP_EOL;
}

$sizes = ['A1', 'A2', 'A3'];
$content = 'foggyline';

for ($i = 0; $i < count($sizes); $i++) {
  $pid = pcntl_fork();

  if (!$pid) {
    generatePdf($content, $sizes[$i]);
    exit($i);
  }
}

while (pcntl_waitpid(0, $status) != -1) {
  $status = pcntl_wexitstatus($status);
  echo "Child $status finished! - " . date('h:i:sa') . PHP_EOL;
}

```

尽管这个例子的大部分内容与上一个例子相似，但请注意底部的整个`while`循环。`while`循环将一直循环直到`pcntl_waitpid()`函数返回`-1`（没有子进程了）。`while`循环的每次迭代都会检查终止子进程的返回代码，并将其存储到`$status`变量中，然后再次在`while`循环表达式中进行评估。

查看[`php.net/manual/en/ref.pcntl.php`](http://php.net/manual/en/ref.pcntl.php)以获取有关`pcntl_fork()`、`pcntl_waitpid()`和`pcntl_wexitstatus()`函数参数和返回值的更多详细信息。

上述代码的输出结果如下：

```php
$ time ./app.php
Started PDF A2 - 04:52:37pm
Started PDF A3 - 04:52:37pm
Started PDF A1 - 04:52:37pm
Finished PDF A2 - 04:52:40pm
Finished PDF A1 - 04:52:40pm
Finished PDF A3 - 04:52:40pm
Child 2 finished! - 04:52:40pm
Child 1 finished! - 04:52:40pm
Child 0 finished! - 04:52:40pm

real 0m3.053s
user 0m0.016s
sys 0m0.028s
$

```

控制台直到所有子进程执行完毕才会返回控制权，这可能是大多数任务的首选解决方案。

虽然进程分叉为我们打开了几种可能性，但我们需要问自己，这真的值得吗？如果简单地重组我们的应用程序以使用更多的消息队列、CRON 和其他更简单的技术，可以获得类似的性能，并且更容易扩展、维护和调试，那么我们可能应该避免分叉。

# 总结

在本章中，我们熟悉了 PHP CLI 周围一些有趣的特性和工具。本章以 PHP CLI SAPI 的基本介绍开始，作为 PHP 中众多 SAPI 接口之一。然后我们深入了解了一个简单但功能强大的控制台组件，学习了如何轻松创建自己的控制台应用程序。I/O 流部分帮助我们理解标准流以及它们如何被 PHP 处理。最后，我们深入了解了 PCNTL 扩展提供的进程控制函数。这些函数的组合为我们编写控制台应用程序打开了广阔的可能性。虽然与面向浏览器的应用程序相比，整体控制台应用程序开发可能不够有趣，但它在现代开发中肯定有其作用。CLI 环境简单地允许我们更好地控制我们的应用程序。

往前看，我们将深入了解 PHP 中最重要和有趣的面向对象编程特性之一。
