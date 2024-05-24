# 精通 PHP7（三）

> 原文：[`zh.annas-archive.org/md5/c80452b19d206124b22230f7a590b2c3`](https://zh.annas-archive.org/md5/c80452b19d206124b22230f7a590b2c3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：突出的面向对象编程特性

“面向对象”（OO）这个术语自 70 年代以来就存在，当时由计算机科学家 Alan Kay 创造。该术语代表了基于对象概念的编程范式。当时，Simula 是第一种展示面向对象特性的语言，如对象、类、继承、子类型等。1977 年标准化为 Simula 67 后，它成为后来语言的灵感来源。其中一种受到启发的语言是 Smalltalk，由 Xerox 的 Alan Kay 领导的研究团队创建。与 Simula 相比，Smalltalk 极大地改进了整体的面向对象概念。随着时间的推移，Smalltalk 成为了最有影响力的面向对象编程语言之一。

虽然这些早期日子还有很多值得说的地方，但重点是面向对象编程是出于特定的需求而诞生的。Simula 使用静态对象来对建模现实世界的实体，而 Smalltalk 使用动态对象作为计算的基础，可以创建、更改或删除。

MVC 模式，是最常见的面向对象软件设计模式之一，是在 Smalltalk 中引入的。

将物理实体映射为类描述的对象的便利性显然影响了开发人员对面向对象范式的整体流行度。然而，对象不仅仅是关于各种属性的映射实例，它们还涉及消息和责任。虽然我们可能基于第一个前提接受面向对象编程，但我们肯定开始欣赏后者，因为构建大型和可扩展系统的关键在于对象通信的便利性。

PHP 语言包含多种范式，最为突出的是：命令式、函数式、面向对象、过程式和反射。然而，PHP 中的面向对象支持直到 PHP 5 发布之前才完全启动。PHP 7 的最新版本带来了一些微小但值得注意的改进，现在被认为是一个稳定和成熟的 PHP 面向对象模型。

在本章中，我们将探讨 PHP 面向对象的一些突出特性：

+   对象继承

+   对象和引用

+   对象迭代

+   对象比较

+   特征

+   反射

# 对象继承

面向对象范式将对象置于应用程序设计的核心，其中对象可以被视为包含各种属性和方法的单元。这些属性和方法之间的交互定义了对象的内部状态。每个对象都是从称为类的蓝图构建的。在基于类的面向对象编程中，没有类的对象，至少不是一个对象。

我们区分基于类的面向对象编程（PHP、Java、C#，...）和基于原型的面向对象编程（ECMAScript / JavaScript、Lua，...）。在基于类的面向对象编程中，对象是从类创建的；在基于原型的面向对象编程中，对象是从其他对象创建的。

构建或创建新对象的过程称为实例化。在 PHP 中，与许多其他语言一样，我们使用`new`关键字从给定的类实例化一个对象。让我们看看以下示例：

```php
<?php

class JsonOutput
{
  protected $content;

  public function setContent($content)
  {
    $this->content = $content;
  }

  public function render()
  {
    return json_encode($this->content);
  }
}

class SerializedOutput
{
  protected $content;

  public function setContent($content)
  {
    $this->content = $content;
  }

  public function render()
  {
    return serialize($this->content);
  }
}

$users = [
  ['user' => 'John', 'age' => 34],
  ['user' => 'Alice', 'age' => 33],
];

$json = new JsonOutput();
$json->setContent($users);
echo $json->render();

$ser = new SerializedOutput();
$ser->setContent($users);
echo $ser->render();

```

在这里，我们定义了两个简单的类，`JsonOutput`和`SerializedOutput`。我们之所以说简单，仅仅是因为它们有一个属性和两个方法。这两个类几乎是相同的——它们只在`render()`方法中的一行代码上有所不同。一个类将给定的内容转换为 JSON，而另一个类将其转换为序列化字符串。在我们的类声明之后，我们定义了一个虚拟的$users 数组，然后将其提供给`JsonOutput`和`SerializedOutput`类的实例，即`$json`和`$ser`对象。

虽然这远非理想的类设计，但它作为继承的一个很好的介绍。

允许类和因此对象继承另一个类的属性和方法。术语如超类、基类或父类用于标记用作继承基础的类。术语如子类、派生类或子类用于标记继承类。

PHP 的`extends`关键字用于启用继承。继承有其限制。我们一次只能从一个类扩展，因为 PHP 不支持多重继承。但是，具有继承链是完全有效的：

```php
// valid
class A {}
class B extends A {}
class C extends B {}

// invalid
class A {}
class B {}
class C extends A, B {}

```

在有效示例中显示的`C`类最终将继承类`B`和`A`的所有允许的属性和方法。当我们说允许时，我们指的是属性和方法的可见性，即访问修饰符：

```php
<?php   error_reporting(E_ALL);   class A {
  public $x = 10;
  protected $y = 20;
  private $z = 30;    public function x()
 {  return $this->x;
 }    protected function y()
 {  return $this->y;
 }    private function z()
 {  return $this->z;
 } }   class B extends A {   }   $obj = new B(); var_dump($obj->x); // 10 var_dump($obj->y); // Uncaught Error: Cannot access protected property B::$y var_dump($obj->z); // Notice: Undefined property: B::$z var_dump($obj->x()); // 10 var_dump($obj->y()); // Uncaught Error: Call to protected method A::y() from context var_dump($obj->z()); // Uncaught Error: Call to private method A::z() from context

```

在对象上下文中，访问修饰符的行为与前面的示例一样，这基本上是我们所期望的。无论它是类`A`的实例还是类`B`的实例，对象都会表现出相同的行为。让我们观察子类内部工作中访问修饰符的行为：

```php
class B extends A
{
  public function test()
  {
    var_dump($this->x); // 10
    var_dump($this->y); // 20
    var_dump($this->z); // Notice: Undefined property: B::$z
    var_dump($this->x()); // 10
    var_dump($this->y()); // 20
    var_dump($this->z()); // Uncaught Error: Call to private method 
      A::z() from context 'B'
  }
}

$obj = new B();
$obj->test();

```

我们可以看到，`public`和`protected`成员（属性或方法）可以从子类中访问，而私有成员则不行——它们只能从定义它们的类中访问。

`extends`关键字也适用于接口：

```php
<?php   interface User {}  interface Employee extends User {}

```

能够继承类和接口的属性和方法构成了一个强大的整体对象继承机制。

了解这些简单的继承规则，让我们看看如何使用继承将我们的`JsonOutput`和`SerializedOutput`类重写为更方便的形式：

```php
<?php   class Output {
  protected $content;    public function setContent($content)
 {  $this->content = $content;
 }    public function render()
 {  return $this->content;
 } }   class JsonOutput extends Output {
  public function render()
 {  return json_encode($this->content);
 } }   class SerializedOutput extends Output {
  public function render()
 {  return serialize($this->content);
 } }

```

我们首先定义了一个`Output`类，其内容几乎与之前的`JsonOutput`和`SerializedOutput`类相同，只是将其`render()`方法更改为简单地返回内容。然后，我们以这样的方式重写了`JsonOutput`和`SerializedOutput`类，它们都扩展了`Output`类。在这种设置中，`Output`类成为父类，而`JsonOutput`和`SerializedOutput`成为子类。子类重新定义了`render()`方法，从而覆盖了父类的实现。`$this`关键字可以访问所有的公共和受保护的修饰符，这使得访问`$content`属性变得容易。

虽然继承可能是将代码结构化为方便的父/子关系链的快速而强大的方法，但应避免滥用或过度使用。在更大的系统中，这可能特别棘手，我们可能会花更多的时间来处理大型类层次结构，而不是实际维护子系统接口。因此，我们应该谨慎使用它。

# 对象和引用

在代码中有两种传递参数的方式：

+   **按引用传递**：这是调用者和被调用者都使用相同的变量作为参数。

+   **按值传递**：这是调用者和被调用者都有自己的变量副本作为参数。如果被调用者决定更改传递参数的值，调用者将不会注意到它。

按值传递是默认的 PHP 行为，如下例所示：

```php
<?php

class Util
{
  function hello($msg)
  {
    $msg = "<p>Welcome $msg</p>";
    return $msg;
  }
}

$str = 'John';

$obj = new Util();
echo $obj->hello($str); // Welcome John

echo $str; // John

```

查看`hello()`方法的内部，我们可以看到它将`$msg`参数值重置为另一个字符串值，该值包含在 HTML 标记中。默认的 PHP 按值传递行为阻止了这种变化在方法范围之外传播。在函数定义中的参数名称之前使用`&`运算符，我们可以强制进行引用传递行为：

```php
<?php

class Util
{
  function hello(&$msg)
  {
    $msg = "<p>Welcome $msg</p>";
    return $msg;
  }
}

$str = 'John';

$obj = new Util();
echo $obj->hello($str); // Welcome John

echo $str; // Welcome John

```

能够做某事并不一定意味着我们应该这样做。应谨慎使用引用传递行为，只有在真正有很好的理由时才应该这样做。前面的例子清楚地显示了内部`hello()`方法对外部范围内的简单标量类型值的副作用。对象实例方法，甚至纯函数，不应该对外部范围产生这种类型的副作用。

一些 PHP 函数，如`sort()`，使用`&`运算符来强制对给定数组参数进行引用传递行为。

说了这么多，对象在哪里适用呢？PHP 中的对象倾向于传递引用行为。当对象作为参数传递时，它仍然被传递为值，但被传递的值不是对象本身，而是对象标识符。因此，将对象作为参数传递的行为更像是通过引用传递：

```php
<?php

class User
{
  public $salary = 4200;
}

function bonus(User $u)
{
  $u->salary = $u->salary + 500;
}

$user = new User();
echo $user->salary; // 4200
bonus($user);
echo $user->salary; // 4700 

```

由于对象比标量值更大，通过引用传递大大减少了内存和 CPU 占用。

# 对象迭代

PHP 数组是 PHP 中最常用的集合结构。我们几乎可以将任何东西都放入数组中，从标量值到对象。使用`foreach`语句轻松遍历这种结构的元素。然而，数组并不是唯一可迭代的类型，对象本身也是可迭代的。

让我们来看下面的基于数组的例子：

```php
<?php

$user = [
  'name' => 'John',
  'age' => 34,
  'salary' => 4200.00
];

foreach ($user as $k => $v) {
  echo "key: $k, value: $v" . PHP_EOL;
}

```

现在让我们来看下面的基于对象的例子：

```php
<?php

class User
{
  public $name = 'John';
  public $age = 34;
  public $salary = 4200.00;
}

$user = new User();

foreach ($user as $k => $v) {
  echo "key: $k, value: $v" . PHP_EOL;
}

```

在控制台上执行这两个例子，将得到相同的输出：

```php
key: name, value: John 
key: age, value: 34 
key: salary, value: 4200

```

默认情况下，迭代仅适用于公共属性，不包括列表中的任何私有或受保护属性。

PHP 提供了一个`Iterator`接口，使我们能够指定要使其可迭代的值。

```php
Iterator extends Traversable {
  abstract public mixed current(void)
  abstract public scalar key(void)
  abstract public void next(void)
  abstract public void rewind(void)
  abstract public boolean valid(void)
} 

```

以下示例演示了一个简单的`Iterator`接口实现：

```php
<?php

class User implements \Iterator
{
  public $name = 'John';
  private $age = 34;
  protected $salary = 4200.00;

  private $info = [];

  public function __construct()
  {
    $this->info = [
      'name' => $this->name,
      'age' => $this->age,
      'salary' => $this->salary
    ];
  }

  public function current()
  {
    return current($this->info);
  }

  public function next()
  {
    return next($this->info);
  }

  public function key()
  {
    return key($this->info);
  }

  public function valid()
  {
    $key = key($this->info);
    return ($key !== null && $key !== false);
  }

  public function rewind()
  {
    return reset($this->info);
  }
}

```

通过这种实现，我们似乎现在能够迭代 User 类的私有和受保护属性。尽管如此，实际情况并非如此。发生的是，通过构造函数，类正在用我们希望迭代的所有其他属性的数据填充`$info`参数。然后，接口规定的方法确保我们的类与`foreach`结构良好地配合。

对象迭代是 PHP 在日常开发中经常被忽视的一个很好的特性。

# 对象比较

PHP 语言提供了几个比较运算符，允许我们比较两个不同的值，结果要么是`true`，要么是`false`：

+   `==`: 等于

+   `===`: 相同

+   `!=`: 不等于

+   `<>`: 不等于

+   `!==`: 不相同

+   `<`: 小于

+   `>`: 大于

+   `<=`: 小于或等于

+   `>=`: 大于或等于

虽然所有这些运算符同样重要，让我们更仔细地看看在对象的上下文中相等（`==`）和相同（`===`）运算符的行为。

让我们来看下面的例子：

```php
<?php

class User {
  public $name = 'N/A';
  public $age = 0;
}

$user = new User();
$employee = new User();

var_dump($user == $employee); // true
var_dump($user === $employee); // false

```

在这里，我们有一个简单的`User`类，其中有两个属性设置为一些默认值。然后我们有同一个类的两个不同实例，`$user`和`$employee`。鉴于这两个对象都具有相同的属性，并且具有相同的值，相等（`==`）运算符返回`true`。另一方面，相同（`===`）运算符返回 false。尽管对象是同一个类的，且在这些属性中具有相同的属性和值，但相同运算符将它们视为不同。

让我们来看下面的例子：

```php
<?php

class User {
  public $name = 'N/A';
  public $age = 0;
}

$user = new User();
$employee = $user;

var_dump($user == $employee); // true
var_dump($user === $employee); // true

```

相同（`===`）运算符只有当两个对象引用同一个类的同一个实例时才认为它们是相同的。相同的运算符行为也适用于对应的运算符，即不等（`<>`或`!=`）和不相同（`!==`）运算符。

除了对象，相同运算符也适用于任何其他类型：

```php
<?php   var_dump(2 == 2); // true var_dump(2 == "2"); // true var_dump(2 == "2ABC"); // true   var_dump(2 === 2); // true var_dump(2 === "2"); // false var_dump(2 === "2ABC"); // false

```

从前面的例子中可以清楚地看出相同运算符的重要性。`2 == "2ABC"`表达式的计算结果为 true，这让人感到困惑。我们甚至可能认为这是 PHP 语言本身的一个 bug。虽然依赖 PHP 的自动类型转换大多数情况下都没问题，但有时会出现意外的 bug，影响我们的应用逻辑。使用相同运算符可以重新确认比较，确保我们考虑的不仅是值，还有类型。

# 特征

我们之前提到 PHP 是一种单继承语言。在 PHP 中，我们不能使用`extends`关键字来扩展多个类。这个特性实际上是一种罕见的商品，只有少数编程语言支持，比如 C++。无论好坏，多重继承允许我们对代码结构进行一些有趣的调整。

PHP Traits 提供了一种机制，通过它我们可以在代码重用或功能分组的上下文中实现这些结构。使用`trait`关键字声明 Trait，如下所示：

```php
<?php

trait Formatter
{
  // Trait body
}

```

Trait 的主体可以是我们在类中放置的任何东西。虽然它们类似于类，但我们不能实例化 Trait 本身。我们只能从另一个类中使用 Trait。为此，我们在类主体中使用`use`关键字，如下例所示：

```php
class Ups
{
  use Formatter;

  // Class body (properties & methods)
}

```

为了更好地理解 Trait 如何有助于，让我们看看以下示例：

```php
<?php   trait Formatter {
  public function formatPrice($price)
 {  return sprintf('%.2F', $price);
 } }   class Ups {
  use Formatter;   private $price = 4.4999; // Base shipping price   public function getShippingPrice($formatted = false)
 {  // Shipping cost calc... $this->price = XXX    if ($formatted) {
  return $this->formatPrice($this->price);
 }    return $this->price;
 } }   class Dhl {
  use Formatter;    private $price = 9.4999; // Base shipping price    public function getShippingPrice($formatted = false)
 {  // Shipping cost calc... $this->price = XXX    if ($formatted) {
  return $this->formatPrice($this->price);
 }    return $this->price;
 } }   $ups = new Ups(); echo $ups->getShippingPrice(true); // 4.50   $dhl = new Dhl(); echo $dhl->getShippingPrice(true); // 9.50

```

前面的例子演示了在代码重用上下文中使用 trait 的情况，其中两个不同的运输类`Ups`和`Dhl`使用相同的 trait。trait 本身包装了一个很好的`formatPrice()`辅助方法，用于将给定的价格格式化为两个小数位。

与类一样，traits 可以访问`$this`，这意味着我们可以轻松地将`Formatter` trait 的先前`formatPrice()`方法重写如下：

```php
<?php   trait Formatter {
  public function formatPrice()
 {  return sprintf('%.2F', $this->price);
 } }

```

然而，这严重限制了我们对 trait 的使用，因为它的`formatPrice()`方法现在期望有一个`$price`成员，而一些使用`Formatter` trait 的类可能没有。

让我们看另一个例子，在这个例子中，我们在功能分组的上下文中使用 traits：

```php
<?php   trait SalesOrderCustomer {
  public function getCustomerFirstname()
 { /* body */
  }    public function getCustomerEmail()
 { /* body */
  }    public function getCustomerGender()
 { /* body */
  } }   trait SalesOrderActions {
  public function cancel()
 { /* body */
  }    public function complete()
 { /* body */
  }    public function hold()
 { /* body */
  } }   class SalesOrder {
  use SalesOrderCustomer;
  use SalesOrderActions;    /* body */ }

```

我们在这里所做的不过是将我们的类代码剪切并粘贴到两个不同的 traits 中。我们将所有与可能的订单操作相关的方法分组到一个`SalesOrderActions` trait 中，将所有与订单客户相关的方法分组到`SalesOrderCustomer` trait 中。这让我们回到了可能并不一定是可取的哲学。

使用多个 traits 有时可能会导致冲突，即在多个 trait 中可以找到相同的方法名。我们可以使用`insteadof`和`as`关键字来缓解这些类型的冲突，如下例所示：

```php
<?php   trait CsvHandler {
  public function import()
 {  echo 'CsvHandler > import' . PHP_EOL;
 }   public function export()
 {  echo 'CsvHandler > export' . PHP_EOL;
 } }   trait XmlHandler {
  public function import()
 {  echo 'XmlHandler > import' . PHP_EOL;
 }    public function export()
 {  echo 'XmlHandler > export' . PHP_EOL;
 } }   class SalesOrder {
  use CsvHandler, XmlHandler {
 XmlHandler::import insteadof CsvHandler;
 CsvHandler::export insteadof XmlHandler;
 XmlHandler::export as exp;
 }    public function initImport()
 {  $this->import();
 }    public function initExport()
 {  $this->export();
  $this->exp();
 } }   $order = new SalesOrder(); $order->initImport(); $order->initExport();   //XmlHandler > import //CsvHandler > export //XmlHandler > export

```

`as`关键字也可以与`public`、`protected`或`private`关键字一起使用，以更改方法的可见性：

```php
<?php   trait Message {
  private function hello()
 {  return 'Hello!';
 } }   class User {
  use Message {
 hello as public;
 } }   $user = new User(); echo $user->hello(); // Hello!

```

更有趣的是，traits 可以进一步由其他 traits 组成，甚至支持`abstract`和`static`成员，如下例所示：

```php
<?php

trait A
{
  public static $counter = 0;

  public function theA()
  {
    return self::$counter;
  }
}

trait B
{
  use A;

  abstract public function theB();
}

class C
{
  use B;

  public function theB()
  {
    return self::$counter;
  }
}

$c = new C();
$c::$counter++;
echo $c->theA(); // 1
$c::$counter++;
$c::$counter++;
echo $c->theB(); // 3

```

除了不能实例化外，traits 与类共享许多特性。虽然它们为我们提供了一些有趣的代码结构工具，但它们也很容易违反单一责任原则。对 trait 使用的整体印象通常是扩展常规类，这使得很难找到正确的用例。我们可以使用它们来描述许多但不是必要的特征。例如，喷气发动机并非每架飞机都必需，但很多飞机都有它们，而其他飞机可能有螺旋桨。

# 反射

反射是每个开发人员都应该警惕的一个非常重要的概念。它表示程序在运行时检查自身的能力，从而允许轻松地反向工程类、接口、函数、方法和扩展。

我们可以从控制台快速了解 PHP 反射的能力。PHP CLI 支持几个基于反射的命令：

+   `--rf <*function name*>`：显示有关函数的信息

+   `--rc <*class name*>`：显示有关类的信息

+   `--re <*extension name*>`：显示有关扩展的信息

+   `--rz <*extension name*>`：显示有关 Zend 扩展的信息

+   `--ri <*extension name*>`：显示扩展的配置

以下输出演示了`php --rf str_replace`命令的结果：

```php
Function [ <internal:standard> function str_replace ] {
  - Parameters [4] {
     Parameter #0 [ <required> $search ]
     Parameter #1 [ <required> $replace ]
     Parameter #2 [ <required> $subject ]
     Parameter #3 [ <optional> &$replace_count ]
  }
}

```

输出反映了`str_replace()`函数，这是一个标准的 PHP 函数。它清楚地描述了参数的总数，以及它们的名称和必需或可选的分配。

反射的真正力量，开发人员可以利用的力量，来自反射 API。让我们看看以下例子：

```php
<?php

class User
{
  public $name = 'John';
  protected $ssn = 'AAA-GG-SSSS';
  private $salary = 4200.00;
}

$user = new User();

echo $user->name = 'Marc'; // Marc

//echo $user->ssn = 'BBB-GG-SSSS';
// Uncaught Error: Cannot access protected property User::$ssn

//echo $user->salary = 5600.00;
// Uncaught Error: Cannot access private property User::$salary

var_dump($user);
//object(User)[1]
// public 'name' => string 'Marc' (length=4)
// protected 'ssn' => string 'AAA-GG-SSSS' (length=11)
// private 'salary' => float 4200

```

我们首先定义了一个`User`类，其中包含三个不同可见性的属性。然后我们实例化了一个`User`类的对象，并尝试更改所有三个属性的值。通常，定义为`protected`或`private`的成员不能在对象外部访问。尝试以读取或写入模式访问它们会抛出一个无法访问的错误。这是我们认为的正常行为。

使用 PHP 反射 API，我们可以绕过这种正常行为，从而可以访问私有和受保护的成员。反射 API 本身为我们提供了几个可用的类：

+   反射

+   ReflectionClass

+   ReflectionZendExtension

+   ReflectionExtension

+   ReflectionFunction

+   ReflectionFunctionAbstract

+   ReflectionMethod

+   ReflectionObject

+   ReflectionParameter

+   ReflectionProperty

+   ReflectionType

+   ReflectionGenerator

+   Reflector（接口）

+   ReflectionException（异常）

这些类中的每一个都公开了各种功能，使我们能够玩弄其他类、接口、函数、方法和扩展的内部。假设我们的目标是从前面的例子中更改`protected`和`private`属性的值，我们可以使用`ReflectionClass`和`ReflectionProperty`，如下例所示：

```php
<?php

// ...

$user = new User();

$reflector = new ReflectionClass('User');

foreach ($reflector->getProperties() as $prop) {
  $prop->setAccessible(true);
  if ($prop->getName() == 'name') $prop->setValue($user, 'Alice');
  if ($prop->getName() == 'ssn') $prop->setValue($user, 'CCC-GG-SSSS');
  if ($prop->getName() == 'salary') $prop->setValue($user, 2600.00);
}

var_dump($user);

//object(User)[1]
// public 'name' => string 'Alice' (length=5)
// protected 'ssn' => string 'CCC-GG-SSSS' (length=11)
// private 'salary' => float 2600

```

我们首先实例化了一个`User`类的对象，就像在前面的例子中一样。然后我们创建了一个`ReflectionClass`的实例，将`User`类的名称传递给它的构造函数。新创建的`$reflector`实例允许我们通过其`getProperties()`方法获取`User`类的所有属性列表。逐个循环遍历属性，我们启动了反射 API 的真正魔力。每个属性（`$prop`）都是`ReflectionProperty`类的一个实例。`ReflectionProperty`类的两个方法，`setAccessible()`和`setValue()`，为我们提供了恰到好处的功能，使我们能够达到我们的目标。使用这些方法，我们能够设置原本无法访问的对象属性的值。

另一个简单但有趣的反射示例是文档注释提取：

```php
<?php

class Calc
{
  /**
  * @param $x The number x
  * @param $y The number y
  * @return mixed The number z
  */
  public function sum($x, $y)
  {
    return $x + $y;
  }
}

$calc = new Calc();

$reflector = new ReflectionClass('Calc');
$comment = $reflector->getMethod('sum')->getDocComment();

echo $comment;

```

仅用两行代码，我们就能够反映`Calc`类并从其`sum()`方法中提取文档注释。虽然反射 API 的实际用途可能一开始并不明显，但正是这些功能使我们能够构建强大而动态的库和平台。

phpDocumentor 工具使用 PHP 反射功能自动生成源代码的文档。流行的 Magento v2.x 电子商务平台广泛使用 PHP 反射功能自动实例化被`__construct()`参数类型提示的对象。

# 总结

在本章中，我们看了一些 PHP 面向对象编程中最基本但不太为人知的特性，这些特性有时在我们日常开发中并没有得到足够的关注。如今，大多数主流工作都集中在使用框架和平台，这些框架和平台往往会将一些概念抽象化。了解对象的内部工作对于成功开发和调试更大型的系统至关重要。反射 API 在操作对象时提供了很大的力量。结合我们在第四章中提到的魔术方法的力量，*魔术方法背后的魔术*，PHP 面向对象模型似乎相当丰富多彩。

接下来，我们将假设我们已经有一个可用的应用程序，并专注于优化其性能。


# 第七章：优化高性能

多年来，PHP 已经发展成为我们构建 Web 应用程序所使用的一种非凡语言。令人印象深刻的语言特性，以及无数的库和框架，使我们的工作变得更加容易。我们经常编写涵盖多层堆栈的代码，而不加思索。这使得很容易忽视每个应用程序最重要的方面之一--性能。

虽然性能有几个方面需要开发人员注意，但最终用户只对一个方面感兴趣 - 网页加载所需的时间。这才是最重要的。如今，用户期望他们的页面在 2 秒内加载。如果超过这个时间，我们将面临转化率下降，这通常会导致大型电子商务零售商严重的财务损失：

“页面响应延迟 1 秒可能导致转化率减少 7%。”“如果一个电子商务网站每天赚取 10 万美元，1 秒的页面延迟可能会导致您每年损失 250 万美元的销售额。”

- kissmetrics.com

在本章中，我们将讨论一些直接或间接影响应用程序性能和行为的 PHP 领域：

+   最大执行时间

+   内存管理

+   文件上传

+   会话处理

+   输出缓冲

+   禁用调试消息

+   Zend OPcache

+   并发

# 最大执行时间

**最大执行时间**是开发人员经常遇到的最常见错误之一。默认情况下，在浏览器中执行的 PHP 脚本的最大执行时间为 30 秒，除非我们在 CLI 环境中执行脚本，那里没有这样的限制。

我们可以通过一个简单的例子进行测试，通过`index.php`和`script.php`文件，如下所示：

```php
<?php
// index.php
require_once 'script.php';
error_reporting(E_ALL);
ini_set('display_errors', 'On');
sleep(10);
echo 'Test#1';

```

```php
?php
// script.php
sleep(25);
echo 'Test#2';

```

在浏览器中执行，将返回以下错误：

```php
Test#2
Fatal error: Maximum execution time of 30 seconds exceeded in /var/www/html/index.php on line 5

```

在 CLI 环境中执行，将返回以下输出：

```php
Test#2Test#1

```

幸运的是，PHP 提供了两种控制超时值的方法：

+   使用`max_execution_time`配置指令（`php.ini`文件，`ini_set()`函数）

+   使用`set_time_limit()`函数

`set_time_limit()`函数的使用具有有趣的含义。让我们看看以下例子：

```php
<?php
// index.php
error_reporting(E_ALL);
ini_set('display_errors', 'On');
echo 'Test#1';
sleep(5);
set_time_limit(10);
sleep(15);
echo 'Test#2';

```

上面的例子将导致以下错误：

```php
Test#1
Fatal error: Maximum execution time of 10 seconds exceeded in /var/www/html/index.php on line 9

```

有趣的是，`set_time_limit()`函数会从调用它的地方重新启动超时计数器。这实际上意味着，在一个非常复杂的系统中，通过在代码中多次使用`set_time_limit()`函数，我们可以显著扩展超时时间，超出最初设想的边界。这是非常危险的，因为 PHP 超时不是在向用户浏览器交付最终网页时唯一的超时。 

Web 服务器具有各种超时配置，可能会中断 PHP 执行：

+   Apache：

+   `TimeOut`指令，默认为 60 秒

+   Nginx：

+   `client_header_timeout`指令，默认为 60 秒

+   `client_body_timeout`指令，默认为 60 秒

+   `fastcgi_read_timeout`指令，默认为 60 秒

虽然我们可以在浏览器环境中控制脚本超时，但重要的问题是*为什么我们要这样做*？超时通常是资源密集型操作的结果，例如各种非优化循环，数据导出，导入，PDF 文件生成等。CLI 环境，或者理想情况下，专用服务，应该是我们处理所有资源密集型工作的首选。而浏览器环境的主要重点应该是以尽可能短的时间向用户提供页面。

# 内存管理

PHP 开发人员经常需要处理大量数据。虽然“大量”是一个相对的术语，但内存不是。当不负责任地使用某些函数和语言结构的组合时，我们的服务器内存可能在几秒钟内被堵塞。

可能最臭名昭著的函数是`file_get_contents()`。这个易于使用的函数会将整个文件的内容放入内存中。为了更好地理解问题，让我们看看以下例子：

```php
<?php

$content = file_get_contents('users.csv');
$lines = explode("\r\n", $content);

foreach ($lines as $line) {
  $user = str_getcsv($line);
  // Do something with data from $user...
}

```

虽然这段代码完全有效且可用，但它是潜在的性能瓶颈。`$content`变量将整个`users.csv`文件的内容加载到内存中。虽然这对于小文件大小可能有效，比如几兆字节，但这段代码并没有经过性能优化。一旦`users.csv`开始增长，我们将开始遇到内存问题。

我们可以采取什么措施来减轻问题？我们可以重新思考解决问题的方法。一旦我们将思维转向“必须优化性能”模式，其他解决方案就会变得清晰。我们可以不将整个文件的内容读入变量，而是逐行解析文件。

```php
<?php

if (($users = fopen('users.csv', 'r')) !== false) {
  while (($user = fgetcsv($users)) !== false) {
    // Do something with data from $user...
  }
  fclose($users);
}

```

我们不使用`file_get_contents()`和`str_getcsv()`，而是专注于使用另一组函数`fopen()`和`fgetcsv()`。最终结果完全相同，而且完全符合性能友好。在这种特定情况下使用带有句柄的函数，我们有效地确保了内存限制对我们的脚本不构成问题。

不负责任地使用循环是内存的另一个常见原因：

```php
<?php   $conn = new PDO('mysql:host=localhost;dbname=eelgar_live_magento', 'root', 'mysql');   $stmt = $conn->query('SELECT * FROM customer_entity'); $users = $stmt->fetchAll();   foreach ($users as $user) {
  if (strstr($user['email'], 'test')) {
  // $user['entity_id']
 // $user['email'] // Do something with data from $user...  } }

```

现在，让我们继续看一个修改后的、内存友好的例子，效果相同：

```php
<?php

$conn = new PDO('mysql:host=localhost;dbname=eelgar_live_magento', 
  'root', 'mysql');

$stmt = $conn->prepare('SELECT entity_id, email FROM customer_entity WHERE email LIKE :email');
$stmt->bindValue(':email', '%test%');
$stmt->execute();

while ($user = $stmt->fetch(PDO::FETCH_ASSOC)) {
  // $user['entity_id']
  // $user['email']
  // Do something with data from $user...
}

```

`fetchAll()`方法比`fetch()`稍快，但需要更多内存。

当 PHP 达到内存限制时，它会停止脚本执行并抛出以下错误：

```php
Fatal error: Allowed memory size of 33554432 bytes exhausted (tried to 
allocate 2348617 bytes) ...

```

幸运的是，`memory_limit`指令使我们能够控制可用内存量。默认的`memory_limit`值是`128M`，这意味着 128 兆字节的内存。该指令是`PHP_INI_ALL`可更改的，这意味着除了通过`php.ini`文件设置它外，我们还可以使用`ini_set('memory_limit', '512M');`在运行时设置它。

除了调整`memory_limit`指令外，PHP 提供了以下两个返回内存使用信息的函数：

+   `memory_get_usage()`: 返回当前 PHP 脚本分配的内存量

+   `memory_get_peak_usage()`: 返回 PHP 脚本分配的内存峰值

虽然我们可能会想要增加这个值，但我们应该三思而后行。内存限制是针对进程而不是服务器的。Web 服务器本身可以启动多个进程。因此，使用大内存限制值可能会阻塞我们的服务器。除此之外，任何可能实际消耗大量内存的脚本都很容易成为性能优化的候选。对我们的代码应用简单而经过深思熟虑的技术可以大大减少内存使用。

在实际内存管理方面，这里的情况相当自动化。与 C 语言不同，我们需要自己管理内存，PHP 使用垃圾回收结合引用计数机制。不用深入机制本身的细节，可以说变量在不再使用时会自动释放。

有关垃圾回收的更多详细信息，请查看[`php.net/manual/en/features.gc.php`](http://php.net/manual/en/features.gc.php)。

# 文件上传

上传文件是许多 PHP 应用程序的常见功能。PHP 提供了一个方便的全局`$_FILES`变量，我们可以用它来访问上传的文件，或者在文件上传尝试后的错误。

让我们看看以下简单的文件上传表单：

```php
<form method="post" enctype="multipart/form-data">
  <input type="file" name="photo" />
  <input type="file" name="article" />
  <input type="submit" name="submit" value="Upload" />
</form>

```

为了让 PHP 获取文件，我们需要将`form method`的值设置为`post`，并将`enctype`设置为`multipart/form-data`。一旦提交，PHP 将接收并适当填充`$_FILES`变量：

```php
array(2) { 
  ["photo"] => array(5) { 
    ["name"] => string(9) "photo.jpg" 
    ["type"] => string(10) "image/jpeg" 
    ["tmp_name"] => string(14) "/tmp/phpGutI91" 
    ["error"] => int(0) 
    ["size"] => int(42497) 
  } 
  ["article"] => array(5) { 
    ["name"] => string(11) "article.pdf" 
    ["type"] => string(15) "application/pdf" 
    ["tmp_name"] => string(14) "/tmp/phpxsnx1e" 
    ["error"] => int(0) 
    ["size"] => int(433176)
  } 
}

```

在不涉及实际的上传后文件管理的细节的情况下，可以说`$_FILES`包含足够的信息，以便我们可以选择并进一步管理文件，或者在上传过程中指示可能的错误代码。以下八个错误代码可以返回：

+   `UPLOAD_ERR_OK`

+   `UPLOAD_ERR_INI_SIZE`

+   `UPLOAD_ERR_FORM_SIZE`

+   `UPLOAD_ERR_PARTIAL`

+   `UPLOAD_ERR_NO_FILE`

+   `UPLOAD_ERR_NO_TMP_DIR`

+   `UPLOAD_ERR_CANT_WRITE`

+   `UPLOAD_ERR_EXTENSION`

虽然所有错误应该得到同等对待，但其中两个（`UPLOAD_ERR_FORM_SIZE`和`UPLOAD_ERR_PARTIAL`）引发了关键的性能问题：*我们可以上传多大的文件*以及*在过程中是否存在任何超时*？ 

这两个问题的答案可以在配置指令中找到，其中一些直接与文件上传相关，而其他一些与更一般的 PHP 选项相关：

+   `session.gc_maxlifetime`：这是数据被视为垃圾并清理的秒数；默认为 1,440 秒

+   `session.cookie_lifetime`：这是 cookie 的生存时间（以秒为单位）；默认情况下，cookie 在浏览器关闭之前有效

+   `max_input_time`：这是脚本允许解析输入数据（如 POST）的最长时间（以秒为单位）；默认情况下，此功能已关闭

+   `max_execution_time`：这是脚本允许运行的最长时间；默认为 30 秒

+   `upload_max_filesize`：这是上传文件的最大大小；默认为 2 兆字节（2M）

+   `max_file_uploads`：这是允许在单个请求中上传的最大文件数

+   `post_max_size`：这是允许的 POST 数据的最大大小；默认为 8 兆字节（8M）

调整这些选项可以确保我们避免超时和计划的大小限制。为了确保我们可以在过程的早期避免最大文件大小限制，`MAX_FILE_SIZE`可以用作隐藏的表单字段：

```php
<form method="post" enctype="multipart/form-data">
 <input type="hidden" name="MAX_FILE_SIZE" value="100"/>
 <input type="file" name="photo"/>
 <input type="file" name="article"/>
 <input type="submit" name="submit" value="Upload"/>
</form>

```

`MAX_FILE_SIZE`字段必须位于表单可能具有的任何其他文件字段之前。它的值代表 PHP 接受的最大文件大小。

尝试上传大于`MAX_FILE_SIZE`隐藏字段定义的文件现在将导致类似于此处所示的`$_FILES`变量：

```php
array(2) {
  ["photo"] => array(5) {
    ["name"] => string(9) "photo.jpg"
    ["type"] => string(0) ""
    ["tmp_name"] => string(0) ""
    ["error"] => int(2)
    ["size"] => int(0)
  }
  ["article"] => array(5) {
    ["name"] => string(11) "article.pdf"
    ["type"] => string(0) ""
    ["tmp_name"] => string(0) ""
    ["error"] => int(2)
    ["size"] => int(0)
  }
}

```

我们可以看到错误现在已经变成了值`2`，这等于`UPLOAD_ERR_FORM_SIZE`常量。

通常情况下，我们会通过代码优化来解决默认配置的限制，但文件上传是特殊的；因此，我们确实需要确保如果需要的话可以上传大文件。

# 会话处理

会话在 PHP 中是一个有趣的机制，允许我们在总体上是无状态的通信中保持状态。我们可以将它们视为保存在文件中的*每个用户序列化信息数组*。我们使用它们来在各个页面上存储用户特定的信息。默认情况下，会话依赖于 cookie，尽管它们可以配置为在浏览器中使用`SID`参数。

PHP 会话的 cookie 版本大致如下：

1.  从 cookie 中读取会话令牌。

1.  在磁盘上创建或打开现有文件。

1.  锁定文件以进行写入。

1.  读取文件的内容。

1.  将文件数据放入全局`$_SESSION`变量中。

1.  设置缓存头。

1.  将 cookie 返回给客户端。

1.  在每个页面请求上，重复步骤 1-7。

PHP 会话的*SID 版本*工作方式基本相同，除了 cookie 部分。这里的 cookie 被我们通过 URL 推送的 SID 值所取代。

会话机制可用于各种事情，其中一些包括用户登录机制，存储小型数据缓存，模板的部分等。根据使用情况，这可能会引发“最大会话大小”的问题。

默认情况下，脚本执行时，会将会话从文件读入内存。因此，会话文件的最大大小不能超过`memory_limit`指令，默认为 128 兆字节。我们可以通过定义自定义会话处理程序来绕过这种*默认*会话行为。`session_set_save_handler()`函数允许我们注册自定义会话处理程序，该处理程序必须符合`SessionHandlerInterface`接口。使用自定义会话处理程序，我们可以将会话数据存储在数据库中，从而实现更高的性能效率，因为我们现在可以在负载均衡器后面创建可扩展的 PHP 环境，其中所有应用程序节点连接到一个中央会话服务器。

Redis 和 memcached 是两种在 PHP 开发人员中非常流行的数据存储方式。Magento 2 电子商务平台支持 Redis 和 memcached 用于外部会话存储。

会话存储在性能方面起着关键作用，有一些配置指令值得关注：

+   `session.gc_probability`: 这默认为 1

+   `session.gc_divisor`: 这默认为 100

+   `gc_maxlifetime`: 这默认为 1,440 秒（24 分钟）

`gc_probability`和`gc_divisor`指令一起工作。它们的比率（*gc_probability/gc_divisor => 1/100 => 1%*）定义了在每次`session_start()`调用时垃圾收集器运行的概率。一旦垃圾收集器运行，`gc_maxlifetime`指令的值告诉它是否应将某些内容视为垃圾并潜在地进行清理。

在高性能网站中，会话很容易成为瓶颈。深思熟虑的调整和会话存储选择可以带来恰到好处的性能差异。

# 输出缓冲

输出缓冲是一种控制脚本输出的 PHP 机制。想象一下，我们在 PHP 脚本中写下`echo 'test';`，但屏幕上什么都看不到。这是怎么可能的？答案是**输出缓冲**。

以下代码是输出缓冲的一个简单示例：

```php
<?php

ob_start();
sleep(2);
echo 'Chunk#1' . PHP_EOL;
sleep(3);
ob_end_flush();

ob_start();
echo 'Chunk#2' . PHP_EOL;
sleep(5);
ob_end_clean();

ob_start();
echo 'Chunk#3' . PHP_EOL;
ob_end_flush();

ob_start();
sleep(5);
echo 'Chunk#4' . PHP_EOL;

//Chunk#1
//Chunk#3
//Chunk#4

```

在 CLI 环境中执行时，我们首先会在几秒钟后看到`Chunk#1`，然后再过几秒钟，我们会看到`Chunk#3`，最后再过几秒钟，我们会看到`Chunk#4`。`Chunk#2`永远不会被输出。鉴于我们习惯于在调用后立即看到`echo`构造输出的内容，这是一个相当有意思的概念。

有几个与输出缓冲相关的函数，其中以下五个是最有趣的：

+   `ob_start()`: 这会触发一个新的缓冲区，并在另一个*未关闭*缓冲区之后调用时创建堆叠的缓冲区

+   `ob_end_flush()`: 这会输出顶部的缓冲区并关闭这个输出缓冲区

+   `ob_end_clean()`: 这会清除输出缓冲区并关闭输出缓冲

+   `ob_get_contents()`: 这会返回输出缓冲区的内容

+   `ob_gzhandler()`: 这是与`ob_start()`一起使用的回调函数，用于对输出缓冲进行 GZIP 压缩

以下示例演示了堆叠的缓冲区：

```php
<?php

ob_start(); // BUFFER#1
sleep(2);
echo 'Chunk #1' . PHP_EOL;

 ob_start(); // BUFFER#2
 sleep(2);
 echo 'Chunk #2' . PHP_EOL;
 ob_start(); // BUFFER#3
 sleep(2);
 echo 'Chunk #3' . PHP_EOL;
 ob_end_flush();
 ob_end_flush();

sleep(2);
echo 'Chunk #4' . PHP_EOL;
ob_end_flush();

//Chunk #1
//Chunk #2
//Chunk #3
//Chunk #4

```

整个输出在这里被暂停了大约 8 秒，之后所有四个`Chunk#...`字符串一次性输出。这是因为`ob_end_flush()`函数是唯一将输出发送到控制台的函数，而`ob_end_flush()`函数仅仅关闭缓冲区，并将其传递给代码中存在的父缓冲区。

`ob_get_contents()`函数的使用可以为输出缓冲添加更多动态，如下例所示：

```php
<?php

$users = ['John', 'Marcy', 'Alice', 'Jack'];

ob_start();
foreach ($users as $user) {
  echo 'User: ' . $user . PHP_EOL;
}
$report = ob_get_contents();
ob_end_clean();

ob_start();
echo 'Listing users:' . PHP_EOL;
ob_end_flush();

echo $report;

echo 'Total of ' . count($users) . ' users listed' . PHP_EOL;

//Listing users:
//User: John
//User: Marcy
//User: Alice
//User: Jack
//Total of 4 users listed

```

`ob_get_content()`函数允许我们获取缓冲区中存储的内容的字符串表示。我们可以选择是否要进一步修改该内容，输出它，或将其传递给其他结构。

所有这些如何适用于网页？毕竟，我们主要关注我们脚本的性能，大多数情况下是在网页的上下文中。没有输出缓冲，HTML 将随着 PHP 在脚本中的进行而以块的形式发送到浏览器。有了输出缓冲，HTML 将在我们的脚本结束时作为一个字符串发送到浏览器。

请记住，`ob_start()`函数接受一个回调函数，我们可以使用回调函数进一步修改输出。这种修改可以是任何形式的过滤，甚至是压缩。

以下示例演示了输出过滤的使用：

```php
<?php

ob_start('strip_away');
echo '<h1>', 'Bummer', '</h1>';
echo '<p>', 'I felt foolish and angry about it!', '</p>';
ob_end_flush();

function strip_away($buffer)
{
  $keywords = ['bummer', 'foolish', 'angry'];
  foreach ($keywords as $keyword) {
    $buffer = str_ireplace(
      $keyword,
      str_repeat('X', strlen($keyword)),
      $buffer
    );
  }
  return $buffer;
}

// Outputs:
// <h1>XXXXXX</h1><p>I felt XXXXXXX and XXXXX about it!</p>

```

现在，然而，我们不太可能自己编写这些结构，因为框架抽象为我们掩盖了它。

# 禁用调试消息

Ubuntu 服务器是一种流行的、免费的、开源的 Linux 发行版，我们可以使用它快速设置**LAMP**（**Linux, Apache, MySQL, PHP**）堆栈。Ubuntu 服务器的易安装性和长期支持使其成为 PHP 开发人员的热门选择。通过干净的服务器安装，我们可以通过执行以下命令快速启动和运行 LAMP 堆栈：

```php
sudo apt-get update && sudo apt-get upgrade
sudo apt-get install lamp-server^ 

```

完成这些操作后，访问我们的外部服务器 IP 地址，我们应该看到一个 Apache 页面，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/65d05a45-40ba-469f-b2b8-2e510122490d.jpg)

我们在浏览器中看到的 HTML 源自`/var/www/html/index.html`文件。将`index.html`替换为`index.php`后，我们就可以使用 PHP 代码了。

介绍 Ubuntu 服务器的原因是为了强调某些服务器默认值。在所有配置指令中，我们不应该盲目接受*错误记录*和*错误显示*指令的默认值，而不真正理解它们。在开发和生产环境之间不断切换使得在浏览器中暴露机密信息或错过记录正确错误变得太容易了。

考虑到这一点，让我们假设我们在新安装的 Ubuntu 服务器 LAMP 堆栈上有以下损坏的`index.php`文件：

```php
<?php

echo 'Test;

```

尝试在浏览器中打开时，Apache 将返回`HTTP 500 Internal Server Error`，这取决于浏览器，可能会对最终用户可见，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/4fab80d6-e7a8-43a9-b4e6-574dc6d457e6.jpg)

理想情况下，我们希望我们的 Web 服务器配置了一个漂亮的通用错误页面，以使其更加用户友好。虽然浏览器的响应可能会满足最终用户，但在这种情况下，它确实不能满足开发人员。返回的信息并没有指示任何关于错误性质的信息，这使得难以修复。幸运的是，对于我们来说，在这种情况下默认的 LAMP 堆栈配置包括将错误记录到`/var/log/apache2/error.log`文件中：

```php
[Thu Feb 02 19:23:26.026521 2017] [:error] [pid 5481] [client 93.140.71.25:55229] PHP Parse error: syntax error, unexpected ''Test;' (T_ENCAPSED_AND_WHITESPACE) in /var/www/html/index.php on line 3

```

虽然这种行为对于生产环境来说是完美的，但对于开发环境来说却很麻烦。在开发过程中，我们真的希望我们的错误能够显示在浏览器中，以加快速度。PHP 允许我们通过几个配置指令来控制错误报告和日志记录行为，以下是最重要的：

+   `error_reporting`：这是我们希望监视的错误级别；我们可以使用管道（`|`）运算符列出几个错误级别常量。它的默认值是`E_ALL & ~E_NOTICE & ~E_STRICT & ~E_DEPRECATED`。

+   `display_errors`：这指定是否将错误发送到浏览器/CLI 或对用户隐藏。

+   `error_log`：这是我们想要记录 PHP 错误的文件。

+   `log_errors`：这告诉我们是否应将错误记录到`error_log`文件中。

可用的错误级别常量定义如下：

+   `E_ERROR (1)`

+   `E_WARNING (2)`

+   `E_PARSE (4)`

+   `E_NOTICE (8)`

+   `E_CORE_ERROR (16)`

+   `E_CORE_WARNING (32)`

+   `E_COMPILE_ERROR (64)`

+   `E_COMPILE_WARNING (128)`

+   `E_USER_ERROR (256)`

+   `E_USER_WARNING (512)`

+   `E_USER_NOTICE (1024)`

+   `E_STRICT (2048)`

+   `E_RECOVERABLE_ERROR (4096)`

+   `E_DEPRECATED (8192)`

+   `E_USER_DEPRECATED (16384)`

+   `E_ALL (32767)`

使用`error_reporting()`和`ini_set()`函数，我们可以使用一些指令来配置日志和显示运行时的情况：

```php
<?php

error_reporting(E_ALL);
ini_set('display_errors', 'On');

```

小心使用`ini_set()`来设置`display_errors`，如果脚本有致命错误，它将不会产生任何效果，因为运行时不会被执行。

错误显示和错误日志记录是两种不同的机制，彼此协同工作。在开发环境中，我们可能更多地从错误显示中受益，而在生产环境中，错误日志记录是更好的选择。

# Zend OPcache

PHP 的一个主要缺点是它在每个请求上加载和解析 PHP 脚本。PHP 代码首先以纯文本形式编译为操作码，然后执行操作码。尽管这种性能影响在总共只有一个或几个脚本的小型应用中可能不会被注意到，但对于较大的平台（如 Magento、Drupal 等）来说，它会产生很大的影响。

从 PHP 5.5 开始，有一个开箱即用的解决方案。Zend OPcache 扩展通过将编译后的操作码存储在共享内存（RAM）中来解决重复编译的问题。只需更改配置指令即可打开或关闭它。

有很多配置指令，其中一些可以帮助我们入门：

+   `opcache.enable`：默认为 1，可通过`PHP_INI_ALL`更改。

+   `opcache.enable_cli`：默认为 0，可通过`PHP_INI_SYSTEM`更改。

+   `opcache.memory_consumption`：默认为 64，可通过`PHP_INI_SYSTEM`更改，定义了 OPcache 使用的共享内存大小。

+   `opcache.max_accelerated_files`：默认为 2000，可通过`PHP_INI_SYSTEM`更改，定义了 OPcache 哈希表中键/脚本的最大数量。其最大值为 1000000。

+   `opcache.max_wasted_percentage`：默认为 5，可通过`PHP_INI_SYSTEM`更改，定义了允许浪费内存的最大百分比，然后安排重新启动。

尽管`opcache.enable`标记为`PHP_INI_ALL`，但在运行时使用`ini_set()`启用它是行不通的。只有使用`ini_set()`来禁用它才有效。

尽管完全自动化，Zend OPcache 还为我们提供了一些函数：

+   `opcache_compile_file()`：这会编译并缓存一个脚本而不执行它

+   `opcache_get_configuration()`：这会获取 OPcache 配置信息

+   `opcache_get_status()`：这会获取 OPcache 信息

+   `opcache_invalidate()`：这会使 OPcache 失效

+   `opcache_is_script_cached()`：这告诉我们脚本是否通过 OPcache 缓存

+   `opcache_reset()`：这会重置 OPcache 缓存

虽然我们不太可能自己使用这些方法，但它们对于处理 OPcache 的实用工具非常有用。

opcache-gui 工具显示 OPcache 统计信息、设置和缓存文件，并提供实时更新。该工具可在[`github.com/amnuts/opcache-gui`](https://github.com/amnuts/opcache-gui)下载。

需要注意的一件事是 OPcache 潜在的*缓存冲击*问题。通过`memory_consumption`、`max_accelerated_files`和`max_wasted_percentage`配置指令，OPcache 确定何时需要刷新缓存。当这种情况发生时，具有大量流量的服务器可能会遇到缓存冲击问题，大量请求同时生成相同的缓存条目。因此，我们应该尽量避免频繁的缓存刷新。为此，我们可以使用缓存监控工具，并调整这三个配置指令以适应我们的应用程序大小。

# 并发性

并发性是一个适用于多层堆栈的主题，有一些关于 Web 服务器的配置指令，每个开发人员都应该熟悉。并发性指的是在 Web 服务器内处理多个连接。对于 PHP 来说，两个最受欢迎的 Web 服务器，Apache 和 Nginx，都允许一些基本配置来处理多个连接。

虽然有很多关于哪个服务器更快的争论，但带有 MPM 事件模块的 Apache 与 Nginx 的性能基本相当。

以下指令规定了 Apache MPM 事件并发性，因此值得密切关注：

+   `ThreadsPerChild`：这是每个子进程创建的线程数

+   `ServerLimit`：这是可配置的进程数量限制

+   `MaxRequestWorkers`：这是同时处理的最大连接数

+   `AsyncRequestWorkerFactor`：这是每个进程的并发连接限制

可以使用以下公式计算可能的最大并发连接数：

最大连接数=（AsyncRequestWorkerFactor + 1）* MaxRequestWorkers

这个公式非常简单；但是，改变`AsyncRequestWorkerFactor`不仅仅是输入更高的配置值。我们需要对击中 Web 服务器的流量有扎实的了解，这意味着进行广泛的测试和数据收集。

以下指令规定了 Nginx 的并发性，因此值得密切关注：

+   `worker_processes`：这是工作进程的数量；默认为 1

+   `worker_connections`：这是工作进程可以打开的最大同时连接数；默认为 512

Nginx 可以提供服务的理想总用户数可以归结为以下公式：

最大连接数=工作进程*工作连接数

虽然我们只是初步了解了 Web 服务器并发性和这两个 Web 服务器的总体配置指令，但上述信息应该作为我们的起点。虽然开发人员通常不会调整 Web 服务器，但他们应该知道何时标记可能影响其 PHP 应用程序性能的错误配置。

# 总结

在本章中，我们已经讨论了 PHP 性能优化的一些方面。虽然这些只是涉及整体性能主题的表面，但它们概述了每个 PHP 开发人员都应该深入了解的最常见领域。广泛的配置指令范围允许我们调整应用程序行为，通常与 Web 服务器本身协同工作。然而，最佳性能的支柱在于在整个堆栈中谨慎使用资源，正如我们通过简单的 SQL 查询示例所观察到的。

接下来，我们将研究无服务器架构，这是标准开发环境的新兴抽象。


# 第八章：无服务器之前

“无服务器”一词可能是最近软件行业中最热门的术语之一。它可以被描述为部分或完全抽象出运行软件所需的基础架构的架构风格。这种抽象通常由各种第三方服务提供商提供。

将其放在 Web 应用程序开发的背景下，让我们考虑单页应用程序（SPA）。如今，我们可以轻松地在完全托管的基础架构上开发整个 SPA，比如 AWS。这样的 SPA 可以用 Angular 编写，客户端组件可以从 S3 存储桶中提供，通过 Amazon Cognito 服务管理用户，同时使用 DynamoDB 作为应用程序数据存储。托管的基础架构将我们从任何主机或服务器交易中抽象出来，使我们能够将精力集中在应用程序上。我们最终得到的是一种无服务器应用程序，这取决于我们定义的范围有多窄。

像任何架构风格一样，无服务器远非“解决方案”。虽然某些类型的应用程序可能会从中受益，但其他类型的应用程序可能会发现它完全不匹配。例如，长时间运行的应用程序可能很容易成为无服务器框架的昂贵解决方案，而不是在专用服务器上运行工作负载。关键是找到合适的平衡。

无服务器的更严格和狭窄的定义是纯代码/函数托管，通常称为函数即服务（FaaS）。这样的基础设施提供高并发、可扩展、成本效益的解决方案，因为它们大多是按“按执行付费”的模式定价。AWS Lambda 和 Iron.io 是两个完美体现这一概念的平台。

在本章中，我们将更仔细地看看如何利用 AWS Lambda 和 Iron.io 平台来部署我们代码的块：

+   使用无服务器框架

+   使用 Iron.io IronWorker

# 使用无服务器框架

AWS Lambda 是由亚马逊网络服务（AWS）提供的计算服务。它的特点是可以在不提供或管理任何服务器的情况下运行代码。自动扩展功能使其能够承受每秒数千个请求。加上按执行付费的额外好处，这项服务在开发人员中引起了一些关注。随着时间的推移，无服务器框架被开发出来，以使 AWS Lambda 服务的使用变得容易。

无服务器框架可在[`serverless.com`](https://serverless.com)上找到。

假设我们已经创建了一个 AWS 账户，并且手头上有一个干净的 Ubuntu 服务器安装，让我们继续概述设置和利用无服务器框架所需的步骤。

在我们可以在 AWS Lambda 上部署应用程序之前，我们需要确保我们有一个具有正确权限集的用户。AWS 权限非常强大，我们可以根据资源对其进行调整。无服务器框架除了 AWS Lambda 本身之外，还使用了其他几个 AWS 资源，如 S3、API Gateway 等。为了使我们的演示简单，我们将首先创建一个具有管理员访问权限的 IAM 用户：

1.  我们首先登录到[`aws.amazon.com/console/`](https://aws.amazon.com/console/)的 AWS 控制台。登录后，我们需要在“我的安全凭证”|“用户”屏幕下继续：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/26e8dfc0-bee9-4725-9426-068b56ebcace.png)

1.  要添加新用户，我们点击“添加用户”按钮。这将触发一个四步过程，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/2b71f9fd-594c-4e29-a045-f80cebfa993c.png)

1.  我们在这里提供两条信息，用户名和访问类型。我们的无服务器集成需要编程访问类型。单击“下一步：权限”按钮将我们带到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/afed7936-66d3-43d5-b95c-200800c9b0ac.png)

1.  这里有几种方法可以在这里为用户附加权限。 为了保持简单，我们点击“直接附加现有策略”框，并在“策略类型”字段过滤器中输入 AdministratorAccess。 然后我们简单地勾选 AdministratorAccess 策略，然后点击“下一步：审阅”按钮，这将带我们到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/e4ce7578-bcdc-45a8-9e40-d3c2c4cf9a61.png)

1.  在这里，我们仅仅回顾了当前的进展，最后点击“创建用户”按钮，这将带我们到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/f8227089-6927-46fa-a6a4-195feb1ce937.png)

1.  现在我们有了 Access key ID 和 Secret access key，这是 serverless 框架所需的两个信息。

通常认为，创建具有完整管理权限的用户是一个不好的安全实践。 通常，我们会创建具有所需权限的最低限度的用户。

完成了这些步骤，我们可以继续设置 serverless 框架本身。

serverless 框架运行在 Node.js 之上。 假设我们有一个干净的 Ubuntu 服务器实例，我们可以通过以下步骤进行设置：

1.  使用以下控制台命令安装 Node.js：

```php
curl -sL https://deb.nodesource.com/setup_7.x | sudo -E bash -
sudo apt-get install -y nodejs

```

1.  一旦安装了 Node.js，`npm`控制台工具就可用了。 服务器框架本身作为一个`npm`包可在[`www.npmjs.com/package/serverless`](https://www.npmjs.com/package/serverless)上获得。 运行以下控制台命令应该可以在我们的服务器上安装它：

```php
sudo npm install -g serverless
serverless --version

```

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/3ff41a29-4d16-41cf-bff0-4bf06d7490e2.png)

1.  现在安装了 serverless 框架，我们需要设置控制台环境变量：`AWS_ACCESS_KEY_ID`和`AWS_SECRET_ACCESS_KEY`。 这些在部署期间由 serverless 使用：

```php
export AWS_ACCESS_KEY_ID=<--AWS_ACCESS_KEY_ID-->
export AWS_SECRET_ACCESS_KEY=<--AWS_SECRET_ACCESS_KEY--> 

```

1.  现在我们可以处理与 PHP 相关的细枝末节了。 官方 serverless 框架示例使用运行 PHP 函数的 AWS Lambda，可以在[`github.com/ZeroSharp/serverless-php`](https://github.com/ZeroSharp/serverless-php)找到。 我们可以通过以下控制台命令安装它：

```php
serverless install --url https://github.com/ZeroSharp/serverless-php

```

这应该给我们一个类似以下截图的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/ecebec78-dabf-4a68-b734-acdfb7542473.png)

serverless 安装命令只是将 Git 存储库的内容拉到本地目录中。 在新创建的`serverless-php`目录中，有一个`index.php`文件，其中包含我们的 PHP 应用程序代码。 令人奇怪的是，这里有一些东西，乍一看似乎与 PHP 无关，比如`handler.js`。 快速查看`handler.js`揭示了一些有趣的东西，即 AWS Lambda 服务实际上并不直接运行 PHP 代码。 它的工作方式是`handler.js`，这是一个 Node.js 应用程序，生成一个带有包含的`php`二进制文件的进程。 简而言之，`index.php`是我们的应用程序文件，其余的是必要的样板。

作为一个快速的健全检查，让我们触发以下两个命令：

```php
php index.php
serverless invoke local --function hello

```

这些应该给我们以下输出，表明 serverless 能够看到并执行我们的函数：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/43fdf30e-4b1c-4deb-a925-3602a44b81e1.png)

最后，我们准备将我们的 PHP 应用程序部署到 AWS Lambda 服务。 我们通过执行以下命令来实现这一点：

```php
serverless deploy

```

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/95344457-6c57-4980-b8b5-1142d0972798.png)

这个简单的命令启动了一系列事件，导致在 AWS 控制台中利用了几种不同的 AWS 服务。

打开在端点下列出的链接显示我们的应用程序是公开可用的：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/9ce30662-5947-40ef-ab1f-c83d254b707e.png)

这是由 Amazon API Gateway 服务下自动创建的 API 入口所实现的，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/e369c9b8-3397-46dd-b7c2-5981dca8800f.png)

API Gateway 将`GET /hello` URL 操作与 AWS Lambda `serverless-php-dev-hello`应用程序连接起来。 在 AWS Lambda 屏幕下查看这个应用程序：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/7f7e212a-3c65-41bd-bc8b-fd69a845e979.png)

CloudFormation 堆栈也已创建，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/b167b8cc-6d54-4f29-8577-ba77cdb709ba.png)

S3 存储桶也已创建，如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/7f0a9b21-a5be-4b4f-b51d-9775fb452b9a.png)

CloudWatch 日志组也已创建，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/e52db856-4769-46ea-aa17-0b1c01f8e784.png)

简而言之，`serverless deploy`为我们启动了许多服务，因此我们有更多时间专注于实际的应用程序开发。尽管 AWS Lambda 只在运行代码时收费，但混合使用的其他一些服务可能是不同的。这就是为什么重要的是要密切关注自动触发的一切。

幸运的是，无服务器还提供了一个清理命令，写成如下：

```php
serverless remove

```

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/8a1807f7-94d9-4e90-bcab-e513dec0fa22.png)

此命令通过删除先前创建的所有服务和资源来进行总体清理。

# 使用 Iron.io IronWorker

Iron.io 是一个为高性能和并发设计的无服务器作业处理平台。该平台围绕 Docker 容器构建，本身是与语言无关的。我们可以使用它来运行几乎任何编程语言，包括 PHP。Iron.io 平台的三个主要特点是：

+   **IronWorker**：这是一个弹性的任务/队列式工作服务，可扩展处理

+   **IronMQ**：这是为分布式系统设计的消息队列服务

+   **IronCache**：这是一个弹性和耐用的键/值存储

虽然我们不能在 Iron.io 平台上运行实时 PHP，但我们可以利用其 IronWorker 功能来进行任务/队列式类型的应用程序。

假设我们已经打开了一个 Iron.io 账户并且在 Ubuntu 服务器上安装了 Docker，我们就能够按照下面的步骤来了解 IronWorker 的工作流程。

我们首先点击 Iron.io 仪表板下的 New Project 按钮。这将打开一个简单的屏幕，我们只需要输入项目名称：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/3893fc43-cfa5-4ed0-b4ba-048ea945b652.png)

项目创建后，我们可以点击项目设置链接。这将打开一个屏幕，显示包括认证/配置参数在内的多个信息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/271ab3b9-79d2-4e1b-817a-c2bfd145e822.png)

我们稍后将配置`iron.json`文件，因此需要这些参数。有了这些信息，我们就可以继续进行应用程序的配置。

在应用程序方面，我们首先安装`iron`控制台工具：

```php
curl -sSL https://cli.iron.io/install | sh

```

安装完成后，`iron`命令应该可以通过控制台使用，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/456cb0f0-3aea-4c2d-afc4-61428794c65a.png)

现在我们准备启动我们的第一个 Iron 应用。

假设我们有一个干净的目录，我们想要放置我们的应用程序文件，我们首先添加`composer.json`，内容如下：

```php
{
  "require": {
    "iron-io/iron_worker": "2.0.4",
    "iron-io/iron_mq": "2.*",
    "wp-cli/php-cli-tools": "~0.10.3"
  }
}

```

在这里，我们只是告诉 Composer 要拉取哪些库：

+   `iron_worker`：这是 IronWorker 的客户端库（[`packagist.org/packages/iron-io/iron_worker`](https://packagist.org/packages/iron-io/iron_worker)）

+   `iron_mq`：这是 IronMQ 的客户端绑定（[`packagist.org/packages/iron-io/iron_mq`](https://packagist.org/packages/iron-io/iron_mq)）

+   `php-cli-tools`：这些是用于 PHP 的控制台实用程序（[`packagist.org/packages/wp-cli/php-cli-tools`](https://packagist.org/packages/wp-cli/php-cli-tools)）

然后我们创建`Dockerfile`，内容如下：

```php
FROM iron/php

WORKDIR /app
ADD . /app

ENTRYPOINT ["php", "greet.php"]

```

这些`Dockerfile`指令帮助 Docker 自动为我们构建必要的镜像。

然后我们添加`greet.payload.json`文件及其内容如下：

```php
{
  "name": "John"
}

```

这实际上并不是流程中必要的一部分，但我们正在使用它来模拟我们的应用程序接收到的有效载荷。

然后我们添加`greet.php`文件及其内容如下：

```php
<?php

require 'vendor/autoload.php';

$payload = IronWorker\Runtime::getPayload(true);

echo 'Welcome ', $payload['name'], PHP_EOL;

```

`greet.php`文件是我们的实际应用程序。在 IronWorker 服务上创建的作业将排队并执行此应用程序。应用程序本身很简单；它只是简单地获取名为`name`的负载变量的值，并将其输出。这对于我们的 IronWorker 演示足够了。

然后创建`iron.json`文件，内容类似如下：

```php
{
  "project_id": "589dc552827e8d00072c7e11",
  "token": "Gj5vBCht0BP9MeBUNn5g"
}

```

确保我们粘贴了从 Iron.io 仪表板的项目设置屏幕获取的`project_id`和`token`。

有了这些文件，我们已经定义了我们的应用程序，现在准备开始 Docker 相关的任务。总体思路是，我们将首先创建一个本地 Docker 镜像用于测试。一旦测试完成，我们将把 Docker 镜像推送到 Docker 仓库，然后配置 Iron.io 平台使用 Docker 仓库中的镜像来驱动其 IronWorker 作业。

我们现在可以通过运行以下命令将我们的工作程序依赖项安装到 Docker 中，如`composer.json`文件所设定的。

```php
docker run --rm -v "$PWD":/worker -w /worker iron/php:dev composer install

```

输出应该显示 Composer 正在安装依赖项，如下图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/54528b74-a093-4227-9bfe-d67ebba7aa26.png)

一旦 Composer 安装完依赖项，我们应该测试一下我们的应用程序是否在执行。我们可以通过以下命令来做到这一点：

```php
docker run --rm -e "PAYLOAD_FILE=greet.payload.json" -v "$PWD":/worker -w /worker iron/php php greet.php

```

前面命令的输出应该是一个“欢迎 John”字符串，如下图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/773c3783-468f-4602-a540-ec2c766777bf.png)

这证实了我们的 Docker 镜像正常工作，现在我们准备构建并部署它到[`hub.docker.com`](https://hub.docker.com)。

Docker Hub，位于[`hub.docker.com`](https://hub.docker.com)，是一个基于云的服务，提供了集中的容器镜像管理解决方案。虽然它是一个商业服务，但也有一个免费的*一个仓库*计划。

假设我们已经打开了 Docker Hub 账户，通过控制台执行以下命令将标记我们已登录：

```php
docker login --username=ajzele

```

其中`ajzele`是用户名，应该用我们自己的替换：![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/4443de04-07d7-4d4c-961e-ed0ed8e90bd3.png)

我们现在可以通过执行以下命令打包我们的 Docker 镜像：

```php
docker build -t ajzele/greet:0.0.1 .

```

这是一个标准的构建命令，将创建一个带有版本`0.0.1`标记的`ajzele/greet`镜像

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/249c6260-3677-4b42-ab8a-c29131084018.png)

现在创建了镜像，我们应该先测试它，然后再将其推送到 Docker Hub。执行以下命令确认我们新创建的`ajzele/greet`镜像工作正常：

```php
docker run --rm -it -e "PAYLOAD_FILE=greet.payload.json" ajzele/greet:0.0.1

```

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/27fcdeea-f539-4b2d-81d6-48e901398b95.png)

生成的欢迎 John 输出确认我们的镜像现在已准备好部署到 Docker Hub，可以使用以下命令完成：

```php
docker push ajzele/greet:0.0.1

```

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/0e266f2c-0cb6-44f1-9a97-7b6870f8e86c.png)

一旦推送过程完成，我们应该能在 Docker Hub 仪表板下看到我们的镜像：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/962b5d25-bf1d-45e3-a699-78234cf300d2.png)

到目前为止有相当多的步骤，但我们快要完成了。现在我们的应用程序在 Docker Hub 仓库中可用作为 Docker 镜像，我们可以把重点转回 Iron.io 平台。我们在过程中早已安装的`iron`控制台工具能够在 Iron.io 仪表板下注册 Docker Hub 镜像为一个新的工作程序：

```php
iron register ajzele/greet:0.0.1

```

以下截图显示了此命令的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/aa2d7445-b1b8-4ee6-9c08-382268bd66e8.png)

此时，我们应该在 Iron.io 仪表板的 TASKS 选项卡下看到`ajzele/greet`工作程序：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/12bdfd6d-417a-4f1a-933e-43f3ef7edd37.png)

虽然工作程序已注册，但此时尚未执行。Iron.io 平台允许我们将工作程序作为定时或排队任务执行。

如下截图所示的定时任务允许我们选择注册的 Docker 镜像以及执行时间和其他一些选项：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/afdb4665-59f0-4bb3-8d05-d22a9fafeec3.png)

如下截图所示，排队任务还允许我们选择注册的 Docker 镜像，但这次没有任何特定的时间配置：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/195b6831-ff13-400e-a34a-6c9e1a1a0812.png)

使用`iron`控制台工具，我们可以基于`ajzele/greet` worker 创建计划和排队任务。

以下命令创建了一个基于`ajzele/greet` worker 的计划任务：

```php
iron worker schedule --payload-file greet.payload.json -start-at="2017-02-12T14:16:28+00:00" ajzele/greet

```

`start-at`参数以 RFC3339 格式定义了一个时间。

有关 RFC3339 格式的更多信息，请查看[`tools.ietf.org/html/rfc3339`](https://tools.ietf.org/html/rfc3339)。

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/62b5908c-ed94-43e7-8f1c-5040177b6f1c.png)

Iron.io 仪表板现在应该将其显示为 SCHEDULED TASKS 部分下的新条目：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/46ff3923-9a05-4496-a2fa-8a5c4a2d698b.png)

当计划的时间到来时，Iron.io 平台将执行此计划任务。

以下命令创建了一个基于`ajzele/greet` worker 的排队任务：

```php
iron worker queue --payload-file greet.payload.json --wait ajzele/greet

```

以下截图显示了此命令的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/14d527b1-f84d-4879-9f90-b6e337065ab5.png)

Iron.io 仪表板通过增加 TASKS 部分下的 Complete 计数器（在下面的截图中当前显示为*3*）记录每个执行的任务：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/1cc021bf-9195-40a4-95a2-0588d956d8bc.png)

进入`ajzele/greet` worker 可以查看每个作业的详细信息，包括计划和排队的作业。

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/6ec8a8ac-57dd-4ce4-a397-37237b31fc67.png)

到目前为止，您已经学会了如何创建 PHP 应用程序 Docker 镜像，将其推送到 Docker Hub，将其注册到 Iron.io 平台，并开始调度和排队任务。关于调度和排队任务的部分可能有点棘手，因为我们是从控制台而不是从 PHP 代码中进行的。

幸运的是，`composer.json`文件引用了我们需要的所有库，以便能够从 PHP 代码中调度和排队任务。假设我们抓取了`iron.json`和`composer.json`文件，并移动到完全不同的服务器，甚至是我们的本地开发机器。在那里，我们只需要在控制台上运行`composer install`，并创建内容如下的`index.php`文件：

```php
<?php

require './vendor/autoload.php';

$worker = new IronWorker\IronWorker();

$worker->postScheduleAdvanced(
  'ajzele/greet',
  ['name' => 'Mariya'],
  '2017-02-12T14:33:39+00:00'
);

$worker->postTask(
  'ajzele/greet',
  ['name' => 'Alice']
);

```

一旦这段代码被执行，它将创建一个已计划和一个排队的任务，就像`iron`控制台工具一样。

虽然我们可能不会使用它来托管整个 PHP 应用程序，但 Iron.io 平台使得创建和运行各种隔离作业变得轻松和无忧。

# 总结

在本章中，我们采用了两个流行的无服务器平台--AWS 和 Iron.io 的实际操作方法。使用无服务器框架，我们能够快速将我们的代码部署到 AWS Lambda 服务。实际的部署涉及了一些 AWS 服务，将我们的小代码块作为一个 REST API 端点暴露出来，后台调用 AWS Lambda。由于所有服务都由 AWS 管理，我们得到了真正的无服务器体验。如果我们考虑一下，这是一个非常强大的概念。除了 AWS，Iron.io 是另一个有趣的无服务器平台。与 AWS Lambda 上的实时代码执行不同，Iron.io 上的代码执行是作为已计划/排队的任务（并不是说 AWS 没有自己的排队解决方案）。虽然 AWS Lambda 原生支持 Node.js、Java、Python 和.NET Core 运行时，但 Iron.io 通过使用 Docker 容器来抽象语言。尽管如此，我们仍然能够通过 Node.js 来包装 PHP 二进制文件，甚至在 AWS Lambda 上运行 PHP。

无服务器方法确实具有吸引力。虽然它可能不是我们某些应用程序的完整解决方案，但它确实可以处理资源密集型的部分。无需费力的使用和按执行付费的模式对某些人来说可能是一个改变游戏规则的因素。

接下来，我们将看一下 PHP 在流行的响应式编程范式方面提供了什么。


# 第九章：响应式编程

软件行业时不时会发生变革。这种变革丰富了思想，承诺更容易的系统和应用程序开发。如今，驱动这一切的主要是互联网，因为它是所有连接应用程序的媒介，不仅仅是在我们的浏览器中运行的应用程序。大多数移动用户消费大量的云服务，甚至没有意识到。在这样一个互联的世界中确保一致的用户体验是一个以多种方式解决的挑战。响应性就是其中一种观点，其中编程语言本身起着重要作用。

传统上，PHP 遵循同步编程模型，不太适合异步编程。尽管标准库已经包含了编写异步 I/O 应用程序所需的一切，但现实可能大相径庭。例如，MySQLi 和 MySQL（PDO）仍然是阻塞的，使得使用 PHP 进行异步编程毫无意义。幸运的是，形势正在改变，人们对 PHP 的异步性有了更多的认识。

响应式编程是软件行业的新兴话题，它建立在可观察对象的基础上。我们将其与异步行为联系在一起，因为可观察对象提供了访问多个项目的异步序列的理想方式。在更高的层面上，它只是另一种编程范式，就像过程式、面向对象、声明式和函数式编程一样。虽然采用可观察对象、操作符、观察者和其他构建块需要一定的思维转变，但作为回报，它允许更大的表现力和单向数据流，从而导致更清洁和简单的代码。

在本章中，我们将更详细地研究以下几个部分：

+   与事件驱动编程的相似之处

+   使用 RxPHP：

+   安装 RxPHP

+   可观察对象和观察者

+   主题

+   操作符

+   编写自定义操作符

+   非阻塞 I/O

+   使用 React：

+   安装 React

+   React 事件循环

+   可观察对象和事件循环

# 与事件驱动编程的相似之处

维基百科对响应式编程的定义如下：

“以数据流和变化传播为导向的编程范式。”

这个想法的第一印象可能暗示与众所周知的事件驱动编程有些相似。数据流和变化的传播听起来有点像我们可以通过 PHP 中的`\SplSubject`、`\SplObjectStorage`和`\SplObserver`接口来实现的东西，如下面的琐碎例子所示。`\SplObjectStorage`接口进一步封装了`\Countable`、`\Iterator`、`\Traversable`、`\Serializable`和`\ArrayAccess`接口：

```php
<?php   class UserRegister implements \SplSubject {
  protected $user;
  protected $observers;    public function __construct($user)
 {  $this->user = $user;
  $this->observers = new \SplObjectStorage();
 }    public function attach(\SplObserver $observer)
 {  $this->observers->attach($observer);
 }    public function detach(\SplObserver $observer)
 {  $this->observers->detach($observer);
 }    public function notify()
 {  foreach ($this->observers as $observer) {
  $observer->update($this);
 } }    public function getUser()
 {  return $this->user;
 } }   class Mailer implements \SplObserver {
  public function update(\SplSubject $subject)
 {  if ($subject instanceof UserRegister) {
  echo 'Mailing ', $subject->getUser(), PHP_EOL;
 } } }   class Logger implements \SplObserver {
  public function update(\SplSubject $subject)
 {  if ($subject instanceof UserRegister) {
  echo 'Logging ', $subject->getUser(), PHP_EOL;
 } } }   $userRegister = new UserRegister('John'); // some code... $userRegister->attach(new Mailer()); // some code... $userRegister->attach(new Logger()); // some code... $userRegister->notify();

```

我们可以说，数据流转化为从`$userRegister`实例的`notify()`方法传来的更新序列，变化的传播转化为触发`mailer`和`logger`实例的`update()`方法，而`\SplObjectStorage`方法则起着重要作用。这只是在 PHP 代码的上下文中对响应式编程范式的一个琐碎和肤浅的解释。此外，目前这里没有异步性。PHP 运行时和标准库有效地提供了编写异步代码所需的一切。在其中加入*响应性*，只是选择合适的库的问题。

尽管 PHP 反应式编程的库选择远不及 JavaScript 生态系统丰富，但有一些值得注意的库，如 RxPHP 和 React。

# 使用 RxPHP

最初由微软为.NET 平台开发，名为**ReactiveX**（响应式扩展）的一组库可在[`reactivex.io`](http://reactivex.io)上找到。 ReactiveX 允许我们使用可观察序列编写异步和基于事件的程序。 他们通过抽象化低级关注点（例如非阻塞 I/O）来实现这一点，我们稍后会谈论。 随着时间的推移，几种编程语言制作了自己的 ReactiveX 实现，遵循几乎相同的设计模式。 名为 RxPHP 的 PHP 实现可以从[`github.com/ReactiveX/RxPHP`](https://github.com/ReactiveX/RxPHP)下载：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/2e6cd07e-5278-44a0-bf41-28da819dc572.png)

# 安装 RxPHP

RxPHP 库可作为 Composer`reactivex/rxphp`包使用。 假设我们已经安装了 PHP 和 Composer，我们可以在空目录中简单地执行以下命令：

```php
composer require reactivex/rxphp

```

这应该给我们一个类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/fd7135e9-4256-4fe9-9950-72f5b86a3c0e.png)

输出建议安装`react/event-loop`；我们需要确保执行以下命令进行跟进：

```php
composer require react/event-loop

```

这应该给我们一个类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/8627f3dc-2c79-4815-babe-131e0476128d.png)

现在剩下的就是创建一个`index.php`文件，其中包括由 Composer 生成的`autoload.php`文件，然后我们就可以开始玩了

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/ccd5737a-95a9-4f41-be15-b8026849479e.png)

RxPHP 库由几个关键组件组成，其中最基本的是以下内容：

+   可观察

+   观察者

+   主题

+   操作员

继续前进，让我们更仔细地看看每个组件。

# 可观察和观察者

在我们的介绍示例中，我们提到了使用`\SplSubject`和`\SplObserver`的观察者模式。 现在，我们正在介绍 RxPHP 可观察和观察者组件。 我们可能会说`\SplSubject`类似于`Rx\Observable`，而`\SplObserver`类似于`Rx\Observer\CallbackObserver`。 然而，整个 SPL 和 Rx 只是表面上类似。 `Rx\Observable`比`\SplObserver`更强大。 我们可以将`Rx\Observable`视为事件的惰性源，一种随时间产生值的东西。 可观察对象向其观察者发出以下三种类型的事件：

+   流中的当前项目

+   错误，如果发生了错误

+   完整的状态

简而言之，它是一个知道如何发出内部数据更改信号的响应式数据源。

让我们看下面的简单例子：

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   use \Rx\Observable; use \Rx\Observer\CallbackObserver; use \React\EventLoop\Factory; use \Rx\Scheduler;   $loop = Factory::create();   Scheduler::setDefaultFactory(function () use ($loop) {
  return new Scheduler\EventLoopScheduler($loop); });   $users = Observable::fromArray(['John', 'Mariya', 'Marc', 'Lucy']);   $logger = new CallbackObserver(
  function ($user) {
  echo 'Logging: ', $user, PHP_EOL;
 },  function (\Throwable $t) {
  echo $t->getMessage(), PHP_EOL;
 },  function () {
  echo 'Stream complete!', PHP_EOL;
 } );   $users->subscribe($logger);   $loop->run();

```

其输出如下：

```php
Logging: John
Logging: Mariya
Logging: Marc
Logging: Lucy
Stream complete!

```

我们看到`Observable`实例的`subscribe()`方法接受`CallbackObserver`的实例。 观察者的三个参数中的每一个都是回调函数。 第一个回调处理流项目，第二个返回潜在错误，第三个指示已完成的流。

RxPHP 提供了几种类型的可观察对象：

+   `AnonymousObservable`

+   `ArrayObservable`

+   `ConnectableObservable`

+   `EmptyObservable`

+   `ErrorObservable`

+   `ForkJoinObservable`

+   `GroupedObservable`

+   `IntervalObservable`

+   `IteratorObservable`

+   `MulticastObservable`

+   `NeverObservable`

+   `RangeObservable`

+   `RefCountObservable`

+   `ReturnObservable`

+   `TimerObservable`

让我们来看一个更详细的例子：可观察和观察者

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   use \Rx\Observable; use \Rx\Observer\CallbackObserver; use \React\EventLoop\Factory; use \Rx\Scheduler;   $loop = Factory::create();   Scheduler::setDefaultFactory(function () use ($loop) {
  return new Scheduler\EventLoopScheduler($loop); });   // Generator function, reads CSV file function users($file) {
  $users = fopen($file, 'r');
  while (!feof($users)) {
  yield fgetcsv($users)[0];
 }  fclose($users); }   // The RxPHP Observer $logger = new CallbackObserver(
  function ($user) {
  echo $user, PHP_EOL;
 },  function (\Throwable $t) {
  echo $t->getMessage(), PHP_EOL;
 },  function () {
  echo 'stream complete!', PHP_EOL;
 } );   // Dummy map callback function $mapper = function ($value) {
  return time() . ' | ' . $value; };   // Dummy filter callback function $filter = function ($value) {
  return strstr($value, 'Ma'); };   // Generator function $users = users(__DIR__ . '/users.csv');   // The RxPHP Observable - from generator Observable::fromIterator($users)
 ->map($mapper)
 ->filter($filter)
 ->subscribe($logger);   $loop->run();

```

我们首先创建了一个名为`users()`的简单生成器函数。 生成器的好处是它充当迭代器，这使得使用`fromIterator()`方法从中创建 RxPHP 可观察对象变得容易。 一旦我们有了可观察对象，我们可以将其方法链接在一起，例如`map()`和`filter()`。 通过这种方式，我们控制了流向我们订阅的观察者的数据流。

假设`users.csv`文件包含以下内容：

```php
"John"
"Mariya"
"Marc"
"Lucy"

```

前面代码的输出应该是这样的：

```php
1487439356 | Mariya
1487439356 | Marc
stream complete!

```

现在，假设我们想要将多个观察者附加到我们的`$users`流：

```php
$mailer = new CallbackObserver(
  function ($user) {
    echo 'Mailer: ', $user, PHP_EOL;
  },
  function (\Throwable $t) {
    echo 'Mailer: ', $t->getMessage(), PHP_EOL;
  },
  function () {
    echo 'Mailer stream complete!', PHP_EOL;
  }
);

$logger = new CallbackObserver(
  function ($user) {
    echo 'Logger: ', $user, PHP_EOL;
  },
  function (\Throwable $t) {
    echo 'Logger: ', $t->getMessage(), PHP_EOL;
  },
  function () {
    echo 'Logger stream complete!', PHP_EOL;
  }
);

$users = Observable::fromIterator(users(__DIR__ . '/users.csv'));

$users->subscribe($mailer);
$users->subscribe($logger);

```

这不会起作用。 代码不会抛出任何错误，但结果可能不是我们期望的：

```php
Mailer: John
Logger: Mariya
Mailer: Marc
Logger: Lucy
Mailer:
Logger:
Mailer stream complete!
Logger stream complete!

```

我们不能通过这种方式真正附加多个订阅者。第一个附加的观察者消耗了流，这就是为什么第二个观察者看到它是空的。这就是`Rx\Subject\Subject`组件可能会派上用场的地方。

# 主题

`Rx\Subject\Subject`是一个有趣的组件--它既充当可观察对象又充当观察者。这种好处在以下示例中得以体现：

```php
use \Rx\Subject\Subject;

$mailer  = new class() extends Subject {
  public function onCompleted()
 {  echo 'mailer.onCompleted', PHP_EOL;
  parent::onCompleted();
 }    public function onNext($val)
 {  echo 'mailer.onNext: ', $val, PHP_EOL;
  parent::onNext($val);
 }    public function onError(\Throwable $error)
 {  echo 'mailer.onError', $error->getMessage(), PHP_EOL;
  parent::onError($error);
 } };     $logger = new class() extends Subject {
  public function onCompleted()
 {  echo 'logger.onCompleted', PHP_EOL;
  parent::onCompleted();
 }    public function onNext($val)
 {  echo 'logger.onNext: ', $val, PHP_EOL;
  parent::onNext($val);
 }    public function onError(\Throwable $error)
 {  echo 'logger.onError', $error->getMessage(), PHP_EOL;
  parent::onError($error);
 } };   $users = Observable::fromIterator(users(__DIR__ . '/users.csv')); $mailer->subscribe($logger); $users->subscribe($mailer);

```

使用匿名类，我们能够即时扩展`Rx\Subject\Subject`类。底层的`onCompleted()`，`onError(Exception $error)`和`onNext($value)`方法是我们连接到观察者相关逻辑的地方。一旦执行，代码的输出如下：

```php
mailer.onNext: John
logger.onNext: John
mailer.onNext: Mariya
logger.onNext: Mariya
mailer.onNext: Marc
logger.onNext: Marc
mailer.onNext: Lucy
logger.onNext: Lucy
mailer.onNext:
logger.onNext:
mailer.onCompleted
logger.onCompleted

```

这里发生的是邮件程序首先进入流，然后流回到记录器流。这是因为`Rx\Subject\Subject`的双重性质才可能。重要的是要注意记录器不观察原始流。我们可以通过将过滤器添加到`$mailer`来轻松测试这一点：

```php
// ...

$mailer
 ->filter(function ($val) {
   return strstr($val, 'Marc') == false;
 })
 ->subscribe($logger);

$users->subscribe($mailer);

```

现在的输出将不包括记录器观察者上的用户名：

```php
mailer.onNext: John
logger.onNext: John
mailer.onNext: Mariya
logger.onNext: Mariya
mailer.onNext: Marc
mailer.onNext: Lucy
logger.onNext: Lucy
mailer.onNext:
logger.onNext:
mailer.onCompleted
logger.onCompleted

```

# 操作符

RxPHP 的可观察模型允许我们使用简单和可组合的操作来处理流。每个操作都是由一个单独的操作符完成的。操作符的组合是可能的，因为操作符本身在其操作的结果中大多返回可观察对象。快速查看`vendor\reactivex\rxphp\lib\Rx\Operator`目录，会发现 48 个不同的操作符实现，分为几个不同的类别

+   创建 o

+   转换可观察对象

+   过滤可观察对象

+   组合可观察对象

+   错误处理操作符

+   可观察对象实用程序操作符

+   条件和布尔操作符

+   数学和聚合操作符

+   可连接的可观察对象操作符

`map`，`filter`和`reduce`方法可能是最为人熟知和流行的操作符，所以让我们从它们开始我们的示例：

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   use \Rx\Observable; use \Rx\Observer\CallbackObserver; use \React\EventLoop\Factory; use \Rx\Scheduler;   $loop = Factory::create();   Scheduler::setDefaultFactory(function () use ($loop) {
  return new Scheduler\EventLoopScheduler($loop); });   // Generator function function xrange($start, $end, $step = 1) {
  for ($i = $start; $i <= $end; $i += $step) {
  yield $i;
 } }   // Observer $observer = new CallbackObserver(
  function ($item) {
  echo $item, PHP_EOL;
 } );   echo 'start', PHP_EOL; // Observable stream, made from iterator/generator Observable::fromIterator(xrange(1, 10, 1))
 ->map(function ($item) {
  return $item * 2;
 }) ->filter(function ($item) {
  return $item % 3 == 0;
 }) ->reduce(function ($x, $y) {
  return $x + $y;
 }) ->subscribe($observer);   echo 'end', PHP_EOL;   $loop->run();

```

我们首先编写了一个名为`xrange()`的简单生成器函数。生成器的美妙之处在于，无论我们选择的范围如何，`xrange()`函数始终占用相同的内存量。这为我们提供了一个很好的基础来使用 ReactiveX 操作符。然后，我们创建了一个简单的`$observer`，仅利用其`$onNext`可调用，而忽略了`$onError`和`$onCompleted`可调用，以便本节的目的。然后，我们从我们的`xrange()`函数创建了一个可观察流，传递了一个范围从 1 到 20。最后，我们到了将`map()`，`filter()`，`reduce()`和`subscribe()`方法调用连接到我们的可观察实例的地步。

如果我们现在执行这段代码，结果输出将是数字`36`。要理解这是从哪里来的，让我们退一步并注释掉`filter()`和`reduce()`方法：

```php
Observable::fromIterator(xrange(1, 10, 1))
 ->map(function ($item) {
   return $item * 2;
 })
// ->filter(function ($item) {
  // return $item % 3 == 0;
// })
// ->reduce(function ($x, $y) {
  // return $x + $y;
// })
 ->subscribe($observer);

```

现在的输出如下：

```php
start
2
4
6
8
10
12
14
16
18
20
end

```

`map()`函数通过将函数应用于每个项目来转换发出的项目。在这种情况下，该函数是`$item * 2`。现在，让我们继续恢复`filter()`函数，但将`reduce()`函数注释掉：

```php
Observable::fromIterator(xrange(1, 10, 1))
 ->map(function ($item) {
   return $item * 2;
 })
 ->filter(function ($item) {
   return $item % 3 == 0;
 })
// ->reduce(function ($x, $y) {
  // return $x + $y;
// })
 ->subscribe($observer);

```

现在知道`filter()`函数将接收`map()`函数输出流（`2`，`4`，`6`，... `20`），我们观察到以下输出：

```php
start
6
12
18
end

```

`filter()`函数通过仅发出通过谓词测试的项目来转换发出的项目。在这种情况下，谓词测试是`$item % 3 == 0`，这意味着它返回能被`3`整除的项目。

最后，如果我们恢复`reduce()`函数，结果将返回为`36`。与`map()`和`filter()`只接受单个发出的项目值不同，`reduce()`函数回调接受两个值。

对`reduce()`回调的快速更改澄清了发生了什么：

```php
 ->reduce(function ($x, $y) {
   $z = $x + $y;
   echo '$x: ', $x, PHP_EOL;
   echo '$y: ', $y, PHP_EOL;
   echo '$z: ', $z, PHP_EOL, PHP_EOL;
   return $z;
 })

```

这将产生以下输出：

```php
start
$x: 6
$y: 12
$z: 18

$x: 18
$y: 18
$z: 36

36
end

```

我们可以看到，`$x`作为第一个发出的项目的值，而`$y`作为第二个发出的项目的值。然后函数对它们进行求和计算，使得返回结果现在是第二次迭代中的第一个发出的项目，基本上是给出了`(6 + 12) => 18 => (18 + 18) => 36`。

考虑到 RxPHP 支持的大量操作符，我们可以想象通过简单地将多个操作符组合成链来解决现实生活中的复杂问题的优雅方式：

```php
$observable
 ->operator1(function () { /* ...*/ })
 ->operator2(function () { /* ...*/ })
 ->operator3(function () { /* ...*/ })
 // ...
 ->operatorN(function () { /* ...*/ })
 ->subscribe($observer);

```

如果现有的操作符不够用，我们可以通过扩展`Rx\Operator\OperatorInterface`来轻松编写自己的操作符。

# 编写自定义操作符

虽然 RxPHP 为我们提供了 40 多个操作符供我们使用，但有时可能需要使用不存在的操作符。考虑以下情况：

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   use \Rx\Observer\CallbackObserver; use \React\EventLoop\Factory; use \Rx\Scheduler;   $loop = Factory::create();   Scheduler::setDefaultFactory(function () use ($loop) {
  return new Scheduler\EventLoopScheduler($loop); });   // correct $users = serialize(['John', 'Mariya', 'Marc', 'Lucy']);   // faulty // $users = str_replace('i:', '', serialize(['John', 'Mariya', 'Marc', 'Lucy']));   $observer = new CallbackObserver(
  function ($value) {
  echo 'Observer.$onNext: ', print_r($value, true), PHP_EOL;
 },  function (\Throwable $t) {
  echo 'Observer.$onError: ', $t->getMessage(), PHP_EOL;
 },  function () {
  echo 'Observer.$onCompleted', PHP_EOL;
 } );   Rx\Observable::just($users)
 ->map(function ($value) {
  return unserialize($value);
 }) ->subscribe($observer);   $loop->run();

```

使用*正确的*`$users`变量执行此代码会得到以下预期输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/adcac991-4be4-46cb-a8f4-d86272baeac5.png)

然而，如果我们去掉*有问题的*`$user`变量前面的注释，输出结果会稍微出乎意料，或者至少不是我们希望处理的方式：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/de247ab0-2353-4b00-bf0e-705febf72d38.png)

我们真正想要的是将反序列化逻辑转移到 RxPHP 操作符中，并优雅地处理失败的`unserialize()`尝试。幸运的是，编写自定义操作符是一项简单的任务。快速查看`vendor/reactivex/rxphp/src/Operator/OperatorInterface.php`文件，可以看到以下接口：

```php
<?php   declare(strict_types=1);   namespace Rx\Operator;   use Rx\DisposableInterface; use Rx\ObservableInterface; use Rx\ObserverInterface;   interface OperatorInterface {
  public function __invoke(
 ObservableInterface $observable,
 ObserverInterface $observer
  ): DisposableInterface; } 

```

接口非常简单，只需要实现一个`__invoke()`方法。我们在第四章中详细介绍了`__invoke()`方法，*魔术方法背后的魔术*。当我们尝试将对象作为函数调用时，将调用此方法。在这种情况下，`OperatorInterface`列出了`__invoke()`方法的三个参数，其中两个是必需的。

+   `$observable`：这将是我们的输入可观察对象，我们将订阅它

+   `$observer`：这是我们将发出输出值的地方

考虑到这一点，以下是我们自定义`UnserializeOperator`的实现：

```php
<?php   use \Rx\DisposableInterface; use \Rx\ObservableInterface; use \Rx\ObserverInterface; use \Rx\SchedulerInterface; use \Rx\Observer\CallbackObserver; use \Rx\Operator\OperatorInterface;   class UnserializeOperator implements OperatorInterface {
  /**
 * @param \Rx\ObservableInterface $observable
 * @param \Rx\ObserverInterface $observer
 * @param \Rx\SchedulerInterface $scheduler  * @return \Rx\DisposableInterface
 */  public function __invoke(
 ObservableInterface $observable,
 ObserverInterface $observer,
 SchedulerInterface $scheduler  = null
  ): DisposableInterface
 {  $callbackObserver = new CallbackObserver(
  function ($value) use ($observer) {
  if ($unsValue = unserialize($value)) {
  $observer->onNext($unsValue);
 } else {
  $observer->onError(
  new InvalidArgumentException('Faulty serialized string.')
 ); } },  function ($error) use ($observer) {
  $observer->onError($error);
 },  function () use ($observer) {
  $observer->onCompleted();
 } );    // ->subscribe(...) => DisposableInterface
  return $observable->subscribe($callbackObserver, $scheduler);
 } }

```

不幸的是，我们无法像链式调用 RxPHP 操作符那样直接链式调用我们的操作符。我们需要使用`lift()`操作符来帮助自己：

```php
Rx\Observable::just($users)
 ->lift(function () {
  return new UnserializeOperator();
 })
 ->subscribe($observer);

```

有了`UnserializeOperator`，有问题的序列化`$users`字符串现在会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/540a7acd-603e-456b-bd8b-8d5eb4af2f0c.png)

我们的操作符现在成功地处理错误，即将它们委托给观察者的`onError`回调。

充分利用 RxPHP 主要是了解其操作符的各个方面。`vendor/reactivex/rxphp/demo/`目录提供了许多操作符使用示例。值得花一些时间逐个查看。

# 非阻塞 IO

使用 RxPHP 扩展开启了许多可能性。它的可观察对象、操作符和订阅者/观察者实现确实很强大。然而，它们没有提供异步性。这就是 React 库发挥作用的地方，它提供了一个基于事件驱动的、非阻塞的 I/O 抽象层。在我们讨论 React 之前，让我们先举一个 PHP 中阻塞与非阻塞 I/O 的简单例子。

我们创建一个小的*信标*脚本，它只会随着时间生成一些**标准输出**（**stdout**）。然后，我们将创建一个从**标准输入**（**stdin**）读取的脚本，并查看在读取时以流阻塞和流非阻塞模式下的行为。

我们首先创建`beacon.php`文件，内容如下：

```php
<?php

$now = time();

while ($now + $argv[1] > time()) {
  echo 'signal ', microtime(), PHP_EOL;
  usleep(200000); // 0.2s
}

```

使用`$argv[1]`表明该文件是用于从控制台运行。使用`$argv[1]`，我们提供希望脚本运行的秒数。在循环内，我们有一个信号...输出，然后是短暂的`0.2`秒脚本休眠。

我们的信标脚本已经就位，让我们继续创建`index.php`文件，内容如下：

```php
<?php

// stream_set_blocking(STDIN, 0);
// stream_set_blocking(STDIN, 1); // default

echo 'start', PHP_EOL;

while (($line = fgets(STDIN)) !== false) {
  echo $line;
}

echo 'end', PHP_EOL;

```

除了两个明显的开始/结束输出外，我们利用`fgets()`函数从标准输入中读取。`stream_set_blocking()`方法故意被暂时注释掉。请注意，这两个脚本完全不相关。`index.php`从未引用`beacon.php`文件。这是因为我们将使用控制台及其管道（`|`）来将`beacon.php`脚本的 stdout 桥接到`index.php`消耗的 stdin。

```php
php beacon.php 2 | php index.php

```

结果输出如下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/24b412d5-df8a-41c2-ae3f-f34d9cb535ad.png)

这个输出没有问题；这是我们预期的。我们首先看到开始字符串出现，然后出现几次 signal...，最后是结束字符串。然而，问题在于，`fgets()`函数从 stdout 中拉取的所有 signal...位都是阻塞 I/O 的一个例子。虽然在这个小例子中我们可能不会察觉到，但我们很容易想象一个 beacon 脚本从一个非常大的文件或一个慢的数据库连接中发送输出。我们的`index.php`脚本将在那段时间内被简单地挂起执行，或者更好地说，它将等待`while (($line = fgets(STDIN)...`行解决。

我们如何解决这个问题？首先，我们需要明白这实际上并不是一个技术问题。等待接收数据并没有什么问题。无论我们如何抽象事物，总会有某个人或某些东西需要在某个地方等待数据。诀窍在于将这个地方放在正确的位置，这样它就不会妨碍用户体验。JavaScript 的 promise 和回调就是我们可能想要放置这个地方的一个例子。让我们来看一下 JavaScript jQuery 库所做的简单 AJAX 调用：

```php
console.log('start-time: ' + Date.now());

$.ajax({
  url: 'http://foggyline.net/',
  success: function (result) {
    console.log('result-time: ' + Date.now())
    console.log(result)
  }
});

console.log('end-time: ' + Date.now());

```

以下截图显示了结果输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/dec130cd-c357-416b-a618-5395b5c1c72d.png)

注意`start-time`和`end-time`在`result-time`之前被输出。JavaScript 没有像 PHP 在前面的例子中的`while (($line = fgets(STDIN)...`行那样在`$.ajax({...`行阻塞执行。这是因为 JavaScript 运行时与 PHP 根本不同。JavaScript 的异步性质依赖于代码块的分离和单独执行，然后通过回调机制更新所需的内容，这是由 JavaScript 事件循环并发模型和消息队列机制实现的功能。这种情况下的回调是分配给`ajax()`方法调用的`success`属性的匿名函数。一旦 AJAX 调用成功执行，它调用了分配的`success`函数，这反过来导致了 AJAX 调用需要时间来执行的输出。

现在，让我们回到我们的小 PHP 例子，通过删除我们放在`stream_set_blocking(STDIN, 0);`表达式前面的注释来修改`index.php`文件。再次运行命令，这次使用管道（`|`），结果输出如下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/4c4e8bb4-7afb-408d-b467-b8ea55b2acc4.png)

这一次，`while (($line = fgets(STDIN)...`行没有通过等待`beacon.php`完成来阻塞执行。诀窍在于`stream_set_blocking()`函数，因为它使我们能够控制流的阻塞模式，默认情况下设置为阻塞 I/O。让我们继续制作一个更像 PHP 的例子，这次不使用控制台管道。我们将保留`beacon.php`文件不变，但修改`index.php`文件如下：

```php
<?php

echo 'start', PHP_EOL;

$process = proc_open('php beacon.php 2', [
  ['pipe', 'r'], // STDIN
  ['pipe', 'w'], // STDOUT
  ['file', './signals.log', 'a'] //STDERR
], $pipes);

//stream_set_blocking($pipes[1], 1); // Blocking I/O
//stream_set_blocking($pipes[1], 0); // Non-blocking I/O

while (proc_get_status($process)['running']) {
  usleep(100000); // 0.1s
  if ($signal = fgets($pipes[1])) {
    echo $signal;
  } else {
    echo '--- beacon lost ---', PHP_EOL;
  }
}

fclose($pipes[1]);
proc_close($process);

echo 'end', PHP_EOL;

```

我们从`proc_open()`函数开始，它允许我们执行一个命令并为标准输入、输出和错误打开文件指针。`'php beacon.php 2'`参数基本上做了我们控制台命令的事情，关于管道字符左边的部分。我们捕获信标脚本的输出方式是使用`fgets()`函数。然而，我们不是直接这样做的，我们是通过这里的 while 循环来做的，条件是进程`running`状态。换句话说，只要进程在运行，就检查是否有新的输出来自新创建的进程。如果有输出，显示它；如果没有，显示`---信标丢失---`消息。以下截图显示了默认（阻塞）I/O 的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/4a9d00b2-7ccb-4731-b79f-7ed3a6eb0252.png)

如果我们现在取消注释`stream_set_blocking($pipes[1], 0);`前面的注释，生成的输出将变成这样：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/502a795f-e386-41f8-b9d8-4862cd4f2a27.png)

这里的输出显示了信标和我们运行的脚本之间的非阻塞关系。解除流的阻塞，我们能够利用`fgets()`函数，这通常会阻塞脚本以定期检查标准输入，只要进程正在运行。简而言之，我们现在能够从子进程读取输出，同时能够初始化更多的子进程。尽管这个例子本身离 jQuery promise/callback 例子的便利还有很长的路要走，但这是我们写代码时阻塞和非阻塞 I/O 背后复杂性的第一步。这就是我们将会欣赏 RxPHP 可观察对象和 React 事件循环的作用的地方。

# 使用 React

React 是一个库，它使得在 PHP 中进行事件驱动编程成为可能，就像 JavaScript 一样。基于反应器模式，它本质上充当一个事件循环，允许使用其组件的各种第三方库编写异步代码。

[`en.wikipedia.org/wiki/Reactor_pattern`](https://en.wikipedia.org/wiki/Reactor_pattern)页面上说，*反应器设计模式是一种处理服务请求的事件处理模式，由一个或多个输入并发地传递给服务处理程序*。

该库可在[`github.com/reactphp/react`](https://github.com/reactphp/react)找到

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/f69decec-31c7-445e-920e-3c45c3e22e7f.png)

# 安装 React

React 库可作为 Composer `react/react`包获得。假设我们仍然在我们安装 RxPHP 的项目目录中，我们可以简单地执行以下命令来将 React 添加到我们的项目中：

```php
composer require react/react

```

这应该给我们一个类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/58f88a2d-ef96-4ca2-b052-662c17135a41.png)

我们可以看到一些有趣的`react/*`包被引入，`react/event-loop`是其中之一。建议我们安装更高性能的循环实现的消息绝对值得关注，尽管超出了本书的范围。

# React 事件循环

没有建议的任何事件循环扩展，React 事件循环默认为`React\EventLoop\StreamSelectLoop`类，这是基于`stream_select()`函数的事件循环。

[`php.net/manual/en/function.stream-select.php`](http://php.net/manual/en/function.stream-select.php)页面上说，*stream_select()函数接受流数组并等待它们改变状态*

正如我们在之前的例子中看到的，使用 React 创建事件循环是简单的

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   use \React\EventLoop\Factory; use \Rx\Scheduler;   $loop = Factory::create();   Scheduler::setDefaultFactory(function () use ($loop) {
  return new Scheduler\EventLoopScheduler($loop); });   // Within the loop   $loop->run();

```

我们使用了`Factory::create()`静态函数，实现如下：

```php
class Factory
{
  public static function create()
  {
    if (function_exists('event_base_new')) {
      return new LibEventLoop();
    } elseif (class_exists('libev\EventLoop', false)) {
      return new LibEvLoop;
    } elseif (class_exists('EventBase', false)) {
      return new ExtEventLoop;
    }
    return new StreamSelectLoop();
  }
}

```

在这里，我们可以看到，除非我们安装了`ext-libevent`、`ext-event`或`ext-libev`，否则将使用`StreamSelectLoop`实现。

循环的每次迭代都是一个滴答。事件循环跟踪计时器和流。如果没有这两者中的任何一个，就没有滴答声，循环就简单地

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   use \React\EventLoop\Factory; use \Rx\Scheduler;   echo 'STEP#1 ', time(), PHP_EOL;   $loop = Factory::create();   Scheduler::setDefaultFactory(function () use ($loop) {
  return new Scheduler\EventLoopScheduler($loop); });    echo 'STEP#2 ', time(), PHP_EOL;   $loop->run();   echo 'STEP#3 ', time(), PHP_EOL;

```

前面的代码给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/0c81eb9e-fdaf-4494-98d2-08934a6ff4a9.png)

一旦我们添加了一些计时器，情况就会发生变化

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   use \React\EventLoop\Factory; use \Rx\Scheduler;   echo 'STEP#1 ', time(), PHP_EOL;   $loop = Factory::create();   Scheduler::setDefaultFactory(function () use ($loop) {
  return new Scheduler\EventLoopScheduler($loop); });   echo 'STEP#2 ', PHP_EOL;   $loop->addTimer(2, function () {
  echo 'timer#1 ', time(), PHP_EOL; });   echo 'STEP#3 ', time(), PHP_EOL;   $loop->addTimer(5, function () {
  echo 'timer#2 ', time(), PHP_EOL; });   echo 'STEP#4 ', time(), PHP_EOL;   $loop->addTimer(3, function () {
  echo 'timer#3 ', time(), PHP_EOL; });   echo 'STEP#5 ', time(), PHP_EOL; $loop->run();   echo 'STEP#6 ', time(), PHP_EOL;

```

前面的代码给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/48487a6d-646b-4b0a-ac55-4e0520019a7c.png)

注意计时器输出的顺序和每个计时器旁边的时间。我们的循环仍然成功结束了，因为我们的计时器到期了。为了使循环持续运行，我们可以添加一个*周期计时器*。

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   use \React\EventLoop\Factory; use \Rx\Scheduler;   echo 'STEP#1 ', time(), PHP_EOL;   $loop = Factory::create();   Scheduler::setDefaultFactory(function () use ($loop) {
  return new Scheduler\EventLoopScheduler($loop); });   echo 'STEP#2 ', PHP_EOL;   $loop->addPeriodicTimer(1, function () {
  echo 'timer ', time(), PHP_EOL; });   echo 'STEP#3 ', time(), PHP_EOL;   $loop->run();   echo 'STEP#4 ', time(), PHP_EOL;

```

前面的代码给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/bee357c9-0bb1-42c3-b5bd-146eb5cb191b.png)

这个循环现在将继续产生相同的计时器...输出，直到我们在控制台上按下*Ctrl* + *C*。我们可能会想，这与 PHP 的`while`循环有什么不同？一般来说，`while`循环是轮询类型的，因为它不断地检查事物，几乎没有机会让处理器切换任务。事件循环使用更有效的中断驱动 I/O，而不是轮询。然而，默认的`StreamSelectLoop`使用`while`循环来实现其事件循环。

计时器和流的添加使其变得有用，因为它将难点抽象化了。

# 可观察对象和事件循环

让我们继续看看如何使我们的可观察对象与事件循环一起工作：

```php
<?php   require_once __DIR__ . '/vendor/autoload.php';   use \React\EventLoop\Factory; use \Rx\Scheduler; use \Rx\Observable; use  \Rx\Subject\Subject; use \Rx\Scheduler\EventLoopScheduler;   $loop = Factory::create();   Scheduler::setDefaultFactory(function () use ($loop) {
  return new Scheduler\EventLoopScheduler($loop); });   $stdin = fopen('php://stdin', 'r');   stream_set_blocking($stdin, 0);   $observer = new class() extends Subject  {
  public function onCompleted()
 {  echo '$observer.onCompleted: ', PHP_EOL;
  parent::onCompleted();
 }    public function onNext($val)
 {  echo '$observer.onNext: ', $val, PHP_EOL;
  parent::onNext($val);
 }    public function onError(\Throwable $error)
 {  echo '$observer.onError: ', $error->getMessage(), PHP_EOL;
  parent::onError($error);
 } };   $loop = Factory::create();   $scheduler = new EventLoopScheduler($loop);   $disposable = Observable::interval(500, $scheduler)
 ->map(function () use ($stdin) {
  return trim(fread($stdin, 1024));
 }) ->filter(function ($str) {
  return strlen($str) > 0;
 }) ->subscribe($observer);   $observer->filter(function ($value) {
  return $value == 'quit'; })->subscribeCallback(function ($value) use ($disposable) {
  echo 'disposed!', PHP_EOL;
  $disposable->dispose(); });   $loop->run(); 

```

这里有很多事情要做。我们首先创建了一个标准输入，然后将其标记为非阻塞。然后我们创建了`Subject`类型的观察者。这是因为，正如我们将在后面看到的，我们希望我们的观察者表现得像观察者和可观察者。然后我们实例化了循环，并传递给`EventLoopScheduler`。为了使可观察对象与循环一起工作，我们需要用调度程序包装它们。然后我们使用`IntervalObservable`的实例，使其`map()`操作符读取标准输入，而`filter()`操作符被设置为过滤掉任何空输入（在控制台上按 Enter 键而没有文本）。我们将这个可观察对象存储到`$disposable`变量中。最后，由于我们的`$observer`是`Subject`的一个实例，我们能够将`filter()`操作符附加到它以及`subscribeCallback()`。我们在这里指示`filter()`操作符只过滤出带有退出字符串的输入。一旦在控制台上输入`quit`，然后按*Enter*键，`subscribeCallback()`就会被执行。在`subscribeCallback()`中，我们有一个`$disposable->dispose()`表达式。调用可处置的 dispose 方法会自动取消`$observer`对`$observable`的订阅。鉴于循环中没有其他计时器或流，这会自动终止循环。

以下截图显示了前面代码的控制台输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-php7/img/39aa8f7d-4f9a-4c4c-920f-9f8a202dc1c9.png)

当代码运行时，我们首先看到`start`字符串，然后我们输入`John`并按下，然后我们说$observer.onNext...，一直重复，直到我们输入`quit`。

React 事件循环为我们打开了一个有趣的可能性，就像我们在 JavaScript 和浏览器中习惯看到的那样。虽然关于 React 还有很多要说的，但这应该足以让我们开始使用 RxPHP 和 React 的组合。

# 总结

在本章中，我们涉及了 RxPHP 和 React，这两个库承诺将响应式编程带到 PHP 中。虽然 RxPHP 提供了强大的可组合语法包装的可观察对象，React 则通过事件循环实现丰富了我们的体验。需要谨慎的是，这对于 PHP 来说仍然是一个相对实验性的领域，远未准备好用于主流生产。然而，它确实表明了 PHP 在运行时能力上并不受限，并在响应式领域显示出了潜力。

接下来，我们将把重点转移到现代 PHP 应用程序中常见的设计模式。
