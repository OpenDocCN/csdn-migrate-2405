# PHP 数据对象学习手册（三）

> 原文：[`zh.annas-archive.org/md5/33ff31751d56930c46ef1daf9ca0ebcb`](https://zh.annas-archive.org/md5/33ff31751d56930c46ef1daf9ca0ebcb)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 附录 A. PHP5 中面向对象编程的介绍

在本书中，我们主要使用过程化代码来构建示例应用程序。然而，PDO API 是完全面向对象的，在最后一章中，我们通过使用类来模拟数据库中的真实实体。这个附录是为那些不熟悉 PHP5 面向对象扩展的程序员准备的。我们将向您介绍面向对象编程的基础知识，因为许多来自较早 PHP 版本的开发人员没有这种编程经验。然而，这只是一个简短的介绍；如果您想掌握面向对象编程，您应该参考一些专门讨论这个主题的书籍。

# 什么是面向对象编程？

面向对象编程（OOP）是一个相对较新的概念，尽管其根源可以追溯到 20 世纪 60 年代。在 OOP 中，软件与模拟真实实体的对象一起工作（例如第七章中的书籍和作者）。而过程式编程涉及一系列指令，OOP 中的应用涉及一组相互交互的对象。

## 声明对象的语法

一个对象可以被视为多个变量的容器，称为属性，以及对这些变量进行操作的函数。这些函数称为方法。每个对象都属于一个类。在 PHP 中，每个对象只能属于一个类（尽管一些其他面向对象编程语言允许多重继承），但可以有许多对象或实例属于同一个类。类是一种语法结构，允许您描述属于这个类的对象将具有什么属性和方法。

有一个类似物种和生物体的类比——例如，狗（一种物种，或者一个类）是所有活着的狗的概括。一个概括的狗有诸如体重和年龄的属性，以及像叫的方法，而现实生活中的狗，比如莱西，属于狗这个物种，可以被描述为`Dog`类的一个实例。

让我们看看在 PHP5 中如何建模这个：

```php
class Dog
{
public $weight;
public $age;
function bark()
{
print "woof!";
}
}
$lessie = new Dog();
$lessie->weight = 15;
$lessie->age = 3;
$lessie->bark();

```

在这段小代码片段中，我们定义了一个叫做`Dog`的类。在 PHP5 中，类的定义以保留字`class`开头，后面跟着类的名称（类的名称可以包含与函数名称相同的字符）。所有的类的属性和方法，统称为**成员**，都定义在`{...}`块内。

正如你所看到的，当我们声明属性和方法时，我们使用关键字`public`。在 PHP4 中，我们将使用`var`关键字，但是这个关键字在 PHP5 中已经被弃用。除了`public`关键字，我们还可以使用`protected`关键字或`private`关键字，但稍后会详细介绍。

正如你在代码的第二部分中所看到的，我们使用`new`关键字创建对象。

```php
$lessie = new Dog();

```

这一行创建了一个属于`Dog`类的新对象，并将其分配给`$lessie`变量。这是一个非常重要的步骤，因为这是创建对象的唯一方法。在 PHP 处理完它之后，`$lessie`变量变得初始化，我们可以访问`Dog`类中声明的属性和方法，以便对名为`Lessie`的对象进行操作。我们现在想在我们的应用程序中有两只狗，第二只将被称为`K9`。为了实现这一点，我们需要写类似这样的代码：

```php
$k9 = new Dog();
$k9->age = 5;
$k9->weight = 18;

```

现在，我们可以访问`$k9`和`$lessie`变量，如果我们想要与我们的每只狗进行交互。

换句话说，在我们可以与一个实例通信之前，它必须首先用`new`关键字创建。

变量初始化后，我们可以访问它的属性和方法。正如你在代码中看到的那样，这是通过`->`构造实现的，该构造用于属性和方法。请注意，当访问类的属性时，我们不必在`->`后面写美元符号（但在类定义内声明属性时必须使用）。

方法是用`function`关键字声明的，后面跟着方法的名称和参数列表。事实上，类的方法的声明方式与普通函数的声明方式类似，但有一个主要区别。在方法的声明中，总是存在一个隐式变量，称为`$this`，它允许你访问对象的属性。让我们看看如何创建一个`getInfo()`方法来返回有关我们的狗的一些额外信息：

```php
<?php
class Dog
{
public $weight;
public $age;
function bark()
{
print "woof!";
}
**function getInfo()
{
return 'Weight: ' . $this->weight . ' kg, age: ' . $this->age .
' years';
}**
}
$lessie = new Dog();
$lessie->weight = 15;
$lessie->age = 3;
$k9 = new Dog();
$k9->age = 5;
$k9->weight = 18;
echo 'Lessie: ', $lessie->getInfo(), "\n";
echo 'K9: ', $k9->getInfo(), "\n";

```

这段代码将显示以下输出：

```php
Lessie: Weight: 15 kg, age: 3 years
K9: Weight: 18 kg, age: 5 years

```

## 构造函数

每个类还有一个特殊的函数（可能是隐式的或显式声明的），称为**构造函数**。构造函数总是在 PHP 遇到`new`关键字时调用，它的目的是执行一些初始化任务。让我们扩展`Dog`类，使其具有`$name`属性。我们还将更改代码，以便在构造函数中初始化`name, weight`和`age`属性，而不是在主应用程序中：

```php
<?php
class Dog
{
public $weight;
public $age;
**public $name;
function __construct($name, $age, $weight)
{
$this->name = $name;
$this->weight = $weight;
$this->age = $age;
}**
function bark()
{
print "woof!";
}
**function getInfo()
{
return
'Name: ' . $this->name .
', weight: ' . $this->weight .
' kg, age: ' . $this->age .
' years';
}
}
$lessie = new Dog('Lessie', 3, 15);
$k9 = new Dog('K9', 5, 18);
echo $lessie->getInfo(), "\n";
echo $k9->getInfo(), "\n";**

```

这个应用程序将显示以下内容：

```php
Name: Lessie, weight: 15 kg, age: 3 years
Name: K9, weight: 18 kg, age: 5 years

```

这是我们所做的简要总结。我们首先声明了`$name`属性，然后是我们`Dog`类的构造函数。构造函数被声明为一个特殊名称为`__construct`的函数（`constructor`一词前面加上两个下划线('_')）。我们的构造函数接受三个参数——`name`、`age`和`weight`，它们的值被分配给对象的属性。我们分配值给属性的顺序并不重要。请注意，我们必须始终使用`$this`变量来表示对象的属性。通过这样做，我们可以区分构造函数中的局部变量`$name, $age`和`$weight`（作为参数传递）和对象自己的属性，它们在构造函数中具有相同的名称。

我们还改变了`getInfo()`方法，使其也返回狗的名字。现在我们可以通过将名字、年龄和体重传递给构造函数来实例化对象。由于这些属性在构造函数中被赋值，我们不必在代码的主要部分中这样做。

还应该注意的是，你可以在类定义中为属性分配默认值。这将确保该类的每个对象都自动分配默认值。例如，我们可以这样做：

```php
class Dog
{
public $weight;
public $age;
public $name;
public $hasCollar = true;
function __construct($name, $age, $weight)
{
$this->name = $name;
$this->weight = $weight;
$this->age = $age;
}
function bark()
{
print "woof!";
}
**function getInfo()
{
return
'Name: ' . $this->name .
', weight: ' . $this->weight .
' kg, age: ' . $this->age .
' years, has collar: ' . ($this->hasCollar ? 'yes' : 'no');
}**
}

```

如果你使用这个`Dog`类定义运行应用程序，你将看到以下输出：

```php
Name: Lessie, weight: 15 kg, age: 3 years, has collar: yes
Name: K9, weight: 18 kg, age: 5 years, has collar: yes

```

正如你现在所看到的，`hasCollar`的默认属性值已传播到每个新创建的实例（当然，它可以稍后为每个对象更改）。

## 析构函数

有一个与构造函数相对的概念，叫做析构函数。顾名思义，析构函数用于执行清理任务（这些任务的经典示例是删除临时文件，关闭数据库连接等）。在 PHP5 中，当对象没有更多的引用时（例如，通过将持有对象引用的变量设置为**null**或应用程序终止），对象上的析构函数将被调用。

析构函数是一个方法：`__destruct()`。如果你把这个方法添加到类中，那么当对象被释放时它将被调用。让我们把析构函数添加到**Dog**类中：

```php
class Dog {
public $weight;
public $age;
public $name;
public $hasCollar = true;
function __construct($name, $age, $weight) {
$this->name = $name;
$this->weight = $weight;
$this->age = $age;
}
function bark() {
print "woof!";
}
function getInfo() {
return
'Name: ' . $this->name .
', weight: ' . $this->weight .
' kg, age: ' . $this->age .
' years, has collar: ’ . ($this->hasCollar ? 'yes’ : 'no’);
}
function __destruct() {
print "Freeing $this->name\n";
}
}

```

现在，如果你再次运行代码，它将给出以下输出：

```php
Name: Lessie, weight: 15 kg, age: 3 years, has collar: yes
Name: K9, weight: 18 kg, age: 5 years, has collar: yes
Freeing K9
Freeing Lessie

```

请注意，PHP5 调用析构函数的顺序是不确定的。此外，在析构函数中，代码可能无法访问其他对象，除非它们被释放的对象引用。换句话说，析构函数只应清理由该对象创建的资源。

# 面向对象编程的优势

面向对象编程的力量在于它的三个主要特征：继承、封装和多态。

## 继承

面向对象编程中的继承允许你创建新的类，这些类继承了现有类的行为（方法）和属性（属性）。让我们考虑下面的例子。假设我们有一个名为`Fruit`的类。它是不同水果的通用类型类，它的共同属性是颜色和重量。在面向对象编程中，我们可以对`Fruit`进行子类化，创建新的类`Apple`和`Banana`。这两个类（作为`Fruit`的子类）将具有相同的属性：`weight`和`color`。（请注意，我们谈论的是属性本身，而不是它们的值）。一个苹果可以是绿色的，而一个`Banana`可以是黄色的。但是，与`Apple`或`Banana`类实例交互的任何代码都不需要知道它正在与哪种水果进行通信。

让我们把这个例子写成代码：

```php
class Fruit
{
public $color;
public $weight;
}
class Apple extends Fruit
{
function __construct()
{
$this->color = 'green';
$this->weight = 200;
}
}
class Banana extends Fruit
{
function __construct()
{
$this->color = 'yellow';
$this->weight = 250;
}
}
$a[] = new Apple();
$a[] = new Banana();
foreach($a as $f)
{
echo $f->color, "\t", $f->weight, "\n";
}

```

正如你所看到的，在这个小应用程序中，我们有一个`Apple`对象和一个`Banana`对象。我们在循环中对它们进行迭代，但是无论它们的类型如何，我们都可以访问它们的属性，因为这两个类使用相同的属性名称。但是这些属性对于每种水果来说都有不同的值。

继承还允许扩展或完全重写父类的行为。假设我们的`Fruit`类有一个额外的特征——每公斤的价格。它还有一个新的方法——`getPrice()`，它只是将重量（以克为单位）乘以价格：

```php
class Fruit
{
public $color;
public $weight;
public $price;
function getPrice()
{
return $this->weight / 1000 * $this->price;
}
}

```

现在我们可以在子类中使用这种方法：

```php
class Apple extends Fruit
{
function __construct()
{
$this->color = 'green';
$this->weight = 200;
$this->price = 2;
}
}
class Banana extends Fruit
{
function __construct()
{
$this->color = 'yellow';
$this->weight = 250;
$this->price = 3;
}
}
$a[] = new Apple();
$a[] = new Banana();
foreach($a as $f)
{
echo $f->getPrice(), "\n";
}

```

接下来，我们假设`Banana`类有另一个方法来计算价格，以便应用折扣：

```php
class Banana extends Fruit
{
function __construct()
{
$this->color = 'yellow';
$this->weight = 250;
$this->price = 3;
}
function getPrice()
{
return $this->weight / 1000 * $this->price * 0.9;
}
}

```

正如你所看到的，我们改变了`Banana`类中的方法，以便调用`Banana`类的`getPrice()`方法的代码将获得折扣价格，而`Apple`类的`getPrice()`方法返回全价。

另一方面，我们可以在`Banana`类中重用`Fruit`类的`getPrice()`方法的实现（这样我们就不必在基类中重复包含的代码）：

```php
function getPrice()
{
return parent::getPrice() * 0.9;
}

```

## 封装

封装（有时称为信息隐藏）是一个更为理论的概念。它涉及以一种方式在类中定义方法，以便我们可以隐藏实现细节，使客户端代码无法访问。当我们在`Banana`类中重新定义价格计算时，我们已经看到了这一点。从应用程序的角度来看，什么都没有改变：我们仍然调用`getPrice()`方法，但我们不知道这个计算是如何进行的。

换句话说，类是通过它们的方法访问的，这些方法具有相同的名称，因此，即使这些名称背后的代码发生了变化，名称本身也不会改变。这确保了现有的代码不需要更改以适应方法的新版本。

我们可以做更多的工作来隐藏客户端代码的实现细节，PHP5 和其他面向对象的语言一样，支持方法和属性的**可见性修饰符**。例如，我们可以在`Banana`类中添加一个私有属性，它将对应用程序的其余部分隐藏起来：

```php
class Banana extends Fruit
{
**private $mySecretProperty;**
function __construct()
{
$this->color = 'yellow';
$this->weight = 250;
$this->price = 3;
}
function getPrice()
{
return parent::getPrice() * 0.9;
}
}

```

`$mySecretProperty`属性只能在`Banana`类中访问（或可见）；试图从`Banana`类的方法之外访问它将触发运行时错误。（在编译语言中，这将导致编译错误。）

在 PHP5 中，还存在两个修饰符：**public**（我们已经使用过）和**protected**。公共方法或属性可以从整个应用程序中访问，而受保护的方法或属性只能在类及其子类中访问。

## 多态性

多态性是面向对象编程的一个特性，它允许我们编写能够处理属于不同类的对象的代码，只要这些类有相同的基类。我们在上面的例子中已经看到了多态性的作用，当我们使用它们的名称访问不同对象的属性和方法时，返回不同的值并执行不同的操作。

子类实现了基类的所有属性和方法，并且基类的所有未来子类都保证实现这些属性和方法，以便现有代码甚至可以与尚不存在的子类一起工作。

PHP5 支持接口。接口是一种描述不同类和类层次结构中某些行为的构造。例如，让我们考虑一个`Tradeable`接口，其中有一个方法`isImported()`：

```php
interface Tradeable
{
public isImported();
}

```

现在，我们可以在`Fruit`类的定义中声明它实现了 Tradeable 接口：

```php
class Fruit **implements Tradeable**
{
public $color;
public $weight;
public $price;
function getPrice()
{
return $this->weight / 1000 * $this->price;
}
function isImported()
{
return false;
}
}

```

我们已经创建了`Fruit`对象及其子类（`Apple`和`Banans`）的所有对象默认为非进口。现在我们可以将香蕉设为进口，同时将苹果保留为国产：

```php
class Banana extends Fruit
{
function __construct()
{
$this->color = 'yellow';
$this->weight = 250;
$this->price = 3;
}
function getPrice()
{
return parent::getPrice() * 0.9;
}
function isImported()
{
return true;
}
}

```

接下来，我们将创建一个虚构的`Car`类，实现`Tradeable`接口：

```php
class Car implements Tradeable
{
public $year;
public $make;
public $model;
function isImported()
{
return true;
}
}

```

请注意，`Car`没有扩展`Fruit`，但它仍然具有`isImported()`方法。现在我们可以从应用程序中调用这个方法：

```php
$a[] = new Apple();
$a[] = new Banana();
$a[] = new Car();
foreach($a as $item)
{
echo $item->isImported();
}

```

这个小例子展示了如何通过给它们一个共同的接口，以相同的方式处理来自不同类层次结构的对象。通过这样做，通常具有完全不同含义的对象可以以多态的方式进行操作。

# 静态属性、方法和类常量

在本附录中的所有示例中，我们都在使用模拟现实生活实体的类的实例（对象）。但是，在 PHP5 中，可以使用**静态**属性和方法。静态属性是对给定类的所有实例都通用的变量，因此，如果更改静态属性，它将对属于该类的所有对象进行更改。

静态属性的声明方式与常规属性相同，但有一个特殊的**static**关键字：

```php
class DataModel
{
**public static $conn = null;**
}

```

可以在不创建类的实例的情况下访问静态属性：

```php
if(!DataModel::$conn) {
echo 'Connection not established!';
}

```

访问静态属性的语法如下：类名，然后是双冒号，然后是属性名。请注意，对于静态属性（与常规属性不同），必须存在美元符号`$`。

静态方法和静态属性一样，可以在不实例化对象的情况下访问。它们的声明和访问方式如下：

```php
class DataModel
{
public static $conn = null;
**static function getConn()**
{
if(!DataModel::$conn) {
DataModel::$conn = new PDO('sqlite:./my.db', 'user', 'pass');
}
return DataModel::$conn;
}
}
**$conn = DataModel::getConn();**

```

静态方法的声明具有`static`关键字，后面跟着常规方法声明。可以通过类名后跟双冒号，然后是方法名来访问该方法。

可以在类声明内部使用快捷关键字`self`访问静态属性和方法：

```php
class DataModel
{
public static $conn = null;
static function getConn()
{
**if(!self::$conn) {
self::$conn = new PDO('sqlite:./my.db', 'user', 'pass');**
}
**return self::$conn;**
}
}
**$conn = DataModel::getConn();**

```

静态方法的定义也有一个主要区别。您不能使用`$this`变量（因为没有对象可以引用`$this`变量）。

类的另一个“静态”特性是类常量。类常量的作用类似于静态属性，但其值不能被更改。类常量必须始终在类声明部分分配其值，并且它们之前没有美元符号（因此它们的命名方式就像常规的 PHP 常量）。类常量主要用于保持全局命名空间的清洁（这也是静态方法的用途之一）：

```php
class DataModel
{
public static $conn = null;
**const ORDER_AZ = 1;
const ORDER_ZA = 2;**
static function getConn()
{
if(!self::$conn) {
self::$conn = new PDO('sqlite:./my.db', 'user', 'pass');
}
return self::$conn;
}
static function getItems($sortMode)
{
if($sortMode == self::ORDER_AZ) {
$sql = // SQL for ascending
}
else {
$sql = // SQL for descending
}
}
}
$items = DataModel::getItems(DataModel::ORDER_ZA);

```

在代码中尝试为类常量分配一个值将导致解析错误。

# 异常

正如我们所见，异常是 PHP5 的一个非常重要的补充。异常是一种特殊类型的对象，当实例化并“抛出”时，会打破正常的执行流程并跳转到所谓的`catch`块。

异常用于报告错误条件。传统上，如果函数失败，函数会返回错误代码。应用程序必须在继续下一个函数调用之前检查每个函数调用。记住您用于连接到 MySQL 数据库的代码片段：

```php
$dbh = mysql_connect($host, $user, $pass);
if(!$dbh) {
die('Could not connect to the DB!');
}
if(!mysql_select_db('mydb')) {
die('Could not select the DB');
}
$q = mysql_query('SELECT * FROM test');
if(!$q) {
die('Could not execute query');
}
while($r = mysql_fetch_row($q))
{
...
}

```

如果`mysql_xxx`函数可能会抛出异常，那么这段代码可以简化为这样：

```php
try
exception handlingexception, throwing{
mysql_connect($host, $user, $pass);
mysql_select_db('mydb');
$q = mysql_query('SELECT * FROM test');
while($r = mysql_fetch_row($q))
{
...
}
}
catch(Exception $e)
{
die(e->getMessage());
}

```

当然，这段代码不会起作用，因为这些函数并不是设计来抛出异常的。您将需要使用 PDO，在第三章中我们看到了如何处理 PDO 异常。

异常允许您延迟错误检查并保持更清晰的代码。导致异常抛出的函数（或方法）将被终止，并且`catch`关键字指定的块中的代码将被执行。任何可能抛出异常的代码都被包装在`try`块中：

```php
try
{
// do something exceptional
}
catch(Exception $e)
{
// display warnings etc
// $e->getMessage() contains error message
}

```

异常的真正威力在于能够将它们升级到调用堆栈。这意味着，如果您设计了一个可能抛出异常的函数或类方法，那么该函数或方法不必捕获该异常。事实上，许多应用程序库都是设计成不处理异常，而是让它们传递给调用代码。

例如，本书中遇到的`PDO`和`PDOStatement`类的许多方法都可能抛出异常，您有责任捕获并适当处理它们。

仔细看上面代码片段中的`catch`块。它后面跟着`Exception`（这是 PHP 中所有异常的基类的名称）和变量标识符`$e`。我们可以在`catch`块中使用`$e`变量来检查错误消息和其他调试信息。`Exception`类定义了以下方法：

+   `getMessage()`返回错误消息。

+   `getCode()`返回错误代码。

+   `getFile()`返回异常发生的文件名。

+   `getLine()`返回异常发生的行号。

+   `getTrace()`和`getTraceAsString()`返回回溯（调用堆栈），用于调试。

当然，错误消息和错误代码会根据异常发生的位置而变化，因此它们取决于您使用的应用程序库（如 PDO）。

我们在`catch`关键字后面指定了`Exception`类名，因为这个类，像其他类一样，可以被扩展以创建子类。例如，从 PDO 方法抛出的所有异常都是`PDOException`类的实例。

异常处理机制允许我们为不同类别的异常创建不同的处理程序。例如，我们可以这样做：

```php
try
{
$conn = new PDO('sqlite:./mydb', '', '');
$q = $conn->query('SELECT * FROM test');
while($r = $q->fetch())
{
...
}
**}
catch(PDOException $pdoe)
{**
die('Database error: ' . $pdoe->getMessage());
**}
catch(Exception $e)
{**
die('Unexpected error: ' . $e->getMessage());
}

```

这段代码为所有 PDO 错误定义了两个错误处理程序：一个用于数据库错误，另一个用于所有其他错误，我们将其标识为意外错误。当然，在实际应用中，错误处理策略会更加复杂，但这个例子展示了异常如何被分类。

# 总结

在这个附录中，我们看到 PHP5 具有一些新的面向对象编程扩展，这些扩展与现代编程语言的扩展相当。它们允许我们编写非常庞大的应用程序，同时保持代码重用和整洁。面向对象编程是大型项目（如内容管理系统或涉及 PDO 的数据库库）的自然解决方案。现在，为 PHP5 编写的库都考虑了面向对象编程。

然而，这个附录只是简要介绍了面向对象编程背后的主要概念，以便您可以跟随本书中的代码示例。如果您想完全掌握面向对象编程，您应该参考一些能够介绍并指导您掌握这一挑战性主题的书籍。
