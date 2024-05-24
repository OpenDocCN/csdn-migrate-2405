# PHP7 编程秘籍（五）

> 原文：[`zh.annas-archive.org/md5/2ddf943a2c311275def462dcde4895fb`](https://zh.annas-archive.org/md5/2ddf943a2c311275def462dcde4895fb)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：查看高级算法

在本章中，我们将涵盖：

+   使用 getter 和 setter

+   实现链表

+   构建冒泡排序

+   实现堆栈

+   构建二分搜索类

+   实现搜索引擎

+   显示多维数组并累积总数

# 介绍

在本章中，我们涵盖了实现各种高级算法的配方，例如链表、冒泡排序、堆栈和二分搜索。此外，我们还涵盖了 getter 和 setter，以及实现搜索引擎和显示来自多维数组的值并累积总数。

# 使用 getter 和 setter

乍一看，似乎定义具有`public`属性的类，然后可以直接读取或写入这些属性是有意义的。然而，最佳做法是将属性定义为`protected`，然后为每个属性定义**getter**和**setter**。顾名思义，*getter*用于检索属性的值。*setter*用于设置值。

### 提示

**最佳实践**

将属性定义为`protected`以防止意外*外部*访问。使用`public` get*和 set*方法来访问这些属性。通过这种方式，不仅可以更精确地控制访问，还可以在获取和设置它们时进行格式和数据类型的更改。

## 如何做...

1.  Getter 和 setter 在获取或设置值时提供了额外的灵活性。如果需要，您可以添加额外的逻辑层，这是直接读取或写入公共属性时无法实现的。您只需要创建一个以`get`或`set`为前缀的公共方法。属性的名称成为后缀。约定是将变量的第一个字母大写。因此，如果属性是`$testValue`，getter 将是`getTestValue()`。

1.  在此示例中，我们定义了一个具有受保护属性`$date`的类。请注意，`get`和`set`方法允许将其视为`DateTime`对象或字符串。无论如何，该值实际上都存储为`DateTime`实例。

```php
$a = new class() {
  protected $date;
  public function setDate($date)
  {
    if (is_string($date)) {
        $this->date = new DateTime($date);
    } else {
        $this->date = $date;
    }
  }
  public function getDate($asString = FALSE)
  {
    if ($asString) {
        return $this->date->format('Y-m-d H:i:s');
    } else {
        return $this->date;
    }
  }
};
```

1.  Getter 和 setter 允许您过滤或清理传入或传出的数据。在下面的示例中，有两个属性`$intVal`和`$arrVal`，它们被设置为默认初始值`NULL`。请注意，getter 的返回值不仅是数据类型化的，而且还提供了默认值。setter 也要么强制执行传入的数据类型，要么将传入的值强制转换为特定的数据类型：

```php
<?php
class GetSet
{
  protected $intVal = NULL;
  protected $arrVal = NULL;
  // note the use of the null coalesce operator to return a default value
  public function getIntVal() : int
  {
    return $this->intVal ?? 0;
  }
  public function getArrVal() : array
  {
    return $this->arrVal ?? array();
  }
  public function setIntVal($val)
  {
    $this->intVal = (int) $val ?? 0;
  }
  public function setArrVal(array $val)
  {
    $this->arrVal = $val ?? array();
  }
}
```

1.  如果一个类有很多属性，为每个属性定义一个明确的 getter 和 setter 可能会变得乏味。在这种情况下，可以使用魔术方法`__call()`定义一种*回退*。以下类定义了九个不同的属性。我们不必定义九个 getter 和九个 setter，而是定义一个名为`__call()`的方法，该方法确定使用是`get`还是`set`。如果是`get`，它会从内部数组中检索键。如果是`set`，它会将值存储在内部数组中。

### 注意

`__call()`方法是一个魔术方法，如果应用程序调用不存在的方法，则会执行该方法。

```php
<?php
class LotsProps
{
  protected $firstName  = NULL;
  protected $lastName   = NULL;
  protected $addr1      = NULL;
  protected $addr2      = NULL;
  protected $city       = NULL;
  protected $state      = NULL;
  protected $province   = NULL;
  protected $postalCode = NULL;
  protected $country    = NULL;
  protected $values     = array();

  public function __call($method, $params)
  {
    preg_match('/^(get|set)(.*?)$/i', $method, $matches);
    $prefix = $matches[1] ?? '';
    $key    = $matches[2] ?? '';
    $key    = strtolower($key);
    if ($prefix == 'get') {
        return $this->values[$key] ?? '---';
    } else {
        $this->values[$key] = $params[0];
    }
  }
}
```

## 工作原理...

将步骤 1 中提到的代码复制到一个新文件`chap_10_oop_using_getters_and_setters.php`中。要测试该类，请添加以下内容：

```php
// set date using a string
$a->setDate('2015-01-01');
var_dump($a->getDate());

// retrieves the DateTime instance
var_dump($a->getDate(TRUE));

// set date using a DateTime instance
$a->setDate(new DateTime('now'));
var_dump($a->getDate());

// retrieves the DateTime instance
var_dump($a->getDate(TRUE));
```

在下面的输出中，您可以看到`$date`属性可以使用`string`或实际的`DateTime`实例进行设置。当执行`getDate()`时，可以根据`$asString`标志的值返回`string`或`DateTime`实例：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_10_12.jpg)

接下来，看一下步骤 2 中定义的代码。将此代码复制到一个名为`chap_10_oop_using_getters_and_setters_defaults.php`的文件中，并添加以下内容：

```php
// create the instance
$a = new GetSet();

// set a "proper" value
$a->setIntVal(1234);
echo $a->getIntVal();
echo PHP_EOL;

// set a bogus value
$a->setIntVal('some bogus value');
echo $a->getIntVal();
echo PHP_EOL;

// NOTE: boolean TRUE == 1
$a->setIntVal(TRUE);
echo $a->getIntVal();
echo PHP_EOL;

// returns array() even though no value was set
var_dump($a->getArrVal());
echo PHP_EOL;

// sets a "proper" value
$a->setArrVal(['A','B','C']);
var_dump($a->getArrVal());
echo PHP_EOL;

try {
    $a->setArrVal('this is not an array');
    var_dump($a->getArrVal());
    echo PHP_EOL;
} catch (TypeError $e) {
    echo $e->getMessage();
}

echo PHP_EOL;
```

从以下输出中可以看出，设置*正确*的整数值会按预期工作。非数字值默认为`0`。有趣的是，如果您将布尔值`TRUE`作为`setIntVal()`的参数，它会被插入为`1`。

如果您在不设置值的情况下调用`getArrVal()`，默认值是一个空数组。设置数组值会按预期工作。但是，如果您将非数组值作为参数提供，数组的类型提示会导致抛出`TypeError`，可以像这样捕获：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_10_13.jpg)

最后，将步骤 3 中定义的`LotsProps`类放在一个单独的文件`chap_10_oop_using_getters_and_setters_magic_call.php`中。现在添加代码来设置值。当然，会调用魔术方法`__call()`。运行`preg_match()`后，不存在的属性的剩余部分，在`set`字母之后，将成为内部数组`$values`中的一个键：

```php
$a = new LotsProps();
$a->setFirstName('Li\'l Abner');
$a->setLastName('Yokum');
$a->setAddr1('1 Dirt Street');
$a->setCity('Dogpatch');
$a->setState('Kentucky');
$a->setPostalCode('12345');
$a->setCountry('USA');
?>
```

然后，您可以定义显示值的 HTML，使用相应的`get`方法。这些方法将返回内部数组的键：

```php
<div class="container">
<div class="left blue1">Name</div>
<div class="right yellow1">
<?= $a->getFirstName() . ' ' . $a->getLastName() ?></div>   
</div>
<div class="left blue2">Address</div>
<div class="right yellow2">
    <?= $a->getAddr1() ?>
    <br><?= $a->getAddr2() ?>
    <br><?= $a->getCity() ?>
    <br><?= $a->getState() ?>
    <br><?= $a->getProvince() ?>
    <br><?= $a->getPostalCode() ?>
    <br><?= $a->getCountry() ?>
</div>   
</div>
```

这是最终输出：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_10_14.jpg)

# 实现链表

链表是一个列表包含指向另一个列表键的列表。类似地，在数据库术语中，您可以有一个包含数据的表，以及一个指向数据的单独索引。一个索引可以按 ID 生成项目列表。另一个索引可能根据标题产生列表等等。链表的显着特点是您不必触及原始项目列表。

例如，在接下来显示的图表中，主列表包含 ID 号码和水果的名称。如果您直接输出主列表，水果名称将按照以下顺序显示：**苹果**，**葡萄**，**香蕉**，**橙子**，**樱桃**。另一方面，如果您使用链表作为索引，结果输出的水果名称将是**苹果**，**香蕉**，**樱桃**，**葡萄**和**橙子**。

![实现链表](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_10_01.jpg)

## 如何做...

1.  链表的主要用途之一是以不同的顺序显示项目。一种方法是创建键值对的迭代，其中键表示新顺序，值包含主列表中键的值。这样的函数可能如下所示：

```php
function buildLinkedList(array $primary,
                         callable $makeLink)
{
  $linked = new ArrayIterator();
  foreach ($primary as $key => $row) {
    $linked->offsetSet($makeLink($row), $key);
  }
  $linked->ksort();
  return $linked;
}
```

1.  我们使用匿名函数生成新的键，以提供额外的灵活性。您还会注意到我们按键排序(`ksort()`)，以便链表按键顺序迭代。

1.  我们只需要通过链表进行迭代，但是从主列表`$customer`中产生结果：

```php
foreach ($linked as $key => $link) {
  $output .= printRow($customer[$link]);
}
```

1.  请注意，我们绝对不会触及主列表。这使我们能够生成多个链表，每个链表代表不同的顺序，同时保留我们的原始数据集。

1.  链表的另一个重要用途是用于过滤。该技术与之前显示的类似。唯一的区别是我们扩展了`buildLinkedList()`函数，添加了一个过滤列和过滤值：

```php
function buildLinkedList(array $primary,
                         callable $makeLink,
                         $filterCol = NULL,
                         $filterVal = NULL)
{
  $linked = new ArrayIterator();
  $filterVal = trim($filterVal);
  foreach ($primary as $key => $row) {
    if ($filterCol) {
      if (trim($row[$filterCol]) == $filterVal) {
        $linked->offsetSet($makeLink($row), $key);
      }
    } else {
      $linked->offsetSet($makeLink($row), $key);
    }
  }
  $linked->ksort();
  return $linked;
}
```

1.  我们只在链表中包含与主列表中的`$filterCol`表示的值匹配的值。迭代逻辑与步骤 2 中显示的相同。

1.  最后，另一种形式的链表是*双向*链表。在这种情况下，列表构造成可以向前或向后进行迭代。在 PHP 的情况下，我们很幸运地拥有一个 SPL 类`SplDoublyLinkedList`，它可以很好地完成这项任务。以下是构建双向链表的函数：

```php
function buildDoublyLinkedList(ArrayIterator $linked)
{
  $double = new SplDoublyLinkedList();
  foreach ($linked as $key => $value) {
    $double->push($value);
  }
  return $double;
}
```

### 注意

`SplDoublyLinkedList`的术语可能会产生误导。`SplDoublyLinkedList::top()`实际上指向列表的*末尾*，而`SplDoublyLinkedList::bottom()`指向*开始*！

## 工作原理...

将第一个项目中显示的代码复制到一个文件`chap_10_linked_list_include.php`中。为了演示链表的使用，您需要一个数据源。在这个示例中，您可以使用先前配方中提到的`customer.csv`文件。它是一个 CSV 文件，包含以下列：

```php
"id","name","balance","email","password","status","security_question",
"confirm_code","profile_id","level"
```

您可以将以下函数添加到先前提到的包含文件中，以生成客户的主列表，并显示有关它们的信息。请注意，我们使用第一列 id 作为主键：

```php
function readCsv($fn, &$headers)
{
  if (!file_exists($fn)) {
    throw new Error('File Not Found');
  }
  $fileObj = new SplFileObject($fn, 'r');
  $result = array();
  $headers = array();
  $firstRow = TRUE;
  while ($row = $fileObj->fgetcsv()) {
    // store 1st row as headers
    if ($firstRow) {
      $firstRow = FALSE;
      $headers = $row;
    } else {
      if ($row && $row[0] !== NULL && $row[0] !== 0) {
        $result[$row[0]] = $row;
      }
    }
  }
  return $result;
}

function printHeaders($headers)
{
  return sprintf('%4s : %18s : %8s : %32s : %4s' . PHP_EOL,
                 ucfirst($headers[0]),
                 ucfirst($headers[1]),
                 ucfirst($headers[2]),
                 ucfirst($headers[3]),
                 ucfirst($headers[9]));
}

function printRow($row)
{
  return sprintf('%4d : %18s : %8.2f : %32s : %4s' . PHP_EOL,
                 $row[0], $row[1], $row[2], $row[3], $row[9]);
}

function printCustomer($headers, $linked, $customer)
{
  $output = '';
  $output .= printHeaders($headers);
  foreach ($linked as $key => $link) {
    $output .= printRow($customer[$link]);
  }
  return $output;
}
```

然后您可以定义一个调用程序`chap_10_linked_list_in_order.php`，其中包括先前定义的文件，并读取`customer.csv`：

```php
<?php
define('CUSTOMER_FILE', __DIR__ . '/../data/files/customer.csv');
include __DIR__ . '/chap_10_linked_list_include.php';
$headers = array();
$customer = readCsv(CUSTOMER_FILE, $headers);
```

然后您可以定义一个将在链表中生成一个键的匿名函数。在这个示例中，定义一个将第一列（名称）分解为名和姓的函数：

```php
$makeLink = function ($row) {
  list($first, $last) = explode(' ', $row[1]);
  return trim($last) . trim($first);
};
```

然后您可以调用函数来构建链表，并使用`printCustomer()`来显示结果：

```php
$linked = buildLinkedList($customer, $makeLink);
echo printCustomer($headers, $linked, $customer);
```

以下是输出可能会出现的方式：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_10_02.jpg)

要生成过滤结果，请修改`buildLinkedList()`，如步骤 4 中所述。然后可以添加逻辑来检查过滤列的值是否与过滤器中的值匹配：

```php
define('LEVEL_FILTER', 'INT');

$filterCol = 9;
$filterVal = LEVEL_FILTER;
$linked = buildLinkedList($customer, $makeLink, $filterCol, $filterVal);
```

## 还有更多...

PHP 7.1 引入了使用`[ ]`作为`list()`的替代方法。如果您查看先前提到的匿名函数，您可以在 PHP 7.1 中将其重写如下：

```php
$makeLink = function ($row) {
  [$first, $last] = explode(' ', $row[1]);
  return trim($last) . trim($first);
};
```

更多信息，请参见[`wiki.php.net/rfc/short_list_syntax`](https://wiki.php.net/rfc/short_list_syntax)。

# 构建冒泡排序

经典的**冒泡排序**经常分配给大学生练习。尽管如此，掌握这个算法很重要，因为有许多情况下内置的 PHP 排序函数不适用。一个例子是对多维数组进行排序，其中排序键不是第一列。

冒泡排序的工作方式是通过递归迭代列表并交换当前值和下一个值。如果要使项目按升序排列，则如果下一个项目小于当前项目，则进行交换。对于降序排序，如果相反情况为真，则进行交换。当不再发生交换时，排序结束。

在下图中，第一次通过后，**Grape**和**Banana**被交换，**Orange**和**Cherry**也被交换。第二次通过后，**Grape**和**Cherry**被交换。在最后一次通过中不再发生交换，冒泡排序结束：

![构建冒泡排序](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_10_03.jpg)

## 如何做...

1.  我们不想实际*移动*数组中的值；这在资源使用方面将是非常昂贵的。相反，我们将使用在前面的配方中讨论的**链表**。

1.  首先，我们使用在前面的配方中讨论的`buildLinkedList()`函数构建一个链表。

1.  然后我们定义一个新函数`bubbleSort()`，它接受引用的链表，主列表，排序字段和表示排序顺序（升序或降序）的参数：

```php
function bubbleSort(&$linked, $primary, $sortField, $order = 'A')
{
```

1.  所需的变量包括代表迭代次数的变量，交换次数的变量，以及基于链表的迭代器：

```php
  static $iterations = 0;
  $swaps = 0;
  $iterator = new ArrayIterator($linked);
```

1.  在`while()`循环中，只有在迭代仍然有效时才继续进行，也就是说仍在进行中。然后我们获取当前键和值，以及下一个键和值。请注意额外的`if()`语句以确保迭代仍然有效（也就是说，确保我们不会掉出列表的末尾！）：

```php
while ($iterator->valid()) {
  $currentLink = $iterator->current();
  $currentKey  = $iterator->key();
  if (!$iterator->valid()) break;
  $iterator->next();
  $nextLink = $iterator->current();
  $nextKey  = $iterator->key();
```

1.  接下来，我们检查排序是升序还是降序。根据方向，我们检查下一个值是大于还是小于当前值。比较的结果存储在`$expr`中：

```php
if ($order == 'A') {
    $expr = $primary[$linked->offsetGet
            ($currentKey)][$sortField] > 
            $primary[$linked->offsetGet($nextKey)][$sortField];
} else {
    $expr = $primary[$linked->offsetGet
            ($currentKey)][$sortField] < 
            $primary[$linked->offsetGet($nextKey)][$sortField];
}
```

1.  如果`$expr`的值为`TRUE`，并且我们有有效的当前键和下一个键，则交换链表中的值。我们还增加`$swaps`：

```php
if ($expr && $currentKey && $nextKey 
    && $linked->offsetExists($currentKey) 
    && $linked->offsetExists($nextKey)) {
    $tmp = $linked->offsetGet($currentKey);
    $linked->offsetSet($currentKey, 
    $linked->offsetGet($nextKey));
    $linked->offsetSet($nextKey, $tmp);
    $swaps++;
  }
}
```

1.  最后，如果发生了任何交换，我们需要再次运行迭代，直到没有更多的交换。因此，我们对同一个方法进行递归调用：

```php
if ($swaps) bubbleSort($linked, $primary, $sortField, $order);
```

1.  *真正*的返回值是重新组织的链表。我们还返回迭代的次数，仅供参考：

```php
  return ++$iterations;
}
```

## 工作原理...

将之前讨论的`bubbleSort()`函数添加到上一篇教程中创建的包含文件中。您可以使用前一篇教程中讨论的相同逻辑来读取`customer.csv`文件，生成一个主列表：

```php
<?php
define('CUSTOMER_FILE', __DIR__ . '/../data/files/customer.csv');
include __DIR__ . '/chap_10_linked_list_include.php';
$headers = array();
$customer = readCsv(CUSTOMER_FILE, $headers);
```

然后，您可以使用第一列作为排序键来生成一个链表：

```php
$makeLink = function ($row) {
  return $row[0];
};
$linked = buildLinkedList($customer, $makeLink);
```

最后，调用`bubbleSort()`函数，提供链表和客户列表作为参数。您还可以提供一个排序列，在本示例中是列 2，表示账户余额，使用字母'A'表示升序。`printCustomer()`函数可用于显示输出：

```php
echo 'Iterations: ' . bubbleSort($linked, $customer, 2, 'A') . PHP_EOL;
echo printCustomer($headers, $linked, $customer);
```

以下是输出的示例：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_10_04.jpg)

# 实现堆栈

**堆栈**是一种简单的算法，通常实现为**后进先出**（**LIFO**）。想象一下一堆书放在图书馆的桌子上。当图书管理员去把书放回原位时，首先处理的是最顶部的书，依此类推，直到堆栈底部的书被替换。最顶部的书是最后放在堆栈上的，因此后进先出。

在编程术语中，堆栈用于临时存储信息。检索顺序有助于首先检索最近的项目。

## 如何做...

1.  首先，我们定义一个`Application\Generic\Stack`类。核心逻辑封装在 SPL 类`SplStack`中：

```php
namespace Application\Generic;
use SplStack;
class Stack
{
  // code
}
```

1.  接下来，我们定义一个表示堆栈的属性，并设置一个`SplStack`实例：

```php
protected $stack;
public function __construct()
{
  $this->stack = new SplStack();
}
```

1.  然后我们定义了从堆栈中添加和删除的方法，经典的`push()`和`pop()`方法：

```php
public function push($message)
{
  $this->stack->push($message);
}
public function pop()
{
  return $this->stack->pop();
}
```

1.  我们还添加了一个`__invoke()`的实现，返回`stack`属性的实例。这允许我们在直接函数调用中使用对象：

```php
public function __invoke()
{
  return $this->stack;
}
```

## 工作原理...

堆栈的一个可能用途是存储消息。在消息的情况下，通常希望首先检索最新的消息，因此这是堆栈的一个完美用例。按照本教程中讨论的内容定义`Application\Generic\Stack`类。接下来，定义一个调用程序，设置自动加载并创建`stack`的实例：

```php
<?php
// setup class autoloading
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Generic\Stack;
$stack = new Stack();
```

要对堆栈执行操作，存储一系列消息。由于您很可能会在应用程序的不同点存储消息，因此可以使用`sleep()`来模拟其他代码的运行：

```php
echo 'Do Something ... ' . PHP_EOL;
$stack->push('1st Message: ' . date('H:i:s'));
sleep(3);

echo 'Do Something Else ... ' . PHP_EOL;
$stack->push('2nd Message: ' . date('H:i:s'));
sleep(3);

echo 'Do Something Else Again ... ' . PHP_EOL;
$stack->push('3rd Message: ' . date('H:i:s'));
sleep(3);
```

最后，只需遍历堆栈以检索消息。请注意，您可以调用堆栈对象，就像它是一个函数一样，它返回`SplStack`实例：

```php
echo 'What Time Is It?' . PHP_EOL;
foreach ($stack() as $item) {
  echo $item . PHP_EOL;
}
```

以下是预期输出：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_10_05.jpg)

# 构建二进制搜索类

传统搜索通常按顺序遍历项目列表。这意味着要搜索的最大可能数量的项目可能与列表的长度相同！这并不是很有效。如果需要加快搜索速度，请考虑实现*二进制*搜索。

这种技术非常简单：找到列表中点，并确定搜索项是小于、等于还是大于中点项。如果小于，则将上限设置为中点，并仅搜索列表的前半部分。如果大于，则将下限设置为中点，并仅搜索列表的后半部分。然后继续将列表分成 1/4、1/8、1/16 等，直到找到搜索项（或没有找到）。

### 注意

需要注意的是，尽管比较的最大次数远远小于顺序搜索（*log n + 1*，其中*n*是列表中的元素数，*log*是二进制对数），但参与搜索的列表必须首先排序，这当然会降低性能。

## 如何做...

1.  我们首先构建一个搜索类`Application\Generic\Search`，它接受主列表作为参数。作为控制，我们还定义一个属性`$iterations`：

```php
namespace Application\Generic;
class Search
{
  protected $primary;
  protected $iterations;
  public function __construct($primary)
  {
    $this->primary = $primary;
  }
```

1.  接下来，我们定义一个方法`binarySearch()`，它设置了搜索基础设施。首要任务是构建一个单独的数组`$search`，其中键是搜索中包含的列的组合。然后我们按键排序：

```php
public function binarySearch(array $keys, $item)
{
  $search = array();
  foreach ($this->primary as $primaryKey => $data) {
    $searchKey = function ($keys, $data) {
      $key = '';
      foreach ($keys as $k) $key .= $data[$k];
```

```php
      return $key;
    };
    $search[$searchKey($keys, $data)] = $primaryKey;
  }
  ksort($search);
```

1.  然后我们将键提取到另一个数组`$binary`中，以便我们可以根据数字键执行二进制排序。然后我们调用`doBinarySearch()`，它会从我们的中间数组`$search`中得到一个键，或一个布尔值`FALSE`：

```php
  $binary = array_keys($search);
  $result = $this->doBinarySearch($binary, $item);
  return $this->primary[$search[$result]] ?? FALSE;
}
```

1.  首先，`doBinarySearch()`初始化一系列参数。`$iterations`，`$found`，`$loop`，`$done`和`$max`都用于防止无限循环。`$upper`和`$lower`表示要检查的列表切片：

```php
public function doBinarySearch($binary, $item)
{
  $iterations = 0;
  $found = FALSE;
  $loop  = TRUE;
  $done  = -1;
  $max   = count($binary);
  $lower = 0;
  $upper = $max - 1;
```

1.  然后我们实现一个`while()`循环并设置中点：

```php
  while ($loop && !$found) {
    $mid = (int) (($upper - $lower) / 2) + $lower;
```

1.  现在我们可以使用新的 PHP 7 **太空船操作符**，它在单个比较中给出小于、等于或大于。如果小于，则将上限设置为中点。如果大于，则将下限调整为中点。如果相等，则完成：

```php
switch ($item <=> $binary[$mid]) {
  // $item < $binary[$mid]
  case -1 :
  $upper = $mid;
  break;
  // $item == $binary[$mid]
  case 0 :
  $found = $binary[$mid];
  break;
  // $item > $binary[$mid]
  case 1 :
  default :
  $lower = $mid;
}
```

1.  现在是一点循环控制。我们增加迭代次数，并确保它不超过列表的大小。如果超过了，肯定有问题，我们需要退出。否则，我们检查上限和下限是否连续两次相同，如果是，则搜索项未找到。然后我们存储迭代次数并返回找到的内容（或未找到）：

```php
    $loop = (($iterations++ < $max) && ($done < 1));
    $done += ($upper == $lower) ? 1 : 0;
  }
  $this->iterations = $iterations;
  return $found;
}
```

## 它是如何工作的...

首先，实现`Application\Generic\Search`类，定义本教程中描述的方法。接下来，定义一个调用程序`chap_10_binary_search.php`，它设置自动加载并将`customer.csv`文件读取为搜索目标（如前一教程中所讨论的）：

```php
<?php
define('CUSTOMER_FILE', __DIR__ . '/../data/files/customer.csv');
include __DIR__ . '/chap_10_linked_list_include.php';
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Generic\Search;
$headers = array();
$customer = readCsv(CUSTOMER_FILE, $headers);
```

然后，您可以创建一个新的`Search`实例，并在列表的中间某个位置指定一个项目。在本示例中，搜索基于列 1，即客户名称，项目为`Todd Lindsey`：

```php
$search = new Search($customer);
$item = 'Todd Lindsey';
$cols = [1];
echo "Searching For: $item\n";
var_dump($search->binarySearch($cols, $item));
```

为了说明，在`Application\Generic\Search::doBinarySearch()`中的`switch()`之前添加此行：

```php
echo 'Upper:Mid:Lower:<=> | ' . $upper . ':' . $mid . ':' . $lower . ':' . ($item <=> $binary[$mid]);
```

输出如下所示。请注意，上限、中间和下限会调整，直到找到项目：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_10_06.jpg)

## 另请参阅

有关二进制搜索的更多信息，请参阅维基百科上的一篇优秀文章，其中介绍了基本数学内容[`en.wikipedia.org/wiki/Binary_search_algorithm`](https://en.wikipedia.org/wiki/Binary_search_algorithm)。

# 实施搜索引擎

为了实现搜索引擎，我们需要为多个列的搜索做好准备。此外，重要的是要认识到搜索项可能在字段的中间找到，并且用户很少提供足够的信息进行精确匹配。因此，我们将大量依赖 SQL 的`LIKE %value%`子句。

## 如何做...

1.  首先，我们定义一个基本类来保存搜索条件。该对象包含三个属性：键，最终表示数据库列；运算符（`LIKE`，`<`，`>`等）；和可选的项目。项目是可选的原因是一些运算符，如`IS NOT NULL`，不需要特定的数据：

```php
namespace Application\Database\Search;
class Criteria
{
  public $key;
  public $item;
  public $operator;
  public function __construct($key, $operator, $item = NULL)
  {
    $this->key  = $key;
    $this->operator = $operator;
    $this->item = $item;
  }
}
```

1.  接下来，我们需要定义一个类`Application\Database\Search\Engine`，并提供必要的类常量和属性。`$columns`和`$mapping`之间的区别在于`$columns`保存的信息最终将出现在 HTML 的`SELECT`字段（或等效字段）中。出于安全原因，我们不希望公开数据库列的实际名称，因此需要另一个数组`$mapping`：

```php
namespace Application\Database\Search;
use PDO;
use Application\Database\Connection;
class Engine
{
  const ERROR_PREPARE = 'ERROR: unable to prepare statement';
  const ERROR_EXECUTE = 'ERROR: unable to execute statement';
  const ERROR_COLUMN  = 'ERROR: column name not on list';
  const ERROR_OPERATOR= 'ERROR: operator not on list';
  const ERROR_INVALID = 'ERROR: invalid search criteria';

  protected $connection;
  protected $table;
  protected $columns;
  protected $mapping;
  protected $statement;
  protected $sql = '';
```

1.  接下来，我们定义一组我们愿意支持的运算符。键表示实际的 SQL。值是表单中将出现的内容：

```php
  protected $operators = [
      'LIKE'     => 'Equals',
      '<'        => 'Less Than',
      '>'        => 'Greater Than',
      '<>'       => 'Not Equals',
      'NOT NULL' => 'Exists',
  ];
```

1.  构造函数接受数据库连接实例作为参数。为了我们的目的，我们将使用第五章中定义的`Application\Database\Connection`。我们还需要提供数据库表的名称，以及`$columns`，一个任意列键和标签的数组，这些将出现在 HTML 表单中。这将引用`$mapping`，其中键与`$columns`匹配，但值表示实际的数据库列名：

```php
public function __construct(Connection $connection, 
                            $table, array $columns, array $mapping)
{
  $this->connection  = $connection;
  $this->setTable($table);
  $this->setColumns($columns);
  $this->setMapping($mapping);
}
```

1.  在构造函数之后，我们提供一系列有用的 getter 和 setter：

```php
public function setColumns($columns)
{
  $this->columns = $columns;
}
public function getColumns()
{
  return $this->columns;
}
// etc.
```

1.  可能最关键的方法是构建要准备的 SQL 语句。在初始`SELECT`设置之后，我们添加一个`WHERE`子句，使用`$mapping`添加实际的数据库列名。然后添加操作符并实现`switch()`，根据操作符，可能会或可能不会添加一个表示搜索项的命名占位符：

```php
public function prepareStatement(Criteria $criteria)
{
  $this->sql = 'SELECT * FROM ' . $this->table . ' WHERE ';
  $this->sql .= $this->mapping[$criteria->key] . ' ';
  switch ($criteria->operator) {
    case 'NOT NULL' :
      $this->sql .= ' IS NOT NULL OR ';
      break;
    default :
      $this->sql .= $criteria->operator . ' :' 
      . $this->mapping[$criteria->key] . ' OR ';
  }
```

1.  现在核心的`SELECT`已经定义，我们删除任何尾随的`OR`关键字，并添加一个导致结果根据搜索列排序的子句。然后将该语句发送到数据库进行准备：

```php
  $this->sql = substr($this->sql, 0, -4)
    . ' ORDER BY ' . $this->mapping[$criteria->key];
  $statement = $this->connection->pdo->prepare($this->sql);
  return $statement;
}
```

1.  现在我们准备转向主要的展示，`search()`方法。我们接受一个`Application\Database\Search\Criteria`对象作为参数。这确保我们至少有一个项目键和操作符。为了安全起见，我们添加了一个`if()`语句来检查这些属性：

```php
public function search(Criteria $criteria)
{
  if (empty($criteria->key) || empty($criteria->operator)) {
    yield ['error' => self::ERROR_INVALID];
    return FALSE;
  }
```

1.  然后我们调用`prepareStatement()`使用`try` / `catch`来捕获错误：

```php
try {
    if (!$statement = $this->prepareStatement($criteria)) {
      yield ['error' => self::ERROR_PREPARE];
      return FALSE;
}
```

1.  接下来，我们构建一个将提供给`execute()`的参数数组。键表示在准备语句中用作占位符的数据库列名。请注意，我们使用`=`而不是`LIKE %value%构造`：

```php
$params = array();
switch ($criteria->operator) {
  case 'NOT NULL' :
    // do nothing: already in statement
    break;
    case 'LIKE' :
    $params[$this->mapping[$criteria->key]] = 
    '%' . $criteria->item . '%';
    break;
    default :
    $params[$this->mapping[$criteria->key]] = 
    $criteria->item;
}
```

1.  该语句被执行，并使用`yield`关键字返回结果，这有效地将此方法转换为生成器：

```php
    $statement->execute($params);
    while ($row = $statement->fetch(PDO::FETCH_ASSOC)) {
      yield $row;
    }
  } catch (Throwable $e) {
    error_log(__METHOD__ . ':' . $e->getMessage());
    throw new Exception(self::ERROR_EXECUTE);
  }
  return TRUE;
}
```

## 工作原理...

将本章中讨论的代码放在`Application\Database\Search`下的文件`Criteria.php`和`Engine.php`中。然后可以定义一个调用脚本`chap_10_search_engine.php`，设置自动加载。您可以利用第五章中讨论的`Application\Database\Connection`类，*与数据库交互*，以及第六章中涵盖的表单元素类，*构建可扩展的网站*：

```php
<?php
define('DB_CONFIG_FILE', '/../config/db.config.php');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');

use Application\Database\Connection;
use Application\Database\Search\ { Engine, Criteria };
use Application\Form\Generic;
use Application\Form\Element\Select;
```

现在您可以定义哪些数据库列将出现在表单中，以及匹配的映射文件：

```php
$dbCols = [
  'cname' => 'Customer Name',
  'cbal' => 'Account Balance',
  'cmail' => 'Email Address',
  'clevel' => 'Level'
];

$mapping = [
  'cname' => 'name',
  'cbal' => 'balance',
  'cmail' => 'email',
  'clevel' => 'level'
];
```

您现在可以设置数据库连接并创建搜索引擎实例：

```php
$conn = new Connection(include __DIR__ . DB_CONFIG_FILE);
$engine = new Engine($conn, 'customer', $dbCols, $mapping);
```

为了显示适当的下拉`SELECT`元素，我们基于`Application\Form\*`类定义包装器和元素：

```php
$wrappers = [
  Generic::INPUT => ['type' => 'td', 'class' => 'content'],
  Generic::LABEL => ['type' => 'th', 'class' => 'label'],
  Generic::ERRORS => ['type' => 'td', 'class' => 'error']
];

// define elements
$fieldElement = new Select('field',
                Generic::TYPE_SELECT,
                'Field',
                $wrappers,
                ['id' => 'field']);
                $opsElement = new Select('ops',
                Generic::TYPE_SELECT,
                'Operators',
                $wrappers,
                ['id' => 'ops']);
                $itemElement = new Generic('item',
                Generic::TYPE_TEXT,
                'Searching For ...',
                $wrappers,
                ['id' => 'item','title' => 'If more than one item, separate with commas']);
                $submitElement = new Generic('submit',
                Generic::TYPE_SUBMIT,
                'Search',
                $wrappers,
                ['id' => 'submit','title' => 'Click to Search', 'value' => 'Search']);
```

然后我们获取输入参数（如果已定义），设置表单元素选项，创建搜索条件并运行搜索：

```php
$key  = (isset($_GET['field'])) 
? strip_tags($_GET['field']) : NULL;
$op   = (isset($_GET['ops'])) ? $_GET['ops'] : NULL;
$item = (isset($_GET['item'])) ? strip_tags($_GET['item']) : NULL;
$fieldElement->setOptions($dbCols, $key);
$itemElement->setSingleAttribute('value', $item);
$opsElement->setOptions($engine->getOperators(), $op);
$criteria = new Criteria($key, $op, $item);
$results = $engine->search($criteria);
?>
```

显示逻辑主要是朝向呈现表单。更详细的介绍在第六章中讨论，*构建可扩展的网站*，但我们在这里展示核心逻辑：

```php
  <form name="search" method="get">
  <table class="display" cellspacing="0" width="100%">
    <tr><?= $fieldElement->render(); ?></tr>
    <tr><?= $opsElement->render(); ?></tr>
    <tr><?= $itemElement->render(); ?></tr>
    <tr><?= $submitElement->render(); ?></tr>
    <tr>
    <th class="label">Results</th>
      <td class="content" colspan=2>
      <span style="font-size: 10pt;font-family:monospace;">
      <table>
      <?php foreach ($results as $row) : ?>
        <tr>
          <td><?= $row['id'] ?></td>
          <td><?= $row['name'] ?></td>
          <td><?= $row['balance'] ?></td>
          <td><?= $row['email'] ?></td>
          <td><?= $row['level'] ?></td>
        </tr>
      <?php endforeach; ?>
      </table>
      </span>
      </td>
    </tr>
  </table>
  </form>
```

这是浏览器中的示例输出：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_10_07.jpg)

# 显示多维数组和累积总数

如何正确显示多维数组中的数据一直是任何 Web 开发人员的经典问题。举例来说，假设您希望显示客户及其购买的列表。对于每个客户，您希望显示他们的姓名，电话号码，账户余额等。这已经代表了一个二维数组，其中*x*轴代表客户，*y*轴代表该客户的数据。现在加入购买，您就有了第三个轴！如何在二维屏幕上表示 3D 模型？一个可能的解决方案是使用简单的 JavaScript 可见性切换来结合“隐藏”的分区标签。

## 如何做...

1.  首先，我们需要从使用多个`JOIN`子句的 SQL 语句中生成一个 3D 数组。我们将使用在第一章中介绍的`Application/Database/Connection`类，*建立基础*，来制定一个适当的 SQL 查询。我们留下两个参数`min`和`max`，以支持分页。不幸的是，在这种情况下，我们不能简单地使用`LIMIT`和`OFFSET`，因为行数将取决于任何给定顾客的购买数量。因此，我们可以通过对顾客 ID 的限制来限制行数，假设（希望）是递增的。为了使这个功能正常工作，我们还需要将主要的`ORDER`设置为顾客 ID：

```php
define('ITEMS_PER_PAGE', 6);
define('SUBROWS_PER_PAGE', 6);
define('DB_CONFIG_FILE', '/../config/db.config.php');
include __DIR__ . '/../Application/Database/Connection.php';
use Application\Database\Connection;
$conn = new Connection(include __DIR__ . DB_CONFIG_FILE);
$sql  = 'SELECT c.id,c.name,c.balance,c.email,f.phone, '
  . 'u.transaction,u.date,u.quantity,u.sale_price,r.title '
  . 'FROM customer AS c '
  . 'JOIN profile AS f '
  . 'ON f.id = c.id '
  . 'JOIN purchases AS u '
  . 'ON u.customer_id = c.id '
  . 'JOIN products AS r '
  . 'ON u.product_id = r.id '
  . 'WHERE c.id >= :min AND c.id < :max '
  . 'ORDER BY c.id ASC, u.date DESC ';
```

1.  接下来我们可以实现基于顾客 ID 的分页形式，使用简单的`$_GET`参数进行限制。请注意，我们添加了额外的检查，以确保`$prev`的值不会低于零。您可能考虑添加另一个控件，以确保`$next`的值不会超出最后一个顾客 ID。在这个例子中，我们只允许它递增：

```php
$page = $_GET['page'] ?? 1;
$page = (int) $page;
$next = $page + 1;
$prev = $page - 1;
$prev = ($prev >= 0) ? $prev : 0;
```

1.  然后我们计算`$min`和`$max`的值，并准备并执行 SQL 语句：

```php
$min  = $prev * ITEMS_PER_PAGE;
$max  = $page * ITEMS_PER_PAGE;
$stmt = $conn->pdo->prepare($sql);
$stmt->execute(['min' => $min, 'max' => $max]);
```

1.  使用`while()`循环可以用来获取结果。我们在这个例子中使用了`PDO::FETCH_ASSOC`的简单获取模式。我们使用顾客 ID 作为键，将基本顾客信息存储为数组参数。然后我们在一个子数组中存储一组购买信息，`$results[$key]['purchases'][]`。当顾客 ID 改变时，这是一个信号，表示要为下一个顾客存储相同的信息。请注意，我们在一个数组键 total 中累积每个顾客的总数：

```php
$custId = 0;
$result = array();
$grandTotal = 0.0;
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
  if ($row['id'] != $custId) {
    $custId = $row['id'];
    $result[$custId] = [
      'name'    => $row['name'],
      'balance' => $row['balance'],
      'email'   => $row['email'],
      'phone'   => $row['phone'],
    ];
    $result[$custId]['total'] = 0;
  }
  $result[$custId]['purchases'][] = [
    'transaction' => $row['transaction'],
    'date'        => $row['date'],
    'quantity'    => $row['quantity'],
    'sale_price'  => $row['sale_price'],
    'title'       => $row['title'],
  ];
  $result[$custId]['total'] += $row['sale_price'];
  $grandTotal += $row['sale_price'];
}
?>
```

1.  接下来我们实现视图逻辑。首先，我们从显示主要顾客信息的块开始：

```php
<div class="container">
<?php foreach ($result as $key => $data) : ?>
<div class="mainLeft color0">
    <?= $data['name'] ?> [<?= $key ?>]
</div>
<div class="mainRight">
  <div class="row">
    <div class="left">Balance</div>
           <div class="right"><?= $data['balance']; ?></div>
  </div>
  <div class="row">
    <div class="left color2">Email</div>
           <div class="right"><?= $data['email']; ?></div>
  </div>
  <div class="row">
    <div class="left">Phone</div>
           <div class="right"><?= $data['phone']; ?></div>
    </div>
  <div class="row">
        <div class="left color2">Total Purchases</div>
    <div class="right">
<?= number_format($data['total'],2); ?>
</div>
  </div>
```

1.  接下来是显示该顾客的购买列表的逻辑：

```php
<!-- Purchases Info -->
<table>
  <tr>
  <th>Transaction</th><th>Date</th><th>Qty</th>
   <th>Price</th><th>Product</th>
  </tr>
  <?php $count  = 0; ?>
  <?php foreach ($data['purchases'] as $purchase) : ?>
  <?php $class = ($count++ & 01) ? 'color1' : 'color2'; ?>
  <tr>
  <td class="<?= $class ?>"><?= $purchase['transaction'] ?></td>
  <td class="<?= $class ?>"><?= $purchase['date'] ?></td>
  <td class="<?= $class ?>"><?= $purchase['quantity'] ?></td>
  <td class="<?= $class ?>"><?= $purchase['sale_price'] ?></td>
  <td class="<?= $class ?>"><?= $purchase['title'] ?></td>
  </tr>
  <?php endforeach; ?>
</table>
```

1.  为了分页的目的，我们添加按钮来表示*上一个*和*下一个*：

```php
<?php endforeach; ?>
<div class="container">
  <a href="?page=<?= $prev ?>">
        <input type="button" value="Previous"></a>
  <a href="?page=<?= $next ?>">
        <input type="button" value="Next" class="buttonRight"></a>
</div>
<div class="clearRow"></div>
</div>
```

1.  到目前为止，结果非常不整洁！因此，我们添加了一个简单的 JavaScript 函数，根据其`id`属性切换`<div>`标签的可见性：

```php
<script type="text/javascript">
function showOrHide(id) {
  var div = document.getElementById(id);
  div.style.display = div.style.display == "none" ? "block" : "none";
}
</script>
```

1.  接下来我们将购买表格包裹在最初不可见的`<div>`标签中。然后，我们可以设置初始可见的子行数的限制，并添加一个*显示*剩余购买数据的链接：

```php
<div class="row" id="<?= 'purchase' . $key ?>" style="display:none;">
  <table>
    <tr>
      <th>Transaction</th><th>Date</th><th>Qty</th>
                 <th>Price</th><th>Product</th>
    </tr>
  <?php $count  = 0; ?>
  <?php $first  = TRUE; ?>
  <?php foreach ($data['purchases'] as $purchase) : ?>
    <?php if ($count > SUBROWS_PER_PAGE && $first) : ?>
    <?php     $first = FALSE; ?>
    <?php     $subId = 'subrow' . $key; ?>
    </table>
    <a href="#" onClick="showOrHide('<?= $subId ?>')">More</a>
    <div id="<?= $subId ?>" style="display:none;">
    <table>
    <?php endif; ?>
  <?php $class = ($count++ & 01) ? 'color1' : 'color2'; ?>
  <tr>
  <td class="<?= $class ?>"><?= $purchase['transaction'] ?></td>
  <td class="<?= $class ?>"><?= $purchase['date'] ?></td>
  <td class="<?= $class ?>"><?= $purchase['quantity'] ?></td>
  <td class="<?= $class ?>"><?= $purchase['sale_price'] ?></td>
  <td class="<?= $class ?>"><?= $purchase['title'] ?></td>
  </tr>
  <?php endforeach; ?>
  </table>
  <?php if (!$first) : ?></div><?php endif; ?>
</div>
```

1.  然后我们添加一个按钮，当点击时，会显示隐藏的`<div>`标签：

```php
<input type="button" value="Purchases" class="buttonRight" 
    onClick="showOrHide('<?= 'purchase' . $key ?>')">
```

## 它是如何工作的...

将步骤 1 到 5 中描述的代码放入一个文件`chap_10_html_table_multi_array_hidden.php`中。

在`while()`循环的内部，添加以下内容：

```php
printf('%6s : %20s : %8s : %20s' . PHP_EOL, 
    $row['id'], $row['name'], $row['transaction'], $row['title']);
```

在`while()`循环之后，添加一个`exit`命令。以下是输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_10_08.jpg)

您会注意到基本的顾客信息，如 ID 和姓名，会重复出现在每个结果行中，但购买信息，如交易和产品标题，会有所不同。继续并删除`printf()`语句。

用以下内容替换`exit`命令：

```php
echo '<pre>', var_dump($result), '</pre>'; exit;
```

新组成的 3D 数组如下所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_10_09.jpg)

您现在可以添加步骤 5 到 7 中显示逻辑。虽然您现在显示了所有数据，但视觉显示并不有用。现在继续添加剩下步骤中提到的改进。这是初始输出可能会出现的样子：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_10_15.jpg)

当点击**购买**按钮时，初始购买信息会出现。如果点击**更多**的链接，剩余的购买信息会显示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_10_11.jpg)


# 第十一章：实施软件设计模式

在本章中，我们将涵盖以下主题：

+   创建数组到对象的水合物

+   构建对象到数组的水合物

+   实施策略模式

+   定义映射器

+   实施对象关系映射

+   实施发布/订阅设计模式

# 介绍

将**软件设计模式**融入**面向对象编程**（**OOP**）代码的想法首次在一部名为《设计模式：可复用面向对象软件的基本元素》的重要著作中讨论，该著作由著名的四人组（E. Gamma，R. Helm，R. Johnson 和 J. Vlissides）于 1994 年撰写。这项工作既没有定义标准也没有协议，而是确定了多年来被证明有用的常见通用软件设计。本书讨论的模式通常被认为属于三类：创建型、结构型和行为型。

这本书中已经介绍了许多这些模式的例子。以下是一个简要总结：

| 设计模式 | 章节 | 食谱 |
| --- | --- | --- |
| 单例 | 2 | 定义可见性 |
| 工厂 | 6 | 实施表单工厂 |
| 适配器 | 8 | 处理没有`gettext（）`的翻译 |
| 代理 | 7 | 创建一个简单的 REST 客户端创建一个简单的 SOAP 客户端 |
| 迭代器 | 23 | 递归目录迭代器使用迭代器 |

在本章中，我们将研究一些额外的设计模式，主要关注并发和架构模式。

# 创建数组到对象的水合物

**水合物**模式是**数据传输对象**设计模式的一种变体。它的设计原则非常简单：将数据从一个地方移动到另一个地方。在这个示例中，我们将定义类来将数据从数组移动到对象。

## 如何做...

1.  首先，我们定义一个能够使用 getter 和 setter 的`Hydrator`类。为了说明这一点，我们将使用`Application\Generic\Hydrator\GetSet`： 

```php
namespace Application\Generic\Hydrator;
class GetSet
{
  // code
}
```

1.  接下来，我们定义一个“hydrate（）”方法，它接受数组和对象作为参数。然后调用对象上的“setXXX（）”方法，以从数组中填充它的值。我们使用“get_class（）”来确定对象的类，然后使用“get_class_methods（）”来获取所有方法的列表。“preg_match（）”用于匹配方法前缀及其后缀，随后假定为数组键：

```php
public static function hydrate(array $array, $object)
{
  $class = get_class($object);
  $methodList = get_class_methods($class);
  foreach ($methodList as $method) {
    preg_match('/^(set)(.*?)$/i', $method, $matches);
    $prefix = $matches[1] ?? '';
    $key    = $matches[2] ?? '';
    $key    = strtolower(substr($key, 0, 1)) . substr($key, 1);
    if ($prefix == 'set' && !empty($array[$key])) {
        $object->$method($array[$key]);
    }
  }
  return $object;
}
```

## 工作原理...

为了演示如何使用数组到水合物对象，首先按照*如何做...*部分中的说明定义`Application\Generic\Hydrator\GetSet`类。接下来，定义一个实体类，用于测试这个概念。为了本示例，创建一个`Application\Entity\Person`类，具有适当的属性和方法。确保为所有属性定义 getter 和 setter。这里没有显示所有这样的方法：

```php
namespace Application\Entity;
class Person
{
  protected $firstName  = '';
  protected $lastName   = '';
  protected $address    = '';
  protected $city       = '';
  protected $stateProv  = '';
  protected $postalCode = '';
  protected $country    = '';

  public function getFirstName()
  {
    return $this->firstName;
  }

  public function setFirstName($firstName)
  {
    $this->firstName = $firstName;
  }

  // etc.
}
```

现在可以创建一个名为`chap_11_array_to_object.php`的调用程序，设置自动加载，并使用适当的类：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Entity\Person;
use Application\Generic\Hydrator\GetSet;
```

接下来，您可以定义一个测试数组，其中包含将添加到新的`Person`实例中的值：

```php
$a['firstName'] = 'Li\'l Abner';
$a['lastName']  = 'Yokum';
$a['address']   = '1 Dirt Street';
$a['city']      = 'Dogpatch';
$a['stateProv'] = 'Kentucky';
$a['postalCode']= '12345';
$a['country']   = 'USA';
```

现在可以以静态方式调用`hydrate（）`和`extract（）`：

```php
$b = GetSet::hydrate($a, new Person());
var_dump($b);
```

结果显示在以下屏幕截图中：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_11_01.jpg)

# 构建对象到数组的水合物

这个食谱是*创建数组到对象的水合物*食谱的相反。在这种情况下，我们需要从对象属性中提取值，并返回一个关联数组，其中键将是列名。

## 如何做...

1.  为了说明这一点，我们将在前一篇中定义的`Application\Generic\Hydrator\GetSet`类的基础上进行构建：

```php
namespace Application\Generic\Hydrator;
class GetSet
{
  // code
}
```

1.  在前一篇中定义的`hydrate（）`方法之后，我们定义了一个`extract（）`方法，它以对象作为参数。逻辑与`hydrate（）`使用的逻辑类似，只是这次我们要搜索`getXXX（）`方法。同样，使用`preg_match（）`来匹配方法前缀及其后缀，随后假定为数组键：

```php
public static function extract($object)
{
  $array = array();
  $class = get_class($object);
  $methodList = get_class_methods($class);
  foreach ($methodList as $method) {
    preg_match('/^(get)(.*?)$/i', $method, $matches);
    $prefix = $matches[1] ?? '';
    $key    = $matches[2] ?? '';
    $key    = strtolower(substr($key, 0, 1)) . substr($key, 1);
    if ($prefix == 'get') {
      $array[$key] = $object->$method();
    }
  }
  return $array;
}
}
```

### 注意

棘手的部分是弄清楚选择哪种填充策略。为此，我们定义了`chooseStrategy()`，它以对象作为参数。我们首先通过获取类方法列表来进行一些侦探工作。然后我们扫描列表，看看是否有任何`getXXX()`或`setXXX()`方法。如果有，我们选择`GetSet`填充器作为我们选择的策略：

## 它是如何工作的...

定义一个名为`chap_11_object_to_array.php`的调用程序，设置自动加载，并使用适当的类：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Entity\Person;
use Application\Generic\Hydrator\GetSet;
```

我们还添加了一个`addStrategy()`方法，允许我们覆盖或添加新的策略，而无需重新编写类：

```php
$obj = new Person();
$obj->setFirstName('Li\'lAbner');
$obj->setLastName('Yokum');
$obj->setAddress('1DirtStreet');
$obj->setCity('Dogpatch');
$obj->setStateProv('Kentucky');
$obj->setPostalCode('12345');
$obj->setCountry('USA');
```

通常情况下，运行时条件会迫使开发人员定义多种解决同一问题的方式。传统上，这涉及到一个庞大的`if/elseif/else`命令块。然后，您要么必须在`if`语句内定义大块逻辑，要么创建一系列函数或方法来实现不同的方法。策略模式试图通过使主类封装一系列代表解决同一问题的不同方法的子类来规范化这个过程。

```php
$a = GetSet::extract($obj);
var_dump($a);
```

输出如下：

请注意，我们已将`hydrate()`和`extract()`定义为静态方法，以方便使用。

# 实施策略模式

我们首先定义反映可用内置策略的类常量：

## 接下来，定义一个`Person`的实例，为其属性设置值：

1.  在这个示例中，我们将使用之前定义的`GetSet`填充器类作为策略。我们将定义一个主要的`Application\Generic\Hydrator\Any`类，然后在`Application\Generic\Hydrator\Strategy`命名空间中使用策略类，包括`GetSet`、`PublicProps`和`Extending`。

1.  以下是输出的截图：

```php
namespace Application\Generic\Hydrator;
use InvalidArgumentException;
use Application\Generic\Hydrator\Strategy\ { 
GetSet, PublicProps, Extending };
class Any
{
  const STRATEGY_PUBLIC  = 'PublicProps';
  const STRATEGY_GET_SET = 'GetSet';
  const STRATEGY_EXTEND  = 'Extending';
  protected $strategies;
  public $chosen;
```

1.  在新的命名空间中，我们定义一个接口，允许我们识别任何可以被`Application\Generic\Hydrator\Any`消耗的策略：

```php
public function __construct()
{
  $this->strategies[self::STRATEGY_GET_SET] = new GetSet();
  $this->strategies[self::STRATEGY_PUBLIC] = new PublicProps();
  $this->strategies[self::STRATEGY_EXTEND] = new Extending();
}
```

1.  `hydrate()`方法是最困难的，因为我们假设没有定义 getter 或 setter，也没有使用`public`可见级别定义属性。因此，我们需要定义一个扩展要被填充的对象类的类。我们首先定义一个字符串，将用作构建新类的模板：

```php
public function addStrategy($key, HydratorInterface $strategy)
{
  $this->strategies[$key] = $strategy;
}
```

1.  `hydrate()`和`extract()`方法只是调用所选择策略的方法：

```php
public function hydrate(array $array, $object)
{
  $strategy = $this->chooseStrategy($object);
  $this->chosen = get_class($strategy);
  return $strategy::hydrate($array, $object);
}

public function extract($object)
{
  $strategy = $this->chooseStrategy($object);
  $this->chosen = get_class($strategy);
  return $strategy::extract($object);
}
```

1.  现在我们将注意力转向策略本身。首先，我们定义一个新的`Application\Generic\Hydrator\Strategy`命名空间。

```php
public function chooseStrategy($object)
{
  $strategy = NULL;
  $methodList = get_class_methods(get_class($object));
  if (!empty($methodList) && is_array($methodList)) {
      $getSet = FALSE;
      foreach ($methodList as $method) {
        if (preg_match('/^get|set.*$/i', $method)) {
            $strategy = $this->strategies[self::STRATEGY_GET_SET];
      break;
    }
  }
}
```

1.  在我们的`chooseStrategy()`方法中，如果没有 getter 或 setter，我们接下来使用`get_class_vars()`来确定是否有任何可用的属性。如果有，我们选择`PublicProps`作为我们的填充器：

```php
if (!$strategy) {
    $vars = get_class_vars(get_class($object));
    if (!empty($vars) && count($vars)) {
        $strategy = $this->strategies[self::STRATEGY_PUBLIC];
    }
}
```

1.  如果一切都失败了，我们将退回到`Extending`填充器，它返回一个简单地扩展对象类的新类，从而使任何`public`或`protected`属性可用：

```php
if (!$strategy) {
    $strategy = $this->strategies[self::STRATEGY_EXTEND];
}
return $strategy;
}
}
```

1.  然后，我们定义一个构造函数，将所有内置策略添加到`$strategies`属性中：

1.  如何做...

```php
namespace Application\Generic\Hydrator\Strategy;
interface HydratorInterface
{
  public static function hydrate(array $array, $object);
  public static function extract($object);
}
```

1.  `GetSet`填充器与前两个示例中定义的完全相同，唯一的添加是它将实现新的接口：

```php
namespace Application\Generic\Hydrator\Strategy;
class GetSet implements HydratorInterface
{

  public static function hydrate(array $array, $object)
  {
    // defined in the recipe:
    // "Creating an Array to Object Hydrator"
  }

  public static function extract($object)
  {
    // defined in the recipe:
    // "Building an Object to Array Hydrator"
  }
}
```

1.  下一个填充器只是读取和写入公共属性：

```php
namespace Application\Generic\Hydrator\Strategy;
class PublicProps implements HydratorInterface
{
  public static function hydrate(array $array, $object)
  {
    $propertyList= array_keys(
      get_class_vars(get_class($object)));
    foreach ($propertyList as $property) {
      $object->$property = $array[$property] ?? NULL;
    }
    return $object;
  }

  public static function extract($object)
  {
    $array = array();
    $propertyList = array_keys(
      get_class_vars(get_class($object)));
    foreach ($propertyList as $property) {
      $array[$property] = $object->$property;
    }
    return $array;
  }
}
```

1.  最后，`Extending`，填充器的瑞士军刀，扩展了对象类，从而直接访问属性。我们进一步定义了魔术 getter 和 setter，以提供对属性的访问。

1.  最后，以静态方式调用新的`extract()`方法：

```php
namespace Application\Generic\Hydrator\Strategy;
class Extending implements HydratorInterface
{
  const UNDEFINED_PREFIX = 'undefined';
  const TEMP_PREFIX = 'TEMP_';
  const ERROR_EVAL = 'ERROR: unable to evaluate object';
  public static function hydrate(array $array, $object)
  {
    $className = get_class($object);
    $components = explode('\\', $className);
    $realClass  = array_pop($components);
    $nameSpace  = implode('\\', $components);
    $tempClass = $realClass . self::TEMP_SUFFIX;
    $template = 'namespace ' 
      . $nameSpace . '{'
      . 'class ' . $tempClass 
      . ' extends ' . $realClass . ' '
```

1.  在`hydrate()`方法中，我们定义了一个`$values`属性和一个将要被填充到对象中的数组的构造函数。我们循环遍历值数组，将值分配给属性。我们还定义了一个有用的`getArrayCopy()`方法，如果需要，返回这些值，以及一个模拟直接属性访问的魔术`__get()`方法：

```php
. '{ '
. '  protected $values; '
. '  public function __construct($array) '
. '  { $this->values = $array; '
. '    foreach ($array as $key => $value) '
. '       $this->$key = $value; '
. '  } '
. '  public function getArrayCopy() '
. '  { return $this->values; } '
```

1.  为方便起见，我们定义了一个魔术`__get()`方法，模拟直接变量访问，就像它们是公共的一样：

```php
. '  public function __get($key) '
. '  { return $this->values[$key] ?? NULL; } '
```

1.  在新类的模板中，我们还定义了一个魔术`__call()`方法，模拟 getter 和 setter：

```php
. '  public function __call($method, $params) '
. '  { '
. '    preg_match("/^(get|set)(.*?)$/i", '
. '        $method, $matches); '
. '    $prefix = $matches[1] ?? ""; '
. '    $key    = $matches[2] ?? ""; '
. '    $key    = strtolower(substr($key, 0, 1)) ' 
. '              substr($key, 1); '
. '    if ($prefix == "get") { '
. '        return $this->values[$key] ?? NULL; '
. '     } else { '
. '        $this->values[$key] = $params[0]; '
. '     } '
. '  } '
. '} '
. '} // ends namespace ' . PHP_EOL
```

1.  最后，在新类的模板中，我们添加一个函数，在全局命名空间中构建并返回类实例：

```php
. 'namespace { '
. 'function build($array) '
. '{ return new ' . $nameSpace . '\\' 
.    $tempClass . '($array); } '
. '} // ends global namespace '
. PHP_EOL;
```

1.  仍然在`hydrate()`方法中，我们使用`eval()`执行完成的模板。然后运行刚在模板末尾定义的`build()`方法。请注意，由于我们不确定要填充的类的命名空间，我们从全局命名空间中定义和调用`build()`：

```php
try {
    eval($template);
} catch (ParseError $e) {
    error_log(__METHOD__ . ':' . $e->getMessage());
    throw new Exception(self::ERROR_EVAL);
}
return \build($array);
}
```

1.  `extract()`方法更容易定义，因为我们的选择非常有限。通过魔术方法扩展类并从数组中填充它很容易实现。反之则不然。如果我们扩展类，我们将丢失所有属性值，因为我们扩展的是类，而不是对象实例。因此，我们唯一的选择是使用 getter 和公共属性的组合：

```php
public static function extract($object)
{
  $array = array();
  $class = get_class($object);
  $methodList = get_class_methods($class);
  foreach ($methodList as $method) {
    preg_match('/^(get)(.*?)$/i', $method, $matches);
    $prefix = $matches[1] ?? '';
    $key    = $matches[2] ?? '';
    $key    = strtolower(substr($key, 0, 1)) 
    . substr($key, 1);
    if ($prefix == 'get') {
        $array[$key] = $object->$method();
    }
  }
  $propertyList= array_keys(get_class_vars($class));
  foreach ($propertyList as $property) {
    $array[$property] = $object->$property;
  }
  return $array;
  }
}
```

## 它是如何工作的...

您可以首先定义三个具有相同属性的测试类：`firstName`，`lastName`等。第一个`Person`应该有受保护的属性以及 getter 和 setter。第二个`PublicPerson`将具有公共属性。第三个`ProtectedPerson`具有受保护的属性，但没有 getter 或 setter：

```php
<?php
namespace Application\Entity;
class Person
{
  protected $firstName  = '';
  protected $lastName   = '';
  protected $address    = '';
  protected $city       = '';
  protected $stateProv  = '';
  protected $postalCode = '';
  protected $country    = '';

    public function getFirstName()
    {
      return $this->firstName;
    }

    public function setFirstName($firstName)
    {
      $this->firstName = $firstName;
    }

  // be sure to define remaining getters and setters

}

<?php
namespace Application\Entity;
class PublicPerson
{
  private $id = NULL;
  public $firstName  = '';
  public $lastName   = '';
  public $address    = '';
  public $city       = '';
  public $stateProv  = '';
  public $postalCode = '';
  public $country    = '';
}

<?php
namespace Application\Entity;

class ProtectedPerson
{
  private $id = NULL;
  protected $firstName  = '';
  protected $lastName   = '';
  protected $address    = '';
  protected $city       = '';
  protected $stateProv  = '';
  protected $postalCode = '';
  protected $country    = '';
}
```

现在，您可以定义一个名为`chap_11_strategy_pattern.php`的调用程序，该程序设置自动加载并使用适当的类：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Entity\ { Person, PublicPerson, ProtectedPerson };
use Application\Generic\Hydrator\Any;
use Application\Generic\Hydrator\Strategy\ { GetSet, Extending, PublicProps };
```

接下来，创建一个`Person`的实例，并运行 setter 来定义属性的值：

```php
$obj = new Person();
$obj->setFirstName('Li\'lAbner');
$obj->setLastName('Yokum');
$obj->setAddress('1 Dirt Street');
$obj->setCity('Dogpatch');
$obj->setStateProv('Kentucky');
$obj->setPostalCode('12345');
$obj->setCountry('USA');
```

接下来，创建`Any`水合剂的实例，调用`extract()`，并使用`var_dump()`查看结果：

```php
$hydrator = new Any();
$b = $hydrator->extract($obj);
echo "\nChosen Strategy: " . $hydrator->chosen . "\n";
var_dump($b);
```

请注意，在以下输出中，选择了`GetSet`策略：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_11_03.jpg)

### 注意

请注意，`id`属性未设置，因为它的可见性级别是`private`。

接下来，您可以定义一个具有相同值的数组。在`Any`实例上调用`hydrate()`，并提供一个新的`PublicPerson`实例作为参数：

```php
$a = [
  'firstName'  => 'Li\'lAbner',
  'lastName'   => 'Yokum',
  'address'    => '1 Dirt Street',
  'city'       => 'Dogpatch',
  'stateProv'  => 'Kentucky',
  'postalCode' => '12345',
  'country'    => 'USA'
];

$p = $hydrator->hydrate($a, new PublicPerson());
echo "\nChosen Strategy: " . $hydrator->chosen . "\n";
var_dump($p);
```

这是结果。请注意，这种情况下选择了`PublicProps`策略：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_11_04.jpg)

最后，再次调用`hydrate()`，但这次提供一个`ProtectedPerson`的实例作为对象参数。然后我们调用`getFirstName()`和`getLastName()`来测试魔术 getter。我们还以直接变量访问的方式访问名字和姓氏：

```php
$q = $hydrator->hydrate($a, new ProtectedPerson());
echo "\nChosen Strategy: " . $hydrator->chosen . "\n";
echo "Name: {$q->getFirstName()} {$q->getLastName()}\n";
echo "Name: {$q->firstName} {$q->lastName}\n";
var_dump($q);
```

这是最后的输出，显示选择了`Extending`策略。您还会注意到实例是一个新的`ProtectedPerson_TEMP`类，并且受保护的属性已完全填充：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_11_05.jpg)

# 定义一个映射器

**映射器**或**数据映射器**的工作方式与水合剂类似：将数据从一个模型（数组或对象）转换为另一个模型。一个关键的区别是，水合剂是通用的，不需要预先编程对象属性名称，而映射器则相反：它需要精确的属性名称信息来定义两个模型。在这个示例中，我们将演示使用映射器将数据从一个数据库表转换为另一个数据库表。

## 如何做...

1.  我们首先定义一个`Application\Database\Mapper\FieldConfig`类，其中包含单个字段的映射指令。我们还定义适当的类常量：

```php
namespace Application\Database\Mapper;
use InvalidArgumentException;
class FieldConfig
{
  const ERROR_SOURCE = 
    'ERROR: need to specify destTable and/or source';
  const ERROR_DEST   = 'ERROR: need to specify either '
    . 'both destTable and destCol or neither';
```

1.  关键属性与适当的类常量一起定义。`$key`用于标识对象。`$source`表示源数据库表中的列。`$destTable`和`$destCol`表示目标数据库表和列。如果定义了`$default`，则包含默认值或产生适当值的回调：

```php
public $key;
public $source;
public $destTable;
public $destCol;
public $default;
```

1.  现在我们转向构造函数，它分配默认值，构建密钥，并检查`$source`或`$destTable`和`$destCol`是否已定义：

```php
public function __construct($source = NULL,
                            $destTable = NULL,
                            $destCol   = NULL,
                            $default   = NULL)
{
  // generate key from source + destTable + destCol
  $this->key = $source . '.' . $destTable . '.' . $destCol;
  $this->source = $source;
  $this->destTable = $destTable;
  $this->destCol = $destCol;
  $this->default = $default;
  if (($destTable && !$destCol) || 
      (!$destTable && $destCol)) {
      throw new InvalidArgumentException(self::ERROR_DEST);
  }
  if (!$destTable && !$source) {
      throw new InvalidArgumentException(
        self::ERROR_SOURCE);
  }
}
```

### 注意

请注意，我们允许源列和目标列为空。这是因为我们可能有一个源列在目标表中没有位置。同样，目标表中可能有强制列，在源表中没有表示。

1.  在默认值的情况下，我们需要检查值是否是一个回调。如果是，我们运行回调；否则，我们返回直接值。请注意，回调应该被定义为接受数据库表行作为参数：

```php
public function getDefault()
{
  if (is_callable($this->default)) {
      return call_user_func($this->default, $row);
  } else {
      return $this->default;
  }
}
```

1.  最后，为了完成这个类，我们为这五个属性定义了 getter 和 setter：

```php
public function getKey()
{
  return $this->key;
}

public function setKey($key)
{
  $this->key = $key;
}

// etc.
```

1.  接下来，我们定义一个`Application\Database\Mapper\Mapping`映射类，它接受源表和目标表的名称，以及一个`FieldConfig`对象数组作为参数。您将看到我们允许目标表属性为数组，因为映射可能是到两个或更多目标表：

```php
namespace Application\Database\Mapper;
class Mapping
{
  protected $sourceTable;
  protected $destTable;
  protected $fields;
  protected $sourceCols;
  protected $destCols;

  public function __construct(
    $sourceTable, $destTable, $fields = NULL)
  {
    $this->sourceTable = $sourceTable;
    $this->destTable = $destTable;
    $this->fields = $fields;
  }
```

1.  然后我们为这些属性定义 getter 和 setter：

```php
public function getSourceTable()
{
  return $this->sourceTable;
}
public function setSourceTable($sourceTable)
{
  $this->sourceTable = $sourceTable;
}
// etc.
```

1.  对于字段配置，我们还需要提供添加单个字段的能力。无需提供键作为单独的参数，因为这可以从`FieldConfig`实例中获取：

```php
public function addField(FieldConfig $field)
{
  $this->fields[$field->getKey()] = $field;
  return $this;
}
```

1.  获取源列名的数组非常重要。问题在于源列名是`FieldConfig`对象中的一个属性。因此，当调用这个方法时，我们循环遍历`FieldConfig`对象数组，并在每个对象上调用`getSource()`来获取源列名：

```php
public function getSourceColumns()
{
  if (!$this->sourceCols) {
      $this->sourceCols = array();
      foreach ($this->getFields() as $field) {
        if (!empty($field->getSource())) {
            $this->sourceCols[$field->getKey()] = 
              $field->getSource();
        }
      }
  }
  return $this->sourceCols;
}
```

1.  我们对`getDestColumns()`使用了类似的方法。与获取源列列表相比的一个重大区别是，我们只想要一个特定目标表的列，如果定义了多个这样的表，这一点至关重要。我们不需要检查`$destCol`是否设置，因为这已经在`FieldConfig`的构造函数中处理了：

```php
public function getDestColumns($table)
{
  if (empty($this->destCols[$table])) {
      foreach ($this->getFields() as $field) {
        if ($field->getDestTable()) {
          if ($field->getDestTable() == $table) {
              $this->destCols[$table][$field->getKey()] = 
                $field->getDestCol();
          }
        }
      }
  }
  return $this->destCols[$table];
}
```

1.  最后，我们定义一个方法，它的第一个参数是表示来自源表的一行数据的数组。第二个参数是目标表的名称。该方法生成一个准备插入到目标表中的数据数组。

1.  我们必须做出一个决定，哪个优先级更高：默认值（可以由回调提供）还是来自源表的数据。我们决定首先测试默认值。如果默认值返回`NULL`，则使用来自源表的数据。请注意，如果需要进一步处理，默认值应该被定义为回调。

```php
public function mapData($sourceData, $destTable)
{
  $dest = array();
  foreach ($this->fields as $field) {
    if ($field->getDestTable() == $destTable) {
        $dest[$field->getDestCol()] = NULL;
        $default = $field->getDefault($sourceData);
        if ($default) {
            $dest[$field->getDestCol()] = $default;
        } else {
            $dest[$field->getDestCol()] = 
                  $sourceData[$field->getSource()];
        }
    }
  }
  return $dest;
}
}
```

### 注意

请注意，目标插入中会出现一些在源行中不存在的列。在这种情况下，`FieldConfig`对象的`$source`属性被留空，然后提供一个默认值，可以是标量值或回调函数。

1.  现在我们准备定义两个方法来生成 SQL。第一个方法将生成一个 SQL 语句，用于从源表中读取数据。该语句将包括要准备的占位符（例如，使用`PDO::prepare()`）：

```php
public function getSourceSelect($where = NULL)
{
  $sql = 'SELECT ' 
  . implode(',', $this->getSourceColumns()) . ' ';
  $sql .= 'FROM ' . $this->getSourceTable() . ' ';
  if ($where) {
    $where = trim($where);
    if (stripos($where, 'WHERE') !== FALSE) {
        $sql .= $where;
    } else {
        $sql .= 'WHERE ' . $where;
    }
  }
  return trim($sql);
}
```

1.  另一个 SQL 生成方法生成一个要为特定目标表准备的语句。请注意，占位符与列名相同，前面加上“`:`”：

```php
public function getDestInsert($table)
{
  $sql = 'INSERT INTO ' . $table . ' ';
  $sql .= '( ' 
  . implode(',', $this->getDestColumns($table)) 
  . ' ) ';
  $sql .= ' VALUES ';
  $sql .= '( :' 
  . implode(',:', $this->getDestColumns($table)) 
  . ' ) ';
  return trim($sql);
}
```

## 工作原理...

使用步骤 1 到 5 中显示的代码生成一个`Application\Database\Mapper\FieldConfig`类。将步骤 6 到 14 中显示的代码放入第二个`Application\Database\Mapper\Mapping`类中。

在定义执行映射的调用程序之前，重要的是考虑源和目标数据库表。源表`prospects_11`的定义如下：

```php
CREATE TABLE `prospects_11` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `first_name` varchar(128) NOT NULL,
  `last_name` varchar(128) NOT NULL,
  `address` varchar(256) DEFAULT NULL,
  `city` varchar(64) DEFAULT NULL,
  `state_province` varchar(32) DEFAULT NULL,
  `postal_code` char(16) NOT NULL,
  `phone` varchar(16) NOT NULL,
  `country` char(2) NOT NULL,
  `email` varchar(250) NOT NULL,
  `status` char(8) DEFAULT NULL,
  `budget` decimal(10,2) DEFAULT NULL,
  `last_updated` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UNIQ_35730C06E7927C74` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```

在这个例子中，您可以使用两个目标表，`customer_11`和`profile_11`，它们之间存在 1:1 的关系：

```php
CREATE TABLE `customer_11` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(256) CHARACTER SET latin1 
     COLLATE latin1_general_cs NOT NULL,
  `balance` decimal(10,2) NOT NULL,
  `email` varchar(250) NOT NULL,
  `password` char(16) NOT NULL,
  `status` int(10) unsigned NOT NULL DEFAULT '0',
  `security_question` varchar(250) DEFAULT NULL,
  `confirm_code` varchar(32) DEFAULT NULL,
  `profile_id` int(11) DEFAULT NULL,
  `level` char(3) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UNIQ_81398E09E7927C74` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=80 DEFAULT CHARSET=utf8 COMMENT='Customers';

CREATE TABLE `profile_11` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `address` varchar(256) NOT NULL,
  `city` varchar(64) NOT NULL,
  `state_province` varchar(32) NOT NULL,
  `postal_code` varchar(10) NOT NULL,
  `country` varchar(3) NOT NULL,
  `phone` varchar(16) NOT NULL,
  `photo` varchar(128) NOT NULL,
  `dob` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=80 DEFAULT CHARSET=utf8 COMMENT='Customers';
```

现在可以定义一个名为`chap_11_mapper.php`的调用程序，设置自动加载并使用前面提到的两个类。还可以使用第五章中定义的`Connection`类，*与数据库交互*：

```php
<?php
define('DB_CONFIG_FILE', '/../config/db.config.php');
define('DEFAULT_PHOTO', 'person.gif');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Database\Mapper\ { FieldConfig, Mapping };
use Application\Database\Connection;
$conn = new Connection(include __DIR__ . DB_CONFIG_FILE);
```

为了演示目的，在确保两个目标表存在后，可以清空这两个表，以确保显示的任何数据都是干净的：

```php
$conn->pdo->query('DELETE FROM customer_11');
$conn->pdo->query('DELETE FROM profile_11');
```

现在可以构建`Mapping`实例并用`FieldConfig`对象填充它。每个`FieldConfig`对象表示源和目标之间的映射。在构造函数中，以数组形式提供源表的名称和两个目标表的名称：

```php
$mapper = new Mapping('prospects_11', ['customer_11','profile_11']);
```

可以从`prospects_11`到`customer_11`之间简单地进行字段映射，其中没有默认值：

```php
$mapper>addField(new FieldConfig('email','customer_11','email'))
```

请注意，`addField()`返回当前的映射实例，因此无需不断指定`$mapper->addField()`。这种技术被称为**流畅接口**。

名称字段比较棘手，在`prospects_11`表中由两列表示，但在`customer_11`表中只有一列。因此，您可以添加一个回调作为`first_name`的默认值，将这两个字段合并为一个。您还需要为`last_name`定义一个条目，但没有目标映射：

```php
->addField(new FieldConfig('first_name','customer_11','name',
  function ($row) { return trim(($row['first_name'] ?? '') 
. ' ' .  ($row['last_name'] ?? ''));}))
->addField(new FieldConfig('last_name'))
```

`customer_11::status`字段可以使用空值合并运算符(`??`)来确定是否已设置：

```php
->addField(new FieldConfig('status','customer_11','status',
  function ($row) { return $row['status'] ?? 'Unknown'; }))
```

`customer_11::level`字段在源表中没有表示，因此可以为源字段创建一个`NULL`条目，但确保设置了目标表和列。同样，`customer_11::password`在源表中也不存在。在这种情况下，回调使用电话号码作为临时密码：

```php
->addField(new FieldConfig(NULL,'customer_11','level','BEG'))
->addField(new FieldConfig(NULL,'customer_11','password',
  function ($row) { return $row['phone']; }))
```

还可以将`prospects_11`到`profile_11`的映射设置如下。请注意，由于源照片和出生日期列在`prospects_11`中不存在，因此可以设置任何适当的默认值：

```php
->addField(new FieldConfig('address','profile_11','address'))
->addField(new FieldConfig('city','profile_11','city'))
->addField(new FieldConfig('state_province','profile_11', 
'state_province', function ($row) { 
  return $row['state_province'] ?? 'Unknown'; }))
->addField(new FieldConfig('postal_code','profile_11',
'postal_code'))
->addField(new FieldConfig('phone','profile_11','phone'))
->addField(new FieldConfig('country','profile_11','country'))
->addField(new FieldConfig(NULL,'profile_11','photo',
DEFAULT_PHOTO))
->addField(new FieldConfig(NULL,'profile_11','dob',
date('Y-m-d')));
```

为了建立`profile_11`和`customer_11`表之间的 1:1 关系，我们使用回调将`customer_11::id`、`customer_11::profile_id`和`profile_11::id`的值设置为`$row['id']`的值：

```php
$idCallback = function ($row) { return $row['id']; };
$mapper->addField(new FieldConfig('id','customer_11','id',
$idCallback))
->addField(new FieldConfig(NULL,'customer_11','profile_id',
$idCallback))
->addField(new FieldConfig('id','profile_11','id',$idCallback));
```

现在可以调用适当的方法生成三个 SQL 语句，一个用于从源表中读取数据，另外两个用于插入到两个目标表中：

```php
$sourceSelect  = $mapper->getSourceSelect();
$custInsert    = $mapper->getDestInsert('customer_11');
$profileInsert = $mapper->getDestInsert('profile_11');
```

这三个语句可以立即准备好以供以后执行：

```php
$sourceStmt  = $conn->pdo->prepare($sourceSelect);
$custStmt    = $conn->pdo->prepare($custInsert);
$profileStmt = $conn->pdo->prepare($profileInsert);
```

然后执行`SELECT`语句，从源表中生成行。然后在循环中为每个目标表生成`INSERT`数据，并执行适当的预处理语句：

```php
$sourceStmt->execute();
while ($row = $sourceStmt->fetch(PDO::FETCH_ASSOC)) {
  $custData = $mapper->mapData($row, 'customer_11');
  $custStmt->execute($custData);
  $profileData = $mapper->mapData($row, 'profile_11');
  $profileStmt->execute($profileData);
  echo "Processing: {$custData['name']}\n";
}
```

以下是生成的三个 SQL 语句：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_11_06.jpg)

然后可以使用 SQL `JOIN`直接从数据库中查看数据，以确保关系已经保持：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_11_07.jpg)

# 实现对象关系映射

有两种主要技术可以实现对象之间的关系映射。第一种技术涉及将相关的子对象预先加载到父对象中。这种方法的优势在于易于实现，并且所有父子信息都可以立即使用。缺点是可能会消耗大量内存，并且性能曲线会被扭曲。

第二种技术是将次要查找嵌入到父对象中。在后一种方法中，当需要访问子对象时，可以运行一个 getter 来执行次要查找。这种方法的优势在于性能需求在请求周期内得到了分散，并且内存使用更容易管理。这种方法的缺点是会生成更多的查询，这意味着对数据库服务器的更多工作。

### 请注意

然而，请注意，我们将展示如何使用**预处理语句**来大大抵消这种劣势。

## 如何做…

让我们看一下实现对象关系映射的两种技术。

### 技术＃1-预加载所有子信息

首先，我们将讨论如何通过预加载所有子信息到父类中来实现对象关系映射。对于此示例，我们将使用与三个相关数据库表`customer`，`purchases`和`products`对应的实体类定义：

1.  我们将使用现有的`Application\Entity\Customer`类（在第五章中定义，*与数据库交互*，在*定义实体类以匹配数据库表的方法*中）作为开发`Application\Entity\Purchase`类的模型。与以前一样，我们将使用数据库定义作为实体类定义的基础。以下是`purchases`表的数据库定义：

```php
CREATE TABLE `purchases` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `transaction` varchar(8) NOT NULL,
  `date` datetime NOT NULL,
  `quantity` int(10) unsigned NOT NULL,
  `sale_price` decimal(8,2) NOT NULL,
  `customer_id` int(11) DEFAULT NULL,
  `product_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `IDX_C3F3` (`customer_id`),
  KEY `IDX_665A` (`product_id`),
  CONSTRAINT `FK_665A` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`),
  CONSTRAINT `FK_C3F3` FOREIGN KEY (`customer_id`) REFERENCES `customer` (`id`)
);
```

1.  根据客户实体类，`Application\Entity\Purchase`可能如下所示。请注意，未显示所有的 getter 和 setter：

```php
namespace Application\Entity;

class Purchase extends Base
{

  const TABLE_NAME = 'purchases';
  protected $transaction = '';
  protected $date = NULL;
  protected $quantity = 0;
  protected $salePrice = 0.0;
  protected $customerId = 0;
  protected $productId = 0;

  protected $mapping = [
    'id'            => 'id',
    'transaction'   => 'transaction',
    'date'          => 'date',
    'quantity'      => 'quantity',
    'sale_price'    => 'salePrice',
    'customer_id'   => 'customerId',
    'product_id'    => 'productId',
  ];

  public function getTransaction() : string
  {
    return $this->transaction;
  }
  public function setTransaction($transaction)
  {
    $this->transaction = $transaction;
  }
  // NOTE: other getters / setters are not shown here
}
```

1.  现在我们准备定义`Application\Entity\Product`。以下是`products`表的数据库定义：

```php
CREATE TABLE `products` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sku` varchar(16) DEFAULT NULL,
  `title` varchar(255) NOT NULL,
  `description` varchar(4096) DEFAULT NULL,
  `price` decimal(10,2) NOT NULL,
  `special` int(11) NOT NULL,
  `link` varchar(128) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UNIQ_38C4` (`sku`)
);
```

1.  根据客户实体类，`Application\Entity\Product`可能如下所示：

```php
namespace Application\Entity;

class Product extends Base
{

  const TABLE_NAME = 'products';
  protected $sku = '';
  protected $title = '';
  protected $description = '';
  protected $price = 0.0;
  protected $special = 0;
  protected $link = '';

  protected $mapping = [
    'id'          => 'id',
    'sku'         => 'sku',
    'title'       => 'title',
    'description' => 'description',
    'price'       => 'price',
    'special'     => 'special',
    'link'        => 'link',
  ];

  public function getSku() : string
  {
    return $this->sku;
  }
  public function setSku($sku)
  {
    $this->sku = $sku;
  }
  // NOTE: other getters / setters are not shown here
}
```

1.  接下来，我们需要实现一种嵌入相关对象的方法。我们将从`Application\Entity\Customer`父类开始。在本节中，我们将假设以下关系，如下图所示：

+   一个客户，多个购买

+   一个购买，一个产品

![技术＃1-预加载所有子信息](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_11_08.jpg)

1.  因此，我们定义了一个处理购买的 getter 和 setter，以对象数组的形式进行处理：

```php
protected $purchases = array();
public function addPurchase($purchase)
{
  $this->purchases[] = $purchase;
}
public function getPurchases()
{
  return $this->purchases;
}
```

1.  现在我们将注意力转向`Application\Entity\Purchase`。在这种情况下，购买和产品之间存在 1：1 的关系，因此无需处理数组：

```php
protected $product = NULL;
public function getProduct()
{
  return $this->product;
}
public function setProduct(Product $product)
{
  $this->product = $product;
}
```

### 注意

请注意，在两个实体类中，我们不会更改`$mapping`数组。这是因为实现对象关系映射对实体属性名称和数据库列名称之间的映射没有影响。

1.  由于仍然需要获取基本客户信息的核心功能，我们只需要扩展第五章中描述的`Application\Database\CustomerService`类，*与数据库交互*，在*将实体类与 RDBMS 查询绑定*中。我们可以创建一个新的`Application\Database\CustomerOrmService_1`类，它扩展了`Application\Database\CustomerService`：

```php
namespace Application\Database;
use PDO;
use PDOException;
use Application\Entity\Customer;
use Application\Entity\Product;
use Application\Entity\Purchase;
class CustomerOrmService_1 extends CustomerService
{
  // add methods here
}
```

1.  然后，我们向新的服务类添加一个方法，该方法执行查找并将结果嵌入到核心客户实体中，以`Product`和`Purchase`实体的形式。此方法执行`JOIN`形式的查找。这是可能的，因为购买和产品之间存在 1：1 的关系。因为`id`列在两个表中的名称相同，所以我们需要将购买 ID 列添加为别名。然后，我们遍历结果，创建`Product`和`Purchase`实体。在覆盖 ID 之后，我们可以将`Product`实体嵌入`Purchase`实体中，然后将`Purchase`实体添加到`Customer`实体中的数组中：

```php
protected function fetchPurchasesForCustomer(Customer $cust)
{
  $sql = 'SELECT u.*,r.*,u.id AS purch_id '
    . 'FROM purchases AS u '
    . 'JOIN products AS r '
    . 'ON r.id = u.product_id '
    . 'WHERE u.customer_id = :id '
    . 'ORDER BY u.date';
  $stmt = $this->connection->pdo->prepare($sql);
  $stmt->execute(['id' => $cust->getId()]);
  while ($result = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $product = Product::arrayToEntity($result, new Product());
    $product->setId($result['product_id']);
    $purch = Purchase::arrayToEntity($result, new Purchase());
    $purch->setId($result['purch_id']);
    $purch->setProduct($product);
    $cust->addPurchase($purch);
  }
  return $cust;
}
```

1.  接下来，我们提供原始`fetchById()`方法的包装器。这段代码块不仅需要获取原始的`Customer`实体，还需要查找并嵌入`Product 和 Purchase`实体。我们可以调用新的`fetchByIdAndEmbedPurchases()`方法，并接受客户 ID 作为参数：

```php
public function fetchByIdAndEmbedPurchases($id)
{
  return $this->fetchPurchasesForCustomer(
    $this->fetchById($id));
}
```

### 技术＃2-嵌入次要查找

现在我们将介绍将次要查找嵌入到相关实体类中的方法。我们将继续使用与上述相同的示例，使用与三个相关数据库表`customer`，`purchases`和`products`对应的实体类定义：

1.  这种方法的机制与前一节中描述的方法非常相似。主要区别在于，我们不会立即进行数据库查找和生成实体类，而是嵌入一系列匿名函数，这些函数将从视图逻辑中调用相同的操作。

1.  我们需要向`Application\Entity\Customer`类添加一个新方法，将单个条目添加到`purchases`属性中。我们将提供一个匿名函数，而不是`Purchase`实体数组：

```php
public function setPurchases(Closure $purchaseLookup)
{
  $this->purchases = $purchaseLookup;
}
```

1.  接下来，我们将复制`Application\Database\CustomerOrmService_1`类，并将其命名为`Application\Database\CustomerOrmService_2`：

```php
namespace Application\Database;
use PDO;
use PDOException;
use Application\Entity\Customer;
use Application\Entity\Product;
use Application\Entity\Purchase;
class CustomerOrmService_2 extends CustomerService
{
  // code
}
```

1.  然后，我们定义了一个`fetchPurchaseById()`方法，根据其 ID 查找单个购买并生成一个`Purchase`实体。因为在这种方法中，我们最终将进行一系列重复的请求以获取单个购买，所以我们可以通过使用相同的预处理语句（在本例中称为`$purchPreparedStmt`属性）来恢复数据库效率：

```php
public function fetchPurchaseById($purchId)
{
  if (!$this->purchPreparedStmt) {
      $sql = 'SELECT * FROM purchases WHERE id = :id';
      $this->purchPreparedStmt = 
      $this->connection->pdo->prepare($sql);
  }
  $this->purchPreparedStmt->execute(['id' => $purchId]);
  $result = $this->purchPreparedStmt->fetch(PDO::FETCH_ASSOC);
  return Purchase::arrayToEntity($result, new Purchase());
}
```

1.  之后，我们需要一个`fetchProductById()`方法，根据其 ID 查找单个产品并生成一个`Product`实体。鉴于客户可能多次购买同一产品，我们可以通过在`$products`数组中存储已获取的产品实体来提高效率。此外，与购买一样，我们可以在同一个预处理语句上执行查找：

```php
public function fetchProductById($prodId)
{
  if (!isset($this->products[$prodId])) {
      if (!$this->prodPreparedStmt) {
          $sql = 'SELECT * FROM products WHERE id = :id';
          $this->prodPreparedStmt = 
          $this->connection->pdo->prepare($sql);
      }
      $this->prodPreparedStmt->execute(['id' => $prodId]);
      $result = $this->prodPreparedStmt
      ->fetch(PDO::FETCH_ASSOC);
      $this->products[$prodId] = 
        Product::arrayToEntity($result, new Product());
  }
  return $this->products[$prodId];
}
```

1.  现在，我们可以重新设计`fetchPurchasesForCustomer()`方法，使其嵌入一个匿名函数，该函数调用`fetchPurchaseById()`和`fetchProductById()`，然后将结果的产品实体分配给新找到的购买实体。在本例中，我们进行了一个初始查找，只返回该客户的所有购买的 ID。然后，我们在`Customer::$purchases`属性中嵌入了一系列匿名函数，将购买 ID 作为数组键，匿名函数作为其值：

```php
public function fetchPurchasesForCustomer(Customer $cust)
{
  $sql = 'SELECT id '
    . 'FROM purchases AS u '
    . 'WHERE u.customer_id = :id '
    . 'ORDER BY u.date';
  $stmt = $this->connection->pdo->prepare($sql);
  $stmt->execute(['id' => $cust->getId()]);
  while ($result = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $cust->addPurchaseLookup(
    $result['id'],
    function ($purchId, $service) { 
      $purchase = $service->fetchPurchaseById($purchId);
      $product  = $service->fetchProductById(
                  $purchase->getProductId());
      $purchase->setProduct($product);
      return $purchase; }
    );
  }
  return $cust;
}
```

## 它是如何工作的...

根据本教程的步骤，定义以下类如下：

| 类 | 技术#1 步骤 |
| --- | --- |
| `Application\Entity\Purchase` | 1 - 2, 7 |
| `Application\Entity\Product` | 3 - 4 |
| `Application\Entity\Customer` | 6, 16, + 在第五章, *与数据库交互*中描述。 |
| `Application\Database\CustomerOrmService_1` | 8 - 10 |

这种方法的第二种途径如下：

| 类 | 技术#2 步骤 |
| --- | --- |
| `Application\Entity\Customer` | 2 |
| `Application\Database\CustomerOrmService_2` | 3 - 6 |

为了实现第一种方法，即嵌入实体，定义一个名为`chap_11_orm_embedded.php`的调用程序，设置自动加载并使用适当的类：

```php
<?php
define('DB_CONFIG_FILE', '/../config/db.config.php');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Database\Connection;
use Application\Database\CustomerOrmService_1;
```

接下来，创建一个服务的实例，并使用随机 ID 查找一个客户：

```php
$service = new CustomerOrmService_1(new Connection(include __DIR__ . DB_CONFIG_FILE));
$id   = rand(1,79);
$cust = $service->fetchByIdAndEmbedPurchases($id);
```

在视图逻辑中，您将通过`fetchByIdAndEmbedPurchases()`方法获取一个完全填充的`Customer`实体。现在，您只需要调用正确的 getter 来显示信息：

```php
  <!-- Customer Info -->
  <h1><?= $cust->getname() ?></h1>
  <div class="row">
    <div class="left">Balance</div><div class="right">
      <?= $cust->getBalance(); ?></div>
  </div>
    <!-- etc. -->
```

然后，显示购买信息所需的逻辑将类似于以下 HTML。请注意，`Customer::getPurchases()`返回一个`Purchase`实体数组。要从`Purchase`实体获取产品信息，在循环内调用`Purchase::getProduct()`，这将生成一个`Product`实体。然后可以调用任何`Product`的 getter，在本例中为`Product::getTitle()`：

```php
  <!-- Purchases Info -->
  <table>
  <?php foreach ($cust->getPurchases() as $purchase) : ?>
  <tr>
  <td><?= $purchase->getTransaction() ?></td>
  <td><?= $purchase->getDate() ?></td>
  <td><?= $purchase->getQuantity() ?></td>
  <td><?= $purchase->getSalePrice() ?></td>
  <td><?= $purchase->getProduct()->getTitle() ?></td>
  </tr>
  <?php endforeach; ?>
</table>
```

将注意力转向使用辅助查找的第二种方法，定义一个名为`chap_11_orm_secondary_lookups.php`的调用程序，设置自动加载并使用适当的类：

```php
<?php
define('DB_CONFIG_FILE', '/../config/db.config.php');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Database\Connection;
use Application\Database\CustomerOrmService_2;
```

接下来，创建一个服务的实例，并使用随机 ID 查找一个客户：

```php
$service = new CustomerOrmService_2(new Connection(include __DIR__ . DB_CONFIG_FILE));
$id   = rand(1,79);
```

现在，您可以检索一个`Application\Entity\Customer`实例，并为该客户调用`fetchPurchasesForCustomer()`，这将嵌入一系列匿名函数：

```php
$cust = $service->fetchById($id);
$cust = $service->fetchPurchasesForCustomer($cust);
```

显示核心客户信息的视图逻辑与之前描述的相同。然后，显示购买信息所需的逻辑看起来像以下 HTML 代码片段。请注意，`Customer::getPurchases()`返回一个匿名函数数组。每个函数调用返回一个特定的购买和相关产品：

```php
<table>
  <?php foreach($cust->getPurchases() as $purchId => $function) : ?>
  <tr>
  <?php $purchase = $function($purchId, $service); ?>
  <td><?= $purchase->getTransaction() ?></td>
  <td><?= $purchase->getDate() ?></td>
  <td><?= $purchase->getQuantity() ?></td>
  <td><?= $purchase->getSalePrice() ?></td>
  <td><?= $purchase->getProduct()->getTitle() ?></td>
  </tr>
  <?php endforeach; ?>
</table>
```

以下是输出的示例：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_11_09.jpg)

### 提示

**最佳实践**

尽管循环的每次迭代代表两个独立的数据库查询（一个用于购买，一个用于产品），但通过使用*准备好的语句*保留了效率。两个语句提前准备好：一个查找特定的购买，一个查找特定的产品。然后多次执行这些准备好的语句。此外，每个产品检索都独立存储在一个数组中，从而实现了更高的效率。

## 另请参阅

可能最好的实现对象关系映射的库的例子是 Doctrine。Doctrine 使用其文档称为代理的嵌入式方法。有关更多信息，请参阅[`www.doctrine-project.org/projects/orm.html`](http://www.doctrine-project.org/projects/orm.html)。

您可能还考虑观看来自 O'Reilly Media 的*学习 Doctrine*的培训视频，网址为[`shop.oreilly.com/product/0636920041382.do`](http://shop.oreilly.com/product/0636920041382.do)。（免责声明：这是本书和本视频的作者的厚颜无耻的宣传！）

# 实施发布/订阅设计模式

**发布/订阅**（**Pub/Sub**）设计模式通常是软件事件驱动编程的基础。这种方法允许不同软件应用程序之间或单个应用程序中的不同软件模块之间进行**异步**通信。该模式的目的是允许方法或函数在发生重要动作时发布信号。然后一个或多个类将订阅并在特定信号被发布时采取行动。

这种行为的例子是当数据库被修改时，或者用户已登录时。此设计模式的另一个常见用途是应用程序提供新闻订阅。如果发布了紧急新闻项目，应用程序将发布此事实，允许客户端订阅者刷新其新闻列表。

## 如何做...

1.  首先，我们定义我们的发布者类`Application\PubSub\Publisher`。您会注意到我们正在使用两个有用的**标准 PHP 库**（**SPL**）接口，`SplSubject`和`SplObserver`：

```php
namespace Application\PubSub;
use SplSubject;
use SplObserver;
class Publisher implements SplSubject
{
  // code
}
```

1.  接下来，我们添加属性来表示发布者名称，要传递给订阅者的数据以及订阅者的数组（也称为监听器）。您还会注意到我们将使用链表（在第十章中描述，*查看高级算法*）以允许优先级：

```php
protected $name;
protected $data;
protected $linked;
protected $subscribers;
```

1.  构造函数初始化这些属性。我们还加入了`__toString()`，以防我们需要快速访问此发布者的名称：

```php
public function __construct($name)
{
  $this->name = $name;
  $this->data = array();
  $this->subscribers = array();
  $this->linked = array();
}

public function __toString()
{
  return $this->name;
}
```

1.  为了将订阅者与此发布者关联，我们定义`attach()`，它在`SplSubject`接口中指定。我们接受一个`SplObserver`实例作为参数。请注意，我们需要向`$subscribers`和`$linked`属性添加条目。然后使用`arsort()`按优先级对`$linked`进行排序，表示值排序，以维护键：

```php
public function attach(SplObserver $subscriber)
{
  $this->subscribers[$subscriber->getKey()] = $subscriber;
  $this->linked[$subscriber->getKey()] = 
    $subscriber->getPriority();
  arsort($this->linked);
}
```

1.  接口还要求我们定义`detach()`，它从列表中移除订阅者：

```php
public function detach(SplObserver $subscriber)
{
  unset($this->subscribers[$subscriber->getKey()]);
  unset($this->linked[$subscriber->getKey()]);
}
```

1.  接口还要求我们定义`notify()`，它调用所有订阅者的`update()`。请注意，我们循环遍历链接列表以确保按优先级顺序调用订阅者：

```php
public function notify()
{
  foreach ($this->linked as $key => $value)
  {
    $this->subscribers[$key]->update($this);
  }
}
```

1.  接下来，我们定义适当的 getter 和 setter。我们这里没有全部显示出来以节省空间：

```php
public function getName()
{
  return $this->name;
}

public function setName($name)
{
  $this->name = $name;
}
```

1.  最后，我们需要提供一种通过键设置数据项的方法，然后在调用`notify()`时这些数据项将对订阅者可用：

```php
public function setDataByKey($key, $value)
{
  $this->data[$key] = $value;
}
```

1.  现在我们可以看一下`Application\PubSub\Subscriber`。通常，我们会为每个发布者定义多个订阅者。在这种情况下，我们实现了`SplObserver`接口：

```php
namespace Application\PubSub;
use SplSubject;
use SplObserver;
class Subscriber implements SplObserver
{
  // code
}
```

1.  每个订阅者都需要一个唯一的标识符。在这种情况下，我们使用`md5()`和日期/时间信息以及随机数来创建密钥。构造函数初始化属性如下。订阅者执行的实际逻辑功能以回调的形式进行：

```php
protected $key;
protected $name;
protected $priority;
protected $callback;
public function __construct(
  string $name, callable $callback, $priority = 0)
{
  $this->key = md5(date('YmdHis') . rand(0,9999));
  $this->name = $name;
  $this->callback = $callback;
  $this->priority = $priority;
}
```

1.  当调用发布者的`notify()`时，将调用`update()`函数。我们将一个发布者实例作为参数传递，并调用为该订阅者定义的回调函数：

```php
public function update(SplSubject $publisher)
{
  call_user_func($this->callback, $publisher);
}
```

1.  我们还需要为方便起见定义 getter 和 setter。这里没有展示所有的内容：

```php
public function getKey()
{
  return $this->key;
}

public function setKey($key)
{
  $this->key = $key;
}

// other getters and setters not shown
```

## 工作原理...

为了说明这一点，定义一个名为`chap_11_pub_sub_simple_example.php`的调用程序，设置自动加载并使用适当的类：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\PubSub\ { Publisher, Subscriber };
```

接下来，创建一个发布者实例并分配数据：

```php
$pub = new Publisher('test');
$pub->setDataByKey('1', 'AAA');
$pub->setDataByKey('2', 'BBB');
$pub->setDataByKey('3', 'CCC');
$pub->setDataByKey('4', 'DDD');
```

现在可以创建测试订阅者，从发布者那里读取数据并输出结果。第一个参数是名称，第二个是回调，最后一个是优先级：

```php
$sub1 = new Subscriber(
  '1',
  function ($pub) {
    echo '1:' . $pub->getData()[1] . PHP_EOL;
  },
  10
);
$sub2 = new Subscriber(
  '2',
  function ($pub) {
    echo '2:' . $pub->getData()[2] . PHP_EOL;
  },
  20
);
$sub3 = new Subscriber(
  '3',
  function ($pub) {
    echo '3:' . $pub->getData()[3] . PHP_EOL;
  },
  99
);
```

为了测试目的，以不正确的顺序附加订阅者，并调用`notify()`两次：

```php
$pub->attach($sub2);
$pub->attach($sub1);
$pub->attach($sub3);
$pub->notify();
$pub->notify();
```

接下来，定义并附加另一个订阅者，查看订阅者 1 的数据，如果不为空则退出：

```php
$sub4 = new Subscriber(
  '4',
  function ($pub) {
    echo '4:' . $pub->getData()[4] . PHP_EOL;
    if (!empty($pub->getData()[1]))
      die('1 is set ... halting execution');
  },
  25
);
$pub->attach($sub4);
$pub->notify();
```

这是输出。请注意，输出按优先级顺序排列（优先级较高的排在前面），第二个输出块被中断：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_11_10.jpg)

## 还有更多...

一个密切相关的软件设计模式是**Observer**。机制类似，但普遍认为的区别是 Observer 以同步方式运行，当接收到信号（通常也称为消息或事件）时，会调用所有观察者方法。相比之下，Pub/Sub 模式以异步方式运行，通常使用消息队列。另一个区别是，在 Pub/Sub 模式中，发布者不需要知道订阅者。

## 参见

有关观察者和 Pub/Sub 模式之间的区别的讨论，请参阅[`stackoverflow.com/questions/15594905/difference-between-observer-pub-sub-and-data-binding`](http://stackoverflow.com/questions/15594905/difference-between-observer-pub-sub-and-data-binding)上的文章。
