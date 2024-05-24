# 函数式 PHP（二）

> 原文：[`zh.annas-archive.org/md5/542d15e7552f9c0cf0925a989aaf5fc0`](https://zh.annas-archive.org/md5/542d15e7552f9c0cf0925a989aaf5fc0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：组合函数

在之前的章节中，我们谈了很多关于构建模块和小纯函数。 但到目前为止，我们甚至没有暗示这些如何用来构建更大的东西。 如果你不能使用构建模块，那么构建模块有什么用呢？ 答案部分地在于函数组合。

尽管这一章完成了前一章，但这种技术是任何函数式程序的一个不可或缺的重要部分，因此它值得有自己的一章。

在本章中，我们将涵盖以下主题：

+   函数组合

+   部分应用

+   柯里化

+   参数顺序的重要性

+   这些概念的现实应用

# 函数组合

正如在函数式编程中经常发生的那样，函数组合的概念是从数学中借来的。 如果您有两个函数`f`和`g`，您可以通过组合它们来创建第三个函数。 数学中的通常表示法是*(f g)(x)*，这相当于依次调用它们*f(g(x))*。

您可以使用一个包装函数非常容易地组合任何两个给定的函数与 PHP。 比如说，您想以大写字母显示标题，并且只保留安全的 HTML 字符：

```php
<?php 

function safe_title(string $s) 
{ 
    $safe = htmlspecialchars($s); 
    return strtoupper($safe); 
} 
```

您也可以完全避免临时变量：

```php
<?php 

function safe_title2(string $s) 
{ 
    return strtoupper(htmlspecialchars($s)); 
} 
```

当您只想组合几个函数时，这样做效果很好。 但是创建很多这样的包装函数可能会变得非常繁琐。 如果您能简单地使用`$safe_title = strtoupper htmlspecialchars`这行代码会怎么样呢？ 遗憾的是，PHP 中不存在这样的运算符，但我们之前介绍的`functional-php`库包含一个`compose`函数，它正是这样做的：

```php
<?php 
require_once __DIR__.'/vendor/autoload.php'; 

use function Functional\compose; 

$safe_title2 = compose('htmlspecialchars', 'strtoupper'); 
```

收益可能看起来并不重要，但让我们在更多的上下文中比较一下使用这种方法：

```php
<?php 

$titles = ['Firefly', 'Buffy the Vampire Slayer', 'Stargate Atlantis', 'Tom & Jerry', 'Dawson's Creek']; 

$titles2 = array_map(function(string $s) { 
    return strtoupper(htmlspecialchars($s)); 
}, $titles); 

$titles3 = array_map(compose('htmlspecialchars', 'strtoupper'),  $titles); 
```

就个人而言，我发现第二种方法更容易阅读和理解。 而且它变得更好了，因为您可以将两个以上的函数传递给`compose`函数：

```php
<?php 

$titles4 = array_map(compose('htmlspecialchars', 'strtoupper', 'trim'), $titles); 
```

一个可能会误导的事情是函数应用的顺序。 数学表示法`f ∘ g`首先应用`g`，然后将结果传递给`f`。 然而，`functional-php`库中的`compose`函数按照它们在`compose('first', 'second', 'third')`参数中传递的顺序应用函数。

这可能更容易理解，取决于您的个人偏好，但是当您使用另一个库时要小心，因为应用的顺序可能会被颠倒。 一定要确保您已经仔细阅读了文档。

# 部分应用

您可能想设置函数的一些参数，但将其中一些参数留到以后再分配。 例如，我们可能想创建一个返回博客文章摘录的函数。

设置这样一个值的专用术语是**绑定参数**或**绑定参数**。 过程本身称为**部分应用**，新函数被设置为部分应用。

这样做的天真方式是将函数包装在一个新函数中：

```php
<?php 
function excerpt(string $s) 
{ 
    return substr($s, 0, 5); 
} 

echo excerpt('Lorem ipsum dolor si amet.'); 
// Lorem 
```

与组合一样，总是创建新函数可能会很快变得繁琐。 但再一次，`functional-php`库为我们提供了帮助。 您可以决定从左侧、右侧或函数签名中的任何特定位置绑定参数，分别使用`partial_left`、`partial_right`或`partial_any`函数。

为什么有三个函数？ 主要是出于性能原因，因为左侧和右侧版本的性能会更快，因为参数将被一次性替换，而最后一个将使用在每次调用新函数时计算的占位符。

在上一个例子中，占位符是使用函数`...`定义的，它是省略号 Unicode 字符。 如果您的计算机没有简便的方法输入它，您也可以使用`Functional`命名空间中的`placeholder`函数，它是一个别名。

# 柯里化

**柯里化**经常被用作部分应用的同义词。 尽管这两个概念都允许我们绑定函数的一些参数，但核心思想有些不同。

柯里化的思想是将接受多个参数的函数转换为接受一个参数的函数序列。由于这可能有点难以理解，让我们尝试对`substr`函数进行柯里化。结果被称为**柯里化函数**：

```php
<?php 

function substr_curryied(string $s) 
{ 
    return function(int $start) use($s) { 
        return function(int $length) use($s, $start) { 
            return substr($s, $start, $length); 
        }; 
    }; 
} 

$f = substr_curryied('Lorem ipsum dolor sit amet.'); 
$g = $f(0); 
echo $g(5); 
// Lorem 
```

正如你所看到的，每次调用都会返回一个接受下一个参数的新函数。这说明了与部分应用的主要区别。当你调用部分应用的函数时，你会得到一个结果。但是，当你调用柯里化函数时，你会得到一个新的函数，直到传递最后一个参数。此外，你只能按顺序从左边开始绑定参数。

如果调用链看起来过长，你可以从 PHP 7 开始大大简化它。这是因为 RFC *统一变量语法*已经实现（详见[`wiki.php.net/rfc/uniform_variable_syntax`](https://wiki.php.net/rfc/uniform_variable_syntax)）：

```php
<?php 

echo substr_curryied('Lorem ipsum dolor sit amet.')(0)(5); 
// Lorem 
```

柯里化的优势可能在这样的情况下并不明显。但是，一旦你开始使用高阶函数，比如`map`或`reduce`函数，这个想法就变得非常强大了。

你可能还记得`functional-php`库中的`pluck`函数。这个想法是从对象集合中检索给定的属性。如果`pluck`函数被实现为柯里化函数，它可以以多种方式使用：

```php
<?php 

function pluck(string $property) 
{ 
    return function($o) use($property) { 
        if (is_object($o) && isset($o->{$propertyName})) { 
            return $o->{$property}; 
        } elseif ((is_array($o) || $o instanceof ArrayAccess) &&  isset($o[$property])) { 
            return $o[$property]; 
        } 

        return false; 
    }; 
} 
```

我们可以轻松地从任何类型的对象或数组中获取值：

```php
<?php 

$user = ['name' => 'Gilles', 'country' => 'Switzerland', 'member'  => true]; 
pluck('name')($user); 
```

我们可以从对象集合中提取属性，就像`functional-php`库中的版本一样：

```php
<?php 

$users = [ 
    ['name' => 'Gilles', 'country' => 'Switzerland', 'member' =>  true], 
    ['name' => 'Léon', 'country' => 'Canada', 'member' => false], 
    ['name' => 'Olive', 'country' => 'England', 'member' => true], 
]; 
pluck('country')($users); 
```

由于我们的实现在找不到内容时返回`false`，我们可以用它来过滤包含特定值的数组：

```php
<?php 

array_filter($users, pluck('member')); 
```

我们可以组合多个用例来获取所有成员的名称：

```php
<?php 

pluck('name', array_filter($users, pluck('member'))); 
```

如果没有柯里化，我们要么需要编写一个更传统的`pluck`函数的包装器，要么创建三个专门的函数。

让我们再进一步，结合多个柯里化函数。首先，我们需要创建一个包装函数，包装`array_map`和`preg_replace`函数：

```php
<?php 

function map(callable $callback) 
{ 
    return function(array $array) use($callback) { 
        return array_map($callback, $array); 
    }; 
} 

function replace($regex) 
{ 
    return function(string $replacement) use($regex) { 
        return function(string $subject) use($regex, $replacement)  
{ 
            return preg_replace($regex, $replacement, $subject); 
        }; 
    }; 
} 
```

现在我们可以使用这些来创建多个新函数，例如，一个将字符串中所有空格替换为下划线或所有元音字母替换为星号的函数：

```php
<?php function map(callable $callback) 
{ 
    return function(array $array) use($callback) { 
        return array_map($callback, $array); 
    }; 
} 

function replace($regex) 
{ 
    return function(string $replacement) use($regex) { 
        return function(string $subject) use($regex, $replacement)  
{ 
            return preg_replace($regex, $replacement, $subject); 
        }; 
    }; 
} 
```

## 在 PHP 中进行柯里化函数

我希望你现在已经相信了柯里化的力量。如果没有，我希望接下来的例子能说服你。与此同时，你可能会认为围绕现有函数编写新的实用程序函数来创建新的柯里化版本真的很麻烦，你是对的。

在 Haskell 等语言中，所有函数默认都是柯里化的。不幸的是，PHP 中并非如此，但这个过程足够简单和重复，我们可以编写一个辅助函数。

由于 PHP 中可能有可选参数的可能性，我们首先要创建一个名为`curry_n`的函数，该函数接受你想要柯里化的参数数量。这样，你也可以决定是否要对所有参数进行柯里化，还是只对其中一些进行柯里化。它也可以用于具有可变参数数量的函数：

```php
<?php 

function curry_n(int $count, callable $function): callable 
{ 
    $accumulator = function(array $arguments) use($count,  $function, &$accumulator) { 
        return function() use($count, $function, $arguments,  $accumulator) { 
            $arguments = array_merge($arguments, func_get_args()); 

            if($count <= count($arguments)) { 
                return call_user_func_array($function,  $arguments); 
            } 

            return $accumulator($arguments); 
        }; 
    }; 
    return $accumulator([]); 
} 
```

这个想法是使用一个内部辅助函数，将已传递的值作为参数，然后使用这些创建一个闭包。当调用时，闭包将根据实际值的数量决定我们是否可以调用原始函数，或者我们是否需要使用我们的辅助函数创建一个新函数。

请注意，如果你给出的参数计数高于实际计数，所有多余的参数将被传递到原始函数，但可能会被忽略。此外，给出较小的计数将导致最后一步期望更多的参数才能正确完成。

现在我们可以创建第二个函数，使用`reflection`变量来确定参数的数量：

```php
<?php 

function curry(callable $function, bool $required = true):  callable 
{ 
    if(is_string($function) && strpos($function, '::', 1) !==  false) { 
        $reflection = new \ReflectionMethod($f); 
    }  
    else if(is_array($function) && count($function) == 2)  
    { 
        $reflection = new \ReflectionMethod($function[0],  $function[1]); 
    }  
    else if(is_object($function) && method_exists($function,  '__invoke'))  
    { 
        $reflection = new \ReflectionMethod($function,  '__invoke'); 
    }  
    else  
    {         
        $reflection = new \ReflectionFunction($function); 
    } 

    $count = $required ? $reflection->getNumberOfRequiredParameters() : 
        $reflection->getNumberOfParameters(); 

    return curry_n($count, $function); 
} 
```

正如你所看到的，没有简单的方法来确定函数期望的参数数量。我们还必须添加一个参数来确定我们是否应该考虑所有参数，包括具有默认值的参数，还是只考虑必填参数。

您可能已经注意到，我们并没有创建严格只接受一个参数的函数；相反，我们使用了`func_get_args`函数来获取所有传递的参数。这使得使用柯里化函数更加自然，并且与函数式语言中所做的事情相当。我们对柯里化的定义现在更接近于*一个函数，直到接收到所有参数才返回一个新函数*。

本书其余部分的示例将假定此柯里化函数可用并准备好使用。

在撰写本文时，`functional-php`库上有一个待处理的拉取请求，以合并此函数。

# 参数顺序非常重要！

正如你可能还记得第一章所述，`array_map`和`array_filter`函数的参数顺序不同。当然，这使它们更难使用，因为你更容易出错，但这并不是唯一的问题。为了说明参数顺序的重要性，让我们创建这两个函数的柯里化版本：

```php
<?php 

$map = curry_n(2, 'array_map'); 
$filter = curry_n(2, 'array_filter'); 
```

我们在这里使用`curry_n`函数有两个不同的原因：

+   `array_map`函数接受可变数量的数组，因此我们强制将值设为 2 以确保安全

+   `array_filter`函数有一个名为`$flag`的第三个参数，其可选值是可以接受的

还记得我们新的柯里化函数的参数顺序吗？`$map`参数将首先获取回调函数，而`$filters`参数期望首先获取集合。让我们尝试创建一个新的有用函数，了解这一点：

```php
<?php 

$trim = $map('trim'); 
$hash = $map('sha1'); 

$oddNumbers = $filter([1, 3, 5, 7]); 
$vowels = $filter(['a', 'e', 'i', 'o', 'u']); 
```

我们的映射示例确实非常基础，但有一定用途，而我们的过滤示例只是静态数据。我敢打赌，你可以找到一些方法来使用`$trim`和`$hash`参数，但你需要一个奇数或元音字母的列表来进行过滤的可能性有多大呢？

本章稍早前的另一个例子可以从这里得到-还记得我们对`substr`函数的柯里化示例吗？

```php
<?php 

function substr_curryied(string $s) 
{ 
    return function(int $start) use($s) { 
        return function(int $length) use($s, $start) { 
            return substr($s, $start, $length); 
        }; 
    }; 
} 

$f = substr_curryied('Lorem ipsum dolor sit amet.'); 
$g = $f(0); 
echo $g(5); 
// Lorem 
```

我可以向你保证，如果我们首先定义开始和长度来创建，那将会更有用。例如，一个`$take5fromStart`函数；而不是拥有这些尴尬的`$substrOnLoremIpsum`参数，我们只需在示例中调用`$f`参数。

这里重要的是，你想要操作的数据，也就是你的“主题”，必须放在最后，因为这大大增加了对柯里化函数的重用，并且让你可以将它们作为其他高阶函数的参数使用。

就像上一个例子一样，假设我们想要创建一个函数，该函数获取集合中所有元素的前两个字母。我们将尝试使用一组两个函数来实现，其中参数的顺序不同。

函数的实现留作练习，因为这并不重要。

在第一个例子中，主语是第一个参数：

```php
<?php 

$map = curry(function(array $array, callable $cb) {}); 
$take = curry(function(string $string, int $count) {}); 

$firstTwo = function(array $array) { 
    return $map($array, function(string $s) { 
        return $take($s, 2); 
    }); 
} 
```

参数顺序迫使我们创建包装函数。事实上，即使函数是柯里化的，也无关紧要，因为我们无法利用这一点。

在第二个例子中，主语位于最后：

```php
<?php 

$map = curry(function(callable $cb, array $array) {}); 
$take = curry(function(int $count, string $string) {}); 

$firstTwo = $map($take(2)); 
```

事实上，精心选择的顺序也对函数组合有很大帮助，正如我们将在下一节中看到的那样。

最后，关于主题的说明，为了公平起见，使用参数顺序相反的函数版本可以使用`functional-php`库中的`partial_right`函数编写，并且您可以使用`partial_any`函数来处理参数顺序奇怪的函数。但即便如此，解决方案也不像参数顺序正确的解决方案那样简单：

```php
<?php 

use function Functional\partial_right; 

$firstTwo = partial_right($map, partial_right($take, 2)); 
```

# 使用组合来解决真正的问题

举个例子，假设你的老板走进来，希望你制作一个新报告，其中包含过去 30 天内注册的所有用户的电话号码。我们假设有以下类来表示我们的用户。显然，一个真正的类将存储和返回真实数据，但让我们只定义我们的 API：

```php
<?php 

class User { 
    public function phone(): string 
    { 
        return ''; 
    } 

    public function registration_date(): DateTime 
    { 
        return new DateTime(); 
    } 
} 

$users = [new User(), new User(), new User()]; // etc. 
```

对于没有任何函数式编程知识的人来说，你可能会写出这样的代码：

```php
<?php 

class User { 
    public function phone(): string 
    { 
        return ''; 
    }  
    public function registration_date(): DateTime 
    { 
        return new DateTime(); 
    } 
} 

$users = [new User(), new User(), new User()]; // etc. 
```

我们的函数的第一眼看告诉我们它不是纯的，因为限制是在函数内部计算的，因此后续调用可能导致不同的用户列表。我们还可以利用`map`和`filter`函数：

```php
<?php 

function getUserPhonesFromDate($limit, $users) 
{ 
    return array_map(function(User $u) { 
        return $u->phone(); 
    }, array_filter($users, function(User $u) use($limit) { 
        return $u->registration_date()->getTimestamp() > $limit; 
    })); 
} 
```

根据你的喜好，现在代码可能会更容易阅读一些，或者完全不容易，但至少我们有了一个纯函数，我们的关注点也更加分离。然而，我们可以做得更好。首先，`functional-php`库有一个函数，允许我们创建一个调用对象方法的辅助函数：

```php
<?php 

use function Functional\map; 
use function Functional\filter; 
use function Functional\partial_method; 

function getUserPhonesFromDate2($limit, $users) 
{ 
    return map( 
        filter(function(User $u) use($limit) { 
            return $u->registration_date()->getTimestamp()  >$limit; 
        }, $users), 
        partial_method('phone') 
    ); 
} 
```

这样会好一些，但如果我们接受需要创建一些新的辅助函数，我们甚至可以进一步改进解决方案。此外，这些辅助函数是我们将能够重用的新构建块：

```php
<?php 

function greater($limit) { 
    return function($a) { 
        return $a > $limit; 
    }; 
} 

function getUserPhonesFromDate3($limit, $users) 
{ 
    return map( 
        filter(compose( 
            partial_method('registration_date'), 
            partial_method('getTimestamp'), 
            greater($limit) 
          ), 
          $users), 
        partial_method('phone') 
    ); 
} 
```

如果我们有`filter`和`map`函数的柯里化版本，甚至可以创建一个只接受日期并返回一个新函数的函数，这个新函数可以进一步组合和重用：

```php
<?php 

use function Functional\partial_right; 

$filter = curry('filter'); 
$map = function($cb) { 
    return function($data) use($cb) { 
        return map($data, $cb); 
    }; 
}; 

function getPhonesFromDate($limit) 
{ 
    return function($data) use($limit) { 
        $function = compose( 
            $filter(compose( 
            partial_method('getTimestamp'), 
                partial_method('registration_date'), 
                greater($limit) 
            )), 
            $map(partial_method('phone')) 
        ); 
        return $function($data); 
    }; 
} 
```

作为一个关于拥有良好参数顺序的必要性的良好提醒，由于`functional-php`库中的`map`函数具有与 PHP 原始函数相同的签名，我们不得不手动进行柯里化。

我们的结果函数比原始的命令式函数稍长一些，但在我看来，它更容易阅读。你可以轻松地跟踪发生了什么：

1.  使用以下方式过滤数据：

1.  注册日期

1.  从中，你可以得到时间戳。

1.  检查它是否大于给定的限制。

1.  在结果上映射`phone`方法。

如果你觉得`partial_method`这个名字不太理想，并且调用`compose`函数的存在在某种程度上让人有点难以理解，我完全同意。事实上，在一个具有`compose`运算符、自动柯里化和一些语法糖来推迟对方法的调用的假设语言中，它可能看起来像这样：

```php
getFromDate($limit) = filter( 
  (->registration_date) >> 
  (->getTimestamp) >> 
  (> $limit) 
) >> map(->phone) 
```

现在我们有了我们的函数，你的老板又走进你的办公室，提出了新的要求。实际上，他只想要过去 30 天内最近的三次注册。很简单，让我们只是用一些更多的构建块来组合我们的新函数：

```php
<?php 

use function Functional\sort; 
use function Functional\compare_on; 

function take(int $count) { 
    return function($array) use($count) { 
        return array_slice($array, 0, $count); 
    }; 
}; 

function compare($a, $b) { 
    return $a == $b ? 0 : $a < $b ? -1 : 1; 
} 

function getAtMostThreeFromDate($limit) 
{ 
    return function($data) use($limit) { 
        $function = compose( 
            partial_right( 
                'sort', 
                compare_on('compare',  partial_method('registration_date')) 
            ), 
            take(3), 
            getPhonesFromDate($limit) 
        ); 
        return $function($data); 
    }; 
} 
```

为了从数组的开头获取一定数量的项目，我们需要在`array_slice`函数周围创建一个`take`函数。我们还需要一个比较值的函数，这很简单，因为`DateTime`函数重载了比较运算符。

再次，`functional-php`库对`sort`函数的参数顺序搞错了，所以我们需要部分应用而不是柯里化。而`compare_on`函数创建了一个比较器，给定一个比较函数和一个“reducer”，它在比较每个项目时被调用。在我们的情况下，我们想要比较注册日期，所以我们重用了我们的不同方法应用。

我们需要在过滤之前执行排序操作，因为我们的`getPhonesFromDate`方法只返回电话号码，正如其名称所示。我们的结果函数本身是其他函数的柯里化组合，因此可以轻松重用。

我希望这个小例子已经说服你使用小函数作为构建块并将它们组合起来解决问题的力量。如果不是这样，也许我们将在接下来的章节中看到的更高级的技术之一会说服你。

最后一点，也许你从例子中已经知道，PHP 遗憾地缺少了很多实用函数，以便让函数式编程者的生活变得更容易。而且，即使是广泛使用的`functional-php`库，也会出现一些参数顺序错误，并且缺少一些重要的代码，比如柯里化。

通过结合多个库，我们可以更好地覆盖所需的功能，但这也会增加大量无用的代码和一些不匹配的函数名称，这并不会让你的生活变得更轻松。

我可以建议的是保留一个文件，记录你在学习过程中创造的所有小技巧，很快你就会拥有自己的助手编译，真正适合你的需求和编码风格。这个建议可能违反了围绕着大型社区的可重用包的最佳实践，但在有人创建正确的库之前，它会有很大帮助。谁知道，也许你就是有足够精力创建功能 PHP 生态系统中缺失的珍珠的人。

# 总结

本章围绕函数组合展开，一旦你习惯了它，这是一个非常强大的想法。通过使用小的构建模块，你可以创建复杂的过程，同时保持短函数提供的可读性和可维护性。

我们还谈到了部分应用和柯里化的最强大概念，它们使我们能够轻松地创建现有函数的更专业化版本，并重写我们的代码以使其更易读。

我们讨论了参数顺序，这是一个经常被忽视但非常重要的话题，一旦你想使用高阶函数时就会变得重要。柯里化和正确的参数顺序的结合使我们能够减少样板代码和包装函数的需求，这个过程有时被称为 eta-reduction。

最后，通过前面提到的所有工具，我们试图演示一些你在日常编程中可能遇到的问题和难题的解决方案，以帮助你写出更好的代码。


# 第五章：函子、应用函子和单子

上一章介绍了第一个真正的函数式技术，比如函数组合和柯里化。在本章中，我们将再次深入介绍更多的理论概念，介绍单子的概念。由于我们有很多内容要涵盖，实际应用将不会很多。然而，第六章*真实生活中的单子*将使用我们在这里学到的一切来解决真实问题。

你可能已经听说过**单子**这个术语。通常，它与非函数式程序员的恐惧感联系在一起。单子通常被描述为难以理解，尽管有无数关于这个主题的教程。事实上，它们很难理解，写这些教程的人经常忘记了他们正确理解这个想法花了多少时间。这是一个常见的教学陷阱，可能在这篇文章中更好地描述了[`byorgey.wordpress.com/2009/01/12/abstraction-intuition-and-the-monad-tutorial-fallacy/`](https://byorgey.wordpress.com/2009/01/12/abstraction-intuition-and-the-monad-tutorial-fallacy/)。

你可能不会一次性理解所有内容。单子是一个非常抽象的概念，即使在本章结束时，这个主题对你来说似乎很清楚，你可能在以后遇到一些东西，它会使你对单子的真正理解感到困惑。

我会尽力清楚地解释事情，但如果你觉得我的解释不够，我在本章末尾的*进一步阅读*部分添加了关于这个主题的其他材料的参考。在本章中，我们将涵盖以下主题：

+   函子及相关法则

+   应用函子及相关法则

+   幺半群及相关法则

+   单子及相关法则

将会有很多理论内容，只有概念的实现。在第六章*真实生活中的单子*之前，不要期望有很多例子。

# 函子

在直接讲述单子之前，让我们从头开始。为了理解单子是什么，我们需要介绍一些相关概念。第一个是函子。

为了让事情变得复杂一些，术语**函子**在命令式编程中用来描述函数对象，这是完全不同的东西。在 PHP 中，一个具有`__invoke`方法的对象，就像我们在第一章中看到的那样，*函数作为一等公民*，就是这样一个函数对象。

然而，在函数式编程中，函子是从范畴论的数学领域中借用并改编的概念。细节对我们的目的并不那么重要；它足以说，函子是一种模式，允许我们将函数映射到一个或多个值所包含的上下文中。此外，为了使定义尽可能完整，我们的函子必须遵守一些法则，我们将在稍后描述和验证。

我们已经多次在集合上使用了 map，这使它们成为了事实上的函子。但是如果你记得的话，我们也以相同的方式命名了我们的方法来将一个函数应用于 Maybe 中包含的值。原因是函子可以被看作是具有一种方法来将函数应用于包含的值的容器。

在某种意义上，任何实现以下接口的类都可以被称为`函子`：

```php
<?php 

interface Functor 
{ 
    public function map(callable $f): Functor; 
} 
```

然而，这样描述有点简化了。一个简单的 PHP 数组也是一个函子（因为存在`array_map`函数），只要你使用`functional-php`库和它的 map 函数，任何实现`Traversable`接口的东西也是一个函子。

为什么对于一个如此简单的想法要大惊小怪？因为，尽管这个想法本身很简单，它使我们能够以不同的方式思考正在发生的事情，并可能有助于理解和重构代码。

此外，`map`函数可以做的远不止盲目地应用给定的`callable`类型，就像数组一样。如果你记得我们的`Maybe`类型实现，在值为`Nothing`的情况下，`map`函数只是简单地保持返回`Nothing`值，以便更简单地管理空值。

我们还可以想象在我们的函子中有更复杂的数据结构，比如树，其中给`map`函数的函数应用于所有节点。

函子允许我们共享一个共同的接口，我们的`map`方法或函数，对各种数据类型执行类似的操作，同时隐藏实现的复杂性。就像函数式编程一样，认知负担减少了，因为你不需要为相同的操作有多个名称。例如，"apply"、"perform"和"walk"等函数和方法名称通常用来描述相同的事情。

## 恒等函数

我们最终关注的是与这个概念相关的两个函子定律。但在介绍它们之前，我们需要稍微偏离一下，讨论一下恒等函数，通常是`id`。这是一个非常简单的函数，只是简单地返回它的参数：

```php
<?php 

function id($value) 
{ 
    return $value; 
} 
```

为什么有人需要一个做得这么少的函数？首先，我们以后会需要它来证明本章中介绍的各种抽象的定律。但现实世界中也存在应用。

例如，当你对数字进行折叠运算，比如求和，你会使用初始值`0`。`id`函数在对函数进行折叠时起着相同的作用。事实上，`functional-php`库中的 compose 函数是使用`id`函数实现的。

另一个用途可能是来自另一个库的某个函数，它执行你感兴趣的操作，但也在结果数据上调用回调。如果回调是必需的，但你不想对数据做其他任何操作，只需传递`id`，你将得到未经改变的数据。

让我们使用我们的新函数来声明我们的`compose`函数的一个属性，对于任何只接受一个参数的函数`f`：

```php
compose(id, f) == compose(f, id) 
```

这基本上是说，如果你先应用参数`id`然后是`f`，你会得到与先应用`f`然后是`id`完全相同的结果。到这一点，这对你来说应该是显而易见的。如果不是，我鼓励你重新阅读上一章，直到你清楚地理解为什么会这样。

## 函子定律

现在我们已经涵盖了我们的恒等函数，让我们回到我们的定律。它们有两个重要原因：

+   它们给了我们一组约束条件，以确保我们的函子的有效性。

+   它们允许我们进行经过验证的重构

话不多说，它们在这里：

1.  *map(id) == id*

1.  *compose(map(f), map(g)) == map(compose(f, g))*

第一定律规定，将`id`函数映射到包含的值上，与直接在函子本身上调用`id`函数完全相同。当这个定律成立时，这保证了我们的 map 函数只将给定的函数应用于数据，而不进行任何其他类型的处理。

第二定律规定，首先在我们的值上映射`f`函数，然后是`g`函数，与首先将`f`和`g`组合在一起，然后映射结果函数完全相同。知道这一点，我们可以进行各种优化。例如，我们可以将它们组合在一起，只进行一次循环，而不是对我们的数据进行三种不同方法的三次循环。

我可以想象现在对你来说并不是一切都很清楚，所以不要浪费时间试图进一步解释它们，让我们验证它们是否适用于`array_map`方法。这可能会帮助你理解它的要点；以下代码期望之前定义的`id`函数在作用域内：

```php
<?php 

$data = [1, 2, 3, 4]; 

var_dump(array_map('id', $data) === id($data)); 
// bool(true) 

function add2($a) 
{ 
    return $a + 2; 
} 

function times10($a) 
{ 
    return $a * 10; 
} 

function composed($a) { 
    return add2(times10($a)); 
} 

var_dump( 
array_map('add2', array_map('times10', $data)) === array_map('composed', $data) 
); 
// bool(true) 
```

组合是手动执行的；在我看来，在这里使用柯里化只会使事情变得更加复杂。

正如我们所看到的，`array_map`方法符合这两个定律，这是一个好迹象，因为这意味着没有隐藏的数据处理在背后进行，我们可以避免在数组上循环两次或更多次，当只需要一次时。

让我们尝试一下我们之前定义的`Maybe`类型：

```php
<?php 

$just = Maybe::just(10); 
$nothing = Maybe::nothing(); 

var_dump($just->map('id') == id($just)); 
// bool(true) 

var_dump($nothing->map('id') === id($nothing)); 
// bool(true) 
```

我们不得不切换到非严格相等的方式来处理`$just`情况，因为否则我们会得到一个错误的结果，因为 PHP 比较对象实例而不是它们的值。`Maybe`类型将结果值包装在一个新对象中，PHP 只在非严格相等的情况下执行内部值比较；上面定义的`add2`、`times10`和`composed`函数预期在范围内。

```php
<?php 

var_dump($just->map('times10')->map('add2') == $just->map('composed')); 
// bool(true) 

var_dump($nothing->map('times10')->map('add2') === $nothing->map('composed')); 
// bool(true) 
```

很好，我们的`Maybe`类型实现是一个有效的函数器。

## 身份函数器

正如我们在关于身份函数的部分讨论的那样，还存在一个身份函数器。它充当一个非常简单的函数器，除了保存值之外不对值进行任何操作：

```php
<?php 

class IdentityFunctor implements Functor 
{ 
    private $value; 

    public function __construct($value) 
    { 
        $this->value = $value; 
    } 

    public function map(callable $f): Functor 
    { 
        return new static($f($this->value)); 
    } 

    public function get() 
    { 
        return $this->value; 
    } 
} 
```

与身份函数一样，这种函数器的用途并不立即明显。然而，思想是一样的-当您有一个函数以函数器作为参数时，您可以使用它，但不想修改您的实际值。

这应该在本书的后续章节中变得更加清晰。与此同时，我们将使用身份函数器来解释一些更高级的概念。

## 结束语

让我再次重申，函数器是一个非常简单的抽象概念，但也是一个非常强大的概念。我们只看到了其中两个，但有无数的数据结构可以非常容易地转换为函数器。

任何允许您将给定函数映射到上下文中保存的一个或多个值的函数或类都可以被视为函数器。身份函数器或数组是这种上下文的简单示例；其他示例包括我们之前讨论过的`Maybe`和`Either`类型，或者任何具有`map`方法的类，该方法允许您将函数应用于包含的值。

我无法鼓励您足够尝试实现这种映射模式，并验证无论您创建一个新的类或数据结构，这两个定律是否成立。这将使您更容易理解您的代码可以执行什么，并且您将能够使用组合进行优化，并保证您的重构是正确的。

# 应用函数器

让我们拿一个我们的身份函数器的实例，保存一些整数和一个柯里化版本的`add`函数：

```php
<?php 

$add = curry(function(int $a, int $b) { return $a + $b; }); 

$id = new IdentityFunctor(5); 
```

现在，当我们尝试在我们的函数器上映射`$add`参数时会发生什么？考虑以下代码：

```php
<?php 

$hum = $id->map($add); 

echo get_class($hum->get()); 
// Closure 
```

你可能已经猜到了，我们的函数器现在包含一个闭包，代表一个部分应用的`add`参数，其值为`5`作为第一个参数。您可以使用`get`方法检索函数并使用它，但实际上并不是很有用。

另一种可能性是映射另一个函数，以我们的函数作为参数，并对其进行操作：

```php
<?php 

$result = $hum->map(function(callable $f) { 
    return $f(10); 
}); 
echo $result->get(); 
// 15 
```

但我想我们都会同意，这并不是执行这样的操作的一种非常有效的方式。更好的方法是能够简单地将值`10`或者另一个函数器传递给`$hum`并获得相同的结果。

进入应用函数器。顾名思义，这个想法是应用函数器。更准确地说，是将函数器应用于其他函数器。在我们的情况下，我们可以将包含函数的函数器`$hum`应用于另一个包含值`10`的函数器，并获得我们想要的值`15`。

让我们创建一个扩展版本的`IdentityFunctor`类来测试我们的想法：

```php
<?php 

class IdentityFunctorExtended extends IdentityFunctor 
{ 
    public function apply(IdentityFunctorExtended $f) 
    { 
        return $f->map($this->get()); 
    } 
} 

$applicative = (new IdentityFunctorExtended(5))->map($add); 
$ten = new IdentityFunctorExtended(10); 
echo $applicative->apply($ten)->get(); 
// 15 
```

甚至可以创建一个只包含函数的`Applicative`类，并在之后应用这些值：

```php
<?php 

$five = new IdentityFunctorExtended(5); 
$ten = new IdentityFunctorExtended(10); 
$applicative = new IdentityFunctorExtended($add); 

echo $applicative->apply($five)->apply($ten)->get(); 
// 15 
```

## 应用抽象

现在我们能够使用我们的`IdentifyFunctor`类作为柯里化函数的持有者。如果我们能够将这个想法抽象出来，并在`Functor`类的基础上创建一些东西会怎样？

```php
<?php 

abstract class Applicative implements Functor 
{ 
    public abstract static function pure($value): Applicative; 
    public abstract function apply(Applicative $f): Applicative; 
    public function map(callable $f): Functor 
    { 
        return $this->pure($f)->apply($this); 
    } 
} 
```

正如你所看到的，我们创建了一个新的抽象类而不是一个接口。原因是因为我们可以使用`pure`和`apply`方法来实现`map`函数，所以强制每个想要创建`Applicative`类的人都要实现它是没有意义的。

`pure`函数之所以被称为如此，是因为`Applicative`类中存储的任何东西都被认为是纯的，因为没有办法直接修改它。这个术语来自 Haskell 实现。其他实现有时使用名称*unit*。pure 用于从任何`callable`创建一个新的 applicative。

`apply`函数将存储的函数应用于给定的参数。参数必须是相同类型的，以便实现知道如何访问内部值。遗憾的是，PHP 类型系统不允许我们强制执行这个规则，我们必须默认为`Applicative`。

我们对 map 的定义也有同样的问题，必须将返回类型保持为`Functor`。我们需要这样做，因为 PHP 类型引擎不支持一种称为**返回类型协变**的特性。如果支持的话，我们可以指定一个更专门的类型（即子类型）作为返回值。

`map`函数是使用上述函数实现的。首先我们使用`pure`方法封装我们的`callable`，然后将这个新的 applicative 应用于实际值。没有什么特别的。

让我们测试我们的实现：

```php
<?php 

$five = IdentityApplicative::pure(5); 
$ten = IdentityApplicative::pure(10); 
$applicative = IdentityApplicative::pure($add); 

echo $applicative->apply($five)->apply($ten)->get(); 
// 15 

$hello = IdentityApplicative::pure('Hello world!'); 

echo IdentityApplicative::pure('strtoupper')->apply($hello)->get(); 
// HELLO WORLD! echo $hello->map('strtoupper')->get(); 
// HELLO WORLD! 
```

一切似乎都运行正常。我们甚至能够验证我们的 map 实现似乎是正确的。

与 functor 一样，我们可以创建最简单的`Applicative`类抽象：

```php
<?php 

class IdentityApplicative extends Applicative 
{ 
    private $value; 

    protected function __construct($value) 
    { 
        $this->value = $value; 
    } 

    public static function pure($value): Applicative 
    { 
        return new static($value); 
    } 

    public function apply(Applicative $f): Applicative 
    { 
        return static::pure($this->get()($f->get())); 
    } 

    public function get() 
    { 
        return $this->value; 
    } 
} 
```

## Applicative 法则

applicative 的第一个重要属性是它们是*封闭的组合*，意味着 applicative 将返回相同类型的新 applicative。此外，apply 方法接受自己类型的 applicative。我们无法使用 PHP 类型系统来强制执行这一点，所以你需要小心，否则可能会在某个时候出现问题。

还需要遵守以下规则才能拥有一个正确的 applicative functor。我们将首先详细介绍它们，然后稍后验证它们对我们的`IdentityApplicative`类是否成立。

### 映射

*纯（f）->应用 == map（f）*

使用 applicative 应用函数与对其进行映射是相同的。这个法则简单地告诉我们，我们可以在以前使用 functor 的任何地方使用 applicative。切换到 applicative 不会使我们失去任何权力。

实际上，这并不是一个法则，因为它可以从以下四个法则中推导出来。但由于这并不明显，为了让事情更清晰，让我们来陈述一下。

### 身份

*纯（id）->应用（$x）== id（$x）*

应用恒等函数不会改变值。与 functor 的身份法则一样，这确保`apply`方法除了应用函数之外不会发生任何隐藏的转换。

### 同态

*纯（f）->应用（$x）==纯（f（$x））*

创建一个 applicative functor 并将其应用于一个值与首先在值上调用函数，然后在 functor 中封装它具有相同的效果。

这是一个重要的法则，因为我们深入研究 applicative 的第一个动机是使用柯里化函数而不是一元函数。这个法则确保我们可以在任何阶段创建我们的 applicative，而不需要立即封装我们的函数。

### 交换

*纯（f）->应用（$x）==纯（function（$f）{ $f（$x）; }）->应用（f）*

这个有点棘手。它声明对值应用函数与创建一个提升值的 applicative functor 并将其应用于函数是相同的。在这种情况下，提升值是围绕该值的闭包，它将在其上调用给定的函数。该法则确保纯函数除了封装给定值之外不执行任何修改。

### 组合

*纯（组合）->应用（f1）->应用（f2）->应用（$x）==纯（f1）->应用（纯（f2）->应用（$x））*

这种法律的简化版本可以用*pure(compose(f1, f2))->apply($x)*来写在左边。它简单地陈述了 functors 的组合法则，即你可以将两个函数的组合版本应用到你的值上，或者分别调用它们。这确保你可以对 functors 执行相同的优化。

### 验证法律是否成立

正如我们对 functors 所看到的，强烈建议测试你的实现是否符合所有法律。这可能是一个非常乏味的过程，特别是如果你有四个。因此，我们不要手动执行检查，让我们写一个辅助程序：

```php
<?php 

function check_applicative_laws(Applicative $f1, callable $f2, $x) 
{ 
    $identity = function($x) { return $x; }; 
    $compose = function(callable $a) { 
        return function(callable $b) use($a) { 
            return function($x) use($a, $b) { 
                return $a($b($x)); 
            }; 
        }; 
    }; 

    $pure_x = $f1->pure($x); 
    $pure_f2 = $f1->pure($f2); 

    return [ 
        'identity' => 
            $f1->pure($identity)->apply($pure_x) == 
            $pure_x, 
        'homomorphism' => 
            $f1->pure($f2)->apply($pure_x) == 
            $f1->pure($f2($x)), 
        'interchange' => 
            $f1->apply($pure_x) == 
            $f1->pure(function($f) use($x) { return $f($x); })->apply($f1), 
        'composition' => 
            $f1->pure($compose)->apply($f1)->apply($pure_f2)->apply($pure_x) == 
            $f1->apply($pure_f2->apply($pure_x)), 
        'map' => 
            $pure_f2->apply($pure_x) == 
            $pure_x->map($f2) 
    ]; 
} 
```

`identity`和`compose`函数在辅助程序中声明，因此它是完全自包含的，你可以在各种情况下使用它。此外，`functional-php`库中的`compose`函数不适用，因为它不是柯里化的，它接受可变数量的参数。

此外，为了避免有很多争论，我们使用`Applicative`类的一个实例，这样我们就可以有一个第一个函数和要检查的类型，然后是一个`callable`和一个将被提升到 applicative 并在必要时使用的值。

这种选择限制了我们可以使用的函数，因为值必须与两个函数的参数类型匹配；第一个函数还必须返回相同类型的参数。如果这对你来说太过约束，你可以决定扩展辅助程序，以接受另外两个参数，第二个 applicative 和一个提升的值，并在必要时使用它们。

让我们验证我们的`IdentityApplicative`类：

```php
<?php 

print_r(check_applicative_laws( 
IdentityApplicative::pure('strtoupper'), 
    'trim', 
    ' Hello World! ' 
)); 
// Array 
// ( 
//     [identity] => 1 
//     [homomorphism] => 1 
//     [interchange] => 1 
//     [composition] => 1 
//     [map] => 1 
// ) 
```

很好，一切似乎都很好。如果你想使用这个辅助程序，你需要选择兼容的函数，因为你可能会遇到一些缺乏清晰度的错误消息，因为我们无法确保第一个函数的返回值类型与第二个函数的第一个参数类型匹配。

由于这种自动检查可以极大地帮助，让我们迅速地为 functors 编写相同类型的函数：

```php
<?php 

function check_functor_laws(Functor $func, callable $f, callable $g) 
{ 
    $id = function($a) { return $a; }; 
    $composed = function($a) use($f, $g) { return $g($f($a)); }; 

    return [ 
        'identity' => $func->map($id) == $id($func), 
        'composition' => $func->map($f)->map($g) == $func->map($composed) 
    ]; 
} 
```

并检查我们从未测试过的`IdentityFunctor`：

```php
<?php 

print_r(check_functor_laws( 
    new IdentityFunctor(10), 
    function($a) { return $a * 10; }, 
    function($a) { return $a + 2; } 
)); 
// Array 
// ( 
//     [identity] => 1 
//     [composition] => 1 
// ) 
```

好的，一切都很好。

## 使用 applicatives

正如我们已经看到的，数组是 functors，因为它们有一个`map`函数。但是一个集合也很容易成为 applicative。让我们实现一个`CollectionApplicative`类：

```php
<?php 

class CollectionApplicative extends Applicative implements IteratorAggregate 
{ 
    private $values; 

    protected function __construct($values) 
    { 
        $this->values = $values; 
    } 

    public static function pure($values): Applicative 
    { 
        if($values instanceof Traversable) { 
            $values = iterator_to_array($values); 
        } else if(! is_array($values)) { 
            $values = [$values]; 
        } 

        return new static($values); 
    } 

    public function apply(Applicative $data): Applicative 
    { 
        return $this->pure(array_reduce($this->values, 
            function($acc, callable $function) use($data) { 
                return array_merge($acc, array_map($function, $data->values) ); 
            }, []) 
        ); 
    } 

    public function getIterator() { 
        return new ArrayIterator($this->values); 
    } 
} 
```

正如你所看到的，这一切都相当容易。为了简化我们的生活，我们只需将不是集合的任何东西包装在一个数组中，并将`Traversable`接口的实例转换为真正的数组。这段代码显然需要一些改进才能用于生产，但对于我们的小演示来说已经足够了：

```php
<?php 

print_r(iterator_to_array(CollectionApplicative::pure([ 
  function($a) { return $a * 2; }, 
  function($a) { return $a + 10; } 
])->apply(CollectionApplicative::pure([1, 2, 3])))); 
// Array 
// ( 
//     [0] => 2 
//     [1] => 4 
//     [2] => 6 
//     [3] => 11 
//     [4] => 12 
//     [5] => 13 
// ) 
```

这里发生了什么？我们的 applicative 中有一个函数列表，我们将其应用到一个数字列表。结果是一个新的列表，每个函数都应用到每个数字上。

这个小例子并不是真正有用的，但这个想法可以应用到任何事情上。想象一下，你有一种图库应用，用户可以上传一些图像。你还有各种处理你想对这些图像进行的处理：

+   限制最终图像的大小，因为用户倾向于上传过大的图像

+   为索引页面创建一个缩略图

+   为移动设备创建一个小版本

你唯一需要做的就是创建一个包含所有函数的数组，一个包含上传图像的数组，并将我们刚刚对数字做的相同模式应用到它们。然后你可以使用`functional-php`库中的 group 函数将你的图像重新分组在一起：

```php
<?php 

use function Functional\group; 

function limit_size($image) { return $image; } 
function thumbnail($image) { return $image.'_tn'; } 
function mobile($image) { return $image.'_small'; } 

$images = CollectionApplicative::pure(['one', 'two', 'three']); 

$process = CollectionApplicative::pure([ 
  'limit_size', 'thumbnail', 'mobile' 
]); 

$transformed = group($process->apply($images), function($image, $index) { 
    return $index % 3; 
}); 
```

我们使用转换后的数组中的索引来将图像重新分组。每三个图像是限制的，每四个是缩略图，最后是移动版本。结果如下所示：

```php
<?php 

print_r($transformed); 
// Array 
// ( 
//     [0] => Array 
//         ( 
//             [0] => one 
//             [3] =>one_tn 
//             [6] =>one_small 
//         ) 
// 
//     [1] => Array 
//         ( 
//             [1] => two 
//             [4] =>two_tn 
//             [7] =>two_small 
//         ) 
// 
//     [2] => Array 
//         ( 
//             [2] => three 
//             [5] =>three_tn 
//             [8] =>three_small 
//         ) 
// 
//) 
```

在这个阶段，你可能会渴望更多，但你需要耐心。让我们先完成本章的理论，我们很快就会在下一章看到更有力的例子。

# 单子

现在我们对应用函子有了一定的了解，在谈论单子之前，我们需要在这个谜题中增加最后一块，即单子。再次，这个概念来自范畴论的数学领域。

**单子**是任何类型和该类型上的二元操作的组合，具有关联的身份元素。例如，以下是一些组合，您可能从未预料到它们是单子：

+   整数和加法操作，其身份是 0，因为*$i + 0 == $i*

+   整数和乘法操作，其身份是 1，因为*$i * 1 == $i*

+   数组和合并操作，其身份是空数组，因为*array_merge($a, []) == $a*

+   字符串和连接操作，其身份是空字符串，因为*$s . '' == $s*

在本章的其余部分，让我们称我们的操作为*op*，身份元素为*id*。`op`调用来自操作或操作员，并在多种语言的`Monoid`实现中使用。Haskell 使用术语**mempty**和**mappend**以避免与其他函数名称冲突。有时使用零代替*id*或身份。

单子还必须遵守一定数量的法则，确切地说是两个。

## 身份法则

*$a op id == id op $a == $a*

第一个法则确保了身份可以在操作符的两侧使用。身份元素只有在作为操作符的右手或左手侧应用时才能起作用。例如，对矩阵的操作就是这种情况。在这种情况下，我们谈论左和右身份元素。在`Monoid`的情况下，我们需要一个双侧身份，或者简单地说是身份。

对于大多数身份法则，验证`Monoid`实现可以确保我们正确应用操作符而没有其他副作用。

## 结合律

*($a op $b) op $c == $a op ($b op $c)*

这项法律保证了我们可以按任何顺序重新组合我们对操作员的呼叫，只要其他一些操作没有交错。这很重要，因为它允许我们推理可能的优化，并确保结果是相同的。

知道一系列操作是可结合的；您还可以将序列分成多个部分，将计算分布到多个线程、核心或计算机上，当所有中间结果出现时，将它们之间的操作应用以获得最终结果。

## 验证法则

让我们验证一下我们之前谈到的单子的法则。首先是整数加法：

```php
<?php 

$a = 10; $b = 20; $c = 30; 

var_dump($a + 0 === $a); 
// bool(true) 
var_dump(0 + $a === $a); 
// bool(true) 
var_dump(($a + $b) + $c === $a + ($b + $c)); 
// bool(true) 
```

然后，整数乘法：

```php
<?php 

var_dump($a * 1 === $a); 
// bool(true) 
var_dump(1 * $a === $a); 
// bool(true) 
var_dump(($a * $b) * $c === $a * ($b * $c)); 
// bool(true) 
```

然后数组合并如下：

```php
<?php 

$v1 = [1, 2, 3]; $v2 = [5]; $v3 = [10]; 

var_dump(array_merge($v1, []) === $v1); 
// bool(true) 
var_dump(array_merge([], $v1) === $v1); 
// bool(true) 
var_dump( 
array_merge(array_merge($v1, $v2), $v3) === 
array_merge($v1, array_merge($v2, $v3)) 
); 
// bool(true) 
```

最后，字符串连接：

```php
<?php 

$s1 = "Hello"; $s2 = " World"; $s3 = "!"; 

var_dump($s1 . '' === $s1); 
// bool(true) 
var_dump('' . $s1 === $s1); 
// bool(true) 
var_dump(($s1 . $s2) . $s3 == $s1 . ($s2 . $s3)); 
// bool(true) 
```

很好，我们所有的单子都遵守这两个法则。

减法或除法呢？它们也是单子吗？很明显，0 是减法的身份，1 是除法的身份，但结合性呢？

考虑以下检查减法或除法的结合性：

```php
<?php

var_dump(($a - $b) - $c === $a - ($b - $c));
// bool(false)
var_dump(($a / $b) / $c === $a / ($b / $c));
// bool(false) 
```

我们清楚地看到，减法和除法都不是可结合的。在处理这种抽象时，始终重要的是使用法则来测试我们的假设。否则，重构或调用某个期望`Monoid`的函数可能会出现严重问题。显然，对于函子和应用函子也是如此。

## 单子有什么用？

老实说，单子本身并不是真正有用的，特别是在 PHP 中。最终，在一种语言中，您可以声明新的操作符或重新定义现有的操作符，您可以确保它们的结合性和存在单子。但即使如此，也没有真正的优势。

另外，如果语言可以自动分配使用`Monoid`的运算，那将是加快漫长计算的一个很好的方法。但我不知道任何语言，即使是学术语言，目前都能做到这一点。一些语言执行操作重新排序以提高效率，但仅此而已。显然，PHP 不能做任何这些，因为幺半群的概念不在核心中。

那么为什么要费心呢？因为幺半群可以与高阶函数和一些我们将在后面发现的构造一起使用，以充分利用它们的法律。此外，由于 PHP 不允许我们像 Haskell 那样使用现有的运算符作为函数，例如，我们之前不得不定义`add`之类的函数。相反，我们可以定义一个`Monoid`类。它将具有与我们的简单函数相同的效用，并添加一些很好的属性。

冒昧地说，明确声明一个操作是幺半群可以减轻认知负担。使用幺半群时，您可以确保操作是可结合的，并且遵守双边单位。

## 一个幺半群的实现

PHP 不支持泛型，因此我们无法正式地编码我们的`Monoid`的类型信息。您将不得不选择一个不言自明的名称或者清楚地记录这是什么类型。

另外，由于我们希望我们的实现能够替换诸如`add`之类的函数，我们需要在我们的类上添加一些额外的方法来允许这种用法。让我们看看我们能做些什么：

```php
<?php 

abstract class Monoid 
{ 
    public abstract static function id(); 
    public abstract static function op($a, $b); 

    public static function concat(array $values) 
    { 
        $class = get_called_class(); 
        return array_reduce($values, [$class, 'op'], [$class, 'id']()); 
    } 

    public function __invoke(...$args) 
    { 
        switch(count($args)) { 
            case 0: throw new RuntimeException("Except at least 1 parameter"); 
            case 1: 
                return function($b) use($args) { 
                    return static::op($args[0], $b); 
                }; 
            default: 
                return static::concat($args); 
        } 
    } 
} 
```

显然，我们的`id`和`op`函数声明为抽象，因为它们将是我们每个幺半群的特定部分。

拥有`Monoid`的一个主要优势是可以轻松地折叠具有`Monoid`类类型的值的集合。这就是为什么我们创建`concat`方法作为一个辅助方法来做到这一点。

最后，我们有一个`__invoke`函数，以便我们的`Monoid`可以像普通函数一样使用。该函数以一种特定的方式进行柯里化。如果您在第一次调用时传递了多个参数，`concat`方法将被用于立即返回结果。否则，只有一个参数，您将得到一个等待第二个参数的新函数。

既然我们在这里，让我们编写一个检查法律的函数：

```php
<?php 

function check_monoid_laws(Monoid $m, $a, $b, $c) 
{ 
    return [ 
        'left identity' => $m->op($m->id(), $a) == $a, 
        'right identity' => $m->op($a, $m->id()) == $a, 
        'associativity' => 
            $m->op($m->op($a, $b), $c) == 
            $m->op($a, $m->op($b, $c)) 
    ]; 
} 
```

## 我们的第一个幺半群

让我们为我们之前看到的情况创建幺半群，并演示我们如何使用它们：

```php
<?php 

class IntSum extends Monoid 
{ 
    public static function id() { return 0; } 
    public static function op($a, $b) { return $a + $b; } 
} 

class IntProduct extends Monoid 
{ 
    public static function id() { return 1; } 
    public static function op($a, $b) { return $a * $b; } 
} 

class StringConcat extends Monoid 
{ 
    public static function id() { return ''; } 
    public static function op($a, $b) { return $a.$b; } 
} 

class ArrayMerge extends Monoid 
{ 
    public static function id() { return []; } 
    public static function op($a, $b) { return array_merge($a, $b); } 
} 
```

让我们验证它们的法律：

```php
<?php 

print_r(check_monoid_laws(new IntSum(), 5, 10, 20)); 
// Array 
// ( 
//     [left identity] => 1 
//     [right identity] => 1 
//     [associativity] => 1 
// ) 

print_r(check_monoid_laws(new IntProduct(), 5, 10, 20)); 
// Array 
// ( 
//     [left identity] => 1 
//     [right identity] => 1 
//     [associativity] => 1 
// ) 

print_r(check_monoid_laws(new StringConcat(), "Hello ", "World", "!")); 
// Array 
// ( 
//     [left identity] => 1 
//     [right identity] => 1 
//     [associativity] => 1 
// ) 

print_r(check_monoid_laws(new ArrayMerge(), [1, 2, 3], [4, 5], [10])); 
// Array 
// ( 
//     [left identity] => 1 
//     [right identity] => 1 
//     [associativity] => 1 
// ) 
```

举个例子，让我们尝试创建一个减法的幺半群并检查法律：

```php
<?php 

class IntSubtraction extends Monoid 
{ 
    public static function id() { return 0; } 
    public static function op($a, $b) { return $a - $b; } 
} 

print_r(check_monoid_laws(new IntSubtraction(), 5, 10, 20)); 
// Array 
// ( 
//     [left identity] => 
//     [right identity] => 1 
//     [associativity] => 
// ) 
```

如预期的那样，结合律失败了。我们还有一个左单位的问题，因为 *0 - $a == -$a*。所以让我们不要忘记测试我们的幺半群，以确保它们是正确的。

关于布尔类型，可以创建两个有趣的幺半群：

```php
<?php 

class Any extends Monoid 
{ 
    public static function id() { return false; } 
    public static function op($a, $b) { return $a || $b; } 
} 

class All extends Monoid 
{ 
    public static function id() { return true; } 
    public static function op($a, $b) { return $a && $b; } 
} 

print_r(check_monoid_laws(new Any(), true, false, true)); 
// Array 
// ( 
//     [left identity] => 1 
//     [right identity] => 1 
//     [associativity] => 1 
// ) 

print_r(check_monoid_laws(new All(), true, false, true)); 
// Array 
// ( 
//     [left identity] => 1 
//     [right identity] => 1 
//     [associativity] => 1 
// ) 
```

这两个幺半群使我们能够验证是否至少满足一个条件或所有条件。这些是`functional-php`库中`every`和`some`函数的幺半群版本。这两个幺半群与求和和乘积的作用相同，因为 PHP 不允许我们将布尔运算符用作函数：

```php
<?php 

echo Any::concat([true, false, true, false]) ? 'true' : 'false'; 
// true 

echo All::concat([true, false, true, false]) ? 'true' : 'false'; 
// false 
```

当您需要以编程方式创建一系列条件时，它们可能会很有用。只需将它们提供给`Monoid`，而不是迭代所有条件来生成结果。您还可以编写一个*none*幺半群作为练习，以查看您是否理解了这个概念。

## 使用幺半群

使用我们的新幺半群最明显的方法之一是折叠一组值：

```php
<?php 

$numbers = [1, 23, 45, 187, 12]; 
echo IntSum::concat($numbers); 
// 268 

$words = ['Hello ', ', ', 'my ', 'name is John.']; 
echo StringConcat::concat($words); 
// Hello , my name is John. $arrays = [[1, 2, 3], ['one', 'two', 'three'], [true, false]]; 
print_r(ArrayMerge::concat($arrays)); 
// [1, 2, 3, 'one', 'two', 'three', true, false] 
```

这个属性非常有趣，以至于大多数函数式编程语言都实现了`Foldable`类型的想法。这样的类型需要有一个关联的幺半群。借助我们刚刚看到的属性，该类型可以很容易地折叠。然而，将这个想法移植到 PHP 是困难的，因为我们将缺少改进使用`concat`方法所需的语法糖。

您还可以将它们用作`callable`类型，并将它们传递给高阶函数：

```php
<?php 

use function Functional\compose; 

$add = new IntSum(); 
$times = new IntProduct(); 

$composed = compose($add(5), $times(2)); 
echo $composed(2); 
// 14 
```

显然，这不仅限于 compose 函数。您可以重写本书中使用`add`函数的所有先前示例，并使用我们的新`Monoid`代替。

随着我们在本书中的进展，我们将看到更多与我们尚未发现的功能技术相关联的单子的使用方式。

# 单子

我们开始学习函子，它是一组可以映射的值。然后我们介绍了应用函子的概念，它允许我们将这些值放入特定的上下文并对它们应用函数，同时保留上下文。我们还快速讨论了幺半群及其属性。

有了所有这些先前的知识，我们终于准备好开始单子的概念了。正如 James Iry 在*编程语言简史*中幽默地指出的那样：

> *单子是自函子范畴中的幺半群，有什么问题吗？*

这句虚构的引语归功于 Philip Wadler，他是 Haskell 规范的最初参与者之一，也是单子使用的倡导者，可以在[`james-iry.blogspot.com/2009/05/brief-incomplete-and-mostly-wrong.html`](http://james-iry.blogspot.com/2009/05/brief-incomplete-and-mostly-wrong.html)找到其上下文。

如果没有一些范畴论的知识，很难清楚地解释这句话到底是什么意思，特别是因为它是虚构的，故意模糊以至于有趣。可以说，单子类似于幺半群，因为它们大致共享相同的法则集。此外，它们直接与函子和应用相关联。

单子，就像函子一样，充当某种值的容器。此外，就像应用程序一样，您可以将函数应用于封装的值。这三种模式都是将一些数据放入上下文的一种方式。但是，两者之间有一些区别：

+   应用封装了一个函数。单子和函子封装了一个值。

+   应用程序使用返回非提升值的函数。单子使用返回相同类型的单子的函数。

由于函数也是有效值，这并不意味着两者不兼容，只是意味着我们需要为我们的单子类型定义一个新的 API。但是，我们可以自由地扩展 Applicative，因为它在单子上下文中包含完全有效的方法：

```php
<?php 

abstract class Monad extends Applicative 
{ 
    public static function return($value): Monad 
    { 
        return static::pure($value); 
    } 

    public abstract function bind(callable $f): Monad; 
} 
```

我们的实现非常简单。我们将 pure 与 Haskell 中的 return 别名，这样人们就不会迷失。请注意，它与您习惯的 return 关键字无关；它只是将值放入单子的上下文中。我们还定义了一个新的绑定函数，它以`callable`类型作为参数。

由于我们不知道内部值将如何存储，并且由于 PHP 类型系统的限制，我们无法实现`apply`或`bind`函数，尽管它们应该是非常相似的：

+   `apply`方法接受一个包装在`Applicative`类中的值，并将存储的函数应用于它

+   `bind`方法接受一个函数并将其应用于存储的值

两者之间的区别在于`bind`方法需要直接返回值，而`apply`方法首先再次使用`pure`或`return`函数包装值。

正如您可能已经了解的那样，使用不同语言的人倾向于以稍有不同的方式命名事物。这就是为什么有时您会看到`bind`方法被称为**chain**或**flatMap**，这取决于您正在查看的实现。

## 单子定律

你现在知道了；单子必须遵守一些法则才能被称为单子。这些法则与幺半群的法则相同-单位元和结合律。因此，单子的所有有用属性也适用于单子。

然而，正如你将看到的，我们将描述的法则似乎与我们之前为单子看到的幂等性和结合性法则没有任何共同之处。这与我们定义的`bind`和`return`函数的方式有关。使用一种叫做**Kleisli**组合操作符，我们可以转换这些法则，使它们看起来有点像我们之前看到的那些。然而，这有点复杂，对我们的目的毫无用处。如果你想了解更多，我可以引导你到[`wiki.haskell.org/Monad_laws`](https://wiki.haskell.org/Monad_laws)。

### 左单位元

*return(x)->bind(f) == f(x)*

这个法则规定，如果你取一个值，将其包装在单子的上下文中，并将其绑定到*f*，结果必须与直接在值上调用函数的结果相同。它确保`bind`方法对函数和值除了应用之外没有任何副作用。

这只有在`bind`方法不像`apply`方法那样再次将函数的返回值包装在单子内时才成立。这是函数的工作。

### 右单位元

*m->bind(return) == m*

这个法则规定，如果你将返回的值绑定到一个单子，你将得到你的单子。它确保`return`除了将值放入单子的上下文之外没有其他影响。

### 结合性

*m->bind(f)->bind(g) == m->bind((function($x) { f($x)->bind(g); })*

这些法则规定，你可以先将单子内的值绑定到*f*，然后再绑定到*g*，或者你可以将其绑定到第一个函数与第二个函数的组合。我们需要一个中间函数来模拟这一点，就像我们在 applicatives 的交换法则中需要一个中间函数一样。

这个法则允许我们获得与之前的结合性和组合性法则相同的好处。这种形式有点奇怪，因为单子保存的是值，而不是函数或操作符。

### 验证我们的单子

让我们写一个函数来检查单子的有效性：

```php
<?php 

function check_monad_laws($x, Monad $m, callable $f, callable $g) 
{ 
    return [ 
        'left identity' => $m->return($x)->bind($f) == $f($x), 
        'right identity' => $m->bind([$m, 'return']) == $m, 
        'associativity' => 
            $m->bind($f)->bind($g) ==             $m->bind(function($x) use($f, $g) { return $f($x)->bind($g); }), 
    ]; 
} 
```

我们还需要一个单位单子：

```php
class IdentityMonad extends Monad 
{ 
    private $value; 

    private function __construct($value) 
    { 
        $this->value = $value; 
    } 

    public static function pure($value): Applicative 
    { 
        return new static($value); 
    } 

    public function get() 
    { 
        return $this->value; 
    } 

    public function bind(callable $f): Monad 
    { 
        return $f($this->get()); 
    } 

    public function apply(Applicative $a): Applicative 
    { 
        return static::pure($this->get()($a->get())); 
    } 
} 
```

最后我们可以验证一切是否成立：

```php
<?php 

print_r(check_monad_laws( 
    10, 
IdentityMonad::return(20), 
    function(int $a) { return IdentityMonad::return($a + 10); }, 
    function(int $a) { return IdentityMonad::return($a * 2); } 
)); 
// Array 
// ( 
//     [left identity] => 1 
//     [right identity] => 1 
//     [associativity] => 1 
// ) 
```

## 为什么要使用单子？

第一个原因是实际的。当你使用 applicative 应用一个函数时，结果会自动放入 applicative 的上下文中。这意味着，如果你有一个返回 applicative 的函数，并应用它，结果将是一个 applicative 内部的 applicative。任何看过电影《盗梦空间》的人都知道，把东西放在东西里面并不总是一个好主意。

单子是一种避免这种不必要嵌套的方式。`bind`函数将封装返回值的任务委托给函数，这意味着你只会有一层深度。

单子也是一种执行流程控制的方式。正如我们所见，函数式程序员倾向于避免使用循环或任何其他类型的控制流，比如使你的代码更难以理解的`if`条件。单子是一种强大的方式，以一种非常表达性的方式来顺序转换，同时保持你的代码整洁。

像 Haskell 这样的语言还有特定的语法糖来处理单子，比如`do`符号，这使得你的代码更容易阅读。一些人尝试在 PHP 中实现这样的东西，但在我看来并没有取得太大的成功。

然而，要真正理解单子抽象的力量，你必须看一些具体的实现，就像我们将在下一章中所做的那样。它们将允许我们以纯函数的方式执行*IO*操作，将日志消息从一个函数传递到另一个函数，甚至使用纯函数计算随机数。

## 关于单子的另一种看法

我们决定实现我们的`Monad`类，将`apply`和`bind`方法都留为抽象的。我们别无选择，因为值在`Monad`类内部的存储方式将只在`child`类中决定。

然而，正如我们已经说过的，`bind`方法有时在 Scala 中被称为 flatMap。顾名思义，这只是 map 和一个叫做`flatten`的函数的组合。

你明白我要说什么了吗？还记得嵌套应用的问题吗？我们可以添加一个`flatten`函数，或者像 Haskell 称呼的那样，将它作为`Monad`类的方法，而不是将`bind`作为一个抽象方法，我们可以使用`map`和我们的新方法来实现它。

我们仍然需要实现两种方法，但是两者不再做大致相同的工作，调用一个带有值的函数，一个将继续执行，另一个将负责解除`Monad`实例的嵌套。

因此，这样的函数对外部世界的用途有限，我决定使用所提供的实现。使用`flatten`函数进行实现是一个不错的练习，您可以尝试解决以更好地理解单子的工作原理。

## 一个快速的单子示例

想象一下，我们需要使用`read_file`函数读取文件的内容，然后使用`post`函数将其发送到**webservice**。我们将创建两个版本的上传函数来实现这一点：

+   第一个版本将使用传统函数，在出现错误的情况下返回布尔值`false`。

+   功能版本将假定返回`Either`单子实例的柯里化函数。我们将在下一章中进一步描述这个单子；让我们假设它的工作原理与我们之前看到的`Either`类型相同。

在成功的情况下，必须调用给定的回调函数，并返回`post`方法返回的状态码：

```php
<?php 

function upload(string $path, callable $f) { 
    $content = read_file(filename); 
    if($content === false) { 
        return false; 
    } 

    $status = post('/uploads', $content); 
    if($status === false) { 
        return $false; 
    } 

    return $f($status); 
} 
```

现在是功能版本，如下所示：

```php
<?php 

function upload_fp(string $path, callable $f) { 
    return Either::pure($path) 
      ->bind('read_file') 
      ->bind(post('/uploads')) 
      ->bind($f); 
} 
```

我不知道你更喜欢哪一个，但我的选择很明确。使用`Either`而不是`Maybe`的选择也不是无辜的。这意味着在出现错误的情况下，功能版本还可以返回详细的错误消息，而不仅仅是`false`。

# 进一步阅读

如果在完成本章后，您仍然感到有些迷茫，因为这是一个如此重要的话题，不要犹豫阅读以下文章或您自己找到的其他文章：

+   PHP 中关于单子的简要介绍，还有一个相关的库，网址是[`blog.ircmaxell.com/2013/07/taking-monads-to-oop-php.html`](http://blog.ircmaxell.com/2013/07/taking-monads-to-oop-php.html)。

+   Scala 的一个很好的介绍，任何写过一些 Java 的人都应该能理解，网址是[`medium.com/@sinisalouc/demystifying-the-monad-in-scala-cc716bb6f534`](https://medium.com/@sinisalouc/demystifying-the-monad-in-scala-cc716bb6f534)。

+   一个更数学化的视频，网址是[`channel9.msdn.com/Shows/Going+Deep/Brian-Beckman-Dont-fear-the-Monads`](https://channel9.msdn.com/Shows/Going+Deep/Brian-Beckman-Dont-fear-the-Monads)。

+   一个关于单子的幽默 JavaScript 教程。你可能会喜欢也可能会讨厌这种风格。如果你精通 JavaScript，我只能建议你阅读整本书：[`drboolean.gitbooks.io/mostly-adequate-guide/content/ch9.html`](https://drboolean.gitbooks.io/mostly-adequate-guide/content/ch9.html)。

+   一个关于单子的非常完整，尽管有些困难的介绍。需要一些基本的 Haskell 知识才能理解[`wiki.haskell.org/All_About_Monads`](https://wiki.haskell.org/All_About_Monads)中的解释。

# 总结

这一章肯定是一个艰深的话题，但不要害怕，这是最后一个。从现在开始，我们将处理更多实际的主题和真实的应用。第六章，“真实的单子”将介绍我们刚刚学到的抽象的一些有用用途。

抽象，如函子，应用和单子，是函数世界的设计模式。它们是高级抽象，可以在许多不同的地方找到，您需要一些时间才能辨别它们。但是，一旦您对它们有了感觉，您可能会意识到它们无处不在，并且这将极大地帮助您思考如何操纵数据。

我们抽象的法则确实很普遍。在编写代码时，您可能已经在不知不觉中假设了它们。能够识别我们学到的模式将使您在重构或编写算法时更加自信，因为您的直觉总是会得到事实的支持。

如果您想玩玩本章的概念，我只能建议您开始使用我们在第三章中介绍的`functional-php`库进行实验。它包含许多定义各种代数结构的接口，这是数学家给予函子、单子等的花哨名称。一些方法名称可能不完全与我们使用的名称相同，但您应该能够理解它们背后的思想。由于库的名称有点难以找到，这里再次提供链接，[`github.com/widmogrod/php-functional`](https://github.com/widmogrod/php-functional)。


# 第六章：现实生活中的单子

在上一章中，我们涵盖了关于各种抽象的许多理论基础，引导我们到单子的概念。现在是时候应用这些知识，通过介绍一些单子的实例，这些实例将在您日常编码中证明有用。

每个部分都将以解决给定单子的问题的介绍开始，然后是一些用法示例，以便您可以获得一些实践。正如本介绍末尾所解释的那样，书中不会呈现实现本身，而是集中于用法。

正如您将看到的，一旦理论问题解决了，大多数实现对您来说将会显得非常自然。此外，其实用性不仅限于函数式编程的范围。本章中学到的大部分内容都可以应用于任何开发环境。

将要介绍的大多数单子都与副作用的管理有关，或者说一旦它们明确包含在单子中就是影响。在进行函数式编程时，副作用是不受欢迎的。一旦包含，我们就可以控制它们，使它们仅仅成为我们程序的影响。

单子主要用于两个原因。第一个是它们非常适合执行流程控制，正如在上一章中已经解释的那样。第二个是它们的结构允许您轻松地封装效果并保护代码的其余部分免受杂质的影响。

然而，让我们记住，这只是单子的一个可能用途。您可以用这个概念做更多的事情。但是让我们不要过于急躁；我们将在途中发现这一点。

在本章中，我们将涵盖以下主题：

+   单子辅助方法

+   Maybe 和 Either 单子

+   List 单子

+   Writer 单子

+   Reader 单子

+   State 单子

+   IO 单子

为了专注于使用单子，并且由于实现通常不是最重要的部分，我们将使用**PHP Functional**库提供的单子。显然，重要的实现细节将在书中突出显示。您可以使用`composer`调用在您的项目中安装它。

```php
**composer require widmogrod/php-functional**

```

重要的是要注意，`php-functional`库的作者在方法命名和一些实现细节方面做出了其他选择：

+   `apply`方法简单地是`ap`

+   `unit`和`return`关键字在类中被`of`替换

+   继承树有点不同，例如，有`Pointed`和`Chain`接口

+   该库使用特征来共享代码

+   一些辅助函数是在类外实现的，需要单独导入

# 单子辅助方法

在上一章中，我们谈到了`flatten`方法以及它如何用于压缩相同单子实例的多个嵌套级别。这个函数经常被提及，因为它可以用于以另一种方式重写单子。然而，还有其他有用的辅助函数。

## filterM 方法

过滤是函数式编程中的一个关键概念，但是如果我们的过滤函数返回的是一个单子而不是一个简单的布尔值呢？这就是`filterM`方法的用途。该方法不是期望返回一个简单的布尔值的谓词，而是使用任何可以转换为布尔值并且还将结果集合包装在相同单子中的谓词：

```php
<?php 

use function Functional\head; 
use function Functional\tail; 

use Monad\Writer; 

function filterM(callable $f, $collection) 
{ 
    $monad = $f(head($collection)); 

    $_filterM = function($collection) use($monad, $f, &$_filterM){ 
        if(count($collection) == 0) { 
            return $monad->of([]); 
        } 

        $x = head($collection); 
        $xs = tail($collection); 

        return $f($x)->bind(function($bool) use($x, $xs, $monad, $_filterM) { 
            return $_filterM($xs)->bind(function(array $acc) use($bool, $x, $monad) { 
                if($bool) { 
                    array_unshift($acc, $x); 
                } 

                return $monad->of($acc); 
            }); 
        }); 
    }; 
    return $_filterM($collection); 
} 
```

实现有点难以理解，所以我会尝试解释发生了什么：

1.  首先，我们需要了解我们正在处理的单子的信息，因此我们提取我们的集合的第一个元素，并通过应用回调函数从中获取单子。

1.  然后我们声明一个围绕单子和谓词的闭包。

1.  闭包首先测试集合是否为空。如果是这种情况，我们将返回一个包含空数组的单子实例。否则，我们将在集合的第一个元素上运行谓词。

1.  我们将一个包含当前值的闭包绑定到包含布尔值的结果单子上。

1.  第二个闭包递归地遍历整个数组，如果需要的话。

1.  一旦我们到达最后一个元素，我们就会绑定一个新的闭包，它将使用布尔值将值添加到累加器中，或者不添加。

这并不容易，但由于它主要是内部管道工作，再加上 PHP 缺乏语法糖，理解一切并不是必要的。为了比较，这里是使用 Haskell 模式匹配和*do notation*功能实现的相同代码：

```php
filterM :: (Monad m) => (a -> m Bool) -> [a] -> m [a] 
filterM _ []     = return [] 
filterM f (x:xs) = do 
    bool <- f x 
    acc  <- filterM p xs 
    return (if bool then x:acc else acc) 
```

正如您所看到的，这样更容易阅读。我认为任何人都能理解发生了什么。不幸的是，在 PHP 中，我们必须创建嵌套的内部函数才能实现相同的结果。然而，这并不是真正的问题，因为最终的函数非常容易使用。然而，一些功能模式的内部工作有时在 PHP 中可能有点令人不快，并且它们本身并不完全功能。

随着我们发现一些单子，例子将随之而来。这个辅助函数的实现在`php-functional`库中可用。

## foldM 方法

`foldM`方法是`fold`方法的单子版本。它接受一个返回单子的函数，然后产生一个也是单子的值。然而，累加器和集合都是简单的值：

```php
<?php 

function foldM(callable $f, $initial, $collection) 
{ 
    $monad = $f($initial, head($collection)); 

    $_foldM = function($acc, $collection) use($monad, $f, &$_foldM){ 
        if(count($collection) == 0) { 
            return $monad->of($acc); 
        } 

        $x = head($collection); 
        $xs = tail($collection); 

        return $f($acc, $x)->bind(function($result) use($acc,$xs,$_foldM) { 
            return $_foldM($result, $xs); 
        }); 
    }; 

    return $_foldM($initial, $collection); 
} 
```

该实现比`filterM`方法的实现要小一点，因为我们只需要递归；不需要从布尔值到值的转换。同样，我们将在本章的后续部分展示一些例子，并且`php-funcational`库中也有实现。

## 结束语

存在多个其他函数可以增强为与单子值一起使用。例如，您可以使用`zipWithM`方法，它使用返回单子的合并函数合并两个集合。`php-functional`库有一个`mcompose`的实现，它允许您组合返回相同单子实例的函数。

当您在使用单子时发现某种重复模式时，不要犹豫将其因式分解为辅助函数。它可能经常会派上用场。

# Maybe 和 Either 单子

您应该已经非常清楚我们已经多次讨论过的 Maybe 和 Either 类型。我们首先定义了它们，然后我们了解到它们实际上是一个函子的完美例子。

我们现在将更进一步，将它们定义为单子，这样我们将能够在更多情况下使用它们。

## 动机

`Maybe`单子代表了一种计算序列随时可能停止返回有意义值的想法，使用我们在前一章中定义的`Nothing`类。当转换链相互依赖并且某些步骤可能无法返回值时，它特别有用。它允许我们避免通常伴随这种情况的可怕的`null`检查。

`Either`单子大部分具有相同的动机。微小的区别在于步骤通常要么抛出异常，要么返回错误，而不是空值。操作失败意味着我们需要存储由`Left`值表示的错误消息，而不是`Nothing`值。

## 实现

Maybe 和 Either 类型的代码可以在`php-functional`库中找到。实现非常简单-与我们自己先前的实现的主要区别是缺少`isJust`和`isNothing`等方法，并且实例是使用辅助函数构造而不是静态工厂。

重要的是要注意，`php-functional`库中实现的 Either 单子不幸地没有自己处理捕获异常。您要么应用的函数，要么绑定到它的函数必须自行正确处理异常。您还可以使用`tryCatch`辅助函数来为您执行此操作。

## 例子

为了更好地理解`Maybe`单子的工作原理，让我们看一些例子。`php-functional`库使用辅助函数而不是类上的静态方法来创建新实例。它们位于`Widmogrod\Monad\Maybe`命名空间中。

另一个非常有用的辅助函数是`maybe`方法，它是一个带有以下签名的柯里化函数-`maybe($default, callable $fn, Maybe $maybe)`命名空间。当调用时，它将首先尝试从`$maybe`变量中提取值，并默认为`$default`变量。然后将其作为参数传递给`$fn`变量：

```php
<?php 

use Widmogrod\Monad\Maybe as m; 
use Widmogrod\Functional as f; 

$just = m\just(10); 
$nothing = m\nothing(); 

$just = m\maybeNull(10); 
$nothing = m\maybeNull(null); 

echo maybe('Hello.', 'strtoupper', m\maybe('Hi!')); 
// HI! echo maybe('Hello.', 'strtoupper', m\nothing()); 
// HELLO. 
```

既然辅助函数已经完成，我们将演示如何将`Maybe`单子与`foldM`方法结合使用：

```php
<?php 

$divide = function($acc, $i) { 
    return $i == 0 ? nothing() : just($acc / $i); 
}; 

var_dump(f\foldM($divide, 100, [2, 5, 2])->extract()); 
// int(5) 

var_dump(f\foldM($divide, 100, [2, 0, 2])->extract()); 
// NULL 
```

使用传统函数和`array_reduce`方法来实现这一点，结果大多会非常相似，但它很好地演示了`foldM`方法的工作原理。由于折叠函数绑定到每次迭代的当前单子值，一旦我们有一个空值，接下来的步骤将继续返回空值，直到结束。同样的函数也可以用来返回其他类型的单子，以便还包含有关失败的信息。

我们之前已经看到单子类型如何用于在可能存在或不存在的值上链接多个函数。然而，如果我们需要使用这个值来获取另一个可能为空的值，我们将有嵌套的`Maybe`实例：

```php
<?php 

function getUser($username): Maybe { 
  return $username == 'john.doe' ? just('John Doe') : nothing(); 
} 

var_dump(just('john.doe')->map('getUser')); 
// object(Monad\Maybe\Just)#7 (1) { 
//     ["value":protected]=> object(Monad\Maybe\Just)#6 (1) { 
//         ["value":protected]=> string(8) "John Doe" 
//     } 
// } 

var_dump(just('jane.doe')->map('getUser')); 
// object(Monad\Maybe\Just)#8 (1) { 
//     ["value":protected]=> object(Monad\Maybe\Nothing)#6 (0) { } 
// } 
```

在这种情况下，您可以使用`flatten`方法，或者简单地使用`bind`方法而不是`map`方法：

```php
<?php 

var_dump(just('john.doe')->bind('getUser')); 
// object(Monad\Maybe\Just)#6 (1) { 
//     ["value":protected]=> string(8) "John Doe" 
// } 

var_dump(just('jane.doe')->bind('getUser')); 
// object(Monad\Maybe\Nothing)#8 (0) { } 
```

我同意`Maybe`单子的例子有点令人失望，因为大多数用法已经在之前的单子中描述过了，因此创建`Maybe`单子本身并不会增加功能，它只会允许我们使用其他期望单子的模式；功能与以前一样。

`Either`单子也可以做类似的情况；这就是为什么这里不会有新的例子。只需确保查看辅助函数，而不是在想要使用单子时重写管道。

# 列表单子

列表或集合单子代表了所有以集合作为参数并返回零个、一个或多个值的函数的范畴。该函数应用于输入列表中的所有可能值，并将结果连接起来生成一个新的集合。

重要的是要理解列表单子实际上并不代表一个简单的值列表，而是代表单子的所有不同可能值的列表。这个想法通常被描述为*非确定性*。正如我们在`CollectionApplicative`函数中看到的，当您将一组函数应用于一组值时，这可能会导致有趣的结果。我们将尝试在例子中扩展这个主题以澄清这一点。

## 动机

列表单子体现了这样一个观念，即在完整计算结束之前，您无法知道最佳结果。它允许我们探索所有可能的解决方案，直到我们有最终的解决方案。

## 实现

单子是在`php-functional`库中以`Collection`方法的名称实现的。这是以一种非常直接的方式完成的。然而，与我们自己以前的实现相比，有两种新方法可用：

+   `reduce`方法将对单子内存储的值执行折叠操作。

+   `traverse`方法将一个返回应用程序的函数映射到单子内存储的所有值。然后将应用程序应用于当前累加器。

## 例子

让我们从一些困难的事情开始，使用我们之前发现的`filterM`方法。我们将创建一个被称为集合的`powerset`。`powerset`集合是给定集合的所有可能子集，或者，如果您愿意，是其成员的所有可能组合：

```php
<?php 

use Monad\Collection; 
use Functional as f; 

$powerset = filterM(function($x) { 
    return Collection::of([true, false]); 
}, [1, 2, 3]); 

print_r($powerset->extract()); 
// Array ( 
//     [0] => Array ( [0] => 1 [1] => 2 [2] => 3 ) 
//     [1] => Array ( [0] => 1 [1] => 2 ) 
//     [2] => Array ( [0] => 1 [1] => 3 ) 
//     [3] => Array ( [0] => 1 ) 
//     [4] => Array ( [0] => 2 [1] => 3 ) 
//     [5] => Array ( [0] => 2 ) 
//     [6] => Array ( [0] => 3 ) 
//     [7] => Array ( ) // ) 
```

### 注意

由于构造函数没有在实际数组内包装另一个数组，所以这目前无法使用 Collection/filterM 的实际实现。请参阅[`github.com/widmogrod/php-functional/issues/31`](https://github.com/widmogrod/php-functional/issues/31)。

这里发生了什么？这似乎是某种黑魔法。事实上，这很容易解释。将函数绑定到集合会导致该函数应用于其所有成员。在这种特殊情况下，我们的过滤函数返回一个包含`true`和`false`值的集合。这意味着`filterM`方法的内部闭包负责用值替换布尔值被运行两次，然后结果被附加到先前创建的所有集合上。让我们看看第一步以使事情更清晰：

1.  过滤首先应用于值`1`，创建两个集合`[]`和`[1]`。

1.  现在过滤器应用于值`2`，创建两个新集合（`[]`和`[2]`），需要附加到我们之前创建的集合上，创建四个集合`[]`，`[1]`，`[2]`，`[1, 2]`。

1.  每一步都会创建两个集合，这些集合将附加到先前创建的集合上，使得集合的数量呈指数级增长。

还不清楚吗？让我们看另一个例子。这一次，试着将集合想象成一棵树，其中每个初始值都是一个分支。当你绑定一个函数时，它被应用于每个分支，如果结果是另一个集合，它就会创建新的分支：

```php
<?php 
use Monad\Collection; 
use Functional as f; 

$a = Collection::of([1, 2, 3])->bind(function($x) { 
    return [$x, -$x]; 
}); 
print_r($a->extract()); 
// Array ( 
//     [0] => 1 
//     [1] => -1 
//     [2] => 2 
//     [3] => -2 
//     [4] => 3 
//     [5] => -3 
// ) 

$b = $a->bind(function($y) { 
    return $y > 0 ? [$y * 2, $y / 2] : $y; 
}); 
print_r($b->extract()); 
// Array ( 
//     [0] => 2 
//     [1] => 0.5 
//     [2] => -1 
//     [3] => 4 
//     [4] => 1 
//     [5] => -2 
//     [6] => 6 
//     [7] => 1.5 
//     [8] => -3 
// ) 
```

为了让事情对你更加复杂一些，第二个函数根据给定的值返回可变数量的元素。让我们将其可视化为一棵树：

![Examples](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/fn-php/img/image_06_001.jpg)

### 骑士可以去哪里？

现在我们对`Collection`单子的工作原理有了很好的理解，让我们来解决一个更困难的挑战。给定国际象棋棋盘上的起始位置，我们想知道骑士棋子在三步内可以到达的所有可能有效位置。

我希望你花一点时间想象一下你会如何实现它。一旦你完成了，让我们尝试使用我们的单子。我们首先需要一种方法来编码我们的骑士位置。一个简单的类就足够了。此外，国际象棋棋盘有八列和八行，所以让我们添加一个检查位置是否有效的方法：

```php
<?php 

class ChessPosition { 
    public $col; 
    public $row; 

    public function __construct($c, $r) 
    { 
        $this->col = $c; 
        $this->row = $r; 
    } 

    public function isValid(): bool 
    { 
        return ($this->col > 0 && $this->col < 9) && 
               ($this->row > 0 && $this->row < 9); 
    } 
} 

function chess_pos($c, $r) { return new ChessPosition($c, $r); } 
```

现在我们需要一个函数，给定一个起始位置，返回骑士的所有有效移动：

```php
<?php 

function moveKnight(ChessPosition $pos): Collection 
{ 
    return Collection::of(f\filter(f\invoke('isValid'), Collection::of([ 
        chess_pos($pos->col + 2, $pos->row - 1), 
        chess_pos($pos->col + 2, $pos->row + 1), 
        chess_pos($pos->col - 2, $pos->row - 1), 
        chess_pos($pos->col - 2, $pos->row + 1), 
        chess_pos($pos->col + 1, $pos->row - 2), 
        chess_pos($pos->col + 1, $pos->row + 2), 
        chess_pos($pos->col - 1, $pos->row - 2), 
        chess_pos($pos->col - 1, $pos->row + 2), 
    ]))); 
} 

print_r(moveKnight(chess_pos(8,1))->extract()); 
// Array ( 
//     [0] => ChessPosition Object ( [row] => 2 [col] => 6 ) 
//     [1] => ChessPosition Object ( [row] => 3 [col] => 7 ) 
// ) 
```

很好，看起来工作得很好。现在我们只需要连续三次绑定这个函数。而且，在此过程中，我们还将创建一个函数，检查骑士是否可以在三步内到达给定位置：

```php
<?php 

function moveKnight3($start): array 
{ 
    return Collection::of($start) 
        ->bind('moveKnight') 
        ->bind('moveKnight') 
        ->bind('moveKnight') 
        ->extract(); 
} 

function canReach($start, $end): bool 
{ 
    return in_array($end, moveKnight3($start)); 
} 

var_dump(canReach(chess_pos(6, 2), chess_pos(6, 1))); 
// bool(true) 

var_dump(canReach(chess_pos(6, 2), chess_pos(7, 3))); 
// bool(false) 
```

唯一剩下的事情就是在真正的国际象棋棋盘上检查我们的函数是否正确工作。我不知道你是如何以命令式的方式做到这一点的，但是我的解决方案比我们现在得到的解决方案要不那么优雅。

如果你想再玩一会儿，你可以尝试参数化移动的次数，或者为其他棋子实现这个功能。正如你将看到的，这只需要进行最小的更改。

# 写作单子

如果你记得的话，纯函数不能有任何副作用，这意味着你不能在其中放置调试语句，例如。如果你像我一样，`var_dump`方法是你的调试工具，那么你只能违反纯度规则或使用其他调试技术。由于函数的所有输出必须通过其返回值，脑海中首先浮现的一个想法是返回一个值元组-原始返回值和你需要的任何调试语句。

然而，这个解决方案非常复杂。想象一下，你有一个函数，它可以将一个数值减半，返回减半后的值和接收到的输入，用于调试目的。现在，如果你想将这个函数与自身组合，创建一个新的函数，返回被四除的值，你还需要修改输入，以便它们可以接受你的新返回格式。这一过程一直持续下去，直到你相应地修改了所有的函数。这也会对柯里化造成一些问题，因为现在你有了一个多余的参数，如果你不关心调试语句，这个参数实际上并不实用。

你正在寻找的解决方案是`Writer`monad。遗憾的是，在撰写本文时，`php-functional`库中还没有实现。

## 动机

Writer monad 用于封装函数的主要返回值旁边的某种相关语句。这个语句可以是任何东西。它经常用于存储生成的调试输出或跟踪信息。手动这样做是繁琐的，可能会导致复杂的管理代码。

`Writer` monad 提供了一种干净的方式来管理这种副输出，并允许你在返回简单值的函数旁边插入返回这种信息的函数。在计算序列结束时，附加值可以被丢弃、显示或根据操作模式进行任何处理。

## 实现

由于 monad 需要连接输出值，任何 monoid 的实例都可以被用作这样。为了简化基于字符串的日志记录，任何字符串也可以被直接管理。显然，使用一个具有缓慢操作的 monoid 将导致性能成本。

`php-functional`库包括一个`StringMonoid`类的实现，每个字符串都将被提升到这个类中。然而，`runWriter`方法将始终返回一个`StringMonoid`类，因此对于使用它的人来说并不奇怪。除此之外，这个实现非常简单直接。

## 示例

正如我们刚才看到的，`Writer`非常适合日志记录。结合`filter`方法，这可以用来理解在过滤函数中发生了什么，而无需倾向于转储值：

```php
<?php 

$data = [1, 10, 15, 20, 25]; 
$filter = function($i) { 
    if ($i % 2 == 1) { 
        return new Writer(false, "Reject odd number $i.\n"); 
    } else if($i > 15) { 
      return new Writer(false, "Reject $i because it is bigger than 15\n"); 
    } 

    return new Writer(true); 
}; 

list($result, $log) = filterM($filter, $data)->runWriter(); 

var_dump($result); 
// array(1) { 
//   [0]=> int(10) 
// } 

echo $log->get(); 
// Reject odd number 1\. // Reject odd number 15\. // Reject 20 because it is bigger than 15 
// Reject odd number 25\. 
```

正如我们所看到的，`Writer` monad 允许我们准确了解为什么某些数字被过滤掉。在这样一个简单的例子中，这可能看起来不像什么，但条件并不总是那么容易理解。

你也可以使用`Writer`来添加更传统的调试信息：

```php
<?php 

function some_complex_function(int $input) 
{ 
    $msg = new StringMonoid('received: '.print_r($input,  true).'.'); 

    if($input > 10) { 
        $w = new Writer($input / 2, $msg->concat(new  StringMonoid("Halved the value. "))); 
    } else { 
        $w = new Writer($input, $msg); 
    } 

    if($input > 20) 
    { 
        return $w->bind('some_complex_function'); 
    } 

    return $w; 
} 

list($value, $log) = (new Writer(15))->bind('some_complex_function')->runWriter(); 
echo $log->get(); 
// received: 15\. Halved the value. list($value, $log) = some_complex_function(27)->runWriter(); 
echo $log->get(); // received: 27\. Halved the value. received: 13\. Halved the value. list($value, $log) = some_complex_function(50)->runWriter(); 
echo $log->get(); 
// received: 50\. Halved the value. received: 25\. Halved the value. received: 12\. Halved the value. 
```

这个 monad 非常适合跟踪有用的信息。此外，它经常避免在你的函数和库代码中留下一些不需要的`var_dump`或`echo`方法。一旦调试完成，留下这些消息，它们可能对其他人有用，然后移除`runWriter`方法返回的`$log`值的使用。

显然，你也可以使用`Writer`monad 来跟踪任何类型的信息。一个很好的用法是通过`Writer`实例始终返回执行时间，将性能分析直接嵌入到你的函数中。

如果你需要存储多种类型的数据，`Writer` monad 不仅限于字符串值，任何 monoid 都可以。例如，你可以声明一个包含执行时间、堆栈跟踪和调试消息的特定 monoid，并将其与你的 Writer 一起使用。这样，你的每个函数都能向调用它们的人传递有用的信息。

我们可以说，始终具有这种信息会减慢程序的运行速度。这可能是正确的，但我想在大多数应用程序中，这种优化是不需要的。

# Reader monad

碰巧你有一堆函数，它们都应该接受相同的参数，或者给定值列表的一个子集。例如，你有一个配置文件，你的应用程序的各个部分需要访问其中存储的值。一个解决方案是有一种全局对象或单例来存储这些信息，但正如我们已经讨论过的，这会导致一些问题。在现代 PHP 框架中更常见的方法是使用一个叫做**依赖注入**（**DI**）的概念。Reader 单子允许你以纯函数的方式做到这一点。

## 动机

提供一种共享公共环境的方式，例如配置信息或类实例，跨多个函数进行。这个环境对于计算序列是只读的。然而，它可以被修改或扩展，用于当前步骤的任何子计算。

## 实施

`Reader`类执行函数评估是懒惰的，因为当函数绑定时环境的内容还不知道。这意味着所有函数都被包裹在单子内部的闭包中，当调用`runReader`方法时才运行。除此之外，在`php-functional`库中可用的实现非常直接。

## 例子

使用`Reader`单子与我们到目前为止所见到的有些不同。绑定的函数将接收计算中前一步的值，并且必须返回一个持有接收环境的函数的新 reader。如果你只想处理当前值，使用`map`函数会更容易，因为它不需要返回一个`Reader`实例。然而，你将不会收到上下文：

```php
<?php 
function hello() 
{ 
    return Reader::of(function($name) { 
        return "Hello $name!"; 
    }); 
} 

function ask($content) 
{ 
    return Reader::of(function($name) use($content) { 
        return $content. ($name == 'World' ? '' : ' How are you ?'); 
    }); 
} 

$r = hello() 
      ->bind('ask') 
      ->map('strtoupper'); 

echo $r->runReader('World'); 
// HELLO WORLD! echo $r->runReader('Gilles'); 
// HELLO GILLES! HOW ARE YOU ? 
```

这个不太有趣的例子只是提出了你可以做什么的基础知识。下一个例子将展示如何使用这个单子进行 DI。

### 注意

如果你使用过现代的 Web 框架，你可能已经知道什么是依赖注入，或者 DI。否则，这里是一个真正快速的解释，我可能会因此被烧死。DI 是一种模式，用于避免使用单例或全局可用的实例。相反，你声明你的依赖项作为函数或构造函数参数，一个**依赖注入容器**（**DIC**）负责为你提供它们。

通常，这涉及让 DIC 实例化所有对象，而不是使用`new`关键字，但方法因框架而异。

我们如何使用`Reader`单子来做到这一点？很简单。我们需要创建一个容器来保存所有的服务，然后我们将使用我们的 reader 来传递这些服务。

举例来说，假设我们有一个用于连接数据库的`EntityManager`，以及一个发送电子邮件的服务。另外，为了保持简单，我们不会进行任何封装，而是使用简单的函数而不是类：

```php
<?php 

class DIC 
{ 
    public $userEntityManager; 
    public $emailService; 
} 

function getUser(string $username) 
{ 
    return Reader::of(function(DIC $dic) use($username) { 
        return $dic->userEntityManager->getUser($username); 
    }); 
} 

function getUserEmail($username) 
{ 
    return getUser($username)->map(function($user) { 
        return $user->email; 

    }); 
} 

function sendEmail($title, $content, $email) 
{ 
    return Reader::of(function(DIC $dic) use($title, $content, $email) { 
        return $dic->emailService->send($title, $content, $email); 
    }); 
} 
```

现在我们想要编写一个在用户在我们的应用程序上注册后被调用的控制器。我们需要给他们发送一封电子邮件并显示某种确认。现在，让我们假设用户已经保存在数据库中，并且我们的理论框架提供了`POST`方法值作为参数的使用：

```php
<?php 

function controller(array $post) 
{ 
    return Reader::of(function(DIC $dic) use($post) { 
        getUserEmail($post['username']) 
            ->bind(f\curry('sendEmail', ['Welcome', '...'])) 
            ->runReader($dic); 

        return "<h1>Welcome !</h1>"; 
    }); 
} 
```

好的，我们已经准备好进行快速测试。我们将创建一些面向服务的类，以查看管道是否正常工作：

```php
<?php 

$dic = new DIC(); 
$dic->userEntityManager = new class() { 
    public function getUser() { 
      return new class() { 
          public $email = 'john.doe@email.com'; 
      }; 
    } 
}; 

$dic->emailService = new class() { 
    public function send($title, $content, $email) { 
        echo "Sending '$title' to $email"; 
    } 
}; 

$content = controller(['username' => 'john.doe'])->runReader($dic); 
// Sending 'Welcome' to john.doe@email.com 

echo $content; 
// <h1>Welcome !</h1> 
```

显然，我们还没有一个可用的框架，但我认为这很好地展示了`Reader`单子在 DI 方面提供的可能性。

关于需要执行的 IO 操作，以将新创建的用户存储到数据库中并发送邮件，我们将看到如何使用稍后将介绍的 IO 单子来实现。

# 状态单子

State 单子是读取器单子的一种泛化，因为每个步骤在调用下一步之前都可以修改当前状态。由于引用透明语言不能具有共享的全局状态，技巧是将状态封装在单子内部，并将其显式地传递给序列的每个部分。

## 动机

它提供了一个干净且易于使用的过程，可以在序列中的多个步骤之间传递共享状态。这显然可以手动完成，但这个过程容易出错，并且导致代码可读性较差。单子隐藏了复杂性，因此您可以简单地编写以状态作为输入并返回新状态的函数。

## 实现

`php-functional`库中提供的实现与我们刚刚讨论的`Reader`单子几乎相同，只有一个关键区别-每个绑定函数都可以更新状态。这导致了与绑定到单子的函数不同的函数-它们需要返回一个包含值作为第一个元素和新状态作为第二个元素的数组，而不是返回一个值。

## 示例

正如我们已经讨论过的，函数不可能返回当前时间或某种随机值。`state`单子可以通过提供一种干净的方式来传递`state`变量来帮助我们做到这一点，就像我们之前使用`Reader`环境一样：

```php
function randomInt() 
{ 
    return s\state(function($state) { 
        mt_srand($state); 
        return [mt_rand(), mt_rand()]; 
    }); 
} 

echo s\evalState(randomInt(), 12345); 
// 162946439 
```

`state`单子的另一个用途是实现缓存系统：

```php
<?php 

function getUser($id, $current = []) 
{ 
    return f\curryN(2, function($id, $current) { 
        return s\state(function($cache) use ($id, $current) { 
            if(! isset($cache[$id])) { 
                $cache[$id] = "user #$id"; 
            } 

            return [f\append($current, $cache[$id]), $cache]; 
        }); 
    })(...func_get_args()); 
} 

list($users, $cache) = s\runState( 
  getUser(1, []) 
    ->bind(getUser(2)) 
    ->bind(getUser(1)) 
    ->bind(getUser(3)), 
  [] 
); 

print_r($users); 
// Array ( 
//     [0] => user #1 
//     [1] => user #2 
//     [2] => user #1 
//     [3] => user #3 
// ) 

print_r($cache); 
// Array ( 
//     [1] => user #1 
//     [2] => user #2 
//     [3] => user #3 
// ) 
```

正如我们所看到的，用户列表中包含`user 1`两次，但缓存只有一次。这是一个非常基本的缓存机制，但它可能会派上用场。

`state`单子还有许多其他用途，但老实说，如果没有像 do 表示法这样的语法糖，我不太确定它是否适合 PHP 编程。如果您感兴趣，我相信您会在网上找到许多其他资源，但我们将在这里停止示例。

# IO 单子

输入和输出是副作用的精髓。当您从外部源获取函数输出时，没有办法保证纯度，因为这些输出会随着输入无关地发生变化。并且一旦您输出了某些东西，无论是屏幕、文件还是其他任何地方，您都改变了与函数输出无关的外部状态。

函数社区中的一些人认为，例如，日志输出或调试语句不一定应被视为副作用，因为通常它们对于运行应用程序的结果没有影响。最终用户并不在乎是否将某些内容写入日志文件，只要它能得到想要的结果并且操作可以随意重复。说实话，我对这个问题的看法还没有完全形成，而且老实说，我并不在乎，因为写入单子让我们以巧妙的方式处理日志记录和调试语句。

然而，有时您需要从外部获取信息，通常，如果您的应用程序值得做任何事情，您需要在某个地方显示或写入最终结果。

我们可以想象在开始任何计算之前获取所有值，并使用某种巧妙的数据结构传递它们。这对于一些较简单的应用程序可能有效，但是一旦您需要根据一些计算出的值执行数据库访问，现实开始显现，您会意识到这在长期内根本行不通。

IO 单子提出的技巧是按照我们刚刚提出的方式进行，但是相反。您首先描述程序所需的所有计算步骤。您将它们封装在 IO 单子的实例中，当一切都清晰地定义为引用透明的函数调用时，您启动最终执行所有所需 IO 操作的程序，并调用每个描述的步骤。

这样，您的应用程序只由纯函数组成，您可以轻松测试和理解。与输入和输出相关的所有操作都是在最后执行的，复杂性被隐藏在 IO 单子内部。为了强制执行这一点，IO 单子被称为单向单子，意味着无法从中获取任何值。您只有两个选择：

+   将计算或操作绑定到单子，以便稍后执行它们

+   运行这些计算以获得应用程序的最终结果

我想如果您从未见过像这样创建的应用程序，可能会感到非常困惑。这些例子将尝试给您第一印象，以及我们将在第十一章，“设计一个功能应用程序”中深入探讨这个主题。

## 动机

IO 单子通过将所有 IO 操作限制在单子内部，解决了输入和输出破坏引用透明度和函数纯度的问题。应用程序所需的所有计算步骤首先以功能方式描述。完成这一点后，我们接受最终步骤无法无副作用，并运行存储在单子内部的所有序列。

## 实施

`php-functional`库提供的实现非常简单，因为没有真正的微妙之处。只需要一个小技巧，即在调用`run`方法时进行计算，而不是在函数绑定时进行计算。

此外，该库还提供了`Widmogrod\Monad\IO`命名空间下的辅助函数，以帮助您使用单子。您可以轻松地从命令行读取用户输入，在屏幕上打印文本，并读取和写入文件和环境变量。

## 例子

我们将利用`mcompose`方法来组合多个`IO`操作：

```php
<?php 

use Widmogrod\Functional as f; 
use Widmogrod\Monad\IO; 
use Widmogrod\Monad\Identity; 

$readFromInput = f\mcompose(IO\putStrLn, IO\getLine, IO\putStrLn); 
$readFromInput(Monad\Identity::of('Enter something and press  <enter>'))->run(); 
// Enter something and press <enter> 
// Hi! // Hi! 
```

因此，我们首先创建一个使用`putStrLn`显示单子当前内容的函数，要求一些输入，并将结果显示回来。

如果要保持引用透明度，IO 单子需要包装整个应用程序的计算。这是因为您的输入需要通过它来检索，任何输出也必须通过单子完成。这意味着我们可以展示很多例子，而实际上并没有真正抓住其使用的真正本质。这就是为什么我们将在这里停下来，等到第十一章，“设计一个功能应用程序”，看看如何实现它。

# 总结

在本章中，我们已经看过多个单子及其实现。我希望这些例子清楚地说明了如何使用它们以及它们的好处是什么：

+   当计算可能返回空时，可以使用 Maybe 单子

+   Either 单子可用于计算可能出错的情况

+   List 单子可用于计算有多个可能结果的情况

+   当需要在返回值旁边传递一些辅助信息时，可以使用 Writer 单子

+   Reader 单子可用于在多个计算之间共享一个公共环境

+   State 单子是 Reader 单子的升级版本，其中环境可以在每次计算之间更新

+   IO 单子可用于以引用透明的方式执行 IO 操作

然而，还有其他多个计算可以使用单子简化。在编写代码时，我鼓励您退后一步，看看结构是否符合单子模式。如果是这样，您可能应该使用我们的`Monad`类来实现它，以从迄今为止学到的知识中受益。

另外，这些各种单子可以组合使用，实现复杂的转换和计算。我们将在第十章*PHP 框架和 FP*中讨论这个话题，其中我们将讨论单子变换器，以及第十一章*设计一个函数式应用*。

在书的这一部分，你可能会对一些函数式技术印象深刻，但我想我们到目前为止看到的大部分东西都有点尴尬，函数式编程可能看起来很繁琐。这种感觉对于两个主要原因来说是完全正常的。

首先，这种尴尬往往是由于某种缺失的抽象或待发现的技术所致。如果这是一本关于 Haskell 的书，你会学到所有这些内容，并且你会有一些其他书来查找它们。然而，这本书是关于 PHP 的；我们将在后面的章节中学习一些更多的概念，但之后，你将大部分时间都是靠自己，就像一个先驱一样。

我只能鼓励你在遇到这些情况时坚持下去，寻找代码中的模式和共性因素。一步一步，你将打造一个强大的工具箱，事情会变得更容易。

其次，这一切对你来说可能都是新的。转换编程范式真的很难，可能会让人感到沮丧。但不要害怕，随着时间、练习和经验的积累，你会变得更加自信，收获也会开始超过成本。学习曲线越陡峭，回报就越大。

在下一章中，我们将发现一些新的函数式概念和模式，这将使我们能够充分利用我们到目前为止学到的各种技术。
