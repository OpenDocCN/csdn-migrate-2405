# PHP7 数据结构和算法（二）

> 原文：[`zh.annas-archive.org/md5/eb90534f20ff388513beb1e54fb823ef`](https://zh.annas-archive.org/md5/eb90534f20ff388513beb1e54fb823ef)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：构建堆栈和队列

在日常生活中，我们使用两种最常见的数据结构。我们可以假设这些数据结构受到现实世界的启发，但它们在计算世界中有非常重要的影响。我们谈论的是堆栈和队列数据结构。我们每天都堆放我们的书籍、文件、盘子和衣服，而我们在售票处、公交车站和购物结账处维护队列。此外，我们已经听说过 PHP 中的消息队列，这是高端应用中最常用的功能之一。在本章中，我们将探索流行的堆栈和队列数据结构的不同实现。我们将学习关于队列、优先队列、循环队列和双端队列在 PHP 中的实现。

# 理解堆栈

堆栈是一种遵循**后进先出**（**LIFO**）原则的线性数据结构。这意味着堆栈只有一个端口，用于向结构中添加项目和移除项目。在堆栈中添加新项目称为推入（push），而在移除项目时称为弹出（pop）。由于我们只能操作一个端口，我们总是在该端口推入项目，当我们弹出时，该端口的最后一个项目将被弹出。堆栈中最顶部的元素也是堆栈端口的起始位置，称为顶部。如果我们考虑以下图像，我们可以看到在每次弹出和推入操作后，顶部都会改变。此外，我们在堆栈的顶部执行操作，而不是在堆栈的开始或中间。当堆栈为空时，弹出元素时，我们必须小心，以及当堆栈已满时推入元素。如果我们想要推入的元素超过其容量，可能会发生堆栈溢出。

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00027.jpg)

根据我们之前的讨论，我们现在知道堆栈中有四种基本操作：

+   **推入**：在堆栈的顶部添加项目。

+   **弹出**：移除堆栈的顶部项目。

+   **顶部**：返回堆栈的顶部项目。它与弹出不同，因为它不会移除项目，它只是为我们获取值。

+   **isEmpty**：检查堆栈是否为空。

现在让我们以不同的方式使用 PHP 实现堆栈。首先，我们将尝试使用 PHP 的内置数组函数来实现堆栈。然后，我们将看看如何构建一个堆栈，而不使用 PHP 的内置函数，而是使用其他数据结构，如链表。

# 使用 PHP 数组实现堆栈

首先，我们将为堆栈创建一个接口，以便我们可以在不同的实现中使用它，并确保所有实现彼此相似。让我们为堆栈编写一个简单的接口：

```php
interface Stack { 

    public function push(string $item); 

    public function pop(); 

    public function top(); 

    public function isEmpty(); 

}

```

正如我们从前面的接口中看到的，我们将所有堆栈函数放在接口中，因为实现它的类必须具有所有这些提到的函数，否则在运行时会抛出致命错误。由于我们正在使用 PHP 数组实现堆栈，我们将使用一些现有的 PHP 函数来进行推入、弹出和顶部操作。我们将以这样的方式实现堆栈，以便我们可以定义堆栈的大小。如果数组中没有项目，但我们仍然想要弹出，它将抛出一个下溢异常，如果我们尝试推入的项目超过其容量允许的数量，那么将抛出一个溢出异常。以下是使用数组实现堆栈的代码：

```php
class Books implements Stack { 

    private $limit; 

    private $stack; 

    public function __construct(int $limit = 20) { 

      $this->limit = $limit; 

      $this->stack = []; 

    } 

    public function pop(): string { 

      if ($this->isEmpty()) { 

          throw new UnderflowException('Stack is empty'); 

      } else { 

          return array_pop($this->stack); 

      } 

    } 

    public function push(string $newItem) { 

      if (count($this->stack) < $this->limit) { 

          array_push($this->stack, $newItem); 

      } else { 

          throw new OverflowException('Stack is full'); 

      } 

    } 

    public function top(): string { 

      return end($this->stack); 

    } 

    public function isEmpty(): bool { 

      return empty($this->stack); 

    } 

}

```

现在让我们来看一下我们为堆栈编写的代码。我们将堆栈实现命名为`Books`，但只要是有效的类名，我们可以随意命名。首先，我们使用`__construct()`方法构建堆栈，并提供限制我们可以存储在堆栈中的项目数量的选项。默认值设置为`20`。下一个方法定义了弹出操作：

```php
public function pop():  string { 

  if ($this->isEmpty()) {

      throw new UnderflowException('Stack is empty');

  } else {

      return array_pop($this->stack);

  }

 }

```

如果堆栈不为空，`pop`方法将返回一个字符串。我们为此目的使用了我们在堆栈类中定义的 empty 方法。如果堆栈为空，我们从 SPL 中抛出`UnderFlowException`。如果没有要弹出的项目，我们可以阻止该操作发生。如果堆栈不为空，我们使用 PHP 的`array_pop`函数返回数组中的最后一个项目。

在推送方法中，我们做与弹出相反的操作。首先，我们检查堆栈是否已满。如果没有满，我们使用 PHP 的`array_push`函数将字符串项目添加到堆栈的末尾。如果堆栈已满，我们从 SPL 中抛出`OverFlowException`。`top`方法返回堆栈的顶部元素。`isEmpty`方法检查堆栈是否为空。

由于我们遵循 PHP 7，我们在方法级别使用标量类型声明和方法的返回类型。

为了使用我们刚刚实现的堆栈类，我们必须考虑一个示例，我们可以在其中使用所有这些操作。让我们编写一个小程序来创建一个书堆栈。以下是此代码：

```php
try { 

    $programmingBooks = new Books(10); 

    $programmingBooks->push("Introduction to PHP7"); 

    $programmingBooks->push("Mastering JavaScript"); 

    $programmingBooks->push("MySQL Workbench tutorial"); 

    echo $programmingBooks->pop()."\n"; 

    echo $programmingBooks->top()."\n"; 

} catch (Exception $e) { 

    echo $e->getMessage(); 

}

```

我们已经为我们的书堆栈创建了一个实例，并将我们的编程书籍标题放在其中。我们进行了三次推送操作。最后插入的书名是`"MySQL workbench tutorial"`。如果我们在三次推送操作后进行弹出，我们将得到这个标题名。之后，顶部将返回`"Mastering JavaScript"`，这将成为执行弹出操作后的顶部项目。我们将整个代码嵌套在`try...catch`块中，以便处理溢出和下溢抛出的异常。前面的代码将产生以下输出：

```php
MySQL Workbench tutorial

Mastering JavaScript

```

现在让我们专注于刚刚完成的不同堆栈操作的复杂性。

# 理解堆栈操作的复杂性

以下是不同堆栈操作的时间复杂度。对于最坏情况，堆栈操作的时间复杂度如下：

| **操作** | **时间复杂度** |
| --- | --- |
| pop | `O(1)` |
| 推送 | `O(1)` |
| top | `O(1)` |
| isEmpty | `O(1)` |

由于堆栈在一端操作，始终记住堆栈的顶部，如果我们要在堆栈中搜索项目，这意味着我们必须搜索整个列表。访问堆栈中的特定项目也是一样。虽然使用堆栈进行这些操作并不是一个好的做法，但如果我们想这样做，我们必须记住时间复杂度基于更多的一般堆栈操作。

| **操作** | **时间复杂度** |
| --- | --- |
| 访问 | `O(n)` |
| 搜索 | `O(n)` |

堆栈的空间复杂度始终为`O(n)`。

到目前为止，我们已经看到如何使用 PHP 数组和其内置函数`array_pop`和`array_push`来实现堆栈。但是我们可以忽略内置函数，使用手动数组操作来实现，或者我们可以使用`array_shift`和`array_unshift`内置函数。

# 使用链表实现堆栈

在第三章，*使用链表*中，我们学习了如何实现链表。我们看到在链表中，我们可以在末尾插入节点，从末尾删除节点，在列表中间插入节点，在开头插入节点等。如果我们考虑单链表数据结构的末尾插入和末尾删除操作，我们可以轻松地执行类似的操作。因此，让我们使用上一章的`LinkedList`类来实现堆栈。代码如下：

```php
class BookList implements Stack { 

    private $stack; 

    public function __construct() { 

      $this->stack = new LinkedList(); 

    }

    public function pop(): string { 

      if ($this->isEmpty()) { 

          throw new UnderflowException('Stack is empty'); 

      } else { 

          $lastItem = $this->top(); 

          $this->stack->deleteLast(); 

          return $lastItem; 

      } 

    } 

    public function push(string $newItem) { 

      $this->stack->insert($newItem); 

    } 

public function top(): string { 

  return $this->stack->getNthNode($this->stack->getSize())->data; 

} 

    public function isEmpty(): bool { 

      return $this->stack->getSize() == 0; 

    } 

}

```

让我们逐个查看每个代码块，以了解这里发生了什么。如果我们从顶部开始，我们可以看到在`constructor`方法中，我们创建了一个新的`LinkedList`对象，并将其分配给我们的堆栈属性，而不是上一个示例中的数组。我们假设`LinkedList`类是自动加载的，或者文件已经包含在脚本中。现在让我们专注于推入操作。推入操作就像它可以得到的那样简单。我们只需要在链表中插入一个新节点。由于链表没有任何大小限制，我们在这里不检查任何溢出。

在我们的链表实现中，没有显示最后一个节点的方法。我们已经插入了一个新的最后一个节点并删除了上一个最后一个节点，但是在这里，我们需要获取最后一个节点的值而不删除它。为了实现这个功能，这正是我们堆栈的顶部操作，我们可以利用`LinkedList`实现中的`getNthNode`方法以及`getSize`。这样，我们就可以得到节点。但是我们必须记住一件事：我们想要节点的字符串值，而不是完整的节点对象。这就是为什么我们返回返回的节点的数据属性。

与顶部操作类似，弹出操作在删除节点之前也需要返回最后一个节点的数据。为了实现这一点，我们使用`top()`方法，然后使用`LinkedList`类的`deleteLast()`方法。现在让我们运行一个使用这个新实现的`BookList`类进行堆栈操作的示例代码。以下是代码：

```php
try { 

    $programmingBooks = new BookList(); 

    $programmingBooks->push("Introduction to PHP7"); 

    $programmingBooks->push("Mastering JavaScript"); 

    $programmingBooks->push("MySQL Workbench tutorial"); 

    echo $programmingBooks->pop()."\n"; 

    echo $programmingBooks->pop()."\n"; 

    echo $programmingBooks->top()."\n"; 

} catch (Exception $e) { 

    echo $e->getMessage(); 

}

```

它看起来与我们上次运行的示例非常相似，但这里我们尝试执行两次弹出操作，然后是顶部操作。因此，输出将如下所示：

```php
MySQL Workbench tutorial

Mastering JavaScript

Introduction to PHP7

```

如果我们了解堆栈的基本行为以及如何实现它，我们可以使用数组、链表、双向链表来实现堆栈。由于我们已经看到了数组和链表的实现，现在我们将探索堆栈的 SPL 实现，它实际上使用了双向链表。

# 使用 SPL 中的 SplStack 类

如果我们不想实现自己的堆栈版本，可以使用现有的 SPL 堆栈实现。它非常容易使用，需要编写的代码很少。正如我们已经知道的，`SplStack`使用`SplDoublyLinkedList`。它具有所有可能的操作，如推入、弹出、向前移动、向后移动、移位、反移位等。为了实现我们之前看到的相同示例，我们必须编写以下行：

```php
$books = new SplStack(); 

$books->push("Introduction to PHP7"); 

$books->push("Mastering JavaScript"); 

$books->push("MySQL Workbench tutorial"); 

echo $books->pop() . "\n"; 

echo $books->top() . "\n"; 

```

是的，使用`SplStack`类构建堆栈就是这么简单。我们可以决定是否要使用 PHP 数组、链表或内置类（如`SplStack`）来实现它。

# 堆栈的现实生活用途

堆栈在现代应用程序中有许多用途。无论是在浏览器历史记录中还是在流行的开发术语堆栈跟踪中，堆栈都被广泛使用。现在我们将尝试使用堆栈解决一个现实世界的问题。

# 嵌套括号匹配

当我们解决数学表达式时，我们需要考虑的第一件事是嵌套括号的正确性。如果括号没有正确嵌套，那么计算可能不可能，或者可能是错误的。让我们看一些例子：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00028.jpg)

从前面的表达式中，只有第一个是正确的；其他两个是不正确的，因为括号没有正确嵌套。为了确定括号是否嵌套，我们可以使用堆栈来实现解决方案。以下是伪算法的实现：

```php
valid = true 

s = empty stack 

for (each character of the string) { 

   if(character = ( or { or [ ) 

       s.push(character) 

  else if (character = ) or } or ] ) { 

   if(s is empty) 

valid = false 

     last = s.pop() 

    if(last is not opening parentheses of character)  

         valid = false 

  } 

} 

if(s is not empty) 

valid = false

```

如果我们看伪代码，看起来非常简单。目标是忽略字符串中的任何数字、操作数或空格，并只考虑括号、大括号和方括号。如果它们是开放括号，我们将推入堆栈。如果它们是闭合括号，我们将弹出堆栈。如果弹出的括号不是我们要匹配的开放括号，则它是无效的。循环结束时，如果字符串有效，则堆栈应为空。但是如果堆栈不为空，则有额外的括号，因此字符串无效。现在让我们将其转换为程序：

```php
function expressionChecker(string $expression): bool { 

    $valid = TRUE; 

    $stack = new SplStack(); 

    for ($i = 0; $i < strlen($expression); $i++) { 

    $char = substr($expression, $i, 1); 

    switch ($char) { 

      case '(': 

      case '{': 

      case '[': 

      $stack->push($char); 

      break; 

      case ')': 

      case '}': 

      case ']': 

      if ($stack->isEmpty()) { 

          $valid = FALSE; 

      } else { 

        $last = $stack->pop(); 

        if (($char == ")" && $last != "(")  

          || ($char == "}" && $last != "{")  

          || ($char == "]" && $last != "[")) { 

      $valid = FALSE; 

        } 

    } 

    break; 

  } 

  if (!$valid) 

      break; 

    } 

    if (!$stack->isEmpty()) { 

    $valid = FALSE; 

    } 

    return $valid; 

}

```

现在让我们运行我们之前讨论的三个示例：

```php
$expressions = []; 

$expressions[] = "8 * (9 -2) + { (4 * 5) / ( 2 * 2) }"; 

$expressions[] = "5 * 8 * 9 / ( 3 * 2 ) )"; 

$expressions[] = "[{ (2 * 7) + ( 15 - 3) ]"; 

foreach ($expressions as $expression) { 

    $valid = expressionChecker($expression); 

    if ($valid) { 

    echo "Expression is valid \n"; 

    } else { 

    echo "Expression is not valid \n"; 

    } 

} 

```

这将产生我们想要的以下输出：

```php
Expression is valid

Expression is not valid

Expression is not valid

```

# 理解队列

队列是另一种遵循**先进先出**（**FIFO**）原则的特殊线性数据结构。操作有两端：一个用于向队列追加，一个用于从队列中移除。这与堆栈不同，堆栈中我们使用一个端口进行添加和移除操作。插入将始终在后部或后部进行。元素的移除将从前端进行。向队列添加新元素的过程称为入队，移除元素的过程称为出队。查看队列前端元素而不移除元素的过程称为 peek，类似于堆栈的 top 操作。以下图示表示队列的表示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00029.jpg)

现在，如果我们为队列定义一个接口，它将如下所示：

```php
interface Queue { 

    public function enqueue(string $item); 

    public function dequeue(); 

    public function peek(); 

    public function isEmpty(); 

}

```

现在我们可以使用不同的方法实现队列，就像我们为堆栈所做的那样。首先，我们将使用 PHP 数组实现队列，然后是`LinkedList`，然后是`SplQueue`。

# 使用 PHP 数组实现队列

我们现在将使用 PHP 数组来实现队列数据结构。我们已经看到我们可以使用`array_push()`函数将元素添加到数组的末尾。为了删除数组的第一个元素，我们可以使用 PHP 的`array_shift()`函数，对于 peek 函数，我们可以使用 PHP 的`current()`函数。根据我们的讨论，代码将如下所示：

```php
class AgentQueue implements Queue {

    private $limit; 

    private $queue; 

    public function __construct(int $limit = 20) { 

      $this->limit = $limit; 

      $this->queue = []; 

    } 

    public function dequeue(): string { 

      if ($this->isEmpty()) { 

          throw new UnderflowException('Queue is empty'); 

      } else { 

          return array_shift($this->queue); 

      } 

    } 

    public function enqueue(string $newItem) { 

      if (count($this->queue) < $this->limit) { 

          array_push($this->queue, $newItem); 

      } else { 

          throw new OverflowException('Queue is full'); 

      } 

    } 

    public function peek(): string { 

      return current($this->queue); 

    } 

    public function isEmpty(): bool { 

      return empty($this->queue); 

    } 

}

```

在这里，我们保持了与堆栈相同的原则。我们希望定义一个固定大小的队列，并检查溢出和下溢。为了运行队列实现，我们可以考虑将其用作呼叫中心应用程序的代理队列。以下是利用我们的队列操作的代码：

```php
try { 

    $agents = new AgentQueue(10); 

    $agents->enqueue("Fred"); 

    $agents->enqueue("John"); 

    $agents->enqueue("Keith"); 

    $agents->enqueue("Adiyan"); 

    $agents->enqueue("Mikhael"); 

    echo $agents->dequeue()."\n"; 

    echo $agents->dequeue()."\n"; 

    echo $agents->peek()."\n"; 

} catch (Exception $e) { 

    echo $e->getMessage(); 

} 

```

这将产生以下输出：

```php
Fred

John

Keith

```

# 使用链表实现队列

与堆栈实现一样，我们将在第三章中使用我们的链表实现，*使用链表*，在这里实现队列。我们可以使用`insert()`方法来确保我们始终在末尾插入。我们可以使用`deleteFirst()`进行出队操作，使用`getNthNode()`进行查看操作。以下是使用链表实现队列的示例实现：

```php
class AgentQueue implements Queue { 

    private $limit; 

    private $queue; 

    public function __construct(int $limit = 20) { 

      $this->limit = $limit; 

      $this->queue = new LinkedList(); 

    } 

    public function dequeue(): string { 

      if ($this->isEmpty()) { 

          throw new UnderflowException('Queue is empty'); 

      } else { 

          $lastItem = $this->peek(); 

          $this->queue->deleteFirst(); 

          return $lastItem; 

      } 

    } 

    public function enqueue(string $newItem) { 

      if ($this->queue->getSize() < $this->limit) { 

          $this->queue->insert($newItem); 

      } else { 

          throw new OverflowException('Queue is full'); 

      } 

    } 

    public function peek(): string { 

      return $this->queue->getNthNode(1)->data; 

    } 

    public function isEmpty(): bool { 

      return $this->queue->getSize() == 0; 

    } 

}

```

# 使用 SPL 中的 SplQueue 类

如果我们不想费力实现队列功能，并且满意于内置解决方案，我们可以使用`SplQueue`类来满足我们的基本队列需求。我们必须记住一件事：`SplQueue`类中没有 peek 函数可用。我们必须使用`bottom()`函数来获取队列的第一个元素。以下是使用`SplQueue`为我们的`AgentQueue`实现的简单队列实现：

```php
$agents = new SplQueue(); 

$agents->enqueue("Fred"); 

$agents->enqueue("John"); 

$agents->enqueue("Keith"); 

$agents->enqueue("Adiyan"); 

$agents->enqueue("Mikhael"); 

echo $agents->dequeue()."\n"; 

echo $agents->dequeue()."\n"; 

echo $agents->bottom()."\n";

```

# 理解优先队列

优先级队列是一种特殊类型的队列，其中项目根据其优先级插入和移除。在编程世界中，优先级队列的使用是巨大的。例如，假设我们有一个非常庞大的电子邮件队列系统，我们通过队列系统发送月度通讯。如果我们需要使用相同的队列功能向用户发送紧急电子邮件，那么会发生什么？由于一般队列原则是在末尾添加项目，发送该消息的过程将被延迟很多。为了解决这个问题，我们可以使用优先级队列。在这种情况下，我们为每个节点分配一个优先级，并根据该优先级对它们进行排序。具有更高优先级的项目将排在列表顶部，并且将更早地出列。

我们可以采取两种方法来构建优先级队列。

# 有序序列

如果我们为优先级队列计划一个有序序列，它可以是升序或降序。有序序列的积极面是我们可以快速找到最大或删除最大优先级的项目，因为我们可以使用`O(1)`的复杂度找到它。但是插入会花费更多时间，因为我们必须检查队列中的每个元素，以根据其优先级将项目放在正确的位置。

# 无序序列

无序序列不需要我们遍历每个队列元素以放置新添加的元素。它总是作为一般队列原则添加到后面。因此，我们可以以`O(1)`的复杂度实现入队操作。但是，如果我们想要找到或删除最高优先级的元素，那么我们必须遍历每个元素以找到正确的元素。因此，它不太适合搜索。

现在我们将编写代码，使用有序序列和链表来实现优先级队列。

# 使用链表实现优先级队列

到目前为止，我们只看到了使用一个值的链表，即节点数据。现在我们需要传递另一个值，即优先级。为了实现这一点，我们需要改变我们的`ListNode`实现：

```php
class ListNode {

    public $data = NULL; 

    public $next = NULL;

    public $priority = NULL;

    public function __construct(string $data = NULL, int $priority = 

      NULL) { 

      $this->data = $data;

      $this->priority = $priority;

    }

}

```

现在我们的节点包含数据和优先级。为了在插入操作期间考虑这个优先级，我们还需要改变`LinkedList`类内的`insert()`实现。以下是修改后的实现：

```php
public function insert(string $data = NULL, int $priority = NULL) { 

  $newNode = new ListNode($data, $priority); 

  $this->_totalNode++; 

  if ($this->_firstNode === NULL) { 

      $this->_firstNode = &$newNode; 

  } else { 

      $previous = $this->_firstNode; 

      $currentNode = $this->_firstNode; 

      while ($currentNode !== NULL) { 

      if ($currentNode->priority < $priority) { 

         if ($currentNode == $this->_firstNode) { 

         $previous = $this->_firstNode; 

         $this->_firstNode = $newNode; 

         $newNode->next = $previous; 

         return; 

         } 

         $newNode->next = $currentNode; 

         $previous->next = $newNode; 

         return; 

    } 

    $previous = $currentNode; 

    $currentNode = $currentNode->next; 

    } 

  } 

  return TRUE; 

}

```

我们可以看到，我们的`insert`方法已经更改为在插入操作期间同时获取数据和优先级。通常情况下，第一个过程是创建一个新节点并增加节点计数。插入有三种可能性，如下所示：

+   列表为空，所以新节点是第一个节点。

+   列表不为空，但新项目具有最高优先级，所以。所以它成为第一个节点，之前的第一个节点跟随它。

+   列表不为空，优先级不是最高，所以将新节点插入列表内，或者可能在列表末尾。

在我们的实现中，我们考虑了所有三种可能性，三个事实。因此，我们始终将最高优先级的项目放在列表的开头。现在让我们使用新代码运行`AgentQueue`实现，如下例所示：

```php
try { 

    $agents = new AgentQueue(10); 

    $agents->enqueue("Fred", 1); 

    $agents->enqueue("John", 2); 

    $agents->enqueue("Keith", 3); 

    $agents->enqueue("Adiyan", 4); 

    $agents->enqueue("Mikhael", 2); 

    $agents->display(); 

    echo $agents->dequeue()."\n"; 

    echo $agents->dequeue()."\n"; 

} catch (Exception $e) { 

    echo $e->getMessage(); 

}

```

如果没有优先级，那么队列应该是`Fred`，`John`，`Keith`，`Adiyan`和`Mikhael`。但由于我们已经将优先级添加到列表中，输出结果是：

```php
Adiyan

Keith

John

Mikhael

Fred

```

由于`Adiyan`具有最高优先级，即使它是在队列的第四个位置插入的，它也被放在队列的开头。

# 使用 SplPriorityQueue 实现优先级队列

PHP 已经内置了使用 SPL 实现优先级队列的支持。我们可以使用`SplPriorityQueue`类来实现我们的优先级队列。以下是使用链表的示例之前的示例，但这次我们选择了 SPL：

```php
class MyPQ extends SplPriorityQueue { 

    public function compare($priority1, $priority2) { 

    return $priority1 <=> $priority2; 

    }

}

$agents = new MyPQ();

$agents->insert("Fred", 1); 

$agents->insert("John", 2);

$agents->insert("Keith", 3);

$agents->insert("Adiyan", 4);

$agents->insert("Mikhael", 2);

//mode of extraction

$agents->setExtractFlags(MyPQ::EXTR_BOTH); 

//Go to TOP

$agents->top();

while ($agents->valid()) {

    $current = $agents->current();

    echo $current['data'] . "\n";

    $agents->next();

}

```

这将产生与链表示例相同的结果。扩展到我们自己的`MyPQ`类的附加优势是，我们可以定义是否要按升序或降序对其进行排序。在这里，我们选择降序排序，使用 PHP 组合比较运算符或太空船运算符。

大多数情况下，优先队列是使用堆来实现的。当我们转到堆章节时，我们还将使用堆来实现优先队列。

# 实现循环队列

当我们使用标准队列时，每次出队一个项目，我们都必须重新缓冲整个队列。为了解决这个问题，我们可以使用循环队列，其中后端紧随前端，形成一个循环。这种特殊类型的队列需要对入队和出队操作进行特殊计算，考虑到队列的后端、前端和限制。循环队列始终是固定队列，也称为循环缓冲区或环形缓冲区。以下图示了循环队列的表示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00030.jpg)

我们可以使用 PHP 数组来实现循环队列。由于我们必须计算后端和前端部分的位置，数组可以有效地用于此目的。以下是循环队列的示例：

```php
class CircularQueue implements Queue { 

    private $queue; 

    private $limit; 

    private $front = 0; 

    private $rear = 0; 

    public function __construct(int $limit = 5) { 

      $this->limit = $limit; 

      $this->queue = []; 

    } 

    public function size() { 

      if ($this->rear > $this->front) 

          return $this->rear - $this->front; 

      return $this->limit - $this->front + $this->rear; 

    } 

    public function isEmpty() { 

      return $this->rear == $this->front; 

    } 

    public function isFull() { 

      $diff = $this->rear - $this->front; 

      if ($diff == -1 || $diff == ($this->limit - 1)) 

          return true; 

      return false; 

    } 

    public function enqueue(string $item) { 

      if ($this->isFull()) { 

          throw new OverflowException("Queue is Full."); 

      } else { 

          $this->queue[$this->rear] = $item; 

          $this->rear = ($this->rear + 1) % $this->limit; 

      } 

    } 

    public function dequeue() { 

      $item = ""; 

      if ($this->isEmpty()) { 

          throw new UnderflowException("Queue is empty"); 

      } else { 

          $item = $this->queue[$this->front]; 

          $this->queue[$this->front] = NULL; 

          $this->front = ($this->front + 1) % $this->limit; 

      } 

      return $item; 

    } 

    public function peek() { 

      return $this->queue[$this->front]; 

    }

}

```

由于我们将`0`视为前端标记，队列的总大小将为`limit - 1`。

# 创建双端队列（deque）

到目前为止，我们已经实现了队列，其中一个端口用于入队，称为后端，另一个端口用于出队，称为前端。因此，通常每个端口都应该用于特定的目的。但是，如果我们需要从两端进行入队和出队操作怎么办？这可以通过使用一个称为双端队列或 deque 的概念来实现。在 deque 中，两端都可以用于入队和出队操作。如果我们查看使用链表的队列实现，我们会发现我们可以使用链表实现进行在末尾插入、在开头插入、在末尾删除和在开头删除。如果我们基于此实现一个新的 deque 类，我们可以轻松实现我们的目标。以下图示了一个双端队列：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00031.jpg)

这是一个双端队列的实现：

```php
class DeQueue { 

    private $limit; 

    private $queue; 

    public function __construct(int $limit = 20) { 

      $this->limit = $limit; 

      $this->queue = new LinkedList(); 

    } 

    public function dequeueFromFront(): string { 

      if ($this->isEmpty()) { 

          throw new UnderflowException('Queue is empty'); 

      } else { 

          $lastItem = $this->peekFront(); 

          $this->queue->deleteFirst(); 

          return $lastItem; 

      } 

    } 

    public function dequeueFromBack(): string { 

      if ($this->isEmpty()) { 

          throw new UnderflowException('Queue is empty'); 

      } else { 

          $lastItem = $this->peekBack(); 

          $this->queue->deleteLast(); 

          return $lastItem; 

      } 

    } 

    public function enqueueAtBack(string $newItem) { 

      if ($this->queue->getSize() < $this->limit) { 

          $this->queue->insert($newItem); 

      } else { 

          throw new OverflowException('Queue is full'); 

      } 

    } 

    public function enqueueAtFront(string $newItem) { 

      if ($this->queue->getSize() < $this->limit) { 

          $this->queue->insertAtFirst($newItem); 

      } else { 

          throw new OverflowException('Queue is full'); 

      } 

    } 

    public function peekFront(): string { 

      return $this->queue->getNthNode(1)->data; 

    } 

    public function peekBack(): string { 

      return $this->queue->getNthNode($this->queue->getSize())->data; 

    } 

    public function isEmpty(): bool { 

      return $this->queue->getSize() == 0; 

    } 

}

```

现在我们将使用这个类来检查双端队列的操作：

```php
try { 

    $agents = new DeQueue(10); 

    $agents->enqueueAtFront("Fred"); 

    $agents->enqueueAtFront("John"); 

    $agents->enqueueAtBack("Keith"); 

    $agents->enqueueAtBack("Adiyan"); 

    $agents->enqueueAtFront("Mikhael"); 

    echo $agents->dequeueFromBack() . "\n"; 

    echo $agents->dequeueFromFront() . "\n"; 

    echo $agents->peekFront() . "\n"; 

} catch (Exception $e) { 

    echo $e->getMessage(); 

}

```

如果我们查看前面的代码示例，首先我们在前端添加`Fred`，然后再次在前端添加`John`。所以现在的顺序是`John`，`Fred`。然后我们在后端添加`Keith`，然后是`Adiyan`。所以现在我们有顺序`John`，`Fred`，`Keith`，`Adiyan`。最后，我们在开头添加`Mikhael`。所以最终的顺序是`Mikhael`，`John`，`Fred`，`Keith`，`Adiyan`。

由于我们首先从后端进行出队操作，`Adiyan`将首先出队，然后是从前端的`Mikhael`。新的前端将是`John`。当您运行代码时，以下是输出：

```php
Adiyan

Mikhael

John

```

# 摘要

栈和队列是最常用的数据结构之一。在未来的算法和数据结构中，我们可以以不同的方式使用这些抽象数据类型。在本章中，我们学习了实现栈和队列的不同方法，以及不同类型的队列。在下一章中，我们将讨论递归-一种通过将大问题分解为较小实例来解决问题的特殊方法。


# 第五章：应用递归算法 - 递归

解决复杂问题总是很困难的。即使对于程序员来说，解决复杂问题也可能更加困难，有时需要特殊的解决方案。递归是计算机程序员用来解决复杂问题的一种特殊方法。在本章中，我们将介绍递归的定义、属性、不同类型的递归以及许多示例。递归并不是一个新概念；在自然界中，我们看到许多递归元素。分形展现了递归行为。以下图像显示了自然递归：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00032.jpg)

# 理解递归

递归是通过将大问题分解为小问题来解决更大问题的一种方法。换句话说，递归是将大问题分解为更小的相似问题来解决它们并获得实际结果。通常，递归被称为函数调用自身。这可能听起来很奇怪，但事实是当函数递归时，函数必须调用自身。这是什么样子？让我们看一个例子，

在数学中，“阶乘”这个术语非常流行。数字*N*的阶乘被定义为小于等于*N*的所有正整���的乘积。它总是用*!*（感叹号）表示。因此，*5*的阶乘可以写成如下形式：

*5! = 5 X 4 X 3 X 2 X 1*

同样，我们可以写出给定数字的以下阶乘：

*4! = 4 X 3 X 2 X 1*

*3! = 3 X 2 X 1*

*2! = 2 X 1*

*1! = 1*

如果我们仔细观察我们的例子，我们可以看到我们可以用*4*的阶乘来表示*5*的阶乘，就像这样：

*5! = 5 X 4!*

同样，我们可以写成：

*4! = 4 X 3!*

*3! = 3 X 2!*

*2! = 2 X 1!*

*1! = 1 X 0!*

*0! = 1*

或者，我们可以简单地说一般来说：

*n! = n * (n-1)!*

这代表了递归。我们将每个步骤分解成更小的步骤，并解决实际的大问题。这里有一张图片展示了如何计算 3 的阶乘：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00033.jpg)

因此，步骤如下：

1.  *3! = 3 X 2!*

1.  *2! = 2 X 1!*

1.  *1! = 1 X 0!*

1.  *0! = 1*

1.  *1! = 1 X 1 = 1*

1.  *2! = 2 X 1 = 2*

1.  *3! = 3 X 2 = 6*

# 递归算法的属性

现在，问题可能是，“如果一个函数调用自身，那么它如何停止或知道何时完成递归调用？”当我们编写递归解决方案时，我们必须确保它具有以下属性：

1.  每个递归调用都应该是一个更小的子问题。就像阶乘的例子，6 的阶乘是用 6 和 5 的阶乘相乘来解决的，依此类推。

1.  它必须有一个基本情况。当达到基本情况时，将不会有进一步的递归，并且基本情况必须能够解决问题，而不需要进一步的递归调用。在我们的阶乘示例中，我们没有从 0 进一步。所以，在这种情况下，0 是我们的基本情况。

1.  不应该有任何循环。如果每个递归调用都调用同一个问题，那么将会有一个永无止境的循环。经过一些重复后，计算机将显示堆栈溢出错误。

因此，如果我们现在使用 PHP 7 编写我们的阶乘程序，那么它将如下所示：

```php
function factorial(int $n): int {

   if ($n == 0)

    return 1;

   return $n * factorial($n - 1);

}

```

在前面的示例代码中，我们可以看到我们有一个基本条件，当$n$的值为$0$时，我们返回`1`。如果不满足这个条件，那么我们返回$n$的乘积和$n-1$的阶乘。所以，它满足 1 和 3 这两个数字的属性。我们避免了循环，并确保每个递归调用都创建了一个更大的子问题。我们将像这样编写递归行为的算法：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00034.jpg)

# 递归与迭代算法

如果我们分析我们的阶乘函数，我们可以看到它可以使用简单的迭代方法来编写，使用`for`或`while`循环，如下所示：

```php
function factorial(int $n): int { 

    $result = 1; 

    for ($i = $n; $i > 0; $i--) {

      $result *= $i; 

    } 

    return $result; 

}

```

如果这可以写成一个简单的迭代形式，那么为什么要使用递归呢？递归用于解决更复杂的问题。并非所有问题都可以如此轻松地迭代解决。例如，我们需要显示某个目录中的所有文件。我们可以通过运行循环来列出所有文件来简单地做到这一点。但是，如果里面还有另一个目录呢？那么，我们必须运行另一个循环来获取该目录中的所有文件。如果该目录中还有另一个目录，依此类推呢？在这种情况下，迭代方法可能根本无济于事，或者可能会产生一个复杂的解决方案。在这里最好选择递归方法。

递归管理一个调用堆栈来管理函数调用。因此，与迭代相比，递归将需要更多的内存和时间来完成。此外，在迭代中，每一步都可以得到一个结果，但对于递归，我们必须等到基本情况执行才能得到任何结果。如果我们考虑阶乘的迭代和递归示例，我们可以看到有一个名为`$result`的局部变量来存储每一步的计算。然而，在递归中，不需要局部变量或赋值。

# 使用递归实现斐波那契数

在数学中，斐波那契数是特殊的整数序列，其中一个数字由过去两个数字的求和组成，如下所示的表达式：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00035.gif)

如果我们使用 PHP 7 来实现，它将如下所示：

```php
function fibonacci(int $n): int { 

    if ($n == 0) { 

    return 1; 

    } else if ($n == 1) { 

    return 1; 

    } else { 

    return fibonacci($n - 1) + fibonacci($n - 2); 

    } 

}

```

如果我们考虑前面的实现，可以看到它与以前的示例有些不同。现在，我们从一个函数调用中调用两个函数。我们将很快讨论不同类型的递归。

# 使用递归实现 GCD 计算

递归的另一个常见用途是实现两个数字的**最大公约数**（**GCD**）计算。在 GCD 计算中，我们会一直进行下去，直到余数变为 0。可以表示如下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00036.jpg)

现在，如果我们使用 PHP 7 进行递归实现，它将如下所示：

```php
function gcd(int $a, int $b): int { 

    if ($b == 0) { 

     return $a; 

    } else { 

     return gcd($b, $a % $b); 

    } 

}

```

这个实现的另一个有趣部分是，与阶乘不同，我们不是从基本情况返回到调用堆栈中的其他步骤。基本情况将返回计算出的值。这是递归的一种优化方式。

# 不同类型的递归

到目前为止，我们已经看到了一些递归的示例案例以及它的使用方式。尽管术语是递归，但有不同类型的递归。我们将逐一探讨它们。

# 线性递归

在编程世界中最常用的递归之一是线性递归。当一个函数在每次运行中只调用自身一次时，我们将其称为线性递归。就像我们的阶乘示例一样，当我们将大的计算分解为较小的计算，直到达到基本条件时，我们称之为缠绕。当我们从基本条件返回到第一个递归调用时，我们称之为展开。在本章的后续部分中，我们将研究不同的线性递归。

# 二进制递归

在二进制递归中，函数在每次运行中调用自身两次。因此，计算取决于对自身的两个不同递归调用的结果。如果我们看看我们的斐波那契序列生成递归函数，我们很容易发现它是一个二进制递归。除此之外，在编程世界中，我们还有许多常用的二进制递归，如二分查找、分治、归并排序等。下图显示了一个二进制递归：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00037.jpg)

# 尾递归

当返回时没有待处理的操作时，递归方法是尾递归。例如，在我们的阶乘代码中，返回的值用于与前一个值相乘以计算阶乘。因此，这不是尾递归。斐波那契数列递归也是如此。如果我们看看我们的最大公约数递归，我们会发现在返回后没有要执行的操作。因此，最终返回或基本情况返回实际上就是答案。因此，最大公约数是尾递归的一个例子。尾递归也是线性递归的一种形式。

# 相互递归

可能会出现这样的情况，我们可能需要从两个不同的方法中交替地递归调用两个不同的方法。例如，函数 `A()` 调用函数 `B()`，函数 `B()` 在每次调用中调用函数 `A()`。这被称为相互递归。

# 嵌套递归

当递归函数调用自身作为参数时，它被称为嵌套递归。嵌套递归的一个常见例子是 Ackermann 函数。看看下面的方程：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00038.gif)

如果我们看最后一行，我们可以看到函数 `A()` 被递归调用，但第二个参数本身是另一个递归调用。因此，这是嵌套递归的一个例子。

尽管有不同类型的递归可用，但我们只会根据我们的需求使用那些必需的。现在，我们将看到递归在我们的项目中的一些实际用途。

# 使用递归构建 N 级类别树

构建多级嵌套的类别树或菜单总是一个问题。许多 CMS 和网站只允许一定级别的嵌套。为了避免由于多次连接而导致的性能问题，一些只允许最多 3-4 级的嵌套。现在，我们将探讨如何利用递归创建一个 N 级嵌套的类别树或菜单，而不会影响性能。以下是我们解决方案的方法：

1.  我们将为数据库中的类别定义表结构。

1.  我们将在不使用任何连接或多个查询的情况下获取表中的所有类别。这将是一个带有简单选择语句的单个数据库查询。

1.  我们将构建一个类别数组，以便我们可以利用递归来显示嵌套的类别或菜单。

让我们假设我们的数据库中有一个简单的表结构来存储我们的类别，它看起来像这样：

```php
CREATE TABLE `categories` ( 

  `id` int(11) NOT NULL, 

  `categoryName` varchar(100) NOT NULL, 

  `parentCategory` int(11) DEFAULT 0, 

  `sortInd` int(11) NOT NULL 

) ENGINE=InnoDB DEFAULT CHARSET=utf8;

```

为简单起见，我们假设表中不需要其他字段。此外，我们的表中有一些数据如下：

| **Id** | **类别名称** | **父类别** | **排序索引** |
| --- | --- | --- | --- |
| 1 | 第一 | 0 | 0 |
| 2 | 第二 | 1 | 0 |
| 3 | 第三 | 1 | 1 |
| 4 | 第四 | 3 | 0 |
| 5 | 第五 | 4 | 0 |
| 6 | 第六 | 5 | 0 |
| 7 | 第七 | 6 | 0 |
| 8 | 第八 | 7 | 0 |
| 9 | 第九 | 1 | 0 |
| 10 | 第十 | 2 | 1 |

现在，我们已经为我们的数据库创建了一个结构化的表，并且我们也假设输入了一些示例数据。让我们构建一个查询来检索这些数据，以便我们可以转移到我们的递归解决方案：

```php
$dsn = "mysql:host=127.0.0.1;port=3306;dbname=packt;"; 

$username = "root"; 

$password = ""; 

$dbh = new PDO($dsn, $username, $password); 

$result = $dbh->query("Select * from categories order by parentCategory asc, sortInd asc", PDO::FETCH_OBJ); 

$categories = []; 

foreach($result as $row) { 

    $categories[$row->parentCategory][] = $row;

}

```

上述代码的核心部分是我们如何将我们的类别存储在数组中。我们根据它们的父类别存储结果。这将帮助我们递归地显示类别的子类别。这看起来非常简单。现在，基于类别数组，让我们编写递归函数以分层显示类别：

```php
function showCategoryTree(Array $categories, int $n) {

    if(isset($categories[$n])) { 

      foreach($categories[$n] as $category) {        

          echo str_repeat("-", $n)."".$category->categoryName."\n"; 

          showCategoryTree($categories, $category->id);          

      }

    }

    return;

}

```

上述代码实际上显示了所有类别及其子类别的递归。我们取一个级别，首先打印该级别上的类别。接着，我们将检查它是否有任何子级别的类别，使用代码 `showCategoryTree($categories, $category->id)`。现在，如果我们用根级别（级别 0）调用递归函数，那么我们将得到以下输出：

```php
showCategoryTree($categories, 0);

```

这将产生以下输出：

```php
First

-Second

--Tenth

-Third

---Fourth

----fifth

-----Sixth

------seventh

-------Eighth

-Nineth

```

正如我们所看到的，不需要考虑类别级别的深度或多个查询，我们可以只用一个简单的查询和递归函数构建嵌套类别或菜单。如果需要动态显示和隐藏功能，我们可以使用`<ul>`和`<li>`来创建嵌套菜单。这对于在不涉及实现阻碍的情况下获得问题的有效解决方案非常重要，比如具有固定级别的连接或固定级别的类别。前面的示例是尾递归的完美展示，在这里我们不需要等待递归返回任何东西，随着我们的前进，结果已经显示出来了。

# 构建嵌套的评论回复系统

我们经常面临的挑战是以适当的方式显示评论回复。按时间顺序显示它们有时不符合我们的需求。我们可能需要以这样的方式显示它们，即每条评论的回复都在实际评论本身下面。换句话说，我们可以说我们需要一个嵌套的评论回复系统或者线程化评论。我们想要构建类似以下截图的东西：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00039.jpg)

我们可以按照嵌套类别部分所做的相同步骤进行。但是，这一次，我们将有一些 UI 元素，使其看起来更真实。假设我们有一个名为`comments`的表，其中包含以下数据和列。为简单起见，我们不涉及多个表关系。我们假设用户名存储在与评论相同的表中：

| **Id** | **评论** | **用户名** | **日期时间** | **父 ID** | **帖子 ID** |
| --- | --- | --- | --- | --- | --- |
| 1 | 第一条评论 | Mizan | 2016-10-01 15:10:20 | 0 | 1 |
| 2 | 第一条回复 | Adiyan | 2016-10-02 04:09:10 | 1 | 1 |
| 3 | 第一条回复的回复 | Mikhael | 2016-10-03 11:10:47 | 2 | 1 |
| 4 | 第一条回复的回复的回复 | Arshad | 2016-10-04 21:22:45 | 3 | 1 |
| 5 | 第一条回复的回复的回复的回复 | Anam | 2016-10-05 12:01:29 | 4 | 1 |
| 6 | 第二条评论 | Keith | 2016-10-01 15:10:20 | 0 | 1 |
| 7 | 第二篇帖子的第一条评论 | Milon | 2016-10-02 04:09:10 | 0 | 2 |
| 8 | 第三条评论 | Ikrum | 2016-10-03 11:10:47 | 0 | 1 |
| 9 | 第二篇帖子的第二条评论 | Ahmed | 2016-10-04 21:22:45 | 0 | 2 |
| 10 | 第二篇帖子的第二条评论的回复 | Afsar | 2016-10-18 05:18:24 | 9 | 2 |

现在让我们编写一个准备好的语句来从帖子中获取所有评论。然后，我们可以构建一个类似嵌套类别的数组：

```php
$sql = "Select * from comments where postID = :postID order by parentID asc, datetime asc"; 

$stmt = $dbh->prepare($sql, array(PDO::ATTR_CURSOR => PDO::CURSOR_FWDONLY)); 

$stmt->setFetchMode(PDO::FETCH_OBJ); 

$stmt->execute(array(':postID' => 1)); 

$result = $stmt->fetchAll(); 

$comments = []; 

foreach ($result as $row) { 

    $comments[$row->parentID][] = $row;

}

```

现在，我们有了数组和其中的所有必需数据；我们现在可以编写一个函数，该函数将递归调用以正确缩进显示评论：

```php
function displayComment(Array $comments, int $n) { 

   if (isset($comments[$n])) { 

      $str = "<ul>"; 

      foreach ($comments[$n] as $comment) { 

          $str .= "<li><div class='comment'><span class='pic'>

            {$comment->username}</span>"; 

          $str .= "<span class='datetime'>{$comment->datetime}</span>"; 

          $str .= "<span class='commenttext'>" . $comment->comment . "

            </span></div>"; 

          $str .= displayComment($comments, $comment->id); 

          $str .= "</li>"; 

       } 

      $str .= "</ul>"; 

      return $str; 

    } 

    return ""; 

} 

echo displayComment($comments, 0); 

```

由于我们在 PHP 代码中添加了一些 HTML 元素，因此我们需要一些基本的 CSS 来使其工作。这是我们编写的 CSS 代码，用于创建清晰的设计。没有花哨的东西，只是纯 CSS 来创建级联效果和对评论每个部分的基本样式：

```php
  ul { 

      list-style: none; 

      clear: both; 

  }

  li ul { 

      margin: 0px 0px 0px 50px; 

  } 

  .pic { 

      display: block; 

      width: 50px; 

      height: 50px; 

      float: left; 

      color: #000; 

      background: #ADDFEE; 

      padding: 15px 10px; 

      text-align: center; 

      margin-right: 20px; 

  }

  .comment { 

      float: left; 

      clear: both; 

      margin: 20px; 

      width: 500px; 

  }

  .datetime { 

      clear: right; 

      width: 400px; 

      margin-bottom: 10px; 

      float: left; 

  }

```

正如前面提到的，我们在这里并不试图做一些复杂的东西，只是响应式的，设备友好的等等。我们假设您可以在应用程序的不同部分集成逻辑而不会出现任何问题。

这是数据和前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00040.jpg)

从前面的两个示例中，我们可以看到，很容易创建嵌套内容，而无需多个查询或对嵌套的连接语句有限制。我们甚至不需要自连接来生成嵌套数据。

# 使用递归查找文件和目录

我们经常需要找到目录中的所有文件。这包括其中所有的子目录，以及这些子目录中的目录。因此，我们需要一个递归解决方案来找到给定目录中的文件列表。以下示例将展示一个简单的递归函数来列出目录中的所有文件：

```php
function showFiles(string $dirName, Array &$allFiles = []) { 

    $files = scandir($dirName); 

    foreach ($files as $key => $value) { 

      $path = realpath($dirName . DIRECTORY_SEPARATOR . $value); 

      if (!is_dir($path)) { 

          $allFiles[] = $path; 

      } else if ($value != "." && $value != "..") { 

          showFiles($path, $allFiles); 

          $allFiles[] = $path; 

      } 

   } 

    return; 

} 

$files = []; 

showFiles(".", $files);

```

`showFiles` 函数实际上接受一个目录，并首先扫描目录以列出其中的所有文件和目录。然后，通过 `foreach` 循环，它遍历每个文件和目录。如果是一个目录，我们再次调用 `.` 函数以列出其中的文件和目录。这将继续，直到我们遍历所有文件和目录。现在，我们有了 `$files` 数组下的所有文件。现在，让我们使用 `foreach` 循环顺序显示文件：

```php
foreach($files as $file) {

    echo $file."\n";

}

```

这将在命令行中产生以下输出：

```php
/home/mizan/packtbook/chapter_1_1.php

/home/mizan/packtbook/chapter_1_2.php

/home/mizan/packtbook/chapter_2_1.php

/home/mizan/packtbook/chapter_2_2.php

/home/mizan/packtbook/chapter_3_.php

/home/mizan/packtbook/chapter_3_1.php

/home/mizan/packtbook/chapter_3_2.php

/home/mizan/packtbook/chapter_3_4.php

/home/mizan/packtbook/chapter_4_1.php

/home/mizan/packtbook/chapter_4_10.php

/home/mizan/packtbook/chapter_4_11.php

/home/mizan/packtbook/chapter_4_2.php

/home/mizan/packtbook/chapter_4_3.php

/home/mizan/packtbook/chapter_4_4.php

/home/mizan/packtbook/chapter_4_5.php

/home/mizan/packtbook/chapter_4_6.php

/home/mizan/packtbook/chapter_4_7.php

/home/mizan/packtbook/chapter_4_8.php

/home/mizan/packtbook/chapter_4_9.php

/home/mizan/packtbook/chapter_5_1.php

/home/mizan/packtbook/chapter_5_2.php

/home/mizan/packtbook/chapter_5_3.php

/home/mizan/packtbook/chapter_5_4.php

/home/mizan/packtbook/chapter_5_5.php

/home/mizan/packtbook/chapter_5_6.php

/home/mizan/packtbook/chapter_5_7.php

/home/mizan/packtbook/chapter_5_8.php

/home/mizan/packtbook/chapter_5_9.php

```

这些是我们在开发过程中面临的一些常见挑战的解决方案。然而，还有其他地方我们将大量使用递归，比如二进制搜索、树、分治算法等。我们将在接下来的章节中讨论它们。

# 分析递归算法

递归算法的分析取决于我们使用的递归类型。如果是线性的，复杂度将不同；如果是二进制的，复杂度也将不同。因此，递归算法没有通用的复杂度。我们必须根据具体情况进行分析。在这里，我们将分析阶乘序列。首先，让我们专注于阶乘部分。如果我们回忆一下这一节，我们对阶乘递归有这样的东西：

```php
function factorial(int $n): int { 

    if ($n == 0) 

    return 1; 

    return $n * factorial($n - 1); 

} 

```

假设计算阶乘（`$n`）需要 `T(n)`。我们将专注于如何使用大 O 符号表示这个 `T(n)`。每次调用阶乘函数时，都涉及某些步骤：

1.  每次，我们都在检查基本情况。

1.  然后，我们在每个循环中调用阶乘（`$n-1`）。

1.  我们在每个循环中用 `$n` 进行乘法。

1.  然后，我们返回结果。

现在，如果我们用 `T(n)` 表示这个，那么我们可以说：

*T(n) = 当 n = 0 时，a*

*T(n) = 当 n > 0 时，T(n-1) + b*

在这里，*a* 和 *b* 都是一些常数。现在，让我们用 *n* 生成 *a* 和 *b* 之间的关系。我们可以轻松地写出以下方程：

*T(0) = a*

*T(1) = T(0) + b = a + b*

*T(2) = T(1) + b = a + b + b = a + 2b*

*T(3) = T(2) + b = a + 2b + b = a + 3b*

*T(4) = T(3) + b = a + 3b + b = a + 4b*

我们可以看到这里出现了一个模式。因此，我们可以确定：

*T(n) = a + (n) b*

或者，我们也可以简单地说 `T(n) = O(n)`。

因此，阶乘递归具有线性复杂度 `O(n)`。

具有递归的斐波那契序列大约具有 `O(2^n)` 的复杂度。计算非常详细，因为我们必须考虑大 O 符号的下界和上界。在接下来的章节中，我们还将分析二进制递归，如二进制搜索和归并排序。我们将在这些章节中更多地关注递归分析。

# PHP 中的最大递归深度

由于递归是函数调用自身的过程，我们可以心中有一个有效的问题，比如“这个递归可以有多深？”。让我们为此编写一个小程序：

```php
function maxDepth() {

    static $i = 0;

    print ++$i . "\n";

    maxDepth();

}

maxDepth();

```

我们能猜测最大深度水平吗？在耗尽内存限制之前，深度达到了 917,056 级。如果启用了**XDebug**，那么限制将比这个小得多。这也取决于您的内存、操作系统和 PHP 设置，如内存限制和最大执行时间。

虽然我们有选择深入进行递归，但始终重要的是要记住，我们必须控制好我们的递归函数。我们应该知道基本条件以及递归必须在何处结束。否则，可能会产生一些错误的结果或突然结束。

# 使用 SPL 递归迭代器

标准 PHP 库 SPL 有许多内置的迭代器，用于递归目的。我们可以根据需要使用它们，而不必费力实现它们。以下是迭代器及其功能的列表：

+   **RecursiveArrayIterator**：这个递归迭代器允许迭代任何类型的数组或对象，并修改键或值，或取消它们。它还允许迭代当前迭代器条目。

+   递归回调过滤迭代器：如果我们希望递归地将回调应用于任何数组或对象，这个迭代器可以非常有帮助。

+   递归目录迭代器：这个迭代器允许迭代任何目录或文件系统。它使得目录列表非常容易。例如，我们可以很容易地使用这个迭代器重新编写本章中编写的目录列表程序：

```php
$path = realpath('.'); 

$files = new RecursiveIteratorIterator( 

   new RecursiveDirectoryIterator($path), RecursiveIteratorIterator::SELF_FIRST); 

foreach ($files as $name => $file) { 

    echo "$name\n"; 

}

```

+   递归过滤迭代器：如果我们在迭代过程中递归地寻找过滤选项，我们可以使用这个抽象迭代器来实现过滤部分。

+   递归迭代迭代器：如果我们想要迭代任何递归迭代器，我们可以使用这个。它已经内置，我们可以很容易地应用它。在`RecursiveDirectoryIterator`部分中显示了它的使用示例。

+   递归正则表达式迭代器：如果您想要应用正则表达式来过滤迭代器，我们可以使用这个迭代器以及其他迭代器。

+   递归树迭代器：递归树迭代器允许我们为任何目录或多维数组创建类似树的图形表示。例如，以下足球队列表数组将产生树结构：

```php
$teams = array( 

    'Popular Football Teams', 

    array( 

  'La Lega', 

  array('Real Madrid', 'FC Barcelona', 'Athletico Madrid', 'Real  

    Betis', 'Osasuna') 

    ), 

    array( 

  'English Premier League', 

  array('Manchester United', 'Liverpool', 'Manchester City', 'Arsenal',   

    'Chelsea') 

    ) 

); 

$tree = new RecursiveTreeIterator( 

  new RecursiveArrayIterator($teams), null, null, RecursiveIteratorIterator::LEAVES_ONLY 

); 

foreach ($tree as $leaf) 

    echo $leaf . PHP_EOL;

```

输出将如下所示：

```php
|-Popular Football Teams

| |-La Lega

|   |-Real Madrid

|   |-FC Barcelona

|   |-Athletico Madrid

|   |-Real Betis

|   \-Osasuna

 |-English Premier League

 |-Manchester United

 |-Liverpool

 |-Manchester City

 |-Arsenal

 \-Chelsea

```

# 使用 PHP 内置函数 array_walk_recursive

`array_walk_recursive`可以是 PHP 中非常方便的内置函数，因为它可以递归地遍历任何大小的数组并应用回调函数。无论我们想要找出多维数组中是否存在元素，还是获取多维数组的总和，我们都可以毫无问题地使用这个函数。

执行以下代码示例将产生输出**136**：

```php
function array_sum_recursive(Array $array) { 

    $sum = 0; 

    array_walk_recursive($array, function($v) use (&$sum) { 

      $sum += $v; 

    }); 

    return $sum; 

} 

$arr =  

[1, 2, 3, 4, 5, [6, 7, [8, 9, 10, [11, 12, 13, [14, 15, 16]]]]]; 

echo array_sum_recursive($arr); 

```

PHP 中的另外两个内置递归数组函数是`array_merge_recursive`和`array_replace_recursive`。我们可以使用它们来合并多个数组到一个数组中，或者从多个数组中替换，分别。

# 总结

到目前为止，我们讨论了递归的不同属性和实际用途。我们已经看到了如何分析递归算法。计算机编程和递归是两个不可分割的部分。递归的使用几乎无处不在于编程世界中。在接下来的章节中，我们将更深入地探讨它，并在适用的地方应用它。在下一章中，我们将讨论另一个特殊的数据结构，称为“树”。


# 第六章：理解和实现树

到目前为止，我们对数据结构的探索只涉及了线性部分。无论我们使用数组、链表、栈还是队列，所有这些都是线性数据结构。我们已经看到了线性数据结构操作的复杂性，大多数情况下，插入和删除可以以`O(1)`的复杂度执行。然而，搜索有点复杂，并且需要`O(n)`的复杂度。唯一的例外是 PHP 数组，实际上它的工作原理是哈希表，如果索引或键以这种方式管理，可以在`O(1)`中进行搜索。为了解决这个问题，我们可以使用分层数据结构而不是线性数据结构。分层数据可以解决许多线性数据结构无法轻松解决的问题。每当我们谈论家族谱系、组织结构和网络连接图时，实际上我们在谈论分层数据。树是一种表示分层数据的特殊**抽象数据类型**（**ADT**）。与链表不同，链表也是一种 ADT，树是分层的，而链表是线性的。在本章中，我们将探索树的世界。树结构的一个完美例子可以是家族谱系，就像下面的图片：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00041.jpg)

# 树的定义和属性

树是由边连接的节点或顶点的分层集合。树不能有循环，只有边存在于节点和其后代节点或子节点之间。同一父节点的两个子节点之间不能有任何边。每个节点除了顶节点（也称为根节点）外，还可以有一个父节点。每棵树只能有一个根节点。在下图中，**A**是根节点，**B**，**C**和**D**是**A**的子节点。我们还可以说 A 是**B**，**C**和**D**的父节点。**B**，**C**和**D**被称为兄弟姐妹，因为它们是来自同一父节点**A**的子节点：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00042.gif)

没有任何子节点的节点称为叶子。在前面的图表中，**K**，**L**，**F**，**G**，**M**，**I**和**J**都是叶子节点。叶子节点也称为外部节点或终端节点。除了根节点之外，至少有一个子节点的节点称为内部节点。在这里，**B**，**C**，**D**，**E**和**H**是内部节点。在描述树数据结构时，我们使用一些其他常见术语：

+   **后代**：这是一个可以通过重复进行到达父节点的节点。例如，在前面的图表中，**M** 是**C**的后代。

+   **祖先**：这是一个可以通过重复方式从子节点到父节点到达的节点。例如，**B**是**L**的祖先。

+   **度**：特定父节点的子节点总数称为其度。在我们的例子中，**A** 的度为 3，**B** 的度为 1，**C** 的度为 3，**D** 的度为 2。

+   **路径**：从源节点到目标节点的节点和边的序列称为两个节点之间的路径。路径的长度是路径中的节点数。在我们的例子中，**A**到**M**的路径是**A-C-H-M**，路径的长度为 4：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00043.jpg)

+   **节点的高度**：节点的高度由节点与后代节点的最深层之间的边的数量定义。例如，节点**B**的高度为 2。

+   **层级**：层级表示节点的代。如果父节点在第*n*层，其子节点将在*n+1*层。因此，层级由节点与根之间的边的数量加 1 定义。在这里：

+   +   根**A**在**Level 0**

+   **B**，**C**和**D**在**Level 1**

+   **E**，**F**，**G**，**H**，**I**和**J**在**Level 2**

+   **K**，**L**和**M**在**Level 3**

+   **树的高度**：树的高度由其根节点的高度定义。在这里，树的高度为 3。

+   **子树**：在树结构中，每个子节点都递归地形成一个子树。换句话说，树由许多子树组成。例如，**B**与**E**，**K**和**L**形成一个子树，而**E**与**K**和**L**形成一个子树。在前面的例子中，我们已经在左侧用不同的颜色标识了每个子树。我们也可以对**C**和**D**及其子树做同样的事情。

+   **深度**：节点的深度由节点与根节点之间的边的数量确定。例如，在我们的树图中，**H**的深度为 2，**L**的深度为 3。

+   **森林**：森林是零个或多个不相交树的集合。

+   **遍历**：这表示按特定顺序访问节点的过程。我们将在接下来的部分经常使用这个术语。

+   **键**：键是用于搜索目的的节点中的值。

# 使用 PHP 实现树

到目前为止，您已经了解了树数据结构的不同属性。如果我们将树数据结构与现实生活中的例子进行比较，我们可以考虑我们的组织结构或家族谱来表示数据结构。对于组织结构，有一个根节点，可以是公司的 CEO，然后是 CXO 级别的员工，然后是其他级别的员工。在这里，我们不限制特定节点的程度。这意味着一个节点可以有多个子节点。因此，让我们考虑一个节点结构，我们可以定义节点属性、其父节点和其子节点。它可能看起来像这样：

```php
class TreeNode { 

    public $data = NULL; 

    public $children = []; 

    public function __construct(string $data = NULL) { 

      $this->data = $data; 

    } 

    public function addChildren(TreeNode $node) { 

      $this->children[] = $node; 

    } 

} 

```

如果我们看一下前面的代码，我们可以看到我们为数据和子节点声明了两个公共属性。我们还有一个方法来向特定节点添加子节点。在这里，我们只是将新的子节点追加到数组的末尾。这将使我们有选择地为特定节点添加多个节点作为子节点。由于树是一个递归结构，它将帮助我们递归地构建树，也可以递归地遍历树。

现在，我们有了节点，让我们构建一个树结构，定义树的根节点以及遍历整个树的方法。因此，基本的树结构将如下所示：

```php
class Tree { 

    public $root = NULL; 

    public function __construct(TreeNode $node) { 

      $this->root = $node; 

    } 

    public function traverse(TreeNode $node, int $level = 0) { 

      if ($node) { 

        echo str_repeat("-", $level); 

        echo $node->data . "\n"; 

        foreach ($node->children as $childNode) { 

          $this->traverse($childNode, $level + 1); 

        } 

      } 

    } 

} 

```

前面的代码显示了一个简单的树类，我们可以在其中存储根节点引用，并从任何节点遍历树。在遍历部分，我们正在访问每个子节点，然后立即递归调用遍历方法以获取当前节点的子节点。我们正在传递一个级别，以便在节点名称的开头打印一个破折号（-），这样我们就可以轻松地理解子级数据。

现在让我们创建根节点并将其分配给树作为根。代码将如下所示：

```php
    $ceo = new TreeNode("CEO"); 

    $tree = new Tree($ceo); 

```

在这里，我们创建了第一个节点作为 CEO，然后创建了树，并将 CEO 节点分配为树的根节点。现在是时候从根节点开始扩展我们的树了。由于我们选择了 CEO 的例子，我们现在将在 CEO 下添加 CXO 和其他员工。以下是此代码：

```php
$cto     = new TreeNode("CTO"); 

$cfo     = new TreeNode("CFO"); 

$cmo     = new TreeNode("CMO"); 

$coo     = new TreeNode("COO"); 

$ceo->addChildren($cto); 

$ceo->addChildren($cfo); 

$ceo->addChildren($cmo); 

$ceo->addChildren($coo); 

$seniorArchitect = new TreeNode("Senior Architect"); 

$softwareEngineer = new TreeNode("Software Engineer"); 

$userInterfaceDesigner      = new TreeNode("User Interface Designer"); 

$qualityAssuranceEngineer = new TreeNode("Quality Assurance Engineer"); 

$cto->addChildren($seniorArchitect); 

$seniorArchitect->addChildren($softwareEngineer); 

$cto->addChildren($qualityAssuranceEngineer); 

$cto->addChildren($userInterfaceDesigner); 

$tree->traverse($tree->root); 

```

在这里，我们在开始时创建了四个新节点（CTO、CFO、CMO 和 COO），并将它们分配为 CEO 节点的子节点。然后我们创建了高级架构师，这是软件工程师节点，接着是用户界面设计师和质量保证工程师。我们已经将高级软件工程师节点分配为高级架构师节点的子节点，并将高级架构师分配为 CTO 的子节点，以及用户界面工程师和质量保证工程师。最后一行是从根节点显示树。这将在我们的命令行中输出以下行：

```php
CEO

-CTO

--Senior Architect

---Software Engineer

--Quality Assurance Engineer

--User Interface Designer

-CFO

-CMO

-COO

```

考虑到前面的输出，我们在级别 0 处有`CEO`。`CTO`，`CFO`，`CMO`和`COO`在级别 1 处。`Senior Architect`，`User Interface Designer`和`Quality Assurance Engineer`在级别 2 处，`Software Engineer`在级别 3 处。

我们已经使用 PHP 构建了一个基本的树数据结构。现在，我们将探索我们拥有的不同类型的树。

# 不同类型的树结构

编程世界中存在许多类型的树数据结构。我们将在这里探讨一些最常用的树结构。

# 二叉树

二进制是树结构的最基本形式，其中每个节点最多有两个子节点。子节点称为左节点和右节点。二叉树将如下图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00044.jpg)

# 二叉搜索树

二叉搜索树（BST）是一种特殊类型的二叉树，其中节点以排序的方式存储。它以这样一种方式排序，即在任何给定点，节点值必须大于或等于左子节点值，并且小于右子节点值。每个节点都必须满足此属性，才能将其视为二叉搜索树。由于节点按特定顺序排序，二叉搜索算法可以应用于以对数时间搜索 BST 中的项目。这总是优于线性搜索，它需要**O(n)**时间，我们将在下一章中探讨它。以下是一个二叉搜索树的示例：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00045.jpg)

# 自平衡二叉搜索树

自平衡二叉搜索树或高度平衡二叉搜索树是一种特殊类型的二叉搜索树，它试图通过自动调整始终保持树的高度或层级数尽可能小。例如，下图显示了左侧的二叉搜索树和右侧的自平衡二叉搜索树：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00046.jpg)

高度平衡的二叉树总是比普通 BST 更好，因为它可以使搜索操作比普通 BST 更快。有不同的自平衡或高度平衡二叉搜索树的实现。其中一些流行的如下：

+   AA 树

+   AVL 树

+   红黑树

+   替罪羊树

+   伸展树

+   2-3 树

+   Treap

我们将在以下章节讨论一些高度平衡树。

# AVL 树

AVL 树是一种自平衡的二叉搜索树，其中一个节点的两个子树的高度最多相差 1。如果高度增加，在任何情况下都会重新平衡以使高度差为 1。这使 AVL 树在不同操作的复杂度上具有对数优势。以下是 AVL 树的示例：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00047.jpg)

# 红黑树

红黑树是一种具有额外属性的自平衡二叉搜索树，即颜色。二叉树中的每个节点存储一位额外的信息，即颜色，可以具有红色或黑色的值。与 AVL 树一样，红黑树也用于实时应用，因为平均和最坏情况的复杂度也是对数的。示例红黑树如下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00048.jpg)

# B 树

B 树是一种特殊类型的二叉树，它是自平衡的。这与自平衡的二叉搜索树不同。关键区别在于，在 B 树中，我们可以有任意数量的节点作为子节点，而不仅仅是两个。B 树用于大量数据，并主要用于文件系统和数据库。B 树中不同操作的复杂度是对数的。

# N 叉树

N 叉树是一种特殊类型的树，其中一个节点最多可以有 N 个子节点。这也被称为 k 路树或 M 路树。二叉树是 N 叉树，其中 N 的值为 2。

# 理解二叉树

我们经常会对二叉树和二叉搜索树感到困惑。正如我们在定义中所看到的，BST 是一种排序的二叉树。如果它是排序的，那么与普通二叉树相比，我们可以有性能改进。每个二叉树节点最多可以有两个子节点，分别称为左子节点和右子节点。然而，根据二叉树的类型，可以有零个、一个或两个子节点。

我们还可以将二叉树分类为不同的类别：

+   **满二叉树：** 满二叉树是一棵树，每个节点上要么没有子节点，要么有两个子节点。满二叉树也被称为完全二叉树或平衡二叉树。

+   **完美二叉树：** 完美二叉树是一棵二叉树，其中所有内部节点恰好有两个子节点，所有叶子节点的级别或深度相同。

+   **完全二叉树：** 完全二叉树是一棵二叉树，除了最后一层外，所有层都完全填充，所有节点尽可能地靠左。以下图表显示了满二叉树、完全二叉树和完美二叉树：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00049.jpg)

# 实现二叉树

我们现在将创建一个二叉树（不是二叉搜索树）。二叉树中必须具有的关键因素是，我们必须为左孩子节点和右孩子节点保留两个占位符，以及我们想要存储在节点中的数据。二叉节点的简单实现将如下所示：

```php
class BinaryNode { 

    public $data; 

    public $left; 

    public $right; 

    public function __construct(string $data = NULL) { 

      $this->data = $data; 

      $this->left = NULL; 

      $this->right = NULL; 

    } 

    public function addChildren(BinaryNode $left, BinaryNode $right) { 

      $this->left = $left;

      $this->right = $right;

    }

}

```

前面的代码显示，我们有一个带有树属性的类来存储数据，左边和右边。当我们构造一个新节点时，我们将节点值添加到数据属性中，左边和右边保持`NULL`，因为我们不确定是否需要它们。我们还有一个`addChildren`方法来向特定节点添加左孩子和右孩子。

现在，我们将创建一个二叉树类，我们可以在其中定义根节点以及类似于本章早期的基本树实现的遍历方法。两种实现之间的区别在于遍历过程。在我们之前的示例中，我们使用`foreach`来遍历每个子节点，因为我们不知道有多少个节点。由于二叉树中的每个节点最多可以有两个节点，并且它们被命名为左和右，我们只能遍历左节点，然后遍历每个特定节点访问的右节点。更改后的代码将如下所示：

```php
class BinaryTree { 

    public $root = NULL; 

    public function __construct(BinaryNode $node) { 

    $this->root = $node; 

    } 

    public function traverse(BinaryNode $node, int $level    

      = 0) { 

      if ($node) { 

          echo str_repeat("-", $level); 

          echo $node->data . "\n"; 

          if ($node->left) 

            $this->traverse($node->left, $level + 1); 

          if ($node->right) 

            $this->traverse($node->right, $level + 1); 

         } 

    } 

} 

```

这看起来与本章早期我们所拥有的基本树类非常相似。现在，让我们用一些节点填充二叉树。通常，在任何足球或板球比赛中，我们都有淘汰赛轮次，两支球队互相比赛，赢家继续前进，一直到决赛。我们可以在我们的示例中使用类似的结构作为二叉树。因此，让我们创建一些二叉节点并将它们结构化：

```php
$final = new BinaryNode("Final"); 

$tree = new BinaryTree($final); 

$semiFinal1 = new BinaryNode("Semi Final 1"); 

$semiFinal2 = new BinaryNode("Semi Final 2"); 

$quarterFinal1 = new BinaryNode("Quarter Final 1"); 

$quarterFinal2 = new BinaryNode("Quarter Final 2"); 

$quarterFinal3 = new BinaryNode("Quarter Final 3"); 

$quarterFinal4 = new BinaryNode("Quarter Final 4"); 

$semiFinal1->addChildren($quarterFinal1, $quarterFinal2); 

$semiFinal2->addChildren($quarterFinal3, $quarterFinal4); 

$final->addChildren($semiFinal1, $semiFinal2); 

$tree->traverse($tree->root); 

```

首先，我们创建了一个名为 final 的节点，并将其作为根节点。然后，我们创建了两个半决赛节点和四个四分之一决赛节点。两个半决赛节点分别有两个四分之一决赛节点作为左右子节点。最终节点有两个半决赛节点作为左右子节点。`addChildren`方法正在为节点执行子节点分配工作。在最后一行，我们遍历了树并按层次显示了数据。如果我们在命令行中运行此代码，我们将看到以下输出：

```php
Final

-Semi Final 1

--Quarter Final 1

--Quarter Final 2

-Semi Final 2

--Quarter Final 3

--Quarter Final 4

```

# 使用 PHP 数组创建二叉树

我们可以使用 PHP 数组实现二叉树。由于二叉树最多可以有零到两个子节点，我们可以将最大子节点数设为 2，并构建一个公式来找到给定节点的子节点。让我们从上到下、从左到右为二叉树中的节点编号。因此，根节点将具有编号**0**，左孩子**1**，右孩子**2**，依此类推，直到为每个节点编号，就像以下图表所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00050.gif)

我们很容易看到，对于节点**0**，左孩子是**1**，右孩子是**2**。对于节点**1**，左孩子是**3**，右孩子是**4**，依此类推。我们可以很容易地将这个放入一个公式中：

如果*i*是我们的节点编号，那么：

*左节点= 2 X i + 1*

*右节点= 2 X (i + 1)*

现在，让我们使用 PHP 数组创建比赛日程的示例。如果按照我们的讨论进行排名，那么它将如下所示：

```php
    $nodes = []; 

    $nodes[] = "Final"; 

    $nodes[] = "Semi Final 1"; 

    $nodes[] = "Semi Final 2"; 

    $nodes[] = "Quarter Final 1"; 

    $nodes[] = "Quarter Final 2"; 

    $nodes[] = "Quarter Final 3"; 

    $nodes[] = "Quarter Final 4"; 

```

基本上，我们将创建一个带有自动索引的数组，从 0 开始。这个数组将被用作二叉树的表示。现在，我们将修改我们的`BinaryTree`类，使用这个数组而不是我们的节点类，以及左右子节点以及遍历方法。现在，我们将基于节点编号而不是实际节点引用进行遍历：

```php
class BinaryTree { 

    public $nodes = []; 

    public function __construct(Array $nodes) { 

      $this->nodes = $nodes; 

    } 

    public function traverse(int $num = 0, int $level = 0) { 

      if (isset($this->nodes[$num])) { 

          echo str_repeat("-", $level); 

          echo $this->nodes[$num] . "\n"; 

          $this->traverse(2 * $num + 1, $level+1); 

          $this->traverse(2 * ($num + 1), $level+1); 

      } 

    } 

} 

```

从前面的实现中可以看出，遍历部分使用节点位置而不是引用。这个节点位置就是数组索引。因此，我们可以直接访问数组索引并检查它是否为空。如果不为空，我们可以继续使用递归的方式深入。如果我们想使用数组创建二叉树并打印数组值，我们必须编写以下代码：

```php
$tree = new BinaryTree($nodes); 

$tree->traverse(0); 

```

如果我们在命令行中运行此代码，将会看到以下输出：

```php
Final

-Semi Final 1

--Quarter Final 1

--Quarter Final 2

-Semi Final 2

--Quarter Final 3

--Quarter Final 4

```

我们可以使用一个简单的`while`循环来遍历数组并访问每个节点，而不是递归进行。在我们所有的递归示例中，我们会发现如果以迭代的方式使用它们，有些会更有效率。我们也可以直接使用它们，而不是为二叉树创建一个类。

# 理解二叉搜索树

BST 是一种二叉树，它是按照树始终排序的方式构建的。这意味着左孩子节点的值小于或等于父节点的值，右孩子节点的值大于父节点的值。因此，每当我们需要搜索一个值时，要么搜索左边，要么搜索右边。由于它是排序的，我们只需要搜索树的一部分，而不是两部分，这种递归持续进行。由于它的分割性质，搜索变得非常快，我们可以实现对搜索的对数复杂度。例如，如果我们有*n*个节点，我们将搜索前半部分或后半部分的节点。一旦我们在前半部分或后半部分，我们可以再次将其分成两半，这意味着我们的一半现在变成了四分之一，如此循环直到达到最终节点。由于我们不是移动到每个节点进行搜索，因此操作不会花费`O(n)`的复杂度。在下一章中，我们将对二分搜索的复杂性进行分析，并看到为什么二叉搜索树的搜索复杂度是`O(log n)`。与二叉树不同，我们不能在不重建 BST 属性的情况下向树中添加任何节点或删除任何节点。

如果节点**X**有两个孩子，则节点**X**的后继是属于树的最小值，大于**X**的值。换句话说，后继是右子树的最小值。另一方面，前驱是左子树的最大值。现在，我们将更多关注 BST 的不同操作以及执行这些操作时需要考虑的步骤。

以下是 BST 的操作。

# 插入一个新节点

当我们在二叉搜索树中插入一个新节点时，我们必须考虑以下步骤：

1.  创建一个新节点作为叶子节点（没有左孩子或右孩子）。

1.  从根节点开始，并将其设置为当前节点。

1.  如果节点为空，则将新节点作为根。

1.  检查新值是小于当前节点还是大于当前节点。

1.  如果小于，则转到左侧并将左侧设置为当前节点。

1.  如果大于，则转到右侧并将右侧设置为当前节点。

1.  继续*步骤 3*，直到所有节点都被访问并设置了新节点。

# 搜索一个节点

当我们在二叉搜索树中搜索一个新节点时，我们必须考虑以下步骤：

1.  从根节点开始，并将其设置为当前节点。

1.  如果当前节点为空，则返回 false。

1.  如果当前节点的值是搜索值，则返回 true。

1.  检查搜索值是小于当前节点还是大于当前节点。

1.  如果小于，则转到左侧并将左侧设置为当前节点。

1.  如果大于，则转到右侧并将右侧设置为当前节点。

1.  继续*步骤 3*，直到所有节点都被访问。

# 查找最小值

由于二叉搜索树以排序方式存储数据，我们始终可以在左节点中找到较小的数据，在右节点中找到较大的数据。因此，查找最小值将需要我们从根节点开始访问所有左节点，直到找到最左边的节点及其值。以下是查找最小值的步骤：

1.  从根节点开始，并将其设置为当前节点。

1.  如果当前节点为空，则返回 false。

1.  转到左侧并将左侧设置为当前节点。

1.  如果当前节点没有左节点，则转到*步骤 5*；否则，继续*步骤 4*。

1.  继续*步骤 3*，直到所有左节点都被访问。

1.  返回当前节点。

# 查找最大值

以下是查找最大值的步骤：

1.  从根节点开始，并将其设置为当前节点。

1.  如果当前节点为空，则返回 false。

1.  转到右侧并将右侧设置为当前节点。

1.  如果当前节点没有右节点，则转到*步骤 5*；否则，继续*步骤 4*。

1.  继续*步骤 3*，直到所有右节点都被访问。

1.  返回当前节点。

# 删除节点

当我们删除一个节点时，我们必须考虑节点可以是内部节点或叶子节点。如果它是叶子节点，则它没有子节点。但是，如果节点是内部节点，则它可以有一个或两个子节点。在这种情况下，我们需要采取额外的步骤来确保在删除后树的构造是正确的。这就是为什么从 BST 中删除节点始终是一项具有挑战性的工作，与其他操作相比。以下是删除节点时要考虑的事项：

1.  如果节点没有子节点，则使节点为 NULL。

1.  如果节点只有一个子节点，则使子节点取代节点的位置。

1.  如果节点有两个子节点，则找到节点的后继并将其替换为当前节点的位置。删除后继节点。

我们已经讨论了二叉搜索树的大部分可能操作。现在，我们将逐步实现二叉搜索树，从插入、搜索、查找最小和最大值开始，最后是删除操作。让我们开始实现吧。

# 构建二叉搜索树

正如我们所知，一个节点可以有两个子节点，并且本身可以以递归方式表示树。我们将定义我们的节点类更加功能强大，并具有所有必需的功能来查找最大值、最小值、前任和后继。稍后，我们还将为节点添加删除功能。让我们检查 BST 的节点类的以下代码：

```php
class Node { 

    public $data; 

    public $left; 

    public $right; 

    public function __construct(int $data = NULL) { 

       $this->data = $data; 

       $this->left = NULL; 

       $this->right = NULL; 

    } 

    public function min() { 

       $node = $this; 

       while($node->left) { 

         $node = $node->left; 

       } 

         return $node; 

    } 

    public function max() { 

         $node = $this; 

         while($node->right) { 

            $node = $node->right; 

         } 

         return $node; 

    } 

    public function successor() { 

         $node = $this; 

         if($node->right) 

               return $node->right->min(); 

         else 

               return NULL; 

    } 

    public function predecessor() { 

         $node = $this; 

         if($node->left) 

               return $node->left->max(); 

         else 

               return NULL;

    }

}

```

节点类看起来很简单，并且与我们在前一节中定义的步骤相匹配。每个新节点都是叶子节点，因此在创建时没有左节点或右节点。由于我们知道可以在节点的左侧找到较小的值以找到最小值，因此我们正在到达最左边的节点和最右边的节点以获取最大值。对于后继，我们正在从给定节点的右子树中找到节点的最小值，并且对于前任部分，我们正在从左子树中找到节点的最大值。

现在，我们需要一个 BST 结构来在树中添加新节点，以便我们可以遵循插入原则：

```php
class BST { 

    public $root = NULL; 

    public function __construct(int $data) { 

         $this->root = new Node($data); 

    } 

    public function isEmpty(): bool { 

         return $this->root === NULL; 

    } 

    public function insert(int $data) { 

         if($this->isEmpty()) { 

               $node = new Node($data); 

               $this->root = $node; 

               return $node; 

         }  

    $node = $this->root; 

    while($node) { 

      if($data > $node->data) { 

          if($node->right) { 

            $node = $node->right; 

          } else { 

            $node->right = new Node($data); 

            $node = $node->right; 

            break; 

          } 

      } elseif($data < $node->data) { 

          if($node->left) { 

            $node = $node->left; 

          } else { 

            $node->left = new Node($data); 

            $node = $node->left; 

            break; 

          } 

      } else { 

            break; 

      } 

    } 

    return $node; 

    } 

    public function traverse(Node $node) { 

      if ($node) { 

          if ($node->left) 

            $this->traverse($node->left); 

          echo $node->data . "\n"; 

          if ($node->right)

            $this->traverse($node->right);

      }

    }

}

```

如果我们看前面的代码，我们只有一个 BST 类的属性，它将标记根节点。在构建 BST 对象时，我们传递一个单个值，该值将用作树的根。`isEmpty`方法检查树是否为空。`insert`方法允许我们在树中添加新节点。逻辑检查值是否大于或小于根节点，并遵循 BST 的原则将新节点插入正确的位置。如果值已经插入，我们将忽略它并避免添加到树中。

我们还有一个`traverse`方法来遍历节点并以有序格式查看数据（首先左侧，然后是节点，然后是右侧节点的值）。它有一个指定的名称，我们将在下一节中探讨。现在，让我们准备一个样本代码来使用 BST 类，并添加一些数字，然后检查这些数字是否以正确的方式存储。如果 BST 有效，则遍历将显示一个有序的数字列表，无论我们如何插入它们：

```php
$tree = new BST(10); 

$tree->insert(12); 

$tree->insert(6); 

$tree->insert(3); 

$tree->insert(8); 

$tree->insert(15); 

$tree->insert(13); 

$tree->insert(36); 

$tree->traverse($tree->root);

```

如果我们看一下前面的代码，`10`是我们的根节点，然后我们随机添加了新节点。最后，我们调用了遍历方法来显示节点以及它们在二叉搜索树中的存储方式。以下是前面代码的输出：

```php
3

6

8

10

12

13

15

36

```

实际树在视觉上看起来是这样的，与 BST 实现所期望的完全一样：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00051.jpg)

现在，我们将在我们的 BST 类中添加搜索部分。我们想要找出值是否存在于树中。如果值不在我们的 BST 中，它将返回 false，否则返回节点。这是简单的搜索功能：

```php
public function search(int $data) { 

  if ($this->isEmpty()) { 

      return FALSE; 

  } 

  $node = $this->root; 

  while ($node) { 

      if ($data > $node->data) { 

        $node = $node->right; 

      } elseif ($data < $node->data) { 

        $node = $node->left; 

      } else { 

        break; 

      } 

  } 

  return $node; 

}

```

在前面的代码中，我们可以看到我们正在从节点中搜索树中的值，并迭代地跟随树的左侧或右侧。如果没有找到具有该值的节点，则返回节点的叶子节点，即`NULL`。我们可以这样测试代码：

```php
echo $tree->search(14) ? "Found" : "Not Found";

echo "\n";

echo $tree->search(36) ? "Found" : "Not Found";

```

这将产生以下输出。由于`14`不在我们的列表中，它将显示`Not Found`，而对于`36`，它将显示`Found`：

```php
Not Found

Found

```

现在，我们将进入编码中最复杂的部分，即删除节点。我们需要实现节点可以有零个、一个或两个子节点的每种情况。以下图像显示了我们需要满足的删除节点的三个条件，并确保在操作后二叉搜索树仍然是二叉搜索树。当处理具有两个子节点的节点时，我们需要小心。因为我们需要在节点之间来回移动，我们需要知道当前节点的父节点是哪个节点。因此，我们需要添加一个额外的属性来跟踪任何节点的父节点：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00052.jpg)

这是我们要添加到`Node`类的代码更改：

```php
    public $data;

    public $left;

    public $right;

    public $parent;

    public function __construct(int $data = NULL, Node $parent = NULL)   

     {

      $this->data = $data; 

      $this->parent = $parent; 

      $this->left = NULL; 

      $this->right = NULL; 

     }

```

此代码块现在还将新创建的节点与其直接父节点建立父子关系。我们还希望将我们的删除功能与单个节点关联起来，以便我们可以找到一个节点，然后只需使用`delete`方法将其删除。以下是删除功能的代码：

```php
public function delete() { 

    $node = $this; 

    if (!$node->left && !$node->right) { 

        if ($node->parent->left === $node) { 

          $node->parent->left = NULL; 

        } else { 

          $node->parent->right = NULL; 

        } 

    } elseif ($node->left && $node->right) { 

        $successor = $node->successor(); 

        $node->data = $successor->data; 

        $successor->delete(); 

    } elseif ($node->left) { 

        if ($node->parent->left === $node) { 

          $node->parent->left = $node->left; 

          $node->left->parent = $node->parent->left; 

        } else { 

          $node->parent->right = $node->left; 

          $node->left->parent = $node->parent->right; 

        } 

        $node->left = NULL; 

    } elseif ($node->right) { 

        if ($node->parent->left === $node) { 

          $node->parent->left = $node->right; 

          $node->right->parent = $node->parent->left; 

        } else { 

          $node->parent->right = $node->right; 

          $node->right->parent = $node->parent->right; 

        } 

        $node->right = NULL; 

    }

}

```

第一个条件检查节点是否是叶子节点。如果节点是叶子节点，那么我们只需使父节点删除子节点的引用（左侧或右侧）。这样，节点将与树断开连接，满足了我们零个子节点的第一个条件。

接下来的条件实际上检查了我们的第三个条件，即节点有两个子节点的情况。在这种情况下，我们获取节点的后继节点，将后继节点的值分配给节点本身，并删除后继节点。这只是从后继节点复制数据。

接下来的两个条件检查节点是否有单个子节点，就像我们之前的*Case 2*图表所示。由于节点只有一个子节点，它可以是左子节点或右子节点。因此，条件检查单个子节点是否是节点的左子节点。如果是，我们需要根据节点本身与其父节点的位置，将左子节点指向节点的父节点左侧或右侧引用。右子节点也适用相同的规则。在这里，右子节点引用设置为其父节点的左侧或右侧子节点，而不是基于节点位置的引用。

由于我们已经更新了我们的节点类，我们需要对我们的 BST 类进行一些更改，以便插入和删除节点。插入代码将如下所示：

```php
function insert(int $data)

 {

    if ($this->isEmpty()) {

          $node = new Node($data);

          $this->root = $node;

          return $node;

    }

    $node = $this->root;

    while ($node) {

          if ($data > $node->data) {

                if ($node->right) {

                      $node = $node->right;

                }

                else {

                      $node->right = new Node($data, $node);

                      $node = $node->right;

                      break;

                }

          }

          elseif ($data < $node->data) {

                if ($node->left) {

                      $node = $node->left;

                }

                else {

                      $node->left = new Node($data, $node);

                      $node = $node->left;

                      break;

                }

          }

          else {

                break;

    }

 }

    return $node;

 }

```

代码看起来与我们之前使用的代码类似，只有一个小改变。现在，当我们创建一个新节点时，我们会发送当前��点的引用。这个当前节点将被用作新节点的父节点。`new Node($data, $node)`代码实际上就是这样做的。

对于删除一个节点，我们可以先进行搜索，然后使用节点类中的`delete`方法删除搜索到的节点。因此，`remove`函数本身将会非常小，就像这里的代码一样：

```php
public function remove(int $data) {

    $node = $this->search($data);

    if ($node) $node->delete();

 }

```

如代码所示，我们首先搜索数据。如果节点存在，我们将使用`delete`方法将其移除。现在，让我们运行我们之前的例子，使用`remove`调用，看看它是否有效：

```php
   $tree->remove(15);

   $tree->traverse($tree->root);

```

我们只是从我们的树中移除`15`，然后从根节点遍历树。我们现在将看到以下输出：

```php
3

6

8

10

12

13

36

```

我们可以看到 15 不再是我们 BST 的一部分了。这样，我们可以移除任何节点，如果我们使用相同的方法进行遍历，我们将会看到一个排序的列表。如果我们看我们之前的输出，我们可以看到输出是按升序显示的。这其中有一个原因，我们将在下一个主题-不同的树遍历方式中探讨。

您可以在[`btv.melezinek.cz/binary-search-tree.html`](http://btv.melezinek.cz/binary-search-tree.html)找到一个用于可视化二叉搜索树操作的好工具。这对于学习者来说是一个很好的开始，可以通过可视化的方式理解不同的操作。

# 树的遍历

树的遍历是指我们访问给定树中的每个节点的方式。根据我们进行遍历的方式，我们可以遵循三种不同的遍历方式。这些遍历在许多不同的方面都非常重要。表达式求值的波兰表示法转换就是使用树遍历的最流行的例子之一。

# 中序

中序树遍历首先访问左节点，然后是根节点，然后是右节点。对于每个节点，这将递归地继续进行。左节点存储的值比根节点值小，右节点存储的值比根节点大。因此，当我们应用中序遍历时，我们得到一个排序的列表。这就是为什么到目前为止，我们的二叉树遍历显示的是一个排序的数字列表。这种遍历部分实际上就是中序树遍历的例子。中序树遍历遵循以下原则：

1.  通过递归调用中序函数来遍历左子树。

1.  显示根（或当前节点）的数据部分。

1.  递归调用中序函数来遍历右子树。

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00053.jpg)

前面的树将显示 A、B、C、D、E、F、G、H 和 I 作为输出，因为它是按照中序遍历进行遍历的。

# 前序

在前序遍历中，首先访问根节点，然后是左节点，然后是右节点。前序遍历的原则如下：

1.  显示根（或当前节点）的数据部分。

1.  通过递归调用前序函数来遍历左子树。

1.  通过递归调用前序函数来遍历右子树。

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00054.jpg)

前面的树将以 F、B、A、D、C、E、G、I 和 H 作为输出，因为它是按照前序遍历进行遍历的。

# 后序

在后序遍历中，最后访问根节点。首先访问左节点，然后是右节点。后序遍历的原则如下：

1.  通过递归调用后序函数来遍历左子树。

1.  通过递归调用后序函数来遍历右子树。

1.  显示根（或当前节点）的数据部分。

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00055.jpg)

前序遍历将以 A、C、E、D、B、H、I、G 和 F 作为输出，因为它是按照后序遍历进行遍历的。

现在，让我们在我们的 BST 类中实现遍历逻辑：

```php
public function traverse(Node $node, string $type="in-order") { 

switch($type) {        

    case "in-order": 

      $this->inOrder($node); 

    break; 

    case "pre-order": 

      $this->preOrder($node); 

    break; 

    case "post-order": 

      $this->postOrder($node); 

    break;       

}      

} 

public function preOrder(Node $node) { 

  if ($node) { 

      echo $node->data . " "; 

      if ($node->left) $this->traverse($node->left); 

      if ($node->right) $this->traverse($node->right); 

  }      

} 

public function inOrder(Node $node) { 

  if ($node) {           

      if ($node->left) $this->traverse($node->left); 

      echo $node->data . " "; 

      if ($node->right) $this->traverse($node->right); 

  } 

} 

public function postOrder(Node $node) { 

  if ($node) {           

      if ($node->left) $this->traverse($node->left); 

      if ($node->right) $this->traverse($node->right); 

      echo $node->data . " "; 

  } 

} 

```

现在，如果我们对我们之前的二叉搜索树运行三种不同的遍历方法，这里是运行遍历部分的代码：

```php
   $tree->traverse($tree->root, 'pre-order');

   echo "\n";

   $tree->traverse($tree->root, 'in-order');

   echo "\n";

   $tree->traverse($tree->root, 'post-order');

```

这将在我们的命令行中产生以下输出：

```php
10 3 6 8 12 13 15 36

3 6 8 10 12 13 15 36

3 6 8 12 13 15 36 10

```

# 不同树数据结构的复杂性

到目前为止，我们已经看到了不同的树类型及其操作。不可能逐一介绍每种树类型及其不同的操作，因为这将超出本书的范围。我们希望对其他树结构及其操作复杂性有一个最基本的了解。下面是一个包含不同类型树的平均和最坏情况下操作复杂度以及空间的图表。根据我们的需求，我们可能需要选择不同的树结构：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00056.jpg)

# 总结

在本章中，我们详细讨论了非线性数据结构。您了解到树是分层数据结构，有不同的树类型、操作和复杂性。我们还看到了如何定义二叉搜索树。这对于实现不同的搜索技术和数据存储将非常有用。在下一章中，我们将把重点从数据结构转移到算法上。我们将专注于第一类算法--排序算法。
