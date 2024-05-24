# 精通 Python（三）

> 原文：[`zh.annas-archive.org/md5/37ba6447e713c9bd5373842650e2e5f3`](https://zh.annas-archive.org/md5/37ba6447e713c9bd5373842650e2e5f3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：生成器和协程-无限，一步一步

生成器是一种通过函数生成值的特定类型的迭代器。传统方法构建并返回项目的`list`，而生成器只会在调用者请求时单独`yield`每个值。这种方法有几个好处：

+   生成器完全暂停执行，直到下一个值被产生，这使得它们完全是惰性的。如果从生成器中获取五个项目，只会生成五个项目，因此不需要其他计算。

+   生成器不需要保存值。而传统函数需要创建一个`list`并存储所有结果，直到它们被返回，生成器只需要存储一个单一的值。

+   生成器可以具有无限的大小。没有必要在某一点停止。

然而，这些好处是有代价的。这些好处的直接结果是一些缺点：

+   在处理完成之前，您永远不知道还有多少值；甚至可能是无限的。这在某些情况下使用是危险的；执行`list(some_infinite_generator)`将耗尽内存。

+   您无法切片生成器。

+   您无法在产生指定的项目之前获取所有值。

+   您无法重新启动生成器。所有值只产生一次。

除了生成器之外，还有一种变体的生成器语法，可以创建协程。协程是允许进行多任务处理而不需要多个线程或进程的函数。生成器只能向调用者产生值，而协程实际上可以在运行时从调用者那里接收值。虽然这种技术有一些限制，但如果符合您的目的，它可以以非常低的成本实现出色的性能。

简而言之，本章涵盖的主题有：

+   生成器的特点和用途

+   生成器推导

+   生成器函数

+   生成器类

+   捆绑生成器

+   协程

# 生成器是什么？

生成器，最简单的形式是一个函数，它一次返回一个元素，而不是返回一组项目。这样做的最重要的优点是它需要非常少的内存，而且不需要预先定义的大小。创建一个无限的生成器（比如在第四章中讨论的`itertools.count`迭代器，*功能编程-可读性与简洁性*）实际上是相当容易的，但当然也是有代价的。没有对象的大小可用，使得某些模式难以实现。

编写生成器（作为函数）的基本技巧是使用`yield`语句。让我们以`itertools.count`生成器为例，并用一个`stop`变量扩展它：

```py
>>> def count(start=0, step=1, stop=10):
...     n = start
...     while n <= stop:
...         yield n
...         n += step

>>> for x in count(10, 2.5, 20):
...     print(x)
10
12.5
15.0
17.5
20.0

```

由于生成器可能是无限的，因此需要谨慎。如果没有`stop`变量，简单地执行`list(count())`将很快导致内存不足的情况。

那么这是如何工作的呢？这只是一个普通的`for`循环，但这与返回项目列表的常规方法之间的重要区别在于`yield`语句一次返回一个项目。这里需要注意的一点是，`return`语句会导致`StopIteration`，并且将某些东西传递给`return`将成为`StopIteration`的参数。应该注意的是，这种行为在 Python 3.3 中发生了变化；在 Python 3.2 和更早的版本中，除了`None`之外，根本不可能返回任何东西。这里有一个例子：

```py
>>> def generator():
...     yield 'this is a generator'
...     return 'returning from a generator'

>>> g = generator()
>>> next(g)
'this is a generator'
>>> next(g)
Traceback (most recent call last):
 **...
StopIteration: returning from a generator

```

当然，与以往一样，有多种使用 Python 创建生成器的方法。除了函数之外，还有生成器推导和类可以做同样的事情。生成器推导与列表推导几乎完全相同，但使用括号而不是方括号，例如：

```py
>>> generator = (x ** 2 for x in range(4))

>>> for x in generator:
...    print(x)
0
1
4
9

```

为了完整起见，`count`函数的类版本如下：

```py
>>> class Count(object):
...     def __init__(self, start=0, step=1, stop=10):
...         self.n = start
...         self.step = step
...         self.stop = stop
...
...     def __iter__(self):
...         return self
...
...     def __next__(self):
...         n = self.n
...         if n > self.stop:
...             raise StopIteration()
...
...         self.n += self.step
...         return n

>>> for x in Count(10, 2.5, 20):
...     print(x)
10
12.5
15.0
17.5
20.0

```

类和基于函数的方法之间最大的区别是你需要显式地引发`StopIteration`而不是简单地返回它。除此之外，它们非常相似，尽管基于类的版本显然增加了一些冗余。

## 生成器的优缺点

你已经看到了一些生成器的例子，并了解了你可以用它们做什么的基础知识。然而，重要的是要记住它们的优缺点。

以下是最重要的优点：

+   内存使用。项目可以一次处理一个，因此通常不需要将整个列表保存在内存中。

+   结果可能取决于外部因素，而不是具有静态列表。例如，考虑处理队列/堆栈。

+   生成器是懒惰的。这意味着如果你只使用生成器的前五个结果，剩下的甚至不会被计算。

+   一般来说，编写生成函数比编写列表生成函数更简单。

最重要的缺点：

+   结果只能使用一次。处理生成器的结果后，不能再次使用。

+   在处理完成之前，大小是未知的，这可能对某些算法有害。

+   生成器是不可索引的，这意味着`some_generator[5]`是行不通的。

考虑到所有的优缺点，我的一般建议是尽可能使用生成器，只有在实际需要时才返回`list`或`tuple`。将生成器转换为`list`就像`list(some_generator)`一样简单，所以这不应该阻止你，因为生成函数往往比生成`list`的等效函数更简单。

内存使用的优势是可以理解的；一个项目需要的内存比许多项目少。然而，懒惰部分需要一些额外的解释，因为它有一个小问题：

```py
>>> def generator():
...     print('Before 1')
...     yield 1
...     print('After 1')
...     print('Before 2')
...     yield 2
...     print('After 2')
...     print('Before 3')
...     yield 3
...     print('After 3')

>>> g = generator()
>>> print('Got %d' % next(g))
Before 1
Got 1

>>> print('Got %d' % next(g))
After 1
Before 2
Got 2

```

正如你所看到的，生成器在`yield`语句后有效地冻结，所以即使`After 2`在`3`被产生之前也不会打印。

这有重要的优势，但这绝对是你需要考虑的事情。你不能在`yield`后立即清理，因为它直到下一个`yield`才会执行。

## 管道-生成器的有效使用

生成器的理论可能性是无限的（无意冒犯），但它们的实际用途可能很难找到。如果你熟悉 Unix/Linux shell，你可能以前使用过管道，比如`ps aux | grep python'`，例如列出所有 Python 进程。当然，有很多方法可以做到这一点，但让我们在 Python 中模拟类似的东西，以便看到一个实际的例子。为了创建一个简单和一致的输出，我们将创建一个名为`lines.txt`的文件，其中包含以下行：

```py
spam
eggs
spam spam
eggs eggs
spam spam spam
eggs eggs eggs
```

现在，让我们来看下面的 Linux/Unix/Mac shell 命令，以读取带有一些修改的文件：

```py
# cat lines.txt | grep spam | sed 's/spam/bacon/g'
bacon
bacon bacon
bacon bacon bacon

```

这使用`cat`读取文件，使用`grep`输出包含`spam`的所有行，并使用`sed`命令将`spam`替换为`bacon`。现在让我们看看如何可以利用 Python 生成器来重新创建这个过程：

```py
>>> def cat(filename):
...     for line in open(filename):
...         yield line.rstrip()
...
>>> def grep(sequence, search):
...     for line in sequence:
...         if search in line:
...             yield line
...
>>> def replace(sequence, search, replace):
...     for line in sequence:
...         yield line.replace(search, replace)
...
>>> lines = cat('lines.txt')
>>> spam_lines = grep(lines, 'spam')
>>> bacon_lines = replace(spam_lines, 'spam', 'bacon')

>>> for line in bacon_lines:
...     print(line)
...
bacon
bacon bacon
bacon bacon bacon

# Or the one-line version, fits within 78 characters:
>>> for line in replace(grep(cat('lines.txt'), 'spam'),
...                     'spam', 'bacon'):
...     print(line)
...
bacon
bacon bacon
bacon bacon bacon

```

这就是生成器的最大优势。你可以用很少的性能影响多次包装一个列表或序列。在请求值之前，涉及的任何函数都不会执行任何操作。

## tee-多次使用输出

如前所述，生成器最大的缺点之一是结果只能使用一次。幸运的是，Python 有一个函数允许你将输出复制到多个生成器。如果你习惯在命令行 shell 中工作，`tee`这个名字可能对你来说很熟悉。`tee`程序允许你将输出同时写到屏幕和文件，这样你就可以在保持实时查看的同时存储输出。

Python 版本的`itertools.tee`也做了类似的事情，只是它返回了几个迭代器，允许你分别处理结果。

默认情况下，`tee`会将您的生成器分成一个包含两个不同生成器的元组，这就是为什么元组解包在这里能很好地工作。通过传递`n`参数，这可以很容易地改变以支持超过 2 个生成器。这是一个例子：

```py
>>> import itertools

>>> def spam_and_eggs():
...     yield 'spam'
...     yield 'eggs'

>>> a, b = itertools.tee(spam_and_eggs())
>>> next(a)
'spam'
>>> next(a)
'eggs'
>>> next(b)
'spam'
>>> next(b)
'eggs'
>>> next(b)
Traceback (most recent call last):
 **...
StopIteration

```

看到这段代码后，您可能会对`tee`的内存使用情况感到好奇。它是否需要为您存储整个列表？幸运的是，不需要。`tee`函数在处理这个问题时非常聪明。假设您有一个包含 1,000 个项的生成器，并且同时从`a`中读取前 100 个项和从`b`中读取前 75 个项。那么`tee`将只在内存中保留差异（`100-75=25`个项），并在您迭代结果时丢弃其余的部分。

当然，`tee`是否是您的最佳解决方案取决于情况。如果实例`a`在实例`b`之前从头到（几乎）末尾被读取，那么使用`tee`就不是一个好主意。将生成器简单地转换为`list`会更快，因为它涉及的操作要少得多。

## 从生成器生成

正如我们之前所看到的，我们可以使用生成器来过滤、修改、添加和删除项。然而，在许多情况下，您会注意到在编写生成器时，您将从子生成器和/或序列中返回。一个例子是使用`itertools`库创建`powerset`时：

```py
>>> import itertools

>>> def powerset(sequence):
...     for size in range(len(sequence) + 1):
...         for item in itertools.combinations(sequence, size):
...             yield item

>>> for result in powerset('abc'):
...     print(result)
()
('a',)
('b',)
('c',)
('a', 'b')
('a', 'c')
('b', 'c')
('a', 'b', 'c')

```

这种模式是如此常见，以至于`yield`语法实际上得到了增强，使得这更加容易。Python 3.3 引入了`yield from`语法，使这种常见模式变得更加简单：

```py
>>> import itertools

>>> def powerset(sequence):
...     for size in range(len(sequence) + 1):
...         yield from itertools.combinations(sequence, size)

>>> for result in powerset('abc'):
...     print(result)
()
('a',)
('b',)
('c',)
('a', 'b')
('a', 'c')
('b', 'c')
('a', 'b', 'c')

```

这就是你只用三行代码创建一个幂集的方法。

也许，这种情况下更有用的例子是递归地扁平化一个序列。

```py
>>> def flatten(sequence):
...     for item in sequence:
...         try:
...             yield from flatten(item)
...         except TypeError:
...             yield item
...
>>> list(flatten([1, [2, [3, [4, 5], 6], 7], 8]))
[1, 2, 3, 4, 5, 6, 7, 8]

```

请注意，此代码使用`TypeError`来检测非可迭代对象。结果是，如果序列（可能是一个生成器）返回`TypeError`，它将默默地隐藏它。

还要注意，这是一个非常基本的扁平化函数，没有任何类型检查。例如，包含`str`的可迭代对象将被递归地扁平化，直到达到最大递归深度，因为`str`中的每个项也会返回一个`str`。

## 上下文管理器

与本书中描述的大多数技术一样，Python 也捆绑了一些有用的生成器。其中一些（例如`itertools`和`contextlib.contextmanager`）已经在第四章和第五章中讨论过，但我们可以使用一些额外的例子来演示它们可以多么简单和强大。

Python 上下文管理器似乎与生成器没有直接关联，但这是它们内部使用的一个很大的部分：

```py
>>> import datetime
>>> import contextlib

# Context manager that shows how long a context was active
>>> @contextlib.contextmanager
... def timer(name):
...     start_time = datetime.datetime.now()
...     yield
...     stop_time = datetime.datetime.now()
...     print('%s took %s' % (name, stop_time - start_time))

# The write to log function writes all stdout (regular print data) to
# a file. The contextlib.redirect_stdout context wrapper
# temporarily redirects standard output to a given file handle, in
# this case the file we just opened for writing.
>>> @contextlib.contextmanager
... def write_to_log(name):
...     with open('%s.txt' % name, 'w') as fh:
...         with contextlib.redirect_stdout(fh):
...             with timer(name):
...                 yield

# Use the context manager as a decorator
>>> @write_to_log('some function')
... def some_function():
...     print('This function takes a bit of time to execute')
...     ...
...     print('Do more...')

>>> some_function()

```

虽然所有这些都可以正常工作，但是三层上下文管理器往往会变得有点难以阅读。通常，装饰器可以解决这个问题。然而，在这种情况下，我们需要一个上下文管理器的输出作为下一个上下文管理器的输入。

这就是`ExitStack`的用武之地。它允许轻松地组合多个上下文管理器：

```py
>>> import contextlib

>>> @contextlib.contextmanager
... def write_to_log(name):
...     with contextlib.ExitStack() as stack:
...         fh = stack.enter_context(open('stdout.txt', 'w'))
...         stack.enter_context(contextlib.redirect_stdout(fh))
...         stack.enter_context(timer(name))
...
...         yield

>>> @write_to_log('some function')
... def some_function():
...     print('This function takes a bit of time to execute')
...     ...
...     print('Do more...')

>>> some_function()

```

看起来至少简单了一点，不是吗？虽然在这种情况下必要性有限，但当您需要进行特定的拆卸时，`ExitStack`的便利性很快就会显现出来。除了之前看到的自动处理外，还可以将上下文传递给一个新的`ExitStack`并手动处理关闭：

```py
>>> import contextlib

>>> with contextlib.ExitStack() as stack:
...     spam_fh = stack.enter_context(open('spam.txt', 'w'))
...     eggs_fh = stack.enter_context(open('eggs.txt', 'w'))
...     spam_bytes_written = spam_fh.write('writing to spam')
...     eggs_bytes_written = eggs_fh.write('writing to eggs')
...     # Move the contexts to a new ExitStack and store the
...     # close method
...     close_handlers = stack.pop_all().close

>>> spam_bytes_written = spam_fh.write('still writing to spam')
>>> eggs_bytes_written = eggs_fh.write('still writing to eggs')

# After closing we can't write anymore
>>> close_handlers()
>>> spam_bytes_written = spam_fh.write('cant write anymore')
Traceback (most recent call last):
 **...
ValueError: I/O operation on closed file.

```

大多数`contextlib`函数在 Python 手册中都有详尽的文档。特别是`ExitStack`，可以在[`docs.python.org/3/library/contextlib.html#contextlib.ExitStack`](https://docs.python.org/3/library/contextlib.html#contextlib.ExitStack)上找到许多示例。我建议密切关注`contextlib`文档，因为它在每个 Python 版本中都有很大的改进。

# 协程

协程是通过多个入口点提供非抢占式多任务处理的子例程。基本前提是，协程允许两个函数在运行时相互通信。通常，这种类型的通信仅保留给多任务处理解决方案，但协程以几乎没有额外性能成本的相对简单方式提供了这种实现。

由于生成器默认是惰性的，协程的工作方式是非常明显的。直到结果被消耗，生成器都会休眠；但在消耗结果时，生成器会变得活跃。普通生成器和协程之间的区别在于，协程不仅仅将值返回给调用函数，还可以接收值。

## 一个基本的例子

在前面的段落中，我们看到了普通生成器如何产出值。但生成器能做的不仅仅是这些。它们也可以接收值。基本用法非常简单：

```py
>>> def generator():
...     value = yield 'spam'
...     print('Generator received: %s' % value)
...     yield 'Previous value: %r' % value

>>> g = generator()
>>> print('Result from generator: %s' % next(g))
Result from generator: spam
>>> print(g.send('eggs'))
Generator received: eggs
Previous value: 'eggs'

```

就是这样。在调用`send`方法之前，函数会被冻结，此时它将处理到下一个`yield`语句。

## 启动

由于生成器是惰性的，你不能直接向全新的生成器发送一个值。在值被发送到生成器之前，要么必须使用`next()`获取结果，要么必须发出`send(None)`，以便实际到达代码。这种需求是可以理解的，但有时有点乏味。让我们创建一个简单的装饰器来省略这个需求：

```py
>>> import functools

>>> def coroutine(function):
...     @functools.wraps(function)
...     def _coroutine(*args, **kwargs):
...         active_coroutine = function(*args, **kwargs)
...         next(active_coroutine)
...         return active_coroutine
...     return _coroutine

>>> @coroutine
... def spam():
...     while True:
...         print('Waiting for yield...')
...         value = yield
...         print('spam received: %s' % value)

>>> generator = spam()
Waiting for yield...

>>> generator.send('a')
spam received: a
Waiting for yield...

>>> generator.send('b')
spam received: b
Waiting for yield...

```

你可能已经注意到，即使生成器仍然是惰性的，它现在会自动执行所有代码，直到再次到达`yield`语句。在那时，它将保持休眠状态，直到发送新值。

### 注意

请注意，从现在开始，`coroutine`装饰器将在本章中使用。为简洁起见，我们将在以下示例中省略它。

## 关闭和抛出异常

与普通生成器不同，一旦输入序列耗尽，协程通常采用无限的`while`循环，这意味着它们不会以正常方式被关闭。这就是为什么协程也支持`close`和`throw`方法，它们将退出函数。这里重要的不是关闭，而是添加拆卸方法的可能性。从本质上讲，这与上下文包装器如何使用`__enter__`和`__exit__`方法的方式非常相似，但在这种情况下是协程：

```py
@coroutine
def simple_coroutine():
    print('Setting up the coroutine')
    try:
        while True:
            item = yield
            print('Got item: %r' % item)
    except GeneratorExit:
        print('Normal exit')
    except Exception as e:
        print('Exception exit: %r' % e)
        raise
    finally:
        print('Any exit')

print('Creating simple coroutine')
active_coroutine = simple_coroutine()
print()

print('Sending spam')
active_coroutine.send('spam')
print()

print('Close the coroutine')
active_coroutine.close()
print()

print('Creating simple coroutine')
active_coroutine = simple_coroutine()
print()

print('Sending eggs')
active_coroutine.send('eggs')
print()

print('Throwing runtime error')
active_coroutine.throw(RuntimeError, 'Oops...')
print()
```

这将生成以下输出，应该是预期的——没有奇怪的行为，只是退出协程的两种方法：

```py
# python3 H06.py
Creating simple coroutine
Setting up the coroutine

Sending spam
Got item: 'spam'

Close the coroutine
Normal exit
Any exit

Creating simple coroutine
Setting up the coroutine

Sending eggs
Got item: 'eggs'

Throwing runtime error
Exception exit: RuntimeError('Oops...',)
Any exit
Traceback (most recent call last):
...
 **File ... in <module>
 **active_coroutine.throw(RuntimeError, 'Oops...')
 **File ... in simple_coroutine
 **item = yield
RuntimeError: Oops...

```

## 双向管道

在前面的段落中，我们看到了管道；它们按顺序处理输出并且是单向的。然而，有些情况下这还不够——有时你需要一个不仅将值发送到下一个管道，而且还能从子管道接收信息的管道。我们可以通过这种方式在执行之间保持生成器的状态，而不是始终只有一个单一的列表被处理。因此，让我们首先将之前的管道转换为协程。首先，再次使用`lines.txt`文件：

```py
spam
eggs
spam spam
eggs eggs
spam spam spam
eggs eggs eggs
```

现在，协程管道。这些函数与以前的相同，但使用协程而不是生成器：

```py
>>> @coroutine
... def replace(search, replace):
...     while True:
...         item = yield
...         print(item.replace(search, replace))

>>> spam_replace = replace('spam', 'bacon')
>>> for line in open('lines.txt'):
...     spam_replace.send(line.rstrip())
bacon
eggs
bacon bacon
eggs eggs
bacon bacon bacon
eggs eggs eggs

```

鉴于这个例子，你可能会想知道为什么我们现在打印值而不是产出它。嗯！我们可以，但要记住生成器会冻结，直到产出一个值。让我们看看如果我们只是`yield`值而不是调用`print`会发生什么。默认情况下，你可能会想这样做：

```py
>>> @coroutine
... def replace(search, replace):
...     while True:
...         item = yield
...         yield item.replace(search, replace)

>>> spam_replace = replace('spam', 'bacon')
>>> spam_replace.send('spam')
'bacon'
>>> spam_replace.send('spam spam')
>>> spam_replace.send('spam spam spam')
'bacon bacon bacon'

```

现在一半的值已经消失了，所以问题是，“它们去哪了？”注意第二个`yield`没有存储结果。这就是值消失的地方。我们需要将它们也存储起来：

```py
>>> @coroutine
... def replace(search, replace):
...     item = yield
...     while True:
...         item = yield item.replace(search, replace)

>>> spam_replace = replace('spam', 'bacon')
>>> spam_replace.send('spam')
'bacon'
>>> spam_replace.send('spam spam')
'bacon bacon'
>>> spam_replace.send('spam spam spam')
'bacon bacon bacon'

```

但即使这样还远非最佳。我们现在基本上是在使用协程来模仿生成器的行为。虽然它能工作，但有点傻而且不是很清晰。这次让我们真正建立一个管道，让协程将数据发送到下一个协程（或多个协程），并通过将结果发送到多个协程来展示协程的力量：

```py
# Grep sends all matching items to the target
>>> @coroutine
... def grep(target, pattern):
...     while True:
...         item = yield
...         if pattern in item:
...             target.send(item)

# Replace does a search and replace on the items and sends it to
# the target once it's done
>>> @coroutine
... def replace(target, search, replace):
...     while True:
...         target.send((yield).replace(search, replace))

# Print will print the items using the provided formatstring
>>> @coroutine
... def print_(formatstring):
...     while True:
...         print(formatstring % (yield))

# Tee multiplexes the items to multiple targets
>>> @coroutine
... def tee(*targets):
...     while True:
...         item = yield
...         for target in targets:
...             target.send(item)

# Because we wrap the results we need to work backwards from the
# inner layer to the outer layer.

# First, create a printer for the items:
>>> printer = print_('%s')

# Create replacers that send the output to the printer
>>> replacer_spam = replace(printer, 'spam', 'bacon')
>>> replacer_eggs = replace(printer, 'spam spam', 'sausage')

# Create a tee to send the input to both the spam and the eggs
# replacers
>>> branch = tee(replacer_spam, replacer_eggs)

# Send all items containing spam to the tee command
>>> grepper = grep(branch, 'spam')

# Send the data to the grepper for all the processing
>>> for line in open('lines.txt'):
...     grepper.send(line.rstrip())
bacon
spam
bacon bacon
sausage
bacon bacon bacon
sausage spam

```

这使得代码更简单、更易读，但更重要的是，它展示了如何将单一源拆分为多个目的地。虽然这看起来可能不那么令人兴奋，但它肯定是。如果你仔细观察，你会发现`tee`方法将输入分成两个不同的输出，但这两个输出都写回到同一个`print_`实例。这意味着你可以将数据沿着任何方便的方式路由，而无需任何努力就可以将其最终发送到同一个终点。

尽管如此，这个例子仍然不是那么有用，因为这些函数仍然没有充分利用协程的全部功能。最重要的特性，即一致的状态，在这种情况下并没有真正被使用。

从这些行中学到的最重要的一课是，在大多数情况下混合使用生成器和协程并不是一个好主意，因为如果使用不正确，它可能会产生非常奇怪的副作用。尽管两者都使用`yield`语句，但它们是具有不同行为的显著不同的实体。下一段将展示混合协程和生成器可以有用的为数不多的情况之一。

## 使用状态

既然我们知道如何编写基本的协程以及需要注意的陷阱，那么如何编写一个需要记住状态的函数呢？也就是说，一个始终给出所有发送值的平均值的函数。这是为数不多的情况之一，仍然相对安全和有用地结合协程和生成器语法：

```py
>>> @coroutine
... def average():
...     count = 1
...     total = yield
...     while True:
...         total += yield total / count
...         count += 1

>>> averager = average()
>>> averager.send(20)
20.0
>>> averager.send(10)
15.0
>>> averager.send(15)
15.0
>>> averager.send(-25)
5.0

```

尽管这仍然需要一些额外的逻辑才能正常工作。为了确保我们不会除以零，我们将`count`初始化为`1`。之后，我们使用`yield`获取我们的第一个项目，但在那时我们不发送任何数据，因为第一个`yield`是启动器，并且在我们获得值之前执行。一旦设置好了，我们就可以轻松地在求和的同时产生平均值。并不是太糟糕，但纯协程版本稍微更容易理解，因为我们不必担心启动：

```py
>>> @coroutine
... def print_(formatstring):
...     while True:
...         print(formatstring % (yield))

>>> @coroutine
... def average(target):
...     count = 0
...     total = 0
...     while True:
...         count += 1
...         total += yield
...         target.send(total / count)

>>> printer = print_('%.1f')
>>> averager = average(printer)
>>> averager.send(20)
20.0
>>> averager.send(10)
15.0
>>> averager.send(15)
15.0
>>> averager.send(-25)
5.0

```

就像应该的那样，只需保持计数和总值，然后简单地为每个新值发送新的平均值。

另一个很好的例子是`itertools.groupby`，也很容易用协程实现。为了比较，我们将再次展示生成器协程和纯协程版本：

```py
>>> @coroutine
... def groupby():
...     # Fetch the first key and value and initialize the state
...     # variables
...     key, value = yield
...     old_key, values = key, []
...     while True:
...         # Store the previous value so we can store it in the
...         # list
...         old_value = value
...         if key == old_key:
...             key, value = yield
...         else:
...             key, value = yield old_key, values
...             old_key, values = key, []
...         values.append(old_value)

>>> grouper = groupby()
>>> grouper.send(('a', 1))
>>> grouper.send(('a', 2))
>>> grouper.send(('a', 3))
>>> grouper.send(('b', 1))
('a', [1, 2, 3])
>>> grouper.send(('b', 2))
>>> grouper.send(('a', 1))
('b', [1, 2])
>>> grouper.send(('a', 2))
>>> grouper.send((None, None))
('a', [1, 2])

```

正如你所看到的，这个函数使用了一些技巧。我们存储了前一个`key`和`value`，以便我们可以检测到组（`key`）何时发生变化。这就是第二个问题；显然我们只有在组发生变化后才能识别出一个组，因此只有在组发生变化后才会返回结果。这意味着最后一组只有在它之后发送了不同的组之后才会发送，因此是`(None, None)`。现在，这是纯协程版本：

```py
>>> @coroutine
... def print_(formatstring):
...     while True:
...         print(formatstring % (yield))

>>> @coroutine
... def groupby(target):
...     old_key = None
...     while True:
...         key, value = yield
...         if old_key != key:
...             # A different key means a new group so send the
...             # previous group and restart the cycle.
...             if old_key and values:
...                 target.send((old_key, values))
...             values = []
...             old_key = key
...         values.append(value)

>>> grouper = groupby(print_('group: %s, values: %s'))
>>> grouper.send(('a', 1))
>>> grouper.send(('a', 2))
>>> grouper.send(('a', 3))
>>> grouper.send(('b', 1))
group: a, values: [1, 2, 3]
>>> grouper.send(('b', 2))
>>> grouper.send(('a', 1))
group: b, values: [1, 2]
>>> grouper.send(('a', 2))
>>> grouper.send((None, None))
group: a, values: [1, 2]

```

虽然这些函数非常相似，但纯协程版本再次要简单得多。这是因为我们不必考虑启动和可能丢失的值。

# 总结

本章向我们展示了如何创建生成器以及它们的优势和劣势。此外，现在应该清楚如何解决它们的限制以及这样做的影响。

虽然关于协程的段落应该已经提供了一些关于它们是什么以及如何使用它们的见解，但并非一切都已经展示出来。我们看到了纯协程和同时是生成器的协程的构造，但它们仍然是同步的。协程允许将结果发送给许多其他协程，因此可以有效地同时执行许多函数，但如果某个操作被阻塞，它们仍然可以完全冻结 Python。这就是我们下一章将会帮助解决的问题。

Python 3.5 引入了一些有用的功能，比如`async`和`await`语句。这使得协程可以完全异步和非阻塞，而本章节使用的是自 Python 2.5 以来可用的基本协程功能。

下一章将扩展新功能，包括`asyncio`模块。这个模块使得使用协程进行异步 I/O 到诸如 TCP、UDP、文件和进程等端点变得几乎简单。


# 第七章：异步 IO - 无需线程的多线程

上一章向我们展示了同步协程的基本实现。然而，当涉及到外部资源时，同步协程是一个坏主意。只要一个远程连接停顿，整个进程就会挂起，除非你使用了多进程（在第十三章中有解释，*多进程 - 当单个 CPU 核心不够用*）或异步函数。

异步 IO 使得可以访问外部资源而无需担心减慢或阻塞应用程序。Python 解释器不需要主动等待结果，而是可以简单地继续执行其他任务，直到再次需要。这与 Node.js 和 JavaScript 中的 AJAX 调用的功能非常相似。在 Python 中，我们已经看到诸如`asyncore`、`gevent`和`eventlet`等库多年来已经实现了这一点。然而，随着`asyncio`模块的引入，使用起来变得更加容易。

本章将解释如何在 Python（特别是 3.5 及以上版本）中使用异步函数，以及如何重构代码，使其仍然能够正常运行，即使它不遵循标准的过程式编码模式来返回值。

本章将涵盖以下主题：

+   使用以下函数：

+   `async def`

+   `async for`

+   `async with`

+   `await`

+   并行执行

+   服务器

+   客户端

+   使用`Future`来获取最终结果

# 介绍 asyncio 库

`asyncio`库的创建是为了使异步处理更加容易，并且结果更加可预测。它的目的是取代`asyncore`模块，后者已经可用了很长时间（事实上自 Python 1.5 以来）。`asyncore`模块从来没有很好地可用，这促使了`gevent`和`eventlet`第三方库的创建。`gevent`和`eventlet`都比`asyncore`更容易实现异步编程，但我觉得随着`asyncio`的引入，它们已经基本过时了。尽管我不得不承认`asyncio`仍然有一些问题，但它正在积极开发中，这让我认为所有问题很快就会被核心 Python 库或第三方包解决。

`asyncio`库是在 Python 3.4 中正式引入的，但是可以通过 Python 包索引为 Python 3.3 提供后向端口。考虑到这一点，虽然本章的一些部分可以在 Python 3.3 上运行，但大部分是以 Python 3.5 和新引入的`async`和`await`关键字为基础编写的。

## 异步和等待语句

在继续任何示例之前，重要的是要了解 Python 3.4 和 Python 3.5 代码语法之间的关系。尽管`asyncio`库仅在 Python 3.4 中引入，但 Python 3.5 中已经替换了大部分通用语法。虽然不是强制性的，但更简单，因此推荐使用`async`和`await`的语法已经被引入。

### Python 3.4

对于传统的 Python 3.4 用法，需要考虑一些事项：

+   函数应使用`asyncio.coroutine`装饰器声明

+   应使用`yield from coroutine()`来获取异步结果

+   不直接支持异步循环，但可以使用`while True: yield from coroutine()`来模拟

以下是一个例子：

```py
import asyncio

@asyncio.coroutine
def sleeper():
    yield from asyncio.sleep(1)
```

### Python 3.5

在 Python 3.5 中，引入了一种新的语法来标记函数为异步的。可以使用`async`关键字来代替`asyncio.coroutine`装饰器。此外，Python 现在支持`await`语句，而不是令人困惑的`yield from`语法。`yield from`语句稍微令人困惑，因为它可能让人觉得正在交换值，而这并不总是情况。

以下是`async`语句：

```py
async def some_coroutine():
    pass
```

它可以代替装饰器：

```py
import asyncio

@asyncio.coroutine
def some_coroutine():
    pass
```

在 Python 3.5 中，以及很可能在未来的版本中，`coroutine`装饰器仍然受到支持，但如果不需要向后兼容性，我强烈推荐使用新的语法。

此外，我们可以使用更合乎逻辑的`await`语句，而不是`yield from`语句。因此，前面段落中的示例变得和以下示例一样简单：

```py
import asyncio

async def sleeper():
    await asyncio.sleep(1)
```

`yield from`语句源自 Python 中原始协程实现，并且是在同步协程中使用的`yield`语句的一个逻辑扩展。实际上，`yield from`语句仍然有效，而`await`语句只是它的一个包装器，增加了一些检查。在使用`await`时，解释器会检查对象是否是可等待对象，这意味着它需要是以下对象之一：

+   使用`async def`语句创建的本地协程

+   使用`asyncio.coroutine`装饰器创建的协程

+   实现`__await__`方法的对象

这个检查本身就使得`await`语句比`yield from`语句更可取，但我个人认为`await`更好地传达了语句的含义。

总之，要转换为新的语法，进行以下更改：

+   函数应该使用`async def`声明，而不是`def`

+   应该使用`await coroutine()`来获取异步结果

+   可以使用`async for ... in ...`创建异步循环

+   可以使用`async with ...`创建异步`with`语句

### 在 3.4 和 3.5 语法之间进行选择

除非你真的需要 Python 3.3 或 3.4 支持，我强烈推荐使用 Python 3.5 语法。新的语法更清晰，支持更多功能，比如异步`for`循环和`with`语句。不幸的是，它们并不完全兼容，所以你需要做出选择。在`async def`（3.5）中，我们不能使用`yield from`，但我们只需要用`await`替换`yield from`就可以解决这个问题。

## 单线程并行处理的简单示例

并行处理有很多用途：服务器同时处理多个请求，加快繁重任务的速度，等待外部资源等等。通用协程在某些情况下可以帮助处理多个请求和外部资源，但它们仍然是同步的，因此受到限制。使用`asyncio`，我们可以超越通用协程的限制，轻松处理阻塞资源，而不必担心阻塞主线程。让我们快速看一下代码如何在多个并行函数中不会阻塞：

```py
>>> import asyncio

>>> async def sleeper(delay):
...     await asyncio.sleep(delay)
...     print('Finished sleeper with delay: %d' % delay)

>>> loop = asyncio.get_event_loop()
>>> results = loop.run_until_complete(asyncio.wait((
...     sleeper(1),
...     sleeper(3),
...     sleeper(2),
... )))
Finished sleeper with delay: 1
Finished sleeper with delay: 2
Finished sleeper with delay: 3

```

即使我们按顺序开始了睡眠器，1、3、2，它们会按照相应的时间睡眠，`asyncio.sleep`结合`await`语句实际上告诉 Python，它应该继续处理需要实际处理的任务。普通的`time.sleep`实际上会阻塞 Python 任务，这意味着它们会按顺序执行。这使得它更加透明，可以处理任何类型的等待，我们可以将其交给`asyncio`，而不是让整个 Python 线程忙碌。因此，我们可以用`while True: fh.read()`来代替，只要有新数据就可以立即响应。

让我们分析一下这个例子中使用的组件：

+   `asyncio.coroutine`：这个装饰器使得可以从`async def`协程中进行 yield。除非你使用这种语法，否则没有真正需要这个装饰器，但如果只用作文档，这是一个很好的默认值。

+   `asyncio.sleep`：这是`time.sleep`的异步版本。这两者之间的主要区别是，`time.sleep`在睡眠时会让 Python 进程保持忙碌，而`asyncio.sleep`允许在事件循环中切换到不同的任务。这个过程与大多数操作系统中的任务切换的工作方式非常相似。

+   `asyncio.get_event_loop`：默认事件循环实际上是`asyncio`任务切换器；我们将在下一段解释更多关于这些的内容。

+   `asyncio.wait`：这是用于包装一系列协程或未来并等待结果的协程。等待时间是可配置的，等待方式也是可配置的（首先完成，全部完成，或者第一个异常）。

这应该解释了示例的基本工作原理：`sleeper`函数是异步协程，经过给定的延迟后退出。`wait`函数在退出之前等待所有协程完成，`event`循环用于在三个协程之间切换。

## `asyncio`的概念

`asyncio`库有几个基本概念，必须在我们进一步探讨示例和用法之前加以解释。前一段中显示的示例实际上使用了大部分这些概念，但对于如何以及为什么可能仍然有一些解释是有用的。

`asyncio`的主要概念是*协程*和*事件循环*。在其中，还有几个可用的辅助类，如`Streams`、`Futures`和`Processes`。接下来的几段将解释基础知识，以便你能够理解后面段落中的示例中的实现。

### 未来和任务

`asyncio.Future`类本质上是一个结果的承诺；如果结果可用，它会返回结果，并且一旦接收到结果，它将把结果传递给所有注册的回调函数。它在内部维护一个状态变量，允许外部方将未来标记为已取消。API 与`concurrent.futures.Future`类非常相似，但由于它们并不完全兼容，所以请确保不要混淆两者。

`Future`类本身并不那么方便使用，这就是`asyncio.Task`发挥作用的地方。`Task`类包装了一个协程，并自动处理执行、结果和状态。协程将通过给定的事件循环执行，或者如果没有给定，则通过默认事件循环执行。

这些类的创建并不是你需要直接担心的事情。这是因为推荐的方式是通过`asyncio.ensure_future`或`loop.create_task`来创建类。前者实际上在内部执行了`loop.create_task`，但如果你只想在主/默认事件循环上执行它而不必事先指定，那么这种方式更方便。使用起来非常简单。要手动创建自己的未来，只需告诉事件循环为你执行`create_task`。下面的示例由于所有的设置代码而有点复杂，但 C 的使用应该是清楚的。最重要的一点是事件循环应该被链接，以便任务知道如何/在哪里运行：

```py
>>> import asyncio

>>> async def sleeper(delay):
...     await asyncio.sleep(delay)
...     print('Finished sleeper with delay: %d' % delay)

# Create an event loop
>>> loop = asyncio.get_event_loop()

# Create the task
>>> result = loop.call_soon(loop.create_task, sleeper(1))

# Make sure the loop stops after 2 seconds
>>> result = loop.call_later(2, loop.stop)

# Start the loop and make it run forever. Or at least until the loop.stop gets
# called in 2 seconds.
>>> loop.run_forever()
Finished sleeper with delay: 1

```

现在，稍微了解一下调试异步函数。调试异步函数曾经非常困难，甚至是不可能的，因为没有好的方法来查看函数在哪里以及如何停滞。幸运的是，情况已经改变。在`Task`类的情况下，只需调用`task.get_stack`或`task.print_stack`就可以看到它当前所在的位置。使用方法可以简单到如下：

```py
>>> import asyncio

>>> async def stack_printer():
...     for task in asyncio.Task.all_tasks():
...         task.print_stack()

# Create an event loop
>>> loop = asyncio.get_event_loop()

# Create the task
>>> result = loop.run_until_complete(stack_printer())

```

### 事件循环

事件循环的概念实际上是`asyncio`中最重要的一个。你可能已经怀疑协程本身就是一切的关键，但没有事件循环，它们就毫无用处。事件循环就像任务切换器一样工作，就像操作系统在 CPU 上切换活动任务的方式一样。即使有多核处理器，仍然需要一个主进程告诉 CPU 哪些任务需要运行，哪些需要等待/休眠一段时间。这正是事件循环所做的：它决定要运行哪个任务。

#### 事件循环实现

到目前为止，我们只看到了`asyncio.get_event_loop`，它返回默认的事件循环和默认的事件循环策略。目前，有两种捆绑的事件循环实现：`async.SelectorEventLoop`和`async.ProactorEventLoop`实现。哪一种可用取决于您的操作系统。后一种事件循环仅在 Windows 机器上可用，并使用 I/O 完成端口，这是一个据说比`asyncio.SelectorEventLoop`的`Select`实现更快更高效的系统。如果性能是一个问题，这是需要考虑的事情。幸运的是，使用起来相当简单：

```py
import asyncio

loop = asyncio.ProActorEventLoop()
asyncio.set_event_loop(loop)
```

备用事件循环基于选择器，自 Python 3.4 以来，可以通过核心 Python 安装中的`selectors`模块获得。`selectors`模块是在 Python 3.4 中引入的，以便轻松访问低级异步 I/O 操作。基本上，它允许您通过使用 I/O 多路复用来打开和读取许多文件。由于`asyncio`为您处理了所有复杂性，通常不需要直接使用该模块，但如果需要，使用起来相当简单。以下是将函数绑定到标准输入的读事件（`EVENT_READ`）的示例。代码将简单地等待，直到其中一个注册的文件提供新数据：

```py
import sys
import selectors

def read(fh):
    print('Got input from stdin: %r' % fh.readline())

if __name__ == '__main__':
    # Create the default selector
    selector = selectors.DefaultSelector()

    # Register the read function for the READ event on stdin
    selector.register(sys.stdin, selectors.EVENT_READ, read)

    while True:
        for key, mask in selector.select():
            # The data attribute contains the read function here
            callback = key.data
            # Call it with the fileobj (stdin here)
            callback(key.fileobj)
```

有几种选择器可用，例如传统的`selectors.SelectSelector`（内部使用`select.select`），但也有更现代的解决方案，如`selectors.KqueueSelector`、`selectors.EpollSelector`和`selectors.DevpollSelector`。尽管默认情况下应该选择最有效的选择器，但在某些情况下，最有效的选择器可能不适合。在这些情况下，选择器事件循环允许您指定不同的选择器：

```py
import asyncio
import selectors

selector = selectors.SelectSelector()
loop = asyncio.SelectorEventLoop(selector)
asyncio.set_event_loop(loop)
```

应该注意的是，这些选择器之间的差异在大多数实际应用程序中通常太小而难以注意到。我遇到的唯一一种情况是在构建一个必须处理大量同时连接的服务器时，这种优化才会有所不同。当我说“大量”时，我指的是在单个服务器上有超过 100,000 个并发连接的问题，这只有少数人在这个星球上需要处理。

#### 事件循环策略

事件循环策略是创建和存储实际事件循环的对象。它们被设计为最大灵活性，但通常不需要修改。我能想到的唯一原因修改事件循环策略是如果您想要使特定事件循环在特定处理器和/或系统上运行，或者如果您希望更改默认事件循环类型。除此之外，它提供的灵活性超出了大多数人所需的范围。通过以下代码，使自己的事件循环（在这种情况下是`ProActorEventLoop`）成为默认事件循环是完全可能的：

```py
import asyncio

class ProActorEventLoopPolicy(
        asyncio.events.BaseDefaultEventLoopPolicy):
    _loop_factory = asyncio.SelectorEventLoop

policy = ProActorEventLoopPolicy()
asyncio.set_event_loop_policy(policy)
```

#### 事件循环使用

到目前为止，我们只看到了`loop.run_until_complete`方法。当然，还有其他一些方法。你最有可能经常使用的是`loop.run_forever`。这个方法，正如你所期望的那样，会一直运行下去，或者至少直到`loop.stop`被运行。

所以，假设我们现在有一个永远运行的事件循环，我们需要向其中添加任务。这就是事情变得有趣的地方。在默认事件循环中有很多选择：

+   `call_soon`：将项目添加到（FIFO）队列的末尾，以便按照插入的顺序执行函数。

+   `call_soon_threadsafe`：这与`call_soon`相同，只是它是线程安全的。`call_soon`方法不是线程安全的，因为线程安全需要使用全局解释器锁（GIL），这在线程安全时会使您的程序变成单线程。性能章节将更彻底地解释这一点。

+   `call_later`：在给定的秒数后调用函数。如果两个任务将同时运行，它们将以未定义的顺序运行。请注意，延迟是最小值。如果事件循环被锁定/忙碌，它可能会稍后运行。

+   `call_at`：在与`loop.time`的输出相关的特定时间调用函数。`loop.time`之后的每个整数都会增加一秒。

所有这些函数都返回`asyncio.Handle`对象。只要任务尚未执行，这些对象就允许通过`handle.cancel`函数取消任务。但是要小心取消来自其他线程，因为取消也不是线程安全的。要以线程安全的方式执行它，我们还必须将取消函数作为任务执行：`loop.call_soon_threadsafe(handle.cancel)`。以下是一个示例用法：

```py
>>> import time
>>> import asyncio

>>> t = time.time()

>>> def printer(name):
...     print('Started %s at %.1f' % (name, time.time() - t))
...     time.sleep(0.2)
...     print('Finished %s at %.1f' % (name, time.time() - t))

>>> loop = asyncio.get_event_loop()
>>> result = loop.call_at(loop.time() + .2, printer, 'call_at')
>>> result = loop.call_later(.1, printer, 'call_later')
>>> result = loop.call_soon(printer, 'call_soon')
>>> result = loop.call_soon_threadsafe(printer, 'call_soon_threadsafe')

>>> # Make sure we stop after a second
>>> result = loop.call_later(1, loop.stop)

>>> loop.run_forever()
Started call_soon at 0.0
Finished call_soon at 0.2
Started call_soon_threadsafe at 0.2
Finished call_soon_threadsafe at 0.4
Started call_later at 0.4
Finished call_later at 0.6
Started call_at at 0.6
Finished call_at at 0.8

```

你可能会想知道为什么我们在这里没有使用协程装饰器。原因是循环不允许直接运行协程。要通过这些调用函数运行协程，我们需要确保它被包装在`asyncio.Task`中。正如我们在前一段中看到的那样，这很容易——幸运的是：

```py
>>> import time
>>> import asyncio

>>> t = time.time()

>>> async def printer(name):
...     print('Started %s at %.1f' % (name, time.time() - t))
...     await asyncio.sleep(0.2)
...     print('Finished %s at %.1f' % (name, time.time() - t))

>>> loop = asyncio.get_event_loop()

>>> result = loop.call_at(
...     loop.time() + .2, loop.create_task, printer('call_at'))
>>> result = loop.call_later(.1, loop.create_task,
...     printer('call_later'))
>>> result = loop.call_soon(loop.create_task,
...     printer('call_soon'))

>>> result = loop.call_soon_threadsafe(
...     loop.create_task, printer('call_soon_threadsafe'))

>>> # Make sure we stop after a second
>>> result = loop.call_later(1, loop.stop)

>>> loop.run_forever()
Started call_soon at 0.0
Started call_soon_threadsafe at 0.0
Started call_later at 0.1
Started call_at at 0.2
Finished call_soon at 0.2
Finished call_soon_threadsafe at 0.2
Finished call_later at 0.3
Finished call_at at 0.4

```

这些调用方法可能看起来略有不同，但内部实际上都归结为通过`heapq`实现的两个队列。`loop._scheduled`用于计划操作，`loop._ready`用于立即执行。当调用`_run_once`方法（`run_forever`方法在`while True`循环中包装了这个方法）时，循环将首先尝试使用特定的循环实现（例如`SelectorEventLoop`）处理`loop._ready`堆中的所有项目。一旦`loop._ready`中的所有项目都被处理，循环将继续将`loop._scheduled`堆中的项目移动到`loop._ready`堆中，如果它们已经到期。

`call_soon`和`call_soon_threadsafe`都写入`loop._ready`堆。而`call_later`方法只是`call_at`的一个包装，其计划时间是当前值加上`asyncio.time`，它写入`loop._scheduled`堆。

这种处理方法的结果是，通过`call_soon*`方法添加的所有内容都将始终在通过`call_at`/`call_later`方法添加的所有内容之后执行。

至于`ensure_futures`函数，它将在内部调用`loop.create_task`来将协程包装在`Task`对象中，当然，这是`Future`对象的子类。如果出于某种原因需要扩展`Task`类，可以通过`loop.set_task_factory`方法轻松实现。

根据事件循环的类型，实际上有许多其他方法可以创建连接、文件处理程序等。这些将在后面的段落中通过示例进行解释，因为它们与事件循环的关系较小，更多地涉及使用协程进行编程。

### 进程

到目前为止，我们只是执行了特定的异步 Python 函数，但有些事情在 Python 中异步运行起来会更困难。例如，假设我们有一个长时间运行的外部应用程序需要运行。`subprocess`模块将是运行外部应用程序的标准方法，并且它运行得相当好。通过一些小心，甚至可以确保它们不会通过轮询输出来阻塞主线程。然而，这仍然需要轮询。然而，事件会更好，这样我们在等待结果时可以做其他事情。幸运的是，这很容易通过`asyncio.Process`安排。与`Future`和`Task`类似，这个类是通过事件循环创建的。在使用方面，这个类与`subprocess.Popen`类非常相似，只是函数已经变成了异步的。当然，这会导致轮询函数的消失。

首先，让我们看传统的顺序版本：

```py
>>> import time
>>> import subprocess
>>>
>>>
>>> t = time.time()
>>>
>>>
>>> def process_sleeper():
...     print('Started sleep at %.1f' % (time.time() - t))
...     process = subprocess.Popen(['sleep', '0.1'])
...     process.wait()
...     print('Finished sleep at %.1f' % (time.time() - t))
...
>>>
>>> for i in range(3):
...     process_sleeper()
Started sleep at 0.0
Finished sleep at 0.1
Started sleep at 0.1
Finished sleep at 0.2
Started sleep at 0.2
Finished sleep at 0.3

```

由于一切都是按顺序执行的，所以等待的时间是休眠命令休眠的 0.1 秒的三倍。因此，与其同时等待所有这些，这次让我们并行运行它们：

```py
>>> import time
>>> import subprocess 

>>> t = time.time()

>>> def process_sleeper():
...     print('Started sleep at %.1f' % (time.time() - t))
...     return subprocess.Popen(['sleep', '0.1'])
...
>>>
>>> processes = []
>>> for i in range(5):
...     processes.append(process_sleeper())
Started sleep at 0.0
Started sleep at 0.0
Started sleep at 0.0
Started sleep at 0.0
Started sleep at 0.0

>>> for process in processes:
...     returncode = process.wait()
...     print('Finished sleep at %.1f' % (time.time() - t))
Finished sleep at 0.1
Finished sleep at 0.1
Finished sleep at 0.1
Finished sleep at 0.1
Finished sleep at 0.1

```

虽然从运行时间上看这样做要好得多，但我们的程序结构现在有点混乱。我们需要两个循环，一个用于启动进程，另一个用于测量完成时间。此外，我们还必须将打印语句移到函数外部，这通常也是不可取的。这次，我们将尝试`asyncio`版本：

```py
>>> import time
>>> import asyncio

>>> t = time.time()

>>> async def async_process_sleeper():
...     print('Started sleep at %.1f' % (time.time() - t))
...     process = await asyncio.create_subprocess_exec('sleep', '0.1')
...     await process.wait()
...     print('Finished sleep at %.1f' % (time.time() - t))

>>> loop = asyncio.get_event_loop()
>>> for i in range(5):
...     task = loop.create_task(async_process_sleeper())

>>> future = loop.call_later(.5, loop.stop)

>>> loop.run_forever()
Started sleep at 0.0
Started sleep at 0.0
Started sleep at 0.0
Started sleep at 0.0
Started sleep at 0.0
Finished sleep at 0.1
Finished sleep at 0.1
Finished sleep at 0.1
Finished sleep at 0.1
Finished sleep at 0.1

```

如您所见，这种方式很容易同时运行多个应用程序。但这只是简单的部分；处理进程的难点在于交互式输入和输出。`asyncio`模块有几种措施可以使其更容易，但在实际处理结果时仍然可能会有困难。以下是调用 Python 解释器、执行一些代码并再次退出的示例：

```py
import asyncio

async def run_script():
    process = await asyncio.create_subprocess_shell(
        'python3',
        stdout=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE,
    )

    # Write a simple Python script to the interpreter
    process.stdin.write(b'\n'.join((
        b'import math',
        b'x = 2 ** 8',
        b'y = math.sqrt(x)',
        b'z = math.sqrt(y)',
        b'print("x: %d" % x)',
        b'print("y: %d" % y)',
        b'print("z: %d" % z)',
        b'for i in range(int(z)):',
        b'    print("i: %d" % i)',
    )))
    # Make sure the stdin is flushed asynchronously
    await process.stdin.drain()
    # And send the end of file so the Python interpreter will
    # start processing the input. Without this the process will
    # stall forever.
    process.stdin.write_eof()

    # Fetch the lines from the stdout asynchronously
    async for out in process.stdout:
        # Decode the output from bytes and strip the whitespace
        # (newline) at the right
        print(out.decode('utf-8').rstrip())

    # Wait for the process to exit
    await process.wait()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_script())
    loop.close()
```

代码足够简单，但这段代码中有一些对我们来说不明显但却需要的部分。虽然创建子进程和编写代码是相当明显的，但您可能会对`process.stdin.write_eof()`这一行感到疑惑。问题在于缓冲。为了提高性能，大多数程序默认会对输入和输出进行缓冲。在 Python 程序的情况下，结果是除非我们发送**文件结束**（**eof**），否则程序将继续等待更多的输入。另一种选择是关闭`stdin`流或以某种方式与 Python 程序通信，告诉它我们不会再发送任何输入。然而，这当然是需要考虑的事情。另一个选择是使用`yield` from `process.stdin.drain()`，但那只处理了代码的发送方；接收方可能仍在等待更多的输入。不过，让我们看一下输出：

```py
# python3 processes.py
x: 256
y: 16
z: 4
i: 0
i: 1
i: 2
i: 3

```

使用这种实现方式，我们仍然需要一个循环来从`stdout`流中获取所有的结果。不幸的是，`asyncio.StreamReader`（`process.stdout`所属的类）类尚不支持`async for`语法。如果支持的话，一个简单的`async for out in process.stdout`就可以工作了。一个简单的`yield from process.stdout.read()`也可以工作，但通常逐行阅读更方便使用。

如果可能的话，我建议您避免使用`stdin`向子进程发送数据，而是使用一些网络、管道或文件通信。正如我们将在下面的段落中看到的，这些更方便处理。

## 异步服务器和客户端

导致脚本和应用程序停滞的最常见原因之一是使用远程资源。使用`asyncio`，至少其中的大部分是很容易解决的。获取多个远程资源并为多个客户端提供服务比以前要容易得多，也更轻量级。虽然多线程和多进程也可以用于这些情况，但`asyncio`是一个更轻量级的替代方案，实际上更容易管理。创建客户端和服务器有两种主要方法。协程方式是使用`asyncio.open_connection`和`asyncio.start_server`。基于类的方法要求您继承`asyncio.Protocol`类。虽然它们本质上是相同的，但工作方式略有不同。

### 基本回显服务器

基本的客户端和服务器版本编写起来相当简单。`asyncio`模块负责所有底层连接处理，我们只需要连接正确的方法。对于服务器，我们需要一个处理传入连接的方法，对于客户端，我们需要一个创建连接的函数。为了说明发生了什么以及在何时发生，我们将添加一个专门的打印函数，打印自服务器进程启动以来的时间和给定的参数：

```py
import time
import sys
import asyncio

HOST = '127.0.0.1'
PORT = 1234

start_time = time.time()

def printer(start_time, *args, **kwargs):
    '''Simple function to print a message prefixed with the
    time relative to the given start_time'''
    print('%.1f' % (time.time() - start_time), *args, **kwargs)

async def handle_connection(reader, writer):
    client_address = writer.get_extra_info('peername')
    printer(start_time, 'Client connected', client_address)

    # Send over the server start time to get consistent
    # timestamps
    writer.write(b'%.2f\n' % start_time)
    await writer.drain()

    repetitions = int((await reader.readline()))
    printer(start_time, 'Started sending to', client_address)

    for i in range(repetitions):
        message = 'client: %r, %d\n' % (client_address, i)
        printer(start_time, message, end='')
        writer.write(message.encode())
        await writer.drain()

    printer(start_time, 'Finished sending to', client_address)
    writer.close()

async def create_connection(repetitions):
    reader, writer = await asyncio.open_connection(
        host=HOST, port=PORT)

    start_time = float((await reader.readline()))

    writer.write(repetitions.encode() + b'\n')
    await writer.drain()

    async for line in reader:
        # Sleeping a little to emulate processing time and make
        # it easier to add more simultaneous clients
        await asyncio.sleep(1)

        printer(start_time, 'Got line: ', line.decode(),
                end='')

    writer.close()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()

    if sys.argv[1] == 'server':
        server = asyncio.start_server(
            handle_connection,
            host=HOST,
            port=PORT,
        )
        running_server = loop.run_until_complete(server)

        try:
            result = loop.call_later(5, loop.stop)
            loop.run_forever()
        except KeyboardInterrupt:
            pass

        running_server.close()
        loop.run_until_complete(running_server.wait_closed())
    elif sys.argv[1] == 'client':
        loop.run_until_complete(create_connection(sys.argv[2]))

    loop.close()
```

现在我们将运行服务器和两个同时的客户端。由于这些是并行运行的，服务器输出当然有点奇怪。因此，我们将从服务器到客户端同步启动时间，并在所有打印语句前加上自服务器启动以来的秒数。

服务器：

```py
# python3 simple_connections.py server
0.4 Client connected ('127.0.0.1', 59990)
0.4 Started sending to ('127.0.0.1', 59990)
0.4 client: ('127.0.0.1', 59990), 0
0.4 client: ('127.0.0.1', 59990), 1
0.4 client: ('127.0.0.1', 59990), 2
0.4 Finished sending to ('127.0.0.1', 59990)
2.0 Client connected ('127.0.0.1', 59991)
2.0 Started sending to ('127.0.0.1', 59991)
2.0 client: ('127.0.0.1', 59991), 0
2.0 client: ('127.0.0.1', 59991), 1
2.0 Finished sending to ('127.0.0.1', 59991)

```

第一个客户端：

```py
# python3 simple_connections.py client 3
1.4 Got line:  client: ('127.0.0.1', 59990), 0
2.4 Got line:  client: ('127.0.0.1', 59990), 1
3.4 Got line:  client: ('127.0.0.1', 59990), 2

```

第二个客户端：

```py
# python3 simple_connections.py client 2
3.0 Got line:  client: ('127.0.0.1', 59991), 0
4.0 Got line:  client: ('127.0.0.1', 59991), 1

```

由于输入和输出都有缓冲区，我们需要在写入后手动排空输入，并在从对方读取输出时使用`yield from`。这正是与常规外部进程通信更困难的原因。进程的标准输入更侧重于用户输入而不是计算机输入，这使得使用起来不太方便。

### 注意

如果您希望使用`reader.read(BUFFER)`而不是`reader.readline()`，也是可能的。只是请注意，您需要明确地分隔数据，否则可能会意外地被附加。所有写操作都写入同一个缓冲区，导致一个长的返回流。另一方面，尝试在`reader.readline()`中没有新行(`\n`)的情况下进行写入将导致客户端永远等待。

# 摘要

在本章中，我们看到了如何在 Python 中使用`asyncio`进行异步 I/O。对于许多场景，`asyncio`模块仍然有些原始和未完成，但不应该有任何使用上的障碍。创建一个完全功能的服务器/客户端设置仍然有点复杂，但`asyncio`最明显的用途是处理基本的网络 I/O，如数据库连接和外部资源，如网站。特别是后者只需使用`asyncio`就可以实现几行代码，从您的代码中删除一些非常重要的瓶颈。

本章的重点是理解如何告诉 Python 在后台等待结果，而不是像通常那样简单地等待或轮询结果。在第十三章中，*多处理-当单个 CPU 核心不够用*，您将了解多处理，这也是处理停滞资源的选项。然而，多处理的目标实际上是使用多个处理器，而不是处理停滞资源。当涉及潜在缓慢的外部资源时，我建议您尽可能使用`asyncio`。

在基于`asyncio`库构建实用程序时，确保搜索预制库来解决您的问题，因为其中许多目前正在开发中。在撰写本章时，Python 3.5 尚未正式发布，因此很可能很快会出现更多使用`async/await`语法的文档和库。为了确保您不重复他人已完成的工作，请在撰写扩展`asyncio`的代码之前彻底搜索互联网。

下一章将解释一个完全不同的主题-使用元类构建类。常规类是使用 type 类创建的，但现在我们将看到如何扩展和修改默认行为，使类几乎可以做任何我们想要的事情。元类甚至可以实现自动注册插件，并以非常神奇的方式向类添加功能-简而言之，如何定制不仅类实例而且类定义本身。


# 第八章：元类-使类（而不是实例）更智能

前几章已经向我们展示了如何使用装饰器修改类和函数。但这并不是修改或扩展类的唯一选项。在创建类之前修改你的类的更高级的技术是使用**元类**。这个名字已经暗示了它可能是什么；元类是一个包含有关类的元信息的类。

元类的基本前提是在定义时为你生成另一个类的类，因此通常你不会用它来改变类实例，而只会用它来改变类定义。通过改变类定义，可以自动向类添加一些属性，验证是否设置了某些属性，改变继承关系，自动将类注册到管理器，并做许多其他事情。

尽管元类通常被认为是比（类）装饰器更强大的技术，但实际上它们在可能性上并没有太大的区别。选择通常取决于方便性或个人偏好。

本章涵盖了以下主题：

+   基本的动态类创建

+   带参数的元类

+   类创建的内部工作原理，操作顺序

+   抽象基类、示例和内部工作原理

+   使用元类的自动插件系统

+   存储类属性的定义顺序

# 动态创建类

元类是在 Python 中创建新类的工厂。实际上，即使你可能不知道，Python 在你创建一个类时总是会执行`type`元类。

在以程序方式创建类时，`type`元类被用作一个函数。这个函数接受三个参数：`name`，`bases`和`dict`。`name`将成为`__name__`属性，`bases`是继承的基类列表，将存储在`__bases__`中，`dict`是包含所有变量的命名空间字典，将存储在`__dict__`中。

应该注意`type()`函数还有另一个用途。根据之前记录的参数，它会根据这些规格创建一个类。给定一个类实例的单个参数，它也会返回该类，但是从实例中返回。你下一个问题可能是，“如果我在类定义而不是类实例上调用`type()`会发生什么？”嗯，这会返回类的元类，默认为`type`。

让我们用几个例子来澄清这一点：

```py
>>> class Spam(object):
>>>     eggs = 'my eggs'

>>> Spam = type('Spam', (object,), dict(eggs='my eggs'))

```

前两个`Spam`的定义完全相同；它们都创建了一个具有`eggs`和`object`作为基类的类。让我们测试一下这是否像你期望的那样工作：

```py
>>> class Spam(object):
...     eggs = 'my eggs'

>>> spam = Spam()
>>> spam.eggs
'my eggs'
>>> type(spam)
<class '…Spam'>
>>> type(Spam)
<class 'type'>

>>> Spam = type('Spam', (object,), dict(eggs='my eggs'))

>>> spam = Spam()
>>> spam.eggs
'my eggs'
>>> type(spam)
<class '...Spam'>
>>> type(Spam)
<class 'type'>

```

如预期的那样，这两个结果是相同的。在创建类时，Python 会悄悄地添加`type`元类，而`custom`元类只是继承`type`的类。一个简单的类定义有一个隐式的元类，使得一个简单的定义如下：

```py
class Spam(object):
 **pass

```

本质上与：

```py
class Spam(object, metaclass=type):
 **pass

```

这引发了一个问题，即如果每个类都是由一个（隐式的）元类创建的，那么`type`的元类是什么？这实际上是一个递归定义；`type`的元类是`type`。这就是自定义元类的本质：一个继承了 type 的类，允许在不需要修改类定义本身的情况下修改类。

## 一个基本的元类

由于元类可以修改任何类属性，你可以做任何你想做的事情。在我们继续讨论更高级的元类之前，让我们看一个基本的例子：

```py
# The metaclass definition, note the inheritance of type instead
# of object
>>> class MetaSpam(type):
...
...     # Notice how the __new__ method has the same arguments
...     # as the type function we used earlier?
...     def __new__(metaclass, name, bases, namespace):
...         name = 'SpamCreatedByMeta'
...         bases = (int,) + bases
...         namespace['eggs'] = 1
...         return type.__new__(metaclass, name, bases, namespace)

# First, the regular Spam:
>>> class Spam(object):
...     pass

>>> Spam.__name__
'Spam'
>>> issubclass(Spam, int)
False
>>> Spam.eggs
Traceback (most recent call last):
 **...
AttributeError: type object 'Spam' has no attribute 'eggs'

# Now the meta-Spam
>>> class Spam(object, metaclass=MetaSpam):
...     pass

>>> Spam.__name__
'SpamCreatedByMeta'
>>> issubclass(Spam, int)
True
>>> Spam.eggs
1

```

正如你所看到的，使用元类可以轻松修改类定义的所有内容。这使得它既是一个非常强大又是一个非常危险的工具，因为你可以很容易地引起非常意外的行为。

## 元类的参数

向元类添加参数的可能性是一个鲜为人知但非常有用的特性。在许多情况下，简单地向类定义添加属性或方法就足以检测要做什么，但也有一些情况下更具体的指定是有用的。

```py
>>> class MetaWithArguments(type):
...     def __init__(metaclass, name, bases, namespace, **kwargs):
...         # The kwargs should not be passed on to the
...         # type.__init__
...         type.__init__(metaclass, name, bases, namespace)
...
...     def __new__(metaclass, name, bases, namespace, **kwargs):
...         for k, v in kwargs.items():
...             namespace.setdefault(k, v)
...
...         return type.__new__(metaclass, name, bases, namespace)

>>> class WithArgument(metaclass=MetaWithArguments, spam='eggs'):
...     pass

>>> with_argument = WithArgument()
>>> with_argument.spam
'eggs'

```

这个简单的例子可能没有用，但可能性是存在的。你需要记住的唯一一件事是，为了使其工作，`__new__` 和 `__init__` 方法都需要被扩展。

## 通过类访问元类属性

在使用元类时，可能会感到困惑，注意到类实际上不仅仅是构造类，它实际上在创建时继承了类。举个例子：

```py
>>> class Meta(type):
...
...     @property
...     def spam(cls):
...         return 'Spam property of %r' % cls
...
...     def eggs(self):
...         return 'Eggs method of %r' % self

>>> class SomeClass(metaclass=Meta):
...     pass

>>> SomeClass.spam
"Spam property of <class '...SomeClass'>"
>>> SomeClass().spam
Traceback (most recent call last):
 **...
AttributeError: 'SomeClass' object has no attribute 'spam'

>>> SomeClass.eggs()
"Eggs method of <class '...SomeClass'>"
>>> SomeClass().eggs()
Traceback (most recent call last):
 **...
AttributeError: 'SomeClass' object has no attribute 'eggs'

```

正如前面的例子中所示，这些方法仅适用于 `class` 对象，而不适用于实例。`spam` 属性和 `eggs` 方法无法通过实例访问，但可以通过类访问。我个人认为这种行为没有任何有用的情况，但它确实值得注意。

# 使用 collections.abc 的抽象类

抽象基类模块是 Python 中最有用和最常用的元类示例之一，因为它可以轻松确保类遵循特定接口，而无需进行大量手动检查。我们已经在前几章中看到了一些抽象基类的示例，但现在我们将看看这些抽象基类的内部工作原理和更高级的特性，比如自定义 ABC。

## 抽象类的内部工作原理

首先，让我们演示常规抽象基类的用法：

```py
>>> import abc

>>> class Spam(metaclass=abc.ABCMeta):
...
...     @abc.abstractmethod
...     def some_method(self):
...         raise NotImplemented()

>>> class Eggs(Spam):
...     def some_new_method(self):
...         pass

>>> eggs = Eggs()
Traceback (most recent call last):
 **...
TypeError: Can't instantiate abstract class Eggs with abstract
methods some_method

>>> class Bacon(Spam):
...     def some_method():
...         pass

>>> bacon = Bacon()

```

正如你所看到的，抽象基类阻止我们在继承所有抽象方法之前实例化类。除了常规方法外，还支持 `property`、`staticmethod` 和 `classmethod`。

```py
>>> import abc

>>> class Spam(object, metaclass=abc.ABCMeta):
...     @property
...     @abc.abstractmethod
...     def some_property(self):
...         raise NotImplemented()
...
...     @classmethod
...     @abc.abstractmethod
...     def some_classmethod(cls):
...         raise NotImplemented()
...
...     @staticmethod
...     @abc.abstractmethod
...     def some_staticmethod():
...         raise NotImplemented()
...
...     @abc.abstractmethod
...     def some_method():
...         raise NotImplemented()

```

那么 Python 在内部做了什么呢？当然，你可以阅读 `abc.py` 源代码，但我认为简单的解释会更好。

首先，`abc.abstractmethod` 将 `__isabstractmethod__` 属性设置为 `True`。因此，如果你不想使用装饰器，你可以简单地模拟这种行为，做一些类似的事情：

```py
some_method.__isabstractmethod__ = True

```

在那之后，`abc.ABCMeta` 元类遍历命名空间中的所有项目，并查找 `__isabstractmethod__` 属性评估为 `True` 的对象。除此之外，它还遍历所有基类，并检查每个基类的 `__abstractmethods__` 集合，以防类继承了一个 `abstract` 类。所有 `__isabstractmethod__` 仍然评估为 `True` 的项目都被添加到 `__abstractmethods__` 集合中，该集合存储在类中作为 `frozenset`。

### 注意

请注意，我们不使用 `abc.abstractproperty`、`abc.abstractclassmethod` 和 `abc.abstractstaticmethod`。自 Python 3.3 起，这些已被弃用，因为 `classmethod`、`staticmethod` 和 `property` 装饰器被 `abc.abstractmethod` 所识别，因此简单的 `property` 装饰器后跟 `abc.abstractmethod` 也被识别。在对装饰器进行排序时要小心；`abc.abstractmethod` 需要是最内层的装饰器才能正常工作。

现在的问题是实际的检查在哪里进行；检查类是否完全实现。这实际上是通过一些 Python 内部功能实现的：

```py
>>> class AbstractMeta(type):
...     def __new__(metaclass, name, bases, namespace):
...         cls = super().__new__(metaclass, name, bases, namespace)
...         cls.__abstractmethods__ = frozenset(('something',))
...         return cls

>>> class Spam(metaclass=AbstractMeta):
...     pass

>>> eggs = Spam()
Traceback (most recent call last):
 **...
TypeError: Can't instantiate abstract class Spam with ...

```

我们可以很容易地自己使用 `metaclass` 模拟相同的行为，但应该注意 `abc.ABCMeta` 实际上做了更多，我们将在下一节中进行演示。为了模仿内置抽象基类支持的行为，看看下面的例子：

```py
>>> import functools

>>> class AbstractMeta(type):
...     def __new__(metaclass, name, bases, namespace):
...         # Create the class instance
...         cls = super().__new__(metaclass, name, bases, namespace)
...
...         # Collect all local methods marked as abstract
...         abstracts = set()
...         for k, v in namespace.items():
...             if getattr(v, '__abstract__', False):
...                 abstracts.add(k)
...
...         # Look for abstract methods in the base classes and add
...         # them to the list of abstracts
...         for base in bases:
...             for k in getattr(base, '__abstracts__', ()):
...                 v = getattr(cls, k, None)
...                 if getattr(v, '__abstract__', False):
...                     abstracts.add(k)
...
...         # store the abstracts in a frozenset so they cannot be
...         # modified
...         cls.__abstracts__ = frozenset(abstracts)
...
...         # Decorate the __new__ function to check if all abstract
...         # functions were implemented
...         original_new = cls.__new__
...         @functools.wraps(original_new)
...         def new(self, *args, **kwargs):
...             for k in self.__abstracts__:
...                 v = getattr(self, k)
...                 if getattr(v, '__abstract__', False):
...                     raise RuntimeError(
...                         '%r is not implemented' % k)
...
...             return original_new(self, *args, **kwargs)
...
...         cls.__new__ = new
...         return cls

>>> def abstractmethod(function):
...     function.__abstract__ = True
...     return function

>>> class Spam(metaclass=AbstractMeta):
...     @abstractmethod
...     def some_method(self):
...         pass

# Instantiating the function, we can see that it functions as the
# regular ABCMeta does
>>> eggs = Spam()
Traceback (most recent call last):
 **...
RuntimeError: 'some_method' is not implemented

```

实际的实现要复杂一些，因为它仍然需要处理旧式类和`property`、`classmethod` 和 `staticmethod` 类型的方法。此外，它还具有缓存功能，但这段代码涵盖了实现的最有用部分。这里最重要的技巧之一是实际的检查是通过装饰实际类的 `__new__` 函数来执行的。这个方法在类中只执行一次，所以我们可以避免为多个实例化添加这些检查的开销。

### 注意

抽象方法的实际实现可以通过在 Python 源代码中查找 `Objects/descrobject.c`、`Objects/funcobject.c` 和 `Objects/object.c` 文件中的 `__isabstractmethod__` 来找到。实现的 Python 部分可以在 `Lib/abc.py` 中找到。

## 自定义类型检查

当然，使用抽象基类来定义自己的接口是很好的。但是告诉 Python 你的类实际上类似于什么样的类型也是非常方便的。为此，`abc.ABCMeta` 提供了一个注册函数，允许你指定哪些类型是相似的。例如，一个自定义的列表将列表类型视为相似的：

```py
>>> import abc

>>> class CustomList(abc.ABC):
...     'This class implements a list-like interface'
...     pass

>>> CustomList.register(list)
<class 'list'>

>>> issubclass(list, CustomList)
True
>>> isinstance([], CustomList)
True
>>> issubclass(CustomList, list)
False
>>> isinstance(CustomList(), list)
False

```

正如最后四行所示，这是一个单向关系。反过来通常很容易通过继承列表来实现，但在这种情况下不起作用。`abc.ABCMeta` 拒绝创建继承循环。

```py
>>> import abc

>>> class CustomList(abc.ABC, list):
...     'This class implements a list-like interface'
...     pass

>>> CustomList.register(list)
Traceback (most recent call last):
 **...
RuntimeError: Refusing to create an inheritance cycle

```

为了能够处理这样的情况，`abc.ABCMeta` 中还有另一个有用的特性。在子类化 `abc.ABCMeta` 时，可以扩展 `__subclasshook__` 方法来定制 `issubclass` 和 `isinstance` 的行为。

```py
>>> import abc

>>> class UniversalClass(abc.ABC):
...    @classmethod
...    def __subclasshook__(cls, subclass):
...        return True

>>> issubclass(list, UniversalClass)
True
>>> issubclass(bool, UniversalClass)
True
>>> isinstance(True, UniversalClass)
True
>>> issubclass(UniversalClass, bool)
False

```

`__subclasshook__` 应该返回 `True`、`False` 或 `NotImplemented`，这将导致 `issubclass` 返回 `True`、`False` 或在引发 `NotImplemented` 时的通常行为。

## 在 Python 3.4 之前使用 abc.ABC

我们在本段中使用的 `abc.ABC` 类仅在 Python 3.4 及更高版本中可用，但在旧版本中实现它是微不足道的。它只是 `metaclass=abc.ABCMeta` 的语法糖。要自己实现它，你可以简单地使用以下代码片段：

```py
import abc

class ABC(metaclass=abc.ABCMeta):
    pass
```

# 自动注册插件系统

元类最常见的用途之一是让类自动注册为插件/处理程序。这些示例可以在许多项目中看到，比如 Web 框架。这些代码库太庞大了，在这里无法有用地解释。因此，我们将展示一个更简单的例子，展示元类作为自注册的 `plugin` 系统的强大功能：

```py
>>> import abc

>>> class Plugins(abc.ABCMeta):
...     plugins = dict()
...
...     def __new__(metaclass, name, bases, namespace):
...         cls = abc.ABCMeta.__new__(metaclass, name, bases,
...                                   namespace)
...         if isinstance(cls.name, str):
...             metaclass.plugins[cls.name] = cls
...         return cls
...
...     @classmethod
...     def get(cls, name):
...         return cls.plugins[name]

>>> class PluginBase(metaclass=Plugins):
...     @property
...     @abc.abstractmethod
...     def name(self):
...         raise NotImplemented()

>>> class SpamPlugin(PluginBase):
...     name = 'spam'

>>> class EggsPlugin(PluginBase):
...     name = 'eggs'

>>> Plugins.get('spam')
<class '...SpamPlugin'>
>>> Plugins.plugins
{'spam': <class '...SpamPlugin'>,
 **'eggs': <class '...EggsPlugin'>}

```

当然，这个例子有点简单，但它是许多插件系统的基础。这是在实现这样的系统时需要注意的一个非常重要的事情；然而，尽管元类在定义时运行，模块仍然需要被导入才能工作。有几种选项可以做到这一点；通过 `get` 方法进行按需加载是我的选择，因为这样即使插件没有被使用也不会增加加载时间。

以下示例将使用以下文件结构以获得可重现的结果。所有文件将包含在一个名为 plugins 的目录中。

`__init__.py` 文件用于创建快捷方式，因此简单的导入 plugins 将导致 `plugins.Plugins` 可用，而不需要显式导入 `plugins.base`。

```py
# plugins/__init__.py
from .base import Plugin
from .base import Plugins

__all__ = ['Plugin', 'Plugins']
```

包含 `Plugins` 集合和 `Plugin` 基类的 `base.py` 文件：

```py
# plugins/base.py
import abc

class Plugins(abc.ABCMeta):
    plugins = dict()

    def __new__(metaclass, name, bases, namespace):
        cls = abc.ABCMeta.__new__(
            metaclass, name, bases, namespace)
        if isinstance(cls.name, str):
            metaclass.plugins[cls.name] = cls
        return cls

    @classmethod
    def get(cls, name):
        return cls.plugins[name]

class Plugin(metaclass=Plugins):
    @property
    @abc.abstractmethod
    def name(self):
        raise NotImplemented()
```

和两个简单的插件，`spam.py`：

```py
from . import base

class Spam(base.Plugin):
    name = 'spam'
```

和 `eggs.py`：

```py
from . import base

class Eggs(base.Plugin):
    name = 'eggs'
```

## 按需导入插件

解决导入问题的第一个解决方案是在 `Plugins` 元类的 `get` 方法中处理它。每当在注册表中找不到插件时，它应该自动从 `plugins` 目录加载模块。

这种方法的优势在于，不仅插件不需要显式预加载，而且只有在需要时才加载插件。未使用的插件不会被触及，因此这种方法有助于减少应用程序的加载时间。

缺点是代码不会被运行或测试，所以它可能完全失效，直到最终加载时你才会知道。这个问题的解决方案将在测试章节中介绍，第十章，*测试和日志 - 为错误做准备*。另一个问题是，如果代码自注册到应用程序的其他部分，那么该代码也不会被执行。

修改`Plugins.get`方法，我们得到以下结果：

```py
import abc
import importlib

class Plugins(abc.ABCMeta):
    plugins = dict()

    def __new__(metaclass, name, bases, namespace):
        cls = abc.ABCMeta.__new__(
            metaclass, name, bases, namespace)
        if isinstance(cls.name, str):
            metaclass.plugins[cls.name] = cls
        return cls

    @classmethod
    def get(cls, name):
        if name not in cls.plugins:
            print('Loading plugins from plugins.%s' % name)
            importlib.import_module('plugins.%s' % name)
        return cls.plugins[name]
```

执行时会得到以下结果：

```py
>>> import plugins
>>> plugins.Plugins.get('spam')
Loading plugins from plugins.spam
<class 'plugins.spam.Spam'>

>>> plugins.Plugins.get('spam')
<class 'plugins.spam.Spam'>

```

正如你所看到的，这种方法只会导入一次`import`。第二次，插件将在插件字典中可用，因此不需要加载。

## 通过配置导入插件

通常只加载所需的插件是一个更好的主意，但预加载可能需要的插件也有其优点。显式比隐式更好，显式加载插件列表通常是一个很好的解决方案。这种方法的附加优势是，首先你可以使注册更加先进，因为你保证它被运行，其次你可以从多个包中加载插件。

在`get`方法中，我们将这次添加一个`load`方法；一个导入所有给定模块名称的`load`方法：

```py
import abc
import importlib

class Plugins(abc.ABCMeta):
    plugins = dict()

    def __new__(metaclass, name, bases, namespace):
        cls = abc.ABCMeta.__new__(
            metaclass, name, bases, namespace)
        if isinstance(cls.name, str):
            metaclass.plugins[cls.name] = cls
        return cls

    @classmethod
    def get(cls, name):
        return cls.plugins[name]

    @classmethod
    def load(cls, *plugin_modules):
        for plugin_module in plugin_modules:
            plugin = importlib.import_module(plugin_module)
```

可以使用以下代码调用：

```py
>>> import plugins

>>> plugins.Plugins.load(
...     'plugins.spam',
...     'plugins.eggs',
... )

>>> plugins.Plugins.get('spam')
<class 'plugins.spam.Spam'>

```

一个相当简单和直接的系统，根据设置加载插件，这可以很容易地与任何类型的设置系统结合使用来填充`load`方法。

## 通过文件系统导入插件

在可能的情况下，最好避免让系统依赖于文件系统上模块的自动检测，因为这直接违反了`PEP8`。特别是，“显式比隐式更好”。虽然这些系统在特定情况下可以正常工作，但它们经常会使调试变得更加困难。在 Django 中类似的自动导入系统给我带来了不少头疼，因为它们往往会混淆错误。话虽如此，基于插件目录中所有文件的自动插件加载仍然是一个值得演示的可能性。

```py
import os
import re
import abc
import importlib

MODULE_NAME_RE = re.compile('[a-z][a-z0-9_]*', re.IGNORECASE)

class Plugins(abc.ABCMeta):
    plugins = dict()

    def __new__(metaclass, name, bases, namespace):
        cls = abc.ABCMeta.__new__(
            metaclass, name, bases, namespace)
        if isinstance(cls.name, str):
            metaclass.plugins[cls.name] = cls
        return cls

    @classmethod
    def get(cls, name):
        return cls.plugins[name]

    @classmethod
    def load_directory(cls, module, directory):
        for file_ in os.listdir(directory):
            name, ext = os.path.splitext(file_)
            full_path = os.path.join(directory, file_)
            import_path = [module]
            if os.path.isdir(full_path):
                import_path.append(file_)
            elif ext == '.py' and MODULE_NAME_RE.match(name):
                import_path.append(name)
            else:
                # Ignoring non-matching files/directories
                continue

            plugin = importlib.import_module('.'.join(import_path))

    @classmethod
    def load(cls, **plugin_directories):
        for module, directory in plugin_directories.items():
            cls.load_directory(module, directory)
```

如果可能的话，我会尽量避免使用完全自动的导入系统，因为它很容易出现意外错误，并且会使调试变得更加困难，更不用说导入顺序无法轻松地通过这种方式进行控制。为了使这个系统变得更加智能（甚至导入 Python 路径之外的包），你可以使用`importlib.abc`中的抽象基类创建一个插件加载器。请注意，你很可能仍然需要通过`os.listdir`或`os.walk`列出目录。

# 实例化类时的操作顺序

在调试动态创建和/或修改的类时，类实例化的操作顺序非常重要。类的实例化按以下顺序进行。

## 查找元类

元类来自于类的显式给定的元类或`bases`，或者使用默认的`type`元类。

对于每个类，类本身和 bases，将使用以下匹配的第一个：

+   显式给定的元类

+   从 bases 中显式元类

+   `type()`

### 注意

请注意，如果找不到是所有候选元类的子类型的元类，将引发`TypeError`。这种情况发生的可能性不太大，但在使用多重继承/混入元类时肯定是可能的。

## 准备命名空间

通过之前选择的元类准备类命名空间。如果元类有一个`__prepare__`方法，它将被调用`namespace = metaclass.__prepare__(names, bases, **kwargs)`，其中`**kwargs`来自类定义。如果没有`__prepare__`方法可用，结果将是`namespace = dict()`。

请注意，有多种实现自定义命名空间的方法，正如我们在前一段中看到的，`type()`函数调用还接受一个`dict`参数，也可以用于修改命名空间。

## 执行类主体

类的主体执行方式与普通代码执行非常相似，但有一个关键区别，即单独的命名空间。由于类有一个单独的命名空间，不应该污染`globals()/locals()`命名空间，因此在该上下文中执行。结果调用看起来像这样：`exec(body, globals(), namespace)`，其中`namespace`是先前生成的命名空间。

## 创建类对象（而不是实例）

现在我们已经准备好所有组件，实际的类对象可以被生成。这是通过`class_ = metaclass(name, bases, namespace, **kwargs)`调用完成的。正如您所看到的，这实际上与之前讨论的`type()`调用完全相同。这里的`**kwargs`与之前传递给`__prepare__`方法的参数相同。

值得注意的是，这也是在`super()`调用中不带参数时将被引用的对象。

## 执行类装饰器

现在类对象实际上已经完成，类装饰器将被执行。由于这仅在类对象中的所有其他内容已经构建完成后执行，因此变得更难修改类属性，例如继承哪些类以及类的名称。通过修改`__class__`对象，您仍然可以修改或覆盖这些内容，但至少更加困难。

## 创建类实例

从先前生成的类对象中，现在我们可以像通常一样创建实际的实例。应该注意的是，与之前的步骤不同，这两个步骤和类装饰器步骤是唯一在每次实例化类时执行的步骤。在这两个步骤之前的步骤只在每个类定义时执行一次。

## 示例

足够的理论！让我们说明创建和实例化类对象的过程，以便检查操作顺序：

```py
>>> import functools

>>> def decorator(name):
...     def _decorator(cls):
...         @functools.wraps(cls)
...         def __decorator(*args, **kwargs):
...             print('decorator(%s)' % name)
...             return cls(*args, **kwargs)
...         return __decorator
...     return _decorator

>>> class SpamMeta(type):
...
...     @decorator('SpamMeta.__init__')
...     def __init__(self, name, bases, namespace, **kwargs):
...         print('SpamMeta.__init__()')
...         return type.__init__(self, name, bases, namespace)
...
...     @staticmethod
...     @decorator('SpamMeta.__new__')
...     def __new__(cls, name, bases, namespace, **kwargs):
...         print('SpamMeta.__new__()')
...         return type.__new__(cls, name, bases, namespace)
...
...     @classmethod
...     @decorator('SpamMeta.__prepare__')
...     def __prepare__(cls, names, bases, **kwargs):
...         print('SpamMeta.__prepare__()')
...         namespace = dict(spam=5)
...         return namespace

>>> @decorator('Spam')
... class Spam(metaclass=SpamMeta):
...
...     @decorator('Spam.__init__')
...     def __init__(self, eggs=10):
...         print('Spam.__init__()')
...         self.eggs = eggs
decorator(SpamMeta.__prepare__)
SpamMeta.__prepare__()
decorator(SpamMeta.__new__)
SpamMeta.__new__()
decorator(SpamMeta.__init__)
SpamMeta.__init__()

# Testing with the class object
>>> spam = Spam
>>> spam.spam
5
>>> spam.eggs
Traceback (most recent call last):
 **...
AttributeError: ... object has no attribute 'eggs'

# Testing with a class instance
>>> spam = Spam()
decorator(Spam)
decorator(Spam.__init__)
Spam.__init__()
>>> spam.spam
5
>>> spam.eggs
10

```

该示例清楚地显示了类的创建顺序：

1.  通过`__prepare__`准备命名空间。

1.  使用`__new__`创建类主体。

1.  使用`__init__`初始化元类（请注意，这不是类`__init__`）。

1.  通过类装饰器初始化类。

1.  通过类`__init__`函数初始化类。

我们可以从中注意到的一点是，类装饰器在实际实例化类时每次都会执行，而不是在此之前。当然，这既是优点也是缺点，但如果您希望构建所有子类的注册表，那么使用元类肯定更方便，因为装饰器在实例化类之前不会注册。

除此之外，在实际创建类对象（而不是实例）之前修改命名空间的能力也是非常强大的。例如，可以方便地在几个类对象之间共享特定范围，或者轻松确保某些项目始终在范围内可用。

# 按定义顺序存储类属性

有些情况下，定义顺序是有影响的。例如，假设我们正在创建一个表示 CSV（逗号分隔值）格式的类。CSV 格式期望字段有特定的顺序。在某些情况下，这将由标题指示，但保持一致的字段顺序仍然很有用。类似的系统在 ORM 系统（如 SQLAlchemy）中使用，用于存储表定义的列顺序以及在 Django 中的表单中的输入字段顺序。

## 没有元类的经典解决方案

一种简单的存储字段顺序的方法是给字段实例一个特殊的`__init__`方法，每次定义都会增加，因此字段具有递增的索引属性。这种解决方案可以被认为是经典解决方案，因为它在 Python 2 中也适用。

```py
>>> import itertools

>>> class Field(object):
...     counter = itertools.count()
...
...     def __init__(self, name=None):
...         self.name = name
...         self.index = next(Field.counter)
...
...     def __repr__(self):
...         return '<%s[%d] %s>' % (
...             self.__class__.__name__,
...             self.index,
...             self.name,
...         )

>>> class FieldsMeta(type):
...     def __new__(metaclass, name, bases, namespace):
...         cls = type.__new__(metaclass, name, bases, namespace)
...         fields = []
...         for k, v in namespace.items():
...             if isinstance(v, Field):
...                 fields.append(v)
...                 v.name = v.name or k
...
...         cls.fields = sorted(fields, key=lambda f: f.index)
...         return cls

>>> class Fields(metaclass=FieldsMeta):
...     spam = Field()
...     eggs = Field()

>>> Fields.fields
[<Field[0] spam>, <Field[1] eggs>]

>>> fields = Fields()
>>> fields.eggs.index
1
>>> fields.spam.index
0
>>> fields.fields
[<Field[0] spam>, <Field[1] eggs>]

```

为了方便起见，也为了使事情更美观，我们添加了`FieldsMeta`类。这里并不严格需要它，但它会自动填写名称（如果需要的话），并添加包含字段排序列表的`fields`列表。

## 使用元类获取排序的命名空间

前面的解决方案更加直接，并且也支持 Python 2，但是在 Python 3 中我们有更多的选择。正如你在前面的段落中看到的，自从 Python 3 以来，我们有了`__prepare__`方法，它返回命名空间。从前面的章节中，你可能还记得`collections.OrderedDict`，所以让我们看看当我们将它们结合起来会发生什么。

```py
>>> import collections

>>> class Field(object):
...     def __init__(self, name=None):
...         self.name = name
...
...     def __repr__(self):
...         return '<%s %s>' % (
...             self.__class__.__name__,
...             self.name,
...         )

>>> class FieldsMeta(type):
...     @classmethod
...     def __prepare__(metaclass, name, bases):
...         return collections.OrderedDict()
...
...     def __new__(metaclass, name, bases, namespace):
...         cls = type.__new__(metaclass, name, bases, namespace)
...         cls.fields = []
...         for k, v in namespace.items():
...             if isinstance(v, Field):
...                 cls.fields.append(v)
...                 v.name = v.name or k
...
...         return cls

>>> class Fields(metaclass=FieldsMeta):
...     spam = Field()
...     eggs = Field()

>>> Fields.fields
[<Field spam>, <Field eggs>]
>>> fields = Fields()
>>> fields.fields
[<Field spam>, <Field eggs>]
```

正如你所看到的，字段确实按照我们定义的顺序排列。`Spam`在前，`eggs`在后。由于类命名空间现在是`collections.OrderedDict`实例，我们知道顺序是有保证的。而不是 Python `dict`的常规非确定性顺序。这展示了元类在以通用方式扩展类时可以多么方便。元类的另一个重要优势是，与自定义的`__init__`方法不同，如果用户忘记调用父类的`__init__`方法，他们也不会失去功能。元类总是会被执行，除非添加了不同的元类。

# 总结

Python 元类系统是每个 Python 程序员一直在使用的东西，也许甚至不知道。每个类都应该通过某个（子类）`type`来创建，这允许无限的定制和魔法。现在，你可以像平常一样创建类，并在定义期间动态添加、修改或删除类的属性；非常神奇但非常有用。然而，魔法组件也是它应该谨慎使用的原因。虽然元类可以让你的生活变得更轻松，但它们也是产生完全难以理解的代码的最简单方式之一。

尽管如此，元类有一些很好的用例，许多库如`SQLAlchemy`和`Django`都使用元类来使你的代码工作更加轻松，而且可以说更好。实际上，理解内部使用的魔法通常对于使用这些库并不是必需的，这使得这些情况是可以辩护的。问题在于，对于初学者来说，是否值得使用更好的体验来换取一些内部的黑魔法，从这些库的成功来看，我会说在这种情况下是值得的。

总之，当考虑使用元类时，请记住蒂姆·彼得斯曾经说过的话：“元类比 99%的用户应该担心的更深奥。如果你想知道自己是否需要它们，那就不需要。”

现在我们将继续解决一些元类产生的魔法：文档。下一章将向我们展示如何为代码编写文档，如何测试文档，并且最重要的是，如何通过在文档中注释类型来使文档更加智能。
