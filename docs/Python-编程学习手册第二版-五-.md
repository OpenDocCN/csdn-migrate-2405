# Python 编程学习手册第二版（五）

> 原文：[`zh.annas-archive.org/md5/406733548F67B770B962DA4756270D5F`](https://zh.annas-archive.org/md5/406733548F67B770B962DA4756270D5F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：调试和故障排除

“如果调试是消除软件错误的过程，那么编程一定是引入错误的过程。”- Edsger W. Dijkstra

在专业程序员的生活中，调试和故障排除占据了相当大的时间。即使你在人类编写的最美丽的代码库上工作，仍然会有错误；这是肯定的。

在我的观点中，一个优秀的软件开发人员是一个即使在阅读没有报告错误或错误的代码时也能保持高度关注的人。

能够高效快速地调试代码是每个程序员都需要不断提高的技能。有些人认为因为他们已经阅读了手册，所以没问题，但现实是，游戏中的变量数量如此之大，以至于没有手册。有一些指导方针可以遵循，但没有一本魔法书会教你所有你需要知道的东西，以便成为这方面的专家。

在这个特定的主题上，我觉得我从同事那里学到了最多。观察一个非常熟练的人攻击问题让我感到惊讶。我喜欢看到他们采取的步骤，验证排除可能的原因，以及他们考虑嫌疑人的方式，最终导致他们找到解决方案。

我们与之合作的每个同事都可以教给我们一些东西，或者用一个最终证明是正确的奇妙猜测让我们感到惊讶。当这种情况发生时，不要只停留在惊讶中（或者更糟糕的是嫉妒），而是抓住这一刻，问问他们是如何猜到的，以及为什么。答案将让你看到是否有一些东西你可以后来深入研究，也许下一次，你就是那个发现问题的人。

有些错误很容易发现。它们是由粗心的错误造成的，一旦你看到这些错误的影响，很容易找到解决问题的方法。

但还有其他一些错误要微妙得多，更加难以捉摸，需要真正的专业知识，以及大量的创造力和超越常规的思维来处理。

对我来说，最糟糕的是那些不确定的错误。有时会发生，有时不会。有些只在环境 A 中发生，但在环境 B 中却没有，尽管 A 和 B 应该是完全相同的。这些错误是真正邪恶的，它们会让你发疯。

当然，错误不仅仅发生在沙盒中，对吧？当你的老板告诉你，“别担心！花点时间解决这个问题。先吃午饭！”的时候，不。它们发生在星期五下午五点半，当你的大脑已经烧坏，你只想回家的时候。就在那些每个人都在瞬间变得沮丧的时刻，当你的老板在你身边喘着气的时候，你必须能够保持冷静。我是认真的。如果你让自己的大脑感到紧张，那么创造性思维、逻辑推理以及你在那一刻所需要的一切都会消失。所以深呼吸，端正坐姿，集中注意力。

在这一章中，我将尝试演示一些有用的技术，根据错误的严重程度，以及一些建议，希望能够增强你对错误和问题的解决能力。

具体来说，我们将看一下以下内容：

+   调试技术

+   性能分析

+   断言

+   故障排除指南

# 调试技术

在这部分，我将向你介绍最常见的技术，我经常使用的技术；但是，请不要认为这个列表是详尽无遗的。

# 使用打印进行调试

这可能是所有技术中最简单的技术。它并不是非常有效，不能在所有地方使用，需要同时访问源代码和一个能运行它的终端（因此显示`print`函数调用结果）。

然而，在许多情况下，这仍然是一种快速和有用的调试方式。例如，如果你正在开发一个 Django 网站，页面上发生的情况与你的预期不符，你可以在视图中填充打印，并在重新加载页面时留意控制台。当你在代码中散布调用`print`时，通常会出现这样的情况，你会重复大量的调试代码，要么是因为你正在打印时间戳（就像我们在测量列表推导和生成器的速度时所做的那样），要么是因为你不得不以某种方式构建一个你想要显示的字符串。

另一个问题是，在你的代码中很容易忘记调用`print`。

因此，出于这些原因，我有时候更喜欢编写自定义函数，而不是直接调用`print`。让我们看看如何做。

# 使用自定义函数进行调试

在一个片段中有一个自定义函数，你可以快速抓取并粘贴到代码中，然后用于调试，这是非常有用的。如果你很快，你总是可以即兴编写一个。重要的是以一种不会在最终删除调用和定义时留下东西的方式编写它。因此*以一种完全自包含的方式编写它是很重要的*。这个要求的另一个很好的理由是它将避免与代码的其余部分潜在的名称冲突。

让我们看一个这样的函数的例子：

```py
# custom.py
def debug(*msg, print_separator=True):
    print(*msg)
    if print_separator:
        print('-' * 40)

debug('Data is ...')
debug('Different', 'Strings', 'Are not a problem')
debug('After while loop', print_separator=False)
```

在这种情况下，我使用了一个仅限关键字的参数，以便能够打印一个分隔符，这是一个由`40`个破折号组成的行。

这个函数非常简单。我只是将`msg`中的任何内容重定向到对`print`的调用，如果`print_separator`为`True`，我会打印一条分隔线。运行代码将显示以下内容：

```py
$ python custom.py
Data is ...
----------------------------------------
Different Strings Are not a problem
----------------------------------------
After while loop
```

正如你所看到的，最后一行后面没有分隔符。

这只是一种简单的方法，以某种方式增强对`print`函数的简单调用。让我们看看如何利用 Python 的一个棘手特性来计算调用之间的时间差：

```py
# custom_timestamp.py
from time import sleep

def debug(*msg, timestamp=[None]):
    print(*msg)
    from time import time  # local import
    if timestamp[0] is None:
        timestamp[0] = time()  #1
    else:
        now = time()
        print(
            ' Time elapsed: {:.3f}s'.format(now - timestamp[0])
        )
        timestamp[0] = now  #2

debug('Entering nasty piece of code...')
sleep(.3)
debug('First step done.')
sleep(.5)
debug('Second step done.')
```

这有点棘手，但仍然相当简单。首先，注意我们从`debug`函数内部的`time`模块中导入`time`函数。这使我们避免了在函数外部添加该导入，也许会忘记在那里添加。

看一下我是如何定义`timestamp`的。当然，它是一个列表，但这里重要的是它是一个**可变**对象。这意味着当 Python 解析函数时，它将被设置，并且在不同的调用中保留其值。因此，如果我们在每次调用后都放一个时间戳，我们就可以跟踪时间，而不必使用外部全局变量。我从我的**闭包**研究中借鉴了这个技巧，我鼓励你去了解一下，因为它非常有趣。

好了，所以，在打印出我们必须打印的任何消息和一些导入时间之后，我们检查`timestamp`中的唯一项的内容。如果它是`None`，我们没有先前的引用，因此我们将值设置为当前时间（`#1`）。

另一方面，如果我们有一个先前的引用，我们可以计算一个差值（我们很好地格式化为三个小数位），然后我们最终再次将当前时间放入`timestamp`（`#2`）。这是一个很好的技巧，不是吗？

运行这段代码会显示以下结果：

```py
$ python custom_timestamp.py
Entering nasty piece of code...
First step done.
 Time elapsed: 0.304s
Second step done.
 Time elapsed: 0.505s
```

无论你的情况如何，拥有一个像这样的自包含函数可能非常有用。

# 检查回溯

我们在第八章中简要讨论了回溯，*测试、分析和处理异常*，当我们看到了几种不同类型的异常。回溯提供了关于应用程序出了什么问题的信息。阅读它是有帮助的，所以让我们看一个小例子：

```py
# traceback_simple.py
d = {'some': 'key'}
key = 'some-other'
print(d[key])
```

我们有一个字典，我们尝试访问其中不存在的键。你应该记住这将引发一个`KeyError`异常。让我们运行代码：

```py
$ python traceback_simple.py
Traceback (most recent call last):
 File "traceback_simple.py", line 3, in <module>
 print(d[key])
KeyError: 'some-other'
```

您可以看到我们获得了所有需要的信息：模块名称，导致错误的行（数字和指令），以及错误本身。有了这些信息，您可以返回到源代码并尝试理解发生了什么。

现在让我们创建一个更有趣的例子，基于此构建，并练习 Python 3 中才有的一个特性。假设我们正在验证一个字典，处理必填字段，因此我们希望它们存在。如果没有，我们需要引发一个自定义的`ValidationError`，我们将在运行验证器的过程中进一步捕获它（这里没有显示，所以它可能是任何东西）。应该是这样的：

```py
# traceback_validator.py
class ValidatorError(Exception):
    """Raised when accessing a dict results in KeyError. """

d = {'some': 'key'}
mandatory_key = 'some-other'
try:
    print(d[mandatory_key])
except KeyError as err:
    raise ValidatorError(
        f'`{mandatory_key}` not found in d.'
    ) from err
```

我们定义了一个自定义异常，当必需的键不存在时会引发该异常。请注意，它的主体由其文档字符串组成，因此我们不需要添加任何其他语句。

非常简单，我们定义了一个虚拟字典，并尝试使用`mandatory_key`访问它。当发生`KeyError`时，我们捕获并引发`ValidatorError`。我们通过使用 Python 3 中由 PEP 3134（[`www.python.org/dev/peps/pep-3134/`](https://www.python.org/dev/peps/pep-3134/)）引入的`raise ... from ...`语法来实现这一点，以链接异常。这样做的目的是，我们可能还想在其他情况下引发`ValidatorError`，不一定是由于缺少必需的键而引起的。这种技术允许我们在一个简单的`try`/`except`中运行验证，只关心`ValidatorError`。

如果不能链接异常，我们将丢失关于`KeyError`的信息。代码产生了这个结果：

```py
$ python traceback_validator.py
Traceback (most recent call last):
 File "traceback_validator.py", line 7, in <module>
 print(d[mandatory_key])
KeyError: 'some-other'

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
 File "traceback_validator.py", line 10, in <module>
 '`{}` not found in d.'.format(mandatory_key)) from err
__main__.ValidatorError: `some-other` not found in d.
```

这很棒，因为我们可以看到导致我们引发`ValidationError`的异常的回溯，以及`ValidationError`本身的回溯。

我和我的一位审阅者就`pip`安装程序产生的回溯进行了很好的讨论。他在设置一切以便审查第十三章 *数据科学*的代码时遇到了麻烦。他的新的 Ubuntu 安装缺少一些`pip`软件包所需的库，以便正确运行。

他被阻止的原因是，他试图修复回溯中显示的错误，从顶部开始。我建议他从底部开始，然后修复。原因是，如果安装程序已经到达最后一行，我猜在那之前，无论发生了什么错误，仍然有可能从中恢复。只有在最后一行之后，`pip`决定无法继续下去，因此我开始修复那个错误。一旦安装了修复该错误所需的库，其他一切都顺利进行。

阅读回溯可能会很棘手，我的朋友缺乏解决这个问题所需的经验。因此，如果您也遇到了同样的情况。不要灰心，试着摇动一下，不要想当然。

Python 有一个庞大而美妙的社区，很少有可能当您遇到问题时，您是第一个遇到它的人，所以打开浏览器并搜索。通过这样做，您的搜索技能也会得到提高，因为您将不得不将错误减少到最小但必要的详细信息集，以使您的搜索有效。

如果您想更好地玩耍和理解回溯，标准库中有一个模块可以使用，惊喜惊喜，名为`traceback`。它提供了一个标准接口，用于提取、格式化和打印 Python 程序的堆栈跟踪，模仿 Python 解释器在打印堆栈跟踪时的行为。

# 使用 Python 调试器

调试 Python 的另一个非常有效的方法是使用 Python 调试器：`pdb`。不过，您应该绝对检查`pdbpp`库，而不是直接使用它。`pdbpp`通过提供一些方便的工具来增强标准的`pdb`接口，其中我最喜欢的是**粘性模式**，它允许您在逐步执行其指令时查看整个函数。

有几种不同的使用调试器的方法（无论哪个版本，都不重要），但最常见的一种方法是简单地设置一个断点并运行代码。当 Python 达到断点时，执行将被暂停，并且您可以访问该点的控制台，以便您可以检查所有名称等。您还可以即时更改数据以改变程序的流程。

作为一个玩具示例，假设我们有一个解析器，因为字典中缺少一个键而引发`KeyError`。字典来自我们无法控制的 JSON 有效负载，我们只是想暂时欺骗并通过控制，因为我们对之后发生的事情感兴趣。让我们看看我们如何能拦截这一刻，检查数据，修复它，并深入了解，使用`pdbpp`：

```py
# pdebugger.py
# d comes from a JSON payload we don't control
d = {'first': 'v1', 'second': 'v2', 'fourth': 'v4'}
# keys also comes from a JSON payload we don't control
keys = ('first', 'second', 'third', 'fourth')

def do_something_with_value(value):
    print(value)

for key in keys:
    do_something_with_value(d[key])

print('Validation done.')
```

正如您所看到的，当`key`获得`'third'`值时，代码将中断，这个值在字典中缺失。请记住，我们假装`d`和`keys`都是动态来自我们无法控制的 JSON 有效负载，因此我们需要检查它们以修复`d`并通过`for`循环。如果我们按原样运行代码，我们会得到以下结果：

```py
$ python pdebugger.py
v1
v2
Traceback (most recent call last):
 File "pdebugger.py", line 10, in <module>
 do_something_with_value(d[key])
KeyError: 'third'
```

所以我们看到字典中缺少`key`，但由于每次运行此代码时我们可能会得到不同的字典或`keys`元组，这些信息并不能真正帮助我们。让我们在`for`循环之前注入一个`pdb`调用。您有两个选择：

```py
import pdb
pdb.set_trace()
```

这是最常见的方法。您导入`pdb`并调用其`set_trace`方法。许多开发人员在其编辑器中有宏，可以通过键盘快捷键添加此行。不过，从 Python 3.7 开始，我们甚至可以进一步简化事情，变成这样：

```py
breakpoint()
```

新的`breakpoint`内置函数在底层调用`sys.breakpointhook()`，默认情况下编程为调用`pdb.set_trace()`。但是，您可以重新编程`sys.breakpointhook()`来调用任何您想要的东西，因此`breakpoint`也将指向那个东西，这非常方便。

此示例的代码位于`pdebugger_pdb.py`模块中。如果我们现在运行此代码，事情变得有趣起来（请注意，您的输出可能会有所不同，本输出中的所有注释都是我添加的）：

```py
$ python pdebugger_pdb.py
(Pdb++) l
 16
 17 -> for key in keys:  # breakpoint comes in
 18 do_something_with_value(d[key])
 19

(Pdb++) keys  # inspecting the keys tuple
('first', 'second', 'third', 'fourth')
(Pdb++) d.keys()  # inspecting keys of `d`
dict_keys(['first', 'second', 'fourth'])
(Pdb++) d['third'] = 'placeholder'  # add tmp placeholder
(Pdb++) c  # continue
v1
v2
placeholder
v4
Validation done.
```

首先，请注意，当您达到断点时，会收到一个控制台，告诉您您所在的位置（Python 模块）以及下一行要执行的行。在这一点上，您可以执行一系列的探索性操作，比如检查下一行之前和之后的代码，打印堆栈跟踪，并与对象交互。请参考官方 Python 文档（[`docs.python.org/3.7/library/pdb.html`](https://docs.python.org/3.7/library/pdb.html)）上的`pdb`，了解更多信息。在我们的例子中，我们首先检查`keys`元组。之后，我们检查`d`的键。我们发现`'third'`缺失了，所以我们自己放进去（这可能危险—想一想）。最后，现在所有的键都在了，我们输入`c`，表示（*c*）继续。

`pdb`还可以让您逐行执行代码，使用（*n*）下一步，深入分析函数，或使用（*b*）断点处理。有关命令的完整列表，请参考文档或在控制台中输入（*h*）帮助。

您可以看到，从前面的运行输出中，我们最终可以到达验证的结尾。

`pdb`（或`pdbpp`）是我每天都使用的宝贵工具。所以，去玩耍吧，设置一个断点，尝试检查它，按照官方文档尝试在您的代码中使用命令，看看它们的效果并好好学习。

请注意，在此示例中，我假设您已安装了`pdbpp`。如果不是这样，那么您可能会发现一些命令在`pdb`中不起作用。一个例子是字母`d`，在`pdb`中会被解释为*down*命令。为了解决这个问题，您需要在`d`前面加上`!`，告诉`pdb`它应该被字面解释，而不是作为命令。

# 检查日志文件

调试一个行为异常的应用程序的另一种方法是检查其日志文件。**日志文件**是特殊的文件，应用程序会在其中记录各种事情，通常与其内部发生的事情有关。如果重要的过程开始了，我通常期望在日志中有相应的记录。当它结束时也是一样，可能还有它内部发生的事情。

错误需要被记录下来，这样当出现问题时，我们可以通过查看日志文件中的信息来检查出错的原因。

在 Python 中有许多不同的设置记录器的方法。日志记录非常灵活，可以进行配置。简而言之，通常有四个角色：记录器、处理程序、过滤器和格式化程序：

+   **记录器**：公开应用程序代码直接使用的接口

+   **处理程序**：将日志记录（由记录器创建）发送到适当的目的地

+   **过滤器**：提供了一个更精细的设施，用于确定要输出哪些日志记录

+   **格式化程序**：指定最终输出中日志记录的布局

记录是通过调用`Logger`类的实例的方法来执行的。您记录的每一行都有一个级别。通常使用的级别有：`DEBUG`、`INFO`、`WARNING`、`ERROR`和`CRITICAL`。您可以从`logging`模块中导入它们。它们按严重程度排序，正确使用它们非常重要，因为它们将帮助您根据您要搜索的内容过滤日志文件的内容。日志文件通常变得非常庞大，因此将其中的信息正确地写入非常重要，这样在需要时您可以快速找到它。

您可以记录到文件，也可以记录到网络位置，队列，控制台等。一般来说，如果您的架构部署在一台机器上，记录到文件是可以接受的，但当您的架构跨越多台机器（比如面向服务或微服务架构的情况下），实现一个集中的日志记录解决方案非常有用，这样每个服务产生的所有日志消息都可以存储和调查在一个地方。否则，尝试从几个不同来源的巨大文件中找出问题发生了什么可能会变得非常具有挑战性。

**面向服务的架构**（SOA）是软件设计中的一种架构模式，其中应用程序组件通过通信协议向其他组件提供服务，通常通过网络。这个系统的美妙之处在于，当编写正确时，每个服务都可以用最合适的语言来实现其目的。唯一重要的是与其他服务的通信，这需要通过一个共同的格式进行，以便进行数据交换。

**微服务架构**是 SOA 的演变，但遵循一组不同的架构模式。

在这里，我将向您介绍一个非常简单的日志记录示例。我们将向文件记录一些消息：

```py
# log.py
import logging

logging.basicConfig(
    filename='ch11.log',
    level=logging.DEBUG,  # minimum level capture in the file
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p')

mylist = [1, 2, 3]
logging.info('Starting to process `mylist`...')

for position in range(4):
    try:
        logging.debug(
            'Value at position %s is %s', position, mylist[position]
        )
    except IndexError:
        logging.exception('Faulty position: %s', position)

logging.info('Done parsing `mylist`.')
```

让我们逐行进行。首先，我们导入`logging`模块，然后设置基本配置。一般来说，生产日志配置比这复杂得多，但我想尽可能简单。我们指定一个文件名，我们想要在文件中捕获的最低日志级别，以及消息格式。我们将记录日期和时间信息、级别和消息。

我将从记录一个告诉我我们即将处理列表的`info`消息开始。然后，我将记录（这次使用`DEBUG`级别，使用`debug`函数）某个位置的值。我在这里使用`debug`，因为我希望能够在将来过滤这些日志（通过将最低级别设置为`logging.INFO`或更高），因为我可能必须处理非常大的列表，而我不想记录所有的值。

如果我们得到`IndexError`（我们确实得到了，因为我正在循环遍历`range(4)`），我们调用`logging.exception()`，它与`logging.error()`相同，但还会打印出回溯。

在代码的结尾，我记录了另一个`info`消息，说我们已经完成了。结果是这样的：

```py
# ch11.log
[05/06/2018 11:13:48 AM] INFO:Starting to process `mylist`...
[05/06/2018 11:13:48 AM] DEBUG:Value at position 0 is 1
[05/06/2018 11:13:48 AM] DEBUG:Value at position 1 is 2
[05/06/2018 11:13:48 AM] DEBUG:Value at position 2 is 3
[05/06/2018 11:13:48 AM] ERROR:Faulty position: 3
Traceback (most recent call last):
  File "log.py", line 15, in <module>
    position, mylist[position]))
IndexError: list index out of range
[05/06/2018 11:13:48 AM] INFO:Done parsing `mylist`.
```

这正是我们需要的，可以调试在服务器上运行而不是在我们的控制台上运行的应用程序。我们可以看到发生了什么，引发的任何异常的回溯等等。

这里介绍的示例只是日志记录的皮毛。要获得更深入的解释，您可以在官方 Python 文档的*Python HOWTOs*部分找到信息：*日志记录 HOWTO*和*日志记录 Cookbook*。

日志记录是一门艺术。您需要在记录所有内容和不记录任何内容之间找到一个良好的平衡。理想情况下，您应该记录任何需要确保应用程序正常工作的内容，以及可能的所有错误或异常。

# 其他技术

在这最后一节中，我想简要演示一些您可能会发现有用的技术。

# 分析

我们在第八章中讨论了分析，*测试、分析和处理异常*，我在这里提到它只是因为分析有时可以解释由于组件过慢而导致的奇怪错误。特别是涉及网络时，了解应用程序需要经历的时间和延迟非常重要，以便在出现问题时了解可能发生了什么，因此我建议您熟悉分析技术，也从故障排除的角度来看。

# 断言

断言是确保代码验证您的假设的一种好方法。如果是，一切都会正常进行，但如果不是，您会得到一个很好的异常，可以处理。有时，与其检查，不如在代码中放置一些断言来排除可能性更快。让我们看一个例子：

```py
# assertions.py
mylist = [1, 2, 3]  # this ideally comes from some place
assert 4 == len(mylist)  # this will break
for position in range(4):
    print(mylist[position])
```

这段代码模拟了一个情况，即`mylist`并非由我们定义，但我们假设它有四个元素。因此我们在那里放置了一个断言，结果是这样的：

```py
$ python assertions.py
Traceback (most recent call last):
 File "assertions.py", line 3, in <module>
 assert 4 == len(mylist)  # this will break
AssertionError
```

这告诉我们问题出在哪里。

# 查找信息的位置

在 Python 官方文档中，有一个专门介绍调试和分析的部分，您可以在那里了解`bdb`调试器框架，以及诸如`faulthandler`、`timeit`、`trace`、`tracemallock`和当然`pdb`等模块。只需转到文档中的标准库部分，您就可以非常容易地找到所有这些信息。

# 故障排除指南

在这个简短的部分中，我想给您一些建议，这些建议来自我的故障排除经验。

# 使用控制台编辑器

首先，要熟练使用**Vim**或**nano**作为编辑器，并学习控制台的基础知识。当事情出错时，您就没有您的编辑器带来的所有便利了。您必须连接到服务器并从那里工作。因此，熟练使用控制台命令浏览生产环境，并能够使用基于控制台的编辑器编辑文件，比如 vi、Vim 或 nano，是一个非常好的主意。不要让您通常的开发环境宠坏了您。

# 检查的位置

我的第二个建议涉及在哪里放置调试断点。无论您使用`print`、自定义函数还是`pdb`，您仍然必须选择在哪里放置提供信息的调用，对吧？

有些地方比其他地方更好，有些处理调试进展的方法比其他方法更好。

我通常不会在`if`子句中设置断点，因为如果该子句没有执行，我就失去了获取所需信息的机会。有时很难或很快到达断点，所以在设置断点之前请仔细考虑。

另一件重要的事情是从哪里开始。想象一下，您有 100 行代码来处理您的数据。数据从第 1 行进入，但在第 100 行出现错误。您不知道错误在哪里，那么该怎么办呢？您可以在第 1 行设置断点，耐心地检查所有行，检查您的数据。在最坏的情况下，99 行（和许多杯咖啡）后，您找到了错误。因此，请考虑使用不同的方法。

您从第 50 行开始，然后进行检查。如果数据正常，这意味着错误发生在后面，这种情况下，您将在第 75 行设置下一个断点。如果第 50 行的数据已经出错，您将在第 25 行设置断点。然后，您重复这个过程。每次，您要么向后移动，要么向前移动，跳过上次的一半。

在最坏的情况下，您的调试将从 1、2、3、...、99 以线性方式进行，变成一系列跳跃，如 50、75、87、93、96、...、99，速度要快得多。事实上，这是对数的。这种搜索技术称为**二分搜索**，它基于分而治之的方法，非常有效，因此请尽量掌握它。

# 使用测试进行调试

您还记得第八章吗，*测试、性能分析和处理异常*，关于测试？如果我们有一个错误，而所有测试都通过了，这意味着我们的测试代码库中有问题或遗漏。因此，一种方法是修改测试，以便它们适应已经发现的新边缘情况，然后逐步检查代码。这种方法非常有益，因为它确保在修复错误时，您的错误将被测试覆盖。

# 监控

监控也非常重要。软件应用程序可能会在遇到边缘情况时变得完全疯狂，并且在网络中断、队列已满或外部组件无响应等情况下出现非确定性的故障。在这些情况下，重要的是要了解问题发生时的整体情况，并能够以微妙、甚至神秘的方式将其与相关的内容联系起来。

您可以监视 API 端点、进程、网页可用性和加载时间，基本上几乎可以监视您可以编码的所有内容。一般来说，从头开始设计应用程序时，考虑如何监视它可能非常有用。

# 总结

在这个简短的章节中，我们探讨了不同的调试和故障排除技术和建议。调试是软件开发人员工作中始终存在的活动，因此擅长调试非常重要。

如果以正确的态度对待，调试可以是有趣和有益的。

我们探讨了检查我们的代码库的技术，包括函数、日志记录、调试器、回溯信息、性能分析和断言。我们看到了它们大部分的简单示例，我们还谈到了一套指导方针，将在面对困难时提供帮助。

只要记住始终保持*冷静和专注*，调试就会变得更容易。这也是一种需要学习的技能，也是最重要的。激动和紧张的心态无法正常、逻辑和创造性地工作，因此，如果您不加强它，很难将所有知识充分利用。

在下一章中，我们将探讨 GUI 和脚本，从更常见的 Web 应用程序场景中进行有趣的偏离。


# 第十二章：GUI 和脚本

“用户界面就像一个笑话。如果你不得不解释它，那就不是那么好。”– Martin LeBlanc

在本章中，我们将一起开展一个项目。我们将编写一个简单的抓取器，用于查找和保存网页中的图像。我们将专注于三个部分：

+   Python 中的简单 HTTP 网络服务器

+   一个用于抓取给定 URL 的脚本

+   一个 GUI 应用程序，用于抓取给定 URL

**图形用户界面**（**GUI**）是一种允许用户通过图形图标、按钮和小部件与电子设备进行交互的界面类型，与需要在键盘上键入命令或文本的基于文本或命令行的界面相对。简而言之，任何浏览器，任何办公套件（如 LibreOffice）以及一般情况下，任何在单击图标时弹出的东西都是 GUI 应用程序。

因此，如果您还没有这样做，现在是在名为`ch12`的文件夹中的项目根目录中启动控制台并定位的绝佳时机。在该文件夹中，我们将创建两个 Python 模块（`scrape.py`和`guiscrape.py`）和一个文件夹（`simple_server`）。在`simple_server`中，我们将编写我们的 HTML 页面：`index.html`。图像将存储在`simple_server/img`中。

`ch12`中的结构应该是这样的：

```py
$ tree -A
.
├── guiscrape.py
├── scrape.py
└── simple_server
 ├── img
 │ ├── owl-alcohol.png
 │ ├── owl-book.png
 │ ├── owl-books.png
 │ ├── owl-ebook.jpg
 │ └── owl-rose.jpeg
 ├── index.html
 └── serve.sh
```

如果您使用的是 Linux 或 macOS，您可以像我一样将启动 HTTP 服务器的代码放在一个名为`serve.sh`的文件中。在 Windows 上，您可能想使用批处理文件。

我们要抓取的 HTML 页面具有以下结构：

```py
# simple_server/index.html
<!DOCTYPE html>
<html lang="en">
  <head><title>Cool Owls!</title></head>
  <body>
    <h1>Welcome to my owl gallery</h1>
    <div>
      <img src="img/owl-alcohol.png" height="128" />
      <img src="img/owl-book.png" height="128" />
      <img src="img/owl-books.png" height="128" />
      <img src="img/owl-ebook.jpg" height="128" />
      <img src="img/owl-rose.jpeg" height="128" />
    </div>
    <p>Do you like my owls?</p>
  </body>
</html>
```

这是一个非常简单的页面，所以我们只需要注意一下，我们有五张图片，其中三张是 PNG 格式，两张是 JPG 格式（请注意，尽管它们都是 JPG 格式，但一张以`.jpg`结尾，另一张以`.jpeg`结尾，这两种都是此格式的有效扩展名）。

因此，Python 为您提供了一个非常简单的免费 HTTP 服务器，您可以使用以下命令启动它（在`simple_server`文件夹中）：

```py
$ python -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
127.0.0.1 - - [06/May/2018 16:54:30] "GET / HTTP/1.1" 200 -
...
```

最后一行是当您访问`http://localhost:8000`时得到的日志，我们美丽的页面将在那里提供。或者，您可以将该命令放在一个名为`serve.sh`的文件中，并使用以下命令运行它（确保它是可执行的）：

```py
$ ./serve.sh
```

它将产生相同的效果。如果您有本书的代码，您的页面应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00012.jpeg)

随意使用任何其他图像集，只要您至少使用一个 PNG 和一个 JPG，并且在`src`标签中使用相对路径而不是绝对路径。我从[`openclipart.org/`](https://openclipart.org/)获取了这些可爱的猫头鹰。

# 第一种方法 - 脚本

现在，让我们开始编写脚本。我将分三步讲解源代码：导入、解析参数和业务逻辑。

# 导入

脚本的开始部分如下：

```py
# scrape.py
import argparse
import base64
import json
import os
from bs4 import BeautifulSoup
import requests
```

从顶部开始浏览它们，您会发现我们需要解析参数，然后将其提供给脚本本身（`argparse`）。我们将需要`base64`库来将图像保存在 JSON 文件中（`json`），并且我们需要打开文件进行写入（`os`）。最后，我们需要`BeautifulSoup`来轻松抓取网页，以及`requests`来获取其内容。我假设您熟悉`requests`，因为我们在之前的章节中使用过它。

我们将在《第十四章》*Web Development*中探讨 HTTP 协议和`requests`机制，所以现在，让我们简单地说，我们执行一个 HTTP 请求来获取网页的内容。我们可以使用库（如`requests`）以编程方式执行此操作，这更或多是相当于在浏览器中输入 URL 并按下*Enter*（然后浏览器获取网页内容并将其显示给您）。

所有这些导入中，只有最后两个不属于 Python 标准库，所以请确保您已经安装了它们：

```py
$ pip freeze | egrep -i "soup|requests"
beautifulsoup4==4.6.0
requests==2.18.4
```

当然，版本号可能对您来说是不同的。如果它们没有安装，请使用此命令进行安装：

```py
$ pip install beautifulsoup4==4.6.0 requests==2.18.4
```

在这一点上，我认为可能会让您困惑的唯一事情是`base64/json`对，所以请允许我花几句话来解释。

正如我们在上一章中看到的，JSON 是应用程序之间数据交换的最流行格式之一。它也被广泛用于其他目的，例如在文件中保存数据。在我们的脚本中，我们将为用户提供将图像保存为图像文件或 JSON 单个文件的功能。在 JSON 中，我们将放置一个字典，其中键是图像名称，值是它们的内容。唯一的问题是以二进制格式保存图像很棘手，这就是`base64`库发挥作用的地方。

`base64`库实际上非常有用。例如，每次您发送带有附加图像的电子邮件时，图像在发送电子邮件之前都会使用`base64`进行编码。在接收方端，图像会自动解码为其原始二进制格式，以便电子邮件客户端可以显示它们。

# 解析参数

既然技术问题已经解决，让我们看看我们脚本的第二部分（应该在`scrape.py`模块的末尾）：

```py
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Scrape a webpage.')
    parser.add_argument(
        '-t',
        '--type',
        choices=['all', 'png', 'jpg'],
        default='all',
        help='The image type we want to scrape.')
    parser.add_argument(
        '-f',
        '--format',
        choices=['img', 'json'],
        default='img',
        help='The format images are _saved to.')
    parser.add_argument(
        'url',
        help='The URL we want to scrape for images.')
    args = parser.parse_args()
    scrape(args.url, args.format, args.type)
```

看看第一行；这是脚本编写时非常常见的习语。根据官方 Python 文档，`'__main__'`字符串是顶层代码执行的范围名称。当从标准输入、脚本或交互式提示中读取时，模块的`__name__`被设置为`'__main__'`。

因此，如果您将执行逻辑放在`if`下面，它将仅在直接运行脚本时运行，因为其`__name__`将为`'__main__'`。另一方面，如果您从此模块导入，则其名称将设置为其他内容，因此`if`下的逻辑将不会运行。

我们要做的第一件事是定义我们的解析器。我建议使用标准库模块`argparse`，它足够简单且功能强大。还有其他选择，但在这种情况下，`argparse`将为我们提供所需的一切。

我们希望向我们的脚本提供三种不同的数据：我们要保存的图像类型，我们要保存它们的格式以及要抓取的页面的 URL。

类型可以是 PNG、JPG 或两者（默认），而格式可以是图像或 JSON，图像是默认值。URL 是唯一的强制参数。

因此，我们添加了`-t`选项，还允许长版本`--type`。选择是`'all'`，`'png'`和`'jpg'`。我们将默认设置为`'all'`并添加一个`help`消息。

我们对`format`参数执行类似的过程，允许使用短语法和长语法（`-f`和`--format`），最后我们添加`url`参数，这是唯一一个以不同方式指定的参数，因此它不会被视为选项，而是作为位置参数。

为了解析所有参数，我们只需要`parser.parse_args()`。非常简单，不是吗？

最后一行是我们触发实际逻辑的地方，通过调用`scrape`函数，传递我们刚刚解析的所有参数。我们很快将看到它的定义。`argparse`的好处是，如果通过传递`-h`调用脚本，它将自动为您打印一个漂亮的使用文本。让我们试一试：

```py
$ python scrape.py -h
usage: scrape.py [-h] [-t {all,png,jpg}] [-f {img,json}] url

Scrape a webpage.

positional arguments:
 url The URL we want to scrape for images.

```

```py
optional arguments:
 -h, --help show this help message and exit
 -t {all,png,jpg}, --type {all,png,jpg}
 The image type we want to scrape.
 -f {img,json}, --format {img,json}
 The format images are _saved to.
```

如果您仔细考虑一下，这样做的真正优势在于我们只需要指定参数，而不必担心使用文本，这意味着我们不必在每次更改内容时保持与参数定义同步。这是非常宝贵的。

以下是调用我们的`scrape.py`脚本的几种不同方式，演示了`type`和`format`是可选的，以及如何使用短语法和长语法来使用它们：

```py
$ python scrape.py http://localhost:8000
$ python scrape.py -t png http://localhost:8000
$ python scrape.py --type=jpg -f json http://localhost:8000
```

第一个是使用`type`和`format`的默认值。第二个将仅保存 PNG 图像，第三个将仅保存 JPG 图像，但以 JSON 格式保存。

# 业务逻辑

现在我们已经看到了脚手架，让我们深入到实际的逻辑中（如果看起来令人生畏，不要担心；我们会一起学习）。在脚本中，这个逻辑位于导入之后和解析之前（在`if __name__`子句之前）。

```py
def scrape(url, format_, type_):
    try:
        page = requests.get(url)
    except requests.RequestException as err:
        print(str(err))
    else:
        soup = BeautifulSoup(page.content, 'html.parser')
        images = _fetch_images(soup, url)
        images = _filter_images(images, type_)
        _save(images, format_)
```

让我们从`scrape`函数开始。它所做的第一件事就是获取给定`url`参数的页面。无论在此过程中可能发生的任何错误，我们都会将其捕获在`RequestException`（`err`）中并打印出来。`RequestException`是`requests`库中所有异常的基本异常类。

然而，如果一切顺利，我们从`GET`请求中得到了一个页面，那么我们可以继续（`else`分支），并将其内容提供给`BeautifulSoup`解析器。`BeautifulSoup`库允许我们在很短的时间内解析网页，而不必编写查找页面上所有图像所需的所有逻辑，这是我们真的不想做的。这并不像看起来那么容易，重新发明轮子从来都不是好事。为了获取图像，我们使用`_fetch_images`函数，并用`_filter_images`对它们进行过滤。最后，我们调用`_save`来保存结果。

将代码分割成不同的函数并赋予有意义的名称，使我们更容易阅读它。即使你没有看到`_fetch_images`、`_filter_images`和`_save`函数的逻辑，也不难预测它们的功能，对吧？看看下面的内容：

```py
def _fetch_images(soup, base_url):
    images = []
    for img in soup.findAll('img'):
        src = img.get('src')
        img_url = f'{base_url}/{src}'
        name = img_url.split('/')[-1]
        images.append(dict(name=name, url=img_url))
    return images
```

`_fetch_images`接受一个`BeautifulSoup`对象和一个基本 URL。它所做的就是循环遍历页面上找到的所有图像，并在一个字典中填写关于它们的`name`和`url`信息（每个图像一个字典）。所有字典都添加到`images`列表中，并在最后返回。

当我们获取图像的名称时，有一些技巧。我们使用`'/'`作为分隔符来分割`img_url`（`http://localhost:8000/img/my_image_name.png`）字符串，并将最后一项作为图像名称。有一种更健壮的方法来做到这一点，但对于这个例子来说，这将是杀鸡用牛刀。如果你想看到每个步骤的细节，请尝试将这个逻辑分解为更小的步骤，并打印每个步骤的结果来帮助你理解。在本书的末尾，我会向你展示另一种更有效的调试技术。

无论如何，只需在`_fetch_images`函数的末尾添加`print(images)`，我们就得到了这个：

```py
[{'url': 'http://localhost:8000/img/owl-alcohol.png', 'name': 'owl-alcohol.png'}, {'url': 'http://localhost:8000/img/owl-book.png', 'name': 'owl-book.png'}, ...]  
```

我为了简洁起见截断了结果。你可以看到每个字典都有一个`url`和`name`键/值对，我们可以用它们来获取、识别和保存我们喜欢的图像。此时，我听到你在问，如果页面上的图像是用绝对路径而不是相对路径指定的，会发生什么，对吧？好问题！

答案是脚本将无法下载它们，因为这个逻辑期望相对路径。当我想要添加一点逻辑来解决这个问题时，我想在这个阶段，这将是一个很好的练习，所以我会留给你来解决它。

提示：检查`src`变量的开头。如果以`'http'`开头，那么它可能是一个绝对路径。你可能还想查看`urllib.parse`来做到这一点。

我希望`_filter_images`函数的主体对你有趣。我想向你展示如何使用映射技术来检查多个扩展名：

```py
def _filter_images(images, type_):
    if type_ == 'all':
        return images
    ext_map = {
        'png': ['.png'],
        'jpg': ['.jpg', '.jpeg'],
    }
    return [
        img for img in images
        if _matches_extension(img['name'], ext_map[type_])
    ]

def _matches_extension(filename, extension_list):
    name, extension = os.path.splitext(filename.lower())
    return extension in extension_list
```

在这个函数中，如果`type_`是`all`，那么不需要进行过滤，所以我们只返回所有的图像。另一方面，当`type_`不是`all`时，我们从`ext_map`字典中获取允许的扩展名，并用它来过滤函数体结束的列表推导式中的图像。你可以看到，通过使用另一个辅助函数`_matches_extension`，我使列表推导式更简单、更易读。

`_matches_extension`函数所做的就是分割获取图像扩展名的名称，并检查它是否在允许的列表中。你能找到一个微小的改进（速度方面）可以应用到这个函数吗？

我相信你一定想知道为什么我要将所有图像收集到列表中，然后再删除它们，而不是在将它们添加到列表之前检查是否要保存它们。第一个原因是我现在需要在 GUI 应用程序中使用`_fetch_images`。第二个原因是合并、获取和过滤会产生一个更长更复杂的函数，而我正在尽量降低复杂性。第三个原因是这可能是一个很好的练习给你做：

```py
def _save(images, format_):
    if images:
        if format_ == 'img':
            _save_images(images)
        else:
            _save_json(images)
        print('Done')
    else:
        print('No images to save.')

def _save_images(images):
    for img in images:
        img_data = requests.get(img['url']).content
        with open(img['name'], 'wb') as f:
            f.write(img_data)

def _save_json(images):
    data = {}
    for img in images:
        img_data = requests.get(img['url']).content
        b64_img_data = base64.b64encode(img_data)
        str_img_data = b64_img_data.decode('utf-8')
        data[img['name']] = str_img_data
    with open('images.json', 'w') as ijson:
        ijson.write(json.dumps(data))
```

让我们继续阅读代码并检查`_save`函数。你可以看到，当`images`不为空时，这基本上充当一个调度程序。我们要么调用`_save_images`，要么调用`_save_json`，这取决于`format_`变量中存储的信息。

我们快要完成了。让我们跳到`_save_images`。我们循环遍历`images`列表，对于我们在那里找到的每个字典，我们对图像 URL 执行一个`GET`请求，并将其内容保存在一个文件中，我们将其命名为图像本身。

最后，现在让我们进入`_save_json`函数。它与之前的函数非常相似。我们基本上填充了`data`字典。图像名称是*键*，其二进制内容的 Base64 表示是*值*。当我们完成填充字典时，我们使用`json`库将其转储到`images.json`文件中。我会给你一个小预览：

```py
# images.json (truncated)
{
  "owl-alcohol.png": "iVBORw0KGgoAAAANSUhEUgAAASwAAAEICA...
  "owl-book.png": "iVBORw0KGgoAAAANSUhEUgAAASwAAAEbCAYAA...
  "owl-books.png": "iVBORw0KGgoAAAANSUhEUgAAASwAAAElCAYA...
  "owl-ebook.jpg": "/9j/4AAQSkZJRgABAQEAMQAxAAD/2wBDAAEB...
  "owl-rose.jpeg": "/9j/4AAQSkZJRgABAQEANAA0AAD/2wBDAAEB...
}
```

就是这样！现在，在继续下一部分之前，请确保你玩过这个脚本并了解它是如何工作的。尝试修改一些东西，打印出中间结果，添加一个新的参数或功能，或者打乱逻辑。我们现在将把它迁移到一个 GUI 应用程序中，这将增加一层复杂性，因为我们将不得不构建 GUI 界面，所以熟悉业务逻辑非常重要——这将使你能够集中精力处理代码的其余部分。

# 第二种方法-一个 GUI 应用程序

有几个库可以用 Python 编写 GUI 应用程序。最著名的是**Tkinter**、**wxPython**、**PyGTK**和**PyQt**。它们都提供了各种工具和小部件，可以用来组成 GUI 应用程序。

我将在本章的其余部分中使用 Tkinter。**Tkinter**代表**Tk 界面**，它是 Python 与 Tk GUI 工具包的标准接口。Tk 和 Tkinter 都可以在大多数 Unix 平台、macOS X 以及 Windows 系统上使用。

让我们通过运行这个命令来确保`tkinter`在你的系统上安装正确：

```py
$ python -m tkinter
```

它应该打开一个对话框窗口，展示一个简单的`Tk`界面。如果你能看到它，那就没问题。但是，如果它不起作用，请在 Python 官方文档中搜索`tkinter`（[`docs.python.org/3.7/library/tkinter.html`](https://docs.python.org/3.7/library/tkinter.html)）。你会找到一些资源的链接，这些资源将帮助你快速上手。

我们将制作一个非常简单的 GUI 应用程序，基本上模仿本章第一部分中所见的脚本的行为。我们不会添加单独保存 JPG 或 PNG 的功能，但在你完成本章后，你应该能够玩转代码，并自己加入该功能。

所以，这就是我们的目标：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00013.jpeg)

华丽，不是吗？正如你所看到的，这是一个非常简单的界面（这是在 Mac 上的样子）。有一个框架（即容器）用于 URL 字段和获取信息按钮，另一个框架用于**Listbox**（内容）来保存图像名称和控制保存方式的单选按钮，最后底部有一个抓取按钮。我们还有一个状态栏，它会向我们显示一些信息。

为了获得这种布局，我们可以将所有小部件放在根窗口上，但那样会使布局逻辑变得非常混乱和不必要地复杂。因此，我们将使用框架来划分空间，并将小部件放在这些框架中。这样我们将获得一个更好的结果。所以，这是布局的草案：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00014.jpeg)

我们有一个**根窗口**，它是应用程序的主窗口。我们将它分成两行，第一行放置**主框架**，第二行放置**状态框架**（用于保存状态栏文本）。**主框架**随后被分成三行。在第一行，我们放置**URL 框架**，其中包含**URL**小部件。在第二行，我们放置**Img 框架**，它将包含**Listbox**和**Radio 框架**，后者将承载一个标签和单选按钮小部件。最后我们有第三行，它将只包含**Scrape**按钮。

为了布局框架和小部件，我们将使用一个布局管理器，称为**grid**，它简单地将空间分成行和列，就像矩阵一样。

现在，我要写的所有代码都来自`guiscrape.py`模块，所以我不会为每个片段重复它的名称，以节省空间。该模块在逻辑上分为三个部分，与脚本版本类似：导入、布局逻辑和业务逻辑。我们将逐行分析它们，分为三个部分。

# 导入

导入与脚本版本类似，只是我们失去了`argparse`，它不再需要，并且添加了两行：

```py
# guiscrape.py
from tkinter import * 
from tkinter import ttk, filedialog, messagebox 
...
```

第一行在处理`tkinter`时是相当常见的做法，尽管通常使用`*`语法进行导入是不好的做法*.*你可能会遇到名称冲突，而且如果模块太大，导入所有内容将会很昂贵。

之后，我们明确导入了`ttk`，`filedialog`和`messagebox`，遵循了这个库的常规方法。`ttk`是一组新的样式化小部件。它们基本上的行为与旧的小部件相同，但能够根据操作系统的样式正确地绘制自己，这很好。

其余的导入（已省略）是我们现在所熟知的任务所需的。请注意，在这第二部分中，我们不需要使用`pip`安装任何东西；我们已经拥有了我们需要的一切。

# 布局逻辑

我将逐块粘贴它，这样我可以更容易地向你解释。你会看到我们在布局草案中讨论的所有那些部分是如何排列和粘合在一起的。我将要粘贴的内容，就像我们之前在脚本中所做的那样，是`guiscrape.py`模块的最后部分。我们将最后留下中间部分，也就是业务逻辑：

```py
if __name__ == "__main__":
    _root = Tk()
    _root.title('Scrape app')
```

正如你现在所知，我们只想在模块直接运行时执行逻辑，所以第一行不应该让你感到惊讶。

在最后两行，我们设置了主窗口，它是`Tk`类的一个实例。我们实例化它并给它一个标题。请注意，我使用了`tkinter`对象的所有名称的前置下划线技术，以避免与业务逻辑中的名称潜在冲突。我觉得这样更清晰，但你可以不同意：

```py
    _mainframe = ttk.Frame(_root, padding='5 5 5 5')
    _mainframe.grid(row=0, column=0, sticky=(E, W, N, S))
```

在这里，我们设置了**主框架**。它是一个`ttk.Frame`实例。我们将`_root`设置为它的父级，并给它一些`padding`。`padding`是以像素为单位的度量，用于在内部内容和边框之间插入多少空间，以便让我们的布局有一点空间，否则我们会有一个*沙丁鱼效应*，小部件被过紧地打包在一起。

第二行更有趣。我们将这个`_mainframe`放在父对象`_root`的第一行（`0`）和第一列（`0`）。我们还说这个框架需要在每个方向上扩展自己，使用`sticky`参数和所有四个基本方向。如果你想知道它们是从哪里来的，那就是`from tkinter import *`魔法给我们带来的：

```py
    _url_frame = ttk.LabelFrame(
        _mainframe, text='URL', padding='5 5 5 5')
    _url_frame.grid(row=0, column=0, sticky=(E, W))
    _url_frame.columnconfigure(0, weight=1)
    _url_frame.rowconfigure(0, weight=1)
```

接下来，我们首先放置**URL Frame**。这次，父对象是`_mainframe`，正如您从我们的草图中记得的那样。这不仅仅是一个简单的`Frame`，它实际上是一个`LabelFrame`，这意味着我们可以设置文本参数，并期望在其周围绘制一个矩形，并在其左上部分写入文本参数的内容（如果有必要，请查看上一张图片）。我们将此框架定位在（`0`，`0`），并说它应该向左和向右扩展。我们不需要其他两个方向。

最后，我们使用`rowconfigure`和`columnconfigure`来确保它在需要调整大小时能够正确运行。这只是我们当前布局中的一种形式：

```py
    _url = StringVar()
    _url.set('http://localhost:8000')
    _url_entry = ttk.Entry(
        _url_frame, width=40, textvariable=_url)
    _url_entry.grid(row=0, column=0, sticky=(E, W, S, N), padx=5)
    _fetch_btn = ttk.Button(
        _url_frame, text='Fetch info', command=fetch_url)
    _fetch_btn.grid(row=0, column=1, sticky=W, padx=5)
```

在这里，我们有布局 URL 文本框和`_fetch`按钮的代码。在这种环境中，文本框称为`Entry`。我们像往常一样实例化它，将`_url_frame`设置为其父级并为其设置宽度。而且，这是最有趣的部分，我们将`textvariable`参数设置为`_url`。`_url`是`StringVar`，它是一个现在连接到`Entry`并将用于操作其内容的对象。因此，我们不直接修改`_url_entry`实例中的文本，而是通过访问`_url`。在这种情况下，我们调用其`set`方法将初始值设置为我们本地网页的 URL。

我们将`_url_entry`定位在（`0`，`0`），为其设置了四个基本方向，使其粘附，并且还使用`padx`在左右边缘设置了一些额外的填充，该参数在*x*轴（水平）上添加填充。另一方面，`pady`负责垂直方向。

到目前为止，您应该知道每次在对象上调用`.grid`方法时，我们基本上都在告诉网格布局管理器根据我们在`grid()`调用中指定的规则将该对象放置在某个地方。

类似地，我们设置并放置了`_fetch`按钮。唯一有趣的参数是`command=fetch_url`。这意味着当我们单击此按钮时，我们调用`fetch_url`函数。这种技术称为**回调**：

```py
    _img_frame = ttk.LabelFrame(
        _mainframe, text='Content', padding='9 0 0 0')
    _img_frame.grid(row=1, column=0, sticky=(N, S, E, W))
```

这就是我们在布局草图中称为**Img Frame**的东西。它放置在其父级`_mainframe`的第二行。它将容纳**Listbox**和**Radio Frame**：

```py
    _images = StringVar()
    _img_listbox = Listbox(
        _img_frame, listvariable=_images, height=6, width=25)
    _img_listbox.grid(row=0, column=0, sticky=(E, W), pady=5)
    _scrollbar = ttk.Scrollbar(
        _img_frame, orient=VERTICAL, command=_img_listbox.yview)
    _scrollbar.grid(row=0, column=1, sticky=(S, N), pady=6)
    _img_listbox.configure(yscrollcommand=_scrollbar.set)
```

这可能是整个布局逻辑中最有趣的部分。与`_url_entry`一样，我们需要通过将其绑定到`_images`变量来驱动`Listbox`的内容。我们设置`Listbox`，使`_img_frame`成为其父级，并且`_images`是其绑定的变量。我们还传递了一些尺寸。

有趣的部分来自`_scrollbar`实例。请注意，当我们实例化它时，我们将其命令设置为`_img_listbox.yview`。这是`Listbox`和`Scrollbar`之间的合同的第一部分。另一半由`_img_listbox.configure`方法提供，该方法设置`yscrollcommand=_scrollbar.set`。

通过提供这种相互关系，当我们在`Listbox`上滚动时，`Scrollbar`将相应移动，反之亦然，当我们操作`Scrollbar`时，`Listbox`将相应滚动：

```py
    _radio_frame = ttk.Frame(_img_frame)
    _radio_frame.grid(row=0, column=2, sticky=(N, S, W, E))
```

我们放置**Radio Frame**，准备填充。请注意，`Listbox`占据了`_img_frame`的（`0`，`0`），`Scrollbar`占据了（`0`，`1`），因此`_radio_frame`将放在（`0`，`2`）：

```py
    _choice_lbl = ttk.Label(
        _radio_frame, text="Choose how to save images")
    _choice_lbl.grid(row=0, column=0, padx=5, pady=5)
    _save_method = StringVar()
    _save_method.set('img')
    _img_only_radio = ttk.Radiobutton(
        _radio_frame, text='As Images', variable=_save_method,
        value='img')
    _img_only_radio.grid(
        row=1, column=0, padx=5, pady=2, sticky=W)
    _img_only_radio.configure(state='normal')
    _json_radio = ttk.Radiobutton(
        _radio_frame, text='As JSON', variable=_save_method,
        value='json')
    _json_radio.grid(row=2, column=0, padx=5, pady=2, sticky=W)
```

首先，我们放置标签，并为其添加一些填充。请注意，标签和单选按钮都是`_radio_frame`的子级。

至于`Entry`和`Listbox`对象，`Radiobutton`也受到与外部变量的绑定的影响，我称之为`_save_method`。每个`Radiobutton`实例都设置了一个值参数，通过检查`_save_method`上的值，我们知道

选择哪个按钮：

```py
    _scrape_btn = ttk.Button(
        _mainframe, text='Scrape!', command=save)
    _scrape_btn.grid(row=2, column=0, sticky=E, pady=5)
```

在`_mainframe`的第三行放置**Scrape**按钮。其`command`是`save`，在成功解析网页后，将图像保存到`Listbox`中：

```py
    _status_frame = ttk.Frame(
        _root, relief='sunken', padding='2 2 2 2')
    _status_frame.grid(row=1, column=0, sticky=(E, W, S))
    _status_msg = StringVar()
    _status_msg.set('Type a URL to start scraping...')
    _status = ttk.Label(
        _status_frame, textvariable=_status_msg, anchor=W)
    _status.grid(row=0, column=0, sticky=(E, W))
```

我们通过放置状态框架来结束布局部分，这是一个简单的`ttk.Frame`。为了给它一个小小的状态栏效果，我们将其`relief`属性设置为`'sunken'`，并给它统一的两像素填充。它需要粘附在`_root`窗口的左侧、右侧和底部，因此我们将其`sticky`属性设置为`(E, W, S)`。

然后我们在其中放置一个标签，并且这次我们将其绑定到`StringVar`对象，因为我们每次想要更新状态栏文本时都必须修改它。您现在应该熟悉这种技术了。

最后，在最后一行，我们通过在`Tk`实例上调用`mainloop`方法来运行应用程序：

```py
    _root.mainloop()
```

请记住，所有这些指令都放在原始脚本中的`if __name__ == "__main__":`子句下。

如您所见，设计我们的 GUI 应用程序的代码并不难。当然，在开始时，您必须稍微尝试一下。并不是每件事情都会在第一次尝试时完美无缺，但我向您保证，这非常容易，您可以在网上找到大量的教程。现在让我们来到有趣的部分，业务逻辑。

# 业务逻辑

我们将分析 GUI 应用程序的业务逻辑分为三个部分。有获取逻辑、保存逻辑和警报逻辑。

# 获取网页

让我们从获取页面和图片的代码开始：

```py
config = {}

def fetch_url():
    url = _url.get()
    config['images'] = []
    _images.set(())  # initialised as an empty tuple
    try:
        page = requests.get(url)
    except requests.RequestException as err:
        _sb(str(err))
    else:
        soup = BeautifulSoup(page.content, 'html.parser')
        images = fetch_images(soup, url)
        if images:
            _images.set(tuple(img['name'] for img in images))
            _sb('Images found: {}'.format(len(images)))
        else:
            _sb('No images found')
        config['images'] = images

def fetch_images(soup, base_url):
    images = []
    for img in soup.findAll('img'):
        src = img.get('src')
        img_url = f'{base_url}/{src}'
        name = img_url.split('/')[-1]
        images.append(dict(name=name, url=img_url))
    return images
```

首先，让我解释一下`config`字典。我们需要一种在 GUI 应用程序和业务逻辑之间传递数据的方式。现在，我个人偏好的做法是，不是用许多不同的变量污染全局命名空间，而是使用一个单一的字典，其中包含我们需要来回传递的所有对象，这样全局命名空间就不会被所有这些名称弄得混乱，我们有一个单一、清晰、简单的方式来知道我们应用程序所需的所有对象在哪里。

在这个简单的例子中，我们将`config`字典填充了我们从页面获取的图片，但我想向您展示这种技术，这样您至少有一个例子。这种技术来自于我的 JavaScript 经验。当您编写网页时，通常会导入几种不同的库。如果每个库都用各种变量弄乱了全局命名空间，可能会出现问题，因为名称冲突和变量覆盖的问题。

因此，最好尽量保持全局命名空间的清洁。在这种情况下，我发现使用一个`config`变量是完全可以接受的。

`fetch_url`函数与我们在脚本中所做的非常相似。首先，我们通过调用`_url.get()`来获取`url`的值。请记住，`_url`对象是一个绑定到`_url_entry`对象的`StringVar`实例，后者是一个`Entry`。您在 GUI 上看到的文本字段是`Entry`，但在幕后的文本是`StringVar`对象的值。

通过在`_url`上调用`get()`，我们可以获得文本的值，该值显示在`_url_entry`中。

下一步是准备`config['images']`为空列表，并清空与`_img_listbox`绑定的`_images`变量。当然，这会清理`_img_listbox`中的所有项目。

准备工作完成后，我们可以尝试获取页面，使用与本章开头的脚本中采用的相同的`try`/`except`逻辑。唯一的区别是如果出现问题，我们会调用`_sb(str(err))`。`_sb`是一个帮助函数，我们很快就会看到它的代码。基本上，它为我们设置状态栏中的文本。不是一个好名字，对吧？我不得不向您解释它的行为-值得思考。

如果我们可以获取页面，那么我们就创建`soup`实例，并从中获取图片。`fetch_images`的逻辑与之前解释的逻辑完全相同，因此我就不在这里重复了。

如果我们有图像，我们使用一个快速的元组推导式（实际上是一个生成器表达式馈送到一个元组构造函数），将`_images`作为`StringVar`，这会使我们的`_img_listbox`填充所有图像名称。最后，我们更新状态栏。

如果没有图像，我们仍然更新状态栏，并且在函数结束时，无论找到了多少图像，我们都会更新`config['images']`以保存`images`列表。这样，我们就能够通过检查`config['images']`而无需传递该列表来从其他函数中访问图像。

# 保存图像

保存图像的逻辑非常简单。如下所示：

```py
def save():
    if not config.get('images'):
        _alert('No images to save')
        return

    if _save_method.get() == 'img':
        dirname = filedialog.askdirectory(mustexist=True)
        _save_images(dirname)
    else:
        filename = filedialog.asksaveasfilename(
            initialfile='images.json',
            filetypes=[('JSON', '.json')])
        _save_json(filename)

def _save_images(dirname):
    if dirname and config.get('images'):
        for img in config['images']:
            img_data = requests.get(img['url']).content
            filename = os.path.join(dirname, img['name'])
            with open(filename, 'wb') as f:
                f.write(img_data)
        _alert('Done')

def _save_json(filename):
    if filename and config.get('images'):
        data = {}
        for img in config['images']:
            img_data = requests.get(img['url']).content
            b64_img_data = base64.b64encode(img_data)
            str_img_data = b64_img_data.decode('utf-8')
            data[img['name']] = str_img_data

        with open(filename, 'w') as ijson:
            ijson.write(json.dumps(data))
        _alert('Done')
```

当用户点击抓取按钮时，使用回调机制调用`save`函数。

这个函数的第一件事就是检查是否有要保存的图像。如果没有，它会使用另一个辅助函数`_alert`来提醒用户，我们很快就会看到它的代码。如果没有图像，就不会执行进一步的操作。

另一方面，如果`config['images']`列表不为空，`save`充当一个调度程序，并根据`_same_method`持有的值调用`_save_images`或`_save_json`。请记住，这个变量与单选按钮相关联，因此我们期望它的值要么是`'img'`，要么是`'json'`。

这个调度程序与脚本中的不同。根据我们选择的方法，必须采取不同的操作。

如果我们想要将图像保存为图像，我们需要要求用户选择一个目录。我们通过调用`filedialog.askdirectory`并将调用的结果分配给`dirname`变量来实现这一点。这将打开一个漂亮的对话框窗口，询问我们选择一个目录。我们选择的目录必须存在，如我们调用该方法的方式所指定的。这样做是为了在保存文件时不必编写处理可能缺少的目录的代码。

这个对话框在 mac 上应该是这样的：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00015.jpeg)

如果我们取消操作，`dirname`将被设置为`None`。

在完成对`save`中的逻辑分析之前，让我们快速浏览一下`_save_images`。

它与脚本中的版本非常相似，因此请注意，在开始时，为了确保我们确实有事情要做，我们检查`dirname`和`config['images']`中至少有一张图像的存在。

如果是这样，这意味着我们至少有一个要保存的图像和它的路径，所以我们可以继续。保存图像的逻辑已经解释过了。这一次我们做的不同的一件事是，通过`os.path.join`将目录（即完整路径）与图像名称连接起来。

在`_save_images`结束时，如果我们至少保存了一张图像，我们会提醒用户我们已经完成了。

现在让我们回到`save`中的另一个分支。当用户在按下抓取按钮之前选择了作为 JSON 的单选按钮时，将执行此分支。在这种情况下，我们想要保存一个文件；因此，我们不能只要求一个目录。我们还希望让用户有能力选择一个文件名。因此，我们启动了一个不同的对话框：`filedialog.asksaveasfilename`。

我们传递一个初始文件名，该文件名建议给用户-如果他们不喜欢它，他们有能力更改它。此外，因为我们正在保存一个 JSON 文件，我们通过传递`filetypes`参数来强制用户使用正确的扩展名。这是一个列表，其中包含任意数量的两元组*(描述，扩展名)*，用于运行对话框的逻辑。

这个对话框在 macOS 上应该是这样的：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00016.jpeg)

一旦我们选择了一个位置和一个文件名，我们就可以继续进行保存逻辑，这与之前的脚本中的逻辑相同。我们从一个 Python 字典（`data`）创建一个 JSON 对象，该字典由`images`名称和 Base64 编码内容组成的键值对。

在`_save_json`中，我们还有一个小检查，确保我们没有文件名和至少一个要保存的图像时不会继续。这确保了如果用户按下取消按钮，不会发生任何不好的事情。

# 警告用户

最后，让我们看看警报逻辑。这非常简单：

```py
def _sb(msg):
    _status_msg.set(msg)

def _alert(msg):
    messagebox.showinfo(message=msg)
```

就改变状态栏消息而言，我们所需要做的就是访问`_status_msg` `StringVar`，因为它与`_status`标签相关联。

另一方面，如果我们想向用户显示更明显的消息，我们可以弹出一个消息框。在 Mac 上应该是这样的：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00017.jpeg)

`messagebox`对象还可以用于警告用户（`messagebox.showwarning`）或者表示错误（`messagebox.showerror`）。但它也可以用于提供询问我们是否确定要继续或者是否真的要删除那个文件等对话框。

如果你通过简单地打印`dir(messagebox)`的返回值来检查`messagebox`，你会发现诸如`askokcancel`、`askquestion`、`askretrycancel`、`askyesno`和`askyesnocancel`等方法，以及一组常量来验证用户的响应，如`CANCEL`、`NO`、`OK`、`OKCANCEL`、`YES`和`YESNOCANCEL`。你可以将这些与用户的选择进行比较，以便知道对话框关闭时执行的下一个操作。

# 我们如何改进应用程序？

现在你已经习惯了设计 GUI 应用程序的基础知识，我想给你一些建议，如何使我们的应用程序更好。

我们可以从代码质量开始。你认为这段代码足够好，还是你会改进它？如果是的话，你会怎么做？我会测试它，并确保它是健壮的，并且考虑到用户可能通过点击应用程序而创建的各种情况。我还会确保当我们正在抓取的网站因任何原因而关闭时，行为是我所期望的。

我们可以改进的另一件事是命名。我谨慎地用下划线作为前缀命名了所有组件，既突出了它们的*私有*性质，又避免了与它们链接的底层对象发生名称冲突。但回想起来，许多这些组件可能需要更好的名称，因此真的取决于你重构，直到找到最适合你的形式。你可以从给`_sb`函数一个更好的名称开始！

就用户界面而言，你可以尝试调整主应用程序的大小。看看会发生什么？整个内容保持不变。如果你扩展，会添加空白空间，如果你缩小，整个小部件集会逐渐消失。这种行为并不是很好，因此一个快速的解决方案可能是使根窗口固定（即无法调整大小）。

你可以做的另一件事是改进应用程序，使其具有与脚本中相同的功能，只保存 PNG 或 JPG。为了做到这一点，你可以在某个地方放置一个组合框，有三个值：全部、PNG、JPG，或类似的东西。用户在保存文件之前应该能够选择其中一个选项。

更好的是，你可以更改`Listbox`的声明，以便可以同时选择多个图像，并且只保存所选的图像。如果你成功做到这一点（相信我，这并不像看起来那么难），那么你应该考虑更好地呈现`Listbox`，也许为行提供交替的背景颜色。

你可以添加的另一件好事是添加一个按钮，打开一个对话框来选择一个文件。文件必须是应用程序可以生成的 JSON 文件之一。一旦选择，你可以运行一些逻辑来从它们的 Base64 编码版本重建图像。这样做的逻辑非常简单，所以这里有一个例子：

```py
with open('images.json', 'r') as f:
    data = json.loads(f.read())

for (name, b64val) in data.items():
    with open(name, 'wb') as f:
        f.write(base64.b64decode(b64val))
```

如你所见，我们需要以读模式打开`images.json`，并获取`data`字典。一旦我们有了它，我们就可以循环遍历它的项目，并保存每个图像的 Base64 解码内容。我会把这个逻辑留给你，让你把它与应用程序中的一个按钮联系起来。

你可以添加的另一个很酷的功能是能够打开一个预览窗格，显示从`Listbox`中选择的任何图像，这样用户就可以在决定保存它们之前先看一眼这些图像。

最后，对于这个应用的最后一个建议是添加一个菜单。甚至可以添加一个简单的菜单，包括文件和？来提供通常的帮助或关于。只是为了好玩。添加菜单并不复杂；你可以添加文本、键盘快捷键、图像等等。

# 我们从这里去哪里？

如果你对深入了解 GUI 的世界感兴趣，那么我想给你提几个建议。

# 乌龟模块

`turtle`模块是 Python 标准发行版中自 Python 2.5 版本以来的同名模块的扩展重新实现。这是向孩子介绍编程的一种非常受欢迎的方式。

它基于一个想象中的乌龟从笛卡尔平面的(0, 0)开始的想法。你可以通过编程命令乌龟向前和向后移动，旋转等等；通过组合所有可能的移动，可以绘制各种复杂的形状和图像。

它绝对值得一看，即使只是为了看到一些不同的东西。

# wxPython，PyQt 和 PyGTK

在你探索了 tkinter 的广阔领域之后，我建议你探索其他 GUI 库：wxPython（https://www.wxpython.org/），PyQt（https://riverbankcomputing.com/software/pyqt/intro），和 PyGTK（https://pygobject.readthedocs.io/en/latest/）。你可能会发现其中一个更适合你，或者它会让你更容易编写你需要的应用程序。

我相信只有当编码人员意识到他们可以使用的工具时，他们才能实现他们的想法。如果你的工具集太狭窄，你的想法可能看起来是不可能的，或者非常难以实现，它们可能会保持原样，只是想法。

当然，今天的技术范围是巨大的，所以不可能了解一切；因此，当你要学习新技术或新主题时，我的建议是通过广度优先探索来增加你的知识。

调查几件事情，然后深入研究看起来最有希望的一个或几个。这样你就能至少用一种工具高效地工作，当这个工具不再满足你的需求时，你会知道在哪里深入挖掘，感谢你之前的探索。

# 最少惊讶法则

在设计界面时，有许多不同的事情需要牢记。其中一个对我来说最重要的是最少惊讶法则。它基本上是说，如果在你的设计中一个必要的功能具有很高的惊讶因素，可能需要重新设计你的应用程序。举个例子，当你习惯于在 Windows 上工作时，最小化、最大化和关闭窗口的按钮在右上角，但在 Linux 上工作时，它们在左上角，这是相当困难的。你会发现自己不断地去右上角，只发现按钮在另一边。

如果某个按钮在应用程序中变得如此重要，以至于设计师现在将其放在一个精确的位置，请不要创新。只需遵循惯例。用户只会在不得不花时间寻找不在预期位置的按钮时感到沮丧。

对这个规则的忽视是我无法使用 Jira 等产品的原因。做简单的事情花费了我几分钟的时间，本应该只需要几秒钟。

# 线程考虑

这个主题超出了本书的范围，但我还是想提一下。

如果你正在编写一个 GUI 应用程序，需要在点击按钮时执行一个长时间运行的操作，你会发现你的应用程序可能会在操作完成之前冻结。为了避免这种情况，并保持应用程序的响应性，你可能需要在不同的线程（甚至是不同的进程）中运行那个耗时的操作，这样操作系统就能够不时地为 GUI 分配一点时间，以保持其响应性。

首先要对基本原理有很好的掌握，然后再去享受探索的乐趣！

# 总结

在本章中，我们一起完成了一个项目。我们编写了一个脚本，可以抓取一个非常简单的网页，并接受可选命令来改变其行为。我们还编写了一个 GUI 应用程序，通过点击按钮而不是在控制台上输入来完成相同的操作。我希望你阅读和跟随的过程和我写作的过程一样愉快。

我们看到了许多不同的概念，比如处理文件和执行 HTTP 请求，并讨论了可用性和设计的指导方针。

我只能触及皮毛，但希望你有一个很好的起点，可以从中扩展你的探索。

在整个章节中，我指出了几种不同的改进应用程序的方法，并向你提出了一些练习和问题。我希望你花时间去尝试这些想法。你可以通过玩弄像我们一起编写的这个应用程序一样有趣的应用程序来学到很多东西。

在下一章中，我们将讨论数据科学，或者至少讨论一下当涉及这个主题时，Python 程序员所拥有的工具。


# 第十三章：数据科学

“如果我们有数据，让我们看看数据。如果我们只有意见，那就听我的。”- Jim Barksdale，前网景公司 CEO

**数据科学**是一个非常广泛的术语，根据上下文、理解、工具等可以有几种不同的含义。关于这个主题有无数的书籍，这对心脏脆弱的人来说并不适合。

为了做好数据科学，你至少需要了解数学和统计学。然后，你可能想深入研究其他学科，比如模式识别和机器学习，当然，你可以选择各种语言和工具。

我无法在这里讨论所有内容。因此，为了使本章有意义，我们将一起做一个很酷的项目。

大约在 2012/2013 年，我在伦敦一家顶级社交媒体公司工作。我在那里呆了两年，很荣幸能和一些非常聪明的人一起工作，他们的才华令我只能开始描述。我们是世界上第一个可以访问 Twitter 广告 API 的公司，我们也是 Facebook 的合作伙伴。这意味着有大量的数据。

我们的分析师们处理了大量的活动，并且他们为了完成工作而苦苦挣扎，所以我所在的开发团队尝试通过介绍 Python 和 Python 提供的处理数据的工具来帮助他们。这是一段非常有趣的旅程，让我在公司里指导了几个人，最终带我去了马尼拉，在那里我为分析师们进行了为期两周的 Python 和数据科学密集培训。

我们在本章中要做的项目是我在马尼拉向学生展示的最终示例的轻量级版本。我已经重新编写了它，使其适合本章的篇幅，并对一些地方进行了一些调整，但所有主要概念都在其中，所以对你来说应该是有趣和有教育意义的。

具体来说，我们将探讨以下内容：

+   Jupyter Notebook

+   Pandas 和 NumPy：Python 中的数据科学主要库

+   Pandas 的`DataFrame`类的一些概念

+   创建和操作数据集

让我们先谈谈罗马神话中的神祗。

# IPython 和 Jupyter Notebook

在 2001 年，Fernando Perez 是科罗拉多大学博尔德分校的物理学研究生，他试图改进 Python shell，以便在使用类似 Mathematica 和 Maple 等工具时能够获得他习惯的便利。这一努力的结果被命名为**IPython**。

简而言之，那个小脚本最初是 Python shell 的增强版本，通过其他编码人员的努力，最终得到了来自不同公司的适当资金支持，成为了今天的出色和成功的项目。它诞生 10 年后，一个 Notebook 环境被创建，由 WebSockets、Tornado web 服务器、jQuery、CodeMirror 和 MathJax 等技术提供支持。ZeroMQ 库也被用来处理 Notebook 界面和其背后的 Python 核心之间的消息。

IPython Notebook 变得如此受欢迎和广泛使用，随着时间的推移，各种好东西都被添加进去。它可以处理小部件、并行计算、各种媒体格式等等。而且，在某个时候，甚至可以在 Notebook 内部使用 Python 以外的语言进行编码。

这导致了一个庞大的项目，曾经被分成两部分：IPython 被精简以更专注于内核部分和 shell，而 Notebook 已经成为一个名为**Jupyter**的全新项目。Jupyter 允许以 40 多种语言进行交互式科学计算。

本章的项目将全部在 Jupyter Notebook 中编写和运行，所以让我简单解释一下 Notebook 是什么。

笔记本环境是一个网页，它公开了一个简单的菜单和可以运行 Python 代码的单元格。尽管单元格是可以单独运行的独立实体，但它们都共享相同的 Python 内核。这意味着您在一个单元格中定义的所有名称（变量、函数等）将在任何其他单元格中都可用。

简而言之，Python 内核是 Python 正在运行的进程。因此，笔记本网页是向用户公开的用于驱动此内核的接口。网页使用非常快速的消息传递系统与内核进行通信。

除了所有图形优势之外，拥有这样的环境之美在于能够以块的方式运行 Python 脚本，这可能是一个巨大的优势。拿一个连接到数据库以获取数据然后操作该数据的脚本来说。如果您以常规方式进行，使用 Python 脚本，您必须每次想要对其进行实验时都获取数据。在笔记本环境中，您可以在一个单元格中获取数据，然后在其他单元格中操作和实验，因此不必每次都获取数据。

笔记本环境对于数据科学也非常有帮助，因为它允许逐步的内省。您完成一部分工作，然后进行验证。然后再做另一部分并再次验证，依此类推。

这对于原型设计也是非常宝贵的，因为结果就在你眼前，立即可用。

如果您想了解更多关于这些工具的信息，请访问[ipython.org](https://ipython.org/)和[jupyter.org](http://jupyter.org/)。

我创建了一个非常简单的示例笔记本，其中包含一个`fibonacci`函数，该函数为您提供了小于给定`N`的所有斐波那契数的列表。在我的浏览器中，它看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00018.jpeg)

每个单元格都有一个 In []标签。如果方括号之间没有任何内容，这意味着单元格从未被执行过。如果有一个数字，这意味着单元格已被执行，并且该数字表示单元格被执行的顺序。最后，*表示该单元格当前正在执行。

您可以看到图片中，在第一个单元格中我定义了`fibonacci`函数，并执行了它。这样做的效果是将`fibonacci`名称放在与笔记本关联的全局框架中，因此`fibonacci`函数现在也可以在其他单元格中使用。实际上，在第二个单元格中，我可以运行`fibonacci(100)`并在 Out [2]中看到结果。在第三个单元格中，我向您展示了笔记本中的几个魔术函数之一。%timeit 多次运行代码并为您提供一个很好的基准。我在第五章中进行的所有列表理解和生成器的测量都是使用这个很好的功能进行的，*节省时间和内存*。

您可以执行单元格任意次数，并更改运行它们的顺序。单元格非常灵活，您还可以放入 Markdown 文本或将其呈现为标题。

**Markdown**是一种轻量级标记语言，具有纯文本格式化语法，设计成可以转换为 HTML 和许多其他格式。

此外，无论您将什么放在单元格的最后一行，都将自动为您打印出来。这非常方便，因为您不必明确地编写`print(...)`。

随时探索笔记本环境；一旦您熟悉它，我保证这将是一段持久的关系。

# 安装所需的库

为了运行笔记本，您必须安装一些库，每个库都与其他库合作以使整个系统工作。或者，您可以只安装 Jupyter，它会为您处理一切。对于本章，我们需要安装一些其他依赖项。您可以在项目的根文件夹中的`requirements/requirements.data.science.in`中找到它们的列表。要安装它们，请查看`README.rst`，您将在其中找到专门针对本章的说明。

# 使用 Anaconda

有时安装数据科学库可能非常痛苦。如果您在虚拟环境中为本章安装库而苦苦挣扎，您的另一个选择是安装 Anaconda。Anaconda 是 Python 和 R 编程语言的免费开源发行版，用于数据科学和机器学习相关应用，旨在简化软件包管理和部署。您可以从[anaconda.org](https://anaconda.org/)网站下载它。安装在系统中后，查看本章的各种要求，并通过 Anaconda 安装它们。 

# 开始笔记本

一旦您安装了所有必需的库，您可以使用以下命令启动笔记本，或者使用 Anaconda 界面：

```py
 $ jupyter notebook 
```

您将在浏览器中打开此地址（端口可能不同）：`http://localhost:8888/`。转到该页面并使用菜单创建一个新的笔记本。当您感到舒适时，您已经准备好了。我强烈建议您在继续阅读之前尝试并运行 Jupyter 环境。有时不得不处理困难的依赖关系是一个很好的练习。

我们的项目将在笔记本中进行，因此我将使用单元格编号标记每个代码片段，以便您可以轻松地复制代码并跟随操作。

如果您熟悉键盘快捷键（查看笔记本的帮助部分），您将能够在单元格之间移动并处理它们的内容，而无需使用鼠标。这将使您在笔记本中工作时更加熟练和更快。

现在让我们继续讨论本章最有趣的部分：数据。

# 处理数据

通常，当您处理数据时，您会经历以下路径：获取数据，清理和操作数据，然后检查数据，并将结果呈现为值，电子表格，图形等。我希望您能够独立完成这个过程的所有三个步骤，而不依赖于外部数据提供者，因此我们将进行以下操作：

1.  我们将创建数据，模拟数据以一种不完美或不准备好被处理的格式

1.  我们将对其进行清理并将其提供给项目中将使用的主要工具，如`pandas`库中的`DataFrame`

1.  我们将在`DataFrame`中操作数据

1.  我们将以不同格式将`DataFrame`保存到文件中

1.  我们将检查数据并从中获取一些结果

# 设置笔记本

首先，让我们生成数据。我们从`ch13-dataprep`笔记本开始：

```py
#1
import json
import random
from datetime import date, timedelta
import faker
```

单元格`＃1`负责导入。我们已经遇到过它们，除了`faker`。您可以使用此模块准备虚假数据。在测试中非常有用，当您准备您的固定装置时，可以获得各种各样的东西，如姓名，电子邮件地址，电话号码和信用卡详细信息。当然，这都是假的。

# 准备数据

我们希望实现以下数据结构：我们将拥有一个用户对象列表。每个用户对象将与多个活动对象相关联。在 Python 中，一切都是对象，所以我以一种通用的方式使用这个术语。用户对象可以是字符串，字典或其他东西。

在社交媒体世界中，**广告系列**是媒体机构代表客户在社交媒体网络上运行的促销活动。请记住，我们将准备这些数据，使其不是完美的（但也不会太糟糕...）：

```py
#2
fake = faker.Faker() 
```

首先，我们实例化`Faker`，我们将用它来创建数据：

```py
#3
usernames = set()
usernames_no = 1000

# populate the set with 1000 unique usernames
while len(usernames) < usernames_no:
    usernames.add(fake.user_name())
```

然后我们需要用户名。我想要 1,000 个唯一的用户名，所以我循环遍历`用户名`集合的长度，直到它有 1,000 个元素。`set`方法不允许重复元素，因此确保了唯一性：

```py
#4
def get_random_name_and_gender():
    skew = .6  # 60% of users will be female
    male = random.random() > skew
    if male:
        return fake.name_male(), 'M'
    else:
        return fake.name_female(), 'F'

def get_users(usernames):
    users = []
    for username in usernames:
        name, gender = get_random_name_and_gender()
        user = {
            'username': username,
            'name': name,
            'gender': gender,
            'email': fake.email(),
            'age': fake.random_int(min=18, max=90),
            'address': fake.address(),
        }
        users.append(json.dumps(user))
    return users

users = get_users(usernames)
users[:3]
```

在这里，我们创建了一个`用户`列表。每个`用户名`现在已经增加到一个完整的`用户`字典中，其中包括`姓名`，`性别`和`电子邮件`等其他细节。然后将每个`用户`字典转储为 JSON 并添加到列表中。当然，这种数据结构并不是最佳的，但我们正在模拟用户以这种方式来到我们这里的情况。

注意到了`random.random()`的偏斜使用，使 60%的用户为女性。其余的逻辑应该对你来说非常容易理解。

还要注意最后一行。每个单元格都会自动打印最后一行的内容；因此，`＃4`的输出是一个包含前三个`用户`的列表：

```py
['{"username": "samuel62", "name": "Tonya Lucas", "gender": "F", "email": "anthonyrobinson@robbins.biz", "age": 27, "address": "PSC 8934, Box 4049\\nAPO AA 43073"}',
 '{"username": "eallen", "name": "Charles Harmon", "gender": "M", "email": "courtneycollins@hotmail.com", "age": 28, "address": "38661 Clark Mews Apt. 528\\nAnthonychester, ID 25919"}',
 '{"username": "amartinez", "name": "Laura Dunn", "gender": "F", "email": "jeffrey35@yahoo.com", "age": 88, "address": "0536 Daniel Court Apt. 541\\nPort Christopher, HI 49399-3415"}']
```

我希望你正在用自己的笔记本跟着做。如果是的话，请注意所有数据都是使用随机函数和值生成的；因此，你会看到不同的结果。每次执行笔记本时都会发生变化。

在下面的代码中，`＃5`是生成广告系列名称的逻辑：

```py
#5
# campaign name format:
# InternalType_StartDate_EndDate_TargetAge_TargetGender_Currency
def get_type():
    # just some gibberish internal codes
    types = ['AKX', 'BYU', 'GRZ', 'KTR']
    return random.choice(types)

def get_start_end_dates():
    duration = random.randint(1, 2 * 365)
    offset = random.randint(-365, 365)
    start = date.today() - timedelta(days=offset)
    end = start + timedelta(days=duration)

    def _format_date(date_):
        return date_.strftime("%Y%m%d")
    return _format_date(start), _format_date(end)

def get_age():
    age = random.randint(20, 45)
    age -= age % 5
    diff = random.randint(5, 25)
    diff -= diff % 5
    return '{}-{}'.format(age, age + diff)

def get_gender():
    return random.choice(('M', 'F', 'B'))

def get_currency():
    return random.choice(('GBP', 'EUR', 'USD'))

def get_campaign_name():
    separator = '_'
    type_ = get_type()
    start, end = get_start_end_dates()
    age = get_age()
    gender = get_gender()
    currency = get_currency()
    return separator.join(
        (type_, start, end, age, gender, currency))
```

分析师们经常使用电子表格，并想出各种编码技术，以尽可能多地压缩信息到广告系列名称中。我选择的格式是这种技术的一个简单示例——有一个代码告诉我们广告系列类型，然后是开始和结束日期，然后是目标`年龄`和`性别`，最后是货币。所有值都用下划线分隔。

在`get_type`函数中，我使用`random.choice()`从集合中随机获取一个值。也许更有趣的是`get_start_end_dates`。首先，我得到了广告系列的持续时间，从一天到两年（随机），然后我得到了一个随机的时间偏移，我从今天的日期中减去它以获得开始日期。鉴于偏移是-365 到 365 之间的随机数，如果我将它添加到今天的日期而不是减去它，会有什么不同吗？

当我有开始和结束日期时，我会返回它们的字符串版本，用下划线连接起来。

然后，我们对年龄计算进行了一些模块化的技巧。我希望你还记得第二章中的取模运算符（`％`）。

这里发生的是，我想要一个具有五的倍数作为极端的日期范围。因此，有很多方法可以做到这一点，但我做的是从`20`到`45`之间获取一个随机数，然后去除除以`5`的余数。因此，例如，如果我得到*28*，我将从中去除*28％5 = 3*，得到*25*。我本来可以使用`random.randrange()`，但很难抵制模块化除法。

其余的函数只是`random.choice()`的一些其他应用，最后一个`get_campaign_name`只是一个收集所有这些拼图块的收集器，返回最终的广告系列名称：

```py
#6
# campaign data:
# name, budget, spent, clicks, impressions
def get_campaign_data():
    name = get_campaign_name()
    budget = random.randint(10**3, 10**6)
    spent = random.randint(10**2, budget) 
    clicks = int(random.triangular(10**2, 10**5, 0.2 * 10**5)) 
    impressions = int(random.gauss(0.5 * 10**6, 2))
    return {
        'cmp_name': name,
        'cmp_bgt': budget,
        'cmp_spent': spent,
```

```py
        'cmp_clicks': clicks,
        'cmp_impr': impressions
    }
```

在`＃6`中，我们编写了一个创建完整广告系列对象的函数。我使用了`random`模块中的一些不同函数。`random.randint()`给出了两个极端之间的整数。它的问题在于它遵循均匀概率分布，这意味着区间内的任何数字出现的概率都是相同的。

因此，当处理大量数据时，如果你使用均匀分布来分发你的固定值，你得到的结果将会看起来很相似。因此，我选择使用`triangular`和`gauss`，对于`clicks`和`impressions`。它们使用不同的概率分布，这样我们最终会有一些更有趣的东西。

为了确保我们对术语的理解是一致的：`clicks`代表对活动广告的点击次数，`budget`是分配给活动的总金额，`spent`是已经花费的金额，`impressions`是活动从其来源获取的次数，无论点击了多少次活动。通常，`impressions`的数量大于`clicks`的数量。

现在我们有了数据，是时候把它们整合在一起了：

```py
#7
def get_data(users):
    data = []
    for user in users:
        campaigns = [get_campaign_data()
                     for _ in range(random.randint(2, 8))]
        data.append({'user': user, 'campaigns': campaigns})
    return data
```

正如你所看到的，`data`中的每个项目都是一个带有`user`和与该`user`相关的一系列活动的字典。

# 清理数据

让我们开始清理数据：

```py
#8
rough_data = get_data(users)
rough_data[:2]  # let's take a peek
```

我们模拟从源获取数据然后检查它。笔记本是检查你的步骤的完美工具。你可以根据需要调整粒度。`rough_data`中的第一项看起来像这样：

```py
{'user': '{"username": "samuel62", "name": "Tonya Lucas", "gender": "F", "email": "anthonyrobinson@robbins.biz", "age": 27, "address": "PSC 8934, Box 4049\\nAPO AA 43073"}',
 'campaigns': [{'cmp_name': 'GRZ_20171018_20171116_35-55_B_EUR',
 'cmp_bgt': 999613,
 'cmp_spent': 43168,
 'cmp_clicks': 35603,
 'cmp_impr': 500001},
 ...
 {'cmp_name': 'BYU_20171122_20181016_30-45_B_USD',
 'cmp_bgt': 561058,
 'cmp_spent': 472283,
 'cmp_clicks': 44823,
 'cmp_impr': 499999}]} 
```

所以，我们现在开始处理它：

```py
#9
data = []
for datum in rough_data:
    for campaign in datum['campaigns']:
        campaign.update({'user': datum['user']})
        data.append(campaign)
data[:2]  # let's take another peek
```

为了能够用这个`data`来填充`DataFrame`，我们需要做的第一件事是对其进行去规范化。这意味着将`data`转换为一个列表，其项是活动字典，附加上它们的相关`user`字典。用户将在他们所属的每个活动中被复制。`data`中的第一项看起来像这样：

```py
{'cmp_name': 'GRZ_20171018_20171116_35-55_B_EUR',
 'cmp_bgt': 999613,
 'cmp_spent': 43168,
 'cmp_clicks': 35603,
 'cmp_impr': 500001,
 'user': '{"username": "samuel62", "name": "Tonya Lucas", "gender": "F", "email": "anthonyrobinson@robbins.biz", "age": 27, "address": "PSC 8934, Box 4049\\nAPO AA 43073"}'}
```

你可以看到`user`对象已经被带入了活动字典中，这对于每个活动都是重复的。

现在，我想帮助你并提供本章的确定性第二部分，所以我将保存我在这里生成的数据，这样我（以及你）就可以从下一个笔记本中加载它，然后我们应该有相同的结果：

```py
#10
with open('data.json', 'w') as stream:
    stream.write(json.dumps(data))
```

你应该在书的源代码中找到`data.json`文件。现在我们已经完成了`ch13-dataprep`，所以我们可以关闭它，然后打开`ch13`。

# 创建 DataFrame

首先，我们有另一轮导入：

```py
#1
import json
import calendar
import numpy as np
from pandas import DataFrame
import arrow
import pandas as pd
```

`json`和`calendar`库来自标准库。`numpy`是 NumPy 库，用于科学计算的基本包。NumPy 代表 Numeric Python，它是数据科学环境中最广泛使用的库之一。我稍后会在本章中谈到它。`pandas`是整个项目的核心。**Pandas**代表**Python 数据分析库**。除了许多其他功能外，它提供了`DataFrame`，这是一种类似矩阵的数据结构，具有高级处理能力。习惯上，单独导入`DataFrame`，然后`import pandas as pd`。

`arrow`是一个很好的第三方库，可以极大地加快处理日期的速度。从技术上讲，我们可以使用标准库来做到这一点，但我认为没有理由不扩展示例的范围并向你展示一些不同的东西。

在导入之后，我们将`data`加载如下：

```py
#2
with open('data.json') as stream:
    data = json.loads(stream.read())
```

最后，是时候创建`DataFrame`了：

```py
#3
df = DataFrame(data)
df.head()
```

我们可以使用`DataFrame`的`head`方法来检查前五行。你应该会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00019.jpeg)

Jupyter 会自动将`df.head()`调用的输出呈现为 HTML。为了获得基于文本的输出，只需将`df.head()`包装在`print`调用中。

`DataFrame`结构非常强大。它允许我们操纵许多内容。您可以按行、列进行过滤，对数据进行聚合以及许多其他操作。您可以在不受纯 Python 数据的时间惩罚的情况下操作行或列。这是因为在幕后，`pandas`利用了 NumPy 库的强大功能，而 NumPy 库本身又从其核心的低级实现中获得了令人难以置信的速度。

使用`DataFrame`允许我们将 NumPy 的强大功能与类似电子表格的功能相结合，这样我们就能够以类似分析师的方式处理我们的数据。只是，我们用代码来做。

但让我们回到我们的项目。让我们看看两种快速了解数据的方法：

```py
#4
df.count()
```

`count`返回每列中所有非空单元格的计数。这有助于您了解数据有多稀疏。在我们的情况下，我们没有缺失值，因此输出是：

```py
cmp_bgt       5037
cmp_clicks    5037
cmp_impr      5037
cmp_name      5037
cmp_spent     5037
user          5037
dtype: int64
```

太好了！我们有 5,037 行数据，数据类型是整数（`dtype: int64`表示长整数，因为每个整数占用 64 位）。考虑到我们有 1,000 个用户，每个用户的活动数量是 2 到 8 之间的随机数，我们正好符合我的预期：

```py
#5
df.describe() 
```

`describe`方法是一个不错的、快速的深入了解的方法：

```py
 cmp_bgt   cmp_clicks      cmp_impr     cmp_spent
count  5037.000000  5037.000000   5037.000000   5037.000000
mean 496930.317054 40920.962676 499999.498312 246963.542783
std  287126.683484 21758.505210      2.033342 217822.037701
min    1057.000000   341.000000 499993.000000    114.000000
25%  247663.000000 23340.000000 499998.000000  64853.000000
50%  491650.000000 37919.000000 500000.000000 183716.000000
75%  745093.000000 56253.000000 500001.000000 379478.000000
max  999577.000000 99654.000000 500008.000000 975799.000000
```

正如您所看到的，它为我们提供了几个度量，如`count`、`mean`、`std`（标准偏差）、`min`和`max`，并显示数据在各个象限中的分布情况。由于这种方法，我们已经对我们的数据结构有了一个大致的了解。

让我们看看哪三个活动的预算最高和最低：

```py
#6
df.sort_index(by=['cmp_bgt'], ascending=False).head(3) 
```

这给出了以下输出：

```py
 cmp_bgt  cmp_clicks  cmp_impr                           cmp_name
3321   999577        8232    499997  GRZ_20180810_20190107_40-55_M_EUR   
2361   999534       53223    499999  GRZ_20180516_20191030_25-30_B_EUR   
2220   999096       13347    499999  KTR_20180620_20190809_40-50_F_USD
```

调用`tail`会显示出预算最低的活动：

```py
#7
df.sort_values(by=['cmp_bgt'], ascending=False).tail(3)
```

# 解开活动名称

现在是时候增加复杂性了。首先，我们想摆脱那个可怕的活动名称（`cmp_name`）。我们需要将其分解为部分，并将每个部分放入一个专用列中。为了做到这一点，我们将使用`Series`对象的`apply`方法。

`pandas.core.series.Series`类基本上是一个数组的强大包装器（将其视为具有增强功能的列表）。我们可以通过与字典中的键相同的方式从`DataFrame`中提取`Series`对象，并且我们可以在该`Series`对象上调用`apply`，这将运行一个函数将`Series`中的每个项目传递给它。我们将结果组合成一个新的`DataFrame`，然后将该`DataFrame`与`df`连接：

```py
#8
def unpack_campaign_name(name):
    # very optimistic method, assumes data in campaign name
    # is always in good state
    type_, start, end, age, gender, currency = name.split('_')
    start = arrow.get(start, 'YYYYMMDD').date()
    end = arrow.get(end, 'YYYYMMDD').date()
    return type_, start, end, age, gender, currency

campaign_data = df['cmp_name'].apply(unpack_campaign_name)
campaign_cols = [
    'Type', 'Start', 'End', 'Age', 'Gender', 'Currency']
campaign_df = DataFrame(
    campaign_data.tolist(), columns=campaign_cols, index=df.index)
campaign_df.head(3)
```

在`unpack_campaign_name`中，我们将活动`name`分成几部分。我们使用`arrow.get()`从这些字符串中获取一个合适的`date`对象（`arrow`使这变得非常容易，不是吗？），然后我们返回这些对象。快速查看最后一行显示：

```py
 Type       Start         End    Age Gender Currency
0  KTR  2019-03-24  2020-11-06  20-35      F      EUR
1  GRZ  2017-05-21  2018-07-24  30-45      B      GBP
2  KTR  2017-12-18  2018-02-08  30-40      F      GBP
```

太好了！一个重要的事情：即使日期显示为字符串，它们只是托管在`DataFrame`中的真实`date`对象的表示。

另一件非常重要的事情：当连接两个`DataFrame`实例时，它们必须具有相同的`index`，否则`pandas`将无法知道哪些行与哪些行配对。因此，当我们创建`campaign_df`时，我们将其`index`设置为`df`的`index`。这使我们能够将它们连接起来。在创建此`DataFrame`时，我们还传递了列的名称：

```py
#9
df = df.join(campaign_df)
```

在`join`之后，我们做了一个快速查看，希望看到匹配的数据：

```py
#10
df[['cmp_name'] + campaign_cols].head(3)
```

上述代码片段的截断输出如下：

```py
 cmp_name Type      Start        End
0 KTR_20190324_20201106_20-35_F_EUR  KTR 2019-03-24 2020-11-06
1 GRZ_20170521_20180724_30-45_B_GBP  GRZ 2017-05-21 2018-07-24
2 KTR_20171218_20180208_30-40_F_GBP  KTR 2017-12-18 2018-02-08
```

正如您所看到的，`join`是成功的；活动名称和单独的列显示了相同的数据。您看到我们在那里做了什么吗？我们使用方括号语法访问`DataFrame`，并传递一个列名的列表。这将产生一个全新的`DataFrame`，其中包含这些列（顺序相同），然后我们调用`head()`方法。

# 解开用户数据

现在我们对每个`user` JSON 数据的每一部分做完全相同的事情。我们在`user`系列上调用`apply`，运行`unpack_user_json`函数，该函数接受一个 JSON `user`对象并将其转换为其字段的列表，然后我们可以将其注入到全新的`DataFrame` `user_df`中。之后，我们将`user_df`与`df`重新连接，就像我们对`campaign_df`所做的那样：

```py
#11
def unpack_user_json(user):
    # very optimistic as well, expects user objects
    # to have all attributes
    user = json.loads(user.strip())
    return [
        user['username'],
        user['email'],
        user['name'],
        user['gender'],
        user['age'],
        user['address'],
    ]

user_data = df['user'].apply(unpack_user_json)
user_cols = [
    'username', 'email', 'name', 'gender', 'age', 'address']
user_df = DataFrame(
    user_data.tolist(), columns=user_cols, index=df.index)
```

这与之前的操作非常相似，不是吗？我们还需要注意，在创建`user_df`时，我们需要指示`DataFrame`关于列名和`index`。让我们加入并快速查看一下：

```py
#12
df = df.join(user_df)

#13
df[['user'] + user_cols].head(2)
```

输出向我们展示了一切都进行得很顺利。我们很好，但我们还没有完成。如果你在一个单元格中调用`df.columns`，你会看到我们的列名仍然很丑陋。让我们来改变一下：

```py
#14
better_columns = [
    'Budget', 'Clicks', 'Impressions',
    'cmp_name', 'Spent', 'user',
    'Type', 'Start', 'End',
    'Target Age', 'Target Gender', 'Currency',
    'Username', 'Email', 'Name',
    'Gender', 'Age', 'Address',
]
df.columns = better_columns
```

好了！现在，除了`'cmp_name'`和`'user'`之外，我们只有漂亮的名称。

完成`datasetNext`步骤将是添加一些额外的列。对于每个活动，我们有点击次数和展示次数，还有花费金额。这使我们能够引入三个测量比率：**CTR**，**CPC**和**CPI**。它们分别代表**点击通过率**，**每次点击成本**和**每次展示成本**。

最后两个很简单，但 CTR 不是。简而言之，它是点击次数和展示次数之间的比率。它为您提供了一个指标，即有多少次点击是在广告活动上每次展示中进行的-这个数字越高，广告吸引用户点击的成功性就越高：

```py
#15
def calculate_extra_columns(df):
    # Click Through Rate
    df['CTR'] = df['Clicks'] / df['Impressions']
    # Cost Per Click
    df['CPC'] = df['Spent'] / df['Clicks']
    # Cost Per Impression
    df['CPI'] = df['Spent'] / df['Impressions']
calculate_extra_columns(df)
```

我将其写成一个函数，但我也可以直接在单元格中编写代码。这不重要。我想让你注意到的是，我们只需每行代码添加这三列，但`DataFrame`会自动应用操作（在这种情况下是除法）到适当列的每对单元格。因此，即使它们被掩盖为三个除法，这实际上是*5037 * 3*个除法，因为它们是针对每一行执行的。Pandas 为我们做了很多工作，并且很好地隐藏了其复杂性。

函数`calculate_extra_columns`接受`DataFrame`，并直接在其上运行。这种操作模式称为**原地**。你还记得`list.sort()`是如何对列表进行排序的吗？它是一样的。你也可以说这个函数不是纯的，这意味着它具有副作用，因为它修改了作为参数传递的可变对象。

我们可以通过过滤相关列并调用`head`来查看结果：

```py
#16
df[['Spent', 'Clicks', 'Impressions',
    'CTR', 'CPC', 'CPI']].head(3)
```

这向我们展示了每一行上的计算都是正确执行的：

```py
 Spent  Clicks  Impressions       CTR       CPC       CPI
0   39383   62554       499997  0.125109  0.629584  0.078766
1  210452   36176       500001  0.072352  5.817448  0.420903
2  342507   62299       500001  0.124598  5.497793  0.685013
```

现在，我想手动验证第一行的结果的准确性：

```py
#17
clicks = df['Clicks'][0]
impressions = df['Impressions'][0]
spent = df['Spent'][0]
CTR = df['CTR'][0]
CPC = df['CPC'][0]
CPI = df['CPI'][0]
print('CTR:', CTR, clicks / impressions)
print('CPC:', CPC, spent / clicks)
print('CPI:', CPI, spent / impressions)
```

这产生了以下输出：

```py
CTR: 0.1251087506525039 0.1251087506525039
CPC: 0.6295840393899671 0.6295840393899671
CPI: 0.0787664725988356 0.0787664725988356
```

这正是我们在先前的输出中看到的。当然，我通常不需要这样做，但我想向你展示如何以这种方式执行计算。你可以通过将其名称传递给`DataFrame`的方括号来访问`Series`（一列），然后通过其位置访问每一行，就像你使用常规列表或元组一样。

我们的`DataFrame`几乎完成了。我们现在缺少的只是一个列，告诉我们活动的持续时间，以及一个列，告诉我们每个活动的开始日期对应的是一周中的哪一天。这使我能够扩展如何使用`date`对象进行操作：

```py
#18
def get_day_of_the_week(day):
    number_to_day = dict(enumerate(calendar.day_name, 1))
    return number_to_day[day.isoweekday()]

def get_duration(row):
    return (row['End'] - row['Start']).days

df['Day of Week'] = df['Start'].apply(get_day_of_the_week)
df['Duration'] = df.apply(get_duration, axis=1)
```

我们在这里使用了两种不同的技术，但首先是代码。

`get_day_of_the_week`接受一个`date`对象。如果你不明白它的作用，请花点时间自己尝试理解一下，然后再阅读解释。使用我们之前做过几次的从内到外的技术。

所以，我相信你现在已经知道了，如果你将`calendar.day_name`放在`list`调用中，你会得到`['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']`。这意味着，如果我们从`1`开始枚举`calendar.day_name`，我们会得到诸如`(1, 'Monday')`，`(2, 'Tuesday')`等等的对。如果我们将这些对传递给一个字典，我们就得到了一种将星期几与它们的名称相对应的映射关系。当映射创建完成后，为了得到一天的名称，我们只需要知道它的数字。为了得到它，我们调用`date.isoweekday()`，这告诉我们那一天是一周的第几天（作为一个数字）。你将这个数字传递给映射，嘭！你就得到了这一天的名称。

`get_duration` 也很有趣。首先，注意它接受整行数据，而不仅仅是单个值。在函数体内部发生的是我们计算活动结束日期和开始日期之间的差值。当你对`date`对象进行减法运算时，结果是一个`timedelta`对象，它代表了一定的时间量。我们取它的`.days`属性的值。就是这么简单。

现在，我们可以介绍有趣的部分，应用这两个函数。

第一个应用是在`Series`对象上执行的，就像我们之前对`'user'`和`'cmp_name'`做的那样；这里没有什么新的。

第二个应用于整个`DataFrame`，为了指示`pandas`在行上执行该操作，我们传递`axis=1`。

我们可以很容易地验证结果，如下所示：

```py
#19
df[['Start', 'End', 'Duration', 'Day of Week']].head(3)
```

前面的代码产生了以下输出：

```py
 Start         End  Duration Day of Week
0  2019-03-24  2020-11-06       593      Sunday
1  2017-05-21  2018-07-24       429      Sunday
2  2017-12-18  2018-02-08        52      Monday
```

所以，我们现在知道在 2019 年 3 月 24 日和 2020 年 11 月 6 日之间有 593 天，2019 年 3 月 24 日是星期日。

如果你想知道这样做的目的是什么，我会举个例子。想象一下，你有一个与通常在星期日举行的体育赛事相关联的活动。你可能想根据日期检查你的数据，以便将它们与你拥有的各种测量结果相关联。我们在这个项目中不打算这样做，但是看到这种方式在`DataFrame`上调用`apply()`是很有用的。

# 清理一切

现在我们已经得到了我们想要的一切，是时候进行最后的清理了；记住我们仍然有`'cmp_name'`和`'user'`列。现在它们没有用了，所以它们必须离开。另外，我想重新排列`DataFrame`中的列，使其更相关于它现在包含的数据。为了做到这一点，我们只需要根据我们想要的列列表对`df`进行过滤。我们将得到一个全新的`DataFrame`，我们可以重新分配给`df`本身：

```py
#20
final_columns = [
    'Type', 'Start', 'End', 'Duration', 'Day of Week', 'Budget',
    'Currency', 'Clicks', 'Impressions', 'Spent', 'CTR', 'CPC',
    'CPI', 'Target Age', 'Target Gender', 'Username', 'Email',
    'Name', 'Gender', 'Age'
]
df = df[final_columns]
```

我将活动信息分组放在前面，然后是测量数据，最后是用户数据。现在我们的`DataFrame`已经干净，可以供我们检查。

在我们开始用图表疯狂之前，怎么样先对`DataFrame`进行快照，这样我们就可以很容易地从文件中重新构建它，而不必重新做到这里的所有步骤。一些分析师可能希望以电子表格形式保存它，以进行与我们想要进行的不同类型的分析，所以让我们看看如何将`DataFrame`保存到文件。这比说起来更容易。

# 将 DataFrame 保存到文件

我们可以以许多不同的方式保存`DataFrame`。你可以输入`df.to_`，然后按下*Tab*键，使自动补全弹出，以查看所有可能的选项。

我们将以三种不同的格式保存`DataFrame`，只是为了好玩。首先是 CSV：

```py
#21
df.to_csv('df.csv')
```

然后是 JSON：

```py
#22
df.to_json('df.json')
```

最后，在 Excel 电子表格中：

```py
#23
df.to_excel('df.xls')
```

CSV 文件如下（输出截断）：

```py
,Type,Start,End,Duration,Day of Week,Budget,Currency,Clicks,Im
0,KTR,2019-03-24,2020-11-06,593,Sunday,847110,EUR,62554,499997
1,GRZ,2017-05-21,2018-07-24,429,Sunday,510835,GBP,36176,500001
2,KTR,2017-12-18,2018-02-08,52,Monday,720897,GBP,62299,500001,
```

JSON 的输出如下（同样，输出截断）：

```py
{
 "Age": {
 "0": 29,
 "1": 29,
 "10": 80,
```

所以，将`DataFrame`以许多不同的格式保存是非常容易的，好消息是反之亦然：将电子表格加载到`DataFrame`中也非常容易。`pandas`背后的程序员们为了简化我们的任务走了很长的路，这是值得感激的。

# 可视化结果

最后，精彩的部分。在本节中，我们将可视化一些结果。从数据科学的角度来看，我对深入分析并不感兴趣，特别是因为数据是完全随机的，但是，这段代码将帮助您开始使用图形和其他功能。

我在生活中学到的一件事，也许这会让您感到惊讶，那就是—*外表也很重要*，因此当您呈现您的结果时，您应该尽力*使它们漂亮*。

首先，我们告诉`pandas`在单元格输出框中呈现图形，这很方便。我们用以下方法做到这一点：

```py
#24
%matplotlib inline
```

然后，我们进行一些样式处理：

```py
#25
import matplotlib.pyplot as plt
plt.style.use(['classic', 'ggplot'])
import pylab
pylab.rcParams.update({'font.family' : 'serif'})
```

它的目的是让我们在本节中查看的图形看起来更漂亮一些。您也可以在从控制台启动笔记本时传递参数来指示笔记本执行此操作，但我也想向您展示这种方式，因为如果您想绘制某些东西就必须重新启动笔记本可能会很烦人。通过这种方式，您可以即时执行，然后继续工作。

我们还使用`pylab`来将`font.family`设置为`serif`。这在您的系统上可能并不是必要的。尝试将其注释掉并执行笔记本，看看是否有任何变化。

现在`DataFrame`完成了，让我们再次运行`df.describe()`（`#26`）。结果应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00020.jpeg)

这种快速结果非常适合满足那些只有 20 秒时间来关注你并且只想要粗略数字的经理们。

再次，请记住我们的广告系列有不同的货币，因此这些数字实际上是没有意义的。这里的重点是演示`DataFrame`的功能，而不是进行正确或详细的真实数据分析。

另外，图表通常比带有数字的表格要好得多，因为它更容易阅读，并且可以立即给出反馈。因此，让我们绘制出每个广告系列的四个信息—`'Budget'`、`'Spent'`、`'Clicks'`和`'Impressions'`：

```py
#27
df[['Budget', 'Spent', 'Clicks', 'Impressions']].hist(
    bins=16, figsize=(16, 6));
```

我们推断这四列（这将给我们另一个只由这些列组成的`DataFrame`）并在其上调用直方图`hist()`方法。我们对箱子和图形大小进行了一些测量，但基本上一切都是自动完成的。

一个重要的事情：由于这个指令是这个单元格中唯一的指令（这也意味着，它是最后一个），笔记本会在绘制图形之前打印其结果。要抑制这种行为，只绘制图形而不打印任何内容，只需在末尾加上一个分号（你以为我在怀念 Java，不是吗？）。这里是图形：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00021.jpeg)

它们很漂亮，不是吗？您有没有注意到衬线字体？这些数字的含义如何？如果您回过头看一下我们生成数据的方式，您会发现所有这些图形都是完全合理的：

+   预算只是一个在间隔内的随机整数，因此我们预期是均匀分布，而我们确实有；它几乎是一条恒定的线。

+   花费也是均匀分布，但其间隔的高端是预算，而预算是在变化的。这意味着我们应该期望类似于向右减少的二次双曲线。而它也在那里。

+   点击是用三角形分布生成的，平均值大约是间隔大小的 20%，您可以看到峰值就在那里，大约向左 20%。

+   印象是一个高斯分布，这是假设著名的钟形曲线的分布。平均值恰好在中间，标准偏差为 2。您可以看到图形符合这些参数。

好了！让我们绘制出我们计算的测量值：

```py
#28
df[['CTR', 'CPC', 'CPI']].hist(
    bins=20, figsize=(16, 6))
```

这是图形表示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00022.jpeg)

我们可以看到 CPC 向左高度倾斜，这意味着大多数 CPC 值非常低。CPI 形状类似，但不那么极端。

现在，这一切都很好，但如果你只想分析数据的特定部分，你该怎么做呢？我们可以对`DataFrame`应用一个掩码，这样我们就可以得到另一个只包含满足掩码条件的行的`DataFrame`。这就像应用全局的、逐行的`if`子句一样：

```py
#29
mask = (df.Spent > 0.75 * df.Budget)
df[mask][['Budget', 'Spent', 'Clicks', 'Impressions']].hist(
    bins=15, figsize=(16, 6), color='g');
```

在这种情况下，我准备了`mask`，以过滤掉花费金额少于或等于预算的所有行。换句话说，我们只包括那些花费至少达到预算四分之三的广告系列。请注意，在`mask`中，我向你展示了一种请求`DataFrame`列的替代方式，即使用直接属性访问（`object.property_name`），而不是类似字典的访问（`object['property_name']`）。如果`property_name`是一个有效的 Python 名称，你可以交替使用这两种方式（JavaScript 也是这样工作的）。

`mask`的应用方式类似于我们访问带有键的字典。当你将`mask`应用到`DataFrame`上时，你会得到另一个`DataFrame`，然后我们只选择相关的列，并再次调用`hist()`。这一次，只是为了好玩，我们希望结果是绿色的：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00023.jpeg)

请注意，图形的形状除了'花费'图形之外，基本没有改变，'花费'图形非常不同。原因是我们只要求包括花费金额至少达到预算的行。这意味着我们只包括了花费接近预算的行。预算数字来自均匀分布。因此，很明显，'花费'图形现在呈现出这种形状。如果你把边界设得更紧，要求达到 85%或更多，你会看到'花费'图形越来越像预算图形。

现在让我们来看看不同的东西。如何按星期几分组测量'花费'、'点击'和'展示'的指标：

```py
#30
df_weekday = df.groupby(['Day of Week']).sum()
df_weekday[['Impressions', 'Spent', 'Clicks']].plot(
    figsize=(16, 6), subplots=True);
```

第一行通过在`df`上按照'星期几'分组来创建一个新的`DataFrame`，`df_weekday`。用于聚合数据的函数是加法。

第二行使用列名列表获取`df_weekday`的一个切片，这是我们现在习惯的做法。然后我们调用`plot()`，这和`hist()`有点不同。`subplots=True`选项使`plot`绘制三个独立的图形：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00024.jpeg)

有趣的是，我们可以看到大部分活动发生在星期日和星期三。如果这是有意义的数据，这可能是向客户提供重要信息的原因，这就是为什么我向你展示这个例子。

请注意，日期按字母顺序排序，这有点混乱。你能想到一个快速的解决方案来解决这个问题吗？我把这个问题留给你作为一个练习来解决。

让我们用几个简单的聚合来结束这个演示部分。我们想在'Target Gender'和'Target Age'上进行聚合，并显示'Impressions'和'Spent'。对于这两个指标，我们想看到'平均值'和标准差（'std'）：

```py
#31
agg_config = {
    'Impressions': ['mean', 'std'],
    'Spent': ['mean', 'std'],
}
df.groupby(['Target Gender', 'Target Age']).agg(agg_config)
```

这很容易做。我们将准备一个字典作为配置。然后，我们对'Target Gender'和'Target Age'列进行分组，并将我们的配置字典传递给`agg()`方法。结果被截断和重新排列了一点，以使其适应，并在这里显示：

```py
 Impressions                    Spent
                                   mean       std           mean
Target Gender Target Age                                        
B             20-25       499999.741573  1.904111  218917.000000
              20-30       499999.618421  2.039393  237180.644737
              20-35       499999.358025  2.039048  256378.641975
...                                 ...       ...            ...
M             20-25       499999.355263  2.108421  277232.276316
              20-30       499999.635294  2.075062  252140.117647
              20-35       499999.835821  1.871614  308598.149254 
```

当然，这是文本表示，但你也可以有 HTML 表示。

在我们结束本章之前，让我们做一件事。我想向你展示一个叫做**数据透视表**的东西。在数据环境中，这是一个流行词，所以这样一个简单的例子是必不可少的：

```py
#32
pivot = df.pivot_table(
    values=['Impressions', 'Clicks', 'Spent'],
    index=['Target Age'],
    columns=['Target Gender'],
    aggfunc=np.sum
)
pivot
```

我们创建了一个数据透视表，显示了“目标年龄”和“展示次数”、“点击次数”和“花费”之间的相关性。最后三个将根据“目标性别”进行细分。用于计算结果的聚合函数（aggfunc）是 numpy.sum 函数（如果我没有指定任何内容，numpy.mean 将是默认值）。

创建了数据透视表之后，我们只需用单元格中的最后一行打印它，这里是结果的一部分：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00025.jpeg)

当数据有意义时，它非常清晰并提供非常有用的信息。

就是这样！我会让你自己去探索 IPython、Jupyter 和数据科学的美妙世界。我强烈建议你熟悉 Notebook 环境。它比控制台好得多，非常实用和有趣，你甚至可以用它创建幻灯片和文档。

# 接下来我们去哪里？

数据科学确实是一个迷人的课题。正如我在介绍中所说的，那些想要深入研究它的人需要在数学和统计学方面接受良好的训练。与插值不正确的数据一起工作会使得任何关于它的结果变得毫无意义。同样，对于不正确外推或以错误频率采样的数据也是如此。举个例子，想象一群排队的人，如果由于某种原因，这群人的性别在男女之间交替，那么排队就会是这样：F-M-F-M-F-M-F-M-F...

如果你只取偶数元素进行采样，你会得出结论说这个群体只由男性组成，而采样奇数元素会告诉你完全相反的结论。

当然，这只是一个愚蠢的例子，我知道，但在这个领域很容易犯错，特别是在处理大数据时，采样是强制性的，因此，你所做的内省的质量首先取决于采样本身的质量。

在数据科学和 Python 方面，这些是你想要了解的主要工具：

+   NumPy（http://www.numpy.org/）：这是用 Python 进行科学计算的主要包。它包含一个强大的 N 维数组对象，复杂的（广播）函数，用于集成 C/C++和 Fortran 代码的工具，有用的线性代数，傅里叶变换，随机数功能等等。

+   Scikit-Learn（http://scikit-learn.org/）：这可能是 Python 中最流行的机器学习库。它具有简单高效的数据挖掘和数据分析工具，适用于所有人，并且可以在各种环境中重复使用。它构建在 NumPy、SciPy 和 Matplotlib 之上。

+   Pandas（http://pandas.pydata.org/）：这是一个开源的、BSD 许可的库，提供高性能、易于使用的数据结构和数据分析工具。我们在本章中一直在使用它。

+   IPython（http://ipython.org/）/Jupyter（http://jupyter.org/）：这提供了丰富的交互式计算架构。

+   Matplotlib（http://matplotlib.org/）：这是一个 Python 2-D 绘图库，可以在各种硬拷贝格式和交互式环境中生成出版质量的图形。Matplotlib 可以在 Python 脚本、Python 和 IPython shell、Jupyter Notebook、Web 应用程序服务器和四个图形用户界面工具包中使用。

+   Numba（http://numba.pydata.org/）：这使您能够通过直接在 Python 中编写高性能函数来加速应用程序。通过一些注释，面向数组和数学密集型的 Python 代码可以即时编译为本机机器指令，性能类似于 C、C++和 Fortran，而无需切换语言或 Python 解释器。

+   **Bokeh** ([`bokeh.pydata.org/`](https://bokeh.pydata.org/))：这是一个 Python 交互式可视化库，旨在面向现代网络浏览器进行演示。它的目标是以 D3.js 的风格提供优雅、简洁的新图形构建，同时在非常大或流式数据集上提供高性能的交互能力。

除了这些单一的库之外，你还可以找到生态系统，比如**SciPy** ([`scipy.org/`](http://scipy.org/)) 和前面提到的**Anaconda** ([`anaconda.org/`](https://anaconda.org/))，它们捆绑了几个不同的软件包，以便为您提供一个“开箱即用”的解决方案。

在一些系统上安装所有这些工具及其多个依赖项是很困难的，所以我建议你也尝试一下生态系统，看看你是否对它们感到舒适。这可能是值得的。

# 总结

在这一章中，我们谈到了数据科学。我们并没有试图解释这个极其广泛的主题，而是深入了一个项目。我们熟悉了 Jupyter Notebook，以及不同的库，比如 Pandas、Matplotlib 和 NumPy。

当然，不得不把所有这些信息压缩到一个章节中意味着我只能简要地涉及我提出的主题。我希望我们一起经历的项目足够全面，让你对在这个领域工作时可能遵循的工作流程有所了解。

下一章专门讨论网页开发。所以，请确保你已经准备好浏览器，让我们开始吧！
