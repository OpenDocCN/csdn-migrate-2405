# Python 编程学习手册第二版（二）

> 原文：[`zh.annas-archive.org/md5/406733548F67B770B962DA4756270D5F`](https://zh.annas-archive.org/md5/406733548F67B770B962DA4756270D5F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：迭代和做决定

“疯狂：一遍又一遍地做同样的事情，却期待不同的结果。”- 阿尔伯特·爱因斯坦

在上一章中，我们看了 Python 的内置数据类型。现在你已经熟悉了数据的各种形式和形状，是时候开始看看程序如何使用它了。

根据维基百科：

在计算机科学中，控制流（或者叫控制流程）是指规定命令式程序的各个语句、指令或函数调用的执行或评估顺序。

为了控制程序的流程，我们有两个主要的工具：**条件编程**（也称为**分支**）和**循环**。我们可以以许多不同的组合和变体使用它们，但在本章中，我不打算以*文档*的方式介绍这两个结构的所有可能形式，而是给你一些基础知识，然后和你一起编写一些小脚本。在第一个脚本中，我们将看到如何创建一个简单的素数生成器，而在第二个脚本中，我们将看到如何根据优惠券给顾客打折。这样，你应该更好地了解条件编程和循环如何使用。

在本章中，我们将涵盖以下内容：

+   条件编程

+   Python 中的循环

+   快速浏览`itertools`模块

# 条件编程

条件编程，或者分支，是你每天、每时每刻都在做的事情。它涉及评估条件：*如果交通灯是绿色的，那么我可以过去；* *如果下雨，那么我会带伞；* *如果我上班迟到了，那么我会打电话给我的经理*。

主要工具是`if`语句，它有不同的形式和颜色，但基本上它评估一个表达式，并根据结果选择要执行的代码部分。像往常一样，让我们看一个例子：

```py
# conditional.1.py
late = True 
if late: 
    print('I need to call my manager!') 
```

这可能是最简单的例子：当传递给`if`语句时，`late`充当条件表达式，在布尔上下文中进行评估（就像我们调用`bool(late)`一样）。如果评估的结果是`True`，那么我们就进入`if`语句后面的代码体。请注意，`print`指令是缩进的：这意味着它属于由`if`子句定义的作用域。执行这段代码会产生：

```py
$ python conditional.1.py
I need to call my manager!
```

由于`late`是`True`，`print`语句被执行了。让我们扩展一下这个例子：

```py
# conditional.2.py
late = False 
if late: 
    print('I need to call my manager!')  #1 
else: 
    print('no need to call my manager...')  #2 
```

这次我设置了`late = False`，所以当我执行代码时，结果是不同的：

```py
$ python conditional.2.py
no need to call my manager...
```

根据评估`late`表达式的结果，我们可以进入块`#1`或块`#2`，*但不能同时进入*。当`late`评估为`True`时，执行块`#1`，而当`late`评估为`False`时，执行块`#2`。尝试给`late`名称分配`False`/`True`值，并看看这段代码的输出如何相应地改变。

前面的例子还介绍了`else`子句，当我们想要在`if`子句中的表达式评估为`False`时提供一组备用指令时，它非常方便。`else`子句是可选的，通过比较前面的两个例子可以明显看出。

# 一个专门的 else - elif

有时，您只需要在满足条件时执行某些操作（简单的`if`子句）。在其他时候，您需要提供一个替代方案，以防条件为`False`（`if`/`else`子句），但有时您可能有更多的选择路径，因此，由于调用经理（或不调用他们）是一种二进制类型的示例（要么您打电话，要么您不打电话），让我们改变示例的类型并继续扩展。这次，我们决定税收百分比。如果我的收入低于$10,000，我将不支付任何税。如果在$10,000 和$30,000 之间，我将支付 20%的税。如果在$30,000 和$100,000 之间，我将支付 35%的税，如果超过$100,000，我将（很高兴）支付 45%的税。让我们把这一切都写成漂亮的 Python 代码：

```py
# taxes.py
income = 15000 
if income < 10000: 
    tax_coefficient = 0.0  #1 
elif income < 30000: 
    tax_coefficient = 0.2  #2 
elif income < 100000: 
    tax_coefficient = 0.35  #3 
else: 
    tax_coefficient = 0.45  #4 

print('I will pay:', income * tax_coefficient, 'in taxes') 
```

执行上述代码产生的结果：

```py
$ python taxes.py
I will pay: 3000.0 in taxes
```

让我们逐行通过这个例子：我们首先设置收入值。在这个例子中，我的收入是$15,000。我们进入`if`子句。请注意，这一次我们还引入了`elif`子句，它是`else-if`的缩写，与裸的`else`子句不同，它也有自己的条件。因此，`income < 10000`的`if`表达式评估为`False`，因此块`#1`不被执行。

控制传递给下一个条件评估器：`elif income < 30000`。这个评估为`True`，因此块`#2`被执行，因此，Python 在整个`if`/`elif`/`elif`/`else`子句之后恢复执行（我们现在可以称之为`if`子句）。在`if`子句之后只有一条指令，即`print`调用，它告诉我们今年我将支付`3000.0`的税（*15,000 * 20%*）。请注意，顺序是强制的：`if`首先出现，然后（可选）是尽可能多的`elif`子句，然后（可选）是一个`else`子句。

有趣，对吧？无论每个块内有多少行代码，当其中一个条件评估为`True`时，相关的块将被执行，然后在整个子句之后恢复执行。如果没有一个条件评估为`True`（例如，`income = 200000`），那么`else`子句的主体将被执行（块`#4`）。这个例子扩展了我们对`else`子句行为的理解。当之前的`if`/`elif`/.../`elif`表达式没有评估为`True`时，它的代码块被执行。

尝试修改`income`的值，直到您可以随意执行所有块（每次执行一个）。然后尝试**边界**。这是至关重要的，每当您将条件表达为**相等**或**不等**（`==`，`!=`，`<`，`>`，`<=`，`>=`）时，这些数字代表边界。彻底测试边界是至关重要的。我是否允许您在 18 岁或 17 岁时开车？我是用`age < 18`还是`age <= 18`来检查您的年龄？您无法想象有多少次我不得不修复由于使用错误的运算符而产生的微妙错误，因此继续并尝试修改上述代码。将一些`<`更改为`<=`，并将收入设置为边界值之一（10,000，30,000，100,000）以及之间的任何值。看看结果如何变化，并在继续之前对其有一个很好的理解。

现在让我们看另一个示例，向我们展示如何嵌套`if`子句。假设您的程序遇到错误。如果警报系统是控制台，我们打印错误。如果警报系统是电子邮件，我们根据错误的严重程度发送它。如果警报系统不是控制台或电子邮件之外的任何其他东西，我们不知道该怎么办，因此我们什么也不做。让我们把这写成代码：

```py
# errorsalert.py
alert_system = 'console'  # other value can be 'email' 
error_severity = 'critical'  # other values: 'medium' or 'low' 
error_message = 'OMG! Something terrible happened!' 

if alert_system == 'console': 
    print(error_message)  #1 
elif alert_system == 'email': 
    if error_severity == 'critical': 
        send_email('admin@example.com', error_message)  #2 
    elif error_severity == 'medium': 
        send_email('support.1@example.com', error_message)  #3 
    else: 
        send_email('support.2@example.com', error_message)  #4 
```

上面的例子非常有趣，因为它很愚蠢。它向我们展示了两个嵌套的`if`子句（**外部**和**内部**）。它还向我们展示了外部`if`子句没有任何`else`，而内部`if`子句有。请注意，缩进是允许我们将一个子句嵌套在另一个子句中的原因。

如果`alert_system == 'console'`，则执行`#1`部分，其他情况则不执行。另一方面，如果`alert_system == 'email'`，那么我们进入另一个`if`子句，我们称之为内部。在内部`if`子句中，根据`error_severity`，我们向管理员、一级支持或二级支持发送电子邮件（块`#2`，`#3`和`#4`）。在此示例中未定义`send_email`函数，因此尝试运行它会导致错误。在本书的源代码中，您可以从网站下载，我包含了一个技巧，将该调用重定向到常规的`print`函数，这样您就可以在控制台上进行实验，而不必实际发送电子邮件。尝试更改值，看看它是如何工作的。

# 三元运算符

在转移到下一个主题之前，我想向您展示的最后一件事是**三元运算符**，或者通俗地说，是`if`/`else`子句的简短版本。当根据某个条件来分配名称的值时，有时使用三元运算符而不是适当的`if`子句更容易阅读。在下面的示例中，两个代码块完全做同样的事情：

```py
# ternary.py
order_total = 247  # GBP 

# classic if/else form 
if order_total > 100: 
    discount = 25  # GBP 
else: 
    discount = 0  # GBP 
print(order_total, discount) 

# ternary operator 
discount = 25 if order_total > 100 else 0 
print(order_total, discount) 
```

对于这样简单的情况，我发现能够用一行代码来表达这种逻辑非常好，而不是用四行。记住，作为编码人员，您花在阅读代码上的时间远远多于编写代码的时间，因此 Python 的简洁性是无价的。

您清楚三元运算符是如何工作的吗？基本上，`name = something if condition else something-else`。因此，如果`condition`评估为`True`，则`name`被分配为`something`，如果`condition`评估为`False`，则为`something-else`。

现在您已经了解了如何控制代码的路径，让我们继续下一个主题：*循环*。

# 循环

如果您在其他编程语言中有循环的经验，您会发现 Python 的循环方式有些不同。首先，什么是循环？**循环**意味着能够根据给定的循环参数多次重复执行代码块。有不同的循环结构，它们有不同的目的，Python 已将它们全部简化为只有两种，您可以使用它们来实现您需要的一切。这些是`for`和`while`语句。

虽然使用它们中的任何一个都可以做你需要做的一切，但它们有不同的目的，因此它们通常在不同的上下文中使用。我们将在本章中深入探讨这种差异。

# `for`循环

当循环遍历序列时，例如列表、元组或对象集合时，使用`for`循环。让我们从一个简单的示例开始，扩展概念，看看 Python 语法允许我们做什么：

```py
# simple.for.py
for number in [0, 1, 2, 3, 4]: 
    print(number) 
```

这段简单的代码片段在执行时打印从`0`到`4`的所有数字。`for`循环接收到列表`[0, 1, 2, 3, 4]`，在每次迭代时，`number`从序列中获得一个值（按顺序迭代），然后执行循环体（打印行）。`number`的值在每次迭代时都会更改，根据序列中接下来的值。当序列耗尽时，`for`循环终止，代码的执行在循环后恢复正常。

# 遍历范围

有时我们需要遍历一系列数字，将其硬编码到某个地方将会很不方便。在这种情况下，`range`函数就派上用场了。让我们看看前面代码片段的等价物：

```py
# simple.for.py
for number in range(5): 
    print(number) 
```

在 Python 程序中，`range`函数在创建序列时被广泛使用：您可以通过传递一个值来调用它，该值充当`stop`（从`0`开始计数），或者您可以传递两个值（`start`和`stop`），甚至三个值（`start`，`stop`和`step`）。查看以下示例：

```py
>>> list(range(10))  # one value: from 0 to value (excluded)
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
>>> list(range(3, 8))  # two values: from start to stop (excluded)
[3, 4, 5, 6, 7]
>>> list(range(-10, 10, 4))  # three values: step is added
[-10, -6, -2, 2, 6]
```

暂时忽略我们需要在`range(...)`内部包装一个`list`。`range`对象有点特殊，但在这种情况下，我们只对了解它将向我们返回什么值感兴趣。您可以看到，切片的处理方式与之相同：`start`包括在内，`stop`排除在外，还可以添加一个`step`参数，其默认值为`1`。

尝试修改我们的`simple.for.py`代码中`range()`调用的参数，并查看它打印出什么。熟悉它。

# 在序列上进行迭代

现在我们有了迭代序列的所有工具，所以让我们在此基础上构建示例：

```py
# simple.for.2.py
surnames = ['Rivest', 'Shamir', 'Adleman'] 
for position in range(len(surnames)): 
    print(position, surnames[position]) 
```

前面的代码给游戏增加了一点复杂性。执行将显示此结果：

```py
$ python simple.for.2.py
0 Rivest
1 Shamir
2 Adleman
```

让我们使用**从内到外**的技术来分解它，好吗？我们从我们试图理解的最内部部分开始，然后向外扩展。因此，`len(surnames)`是`surnames`列表的长度：`3`。因此，`range(len(surnames))`实际上被转换为`range(3)`。这给我们提供了范围[0, 3)，基本上是一个序列（`0`，`1`，`2`）。这意味着`for`循环将运行三次迭代。在第一次迭代中，`position`将取值`0`，而在第二次迭代中，它将取值`1`，最后在第三次和最后一次迭代中取值`2`。如果不是`surnames`列表的可能索引位置（`0`，`1`，`2`），那是什么？在位置`0`，我们找到`'Rivest'`，在位置`1`，`'Shamir'`，在位置`2`，`'Adleman'`。如果您对这三个人一起创造了什么感到好奇，请将`print(position, surnames[position])`更改为`print(surnames[position][0], end='')`，在循环之外添加最后一个`print()`，然后再次运行代码。

现在，这种循环的风格实际上更接近于 Java 或 C++等语言。在 Python 中，很少见到这样的代码。您可以只是迭代任何序列或集合，因此没有必要在每次迭代时获取位置列表并从序列中检索元素。这是昂贵的，没有必要的昂贵。让我们将示例改为更符合 Python 风格的形式：

```py
# simple.for.3.py
surnames = ['Rivest', 'Shamir', 'Adleman'] 
for surname in surnames: 
    print(surname) 
```

现在这就是了！它几乎是英语。`for`循环可以在`surnames`列表上进行迭代，并且在每次交互中按顺序返回每个元素。运行此代码将逐个打印出三个姓氏。阅读起来更容易，对吧？

但是，如果您想要打印位置呢？或者如果您实际上需要它呢？您应该回到`range(len(...))`形式吗？不。您可以使用`enumerate`内置函数，就像这样：

```py
# simple.for.4.py
surnames = ['Rivest', 'Shamir', 'Adleman'] 
for position, surname in enumerate(surnames): 
    print(position, surname) 
```

这段代码也非常有趣。请注意，`enumerate`在每次迭代时都会返回一个两元组（`position，surname`），但仍然比`range(len(...))`示例更可读（更有效）。您可以使用`start`参数调用`enumerate`，例如`enumerate(iterable, start)`，它将从`start`开始，而不是`0`。这只是另一件小事，向您展示了 Python 在设计时考虑了多少，以便使您的生活更轻松。

您可以使用`for`循环来迭代列表、元组和一般 Python 称为可迭代的任何东西。这是一个非常重要的概念，所以让我们再谈一谈。

# 迭代器和可迭代对象

根据 Python 文档（[`docs.python.org/3/glossary.html`](https://docs.python.org/3/glossary.html)）的说法，可迭代对象是：

能够逐个返回其成员的对象。可迭代对象的示例包括所有序列类型（如列表、str 和元组）和一些非序列类型，如字典、文件对象和您使用 __iter__()或 __getitem__()方法定义的任何类的对象。可迭代对象可以在 for 循环和许多其他需要序列的地方使用（zip()、map()等）。当将可迭代对象作为参数传递给内置函数 iter()时，它会返回该对象的迭代器。该迭代器对值集合进行一次遍历。在使用可迭代对象时，通常不需要调用 iter()或自己处理迭代器对象。for 语句会自动为您执行这些操作，为循环的持续时间创建一个临时的无名变量来保存迭代器。

简而言之，当你写`for k in sequence: ... body ...`时，`for`循环会向`sequence`请求下一个元素，它会得到一些返回值，将返回值称为`k`，然后执行其主体。然后，再次，`for`循环会向`sequence`请求下一个元素，再次将其称为`k`，并再次执行主体，依此类推，直到序列耗尽。空序列将导致主体执行零次。

一些数据结构在进行迭代时按顺序产生它们的元素，例如列表、元组和字符串，而另一些则不会，例如集合和字典（Python 3.6 之前）。Python 让我们能够迭代可迭代对象，使用一种称为**迭代器**的对象类型。

根据官方文档（[`docs.python.org/3/glossary.html`](https://docs.python.org/3/glossary.html)）的说法，迭代器是：

代表数据流的对象。对迭代器的 __next__()方法进行重复调用（或将其传递给内置函数 next()）会返回数据流中的连续项目。当没有更多数据可用时，会引发 StopIteration 异常。此时，迭代器对象已耗尽，对其 __next__()方法的任何进一步调用都会再次引发 StopIteration。迭代器需要具有一个返回迭代器对象本身的 __iter__()方法，因此每个迭代器也是可迭代的，并且可以在大多数其他可接受可迭代对象的地方使用。一个值得注意的例外是尝试多次迭代传递的代码。容器对象（如列表）每次将其传递给 iter()函数或在 for 循环中使用时都会产生一个全新的迭代器。尝试对迭代器执行此操作将只返回上一次迭代传递中使用的相同耗尽的迭代器对象，使其看起来像一个空容器。

如果你不完全理解前面的法律术语，不要担心，你以后会理解的。我把它放在这里作为将来的方便参考。

实际上，整个可迭代/迭代器机制在代码后面有些隐藏。除非出于某种原因需要编写自己的可迭代或迭代器，否则你不必过多担心这个问题。但是理解 Python 如何处理这一关键的控制流方面非常重要，因为它将塑造你编写代码的方式。

# 遍历多个序列

让我们看另一个例子，如何迭代两个相同长度的序列，以便处理它们各自的元素对。假设我们有一个人员列表和一个代表第一个列表中人员年龄的数字列表。我们想要打印所有人员的姓名/年龄对。让我们从一个例子开始，然后逐渐完善它：

```py
# multiple.sequences.py
people = ['Conrad', 'Deepak', 'Heinrich', 'Tom']
ages = [29, 30, 34, 36]
for position in range(len(people)):
    person = people[position]
    age = ages[position]
    print(person, age)
```

到目前为止，这段代码对你来说应该很容易理解。我们需要遍历位置列表（`0`，`1`，`2`，`3`），因为我们想要从两个不同的列表中检索元素。执行后，我们得到以下结果：

```py
$ python multiple.sequences.py
Conrad 29
Deepak 30
Heinrich 34
Tom 36
```

这段代码既低效又不符合 Python 风格。它是低效的，因为根据位置检索元素可能是一个昂贵的操作，并且我们在每次迭代时都是从头开始做的。邮递员在递送信件时不会每次都回到路的起点，对吧？他们从一户到另一户。让我们尝试使用`enumerate`使其更好：

```py
# multiple.sequences.enumerate.py
people = ['Conrad', 'Deepak', 'Heinrich', 'Tom']
ages = [29, 30, 34, 36]
for position, person in enumerate(people):
    age = ages[position]
    print(person, age)
```

这样做更好，但还不完美。而且还有点丑陋。我们在`people`上进行了适当的迭代，但仍然使用位置索引获取`age`，我们也想要摆脱。别担心，Python 给了你`zip`函数，记得吗？让我们使用它：

```py
# multiple.sequences.zip.py
people = ['Conrad', 'Deepak', 'Heinrich', 'Tom']
ages = [29, 30, 34, 36]
for person, age in zip(people, ages):
    print(person, age)
```

啊！好多了！再次将前面的代码与第一个示例进行比较，并欣赏 Python 的优雅之处。我想展示这个例子的原因有两个。一方面，我想让您了解 Python 中较短的代码与其他语言相比有多么简洁，其他语言的语法不允许您像这样轻松地迭代序列或集合。另一方面，更重要的是，请注意，当`for`循环请求`zip(sequenceA, sequenceB)`的下一个元素时，它会得到一个元组，而不仅仅是一个单一对象。它会得到一个元组，其中包含与我们提供给`zip`函数的序列数量一样多的元素。让我们通过两种方式扩展前面的示例，使用显式和隐式赋值：

```py
# multiple.sequences.explicit.py
people = ['Conrad', 'Deepak', 'Heinrich', 'Tom']
ages = [29, 30, 34, 36]
nationalities = ['Poland', 'India', 'South Africa', 'England']
for person, age, nationality in zip(people, ages, nationalities):
    print(person, age, nationality)
```

在前面的代码中，我们添加了国籍列表。现在我们向`zip`函数提供了三个序列，for 循环在每次迭代时都会返回一个*三元组*。请注意，元组中元素的位置与`zip`调用中序列的位置相对应。执行代码将产生以下结果：

```py
$ python multiple.sequences.explicit.py
Conrad 29 Poland
Deepak 30 India
Heinrich 34 South Africa
Tom 36 England
```

有时，由于在前面的简单示例中可能不太清楚的原因，您可能希望在`for`循环的主体中分解元组。如果这是您的愿望，完全可以做到：

```py
# multiple.sequences.implicit.py
people = ['Conrad', 'Deepak', 'Heinrich', 'Tom']
ages = [29, 30, 34, 36]
nationalities = ['Poland', 'India', 'South Africa', 'England']
for data in zip(people, ages, nationalities):
    person, age, nationality = data
    print(person, age, nationality)
```

它基本上是在某些情况下自动为您执行`for`循环的操作，但是在某些情况下，您可能希望自己执行。在这里，来自`zip(...)`的三元组`data`在`for`循环的主体中被分解为三个变量：`person`、`age`和`nationality`。

# while 循环

在前面的页面中，我们看到了`for`循环的运行情况。当您需要循环遍历一个序列或集合时，它非常有用。需要记住的关键点是，当您需要能够区分使用哪种循环结构时，`for`循环在必须迭代有限数量的元素时非常有效。它可以是一个巨大的数量，但是仍然是在某个点结束的东西。

然而，还有其他情况，当您只需要循环直到满足某个条件，甚至无限循环直到应用程序停止时，例如我们实际上没有东西可以迭代，因此`for`循环将是一个不好的选择。但是不用担心，对于这些情况，Python 为我们提供了`while`循环。

`while`循环类似于`for`循环，因为它们都循环，并且在每次迭代时执行一组指令。它们之间的不同之处在于`while`循环不会循环遍历一个序列（它可以，但您必须手动编写逻辑，而且这没有任何意义，您只想使用`for`循环），而是只要满足某个条件就会循环。当条件不再满足时，循环结束。

像往常一样，让我们看一个示例，以便更好地理解。我们想要打印一个正数的二进制表示。为了做到这一点，我们可以使用一个简单的算法，它收集除以`2`的余数（以相反的顺序），结果就是数字本身的二进制表示：

```py
6 / 2 = 3 (remainder: 0) 
3 / 2 = 1 (remainder: 1) 
1 / 2 = 0 (remainder: 1) 
List of remainders: 0, 1, 1\. 
Inverse is 1, 1, 0, which is also the binary representation of 6: 110
```

让我们编写一些代码来计算数字 39 的二进制表示：100111[2]：

```py
# binary.py
n = 39
remainders = []
while n > 0:
    remainder = n % 2  # remainder of division by 2
    remainders.insert(0, remainder)  # we keep track of remainders
    n //= 2  # we divide n by 2

print(remainders)
```

在前面的代码中，我突出显示了`n > 0`，这是保持循环的条件。我们可以通过使用`divmod`函数使代码变得更短（更符合 Python 风格），该函数使用一个数字和一个除数调用，并返回一个包含整数除法结果及其余数的元组。例如，`divmod(13, 5)`将返回`(2, 3)`，确实*5 * 2 + 3 = 13*：

```py
# binary.2.py
n = 39
remainders = []
while n > 0:
    n, remainder = divmod(n, 2)
    remainders.insert(0, remainder)

print(remainders)
```

在前面的代码中，我们已经将`n`重新分配为除以`2`的结果，并在一行中得到了余数。

请注意，在`while`循环中的条件是继续循环的条件。如果评估为`True`，则执行主体，然后进行另一个评估，依此类推，直到条件评估为`False`。当发生这种情况时，循环立即退出，而不执行其主体。

如果条件永远不会评估为`False`，则循环变成所谓的**无限循环**。无限循环用于例如从网络设备轮询：您询问套接字是否有任何数据，如果有任何数据，则对其进行某些操作，然后您休眠一小段时间，然后再次询问套接字，一遍又一遍，永远不停止。

拥有循环条件或无限循环的能力，这就是为什么仅使用`for`循环是不够的原因，因此 Python 提供了`while`循环。

顺便说一句，如果您需要数字的二进制表示，请查看`bin`函数。

只是为了好玩，让我们使用`while`逻辑来调整一个例子（`multiple.sequences.py`）：

```py
# multiple.sequences.while.py
people = ['Conrad', 'Deepak', 'Heinrich', 'Tom']
ages = [29, 30, 34, 36]
position = 0
while position < len(people):
    person = people[position]
    age = ages[position]
    print(person, age)
    position += 1
```

在前面的代码中，我突出显示了`position`变量的*初始化*、*条件*和*更新*，这使得可以通过手动处理迭代变量来模拟等效的`for`循环代码。所有可以使用`for`循环完成的工作也可以使用`while`循环完成，尽管您可以看到为了实现相同的结果，您需要经历一些样板文件。反之亦然，但除非您有理由这样做，否则您应该使用正确的工具来完成工作，99.9%的时间您都会没问题。

因此，总结一下，当您需要遍历可迭代对象时，请使用`for`循环，当您需要根据满足或不满足的条件循环时，请使用`while`循环。如果您记住了两种目的之间的区别，您将永远不会选择错误的循环结构。

现在让我们看看如何改变循环的正常流程。

# 中断和继续语句

根据手头的任务，有时您需要改变循环的常规流程。您可以跳过单个迭代（任意次数），或者完全退出循环。跳过迭代的常见用例是，例如，当您遍历项目列表并且只有在验证了某些条件时才需要处理每个项目时。另一方面，如果您正在遍历项目集，并且找到了满足您某些需求的项目，您可能决定不继续整个循环，因此退出循环。有无数种可能的情况，因此最好看一些例子。

假设您想对购物篮列表中所有今天到期的产品应用 20%的折扣。您实现这一点的方式是使用`continue`语句，它告诉循环结构（`for`或`while`）立即停止执行主体并继续下一个迭代（如果有的话）。这个例子将带我们深入了解，所以准备好跳下去：

```py
# discount.py
from datetime import date, timedelta

today = date.today()
tomorrow = today + timedelta(days=1)  # today + 1 day is tomorrow
products = [
    {'sku': '1', 'expiration_date': today, 'price': 100.0},
    {'sku': '2', 'expiration_date': tomorrow, 'price': 50},
    {'sku': '3', 'expiration_date': today, 'price': 20},
]

for product in products:
    if product['expiration_date'] != today:
        continue
    product['price'] *= 0.8  # equivalent to applying 20% discount
    print(
        'Price for sku', product['sku'],
        'is now', product['price'])
```

我们首先导入`date`和`timedelta`对象，然后设置我们的产品。`sku`为`1`和`3`的产品具有“今天”的到期日期，这意味着我们希望对它们应用 20%的折扣。我们遍历每个产品并检查到期日期。如果它不是（不等运算符，`!=`）“今天”，我们不希望执行其余的主体套件，因此我们`continue`。

请注意，在代码块中放置`continue`语句的位置并不重要（甚至可以使用多次）。当到达它时，执行停止并返回到下一次迭代。如果我们运行`discount.py`模块，这是输出：

```py
$ python discount.py
Price for sku 1 is now 80.0
Price for sku 3 is now 16.0
```

这向你展示了循环体的最后两行没有被执行，对于`sku`编号`2`。

现在让我们看一个中断循环的例子。假设我们想要判断列表中的至少一个元素在传递给`bool`函数时是否评估为`True`。鉴于我们需要知道是否至少有一个，当我们找到它时，就不需要继续扫描列表。在 Python 代码中，这意味着使用`break`语句。让我们把这写成代码：

```py
# any.py
items = [0, None, 0.0, True, 0, 7]  # True and 7 evaluate to True

found = False  # this is called "flag"
for item in items:
    print('scanning item', item)
    if item:
        found = True  # we update the flag
        break

if found:  # we inspect the flag
    print('At least one item evaluates to True')
else:
    print('All items evaluate to False')
```

前面的代码在编程中是一个常见的模式，你会经常看到它。当你以这种方式检查项目时，基本上你是设置一个`flag`变量，然后开始检查。如果你找到一个符合你标准的元素（在这个例子中，评估为`True`），然后你更新标志并停止迭代。迭代后，你检查标志并相应地采取行动。执行结果是：

```py
$ python any.py
scanning item 0
scanning item None
scanning item 0.0
scanning item True
At least one item evaluates to True
```

看到了吗？在找到`True`后执行停止了吗？`break`语句的作用与`continue`相同，即立即停止循环体的执行，但也阻止其他迭代运行，有效地跳出循环。`continue`和`break`语句可以在`for`和`while`循环结构中一起使用，数量上没有限制。

顺便说一句，没有必要编写代码来检测序列中是否至少有一个元素评估为`True`。只需查看内置的`any`函数。

# 特殊的 else 子句

我在 Python 语言中看到的一个特性是在`while`和`for`循环后面有`else`子句的能力。它很少被使用，但绝对是一个不错的功能。简而言之，你可以在`for`或`while`循环后面有一个`else`代码块。如果循环正常结束，因为迭代器耗尽（`for`循环）或者因为条件最终不满足（`while`循环），那么`else`代码块（如果存在）会被执行。如果执行被`break`语句中断，`else`子句就不会被执行。让我们来看一个`for`循环的例子，它遍历一组项目，寻找一个满足某些条件的项目。如果我们找不到至少一个满足条件的项目，我们想要引发一个**异常**。这意味着我们想要中止程序的正常执行，并且表示出现了一个错误或异常，我们无法处理。异常将在第八章中讨论，*测试、分析和处理异常*，所以如果你现在不完全理解它们，不用担心。只要记住它们会改变代码的正常流程。

现在让我向你展示两个做同样事情的例子，但其中一个使用了特殊的`for...else`语法。假设我们想在一群人中找到一个能开车的人：

```py
# for.no.else.py
class DriverException(Exception):
    pass

people = [('James', 17), ('Kirk', 9), ('Lars', 13), ('Robert', 8)]
driver = None
for person, age in people:
    if age >= 18:
        driver = (person, age)
        break

if driver is None:
    raise DriverException('Driver not found.')
```

再次注意`flag`模式。我们将驾驶员设置为`None`，然后如果我们找到一个，我们会更新`driver`标志，然后在循环结束时检查它是否找到了。我有一种感觉，那些孩子可能会开一辆非常*金属感*的车，但无论如何，请注意，如果找不到驾驶员，将会引发`DriverException`，向程序表示执行无法继续（我们缺少驾驶员）。

相同的功能可以使用以下代码更加优雅地重写：

```py
# for.else.py
class DriverException(Exception):
    pass

people = [('James', 17), ('Kirk', 9), ('Lars', 13), ('Robert', 8)]
for person, age in people:
    if age >= 18:
        driver = (person, age)
        break
else:
    raise DriverException('Driver not found.')
```

请注意，我们不再被迫使用`flag`模式。异常是作为`for`循环逻辑的一部分引发的，这是合理的，因为`for`循环正在检查某些条件。我们只需要在找到一个时设置一个`driver`对象，因为代码的其余部分将在某个地方使用该信息。请注意，代码更短、更优雅，因为逻辑现在正确地组合在一起。

在*将代码转换为优美、成语化的 Python*视频中，Raymond Hettinger 建议为与 for 循环关联的`else`语句取一个更好的名字：`nobreak`。如果你在记住`else`在`for`循环中的工作原理方面有困难，只需记住这个事实就应该能帮助你。

# 把所有这些放在一起

现在你已经看到了关于条件和循环的所有内容，是时候稍微调剂一下，看看我在本章开头预期的那两个例子。我们将在这里混合搭配，这样你就可以看到如何将所有这些概念结合起来使用。让我们先写一些代码来生成一个质数列表，直到某个限制为止。请记住，我将写一个非常低效和基本的算法来检测质数。对你来说重要的是集中精力关注代码中属于本章主题的部分。

# 质数生成器

根据维基百科：

质数（或质数）是大于 1 的自然数，除了 1 和它本身之外没有其他正因子。大于 1 的自然数如果不是质数，则称为合数。

根据这个定义，如果我们考虑前 10 个自然数，我们可以看到 2、3、5 和 7 是质数，而 1、4、6、8、9 和 10 不是。为了让计算机告诉你一个数*N*是否是质数，你可以将该数除以范围[2，*N*)内的所有自然数。如果其中任何一个除法的余数为零，那么这个数就不是质数。废话够多了，让我们开始吧。我将写两个版本，第二个版本将利用`for...else`语法：

```py
# primes.py
primes = []  # this will contain the primes in the end
upto = 100  # the limit, inclusive
for n in range(2, upto + 1):
    is_prime = True  # flag, new at each iteration of outer for
    for divisor in range(2, n):
        if n % divisor == 0:
            is_prime = False
            break
```

```py
    if is_prime:  # check on flag
        primes.append(n)
print(primes)
```

在前面的代码中有很多需要注意的事情。首先，我们设置了一个空的`primes`列表，它将在最后包含质数。限制是`100`，你可以看到我们在外部循环中调用`range()`的方式是包容的。如果我们写`range(2, upto)`，那么是*[2, upto)*，对吧？因此`range(2, upto + 1)`给我们*[2, upto + 1) == [2, upto]*。

因此，有两个`for`循环。在外部循环中，我们循环遍历候选质数，即从`2`到`upto`的所有自然数。在外部循环的每次迭代中，我们设置一个标志（在每次迭代时设置为`True`），然后开始将当前的`n`除以从`2`到`n-1`的所有数字。如果我们找到`n`的一个适当的除数，那么意味着`n`是合数，因此我们将标志设置为`False`并中断循环。请注意，当我们中断内部循环时，外部循环会继续正常进行。我们之所以在找到`n`的适当除数后中断，是因为我们不需要任何进一步的信息就能判断`n`不是质数。

当我们检查`is_prime`标志时，如果它仍然是`True`，这意味着我们在[2，*n*)中找不到任何是`n`的适当除数的数字，因此`n`是质数。我们将`n`添加到`primes`列表中，然后继续下一个迭代，直到`n`等于`100`。

运行这段代码会产生：

```py
$ python primes.py
[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97] 
```

在我们继续之前，有一个问题：在外部循环的所有迭代中，其中一个与其他所有迭代不同。你能告诉哪一个，以及为什么吗？想一想，回到代码，试着自己找出答案，然后继续阅读。

你弄清楚了吗？如果没有，不要感到难过，这是完全正常的。我让你做这个小练习，因为这是程序员一直在做的事情。通过简单地查看代码来理解代码的功能是您随着时间建立的技能。这非常重要，所以尽量在您能做到的时候进行练习。我现在告诉你答案：与所有其他迭代不同的是第一个迭代。原因是因为在第一次迭代中，`n`是`2`。因此，最内层的`for`循环甚至不会运行，因为它是一个迭代`range(2, 2)`的`for`循环，那不就是[2, 2)吗？自己试一下，用这个可迭代对象编写一个简单的`for`循环，将`print`放在主体套件中，看看是否会发生任何事情（不会...）。

现在，从算法的角度来看，这段代码是低效的，所以让我们至少让它更美观一些：

```py
# primes.else.py
primes = []
upto = 100
for n in range(2, upto + 1):
    for divisor in range(2, n):
        if n % divisor == 0:
            break
    else:
        primes.append(n)
print(primes)
```

漂亮多了，对吧？`is_prime`标志消失了，当我们知道内部`for`循环没有遇到任何`break`语句时，我们将`n`附加到`primes`列表中。看看代码看起来更清晰，阅读起来更好了吗？

# 应用折扣

在这个例子中，我想向你展示一种我非常喜欢的技术。在许多编程语言中，除了`if`/`elif`/`else`结构之外，无论以什么形式或语法，你都可以找到另一个语句，通常称为`switch`/`case`，在 Python 中缺少。它相当于一系列`if`/`elif`/.../`elif`/`else`子句，其语法类似于这样（警告！JavaScript 代码！）：

```py
/* switch.js */
switch (day_number) {
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
        day = "Weekday";
        break;
    case 6:
        day = "Saturday";
        break;
    case 0:
        day = "Sunday";
        break;
    default:
        day = "";
```

```py
        alert(day_number + ' is not a valid day number.')
}
```

在前面的代码中，我们根据名为`day_number`的变量进行`switch`。这意味着我们获取它的值，然后决定它适用于哪种情况（如果有的话）。从`1`到`5`有一个级联，这意味着无论数字如何，[`1`，`5`]都会进入将`day`设置为“工作日”的逻辑部分。然后我们有`0`和`6`的单个情况，以及一个`default`情况来防止错误，它会提醒系统`day_number`不是有效的日期数字，即不在[`0`，`6`]中。Python 完全能够使用`if`/`elif`/`else`语句实现这样的逻辑：

```py
# switch.py
if 1 <= day_number <= 5:
    day = 'Weekday'
elif day_number == 6:
    day = 'Saturday'
elif day_number == 0:
    day = 'Sunday'
else:
    day = ''
    raise ValueError(
        str(day_number) + ' is not a valid day number.')
```

在前面的代码中，我们使用`if`/`elif`/`else`语句在 Python 中复制了 JavaScript 片段的相同逻辑。我最后提出了`ValueError`异常，如果`day_number`不在[`0`，`6`]中，这只是一个例子。这是将`switch`/`case`逻辑转换的一种可能方式，但还有另一种方式，有时称为分派，我将在下一个示例的最后版本中向您展示。

顺便说一下，你有没有注意到前面片段的第一行？你有没有注意到 Python 可以进行双重（实际上甚至多重）比较？这太棒了！

让我们通过简单地编写一些代码来开始新的示例，根据客户的优惠券价值为他们分配折扣。我会尽量保持逻辑的最低限度，记住我们真正关心的是理解条件和循环：

```py
# coupons.py
customers = [
    dict(id=1, total=200, coupon_code='F20'),  # F20: fixed, £20
    dict(id=2, total=150, coupon_code='P30'),  # P30: percent, 30%
    dict(id=3, total=100, coupon_code='P50'),  # P50: percent, 50%
    dict(id=4, total=110, coupon_code='F15'),  # F15: fixed, £15
]
for customer in customers:
    code = customer['coupon_code']
    if code == 'F20':
        customer['discount'] = 20.0
    elif code == 'F15':
        customer['discount'] = 15.0
    elif code == 'P30':
        customer['discount'] = customer['total'] * 0.3
    elif code == 'P50':
        customer['discount'] = customer['total'] * 0.5
    else:
        customer['discount'] = 0.0

for customer in customers:
    print(customer['id'], customer['total'], customer['discount'])
```

我们首先设置一些客户。他们有订单总额、优惠券代码和 ID。我编造了四种不同类型的优惠券，两种是固定的，两种是基于百分比的。你可以看到，在`if`/`elif`/`else`级联中，我相应地应用折扣，并将其设置为`customer`字典中的`'discount'`键。

最后，我只打印出部分数据，看看我的代码是否正常工作：

```py
$ python coupons.py
1 200 20.0
2 150 45.0
3 100 50.0
4 110 15.0
```

这段代码很容易理解，但所有这些子句有点混乱。一眼看上去很难看出发生了什么，我不喜欢。在这种情况下，你可以利用字典来发挥你的优势，就像这样：

```py
# coupons.dict.py
customers = [
    dict(id=1, total=200, coupon_code='F20'),  # F20: fixed, £20
    dict(id=2, total=150, coupon_code='P30'),  # P30: percent, 30%
    dict(id=3, total=100, coupon_code='P50'),  # P50: percent, 50%
    dict(id=4, total=110, coupon_code='F15'),  # F15: fixed, £15
]
discounts = {
    'F20': (0.0, 20.0),  # each value is (percent, fixed)
    'P30': (0.3, 0.0),
    'P50': (0.5, 0.0),
    'F15': (0.0, 15.0),
}
for customer in customers:
    code = customer['coupon_code']
    percent, fixed = discounts.get(code, (0.0, 0.0))
    customer['discount'] = percent * customer['total'] + fixed

for customer in customers:
    print(customer['id'], customer['total'], customer['discount'])
```

运行前面的代码产生了与之前片段相同的结果。我们节省了两行，但更重要的是，我们在可读性上获得了很多好处，因为`for`循环的主体现在只有三行，而且非常容易理解。这里的概念是将字典用作**分发器**。换句话说，我们尝试从字典中根据代码（我们的`coupon_code`）获取一些东西，并通过`dict.get(key, default)`，我们确保当`code`不在字典中时，我们也需要一个默认值。

请注意，我必须应用一些非常简单的线性代数来正确计算折扣。字典中的每个折扣都有一个百分比和固定部分，由一个二元组表示。通过应用`percent * total + fixed`，我们得到正确的折扣。当`percent`为`0`时，该公式只给出固定金额，当固定为`0`时，它给出`percent * total`。

这种技术很重要，因为它也用在其他情境中，比如函数，它实际上比我们在前面片段中看到的要强大得多。使用它的另一个优势是，你可以以这样的方式编码，使得`discounts`字典的键和值可以动态获取（例如，从数据库中获取）。这将使代码能够适应你所拥有的任何折扣和条件，而无需修改任何内容。

如果你不完全明白它是如何工作的，我建议你花点时间来试验一下。更改值并添加打印语句，看看程序运行时发生了什么。

# 快速浏览 itertools 模块

关于可迭代对象、迭代器、条件逻辑和循环的章节，如果没有提到`itertools`模块，就不完整了。如果你喜欢迭代，这是一种天堂。

根据 Python 官方文档（[`docs.python.org/2/library/itertools.html`](https://docs.python.org/2/library/itertools.html)），`itertools`模块是：

这个模块实现了一些受 APL、Haskell 和 SML 构造启发的迭代器构建块。每个都已经被重塑成适合 Python 的形式。该模块标准化了一组核心的快速、内存高效的工具，这些工具本身或组合在一起都很有用。它们一起形成了一个“迭代器代数”，使得可以在纯 Python 中简洁高效地构建专门的工具。

在这里我无法向你展示这个模块中所有的好东西，所以我鼓励你自己去查看，我保证你会喜欢的。简而言之，它为您提供了三种广泛的迭代器类别。我将给你一个非常小的例子，来自每一个迭代器，只是为了让你稍微流口水。

# 无限迭代器

无限迭代器允许您以不同的方式使用`for`循环，就像它是一个`while`循环一样：

```py
# infinite.py
from itertools import count

for n in count(5, 3):
    if n > 20:
        break
    print(n, end=', ') # instead of newline, comma and space
```

运行代码会得到这个结果：

```py
$ python infinite.py
5, 8, 11, 14, 17, 20,
```

`count`工厂类创建一个迭代器，它只是不断地计数。它从`5`开始，然后不断加`3`。如果我们不想陷入无限循环，我们需要手动中断它。

# 在最短输入序列上终止的迭代器

这个类别非常有趣。它允许您基于多个迭代器创建一个迭代器，根据某种逻辑组合它们的值。关键点在于，在这些迭代器中，如果有任何一个比其余的短，那么生成的迭代器不会中断，它将在最短的迭代器耗尽时停止。这非常理论化，我知道，所以让我用`compress`给你举个例子。这个迭代器根据选择器中的相应项目是`True`还是`False`，给你返回数据：

`compress('ABC', (1, 0, 1))`会返回`'A'`和`'C'`，因为它们对应于`1`。让我们看一个简单的例子：

```py
# compress.py
from itertools import compress
data = range(10)
even_selector = [1, 0] * 10
odd_selector = [0, 1] * 10

even_numbers = list(compress(data, even_selector))
odd_numbers = list(compress(data, odd_selector))

print(odd_selector)
print(list(data))
print(even_numbers)
print(odd_numbers)
```

请注意，`odd_selector`和`even_selector`的长度为 20 个元素，而`data`只有 10 个元素。`compress`将在`data`产生最后一个元素时停止。运行此代码会产生以下结果：

```py
$ python compress.py
[0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
[0, 2, 4, 6, 8]
[1, 3, 5, 7, 9]
```

这是一种非常快速和方便的从可迭代对象中选择元素的方法。代码非常简单，只需注意，我们使用`list()`而不是使用`for`循环来迭代压缩调用返回的每个值，`list()`做的事情是一样的，但是它不执行一系列指令，而是将所有的值放入一个列表并返回它。

# 组合生成器

最后但并非最不重要的，组合生成器。如果你对这种事情感兴趣，这些真的很有趣。让我们看一个关于排列的简单例子。

根据 Wolfram Mathworld：

排列，也称为“排列数”或“顺序”，是有序列表 S 的元素重新排列成与 S 本身一一对应的过程。

例如，ABC 有六种排列：ABC，ACB，BAC，BCA，CAB 和 CBA。

如果一个集合有*N*个元素，那么它们的排列数就是*N!*（*N*的阶乘）。对于 ABC 字符串，排列数为*3! = 3 * 2 * 1 = 6*。让我们用 Python 来做一下：

```py
# permutations.py
from itertools import permutations 
print(list(permutations('ABC'))) 
```

这段非常简短的代码产生了以下结果：

```py
$ python permutations.py
[('A', 'B', 'C'), ('A', 'C', 'B'), ('B', 'A', 'C'), ('B', 'C', 'A'), ('C', 'A', 'B'), ('C', 'B', 'A')]
```

当你玩排列时要非常小心。它们的数量增长速度与你进行排列的元素的阶乘成正比，而这个数字可能会变得非常大，非常快。

# 总结

在本章中，我们又迈出了一步，扩展了我们的编码词汇。我们已经看到如何通过评估条件来驱动代码的执行，以及如何循环和迭代序列和对象集合。这赋予了我们控制代码运行时发生的事情的能力，这意味着我们正在了解如何塑造代码，使其按照我们的意愿进行操作，并对动态变化的数据做出反应。

我们还看到了如何在几个简单的例子中将所有东西结合在一起，最后，我们简要地看了一下`itertools`模块，这个模块充满了有趣的迭代器，可以进一步丰富我们使用 Python 的能力。

现在是时候换个方式，向前迈进一步，谈谈函数。下一章将全面讨论它们，因为它们非常重要。确保你对到目前为止所涵盖的内容感到舒适。我想为你提供有趣的例子，所以我将不得不加快速度。准备好了吗？翻页吧。


# 第四章：函数，代码的构建块

“创建建筑就是整理。整理什么？函数和对象。” - 勒·柯布西耶

在前几章中，我们已经看到在 Python 中一切都是对象，函数也不例外。但是，函数究竟是什么？**函数**是一系列执行任务的指令，作为一个单元捆绑在一起。然后可以导入这个单元并在需要的地方使用。在代码中使用函数有许多优点，我们很快就会看到。

在本章中，我们将涵盖以下内容：

+   函数-它们是什么，为什么我们应该使用它们

+   作用域和名称解析

+   函数签名-输入参数和返回值

+   递归和匿名函数

+   导入对象以便重用代码

我相信这句话，*一张图片胜过一千言语*，在向一个对这个概念新手解释函数时尤其正确，所以请看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00007.jpeg)

如你所见，函数是一系列指令的块，作为一个整体打包，就像一个盒子。函数可以接受输入参数并产生输出值。这两者都是可选的，正如我们将在本章的例子中看到的那样。

在 Python 中，函数是通过使用`def`关键字来定义的，随后是函数的名称，后面跟着一对括号（可能包含输入参数，也可能不包含），冒号（`:`）表示函数定义行的结束。紧接着，缩进四个空格，我们找到函数的主体，这是函数在调用时将执行的一系列指令。

请注意，缩进四个空格不是强制性的，但这是**PEP 8**建议的空格数量，并且在实践中是最广泛使用的间距度量。

函数可能会返回输出，也可能不会。如果函数想要返回输出，它会使用`return`关键字，后面跟着期望的输出。如果你有鹰眼，你可能已经注意到在前面图表的输出部分中**Optional**后面的小*****。这是因为在 Python 中，函数总是返回一些东西，即使你没有明确使用`return`子句。如果函数体中没有`return`语句，或者`return`语句本身没有给出值，函数将返回`None`。这种设计选择背后的原因超出了介绍章节的范围，所以你需要知道的是这种行为会让你的生活更轻松。一如既往，感谢 Python。

# 为什么使用函数？

函数是任何语言中最重要的概念和构造之一，所以让我给你一些我们需要它们的原因：

+   它们减少了程序中的代码重复。通过让一个特定的任务由一个好的打包代码块来处理，我们可以导入并在需要时调用它，而不需要复制它的实现。

+   它们有助于将复杂的任务或过程分割成较小的块，每个块都成为一个函数。

+   它们隐藏了实现细节，使用户看不到。

+   它们提高了可追溯性。

+   它们提高了可读性。

让我们看几个例子，以更好地理解每一点。

# 减少代码重复

想象一下，你正在编写一款科学软件，需要计算素数直到一个限制，就像我们在上一章中所做的那样。你有一个很好的算法来计算它们，所以你把它复制粘贴到你需要的地方。然而，有一天，你的朋友，*B.黎曼*，给了你一个更好的算法来计算素数，这将节省你很多时间。在这一点上，你需要检查整个代码库，并用新的代码替换旧的代码。

这实际上是一个不好的做法。这容易出错，你永远不知道你是不是误删或遗漏了哪些行，当你将代码剪切和粘贴到其他代码中时，你也可能会错过其中进行质数计算的地方之一，导致软件处于不一致的状态，同样的操作在不同地方以不同的方式执行。如果你需要用更好的版本替换代码，而不是修复错误，你会错过其中一个地方吗？那将更糟糕。

那么，你应该怎么做呢？简单！你写一个函数，`get_prime_numbers(upto)`，并在任何需要质数列表的地方使用它。当 *B. Riemann* 给你新代码时，你只需要用新实现替换该函数的主体，然后就完成了！软件的其余部分将自动适应，因为它只是调用函数。

你的代码会更短，不会受到在执行任务的旧方法和新方法之间的不一致性的影响，也不会因为复制粘贴失败或疏忽而导致未检测到的错误。使用函数，你只会从中获益，我保证。

# 分解复杂任务

函数还非常有用，可以将长或复杂的任务分解为较小的任务。最终结果是，代码从中受益的方式有很多，例如可读性、可测试性和可重用性。举个简单的例子，想象一下你正在准备一份报告。你的代码需要从数据源获取数据，解析数据，过滤数据，整理数据，然后需要运行一系列算法来产生将供`Report`类使用的结果。阅读这样的程序通常只有一个大的`do_report(data_source)`函数。有数十行或数百行代码以`return report`结束。

这些情况在科学代码中更常见，科学代码在算法上往往很出色，但有时在编写风格方面缺乏经验丰富的程序员的触感。现在，想象一下几百行代码。很难跟进，找到事情在改变上下文的地方（比如完成一个任务并开始下一个任务）。你有心中的画面了吗？好。不要这样做！相反，看看这段代码：

```py
# data.science.example.py
def do_report(data_source):
    # fetch and prepare data
    data = fetch_data(data_source)
    parsed_data = parse_data(data)
    filtered_data = filter_data(parsed_data)
    polished_data = polish_data(filtered_data)

    # run algorithms on data
    final_data = analyse(polished_data)

    # create and return report
    report = Report(final_data)
    return report
```

前面的例子当然是虚构的，但你能看出通过代码会有多容易吗？如果最终结果看起来不对，逐个调试`do_report`函数中的每个单个数据输出将非常容易。此外，暂时从整个过程中排除部分过程也更容易（你只需要注释掉需要暂停的部分）。这样的代码更容易处理。

# 隐藏实现细节

让我们继续使用前面的例子来谈谈这一点。你可以看到，通过查看`do_report`函数的代码，即使不阅读一行实现代码，你也能很好地理解。这是因为函数隐藏了实现细节。这个特性意味着，如果你不需要深入了解细节，你就不会被迫这样做，就像如果`do_report`只是一个庞大的函数一样。为了理解发生了什么，你必须阅读每一行代码。但使用函数，你就不需要这样做。这减少了你阅读代码的时间，而在专业环境中，阅读代码所花费的时间远远超过编写代码的时间，因此尽可能减少这一时间非常重要。

# 提高可读性

编码人员有时看不出编写一个只有一两行代码的函数的意义，所以让我们看一个示例，告诉你为什么你应该这样做。

想象一下，你需要将两个矩阵相乘：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00008.jpeg)

你更喜欢阅读这段代码吗：

```py
# matrix.multiplication.nofunc.py
a = [[1, 2], [3, 4]]
b = [[5, 1], [2, 1]]

c = [[sum(i * j for i, j in zip(r, c)) for c in zip(*b)]
     for r in a]
```

或者你更喜欢这个：

```py
# matrix.multiplication.func.py
# this function could also be defined in another module
def matrix_mul(a, b):
    return [[sum(i * j for i, j in zip(r, c)) for c in zip(*b)]
            for r in a]

a = [[1, 2], [3, 4]]
b = [[5, 1], [2, 1]]
c = matrix_mul(a, b)
```

在第二个例子中，更容易理解`c`是`a`和`b`之间乘法的结果。通过代码更容易阅读，如果你不需要修改乘法逻辑，甚至不需要深入了解实现细节。因此，在这里提高了可读性，而在第一个片段中，你将不得不花时间去理解那个复杂的列表推导在做什么。

如果你不理解*列表推导*，不要担心，我们将在第五章中学习它们，*节省时间和内存*。

# 提高可追踪性

想象一下，你已经写了一个电子商务网站。你在页面上展示了产品价格。假设你的数据库中的价格是不含增值税（销售税）的，但你想在网站上以 20%的增值税显示它们。以下是从不含增值税价格计算含增值税价格的几种方式：

```py
# vat.py
price = 100  # GBP, no VAT
final_price1 = price * 1.2
final_price2 = price + price / 5.0
final_price3 = price * (100 + 20) / 100.0
final_price4 = price + price * 0.2
```

这四种不同的计算增值税含价的方式都是完全可以接受的，我向你保证，这些方式我在多年的同事代码中都找到过。现在，想象一下，你已经开始在不同的国家销售你的产品，其中一些国家有不同的增值税率，所以你需要重构你的代码（整个网站）以使增值税计算动态化。

你如何追踪所有进行增值税计算的地方？编码今天是一个协作的任务，你不能确定增值税是使用这些形式中的一个进行计算的。相信我，这将是一场噩梦。

因此，让我们编写一个函数，它接受输入值`vat`和`price`（不含增值税），并返回含增值税的价格：

```py
# vat.function.py
def calculate_price_with_vat(price, vat):
    return price * (100 + vat) / 100
```

现在你可以导入该函数，并在网站中任何需要计算含增值税价格的地方使用它，当你需要追踪这些调用时，你可以搜索`calculate_price_with_vat`。

请注意，在前面的例子中，假定`price`是不含增值税的，`vat`是一个百分比值（例如，19、20 或 23）。

# 作用域和名称解析

还记得我们在第一章中讨论作用域和命名空间吗，*Python 简介*？我们现在要扩展这个概念。最后，我们可以谈谈函数，这将使一切更容易理解。让我们从一个非常简单的例子开始：

```py
# scoping.level.1.py
def my_function():
    test = 1  # this is defined in the local scope of the function
    print('my_function:', test)

test = 0  # this is defined in the global scope
my_function()
print('global:', test)
```

在前面的例子中，我在两个不同的地方定义了`test`名称。它实际上在两个不同的作用域中。一个是全局作用域（`test = 0`），另一个是`my_function`函数的局部作用域（`test = 1`）。如果你执行这段代码，你会看到这个：

```py
$ python scoping.level.1.py
my_function: 1
global: 0
```

很明显，`test = 1`覆盖了`my_function`中的`test = 0`赋值。在全局上下文中，`test`仍然是`0`，正如你从程序的输出中看到的那样，但是我们在函数体中重新定义了`test`名称，并将其指向值为`1`的整数。因此，这两个`test`名称都存在，一个在全局范围内，指向值为`0`的`int`对象，另一个在`my_function`范围内，指向值为`1`的`int`对象。让我们注释掉`test = 1`的那一行。Python 会在下一个封闭的命名空间中搜索`test`名称（回想一下**LEGB**规则：**local**，**enclosing**，**global**，**built-in**，在第一章中描述的*Python 简介*），在这种情况下，我们将看到值`0`被打印两次。在你的代码中试一下。

现在，让我们提高一下难度：

```py
# scoping.level.2.py
def outer():
    test = 1  # outer scope
    def inner():
        test = 2  # inner scope
        print('inner:', test)

    inner()
    print('outer:', test)

test = 0  # global scope
outer()
print('global:', test)
```

在前面的代码中，我们有两个级别的遮蔽。一个级别在函数`outer`中，另一个级别在函数`inner`中。这并不是什么高深的科学，但可能会有些棘手。如果我们运行这段代码，我们会得到：

```py
$ python scoping.level.2.py
inner: 2
outer: 1
global: 0
```

试着注释掉`test = 1`这一行。你能猜到结果会是什么吗？嗯，当到达`print('outer:', test)`这一行时，Python 将不得不在下一个封闭作用域中查找`test`，因此它会找到并打印`0`，而不是`1`。确保你也注释掉`test = 2`，看看你是否理解发生了什么，以及 LEGB 规则是否清楚，然后再继续。

还有一点要注意的是，Python 允许你在另一个函数中定义一个函数。内部函数的名称是在外部函数的命名空间中定义的，就像其他任何名称一样。

# 全局和非局部语句

回到前面的例子，我们可以通过使用这两个特殊语句之一：`global`和`nonlocal`，来改变对`test`名称的遮蔽。正如你从前面的例子中看到的，当我们在`inner`函数中定义`test = 2`时，我们既没有覆盖`outer`函数中的`test`，也没有覆盖全局作用域中的`test`。如果我们在没有定义它们的嵌套作用域中使用它们，我们可以获得对这些名称的读取访问权限，但我们不能修改它们，因为当我们写一个赋值指令时，实际上是在当前作用域中定义一个新名称。

我们如何改变这种行为呢？嗯，我们可以使用`nonlocal`语句。根据官方文档：

“非局部语句使得列出的标识符引用最近的封闭作用域中先前绑定的变量，不包括全局变量。”

让我们在`inner`函数中引入它，看看会发生什么：

```py
# scoping.level.2.nonlocal.py
def outer():
    test = 1  # outer scope
    def inner():
        nonlocal test
        test = 2  # nearest enclosing scope (which is 'outer')
        print('inner:', test)

    inner()
    print('outer:', test)

test = 0  # global scope
outer()
print('global:', test)
```

请注意，在`inner`函数的主体中，我已经声明了`test`名称为`nonlocal`。运行这段代码会产生以下结果：

```py
$ python scoping.level.2.nonlocal.py
inner: 2
outer: 2
global: 0
```

哇，看看那个结果！这意味着，通过在`inner`函数中声明`test`为`nonlocal`，我们实际上将`test`名称绑定到了在`outer`函数中声明的`test`。如果我们从`inner`函数中删除`nonlocal test`行，并在`outer`函数中尝试相同的技巧，我们将得到一个`SyntaxError`，因为`nonlocal`语句只在不包括全局作用域的封闭作用域中起作用。

那么有没有办法访问全局命名空间中的`test = 0`呢？当然有，我们只需要使用`global`语句：

```py
# scoping.level.2.global.py
def outer():
    test = 1  # outer scope
    def inner():
        global test
        test = 2  # global scope
        print('inner:', test)

    inner()
    print('outer:', test)

test = 0  # global scope
outer()
print('global:', test)
```

请注意，我们现在已经声明了`test`名称为`global`，这基本上将其绑定到我们在全局命名空间中定义的那个（`test = 0`）。运行代码，你应该会得到以下结果：

```py
$ python scoping.level.2.global.py
inner: 2
outer: 1
global: 2
```

这表明受`test = 2`赋值影响的名称现在是`global`。这个技巧在`outer`函数中也会起作用，因为在这种情况下，我们是在引用全局作用域。试一试，看看有什么变化，熟悉一下作用域和名称解析，这很重要。另外，你能告诉我在前面的例子中如果在`outer`之外定义`inner`会发生什么吗？

# 输入参数

在本章的开头，我们看到函数可以接受输入参数。在我们深入讨论所有可能类型的参数之前，让我们确保你清楚地理解了将参数传递给函数意味着什么。有三个关键点需要记住：

+   参数传递只不过是将一个对象分配给一个局部变量名

+   在函数内部将对象分配给参数名称不会影响调用者

+   在函数中更改可变对象参数会影响调用者

让我们分别看一下每个观点的例子。

# 参数传递

看一下下面的代码。我们在全局作用域中声明了一个名称`x`，然后我们声明了一个函数`func(y)`，最后我们调用它，传递了`x`：

```py
# key.points.argument.passing.py
x = 3
def func(y):
    print(y)
func(x)  # prints: 3
```

当`func`被`x`调用时，在它的局部作用域中，创建了一个名称`y`，它指向了`x`指向的相同对象。这通过下图更好地解释了（不用担心 Python 3.3，这是一个没有改变的特性）：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00009.jpeg)

前面图的右侧部分描述了程序在执行到最后（`func`返回`None`后）的状态。看一下 Frames 列，注意全局命名空间（全局帧）中有两个名称，`x`和`func`，分别指向一个`int`（值为**3**）和一个`function`对象。在其下方的名为`func`的矩形中，我们可以看到函数的局部命名空间，其中只定义了一个名称`y`。因为我们用`x`调用了`func`（图的左侧第 5 行），`y`指向与`x`指向的相同的对象。这就是在将参数传递给函数时发生的情况。如果我们在函数定义中使用名称`x`而不是`y`，情况将完全相同（可能一开始有点混乱），函数中会有一个局部的`x`，外部会有一个全局的`x`，就像我们在本章前面看到的*作用域和名称解析*部分一样。

总之，实际发生的是函数在其局部范围内创建了作为参数定义的名称，当我们调用它时，我们基本上告诉 Python 这些名称必须指向哪些对象。

# 分配给参数名称不会影响调用者

这一点一开始可能会难以理解，所以让我们看一个例子：

```py
# key.points.assignment.py
x = 3
def func(x):
    x = 7  # defining a local x, not changing the global one
func(x)
print(x)  # prints: 3
```

在前面的代码中，当执行`x = 7`时，在`func`函数的局部范围内，名称`x`指向一个值为`7`的整数，而全局的`x`保持不变。

# 改变可变对象会影响调用者

这是最后一点，非常重要，因为 Python 在处理可变对象时表现出不同的行为（尽管只是表面上）。让我们看一个例子：

```py
# key.points.mutable.py
x = [1, 2, 3]
def func(x):
    x[1] = 42  # this affects the caller!

func(x)
print(x)  # prints: [1, 42, 3]
```

哇，我们实际上改变了原始对象！如果你仔细想想，这种行为并不奇怪。函数调用中的`x`名称被设置为指向调用者对象，并且在函数体内，我们没有改变`x`，也就是说，我们没有改变它的引用，换句话说，我们没有改变`x`指向的对象。我们正在访问该对象在位置 1 的元素，并改变它的值。

记住*输入参数*部分的第 2 点：*在函数内将对象分配给参数名称不会影响调用者*。如果这对你来说很清楚，下面的代码就不会让人感到惊讶：

```py
# key.points.mutable.assignment.py
x = [1, 2, 3]
def func(x):
    x[1] = 42  # this changes the caller!
    x = 'something else'  # this points x to a new string object

func(x)
print(x)  # still prints: [1, 42, 3]
```

看一下我标记的两行。一开始，就像以前一样，我们再次访问调用者对象，在位置 1 处将其值更改为数字`42`。然后，我们重新分配`x`指向`'something else'`字符串。这不会改变调用者，并且实际上输出与前面片段的输出相同。

花点时间来玩弄这个概念，并尝试使用打印和调用`id`函数，直到你的思维中一切都清楚为止。这是 Python 的一个关键方面，必须非常清楚，否则你可能会在代码中引入微妙的错误。再一次，Python Tutor 网站（[`www.pythontutor.com/`](http://www.pythontutor.com/)）将通过可视化这些概念来帮助你很多。

现在我们对输入参数及其行为有了很好的理解，让我们看看如何指定它们。

# 如何指定输入参数

有五种不同的指定输入参数的方式：

+   位置参数

+   关键字参数

+   可变位置参数

+   可变关键字参数

+   仅限关键字参数

让我们逐个来看看它们。

# 位置参数

位置参数是从左到右读取的，它们是最常见的参数类型：

```py
# arguments.positional.py
def func(a, b, c):
    print(a, b, c)
func(1, 2, 3)  # prints: 1 2 3
```

没有太多其他的事情可说。它们可以是任意多的，并且按位置分配。在函数调用中，`1`先出现，`2`第二出现，`3`第三出现，因此它们分别分配给`a`，`b`和`c`。

# 关键字参数和默认值

**关键字参数**是使用`name=value`语法按关键字分配的：

```py
# arguments.keyword.py
def func(a, b, c):
    print(a, b, c)
func(a=1, c=2, b=3)  # prints: 1 3 2
```

关键字参数是根据名称匹配的，即使它们不遵守定义的原始位置（当我们混合和匹配不同类型的参数时，我们将看到这种行为有一个限制）。

关键字参数的对应物，在定义方面，是**默认值**。语法是相同的，`name=value`，并且允许我们不必提供参数，如果我们对给定的默认值满意的话：

```py
# arguments.default.py
def func(a, b=4, c=88):
    print(a, b, c)

func(1)  # prints: 1 4 88
func(b=5, a=7, c=9)  # prints: 7 5 9
func(42, c=9)  # prints: 42 4 9
func(42, 43, 44)  # prints: 42, 43, 44
```

有两件很重要的事情需要注意。首先，你不能在位置参数的左边指定默认参数。其次，在这些例子中，当一个参数被传递而没有使用`argument_name=value`语法时，它必须是列表中的第一个，并且总是被赋值给`a`。还要注意，以位置方式传递值仍然有效，并且遵循函数签名的顺序（例子的最后一行）。

尝试混淆这些参数，看看会发生什么。Python 的错误消息非常擅长告诉你出了什么问题。所以，例如，如果你尝试这样做：

```py
# arguments.default.error.py
def func(a, b=4, c=88):
    print(a, b, c)
func(b=1, c=2, 42)  # positional argument after keyword one
```

你会得到以下错误：

```py
$ python arguments.default.error.py
 File "arguments.default.error.py", line 4
 func(b=1, c=2, 42) # positional argument after keyword one
 ^
SyntaxError: positional argument follows keyword argument
```

这会告诉你你调用函数的方式不正确。

# 可变位置参数

有时候你可能想要向函数传递可变数量的位置参数，Python 提供了这样的能力。让我们看一个非常常见的用例，`minimum`函数。这是一个计算其输入值的最小值的函数：

```py
# arguments.variable.positional.py
def minimum(*n):
    # print(type(n))  # n is a tuple
    if n:  # explained after the code
        mn = n[0]
        for value in n[1:]:
            if value < mn:
                mn = value
        print(mn)

minimum(1, 3, -7, 9)  # n = (1, 3, -7, 9) - prints: -7
minimum()             # n = () - prints: nothing
```

正如你所看到的，当我们在参数名前面加上`*`时，我们告诉 Python 该参数将根据函数的调用方式收集可变数量的位置参数。在函数内部，`n`是一个元组。取消注释`print(type(n))`，自己看看并玩弄一下。

你是否注意到我们如何用简单的`if n:`检查`n`是否为空？这是因为在 Python 中，集合对象在非空时求值为`True`，否则为`False`。这对于元组、集合、列表、字典等都是成立的。

还有一件事需要注意的是，当我们调用函数时没有传递参数时，我们可能希望抛出一个错误，而不是默默地什么都不做。在这种情况下，我们不关心使这个函数健壮，而是要理解可变位置参数。

让我们举个例子来展示两件事，根据我的经验，这对于新手来说是令人困惑的：

```py
# arguments.variable.positional.unpacking.py
def func(*args):
    print(args)

values = (1, 3, -7, 9)
func(values)   # equivalent to: func((1, 3, -7, 9))
func(*values)  # equivalent to: func(1, 3, -7, 9)
```

仔细看一下前面例子的最后两行。在第一个例子中，我们用一个参数调用`func`，一个四元组。在第二个例子中，通过使用`*`语法，我们在做一种叫做**解包**的操作，这意味着四元组被解包，函数被调用时有四个参数：`1, 3, -7, 9`。

这种行为是 Python 为了让你在动态调用函数时做一些惊人的事情而做的魔术的一部分。

# 可变关键字参数

可变关键字参数与可变位置参数非常相似。唯一的区别是语法（`**`而不是`*`）以及它们被收集在一个字典中。收集和解包的工作方式相同，让我们看一个例子：

```py
# arguments.variable.keyword.py
def func(**kwargs):
    print(kwargs)

# All calls equivalent. They print: {'a': 1, 'b': 42}
func(a=1, b=42)
func(**{'a': 1, 'b': 42})
func(**dict(a=1, b=42))
```

在前面的例子中，所有的调用都是等价的。你可以看到，在函数定义中在参数名前面添加`**`告诉 Python 使用该名称来收集可变数量的关键字参数。另一方面，当我们调用函数时，我们可以显式传递`name=value`参数，或者使用相同的`**`语法解包字典。

能够传递可变数量的关键字参数的重要性可能目前还不明显，那么，来看一个更现实的例子如何？让我们定义一个连接到数据库的函数。我们希望通过简单调用这个函数而连接到默认数据库。我们还希望通过传递适当的参数来连接到任何其他数据库。在继续阅读之前，试着花几分钟时间自己想出一个解决方案：

```py
# arguments.variable.db.py
def connect(**options):
    conn_params = {
        'host': options.get('host', '127.0.0.1'),
        'port': options.get('port', 5432),
        'user': options.get('user', ''),
        'pwd': options.get('pwd', ''),
    }
    print(conn_params)
    # we then connect to the db (commented out)
    # db.connect(**conn_params)

connect()
connect(host='127.0.0.42', port=5433)
connect(port=5431, user='fab', pwd='gandalf')
```

注意在函数中，我们可以准备一个连接参数的字典（`conn_params`），使用默认值作为回退，允许在函数调用中提供这些参数时覆盖它们。有更少行代码的更好的方法来做到这一点，但我们现在不关心这个。运行前面的代码产生了以下结果：

```py
$ python arguments.variable.db.py
{'host': '127.0.0.1', 'port': 5432, 'user': '', 'pwd': ''}
{'host': '127.0.0.42', 'port': 5433, 'user': '', 'pwd': ''}
{'host': '127.0.0.1', 'port': 5431, 'user': 'fab', 'pwd': 'gandalf'}
```

注意函数调用和输出之间的对应关系。注意默认值是如何根据传递给函数的内容被覆盖的。

# 仅限关键字参数

Python 3 允许一种新类型的参数：**仅限关键字**参数。我们只会简要地研究它们，因为它们的使用情况并不那么频繁。有两种指定它们的方式，要么在可变位置参数之后，要么在一个裸的`*`之后。让我们看一下两种方式的例子：

```py
# arguments.keyword.only.py
def kwo(*a, c):
    print(a, c)

kwo(1, 2, 3, c=7)  # prints: (1, 2, 3) 7
kwo(c=4)  # prints: () 4
# kwo(1, 2)  # breaks, invalid syntax, with the following error
# TypeError: kwo() missing 1 required keyword-only argument: 'c'

def kwo2(a, b=42, *, c):
    print(a, b, c)

kwo2(3, b=7, c=99)  # prints: 3 7 99
kwo2(3, c=13)  # prints: 3 42 13
# kwo2(3, 23)  # breaks, invalid syntax, with the following error
# TypeError: kwo2() missing 1 required keyword-only argument: 'c'
```

正如预期的那样，函数`kwo`接受可变数量的位置参数（`a`）和一个仅限关键字的参数`c`。调用的结果很直接，你可以取消注释第三个调用以查看 Python 返回的错误。

相同的规则适用于函数`kwo2`，它与`kwo`不同之处在于它接受一个位置参数`a`，一个关键字参数`b`，然后是一个仅限关键字参数`c`。你可以取消注释第三个调用以查看错误。

现在你知道如何指定不同类型的输入参数，让我们看看如何在函数定义中组合它们。

# 组合输入参数

你可以组合输入参数，只要遵循这些顺序规则：

+   在定义函数时，普通的位置参数首先出现（`name`），然后是任意的默认参数（`name=value`），然后是可变位置参数（`*name`或简单的`*`），然后是任意的仅限关键字参数（`name`或`name=value`形式都可以），最后是任意的可变关键字参数（`**name`）。

+   另一方面，在调用函数时，参数必须按照以下顺序给出：首先是位置参数（`value`），然后是任意组合的关键字参数（`name=value`），可变位置参数（`*name`），然后是可变关键字参数（`**name`）。

由于这在理论世界中留下来可能有点棘手，让我们看一些快速的例子：

```py
# arguments.all.py
def func(a, b, c=7, *args, **kwargs):
    print('a, b, c:', a, b, c)
    print('args:', args)
    print('kwargs:', kwargs)

func(1, 2, 3, *(5, 7, 9), **{'A': 'a', 'B': 'b'})
func(1, 2, 3, 5, 7, 9, A='a', B='b')  # same as previous one
```

注意函数定义中参数的顺序，以及两个调用是等价的。在第一个调用中，我们使用了可迭代对象和字典的解包操作符，而在第二个调用中，我们使用了更明确的语法。执行这个代码产生了以下结果（我只打印了一个调用的结果，另一个是一样的）：

```py
$ python arguments.all.py
a, b, c: 1 2 3
args: (5, 7, 9)
kwargs: {'A': 'a', 'B': 'b'}
```

现在让我们看一个带有仅限关键字参数的例子：

```py
# arguments.all.kwonly.py
def func_with_kwonly(a, b=42, *args, c, d=256, **kwargs):
    print('a, b:', a, b)
    print('c, d:', c, d)
    print('args:', args)
    print('kwargs:', kwargs)

# both calls equivalent
func_with_kwonly(3, 42, c=0, d=1, *(7, 9, 11), e='E', f='F')
func_with_kwonly(3, 42, *(7, 9, 11), c=0, d=1, e='E', f='F')
```

注意我在函数声明中突出显示了仅限关键字参数。它们出现在`*args`变量位置参数之后，如果它们直接出现在单个`*`之后的话，情况也是一样的（在这种情况下就不会有变量位置参数了）。执行这个代码产生了以下结果（我只打印了一个调用的结果）：

```py
$ python arguments.all.kwonly.py
a, b: 3 42
c, d: 0 1
args: (7, 9, 11)
kwargs: {'e': 'E', 'f': 'F'}
```

另一个需要注意的事情是我给变量位置和关键字参数的名称。你可以自由选择不同的名称，但要注意`args`和`kwargs`是至少在一般情况下给这些参数的常规名称。

# 额外的解包概括

Python 3.5 中引入的最近的新特性之一是能够扩展可迭代（`*`）和字典（`**`）解包操作符，以允许在更多位置、任意次数和额外情况下进行解包。我将给你一个关于函数调用的例子：

```py
# additional.unpacking.py
def additional(*args, **kwargs):
    print(args)
    print(kwargs)

args1 = (1, 2, 3)
args2 = [4, 5]
kwargs1 = dict(option1=10, option2=20)
kwargs2 = {'option3': 30}
additional(*args1, *args2, **kwargs1, **kwargs2)
```

在前面的例子中，我们定义了一个简单的函数，打印它的输入参数`args`和`kwargs`。新特性在于我们调用这个函数的方式。注意我们如何解包多个可迭代对象和字典，并且它们在`args`和`kwargs`下正确地合并。这个特性之所以重要的原因是它允许我们不必在代码中合并`args1`和`args2`，以及`kwargs1`和`kwargs2`。运行代码会产生：

```py
$ python additional.unpacking.py
(1, 2, 3, 4, 5)
{'option1': 10, 'option2': 20, 'option3': 30}
```

请参考 PEP 448（[`www.python.org/dev/peps/pep-0448/`](https://www.python.org/dev/peps/pep-0448/)）了解这个新特性的全部内容，并查看更多例子。

# 避免陷阱！可变默认值

在 Python 中需要非常注意的一件事是，默认值是在`def`时创建的，因此，对同一个函数的后续调用可能会根据它们的默认值的可变性而有所不同。让我们看一个例子：

```py
# arguments.defaults.mutable.py
def func(a=[], b={}):
    print(a)
    print(b)
    print('#' * 12)
    a.append(len(a))  # this will affect a's default value
    b[len(a)] = len(a)  # and this will affect b's one

func()
func()
func()
```

两个参数都有可变的默认值。这意味着，如果你影响这些对象，任何修改都会在后续的函数调用中保留下来。看看你能否理解这些调用的输出：

```py
$ python arguments.defaults.mutable.py
[]
{}
############
[0]
{1: 1}
############
[0, 1]
{1: 1, 2: 2}
############
```

很有趣，不是吗？虽然这种行为一开始可能看起来很奇怪，但实际上是有道理的，而且非常方便，例如，在使用记忆化技术时（如果你感兴趣的话，可以搜索一个例子）。更有趣的是，当我们在调用之间引入一个不使用默认值的调用时会发生什么，比如这样：

```py
# arguments.defaults.mutable.intermediate.call.py
func()
func(a=[1, 2, 3], b={'B': 1})
func()
```

当我们运行这段代码时，输出如下：

```py
$ python arguments.defaults.mutable.intermediate.call.py
[]
{}
############
[1, 2, 3]
{'B': 1}
############
[0]
{1: 1}
############
```

这个输出告诉我们，即使我们用其他值调用函数，默认值仍然保留。一个让人想到的问题是，我怎样才能每次都得到一个全新的空值呢？嗯，约定是这样的：

```py
# arguments.defaults.mutable.no.trap.py
def func(a=None):
    if a is None:
        a = []
    # do whatever you want with `a` ...
```

请注意，通过使用前面的技术，如果在调用函数时没有传递`a`，你总是会得到一个全新的空列表。

好了，输入就到此为止，让我们看看另一面，输出。

# 返回值

函数的返回值是 Python 领先于大多数其他语言的东西之一。通常函数只允许返回一个对象（一个值），但在 Python 中，你可以返回一个元组，这意味着你可以返回任何你想要的东西。这个特性允许程序员编写在其他语言中要难得多或者肯定更加繁琐的软件。我们已经说过，要从函数中返回一些东西，我们需要使用`return`语句，后面跟着我们想要返回的东西。在函数体中可以有多个 return 语句。

另一方面，如果在函数体内部我们没有返回任何东西，或者我们调用一个裸的`return`语句，函数将返回`None`。这种行为是无害的，尽管我在这里没有足够的空间来详细解释为什么 Python 被设计成这样，但我只想告诉你，这个特性允许出现几种有趣的模式，并确认 Python 是一种非常一致的语言。

我说它是无害的，因为你从来不会被迫收集函数调用的结果。我会用一个例子来说明我的意思：

```py
# return.none.py
def func():
    pass
func()  # the return of this call won't be collected. It's lost.
a = func()  # the return of this one instead is collected into `a`
print(a)  # prints: None
```

请注意，函数的整个主体只由`pass`语句组成。正如官方文档告诉我们的那样，`pass`是一个空操作。当它被执行时，什么都不会发生。当语法上需要一个语句，但不需要执行任何代码时，它是有用的。在其他语言中，我们可能会用一对花括号（`{}`）来表示这一点，它定义了一个*空作用域*，但在 Python 中，作用域是通过缩进代码来定义的，因此`pass`这样的语句是必要的。

还要注意，`func`函数的第一个调用返回一个值（`None`），我们没有收集。正如我之前所说的，收集函数调用的返回值并不是强制性的。

现在，这很好但不是很有趣，那么我们来写一个有趣的函数吧？记住，在第一章中，*Python 的初步介绍*，我们谈到了一个函数的阶乘。让我们在这里写一个（为简单起见，我将假设函数总是以适当的值正确调用，因此我不会对输入参数进行检查）：

```py
# return.single.value.py
def factorial(n):
    if n in (0, 1):
        return 1
    result = n
    for k in range(2, n):
        result *= k
    return result

f5 = factorial(5)  # f5 = 120
```

注意我们有两个返回点。如果`n`是`0`或`1`（在 Python 中，通常使用`in`类型的检查，就像我所做的那样，而不是更冗长的`if n == 0 or n == 1:`），我们返回`1`。否则，我们执行所需的计算，然后返回`result`。让我们尝试以更简洁的方式编写这个函数：

```py
# return.single.value.2.py from functools import reduce
from operator import mul

def factorial(n):
    return reduce(mul, range(1, n + 1), 1)

f5 = factorial(5)  # f5 = 120
```

我知道你在想什么：一行？Python 是优雅而简洁的！我认为这个函数是可读的，即使你从未见过`reduce`或`mul`，但如果你不能读懂或理解它，花几分钟时间在 Python 文档中进行一些研究，直到它的行为对你清晰明了。能够在文档中查找函数并理解他人编写的代码是每个开发人员都需要执行的任务，所以把它当作一个挑战。

为此，请确保查找`help`函数，在控制台上探索时非常有帮助。

# 返回多个值

与大多数其他语言不同，在 Python 中很容易从函数中返回多个对象。这个特性打开了一个全新的可能性世界，并允许你以其他语言难以复制的风格编码。我们的思维受到我们使用的工具的限制，因此当 Python 给你比其他语言更多的自由时，实际上也在提高你自己的创造力。返回多个值非常容易，你只需使用元组（显式或隐式）。让我们看一个简单的例子，模仿`divmod`内置函数：

```py
# return.multiple.py
def moddiv(a, b):
    return a // b, a % b

print(moddiv(20, 7))  # prints (2, 6)
```

我本可以将前面代码中的突出部分用括号括起来，使其成为一个显式元组，但没有必要。前面的函数同时返回除法的结果和余数。

在这个例子的源代码中，我留下了一个简单的测试函数的例子，以确保我的代码进行了正确的计算。

# 一些建议

在编写函数时，遵循指南非常有用，这样你就可以很好地编写它们。我会快速指出其中一些：

+   **函数应该只做一件事**：只做一件事的函数很容易用一句简短的话来描述。做多件事的函数可以拆分成做一件事的小函数。这些小函数通常更容易阅读和理解。记住我们几页前看到的数据科学例子。

+   **函数应该小而精**：它们越小，测试它们和编写它们就越容易，以便它们只做一件事。

+   **输入参数越少越好**：需要大量参数的函数很快就变得难以管理（还有其他问题）。

+   **函数在返回值上应该保持一致**：返回`False`或`None`并不相同，即使在布尔上下文中它们都评估为`False`。`False`意味着我们有信息（`False`），而`None`意味着没有信息。尝试编写函数，无论在函数体中发生什么，都以一致的方式返回。

+   **函数不应该有副作用**：换句话说，函数不应该影响你调用它们时的值。这可能是最难理解的陈述，所以我会给你一个例子，使用列表。在下面的代码中，请注意`numbers`没有被`sorted`函数排序，实际上`sorted`函数返回的是`numbers`的排序副本。相反，`list.sort()`方法是作用于`numbers`对象本身的，这是可以的，因为它是一个方法（属于对象的函数，因此有权修改它）：

```py
>>> numbers = [4, 1, 7, 5]
>>> sorted(numbers)  # won't sort the original `numbers` list
[1, 4, 5, 7]
>>> numbers  # let's verify
[4, 1, 7, 5]  # good, untouched
>>> numbers.sort()  # this will act on the list
>>> numbers
[1, 4, 5, 7]
```

遵循这些准则，你将会写出更好的函数，这将对你有所帮助。

Robert C. Martin 的《代码整洁之道》中的*第三章*，*函数*专门讲述了函数，这可能是我读过的关于这个主题的最好的一套准则。

# 递归函数

当一个函数调用自身来产生结果时，它被称为**递归**。有时递归函数非常有用，因为它们使编写代码变得更容易。有些算法使用递归范式编写起来非常容易，而其他一些则不是。没有递归函数不能以迭代方式重写，因此通常由程序员来选择最佳的方法来处理当前情况。

递归函数的主体通常有两个部分：一个是返回值取决于对自身的后续调用，另一个是不取决于对自身的调用（称为基本情况）。

举个例子，我们可以考虑（希望现在已经熟悉的）`factorial`函数，*N!*。基本情况是当*N*为`0`或`1`时。函数返回`1`，无需进一步计算。另一方面，在一般情况下，*N!*返回乘积*1 * 2 * ... * (N-1) * N*。如果你仔细想一想，*N!*可以这样重写：*N! = (N-1)! * N*。作为一个实际的例子，考虑*5! = 1 * 2 * 3 * 4 * 5 = (1 * 2 * 3 * 4) * 5 = 4! * 5*。

让我们把这个写成代码：

```py
# recursive.factorial.py
def factorial(n):
    if n in (0, 1):  # base case
        return 1
    return factorial(n - 1) * n  # recursive case
```

在编写递归函数时，始终要考虑你进行了多少嵌套调用，因为有一个限制。有关此信息，请查看`sys.getrecursionlimit()`和`sys.setrecursionlimit()`。

递归函数在编写算法时经常使用，而且编写起来真的很有趣。作为练习，尝试使用递归和迭代方法解决一些简单的问题。

# 匿名函数

我想谈谈的最后一种函数类型是**匿名**函数。这些函数在 Python 中被称为**lambda**，通常在需要一个完全成熟的函数及其自己的名称会显得过度的情况下使用，我们只需要一个快速、简单的一行代码来完成工作。

假设你想要一个包含* N *的所有倍数的列表。假设你想使用`filter`函数来过滤掉那些元素，该函数接受一个函数和一个可迭代对象，并构造一个过滤器对象，你可以从中迭代，从可迭代对象中返回`True`的元素。如果不使用匿名函数，你可能会这样做：

```py
# filter.regular.py
def is_multiple_of_five(n):
    return not n % 5

def get_multiples_of_five(n):
    return list(filter(is_multiple_of_five, range(n)))
```

请注意我们如何使用`is_multiple_of_five`来过滤前`n`个自然数。这似乎有点多余，任务很简单，我们不需要保留`is_multiple_of_five`函数以供其他用途。让我们使用 lambda 函数重新编写它：

```py
# filter.lambda.py
def get_multiples_of_five(n):
    return list(filter(lambda k: not k % 5, range(n)))
```

逻辑完全相同，但过滤函数现在是一个 lambda。定义 lambda 非常容易，遵循这种形式：`func_name = lambda [parameter_list]: expression`。返回一个函数对象，等同于这个：`def func_name([parameter_list]): return expression`。

请注意，可选参数遵循常见的语法，用方括号括起来表示。

让我们再看看两种形式定义的等效函数的另外一些例子：

```py
# lambda.explained.py
# example 1: adder
def adder(a, b):
    return a + b

# is equivalent to:
adder_lambda = lambda a, b: a + b

# example 2: to uppercase
def to_upper(s):
    return s.upper()

```

```py
# is equivalent to:
to_upper_lambda = lambda s: s.upper()
```

前面的例子非常简单。第一个例子是两个数字相加，第二个例子是产生字符串的大写版本。请注意，我将`lambda`表达式返回的内容赋给了一个名称（`adder_lambda`、`to_upper_lambda`），但当你像我们在`filter`示例中那样使用 lambda 时，没有必要这样做。

# 函数属性

每个函数都是一个完整的对象，因此它们有许多属性。其中一些是特殊的，可以用内省的方式在运行时检查函数对象。以下脚本是一个示例，显示了其中一部分属性以及如何显示示例函数的值：

```py
# func.attributes.py
def multiplication(a, b=1):
    """Return a multiplied by b. """
    return a * b

special_attributes = [
    "__doc__", "__name__", "__qualname__", "__module__",
    "__defaults__", "__code__", "__globals__", "__dict__",
    "__closure__", "__annotations__", "__kwdefaults__",
]

for attribute in special_attributes:
    print(attribute, '->', getattr(multiplication, attribute))
```

我使用了内置的`getattr`函数来获取这些属性的值。`getattr(obj, attribute)`等同于`obj.attribute`，在我们需要使用字符串名称在运行时获取属性时非常方便。运行这个脚本会产生：

```py
$ python func.attributes.py
__doc__ -> Return a multiplied by b.
__name__ -> multiplication
__qualname__ -> multiplication
__module__ -> __main__
__defaults__ -> (1,)
__code__ -> <code object multiplication at 0x10caf7660, file "func.attributes.py", line 1>
__globals__ -> {...omitted...}
__dict__ -> {}
```

```py
__closure__ -> None
__annotations__ -> {}
__kwdefaults__ -> None
```

我已省略了`__globals__`属性的值，因为它太大了。关于这个属性的含义解释可以在*Python 数据模型*文档页面的*可调用**类型*部分找到（[`docs.python.org/3/reference/datamodel.html#the-standard-type-hierarchy`](https://docs.python.org/3/reference/datamodel.html#the-standard-type-hierarchy)）。如果你想要查看对象的所有属性，只需调用`dir(object_name)`，就会得到所有属性的列表。

# 内置函数

Python 自带了许多内置函数。它们随处可用，你可以通过检查`builtins`模块的`dir(__builtins__)`来获取它们的列表，或者查看官方 Python 文档。不幸的是，我没有足够的空间在这里介绍它们所有。我们已经见过其中一些，比如`any`、`bin`、`bool`、`divmod`、`filter`、`float`、`getattr`、`id`、`int`、`len`、`list`、`min`、`print`、`set`、`tuple`、`type`和`zip`，但还有许多其他的，你至少应该阅读一次。熟悉它们，进行实验，为每一个编写一小段代码，并确保你能随时使用它们。

# 最后一个例子

在我们结束本章之前，最后一个例子怎么样？我在想我们可以编写一个函数来生成一个小于某个限制的质数列表。我们已经看到了这个代码，所以让我们把它变成一个函数，并且为了保持趣味性，让我们对它进行优化一下。

原来你不需要将*N*除以从*2*到*N*-1 的所有数字来判断一个数*N*是否是质数。你可以停在*√N*。此外，你不需要测试从*2*到*√N*的所有数字的除法，你可以只使用该范围内的质数。如果你感兴趣，我会留给你去弄清楚为什么这样做有效。让我们看看代码如何改变：

```py
# primes.py
from math import sqrt, ceil

def get_primes(n):
    """Calculate a list of primes up to n (included). """
    primelist = []
    for candidate in range(2, n + 1):
        is_prime = True
        root = ceil(sqrt(candidate))  # division limit
        for prime in primelist:  # we try only the primes
            if prime > root:  # no need to check any further
                break
            if candidate % prime == 0:
                is_prime = False
                break
        if is_prime:
            primelist.append(candidate)
    return primelist
```

这段代码和上一章的代码是一样的。我们改变了除法算法，以便只使用先前计算的质数来测试可整除性，并且一旦测试除数大于候选数的平方根，我们就停止了。我们使用了`primelist`结果列表来获取除法的质数。我们使用了一个花哨的公式来计算根值，即候选数的根的天花板的整数值。虽然一个简单的`int(k ** 0.5) + 1`同样可以满足我们的目的，但我选择的公式更简洁，并且需要我使用一些导入，我想向你展示。查看`math`模块中的函数，它们非常有趣！

# 代码文档化

我非常喜欢不需要文档的代码。当您正确编写程序，选择正确的名称并处理细节时，您的代码应该是不言自明的，不需要文档。有时注释非常有用，文档也是如此。您可以在*PEP 257 - Docstring conventions*（[`www.python.org/dev/peps/pep-0257/`](https://www.python.org/dev/peps/pep-0257/)）中找到有关 Python 文档的指南，但我会在这里向您展示基础知识。

Python 是用字符串记录的，这些字符串被称为**文档字符串**。任何对象都可以被记录，你可以使用单行或多行文档字符串。单行文档字符串非常简单。它们不应该为函数提供另一个签名，而是清楚地说明其目的。

```py
# docstrings.py
def square(n):
    """Return the square of a number n. """
    return n ** 2

def get_username(userid):
    """Return the username of a user given their id. """
    return db.get(user_id=userid).username
```

使用三个双引号的字符串允许您以后轻松扩展。使用句子以句点结束，并且不要在之前或之后留下空行。

多行注释的结构方式类似。应该有一个简短的单行说明对象要点的一行，然后是更详细的描述。例如，我已经使用 Sphinx 符号对一个虚构的`connect`函数进行了文档记录，如下例所示：

```py
def connect(host, port, user, password):
    """Connect to a database.

    Connect to a PostgreSQL database directly, using the given
    parameters.

    :param host: The host IP.
    :param port: The desired port.
    :param user: The connection username.
    :param password: The connection password.
    :return: The connection object.
    """
    # body of the function here...
    return connection
```

**Sphinx**可能是创建 Python 文档最广泛使用的工具。事实上，官方 Python 文档就是用它编写的。值得花一些时间去了解它。

# 导入对象

现在您已经对函数有了很多了解，让我们看看如何使用它们。编写函数的整个目的是以后能够重复使用它们，在 Python 中，这意味着将它们导入到需要它们的命名空间中。有许多不同的方法可以将对象导入到命名空间中，但最常见的是`import module_name`和`from module_name import function_name`。当然，这些都是相当简单的例子，但请暂时忍耐。

`import module_name`形式会找到`module_name`模块，并在执行`import`语句的本地命名空间中为其定义一个名称。`from module_name import identifier`形式比这略微复杂一些，但基本上做的是相同的事情。它找到`module_name`，并搜索属性（或子模块），并在本地命名空间中存储对`identifier`的引用。

两种形式都可以使用`as`子句更改导入对象的名称：

```py
from mymodule import myfunc as better_named_func 
```

为了让您了解导入的样子，这是我一个项目的测试模块的一个例子（请注意，导入块之间的空行遵循 PEP 8 的指南：标准库、第三方库和本地代码）：

```py
from datetime import datetime, timezone  # two imports on the same line
from unittest.mock import patch  # single import

import pytest  # third party library

from core.models import (  # multiline import
    Exam,
    Exercise,
    Solution,
)
```

当您拥有从项目根目录开始的文件结构时，您可以使用点表示法来获取要导入到当前命名空间的对象，无论是包、模块、类、函数还是其他任何东西。`from module import`语法还允许使用一个全捕子句`from module import *`，有时用于一次性将模块中的所有名称导入当前命名空间，但出于多种原因，如性能和潜在的静默屏蔽其他名称的风险，这是不被赞同的。您可以在官方 Python 文档中阅读有关导入的所有内容，但在我们离开这个主题之前，让我给您一个更好的例子。

假设您已经在一个名为`lib`的文件夹中定义了一对函数：`square(n)`和`cube(n)`，并且想要在`lib`文件夹的同一级别的一对模块`func_import.py`和`func_from.py`中使用它们。显示该项目的树结构会产生以下内容：

```py
├── func_from.py
├── func_import.py
├── lib
 ├── funcdef.py
 └── __init__.py

```

在我展示每个模块的代码之前，请记住，为了告诉 Python 它实际上是一个包，我们需要在其中放置一个`__init__.py`模块。

关于`__init__.py`文件有两点需要注意。首先，它是一个完整的 Python 模块，因此您可以像对待任何其他模块一样在其中放置代码。其次，从 Python 3.3 开始，不再需要它的存在来使文件夹被解释为 Python 包。

代码如下：

```py
# funcdef.py
def square(n): 
    return n ** 2 
def cube(n): 
    return n ** 3 

# func_import.py import lib.funcdef 
print(lib.funcdef.square(10)) 
print(lib.funcdef.cube(10)) 

# func_from.py
from lib.funcdef import square, cube 
print(square(10)) 
print(cube(10)) 
```

这两个文件在执行时都会打印出`100`和`1000`。您可以看到我们如何根据当前作用域中导入的内容以及导入的方式来访问`square`和`cube`函数的不同之处。

# 相对导入

到目前为止，我们看到的导入被称为**绝对**导入，即它们定义了我们要导入的模块的整个路径，或者我们要从中导入对象的模块。在 Python 中还有另一种导入对象的方式，称为**相对导入**。在需要重新排列大型包的结构而无需编辑子包的情况下，或者当我们希望使包内的模块能够自我导入时，相对导入非常有用。相对导入是通过在模块前面添加与我们需要回溯的文件夹数量相同的前导点来完成的，以便找到我们正在搜索的内容。简而言之，就是这样的：

```py
from .mymodule import myfunc 
```

有关相对导入的完整解释，请参阅 PEP 328（[`www.python.org/dev/peps/pep-0328/`](https://www.python.org/dev/peps/pep-0328/)）。在后面的章节中，我们将使用不同的库创建项目，并使用多种不同类型的导入，包括相对导入，因此请确保您花点时间在官方 Python 文档中了解相关内容。

# 总结

在本章中，我们探索了函数的世界。它们非常重要，从现在开始，我们基本上会在任何地方使用它们。我们讨论了使用它们的主要原因，其中最重要的是代码重用和实现隐藏。

我们看到函数对象就像一个接受可选输入并产生输出的盒子。我们可以以许多不同的方式向函数提供输入值，使用位置参数和关键字参数，并对两种类型都使用变量语法。

现在您应该知道如何编写函数、对其进行文档化、将其导入到您的代码中并调用它。

下一章将迫使我更加加速，因此我建议您抓住任何机会，通过深入研究 Python 官方文档来巩固和丰富您迄今为止所获得的知识。


# 第五章：节省时间和内存

“不是每天增加，而是每天减少。砍掉不必要的部分。”- 李小龙

我喜欢李小龙的这句话。他是一个很聪明的人！特别是第二部分，“*砍掉不必要的部分*”，对我来说是使计算机程序优雅的原因。毕竟，如果有更好的方法来做事情，这样我们就不会浪费时间或内存，为什么不呢？

有时，不将我们的代码推向最大限度是有合理的原因的：例如，有时为了实现微不足道的改进，我们必须牺牲可读性或可维护性。当我们可以用可读性强、清晰的代码在 1.05 秒内提供网页，而不是用难以理解、复杂的代码在 1 秒内提供网页时，这是没有意义的。

另一方面，有时候从一个函数中削减一毫秒是完全合理的，特别是当这个函数被调用数千次时。你在那里节省的每一毫秒意味着每一千次调用节省一秒，这对你的应用可能是有意义的。

鉴于这些考虑，本章的重点不是为你提供将代码推向性能和优化的绝对极限的工具，“不管怎样”，而是使你能够编写高效、优雅的代码，读起来流畅，运行快速，并且不会明显浪费资源。

在本章中，我们将涵盖以下内容：

+   map、zip 和 filter 函数

+   推导式

+   生成器

我将进行几项测量和比较，并谨慎得出一些结论。请记住，在一个不同的盒子上，使用不同的设置或不同的操作系统，结果可能会有所不同。看看这段代码：

```py
# squares.py
def square1(n):
    return n ** 2  # squaring through the power operator

def square2(n):
    return n * n  # squaring through multiplication
```

这两个函数都返回`n`的平方，但哪个更快？从我对它们进行的简单基准测试来看，第二个似乎稍微更快。如果你仔细想想，这是有道理的：计算一个数字的幂涉及乘法，因此，无论你使用什么算法来执行幂运算，它都不太可能击败`square2`中的简单乘法。

我们在乎这个结果吗？在大多数情况下，不在乎。如果你正在编写一个电子商务网站，很可能你甚至不需要将一个数字提高到二次方，如果你需要，这可能是一个零星的操作。你不需要担心在你调用几次的函数上节省一小部分微秒。

那么，优化什么时候变得重要呢？一个非常常见的情况是当你必须处理大量的数据集时。如果你在一百万个“客户”对象上应用相同的函数，那么你希望你的函数调整到最佳状态。在一个被调用一百万次的函数上节省 1/10 秒，可以节省你 100,000 秒，大约 27.7 小时。这不一样，对吧？所以，让我们专注于集合，让我们看看 Python 给你提供了哪些工具来高效优雅地处理它们。

我们将在本章中看到的许多概念都是基于迭代器和可迭代对象的概念。简单地说，当要求一个对象返回其下一个元素时，以及在耗尽时引发`StopIteration`异常的能力。我们将看到如何在第六章中编写自定义迭代器和可迭代对象，*面向对象编程、装饰器和迭代器*。

由于我们将在本章中探讨的对象的性质，我经常被迫将代码包装在`list`构造函数中。这是因为将迭代器/生成器传递给`list(...)`会耗尽它，并将所有生成的项目放入一个新创建的列表中，我可以轻松地打印出来显示它的内容。这种技术会影响可读性，所以让我介绍一个`list`的别名：

```py
# alias.py
>>> range(7)
range(0, 7)
>>> list(range(7))  # put all elements in a list to view them
[0, 1, 2, 3, 4, 5, 6]
>>> _ = list  # create an "alias" to list
>>> _(range(7))  # same as list(range(7))
[0, 1, 2, 3, 4, 5, 6]
```

我已经突出显示的三个部分中，第一个是我们需要执行的调用，以便显示`range(7)`生成的内容，第二个是我创建别名到`list`的时刻（我选择了希望不引人注目的下划线），第三个是等效的调用，当我使用别名而不是`list`时。

希望这样做可以提高可读性，请记住，我将假设这个别名已经在本章的所有代码中定义了。

# map、zip 和 filter 函数

我们将从回顾`map`、`filter`和`zip`开始，这些是处理集合时可以使用的主要内置函数，然后我们将学习如何使用两个非常重要的构造来实现相同的结果：**推导**和**生成器**。系好安全带！

# 地图

根据官方 Python 文档：

map(function, iterable, ...)返回一个迭代器，它将函数应用于可迭代对象的每个项目，产生结果。如果传递了额外的可迭代参数，函数必须接受相同数量的参数，并且会并行应用于所有可迭代对象的项目。对于多个可迭代对象，当最短的可迭代对象耗尽时，迭代器会停止。

我们将在本章后面解释 yielding 的概念。现在，让我们将其翻译成代码——我们将使用一个接受可变数量的位置参数的`lambda`函数，并将它们返回为一个元组：

```py
# map.example.py
>>> map(lambda *a: a, range(3))  # 1 iterable
<map object at 0x10acf8f98>  # Not useful! Let's use alias
>>> _(map(lambda *a: a, range(3)))  # 1 iterable
[(0,), (1,), (2,)]
>>> _(map(lambda *a: a, range(3), 'abc'))  # 2 iterables
[(0, 'a'), (1, 'b'), (2, 'c')]
>>> _(map(lambda *a: a, range(3), 'abc', range(4, 7)))  # 3
[(0, 'a', 4), (1, 'b', 5), (2, 'c', 6)]
>>> # map stops at the shortest iterator
>>> _(map(lambda *a: a, (), 'abc'))  # empty tuple is shortest
[]
>>> _(map(lambda *a: a, (1, 2), 'abc'))  # (1, 2) shortest
[(1, 'a'), (2, 'b')]
>>> _(map(lambda *a: a, (1, 2, 3, 4), 'abc'))  # 'abc' shortest
[(1, 'a'), (2, 'b'), (3, 'c')]
```

在前面的代码中，你可以看到为什么我们必须用`list(...)`（或者在这种情况下使用它的别名`_`）来包装调用。没有它，我会得到一个`map`对象的字符串表示，这在这种情况下并不真正有用，是吗？

你还可以注意到每个可迭代对象的元素是如何应用于函数的；首先是每个可迭代对象的第一个元素，然后是每个可迭代对象的第二个元素，依此类推。还要注意，`map`在我们调用它的可迭代对象中最短的一个耗尽时停止。这实际上是一种非常好的行为；它不强迫我们将所有可迭代对象平齐到一个公共长度，并且如果它们的长度不相同时也不会中断。

当你必须将相同的函数应用于一个或多个对象集合时，`map`非常有用。作为一个更有趣的例子，让我们看看**装饰-排序-解除装饰**惯用法（也称为**Schwartzian transform**）。这是一种在 Python 排序没有提供*key-functions*时非常流行的技术，因此今天使用较少，但偶尔还是会派上用场的一个很酷的技巧。

让我们在下一个例子中看一个变体：我们想按照学生所累积的学分总和降序排序，以便将最好的学生放在位置 0。我们编写一个函数来生成一个装饰对象，然后进行排序，然后进行 undecorate。每个学生在三个（可能不同的）科目中都有学分。在这种情况下，装饰对象意味着以一种允许我们按照我们想要的方式对原始对象进行排序的方式来转换它，无论是向其添加额外数据，还是将其放入另一个对象中。这种技术与 Python 装饰器无关，我们将在本书后面探讨。

在排序之后，我们将装饰的对象恢复为它们的原始对象。这被称为 undecorate：

```py
# decorate.sort.undecorate.py
students = [
    dict(id=0, credits=dict(math=9, physics=6, history=7)),
    dict(id=1, credits=dict(math=6, physics=7, latin=10)),
    dict(id=2, credits=dict(history=8, physics=9, chemistry=10)),
    dict(id=3, credits=dict(math=5, physics=5, geography=7)),
]

def decorate(student):
    # create a 2-tuple (sum of credits, student) from student dict
    return (sum(student['credits'].values()), student)

def undecorate(decorated_student):
    # discard sum of credits, return original student dict
    return decorated_student[1]

students = sorted(map(decorate, students), reverse=True)
students = _(map(undecorate, students))
```

让我们首先了解每个学生对象是什么。实际上，让我们打印第一个：

```py
{'credits': {'history': 7, 'math': 9, 'physics': 6}, 'id': 0}
```

你可以看到它是一个具有两个键的字典：`id`和`credits`。`credits`的值也是一个字典，在其中有三个科目/成绩键/值对。正如你在数据结构世界中所记得的，调用`dict.values()`会返回一个类似于`iterable`的对象，只有值。因此，第一个学生的`sum(student['credits'].values())`等同于`sum((9, 6, 7))`。

让我们打印调用 decorate 与第一个学生的结果：

```py
>>> decorate(students[0])
(22, {'credits': {'history': 7, 'math': 9, 'physics': 6}, 'id': 0})
```

如果我们对所有学生都这样装饰，我们可以通过仅对元组列表进行排序来按学分总额对它们进行排序。为了将装饰应用到 students 中的每个项目，我们调用`map(decorate, students)`。然后我们对结果进行排序，然后以类似的方式进行解除装饰。如果你已经正确地阅读了之前的章节，理解这段代码不应该太难。

运行整个代码后打印学生：

```py
$ python decorate.sort.undecorate.py
[{'credits': {'chemistry': 10, 'history': 8, 'physics': 9}, 'id': 2},
 {'credits': {'latin': 10, 'math': 6, 'physics': 7}, 'id': 1},
 {'credits': {'history': 7, 'math': 9, 'physics': 6}, 'id': 0},
 {'credits': {'geography': 7, 'math': 5, 'physics': 5}, 'id': 3}]
```

你可以看到，根据学生对象的顺序，它们确实已经按照他们的学分总和进行了排序。

有关*装饰-排序-解除装饰*习惯用法的更多信息，请参阅官方 Python 文档的排序指南部分（[`docs.python.org/3.7/howto/sorting.html#the-old-way-using-decorate-sort-undecorate`](https://docs.python.org/3.7/howto/sorting.html#the-old-way-using-decorate-sort-undecorate)）。

关于排序部分要注意的一件事是：如果两个或更多的学生总分相同怎么办？排序算法将继续通过比较`student`对象来对元组进行排序。这没有任何意义，在更复杂的情况下，可能会导致不可预测的结果，甚至错误。如果你想确保避免这个问题，一个简单的解决方案是创建一个三元组而不是两元组，将学分总和放在第一个位置，`students`列表中`student`对象的位置放在第二个位置，`student`对象本身放在第三个位置。这样，如果学分总和相同，元组将根据位置进行排序，位置总是不同的，因此足以解决任何一对元组之间的排序问题。

# zip

我们已经在之前的章节中介绍了`zip`，所以让我们正确定义它，然后我想向你展示如何将它与`map`结合起来使用。

根据 Python 文档：

zip(*iterables)返回一个元组的迭代器，其中第 i 个元组包含来自每个参数序列或可迭代对象的第 i 个元素。当最短的输入可迭代对象耗尽时，迭代器停止。使用单个可迭代对象参数时，它返回一个 1 元组的迭代器。没有参数时，它返回一个空的迭代器。

让我们看一个例子：

```py
# zip.grades.py
>>> grades = [18, 23, 30, 27]
>>> avgs = [22, 21, 29, 24]
>>> _(zip(avgs, grades))
[(22, 18), (21, 23), (29, 30), (24, 27)]
>>> _(map(lambda *a: a, avgs, grades))  # equivalent to zip
[(22, 18), (21, 23), (29, 30), (24, 27)]
```

在上面的代码中，我们将每个学生的平均值和最后一次考试的成绩进行了`zip`。注意使用`map`来复制`zip`是多么容易（示例的最后两条指令）。同样，在可视化结果时，我们必须使用我们的`_`别名。

`map`和`zip`的结合使用的一个简单例子可能是计算序列中每个元素的最大值，即每个序列的第一个元素的最大值，然后是第二个元素的最大值，依此类推：

```py
# maxims.py
>>> a = [5, 9, 2, 4, 7]
>>> b = [3, 7, 1, 9, 2]
>>> c = [6, 8, 0, 5, 3]
>>> maxs = map(lambda n: max(*n), zip(a, b, c))
>>> _(maxs)
[6, 9, 2, 9, 7]
```

注意计算三个序列的最大值是多么容易。当然，严格来说并不一定需要`zip`，我们可以使用`map`。有时候在展示一个简单的例子时，很难理解为什么使用某种技术可能是好的或坏的。我们忘记了我们并不总是能控制源代码，我们可能必须使用第三方库，而我们无法按照自己的意愿进行更改。因此，有不同的方法来处理数据真的很有帮助。

# 筛选

根据 Python 文档：

filter(function, iterable)从可迭代对象中构建一个迭代器，其中包含函数返回 True 的那些元素。可迭代对象可以是序列、支持迭代的容器，或者是迭代器。如果函数为 None，则假定为恒等函数，即删除可迭代对象中所有为假的元素。

让我们看一个非常快速的例子：

```py
# filter.py
>>> test = [2, 5, 8, 0, 0, 1, 0]
>>> _(filter(None, test))
[2, 5, 8, 1]
>>> _(filter(lambda x: x, test))  # equivalent to previous one
[2, 5, 8, 1]
>>> _(filter(lambda x: x > 4, test))  # keep only items > 4
[5, 8]
```

在上面的代码中，注意第二次调用`filter`等同于第一次调用。如果我们传递一个接受一个参数并返回参数本身的函数，只有那些为`True`的参数才会使函数返回`True`，因此这种行为与传递`None`完全相同。模仿一些内置的 Python 行为通常是一个很好的练习。当你成功时，你可以说你完全理解了 Python 在特定情况下的行为。

有了`map`，`zip`和`filter`（以及 Python 标准库中的其他几个函数），我们可以非常有效地处理序列。但这些函数并不是唯一的方法。所以让我们看看 Python 最好的特性之一：推导。

# 推导

推导是一种简洁的表示法，既对一组元素执行某些操作，又/或选择满足某些条件的子集。它们借鉴自函数式编程语言 Haskell（[`www.haskell.org/`](https://www.haskell.org/)），并且与迭代器和生成器一起为 Python 增添了函数式风味。

Python 为您提供不同类型的推导：`list`，`dict`和`set`。我们现在将集中在第一个上，然后解释另外两个将会很容易。

让我们从一个非常简单的例子开始。我想计算一个包含前 10 个自然数的平方的列表。你会怎么做？有几种等效的方法：

```py
# squares.map.py
# If you code like this you are not a Python dev! ;)
>>> squares = []
>>> for n in range(10):
...     squares.append(n ** 2)
...
>>> squares
[0, 1, 4, 9, 16, 25, 36, 49, 64, 81]

# This is better, one line, nice and readable
>>> squares = map(lambda n: n**2, range(10))
>>> _(squares)
[0, 1, 4, 9, 16, 25, 36, 49, 64, 81]
```

前面的例子对你来说应该不是什么新鲜事。让我们看看如何使用`list`推导来实现相同的结果：

```py
# squares.comprehension.py
>>> [n ** 2 for n in range(10)]
[0, 1, 4, 9, 16, 25, 36, 49, 64, 81]
```

就是这么简单。是不是很优雅？基本上我们在方括号内放了一个`for`循环。现在让我们过滤掉奇数平方。我将首先向你展示如何使用`map`和`filter`，然后再次使用`list`推导：

```py
# even.squares.py
# using map and filter
sq1 = list(
    map(lambda n: n ** 2, filter(lambda n: not n % 2, range(10)))
)
# equivalent, but using list comprehensions
sq2 = [n ** 2 for n in range(10) if not n % 2]

print(sq1, sq1 == sq2)  # prints: [0, 4, 16, 36, 64] True
```

我认为现在可读性的差异是明显的。列表推导读起来好多了。它几乎是英语：如果 n 是偶数，给我所有 0 到 9 之间的 n 的平方（n ** 2）。

根据 Python 文档：

列表推导由包含表达式的括号组成，后面跟着一个 for 子句，然后是零个或多个 for 或 if 子句。结果将是一个新列表，由在 for 和 if 子句的上下文中评估表达式得出。

# 嵌套推导

让我们看一个嵌套循环的例子。在处理算法时，经常需要使用两个占位符对序列进行迭代是很常见的。第一个占位符从左到右遍历整个序列。第二个也是如此，但它从第一个开始，而不是从 0 开始。这个概念是为了测试所有对而不重复。让我们看看经典的`for`循环等价：

```py
# pairs.for.loop.py
items = 'ABCD'
pairs = []

for a in range(len(items)):
    for b in range(a, len(items)):
        pairs.append((items[a], items[b]))
```

如果你在最后打印出对，你会得到：

```py
$ python pairs.for.loop.py
[('A', 'A'), ('A', 'B'), ('A', 'C'), ('A', 'D'), ('B', 'B'), ('B', 'C'), ('B', 'D'), ('C', 'C'), ('C', 'D'), ('D', 'D')]
```

所有具有相同字母的元组都是`b`与`a`处于相同位置的元组。现在，让我们看看如何将其转换为`list`推导：

```py
# pairs.list.comprehension.py
items = 'ABCD'
pairs = [(items[a], items[b])
    for a in range(len(items)) for b in range(a, len(items))]
```

这个版本只有两行长，但实现了相同的结果。请注意，在这种特殊情况下，因为`for`循环在`b`上有一个对`a`的依赖，所以它必须在推导中跟在`a`上的`for`循环之后。如果你交换它们，你会得到一个名称错误。

# 过滤推导

我们可以对推导应用过滤。让我们首先用`filter`来做。让我们找出所有勾股数的短边小于 10 的三元组。显然，我们不想测试两次组合，因此我们将使用与我们在上一个例子中看到的类似的技巧：

```py
# pythagorean.triple.py
from math import sqrt
# this will generate all possible pairs
mx = 10
triples = [(a, b, sqrt(a**2 + b**2))
    for a in range(1, mx) for b in range(a, mx)]
# this will filter out all non pythagorean triples
triples = list(
    filter(lambda triple: triple[2].is_integer(), triples))

print(triples)  # prints: [(3, 4, 5.0), (6, 8, 10.0)]
```

勾股数是满足整数方程 a² + b² = c²的整数三元组（a，b，c）。

在前面的代码中，我们生成了一个*三元组*列表`triples`。每个元组包含两个整数（腿）和勾股定理三角形的斜边，其腿是元组中的前两个数字。例如，当`a`为`3`，`b`为`4`时，元组将是`(3, 4, 5.0)`，当`a`为`5`，`b`为`7`时，元组将是`(5, 7, 8.602325267042627)`。

在完成所有`triples`之后，我们需要过滤掉所有没有整数斜边的三元组。为了做到这一点，我们基于`float_number.is_integer()`为`True`进行过滤。这意味着在我之前向您展示的两个示例元组中，具有`5.0`斜边的元组将被保留，而具有`8.602325267042627`斜边的元组将被丢弃。

这很好，但我不喜欢三元组有两个整数和一个浮点数。它们应该都是整数，所以让我们使用`map`来修复这个问题：

```py
# pythagorean.triple.int.py
from math import sqrt
mx = 10
triples = [(a, b, sqrt(a**2 + b**2))
    for a in range(1, mx) for b in range(a, mx)]
triples = filter(lambda triple: triple[2].is_integer(), triples)
# this will make the third number in the tuples integer
triples = list(
    map(lambda triple: triple[:2] + (int(triple[2]), ), triples))

print(triples)  # prints: [(3, 4, 5), (6, 8, 10)]
```

注意我们添加的步骤。我们取`triples`中的每个元素，并对其进行切片，仅取其中的前两个元素。然后，我们将切片与一个一元组连接起来，在其中放入我们不喜欢的那个浮点数的整数版本。看起来像是很多工作，对吧？确实是。让我们看看如何使用`list`推导来完成所有这些工作：

```py
# pythagorean.triple.comprehension.py
from math import sqrt
# this step is the same as before
mx = 10
triples = [(a, b, sqrt(a**2 + b**2))
    for a in range(1, mx) for b in range(a, mx)]
# here we combine filter and map in one CLEAN list comprehension
triples = [(a, b, int(c)) for a, b, c in triples if c.is_integer()]
print(triples)  # prints: [(3, 4, 5), (6, 8, 10)]
```

我知道。这样会好得多，不是吗？它干净、可读、更短。换句话说，它是优雅的。

我在这里走得很快，就像在第四章的*摘要*中预期的那样，*函数，代码的构建块*。您在玩这个代码吗？如果没有，我建议您这样做。非常重要的是，您要玩耍，打破事物，改变事物，看看会发生什么。确保您清楚地了解发生了什么。您想成为一个忍者，对吧？

# dict 推导

字典和`set`推导的工作方式与列表推导完全相同，只是语法上有一点不同。以下示例足以解释您需要了解的所有内容：

```py
# dictionary.comprehensions.py
from string import ascii_lowercase
lettermap = dict((c, k) for k, c in enumerate(ascii_lowercase, 1))
```

如果打印`lettermap`，您将看到以下内容（我省略了中间结果，您会明白的）：

```py
$ python dictionary.comprehensions.py
{'a': 1,
 'b': 2,
 ...
 'y': 25,
 'z': 26}
```

在前面的代码中发生的是，我们正在用推导（技术上是生成器表达式，我们稍后会看到）向`dict`构造函数提供数据。我们告诉`dict`构造函数从推导中的每个元组中制作*键*/*值*对。我们使用`enumerate`列举所有小写 ASCII 字母的序列，从`1`开始。小菜一碟。还有另一种做同样事情的方法，更接近其他字典语法：

```py
lettermap = {c: k for k, c in enumerate(ascii_lowercase, 1)} 
```

它确实做了完全相同的事情，只是语法略有不同，更突出了*键：值*部分。

字典不允许键中有重复，如下例所示：

```py
# dictionary.comprehensions.duplicates.py
word = 'Hello'
swaps = {c: c.swapcase() for c in word}
print(swaps)  # prints: {'H': 'h', 'e': 'E', 'l': 'L', 'o': 'O'}
```

我们创建一个字典，其中键是`'Hello'`字符串中的字母，值是相同的字母，但大小写不同。请注意只有一个`'l': 'L'`对。构造函数不会抱怨，它只是将重复的键重新分配给最新的值。让我们通过另一个例子来更清楚地说明这一点；让我们为每个键分配其在字符串中的位置：

```py
# dictionary.comprehensions.positions.py
word = 'Hello'
positions = {c: k for k, c in enumerate(word)}
print(positions)  # prints: {'H': 0, 'e': 1, 'l': 3, 'o': 4}
```

请注意与字母`'l'`关联的值：`3`。`'l': 2`对不在那里；它已被`'l': 3`覆盖。

# set 推导

`set`推导非常类似于列表和字典推导。Python 允许使用`set()`构造函数，或显式的`{}`语法。让我们看一个快速的例子：

```py
# set.comprehensions.py
word = 'Hello'
letters1 = set(c for c in word)
letters2 = {c for c in word}
print(letters1)  # prints: {'H', 'o', 'e', 'l'}
print(letters1 == letters2)  # prints: True
```

请注意，对于`set`推导和字典推导，不允许重复，因此生成的集合只有四个字母。还要注意，分配给`letters1`和`letters2`的表达式产生了等效的集合。

用于创建`letters2`的语法与用于创建字典推导的语法非常相似。您只能通过字典需要使用冒号分隔的键和值来区分它们，而集合则不需要。

# 生成器

**生成器**是 Python 赋予我们的非常强大的工具。它们基于*迭代*的概念，正如我们之前所说的，它们允许结合优雅和高效的编码模式。

生成器有两种类型：

+   **生成器函数**：这些与常规函数非常相似，但是它们不是通过返回语句返回结果，而是使用 yield，这使它们能够在每次调用之间暂停和恢复它们的状态。

+   **生成器表达式**：这些与我们在本章中看到的`list`推导非常相似，但是它们不是返回一个列表，而是返回一个逐个产生结果的对象。

# 生成器函数

生成器函数在所有方面都像常规函数一样，只有一个区别。它们不是一次性收集结果并返回它们，而是在每次调用`next`时自动转换为产生结果的迭代器。

这一切都是非常理论的，所以让我们清楚地说明为什么这样的机制是如此强大，然后让我们看一个例子。

假设我让你大声数数从 1 数到 1,000,000。你开始了，然后在某个时候我让你停下来。过了一段时间，我让你继续。在这一点上，你需要记住能够正确恢复的最小信息是什么？嗯，你需要记住你最后一个叫的数字。如果我在 31,415 后停止了你，你就会继续 31,416，依此类推。

重点是，你不需要记住 31,415 之前说的所有数字，也不需要它们被写在某个地方。嗯，你可能不知道，但你已经像一个生成器一样行为了！

仔细看一下以下代码：

```py
# first.n.squares.py
def get_squares(n): # classic function approach
    return [x ** 2 for x in range(n)]
print(get_squares(10))

def get_squares_gen(n):  # generator approach
    for x in range(n):
        yield x ** 2  # we yield, we don't return
print(list(get_squares_gen(10)))
```

两个`print`语句的结果将是相同的：`[0, 1, 4, 9, 16, 25, 36, 49, 64, 81]`。但是这两个函数之间有很大的区别。`get_squares`是一个经典函数，它收集[0，*n*)范围内所有数字的平方，并将其返回为列表。另一方面，`get_squares_gen`是一个生成器，行为非常不同。每当解释器到达`yield`行时，它的执行就会被暂停。这些`print`语句返回相同结果的唯一原因是因为我们将`get_squares_gen`传递给`list`构造函数，它通过请求下一个元素直到引发`StopIteration`来完全耗尽生成器。让我们详细看一下：

```py
# first.n.squares.manual.py
def get_squares_gen(n):
    for x in range(n):
        yield x ** 2

squares = get_squares_gen(4)  # this creates a generator object
print(squares)  # <generator object get_squares_gen at 0x10dd...>
print(next(squares))  # prints: 0
print(next(squares))  # prints: 1
print(next(squares))  # prints: 4
print(next(squares))  # prints: 9
# the following raises StopIteration, the generator is exhausted,
# any further call to next will keep raising StopIteration
print(next(squares))
```

在前面的代码中，每次我们在生成器对象上调用`next`时，要么启动它（第一个`next`），要么使它从上次暂停的地方恢复（任何其他`next`）。

第一次在它上面调用`next`时，我们得到`0`，这是`0`的平方，然后是`1`，然后是`4`，然后是`9`，由于`for`循环在那之后停止了（`n`是`4`），然后生成器自然结束了。经典函数在那一点上只会返回`None`，但为了符合迭代协议，生成器将会引发`StopIteration`异常。

这解释了`for`循环的工作原理。当你调用`for k in range(n)`时，在幕后发生的是`for`循环从`range(n)`中获取一个迭代器，并开始在其上调用`next`，直到引发`StopIteration`，这告诉`for`循环迭代已经结束。

Python 的每个迭代方面内置了这种行为，这使得生成器更加强大，因为一旦我们编写它们，我们就能够将它们插入到我们想要的任何迭代机制中。

此时，你可能会问自己为什么要使用生成器而不是普通函数。好吧，本章的标题应该暗示了答案。稍后我会谈论性能，所以现在让我们集中在另一个方面：有时生成器允许你做一些用简单列表无法做到的事情。例如，假设你想分析一个序列的所有排列。如果序列的长度为*N*，那么它的排列数就是*N!*。这意味着如果序列长度为 10 个元素，排列数就是 3,628,800。但是 20 个元素的序列将有 2,432,902,008,176,640,000 个排列。它们呈阶乘增长。

现在想象一下，你有一个经典函数，它试图计算所有的排列，把它们放在一个列表中，并返回给你。对于 10 个元素，可能需要几十秒，但对于 20 个元素，根本不可能完成。

另一方面，一个生成器函数将能够开始计算并返回第一个排列，然后是第二个，依此类推。当然你没有时间解析它们所有，因为太多了，但至少你能够处理其中的一些。

还记得我们在谈论`for`循环中的`break`语句吗？当我们找到一个能整除*候选素数*的数时，我们就打破了循环，没有必要继续下去了。

有时情况完全相同，只是你需要迭代的数据量太大，无法将其全部保存在列表中。在这种情况下，生成器是非常宝贵的：它们使得原本不可能的事情成为可能。

因此，为了节省内存（和时间），尽可能使用生成器函数。

值得注意的是，你可以在生成器函数中使用 return 语句。它将产生一个`StopIteration`异常被引发，有效地结束迭代。这是非常重要的。如果`return`语句实际上使函数返回了什么东西，它将打破迭代协议。Python 的一致性防止了这种情况，并且在编码时为我们提供了极大的便利。让我们看一个快速的例子：

```py
# gen.yield.return.py
def geometric_progression(a, q):
    k = 0
    while True:
        result = a * q**k
        if result <= 100000:
            yield result
        else:
            return
        k += 1

for n in geometric_progression(2, 5):
    print(n)
```

前面的代码产生了等比级数的所有项，*a*，*aq*，*aq²*，*aq³*，.... 当级数产生一个大于`100000`的项时，生成器就会停止（使用`return`语句）。 运行代码会产生以下结果：

```py
$ python gen.yield.return.py
2
10
50
250
1250
6250
31250
```

下一个项本来会是`156250`，这太大了。

说到`StopIteration`，从 Python 3.5 开始，生成器中异常处理的方式已经发生了变化。在这一点上理解这种变化的影响可能要求你付出太多，所以只需知道你可以在 PEP 479 中阅读有关它的所有内容即可（[`legacy.python.org/dev/peps/pep-0479/`](https://legacy.python.org/dev/peps/pep-0479/)）。

# 超越 next

在本章的开头，我告诉过你生成器对象是基于迭代协议的。我们将在第六章中看到一个完整的例子，说明如何编写自定义的迭代器/可迭代对象。现在，我只是希望你理解`next()`是如何工作的。

当你调用`next(generator)`时，你调用了`generator.__next__()`方法。记住，**方法**只是属于对象的函数，而 Python 中的对象可以有特殊的方法。`__next__()`只是其中之一，它的目的是返回迭代的下一个元素，或者在迭代结束时引发`StopIteration`，并且没有更多的元素可以返回。

如果你还记得，在 Python 中，对象的特殊方法也被称为**魔术方法**，或者**dunder**（来自“双下划线”）**方法**。

当我们编写一个生成器函数时，Python 会自动将其转换为一个与迭代器非常相似的对象，当我们调用`next(generator)`时，该调用会转换为`generator.__next__()`。让我们重新讨论一下关于生成平方数的先前示例：

```py
# first.n.squares.manual.method.py
def get_squares_gen(n):
    for x in range(n):
        yield x ** 2

squares = get_squares_gen(3)
print(squares.__next__())  # prints: 0
print(squares.__next__())  # prints: 1
print(squares.__next__())  # prints: 4
# the following raises StopIteration, the generator is exhausted,
# any further call to next will keep raising StopIteration
```

结果与前面的示例完全相同，只是这次我们直接调用`squares.__next__()`，而不是使用`next(squares)`代理调用。

生成器对象还有另外三种方法，允许我们控制它们的行为：`send`，`throw`和`close`。`send`允许我们向生成器对象发送一个值，而`throw`和`close`分别允许我们在生成器内部引发异常并关闭它。它们的使用非常高级，我不会在这里详细介绍它们，但我想在`send`上花几句话，举个简单的例子：

```py
# gen.send.preparation.py
def counter(start=0):
    n = start
    while True:
        yield n
        n += 1

c = counter()
print(next(c))  # prints: 0
print(next(c))  # prints: 1
print(next(c))  # prints: 2
```

前面的迭代器创建了一个将永远运行的生成器对象。您可以不断调用它，它永远不会停止。或者，您可以将其放入`for`循环中，例如，`for n in counter(): ...`，它也将永远运行。但是，如果您想在某个时刻停止它怎么办？一种解决方案是使用变量来控制`while`循环。例如：

```py
# gen.send.preparation.stop.py
stop = False
def counter(start=0):
    n = start
    while not stop:
        yield n
        n += 1

c = counter()
print(next(c))  # prints: 0
print(next(c))  # prints: 1
stop = True
print(next(c))  # raises StopIteration
```

这样就可以了。我们从`stop = False`开始，直到我们将其更改为`True`，生成器将像以前一样继续运行。然而，一旦我们将`stop`更改为`True`，`while`循环将退出，并且下一次调用将引发`StopIteration`异常。这个技巧有效，但我不喜欢它。我们依赖于一个外部变量，这可能会导致问题：如果另一个函数改变了`stop`会怎么样？此外，代码是分散的。简而言之，这还不够好。

我们可以通过使用`generator.send()`来改进它。当我们调用`generator.send()`时，我们向`send`提供的值将被传递给生成器，执行将恢复，我们可以通过`yield`表达式获取它。用文字解释这一切都很复杂，所以让我们看一个例子：

```py
# gen.send.py
def counter(start=0):
    n = start
    while True:
        result = yield n             # A
        print(type(result), result)  # B
        if result == 'Q':
            break
        n += 1

c = counter()
print(next(c))         # C
print(c.send('Wow!'))  # D
print(next(c))         # E
print(c.send('Q'))     # F
```

执行上述代码会产生以下结果：

```py
$ python gen.send.py
0
<class 'str'> Wow!
1
<class 'NoneType'> None
2
<class 'str'> Q
Traceback (most recent call last):
 File "gen.send.py", line 14, in <module>
 print(c.send('Q')) # F
StopIteration
```

我认为逐行阅读这段代码是值得的，就好像我们在执行它一样，看看我们是否能理解发生了什么。

我们通过调用`next`(`#C`)开始生成器执行。在生成器中，`n`被设置为与`start`相同的值。进入`while`循环，执行停止（`#A`），`n`（`0`）被返回给调用者。`0`被打印在控制台上。

然后我们调用`send`(`#D`)，执行恢复，`result`被设置为`'Wow!'`（仍然是`#A`），然后它的类型和值被打印在控制台上（`#B`）。`result`不是`'Q'`，因此`n`增加了`1`，执行返回到`while`条件，这时，`True`被评估为`True`（这不难猜到，对吧？）。另一个循环开始，执行再次停止（`#A`），`n`（`1`）被返回给调用者。`1`被打印在控制台上。

在这一点上，我们调用`next`(`#E`)，执行再次恢复（`#A`），因为我们没有明确向生成器发送任何内容，Python 的行为与不使用`return`语句的函数完全相同；`yield n`表达式（`#A`）返回`None`。因此，`result`被设置为`None`，其类型和值再次被打印在控制台上（`#B`）。执行继续，`result`不是`'Q'`，所以`n`增加了`1`，我们再次开始另一个循环。执行再次停止（`#A`），`n`（`2`）被返回给调用者。`2`被打印在控制台上。

现在到了大结局：我们再次调用`send`（`#F`），但这次我们传入了`'Q'`，因此当执行恢复时，`result`被设置为`'Q'`（`#A`）。它的类型和值被打印在控制台上（`#B`），最后`if`子句评估为`True`，`while`循环被`break`语句停止。生成器自然终止，这意味着会引发`StopIteration`异常。您可以在控制台上看到它的回溯打印在最后几行上。

这一开始并不容易理解，所以如果对您来说不清楚，不要气馁。您可以继续阅读，然后过一段时间再回到这个例子。

使用`send`允许有趣的模式，值得注意的是`send`也可以用于启动生成器的执行（只要您用`None`调用它）。

# `yield from`表达式

另一个有趣的构造是`yield from`表达式。这个表达式允许您从子迭代器中产生值。它的使用允许相当高级的模式，所以让我们快速看一个非常快速的例子：

```py
# gen.yield.for.py def print_squares(start, end):
    for n in range(start, end):
        yield n ** 2

for n in print_squares(2, 5):
    print(n)
```

前面的代码在控制台上打印出数字`4`，`9`，`16`（分别在不同的行上）。到现在为止，我希望您能够自己理解它，但让我们快速回顾一下发生了什么。函数外部的`for`循环从`print_squares(2, 5)`获取一个迭代器，并在其上调用`next`，直到迭代结束。每次调用生成器时，执行都会被暂停（稍后恢复）在`yield n ** 2`上，它返回当前`n`的平方。让我们看看如何利用`yield from`表达式改变这段代码：

```py
# gen.yield.from.py
def print_squares(start, end):
    yield from (n ** 2 for n in range(start, end))

for n in print_squares(2, 5):
    print(n)
```

这段代码产生了相同的结果，但是您可以看到`yield from`实际上正在运行一个子迭代器`(n ** 2 ...)`。`yield from`表达式将子迭代器产生的每个值返回给调用者。它更短，阅读起来更好。

# 生成器表达式

现在让我们谈谈其他一次生成值的技术。

语法与`list`推导完全相同，只是，不是用方括号包装推导，而是用圆括号包装。这就是所谓的**生成器表达式**。

通常，生成器表达式的行为类似于等效的`list`推导，但有一件非常重要的事情要记住：生成器只允许一次迭代，然后它们将被耗尽。让我们看一个例子：

```py
# generator.expressions.py
>>> cubes = [k**3 for k in range(10)]  # regular list
>>> cubes
[0, 1, 8, 27, 64, 125, 216, 343, 512, 729]
>>> type(cubes)
<class 'list'>
>>> cubes_gen = (k**3 for k in range(10))  # create as generator
>>> cubes_gen
<generator object <genexpr> at 0x103fb5a98>
>>> type(cubes_gen)
<class 'generator'>
>>> _(cubes_gen)  # this will exhaust the generator
[0, 1, 8, 27, 64, 125, 216, 343, 512, 729]
>>> _(cubes_gen)  # nothing more to give
[]
```

看看生成器表达式被创建并分配名称`cubes_gen`的行。您可以看到它是一个生成器对象。为了看到它的元素，我们可以使用`for`循环，手动调用`next`，或者简单地将其传递给`list`构造函数，这就是我所做的（记住我使用`_`作为别名）。

请注意，一旦生成器被耗尽，就没有办法再次从中恢复相同的元素。如果我们想要再次从头开始使用它，我们需要重新创建它。

在接下来的几个例子中，让我们看看如何使用生成器表达式复制`map`和`filter`： 

```py
# gen.map.py
def adder(*n):
    return sum(n)
s1 = sum(map(lambda *n: adder(*n), range(100), range(1, 101)))
s2 = sum(adder(*n) for n in zip(range(100), range(1, 101)))
```

在前面的例子中，`s1`和`s2`完全相同：它们是`adder(0, 1), adder(1, 2), adder(2, 3)`的和，依此类推，这对应于`sum(1, 3, 5, ...)`。尽管语法不同，但我发现生成器表达式更易读：

```py
# gen.filter.py
cubes = [x**3 for x in range(10)]

odd_cubes1 = filter(lambda cube: cube % 2, cubes)
odd_cubes2 = (cube for cube in cubes if cube % 2)
```

在前面的例子中，`odd_cubes1`和`odd_cubes2`是相同的：它们生成奇数立方体的序列。当事情变得有点复杂时，我再次更喜欢生成器语法。这应该在事情变得有点复杂时显而易见：

```py
# gen.map.filter.py
N = 20
cubes1 = map(
    lambda n: (n, n**3),
    filter(lambda n: n % 3 == 0 or n % 5 == 0, range(N))
)
cubes2 = (
    (n, n**3) for n in range(N) if n % 3 == 0 or n % 5 == 0)
```

前面的代码创建了两个生成器，`cubes1`和`cubes2`。它们完全相同，当`n`是`3`或`5`的倍数时返回两个元组（*n，n³*）。

如果打印列表（`cubes1`），您会得到：`[(0, 0), (3, 27), (5, 125), (6, 216), (9, 729), (10, 1000), (12, 1728), (15, 3375), (18, 5832)]`。

看看生成器表达式读起来好多了？当事情非常简单时，这可能是值得商榷的，但是一旦你开始嵌套函数一点，就像我们在这个例子中所做的那样，生成器语法的优越性就显而易见了。它更短，更简单，更优雅。

现在，让我问你一个问题——以下代码的区别是什么：

```py
# sum.example.py
s1 = sum([n**2 for n in range(10**6)])
s2 = sum((n**2 for n in range(10**6)))
s3 = sum(n**2 for n in range(10**6))
```

严格来说，它们都产生相同的总和。获取`s2`和`s3`的表达式完全相同，因为`s2`中的括号是多余的。它们都是`sum`函数中的生成器表达式。然而，获取`s1`的表达式是不同的。在`sum`中，我们找到了一个`list`理解。这意味着为了计算`s1`，`sum`函数必须在列表上调用一百万次`next`。

你看到我们在浪费时间和内存吗？在`sum`可以开始在列表上调用`next`之前，列表需要被创建，这是一种浪费时间和空间。对于`sum`来说，在一个简单的生成器表达式上调用`next`要好得多。没有必要将`range(10**6)`中的所有数字存储在列表中。

因此，*在编写表达式时要注意额外的括号*：有时很容易忽略这些细节，这使得我们的代码非常不同。如果你不相信我，看看下面的代码：

```py
# sum.example.2.py
s = sum([n**2 for n in range(10**8)])  # this is killed
# s = sum(n**2 for n in range(10**8))    # this succeeds
print(s)  # prints: 333333328333333350000000
```

尝试运行前面的例子。如果我在我的旧 Linux 框上运行第一行，内存为 8GB，这就是我得到的：

```py
$ python sum.example.2.py
Killed  
```

另一方面，如果我注释掉第一行，并取消注释第二行，这就是结果：

```py
$ python sum.example.2.py
333333328333333350000000  
```

甜蜜的生成器表达式。两行之间的区别在于，在第一行中，必须先制作一个前一亿个数字的平方的列表，然后才能将它们相加。那个列表很大，我们的内存用完了（至少，我的内存用完了，如果你的内存没有用完，试试更大的数字），因此 Python 为我们终止了进程。悲伤的脸。

但是当我们去掉方括号时，我们不再有一个列表。`sum`函数接收`0`，`1`，`4`，`9`，直到最后一个，然后将它们相加。没有问题，开心脸。

# 一些性能考虑

因此，我们已经看到了实现相同结果的许多不同方法。我们可以使用`map`，`zip`和`filter`的任何组合，或者选择使用理解，或者可能选择使用生成器，无论是函数还是表达式。我们甚至可以决定使用`for`循环；当要应用于每个运行参数的逻辑不简单时，它们可能是最佳选择。

除了可读性问题之外，让我们谈谈性能。在性能方面，通常有两个因素起着重要作用：**空间**和**时间**。

空间意味着数据结构要占用的内存大小。选择的最佳方法是问自己是否真的需要一个列表（或元组），或者一个简单的生成器函数是否同样有效。如果答案是肯定的，那就选择生成器，它会节省很多空间。对于函数也是一样；如果你实际上不需要它们返回一个列表或元组，那么你也可以将它们转换为生成器函数。

有时，你将不得不使用列表（或元组），例如有一些算法使用多个指针扫描序列，或者可能多次运行序列。生成器函数（或表达式）只能迭代一次，然后就用完了，所以在这些情况下，它不是正确的选择。

时间比空间更难，因为它取决于更多的变量，因此不可能绝对肯定地说*X 比 Y 更快*对于所有情况。然而，基于今天在 Python 上运行的测试，我们可以说，平均而言，`map`表现出与`list`理解和生成器表达式类似的性能，而`for`循环一直较慢。

为了充分理解这些陈述背后的推理，我们需要了解 Python 的工作原理，这有点超出了本书的范围，因为它在技术细节上太复杂。让我们只说`map`和`list`理解在解释器内以 C 语言速度运行，而 Python `for`循环作为 Python 虚拟机内的 Python 字节码运行，通常要慢得多。

Python 有几种不同的实现。最初的，也是最常见的一个是 CPython ([`github.com/python/cpython`](https://github.com/python/cpython))，它是用 C 语言编写的。C 语言是今天仍然使用的最强大和流行的编程语言之一。

我们来做一个小练习，试着找出我所说的是否准确？我将编写一小段代码，收集`divmod(a, b)`的结果，对于一定的整数对`(a, b)`。我将使用`time`模块中的`time`函数来计算我将执行的操作的经过时间：

```py
# performances.py
from time import time
mx = 5000

t = time()  # start time for the for loop
floop = []
for a in range(1, mx):
    for b in range(a, mx):
        floop.append(divmod(a, b))
print('for loop: {:.4f} s'.format(time() - t))  # elapsed time

t = time()  # start time for the list comprehension
compr = [
    divmod(a, b) for a in range(1, mx) for b in range(a, mx)]
print('list comprehension: {:.4f} s'.format(time() - t))

t = time()  # start time for the generator expression
gener = list(
    divmod(a, b) for a in range(1, mx) for b in range(a, mx))
print('generator expression: {:.4f} s'.format(time() - t))
```

你可以看到，我们创建了三个列表：`floop`、`compr`和`gener`。运行代码会产生以下结果：

```py
$ python performances.py
for loop: 4.4814 s
list comprehension: 3.0210 s
generator expression: 3.4334 s
```

`list`理解运行时间约为`for`循环时间的 67%。这令人印象深刻。生成器表达式接近这个时间，约为`for`循环时间的 77%。生成器表达式较慢的原因是我们需要将其提供给`list()`构造函数，这与纯粹的`list`理解相比有更多的开销。如果我不必保留这些计算的结果，生成器可能是更合适的选择。

有趣的是，在`for`循环的主体中，我们正在向列表中添加数据。这意味着 Python 在幕后做着工作，不时地调整大小，为要添加的项目分配空间。我猜想创建一个零列表，并简单地用结果填充它，可能会加快`for`循环的速度，但我错了。你自己检查一下，你只需要预分配`mx * (mx - 1) // 2`个元素。

让我们看一个类似的例子，比较一下`for`循环和`map`调用：

```py
# performances.map.py
from time import time
mx = 2 * 10 ** 7

t = time()
absloop = []
for n in range(mx):
    absloop.append(abs(n))
print('for loop: {:.4f} s'.format(time() - t))

t = time()
abslist = [abs(n) for n in range(mx)]
print('list comprehension: {:.4f} s'.format(time() - t))

t = time()
absmap = list(map(abs, range(mx)))
print('map: {:.4f} s'.format(time() - t))
```

这段代码在概念上与前面的例子非常相似。唯一改变的是我们应用了`abs`函数而不是`divmod`，并且我们只有一个循环而不是两个嵌套的循环。执行后得到以下结果：

```py
$ python performances.map.py
for loop: 3.8948 s
list comprehension: 1.8594 s
map: 1.1548 s
```

而`map`赢得了比赛：约为`list`理解时间的 62%，`for`循环时间的 30%。这些结果可能会有所不同，因为各种因素，如操作系统和 Python 版本。但总的来说，我认为这些结果足够好，可以让我们对编写性能代码有一个概念。

尽管有一些个案的小差异，很明显`for`循环选项是最慢的，所以让我们看看为什么我们仍然想要使用它。

# 不要过度使用理解和生成器

我们已经看到了`list`理解和生成器表达式有多么强大。它们确实如此，不要误会我的意思，但当我处理它们时的感觉是，它们的复杂性呈指数增长。你尝试在一个单一的理解或生成器表达式中做的越多，它就越难以阅读、理解，因此也就越难以维护或更改。

如果你再次查看 Python 之禅，有几行我认为值得在处理优化代码时牢记：

```py
>>> import this
...
Explicit is better than implicit.
Simple is better than complex.
...
Readability counts.
...
If the implementation is hard to explain, it's a bad idea.
...
```

理解和生成器表达式比较隐式而不是显式，可能相当难以阅读和理解，也很难解释。有时你必须使用由内而外的技术来分解它们，以理解发生了什么。

举个例子，让我们再谈谈毕达哥拉斯三元组。只是提醒一下，毕达哥拉斯三元组是一组正整数元组(*a*, *b*, *c*)，使得*a² + b² = c²*。

我们在*过滤理解*部分看到了如何计算它们，但我们以一种非常低效的方式进行了，因为我们正在扫描所有低于某个阈值的数字对，计算斜边，并过滤掉那些没有产生三元组的数字对。

获得勾股数三元组的更好方法是直接生成它们。有许多不同的公式可以用来做到这一点，我们将使用**欧几里得公式**。

这个公式表明，任何三元组(*a*，*b*，*c*)，其中*a = m² - n²*，*b = 2mn*，*c = m² + n²*，*m*和*n*是正整数，满足*m > n*，都是勾股数三元组。例如，当*m = 2*，*n = 1*时，我们找到了最小的三元组：(*3*，*4*，*5*)。

然而，有一个问题：考虑一下三元组(*6*，*8*，*10*)，它就像(*3*，*4*，*5*)一样，只是所有数字都乘以*2*。这个三元组肯定是勾股数三元组，因为*6² + 8² = 10²*，但我们可以通过简单地将其每个元素乘以*2*来从(*3*，*4*，*5*)派生出它。对于所有可以写成(*3k*，*4k*，*5k*)的三元组，其中*k*是大于*1*的正整数，情况也是如此。

不能通过将另一个三元组的元素乘以某个因子*k*获得的三元组称为**原始**。另一种陈述这一点的方式是：如果三元组的三个元素是**互质**的，那么这个三元组就是原始的。当两个数在它们的除数中没有共享任何质因数时，它们就是互质的，也就是说，它们的**最大公约数**（**GCD**）是*1*。例如，3 和 5 是互质的，而 3 和 6 不是，因为它们都可以被 3 整除。

因此，欧几里得公式告诉我们，如果*m*和*n*是互质的，并且*m - n*是奇数，那么它们生成的三元组是原始的。在下面的例子中，我们将编写一个生成器表达式，计算所有原始的勾股数三元组，其斜边(*c*)小于或等于某个整数*N*。这意味着我们希望所有满足*m² + n² ≤ N*的三元组。当*n*为*1*时，公式如下：*m² ≤ N - 1*，这意味着我们可以用*m ≤ N^(1/2)*的上限来近似计算。

因此，总结一下：*m*必须大于*n*，它们也必须互质，它们的差异*m - n*必须是奇数。此外，为了避免无用的计算，我们将*m*的上限设定为*floor(sqrt(N)) + 1*。

实数*x*的`floor`函数给出最大整数*n*，使得*n < x*，例如，*floor(3.8) = 3*，*floor(13.1) = 13*。取*floor(sqrt(N)) + 1*意味着取*N*的平方根的整数部分，并添加一个最小的边距，以确保我们不会错过任何数字。

让我们一步一步地将所有这些放入代码中。让我们首先编写一个使用**欧几里得算法**的简单`gcd`函数：

```py
# functions.py
def gcd(a, b):
    """Calculate the Greatest Common Divisor of (a, b). """
    while b != 0:
        a, b = b, a % b
    return a
```

欧几里得算法的解释可以在网上找到，所以我不会在这里花时间谈论它；我们需要专注于生成器表达式。下一步是利用之前收集的知识来生成一个原始勾股数三元组的列表：

```py
# pythagorean.triple.generation.py
from functions import gcd
N = 50

triples = sorted(                                    # 1
    ((a, b, c) for a, b, c in (                      # 2
        ((m**2 - n**2), (2 * m * n), (m**2 + n**2))  # 3
        for m in range(1, int(N**.5) + 1)            # 4
        for n in range(1, m)                         # 5
        if (m - n) % 2 and gcd(m, n) == 1            # 6
    ) if c <= N), key=lambda *triple: sum(*triple)   # 7
)
```

这就是了。它不容易阅读，所以让我们逐行进行解释。在`#3`处，我们开始一个生成器表达式，用于创建三元组。从`#4`和`#5`可以看出，我们在*[1，M]*中循环*m*，其中*M*是*sqrt(N)*的整数部分，再加上*1*。另一方面，*n*在*[1，m)*中循环，以遵守*m > n*的规则。值得注意的是我如何计算*sqrt(N)*，即`N**.5`，这只是另一种我想向你展示的方法。

在`＃6`，您可以看到使三元组原始的过滤条件：当`(m - n)`为奇数时，`(m - n)％2`的值为`True`，而`gcd(m, n) == 1`表示`m`和`n`是互质的。有了这些条件，我们知道三元组将是原始的。这照顾了最内层的生成器表达式。最外层的生成器表达式从`＃2`开始，结束于`＃7`。我们取(*a*, *b*, *c*)在(...最内层生成器...)中，使得`c <= N`。

最后，在`＃1`我们应用排序，以按顺序呈现列表。在最外层生成器表达式关闭后的`＃7`处，您可以看到我们指定排序键为和的总和*a + b + c*。这只是我的个人偏好，没有数学原因。

那么，你觉得呢？阅读起来简单吗？我不这么认为。相信我，这仍然是一个简单的例子；在我的职业生涯中，我见过更糟糕的情况。这种代码难以理解、调试和修改。它不应该出现在专业环境中。

所以，让我们看看是否可以将这段代码重写成更易读的形式：

```py
# pythagorean.triple.generation.for.py
from functions import gcd

def gen_triples(N):
    for m in range(1, int(N**.5) + 1):                  # 1
        for n in range(1, m):                           # 2
            if (m - n) % 2 and gcd(m, n) == 1:          # 3
                c = m**2 + n**2                         # 4
                if c <= N:                              # 5
                    a = m**2 - n**2                     # 6
                    b = 2 * m * n                       # 7
                    yield (a, b, c)                     # 8

triples = sorted(
    gen_triples(50), key=lambda *triple: sum(*triple))  # 9
```

这好多了。让我们逐行看一下。你会看到它有多容易理解。

我们从`＃1`和`＃2`开始循环，方式与之前的示例中的循环方式完全相同。在第`＃3`行，我们对原始三元组进行了过滤。在第`＃4`行，我们有了一点偏离之前的做法：我们计算了`c`，在第`＃5`行，我们对`c`小于或等于`N`进行了过滤。只有当`c`满足这个条件时，我们才计算`a`和`b`，并产生结果的元组。尽可能延迟所有计算总是很好的，这样我们就不会浪费时间和 CPU。在最后一行，我们使用了与生成器表达式示例中相同的键进行排序。

希望你同意，这个例子更容易理解。我向你保证，如果有一天你不得不修改这段代码，你会发现修改这个代码很容易，而修改另一个版本将需要更长的时间（而且容易出错）。

如果打印两个示例的结果（它们是相同的），你会得到这个：

```py
[(3, 4, 5), (5, 12, 13), (15, 8, 17), (7, 24, 25), (21, 20, 29), (35, 12, 37), (9, 40, 41)]  
```

故事的寓意是，尽量使用理解和生成器表达式，但如果代码开始变得复杂，难以修改或阅读，你可能需要将其重构为更易读的形式。你的同事会感谢你。

# 名称本地化

既然我们熟悉了所有类型的理解和生成器表达式，让我们谈谈它们内部的名称本地化。Python 3.*在所有四种理解形式中都将循环变量本地化：`list`、`dict`、`set`和生成器表达式。这种行为与`for`循环的行为不同。让我们看一个简单的例子来展示所有情况：

```py
# scopes.py
A = 100
ex1 = [A for A in range(5)]
print(A)  # prints: 100

ex2 = list(A for A in range(5))
print(A)  # prints: 100

ex3 = dict((A, 2 * A) for A in range(5))
print(A)  # prints: 100

ex4 = set(A for A in range(5))
print(A)  # prints: 100

s = 0
for A in range(5):
    s += A
print(A)  # prints: 4
```

在前面的代码中，我们声明了一个全局名称`A = 100`，然后我们使用了四种理解方式：`list`、生成器表达式、字典和`set`。它们都没有改变全局名称`A`。相反，您可以在最后看到`for`循环修改了它。最后的打印语句打印出`4`。

让我们看看如果没有`A`会发生什么：

```py
# scopes.noglobal.py
ex1 = [A for A in range(5)]
print(A)  # breaks: NameError: name 'A' is not defined
```

前面的代码可以使用任何四种理解方式来完成相同的工作。运行第一行后，`A`在全局命名空间中未定义。再次，`for`循环的行为不同：

```py
# scopes.for.py
s = 0
for A in range(5):
    s += A
print(A) # prints: 4
print(globals())
```

前面的代码表明，在`for`循环之后，如果循环变量在之前没有定义，我们可以在全局框架中找到它。为了确保这一点，让我们调用`globals()`内置函数来一探究竟：

```py
$ python scopes.for.py
4
{'__name__': '__main__', '__doc__': None, ..., 's': 10, 'A': 4}
```

除了我省略的大量样板之外，我们可以发现`'A': 4`。

# 内置生成行为

在内置类型中，生成行为现在非常普遍。这是 Python 2 和 Python 3 之间的一个重大区别。许多函数，如`map`、`zip`和`filter`，都已经改变，以便它们返回像可迭代对象一样的对象。这种改变背后的想法是，如果你需要制作这些结果的列表，你可以总是将调用包装在`list()`类中，然后你就完成了。另一方面，如果你只需要迭代，并希望尽可能减少对内存的影响，你可以安全地使用这些函数。

另一个显著的例子是`range`函数。在 Python 2 中，它返回一个列表，还有另一个叫做`xrange`的函数，它返回一个你可以迭代的对象，它会动态生成数字。在 Python 3 中，这个函数已经消失了，`range`现在的行为就像它。

但是，这个概念，总的来说，现在是相当普遍的。你可以在`open()`函数中找到它，这个函数用于操作文件对象（我们将在第七章中看到它，*文件和数据持久性*），但也可以在`enumerate`、字典`keys`、`values`和`items`方法以及其他一些地方找到它。

这一切都是有道理的：Python 的目标是尽可能减少内存占用，尽量避免浪费空间，特别是在大多数情况下广泛使用的那些函数和方法中。

你还记得本章开头吗？我说过，优化那些必须处理大量对象的代码的性能比每天调用两次的函数节省几毫秒更有意义。

# 最后一个例子

在我们结束本章之前，我会向你展示一个我曾经在一家我曾经工作过的公司提交给 Python 开发人员角色的一个简单问题。

问题是：给定序列`0 1 1 2 3 5 8 13 21 ...`，编写一个函数，它将返回这个序列的项直到某个限制`N`。

如果你没有意识到，那就是斐波那契数列，它被定义为*F(0) = 0*，*F(1) = 1*，对于任何*n > 1*，*F(n) = F(n-1) + F(n-2)*。这个序列非常适合测试关于递归、记忆化技术和其他技术细节的知识，但在这种情况下，这是一个检查候选人是否了解生成器的好机会。

让我们从一个基本版本的函数开始，然后对其进行改进：

```py
# fibonacci.first.py
def fibonacci(N):
    """Return all fibonacci numbers up to N. """
    result = [0]
    next_n = 1
    while next_n <= N:
        result.append(next_n)
        next_n = sum(result[-2:])
    return result

print(fibonacci(0))   # [0]
print(fibonacci(1))   # [0, 1, 1]
print(fibonacci(50))  # [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]
```

从头开始：我们将`result`列表设置为起始值`[0]`。然后我们从下一个元素（`next_n`）开始迭代，即`1`。只要下一个元素不大于`N`，我们就不断将它附加到列表中并计算下一个。我们通过取`result`列表中最后两个元素的切片并将其传递给`sum`函数来计算下一个元素。如果这对你来说不清楚，可以在这里和那里添加一些`print`语句，但到现在我希望这不会成为一个问题。

当`while`循环的条件评估为`False`时，我们退出循环并返回`result`。你可以在每个`print`语句旁边的注释中看到这些`print`语句的结果。

在这一点上，我会问候选人以下问题：*如果我只想迭代这些数字怎么办？* 一个好的候选人会改变代码，你会在这里找到（一个优秀的候选人会从这里开始！）：

```py
# fibonacci.second.py
def fibonacci(N):
    """Return all fibonacci numbers up to N. """
    yield 0
    if N == 0:
        return
    a = 0
    b = 1
    while b <= N:
        yield b
        a, b = b, a + b

print(list(fibonacci(0)))   # [0]
print(list(fibonacci(1)))   # [0, 1, 1]
print(list(fibonacci(50)))  # [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]
```

这实际上是我得到的解决方案之一。我不知道为什么我保存了它，但我很高兴我这样做了，这样我就可以向你展示它。现在，`fibonacci`函数是一个*生成器函数*。首先我们产生`0`，然后如果`N`是`0`，我们返回（这将导致引发`StopIteration`异常）。如果不是这种情况，我们开始迭代，每个循环周期产生`b`，然后更新`a`和`b`。为了能够产生序列的下一个元素，我们只需要过去的两个：`a`和`b`。

这段代码好多了，内存占用更少，我们只需要用`list()`将调用包装起来，就像往常一样，就可以得到一个斐波那契数列。但是优雅呢？我不能就这样把它留下吧？让我们试试下面的方法：

```py
# fibonacci.elegant.py
def fibonacci(N):
    """Return all fibonacci numbers up to N. """
    a, b = 0, 1
    while a <= N:
        yield a
        a, b = b, a + b
```

好多了。这个函数的整个主体只有四行，如果算上文档字符串的话就是五行。请注意，在这种情况下，使用元组赋值（`a, b = 0, 1`和`a, b = b, a + b`）有助于使代码更短、更易读。

# 摘要

在本章中，我们更深入地探讨了迭代和生成的概念。我们详细研究了`map`、`zip`和`filter`函数，并学会了如何将它们作为常规`for`循环方法的替代方法。

然后我们讨论了列表、字典和集合的理解概念。我们探讨了它们的语法以及如何将它们作为传统的`for`循环方法和`map`、`zip`和`filter`函数的替代方法来使用。

最后，我们讨论了生成的概念，有两种形式：生成器函数和表达式。我们学会了如何通过使用生成技术来节省时间和空间，并看到它们如何使得通常情况下无法实现的事情成为可能。

我们谈到了性能，并看到`for`循环在速度上是最慢的，但它们提供了最佳的可读性和灵活性。另一方面，诸如`map`和`filter`以及`list`推导这样的函数可能会快得多。

使用这些技术编写的代码复杂度呈指数级增长，因此，为了更有利于可读性和易维护性，我们仍然需要有时使用传统的`for`循环方法。另一个区别在于名称本地化，其中`for`循环的行为与所有其他类型的推导不同。

下一章将全面讨论对象和类。它在结构上与本章类似，我们不会探讨许多不同的主题，只是其中的一些，但我们会尝试更深入地探讨它们。

在继续下一章之前，请确保您理解了本章的概念。我们正在一砖一瓦地建造一堵墙，如果基础不牢固，我们将走不远。
