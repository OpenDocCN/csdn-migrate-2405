# Python 入门指南（五）

> 原文：[`zh.annas-archive.org/md5/97bc15629f1b51a0671040c56db61b92`](https://zh.annas-archive.org/md5/97bc15629f1b51a0671040c56db61b92)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十六章：Python 中的对象

因此，我们现在手头上有一个设计，并且准备将该设计转化为一个可工作的程序！当然，通常情况下不会这样。我们将在整本书中看到好的软件设计示例和提示，但我们的重点是面向对象的编程。因此，让我们来看一下 Python 语法，它允许我们创建面向对象的软件。

完成本章后，我们将了解以下内容：

+   如何在 Python 中创建类和实例化对象

+   如何向 Python 对象添加属性和行为

+   如何将类组织成包和模块

+   如何建议人们不要破坏我们的数据

# 创建 Python 类

我们不必写太多 Python 代码就能意识到 Python 是一种非常*干净*的语言。当我们想做某事时，我们可以直接做，而不必设置一堆先决条件代码。Python 中无处不在的*hello world*，正如你可能已经看到的，只有一行。

同样，Python 3 中最简单的类如下所示：

```py
class MyFirstClass: 
    pass 
```

这是我们的第一个面向对象的程序！类定义以`class`关键字开头。然后是一个名称（我们选择的）来标识类，并以冒号结束。

类名必须遵循标准的 Python 变量命名规则（必须以字母或下划线开头，只能由字母、下划线或数字组成）。此外，Python 风格指南（在网上搜索*PEP 8*）建议使用**CapWords**表示法来命名类（以大写字母开头；任何后续的单词也应以大写字母开头）。

类定义行后面是类内容，缩进。与其他 Python 结构一样，缩进用于界定类，而不是大括号、关键字或括号，就像许多其他语言使用的那样。同样符合风格指南，除非有充分的理由不这样做（比如适应使用制表符缩进的其他人的代码），否则使用四个空格进行缩进。

由于我们的第一个类实际上并没有添加任何数据或行为，我们只需在第二行使用`pass`关键字表示不需要采取进一步的行动。

我们可能会认为这个最基本的类没有太多可以做的，但它确实允许我们实例化该类的对象。我们可以将该类加载到 Python 3 解释器中，这样我们就可以交互式地使用它。为了做到这一点，将前面提到的类定义保存在一个名为`first_class.py`的文件中，然后运行`python -i first_class.py`命令。`-i`参数告诉 Python*运行代码然后转到交互式解释器*。以下解释器会话演示了与这个类的基本交互：

```py
>>> a = MyFirstClass()
>>> b = MyFirstClass()
>>> print(a)
<__main__.MyFirstClass object at 0xb7b7faec>
>>> print(b)
<__main__.MyFirstClass object at 0xb7b7fbac>
>>>  
```

这段代码从新类实例化了两个对象，命名为`a`和`b`。创建一个类的实例只需要输入类名，后面跟着一对括号。它看起来很像一个普通的函数调用，但 Python 知道我们*调用*的是一个类而不是一个函数，所以它知道它的工作是创建一个新对象。当打印时，这两个对象告诉我们它们属于哪个类以及它们所在的内存地址。在 Python 代码中很少使用内存地址，但在这里，它们表明有两个不同的对象参与其中。

# 添加属性

现在，我们有一个基本的类，但它相当无用。它不包含任何数据，也不做任何事情。我们需要做什么来为给定的对象分配属性？

实际上，在类定义中我们不必做任何特殊的事情。我们可以使用点符号在实例化的对象上设置任意属性：

```py
class Point: 
    pass 

p1 = Point() 
p2 = Point() 

p1.x = 5 
p1.y = 4 

p2.x = 3 
p2.y = 6 

print(p1.x, p1.y) 
print(p2.x, p2.y) 
```

如果我们运行这段代码，结尾的两个`print`语句会告诉我们两个对象上的新属性值：

```py
5 4
3 6
```

这段代码创建了一个没有数据或行为的空`Point`类。然后，它创建了该类的两个实例，并分别为这些实例分配`x`和`y`坐标，以标识二维空间中的一个点。我们只需要使用`<object>.<attribute> = <value>`语法为对象的属性分配一个值。这有时被称为**点符号表示法**。在阅读标准库或第三方库提供的对象属性时，你可能已经遇到过这种表示法。值可以是任何东西：Python 原语、内置数据类型或另一个对象。甚至可以是一个函数或另一个类！

# 让它做点什么

现在，拥有属性的对象很棒，但面向对象编程实际上是关于对象之间的交互。我们感兴趣的是调用会影响这些属性的动作。我们有数据；现在是时候为我们的类添加行为了。

让我们在我们的`Point`类上建模一些动作。我们可以从一个名为`reset`的**方法**开始，它将点移动到原点（原点是`x`和`y`都为零的地方）。这是一个很好的介绍性动作，因为它不需要任何参数：

```py
class Point: 
 def reset(self): 
        self.x = 0 
        self.y = 0 

p = Point() 
p.reset() 
print(p.x, p.y) 
```

这个`print`语句显示了属性上的两个零：

```py
0 0  
```

在 Python 中，方法的格式与函数完全相同。它以`def`关键字开头，后面跟着一个空格，然后是方法的名称。然后是一组包含参数列表的括号（我们将在接下来讨论`self`参数），并以冒号结束。下一行缩进包含方法内部的语句。这些语句可以是任意的 Python 代码，对对象本身和传入的任何参数进行操作，方法会自行决定。

# 自言自语

在方法和普通函数之间的一个语法上的区别是，所有方法都有一个必需的参数。这个参数通常被命名为`self`；我从未见过 Python 程序员使用其他名称来命名这个变量（约定是一件非常有力的事情）。但是没有什么能阻止你将其命名为`this`甚至`Martha`。

方法中的`self`参数是对调用该方法的对象的引用。我们可以访问该对象的属性和方法，就好像它是另一个对象一样。这正是我们在`reset`方法中所做的，当我们设置`self`对象的`x`和`y`属性时。

在这个讨论中，注意**类**和**对象**之间的区别。我们可以将**方法**视为附加到类的函数。**self**参数是该类的特定实例。当你在两个不同的对象上调用方法时，你调用了相同的方法两次，但是将两个不同的**对象**作为**self**参数传递。

请注意，当我们调用`p.reset()`方法时，我们不必将`self`参数传递给它。Python 会自动为我们处理这部分。它知道我们在调用`p`对象上的方法，所以会自动将该对象传递给方法。

然而，方法实际上只是一个恰好在类上的函数。我们可以不在对象上调用方法，而是显式地在类上调用函数，将我们的对象作为`self`参数传递：

```py
>>> p = Point() 
>>> Point.reset(p) 
>>> print(p.x, p.y) 
```

输出与前面的例子相同，因为在内部发生了完全相同的过程。

如果我们在类定义中忘记包括`self`参数会发生什么？Python 会报错，如下所示：

```py
>>> class Point:
... def reset():
... pass
...
>>> p = Point()
>>> p.reset()
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
TypeError: reset() takes 0 positional arguments but 1 was given
```

错误消息并不像它本应该的那样清晰（嘿，傻瓜，你忘了`self`参数会更有信息量）。只要记住，当你看到指示缺少参数的错误消息时，首先要检查的是你是否在方法定义中忘记了`self`。

# 更多参数

那么，我们如何将多个参数传递给一个方法呢？让我们添加一个新的方法，允许我们将一个点移动到任意位置，而不仅仅是原点。我们还可以包括一个接受另一个`Point`对象作为输入并返回它们之间距离的方法：

```py
import math

class Point:
 def move(self, x, y):
        self.x = x
        self.y = y

    def reset(self):
        self.move(0, 0)

 def calculate_distance(self, other_point):
        return math.sqrt(
            (self.x - other_point.x) ** 2
            + (self.y - other_point.y) ** 2
        )

# how to use it:
point1 = Point()
point2 = Point()

point1.reset()
point2.move(5, 0)
print(point2.calculate_distance(point1))
assert point2.calculate_distance(point1) == point1.calculate_distance(
    point2
)
point1.move(3, 4)
print(point1.calculate_distance(point2))
print(point1.calculate_distance(point1))
```

结尾处的`print`语句给出了以下输出：

```py
5.0
4.47213595499958
0.0  
```

这里发生了很多事情。这个类现在有三个方法。`move`方法接受两个参数`x`和`y`，并在`self`对象上设置值，就像前面示例中的旧`reset`方法一样。旧的`reset`方法现在调用`move`，因为重置只是移动到一个特定的已知位置。

`calculate_distance`方法使用不太复杂的勾股定理来计算两点之间的距离。我希望你能理解这个数学（`**2`表示平方，`math.sqrt`计算平方根），但这并不是我们当前重点的要求，我们的当前重点是学习如何编写方法。

前面示例的结尾处的示例代码显示了如何调用带有参数的方法：只需将参数包含在括号内，并使用相同的点表示法来访问方法。我只是随机选择了一些位置来测试这些方法。测试代码调用每个方法并在控制台上打印结果。`assert`函数是一个简单的测试工具；如果`assert`后面的语句评估为`False`（或零、空或`None`），程序将退出。在这种情况下，我们使用它来确保无论哪个点调用另一个点的`calculate_distance`方法，距离都是相同的。

# 初始化对象

如果我们不显式设置`Point`对象上的`x`和`y`位置，要么使用`move`，要么直接访问它们，我们就会得到一个没有真实位置的破碎点。当我们尝试访问它时会发生什么呢？

好吧，让我们试试看。*试一试*是 Python 学习中非常有用的工具。打开你的交互式解释器，然后开始输入。以下交互式会话显示了如果我们尝试访问一个缺失属性会发生什么。如果你将前面的示例保存为文件，或者正在使用本书分发的示例，你可以使用`python -i more_arguments.py`命令将其加载到 Python 解释器中：

```py
>>> point = Point()
>>> point.x = 5
>>> print(point.x)
5
>>> print(point.y)
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
AttributeError: 'Point' object has no attribute 'y' 
```

好吧，至少它抛出了一个有用的异常。我们将在第十八章中详细介绍异常，*预料之外的情况*。你可能以前见过它们（特别是无处不在的 SyntaxError，它意味着你输入了错误的东西！）。在这一点上，只需意识到它意味着出了问题。

输出对于调试是有用的。在交互式解释器中，它告诉我们错误发生在第 1 行，这只是部分正确的（在交互式会话中，一次只执行一行）。如果我们在文件中运行脚本，它会告诉我们确切的行号，这样很容易找到错误的代码。此外，它告诉我们错误是`AttributeError`，并给出一个有用的消息告诉我们这个错误是什么意思。

我们可以捕获并从这个错误中恢复，但在这种情况下，感觉我们应该指定某种默认值。也许每个新对象默认应该被`reset()`，或者也许当用户创建对象时，我们可以强制用户告诉我们这些位置应该是什么。

大多数面向对象的编程语言都有**构造函数**的概念，这是一个特殊的方法，用于在创建对象时创建和初始化对象。Python 有点不同；它有一个构造函数*和*一个初始化器。构造函数很少使用，除非你在做一些非常奇特的事情。所以，我们将从更常见的初始化方法开始讨论。

Python 的初始化方法与任何其他方法相同，只是它有一个特殊的名称`__init__`。前导和尾随的双下划线意味着这是一个特殊的方法，Python 解释器将把它视为一个特殊情况。

永远不要以双下划线开头和结尾命名自己的方法。它可能对 Python 今天无关紧要，但总有可能 Python 的设计者将来会添加一个具有该名称特殊目的的函数，当他们这样做时，你的代码将会出错。

让我们在我们的`Point`类上添加一个初始化函数，当实例化`Point`对象时需要用户提供`x`和`y`坐标：

```py
class Point: 
 def __init__(self, x, y): 
        self.move(x, y) 

    def move(self, x, y): 
        self.x = x 
        self.y = y 

    def reset(self): 
        self.move(0, 0) 

# Constructing a Point 
point = Point(3, 5) 
print(point.x, point.y) 
```

现在，我们的点永远不会没有`y`坐标！如果我们尝试构造一个点而没有包括正确的初始化参数，它将失败，并显示一个类似于我们之前忘记`self`参数时收到的`参数不足`错误。

如果我们不想使这两个参数成为必需的，我们可以使用与 Python 函数使用的相同语法来提供默认参数。关键字参数语法在每个变量名称后附加一个等号。如果调用对象没有提供此参数，则将使用默认参数。变量仍然可用于函数，但它们将具有参数列表中指定的值。这是一个例子：

```py
class Point: 
    def __init__(self, x=0, y=0): 
        self.move(x, y) 
```

大多数情况下，我们将初始化语句放在`__init__`函数中。但正如前面提到的，Python 除了初始化函数外还有一个构造函数。你可能永远不需要使用另一个 Python 构造函数（在十多年的专业 Python 编码中，我只想到了两种情况，在其中一种情况下，我可能不应该使用它！），但知道它的存在是有帮助的，所以我们将简要介绍一下。

构造函数被称为`__new__`，而不是`__init__`，并且只接受一个参数；正在构造的**类**（在构造对象之前调用，因此没有`self`参数）。它还必须返回新创建的对象。在涉及复杂的元编程时，这具有有趣的可能性，但在日常 Python 中并不是非常有用。实际上，你几乎永远不需要使用`__new__`。`__init__`方法几乎总是足够的。

# 自我解释

Python 是一种非常易于阅读的编程语言；有些人可能会说它是自我记录的。然而，在进行面向对象编程时，编写清楚总结每个对象和方法功能的 API 文档是很重要的。保持文档的最新状态是困难的；最好的方法是将其直接写入我们的代码中。

Python 通过使用**文档字符串**来支持这一点。每个类、函数或方法头部都可以有一个标准的 Python 字符串作为定义后面的第一行（以冒号结尾的行）。这一行应与随后的代码缩进相同。

文档字符串只是用撇号（`'`）或引号（`"`）括起来的 Python 字符串。通常，文档字符串非常长，跨越多行（风格指南建议行长不超过 80 个字符），可以格式化为多行字符串，用匹配的三个撇号（`'''`）或三引号（`"""`）字符括起来。

文档字符串应清楚而简洁地总结所描述的类或方法的目的。它应解释任何使用不明显的参数，并且还是包含如何使用 API 的简短示例的好地方。还应注意任何使用 API 的不知情用户应该注意的注意事项或问题。

为了说明文档字符串的用法，我们将以完全记录的`Point`类结束本节：

```py
import math

class Point:
    "Represents a point in two-dimensional geometric coordinates"

    def __init__(self, x=0, y=0):
        """Initialize the position of a new point. The x and y
           coordinates can be specified. If they are not, the
           point defaults to the origin."""
        self.move(x, y)

    def move(self, x, y):
        "Move the point to a new location in 2D space."
        self.x = x
        self.y = y

    def reset(self):
        "Reset the point back to the geometric origin: 0, 0"
        self.move(0, 0)

    def calculate_distance(self, other_point):
        """Calculate the distance from this point to a second
        point passed as a parameter.

        This function uses the Pythagorean Theorem to calculate
        the distance between the two points. The distance is
        returned as a float."""

        return math.sqrt(
            (self.x - other_point.x) ** 2
            + (self.y - other_point.y) ** 2
        )
```

尝试在交互式解释器中键入或加载（记住，是`python -i point.py`）这个文件。然后，在 Python 提示符下输入`help(Point)<enter>`。

你应该看到类的格式良好的文档，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/42cfc96e-6a55-47a9-aad7-b896b9f4fe59.png)

# 模块和包

现在我们知道如何创建类和实例化对象了。在开始失去追踪之前，你不需要写太多的类（或者非面向对象的代码）。对于小程序，我们可以把所有的类放在一个文件中，并在文件末尾添加一个小脚本来启动它们的交互。然而，随着项目的增长，要在我们定义的许多类中找到需要编辑的类可能会变得困难。这就是**模块**的用武之地。模块只是 Python 文件，没有别的。我们小程序中的单个文件就是一个模块。两个 Python 文件就是两个模块。如果我们有两个文件在同一个文件夹中，我们可以从一个模块中加载一个类以在另一个模块中使用。

例如，如果我们正在构建一个电子商务系统，我们可能会在数据库中存储大量数据。我们可以把所有与数据库访问相关的类和函数放在一个单独的文件中（我们将其称为一个合理的名字：`database.py`）。然后，我们的其他模块（例如，客户模型、产品信息和库存）可以导入该模块中的类以访问数据库。

`import`语句用于导入模块或特定类或函数。我们在前一节的`Point`类中已经看到了一个例子。我们使用`import`语句获取 Python 的内置`math`模块，并在`distance`计算中使用它的`sqrt`函数。

这里有一个具体的例子。假设我们有一个名为`database.py`的模块，其中包含一个名为`Database`的类。第二个名为`products.py`的模块负责与产品相关的查询。在这一点上，我们不需要太多考虑这些文件的内容。我们知道的是`products.py`需要从`database.py`中实例化`Database`类，以便它可以在数据库中的产品表上执行查询。

有几种`import`语句的变体语法可以用来访问这个类：

```py
import database 
db = database.Database() 
# Do queries on db 
```

这个版本将`database`模块导入到`products`命名空间（模块或函数中当前可访问的名称列表），因此可以使用`database.<something>`的表示法访问`database`模块中的任何类或函数。或者，我们可以使用`from...import`语法只导入我们需要的一个类：

```py
from database import Database 
db = Database() 
# Do queries on db 
```

如果由于某种原因，`products`已经有一个名为`Database`的类，我们不希望这两个名称混淆，我们可以在`products`模块中使用时重命名该类：

```py
from database import Database as DB 
db = DB() 
# Do queries on db 
```

我们也可以在一个语句中导入多个项目。如果我们的`database`模块还包含一个`Query`类，我们可以使用以下代码导入两个类：

```py
from database import Database, Query 
```

一些来源称我们可以使用以下语法从`database`模块中导入所有类和函数：

```py
from database import * 
```

**不要这样做。** 大多数有经验的 Python 程序员会告诉你，你不应该使用这种语法（有些人会告诉你有一些非常具体的情况下它是有用的，但我不同意）。他们会使用模糊的理由，比如*它会使命名空间混乱*，这对初学者来说并不太有意义。避免使用这种语法的一个方法是使用它并在两年后尝试理解你的代码。但我们可以通过一个简单的解释来节省一些时间和两年的糟糕代码！

当我们在文件顶部明确导入`database`类时，使用`from database import Database`，我们可以很容易地看到`Database`类来自哪里。我们可能会在文件的后面 400 行使用`db = Database()`，我们可以快速查看导入来看`Database`类来自哪里。然后，如果我们需要澄清如何使用`Database`类，我们可以访问原始文件（或者在交互式解释器中导入模块并使用`help(database.Database)`命令）。然而，如果我们使用`from database import *`语法，要找到该类的位置就要花费更多的时间。代码维护变成了一场噩梦。

此外，大多数代码编辑器能够提供额外的功能，比如可靠的代码补全、跳转到类的定义或内联文档，如果使用普通的导入。`import *`语法通常会完全破坏它们可靠地执行这些功能的能力。

最后，使用`import *`语法可能会将意外的对象带入我们的本地命名空间。当然，它会导入从被导入的模块中定义的所有类和函数，但它也会导入任何被导入到该文件中的类或模块！

模块中使用的每个名称都应该来自一个明确定义的地方，无论它是在该模块中定义的，还是从另一个模块中明确导入的。不应该有看起来像是凭空出现的魔术变量。我们应该*总是*能够立即确定我们当前命名空间中的名称来自哪里。我保证，如果你使用这种邪恶的语法，总有一天你会非常沮丧地发现*这个类到底是从哪里来的？*

玩一下，尝试在交互式解释器中输入`import this`。它会打印一首很好的诗（其中有一些你可以忽略的笑话），总结了一些 Python 程序员倾向于实践的习惯用法。特别是在这次讨论中，注意到了*明确胜于隐式*这一句。将名称明确导入到你的命名空间中，比隐式的`import *`语法使你的代码更容易浏览。

# 模块组织

随着项目逐渐发展成为越来越多模块的集合，我们可能会发现我们想要在模块的层次上添加另一层抽象，一种嵌套的层次结构。然而，我们不能将模块放在模块内；毕竟，一个文件只能包含一个文件，而模块只是文件。

然而，文件可以放在文件夹中，模块也可以。**包**是文件夹中模块的集合。包的名称就是文件夹的名称。我们需要告诉 Python 一个文件夹是一个包，以区别于目录中的其他文件夹。为此，在文件夹中放置一个（通常是空的）名为`__init__.py`的文件。如果我们忘记了这个文件，我们将无法从该文件夹导入模块。

让我们将我们的模块放在一个名为`ecommerce`的包中，该包还将包含一个`main.py`文件来启动程序。此外，让我们在`ecommerce`包内添加另一个用于各种支付选项的包。文件夹层次结构将如下所示：

```py
parent_directory/ 
    main.py 
    ecommerce/ 
        __init__.py 
        database.py 
        products.py 
        payments/ 
            __init__.py 
            square.py 
            stripe.py 
```

在包之间导入模块或类时，我们必须注意语法。在 Python 3 中，有两种导入模块的方式：绝对导入和相对导入。

# 绝对导入

绝对导入指定要导入的模块、函数或类的完整路径。如果我们需要访问`products`模块内的`Product`类，我们可以使用以下任何一种语法来执行绝对导入：

```py
import ecommerce.products 
product = ecommerce.products.Product() 

//or

from ecommerce.products import Product 
product = Product() 

//or

from ecommerce import products 
product = products.Product() 
```

`import`语句使用句点运算符来分隔包或模块。

这些语句将从任何模块中起作用。我们可以在`main.py`、`database`模块中或两个支付模块中的任何一个中使用这种语法实例化`Product`类。确实，假设包对 Python 可用，它将能够导入它们。例如，这些包也可以安装在 Python 站点包文件夹中，或者`PYTHONPATH`环境变量可以被定制为动态地告诉 Python 要搜索哪些文件夹以及它要导入的模块。

那么，在这些选择中，我们选择哪种语法呢？这取决于你的个人喜好和手头的应用。如果`products`模块中有数十个类和函数我想要使用，我通常使用`from ecommerce import products`语法导入模块名称，然后使用`products.Product`访问单个类。如果我只需要`products`模块中的一个或两个类，我可以直接使用`from ecommerce.products import Product`语法导入它们。我个人不经常使用第一种语法，除非我有某种名称冲突（例如，我需要访问两个完全不同的名为`products`的模块并且需要将它们分开）。做任何你认为使你的代码看起来更优雅的事情。

# 相对导入

在包内使用相关模块时，指定完整路径似乎有些多余；我们知道父模块的名称。这就是**相对导入**的用武之地。相对导入基本上是一种说法，即按照当前模块的位置来查找类、函数或模块。例如，如果我们在`products`模块中工作，并且想要从旁边的`database`模块导入`Database`类，我们可以使用相对导入：

```py
from .database import Database 
```

`database`前面的句点表示*使用当前包内的数据库模块*。在这种情况下，当前包是包含我们当前正在编辑的`products.py`文件的包，也就是`ecommerce`包。

如果我们正在编辑`ecommerce.payments`包内的`paypal`模块，我们可能会希望*使用父包内的数据库包*。这很容易通过两个句点来实现，如下所示：

```py
from ..database import Database 
```

我们可以使用更多句点来进一步上溯层次。当然，我们也可以沿着一边下去，然后沿着另一边上来。我们没有足够深的示例层次结构来正确说明这一点，但是如果我们有一个包含`email`模块并且想要将`send_mail`函数导入到我们的`paypal`模块的`ecommerce.contact`包，以下将是一个有效的导入：

```py
from ..contact.email import send_mail 
```

这个导入使用两个句点，表示*父级支付包*，然后使用正常的`package.module`语法返回到联系包。

最后，我们可以直接从包中导入代码，而不仅仅是包内的模块。在这个例子中，我们有一个名为`ecommerce`的包，其中包含两个名为`database.py`和`products.py`的模块。数据库模块包含一个`db`变量，可以从许多地方访问。如果可以像`import ecommerce.db`而不是`import ecommerce.database.db`这样导入，那不是很方便吗？

还记得`__init__.py`文件定义目录为包吗？这个文件可以包含我们喜欢的任何变量或类声明，并且它们将作为包的一部分可用。在我们的例子中，如果`ecommerce/__init__.py`文件包含以下行：

```py
from .database import db 
```

然后我们可以从`main.py`或任何其他文件中使用以下导入访问`db`属性：

```py
from ecommerce import db 
```

将`__init__.py`文件视为一个`ecommerce.py`文件可能有所帮助，如果该文件是一个模块而不是一个包。如果您将所有代码放在一个单独的模块中，然后决定将其拆分为多个模块的包，这也可能很有用。新包的`__init__.py`文件仍然可以是其他模块与其交流的主要联系点，但代码可以在几个不同的模块或子包中进行内部组织。

我建议不要在`__init__.py`文件中放太多代码。程序员不希望在这个文件中发生实际逻辑，就像`from x import *`一样，如果他们正在寻找特定代码的声明并且找不到直到他们检查`__init__.py`，它可能会让他们困惑。

# 组织模块内容

在任何一个模块内，我们可以指定变量、类或函数。它们可以是一种方便的方式来存储全局状态，而不会发生命名空间冲突。例如，我们一直在将`Database`类导入各种模块，然后实例化它，但也许更合理的是只有一个`database`对象全局可用于`database`模块。`database`模块可能是这样的：

```py
class Database: 
    # the database implementation 
    pass 

database = Database() 
```

然后我们可以使用我们讨论过的任何导入方法来访问`database`对象，例如：

```py
from ecommerce.database import database 
```

前面的类的一个问题是，`database`对象在模块第一次被导入时就被立即创建，通常是在程序启动时。这并不总是理想的，因为连接到数据库可能需要一些时间，会减慢启动速度，或者数据库连接信息可能尚未可用。我们可以通过调用`initialize_database`函数来延迟创建数据库，以创建一个模块级变量：

```py
class Database: 
    # the database implementation 
    pass 

database = None 

def initialize_database(): 
    global database 
    database = Database() 
```

`global`关键字告诉 Python，`initialize_database`内部的数据库变量是我们刚刚定义的模块级变量。如果我们没有将变量指定为全局的，Python 会创建一个新的局部变量，当方法退出时会被丢弃，从而保持模块级别的值不变。

正如这两个例子所说明的，所有模块级代码都会在导入时立即执行。但是，如果它在方法或函数内部，函数会被创建，但其内部代码直到调用函数时才会被执行。对于执行脚本（比如我们电子商务示例中的主要脚本）来说，这可能是一个棘手的问题。有时，我们编写一个执行有用操作的程序，然后后来发现我们想要从该模块导入一个函数或类到另一个程序中。然而，一旦我们导入它，模块级别的任何代码都会立即执行。如果我们不小心，我们可能会在真正只想访问该模块中的一些函数时运行第一个程序。

为了解决这个问题，我们应该总是将启动代码放在一个函数中（通常称为`main`），并且只有在知道我们正在作为脚本运行模块时才执行该函数，而不是在我们的代码被从另一个脚本导入时执行。我们可以通过在条件语句中**保护**对`main`的调用来实现这一点，如下所示：

```py
class UsefulClass:
    """This class might be useful to other modules."""

    pass

def main():
    """Creates a useful class and does something with it for our module."""
    useful = UsefulClass()
    print(useful)

if __name__ == "__main__":
    main()
```

每个模块都有一个`__name__`特殊变量（记住，Python 使用双下划线表示特殊变量，比如类的`__init__`方法），它指定了模块在导入时的名称。当模块直接用`python module.py`执行时，它不会被导入，所以`__name__`会被任意设置为`"__main__"`字符串。制定一个规则，将所有脚本都包裹在`if __name__ == "__main__":`测试中，以防万一你写了一个以后可能想被其他代码导入的函数。

那么，方法放在类中，类放在模块中，模块放在包中。这就是全部吗？

实际上，不是。这是 Python 程序中的典型顺序，但不是唯一可能的布局。类可以在任何地方定义。它们通常在模块级别定义，但也可以在函数或方法内部定义，就像这样：

```py
def format_string(string, formatter=None):
    """Format a string using the formatter object, which 
    is expected to have a format() method that accepts 
    a string."""

    class DefaultFormatter:
        """Format a string in title case."""

        def format(self, string):
            return str(string).title()

    if not formatter:
        formatter = DefaultFormatter()

    return formatter.format(string)

hello_string = "hello world, how are you today?"
print(" input: " + hello_string)
print("output: " + format_string(hello_string))
```

输出如下：

```py
 input: hello world, how are you today?
output: Hello World, How Are You Today?
```

`format_string`函数接受一个字符串和可选的格式化器对象，然后将格式化器应用于该字符串。如果没有提供格式化器，它会创建一个自己的格式化器作为本地类并实例化它。由于它是在函数范围内创建的，这个类不能从函数外部访问。同样，函数也可以在其他函数内部定义；一般来说，任何 Python 语句都可以在任何时候执行。

这些内部类和函数偶尔对于不需要或不值得在模块级别拥有自己的作用域的一次性项目是有用的，或者只在单个方法内部有意义。然而，通常不会看到频繁使用这种技术的 Python 代码。

# 谁可以访问我的数据？

大多数面向对象的编程语言都有**访问控制**的概念。这与抽象有关。对象上的一些属性和方法被标记为私有，意味着只有该对象可以访问它们。其他的被标记为受保护，意味着只有该类和任何子类才能访问。其余的是公共的，意味着任何其他对象都可以访问它们。

Python 不这样做。Python 实际上不相信强制执行可能在某一天妨碍你的法律。相反，它提供了未强制执行的指南和最佳实践。从技术上讲，类上的所有方法和属性都是公开可用的。如果我们想表明一个方法不应该公开使用，我们可以在文档字符串中放置一个注释，指出该方法仅用于内部使用（最好还要解释公共 API 的工作原理！）。

按照惯例，我们还应该使用下划线字符`_`作为内部属性或方法的前缀。Python 程序员会将其解释为*这是一个内部变量，在直接访问之前要三思*。但是，如果他们认为这样做符合他们的最佳利益，解释器内部没有任何东西可以阻止他们访问它。因为，如果他们这样认为，我们为什么要阻止他们呢？我们可能不知道我们的类将来可能被用于什么用途。

还有另一件事可以强烈建议外部对象不要访问属性或方法：用双下划线`__`作为前缀。这将对属性进行**名称混淆**。实质上，名称混淆意味着如果外部对象真的想这样做，仍然可以调用该方法，但这需要额外的工作，并且强烈表明您要求您的属性保持**私有**。以下是一个示例代码片段：

```py
class SecretString:
    """A not-at-all secure way to store a secret string."""

    def __init__(self, plain_string, pass_phrase):
 self.__plain_string = plain_string
 self.__pass_phrase = pass_phrase

    def decrypt(self, pass_phrase):
        """Only show the string if the pass_phrase is correct."""
 if pass_phrase == self.__pass_phrase:
 return self.__plain_string
        else:
            return ""
```

如果我们在交互式解释器中加载这个类并测试它，我们可以看到它将明文字符串隐藏在外部世界之外：

```py
>>> secret_string = SecretString("ACME: Top Secret", "antwerp")
>>> print(secret_string.decrypt("antwerp"))
ACME: Top Secret
>>> print(secret_string.__plain_string)
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
AttributeError: 'SecretString' object has no attribute
'__plain_string'  
```

看起来好像可以了；没有人可以在没有口令的情况下访问我们的`plain_string`属性，所以应该是安全的。然而，在我们过于兴奋之前，让我们看看有多容易破解我们的安全性：

```py
>>> print(secret_string._SecretString__plain_string)
ACME: Top Secret  
```

哦不！有人发现了我们的秘密字符串。好在我们检查了。

这就是 Python 名称混淆的工作原理。当我们使用双下划线时，属性前缀为`_<classname>`。当类中的方法内部访问变量时，它们会自动取消混淆。当外部类希望访问它时，它们必须自己进行名称混淆。因此，名称混淆并不保证隐私；它只是强烈建议。除非有极其充分的理由，大多数 Python 程序员不会触碰另一个对象上的双下划线变量。

然而，大多数 Python 程序员不会在没有充分理由的情况下触碰单个下划线变量。因此，在 Python 中使用名称混淆的变量的很少有很好的理由，这样做可能会引起麻烦。例如，名称混淆的变量可能对尚未知道的子类有用，它必须自己进行混淆。如果其他对象想要访问您的隐藏信息，就让它们知道，使用单下划线前缀或一些清晰的文档字符串，表明您认为这不是一个好主意。

# 第三方库

Python 附带了一个可爱的标准库，这是一个包和模块的集合，可以在运行 Python 的每台机器上使用。然而，您很快会发现它并不包含您所需的一切。当这种情况发生时，您有两个选择：

+   自己编写一个支持包

+   使用别人的代码

我们不会详细介绍如何将您的软件包转换为库，但是如果您有需要解决的问题，而且不想编写代码（最好的程序员非常懒惰，更喜欢重用现有的经过验证的代码，而不是编写自己的代码），您可能可以在**Python 软件包索引**（**PyPI**）[`pypi.python.org/`](http://pypi.python.org/)上找到您想要的库。确定要安装的软件包后，您可以使用一个名为`pip`的工具来安装它。但是，`pip`不随 Python 一起提供，但 Python 3.4 及更高版本包含一个称为`ensurepip`的有用工具。您可以使用此命令来安装它：

```py
$python -m ensurepip  
```

这可能在 Linux、macOS 或其他 Unix 系统上失败，这种情况下，您需要成为 root 用户才能使其工作。在大多数现代 Unix 系统上，可以使用`sudo python -m ensurepip`来完成此操作。

如果您使用的 Python 版本早于 Python 3.4，您需要自己下载并安装`pip`，因为`ensurepip`不可用。您可以按照以下网址的说明进行操作：[`pip.readthedocs.org/`](http://pip.readthedocs.org/)。

一旦安装了`pip`并且知道要安装的软件包的名称，您可以使用以下语法来安装它：

```py
$pip install requests  
```

然而，如果这样做，您要么会直接将第三方库安装到系统 Python 目录中，要么更有可能会收到您没有权限这样做的错误。您可以以管理员身份强制安装，但 Python 社区的共识是，您应该只使用系统安装程序将第三方库安装到系统 Python 目录中。

相反，Python 3.4（及更高版本）提供了`venv`工具。该实用程序基本上为您的工作目录提供了一个名为*虚拟环境*的迷你 Python 安装。当您激活迷你 Python 时，与 Python 相关的命令将在该目录上运行，而不是在系统目录上运行。因此，当您运行`pip`或`python`时，它根本不会触及系统 Python。以下是如何使用它：

```py
cd project_directory
python -m venv env
source env/bin/activate  # on Linux or macOS
env/bin/activate.bat     # on Windows  
```

通常，您会为您工作的每个 Python 项目创建一个不同的虚拟环境。您可以将虚拟环境存储在任何地方，但我传统上将它们保存在与项目文件相同的目录中（但在版本控制中被忽略），因此我们首先`cd`进入该目录。然后，我们运行`venv`实用程序来创建名为`env`的虚拟环境。最后，我们使用最后两行中的一行（取决于操作系统，如注释中所示）来激活环境。每次想要使用特定的虚拟环境时，我们都需要执行此行，然后在完成该项目的工作时使用`deactivate`命令。

虚拟环境是保持第三方依赖项分开的绝佳方式。通常会有不同的项目依赖于特定库的不同版本（例如，旧网站可能在 Django 1.8 上运行，而更新的版本则在 Django 2.1 上运行）。将每个项目放在单独的虚拟环境中可以轻松地在 Django 的任一版本中工作。此外，如果您尝试使用不同的工具安装相同的软件包，它还可以防止系统安装的软件包和`pip`安装的软件包之间发生冲突。

有几种有效管理虚拟环境的第三方工具。其中一些包括`pyenv`、`virtualenvwrapper`和`conda`。我个人在撰写本文时更偏好`pyenv`，但这里没有明显的赢家。快速搜索一下，看看哪种适合您。

# 案例研究

为了将所有这些联系在一起，让我们构建一个简单的命令行笔记本应用程序。这是一个相当简单的任务，所以我们不会尝试使用多个软件包。但是，我们将看到类、函数、方法和文档字符串的常见用法。

让我们先进行快速分析：笔记是存储在笔记本中的简短备忘录。每个笔记应记录写入的日期，并可以添加标签以便轻松查询。应该可以修改笔记。我们还需要能够搜索笔记。所有这些事情都应该从命令行完成。

一个明显的对象是`Note`对象；一个不太明显的对象是`Notebook`容器对象。标签和日期似乎也是对象，但我们可以使用 Python 标准库中的日期和逗号分隔的字符串来表示标签。为了避免复杂性，在原型中，我们不需要为这些对象定义单独的类。

`Note`对象具有`memo`本身，`tags`和`creation_date`的属性。每个笔记还需要一个唯一的整数`id`，以便用户可以在菜单界面中选择它们。笔记可以有一个修改笔记内容的方法和另一个标签的方法，或者我们可以让笔记本直接访问这些属性。为了使搜索更容易，我们应该在`Note`对象上放置一个`match`方法。这个方法将接受一个字符串，并且可以告诉我们一个笔记是否与字符串匹配，而不直接访问属性。这样，如果我们想修改搜索参数（例如，搜索标签而不是笔记内容，或者使搜索不区分大小写），我们只需要在一个地方做就可以了。

`Notebook`对象显然具有笔记列表作为属性。它还需要一个搜索方法，返回一个经过筛选的笔记列表。

但是我们如何与这些对象交互？我们已经指定了一个命令行应用程序，这可能意味着我们以不同的选项运行程序来添加或编辑命令，或者我们有某种菜单，允许我们选择对笔记本做不同的事情。我们应该尽量设计它，以便支持任一接口，并且未来的接口，比如 GUI 工具包或基于 Web 的接口，可以在未来添加。

作为一个设计决策，我们现在将实现菜单界面，但会牢记命令行选项版本，以确保我们设计`Notebook`类时考虑到可扩展性。

如果我们有两个命令行界面，每个界面都与`Notebook`对象交互，那么`Notebook`将需要一些方法供这些界面与之交互。我们需要能够`add`一个新的笔记，并且通过`id`来`modify`一个现有的笔记，除了我们已经讨论过的`search`方法。界面还需要能够列出所有笔记，但它们可以通过直接访问`notes`列表属性来实现。

我们可能会错过一些细节，但我们对需要编写的代码有一个很好的概述。我们可以用一个简单的类图总结所有这些分析：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/ade40d12-754a-4428-80a5-64690676d0c8.png)

在编写任何代码之前，让我们为这个项目定义文件夹结构。菜单界面应该明确地放在自己的模块中，因为它将是一个可执行脚本，并且我们将来可能会有其他可执行脚本访问笔记本。`Notebook`和`Note`对象可以放在一个模块中。这些模块可以都存在于同一个顶级目录中，而不必将它们放在一个包中。一个空的`command_option.py`模块可以帮助我们在未来提醒自己，我们计划添加新的用户界面：

```py
parent_directory/ 
    notebook.py 
    menu.py 
    command_option.py 
```

现在让我们看一些代码。我们首先定义`Note`类，因为它似乎最简单。以下示例完整呈现了`Note`。示例中的文档字符串解释了它们如何组合在一起，如下所示：

```py
import datetime

# Store the next available id for all new notes
last_id = 0

class Note:
    """Represent a note in the notebook. Match against a
    string in searches and store tags for each note."""

    def __init__(self, memo, tags=""):
        """initialize a note with memo and optional
        space-separated tags. Automatically set the note's
        creation date and a unique id."""
        self.memo = memo
        self.tags = tags
        self.creation_date = datetime.date.today()
        global last_id
        last_id += 1
        self.id = last_id

    def match(self, filter):
        """Determine if this note matches the filter
        text. Return True if it matches, False otherwise.

        Search is case sensitive and matches both text and
        tags."""
        return filter in self.memo or filter in self.tags
```

在继续之前，我们应该快速启动交互式解释器并测试我们到目前为止的代码。经常测试，因为事情从来不按照你的期望工作。事实上，当我测试这个例子的第一个版本时，我发现我在`match`函数中忘记了`self`参数！我们将在第二十四章中讨论自动化测试，*测试面向对象的程序*。目前，只需使用解释器检查一些东西就足够了：

```py
>>> from notebook import Note
>>> n1 = Note("hello first")
>>> n2 = Note("hello again")
>>> n1.id
1
>>> n2.id
2
>>> n1.match('hello')
True
>>> n2.match('second')
False  
```

看起来一切都表现如预期。让我们接下来创建我们的笔记本：

```py
class Notebook:
    """Represent a collection of notes that can be tagged,
    modified, and searched."""

    def __init__(self):
        """Initialize a notebook with an empty list."""
        self.notes = []

    def new_note(self, memo, tags=""):
        """Create a new note and add it to the list."""
        self.notes.append(Note(memo, tags))

    def modify_memo(self, note_id, memo):
        """Find the note with the given id and change its
        memo to the given value."""
        for note in self.notes:
            if note.id == note_id:
                note.memo = memo
                break

    def modify_tags(self, note_id, tags):
        """Find the note with the given id and change its
        tags to the given value."""
        for note in self.notes:
            if note.id == note_id:
                note.tags = tags
                break

    def search(self, filter):
        """Find all notes that match the given filter
        string."""
        return [note for note in self.notes if note.match(filter)]
```

我们将很快整理一下。首先，让我们测试一下以确保它能正常工作：

```py
>>> from notebook import Note, Notebook
>>> n = Notebook()
>>> n.new_note("hello world")
>>> n.new_note("hello again")
>>> n.notes
[<notebook.Note object at 0xb730a78c>, <notebook.Note object at 0xb73103ac>]
>>> n.notes[0].id
1
>>> n.notes[1].id
2
>>> n.notes[0].memo
'hello world'
>>> n.search("hello")
[<notebook.Note object at 0xb730a78c>, <notebook.Note object at 0xb73103ac>]
>>> n.search("world")
[<notebook.Note object at 0xb730a78c>]
>>> n.modify_memo(1, "hi world")
>>> n.notes[0].memo
'hi world'  
```

它确实有效。但是代码有点混乱；我们的`modify_tags`和`modify_memo`方法几乎是相同的。这不是良好的编码实践。让我们看看如何改进它。

两种方法都试图在对笔记做某事之前识别具有给定 ID 的笔记。因此，让我们添加一个方法来定位具有特定 ID 的笔记。我们将在方法名称前加下划线以表明该方法仅供内部使用，但是，当然，我们的菜单界面可以访问该方法，如果它想要的话：

```py
    def _find_note(self, note_id):
        """Locate the note with the given id."""
        for note in self.notes:
            if note.id == note_id:
                return note
        return None

    def modify_memo(self, note_id, memo):
        """Find the note with the given id and change its
        memo to the given value."""
        self._find_note(note_id).memo = memo

    def modify_tags(self, note_id, tags):
        """Find the note with the given id and change its
        tags to the given value."""
        self._find_note(note_id).tags = tags
```

现在应该可以工作了。让我们看看菜单界面。界面需要呈现菜单并允许用户输入选择。这是我们的第一次尝试：

```py
import sys
from notebook import Notebook

class Menu:
    """Display a menu and respond to choices when run."""

    def __init__(self):
        self.notebook = Notebook()
        self.choices = {
            "1": self.show_notes,
            "2": self.search_notes,
            "3": self.add_note,
            "4": self.modify_note,
            "5": self.quit,
        }

    def display_menu(self):
        print(
            """
Notebook Menu

1\. Show all Notes
2\. Search Notes
3\. Add Note
4\. Modify Note
5\. Quit
"""
        )

    def run(self):
        """Display the menu and respond to choices."""
        while True:
            self.display_menu()
            choice = input("Enter an option: ")
            action = self.choices.get(choice)
            if action:
                action()
            else:
                print("{0} is not a valid choice".format(choice))

    def show_notes(self, notes=None):
        if not notes:
            notes = self.notebook.notes
        for note in notes:
            print("{0}: {1}\n{2}".format(note.id, note.tags, note.memo))

    def search_notes(self):
        filter = input("Search for: ")
        notes = self.notebook.search(filter)
        self.show_notes(notes)

    def add_note(self):
        memo = input("Enter a memo: ")
        self.notebook.new_note(memo)
        print("Your note has been added.")

    def modify_note(self):
        id = input("Enter a note id: ")
        memo = input("Enter a memo: ")
        tags = input("Enter tags: ")
        if memo:
            self.notebook.modify_memo(id, memo)
        if tags:
            self.notebook.modify_tags(id, tags)

    def quit(self):
        print("Thank you for using your notebook today.")
        sys.exit(0)

if __name__ == "__main__":
    Menu().run()
```

这段代码首先使用绝对导入导入笔记本对象。相对导入不起作用，因为我们还没有将我们的代码放在一个包内。`Menu`类的`run`方法重复显示菜单，并通过调用笔记本上的函数来响应选择。这是使用 Python 特有的一种习惯用法；它是命令模式的一个轻量级版本，我们将在第二十二章中讨论，*Python 设计模式 I*。用户输入的选择是字符串。在菜单的`__init__`方法中，我们创建一个将字符串映射到菜单对象本身的函数的字典。然后，当用户做出选择时，我们从字典中检索对象。`action`变量实际上是指特定的方法，并且通过在变量后附加空括号（因为没有一个方法需要参数）来调用它。当然，用户可能输入了不合适的选择，所以我们在调用之前检查动作是否真的存在。

各种方法中的每一个都请求用户输入，并调用与之关联的`Notebook`对象上的适当方法。对于`search`实现，我们注意到在过滤了笔记之后，我们需要向用户显示它们，因此我们让`show_notes`函数充当双重职责；它接受一个可选的`notes`参数。如果提供了，它只显示过滤后的笔记，但如果没有提供，它会显示所有笔记。由于`notes`参数是可选的，`show_notes`仍然可以被调用而不带参数作为空菜单项。

如果我们测试这段代码，我们会发现如果我们尝试修改一个笔记，它会失败。有两个错误，即：

+   当我们输入一个不存在的笔记 ID 时，笔记本会崩溃。我们永远不应该相信用户输入正确的数据！

+   即使我们输入了正确的 ID，它也会崩溃，因为笔记 ID 是整数，但我们的菜单传递的是字符串。

后一个错误可以通过修改`Notebook`类的`_find_note`方法，使用字符串而不是存储在笔记中的整数来比较值来解决，如下所示：

```py
    def _find_note(self, note_id):
        """Locate the note with the given id."""
        for note in self.notes:
            if str(note.id) == str(note_id):
                return note
        return None
```

在比较它们之前，我们只需将输入（`note_id`）和笔记的 ID 都转换为字符串。我们也可以将输入转换为整数，但是如果用户输入字母`a`而不是数字`1`，那么我们会遇到麻烦。

用户输入不存在的笔记 ID 的问题可以通过更改笔记本上的两个`modify`方法来解决，检查`_find_note`是否返回了一个笔记，如下所示：

```py
    def modify_memo(self, note_id, memo):
        """Find the note with the given id and change its
        memo to the given value."""
        note = self._find_note(note_id)
        if note:
            note.memo = memo
            return True
        return False
```

这个方法已更新为返回`True`或`False`，取决于是否找到了一个笔记。菜单可以使用这个返回值来显示错误，如果用户输入了一个无效的笔记。

这段代码有点笨拙。如果它引发异常会好一些。我们将在第十八章中介绍这些，*预料之外*。

# 练习

编写一些面向对象的代码。目标是使用本章学到的原则和语法，确保你理解我们所涵盖的主题。如果你一直在做一个 Python 项目，回过头来看看，是否有一些对象可以创建，并添加属性或方法。如果项目很大，尝试将其分成几个模块，甚至包，并玩弄语法。

如果你没有这样的项目，尝试开始一个新的项目。它不一定要是你打算完成的东西；只需勾勒出一些基本的设计部分。你不需要完全实现所有内容；通常，只需要`print("这个方法将做一些事情")`就足以让整体设计就位。这被称为**自顶向下设计**，在这种设计中，你先解决不同的交互，并描述它们应该如何工作，然后再实际实现它们所做的事情。相反，**自底向上设计**首先实现细节，然后将它们全部联系在一起。这两种模式在不同的时候都很有用，但对于理解面向对象的原则，自顶向下的工作流更合适。

如果你在想法上遇到困难，可以尝试编写一个待办事项应用程序。（提示：它将类似于笔记本应用程序的设计，但具有额外的日期管理方法。）它可以跟踪你每天想做的事情，并允许你标记它们为已完成。

现在尝试设计一个更大的项目。与之前一样，它不一定要真正做任何事情，但确保你尝试使用包和模块导入语法。在各个模块中添加一些函数，并尝试从其他模块和包中导入它们。使用相对和绝对导入。看看它们之间的区别，并尝试想象你想要使用每种导入方式的场景。

# 总结

在本章中，我们学习了在 Python 中创建类并分配属性和方法是多么简单。与许多语言不同，Python 区分构造函数和初始化程序。它对访问控制有一种放松的态度。有许多不同级别的作用域，包括包、模块、类和函数。我们理解了相对导入和绝对导入之间的区别，以及如何管理不随 Python 一起提供的第三方包。

在下一章中，我们将学习如何使用继承来共享实现。


# 第十七章：当对象相似时

在编程世界中，重复的代码被认为是邪恶的。我们不应该在不同的地方有相同或相似的代码的多个副本。

有许多方法可以合并具有类似功能的代码或对象。在本章中，我们将介绍最著名的面向对象原则：继承。正如在第十五章中讨论的那样，*面向对象设计*，继承允许我们在两个或多个类之间创建 is a 关系，将通用逻辑抽象到超类中，并在子类中管理特定细节。特别是，我们将介绍以下内容的 Python 语法和原则：

+   基本继承

+   从内置类型继承

+   多重继承

+   多态和鸭子类型

# 基本继承

从技术上讲，我们创建的每个类都使用继承。所有 Python 类都是名为`object`的特殊内置类的子类。这个类在数据和行为方面提供的很少（它提供的行为都是为了内部使用的双下划线方法），但它确实允许 Python 以相同的方式对待所有对象。

如果我们不明确从不同的类继承，我们的类将自动从`object`继承。然而，我们可以明确声明我们的类从`object`派生，使用以下语法：

```py
class MySubClass(object): 
    pass 
```

这就是继承！从技术上讲，这个例子与我们在第十六章中的第一个例子没有什么不同，*Python 中的对象*，因为如果我们不明确提供不同的**超类**，Python 3 会自动从`object`继承。超类或父类是被继承的类。子类是从超类继承的类。在这种情况下，超类是`object`，而`MySubClass`是子类。子类也被称为从其父类派生，或者说子类扩展了父类。

从示例中你可能已经发现，继承需要比基本类定义多出一点额外的语法。只需在类名和后面的冒号之间的括号内包含父类的名称。这就是我们告诉 Python 新类应该从给定的超类派生的所有内容。

我们如何在实践中应用继承？继承最简单和最明显的用途是向现有类添加功能。让我们从一个简单的联系人管理器开始，跟踪几个人的姓名和电子邮件地址。`Contact`类负责在类变量中维护所有联系人的列表，并为单个联系人初始化姓名和地址：

```py
class Contact:
    all_contacts = []

    def __init__(self, name, email):
        self.name = name
        self.email = email
        Contact.all_contacts.append(self)
```

这个例子向我们介绍了**类变量**。`all_contacts`列表，因为它是类定义的一部分，被这个类的所有实例共享。这意味着只有一个`Contact.all_contacts`列表。我们也可以在`Contact`类的任何实例方法中作为`self.all_contacts`访问它。如果在对象（通过`self`）上找不到字段，那么它将在类上找到，并且因此将引用相同的单个列表。

对于这个语法要小心，因为如果你使用`self.all_contacts`来*设置*变量，你实际上会创建一个**新的**与该对象关联的实例变量。类变量仍然不变，并且可以作为`Contact.all_contacts`访问。

这是一个简单的类，允许我们跟踪每个联系人的一些数据。但是如果我们的一些联系人也是我们需要从中订购物品的供应商呢？我们可以在`Contact`类中添加一个`order`方法，但这将允许人们意外地从客户或家庭朋友的联系人那里订购东西。相反，让我们创建一个新的`Supplier`类，它的行为类似于我们的`Contact`类，但有一个额外的`order`方法：

```py
class Supplier(Contact):
    def order(self, order):
        print(
            "If this were a real system we would send "
            f"'{order}' order to '{self.name}'"
        )
```

现在，如果我们在我们可靠的解释器中测试这个类，我们会发现所有联系人，包括供应商，在它们的`__init__`中都接受名称和电子邮件地址，但只有供应商有一个功能性的订单方法：

```py
>>> c = Contact("Some Body", "somebody@example.net")
>>> s = Supplier("Sup Plier", "supplier@example.net")
>>> print(c.name, c.email, s.name, s.email)
Some Body somebody@example.net Sup Plier supplier@example.net
>>> c.all_contacts
[<__main__.Contact object at 0xb7375ecc>,
 <__main__.Supplier object at 0xb7375f8c>]
>>> c.order("I need pliers")
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
AttributeError: 'Contact' object has no attribute 'order'
>>> s.order("I need pliers")
If this were a real system we would send 'I need pliers' order to
'Sup Plier '  
```

所以，现在我们的`Supplier`类可以做所有联系人可以做的事情（包括将自己添加到`all_contacts`列表中）以及作为供应商需要处理的所有特殊事情。这就是继承的美妙之处。

# 扩展内置类

这种继承的一个有趣用途是向内置类添加功能。在前面看到的`Contact`类中，我们正在将联系人添加到所有联系人的列表中。如果我们还想按名称搜索该列表怎么办？嗯，我们可以在`Contact`类上添加一个搜索方法，但感觉这个方法实际上属于列表本身。我们可以使用继承来实现这一点：

```py
class ContactList(list):
    def search(self, name):
        """Return all contacts that contain the search value
        in their name."""
        matching_contacts = []
        for contact in self:
            if name in contact.name:
                matching_contacts.append(contact)
        return matching_contacts

class Contact:
    all_contacts = ContactList()

    def __init__(self, name, email):
        self.name = name
        self.email = email
        Contact.all_contacts.append(self)
```

我们不是实例化一个普通列表作为我们的类变量，而是创建一个扩展内置`list`数据类型的新`ContactList`类。然后，我们将这个子类实例化为我们的`all_contacts`列表。我们可以测试新的搜索功能如下：

```py
>>> c1 = Contact("John A", "johna@example.net")
>>> c2 = Contact("John B", "johnb@example.net")
>>> c3 = Contact("Jenna C", "jennac@example.net")
>>> [c.name for c in Contact.all_contacts.search('John')]
['John A', 'John B']  
```

你是否想知道我们如何将内置语法`[]`改变成我们可以继承的东西？使用`[]`创建一个空列表实际上是使用`list()`创建一个空列表的快捷方式；这两种语法的行为是相同的：

```py
>>> [] == list()
True  
```

实际上，`[]`语法实际上是所谓的**语法糖**，在幕后调用`list()`构造函数。`list`数据类型是一个我们可以扩展的类。事实上，列表本身扩展了`object`类：

```py
>>> isinstance([], object)
True  
```

作为第二个例子，我们可以扩展`dict`类，它与列表类似，是在使用`{}`语法缩写时构造的类：

```py
class LongNameDict(dict): 
    def longest_key(self): 
        longest = None 
        for key in self: 
            if not longest or len(key) > len(longest): 
                longest = key 
        return longest 
```

这在交互式解释器中很容易测试：

```py
>>> longkeys = LongNameDict()
>>> longkeys['hello'] = 1
>>> longkeys['longest yet'] = 5
>>> longkeys['hello2'] = 'world'
>>> longkeys.longest_key()
'longest yet'  
```

大多数内置类型都可以类似地扩展。常见的扩展内置类包括`object`、`list`、`set`、`dict`、`file`和`str`。数值类型如`int`和`float`有时也会被继承。

# 重写和 super

因此，继承非常适合*向*现有类添加新行为，但是*改变*行为呢？我们的`Contact`类只允许名称和电子邮件地址。这对大多数联系人可能已经足够了，但是如果我们想为我们的亲密朋友添加电话号码呢？

正如我们在第十六章中看到的，*Python 中的对象*，我们可以很容易地在构造后在联系人上设置`phone`属性。但是，如果我们想在初始化时使这个第三个变量可用，我们必须重写`__init__`。重写意味着用子类中的新方法（具有相同名称）更改或替换超类的方法。不需要特殊的语法来做到这一点；子类的新创建的方法会自动被调用，而不是超类的方法。如下面的代码所示：

```py
class Friend(Contact): 
 def __init__(self, name, email, phone):         self.name = name 
        self.email = email 
        self.phone = phone 
```

任何方法都可以被重写，不仅仅是`__init__`。然而，在继续之前，我们需要解决这个例子中的一些问题。我们的`Contact`和`Friend`类有重复的代码来设置`name`和`email`属性；这可能会使代码维护复杂化，因为我们必须在两个或更多地方更新代码。更令人担忧的是，我们的`Friend`类忽略了将自己添加到我们在`Contact`类上创建的`all_contacts`列表中。

我们真正需要的是一种方法，可以从我们的新类内部执行`Contact`类上的原始`__init__`方法。这就是`super`函数的作用；它将对象作为父类的实例返回，允许我们直接调用父类方法：

```py
class Friend(Contact): 
    def __init__(self, name, email, phone): 
 super().__init__(name, email) 
        self.phone = phone 
```

这个例子首先使用`super`获取父对象的实例，并在该对象上调用`__init__`，传入预期的参数。然后进行自己的初始化，即设置`phone`属性。

`super()`调用可以在任何方法内部进行。因此，所有方法都可以通过覆盖和调用`super`进行修改。`super`的调用也可以在方法的任何地方进行；我们不必将调用作为第一行。例如，我们可能需要在将传入参数转发给超类之前操纵或验证传入参数。

# 多重继承

多重继承是一个敏感的话题。原则上，它很简单：从多个父类继承的子类能够访问它们两者的功能。实际上，这并没有听起来那么有用，许多专家程序员建议不要使用它。

作为一个幽默的经验法则，如果你认为你需要多重继承，你可能是错的，但如果你知道你需要它，你可能是对的。

最简单和最有用的多重继承形式被称为**mixin**。mixin 是一个不打算独立存在的超类，而是打算被其他类继承以提供额外的功能。例如，假设我们想要为我们的`Contact`类添加功能，允许向`self.email`发送电子邮件。发送电子邮件是一个常见的任务，我们可能希望在许多其他类上使用它。因此，我们可以编写一个简单的 mixin 类来为我们发送电子邮件：

```py
class MailSender: 
    def send_mail(self, message): 
        print("Sending mail to " + self.email) 
        # Add e-mail logic here 
```

为了简洁起见，我们不会在这里包含实际的电子邮件逻辑；如果你有兴趣学习如何做到这一点，请参阅 Python 标准库中的`smtplib`模块。

这个类并没有做任何特别的事情（实际上，它几乎不能作为一个独立的类运行），但它确实允许我们定义一个新的类，描述了`Contact`和`MailSender`，使用多重继承：

```py
class EmailableContact(Contact, MailSender): 
    pass 
```

多重继承的语法看起来像类定义中的参数列表。在括号内不是包含一个基类，而是包含两个（或更多），用逗号分隔。我们可以测试这个新的混合体，看看 mixin 的工作情况：

```py
>>> e = EmailableContact("John Smith", "jsmith@example.net")
>>> Contact.all_contacts
[<__main__.EmailableContact object at 0xb7205fac>]
>>> e.send_mail("Hello, test e-mail here")
Sending mail to jsmith@example.net  
```

`Contact`初始化器仍然将新联系人添加到`all_contacts`列表中，mixin 能够向`self.email`发送邮件，所以我们知道一切都在运行。

这并不难，你可能想知道关于多重继承的严重警告是什么。我们将在一分钟内讨论复杂性，但让我们考虑一下我们在这个例子中的其他选择，而不是使用 mixin：

+   我们本可以使用单一继承，并将`send_mail`函数添加到子类中。这里的缺点是，邮件功能必须为任何其他需要邮件的类重复。

+   我们可以创建一个独立的 Python 函数来发送电子邮件，并在需要发送电子邮件时以参数的形式调用该函数并提供正确的电子邮件地址（这将是我的选择）。

+   我们本可以探索一些使用组合而不是继承的方法。例如，`EmailableContact`可以将`MailSender`对象作为属性，而不是继承它。

+   我们可以在创建类之后对`Contact`类进行 monkey patching（我们将在第二十章中简要介绍 monkey patching，*Python 面向对象的快捷方式*）。这是通过定义一个接受`self`参数的函数，并将其设置为现有类的属性来完成的。

当混合来自不同类的方法时，多重继承效果还不错，但当我们必须在超类上调用方法时，情况就变得非常混乱。有多个超类。我们怎么知道该调用哪一个？我们怎么知道以什么顺序调用它们？

让我们通过向我们的`Friend`类添加家庭地址来探讨这些问题。我们可能会采取一些方法。地址是一组表示联系人的街道、城市、国家和其他相关细节的字符串。我们可以将这些字符串中的每一个作为参数传递给`Friend`类的`__init__`方法。我们也可以将这些字符串存储在元组、字典或数据类中，并将它们作为单个参数传递给`__init__`。如果没有需要添加到地址的方法，这可能是最好的做法。

另一个选择是创建一个新的`Address`类来保存这些字符串，然后将这个类的实例传递给我们的`Friend`类的`__init__`方法。这种解决方案的优势在于，我们可以为数据添加行为（比如，一个给出方向或打印地图的方法），而不仅仅是静态存储。这是组合的一个例子，正如我们在第十五章中讨论的那样，*面向对象设计*。组合是这个问题的一个完全可行的解决方案，它允许我们在其他实体中重用`Address`类，比如建筑物、企业或组织。

然而，继承也是一个可行的解决方案，这就是我们想要探讨的。让我们添加一个新的类来保存地址。我们将这个新类称为`AddressHolder`，而不是`Address`，因为继承定义了一种是一个关系。说`Friend`类是`Address`类是不正确的，但由于朋友可以有一个`Address`类，我们可以说`Friend`类是`AddressHolder`类。稍后，我们可以创建其他实体（公司，建筑物）也持有地址。然而，这种复杂的命名是一个很好的指示，我们应该坚持组合，而不是继承。但出于教学目的，我们将坚持使用继承。这是我们的`AddressHolder`类：

```py
class AddressHolder: 
    def __init__(self, street, city, state, code): 
        self.street = street 
        self.city = city 
        self.state = state 
        self.code = code 
```

我们只需在初始化时将所有数据放入实例变量中。

# 菱形问题

我们可以使用多重继承将这个新类添加为现有`Friend`类的父类。棘手的部分是现在我们有两个父`__init__`方法，它们都需要被初始化。而且它们需要用不同的参数进行初始化。我们该怎么做呢？嗯，我们可以从一个天真的方法开始：

```py
class Friend(Contact, AddressHolder): 
    def __init__( 
        self, name, email, phone, street, city, state, code): 
 Contact.__init__(self, name, email) 
        AddressHolder.__init__(self, street, city, state, code) 
        self.phone = phone 
```

在这个例子中，我们直接调用每个超类的`__init__`函数，并显式传递`self`参数。这个例子在技术上是有效的；我们可以直接在类上访问不同的变量。但是有一些问题。

首先，如果我们忽略显式调用初始化程序，超类可能会未初始化。这不会破坏这个例子，但在常见情况下可能会导致难以调试的程序崩溃。例如，想象一下尝试将数据插入未连接的数据库。

一个更隐匿的可能性是由于类层次结构的组织而多次调用超类。看看这个继承图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/aa756ecd-f4b1-4ece-b1ec-50fc35c748fa.png)

`Friend`类的`__init__`方法首先调用`Contact`的`__init__`，这隐式地初始化了`object`超类（记住，所有类都派生自`object`）。然后`Friend`调用`AddressHolder`的`__init__`，这又隐式地初始化了`object`超类。这意味着父类已经被设置了两次。对于`object`类来说，这相对无害，但在某些情况下，这可能会带来灾难。想象一下，每次请求都要尝试两次连接到数据库！

基类应该只被调用一次。是的，但是何时呢？我们先调用`Friend`，然后`Contact`，然后`Object`，然后`AddressHolder`？还是`Friend`，然后`Contact`，然后`AddressHolder`，然后`Object`？

方法的调用顺序可以通过修改类的`__mro__`（**方法解析顺序**）属性来动态调整。这超出了本书的范围。如果您认为您需要了解它，我们建议阅读*Expert Python Programming*，*Tarek Ziadé*，*Packt Publishing*，或者阅读有关该主题的原始文档（注意，它很深！）[`www.python.org/download/releases/2.3/mro/`](http://www.python.org/download/releases/2.3/mro/)。

让我们看一个更清楚地说明这个问题的第二个刻意的例子。在这里，我们有一个基类，它有一个名为`call_me`的方法。两个子类重写了该方法，然后另一个子类使用多重继承扩展了这两个子类。这被称为菱形继承，因为类图的形状是菱形：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/ad8de812-f1cd-43b8-86d2-0c1b13a40b49.png)

让我们将这个图转换成代码；这个例子展示了方法何时被调用：

```py
class BaseClass:
    num_base_calls = 0

    def call_me(self):
        print("Calling method on Base Class")
        self.num_base_calls += 1

class LeftSubclass(BaseClass):
    num_left_calls = 0

    def call_me(self):
        BaseClass.call_me(self)
        print("Calling method on Left Subclass")
        self.num_left_calls += 1

class RightSubclass(BaseClass):
    num_right_calls = 0

    def call_me(self):
        BaseClass.call_me(self)
        print("Calling method on Right Subclass")
        self.num_right_calls += 1

class Subclass(LeftSubclass, RightSubclass):
    num_sub_calls = 0

    def call_me(self):
 LeftSubclass.call_me(self)
 RightSubclass.call_me(self)
        print("Calling method on Subclass")
        self.num_sub_calls += 1
```

这个例子确保每个重写的`call_me`方法直接调用具有相同名称的父方法。它通过将信息打印到屏幕上来告诉我们每次调用方法。它还更新了类的静态变量，以显示它被调用的次数。如果我们实例化一个`Subclass`对象并调用它的方法一次，我们会得到输出：

```py
>>> s = Subclass()
>>> s.call_me()
Calling method on Base Class
Calling method on Left Subclass
Calling method on Base Class
Calling method on Right Subclass
Calling method on Subclass
>>> print(
... s.num_sub_calls,
... s.num_left_calls,
... s.num_right_calls,
... s.num_base_calls)
1 1 1 2  
```

因此，我们可以清楚地看到基类的`call_me`方法被调用了两次。如果该方法正在执行实际工作，比如两次存入银行账户，这可能会导致一些隐匿的错误。

多重继承要记住的一件事是，我们只想调用类层次结构中的`next`方法，而不是`parent`方法。实际上，下一个方法可能不在当前类的父类或祖先上。`super`关键字再次拯救了我们。事实上，`super`最初是为了使复杂的多重继承形式成为可能。以下是使用`super`编写的相同代码：

```py
class BaseClass:
    num_base_calls = 0

    def call_me(self):
        print("Calling method on Base Class")
        self.num_base_calls += 1

class LeftSubclass(BaseClass):
    num_left_calls = 0

    def call_me(self):
 super().call_me()
        print("Calling method on Left Subclass")
        self.num_left_calls += 1

class RightSubclass(BaseClass):
    num_right_calls = 0

    def call_me(self):
 super().call_me()
        print("Calling method on Right Subclass")
        self.num_right_calls += 1

class Subclass(LeftSubclass, RightSubclass):
    num_sub_calls = 0

    def call_me(self):
 super().call_me()
        print("Calling method on Subclass")
        self.num_sub_calls += 1
```

更改非常小；我们只用`super()`调用替换了天真的直接调用，尽管底部子类只调用了一次`super`，而不是必须为左侧和右侧都进行调用。更改足够简单，但是当我们执行它时，看看差异：

```py
>>> s = Subclass()
>>> s.call_me()
Calling method on Base Class
Calling method on Right Subclass
Calling method on Left Subclass
Calling method on Subclass
>>> print(s.num_sub_calls, s.num_left_calls, s.num_right_calls,
s.num_base_calls)
1 1 1 1  
```

看起来不错；我们的基本方法只被调用了一次。但是`super()`在这里实际上是在做什么呢？由于`print`语句是在`super`调用之后执行的，打印输出的顺序是每个方法实际执行的顺序。让我们从后往前看输出，看看是谁在调用什么。

首先，`Subclass`的`call_me`调用了`super().call_me()`，这恰好是在引用

到`LeftSubclass.call_me()`。然后`LeftSubclass.call_me()`方法调用`super().call_me()`，但在这种情况下，`super()`指的是`RightSubclass.call_me()`。

**特别注意**：`super`调用*不*调用`LeftSubclass`的超类（即`BaseClass`）上的方法。相反，它调用`RightSubclass`，即使它不是`LeftSubclass`的直接父类！这是*next*方法，而不是父方法。然后`RightSubclass`调用`BaseClass`，并且`super`调用确保了类层次结构中的每个方法都被执行一次。

# 不同的参数集

当我们返回到我们的`Friend`多重继承示例时，这将使事情变得复杂。在`Friend`的`__init__`方法中，我们最初调用了两个父类的`__init__`，*使用不同的参数集*：

```py
Contact.__init__(self, name, email) 
AddressHolder.__init__(self, street, city, state, code) 
```

在使用`super`时如何管理不同的参数集？我们不一定知道`super`将尝试首先初始化哪个类。即使我们知道，我们也需要一种方法来传递`extra`参数，以便后续对其他子类的`super`调用接收正确的参数。

具体来说，如果对`super`的第一个调用将`name`和`email`参数传递给`Contact.__init__`，然后`Contact.__init__`调用`super`，它需要能够将与地址相关的参数传递给`next`方法，即`AddressHolder.__init__`。

每当我们想要调用具有相同名称但不同参数集的超类方法时，就会出现这个问题。通常情况下，您只会在`__init__`中想要使用完全不同的参数集，就像我们在这里做的那样。即使在常规方法中，我们可能也想要添加仅对一个子类或一组子类有意义的可选参数。

遗憾的是，解决这个问题的唯一方法是从一开始就计划好。我们必须设计基类参数列表，以接受任何不是每个子类实现所需的参数的关键字参数。最后，我们必须确保该方法自由接受意外的参数并将它们传递给其`super`调用，以防它们对继承顺序中的后续方法是必要的。

Python 的函数参数语法提供了我们需要做到这一点的所有工具，但它使整体代码看起来笨重。请看下面`Friend`多重继承代码的正确版本：

```py
class Contact:
    all_contacts = []

 def __init__(self, name="", email="", **kwargs):
 super().__init__(**kwargs)
        self.name = name
        self.email = email
        self.all_contacts.append(self)

class AddressHolder:
 def __init__(self, street="", city="", state="", code="", **kwargs):
 super().__init__(**kwargs)
        self.street = street
        self.city = city
        self.state = state
        self.code = code

class Friend(Contact, AddressHolder):
 def __init__(self, phone="", **kwargs):
 super().__init__(**kwargs)
        self.phone = phone
```

我们通过给它们一个空字符串作为默认值，将所有参数都更改为关键字参数。我们还确保包含一个`**kwargs`参数来捕获我们特定方法不知道如何处理的任何额外参数。它将这些参数传递给`super`调用的下一个类。

如果您不熟悉`**kwargs`语法，它基本上会收集传递给方法的任何未在参数列表中明确列出的关键字参数。这些参数存储在一个名为`kwargs`的字典中（我们可以随意命名变量，但约定建议使用`kw`或`kwargs`）。当我们使用`**kwargs`语法调用不同的方法（例如`super().__init__`）时，它会解包字典并将结果作为普通关键字参数传递给方法。我们将在第二十章中详细介绍这一点，*Python 面向对象的快捷方式*。

前面的例子做了它应该做的事情。但是它开始看起来凌乱，很难回答问题，“我们需要传递什么参数到`Friend.__init__`中？”这是任何计划使用该类的人首要考虑的问题，因此应该在方法中添加一个文档字符串来解释发生了什么。

此外，即使使用这种实现方式，如果我们想要在父类中*重用*变量，它仍然是不够的。当我们将`**kwargs`变量传递给`super`时，字典不包括任何作为显式关键字参数包含的变量。例如，在`Friend.__init__`中，对`super`的调用在`kwargs`字典中没有`phone`。如果其他类中需要`phone`参数，我们需要确保它包含在传递的字典中。更糟糕的是，如果我们忘记这样做，调试将变得非常令人沮丧，因为超类不会抱怨，而只会简单地将默认值（在这种情况下为空字符串）分配给变量。

有几种方法可以确保变量向上传递。假设`Contact`类出于某种原因需要使用`phone`参数进行初始化，并且`Friend`类也需要访问它。我们可以采取以下任一方法：

+   不要将`phone`作为显式关键字参数包含在内。相反，将其留在`kwargs`字典中。`Friend`可以使用`kwargs['phone']`语法查找它。当它将`**kwargs`传递给`super`调用时，`phone`仍将存在于字典中。

+   将`phone`作为显式关键字参数，但在将其传递给`super`之前更新`kwargs`字典，使用标准字典`kwargs['phone'] = phone`语法。

+   将`phone`作为一个显式关键字参数，但使用`kwargs.update`方法更新`kwargs`字典。如果有多个参数需要更新，这是很有用的。您可以使用`dict(phone=phone)`构造函数或`{'phone': phone}`语法创建传递给`update`的字典。

+   将`phone`作为一个显式关键字参数，但使用`super().__init__(phone=phone, **kwargs)`语法将其明确传递给 super 调用。

我们已经涵盖了 Python 中多重继承的许多注意事项。当我们需要考虑所有可能的情况时，我们必须为它们做计划，我们的代码会变得混乱。基本的多重继承可能很方便，但在许多情况下，我们可能希望选择一种更透明的方式来组合两个不同的类，通常使用组合或我们将在第二十二章和第二十三章中介绍的设计模式之一。

我已经浪费了我生命中的整整一天，搜索复杂的多重继承层次结构，试图弄清楚我需要传递到其中一个深度嵌套的子类的参数。代码的作者倾向于不记录他的类，并经常传递 kwargs——以防万一将来可能会需要。这是一个特别糟糕的例子，使用了不需要的多重继承。多重继承是一个新编码者喜欢炫耀的大而复杂的术语，但我建议避免使用它，即使你认为它是一个好选择。当他们以后不得不阅读代码时，你未来的自己和其他编码者会很高兴他们理解你的代码。

# 多态性

我们在《面向对象设计》的第十五章中介绍了多态性。这是一个华丽的名字，描述了一个简单的概念：不同的行为发生取决于使用哪个子类，而不必明确知道子类实际上是什么。举个例子，想象一个播放音频文件的程序。媒体播放器可能需要加载一个`AudioFile`对象，然后`play`它。我们可以在对象上放一个`play()`方法，负责解压或提取音频并将其路由到声卡和扬声器。播放`AudioFile`的行为可能是非常简单的：

```py
audio_file.play() 
```

然而，解压和提取音频文件的过程对不同类型的文件来说是非常不同的。虽然`.wav`文件是未压缩存储的，`.mp3`、`.wma`和`.ogg`文件都使用完全不同的压缩算法。

我们可以使用多态性的继承来简化设计。每种类型的文件可以由`AudioFile`的不同子类表示，例如`WavFile`和`MP3File`。每个子类都会有一个`play()`方法，为了确保正确的提取过程，每个文件的实现方式都会有所不同。媒体播放器对象永远不需要知道它正在引用哪个`AudioFile`的子类；它只是调用`play()`，并以多态的方式让对象处理实际的播放细节。让我们看一个快速的骨架，展示这可能是什么样子：

```py
class AudioFile:
    def __init__(self, filename):
        if not filename.endswith(self.ext):
            raise Exception("Invalid file format")

        self.filename = filename

class MP3File(AudioFile):
    ext = "mp3"

    def play(self):
        print("playing {} as mp3".format(self.filename))

class WavFile(AudioFile):
    ext = "wav"

    def play(self):
        print("playing {} as wav".format(self.filename))

class OggFile(AudioFile):
    ext = "ogg"

    def play(self):
        print("playing {} as ogg".format(self.filename))
```

所有音频文件都会检查初始化时是否给出了有效的扩展名。但你是否注意到父类中的`__init__`方法如何能够从不同的子类访问`ext`类变量？这就是多态性的工作原理。如果文件名不以正确的名称结尾，它会引发异常（异常将在下一章中详细介绍）。`AudioFile`父类实际上并没有存储对`ext`变量的引用，但这并不妨碍它能够在子类上访问它。

此外，`AudioFile`的每个子类以不同的方式实现`play()`（这个例子实际上并不播放音乐；音频压缩算法确实值得单独一本书！）。这也是多态的实现。媒体播放器可以使用完全相同的代码来播放文件，无论它是什么类型；它不关心它正在查看的`AudioFile`的子类是什么。解压音频文件的细节被*封装*。如果我们测试这个例子，它会按照我们的期望工作。

```py
>>> ogg = OggFile("myfile.ogg")
>>> ogg.play()
playing myfile.ogg as ogg
>>> mp3 = MP3File("myfile.mp3")
>>> mp3.play()
playing myfile.mp3 as mp3
>>> not_an_mp3 = MP3File("myfile.ogg")
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
 File "polymorphic_audio.py", line 4, in __init__
 raise Exception("Invalid file format")
Exception: Invalid file format  
```

看看`AudioFile.__init__`如何能够检查文件类型，而不实际知道它指的是哪个子类？

多态实际上是面向对象编程中最酷的东西之一，它使一些在早期范式中不可能的编程设计变得显而易见。然而，由于鸭子类型，Python 使多态看起来不那么令人敬畏。Python 中的鸭子类型允许我们使用*任何*提供所需行为的对象，而无需强制它成为子类。Python 的动态性使这变得微不足道。下面的例子不扩展`AudioFile`，但可以使用完全相同的接口在 Python 中与之交互：

```py
class FlacFile: 
    def __init__(self, filename): 
        if not filename.endswith(".flac"): 
            raise Exception("Invalid file format") 

        self.filename = filename 

    def play(self): 
        print("playing {} as flac".format(self.filename)) 
```

我们的媒体播放器可以像扩展`AudioFile`的对象一样轻松地播放这个对象。

在许多面向对象的上下文中，多态是使用继承的最重要原因之一。因为在 Python 中可以互换使用任何提供正确接口的对象，所以减少了对多态公共超类的需求。继承仍然可以用于共享代码，但如果所有被共享的只是公共接口，那么只需要鸭子类型。这种对继承的需求减少也减少了对多重继承的需求；通常，当多重继承似乎是一个有效的解决方案时，我们可以使用鸭子类型来模仿多个超类中的一个。

当然，只因为一个对象满足特定接口（通过提供所需的方法或属性）并不意味着它在所有情况下都能简单地工作。它必须以在整个系统中有意义的方式满足该接口。仅仅因为一个对象提供了`play()`方法并不意味着它会自动与媒体播放器一起工作。例如，我们在第十五章中的国际象棋 AI 对象，*面向对象设计*，可能有一个`play()`方法来移动国际象棋棋子。即使它满足了接口，这个类在我们试图将它插入媒体播放器时可能会以惊人的方式崩溃！

鸭子类型的另一个有用特性是，鸭子类型的对象只需要提供实际被访问的方法和属性。例如，如果我们需要创建一个假的文件对象来读取数据，我们可以创建一个具有`read()`方法的新对象；如果将与假对象交互的代码不会调用`write`方法，那么我们就不必覆盖`write`方法。简而言之，鸭子类型不需要提供可用对象的整个接口；它只需要满足实际被访问的接口。

# 抽象基类

虽然鸭子类型很有用，但事先很难判断一个类是否能够满足你所需的协议。因此，Python 引入了**抽象基类**（**ABC**）的概念。抽象基类定义了一组类必须实现的方法和属性，以便被视为该类的鸭子类型实例。该类可以扩展抽象基类本身，以便用作该类的实例，但必须提供所有适当的方法。

实际上，很少需要创建新的抽象基类，但我们可能会发现需要实现现有 ABC 的实例的情况。我们将首先介绍实现 ABC，然后简要介绍如何创建自己的 ABC，如果你有需要的话。

# 使用抽象基类

Python 标准库中存在的大多数抽象基类都位于`collections`模块中。其中最简单的之一是`Container`类。让我们在 Python 解释器中检查一下这个类需要哪些方法：

```py
>>> from collections import Container 
>>> Container.__abstractmethods__ 
frozenset(['__contains__']) 
```

因此，`Container`类确切地有一个需要被实现的抽象方法，`__contains__`。你可以发出`help(Container.__contains__)`来查看这个函数签名应该是什么样子的：

```py
Help on method __contains__ in module _abcoll:
 __contains__(self, x) unbound _abcoll.Container method
```

我们可以看到`__contains__`需要接受一个参数。不幸的是，帮助文件并没有告诉我们这个参数应该是什么，但从 ABC 的名称和它实现的单个方法来看，很明显这个参数是用户要检查的容器是否包含的值。

这个方法由`list`、`str`和`dict`实现，用于指示给定的值是否*在*该数据结构中。然而，我们也可以定义一个愚蠢的容器，告诉我们给定的值是否在奇数集合中：

```py
class OddContainer: 
    def __contains__(self, x): 
        if not isinstance(x, int) or not x % 2: 
            return False 
        return True 
```

有趣的是：我们可以实例化一个`OddContainer`对象，并确定，即使我们没有扩展`Container`，该类也是一个`Container`对象。

```py
>>> from collections import Container 
>>> odd_container = OddContainer() 
>>> isinstance(odd_container, Container) 
True 
>>> issubclass(OddContainer, Container) 
True 
```

这就是为什么鸭子类型比经典多态更棒的原因。我们可以创建关系而不需要编写设置继承（或更糟的是多重继承）的代码的开销。

`Container` ABC 的一个很酷的地方是，任何实现它的类都可以免费使用`in`关键字。实际上，`in`只是语法糖，委托给`__contains__`方法。任何具有`__contains__`方法的类都是`Container`，因此可以通过`in`关键字查询，例如：

```py
>>> 1 in odd_container 
True 
>>> 2 in odd_container 
False 
>>> 3 in odd_container 
True 
>>> "a string" in odd_container 
False 
```

# 创建一个抽象基类

正如我们之前看到的，要启用鸭子类型并不需要有一个抽象基类。然而，想象一下我们正在创建一个带有第三方插件的媒体播放器。在这种情况下，最好创建一个抽象基类来记录第三方插件应该提供的 API（文档是 ABC 的一个更强大的用例）。`abc`模块提供了你需要做到这一点的工具，但我提前警告你，这利用了 Python 中一些最深奥的概念，就像下面的代码块中所演示的那样：

```py
import abc 

class MediaLoader(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def play(self):
        pass

    @abc.abstractproperty
    def ext(self):
        pass

    @classmethod
    def __subclasshook__(cls, C):
        if cls is MediaLoader:
            attrs = set(dir(C))
            if set(cls.__abstractmethods__) <= attrs:
                return True

        return NotImplemented
```

这是一个复杂的例子，包括了几个 Python 特性，这些特性在本书的后面才会被解释。它被包含在这里是为了完整性，但你不需要理解所有这些来了解如何创建你自己的 ABC。

第一件奇怪的事情是`metaclass`关键字参数被传递到类中，而在通常情况下你会看到父类列表。这是来自元类编程的神秘艺术中很少使用的构造。我们不会在本书中涵盖元类，所以你需要知道的是，通过分配`ABCMeta`元类，你为你的类赋予了超级英雄（或至少是超类）的能力。

接下来，我们看到了`@abc.abstractmethod`和`@abc.abstractproperty`构造。这些是 Python 装饰器。我们将在第二十二章中讨论这些。现在，只需要知道通过将方法或属性标记为抽象，你声明了这个类的任何子类必须实现该方法或提供该属性，才能被视为该类的合格成员。

看看如果你实现了提供或不提供这些属性的子类会发生什么：

```py
>>> class Wav(MediaLoader): 
...     pass 
... 
>>> x = Wav() 
Traceback (most recent call last): 
  File "<stdin>", line 1, in <module> 
TypeError: Can't instantiate abstract class Wav with abstract methods ext, play 
>>> class Ogg(MediaLoader): 
...     ext = '.ogg' 
...     def play(self): 
...         pass 
... 
>>> o = Ogg() 
```

由于`Wav`类未实现抽象属性，因此无法实例化该类。该类仍然是一个合法的抽象类，但你必须对其进行子类化才能实际执行任何操作。`Ogg`类提供了这两个属性，因此可以干净地实例化。

回到`MediaLoader` ABC，让我们解剖一下`__subclasshook__`方法。它基本上是说，任何提供了这个 ABC 所有抽象属性的具体实现的类都应该被认为是`MediaLoader`的子类，即使它实际上并没有继承自`MediaLoader`类。

更常见的面向对象语言在接口和类的实现之间有明确的分离。例如，一些语言提供了一个明确的`interface`关键字，允许我们定义一个类必须具有的方法，而不需要任何实现。在这样的环境中，抽象类是提供了接口和一些但不是所有方法的具体实现的类。任何类都可以明确声明它实现了给定的接口。

Python 的 ABCs 有助于提供接口的功能，而不会影响鸭子类型的好处。

# 解密魔术

如果你想要创建满足这个特定契约的抽象类，你可以复制并粘贴子类代码而不必理解它。我们将在本书中涵盖大部分不寻常的语法，但让我们逐行地概述一下：

```py
    @classmethod 
```

这个装饰器标记方法为类方法。它基本上表示该方法可以在类上调用，而不是在实例化的对象上调用：

```py
    def __subclasshook__(cls, C): 
```

这定义了`__subclasshook__`类方法。这个特殊的方法是由 Python 解释器调用来回答这个问题：类`C`是这个类的子类吗？

```py
        if cls is MediaLoader: 
```

我们检查方法是否是在这个类上专门调用的，而不是在这个类的子类上调用。例如，这可以防止`Wav`类被认为是`Ogg`类的父类：

```py
            attrs = set(dir(C)) 
```

这一行所做的只是获取类的方法和属性集，包括其类层次结构中的任何父类：

```py
            if set(cls.__abstractmethods__) <= attrs: 
```

这一行使用集合符号来查看候选类中是否提供了这个类中的抽象方法。请注意，它不检查方法是否已经被实现；只是检查它们是否存在。因此，一个类可能是一个子类，但仍然是一个抽象类本身。

```py
                return True 
```

如果所有的抽象方法都已经提供，那么候选类是这个类的子类，我们返回`True`。该方法可以合法地返回三个值之一：`True`，`False`或`NotImplemented`。`True`和`False`表示该类是否明确是这个类的子类：

```py
return NotImplemented 
```

如果任何条件都没有被满足（也就是说，这个类不是`MediaLoader`，或者没有提供所有的抽象方法），那么返回`NotImplemented`。这告诉 Python 机制使用默认机制（候选类是否明确扩展了这个类？）来检测子类。

简而言之，我们现在可以将`Ogg`类定义为`MediaLoader`类的子类，而不实际扩展`MediaLoader`类：

```py
>>> class Ogg(): ... ext = '.ogg' ... def play(self): ... print("this will play an ogg file") ... >>> issubclass(Ogg, MediaLoader) True >>> isinstance(Ogg(), MediaLoader) True
```

# 案例研究

让我们尝试用一个更大的例子把我们学到的东西联系起来。我们将为编程作业开发一个自动评分系统，类似于 Dataquest 或 Coursera 使用的系统。该系统需要为课程作者提供一个简单的基于类的接口，以便创建他们的作业，并且如果不满足该接口，应该提供有用的错误消息。作者需要能够提供他们的课程内容，并编写自定义答案检查代码，以确保他们的学生得到正确的答案。他们还可以访问学生的姓名，使内容看起来更友好一些。

评分系统本身需要跟踪学生当前正在进行的作业。学生可能在得到正确答案之前尝试几次作业。我们希望跟踪尝试次数，以便课程作者可以改进更难的课程内容。

让我们首先定义课程作者需要使用的接口。理想情况下，除了课程内容和答案检查代码之外，它将要求课程作者写入最少量的额外代码。以下是我能想到的最简单的类：

```py
class IntroToPython:
    def lesson(self):
        return f"""
            Hello {self.student}. define two variables,
            an integer named a with value 1
            and a string named b with value 'hello'

        """

```

```py
    def check(self, code):
        return code == "a = 1\nb = 'hello'"
```

诚然，该课程作者可能对他们的答案检查方式有些天真。

我们可以从定义这个接口的抽象基类开始，如下所示：

```py
class Assignment(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def lesson(self, student):
        pass

    @abc.abstractmethod
    def check(self, code):
        pass

    @classmethod
    def __subclasshook__(cls, C):
        if cls is Assignment:
            attrs = set(dir(C))
            if set(cls.__abstractmethods__) <= attrs:
                return True

        return NotImplemented
```

这个 ABC 定义了两个必需的抽象方法，并提供了魔术`__subclasshook__`方法，允许一个类被视为子类，而无需明确扩展它（我通常只是复制并粘贴这段代码。不值得记忆。）

我们可以使用`issubclass(IntroToPython, Assignment)`来确认`IntroToPython`类是否满足这个接口，这应该返回`True`。当然，如果愿意，我们也可以明确扩展`Assignment`类，就像在第二个作业中所看到的那样：

```py
class Statistics(Assignment):
    def lesson(self):
        return (
            "Good work so far, "
            + self.student
            + ". Now calculate the average of the numbers "
            + " 1, 5, 18, -3 and assign to a variable named 'avg'"
        )

    def check(self, code):
        import statistics

        code = "import statistics\n" + code

        local_vars = {}
        global_vars = {}
        exec(code, global_vars, local_vars)

        return local_vars.get("avg") == statistics.mean([1, 5, 18, -3])
```

不幸的是，这位课程作者也相当天真。`exec`调用将在评分系统内部执行学生的代码，使他们可以访问整个系统。显然，他们将首先对系统进行黑客攻击，使他们的成绩达到 100%。他们可能认为这比正确完成作业更容易！

接下来，我们将创建一个类，用于管理学生在特定作业上尝试的次数：

```py
class AssignmentGrader:
    def __init__(self, student, AssignmentClass):
        self.assignment = AssignmentClass()
        self.assignment.student = student
        self.attempts = 0
        self.correct_attempts = 0

    def check(self, code):
        self.attempts += 1
        result = self.assignment.check(code)
        if result:
            self.correct_attempts += 1

        return result

    def lesson(self):
        return self.assignment.lesson()
```

这个类使用组合而不是继承。乍一看，这些方法存在于`Assignment`超类似乎是有道理的。这将消除令人讨厌的`lesson`方法，它只是代理到作业对象上的相同方法。当然，可以直接在`Assignment`抽象基类上放置所有这些逻辑，甚至可以让 ABC 从这个`AssignmentGrader`类继承。事实上，我通常会推荐这样做，但在这种情况下，这将强制所有课程作者明确扩展该类，这违反了我们尽可能简单地请求内容创作的要求。

最后，我们可以开始组建`Grader`类，该类负责管理哪些作业是可用的，每个学生当前正在进行哪个作业。最有趣的部分是注册方法：

```py
import uuid

class Grader:
    def __init__(self):
        self.student_graders = {}
        self.assignment_classes = {}

    def register(self, assignment_class):
        if not issubclass(assignment_class, Assignment):
            raise RuntimeError(
                "Your class does not have the right methods"
            )

        id = uuid.uuid4()
        self.assignment_classes[id] = assignment_class
        return id
```

这个代码块包括初始化器，其中包括我们将在一分钟内讨论的两个字典。`register`方法有点复杂，所以我们将彻底剖析它。

第一件奇怪的事是这个方法接受的参数：`assignment_class`。这个参数意味着是一个实际的类，而不是类的实例。记住，类也是对象，可以像其他类一样传递。鉴于我们之前定义的`IntroToPython`类，我们可以在不实例化的情况下注册它，如下所示：

```py
from grader import Grader
from lessons import IntroToPython, Statistics

grader = Grader()
itp_id = grader.register(IntroToPython)
```

该方法首先检查该类是否是`Assignment`类的子类。当然，我们实现了一个自定义的`__subclasshook__`方法，因此这包括了不明确地作为`Assignment`子类的类。命名可能有点欺骗性！如果它没有这两个必需的方法，它会引发一个异常。异常是我们将在下一章详细讨论的一个主题；现在，只需假设它会使程序生气并退出。

然后，我们生成一个随机标识符来表示特定的作业。我们将`assignment_class`存储在一个由该 ID 索引的字典中，并返回该 ID，以便调用代码将来可以查找该作业。据推测，另一个对象将在某种课程大纲中放置该 ID，以便学生按顺序完成作业，但在项目的这一部分我们不会这样做。

`uuid`函数返回一个称为通用唯一标识符的特殊格式字符串，也称为全局唯一标识符。它基本上代表一个几乎不可能与另一个类似生成的标识符冲突的极大随机数。这是创建用于跟踪项目的任意 ID 的一种很好、快速和干净的方法。

接下来，我们有`start_assignment`函数，它允许学生开始做一项作业，给定该作业的 ID。它所做的就是构造我们之前定义的`AssignmentGrader`类的一个实例，并将其放入存储在`Grader`类上的字典中，如下所示：

```py
    def start_assignment(self, student, id):
        self.student_graders[student] = AssignmentGrader(
            student, self.assignment_classes[id]
        )
```

之后，我们编写了一些代理方法，用于获取学生当前正在进行的课程或检查作业的代码：

```py
    def get_lesson(self, student):
        assignment = self.student_graders[student]
        return assignment.lesson()

    def check_assignment(self, student, code):
        assignment = self.student_graders[student]
        return assignment.check(code)
```

最后，我们创建了一个方法，用于总结学生当前作业的进展情况。它查找作业对象，并创建一个格式化的字符串，其中包含我们对该学生的所有信息：

```py

    def assignment_summary(self, student):
        grader = self.student_graders[student]
        return f"""
        {student}'s attempts at {grader.assignment.__class__.__name__}:

        attempts: {grader.attempts}
        correct: {grader.correct_attempts}

        passed: {grader.correct_attempts > 0}
        """
```

就是这样。您会注意到，这个案例研究并没有使用大量的继承，这可能看起来有点奇怪，因为这一章的主题，但鸭子类型非常普遍。Python 程序通常被设计为使用继承，随着迭代的进行，它会简化为更多功能的构造。举个例子，我最初将`AssignmentGrader`定义为继承关系，但中途意识到最好使用组合，原因如前所述。

以下是一些测试代码，展示了所有这些对象是如何连接在一起的：

```py
grader = Grader()
itp_id = grader.register(IntroToPython)
stat_id = grader.register(Statistics)

grader.start_assignment("Tammy", itp_id)
print("Tammy's Lesson:", grader.get_lesson("Tammy"))
print(
    "Tammy's check:",
    grader.check_assignment("Tammy", "a = 1 ; b = 'hello'"),
)
print(
    "Tammy's other check:",
    grader.check_assignment("Tammy", "a = 1\nb = 'hello'"),
)

print(grader.assignment_summary("Tammy"))

grader.start_assignment("Tammy", stat_id)
print("Tammy's Lesson:", grader.get_lesson("Tammy"))
print("Tammy's check:", grader.check_assignment("Tammy", "avg=5.25"))
print(
    "Tammy's other check:",
    grader.check_assignment(
        "Tammy", "avg = statistics.mean([1, 5, 18, -3])"
    ),
)

print(grader.assignment_summary("Tammy"))
```

# 练习

看看你的工作空间中的一些物理物体，看看你能否用继承层次结构描述它们。人类几个世纪以来一直在将世界划分为这样的分类法，所以这应该不难。在对象类之间是否存在一些非明显的继承关系？如果你要在计算机应用程序中对这些对象进行建模，它们会共享哪些属性和方法？哪些属性需要多态地重写？它们之间有哪些完全不同的属性？

现在写一些代码。不是为了物理层次结构；那很无聊。物理物品比方法更多。只是想想你过去一年想要解决的宠物编程项目。无论你想解决什么问题，都试着想出一些基本的继承关系，然后实现它们。确保你也注意到了实际上不需要使用继承的关系。有哪些地方你可能想要使用多重继承？你确定吗？你能看到任何你想使用混入的地方吗？试着拼凑一个快速的原型。它不必有用，甚至不必部分工作。你已经看到了如何使用`python -i`测试代码；只需编写一些代码并在交互式解释器中测试它。如果它有效，再写一些。如果不行，修复它！

现在，看看案例研究中的学生评分系统。它缺少很多东西，不仅仅是良好的课程内容！学生如何进入系统？是否有一个课程大纲规定他们应该按照什么顺序学习课程？如果你将`AssignmentGrader`更改为在`Assignment`对象上使用继承而不是组合，会发生什么？

最后，尝试想出一些使用混入的好用例，然后尝试使用混入，直到意识到可能有更好的设计使用组合！

# 总结

我们已经从简单的继承，这是面向对象程序员工具箱中最有用的工具之一，一直到多重继承——最复杂的之一。继承可以用来通过继承向现有类和内置类添加功能。将类似的代码抽象成父类可以帮助增加可维护性。父类上的方法可以使用`super`进行调用，并且在使用多重继承时，参数列表必须安全地格式化以使这些调用起作用。抽象基类允许您记录一个类必须具有哪些方法和属性才能满足特定接口，并且甚至允许您更改*子类*的定义。

在下一章中，我们将介绍处理特殊情况的微妙艺术。


# 第十八章：预料之外的情况

程序非常脆弱。如果代码总是返回有效的结果，那将是理想的，但有时无法计算出有效的结果。例如，不能除以零，或者访问五项列表中的第八项。

在过去，唯一的解决方法是严格检查每个函数的输入，以确保它们是有意义的。通常，函数有特殊的返回值来指示错误条件；例如，它们可以返回一个负数来表示无法计算出正值。不同的数字可能表示不同的错误。调用这个函数的任何代码都必须明确检查错误条件并相应地采取行动。许多开发人员不愿意这样做，程序就会崩溃。然而，在面向对象的世界中，情况并非如此。

在本章中，我们将学习**异常**，这是特殊的错误对象，只有在有意义处理它们时才需要处理。特别是，我们将涵盖以下内容：

+   如何引发异常

+   在异常发生时如何恢复

+   如何以不同的方式处理不同类型的异常

+   在异常发生时进行清理

+   创建新类型的异常

+   使用异常语法进行流程控制

# 引发异常

原则上，异常只是一个对象。有许多不同的异常类可用，我们也可以很容易地定义更多我们自己的异常。它们所有的共同之处是它们都继承自一个名为`BaseException`的内置类。当这些异常对象在程序的控制流中被处理时，它们就变得特殊起来。当异常发生时，除非在异常发生时应该发生，否则一切都不会发生。明白了吗？别担心，你会明白的！

引发异常的最简单方法是做一些愚蠢的事情。很有可能你已经这样做过，并看到了异常输出。例如，每当 Python 遇到无法理解的程序行时，它就会以`SyntaxError`退出，这是一种异常。这是一个常见的例子：

```py
>>> print "hello world"
 File "<stdin>", line 1
 print "hello world"
 ^
SyntaxError: invalid syntax  
```

这个`print`语句在 Python 2 和更早的版本中是一个有效的命令，但在 Python 3 中，因为`print`是一个函数，我们必须用括号括起参数。因此，如果我们将前面的命令输入 Python 3 解释器，我们会得到`SyntaxError`。

除了`SyntaxError`，以下示例中还显示了一些其他常见的异常：

```py
>>> x = 5 / 0
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
ZeroDivisionError: int division or modulo by zero

>>> lst = [1,2,3]
>>> print(lst[3])
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
IndexError: list index out of range

>>> lst + 2
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
TypeError: can only concatenate list (not "int") to list

>>> lst.add
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
AttributeError: 'list' object has no attribute 'add'

>>> d = {'a': 'hello'}
>>> d['b']
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
KeyError: 'b'

>>> print(this_is_not_a_var)
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
NameError: name 'this_is_not_a_var' is not defined  
```

有时，这些异常是我们程序中出现问题的指示器（在这种情况下，我们会去到指示的行号并进行修复），但它们也会在合法的情况下发生。`ZeroDivisionError`错误并不总是意味着我们收到了无效的输入。它也可能意味着我们收到了不同的输入。用户可能误输入了零，或者故意输入了零，或者它可能代表一个合法的值，比如一个空的银行账户或者一个新生儿的年龄。

你可能已经注意到所有前面的内置异常都以`Error`结尾。在 Python 中，`error`和`Exception`这两个词几乎可以互换使用。错误有时被认为比异常更严重，但它们的处理方式完全相同。事实上，前面示例中的所有错误类都有`Exception`（它继承自`BaseException`）作为它们的超类。

# 引发异常

我们将在一分钟内开始回应这些异常，但首先，让我们发现如果我们正在编写一个需要通知用户或调用函数输入无效的程序应该做什么。我们可以使用 Python 使用的完全相同的机制。这里有一个简单的类，只有当它们是偶数的整数时才向列表添加项目：

```py
class EvenOnly(list): 
    def append(self, integer): 
        if not isinstance(integer, int): 
 raise TypeError("Only integers can be added") 
        if integer % 2: 
 raise ValueError("Only even numbers can be added") 
        super().append(integer) 
```

这个类扩展了内置的`list`，就像我们在第十六章中讨论的那样，*Python 中的对象*，并覆盖了`append`方法以检查两个条件，以确保项目是偶数。我们首先检查输入是否是`int`类型的实例，然后使用模运算符确保它可以被 2 整除。如果两个条件中的任何一个不满足，`raise`关键字会引发异常。`raise`关键字后面跟着作为异常引发的对象。在前面的例子中，从内置的`TypeError`和`ValueError`类构造了两个对象。引发的对象也可以很容易地是我们自己创建的新`Exception`类的实例（我们很快就会看到），在其他地方定义的异常，甚至是先前引发和处理的`Exception`对象。

如果我们在 Python 解释器中测试这个类，我们可以看到在异常发生时输出了有用的错误信息，就像以前一样：

```py
>>> e = EvenOnly()
>>> e.append("a string")
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
 File "even_integers.py", line 7, in add
 raise TypeError("Only integers can be added")
TypeError: Only integers can be added

>>> e.append(3)
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
 File "even_integers.py", line 9, in add
 raise ValueError("Only even numbers can be added")
ValueError: Only even numbers can be added
>>> e.append(2)
```

虽然这个类对于演示异常的作用是有效的，但它并不擅长其工作。仍然可以使用索引表示法或切片表示法将其他值添加到列表中。通过覆盖其他适当的方法，一些是魔术双下划线方法，所有这些都可以避免。

# 异常的影响

当引发异常时，似乎会立即停止程序执行。在引发异常之后应该运行的任何行都不会被执行，除非处理异常，否则程序将以错误消息退出。看一下这个基本函数：

```py
def no_return(): 
    print("I am about to raise an exception") 
    raise Exception("This is always raised") 
    print("This line will never execute") 
    return "I won't be returned" 
```

如果我们执行这个函数，我们会看到第一个`print`调用被执行，然后引发异常。第二个`print`函数调用不会被执行，`return`语句也不会被执行：

```py
>>> no_return()
I am about to raise an exception
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
 File "exception_quits.py", line 3, in no_return
 raise Exception("This is always raised")
Exception: This is always raised  
```

此外，如果我们有一个调用另一个引发异常的函数的函数，那么在调用第二个函数的地方之后，第一个函数中的任何内容都不会被执行。引发异常会立即停止所有执行，直到函数调用堆栈，直到它被处理或强制解释器退出。为了演示，让我们添加一个调用先前函数的第二个函数：

```py
def call_exceptor(): 
    print("call_exceptor starts here...") 
    no_return() 
    print("an exception was raised...") 
    print("...so these lines don't run") 
```

当我们调用这个函数时，我们会看到第一个`print`语句被执行，以及`no_return`函数中的第一行。但一旦引发异常，就不会执行其他任何内容：

```py
>>> call_exceptor()
call_exceptor starts here...
I am about to raise an exception
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
 File "method_calls_excepting.py", line 9, in call_exceptor
 no_return()
 File "method_calls_excepting.py", line 3, in no_return
 raise Exception("This is always raised")
Exception: This is always raised  
```

我们很快就会看到，当解释器实际上没有采取捷径并立即退出时，我们可以在任一方法内部对异常做出反应并处理。事实上，异常可以在最初引发后的任何级别进行处理。

从下到上查看异常的输出（称为回溯），注意两种方法都被列出。在`no_return`内部，异常最初被引发。然后，在其上方，我们看到在`call_exceptor`内部，那个讨厌的`no_return`函数被调用，异常*冒泡*到调用方法。从那里，它再上升一级到主解释器，由于不知道该如何处理它，放弃并打印了一个回溯。

# 处理异常

现在让我们看一下异常硬币的反面。如果我们遇到异常情况，我们的代码应该如何对其做出反应或恢复？我们通过在`try...except`子句中包装可能引发异常的任何代码（无论是异常代码本身，还是调用可能在其中引发异常的任何函数或方法）来处理异常。最基本的语法如下：

```py
try: 
    no_return() 
except: 
    print("I caught an exception") 
print("executed after the exception") 
```

如果我们使用现有的`no_return`函数运行这个简单的脚本——正如我们非常清楚的那样，它总是会引发异常——我们会得到这个输出：

```py
I am about to raise an exception 
I caught an exception 
executed after the exception 
```

`no_return`函数愉快地通知我们它即将引发异常，但我们欺骗了它并捕获了异常。一旦捕获，我们就能够清理自己（在这种情况下，通过输出我们正在处理的情况），并继续前进，而不受那个冒犯性的函数的干扰。`no_return`函数中剩余的代码仍未执行，但调用函数的代码能够恢复并继续。

请注意`try`和`except`周围的缩进。`try`子句包装可能引发异常的任何代码。然后`except`子句回到与`try`行相同的缩进级别。处理异常的任何代码都在`except`子句之后缩进。然后正常代码在原始缩进级别上恢复。

上述代码的问题在于它会捕获任何类型的异常。如果我们编写的代码可能引发`TypeError`和`ZeroDivisionError`，我们可能希望捕获`ZeroDivisionError`，但让`TypeError`传播到控制台。你能猜到语法是什么吗？

这是一个相当愚蠢的函数，它就是这样做的：

```py
def funny_division(divider):
    try:
        return 100 / divider
 except ZeroDivisionError:
        return "Zero is not a good idea!"

print(funny_division(0))
print(funny_division(50.0))
print(funny_division("hello"))
```

通过`print`语句测试该函数，显示它的行为符合预期：

```py
Zero is not a good idea!
2.0
Traceback (most recent call last):
 File "catch_specific_exception.py", line 9, in <module>
 print(funny_division("hello"))
 File "catch_specific_exception.py", line 3, in funny_division
 return 100 / divider
TypeError: unsupported operand type(s) for /: 'int' and 'str'.  
```

输出的第一行显示，如果我们输入`0`，我们会得到适当的模拟。如果使用有效的数字（请注意，它不是整数，但仍然是有效的除数），它会正确运行。但是，如果我们输入一个字符串（你一定想知道如何得到`TypeError`，不是吗？），它会出现异常。如果我们使用了一个未指定`ZeroDivisionError`的空`except`子句，当我们发送一个字符串时，它会指责我们除以零，这根本不是正确的行为。

*裸 except*语法通常不受欢迎，即使你真的想捕获所有异常实例。使用`except Exception:`语法显式捕获所有异常类型。这告诉读者你的意思是捕获异常对象和所有`Exception`的子类。裸 except 语法实际上与使用`except BaseException:`相同，它实际上捕获了非常罕见的系统级异常，这些异常很少有意想要捕获，正如我们将在下一节中看到的。如果你真的想捕获它们，明确使用`except BaseException:`，这样任何阅读你的代码的人都知道你不只是忘记指定想要的异常类型。

我们甚至可以捕获两个或更多不同的异常，并用相同的代码处理它们。以下是一个引发三种不同类型异常的示例。它使用相同的异常处理程序处理`TypeError`和`ZeroDivisionError`，但如果您提供数字`13`，它也可能引发`ValueError`错误：

```py
def funny_division2(divider):
    try:
        if divider == 13:
            raise ValueError("13 is an unlucky number")
        return 100 / divider
 except (ZeroDivisionError, TypeError):
        return "Enter a number other than zero"

for val in (0, "hello", 50.0, 13):

    print("Testing {}:".format(val), end=" ")
    print(funny_division2(val))
```

底部的`for`循环循环遍历几个测试输入并打印结果。如果你对`print`语句中的`end`参数感到疑惑，它只是将默认的尾随换行符转换为空格，以便与下一行的输出连接在一起。以下是程序的运行：

```py
Testing 0: Enter a number other than zero
Testing hello: Enter a number other than zero
Testing 50.0: 2.0
Testing 13: Traceback (most recent call last):
 File "catch_multiple_exceptions.py", line 11, in <module>
 print(funny_division2(val))
 File "catch_multiple_exceptions.py", line 4, in funny_division2
 raise ValueError("13 is an unlucky number")
ValueError: 13 is an unlucky number  
```

数字`0`和字符串都被`except`子句捕获，并打印出合适的错误消息。数字`13`的异常没有被捕获，因为它是一个`ValueError`，它没有包括在正在处理的异常类型中。这一切都很好，但如果我们想捕获不同的异常并对它们采取不同的措施怎么办？或者也许我们想对异常做一些处理，然后允许它继续冒泡到父函数，就好像它从未被捕获过？

我们不需要任何新的语法来处理这些情况。可以堆叠`except`子句，只有第一个匹配项将被执行。对于第二个问题，`raise`关键字，没有参数，将重新引发最后一个异常，如果我们已经在异常处理程序中。观察以下代码：

```py
def funny_division3(divider):
    try:
        if divider == 13:
            raise ValueError("13 is an unlucky number")
        return 100 / divider
 except ZeroDivisionError:
        return "Enter a number other than zero"
 except TypeError:
        return "Enter a numerical value"
 except ValueError:
        print("No, No, not 13!")
        raise
```

最后一行重新引发了`ValueError`错误，因此在输出`No, No, not 13!`之后，它将再次引发异常；我们仍然会在控制台上得到原始的堆栈跟踪。

如果我们像前面的例子中那样堆叠异常子句，只有第一个匹配的子句将被执行，即使有多个子句符合条件。为什么会有多个子句匹配？请记住，异常是对象，因此可以被子类化。正如我们将在下一节中看到的，大多数异常都扩展了`Exception`类（它本身是从`BaseException`派生的）。如果我们在捕获`TypeError`之前捕获`Exception`，那么只有`Exception`处理程序将被执行，因为`TypeError`是通过继承的`Exception`。

这在一些情况下非常有用，比如我们想要专门处理一些异常，然后将所有剩余的异常作为更一般的情况处理。在捕获所有特定异常后，我们可以简单地捕获`Exception`并在那里处理一般情况。

通常，当我们捕获异常时，我们需要引用`Exception`对象本身。这最常发生在我们使用自定义参数定义自己的异常时，但也可能与标准异常相关。大多数异常类在其构造函数中接受一组参数，我们可能希望在异常处理程序中访问这些属性。如果我们定义自己的`Exception`类，甚至可以在捕获时调用自定义方法。捕获异常作为变量的语法使用`as`关键字：

```py
try: 
    raise ValueError("This is an argument") 
except ValueError as e: 
    print("The exception arguments were", e.args) 
```

如果我们运行这个简单的片段，它会打印出我们传递给`ValueError`初始化的字符串参数。

我们已经看到了处理异常的语法的几种变体，但我们仍然不知道如何执行代码，无论是否发生异常。我们也无法指定仅在**不**发生异常时执行的代码。另外两个关键字，`finally`和`else`，可以提供缺失的部分。它们都不需要额外的参数。以下示例随机选择一个要抛出的异常并引发它。然后运行一些不那么复杂的异常处理代码，演示了新引入的语法：

```py
import random 
some_exceptions = [ValueError, TypeError, IndexError, None] 

try: 
    choice = random.choice(some_exceptions) 
    print("raising {}".format(choice)) 
    if choice: 
        raise choice("An error") 
except ValueError: 
    print("Caught a ValueError") 
except TypeError: 
    print("Caught a TypeError") 
except Exception as e: 
    print("Caught some other error: %s" % 
        ( e.__class__.__name__)) 
else: 
    print("This code called if there is no exception") 
finally: 
    print("This cleanup code is always called") 
```

如果我们运行这个例子——它几乎涵盖了每种可能的异常处理场景——几次，每次都会得到不同的输出，这取决于`random`选择的异常。以下是一些示例运行：

```py
$ python finally_and_else.py
raising None
This code called if there is no exception
This cleanup code is always called

$ python finally_and_else.py
raising <class 'TypeError'>
Caught a TypeError
This cleanup code is always called

$ python finally_and_else.py
raising <class 'IndexError'>
Caught some other error: IndexError
This cleanup code is always called

$ python finally_and_else.py
raising <class 'ValueError'>
Caught a ValueError
This cleanup code is always called  
```

请注意`finally`子句中的`print`语句无论发生什么都会被执行。当我们需要在我们的代码运行结束后执行某些任务时（即使发生异常），这是非常有用的。一些常见的例子包括以下情况：

+   清理打开的数据库连接

+   关闭打开的文件

+   通过网络发送关闭握手

`finally`子句在我们从`try`子句内部执行`return`语句时也非常重要。在返回值之前，`finally`处理程序将仍然被执行，而不会执行`try...finally`子句后面的任何代码。

此外，当没有引发异常时，请注意输出：`else`和`finally`子句都会被执行。`else`子句可能看起来多余，因为应该在没有引发异常时执行的代码可以直接放在整个`try...except`块之后。不同之处在于，如果捕获并处理了异常，`else`块将不会被执行。当我们讨论后续使用异常作为流程控制时，我们将会更多地了解这一点。

在`try`块之后可以省略任何`except`、`else`和`finally`子句（尽管单独的`else`是无效的）。如果包含多个子句，则必须先是`except`子句，然后是`else`子句，最后是`finally`子句。`except`子句的顺序通常从最具体到最一般。

# 异常层次结构

我们已经看到了几个最常见的内置异常，你可能会在你的常规 Python 开发过程中遇到其余的异常。正如我们之前注意到的，大多数异常都是`Exception`类的子类。但并非所有异常都是如此。`Exception`本身实际上是继承自一个叫做`BaseException`的类。事实上，所有异常都必须扩展`BaseException`类或其子类之一。

有两个关键的内置异常类，`SystemExit`和`KeyboardInterrupt`，它们直接从`BaseException`而不是`Exception`派生。`SystemExit`异常是在程序自然退出时引发的，通常是因为我们在代码中的某个地方调用了`sys.exit`函数（例如，当用户选择退出菜单项，单击窗口上的*关闭*按钮，或输入命令关闭服务器时）。该异常旨在允许我们在程序最终退出之前清理代码。但是，我们通常不需要显式处理它，因为清理代码可以发生在`finally`子句中。

如果我们处理它，我们通常会重新引发异常，因为捕获它会阻止程序退出。当然，也有一些情况下，我们可能希望阻止程序退出；例如，如果有未保存的更改，我们希望提示用户是否真的要退出。通常，如果我们处理`SystemExit`，那是因为我们想对其进行特殊处理，或者直接预期它。我们尤其不希望它在捕获所有正常异常的通用子句中被意外捕获。这就是它直接从`BaseException`派生的原因。

`KeyboardInterrupt`异常在命令行程序中很常见。当用户使用与操作系统相关的组合键（通常是*Ctrl* + *C*）明确中断程序执行时，就会抛出该异常。这是用户有意中断运行中程序的标准方式，与`SystemExit`一样，它几乎总是应该通过终止程序来响应。同样，像`SystemExit`一样，它应该在`finally`块中处理任何清理任务。

这是一个完全说明了层次结构的类图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/0003cd2e-9b19-4c3c-8280-9c4664984093.png)

当我们使用`except:`子句而没有指定任何异常类型时，它将捕获`BaseException`的所有子类；也就是说，它将捕获所有异常，包括这两个特殊的异常。由于我们几乎总是希望这些得到特殊处理，因此不明智地使用`except:`语句而不带参数。如果你想捕获除`SystemExit`和`KeyboardInterrupt`之外的所有异常，明确地捕获`Exception`。大多数 Python 开发人员认为没有指定类型的`except:`是一个错误，并会在代码审查中标记它。如果你真的想捕获所有异常，只需明确使用`except BaseException:`。

# 定义我们自己的异常

偶尔，当我们想要引发一个异常时，我们发现没有一个内置的异常适合。幸运的是，定义我们自己的新异常是微不足道的。类的名称通常设计为传达出了什么问题，我们可以在初始化程序中提供任意参数以包含额外的信息。

我们所要做的就是继承`Exception`类。我们甚至不必向类中添加任何内容！当然，我们可以直接扩展`BaseException`，但我从未遇到过这种情况。

这是我们在银行应用程序中可能使用的一个简单的异常：

```py
class InvalidWithdrawal(Exception): 
    pass 

raise InvalidWithdrawal("You don't have $50 in your account") 
```

最后一行说明了如何引发新定义的异常。我们能够将任意数量的参数传递给异常。通常使用字符串消息，但可以存储任何在以后的异常处理程序中可能有用的对象。`Exception.__init__`方法设计为接受任何参数并将它们存储为名为`args`的属性中的元组。这使得异常更容易定义，而无需覆盖`__init__`。

当然，如果我们确实想要自定义初始化程序，我们是可以自由这样做的。这里有一个异常，它的初始化程序接受当前余额和用户想要提取的金额。此外，它添加了一个方法来计算请求透支了多少。

```py
class InvalidWithdrawal(Exception): 
    def __init__(self, balance, amount): 
        super().__init__(f"account doesn't have ${amount}") 
        self.amount = amount 
        self.balance = balance 

    def overage(self): 
        return self.amount - self.balance 

raise InvalidWithdrawal(25, 50) 
```

结尾的`raise`语句说明了如何构造这个异常。正如你所看到的，我们可以对异常做任何其他对象可以做的事情。

这是我们如何处理`InvalidWithdrawal`异常的方法，如果有异常被引发：

```py
try: 
    raise InvalidWithdrawal(25, 50) 
except InvalidWithdrawal as e: 
    print("I'm sorry, but your withdrawal is " 
            "more than your balance by " 
            f"${e.overage()}") 
```

在这里，我们看到了`as`关键字的有效使用。按照惯例，大多数 Python 程序员将异常命名为`e`或`ex`变量，尽管通常情况下，你可以自由地将其命名为`exception`，或者如果你愿意的话，可以称之为`aunt_sally`。

定义自己的异常有很多原因。通常，向异常中添加信息或以某种方式记录异常是很有用的。但是，自定义异常的实用性在创建面向其他程序员访问的框架、库或 API 时才真正显现出来。在这种情况下，要小心确保代码引发的异常对客户程序员有意义。它们应该易于处理，并清楚地描述发生了什么。客户程序员应该很容易看到如何修复错误（如果它反映了他们代码中的错误）或处理异常（如果这是他们需要知道的情况）。

异常并不是异常的。新手程序员倾向于认为异常只对异常情况有用。然而，异常情况的定义可能模糊不清，而且可能会有不同的解释。考虑以下两个函数：

```py
def divide_with_exception(number, divisor): 
    try: 
        print(f"{number} / {divisor} = {number / divisor}") 
    except ZeroDivisionError: 
        print("You can't divide by zero") 

def divide_with_if(number, divisor): 
    if divisor == 0: 
        print("You can't divide by zero") 
    else: 
        print(f"{number} / {divisor} = {number / divisor}") 
```

这两个函数的行为是相同的。如果`divisor`为零，则打印错误消息；否则，显示除法结果的消息。我们可以通过使用`if`语句来避免抛出`ZeroDivisionError`。同样，我们可以通过明确检查参数是否在列表范围内来避免`IndexError`，并通过检查键是否在字典中来避免`KeyError`。

但我们不应该这样做。首先，我们可能会编写一个`if`语句，检查索引是否低于列表的参数，但忘记检查负值。

记住，Python 列表支持负索引；`-1`指的是列表中的最后一个元素。

最终，我们会发现这一点，并不得不找到我们检查代码的所有地方。但如果我们简单地捕获`IndexError`并处理它，我们的代码就可以正常工作。

Python 程序员倾向于遵循“宁可请求原谅，而不是事先征得许可”的模式，也就是说，他们执行代码，然后处理任何出现的问题。相反，先“三思而后行”的做法通常不太受欢迎。这样做的原因有几个，但主要原因是不应该需要消耗 CPU 周期来寻找在正常代码路径中不会出现的异常情况。因此，明智的做法是将异常用于异常情况，即使这些情况只是稍微异常。进一步地，我们实际上可以看到异常语法对于流程控制也是有效的。与`if`语句一样，异常可以用于决策、分支和消息传递。

想象一家销售小部件和小工具的公司的库存应用程序。当客户购买商品时，商品可以是有库存的，这种情况下商品会从库存中移除并返回剩余商品数量，或者可能是缺货的。现在，缺货在库存应用程序中是一件完全正常的事情。这绝对不是一个异常情况。但如果缺货了，我们应该返回什么呢？一个显示缺货的字符串？一个负数？在这两种情况下，调用方法都必须检查返回值是正整数还是其他值，以确定是否缺货。这似乎有点混乱，特别是如果我们在代码中忘记做这个检查。

相反，我们可以引发`OutOfStock`并使用`try`语句来控制程序流程。有道理吗？此外，我们还要确保不会将同一商品卖给两个不同的客户，或者出售还未备货的商品。促进这一点的一种方法是锁定每种商品，以确保一次只有一个人可以更新它。用户必须锁定商品，操作商品（购买、补充库存、计算剩余商品数量...），然后解锁商品。以下是一个带有描述部分方法应该做什么的文档字符串的不完整的`Inventory`示例：

```py
class Inventory:
    def lock(self, item_type):
        """Select the type of item that is going to
        be manipulated. This method will lock the
        item so nobody else can manipulate the
        inventory until it's returned. This prevents
        selling the same item to two different
        customers."""
        pass

    def unlock(self, item_type):
        """Release the given type so that other
        customers can access it."""
        pass

    def purchase(self, item_type):
        """If the item is not locked, raise an
        exception. If the item_type does not exist,
        raise an exception. If the item is currently
        out of stock, raise an exception. If the item
        is available, subtract one item and return
        the number of items left."""
        pass
```

我们可以将这个对象原型交给开发人员，并让他们实现方法，确保它们按照我们说的那样工作，而我们则可以继续编写需要进行购买的代码。我们将使用 Python 强大的异常处理来考虑不同的分支，具体取决于购买是如何进行的。

```py
item_type = "widget"
inv = Inventory()
inv.lock(item_type)
try:
    num_left = inv.purchase(item_type)
except InvalidItemType:
    print("Sorry, we don't sell {}".format(item_type))
except OutOfStock:
    print("Sorry, that item is out of stock.")
else:
    print("Purchase complete. There are {num_left} {item_type}s left")
finally:
    inv.unlock(item_type)
```

注意所有可能的异常处理子句是如何用来确保在正确的时间发生正确的操作。尽管`OutOfStock`并不是一个非常异常的情况，但我们能够使用异常来适当地处理它。这段代码也可以用`if...elif...else`结构来编写，但这样不容易阅读和维护。

我们还可以使用异常来在不同的方法之间传递消息。例如，如果我们想要告知客户商品预计何时会再次有货，我们可以确保我们的`OutOfStock`对象在构造时需要一个`back_in_stock`参数。然后，当我们处理异常时，我们可以检查该值并向客户提供额外的信息。附加到对象的信息可以很容易地在程序的两个不同部分之间传递。异常甚至可以提供一个方法，指示库存对象重新订购或预订商品。

使用异常来进行流程控制可以设计出一些方便的程序。从这次讨论中要记住的重要事情是异常并不是我们应该尽量避免的坏事。发生异常并不意味着你应该阻止这种异常情况的发生。相反，这只是一种在两个可能不直接调用彼此的代码部分之间传递信息的强大方式。

# 案例研究

我们一直在比较低级的细节层面上看异常的使用和处理——语法和定义。这个案例研究将帮助我们将这一切与之前的章节联系起来，这样我们就能看到异常在对象、继承和模块的更大背景下是如何使用的。

今天，我们将设计一个简单的中央认证和授权系统。整个系统将放置在一个模块中，其他代码将能够查询该模块对象以进行认证和授权。我们应该承认，从一开始，我们并不是安全专家，我们设计的系统可能存在许多安全漏洞。

我们的目的是研究异常，而不是保护系统。然而，对于其他代码可以与之交互的基本登录和权限系统来说，这是足够的。以后，如果其他代码需要更安全，我们可以请安全或密码专家审查或重写我们的模块，最好不要改变 API。

认证是确保用户确实是他们所说的人的过程。我们将遵循当今常见的网络系统的做法，使用用户名和私人密码组合。其他的认证方法包括语音识别、指纹或视网膜扫描仪以及身份证。

授权，另一方面，完全取决于确定特定（经过身份验证的）用户是否被允许执行特定操作。我们将创建一个基本的权限列表系统，该系统存储了允许执行每个操作的特定人员的列表。

此外，我们将添加一些管理功能，以允许新用户加入系统。为简洁起见，我们将省略密码编辑或一旦添加后更改权限，但是这些（非常必要的）功能当然可以在将来添加。

这是一个简单的分析；现在让我们继续设计。显然，我们需要一个存储用户名和加密密码的`User`类。这个类还将允许用户通过检查提供的密码是否有效来登录。我们可能不需要一个`Permission`类，因为可以将这些类别映射到使用字典的用户列表。我们应该有一个中央的`Authenticator`类，负责用户管理和登录或注销。拼图的最后一块是一个`Authorizor`类，处理权限和检查用户是否能执行某项活动。我们将在`auth`模块中提供这些类的单个实例，以便其他模块可以使用这个中央机制来满足其所有的身份验证和授权需求。当然，如果它们想要实例化这些类的私有实例，用于非中央授权活动，它们是可以自由这样做的。

随着我们的进行，我们还将定义几个异常。我们将从一个特殊的`AuthException`基类开始，它接受`username`和可选的`user`对象作为参数；我们自定义的大多数异常将继承自这个类。

让我们首先构建`User`类；这似乎足够简单。可以使用用户名和密码初始化一个新用户。密码将被加密存储，以减少被盗的可能性。我们还需要一个`check_password`方法来测试提供的密码是否正确。以下是完整的类：

```py
import hashlib

class User:
    def __init__(self, username, password):
        """Create a new user object. The password
        will be encrypted before storing."""
        self.username = username
        self.password = self._encrypt_pw(password)
        self.is_logged_in = False

    def _encrypt_pw(self, password):
        """Encrypt the password with the username and return
        the sha digest."""
        hash_string = self.username + password
        hash_string = hash_string.encode("utf8")
        return hashlib.sha256(hash_string).hexdigest()

    def check_password(self, password):
        """Return True if the password is valid for this
        user, false otherwise."""
        encrypted = self._encrypt_pw(password)
        return encrypted == self.password
```

由于在`__init__`和`check_password`中需要加密密码的代码，我们将其提取到自己的方法中。这样，如果有人意识到它不安全并需要改进，它只需要在一个地方进行更改。这个类可以很容易地扩展到包括强制或可选的个人详细信息，比如姓名、联系信息和出生日期。

在编写代码添加用户之前（这将在尚未定义的`Authenticator`类中进行），我们应该检查一些用例。如果一切顺利，我们可以添加一个带有用户名和密码的用户；`User`对象被创建并插入到字典中。但是，有哪些情况可能不顺利呢？显然，我们不希望添加一个已经存在于字典中的用户名的用户。

如果这样做，我们将覆盖现有用户的数据，新用户可能会访问该用户的权限。因此，我们需要一个`UsernameAlreadyExists`异常。另外，出于安全考虑，如果密码太短，我们可能应该引发一个异常。这两个异常都将扩展`AuthException`，我们之前提到过。因此，在编写`Authenticator`类之前，让我们定义这三个异常类：

```py
class AuthException(Exception): 
    def __init__(self, username, user=None): 
        super().__init__(username, user) 
        self.username = username 
        self.user = user 

class UsernameAlreadyExists(AuthException): 
    pass 

class PasswordTooShort(AuthException): 
    pass 
```

`AuthException`需要用户名，并且有一个可选的用户参数。第二个参数应该是与该用户名关联的`User`类的实例。我们正在定义的两个具体异常只需要通知调用类发生了异常情况，因此我们不需要为它们添加任何额外的方法。

现在让我们开始`Authenticator`类。它可以简单地是用户名到用户对象的映射，因此我们将从初始化函数中的字典开始。添加用户的方法需要在将新的`User`实例添加到字典之前检查两个条件（密码长度和先前存在的用户）：

```py
class Authenticator:
    def __init__(self):
        """Construct an authenticator to manage
        users logging in and out."""
        self.users = {}

    def add_user(self, username, password):
        if username in self.users:
            raise UsernameAlreadyExists(username)
        if len(password) < 6:
            raise PasswordTooShort(username)
        self.users[username] = User(username, password)
```

当然，如果需要，我们可以扩展密码验证以引发其他方式太容易破解的密码的异常。现在让我们准备`login`方法。如果我们现在不考虑异常，我们可能只希望该方法根据登录是否成功返回`True`或`False`。但我们正在考虑异常，这可能是一个不那么异常的情况使用它们的好地方。我们可以引发不同的异常，例如，如果用户名不存在或密码不匹配。这将允许尝试登录用户的任何人使用`try`/`except`/`else`子句优雅地处理情况。因此，首先我们添加这些新的异常：

```py
class InvalidUsername(AuthException): 
    pass 

class InvalidPassword(AuthException): 
    pass 
```

然后我们可以为我们的`Authenticator`类定义一个简单的`login`方法，如果必要的话引发这些异常。如果不是，它会标记`user`已登录并返回以下内容：

```py
    def login(self, username, password): 
        try: 
            user = self.users[username] 
        except KeyError: 
            raise InvalidUsername(username) 

        if not user.check_password(password): 
            raise InvalidPassword(username, user) 

        user.is_logged_in = True 
        return True 
```

请注意`KeyError`的处理方式。这可以使用`if username not in self.users:`来处理，但我们选择直接处理异常。我们最终吞掉了这个第一个异常，并引发了一个更适合用户界面 API 的全新异常。

我们还可以添加一个方法来检查特定用户名是否已登录。在这里决定是否使用异常更加棘手。如果用户名不存在，我们应该引发异常吗？如果用户未登录，我们应该引发异常吗？

要回答这些问题，我们需要考虑该方法如何被访问。大多数情况下，这种方法将用于回答是/否的问题，*我应该允许他们访问<something>吗？*答案要么是，*是的，用户名有效且他们已登录*，要么是，*不，用户名无效或他们未登录*。因此，布尔返回值就足够了。这里没有必要使用异常，只是为了使用异常：

```py
    def is_logged_in(self, username): 
        if username in self.users: 
            return self.users[username].is_logged_in 
        return False 
```

最后，我们可以向我们的模块添加一个默认的认证实例，以便客户端代码可以使用`auth.authenticator`轻松访问它：

```py
authenticator = Authenticator() 
```

这一行放在模块级别，不在任何类定义之外，因此可以通过`auth.authenticator`访问`authenticator`变量。现在我们可以开始`Authorizor`类，它将权限映射到用户。`Authorizor`类不应允许用户访问权限，如果他们未登录，因此它们将需要引用特定的认证实例。我们还需要在初始化时设置权限字典：

```py
class Authorizor: 
    def __init__(self, authenticator): 
        self.authenticator = authenticator 
        self.permissions = {} 
```

现在我们可以编写方法来添加新的权限，并设置哪些用户与每个权限相关联：

```py
    def add_permission(self, perm_name): 
        '''Create a new permission that users 
        can be added to''' 
        try: 
            perm_set = self.permissions[perm_name] 
        except KeyError: 
            self.permissions[perm_name] = set() 
        else: 
            raise PermissionError("Permission Exists") 

    def permit_user(self, perm_name, username): 
        '''Grant the given permission to the user''' 
        try: 
            perm_set = self.permissions[perm_name] 
        except KeyError: 
            raise PermissionError("Permission does not exist") 
        else: 
            if username not in self.authenticator.users: 
                raise InvalidUsername(username) 
            perm_set.add(username) 
```

第一个方法允许我们创建一个新的权限，除非它已经存在，否则会引发异常。第二个方法允许我们将用户名添加到权限中，除非权限或用户名尚不存在。

我们使用`set`而不是`list`来存储用户名，这样即使您多次授予用户权限，集合的性质意味着用户只会在集合中出现一次。

这两种方法都引发了`PermissionError`错误。这个新错误不需要用户名，所以我们将它直接扩展为`Exception`，而不是我们自定义的`AuthException`：

```py
class PermissionError(Exception): 
    pass 
```

最后，我们可以添加一个方法来检查用户是否具有特定的`permission`。为了让他们获得访问权限，他们必须同时登录到认证器并在被授予该特权访问的人员集合中。如果这两个条件中有一个不满足，就会引发异常：

```py
    def check_permission(self, perm_name, username): 
        if not self.authenticator.is_logged_in(username): 
            raise NotLoggedInError(username) 
        try: 
            perm_set = self.permissions[perm_name] 
        except KeyError: 
            raise PermissionError("Permission does not exist") 
        else: 
            if username not in perm_set: 
                raise NotPermittedError(username) 
            else: 
                return True 
```

这里有两个新的异常；它们都使用用户名，所以我们将它们定义为`AuthException`的子类：

```py
class NotLoggedInError(AuthException): 
    pass 

class NotPermittedError(AuthException): 
    pass 
```

最后，我们可以添加一个默认的`authorizor`来与我们的默认认证器配对：

```py
authorizor = Authorizor(authenticator) 
```

这完成了一个基本的身份验证/授权系统。我们可以在 Python 提示符下测试系统，检查用户`joe`是否被允许在油漆部门执行任务：

```py
>>> import auth
>>> auth.authenticator.add_user("joe", "joepassword")
>>> auth.authorizor.add_permission("paint")
>>> auth.authorizor.check_permission("paint", "joe")
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
 File "auth.py", line 109, in check_permission
 raise NotLoggedInError(username)
auth.NotLoggedInError: joe
>>> auth.authenticator.is_logged_in("joe")
False
>>> auth.authenticator.login("joe", "joepassword")
True
>>> auth.authorizor.check_permission("paint", "joe")
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
 File "auth.py", line 116, in check_permission
    raise NotPermittedError(username)
auth.NotPermittedError: joe
>>> auth.authorizor.check_permission("mix", "joe")
Traceback (most recent call last):
 File "auth.py", line 111, in check_permission
 perm_set = self.permissions[perm_name]
KeyError: 'mix'

During handling of the above exception, another exception occurred:
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
 File "auth.py", line 113, in check_permission
 raise PermissionError("Permission does not exist")
auth.PermissionError: Permission does not exist
>>> auth.authorizor.permit_user("mix", "joe")
Traceback (most recent call last):
 File "auth.py", line 99, in permit_user
 perm_set = self.permissions[perm_name]
KeyError: 'mix'

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
 File "auth.py", line 101, in permit_user
 raise PermissionError("Permission does not exist")
auth.PermissionError: Permission does not exist
>>> auth.authorizor.permit_user("paint", "joe")
>>> auth.authorizor.check_permission("paint", "joe")
True  
```

虽然冗长，前面的输出显示了我们所有的代码和大部分异常的运行情况，但要真正理解我们定义的 API，我们应该编写一些实际使用它的异常处理代码。这里有一个基本的菜单界面，允许特定用户更改或测试程序：

```py
import auth

# Set up a test user and permission
auth.authenticator.add_user("joe", "joepassword")
auth.authorizor.add_permission("test program")
auth.authorizor.add_permission("change program")
auth.authorizor.permit_user("test program", "joe")

class Editor:
    def __init__(self):
        self.username = None
        self.menu_map = {
            "login": self.login,
            "test": self.test,
            "change": self.change,
            "quit": self.quit,
        }

    def login(self):
        logged_in = False
        while not logged_in:
            username = input("username: ")
            password = input("password: ")
            try:
                logged_in = auth.authenticator.login(username, password)
            except auth.InvalidUsername:
                print("Sorry, that username does not exist")
            except auth.InvalidPassword:
                print("Sorry, incorrect password")
            else:
                self.username = username

    def is_permitted(self, permission):
        try:
            auth.authorizor.check_permission(permission, self.username)
        except auth.NotLoggedInError as e:
            print("{} is not logged in".format(e.username))
            return False
        except auth.NotPermittedError as e:
            print("{} cannot {}".format(e.username, permission))
            return False
        else:
            return True

    def test(self):
        if self.is_permitted("test program"):
            print("Testing program now...")

    def change(self):
        if self.is_permitted("change program"):
            print("Changing program now...")

    def quit(self):
        raise SystemExit()

    def menu(self):
        try:
            answer = ""
            while True:
                print(
                    """
Please enter a command:
\tlogin\tLogin
\ttest\tTest the program
\tchange\tChange the program
\tquit\tQuit
"""
                )
                answer = input("enter a command: ").lower()
                try:
                    func = self.menu_map[answer]
                except KeyError:
                    print("{} is not a valid option".format(answer))
                else:
                    func()
        finally:
            print("Thank you for testing the auth module")

Editor().menu()
```

这个相当长的例子在概念上非常简单。 `is_permitted` 方法可能是最有趣的；这是一个主要是内部方法，被`test`和`change`调用，以确保用户在继续之前被允许访问。当然，这两种方法都是存根，但我们这里不是在写编辑器；我们是通过测试身份验证和授权框架来说明异常和异常处理的使用。

# 练习

如果你以前从未处理过异常，你需要做的第一件事是查看你写过的任何旧的 Python 代码，并注意是否有应该处理异常的地方。你会如何处理它们？你需要完全处理它们吗？有时，让异常传播到控制台是与用户沟通的最佳方式，特别是如果用户也是脚本的编码者。有时，你可以从错误中恢复并允许程序继续。有时，你只能将错误重新格式化为用户可以理解的内容并显示给他们。

一些常见的查找地方是文件 I/O（你的代码是否可能尝试读取一个不存在的文件？），数学表达式（你要除以的值是否可能为零？），列表索引（列表是否为空？）和字典（键是否存在？）。问问自己是否应该忽略问题，通过先检查值来处理它，还是通过异常来处理它。特别注意可能使用`finally`和`else`来确保在所有条件下执行正确代码的地方。

现在写一些新代码。想想一个需要身份验证和授权的程序，并尝试编写一些使用我们在案例研究中构建的`auth`模块的代码。如果模块不够灵活，可以随意修改模块。尝试处理

以明智的方式处理所有异常。如果你在想出需要身份验证的东西时遇到麻烦，可以尝试在第十六章的记事本示例中添加授权，*Python 中的对象*，或者在`auth`模块本身添加授权——如果任何人都可以开始添加权限，这个模块就不是一个非常有用的模块！也许在允许添加或更改权限之前需要管理员用户名和密码。

最后，试着想想你的代码中可以引发异常的地方。可以是你写过或正在处理的代码；或者你可以编写一个新的项目作为练习。你可能最容易设计一个小型框架或 API，供其他人使用；异常是你的代码和别人之间的绝妙沟通工具。记得设计和记录任何自引发的异常作为 API 的一部分，否则他们将不知道是否以及如何处理它们！

# 总结

在这一章中，我们深入讨论了引发、处理、定义和操纵异常的细节。异常是一种强大的方式，可以在不要求调用函数显式检查返回值的情况下，传达异常情况或错误条件。有许多内置的异常，引发它们非常容易。处理不同异常事件有几种不同的语法。

在下一章中，我们将讨论到目前为止所学的一切如何结合在一起，讨论面向对象编程原则和结构在 Python 应用程序中应该如何最好地应用。
