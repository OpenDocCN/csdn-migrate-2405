# Python 入门指南（六）

> 原文：[`zh.annas-archive.org/md5/97bc15629f1b51a0671040c56db61b92`](https://zh.annas-archive.org/md5/97bc15629f1b51a0671040c56db61b92)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十九章：何时使用面向对象编程

在之前的章节中，我们已经涵盖了面向对象编程的许多定义特性。我们现在知道面向对象设计的原则和范例，并且我们已经涵盖了 Python 中面向对象编程的语法。

然而，我们并不确切知道如何，尤其是何时在实践中利用这些原则和语法。在本章中，我们将讨论我们所获得的知识的一些有用应用，同时查看一些新的主题：

+   如何识别对象

+   数据和行为，再次

+   使用属性封装数据行为

+   使用行为限制数据

+   不要重复自己的原则

+   识别重复的代码

# 将对象视为对象

这可能看起来很明显；你通常应该在代码中为问题域中的单独对象给予特殊的类。我们在之前章节的案例研究中已经看到了这样的例子：首先，我们确定问题中的对象，然后对其数据和行为进行建模。

在面向对象分析和编程中，识别对象是一项非常重要的任务。但这并不总是像计算短段落中的名词那样容易，坦率地说，我明确为此目的构建了。记住，对象是既有数据又有行为的东西。如果我们只处理数据，通常最好将其存储在列表、集合、字典或其他 Python 数据结构中。另一方面，如果我们只处理行为，但没有存储的数据，一个简单的函数更合适。

然而，对象既有数据又有行为。熟练的 Python 程序员使用内置数据结构，除非（或直到）明显需要定义一个类。如果这并没有帮助组织我们的代码，那么没有理由添加额外的抽象级别。另一方面，*明显的*需要并不总是不言自明的。

我们通常可以通过将数据存储在几个变量中来启动我们的 Python 程序。随着程序的扩展，我们将会发现我们正在将相同的一组相关变量传递给一组函数。这是思考将变量和函数组合成一个类的时候了。如果我们正在设计一个在二维空间中模拟多边形的程序，我们可能会从将每个多边形表示为点列表开始。这些点将被建模为两个元组（*x*，*y*），描述该点的位置。这是所有的数据，存储在一组嵌套的数据结构中（具体来说，是一个元组列表）：

```py
square = [(1,1), (1,2), (2,2), (2,1)] 
```

现在，如果我们想要计算多边形周长的距离，我们需要计算每个点之间的距离。为此，我们需要一个函数来计算两点之间的距离。以下是两个这样的函数：

```py
import math

def distance(p1, p2):
    return math.sqrt((p1[0]-p2[0])**2 + (p1[1]-p2[1])**2)

def perimeter(polygon):
    perimeter = 0
    points = polygon + [polygon[0]]
    for i in range(len(polygon)):
        perimeter += distance(points[i], points[i+1])
    return perimeter

```

现在，作为面向对象的程序员，我们清楚地认识到`polygon`类可以封装点的列表（数据）和`perimeter`函数（行为）。此外，`point`类，就像我们在第十六章中定义的那样，*Python 中的对象*，可能封装`x`和`y`坐标以及`distance`方法。问题是：这样做有价值吗？

对于以前的代码，也许是，也许不是。有了我们最近在面向对象原则方面的经验，我们可以以创纪录的速度编写面向对象的版本。让我们进行比较：

```py
class Point:
 def __init__(self, x, y):
 self.x = x
 self.y = y

    def distance(self, p2):
        return math.sqrt((self.x-p2.x)**2 + (self.y-p2.y)**2)

class Polygon:
 def __init__(self):
 self.vertices = []

 def add_point(self, point):
 self.vertices.append((point))

    def perimeter(self):
        perimeter = 0
        points = self.vertices + [self.vertices[0]]
        for i in range(len(self.vertices)):
            perimeter += points[i].distance(points[i+1])
        return perimeter
```

正如我们从突出显示的部分所看到的，这里的代码量是我们之前版本的两倍，尽管我们可以争辩说`add_point`方法并不是严格必要的。

现在，为了更好地理解这两种 API 之间的差异，让我们比较一下两种使用情况。以下是使用面向对象的代码计算正方形的周长：

```py
>>> square = Polygon()
>>> square.add_point(Point(1,1))
>>> square.add_point(Point(1,2))
>>> square.add_point(Point(2,2))
>>> square.add_point(Point(2,1))
>>> square.perimeter()
4.0  
```

这可能看起来相当简洁和易读，但让我们将其与基于函数的代码进行比较：

```py
>>> square = [(1,1), (1,2), (2,2), (2,1)]
>>> perimeter(square)
4.0  
```

嗯，也许面向对象的 API 并不那么紧凑！也就是说，我认为它比函数示例更容易*阅读*。我们怎么知道第二个版本中的元组列表应该表示什么？我们怎么记得我们应该传递到`perimeter`函数的对象是什么？（两个元组的列表？这不直观！）我们需要大量的文档来解释这些函数应该如何使用。

相比之下，面向对象的代码相对自我说明。我们只需要查看方法列表及其参数，就可以知道对象的功能和如何使用它。当我们为函数版本编写所有文档时，它可能会比面向对象的代码还要长。

最后，代码长度并不是代码复杂性的良好指标。一些程序员会陷入复杂的*一行代码*中，这一行代码可以完成大量工作。这可能是一个有趣的练习，但结果通常是令人难以阅读的，即使对于原始作者来说，第二天也是如此。最小化代码量通常可以使程序更易于阅读，但不要盲目地假设这是正确的。

幸运的是，这种权衡是不必要的。我们可以使面向对象的`Polygon` API 与函数实现一样易于使用。我们只需要修改我们的`Polygon`类，使其可以用多个点构造。让我们给它一个接受`Point`对象列表的初始化器。事实上，让我们也允许它接受元组，如果需要，我们可以自己构造`Point`对象：

```py
def __init__(self, points=None): 
    points = points if points else [] 
    self.vertices = [] 
    for point in points: 
        if isinstance(point, tuple): 
            point = Point(*point) 
        self.vertices.append(point) 
```

这个初始化器遍历列表，并确保任何元组都转换为点。如果对象不是元组，我们将其保留，假设它已经是`Point`对象，或者是一个未知的鸭子类型对象，可以像`Point`对象一样工作。

如果您正在尝试上述代码，您可以对`Polygon`进行子类化，并覆盖`__init__`函数，而不是替换初始化器或复制`add_point`和`perimeter`方法。

然而，在面向对象和更注重数据的版本之间没有明显的赢家。它们都做同样的事情。如果我们有新的函数接受多边形参数，比如`area(polygon)`或`point_in_polygon(polygon, x, y)`，面向对象代码的好处变得越来越明显。同样，如果我们为多边形添加其他属性，比如`color`或`texture`，将这些数据封装到一个类中就变得更有意义。

区别是一个设计决策，但一般来说，数据集越重要，就越有可能具有针对该数据的多个特定功能，使用具有属性和方法的类会更有用。

在做出这个决定时，考虑类将如何使用也是很重要的。如果我们只是试图在更大的问题的背景下计算一个多边形的周长，使用函数可能会是编码最快且最容易*仅一次*使用。另一方面，如果我们的程序需要以各种方式操作大量多边形（计算周长、面积和与其他多边形的交集、移动或缩放它们等），我们几乎肯定已经确定了一个对象；一个需要非常灵活的对象。

此外，要注意对象之间的交互。寻找继承关系；继承无法在没有类的情况下优雅地建模，因此一定要使用它们。寻找我们在第十五章中讨论的其他类型的关系，*面向对象设计*，关联和组合。组合在技术上可以使用只有数据结构来建模；例如，我们可以有一个包含元组值的字典列表，但有时创建几个对象类会更不复杂，特别是如果与数据相关联的行为。

不要急于使用对象，只是因为你可以使用对象，但是当你需要使用类时，不要忽视创建一个类。

# 使用属性为类数据添加行为

在整本书中，我们一直专注于行为和数据的分离。这在面向对象编程中非常重要，但是我们将看到，在 Python 中，这种区别是模糊的。Python 非常擅长模糊界限；它并不完全帮助我们*打破思维定势*。相反，它教会我们停止思考盒子。

在我们深入细节之前，让我们讨论一些糟糕的面向对象理论。许多面向对象的语言教导我们永远不要直接访问属性（Java 是最臭名昭著的）。他们坚持我们应该像这样写属性访问：

```py
class Color: 
    def __init__(self, rgb_value, name): 
        self._rgb_value = rgb_value 
        self._name = name 

 def set_name(self, name): 
        self._name = name 

 def get_name(self): 
        return self._name 
```

变量以下划线开头，表示它们是私有的（其他语言实际上会强制它们为私有）。然后，`get`和`set`方法提供对每个变量的访问。这个类将在实践中使用如下：

```py
>>> c = Color("#ff0000", "bright red")
>>> c.get_name()
'bright red'
>>> c.set_name("red")
>>> c.get_name()
'red'  
```

这不像 Python 青睐的直接访问版本那样易读：

```py
class Color: 
    def __init__(self, rgb_value, name): 
        self.rgb_value = rgb_value 
        self.name = name 

c = Color("#ff0000", "bright red") 
print(c.name) c.name = "red"
print(c.name)
```

那么，为什么有人坚持使用基于方法的语法呢？他们的理由是，有一天，我们可能希望在设置或检索值时添加额外的代码。例如，我们可以决定缓存一个值以避免复杂的计算，或者我们可能希望验证给定的值是否是合适的输入。

例如，在代码中，我们可以决定将`set_name()`方法更改如下：

```py
def set_name(self, name): 
    if not name: 
        raise Exception("Invalid Name") 
    self._name = name 
```

现在，在 Java 和类似的语言中，如果我们最初为直接属性访问编写了原始代码，然后稍后将其更改为像前面的方法，我们会有问题：任何访问属性的代码现在都必须访问一个方法。如果他们没有将访问样式从属性访问更改为函数调用，他们的代码将会出错。

这些语言中的口头禅是我们永远不应该将公共成员变为私有成员。这在 Python 中并没有太多意义，因为 Python 没有真正的私有成员的概念！

Python 给了我们`property`关键字，可以使方法看起来像属性。因此，我们可以编写代码来直接访问成员，如果我们需要在获取或设置属性值时进行一些计算，我们可以在不改变接口的情况下进行修改。让我们看看它是什么样子：

```py
class Color: 
    def __init__(self, rgb_value, name): 
        self.rgb_value = rgb_value 
        self._name = name 

    def _set_name(self, name): 
        if not name: 
            raise Exception("Invalid Name") 
        self._name = name 

    def _get_name(self): 
        return self._name 

 name = property(_get_name, _set_name) 
```

与之前的类相比，我们首先将`name`属性更改为(半)私有的`_name`属性。然后，我们添加了两个更多的(半)私有方法来获取和设置该变量，在设置时执行验证。

最后，我们在底部有`property`声明。这就是 Python 的魔力。它在`Color`类上创建了一个名为`name`的新属性，以替换直接的`name`属性。它将此属性设置为**property**。在幕后，`property`在访问或更改值时调用我们刚刚创建的两个方法。这个新版本的`Color`类可以像以前的版本一样使用，但是现在在设置`name`属性时执行验证：

```py
>>> c = Color("#0000ff", "bright red")
>>> print(c.name)
bright red
>>> c.name = "red"
>>> print(c.name)
red
>>> c.name = ""
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
 File "setting_name_property.py", line 8, in _set_name
 raise Exception("Invalid Name")
Exception: Invalid Name  
```

因此，如果我们以前编写了访问`name`属性的代码，然后更改为使用基于`property`的对象，以前的代码仍然可以工作，除非它发送了一个空的`property`值，这正是我们想要在第一次禁止的行为。成功！

请记住，即使有了`name`属性，以前的代码也不是 100%安全的。人们仍然可以直接访问`_name`属性，并将其设置为空字符串。但是，如果他们访问了我们明确标记为下划线的变量，暗示它是私有的，他们就必须处理后果，而不是我们。

# 属性详解

将`property`函数视为返回一个对象，通过我们指定的方法代理对设置或访问属性值的任何请求。内置的`property`就像这样的对象的构造函数，并且该对象被设置为给定属性的公共成员。

这个`property`构造函数实际上可以接受两个额外的参数，一个`delete`函数和一个属性的文档字符串。在实践中很少提供`delete`函数，但如果我们有理由这样做，它可能对记录已删除的值或可能否决删除很有用。文档字符串只是描述属性功能的字符串，与我们在第十六章中讨论的文档字符串没有什么不同，*Python 中的对象*。如果我们不提供此参数，文档字符串将从第一个参数的文档字符串复制：`getter`方法。这是一个愚蠢的例子，说明每当调用任何方法时：

```py
class Silly:
    def _get_silly(self):
        print("You are getting silly")
        return self._silly

    def _set_silly(self, value):
        print("You are making silly {}".format(value))
        self._silly = value

    def _del_silly(self):
        print("Whoah, you killed silly!")
        del self._silly

 silly = property(_get_silly, _set_silly, _del_silly, "This is a silly property")
```

如果我们实际使用这个类，当我们要求它时，它确实会打印出正确的字符串：

```py
>>> s = Silly()
>>> s.silly = "funny"
You are making silly funny
>>> s.silly
You are getting silly
'funny'
>>> del s.silly
Whoah, you killed silly!  
```

此外，如果我们查看`Silly`类的帮助文件（通过在解释器提示符处发出`help(Silly)`），它会显示我们的`silly`属性的自定义文档字符串：

```py
Help on class Silly in module __main__: 

class Silly(builtins.object) 
 |  Data descriptors defined here: 
 |   
 |  __dict__ 
 |      dictionary for instance variables (if defined) 
 |   
 |  __weakref__ 
 |      list of weak references to the object (if defined) 
 |   
 |  silly 
 |      This is a silly property 
```

再次，一切都按我们计划的那样运行。在实践中，属性通常只使用前两个参数进行定义：`getter`和`setter`函数。如果我们想为属性提供文档字符串，我们可以在`getter`函数上定义它；属性代理将把它复制到自己的文档字符串中。`delete`函数通常为空，因为对象属性很少被删除。如果程序员尝试删除没有指定`delete`函数的属性，它将引发异常。因此，如果有正当理由删除我们的属性，我们应该提供该函数。

# 装饰器-创建属性的另一种方法

如果您以前从未使用过 Python 装饰器，您可能希望跳过本节，在我们讨论第二十二章中的装饰器模式之后再回来，*Python 设计模式 I*。但是，您不需要理解正在发生的事情，以使用装饰器语法来使属性方法更易读。

`property`函数可以与装饰器语法一起使用，将`get`函数转换为`property`函数，如下所示：

```py
class Foo: 
 @property 
    def foo(self): 
        return "bar" 
```

这将`property`函数应用为装饰器，并且等同于以前的`foo = property(foo)`语法。从可读性的角度来看，主要区别在于我们可以在方法的顶部将`foo`函数标记为属性，而不是在定义之后，这样很容易被忽视。这也意味着我们不必创建带有下划线前缀的私有方法来定义属性。

更进一步，我们可以为新属性指定一个`setter`函数，如下所示：

```py
class Foo: 
 @property 
    def foo(self): 
        return self._foo 

 @foo.setter 
    def foo(self, value): 
        self._foo = value 
```

这个语法看起来很奇怪，尽管意图是明显的。首先，我们将`foo`方法装饰为 getter。然后，我们通过应用最初装饰的`foo`方法的`setter`属性，装饰了第二个同名方法！`property`函数返回一个对象；这个对象总是带有自己的`setter`属性，然后可以将其应用为其他函数的装饰器。使用相同的名称来命名获取和设置方法并不是必需的，但它确实有助于将访问一个属性的多个方法分组在一起。

我们还可以使用`@foo.deleter`指定一个`delete`函数。我们不能使用`property`装饰器来指定文档字符串，因此我们需要依赖于属性从初始 getter 方法复制文档字符串。下面是我们之前的`Silly`类重写，以使用`property`作为装饰器：

```py
class Silly: 
 @property 
    def silly(self): 
        "This is a silly property" 
        print("You are getting silly") 
        return self._silly 

 @silly.setter 
    def silly(self, value): 
        print("You are making silly {}".format(value)) 
        self._silly = value 

 @silly.deleter 
    def silly(self): 
        print("Whoah, you killed silly!") 
        del self._silly 
```

这个类的操作*完全*与我们之前的版本相同，包括帮助文本。您可以使用您认为更可读和优雅的任何语法。

# 决定何时使用属性

由于内置的属性模糊了行为和数据之间的区分，很难知道何时选择属性、方法或属性。我们之前看到的用例示例是属性的最常见用法之一；我们在类上有一些数据，然后希望添加行为。在决定使用属性时，还有其他因素需要考虑。

在 Python 中，数据、属性和方法在类上都是属性。方法可调用的事实并不能将其与其他类型的属性区分开；事实上，我们将在第二十章中看到，*Python 面向对象的快捷方式*，可以创建可以像函数一样调用的普通对象。我们还将发现函数和方法本身也是普通对象。

方法只是可调用的属性，属性只是可定制的属性，这可以帮助我们做出这个决定。方法通常应该表示动作；可以对对象执行的操作。当你调用一个方法时，即使只有一个参数，它也应该*做*一些事情。方法名称通常是动词。

确认属性不是一个动作后，我们需要在标准数据属性和属性之间做出选择。通常情况下，始终使用标准属性，直到需要以某种方式控制对该属性的访问。无论哪种情况，您的属性通常是一个名词。属性和属性之间唯一的区别是，当检索、设置或删除属性时，我们可以自动调用自定义操作。

让我们看一个更现实的例子。自定义行为的常见需求是缓存难以计算或昂贵的查找值（例如，需要网络请求或数据库查询）。目标是将值存储在本地，以避免重复调用昂贵的计算。

我们可以通过属性的自定义 getter 来实现这一点。第一次检索值时，我们执行查找或计算。然后，我们可以将值作为对象的私有属性（或专用缓存软件中）进行本地缓存，下次请求值时，我们返回存储的数据。以下是我们可能缓存网页的方法：

```py
from urllib.request import urlopen

class WebPage:
    def __init__(self, url):
        self.url = url
        self._content = None

    @property
 def content(self):
 if not self._content:
 print("Retrieving New Page...")
 self._content = urlopen(self.url).read()
 return self._content
```

我们可以测试这段代码，以查看页面只被检索一次：

```py
>>> import time
>>> webpage = WebPage("http://ccphillips.net/")
>>> now = time.time()
>>> content1 = webpage.content
Retrieving New Page...
>>> time.time() - now
22.43316888809204
>>> now = time.time()
>>> content2 = webpage.content
>>> time.time() - now
1.9266459941864014
>>> content2 == content1
True  
```

我在 2010 年首次测试这段代码时使用的是糟糕的卫星连接，第一次加载内容花了 20 秒。第二次，我在 2 秒内得到了结果（实际上只是在解释器中输入这些行所花费的时间）。在我更现代的连接上，情况如下：

```py
>>> webpage = WebPage("https://dusty.phillips.codes")
>>> import time
>>> now = time.time() ; content1 = webpage.content ; print(time.time() - now)
Retrieving New Page...
0.6236202716827393
>>> now = time.time() ; content2 = webpage.content ; print(time.time() - now)
1.7881393432617188e-05M
```

从我的网络主机检索页面大约需要 620 毫秒。从我的笔记本电脑的 RAM 中，只需要 0.018 毫秒！

自定义 getter 也适用于需要根据其他对象属性动态计算的属性。例如，我们可能想要计算整数列表的平均值：

```py
class AverageList(list): 
    @property 
    def average(self): 
        return sum(self) / len(self) 
```

这个非常简单的类继承自`list`，所以我们可以免费获得类似列表的行为。我们只需向类添加一个属性，就可以得到列表的平均值。

```py
>>> a = AverageList([1,2,3,4])
>>> a.average
2.5  
```

当然，我们也可以将其制作成一个方法，但那样我们应该将其命名为`calculate_average()`，因为方法代表动作。但名为`average`的属性更合适，而且更容易输入和阅读。

自定义 setter 对于验证是有用的，正如我们已经看到的，但它们也可以用于将值代理到另一个位置。例如，我们可以为`WebPage`类添加一个内容 setter，以便在设置值时自动登录到我们的 Web 服务器并上传新页面。

# 管理对象

我们一直专注于对象及其属性和方法。现在，我们将看看如何设计更高级的对象；管理其他对象的对象 - 将所有东西联系在一起的对象。

这些对象与大多数先前的示例之间的区别在于，后者通常代表具体的想法。管理对象更像办公室经理；他们不会在现场进行实际的*可见*工作，但没有他们，部门之间就不会有沟通，也没有人知道他们应该做什么（尽管如果组织管理不善，这也可能是真的！）。类似地，管理类上的属性倾向于引用做*可见*工作的其他对象；这样的类上的行为在适当的时候委托给这些其他类，并在它们之间传递消息。

例如，我们将编写一个程序，对存储在压缩的 ZIP 文件中的文本文件执行查找和替换操作。我们需要对象来表示 ZIP 文件和每个单独的文本文件（幸运的是，我们不必编写这些类，因为它们在 Python 标准库中可用）。管理对象将负责确保以下三个步骤按顺序发生：

1.  解压缩压缩文件

1.  执行查找和替换操作

1.  压缩新文件

该类使用`.zip`文件名、搜索和替换字符串进行初始化。我们创建一个临时目录来存储解压后的文件，以便文件夹保持干净。`pathlib`库在文件和目录操作中提供帮助。接口在以下示例中应该很清楚：

```py
import sys 
import shutil 
import zipfile 
from pathlib import Path 

class ZipReplace: 
    def __init__(self, filename, search_string, replace_string): 
        self.filename = filename 
        self.search_string = search_string 
        self.replace_string = replace_string 
        self.temp_directory = Path(f"unzipped-{filename}")
```

然后，我们为三个步骤创建一个整体*管理*方法。该方法将责任委托给其他对象：

```py
def zip_find_replace(self): 
    self.unzip_files() 
    self.find_replace() 
    self.zip_files() 
```

显然，我们可以在一个方法中完成所有三个步骤，或者在一个脚本中完成，而不必创建对象。将三个步骤分开有几个优点：

+   可读性：每个步骤的代码都在一个易于阅读和理解的自包含单元中。方法名称描述了方法的作用，需要更少的额外文档来理解正在发生的事情。

+   可扩展性：如果子类想要使用压缩的 TAR 文件而不是 ZIP 文件，它可以重写`zip`和`unzip`方法，而无需复制`find_replace`方法。

+   分区：外部类可以创建此类的实例，并在不必`zip`内容的情况下直接在某个文件夹上调用`find_replace`方法。

委托方法是以下代码中的第一个；其余方法包括在内是为了完整性：

```py
    def unzip_files(self):
        self.temp_directory.mkdir()
        with zipfile.ZipFile(self.filename) as zip:
            zip.extractall(self.temp_directory)

    def find_replace(self):
        for filename in self.temp_directory.iterdir():
            with filename.open() as file:
                contents = file.read()
            contents = contents.replace(self.search_string, self.replace_string)
            with filename.open("w") as file:
                file.write(contents)

    def zip_files(self):
        with zipfile.ZipFile(self.filename, "w") as file:
            for filename in self.temp_directory.iterdir():
                file.write(filename, filename.name)
        shutil.rmtree(self.temp_directory)

if __name__ == "__main__":
    ZipReplace(*sys.argv[1:4]).zip_find_replace()
```

为了简洁起见，对于压缩和解压缩文件的代码文档很少。我们目前关注的是面向对象的设计；如果您对`zipfile`模块的内部细节感兴趣，请参考标准库中的文档，可以在线查看，也可以在交互式解释器中输入`import zipfile ; help(zipfile)`。请注意，此玩具示例仅搜索 ZIP 文件中的顶层文件；如果解压后的内容中有任何文件夹，它们将不会被扫描，也不会扫描这些文件夹中的任何文件。

如果您使用的是早于 3.6 的 Python 版本，则需要在调用`ZipFile`对象上的`extractall`、`rmtree`和`file.write`之前将路径对象转换为字符串。

示例中的最后两行允许我们通过传递`zip`文件名、搜索字符串和替换字符串作为参数来从命令行运行程序，如下所示：

```py
$python zipsearch.py hello.zip hello hi  
```

当然，这个对象不一定要从命令行创建；它可以从另一个模块导入（执行批量 ZIP 文件处理），或者作为 GUI 界面的一部分访问，甚至作为一个更高级别的管理对象的一部分，该对象知道从哪里获取 ZIP 文件（例如，从 FTP 服务器检索它们或将它们备份到外部磁盘）。

随着程序变得越来越复杂，被建模的对象变得越来越不像物理对象。属性是其他抽象对象，方法是改变这些抽象对象状态的行为。但无论多么复杂，每个对象的核心都是一组具体数据和明确定义的行为。

# 删除重复的代码

通常，诸如`ZipReplace`之类的管理样式类中的代码非常通用，可以以各种方式应用。可以使用组合或继承来帮助将此代码放在一个地方，从而消除重复代码。在我们查看任何此类示例之前，让我们讨论一点理论。具体来说，为什么重复代码是一件坏事？

有几个原因，但归根结底都是可读性和可维护性。当我们编写类似于早期代码的新代码时，最容易的方法是复制旧代码并更改需要更改的内容（变量名称、逻辑、注释），使其在新位置上运行。或者，如果我们正在编写似乎类似但不完全相同的新代码，与项目中的其他代码相比，通常更容易编写具有类似行为的新代码，而不是弄清楚如何提取重叠功能。

但是，一旦有人阅读和理解代码，并且遇到重复的代码块，他们就面临着两难境地。可能看起来有意义的代码突然必须被理解。一个部分与另一个部分有何不同？它们如何相同？在什么条件下调用一个部分？我们什么时候调用另一个部分？你可能会争辩说你是唯一阅读你的代码的人，但是如果你八个月不碰那段代码，它对你来说将和对一个新手编程人员一样难以理解。当我们试图阅读两个相似的代码部分时，我们必须理解它们为何不同，以及它们如何不同。这浪费了读者的时间；代码应始终被编写为首要可读性。

我曾经不得不尝试理解某人的代码，其中有三个完全相同的 300 行非常糟糕的代码副本。在我最终理解这三个*相同*版本实际上执行略有不同的税收计算之前，我已经与这段代码一起工作了一个月。一些微妙的差异是有意的，但也有明显的地方，某人在一个函数中更新了一个计算，而没有更新其他两个。代码中难以理解的微妙错误数量不计其数。最终，我用一个大约 20 行的易于阅读的函数替换了所有 900 行。

阅读这样的重复代码可能很烦人，但代码维护更加痛苦。正如前面的故事所示，保持两个相似的代码部分最新可能是一场噩梦。每当我们更新其中一个部分时，我们必须记住更新两个部分，并且我们必须记住多个部分的不同之处，以便在编辑每个部分时修改我们的更改。如果我们忘记更新所有部分，我们最终会遇到非常恼人的错误，通常表现为“但我已经修复了，为什么还在发生*？”

结果是，阅读或维护我们的代码的人们必须花费天文数字的时间来理解和测试它，而不是在第一次编写时以非重复的方式编写它所需的时间。当我们自己进行维护时，这更加令人沮丧；我们会发现自己说，“为什么我第一次就没做对呢？”通过复制和粘贴现有代码节省的时间在第一次进行维护时就丢失了。代码被阅读和修改的次数比编写的次数多得多，而且频率也更高。可理解的代码应始终是优先考虑的。

这就是为什么程序员，尤其是 Python 程序员（他们倾向于比普通开发人员更重视优雅的代码），遵循所谓的**不要重复自己**（**DRY**）原则。DRY 代码是可维护的代码。我给初学者的建议是永远不要使用编辑器的复制粘贴功能。对于中级程序员，我建议他们在按下*Ctrl* + *C*之前三思。

但是，我们应该怎么做才能避免代码重复呢？最简单的解决方案通常是将代码移到一个函数中，该函数接受参数以解决不同的部分。这不是一个非常面向对象的解决方案，但通常是最佳的解决方案。

例如，如果我们有两段代码，它们将 ZIP 文件解压缩到两个不同的目录中，我们可以很容易地用一个接受目录参数的函数来替换它。这可能会使函数本身稍微难以阅读，但一个好的函数名称和文档字符串很容易弥补这一点，任何调用该函数的代码都会更容易阅读。

这就足够的理论了！故事的寓意是：始终努力重构代码，使其更易读，而不是编写可能看起来更容易的糟糕代码。

# 在实践中

让我们探讨两种重用现有代码的方法。在编写代码以替换 ZIP 文件中的文本文件中的字符串后，我们后来受托将 ZIP 文件中的所有图像缩放到 640 x 480。看起来我们可以使用与我们在`ZipReplace`中使用的非常相似的范例。我们的第一反应可能是保存该文件的副本，并将`find_replace`方法更改为`scale_image`或类似的内容。

但是，这是次优的。如果有一天我们想要更改`unzip`和`zip`方法以打开 TAR 文件呢？或者也许我们想要为临时文件使用一个保证唯一的目录名称。在任何一种情况下，我们都必须在两个不同的地方进行更改！

我们将从展示基于继承的解决方案开始解决这个问题。首先，我们将修改我们原始的`ZipReplace`类，将其变成一个用于处理通用 ZIP 文件的超类：

```py
import sys
import shutil
import zipfile
from pathlib import Path

class ZipProcessor:
    def __init__(self, zipname):
        self.zipname = zipname
        self.temp_directory = Path(f"unzipped-{zipname[:-4]}")

    def process_zip(self):
        self.unzip_files()
        self.process_files()
        self.zip_files()

    def unzip_files(self):
        self.temp_directory.mkdir()
        with zipfile.ZipFile(self.zipname) as zip:
            zip.extractall(self.temp_directory)

    def zip_files(self):
        with zipfile.ZipFile(self.zipname, "w") as file:
            for filename in self.temp_directory.iterdir():
                file.write(filename, filename.name)
        shutil.rmtree(self.temp_directory)
```

我们将`filename`属性更改为`zipname`，以避免与各种方法内部的`filename`本地变量混淆。这有助于使代码更易读，尽管实际上并没有改变设计。

我们还删除了`__init__`中的两个参数（`search_string`和`replace_string`），这些参数是特定于`ZipReplace`的。然后，我们将`zip_find_replace`方法重命名为`process_zip`，并让它调用一个（尚未定义的）`process_files`方法，而不是`find_replace`；这些名称更改有助于展示我们新类的更一般化特性。请注意，我们已经完全删除了`find_replace`方法；该代码是特定于`ZipReplace`，在这里没有业务。

这个新的`ZipProcessor`类实际上并没有定义`process_files`方法。如果我们直接运行它，它会引发异常。因为它不是用来直接运行的，我们删除了原始脚本底部的主要调用。我们可以将其作为抽象基类，以便传达这个方法需要在子类中定义，但出于简洁起见，我将其省略了。

现在，在我们转向图像处理应用程序之前，让我们修复我们原始的`zipsearch`类，以利用这个父类，如下所示：

```py
class ZipReplace(ZipProcessor):
    def __init__(self, filename, search_string, replace_string):
        super().__init__(filename)
        self.search_string = search_string
        self.replace_string = replace_string

    def process_files(self):
        """perform a search and replace on all files in the
        temporary directory"""
        for filename in self.temp_directory.iterdir():
            with filename.open() as file:
                contents = file.read()
            contents = contents.replace(self.search_string, self.replace_string)
            with filename.open("w") as file:
                file.write(contents)
```

这段代码比原始版本要短，因为它继承了父类的 ZIP 处理能力。我们首先导入我们刚刚编写的基类，并使`ZipReplace`扩展该类。然后，我们使用`super()`来初始化父类。`find_replace`方法仍然存在，但我们将其重命名为`process_files`，以便父类可以从其管理界面调用它。因为这个名称不像旧名称那样描述性强，我们添加了一个文档字符串来描述它正在做什么。

现在，考虑到我们现在所做的工作量相当大，而我们现在的程序在功能上与我们开始的程序并无不同！但是经过这样的工作，我们现在可以更容易地编写其他操作 ZIP 存档文件的类，比如（假设请求的）照片缩放器。此外，如果我们想要改进或修复 ZIP 功能，我们只需更改一个`ZipProcessor`基类，就可以同时为所有子类进行操作。因此维护工作将更加有效。

看看现在创建一个利用`ZipProcessor`功能的照片缩放类有多简单：

```py
from PIL import Image 

class ScaleZip(ZipProcessor): 

    def process_files(self): 
        '''Scale each image in the directory to 640x480''' 
        for filename in self.temp_directory.iterdir(): 
            im = Image.open(str(filename)) 
            scaled = im.resize((640, 480)) 
            scaled.save(filename)

if __name__ == "__main__": 
    ScaleZip(*sys.argv[1:4]).process_zip() 
```

看看这个类有多简单！我们之前所做的所有工作都得到了回报。我们所做的就是打开每个文件（假设它是一个图像；如果文件无法打开或不是图像，程序将崩溃），对其进行缩放，然后保存。`ZipProcessor`类负责压缩和解压，而我们无需额外工作。

# 案例研究

对于这个案例研究，我们将尝试进一步探讨一个问题，即何时应该选择对象而不是内置类型？我们将建模一个可能在文本编辑器或文字处理器中使用的`Document`类。它应该具有哪些对象、函数或属性？

我们可能会从`Document`内容开始使用`str`，但在 Python 中，字符串是不可变的。一旦定义了一个`str`，它就永远存在。我们无法在其中插入字符或删除字符，而不创建全新的字符串对象。这将导致大量的`str`对象占用内存，直到 Python 的垃圾收集器决定清理它们。

因此，我们将使用字符列表而不是字符串，这样我们可以随意修改。此外，我们需要知道列表中的当前光标位置，并且可能还需要存储文档的文件名。

真正的文本编辑器使用一种名为`rope`的基于二叉树的数据结构来模拟其文档内容。本书的标题不是*高级数据结构*，所以如果你对这个迷人的主题感兴趣，你可能想在网上搜索*rope 数据结构*了解更多信息。

我们可能想对文本文档进行许多操作，包括插入、删除和选择字符；剪切、复制和粘贴所选内容；以及保存或关闭文档。看起来有大量的数据和行为，因此将所有这些内容放入自己的`Document`类是有道理的。

一个相关的问题是：这个类应该由一堆基本的 Python 对象组成，比如`str`文件名、`int`光标位置和字符的`list`？还是应该将其中一些或全部内容定义为自己的特定对象？单独的行和字符呢？它们需要有自己的类吗？

我们将在进行过程中回答这些问题，但让我们先从最简单的`Document`类开始，看看它能做什么：

```py
class Document: 
    def __init__(self): 
        self.characters = [] 
        self.cursor = 0 
        self.filename = '' 

    def insert(self, character): 
        self.characters.insert(self.cursor, character) 
        self.cursor += 1 

    def delete(self): 
        del self.characters[self.cursor] 

    def save(self): 
        with open(self.filename, 'w') as f: 
            f.write(''.join(self.characters)) 

    def forward(self): 
        self.cursor += 1 

    def back(self): 
        self.cursor -= 1 
```

这个基本类允许我们完全控制编辑基本文档。看看它的运行情况：

```py
>>> doc = Document()
>>> doc.filename = "test_document"
>>> doc.insert('h')
>>> doc.insert('e')
>>> doc.insert('l')
>>> doc.insert('l')
>>> doc.insert('o')
>>> "".join(doc.characters)
'hello'
>>> doc.back()
>>> doc.delete()
>>> doc.insert('p')
>>> "".join(doc.characters)
'hellp'  
```

看起来它正在工作。我们可以将键盘的字母和箭头键连接到这些方法，文档将正常跟踪一切。

但是，如果我们想要连接的不仅仅是箭头键。如果我们还想连接*Home*和*End*键怎么办？我们可以向`Document`类添加更多方法，用于在字符串中向前或向后搜索换行符（换行符，转义为`\n`，表示一行的结束和新行的开始），并跳转到它们，但如果我们为每种可能的移动操作（按单词移动，按句子移动，*Page Up*，*Page Down*，行尾，空格开头等）都这样做，那么这个类将会很庞大。也许把这些方法放在一个单独的对象上会更好。因此，让我们将`Cursor`属性转换为一个对象，该对象知道自己的位置并可以操纵该位置。我们可以将向前和向后的方法移到该类中，并为*Home*和*End*键添加另外两个方法，如下所示：

```py
class Cursor:
    def __init__(self, document):
        self.document = document
        self.position = 0

    def forward(self):
        self.position += 1

    def back(self):
        self.position -= 1

    def home(self):
        while self.document.characters[self.position - 1].character != "\n":
            self.position -= 1
            if self.position == 0:
                # Got to beginning of file before newline
                break

    def end(self):
        while (
            self.position < len(self.document.characters)
            and self.document.characters[self.position] != "\n"
        ):
            self.position += 1
```

这个类将文档作为初始化参数，以便方法可以访问文档字符列表的内容。然后提供了向后和向前移动的简单方法，以及移动到`home`和`end`位置的方法。

这段代码并不是很安全。你很容易越过结束位置，如果你试图在空文件上回到开头，它会崩溃。这些示例被保持简短以便阅读，但这并不意味着它们是防御性的！你可以通过练习来改进这段代码的错误检查；这可能是扩展你的异常处理技能的绝佳机会。

`Document`类本身几乎没有改变，只是删除了移动到`Cursor`类的两个方法：

```py
class Document: 
    def __init__(self): 
        self.characters = [] 
        self.cursor = Cursor(self) 
        self.filename = '' 

       def insert(self, character): 
        self.characters.insert(self.cursor.position, 
                character) 
        self.cursor.forward() 

    def delete(self): 
        del self.characters[self.cursor.position] 

    def save(self):
        with open(self.filename, "w") as f:
            f.write("".join(self.characters))
```

我们刚刚更新了访问旧光标整数的任何内容，以使用新对象代替。我们现在可以测试`home`方法是否真的移动到换行符，如下所示：

```py
>>> d = Document()
>>> d.insert('h')
>>> d.insert('e')
>>> d.insert('l')
>>> d.insert('l')
>>> d.insert('o')
>>> d.insert('\n')
>>> d.insert('w')
>>> d.insert('o')
>>> d.insert('r')
>>> d.insert('l')
>>> d.insert('d')
>>> d.cursor.home()
>>> d.insert("*")
>>> print("".join(d.characters))
hello
*world  
```

现在，由于我们一直在大量使用字符串`join`函数（将字符连接起来，以便查看实际文档内容），我们可以向`Document`类添加一个属性，以便得到完整的字符串，如下所示：

```py
@property 
def string(self): 
    return "".join(self.characters) 
```

这使得我们的测试变得更简单：

```py
>>> print(d.string)
hello
world  
```

这个框架很容易扩展，创建和编辑完整的纯文本文档（尽管可能会有点耗时！）现在，让我们将其扩展到适用于富文本的工作；可以具有**粗体**、下划线或*斜体*字符的文本。

我们可以以两种方式处理这个问题。第一种是在字符列表中插入*虚假*字符，这些字符就像指令一样，比如*粗体字符，直到找到停止粗体字符*。第二种是向每个字符添加信息，指示它应该具有什么格式。虽然前一种方法在真实编辑器中更常见，但我们将实现后一种解决方案。为此，我们显然需要一个字符类。这个类将具有表示字符的属性，以及三个布尔属性，表示它是否*粗体、斜体或下划线*。

嗯，等等！这个`Character`类会有任何方法吗？如果没有，也许我们应该使用许多 Python 数据结构之一；元组或命名元组可能就足够了。有没有任何操作我们想要在字符上执行或调用？

嗯，显然，我们可能想对字符进行一些操作，比如删除或复制它们，但这些是需要在`Document`级别处理的事情，因为它们实际上是在修改字符列表。是否有需要对单个字符进行处理的事情？

实际上，现在我们在思考`Character`类实际上**是**什么……它是什么？可以肯定地说`Character`类是一个字符串吗？也许我们应该在这里使用继承关系？然后我们可以利用`str`实例带来的众多方法。

我们在谈论什么样的方法？有`startswith`、`strip`、`find`、`lower`等等。这些方法中的大多数都希望在包含多个字符的字符串上工作。相比之下，如果`Character`是`str`的子类，我们可能最好重写`__init__`，以便在提供多字符字符串时引发异常。由于我们将免费获得的所有这些方法实际上并不适用于我们的`Character`类，因此似乎我们不应该使用继承。

这让我们回到了最初的问题；`Character`甚至应该是一个类吗？`object`类上有一个非常重要的特殊方法，我们可以利用它来表示我们的字符。这个方法叫做`__str__`（两端都有两个下划线，就像`__init__`一样），它在字符串操作函数中被使用，比如`print`和`str`构造函数，将任何类转换为字符串。默认实现做了一些无聊的事情，比如打印模块和类的名称，以及它在内存中的地址。但如果我们重写它，我们可以让它打印任何我们喜欢的东西。

对于我们的实现，我们可以使用特殊字符作为前缀来表示字符是否为粗体、斜体或下划线。因此，我们将创建一个表示字符的类，如下所示：

```py
class Character: 
    def __init__(self, character, 
            bold=False, italic=False, underline=False): 
        assert len(character) == 1 
        self.character = character 
        self.bold = bold 
        self.italic = italic 
        self.underline = underline 

    def __str__(self): 
        bold = "*" if self.bold else '' 
        italic = "/" if self.italic else '' 
        underline = "_" if self.underline else '' 
        return bold + italic + underline + self.character 
```

这个类允许我们创建字符，并在应用`str()`函数时用特殊字符作为前缀。没有太多激动人心的地方。我们只需要对`Document`和`Cursor`类进行一些小修改，以便与这个类一起工作。在`Document`类中，我们在`insert`方法的开头添加以下两行：

```py
def insert(self, character): 
    if not hasattr(character, 'character'): 
        character = Character(character) 
```

这是一段相当奇怪的代码。它的基本目的是检查传入的字符是`Character`还是`str`。如果是字符串，它就会被包装在`Character`类中，以便列表中的所有对象都是`Character`对象。然而，完全有可能有人使用我们的代码想要使用既不是`Character`也不是字符串的类，使用鸭子类型。如果对象有一个字符属性，我们假设它是类似`Character`的对象。但如果没有，我们假设它是类似`str`的对象，并将其包装在`Character`中。这有助于程序利用鸭子类型和多态性；只要对象具有字符属性，它就可以在`Document`类中使用。

这种通用检查可能非常有用。例如，如果我们想要制作一个带有语法高亮的程序员编辑器，我们需要字符的额外数据，比如字符属于哪种类型的语法标记。请注意，如果我们要做很多这种比较，最好实现`Character`作为一个带有适当`__subclasshook__`的抽象基类，如第十七章中讨论的那样，*当对象相似*。

此外，我们需要修改`Document`上的字符串属性，以接受新的`Character`值。我们只需要在连接之前对每个字符调用`str()`，如下所示：

```py
    @property 
    def string(self): 
        return "".join((str(c) for c in self.characters)) 
```

这段代码使用了一个生成器表达式，我们将在第二十一章中讨论，*迭代器模式*。这是一个在序列中对所有对象执行特定操作的快捷方式。

最后，我们还需要检查`home`和`end`函数中的`Character.character`，而不仅仅是我们之前存储的字符串字符，看它是否匹配换行符，如下所示：

```py
    def home(self): 
        while self.document.characters[ 
                self.position-1].character != '\n': 
            self.position -= 1 
            if self.position == 0: 
                # Got to beginning of file before newline 
                break 

    def end(self): 
        while self.position < len( 
                self.document.characters) and \ 
                self.document.characters[ 
                        self.position 
                        ].character != '\n': 
            self.position += 1
```

这完成了字符的格式化。我们可以测试它，看它是否像下面这样工作：

```py
>>> d = Document()
>>> d.insert('h')
>>> d.insert('e')
>>> d.insert(Character('l', bold=True))
>>> d.insert(Character('l', bold=True))
>>> d.insert('o')
>>> d.insert('\n')
>>> d.insert(Character('w', italic=True))
>>> d.insert(Character('o', italic=True))
>>> d.insert(Character('r', underline=True))
>>> d.insert('l')
>>> d.insert('d')
>>> print(d.string)
he*l*lo
/w/o_rld
>>> d.cursor.home()
>>> d.delete()
>>> d.insert('W')
>>> print(d.string)
he*l*lo
W/o_rld
>>> d.characters[0].underline = True
>>> print(d.string)
_he*l*lo
W/o_rld  
```

正如预期的那样，每当我们打印字符串时，每个粗体字符前面都有一个`*`字符，每个斜体字符前面都有一个`/`字符，每个下划线字符前面都有一个`_`字符。我们所有的函数似乎都能工作，并且我们可以在事后修改列表中的字符。我们有一个可以插入到适当的图形用户界面中并与键盘进行输入和屏幕进行输出的工作的富文本文档对象。当然，我们希望在 UI 中显示真正的*粗体、斜体和下划线*字体，而不是使用我们的`__str__`方法，但它对我们要求的基本测试是足够的。

# 练习

我们已经看过了在面向对象的 Python 程序中对象、数据和方法可以相互交互的各种方式。和往常一样，您的第一个想法应该是如何将这些原则应用到您自己的工作中。您是否有一些混乱的脚本横七竖八地散落在那里，可以使用面向对象的管理器进行重写？浏览一下您的旧代码，寻找一些不是动作的方法。如果名称不是动词，尝试将其重写为属性。

思考您用任何语言编写的代码。它是否违反了 DRY 原则？是否有任何重复的代码？您是否复制和粘贴了代码？您是否编写了两个类似代码的版本，因为您不想理解原始代码？现在回顾一下您最近的一些代码，看看是否可以使用继承或组合重构重复的代码。尝试选择一个您仍然有兴趣维护的项目；不要选择那些您永远不想再碰的代码。这将有助于在您进行改进时保持您的兴趣！

现在，回顾一下本章中我们看过的一些例子。从使用属性缓存检索数据的缓存网页示例开始。这个示例的一个明显问题是缓存从未被刷新。在属性的 getter 中添加一个超时，并且只有在页面在超时过期之前被请求时才返回缓存的页面。您可以使用`time`模块（`time.time() - an_old_time`返回自`an_old_time`以来经过的秒数）来确定缓存是否已过期。

还要看看基于继承的`ZipProcessor`。在这里使用组合而不是继承可能是合理的。您可以在`ZipProcessor`构造函数中传递这些类的实例，并调用它们来执行处理部分。实现这一点。

您觉得哪个版本更容易使用？哪个更优雅？哪个更容易阅读？这些都是主观问题；答案因人而异。然而，了解答案是重要的。如果您发现自己更喜欢继承而不是组合，那么您需要注意不要在日常编码中过度使用继承。如果您更喜欢组合，请确保不要错过创建优雅的基于继承的解决方案的机会。

最后，在案例研究中为各种类添加一些错误处理程序。它们应确保输入单个字符，不要尝试将光标移动到文件的末尾或开头，不要删除不存在的字符，也不要保存没有文件名的文件。尽量考虑尽可能多的边缘情况，并对其进行考虑（考虑边缘情况大约占专业程序员工作的 90%！）。考虑不同的处理方式；当用户尝试移动到文件末尾时，您应该引发异常，还是只停留在最后一个字符？

在您的日常编码中，注意复制和粘贴命令。每次在编辑器中使用它们时，考虑是否改进程序的组织结构，以便您只有要复制的代码的一个版本。

# 总结

在这一章中，我们专注于识别对象，特别是那些不太明显的对象；管理和控制对象。对象应该既有数据又有行为，但属性可以用来模糊两者之间的区别。 DRY 原则是代码质量的重要指标，继承和组合可以用来减少代码重复。

在下一章中，我们将讨论如何整合 Python 的面向对象和非面向对象的方面。在这个过程中，我们会发现它比起初看起来更加面向对象！


# 第二十章：Python 面向对象的快捷方式

Python 的许多方面看起来更像结构化或函数式编程，而不是面向对象编程。尽管面向对象编程在过去的二十年中是最可见的范式，但旧模型最近又出现了。与 Python 的数据结构一样，这些工具大多是在基础面向对象实现之上的一层语法糖；我们可以将它们看作是建立在（已经抽象化的）面向对象范式之上的进一步抽象层。在本章中，我们将涵盖一些不严格面向对象的 Python 特性：

+   内置函数可以一次性处理常见任务

+   文件 I/O 和上下文管理器

+   方法重载的替代方法

+   函数作为对象

# Python 内置函数

Python 中有许多函数可以在某些类型的对象上执行任务或计算结果，而不是作为基础类的方法。它们通常抽象出适用于多种类型的类的常见计算。这是鸭子类型的最佳体现；这些函数接受具有某些属性或方法的对象，并能够使用这些方法执行通用操作。我们已经使用了许多内置函数，但让我们快速浏览一下重要的函数，并学习一些巧妙的技巧。

# len()函数

最简单的例子是`len()`函数，它计算某种容器对象中的项目数量，比如字典或列表。你之前已经见过它，演示如下：

```py
>>> len([1,2,3,4])
4  
```

你可能会想为什么这些对象没有一个长度属性，而是必须在它们上调用一个函数。从技术上讲，它们是有的。大多数`len()`适用的对象都有一个名为`__len__()`的方法，返回相同的值。所以`len(myobj)`似乎调用了`myobj.__len__()`。

为什么我们应该使用`len()`函数而不是`__len__`方法？显然，`__len__`是一个特殊的双下划线方法，这表明我们不应该直接调用它。这一定有一个解释。Python 开发人员不会轻易做出这样的设计决定。

主要原因是效率。当我们在对象上调用`__len__`时，对象必须在其命名空间中查找该方法，并且如果该对象上定义了特殊的`__getattribute__`方法（每次访问对象的属性或方法时都会调用），它也必须被调用。此外，该方法的`__getattribute__`可能被编写为执行一些不好的操作，比如拒绝让我们访问特殊方法，比如`__len__`！`len()`函数不会遇到这些问题。它实际上调用了基础类的`__len__`函数，所以`len(myobj)`映射到了`MyObj.__len__(myobj)`。

另一个原因是可维护性。将来，Python 开发人员可能希望更改`len()`，以便它可以计算没有`__len__`的对象的长度，例如，通过计算迭代器返回的项目数量。他们只需要更改一个函数，而不是在整个对象中无数的`__len__`方法。

`len()`作为外部函数还有一个极其重要且经常被忽视的原因：向后兼容性。这经常在文章中被引用为*出于历史原因*，这是作者用来表示某事之所以是某种方式是因为很久以前犯了一个错误，我们现在被困在这种方式中的一种委婉的说法。严格来说，`len()`并不是一个错误，而是一个设计决定，但这个决定是在一个不太面向对象的时代做出的。它经受住了时间的考验，并且有一些好处，所以要习惯它。

# 反转

`reversed()`函数接受任何序列作为输入，并返回该序列的一个副本，顺序相反。通常在`for`循环中使用，当我们想要从后向前循环遍历项目时。

与`len`类似，`reversed`在参数的类上调用`__reversed__()`函数。如果该方法不存在，`reversed`将使用对`__len__`和`__getitem__`的调用来构建反转的序列，这些方法用于定义序列。如果我们想要以某种方式自定义或优化过程，我们只需要重写`__reversed__`，就像下面的代码所示：

```py
normal_list = [1, 2, 3, 4, 5]

class CustomSequence:
    def __len__(self):
        return 5

    def __getitem__(self, index):
        return f"x{index}"

class FunkyBackwards:
 def __reversed__(self):
 return "BACKWARDS!"

for seq in normal_list, CustomSequence(), FunkyBackwards():
    print(f"\n{seq.__class__.__name__}: ", end="")
    for item in reversed(seq):
        print(item, end=", ")
```

最后的`for`循环打印了正常列表的反转版本，以及两个自定义序列的实例。输出显示`reversed`适用于它们三个，但当我们自己定义`__reversed__`时，结果却大不相同：

```py
list: 5, 4, 3, 2, 1,
CustomSequence: x4, x3, x2, x1, x0,
FunkyBackwards: B, A, C, K, W, A, R, D, S, !,  
```

当我们反转`CustomSequence`时，`__getitem__`方法会为每个项目调用，它只是在索引之前插入一个`x`。对于`FunkyBackwards`，`__reversed__`方法返回一个字符串，其中每个字符在`for`循环中单独输出。

前面的两个类不是很好的序列，因为它们没有定义一个适当版本的`__iter__`，所以对它们进行正向`for`循环永远不会结束。

# 枚举

有时，当我们在`for`循环中循环遍历容器时，我们希望访问当前正在处理的项目的索引（列表中的当前位置）。`for`循环不提供索引，但`enumerate`函数给了我们更好的东西：它创建了一个元组序列，其中每个元组中的第一个对象是索引，第二个对象是原始项目。

如果我们需要直接使用索引号，这是很有用的。考虑一些简单的代码，输出文件中的每一行及其行号：

```py
import sys

filename = sys.argv[1]

with open(filename) as file:
 for index, line in enumerate(file):
        print(f"{index+1}: {line}", end="")
```

使用自己的文件名作为输入文件运行此代码，可以显示它是如何工作的：

```py
1: import sys
2:
3: filename = sys.argv[1]
4:
5: with open(filename) as file:
6:     for index, line in enumerate(file):
7:         print(f"{index+1}: {line}", end="")
```

`enumerate`函数返回一个元组序列，我们的`for`循环将每个元组拆分为两个值，并且`print`语句将它们格式化在一起。对于每行号，它会将索引加一，因为`enumerate`，像所有序列一样，是从零开始的。

我们只是涉及了一些更重要的 Python 内置函数。正如你所看到的，其中许多调用面向对象的概念，而其他一些则遵循纯函数式或过程式范例。标准库中还有许多其他函数；一些更有趣的包括以下内容：

+   `all`和`any`，它们接受一个可迭代对象，并在所有或任何项目评估为 true 时返回`True`（例如非空字符串或列表，非零数，不是`None`的对象，或文字`True`）。

+   `eval`、`exec`和`compile`，它们将字符串作为代码在解释器中执行。对于这些要小心；它们不安全，所以不要执行未知用户提供给你的代码（一般来说，假设所有未知用户都是恶意的、愚蠢的，或两者兼有）。

+   `hasattr`、`getattr`、`setattr`和`delattr`，它们允许通过它们的字符串名称操作对象的属性。

+   `zip`接受两个或多个序列，并返回一个新的元组序列，其中每个元组包含来自每个序列的单个值。

+   还有更多！查看`dir(__builtins__)`中列出的每个函数的解释器帮助文档。

# 文件 I/O

到目前为止，我们的示例都是在文件系统上操作文本文件，而没有考虑底层发生了什么。然而，操作系统实际上将文件表示为一系列字节，而不是文本。从文件中读取文本数据是一个相当复杂的过程。Python，特别是 Python 3，在幕后为我们处理了大部分工作。我们真是幸运！

文件的概念早在有人创造术语“面向对象编程”之前就已经存在。然而，Python 已经将操作系统提供的接口包装成一个甜蜜的抽象，使我们能够使用文件（或类似文件，即鸭子类型）对象。

`open()`内置函数用于打开文件并返回文件对象。要从文件中读取文本，我们只需要将文件名传递给函数。文件将被打开以进行读取，并且字节将使用平台默认编码转换为文本。

当然，我们并不总是想要读取文件；通常我们想要向其中写入数据！要打开文件进行写入，我们需要将`mode`参数作为第二个位置参数传递，并将其值设置为`"w"`：

```py
contents = "Some file contents" 
file = open("filename", "w") 
file.write(contents) 
file.close() 
```

我们还可以将值`"a"`作为模式参数提供，以便将其附加到文件的末尾，而不是完全覆盖现有文件内容。

这些具有内置包装器以将字节转换为文本的文件非常好，但是如果我们要打开的文件是图像、可执行文件或其他二进制文件，那将非常不方便，不是吗？

要打开二进制文件，我们修改模式字符串以附加`'b'`。因此，`'wb'`将打开一个用于写入字节的文件，而`'rb'`允许我们读取它们。它们将像文本文件一样运行，但不会自动将文本编码为字节。当我们读取这样的文件时，它将返回`bytes`对象而不是`str`，当我们向其写入时，如果尝试传递文本对象，它将失败。

这些用于控制文件打开方式的模式字符串相当神秘，既不符合 Python 的风格，也不是面向对象的。但是，它们与几乎所有其他编程语言一致。文件 I/O 是操作系统必须处理的基本工作之一，所有编程语言都必须使用相同的系统调用与操作系统进行通信。只要 Python 返回一个带有有用方法的文件对象，而不是大多数主要操作系统用于标识文件句柄的整数，就应该感到高兴！

一旦文件被打开以进行读取，我们就可以调用`read`、`readline`或`readlines`方法来获取文件的内容。`read`方法返回文件的整个内容作为`str`或`bytes`对象，具体取决于模式中是否有`'b'`。不要在大文件上不带参数地使用此方法。您不希望知道如果尝试将这么多数据加载到内存中会发生什么！

还可以从文件中读取固定数量的字节；我们将整数参数传递给`read`方法，描述我们要读取多少字节。对`read`的下一次调用将加载下一个字节序列，依此类推。我们可以在`while`循环中执行此操作，以以可管理的块读取整个文件。

`readline`方法返回文件中的一行（每行以换行符、回车符或两者结尾，具体取决于创建文件的操作系统）。我们可以重复调用它以获取其他行。复数`readlines`方法返回文件中所有行的列表。与`read`方法一样，它不适用于非常大的文件。这两种方法甚至在文件以`bytes`模式打开时也可以使用，但只有在解析具有合理位置的换行符的文本数据时才有意义。例如，图像或音频文件不会包含换行符（除非换行符字节恰好表示某个像素或声音），因此应用`readline`是没有意义的。

为了可读性，并且避免一次将大文件读入内存，通常最好直接在文件对象上使用`for`循环。对于文本文件，它将一次读取每一行，我们可以在循环体内处理它。对于二进制文件，最好使用`read()`方法读取固定大小的数据块，传递一个参数以读取的最大字节数。

写入文件同样简单；文件对象上的`write`方法将一个字符串（或字节，用于二进制数据）对象写入文件。可以重复调用它来写入多个字符串，一个接着一个。`writelines`方法接受一个字符串序列，并将迭代的每个值写入文件。`writelines`方法在序列中的每个项目后面*不*添加新行。它基本上是一个命名不当的便利函数，用于写入字符串序列的内容，而无需使用`for`循环显式迭代它。

最后，我是指最后，我们来到`close`方法。当我们完成读取或写入文件时，应调用此方法，以确保任何缓冲写入都写入磁盘，文件已经得到适当清理，并且与文件关联的所有资源都已释放回操作系统。从技术上讲，当脚本退出时，这将自动发生，但最好是明确地清理自己，特别是在长时间运行的进程中。

# 放在上下文中

当我们完成文件时需要关闭文件，这可能会使我们的代码变得非常丑陋。因为在文件 I/O 期间可能会发生异常，我们应该将对文件的所有调用都包装在`try`...`finally`子句中。文件应该在`finally`子句中关闭，无论 I/O 是否成功。这并不是很 Pythonic。当然，有一种更优雅的方法来做。

如果我们在类似文件的对象上运行`dir`，我们会发现它有两个名为`__enter__`和`__exit__`的特殊方法。这些方法将文件对象转换为所谓的**上下文管理器**。基本上，如果我们使用一个称为`with`语句的特殊语法，这些方法将在嵌套代码执行之前和之后被调用。对于文件对象，`__exit__`方法确保文件被关闭，即使发生异常。我们不再需要显式地管理文件的关闭。下面是`with`语句在实践中的样子：

```py
with open('filename') as file: 
    for line in file: 
        print(line, end='') 
```

`open`调用返回一个文件对象，该对象具有`__enter__`和`__exit__`方法。返回的对象通过`as`子句分配给名为`file`的变量。我们知道当代码返回到外部缩进级别时，文件将被关闭，即使发生异常也会发生这种情况。

`with`语句在标准库中的几个地方使用，需要执行启动或清理代码。例如，`urlopen`调用返回一个对象，可以在`with`语句中使用，以在完成后清理套接字。线程模块中的锁可以在语句执行后自动释放锁。

最有趣的是，因为`with`语句可以应用于具有适当特殊方法的任何对象，我们可以在自己的框架中使用它。例如，记住字符串是不可变的，但有时需要从多个部分构建字符串。出于效率考虑，通常通过将组件字符串存储在列表中并在最后将它们连接起来来完成。让我们创建一个简单的上下文管理器，允许我们构建一个字符序列，并在退出时自动将其转换为字符串：

```py
class StringJoiner(list): 
 def __enter__(self): 
        return self 

 def __exit__(self, type, value, tb): 
        self.result = "".join(self) 
```

这段代码将`list`类中所需的两个特殊方法添加到它继承的`list`类中。`__enter__`方法执行任何必需的设置代码（在本例中没有），然后返回将分配给`with`语句中`as`后面的变量的对象。通常，就像我们在这里做的那样，这只是上下文管理器对象本身。`__exit__`方法接受三个参数。在正常情况下，它们都被赋予`None`的值。然而，如果`with`块内发生异常，它们将被设置为与异常类型、值和回溯相关的值。这允许`__exit__`方法执行可能需要的任何清理代码，即使发生异常。在我们的例子中，我们采取了不负责任的路径，并通过连接字符串中的字符创建了一个结果字符串，而不管是否抛出异常。

虽然这是我们可以编写的最简单的上下文管理器之一，它的用处是可疑的，但它确实可以与`with`语句一起使用。看看它的运行情况：

```py
import random, string 
with StringJoiner() as joiner: 
    for i in range(15): 
        joiner.append(random.choice(string.ascii_letters)) 

print(joiner.result) 
```

这段代码构造了一个包含 15 个随机字符的字符串。它使用从`list`继承的`append`方法将这些字符附加到`StringJoiner`上。当`with`语句超出范围（回到外部缩进级别）时，将调用`__exit__`方法，并且`joiner`对象上的`result`属性变得可用。然后我们打印这个值来看一个随机字符串。

# 方法重载的替代方法

许多面向对象的编程语言的一个显著特点是一个称为**方法重载**的工具。方法重载简单地指的是具有相同名称的多个方法，这些方法接受不同的参数集。在静态类型的语言中，如果我们想要一个方法既可以接受整数也可以接受字符串，这是很有用的。在非面向对象的语言中，我们可能需要两个函数，称为`add_s`和`add_i`，来适应这种情况。在静态类型的面向对象语言中，我们需要两个方法，都称为`add`，一个接受字符串，一个接受整数。

在 Python 中，我们已经看到我们只需要一个方法，它接受任何类型的对象。它可能需要对对象类型进行一些测试（例如，如果它是一个字符串，将其转换为整数），但只需要一个方法。

然而，方法重载在我们希望一个方法接受不同数量或一组不同的参数时也很有用。例如，电子邮件消息方法可能有两个版本，其中一个接受*from*电子邮件地址的参数。另一个方法可能会查找默认的*from*电子邮件地址。Python 不允许使用相同名称的多个方法，但它提供了一个不同的、同样灵活的接口。

我们已经在之前的例子中看到了向方法和函数传递参数的一些可能方式，但现在我们将涵盖所有细节。最简单的函数不接受任何参数。我们可能不需要一个例子，但为了完整起见，这里有一个：

```py
def no_args(): 
    pass 
```

这就是它的名字：

```py
no_args() 
```

接受参数的函数将在逗号分隔的列表中提供这些参数的名称。只需要提供每个参数的名称。

在调用函数时，这些位置参数必须按顺序指定，不能遗漏或跳过任何一个。这是我们在之前的例子中指定参数的最常见方式：

```py
def mandatory_args(x, y, z): 
    pass 
```

要调用它，输入以下内容：

```py
mandatory_args("a string", a_variable, 5) 
```

任何类型的对象都可以作为参数传递：对象、容器、原始类型，甚至函数和类。前面的调用显示了一个硬编码的字符串、一个未知的变量和一个整数传递到函数中。

# 默认参数

如果我们想要使一个参数变为可选的，而不是创建一个带有不同参数集的第二个方法，我们可以在单个方法中指定一个默认值，使用等号。如果调用代码没有提供这个参数，它将被分配一个默认值。但是，调用代码仍然可以选择通过传递不同的值来覆盖默认值。通常，`None`、空字符串或空列表是合适的默认值。

以下是带有默认参数的函数定义：

```py
def default_arguments(x, y, z, a="Some String", b=False): 
    pass 
```

前三个参数仍然是必需的，并且必须由调用代码传递。最后两个参数有默认参数。

我们可以以多种方式调用这个函数。我们可以按顺序提供所有参数，就好像所有参数都是位置参数一样，如下所示：

```py
default_arguments("a string", variable, 8, "", True) 
```

或者，我们可以按顺序只提供必需的参数，将关键字参数分配为它们的默认值：

```py
default_arguments("a longer string", some_variable, 14) 
```

我们还可以在调用函数时使用等号语法，以不同的顺序提供值，或者跳过我们不感兴趣的默认值。例如，我们可以跳过第一个关键字参数并提供第二个参数：

```py
default_arguments("a string", variable, 14, b=True) 
```

令人惊讶的是，我们甚至可以使用等号语法来改变位置参数的顺序，只要所有参数都被提供：

```py
>>> default_arguments(y=1,z=2,x=3,a="hi")
3 1 2 hi False  
```

偶尔你可能会发现创建一个*仅限关键字*参数很有用，也就是说，必须作为关键字参数提供的参数。你可以通过在关键字参数前面加上`*`来实现这一点：

```py
def kw_only(x, y='defaultkw', *, a, b='only'):
    print(x, y, a, b)
```

这个函数有一个位置参数`x`，和三个关键字参数`y`、`a`和`b`。`x`和`y`都是必需的，但是`a`只能作为关键字参数传递。`y`和`b`都是可选的，默认值是，但是如果提供了`b`，它只能作为关键字参数。

如果你不传递`a`，这个函数会失败：

```py
>>> kw_only('x')
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
TypeError: kw_only() missing 1 required keyword-only argument: 'a'
```

如果你将`a`作为位置参数传递，也会失败：

```py
>>> kw_only('x', 'y', 'a')
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
TypeError: kw_only() takes from 1 to 2 positional arguments but 3 were given
```

但是你可以将`a`和`b`作为关键字参数传递：

```py
>>> kw_only('x', a='a', b='b')
x defaultkw a b
```

有这么多的选项，可能很难选择一个，但是如果你把位置参数看作是一个有序列表，关键字参数看作是一种字典，你会发现正确的布局往往会自然而然地形成。如果你需要要求调用者指定一个参数，那就把它设为必需的；如果有一个合理的默认值，那就把它设为关键字参数。根据需要提供哪些值，以及哪些可以保持默认值，选择如何调用方法通常会自行解决。关键字参数相对较少见，但是当使用情况出现时，它们可以使 API 更加优雅。

需要注意的一点是，关键字参数的默认值是在函数首次解释时进行评估的，而不是在调用时进行的。这意味着我们不能有动态生成的默认值。例如，以下代码的行为不会完全符合预期：

```py
number = 5 
def funky_function(number=number): 
    print(number) 

number=6 
funky_function(8) 
funky_function() 
print(number) 
```

如果我们运行这段代码，首先输出数字`8`，但是后来对没有参数的调用输出数字`5`。我们已经将变量设置为数字`6`，这可以从输出的最后一行看出，但是当调用函数时，打印出的是数字`5`；默认值是在函数定义时计算的，而不是在调用时。

这在空容器（如列表、集合和字典）中有些棘手。例如，通常会要求调用代码提供一个我们的函数将要操作的列表，但是列表是可选的。我们希望将一个空列表作为默认参数。我们不能这样做；它只会在代码首次构建时创建一个列表，如下所示：

```py
//DON'T DO THIS
>>> def hello(b=[]):
...     b.append('a')
...     print(b)
...
>>> hello()
['a']
>>> hello()
['a', 'a']  
```

哎呀，这不是我们预期的结果！通常的解决方法是将默认值设为`None`，然后在方法内部使用`iargument = argument if argument else []`这种习惯用法。请注意！

# 可变参数列表

仅仅使用默认值并不能让我们获得方法重载的所有灵活优势。使 Python 真正灵活的一件事是能够编写接受任意数量的位置或关键字参数而无需显式命名它们的方法。我们还可以将任意列表和字典传递给这样的函数。

例如，一个接受链接或链接列表并下载网页的函数可以使用这样的可变参数，或**varargs**。我们可以接受任意数量的参数，其中每个参数都是不同的链接，而不是接受一个预期为链接列表的单个值。我们可以通过在函数定义中指定`*`运算符来实现这一点：

```py
def get_pages(*links): 
    for link in links: 
        #download the link with urllib 
        print(link) 
```

`*links`参数表示，“我将接受任意数量的参数，并将它们全部放入一个名为`links`的列表中”。如果我们只提供一个参数，它将是一个只有一个元素的列表；如果我们不提供参数，它将是一个空列表。因此，所有这些函数调用都是有效的：

```py
get_pages() 
get_pages('http://www.archlinux.org') 
get_pages('http://www.archlinux.org', 
        'http://ccphillips.net/') 
```

我们还可以接受任意关键字参数。这些参数以字典的形式传递给函数。它们在函数声明中用两个星号（如`**kwargs`）指定。这个工具通常用于配置设置。下面的类允许我们指定一组具有默认值的选项：

```py
class Options: 
    default_options = { 
            'port': 21, 
            'host': 'localhost', 
            'username': None, 
            'password': None, 
            'debug': False, 
            } 
 def __init__(self, **kwargs): 
        self.options = dict(Options.default_options) 
        self.options.update(kwargs) 

    def __getitem__(self, key): 
        return self.options[key] 
```

这个类中所有有趣的东西都发生在`__init__`方法中。我们在类级别有一个默认选项和值的字典。`__init__`方法做的第一件事就是复制这个字典。我们这样做是为了避免直接修改字典，以防我们实例化两组不同的选项。（记住，类级别的变量在类的实例之间是共享的。）然后，`__init__`方法使用新字典上的`update`方法将任何非默认值更改为提供的关键字参数。`__getitem__`方法简单地允许我们使用索引语法使用新类。下面是一个演示该类运行情况的会话：

```py
>>> options = Options(username="dusty", password="drowssap",
 debug=True)
>>> options['debug']
True
>>> options['port']
21
>>> options['username']
'dusty'  
```

我们能够使用字典索引语法访问我们的`options`实例，字典中包括默认值和我们使用关键字参数设置的值。

关键字参数语法可能是危险的，因为它可能违反“明确胜于隐式”的规则。在前面的例子中，可以向`Options`初始化程序传递任意关键字参数，以表示默认字典中不存在的选项。这可能不是一件坏事，取决于类的目的，但它使得使用该类的人很难发现有哪些有效选项可用。它还使得很容易输入令人困惑的拼写错误（例如*Debug*而不是*debug*），从而添加了两个选项，而本应只有一个选项存在。

当我们需要接受要传递给第二个函数的任意参数时，关键字参数也非常有用，但我们不知道这些参数是什么。我们在第十七章中看到了这一点，*当对象相似*，当我们为多重继承构建支持时。当然，我们可以在一个函数调用中结合使用可变参数和可变关键字参数语法，并且我们也可以使用普通的位置参数和默认参数。下面的例子有些牵强，但演示了这四种类型的作用：

```py
import shutil
import os.path

def augmented_move(
    target_folder, *filenames, verbose=False, **specific
):
    """Move all filenames into the target_folder, allowing
    specific treatment of certain files."""

    def print_verbose(message, filename):
        """print the message only if verbose is enabled"""
        if verbose:
            print(message.format(filename))

    for filename in filenames:
        target_path = os.path.join(target_folder, filename)
        if filename in specific:
            if specific[filename] == "ignore":
                print_verbose("Ignoring {0}", filename)
            elif specific[filename] == "copy":
                print_verbose("Copying {0}", filename)
                shutil.copyfile(filename, target_path)
        else:
            print_verbose("Moving {0}", filename)
            shutil.move(filename, target_path)
```

此示例处理一个任意文件列表。第一个参数是目标文件夹，默认行为是将所有剩余的非关键字参数文件移动到该文件夹中。然后是一个仅限关键字参数`verbose`，它告诉我们是否要打印每个处理的文件的信息。最后，我们可以提供一个包含要对特定文件名执行的操作的字典；默认行为是移动文件，但如果在关键字参数中指定了有效的字符串操作，它可以被忽略或复制。请注意函数参数的排序；首先指定位置参数，然后是`*filenames`列表，然后是任何特定的仅限关键字参数，最后是一个`**specific`字典来保存剩余的关键字参数。

我们创建一个内部辅助函数`print_verbose`，它只在设置了`verbose`键时才打印消息。通过将此功能封装在一个单一位置中，该函数使代码易于阅读。

在常见情况下，假设所涉及的文件存在，可以调用此函数如下：

```py
>>> augmented_move("move_here", "one", "two")  
```

这个命令将文件`one`和`two`移动到`move_here`目录中，假设它们存在（函数中没有错误检查或异常处理，因此如果文件或目标目录不存在，它将失败）。移动将在没有任何输出的情况下发生，因为`verbose`默认为`False`。

如果我们想要看到输出，我们可以使用以下命令调用它：

```py
>>> augmented_move("move_here", "three", verbose=True)
Moving three  
```

这将移动名为`three`的一个文件，并告诉我们它在做什么。请注意，在此示例中不可能将`verbose`指定为位置参数；我们必须传递关键字参数。否则，Python 会认为它是`*filenames`列表中的另一个文件名。

如果我们想要复制或忽略列表中的一些文件，而不是移动它们，我们可以传递额外的关键字参数，如下所示：

```py
>>> augmented_move("move_here", "four", "five", "six",
 four="copy", five="ignore")  
```

这将移动第六个文件并复制第四个文件，但不会显示任何输出，因为我们没有指定`verbose`。当然，我们也可以这样做，关键字参数可以以任何顺序提供，如下所示：

```py
>>> augmented_move("move_here", "seven", "eight", "nine",
 seven="copy", verbose=True, eight="ignore")
Copying seven
Ignoring eight
Moving nine  
```

# 解压参数

还有一个关于可变参数和关键字参数的巧妙技巧。我们在之前的一些示例中使用过它，但现在解释一下也不算晚。给定一个值列表或字典，我们可以将这些值传递到函数中，就好像它们是普通的位置或关键字参数一样。看看这段代码：

```py
def show_args(arg1, arg2, arg3="THREE"): 
    print(arg1, arg2, arg3) 

some_args = range(3) 
more_args = { 
        "arg1": "ONE", 
        "arg2": "TWO"} 

print("Unpacking a sequence:", end=" ") 

show_args(*some_args) 
print("Unpacking a dict:", end=" ") 

show_args(**more_args) 
```

当我们运行它时，它看起来像这样：

```py
Unpacking a sequence: 0 1 2
Unpacking a dict: ONE TWO THREE  
```

该函数接受三个参数，其中一个具有默认值。但是当我们有一个包含三个参数的列表时，我们可以在函数调用内部使用`*`运算符将其解压为三个参数。如果我们有一个参数字典，我们可以使用`**`语法将其解压缩为一组关键字参数。

这在将从用户输入或外部来源（例如互联网页面或文本文件）收集的信息映射到函数或方法调用时最常用。

还记得我们之前的例子吗？它使用文本文件中的标题和行来创建包含联系信息的字典列表。我们可以使用关键字解压缩将这些字典传递给专门构建的`Contact`对象上的`__init__`方法，该对象接受相同的参数集。看看你是否可以调整示例使其正常工作。

这种解压缩语法也可以在函数调用之外的某些领域中使用。`Options`类之前有一个`__init__`方法，看起来像这样：

```py
 def __init__(self, **kwargs):
        self.options = dict(Options.default_options)
        self.options.update(kwargs)
```

更简洁的方法是解压缩这两个字典，如下所示：

```py
    def __init__(self, **kwargs):
        self.options = {**Options.default_options, **kwargs}
```

因为字典按从左到右的顺序解压缩，结果字典将包含所有默认选项，并且任何 kwarg 选项都将替换一些键。以下是一个示例：

```py
>>> x = {'a': 1, 'b': 2}
>>> y = {'b': 11, 'c': 3}
>>> z = {**x, **y}
>>> z
{'a': 1, 'b': 11, 'c': 3}
```

# 函数也是对象

过分强调面向对象原则的编程语言往往不赞成不是方法的函数。在这样的语言中，你应该创建一个对象来包装涉及的单个方法。有许多情况下，我们希望传递一个简单的对象，只需调用它执行一个动作。这在事件驱动编程中最常见，比如图形工具包或异步服务器；我们将在第二十二章 *Python 设计模式 I* 和第二十三章 *Python 设计模式 II* 中看到一些使用它的设计模式。

在 Python 中，我们不需要将这样的方法包装在对象中，因为函数本身就是对象！我们可以在函数上设置属性（尽管这不是常见的活动），并且我们可以传递它们以便在以后的某个日期调用它们。它们甚至有一些可以直接访问的特殊属性。这里是另一个刻意的例子：

```py
def my_function():
    print("The Function Was Called")

my_function.description = "A silly function"

def second_function():
    print("The second was called")

second_function.description = "A sillier function."

def another_function(function):
    print("The description:", end=" ")
    print(function.description)
    print("The name:", end=" ")
    print(function.__name__)
    print("The class:", end=" ")
    print(function.__class__)
    print("Now I'll call the function passed in")
    function()

another_function(my_function)
another_function(second_function)
```

如果我们运行这段代码，我们可以看到我们能够将两个不同的函数传递给我们的第三个函数，并为每个函数获得不同的输出：

```py
The description: A silly function 
The name: my_function 
The class: <class 'function'> 
Now I'll call the function passed in 
The Function Was Called 
The description: A sillier function. 
The name: second_function 
The class: <class 'function'> 
Now I'll call the function passed in 
The second was called 
```

我们在函数上设置了一个属性，名为 `description`（诚然不是很好的描述）。我们还能看到函数的 `__name__` 属性，并访问它的类，证明函数确实是一个带有属性的对象。然后，我们使用可调用语法（括号）调用了函数。

函数是顶级对象的事实最常用于传递它们以便在以后的某个日期执行，例如，当某个条件已满足时。让我们构建一个事件驱动的定时器，就是这样做的：

```py
import datetime
import time

class TimedEvent:
    def __init__(self, endtime, callback):
        self.endtime = endtime
 self.callback = callback

    def ready(self):
        return self.endtime <= datetime.datetime.now()

class Timer:
    def __init__(self):
        self.events = []

    def call_after(self, delay, callback):
        end_time = datetime.datetime.now() + datetime.timedelta(
            seconds=delay
        )

        self.events.append(TimedEvent(end_time, callback))

    def run(self):
        while True:
            ready_events = (e for e in self.events if e.ready())
            for event in ready_events:
 event.callback(self)
                self.events.remove(event)
            time.sleep(0.5)
```

在生产中，这段代码肯定应该使用文档字符串进行额外的文档化！`call_after` 方法至少应该提到 `delay` 参数是以秒为单位的，并且 `callback` 函数应该接受一个参数：调用者定时器。

我们这里有两个类。`TimedEvent` 类实际上并不是其他类可以访问的；它只是存储 `endtime` 和 `callback`。我们甚至可以在这里使用 `tuple` 或 `namedtuple`，但是为了方便给对象一个行为，告诉我们事件是否准备好运行，我们使用了一个类。

`Timer` 类简单地存储了一个即将到来的事件列表。它有一个 `call_after` 方法来添加一个新事件。这个方法接受一个 `delay` 参数，表示在执行回调之前等待的秒数，以及 `callback` 函数本身：在正确的时间执行的函数。这个 `callback` 函数应该接受一个参数。

`run` 方法非常简单；它使用生成器表达式来过滤出任何时间到达的事件，并按顺序执行它们。*定时器* 循环然后无限继续，因此必须使用键盘中断（*Ctrl* + *C*，或 *Ctrl* + *Break*）来中断。我们在每次迭代后睡眠半秒，以免使系统停滞。

这里需要注意的重要事情是涉及回调函数的行。函数像任何其他对象一样被传递，定时器从不知道或关心函数的原始名称是什么，或者它是在哪里定义的。当该函数被调用时，定时器只是将括号语法应用于存储的变量。

这是一组测试定时器的回调：

```py
def format_time(message, *args):
    now = datetime.datetime.now()
    print(f"{now:%I:%M:%S}: {message}")

def one(timer):
    format_time("Called One")

def two(timer):
    format_time("Called Two")

def three(timer):
    format_time("Called Three")

class Repeater:
    def __init__(self):
        self.count = 0

    def repeater(self, timer):
        format_time(f"repeat {self.count}")
        self.count += 1
        timer.call_after(5, self.repeater)

timer = Timer()
timer.call_after(1, one)
timer.call_after(2, one)
timer.call_after(2, two)
timer.call_after(4, two)
timer.call_after(3, three)
timer.call_after(6, three)
repeater = Repeater()
timer.call_after(5, repeater.repeater)
format_time("Starting")
timer.run()
```

这个例子让我们看到多个回调是如何与定时器交互的。第一个函数是 `format_time` 函数。它使用格式字符串语法将当前时间添加到消息中；我们将在下一章中了解它们。接下来，我们创建了三个简单的回调方法，它们只是输出当前时间和一个简短的消息，告诉我们哪个回调已经被触发。

`Repeater`类演示了方法也可以用作回调，因为它们实际上只是绑定到对象的函数。它还展示了回调函数中的`timer`参数为什么有用：我们可以在当前运行的回调内部向计时器添加新的定时事件。然后，我们创建一个计时器，并向其添加几个在不同时间后调用的事件。最后，我们启动计时器；输出显示事件按预期顺序运行：

```py
02:53:35: Starting 
02:53:36: Called One 
02:53:37: Called One 
02:53:37: Called Two 
02:53:38: Called Three 
02:53:39: Called Two 
02:53:40: repeat 0 
02:53:41: Called Three 
02:53:45: repeat 1 
02:53:50: repeat 2 
02:53:55: repeat 3 
02:54:00: repeat 4 
```

Python 3.4 引入了类似于这种通用事件循环架构。

# 使用函数作为属性

函数作为对象的一个有趣效果是它们可以被设置为其他对象的可调用属性。可以向已实例化的对象添加或更改函数，如下所示：

```py
class A: 
    def print(self): 
        print("my class is A") 

def fake_print(): 
    print("my class is not A") 

a = A() 
a.print() 
a.print = fake_print 
a.print() 
```

这段代码创建了一个非常简单的类，其中包含一个不告诉我们任何新信息的`print`方法。然后，我们创建了一个告诉我们一些我们不相信的新函数。

当我们在`A`类的实例上调用`print`时，它的行为符合预期。如果我们将`print`方法指向一个新函数，它会告诉我们一些不同的东西：

```py
my class is A 
my class is not A 
```

还可以替换类的方法而不是对象的方法，尽管在这种情况下，我们必须将`self`参数添加到参数列表中。这将更改该对象的所有实例的方法，即使已经实例化了。显然，这样替换方法可能既危险又令人困惑。阅读代码的人会看到已调用一个方法，并查找原始类上的该方法。但原始类上的方法并不是被调用的方法。弄清楚到底发生了什么可能会变成一个棘手而令人沮丧的调试过程。

尽管如此，它确实有其用途。通常，在运行时替换或添加方法（称为**monkey patching**）在自动化测试中使用。如果测试客户端-服务器应用程序，我们可能不希望在测试客户端时实际连接到服务器；这可能导致意外转账或向真实人发送尴尬的测试电子邮件。相反，我们可以设置我们的测试代码，以替换发送请求到服务器的对象上的一些关键方法，以便它只记录已调用这些方法。

Monkey-patching 也可以用于修复我们正在交互的第三方代码中的错误或添加功能，并且不会以我们需要的方式运行。但是，应该谨慎使用；它几乎总是一个*混乱的黑客*。不过，有时它是适应现有库以满足我们需求的唯一方法。

# 可调用对象

正如函数是可以在其上设置属性的对象一样，也可以创建一个可以像函数一样被调用的对象。

通过简单地给它一个接受所需参数的`__call__`方法，任何对象都可以被调用。让我们通过以下方式使我们的计时器示例中的`Repeater`类更易于使用：

```py
class Repeater: 
    def __init__(self): 
        self.count = 0 

 def __call__(self, timer): 
        format_time(f"repeat {self.count}") 
        self.count += 1 

        timer.call_after(5, self) 

timer = Timer() 

timer.call_after(5, Repeater()) 
format_time("{now}: Starting") 
timer.run() 
```

这个例子与之前的类并没有太大不同；我们只是将`repeater`函数的名称更改为`__call__`，并将对象本身作为可调用对象传递。请注意，当我们进行`call_after`调用时，我们传递了参数`Repeater()`。这两个括号创建了一个类的新实例；它们并没有显式调用该类。这发生在稍后，在计时器内部。如果我们想要在新实例化的对象上执行`__call__`方法，我们将使用一个相当奇怪的语法：`Repeater()()`。第一组括号构造对象；第二组执行`__call__`方法。如果我们发现自己这样做，可能没有使用正确的抽象。只有在对象需要被视为函数时才实现`__call__`函数。

# 案例研究

为了将本章介绍的一些原则联系起来，让我们构建一个邮件列表管理器。该管理器将跟踪分类为命名组的电子邮件地址。当发送消息时，我们可以选择一个组，并将消息发送到分配给该组的所有电子邮件地址。

在我们开始这个项目之前，我们应该有一个安全的方法来测试它，而不是向一群真实的人发送电子邮件。幸运的是，Python 在这方面有所帮助；就像测试 HTTP 服务器一样，它有一个内置的**简单邮件传输协议**（**SMTP**）服务器，我们可以指示它捕获我们发送的任何消息，而不实际发送它们。我们可以使用以下命令运行服务器：

```py
$python -m smtpd -n -c DebuggingServer localhost:1025  
```

在命令提示符下运行此命令将在本地机器上的端口 1025 上启动运行 SMTP 服务器。但我们已经指示它使用`DebuggingServer`类（这个类是内置 SMTP 模块的一部分），它不是将邮件发送给预期的收件人，而是在接收到邮件时简单地在终端屏幕上打印它们。

现在，在编写我们的邮件列表之前，让我们编写一些实际发送邮件的代码。当然，Python 也支持这一点在标准库中，但它的接口有点奇怪，所以我们将编写一个新的函数来清晰地包装它，如下面的代码片段所示：

```py
import smtplib
from email.mime.text import MIMEText

def send_email(
    subject,
    message,
    from_addr,
    *to_addrs,
    host="localhost",
    port=1025,
    **headers
):

    email = MIMEText(message)
    email["Subject"] = subject
    email["From"] = from_addr
    for header, value in headers.items():
        email[header] = value

    sender = smtplib.SMTP(host, port)
    for addr in to_addrs:
        del email["To"]
        email["To"] = addr
        sender.sendmail(from_addr, addr, email.as_string())
    sender.quit()
```

我们不会过分深入讨论此方法内部的代码；标准库中的文档可以为您提供使用`smtplib`和`email`模块所需的所有信息。

在函数调用中使用了变量参数和关键字参数语法。变量参数列表允许我们在默认情况下提供单个`to`地址的字符串，并允许在需要时提供多个地址。任何额外的关键字参数都映射到电子邮件标头。这是变量参数和关键字参数的一个令人兴奋的用法，但实际上并不是对调用函数的人来说一个很好的接口。事实上，它使程序员想要做的许多事情都变得不可能。

传递给函数的标头表示可以附加到方法的辅助标头。这些标头可能包括`Reply-To`、`Return-Path`或*X-pretty-much-anything*。但是为了在 Python 中成为有效的标识符，名称不能包括`-`字符。一般来说，该字符表示减法。因此，不可能使用`Reply-To``=``my@email.com`调用函数。通常情况下，我们太急于使用关键字参数，因为它们是我们刚学会的一个闪亮的新工具。

我们将不得不将参数更改为普通字典；这将起作用，因为任何字符串都可以用作字典中的键。默认情况下，我们希望这个字典是空的，但我们不能使默认参数为空字典。因此，我们将默认参数设置为`None`，然后在方法的开头设置字典，如下所示：

```py
def send_email(subject, message, from_addr, *to_addrs, 
        host="localhost", port=1025, headers=None): 

    headers = headers if headers else {}
```

如果我们在一个终端中运行我们的调试 SMTP 服务器，我们可以在 Python 解释器中测试这段代码：

```py
>>> send_email("A model subject", "The message contents",
 "from@example.com", "to1@example.com", "to2@example.com")  
```

然后，如果我们检查调试 SMTP 服务器的输出，我们会得到以下结果：

```py
---------- MESSAGE FOLLOWS ----------
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Subject: A model subject
From: from@example.com
To: to1@example.com
X-Peer: 127.0.0.1

The message contents
------------ END MESSAGE ------------
---------- MESSAGE FOLLOWS ----------
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Subject: A model subject
From: from@example.com
To: to2@example.com
X-Peer: 127.0.0.1

The message contents
------------ END MESSAGE ------------  
```

很好，它已经*发送*了我们的电子邮件到两个预期地址，并包括主题和消息内容。现在我们可以发送消息了，让我们来完善电子邮件组管理系统。我们需要一个对象，以某种方式将电子邮件地址与它们所在的组匹配起来。由于这是多对多的关系（任何一个电子邮件地址可以在多个组中；任何一个组可以与多个电子邮件地址相关联），我们学习过的数据结构似乎都不太理想。我们可以尝试一个将组名与相关电子邮件地址列表匹配的字典，但这样会重复电子邮件地址。我们也可以尝试一个将电子邮件地址与组匹配的字典，这样会重复组。两者都不太理想。出于好玩，让我们尝试后一种版本，尽管直觉告诉我，将组与电子邮件地址的解决方案可能更加直接。

由于字典中的值始终是唯一电子邮件地址的集合，我们可以将它们存储在一个 `set` 容器中。我们可以使用 `defaultdict` 来确保每个键始终有一个 `set` 容器可用，如下所示：

```py
from collections import defaultdict

class MailingList:
    """Manage groups of e-mail addresses for sending e-mails."""

    def __init__(self):
        self.email_map = defaultdict(set)

    def add_to_group(self, email, group):
        self.email_map[email].add(group)
```

现在，让我们添加一个方法，允许我们收集一个或多个组中的所有电子邮件地址。这可以通过将组列表转换为集合来完成：

```py
def emails_in_groups(self, *groups): groups = set(groups) emails = set() for e, g in self.email_map.items(): if g & groups: emails.add(e) return emails 
```

首先，看一下我们正在迭代的内容：`self.email_map.items()`。当然，这个方法返回字典中每个项目的键值对元组。值是表示组的字符串集合。我们将这些拆分成两个变量，命名为 `e` 和 `g`，分别代表电子邮件和组。只有当传入的组与电子邮件地址的组相交时，我们才将电子邮件地址添加到返回值的集合中。`g``&``groups` 语法是 `g.intersection(groups)` 的快捷方式；`set` 类通过实现特殊的 `__and__` 方法来调用 `intersection`。

使用集合推导式可以使这段代码更加简洁，我们将在第二十一章 *迭代器模式* 中讨论。

现在，有了这些基本组件，我们可以轻松地向我们的 `MailingList` 类添加一个发送消息到特定组的方法：

```py
    def send_mailing(
        self, subject, message, from_addr, *groups, headers=None
    ):
        emails = self.emails_in_groups(*groups)
        send_email(
            subject, message, from_addr, *emails, headers=headers
        )
```

这个函数依赖于可变参数列表。作为输入，它接受可变参数作为组的列表。它获取指定组的电子邮件列表，并将它们作为可变参数传递到 `send_email` 中，以及传递到这个方法中的其他参数。

可以通过确保 SMTP 调试服务器在一个命令提示符中运行，并在第二个提示符中使用以下命令加载代码来测试程序：

```py
$python -i mailing_list.py  
```

使用以下命令创建一个 `MailingList` 对象：

```py
>>> m = MailingList()  
```

然后，创建一些虚假的电子邮件地址和组，如下所示：

```py
>>> m.add_to_group("friend1@example.com", "friends")
>>> m.add_to_group("friend2@example.com", "friends")
>>> m.add_to_group("family1@example.com", "family")
>>> m.add_to_group("pro1@example.com", "professional")  
```

最后，使用以下命令发送电子邮件到特定组：

```py
>>> m.send_mailing("A Party",
"Friends and family only: a party", "me@example.com", "friends",
"family", headers={"Reply-To": "me2@example.com"})  
```

指定组中的每个地址的电子邮件应该显示在 SMTP 服务器的控制台上。

邮件列表目前运行良好，但有点无用；一旦我们退出程序，我们的信息数据库就会丢失。让我们修改它，添加一些方法来从文件中加载和保存电子邮件组的列表。

一般来说，当将结构化数据存储在磁盘上时，最好仔细考虑它的存储方式。存在众多数据库系统的原因之一是，如果其他人已经考虑过数据的存储方式，那么你就不必再去考虑。我们将在下一章中研究一些数据序列化机制，但在这个例子中，让我们保持简单，选择可能有效的第一个解决方案。

我心目中的数据格式是存储每个电子邮件地址，后跟一个空格，再跟着一个逗号分隔的组列表。这个格式看起来是合理的，我们将采用它，因为数据格式化不是本章的主题。然而，为了说明为什么你需要认真考虑如何在磁盘上格式化数据，让我们强调一下这种格式的一些问题。

首先，空格字符在技术上是电子邮件地址中合法的。大多数电子邮件提供商禁止它（有充分的理由），但定义电子邮件地址的规范说，如果在引号中，电子邮件可以包含空格。如果我们要在我们的数据格式中使用一个空格作为标记，我们应该在技术上能够区分该空格和电子邮件中的空格。为了简单起见，我们将假装这不是真的，但是现实生活中的数据编码充满了这样的愚蠢问题。

其次，考虑逗号分隔的组列表。如果有人决定在组名中放一个逗号会发生什么？如果我们决定在组名中将逗号设为非法字符，我们应该添加验证来强制在我们的`add_to_group`方法中执行这样的命名。为了教学上的清晰，我们也将忽略这个问题。最后，我们需要考虑许多安全性问题：有人是否可以通过在他们的电子邮件地址中放一个假逗号来将自己放入错误的组？如果解析器遇到无效文件会怎么做？

从这次讨论中得出的要点是，尽量使用经过现场测试的数据存储方法，而不是设计我们自己的数据序列化协议。你可能会忽视很多奇怪的边缘情况，最好使用已经遇到并解决了这些边缘情况的代码。

但是忘了这些。让我们只写一些基本的代码，使用大量的一厢情愿来假装这种简单的数据格式是安全的，如下所示：

```py
email1@mydomain.com group1,group2
email2@mydomain.com group2,group3  
```

执行此操作的代码如下：

```py
    def save(self):
        with open(self.data_file, "w") as file:
            for email, groups in self.email_map.items():
                file.write("{} {}\n".format(email, ",".join(groups)))

    def load(self):
        self.email_map = defaultdict(set)
        with suppress(IOError):
            with open(self.data_file) as file:
                for line in file:
                    email, groups = line.strip().split(" ")
                    groups = set(groups.split(","))
                    self.email_map[email] = groups
```

在`save`方法中，我们在上下文管理器中打开文件并将文件写为格式化字符串。记住换行符；Python 不会为我们添加它。`load`方法首先重置字典（以防它包含来自先前调用`load`的数据）。它添加了对标准库`suppress`上下文管理器的调用，可用作`from contextlib import suppress`。这个上下文管理器捕获任何 I/O 错误并忽略它们。这不是最好的错误处理，但比 try...finally...pass 更美观。

然后，load 方法使用`for`...`in`语法，循环遍历文件中的每一行。同样，换行符包含在行变量中，所以我们必须调用`.strip()`来去掉它。我们将在下一章中学习更多关于这种字符串操作的知识。

在使用这些方法之前，我们需要确保对象有一个`self.data_file`属性，可以通过修改`__init__`来实现：

```py
    def __init__(self, data_file): 
        self.data_file = data_file 
        self.email_map = defaultdict(set) 
```

我们可以在解释器中测试这两种方法：

```py
>>> m = MailingList('addresses.db')
>>> m.add_to_group('friend1@example.com', 'friends')
>>> m.add_to_group('family1@example.com', 'friends')
>>> m.add_to_group('family1@example.com', 'family')
>>> m.save()  
```

生成的`addresses.db`文件包含如下行，如预期的那样：

```py
friend1@example.com friends
family1@example.com friends,family  
```

我们也可以成功地将这些数据加载回`MailingList`对象中：

```py
>>> m = MailingList('addresses.db')
>>> m.email_map
defaultdict(<class 'set'>, {})
>>> m.load()
>>> m.email_map
defaultdict(<class 'set'>, {'friend2@example.com': {'friends\n'}, 
'family1@example.com': {'family\n'}, 'friend1@example.com': {'friends\n'}})  
```

正如你所看到的，我忘记了添加`load`命令，也可能很容易忘记`save`命令。为了让任何想要在自己的代码中使用我们的`MailingList` API 的人更容易一些，让我们提供支持上下文管理器的方法：

```py
    def __enter__(self): 
        self.load() 
        return self 

    def __exit__(self, type, value, tb): 
        self.save() 
```

这些简单的方法只是将它们的工作委托给加载和保存，但是现在我们可以在交互式解释器中编写这样的代码，并知道以前存储的所有地址都已经被加载，当我们完成时整个列表将被保存到文件中：

```py
>>> with MailingList('addresses.db') as ml:
...    ml.add_to_group('friend2@example.com', 'friends')
...    ml.send_mailing("What's up", "hey friends, how's it going", 'me@example.com', 
       'friends')  
```

# 练习

如果你之前没有遇到`with`语句和上下文管理器，我鼓励你像往常一样，浏览你的旧代码，找到所有打开文件的地方，并确保它们使用`with`语句安全关闭。还要寻找编写自己的上下文管理器的地方。丑陋或重复的`try`...`finally`子句是一个很好的起点，但你可能会发现在任何需要在上下文中执行之前和/或之后任务的地方都很有用。

你可能之前已经使用过许多基本的内置函数。我们涵盖了其中几个，但没有详细讨论。尝试使用`enumerate`、`zip`、`reversed`、`any`和`all`，直到你记住在合适的时候使用它们为止。`enumerate`函数尤其重要，因为不使用它会导致一些非常丑陋的`while`循环。

还要探索一些将函数作为可调用对象传递的应用，以及使用`__call__`方法使自己的对象可调用。您可以通过将属性附加到函数或在对象上创建`__call__`方法来实现相同的效果。在哪种情况下会使用一种语法，什么时候更适合使用另一种语法呢？

如果有大量邮件需要发送，我们的邮件列表对象可能会压倒邮件服务器。尝试重构它，以便你可以为不同的目的使用不同的`send_email`函数。其中一个函数可能是我们在这里使用的版本。另一个版本可能会将邮件放入队列，由不同的线程或进程发送。第三个版本可能只是将数据输出到终端，从而避免了需要虚拟的 SMTP 服务器。你能构建一个带有回调的邮件列表，以便`send_mailing`函数使用传入的任何内容吗？如果没有提供回调，它将默认使用当前版本。

参数、关键字参数、可变参数和可变关键字参数之间的关系可能有点令人困惑。当我们涵盖多重继承时，我们看到它们如何痛苦地相互作用。设计一些其他示例，看看它们如何很好地协同工作，以及了解它们何时不起作用。

# 总结

在本章中，我们涵盖了一系列主题。每个主题都代表了 Python 中流行的重要非面向对象的特性。仅仅因为我们可以使用面向对象的原则，并不总是意味着我们应该这样做！

然而，我们也看到 Python 通常通过提供语法快捷方式来实现这些功能，以传统的面向对象语法。了解这些工具背后的面向对象原则使我们能够更有效地在自己的类中使用它们。

我们讨论了一系列内置函数和文件 I/O 操作。在调用带参数、关键字参数和可变参数列表的函数时，我们有许多不同的语法可用。上下文管理器对于在两个方法调用之间夹入一段代码的常见模式非常有用。甚至函数本身也是对象，反之亦然，任何普通对象都可以被调用。

在下一章中，我们将学习更多关于字符串和文件操作的知识，甚至花一些时间来了解标准库中最不面向对象的主题之一：正则表达式。


# 第二十一章：迭代器模式

我们已经讨论了 Python 的许多内置功能和习语，乍一看似乎违反了面向对象的原则，但实际上在幕后提供了对真实对象的访问。在本章中，我们将讨论`for`循环，它似乎如此结构化，实际上是一组面向对象原则的轻量级包装。我们还将看到一系列扩展到这种语法，自动创建更多类型的对象。我们将涵盖以下主题：

+   设计模式是什么

+   迭代器协议-最强大的设计模式之一

+   列表、集合和字典推导

+   生成器和协程

# 简要介绍设计模式

当工程师和建筑师决定建造一座桥、一座塔或一座建筑时，他们遵循某些原则以确保结构完整性。桥梁有各种可能的设计（例如悬索和悬臂），但如果工程师不使用标准设计之一，并且没有一个杰出的新设计，那么他/她设计的桥梁可能会坍塌。

设计模式是试图将同样的正确设计结构的正式定义引入到软件工程中。有许多不同的设计模式来解决不同的一般问题。设计模式通常解决开发人员在某些特定情况下面临的特定常见问题。然后，设计模式是对该问题的理想解决方案的建议，从面向对象设计的角度来看。

了解设计模式并选择在软件中使用它并不保证我们正在创建一个*正确*的解决方案。1907 年，魁北克大桥（至今仍是世界上最长的悬臂桥）在建设完成之前坍塌，因为设计它的工程师严重低估了用于建造它的钢材重量。同样，在软件开发中，我们可能会错误地选择或应用设计模式，并创建在正常操作情况下或在超出原始设计限制时*崩溃*的软件。

任何一个设计模式都提出了一组以特定方式相互作用的对象，以解决一般问题。程序员的工作是识别何时面临这样一个特定版本的问题，然后选择和调整通用设计以满足其精确需求。

在本章中，我们将介绍迭代器设计模式。这种模式如此强大和普遍，以至于 Python 开发人员提供了多种语法来访问该模式的基础面向对象原则。我们将在接下来的两章中介绍其他设计模式。其中一些具有语言支持，而另一些则没有，但没有一个像迭代器模式那样成为 Python 程序员日常生活中的固有部分。

# 迭代器

在典型的设计模式术语中，迭代器是一个具有`next()`方法和`done()`方法的对象；后者如果序列中没有剩余项目，则返回`True`。在没有内置迭代器支持的编程语言中，迭代器将像这样循环：

```py
while not iterator.done(): 
    item = iterator.next() 
    # do something with the item 
```

在 Python 中，迭代是一种特殊的特性，因此该方法得到了一个特殊的名称`__next__`。可以使用内置的`next(iterator)`来访问此方法。Python 的迭代器协议不是使用`done`方法，而是引发`StopIteration`来通知循环已完成。最后，我们有更易读的`foriteminiterator`语法来实际访问迭代器中的项目，而不是使用`while`循环。让我们更详细地看看这些。

# 迭代器协议

`Iterator`抽象基类在`collections.abc`模块中定义了 Python 中的迭代器协议。正如前面提到的，它必须有一个`__next__`方法，`for`循环（以及其他支持迭代的功能）可以调用它来从序列中获取一个新元素。此外，每个迭代器还必须满足`Iterable`接口。任何提供`__iter__`方法的类都是可迭代的。该方法必须返回一个`Iterator`实例，该实例将覆盖该类中的所有元素。

这可能听起来有点混乱，所以看看以下示例，但请注意，这是解决这个问题的一种非常冗长的方式。它清楚地解释了迭代和所讨论的两个协议，但在本章的后面，我们将看到几种更易读的方法来实现这种效果：

```py
class CapitalIterable: 
    def __init__(self, string): 
        self.string = string 

 def __iter__(self): 
        return CapitalIterator(self.string) 

class CapitalIterator: 
    def __init__(self, string): 
        self.words = [w.capitalize() for w in string.split()] 
        self.index = 0 

 def __next__(self): 
        if self.index == len(self.words): 
 raise StopIteration() 

        word = self.words[self.index] 
        self.index += 1 
        return word 

    def __iter__(self): 
        return self 
```

这个例子定义了一个`CapitalIterable`类，其工作是循环遍历字符串中的每个单词，并输出它们的首字母大写。这个可迭代对象的大部分工作都交给了`CapitalIterator`实现。与这个迭代器互动的规范方式如下：

```py
>>> iterable = CapitalIterable('the quick brown fox jumps over the lazy dog')
>>> iterator = iter(iterable)
>>> while True:
...     try:
...         print(next(iterator))
...     except StopIteration:
...         break
... 
The
Quick
Brown
Fox
Jumps
Over
The
Lazy
Dog  
```

这个例子首先构造了一个可迭代对象，并从中检索了一个迭代器。这种区别可能需要解释；可迭代对象是一个可以循环遍历的对象。通常，这些元素可以被多次循环遍历，甚至可能在同一时间或重叠的代码中。另一方面，迭代器代表可迭代对象中的特定位置；一些项目已被消耗，一些尚未被消耗。两个不同的迭代器可能在单词列表中的不同位置，但任何一个迭代器只能标记一个位置。

每次在迭代器上调用`next()`时，它都会按顺序从可迭代对象中返回另一个标记。最终，迭代器将被耗尽（不再有任何元素返回），在这种情况下会引发`Stopiteration`，然后我们跳出循环。

当然，我们已经知道了一个更简单的语法，用于从可迭代对象构造迭代器：

```py
>>> for i in iterable:
...     print(i)
... 
The
Quick
Brown
Fox
Jumps
Over
The
Lazy
Dog  
```

正如你所看到的，`for`语句，尽管看起来并不像面向对象，实际上是一种显而易见的面向对象设计原则的快捷方式。在讨论理解时，请记住这一点，因为它们似乎是面向对象工具的完全相反。然而，它们使用与`for`循环完全相同的迭代协议，只是另一种快捷方式。

# 理解

理解是一种简单但强大的语法，允许我们在一行代码中转换或过滤可迭代对象。结果对象可以是一个完全正常的列表、集合或字典，也可以是一个生成器表达式，可以在保持一次只有一个元素在内存中的情况下高效地消耗。

# 列表理解

列表理解是 Python 中最强大的工具之一，所以人们倾向于认为它们是高级的。事实并非如此。事实上，我已经在以前的例子中使用了理解，假设你会理解它们。虽然高级程序员确实经常使用理解，但并不是因为它们很高级。而是因为它们很简单，并处理了软件开发中最常见的一些操作。

让我们来看看其中一个常见操作；即，将一个项目列表转换为相关项目列表。具体来说，假设我们刚刚从文件中读取了一个字符串列表，现在我们想将其转换为整数列表。我们知道列表中的每个项目都是整数，并且我们想对这些数字进行一些操作（比如计算平均值）。以下是一种简单的方法：

```py
input_strings = ["1", "5", "28", "131", "3"]

output_integers = [] 
for num in input_strings: 
    output_integers.append(int(num)) 
```

这个方法很好用，而且只有三行代码。如果你不习惯理解，你可能不会觉得它看起来很丑陋！现在，看看使用列表理解的相同代码：

```py
input_strings = ["1", "5", "28", "131", "3"]
output_integers = [int(num) for num in input_strings] 
```

我们只剩下一行，而且，对于性能来说很重要的是，我们已经放弃了列表中每个项目的`append`方法调用。总的来说，即使你不习惯推导式语法，也很容易理解发生了什么。

方括号表示，我们正在创建一个列表。在这个列表中是一个`for`循环，它遍历输入序列中的每个项目。唯一可能令人困惑的是在列表的左大括号和`for`循环开始之间发生了什么。这里发生的事情应用于输入列表中的*每个*项目。所讨论的项目由循环中的`num`变量引用。因此，它对每个元素调用`int`函数，并将结果整数存储在新列表中。

这就是基本列表推导式的全部内容。推导式是高度优化的 C 代码；当循环遍历大量项目时，列表推导式比`for`循环要快得多。如果仅仅从可读性的角度来看，不能说服你尽可能多地使用它们，那么速度应该是一个令人信服的理由。

将一个项目列表转换为相关列表并不是列表推导式唯一能做的事情。我们还可以选择通过在推导式中添加`if`语句来排除某些值。看一下：

```py
output_integers = [int(num) for num in input_strings if len(num) < 3]
```

这个例子和前面的例子唯一不同的地方是`if len(num) < 3`部分。这个额外的代码排除了任何超过两个字符的字符串。`if`语句应用于**在**`int`函数之前的每个元素，因此它测试字符串的长度。由于我们的输入字符串在本质上都是整数，它排除了任何超过 99 的数字。

列表推导式用于将输入值映射到输出值，并在途中应用过滤器以包括或排除满足特定条件的任何值。

任何可迭代对象都可以成为列表推导式的输入。换句话说，任何我们可以放入`for`循环中的东西也可以放入推导式中。例如，文本文件是可迭代的；对文件的迭代器每次调用`__next__`都会返回文件的一行。我们可以使用`zip`函数将第一行是标题行的制表符分隔文件加载到字典中：

```py
import sys

filename = sys.argv[1]

with open(filename) as file:
    header = file.readline().strip().split("\t")
 contacts = [
 dict(
 zip(header, line.strip().split("\t")))
 for line in file
 ]

for contact in contacts:
    print("email: {email} -- {last}, {first}".format(**contact))

```

这一次，我添加了一些空白以使其更易读（列表推导式不一定要放在一行上）。这个例子从压缩的标题和分割行中创建了一个字典列表，对文件中的每一行进行了处理。

嗯，什么？如果那段代码或解释没有意义，不要担心；它很令人困惑。一个列表推导式在这里做了一堆工作，代码很难理解、阅读，最终也很难维护。这个例子表明，列表推导式并不总是最好的解决方案；大多数程序员都会同意，`for`循环比这个版本更可读。

记住：我们提供的工具不应该被滥用！始终选择适合工作的正确工具，这总是编写可维护代码。

# 集合和字典推导式

理解并不局限于列表。我们也可以使用类似的语法来创建集合和字典。让我们从集合开始。创建集合的一种方法是将列表推导式放入`set()`构造函数中，将其转换为集合。但是，为什么要浪费内存在一个被丢弃的中间列表上，当我们可以直接创建一个集合呢？

这是一个使用命名元组来模拟作者/标题/流派三元组的例子，然后检索写作特定流派的所有作者的集合：

```py
from collections import namedtuple

Book = namedtuple("Book", "author title genre")
books = [
    Book("Pratchett", "Nightwatch", "fantasy"),
    Book("Pratchett", "Thief Of Time", "fantasy"),
    Book("Le Guin", "The Dispossessed", "scifi"),
    Book("Le Guin", "A Wizard Of Earthsea", "fantasy"),
    Book("Turner", "The Thief", "fantasy"),
    Book("Phillips", "Preston Diamond", "western"),
    Book("Phillips", "Twice Upon A Time", "scifi"),
]

fantasy_authors = {b.author for b in books if b.genre == "fantasy"}

```

与演示数据设置相比，突出显示的集合推导式确实很短！如果我们使用列表推导式，特里·普拉切特当然会被列出两次。事实上，集合的性质消除了重复项，我们最终得到了以下结果：

```py
>>> fantasy_authors
{'Turner', 'Pratchett', 'Le Guin'}  
```

仍然使用大括号，我们可以引入冒号来创建字典理解。这将使用*键:值*对将序列转换为字典。例如，如果我们知道标题，可能会很快地在字典中查找作者或流派。我们可以使用字典理解将标题映射到`books`对象：

```py
fantasy_titles = {b.title: b for b in books if b.genre == "fantasy"}
```

现在，我们有了一个字典，并且可以使用正常的语法按标题查找书籍。

总之，理解不是高级的 Python，也不是应该避免使用的*非面向对象*工具。它们只是一种更简洁和优化的语法，用于从现有序列创建列表、集合或字典。

# 生成器表达式

有时我们想处理一个新的序列，而不将新的列表、集合或字典拉入系统内存。如果我们只是一个接一个地循环遍历项目，并且实际上并不关心是否创建了一个完整的容器（如列表或字典），那么创建该容器就是浪费内存。当一次处理一个项目时，我们只需要当前对象在内存中的可用性。但是当我们创建一个容器时，所有对象都必须在开始处理它们之前存储在该容器中。

例如，考虑一个处理日志文件的程序。一个非常简单的日志文件可能以这种格式包含信息：

```py
Jan 26, 2015 11:25:25 DEBUG This is a debugging message. Jan 26, 2015 11:25:36 INFO This is an information method. Jan 26, 2015 11:25:46 WARNING This is a warning. It could be serious. Jan 26, 2015 11:25:52 WARNING Another warning sent. Jan 26, 2015 11:25:59 INFO Here's some information. Jan 26, 2015 11:26:13 DEBUG Debug messages are only useful if you want to figure something out. Jan 26, 2015 11:26:32 INFO Information is usually harmless, but helpful. Jan 26, 2015 11:26:40 WARNING Warnings should be heeded. Jan 26, 2015 11:26:54 WARNING Watch for warnings. 
```

流行的网络服务器、数据库或电子邮件服务器的日志文件可能包含大量的数据（我曾经不得不清理近 2TB 的日志文件）。如果我们想处理日志中的每一行，我们不能使用列表理解；它会创建一个包含文件中每一行的列表。这可能不适合在 RAM 中，并且可能会使计算机陷入困境，这取决于操作系统。

如果我们在日志文件上使用`for`循环，我们可以在将下一行读入内存之前一次处理一行。如果我们能使用理解语法来获得相同的效果，那不是很好吗？

这就是生成器表达式的用武之地。它们使用与理解相同的语法，但不创建最终的容器对象。要创建生成器表达式，将理解包装在`()`中，而不是`[]`或`{}`。

以下代码解析了以前介绍的格式的日志文件，并输出了一个只包含`WARNING`行的新日志文件：

```py
import sys 

inname = sys.argv[1] 
outname = sys.argv[2] 

with open(inname) as infile: 
    with open(outname, "w") as outfile: 
 warnings = (l for l in infile if 'WARNING' in l) 
        for l in warnings: 
            outfile.write(l) 
```

该程序在命令行上获取两个文件名，使用生成器表达式来过滤警告（在这种情况下，它使用`if`语法并保持行不变），然后将警告输出到另一个文件。如果我们在示例文件上运行它，输出如下：

```py
Jan 26, 2015 11:25:46 WARNING This is a warning. It could be serious.
Jan 26, 2015 11:25:52 WARNING Another warning sent.
Jan 26, 2015 11:26:40 WARNING Warnings should be heeded.
Jan 26, 2015 11:26:54 WARNING Watch for warnings. 
```

当然，对于这样一个简短的输入文件，我们可以安全地使用列表理解，但是如果文件有数百万行，生成器表达式将对内存和速度产生巨大影响。

将`for`表达式括在括号中会创建一个生成器表达式，而不是元组。

生成器表达式通常在函数调用内最有用。例如，我们可以在生成器表达式上调用`sum`、`min`或`max`，而不是列表，因为这些函数一次处理一个对象。我们只对聚合结果感兴趣，而不关心任何中间容器。

总的来说，在四个选项中，尽可能使用生成器表达式。如果我们实际上不需要列表、集合或字典，而只需要过滤或转换序列中的项目，生成器表达式将是最有效的。如果我们需要知道列表的长度，或对结果进行排序、去除重复项或创建字典，我们将不得不使用理解语法。

# 生成器

生成器表达式实际上也是一种理解；它将更高级（这次确实更高级！）的生成器语法压缩成一行。更高级的生成器语法看起来甚至不那么面向对象，但我们将再次发现，这只是一种简单的语法快捷方式，用于创建一种对象。

让我们进一步考虑一下日志文件示例。如果我们想要从输出文件中删除`WARNING`列（因为它是多余的：这个文件只包含警告），我们有几种不同级别的可读性选项。我们可以使用生成器表达式来实现：

```py
import sys

# generator expression
inname, outname = sys.argv[1:3]

with open(inname) as infile:
    with open(outname, "w") as outfile:
 warnings = (
 l.replace("\tWARNING", "") for l in infile if "WARNING" in l
 )
        for l in warnings:
            outfile.write(l)
```

尽管如此，这是完全可读的，但我不想使表达式比这更复杂。我们也可以使用普通的`for`循环来实现：

```py
with open(inname) as infile:
    with open(outname, "w") as outfile:
        for l in infile:
            if "WARNING" in l:
                outfile.write(l.replace("\tWARNING", ""))
```

这显然是可维护的，但在如此少的行数中有如此多级缩进有点丑陋。更令人担忧的是，如果我们想要做一些其他事情而不是简单地打印出行，我们还必须复制循环和条件代码。

现在让我们考虑一个真正面向对象的解决方案，没有任何捷径：

```py
class WarningFilter:
    def __init__(self, insequence):
        self.insequence = insequence

 def __iter__(self):
        return self

 def __next__(self):
        l = self.insequence.readline()
        while l and "WARNING" not in l:
            l = self.insequence.readline()
        if not l:
 raise StopIteration
        return l.replace("\tWARNING", "")

with open(inname) as infile:
    with open(outname, "w") as outfile:
        filter = WarningFilter(infile)
        for l in filter:
            outfile.write(l)
```

毫无疑问：这太丑陋和难以阅读了，你甚至可能无法理解发生了什么。我们创建了一个以文件对象为输入的对象，并提供了一个像任何迭代器一样的`__next__`方法。

这个`__next__`方法从文件中读取行，如果不是`WARNING`行，则将其丢弃。当我们遇到`WARNING`行时，我们修改并返回它。然后我们的`for`循环再次调用`__next__`来处理后续的`WARNING`行。当我们用完行时，我们引发`StopIteration`来告诉循环我们已经完成了迭代。与其他示例相比，这相当丑陋，但也很强大；现在我们手头有一个类，我们可以随心所欲地使用它。

有了这样的背景，我们终于可以看到真正的生成器在起作用了。下一个示例*完全*与前一个示例相同：它创建了一个具有`__next__`方法的对象，当输入用完时会引发`StopIteration`：

```py
def warnings_filter(insequence):
    for l in insequence:
        if "WARNING" in l:
 yield l.replace("\tWARNING", "")

with open(inname) as infile:
    with open(outname, "w") as outfile:
        filter = warnings_filter(infile)
        for l in filter:
            outfile.write(l)
```

好吧，那可能相当容易阅读...至少很简短。但这到底是怎么回事？这根本毫无意义。而且`yield`到底是什么？

实际上，`yield`是生成器的关键。当 Python 在函数中看到`yield`时，它会将该函数包装在一个对象中，类似于我们之前示例中的对象。将`yield`语句视为类似于`return`语句；它退出函数并返回一行。但与`return`不同的是，当函数再次被调用（通过`next()`）时，它将从上次离开的地方开始——在`yield`语句之后的行——而不是从函数的开头开始。

在这个示例中，`yield`语句之后没有行，因此它会跳到`for`循环的下一个迭代。由于`yield`语句位于`if`语句内，它只会产生包含`WARNING`的行。

虽然看起来这只是一个循环遍历行的函数，但实际上它创建了一种特殊类型的对象，即生成器对象：

```py
>>> print(warnings_filter([]))
<generator object warnings_filter at 0xb728c6bc>  
```

我将一个空列表传递给函数，充当迭代器。函数所做的就是创建并返回一个生成器对象。该对象上有`__iter__`和`__next__`方法，就像我们在前面的示例中创建的那样。（你可以调用内置的`dir`函数来确认。）每当调用`__next__`时，生成器运行函数，直到找到`yield`语句。然后它返回`yield`的值，下一次调用`__next__`时，它会从上次离开的地方继续。

这种生成器的使用并不那么高级，但如果你没有意识到函数正在创建一个对象，它可能看起来像魔术一样。这个示例非常简单，但通过在单个函数中多次调用`yield`，你可以获得非常强大的效果；在每次循环中，生成器将简单地从最近的`yield`处继续到下一个`yield`处。

# 从另一个可迭代对象中产生值

通常，当我们构建一个生成器函数时，我们会陷入一种情况，我们希望从另一个可迭代对象中产生数据，可能是我们在生成器内部构造的列表推导或生成器表达式，或者可能是一些传递到函数中的外部项目。以前可以通过循环遍历可迭代对象并逐个产生每个项目来实现。然而，在 Python 3.3 版本中，Python 开发人员引入了一种新的语法，使其更加优雅一些。

让我们稍微调整一下生成器的例子，使其不再接受一系列行，而是接受一个文件名。这通常会被视为不好的做法，因为它将对象与特定的范例联系在一起。如果可能的话，我们应该在输入上操作迭代器；这样，同一个函数可以在日志行来自文件、内存或网络的情况下使用。

这个代码版本说明了你的生成器可以在从另一个可迭代对象（在本例中是一个生成器表达式）产生信息之前做一些基本的设置：

```py
def warnings_filter(infilename):
    with open(infilename) as infile:
 yield from (
 l.replace("\tWARNING", "") for l in infile if "WARNING" in l
 )

filter = warnings_filter(inname)
with open(outname, "w") as outfile:
    for l in filter:
        outfile.write(l)
```

这段代码将前面示例中的`for`循环合并为一个生成器表达式。请注意，这种转换并没有帮助任何事情；前面的示例中使用`for`循环更易读。

因此，让我们考虑一个比其替代方案更易读的例子。构建一个生成器，从多个其他生成器中产生数据可能是有用的。例如，`itertools.chain`函数按顺序从可迭代对象中产生数据，直到它们全部耗尽。这可以使用`yield from`语法非常容易地实现，因此让我们考虑一个经典的计算机科学问题：遍历一棵通用树。

通用树数据结构的一个常见实现是计算机的文件系统。让我们模拟 Unix 文件系统中的一些文件夹和文件，这样我们就可以有效地使用`yield from`来遍历它们：

```py
class File:
    def __init__(self, name):
        self.name = name

class Folder(File):
    def __init__(self, name):
        super().__init__(name)
        self.children = []

root = Folder("")
etc = Folder("etc")
root.children.append(etc)
etc.children.append(File("passwd"))
etc.children.append(File("groups"))
httpd = Folder("httpd")
etc.children.append(httpd)
httpd.children.append(File("http.conf"))
var = Folder("var")
root.children.append(var)
log = Folder("log")
var.children.append(log)
log.children.append(File("messages"))
log.children.append(File("kernel"))

```

这个设置代码看起来很费力，但在一个真实的文件系统中，它会更加复杂。我们需要从硬盘读取数据并将其结构化成树。然而，一旦在内存中，输出文件系统中的每个文件的代码就非常优雅：

```py
def walk(file):
    if isinstance(file, Folder):
        yield file.name + "/"
        for f in file.children:
 yield from walk(f)
    else:
        yield file.name
```

如果这段代码遇到一个目录，它会递归地要求`walk()`生成每个子目录下所有文件的列表，然后产生所有这些数据以及它自己的文件名。在它遇到一个普通文件的简单情况下，它只会产生那个文件名。

顺便说一句，解决前面的问题而不使用生成器是相当棘手的，以至于它是一个常见的面试问题。如果你像这样回答，准备好让你的面试官既印象深刻又有些恼火，因为你回答得如此轻松。他们可能会要求你解释到底发生了什么。当然，凭借你在本章学到的原则，你不会有任何问题。祝你好运！

`yield from`语法在编写链式生成器时是一个有用的快捷方式。它被添加到语言中是出于不同的原因，以支持协程。然而，它现在并没有被那么多地使用，因为它的用法已经被`async`和`await`语法所取代。我们将在下一节看到两者的例子。

# 协程

协程是非常强大的构造，经常被误解为生成器。许多作者不恰当地将协程描述为*带有一些额外语法的生成器*。这是一个容易犯的错误，因为在 Python 2.5 中引入协程时，它们被介绍为*我们在生成器语法中添加了一个* `send` *方法*。实际上，区别要更微妙一些，在看到一些例子之后会更有意义。

协程是相当难以理解的。在`asyncio`模块之外，它们在野外并不经常使用。你绝对可以跳过这一部分，快乐地在 Python 中开发多年，而不必遇到协程。有一些库广泛使用协程（主要用于并发或异步编程），但它们通常是这样编写的，以便你可以使用协程而不必真正理解它们是如何工作的！所以，如果你在这一部分迷失了方向，不要绝望。

如果我还没有吓到你，让我们开始吧！这是一个最简单的协程之一；它允许我们保持一个可以通过任意值增加的累加值：

```py
def tally(): 
    score = 0 
    while True: 
 increment = yield score 
        score += increment 
```

这段代码看起来像是不可能工作的黑魔法，所以在逐行描述之前，让我们证明它可以工作。这个简单的对象可以被棒球队的记分应用程序使用。可以为每个队伍分别保留计分，并且他们的得分可以在每个半局结束时累加的得分增加。看看这个交互式会话：

```py
>>> white_sox = tally()
>>> blue_jays = tally()
>>> next(white_sox)
0
>>> next(blue_jays)
0
>>> white_sox.send(3)
3
>>> blue_jays.send(2)
2
>>> white_sox.send(2)
5
>>> blue_jays.send(4)
6  
```

首先，我们构建了两个`tally`对象，一个用于每个队伍。是的，它们看起来像函数，但与上一节中的生成器对象一样，函数内部有`yield`语句告诉 Python 要付出很大的努力将简单的函数转换为对象。

然后我们对每个协程对象调用`next()`。这与调用任何生成器的`next()`做的事情是一样的，也就是说，它执行每一行代码，直到遇到`yield`语句，返回该点的值，然后*暂停*，直到下一个`next()`调用。

到目前为止，没有什么新鲜的。但是回顾一下我们协程中的`yield`语句：

```py
increment = yield score 
```

与生成器不同，这个`yield`函数看起来像是要返回一个值并将其赋给一个变量。事实上，这正是发生的事情。协程仍然在`yield`语句处暂停，等待被另一个`next()`调用再次激活。

除了我们不调用`next()`。正如你在交互式会话中看到的，我们调用一个名为`send()`的方法。`send()`方法和`next()`做*完全*相同的事情，只是除了将生成器推进到下一个`yield`语句之外，它还允许你从生成器外部传入一个值。这个值被分配给`yield`语句的左侧。

对于许多人来说，真正令人困惑的是这发生的顺序：

1.  `yield`发生，生成器暂停

1.  `send()`发生在函数外部，生成器被唤醒

1.  传入的值被分配给`yield`语句的左侧

1.  生成器继续处理，直到遇到另一个`yield`语句

因此，在这个特定的例子中，我们构建了协程并通过单次调用`next()`将其推进到`yield`语句，然后每次调用`send()`都将一个值传递给协程。我们将这个值加到它的得分上。然后我们回到`while`循环的顶部，并继续处理，直到我们遇到`yield`语句。`yield`语句返回一个值，这个值成为我们最近一次调用`send`的返回值。不要错过这一点：像`next()`一样，`send()`方法不仅提交一个值给生成器，还返回即将到来的`yield`语句的值。这就是我们定义生成器和协程之间的区别的方式：生成器只产生值，而协程也可以消耗值。

`next(i)`、`i.__next__()`和`i.send(value)`的行为和语法相当不直观和令人沮丧。第一个是普通函数，第二个是特殊方法，最后一个是普通方法。但这三个都是做同样的事情：推进生成器直到它产生一个值并暂停。此外，`next()`函数和相关的方法可以通过调用`i.send(None)`来复制。在这里有两个不同的方法名是有价值的，因为它有助于我们的代码读者轻松地看到他们是在与协程还是生成器交互。我只是觉得在某些情况下它是一个函数调用，而在另一种情况下它是一个普通方法有点令人恼火。

# 回到日志解析

当然，前面的例子可以很容易地使用一对整数变量编码，并在它们上调用`x += increment`。让我们看一个第二个例子，其中协程实际上节省了我们一些代码。这个例子是我在 Facebook 工作时不得不解决的问题的一个简化版本（出于教学目的）。

Linux 内核日志包含几乎看起来与此类似但又不完全相同的行：

```py
unrelated log messages 
sd 0:0:0:0 Attached Disk Drive 
unrelated log messages 
sd 0:0:0:0 (SERIAL=ZZ12345) 
unrelated log messages 
sd 0:0:0:0 [sda] Options 
unrelated log messages 
XFS ERROR [sda] 
unrelated log messages 
sd 2:0:0:1 Attached Disk Drive 
unrelated log messages 
sd 2:0:0:1 (SERIAL=ZZ67890) 
unrelated log messages 
sd 2:0:0:1 [sdb] Options 
unrelated log messages 
sd 3:0:1:8 Attached Disk Drive 
unrelated log messages 
sd 3:0:1:8 (SERIAL=WW11111) 
unrelated log messages 
sd 3:0:1:8 [sdc] Options 
unrelated log messages 
XFS ERROR [sdc] 
unrelated log messages 
```

有一大堆交错的内核日志消息，其中一些与硬盘有关。硬盘消息可能与其他消息交错，但它们以可预测的格式和顺序出现。对于每个硬盘，已知的序列号与总线标识符（如`0:0:0:0`）相关联。块设备标识符（如`sda`）也与该总线相关联。最后，如果驱动器的文件系统损坏，它可能会出现 XFS 错误。

现在，考虑到前面的日志文件，我们需要解决的问题是如何获取任何出现 XFS 错误的驱动器的序列号。这个序列号可能稍后会被数据中心的技术人员用来识别并更换驱动器。

我们知道我们可以使用正则表达式识别单独的行，但是我们将不得不在循环遍历行时更改正则表达式，因为我们将根据先前找到的内容寻找不同的东西。另一个困难的地方是，如果我们找到一个错误字符串，包含该字符串的总线以及序列号的信息已经被处理过。这可以通过以相反的顺序迭代文件的行来轻松解决。

在查看这个例子之前，请注意——基于协程的解决方案所需的代码量非常少：

```py
import re

def match_regex(filename, regex):
    with open(filename) as file:
        lines = file.readlines()
    for line in reversed(lines):
        match = re.match(regex, line)
        if match:
 regex = yield match.groups()[0]

def get_serials(filename):
    ERROR_RE = "XFS ERROR (\[sd[a-z]\])"
    matcher = match_regex(filename, ERROR_RE)
    device = next(matcher)
    while True:
        try:
            bus = matcher.send(
                "(sd \S+) {}.*".format(re.escape(device))
            )
            serial = matcher.send("{} \(SERIAL=([^)]*)\)".format(bus))
 yield serial
            device = matcher.send(ERROR_RE)
        except StopIteration:
            matcher.close()
            return

for serial_number in get_serials("EXAMPLE_LOG.log"):
    print(serial_number)
```

这段代码将工作分成了两个独立的任务。第一个任务是循环遍历所有行并输出与给定正则表达式匹配的任何行。第二个任务是与第一个任务交互，并为其提供指导，告诉它在任何给定时间应该搜索什么正则表达式。

首先看`match_regex`协程。记住，它在构造时不执行任何代码；相反，它只创建一个协程对象。一旦构造完成，协程外部的某人最终会调用`next()`来启动代码运行。然后它存储两个变量`filename`和`regex`的状态。然后它读取文件中的所有行并以相反的顺序对它们进行迭代。将传入的每一行与正则表达式进行比较，直到找到匹配项。当找到匹配项时，协程会产生正则表达式的第一个组并等待。

在将来的某个时候，其他代码将发送一个新的正则表达式来搜索。请注意，协程从不关心它试图匹配的正则表达式是什么；它只是循环遍历行并将它们与正则表达式进行比较。决定提供什么正则表达式是别人的责任。

在这种情况下，其他人是`get_serials`生成器。它不关心文件中的行；事实上，它甚至不知道它们。它做的第一件事是从`match_regex`协程构造函数创建一个`matcher`对象，给它一个默认的正则表达式来搜索。它将协程推进到它的第一个`yield`并存储它返回的值。然后它进入一个循环，指示`matcher`对象基于存储的设备 ID 搜索总线 ID，然后基于该总线 ID 搜索序列号。

它在向外部`for`循环空闲地产生该序列号之前指示匹配器找到另一个设备 ID 并重复循环。

基本上，协程的工作是在文件中搜索下一个重要的行，而生成器（`get_serial`，它使用`yield`语法而不进行赋值）的工作是决定哪一行是重要的。生成器有关于这个特定问题的信息，比如文件中行的顺序。

另一方面，协程可以插入到需要搜索文件以获取给定正则表达式的任何问题中。

# 关闭协程和引发异常

普通的生成器通过引发`StopIteration`来信号它们的退出。如果我们将多个生成器链接在一起（例如，通过在另一个生成器内部迭代一个生成器），`StopIteration`异常将向外传播。最终，它将遇到一个`for`循环，看到异常并知道是时候退出循环了。

尽管它们使用类似的语法，协程通常不遵循迭代机制。通常不是通过一个直到遇到异常的数据，而是通常将数据推送到其中（使用`send`）。通常是负责推送的实体告诉协程何时完成。它通过在相关协程上调用`close()`方法来做到这一点。

当调用`close()`方法时，它将在协程等待发送值的点引发`GeneratorExit`异常。通常，协程应该将它们的`yield`语句包装在`try`...`finally`块中，以便执行任何清理任务（例如关闭关联文件或套接字）。

如果我们需要在协程内部引发异常，我们可以类似地使用`throw()`方法。它接受一个异常类型，可选的`value`和`traceback`参数。当我们在一个协程中遇到异常并希望在相邻的协程中引发异常时，后者是有用的，同时保持回溯。

前面的例子可以在没有协程的情况下编写，并且读起来几乎一样。事实上，正确地管理协程之间的所有状态是相当困难的，特别是当你考虑到上下文管理器和异常等因素时。幸运的是，Python 标准库包含一个名为`asyncio`的包，可以为您管理所有这些。一般来说，我建议您避免使用裸协程，除非您专门为 asyncio 编写代码。日志示例几乎可以被认为是一种*反模式*；一种应该避免而不是拥抱的设计模式。

# 协程、生成器和函数之间的关系

我们已经看到了协程的运行，现在让我们回到讨论它们与生成器的关系。在 Python 中，就像经常发生的情况一样，这种区别是相当模糊的。事实上，所有的协程都是生成器对象，作者经常交替使用这两个术语。有时，他们将协程描述为生成器的一个子集（只有从`yield`返回值的生成器被认为是协程）。这在 Python 中是技术上正确的，正如我们在前面的部分中看到的。

然而，在更广泛的理论计算机科学领域，协程被认为是更一般的原则，生成器是协程的一种特定类型。此外，普通函数是协程的另一个独特子集。

协程是一个可以在一个或多个点传入数据并在一个或多个点获取数据的例程。在 Python 中，数据传入和传出的点是`yield`语句。

函数，或子例程，是协程的最简单类型。您可以在一个点传入数据，并在函数返回时在另一个点获取数据。虽然函数可以有多个`return`语句，但对于任何给定的函数调用，只能调用其中一个。

最后，生成器是一种可以在一个点传入数据的协程，但可以在多个点传出数据的协程。在 Python 中，数据将在`yield`语句处传出，但无法再传入数据。如果调用`send`，数据将被悄悄丢弃。

因此，理论上，生成器是协程的一种类型，函数是协程的一种类型，还有一些既不是函数也不是生成器的协程。够简单了吧？那么，为什么在 Python 中感觉更复杂呢？

在 Python 中，生成器和协程都是使用类似于构造函数的语法构造的。但是生成的对象根本不是函数；它是一种完全不同类型的对象。函数当然也是对象。但它们有不同的接口；函数是可调用的并返回值，生成器使用`next()`提取数据，协程使用`send`推入数据。

还有一种使用`async`和`await`关键字的协程的替代语法。这种语法使得代码更清晰，表明代码是一个协程，并进一步打破了协程和生成器之间的欺骗性对称性。

# 案例研究

Python 目前最流行的领域之一是数据科学。为了纪念这一事实，让我们实现一个基本的机器学习算法。

机器学习是一个庞大的主题，但总体思想是利用从过去数据中获得的知识对未来数据进行预测或分类。这些算法的用途层出不穷，数据科学家每天都在找到应用机器学习的新方法。一些重要的机器学习应用包括计算机视觉（如图像分类或人脸识别）、产品推荐、识别垃圾邮件和自动驾驶汽车。

为了不偏离整本关于机器学习的书，我们将看一个更简单的问题：给定一个 RGB 颜色定义，人们会将该颜色定义为什么名字？

标准 RGB 颜色空间中有超过 1600 万种颜色，人类只为其中的一小部分取了名字。虽然有成千上万种名称（有些相当荒谬；只需去任何汽车经销商或油漆商店），让我们构建一个试图将 RGB 空间划分为基本颜色的分类器：

+   红色

+   紫色

+   蓝色

+   绿色

+   黄色

+   橙色

+   灰色

+   粉色

（在我的测试中，我将白色和黑色的颜色分类为灰色，棕色的颜色分类为橙色。）

我们需要的第一件事是一个数据集来训练我们的算法。在生产系统中，您可能会从*颜色列表*网站上获取数据，或者对成千上万的人进行调查。相反，我创建了一个简单的应用程序，它会呈现一个随机颜色，并要求用户从前面的八个选项中选择一个来分类。我使用了 Python 附带的用户界面工具包`tkinter`来实现它。我不打算详细介绍这个脚本的内容，但为了完整起见，这是它的全部内容（它有点长，所以您可能想从 Packt 的 GitHub 存储库中获取本书示例的完整内容，而不是自己输入）：

```py
import random
import tkinter as tk
import csv

class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.grid(sticky="news")
        master.columnconfigure(0, weight=1)
        master.rowconfigure(0, weight=1)
        self.create_widgets()
        self.file = csv.writer(open("colors.csv", "a"))

    def create_color_button(self, label, column, row):
        button = tk.Button(
            self, command=lambda: self.click_color(label), text=label
        )
        button.grid(column=column, row=row, sticky="news")

    def random_color(self):
        r = random.randint(0, 255)
        g = random.randint(0, 255)
        b = random.randint(0, 255)

        return f"#{r:02x}{g:02x}{b:02x}"

    def create_widgets(self):
        self.color_box = tk.Label(
            self, bg=self.random_color(), width="30", height="15"
        )
        self.color_box.grid(
            column=0, columnspan=2, row=0, sticky="news"
        )
        self.create_color_button("Red", 0, 1)
        self.create_color_button("Purple", 1, 1)
        self.create_color_button("Blue", 0, 2)
        self.create_color_button("Green", 1, 2)
        self.create_color_button("Yellow", 0, 3)
        self.create_color_button("Orange", 1, 3)
        self.create_color_button("Pink", 0, 4)
        self.create_color_button("Grey", 1, 4)
        self.quit = tk.Button(
            self, text="Quit", command=root.destroy, bg="#ffaabb"
        )
        self.quit.grid(column=0, row=5, columnspan=2, sticky="news")

    def click_color(self, label):
        self.file.writerow([label, self.color_box["bg"]])
        self.color_box["bg"] = self.random_color()

root = tk.Tk()
app = Application(master=root)
app.mainloop()
```

如果您愿意，可以轻松添加更多按钮以获取其他颜色。您可能会在布局上遇到问题；`create_color_button`的第二个和第三个参数表示按钮所在的两列网格的行和列。一旦您将所有颜色放在位，您将希望将**退出**按钮移动到最后一行。

对于这个案例研究，了解这个应用程序的重要事情是输出。它创建了一个名为`colors.csv`的**逗号分隔值**（**CSV**）文件。该文件包含两个 CSV：用户为颜色分配的标签和颜色的十六进制 RGB 值。以下是一个示例：

```py
Green,#6edd13
Purple,#814faf
Yellow,#c7c26d
Orange,#61442c
Green,#67f496
Purple,#c757d5
Blue,#106a98
Pink,#d40491
.
.
.
Blue,#a4bdfa
Green,#30882f
Pink,#f47aad
Green,#83ddb2
Grey,#baaec9
Grey,#8aa28d
Blue,#533eda
```

在我厌倦并决定开始对我的数据集进行机器学习之前，我制作了 250 多个数据点。如果您想使用它，我的数据点已经与本章的示例一起提供（没有人告诉我我是色盲，所以它应该是合理的）。

我们将实现一种更简单的机器学习算法，称为*k 最近邻*。该算法依赖于数据集中点之间的某种*距离*计算（在我们的情况下，我们可以使用三维版本的毕达哥拉斯定理）。给定一个新的数据点，它找到一定数量（称为*k*，这是*k 最近邻*中的*k*）的数据点，这些数据点在通过该距离计算进行测量时最接近它。然后以某种方式组合这些数据点（对于线性计算，平均值可能有效；对于我们的分类问题，我们将使用模式），并返回结果。

我们不会详细介绍算法的工作原理；相反，我们将专注于如何将迭代器模式或迭代器协议应用于这个问题。

现在让我们编写一个程序，按顺序执行以下步骤：

1.  从文件中加载示例数据并构建模型。

1.  生成 100 种随机颜色。

1.  对每种颜色进行分类，并以与输入相同的格式输出到文件。

第一步是一个相当简单的生成器，它加载 CSV 数据并将其转换为符合我们需求的格式：

```py
import csv

dataset_filename = "colors.csv"

def load_colors(filename):
    with open(filename) as dataset_file:
        lines = csv.reader(dataset_file)
 for line in lines:
            label, hex_color = line
 yield (hex_to_rgb(hex_color), label)
```

我们以前没有见过`csv.reader`函数。它返回文件中行的迭代器。迭代器返回的每个值都是一个由逗号分隔的字符串列表。因此，行`Green,#6edd13`返回为`["Green", "#6edd13"]`。

然后`load_colors`生成器逐行消耗该迭代器，并产生 RGB 值的元组以及标签。这种方式将生成器链接在一起是非常常见的，其中一个迭代器调用另一个迭代器，依此类推。您可能希望查看 Python 标准库中的`itertools`模块，其中有许多等待您的现成生成器。

在这种情况下，RGB 值是 0 到 255 之间的整数元组。从十六进制到 RGB 的转换有点棘手，因此我们将其提取到一个单独的函数中：

```py
def hex_to_rgb(hex_color):
    return tuple(int(hex_color[i : i + 2], 16) for i in range(1, 6, 2))

```

这个生成器表达式正在做很多工作。它以`“＃12abfe”`这样的字符串作为输入，并返回一个类似`(18, 171, 254)`的元组。让我们从后往前分解。

`range`调用将返回数字`[1, 3, 5]`。这些数字代表十六进制字符串中三个颜色通道的索引。索引`0`被跳过，因为它代表字符`“＃”`，而我们不关心这个字符。对于这三个数字中的每一个，它提取`i`和`i+2`之间的两个字符的字符串。对于前面的示例字符串，这将是`12`，`ab`和`fe`。然后将此字符串值转换为整数。作为`int`函数的第二个参数传递的`16`告诉函数使用基数 16（十六进制）而不是通常的基数 10（十进制）进行转换。

考虑到生成器表达式的阅读难度，您认为它应该以不同的格式表示吗？例如，它可以被创建为多个生成器表达式的序列，或者展开为一个带有`yield`语句的普通生成器函数。您更喜欢哪种？

在这种情况下，我相信函数名称能够解释这行丑陋代码在做什么。

现在我们已经加载了*训练数据*（手动分类的颜色），我们需要一些新数据来测试算法的工作效果。我们可以通过生成一百种随机颜色来实现这一点，每种颜色由 0 到 255 之间的三个随机数字组成。

有很多方法可以做到这一点：

+   一个带有嵌套生成器表达式的列表推导：``[tuple(randint(0,255) for c in range(3)) for r in range(100)]``

+   一个基本的生成器函数

+   实现`__iter__`和`__next__`协议的类

+   通过一系列协同程序将数据传递

+   即使只是一个基本的`for`循环

生成器版本似乎最易读，所以让我们将该函数添加到我们的程序中：

```py
from random import randint

def generate_colors(count=100):
    for i in range(count):
        yield (randint(0, 255), randint(0, 255), randint(0, 255))
```

注意我们如何对要生成的颜色数量进行参数化。现在我们可以在将来重用这个函数来执行其他生成颜色的任务。

现在，在进行分类之前，我们需要一个计算两种颜色之间*距离*的函数。由于可以将颜色看作是三维的（例如，红色、绿色和蓝色可以映射到*x*、*y*和*z*轴），让我们使用一些基本的数学：

```py
def color_distance(color1, color2):
    channels = zip(color1, color2)
    sum_distance_squared = 0
    for c1, c2 in channels:
        sum_distance_squared += (c1 - c2) ** 2
    return sum_distance_squared
```

这是一个看起来非常基本的函数；它看起来甚至没有使用迭代器协议。没有`yield`函数，也没有推导。但是，有一个`for`循环，`zip`函数的调用也在进行一些真正的迭代（如果您不熟悉它，`zip`会产生元组，每个元组包含来自每个输入迭代器的一个元素）。

这个距离计算是你可能从学校记得的勾股定理的三维版本：*a² + b² = c²*。由于我们使用了三个维度，我猜实际上应该是*a² + b² + c² = d²*。距离在技术上是*a² + b² + c²*的平方根，但没有必要执行相对昂贵的`sqrt`计算，因为平方距离在大小上都是相同的。

现在我们已经有了一些基本的管道，让我们来实现实际的 k-nearest neighbor。这个例程可以被认为是消耗和组合我们已经看到的两个生成器（`load_colors`和`generate_colors`）：

```py
def nearest_neighbors(model_colors, target_colors, num_neighbors=5):
    model_colors = list(model_colors)

    for target in target_colors:
        distances = sorted(
            ((color_distance(c[0], target), c) for c in model_colors)
        )
        yield target, distances[:5]
```

首先，我们将`model_colors`生成器转换为列表，因为它必须被多次使用，每次用于`target_colors`中的一个。如果我们不这样做，就必须重复从源文件加载颜色，这将执行大量不必要的磁盘读取。

这种决定的缺点是整个列表必须一次性全部存储在内存中。如果我们有一个无法放入内存的大型数据集，实际上需要每次从磁盘重新加载生成器（尽管在这种情况下，我们实际上会考虑不同的机器学习算法）。

`nearest_neighbors`生成器循环遍历每个目标颜色（例如`(255, 14, 168)`的三元组），并在生成器表达式中调用`color_distance`函数。然后，`sorted`调用对该生成器表达式的结果按其第一个元素进行排序，即距离。这是一段复杂的代码，一点也不面向对象。您可能需要将其分解为普通的`for`循环，以确保您理解生成器表达式在做什么。

`yield`语句稍微复杂一些。对于`target_colors`生成器中的每个 RGB 三元组，它产生目标和`num_neighbors`（这是*k*在*k-nearest*中，顺便说一下，许多数学家和数据科学家倾向于使用难以理解的单字母变量名）最接近的颜色的列表推导。

列表推导中的每个元素的内容是`model_colors`生成器的一个元素；也就是说，一个包含三个 RGB 值和手动输入的字符串名称的元组。因此，一个元素可能看起来像这样：`((104, 195, 77), 'Green')`。当我看到嵌套元组时，我首先想到的是，*这不是正确的数据结构*。RGB 颜色可能应该表示为一个命名元组，并且这两个属性可能应该放在一个数据类上。 

我们现在可以添加*另一个*生成器到链中，以找出我们应该给这个目标颜色起什么名字：

```py
from collections import Counter

def name_colors(model_colors, target_colors, num_neighbors=5):
    for target, near in nearest_neighbors(
        model_colors, target_colors, num_neighbors=5
    ):
        print(target, near)
        name_guess = Counter(n[1] for n in near).most_common()[0][0]
        yield target, name_guess
```

这个生成器将`nearest_neighbors`返回的元组解包成三元组目标和五个最近的数据点。它使用`Counter`来找到在返回的颜色中最常出现的名称。在`Counter`构造函数中还有另一个生成器表达式；这个生成器表达式从每个数据点中提取第二个元素（颜色名称）。然后它产生一个 RGB 值和猜测的名称的元组。返回值的一个例子是`(91, 158, 250) Blue`。

我们可以编写一个函数，接受`name_colors`生成器的输出，并将其写入 CSV 文件，RGB 颜色表示为十六进制值：

```py
def write_results(colors, filename="output.csv"):
    with open(filename, "w") as file:
        writer = csv.writer(file)
        for (r, g, b), name in colors:
            writer.writerow([name, f"#{r:02x}{g:02x}{b:02x}"])
```

这是一个函数，而不是一个生成器。它在`for`循环中消耗生成器，但它不产生任何东西。它构造了一个 CSV 写入器，并为每个目标颜色输出名称、十六进制值（例如`Purple,#7f5f95`）对的行。这里可能会让人困惑的唯一一件事是格式字符串的内容。与每个`r`、`g`和`b`通道一起使用的`:02x`修饰符将数字输出为前导零填充的两位十六进制数。

现在我们所要做的就是将这些不同的生成器和管道连接在一起，并通过一个函数调用启动整个过程：

```py
def process_colors(dataset_filename="colors.csv"):
    model_colors = load_colors(dataset_filename)
    colors = name_colors(model_colors, generate_colors(), 5)
    write_results(colors)

if __name__ == "__main__":
    process_colors()
```

因此，这个函数与我们定义的几乎所有其他函数不同，它是一个完全正常的函数，没有`yield`语句或`for`循环。它根本不进行任何迭代。

然而，它构造了三个生成器。你能看到所有三个吗？：

+   `load_colors`返回一个生成器

+   `generate_colors`返回一个生成器

+   `name_guess`返回一个生成器

`name_guess`生成器消耗了前两个生成器。然后，它又被`write_results`函数消耗。

我写了第二个 Tkinter 应用程序来检查算法的准确性。它与第一个应用程序类似，只是它会渲染每种颜色及与该颜色相关联的标签。然后你必须手动点击是或否，以确定标签是否与颜色匹配。对于我的示例数据，我得到了大约 95%的准确性。通过实施以下内容，这个准确性可以得到提高：

+   添加更多颜色名称

+   通过手动分类更多颜色来添加更多的训练数据

+   调整`num_neighbors`的值

+   使用更高级的机器学习算法

这是输出检查应用的代码，不过我建议下载示例代码。这样打字会很麻烦：

```py
import tkinter as tk
import csv

class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.grid(sticky="news")
        master.columnconfigure(0, weight=1)
        master.rowconfigure(0, weight=1)
        self.csv_reader = csv.reader(open("output.csv"))
        self.create_widgets()
        self.total_count = 0
        self.right_count = 0

    def next_color(self):
        return next(self.csv_reader)

    def mk_grid(self, widget, column, row, columnspan=1):
        widget.grid(
            column=column, row=row, columnspan=columnspan, sticky="news"
        )

    def create_widgets(self):
        color_text, color_bg = self.next_color()
        self.color_box = tk.Label(
            self, bg=color_bg, width="30", height="15"
        )
        self.mk_grid(self.color_box, 0, 0, 2)

        self.color_label = tk.Label(self, text=color_text, height="3")
        self.mk_grid(self.color_label, 0, 1, 2)

        self.no_button = tk.Button(
            self, command=self.count_next, text="No"
        )
        self.mk_grid(self.no_button, 0, 2)

        self.yes_button = tk.Button(
            self, command=self.count_yes, text="Yes"
        )
        self.mk_grid(self.yes_button, 1, 2)

        self.percent_accurate = tk.Label(self, height="3", text="0%")
        self.mk_grid(self.percent_accurate, 0, 3, 2)

        self.quit = tk.Button(
            self, text="Quit", command=root.destroy, bg="#ffaabb"
        )
        self.mk_grid(self.quit, 0, 4, 2)

    def count_yes(self):
        self.right_count += 1
        self.count_next()

    def count_next(self):
        self.total_count += 1
        percentage = self.right_count / self.total_count
        self.percent_accurate["text"] = f"{percentage:.0%}"
        try:
            color_text, color_bg = self.next_color()
        except StopIteration:
            color_text = "DONE"
            color_bg = "#ffffff"
            self.color_box["text"] = "DONE"
            self.yes_button["state"] = tk.DISABLED
            self.no_button["state"] = tk.DISABLED
        self.color_label["text"] = color_text
        self.color_box["bg"] = color_bg

root = tk.Tk()
app = Application(master=root)
app.mainloop()
```

你可能会想，*这与面向对象编程有什么关系？这段代码中甚至没有一个类！* 从某些方面来说，你是对的；生成器通常不被认为是面向对象的。然而，创建它们的函数返回对象；实际上，你可以把这些函数看作构造函数。构造的对象有一个适当的`__next__()`方法。基本上，生成器语法是一种特定类型的对象的语法快捷方式，如果没有它，创建这种对象会非常冗长。

# 练习

如果你在日常编码中很少使用推导，那么你应该做的第一件事是搜索一些现有的代码，找到一些`for`循环。看看它们中是否有任何可以轻松转换为生成器表达式或列表、集合或字典推导的。

测试列表推导是否比`for`循环更快。这可以通过内置的`timeit`模块来完成。使用`timeit.timeit`函数的帮助文档找出如何使用它。基本上，编写两个做同样事情的函数，一个使用列表推导，一个使用`for`循环来迭代数千个项目。将每个函数传入`timeit.timeit`，并比较结果。如果你感到有冒险精神，也可以比较生成器和生成器表达式。使用`timeit`测试代码可能会让人上瘾，所以请记住，除非代码被执行了大量次数，比如在一个巨大的输入列表或文件上，否则代码不需要非常快。

玩转生成器函数。从需要多个值的基本迭代器开始（数学序列是典型的例子；如果你想不出更好的例子，斐波那契数列已经被过度使用了）。尝试一些更高级的生成器，比如接受多个输入列表并以某种方式产生合并值的生成器。生成器也可以用在文件上；你能否编写一个简单的生成器，显示两个文件中相同的行？

协程滥用迭代器协议，但实际上并不符合迭代器模式。你能否构建一个非协程版本的代码，从日志文件中获取序列号？采用面向对象的方法，以便在类上存储额外的状态。如果你能创建一个对象，它可以完全替代现有的协程，你将学到很多关于协程的知识。

本章的案例研究中有很多奇怪的元组传递，很难跟踪。看看是否可以用更面向对象的解决方案替换这些返回值。另外，尝试将一些共享数据的函数（例如`model_colors`和`target_colors`）移入一个类中进行实验。这样可以减少大多数生成器需要传入的参数数量，因为它们可以在`self`上查找。

# 总结

在本章中，我们了解到设计模式是有用的抽象，为常见的编程问题提供最佳实践解决方案。我们介绍了我们的第一个设计模式，迭代器，以及 Python 使用和滥用这种模式的多种方式。原始的迭代器模式非常面向对象，但在代码上也相当丑陋和冗长。然而，Python 的内置语法将丑陋抽象化，为我们留下了这些面向对象构造的清晰接口。

理解推导和生成器表达式可以将容器构造与迭代结合在一行中。生成器对象可以使用`yield`语法构造。协程在外部看起来像生成器，但用途完全不同。

我们将在接下来的两章中介绍几种设计模式。
