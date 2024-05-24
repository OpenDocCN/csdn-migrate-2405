# Python 编程学习手册第二版（三）

> 原文：[`zh.annas-archive.org/md5/406733548F67B770B962DA4756270D5F`](https://zh.annas-archive.org/md5/406733548F67B770B962DA4756270D5F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：OOP，装饰器和迭代器

La classe non è acqua.（类似水）- 意大利谚语

我可能会写一本关于**面向对象编程**（**OOP**）和类的整本书。在本章中，我面临着在广度和深度之间找到平衡的艰难挑战。有太多的事情要讲述，其中很多如果我深入描述的话，将会占用整个章节以上的篇幅。因此，我将尽量给你一个我认为是对基础知识的良好全景视图，再加上一些在接下来的章节中可能会派上用场的东西。Python 的官方文档将有助于填补这些空白。

在本章中，我们将涵盖以下主题：

+   装饰器

+   Python 中的 OOP

+   迭代器

# 装饰器

在第五章《节省时间和内存》中，我测量了各种表达式的执行时间。如果你还记得的话，我不得不初始化一个变量到开始时间，并在执行后从当前时间中减去它，以计算经过的时间。我还在每次测量后在控制台上打印出来。那太麻烦了。

每当你发现自己重复做某些事情时，警报应该响起。你能把那段代码放到一个函数中，避免重复吗？大多数情况下答案是*是*，所以让我们看一个例子：

```py
# decorators/time.measure.start.py
from time import sleep, time

def f():
    sleep(.3)

def g():
    sleep(.5)

t = time()
f()
print('f took:', time() - t)  # f took: 0.3001396656036377

t = time()
g()
print('g took:', time() - t)  # g took: 0.5039339065551758
```

在前面的代码中，我定义了两个函数`f`和`g`，它们除了休眠（分别为 0.3 和 0.5 秒）之外什么也不做。我使用`sleep`函数来暂停执行所需的时间。请注意时间测量非常准确。现在，我们如何避免重复那段代码和那些计算呢？一个潜在的方法可能是：

```py
# decorators/time.measure.dry.py
from time import sleep, time

def f():
    sleep(.3)

def g():
    sleep(.5)

def measure(func):
    t = time()
    func()
    print(func.__name__, 'took:', time() - t)

measure(f)  # f took: 0.30434322357177734
measure(g)  # g took: 0.5048270225524902
```

啊，现在好多了。整个计时机制已经封装到一个函数中，所以我们不需要重复代码。我们可以动态打印函数名称，编码起来也很容易。如果我们需要将参数传递给我们测量的函数呢？这段代码可能会变得有点复杂，所以让我们看一个例子：

```py
# decorators/time.measure.arguments.py
from time import sleep, time

def f(sleep_time=0.1):
    sleep(sleep_time)

def measure(func, *args, **kwargs):
    t = time()
    func(*args, **kwargs)
    print(func.__name__, 'took:', time() - t)

measure(f, sleep_time=0.3)  # f took: 0.30056095123291016
measure(f, 0.2)  # f took: 0.2033553123474121
```

现在，`f`期望被提供`sleep_time`（默认值为`0.1`），所以我们不再需要`g`。我还必须更改`measure`函数，使其现在接受一个函数、任意变量位置参数和任意变量关键字参数。这样，无论我们用什么调用`measure`，我们都会将这些参数重定向到我们在内部调用`func`的调用中。

这很好，但我们可以再推进一点。假设我们想要在`f`函数中内置这种计时行为，这样我们就可以直接调用它并进行测量。我们可以这样做：

```py
# decorators/time.measure.deco1.py
from time import sleep, time

def f(sleep_time=0.1):
    sleep(sleep_time)

def measure(func):
    def wrapper(*args, **kwargs):
        t = time()
        func(*args, **kwargs)
        print(func.__name__, 'took:', time() - t)
    return wrapper

f = measure(f)  # decoration point

```

```py
f(0.2)  # f took: 0.20372915267944336
f(sleep_time=0.3)  # f took: 0.30455899238586426
print(f.__name__)  # wrapper <- ouch!
```

前面的代码可能并不那么直接。让我们看看这里发生了什么。魔法在于**装饰点**。当我们用`f`作为参数调用`measure`时，我们基本上用`measure`返回的任何东西重新分配了`f`。在`measure`中，我们定义了另一个函数`wrapper`，然后返回它。因此，在装饰点之后的效果是，当我们调用`f`时，实际上是在调用`wrapper`。由于内部的`wrapper`调用了`func`，也就是`f`，我们实际上是这样关闭了循环。如果你不相信我，看看最后一行。

`wrapper`实际上是...一个包装器。它接受变量和位置参数，并用它们调用`f`。它还在调用周围进行时间测量计算。

这种技术称为**装饰**，而`measure`实际上是一个**装饰器**。这种范式变得如此受欢迎和广泛使用，以至于 Python 在某个时候添加了一个专门的语法（查看[`www.python.org/dev/peps/pep-0318/`](https://www.python.org/dev/peps/pep-0318/)）。让我们探讨三种情况：一个装饰器，两个装饰器和一个带参数的装饰器：

```py
# decorators/syntax.py
def func(arg1, arg2, ...):
    pass
func = decorator(func)

# is equivalent to the following:

@decorator
def func(arg1, arg2, ...):
    pass
```

基本上，我们不需要手动将函数重新分配给装饰器返回的内容，而是在函数的定义前面加上特殊的语法`@decorator_name`。

我们可以以以下方式将多个装饰器应用于同一个函数：

```py
# decorators/syntax.py
def func(arg1, arg2, ...):
    pass
func = deco1(deco2(func))

# is equivalent to the following:

@deco1
@deco2
def func(arg1, arg2, ...):
    pass
```

在应用多个装饰器时，要注意顺序。在上面的例子中，首先用`deco2`装饰`func`，然后用`deco1`装饰结果。一个很好的经验法则是：*装饰器离函数越近，越早应用*。

有些装饰器可以接受参数。这种技术通常用于生成其他装饰器。让我们先看一下语法，然后再看一个例子：

```py
# decorators/syntax.py
def func(arg1, arg2, ...):
    pass
func = decoarg(arg_a, arg_b)(func)

# is equivalent to the following:

@decoarg(arg_a, arg_b)
def func(arg1, arg2, ...):
    pass
```

正如你所看到的，这种情况有点不同。首先，使用给定的参数调用`decoarg`，然后调用它的返回值（实际的装饰器）与`func`。在我给你另一个例子之前，让我们解决一个让我困扰的问题。我不想在装饰函数时丢失原始函数名称和文档字符串（以及其他属性，具体细节请查看文档）。但是因为在我们的装饰器内部返回了`wrapper`，来自`func`的原始属性就丢失了，`f`最终被分配了`wrapper`的属性。`functools`模块有一个简单的解决方法。我将修复最后一个例子，并且还将重写其语法以使用`@`运算符：

```py
# decorators/time.measure.deco2.py
from time import sleep, time
from functools import wraps

def measure(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        t = time()
        func(*args, **kwargs)
        print(func.__name__, 'took:', time() - t)
    return wrapper

@measure
def f(sleep_time=0.1):
    """I'm a cat. I love to sleep! """
    sleep(sleep_time)

f(sleep_time=0.3)  # f took: 0.3010902404785156
print(f.__name__, ':', f.__doc__)  # f : I'm a cat. I love to sleep!
```

现在我们说得通了！正如你所看到的，我们所需要做的就是告诉 Python`wrapper`实际上包装了`func`（通过`wraps`函数），你可以看到原始名称和文档字符串现在得到了保留。

让我们看另一个例子。我想要一个装饰器，在函数的结果大于一定阈值时打印错误消息。我还将利用这个机会向你展示如何同时应用两个装饰器：

```py
# decorators/two.decorators.py
from time import sleep, time
from functools import wraps

def measure(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        t = time()
        result = func(*args, **kwargs)
        print(func.__name__, 'took:', time() - t)
        return result
    return wrapper

def max_result(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        if result > 100:
            print('Result is too big ({0}). Max allowed is 100.'
                  .format(result))
        return result
    return wrapper

@measure
@max_result
def cube(n):
    return n ** 3

print(cube(2))
print(cube(5))
```

花点时间来研究上面的例子，直到你确信你理解得很好。如果你理解了，我认为现在没有任何装饰器是你写不出来的。

我不得不增强`measure`装饰器，使得它的`wrapper`现在返回对`func`的调用结果。`max_result`装饰器也是这样做的，但在返回之前，它检查`result`是否大于`100`，这是允许的最大值。我用这两个装饰器装饰了`cube`。首先应用`max_result`，然后是`measure`。运行这段代码会产生这个结果：

```py
$ python two.decorators.py
cube took: 3.0994415283203125e-06
8 
Result is too big (125). Max allowed is 100.
cube took: 1.0013580322265625e-05
125
```

为了方便起见，我用一个空行分隔了两次调用的结果。在第一次调用中，结果是`8`，通过了阈值检查。运行时间被测量并打印。最后，我们打印结果（`8`）。

在第二次调用中，结果是`125`，所以错误消息被打印，结果被返回，然后轮到`measure`，再次打印运行时间，最后，我们打印结果（`125`）。

如果我用不同顺序的相同两个装饰器装饰`cube`函数，错误消息将会在打印运行时间的行之后而不是之前。

# 装饰器工厂

现在让我们简化这个例子，回到一个单一的装饰器：`max_result`。我想让它这样做，以便我可以用不同的阈值装饰不同的函数，我不想为每个阈值编写一个装饰器。让我们修改`max_result`，以便它允许我们动态地指定阈值来装饰函数：

```py
# decorators/decorators.factory.py
from functools import wraps

def max_result(threshold):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            if result > threshold:
                print(
                    'Result is too big ({0}). Max allowed is {1}.'
                    .format(result, threshold))
            return result
        return wrapper
    return decorator

@max_result(75)
def cube(n):
    return n ** 3

print(cube(5))
```

上面的代码向你展示了如何编写**装饰器工厂**。如果你还记得，用带参数的装饰器装饰函数与编写`func = decorator(argA, argB)(func)`是一样的，所以当我们用`max_result(75)`装饰`cube`时，我们实际上是在做`cube = max_result(75)(cube)`。

让我们一步步地看发生了什么。当我们调用`max_result(75)`时，我们进入它的主体。在里面定义了一个`decorator`函数，它以函数作为唯一的参数。在该函数内部执行了通常的装饰器技巧。我们定义了`wrapper`，在其中我们检查原始函数调用的结果。这种方法的美妙之处在于，从最内层，我们仍然可以动态地引用`func`和`threshold`，这使我们能够动态地设置阈值。

`wrapper`返回`result`，`decorator`返回`wrapper`，`max_result`返回`decorator`。这意味着我们的`cube = max_result(75)(cube)`调用实际上变成了`cube = decorator(cube)`。不仅仅是任何`decorator`，而是`threshold`的值为`75`的`decorator`。这是通过一种称为**闭包**的机制实现的，这超出了本章的范围，但仍然非常有趣，所以我提到它让您进行一些研究。

运行上一个示例会产生以下结果：

```py
$ python decorators.factory.py
Result is too big (125). Max allowed is 75.
125
```

前面的代码允许我随心所欲地使用`max_result`装饰器，就像这样：

```py
# decorators/decorators.factory.py
@max_result(75)
def cube(n):
    return n ** 3

@max_result(100)
def square(n):
    return n ** 2

@max_result(1000)
def multiply(a, b):
    return a * b
```

请注意，每个装饰都使用不同的`threshold`值。

装饰器在 Python 中非常受欢迎。它们经常被使用，并且大大简化（我敢说还美化）了代码。

# 面向对象编程（OOP）

这是一个相当漫长而希望愉快的旅程，到现在为止，我们应该准备好去探索面向对象编程了。我将使用 Kindler, E.; Krivy, I. (2011)的定义。*Object-oriented simulation of systems with sophisticated control* by *International Journal of General Systems*，并将其适应到 Python 中：

面向对象编程（OOP）是一种基于“对象”概念的编程范式，对象是包含数据（属性形式）和代码（方法形式）的数据结构。对象的一个显著特征是对象的方法可以访问并经常修改与其关联的数据属性（对象具有“self”的概念）。在面向对象编程中，计算机程序是通过使它们由相互交互的对象构成来设计的。

Python 完全支持这种范式。实际上，正如我们已经说过的，*Python 中的一切都是对象*，因此这表明 OOP 不仅受到 Python 的支持，而且它是其核心的一部分。

面向对象编程的两个主要角色是**对象**和**类**。类用于创建对象（对象是从它们创建的类的实例），因此我们可以将它们视为实例工厂。当对象由类创建时，它们继承类的属性和方法。它们代表程序领域中的具体项目。

# 最简单的 Python 类

我将从您可以在 Python 中编写的最简单的类开始：

```py
# oop/simplest.class.py
class Simplest():  # when empty, the braces are optional
    pass

print(type(Simplest))  # what type is this object?
simp = Simplest()  # we create an instance of Simplest: simp
print(type(simp))  # what type is simp?
# is simp an instance of Simplest?
print(type(simp) == Simplest)  # There's a better way for this
```

让我们运行前面的代码，并逐行解释它：

```py
$ python simplest.class.py
<class 'type'>
<class '__main__.Simplest'>
True
```

我定义的`Simplest`类在其主体中只有`pass`指令，这意味着它没有任何自定义属性或方法。如果为空，则名称后面的括号是可选的。我将打印它的类型（`__main__`是顶层代码执行的范围的名称），我知道，在注释中，我写的是*object*而不是*class*。事实证明，正如您可以从`print`的结果中看到的那样，*类实际上是对象*。准确地说，它们是`type`的实例。解释这个概念将导致我们讨论**元类**和**元编程**，这些是需要牢固掌握基本原理才能理解的高级概念，超出了本章的范围。像往常一样，我提到它是为了给您留下一个指针，以便在您准备深入了解时使用。

让我们回到这个例子：我使用`Simplest`创建了一个实例`simp`。您可以看到创建实例的语法与我们调用函数的方式相同。然后我们打印`simp`属于的类型，并验证`simp`实际上是`Simplest`的一个实例。我将在本章后面向您展示更好的方法。

到目前为止，一切都很简单。但是，当我们写`class ClassName(): pass`时会发生什么呢？嗯，Python 所做的是创建一个类对象并为其分配一个名称。这与我们使用`def`声明函数时发生的情况非常相似。

# 类和对象的命名空间

在类对象创建后（通常在模块首次导入时发生），它基本上代表一个命名空间。我们可以调用该类来创建其实例。每个实例都继承了类属性和方法，并被赋予了自己的命名空间。我们已经知道，要遍历命名空间，我们只需要使用点（`.`）运算符。

让我们看另一个例子：

```py
# oop/class.namespaces.py
class Person:
    species = 'Human'

print(Person.species)  # Human
Person.alive = True  # Added dynamically!
print(Person.alive)  # True

man = Person()
print(man.species)  # Human (inherited)
print(man.alive)  # True (inherited)

Person.alive = False
print(man.alive)  # False (inherited)

man.name = 'Darth'
man.surname = 'Vader'
print(man.name, man.surname)  # Darth Vader
```

在上面的例子中，我定义了一个名为`species`的类属性。在类的主体中定义的任何变量都是属于该类的属性。在代码中，我还定义了`Person.alive`，这是另一个类属性。你可以看到从类中访问该属性没有限制。你可以看到`man`是`Person`的一个实例，它继承了它们两个，并在它们改变时立即反映出来。

`man`也有两个属于它自己命名空间的属性，因此被称为**实例属性**：`name`和`surname`。

类属性在所有实例之间共享，而实例属性不共享；因此，你应该使用类属性来提供所有实例共享的状态和行为，并使用实例属性来存储只属于一个特定对象的数据。

# 属性遮蔽

当你在对象中搜索属性时，如果没有找到，Python 会继续在用于创建该对象的类中搜索（并一直搜索，直到找到或达到继承链的末尾）。这导致了一个有趣的遮蔽行为。让我们看另一个例子：

```py
# oop/class.attribute.shadowing.py
class Point:
    x = 10
    y = 7

p = Point()
print(p.x)  # 10 (from class attribute)
print(p.y)  # 7 (from class attribute)

p.x = 12  # p gets its own `x` attribute
print(p.x)  # 12 (now found on the instance)
print(Point.x)  # 10 (class attribute still the same)

del p.x  # we delete instance attribute
print(p.x)  # 10 (now search has to go again to find class attr)

p.z = 3  # let's make it a 3D point
print(p.z)  # 3

print(Point.z)
# AttributeError: type object 'Point' has no attribute 'z'
```

前面的代码非常有趣。我们定义了一个名为`Point`的类，其中有两个类属性`x`和`y`。当我们创建一个实例`p`时，你可以看到我们可以从`p`的命名空间（`p.x`和`p.y`）打印出`x`和`y`。当我们这样做时，Python 在实例上找不到任何`x`或`y`属性，因此搜索类，并在那里找到它们。

然后我们通过分配`p.x = 12`给`p`赋予了它自己的`x`属性。这种行为一开始可能看起来有点奇怪，但是如果你仔细想想，它与在函数中发生的事情完全相同，当外部有一个全局`x = 10`时，函数声明`x = 12`。我们知道`x = 12`不会影响全局变量，对于类和实例来说，情况也是一样的。

在分配`p.x = 12`之后，当我们打印它时，搜索不需要读取类属性，因为`x`在实例中找到了，因此我们得到了`12`的输出。我们还打印了`Point.x`，它指的是类命名空间中的`x`。

然后，我们从`p`的命名空间中删除`x`，这意味着在下一行，当我们再次打印它时，Python 将再次在类中搜索它，因为它在实例中不再被找到。

最后三行向你展示了将属性分配给实例并不意味着它们将在类中被找到。实例得到了类中的所有内容，但反之则不成立。

你认为将`x`和`y`坐标作为类属性是一个好主意吗？如果你添加另一个`Point`的实例会怎么样？这是否有助于说明类属性为什么非常有用？

# 我自己和我 - 使用 self 变量

在类方法内部，我们可以通过一个特殊的参数`self`来引用一个实例，按照惯例称之为`self`。`self`始终是实例方法的第一个属性。让我们一起研究这种行为，以及我们如何可以与所有实例共享，不仅是属性，还有方法：

```py
# oop/class.self.py
class Square:
    side = 8
    def area(self):  # self is a reference to an instance
        return self.side ** 2

sq = Square()
print(sq.area())  # 64 (side is found on the class)
print(Square.area(sq))  # 64 (equivalent to sq.area())

sq.side = 10
print(sq.area())  # 100 (side is found on the instance)
```

注意`area`方法如何被`sq`使用。两个调用`Square.area(sq)`和`sq.area()`是等价的，并教会我们机制是如何工作的。你可以将实例传递给方法调用（`Square.area(sq)`），在方法内部将使用名称`self`，或者你可以使用更舒适的语法`sq.area()`，Python 会在幕后为你翻译它。

让我们看一个更好的例子：

```py
# oop/class.price.py
class Price:
    def final_price(self, vat, discount=0):
        """Returns price after applying vat and fixed discount."""
        return (self.net_price * (100 + vat) / 100) - discount

p1 = Price()
p1.net_price = 100
print(Price.final_price(p1, 20, 10))  # 110 (100 * 1.2 - 10)
print(p1.final_price(20, 10))  # equivalent
```

前面的代码向您展示了，在声明方法时没有任何阻止我们使用参数。我们可以使用与函数相同的语法，但需要记住第一个参数始终是实例。我们不一定需要将其称为`self`，但这是约定，这是为数不多的非常重要遵守的情况之一。

# 初始化实例

您是否注意到，在调用`p1.final_price(...)`之前，我们必须将`net_price`赋给`p1`？有更好的方法可以做到这一点。在其他语言中，这将被称为**构造函数**，但在 Python 中不是。它实际上是一个**初始化程序**，因为它在已创建的实例上工作，因此被称为`__init__`。它是一个*魔术方法*，在对象创建后立即运行。Python 对象还有一个`__new__`方法，这才是真正的构造函数。实际上，我们通常不需要覆盖它，这种做法在编写元类时才会用到，正如我们提到的，这是一个相当高级的主题，我们不会在本书中探讨：

```py
# oop/class.init.py
class Rectangle:
    def __init__(self, side_a, side_b):
        self.side_a = side_a
        self.side_b = side_b

    def area(self):
        return self.side_a * self.side_b

r1 = Rectangle(10, 4)
print(r1.side_a, r1.side_b)  # 10 4
print(r1.area())  # 40

r2 = Rectangle(7, 3)
print(r2.area())  # 21
```

事情终于开始有了眉目。当一个对象被创建时，`__init__`方法会自动运行。在这种情况下，我编写了这样一个代码，当我们创建一个对象（通过调用类名像调用函数一样），我们传递参数给创建调用，就像我们在任何常规函数调用中一样。我们传递参数的方式遵循`__init__`方法的签名，因此，在两个创建语句中，`10`和`7`将分别成为`r1`和`r2`的`side_a`，而`4`和`3`将成为`side_b`。您可以看到从`r1`和`r2`调用`area()`反映了它们具有不同的实例参数。以这种方式设置对象更加美观和方便。

# OOP 是关于代码重用的

到目前为止，应该很清楚：*OOP 是关于代码重用的*。我们定义一个类，创建实例，这些实例使用仅在类中定义的方法。它们将根据初始化程序设置实例的方式而表现出不同的行为。

# 继承和组合

但这只是故事的一半，*OOP 更加强大*。我们有两个主要的设计构造可以利用：继承和组合。

**继承**意味着两个对象通过*是一个*类型的关系相关联。另一方面，**组合**意味着两个对象通过*有一个*类型的关系相关联。这一切都很容易通过一个例子来解释：

```py
# oop/class_inheritance.py
class Engine:
    def start(self):
        pass

    def stop(self):
        pass

class ElectricEngine(Engine):  # Is-A Engine
    pass

class V8Engine(Engine):  # Is-A Engine
    pass

class Car:
    engine_cls = Engine

    def __init__(self):
        self.engine = self.engine_cls()  # Has-A Engine

    def start(self):
        print(
            'Starting engine {0} for car {1}... Wroom, wroom!'
            .format(
                self.engine.__class__.__name__,
                self.__class__.__name__)
        )
        self.engine.start()

    def stop(self):
        self.engine.stop()

class RaceCar(Car):  # Is-A Car
    engine_cls = V8Engine

class CityCar(Car):  # Is-A Car
    engine_cls = ElectricEngine

class F1Car(RaceCar):  # Is-A RaceCar and also Is-A Car
    pass  # engine_cls same as parent

car = Car()
racecar = RaceCar()
citycar = CityCar()
f1car = F1Car()
cars = [car, racecar, citycar, f1car]

for car in cars:
    car.start()

""" Prints:
Starting engine Engine for car Car... Wroom, wroom!
Starting engine V8Engine for car RaceCar... Wroom, wroom!
Starting engine ElectricEngine for car CityCar... Wroom, wroom!
Starting engine V8Engine for car F1Car... Wroom, wroom!
"""
```

前面的例子向您展示了对象之间*是一个*和*有一个*类型的关系。首先，让我们考虑`Engine`。这是一个简单的类，有两个方法，`start`和`stop`。然后我们定义了`ElectricEngine`和`V8Engine`，它们都继承自`Engine`。您可以看到，当我们定义它们时，在类名后面的括号中放入了`Engine`，这表明它们继承自`Engine`。

这意味着`ElectricEngine`和`V8Engine`都继承自`Engine`类的属性和方法，这被称为它们的**基类**。

汽车也是如此。`Car`是`RaceCar`和`CityCar`的基类。`RaceCar`也是`F1Car`的基类。另一种说法是，`F1Car`继承自`RaceCar`，`RaceCar`继承自`Car`。因此，`F1Car`*是一个*`RaceCar`，`RaceCar`*是一个*`Car`。由于传递性，我们也可以说`F1Car`*是一个*`Car`。`CityCar`也是*是一个*`Car`。

当我们定义`class A(B): pass`时，我们说`A`是`B`的*子类*，而`B`是`A`的*父类*。*父类*和*基类*是同义词，*子类*和*派生类*也是。此外，我们说一个类从另一个类继承，或者扩展它。

这就是继承机制。

另一方面，让我们回到代码。每个类都有一个类属性`engine_cls`，它是我们想要分配给每种类型汽车的发动机类的引用。`Car`有一个通用的`Engine`，而两辆赛车有一个强大的 V8 发动机，城市车有一个电动发动机。

当在初始化方法`__init__`中创建汽车时，我们创建分配给汽车的任何发动机类的实例，并将其设置为`engine`实例属性。

让`engine_cls`在所有类实例之间共享是有道理的，因为很可能同一辆车的实例会有相同类型的发动机。另一方面，将一个单一的发动机（任何`Engine`类的实例）作为类属性是不好的，因为我们会在所有实例之间共享一个发动机，这是不正确的。

汽车和发动机之间的关系类型是*Has-A*类型。汽车*Has-A*发动机。这被称为**组合**，反映了对象可以由许多其他对象组成的事实。汽车*Has-A*发动机、齿轮、车轮、车架、车门、座椅等等。

在设计面向对象的代码时，以这种方式描述对象非常重要，这样我们才能正确地使用继承和组合来最佳地构造我们的代码。

请注意，我必须避免在`class_inheritance.py`脚本名称中使用点，因为模块名称中的点使导入变得困难。书中源代码中的大多数模块都是作为独立脚本运行的，因此我选择在可能的情况下添加点以增强可读性，但一般来说，你应该避免在模块名称中使用点。

在我们离开这一段之前，让我们通过另一个示例来检查我是否告诉了你真相：

```py
# oop/class.issubclass.isinstance.py
from class_inheritance import Car, RaceCar, F1Car

car = Car()
racecar = RaceCar()
f1car = F1Car()
cars = [(car, 'car'), (racecar, 'racecar'), (f1car, 'f1car')]
car_classes = [Car, RaceCar, F1Car]

for car, car_name in cars:
    for class_ in car_classes:
        belongs = isinstance(car, class_)
        msg = 'is a' if belongs else 'is not a'
        print(car_name, msg, class_.__name__)

""" Prints:
car is a Car
car is not a RaceCar
car is not a F1Car
racecar is a Car
racecar is a RaceCar
racecar is not a F1Car
f1car is a Car
f1car is a RaceCar
f1car is a F1Car
"""
```

正如你所看到的，`car`只是`Car`的一个实例，而`racecar`是`RaceCar`的一个实例（通过扩展也是`Car`的一个实例），`f1car`是`F1Car`的一个实例（通过扩展也是`RaceCar`和`Car`的一个实例）。*banana*是*banana*的一个实例。但是，它也是*Fruit*。同时，它也是*Food*，对吧？这是相同的概念。要检查对象是否是类的实例，请使用`isinstance`方法。它比纯粹的类型比较更可取：`(type(object) == Class)`。

请注意，我没有在实例化汽车时留下打印信息。我们在上一个示例中看到了它们。

让我们也来检查继承-相同的设置，不同的逻辑在`for`循环中：

```py
# oop/class.issubclass.isinstance.py
for class1 in car_classes:
    for class2 in car_classes:
        is_subclass = issubclass(class1, class2)
        msg = '{0} a subclass of'.format(
            'is' if is_subclass else 'is not')
        print(class1.__name__, msg, class2.__name__)

""" Prints:
Car is a subclass of Car
Car is not a subclass of RaceCar
Car is not a subclass of F1Car
RaceCar is a subclass of Car
RaceCar is a subclass of RaceCar
RaceCar is not a subclass of F1Car
F1Car is a subclass of Car
F1Car is a subclass of RaceCar
F1Car is a subclass of F1Car
"""
```

有趣的是，我们了解到*一个类是其自身的子类*。检查前面示例的输出，看看它是否与我提供的解释相匹配。

关于惯例的一件事要注意的是，类名始终使用`CapWords`编写，这意味着`ThisWayIsCorrect`，而不是函数和方法，它们是`this_way_is_correct`。此外，在代码中，如果要使用 Python 保留的关键字或内置函数或类的名称，惯例是在名称后添加下划线。在第一个`for`循环示例中，我正在使用`for class_ in ...`循环遍历类名，因为`class`是一个保留字。但你已经知道这一切，因为你已经彻底研究了 PEP8，对吧？

为了帮助你理解*Is-A*和*Has-A*之间的区别，请看下面的图表：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00010.jpeg)

# 访问基类

我们已经看到了类声明，比如`class ClassA: pass`和`class ClassB(BaseClassName): pass`。当我们不明确指定基类时，Python 会将特殊的**object**类设置为我们正在定义的类的基类。最终，所有类都源自一个对象。请注意，如果不指定基类，括号是可选的。

因此，编写`class A: pass`或`class A(): pass`或`class A(object): pass`都是完全相同的。*object*类是一个特殊的类，它具有所有 Python 类共有的方法，并且不允许你在其上设置任何属性。

让我们看看如何从类内部访问基类：

```py
# oop/super.duplication.py
class Book:
    def __init__(self, title, publisher, pages):
        self.title = title
        self.publisher = publisher
        self.pages = pages

class Ebook(Book):
    def __init__(self, title, publisher, pages, format_):
        self.title = title
        self.publisher = publisher
        self.pages = pages
        self.format_ = format_
```

看一下前面的代码。`Ebook`中有三个输入参数是重复的。这是非常糟糕的做法，因为我们现在有两组执行相同操作的指令。此外，`Book.__init__`签名的任何更改都不会反映在`Ebook`中。我们知道`Ebook`*是一个*`Book`，因此我们可能希望更改能够反映在子类中。

让我们看一种解决这个问题的方法：

```py
# oop/super.explicit.py
class Book:
    def __init__(self, title, publisher, pages):
        self.title = title
        self.publisher = publisher
        self.pages = pages

class Ebook(Book):
    def __init__(self, title, publisher, pages, format_):
        Book.__init__(self, title, publisher, pages)
        self.format_ = format_

ebook = Ebook(
    'Learn Python Programming', 'Packt Publishing', 500, 'PDF')
print(ebook.title)  # Learn Python Programming
print(ebook.publisher)  # Packt Publishing
print(ebook.pages)  # 500
print(ebook.format_)  # PDF
```

现在好多了。我们去掉了那个讨厌的重复。基本上，我们告诉 Python 调用`Book`类的`__init__`方法，并将`self`传递给调用，确保将该调用绑定到当前实例。

如果我们修改`Book`的`__init__`方法中的逻辑，我们不需要触及`Ebook`，它将自动适应更改。

这种方法很好，但我们仍然可以做得更好一点。假设我们将`Book`的名称更改为`Liber`，因为我们爱上了拉丁语。我们必须修改`Ebook`的`__init__`方法以反映这一变化。这可以通过使用`super`来避免：

```py
# oop/super.implicit.py
class Book:
    def __init__(self, title, publisher, pages):
        self.title = title
        self.publisher = publisher
        self.pages = pages

class Ebook(Book):
    def __init__(self, title, publisher, pages, format_):
        super().__init__(title, publisher, pages)
        # Another way to do the same thing is:
        # super(Ebook, self).__init__(title, publisher, pages)
        self.format_ = format_

ebook = Ebook(
    'Learn Python Programming', 'Packt Publishing', 500, 'PDF')
print(ebook.title) # Learn Python Programming
print(ebook.publisher) # Packt Publishing
print(ebook.pages) # 500
print(ebook.format_) # PDF
```

`super`是一个返回代理对象的函数，该代理对象将方法调用委托给父类或同级类。在这种情况下，它将该调用委托给`Book`类的`__init__`，这种方法的美妙之处在于现在我们甚至可以自由地将`Book`更改为`Liber`，而不必触及`Ebook`的`__init__`方法中的逻辑。

现在我们知道如何从子类访问基类，让我们来探索 Python 的多重继承。

# 多重继承

除了使用多个基类来组成一个类之外，这里感兴趣的是属性搜索是如何执行的。看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/lrn-py-prog-2e/img/00011.jpeg)

正如你所看到的，`Shape`和`Plotter`充当了所有其他类的基类。`Polygon`直接从它们继承，`RegularPolygon`从`Polygon`继承，而`RegularHexagon`和`Square`都从`RegulaPolygon`继承。还要注意，`Shape`和`Plotter`隐式地从`object`继承，因此我们有了所谓的**菱形**，或者更简单地说，有多条路径到达基类。我们将在几分钟后看到为什么这很重要。让我们将其翻译成一些简单的代码：

```py
# oop/multiple.inheritance.py
class Shape:
    geometric_type = 'Generic Shape'
    def area(self):  # This acts as placeholder for the interface
        raise NotImplementedError
    def get_geometric_type(self):
        return self.geometric_type

class Plotter:
    def plot(self, ratio, topleft):
        # Imagine some nice plotting logic here...
        print('Plotting at {}, ratio {}.'.format(
            topleft, ratio))

class Polygon(Shape, Plotter):  # base class for polygons
    geometric_type = 'Polygon'

class RegularPolygon(Polygon):  # Is-A Polygon
    geometric_type = 'Regular Polygon'
    def __init__(self, side):
        self.side = side

class RegularHexagon(RegularPolygon):  # Is-A RegularPolygon
    geometric_type = 'RegularHexagon'
    def area(self):
        return 1.5 * (3 ** .5 * self.side ** 2)

class Square(RegularPolygon):  # Is-A RegularPolygon
    geometric_type = 'Square'
    def area(self):
        return self.side * self.side

hexagon = RegularHexagon(10)
print(hexagon.area())  # 259.8076211353316
print(hexagon.get_geometric_type())  # RegularHexagon
hexagon.plot(0.8, (75, 77))  # Plotting at (75, 77), ratio 0.8.

square = Square(12)
print(square.area())  # 144
print(square.get_geometric_type())  # Square
square.plot(0.93, (74, 75))  # Plotting at (74, 75), ratio 0.93.
```

看一下前面的代码：`Shape`类有一个属性`geometric_type`和两个方法：`area`和`get_geometric_type`。通常使用基类（例如我们的例子中的`Shape`）来定义一个*接口*是很常见的，子类必须提供这些方法的实现。有不同和更好的方法来做到这一点，但我想尽可能地保持这个例子简单。

我们还有`Plotter`类，它添加了`plot`方法，从而为任何继承它的类提供绘图功能。当然，在这个例子中，`plot`的实现只是一个虚拟的`print`。第一个有趣的类是`Polygon`，它同时继承自`Shape`和`Plotter`。

有许多类型的多边形，其中之一是正多边形，它既是等角的（所有角度相等），又是等边的（所有边相等），因此我们创建了从`Polygon`继承的`RegularPolygon`类。对于正多边形，我们可以在`RegularPolygon`上实现一个简单的`__init__`方法，它接受边长。最后，我们创建了`RegularHexagon`和`Square`类，它们都继承自`RegularPolygon`。

这个结构相当长，但希望能让你了解在设计代码时如何专门化对象的分类。

现在，请看最后八行。请注意，当我在`hexagon`和`square`上调用`area`方法时，我得到了两者的正确面积。这是因为它们都提供了正确的实现逻辑。此外，我可以在它们两个上调用`get_geometric_type`，即使它没有在它们的类上定义，Python 也必须一直到`Shape`才能找到它的实现。请注意，即使实现是在`Shape`类中提供的，用于返回值的`self.geometric_type`也是从调用实例中正确获取的。

`plot`方法的调用也很有趣，并且向您展示了如何为对象增加它们本来没有的功能。这种技术在诸如 Django（我们将在第十四章中探索*Web Development*）这样的 Web 框架中非常受欢迎，它提供了称为**mixins**的特殊类，您可以直接使用其功能。您只需要将所需的 mixin 定义为自己的基类之一，就可以了。

多重继承很强大，但也可能变得非常混乱，因此我们需要确保了解在使用它时会发生什么。

# 方法解析顺序

到目前为止，我们知道当您要求`someobject.attribute`，并且在该对象上找不到`attribute`时，Python 会开始在创建`someobject`的类中搜索。如果那里也找不到，Python 会沿着继承链向上搜索，直到找到`attribute`或者到达`object`类。如果继承链只由单继承步骤组成，这是很容易理解的，这意味着类只有一个父类。然而，当涉及到多重继承时，有时很难预测如果找不到属性，下一个将被搜索的类是什么。

Python 提供了一种始终了解类在属性查找中被搜索顺序的方法：**Method Resolution Order**（**MRO**）。

MRO 是在查找期间搜索成员的基类的顺序。从 2.3 版本开始，Python 使用一种称为**C3**的算法，它保证了单调性。

在 Python 2.2 中引入了*新式类*。在 Python 2.*中编写新式类的方式是使用显式的`object`基类进行定义。经典类没有明确继承自`object`，并且在 Python 3 中已被移除。Python 2.*中经典类和新式类之间的一个区别是新式类使用新的 MRO 进行搜索。

关于前面的例子，让我们看看`Square`类的 MRO：

```py
# oop/multiple.inheritance.py
print(square.__class__.__mro__)
# prints:
# (<class '__main__.Square'>, <class '__main__.RegularPolygon'>,
# <class '__main__.Polygon'>, <class '__main__.Shape'>,
# <class '__main__.Plotter'>, <class 'object'>)
```

要获得类的 MRO，我们可以从实例到其`__class__`属性，然后从那里到其`__mro__`属性。或者，我们可以直接调用`Square.__mro__`或`Square.mro()`，但如果你必须动态地执行它，更有可能你会有一个对象而不是一个类。

请注意，唯一的疑点是在`Polygon`之后的二分，继承链分为两种方式：一种通向`Shape`，另一种通向`Plotter`。通过扫描`Square`类的 MRO，我们知道`Shape`在`Plotter`之前被搜索。

为什么这很重要？好吧，考虑以下代码：

```py
# oop/mro.simple.py
class A:
    label = 'a'

class B(A):
    label = 'b'

class C(A):
    label = 'c'

class D(B, C):
    pass

d = D()
print(d.label)  # Hypothetically this could be either 'b' or 'c'
```

`B`和`C`都继承自`A`，`D`同时继承自`B`和`C`。这意味着查找`label`属性可以通过`B`或`C`到达顶部（`A`）。根据首先到达的位置，我们会得到不同的结果。

因此，在前面的例子中，我们得到了`'b'`，这是我们所期望的，因为`B`是`D`的基类中最左边的一个。但是如果我从`B`中删除`label`属性会发生什么呢？这将是一个令人困惑的情况：算法会一直到达`A`还是首先到达`C`？让我们找出来：

```py
# oop/mro.py
class A:
    label = 'a'

class B(A):
    pass  # was: label = 'b'

class C(A):
    label = 'c'

class D(B, C):
    pass

d = D()
print(d.label)  # 'c'
print(d.__class__.mro())  # notice another way to get the MRO
# prints:
# [<class '__main__.D'>, <class '__main__.B'>,
# <class '__main__.C'>, <class '__main__.A'>, <class 'object'>]
```

因此，我们了解到 MRO 是`D`-`B`-`C`-`A`-`object`，这意味着当我们要求`d.label`时，我们得到的是`'c'`，这是正确的。

在日常编程中，通常不常见需要处理 MRO，但第一次与框架中的一些混合物作斗争时，我向您保证，您会很高兴我花了一段时间来解释它。

# 类和静态方法

到目前为止，我们已经编写了具有数据和实例方法形式属性的类，但是还有两种类型的方法可以放在类中：**静态方法**和**类方法**。

# 静态方法

您可能还记得，当您创建一个类对象时，Python 会为其分配一个名称。该名称充当命名空间，有时将功能分组在其下是有意义的。静态方法非常适合这种用例，因为与实例方法不同，它们不会传递任何特殊参数。让我们看一个虚构的`StringUtil`类的示例：

```py
# oop/static.methods.py
class StringUtil:

    @staticmethod
    def is_palindrome(s, case_insensitive=True):
        # we allow only letters and numbers
        s = ''.join(c for c in s if c.isalnum())  # Study this!
        # For case insensitive comparison, we lower-case s
        if case_insensitive:
            s = s.lower()
        for c in range(len(s) // 2):
            if s[c] != s[-c -1]:
                return False
        return True

    @staticmethod
    def get_unique_words(sentence):
        return set(sentence.split())

print(StringUtil.is_palindrome(
    'Radar', case_insensitive=False))  # False: Case Sensitive
print(StringUtil.is_palindrome('A nut for a jar of tuna'))  # True
print(StringUtil.is_palindrome('Never Odd, Or Even!'))  # True
print(StringUtil.is_palindrome(
    'In Girum Imus Nocte Et Consumimur Igni')  # Latin! Show-off!
)  # True

print(StringUtil.get_unique_words(
    'I love palindromes. I really really love them!'))
# {'them!', 'really', 'palindromes.', 'I', 'love'}
```

前面的代码非常有趣。首先，我们了解到静态方法是通过简单地将`staticmethod`装饰器应用于它们来创建的。您可以看到它们没有传递任何特殊参数，因此除了装饰之外，它们看起来确实就像函数。

我们有一个名为`StringUtil`的类，它充当函数的容器。另一种方法是使用内部函数的单独模块。大多数情况下，这实际上是一种偏好。

`is_palindrome` 中的逻辑现在应该对您来说很简单，但以防万一，让我们来看一下。首先，我们从`s`中删除所有既不是字母也不是数字的字符。为了做到这一点，我们使用字符串对象（在本例中是空字符串对象）的`join`方法。通过在空字符串上调用`join`，结果是将传递给`join`的可迭代对象中的所有元素连接在一起。我们向`join`提供了一个生成器表达式，该表达式表示如果字符是字母数字或数字，则从`s`中取任何字符。这是因为在回文句子中，我们希望丢弃任何不是字符或数字的内容。

如果`case_insensitive`为`True`，我们将转换`s`为小写，然后继续检查它是否是回文。为了做到这一点，我们比较第一个和最后一个字符，然后比较第二个和倒数第二个字符，依此类推。如果我们在任何时候发现差异，这意味着字符串不是回文，因此我们可以返回`False`。另一方面，如果我们正常退出`for`循环，这意味着没有发现任何差异，因此我们可以说字符串是回文。

请注意，无论字符串的长度是奇数还是偶数，此代码都能正确工作。`len(s) // 2` 可以达到`s`的一半，如果`s`的字符数量是奇数，中间的字符不会被检查（比如在 *RaDaR* 中，*D* 不会被检查），但我们不在乎；它将与自身进行比较，因此始终通过该检查。

`get_unique_words`要简单得多：它只返回一个集合，我们向其中提供了一个句子中的单词列表。`set`类为我们删除了任何重复项，因此我们不需要做其他任何事情。

`StringUtil`类为我们提供了一个很好的容器命名空间，用于处理字符串的方法。我本可以编写一个类似的示例，使用`MathUtil`类和一些静态方法来处理数字，但我想向您展示一些不同的东西。

# 类方法

类方法与静态方法略有不同，因为与实例方法一样，它们也需要一个特殊的第一个参数，但在这种情况下，它是类对象本身。编写类方法的一个非常常见的用例是为类提供工厂功能。让我们看一个示例：

```py
# oop/class.methods.factory.py
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    @classmethod
    def from_tuple(cls, coords):  # cls is Point
        return cls(*coords)

    @classmethod
    def from_point(cls, point):  # cls is Point
        return cls(point.x, point.y)

p = Point.from_tuple((3, 7))
print(p.x, p.y)  # 3 7
q = Point.from_point(p)
print(q.x, q.y)  # 3 7
```

在前面的代码中，我向你展示了如何使用类方法来创建类的工厂。在这种情况下，我们希望通过传递两个坐标（常规创建`p = Point(3, 7)`）来创建一个`Point`实例，但我们也希望能够通过传递一个元组（`Point.from_tuple`）或另一个实例（`Point.from_point`）来创建一个实例。

在这两个类方法中，`cls`参数指的是`Point`类。与实例方法一样，实例方法以`self`作为第一个参数，类方法以`cls`作为参数。`self`和`cls`都是根据约定命名的，你不是被强制遵循，但强烈鼓励尊重。这是没有 Python 程序员会更改的东西，因为它是一个如此强大的约定，解析器、linter 和任何自动处理代码的工具都会期望，所以最好坚持遵循它。

类方法和静态方法很好地配合。静态方法实际上在分解类方法的逻辑以改进其布局方面非常有帮助。让我们通过重构`StringUtil`类来看一个例子：

```py
# oop/class.methods.split.py
class StringUtil:

    @classmethod
    def is_palindrome(cls, s, case_insensitive=True):
        s = cls._strip_string(s)
        # For case insensitive comparison, we lower-case s
        if case_insensitive:
            s = s.lower()
        return cls._is_palindrome(s)

    @staticmethod
    def _strip_string(s):
        return ''.join(c for c in s if c.isalnum())

    @staticmethod
    def _is_palindrome(s):
        for c in range(len(s) // 2):
            if s[c] != s[-c -1]:
                return False
        return True

    @staticmethod
    def get_unique_words(sentence):
        return set(sentence.split())

print(StringUtil.is_palindrome('A nut for a jar of tuna'))  # True
print(StringUtil.is_palindrome('A nut for a jar of beans'))  # False
```

将这段代码与以前的版本进行比较。首先，请注意，即使`is_palindrome`现在是一个类方法，我们调用它的方式与它是静态方法时的调用方式相同。我们将它更改为类方法的原因是，在提取出一些逻辑片段（`_strip_string`和`_is_palindrome`）之后，我们需要引用它们，如果我们的方法中没有`cls`，唯一的选择就是这样调用它们：`StringUtil._strip_string(...)`和`StringUtil._is_palindrome(...)`，这不是一个好的做法，因为我们会在`is_palindrome`方法中硬编码类名，这样我们就会置自己于在想要更改类名时必须修改它的位置。使用`cls`将作为类名，这意味着我们的代码不需要任何修改。

注意新的逻辑读起来比以前的版本好得多。此外，注意，通过在*提取出来*的方法前加下划线，我暗示这些方法不应该从类外部调用，但这将是下一段的主题。

# 私有方法和名称混淆

如果你有 Java、C#或 C++等语言的背景，那么你知道它们允许程序员为属性（数据和方法）分配隐私状态。每种语言对此有自己略有不同的特点，但主要是公共属性可以从代码中的任何地方访问，而私有属性只能在其定义的范围内访问。

在 Python 中，没有这样的东西。一切都是公开的；因此，我们依赖于约定和一种称为**名称混淆**的机制。

约定如下：如果属性的名称没有下划线，它被认为是公共的。这意味着你可以自由访问和修改它。当名称有一个下划线时，属性被认为是私有的，这意味着它可能是用于内部使用的，你不应该从外部使用或修改它。私有属性的一个非常常见的用例是辅助方法，它们应该被公共方法使用（可能与其他方法一起调用链），以及内部数据，例如缩放因子，或者理想情况下我们会将其放在一个常量中（一个不能改变的变量，但是，惊讶的是，Python 也没有这些）。

这个特性通常会吓跑其他背景的人；他们会因为缺乏隐私而感到受到威胁。老实说，在我整个与 Python 的专业经验中，我从来没有听说过有人因为 Python 缺乏私有属性而尖叫“*哦，天哪，我们因为 Python 缺乏私有属性而有了一个可怕的错误！*”我发誓没有一次。

也就是说，对隐私的呼吁实际上是有道理的，因为没有它，你会真正地在你的代码中引入错误。让我告诉你我的意思：

```py
# oop/private.attrs.py
class A:
    def __init__(self, factor):
        self._factor = factor

    def op1(self):
        print('Op1 with factor {}...'.format(self._factor))

class B(A):
    def op2(self, factor):
        self._factor = factor
        print('Op2 with factor {}...'.format(self._factor))

obj = B(100)
obj.op1()    # Op1 with factor 100...
obj.op2(42)  # Op2 with factor 42...
obj.op1()    # Op1 with factor 42... <- This is BAD
```

在前面的代码中，我们有一个名为`_factor`的属性，假设它非常重要，不希望在创建实例后在运行时被修改，因为`op1`依赖于它才能正确运行。我们用一个前导下划线命名它，但问题在于当我们调用`obj.op2(42)`时，我们修改了它，并且这在后续调用`op1`时也会反映出来。

让我们通过添加另一个前导下划线来修复这种不良行为：

```py
# oop/private.attrs.fixed.py
class A:
    def __init__(self, factor):
        self.__factor = factor

    def op1(self):
        print('Op1 with factor {}...'.format(self.__factor))

class B(A):
    def op2(self, factor):
        self.__factor = factor
        print('Op2 with factor {}...'.format(self.__factor))

obj = B(100)
obj.op1()    # Op1 with factor 100...
obj.op2(42)  # Op2 with factor 42...
obj.op1()    # Op1 with factor 100... <- Wohoo! Now it's GOOD!
```

哇，看那个！现在它按预期工作了。Python 有点神奇，在这种情况下，发生的是名称修饰机制已经启动。

名称修饰意味着任何属性名称至少有两个前导下划线和最多一个尾随下划线，例如`__my_attr`，将被替换为一个包含下划线和类名的名称，然后是实际名称，例如`_ClassName__my_attr`。

这意味着当你从一个类继承时，修饰机制会在基类和子类中给你的私有属性取两个不同的名称，以避免名称冲突。每个类和实例对象都在一个特殊的属性`__dict__`中存储对它们的属性的引用，所以让我们检查`obj.__dict__`来看看名称修饰是如何起作用的：

```py
# oop/private.attrs.py
print(obj.__dict__.keys())
# dict_keys(['_factor'])
```

这是我们在这个例子的有问题版本中找到的`_factor`属性。但是看看使用`__factor`的那个：

```py
# oop/private.attrs.fixed.py
print(obj.__dict__.keys())
# dict_keys(['_A__factor', '_B__factor'])
```

看到了吗？`obj`现在有两个属性，`_A__factor`（在`A`类中修饰）和`_B__factor`（在`B`类中修饰）。这就是确保当你执行`obj.__factor = 42`时，`A`中的`__factor`不会改变的机制，因为你实际上是在触及`_B__factor`，这样就保留了`_A__factor`的安全和完整。

如果你正在设计一个希望被其他开发人员使用和扩展的类库，你需要牢记这一点，以避免意外覆盖你的属性。这样的错误可能相当微妙，很难发现。

# 属性装饰器

还有一件不得不提的事情是`property`装饰器。想象一下，你在一个`Person`类中有一个`age`属性，而且在某个时候你想要确保当你改变它的值时，你也要检查`age`是否在一个合适的范围内，比如[18, 99]。你可以编写访问器方法，比如`get_age()`和`set_age(...)`（也称为**getter**和**setter**），并在那里放置逻辑。`get_age()`很可能只是返回`age`，而`set_age(...)`也会进行范围检查。问题是，你可能已经有很多直接访问`age`属性的代码，这意味着你现在需要进行一些繁琐的重构。像 Java 这样的语言通过默认使用访问器模式来解决这个问题。许多 Java **集成开发环境**（**IDE**）会在你写属性声明时自动为你编写 getter 和 setter 访问器方法的存根。

Python 更聪明，它可以使用`property`装饰器来实现这一点。当你用`property`装饰一个方法时，你可以像使用数据属性一样使用方法的名称。因此，最好不要在这样的方法中放入需要花费一些时间才能完成的逻辑，因为通过访问它们作为属性，我们不希望等待。

让我们看一个例子：

```py
# oop/property.py
class Person:
    def __init__(self, age):
        self.age = age  # anyone can modify this freely

class PersonWithAccessors:
    def __init__(self, age):
        self._age = age

    def get_age(self):
        return self._age

    def set_age(self, age):
        if 18 <= age <= 99:
            self._age = age
        else:
            raise ValueError('Age must be within [18, 99]')

class PersonPythonic:
    def __init__(self, age):
        self._age = age

    @property
    def age(self):
        return self._age

    @age.setter
    def age(self, age):
        if 18 <= age <= 99:
            self._age = age
        else:
            raise ValueError('Age must be within [18, 99]')

person = PersonPythonic(39)
print(person.age)  # 39 - Notice we access as data attribute
person.age = 42    # Notice we access as data attribute
print(person.age)  # 42
person.age = 100   # ValueError: Age must be within [18, 99]
```

`Person`类可能是我们编写的第一个版本。然后我们意识到我们需要放置范围逻辑，所以，用另一种语言，我们需要将`Person`重写为`PersonWithAccessors`类，并重构所有使用`Person.age`的代码。在 Python 中，我们将`Person`重写为`PersonPythonic`（当然通常不会更改名称），这样年龄就存储在私有的`_age`变量中，并且我们使用装饰器定义属性的 getter 和 setter，这使我们可以像以前一样继续使用`person`实例。getter 是在我们读取属性时调用的方法。另一方面，setter 是在我们写入属性时调用的方法。在其他语言中，比如 Java，习惯上将它们定义为`get_age()`和`set_age(int value)`，但我觉得 Python 的语法更整洁。它允许你开始编写简单的代码，以后再进行重构，只有在需要时才需要，没有必要因为它们可能在将来有用而污染你的代码。

`property`装饰器还允许只读数据（没有 setter）以及在属性被删除时进行特殊操作。请参考官方文档以深入了解。

# 运算符重载

我发现 Python 对**运算符重载**的处理方式非常出色。重载运算符意味着根据使用的上下文给它赋予不同的含义。例如，当处理数字时，`+`运算符表示加法，但当处理序列时，它表示连接。

在 Python 中，当你使用操作符时，你很可能在幕后调用一些对象的特殊方法。例如，`a[k]`的调用大致相当于`type(a).__getitem__(a, k)`。

举个例子，让我们创建一个类，它存储一个字符串，并且如果该字符串中包含'42'，则求值为`True`，否则为`False`。此外，让我们给这个类一个长度属性，它对应于存储的字符串的长度：

```py
# oop/operator.overloading.py
class Weird:
    def __init__(self, s):
        self._s = s

    def __len__(self):
        return len(self._s)

    def __bool__(self):
        return '42' in self._s

weird = Weird('Hello! I am 9 years old!')
print(len(weird))  # 24
print(bool(weird))  # False

weird2 = Weird('Hello! I am 42 years old!')
print(len(weird2))  # 25
print(bool(weird2))  # True
```

那很有趣，不是吗？要了解可以重写的魔术方法的完整列表，以便为您的类提供自定义的操作符实现，请参考官方文档中的 Python 数据模型。

# 多态-简要概述

**多态**一词来自希腊语*polys*（许多，多）和*morphē*（形式，形状），它的意思是为不同类型的实体提供单一接口。

在我们的汽车示例中，我们调用`engine.start()`，无论引擎是什么类型。只要它公开了 start 方法，我们就可以调用它。这就是多态的实际应用。

在其他语言中，比如 Java，为了让函数能够接受不同类型并调用它们的方法，这些类型需要以一种方式编码，使它们共享一个接口。这样，编译器就知道无论函数输入的对象类型是什么（只要它扩展了正确的接口），方法都将可用。

在 Python 中，情况就不同了。多态是隐式的，没有任何东西阻止你在对象上调用方法；因此，从技术上讲，没有必要实现接口或其他模式。

还有一种特殊的多态称为**特定多态**，这就是我们在上一段看到的：运算符重载。这是运算符根据其输入的数据类型而改变形状的能力。

多态还允许 Python 程序员简单地使用对象暴露的接口（方法和属性），而无需检查它是从哪个类实例化的。这使得代码更加紧凑，感觉更加自然。

我不能在多态上花太多时间，但我鼓励你自己去了解，这将扩展你对面向对象编程的理解。祝你好运！

# 数据类

在我们离开面向对象编程领域之前，我想提一件事：数据类。在 Python 3.7 中由 PEP557 引入（[`www.python.org/dev/peps/pep-0557/`](https://www.python.org/dev/peps/pep-0557/)），它们可以被描述为<q class="calibre30">*带有默认值的可变命名元组*</q>。让我们深入一个例子：

```py
# oop/dataclass.py
from dataclasses import dataclass

@dataclass
class Body:
    '''Class to represent a physical body.'''
    name: str
    mass: float = 0\.  # Kg
    speed: float = 1\.  # m/s

    def kinetic_energy(self) -> float:
        return (self.mass * self.speed ** 2) / 2

body = Body('Ball', 19, 3.1415)
print(body.kinetic_energy())  # 93.755711375 Joule
print(body)  # Body(name='Ball', mass=19, speed=3.1415)
```

在上面的代码中，我创建了一个表示物体的类，其中有一个方法允许我计算它的动能（使用著名的公式*E[k]=½mv²*）。请注意，`name`应该是一个字符串，而`mass`和`speed`都是浮点数，并且都有默认值。有趣的是，我不需要编写任何`__init__`方法，它由`dataclass`装饰器为我完成，还有用于比较和生成对象的字符串表示的方法（在最后一行由`print`隐式调用）。

如果你感兴趣，你可以在 PEP557 中阅读所有的规范，但现在只需记住数据类可能提供一个更好的，稍微更强大的替代命名元组，以防你需要它。

# 编写自定义迭代器

现在我们有了所有的工具来欣赏我们如何编写自己的自定义迭代器。让我们首先定义一个可迭代对象和一个迭代器：

+   **可迭代对象**：如果一个对象能够一次返回其成员，那么它被称为可迭代对象。列表、元组、字符串和字典都是可迭代对象。定义了`__iter__`或`__getitem__`方法的自定义对象也是可迭代对象。

+   **迭代器**：如果一个对象代表数据流，那么它被称为迭代器。自定义迭代器需要为`__iter__`提供一个返回对象本身的实现，并为`__next__`提供一个实现，该实现返回数据流的下一个项目，直到数据流耗尽，此时所有后续对`__next__`的调用都会简单地引发`StopIteration`异常。内置函数，如`iter`和`next`，在幕后调用`__iter__`和`__next__`。

让我们编写一个迭代器，首先返回字符串中所有的奇数字符，然后返回偶数字符：

```py
# iterators/iterator.py
class OddEven:

    def __init__(self, data):
        self._data = data
        self.indexes = (list(range(0, len(data), 2)) +
            list(range(1, len(data), 2)))

    def __iter__(self):
        return self

    def __next__(self):
        if self.indexes:
            return self._data[self.indexes.pop(0)]
        raise StopIteration

oddeven = OddEven('ThIsIsCoOl!')
print(''.join(c for c in oddeven))  # TIICO!hssol

oddeven = OddEven('HoLa')  # or manually...
it = iter(oddeven)  # this calls oddeven.__iter__ internally
print(next(it))  # H
```

```py
print(next(it))  # L
print(next(it))  # o
print(next(it))  # a
```

因此，我们需要为`__iter__`提供一个返回对象本身的实现，然后为`__next__`提供一个实现。让我们来看看。需要发生的是返回`_data[0]`，`_data[2]`，`_data[4]`，...，`_data[1]`，`_data[3]`，`_data[5`，...直到我们返回了数据中的每一项。为了做到这一点，我们准备了一个列表和索引，比如[`0`，`2`，`4`，`6`，...，`1`，`3`，`5`，...]，并且只要其中至少有一个元素，我们就弹出第一个元素并返回数据中该位置的元素，从而实现我们的目标。当`indexes`为空时，我们引发`StopIteration`，这是迭代器协议所要求的。

还有其他方法可以实现相同的结果，所以继续尝试编写不同的方法。确保最终结果适用于所有边缘情况、空序列、长度为`1`、`2`等的序列。

# 总结

在本章中，我们研究了装饰器，发现了拥有装饰器的原因，并涵盖了一些同时使用一个或多个装饰器的示例。我们还看到了接受参数的装饰器，通常用作装饰器工厂。

我们在 Python 中只是触及了面向对象编程的表面。我们涵盖了所有的基础知识，所以现在你应该能够理解未来章节中的代码。我们讨论了类中可以编写的各种方法和属性，我们探讨了继承与组合，方法重写，属性，运算符重载和多态性。

最后，我们简要地涉及了迭代器，所以现在你更深入地理解了生成器。

在下一章中，我们将看到如何处理文件以及如何以多种不同的方式和格式持久化数据。


# 第七章：文件和数据持久化

"持久是我们称之为生活的冒险的关键。" - Torsten Alexander Lange

在前几章中，我们已经探讨了 Python 的几个不同方面。由于示例具有教学目的，我们在简单的 Python shell 中运行它们，或者以 Python 模块的形式运行。它们运行，可能在控制台上打印一些内容，然后终止，不留下它们短暂存在的痕迹。

现实世界的应用通常大不相同。当然，它们仍然在内存中运行，但它们与网络、磁盘和数据库进行交互。它们还使用适合情况的格式与其他应用程序和设备交换信息。

在本章中，我们将开始接近真实世界，探索以下内容：

+   文件和目录

+   压缩

+   网络和流

+   JSON 数据交换格式

+   使用 pickle 和 shelve 进行数据持久化，来自标准库

+   使用 SQLAlchemy 进行数据持久化

像往常一样，我会努力平衡广度和深度，以便在本章结束时，您将对基本原理有扎实的理解，并且将知道如何在网络上获取更多信息。

# 处理文件和目录

在处理文件和目录时，Python 提供了许多有用的工具。特别是在以下示例中，我们将利用`os`和`shutil`模块。由于我们将在磁盘上读写，我将使用一个名为`fear.txt`的文件，其中包含了《恐惧》（Thich Nhat Hanh 著）的摘录，作为我们的一些示例的试验品。

# 打开文件

在 Python 中打开文件非常简单和直观。实际上，我们只需要使用`open`函数。让我们看一个快速的例子：

```py
# files/open_try.py
fh = open('fear.txt', 'rt')  # r: read, t: text

for line in fh.readlines():
    print(line.strip())  # remove whitespace and print

fh.close()
```

前面的代码非常简单。我们调用`open`，传递文件名，并告诉`open`我们要以文本模式读取它。文件名之前没有路径信息；因此，`open`将假定文件在运行脚本的同一文件夹中。这意味着如果我们从`files`文件夹外部运行此脚本，那么`fear.txt`将找不到。

一旦文件被打开，我们就会得到一个文件对象`fh`，我们可以用它来处理文件的内容。在这种情况下，我们使用`readlines()`方法来迭代文件中的所有行，并打印它们。我们对每一行调用`strip()`来去除内容周围的任何额外空格，包括末尾的行终止字符，因为`print`会为我们添加一个。这是一个快速而粗糙的解决方案，在这个例子中有效，但是如果文件的内容包含需要保留的有意义的空格，那么您将需要在清理数据时稍微小心。在脚本的结尾，我们刷新并关闭流。

关闭文件非常重要，因为我们不希望冒着无法释放对文件的控制的风险。因此，我们需要采取一些预防措施，并将前面的逻辑包装在`try`/`finally`块中。这样做的效果是，无论我们尝试打开和读取文件时可能发生什么错误，我们都可以放心地确保`close()`会被调用：

```py
# files/open_try.py
try:
    fh = open('fear.txt', 'rt')
    for line in fh.readlines():
        print(line.strip())
finally:
    fh.close()
```

逻辑完全相同，但现在也是安全的。

如果您现在不理解`try`/`finally`，不要担心。我们将在下一章中探讨如何处理异常。现在，可以说在`try`块的主体中放置代码会为该代码添加一个机制，允许我们检测错误（称为*异常*）并决定发生错误时该怎么办。在这种情况下，如果发生错误，我们实际上不做任何事情，但是通过在`finally`块中关闭文件，我们确保该行无论是否发生错误都会被执行。

我们可以通过以下方式简化前面的示例：

```py
# files/open_try.py
try:
    fh = open('fear.txt')  # rt is default
    for line in fh:  # we can iterate directly on fh
        print(line.strip())
finally:
    fh.close()
```

如您所见，`rt`是打开文件的默认模式，因此我们不需要指定它。此外，我们可以直接在`fh`上进行迭代，而不需要显式调用`readlines()`。Python 非常友好，为我们提供了简写，使我们的代码更短，更容易阅读。

所有前面的示例都会在控制台上打印文件的内容（查看源代码以阅读整个内容）：

```py
An excerpt from Fear - By Thich Nhat Hanh

The Present Is Free from Fear

When we are not fully present, we are not really living. We’re not really there, either for our loved ones or for ourselves. If we’re not there, then where are we? We are running, running, running, even during our sleep. We run because we’re trying to escape from our fear.
...
```

# 使用上下文管理器打开文件

让我们承认吧：不得不使用`try`/`finally`块来传播我们的代码并不是最好的选择。通常情况下，Python 给我们提供了一种更好的方式以安全的方式打开文件：使用上下文管理器。让我们先看看代码：

```py
# files/open_with.py
with open('fear.txt') as fh:
    for line in fh:
        print(line.strip())
```

前面的示例等同于前面的一个示例，但读起来更好。`with`语句支持由上下文管理器定义的运行时上下文的概念。这是使用一对方法`__enter__`和`__exit__`实现的，允许用户定义的类定义在执行语句体之前进入的运行时上下文，并在语句结束时退出。`open`函数在由上下文管理器调用时能够产生一个文件对象，但它真正的美妙之处在于`fh.close()`将会自动为我们调用，即使在出现错误的情况下也是如此。

上下文管理器在多种不同的场景中使用，比如线程同步、文件或其他对象的关闭，以及网络和数据库连接的管理。你可以在`contextlib`文档页面中找到关于它们的信息（[`docs.python.org/3.7/library/contextlib.html`](https://docs.python.org/3.7/library/contextlib.html)）。

# 读写文件

现在我们知道如何打开文件了，让我们看看我们有几种不同的方式可以读写文件：

```py
# files/print_file.py
with open('print_example.txt', 'w') as fw:
    print('Hey I am printing into a file!!!', file=fw)
```

第一种方法使用了`print`函数，你在前几章中已经见过很多次。在获取文件对象之后，这次指定我们打算向其写入（"`w`"），我们可以告诉`print`调用将其效果定向到文件，而不是默认的`sys.stdout`，当在控制台上执行时，它会映射到它。

前面的代码的效果是，如果`print_example.txt`文件不存在，则创建它，或者如果存在，则将其截断，并将行`Hey I am printing into a file!!!`写入其中。

这很简单易懂，但并不是我们通常写文件时所做的。让我们看一个更常见的方法：

```py
# files/read_write.py
with open('fear.txt') as f:
    lines = [line.rstrip() for line in f]

with open('fear_copy.txt', 'w') as fw:
    fw.write('\n'.join(lines))
```

在前面的示例中，我们首先打开`fear.txt`并逐行将其内容收集到一个列表中。请注意，这次我调用了一个更精确的方法`rstrip()`，作为一个例子，以确保我只去掉每行右侧的空白。

在代码片段的第二部分中，我们创建了一个新文件`fear_copy.txt`，并将原始文件中的所有行写入其中，用换行符`\n`连接起来。Python 很慷慨，并且默认使用*通用换行符*，这意味着即使原始文件的换行符可能与`\n`不同，它也会在返回行之前自动转换为我们。当然，这种行为是可以自定义的，但通常它正是你想要的。说到换行符，你能想到副本中可能缺少的换行符吗？

# 读写二进制模式

请注意，通过在选项中传递`t`来打开文件（或者省略它，因为它是默认值），我们是以文本模式打开文件。这意味着文件的内容被视为文本进行处理和解释。如果你希望向文件写入字节，可以以二进制模式打开它。当你处理不仅包含原始文本的文件时，这是一个常见的要求，比如图像、音频/视频以及一般的任何其他专有格式。

为了处理二进制模式的文件，只需在打开它们时指定`b`标志，就像以下示例中所示：

```py
# files/read_write_bin.py
with open('example.bin', 'wb') as fw:
    fw.write(b'This is binary data...')

with open('example.bin', 'rb') as f:
    print(f.read())  # prints: b'This is binary data...'
```

在这个示例中，我仍然使用文本作为二进制数据，但它可以是任何你想要的。你可以看到它被视为二进制数据的事实，因为在输出中你会得到`b'This ...'`前缀。

# 防止覆盖现有文件

Python 允许我们打开文件进行写入。通过使用`w`标志，我们打开一个文件并截断其内容。这意味着文件被覆盖为一个空文件，原始内容丢失。如果您希望仅在文件不存在时打开文件进行写入，可以在下面的示例中使用`x`标志：

```py
# files/write_not_exists.py
with open('write_x.txt', 'x') as fw:
    fw.write('Writing line 1')  # this succeeds

with open('write_x.txt', 'x') as fw:
    fw.write('Writing line 2')  # this fails
```

如果您运行前面的片段，您将在目录中找到一个名为`write_x.txt`的文件，其中只包含一行文本。事实上，片段的第二部分未能执行。这是我在控制台上得到的输出：

```py
$ python write_not_exists.py
Traceback (most recent call last):
 File "write_not_exists.py", line 6, in <module>
 with open('write_x.txt', 'x') as fw:
FileExistsError: [Errno 17] File exists: 'write_x.txt'
```

# 检查文件和目录的存在

如果您想确保文件或目录存在（或不存在），则需要使用`os.path`模块。让我们看一个小例子：

```py
# files/existence.py
import os

filename = 'fear.txt'
path = os.path.dirname(os.path.abspath(filename))

print(os.path.isfile(filename))  # True
print(os.path.isdir(path))  # True
print(path)  # /Users/fab/srv/lpp/ch7/files
```

前面的片段非常有趣。在使用相对引用声明文件名之后（因为缺少路径信息），我们使用`abspath`来计算文件的完整绝对路径。然后，我们通过调用`dirname`来获取路径信息（删除末尾的文件名）。正如您所看到的，结果在最后一行打印出来。还要注意我们如何通过调用`isfile`和`isdir`来检查文件和目录的存在。在`os.path`模块中，您可以找到处理路径名所需的所有函数。

如果您需要以不同的方式处理路径，可以查看`pathlib`。虽然`os.path`使用字符串，但`pathlib`提供了表示适合不同操作系统语义的文件系统路径的类。这超出了本章的范围，但如果您感兴趣，请查看 PEP428（[`www.python.org/dev/peps/pep-0428/`](https://www.python.org/dev/peps/pep-0428/)）以及标准库中的页面。

# 操作文件和目录

让我们看几个快速示例，演示如何操作文件和目录。第一个示例操作内容：

```py
# files/manipulation.py
from collections import Counter
from string import ascii_letters

chars = ascii_letters + ' '

def sanitize(s, chars):
    return ''.join(c for c in s if c in chars)

def reverse(s):
    return s[::-1]

with open('fear.txt') as stream:
    lines = [line.rstrip() for line in stream]

with open('raef.txt', 'w') as stream:
    stream.write('\n'.join(reverse(line) for line in lines))

# now we can calculate some statistics
lines = [sanitize(line, chars) for line in lines]
whole = ' '.join(lines)
cnt = Counter(whole.lower().split())
print(cnt.most_common(3))
```

前面的示例定义了两个函数：`sanitize`和`reverse`。它们是简单的函数，其目的是从字符串中删除任何不是字母或空格的内容，并分别生成字符串的反向副本。

我们打开`fear.txt`并将其内容读入列表。然后我们创建一个新文件`raef.txt`，其中包含原始文件的水平镜像版本。我们使用`join`在新行字符上写入`lines`的所有内容。也许更有趣的是最后的部分。首先，我们通过列表推导将`lines`重新分配为其经过清理的版本。然后我们将它们放在`whole`字符串中，最后将结果传递给`Counter`。请注意，我们拆分字符串并将其转换为小写。这样，每个单词都将被正确计数，而不管其大小写如何，并且由于`split`，我们不需要担心任何额外的空格。当我们打印出最常见的三个单词时，我们意识到真正的 Thich Nhat Hanh 的重点在于其他人，因为`we`是文本中最常见的单词：

```py
$ python manipulation.py
[('we', 17), ('the', 13), ('were', 7)]
```

现在让我们看一个更加面向磁盘操作的操作示例，其中我们使用`shutil`模块：

```py
# files/ops_create.py
import shutil
import os

BASE_PATH = 'ops_example'  # this will be our base path
os.mkdir(BASE_PATH)

path_b = os.path.join(BASE_PATH, 'A', 'B')
path_c = os.path.join(BASE_PATH, 'A', 'C')
path_d = os.path.join(BASE_PATH, 'A', 'D')

os.makedirs(path_b)
os.makedirs(path_c)

for filename in ('ex1.txt', 'ex2.txt', 'ex3.txt'):
    with open(os.path.join(path_b, filename), 'w') as stream:
        stream.write(f'Some content here in {filename}\n')

shutil.move(path_b, path_d)

shutil.move(
    os.path.join(path_d, 'ex1.txt'),
    os.path.join(path_d, 'ex1d.txt')
)
```

在前面的代码中，我们首先声明一个基本路径，该路径将安全地包含我们将要创建的所有文件和文件夹。然后我们使用`makedirs`创建两个目录：`ops_example/A/B`和`ops_example/A/C`。（您能想到使用`map`来创建这两个目录的方法吗？）。

我们使用`os.path.join`来连接目录名称，因为使用`/`会使代码专门运行在目录分隔符为`/`的平台上，但是代码将在具有不同分隔符的平台上失败。让我们委托给`join`来确定适当的分隔符。

创建目录后，在一个简单的`for`循环中，我们放入一些代码，创建目录`B`中的三个文件。然后，我们将文件夹`B`及其内容移动到另一个名称：`D`。最后，我们将`ex1.txt`重命名为`ex1d.txt`。如果您打开该文件，您会看到它仍然包含来自`for`循环的原始文本。对结果调用`tree`会产生以下结果：

```py
$ tree ops_example/
ops_example/
└── A
 ├── C
 └── D
 ├── ex1d.txt
 ├── ex2.txt
 └── ex3.txt 
```

# 操作路径名

让我们通过一个简单的例子来更多地探索`os.path`的能力：

```py
# files/paths.py
import os

filename = 'fear.txt'
path = os.path.abspath(filename)

print(path)
print(os.path.basename(path))
print(os.path.dirname(path))
print(os.path.splitext(path))
print(os.path.split(path))

readme_path = os.path.join(
    os.path.dirname(path), '..', '..', 'README.rst')

```

```py
print(readme_path)
print(os.path.normpath(readme_path))
```

阅读结果可能是对这个简单例子的足够好的解释：

```py
/Users/fab/srv/lpp/ch7/files/fear.txt           # path
fear.txt                                        # basename
/Users/fab/srv/lpp/ch7/files                    # dirname
('/Users/fab/srv/lpp/ch7/files/fear', '.txt')   # splitext
('/Users/fab/srv/lpp/ch7/files', 'fear.txt')    # split
/Users/fab/srv/lpp/ch7/files/../../README.rst   # readme_path
/Users/fab/srv/lpp/README.rst                   # normalized
```

# 临时文件和目录

有时，在运行一些代码时，能够创建临时目录或文件非常有用。例如，在编写影响磁盘的测试时，您可以使用临时文件和目录来运行您的逻辑并断言它是正确的，并确保在测试运行结束时，测试文件夹中没有剩余物品。让我们看看在 Python 中如何做到这一点：

```py
# files/tmp.py
import os
from tempfile import NamedTemporaryFile, TemporaryDirectory

with TemporaryDirectory(dir='.') as td:
    print('Temp directory:', td)
    with NamedTemporaryFile(dir=td) as t:
        name = t.name
        print(os.path.abspath(name))
```

前面的例子非常简单：我们在当前目录（`.`）中创建一个临时目录，并在其中创建一个命名临时文件。我们打印文件名以及其完整路径：

```py
$ python tmp.py
Temp directory: ./tmpwa9bdwgo
/Users/fab/srv/lpp/ch7/files/tmpwa9bdwgo/tmp3d45hm46 
```

运行此脚本将每次产生不同的结果。毕竟，这里我们创建的是一个临时随机名称，对吧？

# 目录内容

使用 Python，您还可以检查目录的内容。我将向您展示两种方法：

```py
# files/listing.py
import os

with os.scandir('.') as it:
    for entry in it:
        print(
            entry.name, entry.path,
            'File' if entry.is_file() else 'Folder'
        )
```

此片段使用`os.scandir`，在当前目录上调用。我们对结果进行迭代，每个结果都是`os.DirEntry`的一个实例，这是一个暴露有用属性和方法的好类。在代码中，我们访问了其中的一部分：`name`、`path`和`is_file()`。运行代码会产生以下结果（为简洁起见，我省略了一些结果）：

```py
$ python listing.py
fixed_amount.py ./fixed_amount.py File
existence.py ./existence.py File
...
ops_example ./ops_example Folder
...
```

扫描目录树的更强大的方法是由`os.walk`给我们的。让我们看一个例子：

```py
# files/walking.py
import os

for root, dirs, files in os.walk('.'):
    print(os.path.abspath(root))
    if dirs:
        print('Directories:')
        for dir_ in dirs:
            print(dir_)
        print()
    if files:
        print('Files:')
        for filename in files:
            print(filename)
        print()
```

运行前面的片段将产生当前目录中所有文件和目录的列表，并且对每个子目录都会执行相同的操作。

# 文件和目录压缩

在我们离开这一部分之前，让我给你举个创建压缩文件的例子。在书的源代码中，我有两个例子：一个创建一个 ZIP 文件，而另一个创建一个`tar.gz`文件。Python 允许您以几种不同的方式和格式创建压缩文件。在这里，我将向您展示如何创建最常见的一种，ZIP：

```py
# files/compression/zip.py
from zipfile import ZipFile

with ZipFile('example.zip', 'w') as zp:
    zp.write('content1.txt')
    zp.write('content2.txt')
    zp.write('subfolder/content3.txt')
    zp.write('subfolder/content4.txt')

with ZipFile('example.zip') as zp:
    zp.extract('content1.txt', 'extract_zip')
    zp.extract('subfolder/content3.txt', 'extract_zip')
```

在前面的代码中，我们导入`ZipFile`，然后在上下文管理器中，我们向其中写入四个虚拟上下文文件（其中两个在子文件夹中，以显示 ZIP 保留了完整路径）。之后，作为示例，我们打开压缩文件并从中提取了一些文件，放入`extract_zip`目录中。如果您有兴趣了解更多关于数据压缩的信息，请确保查看标准库中的*数据压缩和存档*部分（[`docs.python.org/3.7/library/archiving.html`](https://docs.python.org/3.7/library/archiving.html)），在那里您将能够学习有关此主题的所有内容。

# 数据交换格式

现代软件架构倾向于将应用程序拆分为几个组件。无论您是否采用面向服务的架构范例，或者将其推进到微服务领域，这些组件都必须交换数据。但即使您正在编写一个单体应用程序，其代码库包含在一个项目中，也有可能您必须与 API、其他程序交换数据，或者简单地处理网站前端和后端部分之间的数据流，这些部分很可能不会使用相同的语言。

选择正确的格式来交换信息至关重要。特定于语言的格式的优势在于，语言本身很可能会为您提供使序列化和反序列化变得轻而易举的所有工具。但是，您将失去与使用不同版本的相同语言或完全不同语言编写的其他组件进行通信的能力。无论未来看起来如何，只有在给定情况下这是唯一可能的选择时，才应选择特定于语言的格式。

一个更好的方法是选择一种语言无关的格式，可以被所有（或至少大多数）语言使用。在我领导的团队中，我们有来自英格兰、波兰、南非、西班牙、希腊、印度、意大利等国家的人。我们都说英语，所以无论我们的母语是什么，我们都可以理解彼此（嗯...大多数情况下！）。

在软件世界中，一些流行的格式在最近几年已经成为事实上的标准。最著名的可能是 XML、YAML 和 JSON。Python 标准库包括`xml`和`json`模块，而在 PyPI（[`docs.python.org/3.7/library/archiving.html`](https://docs.python.org/3.7/library/archiving.html)）上，您可以找到一些不同的包来处理 YAML。

在 Python 环境中，JSON 可能是最常用的格式。它胜过其他两种格式，因为它是标准库的一部分，而且它很简单。如果您曾经使用过 XML，您就知道它可能是多么可怕。

# 处理 JSON

**JSON**是**JavaScript 对象表示法**的缩写，它是 JavaScript 语言的一个子集。它已经存在了将近二十年，因此它是众所周知的，并且被基本上所有语言广泛采用，尽管它实际上是与语言无关的。您可以在其网站上阅读有关它的所有信息（[`www.json.org/`](https://www.json.org/)），但我现在要给您一个快速介绍。

JSON 基于两种结构：一组名称/值对和一个有序值列表。您会立即意识到，这两个对象分别映射到 Python 中的字典和列表数据类型。作为数据类型，它提供字符串、数字、对象和值，如 true、false 和 null。让我们看一个快速的例子来开始：

```py
# json_examples/json_basic.py
import sys
import json

data = {
    'big_number': 2 ** 3141,
    'max_float': sys.float_info.max,
    'a_list': [2, 3, 5, 7],
}

json_data = json.dumps(data)
data_out = json.loads(json_data)
assert data == data_out  # json and back, data matches
```

我们首先导入`sys`和`json`模块。然后我们创建一个包含一些数字和一个列表的简单字典。我想测试使用非常大的数字进行序列化和反序列化，所以我放了*2³¹⁴¹*和我的系统可以处理的最大浮点数。

我们使用`json.dumps`进行序列化，它将数据转换为 JSON 格式的字符串。然后将该数据输入`json.loads`，它执行相反的操作：从 JSON 格式的字符串中，将数据重构为 Python。在最后一行，我们确保原始数据和通过 JSON 进行序列化/反序列化的结果匹配。

让我们看看下一个例子中，如果我们打印 JSON 数据会是什么样子：

```py
# json_examples/json_basic.py
import json

info = {
    'full_name': 'Sherlock Holmes',
    'address': {
        'street': '221B Baker St',
        'zip': 'NW1 6XE',
        'city': 'London',
        'country': 'UK',
    }
}

print(json.dumps(info, indent=2, sort_keys=True))
```

在这个例子中，我们创建了一个包含福尔摩斯数据的字典。如果您像我一样是福尔摩斯的粉丝，并且在伦敦，您会在那个地址找到他的博物馆（我建议您去参观，它虽小但非常好）。

请注意我们如何调用`json.dumps`。我们已经告诉它用两个空格缩进，并按字母顺序排序键。结果是这样的：

```py
$ python json_basic.py
{
 "address": {
 "city": "London",
 "country": "UK",
 "street": "221B Baker St",
 "zip": "NW1 6XE"
 },
 "full_name": "Sherlock Holmes"
}
```

与 Python 的相似性非常大。唯一的区别是，如果您在字典的最后一个元素上放置逗号，就像我在 Python 中所做的那样（因为这是习惯的做法），JSON 会抱怨。

让我给您展示一些有趣的东西：

```py
# json_examples/json_tuple.py
import json

data_in = {
    'a_tuple': (1, 2, 3, 4, 5),
}

json_data = json.dumps(data_in)
print(json_data)  # {"a_tuple": [1, 2, 3, 4, 5]}
data_out = json.loads(json_data)
print(data_out)  # {'a_tuple': [1, 2, 3, 4, 5]}
```

在这个例子中，我们放了一个元组，而不是一个列表。有趣的是，从概念上讲，元组也是一个有序的项目列表。它没有列表的灵活性，但从 JSON 的角度来看，它仍然被视为相同的。因此，正如您可以从第一个`print`中看到的那样，在 JSON 中，元组被转换为列表。因此，它是一个元组的信息丢失了，当进行反序列化时，`data_out`中的`a_tuple`实际上是一个列表。在处理数据时，重要的是要记住这一点，因为经历一个涉及仅包括您可以使用的数据结构子集的格式的转换过程意味着会有信息丢失。在这种情况下，我们丢失了类型（元组与列表）的信息。

这实际上是一个常见的问题。例如，您不能将所有 Python 对象序列化为 JSON，因为不清楚 JSON 是否应该还原它（或者如何还原）。想想`datetime`，例如。该类的实例是 JSON 不允许序列化的 Python 对象。如果我们将其转换为字符串，比如`2018-03-04T12:00:30Z`，这是带有日期、时间和时区信息的 ISO 8601 表示，当进行反序列化时，JSON 应该怎么做？它应该说*这实际上可以反序列化为一个 datetime 对象，所以最好这样做*，还是应该简单地将其视为字符串并保留它？那些可以以多种方式解释的数据类型又该怎么办？

答案是，在处理数据交换时，我们经常需要在将对象序列化为 JSON 之前将其转换为更简单的格式。这样，当我们对其进行反序列化时，我们将知道如何正确地重建它们。

然而，在某些情况下，主要是为了内部使用，能够序列化自定义对象是很有用的，因此，只是为了好玩，我将向您展示两个例子：复数（因为我喜欢数学）和*datetime*对象。

# 自定义编码/解码与 JSON

在 JSON 世界中，我们可以将编码/解码这样的术语视为序列化/反序列化的同义词。它们基本上都意味着转换为 JSON，然后再从 JSON 转换回来。在下面的例子中，我将向您展示如何编码复数：

```py
# json_examples/json_cplx.py
import json

class ComplexEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, complex):
            return {
                '_meta': '_complex',
                'num': [obj.real, obj.imag],
            }
        return json.JSONEncoder.default(self, obj)

data = {
    'an_int': 42,
    'a_float': 3.14159265,
    'a_complex': 3 + 4j,
}

json_data = json.dumps(data, cls=ComplexEncoder)
print(json_data)

def object_hook(obj):
    try:
        if obj['_meta'] == '_complex':
            return complex(*obj['num'])
    except (KeyError, TypeError):
        return obj

data_out = json.loads(json_data, object_hook=object_hook)
print(data_out)
```

首先，我们定义一个`ComplexEncoder`类，它需要实现`default`方法。这个方法被传递给所有需要被序列化的对象，一个接一个地，在`obj`变量中。在某个时候，`obj`将是我们的复数*3+4j*。当这种情况发生时，我们返回一个带有一些自定义元信息的字典，以及一个包含实部和虚部的列表。这就是我们需要做的，以避免丢失复数的信息。

然后我们调用`json.dumps`，但这次我们使用`cls`参数来指定我们的自定义编码器。结果被打印出来：

```py
{"an_int": 42, "a_float": 3.14159265, "a_complex": {"_meta": "_complex", "num": [3.0, 4.0]}}
```

一半的工作已经完成。对于反序列化部分，我们本可以编写另一个从`JSONDecoder`继承的类，但是，只是为了好玩，我使用了一种更简单的技术，使用了一个小函数：`object_hook`。

在`object_hook`的主体中，我们找到另一个`try`块，但现在不要担心它。我将在下一章节中详细解释它。重要的是`try`块本身的主体中的两行。该函数接收一个对象（请注意，只有当`obj`是一个字典时才调用该函数），如果元数据与我们的复数约定匹配，我们将实部和虚部传递给`complex`函数。`try`/`except`块只是为了防止格式不正确的 JSON 破坏整个过程（如果发生这种情况，我们只需返回对象本身）。

最后的打印返回：

```py
{'an_int': 42, 'a_float': 3.14159265, 'a_complex': (3+4j)}
```

您可以看到`a_complex`已经被正确反序列化。

现在让我们看一个稍微更复杂（没有刻意的双关语）的例子：处理`datetime`对象。我将把代码分成两个部分，序列化部分和之后的反序列化部分：

```py
# json_examples/json_datetime.py
import json
from datetime import datetime, timedelta, timezone

now = datetime.now()
now_tz = datetime.now(tz=timezone(timedelta(hours=1)))

class DatetimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            try:
                off = obj.utcoffset().seconds
            except AttributeError:
                off = None

            return {
                '_meta': '_datetime',
                'data': obj.timetuple()[:6] + (obj.microsecond, ),
                'utcoffset': off,
            }
        return json.JSONEncoder.default(self, obj)

data = {
    'an_int': 42,
    'a_float': 3.14159265,
    'a_datetime': now,
    'a_datetime_tz': now_tz,
}

json_data = json.dumps(data, cls=DatetimeEncoder)
print(json_data)
```

这个例子稍微复杂的原因在于 Python 中的`datetime`对象可以是时区感知的或者不是；因此，我们需要更加小心。流程基本上和之前一样，只是处理不同的数据类型。我们首先获取当前的日期和时间信息，我们既不带（`now`）也带（`now_tz`）时区感知，只是为了确保我们的脚本工作。然后我们继续像之前一样定义一个自定义编码器，并再次实现`default`方法。在该方法中重要的部分是我们如何获取时间偏移（`off`）信息，以秒为单位，并且我们如何构造返回数据的字典。这一次，元数据表示它是*datetime*信息，然后我们保存时间元组的前六个项目（年、月、日、小时、分钟和秒），加上`data`键中的微秒，然后是偏移。你能看出`data`的值是元组的连接吗？如果你能，干得好！

当我们有了自定义编码器后，我们继续创建一些数据，然后进行序列化。`print`语句返回（在我进行了一些美化之后）：

```py
{
 "a_datetime": {
 "_meta": "_datetime",
 "data": [2018, 3, 18, 17, 57, 27, 438792],
 "utcoffset": null
 },
 "a_datetime_tz": {
 "_meta": "_datetime",
 "data": [2018, 3, 18, 18, 57, 27, 438810],
 "utcoffset": 3600
 },
 "a_float": 3.14159265,
 "an_int": 42
}
```

有趣的是，我们发现`None`被翻译为`null`，它的 JavaScript 等价物。此外，我们可以看到我们的数据似乎已经被正确编码。让我们继续进行脚本的第二部分：

```py
# json_examples/json_datetime.py
def object_hook(obj):
    try:
        if obj['_meta'] == '_datetime':
            if obj['utcoffset'] is None:
                tz = None
            else:
                tz = timezone(timedelta(seconds=obj['utcoffset']))
            return datetime(*obj['data'], tzinfo=tz)
    except (KeyError, TypeError):
        return obj

data_out = json.loads(json_data, object_hook=object_hook)
```

再次，我们首先验证元数据告诉我们它是一个`datetime`，然后我们继续获取时区信息。一旦我们有了时区信息，我们将 7 元组（使用`*`来解包其值）和时区信息传递给`datetime`调用，得到我们的原始对象。让我们通过打印`data_out`来验证它：

```py
{
 'a_datetime': datetime.datetime(2018, 3, 18, 18, 1, 46, 54693),
 'a_datetime_tz': datetime.datetime(
 2018, 3, 18, 19, 1, 46, 54711,
 tzinfo=datetime.timezone(datetime.timedelta(seconds=3600))),
 'a_float': 3.14159265,
 'an_int': 42
}
```

正如你所看到的，我们正确地得到了一切。作为一个练习，我想挑战你写相同的逻辑，但是对于一个`date`对象，这应该更简单。

在我们继续下一个主题之前，我想提个小心。也许这是违反直觉的，但是处理`datetime`对象可能是最棘手的事情之一，所以，虽然我很确定这段代码正在做它应该做的事情，我想强调我只是轻微地测试了它。所以如果你打算使用它，请彻底测试它。测试不同的时区，测试夏令时的开启和关闭，测试纪元前的日期等等。你可能会发现这一部分的代码需要一些修改来适应你的情况。

现在让我们转到下一个主题，IO。

# IO、流和请求

**IO**代表**输入**/**输出**，它广泛地指的是计算机与外部世界之间的通信。有几种不同类型的 IO，这超出了本章的范围来解释所有这些，但我仍然想给你举几个例子。

# 使用内存流

第一个将向你展示`io.StringIO`类，它是用于文本 IO 的内存流。而第二个则会逃离我们计算机的局限，并向你展示如何执行 HTTP 请求。让我们看看第一个例子：

```py
# io_examples/string_io.py
import io

stream = io.StringIO()
stream.write('Learning Python Programming.\n')
print('Become a Python ninja!', file=stream)

contents = stream.getvalue()
print(contents)

stream.close()
```

在前面的代码片段中，我们从标准库中导入了`io`模块。这是一个非常有趣的模块，其中包含许多与流和 IO 相关的工具。其中之一是`StringIO`，它是一个内存缓冲区，我们将使用两种不同的方法在其中写入两个句子，就像我们在本章的第一个例子中使用文件一样。我们既可以调用`StringIO.write`，也可以使用`print`，并告诉它将数据定向到我们的流中。

通过调用`getvalue`，我们可以获取流的内容（并打印它），最后我们关闭它。调用`close`会导致文本缓冲立即被丢弃。

有一种更优雅的方法来编写前面的代码（在你看之前，你能猜到吗？）：

```py
# io_examples/string_io.py
with io.StringIO() as stream:
    stream.write('Learning Python Programming.\n')
    print('Become a Python ninja!', file=stream)
    contents = stream.getvalue()
    print(contents)
```

是的，这又是一个上下文管理器。像`open`一样，`io.StringIO`在上下文管理器块内工作得很好。注意与`open`的相似之处：在这种情况下，我们也不需要手动关闭流。

内存对象在许多情况下都很有用。内存比磁盘快得多，对于少量数据来说，可能是完美的选择。

运行脚本时，输出为：

```py
$ python string_io.py
Learning Python Programming.
Become a Python ninja!
```

# 进行 HTTP 请求

现在让我们探索一些关于 HTTP 请求的例子。我将在这些例子中使用`requests`库，你可以使用`pip`安装它。我们将对[httpbin.org](http://httpbin.org/) API 执行 HTTP 请求，有趣的是，这个 API 是由`requests`库的创建者 Kenneth Reitz 开发的。这个库在全世界范围内被广泛采用：

```py
import requests

urls = {
    'get': 'https://httpbin.org/get?title=learn+python+programming',
    'headers': 'https://httpbin.org/headers',
    'ip': 'https://httpbin.org/ip',
    'now': 'https://now.httpbin.org/',
    'user-agent': 'https://httpbin.org/user-agent',
    'UUID': 'https://httpbin.org/uuid',
}

def get_content(title, url):
    resp = requests.get(url)
    print(f'Response for {title}')
    print(resp.json())

for title, url in urls.items():
    get_content(title, url)
    print('-' * 40)
```

前面的片段应该很容易理解。我声明了一个 URL 字典，对这些 URL 我想执行`requests`。我将执行请求的代码封装到一个小函数`get_content`中：如你所见，我们很简单地执行了一个 GET 请求（通过使用`requests.get`），并打印了响应的标题和 JSON 解码版本的响应体。让我多说一句关于最后一点。

当我们对网站或 API 执行请求时，我们会得到一个响应对象，这个对象很简单，就是服务器返回的内容。所有来自[httpbin.org](https://httpbin.org/)的响应体都是 JSON 编码的，所以我们不是通过`resp.text`获取响应体本身，然后手动解码它，而是通过在响应对象上利用`json`方法将两者结合起来。`requests`包变得如此广泛被采用有很多原因，其中一个绝对是它的易用性。

现在，当你在应用程序中执行请求时，你会希望有一个更加健壮的方法来处理错误等等，但是在本章中，一个简单的例子就足够了。别担心，我会在第十四章 *Web Development*中给你一个更全面的 HTTP 请求介绍。

回到我们的代码，最后，我们运行一个`for`循环并获取所有的 URL。当你运行它时，你会在控制台上看到每次调用的结果，就像这样（经过美化和简化）：

```py
$ python reqs.py
Response for get
{
  "args": {
    "title": "learn python programming"
  },
  "headers": {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "close",
    "Host": "httpbin.org",
    "User-Agent": "python-requests/2.19.0"
  },
  "origin": "82.47.175.158",
  "url": "https://httpbin.org/get?title=learn+python+programming"
}
... rest of the output omitted ... 
```

请注意，版本号和 IP 方面的输出可能会有些不同，这没关系。现在，GET 只是 HTTP 动词中的一个，它绝对是最常用的。第二个是无处不在的 POST，当你需要向服务器发送数据时，就会发起这种类型的请求。每当你在网上提交表单时，你基本上就是在发起一个 POST 请求。所以，让我们尝试以编程方式进行一个：

```py
# io_examples/reqs_post.py
import requests

url = 'https://httpbin.org/post'
data = dict(title='Learn Python Programming')

resp = requests.post(url, data=data)
print('Response for POST')
print(resp.json())
```

前面的代码与之前看到的代码非常相似，只是这一次我们不调用`get`，而是调用`post`，因为我们想发送一些数据，我们在调用中指定了这一点。`requests`库提供的远不止这些，它因其美丽的 API 而受到社区的赞扬。这是一个我鼓励你去了解和探索的项目，因为无论如何你最终都会一直使用它。

运行前面的脚本（并对输出进行一些美化处理）会产生以下结果：

```py
$ python reqs_post.py
Response for POST
{ 'args': {},
 'data': '',
 'files': {},
 'form': {'title': 'Learn Python Programming'},
 'headers': { 'Accept': '*/*',
 'Accept-Encoding': 'gzip, deflate',
 'Connection': 'close',
 'Content-Length': '30',
 'Content-Type': 'application/x-www-form-urlencoded',
 'Host': 'httpbin.org',
 'User-Agent': 'python-requests/2.7.0 CPython/3.7.0b2 '
 'Darwin/17.4.0'},
 'json': None,
```

```py
 'origin': '82.45.123.178',
 'url': 'https://httpbin.org/post'}
```

注意现在头部不同了，我们在响应体的`form`键值对中找到了发送的数据。

我希望这些简短的例子足以让你开始，特别是对于请求。网络每天都在变化，所以值得学习基础知识，然后不时地进行复习。

现在让我们转向本章的最后一个主题：以不同格式在磁盘上持久化数据。

# 在磁盘上持久化数据

在本章的最后一节中，我们将探讨如何以三种不同的格式将数据持久化到磁盘。我们将探索`pickle`、`shelve`，以及一个涉及使用 SQLAlchemy 访问数据库的简短示例，SQLAlchemy 是 Python 生态系统中最广泛采用的 ORM 库。

# 使用 pickle 序列化数据

Python 标准库中的`pickle`模块提供了将 Python 对象转换为字节流以及反之的工具。尽管`pickle`和`json`公开的 API 存在部分重叠，但两者是完全不同的。正如我们在本章前面看到的，JSON 是一种文本格式，人类可读，语言无关，并且仅支持 Python 数据类型的受限子集。另一方面，`pickle`模块不是人类可读的，转换为字节，是特定于 Python 的，并且由于 Python 的精彩内省能力，它支持大量的数据类型。

尽管存在这些差异，当你考虑使用其中一个时，你应该知道这些差异，我认为关于`pickle`最重要的关注点在于当你使用它时所面临的安全威胁。从不受信任的来源*unpickling*错误或恶意数据可能非常危险，因此如果你决定在你的应用程序中采用它，你需要格外小心。

话虽如此，让我们通过一个简单的例子来看它的运作方式：

```py
# persistence/pickler.py
import pickle
from dataclasses import dataclass

@dataclass
class Person:
    first_name: str
    last_name: str
    id: int

    def greet(self):
        print(f'Hi, I am {self.first_name} {self.last_name}'
              f' and my ID is {self.id}'
        )

people = [
    Person('Obi-Wan', 'Kenobi', 123),
    Person('Anakin', 'Skywalker', 456),
]

# save data in binary format to a file
with open('data.pickle', 'wb') as stream:
    pickle.dump(people, stream)

# load data from a file
with open('data.pickle', 'rb') as stream:
    peeps = pickle.load(stream)

for person in peeps:
    person.greet()
```

在前面的例子中，我们使用`dataclass`装饰器创建了一个`Person`类，我们在第六章中已经见过，*OOP，Decorators 和 Iterators*。我之所以用数据类写这个例子，只是为了向你展示`pickle`如何毫不费力地处理它，而不需要我们为了更简单的数据类型而做任何事情。

该类有三个属性：`first_name`、`last_name`和`id`。它还公开了一个`greet`方法，简单地打印出带有数据的 hello 消息。

我们创建了一个实例列表，然后将其保存到文件中。为了这样做，我们使用`pickle.dump`，将要*pickled*的内容和要写入的流传递给它。在那之后，我们立即从同一个文件中读取，并通过使用`pickle.load`，将该流的整个内容转换回 Python。为了确保对象已经被正确转换，我们在两个对象上都调用了`greet`方法。结果如下：

```py
$ python pickler.py
Hi, I am Obi-Wan Kenobi and my ID is 123
Hi, I am Anakin Skywalker and my ID is 456 
```

`pickle`模块还允许你通过`dumps`和`loads`函数（注意这两个名称末尾的`s`）将数据转换为（和从）字节对象。在日常应用中，当我们需要持久化不应该与另一个应用程序交换的 Python 数据时，通常会使用`pickle`。我最近遇到的一个例子是`flask`插件中的会话管理，它在将会话对象发送到 Redis 之前对其进行`pickle`。不过，在实践中，你不太可能经常使用这个库。

另一个可能使用得更少，但在资源短缺时非常有用的工具是`shelve`。

# 使用 shelve 保存数据

`shelf`是一个持久的类似字典的对象。它的美妙之处在于，你保存到`shelf`中的值可以是任何你可以`pickle`的对象，因此你不像使用数据库时那样受限制。尽管有趣且有用，但`shelve`模块在实践中很少使用。为了完整起见，让我们快速看一下它是如何工作的：

```py
# persistence/shelf.py
import shelve

class Person:
    def __init__(self, name, id):
        self.name = name
        self.id = id

with shelve.open('shelf1.shelve') as db:
    db['obi1'] = Person('Obi-Wan', 123)
    db['ani'] = Person('Anakin', 456)
    db['a_list'] = [2, 3, 5]
    db['delete_me'] = 'we will have to delete this one...'

    print(list(db.keys()))  # ['ani', 'a_list', 'delete_me', 'obi1']

    del db['delete_me']  # gone!

    print(list(db.keys()))  # ['ani', 'a_list', 'obi1']

    print('delete_me' in db)  # False
    print('ani' in db)  # True

    a_list = db['a_list']
    a_list.append(7)
```

```py
    db['a_list'] = a_list
    print(db['a_list'])  # [2, 3, 5, 7]
```

除了接线和围绕它的样板之外，前面的例子类似于使用字典进行练习。我们创建一个简单的`Person`类，然后在上下文管理器中打开一个`shelve`文件。正如你所看到的，我们使用字典语法来存储四个对象：两个`Person`实例，一个列表和一个字符串。如果我们打印`keys`，我们会得到一个包含我们使用的四个键的列表。打印完后，我们立即从架子上删除了（恰如其名的）`delete_me`键/值对。再次打印`keys`显示删除已成功。然后我们测试了一对键的成员资格，最后，我们将数字`7`附加到`a_list`上。请注意，我们必须从架子上提取列表，修改它，然后再次保存它。

如果这种行为是不希望的，我们可以做一些事情：

```py
# persistence/shelf.py
with shelve.open('shelf2.shelve', writeback=True) as db:
    db['a_list'] = [11, 13, 17]
    db['a_list'].append(19)  # in-place append!
    print(db['a_list'])  # [11, 13, 17, 19]
```

通过以`writeback=True`打开架子，我们启用了`writeback`功能，这使我们可以简单地将`a_list`附加到其中，就好像它实际上是常规字典中的一个值。这个功能之所以不是默认激活的原因是，它会以内存消耗和更慢的关闭架子的方式付出代价。

现在我们已经向与数据持久性相关的标准库模块致敬，让我们来看看 Python 生态系统中最广泛采用的 ORM：*SQLAlchemy*。

# 将数据保存到数据库

对于这个例子，我们将使用内存数据库，这将使事情对我们来说更简单。在书的源代码中，我留下了一些注释，以向您展示如何生成一个 SQLite 文件，所以我希望您也会探索这个选项。

您可以在[sqlitebrowser.org](http://sqlitebrowser.org/)找到一个免费的 SQLite 数据库浏览器。如果您对此不满意，您将能够找到各种工具，有些是免费的，有些不是免费的，您可以用来访问和操作数据库文件。

在我们深入代码之前，让我简要介绍一下关系数据库的概念。

关系数据库是一种允许您按照 1969 年由 Edgar F. Codd 发明的**关系模型**保存数据的数据库。在这个模型中，数据存储在一个或多个表中。每个表都有行（也称为**记录**或**元组**），每个行代表表中的一个条目。表还有列（也称为**属性**），每个列代表记录的一个属性。每个记录通过一个唯一键来标识，更常见的是**主键**，它是表中一个或多个列的联合。举个例子：想象一个名为`Users`的表，有列`id`、`username`、`password`、`name`和`surname`。这样的表非常适合包含我们系统的用户。每一行代表一个不同的用户。例如，具有值`3`、`gianchub`、`my_wonderful_pwd`、`Fabrizio`和`Romano`的行将代表我在系统中的用户。

模型被称为**关系型**的原因是因为您可以在表之间建立关系。例如，如果您向我们虚构的数据库添加一个名为`PhoneNumbers`的表，您可以向其中插入电话号码，然后通过关系建立哪个电话号码属于哪个用户。

为了查询关系数据库，我们需要一种特殊的语言。主要标准称为**SQL**，代表**结构化查询语言**。它源自一种称为**关系代数**的东西，这是一组用于模拟按照关系模型存储的数据并对其进行查询的非常好的代数。你通常可以执行的最常见操作包括对行或列进行过滤、连接表、根据某些标准对结果进行聚合等。举个英文例子，对我们想象中的数据库的查询可能是：*获取所有用户名以“m”开头，最多有一个电话号码的用户（用户名、名字、姓氏）*。在这个查询中，我们要求获取`User`表中的一部分列。我们通过筛选用户，只选择用户名以字母“m”开头的用户，甚至进一步，只选择最多有一个电话号码的用户。

在我在帕多瓦大学上学的时候，我花了一个学期的时间学习关系代数语义和标准 SQL（还有其他东西）。如果不是因为我在考试当天遭遇了一次严重的自行车事故，我会说这是我准备过的最有趣的考试之一。

现在，每个数据库都有自己的 SQL“口味”。它们都在一定程度上遵守标准，但没有一个完全遵守，并且它们在某些方面彼此不同。这在现代软件开发中构成了一个问题。如果我们的应用程序包含 SQL 代码，那么如果我们决定使用不同的数据库引擎，或者可能是同一引擎的不同版本，很可能会发现我们的 SQL 代码需要修改。

这可能会很痛苦，特别是因为 SQL 查询很快就会变得非常复杂。为了稍微减轻这种痛苦，计算机科学家们（感谢他们）创建了将特定语言的对象映射到关系数据库表的代码。毫不奇怪，这种工具的名称是**对象关系映射**（ORM）。

在现代应用程序开发中，通常会通过使用 ORM 来开始与数据库交互，如果你发现自己无法通过 ORM 执行需要执行的查询，那么你会转而直接使用 SQL。这是在完全没有 SQL 和不使用 ORM 之间的一个很好的折衷，这最终意味着专门化与数据库交互的代码，带来了前面提到的缺点。

在这一部分，我想展示一个利用 SQLAlchemy 的例子，这是最流行的 Python ORM。我们将定义两个模型（`Person`和`Address`），它们分别映射到一个表，然后我们将填充数据库并对其执行一些查询。

让我们从模型声明开始：

```py
# persistence/alchemy_models.py
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import (
    Column, Integer, String, ForeignKey, create_engine)
from sqlalchemy.orm import relationship
```

一开始，我们导入一些函数和类型。然后，我们需要创建一个引擎。这个引擎告诉 SQLAlchemy 我们选择的数据库类型是什么。

```py
# persistence/alchemy_models.py
engine = create_engine('sqlite:///:memory:')
Base = declarative_base()

class Person(Base):
    __tablename__ = 'person'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    age = Column(Integer)

    addresses = relationship(
        'Address',
        back_populates='person',
        order_by='Address.email',
        cascade='all, delete-orphan'
    )

    def __repr__(self):
        return f'{self.name}(id={self.id})'

class Address(Base):
    __tablename__ = 'address'

    id = Column(Integer, primary_key=True)
    email = Column(String)
    person_id = Column(ForeignKey('person.id'))
    person = relationship('Person', back_populates='addresses')

    def __str__(self):
        return self.email
    __repr__ = __str__

Base.metadata.create_all(engine)
```

然后，每个模型都继承自`Base`表，在这个例子中，它由`declarative_base()`返回的默认值组成。我们定义了`Person`，它映射到一个名为`person`的表，并公开`id`、`name`和`age`属性。我们还声明了与`Address`模型的关系，通过声明访问`addresses`属性将获取与我们正在处理的特定`Person`实例相关的`address`表中的所有条目。`cascade`选项影响创建和删除的工作方式，但这是一个更高级的概念，所以我建议你现在先略过它，以后可能再进行更深入的调查。

我们声明的最后一件事是`__repr__`方法，它为我们提供了对象的官方字符串表示。这应该是一个可以用来完全重建对象的表示，但在这个例子中，我只是用它来提供输出。Python 将`repr(obj)`重定向到对`obj.__repr__()`的调用。

我们还声明了`Address`模型，它将包含电子邮件地址，以及它们所属的人的引用。你可以看到`person_id`和`person`属性都是关于设置`Address`和`Person`实例之间的关系。注意我在`Address`上声明了`__str__`方法，然后给它分配了一个别名，叫做`__repr__`。这意味着在`Address`对象上调用`repr`和`str`最终都会调用`__str__`方法。这在 Python 中是一种常见的技术，所以我在这里有机会向你展示。

在最后一行，我们告诉引擎根据我们的模型在数据库中创建表。

对这段代码的更深理解需要比我能提供的空间更多，所以我鼓励你阅读**数据库管理系统**（**DBMS**）、SQL、关系代数和 SQLAlchemy。

现在我们有了我们的模型，让我们使用它们来保存一些数据！

让我们看看下面的例子：

```py
# persistence/alchemy.py
from alchemy_models import Person, Address, engine
from sqlalchemy.orm import sessionmaker

Session = sessionmaker(bind=engine)
session = Session()
```

首先我们创建会话，这是我们用来管理数据库的对象。接下来，我们创建了两个人：

```py
anakin = Person(name='Anakin Skywalker', age=32)
obi1 = Person(name='Obi-Wan Kenobi', age=40)
```

然后我们为他们都添加电子邮件地址，使用了两种不同的技术。一种将它们分配给一个列表，另一种只是简单地将它们附加到列表中：

```py
obi1.addresses = [
    Address(email='obi1@example.com'),
    Address(email='wanwan@example.com'),
]

anakin.addresses.append(Address(email='ani@example.com'))
anakin.addresses.append(Address(email='evil.dart@example.com'))
anakin.addresses.append(Address(email='vader@example.com'))
```

我们还没有触及数据库。只有当我们使用会话对象时，它才会发生实际的变化：

```py
session.add(anakin)
session.add(obi1)
session.commit()
```

添加这两个`Person`实例足以添加它们的地址（这要归功于级联效应）。调用`commit`实际上告诉 SQLAlchemy 提交事务并将数据保存到数据库中。事务是在数据库上下文中提供类似沙盒的操作。只要事务没有提交，我们就可以回滚对数据库所做的任何修改，从而恢复到事务开始之前的状态。SQLAlchemy 提供了更复杂和细粒度的处理事务的方式，你可以在它的官方文档中学习，因为这是一个非常高级的话题。现在我们通过使用`like`查询所有以`Obi`开头的人的名字，这将连接到 SQL 中的`LIKE`操作符：

```py
obi1 = session.query(Person).filter(
    Person.name.like('Obi%')
).first()
print(obi1, obi1.addresses)
```

我们获取该查询的第一个结果（我们知道我们只有 Obi-Wan），然后打印出来。然后我们通过使用他的名字进行精确匹配来获取`anakin`（只是为了向你展示另一种过滤的方式）：

```py
anakin = session.query(Person).filter(
    Person.name=='Anakin Skywalker'
).first()
print(anakin, anakin.addresses)
```

然后我们捕获了 Anakin 的 ID，并从全局框架中删除了`anakin`对象：

```py
anakin_id = anakin.id
del anakin
```

我们这样做是因为我想向你展示如何通过 ID 获取对象。在我们这样做之前，我们编写了`display_info`函数，我们将使用它来显示数据库的全部内容（从地址开始获取，以演示如何通过使用 SQLAlchemy 中的关系属性来获取对象）：

```py
def display_info():
    # get all addresses first
    addresses = session.query(Address).all()

    # display results
    for address in addresses:
        print(f'{address.person.name} <{address.email}>')

    # display how many objects we have in total
    print('people: {}, addresses: {}'.format(
        session.query(Person).count(),
        session.query(Address).count())
    )
```

`display_info`函数打印出所有的地址，以及相应的人的名字，并且最后产生了关于数据库中对象数量的最终信息。我们调用这个函数，然后获取并删除`anakin`（想想*Darth Vader*，你就不会因为删除他而难过），然后再次显示信息，以验证他确实已经从数据库中消失了：

```py
display_info()

anakin = session.query(Person).get(anakin_id)
session.delete(anakin)
session.commit()

display_info()
```

所有这些片段一起运行的输出如下（为了方便起见，我已经将输出分成四个块，以反映实际产生该输出的四个代码块）：

```py
$ python alchemy.py
Obi-Wan Kenobi(id=2) [obi1@example.com, wanwan@example.com] 
Anakin Skywalker(id=1) [ani@example.com, evil.dart@example.com, vader@example.com]
 Anakin Skywalker <ani@example.com>
Anakin Skywalker <evil.dart@example.com>
Anakin Skywalker <vader@example.com>
Obi-Wan Kenobi <obi1@example.com>
Obi-Wan Kenobi <wanwan@example.com>
people: 2, addresses: 5
 Obi-Wan Kenobi <obi1@example.com>
Obi-Wan Kenobi <wanwan@example.com>
people: 1, addresses: 2
```

从最后两个代码块可以看出，删除`anakin`已经删除了一个`Person`对象和与之相关的三个地址。再次强调，这是因为在删除`anakin`时发生了级联。

这就结束了我们对数据持久性的简要介绍。这是一个广阔且有时复杂的领域，我鼓励您尽可能多地学习理论。在涉及数据库系统时，缺乏知识或适当的理解可能会带来真正的麻烦。

# 总结

在本章中，我们探讨了如何处理文件和目录。我们学会了如何打开文件进行读写，以及如何通过使用上下文管理器更加优雅地进行操作。我们还探讨了目录：如何递归和非递归地列出它们的内容。我们还学习了路径名，这是访问文件和目录的入口。

我们随后简要介绍了如何创建 ZIP 存档，并提取其内容。该书的源代码还包含了一个不同压缩格式的示例：`tar.gz`。

我们谈到了数据交换格式，并深入探讨了 JSON。我们在为特定的 Python 数据类型编写自定义编码器和解码器时玩得很开心。

然后，我们探讨了 IO，包括内存流和 HTTP 请求。

最后，我们看到了如何使用`pickle`、`shelve`和 SQLAlchemy ORM 库来持久化数据。

现在，您应该对如何处理文件和数据持久性有了相当好的了解，我希望您会花时间自己更深入地探索这些主题。

下一章将讨论测试、性能分析和处理异常。
