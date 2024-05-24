# Python 入门指南（七）

> 原文：[`zh.annas-archive.org/md5/97bc15629f1b51a0671040c56db61b92`](https://zh.annas-archive.org/md5/97bc15629f1b51a0671040c56db61b92)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二十二章：Python 设计模式 I

在上一章中，我们简要介绍了设计模式，并介绍了迭代器模式，这是一个非常有用和常见的模式，以至于它已经被抽象成了编程语言本身的核心。在本章中，我们将回顾其他常见的模式，以及它们在 Python 中的实现方式。与迭代一样，Python 通常提供另一种语法来使处理这些问题更简单。我们将涵盖这些模式的*传统*设计和 Python 版本。

总之，我们将看到：

+   许多特定的模式

+   Python 中每种模式的典型实现

+   用 Python 语法替换某些模式

# 装饰器模式

装饰器模式允许我们用其他对象包装提供核心功能的对象。使用装饰过的对象的任何对象将以与未装饰的对象完全相同的方式与其交互（即，装饰过的对象的接口与核心对象的接口相同）。

装饰器模式的两个主要用途：

+   增强组件发送数据到第二个组件的响应

+   支持多个可选行为

第二个选项通常是多重继承的一个合适的替代方案。我们可以构建一个核心对象，然后创建一个装饰器包装该核心。由于装饰器对象具有与核心对象相同的接口，我们甚至可以将新对象包装在其他装饰器中。以下是它在 UML 图中的样子：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/8b15b21b-6d6e-49e9-88be-d5907baa55b1.png)

在这里，**Core**和所有的装饰器都实现了特定的**接口**。装饰器通过组合维护对**接口**的另一个实例的引用。当调用时，装饰器在调用其包装的接口之前或之后进行一些附加处理。被包装的对象可以是另一个装饰器，也可以是核心功能。虽然多个装饰器可以相互包装，但是所有这些装饰器中心的对象提供了核心功能。

# 一个装饰器的例子

让我们看一个来自网络编程的例子。我们将使用 TCP 套接字。`socket.send()`方法接受一串输入字节并将它们输出到另一端的接收套接字。有很多库可以接受套接字并访问这个函数来在流上发送数据。让我们创建这样一个对象；它将是一个交互式 shell，等待客户端的连接，然后提示用户输入一个字符串响应：

```py
import socket

def respond(client):
    response = input("Enter a value: ")
    client.send(bytes(response, "utf8"))
    client.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 2401))
server.listen(1)
try:
    while True:
        client, addr = server.accept()
        respond(client)
finally:
    server.close()
```

`respond`函数接受一个`socket`参数并提示要发送的数据作为回复，然后发送它。要使用它，我们构建一个服务器套接字，并告诉它在本地计算机上的端口`2401`上进行监听（我随机选择了端口）。当客户端连接时，它调用`respond`函数，该函数交互式地请求数据并做出适当的响应。需要注意的重要事情是，`respond`函数只关心套接字接口的两种方法：`send`和`close`。

为了测试这一点，我们可以编写一个非常简单的客户端，连接到相同的端口并在退出之前输出响应：

```py
import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 2401))
print("Received: {0}".format(client.recv(1024)))
client.close()
```

要使用这些程序，请按照以下步骤进行：

1.  在一个终端中启动服务器。

1.  打开第二个终端窗口并运行客户端。

1.  在服务器窗口的“输入值：”提示处，输入一个值并按*Enter*键。

1.  客户端将接收您输入的内容，将其打印到控制台上，并退出。再次运行客户端；服务器将提示输入第二个值。

结果将看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/eb9bc3a4-1442-4fb6-b56c-44f9a298c86a.png)

现在，回顾我们的服务器代码，我们看到了两个部分。`respond`函数将数据发送到一个`socket`对象中。剩下的脚本负责创建该`socket`对象。我们将创建一对装饰器，定制套接字的行为，而无需扩展或修改套接字本身。

让我们从一个*logging*装饰器开始。这个对象在将数据发送到客户端之前，将任何数据输出到服务器的控制台上：

```py
class LogSocket:
    def __init__(self, socket):
        self.socket = socket

    def send(self, data):
        print(
            "Sending {0} to {1}".format(
                data, self.socket.getpeername()[0]
            )
        )
        self.socket.send(data)

    def close(self):
        self.socket.close()
```

这个类装饰了一个`socket`对象，并向客户端 socket 呈现`send`和`close`接口。一个更好的装饰器还应该实现（可能定制）所有剩余的`socket`方法。它还应该正确地实现`send`的所有参数（实际上还接受一个可选的 flags 参数），但让我们保持我们的例子简单。每当在这个对象上调用`send`时，它都会在将数据发送到客户端之前将输出记录到屏幕上，使用原始 socket。

我们只需要改变原始代码中的一行，就可以使用这个装饰器。我们不再用 socket 调用`respond`，而是用一个装饰过的 socket 调用它：

```py
respond(LogSocket(client)) 
```

虽然这很简单，但我们必须问自己，为什么我们不只是扩展`socket`类并覆盖`send`方法。我们可以调用`super().send`在记录后进行实际发送。这种设计也没有问题。

当面临装饰器和继承之间的选择时，只有在我们需要根据某些条件动态修改对象时，才应该使用装饰器。例如，我们可能只想在服务器当前处于调试模式时启用日志装饰器。当我们有多个可选行为时，装饰器也比多重继承更胜一筹。例如，我们可以编写第二个装饰器，每当调用`send`时，就使用`gzip`压缩数据：

```py
import gzip
from io import BytesIO

class GzipSocket:
    def __init__(self, socket):
        self.socket = socket

    def send(self, data):
        buf = BytesIO()
        zipfile = gzip.GzipFile(fileobj=buf, mode="w")
        zipfile.write(data)
        zipfile.close()
        self.socket.send(buf.getvalue())

    def close(self):
        self.socket.close()
```

在这个版本中，`send`方法在发送到客户端之前压缩传入的数据。

现在我们有了这两个装饰器，我们可以编写代码，在响应时动态地在它们之间切换。这个例子并不完整，但它说明了我们可能遵循的逻辑来混合和匹配装饰器：

```py
        client, addr = server.accept() 
        if log_send: 
            client = LogSocket(client) 
        if client.getpeername()[0] in compress_hosts: 
            client = GzipSocket(client) 
        respond(client) 
```

这段代码检查一个名为`log_send`的假设配置变量。如果启用了，它会将 socket 包装在`LogSocket`装饰器中。类似地，它检查连接的客户端是否在已知接受压缩内容的地址列表中。如果是，它会将客户端包装在`GzipSocket`装饰器中。请注意，这两个装饰器中的任何一个、两个或全部都可能被启用，这取决于配置和连接的客户端。尝试使用多重继承来编写这个，并看看你会有多困惑！

# Python 中的装饰器

装饰器模式在 Python 中很有用，但也有其他选择。例如，我们可以使用 monkey-patching（例如，`socket.socket.send = log_send`）来获得类似的效果。单继承，其中*可选*的计算在一个大方法中完成，可能是一个选择，而多继承不应该被写入，只是因为它不适用于先前看到的特定示例。

在 Python 中，很常见在函数上使用这种模式。正如我们在前一章中看到的，函数也是对象。事实上，函数装饰是如此常见，以至于 Python 提供了一种特殊的语法，使得将这种装饰器应用到函数变得容易。

例如，我们可以更一般地看待日志示例。我们可能会发现，不仅仅是在 socket 上发送调用时记录，记录所有对某些函数或方法的调用可能会有所帮助。以下示例实现了一个装饰器，正是这样做的：

```py
import time

def log_calls(func):
    def wrapper(*args, **kwargs):
        now = time.time()
        print(
            "Calling {0} with {1} and {2}".format(
                func.__name__, args, kwargs
            )
        )
        return_value = func(*args, **kwargs)
        print(
            "Executed {0} in {1}ms".format(
                func.__name__, time.time() - now
            )
        )
        return return_value

    return wrapper

def test1(a, b, c):
    print("\ttest1 called")

def test2(a, b):
    print("\ttest2 called")

def test3(a, b):
    print("\ttest3 called")
    time.sleep(1)

test1 = log_calls(test1)
test2 = log_calls(test2)
test3 = log_calls(test3)

test1(1, 2, 3)
test2(4, b=5)
test3(6, 7)

```

这个装饰器函数与我们之前探讨的示例非常相似；在这些情况下，装饰器接受一个类似 socket 的对象并创建一个类似 socket 的对象。这次，我们的装饰器接受一个函数对象并返回一个新的函数对象。这段代码包括三个单独的任务：

+   一个函数，`log_calls`，接受另一个函数

+   这个函数定义了（内部）一个名为`wrapper`的新函数，在调用原始函数之前做一些额外的工作

+   内部函数从外部函数返回

三个示例函数演示了装饰器的使用。第三个函数包括一个`sleep`调用来演示定时测试。我们将每个函数传递给装饰器，它返回一个新函数。我们将这个新函数赋给原始变量名，有效地用装饰后的函数替换了原始函数。

这种语法允许我们动态构建装饰函数对象，就像我们在套接字示例中所做的那样。如果我们不替换名称，我们甚至可以为不同情况保留装饰和非装饰版本。

通常，这些装饰器是应用于不同函数的永久性通用修改。在这种情况下，Python 支持一种特殊的语法，在函数定义时应用装饰器。我们已经在一些地方看到了这种语法；现在，让我们了解一下它是如何工作的。

我们可以使用`@decorator`语法一次完成所有操作，而不是在方法定义之后应用装饰器函数：

```py
@log_calls 
def test1(a,b,c): 
    print("\ttest1 called") 
```

这种语法的主要好处是，我们可以很容易地看到在阅读函数定义时函数已经被装饰。如果装饰器是后来应用的，那么阅读代码的人可能会错过函数已经被修改的事实。回答类似“为什么我的程序将函数调用记录到控制台？”这样的问题可能会变得更加困难！但是，这种语法只能应用于我们定义的函数，因为我们无法访问其他模块的源代码。如果我们需要装饰第三方库中的函数，我们必须使用之前的语法。

装饰器语法还有更多我们在这里没有看到的内容。我们没有足够的空间来涵盖这里的高级主题，所以请查看 Python 参考手册或其他教程以获取更多信息。装饰器可以被创建为可调用对象，而不仅仅是返回函数的函数。类也可以被装饰；在这种情况下，装饰器返回一个新类，而不是一个新函数。最后，装饰器可以接受参数，以便根据每个函数的情况进行自定义。

# 观察者模式

观察者模式对于状态监控和事件处理非常有用。这种模式允许一个给定的对象被未知和动态的*观察者*对象监视。

每当核心对象上的值发生变化时，它都会通过调用`update()`方法来通知所有观察者对象发生了变化。每个观察者在核心对象发生变化时可能负责不同的任务；核心对象不知道也不关心这些任务是什么，观察者通常也不知道也不关心其他观察者在做什么。

这是它在 UML 中的表示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/e85ff8d1-0a84-4509-baf1-cafe21b4f31e.png)

# 观察者模式示例

观察者模式可能在冗余备份系统中很有用。我们可以编写一个维护特定值的核心对象，然后有一个或多个观察者创建该对象的序列化副本。例如，这些副本可以存储在数据库中，存储在远程主机上，或者存储在本地文件中。让我们使用属性来实现核心对象：

```py
class Inventory:
    def __init__(self):
        self.observers = []
        self._product = None
        self._quantity = 0

    def attach(self, observer):
        self.observers.append(observer)

    @property
    def product(self):
        return self._product

    @product.setter
    def product(self, value):
        self._product = value
        self._update_observers()

    @property
    def quantity(self):
        return self._quantity

    @quantity.setter
    def quantity(self, value):
        self._quantity = value
 self._update_observers()

 def _update_observers(self):
 for observer in self.observers:
 observer()
```

这个对象有两个属性，当设置时，会调用自身的`_update_observers`方法。这个方法所做的就是循环遍历任何注册的观察者，并让每个观察者知道发生了一些变化。在这种情况下，我们直接调用观察者对象；对象将必须实现`__call__`来处理更新。这在许多面向对象的编程语言中是不可能的，但在 Python 中是一个有用的快捷方式，可以帮助我们使我们的代码更易读。

现在让我们实现一个简单的观察者对象；这个对象只会将一些状态打印到控制台上：

```py
class ConsoleObserver: 
    def __init__(self, inventory): 
        self.inventory = inventory 

    def __call__(self): 
        print(self.inventory.product) 
        print(self.inventory.quantity) 
```

这里没有什么特别激动人心的东西；观察到的对象在初始化程序中设置，当观察者被调用时，我们会执行*某些操作*。我们可以在交互式控制台中测试观察者：

```py
    >>> i = Inventory()
    >>> c = ConsoleObserver(i)
    >>> i.attach(c)
    >>> i.product = "Widget"
    Widget
    0
    >>> i.quantity = 5
    Widget
    5  
```

将观察者附加到`Inventory`对象后，每当我们更改两个观察属性中的一个时，观察者都会被调用并执行其操作。我们甚至可以添加两个不同的观察者实例：

```py
    >>> i = Inventory()
    >>> c1 = ConsoleObserver(i)
    >>> c2 = ConsoleObserver(i)
    >>> i.attach(c1)
    >>> i.attach(c2)
    >>> i.product = "Gadget"
    Gadget
    0
    Gadget
    0  
```

这次当我们改变产品时，有两套输出，每个观察者一个。这里的关键思想是我们可以轻松地添加完全不同类型的观察者，同时备份数据到文件、数据库或互联网应用程序。

观察者模式将被观察的代码与观察的代码分离。如果我们不使用这种模式，我们将不得不在每个属性中放置代码来处理可能出现的不同情况；记录到控制台、更新数据库或文件等。所有这些任务的代码都将与被观察的对象混在一起。维护它将是一场噩梦，并且在以后添加新的监视功能将是痛苦的。

# 策略模式

策略模式是面向对象编程中抽象的常见演示。该模式实现了单个问题的不同解决方案，每个解决方案都在不同的对象中。客户端代码可以在运行时动态选择最合适的实现。

通常，不同的算法有不同的权衡；一个可能比另一个更快，但使用了更多的内存，而第三个算法可能在多个 CPU 存在或提供分布式系统时最合适。以下是 UML 中的策略模式：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/6fd266d3-d237-415d-9b9c-aec09ee33129.png)

**用户**连接到策略模式的代码只需要知道它正在处理**抽象**接口。所选择的实际实现以不同的方式执行相同的任务；无论如何，接口都是相同的。

# 策略示例

策略模式的典型示例是排序例程；多年来，已经发明了许多用于对对象集合进行排序的算法；快速排序、归并排序和堆排序都是快速排序算法，具有不同的特性，每种都有其自身的用途，取决于输入的大小和类型，它们的顺序有多乱，以及系统的要求。

如果我们有需要对集合进行排序的客户端代码，我们可以将其传递给具有`sort()`方法的对象。这个对象可以是`QuickSorter`或`MergeSorter`对象，但结果在任何情况下都是相同的：一个排序好的列表。用于进行排序的策略被抽象出来，使其模块化和可替换。

当然，在 Python 中，我们通常只是调用`sorted`函数或`list.sort`方法，并相信它会以接近最佳的方式进行排序。因此，我们确实需要看一个更好的例子。

让我们考虑一个桌面壁纸管理器。当图像显示在桌面背景上时，可以以不同的方式调整到屏幕大小。例如，假设图像比屏幕小，可以在屏幕上平铺、居中或缩放以适应。

还有其他更复杂的策略可以使用，例如缩放到最大高度或宽度，将其与实心、半透明或渐变背景颜色相结合，或其他操作。虽然我们可能希望稍后添加这些策略，但让我们从基本的开始。

我们的策略对象需要两个输入；要显示的图像和屏幕宽度和高度的元组。它们每个都返回一个新的屏幕大小的图像，图像根据给定的策略进行调整。您需要使用`pip3 install pillow`安装`pillow`模块才能使此示例工作：

```py
from PIL import Image

class TiledStrategy:
    def make_background(self, img_file, desktop_size):
        in_img = Image.open(img_file)
        out_img = Image.new("RGB", desktop_size)
        num_tiles = [
            o // i + 1 for o, i in zip(out_img.size, in_img.size)
        ]
        for x in range(num_tiles[0]):
            for y in range(num_tiles[1]):
                out_img.paste(
                    in_img,
                    (
                        in_img.size[0] * x,
                        in_img.size[1] * y,
                        in_img.size[0] * (x + 1),
                        in_img.size[1] * (y + 1),
                    ),
                )
        return out_img

class CenteredStrategy:
    def make_background(self, img_file, desktop_size):
        in_img = Image.open(img_file)
        out_img = Image.new("RGB", desktop_size)
        left = (out_img.size[0] - in_img.size[0]) // 2
        top = (out_img.size[1] - in_img.size[1]) // 2
        out_img.paste(
            in_img,
            (left, top, left + in_img.size[0], top + in_img.size[1]),
        )
        return out_img

class ScaledStrategy:
    def make_background(self, img_file, desktop_size):
        in_img = Image.open(img_file)
        out_img = in_img.resize(desktop_size)
        return out_img
```

在这里，我们有三种策略，每种策略都使用`PIL`来执行它们的任务。各个策略都有一个`make_background`方法，接受相同的参数集。一旦选择，就可以调用适当的策略来创建正确大小的桌面图像。`TiledStrategy`循环遍历可以适应图像宽度和高度的输入图像数量，并将其重复复制到每个位置。`CenteredStrategy`计算出需要在图像的四个边缘留下多少空间来使其居中。`ScaledStrategy`将图像强制缩放到输出大小（忽略纵横比）。

考虑一下，如果没有策略模式，如何在这些选项之间进行切换的实现。我们需要把所有的代码放在一个很大的方法中，并使用一个笨拙的`if`语句来选择预期的选项。每次我们想要添加一个新的策略，我们都必须使方法变得更加笨拙。

# Python 中的策略

策略模式的前面的经典实现，在大多数面向对象的库中非常常见，但在 Python 编程中很少见。

这些类分别代表什么都不做，只提供一个函数的对象。我们可以轻松地将该函数称为`__call__`，并直接使对象可调用。由于对象没有与之关联的其他数据，我们只需要创建一组顶层函数并将它们作为我们的策略传递。

因此，设计模式哲学的反对者会说，*因为 Python 具有一流函数，策略模式是不必要的*。事实上，Python 的一流函数使我们能够以更直接的方式实现策略模式。知道这种模式的存在仍然可以帮助我们选择程序的正确设计，但是使用更可读的语法来实现它。当我们需要允许客户端代码或最终用户从相同接口的多个实现中进行选择时，应该使用策略模式或其顶层函数实现。

# 状态模式

状态模式在结构上类似于策略模式，但其意图和目的非常不同。状态模式的目标是表示状态转换系统：在这些系统中，很明显对象可以处于特定状态，并且某些活动可能会将其驱动到不同的状态。

为了使其工作，我们需要一个管理器或上下文类，提供切换状态的接口。在内部，这个类包含对当前状态的指针。每个状态都知道它被允许处于什么其他状态，并且将根据在其上调用的操作而转换到这些状态。

因此，我们有两种类型的类：上下文类和多个状态类。上下文类维护当前状态，并将操作转发给状态类。状态类通常对于调用上下文的任何其他对象都是隐藏的；它就像一个黑匣子，恰好在内部执行状态管理。在 UML 中的样子如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/fbbbb670-9479-419e-8a82-8c1a99273eba.png)

# 状态示例

为了说明状态模式，让我们构建一个 XML 解析工具。上下文类将是解析器本身。它将以字符串作为输入，并将工具置于初始解析状态。各种解析状态将吃掉字符，寻找特定的值，当找到该值时，转换到不同的状态。目标是为每个标签及其内容创建一个节点对象树。为了使事情更容易管理，我们只解析 XML 的一个子集 - 标签和标签名称。我们将无法处理标签上的属性。它将解析标签的文本内容，但不会尝试解析*混合*内容，其中包含文本内的标签。这是一个我们将能够解析的*简化 XML*文件的示例：

```py
<book> 
    <author>Dusty Phillips</author> 
    <publisher>Packt Publishing</publisher> 
    <title>Python 3 Object Oriented Programming</title> 
    <content> 
        <chapter> 
            <number>1</number> 
            <title>Object Oriented Design</title> 
        </chapter> 
        <chapter> 
            <number>2</number> 
            <title>Objects In Python</title> 
        </chapter> 
    </content> 
</book> 
```

在我们查看状态和解析器之前，让我们考虑一下这个程序的输出。我们知道我们想要一个`Node`对象的树，但`Node`是什么样子呢？它显然需要知道它正在解析的标签的名称，而且由于它是一棵树，它可能应该保持对父节点的指针和按顺序列出节点的子节点的列表。有些节点有文本值，但不是所有节点都有。让我们首先看看这个`Node`类：

```py
class Node:
    def __init__(self, tag_name, parent=None):
        self.parent = parent
        self.tag_name = tag_name
        self.children = []
        self.text = ""

    def __str__(self):
        if self.text:
            return self.tag_name + ": " + self.text
        else:
            return self.tag_name
```

这个类在初始化时设置默认属性值。提供`__str__`方法来帮助在完成时可视化树结构。

现在，看看示例文档，我们需要考虑我们的解析器可以处于哪些状态。显然，它将开始于尚未处理任何节点的状态。我们需要一个用于处理开放标签和关闭标签的状态。当我们在具有文本内容的标签内部时，我们还需要将其处理为单独的状态。

状态转换可能会很棘手；我们如何知道下一个节点是开放标签、关闭标签还是文本节点？我们可以在每个状态中放入一些逻辑来解决这个问题，但实际上创建一个唯一目的是确定下一个状态的新状态更有意义。如果我们将这个过渡状态称为**ChildNode**，我们最终得到以下状态：

+   `FirstTag`

+   `ChildNode`

+   `OpenTag`

+   `CloseTag`

+   `Text`

**FirstTag**状态将切换到**ChildNode**，它负责决定要切换到其他三个状态中的哪一个；当这些状态完成时，它们将切换回**ChildNode**。以下状态转换图显示了可用的状态变化：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/42bbeb78-0f77-46d7-be78-a15970c6a3bd.png)

状态负责获取*字符串的剩余部分*，处理尽可能多的内容，然后告诉解析器处理其余部分。让我们首先构建`Parser`类：

```py
class Parser: 
    def __init__(self, parse_string): 
        self.parse_string = parse_string 
        self.root = None 
        self.current_node = None 

        self.state = FirstTag() 

    def process(self, remaining_string): 
        remaining = self.state.process(remaining_string, self) 
        if remaining: 
            self.process(remaining) 

    def start(self): 
        self.process(self.parse_string) 
```

初始化程序在类上设置了一些变量，这些变量将由各个状态访问。`parse_string`实例变量是我们试图解析的文本。`root`节点是 XML 结构中的*顶部*节点。`current_node`实例变量是我们当前正在向其添加子节点的节点。

这个解析器的重要特性是`process`方法，它接受剩余的字符串，并将其传递给当前状态。解析器（`self`参数）也被传递到状态的`process`方法中，以便状态可以操作它。当状态完成处理时，预期状态将返回未解析字符串的剩余部分。然后解析器递归调用这个剩余字符串上的`process`方法来构造树的其余部分。

现在让我们来看一下`FirstTag`状态：

```py
class FirstTag:
    def process(self, remaining_string, parser):
        i_start_tag = remaining_string.find("<")
        i_end_tag = remaining_string.find(">")
        tag_name = remaining_string[i_start_tag + 1 : i_end_tag]
        root = Node(tag_name)
 parser.root = parser.current_node = root
 parser.state = ChildNode()
        return remaining_string[i_end_tag + 1 :]
```

这个状态找到了第一个标签的开放和关闭尖括号的索引（`i_`代表索引）。您可能认为这个状态是多余的，因为 XML 要求在开放标签之前没有文本。然而，可能需要消耗空白字符；这就是为什么我们搜索开放尖括号而不是假设它是文档中的第一个字符。

请注意，此代码假定输入文件有效。一个正确的实现将严格测试无效输入，并尝试恢复或显示极具描述性的错误消息。

该方法提取标签的名称并将其分配给解析器的根节点。它还将其分配给`current_node`，因为那是我们接下来要添加子节点的节点。

然后是重要的部分：该方法将解析器对象上的当前状态更改为`ChildNode`状态。然后返回字符串的剩余部分（在开放标签之后）以允许其被处理。

看起来相当复杂的`ChildNode`状态实际上只需要一个简单的条件：

```py
class ChildNode: 
    def process(self, remaining_string, parser): 
        stripped = remaining_string.strip() 
        if stripped.startswith("</"): 
 parser.state = CloseTag() 
        elif stripped.startswith("<"): 
 parser.state = OpenTag() 
        else: 
 parser.state = TextNode() 
        return stripped 
```

`strip()`调用从字符串中删除空白。然后解析器确定下一个项是开放标签、关闭标签还是文本字符串。根据发生的可能性，它将解析器设置为特定状态，然后告诉它解析字符串的其余部分。

`OpenTag`状态类似于`FirstTag`状态，只是它将新创建的节点添加到先前的`current_node`对象的`children`中，并将其设置为新的`current_node`。然后继续将处理器放回`ChildNode`状态：

```py
class OpenTag:
    def process(self, remaining_string, parser):
        i_start_tag = remaining_string.find("<")
        i_end_tag = remaining_string.find(">")
        tag_name = remaining_string[i_start_tag + 1 : i_end_tag]
        node = Node(tag_name, parser.current_node)
 parser.current_node.children.append(node)
 parser.current_node = node
 parser.state = ChildNode()
        return remaining_string[i_end_tag + 1 :]
```

`CloseTag`状态基本上做相反的事情；它将解析器的`current_node`设置回父节点，以便在外部标签中添加任何进一步的子节点：

```py
class CloseTag:
    def process(self, remaining_string, parser):
        i_start_tag = remaining_string.find("<")
        i_end_tag = remaining_string.find(">")
        assert remaining_string[i_start_tag + 1] == "/"
        tag_name = remaining_string[i_start_tag + 2 : i_end_tag]
        assert tag_name == parser.current_node.tag_name
 parser.current_node = parser.current_node.parent
 parser.state = ChildNode()
        return remaining_string[i_end_tag + 1 :].strip()
```

两个`assert`语句有助于确保解析字符串是一致的。

最后，`TextNode`状态非常简单地提取下一个关闭标签之前的文本，并将其设置为当前节点的值：

```py
class TextNode: 
    def process(self, remaining_string, parser): 
        i_start_tag = remaining_string.find('<') 
        text = remaining_string[:i_start_tag] 
 parser.current_node.text = text 
        parser.state = ChildNode() 
        return remaining_string[i_start_tag:] 
```

现在我们只需要在创建的解析器对象上设置初始状态。初始状态是一个`FirstTag`对象，所以只需将以下内容添加到`__init__`方法中：

```py
        self.state = FirstTag() 
```

为了测试这个类，让我们添加一个主脚本，从命令行打开一个文件，解析它，并打印节点：

```py
if __name__ == "__main__": 
    import sys 
    with open(sys.argv[1]) as file: 
        contents = file.read() 
        p = Parser(contents) 
        p.start() 

        nodes = [p.root] 
        while nodes: 
            node = nodes.pop(0) 
            print(node) 
            nodes = node.children + nodes 
```

这段代码打开文件，加载内容，并解析结果。然后按顺序打印每个节点及其子节点。我们最初在`node`类上添加的`__str__`方法负责格式化节点以供打印。如果我们在之前的示例上运行脚本，它将输出树如下：

```py
    book
    author: Dusty Phillips
    publisher: Packt Publishing
    title: Python 3 Object Oriented Programming
    content
    chapter
    number: 1
    title: Object Oriented Design
    chapter
    number: 2
    title: Objects In Python  
```

将这与原始简化的 XML 文档进行比较告诉我们解析器正在工作。

# 状态与策略

状态模式看起来与策略模式非常相似；实际上，两者的 UML 图是相同的。实现也是相同的。我们甚至可以将我们的状态编写为一等函数，而不是将它们包装在对象中，就像为策略建议的那样。

虽然这两种模式具有相同的结构，但它们解决完全不同的问题。策略模式用于在运行时选择算法；通常，只有一个算法会被选择用于特定用例。另一方面，状态模式旨在允许在某个过程发展时动态地在不同状态之间切换。在代码中，主要区别在于策略模式通常不知道其他策略对象。在状态模式中，状态或上下文需要知道它可以切换到哪些其他状态。

# 状态转换作为协程

状态模式是解决状态转换问题的经典面向对象解决方案。然而，您可以通过将对象构建为协程来获得类似的效果。还记得我们在第二十一章中构建的正则表达式日志文件解析器吗？那实际上是一个伪装的状态转换问题。该实现与定义状态模式中使用的所有对象（或函数）的实现之间的主要区别在于，协程解决方案允许我们在语言构造中编码更多的样板。有两种实现，但没有一种本质上比另一种更好。状态模式实际上是我考虑在`asyncio`之外使用协程的唯一场合。

# 单例模式

单例模式是最具争议的模式之一；许多人指责它是一种*反模式*，一种应该避免而不是推广的模式。在 Python 中，如果有人使用单例模式，他们几乎肯定是在做错事情，可能是因为他们来自一个更严格的编程语言。

那么，为什么要讨论它呢？单例是所有设计模式中最著名的之一。它在过度面向对象的语言中很有用，并且是传统面向对象编程的重要部分。更相关的是，单例背后的想法是有用的，即使我们在 Python 中以完全不同的方式实现了这个概念。

单例模式背后的基本思想是允许某个对象的确切实例只存在一个。通常，这个对象是一种类似于我们在第十九章中讨论的管理类。这些对象通常需要被各种其他对象引用，并且将对管理对象的引用传递给需要它们的方法和构造函数可能会使代码难以阅读。

相反，当使用单例时，独立的对象从类中请求管理对象的单个实例，因此无需传递对它的引用。UML 图表并没有完全描述它，但为了完整起见，这里是它：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/7a5b6442-fc27-49e5-944f-7bc6903ed2d9.png)

在大多数编程环境中，通过使构造函数私有（这样就没有人可以创建它的其他实例），然后提供一个静态方法来检索单个实例来强制实施单例。这个方法在第一次调用时创建一个新实例，然后对所有后续调用返回相同的实例。

# 单例实现

Python 没有私有构造函数，但为了这个目的，我们可以使用`__new__`类方法来确保只创建一个实例：

```py
class OneOnly: 
 _singleton = None 
    def __new__(cls, *args, **kwargs): 
        if not cls._singleton: 
 cls._singleton = super(OneOnly, cls 
                ).__new__(cls, *args, **kwargs) 
        return cls._singleton 
```

当调用`__new__`时，通常会构造该类的一个新实例。当我们重写它时，我们首先检查我们的单例实例是否已经创建；如果没有，我们使用`super`调用来创建它。因此，每当我们在`OneOnly`上调用构造函数时，我们总是得到完全相同的实例：

```py
    >>> o1 = OneOnly()
    >>> o2 = OneOnly()
    >>> o1 == o2
    True
    >>> o1
    <__main__.OneOnly object at 0xb71c008c>
    >>> o2
    <__main__.OneOnly object at 0xb71c008c>  
```

这两个对象是相等的，并且位于相同的地址；因此，它们是同一个对象。这个特定的实现并不是很透明，因为很难看出一个单例对象已经被创建。每当我们调用一个构造函数，我们期望得到该对象的一个新实例；在这种情况下，这个约定被违反了。也许，如果我们真的认为需要一个单例，类的良好文档字符串可以缓解这个问题。

但我们并不需要它。Python 程序员不喜欢强迫他们的代码用户进入特定的思维方式。我们可能认为一个类只需要一个实例，但其他程序员可能有不同的想法。单例可能会干扰分布式计算、并行编程和自动化测试，例如。在所有这些情况下，拥有特定对象的多个或替代实例可能非常有用，即使*正常*操作可能永远不需要一个。

# 模块变量可以模仿单例

通常，在 Python 中，可以使用模块级变量来充分模拟单例模式。它不像单例那样*安全*，因为人们随时可以重新分配这些变量，但就像我们在第十六章中讨论的私有变量一样，在 Python 中这是可以接受的。如果有人有充分的理由更改这些变量，我们为什么要阻止他们呢？它也不会阻止人们实例化对象的多个实例，但同样，如果他们有充分的理由这样做，为什么要干涉呢？

理想情况下，我们应该给它们一个机制来访问*默认的单例*值，同时也允许它们在需要时创建其他实例。虽然从技术上讲根本不是单例，但它提供了最符合 Python 风格的单例行为机制。

为了使用模块级变量而不是单例，我们在定义类之后实例化类的实例。我们可以改进我们的状态模式以使用单例。我们可以创建一个始终可访问的模块级变量，而不是在每次更改状态时创建一个新对象：

```py
class Node:
    def __init__(self, tag_name, parent=None):
        self.parent = parent
        self.tag_name = tag_name
        self.children = []
        self.text = ""

    def __str__(self):
        if self.text:
            return self.tag_name + ": " + self.text
        else:
            return self.tag_name

class FirstTag:
    def process(self, remaining_string, parser):
        i_start_tag = remaining_string.find("<")
        i_end_tag = remaining_string.find(">")
        tag_name = remaining_string[i_start_tag + 1 : i_end_tag]
        root = Node(tag_name)
        parser.root = parser.current_node = root
        parser.state = child_node
        return remaining_string[i_end_tag + 1 :]

class ChildNode:
    def process(self, remaining_string, parser):
        stripped = remaining_string.strip()
        if stripped.startswith("</"):
            parser.state = close_tag
        elif stripped.startswith("<"):
            parser.state = open_tag
        else:
            parser.state = text_node
        return stripped

class OpenTag:
    def process(self, remaining_string, parser):
        i_start_tag = remaining_string.find("<")
        i_end_tag = remaining_string.find(">")
        tag_name = remaining_string[i_start_tag + 1 : i_end_tag]
        node = Node(tag_name, parser.current_node)
        parser.current_node.children.append(node)
        parser.current_node = node
        parser.state = child_node
        return remaining_string[i_end_tag + 1 :]

class TextNode:
    def process(self, remaining_string, parser):
        i_start_tag = remaining_string.find("<")
        text = remaining_string[:i_start_tag]
        parser.current_node.text = text
        parser.state = child_node
        return remaining_string[i_start_tag:]

class CloseTag:
    def process(self, remaining_string, parser):
        i_start_tag = remaining_string.find("<")
        i_end_tag = remaining_string.find(">")
        assert remaining_string[i_start_tag + 1] == "/"
        tag_name = remaining_string[i_start_tag + 2 : i_end_tag]
        assert tag_name == parser.current_node.tag_name
        parser.current_node = parser.current_node.parent
        parser.state = child_node
        return remaining_string[i_end_tag + 1 :].strip()

first_tag = FirstTag()
child_node = ChildNode()
text_node = TextNode()
open_tag = OpenTag()
close_tag = CloseTag()
```

我们所做的只是创建可以重用的各种状态类的实例。请注意，即使在变量被定义之前，我们也可以在类内部访问这些模块变量？这是因为类内部的代码直到调用方法时才会执行，而到这个时候，整个模块都已经被定义了。

在这个例子中的不同之处在于，我们不是浪费内存创建一堆必须进行垃圾回收的新实例，而是为每个状态重用一个单一的状态对象。即使多个解析器同时运行，只需要使用这些状态类。

当我们最初创建基于状态的解析器时，您可能会想知道为什么我们没有将解析器对象传递给每个单独状态的`__init__`，而是像我们所做的那样将其传递给`process`方法。然后状态可以被引用为`self.parser`。这是状态模式的一个完全有效的实现，但它将不允许利用单例模式。如果状态对象保持对解析器的引用，那么它们就不能同时用于引用其他解析器。

请记住，这是两种不同目的的模式；单例模式的目的可能对实现状态模式有用，但这并不意味着这两种模式有关联。

# 模板模式

模板模式对于消除重复代码非常有用；它旨在支持我们在第十九章中讨论的“不要重复自己”的原则，*何时使用面向对象编程*。它设计用于我们需要完成几个不同任务，这些任务有一些但不是全部步骤相同的情况。共同的步骤在基类中实现，不同的步骤在子类中被覆盖以提供自定义行为。在某些方面，它类似于一般化的策略模式，只是使用基类共享算法的相似部分。以下是它的 UML 格式：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/b96f7011-23f3-410b-bafd-138cad6aaeba.png)

# 一个模板示例

让我们以创建一个汽车销售报告为例。我们可以在 SQLite 数据库表中存储销售记录。SQLite 是一个简单的基于文件的数据库引擎，允许我们使用 SQL 语法存储记录。Python 在其标准库中包含了 SQLite，因此不需要额外的模块。

我们有两个需要执行的共同任务：

+   选择所有新车销售并以逗号分隔的格式输出到屏幕

+   输出一个逗号分隔的所有销售人员及其总销售额的列表，并将其保存到可以导入电子表格的文件中

这些看起来是非常不同的任务，但它们有一些共同的特征。在这两种情况下，我们都需要执行以下步骤：

1.  连接到数据库。

1.  构造一个新车或总销售的查询。

1.  发出查询。

1.  将结果格式化为逗号分隔的字符串。

1.  将数据输出到文件或电子邮件。

查询构造和输出步骤对于这两个任务是不同的，但其余步骤是相同的。我们可以使用模板模式将共同的步骤放在一个基类中，将不同的步骤放在两个子类中。

在开始之前，让我们创建一个数据库并放入一些示例数据，使用几行 SQL：

```py
import sqlite3

conn = sqlite3.connect("sales.db")

conn.execute(
    "CREATE TABLE Sales (salesperson text, "
    "amt currency, year integer, model text, new boolean)"
)
conn.execute(
    "INSERT INTO Sales values"
    " ('Tim', 16000, 2010, 'Honda Fit', 'true')"
)
conn.execute(
    "INSERT INTO Sales values"
    " ('Tim', 9000, 2006, 'Ford Focus', 'false')"
)
conn.execute(
    "INSERT INTO Sales values"
    " ('Gayle', 8000, 2004, 'Dodge Neon', 'false')"
)
conn.execute(
    "INSERT INTO Sales values"
    " ('Gayle', 28000, 2009, 'Ford Mustang', 'true')"
)
conn.execute(
    "INSERT INTO Sales values"
    " ('Gayle', 50000, 2010, 'Lincoln Navigator', 'true')"
)
conn.execute(
    "INSERT INTO Sales values"
    " ('Don', 20000, 2008, 'Toyota Prius', 'false')"
)
conn.commit()
conn.close()
```

希望您能看出这里发生了什么，即使您不懂 SQL；我们创建了一个用于保存数据的表，并使用了六个`insert`语句来添加销售记录。数据存储在名为`sales.db`的文件中。现在我们有一个示例可以用来开发我们的模板模式。

既然我们已经概述了模板必须执行的步骤，我们可以开始定义包含这些步骤的基类。每个步骤都有自己的方法（这样可以轻松地选择性地覆盖任何一个步骤），而且我们还有一个管理方法依次调用这些步骤。没有任何方法内容的话，它可能会是这样的：

```py
class QueryTemplate:
    def connect(self):
        pass

    def construct_query(self):
        pass

    def do_query(self):
        pass

    def format_results(self):
        pass

    def output_results(self):
        pass

    def process_format(self):
        self.connect()
        self.construct_query()
        self.do_query()
        self.format_results()
        self.output_results()
```

`process_format`方法是外部客户端调用的主要方法。它确保每个步骤按顺序执行，但它不关心该步骤是在这个类中实现的还是在子类中实现的。对于我们的示例，我们知道两个类之间会有三个方法是相同的：

```py
import sqlite3 

class QueryTemplate:
    def connect(self):
        self.conn = sqlite3.connect("sales.db")

    def construct_query(self):
        raise NotImplementedError()

    def do_query(self):
        results = self.conn.execute(self.query)
        self.results = results.fetchall()

    def format_results(self):
        output = []
        for row in self.results:
            row = [str(i) for i in row]
            output.append(", ".join(row))
        self.formatted_results = "\n".join(output)

    def output_results(self):
        raise NotImplementedError()
```

为了帮助实现子类，两个未指定的方法会引发`NotImplementedError`。这是在 Python 中指定抽象接口的常见方式，当抽象基类看起来太重量级时。这些方法可以有空实现（使用`pass`），或者可以完全未指定。然而，引发`NotImplementedError`有助于程序员理解该类是用于派生子类和覆盖这些方法的。空方法或不存在的方法更难以识别需要实现和调试，如果我们忘记实现它们。

现在我们有一个模板类，它处理了繁琐的细节，但足够灵活，可以执行和格式化各种查询。最好的部分是，如果我们想要将数据库引擎从 SQLite 更改为另一个数据库引擎（比如`py-postgresql`），我们只需要在这个模板类中进行修改，而不需要触及我们可能编写的两个（或两百个）子类。

现在让我们来看看具体的类：

```py
import datetime 

class NewVehiclesQuery(QueryTemplate):
    def construct_query(self):
        self.query = "select * from Sales where new='true'"

    def output_results(self):
        print(self.formatted_results)

class UserGrossQuery(QueryTemplate):
    def construct_query(self):
        self.query = (
            "select salesperson, sum(amt) "
            + " from Sales group by salesperson"
        )

    def output_results(self):
        filename = "gross_sales_{0}".format(
            datetime.date.today().strftime("%Y%m%d")
        )
        with open(filename, "w") as outfile:
            outfile.write(self.formatted_results)
```

这两个类实际上相当简短，考虑到它们的功能：连接到数据库，执行查询，格式化结果并输出。超类处理了重复的工作，但让我们可以轻松指定在任务之间变化的步骤。此外，我们还可以轻松地更改在基类中提供的步骤。例如，如果我们想要输出除逗号分隔字符串之外的其他内容（例如：要上传到网站的 HTML 报告），我们仍然可以覆盖`format_results`。

# 练习

在撰写本章的示例时，我发现想出应该使用特定设计模式的好例子可能非常困难，但也非常有教育意义。与其去审查当前或旧项目，看看你可以在哪里应用这些模式，正如我在之前的章节中建议的那样，不如考虑这些模式以及可能出现这些模式的不同情况。试着超越你自己的经验。如果你当前的项目是银行业务，考虑一下在零售或销售点应用这些设计模式。如果你通常编写 Web 应用程序，考虑在编写编译器时使用设计模式。

看看装饰器模式，并想出一些适用它的好例子。专注于模式本身，而不是我们讨论的 Python 语法。它比实际模式要更一般一些。然而，装饰器的特殊语法是你可能想要寻找现有项目中适用的地方。

有哪些适合使用观察者模式的领域？为什么？不仅考虑如何应用模式，还要考虑如何在不使用观察者的情况下实现相同的任务？选择使用它会得到什么，或者失去什么？

考虑策略模式和状态模式之间的区别。在实现上，它们看起来非常相似，但它们有不同的目的。你能想到可以互换使用这些模式的情况吗？重新设计一个基于状态的系统以使用策略，或者反之，是否合理？设计实际上会有多大的不同？

模板模式是继承的一个明显应用，可以减少重复的代码，你可能以前就使用过它，只是不知道它的名字。试着想出至少半打不同的场景，它在哪些情况下会有用。如果你能做到这一点，你将会在日常编码中经常找到它的用武之地。

# 总结

本章详细讨论了几种常见的设计模式，包括示例、UML 图表，以及 Python 和静态类型面向对象语言之间的差异讨论。装饰器模式通常使用 Python 的更通用的装饰器语法来实现。观察者模式是一种有用的方式，可以将事件与对这些事件采取的行动分离。策略模式允许选择不同的算法来完成相同的任务。状态模式看起来类似，但实际上是用来表示系统可以使用明确定义的操作在不同状态之间移动。单例模式在一些静态类型的语言中很受欢迎，但在 Python 中几乎总是反模式。

在下一章中，我们将结束对设计模式的讨论。


# 第二十三章：Python 设计模式 II

在本章中，我们将介绍更多的设计模式。我们将再次介绍经典示例以及 Python 中常见的替代实现。我们将讨论以下内容：

+   适配器模式

+   外观模式

+   延迟初始化和享元模式

+   命令模式

+   抽象工厂模式

+   组合模式

# 适配器模式

与我们在上一章中审查的大多数模式不同，适配器模式旨在与现有代码交互。我们不会设计一组全新的实现适配器模式的对象。适配器用于允许两个现有对象一起工作，即使它们的接口不兼容。就像显示适配器允许您将 Micro USB 充电线插入 USB-C 手机一样，适配器对象位于两个不同接口之间，在其间进行实时翻译。适配器对象的唯一目的是执行这种翻译。适配可能涉及各种任务，例如将参数转换为不同格式，重新排列参数的顺序，调用不同命名的方法或提供默认参数。

在结构上，适配器模式类似于简化的装饰器模式。装饰器通常提供与其替代物相同的接口，而适配器在两个不同的接口之间进行映射。这在以下图表中以 UML 形式表示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/f676a8bb-86fa-4186-8fc0-16d8bfb0f58a.png)

在这里，**Interface1**期望调用一个名为**make_action(some, arguments)**的方法。我们已经有了完美的**Interface2**类，它做了我们想要的一切（为了避免重复，我们不想重写它！），但它提供的方法名为**different_action(other, arguments)**。**Adapter**类实现了**make_action**接口，并将参数映射到现有接口。

这里的优势在于，从一个接口映射到另一个接口的代码都在一个地方。另一种选择将会非常丑陋；每当我们需要访问这段代码时，我们都必须在多个地方执行翻译。

例如，假设我们有以下现有类，它接受格式为`YYYY-MM-DD`的字符串日期并计算该日期时的人的年龄：

```py
class AgeCalculator:
    def __init__(self, birthday):
        self.year, self.month, self.day = (
            int(x) for x in birthday.split("-")
        )

    def calculate_age(self, date):
        year, month, day = (int(x) for x in date.split("-"))
        age = year - self.year
        if (month, day) < (self.month, self.day):
            age -= 1
        return age
```

这是一个非常简单的类，它完成了它应该完成的工作。但我们不得不思考程序员当时在想什么，为什么要使用特定格式的字符串，而不是使用 Python 中非常有用的内置`datetime`库。作为尽可能重用代码的负责任的程序员，我们编写的大多数程序将与`datetime`对象交互，而不是字符串。

我们有几种选择来解决这种情况。我们可以重写类以接受`datetime`对象，这可能更准确。但如果这个类是由第三方提供的，我们不知道如何或不能改变它的内部结构，我们需要另一种选择。我们可以使用原样的类，每当我们想要计算`datetime.date`对象上的年龄时，我们可以调用`datetime.date.strftime('%Y-%m-%d')`将其转换为正确的格式。但这种转换会发生在很多地方，更糟糕的是，如果我们将`%m`误写为`%M`，它会给我们当前的分钟而不是输入的月份。想象一下，如果您在十几个不同的地方写了这个，然后当您意识到错误时不得不返回并更改它。这不是可维护的代码，它违反了 DRY 原则。

相反，我们可以编写一个适配器，允许将普通日期插入普通的`AgeCalculator`类，如下面的代码所示：

```py
import datetime 

class DateAgeAdapter:
    def _str_date(self, date):
        return date.strftime("%Y-%m-%d")

    def __init__(self, birthday):
        birthday = self._str_date(birthday)
        self.calculator = AgeCalculator(birthday)

    def get_age(self, date):
        date = self._str_date(date)
        return self.calculator.calculate_age(date)
```

这个适配器将`datetime.date`和`datetime.time`（它们具有相同的接口到`strftime`）转换为一个字符串，以便我们原始的`AgeCalculator`可以使用。现在我们可以使用原始代码与我们的新接口。我将方法签名更改为`get_age`，以演示调用接口可能也在寻找不同的方法名称，而不仅仅是不同类型的参数。

创建一个类作为适配器是实现这种模式的常规方法，但是，通常情况下，在 Python 中还有其他方法可以实现。继承和多重继承可以用于向类添加功能。例如，我们可以在`date`类上添加一个适配器，以便它与原始的`AgeCalculator`类一起使用，如下所示：

```py
import datetime 
class AgeableDate(datetime.date): 
    def split(self, char): 
        return self.year, self.month, self.day 
```

像这样的代码让人怀疑 Python 是否应该合法。我们已经为我们的子类添加了一个`split`方法，它接受一个参数（我们忽略），并返回一个年、月和日的元组。这与原始的`AgeCalculator`类完美配合，因为代码在一个特殊格式的字符串上调用`strip`，而在这种情况下，`strip`返回一个年、月和日的元组。`AgeCalculator`代码只关心`strip`是否存在并返回可接受的值；它并不关心我们是否真的传入了一个字符串。以下代码确实有效：

```py
>>> bd = AgeableDate(1975, 6, 14)
>>> today = AgeableDate.today()
>>> today
AgeableDate(2015, 8, 4)
>>> a = AgeCalculator(bd)
>>> a.calculate_age(today)
40  
```

它有效，但这是一个愚蠢的想法。在这种特定情况下，这样的适配器将很难维护。我们很快会忘记为什么需要向`date`类添加一个`strip`方法。方法名称是模糊的。这可能是适配器的性质，但是显式创建一个适配器而不是使用继承通常可以澄清其目的。

除了继承，有时我们还可以使用猴子补丁来向现有类添加方法。它不适用于`datetime`对象，因为它不允许在运行时添加属性。然而，在普通类中，我们可以添加一个新方法，提供调用代码所需的适配接口。或者，我们可以扩展或猴子补丁`AgeCalculator`本身，以用更符合我们需求的东西替换`calculate_age`方法。

最后，通常可以将函数用作适配器；这显然不符合适配器模式的实际设计，但是如果我们记得函数本质上是具有`__call__`方法的对象，那么它就成为一个明显的适配器适应。

# 外观模式

外观模式旨在为复杂的组件系统提供一个简单的接口。对于复杂的任务，我们可能需要直接与这些对象交互，但通常对于系统的*典型*使用，这些复杂的交互并不是必要的。外观模式允许我们定义一个新对象，封装系统的典型使用。每当我们想要访问常见功能时，我们可以使用单个对象的简化接口。如果项目的另一部分需要访问更复杂的功能，它仍然可以直接与系统交互。外观模式的 UML 图表实际上取决于子系统，但在模糊的方式下，它看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/92ac1454-3982-42bb-9fc3-e000d407a1d6.png)

外观在许多方面类似于适配器。主要区别在于，外观试图从复杂的接口中抽象出一个简单的接口，而适配器只试图将一个现有的接口映射到另一个接口。

让我们为一个电子邮件应用程序编写一个简单的外观。Python 中用于发送电子邮件的低级库，正如我们在第二十章中看到的那样，*Python 面向对象的快捷方式*，非常复杂。用于接收消息的两个库甚至更糟。

有一个简单的类可以让我们发送单封电子邮件，并列出当前在 IMAP 或 POP3 连接中收件箱中的电子邮件，这将是很好的。为了让我们的例子简短，我们将坚持使用 IMAP 和 SMTP：两个完全不同的子系统，碰巧处理电子邮件。我们的外观只执行两个任务：向特定地址发送电子邮件，并在 IMAP 连接上检查收件箱。它对连接做了一些常见的假设，比如 SMTP 和 IMAP 的主机位于同一个地址，用户名和密码相同，并且它们使用标准端口。这涵盖了许多电子邮件服务器的情况，但如果程序员需要更灵活性，他们总是可以绕过外观直接访问这两个子系统。

该类使用电子邮件服务器的主机名、用户名和密码进行初始化：

```py
import smtplib 
import imaplib 

class EmailFacade: 
    def __init__(self, host, username, password): 
        self.host = host 
        self.username = username 
        self.password = password 
```

`send_email`方法格式化电子邮件地址和消息，并使用`smtplib`发送。这不是一个复杂的任务，但需要相当多的调整来将传递到外观的*自然*输入参数正确格式化，以使`smtplib`能够发送消息，如下所示：

```py
    def send_email(self, to_email, subject, message):
        if not "@" in self.username:
            from_email = "{0}@{1}".format(self.username, self.host)
        else:
            from_email = self.username
        message = (
            "From: {0}\r\n" "To: {1}\r\n" "Subject: {2}\r\n\r\n{3}"
        ).format(from_email, to_email, subject, message)

        smtp = smtplib.SMTP(self.host)
        smtp.login(self.username, self.password)
        smtp.sendmail(from_email, [to_email], message)
```

方法开头的`if`语句捕获了`username`是否是整个*from*电子邮件地址，或者只是`@`符号左边的部分；不同的主机对登录详细信息的处理方式不同。

最后，获取当前收件箱中的消息的代码是一团糟。IMAP 协议过度设计，`imaplib`标准库只是协议的薄层。但我们可以简化它，如下所示：

```py
    def get_inbox(self):
        mailbox = imaplib.IMAP4(self.host)
        mailbox.login(
            bytes(self.username, "utf8"), bytes(self.password, "utf8")
        )
        mailbox.select()
        x, data = mailbox.search(None, "ALL")
        messages = []
        for num in data[0].split():
            x, message = mailbox.fetch(num, "(RFC822)")
            messages.append(message[0][1])
        return messages
```

现在，如果我们把所有这些加在一起，我们就有了一个简单的外观类，可以以相当直接的方式发送和接收消息；比起直接与这些复杂的库进行交互，要简单得多。

虽然在 Python 社区很少提到它的名字，但外观模式是 Python 生态系统的一个组成部分。因为 Python 强调语言的可读性，语言及其库往往提供了易于理解的接口来处理复杂的任务。例如，`for`循环，`list`推导和生成器都是更复杂的迭代器协议的外观。`defaultdict`实现是一个外观，它在字典中键不存在时抽象出烦人的边缘情况。第三方的**requests**库是一个强大的外观，可以使 HTTP 请求的库更易读，它们本身是管理基于文本的 HTTP 协议的外观。

# 轻量级模式

轻量级模式是一种内存优化模式。新手 Python 程序员往往忽视内存优化，认为内置的垃圾收集器会处理它们。这通常是完全可以接受的，但是在开发具有许多相关对象的较大应用程序时，关注内存问题可能会有巨大的回报。

轻量级模式确保共享状态的对象可以使用相同的内存来存储该共享状态。通常只有在程序显示出内存问题后才会实现它。在某些情况下，从一开始设计一个最佳配置是有意义的，但请记住，过早优化是创建一个过于复杂以至于无法维护的程序的最有效方式。

让我们看一下轻量级模式的以下 UML 图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/e72ec0b1-cc5e-4be1-a5b4-7f3aa040af2b.png)

每个**享元**都没有特定的状态。每当它需要对**具体状态**执行操作时，该状态都需要被调用代码传递给**享元**。传统上，返回享元的工厂是一个单独的对象；它的目的是为了根据标识该享元的给定键返回一个享元。它的工作原理类似于我们在第二十二章中讨论的单例模式，*Python 设计模式 I*；如果享元存在，我们就返回它；否则，我们创建一个新的。在许多语言中，工厂被实现为`Flyweight`类本身上的静态方法，而不是作为一个单独的对象。

想象一下汽车销售的库存系统。每辆汽车都有特定的序列号和特定的颜色。但是对于特定模型的所有汽车来说，大部分关于汽车的细节都是相同的。例如，本田 Fit DX 型号是一辆几乎没有功能的汽车。LX 型号有空调、倾斜、巡航和电动窗户和锁。Sport 型号有时尚的轮毂、USB 充电器和扰流板。如果没有享元模式，每个单独的汽车对象都必须存储一个长长的列表，其中包含它具有或不具有的功能。考虑到本田一年销售的汽车数量，这将导致大量的内存浪费。

使用享元模式，我们可以为与模型相关的功能列表共享对象，然后只需为单个车辆引用该模型，以及序列号和颜色。在 Python 中，享元工厂通常使用那个奇怪的`__new__`构造函数来实现，类似于我们在单例模式中所做的。

与只需要返回类的一个实例的单例模式不同，我们需要能够根据键返回不同的实例。我们可以将项目存储在字典中，并根据键查找它们。然而，这种解决方案存在问题，因为只要项目在字典中，它就会一直保留在内存中。如果我们卖完了 LX 型号的 Fit，那么 Fit 享元将不再需要，但它仍然会留在字典中。我们可以在卖车时清理这些内容，但这不是垃圾收集器的作用吗？

我们可以利用 Python 的`weakref`模块来解决这个问题。该模块提供了一个`WeakValueDictionary`对象，基本上允许我们在字典中存储项目，而垃圾收集器不会关心它们。如果一个值在一个弱引用字典中，并且在应用程序的任何其他地方都没有对该对象的其他引用（也就是说，我们已经卖完了 LX 型号），垃圾收集器最终会为我们清理掉它。

首先让我们构建我们汽车享元的工厂，如下所示：

```py
import weakref

class CarModel:
    _models = weakref.WeakValueDictionary()

    def __new__(cls, model_name, *args, **kwargs):
        model = cls._models.get(model_name)
        if not model:
            model = super().__new__(cls)
            cls._models[model_name] = model

        return model
```

基本上，每当我们使用给定名称构造一个新的享元时，我们首先在弱引用字典中查找该名称；如果存在，我们就返回该模型；如果不存在，我们就创建一个新的。无论哪种方式，我们都知道`__init__`方法在每次都会被调用，无论它是一个新的还是现有的对象。因此，我们的`__init__`方法可以看起来像以下代码片段：

```py
    def __init__(
        self,
        model_name,
        air=False,
        tilt=False,
        cruise_control=False,
        power_locks=False,
        alloy_wheels=False,
        usb_charger=False,
    ):
        if not hasattr(self, "initted"):
            self.model_name = model_name
            self.air = air
            self.tilt = tilt
            self.cruise_control = cruise_control
            self.power_locks = power_locks
            self.alloy_wheels = alloy_wheels
            self.usb_charger = usb_charger
            self.initted = True

```

`if`语句确保我们只在第一次调用`__init__`时初始化对象。这意味着我们以后可以只用模型名称调用工厂，并得到相同的享元对象。然而，如果享元没有外部引用存在，它将被垃圾收集，我们必须小心不要意外地创建一个具有空值的新享元。

让我们为我们的享元添加一个假设的方法，该方法查找特定车型的车辆上的序列号，并确定它是否曾经参与过任何事故。这个方法需要访问汽车的序列号，这个序列号因车而异；它不能与享元一起存储。因此，这些数据必须由调用代码传递给方法，如下所示：

```py
    def check_serial(self, serial_number):
        print(
            "Sorry, we are unable to check "
            "the serial number {0} on the {1} "
            "at this time".format(serial_number, self.model_name)
        )
```

我们可以定义一个类，该类存储附加信息，以及对 flyweight 的引用，如下所示：

```py
class Car: 
    def __init__(self, model, color, serial): 
        self.model = model 
        self.color = color 
        self.serial = serial 

    def check_serial(self): 
        return self.model.check_serial(self.serial) 
```

我们还可以跟踪可用的模型，以及停车场上的各个汽车，如下所示：

```py
>>> dx = CarModel("FIT DX")
>>> lx = CarModel("FIT LX", air=True, cruise_control=True,
... power_locks=True, tilt=True)
>>> car1 = Car(dx, "blue", "12345")
>>> car2 = Car(dx, "black", "12346")
>>> car3 = Car(lx, "red", "12347")  
```

现在，让我们在以下代码片段中演示弱引用的工作：

```py
>>> id(lx)
3071620300
>>> del lx
>>> del car3
>>> import gc
>>> gc.collect()
0
>>> lx = CarModel("FIT LX", air=True, cruise_control=True,
... power_locks=True, tilt=True)
>>> id(lx)
3071576140
>>> lx = CarModel("FIT LX")
>>> id(lx)
3071576140
>>> lx.air
True  
```

`id`函数告诉我们对象的唯一标识符。当我们在删除对 LX 型号的所有引用并强制进行垃圾回收后第二次调用它，我们发现 ID 已经改变。`CarModel __new__`工厂字典中的值被删除，然后创建了一个新的值。然后，如果我们尝试构建第二个`CarModel`实例，它会返回相同的对象（ID 相同），即使在第二次调用中没有提供任何参数，`air`变量仍然设置为`True`。这意味着对象第二次没有被初始化，就像我们设计的那样。

显然，使用 flyweight 模式比只在单个汽车类上存储特性更复杂。我们应该在什么时候选择使用它？flyweight 模式旨在节省内存；如果我们有成千上万个相似的对象，将相似的属性合并到 flyweight 中对内存消耗会产生巨大影响。

对于优化 CPU、内存或磁盘空间的编程解决方案来说，通常会导致比未经优化的代码更复杂。因此，在决定代码可维护性和优化之间的权衡时，权衡是很重要的。在选择优化时，尝试使用 flyweight 等模式，以确保优化引入的复杂性局限于代码的一个（有良好文档的）部分。

如果一个程序中有很多 Python 对象，通过使用`__slots__`是节省内存的最快方法之一。`__slots__`魔术方法超出了本书的范围，但是如果您查看在线信息，会有很多信息可用。如果内存仍然不足，flyweight 可能是一个合理的解决方案。

# 命令模式

命令模式在必须执行的操作和调用这些操作的对象之间增加了一个抽象级别，通常是在以后的某个时间。在命令模式中，客户端代码创建一个可以在以后执行的`Command`对象。这个对象知道一个接收者对象，在命令在其上执行时管理自己的内部状态。`Command`对象实现了一个特定的接口（通常有一个`execute`或`do_action`方法，并且还跟踪执行操作所需的任何参数。最后，一个或多个`Invoker`对象在正确的时间执行命令。

这是 UML 图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/f4330a13-f32a-4858-8f94-66117207ae14.png)

命令模式的一个常见示例是对图形窗口的操作。通常，操作可以通过菜单栏上的菜单项、键盘快捷键、工具栏图标或上下文菜单来调用。这些都是`Invoker`对象的示例。实际发生的操作，如`Exit`、`Save`或`Copy`，是`CommandInterface`的实现。接收退出的 GUI 窗口，接收保存的文档，接收复制命令的`ClipboardManager`，都是可能的`Receivers`的示例。

让我们实现一个简单的命令模式，为`Save`和`Exit`操作提供命令。我们将从一些适度的接收者类开始，它们本身具有以下代码：

```py
import sys 

class Window: 
    def exit(self): 
        sys.exit(0) 

class Document: 
    def __init__(self, filename): 
        self.filename = filename 
        self.contents = "This file cannot be modified" 

    def save(self): 
        with open(self.filename, 'w') as file: 
            file.write(self.contents) 
```

这些模拟类模拟了在工作环境中可能会做更多工作的对象。窗口需要处理鼠标移动和键盘事件，文档需要处理字符插入、删除和选择。但是对于我们的示例，这两个类将做我们需要的事情。

现在让我们定义一些调用者类。这些将模拟可能发生的工具栏、菜单和键盘事件；同样，它们实际上并没有连接到任何东西，但我们可以看到它们如何与命令、接收者和客户端代码解耦在以下代码片段中：

```py
class ToolbarButton:
    def __init__(self, name, iconname):
        self.name = name
        self.iconname = iconname

    def click(self):
        self.command.execute()

class MenuItem:
    def __init__(self, menu_name, menuitem_name):
        self.menu = menu_name
        self.item = menuitem_name

    def click(self):
        self.command.execute()

class KeyboardShortcut:
    def __init__(self, key, modifier):
        self.key = key
        self.modifier = modifier

    def keypress(self):
        self.command.execute()
```

注意各种操作方法如何调用其各自命令的`execute`方法？这段代码没有显示`command`属性被设置在每个对象上。它们可以传递到`__init__`函数中，但因为它们可能会被更改（例如，使用可自定义的键绑定编辑器），所以更合理的是在对象之后设置属性。

现在，让我们使用以下代码连接命令本身：

```py
class SaveCommand:
    def __init__(self, document):
        self.document = document

    def execute(self):
        self.document.save()

class ExitCommand:
    def __init__(self, window):
        self.window = window

    def execute(self):
        self.window.exit()
```

这些命令很简单；它们演示了基本模式，但重要的是要注意，如果必要，我们可以存储状态和其他信息。例如，如果我们有一个插入字符的命令，我们可以维护当前正在插入的字符的状态。

现在我们所要做的就是连接一些客户端和测试代码，使命令生效。对于基本测试，我们只需在脚本的末尾包含以下代码：

```py
window = Window() 
document = Document("a_document.txt") 
save = SaveCommand(document) 
exit = ExitCommand(window) 

save_button = ToolbarButton('save', 'save.png') 
save_button.command = save 
save_keystroke = KeyboardShortcut("s", "ctrl") 
save_keystroke.command = save 
exit_menu = MenuItem("File", "Exit") 
exit_menu.command = exit 
```

首先，我们创建两个接收者和两个命令。然后，我们创建几个可用的调用者，并在每个调用者上设置正确的命令。为了测试，我们可以使用`python3 -i filename.py`并运行诸如`exit_menu.click()`的代码，这将结束程序，或者`save_keystroke.keystroke()`，这将保存虚拟文件。

不幸的是，前面的例子并不像 Python。它们有很多“样板代码”（不完成任何任务，只提供模式结构），而且`Command`类彼此之间都非常相似。也许我们可以创建一个通用的命令对象，以函数作为回调？

事实上，为什么要麻烦呢？我们可以为每个命令使用函数或方法对象吗？我们可以编写一个函数，直接将其用作命令，而不是具有`execute()`方法的对象。以下是 Python 中命令模式的常见范例：

```py
import sys

class Window:
    def exit(self):
        sys.exit(0)

class MenuItem:
    def click(self):
        self.command()

window = Window()
menu_item = MenuItem()
menu_item.command = window.exit
```

现在看起来更像 Python 了。乍一看，它看起来好像我们完全删除了命令模式，并且紧密连接了`menu_item`和`Window`类。但是如果我们仔细观察，我们会发现根本没有紧密耦合。任何可调用对象都可以设置为`MenuItem`上的命令，就像以前一样。而`Window.exit`方法可以附加到任何调用者上。命令模式的大部分灵活性都得到了保留。我们为可读性牺牲了完全解耦，但在我看来，以及许多 Python 程序员看来，这段代码比完全抽象的版本更易维护。

当然，由于我们可以向任何对象添加`__call__`方法，我们不限于函数。当被调用的方法不必维护状态时，前面的例子是一个有用的快捷方式，但在更高级的用法中，我们也可以使用以下代码：

```py
class Document:
    def __init__(self, filename):
        self.filename = filename
        self.contents = "This file cannot be modified"

    def save(self):
        with open(self.filename, "w") as file:
            file.write(self.contents)

class KeyboardShortcut:
    def keypress(self):
        self.command()

class SaveCommand:
    def __init__(self, document):
        self.document = document

    def __call__(self):
        self.document.save()

document = Document("a_file.txt")
shortcut = KeyboardShortcut()
save_command = SaveCommand(document)
shortcut.command = save_command
```

在这里，我们有一个看起来像第一个命令模式的东西，但更符合习惯。正如你所看到的，让调用者调用一个可调用对象而不是具有执行方法的`command`对象并没有限制我们的任何方式。事实上，这给了我们更多的灵活性。当适用时，我们可以直接链接到函数，但是当情况需要时，我们可以构建一个完整的可调用`command`对象。

命令模式通常扩展为支持可撤销的命令。例如，文本程序可能将每个插入操作包装在一个单独的命令中，不仅有一个`execute`方法，还有一个`undo`方法，用于删除该插入操作。图形程序可能将每个绘图操作（矩形、线条、自由像素等）包装在一个命令中，该命令具有一个`undo`方法，用于将像素重置为其原始状态。在这种情况下，命令模式的解耦显然更有用，因为每个操作都必须保持足够的状态以便在以后的某个日期撤消该操作。

# 抽象工厂模式

抽象工厂模式通常在我们有多种可能的系统实现取决于某些配置或平台问题时使用。调用代码从抽象工厂请求对象，不知道将返回什么类的对象。返回的底层实现可能取决于各种因素，如当前区域设置、操作系统或本地配置。

抽象工厂模式的常见示例包括操作系统无关的工具包、数据库后端和特定国家的格式化程序或计算器的代码。操作系统无关的 GUI 工具包可能使用抽象工厂模式，在 Windows 下返回一组 WinForm 小部件，在 Mac 下返回一组 Cocoa 小部件，在 Gnome 下返回一组 GTK 小部件，在 KDE 下返回一组 QT 小部件。Django 提供了一个抽象工厂，根据当前站点的配置设置，返回一组用于与特定数据库后端（MySQL、PostgreSQL、SQLite 等）交互的对象关系类。如果应用程序需要部署到多个地方，每个地方可以通过仅更改一个配置变量来使用不同的数据库后端。不同的国家有不同的零售商品税、小计和总计计算系统；抽象工厂可以返回特定的税收计算对象。

抽象工厂模式的 UML 类图很难理解，没有具体的示例，因此让我们改变一下，首先创建一个具体的示例。在我们的示例中，我们将创建一组取决于特定区域设置的格式化程序，帮助我们格式化日期和货币。将有一个选择特定工厂的抽象工厂类，以及一些示例具体工厂，一个用于法国，一个用于美国。这些工厂将为日期和时间创建格式化程序对象，可以查询以格式化特定值。如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/af57b154-5695-4e8b-b27c-b5db318c52cb.png)

将这个图像与之前更简单的文本进行比较，可以看出图片并不总是价值千言万语，尤其是考虑到我们甚至没有在这里允许工厂选择代码。

当然，在 Python 中，我们不必实现任何接口类，因此我们可以丢弃`DateFormatter`、`CurrencyFormatter`和`FormatterFactory`。这些格式化类本身非常简单，但冗长，如下所示：

```py
class FranceDateFormatter:
    def format_date(self, y, m, d):
        y, m, d = (str(x) for x in (y, m, d))
        y = "20" + y if len(y) == 2 else y
        m = "0" + m if len(m) == 1 else m
        d = "0" + d if len(d) == 1 else d
        return "{0}/{1}/{2}".format(d, m, y)

class USADateFormatter:
    def format_date(self, y, m, d):
        y, m, d = (str(x) for x in (y, m, d))
        y = "20" + y if len(y) == 2 else y
        m = "0" + m if len(m) == 1 else m
        d = "0" + d if len(d) == 1 else d
        return "{0}-{1}-{2}".format(m, d, y)

class FranceCurrencyFormatter:
    def format_currency(self, base, cents):
        base, cents = (str(x) for x in (base, cents))
        if len(cents) == 0:
            cents = "00"
        elif len(cents) == 1:
            cents = "0" + cents

        digits = []
        for i, c in enumerate(reversed(base)):
            if i and not i % 3:
                digits.append(" ")
            digits.append(c)
        base = "".join(reversed(digits))
        return "{0}€{1}".format(base, cents)

class USACurrencyFormatter:
    def format_currency(self, base, cents):
        base, cents = (str(x) for x in (base, cents))
        if len(cents) == 0:
            cents = "00"
        elif len(cents) == 1:
            cents = "0" + cents
        digits = []
        for i, c in enumerate(reversed(base)):
            if i and not i % 3:
                digits.append(",")
            digits.append(c)
        base = "".join(reversed(digits))
        return "${0}.{1}".format(base, cents)
```

这些类使用一些基本的字符串操作来尝试将各种可能的输入（整数、不同长度的字符串等）转换为以下格式：

|  | **美国** | **法国** |
| --- | --- | --- |
| **日期** | mm-dd-yyyy | dd/mm/yyyy |
| **货币** | $14,500.50 | 14 500€50 |

在这段代码中，输入显然可以进行更多的验证，但是为了这个例子，让我们保持简单。

现在我们已经设置好了格式化程序，我们只需要创建格式化程序工厂，如下所示：

```py
class USAFormatterFactory:
    def create_date_formatter(self):
        return USADateFormatter()

    def create_currency_formatter(self):
        return USACurrencyFormatter()

class FranceFormatterFactory:
    def create_date_formatter(self):
        return FranceDateFormatter()

    def create_currency_formatter(self):
        return FranceCurrencyFormatter()
```

现在我们设置选择适当格式化程序的代码。由于这种事情只需要设置一次，我们可以将其设置为单例模式——但是单例模式在 Python 中并不是非常有用。让我们将当前格式化程序作为模块级变量：

```py
country_code = "US"
factory_map = {"US": USAFormatterFactory, "FR": FranceFormatterFactory}
formatter_factory = factory_map.get(country_code)()
```

在这个例子中，我们硬编码了当前的国家代码；在实践中，它可能会内省区域设置、操作系统或配置文件来选择代码。这个例子使用字典将国家代码与工厂类关联起来。然后，我们从字典中获取正确的类并实例化它。

当我们想要为更多的国家添加支持时，很容易看出需要做什么：创建新的格式化类和抽象工厂本身。请记住，`Formatter`类可能会被重用；例如，加拿大的货币格式与美国相同，但其日期格式比其南部邻居更合理。

抽象工厂通常返回一个单例对象，但这并非必需。在我们的代码中，每次调用时都返回每个格式化程序的新实例。没有理由不能将格式化程序存储为实例变量，并为每个工厂返回相同的实例。

回顾这些例子，我们再次看到，对于工厂来说，似乎有很多样板代码在 Python 中并不感到必要。通常，可能需要抽象工厂的要求可以通过为每种工厂类型（例如：美国和法国）使用单独的模块，并确保在工厂模块中访问正确的模块来更轻松地实现。这些模块的包结构可能如下所示：

```py
localize/ 
    __init__.py 
    backends/ 
        __init__.py 
        USA.py 
        France.py 
        ... 
```

技巧在于`localize`包中的`__init__.py`可以包含将所有请求重定向到正确后端的逻辑。有多种方法可以实现这一点。

如果我们知道后端永远不会动态更改（即在没有程序重新启动的情况下），我们可以在`__init__.py`中放一些`if`语句来检查当前的国家代码，并使用（通常不可接受的）`from``.backends.USA``import``*`语法从适当的后端导入所有变量。或者，我们可以导入每个后端并设置一个`current_backend`变量指向特定的模块，如下所示：

```py
from .backends import USA, France 

if country_code == "US": 
    current_backend = USA 
```

根据我们选择的解决方案，我们的客户端代码将不得不调用`localize.format_date`或`localize.current_backend.format_date`来获取以当前国家区域设置格式化的日期。最终结果比原始的抽象工厂模式更符合 Python 的风格，并且在典型的使用情况下同样灵活。

# 组合模式

组合模式允许从简单组件构建复杂的树状结构。这些组件，称为复合对象，能够表现得像容器，也能像变量一样，具体取决于它们是否有子组件。复合对象是容器对象，其中的内容实际上可能是另一个复合对象。

传统上，复合对象中的每个组件必须是叶节点（不能包含其他对象）或复合节点。关键在于复合和叶节点都可以具有相同的接口。以下的 UML 图表非常简单：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/72017a6f-b691-4b3d-953d-495fc8c3e88a.png)

然而，这种简单的模式使我们能够创建复杂的元素排列，所有这些元素都满足组件对象的接口。以下图表描述了这样一个复杂排列的具体实例：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/4de6c458-0348-42f5-998a-1c5451bc5b4b.png)

组合模式通常在文件/文件夹样式的树中非常有用。无论树中的节点是普通文件还是文件夹，它仍然受到移动、复制或删除节点等操作的影响。我们可以创建一个支持这些操作的组件接口，然后使用复合对象来表示文件夹，使用叶节点来表示普通文件。

当然，在 Python 中，我们可以再次利用鸭子类型来隐式提供接口，因此我们只需要编写两个类。让我们首先在以下代码中定义这些接口：

```py
class Folder: 
    def __init__(self, name): 
        self.name = name 
        self.children = {} 

    def add_child(self, child): 
        pass 

    def move(self, new_path): 
        pass 

    def copy(self, new_path): 
        pass 

    def delete(self): 
        pass 

class File: 
    def __init__(self, name, contents): 
        self.name = name 
        self.contents = contents 

    def move(self, new_path): 
        pass 

    def copy(self, new_path): 
        pass 

    def delete(self): 
        pass 
```

对于每个文件夹（复合）对象，我们维护一个子对象的字典。对于许多复合实现来说，列表就足够了，但在这种情况下，使用字典来按名称查找子对象会很有用。我们的路径将被指定为由`/`字符分隔的节点名称，类似于 Unix shell 中的路径。

考虑涉及的方法，我们可以看到移动或删除节点的行为方式相似，无论它是文件节点还是文件夹节点。然而，复制对于文件夹节点来说必须进行递归复制，而对于文件节点来说，复制是一个微不足道的操作。

为了利用相似的操作，我们可以将一些常见的方法提取到一个父类中。让我们将被丢弃的`Component`接口改为一个基类，使用以下代码：

```py
class Component:
    def __init__(self, name):
        self.name = name

    def move(self, new_path):
        new_folder = get_path(new_path)
        del self.parent.children[self.name]
        new_folder.children[self.name] = self
        self.parent = new_folder

    def delete(self):
        del self.parent.children[self.name]

class Folder(Component):
    def __init__(self, name):
        super().__init__(name)
        self.children = {}

    def add_child(self, child):
        pass

    def copy(self, new_path):
        pass

class File(Component):
    def __init__(self, name, contents):
        super().__init__(name)
        self.contents = contents

    def copy(self, new_path):
        pass

root = Folder("")

def get_path(path):
    names = path.split("/")[1:]
    node = root
    for name in names:
        node = node.children[name]
    return node
```

我们在`Component`类上创建了`move`和`delete`方法。它们都访问一个我们尚未设置的神秘的`parent`变量。`move`方法使用一个模块级别的`get_path`函数，该函数根据给定的路径从预定义的根节点中找到一个节点。所有文件都将被添加到此根节点或该节点的子节点。对于`move`方法，目标应该是一个现有的文件夹，否则我们将会得到一个错误。就像技术书籍中的许多示例一样，错误处理是非常缺乏的，以帮助专注于正在考虑的原则。

让我们在文件夹的`add_child`方法中设置那个神秘的`parent`变量，如下所示：

```py
    def add_child(self, child):
        child.parent = self
        self.children[child.name] = child
```

好吧，这足够简单了。让我们看看我们的复合文件层次结构是否能够正常工作，使用以下代码片段：

```py
$ python3 -i 1261_09_18_add_child.py

>>> folder1 = Folder('folder1')
>>> folder2 = Folder('folder2')
>>> root.add_child(folder1)
>>> root.add_child(folder2)
>>> folder11 = Folder('folder11')
>>> folder1.add_child(folder11)
>>> file111 = File('file111', 'contents')
>>> folder11.add_child(file111)
>>> file21 = File('file21', 'other contents')
>>> folder2.add_child(file21)
>>> folder2.children
{'file21': <__main__.File object at 0xb7220a4c>}
>>> folder2.move('/folder1/folder11')
>>> folder11.children
{'folder2': <__main__.Folder object at 0xb722080c>, 'file111': <__main__.File object at 
0xb72209ec>}
>>> file21.move('/folder1')
>>> folder1.children
{'file21': <__main__.File object at 0xb7220a4c>, 'folder11': <__main__.Folder object at 
0xb722084c>}  
```

是的，我们可以创建文件夹，将文件夹添加到其他文件夹中，将文件添加到文件夹中，并在它们之间移动！在文件层次结构中，我们还能要求什么呢？

好吧，我们可以要求实现复制，但为了节约树木，让我们把它作为一个练习留下来。

复合模式对于各种类似树结构的结构非常有用，包括 GUI 小部件层次结构，文件层次结构，树集，图形和 HTML DOM。当按照传统实现方式在 Python 中实现时，它可以成为 Python 中的一个有用模式，就像之前演示的例子一样。有时，如果只创建了一个浅树，我们可以使用列表的列表或字典的字典，并且不需要实现自定义组件、叶子和复合类。其他时候，我们可以只实现一个复合类，并将叶子和复合对象视为一个类。另外，Python 的鸭子类型可以很容易地将其他对象添加到复合层次结构中，只要它们具有正确的接口。

# 练习

在深入研究每个设计模式的练习之前，花点时间为上一节中的`File`和`Folder`对象实现`copy`方法。`File`方法应该非常简单；只需创建一个具有相同名称和内容的新节点，并将其添加到新的父文件夹中。`Folder`上的`copy`方法要复杂得多，因为您首先必须复制文件夹，然后递归地将其每个子对象复制到新位置。您可以不加区分地在子对象上调用`copy()`方法，无论每个子对象是文件还是文件夹。这将彰显出复合模式有多么强大。

现在，就像在上一章中一样，看看我们讨论过的模式，并考虑您可能实现它们的理想位置。您可能希望将适配器模式应用于现有代码，因为它通常适用于与现有库进行接口，而不是新代码。您如何使用适配器来强制两个接口正确地相互交互？

你能想到一个足够复杂的系统，可以证明使用外观模式是合理的吗？考虑一下外观在现实生活中的使用情况，比如汽车的驾驶员界面，或者工厂的控制面板。在软件中也是类似的，只不过外观接口的用户是其他程序员，而不是受过培训的人。在你最新的项目中，是否有复杂的系统可以从外观模式中受益？

可能你没有任何巨大的、占用内存的代码会从享元模式中受益，但你能想到哪些情况下它可能会有用吗？任何需要处理大量重叠数据的地方，都可以使用享元模式。在银行业会有用吗？在 Web 应用程序中呢？采用享元模式何时是明智的？什么时候又是画蛇添足呢？

命令模式呢？你能想到任何常见（或更好的是，不常见）的例子，其中将动作与调用解耦会有用吗？看看你每天使用的程序，想象它们内部是如何实现的。很可能其中许多都会以某种方式使用命令模式。

抽象工厂模式，或者我们讨论过的更加 Pythonic 的衍生模式，对于创建一键配置系统非常有用。你能想到这样的系统有用的地方吗？

最后，考虑一下组合模式。在编程中，我们周围都有类似树状结构的东西；其中一些，比如我们的文件层次结构示例，是明显的；其他一些则相当微妙。可能会出现哪些情况，组合模式会有用呢？你能想到在自己的代码中可以使用它的地方吗？如果你稍微调整一下模式；例如，包含不同类型的叶子或组合节点，用于不同类型的对象，会怎样？

# 总结

在本章中，我们详细介绍了几种设计模式，包括它们的经典描述以及在 Python 中实现它们的替代方法，Python 通常比传统的面向对象语言更灵活、多才多艺。适配器模式用于匹配接口，而外观模式适用于简化接口。享元模式是一种复杂的模式，只有在需要内存优化时才有用。在 Python 中，命令模式通常更适合使用一等函数作为回调来实现。抽象工厂允许根据配置或系统信息在运行时分离实现。组合模式通常用于类似树状结构的情况。

在下一章中，我们将讨论测试 Python 程序的重要性，以及如何进行测试，重点放在面向对象的原则上。


# 第二十四章：测试面向对象的程序

技术娴熟的 Python 程序员一致认为测试是软件开发中最重要的方面之一。即使这一章放在书的最后，它也不是一个事后补充；到目前为止我们学习的一切都将帮助我们在编写测试时。在本章中，我们将讨论以下主题：

+   单元测试和测试驱动开发的重要性

+   标准的`unittest`模块

+   `pytest`自动化测试套件

+   `mock`模块

+   代码覆盖率

+   使用`tox`进行跨平台测试

# 为什么要测试？

许多程序员已经知道测试他们的代码有多重要。如果你是其中之一，请随意略过本节。你会发现下一节——我们实际上如何在 Python 中创建测试——更加有趣。如果你还不相信测试的重要性，我保证你的代码是有问题的，只是你不知道而已。继续阅读！

有人认为在 Python 代码中测试更重要，因为它的动态特性；而像 Java 和 C++这样的编译语言偶尔被认为在编译时强制执行类型检查，所以在某种程度上更“安全”。然而，Python 测试很少检查类型。它们检查值。它们确保正确的属性在正确的时间设置，或者序列具有正确的长度、顺序和值。这些更高级的概念需要在任何语言中进行测试。

Python 程序员测试比其他语言的程序员更多的真正原因是在 Python 中测试是如此容易！

但是为什么要测试？我们真的需要测试吗？如果我们不测试会怎样？要回答这些问题，从头开始编写一个没有任何测试的井字棋游戏。在完全编写完成之前不要运行它，从头到尾。如果让两个玩家都是人类玩家（没有人工智能），井字棋实现起来相当简单。你甚至不必尝试计算谁是赢家。现在运行你的程序。然后修复所有的错误。有多少错误？我在我的井字棋实现中记录了八个，我不确定是否都捕捉到了。你呢？

我们需要测试我们的代码以确保它正常工作。像我们刚才做的那样运行程序并修复错误是一种粗糙的测试形式。Python 的交互式解释器和几乎零编译时间使得编写几行代码并运行程序以确保这些行正在按预期工作变得容易。但是改变几行代码可能会影响我们没有意识到会受到更改影响的程序的部分，因此忽略测试这些部分。此外，随着程序的增长，解释器可以通过代码的路径数量也在增加，手动测试所有这些路径很快就变得不可能。

为了解决这个问题，我们编写自动化测试。这些是自动运行某些输入通过其他程序或程序部分的程序。我们可以在几秒钟内运行这些测试程序，并覆盖比一个程序员每次更改某些东西时想到的潜在输入情况要多得多。

有四个主要原因要编写测试：

+   确保代码按照开发人员的预期工作

+   确保在进行更改时代码仍然正常工作

+   确保开发人员理解了需求

+   确保我们正在编写的代码具有可维护的接口

第一点真的不能证明写测试所花费的时间；我们可以在交互式解释器中直接测试代码，用同样或更少的时间。但是当我们必须多次执行相同的测试操作序列时，自动化这些步骤一次，然后在需要时运行它们需要的时间更少。每次更改代码时运行测试是个好主意，无论是在初始开发阶段还是在维护版本发布时。当我们有一套全面的自动化测试时，我们可以在代码更改后运行它们，并知道我们没有无意中破坏任何被测试的东西。

前面两点更有趣。当我们为代码编写测试时，它有助于设计代码所采用的 API、接口或模式。因此，如果我们误解了需求，编写测试可以帮助突出这种误解。另一方面，如果我们不确定如何设计一个类，我们可以编写一个与该类交互的测试，这样我们就可以知道与之交互的最自然方式。事实上，通常在编写我们要测试的代码之前编写测试是有益的。

# 测试驱动开发

*先写测试*是测试驱动开发的口头禅。测试驱动开发将*未经测试的代码是有问题的代码*的概念推进了一步，并建议只有未编写的代码才应该未经测试。在我们编写测试之前，我们不会编写任何代码来证明它有效。第一次运行测试时，它应该失败，因为代码还没有被编写。然后，我们编写确保测试通过的代码，然后为下一段代码编写另一个测试。

测试驱动开发很有趣；它允许我们构建小谜题来解决。然后，我们实现解决这些谜题的代码。然后，我们制作一个更复杂的谜题，然后编写解决新谜题的代码，而不会解决以前的谜题。

测试驱动方法有两个目标。第一个是确保测试真的被编写。在我们编写代码之后，很容易说：

嗯，看起来好像可以。我不需要为这个写任何测试。这只是一个小改变；什么都不可能出错。

如果测试在我们编写代码之前已经编写好了，我们将确切地知道它何时有效（因为测试将通过），并且在将来，如果我们或其他人对其进行了更改，我们将知道它是否被破坏。

其次，先编写测试迫使我们考虑代码将如何使用。它告诉我们对象需要具有哪些方法，以及如何访问属性。它帮助我们将初始问题分解为更小的、可测试的问题，然后将经过测试的解决方案重新组合成更大的、也经过测试的解决方案。编写测试因此可以成为设计过程的一部分。通常，当我们为一个新对象编写测试时，我们会发现设计中的异常，这迫使我们考虑软件的新方面。

作为一个具体的例子，想象一下编写使用对象关系映射器将对象属性存储在数据库中的代码。在这种对象中使用自动分配的数据库 ID 是很常见的。我们的代码可能会为各种目的使用这个 ID。如果我们为这样的代码编写测试，在我们编写测试之前，我们可能会意识到我们的设计有缺陷，因为对象在保存到数据库之前不会被分配 ID。如果我们想在测试中操作一个对象而不保存它，那么在我们基于错误的前提编写代码之前，它会突出显示这个问题。

测试使软件更好。在发布软件之前编写测试可以使软件在最终用户看到或购买有错误的版本之前变得更好（我曾为那些以*用户可以测试它*为理念的公司工作过；这不是一个健康的商业模式）。在编写软件之前编写测试可以使软件第一次编写时变得更好。

# 单元测试

让我们从 Python 内置的测试库开始探索。这个库为**单元测试**提供了一个通用的面向对象的接口。单元测试专注于在任何一个测试中测试尽可能少的代码。每个测试都测试可用代码的一个单元。

这个 Python 库的名称是`unittest`，毫不奇怪。它提供了几个用于创建和运行单元测试的工具，其中最重要的是`TestCase`类。这个类提供了一组方法，允许我们比较值，设置测试，并在测试完成时进行清理。

当我们想要为特定任务编写一组单元测试时，我们创建一个`TestCase`的子类，并编写单独的方法来进行实际测试。这些方法都必须以`test`开头的名称。遵循这个约定时，测试会自动作为测试过程的一部分运行。通常，测试会在对象上设置一些值，然后运行一个方法，并使用内置的比较方法来确保正确的结果被计算出来。这里有一个非常简单的例子：

```py
import unittest

class CheckNumbers(unittest.TestCase):
    def test_int_float(self):
        self.assertEqual(1, 1.0)
```

```py
if __name__ == "__main__":
    unittest.main()
```

这段代码简单地继承了`TestCase`类，并添加了一个调用`TestCase.assertEqual`方法的方法。这个方法将根据两个参数是否相等而成功或引发异常。如果我们运行这段代码，`unittest`的`main`函数将给出以下输出：

```py
.
--------------------------------------------------------------
Ran 1 test in 0.000s

OK  
```

你知道浮点数和整数可以被比较为相等吗？让我们添加一个失败的测试，如下：

```py
    def test_str_float(self): 
        self.assertEqual(1, "1") 
```

这段代码的输出更加阴险，因为整数和字符串不是

被认为是相等的：

```py
.F
============================================================
FAIL: test_str_float (__main__.CheckNumbers)
--------------------------------------------------------------
Traceback (most recent call last):
 File "first_unittest.py", line 9, in test_str_float
 self.assertEqual(1, "1")
AssertionError: 1 != '1'

--------------------------------------------------------------
Ran 2 tests in 0.001s

FAILED (failures=1)  
```

第一行的点表示第一个测试（我们之前写的那个）成功通过；其后的字母`F`表示第二个测试失败。然后，在最后，它会给出一些信息性的输出，告诉我们测试失败的原因和位置，以及失败的数量总结。

我们可以在一个`TestCase`类上有尽可能多的测试方法。只要方法名以`test`开头，测试运行器就会将每个方法作为一个单独的、隔离的测试执行。每个测试应该完全独立于其他测试。先前测试的结果或计算不应该对当前测试产生影响。编写良好的单元测试的关键是尽可能保持每个测试方法的长度短小，每个测试用例测试一小部分代码。如果我们的代码似乎无法自然地分解成这样可测试的单元，这可能是代码需要重新设计的迹象。

# 断言方法

测试用例的一般布局是将某些变量设置为已知的值，运行一个或多个函数、方法或进程，然后使用`TestCase`的断言方法*证明*正确的预期结果是通过的或者被计算出来的。

有几种不同的断言方法可用于确认已经实现了特定的结果。我们刚刚看到了`assertEqual`，如果两个参数不能通过相等检查，它将导致测试失败。相反，`assertNotEqual`如果两个参数比较为相等，则会失败。`assertTrue`和`assertFalse`方法分别接受一个表达式，并且如果表达式不能通过`if`测试，则会失败。这些测试不检查布尔值`True`或`False`。相反，它们测试与使用`if`语句相同的条件：`False`、`None`、`0`或空列表、字典、字符串、集合或元组会通过调用`assertFalse`方法。非零数、包含值的容器，或值`True`在调用`assertTrue`方法时会成功。

有一个`assertRaises`方法，可以用来确保特定的函数调用引发特定的异常，或者可以选择作为上下文管理器来包装内联代码。如果`with`语句内的代码引发了正确的异常，则测试通过；否则，测试失败。以下代码片段是两个版本的示例：

```py
import unittest

def average(seq):
    return sum(seq) / len(seq)

class TestAverage(unittest.TestCase):
    def test_zero(self):
        self.assertRaises(ZeroDivisionError, average, [])

    def test_with_zero(self):
        with self.assertRaises(ZeroDivisionError):
            average([])

if __name__ == "__main__":
    unittest.main()
```

上下文管理器允许我们以通常的方式编写代码（通过调用函数或直接执行代码），而不必在另一个函数调用中包装函数调用。

还有几种其他断言方法，总结在下表中：

| **方法** | **描述** |
| --- | --- |
| `assertGreater``assertGreaterEqual``assertLess``assertLessEqual` | 接受两个可比较的对象，并确保命名的不等式成立。 |
| `assertIn``assertNotIn` | 确保元素是（或不是）容器对象中的一个元素。 |
| `assertIsNone``assertIsNotNone` | 确保一个元素是（或不是）确切的`None`值（而不是其他假值）。 |
| `assertSameElements` | 确保两个容器对象具有相同的元素，忽略顺序。 |
| `assertSequenceEqualassertDictEqual``assertSetEqual``assertListEqual``assertTupleEqual` | 确保两个容器以相同的顺序具有相同的元素。如果失败，显示一个比较两个列表的代码差异，以查看它们的不同之处。最后四种方法还测试了列表的类型。 |

每个断言方法都接受一个名为`msg`的可选参数。如果提供了，它将包含在错误消息中，如果断言失败，这对于澄清预期的内容或解释可能导致断言失败的错误的地方非常有用。然而，我很少使用这种语法，更喜欢为测试方法使用描述性的名称。

# 减少样板代码和清理

编写了一些小测试之后，我们经常发现我们必须为几个相关的测试编写相同的设置代码。例如，以下`list`子类有三种用于统计计算的方法：

```py
from collections import defaultdict 

class StatsList(list): 
    def mean(self): 
        return sum(self) / len(self) 

    def median(self): 
        if len(self) % 2: 
            return self[int(len(self) / 2)] 
        else: 
            idx = int(len(self) / 2) 
            return (self[idx] + self[idx-1]) / 2 

    def mode(self): 
        freqs = defaultdict(int) 
        for item in self: 
            freqs[item] += 1 
        mode_freq = max(freqs.values()) 
        modes = [] 
        for item, value in freqs.items(): 
            if value == mode_freq: 
                modes.append(item) 
        return modes 
```

显然，我们将要测试这三种方法中的每一种情况，这些情况具有非常相似的输入。我们将要看到空列表、包含非数字值的列表，或包含正常数据集的列表等情况下会发生什么。我们可以使用`TestCase`类上的`setUp`方法来为每个测试执行初始化。这个方法不接受任何参数，并允许我们在每个测试运行之前进行任意的设置。例如，我们可以在相同的整数列表上测试所有三种方法，如下所示：

```py
from stats import StatsList
import unittest

class TestValidInputs(unittest.TestCase):
    def setUp(self):
        self.stats = StatsList([1, 2, 2, 3, 3, 4])

    def test_mean(self):
        self.assertEqual(self.stats.mean(), 2.5)

    def test_median(self):
        self.assertEqual(self.stats.median(), 2.5)
        self.stats.append(4)
        self.assertEqual(self.stats.median(), 3)

    def test_mode(self):
        self.assertEqual(self.stats.mode(), [2, 3])
        self.stats.remove(2)
        self.assertEqual(self.stats.mode(), [3])

if __name__ == "__main__":
    unittest.main()
```

如果我们运行这个例子，它表明所有测试都通过了。首先注意到`setUp`方法从未在三个`test_*`方法中显式调用过。测试套件会代表我们执行这个操作。更重要的是，注意`test_median`如何改变了列表，通过向其中添加一个额外的`4`，但是当随后调用`test_mode`时，列表已经恢复到了`setUp`中指定的值。如果没有恢复，列表中将会有两个四，而`mode`方法将会返回三个值。这表明`setUp`在每个测试之前都会被单独调用，确保测试类从一个干净的状态开始。测试可以以任何顺序执行，一个测试的结果绝不能依赖于其他测试。

除了`setUp`方法，`TestCase`还提供了一个无参数的`tearDown`方法，它可以用于在类的每个测试运行后进行清理。如果清理需要除了让对象被垃圾回收之外的其他操作，这个方法就很有用。

例如，如果我们正在测试进行文件 I/O 的代码，我们的测试可能会在测试的副作用下创建新文件。`tearDown`方法可以删除这些文件，并确保系统处于与测试运行之前相同的状态。测试用例绝不能有副作用。通常，我们根据它们共同的设置代码将测试方法分组到单独的`TestCase`子类中。需要相同或相似设置的几个测试将被放置在一个类中，而需要不相关设置的测试将被放置在另一个类中。

# 组织和运行测试

对于一个单元测试集合来说，很快就会变得非常庞大和难以控制。一次性加载和运行所有测试可能会变得非常复杂。这是单元测试的主要目标：在程序上轻松运行所有测试，并快速得到一个“是”或“否”的答案，来回答“我的最近的更改是否有问题？”的问题。

与正常的程序代码一样，我们应该将测试类分成模块和包，以保持它们的组织。如果您将每个测试模块命名为以四个字符*test*开头，就可以轻松找到并运行它们。Python 的`discover`模块会查找当前文件夹或子文件夹中以`test`开头命名的任何模块。如果它在这些模块中找到任何`TestCase`对象，就会执行测试。这是一种无痛的方式来确保我们不会错过运行任何测试。要使用它，请确保您的测试模块命名为`test_<something>.py`，然后运行`python3 -m unittest discover`命令。

大多数 Python 程序员选择将他们的测试放在一个单独的包中（通常命名为`tests/`，与他们的源目录并列）。但这并不是必需的。有时，将不同包的测试模块放在该包旁边的子包中是有意义的，例如。

# 忽略损坏的测试

有时，我们知道测试会失败，但我们不希望测试套件报告失败。这可能是因为一个损坏或未完成的功能已经编写了测试，但我们目前并不专注于改进它。更常见的情况是，因为某个功能仅在特定平台、Python 版本或特定库的高级版本上可用。Python 为我们提供了一些装饰器，用于标记测试为预期失败或在已知条件下跳过。

这些装饰器如下：

+   `expectedFailure()`

+   `skip(reason)`

+   `skipIf(condition, reason)`

+   `skipUnless(condition, reason)`

这些是使用 Python 装饰器语法应用的。第一个不接受参数，只是告诉测试运行器在测试失败时不记录测试失败。`skip`方法更进一步，甚至不会运行测试。它期望一个描述为什么跳过测试的字符串参数。另外两个装饰器接受两个参数，一个是布尔表达式，指示是否应该运行测试，另一个是类似的描述。在使用时，这三个装饰器可能会像下面的代码中所示一样应用：

```py
import unittest
import sys

class SkipTests(unittest.TestCase):
    @unittest.expectedFailure
    def test_fails(self):
        self.assertEqual(False, True)

    @unittest.skip("Test is useless")
    def test_skip(self):
        self.assertEqual(False, True)

    @unittest.skipIf(sys.version_info.minor == 4, "broken on 3.4")
    def test_skipif(self):
        self.assertEqual(False, True)

    @unittest.skipUnless(
        sys.platform.startswith("linux"), "broken unless on linux"
    )
    def test_skipunless(self):
        self.assertEqual(False, True)

if __name__ == "__main__":
    unittest.main()
```

第一个测试失败，但被报告为预期的失败；第二个测试从未运行。其他两个测试可能会运行，也可能不会，这取决于当前的 Python 版本和操作系统。在我的 Linux 系统上，运行 Python 3.7，输出如下：

```py
xssF
======================================================================
FAIL: test_skipunless (__main__.SkipTests)
----------------------------------------------------------------------
Traceback (most recent call last):
 File "test_skipping.py", line 22, in test_skipunless
 self.assertEqual(False, True)
AssertionError: False != True

----------------------------------------------------------------------
Ran 4 tests in 0.001s

FAILED (failures=1, skipped=2, expected failures=1)
```

第一行上的`x`表示预期的失败；两个`s`字符表示跳过的测试，`F`表示真正的失败，因为在我的系统上`skipUnless`的条件为`True`。

# 使用 pytest 进行测试

Python 的`unittest`模块需要大量样板代码来设置和初始化测试。它基于非常流行的 Java 的 JUnit 测试框架。它甚至使用相同的方法名称（您可能已经注意到它们不符合 PEP-8 命名标准，该标准建议使用 snake_case 而不是 CamelCase 来表示方法名称）和测试布局。虽然这对于在 Java 中进行测试是有效的，但不一定是 Python 测试的最佳设计。我实际上发现`unittest`框架是过度使用面向对象原则的一个很好的例子。

因为 Python 程序员喜欢他们的代码简洁而简单，所以在标准库之外开发了其他测试框架。其中两个较受欢迎的是`pytest`和`nose`。前者更为健壮，并且支持 Python 3 的时间更长，因此我们将在这里讨论它。

由于`pytest`不是标准库的一部分，您需要自己下载并安装它。您可以从[`pytest.org/`](http://pytest.org/)的`pytest`主页获取它。该网站提供了各种解释器和平台的全面安装说明，但通常您可以使用更常见的 Python 软件包安装程序 pip。只需在命令行上输入`pip install pytest`，就可以开始使用了。

`pytest`的布局与`unittest`模块有很大不同。它不要求测试用例是类。相反，它利用了 Python 函数是对象的事实，并允许任何命名正确的函数像测试一样行为。它不是提供一堆用于断言相等的自定义方法，而是使用`assert`语句来验证结果。这使得测试更易读和易维护。

当我们运行`pytest`时，它会从当前文件夹开始搜索以`test_`开头的任何模块或子包。如果该模块中的任何函数也以`test`开头，它们将作为单独的测试执行。此外，如果模块中有任何以`Test`开头的类，该类上以`test_`开头的任何方法也将在测试环境中执行。

使用以下代码，让我们将之前编写的最简单的`unittest`示例移植到`pytest`：

```py
def test_int_float(): 
    assert 1 == 1.0 
```

对于完全相同的测试，我们写了两行更易读的代码，而不是我们第一个`unittest`示例中需要的六行。

但是，我们并没有禁止编写基于类的测试。类可以用于将相关测试分组在一起，或者用于需要访问类上相关属性或方法的测试。下面的示例显示了一个扩展类，其中包含一个通过和一个失败的测试；我们将看到错误输出比`unittest`模块提供的更全面：

```py
class TestNumbers: 
    def test_int_float(self): 
        assert 1 == 1.0 

    def test_int_str(self): 
        assert 1 == "1" 
```

请注意，类不必扩展任何特殊对象才能被识别为测试（尽管`pytest`可以很好地运行标准的`unittest TestCases`）。如果我们运行`pytest <filename>`，输出如下所示：

```py
============================== test session starts ==============================
platform linux -- Python 3.7.0, pytest-3.8.0, py-1.6.0, pluggy-0.7.1
rootdir: /home/dusty/Py3OOP/Chapter 24: Testing Object-oriented Programs, inifile:
collected 3 items

test_with_pytest.py ..F [100%]

=================================== FAILURES ====================================
___________________________ TestNumbers.test_int_str ____________________________

self = <test_with_pytest.TestNumbers object at 0x7fdb95e31390>

 def test_int_str(self):
> assert 1 == "1"
E AssertionError: assert 1 == '1'

test_with_pytest.py:10: AssertionError
====================== 1 failed, 2 passed in 0.03 seconds =======================
```

输出以有关平台和解释器的一些有用信息开始。这对于在不同系统之间共享或讨论错误很有用。第三行告诉我们正在测试的文件的名称（如果有多个测试模块被识别，它们都将显示出来），然后是在`unittest`模块中看到的熟悉的`.F`；`.`字符表示通过的测试，而字母`F`表示失败。

所有测试运行完毕后，将显示每个测试的错误输出。它呈现了局部变量的摘要（在本例中只有一个：传递给函数的`self`参数），发生错误的源代码以及错误消息的摘要。此外，如果引发的异常不是`AssertionError`，`pytest`将向我们呈现完整的回溯，包括源代码引用。

默认情况下，如果测试成功，`pytest`会抑制`print`语句的输出。这对于测试调试很有用；当测试失败时，我们可以向测试中添加`print`语句来检查特定变量和属性的值。如果测试失败，这些值将被输出以帮助诊断。但是，一旦测试成功，`print`语句的输出就不会显示出来，很容易被忽略。我们不必通过删除`print`语句来*清理*输出。如果由于将来的更改而再次失败，调试输出将立即可用。

# 进行设置和清理的一种方法

`pytest`支持类似于`unittest`中使用的设置和拆卸方法，但它提供了更多的灵活性。我们将简要讨论这些，因为它们很熟悉，但它们并没有像在`unittest`模块中那样被广泛使用，因为`pytest`为我们提供了一个强大的固定设施，我们将在下一节中讨论。

如果我们正在编写基于类的测试，我们可以使用两个名为`setup_method`和`teardown_method`的方法，就像在`unittest`中调用`setUp`和`tearDown`一样。它们在类中的每个测试方法之前和之后被调用，以执行设置和清理任务。但是，与`unittest`方法不同的是，这两种方法都接受一个参数：表示被调用的方法的函数对象。

此外，`pytest`提供了其他设置和拆卸函数，以便更好地控制设置和清理代码的执行时间。`setup_class`和`teardown_class`方法预期是类方法；它们接受一个表示相关类的单个参数（没有`self`参数）。这些方法仅在类被初始化时运行，而不是在每次测试运行时运行。

最后，我们有`setup_module`和`teardown_module`函数，它们在该模块中的所有测试（在函数或类中）之前和之后立即运行。这些可以用于*一次性*设置，例如创建一个将被模块中所有测试使用的套接字或数据库连接。对于这一点要小心，因为如果对象存储了在测试之间没有正确清理的状态，它可能会意外地引入测试之间的依赖关系。

这个简短的描述并没有很好地解释这些方法究竟在什么时候被调用，所以让我们看一个例子，确切地说明了它们何时被调用：

```py
def setup_module(module):
    print("setting up MODULE {0}".format(module.__name__))

def teardown_module(module):
    print("tearing down MODULE {0}".format(module.__name__))

def test_a_function():
    print("RUNNING TEST FUNCTION")

class BaseTest:
    def setup_class(cls):
        print("setting up CLASS {0}".format(cls.__name__))

    def teardown_class(cls):
        print("tearing down CLASS {0}\n".format(cls.__name__))

    def setup_method(self, method):
        print("setting up METHOD {0}".format(method.__name__))

    def teardown_method(self, method):
        print("tearing down METHOD {0}".format(method.__name__))

class TestClass1(BaseTest):
    def test_method_1(self):
        print("RUNNING METHOD 1-1")

    def test_method_2(self):
        print("RUNNING METHOD 1-2")

class TestClass2(BaseTest):
    def test_method_1(self):
        print("RUNNING METHOD 2-1")

    def test_method_2(self):
        print("RUNNING METHOD 2-2")
```

`BaseTest`类的唯一目的是提取四个方法，否则这些方法与测试类相同，并使用继承来减少重复代码的数量。因此，从`pytest`的角度来看，这两个子类不仅每个有两个测试方法，还有两个设置和两个拆卸方法（一个在类级别，一个在方法级别）。

如果我们使用`pytest`运行这些测试，并且禁用了`print`函数的输出抑制（通过传递`-s`或`--capture=no`标志），它们会告诉我们各种函数在与测试本身相关的时候被调用：

```py
setup_teardown.py
setting up MODULE setup_teardown
RUNNING TEST FUNCTION
.setting up CLASS TestClass1
setting up METHOD test_method_1
RUNNING METHOD 1-1
.tearing down  METHOD test_method_1
setting up METHOD test_method_2
RUNNING METHOD 1-2
.tearing down  METHOD test_method_2
tearing down CLASS TestClass1
setting up CLASS TestClass2
setting up METHOD test_method_1
RUNNING METHOD 2-1
.tearing down  METHOD test_method_1
setting up METHOD test_method_2
RUNNING METHOD 2-2
.tearing down  METHOD test_method_2
tearing down CLASS TestClass2

tearing down MODULE setup_teardown  
```

模块的设置和拆卸方法在会话开始和结束时执行。然后运行单个模块级别的测试函数。接下来，执行第一个类的设置方法，然后是该类的两个测试。这些测试分别包装在单独的`setup_method`和`teardown_method`调用中。测试执行完毕后，调用类的拆卸方法。在第二个类之前，发生了相同的顺序，最后调用`teardown_module`方法，确切地一次。

# 设置变量的完全不同的方法

各种设置和拆卸函数的最常见用途之一是确保在运行每个测试方法之前，某些类或模块变量可用且具有已知值。

`pytest`提供了一个完全不同的设置变量的方法，使用所谓的**fixtures**。Fixture 基本上是预定义在测试配置文件中的命名变量。这允许我们将配置与测试的执行分开，并允许 fixtures 在多个类和模块中使用。

为了使用它们，我们向我们的测试函数添加参数。参数的名称用于在特别命名的函数中查找特定的参数。例如，如果我们想测试我们在演示`unittest`时使用的`StatsList`类，我们再次想要重复测试一个有效整数列表。但是，我们可以编写我们的测试如下，而不是使用设置方法：

```py
import pytest
from stats import StatsList

@pytest.fixture
def valid_stats():
    return StatsList([1, 2, 2, 3, 3, 4])

def test_mean(valid_stats):
    assert valid_stats.mean() == 2.5

def test_median(valid_stats):
    assert valid_stats.median() == 2.5
    valid_stats.append(4)
    assert valid_stats.median() == 3

def test_mode(valid_stats):
    assert valid_stats.mode() == [2, 3]
    valid_stats.remove(2)
    assert valid_stats.mode() == [3]
```

这三个测试方法中的每一个都接受一个名为`valid_stats`的参数；这个参数是通过调用`valid_stats`函数创建的，该函数被装饰为`@pytest.fixture`。

Fixture 可以做的远不止返回基本变量。可以将`request`对象传递到 fixture 工厂中，以提供非常有用的方法和属性来修改 funcarg 的行为。`module`、`cls`和`function`属性允许我们准确地查看请求 fixture 的测试。`config`属性允许我们检查命令行参数和大量其他配置数据。

如果我们将 fixture 实现为生成器，我们可以在每次测试运行后运行清理代码。这提供了类似于拆卸方法的功能，但是在每个 fixture 的基础上。我们可以用它来清理文件、关闭连接、清空列表或重置队列。例如，以下代码测试了`os.mkdir`功能，通过创建一个临时目录 fixture：

```py
import pytest
import tempfile
import shutil
import os.path

@pytest.fixture
def temp_dir(request):
    dir = tempfile.mkdtemp()
    print(dir)
    yield dir
    shutil.rmtree(dir)

def test_osfiles(temp_dir):
    os.mkdir(os.path.join(temp_dir, "a"))
    os.mkdir(os.path.join(temp_dir, "b"))
    dir_contents = os.listdir(temp_dir)
    assert len(dir_contents) == 2
    assert "a" in dir_contents
    assert "b" in dir_contents
```

该 fixture 为文件创建一个新的空临时目录。它将此目录提供给测试使用，但在测试完成后删除该目录（使用`shutil.rmtree`，递归删除目录及其中的所有内容）。文件系统将保持与开始时相同的状态。

我们可以传递一个`scope`参数来创建一个持续时间超过一个测试的 fixture。当设置一个昂贵的操作，可以被多个测试重复使用时，这是很有用的，只要资源重用不会破坏测试的原子性或单元性（以便一个测试不依赖于前一个测试，也不受其影响）。例如，如果我们要测试以下回显服务器，我们可能只想在单独的进程中运行一个服务器实例，然后让多个测试连接到该实例：

```py
import socket 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
s.bind(('localhost',1028)) 
s.listen(1) 

    while True: 
        client, address = s.accept() 
        data = client.recv(1024) 
        client.send(data) 
        client.close() 
```

这段代码的作用只是监听特定端口，并等待来自客户端 socket 的输入。当它接收到输入时，它会将相同的值发送回去。为了测试这个，我们可以在单独的进程中启动服务器，并缓存结果供多个测试使用。测试代码可能如下所示：

```py
import subprocess
import socket
import time
import pytest

@pytest.fixture(scope="session")
def echoserver():
    print("loading server")
    p = subprocess.Popen(["python3", "echo_server.py"])
    time.sleep(1)
    yield p
    p.terminate()

@pytest.fixture
def clientsocket(request):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", 1028))
    yield s
    s.close()

def test_echo(echoserver, clientsocket):
    clientsocket.send(b"abc")
    assert clientsocket.recv(3) == b"abc"

def test_echo2(echoserver, clientsocket):
    clientsocket.send(b"def")
    assert clientsocket.recv(3) == b"def"
```

我们在这里创建了两个 fixtures。第一个在单独的进程中运行回显服务器，并在完成时清理进程对象。第二个为每个测试实例化一个新的 socket 对象，并在测试完成时关闭 socket。

第一个 fixture 是我们目前感兴趣的。通过传递给装饰器构造函数的`scope="session"`关键字参数，`pytest`知道我们只希望在单元测试会话期间初始化和终止一次这个 fixture。

作用域可以是字符串`class`、`module`、`package`或`session`中的一个。它决定了参数将被缓存多长时间。在这个例子中，我们将其设置为`session`，因此它将在整个`pytest`运行期间被缓存。进程将在所有测试运行完之前不会被终止或重新启动。当然，`module`作用域仅为该模块中的测试缓存，`class`作用域将对象视为普通的类设置和拆卸。

在本书第三版印刷时，`pytest`中的`package`作用域被标记为实验性质。请小心使用，并要求您提供 bug 报告。

# 使用 pytest 跳过测试

与`unittest`模块一样，经常需要在`pytest`中跳过测试，原因各种各样：被测试的代码尚未编写，测试仅在某些解释器或操作系统上运行，或者测试耗时且只应在特定情况下运行。

我们可以在代码的任何地方跳过测试，使用`pytest.skip`函数。它接受一个参数：描述为什么要跳过的字符串。这个函数可以在任何地方调用。如果我们在测试函数内调用它，测试将被跳过。如果我们在模块级别调用它，那个模块中的所有测试都将被跳过。如果我们在 fixture 内调用它，所有调用该 funcarg 的测试都将被跳过。

当然，在所有这些位置，通常希望只有在满足或不满足某些条件时才跳过测试。由于我们可以在 Python 代码的任何地方执行`skip`函数，我们可以在`if`语句内执行它。因此，我们可能编写一个如下所示的测试：

```py
import sys 
import pytest 

def test_simple_skip(): 
    if sys.platform != "fakeos": 
        pytest.skip("Test works only on fakeOS") 

    fakeos.do_something_fake() 
    assert fakeos.did_not_happen 
```

这实际上是一些相当愚蠢的代码。没有名为`fakeos`的 Python 平台，因此这个测试将在所有操作系统上跳过。它展示了我们如何有条件地跳过测试，由于`if`语句可以检查任何有效的条件，我们对测试何时被跳过有很大的控制权。通常，我们检查`sys.version_info`来检查 Python 解释器版本，`sys.platform`来检查操作系统，或者`some_library.__version__`来检查我们是否有足够新的给定 API 版本。

由于基于某个条件跳过单个测试方法或函数是测试跳过的最常见用法之一，`pytest`提供了一个方便的装饰器，允许我们在一行中执行此操作。装饰器接受一个字符串，其中可以包含任何可执行的 Python 代码，该代码求值为布尔值。例如，以下测试只在 Python 3 或更高版本上运行：

```py
@pytest.mark.skipif("sys.version_info <= (3,0)") 
def test_python3(): 
    assert b"hello".decode() == "hello" 
```

`pytest.mark.xfail`装饰器的行为类似，只是它标记一个测试预期失败，类似于`unittest.expectedFailure()`。如果测试成功，它将被记录为失败。如果失败，它将被报告为预期行为。在`xfail`的情况下，条件参数是可选的。如果没有提供，测试将被标记为在所有条件下都预期失败。

`pytest`除了这里描述的功能之外，还有很多其他功能，开发人员不断添加创新的新方法，使您的测试体验更加愉快。他们在网站上有详尽的文档[`docs.pytest.org/`](https://docs.pytest.org/)。

`pytest`可以找到并运行使用标准`unittest`库定义的测试，除了它自己的测试基础设施。这意味着如果你想从`unittest`迁移到`pytest`，你不必重写所有旧的测试。

# 模拟昂贵的对象

有时，我们想要测试需要提供一个昂贵或难以构建的对象的代码。在某些情况下，这可能意味着您的 API 需要重新思考，以具有更可测试的接口（通常意味着更可用的接口）。但我们有时发现自己编写的测试代码有大量样板代码来设置与被测试代码只是偶然相关的对象。

例如，想象一下我们有一些代码，它在外部键值存储中（如`redis`或`memcache`）跟踪航班状态，以便我们可以存储时间戳和最新状态。这样的基本版本代码可能如下所示：

```py
import datetime
import redis

class FlightStatusTracker:
    ALLOWED_STATUSES = {"CANCELLED", "DELAYED", "ON TIME"}

    def __init__(self):
        self.redis = redis.StrictRedis()

    def change_status(self, flight, status):
        status = status.upper()
        if status not in self.ALLOWED_STATUSES:
            raise ValueError("{} is not a valid status".format(status))

        key = "flightno:{}".format(flight)
        value = "{}|{}".format(
            datetime.datetime.now().isoformat(), status
        )
        self.redis.set(key, value)
```

有很多我们应该为`change_status`方法测试的事情。我们应该检查如果传入了错误的状态，它是否引发了适当的错误。我们需要确保它将状态转换为大写。我们可以看到当在`redis`对象上调用`set()`方法时，键和值的格式是否正确。

然而，在我们的单元测试中，我们不必检查`redis`对象是否正确存储数据。这是绝对应该在集成或应用程序测试中进行测试的事情，但在单元测试级别，我们可以假设 py-redis 开发人员已经测试过他们的代码，并且这个方法可以按我们的要求工作。一般来说，单元测试应该是自包含的，不应依赖于外部资源的存在，比如运行中的 Redis 实例。

相反，我们只需要测试`set()`方法被调用的次数和使用的参数是否正确。我们可以在测试中使用`Mock()`对象来替换麻烦的方法，以便我们可以内省对象。以下示例说明了`Mock`的用法：

```py
from flight_status_redis import FlightStatusTracker
from unittest.mock import Mock
import pytest

@pytest.fixture
def tracker():
    return FlightStatusTracker()

def test_mock_method(tracker):
 tracker.redis.set = Mock()
    with pytest.raises(ValueError) as ex:
        tracker.change_status("AC101", "lost")
    assert ex.value.args[0] == "LOST is not a valid status"
 assert tracker.redis.set.call_count == 0

```

这个使用`pytest`语法编写的测试断言在传入不合适的参数时会引发正确的异常。此外，它为`set`方法创建了一个`Mock`对象，并确保它从未被调用。如果被调用了，这意味着我们的异常处理代码中存在错误。

在这种情况下，简单地替换方法效果很好，因为被替换的对象最终被销毁了。然而，我们经常希望仅在测试期间替换函数或方法。例如，如果我们想测试`Mock`方法中的时间戳格式，我们需要确切地知道`datetime.datetime.now()`将返回什么。然而，这个值会随着运行的不同而改变。我们需要一种方法将其固定到一个特定的值，以便我们可以进行确定性测试。

临时将库函数设置为特定值是猴子补丁的少数有效用例之一。模拟库提供了一个补丁上下文管理器，允许我们用模拟对象替换现有库上的属性。当上下文管理器退出时，原始属性会自动恢复，以免影响其他测试用例。以下是一个例子：

```py
import datetime
from unittest.mock import patch

def test_patch(tracker):
    tracker.redis.set = Mock()
    fake_now = datetime.datetime(2015, 4, 1)
 with patch("datetime.datetime") as dt:
        dt.now.return_value = fake_now
        tracker.change_status("AC102", "on time")
    dt.now.assert_called_once_with()
    tracker.redis.set.assert_called_once_with(
        "flightno:AC102", "2015-04-01T00:00:00|ON TIME"
    )
```

在前面的例子中，我们首先构造了一个名为`fake_now`的值，我们将其设置为`datetime.datetime.now`函数的返回值。我们必须在补丁`datetime.datetime`之前构造这个对象，否则我们会在构造它之前调用已经补丁的`now`函数。

`with`语句邀请补丁用模拟对象替换`datetime.datetime`模块，返回为`dt`值。模拟对象的好处是，每次访问该对象的属性或方法时，它都会返回另一个模拟对象。因此，当我们访问`dt.now`时，它会给我们一个新的模拟对象。我们将该对象的`return_value`设置为我们的`fake_now`对象。现在，每当调用`datetime.datetime.now`函数时，它将返回我们的对象，而不是一个新的模拟对象。但是当解释器退出上下文管理器时，原始的`datetime.datetime.now()`功能会被恢复。

在使用已知值调用我们的`change_status`方法后，我们使用`Mock`类的`assert_called_once_with`函数来确保`now`函数确实被调用了一次，且没有参数。然后我们再次调用它，以证明`redis.set`方法被调用时，参数的格式与我们期望的一样。

模拟日期以便获得确定性的测试结果是一个常见的补丁场景。如果你处于这种情况，你可能会喜欢 Python 包索引中提供的`freezegun`和`pytest-freezegun`项目。

前面的例子很好地说明了编写测试如何指导我们的 API 设计。`FlightStatusTracker`对象乍一看似乎很合理；我们在对象构造时构建了一个`redis`连接，并在需要时调用它。然而，当我们为这段代码编写测试时，我们发现即使我们在`FlightStatusTracker`上模拟了`self.redis`变量，`redis`连接仍然必须被构造。如果没有运行 Redis 服务器，这个调用实际上会失败，我们的测试也会失败。

我们可以通过在`setUp`方法中模拟`redis.StrictRedis`类来解决这个问题，以返回一个模拟对象。然而，一个更好的想法可能是重新思考我们的实现。与其在`__init__`中构造`redis`实例，也许我们应该允许用户传入一个，就像下面的例子一样：

```py
    def __init__(self, redis_instance=None): 
        self.redis = redis_instance if redis_instance else redis.StrictRedis() 
```

这样我们就可以在测试时传入一个模拟对象，这样`StrictRedis`方法就不会被构造。此外，它允许任何与`FlightStatusTracker`交互的客户端代码传入他们自己的`redis`实例。他们可能有各种原因这样做：他们可能已经为代码的其他部分构造了一个；他们可能已经创建了`redis` API 的优化实现；也许他们有一个将指标记录到内部监控系统的实现。通过编写单元测试，我们发现了一个使用案例，使我们的 API 从一开始就更加灵活，而不是等待客户要求我们支持他们的异类需求。

这是对模拟代码奇迹的简要介绍。自 Python 3.3 以来，模拟是标准的`unittest`库的一部分，但正如你从这些例子中看到的，它们也可以与`pytest`和其他库一起使用。模拟还有其他更高级的功能，你可能需要利用这些功能，因为你的代码变得更加复杂。例如，你可以使用`spec`参数邀请模拟模仿现有类，以便在尝试访问模仿类上不存在的属性时引发错误。你还可以构造模拟方法，每次调用时返回不同的参数，通过将列表作为`side_effect`参数。`side_effect`参数非常灵活；你还可以使用它在调用模拟时执行任意函数或引发异常。

一般来说，我们应该对模拟非常吝啬。如果我们发现自己在给定的单元测试中模拟了多个元素，我们可能最终测试的是模拟框架而不是我们的真实代码。这毫无用处；毕竟，模拟已经经过了充分测试！如果我们的代码做了很多这样的事情，这可能是另一个迹象，表明我们正在测试的 API 设计得很糟糕。模拟应该存在于被测试代码和它们接口的库之间的边界上。如果这种情况没有发生，我们可能需要改变 API，以便在不同的地方重新划定边界。

# 测试多少是足够的？

我们已经确定了未经测试的代码是有问题的代码。但我们如何知道我们的代码被测试得有多好？我们如何知道我们的代码有多少被测试，有多少是有问题的？第一个问题更重要，但很难回答。即使我们知道我们已经测试了应用程序中的每一行代码，我们也不知道我们是否已经适当地测试了它。例如，如果我们编写了一个只检查当我们提供一个整数列表时会发生什么的统计测试，如果用于浮点数、字符串或自制对象的列表，它可能仍然会失败得很惨。设计完整测试套件的责任仍然在程序员身上。

第二个问题——我们的代码有多少被测试——很容易验证。**代码覆盖率**是程序执行的代码行数的估计。如果我们知道这个数字和程序中的代码行数，我们就可以估算出实际被测试或覆盖的代码百分比。如果我们另外有一个指示哪些行没有被测试的指标，我们就可以更容易地编写新的测试来确保这些行不会出错。

用于测试代码覆盖率的最流行的工具叫做`coverage.py`。它可以像大多数其他第三方库一样安装，使用`pip install coverage`命令。

我们没有空间来涵盖覆盖 API 的所有细节，所以我们只看一些典型的例子。如果我们有一个运行所有单元测试的 Python 脚本（例如，使用`unittest.main`、`discover`、`pytest`或自定义测试运行器），我们可以使用以下命令执行覆盖分析：

```py
$coverage run coverage_unittest.py  
```

这个命令将正常退出，但它会创建一个名为`.coverage`的文件，其中保存了运行的数据。现在我们可以使用`coverage report`命令来获取代码覆盖的分析：

```py
$coverage report  
```

生成的输出应该如下所示：

```py
Name                           Stmts   Exec  Cover
--------------------------------------------------
coverage_unittest                  7      7   100%
stats                             19      6    31%
--------------------------------------------------
TOTAL                             26     13    50%  
```

这份基本报告列出了执行的文件（我们的单元测试和一个导入的模块）。还列出了每个文件中的代码行数以及测试执行的代码行数。然后将这两个数字合并以估算代码覆盖量。如果我们在`report`命令中传递`-m`选项，它还会添加一个如下所示的列：

```py
Missing
-----------
8-12, 15-23  
```

这里列出的行范围标识了在测试运行期间未执行的`stats`模块中的行。

我们刚刚对代码覆盖工具运行的示例使用了我们在本章早些时候创建的相同的 stats 模块。但是，它故意使用了一个失败的测试来测试文件中的大量代码。以下是测试：

```py
from stats import StatsList 
import unittest 

class TestMean(unittest.TestCase): 
    def test_mean(self): 
        self.assertEqual(StatsList([1,2,2,3,3,4]).mean(), 2.5) 

if __name__ == "__main__": 

    unittest.main() 
```

这段代码没有测试中位数或模式函数，这些函数对应于覆盖输出告诉我们缺失的行号。

文本报告提供了足够的信息，但如果我们使用`coverage html`命令，我们可以获得一个更有用的交互式 HTML 报告，我们可以在 Web 浏览器中查看。网页甚至会突出显示源代码中哪些行已经测试过，哪些行没有测试过。看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/f42ff938-8ab2-424a-bce5-445480a4d0a2.png)

我们也可以使用`pytest`模块的`coverage.py`模块。我们需要安装`pytest`插件以进行代码覆盖率，使用`pip install pytest-coverage`。该插件为`pytest`添加了几个命令行选项，其中最有用的是`--cover-report`，可以设置为`html`，`report`或`annotate`（后者实际上修改了原始源代码以突出显示未覆盖的任何行）。

不幸的是，如果我们可以在本章的这一部分上运行覆盖率报告，我们会发现我们并没有覆盖大部分关于代码覆盖率的知识！可以使用覆盖 API 来从我们自己的程序（或测试套件）中管理代码覆盖率，`coverage.py`接受了许多我们没有涉及的配置选项。我们还没有讨论语句覆盖和分支覆盖之间的区别（后者更有用，并且是最近版本的`coverage.py`的默认值），或者其他风格的代码覆盖。

请记住，虽然 100％的代码覆盖率是我们所有人都应该努力追求的一个远大目标，但 100％的覆盖率是不够的！仅仅因为一个语句被测试了并不意味着它被正确地测试了所有可能的输入。

# 案例研究

让我们通过编写一个小的、经过测试的密码应用程序来了解测试驱动开发。不用担心-您不需要了解复杂的现代加密算法（如 AES 或 RSA）背后的数学。相反，我们将实现一个称为 Vigenère 密码的 16 世纪算法。该应用程序只需要能够使用此密码对消息进行编码和解码，给定一个编码关键字。

如果您想深入了解 RSA 算法的工作原理，我在我的博客上写了一篇文章[`dusty.phillips.codes/`](https://dusty.phillips.codes/)。

首先，我们需要了解密码是如何工作的，如果我们手动应用它（没有计算机）。我们从以下表格开始：

```py
A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 
B C D E F G H I J K L M N O P Q R S T U V W X Y Z A 
C D E F G H I J K L M N O P Q R S T U V W X Y Z A B 
D E F G H I J K L M N O P Q R S T U V W X Y Z A B C 
E F G H I J K L M N O P Q R S T U V W X Y Z A B C D 
F G H I J K L M N O P Q R S T U V W X Y Z A B C D E 
G H I J K L M N O P Q R S T U V W X Y Z A B C D E F 
H I J K L M N O P Q R S T U V W X Y Z A B C D E F G 
I J K L M N O P Q R S T U V W X Y Z A B C D E F G H 
J K L M N O P Q R S T U V W X Y Z A B C D E F G H I 
K L M N O P Q R S T U V W X Y Z A B C D E F G H I J 
L M N O P Q R S T U V W X Y Z A B C D E F G H I J K 
M N O P Q R S T U V W X Y Z A B C D E F G H I J K L 
N O P Q R S T U V W X Y Z A B C D E F G H I J K L M 
O P Q R S T U V W X Y Z A B C D E F G H I J K L M N 
P Q R S T U V W X Y Z A B C D E F G H I J K L M N O 
Q R S T U V W X Y Z A B C D E F G H I J K L M N O P 
R S T U V W X Y Z A B C D E F G H I J K L M N O P Q 
S T U V W X Y Z A B C D E F G H I J K L M N O P Q R 
T U V W X Y Z A B C D E F G H I J K L M N O P Q R S 
U V W X Y Z A B C D E F G H I J K L M N O P Q R S T 
V W X Y Z A B C D E F G H I J K L M N O P Q R S T U 
W X Y Z A B C D E F G H I J K L M N O P Q R S T U V 
X Y Z A B C D E F G H I J K L M N O P Q R S T U V W 
Y Z A B C D E F G H I J K L M N O P Q R S T U V W X 
Z A B C D E F G H I J K L M N O P Q R S T U V W X Y 
```

给定关键字 TRAIN，我们可以对消息 ENCODED IN PYTHON 进行编码如下：

1.  将关键字和消息一起重复，这样很容易将一个字母映射到另一个字母：

```py
E N C O D E D I N P Y T H O N
T R A I N T R A I N T R A I N 
```

1.  对于明文中的每个字母，找到以该字母开头的表中的行。

1.  找到与所选明文字母的关键字字母相关联的列。

1.  编码字符位于该行和列的交点处。

例如，以 E 开头的行与以 T 开头的列相交于字符 X。因此，密文中的第一个字母是 X。以 N 开头的行与以 R 开头的列相交于字符 E，导致密文 XE。C 与 A 相交于 C，O 与 I 相交于 W。D 和 N 映射到 Q，而 E 和 T 映射到 X。完整的编码消息是 XECWQXUIVCRKHWA。

解码遵循相反的过程。首先，找到具有共享关键字字符（T 行）的行，然后找到该行中编码字符（X）所在的位置。明文字符位于该行的列顶部（E）。

# 实施它

我们的程序将需要一个`encode`方法，该方法接受关键字和明文并返回密文，以及一个`decode`方法，该方法接受关键字和密文并返回原始消息。

但我们不只是写这些方法，让我们遵循测试驱动开发策略。我们将使用`pytest`进行单元测试。我们需要一个`encode`方法，我们知道它必须做什么；让我们首先为该方法编写一个测试，如下所示：

```py
def test_encode():
    cipher = VigenereCipher("TRAIN")
    encoded = cipher.encode("ENCODEDINPYTHON")
    assert encoded == "XECWQXUIVCRKHWA"
```

这个测试自然会失败，因为我们没有在任何地方导入`VigenereCipher`类。让我们创建一个新的模块来保存该类。

让我们从以下`VigenereCipher`类开始：

```py
class VigenereCipher:
    def __init__(self, keyword):
        self.keyword = keyword

    def encode(self, plaintext):
        return "XECWQXUIVCRKHWA"

```

如果我们在测试类的顶部添加一行`from``vigenere_cipher``import``VigenereCipher`并运行`pytest`，前面的测试将通过！我们完成了第一个测试驱动开发周期。

这可能看起来像一个荒谬的测试，但实际上它验证了很多东西。第一次我实现它时，在类名中我把 cipher 拼错成了*cypher*。即使是我基本的单元测试也帮助捕捉了一个错误。即便如此，返回一个硬编码的字符串显然不是密码类的最明智的实现，所以让我们添加第二个测试，如下所示：

```py
def test_encode_character(): 
    cipher = VigenereCipher("TRAIN") 
    encoded = cipher.encode("E") 
    assert encoded == "X" 
```

啊，现在那个测试会失败。看来我们要更加努力了。但我突然想到了一件事：如果有人尝试用空格或小写字符对字符串进行编码会怎么样？在我们开始实现编码之前，让我们为这些情况添加一些测试，这样我们就不会忘记它们。预期的行为是去除空格，并将小写字母转换为大写，如下所示：

```py
def test_encode_spaces(): 
    cipher = VigenereCipher("TRAIN") 
    encoded = cipher.encode("ENCODED IN PYTHON") 
    assert encoded == "XECWQXUIVCRKHWA" 

def test_encode_lowercase(): 
    cipher = VigenereCipher("TRain") 
    encoded = cipher.encode("encoded in Python") 
    assert encoded == "XECWQXUIVCRKHWA" 
```

如果我们运行新的测试套件，我们会发现新的测试通过了（它们期望相同的硬编码字符串）。但如果我们忘记考虑这些情况，它们以后应该会失败。

现在我们有了一些测试用例，让我们考虑如何实现我们的编码算法。编写代码使用像我们在早期手动算法中使用的表是可能的，但考虑到每一行只是一个按偏移字符旋转的字母表，这似乎很复杂。事实证明（我问了维基百科），我们可以使用模运算来组合字符，而不是进行表查找。

给定明文和关键字字符，如果我们将这两个字母转换为它们的数字值（根据它们在字母表中的位置，A 为 0，Z 为 25），将它们相加，并取余数模 26，我们就得到了密文字符！这是一个简单的计算，但由于它是逐个字符进行的，我们应该把它放在自己的函数中。在我们这样做之前，我们应该为新函数编写一个测试，如下所示：

```py
from vigenere_cipher import combine_character 
def test_combine_character(): 
    assert combine_character("E", "T") == "X" 
    assert combine_character("N", "R") == "E" 
```

现在我们可以编写代码使这个函数工作。老实说，我在完全正确地编写这个函数之前，不得不多次运行测试。首先，我不小心返回了一个整数，然后我忘记将字符从基于零的比例转换回正常的 ASCII 比例。有了测试可用，很容易测试和调试这些错误。这是测试驱动开发的另一个好处。代码的最终工作版本如下所示：

```py
def combine_character(plain, keyword): 
    plain = plain.upper() 
    keyword = keyword.upper() 
    plain_num = ord(plain) - ord('A') 
    keyword_num = ord(keyword) - ord('A') 
    return chr(ord('A') + (plain_num + keyword_num) % 26) 
```

现在`combine_characters`已经经过测试，我以为我们准备好实现我们的`encode`函数了。然而，在该函数内部我们首先需要一个与明文长度相同的关键字字符串的重复版本。让我们首先实现一个函数。哎呀，我是说让我们首先实现测试，如下所示：

```py
def test_extend_keyword(): cipher = VigenereCipher("TRAIN") extended = cipher.extend_keyword(16) assert extended == "TRAINTRAINTRAINT" 
```

在编写这个测试之前，我原本打算将`extend_keyword`作为一个独立的函数，接受一个关键字和一个整数。但当我开始起草测试时，我意识到更合理的做法是将它作为`VigenereCipher`类的辅助方法，这样它就可以访问`self.keyword`属性。这显示了测试驱动开发如何帮助设计更合理的 API。以下是方法的实现：

```py
    def extend_keyword(self, number):
        repeats = number // len(self.keyword) + 1
        return (self.keyword * repeats)[:number]
```

再次，这需要几次运行测试才能做对。我最终添加了一个修改后的测试副本，一个有十五个字母，一个有十六个字母，以确保它在整数除法有偶数的情况下也能工作。

现在我们终于准备好编写我们的`encode`方法了，如下所示：

```py
    def encode(self, plaintext): 
        cipher = [] 
        keyword = self.extend_keyword(len(plaintext)) 
        for p,k in zip(plaintext, keyword): 
            cipher.append(combine_character(p,k)) 
        return "".join(cipher) 
```

看起来正确。我们的测试套件现在应该通过了，对吗？

实际上，如果我们运行它，我们会发现仍然有两个测试失败。先前失败的编码测试实际上已经通过了，但我们完全忘记了空格和小写字符！幸好我们写了这些测试来提醒我们。我们将不得不在方法的开头添加以下行：

```py
        plaintext = plaintext.replace(" ", "").upper() 
```

如果我们在实现某些功能的过程中想到一个边界情况，我们可以创建一个描述该想法的测试。我们甚至不必实现测试；我们只需运行`assert False`来提醒我们以后再实现它。失败的测试永远不会让我们忘记边界情况，它不像问题跟踪器中的工单那样容易被忽视。如果花费一段时间来修复实现，我们可以将测试标记为预期失败。

现在所有的测试都通过了。这一章非常长，所以我们将压缩解码的示例。以下是一些测试：

```py
def test_separate_character(): 
    assert separate_character("X", "T") == "E" 
    assert separate_character("E", "R") == "N" 

def test_decode(): 
    cipher = VigenereCipher("TRAIN") 
    decoded = cipher.decode("XECWQXUIVCRKHWA") 
    assert decoded == "ENCODEDINPYTHON" 
```

以下是`separate_character`函数：

```py
def separate_character(cypher, keyword): 
    cypher = cypher.upper() 
    keyword = keyword.upper() 
    cypher_num = ord(cypher) - ord('A') 
    keyword_num = ord(keyword) - ord('A') 
    return chr(ord('A') + (cypher_num - keyword_num) % 26) 
```

现在我们可以添加`decode`方法：

```py
    def decode(self, ciphertext): 
        plain = [] 
        keyword = self.extend_keyword(len(ciphertext)) 
        for p,k in zip(ciphertext, keyword): 
            plain.append(separate_character(p,k)) 
        return "".join(plain) 
```

这些方法与编码所使用的方法非常相似。有了所有这些编写并通过的测试，我们现在可以回过头修改我们的代码，知道它仍然安全地通过测试。例如，如果我们用以下重构后的方法替换现有的`encode`和`decode`方法，我们的测试仍然通过：

```py
    def _code(self, text, combine_func): 
        text = text.replace(" ", "").upper() 
        combined = [] 
        keyword = self.extend_keyword(len(text)) 
        for p,k in zip(text, keyword): 
            combined.append(combine_func(p,k)) 
        return "".join(combined) 

    def encode(self, plaintext): 
        return self._code(plaintext, combine_character) 

    def decode(self, ciphertext): 
        return self._code(ciphertext, separate_character) 
```

这是测试驱动开发的最终好处，也是最重要的。一旦测试编写完成，我们可以尽情改进我们的代码，而且可以确信我们的更改没有破坏我们一直在测试的任何东西。此外，我们确切地知道我们的重构何时完成：当所有测试都通过时。

当然，我们的测试可能并不全面测试我们需要的一切；维护或代码重构仍然可能导致未经诊断的错误，这些错误在测试中不会显示出来。自动化测试并不是绝对可靠的。然而，如果出现错误，仍然可以按照测试驱动的计划进行，如下所示：

1.  编写一个测试（或多个测试），复制或*证明*出现的错误。当然，这将失败。

1.  然后编写代码使测试停止失败。如果测试全面，错误将被修复，我们将知道它是否再次发生，只要运行测试套件。

最后，我们可以尝试确定我们的测试在这段代码上的运行情况。安装了`pytest`覆盖插件后，`pytest -coverage-report=report`告诉我们，我们的测试套件覆盖了 100%的代码。这是一个很好的统计数据，但我们不应该对此过于自负。我们的代码在对包含数字的消息进行编码时还没有经过测试，因此其行为是未定义的。

# 练习

练习测试驱动开发。这是你的第一个练习。如果你开始一个新项目，这样做会更容易，但如果你有现有的代码需要处理，你可以通过为每个新功能编写测试来开始。随着你对自动化测试的热爱增加，这可能会变得令人沮丧。未经测试的旧代码将开始感觉僵化和紧密耦合，并且维护起来会变得不舒服；你会开始感觉自己的更改正在破坏代码，而你却无法知道，因为没有测试。但是如果你从小处开始，随着时间的推移，为代码库添加测试会改进它。

因此，要开始尝试测试驱动开发，可以开始一个全新的项目。一旦你开始意识到这些好处（你会的），并意识到编写测试所花费的时间很快就能以更易维护的代码来回报，你就会想要开始为现有代码编写测试。这就是你应该开始做的时候，而不是之前。为我们*知道*有效的代码编写测试是无聊的。在意识到我们认为有效的代码实际上有多破碎之前，很难对项目产生兴趣。

尝试使用内置的`unittest`模块和`pytest`编写相同的一组测试。您更喜欢哪个？`unittest`更类似于其他语言中的测试框架，而`pytest`可以说更符合 Python 的风格。两者都允许我们编写面向对象的测试，并轻松测试面向对象的程序。

在我们的案例研究中，我们使用了`pytest`，但我们没有涉及任何使用`unittest`不容易进行测试的功能。尝试调整测试以使用测试跳过或固定装置（`VignereCipher`的一个实例将会很有帮助）。尝试各种设置和拆卸方法，并将它们的使用与 funcargs 进行比较。哪种对您来说更自然？

尝试对您编写的测试运行覆盖报告。您是否错过了测试任何代码行？即使您有 100％的覆盖率，您是否测试了所有可能的输入？如果您正在进行测试驱动的开发，100％的覆盖率应该是很自然的，因为您会在满足该测试的代码之前编写测试。但是，如果为现有代码编写测试，很可能会有未经测试的边缘条件。

仔细考虑一下那些在某种程度上不同的值，例如：

+   当您期望完整列表时得到空列表

+   负数、零、一或无穷大与正整数相比

+   不能精确舍入到小数位的浮点数

+   当您期望数字时得到字符串

+   当您期望 ASCII 时得到 Unicode 字符串

+   当您期望有意义的东西时得到无处不在的`None`值

如果您的测试涵盖了这些边缘情况，您的代码将会很完善。

# 总结

我们最终涵盖了 Python 编程中最重要的主题：自动化测试。测试驱动开发被认为是最佳实践。标准库`unittest`模块提供了一个出色的开箱即用的测试解决方案，而`pytest`框架具有一些更符合 Python 风格的语法。模拟可以用于在我们的测试中模拟复杂的类。代码覆盖率给我们一个估计，我们的代码有多少被我们的测试运行，但它并不告诉我们我们已经测试了正确的东西。

感谢阅读《Python 入门指南》。我希望您享受了这段旅程，并渴望开始在未来的所有项目中实现面向对象的软件！
