# 通过构建游戏学习 Python（四）

> 原文：[`zh.annas-archive.org/md5/8d68d722c94aedcc91006ddf3f78c65a`](https://zh.annas-archive.org/md5/8d68d722c94aedcc91006ddf3f78c65a)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：使用 Pygame 超越 Turtle - 使用 Pygame 制作贪吃蛇游戏 UI

Python 游戏开发在某种程度上与`pygame`模块相关。到目前为止，我们已经学习了关于 Python 的各种主题和技术，因为在我们进入`pygame`模块之前，我们必须了解它们。所有这些概念将被用作构建 Pygame 游戏时的技术。我们现在可以开始使用面向对象的原则，矢量化移动进行事件处理，旋转技术来旋转游戏中使用的图像或精灵，甚至使用我们在 turtle 模块中学到的东西。在 turtle 模块中，我们学习了如何创建对象（参见第六章，*面向对象编程*），这些对象可以用于在我们可能使用 Pygame 构建的游戏的基本阶段调试不同的功能。因此，我们迄今为止学到的东西将与 Pygame 模块的其他功能一起使用，这些功能可以帮助我们制作更吸引人的游戏。

在本章中，我们将涵盖多个内容，从学习 Pygame 的基础知识——安装、构建模块和不同功能开始。之后，我们将学习 Pygame 的不同对象。它们是可以用于多种功能的模块，例如将形状绘制到屏幕上，处理鼠标和键盘事件，将图像加载到 Pygame 项目中等等。在本章的最后，我们将尝试通过添加多个功能使我们的贪吃蛇游戏在视觉上更具吸引力，例如自定义的贪吃蛇图像、苹果作为食物以及游戏的菜单屏幕。最后，我们将把我们的贪吃蛇游戏转换为可执行文件，以便您可以将游戏与朋友和家人分享，并从他们那里获得反馈。本章将涵盖以下主题：

+   Pygame 基础知识

+   Pygame 对象

+   初始化显示和处理事件

+   对象渲染——制作贪吃蛇游戏

+   游戏菜单

+   转换为可执行文件

+   游戏测试和可能的修改

# 技术要求

您需要以下要求才能完成本章：

+   Python—3.5 或更高版本

+   PyCharm IDE——参考第一章，*了解 Python-设置 Python 和编辑器*，了解下载过程

本章的文件可以在[`github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter11`](https://github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter11)找到。

查看以下视频，以查看代码的运行情况：

[`bit.ly/2o2GngQ`](http://bit.ly/2o2GngQ)

# 理解 pygame

使用`pygame`模块编写游戏需要在您的计算机上安装 pygame。您可以通过访问官方 Pygame 库的网站（[www.pygame.org](http://www.pygame.org)）手动下载，或者使用终端并使用`pip install pygame`命令进行安装。

Pygame 模块可以免费从上述网站下载，因此我们可以按照与下载其他 Python 模块相似的过程进行下载。但是，我们可以通过使用视觉上更具吸引力和有效的替代 IDE **PyCharm** 来消除手动下载 pygame 的麻烦，我们在第一章，*了解 Python-设置 Python 和编辑器*中下载了 PyCharm。在该章节中，我们熟悉了在 PyCharm 中下载和安装第三方包的技术。

一旦您将 pygame 包下载到 PyCharm 中，请给它一些时间来加载。现在，我们可以通过编写以下代码来测试它。以下两行代码检查`pygame`模块是否已下载，如果已下载，它将打印其版本：

```py
import pygame
print(pygame.version.ver) #this command will check pygame version installed
print(pygame.version.vernum) #alternate command
```

如果 pygame 成功安装到您的计算机上，您将观察到以下输出。版本可能有所不同，但在撰写本书时，它是 1.9.6 版（2019 年最新版本）。本书的内容适用于任何版本的`pygame`，因为它具有向后兼容性。请确保您的 pygame 版本新于 1.9+：

```py
pygame 1.9.6
Hello from the pygame community. https://www.pygame.org/contribute.html
1.9.6
```

Pygame 对许多 Python 游戏开发者来说是一个乌托邦；它包含大量的模块，从制作界面到处理用户事件。pygame 中定义的所有这些模块都可以根据我们的需求独立使用。最重要的是，您也可以使用 pygame 制作游戏，这可能是平台特定的，也可能不是。调用 pygame 的模块类似于调用类的方法。您可以始终使用 pygame 命名空间访问这些类，然后使用您想要使用的类。例如，`pygame.key`将读取键盘上按下的键。因此，`key`类负责处理键盘操作。类似地，`pygame.mouse`模块用于管理鼠标事件。pygame 的这些以及许多其他模块都可以相互独立地调用，这使得我们的代码更易于管理和阅读。您可以从 pygame 模块的官方文档页面搜索可用模块的列表，但几乎 80%的游戏只需要四到六个模块。如果您想了解更多信息，最好是探索其官方文档页面。在其中，我们在每个游戏中主要使用两个类，即显示模块，以便访问和操作游戏显示；以及鼠标和键盘或操纵杆模块，以处理游戏的输入事件。我不会说其他模块不重要，但这些模块是游戏的基石。以下表格摘自 Python pygame 官方文档；它给了我们关于`pygame`模块及其用法的简洁概念：

| **模块名称** | **描述** |
| --- | --- |
| `pygame.draw` | 绘制形状、线条和点。 |
| `pygame.event` | 处理外部事件。 |
| `pygame.font` | 处理系统字体。 |
| `pygame.image` | 将图像加载到项目中。 |
| `pygame.joystick` | 处理操纵杆移动/事件。 |
| `pygame.key` | 从键盘读取按键。 |
| `pygame.mixer` | 混音、加载和播放声音。 |
| `pygame.mouse` | 读取鼠标事件。 |
| `pygame.movie` | 播放/运行电影文件。 |
| `pygame.music` | 播放流式音频文件。 |
| `pygame` | 捆绑为高级 pygame 函数/方法。 |
| `pygame.rect` | 处理矩形区域并可以创建一个框结构。 |

此外还有一些其他模块，比如 surface、time 和 transform。我们将在本章和接下来的章节中探讨它们。所有前述的模块都是平台无关的，这意味着它们可以被调用，无论机器使用的操作系统是什么。但是会有一些特定于操作系统的错误，以及由于硬件不兼容或不正确的设备驱动程序而导致的错误。如果任何模块与任何机器不兼容，Python 解析器将其返回为`None`，这意味着我们可以事先检查以确保游戏正常工作。以下代码将检查是否存在任何指定的模块（`pygame.module_name`），如果没有，它将在打印语句中返回一个自定义消息，本例中是“没有这样的模块！尝试其他”：

```py
if pygame.overlay is None:
    print("No such module! Try other one")
    print("https://www.pygame.org/contribute.html")
    exit()
```

要完全掌握`pygame`的概念，我们必须养成观察其他 pygame 开发者编写的代码的习惯。通过这样做，您将学习使用`pygame`构建游戏的模式。如果像我一样，只有在陷入僵局时才查看文档，那么我们可以编写一个简单的程序来帮助我们理解`pygame`的概念以及我们可以调用其不同模块的方式。我们将编写一个简单的代码来说明这一点：

```py
import pygame as p #abbreviating pygame with p

p.init()
screen = p.display.set_mode((400, 350)) #size of screen
finish = False   while not finish:
    for each_event in p.event.get():
        if each_event.type == p.QUIT:
            finish = True
  p.draw.rect(screen, (0, 128, 0), p.Rect(35, 35, 65, 65))
    p.display.flip()
```

在讨论上述代码之前，让我们运行它并观察输出。您将得到一个几何形状—一个绿色的矩形框，它将呈现在特定高度和宽度的屏幕内。现在，是时候快速地记下`pygame`模块的构建块了。为了简化事情，我已经在以下几点中列出了它们：

+   `import pygame`: 这是我们从本书开始就熟悉的导入语句。这次，我们将 pygame 框架导入到我们的 Python 文件中。

+   `pygame.init()`: 这个方法将初始化 pygame 内嵌的一系列模块/类。这意味着我们可以使用 pygame 的命名空间调用其他模块。

+   `pygame.display.set_mode((width, height))`: 作为元组(width, height)传递的大小是期望的屏幕大小。这个大小代表我们的游戏控制台。返回的对象将是一个窗口屏幕，或者表面，我们将在其中执行不同的图形计算。

+   `pygame.event.get()`: 这个语句将处理事件队列。正如我们在前几章中讨论的那样，队列将存储用户的不同事件。如果不显式调用此语句，游戏将受到压倒性的 Windows 消息的阻碍，最终将变得无响应。

+   `pygame.draw.rect()`: 我们将能够使用绘图模块在屏幕上绘制。不同的形状可以使用此模块绘制。关于这一点，我们将在下一节—*Pygame 对象*中进行更多讨论。`rect()`方法以屏幕对象、颜色和位置作为参数，绘制一个矩形。第一个参数代表屏幕对象，它是显示类的返回对象；第二个是颜色代码，以 RGB(red, green, blue)代码的形式作为元组传递；第三个是矩形的尺寸。为了操纵和存储矩形区域，pygame 使用`Rect`对象。`Rect()`可以通过组合四个不同的值—高度、宽度、左侧和顶部来创建。

+   `pygame.QUIT`: 每当您明确关闭 pygame 屏幕时，就会调用此事件，这是通过按游戏控制台最右上角的`close(X)`按钮来完成的。

+   `pygame.display.flip()`: 这与`update()`函数相同，可以使屏幕上的任何新更新可见。在制作或 blitting 形状或字符时，必须在游戏结束时调用此方法，以确保所有对象都被正确渲染。这将交换 pygame 缓冲区，因为 pygame 是一个双缓冲框架。

上述代码在执行时呈现绿色矩形形状。正如我们之前提到的，`rect()`方法负责创建矩形区域，颜色代码(0, 128, 0)代表绿色。

不要被这些术语所压倒；您将在接下来的章节中详细了解它们。在阅读本章时，请确保养成一个习惯，即在代码之间建立逻辑连接：从一个位置映射游戏到另一个位置，也就是显示屏，渲染字符，处理事件。

如果您遇到无法关闭 pygame 终端的情况，那肯定是因为您没有正确处理事件队列。在这种情况下，您可以通过按下*Ctrl* + *C*来停止终端中的 Python。

在跳转到下一节之前，我想讨论一下命令的简单但深奥的工作—pygame 初始化—这是通过`pygame.init()`语句完成的。这只是一条简单的命令，但它执行的任务比我们想象的要多。顾名思义，这是 pygame 的初始化。因此，它必须初始化`pygame`包的每个子模块，即`display`、`rect`、`key`等。不仅如此，它还将加载所有必要的驱动程序和硬件组件的查询，以便进行通信。

如果您想更快地加载任何子模块，可以显式初始化特定的子模块，并避免所有不必要的子模块。例如，`pygame.music.init()`将只初始化 pygame 维护的子模块中的音乐子模块。对于本书中将要涵盖的大多数游戏，`pygame`模块需要超过三个子模块。因此，我们可以使用通用的`pygame.init()`方法来执行初始化。在进行了上述调用之后，我们将能够使用`pygame`模块的所有指定子模块。

初始化过程之后，开始创建显示屏是一个良好的实践。显示屏的尺寸取决于游戏的需求。有时，您可能需要为游戏提供全屏分辨率，以使其完全互动和吸引人。可以通过 pygame 表面对象来操作屏幕大小。在显示类上调用`set_mode`方法将返回表示整个窗口屏幕的对象。如果需要，还可以为显示屏设置标题；标题将添加到顶部导航栏中，与关闭按钮一起。以下代码表示了向游戏屏幕添加标题或游戏名称的方法：

```py
pygame.display.set_caption("My First Game")
```

现在，让我们谈谈传递给`set_mode`方法的参数。第一个——也是最重要的——参数是屏幕表面的尺寸。尺寸应该以元组的形式传递，即宽度和高度，这是强制性的。其他参数是可选的（在之前的程序中，我们甚至都没有使用它们）；它们被称为标志。我们需要它们是因为与宽度和高度相关的信息有时不足以进行适当的显示。

我们可能希望有**全屏**或**可调整大小**的显示，在这种情况下，标志可能更适合于显示创建。说到标志，它是一个可以根据情况打开和关闭的功能，有时候使用它可能会节省时间，相对而言。让我们来看一下下表中的一些标志，尽管我们不会很快使用它们，但在这里介绍它们可以避免在即将到来的部分中不必要的介绍：

| **标志** | **目的** |
| --- | --- |
| `FULLSCREEN` | 创建覆盖整个屏幕的显示。建议用于调试的窗口化屏幕。 |
| `DOUBLEBUF` | 用于创建*双缓冲*显示。强烈建议用于`HWSURFACE`或`OPENGL`，它模拟了 3D 显示。 |
| `HWSURFACE` | 用于创建硬件加速的显示，即使用视频卡内存而不是主内存（必须与`FULLSCREEN`标志结合使用）。 |
| `RESIZABLE` | 创建可调整大小的显示。 |
| `NOFRAME` | 无边框或边框的显示，也没有标题栏。 |
| `OPENGL` | 创建可渲染的 OpenGL 显示。 |

您可以使用按位或运算符将多个标志组合在一起，这有助于在屏幕表面方面获得更好的体验。为了创建一个双缓冲的 OpenGL 渲染显示，您可以将可选的标志参数设置为`DOUBLEBUF|OPENGL;`这里，(`|`)是按位`OR`运算符。即使 pygame 无法渲染我们要求的完美显示，这可能是由于缺乏适当的显卡，pygame 将为我们在选择与我们的硬件兼容的显示方面做出决定。

游戏开发中最重要的一个方面是处理用户事件，通常是在游戏循环内完成的。在主游戏循环内，通常有另一个循环来处理用户事件——事件循环。事件是一系列消息，通知 pygame 在代码外部可以期待什么。事件可能是用户按键事件，也可能是通过第三方库传输的任何信息，例如互联网。

作为一组创建的事件被存储在队列中，并保留在那里，直到我们明确地处理它们。虽然在 pygame 的事件模块中有不同的函数提供了捕获事件的方法，`get()`是最可靠的，也很容易使用。在获取了各种操作后，我们可以使用 pygame 事件处理程序来处理它们，使用`pump`或`get`等函数。请记住，如果您只处理特定的操作，事件队列可能会混入其他您不感兴趣的表面事件。因此，必须明确地使用事件属性来处理事件，类似于我们在前面的示例中使用`QUIT`事件属性所做的。您还可以通过`eventType.__dict__`属性完全访问事件对象的属性。我们将在即将到来的*事件处理*部分中彻底学习它们。

在学习如何使用 pygame 升级我们之前制作的*snake*游戏之前，我们必须学习 pygame 的一些重要概念——*Pygame 对象*、*绘制到屏幕*和*处理用户事件*。我们将逐一详细学习这些概念。我们将从*Pygame 对象*开始，学习表面对象、创建表面和矩形对象。我们还将学习如何使用 pygame 绘制形状。

# Pygame 对象

由内部使用类制作的`pygame`模块通过允许我们创建对象并使用它们的属性，使代码可读性和可重用性。正如我们之前提到的，`pygame`模块中定义了几个类，可以独立调用以执行独立的任务。例如，`draw`类可用于绘制不同的形状，如矩形、多边形、圆形等；`event`类可以调用`get`或`pump`等函数来处理用户事件。可以通过创建对象来进行这些调用，首先为每个操作创建对象。在本节中，您将探索这些概念，这将帮助您学习如何访问表面对象、矩形对象和绘制到屏幕。

创建自定义尺寸的空白表面最基本的方法是从 pygame 命名空间调用`Surface`构造函数。在创建`Surface`类的对象时，必须传递包含宽度和高度信息的元组。以下代码行创建了一个 200x200 像素的空白表面：

```py
screen_surface = pygame.Surface((200,200))
```

我们可以指定一些可选参数，最终会影响屏幕的视觉效果。您可以将标志参数设置为以下一个或多个参数之一：

+   `HWSURFACE`：创建硬件表面。在游戏的上下文中这并不是很重要，因为它是由 pygame 内部完成的。

+   `SRCALPHA`：它使用*alpha 信息*来转换背景，这是指使屏幕背景透明的过程。它创建一个带有 alpha 转换的表面。alpha 信息将使表面的一部分变为透明。如果您将其用作可选标志，您必须指定一个以上的强制参数，包括深度，并将其值分配为 32，这是 alpha 信息的标准值。

此外，如果您想创建一个包含图像作为背景的表面，可以从`pygame`模块中调用`image`类。image 类包含`load`方法，可以使用需要呈现的背景图像文件名作为参数进行调用。传递的文件名应该是完整的名称，带有其原始扩展名：

```py
background_surface = pygame.image.load(image_file_name.extension).convert()
```

从`image`类调用的 load 函数会从您的计算机中读取图像文件，然后返回包含图像的表面。在这里，屏幕尺寸将由图像大小确定。`Surface`对象的`convert()`成员函数将把指定的图像转换为显示屏支持的格式。

现在，让我们学习如何在单个表面内创建多个表面，通常称为子表面。

# 子表面

顾名思义，子表面是单个主表面内的嵌套表面列表。主表面可以被称为父表面。父表面可以使用`Surface`构造函数、`set_mode`或图像创建。当你在子表面上绘制时，它也会绘制在父表面上，因为子表面也是父表面的一部分。创建子表面很容易；你只需要从`Surface`对象调用`subsurface`方法，并且传递的参数应该指示要覆盖的`parent`类的位置。通常传递的坐标应该在父屏幕内创建一个小矩形。下面的代码显示了如何创建一个子表面：

```py
screen = Pygame.load("image.png")
screen.subsurface((0,0),(20,20))
screen.subsurface((20,0),(20,20))
```

你可以将这些子表面存储到数据结构中，比如字典，这样你就可以轻松地引用它们。你可以观察到传递给子表面方法的位置——它们与其他位置不同。点（0，0）总是表示子表面从父屏幕的左上角开始。

子表面有几种可用的方法，你可以从官方文档中了解到所有这些方法。其中最有用的方法之一是`get_parent()`，它返回子表面的父表面。如果没有使用`get_parent`方法调用任何子表面，它将返回`None`。

现在，我们将学习关于表面对象的下一个方法，这是在使用 pygame 制作任何游戏时经常使用的`blit`，它代表**位块传输**。

# `blit`你的对象

虽然术语*blitting*可能没有在牛津词典中定义，但在使用 pygame 制作游戏时具有更大的意义。`blit`通常被称为位边界块传输，或块信息传输，是一种将图像从一个表面复制到另一个表面的方法，通常是通过裁剪或移动。假设你有`Surfaceb`（你的屏幕），你想在屏幕上绘制一个形状，比如一个矩形。所以，你需要做的是绘制一个矩形，然后将缓冲区的矩形块传输到屏幕缓冲区。这个过程叫做*blitting*。当我们使用 pygame 制作游戏时，你会发现它被用来绘制背景、字体、角色，以及你能想象到的一切。

为了`blit`表面，你可以从结果表面对象（通常是显示对象）调用`blit`方法。你必须传递你的源表面，比如角色、动画和图像，以及要`blit`的坐标作为参数。与理论上听起来的相比，调用`blit`方法相当简单。下面的代码显示了如何在指定位置（0,0）`blit`背景图像，即屏幕的左上角：

```py
screen.blit(image_file_name.png, (0,0))
```

假设你有一组需要根据不同帧率渲染的图像。我们也可以使用`blit`方法来做到这一点。我们可以改变帧数的值，并在结果屏幕的不同区域`blit`图像，以制作图像的动画。这通常是在静态图像的情况下完成的。例如，我们将在下一章中使用 Pygame 创建 flappy bird 游戏的克隆。

在那个游戏中，我们需要在不同的位置（通常称为精灵）上`blit`管道和小鸟（flappy 游戏的角色）的静态图像。这些精灵只是可以直接从互联网使用的图像，或者根据我们的需要自己制作的图像。以下代码展示了一种根据不同帧率`blit`图像的简单方法：

```py
screen.blit(list_of_images, (400, 300), (frame_number*10, 0, 100, 100))
```

在 Flappy Bird 游戏中，一个图像列表包含了鸟在飞行和下落两种姿势的图像。根据用户事件，我们将使用`blit`方法渲染它们。

在跳转到下一节之前，让我们了解一下可能微不足道但必须了解的*帧率*主题。这个术语经常被用作衡量游戏性能的基准。视频游戏中的帧率意味着你在屏幕上观察到的图像刷新或获取的次数。帧率是以**每秒帧数**或**FPS**（不要与**第一人称射击**混淆）来衡量的。

决定游戏帧率的因素有很多，但当代游戏玩家希望的是没有任何滞后或游戏运行缓慢。因此，更高的帧率总是更好。低帧率可能会在不合适的时候产生不幸的情况。一个例子可能是在用户能够跳跃或从一定高度跌落的游戏中；低帧率会导致系统滞后，并经常使屏幕*冻结*，使用户无法与游戏进行交互。许多现代游戏，例如第一人称射击游戏，如绝地求生和堡垒之夜，都是以达到大约 60 帧每秒的帧率为目标开发的。但在 Pygame 开发的简单游戏中，15 到 30 帧每秒之间被认为是可以接受的。一些批评者认为 30 帧每秒以下会产生断断续续的动画和不真实的运动，但正如我们所知，pygame 允许我们创建大多数迷你游戏。因此，15 到 30 帧每秒之间对我们来说是足够的。

让我们进入下一节，我们将学习如何使用`pygame`绘制不同的形状。

# 使用 pygame 绘制模块进行绘制

最常用的模块之一是`draw`，它声明了许多方法，可以用来在游戏屏幕上绘制形状。使用此模块的目的是绘制线条、圆形和多边形，事实上，任何几何形状。你可能会想知道使用它的重要性——它有广泛的用途。我们可能需要创建形状以执行裁剪，或者将精灵或图像渲染到屏幕上。有时，您可能希望将这些形状用作游戏中的角色；像俄罗斯方块这样的游戏就是一个完美的例子。即使在创建游戏时您可能不会发现它非常有用，而是会使用精灵，但在测试游戏动画时可能会有所帮助。您不必去任何地方了解这些形状在游戏开发中的重要性；您可以观察到我们迄今为止创建的游戏。直到现在，在贪吃蛇游戏中，我们一直在使用简单的矩形形状来表示蛇的身体和头部。虽然这可能并不十分吸引人，在游戏的初期阶段，我们总是可以使用这样的形状来制作游戏。

使用 pygame 创建这样的形状比使用任何其他模块都要容易。我们可以调用绘制模块，以及函数名称。函数名称将是您想要绘制的形状的名称。例如，对于一个圆，我们将使用`pygame.draw.circle()`，对于一个矩形，我们将使用：`pygame.draw.rect()`。`pygame.draw`中函数的前两个参数是要绘制的表面，后面是要用来绘制的颜色。绘制函数的第一个参数是`Surface`对象，表示要在其上绘制的屏幕。下一个参数表示要在其上绘制形状的屏幕位置。

这三个参数对于每个几何形状都是强制性的，但最后一个取决于形状。该方法的最后一个参数表示在绘制这些形状时使用的数学量，例如圆的半径或直径。通常，传递的第三个参数应该表示坐标位置，以*x*和*y*坐标的形式，其中点（0, 0）表示屏幕左上角的位置。下表列出了在绘制模块中可用的方法数量，这些方法可用于绘制任何几何形状：

| **函数** | **描述** |
| --- | --- |
| `rect` | 绘制矩形 |
| `polygon` | 绘制正多边形（具有三个或更多封闭边的几何形状） |
| `line` | 绘制线条 |
| `lines` | 绘制多条线 |
| `circle` | 绘制圆 |
| `ellipse` | 绘制椭圆 |

举个例子，让我们使用`circle`方法并观察`pygame`绘图模块的运行情况。我们需要知道半径的值才能画一个圆。半径是从圆的中心到圆的边缘的距离，也就是圆的弧长。调用圆函数时应传递的参数是屏幕，代表表面对象；圆的颜色；圆应该被绘制的位置；最后是圆的半径。由于我们使用随机模块生成圆的半径的随机值，而不是给定特定值，以下代码创建了多个圆，具有随机宽度和随机位置，并且使用随机颜色。如果为每个参数输入特定值，将会绘制一个形状：

```py
import pygame as game
from pygame.locals import *
from random import *
import sys

game.init()
display_screen = game.display.set_mode((650, 470), 0, 32)
while True:
    for eachEvent in game.event.get():
        if eachEvent.type == QUIT:
            sys.exit()
    circle_generate_color = (randint(0,255), randint(0,255), 
                            randint(0,255))
 circle_position_arbitary = (randint(0,649), randint(0,469))
 circle_radius_arbitary = randint(1,230)
    game.draw.circle(display_screen, circle_generate_color, 
    circle_position_arbitary, circle_radius_arbitary)
    game.display.update()
```

从本章开始编写的代码在 PyCharm Community IDE 中，该 IDE 是在第一章中下载的，*了解 Python-设置 Python 和编辑器*。确保`pygame`安装在解释器的主目录上，以便在任何新创建的 Python 文件上都可以通用地使用`pygame`。

在使用 PyCharm IDE 时可以注意到的一个重要特性是，它可以为我们提供有关安装`pygame`模块的所有模块的信息。要确定`draw`模块中存在哪些函数，选择代码中的`circle`或`draw`关键字，然后在键盘上按*Ctrl* + *B*，这将将您重定向到`draw`模块的声明文件。

在谈论代码时，很容易理解。主要的三行代码被突出显示，以便您可以直接观察它们的重要性。大多数情况下，第三行调用`circle`方法，声明在`draw`模块中，它接受参数，屏幕对象，颜色，位置和半径以绘制一个圆。前面程序的输出将不断打印具有随机半径和随机颜色的圆，直到用户手动关闭屏幕，这是由于事件处理程序完成的，由`pygame.event.get`方法完成。

同样，您可以绘制许多形状和大小的多边形，范围可以从三边形到 9999 边形。就像我们使用`pygame.draw.circle`函数创建圆形一样，我们可以使用`pygame.draw.polygon`来绘制任何类型的多边形。对多边形函数的调用以点列表的形式作为参数，并将使用这些点绘制多边形形状。我们可以使用类似的方式使用特定的称谓绘制不同的几何形状。

在接下来的部分中，我们将学习使用`pygame`模块初始化显示屏和处理键盘和鼠标事件的不同方法。

# 初始化显示屏和处理事件

游戏开发人员主要将专注于如何使玩家感到参与其中，使游戏更具互动性。在这种情况下，必须将两个方面紧密联系在一起，即视觉上吸引人的显示和处理玩家的事件。我们不希望玩家被糟糕的显示屏和游戏运动中的滞后所压倒。在本节中，我们将讨论开发人员在制作游戏时必须考虑的两个主要方面：通过适应可用的可选参数来初始化显示的不同方式，以及处理用户操作事件，例如按下键盘键或鼠标按钮时。您想要创建的显示类型取决于您计划开发的游戏类型。

在使用`pygame`模块制作游戏时，您必须记住的一件事是，向游戏添加更多操作将影响游戏的流畅性，这意味着如果您向游戏中添加多个功能，游戏的互动性就会越来越差。因此，我们将主要专注于使用`pygame`模块制作迷你游戏。市场上还有更先进的 Python 模块可用于制作高功能游戏，我们将在接下来的章节中探讨它们。目前，我们将看到如何初始化显示，这是通过选择较低的分辨率来完成的，因为我们不希望游戏以任何方式滞后。

从现在开始制作的任何游戏都将具有固定和低分辨率，但您可以通过让用户选择自定义显示来进行实验。以下代码是创建 pygame 窗口的简单方法，我们之前编写的代码中也见过：

```py
displayScreen = pygame.display.set_mode((640, 480), 0, 32) #standard size
```

`set_mode()`的第一个参数将是屏幕的尺寸。元组中的值（640, 480）表示屏幕的高度和宽度。这个尺寸值将创建一个小窗口，与大多数桌面屏幕兼容。然而，我们可能会遇到一个情况，即游戏必须具有`FULLSCREEN`，而不是小屏幕。在这种情况下，我们可以使用一个可选参数，给出`FULLSCREEN`的值。显示全屏的代码看起来像这样：

```py
displayScreen = pygame.display.set_mode((640, 480), FULLSCREEN, 32)
```

然而，我们可能会观察到使用全屏模式与自定义显示之间的性能差异。在全屏模式下打开游戏将运行得更快，因为它不会与其他后台桌面屏幕进行交互，而另一个屏幕，具有自定义显示，可能会与您的机器上运行的其他显示屏合并。除此之外，在小屏幕上调试游戏比全屏游戏更容易，因为您应该考虑在全屏模式下关闭游戏的替代方法，因为关闭按钮将不可见。要检查 PC 支持的不同显示分辨率，您可以调用`list_modes()`方法，它将返回包含分辨率列表的元组，看起来像这样：

```py
>>> import pygame as p
>>> p.init()
>>> print(p.display.list_modes())
[(1366, 768), (1360, 768), (1280, 768), (1280, 720), (1280, 600), (1024, 768), (800, 600), (640, 480), (640, 400), (512, 384), (400, 300), (320, 240), (320, 200)]
```

有时，您可能会感到屏幕上显示的图像质量略有下降。这主要是由于显卡功能较少，无法提供您请求的图像颜色。这由`pygame`进行补偿，它将图像转换为适合您设备的图像。

在某些游戏中，您可能希望用户决定选择显示屏的大小。权衡的问题在于玩家选择高质量视觉还是使游戏运行顺畅。我们的主要目标将是处理事件，可以在可调整大小的屏幕和全屏之间切换。以下代码说明了在窗口化屏幕和全屏之间切换的方法。当用户在键盘上按下*F*时，它将在屏幕之间切换。

当你运行程序时，窗口屏幕和全屏之间的切换过程并不是即时的。这是因为`pygame`需要一些时间来检查显卡的特性，如果显卡不够强大，它会自行处理图像的质量：

```py
import pygame as p #abbreviating pygame module as p
from pygame.locals import *
import sys
p.init()
displayScreen = p.display.set_mode((640, 480), 0, 32)

displayFullscreen = False while True:
    for Each_event in p.event.get():
        if Each_event.type == QUIT:
            sys.exit()
        if Each_event.type == KEYDOWN:
            if Each_event.key == K_f:
                    displayFullscreen = not displayFullscreen
                    if displayFullscreen:
                        displayScreen = p.display.set_mode((640, 480), 
                                        FULLSCREEN, 32)
                    else:
                        displayScreen = p.display.set_mode((640, 480), 0, 32)

    p.display.update()
```

让我们逐行学习显示切换的过程：

1.  你必须从`pygame`模块开始导入。第二个导入语句将导入 Pygame 使用的常量。然而，它的内容会自动放置在`pygame`模块的命名空间中，我们可以使用`pygame.locals`来仅包含`pygame`常量。常量的例子包括：KEYDOWN，键盘`k_constants`等。

1.  你将在游戏开始时设置默认的显示模式。这个显示将是默认显示，每当你第一次运行程序时，当前定制的显示将被渲染。我们默认传递了一个(640, 480)的显示屏。

1.  要切换显示屏，你必须创建一个布尔变量`Fullscreen`，它将是`True`或`False`，基于这一点，我们将设置屏幕的模式。

1.  在主循环中，你必须处理键盘按键动作的事件。每当用户在键盘上按下*F*键时，我们将改变布尔变量的值，如果`FULLSCREEN`变量的值为`True`，我们必须将显示切换到全屏模式。额外的标志`FULLSCREEN`作为第二个参数添加到`add_mode()`函数中，深度为 32。

1.  在 else 部分，如果全屏的值为`False`，你必须以窗口版本显示屏幕。相同的键*F*用于在窗口和全屏之间切换屏幕。

现在我们已经学会了如何使用不同的可用标志修改窗口可视化效果，让我们进入下一部分，我们将讨论接受用户输入和控制游戏，这通常被称为*处理用户事件*。

# 处理用户事件

在传统的 PC 游戏中，我们通常看到玩家只使用键盘来玩游戏。即使在今天，大多数游戏仍然完全依赖于键盘操作。随着游戏行业的发展，我们可以从多种输入设备接受用户输入，如鼠标和操纵杆。通常，鼠标用于处理动作，它可以给游戏画面提供全景视图。如果你玩过反恐精英或任何第一人称射击游戏，鼠标允许玩家在多个角度旋转视角，而键盘操作则处理玩家的移动，如向左移动、向右移动、跳跃等。键盘通常用于触发射击和躲避等动作，因为它的操作就像一个开关。开关只有两种可能性：打开或关闭；键盘按键也只有按下或未按下，这概括了处理键盘操作的技术。在典型的 19 世纪游戏中，我们曾经通过检查键盘的操作来生成游戏敌人。当用户不断按下键盘按键时，我们会生成更多的敌人。

鼠标和键盘这两种输入设备的组合非常适合这些游戏，因为鼠标能够处理方向运动，并且以平滑的方式进行操作。例如，当你玩第一人称射击游戏时，你可以使用键盘和鼠标来旋转玩家。当有敌人在你身后时，通常会使用鼠标快速旋转到那个位置，而不是使用键盘来旋转。

为了检测和监听所有的键盘按键，你必须使用`pygame.key`模块。这个模块能够检测任何键是否被按下，甚至支持方向运动。这个模块还能够处理任何键盘动作。基本上，有两种处理 pygame 中按键的方法：

+   通过处理按键按下事件，当键盘上的键被按下时触发。

+   通过处理键盘上释放键时触发的 KEYUP 事件。

虽然这些事件处理程序是检查按键的一个很好的方法，但处理键盘输入以进行移动并不适合它们。我们需要事先知道键盘键是否被按下，以便绘制下一帧。因此，直接使用`pygame.key`模块将使我们能够有效地处理键盘键。键盘的键（a-z，0-9 和 F1-F12）具有由 pygame 预定义的键常量。这些键常量可以被称为键码，用于唯一标识它们。键码总是以`K_`开头。对于每个可能的键，键码看起来像（`K_a`到`K_z`），（`K_0`到`K_9`），并包含其他常量，如`K_SPACE`，`K_LEFT`和`K_RETURN`。由于硬件不兼容性，pygame 无法处理一些键盘键。这个异常在网上由几位开发者讨论过。你可能需要参考他们以更详细地了解这一点。

处理任何键盘动作的最基本方法是使用`pygame.key get_pressed`函数。这个方法非常强大，因为它为所有键盘常量分配布尔值，要么是`True`，要么是`False`。我们可以通过使用`if`条件来检查：键盘常量的值是`True`还是`False`？如果是`True`，显然是有键被按下了。`get_pressed`方法调用返回一个键常量的字典，字典的键是键盘的键常量，字典的值是布尔值，`dictionary_name[K_a] = True`。假设你正在制作一个程序，它将使用*up*作为跳跃按钮。你需要编写以下代码：

```py
import pygame as p
any_key_pressed = p.key.get_pressed()
if any_key_pressed[K_UP]:
    #UP key has been pressed
    jump()
```

让我们更详细地了解`pygame.key`模块。以下每个函数都将以不同的方式处理键盘键：

+   `pygame.key.get_pressed()`: 正如我们在前面的代码中看到的，这个方法返回一个包含键盘每个键的布尔值的字典。你必须检查键的值来确定它是否被按下。换句话说，如果键盘键的任何值被设置为`True`，则该索引的键被认为是被按下的。

+   `pygame.key.name()`: 正如其名称所示，这个方法调用将返回按下的键的名称。例如，如果我得到一个值为 115 的`KEY_UP`事件，你可以使用`key.name`来打印出这个键的名称，这种情况下是一个字符串，*s*。

+   `pygame.key.get_mods()`: 这将确定哪个修改键被按下。修改键是与*Shift*、*Alt*和*Ctrl*组合的普通键。为了检查是否有任何修改键被按下，你必须首先调用`get_mods`方法，然后跟着`K_MOD`。方法调用和常量之间用按位与运算符分隔，例如，`event.key == pygame.K_RIGHT`和`pygame.key.get_mods() & pygame`。`KMOD_LSHIFT`方法可用于检查左*Shift*键。

+   `pygame.key.set_mods()`: 你也可以临时设置修改键以观察修改键被按下的效果。要设置多个修改键，通常使用按位或运算符（|）将它们组合起来。例如，`pygame.key.set_mods(KMOD_SHIFT | KMOD_LSHIFT)`将设置 SHIFT 和 LEFT *Shift*修改键。

+   `pygame.key.get_focused()`: 要从键盘获取每个按下的键，显示必须专注于键盘操作。这个方法调用将通过检查显示是否正在从系统接收键盘输入来返回一个布尔值。在游戏中可能有一个自定义屏幕的情况下，游戏屏幕没有焦点，因为你可能在使用其他应用程序；这将返回`False`，这意味着显示不活跃或没有专注于监听键盘操作。但在全屏显示模式下，你将完全专注于单个屏幕，在这种情况下，这个方法将始终返回`True`。

还有一些 pygame 按键功能，比如`get_repeat`和`set_repeat`，它们在你想要在键盘上连续按住任意键时发生重复动作的情况下非常有用。例如，打开记事本并连续按下*s*键。你会看到字符`s`会被打印多次。这个功能可以使用`pygame.key set_repeat`函数嵌入。这个函数将接受两个参数：延迟和间隔，单位为毫秒。

第一个延迟值是按键重复之前的初始延迟，而下一个间隔值是重复按键之间的延迟。您可以使用`调用 set_repeat`方法并不带参数来禁用这些按键重复功能。默认情况下，当 pygame 被初始化时，按键重复功能是被禁用的。因此，您不需要手动禁用它。请访问以下网站以获取 pygame 官方文档，以了解更多关于 pygame 按键功能的信息：[`www.pygame.org/docs/ref/key.html`](https://www.pygame.org/docs/ref/key.html)。

您可以通过分配上、下、左或右键来使用键盘为游戏屏幕的精灵/图像/对象设置移动。直到现在，我们一直在使用不同的模块，如 Python turtle 和 curses 来做到这一点。然而，我们无法处理静态精灵或图像的移动。我们只处理了上、下、左、右和几何对象的按键事件，但现在 pygame 允许我们使用更复杂的图形并相应地处理它们。

我们可以分配任何键盘键来执行方向移动，但按照传统方法，我们可以适当地将光标键或箭头键分配为它们在键盘上的位置完美，这样玩家可以轻松游戏。但在一些复杂的多人游戏中，比如第一人称射击游戏，*A*、*W*、*S*和*D*键被分配用于方向移动。现在，你可能想知道为了使任何箭头键以这样的方式行为，可以用于方向移动，你需要做什么。只需回想一下向量的力量：这是一个数学概念，无论你使用什么语言或模块，都对游戏开发有用。移动任何几何形状和图像的技术是相同的；我们需要创建一个指向我们可能想要前进的方向的向量。表示游戏角色的位置非常简单：你可以用 2D 坐标(*x*, *y*)表示它，用 3D 坐标(*x*, *y*, *z*)表示它。然而，方向向量是必须添加到当前向量位置的单位量，以便转到下一帧。例如，通过按下键盘上的下键，我们必须向下移动，*x*位置不变，但*y*坐标增加一个单位。下表解释了四个方向的方向移动：

| **位置** | **方向向量** |
| --- | --- |
| 上 | (0, -1) |
| 下 | (0, 1) |
| 左 | (-1, 0) |
| 右 | (1, 0) |

我们可能还希望玩家允许对角线移动，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/8a263cf7-95c9-4277-ad7c-2dfd24d02cd3.png)

上面的插图代表了上和右键盘键的矢量运动。假设在游戏开始时，玩家位于位置(0, 0)，这意味着他们位于中心。现在，当用户按上（箭头键）键盘键时，将(0, 0)与上方向矢量(0, -1)相加，得到的矢量将是玩家的新位置。对角线移动（两个键的组合，这种情况下是上和右）将在玩家当前矢量位置上增加(0.707, -0.707)。我们可以使用这种矢量运动技术来为任何游戏对象提供方向运动，无论是精灵/静态图像还是几何形状。以下代码代表了使用 pygame 事件处理技术的矢量运动：

```py
import pygame as p
import sys
while True:
    for anyEvent in p.event.get():
        if anyEvent.type == QUIT:
            sys.exit()
        any_keys_pressed = p.key.get_pressed()
        movement_keys = Vector2(0, 0) #Vector2 imported from gameobjects
        #movement keys are diectional (arrow) keys
        if any_keys_pressed[K_LEFT]:
            movement_keys.x = –1
  elif any_keys_pressed[K_RIGHT]:
            movement_keys.x = +1
  if any_keys_pressed[K_UP]:
            movement_keys.y = -1
  elif any_keys_pressed[K_DOWN]:
            movement_keys.y = +1
  movement_keys.normalize() #creates list comprehension 
                                   [refer chapter 7]
```

尽管了解如何使物体在八个方向移动（四个基本方向和四个对角线移动）是值得的，但使用所有八个方向不会使游戏更加流畅。在假设中，使物体朝八个方向移动有点不自然。然而，现在的游戏允许玩家以 360 度的方式观察视图。因此，为了制作具有这种功能的游戏，我们可以使用键进行旋转运动，而不是使用八个键动作。为了计算旋转后的矢量，我们必须使用数学模块计算角度的正弦和余弦。角度的正弦负责*x*分量的运动，而余弦负责*y*分量的运动。这两个函数都使用弧度角；如果旋转角度是度数，你必须使用(`degree*pi/180`)将其转换为弧度：

```py
resultant_x = sin(angle_of_rotational_sprite*pi/180.0) 
#sin(theta) represents base rotation about x-axix
resultant_y = cos(angle_of_rotational_sprite*pi/180.0)
#cos(theta) represents height rotation about y-axis
new_heading_movement = Vector2(resultant_x, resultant_y)
new_heading_movement *= movement_direction
```

现在，让我们学习实现鼠标控制，并观察它如何在游戏开发中使用。

# 鼠标控制

拥有鼠标控制，以及键盘控制，如果你想使游戏更加互动，这是很方便的。有时，处理八个方向键是不够的，在这种情况下，你还必须处理鼠标事件。例如，在像 flappy bird 这样的游戏中，用户基本上必须能够使用鼠标玩，尽管在移动游戏中使用屏幕点击，在 PC 上，你必须能够提供鼠标操作。在显示屏中绘制鼠标光标非常简单；你只需要从`MOUSEMOTION`事件中获取鼠标的坐标。类似于键盘`get_pressed`函数，你可以调用`pygame.mouse.get_pos()`函数来获取鼠标的位置。鼠标移动在游戏中非常有用——如果你想使游戏角色旋转，或者制作一个屏幕点击游戏，甚至如果你想上下查看游戏屏幕。

为了理解处理鼠标事件的方法，让我们看一个简单的例子：

```py
import pygame as game #now instead of using pygame, you can use game

game.init()
windowScreen = game.display.set_mode((300, 300))
done = False   # Draw Rect as place where mouse pointer can be clicked RectangularPlace = game.draw.rect(windowScreen, (255, 0, 0),(150, 150, 150, 150))
game.display.update()
# Main Loop while not done:
    # Mouse position and button clicking.
  position = game.mouse.get_pos()
    leftPressed, rightPressed, centerPressed = game.mouse.get_pressed() #checking if left mouse button is collided with rect place or not if RectangularPlace.collidepoint(position) and leftPressed:
        print("You have clicked on a rectangle")
    # Quit pygame.
  for anyEvent in game.event.get():
        if anyEvent.type == game.QUIT:
            done = True
```

我已经突出了代码的一些重要部分。重点主要放在帮助我们理解鼠标事件实现的那些部分上。让我们逐行看代码：

1.  首先，你必须定义一个对象——一个将有鼠标事件监听器设置以捕获它的区域。在这种情况下，你必须使用`pygame.draw.rect`方法调用将区域声明为矩形。

1.  在主循环内，你必须使用`pygame.mouse.get_pos()`函数获取鼠标的位置，这将表示当前光标坐标。

1.  然后，你必须从`pygame.mouse`模块调用`get_pressed()`方法。将返回一个布尔值列表。对于左、右或中间，布尔值`True`表示在特定实例中，特定鼠标按钮被按下，而其余两个没有。在这里，我们捕获了三个鼠标按钮的布尔值。

1.  现在，要检查用户是否按在矩形内，你必须调用`collidepoint`方法并向其传递一个位置值。位置表示当前光标位置。如果鼠标在当前位置点击，`pressed1`将为`True`。

1.  当这两个语句都为`True`时，您可以相应地执行任何操作。请记住，即使您在窗口屏幕中点击了，这个程序也不会打印消息，因为它不属于矩形的一部分。

与`pygame.key`模块类似，让我们详细了解`pygame.mouse`模块。该模块包含八个函数：

+   `pygame.mouse.get_rel()`: 它将以元组形式返回相对鼠标移动，包括*x*和*y*的相对移动。

+   `pygame.mouse.get_pressed()`: 它将返回三个布尔值，代表鼠标按钮，如果任何一个为`True`，则相应的按钮被视为按下。

+   `pygame.mouse.set_cursor()`: 它将设置标准光标图像。这很少需要，因为通过在鼠标坐标上绘制图像可以获得更好的效果。

+   `pygame.mouse.get_cursor()`: 它执行两个不同的任务：首先，它设置光标的标准图像，其次，它获取关于系统光标的确定性数据。

+   `pygame.mouse.set_visible()`: 它改变标准鼠标光标的可见性。如果为`False`，光标将不可见。

+   `pygame.mouse.get_pos()`: 它返回一个元组，包含鼠标在画布中点击位置的*x*和*y*值。

+   `pygame.mouse.set_pos()`: 它将设置鼠标位置。它接受一个元组作为参数，其中包含画布中*x*和*y*的坐标。

+   `pygame.mouse.get_focused()`: 这个布尔函数的结果基于窗口屏幕是否接收鼠标输入的条件。它类似于`key.get_focused`函数。当 pygame 在当前窗口屏幕中运行时，窗口将接收鼠标输入，但只有当 pygame 窗口被选中并在显示器的最前面运行时才会接收。如果另一个程序在后台运行并被选中，那么 pygame 窗口将无法接收鼠标输入，这个方法调用的输出将是`False`。

您可能玩过一些飞机或坦克游戏，鼠标用作瞄准设备，键盘用于移动和射击动作。这些游戏非常互动。因此，您应该尝试制作一个可以尽可能结合这两种事件的游戏。这两种类型的事件非常有用，对于任何游戏开发都很重要。我建议您花时间尝试这些事件。如果可能的话，尝试只使用几何对象制作自己的游戏。现在，我们将学习如何使用 pygame 和我们自己的精灵制作游戏。

这个游戏将是前一章中由 turtle 模块制作的贪吃蛇游戏的修改版本。所有的概念都是一样的，但是我们将制作外观吸引人的角色，并且我们将使用 pygame 处理事件。

# 对象渲染

计算机以颜色网格的形式存储图像。通常，RGB（红色、绿色和蓝色）足以提供像素的信息。但除了 RGB 值之外，在处理 pygame 游戏开发时，图像的另一个组成部分也很有用，那就是 alpha 信息（通常称为属性组件）。alpha 信息代表图像的透明度。这些额外的信息非常有用；在 pygame 的情况下，通常我们会激活 alpha 属性，然后将一张图像绘制或放置在另一张图像的顶部。通过这样做，我们可以看到部分背景。通常，我们会使用 GIMP 等第三方软件来使图像的背景透明。

除了知道如何使图像的背景透明之外，我们还必须知道如何将它们导入到我们的项目中，以便我们可以使用它们。将任何静态图像或精灵导入 Python 项目非常容易，pygame 使其变得更加容易。我们有一个图像模块，它提供了一个 load 方法来导入图像。在调用 load 方法时，您必须传递一个带有完整文件名的图像，包括扩展名。以下代码表示了一种将图像导入 Python 项目的方法：

```py
gameBackground = pygame.image.load(image_filename_for_background).convert()
Image_Cursor = pygame.image.load(image_filename_mouseCursor).convert_alpha()
```

您想要导入游戏项目的图像应该与游戏项目所在的目录相同。例如，如果 Python 文件保存在 snake 目录中，则 Python 文件加载的图像也应保存在 snake 目录中。

在图像模块中，load 函数将从硬盘加载文件并返回一个包含要加载的图像的新生成的表面。对`pygame.image.load`的第一次调用将读取图像文件，然后立即调用`convert`方法，将图像转换为与我们的显示器相同的格式。由于图像和显示屏的转换处于相同的深度级别，因此绘制到屏幕上相对较快。

第二个语句是加载鼠标光标。有时，您可能希望将自定义鼠标光标加载到游戏中，第二行代码就是这样做的方法。在加载`mouse_cursor`的情况下，使用`convert_alpha`而不是 convert 函数。这是因为鼠标光标的图像包含有关透明度的特殊信息，称为*alpha 信息*，并使图像的一部分变得不可见。通过禁用 alpha 信息，我们的鼠标光标将被矩形或正方形形状包围，从而使光标看起来不太吸引人。基本上，alpha 信息用于表示将具有透明背景的图像。

现在我们已经学会了如何将图像导入 Python 项目，让我们学习如何旋转这些图像。这是一种非常有用的技术，因为在构建游戏时，我们可能需要按一定角度旋转图像，以使游戏更具吸引力。例如，假设我们正在制作一个贪吃蛇游戏，我们正在使用一张图像作为蛇头。现在，当用户在键盘上按下“上”键时，蛇头应该旋转，并且必须平稳地向上移动。这是通过`pygame.transform`模块完成的。`Rotate`方法可以从 transform 模块中调用以便进行旋转。旋转方法接受从`image.load()`函数加载的图像表面，并指定旋转的角度。通常，转换操作会调整像素的大小或移动部分像素，以使表面与显示屏兼容：

```py
pygame.transform.rotate(img, 270) #rotation of image by 270 degree
```

在我们开始开发自己的视觉吸引人的贪吃蛇游戏之前，您必须了解 Pygame `time`模块。点击此链接了解更多信息：[`www.pygame.org/docs/ref/time.html#pygame.time.Clock`](https://www.pygame.org/docs/ref/time.html#pygame.time.Clock)。`Pygame.time`模块用于监控时间。时间时钟还提供了几个函数来帮助控制游戏的帧速率。帧速率是连续图像出现在显示屏上的速率或频率。每当调用时间模块的`Clock()`构造函数时，它将创建一个对象，该对象可用于跟踪时间。Pygame 开发人员在 Pygame 时间模块内部定义了各种函数。但是，我们只会使用`tick`方法，它将更新时钟。

`Pygame.time.Clock.tick()`应该在每帧调用一次。在函数的两次连续调用之间，`tick()`方法跟踪每次调用之间的时间（以毫秒为单位）。通过每帧调用`Clock.tick(60)`，程序被限制在 60 FPS 的范围内运行，并且即使处理能力更高，也不能超过它。因此，它可以用来限制游戏的运行速度。这在由 Pygame 开发的游戏中很重要，因为我们希望游戏能够平稳运行，而不是通过 CPU 资源来补偿。每秒帧数（帧速率）的值可以在由 Pygame 开发的游戏中的游戏中任何地方从 15 到 40。

现在，我们已经有足够的信息来使用 Pygame 制作我们自己的游戏，其中将有精灵和游戏角色的平滑移动。我们将在下一节中开始初始化显示。我们将使用 Pygame 模块更新我们的贪吃蛇游戏。

# 初始化显示

初始化显示非常基础；您可以始终通过导入必要的模块并在`set_mode()`方法中提供显示的特定尺寸来创建窗口化屏幕。除此之外，我们将声明一个主循环。请参考以下代码以观察主循环的声明：

```py
import pygame as game
from sys import exit
game.init()

DisplayScreen = game.display.set_mode((850,650))
game.display.set_caption('The Snake Game') #game title

game.display.update()

gameOver = False

while not gameOver:
    for anyEvent in game.event.get():
        print(event)
        exit()

game.quit()
quit()
```

初始化后，您可以运行程序检查一切是否正常。如果出现“没有 pygame 模块”的错误，请确保您按照上述步骤在 PyCharm IDE 上安装 Pygame。现在，我们将学习如何使用颜色。

# 使用颜色

计算机颜色的基本原理是*颜色相加*，这是一种将三种基本颜色相加以创建新颜色的技术。三种基本颜色是红色、绿色和蓝色，通常称为 RGB 值。每当 Pygame 需要将任何颜色添加到游戏中时，您必须将其传递给三个整数的元组，每个整数分别对应红色、绿色或蓝色。

将整数值传递给元组的顺序很重要，对整数进行微小的更改会导致不同的颜色。颜色的每个组件的值必须在 0 到 255 之间，其中 255 表示颜色具有绝对强度，而 0 表示该颜色根本没有强度。例如，(255, 0, 0)表示红色。以下表格指示了不同颜色的颜色代码：

| 颜色名称 十六进制码#RRGGBB 十进制码(R,G,B) |
| --- |
| --- |
| 黑色 #000000 (0,0,0) |
| 白色 #FFFFFF (255,255,255) |
| 红色 #FF0000 (255,0,0) |
| 酸橙色 #00FF00 (0,255,0) |
| 蓝色 #0000FF (0,0,255) |
| 黄色 #FFFF00 (255,255,0) |
| 青色/水绿色 #00FFFF (0,255,255) |
| 洋红/紫红 #FF00FF (255,0,255) |

现在，让我们为我们的贪吃蛇游戏项目添加一些颜色：

```py
white = (255,255,255)
color_black = (0,0,0)
green = (0,255,0)
color_red = (255,0,0)

while not gameOver:
    #1 EVENT GET
    DisplayScreen.fill(white) #BACKGROUND WHITE
    game.display.update()
```

现在，在下一节中，我们将学习如何使用`pygame`模块创建游戏对象。

# 制作游戏对象

为了开始创建游戏对象，我们不会直接使用贪吃蛇精灵或图像。相反，我们将从使用一个小矩形框开始，然后我们将用贪吃蛇图像替换它。这在大多数游戏中都需要做，因为我们必须在游戏开发的开始测试多个事物，比如帧速率、碰撞、旋转等。在处理所有这些之后，很容易将图像添加到 pygame 项目中。因此，在本节中，我们将制作类似矩形框的游戏对象。我们将制作贪吃蛇的头部和身体，它将是一个小矩形框。我们最初将为贪吃蛇的头部制作一个盒子，另一个为食物，然后为其添加颜色：

```py
while not gameOver:
    DisplayScreen.fill(white) #background of game 
    game.draw.rect(DisplayScreen, color_black, [450,300,10,10]) #1\. snake
    #two ways of defining rect objects
    DisplayScreen.fill(color_red, rect=[200,200,50,50]) #2\. food
```

现在我们将为`game`对象添加移动。在之前的章节中，我们已经谈论了很多这些内容，比如在处理方向移动时使用向量：

```py
change_x = 300
change_y = 300
while not gameOver:
    for anyEvent in game.event.get():
        if anyEvent.type == game.QUIT:
            gameOver = True
        if anyEvent.type == game.KEYDOWN:
            if anyEvent.key == game.K_LEFT:
                change_x -= 10
            if anyEvent.key == game.K_RIGHT:
                change_x += 10

    DisplayScreen.fill(white)
    game.draw.rect(DisplayScreen, black, [change_x,change_y,10,10])
    game.display.update()
```

在先前的代码中，`change_x`和`change_y`表示蛇的初始位置。每当开始玩我们的游戏时，蛇的默认位置将是(`change_x`, `change_y`)。通过按下左键或右键，我们改变它的位置。

当你此刻运行游戏时，你可能会观察到你的游戏只会移动一步，当你按下并立即释放键盘键时，游戏会立即停止。这种异常行为可以通过处理多个运动来纠正。在这种情况下，我们将创建`lead_x_change`，这将根据主`change_x`变量的变化。请记住，我们没有处理上下键事件；因此，不需要`lead_y_change`。

```py
lead_x_change = 0

while not gameOver:
    for anyEvent in game.event.get():
        if anyEent.type == game.QUIT:
            gameOver = True
        if anyEvent.type == game.KEYDOWN:
            if anyEvent.key == game.K_LEFT:
                lead_x_change = -10
            if anyEvent.key == game.K_RIGHT:
                lead_x_change = 10

    change_x += lead_x_change
    DisplayScreen.fill(white)
    game.draw.rect(DisplayScreen, black, [change_x,change_y,10,10])
    game.display.update()
```

在新的代码行中，我们添加了额外的信息`lead_x_change`，它将被称为*x*坐标的变化，每当用户按下左右键盘键时，蛇就会自动移动。代码的突出部分(`change_x += lead_x_change`)负责使蛇持续移动，即使用户不按任何键（蛇游戏的规则）。

现在，当你按下一个键时，你可能会在游戏中看到另一种不寻常的行为。在我的情况下，我运行了我的游戏，当我开始按下左键时，蛇开始快速地连续地从左到右移动。这是由于帧速率的宽松性；我们现在必须明确指示游戏的帧速率，以限制游戏的运行速度。我们将在下一节中介绍这个问题。

# 使用帧速率概念

这个话题对我们来说并不陌生；我已经尽我最大的努力尽早介绍这个话题。在讨论时钟模块时，我们也学习了帧速率的概念。在本节中，我们将看到帧速率的概念在实际中的应用。到目前为止，我们已经制作了一个可以运行的游戏，但它在移动上没有任何限制。它在一个方向或另一个方向上持续移动，速度很快，我们当然不希望这样。我们真正想要的是使蛇持续移动，但在一定的帧速率内。我们将使用`pygame.time.Clock`来创建一个对象，它将跟踪我们游戏的时间。我们将使用`tick`函数来更新时钟。tick 方法应该每帧调用一次。通过每帧调用`Clock.tick(15)`，游戏将永远不会以超过 15 FPS 的速度运行。

```py
clock = game.time.Clock()
while not gameOver:
    #event handling
    #code from preceding topic
    clock.tick(30) #FPS
```

重要的是要理解 FPS 并不等同于游戏中精灵的速度。开发者制作游戏的方式是可以在高端和低端设备上玩。你会发现在低配置的机器上游戏有点迟缓和抖动，但两种设备上的精灵或角色都会以平均速度移动。我们并不否认使用基于时间的运动游戏的机器，帧速率慢会导致视觉体验不佳，但它不会减慢动作的速度。

因此，为了制作一个视觉上吸引人的游戏，甚至在普及设备上也兼容，通常最好将帧速率设置在 20 到 40 FPS 之间。

在接下来的部分，我们将处理剩余的方向运动。处理这些运动并没有什么不同；它们可以通过矢量运动来处理。

# 处理方向运动

我们已经处理了*x*轴变化的运动。现在，让我们添加一些代码来处理*y*轴的运动。为了使蛇持续移动，我们必须使`lead_y_change`，它代表连续添加到当前位置的方向量，即使用户不按任何键盘键：

```py
lead_y_change = 0
while not gameOver:
        if anyEvent.type == game.KEYDOWN:
            if anyEvent.key == game.K_LEFT:
                lead_x_change = -10
                lead_y_change = 0
            elif anyEvent.key == game.K_RIGHT:
                lead_x_change = 10
                lead_y_change = 0
            elif anyEvent.key == game.K_UP:
                lead_y_change = -10
                lead_x_change = 0
            elif anyEvent.key == game.K_DOWN:
                lead_y_change = 10
                lead_x_change = 0  

    change_x += lead_x_change
    change_y += lead_y_change
```

现在我们已经处理了蛇的每种可能的运动，让我们为蛇游戏定义边界。`change_x`和`change_y`的值表示头部的当前位置。如果头部撞到边界，游戏将终止。

```py
while not gameOver:
    if change_x >= 800 or change_x < 0 or change_y >= 600 or change_y < 0:
            gameOver = True
```

现在，我们将学习另一个编程概念，这将使我们的代码看起来更清晰。到目前为止，我们已经为许多组件使用了数值，比如高度、宽度、FPS 等。但是如果你必须更改其中一个这些值会发生什么？在搜索代码和再次调试时会有很多开销。现在，我们可以创建常量变量，而不是直接使用这些数值，我们将这些值存储在其中，并在需要时检索它们。这个过程叫做*去除硬编码*。让我们为每个这些数值创建一个合适的名称的变量。代码应该看起来像这样：

```py
#variable initialization step
import pygame as game

game.init()

color_white = (255,255,255)
color_black = (0,0,0)
color_red = (255,0,0)

#display size
display_width = 800 
display_height = 600

DisplayScreen = game.display.set_mode((display_width,display_height))
game.display.set_caption('') #game title

gameOver = False

change_x = display_width/2
change_y = display_height/2

lead_x_change = 0
lead_y_change = 0

objectClock = game.time.Clock()

pixel_size = 10 #box size 
FPS = 30 #frame rate
```

在变量初始化步骤中去除硬编码后，我们将转向主游戏循环。以下代码表示主游戏循环（在初始化步骤之后添加）：

```py
#main loop
while not gameOver:
    for anyEvent in game.event.get():
        if anyEvent.type == game.QUIT:
            gameOver = True
        if anyEvent.type == game.KEYDOWN:
            if anyEvent.key == game.K_LEFT:
                lead_x_change = -pixel_size
                lead_y_change = 0
            elif anyEvent.key == game.K_RIGHT:
                lead_x_change = pixel_size
                lead_y_change = 0
            elif anyEvent.key == game.K_UP:
                lead_y_change = -pixel_size
                lead_x_change = 0
            elif anyEvent.key == game.K_DOWN:
                lead_y_change = pixel_size
                lead_x_change = 0

       #step 3: adding logic which will check if snake hit boundary or not
```

现在我们已经添加了处理用户事件的方法到主循环中，让我们重构代表逻辑的代码，比如当蛇撞到游戏边界时会发生什么，或者当蛇改变速度时会发生什么。在处理用户事件后，应该在主循环中添加以下代码：

```py
 if change_x >= display_width or change_x < 0 or change_y >= display_height 
                or change_y < 0:
        gameOver = True

    change_x += lead_x_change
    change_y += lead_y_change
    DisplayScreen.fill(color_white)
    game.draw.rect(DisplayScreen, color_black, 
      [change_x,change_y,pixel_size,pixel_size])
    game.display.update()

    objectClock.tick(FPS)
```

前面的所有代码已经简要描述过了，我们在前面的三个代码块中实际上是将变量重构为一些有意义的名称，以消除硬编码；例如，为显示宽度添加一个变量名，为颜色代码添加一个变量名，等等。

在接下来的部分，我们将在屏幕上添加一个食物字符，并创建一些逻辑来检查蛇是否吃了苹果。

# 添加食物到游戏中

在屏幕上添加一个字符非常简单。首先，为字符创建一个位置，最后，在该位置上`blit`字符。在蛇游戏中，食物必须在任意位置渲染。因此，我们将使用随机模块创建随机位置。我创建了一个新的函数`gameLoop()`，它将使用前面部分的代码。我使用`apple`作为食物。稍后，我将为它添加一个苹果图像。以下代码定义了游戏的主循环：

```py
def MainLoopForGame():
    global arrow_key #to track which arrow key user pressed

    gameOver = False
    gameFinish = False
    #initial change_x and change_y represent center of screen
    #initial position for snake
    change_x = display_width/2
    change_y = display_height/2

    lead_x_change = 0
    lead_y_change = 0
```

在为游戏显示和角色定义一些初始值之后，让我们添加一些逻辑来为蛇游戏添加苹果（食物）（这应该在`MainLoopForGame`函数内）。

```py
 XpositionApple = round(random.randrange(0, display_width-pixel_size))
 YpositionApple = round(random.randrange(0, display_height-pixel_size))
```

这两行代码将为*x*和*y*创建随机位置。确保导入随机模块。

接下来，我们需要在`MainLoopForGame`函数内定义主游戏循环。添加到主循环内的代码将处理多个事情，比如处理用户事件，绘制游戏角色等。让我们从以下代码中获取用户事件开始：

```py
 while not gameOver:

        while gameFinish == True:
            DisplayScreen.fill(color_white)
            game.display.update()

            #game is object of pygame
            for anyEvent in game.event.get():
                if anyEvent.type == pygame.KEYDOWN:
                    if anyEvent.key == pygame.K_q:
                        gameOver = True
                        gameFinish = False
                    if anyEvent.key == pygame.K_c:
                        MainLoopForGame()
```

前面的代码将很容易理解，因为我们在本章的前面已经做过这个。我们首先用白色填充游戏的背景屏幕，然后使用`pygame`模块的事件类获取事件。我们检查用户是否输入了`q`键，如果是，我们就退出游戏。同样，既然我们从用户那里得到了一个事件，让我们处理使蛇游戏移动的事件，比如左右箭头键。在获取用户事件后，应该添加以下代码：

```py
 #event to make movement for snake based on arrow keys
        for anyEvent in game.event.get():
            if anyEvent.type == game.QUIT:
                gameOver = True
            if anyEvent.type == game.KEYDOWN:
                if anyEvent.key == game.K_LEFT:
                    arrow_key = 'left'
                    lead_x_change = -pixel_size
                    lead_y_change = 0
                elif anyEvent.key == game.K_RIGHT:
                    arrow_key = 'right'
                    lead_x_change = pixel_size
                    lead_y_change = 0
                elif anyEvent.key == game.K_UP:
                    arrow_key = 'up'
                    lead_y_change = -pixel_size
                    lead_x_change = 0
                elif anyEvent.key == game.K_DOWN:
                    arrow_key = 'down'
                    lead_y_change = pixel_size
                    lead_x_change = 0
```

先前的代码已经编写好了，所以确保你按照程序的顺序进行。参考提供的代码资产[`github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter11`](https://github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter11)。让我们把剩下的代码添加到主循环中，处理渲染蛇食物的逻辑。在处理用户事件之后，应该添加以下代码：

```py
         if change_x >= display_width or change_x < 0 or change_y >= 
                        display_height or change_y < 0:
            gameFinish = True

        change_x += lead_x_change
        change_y += lead_y_change
        DisplayScreen.fill(color_white)
        Width_Apple = 30
        game.draw.rect(DisplayScreen, color_red, [XpositionApple, 
            YpositionApple, Width_Apple, Width_Apple])
        game.draw.rect(DisplayScreen, color_black, 
            [change_x,change_y,pixel_size, pixel_size])
        game.display.update()

        objectClock.tick(FPS)

    game.quit()
    quit()

MainLoopForGame()
```

在代码的突出部分，我们将绘制一个红色的矩形，并将其渲染在由`pixel_size= 10`的高度和宽度的随机模块定义的位置。

现在我们已经为蛇添加了食物，让我们制作一个函数，使蛇的身体增长。到目前为止，我们只处理了蛇的头部；现在是时候制作一个函数，通过单位块来增加蛇的身体。请记住，只有在蛇吃了食物之后才会调用这个函数：

```py
def drawSnake(pixel_size, snakeArray):
    for eachSegment in snakeArray:
        game.draw.rect(DisplayScreen, color_green  [eachSegment[0],eachSegment[1],pixel_size, pixel_size])

```

在主游戏循环中，我们必须声明多个东西。首先，我们将声明`snakeArray`，它将包含蛇的身体。游戏开始时，蛇的长度为 1。每当蛇吃食物时，我们将增加它：

```py
def MainLoopForGame():
 snakeArray = []
 snakeLength = 1

    while not gameOver:
        head_of_Snake = []
 #at the beginning, snake will have only head
 head_of_Snake.append(change_x)
 head_of_Snake.append(change_y)

        snakeArray.append(head_of_Snake)

        if len(snakeArray) > snakeLength:
            del snakeArray[0] #deleting overflow of elements

        for eachPart in snakeArray[:-1]:
            if eachPart == head_of_Snake:
                gameFinish = True #when snake collides with own body

        drawSnake(pixel_size, snakeArray)  
        game.display.update()
```

变量的名称告诉你一切你需要知道的。我们以前做过很多次，也就是为蛇的头部制作列表，并检查它是否与蛇的身体发生碰撞。蛇方法调用`pixel_size`，这是蛇的尺寸，以及包含与蛇身体相关的位置列表的蛇列表。蛇将根据这些列表进行`blit`，通过在`snake`函数内定义的绘制语句。

接下来，我们需要定义逻辑来使蛇吃食物。这个逻辑已经被反复使用，在 pygame 的情况下也不例外。每当蛇的头部位置与食物位置相同时，我们将增加蛇的长度，并在一个新的随机位置生成食物。确保在更新显示后，在主游戏循环中添加以下代码：

```py
#condition where snake rect is at the top of apple rect  
if change_x > XpositionApple and change_x < XpositionApple + Width_Apple or change_x + pixel_size > XpositionApple and change_x + pixel_size < XpositionApple + Width_Apple:

      if change_y > YpositionApple and change_y < YpositionApple + 
        Width_Apple:
                #generate apple to new position
                XpositionApple = round(random.randrange(0, 
                                 display_width-pixel_size))
                YpositionApple = round(random.randrange(0, 
                                 display_height-pixel_size))
                snakeLength += 1

      elif change_y + pixel_size > YpositionApple and change_y + pixel_size 
            < YpositionApple + Width_Apple:

                XpositionApple = round(random.randrange(0, display_width-
                                 pixel_size))
                YpositionApple = round(random.randrange(0, display_height-
                                 pixel_size))
                snakeLength += 1
```

由于我们能够添加一些逻辑来检查蛇是否吃了食物，并做出相应的反应，现在是时候为角色添加精灵或图像了。正如我们之前提到的，我们将添加我们自己的蛇头，而不是使用沉闷的矩形形状。让我们开始创建一个。

# 添加蛇的精灵

最后，我们可以开始使我们的游戏更具吸引力——我们将制作蛇的头。我们不需要额外的知识来为游戏角色创建图像。你也可以从互联网上下载图像并使用它们。然而，在这里，我将向你展示如何为自己创建一个，并如何在我们的蛇游戏中使用它。

按照以下步骤，逐行进行：

1.  打开任何*绘图*应用程序，或者在搜索栏中搜索绘图，然后打开应用程序。

1.  按下*Ctrl* + *W*来调整和扭曲你选择的图片，或者直接使用上方菜单栏的调整按钮。这将打开一个新的调整窗口。可以按百分比和像素进行调整。使用百分比调整并保持 20x20 的纵横比，即水平：20，垂直：20。

1.  之后，你会得到一个绘制屏幕。选择你想要制作的蛇头的颜色。在制作游戏时，我们创建了一个绿色的蛇身体；因此，我也会选择绿色作为蛇头的颜色。我会使用画笔画出类似以下图片的东西。如果你愿意，你可以花时间创作一个更好的。完成后，保存文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/38c3a904-cd84-46db-9eb7-458cab37f736.png)

1.  现在，你必须使图像的背景透明。你也可以使用一些在线工具，但我将使用之前提到过的 GIMP 软件。你必须从官方网站上下载它。它是开源的，可以免费使用。去网站上下载 GIMP：[`www.gimp.org/downloads/`](https://www.gimp.org/downloads/)。

1.  用 GIMP 软件打开你之前制作的蛇头。从最上面的菜单中选择图层选项卡，选择透明度，然后点击添加 Alpha 通道。这将添加一个通道，可以用来使我们图像的背景透明。

1.  从菜单屏幕中点击颜色选项卡。将会出现一个下拉菜单。点击颜色到 Alpha，使背景透明。将该文件导出到与您的 Python 文件存储在同一目录中。

现在我们有了蛇头的精灵，让我们在 Python 文件中使用`blit`命令来渲染它。如你所知，在使用任何图像之前，你必须导入它。由于我已经将蛇头图像保存在与 Python 文件相同的目录中，我可以使用`pygame.image.load`命令：

```py
image = game.image.load('snakehead.png')
```

在`drawSnake`方法的主体内，你必须 blit 图像；就像这样：

```py
DisplayScreen.blit(image, (snakeArray[-1][0], snakeArray[-1][1]))
```

现在，当你运行游戏时，你会观察到一个奇怪的事情。当我们按下任何一个箭头键时，头部不会相应地旋转。它将保持在默认位置。因此，为了使精灵根据方向的移动而旋转，我们必须使用`transform.rotate`函数。观察蛇的方法，因为它有一种方法可以在没有旋转的情况下`blit`图像。现在，我们将添加几行代码，使精灵旋转：

```py
def drawSnake(pixel_size, snakeArray):

 if arrow_key == "right":
 head_of_Snake = game.transform.rotate(image, 270) #making rotation of 270 

 if arrow_key== "left":
 head_of_Snake = game.transform.rotate(image, 90)

 if arrow_key== "up":
 head_of_Snake = image #default

 if arrow_key== "down":
 head_of_Snake = game.transform.rotate(image, 180)

 DisplayScreen.blit(head_of_Snake, (snakeArray[-1][0], snakeArray[-1][1]))
 for eachSegment in snakeArray[:-1]:
 game.draw.rect(DisplayScreen, color_green,[eachSegment[0],eachSegment[1], 
 pixel_size, pixel_size])
```

现在，不再使用苹果的矩形框，让我从互联网上下载一个苹果的样本，以 PNG 的形式（透明背景），也`blit`它：

```py
appleimg = game.image.load('apple.png') 
#add apple.png file in same directory of python file
while not gameOver:
    #code must be added before checking if user eats apple or not
    DisplayScreen.blit(appleimg, (XpositionApple, YpositionApple))
```

让我们运行游戏并观察输出。虽然蛇头看起来更大了，但我们可以随时调整它的大小：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/ade1f80d-3bf7-4b01-84e0-f80900e83a5f.png)

在下一节中，我们将学习如何为我们的游戏添加一个菜单。菜单是每次打开游戏时看到的屏幕，通常是一个欢迎屏幕。

# 为游戏添加一个菜单

为任何游戏添加一个介绍屏幕需要我们具备使用`pygame`模块处理字体的知识。pygame 提供了一个功能，使我们可以使用不同类型的字体，包括改变它们的大小的功能。`pygame.font`模块用于向游戏添加字体。字体用于向游戏屏幕添加文本。由于介绍或欢迎屏幕需要玩家显示一个包含字体的屏幕，我们必须使用这个模块。调用`SysFont`方法向屏幕添加字体。`SysFont`方法接受两个参数：第一个是字体的名称，第二个是字体的大小。以下一行代码初始化了相同字体的三种不同大小：

```py
font_small = game.font.SysFont("comicsansms", 25)
font_medium = game.font.SysFont("comicsansms", 50)
font_large = game.font.SysFont("comicsansms", 80)
```

我们将首先使用`text_object`函数创建一个表面，用于小号、中号和大号字体。文本对象函数将使用文本创建一个矩形表面。传递给此方法的文本将添加到框形对象中，并从中返回，如下所示：

```py
def objects_text(sample_text, sample_color, sample_size):
 if sample_size == "small":
 surface_for_text = font_small.render(sample_text, True, sample_color)
 elif sample_size == "medium":
 surface_for_text= font_medium.render(sample_text, True, sample_color)
 elif sample_size == "large":
 surface_for_text = font_large.render(sample_text, True, sample_color)

 return surface_for_text, surface_for_text.get_rect()
```

让我们在 Python 文件中创建一个新的函数，使用上述字体向屏幕添加一条消息：

```py
def display_ScreenMessage(message, font_color, yDisplace=0, font_size="small"):
 textSurface, textRectShape = objects_text(message, font_color, font_size)
 textRectShape.center = (display_width/ 2), (display_height/ 2) + yDisplace
 DisplaySurface.blit(textSurface, textRectShape)
```

向`screen`方法传递的消息将创建一个矩形表面，以`blit`传递给它的文本作为`msg`。默认字体大小是小号，文本居中对齐在矩形表面的中心。现在，让我们为我们的游戏创建一个游戏介绍方法：

```py
def intro_for_game(): #function for adding game intro
 intro_screen = True   while intro_screen:

 for eachEvent in game.event.get():
 if eachEvent.type == game.QUIT:
 game.quit()
 quit()

 if eachEvent.type == game.KEYDOWN:
 if eachEvent.key == game.K_c:
 intro_screen = False
 if eachEvent.key == game.K_q:
 game.quit()
 quit()

 DisplayScreen.fill(color_white)
 display_ScreenMessage("Welcome to Snake",
 color_green,
  -99,
  "large")

 display_ScreenMessage("Made by Python Programmers",
 color_black,
  50)

 display_ScreenMessage("Press C to play or Q to quit.",
  color_red,
  180)

 game.display.update()
 objectClock.tick(12)
```

这个游戏的`intro`方法在游戏`loop`方法调用之前被调用。例如，看看下面的代码：

```py
intro_for_game()
MainLoopForGame()
```

最后，欢迎菜单的输出应该是这样的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/6fb16dc8-2ad6-4d90-bfc6-9ef51d3d3be5.png)

最后，我们的游戏已经准备好分发了。你可能会看到我们的游戏是一个扩展名为`.py`的 Python 文件，它不能在没有安装 Python 的机器上执行。因此，在下一节中，我们将学习如何将 Python 文件转换为可执行文件，以便我们可以在 Windows 机器上全球分发我们的游戏。

# 转换为可执行文件

如果您已经制作了自己的 pygame 游戏，显然您希望与朋友和家人分享。在互联网世界中，共享文件非常容易，但当另一端的用户没有预安装 Python 时，问题就会出现。不是每个人都能为了测试您的游戏而安装 Python。更好的想法是制作可在许多这些机器上执行的可执行文件。我们将在本节中学习如何转换为`.exe`，其他版本（Linux 和 Mac）将在接下来的章节中介绍。

如果使用 Python 提供的模块，将 Python 文件转换为可执行文件会更容易。其中有几个模块——`py2exe`和`cx_Freeze`。我们将在本节中使用第一个。

# 使用 py2exe

要将 Python 文件转换为可执行文件，我们可以使用另一个名为`py2exe`的 Python 模块。`py2exe`模块不是 pygame 中预安装的——它不是标准库——但可以通过使用以下命令进行下载：

```py
pip install py2exe 
OR
py -3.7 -m pip install py2exe
```

下载`py2exe`模块后，转到包含您的 Python 文件的文件夹。在该位置打开命令提示符或终端并运行代码。它将把您的 Python 文件打包成一个`.exe`文件，或者成为可执行文件。以下命令将搜索并复制脚本使用的所有文件到一个名为`dist`的文件夹中。在`dist`中将会有一个`snake.exe`文件；这个文件将是 Python 代码的输出模拟，可以在没有安装 Python 的机器上执行。例如，您的朋友可能没有在他们的机器上安装 Python，但他们仍然可以运行这个文件。为了将游戏分发到任何其他 Windows 机器，您只需发送`dist`文件夹或`snake.exe`文件的内容。只需运行以下命令：

```py
python snake.py py2exe #conversion command
```

这将创建一个名为*snake*的游戏，并带有`.exe`的扩展名。您可以在 Windows 平台上分发这些文件并从中获得响应。恭喜！你终于做到了。现在，让我们学习使用 pygame 进行游戏测试。

# 游戏测试和可能的修改

有时，您的机器可能会出现内存不足的情况。如果内存不足，并且您尝试将更多图像加载到游戏中，即使使用了 pygame 的最大努力，此过程也将被中止。`pygame.image.load`必须伴随一些内存才能正常执行任务。在内存不足的情况下，您可以预测到肯定会触发某种异常。即使有足够的内存，如果尝试加载不在硬盘驱动器中的图像，或者说，在编写文件名时出现了拼写错误，您可能会收到异常。因此，最好事先处理它们，这样我们就不必事后再去调试它们。

其次，让我们检查当我们向`set_mode`方法提供不寻常的屏幕尺寸时会发生什么。回想一下，`set_mode`是我们用来创建`Surface`对象的方法。例如，假设我们忘记向`set_mode`添加两个值，而只添加了一个。在这种情况下，我们也会触发错误：

```py
screen = pygame.display.set_mode((640))
TypeError: 2 argument expected
```

假设，与其忘记为高度和宽度添加适当的尺寸，如果我们将高度值添加为 0 会发生什么？在 PyCharm IDE 的情况下，这个问题不会创建任何异常。相反，程序将无限运行，导致您的机器崩溃。然而，这些程序通常会抛出一个`pygame.error: cannot set 0 sized display`的异常。现在您知道了`pygame`可能出错的地方，可以捕获这些异常并相应地处理它们：

```py
try:
    display = pygame.display.set_mode((640,0))
except pygame.error:
    print("Not possible to create display")
    exit()
```

因此，最好明智地选择您的显示屏，以消除任何不必要的异常。但更有可能的是，如果您尝试加载不在硬盘上的图像，您可能会遇到`pygame`错误的异常。因此，处理异常是一个很好的做法，以确保游戏的精灵或图像被正确加载。

# 总结

在本章中，我们研究了`pygame`模块，并发现了在游戏开发中使用它的原因。我们从下一章开始涵盖的大多数游戏都将在某种程度上基于`pygame`模块。因此，在继续之前，请确保自己使用 pygame 制作一个简单的游戏。

我们开始学习如何使用 pygame 对象制作游戏。我们学到了各种东西，包括处理涉及鼠标和键盘等输入设备的用户按键事件；我们制作了精灵动画；我们学习了颜色属性；并且使用向量运动处理了不同的对角线和方向性移动。我们使用简单的绘图应用程序创建了自己的精灵，并使用 GIMP 应用程序添加了 alpha 属性。我们尝试通过整合交互式游戏屏幕，也就是菜单屏幕，使游戏更具互动性。最后，我们学会了如何使用`py2exe`模块将 Python 文件转换为可执行文件。

本章的主要目标是让您熟悉精灵的使用，以便您可以制作 2D 游戏。您还学会了如何处理用户事件和不同的移动，包括对角线移动。您还学会了如何使用外部软件创建自定义精灵和图像，以及在游戏中使用它们的方法。不仅如此，您还熟悉了颜色和`rect`对象的概念，并学会了如何使用它们使游戏更具用户互动性，通过部署菜单和得分屏幕。

在下一章中，我们将运用本章学到的概念制作自己的 flappy bird 克隆游戏。除了本章学到的内容，我们还将学习游戏动画、角色动画、碰撞原理、随机对象生成、添加分数等许多概念。


# 第十二章：学习角色动画、碰撞和移动

*动画是一门艺术*。这引发了关于如何通过为每个角色添加纹理或皮肤，或者通过保持无可挑剔的图形用户界面来创建模拟人物或物体的物理行为的虚拟世界的问题。在创建动画时，我们不需要了解控制器或物理设备的工作原理，但动画是物理设备和游戏角色之间的媒介。动画通过在图像视图中以适当的阴影和动作引导玩家，因此它是一门艺术。作为程序员，我们负责游戏角色在特定方向移动的位置和原因，而动画师负责它们的外观和动作。

在 Python 的`pygame`模块中，我们可以使用精灵来创建动画和碰撞-这是大型图形场景的一部分的二维图像。也许我们可以自己制作一个，或者从互联网上下载一个。在使用 pygame 加载这样的精灵之后，我们将学习构建游戏的两个基本模块：处理用户事件和构建动画逻辑。动画逻辑是一个简单而强大的逻辑，它使精灵或图像在用户事件控制下朝特定方向移动。

通过本章，您将熟悉游戏控制器的概念以及使用它为游戏角色创建动画的方法。除此之外，您还将了解有关碰撞原理以及使用 pygame 掩模方法处理碰撞的方法。不仅如此，您还将学习处理游戏角色的移动方式，如跳跃、轻拍和滚动，同时制作类似 flappy bird 的游戏。

在本章中，我们将涵盖以下主题：

+   游戏动画概述

+   滚动背景和角色动画

+   随机对象生成

+   检测碰撞

+   得分和结束屏幕

+   游戏测试

# 技术要求

您需要以下要求清单才能完成本章：

+   Pygame 编辑器（IDLE）版本 3.5 或更高。

+   Pycharm IDE（参考第一章，*了解 Python-设置 Python 和编辑器*，进行安装程序）。

+   Flappy Bird 游戏的代码资产和精灵可在本书的 GitHub 存储库中找到：[`github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter12`](https://github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter12)

观看以下视频，查看代码的运行情况：

[`bit.ly/2oKQQxC`](http://bit.ly/2oKQQxC)

# 了解游戏动画

就像你在电脑游戏中看到的一切一样，动画模仿现实世界，或者试图创造一个让玩家感觉自己正在与之交互的世界。用二维精灵绘制游戏相当简单，就像我们在上一章中为贪吃蛇游戏制作角色时所看到的那样。即使是二维角色，我们也可以通过适当的阴影和动作创建三维运动。使用`pygame`模块可以更容易地为单个对象创建动画；我们在上一章中看到了一点实际操作，当时我们为贪吃蛇游戏创建了一个简单的动画。在本节中，我们将使用`pygame`模块为多个对象创建动画。我们将制作一个简单的程序，用于创建下雪的动画。首先，我们将使用一些形状填充雪花（在此程序中，我们使用的是圆形几何形状，但您可以选择任何形状），然后创建一些动画逻辑，使雪花在环境中移动。

在编写代码之前，确保你进行了一些头脑风暴。由于在上一章中我们编写了一些高级逻辑，所以这一部分对你来说可能更容易，但是确保你也学习了我们在这里做的事情，因为对接下来的部分非常有用，我们将开始制作 Flappy Bird 游戏的克隆版本。

正如我们所知，雪花动画需要一个位置（*x*，*y*）来渲染雪花。这个位置可以任意选择，因此你可以使用随机模块来选择这样的位置。以下代码展示了如何使用`pygame`模块在随机位置绘制任何形状。由于使用了`for`循环进行迭代，我们将使用它来创建一个迭代的范围，最多进行 50 次调用（`eachSnow`的值从 0 到 49）。回想一下前一章，你学习了如何使用 pygame 的`draw`模块将任何形状绘制到屏幕上。考虑到这一点，让我们看看以下代码：

```py
#creates snow 
for eachSnow in range(50):
     x_pos = random.randrange(0, 500)
     y_pos = random.randrange(0, 500)
     pygame.draw.circle(displayScreen, (255,255,255) , [x_pos, y_pos], 2) #size:2
```

想象一下，我们使用了前面的代码来制作动画，这将绘制圆形雪花。运行后，你会发现输出中有些奇怪的地方。你可能已经猜到了，但让我为你解释一下。前面的代码制作了一个圆圈——在某个随机位置——并且先前制作的圆圈在新圆圈创建时立即消失。我们希望我们的代码生成多个雪花，并确保先前制作的圆圈位于右侧位置而不是消失。你发现前面的代码有点 bug 吗？既然你知道了错误的原因，花点时间考虑如何解决这个错误。你可能会想到一个普遍的想法，那就是使用数据结构来解决这个问题。我倾向于使用列表。让我们对前面的代码进行一些修改：

```py
for eachSnow in range(50):
     x_pos = random.randrange(0, 500)
     y_pos = random.randrange(0, 500)
     snowArray.append([x_pos, y_pos])
```

现在，在`snowArray`列表中，我们已经添加了随机创建的雪的位置，即*x*和*y*。对于雪的多个`x_pos`和`y_pos`值，将形成一个嵌套列表。例如，一个列表可能看起来像`[[20,40],[40,30],[30,33]]`，表示随机制作的三个圆形雪花。

对于使用前面的`for`循环创建的每一片雪花，你必须使用另一个循环进行渲染。获取`snow_list`变量的长度可能会有所帮助，因为这将给我们一个关于应该绘制多少雪花的想法。对于由`snow_list`指示的位置数量，我们可以使用`pygame.draw`模块绘制任何形状，如下所示：

```py
for eachSnow in range(len(snowArray)):
 # Draw the snow flake
     pygame.draw.circle(displayScreen, (255,255,255) , snowArray[i], 2)
```

你能看到使用`pygame`模块绘制图形有多容易吗？即使这对你来说并不陌生，这个概念很快就会派上用场。接下来，我们将看看如何让雪花向下飘落。按照以下步骤创建圆形雪花的向下运动：

1.  首先，你必须让雪向下移动一个单位像素。你只需要对`snowArray`元素的`y_pos`坐标进行更改，如下所示：

```py
      color_WHITE = (255, 255, 255)
      for eachSnow in range(len(snowArray)):

       # Draw the snow flake
       pygame.draw.circle(displayScreen, color_WHITE, snow_Array[i], 2)

       # moving snow one step or pixel below
       snowArray[i][1] += 1
```

1.  其次，你必须确保，无论何时雪花消失在视野之外，都会不断地创建。在*步骤 1*中，我们已经为圆形雪花创建了向下运动。在某个时候，它将与较低的水平边界相撞。如果它碰到了这个边界，你必须将它重置，以便从顶部重新渲染。通过添加以下代码，圆形雪花将在屏幕顶部使用随机库进行渲染：

```py
      if snowArray[i][1] > 500:
      # Reset it just above the top
      y_pos = random.randrange(-50, -10)
      snowArray[i][1] = y_pos
      # Give it a new x position
      x_pos = random.randrange(0, 500)
      snowArray[i][0] = y_pos
```

这个动画的完整代码如下（带有注释的代码是不言自明的）：

1.  首先，我们编写的前面的代码需要重新定义和重构，以使代码看起来更好。让我们从初始化开始：

```py
      import pygame as p
      import random as r

      # Initialize the pygame
      p.init()

      color_code_black = [0, 0, 0]
      color_code_white = [255, 255, 255]

      # Set the height and width of the screen
      DISPLAY = [500, 500]

      WINDOW = p.display.set_mode(DISPLAY)

      # Create an empty list to store position of snow
      snowArray = []
```

1.  现在，在初始化的下面添加你的`for`循环：

```py
      # Loop 50 times and add a snow flake in a random x,y position
      for eachSnow in range(50):
          x_pos = r.randrange(0, 500)
          y_pos = r.randrange(0, 500)
          snowArray.append([x_pos, y_pos])

          objectClock = game.time.Clock()
```

1.  类似地，我们将通过创建主循环来结束逻辑，该循环将一直循环，直到用户显式点击关闭按钮：

```py
      # Loop until the user clicks the close button.
      finish = False
      while not finish:

           for anyEvent in p.event.get(): # User did something
               if anyEvent.type == p.QUIT: # If user clicked close
                   finish = True # Flag that we are done so we 
                            exit this loop

       # Set the screen background
               WINDOW.fill(BLACK)

       # Process each snow flake in the list
               for eachSnow in range(len(snowArray)):

       # Draw the snow flake
                   p.draw.circle(WINDOW, color_code_white, snowArray[i], 2)

       # One step down for snow [falling of snow]
                   snowArray[i][1] += 1
```

1.  最后，检查雪花是否在边界内：

```py
# checking if snow is out of boundary or not
 if snowArray[i][1] > 500:
 # reset if it from top
 y_pos = r.randrange(-40, -10)
 snowArray[i][1] = y_pos
 # New random x_position
 x_pos = r.randrange(0, 500)
 snowArray[i][0] = x_pos
```

1.  最后，更新屏幕上已经绘制的内容：

```py
      # Update screen with what you've drawn.
          game.display.update()
          objectClock.tick(20)

      #if you remove following line of code, IDLE will hang at exit
      game.quit()
```

上述代码由许多代码片段组成：初始化游戏变量，然后创建游戏模型。在*步骤 3*中，我们创建了一些简单的逻辑来控制游戏的动画。我们在*步骤 3*中构建了两个代码模型，使我们的游戏对用户进行交互（处理用户事件），并创建一个游戏对象（圆形降雪），它使用`for`循环进行渲染。尽管我们将在接下来的章节中创建更复杂的动画，但这是一个很好的动画程序开始。您可以清楚地看到，在幕后，创建动画需要使用循环、条件和游戏对象。我们使用 Python 编程范式，如 if-else 语句、循环、算术和向量操作来创建游戏对象动画。

除了动画几何形状，您甚至可以动画精灵或图像。为此，您必须制作自己的精灵或从互联网上下载一些。在接下来的部分中，我们将使用`pygame`模块来动画精灵。

# 动画精灵

动画精灵与动画几何形状没有什么不同，但它们被认为是复杂的，因为您必须编写额外的代码来使用动画逻辑`blit`这样的图像。然而，这种动画逻辑对于您加载的每个图像都不会相同；它因游戏而异。因此，您必须事先分析适合您的精灵的动画类型，以便您可以相应地编写代码。在本节中，我们不打算创建任何自定义图像；相反，我们将下载一些（感谢互联网！）。我们将在这些精灵中嵌入动画逻辑，以便我们的程序将促进适当的阴影和移动。

为了让您了解动画静态图像或精灵有多容易，我们将创建一个简单的程序，该程序将加载大约 15 个角色图像（向左和向右移动）。每当用户按键盘上的左键或右键时，我们将`blit`（渲染）它们。执行以下步骤来学习如何创建一个动画精灵程序：

1.  首先，您应该从为`pygame`程序创建一个基本模板开始。您必须导入一些重要的模块，为动画控制台创建一个表面，并声明*空闲*友好的`quit()`函数。

```py
 import pygame
      pygame.init()

      win = pygame.display.set_mode((500,480)) pygame.quit()
```

1.  其次，您必须加载*images*目录中列出的所有精灵和图像。该目录包含几个精灵。您必须下载它并保存在存储 Python 文件的目录中（可以在 GitHub 上找到 sprites/images 文件，网址为[`github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter12`](https://github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter12)）：

```py
 #walk_Right contains images in which character is turning towards 
         Right direction 
      walkRight = [pygame.image.load('Right1.png'), 
 pygame.image.load('Right2.png'), pygame.image.load('Right3.png'), 
 pygame.image.load('Right4.png'), pygame.image.load('Right5.png'), 
       pygame.image.load('Right6.png'), pygame.image.load('Right7.png'), 
 pygame.image.load('Right8.png'), pygame.image.load('Right9.png')]        #walk_left contains images in which character is turning towards 
         left direction
      walkLeft = [pygame.image.load('Left1.png'), 
 pygame.image.load('Left2.png'), pygame.image.load('Left3.png'), 
 pygame.image.load('Left4.png'), pygame.image.load('Left5.png'), 
 pygame.image.load('Left6.png'), pygame.image.load('Left7.png'), 
 pygame.image.load('Left8.png'), pygame.image.load('Left9.png')]

      #Background and stand still images
      background = pygame.image.load('bg.jpg')
      char = pygame.image.load('standing.png')
```

1.  接下来，我们需要声明一些基本变量，例如角色的初始位置和速度，即游戏精灵每单位按键击移动的距离。在下面的代码中，我已经将速度声明为五个单位，这意味着游戏角色将从当前位置移动固定的 5 个像素：

```py
 x = 50
      y = 400
      width = 40
      height = 60
      vel = 5

      clock = pygame.time.Clock()
```

1.  您必须声明一些额外的变量，以便根据用户在键盘上按下什么来跟踪精灵的移动。如果按下左箭头键，则`left`变量将为`True`，而如果按下右箭头键，则`right`变量将为`False`。`walkCount`变量将跟踪按下键的次数：

```py
 left = False
      right = False
      walkCount = 0
```

在这里，我们已经完成了任何 pygame 程序的基本布局——导入适当的模块，声明变量以跟踪移动，加载精灵等等。程序的另外两个部分是最重要的，所以请确保您理解它们。我们将开始创建一个主循环，像往常一样。这个主循环将处理用户事件，也就是说，当用户按下左或右键时要做什么。其次，您必须创建一些动画逻辑，这将根据用户事件确定在什么时间点`blit`什么图像。

我们将从处理用户事件开始。按照以下步骤进行：

1.  首先，您必须声明一个主循环，它必须是一个无限循环。我们将使用`tick`方法为游戏提供**FPS**。正如您可能记得的那样，这个方法应该在每帧调用一次。它将计算自上一次调用以来经过了多少毫秒：

```py
 finish = False 

 while not finish: clock.tick(27)
```

1.  其次，开始处理关键的用户事件。在简单的精灵动画中，您可以从处理两种基本移动开始：左和右。在接下来的部分中，我们将通过处理跳跃/轻击动作来制作游戏。这段代码应该写在一个 while 循环内：

```py
      while not finish:
           clock.tick(27)
           for anyEvent in pygame.event.get():
              if anyEvent.type == pygame.QUIT:
                  finish = True

           keys = pygame.key.get_pressed()

          #checking key pressed and if character is at x(boundary) or not?
           if keys[pygame.K_LEFT] and x > vel: 
              x -= vel #going left by 5pixels
              left = True
              right = False

          #checking RIGHT key press and is character coincides with 
             RIGHT boundary.
          # value (500 - vel - width) is maximum width of screen, 
             thus x should be less
           elif keys[pygame.K_RIGHT] and x < 500 - vel - width:  
              x += vel #going right by 5pixels
              left = False
              right = True

           else: 
              #not pressing any keys
              left = False
              right = False
              walkCount = 0

          Animation_Logic()
```

观察上述代码的最后一行——对`Animation_Logic()`函数的调用已经完成。然而，这个方法还没有被声明。这个方法是由精灵或图像制作的任何游戏的核心模块。在动画逻辑内编写的代码将执行两个不同的任务：

+   从加载精灵时定义的图像列表中 blit 或渲染图像。在我们的情况下，这些是`walkRight`、`walkLeft`、`bg`和`char`。

+   根据逻辑重新绘制游戏窗口，这将检查从图像池中选择哪个图像。请注意，`walkLeft`包含九个不同的图像。这个逻辑将从这些图像中进行选择。

现在我们已经处理了用户事件，让我们学习如何为之前加载的精灵制作动画逻辑。

# 动画逻辑

精灵是包含角色并具有透明背景的静态图像。这些精灵的额外 alpha 信息是必不可少的，因为在 2D 游戏中，我们希望用户只看到角色而不是他们的背景。想象一下一个游戏，其中一个角色与单调的背景 blit。这会给玩家留下对游戏的坏印象。例如，以下精灵是马里奥角色。假设您正在制作一个马里奥游戏，并且从以下精灵中裁剪一个角色，却忘记去除其蓝色背景。角色连同其蓝色背景将在游戏中呈现，使游戏变得糟糕。因此，我们必须手动使用在线工具或离线工具（如 GIMP）去除（如果有的话）角色背景。精灵表的一个示例如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/3e5970c4-966c-4bd4-92fa-1e9e2452d573.png)

现在，让我们继续我们的精灵动画。到目前为止，我们已经使用`pygame`声明了处理事件的模板；现在，让我们编写我们的动画逻辑。正如我们之前所断言的那样，*动画逻辑是简单的逻辑，将在图像之间进行选择并相应地进行 blit。*现在让我们制定这个逻辑：

```py
def Animation_Logic():
    global walkCount

    win.blit(background, (0,0))  

    #check_1
    if walkCount + 1 >= 27:
        walkCount = 0

    if left:  
        win.blit(walkLeft[walkCount//3], (x,y))
        walkCount += 1                          
    elif right:
        win.blit(walkRight[walkCount//3], (x,y))
        walkCount += 1
    else:
        win.blit(char, (x, y))
        walkCount = 0

    pygame.display.update()
```

你将看到的第一件事是`global`变量。`walkCount`变量最初在主循环中声明，并计算用户按下任何键的次数。然而，如果你删除`global walkCount`语句，你将无法在`Animation_Logic`函数内改变`walkCount`的值。如果你只想在函数内访问或打印`walkCount`的值，你不需要将其定义为全局变量。但是，如果你想在函数内操作它的值，你必须将其声明为全局变量。`blit`命令将采用两个参数：一个是需要渲染的精灵，另一个是精灵必须渲染到屏幕上的位置。在前面的代码中，写在`#check_1`之后的代码是为了在角色到达极限位置时对其进行限定。这是一个检查，我们必须渲染一个*char*图像，这是一个角色静止的图像。

渲染精灵始于我们检查左移动是否激活。如果为`True`，则在(*x*, *y*)位置`blit`图像。(*x*, *y*)的值由事件处理程序操作。每当用户按下左箭头键时，*x*的值将从其先前的值减少五个单位，并且图像将被渲染到该位置。由于这个动画只允许角色在水平方向上移动，要么在正的*X*轴上，要么在负的*X*轴上，y 坐标没有变化。同样，对于右移动，我们将从`walkRight`的图像池中渲染图像到指定的(*x*, *y*)位置。在代码的 else 部分，我们`blit`一个 char 图像，这是一个角色静止的图像，没有移动。因此，`walkCount`等于零。在我们`blit`完所有东西之后，我们必须更新它以反映这些变化。我们通过调用`display.update`方法来做到这一点。

让我们运行动画并观察输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/d090b846-6b24-4c12-9ce4-197a81fc49fa.png)

在控制台中，如果你按下左箭头键，角色将开始向左移动，如果你按下右箭头键，角色将向右移动。由于 y 坐标没有变化，并且我们没有在主循环中处理任何事件来促进垂直移动，角色只能在水平方向移动。我强烈建议你尝试这些精灵，并尝试通过改变 y 坐标来处理垂直移动。虽然我已经为你提供了一个包含图像列表的资源列表，但如果你想在游戏中使用其他精灵，你可以去以下网站下载任何你想要的精灵：[`www.spriters-resource.com/`](https://www.spriters-resource.com/)。这个网站对于任何 pygame 开发者来说都是一个天堂，所以一定要去访问并下载任何你想要的游戏精灵，这样你就可以尝试这个（用马里奥来尝试可能会更好）。

从下一节开始，我们将开始制作 Flappy Bird 游戏的克隆。我们将学习滚动背景和角色动画、随机对象生成、碰撞和得分等技术。

# 滚动背景和角色动画

现在你已经了解足够关于 pygame 精灵和动画，你有能力制作一个包含复杂精灵动画和多个对象的游戏。在这一部分，我们将通过制作一个 Flappy Bird 游戏来学习滚动背景和角色动画。这个游戏包含多个对象，鸟是游戏的主角，游戏中的障碍物是一对管道。如果你以前没有玩过这个游戏，可以访问它的官方网站试一试：[`flappybird.io/`](https://flappybird.io/)。

说到游戏，制作起来并不难，但通过照顾游戏编程的多个方面，对于初学者来说可能是一项艰巨的任务。话虽如此，我们不打算自己制作任何精灵——它们在互联网上是免费提供的。这使得我们的任务变得更加容易。由于游戏角色的设计是开源的，我们可以直接专注于游戏的编码部分。但是，如果你想从头开始设计你的游戏角色，可以使用任何简单的绘图应用程序开始制作它们。对于这个 Flappy Bird 游戏，我将使用免费提供的精灵。

我已经在 GitHub 链接中添加了资源。如果你打开图像文件夹，然后打开背景图像文件，你会看到它包含特定高度和宽度的背景图像。但是在 Flappy Bird 游戏中，你可以观察到背景图像是连续渲染的。因此，使用 pygame，我们可以制作一个滚动背景，这样我们就可以连续`blit`背景图像。因此，我们可以使用一张图像并连续`blit`它，而不是使用成千上万份相同的背景图像副本。

让我们从制作一个角色动画和一个滚动背景开始。以下步骤向我们展示了如何使用面向对象编程为每个游戏角色制作一个类：

1.  首先，你必须开始声明诸如 math、os（用于加载具有指定文件名的图像）、random、collections 和 pygame 等模块。你还必须声明一些变量，表示每秒帧数设置、动画速度和游戏控制台的高度和宽度：

```py
 import math
 import os
 from random import randint
 from collections import deque

 import pygame
 from pygame.locals import *

      Frame_Rate = 60 #FPS
      ANIMATION_SPEED = 0.18 # pixels per millisecond
      WINDOW_WIDTH = 284 * 2 # Background image sprite size: 284x512 px;                                                                                                  
                              #our screen is twice so to rendered twice: *2
      WINDOW_HEIGHT = 512 
```

1.  现在，让我们将图像文件夹中的所有图像加载到 Python 项目中。我还将创建两个方法，用于在帧和毫秒之间进行转换。

1.  让我们看看`loading_Images`函数是如何通过以下代码工作的：

```py

 def loading_Images():
       """Function to load images"""
  def loading_Image(image_name):

 """Return the sprites of pygame by create unique filename so that 
           we can reference them"""
 new_filename = os.path.join('.', 'images', image_name)
              image = pygame.image.load(new_filename) #loading with pygame 
                                                       module 
              image.convert()
              return image

          return {'game_background': loading_Image('background.png'),
  'endPipe': loading_Image('endPipe.png'),
  'bodyPipe': loading_Image('bodyPipe.png'),
  # GIF format file/images are not supported by Pygame
  'WingUp': loading_Image('bird-wingup.png'),
  'WingDown': loading_Image('bird-wingdown.png')}
```

在前面的程序中，我们定义了`loading_Image`函数，它从特定目录加载/提取所有图像，并将它们作为包含名称作为键和图像作为值的字典返回。让我们通过以下参数分析这样一个字典中的键和值将如何存储：

+   `background.png`：Flappy Bird 游戏的背景图像。

+   `img:bird-wingup.png`：这张 Flappy Bird 的图像有一只翅膀向上指，当在游戏中点击屏幕时渲染。

+   `img:bird-wingdown.png`：这部分图像在 Flappy Bird 自由下落时使用，也就是当用户没有点击屏幕时。这张图像有 Flappy Bird 的翅膀向下指。

+   `img:bodyPipe.png`：这包含了可以用来创建单个管道的离散身体部位。例如，在 Flappy Bird 游戏中，应该从顶部和底部渲染两个离散的管道片段，它们之间留有一个间隙。

+   `img:endPipe.png`：这部分图像是管道对的底部。有两种类型的这样的图像：小管道对的小管道底部和大管道对的大管道底部图像。

同样，我们有一个嵌套的`loading_Image`函数，用于为每个加载的精灵创建一个文件名。它从`/images/文件夹`加载图像。在连续加载每个图像之后，它们会使用`convert()`方法进行调用，以加快 blitting（渲染）过程。传递给`loading_Image`函数的参数是图像的文件名。`image_name`是给定的文件名（连同其扩展名；`.png`是首选）通过`os.path.join`方法加载它，以及`convert()`方法以加快 blitting（渲染）过程。

加载图像后，我们需要创建两个函数，用于在指定的帧速率下执行帧率的转换（请参阅第十章，*使用海龟升级贪吃蛇游戏*，了解更多关于帧速率的信息）。这些函数集主要执行从帧到毫秒的转换以及相反的转换。帧到毫秒的转换很重要，因为我们必须使用毫秒来移动`Bird`角色，也就是鸟要上升的毫秒数，一个完整的上升需要`Bird.CLIMB_DURATION`毫秒。如果你想让鸟在游戏开始时做一个（小）上升，可以使用这个。让我们创建这样两组函数（代码的详细描述也可以在 GitHub 上找到：[`github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter12`](https://github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter12)）：

```py
def frames_to_msec(frames, fps=FPS):
    """Convert frames to milliseconds at the specified framerate.   Arguments: frames: How many frames to convert to milliseconds. fps: The framerate to use for conversion.  Default: FPS. """  return 1000.0 * frames / fps

def msec_to_frames(milliseconds, fps=FPS):
    """Convert milliseconds to frames at the specified framerate.   Arguments: milliseconds: How many milliseconds to convert to frames. fps: The framerate to use for conversion.  Default: FPS. """  return fps * milliseconds / 1000.0
```

现在，为鸟角色声明一个类。回想一下第六章，*面向对象编程*，我们学到每个实体都应该由一个单独的类来表示。在 Flappy Bird 游戏中，代表`PipePair`（障碍物）的实体或模型与另一个实体（比如鸟）是不同的。因此，我们必须创建一个新的类来表示另一个实体。这个类将代表由玩家控制的鸟。由于鸟是我们游戏的“英雄”，鸟角色的任何移动只允许由玩游戏的用户来控制。玩家可以通过点击屏幕使鸟上升（快速上升），否则它会下沉（缓慢下降）。鸟必须通过管道对之间的空间，每通过一个管道就会得到一个积分。同样，如果鸟撞到管道，游戏就结束了。

现在，我们可以开始编写我们的主角了。你还记得如何做吗？这是任何优秀游戏程序员的最重要特征之一——他们会进行大量头脑风暴，然后写出小而优化的代码。因此，让我们先进行头脑风暴，预测我们想要如何构建鸟角色，以便之后可以无缺陷地编写代码。以下是一些必须作为 Bird 类成员定义的基本属性和常量：

+   **类的属性**：`x`是鸟的 X 坐标，`y`是鸟的 Y 坐标，`msec_to_climb`表示鸟要上升的毫秒数，一个完整的上升需要`Bird.CLIMB_DURATION`毫秒。

+   **常量**：

+   `WIDTH`：鸟图像的宽度（以像素为单位）。

+   `HEIGHT`：鸟图像的高度（以像素为单位）。

+   `SINK_SPEED`：鸟在不上升时每毫秒下降的像素速度。

+   `CLIMB_SPEED`：鸟在上升时每毫秒上升的像素速度，平均而言。更多信息请参阅`Bird.update`文档字符串。

+   `CLIMB_DURATION`：鸟执行完整上升所需的毫秒数。

现在我们已经有了关于游戏中鸟角色的足够信息，我们可以开始为其编写代码了。下面的代码行表示 Bird 类，其中成员被定义为类属性和常量：

```py
class Bird(pygame.sprite.Sprite):     WIDTH = HEIGHT = 50
  SINK_SPEED = 0.18
  CLIMB_SPEED = 0.3   CLIMB_DURATION = 333.3    def __init__(self, x, y, msec_to_climb, images):
        """Initialize a new Bird instance."""    super(Bird, self).__init__() 
        self.x, self.y = x, y
        self.msec_to_climb = msec_to_climb
        self._img_wingup, self._img_wingdown = images
        self._mask_wingup = pygame.mask.from_surface(self._img_wingup)
        self._mask_wingdown = pygame.mask.from_surface(self._img_wingdown)
```

让我们来谈谈鸟类内部定义的构造函数或初始化器。它包含许多参数，可能会让你感到不知所措，但它们实际上很容易理解。在构造函数中，我们通常定义类的属性，比如代表鸟位置的 x 和 y 坐标，以及其他参数。现在让我们来看看这些：

+   `x`：鸟的初始 X 坐标。

+   `y`：鸟的初始 Y 坐标。

+   `msec_to_climb`: 剩余的毫秒数要爬升，完整的爬升需要 `Bird.CLIMB_DURATION` 毫秒。如果你想让小鸟在游戏开始时做一个（小）爬升，可以使用这个。

+   `images`: 包含此小鸟使用的图像的元组。它必须按照以下顺序包含以下图像：

+   小鸟上飞时的翅膀

+   小鸟下落时的翅膀

最后，应声明三个重要属性。这些属性是`image`、`mask`和`rect`。想象属性是小鸟在游戏中的基本动作。它可以上下飞行，这在图像属性中定义。然而，小鸟类的另外两个属性相当不同。`rect`属性将获取小鸟的位置、高度和宽度作为`Pygame.Rect`（矩形的形式）。记住，`pygame`可以使用`rect`属性跟踪每个游戏角色，类似于一个无形的矩形将被绘制在精灵周围。mask 属性获取一个位掩码，可用于与障碍物进行碰撞检测：

```py
@property def image(self):
    "Gets a surface containing this bird image"   if pygame.time.get_ticks() % 500 >= 250:
        return self._img_wingup
    else:
        return self._img_wingdown

@property def mask(self):
    """Get a bitmask for use in collision detection.   The bitmask excludes all pixels in self.image with a transparency greater than 127."""  if pygame.time.get_ticks() % 500 >= 250:
        return self._mask_wingup
    else:
        return self._mask_wingdown

@property def rect(self):
    """Get the bird's position, width, and height, as a pygame.Rect."""
  return Rect(self.x, self.y, Bird.WIDTH, Bird.HEIGHT)
```

由于我们已经熟悉了`rect`和`mask`属性的概念，我就不再重复了，所以让我们详细了解一下图像属性。图像属性获取指向小鸟当前图像的表面。这将决定根据`pygame.time.get_ticks()`返回一个图像，其中小鸟的可见翅膀指向上方或指向下方。这将使 Flappy Bird 动画化，即使 pygame 不支持*动画 GIF*。

现在是时候结束`Bird`类了，但在此之前，你必须声明一个方法，用于更新小鸟的位置。确保你阅读了我在三引号中添加的描述，作为注释：

```py
def update(self, delta_frames=1):
    """Update the bird's position.
 One complete climb lasts CLIMB_DURATION milliseconds, during which the bird ascends with an average speed of CLIMB_SPEED px/ms. This Bird's msec_to_climb attribute will automatically be decreased accordingly if it was > 0 when this method was called.   Arguments: delta_frames: The number of frames elapsed since this method was last called. """  if self.msec_to_climb > 0:
        frac_climb_done = 1 - self.msec_to_climb/Bird.CLIMB_DURATION
        #logic for climb movement
        self.y -= (Bird.CLIMB_SPEED * frames_to_msec(delta_frames) *
                   (1 - math.cos(frac_climb_done * math.pi)))
        self.msec_to_climb -= frames_to_msec(delta_frames)
    else:
        self.y += Bird.SINK_SPEED * frames_to_msec(delta_frames)
```

数学`cosine(angle)`函数用于使小鸟平稳爬升。余弦是一个偶函数，这意味着小鸟会做一个平稳的爬升和下降运动：当小鸟在屏幕中间时，可以执行一个高跳，但当小鸟靠近顶部/底部边界时，只能做一个轻微的跳跃（这是 Flappy Bird 运动的基本原理）。

让我们运行游戏，看看小鸟是如何渲染的。然而，我们还没有创建任何逻辑来让玩家玩游戏（我们很快会做到）。现在，让我们运行游戏，观察界面的样子：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/be35d72a-846f-4d44-b17f-72a7b29304f2.png)

根据上述代码，你必须能够创建一个完整的`Bird`类，其中包含用于遮罩、更新和获取位置（即高度和宽度）的属性，使用`rect`。我们 Flappy Bird 游戏中的小鸟角色仅与运动相关——垂直上下移动。我们游戏中的下一个角色是管道（小鸟的障碍物），处理起来相当复杂。我们必须随机连续地`blit`管道对。让我们看看如何做到这一点。

# 理解随机对象生成

我们已经在前面的部分中介绍了`Bird`角色的动画。它包括一系列处理小鸟垂直运动的属性和特性。由于`Bird`类仅限于为小鸟角色执行动作，我们无法向其添加任何其他角色属性。例如，如果你想在游戏中为障碍物（管道）添加属性，不能将其添加到`Bird`类中。你必须创建另一个类来定义下一个对象。这个概念被称为封装（我们在第六章中学习过，*面向对象编程*），其中代码和数据被包装在一个单元内，以便其他实体无法伤害它。

让我们创建一个新的类来生成游戏的障碍物。你必须首先定义一个类，以及一些常量。我已经在代码中添加了注释，以便你能理解这个类的主要用途：

```py
class PipePair(pygame.sprite.Sprite):
    """class that provides obstacles in the way of the bird in the form of pipe-pair.""" 

 WIDTH = 80
  HEIGHT_PIECE = 32
  ADD_INTERVAL = 3000
```

在我们实际编写这个`PipePair`类之前，让我给你一些关于这个类的简洁信息，以便你能理解以下每个概念。我们将使用不同的属性和常量，如下所示：

+   `PipePair`类：一个管道对（两根管道的组合）被插入以形成两根管道，它们之间只提供了一个小间隙，这样小鸟才能穿过它们。每当小鸟触碰或与任何管道对碰撞时，游戏就会结束。

+   **属性**：`x`是`pipePair`的*X*位置。这个值是一个浮点数，以使移动更加平滑。`pipePair`没有*Y*位置，因为它在*y*方向上不会改变；它始终保持为 0。

+   `image`：这是`pygame`模块提供的表面，用于`blit` `pipePair`。

+   `mask`：有一个位掩码，排除了所有`self.image`中透明度大于 127 的像素。这可以用于碰撞检测。

+   `top_pieces`：顶部管道与末端部分的组合，这是管道顶部部分的基础（这是一个由管道顶部部分组成的一对）。

+   `bottom_pieces`：下管道（向上指向的隧道）与末端部分的组合，这是底部管道的基础。

+   **常量**：

+   `WIDTH`：管道片段的宽度，以像素为单位。因为管道只有一片宽，这也是`PipePair`图像的宽度。

+   `PIECE_HEIGHT`：管道片段的高度，以像素为单位。

+   `ADD_INTERVAL`：添加新管道之间的间隔，以毫秒为单位。

正如我们已经知道的，对于任何类，我们需要做的第一件事就是初始化一个类或构造函数。这个方法将初始化新的随机管道对。以下截图显示了管道对应该如何渲染。管道有两部分，即顶部和底部，它们之间插入了一个小空间：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/66b04e30-29e3-4eaf-b559-771accc219a8.png)

让我们为`PipePair`类创建一个初始化器，它将`blit`管道的底部和顶部部分，并对其进行蒙版处理。让我们了解一下需要在这个构造函数中初始化的参数：

+   `end_image_pipe`：代表管道底部（末端部分）的图像

+   `body_image_pipe`：代表管道垂直部分（管道的一部分）的图像

管道对只有一个 x 属性，y 属性为 0。因此，`x`属性的值被赋为`WIN_WIDTH`，即`float(WIN_WIDTH - 1)`。

以下步骤代表了需要添加到构造函数中以在游戏界面中创建一个随机管道对的代码：

1.  让我们为`PipePair`初始化一个新的随机管道对：

```py
 def __init__(self, end_image_pipe, body_image_pipe):
          """Initialises a new random PipePair.  """  self.x = float(WINDOW_WIDTH - 1)
          self.score_counted = False
  self.image = pygame.Surface((PipePair.WIDTH, WINDOW_HEIGHT), 
                       SRCALPHA)
          self.image.convert() # speeds up blitting
  self.image.fill((0, 0, 0, 0))

        #Logic 1: **create pipe-pieces**--- Explanation is provided after
                     the code
 total_pipe_body_pieces = int((WINDOW_HEIGHT - # fill window from 
                                                           top to bottom
  3 * Bird.HEIGHT - # make room for bird to fit through
  3 * PipePair.HEIGHT_PIECE) / # 2 end pieces + 1 body piece
  PipePair.HEIGHT_PIECE # to get number of pipe pieces
  )
 self.bottom_pipe_pieces = randint(1, total_pipe_body_pieces)
 self.top_pipe_pieces = total_pipe_body_pieces - 
 self.bottom_pieces
```

1.  接下来，我们需要定义两种类型的管道对——底部管道和顶部管道。添加管道对的代码会将管道图像 blit，并且只关心管道对的*y*位置。管道对不需要水平坐标（它们应该垂直渲染）：

```py
       # bottom pipe
  for i in range(1, self.bottom_pipe_pieces + 1):
              piece_pos = (0, WIN_HEIGHT - i*PipePair.PIECE_HEIGHT)
              self.image.blit(body_image_pipe, piece_pos)
          end_y_bottom_pipe = WIN_HEIGHT - self.bottom_height_px
          bottom_end_piece_pos = (0, end_y_bottom_pipe - 
                                 PipePair.PIECE_HEIGHT)
          self.image.blit(end_image_pipe, bottom_end_piece_pos)

          # top pipe
  for i in range(self.top_pipe_pieces):
              self.image.blit(body_image_pipe, (0, i * 
                   PipePair.PIECE_HEIGHT))
          end_y_top_pipe = self.top_height_px
          self.image.blit(end_image_pipe, (0, end_y_top_pipe))

          # external end pieces are further added to make compensation
  self.top_pipe_pieces += 1
  self.bottom_pipe_pieces += 1    # for collision detection
  self.mask = pygame.mask.from_surface(self.image)
```

尽管代码旁边提供的注释有助于理解代码，但我们需要以更简洁的方式了解逻辑。`total_pipe_body_piece`变量存储了一帧中可以添加的管道数量的高度。例如，它推断了可以插入当前实例的底部管道和顶部管道的数量。我们将其强制转换为整数，因为管道对始终是整数。`bottom_pipe_piece`类属性表示底部管道的高度。它可以在 1 到`total_pipe_piece`支持的最大宽度范围内。类似地，顶部管道的高度取决于总管道件数。例如，如果画布的总高度为 10，底部管道的高度为 1，那么通过在两个管道对之间留下一个间隙（假设为 3），剩下的高度应该是顶部管道的高度（即其高度为 10 - (3+1) = 6），这意味着除了管道对之间的间隙外，不应提供其他间隙。

前面的代码中的所有内容都是不言自明的。尽管代码很简单，但我希望你专注于代码的最后一行，我们用它来检测碰撞。检测的过程很重要，因为在 Flappy Bird 游戏中，我们必须检查小鸟是否与管道对发生碰撞。通常通过使用`pygame.mask`模块添加蒙版来实现。

现在，是时候向`PipePair`类添加一些属性了。我们将添加四个属性：`visible`、`rect`、`height_topPipe_px`和`height_bottomPipe_px`。`rect`属性的工作方式类似于`Bird`类的`rect`调用，它返回包含`PipePair`的矩形。类的`visible`属性检查管道对在屏幕上是否可见。另外两个属性返回以像素为单位的顶部和底部管道的高度。以下是`PipePair`类的前四个属性的代码：

```py
@property def height_topPipe_px(self):
 """returns the height of the top pipe, measurement is done in pixels"""
  return (self.top_pipe_pieces * PipePair.HEIGHT_PIECE)

@property def height_bottomPipe_px(self):
 """returns the height of the bottom pipe, measurement is done in pixels"""
  return (self.bottom_pipe_pieces * PipePair.HEIGHT_PIECE)

@property def visible(self):
    """Get whether this PipePair on screen, visible to the player."""
  return -PipePair.WIDTH < self.x < WINDOW_WIDTH

@property def rect(self):
    """Get the Rect which contains this PipePair."""
  return Rect(self.x, 0, PipePair.WIDTH, PipePair.HEIGHT_PIECE)
```

现在，在封装之前，我们需要向`PipePair`类添加另外两个方法。第一个方法`collides_with`将检查小鸟是否与管道对中的管道发生碰撞：

```py
def collides_with(self, bird):
    """check whether bird collides with any pipe in the pipe-pair. The 
       collide-mask deploy a method which returns a list of sprites--in 
       this case images of bird--which collides or intersect with 
       another sprites (pipe-pair)   Arguments: bird: The Bird which should be tested for collision with this PipePair. """  return pygame.sprite.collide_mask(self, bird)
```

第二个方法`update`将更新管道对的位置：

```py
def update(self, delta_frames=1):
    """Update the PipePair's position.   Arguments: delta_frames: The number of frames elapsed since this method was last called. """  self.x -= ANIMATION_SPEED * frames_to_msec(delta_frames)
```

现在我们知道每个方法的工作原理，让我们看看代码的运行情况。在运行游戏之前，你不会了解游戏中的任何缺陷。花时间运行游戏并观察输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/3876e226-50d8-48e1-9258-9fc566b22a87.png)

好的，游戏足够吸引人了。点击事件完美地工作，背景图像与鸟的图像一起呈现，并且上升和下沉动作的物理效果也很好。然而，你可能已经观察到一个奇怪的事情（如果没有，请看前面的截图），即在与管道对碰撞后，我们的小鸟能够继续向前移动。这是我们游戏中的一个大缺陷，我们不希望出现这种情况。相反，我们希望在发生这种情况时关闭游戏。因此，为了克服这样的错误，我们必须使用碰撞的概念（一种处理多个游戏对象相互碰撞的技术）。

现在我们已经完成了两个游戏角色类，即`Bird`和`PipePair`，让我们继续制作游戏的物理部分：初始化显示和处理碰撞。

# 检测碰撞

*处理碰撞*的过程是通过找出两个独立对象触碰时必须执行的操作来完成的。在前面的部分中，我们为每个对象添加了一个掩码，以检查两个对象是否发生碰撞。`pygame`模块使得检查碰撞过程非常容易；我们可以简单地使用`sprite.collide_mask`来检查两个对象是否接触。然而，这个方法所需的参数是掩码对象。在前一节中，我们添加了`collides_with`方法来检查鸟是否与管道对中的一个碰撞。现在，让我们使用该方法来检查碰撞。

除了检测碰撞，我们还将为游戏制作一个物理布局/模板。我在这一部分没有强调基本的 pygame 布局，因为自从我们开始做这个以来，这对你来说应该是不言自明的。以下步骤描述了制作一个检测游戏角色碰撞（`Bird`与`pipePairs`）的模型的布局：

1.  首先定义主函数，之后将被外部调用：

```py
 def main():
          """Only function that will be externally called, this 
            is main function  Instead of importing externally, if we call this function from 
            if **name** == __main__(), this main module will be executed.  """   pygame.init()

          display_surface = pygame.display.set_mode((WIN_WIDTH, 
              WIN_HEIGHT)) #display for screen

          objectClock = pygame.time.Clock()   images = loading_Images()
```

1.  让我们创建一些逻辑，使鸟出现在屏幕的中心。如果你玩过 Flappy Bird 游戏，你会知道鸟被放在画布的中心，它可以向上或向下移动：

```py
       #at any moment of game, bird can only change its y position, 
         so x is constant
          #lets put bird at center           Objectbird = Bird(50, int(WIN_HEIGHT/2 - Bird.HEIGHT/2), 2,
  (images['WingUp'], images['WingDown']))

          pipes = deque() 
      #deque is similar to list which is preferred otherwise 
         if we need faster operations like 
      #append and pop

          frame_clock = 0 # this counter is only incremented 
            if the game isn't paused
```

1.  现在，我们必须将管道对图像添加到`pipes`变量中，因为一个管道是由`pipe-body`和`pipe-end`连接而成的。这个连接是在`PipePair`类内部完成的，因此在创建实例后，我们可以将管道对附加到管道列表中：

```py
  done = paused = False
 while not done:
              clock.tick(FPS)

              # Handle this 'manually'.  
                If we used pygame.time.set_timer(),
 # pipe addition would be messed up when paused.  if not (paused or frame_clock % 
                msec_to_frames(PipePair.ADD_INTERVAL)):
                  pipe_pair = PipePair(images['endPipe'], 
                    images['bodyPipe'])
                  pipes.append(pipe_pair)
```

1.  现在，处理用户的操作。由于 Flappy Bird 游戏是一个点击游戏，我们将处理鼠标事件（参考我们在第十一章中涵盖的*鼠标控制*部分，*使用 Pygame 制作超越乌龟-贪吃蛇游戏 UI*）：

```py
      *#handling events
          **#Since Flappy Bird is Tapped game**
 **#we will handle mouse events***
 *for anyEvent in pygame.event.get():
              #EXIT GAME IF QUIT IS PRESSED*
 *if anyEvent.type == QUIT or (anyEvent.type == KEYUP and 
                anyEvent.key == K_ESCAPE):*
 *done = True
 break elif anyEvent.type == KEYUP and anyEvent.key in 
              (K_PAUSE, K_p):* *paused = not paused*
 *elif anyEvent.type == MOUSEBUTTONUP or 
                (anyEvent.type == KEYUP and anyEvent.key in 
                (K_UP, K_RETURN, K_SPACE)):* *bird.msec_to_climb = 
                Bird.CLIMB_DURATION*

           if paused: 
              continue #not doing anything [halt position]  
```

1.  最后，这就是你一直在等待的：如何利用 Python 的`pygame`模块构建碰撞接口。在完成这些步骤的其余部分后，我们将详细讨论以下代码的突出部分：

```py
 # check for collisions  pipe_collision = any(eachPipe.collides_with(bird) 
                for eachPipe in pipes)
 if pipe_collision or 0 >= bird.y or 
                bird.y >= WIN_HEIGHT - Bird.HEIGHT:
 done = True
 #blit background for position_x_coord in (0, WIN_WIDTH / 2):
 display_surface.blit(images['game_background'], 
                    (position_x_coord, 0))

              #pipes that are out of visible, remove them
 while pipes and not pipes[0].visible:
 pipes.popleft()

 for p in pipes:
 p.update()
 display_surface.blit(p.image, p.rect)

 bird.update()
 display_surface.blit(bird.image, bird.rect) 
```

1.  最后，以一些多余的步骤结束程序，比如使用更新函数渲染游戏，给用户一个多余的消息等等：

```py
              pygame.display.flip()
              frame_clock += 1
          print('Game Over!')
          pygame.quit()
      #----------uptill here add it to main function----------

      if __name__ == '__main__':
        #indicates two things:
        #In case other program import this file, then value of 
           __name__ will be flappybird
        #if we run this program by double clicking filename 
           (flappybird.py), main will be called

          main()     #calling main function
```

在前面的代码中，突出显示的部分很重要，所以确保你理解它们。在这里，`any()`函数通过检查鸟是否与管道对碰撞来返回一个布尔值。根据这个检查，如果是`True`，我们就退出游戏。我们还将检查鸟是否触碰到了水平最低或水平最高的边界，如果是的话也会退出游戏。

让我们运行游戏并观察输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/4296ca36-a86e-479b-9b3b-7178b05417fe.png)

游戏已经足够可玩了，所以让我们为游戏添加一个告诉玩家他们得分如何的功能。

# 得分和结束屏幕

给 Flappy Bird 游戏添加分数非常简单。玩家的分数将是玩家通过的管道或障碍物的数量。如果玩家通过了 20 个管道，他们的分数将是 20。让我们给游戏添加一个得分屏幕：

```py
score = 0
scoreFont = pygame.font.SysFont(None, 30, bold=True) #Score default font: WHITE

while not done:
    #after check for collision
    # procedure for displaying and updating scores of player
     for eachPipe in pipes:
         if eachPipe.x + PipePair.WIDTH < bird.x and not 
           eachPipe.score_counted: 
            #when bird crosses each pipe
             score += 1
             eachPipe.score_counted = True

     Surface_Score = scoreFont.render(str(score), 
        True, (255, 255, 255)) #surface
     x_score_dim = WIN_WIDTH/2 - score_surface.get_width()/2 
     #to render score, no y-position
     display_surface.blit(Surface_Score, (x_score_dim, 
        PipePair.HEIGHT_PIECE)) #rendering

     pygame.display.flip() #update
     frame_clock += 1
print('Game over! Score: %i' % score)
pygame.quit() 
```

现在，游戏看起来更吸引人了：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/70199436-5df8-4e03-acf8-bef436d2120a.png)

在下一节中，我们将看看如何测试一切，并尝试应用一些修改。

# 游戏测试

虽然 Flappy Bird 可以修改的地方较少，但你总是可以通过修改一些游戏角色属性来测试游戏，以改变游戏的难度。在前一节中，我们运行了我们的游戏，并看到管道对之间有很大的空间。这将使游戏对许多用户来说非常容易，所以我们需要通过缩小两个管道对之间的空间来增加难度。例如，在`Bird`类中，我们声明了四个属性。将它们更改为不同的值以观察效果：

```py
WIDTH = HEIGHT = 30 #change it to make space between pipe pairs 
                     smaller/bigger SINK_SPEED = 0.18 #speed at which bird falls CLIMB_SPEED = 0.3 #when user taps on screen, it is climb speed
                  #make it smaller to make game harder CLIMB_DURATION = 333.3
```

您还可以改变游戏属性的值，使您的游戏看起来独一无二。Flappy Bird 中使用的一些不同游戏属性包括*每秒帧数*和*动画速度*。您可以改变这些值来实现必要的变化。虽然您可以改变动画速度的值，但对于 Flappy Bird 游戏来说，每秒帧数为 60 是足够的。

与手动调试和搜索可能的修改不同，您可以简单地在调试模式下运行程序以更快地测试它。假设您已经在 Pycharm 的 IDE 中编写了 Flappy Bird 游戏（我推荐这样做），您可以通过按下*Shift* + *F9*或简单地点击运行选项卡并从那里以调试模式运行程序。运行后，尝试玩游戏，并尝试使其适应用户可能遇到的任何情况。任何错误都将出现在程序的终端中，您可以从中跳转到具有多个错误的程序位置。

# 总结

在本章中，我们更深入地探讨了精灵动画和碰撞的概念。我们看了如何为几何形状制作简单动画，创建复杂的精灵动画，并了解了在某些情况下哪种方法最有效。我们将 pygame 的事件处理方法与动画逻辑相结合，根据当前的游戏状态渲染图像。基本上，动画逻辑维护一个队列，用户事件将被存储在其中。一次获取一个动作将图像渲染到一个位置。

使用 pygame 制作的游戏原型有三个核心模块：加载精灵（原始精灵或从互联网下载的精灵）、处理用户事件和动画逻辑，控制游戏角色的移动。有时，您可能不是拥有独立的精灵图像，而是精灵表—包含角色图像的表。您可以使用在线工具或甚至 pygame 的`rect`方法来裁剪它们。在获得游戏的适当图像或精灵后，我们处理了用户事件，并创建了动画逻辑来使游戏精灵移动。我们还研究了 pygame 的遮罩属性，可以用来检测对象之间的碰撞。

完成本章后，您现在了解了游戏控制器和动画，已经了解了碰撞原理（包括 pygame 的遮罩属性），已经了解了精灵动画（创建角色的奔跑动画），并已经了解了添加交互式记分屏幕以使游戏更加用户友好。

您在本章中获得的知识可以应用的领域范围广泛，对大多数 Python pygame 开发人员来说是*纯金*。处理精灵对于几乎所有基于 pygame 的游戏都很重要。尽管角色动画、碰撞和移动是简单但强大的概念，但它们是使 Python 游戏具有吸引力和互动性的三个主要方面。现在，尝试创建一个简单的**角色扮演游戏**（**RPG**）游戏，比如 Junction Jam（如果您还没有听说过，可以搜索一下），并尝试在其中嵌入碰撞和精灵移动的概念。

在下一章中，我们将通过创建游戏网格和形状来学习 pygame 的基本图形编程。我们将通过编写俄罗斯方块游戏来学习多维列表处理和有效空间确定。


# 第十三章：使用 Pygame 编写俄罗斯方块游戏

*打破常规思维*，这是一个老话，对于游戏开发者来说可能听起来陈词滥调，但仍然非常适用。大多数改变游戏行业的游戏都包含一些独特的元素，并代表了普通观众的口味。但这种全球性的假设通过丢弃可能在大多数游戏开发者中普遍存在的方法而被高估。毕竟，数学范式、对象渲染工具和软件保持不变。因此，在本章中，我们将探索一些每个游戏程序员都必须了解的高级数学变换和范式。

在本章中，我们将学习如何创建本世纪最受欢迎和下载量最大的游戏之一，这是 90 年代孩子们非常熟悉的游戏——*俄罗斯方块*。我们将学习如何通过从多维列表中格式化的形状来从头开始创建它。我们将学习如何绘制基本图形和游戏网格，这将帮助我们定位游戏对象。我们还将学习如何实现几何形状和图形的旋转变换。尽管这个概念听起来可能很简单，但这些概念的应用范围从不同的 2D 到 3D 的**角色扮演游戏**（**RPGs**）。

通过本章结束时，您将熟悉不同的概念，如创建网格（虚拟和物理）结构，以根据位置和颜色代码定位游戏对象。然后，您将学习如何使用列表推导来处理多维列表。此外，读者还将了解不同的移位变换和碰撞检查原则。在上一章中，我们使用 pygame 使用掩码实现了碰撞检查。然而，在本章中，我们将以程序员的方式来做这件事——这可能有点复杂，但包含了丰富的知识。

在本章中，我们将涵盖以下主题：

+   了解俄罗斯方块的基本要素

+   创建网格和随机形状

+   设置窗口和游戏循环

+   转换形状格式

+   修改游戏循环

+   清除行

+   游戏测试

# 技术要求

您需要以下要求才能完成本章：

+   Pygame 编辑器（IDLE）—建议使用 3.5+版本。

+   PyCharm IDE-参考第一章，*了解 Python-设置 Python 和编辑器*，了解安装过程。

+   俄罗斯方块游戏的代码资产可以在 GitHub 上找到，网址为[`github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter13`](https://github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter13)

查看以下视频以查看代码的运行情况：

[`bit.ly/2oDbq2J`](http://bit.ly/2oDbq2J)

# 了解俄罗斯方块的基本要素

将 pygame 精灵和图像合并到我们的 Python 游戏中是一个简单的过程。它需要一个内置的 Python 模块—*os—*，它将从您的计算机加载文件。在上一章中，我们在构建 Flappy Bird 游戏时学习了如何对精灵进行旋转、平移和碰撞，并逐个处理它们。这些变换不仅仅适用于图像，还适用于不同的几何图形和形状。当我们谈论使用这样的变换操作时，俄罗斯方块是每个人心中的游戏——玩家被允许通过周期运动改变几何形状的形状和大小。这种周期性运动将在顺时针和逆时针方向上创建逼真的几何形状的旋转变换。对于不熟悉俄罗斯方块的人，请查看[`www.freetetris.org/game.php`](https://www.freetetris.org/game.php)并观察游戏的网格和环境。

通过观察游戏环境，您会注意到三个主要的事情：

+   **几何形状，如 L、T、S、I 和正方形**：这些几何形状将以字母字符的形式呈现，并且为了区分它们，每个形状将有不同的颜色。

+   **网格**：这将是几何形状可以移动的地方。这将是游戏画布，几何形状将从顶部落到底部。玩家无法控制这个网格，但他们可以控制形状。

+   **旋转形状**：当形状/块向下掉落时，玩家可以使用键盘上的箭头键来改变形状的结构（请记住，只允许旋转变换）。

以下图表显示了我们将在游戏中使用的形状：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/ea74cf4a-be7c-4741-a349-b3cf92a2a87e.png)

如果你玩过上述链接中的游戏，你会看到前面的形状在游戏的网格（画布）内移动。相应的字母代表它们所类似的每个几何形状。玩家只能使用箭头键来旋转这些形状。例如，当形状**I**掉落到网格时，玩家可以在垂直**I**和水平**I**之间切换。但对于正方形形状，我们不必定义任何旋转，因为正方形（由于其相等的边）在旋转后看起来完全相同。

现在你已经熟悉了我们俄罗斯方块游戏的游戏角色（几何形状），让我们进一步进行头脑风暴，以提取关于游戏的一些关键信息。让我们谈谈俄罗斯方块的基本要素。由于俄罗斯方块需要创建不同的几何形状，毫无疑问我们将需要`pygame`模块。`pygame`模块可以用来创建网格、边界和游戏角色。你还记得`pygame`的`draw`模块（来自第十一章，*使用 Pygame 制作 Outdo Turtle - 贪吃蛇游戏 UI*）吗？显然，如果不使用`pygame`的`draw`模块，你无法制作出好的游戏。同样，为了处理用户操作事件，如键盘操作，我们需要 pygame。

函数的蓝图代表了可以通过 Python 的`pygame`模块构建的俄罗斯方块的顶层视图：

+   `build_Grid()`: 这个函数将在游戏画布中绘制网格。网格是我们可以用不同颜色渲染几何形状的地方。

+   `create_Grid()`: 这个函数将在网格中创建不同的水平线，以便我们可以跟踪每个形状进行旋转变换。

+   `rotating_shapes`：这种技术将在相同的原点内旋转几何形状。这意味着旋转不会改变对象的尺寸（长度和高度）。

现在我们已经完成了头脑风暴的过程，让我们深入了解俄罗斯方块的基本概念。俄罗斯方块的环境简单而强大。我们必须在其中绘制网格，以便我们可以跟踪不同形状的每个（*x*，*y*）位置。同样，为了跟踪每个几何形状，我们需要创建一个字典，它将以*键*的形式存储对象的**位置**，以*值*的形式存储对象的**颜色**。

让我们从为我们的游戏编写模板代码开始：

```py
import pygame
import random

#declare GLOBALS
width = 800
height = 700

#since each shape needs equal width and height as of square 
game_width = 300 #each block will have 30 width
game_height = 600 #each block will have 30 height
shape_size = 30

#check top left position for rendering shapes afterwards

top_left_x, top_left_y = (width - game_width) // 2, height - game_height
```

现在我们已经完成了为我们的游戏声明全局变量的工作，这些变量主要负责屏幕的宽度和高度，我们可以开始为游戏对象定义形状格式。在下一节中，我们将定义一个嵌套列表，我们可以用它来定义游戏对象的多个结构（主要用于几何形状）。

# 创建形状格式

接下来的信息有点棘手。我们将声明俄罗斯方块的形状格式（所有必要的几何形状）。让我们看一个简单的例子，如下所示：

```py
#Example for creating shapes I
I = [['..**0**..',
      '..**0**..',
      '..**0**..',
      '..**0**..',
      '.....'],
     ['.....',
      '**0000**.',
      '.....',
      '.....',
      '.....']] #each 0 indicates block for shapes
```

观察前面代码中的形状格式。它是一个嵌套列表，我们需要它是因为`I`支持一次旋转，这将把垂直的`I`变成水平的`I`。观察前面列表的第一个元素；它包含一个句点（`.`），以及一个标识符（`0`），表示空和块的放置。在点或句点的位置，我们不会有任何东西，所以它将保持空白。但在`0`的位置，我们将存储块。为了做到这一点，从前面的代码中删除句点，并观察只有元素`0`。你会在零索引中看到垂直`I`，在第一个索引中看到水平`I`。对于正方形形状，我们不需要额外的*旋转*，所以我们最终将在列表内部声明正方形形状的一个元素。它将是这样的：

```py
#for square shapes square = [['.....',
      '.....',
      '.00..',
      '.00..',
      '.....']]
```

现在我们知道如何为几何形状创建格式了，让我们为不同的形状创建代码的起始部分：

```py
#following is for shape I
""" first element of list represents original structure,
    Second element represents rotational shape of objects """ I = [['..0..',
      '..0..',
      '..0..',
      '..0..',
      '.....'],
     ['.....',
      '0000.',
      '.....',
      '.....',
      '.....']]
#for square shape
O = [['.....',
      '.....',
      '.00..',
      '.00..',
      '.....']]

#for shape J
J = [['.....',
      '.0...',
      '.000.',
      '.....',
      '.....'],
     ['.....',
      '..00.',
      '..0..',
      '..0..',
      '.....'],
     ['.....',
      '.....',
      '.000.',
      '...0.',
      '.....'],
     ['.....',
      '..0..',
      '..0..',
      '.00..',
      '.....']]
```

同样，让我们像之前一样为另外几个几何形状定义形状格式：

```py
#for shape L
L = [['.....',
      '...0.',
      '.000.',
      '.....',
      '.....'],
     ['.....',
      '..0..',
      '..0..',
      '..00.',
      '.....'],
     ['.....',
      '.....',
      '.000.',
      '.0...',
      '.....'],
     ['.....',
      '.00..',
      '..0..',
      '..0..',
      '.....']]
#for shape T
T = [['.....',
      '..0..',
      '.000.',
      '.....',
      '.....'],
     ['.....',
      '..0..',
      '..00.',
      '..0..',
      '.....'],
     ['.....',
      '.....',
      '.000.',
      '..0..',
      '.....'],
     ['.....',
      '..0..',
      '.00..',
      '..0..',
      '.....']]
```

现在我们已经成功地为我们的游戏定义了角色，让我们创建一个数据结构来保存这些对象，以及它们的颜色。让我们编写以下代码来实现这一点：

```py
game_objects = [I, O, J, L, T] #you can create as many as you want
objects_color = [(255, 255, 0), (255, 0, 0), (0, 0 , 255), (255, 255, 0), (128, 165, 0)] 
```

由于我们已经完成了基本的起始文件，也就是说，我们已经理解并创建了我们的游戏对象，在下一节中，我们将开始为我们的游戏创建一个网格，并将游戏对象渲染到屏幕上。

# 创建网格和随机形状

现在我们已经定义了形状的格式，是时候给它们实际的特征了。我们为形状提供特征的方式是定义尺寸和颜色。之前，我们将方块的尺寸定义为 30，这并不是任意的；形状的尺寸必须在高度和宽度上相等。在本章中我们要绘制的每个几何形状都将至少类似于正方形。感到困惑吗？看看我们定义形状格式的代码，包括句点（`.`）和字符（`0`）。如果你仔细观察列表的每个元素，你会看到正方形的格式，行和列中排列着相等数量的点。

正如我们在*了解俄罗斯方块的基本要素*部分中提到的，网格是我们游戏角色将驻留的地方或环境。玩家控制或动作只能在网格区域内激活。让我们谈谈网格在我们的游戏中如何使用。网格是屏幕以垂直和水平线的形式划分，每行和每列都由此组成。让我们自己制作一个并观察结果：

```py
#observe that this is not defined inside any class
def build_Grid(occupied = {}):
    shapes_grid = [[(0, 0, 0) for _ *in range(10)] for* _ in range(20)]
    for row in range(len(shapes_grid)):
        for column in range(len(shapes_grid[row])):
            if (column, row) in occupied:
 piece = occupied[(column, row)]
 shapes_grid[row][column] = piece
    return shapes_grid
```

前面的代码很复杂，但它是 pygame 大多数游戏的基本构建块。前面的代码将返回一个网格，显然是我们俄罗斯方块游戏的环境，但它也可以用于多种用途，比如稍加修改就可以用于制作井字游戏或吃豆人等。`build_Grid()`函数的参数是一个参数——*occupied* 字典。这个字典将从调用这个函数的地方传递给这个函数。主要是这个函数将在主函数内部调用，这将启动创建游戏网格的过程。

传递给`build_Grid`的 occupied 字典将包含一个键和一个值（因为它是一个字典）。键将表示每个块或形状所在的位置。值将包含每个形状的颜色代码，由键表示。例如，在你的打印字典中，你会看到类似`{位置:颜色代码}`的东西。

操作的下一行应该是一个让你大吃一惊的时刻。如果没有，你就错过了什么！这可以在第七章中找到，*列表推导和属性*。借助一行代码，我们定义了行和列的排列（多维列表）。它将为我们提供一系列值，可以用来创建一系列线的网格。当然，线将在主函数中稍后借助`pygame`的`draw`模块来绘制。我们将创建一个包含 10 行和一个包含 20 列的列表。现在，让我们谈谈代码的最后几行（高亮部分）。这些代码将循环遍历每个占用的位置，并通过修改它将其添加到网格中。

在为我们的游戏定义环境之后，我们需要做的下一件大事是定义游戏的形状。记住，每个形状都会有这样的属性：

+   **行和列位置**：网格特定位置将被指定为一定行和列的形状或几何图形。

+   **形状名称**：形状的标识符，表示要渲染哪些形状。我们将为每个形状添加字母字符，例如，形状 S 的字符 S。

+   颜色：每个形状的颜色。

+   **旋转**：每个形状的旋转角度。

现在我们已经了解了每个形状的可用属性，让我们为形状定义类，并将每个属性附加到它上面。按照以下代码创建`Shape`类：

```py
class Shape:
    no_of_rows = 20 #for y dimension
    no_of_columns = 10 #for x dimension

    #constructor
    def __init__(self, column, row, shape):
        self.x = column
        self.y = row
        self.shape = shape
        #class attributes
        self.color = objects_color[game_objects.index(shape)] 
#get color based on character indicated by shape name or shape variable
        self.rotation = 0 
```

`objects_color`和`game_objects`变量之前已经定义，它们是两个包含一个列表中的字母字符的不同列表。另一个列表中包含它们的颜色代码。

此刻，如果你运行你的游戏，你除了一个空的黑屏之外什么也看不到，这是因为我们的网格背景是用黑色代码渲染的。我们知道，如果我们想要画任何东西，可以借助 Python 的`pygame`模块来实现。此外，我们是从网格的顶部到底部绘制形状，所以我们必须随机生成形状。因为我们有五种形状，即 I、O、J、L 和 T，我们需要随机地渲染它们，一一地。让我们编写一个函数来实现以下代码片段。记住，我们在开始时已经导入了一个随机模块：

```py
def generate_shapes():
     global game_objects, objects_color
     return Shape(4, 0, random.choice(game_objects)) #creating instance
```

前面的后端逻辑对于任何涉及几何形状和图形的游戏都是至关重要的。这种知识的范围比你想象的要广泛得多。许多 RPG 游戏，包括 Minecraft，都让玩家与不同的几何形状进行交互。因此，创建网格是至关重要的，这样我们就可以引用每个图形的位置和颜色。现在我们已经创建了一些通用逻辑，可以创建不同形状和颜色的图形，我们需要一个工具，可以将这些形状渲染到网格中，通常是通过 OpenGL 或 pygame 来完成（PyOpenGL 将在接下来的第十四章中介绍，*了解 PyOpenGL*）。然而，在 Python 的情况下，更优秀的工具将是 pygame。因此，我们将使用`pygame`模块来制作俄罗斯方块游戏的形状和字符。

在下一节中，我们将创建一些逻辑，为网格结构设置游戏窗口。我们还将尝试运行游戏并观察其环境。

# 设置窗口和游戏循环

在设置游戏对象之后，我们游戏中的下一个重要步骤是渲染网格。不要被误导以为我们已经创建了网格，因为我们定义了`build_Grid()`方法之后。虽然这是一个有效的观点，但我们建立的网格到目前为止都是虚拟的。如果你简单地调用`build_Grid`方法，你将看不到任何东西，只会看到一个黑屏，这是网格的背景。在这里，我们将为这个网格提供一个结构。使用每个位置，由行和列指定，我们将使用`pygame`模块创建一条直线。

让我们创建一个简单的函数来为我们的游戏绘制一个窗口（主窗口），网格将驻留在其中：

```py
def create_Grid(screen_surface, grid_scene):
     screen_surface.fill(0, 0, 0) #black background
     for i in range(len(grid_scene)):
     for j in range(len(grid_scene[i])):

 #draw main rectangle which represents window
     pygame.draw.rect(screen_surface, grid_scene[i][j], (top_left_x + 
       j* 30, top_left_y + i * 30, 30, 30), 0)
 #above code will draw a rectangle at the middle of surface screen 

    build_Grid(screen_surface, 20 , 10) #creating grid positions       
    pygame.draw.rect(screen_surface, (255, 0, 0), (top_left_x, top_left_y, 
      game_width, game_height), 5)
    pygame.display.update() 
```

上述代码行将创建网格的物理结构，它将有不同的行和列。在循环遍历整个网格场景或网格的位置之后，我们将进入网格范围，以便使用先前突出显示的代码部分绘制一个矩形和网格边框。

同样，让我们通过为其定义边界来为这个网格提供物理结构。每一行和每一列都将通过在其中创建线条来区分。由于我们可以使用 pygame `draw`模块绘制线条，我们将使用它来编写以下函数：

```py
"""function that will create borders in each row and column positions """

def show_grid(screen_Surface, grid):
    """ --- following two variables will show from where to 
     draw lines---- """
    side_x = top_left_x
    side_y = top_left_y 
    for eachRow in range(grid):
        pygame.draw.line(screen_Surface, (128,128,128), (side_x, side_y+ 
        eachRow*30), (side_x + game_width, side_y + eachRow * 30))  
         # drawing horizontal lines (30) 
        for eachCol in range(grid[eachRow]):
            pygame.draw.line(screen_Surface, (128,128,128), (side_x + 
            eachCol * 30, side_y), (side_x + eachCol * 30, side_y +
               game_height))  
            # drawing vertical group of lines
```

上述函数有一个主循环，它循环进入由`build_Grid`方法确定的几行。在进入网格结构的每一行之后，它将使用`pygame` `draw`模块以颜色代码(128, 128, 128)绘制线条，从(`side_x`, `side_y`)开始，然后指向下一个坐标(`side_x + game_width, side_y + eachRow *30`)。起始点(`side_x`, `side_y`)是网格的最左侧角，而下一个坐标值(`side_x + game_width, side_y + eachRow *30`)表示网格的最右侧角的坐标。因此，我们将从网格的最左侧角绘制一条线到最右侧角。

在显式调用了前一个函数之后，你会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/308f5211-105f-4eb1-b438-b076b37c299b.png)

在设置了上述的网格或环境之后，我们将进入有趣的部分，也就是创建主函数。主函数将包含不同的内容，主要是用于调用和设置网格，并处理用户事件或操作，比如用户按下退出键或键盘上的箭头键时会发生什么。让我们用以下代码来定义它：

```py
def main():
 occupied = {} #this refers to the shapes occupied into the screen
 grid = build_Grid(occupied)

 done = False
 current_shape = generate_shapes() #random shapes chosen from lists. 
 next_shape = generate_shapes() 
 clock = pygame.time.Clock()
 time_of_fall = 0 #for automatic fall of shapes

 while not done:
 for eachEvent in pygame.event.get():
 if eachEvent.type == pygame.QUIT:
 done = True
 exit()    
```

既然我们已经开始定义主函数，它是我们游戏的指挥官，让我们定义它必须做的事情，如下所示：

+   调用多个函数，比如`build_Grid()`和`create_Grid()`，它们将设置游戏的环境

+   定义一个方法，执行代表字符的形状的旋转

+   定义一些逻辑，将下落时间限制添加到游戏中，也就是物体下落的速度

+   改变一个形状，在一个形状落到地面后

+   创建一些逻辑来检查形状的占用位置

上述过程是主函数的功能，我们应该解决它们。我们将在本节中解决前两个问题，但剩下的两个问题将在接下来的部分中解决。因此，主函数的第一个操作是调用一些关键函数，用于创建游戏的网格。如果你看上述的代码行，你会看到我们已经调用了`build_Grid`方法，它负责创建网格结构的行和列的虚拟位置。现在，剩下的任务只是调用`create_Grid()`方法，它将使用`pygame` `draw`模块为这个虚拟网格提供适当的物理结构。我们已经定义了这两个函数。

在下一节中，我们将学习一个重要的数学变换范式，即旋转，并将在我们的俄罗斯方块游戏中添加旋转游戏对象的功能。

# 理解旋转

在我们继续编写代码并修改主函数之前，让我们先了解一下数学知识。如果游戏与数学范式无关，那么游戏就什么都不是。运动、形状、角色和控制都由数学表达式处理。在本节中，我们将介绍数学的另一个重要概念：变换。尽管变换在数学中是一个模糊的概念，但我们将尽力学习这个概念。具体来说，有不同类型的变换：旋转、平移、反射和放大。在大多数游戏中，我们只需要两种类型的变换：旋转和放大。在本章中，我们将使用俄罗斯方块实现旋转变换，然后在第十六章中实现放大变换（构建愤怒的小鸟游戏时，*学习游戏人工智能-构建一个玩游戏的机器人*）。

术语*旋转*是一个数学概念，它表示*当一个对象被旋转时，意味着它以特定角度顺时针或逆时针旋转*。考虑以下例子：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/7370dec7-a5e6-4beb-a586-3e05a340cc64.png)

在前面的例子中，我们有一个矩形形状，代表了俄罗斯方块游戏中的字母`I`字符。现在，想象一下玩家按下键盘上的*上*箭头键。在这种情况下，`I`的矩形形状必须以 90 度的角度旋转，并放置为水平的`I`字符，如前面的图表所示。因此，这些旋转是为了改变图形的形状，而不是尺寸。水平`I`和垂直`I`具有相同的尺寸（高度和宽度）。现在您已经了解了一些关于旋转的知识，您可以回到我们为每个字符（I、O、J、L 和 T）定义形状格式的代码，并观察多维列表。在`I`的情况下，您可以观察到它有两个元素。列表的第一个元素是游戏对象`I`的原始形状，列表的第二个元素是在旋转约 90 度后的扭曲形状。观察一下`O`字符，它是一个正方形。即使旋转任意角度，正方形仍然保持不变。因此，在正方形形状的情况下，列表中只有一个元素。

尽管我们已经了解了关于旋转的这些琐事，以及它们如何与每个形状格式相关联，但问题仍然存在：何时可以渲染每个形状，何时应执行旋转操作？答案很简单。当玩家按下键盘上的任何箭头键时，我们将执行旋转。但是哪里的代码暗示用户正在按键盘键？显然，这是在事件处理过程中完成的！在主函数中，我们开始捕获事件，并处理`QUIT`键的操作。现在，让我们使用以下代码对任何箭头键执行旋转：

代码应该添加在事件处理步骤中，在处理`QUIT`键之后。确保为代码提供适当的缩进。代码将在[`github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter13`](https://github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter13)上提供。

```py
        if anyEvent.type == pygame.KEYDOWN:
                if anyEvent.key == pygame.K_LEFT:
                    current_shape.x -= 1  #go left with shape

                elif anyEvent.key == pygame.K_RIGHT:
                    current_shape.x += 1 #go right with shape

                elif anyEvent.key == pygame.K_UP:
                    # rotate shape with angle of rotation 
                     (rotation variable)
                    current_shape.rotation = current_shape.rotation + 1 % 
                     len(current_shape.game_objects)

                if anyEvent.key == pygame.K_DOWN:
                    # moving current shape down into the grid
                    current_shape.y += 1
```

如果您想了解更多关于对象旋转如何在幕后工作的知识，请确保查看以下网址：[`mathsdoctor.co.uk`](https://mathsdoctor.co.uk)。

为了设置窗口画布或游戏屏幕，我们可以简单地调用`pygame set_mode`方法，并相应地渲染网格的窗口。方法调用的以下行应该在主函数中添加，在您设置了用户处理事件之后：

```py
    create_Grid(screen_surface) #screen surface will be initialized with 
                                 pygame below
```

现在我们已经为屏幕创建了一个网格，让我们设置主屏幕并调用主函数：

```py
screen_surface = pygame.display.set_mode((width, height))
main() #calling only
```

我们已经涵盖了几乎所有重要的事情，包括渲染显示，旋转对象，创建网格，渲染网格边界；但还有一个问题：我们如何将形状渲染到网格中？显然，我们的计算机还不够聪明，无法理解我们之前创建的多维列表来定义形状格式。还是困惑？检查我们为每个字符创建的多维列表，比如 I，O，J，L 和 T——我们的计算机无法理解这样的列表。因此，我们必须将这些列表值或属性转换为我们的计算机将进一步处理的维度值。我们的计算机将理解的维度值是指位置值。由于我们已经建立了网格，我们可以使用网格结构的行和列为计算机提供位置值。因此，让我们创建一个函数来实现它。

# 转换形状格式

我们的计算机无法理解数据结构的模糊内容，比如存储在多维列表中的内容。例如，看一下以下代码：

```py
#for square shapes square = [['.....',
      '.....',
      '.00..',
      '.00..',
      '.....']]
```

在以前的方形模式中，我们将一系列句点（`.`）与`0`配对。计算机不会认识 0 代表什么，句点代表什么。我们只知道句点在一个空位上，这意味着它的位置可以被忽略，而`0`所在的位置是块的位置。因此，我们需要编写一个程序，告诉计算机从网格中提取只有`0`所在的位置的程序。我们将通过定义以下函数来实现它：

```py
def define_shape_position(shape_piece):
    positions = []
    list_of_shapes = shape_piece.game_objects[shape_piece.rotation % 
                     len(shape_piece.shape)]

    for i, line in enumerate(list_of_shapes):
        row = list(line)
        for j, column in enumerate(row):
            if column == '0':
                positions.append((shape_piece.x + j, shape_piece.y + i))

    for p, block_pos in enumerate(positions):
        positions[p] = (block_pos[0] - 2, block_pos[1] - 4)

    return positions
```

让我们详细看一下以前的代码：

1.  首先，这个函数返回对象的块的位置。因此，我们首先创建一个块字典。

1.  其次，我们存储了几个形状的列表，由多维字符列表`game_objects`（I，O，J，L 和 T）定义，并进行了旋转。

1.  现在，重要的部分：这个函数必须返回什么位置？这些位置是放置在网格中的`0`的位置。

1.  再次观察多维列表。你会看到一堆点（`.`）和`0`作为元素。我们只想要`0`所在的位置，而不是句点或点所在的位置。

1.  在我们使用`if column == \'0\'`命令检查每一列是否有`0`之后，我们只将这样的位置存储到 positions 字典中，并从函数中返回。

当进行旋转和移动等操作时，用户可能会触发一些无效的移动，比如将对象旋转到网格外部。因此，我们必须检查这些无效的移动并阻止它们发生。我们将创建`check_Moves()`函数来实现这一点。这个函数的参数将是形状和网格位置；形状是必要的，以检查特定旋转是否允许在由网格参数指示的位置内进行。如果网格指定的当前位置已经被占据，那么我们将摆脱这样的移动。有不同的实现方式，但最快最简单的方式是检查网格背景的颜色。如果网格中特定位置的颜色不是黑色，那么这意味着该位置已经被占据。因此，你可以从这个逻辑中得出一个详细的参考，解释为什么我们将网格的背景颜色设为黑色。通过这样做，我们可以检查对象是否已经在网格中。如果任何新对象下降到网格中，我们不应该通过已经存在于网格中的对象。

现在，让我们创建一个函数来检查位置是否被占用：

```py
def check_Moves(shape, grid):
    """ checking if the background color of particular position is 
        black or not, if it is, that means position is not occupied """

    valid_pos = [[(j, i) for j in range(10) if grid[i][j] == (0,0,0)] 
                for i in range(20)] 
    """ valid_pos contains color code in i variable and 
        position in j variable--we have to filter to get only 
        j variable """

    valid_pos = [j for p in valid_pos for j in p]

           """ list comprehension --same as writing
                    for p in valid_pos:
                        for j in p:
                            p
                            """
    """ Now get only the position from such shapes using 
        define_shape_position function """
    shape_pos = define_shape_position(shape)

    """check if pos is valid or not """
    for eachPos in shape_pos:
        if eachPos not in valid_pos:
            if eachPos[1] > -1: #eachPos[1] represents y value of shapes 
              and if it hits boundary
                return False #not valid move

    return True
```

到目前为止，我们一直在为我们的游戏构建后端逻辑，这涉及到渲染网格、操作网格、改变网格位置、实现决定两个对象碰撞时发生什么的逻辑等。尽管我们已经做了这么多，但当你运行游戏时，你仍然只会看到网格的形成，什么都没有。这是因为我们的主循环是游戏的指挥官——它将顺序地命令其他函数，但在主循环内，除了处理用户事件的代码之外，我们什么都没有。因此，在下一节中，我们将修改游戏的主循环并观察输出。

# 修改游戏循环

正如我们之前提到的，我们的主游戏循环负责执行许多任务，包括处理用户事件、处理网格、检查可能的移动等。我们一直在制作将检查这些动作、移动和环境的函数，但我们还没有调用它们一次，这将在本节中完成。如果你从高层次的角度观察主游戏循环，它将包含四个主要的架构构建块：

+   创建网格和处理游戏对象的移动。例如，掉落到网格中的对象的速度应该是多少？

+   处理用户事件。我们已经在检查事件并相应地旋转对象时做过这个，但前面的代码没有考虑`check_Moves()`函数，它将检查移动是否有效。因此，我们将相应地修改前面的代码。

+   为游戏对象添加颜色（唯一颜色）。例如，`S` 的颜色应该与 `I` 不同。

+   添加逻辑，检查对象撞击网格底部时会发生什么。

我们将逐步实现上述每个步骤。让我们从为对象添加速度开始。速度指的是网格结构中对象的自由下落速度。以下代码应该添加到主函数中：

```py
 global grid

 occupied = {} # (x pos, y pos) : (128, 0, 128)
 grid = build_Grid(occupied)
 change_shape = False
 done = False
 current_shape = generate_shapes()
 next_shape = generate_shapes()
 clock = pygame.time.Clock()
 timeforFall = 0

 while not done:
 speedforFall = 0.25

 grid = build_Grid(occupied)
 timeforFall += clock.get_rawtime()
 clock.tick()

 # code for making shape fall freely down the grid
 if timeforFall/1000 >= speedforFall:
 timeForFall = 0
 current_shape.y += 1 #moving downward
 #moving freely downward for invalid moves
 if not (check_Moves(current_shape, grid)) and current_shape.y > 0:
 current_shape.y -= 1
 change_shape = True
```

假设玩家尝试进行无效的移动。即使在这种情况下，游戏对象（形状）也必须自由向下掉落。这样的操作是在前面代码的最后三行中完成的。除此之外，代码是不言自明的；我们已经为对象定义了下落到网格中的速度，并使用了时钟模块来实现时间约束。

实现下一个逻辑，这相对容易一些。我们已经讨论了在俄罗斯方块中处理用户事件，考虑了旋转对象和进行简单的左右移动等细节。然而，在这些代码中，我们没有检查用户尝试的移动是否有效。我们必须首先检查这一点，以确保用户不能进行任何无效的移动。为了实现这一点，我们将调用之前创建的`check_Moves()`方法。以下代码将处理用户事件：

```py
if anyEvent.type == pygame.KEYDOWN:
                if anyEvent.key == pygame.K_LEFT:
                    current_shape.x -= 1
                    if not check_Moves(current_shape, grid):
                        current_shape.x += 1  # not valid move thus 
                           free falling shape

                elif anyEvent.key == pygame.K_RIGHT:
                    current_shape.x += 1
                   if not check_Moves(current_shape, grid):
                        current_shape.x -= **1**
      """ ROTATING OBJECTS """
                elif anyEvent.key == pygame.K_UP:

                    current_shape.rotation = current_shape.rotation + 1 % 
 len(current_shape.shape)
                    if not check_Moves(current_shape, grid):
                        current_shape.rotation = current_shape.rotation - 1 
 % len(current_shape.shape)

"""Moving faster while user presses down action key """
                if anyEvent.key == pygame.K_DOWN:

                    current_shape.y += 1
                    if not check_Moves(current_shape, grid):
                        current_shape.y -= 1
```

首先，关注被突出显示的代码。代码的第一个突出显示的部分是指移动是否有效进入网格，这是由`check_Moves()`函数检查的。我们允许当前形状向右角移动，即朝着正 *x* 轴。同样，关于上键，它负责检查对象是否允许旋转（只有上键会旋转对象；*左* 和 *右* 键会将对象从左到右移动，反之亦然）。在旋转的情况下，我们通过像素变换来旋转它，这是通过选择多维列表中指示的位置之一来完成的。例如，在形状 I 的情况下，列表中有两个元素：一个原始形状和另一个旋转形状。因此，为了使用另一个旋转形状，我们将检查移动是否有效，如果有效，我们将呈现新的形状。

应该添加到主函数中的第三段代码将处理为绘制网格中的形状添加颜色的技术。以下代码将为游戏范围内的每个对象添加颜色：

```py
     position_of_shape = define_shape_position(current_shape) 
     """ define_shape_function was created to return position of blocks of 
         an object """

        # adding color to each objects in to the grid. 
        for pos in range(len(position_of_shape)):
            x, y = position_of_shape[pos]

            """ when shapes is outside the main grid, we don't care """
            if y > -1: # But if we are inside the screen or grid, 
               we add color
                grid[y][x] = current_shape.color #adding color to the grid
```

最后，必须添加到主函数中的最后一段逻辑将处理当对象触地时的情况。让我们添加以下代码到主函数中以实现它：

```py
    if change_shape:
            for eachPos in position_of_shape:
                pos = (eachPos[0], eachPos[1])
                occupied[pos] = current_shape.color
            current_shape = next_shape
            next_shape = generate_shapes()
            change_shape = False
```

在上述代码中，我们通过检查布尔变量`change_shape`的内容来检查对象是否自由下落。然后，我们检查形状的当前位置并创建（*x*，*y*），它将表示占用的位置。然后将这样的位置添加到名为 occupied*的字典中。您必须记住，该字典的值是相同对象的颜色代码。在将当前对象分配给网格范围后，我们将使用`generate_shapes()`方法生成一个新形状。

最后，让我们通过调用`create_Grid()`函数来结束我们的主函数，参数是在以下代码中由 pygame 的`set_mode()`方法初始化的网格和表面对象（我们之前初始化了 pygame 的`surface`对象）：

```py
create_Grid(screen_surface, grid)
```

让我们运行游戏并观察输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/c2d46b20-3945-47a1-b433-1dd79e686249.png)

现在，您可以清楚地看到我们能够制作一个俄罗斯方块游戏，用户可以根据需要转换对象并进行游戏。但等等！我们的游戏缺少一个重要的逻辑。我们如何激励玩家玩这个游戏？如果游戏只是关于旋转对象和用对象填充网格，那它就不会是历史悠久的游戏（这个游戏改变了 90 年代的游戏产业）。是的！游戏中必须添加一些逻辑，当调用这个逻辑时，我们将观察到每当行位置被*占用*时，我们必须清除这些行并将行向下移动一步，这将使我们比以前少了几行。我们将在下一节中实现这一点。

# 清除行

正如我们之前提到的，在本节中，我们将检查所有行的每个位置是否完全被占用。如果它们被占用，我们将从网格中删除这些行，并且这将导致每一行在网格中向下移动一步。这个逻辑很容易实现。我们将检查整行是否被占用，并相应地删除这些行。您还记得`check_Moves()`函数的情况吗？如果此函数检查每行的背景颜色，如果每行都没有黑色背景颜色，这意味着这样的行是被占用的。但即使我们有一个空位置，这意味着这个位置的背景颜色将是黑色，并且将被视为未被占用。因此，在清除行的情况下，我们可以使用类似的技术：如果在任何行中，任何位置的背景颜色是黑色，这意味着该位置未被占用，这样的行不能被清除。

让我们创建一个函数来实现清除行的逻辑：

```py
def delete_Row(grid, occupied):
    # check if the row is occupied or not
    black_background_color = (0, 0, 0)
    number_of_rows_deleted = 0
    for i in range(len(grid)-1,-1,-1):
        eachRow = grid[i]
        if black_background_color not in eachRow:
            number_of_rows_deleted += 1

            index_of_deleted_rows = i
            for j in range(len(eachRow)):
 try:
 del occupied[(j, i)]
                except:
                    continue
```

让我们消化前面的代码。这是一个相当复杂的逻辑，所以确保你学会了所有的东西；这些概念不仅适用于游戏创建，而且在技术面试中也经常被问到。问题在于如何通过创建逻辑来移动数据结构的值，而不是使用 Python 内置函数。我想以这种方式教给你，而不是使用任何内置方法，因为知道这个可能对编程的任何技术领域都有帮助。现在，让我们观察代码。它以创建一个`number_of_rows_deleted`变量开始，该变量表示已从网格中删除的行数。关于已删除行数的信息很重要，因为在删除这些行数后，我们需要将位于已删除行上方的行数向下移动相同的数量。例如，看看下面的图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/712a0c70-671e-482c-a693-9565bc90a21a.png)

同样，现在我们知道了使用`if black_background_color not in eachRow`表达式要删除什么，我们可以确定网格的每一行是否有空位。如果有空位，这意味着行没有被占据，如果有，那么黑色背景颜色，即(0, 0, 0)，不会出现在任何行中。如果我们没有找到黑色背景颜色，那么我们可以确定行被占据，我们可以通过进一步检查条件来删除它们。在代码的突出部分中，你可以看到我们只取第 j 个元素，这只是一列。这是因为在删除行时，`I`的值保持不变，但第 j 列的值不同。因此，我们在单行内循环整个列，并使用`del`命令删除被占据的位置。

从上一行代码中，我们能够删除整行，如果有任何行被占据，但我们没有解决删除后应该发生什么，这是棘手的部分。在我们删除每一行后，不仅会删除方块，整个包含行的网格也会被删除。因此，在删除的方块位置，我们不会有空行；相反，包含网格的整行将被删除。因此，为了确保我们不减少实际网格的数量，我们需要从顶部添加另一行来补偿。让我们编写一些代码来实现这一点：

```py
#code should be added within delete_Row function outside for loop
if number_of_rows_deleted > 0:       #if there is at least one rows deleted 

        for position in sorted(list(occupied), position=lambda x: 
          x[1])[::-1]:
            x, y = position
            if y < index_of_deleted_rows:
                """ shifting operation """
                newPos = (x, y + number_of_rows_deleted)
                occupied[newPos] = occupied.pop(position)

return number_of_rows_deleted
```

好了！让我们消化一下。这是相当复杂但非常强大的信息。前面的代码将实现将行块从顶部向下移入网格。首先，只有在我们删除了任何行时才需要移位；如果是，我们就进入逻辑来执行移位。首先，让我们只观察涉及 lambda 函数的代码，即`list(occupied), position=lambda x: x[1]`。该代码将创建一个包含网格所有位置的列表，然后使用 lambda 函数仅获取位置的*y*部分。请记住，获取方块的*x*位置是多余的——对于每一行，*x*的值保持不变，但*y*的值不同。因此，我们将获取*y*位置的值，然后使用`sorted(x)`函数对其进行排序。排序函数将根据*y*坐标的值对位置进行排序。

首先，排序将根据*y*的较小值到*y*的较大值进行。例如，看看下面的图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/f4cf74ea-2a52-4699-bc7a-b649e98cbffb.png)

调用 sorted 方法，然后反转列表（参见第四章，*数据结构和函数*，了解更多关于如何反转列表的信息）很重要，因为有时网格的底部部分可能没有被占据，只有上层会被占据。在这种情况下，我们不希望移位操作对未被占据的底部行造成任何伤害。

同样，在追踪每一行的位置后，我们将检查是否有任何删除行上方的行，使用`if y < index_of_deleted_rows`表达式。同样，在这种情况下，*x*的值是无关紧要的，因为它在单行内是相同的；在我们检查是否有任何删除行上方的行之后，我们执行移位操作。移位操作非常简单；我们将尝试为位于删除行正上方的每一行分配新位置。我们可以通过增加删除行的数量来创建新位置的值。例如，如果有两行被删除，我们需要将*y*的值增加两个，以便删除行上方的方块和随后的方块将向下移动两行。在我们将行向下移动到网格后，我们必须从先前的位置弹出方块。

既然我们已经定义了一个函数，如果整行被占据，它将清除整行，让我们从主函数中调用它来观察其效果：

```py
def main():
    ...
    while not done:
        ... 
        if change_shape:
            ...
            change_shape = False
            delete_Row(grid, occupied)
```

最后，在这个漫长而乏味的编码日子里，我们取得了非常有成效的结果。当您运行声明了主函数的模块时，您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/529f38a4-88da-4c63-9baa-01e261a7d2de.png)

游戏看起来很吸引人，我已经在代码中测试了一切。代码看起来非常全面和详尽，没有漏洞。同样，您可以玩它并与朋友分享，并发现可以对这个游戏进行的可能修改。这是一个高级游戏，当用 Python 从头开始编码时，它充分提高了自己的水准。在构建这个游戏的过程中，我们学到了很多东西。我们学会了如何定义形状格式（我们以前做过更复杂的事情，比如精灵的转换和处理精灵的碰撞），但这一章在不同方面都具有挑战性。例如，我们必须注意诸如无效移动、可能的碰撞、移位等事项。我们实现了一些逻辑，通过比较两种不同的颜色对象：网格或表面的**背景颜色**与**游戏对象颜色**，来确定对象是否放置在某个位置。

我们还没有完成；我们将在下一节尝试实现更多逻辑。我们将看看我们的游戏可以进行哪些其他修改。我们将尝试构建一些逻辑，随着游戏的进行，将增加游戏的难度级别。

# 游戏测试

我们的游戏可以进行多种修改，但最重要的修改将是添加欢迎屏幕、增加难度级别和得分屏幕。让我们从欢迎屏幕开始，因为它很容易实现。我们可以使用`pygame`模块创建一个窗口，并使用文本表面向用户提供消息。以下代码显示了如何为我们的俄罗斯方块游戏创建一个主屏幕：

```py

def Welcome_Screen(surface):  
    done = False
    while not done:
        surface.fill((128,0,128))
        font = pygame.font.SysFont("comicsans", size, bold=True)
        label = font.render('Press ANY Key To Play Tetris!!', 1, (255, 255, 
                255))

        surface.blit(label, (top_left_x + game_width /2 - 
         (label.get_width()/2), top_left_y + game_height/2 - 
          label.get_height()/2))

        pygame.display.update()
        for eachEvent in pygame.event.get():
            if eachEvent.type == pygame.QUIT:
                done = True
            if event.type == pygame.KEYDOWN:
                main(surface) #calling main when user enters Enter key 

    pygame.display.quit()
```

运行游戏后，您将看到以下输出，其中将呈现欢迎屏幕。按下任意键后，您将被重定向到俄罗斯方块游戏：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/ff97e2d4-de62-4a0c-8075-dda1d8e9657b.png)

同样，让我们添加一些逻辑，以增加游戏的难度。有两种实现这种逻辑的方法。首先，您可以创建一个计时器，如果玩家玩的时间超过关联计时器的范围，我们可以减慢下落速度，使形状比以前下落得更快（增加速度）：

```py
timeforLevel = 0

while not done:
    speedforFall = 0.27 - timeforLevel 
    ...
    if timeforLevel / 10000 > 0.5:
        timeforLevel = 0
        if timeforLevel > 0.15:
            timeforLevel += 0.05
    ...

"""  ---------------------------------------------------
        speedforFall = 0.24 will make object to fall faster comparative 
                       to speedforFall = 0.30 

    ----------------------------------------------------- """ 
```

同样，我们可以实现另一段逻辑来增加游戏的难度。这种方法比之前的更好。在这种方法中，我们将使用*分数*来增加游戏的难度。以下代码表示了如何实现玩家的得分以增加游戏级别的蓝图：

```py
def increaseSpeed(score):
    game_level = int(score*speedForFall)
    speedforFall = 0.28 - (game_level)
    return speedforFall
```

在前面的代码中，我们实现了分数和物体速度之间的关系。假设玩家的分数更高。这意味着用户一直在玩较低难度的级别，因此，这样一个高分值将与更高的下落速度值相乘，导致`speedforFall`的增加，然后从物体的速度中减去，这将创建一个更快的下落动作。相反，玩在更高级别的玩家将有一个较低的分数，这将与物体速度的较低值相乘，导致一个较低的数字，然后从`speedforFall`变量中减去。这将导致玩更难级别的玩家速度变化较小。但假设玩家是专业的，并且在更难的级别中得分更高。在这种情况下，物体的下落速度相应增加。

我们最终完成了一个完全功能的俄罗斯方块游戏。在本章中，我们学习了使用 Python 进行游戏编程的几个高级概念。在创建过程中，我们复习了一些我们之前学到的关于 Python 的基本概念，比如操作多维列表，列表推导，面向对象的范式和数学变换。除了复习这些概念，我们还发现了一些新颖的概念，比如实现旋转，实现移位操作，从头开始创建形状格式，创建网格（虚拟和物理）结构，并在网格中放置物体。

# 总结

在本章中，我们探索了实现多维列表处理的*Pythonic*方式。我们创建了一个多维列表来存储不同几何形状的格式，并使用数学变换对其进行操作。

我们使用了俄罗斯方块的简单示例来演示游戏中几种数据结构的使用，以及它们的操作。我们实现了一个字典，将键存储为位置，值存储为这些物体的颜色代码。构建这样一个字典对于俄罗斯方块等游戏来说是救命的。在制作检查碰撞和移位操作的逻辑时，我们使用字典来观察任何物体的背景颜色是否与任何位置的背景相同。尽管俄罗斯方块只是一个案例研究，但在这个游戏中使用的技术也被用于许多现实世界的游戏，包括 Minecraft，几乎每个 RPG 游戏。

数学变换涉及的操作对我们非常重要。在本章中，我们使用了旋转原理来改变物体的结构而不改变其尺寸。从本章中您将掌握的知识是巨大的。诸如操作多维列表之类的概念可以扩展到数据应用程序，并被称为 2D Numpy 数组，用于创建不同的类比，比如街道类比，多旅行者问题等。尽管字典被认为是数据结构之王，但处理多维列表并不逊色，因为它与列表推导的简单性相结合。除了实现这些复杂的数据结构，我们还学会了如何实现数学变换，即游戏物体的旋转运动。这个特性在任何 3D 游戏中都非常有用，因为它将为用户提供对场景的 360 度视图。同样，我们还学会了如何创建网格结构。

网格结构用于跟踪物体的位置。在像 WorldCraft 这样的复杂游戏中，跟踪游戏的物体和资源是任何游戏开发者的强制性任务，在这种情况下，网格非常有效。可以将不可见的网格实现为字典，或者作为任何复杂的集合。

本章的主要目标是让您熟悉 2D 游戏图形，即绘制基本图形和游戏网格。同样，您还了解了另一种检测游戏对象之间碰撞的方法（在 Flappy Bird 游戏中，我们使用了 pygame 掩模技术来检测碰撞）。在本章中，我们实现了一种通用和传统的碰撞检测方法：通过检查背景颜色属性和对象颜色属性。同样，我们学会了如何通过旋转来创建不同结构的对象。这种技术可以用来在游戏中生成多个敌人。我们没有为每个角色设计多个不同的对象（这可能耗时且昂贵），而是使用变换来改变对象的结构。

下一章是关于 Python OpenGL，通常称为 PyOpenGL。我们将看到如何使用 OpenGL 创建不同的几何结构，并观察如何将 PyOpenGL 和 pygame 一起使用。我们将主要关注不同的数学范式。我们将看到顶点和边等属性如何用于创建不同的复杂数学形状。此外，我们将看到如何使用 PyOpenGL 实现游戏中的放大和缩小功能。
