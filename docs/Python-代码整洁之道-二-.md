# Python 代码整洁之道（二）

> 原文：[`zh.annas-archive.org/md5/164695888A8A98C80BA0F014DEE631C7`](https://zh.annas-archive.org/md5/164695888A8A98C80BA0F014DEE631C7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：SOLID 原则

在本章中，我们将继续探讨应用于 Python 的清晰设计概念。特别是，我们将回顾所谓的**SOLID**原则，以及如何以 Pythonic 的方式实现它们。这些原则包括一系列实践，以实现更高质量的软件。如果我们中有人不知道 SOLID 代表什么，这里是解释：

+   **S**：单一责任原则

+   **O**：开闭原则

+   **L**：里氏替换原则

+   **I**：接口隔离原则

+   **D**：依赖反转原则

本章的目标如下：

+   熟悉软件设计的 SOLID 原则

+   设计遵循单一责任原则的软件组件

+   通过开闭原则实现更易维护的代码

+   通过遵守里氏替换原则，在面向对象设计中实现适当的类层次结构

+   通过接口隔离和依赖反转进行设计

# 单一责任原则

**单一责任原则**（**SRP**）规定软件组件（通常是一个类）必须只有一个责任。类只有一个责任意味着它只负责做一件具体的事情，因此我们可以得出结论，它只有一个变化的原因。

只有在领域问题上有一件事情改变时，类才需要更新。如果我们不得不因为不同的原因对一个类进行修改，那意味着抽象不正确，类承担了太多责任。

正如在第二章中介绍的*Pythonic Code*，这个设计原则帮助我们构建更具凝聚力的抽象；对象只做一件事情，而且做得很好，遵循 Unix 哲学。我们要避免的情况是拥有承担多个责任的对象（通常称为**god-objects**），因为它们知道得太多，或者比它们应该知道的更多。这些对象组合了不同（大多数是不相关的）行为，因此使它们更难以维护。

再次强调，类越小越好。

SRP 与软件设计中的内聚概念密切相关，我们在第三章中已经探讨过这一点，当时我们讨论了软件中的关注点分离。我们努力实现的目标是，类被设计成大部分时间内它们的属性和方法被使用。当这种情况发生时，我们知道它们是相关的概念，因此将它们分组到同一个抽象下是有意义的。

在某种程度上，这个想法与关系数据库设计中的规范化概念有些相似。当我们发现对象的接口的属性或方法有分区时，它们可能被移动到其他地方——这表明它们是两个或更多不同的抽象混合在一起。

还有另一种看待这个原则的方式。如果在查看一个类时，我们发现方法是相互独立的，彼此之间没有关联，那么它们就是需要分解成更小的类的不同责任。

# 一个类承担太多责任

在这个例子中，我们将创建一个应用程序，负责从源头（可以是日志文件、数据库或其他许多来源）读取有关事件的信息，并识别与每个特定日志对应的动作。

不符合 SRP 的设计如下所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/cln-code-py/img/a2877df2-39ec-4056-b127-b0162883a1a4.png)

不考虑实现，该类的代码可能如下所示：

```py
# srp_1.py
class SystemMonitor:
    def load_activity(self):
        """Get the events from a source, to be processed."""

    def identify_events(self):
        """Parse the source raw data into events (domain objects)."""

    def stream_events(self):
        """Send the parsed events to an external agent."""
```

这个类的问题在于它定义了一个接口，其中包含一组与彼此正交的动作对应的方法：每个动作都可以独立于其他动作完成。

这种设计缺陷使得类变得僵化、不灵活、容易出错，因为很难维护。在这个例子中，每个方法代表了类的一个责任。每个责任都意味着类可能需要被修改的原因。在这种情况下，每个方法代表了类将被修改的各种原因之一。

考虑加载器方法，它从特定来源检索信息。无论这是如何完成的（我们可以在这里抽象实现细节），很明显它将有自己的一系列步骤，例如连接到数据源，加载数据，将其解析为预期格式等。如果其中任何一项发生变化（例如，我们想要更改用于保存数据的数据结构），`SystemMonitor`类将需要更改。问问自己这是否有意义。系统监视器对象是否必须因为我们改变了数据的表示而改变？不。

相同的推理也适用于其他两种方法。如果我们改变了指纹事件的方式，或者我们如何将它们传递到另一个数据源，我们最终会对同一个类进行修改。

现在应该很清楚，这个类相当脆弱，而且不太容易维护。有很多不同的原因会影响这个类的变化。相反，我们希望外部因素对我们的代码的影响尽可能小。解决方案是再次创建更小、更具凝聚力的抽象。

# 分配责任

为了使解决方案更易于维护，我们将每个方法分离到不同的类中。这样，每个类都将有一个单一的责任：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/cln-code-py/img/cdac0d5f-a04e-4839-990d-03d6753720b0.png)

通过使用一个对象来实现相同的行为，该对象将与这些新类的实例进行交互，使用这些对象作为协作者，但是这个想法仍然是每个类封装了一组独立于其他类的特定方法。现在的想法是，对这些类的任何更改都不会影响其他类，它们都有一个明确而具体的含义。如果我们需要改变如何从数据源加载事件，警报系统甚至不知道这些变化，因此我们不需要修改系统监视器上的任何内容（只要合同仍然得到保留），数据目标也没有被修改。

现在变化是局部的，影响是最小的，每个类更容易维护。

新的类定义了接口，不仅更易于维护，而且更可重用。想象一下，现在在应用程序的另一个部分，我们还需要从日志中读取活动，但是为了不同的目的。有了这个设计，我们可以简单地使用`ActivityReader`类型的对象（实际上应该是一个接口，但是在本节的目的上，这个细节并不重要，将在下一个原则中解释）。这是有意义的，而在以前的设计中是没有意义的，因为尝试重用我们定义的唯一类也会带有不需要的额外方法（比如`identify_events()`或`stream_events()`）。

一个重要的澄清是，这个原则并不意味着每个类必须只有一个方法。任何新类都可能有额外的方法，只要它们对应于该类负责处理的相同逻辑。

# 开闭原则

**开闭原则**（OCP）规定一个模块应该是开放的和封闭的（但是针对不同的方面）。

例如，在设计一个类时，我们应该仔细地封装逻辑，使其具有良好的维护性，这意味着我们希望它对扩展是**开放的，但对修改是封闭的。**

简单来说，这意味着当领域问题出现新情况时，我们当然希望我们的代码是可扩展的，能够适应新的要求或领域问题的变化。这意味着当领域问题出现新情况时，我们只想向我们的模型添加新的东西，而不是更改任何已经关闭修改的现有内容。

如果由于某种原因，当需要添加新内容时，我们发现自己修改了代码，那么这个逻辑可能设计得很糟糕。理想情况下，当需求发生变化时，我们只需扩展模块以满足新需求，而无需修改代码。

这个原则适用于多个软件抽象。它可以是一个类，甚至是一个模块。在接下来的两个小节中，我们将分别看到每个示例。

# 不遵循开闭原则的可维护性问题示例

让我们从一个系统的示例开始，该系统设计方式不符合开闭原则，以便看到这种设计的可维护性问题以及这种设计的不灵活性。

我们的想法是，系统的一部分负责在另一个正在被监视的系统中发生事件时识别这些事件。在每个点上，我们希望这个组件根据先前收集的数据的值（为简单起见，我们将假设它被打包到一个字典中，并且先前是通过日志、查询等其他方式检索的）正确地识别事件类型。我们有一个类，根据这些数据，将检索事件，这是另一种具有自己层次结构的类型。

解决这个问题的第一次尝试可能看起来像这样：

```py
# openclosed_1.py
class Event:
    def __init__(self, raw_data):
        self.raw_data = raw_data

class UnknownEvent(Event):
    """A type of event that cannot be identified from its data."""

class LoginEvent(Event):
    """A event representing a user that has just entered the system."""

class LogoutEvent(Event):
    """An event representing a user that has just left the system."""

class SystemMonitor:
    """Identify events that occurred in the system."""

    def __init__(self, event_data):
        self.event_data = event_data

    def identify_event(self):
        if (
            self.event_data["before"]["session"] == 0
            and self.event_data["after"]["session"] == 1
        ):
            return LoginEvent(self.event_data)
        elif (
            self.event_data["before"]["session"] == 1
            and self.event_data["after"]["session"] == 0
        ):
            return LogoutEvent(self.event_data)

        return UnknownEvent(self.event_data)
```

以下是前述代码的预期行为：

```py
>>> l1 = SystemMonitor({"before": {"session": 0}, "after": {"session": 1}})
>>> l1.identify_event().__class__.__name__
'LoginEvent'

>>> l2 = SystemMonitor({"before": {"session": 1}, "after": {"session": 0}})
>>> l2.identify_event().__class__.__name__
'LogoutEvent'

>>> l3 = SystemMonitor({"before": {"session": 1}, "after": {"session": 1}})
>>> l3.identify_event().__class__.__name__
'UnknownEvent'
```

我们可以清楚地注意到事件类型的层次结构，以及一些构造它们的业务逻辑。例如，当会话之前没有标志，但现在有了，我们将该记录标识为登录事件。相反，当相反情况发生时，这意味着它是一个注销事件。如果无法识别事件，则返回类型未知的事件。这是为了通过遵循空对象模式（而不是返回`None`，它检索具有一些默认逻辑的相应类型的对象）来保持多态性。空对象模式在第九章中有描述，*常见设计模式*。

这种设计存在一些问题。第一个问题是确定事件类型的逻辑集中在一个庞大的方法中。随着我们想要支持的事件数量增加，这个方法也会增长，最终可能会变成一个非常长的方法，这是不好的，因为正如我们已经讨论过的，它不会只做一件事情并且做得很好。

在同一行上，我们可以看到这种方法不适合修改。每当我们想要向系统添加新类型的事件时，我们都必须更改这种方法中的某些内容（更不用说`elif`语句的链将是一场噩梦！）。

我们希望能够添加新类型的事件，而无需更改这种方法（关闭修改）。我们还希望能够支持新类型的事件（扩展开放），这样当添加新事件时，我们只需添加代码，而不是更改已经存在的代码。

# 重构事件系统以实现可扩展性

前面示例的问题在于`SystemMonitor`类直接与它将要检索的具体类进行交互。

为了实现符合开闭原则的设计，我们必须朝着抽象设计。

一个可能的替代方案是将这个类视为与事件协作，然后将每种特定类型的事件的逻辑委托给其相应的类：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/cln-code-py/img/cc55531b-bccd-4441-86a5-c3de785e5243.png)

然后，我们必须为每种类型的事件添加一个新的（多态的）方法，其单一责任是确定它是否与传递的数据相对应，我们还必须改变逻辑以遍历所有事件，找到正确的事件。

新代码应该如下所示：

```py
# openclosed_2.py
class Event:
    def __init__(self, raw_data):
        self.raw_data = raw_data

    @staticmethod
    def meets_condition(event_data: dict):
        return False

class UnknownEvent(Event):
    """A type of event that cannot be identified from its data"""

class LoginEvent(Event):
    @staticmethod
    def meets_condition(event_data: dict):
        return (
            event_data["before"]["session"] == 0
            and event_data["after"]["session"] == 1
        )

class LogoutEvent(Event):
    @staticmethod
    def meets_condition(event_data: dict):
        return (
            event_data["before"]["session"] == 1
            and event_data["after"]["session"] == 0
        )

class SystemMonitor:
    """Identify events that occurred in the system."""

    def __init__(self, event_data):
        self.event_data = event_data

    def identify_event(self):
        for event_cls in Event.__subclasses__():
            try:
                if event_cls.meets_condition(self.event_data):
                    return event_cls(self.event_data)
            except KeyError:
                continue
        return UnknownEvent(self.event_data)
```

请注意，现在交互是针对抽象的（在这种情况下，它将是通用基类`Event`，甚至可能是一个抽象基类或接口，但对于这个例子来说，拥有一个具体的基类就足够了）。该方法不再使用特定类型的事件，而只是使用遵循通用接口的通用事件 - 它们在`meets_condition`方法方面都是多态的。

请注意，事件是通过`__subclasses__()`方法发现的。支持新类型的事件现在只是创建一个新的事件类，该类必须继承自`Event`并根据其特定的业务逻辑实现自己的`meets_condition()`方法。

# 扩展事件系统

现在，让我们证明这个设计实际上是我们想要的那样具有可扩展性。想象一下，出现了一个新的需求，我们还必须支持与用户在监视系统上执行的交易相对应的事件。

设计的类图必须包括这样一种新的事件类型，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/cln-code-py/img/870dd0e2-4e1f-416e-b4b6-415b4e0c1df1.png)

只需添加到这个新类的代码，逻辑就能按预期工作：

```py
# openclosed_3.py
class Event:
    def __init__(self, raw_data):
        self.raw_data = raw_data

    @staticmethod
    def meets_condition(event_data: dict):
        return False

class UnknownEvent(Event):
    """A type of event that cannot be identified from its data"""

class LoginEvent(Event):
    @staticmethod
    def meets_condition(event_data: dict):
        return (
            event_data["before"]["session"] == 0
            and event_data["after"]["session"] == 1
        )

class LogoutEvent(Event):
    @staticmethod
    def meets_condition(event_data: dict):
        return (
            event_data["before"]["session"] == 1
            and event_data["after"]["session"] == 0
        )

class TransactionEvent(Event):
    """Represents a transaction that has just occurred on the system."""

    @staticmethod
    def meets_condition(event_data: dict):
        return event_data["after"].get("transaction") is not None

class SystemMonitor:
    """Identify events that occurred in the system."""

    def __init__(self, event_data):
        self.event_data = event_data

    def identify_event(self):
        for event_cls in Event.__subclasses__():
            try:
                if event_cls.meets_condition(self.event_data):
                    return event_cls(self.event_data)
            except KeyError:
                continue
        return UnknownEvent(self.event_data)
```

我们可以验证以前的情况仍然像以前一样工作，并且新事件也被正确识别：

```py
>>> l1 = SystemMonitor({"before": {"session": 0}, "after": {"session": 1}})
>>> l1.identify_event().__class__.__name__
'LoginEvent'

>>> l2 = SystemMonitor({"before": {"session": 1}, "after": {"session": 0}})
>>> l2.identify_event().__class__.__name__
'LogoutEvent'

>>> l3 = SystemMonitor({"before": {"session": 1}, "after": {"session": 1}})
>>> l3.identify_event().__class__.__name__
'UnknownEvent'

>>> l4 = SystemMonitor({"after": {"transaction": "Tx001"}})
>>> l4.identify_event().__class__.__name__
'TransactionEvent'
```

请注意，当我们添加新的事件类型时，`SystemMonitor.identify_event()`方法根本没有改变。因此，我们说这个方法对于新类型的事件是封闭的。

相反，`Event`类允许我们在需要时添加新类型的事件。然后我们说，事件对于新类型是开放的。

这就是这个原则的真正本质 - 当领域问题出现新的东西时，我们只想添加新的代码，而不是修改现有的代码。

# 关于 OCP 的最终想法

正如你可能已经注意到的，这个原则与多态的有效使用密切相关。我们希望设计符合客户端可以使用的多态合同的抽象，以及足够通用以便扩展模型是可能的，只要多态关系得到保留。

这个原则解决了软件工程中的一个重要问题：可维护性。不遵循 OCP 的危险是连锁效应和软件中的问题，其中单个更改触发整个代码库的更改，或者有风险破坏代码的其他部分。

一个重要的最终说明是，为了实现这种设计，我们需要能够对我们想要保护的抽象（在这个例子中是新类型的事件）进行适当的封闭。这在所有程序中并不总是可能的，因为一些抽象可能会发生冲突（例如，我们可能有一个适当的抽象，它提供了对一个需求的封闭，但对其他类型的需求却不起作用）。在这些情况下，我们需要有选择地应用一种策略，为需要最具可扩展性的需求提供最佳的封闭。

# Liskov 的替换原则

**Liskov 的替换原则**（**LSP**）规定了对象类型必须具有的一系列属性，以保持其设计的可靠性。

LSP 背后的主要思想是，对于任何类，客户端应该能够无法区分地使用其任何子类型，甚至在运行时也不会影响预期的行为。这意味着客户端完全与类层次结构的变化隔离和不知情。

更正式地说，这是 Liskov 替换原则的原始定义（LISKOV 01）：如果*S*是*T*的子类型，那么类型为*T*的对象可以被类型为*S*的对象替换，而不会破坏程序。

这可以通过一个通用的图表来理解，比如下面的图表。想象一下，有一个客户类需要（包括）另一种类型的对象。一般来说，我们希望这个客户与某种类型的对象进行交互，换句话说，它将通过一个接口来工作。

现在，这种类型可能只是一个通用的接口定义，一个抽象类或一个接口，而不是具有行为本身的类。可能有几个子类扩展了这种类型（在图表中用名称**子类型**描述，最多**N**）。这个原则背后的想法是，如果层次结构被正确实现，客户类必须能够使用任何子类的实例而不会注意到。这些对象应该是可互换的，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/cln-code-py/img/2f7cb18f-e8c5-489c-aa5b-274ce34faf97.png)

这与我们已经讨论过的其他设计原则相关，比如按接口设计。一个好的类必须定义一个清晰简洁的接口，只要子类遵守该接口，程序就会保持正确。

作为这一原则的结果，它也与按合同设计的思想相关。给定类型和客户之间有一个合同。通过遵循 LSP 的规则，设计将确保子类遵守由父类定义的合同。

# 使用工具检测 LSP 问题

有一些与 LSP 相关的情景是如此明显错误，以至于我们学会配置的工具（主要是 Mypy 和 Pylint）可以轻松识别。

# 使用 Mypy 检测方法签名中的不正确数据类型

通过在整个代码中使用类型注释（如之前在第一章中推荐的，*介绍、代码格式和工具*），并配置 Mypy，我们可以快速检测到一些基本错误，并免费检查 LSP 的基本合规性。

如果`Event`类的一个子类以不兼容的方式覆盖了一个方法，Mypy 会通过检查注释来注意到这一点：

```py
class Event:
    ...
    def meets_condition(self, event_data: dict) -> bool:
        return False

class LoginEvent(Event):
    def meets_condition(self, event_data: list) -> bool:
        return bool(event_data)
```

当我们在这个文件上运行 Mypy 时，将会得到一个错误消息，内容如下：

```py
error: Argument 1 of "meets_condition" incompatible with supertype "Event"
```

LSP 的违反是明显的——因为派生类使用了与基类定义的类型不同的`event_data`参数类型，我们不能指望它们能够同样工作。请记住，根据这个原则，这个层次结构的任何调用者都必须能够透明地使用`Event`或`LoginEvent`，而不会注意到任何差异。这两种类型的对象可以互换，不应该使应用程序失败。如果不能做到这一点，将会破坏层次结构上的多态性。

如果返回类型被更改为布尔值之外的其他值，同样的错误也会发生。其理由是这段代码的客户端期望使用布尔值。如果派生类中的一个更改了这个返回类型，它将违反合同，再次，我们不能指望程序会继续正常工作。

关于类型不同但共享公共接口的快速说明：尽管这只是一个简单的例子来演示错误，但事实上字典和列表都有一些共同之处；它们都是可迭代的。这意味着在某些情况下，可能会有一个方法期望接收一个字典，另一个方法期望接收一个列表，只要两者都通过可迭代接口处理参数，这可能是有效的。在这种情况下，问题不在于逻辑本身（LSP 可能仍然适用），而在于签名类型的定义，它们既不应该是`list`也不应该是`dict`，而是两者的并集。无论如何，都必须修改一些东西，无论是方法的代码、整个设计，还是类型注释，但在任何情况下，我们都不应该消除警告并忽略 Mypy 给出的错误。

不要通过`# type: ignore`或类似的方式忽略这样的错误。重构或更改代码以解决真正的问题。工具之所以报告实际的设计缺陷是有充分理由的。

# 使用 Pylint 检测不兼容的签名

LSP 的另一个严重违规是，与其在层次结构中变化参数的类型，方法的签名完全不同。这可能看起来像一个大错误，但要检测它并不总是那么容易记住；Python 是解释性语言，所以没有编译器能够及早检测到这种类型的错误，因此它们直到运行时才会被捕获。幸运的是，我们有静态代码分析器，如 Mypy 和 Pylint，可以及早捕获这类错误。

虽然 Mypy 也会捕捉到这种类型的错误，但同时运行 Pylint 以获得更多的见解也不是坏事。

在存在一个违反层次结构定义的类的情况下（例如，通过更改方法的签名，添加额外参数等），如下所示：

```py
# lsp_1.py
class LogoutEvent(Event):
    def meets_condition(self, event_data: dict, override: bool) -> bool:
        if override:
            return True
        ...
```

Pylint 将检测到它，并打印出一个信息性的错误：

```py
Parameters differ from overridden 'meets_condition' method (arguments-differ)
```

再次，就像在先前的情况下一样，不要压制这些错误。注意工具给出的警告和错误，并相应地调整代码。

# 更微妙的 LSP 违规案例

然而，在其他情况下，LSP 被破坏的方式并不那么清晰或明显，工具无法自动识别，我们必须依靠仔细的代码检查进行代码审查。

修改合同的情况特别难以自动检测。鉴于 LSP 的整个理念是子类可以像其父类一样被客户使用，这也意味着合同在层次结构上必须得到正确保留。

请记住第三章中提到的*良好代码的一般特征*，即在按合同设计时，客户和供应商之间的合同设定了一些规则——客户必须提供方法的前置条件，供应商可能会验证，然后以后置条件的形式返回一些结果给客户进行检查。

父类与其客户定义了一个合同。这个类的子类必须尊重这样的合同。这意味着，例如：

+   子类永远不能使前置条件比父类中定义的更严格

+   子类永远不能使后置条件比父类中定义的更弱

考虑前一节中定义的事件层次结构的例子，但现在通过一个变化来说明 LSP 和 DbC 之间的关系。

这一次，我们假设了一个方法的前提条件，根据数据检查标准，提供的参数必须是一个包含`"before"`和`"after"`两个键的字典，并且它们的值也是嵌套字典。这使我们能够进一步封装，因为现在客户端不需要捕获`KeyError`异常，而只需调用前提条件方法（假设如果系统在错误的假设下运行是可以失败的）。顺便说一句，很好的是我们可以从客户端中删除这个，因为现在，`SystemMonitor`不需要知道协作者类的方法可能引发哪些类型的异常（请记住，异常会削弱封装，因为它们要求调用者对其所调用的对象有额外的了解）。

这种设计可以通过代码中的以下更改来表示：

```py
# lsp_2.py

class Event:
    def __init__(self, raw_data):
        self.raw_data = raw_data

    @staticmethod
    def meets_condition(event_data: dict):
        return False

    @staticmethod
    def meets_condition_pre(event_data: dict):
        """Precondition of the contract of this interface.

        Validate that the ``event_data`` parameter is properly formed.
        """
        assert isinstance(event_data, dict), f"{event_data!r} is not a dict"
        for moment in ("before", "after"):
            assert moment in event_data, f"{moment} not in {event_data}"
            assert isinstance(event_data[moment], dict)
```

现在尝试检测正确事件类型的代码只检查前提条件一次，然后继续找到正确类型的事件：

```py
# lsp_2.py
class SystemMonitor:
    """Identify events that occurred in the system."""

    def __init__(self, event_data):
        self.event_data = event_data

    def identify_event(self):
        Event.meets_condition_pre(self.event_data)
        event_cls = next(
            (
                event_cls
                for event_cls in Event.__subclasses__()
                if event_cls.meets_condition(self.event_data)
            ),
            UnknownEvent,
        )
        return event_cls(self.event_data)
```

合同只规定顶层键`"before"`和`"after"`是必须的，它们的值也应该是字典。在子类中试图要求更严格的参数将会失败。

交易事件的类最初设计是正确的。看看代码如何不对内部名为`"transaction"`的键施加限制；它只在那里使用它的值，但这不是强制性的：

```py
# lsp_2.py
class TransactionEvent(Event):
    """Represents a transaction that has just occurred on the system."""

    @staticmethod
    def meets_condition(event_data: dict):
        return event_data["after"].get("transaction") is not None
```

然而，原始的两个方法是不正确的，因为它们要求存在一个名为`"session"`的键，这不是原始合同的一部分。这违反了合同，现在客户端无法像使用其他类一样使用这些类，因为它会引发`KeyError`。

在修复这个问题之后（更改了`.get()`方法的方括号），LSP 的顺序已经恢复，多态性占优势：

```py
>>> l1 = SystemMonitor({"before": {"session": 0}, "after": {"session": 1}})
>>> l1.identify_event().__class__.__name__
'LoginEvent'

>>> l2 = SystemMonitor({"before": {"session": 1}, "after": {"session": 0}})
>>> l2.identify_event().__class__.__name__
'LogoutEvent'

>>> l3 = SystemMonitor({"before": {"session": 1}, "after": {"session": 1}})
>>> l3.identify_event().__class__.__name__
'UnknownEvent'

>>> l4 = SystemMonitor({"before": {}, "after": {"transaction": "Tx001"}})
>>> l4.identify_event().__class__.__name__
'TransactionEvent'
```

期望自动化工具（无论它们有多好和有用）能够检测到这种情况是不合理的。在设计类时，我们必须小心，不要意外地改变方法的输入或输出，以使其与客户端最初期望的不兼容。

# LSP 的备注

LSP 对于良好的面向对象软件设计是至关重要的，因为它强调了其核心特性之一——多态性。它是关于创建正确的层次结构，使得从基类派生的类在其接口的方法方面对父类具有多态性。

有趣的是注意到这个原则如何与前一个原则相关联——如果我们尝试用一个不兼容的新类扩展一个类，它将失败，与客户端的合同将被打破，因此这样的扩展将不可能（或者，为了使其可能，我们将不得不打破原则的另一端，并修改应该对修改封闭的客户端代码，这是完全不可取和不可接受的）。

仔细思考 LSP 建议的新类的方式有助于我们正确地扩展层次结构。然后我们可以说 LSP 有助于 OCP。

# 接口隔离

**接口隔离原则**（ISP）提供了一些关于我们已经反复讨论过的想法的指导：接口应该是小的。

在面向对象的术语中，**接口**由对象公开的方法集表示。这就是说，对象能够接收或解释的所有消息构成了它的接口，这是其他客户端可以请求的内容。接口将类的公开行为的定义与其实现分离开来。

在 Python 中，接口是根据类的方法隐式定义的。这是因为 Python 遵循所谓的**鸭子类型**原则。

传统上，鸭子类型的理念是任何对象实际上是由它所拥有的方法和它能够做什么来表示的。这意味着，无论类的类型、名称、文档字符串、类属性或实例属性如何，最终定义对象本质的是它所拥有的方法。类上定义的方法（它知道如何做）决定了对象实际上是什么。它被称为鸭子类型，是因为“如果它走起来像鸭子，叫起来像鸭子，那它一定是鸭子”。

很长一段时间以来，鸭子类型是 Python 中定义接口的唯一方式。后来，Python 3（PEP-3119）引入了抽象基类的概念，作为一种以不同方式定义接口的方法。抽象基类的基本思想是它定义了一种基本行为或接口，一些派生类负责实现。这在我们想要确保某些关键方法实际上被覆盖时非常有用，它还可以作为覆盖或扩展诸如`isinstance()`之类方法功能的机制。

该模块还包含一种将某些类型注册为层次结构的一部分的方法，称为**虚拟子类**。其想法是通过添加一个新的标准——走起来像鸭子，叫起来像鸭子，或者...它说它是鸭子，将鸭子类型的概念扩展得更远一些。

Python 解释接口的这些概念对于理解这个原则和下一个原则非常重要。

抽象地说，这意味着 ISP 规定，当我们定义一个提供多个方法的接口时，最好将其分解为多个接口，每个接口包含较少的方法（最好只有一个），具有非常具体和准确的范围。通过将接口分离为尽可能小的单元，以促进代码的可重用性，想要实现这些接口之一的每个类很可能会具有高度的内聚性，因为它具有相当明确的行为和一组责任。

# 提供太多方法的接口

现在，我们希望能够从不同格式的多个数据源中解析事件（例如 XML 和 JSON）。遵循良好的实践，我们决定将接口作为我们的依赖目标，而不是具体的类，设计如下：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/cln-code-py/img/751713a3-59f5-476d-8481-80da4896f722.png)

为了在 Python 中将其创建为接口，我们将使用抽象基类，并将方法（`from_xml()`和`from_json()`）定义为抽象的，以强制派生类实现它们。从这个抽象基类派生并实现这些方法的事件将能够处理它们对应的类型。

但是，如果特定的类不需要 XML 方法，只能从 JSON 构建，它仍然会携带接口的`from_xml()`方法，因为它不需要它，它将不得不通过。这不太灵活，因为它会创建耦合，并迫使接口的客户端使用它们不需要的方法。

# 接口越小，越好。

最好将其分成两个不同的接口，每个接口对应一个方法：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/cln-code-py/img/979e5d6b-abc5-48da-9353-5bce32fea19f.png)

通过这种设计，从`XMLEventParser`派生并实现`from_xml()`方法的对象将知道如何从 XML 构建，从 JSON 文件构建也是一样，但更重要的是，我们保持了两个独立函数的正交性，并保留了系统的灵活性，而不会失去可以通过组合新的较小对象实现的任何功能。

与 SRP 有些相似，但主要区别在于这里我们谈论的是接口，因此它是行为的抽象定义。没有理由改变，因为在接口实际实现之前什么都没有。然而，不遵守这个原则将创建一个与正交功能耦合的接口，这个派生类也将无法遵守 SRP（它将有多个改变的原因）。

# 接口应该有多小？

前一节提出的观点是有效的，但也需要警告——如果被误解或被过分解读，要避免走上危险的道路。

基类（抽象或非抽象）为所有其他类定义了一个接口来扩展它。这应该尽可能小的事实必须以内聚性的方式理解——它应该只做一件事。这并不意味着它一定必须有一个方法。在前面的例子中，巧合的是两种方法完全不同，因此将它们分开成不同的类是有意义的。

但也可能有多个方法合理地属于同一个类。想象一下，您想提供一个混合类，它在上下文管理器中抽象出某些逻辑，以便所有从该混合类派生的类都可以免费获得该上下文管理器逻辑。正如我们已经知道的那样，上下文管理器包括两种方法：`__enter__`和`__exit__`。它们必须一起使用，否则结果将根本不是有效的上下文管理器！

如果不将两种方法放在同一个类中，将导致一个破损的组件，不仅毫无用处，而且具有误导性的危险。希望这个夸张的例子能够对前一节中的例子起到平衡作用，读者可以更准确地了解设计接口。

# 依赖反转

这是一个非常强大的想法，当我们在第九章中探索一些设计模式时，它将再次出现，以及第十章中的*清晰架构*。

**依赖反转原则**（DIP）提出了一个有趣的设计原则，通过它我们可以保护我们的代码，使其不依赖于脆弱、易变或超出我们控制范围的东西。反转依赖的想法是，我们的代码不应该适应细节或具体实现，而是相反的：我们希望通过一种 API 强制任何实现或细节适应我们的代码。

抽象必须以不依赖于细节的方式组织，而是相反的方式——细节（具体实现）应该依赖于抽象。

想象一下，我们设计中的两个对象需要合作，`A`和`B`。`A`与`B`的实例一起工作，但事实证明，我们的模块并不直接控制`B`（它可能是外部库，或者是由另一个团队维护的模块等）。如果我们的代码严重依赖于`B`，当这种情况发生变化时，代码将会崩溃。为了防止这种情况，我们必须反转依赖：使`B`必须适应`A`。这是通过提供一个接口并强制我们的代码不依赖于`B`的具体实现，而是依赖于我们定义的接口来完成的。然后，`B`有责任遵守该接口。

与前几节探讨的概念一致，抽象也以接口的形式出现（或者在 Python 中是抽象基类）。

一般来说，我们可以期望具体实现的变化频率要比抽象组件高得多。正因为如此，我们将抽象（接口）放在我们期望系统发生变化、被修改或扩展的灵活性点上，而不必更改抽象本身。

# 刚性依赖的情况

我们事件监控系统的最后一部分是将识别的事件传递给数据收集器进行进一步分析。这样一个想法的天真实现将包括一个与数据目标交互的事件流类，例如`Syslog`：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/cln-code-py/img/27118de7-913e-4957-94b4-f3b2394f2006.png)

然而，这种设计并不是很好，因为我们有一个高级类（`EventStreamer`）依赖于一个低级类（`Syslog`是一个实现细节）。如果我们想要以不同的方式发送数据到`Syslog`，`EventStreamer`将不得不进行修改。如果我们想要在运行时更改数据目标为另一个目标或添加新目标，我们也会遇到麻烦，因为我们将不断修改`stream()`方法以适应这些要求。

# 倒置依赖关系

解决这些问题的方法是使`EventStreamer`使用接口而不是具体类。这样，实现这个接口取决于包含实现细节的低级类：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/cln-code-py/img/530270e6-552a-4c55-b49f-777b4ec37080.png)

现在有一个表示通用数据目标的接口，数据将被发送到该接口。请注意，依赖关系已经被倒置，因为`EventStreamer`不依赖于特定数据目标的具体实现，它不必随着此数据目标的更改而更改，而是由每个特定的数据目标来正确实现接口并根据需要进行调整。

换句话说，第一个实现的原始`EventStreamer`只能与类型为`Syslog`的对象一起工作，这并不太灵活。然后我们意识到它可以与任何能够响应`.send()`消息的对象一起工作，并确定这个方法是它需要遵守的接口。现在，在这个版本中，`Syslog`实际上是扩展了名为`DataTargetClient`的抽象基类，该类定义了`send()`方法。从现在开始，每种新类型的数据目标（例如电子邮件）都要扩展这个抽象基类并实现`send()`方法。

我们甚至可以在运行时修改此属性以适用于实现`send()`方法的任何其他对象，它仍然可以工作。这就是为什么它经常被称为**依赖注入**的原因：因为依赖关系可以动态提供。

热心的读者可能会想知道为什么这是必要的。Python 足够灵活（有时太灵活了），并且允许我们向`EventStreamer`提供任何特定数据目标对象，而无需该对象遵守任何接口，因为它是动态类型的。问题是：当我们可以简单地向其传递具有`send()`方法的对象时，为什么我们需要定义抽象基类（接口）呢？

公平地说，这是真的；实际上并不需要这样做，程序仍然可以正常工作。毕竟，多态性并不意味着（或要求）继承才能工作。然而，定义抽象基类是一种良好的实践，带来了一些优势，第一个优势是鸭子类型。除了鸭子类型，我们还可以提到模型变得更易读的事实——请记住，继承遵循**是一个**规则，因此通过声明抽象基类并从中扩展，我们在说，例如，`Syslog`是`DataTargetClient`，这是您的代码用户可以阅读和理解的内容（再次强调，这是鸭子类型）。

总的来说，定义抽象基类并不是强制性的，但为了实现更清晰的设计是值得的。这本书的目的之一就是帮助程序员避免犯易犯的错误，因为 Python 太灵活了，我们可以逃避这些错误。

# 摘要

SOLID 原则是良好的面向对象软件设计的关键指导原则。

构建软件是一项非常艰巨的任务——代码的逻辑是复杂的，它在运行时的行为很难（有时甚至是不可能）预测，要求不断变化，环境也在不断变化，还有很多事情可能会出错。

此外，有多种构建软件的方式，不同的技术、范式和许多不同的设计可以共同解决特定问题。然而，并非所有这些方法随着时间的推移都会被证明是正确的，要求也会变化或演变。然而，到那时，要对不正确的设计做出改变已经为时已晚，因为它是僵化的、不灵活的，因此很难将其重构为正确的解决方案。

这意味着，如果我们设计错误，将会在未来付出很大的代价。那么我们如何才能实现最终会有回报的良好设计呢？答案是我们并不确定。我们正在处理未来，而未来是不确定的——我们无法确定我们的设计是否正确，我们的软件是否在未来几年内灵活和适应。正是因为这个原因，我们必须坚持原则。

这就是 SOLID 原则发挥作用的地方。它们并不是魔法规则（毕竟，在软件工程中没有银弹），但它们提供了良好的指导方针，这些指导方针在过去的项目中已被证明有效，并且会使我们的软件更有可能成功。

在本章中，我们探讨了 SOLID 原则，目的是理解清晰的设计。在接下来的章节中，我们将继续探讨语言的细节，并在某些情况下看到这些工具和特性如何与这些原则一起使用。

# 参考资料

以下是您可以参考的信息列表：

+   *SRP 01*：单一责任原则（[`8thlight.com/blog/uncle-bob/2014/05/08/SingleReponsibilityPrinciple.html`](https://8thlight.com/blog/uncle-bob/2014/05/08/SingleReponsibilityPrinciple.html)）

+   *PEP-3119*：引入抽象基类（[`www.python.org/dev/peps/pep-3119/`](https://www.python.org/dev/peps/pep-3119/)）

+   *LISKOV 01*：由 Barbara Liskov 撰写的一篇名为*数据抽象和层次结构*的论文。


# 第五章：使用装饰器改进我们的代码

在本章中，我们将探讨装饰器，并看到它们在许多情况下如何有用，我们想要改进我们的设计。我们将首先探讨装饰器是什么，它们是如何工作的，以及它们是如何实现的。

有了这些知识，我们将重新审视我们在以前章节中学到的关于软件设计的一般良好实践，并看看装饰器如何帮助我们遵守每个原则。

本章的目标如下：

+   了解 Python 中装饰器的工作原理

+   学习如何实现适用于函数和类的装饰器

+   有效实现装饰器，避免常见的实现错误

+   分析如何通过装饰器避免代码重复（DRY 原则）

+   研究装饰器如何有助于关注点分离

+   分析良好装饰器的示例

+   审查常见情况、习语或模式，以确定装饰器是正确的选择

# Python 中的装饰器是什么？

装饰器在 Python 中很久以前就被引入了（PEP-318），作为一种简化函数和方法定义的机制，当它们在原始定义之后需要被修改时。

最初的动机之一是因为诸如`classmethod`和`staticmethod`之类的函数被用来转换方法的原始定义，但它们需要额外的一行，修改函数的原始定义。

更一般地说，每当我们必须对函数应用转换时，我们必须使用`modifier`函数调用它，然后将其重新分配给与函数最初定义的相同名称。

例如，如果我们有一个名为`original`的函数，然后我们有一个在其上更改`original`行为的函数，称为`modifier`，我们必须编写类似以下的内容：

```py
def original(...):
    ...
original = modifier(original)
```

注意我们如何更改函数并将其重新分配给相同的名称。这很令人困惑，容易出错（想象有人忘记重新分配函数，或者确实重新分配了函数，但不是在函数定义后的下一行，而是在更远的地方），而且很麻烦。因此，语言中添加了一些语法支持。

前面的示例可以这样重写：

```py
@modifier
def original(...):
   ...
```

这意味着装饰器只是调用装饰器后面的内容作为装饰器本身的第一个参数的语法糖，结果将是装饰器返回的内容。

根据 Python 术语和我们的示例，`modifier`是我们称之为装饰器，`original`是被装饰的函数，通常也称为“wrapped”对象。

虽然最初的功能是为方法和函数设计的，但实际的语法允许对任何类型的对象进行装饰，因此我们将探讨应用于函数、方法、生成器和类的装饰器。

最后一点是，虽然装饰器的名称是正确的（毕竟，装饰器实际上是在对`wrapped`函数进行更改、扩展或处理），但它不应与装饰器设计模式混淆。

# 装饰函数

函数可能是 Python 对象的最简单表示形式，可以对函数使用装饰器来应用各种逻辑——我们可以验证参数、检查前提条件、完全改变行为、修改其签名、缓存结果（创建原始函数的记忆版本），等等。

例如，我们将创建一个实现“重试”机制的基本装饰器，控制特定领域级别的异常并重试一定次数：

```py
# decorator_function_1.py
class ControlledException(Exception):
    """A generic exception on the program's domain."""

def retry(operation):
    @wraps(operation)
    def wrapped(*args, **kwargs):
        last_raised = None
        RETRIES_LIMIT = 3
        for _ in range(RETRIES_LIMIT):
            try:
                return operation(*args, **kwargs)
            except ControlledException as e:
                logger.info("retrying %s", operation.__qualname__)
                last_raised = e
        raise last_raised

    return wrapped
```

现在可以忽略`@wraps`的使用，因为它将在名为*有效装饰器-避免常见错误*的部分中进行介绍。在 for 循环中使用`_`，意味着这个数字被赋值给一个我们目前不感兴趣的变量，因为它在 for 循环内没有被使用（在 Python 中命名`_`的值被忽略是一个常见的习惯）。

`retry`装饰器不接受任何参数，因此可以轻松地应用到任何函数，如下所示：

```py
@retry
def run_operation(task):
    """Run a particular task, simulating some failures on its execution."""
    return task.run()
```

正如在开头解释的那样，在`run_operation`的顶部定义`@retry`只是 Python 提供的语法糖，实际上执行`run_operation = retry(run_operation)`。

在这个有限的例子中，我们可以看到装饰器如何被用来创建一个通用的`retry`操作，根据一定的条件（在这种情况下，表示为可能与超时相关的异常），允许调用被装饰的代码多次。

# 装饰类

类也可以使用相同的语法装饰（PEP-3129）作用于函数。唯一的区别是，在编写这个装饰器的代码时，我们必须考虑到我们接收到的是一个类，而不是一个函数。

一些从业者可能会认为装饰一个类是相当复杂的，这种情况可能会危及可读性，因为我们会在类中声明一些属性和方法，但在幕后，装饰器可能会应用会使一个完全不同的类。

这个评估是正确的，但只有在这种技术被滥用的情况下。客观地说，这与装饰函数没有什么不同；毕竟，类只是 Python 生态系统中的另一种对象类型，就像函数一样。我们将在标题为*装饰器和关注点分离*的部分中审查这个问题的利弊，但现在我们将探讨特别适用于类的装饰器的好处：

+   所有重用代码和 DRY 原则的好处。类装饰器的一个有效案例是强制多个类符合某个接口或标准（通过在将应用于这些多个类的装饰器中只进行一次检查）。

+   我们可以创建更小或更简单的类，稍后可以通过装饰器进行增强。

+   我们需要应用到某个类的转换逻辑，如果我们使用装饰器，将会更容易维护，而不是使用更复杂（通常是被不鼓励的）方法，比如元类。

在所有可能的装饰器应用中，我们将探讨一个简单的例子，以给出它们可以有用的事情的一些想法。请记住，这不是类装饰器的唯一应用类型，但我们展示的代码也可能有许多其他多种解决方案，都有各自的利弊，但我们选择了装饰器，目的是说明它们的用处。

回顾我们的监控平台的事件系统，现在我们需要为每个事件转换数据并将其发送到外部系统。然而，每种类型的事件在选择如何发送其数据时可能有其自己的特殊之处。

特别是，登录的`event`可能包含诸如我们想要隐藏的凭据之类的敏感信息。其他字段，比如`timestamp`，也可能需要一些转换，因为我们想以特定格式显示它们。满足这些要求的第一次尝试可能就像有一个映射到每个特定`event`的类，并且知道如何对其进行序列化：

```py
class LoginEventSerializer:
    def __init__(self, event):
        self.event = event

    def serialize(self) -> dict:
        return {
            "username": self.event.username,
            "password": "**redacted**",
            "ip": self.event.ip,
            "timestamp": self.event.timestamp.strftime("%Y-%m-%d 
             %H:%M"),
        }

class LoginEvent:
    SERIALIZER = LoginEventSerializer

    def __init__(self, username, password, ip, timestamp):
        self.username = username
        self.password = password
        self.ip = ip
        self.timestamp = timestamp

    def serialize(self) -> dict:
        return self.SERIALIZER(self).serialize()
```

在这里，我们声明了一个类，它将直接与登录事件进行映射，包含了它的逻辑——隐藏`password`字段，并按要求格式化`timestamp`。

虽然这种方法有效，看起来可能是一个不错的选择，但随着时间的推移，当我们想要扩展我们的系统时，我们会发现一些问题：

+   **类太多**：随着事件数量的增加，序列化类的数量也会按同等数量级增长，因为它们是一对一映射的。

+   **解决方案不够灵活**：如果我们需要重用组件的部分（例如，我们需要隐藏另一种类型的`event`中也有的`password`），我们将不得不将其提取到一个函数中，但也要从多个类中重复调用它，这意味着我们实际上并没有重用太多代码。

+   **样板代码**：`serialize()`方法必须存在于所有`event`类中，调用相同的代码。尽管我们可以将其提取到另一个类中（创建一个 mixin），但这似乎不是继承的好用法。

另一种解决方案是能够动态构造一个对象，给定一组过滤器（转换函数）和一个`event`实例，能够通过将这些过滤器应用于其字段来对其进行序列化。然后，我们只需要定义转换每种字段类型的函数，序列化器通过组合许多这些函数来创建。

有了这个对象后，我们可以装饰类以添加`serialize()`方法，它将只调用这些`Serialization`对象本身：

```py

def hide_field(field) -> str:
    return "**redacted**"

def format_time(field_timestamp: datetime) -> str:
    return field_timestamp.strftime("%Y-%m-%d %H:%M")

def show_original(event_field):
    return event_field

class EventSerializer:
    def __init__(self, serialization_fields: dict) -> None:
        self.serialization_fields = serialization_fields

    def serialize(self, event) -> dict:
        return {
            field: transformation(getattr(event, field))
            for field, transformation in 
            self.serialization_fields.items()
        }

class Serialization:

    def __init__(self, **transformations):
        self.serializer = EventSerializer(transformations)

    def __call__(self, event_class):
        def serialize_method(event_instance):
            return self.serializer.serialize(event_instance)
        event_class.serialize = serialize_method
        return event_class

@Serialization(
    username=show_original,
    password=hide_field,
    ip=show_original,
    timestamp=format_time,
)
class LoginEvent:

    def __init__(self, username, password, ip, timestamp):
        self.username = username
        self.password = password
        self.ip = ip
        self.timestamp = timestamp
```

请注意，装饰器使用户更容易知道每个字段将如何处理，而无需查看另一个类的代码。只需阅读传递给类装饰器的参数，我们就知道`username`和 IP 地址将保持不变，`password`将被隐藏，`timestamp`将被格式化。

现在，类的代码不需要定义`serialize()`方法，也不需要扩展实现它的 mixin，因为装饰器将添加它。实际上，这可能是唯一证明创建类装饰器的部分，因为否则，`Serialization`对象可以是`LoginEvent`的类属性，但它正在通过向其添加新方法来更改类的事实使其成为不可能。

此外，我们可以有另一个类装饰器，只需定义类的属性，就可以实现`init`方法的逻辑，但这超出了本示例的范围。这就是诸如`attrs`（ATTRS 01）这样的库所做的事情，标准库中的（PEP-557）也提出了类似的功能。

通过使用 Python 3.7+中的（PEP-557）中的这个类装饰器，可以以更紧凑的方式重写先前的示例，而不需要`init`的样板代码，如下所示：

```py
from dataclasses import dataclass
from datetime import datetime

@Serialization(
    username=show_original,
    password=hide_field,
    ip=show_original,
    timestamp=format_time,
)
@dataclass
class LoginEvent:
    username: str
    password: str
    ip: str
    timestamp: datetime
```

# 其他类型的装饰器

现在我们知道了装饰器的`@`语法实际上意味着什么，我们可以得出结论，不仅可以装饰函数、方法或类；实际上，任何可以定义的东西，例如生成器、协程，甚至已经被装饰的对象，都可以被装饰，这意味着装饰器可以被堆叠。

先前的示例展示了装饰器如何链接。我们首先定义了类，然后对其应用了`@dataclass`，将其转换为数据类，充当这些属性的容器。之后，`@Serialization`将对该类应用逻辑，从而产生一个新的类，其中添加了新的`serialize()`方法。

装饰器的另一个很好的用途是用于应该用作协程的生成器。我们将在第七章中探讨生成器和协程的细节，但主要思想是，在向新创建的生成器发送任何数据之前，必须通过调用`next()`将其推进到下一个`yield`语句。这是每个用户都必须记住的手动过程，因此容易出错。我们可以轻松地创建一个装饰器，它以生成器作为参数，调用`next()`，然后返回生成器。

# 将参数传递给装饰器

到目前为止，我们已经将装饰器视为 Python 中的强大工具。但是，如果我们可以向它们传递参数，使其逻辑更加抽象，它们可能会更加强大。

实现装饰器的几种方法，可以接受参数，但我们将介绍最常见的方法。第一种方法是将装饰器创建为嵌套函数，增加一个新的间接层，使装饰器中的所有内容深入一层。第二种方法是使用类作为装饰器。

一般来说，第二种方法更有利于可读性，因为以对象的方式思考比使用三个或更多个嵌套函数与闭包更容易。然而，为了完整起见，我们将探讨两种方法，读者可以决定对于手头的问题哪种方法更好。

# 带有嵌套函数的装饰器

大致来说，装饰器的一般思想是创建一个返回函数的函数（通常称为高阶函数）。在装饰器主体中定义的内部函数将是实际被调用的函数。

现在，如果我们希望向其传递参数，那么我们需要另一个间接层。第一个将接受参数，并在该函数内部，我们将定义一个新函数，这将是装饰器，然后将定义另一个新函数，即作为装饰过程的结果返回的函数。这意味着我们将至少有三个级别的嵌套函数。

如果到目前为止这还不清楚，不要担心。在查看即将出现的示例之后，一切都会变得清晰起来。

我们看到的第一个装饰器的示例是在一些函数上实现`retry`功能。这是一个好主意，但是有一个问题；我们的实现不允许我们指定重试次数，而是在装饰器内部是一个固定的数字。

现在，我们希望能够指示每个实例将具有多少次重试，也许我们甚至可以为此参数添加一个默认值。为了做到这一点，我们需要另一个级别的嵌套函数——首先是参数，然后是装饰器本身。

这是因为我们现在将有以下形式的东西：

```py
 @retry(arg1, arg2,... )
```

并且必须返回一个装饰器，因为`@`语法将该计算的结果应用于要装饰的对象。从语义上讲，它将转换为以下内容：

```py
  <original_function> = retry(arg1, arg2, ....)(<original_function>)
```

除了所需的重试次数，我们还可以指示我们希望控制的异常类型。支持新要求的代码的新版本可能如下所示：

```py
RETRIES_LIMIT = 3

def with_retry(retries_limit=RETRIES_LIMIT, allowed_exceptions=None):
    allowed_exceptions = allowed_exceptions or (ControlledException,)

    def retry(operation):

        @wraps(operation)
        def wrapped(*args, **kwargs):
            last_raised = None
            for _ in range(retries_limit):
                try:
                    return operation(*args, **kwargs)
                except allowed_exceptions as e:
                    logger.info("retrying %s due to %s", operation, e)
                    last_raised = e
            raise last_raised

        return wrapped

    return retry
```

以下是如何将此装饰器应用于函数的一些示例，显示它接受的不同选项：

```py
# decorator_parametrized_1.py
@with_retry()
def run_operation(task):
    return task.run()

@with_retry(retries_limit=5)
def run_with_custom_retries_limit(task):
    return task.run()

@with_retry(allowed_exceptions=(AttributeError,))
def run_with_custom_exceptions(task):
    return task.run()

@with_retry(
    retries_limit=4, allowed_exceptions=(ZeroDivisionError, AttributeError)
)
def run_with_custom_parameters(task):
    return task.run()
```

# 装饰器对象

前面的示例需要三个级别的嵌套函数。第一个将是一个接收我们想要使用的装饰器的参数的函数。在这个函数内部，其余的函数都是使用这些参数以及装饰器的逻辑的闭包。

更干净的实现方法是使用类来定义装饰器。在这种情况下，我们可以在`__init__`方法中传递参数，然后在名为`__call__`的魔术方法上实现装饰器的逻辑。

装饰器的代码看起来像以下示例中的样子：

```py
class WithRetry:

    def __init__(self, retries_limit=RETRIES_LIMIT, allowed_exceptions=None):
        self.retries_limit = retries_limit
        self.allowed_exceptions = allowed_exceptions or (ControlledException,)

    def __call__(self, operation):

        @wraps(operation)
        def wrapped(*args, **kwargs):
            last_raised = None

            for _ in range(self.retries_limit):
                try:
                    return operation(*args, **kwargs)
                except self.allowed_exceptions as e:
                    logger.info("retrying %s due to %s", operation, e)
                    last_raised = e
            raise last_raised

        return wrapped
```

这个装饰器可以应用得和之前的一个差不多，像这样：

```py
@WithRetry(retries_limit=5)
def run_with_custom_retries_limit(task):
    return task.run()
```

重要的是要注意 Python 语法在这里的作用。首先，我们创建对象，因此在应用`@`操作之前，对象已经被创建，并且其参数传递给它。这将创建一个新对象，并使用`init`方法中定义的这些参数进行初始化。之后，调用`@`操作，因此这个对象将包装名为`run_with_custom_reries_limit`的函数，这意味着它将被传递给`call`魔术方法。

在这个`call`魔术方法中，我们像往常一样定义了装饰器的逻辑-我们包装原始函数，返回一个具有我们想要的逻辑的新函数。

# 装饰器的好处

在本节中，我们将看一些常见的模式，这些模式充分利用了装饰器。这些都是装饰器是一个不错选择的常见情况。

从装饰器可以使用的无数应用中，我们将列举一些最常见或相关的：

+   **转换参数**：更改函数的签名以公开更好的 API，同时封装有关如何处理和转换参数的细节

+   **跟踪代码**：记录函数的执行及其参数

+   **验证参数**

+   **实现重试操作**

+   **通过将一些（重复的）逻辑移入装饰器来简化类**

让我们在下一节详细讨论前两个应用。

# 转换参数

我们之前提到过，装饰器可以用于验证参数（甚至在 DbC 的概念下强制执行一些前置条件或后置条件），因此您可能已经得到这样的想法，即在处理或操作参数时，使用装饰器是很常见的。

特别是，在某些情况下，我们发现自己反复创建类似的对象，或者应用类似的转换，我们希望将其抽象化。大多数情况下，我们可以通过简单地使用装饰器来实现这一点。

# 跟踪代码

在本节讨论“跟踪”时，我们将指的是处理我们希望监视的函数的执行的更一般的内容。这可能涉及到我们希望的一些情况：

+   实际上跟踪函数的执行（例如，通过记录它执行的行）

+   监视函数的一些指标（如 CPU 使用率或内存占用）

+   测量函数的运行时间

+   记录函数调用的时间和传递给它的参数

在下一节中，我们将探讨一个简单的例子，即记录函数的执行情况，包括其名称和运行所花费的时间的装饰器。

# 有效的装饰器-避免常见错误

虽然装饰器是 Python 的一个很棒的特性，但如果使用不当，它们也不免有问题。在本节中，我们将看到一些常见的问题，以避免创建有效的装饰器。

# 保留有关原始包装对象的数据

将装饰器应用于函数时最常见的问题之一是，原始函数的某些属性或属性未得到保留，导致不希望的、难以跟踪的副作用。

为了说明这一点，我们展示了一个负责记录函数即将运行时的装饰器：

```py
# decorator_wraps_1.py

def trace_decorator(function):
    def wrapped(*args, **kwargs):
        logger.info("running %s", function.__qualname__)
        return function(*args, **kwargs)

    return wrapped
```

现在，让我们想象一下，我们有一个应用了这个装饰器的函数。我们可能最初会认为该函数的任何部分都没有修改其原始定义：

```py
@trace_decorator
def process_account(account_id):
    """Process an account by Id."""
    logger.info("processing account %s", account_id)
    ...
```

但也许有一些变化。

装饰器不应该改变原始函数的任何内容，但事实证明，由于它包含一个缺陷，它实际上修改了其名称和`docstring`等属性。

让我们尝试为这个函数获取`help`：

```py
>>> help(process_account)
Help on function wrapped in module decorator_wraps_1:

wrapped(*args, **kwargs) 
```

让我们检查它是如何被调用的：

```py
>>> process_account.__qualname__
'trace_decorator.<locals>.wrapped'
```

我们可以看到，由于装饰器实际上是将原始函数更改为一个新函数（称为`wrapped`），我们实际上看到的是这个函数的属性，而不是原始函数的属性。

如果我们将这样一个装饰器应用于多个函数，它们都有不同的名称，它们最终都将被称为`wrapped`，这是一个主要问题（例如，如果我们想要记录或跟踪函数，这将使调试变得更加困难）。

另一个问题是，如果我们在这些函数上放置了带有测试的文档字符串，它们将被装饰器的文档字符串覆盖。结果，我们希望的带有测试的文档字符串在我们使用`doctest`模块调用我们的代码时将不会运行（正如我们在第一章中所看到的，*介绍、代码格式和工具*）。

修复很简单。我们只需在内部函数（`wrapped`）中应用`wraps`装饰器，告诉它实际上是在包装`function`：

```py
# decorator_wraps_2.py
def trace_decorator(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        logger.info("running %s", function.__qualname__)
        return function(*args, **kwargs)

    return wrapped
```

现在，如果我们检查属性，我们将得到我们最初期望的结果。像这样检查函数的`help`：

```py
>>> Help on function process_account in module decorator_wraps_2:

process_account(account_id)
    Process an account by Id. 
```

并验证其合格的名称是否正确，如下所示：

```py
>>> process_account.__qualname__
'process_account'
```

最重要的是，我们恢复了可能存在于文档字符串中的单元测试！通过使用`wraps`装饰器，我们还可以在`__wrapped__`属性下访问原始的未修改的函数。虽然不应该在生产中使用，但在一些单元测试中，当我们想要检查函数的未修改版本时，它可能会派上用场。

通常，对于简单的装饰器，我们使用`functools.wraps`的方式通常遵循以下一般公式或结构：

```py
def decorator(original_function):
    @wraps(original_function)
    def decorated_function(*args, **kwargs):
        # modifications done by the decorator ...
        return original_function(*args, **kwargs)

    return decorated_function
```

在创建装饰器时，通常对包装的函数应用`functools.wraps`，如前面的公式所示。

# 处理装饰器中的副作用

在本节中，我们将了解在装饰器的主体中避免副作用是明智的。有些情况下可能是可以接受的，但最重要的是，如果有疑问，最好不要这样做，原因将在后面解释。

尽管如此，有时这些副作用是必需的（甚至是期望的）在导入时运行，反之亦然。

我们将看到两者的示例，以及每种情况的适用情况。如果有疑问，最好谨慎行事，并将所有副作用延迟到最后，就在`wrapped`函数将被调用之后。

接下来，我们将看到在`wrapped`函数之外放置额外逻辑不是一个好主意的情况。

# 装饰器中副作用的处理不正确

让我们想象一个创建目的是在函数开始运行时记录日志，然后记录其运行时间的装饰器的情况：

```py
def traced_function_wrong(function):
    logger.info("started execution of %s", function)
    start_time = time.time()

    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        result = function(*args, **kwargs)
        logger.info(
            "function %s took %.2fs",
            function,
            time.time() - start_time
        )
        return result
    return wrapped
```

现在，我们将装饰器应用到一个常规函数上，认为它会正常工作：

```py
@traced_function_wrong
def process_with_delay(callback, delay=0):
    time.sleep(delay)
    return callback()
```

这个装饰器有一个微妙但关键的错误。

首先，让我们导入函数，多次调用它，看看会发生什么：

```py
>>> from decorator_side_effects_1 import process_with_delay
INFO:started execution of <function process_with_delay at 0x...>
```

通过导入函数，我们会注意到有些地方不对劲。日志行不应该出现在那里，因为函数没有被调用。

现在，如果我们运行函数，看看运行需要多长时间？实际上，我们期望多次调用相同的函数会得到类似的结果：

```py
>>> main()
...
INFO:function <function process_with_delay at 0x> took 8.67s

>>> main()
...
INFO:function <function process_with_delay at 0x> took 13.39s

>>> main()
...
INFO:function <function process_with_delay at 0x> took 17.01s
```

每次运行相同的函数，都会花费更长的时间！此时，您可能已经注意到（现在显而易见的）错误。

除了装饰的函数之外，装饰器需要做的一切都应该放在最内部的函数定义中，否则在导入时会出现问题。

```py
process_with_delay = traced_function_wrong(process_with_delay)
```

这将在模块导入时运行。因此，函数中设置的时间将是模块导入时的时间。连续调用将计算从运行时间到原始开始时间的时间差。它还将在错误的时刻记录，而不是在实际调用函数时。

幸运的是，修复也很简单——我们只需将代码移到`wrapped`函数内部以延迟其执行：

```py
def traced_function(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        logger.info("started execution of %s", function.__qualname__)
        start_time = time.time()
        result = function(*args, **kwargs)
        logger.info(
            "function %s took %.2fs",
            function.__qualname__,
            time.time() - start_time
        )
        return result
    return wrapped
```

记住装饰器的语法。`@traced_function_wrong`实际上意味着以下内容：

如果装饰器的操作不同，结果可能会更加灾难性。例如，如果它要求您记录事件并将其发送到外部服务，除非在导入此模块之前正确运行了配置，否则肯定会失败，而这是我们无法保证的。即使我们可以，这也是不好的做法。如果装饰器具有其他任何形式的副作用，例如从文件中读取、解析配置等，也是一样。

# 需要具有副作用的装饰器

有时，装饰器上的副作用是必要的，我们不应该延迟它们的执行直到最后可能的时间，因为这是它们工作所需的机制的一部分。

当我们不想延迟装饰器的副作用时，一个常见的情况是，我们需要将对象注册到一个将在模块中可用的公共注册表中。

例如，回到我们之前的`event`系统示例，现在我们只想在模块中使一些事件可用，而不是所有事件。在事件的层次结构中，我们可能希望有一些中间类，它们不是我们想要在系统上处理的实际事件，而是它们的一些派生类。

我们可以通过装饰器显式注册每个类，而不是根据它是否要被处理来标记每个类。

在这种情况下，我们有一个与用户活动相关的所有事件的类。然而，这只是我们实际想要的事件类型的中间表，即`UserLoginEvent`和`UserLogoutEvent`：

```py
EVENTS_REGISTRY = {}

def register_event(event_cls):
    """Place the class for the event into the registry to make it 
    accessible in
    the module.
    """
    EVENTS_REGISTRY[event_cls.__name__] = event_cls
    return event_cls

class Event:
    """A base event object"""

class UserEvent:
    TYPE = "user"

@register_event
class UserLoginEvent(UserEvent):
    """Represents the event of a user when it has just accessed the system."""

@register_event
class UserLogoutEvent(UserEvent):
    """Event triggered right after a user abandoned the system."""
```

当我们查看前面的代码时，似乎`EVENTS_REGISTRY`是空的，但在从这个模块导入一些内容之后，它将被填充为所有在`register_event`装饰器下的类。

```py
>>> from decorator_side_effects_2 import EVENTS_REGISTRY
>>> EVENTS_REGISTRY
{'UserLoginEvent': decorator_side_effects_2.UserLoginEvent,
 'UserLogoutEvent': decorator_side_effects_2.UserLogoutEvent}
```

这可能看起来很难阅读，甚至具有误导性，因为`EVENTS_REGISTRY`将在运行时具有其最终值，就在模块导入后，我们无法仅通过查看代码来轻松预测其值。

虽然在某些情况下这种模式是合理的。事实上，许多 Web 框架或知名库使用这种模式来工作和公开对象或使它们可用。

在这种情况下，装饰器并没有改变`wrapped`对象，也没有以任何方式改变它的工作方式。然而，这里需要注意的是，如果我们进行一些修改并定义一个修改`wrapped`对象的内部函数，我们可能仍然希望在外部注册生成的对象的代码。

注意使用*outside*这个词。它不一定意味着之前，它只是不属于同一个闭包；但它在外部范围，因此不会延迟到运行时。

# 创建始终有效的装饰器

装饰器可能适用于几种不同的情况。也可能出现这样的情况，我们需要对落入这些不同多种情况的对象使用相同的装饰器，例如，如果我们想重用我们的装饰器并将其应用于函数、类、方法或静态方法。

如果我们创建装饰器，只考虑支持我们想要装饰的第一种对象类型，我们可能会注意到相同的装饰器在不同类型的对象上效果不同。典型的例子是，我们创建一个用于函数的装饰器，然后想将其应用于类的方法，结果发现它不起作用。如果我们为方法设计了装饰器，然后希望它也适用于静态方法或类方法，可能会发生类似的情况。

在设计装饰器时，我们通常考虑重用代码，因此我们也希望将该装饰器用于函数和方法。

使用`*args`和`**kwargs`签名定义我们的装饰器将使它们在所有情况下都起作用，因为这是我们可以拥有的最通用的签名。然而，有时我们可能不想使用这个，而是根据原始函数的签名定义装饰器包装函数，主要是因为两个原因：

+   它将更易读，因为它类似于原始函数。

+   它实际上需要对参数进行一些处理，因此接收`*args`和`**kwargs`将不方便。

考虑我们的代码库中有许多函数需要从参数创建特定对象的情况。例如，我们传递一个字符串，并重复使用它初始化一个驱动程序对象。然后我们认为可以通过使用一个装饰器来消除这种重复。

在下一个例子中，我们假设`DBDriver`是一个知道如何连接和在数据库上运行操作的对象，但它需要一个连接字符串。我们在我们的代码中有的方法，都设计为接收包含数据库信息的字符串，并且总是需要创建一个`DBDriver`实例。装饰器的想法是它将自动进行这种转换——函数将继续接收一个字符串，但装饰器将创建一个`DBDriver`并将其传递给函数，因此在内部我们可以假设我们直接接收到了我们需要的对象。

在下一个清单中展示了在函数中使用这个的例子：

```py
import logging
from functools import wraps

logger = logging.getLogger(__name__)

class DBDriver:
    def __init__(self, dbstring):
        self.dbstring = dbstring

    def execute(self, query):
        return f"query {query} at {self.dbstring}"

def inject_db_driver(function):
    """This decorator converts the parameter by creating a ``DBDriver``
    instance from the database dsn string.
    """
    @wraps(function)
    def wrapped(dbstring):
        return function(DBDriver(dbstring))
    return wrapped

@inject_db_driver
def run_query(driver):
    return driver.execute("test_function")
```

很容易验证，如果我们将一个字符串传递给函数，我们会得到一个`DBDriver`实例完成的结果，所以装饰器的工作是符合预期的：

```py
>>> run_query("test_OK")
'query test_function at test_OK'
```

但现在，我们想在类方法中重用这个相同的装饰器，我们发现了同样的问题：

```py
class DataHandler:
    @inject_db_driver
    def run_query(self, driver):
        return driver.execute(self.__class__.__name__)
```

我们尝试使用这个装饰器，只是意识到它不起作用：

```py
>>> DataHandler().run_query("test_fails")
Traceback (most recent call last):
 ...
TypeError: wrapped() takes 1 positional argument but 2 were given
```

问题是什么？

类中的方法是用额外的参数`self`定义的。

方法只是一种特殊类型的函数，它接收`self`（它们所定义的对象）作为第一个参数。

因此，在这种情况下，装饰器（设计为仅适用于名为`dbstring`的参数）将解释`self`是所说的参数，并调用该方法传递字符串作为 self 的位置，以及在第二个参数的位置上什么都不传，即我们正在传递的字符串。

为了解决这个问题，我们需要创建一个装饰器，它可以同时适用于方法和函数，我们通过将其定义为一个装饰器对象来实现这一点，该对象还实现了协议描述符。

描述符在第七章中有详细解释，*使用生成器*，所以，现在，我们可以将其视为一个可以使装饰器工作的配方。

解决方案是将装饰器实现为一个类对象，并使该对象成为一个描述符，通过实现`__get__`方法。

```py
from functools import wraps
from types import MethodType

class inject_db_driver:
    """Convert a string to a DBDriver instance and pass this to the 
       wrapped function."""

    def __init__(self, function):
        self.function = function
        wraps(self.function)(self)

    def __call__(self, dbstring):
        return self.function(DBDriver(dbstring))

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return self.__class__(MethodType(self.function, instance))
```

描述符的详细信息将在第六章中解释，*使用描述符更充分地利用我们的对象*，但是对于这个例子的目的，我们现在可以说它实际上是将它装饰的可调用对象重新绑定到一个方法，这意味着它将函数绑定到对象，然后使用这个新的可调用对象重新创建装饰器。

对于函数，它仍然有效，因为它根本不会调用`__get__`方法。

# 装饰器与 DRY 原则

我们已经看到装饰器如何允许我们将某些逻辑抽象成一个单独的组件。这样做的主要优势是我们可以多次应用装饰器到不同的对象中，以便重用代码。这遵循了**不要重复自己**（**DRY**）原则，因为我们只定义了某些知识一次。

在前面的部分中实现的“重试”机制是一个很好的例子，它是一个可以多次应用以重用代码的装饰器。我们不是让每个特定的函数包含其“重试”逻辑，而是创建一个装饰器并多次应用它。一旦我们确保装饰器可以同样适用于方法和函数，这就是有意义的。

定义了事件如何表示的类装饰器也符合 DRY 原则，因为它定义了一个特定的位置来序列化事件的逻辑，而无需在不同的类中重复代码。由于我们希望重用这个装饰器并将其应用于许多类，它的开发（和复杂性）是值得的。

当尝试使用装饰器来重用代码时，这最后一点很重要——我们必须绝对确定我们实际上将节省代码。

任何装饰器（特别是如果设计不慎）都会给代码增加另一层间接性，因此会增加更多的复杂性。代码的读者可能希望跟踪装饰器的路径以充分理解函数的逻辑（尽管这些考虑在下一节中有所解决），因此请记住这种复杂性必须得到回报。如果不会有太多的重用，那么不要选择装饰器，而选择一个更简单的选项（也许只是一个单独的函数或另一个小类就足够了）。

但我们如何知道太多的重用是什么？有没有规则来确定何时将现有代码重构为装饰器？在 Python 中，没有特定于装饰器的规则，但我们可以应用软件工程中的一个经验法则（GLASS 01），该法则规定在考虑创建可重用组件之前，应该至少尝试三次使用组件。从同一参考资料（GLASS 01）中还得出了一个观点，即创建可重用组件比创建简单组件困难三倍。

底线是，通过装饰器重用代码是可以接受的，但只有在考虑以下几点时才可以：

+   不要从头开始创建装饰器。等到模式出现并且装饰器的抽象变得清晰时再进行重构。

+   考虑到装饰器必须被应用多次（至少三次）才能实施。

+   将装饰器中的代码保持在最小限度。

# 装饰器和关注点分离

前面列表中的最后一点非常重要，值得单独一节来讨论。我们已经探讨了重用代码的想法，并注意到重用代码的一个关键元素是具有内聚性的组件。这意味着它们应该具有最小的责任水平——只做一件事，只做一件事，并且做得很好。我们的组件越小，就越可重用，也越能在不同的上下文中应用，而不会带有额外的行为，这将导致耦合和依赖，使软件变得僵化。

为了向您展示这意味着什么，让我们回顾一下我们在先前示例中使用的装饰器之一。我们创建了一个装饰器，用类似以下代码的方式跟踪了某些函数的执行：

```py
def traced_function(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        logger.info("started execution of %s", function.__qualname__)
        start_time = time.time()
        result = function(*args, **kwargs)
        logger.info(
            "function %s took %.2fs",
            function.__qualname__,
            time.time() - start_time
        )
        return result
    return wrapped
```

现在，这个装饰器虽然有效，但存在一个问题——它做了不止一件事。它记录了特定函数的调用，并记录了运行所花费的时间。每次使用这个装饰器，我们都要承担这两个责任，即使我们只想要其中一个。

这应该被分解成更小的装饰器，每个装饰器都有更具体和有限的责任：

```py
def log_execution(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        logger.info("started execution of %s", function.__qualname__)
        return function(*kwargs, **kwargs)
    return wrapped

def measure_time(function):
 @wraps(function)
 def wrapped(*args, **kwargs):
 start_time = time.time()
 result = function(*args, **kwargs)

 logger.info("function %s took %.2f", function.__qualname__,
 time.time() - start_time)
 return result
 return wrapped
```

请注意，我们之前所拥有的相同功能可以通过简单地将它们结合起来来实现：

```py
@measure_time
@log_execution
def operation():
    ....
```

注意装饰器的应用顺序也很重要。

不要在一个装饰器中放置多个责任。单一责任原则也适用于装饰器。

# 分析好的装饰器

作为本章的结束语，让我们回顾一些好的装饰器的示例以及它们在 Python 本身以及流行库中的用法。这个想法是获得如何创建好的装饰器的指导方针。

在跳入示例之前，让我们首先确定好的装饰器应该具有的特征：

+   **封装，或关注点分离**：一个好的装饰器应该有效地将它所做的事情和它所装饰的事物之间的不同责任分开。它不能是一个有漏洞的抽象，这意味着装饰器的客户端应该只以黑盒模式调用它，而不知道它实际上是如何实现其逻辑的。

+   **正交性**：装饰器所做的事情应该是独立的，并且尽可能与它所装饰的对象解耦。

+   **可重用性**：希望装饰器可以应用于多种类型，而不仅仅出现在一个函数的一个实例上，因为这意味着它本来可以只是一个函数。它必须足够通用。

装饰器的一个很好的例子可以在 Celery 项目中找到，其中通过将应用程序的`task`装饰器应用到一个函数来定义`task`：

```py
@app.task
def mytask():
   ....
```

这是一个好的装饰器的原因之一是因为它在封装方面非常出色。库的用户只需要定义函数体，装饰器就会自动将其转换为一个任务。`"@app.task"`装饰器肯定包含了大量的逻辑和代码，但这些对`"mytask()"`的主体来说都不相关。这是完全的封装和关注点分离——没有人需要查看装饰器在做什么，因此它是一个不泄漏任何细节的正确抽象。

装饰器的另一个常见用法是在 Web 框架（例如 Pyramid，Flask 和 Sanic 等）中，通过装饰器将视图的处理程序注册到 URL：

```py
@route("/", method=["GET"])
def view_handler(request):
 ...
```

这些类型的装饰器与之前的考虑相同；它们也提供了完全的封装，因为 Web 框架的用户很少（如果有的话）需要知道`"@route"`装饰器在做什么。在这种情况下，我们知道装饰器正在做更多的事情，比如将这些函数注册到 URL 的映射器上，并且它还改变了原始函数的签名，以便为我们提供一个更好的接口，接收一个已经设置好所有信息的请求对象。

前面的两个例子足以让我们注意到关于装饰器的这种用法的另一点。它们符合 API。这些库或框架通过装饰器向用户公开其功能，结果表明装饰器是定义清晰的编程接口的绝佳方式。

这可能是我们应该考虑装饰器的最佳方式。就像在告诉我们事件属性将如何被处理的类装饰器的示例中一样，一个好的装饰器应该提供一个清晰的接口，以便代码的用户知道可以从装饰器中期望什么，而不需要知道它是如何工作的，或者它的任何细节。

# 总结

装饰器是 Python 中强大的工具，可以应用于许多事物，如类、方法、函数、生成器等。我们已经演示了如何以不同的方式创建装饰器，以及不同的目的，并在这个过程中得出了一些结论。

在为函数创建装饰器时，尝试使其签名与被装饰的原始函数匹配。与使用通用的`*args`和`**kwargs`不同，使签名与原始函数匹配将使其更容易阅读和维护，并且它将更接近原始函数，因此对于代码的读者来说更加熟悉。

装饰器是重用代码和遵循 DRY 原则的非常有用的工具。然而，它们的有用性是有代价的，如果不明智地使用，复杂性可能会带来更多的害处。因此，我们强调装饰器应该在实际上会被多次应用（三次或更多次）时使用。与 DRY 原则一样，我们发现关注点分离的想法，目标是尽可能保持装饰器的小巧。

另一个很好的装饰器用法是创建更清晰的接口，例如，通过将类的一部分逻辑提取到装饰器中来简化类的定义。在这个意义上，装饰器还通过提供关于特定组件将要做什么的信息来帮助可读性，而不需要知道如何做（封装）。

在下一章中，我们将看看 Python 的另一个高级特性——描述符。特别是，我们将看到如何借助描述符创建更好的装饰器，并解决本章遇到的一些问题。

# 参考资料

以下是您可以参考的信息列表：

+   *PEP-318*：函数和方法的装饰器（[`www.python.org/dev/peps/pep-0318/`](https://www.python.org/dev/peps/pep-0318/)）

+   *PEP-3129*：类装饰器（[`www.python.org/dev/peps/pep-3129/`](https://www.python.org/dev/peps/pep-3129/)）

+   *WRAPT 01*：[`pypi.org/project/wrapt/`](https://pypi.org/project/wrapt/)

+   *WRAPT 02*：[`wrapt.readthedocs.io/en/latest/decorators.html#universal-decorators`](https://wrapt.readthedocs.io/en/latest/decorators.html#universal-decorators)

+   *Functools 模块*：Python 标准库中`functools`模块中的`wraps`函数（[`docs.python.org/3/library/functools.html#functools.wrap`](https://docs.python.org/3/library/functools.html#functools.wraps)）

+   *ATTRS 01*：`attrs`库（[`pypi.org/project/attrs/`](https://pypi.org/project/attrs/)）

+   *PEP-557*：数据类（[`www.python.org/dev/peps/pep-0557/`](https://www.python.org/dev/peps/pep-0557/)）

+   *GLASS 01*：Robert L. Glass 撰写的书籍*软件工程的事实和谬误*


# 第六章：通过描述符更充分地利用我们的对象

本章介绍了一个在 Python 开发中更为高级的新概念，因为它涉及到描述符。此外，描述符并不是其他语言的程序员熟悉的东西，因此没有简单的类比或类似之处。

描述符是 Python 的另一个独特特性，它将面向对象编程提升到另一个水平，其潜力允许用户构建更强大和可重用的抽象。大多数情况下，描述符的全部潜力都体现在库或框架中。

在本章中，我们将实现与描述符相关的以下目标：

+   了解描述符是什么，它们是如何工作的，以及如何有效地实现它们

+   分析两种类型的描述符（数据和非数据描述符），从它们的概念差异和实现细节方面进行分析

+   通过描述符有效地重用代码

+   分析描述符的良好使用示例，以及如何利用它们来构建我们自己的 API 库

# 描述符的初步了解

首先，我们将探索描述符背后的主要思想，以了解它们的机制和内部工作。一旦这一点清楚，就会更容易吸收不同类型的描述符是如何工作的，我们将在下一节中探讨。

一旦我们对描述符背后的思想有了初步了解，我们将看一个示例，其中它们的使用为我们提供了更清晰和更符合 Python 风格的实现。

# 描述符背后的机制

描述符的工作方式并不是很复杂，但它们的问题在于有很多需要考虑的注意事项，因此这里的实现细节至关重要。

为了实现描述符，我们至少需要两个类。对于这个通用示例，我们将称`client`类为将要利用我们想要在`descriptor`中实现的功能的类（这个类通常只是一个领域模型类，是我们解决方案中创建的常规抽象），我们将称`descriptor`类为实现描述符逻辑的类。

因此，描述符只是一个实现描述符协议的类的实例对象。这意味着这个类必须包含至少一个以下魔术方法（作为 Python 3.6+的描述符协议的一部分）的接口：

+   `__get__`

+   **`__set__`**

+   `__delete__`

+   **`__set_name__`**

为了这个最初的高层次介绍，将使用以下命名约定：

| **名称** | **含义** |
| --- | --- |
| `ClientClass` | 将利用要由描述符实现的功能的领域级抽象。这个类被称为描述符的客户端。这个类包含一个类属性（按照惯例命名为`descriptor`），它是`DescriptorClass`的一个实例。 |
| `DescriptorClass` | 实现`descriptor`本身的类。这个类应该实现一些前面提到的涉及描述符协议的魔术方法。 |
| `client` | `ClientClass`的一个实例。`client = ClientClass()` |
| `descriptor` | `DescriptorClass`的一个实例。`descriptor = DescriptorClass()`。这个对象是一个放置在`ClientClass`中的类属性。 |

这种关系在下图中得到了说明：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/cln-code-py/img/583337dd-c514-4f5d-967b-bd0811b56f7f.png)

要牢记的一个非常重要的观察是，为了使这个协议工作，`descriptor`对象必须被定义为一个类属性。将这个对象创建为一个实例属性是行不通的，因此它必须在类的主体中，而不是在`init`方法中。

始终将`descriptor`对象放置为一个类属性！

稍微批评一下，读者还可以注意到，部分实现描述符协议是可能的——并非所有方法总是必须被定义；相反，我们可以只实现我们需要的方法，我们很快将看到。

现在，我们已经有了结构——我们知道设置了哪些元素以及它们如何交互。我们需要一个用于`descriptor`的类，另一个将使用`descriptor`逻辑的类，这个类将作为类属性具有`descriptor`对象（`DescriptorClass`的实例），以及在调用名为`descriptor`的属性时将遵循描述符协议的`ClientClass`的实例。但现在呢？所有这些在运行时如何组合在一起？

通常，当我们有一个常规类并访问其属性时，我们会按预期获得对象，甚至它们的属性，如下例所示：

```py
>>> class Attribute:
...     value = 42
... 
>>> class Client:
...     attribute = Attribute()
... 
>>> Client().attribute
<__main__.Attribute object at 0x7ff37ea90940>
>>> Client().attribute.value
42
```

但是，在描述符的情况下，情况有所不同。当一个对象被定义为类属性（并且这是一个`descriptor`）时，当一个`client`请求此属性时，我们不是得到对象本身（正如我们从前面的例子中所期望的那样），而是得到了调用`__get__`魔术方法的结果。

让我们从一些仅记录有关上下文的信息并返回相同的`client`对象的简单代码开始：

```py
class DescriptorClass:
    def __get__(self, instance, owner):
        if instance is None:
            return self
        logger.info("Call: %s.__get__(%r, %r)", 
        self.__class__.__name__,instance, owner)
        return instance

class ClientClass:
    descriptor = DescriptorClass()
```

当运行此代码并请求`ClientClass`实例的`descriptor`属性时，我们将发现实际上并没有得到`DescriptorClass`的实例，而是得到了其`__get__()`方法返回的内容：

```py
>>> client = ClientClass()
>>> client.descriptor
INFO:Call: DescriptorClass.__get__(<ClientClass object at 0x...>, <class 'ClientClass'>)
<ClientClass object at 0x...>
>>> client.descriptor is client
INFO:Call: DescriptorClass.__get__(ClientClass object at 0x...>, <class 'ClientClass'>)
True
```

请注意，放置在`__get__`方法下面的日志行被调用，而不是只返回我们创建的对象。在这种情况下，我们让该方法返回`client`本身，从而使最后一条语句的比较成立。在我们更详细地探讨每个方法时，将更详细地解释此方法的参数。

从这个简单但有示例性的例子开始，我们可以开始创建更复杂的抽象和更好的装饰器，因为这里的重要说明是我们有了一个新的（强大的）工具来使用。请注意，这如何以完全不同的方式改变了程序的控制流。有了这个工具，我们可以在`__get__`方法背后抽象出各种逻辑，并使`descriptor`在客户端甚至察觉不到的情况下运行各种转换。这将封装提升到一个新的水平。

# 探索描述符协议的每个方法

到目前为止，我们已经看到了很多描述符在实际中的例子，并且了解了它们的工作原理。这些例子让我们初步了解了描述符的强大之处，但您可能想知道一些我们未能解释的实现细节和习惯用法。

由于描述符只是对象，这些方法将`self`作为第一个参数。对于所有这些方法，这只是指`descriptor`对象本身。

在本节中，我们将详细探讨描述符协议的每个方法，解释每个参数的意义，以及它们的预期用法。

# __get__(self, instance, owner)

第一个参数`instance`指的是调用`descriptor`的对象。在我们的第一个例子中，这意味着`client`对象。

`owner`参数是指对象的类，根据我们的例子（来自*描述符背后的机制*部分的上一个类图），将是`ClientClass`。

从前面的段落中我们得出结论，`__get__`签名中名为`instance`的参数是描述符正在操作的对象，而`owner`是`instance`的类。热心的读者可能会想知道为什么签名会这样定义，毕竟类可以直接从`instance`中获取（`owner = instance.__class__`）。这里有一个特殊情况——当从类（`ClientClass`）而不是从实例（`client`）中调用`descriptor`时，`instance`的值是`None`，但在这种情况下我们可能仍然想要进行一些处理。

通过以下简单的代码，我们可以演示当描述符从类或实例中被调用时的区别。在这种情况下，`__get__`方法对每种情况都做了两件不同的事情。

```py
# descriptors_methods_1.py

class DescriptorClass:
    def __get__(self, instance, owner):
        if instance is None:
            return f"{self.__class__.__name__}.{owner.__name__}"
        return f"value for {instance}"

class ClientClass:

    descriptor = DescriptorClass()
```

当我们直接从`ClientClass`中调用它时，它会做一件事，即用类的名称组成一个命名空间：

```py
>>> ClientClass.descriptor
'DescriptorClass.ClientClass'
```

然后，如果我们从创建的对象中调用它，它将返回另一条消息：

```py
>>> ClientClass().descriptor
'value for <descriptors_methods_1.ClientClass object at 0x...>'
```

一般来说，除非我们真的需要使用`owner`参数做一些事情，最常见的习惯是当`instance`为`None`时，只返回描述符本身。

# __set__(self, instance, value)

当我们尝试给`descriptor`赋值时，就会调用这个方法。它会被以下语句激活，其中`descriptor`是一个实现了`__set__()`的对象。在这种情况下，`instance`参数将是`client`，而`value`将是字符串`"value"`：

```py
client.descriptor = "value"
```

如果`client.descriptor`没有实现`__set__()`，那么`"value"`将完全覆盖`descriptor`。

在给描述符属性赋值时要小心。确保它实现了`__set__`方法，并且我们没有引起不希望的副作用。

默认情况下，这个方法最常见的用途就是在对象中存储数据。然而，到目前为止我们已经看到了描述符的强大之处，我们可以利用它们，例如，如果我们要创建可以多次应用的通用验证对象（再次强调，如果我们不进行抽象，可能会在属性的 setter 方法中重复多次）。

以下清单说明了我们如何利用这个方法来为属性创建通用的`validation`对象，可以使用函数动态创建用于在分配给对象之前验证值的对象：

```py
class Validation:

    def __init__(self, validation_function, error_msg: str):
        self.validation_function = validation_function
        self.error_msg = error_msg

    def __call__(self, value):
        if not self.validation_function(value):
            raise ValueError(f"{value!r} {self.error_msg}")

class Field:

    def __init__(self, *validations):
        self._name = None
        self.validations = validations

    def __set_name__(self, owner, name):
        self._name = name

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return instance.__dict__[self._name]

    def validate(self, value):
        for validation in self.validations:
            validation(value)

    def __set__(self, instance, value):
        self.validate(value)
        instance.__dict__[self._name] = value

class ClientClass:
    descriptor = Field(
        Validation(lambda x: isinstance(x, (int, float)), "is not a 
        number"),
        Validation(lambda x: x >= 0, "is not >= 0"),
    )
```

我们可以在以下清单中看到这个对象的作用：

```py
>>> client = ClientClass()
>>> client.descriptor = 42
>>> client.descriptor
42
>>> client.descriptor = -42
Traceback (most recent call last):
 ...
ValueError: -42 is not >= 0
>>> client.descriptor = "invalid value"
...
ValueError: 'invalid value' is not a number
```

这个想法是，我们通常会将属性放在属性中的东西抽象成一个`descriptor`，并且可以多次重用它。在这种情况下，`__set__()`方法将会做`@property.setter`本来会做的事情。

# __delete__(self, instance)

在以下语句中调用这个方法时，`self`将是`descriptor`属性，`instance`将是这个例子中的`client`对象：

```py
>>> del client.descriptor
```

在下面的例子中，我们使用这个方法来创建一个`descriptor`，目的是防止用户在没有必要的管理权限的情况下删除对象的属性。请注意，在这种情况下，`descriptor`具有用于预测使用它的对象的值的逻辑，而不是不同相关对象的逻辑：

```py
# descriptors_methods_3.py

class ProtectedAttribute:
    def __init__(self, requires_role=None) -> None: 
        self.permission_required = requires_role
        self._name = None

    def __set_name__(self, owner, name):
        self._name = name

    def __set__(self, user, value):
        if value is None:
 raise ValueError(f"{self._name} can't be set to None")
        user.__dict__[self._name] = value

    def __delete__(self, user):
        if self.permission_required in user.permissions:
            user.__dict__[self._name] = None
        else:
            raise ValueError(
                f"User {user!s} doesn't have {self.permission_required} "
                "permission"
            )

class User:
    """Only users with "admin" privileges can remove their email address."""

    email = ProtectedAttribute(requires_role="admin")

    def __init__(self, username: str, email: str, permission_list: list = None) -> None:
        self.username = username
        self.email = email
        self.permissions = permission_list or []

    def __str__(self):
        return self.username
```

在看到这个对象如何工作的例子之前，重要的是要注意这个描述符的一些标准。注意`User`类要求`username`和`email`作为强制参数。根据其`**__init__**`方法，如果没有`email`属性，它就不能成为用户。如果我们要删除该属性，并从对象中完全提取它，我们将创建一个不一致的对象，其中包含一些无效的中间状态，这些状态与`User`类定义的接口不符。像这样的细节非常重要，以避免问题。其他对象期望与这个`User`一起工作，并且也期望它有一个`email`属性。

因此，决定“删除”电子邮件只会将其简单地设置为`None`，这是代码清单中加粗部分的一部分。出于同样的原因，我们必须禁止有人尝试将`None`值设置为它，因为那样会绕过我们放置在`**__delete__**`方法中的机制。

在这里，我们可以看到它的作用，假设只有具有`"admin"`权限的用户才能删除他们的电子邮件地址：

```py
>>> admin = User("root", "root@d.com", ["admin"])
>>> user = User("user", "user1@d.com", ["email", "helpdesk"]) 
>>> admin.email
'root@d.com'
>>> del admin.email
>>> admin.email is None
True
>>> user.email
'user1@d.com'
>>> user.email = None
...
ValueError: email can't be set to None
>>> del user.email
...
ValueError: User user doesn't have admin permission
```

在这个简单的`descriptor`中，我们可以看到只有包含`"admin"`权限的用户才能删除用户的电子邮件。至于其他情况，当我们尝试在该属性上调用`del`时，我们将得到一个`ValueError`异常。

一般来说，描述符的这种方法并不像前两种方法那样常用，但是出于完整性的考虑，还是值得展示一下。

# __set_name__(self, owner, name)

当我们在将要使用它的类中创建`descriptor`对象时，通常需要`descriptor`知道它将要处理的属性的名称。

这个属性名称是我们在`__get__`和`__set__`方法中从`__dict__`中读取和写入的名称。

在 Python 3.6 之前，描述符无法自动获取这个名称，因此最常见的方法是在初始化对象时显式传递它。这样做没问题，但有一个问题，就是每次我们想要为新属性使用描述符时，都需要重复名称。

如果没有这个方法，典型的`descriptor`将如下所示：

```py
class DescriptorWithName:
    def __init__(self, name):
        self.name = name

    def __get__(self, instance, value):
        if instance is None:
            return self
        logger.info("getting %r attribute from %r", self.name, instance)
        return instance.__dict__[self.name]

    def __set__(self, instance, value):
        instance.__dict__[self.name] = value

class ClientClass:
    descriptor = DescriptorWithName("descriptor")
```

我们可以看到`descriptor`如何使用这个值：

```py
>>> client = ClientClass()
>>> client.descriptor = "value"
>>> client.descriptor
INFO:getting 'descriptor' attribute from <ClientClass object at 0x...>
'value'
```

现在，如果我们想要避免两次写入属性名称（一次是在类内部分配的变量，一次是作为描述符的第一个参数的名称），我们必须求助于一些技巧，比如使用类装饰器，或者（更糟糕的是）使用元类。

在 Python 3.6 中，添加了新的方法`__set_name__`，它接收正在创建该描述符的类和正在赋予该描述符的名称。最常见的习惯用法是使用这种方法来存储所需的名称。

为了兼容性，通常最好在`__init__`方法中保留默认值，但仍然利用`__set_name__`。

有了这个方法，我们可以将前面的描述符重写如下：

```py
class DescriptorWithName:
    def __init__(self, name=None):
        self.name = name

    def __set_name__(self, owner, name):
        self.name = name
    ...
```

# 描述符的类型

根据我们刚刚探讨的方法，我们可以在描述符的工作方式方面进行重要的区分。了解这种区别在有效地使用描述符方面起着重要作用，并且还有助于避免运行时的注意事项或常见错误。

如果描述符实现了`__set__`或`__delete__`方法，则称为**数据描述符**。否则，仅实现`__get__`的描述符是**非数据描述符**。请注意，`__set_name__`对这一分类没有影响。

在尝试解析对象的属性时，数据描述符将始终优先于对象的字典，而非数据描述符则不会。这意味着在非数据描述符中，如果对象的字典中有与描述符相同名称的键，将始终调用该键，并且描述符本身永远不会运行。相反，在数据描述符中，即使字典中有与描述符相同名称的键，也永远不会使用该键，因为描述符本身总是会被调用。

接下来的两个部分将通过示例更详细地解释这一点，以便更深入地了解每种类型的描述符可以期望得到什么。

# 非数据描述符

我们将从仅实现`__get__`方法的`descriptor`开始，看看它是如何使用的：

```py
class NonDataDescriptor:
    def __get__(self, instance, owner):
        if instance is None:
            return self
        return 42

class ClientClass:
    descriptor = NonDataDescriptor()
```

像往常一样，如果我们请求`descriptor`，我们将得到其`__get__`方法的结果：

```py
>>> client = ClientClass()
>>> client.descriptor
42
```

但是，如果我们将`descriptor`属性更改为其他值，我们将失去对该值的访问，并获得分配给它的值：

```py
>>> client.descriptor = 43
>>> client.descriptor
43
```

现在，如果我们删除`descriptor`，然后再次请求它，让我们看看我们得到什么：

```py
>>> del client.descriptor
>>> client.descriptor
42
```

让我们回顾一下刚刚发生的事情。当我们首次创建`client`对象时，`descriptor`属性位于类中，而不是实例中，因此如果我们要求`client`对象的字典，它将是空的：

```py
>>> vars(client)
{}
```

然后，当我们请求`.descriptor`属性时，在`client.__dict__`中找不到任何名为`"descriptor"`的键，因此它转到类中，在那里找到它……但只是作为描述符，因此返回`__get__`方法的结果。

但是，我们将`.descriptor`属性的值更改为其他值，这样做的效果是将其设置到`instance`的字典中，这意味着这次它不会是空的：

```py
>>> client.descriptor = 99
>>> vars(client)
{'descriptor': 99}
```

因此，当我们在这里请求`.descriptor`属性时，它将在对象中查找它（这次会找到，因为`__dict__`属性中有一个名为`descriptor`的键，正如`vars`结果所显示的），并返回它，而无需在类中查找。因此，从未调用描述符协议，下次我们请求此属性时，它将返回我们已经覆盖的值（`99`）。

之后，我们通过调用`del`删除此属性，这样做的效果是从对象的字典中删除键`"descriptor"，使我们回到第一个场景，它将默认到描述符协议将被激活的类中：

```py
>>> del client.descriptor
>>> vars(client)
{}
>>> client.descriptor
42
```

这意味着如果我们将`descriptor`的属性设置为其他值，我们可能会意外地破坏它。为什么？因为`descriptor`不处理删除操作（有些不需要）。

这被称为非数据描述符，因为它没有实现`__set__`魔术方法，正如我们将在下一个示例中看到的那样。

# 数据描述符

现在，让我们看看使用数据描述符的区别。为此，我们将创建另一个实现`__set__`方法的简单`descriptor`：

```py
class DataDescriptor:

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return 42

    def __set__(self, instance, value):
        logger.debug("setting %s.descriptor to %s", instance, value)
        instance.__dict__["descriptor"] = value

class ClientClass:
    descriptor = DataDescriptor()
```

让我们看看`descriptor`的值返回的是什么：

```py
>>> client = ClientClass()
>>> client.descriptor
42
```

现在，让我们尝试将此值更改为其他值，看看它返回的是什么：

```py
>>> client.descriptor = 99
>>> client.descriptor
42
```

`descriptor`返回的值没有改变。但是当我们为其分配不同的值时，它必须设置为对象的字典（就像以前一样）：

```py
>>> vars(client)
{'descriptor': 99}

>>> client.__dict__["descriptor"]
99
```

因此，`__set__()`方法被调用，确实将值设置到了对象的字典中，但是这次，当我们请求此属性时，不再使用字典的`__dict__`属性，而是使用`descriptor`（因为它是覆盖的`descriptor`）。

还有一件事——删除属性将不再起作用：

```py
>>> del client.descriptor
Traceback (most recent call last):
 ...
AttributeError: __delete__
```

原因如下——现在，`descriptor`总是生效，调用`del`删除对象的属性时，不会尝试从对象的字典（`__dict__`）中删除属性，而是尝试调用`descriptor`的`__delete__()`方法（在这个例子中没有实现，因此会出现属性错误）。

这是数据和非数据描述符之间的区别。如果描述符实现了`__set__()`，那么它将始终优先，无论对象的字典中存在什么属性。如果这个方法没有被实现，那么首先会查找字典，然后再运行描述符。

你可能已经注意到`set`方法中的这行代码是一个有趣的观察：

```py
instance.__dict__["descriptor"] = value
```

关于这行代码有很多问题，但让我们分解成几部分。

首先，为什么只改变`"descriptor"`属性的名称？这只是一个简化的例子，但是，当使用描述符时，它在这一点上并不知道它被分配的参数的名称，所以我们只是使用了例子中的一个，知道它将是`"descriptor"`。

在一个真实的例子中，你可以做两件事中的一件——要么接收名称作为参数并在`init`方法中内部存储它，这样这个方法将只使用内部属性，或者更好的是使用`__set_name__`方法。

为什么直接访问实例的`__dict__`属性？另一个很好的问题，至少有两种解释。首先，你可能会想为什么不直接这样做：

```py
setattr(instance, "descriptor", value)
```

记住，当我们尝试给一个`descriptor`属性赋值时，会调用这个方法（`__set__`）。所以，使用`setattr()`会再次调用这个`descriptor`，然后再次调用，依此类推。这将导致无限递归。

不要在`__set__`方法内部直接使用`setattr()`或赋值表达式来操作描述符，因为这将触发无限递归。

那么，为什么描述符不能记录所有对象的属性值？

`client`类已经引用了描述符。如果我们从描述符到`client`对象创建一个引用，我们就会创建循环依赖关系，这些对象将永远不会被垃圾回收。因为它们相互指向，它们的引用计数永远不会降到移除的阈值以下。

这里的一个可能的替代方案是使用弱引用，使用`weakref`模块，并且如果我们想要这样做，创建一个弱引用键字典。这个实现在本章后面有解释，但对于本书中的实现，我们更倾向于使用这种习惯用法，因为在编写描述符时它是相当常见和被接受的。

# 描述符的运作

现在我们已经看到了描述符是什么，它们是如何工作的，以及它们背后的主要思想是什么，我们可以看到它们在实际中的运作。在这一部分，我们将探讨一些可以通过描述符优雅地解决的情况。

在这里，我们将看一些使用描述符的例子，并且我们也将涵盖它们的实现考虑因素（创建它们的不同方式，以及它们的优缺点），最后我们将讨论描述符最适合的场景是什么。

# 描述符的应用

我们将从一个简单的可以工作的例子开始，但这将导致一些代码重复。不太清楚这个问题将如何解决。之后，我们将想出一种将重复逻辑抽象成描述符的方法，这将解决重复问题，我们将注意到我们的客户类上的代码将大大减少。

# 首次尝试不使用描述符

我们现在要解决的问题是，我们有一个普通的类，有一些属性，但我们希望跟踪特定属性随时间变化的所有不同值，例如，以列表的形式。我们脑海中首先想到的解决方案是使用属性，每当在属性的 setter 方法中更改值时，我们将其添加到一个内部列表中，以便保持所需的痕迹。

假设我们的类代表应用程序中的一个旅行者，他有一个当前城市，我们希望在程序运行期间跟踪用户访问过的所有城市。以下代码是一个可能的实现，满足这些要求：

```py
class Traveller:

    def __init__(self, name, current_city):
        self.name = name
        self._current_city = current_city
        self._cities_visited = [current_city]

    @property
    def current_city(self):
        return self._current_city

    @current_city.setter
    def current_city(self, new_city):
        if new_city != self._current_city:
            self._cities_visited.append(new_city)
        self._current_city = new_city

    @property
    def cities_visited(self):
        return self._cities_visited
```

我们可以轻松地检查这段代码是否符合我们的要求：

```py
>>> alice = Traveller("Alice", "Barcelona")
>>> alice.current_city = "Paris"
>>> alice.current_city = "Brussels"
>>> alice.current_city = "Amsterdam"

>>> alice.cities_visited
['Barcelona', 'Paris', 'Brussels', 'Amsterdam']
```

到目前为止，这就是我们需要的一切，不需要实现其他内容。对于这个问题来说，属性已经足够了。如果我们需要在应用程序的多个地方使用完全相同的逻辑会发生什么？这意味着这实际上是一个更通用问题的实例——在另一个属性中跟踪所有值。如果我们想对其他属性执行相同的操作，比如跟踪爱丽丝购买的所有票或她去过的所有国家，会发生什么？我们将不得不在所有这些地方重复逻辑。

此外，如果我们需要在不同的类中具有相同的行为，会发生什么？我们将不得不重复代码或提出一个通用解决方案（也许是装饰器、属性构建器或描述符）。由于属性构建器是描述符的一个特殊（更加复杂）的情况，它超出了本书的范围，因此建议使用描述符作为更清晰的处理方式。

# 惯用的实现

现在，我们将看看如何通过使用一个通用的描述符来解决上一节的问题。再次强调，这个例子实际上并不需要，因为要求并没有指定这种通用行为（我们甚至没有遵循之前创建抽象的相似模式的三个实例的规则），但它展示了描述符的作用目标。

除非有实际证据表明我们要解决的重复问题，且复杂性已经证明是值得的，否则不要实现描述符。

现在，我们将创建一个通用的描述符，给定一个属性名称来保存另一个属性的痕迹，将会把属性的不同值存储在一个列表中。

正如我们之前提到的，代码超出了问题的需求，但其意图只是展示描述符如何帮助我们解决问题。由于描述符的通用性，读者会注意到它的逻辑（方法的名称和属性）与手头的领域问题（旅行者对象）无关。这是因为描述符的理念是能够在任何类型的类中使用它，可能是在不同的项目中，产生相同的结果。

为了解决这个问题，代码的一些部分被注释，并且对每个部分的相应解释（它的作用以及它如何与原始问题相关）在下面的代码中描述。

```py
class HistoryTracedAttribute:
    def __init__(self, trace_attribute_name) -> None:
        self.trace_attribute_name = trace_attribute_name  # [1]
        self._name = None

    def __set_name__(self, owner, name):
        self._name = name

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return instance.__dict__[self._name]

    def __set__(self, instance, value):
        self._track_change_in_value_for_instance(instance, value)
        instance.__dict__[self._name] = value

    def _track_change_in_value_for_instance(self, instance, value):
        self._set_default(instance)   # [2]
        if self._needs_to_track_change(instance, value):
            instance.__dict__[self.trace_attribute_name].append(value)

    def _needs_to_track_change(self, instance, value) -> bool:
        try:
            current_value = instance.__dict__[self._name]
        except KeyError:   # [3]
            return True
        return value != current_value  # [4]

    def _set_default(self, instance):
        instance.__dict__.setdefault(self.trace_attribute_name, [])  # [6]

class Traveller:

    current_city = HistoryTracedAttribute("cities_visited")  # [1]

    def __init__(self, name, current_city):
        self.name = name
        self.current_city = current_city  # [5]
```

对代码的一些注解和评论如下（列表中的数字对应前面清单中的注解编号）：

1.  属性的名称是分配给`descriptor`的变量之一，在这种情况下是`current_city`。我们将变量的名称传递给`descriptor`，它将存储`descriptor`的变量的痕迹。在这个例子中，我们告诉我们的对象跟踪`current_city`在名为`cities_visited`的属性中的所有值。

1.  第一次调用`descriptor`时，在`init`中，用于跟踪值的属性将不存在，这种情况下，我们将其初始化为空列表，以便稍后向其添加值。

1.  在`init`方法中，属性`current_city`的名称也不存在，所以我们也想跟踪这个变化。这相当于在前面的例子中用第一个值初始化列表。

1.  只有在新值与当前设置的值不同时才跟踪更改。

1.  在`init`方法中，`descriptor`已经存在，这个赋值指令会触发第 2 步(创建空列表以开始跟踪其值)和第 3 步(将值附加到此列表，并将其设置为对象中的键以便以后检索)的操作。

1.  字典中的`setdefault`方法用于避免`KeyError`。在这种情况下，对于尚不可用的属性，将返回一个空列表(参见[`docs.python.org/3.6/library/stdtypes.html#dict.setdefault`](https://docs.python.org/3.6/library/stdtypes.html#dict.setdefault)以供参考)。

`descriptor`中的代码确实相当复杂。另一方面，`client`类中的代码要简单得多。当然，只有在我们要多次使用这个`descriptor`时才能实现这种平衡，这是我们已经讨论过的问题。

在这一点上可能不太清楚的是，描述符确实完全独立于`client`类。它没有任何关于业务逻辑的暗示。这使得它完全适用于任何其他类；即使它执行完全不同的操作，描述符也会产生相同的效果。

这才是描述符真正的 Python 特性。它们更适合于定义库、框架或内部 API，而不太适合业务逻辑。

# 实现描述符的不同形式

在考虑实现描述符的方法之前，我们必须首先了解描述符特有的一个常见问题。首先，我们将讨论全局共享状态的问题，然后我们将继续看看在考虑这一点的情况下可以实现描述符的不同方式。

# 全局共享状态的问题

正如我们已经提到的，描述符需要被设置为类属性才能工作。这在大多数情况下不会成为问题，但它确实需要考虑一些警告。

类属性的问题在于它们在该类的所有实例之间共享。描述符也不例外，因此，如果我们试图在`descriptor`对象中保留数据，请记住所有这些对象都将访问相同的值。

让我们看看当我们不正确地定义一个将数据本身保存在`descriptor`中而不是在每个对象中存储时会发生什么：

```py
class SharedDataDescriptor:
    def __init__(self, initial_value):
        self.value = initial_value

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return self.value

    def __set__(self, instance, value):
        self.value = value

class ClientClass:
    descriptor = SharedDataDescriptor("first value")
```

在这个例子中，`descriptor`对象存储数据本身。这带来的不便之处在于，当我们修改一个`instance`的值时，同一类的所有其他实例也会被修改为相同的值。下面的代码清单将这个理论付诸实践：

```py
>>> client1 = ClientClass()
>>> client1.descriptor
'first value'

>>> client2 = ClientClass()
>>> client2.descriptor
'first value'

>>> client2.descriptor = "value for client 2"
>>> client2.descriptor
'value for client 2'

>>> client1.descriptor
'value for client 2'
```

注意我们如何改变一个对象，突然之间所有这些对象都来自同一个类，我们可以看到这个值是如何反映的。这是因为`ClientClass.descriptor`是唯一的；它对于所有这些对象都是相同的对象。

在某些情况下，这可能是我们实际想要的(例如，如果我们要创建一种共享状态的 Borg 模式实现，我们希望在一个类的所有对象之间共享状态)，但一般情况下并非如此，我们需要区分对象。这种模式在《常见设计模式》中有更详细的讨论。

为了实现这一点，描述符需要知道每个`instance`的值并相应地返回它。这就是我们一直在使用每个`instance`的字典(`__dict__`)并从中设置和检索值的原因。

这是最常见的方法。我们已经讨论过为什么不能在这些方法上使用`getattr()`和`setattr()`，因此修改`__dict__`属性是最后的选择，而在这种情况下是可以接受的。

# 访问对象的字典

我们在本书中实现描述符的方式是让`descriptor`对象将值存储在对象的字典`__dict__`中，并从那里检索参数。

始终从实例的`__dict__`属性中存储和返回数据。

# 使用弱引用

另一种选择（如果我们不想使用`__dict__`）是让`descriptor`对象自己跟踪每个实例的值，在内部映射中返回这些值。

不过，有一个警告。这个映射不能是任何字典。由于`client`类有一个对描述符的引用，现在描述符将保持对使用它的对象的引用，这将创建循环依赖关系，结果这些对象永远不会被垃圾回收，因为它们互相指向。

为了解决这个问题，字典必须是一个弱键字典，如`weakref`（WEAKREF 01）模块中定义的那样。

在这种情况下，`descriptor`的代码可能如下所示：

```py
from weakref import WeakKeyDictionary

class DescriptorClass:
    def __init__(self, initial_value):
        self.value = initial_value
        self.mapping = WeakKeyDictionary()

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return self.mapping.get(instance, self.value)

    def __set__(self, instance, value):
        self.mapping[instance] = value
```

这解决了问题，但也带来了一些考虑：

+   对象不再持有它们的属性，而是由描述符代替。这在概念上可能有争议，并且从概念上来看可能并不完全准确。如果我们忘记了这个细节，我们可能会通过检查它的字典来询问对象，试图找到根本不存在的东西（例如调用`vars(client)`将不会返回完整的数据）。

+   它对对象提出了需要是可散列的要求。如果它们不是，它们就不能成为映射的一部分。这对一些应用来说可能是一个要求过于苛刻的要求。

出于这些原因，我们更喜欢本书中到目前为止所展示的使用每个实例的字典的实现。然而，为了完整起见，我们也展示了这种替代方法。

# 关于描述符的更多考虑

在这里，我们将讨论关于描述符的一般考虑，包括在何时使用它们是一个好主意，以及我们最初可能认为通过另一种方法解决的问题如何通过描述符得到改进。然后我们将分析原始实现与使用描述符后的实现之间的利弊。

# 重用代码

描述符是一种通用工具和强大的抽象，我们可以使用它们来避免代码重复。决定何时使用描述符的最佳方法是识别我们将使用属性的情况（无论是用于`get`逻辑、`set`逻辑还是两者），但重复其结构多次。

属性只是描述符的一个特例（`@property`装饰器是实现完整描述符协议的描述符，用于定义它们的`get`、`set`和`delete`操作），这意味着我们可以将描述符用于更复杂的任务。

我们在重用代码方面看到的另一个强大类型是装饰器，如第五章中所解释的那样，*使用装饰器改进我们的代码*。描述符可以帮助我们创建更好的装饰器，确保它们能够正确地为类方法工作。

在装饰器方面，我们可以说始终在它们上实现`__get__()`方法是安全的，并且也将其作为描述符。在尝试决定是否值得创建装饰器时，考虑我们在第五章中提到的三个问题规则，*使用装饰器改进我们的代码*，但请注意，对描述符没有额外的考虑。

至于通用描述符，除了适用于装饰器的前述三个实例规则之外（通常适用于任何可重用组件），还应该记住，当我们想要定义一个内部 API 时，应该使用描述符，这是一些客户端将使用的代码。这更多地是面向设计库和框架的特性，而不是一次性解决方案。

除非有非常好的理由，或者代码看起来明显更好，否则我们应该避免在描述符中放入业务逻辑。相反，描述符的代码将包含更多的实现代码，而不是业务代码。这更类似于定义另一部分业务逻辑将用作工具的新数据结构或对象。

一般来说，描述符将包含实现逻辑，而不是业务逻辑。

# 避免类装饰器

如果我们回想一下我们在第五章中使用的类装饰器，*使用装饰器改进我们的代码*，来确定如何序列化事件对象，我们最终得到了一个实现（对于 Python 3.7+）依赖于两个类装饰器的实现：

```py
@Serialization(
    username=show_original,
    password=hide_field,
    ip=show_original,
    timestamp=format_time,
)
@dataclass
class LoginEvent:
    username: str
    password: str
    ip: str
    timestamp: datetime
```

第一个从注释中获取属性来声明变量，而第二个定义了如何处理每个文件。让我们看看是否可以将这两个装饰器改为描述符。

这个想法是创建一个描述符，它将对每个属性的值应用转换，根据我们的要求返回修改后的版本（例如，隐藏敏感信息，并正确格式化日期）：

```py
from functools import partial
from typing import Callable

class BaseFieldTransformation:

    def __init__(self, transformation: Callable[[], str]) -> None:
        self._name = None
        self.transformation = transformation

    def __get__(self, instance, owner):
        if instance is None:
            return self
        raw_value = instance.__dict__[self._name]
        return self.transformation(raw_value)

    def __set_name__(self, owner, name):
        self._name = name

    def __set__(self, instance, value):
        instance.__dict__[self._name] = value

ShowOriginal = partial(BaseFieldTransformation, transformation=lambda x: x)
HideField = partial(
    BaseFieldTransformation, transformation=lambda x: "**redacted**"
)
FormatTime = partial(
    BaseFieldTransformation,
    transformation=lambda ft: ft.strftime("%Y-%m-%d %H:%M"),
)
```

这个“描述符”很有趣。它是用一个接受一个参数并返回一个值的函数创建的。这个函数将是我们想要应用于字段的转换。从定义了通用工作方式的基本定义开始，其余的“描述符”类被定义，只需更改每个类需要的特定函数即可。

该示例使用`functools.partial`（[`docs.python.org/3.6/library/functools.html#functools.partial`](https://docs.python.org/3.6/library/functools.html#functools.partial)）来模拟子类的方式，通过对该类的转换函数进行部分应用，留下一个可以直接实例化的新可调用函数。

为了保持示例简单，我们将实现`__init__()`和`serialize()`方法，尽管它们也可以被抽象化。在这些考虑下，事件的类现在将被定义如下：

```py
class LoginEvent:
    username = ShowOriginal()
    password = HideField()
    ip = ShowOriginal()
    timestamp = FormatTime()

    def __init__(self, username, password, ip, timestamp):
        self.username = username
        self.password = password
        self.ip = ip
        self.timestamp = timestamp

    def serialize(self):
        return {
            "username": self.username,
            "password": self.password,
            "ip": self.ip,
            "timestamp": self.timestamp,
        }
```

我们可以看到对象在运行时的行为：

```py
>>> le = LoginEvent("john", "secret password", "1.1.1.1", datetime.utcnow())
>>> vars(le)
{'username': 'john', 'password': 'secret password', 'ip': '1.1.1.1', 'timestamp': ...}
>>> le.serialize()
{'username': 'john', 'password': '**redacted**', 'ip': '1.1.1.1', 'timestamp': '...'}
>>> le.password
'**redacted**'
```

与以前使用装饰器的实现相比，这里有一些不同之处。这个例子添加了`serialize()`方法，并在呈现其结果的字典之前隐藏了字段，但是如果我们在内存中的任何时候向事件实例询问这些属性，它仍然会给我们原始值，而不会对其进行任何转换（我们可以选择在设置值时应用转换，并直接在`__get__()`中返回它）。

根据应用程序的敏感性，这可能是可以接受的，也可能是不可以接受的，但在这种情况下，当我们要求对象提供其`public`属性时，描述符将在呈现结果之前应用转换。仍然可以通过访问对象的字典（通过访问`__dict__`）来访问原始值，但是当我们请求值时，默认情况下会返回转换后的值。

在这个例子中，所有描述符都遵循一个共同的逻辑，这个逻辑是在基类中定义的。描述符应该将值存储在对象中，然后请求它，应用它定义的转换。我们可以创建一个类的层次结构，每个类定义自己的转换函数，以使模板方法设计模式起作用。在这种情况下，由于派生类中的更改相对较小（只有一个函数），我们选择将派生类创建为基类的部分应用。创建任何新的转换字段应该像定义一个新的类那样简单，这个类将是基类，部分应用了我们需要的函数。这甚至可以临时完成，因此可能不需要为其设置名称。

不管这种实现方式，重点是，由于描述符是对象，我们可以创建模型，并将面向对象编程的所有规则应用于它们。设计模式也适用于描述符。我们可以定义我们的层次结构，设置自定义行为等等。这个例子遵循了我们在第四章中介绍的 OCP，*SOLID 原则*，因为添加新的转换方法类型只需要创建一个新的类，从基类派生出它所需的函数，而无需修改基类本身（公平地说，以前使用装饰器的实现也符合 OCP，但没有涉及每种转换机制的类）。

让我们举一个例子，我们创建一个基类，实现`__init__()`和`serialize()`方法，这样我们就可以通过继承它来简单地定义`LoginEvent`类，如下所示：

```py
class LoginEvent(BaseEvent):
    username = ShowOriginal()
    password = HideField()
    ip = ShowOriginal()
    timestamp = FormatTime()
```

一旦我们实现了这段代码，类看起来更清晰。它只定义了它需要的属性，通过查看每个属性的类，可以快速分析其逻辑。基类将仅抽象出共同的方法，每个事件的类看起来更简单、更紧凑。

每个事件的类不仅看起来简单，而且描述符本身也非常紧凑，比类装饰器简单得多。原始的类装饰器实现很好，但描述符使其变得更好。

# 描述符的分析

到目前为止，我们已经看到了描述符是如何工作的，并探索了一些有趣的情况，其中它们通过简化逻辑和利用更紧凑的类来促进清晰的设计。

到目前为止，我们知道通过使用描述符，我们可以实现更清晰的代码，抽象掉重复的逻辑和实现细节。但是我们如何知道我们的描述符实现是干净和正确的呢？什么是一个好的描述符？我们是否正确地使用了这个工具，还是过度设计了它？

在本节中，我们将分析描述符以回答这些问题。

# Python 如何在内部使用描述符

关于什么是好的描述符的问题，一个简单的答案是，一个好的描述符几乎就像任何其他良好的 Python 对象一样。它与 Python 本身一致。遵循这个前提的想法是，分析 Python 如何使用描述符将给我们一个很好的实现想法，这样我们就知道从我们编写的描述符中可以期望什么。

我们将看到 Python 本身使用描述符来解决其内部逻辑的最常见情况，并且我们还将发现优雅的描述符，它们一直就在眼前。

# 函数和方法

可能最引人共鸣的描述符对象案例可能是函数。函数实现了`__get__`方法，因此当在类内定义时，它们可以作为方法工作。

方法只是多了一个额外参数的函数。按照惯例，方法的第一个参数命名为"self"，它代表正在定义方法的类的实例。然后，方法对"self"的任何操作都与任何其他接收对象并对其进行修改的函数相同。

换句话说，当我们定义类似这样的东西时：

```py
class MyClass:
    def method(self, ...):
        self.x = 1
```

实际上，这与我们定义以下内容是一样的：

```py
class MyClass: pass

def method(myclass_instance, ...):
    myclass_instance.x = 1

 method(MyClass())
```

因此，它只是另一个函数，修改对象，只是它是在类内部定义的，并且被认为是绑定到对象上。

当我们以这种形式调用某些东西时：

```py
instance = MyClass()
instance.method(...)
```

实际上，Python 正在做类似于这样的事情：

```py
instance = MyClass()
MyClass.method(instance, ...)
```

请注意，这只是 Python 在内部处理的一种语法转换。这种工作方式是通过描述符实现的。

由于函数在调用方法之前实现了描述符协议（请参见以下清单），因此首先调用`__get__()`方法，然后在运行内部可调用对象的代码之前进行一些转换：

```py
>>> def function(): pass
...
>>> function.__get__
<method-wrapper '__get__' of function object at 0x...>
```

在`instance.method(...)`语句中，在处理括号内可调用对象的所有参数之前，会先评估`"instance.method"`部分。

由于`method`是作为类属性定义的对象，并且具有`__get__`方法，因此会被调用。它的作用是将`function`转换为方法，这意味着将可调用对象绑定到它将要使用的对象的实例上。

让我们通过一个例子来看看这个，以便我们可以对 Python 内部可能正在做的事情有一个概念。

我们将在类内部定义一个可调用对象，它将充当我们想要定义的函数或方法，以便在外部调用。`Method`类的一个实例应该是在不同类内部使用的函数或方法。这个函数将只打印它的三个参数——它接收到的`instance`（它将是在定义它的类中的`self`参数），以及另外两个参数。请注意，在`__call__()`方法中，`self`参数不代表`MyClass`的实例，而是`Method`的一个实例。名为`instance`的参数应该是`MyClass`类型的对象：

```py
class Method:
    def __init__(self, name):
        self.name = name

    def __call__(self, instance, arg1, arg2):
        print(f"{self.name}: {instance} called with {arg1} and {arg2}")

class MyClass:
    method = Method("Internal call")
```

在考虑这些因素并创建对象之后，根据前面的定义，以下两个调用应该是等效的：

```py
instance = MyClass()
Method("External call")(instance, "first", "second")
instance.method("first", "second")
```

然而，只有第一个按预期工作，因为第二个会出错：

```py
Traceback (most recent call last):
File "file", line , in <module>
    instance.method("first", "second")
TypeError: __call__() missing 1 required positional argument: 'arg2'
```

我们看到了与第五章中装饰器面临的相同错误，*使用装饰器改进我们的代码*。参数向左移动了一个位置，`instance`取代了`self`，`arg1`将成为`instance`，而`arg2`没有提供任何内容。

为了解决这个问题，我们需要将`Method`作为描述符。

这样，当我们首先调用`instance.method`时，我们将调用它的`__get__()`，然后将这个可调用对象绑定到对象上（绕过对象作为第一个参数），然后继续：

```py
from types import MethodType

class Method:
    def __init__(self, name):
        self.name = name

    def __call__(self, instance, arg1, arg2):
        print(f"{self.name}: {instance} called with {arg1} and {arg2}")

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return MethodType(self, instance)
```

现在，这两个调用都按预期工作：

```py
External call: <MyClass object at 0x...> called with fist and second
Internal call: <MyClass object at 0x...> called with first and second
```

我们所做的是通过使用`types`模块中的`MethodType`将`function`（实际上是我们定义的可调用对象）转换为方法。这个类的第一个参数应该是一个可调用对象（在这种情况下是`self`，因为它实现了`__call__`），第二个参数是要将这个函数绑定到的对象。

类似的东西是 Python 中函数对象使用的，这样它们在类内定义时可以作为方法工作。

由于这是一个非常优雅的解决方案，值得探索一下，以便在定义自己的对象时将其作为 Pythonic 方法。例如，如果我们要定义自己的可调用对象，也将其作为描述符是一个好主意，这样我们也可以在类中将其用作类属性。

# 方法的内置装饰器

正如你可能从官方文档（PYDESCR-02）中了解到的，所有的`@property`、`@classmethod`和`@staticmethod`装饰器都是描述符。

我们已经多次提到，当从类直接调用时，惯用法使描述符返回自身。由于属性实际上是描述符，这就是为什么当我们从类中获取它时，我们得到的不是计算属性的结果，而是整个`property object`：

```py
>>> class MyClass:
... @property
... def prop(self): pass
...
>>> MyClass.prop
<property object at 0x...>
```

对于类方法，在描述符中的`__get__`函数将确保类是传递给被装饰的函数的第一个参数，无论是直接从类调用还是从实例调用。对于静态方法，它将确保除了函数定义的参数之外不绑定任何参数，即撤消`__get__()`在使`self`成为该函数的第一个参数的函数上所做的绑定。

让我们举个例子；我们创建一个`@classproperty`装饰器，它的工作方式与常规的`@property`装饰器相同，但是用于类。有了这样一个装饰器，以下代码应该能够工作：

```py
class TableEvent:
    schema = "public"
    table = "user"

    @classproperty
    def topic(cls):
        prefix = read_prefix_from_config()
        return f"{prefix}{cls.schema}.{cls.table}"

>>> TableEvent.topic
'public.user'

>>> TableEvent().topic
'public.user'
```

# Slots

当一个类定义了`__slots__`属性时，它可以包含类所期望的所有属性，但不能再多了。

试图动态地向定义了`__slots__`的类添加额外的属性将导致`AttributeError`。通过定义这个属性，类变得静态，因此它将没有`__dict__`属性，你无法动态地添加更多的对象。

那么，如果不是从对象的字典中检索它的属性，它的属性是如何检索的呢？通过使用描述符。在 slot 中定义的每个名称都将有自己的描述符，它将存储值以便以后检索：

```py
class Coordinate2D:
    __slots__ = ("lat", "long")

    def __init__(self, lat, long):
        self.lat = lat
        self.long = long

    def __repr__(self):
        return f"{self.__class__.__name__}({self.lat}, {self.long})"
```

虽然这是一个有趣的特性，但必须谨慎使用，因为它会剥夺 Python 的动态特性。一般来说，这应该只用于我们知道是静态的对象，并且如果我们绝对确定在代码的其他部分动态地添加任何属性到它们。

作为其优势，使用 slots 定义的对象使用的内存更少，因为它们只需要一个固定的字段集来保存值，而不是整个字典。

# 在装饰器中实现描述符

我们现在了解了 Python 如何在函数中使用描述符，使它们在类内部定义时作为方法工作。我们还看到了一些例子，其中我们可以通过使用接口的`__get__()`方法使装饰器遵守描述符协议，从而使装饰器适应被调用的对象。这解决了我们的装饰器的问题，就像 Python 解决了对象中函数作为方法的问题一样。

调整装饰器的一般方法是在其中实现`__get__()`方法，并使用`types.MethodType`将可调用对象（装饰器本身）转换为绑定到接收到的对象（`__get__`接收的`instance`参数）的方法。

为了使其工作，我们将不得不将装饰器实现为一个对象，因为如果我们使用一个函数，它已经有一个`__get__()`方法，除非我们对其进行调整，否则它将执行不同的操作，这将无法工作。更干净的方法是为装饰器定义一个类。

在定义一个我们想要应用于类方法的装饰器时，使用装饰器类，并在其中实现`__get__()`方法。

# 总结

描述符是 Python 中更高级的功能，它们推动了边界，更接近元编程。它们最有趣的一个方面是它们清晰地表明 Python 中的类只是普通对象，因此它们具有属性，我们可以与它们交互。描述符在这个意义上是类可以拥有的最有趣的属性类型，因为它的协议提供了更高级的面向对象的可能性。

我们已经看到了描述符的机制，它们的方法，以及所有这些是如何结合在一起的，从而使面向对象的软件设计更加有趣。通过理解描述符，我们能够创建强大的抽象，产生清晰而紧凑的类。我们已经看到了如何修复我们想要应用于函数和方法的装饰器，我们对 Python 内部的工作原理有了更多的了解，以及描述符在语言实现中起着核心和关键的作用。

这个关于描述符在 Python 内部如何使用的研究应该作为一个参考，以便在我们自己的代码中识别描述符的良好用法，从而实现成熟的解决方案。

尽管描述符代表了我们的优势的强大选项，但我们必须记住何时适当地使用它们而不是过度设计。在这方面，我们建议应该将描述符的功能保留给真正通用的情况，比如内部开发 API、库或框架的设计。沿着这些线路的另一个重要考虑因素是，一般来说，我们不应该在描述符中放置业务逻辑，而是放置实现技术功能的逻辑，供其他包含业务逻辑的组件使用。

谈到高级功能，下一章还涵盖了一个有趣且深入的主题：生成器。乍一看，生成器相当简单（大多数读者可能已经熟悉它们），但它们与描述符的共同之处在于，它们也可以是复杂的，产生更高级和优雅的设计，并使 Python 成为一种独特的工作语言。

# 参考资料

以下是一些可以供您参考的信息：

+   Python 关于描述符的官方文档 ([`docs.python.org/3/reference/datamodel.html#implementing-descriptors`](https://docs.python.org/3/reference/datamodel.html#implementing-descriptors))

+   *WEAKREF 01*: Python `weakref` 模块 ([`docs.python.org/3/library/weakref.html`](https://docs.python.org/3/library/weakref.html))

+   *PYDESCR-02*: 内置装饰器作为描述符 ([`docs.python.org/3/howto/descriptor.html#static-methods-and-class-methods`](https://docs.python.org/3/howto/descriptor.html#static-methods-and-class-methods))
