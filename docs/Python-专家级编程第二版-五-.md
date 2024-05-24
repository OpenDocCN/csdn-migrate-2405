# Python 专家级编程第二版（五）

> 原文：[`zh.annas-archive.org/md5/4CC2EF9A4469C814CC3EEBD966D2E707`](https://zh.annas-archive.org/md5/4CC2EF9A4469C814CC3EEBD966D2E707)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：测试驱动开发

**测试驱动开发**（**TDD**）是一种生产高质量软件的简单技术。它在 Python 社区中被广泛使用，但在其他社区中也很受欢迎。

由于 Python 的动态特性，测试尤为重要。它缺乏静态类型，因此许多甚至微小的错误直到代码运行并执行每一行时才会被注意到。但问题不仅仅在于 Python 中类型的工作方式。请记住，大多数错误与不良语法使用无关，而是与逻辑错误和微妙的误解有关，这可能导致重大故障。

本章分为两个部分：

+   *我不测试*，倡导 TDD 并快速描述如何使用标准库进行测试

+   *我进行测试*，这是为那些进行测试并希望从中获得更多的开发人员设计的

# 我不测试

如果您已经被说服使用 TDD，您应该转到下一节。它将专注于高级技术和工具，以使您在处理测试时的生活更轻松。这部分主要是为那些不使用这种方法并试图倡导其使用的人而设计的。

## 测试驱动开发原则

测试驱动开发过程，最简单的形式包括三个步骤：

1.  为尚未实现的新功能或改进编写自动化测试。

1.  提供最小的代码，只需通过所有定义的测试即可。

1.  重构代码以满足期望的质量标准。

关于这个开发周期最重要的事实是，在实现之前应该先编写测试。这对于经验不足的开发人员来说并不容易，但这是唯一保证您要编写的代码是可测试的方法。

例如，一个被要求编写一个检查给定数字是否为质数的函数的开发人员，会写一些关于如何使用它以及预期结果的示例：

```py
assert is_prime(5)
assert is_prime(7)
assert not is_prime(8)
```

实现功能的开发人员不需要是唯一负责提供测试的人。示例也可以由其他人提供。例如，网络协议或密码算法的官方规范经常提供旨在验证实现正确性的测试向量。这些是测试用例的完美基础。

从那里，函数可以被实现，直到前面的示例起作用：

```py
def is_prime(number):
    for element in range(2, number):
        if number % element == 0:
            return False
    return True
```

错误或意外结果是函数应该能够处理的新用法示例：

```py
>>> assert not is_prime(1)
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
AssertionError

```

代码可以相应地更改，直到新的测试通过：

```py
def is_prime(number):
    if number in (0, 1):
        return False

    for element in range(2, number):
        if number % element == 0:
            return False

    return True
```

还有更多情况表明实现仍然不完整：

```py
>>> assert not is_prime(-3)** 
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
AssertionError

```

更新后的代码如下：

```py
def is_prime(number):
    if number < 0 or number in (0, 1):
        return False

    for element in range(2, number):
        if number % element == 0:
            return False

    return True
```

从那里，所有测试可以被收集在一个测试函数中，每当代码发展时运行：

```py
def test_is_prime():
    assert is_prime(5)
    assert is_prime(7)

    assert not is_prime(8)
    assert not is_prime(0)
    assert not is_prime(1)

    assert not is_prime(-1)
    assert not is_prime(-3)
    assert not is_prime(-6)
```

每当我们提出一个新的需求时，“test_is_prime（）”函数应该首先更新以定义“is_prime（）”函数的预期行为。然后，运行测试以检查实现是否提供了期望的结果。只有当已知测试失败时，才需要更新经过测试的函数的代码。

测试驱动开发提供了许多好处：

+   它有助于防止软件回归

+   它提高了软件质量

+   它提供了代码行为的一种低级文档

+   它允许您在短时间内更快地生成健壮的代码

处理测试的最佳约定是将它们全部收集在一个单独的模块或包中（通常命名为`tests`），并且有一种简单的方法可以使用单个 shell 命令运行整个测试套件。幸运的是，没有必要自己构建整个测试工具链。Python 标准库和 Python 软件包索引都提供了大量的测试框架和实用工具，可以让您以方便的方式构建、发现和运行测试。我们将在本章后面讨论这些包和模块中最值得注意的例子。

### 防止软件回归

我们在开发人员生活中都会面临软件回归问题。软件回归是由更改引入的新错误。它表现为在软件先前版本中已知的功能或功能在项目开发过程中的某个时刻出现故障并停止工作。

回归的主要原因是软件的复杂性。在某个时刻，不可能猜测代码库中的单个更改可能导致什么结果。更改某些代码可能会破坏其他功能，有时会导致恶意副作用，比如悄悄地损坏数据。高复杂性不仅是庞大代码库的问题。当然，代码量和复杂性之间存在明显的相关性，但即使是小型项目（几百/几千行代码）的架构也可能如此复杂，以至于很难预测相对较小的更改的所有后果。

为了避免回归，软件提供的整套功能应该在每次更改发生时进行测试。如果没有这样做，你将无法可靠地区分软件中一直存在的错误和最近在正确工作的部分引入的新错误。

向多个开发人员开放代码库会加剧这个问题，因为每个人都不会完全了解所有的开发活动。虽然版本控制系统可以防止冲突，但它并不能阻止所有不必要的交互。

TDD 有助于减少软件回归。每次更改后，整个软件都可以自动测试。只要每个功能都有适当的测试集，这种方法就有效。当 TDD 正确执行时，测试基础会随着代码基础一起增长。

由于完整的测试活动可能需要相当长的时间，将其委托给一些可以在后台执行工作的持续集成系统是一个好的做法。我们在第八章“管理代码”中已经讨论过这样的解决方案。然而，开发人员也应该手动执行测试的本地重新启动，至少对于相关模块来说是如此。仅依赖持续集成会对开发人员的生产力产生负面影响。程序员应该能够在其环境中轻松地运行测试的选择。这就是为什么你应该仔细选择项目的测试工具。

### 提高代码质量

当编写新的模块、类或函数时，开发人员会专注于如何编写以及如何产生最佳的代码。但是，当他们专注于算法时，他们可能会失去用户的视角：他们的函数将如何被使用？参数是否易于使用和合乎逻辑？API 的名称是否正确？

这是通过应用前几章描述的技巧来完成的，比如第四章，“选择好的名称”。但要高效地做到这一点，唯一的方法就是写使用示例。这是开发人员意识到他或她编写的代码是否合乎逻辑且易于使用的时刻。通常，在模块、类或函数完成后，第一次重构就会发生。

编写测试，这些测试是代码的用例，有助于从用户的角度进行思考。因此，当开发人员使用 TDD 时，通常会产生更好的代码。测试庞大的函数和庞大的单块类是困难的。考虑测试的代码往往更清晰、更模块化。

### 提供最佳的开发人员文档

测试是开发人员了解软件运行方式的最佳途径。它们是代码最初创建的用例。阅读它们可以快速深入地了解代码的运行方式。有时，一个例子胜过千言万语。

这些测试始终与代码库保持最新，使它们成为软件可以拥有的最佳开发人员文档。测试不会像文档一样过时，否则它们会失败。

### 更快地生成健壮的代码

没有测试的编写会导致长时间的调试会话。一个模块中的错误可能会在软件的完全不同部分表现出来。由于您不知道该责怪谁，您会花费大量时间进行调试。当测试失败时，最好一次只解决一个小错误，因为这样您会更好地了解真正的问题所在。测试通常比调试更有趣，因为它是编码。

如果您测量修复代码所花费的时间以及编写代码所花费的时间，通常会比 TDD 方法所需的时间长。当您开始编写新的代码时，这并不明显。这是因为设置测试环境并编写前几个测试所花费的时间与仅编写代码的时间相比极长。

但是，有些测试环境确实很难设置。例如，当您的代码与 LDAP 或 SQL 服务器交互时，编写测试根本不明显。这在本章的*伪造和模拟*部分中有所涵盖。

## 什么样的测试？

任何软件都可以进行几种测试。主要的是**验收测试**（或**功能测试**）和**单元测试**，这是大多数人在讨论软件测试主题时所考虑的。但是在您的项目中，还有一些其他测试类型可以使用。我们将在本节中简要讨论其中一些。

### 验收测试

验收测试侧重于功能，并处理软件就像黑匣子一样。它只是确保软件确实做了它应该做的事情，使用与用户相同的媒体并控制输出。这些测试通常是在开发周期之外编写的，以验证应用程序是否满足要求。它们通常作为软件的检查表运行。通常，这些测试不是通过 TDD 进行的，而是由经理、QA 人员甚至客户构建的。在这种情况下，它们通常被称为**用户验收测试**。

但是，它们可以并且应该遵循 TDD 原则。在编写功能之前可以提供测试。开发人员通常会得到一堆验收测试，通常是由功能规格书制作的，他们的工作是确保代码能够通过所有这些测试。

编写这些测试所使用的工具取决于软件提供的用户界面。一些 Python 开发人员使用的流行工具包括：

| 应用程序类型 | 工具 |
| --- | --- |
| Web 应用程序 | Selenium（用于带有 JavaScript 的 Web UI） |
| Web 应用程序 | `zope.testbrowser`（不测试 JS） |
| WSGI 应用程序 | `paste.test.fixture`（不测试 JS） |
| Gnome 桌面应用程序 | dogtail |
| Win32 桌面应用程序 | pywinauto |

### 注意

对于功能测试工具的广泛列表，Grig Gheorghiu 在[`wiki.python.org/moin/PythonTestingToolsTaxonomy`](https://wiki.python.org/moin/PythonTestingToolsTaxonomy)上维护了一个 wiki 页面。

### 单元测试

单元测试是完全适合测试驱动开发的低级测试。顾名思义，它们专注于测试软件单元。软件单元可以理解为应用程序代码的最小可测试部分。根据应用程序的不同，大小可能从整个模块到单个方法或函数不等，但通常单元测试是针对可能的最小代码片段编写的。单元测试通常会将被测试的单元（模块、类、函数等）与应用程序的其余部分和其他单元隔离开来。当需要外部依赖项时，例如 Web API 或数据库，它们通常会被伪造对象或模拟替换。

### 功能测试

功能测试侧重于整个功能和功能，而不是小的代码单元。它们在目的上类似于验收测试。主要区别在于功能测试不一定需要使用用户相同的界面。例如，在测试 Web 应用程序时，一些用户交互（或其后果）可以通过合成的 HTTP 请求或直接数据库访问来模拟，而不是模拟真实页面加载和鼠标点击。

这种方法通常比使用*用户验收测试*中使用的工具进行测试更容易和更快。有限功能测试的缺点是它们往往不能涵盖应用程序的足够多的部分，其中不同的抽象层和组件相遇。侧重于这种*相遇点*的测试通常被称为集成测试。

### 集成测试

集成测试代表了比单元测试更高级的测试水平。它们测试代码的更大部分，并侧重于许多应用层或组件相遇和相互交互的情况。集成测试的形式和范围取决于项目的架构和复杂性。例如，在小型和单片项目中，这可能只是运行更复杂的功能测试，并允许它们与真实的后端服务（数据库、缓存等）进行交互，而不是模拟或伪造它们。对于复杂的场景或由多个服务构建的产品，真正的集成测试可能非常广泛，甚至需要在模拟生产环境的大型分布式环境中运行整个项目。

集成测试通常与功能测试非常相似，它们之间的边界非常模糊。很常见的是，集成测试也在逻辑上测试独立的功能和特性。

### 负载和性能测试

负载测试和性能测试提供的是关于代码效率而不是正确性的客观信息。负载测试和性能测试这两个术语有时可以互换使用，但实际上前者指的是性能的有限方面。负载测试侧重于衡量代码在某种人为需求（负载）下的行为。这是测试 Web 应用程序的一种非常流行的方式，其中负载被理解为来自真实用户或程序化客户端的 Web 流量。重要的是要注意，负载测试往往涵盖了对应用程序的整个请求，因此与集成和功能测试非常相似。这使得确保被测试的应用程序组件完全验证工作正常非常重要。性能测试通常是旨在衡量代码性能的所有测试，甚至可以针对代码的小单元。因此，负载测试只是性能测试的一个特定子类型。

它们是一种特殊类型的测试，因为它们不提供二进制结果（失败/成功），而只提供一些性能质量的测量。这意味着单个结果需要被解释和/或与不同测试运行的结果进行比较。在某些情况下，项目要求可能对代码设置一些严格的时间或资源约束，但这并不改变这些测试方法中总是涉及某种任意解释的事实。

负载性能测试是任何需要满足一些**服务****级别协议**的软件开发过程中的一个重要工具，因为它有助于降低关键代码路径性能受损的风险。无论如何，不应该过度使用。

### 代码质量测试

代码质量没有一个确定的任意刻度，可以明确地说它是好还是坏。不幸的是，代码质量这个抽象概念无法用数字形式来衡量和表达。但相反，我们可以测量与代码质量高度相关的软件的各种指标。举几个例子：

+   代码风格违规的数量

+   文档的数量

+   复杂度度量，如 McCabe 的圈复杂度

+   静态代码分析警告的数量

许多项目在其持续集成工作流程中使用代码质量测试。一个良好且流行的方法是至少测试基本指标（静态代码分析和代码风格违规），并且不允许将任何代码合并到主流中使这些指标降低。

## Python 标准测试工具

Python 提供了标准库中的两个主要模块来编写测试：

+   `unittest` ([`docs.python.org/3/library/unittest.html`](https://docs.python.org/3/library/unittest.html))：这是基于 Java 的 JUnit 的标准和最常见的 Python 单元测试框架，最初由 Steve Purcell（以前是`PyUnit`）编写

+   `doctest` ([`docs.python.org/3/library/doctest.html`](https://docs.python.org/3/library/doctest.html))：这是一个具有交互式使用示例的文学编程测试工具

### unittest

`unittest`基本上提供了 Java 的 JUnit 所提供的功能。它提供了一个名为`TestCase`的基类，该类具有一系列广泛的方法来验证函数调用和语句的输出。

这个模块是为了编写单元测试而创建的，但只要测试使用了用户界面，也可以用它来编写验收测试。例如，一些测试框架提供了辅助工具来驱动诸如 Selenium 之类的工具，这些工具是建立在`unittest`之上的。

使用`unittest`为模块编写简单的单元测试是通过子类化`TestCase`并编写以`test`前缀开头的方法来完成的。*测试驱动开发原则*部分的最终示例将如下所示：

```py
import unittest

from primes import is_prime

class MyTests(unittest.TestCase):
    def test_is_prime(self):
        self.assertTrue(is_prime(5))
        self.assertTrue(is_prime(7))

        self.assertFalse(is_prime(8))
        self.assertFalse(is_prime(0))
        self.assertFalse(is_prime(1))

        self.assertFalse(is_prime(-1))
        self.assertFalse(is_prime(-3))
        self.assertFalse(is_prime(-6))

if __name__ == "__main__":
    unittest.main()
```

`unittest.main()`函数是一个实用程序，允许将整个模块作为测试套件来执行：

```py
$ python test_is_prime.py -v
test_is_prime (__main__.MyTests) ... ok

----------------------------------------------------------------------
Ran 1 test in 0.000s

OK

```

`unittest.main()`函数扫描当前模块的上下文，并寻找子类为`TestCase`的类。它实例化它们，然后运行所有以`test`前缀开头的方法。

一个良好的测试套件遵循常见和一致的命名约定。例如，如果`is_prime`函数包含在`primes.py`模块中，测试类可以被称为`PrimesTests`，并放入`test_primes.py`文件中：

```py
import unittest

from primes import is_prime

class PrimesTests(unittest.TestCase):
    def test_is_prime(self):
        self.assertTrue(is_prime(5))
        self.assertTrue(is_prime(7))

        self.assertFalse(is_prime(8))
        self.assertFalse(is_prime(0))
        self.assertFalse(is_prime(1))

        self.assertFalse(is_prime(-1))
        self.assertFalse(is_prime(-3))
        self.assertFalse(is_prime(-6))

if __name__ == '__main__':
    unittest.main()
```

从那时起，每当`utils`模块发展时，`test_utils`模块就会得到更多的测试。

为了工作，`test_primes`模块需要在上下文中有`primes`模块可用。这可以通过将两个模块放在同一个包中，或者通过将被测试的模块显式添加到 Python 路径中来实现。在实践中，`setuptools`的`develop`命令在这里非常有帮助。

在整个应用程序上运行测试假设您有一个脚本，可以从所有测试模块构建一个**测试运行**。`unittest`提供了一个`TestSuite`类，可以聚合测试并将它们作为一个测试运行来运行，只要它们都是`TestCase`或`TestSuite`的实例。

在 Python 的过去，有一个约定，测试模块提供一个返回`TestSuite`实例的`test_suite`函数，该实例在模块被命令提示符调用时在`__main__`部分中使用，或者由测试运行器使用：

```py
import unittest

from primes import is_prime

class PrimesTests(unittest.TestCase):
    def test_is_prime(self):
        self.assertTrue(is_prime(5))

        self.assertTrue(is_prime(7))

        self.assertFalse(is_prime(8))
        self.assertFalse(is_prime(0))
        self.assertFalse(is_prime(1))

        self.assertFalse(is_prime(-1))
        self.assertFalse(is_prime(-3))
        self.assertFalse(is_prime(-6))

class OtherTests(unittest.TestCase):
    def test_true(self):
        self.assertTrue(True)

def test_suite():
    """builds the test suite."""
    suite = unittest.TestSuite()
    suite.addTests(unittest.makeSuite(PrimesTests))
    suite.addTests(unittest.makeSuite(OtherTests))

    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
```

从 shell 中运行这个模块将打印测试运行结果：

```py
$ python test_primes.py -v
test_is_prime (__main__.PrimesTests) ... ok
test_true (__main__.OtherTests) ... ok

----------------------------------------------------------------------
Ran 2 tests in 0.001s

OK

```

在旧版本的 Python 中，当`unittest`模块没有适当的测试发现工具时，需要使用前面的方法。通常，所有测试的运行是由一个全局脚本完成的，该脚本浏览代码树寻找测试并运行它们。这称为**测试发现**，稍后在本章中将更详细地介绍。现在，您只需要知道`unittest`提供了一个简单的命令，可以从带有`test`前缀的模块和包中发现所有测试：

```py
$ python -m unittest -v
test_is_prime (test_primes.PrimesTests) ... ok
test_true (test_primes.OtherTests) ... ok

----------------------------------------------------------------------
Ran 2 tests in 0.001s

OK

```

如果您使用了前面的命令，那么就不需要手动定义`__main__`部分并调用`unittest.main()`函数。

### doctest

`doctest`是一个模块，它从文档字符串或文本文件中提取交互式提示会话的片段，并重放它们以检查示例输出是否与真实输出相同。

例如，以下内容的文本文件可以作为测试运行：

```py
Check addition of integers works as expected::

>>> 1 + 1
2
```

假设这个文档文件存储在文件系统中，文件名为`test.rst`。`doctest`模块提供了一些函数，用于从这样的文档中提取并运行测试：

```py
>>> import doctest
>>> doctest.testfile('test.rst', verbose=True)
Trying:
 **1 + 1
Expecting:
 **2
ok
1 items passed all tests:
 **1 tests in test.rst
1 tests in 1 items.
1 passed and 0 failed.
Test passed.
TestResults(failed=0, attempted=1)

```

使用`doctest`有很多优点：

+   包可以通过示例进行文档和测试

+   文档示例始终是最新的

+   使用 doctests 中的示例来编写一个包有助于保持用户的观点

然而，doctests 并不会使单元测试过时；它们只应该用于在文档中提供可读的示例。换句话说，当测试涉及低级问题或需要复杂的测试装置，这些测试装置会使文档变得晦涩时，就不应该使用它们。

一些 Python 框架，如 Zope，广泛使用 doctests，并且有时会受到对代码不熟悉的人的批评。有些 doctests 真的很难阅读和理解，因为这些示例违反了技术写作的规则之一——它们不能在简单的提示符下运行，并且需要广泛的知识。因此，那些本应帮助新手的文档变得很难阅读，因为基于复杂测试装置或特定测试 API 构建的 doctests 的代码示例很难阅读。

### 注意

如第九章中所解释的，*项目文档*，当你使用 doctests 作为你的包文档的一部分时，要小心遵循技术写作的七条规则。

在这个阶段，你应该对 TDD 带来的好处有一个很好的概述。如果你还不确定，你应该在几个模块上试一试。使用 TDD 编写一个包，并测量构建、调试和重构所花费的时间。你会很快发现它确实是优越的。

# 我进行测试

如果你来自*我不测试*部分，并且现在已经确信要进行测试驱动开发，那么恭喜你！你已经了解了测试驱动开发的基础知识，但在能够有效地使用这种方法之前，你还有一些东西需要学习。

本节描述了开发人员在编写测试时遇到的一些问题，以及解决这些问题的一些方法。它还提供了 Python 社区中流行的测试运行器和工具的快速回顾。

## 单元测试的缺陷

`unittest`模块是在 Python 2.1 中引入的，并且自那时以来一直被开发人员广泛使用。但是一些替代的测试框架由社区中一些对`unittest`的弱点和限制感到沮丧的人创建。

以下是经常提出的常见批评：

+   **框架使用起来很繁重**，因为:

+   你必须在`TestCase`的子类中编写所有测试

+   你必须在方法名前加上`test`前缀

+   鼓励使用`TestCase`提供的断言方法，而不是简单的`assert`语句，现有的方法可能无法覆盖每种情况

+   这个框架很难扩展，因为它需要大量地对基类进行子类化或者使用装饰器等技巧。

+   有时测试装置很难组织，因为`setUp`和`tearDown`设施与`TestCase`级别相关联，尽管它们每次测试运行时只运行一次。换句话说，如果一个测试装置涉及许多测试模块，那么组织它的创建和清理就不简单。

+   在 Python 软件上运行测试活动并不容易。默认的测试运行器（`python -m unittest`）确实提供了一些测试发现，但并没有提供足够的过滤能力。实际上，需要编写额外的脚本来收集测试，汇总它们，然后以方便的方式运行它们。

需要一种更轻量的方法来编写测试，而不会受到太像其大型 Java 兄弟 JUnit 的框架的限制。由于 Python 不要求使用 100%基于类的环境，因此最好提供一个更符合 Python 风格的测试框架，而不是基于子类化。

一个常见的方法是：

+   提供一种简单的方法来标记任何函数或任何类作为测试

+   通过插件系统扩展框架

+   为所有测试级别提供完整的测试装置环境：整个活动、模块级别的一组测试和测试级别

+   基于测试发现提供测试运行器，具有广泛的选项集

## unittest 替代方案

一些第三方工具尝试通过提供`unittest`扩展的形式来解决刚才提到的问题。

Python 维基提供了各种测试实用工具和框架的非常长的列表（参见[`wiki.python.org/moin/PythonTestingToolsTaxonomy`](https://wiki.python.org/moin/PythonTestingToolsTaxonomy)），但只有两个项目特别受欢迎：

+   `nose`：[`nose.readthedocs.org`](http://nose.readthedocs.org)

+   `py.test`：[`pytest.org`](http://pytest.org)

### nose

`nose`主要是一个具有强大发现功能的测试运行器。它具有广泛的选项，允许在 Python 应用程序中运行各种测试活动。

它不是标准库的一部分，但可以在 PyPI 上找到，并可以使用 pip 轻松安装：

```py
pip install nose

```

#### 测试运行器

安装 nose 后，一个名为`nosetests`的新命令可以在提示符下使用。可以直接使用它来运行本章第一节中介绍的测试：

```py
nosetests -v
test_true (test_primes.OtherTests) ... ok
test_is_prime (test_primes.PrimesTests) ... ok
builds the test suite. ... ok

----------------------------------------------------------------------
Ran 3 tests in 0.009s

OK

```

`nose`通过递归浏览当前目录并自行构建测试套件来发现测试。乍一看，前面的例子看起来并不像简单的`python -m unittest`有什么改进。如果你使用`--help`开关运行此命令，你会注意到 nose 提供了数十个参数，允许你控制测试的发现和执行。

#### 编写测试

`nose`更进一步，通过运行所有类和函数，其名称与正则表达式`((?:^|[b_.-])[Tt]est)`匹配的模块中的测试。大致上，所有以`test`开头并位于匹配该模式的模块中的可调用项也将作为测试执行。

例如，这个`test_ok.py`模块将被`nose`识别并运行：

```py
$ more test_ok.py
def test_ok():
 **print('my test')
$ nosetests -v
test_ok.test_ok ... ok

-----------------------------------------------------------------
Ran 1 test in 0.071s

OK

```

还会执行常规的`TestCase`类和`doctests`。

最后，`nose`提供了类似于`TestCase`方法的断言函数。但这些是作为遵循 PEP 8 命名约定的函数提供的，而不是使用`unittest`使用的 Java 约定（参见[`nose.readthedocs.org/`](http://nose.readthedocs.org/)）。

#### 编写测试装置

`nose`支持三个级别的装置：

+   **包级别**：`__init__.py`模块中可以添加`setup`和`teardown`函数，其中包含所有测试模块的测试包

+   **模块级别**：测试模块可以有自己的`setup`和`teardown`函数

+   **测试级别**：可调用项也可以使用提供的`with_setup`装饰器具有装置函数

例如，要在模块和测试级别设置测试装置，请使用以下代码：

```py
def setup():
    # setup code, launched for the whole module
    ...

def teardown():
    # teardown code, launched for the whole module
    ... 

def set_ok():
    # setup code launched only for test_ok
    ...

@with_setup(set_ok)
def test_ok():
    print('my test')
```

#### 与 setuptools 的集成和插件系统

最后，`nose`与`setuptools`完美集成，因此可以使用`test`命令（`python setup.py test`）。这种集成是通过在`setup.py`脚本中添加`test_suite`元数据来完成的：

```py
setup(
    #...
    test_suite='nose.collector',
)
```

`nose`还使用`setuptool's`入口机制，供开发人员编写`nose`插件。这允许你从测试发现到输出格式化覆盖或修改工具的每个方面。

### 注意

在[`nose-plugins.jottit.com`](https://nose-plugins.jottit.com)上维护了一个`nose`插件列表。

#### 总结

`nose`是一个完整的测试工具，修复了`unittest`存在的许多问题。它仍然设计为使用测试的隐式前缀名称，这对一些开发人员来说仍然是一个约束。虽然这个前缀可以定制，但仍然需要遵循一定的约定。

这种约定优于配置的说法并不坏，比在`unittest`中需要的样板代码要好得多。但是，例如使用显式装饰器可能是摆脱`test`前缀的好方法。

此外，通过插件扩展`nose`的能力使其非常灵活，并允许开发人员定制工具以满足其需求。

如果您的测试工作流程需要覆盖很多 nose 参数，您可以在主目录或项目根目录中轻松添加`.noserc`或`nose.cfg`文件。它将指定`nosetests`命令的默认选项集。例如，一个很好的做法是在测试运行期间自动查找 doctests。启用运行 doctests 的`nose`配置文件示例如下：

```py
[nosetests]
with-doctest=1
doctest-extension=.txt

```

### py.test

`py.test`与`nose`非常相似。事实上，后者是受`py.test`启发的，因此我们将主要关注使这些工具彼此不同的细节。该工具诞生于一个名为`py`的更大软件包的一部分，但现在它们是分开开发的。

像本书中提到的每个第三方软件包一样，`py.test`可以在 PyPI 上获得，并且可以通过`pip`安装为`pytest`：

```py
$ pip install pytest

```

从那里，一个新的`py.test`命令在提示符下可用，可以像`nosetests`一样使用。该工具使用类似的模式匹配和测试发现算法来捕获要运行的测试。该模式比`nose`使用的模式更严格，只会捕获：

+   以`Test`开头的类，在以`test`开头的文件中

+   以`test`开头的函数，在以`test`开头的文件中

### 注意

要小心使用正确的字符大小写。如果一个函数以大写的“T”开头，它将被视为一个类，因此会被忽略。如果一个类以小写的“t”开头，`py.test`将会中断，因为它会尝试将其视为一个函数。

`py.test`的优点包括：

+   轻松禁用一些测试类的能力

+   处理 fixtures 的灵活和独特机制

+   将测试分发到多台计算机的能力

#### 编写测试 fixtures

`py.test`支持两种处理 fixtures 的机制。第一种是模仿 xUnit 框架的，类似于`nose`。当然，语义有些不同。`py.test`将在每个测试模块中查找三个级别的 fixtures，如下例所示：

```py
def setup_module(module): 
    """ Setup up any state specific to the execution 
        of the given module.
    """

def teardown_module(module):    
    """ Teardown any state that was previously setup
        with a setup_module method.
    """

def setup_class(cls):    
    """ Setup up any state specific to the execution
        of the given class (which usually contains tests).
    """

def teardown_class(cls):    
    """ Teardown any state that was previously setup
        with a call to setup_class.
    """

def setup_method(self, method):
    """ Setup up any state tied to the execution of the given
        method in a class. setup_method is invoked for every
        test method of a class.
    """

def teardown_method(self, method):
    """ Teardown any state that was previously setup
        with a setup_method call.
    """
```

每个函数将以当前模块、类或方法作为参数。因此，测试 fixture 将能够在上下文中工作，而无需查找它，就像`nose`一样。

`py.test`编写 fixtures 的另一种机制是建立在依赖注入的概念上，允许以更模块化和可扩展的方式维护测试状态。非 xUnit 风格的 fixtures（setup/teardown 过程）总是具有唯一的名称，并且需要通过在类中的测试函数、方法和模块中声明它们的使用来显式激活它们。

fixtures 的最简单实现采用了使用`pytest.fixture()`装饰器声明的命名函数的形式。要将 fixture 标记为在测试中使用，需要将其声明为函数或方法参数。为了更清楚，考虑使用`py.test` fixtures 重写`is_prime`函数的测试模块的先前示例：

```py
import pytest

from primes import is_prime

@pytest.fixture()
def prime_numbers():
    return [3, 5, 7]

@pytest.fixture()
def non_prime_numbers():
    return [8, 0, 1]

@pytest.fixture()
def negative_numbers():
    return [-1, -3, -6]

def test_is_prime_true(prime_numbers):
    for number in prime_numbers:
        assert is_prime(number)

def test_is_prime_false(non_prime_numbers, negative_numbers):
    for number in non_prime_numbers:
        assert not is_prime(number)

    for number in non_prime_numbers:
        assert not is_prime(number)
```

#### 禁用测试函数和类

`py.test` 提供了一个简单的机制，可以在特定条件下禁用一些测试。这称为跳过，`pytest` 包提供了 `.skipif` 装饰器来实现这一目的。如果需要在特定条件下跳过单个测试函数或整个测试类装饰器，就需要使用这个装饰器，并提供一些值来验证是否满足了预期条件。以下是官方文档中跳过在 Windows 上运行整个测试用例类的示例：

```py
import pytest

@pytest.mark.skipif(
    sys.platform == 'win32',
    reason="does not run on windows"
)
class TestPosixCalls:

    def test_function(self):
        """will not be setup or run under 'win32' platform"""
```

当然，您可以预先定义跳过条件，以便在测试模块之间共享：

```py
import pytest

skipwindows = pytest.mark.skipif(
    sys.platform == 'win32',
    reason="does not run on windows"
)

@skip_windows
class TestPosixCalls:

    def test_function(self):
        """will not be setup or run under 'win32' platform"""
```

如果一个测试以这种方式标记，它将根本不会被执行。然而，在某些情况下，您希望运行这样的测试，并希望执行它，但是您知道，在已知条件下它应该失败。为此，提供了一个不同的装饰器。它是 `@mark.xfail`，确保测试始终运行，但如果预定义条件发生，它应该在某个时候失败：

```py
import pytest

@pytest.mark.xfail(
sys.platform == 'win32',
    reason="does not run on windows"
)
class TestPosixCalls:

    def test_function(self):
        """it must fail under windows"""
```

使用 `xfail` 比 `skipif` 更严格。测试始终会被执行，如果在预期情况下没有失败，那么整个 `py.test` 运行将会失败。

#### 自动化分布式测试

`py.test` 的一个有趣特性是它能够将测试分布到多台计算机上。只要计算机可以通过 SSH 访问，`py.test` 就能够通过发送要执行的测试来驱动每台计算机。

然而，这一特性依赖于网络；如果连接中断，从属端将无法继续工作，因为它完全由主控端驱动。

当一个项目有长时间的测试活动时，Buildbot 或其他持续集成工具更可取。但是，当您在开发一个运行测试需要大量资源的应用程序时，`py.test` 分布模型可以用于临时分发测试。

#### 总结

`py.test` 与 `nose` 非常相似，因为它不需要聚合测试的样板代码。它还有一个很好的插件系统，并且在 PyPI 上有大量的扩展可用。

最后，`py.test` 专注于使测试运行速度快，与这一领域的其他工具相比确实更加优越。另一个显著特性是对夹具的原始处理方式，这确实有助于管理可重用的夹具库。有些人可能会认为其中涉及了太多魔法，但它确实简化了测试套件的开发。`py.test` 的这一单一优势使其成为我的首选工具，因此我真的推荐它。

## 测试覆盖

**代码覆盖** 是一个非常有用的度量标准，它提供了关于项目代码测试情况的客观信息。它只是衡量了在所有测试执行期间执行了多少行代码以及哪些行代码。通常以百分比表示，100% 的覆盖率意味着在测试期间执行了每一行代码。

最流行的代码覆盖工具简称为 coverage，并且可以在 PyPI 上免费获得。使用非常简单，只有两个步骤。第一步是在您的 shell 中运行 coverage run 命令，并将运行所有测试的脚本/程序的路径作为参数：

```py
$ coverage run --source . `which py.test` -v
===================== test session starts ======================
platformdarwin -- Python 3.5.1, pytest-2.8.7, py-1.4.31, pluggy-0.3.1 -- /Users/swistakm/.envs/book/bin/python3
cachedir: .cache
rootdir: /Users/swistakm/dev/book/chapter10/pytest, inifile:** 
plugins: capturelog-0.7, codecheckers-0.2, cov-2.2.1, timeout-1.0.0
collected 6 items** 

primes.py::pyflakes PASSED
primes.py::pep8 PASSED
test_primes.py::pyflakes PASSED
test_primes.py::pep8 PASSED
test_primes.py::test_is_prime_true PASSED
test_primes.py::test_is_prime_false PASSED

========= 6 passed, 1 pytest-warnings in 0.10 seconds ==========

```

coverage run 还接受 `-m` 参数，该参数指定可运行的模块名称，而不是程序路径，这对于某些测试框架可能更好：

```py
$ coverage run -m unittest
$ coverage run -m nose
$ coverage run -m pytest

```

下一步是从 `.coverage` 文件中缓存的结果生成可读的代码覆盖报告。`coverage` 包支持几种输出格式，最简单的一种只在您的终端中打印 ASCII 表格：

```py
$ coverage report
Name             StmtsMiss  Cover
------------------------------------
primes.py            7      0   100%
test_primes.py      16      0   100%
------------------------------------
TOTAL               23      0   100%

```

另一个有用的覆盖报告格式是 HTML，可以在您的 Web 浏览器中浏览：

```py
$ coverage html

```

此 HTML 报告的默认输出文件夹是您的工作目录中的 `htmlcov/`。`coverage html` 输出的真正优势在于您可以浏览项目的带有缺失测试覆盖部分的注释源代码（如 *图 1* 所示）：

![测试覆盖](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/B05295_10_01.jpg)

图 1 覆盖率 HTML 报告中带注释的源代码示例

您应该记住，虽然您应该始终努力确保 100%的测试覆盖率，但这并不意味着代码被完美测试，也不意味着代码不会出错的地方。这只意味着每行代码在执行过程中都被执行到了，但并不一定测试了每种可能的条件。实际上，确保完整的代码覆盖率可能相对容易，但确保每个代码分支都被执行到则非常困难。这对于可能具有多个`if`语句和特定语言构造（如`list`/`dict`/`set`推导）组合的函数的测试尤其如此。您应该始终关注良好的测试覆盖率，但您不应该将其测量视为测试套件质量的最终答案。

## 伪造和模拟

编写单元测试预设了对正在测试的代码单元进行隔离。测试通常会向函数或方法提供一些数据，并验证其返回值和/或执行的副作用。这主要是为了确保测试：

+   涉及应用程序的一个原子部分，可以是函数、方法、类或接口

+   提供确定性、可重现的结果

有时，程序组件的正确隔离并不明显。例如，如果代码发送电子邮件，它可能会调用 Python 的`smtplib`模块，该模块将通过网络连接与 SMTP 服务器进行通信。如果我们希望我们的测试是可重现的，并且只是测试电子邮件是否具有所需的内容，那么可能不应该发生这种情况。理想情况下，单元测试应该在任何计算机上运行，而不需要外部依赖和副作用。

由于 Python 的动态特性，可以使用**monkey patching**来修改测试装置中的运行时代码（即在运行时动态修改软件而不触及源代码）来**伪造**第三方代码或库的行为。

### 构建一个伪造

在测试中创建伪造行为可以通过发现测试代码与外部部分交互所需的最小交互集。然后，手动返回输出，或者使用先前记录的真实数据池。

这是通过启动一个空类或函数并将其用作替代来完成的。然后启动测试，并迭代更新伪造，直到其行为正确。这是由于 Python 类型系统的特性。只要对象的行为与预期的类型相匹配，并且不需要通过子类化成为其祖先，它就被认为与给定类型兼容。这种在 Python 中的类型化方法被称为鸭子类型——如果某物的行为像鸭子，那么它就可以被当作鸭子对待。

让我们以一个名为`mailer`的模块中的名为`send`的函数为例，该函数发送电子邮件：

```py
import smtplib
import email.message

def send(
    sender, to,
    subject='None',
    body='None',
    server='localhost'
):
    """sends a message."""
    message = email.message.Message()
    message['To'] = to
    message['From'] = sender
    message['Subject'] = subject
    message.set_payload(body)

    server = smtplib.SMTP(server)
    try:
        return server.sendmail(sender, to, message.as_string())
    finally:
        server.quit()
```

### 注意

`py.test`将用于在本节中演示伪造和模拟。

相应的测试可以是：

```py
from mailer import send

def test_send():
    res = send(
        'john.doe@example.com', 
        'john.doe@example.com', 
        'topic',
        'body'
    )
    assert res == {}
```

只要本地主机上有 SMTP 服务器，这个测试就会通过并工作。如果没有，它会失败，就像这样：

```py
$ py.test --tb=short
========================= test session starts =========================
platform darwin -- Python 3.5.1, pytest-2.8.7, py-1.4.31, pluggy-0.3.1
rootdir: /Users/swistakm/dev/book/chapter10/mailer, inifile:** 
plugins: capturelog-0.7, codecheckers-0.2, cov-2.2.1, timeout-1.0.0
collected 5 items** 

mailer.py ..
test_mailer.py ..F

============================== FAILURES ===============================
______________________________ test_send ______________________________
test_mailer.py:10: in test_send
 **'body'
mailer.py:19: in send
 **server = smtplib.SMTP(server)
.../smtplib.py:251: in __init__
 **(code, msg) = self.connect(host, port)
.../smtplib.py:335: in connect
 **self.sock = self._get_socket(host, port, self.timeout)
.../smtplib.py:306: in _get_socket
 **self.source_address)
.../socket.py:711: in create_connection
 **raise err
.../socket.py:702: in create_connection
 **sock.connect(sa)
E   ConnectionRefusedError: [Errno 61] Connection refused
======== 1 failed, 4 passed, 1 pytest-warnings in 0.17 seconds ========

```

可以添加一个补丁来伪造 SMTP 类：

```py
import smtplib
import pytest
from mailer import send

class FakeSMTP(object):
    pass

@pytest.yield_fixture()
def patch_smtplib():
    # setup step: monkey patch smtplib
    old_smtp = smtplib.SMTP
    smtplib.SMTP = FakeSMTP

    yield

    # teardown step: bring back smtplib to 
    # its former state
    smtplib.SMTP = old_smtp

def test_send(patch_smtplib):
    res = send(
        'john.doe@example.com',
        'john.doe@example.com',
        'topic',
        'body'
    )
    assert res == {}
```

在前面的代码中，我们使用了一个新的`pytest.yield_fixture()`装饰器。它允许我们使用生成器语法在单个 fixture 函数中提供设置和拆卸过程。现在我们的测试套件可以使用`smtplib`的修补版本再次运行：

```py
$ py.test --tb=short -v
======================== test session starts ========================
platform darwin -- Python 3.5.1, pytest-2.8.7, py-1.4.31, pluggy-0.3.1 -- /Users/swistakm/.envs/book/bin/python3
cachedir: .cache
rootdir: /Users/swistakm/dev/book/chapter10/mailer, inifile:** 
plugins: capturelog-0.7, codecheckers-0.2, cov-2.2.1, timeout-1.0.0
collected 5 items** 

mailer.py::pyflakes PASSED
mailer.py::pep8 PASSED
test_mailer.py::pyflakes PASSED
test_mailer.py::pep8 PASSED
test_mailer.py::test_send FAILED

============================= FAILURES ==============================
_____________________________ test_send _____________________________
test_mailer.py:29: in test_send
 **'body'
mailer.py:19: in send
 **server = smtplib.SMTP(server)
E   TypeError: object() takes no parameters
======= 1 failed, 4 passed, 1 pytest-warnings in 0.09 seconds =======

```

从前面的对话记录中可以看出，我们的`FakeSMTP`类实现并不完整。我们需要更新其接口以匹配原始的 SMTP 类。根据鸭子类型原则，我们只需要提供被测试的`send()`函数所需的接口：

```py
class FakeSMTP(object):
    def __init__(self, *args, **kw):
        # arguments are not important in our example
        pass

    def quit(self):
        pass

    def sendmail(self, *args, **kw):
        return {}
```

当然，虚假类可以随着新的测试而发展，以提供更复杂的行为。但它应该尽可能短小简单。相同的原则可以用于更复杂的输出，通过记录它们来通过虚假 API 返回它们。这通常用于 LDAP 或 SQL 等第三方服务器。

当猴子补丁任何内置或第三方模块时，需要特别小心。如果操作不当，这种方法可能会留下意想不到的副作用，会在测试之间传播。幸运的是，许多测试框架和工具提供了适当的实用工具，使得对任何代码单元进行补丁变得安全且容易。在我们的例子中，我们手动完成了所有操作，并提供了一个自定义的`patch_smtplib()` fixture 函数，其中包括了分离的设置和拆卸步骤。在`py.test`中的典型解决方案要简单得多。这个框架带有一个内置的猴子补丁 fixture，应该满足我们大部分的补丁需求。

```py
import smtplib
from mailer import send

class FakeSMTP(object):
    def __init__(self, *args, **kw):
        # arguments are not important in our example
        pass

    def quit(self):
        pass

    def sendmail(self, *args, **kw):
        return {}

def test_send(monkeypatch):
    monkeypatch.setattr(smtplib, 'SMTP', FakeSMTP)

    res = send(
        'john.doe@example.com',
        'john.doe@example.com',
        'topic',
        'body'
    )
    assert res == {}
```

您应该知道，*虚假*有真正的局限性。如果决定虚假一个外部依赖，可能会引入真实服务器不会有的错误或意外行为，反之亦然。

### 使用模拟

模拟对象是通用的虚假对象，可以用来隔离被测试的代码。它们自动化了对象的输入和输出的构建过程。在静态类型的语言中，模拟对象的使用更多，因为猴子补丁更难，但它们在 Python 中仍然很有用，可以缩短代码以模拟外部 API。

Python 中有很多模拟库可用，但最受认可的是`unittest.mock`，它是标准库中提供的。它最初是作为第三方包创建的，而不是作为 Python 发行版的一部分，但很快就被包含到标准库中作为一个临时包（参见[`docs.python.org/dev/glossary.html#term-provisional-api`](https://docs.python.org/dev/glossary.html#term-provisional-api)）。对于早于 3.3 版本的 Python，您需要从 PyPI 安装它：

```py
pip install Mock

```

在我们的例子中，使用`unittest.mock`来补丁 SMTP 比从头开始创建一个虚假对象要简单得多。

```py
import smtplib
from unittest.mock import MagicMock
from mailer import send

def test_send(monkeypatch):
    smtp_mock = MagicMock()
    smtp_mock.sendmail.return_value = {}

    monkeypatch.setattr(
        smtplib, 'SMTP', MagicMock(return_value=smtp_mock)
    )

    res = send(
        'john.doe@example.com',
        'john.doe@example.com',
        'topic',
        'body'
    )
    assert res == {}
```

模拟对象或方法的`return_value`参数允许您定义调用返回的值。当使用模拟对象时，每次代码调用属性时，它都会即时为属性创建一个新的模拟对象。因此，不会引发异常。这就是我们之前编写的`quit`方法的情况，它不需要再定义了。

在前面的示例中，实际上我们创建了两个模拟对象：

+   第一个模拟了 SMTP 类对象而不是它的实例。这使您可以轻松地创建一个新对象，而不管预期的`__init__()`方法是什么。如果将模拟对象视为可调用，默认情况下会返回新的`Mock()`对象。这就是为什么我们需要为其`return_value`关键字参数提供另一个模拟对象，以便对实例接口进行控制。

+   第二个模拟了在补丁`smtplib.SMTP()`调用上返回的实际实例。在这个模拟中，我们控制了`sendmail()`方法的行为。

在我们的例子中，我们使用了`py.test`框架提供的猴子补丁实用程序，但`unittest.mock`提供了自己的补丁实用程序。在某些情况下（比如补丁类对象），使用它们可能比使用特定于框架的工具更简单更快。以下是使用`unittest.mock`模块提供的`patch()`上下文管理器进行猴子补丁的示例：

```py
from unittest.mock import patch
from mailer import send

def test_send():
    with patch('smtplib.SMTP') as mock:
        instance = mock.return_value
        instance.sendmail.return_value = {}
        res = send(
            'john.doe@example.com',
            'john.doe@example.com',
            'topic',
            'body'
        )
        assert res == {}
```

## 测试环境和依赖兼容性

本书中已经多次提到了环境隔离的重要性。通过在应用程序级别（虚拟环境）和系统级别（系统虚拟化）上隔离执行环境，您可以确保您的测试在可重复的条件下运行。这样，您就可以保护自己免受由于损坏的依赖关系引起的罕见和隐晦的问题。

允许适当隔离测试环境的最佳方式是使用支持系统虚拟化的良好持续集成系统。对于开源项目，有很好的免费解决方案，比如 Travis CI（Linux 和 OS X）或 AppVeyor（Windows），但如果你需要为测试专有软件构建这样的解决方案，很可能需要花费一些时间在一些现有的开源 CI 工具（GitLab CI、Jenkins 和 Buildbot）的基础上构建这样的解决方案。

### 依赖矩阵测试

大多数情况下，针对开源 Python 项目的测试矩阵主要关注不同的 Python 版本，很少关注不同的操作系统。对于纯粹是 Python 的项目，没有预期的系统互操作性问题，不在不同系统上进行测试和构建是完全可以的。但是一些项目，特别是作为编译 Python 扩展进行分发的项目，绝对应该在各种目标操作系统上进行测试。对于开源项目，甚至可能被迫使用几个独立的 CI 系统，为仅仅提供三种最流行的系统（Windows、Linux 和 Mac OS X）的构建。如果你正在寻找一个很好的例子，可以看一下小型的 pyrilla 项目（参考[`github.com/swistakm/pyrilla`](https://github.com/swistakm/pyrilla)），这是一个简单的用于 Python 的 C 音频扩展。它同时使用了 Travis CI 和 AppVeyor 来为 Windows 和 Mac OS X 提供编译构建，并支持大量的 CPython 版本。

但是测试矩阵的维度不仅仅局限于系统和 Python 版本。提供与其他软件集成的包，比如缓存、数据库或系统服务，往往应该在各种集成应用的版本上进行测试。一个很好的工具，可以让这样的测试变得容易，是 tox（参考[`tox.readthedocs.org`](http://tox.readthedocs.org)）。它提供了一种简单的方式来配置多个测试环境，并通过单个`tox`命令运行所有测试。它是一个非常强大和灵活的工具，但也非常容易使用。展示其用法的最佳方式是向您展示一个配置文件的示例，实际上这个配置文件是 tox 的核心。以下是 django-userena 项目的`tox.ini`文件（参考[`github.com/bread-and-pepper/django-userena`](https://github.com/bread-and-pepper/django-userena)）：

```py
[tox]
downloadcache = {toxworkdir}/cache/

envlist =
    ; py26 support was dropped in django1.7
    py26-django{15,16},
    ; py27 still has the widest django support
    py27-django{15,16,17,18,19},
    ; py32, py33 support was officially introduced in django1.5
    ; py32, py33 support was dropped in django1.9
    py32-django{15,16,17,18},
    py33-django{15,16,17,18},
    ; py34 support was officially introduced in django1.7
    py34-django{17,18,19}
    ; py35 support was officially introduced in django1.8
    py35-django{18,19}

[testenv]
usedevelop = True
deps =
    django{15,16}: south
    django{15,16}: django-guardian<1.4.0
    django15: django==1.5.12
    django16: django==1.6.11
    django17: django==1.7.11
    django18: django==1.8.7
    django19: django==1.9
    coverage: django==1.9
    coverage: coverage==4.0.3
    coverage: coveralls==1.1

basepython =
    py35: python3.5
    py34: python3.4
    py33: python3.3
    py32: python3.2
    py27: python2.7
    py26: python2.6

commands={envpython} userena/runtests/runtests.py userenaumessages {posargs}

[testenv:coverage]
basepython = python2.7
passenv = TRAVIS TRAVIS_JOB_ID TRAVIS_BRANCH
commands=
    coverage run --source=userena userena/runtests/runtests.py userenaumessages {posargs}
    coveralls
```

这个配置允许在五个不同版本的 Django 和六个版本的 Python 上测试`django-userena`。并非每个 Django 版本都能在每个 Python 版本上运行，`tox.ini`文件使得定义这样的依赖约束相对容易。实际上，整个构建矩阵包括 21 个独特的环境（包括一个用于代码覆盖收集的特殊环境）。手动创建每个测试环境，甚至使用 shell 脚本，都需要巨大的工作量。

Tox 很棒，但是如果我们想要更改不是纯 Python 依赖的测试环境的其他元素，它的使用就会变得更加复杂。这是一个情况，当我们需要在不同版本的系统软件包和后备服务下进行测试时。解决这个问题的最佳方法是再次使用良好的持续集成系统，它允许您轻松地定义环境变量的矩阵，并在虚拟机上安装系统软件。使用 Travis CI 进行这样做的一个很好的例子是`ianitor`项目（参见[`github.com/ClearcodeHQ/ianitor/`](https://github.com/ClearcodeHQ/ianitor/)），它已经在第九章中提到过，*记录您的项目*。这是 Consul 发现服务的一个简单实用程序。Consul 项目有一个非常活跃的社区，每年都会发布许多新版本的代码。这使得对该服务的各种版本进行测试非常合理。这确保了`ianitor`项目仍然与该软件的最新版本保持最新，但也不会破坏与以前的 Consul 版本的兼容性。以下是 Travis CI 的`.travis.yml`配置文件的内容，它允许您对三个不同的 Consul 版本和四个 Python 解释器版本进行测试：

```py
language: python

install: pip install tox --use-mirrors
env:
  matrix:
    # consul 0.4.1
    - TOX_ENV=py27     CONSUL_VERSION=0.4.1
    - TOX_ENV=py33     CONSUL_VERSION=0.4.1
    - TOX_ENV=py34     CONSUL_VERSION=0.4.1
    - TOX_ENV=py35     CONSUL_VERSION=0.4.1

    # consul 0.5.2
    - TOX_ENV=py27     CONSUL_VERSION=0.5.2
    - TOX_ENV=py33     CONSUL_VERSION=0.5.2
    - TOX_ENV=py34     CONSUL_VERSION=0.5.2
    - TOX_ENV=py35     CONSUL_VERSION=0.5.2

    # consul 0.6.4
    - TOX_ENV=py27     CONSUL_VERSION=0.6.4
    - TOX_ENV=py33     CONSUL_VERSION=0.6.4
    - TOX_ENV=py34     CONSUL_VERSION=0.6.4
    - TOX_ENV=py35     CONSUL_VERSION=0.6.4

    # coverage and style checks
    - TOX_ENV=pep8     CONSUL_VERSION=0.4.1
    - TOX_ENV=coverage CONSUL_VERSION=0.4.1

before_script:
  - wget https://releases.hashicorp.com/consul/${CONSUL_VERSION}/consul_${CONSUL_VERSION}_linux_amd64.zip
  - unzip consul_${CONSUL_VERSION}_linux_amd64.zip
  - start-stop-daemon --start --background --exec `pwd`/consul -- agent -server -data-dir /tmp/consul -bootstrap-expect=1

script:
  - tox -e $TOX_ENV
```

前面的例子为`ianitor`代码提供了 14 个独特的测试环境（包括`pep8`和`coverage`构建）。这个配置还使用 tox 在 Travis VM 上创建实际的测试虚拟环境。这实际上是将 tox 与不同的 CI 系统集成的一种非常流行的方法。通过尽可能多地将测试环境配置移动到 tox，您可以减少将自己锁定到单个供应商的风险。像安装新服务或定义系统环境变量这样的事情，大多数 Travis CI 的竞争对手都支持，因此如果市场上有更好的产品可用，或者 Travis 会改变其针对开源项目的定价模式，切换到不同的服务提供商应该相对容易。

## 文档驱动开发

与其他语言相比，*文档测试*在 Python 中是一个真正的优势。文档可以使用代码示例，这些示例也可以作为测试运行，这改变了 TDD 的方式。例如，在开发周期中，文档的一部分可以通过`doctests`来完成。这种方法还确保提供的示例始终是最新的并且确实有效。

通过文档测试构建软件而不是常规单元测试被称为**文档驱动开发**（**DDD**）。开发人员在实现代码时用简单的英语解释代码的功能。

### 写故事

在 DDD 中编写文档测试是通过构建关于代码如何工作和应该如何使用的故事来完成的。首先用简单的英语描述原则，然后在文本中分布一些代码使用示例。一个好的做法是先写关于代码如何工作的文本，然后添加一些代码示例。

要看一个实际的文档测试的例子，让我们看一下`atomisator`软件包（参见[`bitbucket.org/tarek/atomisator`](https://bitbucket.org/tarek/atomisator)）。其`atomisator.parser`子软件包的文档文本（位于`packages/atomisator.parser/atomisator/parser/docs/README.txt`）如下：

```py
=================
atomisator.parser
=================

The parser knows how to return a feed content, with
the `parse` function, available as a top-level function::

>>> from atomisator.parser import Parser

This function takes the feed url and returns an iterator
over its content. A second parameter can specify a maximum
number of entries to return. If not given, it is fixed to 10::

>>> import os
>>> res = Parser()(os.path.join(test_dir, 'sample.xml'))
>>> res
<itertools.imap ...>

Each item is a dictionary that contain the entry::

>>> entry = res.next()
>>> entry['title']
u'CSSEdit 2.0 Released'

The keys available are:

>>> keys = sorted(entry.keys())
>>> list(keys)
    ['id', 'link', 'links', 'summary', 'summary_detail', 'tags', 
     'title', 'title_detail']

Dates are changed into datetime::

>>> type(entry['date'])
>>>
```

随后，文档测试将会发展，以考虑新元素或所需的更改。这个文档测试也是开发人员想要使用该软件包的良好文档，并且应该根据这种用法进行更改。

在文档中编写测试的一个常见陷阱是将其转化为一段难以阅读的文本。如果发生这种情况，就不应再将其视为文档的一部分。

也就是说，一些开发人员专门通过 doctests 工作，通常将他们的 doctests 分为两类：可读和可用的，可以成为软件包文档的一部分，以及不可读的，仅用于构建和测试软件。

许多开发人员认为应该放弃后者，转而使用常规单元测试。其他人甚至为错误修复使用专门的 doctests。

因此，doctests 和常规测试之间的平衡是一种品味问题，由团队决定，只要 doctests 的已发布部分是可读的。

### 注意

在项目中使用 DDD 时，专注于可读性，并决定哪些 doctests 有资格成为已发布文档的一部分。

# 总结

本章提倡使用 TDD，并提供了更多关于：

+   `unittest`陷阱

+   第三方工具：`nose`和`py.test`

+   如何构建伪造和模拟

+   文档驱动开发

由于我们已经知道如何构建、打包和测试软件，在接下来的两章中，我们将专注于寻找性能瓶颈并优化您的程序的方法。


# 第十一章：优化-一般原则和分析技术

|   | *"我们应该忘记小的效率，大约有 97%的时间：过早的优化是万恶之源。"* |   |
| --- | --- | --- |
|   | --*唐纳德·克努斯* |

本章讨论了优化，并提供了一套通用原则和分析技术。它提供了每个开发人员都应该了解的三条优化规则，并提供了优化指南。最后，它着重介绍了如何找到瓶颈。

# 优化的三条规则

优化是有代价的，无论结果如何。当一段代码工作时，也许最好（有时）是不要试图不惜一切代价使其更快。在进行任何优化时，有一些规则需要牢记：

+   首先使其工作

+   从用户的角度出发

+   保持代码可读

## 首先使其工作

一个非常常见的错误是在编写代码时尝试对其进行优化。这在大多数情况下是毫无意义的，因为真正的瓶颈通常出现在你从未想到的地方。

应用程序通常由非常复杂的交互组成，在真正使用之前，很难完全了解发生了什么。

当然，这并不是不尝试尽快使其运行的原因。您应该小心尽量降低其复杂性，并避免无用的重复。但第一个目标是使其工作。这个目标不应该被优化努力所阻碍。

对于代码的每一行，Python 的哲学是有一种，最好只有一种方法来做。因此，只要你遵循 Pythonic 的语法，描述在第二章和第三章中描述的*语法最佳实践*，你的代码应该没问题。通常情况下，写更少的代码比写更多的代码更好更快。

在你的代码能够工作并且你准备进行分析之前，不要做任何这些事情：

+   首先编写一个全局字典来缓存函数的数据

+   考虑将代码的一部分外部化为 C 或 Cython 等混合语言

+   寻找外部库来进行基本计算

对于非常专业的领域，如科学计算或游戏，从一开始就使用专门的库和外部化可能是不可避免的。另一方面，使用像 NumPy 这样的库可能会简化特定功能的开发，并在最后产生更简单更快的代码。此外，如果有一个很好的库可以为你完成工作，你就不应该重写一个函数。

例如，Soya 3D 是一个基于 OpenGL 的游戏引擎（参见[`home.gna.org/oomadness/en/soya3d/index.html`](http://home.gna.org/oomadness/en/soya3d/index.html)），在渲染实时 3D 时使用 C 和 Pyrex 进行快速矩阵运算。

### 注意

优化是在已经工作的程序上进行的。

正如 Kent Beck 所说，“先让它工作，然后让它正确，最后让它快。”

## 从用户的角度出发

我曾见过一些团队致力于优化应用服务器的启动时间，而当服务器已经运行良好时，他们可能更好（有时）是不要尝试不惜一切代价使其更快。在进行任何优化时，有一些规则需要牢记：

虽然使程序启动更快从绝对角度来看是件好事，但团队应该谨慎地优先考虑优化工作，并问自己以下问题：

+   我被要求使其更快了吗？

+   谁发现程序运行缓慢？

+   真的很慢，还是可以接受？

+   使其更快需要多少成本，是否值得？

+   哪些部分需要快？

记住，优化是有成本的，开发人员的观点对客户来说毫无意义，除非您正在编写一个框架或库，而客户也是开发人员。

### 注意

优化不是一场游戏。只有在必要时才应该进行。

## 保持代码可读和易于维护

即使 Python 试图使常见的代码模式运行得最快，优化工作可能会使您的代码变得难以阅读。在产生可读且易于维护的代码与破坏代码以提高速度之间需要保持平衡。

当您达到 90%的优化目标，并且剩下的 10%使您的代码完全无法阅读时，最好停止工作或寻找其他解决方案。

### 注意

优化不应该使您的代码难以阅读。如果发生这种情况，您应该寻找替代解决方案，比如外部化或重新设计。要在可读性和速度之间寻找一个好的折衷方案。

# 优化策略

假设您的程序存在真正的速度问题需要解决。不要试图猜测如何使其更快。瓶颈通常很难通过查看代码来找到，需要一组工具来找到真正的问题。

一个良好的优化策略可以从以下三个步骤开始：

+   **找到另一个罪魁祸首**：确保第三方服务器或资源没有故障

+   **扩展硬件**：确保资源足够

+   **编写速度测试**：创建具有速度目标的场景

## 找到另一个罪魁祸首

通常，性能问题发生在生产级别，客户通知您它的工作方式与软件测试时不同。性能问题可能是因为应用程序没有计划在现实世界中与大量用户和数据大小增加的情况下运行。

但是，如果应用程序与其他应用程序进行交互，首先要做的是检查瓶颈是否位于这些交互上。例如，数据库服务器或 LDAP 服务器可能会导致额外的开销，并使一切变慢。

应用程序之间的物理链接也应该被考虑。也许您的应用程序服务器与内部网络中的另一台服务器之间的网络链接由于错误配置或拥塞而变得非常缓慢。

设计文档应提供所有交互的图表和每个链接的性质，以便全面了解系统并在尝试解决速度问题时提供帮助。

### 注意

如果您的应用程序使用第三方服务器或资源，每次交互都应该经过审计，以确保瓶颈不在那里。

## 扩展硬件

当没有更多的易失性内存可用时，系统开始使用硬盘来存储数据。这就是交换。

这会带来很多额外开销，并且性能会急剧下降。从用户的角度来看，系统在这个阶段被认为已经死机。因此，扩展硬件以防止这种情况发生非常重要。

虽然系统上有足够的内存很重要，但确保应用程序不会表现出异常行为并占用过多内存也很重要。例如，如果一个程序处理几百兆大小的大型视频文件，它不应该完全将它们加载到内存中，而是应该分块处理或使用磁盘流。

磁盘使用也很重要。如果 I/O 错误隐藏在试图反复写入磁盘的代码中，分区已满可能会严重减慢应用程序。此外，即使代码只尝试写入一次，硬件和操作系统也可能尝试多次写入。

请注意，升级硬件（垂直扩展）有一些明显的限制。你无法将无限量的硬件放入一个机架中。此外，高效的硬件价格极其昂贵（收益递减定律），因此这种方法也有经济上的限制。从这个角度来看，总是更好的是拥有可以通过添加新的计算节点或工作节点（水平扩展）来扩展的系统。这样可以使用性价比最高的商品软件来扩展服务。

不幸的是，设计和维护高度可扩展的分布式系统既困难又昂贵。如果你的系统不能轻松地进行水平扩展，或者垂直扩展更快更便宜，那么最好选择这种方法，而不是在系统架构的全面重新设计上浪费时间和资源。请记住，硬件的性能和价格总是随时间变得更快更便宜。许多产品都处于这种甜蜜点，它们的扩展需求与提高硬件性能的趋势相一致。

## 编写速度测试

在开始优化工作时，重要的是使用类似于测试驱动开发的工作流程，而不是不断地运行一些手动测试。一个好的做法是在应用程序中专门设置一个测试模块，其中编写了需要优化的调用序列。有了这种情景，您在优化应用程序时将有助于跟踪您的进展。

甚至可以编写一些断言，设置一些速度目标。为了防止速度回归，这些测试可以在代码优化后留下：

```py
>>> def test_speed():
...     import time
...     start = time.time()
...     the_code()
...     end = time.time() - start
...     assert end < 10, \
...     "sorry this code should not take 10 seconds !"
...** 

```

### 注意

测量执行速度取决于所使用的 CPU 的性能。但是我们将在下一节中看到如何编写通用的持续时间测量。

# 找到瓶颈

通过以下方式找到瓶颈：

+   分析 CPU 使用情况

+   分析内存使用情况

+   分析网络使用情况

## 分析 CPU 使用情况

瓶颈的第一个来源是你的代码。标准库提供了执行代码分析所需的所有工具。它们基于确定性方法。

**确定性分析器**通过在最低级别添加计时器来测量每个函数中花费的时间。这会引入一些开销，但可以很好地了解时间消耗在哪里。另一方面，**统计分析器**对指令指针的使用进行采样，不会对代码进行仪器化。后者不够准确，但允许以全速运行目标程序。

有两种方法可以对代码进行分析：

+   宏观分析：在程序运行时对整个程序进行分析并生成统计数据

+   微观分析：通过手动对程序的精确部分进行仪器化来测量

### 宏观分析

宏观分析是通过以特殊模式运行应用程序来完成的，解释器被仪器化以收集代码使用统计信息。Python 提供了几种工具来实现这一点：

+   `profile`：这是一个纯 Python 实现

+   `cProfile`：这是一个 C 实现，提供了与`profile`工具相同的接口，但开销较小

对大多数 Python 程序员来说，由于其开销较小，推荐的选择是`cProfile`。无论如何，如果需要以某种方式扩展分析器，那么`profile`可能是更好的选择，因为它不使用 C 扩展。

这两种工具具有相同的接口和用法，因此我们将只使用其中一个来展示它们的工作原理。以下是一个`myapp.py`模块，其中包含一个我们将使用`cProfile`测试的主函数：

```py
import time

def medium():
    time.sleep(0.01)

def light():
    time.sleep(0.001)

def heavy():
    for i in range(100):
        light()
        medium()
        medium()
    time.sleep(2)

def main():
    for i in range(2):
        heavy()

if __name__ == '__main__':
    main()
```

该模块可以直接从提示符中调用，并在此处总结结果：

```py
$ python3 -m cProfile myapp.py
 **1208 function calls in 8.243 seconds

 **Ordered by: standard name

 **ncalls  tottime  percall  cumtime  percall filename:lineno(function)
 **2    0.001    0.000    8.243    4.121 myapp.py:13(heavy)
 **1    0.000    0.000    8.243    8.243 myapp.py:2(<module>)
 **1    0.000    0.000    8.243    8.243 myapp.py:21(main)
 **400    0.001    0.000    4.026    0.010 myapp.py:5(medium)
 **200    0.000    0.000    0.212    0.001 myapp.py:9(light)
 **1    0.000    0.000    8.243    8.243 {built-in method exec}
 **602    8.241    0.014    8.241    0.014 {built-in method sleep}

```

提供的统计数据是由分析器填充的统计对象的打印视图。可以手动调用该工具：

```py
>>> import cProfile
>>> from myapp import main
>>> profiler = cProfile.Profile()
>>> profiler.runcall(main)
>>> profiler.print_stats()
 **1206 function calls in 8.243 seconds

 **Ordered by: standard name

 **ncalls  tottime  percall  cumtime  percall file:lineno(function)
 **2    0.001    0.000    8.243    4.121 myapp.py:13(heavy)
 **1    0.000    0.000    8.243    8.243 myapp.py:21(main)
 **400    0.001    0.000    4.026    0.010 myapp.py:5(medium)
 **200    0.000    0.000    0.212    0.001 myapp.py:9(light)
 **602    8.241    0.014    8.241    0.014 {built-in method sleep}

```

统计数据也可以保存在文件中，然后由`pstats`模块读取。该模块提供了一个知道如何处理分析文件并提供一些辅助功能的类的调用：

```py
>>> import pstats
>>> import cProfile
>>> from myapp import main
>>> cProfile.run('main()', 'myapp.stats')
>>> stats = pstats.Stats('myapp.stats')
>>> stats.total_calls
1208
>>> stats.sort_stats('time').print_stats(3)
Mon Apr  4 21:44:36 2016    myapp.stats

 **1208 function calls in 8.243 seconds

 **Ordered by: internal time
 **List reduced from 8 to 3 due to restriction <3>

 **ncalls  tottime  percall  cumtime  percall file:lineno(function)
 **602    8.241    0.014    8.241    0.014 {built-in method sleep}
 **400    0.001    0.000    4.025    0.010 myapp.py:5(medium)
 **2    0.001    0.000    8.243    4.121 myapp.py:13(heavy)

```

从那里，您可以通过打印每个函数的调用者和被调用者来浏览代码：

```py
>>> stats.print_callees('medium')
 **Ordered by: internal time
 **List reduced from 8 to 1 due to restriction <'medium'>

Function           called...
 **ncalls  tottime  cumtime
myapp.py:5(medium) ->  400    4.025    4.025  {built-in method sleep}

>>> stats.print_callees('light')
 **Ordered by: internal time
 **List reduced from 8 to 1 due to restriction <'light'>

Function           called...
 **ncalls  tottime  cumtime
myapp.py:9(light)  ->  200    0.212    0.212  {built-in method sleep}

```

能够对输出进行排序可以在不同的视图上查找瓶颈。例如，考虑以下情景：

+   当调用次数非常高并且占用大部分全局时间时，该函数或方法可能在循环中。通过将此调用移动到不同的范围以减少操作次数，可能可以进行可能的优化

+   当一个函数执行时间很长时，如果可能的话，缓存可能是一个不错的选择

从分析数据中可视化瓶颈的另一个好方法是将它们转换成图表（见*图 1*）。**Gprof2Dot**（[`github.com/jrfonseca/gprof2dot`](https://github.com/jrfonseca/gprof2dot)）可以将分析器数据转换为点图。您可以使用`pip`从 PyPI 下载这个简单的脚本，并在安装了 Graphviz（参见[`www.graphviz.org/`](http://www.graphviz.org/)）的环境中使用它：

```py
$ gprof2dot.py -f pstats myapp.stats | dot -Tpng -o output.png

```

`gprof2dot`的优势在于它试图成为一种语言无关的工具。它不仅限于 Python `profile`或`cProfile`的输出，还可以从多个其他配置文件中读取，比如 Linux perf、xperf、gprof、Java HPROF 等等。

![宏观分析](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/B05295_11_01.jpg)

图 1 使用 gprof2dot 生成的分析概览图的示例

宏观分析是检测有问题的函数或者它的周边的一个好方法。当你找到它之后，你可以转向微观分析。

### 微观分析

当找到慢函数时，有时需要进行更多的分析工作，测试程序的一部分。这是通过手动在代码的一部分进行仪器化速度测试来完成的。

例如，可以使用`cProfile`模块作为装饰器：

```py
>>> import tempfile, os, cProfile, pstats
>>> def profile(column='time', list=5):
...     def _profile(function):
...         def __profile(*args, **kw):
...             s = tempfile.mktemp()
...             profiler = cProfile.Profile()
...             profiler.runcall(function, *args, **kw)
...             profiler.dump_stats(s)
...             p = pstats.Stats(s)
...             p.sort_stats(column).print_stats(list)
...         return __profile
...     return _profile
...
>>> from myapp import main
>>> @profile('time', 6)
... def main_profiled():
...     return main()
...
>>> main_profiled()
Mon Apr  4 22:01:01 2016    /tmp/tmpvswuovz_

 **1207 function calls in 8.243 seconds

 **Ordered by: internal time
 **List reduced from 7 to 6 due to restriction <6>

 **ncalls  tottime  percall  cumtime  percall file:lineno(function)
 **602    8.241    0.014    8.241    0.014 {built-in method sleep}
 **400    0.001    0.000    4.026    0.010 myapp.py:5(medium)
 **2    0.001    0.000    8.243    4.121 myapp.py:13(heavy)
 **200    0.000    0.000    0.213    0.001 myapp.py:9(light)
 **1    0.000    0.000    8.243    8.243 myapp.py:21(main)
 **1    0.000    0.000    8.243    8.243 <stdin>:1(main_profiled)

>>> from myapp import light
>>> stats = profile()(light)
>>> stats()
Mon Apr  4 22:01:57 2016    /tmp/tmpnp_zk7dl

 **3 function calls in 0.001 seconds

 **Ordered by: internal time

 **ncalls  tottime  percall  cumtime  percall file:lineno(function)
 **1    0.001    0.001    0.001    0.001 {built-in method sleep}
 **1    0.000    0.000    0.001    0.001 myapp.py:9(light)

```

这种方法允许测试应用程序的部分，并锐化统计输出。但在这个阶段，拥有一个调用者列表可能并不有趣，因为函数已经被指出为需要优化的函数。唯一有趣的信息是知道它有多快，然后加以改进。

`timeit`更适合这种需求，它提供了一种简单的方法来测量小代码片段的执行时间，使用主机系统提供的最佳底层计时器（`time.time`或`time.clock`）：

```py
>>> from myapp import light
>>> import timeit
>>> t = timeit.Timer('main()')
>>> t.timeit(number=5)
10000000 loops, best of 3: 0.0269 usec per loop
10000000 loops, best of 3: 0.0268 usec per loop
10000000 loops, best of 3: 0.0269 usec per loop
10000000 loops, best of 3: 0.0268 usec per loop
10000000 loops, best of 3: 0.0269 usec per loop
5.6196951866149902

```

该模块允许您重复调用，并且旨在尝试独立的代码片段。这在应用程序上下文之外非常有用，比如在提示符中，但在现有应用程序中使用起来并不方便。

### 注

确定性分析器将根据计算机正在执行的操作提供结果，因此结果可能每次都会有所不同。多次重复相同的测试并进行平均值计算可以提供更准确的结果。此外，一些计算机具有特殊的 CPU 功能，例如**SpeedStep**，如果计算机在启动测试时处于空闲状态，可能会改变结果（参见[`en.wikipedia.org/wiki/SpeedStep`](http://en.wikipedia.org/wiki/SpeedStep)）。因此，对小代码片段进行持续重复测试是一个好的做法。还有一些其他缓存需要记住，比如 DNS 缓存或 CPU 缓存。

但`timeit`的结果应该谨慎使用。它是一个非常好的工具，可以客观比较两个短代码片段，但也容易让您犯下危险的错误，导致令人困惑的结论。例如，使用`timeit`模块比较两个无害的代码片段，可能会让您认为通过加法进行字符串连接比`str.join()`方法更快：

```py
$ python3 -m timeit -s 'a = map(str, range(1000))' '"".join(a)'
1000000 loops, best of 3: 0.497 usec per loop

$ python3 -m timeit -s 'a = map(str, range(1000)); s=""' 'for i in a: s += i'
10000000 loops, best of 3: 0.0808 usec per loop

```

从第二章 *语法最佳实践 - 类级别以下*，我们知道通过加法进行字符串连接不是一个好的模式。尽管有一些微小的 CPython 微优化专门为这种用例设计，但最终会导致二次运行时间。问题在于`timeit`的`setup`参数（命令行中的`-s`参数）以及 Python 3 中范围的工作方式的细微差别。我不会讨论问题的细节，而是留给您作为练习。无论如何，以下是在 Python 3 中使用`str.join()`习惯用法来比较字符串连接的正确方法：

```py
$ python3 -m timeit -s 'a = [str(i) for i in range(10000)]' 's="".join(a)'
10000 loops, best of 3: 128 usec per loop

$ python3 -m timeit -s 'a = [str(i) for i in range(10000)]' '
>s = ""
>for i in a:
>    s += i
>'
1000 loops, best of 3: 1.38 msec per loop

```

### 测量 Pystones

在测量执行时间时，结果取决于计算机硬件。为了能够产生一个通用的度量，最简单的方法是对一段固定的代码序列进行速度基准测试，并计算出一个比率。从那里，函数所花费的时间可以转换为一个通用值，可以在任何计算机上进行比较。

### 注

有很多用于测量计算机性能的通用基准测试工具。令人惊讶的是，一些很多年前创建的工具今天仍在使用。例如，Whetstone 是在 1972 年创建的，当时它提供了一种 Algol 60 的计算机性能分析器。它用于测量**每秒 Whetstone 百万条指令**（**MWIPS**）。在[`freespace.virgin.net/roy.longbottom/whetstone%20results.htm`](http://freespace.virgin.net/roy.longbottom/whetstone%20results.htm)上维护了一张旧 CPU 和现代 CPU 的结果表。

Python 在其`test`包中提供了一个基准测试工具，用于测量一系列精心选择的操作的持续时间。结果是计算机每秒能够执行的**pystones**数量，以及执行基准测试所用的时间，通常在现代硬件上大约为一秒：

```py
>>> from test import pystone
>>> pystone.pystones()
(1.0500000000000007, 47619.047619047589)

```

速率可以用来将配置持续时间转换为一定数量的 pystones：

```py
>>> from test import pystone
>>> benchtime, pystones = pystone.pystones()
>>> def seconds_to_kpystones(seconds):
...     return (pystones*seconds) / 1000** 
...** 
...** 
>>> seconds_to_kpystones(0.03)
1.4563106796116512
>>> seconds_to_kpystones(1)
48.543689320388381
>>> seconds_to_kpystones(2)
97.087378640776762

```

`seconds_to_kpystones`返回**千 pystones**的数量。如果您想对执行速度进行编码，这种转换可以包含在您的测试中。

拥有 pystones 将允许您在测试中使用这个装饰器，以便您可以对执行时间进行断言。这些测试将在任何计算机上都可以运行，并且将允许开发人员防止速度回归。当应用程序的一部分被优化后，他们将能够在测试中设置其最大执行时间，并确保它不会被进一步的更改所违反。这种方法当然不是理想的，也不是 100%准确的，但至少比将执行时间断言硬编码为以秒为单位的原始值要好。

## 内存使用情况

优化应用程序时可能遇到的另一个问题是内存消耗。如果程序开始占用太多内存，以至于系统开始交换，那么您的应用程序中可能存在太多对象被创建的地方，或者您并不打算保留的对象仍然被一些意外的引用保持活动。这通常很容易通过经典的分析来检测，因为消耗足够的内存使系统交换涉及到很多可以被检测到的 CPU 工作。但有时候这并不明显，内存使用情况必须进行分析。

### Python 如何处理内存

当您使用 CPython 实现时，内存使用可能是 Python 中最难进行分析的事情。虽然像 C 这样的语言允许您获取任何元素的内存大小，但 Python 永远不会让您知道给定对象消耗了多少内存。这是由于语言的动态性质，以及内存管理不直接可访问给语言用户。

内存管理的一些原始细节已经在第七章中解释过了，*其他语言中的 Python 扩展*。我们已经知道 CPython 使用引用计数来管理对象分配。这是一种确定性算法，可以确保当对象的引用计数降至零时，将触发对象的释放。尽管是确定性的，但这个过程不容易在复杂的代码库中手动跟踪和推理。此外，根据 CPython 解释器的编译标志、系统环境或运行时上下文，内部内存管理器层可能决定留下一些空闲内存块以便将来重新分配，而不是完全释放它。

CPython 实现中的额外微优化也使得预测实际内存使用变得更加困难。例如，指向相同短字符串或小整数值的两个变量可能指向内存中的同一个对象实例，也可能不是。

尽管看起来相当可怕和复杂，但 Python 中的内存管理有很好的文档记录（参考[`docs.python.org/3/c-api/memory.html`](https://docs.python.org/3/c-api/memory.html)）。请注意，在调试内存问题时，大多数情况下可以忽略之前提到的微优化。此外，引用计数基本上是基于一个简单的陈述——如果给定对象不再被引用，它就会被移除。换句话说，在解释器之后，函数中的所有局部引用都会被移除。

+   离开函数

+   确保对象不再被使用

因此，仍然在内存中的对象有：

+   全局对象

+   仍然以某种方式被引用的对象

要小心**参数** **入站** **出站**的边缘情况。如果在参数中创建了一个对象，如果函数返回该对象，则参数引用仍然存在。如果将其用作默认值，可能会导致意外结果：

```py
>>> def my_function(argument={}):  # bad practice
...     if '1' in argument:
...         argument['1'] = 2
...     argument['3'] = 4
...     return argument
...** 
>>> my_function()
{'3': 4}
>>> res = my_function()
>>> res['4'] = 'I am still alive!'
>>> print my_function()
{'3': 4, '4': 'I am still alive!'}

```

这就是为什么应该始终使用不可变对象的原因，就像这样：

```py
>>> def my_function(argument=None):  # better practice
...     if argument is None:
...         argument = {}  # a fresh dict is created everytime
...     if '1' in argument:
...         argument['1'] = 2
...     argument['3'] = 4
...     return argument
...** 
>>> my_function()
{'3': 4}
>>> res = my_function()
>>> res['4'] = 'I am still alive!'
>>> print my_function()
{'3': 4}

```

Python 中的引用计数很方便，可以免除手动跟踪对象引用和手动销毁对象的义务。尽管这引入了另一个问题，即开发人员从不清理内存中的实例，如果开发人员不注意使用数据结构的方式，它可能会以不受控制的方式增长。

通常的内存占用者有：

+   不受控制地增长的缓存

+   全局注册实例的对象工厂，并且不跟踪它们的使用情况，比如每次调用查询时都会使用的数据库连接器创建者

+   线程没有正确完成

+   具有`__del__`方法并涉及循环的对象也会占用内存。在 Python 的旧版本（3.4 版本之前），垃圾收集器不会打破循环，因为它无法确定应该先删除哪个对象。因此，会造成内存泄漏。在大多数情况下，使用这种方法都是一个坏主意。

不幸的是，在使用 Python/C API 的 C 扩展中，必须手动管理引用计数和引用所有权，使用`Py_INCREF()`和`Py_DECREF()`宏。我们在第七章中已经讨论了处理引用计数和引用所有权的注意事项，所以你应该已经知道这是一个充满各种陷阱的相当困难的话题。这就是为什么大多数内存问题是由没有正确编写的 C 扩展引起的。

### 内存分析

在开始解决 Python 中的内存问题之前，您应该知道 Python 中内存泄漏的性质是非常特殊的。在一些编译语言如 C 和 C++中，内存泄漏几乎完全是由不再被任何指针引用的分配的内存块引起的。如果您没有对内存的引用，就无法释放它，这种情况被称为*内存泄漏*。在 Python 中，用户没有低级内存管理，所以我们更多地处理泄漏的引用——对不再需要但未被移除的对象的引用。这会阻止解释器释放资源，但与 C 中的内存泄漏情况不同。当然，也总是有 C 扩展的特殊情况，但它们是一种完全不同类型的东西，需要完全不同的工具链，而且不能轻易从 Python 代码中检查。

因此，Python 中的内存问题主要是由意外或非计划的资源获取模式引起的。很少情况下，这是由于内存分配和释放例程的错误处理引起的真正错误。这样的例程只在 CPython 中在使用 Python/C API 编写 C 扩展时才对开发人员可用，而且很少会遇到。因此，Python 中所谓的内存泄漏主要是由软件的过度复杂性和其组件之间的次要交互引起的，这些问题很难追踪。为了发现和定位软件的这些缺陷，您需要了解程序中实际内存使用的情况。

获取有关由 Python 解释器控制的对象数量及其实际大小的信息有点棘手。例如，要知道给定对象的大小需要遍历其所有属性，处理交叉引用，然后将所有内容相加。如果考虑到对象相互引用的方式，这是一个相当困难的问题。`gc`模块没有为此提供高级函数，而且需要 Python 以调试模式编译才能获得完整的信息。

通常，程序员在执行给定操作之后和之前会询问系统关于其应用程序的内存使用情况。但这种测量是一种近似值，很大程度上取决于系统级别的内存管理方式。例如，在 Linux 下使用`top`命令或在 Windows 下使用任务管理器，可以在内存问题明显时检测到内存问题。但这种方法很费力，使得很难追踪到有问题的代码块。

幸运的是，有一些工具可以创建内存快照并计算加载对象的数量和大小。但让我们记住，Python 不会轻易释放内存，它更愿意保留内存以防再次需要。

有一段时间，调试 Python 中的内存问题和使用情况时最流行的工具之一是 Guppy-PE 及其 Heapy 组件。不幸的是，它似乎已不再维护，并且缺乏 Python 3 支持。幸运的是，还有一些其他替代方案在某种程度上与 Python 3 兼容：

+   **Memprof** ([`jmdana.github.io/memprof/`](http://jmdana.github.io/memprof/))：宣称可在 Python 2.6、2.7、3.1、3.2 和 3.3 以及一些符合 POSIX 标准的系统（Mac OS X 和 Linux）上运行

+   **memory_profiler** ([`pypi.python.org/pypi/memory_profiler`](https://pypi.python.org/pypi/memory_profiler))：宣称支持与 Memprof 相同的 Python 版本和系统

+   **Pympler** ([`pythonhosted.org/Pympler/`](http://pythonhosted.org/Pympler/))：宣称支持 Python 2.5、2.6、2.7、3.1、3.2、3.3 和 3.4，并且与操作系统无关

请注意，前面的信息纯粹基于最新版本的特色软件包使用的 trove 分类器。这可能会在本书编写后的时间内轻松更改。尽管如此，目前有一个软件包支持最广泛的 Python 版本，并且也已知在 Python 3.5 下完美运行。它就是`objgraph`。它的 API 似乎有点笨拙，并且功能集非常有限。但它工作正常，做了它需要做的事情，并且非常容易使用。内存检测不是永久添加到生产代码中的东西，因此这个工具不需要很漂亮。由于它在 OS 独立性中支持 Python 版本的广泛支持，我们在讨论内存分析示例时将只关注`objgraph`。本节提到的其他工具也是令人兴奋的软件，但您需要自行研究它们。

#### objgraph

`objgraph`（参见[`mg.pov.lt/objgraph/`](http://mg.pov.lt/objgraph/)）是一个简单的工具，用于创建对象引用的图表，应该在查找 Python 内存泄漏时非常有用。它可以在 PyPI 上找到，但它不是一个完全独立的工具，需要 Graphviz 来创建内存使用图表。对于像 Mac OS X 或 Linux 这样的开发人员友好的系统，您可以使用您喜欢的系统包管理器轻松获取它。对于 Windows，您需要从项目页面（参见[`www.graphviz.org/`](http://www.graphviz.org/)）下载 Graphviz 安装程序并手动安装。

`objgraph` 提供了多种实用工具，允许您列出和打印有关内存使用和对象计数的各种统计信息。以下是一个使用这些实用程序的示例，显示了解释器会话的转录。

```py
>>> import objgraph
>>> objgraph.show_most_common_types()
function                   1910
dict                       1003
wrapper_descriptor         989
tuple                      837
weakref                    742
method_descriptor          683
builtin_function_or_method 666
getset_descriptor          338
set                        323
member_descriptor          305
>>> objgraph.count('list')
266
>>> objgraph.typestats(objgraph.get_leaking_objects())
{'Gt': 1, 'AugLoad': 1, 'GtE': 1, 'Pow': 1, 'tuple': 2, 'AugStore': 1, 'Store': 1, 'Or': 1, 'IsNot': 1, 'RecursionError': 1, 'Div': 1, 'LShift': 1, 'Mod': 1, 'Add': 1, 'Invert': 1, 'weakref': 1, 'Not': 1, 'Sub': 1, 'In': 1, 'NotIn': 1, 'Load': 1, 'NotEq': 1, 'BitAnd': 1, 'FloorDiv': 1, 'Is': 1, 'RShift': 1, 'MatMult': 1, 'Eq': 1, 'Lt': 1, 'dict': 341, 'list': 7, 'Param': 1, 'USub': 1, 'BitOr': 1, 'BitXor': 1, 'And': 1, 'Del': 1, 'UAdd': 1, 'Mult': 1, 'LtE': 1}

```

如前所述，`objgraph`允许您创建内存使用模式和交叉引用的图表。该库最有用的图表工具是`objgraph.show_refs()`和`objgraph.show_backrefs()`。它们都接受对被检查对象的引用，并使用 Graphviz 包将图表图像保存到文件中。这些图的示例在*图 2*和*图 3*中呈现。

以下是用于创建这些图表的代码：

```py
import objgraph

def example():
    x = []
    y = [x, [x], dict(x=x)]

    objgraph.show_refs(
        (x, y),
        filename='show_refs.png',
        refcounts=True
    )
    objgraph.show_backrefs(
        (x, y),
        filename='show_backrefs.png',
        refcounts=True
    )

if __name__ == "__main__":
    example()
```

*图 2*显示了由`x`和`y`对象持有的所有引用的图表。从上到下，从左到右，它确切地呈现了四个对象：

+   `y = [x, [x], dict(x=x)]` 列表实例

+   `dict(x=x)` 字典实例

+   `[x]` 列表实例

+   `x = []` 列表实例

![objgraph](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/B05295_11_02.jpg)

图 2 `show_refs()` 函数的示例结果

*图 3*不仅显示了`x`和`y`之间的引用，还显示了所有持有对这两个实例的引用的对象。这些被称为反向引用，对于找到阻止其他对象被释放的对象非常有帮助。

![objgraph](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/B05295_11_03.jpg)

图 3 `show_backrefs()` 函数的示例结果

为了展示`objgraph`如何在实践中使用，让我们回顾一些实际的例子。正如我们在本书中已经多次提到的，CPython 有自己的垃圾收集器，它独立于其引用计数方法存在。它不用于一般的内存管理，而仅用于解决循环引用的问题。在许多情况下，对象可能以一种使得使用简单的基于跟踪引用数量的技术无法删除它们的方式相互引用。以下是最简单的例子：

```py
x = []
y = [x]
x.append(y)
```

这种情况在*图 4*中以可视化方式呈现。在前面的情况下，即使所有对`x`和`y`对象的外部引用都将被移除（例如，通过从函数的局部范围返回），这两个对象也不能被移除，因为这两个对象仍然拥有的两个交叉引用。这是 Python 垃圾收集器介入的情况。它可以检测到对象的循环引用并在循环外没有其他有效引用时触发它们的释放。

![objgraph](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/B05295_11_04.jpg)

图 4 两个对象之间循环引用的示例图表

当这样的循环中至少有一个对象定义了自定义的`__del__()`方法时，真正的问题开始。这是一个自定义的释放处理程序，当对象的引用计数最终变为零时将被调用。它可以执行任意的 Python 代码，因此也可以创建对特色对象的新引用。这就是为什么在 Python 3.4 版本之前的垃圾收集器无法打破引用循环的原因，如果其中至少有一个对象提供了自定义的`__del__()`方法实现。PEP 442 引入了对 Python 的安全对象最终化，并成为 Python 3.4 版本开始的标准的一部分。无论如何，这对于担心向后兼容性并针对广泛的 Python 解释器版本的软件包仍可能是一个问题。以下代码片段向您展示了不同 Python 版本中循环垃圾收集器行为的差异：

```py
import gc
import platform
import objgraph

class WithDel(list):
    """ list subclass with custom __del__ implementation """
    def __del__(self):
        pass

def main():
    x = WithDel()
    y = []
    z = []

    x.append(y)
    y.append(z)
    z.append(x)

    del x, y, z

    print("unreachable prior collection: %s" % gc.collect())
    print("unreachable after collection: %s" % len(gc.garbage))
    print("WithDel objects count:        %s" %
          objgraph.count('WithDel'))

if __name__ == "__main__":
    print("Python version: %s" % platform.python_version())
    print()
    main()
```

在 Python 3.3 下执行上述代码的输出显示，旧版本的 Python 中的循环垃圾收集器无法收集定义了`__del__()`方法的对象：

```py
$ python3.3 with_del.py** 
Python version: 3.3.5

unreachable prior collection: 3
unreachable after collection: 1
WithDel objects count:        1

```

在较新版本的 Python 中，垃圾收集器可以安全地处理对象的最终化，即使它们定义了`__del__()`方法：

```py
$ python3.5 with_del.py** 
Python version: 3.5.1

unreachable prior collection: 3
unreachable after collection: 0
WithDel objects count:        0

```

尽管在最新的 Python 版本中自定义最终化不再棘手，但对于需要在不同环境下工作的应用程序仍然是一个问题。如前所述，`objgraph.show_refs()`和`objgraph.show_backrefs()`函数允许您轻松地发现有问题的类实例。例如，我们可以轻松修改`main()`函数以显示对`WithDel`实例的所有反向引用，以查看是否存在泄漏资源：

```py
def main():
    x = WithDel()
    y = []
    z = []

    x.append(y)
    y.append(z)
    z.append(x)

    del x, y, z

    print("unreachable prior collection: %s" % gc.collect())
    print("unreachable after collection: %s" % len(gc.garbage))
    print("WithDel objects count:        %s" %
          objgraph.count('WithDel'))

    objgraph.show_backrefs(
        objgraph.by_type('WithDel'),
        filename='after-gc.png'
    )
```

在 Python 3.3 下运行上述示例将导致一个图表（见*图 5*），显示`gc.collect()`无法成功移除`x`、`y`和`z`对象实例。此外，`objgraph`突出显示了所有定义了自定义`__del__()`方法的对象，以便更容易地发现此类问题。

![objgraph](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/exp-py-prog-2e/img/B05295_11_05.jpg)

图 5 显示在 Python 3.4 版本之前无法被 Python 垃圾收集器捕获的循环引用的示例图表

### C 代码内存泄漏

如果 Python 代码看起来完全正常，当您循环执行隔离的函数时内存仍然增加，那么泄漏可能发生在 C 端。例如，当缺少`Py_DECREF`调用时会发生这种情况。

Python 核心代码非常健壮，并经过泄漏测试。如果您使用具有 C 扩展的软件包，它们可能是首先要查看的地方。因为您将处理的代码比 Python 的抽象级别低得多，您需要使用完全不同的工具来解决此类内存问题。

在 C 中进行内存调试并不容易，因此在深入研究扩展内部之前，请确保正确诊断问题的根源。隔离一个可疑的包并使用类似于单元测试的代码是一个非常流行的方法：

+   为您怀疑泄漏内存的扩展的每个 API 单元或功能编写单独的测试

+   在隔离中进行测试循环（每次运行一个测试）

+   从外部观察被测试功能中哪些会随时间增加内存使用量

使用这种方法，您可以隔离扩展的故障部分，这将减少以后检查和修复其代码所需的时间。这个过程可能看起来很繁重，因为它需要大量额外的时间和编码，但从长远来看，它真的很值得。您可以通过重用一些测试工具来简化工作，这些工具在第十章中介绍，*测试驱动开发*。像 tox 这样的实用程序也许并不是专门为这种情况设计的，但它们至少可以减少在隔离环境中运行多个测试所需的时间。

希望您已经隔离了扩展中泄漏内存的部分，并最终可以开始实际调试。如果您很幸运，对源代码进行简单的手动检查可能会得到期望的结果。在许多情况下，问题就像添加丢失的`Py_DECREF`调用一样简单。然而，在大多数情况下，我们的工作并不那么简单。在这种情况下，您需要使用一些更强大的工具。在编译代码中对抗内存泄漏的一个显著通用工具是**Valgrind**，它应该是每个程序员的工具包中的一部分。它是一个用于构建动态分析工具的整个仪器框架。因此，它可能不容易学习和掌握，但您绝对应该了解基础知识。

## 分析网络使用情况

正如我之前所说，与数据库、缓存、Web 服务或 LDAP 服务器等第三方程序通信的应用程序在这些应用程序运行缓慢时可能会变慢。这可以通过应用程序端的常规代码分析方法进行跟踪。但是，如果第三方软件单独运行良好，那么问题很可能是网络。

问题可能是配置错误的中心、低带宽网络链接，甚至是大量的流量碰撞，导致计算机多次发送相同的数据包。

以下是一些要素，可以帮助您了解正在发生什么，首先需要调查三个领域：

+   使用诸如以下工具监视网络流量：

+   `ntop`：[`www.ntop.org`](http://www.ntop.org)（仅限 Linux）

+   `wireshark`：[www.wireshark.org](http://www.wireshark.org)（以前称为 Ethereal）

+   使用`net-snmp`（[`www.net-snmp.org`](http://www.net-snmp.org)）跟踪不健康或配置错误的设备。

+   使用统计工具`Pathrate`估算两台计算机之间的带宽。参见[`www.cc.gatech.edu/~dovrolis/bw-est/pathrate.html`](http://www.cc.gatech.edu/~dovrolis/bw-est/pathrate.html)。

如果您想进一步了解网络性能问题，您可能还想阅读*网络性能开源工具包*，作者 Richard Blum，*Wiley*。这本书介绍了调整大量使用网络的应用程序的策略，并提供了扫描复杂网络问题的教程。

*高性能 MySQL*，*O'Reilly Media*，作者 Jeremy Zawodny 在编写使用 MySQL 的应用程序时也是一本不错的书。

# 总结

在本章中，我们已经看到：

+   优化的三个规则：

+   先让它工作

+   以用户的角度看问题

+   保持代码可读性

+   基于编写具有速度目标的场景的优化策略

+   如何分析 CPU 或内存使用情况以及一些网络分析的技巧

现在您知道如何定位性能问题，下一章将介绍一些流行和通用的策略来摆脱这些问题。
