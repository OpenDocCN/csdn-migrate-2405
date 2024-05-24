# Python3 面向对象编程第二版（五）

> 原文：[`zh.annas-archive.org/md5/B484D481722F7AFA9E5B1ED7225BED43`](https://zh.annas-archive.org/md5/B484D481722F7AFA9E5B1ED7225BED43)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：测试面向对象的程序

技术娴熟的 Python 程序员一致认为测试是软件开发中最重要的方面之一。尽管本章放在书的末尾，但它并不是一个事后想法;到目前为止我们所学的一切都将帮助我们编写测试。我们将学习：

+   单元测试和测试驱动开发的重要性

+   标准的`unittest`模块

+   `py.test`自动化测试套件

+   `mock`模块

+   代码覆盖率

+   使用`tox`进行跨平台测试

# 为什么要测试？

许多程序员已经知道测试代码的重要性。如果你是其中之一，请随意略过本节。你会发现下一节——我们实际上如何在 Python 中进行测试——更加有趣。如果你还不相信测试的重要性，我保证你的代码是有问题的，只是你不知道而已。继续阅读!

有人认为测试在 Python 代码中更为重要，因为它的动态性;编译语言如 Java 和 C++有时被认为在某种程度上更“安全”，因为它们在编译时强制执行类型检查。然而，Python 测试很少检查类型。他们检查值。他们确保正确的属性在正确的时间设置，或者序列具有正确的长度，顺序和值。这些更高级的东西需要在任何语言中进行测试。Python 程序员比其他语言的程序员进行更多测试的真正原因是在 Python 中测试是如此容易!

但是为什么要测试？我们真的需要测试吗？如果我们不测试会怎样？要回答这些问题，请从头开始编写一个井字棋游戏，完全不进行任何测试。在完全编写完成之前不要运行它。如果让两个玩家都是人类玩家（没有人工智能），实现井字棋是相当简单的。你甚至不必尝试计算谁是赢家。现在运行你的程序。并修复所有错误。有多少错误？我在我的井字棋实现中记录了八个错误，我不确定是否都捕捉到了。你呢？

我们需要测试我们的代码以确保它能正常工作。运行程序，就像我们刚刚做的那样，并修复错误是一种粗糙的测试形式。Python 程序员可以编写几行代码并运行程序，以确保这些行正在做他们期望的事情。但是更改几行代码可能会影响开发人员没有意识到将受到更改影响的程序的部分，因此不会测试它。此外，随着程序的增长，解释器可以通过代码的各种路径也在增长，手动测试所有这些路径很快就变得不可能。

为了解决这个问题，我们编写自动化测试。这些是自动运行某些输入通过其他程序或程序部分的程序。我们可以在几秒钟内运行这些测试程序，并覆盖比一个程序员每次更改某些东西时想到的更多可能的输入情况。

编写测试的四个主要原因：

+   确保代码按照开发人员的预期工作

+   确保代码在进行更改时继续工作

+   确保开发人员理解了要求

+   确保我们正在编写的代码具有可维护的接口

第一点确实不能证明编写测试所需的时间;我们可以在交互式解释器中直接测试代码。但是，当我们必须多次执行相同的测试操作序列时，自动化这些步骤一次然后在需要时运行它们需要的时间更少。无论是在初始开发还是维护版本期间，改变代码时都要运行测试是个好主意。当我们有一套全面的自动化测试时，我们可以在代码更改后运行它们，并知道我们没有无意中破坏任何被测试的东西。

最后两点更有趣。当我们为代码编写测试时，它有助于我们设计代码所采用的 API、接口或模式。因此，如果我们误解了需求，编写测试可以帮助突出这种误解。另一方面，如果我们不确定如何设计一个类，我们可以编写一个与该类交互的测试，这样我们就知道测试它的最自然方式是什么。事实上，通常在编写我们要测试的代码之前编写测试是有益的。

## 测试驱动开发

“先写测试”是测试驱动开发的口头禅。测试驱动开发将“未经测试的代码是有问题的代码”概念推进了一步，并建议只有未编写的代码才应该未经测试。在编写代码之前不要编写任何代码，直到为该代码编写了测试。因此，第一步是编写一个证明代码可以工作的测试。显然，测试将失败，因为代码还没有被编写。然后编写确保测试通过的代码。然后为下一段代码编写另一个测试。

测试驱动开发是有趣的。它允许我们构建小的谜题来解决。然后我们实现解决谜题的代码。然后我们制作一个更复杂的谜题，编写解决新谜题的代码，而不会解决以前的谜题。

测试驱动方法论有两个目标。第一个目标是确保测试确实被编写。在编写了代码之后，很容易说：“嗯，它似乎可以工作。我不必为此编写任何测试。这只是一个小改动，不可能出错。”如果测试在编写代码之前已经编写好，我们将确切地知道它何时能够工作（因为测试将通过），并且在将来，如果我们或其他人做出的更改破坏了它，我们也会知道。

其次，首先编写测试强迫我们考虑代码将如何进行交互。它告诉我们对象需要具有哪些方法以及如何访问属性。它帮助我们将初始问题分解为更小的、可测试的问题，然后将经过测试的解决方案重新组合成更大的、同样经过测试的解决方案。编写测试因此可以成为设计过程的一部分。通常，如果我们为一个新对象编写测试，我们会发现设计中的异常，这会迫使我们考虑软件的新方面。

举个具体的例子，想象一下编写代码，使用对象关系映射器将对象属性存储在数据库中。在这种对象中使用自动分配的数据库 ID 是很常见的。我们的代码可能会为各种目的使用这个 ID。如果我们为这样的代码编写测试，在编写之前，我们可能会意识到我们的设计是有问题的，因为对象在保存到数据库之前是没有这些 ID 的。如果我们想在测试中操作一个对象而不保存它，它会在我们基于错误前提编写代码之前突出显示这个问题。

测试使软件更好。在发布软件之前编写测试可以使软件在最终用户看到或购买有错误的版本之前变得更好（我曾为奉行“用户可以测试”的理念的公司工作过。这不是一个健康的商业模式！）。在编写软件之前编写测试可以使软件第一次编写时变得更好。

# 单元测试

让我们从 Python 的内置测试库开始探索。该库提供了一个**单元测试**的通用接口。单元测试专注于在任何一个测试中测试尽可能少的代码。每个测试都测试可用代码的一个单元。

这方面的 Python 库被称为`unittest`，这并不奇怪。它提供了几个工具来创建和运行单元测试，其中最重要的是`TestCase`类。这个类提供了一组方法，允许我们比较值，设置测试，并在测试完成时进行清理。

当我们想要为特定任务编写一组单元测试时，我们创建一个`TestCase`的子类，并编写单独的方法来进行实际测试。这些方法必须都以`test`开头。遵循这个约定时，测试会自动作为测试过程的一部分运行。通常，测试会在对象上设置一些值，然后运行一个方法，并使用内置的比较方法来确保计算出了正确的结果。以下是一个非常简单的例子：

```py
import unittest

class CheckNumbers(unittest.TestCase):
    def test_int_float(self):
 **self.assertEqual(1, 1.0)

if __name__ == "__main__":
    unittest.main()
```

这段代码简单地继承了`TestCase`类，并添加了一个调用`TestCase.assertEqual`方法的方法。这个方法要么成功，要么引发异常，这取决于这两个参数是否相等。如果我们运行这段代码，`unittest`的`main`函数将给我们以下输出：

```py
.
--------------------------------------------------------------
Ran 1 test in 0.000s

OK

```

你知道浮点数和整数可以比较相等吗？让我们添加一个失败的测试：

```py
    def test_str_float(self):
        self.assertEqual(1, "1")
```

这段代码的输出更加阴险，因为整数和字符串不被视为相等：

```py
.F
============================================================
FAIL: test_str_float (__main__.CheckNumbers)
--------------------------------------------------------------
Traceback (most recent call last):
 **File "simplest_unittest.py", line 8, in test_str_float
 **self.assertEqual(1, "1")
AssertionError: 1 != '1'

--------------------------------------------------------------
Ran 2 tests in 0.001s

FAILED (failures=1)

```

第一行的点表示第一个测试（我们之前写的那个）成功通过；其后的`F`字母表示第二个测试失败。然后，在最后，它给出了一些信息性的输出，告诉我们测试失败的原因和位置，以及失败的数量总结。 

我们可以在一个`TestCase`类上有尽可能多的测试方法；只要方法名以`test`开头，测试运行器就会将每个方法作为单独的测试执行。每个测试应该完全独立于其他测试。上一个测试的结果或计算不应该对当前测试产生影响。编写良好的单元测试的关键是尽可能保持每个测试方法的长度短，每个测试用例测试代码的一个小单元。如果你的代码似乎无法自然地分解成这样可测试的单元，这可能是你的设计需要重新思考的迹象。

## 断言方法

测试用例的一般布局是将某些变量设置为已知值，运行一个或多个函数、方法或进程，然后使用`TestCase`断言方法来“证明”正确的预期结果是通过的。

有一些不同的断言方法可用于确认已经实现了特定的结果。我们刚刚看到了`assertEqual`，如果两个参数未通过相等检查，它将导致测试失败。相反，`assertNotEqual`将在两个参数比较相等时失败。`assertTrue`和`assertFalse`方法各自接受一个表达式，并在表达式未通过`if`测试时失败。这些测试不是检查布尔值`True`或`False`。相反，它们测试与使用`if`语句相同的条件：`False`、`None`、`0`或空列表、字典、字符串、集合或元组会通过调用`assertFalse`方法，而非零数、包含值的容器或值`True`在调用`assertTrue`方法时会成功。

有一个`assertRaises`方法，可以用来确保特定的函数调用引发特定的异常，或者可以作为上下文管理器来包装内联代码。如果`with`语句内的代码引发了正确的异常，测试通过；否则，测试失败。以下是两个版本的示例：

```py
import unittest

def average(seq):
    return sum(seq) / len(seq)

class TestAverage(unittest.TestCase):
    def test_zero(self):
 **self.assertRaises(ZeroDivisionError,
 **average,
 **[])

    def test_with_zero(self):
 **with self.assertRaises(ZeroDivisionError):
            average([])

if __name__ == "__main__":
    unittest.main()
```

上下文管理器允许我们以通常的方式编写代码（通过调用函数或直接执行代码），而不必在另一个函数调用中包装函数调用。

还有其他几种断言方法，总结如下表：

| 方法 | 描述 |
| --- | --- |
| `assertGreater``assertGreaterEqual``assertLess``assertLessEqual` | 接受两个可比较的对象，并确保命名的不等式成立。 |
| `assertIn``assertNotIn` | 确保元素是（或不是）容器对象中的元素。 |
| `assertIsNone``assertIsNotNone` | 确保元素是（或不是）确切的值`None`（但不是其他假值）。 |
| `assertSameElements` | 确保两个容器对象具有相同的元素，忽略顺序。 |
| `assertSequenceEqualassertDictEqual``assertSetEqual``assertListEqual``assertTupleEqual` | 确保两个容器具有相同顺序的相同元素。如果失败，显示一个代码差异，比较两个列表的差异位置。最后四种方法还测试列表的类型。 |

每个断言方法都接受一个名为`msg`的可选参数。如果提供，它将包含在错误消息中，如果断言失败。这对于澄清预期的内容或解释可能导致断言失败的错误的位置非常有用。

## 减少样板代码和清理

写了一些小测试之后，我们经常发现我们必须为几个相关的测试做相同的设置代码。例如，以下`list`子类有三种用于统计计算的方法：

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

显然，我们将要测试这三种方法中每一种具有非常相似的输入的情况；我们将要看看空列表或包含非数字值的列表或包含正常数据集的列表会发生什么。我们可以使用`TestCase`类上的`setUp`方法为每个测试进行初始化。这个方法不接受任何参数，并允许我们在每次测试运行之前进行任意设置。例如，我们可以按照以下方式测试所有三种方法在相同的整数列表上：

```py
from stats import StatsList
import unittest

class TestValidInputs(unittest.TestCase):
    **def setUp(self):
        self.stats = StatsList([1,2,2,3,3,4])

    def test_mean(self):
        self.assertEqual(self.stats.mean(), 2.5)

    def test_median(self):
        self.assertEqual(self.stats.median(), 2.5)
        self.stats.append(4)
        self.assertEqual(self.stats.median(), 3)

    def test_mode(self):
        self.assertEqual(self.stats.mode(), [2,3])
        self.stats.remove(2)
        self.assertEqual(self.stats.mode(), [3])

if __name__ == "__main__":
    unittest.main()
```

如果我们运行这个例子，它表明所有测试都通过了。首先注意到`setUp`方法从未在三个`test_*`方法内显式调用过。测试套件会代表我们执行这个操作。更重要的是注意`test_median`如何改变列表，通过向其中添加额外的`4`，然而当调用`test_mode`时，列表已经返回到`setUp`中指定的值（如果没有的话，列表中会有两个四，并且`mode`方法会返回三个值）。这表明`setUp`在每个测试之前被单独调用，以确保测试类从一个干净的状态开始。测试可以以任何顺序执行，一个测试的结果不应该依赖于任何其他测试。

除了`setUp`方法，`TestCase`还提供了一个无参数的`tearDown`方法，它可以用于在类的每个测试运行后进行清理。如果清理需要除了让对象被垃圾回收之外的其他操作，这是很有用的。例如，如果我们正在测试进行文件 I/O 的代码，我们的测试可能会创建新文件作为测试的副作用；`tearDown`方法可以删除这些文件，并确保系统处于测试运行之前的相同状态。测试用例不应该具有副作用。一般来说，我们根据它们共同的设置代码将测试方法分组到单独的`TestCase`子类中。需要相同或类似设置的几个测试将放在一个类中，而需要不相关设置的测试将放在另一个类中。

## 组织和运行测试

一个单元测试集合很快就会变得非常庞大和难以管理。一次性加载和运行所有测试很快就会变得复杂。这是单元测试的主要目标；应该很容易运行我们程序上的所有测试，并快速得到一个“是或否”的答案，回答“我的最近的更改是否破坏了任何现有的测试？”的问题。

Python 的`discover`模块基本上是在当前文件夹或子文件夹中查找以`test`开头的模块。如果在这些模块中找到任何`TestCase`对象，就会执行测试。这是一个无痛的方式来确保我们不会错过运行任何测试。要使用它，请确保你的测试模块的名称是`test_<something>.py`，然后运行命令`python3 -m unittest discover`。

## 忽略损坏的测试

有时，测试可能会失败，但我们不希望测试套件报告失败。这可能是因为一个破损或未完成的功能已经编写了测试，但我们目前并不专注于改进它。更常见的情况是，因为某个功能仅在特定平台、Python 版本或特定库的高级版本上可用。Python 为我们提供了一些装饰器，用于标记测试为预期失败或在已知条件下跳过。

装饰器是：

+   `expectedFailure()`

+   `skip(reason)`

+   `skipIf(condition, reason)`

+   `skipUnless(condition, reason)`

这些是使用 Python 装饰器语法应用的。第一个不接受任何参数，只是告诉测试运行器在失败时不记录测试为失败。`skip`方法更进一步，甚至不会运行测试。它期望一个描述为什么跳过测试的字符串参数。另外两个装饰器接受两个参数，一个是布尔表达式，指示是否应该运行测试，另一个是类似的描述。在使用时，这三个装饰器可能会像这样应用：

```py
import unittest
import sys

class SkipTests(unittest.TestCase):
 **@unittest.expectedFailure
    def test_fails(self):
        self.assertEqual(False, True)

 **@unittest.skip("Test is useless")
    def test_skip(self):
        self.assertEqual(False, True)

 **@unittest.skipIf(sys.version_info.minor == 4,
 **"broken on 3.4")
    def test_skipif(self):
        self.assertEqual(False, True)

 **@unittest.skipUnless(sys.platform.startswith('linux'),
 **"broken unless on linux")
    def test_skipunless(self):
        self.assertEqual(False, True)

if __name__ == "__main__":
    unittest.main()
```

第一个测试失败，但被报告为预期失败；第二个测试从未运行。其他两个测试可能会运行，也可能不会，这取决于当前的 Python 版本和操作系统。在我运行 Python 3.4 的 Linux 系统上，输出如下：

```py
xssF
=============================================================
FAIL: test_skipunless (__main__.SkipTests)
--------------------------------------------------------------
Traceback (most recent call last):
 **File "skipping_tests.py", line 21, in test_skipunless
 **self.assertEqual(False, True)
AssertionError: False != True

--------------------------------------------------------------
Ran 4 tests in 0.001s

FAILED (failures=1, skipped=2, expected failures=1)

```

第一行上的`x`表示预期失败；两个`s`字符代表跳过的测试，`F`表示真正的失败，因为在我的系统上，`skipUnless`的条件为`True`。

# 使用 py.test 进行测试

Python `unittest`模块需要大量样板代码来设置和初始化测试。它基于非常流行的 Java 的 JUnit 测试框架。它甚至使用相同的方法名称（您可能已经注意到它们不符合 PEP-8 命名标准，该标准建议使用下划线而不是 CamelCase 来分隔方法名称中的单词），以及测试布局。虽然这对于在 Java 中进行测试是有效的，但不一定是 Python 测试的最佳设计。

因为 Python 程序员喜欢他们的代码简洁而简单，所以在标准库之外开发了其他测试框架。其中两个较受欢迎的是`py.test`和`nose`。前者更为健壮，而且支持 Python 3 的时间更长，因此我们将在这里讨论它。

由于`py.test`不是标准库的一部分，您需要自己下载和安装它；您可以从[`pytest.org/`](http://pytest.org/)的`py.test`主页获取它。该网站提供了各种解释器和平台的全面安装说明，但通常您可以使用更常见的 Python 包安装程序 pip。只需在命令行上键入`pip install pytest`，您就可以开始使用了。

`py.test`的布局与`unittest`模块有很大不同。它不要求测试用例是类。相反，它利用了 Python 函数是对象的事实，并允许任何命名正确的函数像测试一样行为。它不是提供一堆用于断言相等的自定义方法，而是使用`assert`语句来验证结果。这使得测试更易读和易维护。当我们运行`py.test`时，它将从当前文件夹开始搜索该文件夹或子包中以`test_`开头的任何模块。如果此模块中的任何函数也以`test`开头，它们将作为单独的测试执行。此外，如果模块中有任何以`Test`开头的类，该类上以`test_`开头的任何方法也将在测试环境中执行。

让我们将我们之前编写的最简单的`unittest`示例移植到`py.test`：

```py
def test_int_float():
    assert 1 == 1.0
```

对于完全相同的测试，我们编写了两行更易读的代码，与我们第一个`unittest`示例中需要的六行相比。

但是，我们并不禁止编写基于类的测试。类可以用于将相关测试分组在一起，或者用于需要访问类上相关属性或方法的测试。这个例子展示了一个扩展类，其中有一个通过的测试和一个失败的测试；我们将看到错误输出比`unittest`模块提供的更全面：

```py
class TestNumbers:
    def test_int_float(self):
        assert 1 == 1.0

    def test_int_str(self):
        assert 1 == "1"
```

请注意，类不必扩展任何特殊对象才能被选为测试（尽管`py.test`可以很好地运行标准的`unittest TestCases`）。如果我们运行`py.test <filename>`，输出如下：

```py
============== test session starts ==============
python: platform linux2 -- Python 3.4.1 -- pytest-2.6.4
test object 1: class_pytest.py

class_pytest.py .F

=================== FAILURES====================
___________ TestNumbers.test_int_str ____________

self = <class_pytest.TestNumbers object at 0x85b4fac>

 **def test_int_str(self):
>       assert 1 == "1"
E       assert 1 == '1'

class_pytest.py:7: AssertionError
====== 1 failed, 1 passed in 0.10 seconds =======

```

输出以有关平台和解释器的一些有用信息开始。这对于在不同系统之间共享错误很有用。第三行告诉我们正在测试的文件的名称（如果有多个测试模块被选中，它们都将被显示），然后是在`unittest`模块中看到的熟悉的`.F`；`.`字符表示通过的测试，而字母`F`表示失败。

所有测试运行完毕后，将显示每个测试的错误输出。它呈现了本地变量的摘要（在本例中只有一个：传递到函数中的`self`参数），错误发生的源代码以及错误消息的摘要。此外，如果引发的异常不是`AssertionError`，`py.test`将向我们呈现完整的回溯，包括源代码引用。

默认情况下，`py.test`在测试成功时会抑制`print`语句的输出。这对于测试调试很有用；当测试失败时，我们可以向测试中添加`print`语句，以检查测试运行时特定变量和属性的值。如果测试失败，这些值将被输出以帮助诊断。然而，一旦测试成功，`print`语句的输出就不会显示，可以轻松忽略。我们不必通过删除`print`语句来“清理”输出。如果测试因未来更改而再次失败，调试输出将立即可用。

## 设置和清理的一种方法

`py.test`支持类似于`unittest`中使用的设置和清理方法，但它提供了更多的灵活性。我们将简要讨论这些，因为它们很熟悉，但它们没有像在`unittest`模块中那样被广泛使用，因为`py.test`为我们提供了强大的 funcargs 功能，我们将在下一节中讨论。

如果我们正在编写基于类的测试，我们可以使用两个名为`setup_method`和`teardown_method`的方法，基本上与`unittest`中调用`setUp`和`tearDown`的方式相同。它们在类中的每个测试方法之前和之后被调用，以执行设置和清理任务。不过，与`unittest`方法有一个区别。这两个方法都接受一个参数：表示被调用方法的函数对象。

此外，`py.test`还提供了其他设置和清理函数，以便更多地控制设置和清理代码的执行时间。`setup_class`和`teardown_class`方法预期是类方法；它们接受一个表示相关类的单个参数（没有`self`参数）。

最后，我们有`setup_module`和`teardown_module`函数，它们在该模块中的所有测试（在函数或类中）之前和之后立即运行。这些可以用于“一次性”设置，例如创建将被模块中所有测试使用的套接字或数据库连接。要小心使用这个，因为如果设置的对象存储状态，它可能会意外地引入测试之间的依赖关系。

这个简短的描述并没有很好地解释这些方法究竟在什么时候被调用，所以让我们看一个例子，确切地说明了它们何时被调用：

```py
def setup_module(module):
    print("setting up MODULE {0}".format(
        module.__name__))

def teardown_module(module):
    print("tearing down MODULE {0}".format(
        module.__name__))

def test_a_function():
    print("RUNNING TEST FUNCTION")

class BaseTest:
 **def setup_class(cls):
        print("setting up CLASS {0}".format(
            cls.__name__))

 **def teardown_class(cls):
        print("tearing down CLASS {0}\n".format(
            cls.__name__))

 **def setup_method(self, method):
        print("setting up METHOD {0}".format(
            method.__name__))

 **def teardown_method(self, method):
        print("tearing down  METHOD {0}".format(
            method.__name__))

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

`BaseTest`类的唯一目的是提取四个方法，否则这些方法将与测试类相同，并使用继承来减少重复代码的数量。因此，从`py.test`的角度来看，这两个子类不仅每个都有两个测试方法，还有两个设置和两个拆卸方法（一个在类级别，一个在方法级别）。

如果我们使用`py.test`运行这些测试，并且禁用`print`函数输出抑制（通过传递`-s`或`--capture=no`标志），它们会向我们显示各种函数在与测试本身相关的情况下被调用的时间：

```py
py.test setup_teardown.py -s
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

模块的设置和拆卸方法在会话的开始和结束时执行。然后运行单个模块级别的测试函数。接下来，执行第一个类的设置方法，然后执行该类的两个测试。这些测试分别包裹在单独的`setup_method`和`teardown_method`调用中。测试执行完毕后，调用类的拆卸方法。在第二个类之前，发生了相同的顺序，最后调用`teardown_module`方法，确切地调用一次。

## 设置变量的完全不同的方法

各种设置和拆卸函数的最常见用途之一是确保在运行每个测试方法之前，某些类或模块变量可用，并具有已知的值。

`py.test`提供了一种完全不同的方法来使用所谓的**funcargs**，即函数参数。Funcargs 基本上是预定义在测试配置文件中的命名变量。这使我们能够将配置与测试的执行分开，并允许 funcargs 在多个类和模块中使用。

要使用它们，我们向测试函数添加参数。参数的名称用于在特殊命名的函数中查找特定的参数。例如，如果我们想测试我们在演示`unittest`时使用的`StatsList`类，我们将再次想要重复测试一个有效整数列表。但是，我们可以这样编写我们的测试，而不是使用设置方法：

```py
from stats import StatsList

def pytest_funcarg__valid_stats(request):
    return StatsList([1,2,2,3,3,4])

def test_mean(valid_stats):
    assert valid_stats.mean() == 2.5

def test_median(valid_stats):
    assert valid_stats.median() == 2.5
    valid_stats.append(4)
    assert valid_stats.median() == 3

def test_mode(valid_stats):
    assert valid_stats.mode() == [2,3]
    valid_stats.remove(2)
    assert valid_stats.mode() == [3]
```

三个测试方法中的每一个都接受一个名为`valid_stats`的参数；这个参数是通过调用文件顶部定义的`pytest_funcarg__valid_stats`函数创建的。如果 funcarg 需要多个模块使用，它也可以在名为`conftest.py`的文件中定义。`conftest.py`文件由`py.test`解析，以加载任何“全局”测试配置；它是一种用于自定义`py.test`体验的捕捉所有的文件。

与其他`py.test`功能一样，返回 funcarg 的工厂的名称很重要；funcargs 是被命名为`pytest_funcarg__<identifier>`的函数，其中`<identifier>`是一个可以在测试函数中用作参数的有效变量名。这个函数接受一个神秘的`request`参数，并返回要传递给各个测试函数的对象。对于每次调用单个测试函数，都会新创建一个 funcarg；这使我们能够在一个测试中更改列表，并知道它将在下一个测试中被重置为其原始值。

Funcargs 可以做的远不止返回基本变量。传递给 funcarg 工厂的`request`对象提供了一些极其有用的方法和属性，以修改 funcarg 的行为。`module`、`cls`和`function`属性允许我们准确地看到哪个测试正在请求 funcarg。`config`属性允许我们检查命令行参数和其他配置数据。

更有趣的是，请求对象提供了一些方法，允许我们对 funcarg 进行额外的清理，或者在测试之间重用它，这些方法否则将被限制在特定范围的设置和拆卸方法中。

`request.addfinalizer`方法接受一个回调函数，在每个使用 funcarg 的测试函数之后执行清理。这提供了一个类似于拆卸方法的功能，允许我们清理文件、关闭连接、清空列表或重置队列。例如，以下代码通过创建一个临时目录`funcarg`来测试`os.mkdir`功能：

```py
import tempfile
import shutil
import os.path

def pytest_funcarg__temp_dir(request):
    dir = tempfile.mkdtemp()
    print(dir)

    def cleanup():
        shutil.rmtree(dir)
 **request.addfinalizer(cleanup)
    return dir

def test_osfiles(temp_dir):
    os.mkdir(os.path.join(temp_dir, 'a'))
    os.mkdir(os.path.join(temp_dir, 'b'))
    dir_contents = os.listdir(temp_dir)
    assert len(dir_contents) == 2
    assert 'a' in dir_contents
    assert 'b' in dir_contents
```

funcarg 为文件创建一个新的空临时目录。然后它添加一个 finalizer 调用，在测试完成后删除该目录（使用`shutil.rmtree`，递归删除目录及其中的所有内容）。文件系统的状态将保持与开始时相同。

我们可以使用`request.cached_setup`方法创建持续时间超过一个测试的函数参数变量。当设置一个昂贵的操作并且可以被多个测试重复使用时，这是非常有用的，只要资源重用不会破坏测试的原子性或单元性质（以便一个测试不依赖于先前的测试并且不受其影响）。例如，如果我们要测试以下回显服务器，我们可能只想在单独的进程中运行服务器的一个实例，然后让多个测试连接到该实例：

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

这段代码的作用只是在特定端口上监听并等待来自客户端套接字的输入。当它接收到输入时，它会将相同的值发送回去。为了测试这一点，我们可以在单独的进程中启动服务器，并将结果缓存以供多个测试使用。以下是测试代码的样子：

```py
import subprocess
import socket
import time

def pytest_funcarg__echoserver(request):
 **def setup():
 **p = subprocess.Popen(
 **['python3', 'echo_server.py'])
 **time.sleep(1)
 **return p

 **def cleanup(p):
 **p.terminate()

 **return request.cached_setup(
 **setup=setup,
 **teardown=cleanup,
 **scope="session")

def pytest_funcarg__clientsocket(request):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 1028))
    request.addfinalizer(lambda: s.close())
    return s

def test_echo(echoserver, clientsocket):
    clientsocket.send(b"abc")
    assert clientsocket.recv(3) == b'abc'

def test_echo2(echoserver, clientsocket):
    clientsocket.send(b"def")
    assert clientsocket.recv(3) == b'def'
```

我们在这里创建了两个 funcarg。第一个在单独的进程中运行回显服务器，并返回进程对象。第二个为每个测试实例化一个新的套接字对象，并在测试完成时关闭它，使用`addfinalizer`。我们目前感兴趣的是第一个 funcarg。它看起来很像传统的单元测试设置和拆卸。我们创建一个`setup`函数，不接受任何参数并返回正确的参数；在这种情况下，实际上测试忽略了进程对象，因为它们只关心服务器是否正在运行。然后，我们创建一个`cleanup`函数（函数的名称是任意的，因为它只是我们传递给另一个函数的对象），它接受一个参数：`setup`返回的参数。这个清理代码终止了进程。

父函数不直接返回 funcarg 的结果，而是返回对`request.cached_setup`调用的结果。它接受`setup`和`teardown`函数的两个参数（我们刚刚创建的），以及一个`scope`参数。这个最后一个参数应该是三个字符串之一："function"、"module"或"session"；它决定了参数的缓存时间。在这个例子中，我们将其设置为"session"，因此它在整个`py.test`运行期间都被缓存。直到所有测试运行完毕之前，进程都不会被终止或重新启动。当然，"module"作用域只在该模块中缓存它，而"function"作用域则更像一个普通的 funcarg，因为它在每个测试函数运行后都会被重置。

## 使用 py.test 跳过测试

与`unittest`模块一样，经常需要在`py.test`中跳过测试，原因有很多：被测试的代码尚未编写、测试只在某些解释器或操作系统上运行、或者测试很耗时，只应在特定情况下运行。

我们可以在代码的任何地方使用`py.test.skip`函数跳过测试。它接受一个参数：描述为什么要跳过的字符串。这个函数可以在任何地方调用；如果我们在测试函数内部调用它，测试将被跳过。如果我们在模块级别调用它，那么该模块中的所有测试都将被跳过。如果我们在 funcarg 函数内部调用它，那么调用该 funcarg 的所有测试都将被跳过。

当然，在所有这些位置，通常希望只有在满足或不满足某些条件时才跳过测试。由于我们可以在 Python 代码的任何地方执行`skip`函数，我们可以在`if`语句内执行它。因此，我们可以编写一个看起来像这样的测试：

```py
import sys
import py.test

def test_simple_skip():
    if sys.platform != "fakeos":
 **py.test.skip("Test works only on fakeOS")

    fakeos.do_something_fake()
    assert fakeos.did_not_happen
```

这实际上是一些非常愚蠢的代码。没有名为`fakeos`的 Python 平台，因此这个测试将在所有操作系统上跳过。它展示了我们如何有条件地跳过测试，由于`if`语句可以检查任何有效的条件，我们对何时跳过测试有很大的控制权。通常，我们会检查`sys.version_info`来检查 Python 解释器版本，`sys.platform`来检查操作系统，或者`some_library.__version__`来检查我们是否有足够新的给定 API 版本。

由于基于某个条件跳过单个测试方法或函数是测试跳过的最常见用法之一，`py.test`提供了一个方便的装饰器，允许我们在一行中执行此操作。该装饰器接受一个字符串，其中可以包含任何可执行的 Python 代码，该代码将求值为布尔值。例如，以下测试只会在 Python 3 或更高版本上运行：

```py
import py.test

@py.test.mark.skipif("sys.version_info <= (3,0)")
def test_python3():
    assert b"hello".decode() == "hello"
```

`py.test.mark.xfail`装饰器的行为类似，只是它标记一个测试为预期失败，类似于`unittest.expectedFailure()`。如果测试成功，它将被记录为失败；如果失败，它将被报告为预期行为。在`xfail`的情况下，条件参数是可选的；如果没有提供，测试将被标记为在所有条件下预期失败。

# 模拟昂贵的对象

有时，我们想要测试需要提供一个对象的代码，这个对象可能很昂贵或者很难构建。虽然这可能意味着您的 API 需要重新思考，以拥有一个更可测试的接口（通常意味着一个更可用的接口），但我们有时会发现自己编写的测试代码有大量样板代码来设置与被测试代码只是偶然相关的对象。

例如，假设我们有一些代码，用于在键值存储中跟踪航班状态（如`redis`或`memcache`），以便我们可以存储时间戳和最新状态。这样的基本版本代码可能如下所示：

```py
import datetime
import redis

class FlightStatusTracker:
    ALLOWED_STATUSES = {'CANCELLED', 'DELAYED', 'ON TIME'}

    def __init__(self):
        self.redis = redis.StrictRedis()

    def change_status(self, flight, status):
        status = status.upper()
        if status not in self.ALLOWED_STATUSES:
            raise ValueError(
                   "{} is not a valid status".format(status))

        key = "flightno:{}".format(flight)
        value = "{}|{}".format(
            datetime.datetime.now().isoformat(), status)
        self.redis.set(key, value)
```

在`change_status`方法中，有很多事情我们应该测试。我们应该检查如果传入了错误的状态，它是否引发了适当的错误。我们需要确保它将状态转换为大写。我们可以看到当在`redis`对象上调用`set()`方法时，键和值是否具有正确的格式。

然而，在我们的单元测试中不需要检查`redis`对象是否正确存储数据。这是绝对应该在集成或应用程序测试中进行测试的内容，但在单元测试级别，我们可以假设 py-redis 开发人员已经测试过他们的代码，并且这个方法确实符合我们的要求。通常，单元测试应该是自包含的，不依赖于外部资源的存在，比如正在运行的 Redis 实例。

相反，我们只需要测试`set()`方法被调用的次数是否正确，以及传入的参数是否正确。我们可以在测试中使用`Mock()`对象来替换有问题的方法，以便我们可以内省。以下示例说明了模拟的使用：

```py
from unittest.mock import Mock
import py.test
def pytest_funcarg__tracker():
    return FlightStatusTracker()

def test_mock_method(tracker):
 **tracker.redis.set = Mock()
    with py.test.raises(ValueError) as ex:
        tracker.change_status("AC101", "lost")
    assert ex.value.args[0] == "LOST is not a valid status"
 **assert tracker.redis.set.call_count == 0

```

这个使用`py.test`语法编写的测试断言在传入不合适的参数时会引发正确的异常。此外，它为`set`方法创建了一个模拟对象，并确保它从未被调用。如果被调用了，这意味着我们的异常处理代码中存在错误。

在这种情况下，简单地替换方法效果很好，因为被替换的对象最终被销毁了。然而，我们经常希望仅在测试期间替换函数或方法。例如，如果我们想测试模拟方法中的时间戳格式，我们需要确切地知道`datetime.datetime.now()`将返回什么。然而，这个值会随着运行而改变。我们需要一种方法将其固定到一个特定的值，以便我们可以进行可预测的测试。

还记得猴子补丁吗？临时将库函数设置为特定值是其极好的用法。模拟库提供了一个修补上下文管理器，允许我们用模拟对象替换现有库的属性。当上下文管理器退出时，原始属性会自动恢复，以免影响其他测试用例。下面是一个例子：

```py
from unittest.mock import patch
def test_patch(tracker):
    tracker.redis.set = Mock()
 **fake_now = datetime.datetime(2015, 4, 1)
 **with patch('datetime.datetime') as dt:
 **dt.now.return_value = fake_now
        tracker.change_status("AC102", "on time")
    dt.now.assert_called_once_with()
 **tracker.redis.set.assert_called_once_with(
 **"flightno:AC102",
 **"2015-04-01T00:00:00|ON TIME")

```

在这个示例中，我们首先构造了一个名为`fake_now`的值，我们将把它设置为`datetime.datetime.now`函数的返回值。我们必须在修补`datetime.datetime`之前构造这个对象，否则我们会在构造它之前调用修补的`now`函数！

`with`语句邀请修补程序用模拟对象替换`datetime.datetime`模块，并将其返回为值`dt`。模拟对象的好处是，每当您访问该对象的属性或方法时，它都会返回另一个模拟对象。因此，当我们访问`dt.now`时，它会给我们一个新的模拟对象。我们将该对象的`return_value`设置为我们的`fake_now`对象；这样，每当调用`datetime.datetime.now`函数时，它将返回我们的对象，而不是一个新的模拟对象。

然后，在使用已知值调用我们的`change_status`方法之后，我们使用模拟类的`assert_called_once_with`函数来确保`now`函数确实被调用了一次，且没有参数。然后我们再次调用它，以证明`redis.set`方法被调用时，参数的格式与我们预期的一样。

前面的例子很好地说明了编写测试如何指导我们的 API 设计。`FlightStatusTracker`对象乍一看似乎很合理；我们在对象构造时构建了一个`redis`连接，并在需要时调用它。然而，当我们为这段代码编写测试时，我们发现，即使我们在`FlightStatusTracker`上模拟了`self.redis`变量，`redis`连接仍然必须被构造。如果没有运行 Redis 服务器，这个调用实际上会失败，我们的测试也会失败。

我们可以通过在`setUp`方法中模拟`redis.StrictRedis`类来解决这个问题。然而，一个更好的想法可能是重新思考我们的示例。与其在`__init__`中构造`redis`实例，也许我们应该允许用户传入一个，就像下面的示例中一样：

```py
    def __init__(self, redis_instance=None):
        self.redis = redis_instance if redis_instance else redis.StrictRedis()
```

这使我们能够在测试时传入一个模拟对象，这样`StrictRedis`方法就不会被构造。然而，它也允许任何与`FlightStatusTracker`交互的客户端代码传入他们自己的`redis`实例。他们可能有各种各样的原因想要这样做。他们可能已经为其代码的其他部分构造了一个`redis`实例。他们可能已经创建了一个优化的`redis` API 实现。也许他们有一个将指标记录到内部监控系统的实例。通过编写单元测试，我们发现了一个使用案例，使我们的 API 从一开始就更加灵活，而不是等待客户要求支持他们的特殊需求。

这是对模拟代码奇迹的简要介绍。自 Python 3.3 以来，模拟是标准的`unittest`库的一部分，但正如你从这些例子中看到的，它们也可以与`py.test`和其他库一起使用。模拟还有其他更高级的功能，当你的代码变得更加复杂时，你可能需要利用这些功能。例如，你可以使用`spec`参数邀请模拟模仿现有的类，以便在代码尝试访问模仿类上不存在的属性时引发错误。你还可以构造模拟方法，每次调用时返回不同的参数，通过将列表作为`side_effect`参数传递。`side_effect`参数非常灵活；你还可以使用它在调用模拟时执行任意函数或引发异常。

一般来说，我们在使用模拟时应该非常节俭。如果我们发现自己在给定的单元测试中模拟了多个元素，我们可能最终测试的是模拟框架，而不是我们真正的代码。这毫无用处；毕竟，模拟已经经过了充分的测试！如果我们的代码经常这样做，这可能是我们正在测试的 API 设计不好的另一个迹象。模拟应该存在于被测试代码和它们接口的库之间的边界上。如果这种情况没有发生，我们可能需要改变 API，以便在不同的地方重新划定边界。

# 测试多少是足够的？

我们已经确定未经测试的代码是有问题的代码。但是我们如何知道我们的代码被测试得有多好？我们如何知道我们的代码有多少被测试，有多少是有问题的？第一个问题更重要，但很难回答。即使我们知道我们已经测试了应用程序中的每一行代码，我们也不知道我们是否已经适当地测试了它。例如，如果我们编写了一个统计测试，只检查当我们提供一个整数列表时会发生什么，如果用于浮点数、字符串或自定义对象的列表，它可能仍然会失败。设计完整的测试套件的责任仍然在程序员身上。

第二个问题——我们的代码有多少实际被测试——很容易验证。代码覆盖本质上是程序执行的代码行数的估计。如果我们知道这个数字和程序中的代码行数，我们就可以估计实际被测试或覆盖的代码百分比。如果我们另外有一个指示哪些行没有被测试，我们可以更容易地编写新的测试来确保这些行不会出错。

测试代码覆盖率最流行的工具叫做`coverage.py`。它可以像大多数其他第三方库一样使用`pip install coverage`命令进行安装。

我们没有空间来涵盖覆盖 API 的所有细节，所以我们只看一些典型的例子。如果我们有一个运行所有单元测试的 Python 脚本（例如，使用`unittest.main`，自定义测试运行器或`discover`），我们可以使用以下命令进行覆盖分析：

```py
coverage run coverage_unittest.py

```

这个命令将正常退出，但它会创建一个名为`.coverage`的文件，其中包含运行的数据。现在我们可以使用`coverage report`命令来获取代码覆盖的分析：

```py
>>> coverage report

```

输出如下：

```py
Name                           Stmts   Exec  Cover
--------------------------------------------------
coverage_unittest                  7      7   100%
stats                             19      6    31%
--------------------------------------------------
TOTAL                             26     13    50%

```

这个基本报告列出了被执行的文件（我们的单元测试和一个导入的模块）。还列出了每个文件中的代码行数，以及测试执行的代码行数。然后将这两个数字合并，估计代码覆盖的数量。如果我们在报告命令中传递`-m`选项，它还会额外添加一个看起来像这样的列：

```py
Missing
-----------
8-12, 15-23

```

这里列出的行范围标识了在测试运行期间未执行的`stats`模块中的行。

我们刚刚运行代码覆盖工具的示例使用了我们在本章前面创建的相同的 stats 模块。然而，它故意使用了一个失败的单一测试来测试文件中的大量代码。这是测试：

```py
from stats import StatsList
import unittest

class TestMean(unittest.TestCase):
    def test_mean(self):
        self.assertEqual(StatsList([1,2,2,3,3,4]).mean(), 2.5)

if __name__ == "__main__":

    unittest.main()
```

这段代码没有测试中位数或模式函数，这对应于覆盖输出告诉我们缺失的行号。

文本报告已经足够了，但如果我们使用命令`coverage html`，我们可以得到一个更漂亮的交互式 HTML 报告，我们可以在 Web 浏览器中查看。网页甚至会突出显示源代码中测试和未测试的行。它看起来是这样的：

![测试多少是足够的？](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_12_01.jpg)

我们也可以使用`coverage.py`模块与`py.test`一起使用。我们需要安装`py.test`的代码覆盖插件，使用`pip install pytest-coverage`。该插件为`py.test`添加了几个命令行选项，其中最有用的是`--cover-report`，可以设置为`html`、`report`或`annotate`（后者实际上修改源代码以突出显示任何未覆盖的行）。

不幸的是，如果我们可以在本章的这一部分上运行覆盖报告，我们会发现我们并没有覆盖大部分关于代码覆盖的知识！可以使用覆盖 API 来从我们自己的程序（或测试套件）中管理代码覆盖，并且`coverage.py`接受许多我们尚未涉及的配置选项。我们还没有讨论语句覆盖和分支覆盖之间的区别（后者更有用，并且是最近版本的`coverage.py`的默认值），或其他风格的代码覆盖。

请记住，虽然 100%的代码覆盖是我们应该努力追求的一个远大目标，但 100%的覆盖是不够的！仅仅因为一个语句被测试了，并不意味着它对所有可能的输入都进行了适当的测试。

# 案例研究

让我们通过编写一个小型的、经过测试的密码应用程序来走一遍测试驱动开发。不用担心，你不需要理解复杂的现代加密算法（如 Threefish 或 RSA）背后的数学原理。相反，我们将实现一个被称为维吉尼亚密码的十六世纪算法。该应用程序只需要能够使用这个密码对消息进行编码和解码，给定一个编码关键字。

首先，我们需要了解如果我们手动应用密码，它是如何工作的（没有计算机）。我们从这样的表开始：

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

给定一个关键字 TRAIN，我们可以这样编码消息 ENCODED IN PYTHON：

1.  重复关键字和消息在一起，以便从一个到另一个映射字母变得容易：

```py
E N C O D E D I N P Y T H O N    T R A I N T R A I N T R A I N
```

1.  对于明文中的每个字母，找到以该字母开头的行在表中的位置。

1.  找到与所选明文字母的关键字字母相关联的列。

1.  编码字符位于这一行和列的交点处。

例如，以 E 开头的行与以 T 开头的列相交于字符 X。因此，密文的第一个字母是 X。以 N 开头的行与以 R 开头的列相交于字符 E，导致密文 XE。C 与 A 相交于 C，O 与 I 相交于 W。D 和 N 映射到 Q，而 E 和 T 映射到 X。完整的编码消息是 XECWQXUIVCRKHWA。

解码基本上遵循相反的过程。首先，找到具有共享关键字的字符（T 行），然后找到该行中编码字符（X）的位置。明文字符位于该行的列顶部（E）。

## 实施它

我们的程序将需要一个`encode`方法，它接受关键字和明文并返回密文，以及一个`decode`方法，它接受关键字和密文并返回原始消息。

但是，我们不仅仅是编写这些方法，让我们遵循测试驱动的开发策略。我们将使用`py.test`进行单元测试。我们需要一个`encode`方法，我们知道它该做什么；让我们先为该方法编写一个测试：

```py
def test_encode():
    cipher = VigenereCipher("TRAIN")
    encoded = cipher.encode("ENCODEDINPYTHON")
    assert encoded == "XECWQXUIVCRKHWA"
```

这个测试自然会失败，因为我们没有在任何地方导入`VigenereCipher`类。让我们创建一个新模块来保存该类。

让我们从以下`VigenereCipher`类开始：

```py
class VigenereCipher:
    def __init__(self, keyword):
        self.keyword = keyword

    def encode(self, plaintext):
 **return "XECWQXUIVCRKHWA"

```

如果我们在我们的测试类顶部添加一行`from vigenere_cipher import VigenereCipher`并运行`py.test`，前面的测试将通过！我们完成了我们的第一个测试驱动开发周期。

显然，返回一个硬编码的字符串并不是密码类的最明智的实现，所以让我们添加第二个测试：

```py
def test_encode_character():
    cipher = VigenereCipher("TRAIN")
    encoded = cipher.encode("E")
    assert encoded == "X"
```

啊，现在那个测试会失败。看来我们要更加努力了。但我突然想到了一件事：如果有人尝试对一个带有空格或小写字符的字符串进行编码会怎么样？在我们开始实现编码之前，让我们为这些情况添加一些测试，这样我们就不会忘记它们。预期的行为将是去除空格，并将小写字母转换为大写：

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

如果我们运行新的测试套件，我们会发现新的测试通过了（它们期望相同的硬编码字符串）。但是如果我们忘记考虑这些情况，它们以后应该会失败。

现在我们有了一些测试用例，让我们考虑如何实现我们的编码算法。编写代码使用像我们在早期手动算法中使用的表是可能的，但考虑到每一行只是一个按偏移字符旋转的字母表，这似乎很复杂。事实证明（我问了维基百科），我们可以使用模算术来组合字符，而不是进行表查找。给定明文和关键词字符，如果我们将两个字母转换为它们的数值（A 为 0，Z 为 25），将它们相加，并取余数模 26，我们就得到了密文字符！这是一个简单的计算，但由于它是逐个字符进行的，我们可能应该将它放在自己的函数中。在这之前，我们应该为新函数编写一个测试：

```py
from vigenere_cipher import combine_character
def test_combine_character():
    assert combine_character("E", "T") == "X"
    assert combine_character("N", "R") == "E"
```

现在我们可以编写代码使这个函数工作。老实说，我在完全正确之前不得不运行测试几次；首先我返回了一个整数，然后我忘记了将字符从零基础的比例转回到正常的 ASCII 比例。有了测试可用，很容易测试和调试这些错误。这是测试驱动开发的另一个好处。

```py
def combine_character(plain, keyword):
    plain = plain.upper()
    keyword = keyword.upper()
    plain_num = ord(plain) - ord('A')
    keyword_num = ord(keyword) - ord('A')
    return chr(ord('A') + (plain_num + keyword_num) % 26)
```

现在`combine_characters`已经经过测试，我以为我们已经准备好实现我们的`encode`函数了。然而，在该函数内部我们首先需要一个与明文一样长的关键词字符串的重复版本。让我们先实现一个函数。哎呀，我是说让我们先实现测试！

```py
def test_extend_keyword():
    cipher = VigenereCipher("TRAIN")
    extended = cipher.extend_keyword(16)
    assert extended == "TRAINTRAINTRAINT"
```

在编写这个测试之前，我期望将`extend_keyword`作为一个独立的函数，接受一个关键词和一个整数。但是当我开始起草测试时，我意识到将其作为`VigenereCipher`类的辅助方法更合理。这显示了测试驱动开发如何帮助设计更合理的 API。这是方法的实现：

```py
    def extend_keyword(self, number):
        repeats = number // len(self.keyword) + 1
        return (self.keyword * repeats)[:number]
```

再次，这需要几次测试才能做对。最后我添加了第二个版本的测试，一个有十五个字母，一个有十六个字母，以确保它在整数除法有偶数的情况下也能正常工作。

现在我们终于准备好编写我们的`encode`方法了：

```py
    def encode(self, plaintext):
        cipher = []
        keyword = self.extend_keyword(len(plaintext))
        for p,k in zip(plaintext, keyword):
            cipher.append(combine_character(p,k))
        return "".join(cipher)
```

看起来正确。我们的测试套件现在应该通过了，对吗？

实际上，如果我们运行它，我们会发现仍然有两个测试失败。我们完全忘记了空格和小写字符！我们写了这些测试来提醒我们是一件好事。我们将不得不在方法的开头添加这一行：

```py
        plaintext = plaintext.replace(" ", "").upper()
```

### 提示

如果我们在实现某事的过程中对一个特殊情况有了想法，我们可以创建一个描述这个想法的测试。我们甚至不需要实现这个测试；我们可以运行`assert False`来提醒我们以后再实现它。失败的测试永远不会让我们忘记这个特殊情况，它不能被忽视，就像提交任务一样。如果修复实现需要一段时间，我们可以将测试标记为预期失败。

现在所有的测试都成功通过了。这一章非常长，所以我们将压缩解码的示例。以下是一些测试：

```py
def test_separate_character():
    assert separate_character("X", "T") == "E"
    assert separate_character("E", "R") == "N"

def test_decode():
    cipher = VigenereCipher("TRAIN")
    decoded = cipher.decode("XECWQXUIVCRKHWA")
    assert decoded == "ENCODEDINPYTHON"
```

这是`separate_character`函数：

```py
def separate_character(cypher, keyword):
    cypher = cypher.upper()
    keyword = keyword.upper()
    cypher_num = ord(cypher) - ord('A')
    keyword_num = ord(keyword) - ord('A')
    return chr(ord('A') + (cypher_num - keyword_num) % 26)
```

还有`decode`方法：

```py
    def decode(self, ciphertext):
        plain = []
        keyword = self.extend_keyword(len(ciphertext))
        for p,k in zip(ciphertext, keyword):
            plain.append(separate_character(p,k))
        return "".join(plain)
```

这些方法与编码时使用的方法非常相似。有了所有这些编写并通过的测试，我们现在可以回过头修改我们的代码，知道它仍然安全地通过了测试。例如，如果我们用这些重构后的方法替换我们现有的`encode`和`decode`方法，我们的测试仍然通过：

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

这是测试驱动开发的最终好处，也是最重要的。一旦测试编写完成，我们可以尽情改进我们的代码，而且可以确信我们的更改没有破坏我们一直在测试的任何东西。此外，我们知道我们的重构何时完成：当所有测试都通过时。

当然，我们的测试可能并不全面测试我们需要的一切；维护或代码重构仍然可能导致未经诊断的错误，这些错误在测试中不会显示出来。自动化测试并不是绝对可靠的。然而，如果出现错误，仍然可以遵循测试驱动的计划；第一步是编写一个测试（或多个测试），复制或“证明”所讨论的错误正在发生。这当然会失败。然后编写代码使测试停止失败。如果测试全面，错误将被修复，我们将知道它是否再次发生，一旦我们运行测试套件。

最后，我们可以尝试确定我们的测试在这段代码上的运行情况。安装了`py.test`覆盖插件后，`py.test –coverage-report=report`告诉我们我们的测试套件覆盖了 100%的代码。这是一个很好的统计数据，但我们不应该对此过于自负。当编码带有数字的消息时，我们的代码还没有经过测试，因此其行为是未定义的。

# 练习

练习测试驱动开发。这是你的第一个练习。如果你开始一个新项目，这样做会更容易，但如果你有现有的代码需要处理，你可以开始为你实现的每个新功能编写测试。随着你对自动化测试的热爱增加，这可能会变得令人沮丧。未经测试的旧代码将开始感觉僵化和紧密耦合，并且维护起来会变得不舒服；你会开始感觉到你所做的更改正在破坏代码，而你却无法知道，因为没有测试。但是如果你从小处开始，添加测试将改善，随着时间的推移，代码库会得到改善。

因此，要开始尝试测试驱动开发，可以开始一个新项目。一旦你开始意识到写测试的好处（你会的），并意识到写测试所花费的时间很快就能通过更易于维护的代码得到回报，你就会想要开始为现有代码编写测试。这就是你应该开始做的时候，而不是之前。为我们“知道”有效的代码编写测试是无聊的。在意识到我们认为有效的代码实际上有多糟糕之前，很难对项目产生兴趣。

尝试使用内置的`unittest`模块和`py.test`编写相同的一组测试。你更喜欢哪个？`unittest`更类似于其他语言中的测试框架，而`py.test`可以说更符合 Python 的风格。两者都允许我们编写面向对象的测试，并轻松测试面向对象的程序。

在我们的案例研究中，我们使用了`py.test`，但我们没有涉及任何使用`unittest`不容易进行测试的功能。尝试调整测试以使用测试跳过或 funcargs。尝试各种设置和拆卸方法，并将它们与 funcargs 进行比较。哪种对你来说更自然？

在我们的案例研究中，我们有很多使用类似`VigenereCipher`对象的测试；尝试重新设计这段代码以使用 funcarg。这样能节省多少行代码？

尝试对你编写的测试运行覆盖率报告。你有没有漏掉测试任何代码行？即使你有 100%的覆盖率，你是否测试了所有可能的输入？如果你在进行测试驱动开发，100%的覆盖率应该自然而然地遵循，因为你会在满足该测试的代码之前编写测试。然而，如果为现有代码编写测试，很可能会有未经测试的边缘情况。

仔细考虑一下某种程度上不同的值：当你期望完整的列表时却得到空列表，与中间整数相比的零或一或无穷大，不能精确到小数位的浮点数，当你期望数字时得到字符串，或者当你期望有意义的东西时得到无处不在的`None`值。如果你的测试涵盖了这些边缘情况，你的代码将会很好。

# 总结

我们终于涵盖了 Python 编程中最重要的主题：自动化测试。测试驱动开发被认为是最佳实践。标准库`unittest`模块提供了一个很好的开箱即用的测试解决方案，而`py.test`框架具有一些更 Pythonic 的语法。模拟可以用于在我们的测试中模拟复杂的类。代码覆盖率给出了我们的代码有多少被我们的测试运行的估计，但它并不告诉我们我们已经测试了正确的东西。

在下一章中，我们将进入一个完全不同的主题：并发。


# 第十三章：并发

并发是让计算机同时做（或看起来同时做）多件事情的艺术。在历史上，这意味着处理器每秒钟要在不同的任务之间切换多次。在现代系统中，它也可以字面意思上同时在不同的处理器核心上执行两个或更多的任务。

并发本质上不是一个面向对象的主题，但 Python 的并发系统是建立在我们在整本书中介绍的面向对象构造之上的。本章将向您介绍以下主题：

+   线程

+   多处理

+   未来

+   异步 IO

并发是复杂的。基本概念相当简单，但可能发生的错误却极其难以追踪。然而，对于许多项目来说，并发是获得所需性能的唯一途径。想象一下，如果一个 Web 服务器在前一个请求完成之前无法响应用户的请求！我们不会详细讨论它有多难（需要另一本完整的书），但我们将看到如何在 Python 中进行基本的并发，以及一些常见的要避免的陷阱。

# 线程

最常见的情况是，通过并发可以让程序在等待 I/O 时继续进行工作。例如，服务器可以在等待前一个请求的数据到达时开始处理新的网络请求。交互式程序可能在等待用户按键时渲染动画或进行计算。请记住，尽管一个人每分钟可以输入超过 500 个字符，但计算机每秒可以执行数十亿条指令。因此，即使输入速度很快，也可以在按键之间进行大量处理。

在理论上，可能会在程序内部管理所有这些活动之间的切换，但要正确地做到这一点几乎是不可能的。相反，我们可以依赖 Python 和操作系统来处理棘手的切换部分，同时创建看起来是独立运行但同时运行的对象。这些对象称为**线程**；在 Python 中，它们有一个非常简单的 API。让我们看一个基本的例子：

```py
from threading import Thread

class InputReader(Thread):
    def run(self):
        self.line_of_text = input()

print("Enter some text and press enter: ")
thread = InputReader()
thread.start()

count = result = 1
while thread.is_alive():
    result = count * count
    count += 1

print("calculated squares up to {0} * {0} = {1}".format(
    count, result))
print("while you typed '{}'".format(thread.line_of_text))
```

这个例子运行了两个线程。你能看到它们吗？每个程序都有一个线程，称为主线程。从一开始执行的代码都是在这个线程中进行的。第二个线程更明显，存在于`InputReader`类中。

要构建一个线程，我们必须扩展`Thread`类并实现`run`方法。`run`方法内的任何代码（或在该方法内调用的代码）都将在一个单独的线程中执行。

新线程直到我们在对象上调用`start()`方法时才开始运行。在这种情况下，线程立即暂停等待键盘输入。与此同时，原始线程继续执行`start`被调用的地方。它在`while`循环内开始计算平方。`while`循环中的条件检查`InputReader`线程是否已经退出了它的`run`方法；一旦它退出，就会向屏幕输出一些摘要信息。

如果我们运行示例并输入字符串"hello world"，输出如下：

```py
Enter some text and press enter:
hello world
calculated squares up to 1044477 * 1044477 = 1090930114576
while you typed 'hello world'

```

当然，当我们输入字符串时，计算的平方数会更多或更少，这些数字与我们相对打字速度以及我们运行的计算机的处理器速度有关。

只有当我们调用`start`方法时，线程才以并发模式开始运行。如果我们想要去掉并发调用以查看它的比较，我们可以在原来调用`thread.start()`的地方调用`thread.run()`。输出如下：

```py
Enter some text and press enter:
hello world
calculated squares up to 1 * 1 = 1
while you typed 'hello world'

```

在这种情况下，线程永远不会变得活跃，`while`循环也永远不会执行。在我们输入时，浪费了大量的 CPU 资源。

使用线程有效的方法有很多不同的模式。我们不会覆盖所有这些模式，但我们将看一个常见的模式，以便学习`join`方法。让我们检查加拿大每个省的首府城市的当前温度：

```py
from threading import Thread
import json
from urllib.request import urlopen
import time

CITIES = [
    'Edmonton', 'Victoria', 'Winnipeg', 'Fredericton',
    "St. John's", 'Halifax', 'Toronto', 'Charlottetown',
    'Quebec City', 'Regina'
]

class TempGetter(Thread):
 **def __init__(self, city):
 **super().__init__()
 **self.city = city

    def run(self):
        url_template = (
            'http://api.openweathermap.org/data/2.5/'
            'weather?q={},CA&units=metric')
        response = urlopen(url_template.format(self.city))
        data = json.loads(response.read().decode())
        self.temperature = data['main']['temp']

threads = [TempGetter(c) for c in CITIES]
start = time.time()
for thread in threads:
    thread.start()

for thread in threads:
 **thread.join()

for thread in threads:
    print(
        "it is {0.temperature:.0f}°C in {0.city}".format(thread))
print(
    "Got {} temps in {} seconds".format(
    len(threads), time.time() - start))
```

这段代码在启动线程之前构造了 10 个线程。注意我们如何覆盖构造函数以将它们传递到`Thread`对象中，记得调用`super`以确保`Thread`被正确初始化。请注意：新线程还没有运行，因此`__init__`方法仍然是从主线程内部执行的。我们在一个线程中构造的数据可以从其他运行的线程中访问。

在启动了 10 个线程之后，我们再次循环遍历它们，对每个线程调用`join()`方法。这个方法基本上是说“在做任何事情之前等待线程完成”。我们按顺序调用这个方法十次；在所有十个线程完成之前，for 循环不会退出。

此时，我们可以打印存储在每个线程对象上的温度。再次注意，我们可以从主线程访问在线程内部构造的数据。在线程中，默认情况下所有状态都是共享的。

在我的 100 兆比特连接上执行这段代码大约需要 0.2 秒：

```py
it is 5°C in Edmonton
it is 11°C in Victoria
it is 0°C in Winnipeg
it is -10°C in Fredericton
it is -12°C in St. John's
it is -8°C in Halifax
it is -6°C in Toronto
it is -13°C in Charlottetown
it is -12°C in Quebec City
it is 2°C in Regina
 **Got 10 temps in 0.18970298767089844 seconds

```

如果我们在单个线程中运行此代码（通过将`start()`调用更改为`run()`并注释掉`join()`调用），那么它需要接近 2 秒，因为每个 0.2 秒的请求必须在下一个请求开始之前完成。这种 10 倍的加速显示了并发编程有多么有用。

## 线程的许多问题

线程可以是有用的，特别是在其他编程语言中，但现代 Python 程序员倾向于避免它们，原因有几个。正如我们将看到的，有其他方法可以进行并发编程，这些方法正在得到 Python 开发人员的更多关注。在继续讨论更重要的话题之前，让我们先讨论一些这些陷阱。

### 共享内存

线程的主要问题也是它们的主要优势。线程可以访问程序中的所有内存和变量。这很容易导致程序状态的不一致。你是否遇到过一个房间里有一个灯有两个开关，两个不同的人同时打开它们的情况？每个人（线程）都希望他们的动作打开灯（一个变量），但结果值（灯是关闭的）与这些期望是不一致的。现在想象一下，如果这两个线程正在银行账户之间转账或管理车辆的巡航控制。

在多线程编程中解决这个问题的方法是“同步”访问任何读取或写入共享变量的代码。有几种不同的方法可以做到这一点，但我们不会在这里讨论它们，这样我们就可以专注于更具 Python 风格的构造。同步解决方案有效，但很容易忘记应用它。更糟糕的是，由于不适当使用同步而导致的错误很难追踪，因为线程执行操作的顺序是不一致的。我们无法轻松地重现错误。通常，最安全的做法是强制线程之间的通信使用已经适当使用锁的轻量级数据结构。Python 提供了`queue.Queue`类来实现这一点；它的功能基本上与我们将在下一节讨论的`multiprocessing.Queue`相同。

在某些情况下，这些缺点可能被允许共享内存的一个优点所抵消：它很快。如果多个线程需要访问一个巨大的数据结构，共享内存可以快速提供访问。然而，这个优点通常被 Python 中的一个事实所抵消，即在不同 CPU 核心上运行的两个线程不可能在完全相同的时间进行计算。这就带我们来到了线程的第二个问题。

### 全局解释器锁

为了有效地管理内存、垃圾回收和对库中机器代码的调用，Python 有一个叫做**全局解释器锁**或**GIL**的实用程序。它是不可能关闭的，这意味着在 Python 中，线程对于其他语言中它们擅长的一件事情：并行处理是无用的。对于我们的目的来说，GIL 的主要影响是防止任何两个线程在完全相同的时间做工作，即使它们有工作要做。在这种情况下，“做工作”意味着使用 CPU，因此多个线程访问磁盘或网络是完全可以的；一旦线程开始等待某些东西，GIL 就会被释放。

GIL 受到了相当大的诋毁，主要是因为一些人不理解它是什么，或者它给 Python 带来的所有好处。如果我们的语言没有这个限制，那肯定会很好，但 Python 参考开发人员已经确定，至少目前来说，它带来的价值比成本更高。它使参考实现更容易维护和开发，在 Python 最初开发时是单核处理器的时代，它实际上使解释器更快。然而，GIL 的最终结果是它限制了线程给我们带来的好处，而没有减轻成本。

### 注意

虽然 GIL 是大多数人使用的 Python 参考实现中的一个问题，但在一些非标准实现中（如 IronPython 和 Jython）已经解决了这个问题。不幸的是，在出版时，这些都不支持 Python 3。

## 线程开销

与我们将在后面讨论的异步系统相比，线程的最后一个限制是维护线程的成本。每个线程占用一定量的内存（在 Python 进程和操作系统内核中），以记录该线程的状态。在线程之间切换也会使用（少量的）CPU 时间。这项工作是无缝进行的，无需额外编码（我们只需要调用`start()`，剩下的就会被处理），但这项工作仍然需要在某个地方进行。

通过构造我们的工作负载，使得线程可以被重用来执行多个任务，这可以在一定程度上缓解。Python 提供了一个`ThreadPool`功能来处理这个问题。它作为多进程库的一部分提供，并且与我们将在下一节讨论的`ProcessPool`行为相同，因此让我们推迟讨论到下一节。

# 多进程

多进程 API 最初设计是为了模仿线程 API。然而，它已经发展，并且在最近的 Python 3 版本中，它更加稳健地支持更多功能。多进程库是为了在需要并行进行 CPU 密集型作业并且有多个核心可用时设计的（鉴于四核的树莓派目前可以以 35 美元的价格购买，通常有多个核心可用）。多进程在进程大部分时间花在 I/O 等待上时并不有用（例如网络、磁盘、数据库或键盘），但对于并行计算来说是最佳选择。

多进程模块会启动新的操作系统进程来执行工作。在 Windows 机器上，这是一个相对昂贵的操作；在 Linux 上，进程和线程一样是在内核中实现的，因此开销仅限于在每个进程中运行单独的 Python 解释器的成本。

让我们尝试使用类似于`threading` API 提供的构造来并行化一个计算密集型操作：

```py
from multiprocessing import Process, cpu_count
import time
import os

class MuchCPU(Process):
    def run(self):
 **print(os.getpid())
        for i in range(200000000):
            pass

if __name__ == '__main__':
 **procs =  [MuchCPU() for f in range(cpu_count())]
    t = time.time()
    for p in procs:
 **p.start()
    for p in procs:
 **p.join()
    print('work took {} seconds'.format(time.time() - t))
```

这个例子只是让 CPU 进行 2 亿次迭代。你可能不认为这是有用的工作，但是在寒冷的天气下，我很感激我的笔记本在这样的负载下产生的热量。

API 应该是熟悉的；我们实现`Process`的子类（而不是`Thread`）并实现一个`run`方法。这个方法在做一些密集的（如果是误导的）工作之前打印出进程 ID（操作系统为机器上的每个进程分配的唯一编号）。

特别注意`if __name__ == '__main__':`的保护，它围绕在模块级别的代码周围，防止其在被导入时运行，而不是作为程序运行。这在一般情况下是一个好的做法，但在某些操作系统上使用多进程时，这是必不可少的。在幕后，多进程可能必须在新进程中导入模块以执行`run()`方法。如果我们允许整个模块在那一点上执行，它将开始递归地创建新进程，直到操作系统耗尽资源。

我们为机器上的每个处理器核心构建一个进程，然后启动和加入每个进程。在我 2014 年的四核笔记本上，输出如下：

```py
6987
6988
6989
6990
work took 12.96659541130066 seconds

```

前四行是在每个`MuchCPU`实例内打印的进程 ID。最后一行显示，2 亿次迭代在我的机器上大约需要 13 秒。在这 13 秒内，我的进程监视器显示我的四个核心都在以 100%的速度运行。

如果我们在`MuchCPU`中使用`threading.Thread`而不是`multiprocessing.Process`进行子类化，输出如下：

```py
7235
7235
7235
7235
work took 28.577413082122803 seconds

```

这一次，四个线程在同一个进程内运行，需要的时间接近三倍。这是全局解释器锁的成本；在其他语言或 Python 的其他实现中，线程版本的运行速度至少与多进程版本一样快。我们可能期望它需要四倍的时间，但请记住，我的笔记本上还有许多其他程序在运行。在多进程版本中，这些程序也需要使用四个 CPU 的一部分。在线程版本中，这些程序可以使用其他三个 CPU。

## 多进程池

一般来说，没有理由在计算机上有更多的进程数。这样做有几个原因：

+   只有`cpu_count()`个进程可以同时运行

+   每个进程都会消耗资源，拥有完整的 Python 解释器的副本

+   进程之间的通信是昂贵的

+   创建进程需要一定的时间

考虑到这些限制，当程序启动时，最多创建`cpu_count()`个进程，然后让它们根据需要执行任务是有意义的。实现一个基本的通信进程系列并不难，但调试、测试和正确执行可能会有些棘手。当然，由于 Python 是 Python，我们不必做所有这些工作，因为 Python 开发人员已经在多进程池的形式中为我们做了这些工作。

池的主要优势在于它们抽象了在主进程中执行的代码和在子进程中执行的代码的开销。与模仿多线程 API 的多进程一样，很难记住谁在执行什么。池的抽象限制了不同进程中的代码相互交互的位置数量，使得跟踪变得更加容易。

+   池还可以无缝隐藏进程之间传递数据的过程。使用池看起来很像一个函数调用；你将数据传递给一个函数，它在另一个进程或进程中执行，当工作完成时，会返回一个值。重要的是要理解，在幕后，有很多工作在支持这一点：一个进程中的对象被序列化并传递到管道中。

+   另一个进程从管道中检索数据并对其进行反序列化。工作在子进程中完成并产生结果。结果被序列化并传入管道。最终，原始进程对其进行反序列化并返回。

所有这些序列化和将数据传递到管道都需要时间和内存。因此，最好将传入和返回池的数据量和大小保持在最小限度，并且只有在需要对所讨论的数据进行大量处理时才有利于使用池。

拥有这些知识后，使所有这些机制工作的代码出人意料地简单。让我们来看看计算一系列随机数的所有质因数的问题。这是各种加密算法（更不用说对这些算法的攻击！）中常见且昂贵的部分。破解用于保护您的银行账户的极大数字需要多年的处理能力。以下的实现虽然可读，但并不高效，但这没关系，因为我们想看到它使用大量的 CPU 时间：

```py
import random
from multiprocessing.pool import Pool

def prime_factor(value):
    factors = []
    for divisor in range(2, value-1):
        quotient, remainder = divmod(value, divisor)
        if not remainder:
            factors.extend(prime_factor(divisor))
            factors.extend(prime_factor(quotient))
            break
    else:
        factors = [value]
    return factors

if __name__ == '__main__':
 **pool = Pool()

    to_factor = [
        random.randint(100000, 50000000) for i in range(20)
    ]
 **results = pool.map(prime_factor, to_factor)
 **for value, factors in zip(to_factor, results):
        print("The factors of {} are {}".format(value, factors))
```

让我们把注意力集中在并行处理方面，因为用于计算因子的蛮力递归算法非常清晰。我们首先构建一个多进程池实例。默认情况下，该池为其运行的机器上的每个 CPU 核心创建一个单独的进程。

`map`方法接受一个函数和一个可迭代对象。池对可迭代对象中的每个值进行 pickling，并将其传递给一个可用的进程，该进程对其执行函数。当该进程完成其工作时，它对结果因子的列表进行 pickling，并将其传递回池。一旦所有的池都完成了处理工作（这可能需要一些时间），结果列表就会传递回原始进程，该进程一直在耐心地等待所有这些工作的完成。

通常更有用的是使用类似的`map_async`方法，即使进程仍在工作，它也会立即返回。在这种情况下，结果变量不会是一个值的列表，而是通过调用`results.get()`来返回一个值的列表的承诺。这个承诺对象还有`ready()`和`wait()`等方法，允许我们检查是否所有的结果都已经出来了。

或者，如果我们事先不知道要获取结果的所有值，我们可以使用`apply_async`方法来排队一个单独的作业。如果池中有一个尚未工作的进程，它将立即启动；否则，它将保留任务，直到有一个可用的进程。

池也可以被`close`，拒绝接受任何进一步的任务，但处理当前队列中的所有任务；或者被`terminate`，进一步拒绝启动队列中仍在进行的任何作业，尽管当前正在运行的作业仍被允许完成。

## 队列

如果我们需要更多控制进程之间的通信，我们可以使用`Queue`。`Queue`数据结构对于将消息从一个进程发送到一个或多个其他进程非常有用。任何可被 picklable 的对象都可以被发送到`Queue`中，但要记住 pickling 可能是一个昂贵的操作，所以要保持这些对象小。为了说明队列，让我们构建一个存储所有相关条目的文本内容的小型搜索引擎。

这不是构建基于文本的搜索引擎的最明智的方法，但我已经使用这种模式来查询需要使用 CPU 密集型进程来构建然后呈现给用户的图表的数值数据。

这个特定的搜索引擎并行扫描当前目录中的所有文件。为 CPU 上的每个核心构建一个进程。每个进程都被指示将一些文件加载到内存中。让我们来看看执行加载和搜索的函数：

```py
def search(paths, query_q, results_q):
    lines = []
    for path in paths:
        lines.extend(l.strip() for l in path.open())

 **query = query_q.get()
    while query:
 **results_q.put([l for l in lines if query in l])
 **query = query_q.get()

```

请记住，这个函数是在一个不同的进程中运行的（实际上，它是在`cpucount()`个不同的进程中运行的），而不是在主线程中。它传递了一个`path.path`对象的列表和两个`multiprocessing.Queue`对象；一个用于传入查询，一个用于发送输出结果。这些队列具有与我们在第六章中讨论的`Queue`类类似的接口，*Python 数据结构*。但是，它们正在额外工作，对队列中的数据进行 pickling，并通过管道传递到子进程中。这两个队列在主进程中设置，并通过管道传递到子进程中的搜索函数。

搜索代码在效率和功能方面都相当愚蠢；它循环遍历存储在内存中的每一行，并将匹配的行放入列表中。然后将列表放入队列并传回主进程。

让我们来看看设置这些队列的主要进程：

```py
if __name__ == '__main__':
    from multiprocessing import Process, Queue, cpu_count
    from path import path
    cpus = cpu_count()
    pathnames = [f for f in path('.').listdir() if f.isfile()]
    paths = [pathnames[i::cpus] for i in range(cpus)]
 **query_queues = [Queue() for p in range(cpus)]
 **results_queue = Queue()

 **search_procs = [
 **Process(target=search, args=(p, q, results_queue))
 **for p, q in zip(paths, query_queues)
 **]
    for proc in search_procs: proc.start()
```

为了更容易描述，让我们假设`cpu_count`是四。注意导入语句是如何放置在`if`保护内的？这是一个小优化，可以防止它们在某些操作系统上被导入到每个子进程中（在那里它们是不需要的）。我们列出当前目录中的所有路径，然后将列表分成大约相等的四部分。我们还构建了一个包含四个`Queue`对象的列表，以便将数据发送到每个子进程中。最后，我们构建了一个`single`结果队列；这个队列传递给了所有四个子进程。它们每个都可以将数据放入队列中，并且在主进程中进行聚合。

现在让我们来看看实际进行搜索的代码：

```py
    for q in query_queues:
 **q.put("def")
 **q.put(None)  # Signal process termination

    for i in range(cpus):
 **for match in results_queue.get():
            print(match)
    for proc in search_procs: proc.join()
```

这段代码执行了一次对`"def"`进行搜索（因为这是一个充满 Python 文件的目录中的常见短语！）。在一个更适合生产的系统中，我们可能会将一个套接字连接到这个搜索代码。在这种情况下，我们必须改变进程间协议，以便返回队列上的消息包含足够的信息来识别结果附加到哪个查询中的许多查询之一。

这种使用队列的方式实际上是一个可能成为分布式系统的本地版本。想象一下，如果搜索被发送到多台计算机然后重新组合。我们不会在这里讨论，但多进程模块包括一个管理器类，可以消除前面代码中的大量样板。甚至有一个`multiprocessing.Manager`的版本，可以管理远程系统上的子进程，构建一个基本的分布式应用程序。如果你有兴趣进一步探索，请查看 Python 多进程文档。

## 多进程的问题

与线程一样，多进程也存在一些问题，其中一些我们已经讨论过。并发没有最佳的方式；在 Python 中尤其如此。我们总是需要检查并行问题，以找出哪种可用的解决方案是最适合该问题的。有时，没有最佳解决方案。

在多进程的情况下，主要的缺点是在进程之间共享数据非常昂贵。正如我们所讨论的，所有进程之间的通信，无论是通过队列、管道还是更隐式的机制，都需要对对象进行 pickling。过多的 pickling 很快就会占据处理时间。多进程在相对较小的对象之间传递，并且需要对每个对象进行大量的工作时效果最好。另一方面，如果进程之间不需要通信，也许根本没有必要使用该模块；我们可以启动四个独立的 Python 进程并独立使用它们。

多进程的另一个主要问题是，与线程一样，很难确定变量或方法是在哪个进程中被访问的。在多进程中，如果你从另一个进程中访问一个变量，它通常会覆盖当前运行进程中的变量，而另一个进程会保留旧值。这真的很难维护，所以不要这样做。

# Futures

让我们开始以更多异步的方式进行并发。未来包装了多进程或多线程，取决于我们需要的并发类型（倾向于 I/O 与倾向于 CPU）。它们并不能完全解决意外改变共享状态的问题，但它们允许我们构造我们的代码，使得更容易追踪我们这样做的情况。未来为不同的线程或进程提供了明确的边界。与多进程池类似，它们对于“呼叫和回答”类型的交互非常有用，其中处理可以在另一个线程中进行，然后在将来的某个时候（毕竟，它们的名字很贴切），您可以要求它返回结果。它实际上只是多进程池和线程池的一个包装器，但它提供了一个更清晰的 API，并鼓励更好的代码。

未来是一个基本上包装函数调用的对象。该函数调用在后台在一个线程或进程中运行。未来对象有方法来检查未来是否已经完成，并在完成后获取结果。

让我们再做一个文件搜索的例子。在上一节中，我们实现了`unix grep`命令的一个版本。这一次，让我们做一个`find`命令的简单版本。这个例子将在整个文件系统中搜索包含给定字符的路径：

```py
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from os.path import sep as pathsep
from collections import deque

def find_files(path, query_string):
    subdirs = []
    for p in path.iterdir():
        full_path = str(p.absolute())
        if p.is_dir() and not p.is_symlink():
            subdirs.append(p)
        if query_string in full_path:
                print(full_path)

    return subdirs

query = '.py'
futures = deque()
basedir = Path(pathsep).absolute()

with ThreadPoolExecutor(max_workers=10) as executor:
    futures.append(
        executor.submit(find_files, basedir, query))
    while futures:
        future = futures.popleft()
        if future.exception():
            continue
        elif future.done():
            subdirs = future.result()
            for subdir in subdirs:
                futures.append(executor.submit(
                    find_files, subdir, query))
        else:
            futures.append(future)
```

这段代码包括一个名为`find_files`的函数，该函数在一个单独的线程（或进程，如果我们使用`ProcessPoolExecutor`）中运行。这个函数没有什么特别的地方，但请注意它没有访问任何全局变量。与外部环境的所有交互都被传递到函数中或从函数中返回。这不是技术要求，但在使用未来时，这是保持大脑在头脑中的最佳方式。

### 注意

在没有适当同步的情况下访问外部变量会导致一种称为**竞争**条件的情况。例如，想象两个并发写入尝试增加一个整数计数器。它们同时开始并且都将值读取为 5。然后它们都增加了值并将结果写回为 6。但是如果两个进程都尝试增加一个变量，预期的结果应该是它增加了两次，所以结果应该是 7。现代智慧认为避免这样做的最简单方法是尽可能保持尽可能多的状态私有，并通过已知安全的构造来共享它们，比如队列。

在开始之前，我们设置了一些变量；在这个例子中，我们将搜索包含字符`'.py'`的所有文件。我们有一个将会讨论的未来队列。`basedir`变量指向文件系统的根目录；在 Unix 机器上是`'/'`，在 Windows 上可能是`C:\`。

首先，让我们简要介绍一下搜索理论。这个算法实现了并行的广度优先搜索。它不是使用深度优先搜索递归地搜索每个目录，而是将当前文件夹的所有子目录添加到队列中，然后再添加每个文件夹的所有子目录，依此类推。

程序的核心部分称为事件循环。我们可以构建一个`ThreadPoolExecutor`作为上下文管理器，这样当它完成时，它会自动清理并关闭其线程。它需要一个`max_workers`参数来指示同时运行的线程数；如果提交的作业超过这么多，它会排队等待，直到有一个工作线程可用。当使用`ProcessPoolExecutor`时，这通常受限于机器上的 CPU 数量，但使用线程时，它可以更高，取决于同时等待 I/O 的数量。每个线程占用一定量的内存，所以它不应该太高；在磁盘的速度而不是并行请求的数量之前，不需要太多的线程成为瓶颈。

一旦执行器被构建，我们使用根目录向其提交一个作业。`submit()`方法立即返回一个`Future`对象，该对象承诺最终给我们一个结果。未来被放置在队列中。然后循环从队列中重复删除第一个未来并检查它。如果它仍在运行，它会被添加回队列的末尾。否则，我们检查函数是否通过调用`future.exception()`引发了异常。如果是，我们就忽略它（通常是权限错误，尽管真正的应用程序需要更小心地处理异常是什么）。如果我们没有在这里检查异常，那么当我们调用`result()`时，它将被引发，并且可以通过正常的`try`...`except`机制处理。

假设没有发生异常，我们可以调用`result()`来获取函数调用的返回值。由于该函数返回一个不是符号链接的子目录列表（我懒惰地防止无限循环），`result()`返回相同的结果。这些新的子目录被提交给执行器，并且生成的未来被抛到队列中，在以后的迭代中搜索它们的内容。

这就是开发基于未来的 I/O 绑定应用程序所需的全部内容。在底层，它使用了我们已经讨论过的相同的线程或进程 API，但它提供了一个更易理解的接口，并且更容易看到并发运行函数之间的边界（只是不要试图从未来中访问全局变量！）。

# 异步 IO

异步 IO 是 Python 并发编程的最新技术。它将未来的概念和事件循环与我们在第九章中讨论的协程结合起来。结果是写并发代码时尽可能优雅和易于理解，尽管这并不是说很多！

异步 IO 可以用于一些不同的并发任务，但它专门设计用于网络 I/O。大多数网络应用程序，特别是在服务器端，花费大量时间等待来自网络的数据。这可以通过在单独的线程中处理每个客户端来解决，但线程会占用内存和其他资源。异步 IO 使用协程而不是线程。

该库还提供了自己的事件循环，消除了前面示例中几行长的 while 循环的需要。然而，事件循环是有代价的。当我们在事件循环中的异步任务中运行代码时，该代码必须立即返回，既不阻塞 I/O，也不阻塞长时间运行的计算。这在编写我们自己的代码时是一个小事情，但这意味着任何标准库或第三方函数在 I/O 上阻塞时必须创建非阻塞版本。

异步 IO 通过创建一组协程来解决这个问题，这些协程使用`yield from`语法立即将控制返回给事件循环。事件循环负责检查阻塞调用是否已经完成，并执行任何后续任务，就像我们在上一节中手动做的那样。

## 异步 IO 的实际应用

一个典型的阻塞函数的例子是`time.sleep`调用。让我们使用这个调用的异步版本来说明异步 IO 事件循环的基础知识：

```py
import asyncio
import random

@asyncio.coroutine
def random_sleep(counter):
    delay = random.random() * 5
    print("{} sleeps for {:.2f} seconds".format(counter, delay))
 **yield from asyncio.sleep(delay)
    print("{} awakens".format(counter))

@asyncio.coroutine
def five_sleepers():
    print("Creating five tasks")
 **tasks = [
 **asyncio.async(random_sleep(i)) for i in range(5)]
    print("Sleeping after starting five tasks")
 **yield from asyncio.sleep(2)
    print("Waking and waiting for five tasks")
 **yield from asyncio.wait(tasks)

asyncio.get_event_loop().run_until_complete(five_sleepers())
print("Done five tasks")
```

这是一个相当基本的例子，但涵盖了异步 IO 编程的几个特点。最容易理解的顺序是从底部到顶部。

倒数第二行获取事件循环并指示它运行一个 future 直到完成。所讨论的 future 名为`five_sleepers`。一旦该 future 完成了它的工作，循环将退出，我们的代码将终止。作为异步程序员，我们不需要太了解`run_until_complete`调用内部发生了什么，但要知道有很多事情正在进行。它是我们在上一章中编写的 futures 循环的升级版本，它知道如何处理迭代、异常、函数返回、并行调用等。

现在更仔细地看一下`five_sleepers` future。在接下来的几段中忽略装饰器；我们会回到它。协程首先构造了五个`random_sleep` future 的实例。生成的 futures 被包装在`asyncio.async`任务中，将它们添加到循环的任务队列中，以便在控制权返回到事件循环时可以并发执行。

每当我们调用`yield from`时，控制权就会被返回。在这种情况下，我们调用`yield from asyncio.sleep`来暂停此协程的执行两秒钟。在这段时间内，事件循环执行了它排队的任务；即五个`random_sleep` futures。这些协程每个都打印一个开始消息，然后将控制权发送回事件循环，持续一定的时间。如果`random_sleep`中的任何睡眠调用短于两秒，事件循环将控制权传递回相关的 future，在返回之前打印它的唤醒消息。当`five_sleepers`中的睡眠调用醒来时，它执行到下一个`yield from`调用，等待其余的`random_sleep`任务完成。当所有的睡眠调用都执行完毕时，`random_sleep`任务返回，将它们从事件队列中移除。一旦这五个任务都完成了，`asyncio.wait`调用和`five_sleepers`方法也会返回。最后，由于事件队列现在为空，`run_until_complete`调用能够终止，程序结束。

`asyncio.coroutine`装饰器主要是说明这个协程是要在事件循环中作为 future 使用的。在这种情况下，程序即使没有装饰器也能正常运行。然而，`asyncio.coroutine`装饰器也可以用来包装一个普通函数（不含 yield 的函数），以便将其视为 future。在这种情况下，整个函数在返回控制权给事件循环之前执行；装饰器只是强制函数满足协程 API，以便事件循环知道如何处理它。

## 阅读 AsyncIO future

AsyncIO 协程按顺序执行每一行，直到遇到`yield from`语句，此时它将控制权返回给事件循环。事件循环然后执行任何其他准备运行的任务，包括原始协程正在等待的任务。每当子任务完成时，事件循环将结果发送回协程，以便它可以继续执行，直到遇到另一个`yield from`语句或返回。

这使我们能够编写同步执行的代码，直到我们明确需要等待某些东西。这消除了线程的非确定性行为，因此我们不需要太担心共享状态。

### 提示

仍然最好避免从协程内部访问共享状态。这样可以使您的代码更容易理解。更重要的是，即使理想的世界可能所有的异步执行都发生在协程内部，现实是一些 futures 在后台在线程或进程中执行。坚持“不共享”哲学，以避免大量困难的错误。

此外，AsyncIO 允许我们将代码的逻辑部分收集到一个单独的协程中，即使我们在其他地方等待其他工作。作为一个具体的例子，即使`random_sleep`协程中的`yield from asyncio.sleep`调用允许事件循环中发生大量的事情，协程本身看起来好像是按顺序完成了所有工作。异步代码的这种相关部分的阅读能力，而不必担心等待任务完成的机制，是 AsyncIO 模块的主要优势。

## AsyncIO 用于网络

AsyncIO 专门设计用于与网络套接字一起使用，因此让我们实现一个 DNS 服务器。更准确地说，让我们实现 DNS 服务器的一个极其基本的功能。

域名系统的基本目的是将域名（例如 www.amazon.com）转换为 IP 地址（例如 72.21.206.6）。它必须能够执行许多类型的查询，并且知道如何在没有所需答案的情况下联系其他 DNS 服务器。我们不会实现任何这些，但以下示例能够直接响应标准 DNS 查询以查找我最近三个雇主的 IP：

```py
import asyncio
from contextlib import suppress

ip_map = {
    b'facebook.com.': '173.252.120.6',
    b'yougov.com.': '213.52.133.246',
    b'wipo.int.': '193.5.93.80'
}

def lookup_dns(data):
    domain = b''
    pointer, part_length = 13, data[12]
    while part_length:
        domain += data[pointer:pointer+part_length] + b'.'
        pointer += part_length + 1
        part_length = data[pointer - 1]

    ip = ip_map.get(domain, '127.0.0.1')

    return domain, ip

def create_response(data, ip):
    ba = bytearray
    packet = ba(data[:2]) + ba([129, 128]) + data[4:6] * 2
    packet += ba(4) + data[12:]
    packet += ba([192, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4])
    for x in ip.split('.'): packet.append(int(x))
    return packet

class DNSProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

 **def datagram_received(self, data, addr):
        print("Received request from {}".format(addr[0]))
        domain, ip = lookup_dns(data)
        print("Sending IP {} for {} to {}".format(
            domain.decode(), ip, addr[0]))
 **self.transport.sendto(
 **create_response(data, ip), addr)

loop = asyncio.get_event_loop()
transport, protocol = loop.run_until_complete(
 **loop.create_datagram_endpoint(
 **DNSProtocol, local_addr=('127.0.0.1', 4343)))
print("DNS Server running")

with suppress(KeyboardInterrupt):
 **loop.run_forever()
transport.close()
loop.close()

```

此示例设置了一个简单地将一些域名映射到 IPv4 地址的字典。接下来是两个函数，它们从二进制 DNS 查询数据包中提取信息并构造响应。我们不会讨论这些；如果您想了解更多关于 DNS 的信息，请阅读 RFC（“请求评论”，定义大多数互联网协议的格式）1034 和 1035。

您可以通过在另一个终端中运行以下命令来测试此服务：

```py
nslookup -port=4343 facebook.com localhost

```

让我们继续。 AsyncIO 网络围绕传输和协议这两个紧密相关的概念。协议是一个具有特定方法的类，当相关事件发生时会调用这些方法。由于 DNS 运行在**UDP**（**用户数据报协议**）之上，我们将我们的协议类构建为`DatagramProtocol`的子类。这个类有各种事件可以响应；我们特别关注初始连接的发生（仅仅是为了我们可以存储传输以备将来使用）和`datagram_received`事件。对于 DNS，每个接收到的数据报都必须被解析和响应，此时交互就结束了。

因此，当接收到数据报时，我们处理数据包，查找 IP，并使用我们不讨论的函数构造响应（它们在家族中是黑羊）。然后，我们指示底层传输使用其`sendto`方法将生成的数据包发送回请求的客户端。

传输本质上代表了一个通信流。在这种情况下，它抽象了在事件循环中的 UDP 套接字上发送和接收数据的所有麻烦。类似的传输用于与 TCP 套接字和子进程进行交互，例如。

UDP 传输是通过调用循环的`create_datagram_endpoint`协程来构造的。这将构造适当的 UDP 套接字并开始监听它。我们将传递给它套接字需要监听的地址，以及我们创建的协议类，以便传输知道在接收数据时调用什么。

由于初始化套接字的过程需要大量时间，并且会阻塞事件循环，`create_datagram_endpoint`函数是一个协程。在我们的示例中，我们在等待此初始化时实际上不需要做任何事情，因此我们将调用包装在`loop.run_until_complete`中。事件循环负责管理未来，当它完成时，它返回两个值的元组：新初始化的传输和从我们传递的类构造的协议对象。

在幕后，传输已经在事件循环上设置了一个任务，用于监听传入的 UDP 连接。那么，我们所要做的就是通过调用`loop.run_forever()`来启动事件循环，以便该任务可以处理这些数据包。当数据包到达时，它们会在协议上进行处理，一切都会正常运行。

需要注意的另一件重要的事情是，传输（甚至事件循环）在我们完成它们时应该被关闭。在这种情况下，代码在没有两次调用`close()`的情况下也可以正常运行，但是如果我们正在动态构建传输（或者只是进行适当的错误处理！），我们需要更加注意。

您可能对设置协议类和底层传输所需的样板代码感到沮丧。AsyncIO 在这两个关键概念之上提供了一个称为 streams 的抽象。我们将在下一个示例中的 TCP 服务器中看到 streams 的示例。

## 使用执行器包装阻塞代码

AsyncIO 提供了自己的版本的 futures 库，允许我们在没有适当的非阻塞调用时在单独的线程或进程中运行代码。这本质上允许我们将线程和进程与异步模型结合起来。这个特性的更有用的应用之一是在应用程序有 I/O 密集和 CPU 密集活动突发时获得最佳效果。I/O 密集部分可以在事件循环中进行，而 CPU 密集型工作可以分配到不同的进程中。为了说明这一点，让我们使用 AsyncIO 实现“排序作为服务”：

```py
import asyncio
import json
from concurrent.futures import ProcessPoolExecutor

def sort_in_process(data):
    nums = json.loads(data.decode())
    curr = 1
    while curr < len(nums):
        if nums[curr] >= nums[curr-1]:
            curr += 1
        else:
            nums[curr], nums[curr-1] = \
                nums[curr-1], nums[curr]
            if curr > 1:
                curr -= 1

    return json.dumps(nums).encode()

@asyncio.coroutine
def sort_request(reader, writer):
    print("Received connection")
 **length = yield from reader.read(8)
 **data = yield from reader.readexactly(
 **int.from_bytes(length, 'big'))
 **result = yield from asyncio.get_event_loop().run_in_executor(
 **None, sort_in_process, data)
    print("Sorted list")
    writer.write(result)
    writer.close()   
    print("Connection closed")     

loop = asyncio.get_event_loop()
loop.set_default_executor(ProcessPoolExecutor())
server = loop.run_until_complete(
 **asyncio.start_server(sort_request, '127.0.0.1', 2015))
print("Sort Service running")

loop.run_forever()
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
```

这是一个实现一些非常愚蠢想法的好代码示例。将排序作为服务的整个想法相当荒谬。使用我们自己的排序算法而不是调用 Python 的`sorted`甚至更糟。我们使用的算法称为侏儒排序，或者在某些情况下称为“愚蠢排序”。这是一种在纯 Python 中实现的缓慢排序算法。我们定义了自己的协议，而不是使用野外存在的许多完全合适的应用程序协议之一。甚至在这里使用多进程进行并行可能是可疑的；我们最终仍然将所有数据传递到子进程中并传出。有时，重要的是要从您正在编写的程序中退后一步，问自己是否正在尝试实现正确的目标。

但让我们来看看这种设计的一些智能特性。首先，我们将字节传入并传出子进程。这比在主进程中解码 JSON 要聪明得多。这意味着（相对昂贵的）解码可以在不同的 CPU 上进行。此外，被拾取的 JSON 字符串通常比被拾取的列表小，因此在进程之间传递的数据更少。

其次，这两种方法非常线性；看起来代码是一行一行地执行的。当然，在 AsyncIO 中，这只是一种错觉，但我们不必担心共享内存或并发原语。

## Streams

前面的示例现在应该看起来很熟悉，因为它与其他 AsyncIO 程序有相似的样板。但是，有一些区别。您会注意到我们调用了`start_server`而不是`create_server`。这种方法钩入了 AsyncIO 的 streams，而不是使用底层的传输/协议代码。我们可以传入一个普通的协程，而不是传入一个协议类，这个协程接收 reader 和 writer 参数。这两者都代表可以像文件或套接字一样读取和写入的字节流。其次，因为这是一个 TCP 服务器而不是 UDP，当程序完成时需要进行一些套接字清理。这个清理是一个阻塞调用，所以我们必须在事件循环上运行`wait_closed`协程。

Streams 相当容易理解。读取是一个潜在的阻塞调用，因此我们必须使用`yield from`来调用它。写入不会阻塞；它只是将数据放在队列中，AsyncIO 会在后台发送出去。

我们在`sort_request`方法中的代码发出了两个读取请求。首先，它从线路上读取 8 个字节，并使用大端记法将它们转换为整数。这个整数代表客户端打算发送的数据字节数。所以在下一个调用`readexactly`时，它读取了这么多字节。`read`和`readexactly`之间的区别在于前者将读取请求的字节数，而后者将缓冲读取，直到接收到所有字节，或者直到连接关闭。

### 执行器

现在让我们来看看执行器代码。我们导入了与上一节中使用的完全相同的`ProcessPoolExecutor`。请注意，我们不需要它的特殊 AsyncIO 版本。事件循环有一个方便的`run_in_executor`协程，我们可以用它来运行未来。默认情况下，循环在`ThreadPoolExecutor`中运行代码，但如果需要，我们可以传入不同的执行器。或者，就像我们在这个例子中所做的那样，我们可以在设置事件循环时调用`loop.set_default_executor()`来设置不同的默认值。

正如你可能还记得上一节所说的，使用执行器与未来的代码并没有太多样板。然而，当我们在 AsyncIO 中使用它们时，根本没有！协程自动将函数调用包装在未来中，并将其提交给执行器。我们的代码会阻塞，直到未来完成，而事件循环会继续处理其他连接、任务或未来。当未来完成时，协程会唤醒并继续将数据写回客户端。

也许你会想知道，与其在事件循环中运行多个进程，是否在不同的进程中运行多个事件循环会更好。答案是：“也许”。然而，根据确切的问题空间，我们可能最好是运行程序的独立副本，每个副本都有一个事件循环，而不是试图用主多进程进程协调一切。

在本节中，我们已经涵盖了 AsyncIO 的大部分要点，本章还涵盖了许多其他并发原语。并发是一个难题，没有一个解决方案适用于所有用例。设计并发系统最重要的部分是决定使用哪种可用工具来解决问题。我们已经看到了几种并发系统的优缺点，现在对于不同类型的需求，我们有了一些见解，知道哪些是更好的选择。

# 案例研究

为了结束本章和本书，让我们构建一个基本的图像压缩工具。它将使用黑白图像（每个像素 1 位，要么打开要么关闭）并尝试使用一种称为行程长度编码的非常基本的压缩形式来压缩它。你可能会觉得黑白图像有点牵强。如果是这样，那么你还没有在[xkcd.com](http://xkcd.com)上享受足够的时间！

我在本章的示例代码中包含了一些黑白 BMP 图像（这些图像很容易读取数据，并且留下了很多改进文件大小的机会）。

我们将使用一种称为行程长度编码的简单技术来压缩图像。这种技术基本上是将一系列位替换为重复位的数量。例如，字符串 000011000 可能被替换为 04 12 03，表示有 4 个零，然后是 2 个一，然后是 3 个零。为了使事情更有趣，我们将每一行分成 127 位的块。

我并不是随意选择了 127 位。127 个不同的值可以编码为 7 位，这意味着如果一行包含全部 1 或全部 0，我们可以将其存储在一个字节中；第一个位指示它是 0 的一行还是 1 的一行，剩下的 7 位指示该位存在多少个。

将图像分成块还有另一个优点；我们可以在没有相互依赖的情况下并行处理单个块。然而，也有一个主要缺点；如果一个运行中只有几个 1 或 0，那么它将在压缩文件中占用`更多`的空间。当我们将长运行分成块时，我们可能会创建更多这样的小运行，并使文件的大小膨胀。

在处理文件时，我们必须考虑压缩文件中字节的确切布局。我们的文件将在文件开头存储两个字节的小端整数，表示完成文件的宽度和高度。然后它将写入表示每行的 127 位块的字节。

现在，在我们开始设计一个并发系统来构建这样的压缩图像之前，我们应该问一个基本问题：这个应用程序是 I/O 绑定还是 CPU 绑定？

老实说，我的答案是“我不知道”。我不确定应用程序是更多时间从磁盘加载数据并将其写回，还是在内存中进行压缩。我怀疑原则上这是一个 CPU 绑定的应用程序，但一旦我们开始将图像字符串传递到子进程中，我们可能会失去并行性的任何好处。解决这个问题的最佳方法可能是编写一个 C 或 Cython 扩展，但让我们看看在纯 Python 中我们能走多远。

我们将使用自下而上的设计构建此应用程序。这样我们将有一些构建块，可以将它们组合成不同的并发模式，以查看它们的比较。让我们从使用游程编码压缩 127 位块的代码开始：

```py
from bitarray import bitarray
def compress_chunk(chunk):
    compressed = bytearray()
    count = 1
    last = chunk[0]
    for bit in chunk[1:]:
        if bit != last:
            compressed.append(count | (128 * last))
            count = 0
            last = bit
        count += 1
    compressed.append(count | (128 * last))
    return compressed
```

这段代码使用`bitarray`类来操作单个 0 和 1。它作为第三方模块分发，您可以使用`pip install bitarray`命令进行安装。传递给`compress_chunks`的块是这个类的一个实例（尽管示例也可以使用布尔值列表）。在这种情况下，位数组的主要优点是，在进程之间进行 pickling 时，它们占用布尔值列表或包含 1 和 0 的字节字符串的 1/8 的空间。因此，它们 pickle 得更快。它们也比进行大量位操作更容易使用。

该方法使用游程编码压缩数据，并返回包含打包数据的 bytearray。位数组类似于一个由 1 和 0 组成的列表，而 bytearray 类似于一个字节对象的列表（每个字节当然包含 8 个 1 或 0）。

执行压缩的算法非常简单（尽管我想指出，我花了两天的时间来实现和调试它。简单易懂并不一定意味着容易编写！）。它首先将`last`变量设置为当前运行中的位的类型（`True`或`False`）。然后它循环遍历位，计算每一个，直到找到一个不同的。当找到不同的时，它通过使字节的最左边的位（第 128 位）为零或一，取决于`last`变量的内容，构造一个新字节。然后它重置计数器并重复操作。一旦循环结束，它为最后一个运行创建一个字节，并返回结果。

在我们创建构建块的同时，让我们制作一个压缩图像数据行的函数：

```py
def compress_row(row):
    compressed = bytearray()
    chunks = split_bits(row, 127)
    for chunk in chunks:
        compressed.extend(compress_chunk(chunk))
    return compressed
```

这个函数接受一个名为 row 的位数组。它使用一个我们将很快定义的函数将其分成每个 127 位宽的块。然后它使用先前定义的`compress_chunk`压缩每个块，将结果连接成一个`bytearray`，然后返回。

我们将`split_bits`定义为一个简单的生成器：

```py
def split_bits(bits, width):
    for i in range(0, len(bits), width):
        yield bits[i:i+width]
```

现在，由于我们还不确定这个程序在线程或进程中运行哪种方式更有效，让我们把这些函数封装在一个方法中，该方法在提供的执行器中运行一切：

```py
def compress_in_executor(executor, bits, width):
    row_compressors = []
    for row in split_bits(bits, width):
 **compressor = executor.submit(compress_row, row)
        row_compressors.append(compressor)

    compressed = bytearray()
    for compressor in row_compressors:
 **compressed.extend(compressor.result())
    return compressed
```

这个例子几乎不需要解释；它根据图像的宽度将传入的位拆分成行，使用我们已经定义的相同的`split_bits`函数（为自下而上的设计欢呼！）。

请注意，这段代码将压缩任何位序列，尽管它会膨胀，而不是压缩具有位值频繁变化的二进制数据。黑白图像绝对是该压缩算法的良好候选。现在让我们创建一个函数，使用第三方 pillow 模块加载图像文件，将其转换为位，并对其进行压缩。我们可以轻松地在可敬的注释语句中切换执行器。

```py
from PIL import Image
def compress_image(in_filename, out_filename, executor=None):
    executor = executor if executor else ProcessPoolExecutor()
    with Image.open(in_filename) as image:
        bits = bitarray(image.convert('1').getdata())
        width, height = image.size

    compressed = compress_in_executor(executor, bits, width)

    with open(out_filename, 'wb') as file:
        file.write(width.to_bytes(2, 'little'))
        file.write(height.to_bytes(2, 'little'))
        file.write(compressed)

def single_image_main():
    in_filename, out_filename = sys.argv[1:3]
    #executor = ThreadPoolExecutor(4)
 **executor = ProcessPoolExecutor()
    compress_image(in_filename, out_filename, executor)
```

`image.convert()`调用将图像更改为黑白（一位）模式，而`getdata()`返回这些值的迭代器。我们将结果打包到位数组中，以便它们可以更快地通过网络传输。当我们输出压缩文件时，我们首先写入图像的宽度和高度，然后是压缩数据，它以字节数组的形式到达，可以直接写入二进制文件。

编写了所有这些代码后，我们终于能够测试线程池或进程池是否能够给我们更好的性能。我创建了一个大型（7200 x 5600 像素）的黑白图像，并将其通过两个池。`ProcessPool`在我的系统上大约需要 7.5 秒来处理图像，而`ThreadPool`始终需要大约 9 秒。因此，正如我们所怀疑的那样，将位和字节在进程之间来回传递的成本几乎吞噬了在多个处理器上运行的效率收益（尽管从我的 CPU 监视器来看，它确实充分利用了我的机器上的所有四个核心）。

因此，看起来压缩单个图像最有效地在单独的进程中完成，但仅仅是因为我们在父进程和子进程之间传递了如此多的数据。当进程之间传递的数据量非常低时，多进程的效果更好。

所以让我们扩展应用程序以并行压缩目录中的所有位图。我们唯一需要传递给子进程的是文件名，因此与使用线程相比，我们应该获得速度增益。另外，为了有点疯狂，我们将使用现有代码来压缩单个图像。这意味着我们将在每个子进程中运行`ProcessPoolExecutor`来创建更多的子进程。我不建议在现实生活中这样做！

```py
from pathlib import Path
def compress_dir(in_dir, out_dir):
    if not out_dir.exists():
        out_dir.mkdir()

 **executor = ProcessPoolExecutor()
    for file in (
            f for f in in_dir.iterdir() if f.suffix == '.bmp'):
        out_file = (out_dir / file.name).with_suffix('.rle')
 **executor.submit(
 **compress_image, str(file), str(out_file))

def dir_images_main():
    in_dir, out_dir = (Path(p) for p in sys.argv[1:3])
    compress_dir(in_dir, out_dir)
```

这段代码使用我们之前定义的`compress_image`函数，但在每个图像的单独进程中运行它。它没有将执行器传递给函数，因此一旦新进程开始运行，`compress_image`就会创建一个`ProcessPoolExecutor`。

现在我们在执行器内部运行执行器，有四种线程和进程池的组合可以用来压缩图像。它们各自具有非常不同的时间特征：

| 每个图像的进程池 | 每个图像的线程池 |
| --- | --- | --- |
| **每行的进程池** | 42 秒 | 53 秒 |
| **每行的线程池** | 34 秒 | 64 秒 |

正如我们所预料的，对每个图像使用线程，再对每行使用线程是最慢的，因为 GIL 阻止我们并行工作。鉴于当我们对单个图像使用单独的进程时，对每行使用单独的进程时稍微更快，您可能会惊讶地发现，如果我们在单独的进程中处理每个图像，则使用`ThreadPool`功能对行进行处理会更快。花点时间理解为什么会这样。

我的机器只有四个处理器核心。每个图像中的每一行都在一个单独的池中进行处理，这意味着所有这些行都在竞争处理能力。当只有一个图像时，通过并行运行每一行，我们可以获得（非常适度的）加速。然而，当我们增加同时处理的图像数量时，将所有这些行数据传递到子进程中的成本会主动地从其他图像中窃取处理时间。因此，如果我们可以在单独的处理器上处理每个图像，那么只需要将一些文件名 pickle 到子进程管道中，我们就可以获得很好的加速。

因此，我们看到不同的工作负载需要不同的并发范例。即使我们只是使用 futures，我们也必须对要使用的执行器类型做出明智的决定。

还要注意，对于通常大小的图像，程序运行速度足够快，以至于使用哪种并发结构并不重要。实际上，即使我们根本不使用并发，最终用户体验也可能差不多。

这个问题也可以直接使用线程和/或多进程模块来解决，尽管需要编写更多的样板代码。你可能想知道 AsyncIO 在这里是否有用。答案是：“可能不”。大多数操作系统没有很好的方法来从文件系统进行非阻塞读取，因此该库最终会将所有调用包装在 futures 中。

为了完整起见，这是我用来解压 RLE 图像以确认算法是否正确运行的代码（事实上，直到我修复了压缩和解压缩中的错误之后，我才确定它是否完美。我应该使用测试驱动开发！）：

```py
from PIL import Image
import sys

def decompress(width, height, bytes):
    image = Image.new('1', (width, height))

    col = 0
    row = 0
    for byte in bytes:
        color = (byte & 128) >> 7
        count = byte & ~128
        for i in range(count):
            image.putpixel((row, col), color)
            row += 1
        if not row % width:
            col += 1
            row = 0
    return image

with open(sys.argv[1], 'rb') as file:
    width = int.from_bytes(file.read(2), 'little')
    height = int.from_bytes(file.read(2), 'little')

    image = decompress(width, height, file.read())
    image.save(sys.argv[2], 'bmp')
```

这段代码非常简单。每次运行都被编码为一个字节。它使用一些位运算来提取像素的颜色和运行的长度。然后它在图像中设置每个像素，适当的间隔递增下一个要检查的像素的行和列。

# 练习

在本章中，我们涵盖了几种不同的并发范例，但仍然不清楚每种范例何时有用。正如我们在案例研究中看到的，通常最好在承诺采用某种范例之前先尝试几种不同的策略。

Python 3 中的并发是一个庞大的主题，这样大小的一本书也无法涵盖所有相关知识。作为你的第一个练习，我鼓励你去了解一些第三方库，它们可能提供额外的上下文：

+   execnet 是一个允许本地和远程共享无状态并发的库

+   Parallel python 是一种可以并行执行线程的替代解释器

+   Cython 是一种兼容 Python 的语言，它编译成 C 并具有释放 GIL 和利用完全并行多线程的原语。

+   PyPy-STM 是一个在超快 PyPy Python 解释器上实验性实现的软件事务内存

+   Gevent

如果你最近在应用程序中使用了线程，请查看代码，看看是否可以通过使用 futures 使其更易读且更少出错。比较线程和多进程 futures，看看是否可以通过使用多个 CPU 获得任何好处。

尝试为一些基本的 HTTP 请求实现一个 AsyncIO 服务。你可能需要在网上查找 HTTP 请求的结构；它们是相当简单的 ASCII 数据包。如果你能让一个网络浏览器呈现一个简单的 GET 请求，你就会对 AsyncIO 网络传输和协议有一个很好的理解。

确保你理解了在访问共享数据时线程中发生的竞争条件。尝试编写一个程序，使用多个线程以一种使数据故意变得损坏或无效的方式设置共享值。

在第六章中，我们介绍了我们在案例研究中涵盖的链接收集器，*Python 数据结构*。你能通过并行请求使其运行更快吗？对于这个问题，使用原始线程、futures 还是 AsyncIO 更好？

尝试使用线程或多进程直接编写运行长度编码示例。你获得了任何速度提升吗？代码更容易还是更难理解？有没有办法通过并发或并行来加快解压缩脚本的速度？

# 总结

本章结束了我们对面向对象编程的探索，这个主题并不是非常面向对象。并发是一个困难的问题，我们只是触及了表面。虽然进程和线程的底层操作系统抽象并没有提供远程面向对象的 API，但 Python 提供了一些非常好的围绕它们的面向对象抽象。线程和多进程包都提供了对底层机制的面向对象接口。Futures 能够将许多混乱的细节封装到一个对象中。AsyncIO 使用协程对象使我们的代码看起来像是同步运行，同时隐藏了丑陋和复杂的实现细节，背后是一个非常简单的循环抽象。

感谢阅读*Python 3 面向对象编程*，*第二版*。希望您享受了这段旅程，并渴望开始在未来的所有项目中实现面向对象的软件！
