# PyTest 快速启动指南（三）

> 原文：[`zh.annas-archive.org/md5/ef4cd099dd041b2b3c7ad8b8d5fa4114`](https://zh.annas-archive.org/md5/ef4cd099dd041b2b3c7ad8b8d5fa4114)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：总结

在上一章中，我们学习了一些技术，可以用来将基于`unittest`的测试套件转换为 pytest，从简单地将其用作运行器，一直到将复杂的现有功能转换为更符合 pytest 风格的方式。

这是本快速入门指南的最后一章，我们将讨论以下主题：

+   我们学到了什么

+   pytest 社区

+   下一步

+   最终总结

# 我们学到了什么

接下来的章节将总结我们在本书中学到的内容。

# 介绍

+   您应该考虑编写测试作为您的安全网。这将使您对自己的工作更有信心，允许您放心地进行重构，并确保您没有破坏系统的其他部分。

+   如果您正在将 Python 2 代码库转换为 Python 3，测试套件是必不可少的，因为任何指南都会告诉您，([`docs.python.org/3/howto/pyporting.html#have-good-test-coverage`](https://docs.python.org/3/howto/pyporting.html#have-good-test-coverage))。

+   如果您依赖的**外部 API**没有自动化测试，为其编写测试是一个好主意。

+   pytest 之所以是初学者的绝佳选择之一，是因为它很容易上手；使用简单的函数和`assert`语句编写您的测试。

# 编写和运行测试

+   始终使用**虚拟环境**来管理您的软件包和依赖关系。这个建议适用于任何 Python 项目。

+   pytest 的**内省功能**使得表达您的检查变得简洁；可以直接比较字典、文本和列表。

+   使用`pytest.raises`检查异常和`pytest.warns`检查警告。

+   使用`pytest.approx`比较浮点数和数组。

+   测试组织；您可以将您的测试**内联**到应用程序代码中，也可以将它们保存在一个单独的目录中。

+   使用`-k`标志选择测试：`-k test_something`。

+   使用`-x`在**第一个失败**时停止。

+   记住了**重构二人组**：`--lf -x`。

+   使用`-s`禁用**输出捕获**。

+   使用`-ra`显示测试失败、xfails 和跳过的**完整摘要**。

+   使用`pytest.ini`进行**每个存储库的配置**。

# 标记和参数化

+   在测试函数和类中使用`@pytest.mark`装饰器创建**标记**。要应用到**模块**，请使用`pytestmark`特殊变量。

+   使用`@pytest.mark.skipif`、`@pytest.mark.skip`和`pytest.importorskip("module")`来跳过**当前环境**不适用的测试。

+   使用`@pytest.mark.xfail(strict=True)`或`pytest.xfail("reason")`来标记**预期失败**的测试。

+   使用`@pytest.mark.xfail(strict=False)`来标记**不稳定的测试**。

+   使用`@pytest.mark.parametrize`快速测试**多个输入**的代码和测试**相同接口的不同实现**。

# Fixture

+   **Fixture**是 pytest 的主要特性之一，用于**共享资源**并提供易于使用的**测试辅助工具**。

+   使用`conftest.py`文件在测试模块之间**共享 fixtures**。记得优先使用本地导入以加快测试收集速度。

+   使用**autouse** fixture 确保层次结构中的每个测试都使用某个 fixture 来执行所需的设置或拆卸操作。

+   Fixture 可以假定**多个范围**：`function`、`class`、`module`和`session`。明智地使用它们来减少测试套件的总时间，记住高级 fixture 实例在测试之间是共享的。

+   可以使用`@pytest.fixture`装饰器的`params`参数对**fixture 进行参数化**。使用参数化 fixture 的所有测试将自动进行参数化，使其成为一个非常强大的工具。

+   使用`tmpdir`和`tmpdir_factory`创建空目录。

+   使用`monkeypatch`临时更改对象、字典和环境变量的属性。

+   使用`capsys`和`capfd`来捕获和验证发送到标准输出和标准错误的输出。

+   fixture 的一个重要特性是它们**抽象了依赖关系**，在使用**简单函数与 fixture**之间存在平衡。

# 插件

+   使用`plugincompat` ([`plugincompat.herokuapp.com/`](http://plugincompat.herokuapp.com/)) 和 PyPI ([`pypi.org/`](https://pypi.org/)) 搜索新插件。

+   插件**安装简单**：使用`pip`安装，它们会自动激活。

+   有大量的插件可供使用，满足各种需求。

# 将 unittest 套件转换为 pytest

+   你可以从切换到**pytest 作为运行器**开始。通常情况下，这可以在现有代码中**不做任何更改**的情况下完成。

+   使用`unittest2pytest`将`self.assert*`方法转换为普通的`assert`。

+   现有的**设置**和**拆卸**代码可以通过**autouse** fixtures 进行小的重构后重复使用。

+   可以将复杂的测试工具**层次结构**重构为更**模块化的 fixture**，同时保持现有的测试工作。

+   有许多方法可以进行迁移：一次性转换**所有**内容，转换现有测试时逐步转换测试，或者仅在**新**测试中使用 pytest。这取决于你的测试套件大小和时间预算。

# pytest 社区

我们的社区位于 GitHub 的`pytest-dev`组织（[`github.com/pytest-dev`](https://github.com/pytest-dev)）和 BitBucket（[`bitbucket.org/pytest-dev`](https://bitbucket.org/pytest-dev)）。pytest 仓库（[`github.com/pytest-dev/pytest`](https://github.com/pytest-dev/pytest)）本身托管在 GitHub 上，而 GitHub 和 Bitbucket 都托管了许多插件。成员们努力使社区对来自各个背景的新贡献者尽可能友好和欢迎。我们还在`pytest-dev@python.org`上有一个邮件列表，欢迎所有人加入（[`mail.python.org/mailman/listinfo/pytest-dev`](https://mail.python.org/mailman/listinfo/pytest-dev)）。

大多数 pytest-dev 成员居住在西欧，但我们有来自全球各地的成员，包括阿联酋、俄罗斯、印度和巴西（我就住在那里）。

# 参与其中

因为所有 pytest 的维护完全是自愿的，我们一直在寻找愿意加入社区并帮助改进 pytest 及其插件的人，与他人诚信合作。有许多参与的方式：

+   提交功能请求；我们很乐意听取用户对于他们希望在 pytest 或插件中看到的新功能的意见。确保将它们报告为问题以开始讨论（[`github.com/pytest-dev/pytest/issues`](https://github.com/pytest-dev/pytest/issues)）。

+   报告错误：如果你遇到错误，请报告。我们会尽力及时修复错误。

+   更新文档；我们有许多与文档相关的未解决问题（[`github.com/pytest-dev/pytest/issues?utf8=%E2%9C%93&q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc+label%3A%22status%3A+easy%22+label%3A%22type%3A+docs%22+`](https://github.com/pytest-dev/pytest/issues?utf8=%E2%9C%93&q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc+label%3A%22status%3A+easy%22+label%3A%22type%3A+docs%22+))。如果你喜欢帮助他人并撰写良好的文档，这是一个帮助他人的绝佳机会。

+   实现新功能；尽管代码库对新手来说可能看起来令人生畏，但有许多标有易标签的功能或改进（[`github.com/pytest-dev/pytest/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc+label%3A%22status%3A+easy%22`](https://github.com/pytest-dev/pytest/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc+label%3A%22status%3A+easy%22)），这对新贡献者很友好。此外，如果你不确定，可以随时询问！

+   修复错误；尽管 pytest 对自身进行了 2000 多次测试，但像任何软件一样，它也存在已知的错误。我们非常乐意审查已知错误的拉取请求（[`github.com/pytest-dev/pytest/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc+label%3A%22type%3A+bug%22`](https://github.com/pytest-dev/pytest/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc+label%3A%22type%3A+bug%22)）。

+   在推特上使用`#pytest`标签或提及`@pytestdotorg`来传播你的爱。我们也喜欢阅读关于你使用 pytest 的经验的博客文章。

+   在许多会议上，社区的成员组织研讨会、冲刺活动或发表演讲。一定要打个招呼！

成为贡献者很容易；你只需要贡献一个关于相关代码更改、文档或错误修复的拉取请求，如果愿意，你就可以成为`pytest-dev`组织的成员。作为成员，你可以帮助回答、标记和关闭问题，并审查和合并拉取请求。

另一种贡献方式是向`pytest-dev`提交新的插件，可以在 GitHub 或 BitBucket 上进行。我们喜欢当新的插件被添加到组织中，因为这会提供更多的可见性，并帮助与其他成员分享维护工作。

你可以在 pytest 网站上阅读我们的完整贡献指南（[`docs.pytest.org/en/latest/contributing.html`](https://docs.pytest.org/en/latest/contributing.html)）。

# 2016 年冲刺活动

2016 年 6 月，核心团队在德国弗莱堡举办了一次大规模的冲刺活动。超过 20 名参与者参加了为期六天的活动；活动主题围绕着实施新功能和解决问题。我们进行了大量的小组讨论和闪电演讲，并休息一天去美丽的黑森林徒步旅行。

团队成功发起了一次成功的 Indiegogo 活动（[`www.indiegogo.com/projects/python-testing-sprint-mid-2016#/`](https://www.indiegogo.com/projects/python-testing-sprint-mid-2016#/)），旨在筹集 11000 美元以偿还参与者的旅行费用、冲刺场地和餐饮费用。最终，我们筹集了超过 12000 美元，这显示了使用 pytest 的用户和公司的赞赏。

这真是太有趣了！我们一定会在未来重复这样的活动，希望能有更多的参与者。

# 下一步

在学到所有这些知识之后，你可能迫不及待地想要开始使用 pytest，或者更频繁地使用它。

以下是你可以采取的一些下一步的想法：

+   在工作中使用它；如果你已经在日常工作中使用 Python 并有大量的测试，那是开始的最佳方式。你可以慢慢地使用 pytest 作为测试运行器，并以你感到舒适的速度使用更多的 pytest 功能。

+   在你自己的开源项目中使用它：如果你是一个开源项目的成员或所有者，这是获得一些 pytest 经验的好方法。如果你已经有了一个测试套件，那就更好了，但如果没有，当然从 pytest 开始将是一个很好的选择。

+   为开源项目做贡献；你可以选择一个具有`unittest`风格测试的开源项目，并决定提供更改以使用 pytest。2015 年 4 月，pytest 社区组织了所谓的 Adopt pytest 月活动（[`docs.pytest.org/en/latest/adopt.html`](https://docs.pytest.org/en/latest/adopt.html)），开源项目与社区成员配对，将他们的测试套件转换为 pytest。这个活动取得了成功，大多数参与者都玩得很开心。这是参与另一个开源项目并同时学习 pytest 的好方法。

+   为 pytest 本身做出贡献；如前所述，pytest 社区对新贡献者非常欢迎。我们很乐意欢迎你！

本书故意省略了一些主题，因为它们被认为对于快速入门来说有点高级，或者因为由于空间限制，我们无法将它们纳入书中。

+   tox（https://tox.readthedocs.io/en/latest/）是一个通用的虚拟环境管理器和命令行工具，可用于测试具有多个 Python 版本和依赖项的项目。如果您维护支持多个 Python 版本和环境的项目，它就是一个救星。pytest 和`tox`是兄弟项目，它们在一起工作得非常好，尽管它们是独立的，并且对于它们自己的目的非常有用。

+   插件：本书不涵盖如何使用插件扩展 pytest，所以如果您感兴趣，请务必查看 pytest 文档的插件部分（https://docs.pytest.org/en/latest/fixture.html），并寻找其他可以作为示例的插件。此外，请务必查看示例部分（https://docs.pytest.org/en/latest/example/simple.html）以获取高级 pytest 自定义的片段。

+   日志记录和警告是两个 Python 功能，pytest 内置支持，本书没有详细介绍，但如果您经常使用这些功能，它们确实值得一看。

# 最终总结

所以，我们已经完成了快速入门指南。在本书中，我们从在命令行上使用 pytest 到将现有测试套件转换为利用强大的 pytest 功能的技巧和窍门，进行了全面的概述。您现在应该能够每天轻松使用 pytest，并在需要时帮助他人。

您已经走到了这一步，所以祝贺您！希望您在学习的过程中学到了一些东西，并且玩得开心！


# 第七章：引入 pytest

自动化测试被认为是生产高质量软件的不可或缺的工具和方法。测试应该是每个专业软件开发人员工具箱的一部分，但与此同时，许多人认为这是工作中无聊和重复的部分。但当您使用 pytest 作为测试框架时，情况就不一样了。

本书将向您介绍各种关键功能，并教您如何从第一章开始有效地使用 pytest 进行日常编码任务，重点是让您尽快提高生产力。编写测试应该成为一种乐趣，而不是工作中无聊的部分。

我们将首先看一下自动化测试的重要性。我还会试图说服您，这不是因为这是正确的事情，所以您应该拥有它。自动化测试是您希望拥有的东西，因为它会让您的工作变得更加轻松和愉快。我们将简要介绍 Python 的标准`unittest`模块，并介绍 pytest 以及为什么它具有更多的功能，同时使用起来非常简单。然后，我们将介绍如何编写测试，如何将它们组织成类和目录，以及如何有效地使用 pytest 的命令行。然后，我们将看一下如何使用标记来控制跳过测试或期望测试失败，如何利用自定义标记，以及如何使用相同的测试代码参数化来测试多个输入，以避免复制/粘贴代码。这将帮助我们学习如何使用 pytest 最受欢迎的功能之一：fixture 来管理和重用测试资源和环境。之后，我们将介绍 pytest 提供的一些更受欢迎和有用的插件。最后，我们将探讨如何逐步将基于`unittest`的测试套件转换为 pytest 风格，以便在现有代码库中充分利用其许多优势。

在本章中，我们将快速了解为什么我们应该进行测试，内置的`unittest`模块以及 pytest 的概述。以下内容将被涵盖：

+   为什么要花时间编写测试？

+   快速了解`unittest`模块

+   为什么选择 pytest？

让我们先退一步，思考为什么编写测试被认为是如此重要。

# 为什么要花时间编写测试？

手动测试程序是自然的；编写自动化测试则不是。

程序员在学习编码或尝试新技术和库时使用各种技术。编写短小的代码片段，跟随教程，使用 REPL 玩耍，甚至使用 Jupyter（[`jupyter.org/`](http://jupyter.org/)）。通常，这涉及手动验证所学内容的结果，使用打印语句或绘制图形。这是一种简单、自然且完全有效的学习新知识的方式。

然而，这种模式不应该延续到专业软件开发中。专业软件并不简单；相反，它通常非常复杂。根据系统设计的好坏，各个部分可能以奇怪的方式交织在一起，新功能的添加可能会破坏系统的另一个看似无关的部分。修复一个错误可能会导致另一个错误在其他地方出现。

如何确保新功能正常工作或错误已经被彻底解决？同样重要的是，如何确保通过修复或引入新功能，系统的另一部分不会被破坏？

答案是通过拥有一套健康和全面的自动化测试，也称为测试套件。

测试套件简单来说就是测试您的代码的代码。通常，它们会创建一个或多个必要的资源，并调用要测试的应用程序代码。然后，他们断言结果是否符合预期。除了在开发人员的机器上执行外，在大多数现代设置中，它们会被连续运行，例如每小时或每次提交，由像 Jenkins 这样的自动化系统运行。因此，为一段代码添加测试意味着从现在开始，它将在添加功能和修复错误时一遍又一遍地进行测试。

拥有自动化测试意味着您可以对程序进行更改，并立即查看这些更改是否破坏了系统的某个部分，作为开发人员的安全网。拥有一个良好的测试套件非常令人振奋：您不再害怕改进 8 年前编写的代码，如果犯了任何错误，测试套件会告诉您。您可以添加一个新功能，并确信它不会破坏您没有预料到的系统的其他部分。能够有信心地将一个大型库从 Python 2 转换为 3，或进行大规模的重构，是绝对必要的。通过添加一个或多个自动化测试来重现一个 bug，并证明您已经修复了它，您可以确保这个 bug 不会在以后的重构或其他编码错误中再次出现。

一旦你习惯了享受测试套件作为安全网的好处，你甚至可能决定为你依赖的 API 编写测试，但知道开发人员没有测试：能够向原始开发人员提供失败的测试来证明他们的新版本是导致错误的原因，而不是你的代码，这是一个罕见的职业骄傲时刻。

拥有一个写得很好、深入的测试套件将使您能够放心地进行任何大小的更改，并帮助您晚上睡得更好。

# 快速查看 unittest 模块

Python 自带内置的`unittest`模块，这是一个基于 Java 的单元测试框架 JUnit 编写自动化测试的框架。您可以通过从`unittest.TestCase`继承并定义以`test`开头的方法来创建测试。以下是使用`unittest`的典型最小测试用例的示例：

```py
    import unittest
    from fibo import fibonacci

    class Test(unittest.TestCase):

        def test_fibo(self):
            result = fibonacci(4)
            self.assertEqual(result, 3)

    if __name__ == '__main__':
        unittest.main()
```

这个例子的重点是展示测试本身，而不是被测试的代码，所以我们将使用一个简单的`fibonacci`函数。斐波那契数列是一个无限的正整数序列，其中序列中的下一个数字是通过将前两个数字相加得到的。以下是前 11 个数字：

```py
1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, ...
```

我们的`fibonacci`函数接收斐波那契数列的`index`，实时计算值并返回它。

为了确保函数按预期工作，我们使用我们知道正确答案的值来调用它（斐波那契数列的第四个元素是 3），然后调用`self.assertEqual(a, b)`方法来检查`a`和`b`是否相等。如果函数有 bug 并且没有返回预期的结果，当我们执行它时，框架会告诉我们：

```py
 λ python3 -m venv .env
  source .env/bin/activate
 F
 ======================================================================
 FAIL: test_fibo (__main__.Test)
 ----------------------------------------------------------------------
 Traceback (most recent call last):
 File "test_fibo.py", line 8, in test_fibo
 self.assertEqual(result, 3)
 AssertionError: 5 != 3

 ----------------------------------------------------------------------
 Ran 1 test in 0.000s

 FAILED (failures=1)
```

我们的`fibonacci`函数似乎有一个 bug，写它的人忘记了对于`n=0`应该返回`0`。修复函数并再次运行测试显示函数现在是正确的：

```py

    λ python test_fibo.py
 .
 ----------------------------------------------------------------------
 Ran 1 test in 0.000s

 OK
```

这很好，当然是朝着正确的方向迈出的一步。但请注意，为了编写这个非常简单的检查，我们必须做一些与检查本身无关的事情：

1.  导入`unittest`

1.  创建一个从`unittest.TestCase`继承的类

1.  使用`self.assertEqual()`进行检查；有很多`self.assert*`方法应该用于所有情况，比如`self.assertGreaterEqual`（用于≥比较），`self.assertLess`（用于<比较），`self.assertAlmostEqual`（用于浮点数比较），`self.assertMultiLineEqual()`（用于多行字符串比较），等等

上述内容感觉像是不必要的样板文件，虽然这当然不是世界末日，但有些人觉得这段代码不符合 Pythonic 的风格；代码只是为了迎合框架而编写的。

此外，`unittest`框架在帮助您编写真实世界的测试方面并没有提供太多内置功能。需要临时目录吗？您需要自己创建并在之后清理。需要连接到 PostgreSQL 数据库来测试 Flask 应用程序？您需要编写支持代码来连接到数据库，创建所需的表，并在测试结束时进行清理。需要在测试之间共享实用程序测试函数和资源吗？您需要创建基类并通过子类化重用它们，在大型代码库中可能会演变成多重继承。一些框架提供自己的`unittest`支持代码（例如 Django，[`www.djangoproject.com/`](https://www.djangoproject.com/)），但这些框架很少。

# 为什么选择 pytest？

Pytest 是一个成熟且功能齐全的测试框架，从小型测试到应用程序和库的大规模功能测试。

Pytest 很容易上手。要编写测试，您不需要类；您可以编写以`test`开头并使用 Python 内置的`assert`语句的简单函数：

```py
    from fibo import fibonacci

    def test_fibo():
        assert fibonacci(4) == 3
```

就是这样。您导入您的代码，编写一个函数，并使用普通的 assert 调用来确保它们按您的期望工作：无需创建子类并使用各种`self.assert*`方法来进行测试。而美妙的是，当断言失败时，它还提供了有用的输出：

```py
 λ pytest test_fibo2.py -q
 F                                                              [100%]
 ============================= FAILURES ==============================
 _____________________________ test_fibo _____________________________

 def test_fibo():
 >       assert fibonacci(4) == 3
 E       assert 5 == 3
 E        + where 5 = fibonacci(4)

 test_fibo2.py:4: AssertionError
 1 failed in 0.03 seconds
```

请注意，表达式中涉及的值和周围的代码都会显示出来，以便更容易理解错误。

Pytest 不仅使编写测试变得**简单**，它还有许多**命令行选项来提高生产力**，比如仅运行最后失败的测试，或者按名称或特殊标记运行特定组的测试。

创建和管理测试资源是经常被忽视的重要方面，通常在教程或测试框架的概述中被忽略。真实应用程序的测试通常需要复杂的设置，比如启动后台工作程序，填充数据库或初始化 GUI。使用 pytest，这些复杂的测试资源可以通过一个称为**fixtures**的强大机制来管理。fixtures 使用简单，但同时非常强大，许多人称之为*pytest 的杀手功能*。它们将在第四章中详细介绍，*Fixtures*。

定制很重要，pytest 通过定义一个非常强大的**插件**系统进一步发展。插件可以改变测试运行的多个方面，从测试的执行方式到提供新的 fixtures 和功能，以便轻松测试许多类型的应用程序和框架。有一些插件每次以随机顺序执行测试，以确保测试不会改变可能影响其他测试的全局状态，有一些插件多次重复执行失败的测试以排除不稳定的行为，有一些插件在测试运行结束时显示失败，而不仅仅是在最后显示，还有一些插件在多个 CPU 上执行测试以加快测试套件的速度。还有一些插件在测试 Django、Flask、Twisted 和 Qt 应用程序时非常有用，还有一些插件用于使用 Selenium 进行 Web 应用程序的验收测试。外部插件的数量真的令人震惊：在撰写本文时，有超过 500 个 pytest 插件可供安装和立即使用（[`plugincompat.herokuapp.com/`](http://plugincompat.herokuapp.com/)）。

总结 pytest：

+   您可以使用普通的`assert`语句来编写您的检查，并进行详细的报告

+   pytest 具有自动测试发现功能

+   它有 fixtures 来管理测试资源

+   它有许多插件，可以扩展其内置功能，并帮助测试大量的框架和应用程序

+   它可以直接运行基于`unittest`的测试套件，无需任何修改，因此您可以逐渐迁移现有的测试套件

因此，许多人认为 pytest 是在 Python 中编写测试的一种 Pythonic 方法。它使编写简单的测试变得容易，并且足够强大，可以编写非常复杂的功能测试。然而，更重要的是，pytest 让测试变得有趣。

使用 pytest 编写自动化测试，并享受它们的诸多好处，将会变得自然而然。

# 摘要

在本章中，我们介绍了为什么编写测试对于生产高质量软件以及让您有信心引入变化是重要的。之后，我们看了一下内置的`unittest`模块以及如何使用它来编写测试。最后，我们简要介绍了 pytest，发现了使用它编写测试是多么简单，看了它的主要特点，还看了大量覆盖各种用例和框架的第三方插件。

在下一章中，我们将学习如何安装 pytest，如何编写简单的测试，如何更好地将它们组织到项目的文件和目录中，以及如何有效地使用命令行。
