# PyTest 快速启动指南（一）

> 原文：[`zh.annas-archive.org/md5/ef4cd099dd041b2b3c7ad8b8d5fa4114`](https://zh.annas-archive.org/md5/ef4cd099dd041b2b3c7ad8b8d5fa4114)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

自动化测试是开发人员工具中非常重要的工具。拥有一组自动化测试不仅可以提高生产力和软件质量；它还可以作为开发人员的安全网，并在代码重构方面带来信心。Python 自带了一个标准的`unittest`模块，用于编写自动化测试，但也有一个替代方案：pytest。pytest 框架简单易用，从简单的单元测试一直扩展到复杂的集成测试。许多人认为它在方法上是真正 Pythonic 的，具有简单的功能、简单的断言、固定装置、插件和一整套功能。越来越多的开发人员正在采用全面的测试方法，那么为什么不使用一个既简单又强大的框架，许多人认为它是一种真正的乐趣呢？

# 这本书适合谁

这本书适合任何希望开始使用 pytest 来提高其日常工作中测试技能的人。它涵盖了从安装 pytest 及其更重要的功能，一直到将现有的基于`unittest`的测试套件转换为 pytest 的技巧和技巧。还有一些基于作者多年的测试和 pytest 经验的技巧和讨论。在本书中，我们将通过几个代码示例，并且只需要中级水平的 Python，尽管如果您有一些`unittest`经验，您会更喜欢这本书。

# 本书涵盖内容

第一章，*介绍 pytest*，讨论了为什么测试很重要，快速概述了标准的`unittest`模块，最后介绍了 pytest 的主要特性。

第二章，*编写和运行测试*，涵盖了 pytest 的安装，pytest 如何仅使用`assert`语句来检查值，测试模块组织，以及一些非常有用的命令行选项，以提高生产力。

第三章，*标记和参数化*，解释了 pytest 的*标记*如何工作，如何根据特定条件跳过测试，并讨论了预期失败和不稳定测试之间的区别（以及如何处理）。最后，我们将学习如何使用`parametrize`标记将不同的输入集应用于相同的测试代码片段，避免重复，并邀请我们覆盖更多的输入情况。

第四章，*固定装置*，探讨了 pytest 更受欢迎的功能之一，*固定装置*。我们还将介绍一些内置的固定装置，最后介绍一些技巧和诀窍，以更充分地利用测试套件中的固定装置。

第五章，*插件*，介绍了如何在丰富的插件生态系统中安装和搜索有用的插件，还介绍了一系列作者在日常工作中发现有趣和/或必须的各种插件。

第六章，*将 unittest 套件转换为 pytest*，介绍了一系列技术，将帮助您开始使用 pytest，即使您所有的测试都是使用`unittest`框架编写的。它涵盖了从无需更改即可运行测试套件，一直到使用经过时间考验的技术将其转换为利用 pytest 功能。

第七章，*总结*，介绍了如果您想巩固 pytest 技能的可能下一步。我们还将看看友好的 pytest 社区以及如何更多地参与其中。

# 要充分利用本书

以下是您开始所需的简短清单：

+   台式电脑或笔记本电脑：pytest 适用于 Linux、Windows 和 macOS-X，因此选择您喜欢的任何系统。

+   Python 3：所有示例都是用 Python 3.6 编写的，但它们应该可以在 Python 3.4 或更高版本上使用，如果有的话，可以进行轻微修改。大多数示例也可以移植到 Python 2，但需要更多的努力，但强烈建议使用 Python 3。

+   您喜欢的文本编辑器或 IDE 来处理代码。

+   熟悉 Python：不需要太高级的知识，但是 Python 概念，如`with`语句和装饰器是很重要的。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本解压或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为**[`github.com/PacktPublishing/pytest-Quick-Start-Guide`](https://github.com/PacktPublishing/pytest-Quick-Start-Guide)**。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富图书和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码单词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。这是一个例子：“在命令提示符中键入此命令以创建`virtualenv`。”

代码块设置如下：

```py
 # contents of test_player_mechanics.py
    def test_player_hit():
        player = create_player()
        assert player.health == 100
        undead = create_undead()
        undead.hit(player)
        assert player.health == 80
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
def test_empty_name():
    with pytest.raises(InvalidCharacterNameError):
        create_character(name='', class_name='warrior')

def test_invalid_class_name():
    with pytest.raises(InvalidClassNameError):
        create_character(name='Solaire', class_name='mage')
```

任何命令行输入或输出都以以下方式编写：

```py
λ pip install pytest
```


# 第一章：编写和运行测试

在上一章中，我们讨论了为什么测试如此重要，并简要概述了`unittest`模块。我们还粗略地看了 pytest 的特性，但几乎没有尝试过。

在本章中，我们将开始使用 pytest。我们将实用主义，这意味着我们不会详尽地研究 pytest 的所有可能功能，而是为您提供快速概述基础知识，以便您能够迅速提高生产力。我们将看看如何编写测试，如何将它们组织到文件和目录中，以及如何有效地使用 pytest 的命令行。

本章涵盖以下内容：

+   安装 pytest

+   编写和运行测试

+   组织文件和包

+   有用的命令行选项

+   配置：`pytest.ini`文件

在本章中，有很多示例在命令行中输入。它们由λ字符标记。为了避免混乱并专注于重要部分，将抑制 pytest 标题（通常显示 pytest 版本、Python 版本、已安装插件等）。

让我们直接进入如何安装 pytest。

# 安装 pytest

安装 pytest 非常简单，但首先让我们花点时间回顾 Python 开发的良好实践。

所有示例都是针对 Python 3 的。如果需要，它们应该很容易适应 Python 2。

# pip 和 virtualenv

安装依赖项的推荐做法是创建一个`virtualenv`。`virtualenv`（[`packaging.python.org/guides/installing-using-pip-and-virtualenv/`](https://packaging.python.org/guides/installing-using-pip-and-virtualenv/)）就像是一个完全独立的 Python 安装，不同于操作系统自带的 Python，因此可以安全地安装应用程序所需的软件包，而不会破坏系统 Python 或工具。

现在我们将学习如何创建虚拟环境并使用 pip 安装 pytest。如果您已经熟悉`virtualenv`和 pip，可以跳过本节：

1.  在命令提示符中键入以下内容以创建`virtualenv`：

```py
λ python -m venv .env
```

1.  此命令将在当前目录中创建一个`.env`文件夹，其中包含完整的 Python 安装。在继续之前，您应该`activate` `virtualenv`：

```py
λ source .env/bin/activate
```

或者在 Windows 上：

```py
λ .env\Scripts\activate
```

这将把`virtualenv` Python 放在`$PATH`环境变量的前面，因此 Python、pip 和其他工具将从`virtualenv`而不是系统中执行。

1.  最后，要安装 pytest，请键入：

```py
λ pip install pytest
```

您可以通过键入以下内容来验证一切是否顺利进行：

```py
λ pytest --version
This is pytest version 3.5.1, imported from x:\fibo\.env36\lib\site-packages\pytest.py
```

现在，我们已经准备好可以开始了！

# 编写和运行测试

使用 pytest，您只需要创建一个名为`test_*.py`的新文件，并编写以`test`开头的测试函数：

```py
    # contents of test_player_mechanics.py
    def test_player_hit():
        player = create_player()
        assert player.health == 100
        undead = create_undead()
        undead.hit(player)
        assert player.health == 80
```

要执行此测试，只需执行`pytest`，并传递文件名：

```py
λ pytest test_player_mechanics.py
```

如果您不传递任何内容，pytest 将递归查找当前目录中的所有测试文件并自动执行它们。

您可能会在互联网上遇到使用命令行中的`py.test`而不是`pytest`的示例。原因是历史性的：pytest 曾经是`py`包的一部分，该包提供了几个通用工具，包括遵循以`py.<TAB>`开头的约定的工具，用于制表符补全，但自那时起，它已经被移动到自己的项目中。旧的`py.test`命令仍然可用，并且是`pytest`的别名，但后者是推荐的现代用法。

请注意，无需创建类；只需简单的函数和简单的`assert`语句就足够了，但如果要使用类来分组测试，也可以这样做：

```py
    class TestMechanics:

        def test_player_hit(self):
            ...

        def test_player_health_flask(self):
            ...
```

当您想要将多个测试放在同一范围下时，分组测试可能很有用：您可以根据它们所在的类执行测试，对类中的所有测试应用标记（第三章，*标记和参数化*），并创建绑定到类的固定装置（第四章，*固定装置*）。

# 运行测试

Pytest 可以以多种方式运行您的测试。现在让我们快速了解基础知识，然后在本章后面，我们将转向更高级的选项。

您可以从简单地执行`pytest`命令开始：

```py
λ pytest
```

这将递归地查找当前目录和以下所有`test_*.py`和`*_test.py`模块，并运行这些文件中找到的所有测试：

+   您可以将搜索范围缩小到特定目录：

```py
 λ pytest tests/core tests/contrib
```

+   您还可以混合任意数量的文件和目录：

```py
 λ pytest tests/core tests/contrib/test_text_plugin.py
```

+   您可以使用语法`<test-file>::<test-function-name>`执行特定的测试：

```py
 λ pytest tests/core/test_core.py::test_regex_matching
```

+   您可以执行`test`类的所有`test`方法：

```py
 λ pytest tests/contrib/test_text_plugin.py::TestPluginHooks
```

+   您可以使用语法`<test-file>::<test-class>::<test-method-name>`执行`test`类的特定`test`方法：

```py
 λ pytest tests/contrib/
      test_text_plugin.py::TestPluginHooks::test_registration
```

上面使用的语法是 pytest 内部创建的，对于每个收集的测试都是唯一的，并称为“节点 ID”或“项目 ID”。它基本上由测试模块的文件名，类和函数通过`::`字符连接在一起。

pytest 将显示更详细的输出，其中包括节点 ID，使用`-v`标志：

```py
 λ pytest tests/core -v
======================== test session starts ========================
...
collected 6 items

tests\core\test_core.py::test_regex_matching PASSED            [ 16%]
tests\core\test_core.py::test_check_options FAILED             [ 33%]
tests\core\test_core.py::test_type_checking FAILED             [ 50%]
tests\core\test_parser.py::test_parse_expr PASSED              [ 66%]
tests\core\test_parser.py::test_parse_num PASSED               [ 83%]
tests\core\test_parser.py::test_parse_add PASSED               [100%]
```

要查看有哪些测试而不运行它们，请使用`--collect-only`标志：

```py
λ pytest tests/core --collect-only
======================== test session starts ========================
...
collected 6 items
<Module 'tests/core/test_core.py'>
 <Function 'test_regex_matching'>
 <Function 'test_check_options'>
 <Function 'test_type_checking'>
<Module 'tests/core/test_parser.py'>
 <Function 'test_parse_expr'>
 <Function 'test_parse_num'>
 <Function 'test_parse_add'>

=================== no tests ran in 0.01 seconds ====================
```

如果您想要执行特定测试但无法记住其确切名称，则`--collect-only`特别有用。

# 强大的断言

您可能已经注意到，pytest 利用内置的`assert`语句来检查测试期间的假设。与其他框架相反，您不需要记住各种`self.assert*`或`self.expect*`函数。虽然一开始可能看起来不是很重要，但在使用普通断言一段时间后，您会意识到这使得编写测试更加愉快和自然。

再次，这是一个失败的示例：

```py
________________________ test_default_health ________________________

    def test_default_health():
        health = get_default_health('warrior')
>       assert health == 95
E       assert 80 == 95

tests\test_assert_demo.py:25: AssertionError
```

pytest 显示了失败的行，以及涉及失败的变量和表达式。单独来看，这已经相当酷了，但 pytest 进一步提供了有关涉及其他数据类型的失败的专门解释。

# 文本差异

当显示短字符串的解释时，pytest 使用简单的差异方法：

```py
_____________________ test_default_player_class _____________________

    def test_default_player_class():
        x = get_default_player_class()
>       assert x == 'sorcerer'
E       AssertionError: assert 'warrior' == 'sorcerer'
E         - warrior
E         + sorcerer
```

较长的字符串显示更智能的增量，使用`difflib.ndiff`快速发现差异：

```py
__________________ test_warrior_short_description ___________________

    def test_warrior_short_description():
        desc = get_short_class_description('warrior')
>       assert desc == 'A battle-hardened veteran, can equip heavy armor and weapons.'
E       AssertionError: assert 'A battle-har... and weapons.' == 'A battle-hard... and weapons.'
E         - A battle-hardened veteran, favors heavy armor and weapons.
E         ?                            ^ ^^^^
E         + A battle-hardened veteran, can equip heavy armor and weapons.
E         ?                            ^ ^^^^^^^
```

多行字符串也会被特殊处理：

```py

    def test_warrior_long_description():
        desc = get_long_class_description('warrior')
>       assert desc == textwrap.dedent('''\
            A seasoned veteran of many battles. Strength and Dexterity
            allow to yield heavy armor and weapons, as well as carry
            more equipment. Weak in magic.
            ''')
E       AssertionError: assert 'A seasoned v... \n' == 'A seasoned ve... \n'
E         - A seasoned veteran of many battles. High Strength and Dexterity
E         ?                                     -----
E         + A seasoned veteran of many battles. Strength and Dexterity
E           allow to yield heavy armor and weapons, as well as carry
E         - more equipment while keeping a light roll. Weak in magic.
E         ?               ---------------------------
E         + more equipment. Weak in magic. 
```

# 列表

列表的断言失败也默认只显示不同的项目：

```py
____________________ test_get_starting_equiment _____________________

    def test_get_starting_equiment():
        expected = ['long sword', 'shield']
>       assert get_starting_equipment('warrior') == expected
E       AssertionError: assert ['long sword'...et', 'shield'] == ['long sword', 'shield']
E         At index 1 diff: 'warrior set' != 'shield'
E         Left contains more items, first extra item: 'shield'
E         Use -v to get the full diff

tests\test_assert_demo.py:71: AssertionError
```

请注意，pytest 显示了哪个索引不同，并且`-v`标志可用于显示列表之间的完整差异：

```py
____________________ test_get_starting_equiment _____________________

    def test_get_starting_equiment():
        expected = ['long sword', 'shield']
>       assert get_starting_equipment('warrior') == expected
E       AssertionError: assert ['long sword'...et', 'shield'] == ['long sword', 'shield']
E         At index 1 diff: 'warrior set' != 'shield'
E         Left contains more items, first extra item: 'shield'
E         Full diff:
E         - ['long sword', 'warrior set', 'shield']
E         ?               ---------------
E         + ['long sword', 'shield']

tests\test_assert_demo.py:71: AssertionError
```

如果差异太大，pytest 足够聪明，只显示一部分以避免显示太多输出，显示以下消息：

```py
E         ...Full output truncated (100 lines hidden), use '-vv' to show
```

# 字典和集合

字典可能是 Python 中最常用的数据结构之一，因此 pytest 为其提供了专门的表示：

```py
_______________________ test_starting_health ________________________

    def test_starting_health():
        expected = {'warrior': 85, 'sorcerer': 50}
>       assert get_classes_starting_health() == expected
E       AssertionError: assert {'knight': 95...'warrior': 85} == {'sorcerer': 50, 'warrior': 85}
E         Omitting 1 identical items, use -vv to show
E         Differing items:
E         {'sorcerer': 55} != {'sorcerer': 50}
E         Left contains more items:
E         {'knight': 95}
E         Use -v to get the full diff
```

集合也具有类似的输出：

```py
________________________ test_player_classes ________________________

    def test_player_classes():
>       assert get_player_classes() == {'warrior', 'sorcerer'}
E       AssertionError: assert {'knight', 's...r', 'warrior'} == {'sorcerer', 'warrior'}
E         Extra items in the left set:
E         'knight'
E         Use -v to get the full diff
```

与列表一样，还有`-v`和`-vv`选项以显示更详细的输出。

# pytest 是如何做到的？

默认情况下，Python 的 assert 语句在失败时不提供任何详细信息，但正如我们刚才看到的，pytest 显示了有关失败断言中涉及的变量和表达式的大量信息。那么 pytest 是如何做到的呢？

pytest 能够提供有用的异常，因为它实现了一种称为“断言重写”的机制。

断言重写通过安装自定义导入钩子来拦截标准 Python 导入机制。当 pytest 检测到即将导入测试文件（或插件）时，它首先将源代码编译成**抽象语法树**（**AST**），使用内置的`ast`模块。然后，它搜索任何`assert`语句并*重写*它们，以便保留表达式中使用的变量，以便在断言失败时显示更有帮助的消息。最后，它将重写后的`pyc`文件保存到磁盘进行缓存。

这一切可能看起来非常神奇，但实际上这个过程是简单的、确定性的，而且最重要的是完全透明的。

如果您想了解更多细节，请参考[`pybites.blogspot.com.br/2011/07/behind-scenes-of-pytests-new-assertion.html`](http://pybites.blogspot.com.br/2011/07/behind-scenes-of-pytests-new-assertion.html)，由此功能的原始开发者 Benjamin Peterson 编写。`pytest-ast-back-to-python`插件会准确显示重写过程后测试文件的 AST 是什么样子的。请参阅：[`github.com/tomviner/pytest-ast-back-to-python`](https://github.com/tomviner/pytest-ast-back-to-python)。

# 检查异常：pytest.raises

良好的 API 文档将清楚地解释每个函数的目的、参数和返回值。优秀的 API 文档还清楚地解释了在何时引发异常。

因此，测试异常在适当情况下引发的情况，和测试 API 的主要功能一样重要。还要确保异常包含适当和清晰的消息，以帮助用户理解问题。

假设我们正在为一个游戏编写 API。这个 API 允许程序员编写`mods`，这是一种插件，可以改变游戏的多个方面，从新的纹理到完全新的故事情节和角色类型。

这个 API 有一个函数，允许模块编写者创建一个新的角色，并且在某些情况下可能会引发异常：

```py
def create_character(name: str, class_name: str) -> Character:
    """
    Creates a new character and inserts it into the database.

    :raise InvalidCharacterNameError:
        if the character name is empty.

    :raise InvalidClassNameError:
        if the class name is invalid.

    :return: the newly created Character.
    """
    ...
```

Pytest 使得检查代码是否使用`raises`语句引发了适当的异常变得容易：

```py
def test_empty_name():
    with pytest.raises(InvalidCharacterNameError):
        create_character(name='', class_name='warrior')

def test_invalid_class_name():
    with pytest.raises(InvalidClassNameError):
        create_character(name='Solaire', class_name='mage')
```

`pytest.raises`是一个 with 语句，它确保传递给它的异常类将在其执行块内被**触发**。更多细节请参阅（[`docs.python.org/3/reference/compound_stmts.html#the-with-statement`](https://docs.python.org/3/reference/compound_stmts.html#the-with-statement)）。让我们看看`create_character`如何实现这些检查：

```py
def create_character(name: str, class_name: str) -> Character:
    """
    Creates a new character and inserts it into the database.
    ...
    """
    if not name:
        raise InvalidCharacterNameError('character name empty')

    if class_name not in VALID_CLASSES:
        msg = f'invalid class name: "{class_name}"'
        raise InvalidCharacterNameError(msg)
    ...
```

如果您仔细观察，您可能会注意到前面代码中的复制粘贴错误实际上应该为类名检查引发一个`InvalidClassNameError`。

执行此文件：

```py
======================== test session starts ========================
...
collected 2 items

tests\test_checks.py .F                                        [100%]

============================= FAILURES ==============================
______________________ test_invalid_class_name ______________________

 def test_invalid_class_name():
 with pytest.raises(InvalidCharacterNameError):
>           create_character(name='Solaire', class_name='mage')

tests\test_checks.py:51:
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

name = 'Solaire', class_name = 'mage'

 def create_character(name: str, class_name: str) -> Character:
 """
 Creates a new character and inserts it into the database.

 :param name: the character name.

 :param class_name: the character class name.

 :raise InvalidCharacterNameError:
 if the character name is empty.

 :raise InvalidClassNameError:
 if the class name is invalid.

 :return: the newly created Character.
 """
 if not name:
 raise InvalidCharacterNameError('character name empty')

 if class_name not in VALID_CLASSES:
 msg = f'invalid class name: "{class_name}"'
>           raise InvalidClassNameError(msg)
E           test_checks.InvalidClassNameError: invalid class name: "mage"

tests\test_checks.py:40: InvalidClassNameError
================ 1 failed, 1 passed in 0.05 seconds =================
```

`test_empty_name`按预期通过。`test_invalid_class_name`引发了`InvalidClassNameError`，因此异常未被`pytest.raises`捕获，这导致测试失败（就像任何其他异常一样）。

# 检查异常消息

正如本节开头所述，API 应该在引发异常时提供清晰的消息。在前面的例子中，我们只验证了代码是否引发了适当的异常类型，但没有验证实际消息。

`pytest.raises`可以接收一个可选的`match`参数，这是一个正则表达式字符串，将与异常消息匹配，以及检查异常类型。更多细节，请访问：[`docs.python.org/3/howto/regex.html`](https://docs.python.org/3/howto/regex.html)。我们可以使用它来进一步改进我们的测试：

```py
def test_empty_name():
    with pytest.raises(InvalidCharacterNameError,
                       match='character name empty'):
        create_character(name='', class_name='warrior')

def test_invalid_class_name():
    with pytest.raises(InvalidClassNameError,
                       match='invalid class name: "mage"'):
        create_character(name='Solaire', class_name='mage')
```

简单！

# 检查警告：pytest.warns

API 也在不断发展。为旧功能提供新的更好的替代方案，删除参数，旧的使用某个功能的方式演变为更好的方式，等等。

API 编写者必须在保持旧代码正常工作以避免破坏客户端和提供更好的方法之间取得平衡，同时保持自己的 API 代码可维护。因此，通常采用的解决方案是开始在 API 客户端使用旧行为时发出`warnings`，希望他们更新其代码以适应新的结构。警告消息显示在当前用法不足以引发异常的情况下，只是发生了新的更好的方法。通常，在此更新期间会显示警告消息，之后旧的方式将不再受支持。

Python 提供了标准的 warnings 模块，专门用于此目的，可以轻松地警告开发人员关于 API 中即将发生的更改。有关更多详细信息，请访问：[`docs.python.org/3/library/warnings.html`](https://docs.python.org/3/library/warnings.html)。它让您可以从多个警告类中进行选择，例如：

+   `UserWarning`: 用户警告（这里的“用户”指的是开发人员，而不是软件用户）

+   `DeprecationWarning`: features that will be removed in the future

+   `ResourcesWarning`: 与资源使用相关

（此列表不是详尽无遗的。请查阅警告文档以获取完整列表。有关更多详细信息，请访问：[`docs.python.org/3/library/warnings.html`](https://docs.python.org/3/library/warnings.html)）。

警告类帮助用户控制应该显示哪些警告，哪些应该被抑制。

例如，假设一个电脑游戏的 API 提供了这个方便的函数，可以根据玩家角色的类名获取起始生命值：

```py
def get_initial_hit_points(player_class: str) -> int:
    ...
```

时间在流逝，开发人员决定在下一个版本中使用`enum`而不是类名。有关更多详细信息，请访问：[`docs.python.org/3/library/enum.html`](https://docs.python.org/3/library/enum.html)，这更适合表示有限的一组值：

```py
class PlayerClass(Enum):
    WARRIOR = 1
    KNIGHT = 2
    SORCERER = 3
    CLERIC = 4
```

但是突然更改这一点会破坏所有客户端，因此他们明智地决定在下一个版本中支持这两种形式：`str`和`PlayerClass` `enum`。他们不想永远支持这一点，因此他们开始在将类作为`str`传递时显示警告：

```py
def get_initial_hit_points(player_class: Union[PlayerClass, str]) -> int:
    if isinstance(player_class, str):
        msg = 'Using player_class as str has been deprecated' \
              'and will be removed in the future'
        warnings.warn(DeprecationWarning(msg))
        player_class = get_player_enum_from_string(player_class)
    ...
```

与上一节的`pytest.raises`类似，`pytest.warns`函数让您测试 API 代码是否产生了您期望的警告：

```py
def test_get_initial_hit_points_warning():
    with pytest.warns(DeprecationWarning):
        get_initial_hit_points('warrior')
```

与`pytest.raises`一样，`pytest.warns`可以接收一个可选的`match`参数，这是一个正则表达式字符串。将与异常消息匹配：有关更多详细信息，请访问：[`docs.python.org/3/howto/regex.html`](https://docs.python.org/3/howto/regex.html)，

```py
def test_get_initial_hit_points_warning():
    with pytest.warns(DeprecationWarning,
                      match='.*str has been deprecated.*'):
        get_initial_hit_points('warrior')
```

# 比较浮点数：pytest.approx

比较浮点数可能会很棘手。有关更多详细信息，请访问：[`docs.python.org/3/tutorial/floatingpoint.html`](https://docs.python.org/3/tutorial/floatingpoint.html)。在现实世界中我们认为相等的数字，在计算机硬件表示时并非如此：

```py
>>> 0.1 + 0.2 == 0.3
False
```

在编写测试时，很常见的是将我们的代码产生的结果与我们期望的浮点值进行比较。如上所示，简单的`==`比较通常是不够的。一个常见的方法是使用已知的公差，然后使用`abs`来正确处理负数：

```py
def test_simple_math():
    assert abs(0.1 + 0.2) - 0.3 < 0.0001
```

但是，除了难看和难以理解之外，有时很难找到适用于大多数情况的公差。所选的`0.0001`的公差可能适用于上面的数字，但对于非常大的数字或非常小的数字则不适用。根据所执行的计算，您需要为每组输入数字找到一个合适的公差，这是繁琐且容易出错的。

`pytest.approx`通过自动选择适用于表达式中涉及的值的公差来解决这个问题，还提供了非常好的语法：

```py
def test_approx_simple():
    assert 0.1 + 0.2 == approx(0.3)
```

您可以将上述内容理解为`断言 0.1 + 0.2 大约等于 0.3`。

但是`approx`函数并不止于此；它可以用于比较：

+   数字序列：

```py
      def test_approx_list():
          assert [0.1 + 1.2, 0.2 + 0.8] == approx([1.3, 1.0])
```

+   字典`values`（而不是键）：

```py
      def test_approx_dict():
          values = {'v1': 0.1 + 1.2, 'v2': 0.2 + 0.8}
          assert values == approx(dict(v1=1.3, v2=1.0))
```

+   `numpy`数组：

```py
      def test_approx_numpy():
          import numpy as np
          values = np.array([0.1, 0.2]) + np.array([1.2, 0.8])
          assert values == approx(np.array([1.3, 1.0]))
```

当测试失败时，`approx`提供了一个很好的错误消息，显示了失败的值和使用的公差：

```py
    def test_approx_simple_fail():
>       assert 0.1 + 0.2 == approx(0.35)
E       assert (0.1 + 0.2) == 0.35 ± 3.5e-07
E        + where 0.35 ± 3.5e-07 = approx(0.35)
```

# 组织文件和包

Pytest 需要导入您的代码和测试模块，您可以自行决定如何组织它们。Pytest 支持两种常见的测试布局，我们将在下面讨论。

# 伴随您的代码的测试

您可以通过在模块旁边创建一个`tests`文件夹，将测试模块放在它们测试的代码旁边：

```py
setup.py
mylib/
    tests/
         __init__.py
         test_core.py
         test_utils.py    
    __init__.py
    core.py
    utils.py
```

通过将测试放在测试代码附近，您将获得以下优势：

+   在这种层次结构中更容易添加新的测试和测试模块，并保持它们同步

+   您的测试现在是您包的一部分，因此它们可以在其他环境中部署和运行

这种方法的主要缺点是，有些人不喜欢额外模块增加的包大小，这些模块现在与其余代码一起打包，但这通常是微不足道的，不值一提。

作为额外的好处，您可以使用`--pyargs`选项来指定使用模块导入路径的测试。例如：

```py
λ pytest --pyargs mylib.tests
```

这将执行在`mylib.tests`下找到的所有测试模块。

您可能考虑使用`_tests`而不是`_test`作为测试模块名称。这样可以更容易找到目录，因为前导下划线通常会使它们出现在文件夹层次结构的顶部。当然，随意使用`tests`或任何其他您喜欢的名称；pytest 不在乎，只要测试模块本身的名称为`test_*.py`或`*_test.py`。

# 测试与代码分离

与上述方法的替代方法是将测试组织在与主包不同的目录中：

```py
setup.py
mylib/  
    __init__.py
    core.py
    utils.py
tests/
    __init__.py
    test_core.py
    test_utils.py 
```

有些人更喜欢这种布局，因为：

+   它将库代码和测试代码分开

+   测试代码不包含在源包中

上述方法的一个缺点是，一旦您有一个更复杂的层次结构，您可能希望保持测试目录内部的相同层次结构，这可能更难维护和保持同步：

```py
mylib/  
    __init__.py
    core/
        __init__.py
        foundation.py
    contrib/
        __init__.py
        text_plugin.py
tests/
    __init__.py
    core/
        __init__.py
        test_foundation.py
    contrib/
        __init__.py
        test_text_plugin.py
```

那么，哪种布局最好呢？两种布局都有优点和缺点。Pytest 本身可以很好地与它们中的任何一个一起使用，所以请随意选择您更舒适的布局。

# 有用的命令行选项

现在我们将看一下命令行选项，这些选项将使您在日常工作中更加高效。正如本章开头所述，这不是所有命令行功能的完整列表；只是您将使用（并喜爱）最多的那些。

# 关键字表达式：-k

通常情况下，您可能不完全记得要执行的测试的完整路径或名称。在其他时候，您的套件中的许多测试遵循相似的模式，您希望执行所有这些测试，因为您刚刚重构了代码的一个敏感区域。

通过使用`-k <EXPRESSION>`标志（来自*关键字表达式*），您可以运行`item id`与给定表达式松散匹配的测试：

```py
λ pytest -k "test_parse"
```

这将执行所有包含其项目 ID 中包含字符串`parse`的测试。您还可以使用布尔运算符编写简单的 Python 表达式：

```py
λ pytest -k "parse and not num"
```

这将执行所有包含`parse`但不包含`num`的测试。

# 尽快停止：-x，--maxfail

在进行大规模重构时，您可能事先不知道如何或哪些测试会受到影响。在这种情况下，您可能会尝试猜测哪些模块会受到影响，并开始运行这些模块的测试。但是，通常情况下，您会发现自己破坏了比最初估计的更多的测试，并迅速尝试通过按下`CTRL+C`来停止测试会话，当一切开始意外地失败时。

在这些情况下，您可以尝试使用`--maxfail=N`命令行标志，该标志在`N`次失败或错误后自动停止测试会话，或者快捷方式`-x`，它等于`--maxfail=1`。

```py
λ pytest tests/core -x
```

这使您可以快速查看第一个失败的测试并处理失败。修复失败原因后，您可以继续使用`-x`来处理下一个问题。

如果您觉得这很棒，您不会想跳过下一节！

# 上次失败，首先失败：--lf，--ff

Pytest 始终记住以前会话中失败的测试，并可以重用该信息以直接跳转到以前失败的测试。如果您在大规模重构后逐步修复测试套件，这是一个好消息，如前一节所述。

您可以通过传递`--lf`标志（意思是*上次失败*）来运行以前失败的测试：

```py
λ pytest --lf tests/core
...
collected 6 items / 4 deselected
run-last-failure: rerun previous 2 failures
```

当与`-x`（`--maxfail=1`）一起使用时，这两个标志是重构的天堂：

```py
λ pytest -x --lf 
```

这样你就可以开始执行完整的测试套件，然后 pytest 在第一个失败的测试停止。你修复代码，然后再次执行相同的命令行。Pytest 会直接从失败的测试开始，如果通过（或者如果你还没有成功修复代码，则再次停止）。然后它会在下一个失败处停止。反复进行，直到所有测试再次通过。

请记住，无论您在重构过程中执行了另一个测试子集，pytest 始终会记住哪些测试失败了，而不管执行的命令行是什么。

如果您曾经进行过大规模重构，并且必须跟踪哪些测试失败，以便不会浪费时间一遍又一遍地运行测试套件，那么您肯定会欣赏这种提高生产力的方式。

最后，`--ff`标志类似于`--lf`，但它将重新排序您的测试，以便首先运行以前失败的测试，然后是通过的测试或尚未运行的测试：

```py
λ pytest -x --lf
======================== test session starts ========================
...
collected 6 items
run-last-failure: rerun previous 2 failures first
```

# 输出捕获：-s 和--capture

有时，开发人员会错误地留下`print`语句，甚至故意留下以供以后调试使用。有些应用程序也可能会在正常操作或日志记录的过程中写入`stdout`或`stderr`。

所有这些输出会使理解测试套件的显示变得更加困难。因此，默认情况下，pytest 会自动捕获写入`stdout`和`stderr`的所有输出。

考虑这个函数来计算给定文本的哈希值，其中留下了一些调试代码：

```py
import hashlib

def commit_hash(contents):
    size = len(contents)
    print('content size', size)
    hash_contents = str(size) + '\0' + contents
    result = hashlib.sha1(hash_contents.encode('UTF-8')).hexdigest()
    print(result)
    return result[:8]
```

我们对此有一个非常简单的测试：

```py
def test_commit_hash():
    contents = 'some text contents for commit'
    assert commit_hash(contents) == '0cf85793'
```

在执行此测试时，默认情况下，您将看不到`print`调用的输出：

```py
λ pytest tests\test_digest.py
======================== test session starts ========================
...

tests\test_digest.py .                                         [100%]

===================== 1 passed in 0.03 seconds ======================
```

这很干净。

但这些打印语句是为了帮助您理解和调试代码，这就是为什么 pytest 会在测试**失败**时显示捕获的输出。

让我们更改哈希文本的内容，但不更改哈希本身。现在，pytest 将在错误回溯后的单独部分显示捕获的输出：

```py
λ pytest tests\test_digest.py
======================== test session starts ========================
...

tests\test_digest.py F                                         [100%]

============================= FAILURES ==============================
_________________________ test_commit_hash __________________________

 def test_commit_hash():
 contents = 'a new text emerges!'
>       assert commit_hash(contents) == '0cf85793'
E       AssertionError: assert '383aa486' == '0cf85793'
E         - 383aa486
E         + 0cf85793

tests\test_digest.py:15: AssertionError
----------------------- Captured stdout call ------------------------
content size 19
383aa48666ab84296a573d1f798fff3b0b176ae8
===================== 1 failed in 0.05 seconds ======================
```

在本地运行测试时，显示失败测试的捕获输出非常方便，甚至在 CI 上运行测试时也是如此。

# 使用-s 禁用捕获

在本地运行测试时，您可能希望禁用输出捕获，以查看实时打印的消息，或者捕获是否干扰了代码可能正在进行的其他捕获。

在这些情况下，只需向 pytest 传递`-s`以完全禁用捕获：

```py
λ pytest tests\test_digest.py -s
======================== test session starts ========================
...

tests\test_digest.py content size 29
0cf857938e0b4a1b3fdd41d424ae97d0caeab166
.

===================== 1 passed in 0.02 seconds ======================
```

# 使用--capture 捕获方法

Pytest 有两种捕获输出的方法。可以使用`--capture`命令行标志选择使用哪种方法：

+   `--capture=fd`：在**文件描述符级别**捕获输出，这意味着所有写入文件描述符 1（stdout）和 2（stderr）的输出都会被捕获。这将捕获来自 C 扩展的输出，这也是默认值。

+   `--capture=sys`：捕获直接写入`sys.stdout`和`sys.stderr`的输出，而不尝试捕获系统级文件描述符。

通常情况下，您不需要更改这个，但在一些特殊情况下，根据您的代码正在执行的操作，更改捕获方法可能会有用。

为了完整起见，还有`--capture=no`，它与`-s`相同。

# 回溯模式和本地变量：--tb，--showlocals

Pytest 将显示失败测试的完整回溯，这是测试框架所期望的。但是，默认情况下，它不会显示大多数 Python 程序员习惯的标准回溯；它显示了不同的回溯：

```py
============================= FAILURES ==============================
_______________________ test_read_properties ________________________

 def test_read_properties():
 lines = DATA.strip().splitlines()
> grids = list(iter_grids_from_csv(lines))

tests\test_read_properties.py:32:
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
tests\test_read_properties.py:27: in iter_grids_from_csv
 yield parse_grid_data(fields)
tests\test_read_properties.py:21: in parse_grid_data
 active_cells=convert_size(fields[2]),
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

s = 'NULL'

 def convert_size(s):
> return int(s)
E ValueError: invalid literal for int() with base 10: 'NULL'

tests\test_read_properties.py:14: ValueError
===================== 1 failed in 0.05 seconds ======================
```

这种回溯仅显示回溯堆栈中所有帧的单行代码和文件位置，除了第一个和最后一个，其中还显示了一部分代码（加粗）。

虽然一开始有些人可能会觉得奇怪，但一旦你习惯了，你就会意识到它使查找错误原因变得更简单。通过查看回溯的起始和结束周围的代码，通常可以更好地理解错误。我建议您尝试在几周内习惯 pytest 提供的默认回溯；我相信您会喜欢它，永远不会回头。

然而，如果您不喜欢 pytest 的默认回溯，还有其他回溯模式，由`--tb`标志控制。默认值是`--tb=auto`，如前所示。让我们在下一节概览其他模式。

# --tb=long

这种模式将显示失败回溯的**所有帧**的**代码部分**，使其相当冗长。

```py
============================= FAILURES ==============================
_______________________ t________

 def test_read_properties():
 lines = DATA.strip().splitlines()
>       grids = list(iter_grids_from_csv(lines))

tests\test_read_properties.py:32:
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

lines = ['Main Grid,48,44', '2nd Grid,24,21', '3rd Grid,24,null']

 def iter_grids_from_csv(lines):
 for fields in csv.reader(lines):
>       yield parse_grid_data(fields)

tests\test_read_properties.py:27:
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

fields = ['3rd Grid', '24', 'null']

 def parse_grid_data(fields):
 return GridData(
 name=str(fields[0]),
 total_cells=convert_size(fields[1]),
>       active_cells=convert_size(fields[2]),
 )

tests\test_read_properties.py:21:
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

s = 'null'

 def convert_size(s):
>       return int(s)
E       ValueError: invalid literal for int() with base 10: 'null'

tests\test_read_properties.py:14: ValueError
===================== 1 failed in 0.05 seconds ======================
```

# --tb=short

这种模式将显示失败回溯的所有帧的代码的一行，提供简短而简洁的输出：

```py
============================= FAILURES ==============================
_______________________ test_read_properties ________________________
tests\test_read_properties.py:32: in test_read_properties
 grids = list(iter_grids_from_csv(lines))
tests\test_read_properties.py:27: in iter_grids_from_csv
 yield parse_grid_data(fields)
tests\test_read_properties.py:21: in parse_grid_data
 active_cells=convert_size(fields[2]),
tests\test_read_properties.py:14: in convert_size
 return int(s)
E   ValueError: invalid literal for int() with base 10: 'null'
===================== 1 failed in 0.04 seconds ======================
```

# --tb=native

这种模式通常会输出 Python 用于报告异常的完全相同的回溯，受到纯粹主义者的喜爱：

```py
_______________________ test_read_properties ________________________
Traceback (most recent call last):
 File "X:\CH2\tests\test_read_properties.py", line 32, in test_read_properties
 grids = list(iter_grids_from_csv(lines))
 File "X:\CH2\tests\test_read_properties.py", line 27, in iter_grids_from_csv
 yield parse_grid_data(fields)
 File "X:\CH2\tests\test_read_properties.py", line 21, in parse_grid_data
 active_cells=convert_size(fields[2]),
 File "X:\CH2\tests\test_read_properties.py", line 14, in convert_size
 return int(s)
ValueError: invalid literal for int() with base 10: 'null'
===================== 1 failed in 0.03 seconds ======================
```

# --tb=line

这种模式将为每个失败的测试显示一行，仅显示异常消息和错误的文件位置：

```py
============================= FAILURES ==============================
X:\CH2\tests\test_read_properties.py:14: ValueError: invalid literal for int() with base 10: 'null'
```

如果您正在进行大规模重构并且预计会有大量失败，之后打算使用`--lf -x`标志进入**重构天堂模式**，则此模式可能会有用。

# --tb=no

这不会显示任何回溯或失败消息，因此在运行套件以获取有多少失败的概念后，也可以使用`--lf -x`标志逐步修复测试：

```py
tests\test_read_properties.py F                                [100%]

===================== 1 failed in 0.04 seconds ======================
```

# --showlocals（-l）

最后，虽然这不是一个特定的回溯模式标志，`--showlocals`（或`-l`作为快捷方式）通过显示在使用`--tb=auto`、`--tb=long`和`--tb=short`模式时的**本地变量及其值**列表来增强回溯模式。

例如，这是`--tb=auto`和`--showlocals`的输出：

```py
_______________________ test_read_properties ________________________

 def test_read_properties():
 lines = DATA.strip().splitlines()
>       grids = list(iter_grids_from_csv(lines))

lines      = ['Main Grid,48,44', '2nd Grid,24,21', '3rd Grid,24,null']

tests\test_read_properties.py:32:
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
tests\test_read_properties.py:27: in iter_grids_from_csv
 yield parse_grid_data(fields)
tests\test_read_properties.py:21: in parse_grid_data
 active_cells=convert_size(fields[2]),
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

s = 'null'

 def convert_size(s):
>       return int(s)
E       ValueError: invalid literal for int() with base 10: 'null'

s          = 'null'

tests\test_read_properties.py:14: ValueError
===================== 1 failed in 0.05 seconds ======================
```

请注意，这样做会更容易看出坏数据来自哪里：在测试开始时从文件中读取的`'3rd Grid,24,null'`字符串。

`--showlocals`在本地运行测试和 CI 时都非常有用，深受喜爱。不过要小心，因为这可能存在安全风险：本地变量可能会暴露密码和其他敏感信息，因此请确保使用安全连接传输回溯，并小心使其公开。

# 使用--durations 进行缓慢测试

在项目开始时，您的测试套件通常运行非常快，只需几秒钟，生活很美好。但随着项目规模的增长，测试套件的测试数量和运行时间也在增加。

测试套件运行缓慢会影响生产力，特别是如果您遵循 TDD 并且一直运行测试。因此，定期查看运行时间最长的测试并分析它们是否可以更快是很有益的：也许您在一个需要更小（更快）数据集的地方使用了大型数据集，或者您可能正在执行不重要的冗余步骤，这些步骤对于实际进行的测试并不重要。

当发生这种情况时，您会喜欢`--durations=N`标志。此标志提供了`N`个运行时间最长的测试的摘要，或者使用零来查看所有测试的摘要：

```py
λ pytest --durations=5
...
===================== slowest 5 test durations ======================
3.40s call CH2/tests/test_slow.py::test_corner_case
2.00s call CH2/tests/test_slow.py::test_parse_large_file
0.00s call CH2/tests/core/test_core.py::test_type_checking
0.00s teardown CH2/tests/core/test_parser.py::test_parse_expr
0.00s call CH2/tests/test_digest.py::test_commit_hash
================ 3 failed, 7 passed in 5.51 seconds =================
```

当您开始寻找测试以加快速度时，此输出提供了宝贵的信息。

尽管这个标志不是您每天都会使用的东西，因为许多人似乎不知道它，但它值得一提。

# 额外的测试摘要：-ra

Pytest 在测试失败时显示丰富的回溯信息。额外的信息很棒，但实际的页脚对于识别哪些测试实际上失败了并不是很有帮助：

```py
...
________________________ test_type_checking _________________________

    def test_type_checking():
>       assert 0
E       assert 0

tests\core\test_core.py:12: AssertionError
=============== 14 failed, 17 passed in 5.68 seconds ================
```

可以传递 `-ra` 标志以生成一个漂亮的摘要，在会话结束时列出所有失败测试的完整名称：

```py
...
________________________ test_type_checking _________________________

 def test_type_checking():
>       assert 0
E       assert 0

tests\core\test_core.py:12: AssertionError
====================== short test summary info ======================
FAIL tests\test_assert_demo.py::test_approx_simple_fail
FAIL tests\test_assert_demo.py::test_approx_list_fail
FAIL tests\test_assert_demo.py::test_default_health
FAIL tests\test_assert_demo.py::test_default_player_class
FAIL tests\test_assert_demo.py::test_warrior_short_description
FAIL tests\test_assert_demo.py::test_warrior_long_description
FAIL tests\test_assert_demo.py::test_get_starting_equiment
FAIL tests\test_assert_demo.py::test_long_list
FAIL tests\test_assert_demo.py::test_starting_health
FAIL tests\test_assert_demo.py::test_player_classes
FAIL tests\test_checks.py::test_invalid_class_name
FAIL tests\test_read_properties.py::test_read_properties
FAIL tests\core\test_core.py::test_check_options
FAIL tests\core\test_core.py::test_type_checking
=============== 14 failed, 17 passed in 5.68 seconds ================
```

当直接从命令行运行套件时，此标志特别有用，因为在终端上滚动以查找失败的测试可能很烦人。

实际上标志是 `-r`，它接受一些单字符参数：

+   `f`（失败）：`assert` 失败

+   `e`（错误）：引发了意外的异常

+   `s`（跳过）：跳过（我们将在下一章中介绍）

+   `x`（预期失败）：预期失败，确实失败（我们将在下一章中介绍）

+   `X`（预期通过）：预期失败，但通过了（！）（我们将在下一章中介绍）

+   `p`（通过）：测试通过

+   `P`（带输出的通过）：即使是通过的测试也显示捕获的输出（小心 - 这通常会产生大量输出）

+   `a`：显示上述所有内容，但不包括 `P`；这是**默认**的，并且通常是最有用的。

该标志可以接收上述任何组合。因此，例如，如果您只对失败和错误感兴趣，可以向 pytest 传递 `-rfe`。

总的来说，我建议坚持使用 `-ra`，不要想太多，您将获得最多的好处。

# 配置：pytest.ini

用户可以使用名为 `pytest.ini` 的配置文件自定义一些 pytest 行为。该文件通常放置在存储库的根目录，并包含一些应用于该项目的所有测试运行的配置值。它旨在保持在版本控制下，并与其余代码一起提交。

格式遵循简单的 ini 样式格式，所有与 pytest 相关的选项都在`[pytest]` 部分下。有关更多详细信息，请访问：[`docs.python.org/3/library/configparser.html`](https://docs.python.org/3/library/configparser.html)。

```py
[pytest]
```

此文件的位置还定义了 pytest 称之为**根目录**（`rootdir`）的内容：如果存在，包含配置文件的目录被视为根目录。

根目录用于以下内容：

+   创建测试节点 ID

+   作为存储有关项目信息的稳定位置（由 pytest 插件和功能）

没有配置文件，根目录将取决于您从哪个目录执行 pytest 以及传递了哪些参数（算法的描述可以在这里找到：[`docs.pytest.org/en/latest/customize.html#finding-the-rootdir`](https://docs.pytest.org/en/latest/customize.html#finding-the-rootdir)）。因此，即使是最简单的项目，也始终建议在其中有一个 `pytest.ini` 文件，即使是空的。

始终定义一个 `pytest.ini` 文件，即使是空的。

如果您使用 `tox`，可以在传统的 `tox.ini` 文件中放置一个 `[pytest]` 部分，它将同样有效。有关更多详细信息，请访问：[`tox.readthedocs.io/en/latest/`](https://tox.readthedocs.io/en/latest/)：

```py
[tox]
envlist = py27,py36
...

[pytest]
# pytest options
```

这对于避免在存储库根目录中放置太多文件很有用，但这实际上是一种偏好。

现在，我们将看一下更常见的配置选项。随着我们介绍新功能，将在接下来的章节中介绍更多选项。

# 附加命令行：addopts

我们学到了一些非常有用的命令行选项。其中一些可能会成为个人喜爱，但是不得不一直输入它们会很烦人。

`addopts` 配置选项可以用来始终向命令行添加一组选项：

```py
[pytest]
addopts=--tb=native --maxfail=10 -v
```

有了这个配置，输入以下内容：

```py
λ pytest tests/test_core.py
```

与输入以下内容相同：

```py
λ pytest --tb=native --max-fail=10 -v tests/test_core.py
```

请注意，尽管它的名字是`addopts`，但实际上它是在命令行中输入其他选项之前插入选项。这使得在`addopts`中覆盖大多数选项成为可能，当显式传递它们时。

例如，以下代码现在将显示**自动**的回溯，而不是原生的回溯，如在`pytest.ini`中配置的那样：

```py
λ pytest --tb=auto tests/test_core.py
```

# 自定义收集

默认情况下，pytest 使用以下启发式方法收集测试：

+   匹配`test_*.py`和`*_test.py`的文件

+   在测试模块内部，匹配`test*`的函数和匹配`Test*`的类

+   在测试类内部，匹配`test*`的方法

这个约定很容易理解，适用于大多数项目，但可以被这些配置选项覆盖：

+   `python_files`：用于收集测试模块的模式列表

+   `python_functions`：用于收集测试函数和测试方法的模式列表

+   `python_classes`：用于收集测试类的模式列表

以下是更改默认设置的配置文件示例：

```py
[pytest]
python_files = unittests_*.py
python_functions = check_*
python_classes = *TestSuite
```

建议只在遵循不同约定的传统项目中使用这些配置选项，并对新项目使用默认设置。使用默认设置更少工作，避免混淆其他合作者。

# 缓存目录：cache_dir

`--lf`和`--ff`选项之前显示的是由一个名为`cacheprovider`的内部插件提供的，它将数据保存在磁盘上的一个目录中，以便在将来的会话中访问。默认情况下，该目录位于**根目录**下，名称为`.pytest_cache`。这个目录不应该提交到版本控制中。

如果您想要更改该目录的位置，可以使用`cache_dir`选项。该选项还会自动扩展环境变量：

```py
[pytest]
cache_dir=$TMP/pytest-cache
```

# 避免递归进入目录：norecursedirs

pytest 默认会递归遍历命令行给定的所有子目录。当递归进入从不包含任何测试的目录时，这可能会使测试收集花费比预期更多的时间，例如：

+   虚拟环境

+   构建产物

+   文档

+   版本控制目录

pytest 默认会聪明地不会递归进入具有模式`.*`、`build`、`dist`、`CVS`、`_darcs`、`{arch}`、`*.egg`、`venv`的文件夹。它还会尝试通过查看已知位置的激活脚本来自动检测 virtualenvs。

`norecursedirs`选项可用于覆盖 pytest 不应该递归进入的默认模式名称列表：

```py
[pytest]
norecursedirs = artifacts _build docs
```

您还可以使用`--collect-in-virtualenv`标志来跳过`virtualenv`检测。

一般来说，用户很少需要覆盖默认设置，但如果发现自己在项目中一遍又一遍地添加相同的目录，请考虑提交一个问题。更多细节（[`github.com/pytest-dev/pytest/issues/new`](https://github.com/pytest-dev/pytest/issues/new)）。

# 默认情况下选择正确的位置：testpaths

如前所述，常见的目录结构是*源代码之外的布局*，测试与应用程序/库代码分开存放在一个名为`tests`或类似命名的目录中。在这种布局中，使用`testpaths`配置选项非常有用：

```py
[pytest]
testpaths = tests
```

这将告诉 pytest 在命令行中没有给定文件、目录或节点 ID 时在哪里查找测试，这可能会加快测试收集的速度。请注意，您可以配置多个目录，用空格分隔。

# 使用-o/--override 覆盖选项

最后，一个鲜为人知的功能是，您可以使用`-o`/`--override`标志直接在命令行中覆盖任何配置选项。这个标志可以多次传递，以覆盖多个选项：

```py
λ pytest -o python_classes=Suite -o cache_dir=$TMP/pytest-cache
```

# 总结

在本章中，我们介绍了如何使用`virtualenv`和`pip`来安装 pytest。之后，我们深入讨论了如何编写测试，以及运行测试的不同方式，以便只执行我们感兴趣的测试。我们概述了 pytest 如何为不同的内置数据类型提供丰富的输出信息，以便查看失败的测试。我们学会了如何使用`pytest.raises`和`pytest.warns`来检查异常和警告，以及使用`pytest.approx`来避免比较浮点数时的常见问题。然后，我们简要讨论了如何在项目中组织测试文件和模块。我们还看了一些更有用的命令行选项，以便我们可以立即提高工作效率。最后，我们介绍了`pytest.ini`文件如何用于持久的命令行选项和其他配置。

在下一章中，我们将学习如何使用标记来帮助我们在特定平台上跳过测试，如何让我们的测试套件知道代码或外部库中的错误已经修复，以及如何分组测试集，以便我们可以在命令行中有选择地执行它们。之后，我们将学习如何对不同的数据集应用相同的检查，以避免复制和粘贴测试代码。


# 第二章：标记和参数化

在学习了编写和运行测试的基础知识之后，我们将深入了解两个重要的 pytest 功能：**标记**和**参数化**。

首先，我们将学习标记，它允许我们根据应用的标记选择性地运行测试，并将一般数据附加到测试函数，这些数据可以被夹具和插件使用。在同一主题中，我们将看看内置标记及其提供的内容。

其次，我们将学习**测试参数化**，它允许我们轻松地将相同的测试函数应用于一组输入值。这极大地避免了重复的测试代码，并使得很容易添加随着软件发展可能出现的新测试用例。

总之，在本章中我们将涵盖以下内容：

+   标记基础知识

+   内置标记

+   参数化

# 标记基础知识

Pytest 允许您使用元数据对函数和类进行标记。此元数据可用于选择性运行测试，并且也可用于夹具和插件，以执行不同的任务。让我们看看如何创建和应用标记到测试函数，然后再进入内置的 pytest 标记。

# 创建标记

使用`@pytest.mark`装饰器创建标记。它作为工厂工作，因此对它的任何访问都将自动创建一个新标记并将其应用于函数。通过示例更容易理解：

```py
@pytest.mark.slow
def test_long_computation():
    ...
```

通过使用`@pytest.mark.slow`装饰器，您将标记命名为`slow`应用于`test_long_computation`。

标记也可以接收**参数**：

```py
@pytest.mark.timeout(10, method="thread")
def test_topology_sort():
    ...
```

在上一个示例中使用的`@pytest.mark.timeout`来自 pytest-timeout 插件；有关更多详细信息，请访问[`pypi.org/project/pytest-timeout/`](https://pypi.org/project/pytest-timeout/)。通过这样做，我们定义了`test_topology_sort`不应超过 10 秒，在这种情况下，应使用`thread`方法终止。为标记分配参数是一个非常强大的功能，为插件和夹具提供了很大的灵活性。我们将在下一章中探讨这些功能和`pytest-timeout`插件。

您可以通过多次应用`@pytest.mark`装饰器向测试添加多个标记，例如：

```py
@pytest.mark.slow
@pytest.mark.timeout(10, method="thread")
def test_topology_sort():
    ...
```

如果您一遍又一遍地应用相同的标记，可以通过将其分配给一个变量一次并根据需要在测试中应用它来避免重复自己：

```py
timeout10 = pytest.mark.timeout(10, method="thread")

@timeout10
def test_topology_sort():
    ...

@timeout10
def test_remove_duplicate_points():
    ...
```

如果此标记在多个测试中使用，可以将其移动到测试实用程序模块并根据需要导入：

```py
from mylib.testing import timeout10

@timeout10
def test_topology_sort():
    ...

@timeout10
def test_remove_duplicate_points():
    ...
```

# 基于标记运行测试

您可以使用`-m`标志将标记作为选择因素运行测试。例如，要运行所有带有`slow`标记的测试：

```py
λ pytest -m slow
```

`-m`标志还接受表达式，因此您可以进行更高级的选择。要运行所有带有`slow`标记的测试，但不运行带有`serial`标记的测试，您可以使用：

```py
λ pytest -m "slow and not serial"
```

表达式限制为`and`，`not`和`or`运算符。

自定义标记对于优化 CI 系统上的测试运行非常有用。通常，环境问题，缺少依赖项，甚至一些错误提交的代码可能会导致整个测试套件失败。通过使用标记，您可以选择一些快速和/或足够广泛以检测代码中大部分问题的测试，然后首先运行这些测试，然后再运行所有其他测试。如果其中任何一个测试失败，我们将中止作业，并避免通过运行注定会失败的所有测试来浪费大量时间。

我们首先将自定义标记应用于这些测试。任何名称都可以，但常用的名称是`smoke`，如*烟雾探测器*，以便在一切都燃烧之前检测问题。

然后首先运行烟雾测试，只有在它们通过后才运行完整的测试套件：

```py
λ pytest -m "smoke"
...
λ pytest -m "not smoke"
```

如果任何烟雾测试失败，您不必等待整个套件完成以获得此反馈。

您可以通过创建测试的层次结构，从最简单到最慢，增加此技术。例如：

+   `smoke`

+   `unittest`

+   `integration`

+   `<其余所有>`

然后执行如下：

```py
λ pytest -m "smoke"
...
λ pytest -m "unittest"
...
λ pytest -m "integration"
...
λ pytest -m "not smoke and not unittest and not integration"
```

确保包含第四步；否则，没有标记的测试将永远不会运行。

使用标记来区分不同 pytest 运行中的测试也可以用于其他场景。例如，当使用`pytest-xdist`插件并行运行测试时，我们有一个并行会话，可以并行执行大多数测试套件，但可能决定在单独的 pytest 会话中串行运行一些测试，因为它们在一起执行时很敏感或有问题。

# 将标记应用于类

您可以将`@pytest.mark`装饰器应用于一个类。这将使该标记应用于该类中的所有测试方法，避免了将标记代码复制粘贴到所有测试方法中：

```py
@pytest.mark.timeout(10)
class TestCore:

    def test_simple_simulation(self):
        ...

    def test_compute_tracers(self):
        ...
```

前面的代码本质上与以下代码相同：

```py
class TestCore:

 @pytest.mark.timeout(10)
    def test_simple_simulation(self):
        ...

    @pytest.mark.timeout(10)
    def test_compute_tracers(self):
        ...
```

然而，有一个区别：将`@pytest.mark`装饰器应用于一个类意味着所有它的子类都会继承该标记。子类测试类的继承并不常见，但有时是一种有用的技术，可以避免重复测试代码，或者确保实现符合某个特定接口。我们将在本章后面和第四章 *Fixture*中看到更多这方面的例子。

与测试函数一样，装饰器可以应用多次：

```py
@pytest.mark.slow
@pytest.mark.timeout(10)
class TestCore:

    def test_simple_simulation(self):
        ...

    def test_compute_tracers(self):
        ...
```

# 将标记应用于模块

我们还可以将一个标记应用于模块中的所有测试函数和测试类。只需声明一个名为`pytestmark`的**全局变量**：

```py
import pytest

pytestmark = pytest.mark.timeout(10)

class TestCore:

    def test_simple_simulation(self):
        ...

def test_compute_tracers():
    ...
```

以下是等效于这个的：

```py
import pytest

@pytest.mark.timeout(10)
class TestCore:

    def test_simple_simulation(self):
        ...

@pytest.mark.timeout(10)
def test_compute_tracers():
    ...
```

您也可以使用`tuple`或`list`的标记来应用多个标记：

```py
import pytest

pytestmark = [pytest.mark.slow, pytest.mark.timeout(10)]
```

# 自定义标记和 pytest.ini

通过应用`@pytest.mark`装饰器来动态声明新的标记是很方便的。这使得快速开始享受使用标记的好处变得轻而易举。

这种便利性是有代价的：用户可能会在标记名称中犯拼写错误，例如`@pytest.mark.solw`，而不是`@pytest.mark.slow`。根据被测试的项目，这种拼写错误可能只是一个小烦恼，也可能是一个更严重的问题。

因此，让我们回到我们之前的例子，其中一个测试套件根据标记的测试在 CI 上以层次结构执行：

+   `smoke`

+   `unittest`

+   `integration`

+   `<所有其他>`

```py
λ pytest -m "smoke"
...
λ pytest -m "unittest"
...
λ pytest -m "integration"
...
λ pytest -m "not smoke and not unittest and not integration"
```

开发人员在为其中一个测试应用标记时可能会犯拼写错误：

```py
@pytest.mark.smoek
def test_simulation_setup():
    ...
```

这意味着该测试将在最后一步执行，而不是与其他`smoke`测试一起在第一步执行。同样，这可能从一个小麻烦变成一个严重的问题，这取决于测试套件。

具有固定标记集的成熟测试套件可能会在`pytest.ini`文件中声明它们：

```py
[pytest]
markers =
    slow
    serial
    smoke: quick tests that cover a good portion of the code
    unittest: unit tests for basic functionality
    integration: cover to cover functionality testing    
```

`markers`选项接受一个标记列表，格式为`<name>: description`，其中描述部分是可选的（最后一个示例中的`slow`和`serial`没有描述）。

可以使用`--markers`标志显示所有标记的完整列表：

```py
λ pytest --markers
@pytest.mark.slow:

@pytest.mark.serial:

@pytest.mark.smoke: quick tests that cover a good portion of the code

@pytest.mark.unittest: unit tests for basic functionality

@pytest.mark.integration: cover to cover functionality testing

...
```

`--strict`标志使得在`pytest.ini`文件中未声明的标记使用成为错误。使用我们之前的带有拼写错误的示例，现在会得到一个错误，而不是在使用`--strict`运行时 pytest 悄悄地创建标记：

```py
λ pytest --strict tests\test_wrong_mark.py
...
collected 0 items / 1 errors

============================== ERRORS ===============================
_____________ ERROR collecting tests/test_wrong_mark.py _____________
tests\test_wrong_mark.py:4: in <module>
 @pytest.mark.smoek
..\..\.env36\lib\site-packages\_pytest\mark\structures.py:311: in __getattr__
 self._check(name)
..\..\.env36\lib\site-packages\_pytest\mark\structures.py:327: in _check
 raise AttributeError("%r not a registered marker" % (name,))
E AttributeError: 'smoek' not a registered marker
!!!!!!!!!!!!!! Interrupted: 1 errors during collection !!!!!!!!!!!!!!
====================== 1 error in 0.09 seconds ======================
```

希望确保所有标记都在`pytest.ini`中注册的测试套件也应该使用`addopts`：

```py
[pytest]
addopts = --strict
markers =
    slow
    serial
    smoke: quick tests that cover a good portion of the code
    unittest: unit tests for basic functionality
    integration: cover to cover functionality testing
```

# 内置标记

通过学习标记的基础知识以及如何使用它们，现在让我们来看一些内置的 pytest 标记。这不是所有内置标记的详尽列表，但是常用的标记。另外，请记住，许多插件也引入了其他标记。

# @pytest.mark.skipif

您可能有一些测试在满足某些条件之前不应该被执行。例如，一些测试可能依赖于并非总是安装的某些库，或者一个可能不在线的本地数据库，或者仅在某些平台上执行。

Pytest 提供了一个内置标记`skipif`，可以根据特定条件*跳过*测试。如果条件为真，则跳过测试不会被执行，并且不会计入测试套件的失败。

例如，您可以使用`skipif`标记来在 Windows 上执行时始终跳过测试：

```py
import sys
import pytest

@pytest.mark.skipif(
 sys.platform.startswith("win"),
 reason="fork not available on Windows",
)
def test_spawn_server_using_fork():
    ...
```

`@pytest.mark.skipif`的第一个参数是条件：在这个例子中，我们告诉 pytest 在 Windows 中跳过这个测试。`reason=`关键字参数是强制的，并且用于在使用`-ra`标志时显示为什么跳过测试：

```py
 tests\test_skipif.py s                                        [100%]
====================== short test summary info ======================
SKIP [1] tests\test_skipif.py:6: fork not available on Windows
===================== 1 skipped in 0.02 seconds =====================
```

始终写入描述性消息是一个好的风格，包括适用时的票号。

另外，我们可以将相同的条件写成如下形式：

```py
import os
import pytest

@pytest.mark.skipif(
 not hasattr(os, 'fork'), reason="os.fork not available"
)
def test_spawn_server_using_fork2():
    ...
```

后一种版本检查实际功能是否可用，而不是基于平台做出假设（Windows 目前没有`os.fork`函数，但也许将来 Windows 可能会支持该函数）。在测试库的功能时，通常也会出现相同的情况，而不是检查某些功能是否存在。我建议在可能的情况下，最好检查函数是否实际存在，而不是检查库的特定版本。

通常，检查功能和特性通常是更好的方法，而不是检查平台和库版本号。以下是完整的`@pytest.mark.skipif`签名：

```py
@pytest.mark.skipif(condition, *, reason=None)
```

# pytest.skip

`@pytest.mark.skipif`装饰器非常方便，但是标记必须在`import`/`collection`时间评估条件，以确定是否应该跳过测试。我们希望最小化测试收集时间，因为毕竟，如果使用`-k`或`--lf`标志，我们最终可能甚至不会执行所有测试

有时，要在导入时检查测试是否应该跳过几乎是不可能的（除非进行一些令人讨厌的黑客）。例如，您可以根据图形驱动程序的功能来决定是否跳过测试，但只能在初始化底层图形库后才能做出这个决定，而初始化图形子系统绝对不是您希望在导入时执行的事情。

对于这些情况，pytest 允许您在测试主体中使用`pytest.skip`函数来强制跳过测试：

```py
def test_shaders():
    initialize_graphics()
    if not supports_shaders():
 pytest.skip("shades not supported in this driver") # rest of the test code ... 
```

`pytest.skip`通过引发内部异常来工作，因此它遵循正常的 Python 异常语义，而且不需要为了正确跳过测试而做其他事情。

# pytest.importorskip

通常，库的测试会依赖于某个特定库是否已安装。例如，pytest 自己的测试套件中有一些针对`numpy`数组的测试，如果没有安装`numpy`，则应该跳过这些测试。

处理这个问题的一种方法是手动尝试导入库，并在库不存在时跳过测试：

```py
def test_tracers_as_arrays_manual():
    try:
        import numpy
    except ImportError:
        pytest.skip("requires numpy")
    ...
```

这可能很快就会过时，因此 pytest 提供了方便的`pytest.importorskip`函数：

```py
def test_tracers_as_arrays():
    numpy = pytest.importorskip("numpy")
    ...
```

`pytest.importorskip`将导入模块并返回模块对象，或者如果无法导入模块，则完全跳过测试。

如果您的测试需要库的最低版本，`pytest.importorskip`也支持`minversion`参数：

```py
def test_tracers_as_arrays_114():
    numpy = pytest.importorskip("numpy", minversion="1.14")
    ...
```

# @pytest.mark.xfail

您可以使用`@pytest.mark.xfail`装饰器来指示测试*`预计会失败`*。像往常一样，我们将标记装饰器应用到测试函数或方法上：

```py
@pytest.mark.xfail
def test_simulation_34():
    ...
```

这个标记支持一些参数，我们将在本节后面看到所有这些参数；但其中一个特别值得讨论：`strict`参数。此参数为标记定义了两种不同的行为：

+   使用`strict=False`（默认值），如果测试通过，测试将被单独计数为**XPASS**（如果测试通过），或者**XFAIL**（如果测试失败），并且**不会使测试套件失败**

+   使用`strict=True`，如果测试失败，测试将被标记为**XFAIL**，但如果测试意外地通过，它将**使测试套件失败**，就像普通的失败测试一样

但是为什么你想要编写一个你预计会失败的测试，这在哪些情况下有用呢？这一开始可能看起来很奇怪，但有一些情况下这是很方便的。

第一种情况是测试总是失败，并且您希望（大声地）得知它突然开始通过。这可能发生在：

+   你发现你的代码中的一个 bug 的原因是第三方库中的问题。在这种情况下，你可以编写一个演示问题的失败测试，并用`@pytest.mark.xfail(strict=True)`标记它。如果测试失败，测试将在测试会话摘要中标记为**XFAIL**，但如果测试**通过**，它将**失败测试套件**。当你升级导致问题的库时，这个测试可能会开始通过，这将提醒你问题已经解决，并需要你的注意。

+   你想到了一个新功能，并设计了一个或多个在你开始实施之前就对其进行测试的测试用例。你可以使用`@pytest.mark.xfail(strict=True)`标记提交测试，并在编写新功能时从测试中删除该标记。这在协作环境中非常有用，其中一个人提供了关于他们如何设想新功能/API 的测试，另一个人根据测试用例实现它。

+   你发现应用程序中的一个 bug，并编写一个演示问题的测试用例。你可能现在没有时间解决它，或者另一个人更适合在代码的那部分工作。在这种情况下，将测试标记为`@pytest.mark.xfail(strict=True)`是一个很好的方法。

上述所有情况都有一个共同点：你有一个失败的测试，并想知道它是否突然开始通过。在这种情况下，测试通过的事实警告你需要注意的事实：一个带有 bug 修复的库的新版本已发布，部分功能现在按预期工作，或者已修复了一个已知的 bug。

`xfail`标记有用的另一种情况是当你有*有时*失败的测试，也称为**不稳定**的**测试**。不稳定的测试是指有时会失败的测试，即使基础代码没有更改。测试失败看起来是随机的原因有很多；以下是其中一些：

+   多线程代码中的时间问题

+   间歇性的网络连接问题

+   没有正确处理异步事件的测试

+   依赖于不确定的行为

这只是列举了一些可能的原因。这种不确定性通常发生在范围更广的测试中，比如集成或 UI。事实上，你几乎总是需要处理大型测试套件中的不稳定测试。

不稳定的测试是一个严重的问题，因为测试套件应该是代码按预期工作并在发生真正问题时能够检测到的指标。不稳定的测试破坏了这一形象，因为开发人员经常会看到与最近的代码更改无关的不稳定的测试失败。当这种情况变得司空见惯时，人们开始再次运行测试套件，希望这次不稳定的测试通过（它经常会通过），但这会侵蚀对整个测试套件的信任，并给开发团队带来挫折。你应该把不稳定的测试视为一个应该被遏制和处理的威胁。

以下是关于如何处理开发团队中的不稳定测试的一些建议：

1.  首先，你需要能够正确识别不稳定的测试。如果一个测试失败，显然与最近的更改无关，再次运行测试。如果之前失败的测试现在**通过**，这意味着测试是不稳定的。

1.  在你的工单系统中创建一个处理特定不稳定测试的问题。使用命名约定或其他方式标记该问题与不稳定测试相关（例如 GitHub 或 JIRA 标签）。

1.  应用`@pytest.mark.xfail(reason="flaky test #123", strict=False)`标记，确保包括问题票号或标识。如果愿意，可以在描述中添加更多信息。

1.  确保定期将关于不稳定测试的问题分配给自己或其他团队成员（例如，在冲刺计划期间）。这样做的目的是以舒适的步伐处理不稳定的测试，最终减少或消除它们。

这些做法解决了两个主要问题：它们允许您避免破坏测试套件的信任，让不稳定的测试不会妨碍开发团队，并且它们制定了一项政策，以便及时处理不稳定的测试。

在涵盖了`xfail`标记有用的情况后，让我们来看一下完整的签名：

```py
@pytest.mark.xfail(condition=None, *, reason=None, raises=None, run=True, strict=False)
```

+   `condition`：如果给定，第一个参数是一个`True`/`False`条件，类似于`@pytest.mark.skipif`中使用的条件：如果为`False`，则忽略`xfail`标记。它可用于根据外部条件（例如平台、Python 版本、库版本等）标记测试为`xfail`。

```py
@pytest.mark.xfail(
 sys.platform.startswith("win"), 
    reason="flaky on Windows #42", strict=False
)
def test_login_dialog():
    ...
```

+   `reason`：一个字符串，在使用`-ra`标志时将显示在短测试摘要中。强烈建议始终使用此参数来解释为什么将测试标记为`xfail`和/或包括一个票号。

```py
@pytest.mark.xfail(
    sys.platform.startswith("win"), 
    reason="flaky on Windows #42", strict=False
)
def test_login_dialog():
    ...
```

+   `raises`：给定一个异常类型，它声明我们期望测试引发该异常的实例。如果测试引发了另一种类型的异常（甚至是`AssertionError`），测试将正常“失败”。这对于缺少功能或测试已知错误特别有用。

```py
@pytest.mark.xfail(raises=NotImplementedError,
                   reason='will be implemented in #987')
def test_credential_check():
    check_credentials('Hawkwood') # not implemented yet
```

+   `run`：如果为`False`，则测试甚至不会被执行，并且将作为 XFAIL 失败。这对于运行可能导致测试套件进程崩溃的代码的测试特别有用（例如，由于已知问题，C/C++扩展导致分段错误）。

```py
@pytest.mark.xfail(
    run=False, reason="undefined particles cause a crash #625"
)
def test_undefined_particle_collision_crash():
    collide(Particle(), Particle())
```

+   `strict`：如果为`True`，则通过的测试将使测试套件失败。如果为`False`，则无论结果如何，测试都不会使测试套件失败（默认为`False`）。这在本节开始时已经详细讨论过。

配置变量`xfail_strict`控制`xfail`标记的`strict`参数的默认值：

```py
[pytest]
xfail_strict = True
```

将其设置为`True`意味着所有标记为 xfail 的测试，没有显式的`strict`参数，都被视为实际的失败期望，而不是不稳定的测试。任何显式传递`strict`参数的`xfail`标记都会覆盖配置值。

# pytest.xfail

最后，您可以通过调用`pytest.xfail`函数在测试中强制触发 XFAIL 结果：

```py
def test_particle_splitting():
    initialize_physics()
    import numpy
    if numpy.__version__ < "1.13":
        pytest.xfail("split computation fails with numpy < 1.13")
    ...
```

与`pytest.skip`类似，当您只能在运行时确定是否需要将测试标记为`xfail`时，这是非常有用的。

# 参数化

一个常见的测试活动是将多个值传递给同一个测试函数，并断言结果。

假设我们有一个应用程序，允许用户定义自定义数学公式，这些公式将在运行时解析和评估。这些公式以字符串形式给出，并且可以使用诸如`sin`、`cos`、`log`等数学函数。在 Python 中实现这个非常简单的方法是使用内置的`eval`（[`docs.python.org/3/library/functions.html#eval`](https://docs.python.org/3/library/functions.html#eval)），但由于它可以执行任意代码，我们选择使用自定义的标记器和评估器来确保安全。

让我们不要深入实现细节，而是专注于一个测试：

```py
def test_formula_parsing():
    tokenizer = FormulaTokenizer()
    formula = Formula.from_string("C0 * x + 10", tokenizer)
    assert formula.eval(x=1.0, C0=2.0) == pytest.approx(12.0)
```

在这里，我们创建了一个`Tokenizer`类，我们的实现使用它来将公式字符串分解为内部标记，以供以后处理。然后，我们将公式字符串和标记器传递给`Formula.from_string`，以获得一个公式对象。有了公式对象，我们将输入值传递给`formula.eval`，并检查返回的值是否符合我们的期望。

但我们也想测试其他数学运算，以确保我们覆盖了`Formula`类的所有功能。

一种方法是通过使用多个断言来扩展我们的测试，以检查其他公式和输入值：

```py
def test_formula_parsing():
    tokenizer = FormulaTokenizer()
    formula = Formula.from_string("C0 * x + 10", tokenizer)
    assert formula.eval(x=1.0, C0=2.0) == pytest.approx(12.0)

    formula = Formula.from_string("sin(x) + 2 * cos(x)", tokenizer)
 assert formula.eval(x=0.7) == pytest.approx(2.1739021)

    formula = Formula.from_string("log(x) + 3", tokenizer)
    assert formula.eval(x=2.71828182846) == pytest.approx(4.0)
```

这样做是有效的，但如果其中一个断言失败，测试函数内部的后续断言将不会被执行。如果有多个失败，我们将不得不多次运行测试来查看所有失败，并最终修复所有问题。

为了在测试运行中看到多个失败，我们可能决定明确为每个断言编写单独的测试：

```py
def test_formula_linear():
    tokenizer = FormulaTokenizer()
    formula = Formula.from_string("C0 * x + 10", tokenizer)
    assert formula.eval(x=1.0, C0=2.0) == pytest.approx(12.0)

def test_formula_sin_cos():
    tokenizer = FormulaTokenizer()
    formula = Formula.from_string("sin(x) + 2 * cos(x)", tokenizer)
    assert formula.eval(x=0.7) == pytest.approx(2.1739021)

def test_formula_log():
    tokenizer = FormulaTokenizer()
    formula = Formula.from_string("log(x) + 3", tokenizer)
    assert formula.eval(x=2.71828182846) == pytest.approx(4.0)
```

但现在我们到处都在重复代码，这将使维护更加困难。假设将来`FormulaTokenizer`被更新为明确接收可以在公式中使用的函数列表。这意味着我们将不得不在多个地方更新`FormulaTokenzier`的创建。

为了避免重复，我们可能决定改为这样写：

```py
def test_formula_parsing2():
    values = [
 ("C0 * x + 10", dict(x=1.0, C0=2.0), 12.0),
 ("sin(x) + 2 * cos(x)", dict(x=0.7), 2.1739021),
 ("log(x) + 3", dict(x=2.71828182846), 4.0),
 ]
    tokenizer = FormulaTokenizer()
    for formula, inputs, result in values:
        formula = Formula.from_string(formula, tokenizer)
        assert formula.eval(**inputs) == pytest.approx(result)
```

这解决了重复代码的问题，但现在我们又回到了一次只看到一个失败的初始问题。

# 输入 `@pytest.mark.parametrize`

为了解决上述所有问题，pytest 提供了备受喜爱的`@pytest.mark.parametrize`标记。使用这个标记，您可以为测试提供一系列输入值，并且 pytest 会自动生成多个测试函数，每个输入值一个。

以下显示了这一点：

```py
@pytest.mark.parametrize(
 "formula, inputs, result",
 [
 ("C0 * x + 10", dict(x=1.0, C0=2.0), 12.0),
 ("sin(x) + 2 * cos(x)", dict(x=0.7), 2.1739021),
 ("log(x) + 3", dict(x=2.71828182846), 4.0),
 ],
)
def test_formula_parsing(formula, inputs, result):
    tokenizer = FormulaTokenizer()
    formula = Formula.from_string(formula, tokenizer)
    assert formula.eval(**inputs) == pytest.approx(result)
```

`@pytest.mark.parametrize` 标记会自动生成多个测试函数，并使用标记给出的参数对它们进行参数化。调用接收两个参数：

+   `argnames`: 逗号分隔的参数名称字符串，将传递给测试函数。

+   `argvalues`: 一系列元组，每个元组生成一个新的测试调用。元组中的每个项目对应一个参数名称，因此第一个元组 `("C0 * x + 10", dict(x=1.0, C0=2.0), 12.0)` 将生成一个对测试函数的调用，参数为：

+   `formula` = `"C0 * x + 10"`

+   `inputs` = `dict(x=1.0, C0=2.0)`

+   `expected` = `12.0`

使用这个标记，pytest 将运行 `test_formula_parsing` 三次，每次传递由`argvalues`参数给出的一组参数。它还会自动生成不同的节点 ID 用于每个测试，使得很容易区分它们：

```py
======================== test session starts ========================
...
collected 8 items / 5 deselected

test_formula.py::test_formula[C0 * x + 10-inputs0-12.0]
test_formula.py::test_formula[sin(x) + 2 * cos(x)-inputs1-2.1739021]
test_formula.py::test_formula[log(x) + 3-inputs2-4.0] 
============== 3 passed, 5 deselected in 0.05 seconds ===============
```

还要注意的是，函数的主体与本节开头的起始测试一样紧凑，但现在我们有多个测试，这使我们能够在发生多个失败时看到多个失败。

参数化测试不仅避免了重复的测试代码，使维护更容易，还邀请您和随后的开发人员随着代码的成熟添加更多的输入值。它鼓励开发人员覆盖更多的情况，因为人们更愿意向参数化测试的`argvalues`添加一行代码，而不是复制和粘贴整个新测试来覆盖另一个输入值。

总之，`@pytest.mark.parametrize` 将使您覆盖更多的输入情况，开销很小。这绝对是一个非常有用的功能，应该在需要以相同方式测试多个输入值时使用。

# 将标记应用于值集

通常，在参数化测试中，您会发现需要像对普通测试函数一样对一组参数应用一个或多个标记。例如，您想对一组参数应用`timeout`标记，因为运行时间太长，或者对一组参数应用`xfail`标记，因为它尚未实现。

在这些情况下，使用`pytest.param`来包装值集并应用您想要的标记：

```py
@pytest.mark.parametrize(
    "formula, inputs, result",
    [
        ...
        ("log(x) + 3", dict(x=2.71828182846), 4.0),
        pytest.param(
 "hypot(x, y)", dict(x=3, y=4), 5.0,
 marks=pytest.mark.xfail(reason="not implemented: #102"),
 ),
    ],
)
```

`pytest.param` 的签名是这样的：

```py
pytest.param(*values, **kw)
```

其中：

+   `*values` 是参数集：`"hypot(x, y)", dict(x=3, y=4), 5.0`。

+   `**kw` 是选项作为关键字参数：`marks=pytest.mark.xfail(reason="not implemented: #102")`。它接受单个标记或一系列标记。还有另一个选项`ids`，将在下一节中显示。

在幕后，传递给`@pytest.mark.parametrize`的每个参数元组都会转换为一个`pytest.param`，没有额外的选项，因此，例如，在以下第一个代码片段等同于第二个代码片段：

```py
@pytest.mark.parametrize(
    "formula, inputs, result",
    [
        ("C0 * x + 10", dict(x=1.0, C0=2.0), 12.0),
        ("sin(x) + 2 * cos(x)", dict(x=0.7), 2.1739021),
    ]
)
```

```py
@pytest.mark.parametrize(
    "formula, inputs, result",
    [
        pytest.param("C0 * x + 10", dict(x=1.0, C0=2.0), 12.0),
        pytest.param("sin(x) + 2 * cos(x)", dict(x=0.7), 2.1739021),
    ]
)
```

# 自定义测试 ID

考虑以下示例：

```py
@pytest.mark.parametrize(
    "formula, inputs, result",
    [
        ("x + 3", dict(x=1.0), 4.0,),
        ("x - 1", dict(x=6.0), 5.0,),
    ],
)
def test_formula_simple(formula, inputs, result):
    ...
```

正如我们所见，pytest 会根据参数在参数化调用中使用的参数自动生成自定义测试 ID。运行`pytest -v`将生成这些测试 ID：

```py
======================== test session starts ========================
...
tests/test_formula.py::test_formula_simple[x + 3-inputs0-4.0]
tests/test_formula.py::test_formula_simple[x - 1-inputs1-5.0]
```

如果你不喜欢自动生成的 ID，你可以使用`pytest.param`和`id`选项来自定义它：

```py
@pytest.mark.parametrize(
    "formula, inputs, result",
    [
        pytest.param("x + 3", dict(x=1.0), 4.0, id='add'),
        pytest.param("x - 1", dict(x=6.0), 5.0, id='sub'),
    ],
)
def test_formula_simple(formula, inputs, result):
    ...
```

这产生了以下结果：

```py
======================== test session starts ========================
...
tests/test_formula.py::test_formula_simple[add]
tests/test_formula.py::test_formula_simple[sub]
```

这也很有用，因为在使用`-k`标志时，选择测试变得更容易：

```py
λ pytest -k "x + 3-inputs0-4.0"
```

对比：

```py
λ pytest -k "add"
```

# 测试多个实现

设计良好的系统通常利用接口提供的抽象，而不是与特定实现绑定。这使得系统更能够适应未来的变化，因为要扩展它，你需要实现一个符合预期接口的新扩展，并将其集成到系统中。

经常出现的一个挑战是如何确保现有的实现符合特定接口的所有细节。

例如，假设我们的系统需要能够将一些内部类序列化为文本格式以保存和加载到磁盘。以下是我们系统中的一些内部类：

+   `Quantity`：表示一个值和一个计量单位。例如，`Quantity(10, "m")`表示*10 米*。`Quantity`对象具有加法、减法和乘法——基本上，所有你从本机`float`期望的运算符，但考虑到计量单位。

+   `Pipe`：表示液体可以流过的管道。它有一个`length`和`diameter`，都是`Quantity`实例。

最初，在我们的开发中，我们只需要以**JSON**格式保存这些对象，所以我们继续实现一个直接的序列化器类，能够序列化和反序列化我们的类：

```py
class JSONSerializer:

    def serialize_quantity(self, quantity: Quantity) -> str:
        ...

    def deserialize_quantity(self, data: str) -> Quantity:
        ...

    def serialize_pipe(self, pipe: Pipe) -> str:
        ...

    def deserialize_pipe(self, data: str) -> Pipe:
        ...
```

现在我们应该写一些测试来确保一切正常运行。

```py
class Test:

    def test_quantity(self):
        serializer = JSONSerializer()
        quantity = Quantity(10, "m")
        data = serializer.serialize(quantity)
        new_quantity = serializer.deserialize(data)
        assert new_quantity == quantity

    def test_pipe(self):
        serializer = JSONSerializer()
        pipe = Pipe(
            length=Quantity(1000, "m"), diameter=Quantity(35, "cm")
        )
        data = serializer.serialize(pipe)
        new_pipe = serializer.deserialize(data)
        assert new_pipe == pipe
```

这样做效果很好，也是一个完全有效的方法，考虑到我们的需求。

一段时间过去了，新的需求出现了：现在我们需要将我们的对象序列化为其他格式，即`XML`和[`YAML`](http://yaml.org/)。为了保持简单，我们创建了两个新类，`XMLSerializer`和`YAMLSerializer`，它们实现了相同的`serialize`/`deserialize`方法。因为它们符合与`JSONSerializer`相同的接口，我们可以在系统中互换使用新类，这很棒。

但是我们如何测试不同的实现？

一个天真的方法是在每个测试中循环遍历不同的实现：

```py
class Test:

    def test_quantity(self):
        for serializer in [
 JSONSerializer(), XMLSerializer(), YAMLSerializer()
 ]:
            quantity = Quantity(10, "m")
            data = serializer.serialize(quantity)
            new_quantity = serializer.deserialize(data)
            assert new_quantity == quantity

    def test_pipe(self):
        for serializer in [
 JSONSerializer(), XMLSerializer(), YAMLSerializer()
 ]:
            pipe = Pipe(
                length=Quantity(1000, "m"),
                diameter=Quantity(35, "cm"),
            )
            data = serializer.serialize(pipe)
            new_pipe = serializer.deserialize(data)
            assert new_pipe == pipe
```

这样做虽然有效，但并不理想，因为我们必须在每个测试中复制和粘贴循环定义，这样更难以维护。而且，如果其中一个序列化器失败，列表中的下一个序列化器将永远不会被执行。

另一种可怕的方法是每次复制和粘贴整个测试函数，替换序列化器类，但我们不会在这里展示。

一个更好的解决方案是在类级别使用`@pytest.mark.parametrize`。观察：

```py
@pytest.mark.parametrize(
 "serializer_class",
 [JSONSerializer, XMLSerializer, YAMLSerializer],
)
class Test:

    def test_quantity(self, serializer_class):
        serializer = serializer_class()
        quantity = Quantity(10, "m")
        data = serializer.serialize(quantity)
        new_quantity = serializer.deserialize(data)
        assert new_quantity == quantity

    def test_pipe(self, serializer_class):
        serializer = serializer_class()
        pipe = Pipe(
            length=Quantity(1000, "m"), diameter=Quantity(35, "cm")
        )
        data = serializer.serialize(pipe)
        new_pipe = serializer.deserialize(data)
        assert new_pipe == pipe
```

通过一个小改变，我们已经扩展了我们现有的测试，以覆盖所有新的实现：

```py
test_parametrization.py::Test::test_quantity[JSONSerializer] PASSED
test_parametrization.py::Test::test_quantity[XMLSerializer] PASSED
test_parametrization.py::Test::test_quantity[YAMLSerializer] PASSED
test_parametrization.py::Test::test_pipe[JSONSerializer] PASSED
test_parametrization.py::Test::test_pipe[XMLSerializer] PASSED
test_parametrization.py::Test::test_pipe[YAMLSerializer] PASSED
```

`@pytest.mark.parametrize`装饰器还清楚地表明，新的实现应该添加到列表中，并且所有现有的测试必须通过。也需要为类添加的新测试对所有实现都通过。

总之，`@pytest.mark.parametrize`可以是一个非常强大的工具，以确保不同的实现符合接口的规范。

# 总结

在本章中，我们学习了如何使用标记来组织我们的代码，并帮助我们以灵活的方式运行测试套件。然后我们看了如何使用`@pytest.mark.skipif`来有条件地跳过测试，以及如何使用`@pytest.mark.xfail`标记来处理预期的失败和不稳定的测试。然后我们讨论了在协作环境中处理不稳定测试的方法。最后，我们讨论了使用`@pytest.mark.parametrize`的好处，以避免重复我们的测试代码，并使自己和其他人能够轻松地向现有测试添加新的输入案例。

在下一章中，我们将终于介绍 pytest 最受喜爱和强大的功能之一：**fixtures**。
