# Python 测试秘籍第二版（一）

> 原文：[`zh.annas-archive.org/md5/98CC341CCD461D299EE4103040C60B7B`](https://zh.annas-archive.org/md5/98CC341CCD461D299EE4103040C60B7B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

测试一直是软件开发的一部分。几十年来，全面的测试是由复杂的手动测试程序支持的，而这些程序又由庞大的预算支持；但是在 1998 年发生了一些革命性的事情。在他的《更好的 Smalltalk 指南》中，Smalltalk 大师 Kent Beck 引入了一个名为 SUnit 的自动化测试框架。这引发了一系列测试框架，包括 JUnit、PyUnit 和许多其他针对不同语言和各种平台的框架，被称为 xUnit 运动。当 17 位顶级软件专家在 2001 年签署了《敏捷宣言》时，自动化测试成为了敏捷运动的基石。

测试包括许多不同的风格，包括单元测试、集成测试、验收测试、烟测试、负载测试等等。本书深入探讨了并探索了在使用 Python 的灵活力量的同时在所有重要级别进行测试。它还演示了许多工具。

这本书旨在扩展您对测试的知识，使其不再是您听说过的东西，而是您可以在任何级别应用以满足您在改进软件质量方面的需求。

关于，或者稍微练习了一下，变成了您可以在任何级别应用以满足您在改进软件质量方面的需求。我们希望为您提供工具，以获得更好的软件开发和客户满意度的巨大回报。

# 这本书适合谁

如果您是一名希望将测试提升到更高水平并希望扩展您的测试技能的 Python 开发人员，那么这本书适合您。假设您具有一些 Python 编程知识。

# 本书涵盖了什么

第一章《使用 Unittest 开发基本测试》为您快速介绍了 Python 社区中最常用的测试框架。

第二章《使用 Nose 运行自动化测试套件》介绍了最普遍的 Python 测试工具，并向您展示如何编写专门的插件。

第三章《使用 doctest 创建可测试文档》展示了使用 Python 的文档字符串构建可运行的 doctests 以及编写自定义测试运行器的许多不同方法。

第四章《使用行为驱动开发测试客户故事》深入探讨了使用 doctest、mocking 和 Lettuce/Should DSL 编写易于阅读的可测试的客户故事。

第五章《使用验收测试进行高级客户场景》，帮助您进入客户的思维模式，并使用 Pyccuracy 和 Robot Framework 从他们的角度编写测试。

第六章《将自动化测试与持续集成集成》向您展示了如何使用 Jenkins 和 TeamCity 将持续集成添加到您的开发流程中。

第七章《通过测试覆盖率衡量您的成功》探讨了如何创建覆盖率报告并正确解释它们。它还深入探讨了如何将它们与您的持续集成系统结合起来。

第八章《烟/负载测试-测试主要部分》着重介绍了如何创建烟测试套件以从系统中获取脉搏。它还演示了如何将系统置于负载之下，以确保它能够处理当前的负载，并找到未来负载的下一个破坏点。

第九章《新旧系统的良好测试习惯》带您经历了作者从软件测试方面学到的许多不同的经验教训。

*第十章*，*使用 Selenium 进行 Web UI 测试*，教你如何为他们的软件编写合适的测试集。它将解释要使用的各种测试集和框架。本章不包含在书中，可以在以下链接在线获取：[`www.packtpub.com/sites/default/files/downloads/Web_UI_Testing_Using_Selenium.pdf`](https://www.packtpub.com/sites/default/files/downloads/Web_UI_Testing_Using_Selenium.pdf)

# 要充分利用本书

您需要在您的计算机上安装 Python。本书使用许多其他 Python 测试工具，但包括详细的步骤，显示如何安装和使用它们。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择 SUPPORT 选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Python-Testing-Cookbook-Second-Edition`](https://github.com/PacktPublishing/Python-Testing-Cookbook-Second-Edition)。我们还有来自丰富书籍和视频目录的其他代码包可用于**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“您还可以使用`pip install virtualenv`。”

代码块设置如下：

```py
if __name__== "__main__": 
    suite = unittest.TestLoader().loadTestsFromTestCase(\
              RomanNumeralConverterTest) 
    unittest.TextTestRunner(verbosity=2).run(suite) 
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体设置：

```py
def test_bad_inputs(self): 
    r = self.cvt.convert_to_roman 
    d = self.cvt.convert_to_decimal 
    edges = [("equals", r, "", None),\ 
```

任何命令行输入或输出都以以下方式编写：

```py
$ python recipe3.py
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“选择一个要测试的类。这被称为**被测试的类**。”

警告或重要说明会出现在这样的地方。提示和技巧会出现在这样的地方。

# 章节

在本书中，您会经常看到几个标题（*准备就绪*，*如何做...*，*它是如何工作的...*，*还有更多...*和*另请参阅*）。

为了清晰地说明如何完成配方，使用以下各节： 

# 准备就绪

本节告诉您配方中可以期望发生什么，并描述如何设置配方所需的任何软件或任何预备设置。

# 如何做...

本节包含遵循该配方所需的步骤。

# 它是如何工作的...

本节通常包括对前一节中发生的事情的详细解释。

# 还有更多...

本节包括有关配方的其他信息，以使您对配方更加了解。

# 另请参阅

本节提供了有关配方的其他有用信息的链接。


# 第一章：使用 Unittest 开发基本测试

在本章中，我们将涵盖以下食谱：

+   断言基础知识

+   设置和拆卸测试工具

+   从命令行运行测试用例

+   运行一部分测试用例方法

+   链接一系列测试

+   在测试模块内定义测试套件

+   重新调整旧的测试代码以在 unittest 中运行

+   将复杂的测试分解为简单的测试

+   测试边缘

+   通过迭代测试角落情况

# 介绍

测试一直是软件开发的一部分。然而，当 Kent Beck 和 Erich Gamma 为 Java 开发引入了 JUnit（[`junit.org`](http://junit.org)）时，世界被介绍了一个称为**自动化测试**的新概念。它基于 Kent 早期与 Smalltalk 和自动化测试的工作。目前，自动化测试已成为软件行业中一个被广泛接受的概念。

Python 版本最初被称为**PyUnit**，于 1999 年创建，并在 2001 年后添加到 Python 的标准库中，即 Python 2.1。目前，PyUnit 库适用于 Python 的两个版本，即 2.7（[`docs.python.org/2.7/library/unittest.html`](https://docs.python.org/2.7/library/unittest.html)）和 3.x（[`docs.python.org/3.6/library/unittest.html`](https://docs.python.org/3.6/library/unittest.html)）。从那时起，Python 社区将其称为**unittest**，这是导入测试代码的库的名称。

Unittest 是 Python 世界中自动化测试的基础。在本章中，我们将探讨测试和断言代码功能的基础知识，构建测试套件，避免测试情况，最后测试边缘和角落情况。

在本章的所有食谱中，我们将使用`virtualenv`（[`pypi.python.org/pypi/virtualenv`](https://pypi.python.org/pypi/virtualenv)）来创建一个受控的 Python 运行环境。Unittest 是标准库的一部分，不需要额外的安装步骤。但在后面的章节中，使用`virtualenv`将允许我们方便地安装其他测试工具，而不会使我们的默认 Python 安装变得混乱。安装`virtualenv`的步骤如下：

1.  要安装`virtualenv`，可以从前面提到的网站下载，或者如果您有 Easy Install，只需输入：`easy_install virtualenv`。您也可以使用`pip install virtualenv`。

对于某些系统，您可能需要以`root`身份安装它，或者使用`sudo`。

1.  安装`virtualenv`后，使用它创建一个名为`ptc`（*Python Testing Cookbook*的缩写）的干净环境，使用`--no-site-packages`。

1.  激活虚拟 Python 环境。这可能会有所不同，取决于您使用的 shell。看一下这个截图：![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00005.jpeg)

1.  对于 Windows 平台，您可以选择要创建`ptc`文件夹的文件夹，或者直接在所需的驱动器中创建它。看一下这个截图：![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00006.jpeg)

1.  最后，通过检查`pip`的路径来验证环境是否处于活动状态。

有关`virtualenv`的用法和好处的更多信息，请阅读[`iamzed.com/2009/05/07/a-primer-on-virtualenv`](http://iamzed.com/2009/05/07/a-primer-on-virtualenv)。

# 断言基础知识

自动化 unittest 测试用例的基本概念是实例化我们代码的一部分，对其进行操作，并使用断言验证某些结果：

+   如果结果符合预期，unittest 将计为测试成功

+   如果结果不匹配，将引发异常，并且 unittest 将计为测试失败

# 准备工作

Unittest 已添加到 Python 的标准库套件中，不需要任何额外的安装。

# 如何做...

通过这些步骤，我们将编写一个简单的程序，然后使用 unittest 编写一些自动化测试：

1.  为这个配方的代码创建一个名为`recipe1.py`的新文件。选择一个要测试的类。这被称为**被测试的类**。对于这个配方，我们将选择一个使用简单的罗马数字转换器的类：

```py
class RomanNumeralConverter(object):
    def __init__ (self, roman_numeral): 
        self.roman_numeral = roman_numeral 
        self.digit_map = {"M":1000, "D":500,"C":100,\
                         "L":50, "X":10, "V":5, "I":1} 
     def convert_to_decimal(self): 
        val = 0 
        for char in self.roman_numeral: 
            val += self.digit_map[char] 
        return val 
```

这个罗马数字转换器应用了简单的加法规则，但它没有特殊的减法模式，比如`XL`映射到`40`。目的不是要有最好的罗马数字转换器，而是观察各种测试断言。

1.  编写一个新的类，并给它加上`Test`，继承`unittest.TestCase`。在测试类后面加上`Test`是一种常见的约定，但不是必需的。扩展`unittest.TestCase`是需要的，以便连接到 unittest 的标准测试运行器：

```py
import unittest 
class RomanNumeralConverterTest(unittest.TestCase): 
```

1.  创建几个以`test`开头的方法，这样它们就会被 unittest 的测试用例自动捕捉到：

```py
     def test_parsing_millenia(self):
        value =RomanNumeralConverter("M") 
        self.assertEqual(1000, value.convert_to_decimal()) 
     def test_parsing_century(self): 
        value =RomanNumeralConverter("C") 
        self.assertEqual(100, value.convert_to_decimal()) 
     def test_parsing_half_century(self): 
        value =RomanNumeralConverter("L") 
        self.assertEqual(50, value.convert_to_decimal()) 
     def test_parsing_decade(self): 
        value =RomanNumeralConverter("X") 
        self.assertEqual(10, value.convert_to_decimal()) 
     def test_parsing_half_decade(self): 
        value =RomanNumeralConverter("V") 
        self.assertEqual(5, value.convert_to_decimal()) 
     def test_parsing_one(self): 
        value = RomanNumeralConverter("I") 
        self.assertEqual(1, value.convert_to_decimal()) 
     def test_empty_roman_numeral(self): 
        value =RomanNumeralConverter("") 
        self.assertTrue(value.convert_to_decimal() == 0) 
        self.assertFalse(value.convert_to_decimal() > 0) 
     def test_no_roman_numeral(self): 
        value =RomanNumeralConverter(None) 
        self.assertRaises(TypeError, value.convert_to_decimal) 
```

1.  使整个脚本可运行，然后使用 unittest 的测试运行器：

```py
if __name__=="__main__": 
    unittest.main()
```

1.  从命令行运行文件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00007.jpeg)`self.assertEquals()`在 Python 3 中已被弃用。

# 它是如何工作的...

在第一步中，我们选择了一个要测试的类。接下来，我们创建了一个单独的测试类。通过将测试类命名为`[class under test]Test`，很容易知道哪个类正在被测试。每个测试方法的名称必须以`test`开头，这样 unittest 会自动捕捉并运行它。要添加更多的测试，只需定义更多的`test`方法。这些测试利用了各种断言：

+   `assertEqual(first, second[, msg])`: 比较第一个和第二个表达式，如果它们的值不相同则失败。如果失败，我们可以选择打印特殊消息。

+   `assertTrue(expression[, msg])`: 测试表达式，如果为假则失败。如果失败，我们可以选择打印特殊消息。

+   `assertFalse(expression[, msg])`: 测试表达式，如果为真则失败。如果失败，我们可以选择打印特殊消息。

+   `assertRaises(exception, callable, ...)`: 用任何参数运行 callable，对于之后列出的 callable，如果它没有引发异常，则失败。

# 还有更多...

Unittest 提供了许多断言、失败和其他方便的选项。以下部分展示了如何从这些选项中进行选择和挑选的一些建议。

# assertEquals 优于 assertTrue 和 assertFalse

当`assertEquals`断言失败时，错误报告中会打印第一个和第二个值，从而更好地反馈出了问题所在，而`assertTrue`和`assertFalse`只会报告失败。并非所有可测试的结果都适用于这种情况，但如果可能的话，使用`assertEquals`。

理解相等的概念很重要。当比较整数、字符串和其他标量时，这很简单。但是对于诸如字典、列表和集合之类的集合，情况就不那么理想了。复杂的、自定义的对象可能具有自定义的相等定义。这些复杂的对象可能需要更精细的断言。因此，当使用自定义对象时，最好也包括一些直接针对相等性和不相等性的测试方法。

# self.fail([msg])通常可以用断言重写

Unittest 有一个`self.fail([msg])`操作，可以无条件地导致测试失败，并附带一个可选的消息。之前没有展示这个操作，因为不建议使用。

`fail`方法通常用于检测异常等特定情况。一个常见的习惯用法如下：

```py
import unittest 
class BadTest(unittest.TestCase): 
  def test_no_roman_number(self): 
    value = RomanNumeralConverter(None) 
    try: 
      value.convert_to_decimal() 
      self.fail("Expected a TypeError") 
    except TypeError: 
      pass 
    if  __name__=="__main__": 
      unittest.main()
```

这测试了与之前的`test_no_roman_numeral`相同的行为。这种方法的问题在于当代码正常工作时，fail 方法永远不会被执行。定期不执行的代码有可能变得过时和无效。这也会干扰覆盖率报告。因此，最好使用像我们在前面的例子中使用的`assertRaises`。对于其他情况，考虑使用其他断言重写测试。

# 我们的 Python 版本可能会影响我们的选项

Python 官方关于 unittest 的文档显示了许多其他断言；然而，它们取决于我们使用的 Python 版本。有些已经被弃用；其他一些只在以后的版本中可用，比如 Python 3.6。

如果我们的代码必须支持多个版本的 Python，那么我们必须使用最低公共分母。这个配方展示了自 Python 3.6 以来所有版本都可用的核心断言。

# 设置和拆卸测试工具

Unittest 提供了一种简单的机制来配置系统的状态，当一段代码经过测试时。如果需要，它还允许我们在之后清理事物。当一个特定的测试用例在每个测试方法中使用重复步骤时，通常会需要这样做。

除了引用从一个测试方法到下一个测试方法传递状态的外部变量或资源，每个测试方法都从相同的状态开始。

# 如何做...

通过以下步骤，我们将为每个测试方法设置和拆卸测试工具：

1.  为这个配方的代码创建一个名为`recipe2.py`的新文件。

1.  选择一个要测试的类。在这种情况下，我们将使用我们的罗马数字转换器的一个稍微改变的版本，其中函数而不是构造函数提供要转换的输入值：

```py
class RomanNumeralConverter(object): 
    def __init__(self): 
        self.digit_map = {"M":1000, "D":500, "C":100,\
                         "L":50, "X":10, "V":5, "I":1} 
    def convert_to_decimal(self, roman_numeral):
        val = 0 
        for char in roman_numeral: 
            val += self.digit_map[char] 
        return val 
```

1.  使用与被测试类相同的名称创建一个测试类，在末尾添加`Test`：

```py
import unittest 
class RomanNumeralConverterTest(unittest.TestCase): 
```

1.  创建一个`setUp`方法，用于创建被测试类的实例：

```py
    def setUp(self): 
        print ("Creating a new RomanNumeralConverter...") 
        self.cvt =RomanNumeralConverter()
```

1.  创建一个`tearDown`方法，用于销毁被测试类的实例：

```py
     def tearDown(self): 
        print ("Destroying the RomanNumeralConverter...") 
        self.cvt = None 
```

1.  使用`self.converter`创建所有测试方法：

```py
     def test_parsing_millenia(self):
        self.assertEqual(1000,\
                         self.cvt.convert_to_decimal("M")) 
     def test_parsing_century(self): 
        self.assertEqual(100, \
                          self.cvt.convert_to_decimal("C")) 
     def test_parsing_half_century(self): 
        self.assertEqual(50,\
                         self.cvt.convert_to_decimal("L")) 
     def test_parsing_decade(self): 
        self.assertEqual(10,self.cvt.convert_to_decimal("X")) 
     def test_parsing_half_decade(self): 
        self.assertEqual(5,self.cvt.convert_to_decimal("V")) 
     def test_parsing_one(self): 
        self.assertEqual(1,self.cvt.convert_to_decimal("I")) 
     def test_empty_roman_numeral(self): 
        self.assertTrue(self.cvt.convert_to_decimal() == 0) 
        self.assertFalse(self.cvt.convert_to_decimal() > 0) 
     def test_no_roman_numeral(self): 
        self.assertRaises(TypeError,\
                          self.cvt.convert_to_decimal,None)
```

1.  使整个脚本可运行，然后使用 unittest 的测试运行程序：

```py
if __name__=="__main__": 
     unittest.main()
```

1.  从命令行运行文件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00008.jpeg)

# 它是如何工作的...

在第一步中，我们选择了一个要测试的类。接下来，我们创建了一个单独的测试类。通过将测试类命名为`[class under test]Test`，很容易知道哪个类正在被测试。

然后，我们定义了一个`setUp`方法，unittest 在每个`Test`方法之前运行。接下来，我们创建了一个`tearDown`方法，unittest 在每个`Test`方法之后运行。在这种情况下，我们在每个方法中添加了一个打印语句，以演示 unittest 重新运行这两个方法以进行每个测试方法。实际上，这可能会给我们的测试添加太多噪音。

unittest 的一个不足之处是缺少`setUpClass`/`tearDownClass`和`setUpModule`/`tearDownModule`，这提供了在比测试方法级别更大的范围内运行代码的机会。这已经添加到`unittest2`中。

**每个测试用例可以有一个 setUp 和一个 tearDown 方法：**我们的`RomanNumeralConverter`非常简单，很容易适应一个单独的测试类。但是测试类只允许一个`setUp`方法和一个`tearDown`方法。如果需要不同组合的`setUp`/`tearDown`方法来进行各种测试场景，那么这就是编写更多测试类的线索。仅仅因为我们编写了一个`setUp`方法，并不意味着我们需要一个`tearDown`方法。在我们的情况下，我们可以跳过销毁`RomanNumeralConverter`，因为一个新实例将替换它用于每个测试方法。这只是为了演示目的。那些需要`tearDown`方法的其他用例有哪些其他用途？使用需要某种关闭操作的库是编写`tearDown`方法的一个很好的候选者。

# 从命令行运行测试用例

很容易调整测试运行程序，以便在运行时打印出每个测试方法。

# 如何做...

在接下来的步骤中，我们将以更详细的输出运行测试用例，以便更好地了解事物的运行情况：

1.  为这个配方的代码创建一个名为`recipe3.py`的新文件。

1.  选择一个要测试的类。在这种情况下，我们将使用我们的罗马数字转换器：

```py
class RomanNumeralConverter(object): 
    def __init__(self, roman_numeral): 
        self.roman_numeral = roman_numeral 
        self.digit_map = {"M":1000, "D":500, "C":100, "L":50,\
                           "X":10,"V":5, "I":1} 

    def convert_to_decimal(self):
        val = 0 
        for char in self.roman_numeral:
            val += self.digit_map[char] 
        return val
```

1.  使用与被测试类相同的名称创建一个测试类，在末尾添加`Test`：

```py
import unittest
class RomanNumeralConverterTest(unittest.TestCase): 
```

1.  创建几个测试方法。对于这个配方，第二个测试故意编码失败：

```py
def test_parsing_millenia(self): 
    value =RomanNumeralConverter("M") 
    self.assertEqual(1000, value.convert_to_decimal()) 

def test_parsing_century(self): 
    "This test method is coded to fail for demo."
     value =RomanNumeralConverter("C") 
     self.assertEqual(10, value.convert_to_decimal()) 
```

1.  定义一个测试套件，它自动加载所有测试方法，然后以更高级别的详细程度运行它们：

```py
if __name__== "__main__": 
    suite = unittest.TestLoader().loadTestsFromTestCase(\
              RomanNumeralConverterTest) 
    unittest.TextTestRunner(verbosity=2).run(suite) 
```

1.  从命令行运行文件。请注意，在这个截图中，失败的测试方法打印出其 Python 文档字符串：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00009.jpeg)

# 工作原理...

自动化测试的关键部分是组织测试。基本单元称为**测试用例**。这些可以组合成**测试套件**。Python 的 unittest 模块提供了`TestLoader().loadTestsFromTestCase`，可以自动将所有`test*`方法加载到一个测试套件中。然后通过 unittest 的`TextTestRunner`以更高级别的详细程度运行这个测试套件。

`TextTestRunner`是 unittest 的唯一测试运行器。在本书的后面，我们将看到其他具有不同运行器的测试工具，包括插入不同 unittest 测试运行器的运行器。

前面的截图显示了每个方法以及其模块和类名，以及成功/失败。

# 还有更多...

这个配方不仅演示了如何提高运行测试的详细程度，还展示了当测试用例失败时会发生什么。它将`test`方法重命名为嵌入在`test`方法中的文档字符串，并在所有测试方法报告后打印详细信息。

# 运行测试用例方法的子集

有时，只运行给定测试用例中的一部分测试方法很方便。这个配方将展示如何从命令行运行整个测试用例，或者选择一个子集。

# 如何做...

以下步骤显示了如何编写一个命令行脚本来运行测试的子集：

1.  创建一个名为`recipe4.py`的新文件，放置这个配方的所有代码。

1.  选择一个要测试的类。在这种情况下，我们将使用我们的罗马数字转换器：

```py
class RomanNumeralConverter(object):
    def __init__(self, roman_numeral): 
        self.roman_numeral = roman_numeral 
        self.digit_map = {"M":1000, "D":500,\
                        "C":100, "L":50, "X":10, "V":5, "I":1} 

    def convert_to_decimal(self):
        val = 0 
        for char in self.roman_numeral: 
            val+=self.digit_map[char]
        return val
```

1.  使用与要测试的类相同的名称创建一个测试类，并在末尾添加`Test`：

```py
import unittest 
class RomanNumeralConverterTest(unittest.TestCase): 
```

1.  创建几个`test`方法：

```py
    def test_parsing_millenia(self):
        value = RomanNumeralConverter("M") 
        self.assertEquals(1000, value.convert_to_decimal()) 

    def test_parsing_century(self):
        value = RomanNumeralConverter("C") 
        self.assertEquals(100, value.convert_to_decimal()) 
```

1.  编写一个主运行程序，要么运行整个测试用例，要么接受可变数量的测试方法：

```py
if __name__= "__main__":
    import sys
    suite = unittest.TestSuite()
    if len(sys.argv) == 1:
        suite = unittest.TestLoader().loadTestsFromTestCase(\                                                                       RomanNumeralConverterTest) 
    else: 
        for test_name in sys.argv[1:]:
            suite.addTest(RomanNumeralConverterTest(test_name))

    unittest.TextTestRunner(verbosity=2).run(suite) 
```

1.  不带额外命令行参数运行该配方，并查看它运行所有测试，如此截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00010.jpeg)

# 工作原理...

对于这个测试用例，我们编写了几个测试方法。但是，我们没有简单地运行所有测试，或者定义一个固定的列表，而是使用 Python 的`sys`库来解析命令行参数。如果没有额外的参数，它将运行整个测试用例。如果有额外的参数，那么它们被假定为测试方法名称。它使用 unittest 的内置能力在实例化`RomanNumeralConverterTest`时指定测试方法名称。

# 将一系列测试链接在一起

Unittest 使得将测试用例链接成`TestSuite`变得很容易。`TestSuite`可以像`TestCase`一样运行，但它还提供了额外的功能来添加单个/多个测试，并对其进行计数。

为什么我们需要这个？将测试链接成一个套件使我们能够将多个测试用例模块汇集到一个测试运行中，以及挑选和选择测试用例的子集。到目前为止，我们通常运行单个类中的所有测试方法。`TestSuite`给我们提供了一个替代方法来定义一个测试块。

# 如何做...

在接下来的步骤中，我们将编写多个测试用例类，然后将它们的测试方法加载到套件中，以便我们可以运行它们：

1.  创建一个名为`recipe5.py`的新文件，放置我们的示例应用程序和测试用例。

1.  选择一个要测试的类。在这种情况下，我们将使用我们的罗马数字转换器：

```py
class RomanNumeralConverter(object): 
    def __init__(self): 
            self.digit_map = {"M":1000, "D":500,\
                        "C":100, "L":50, "X":10, "V":5, "I":1} 

    def convert_to_decimal(self, roman_numeral):
            val = 0 
            for char in roman_numeral: 
                val += self.digit_map[char] 
            return val 
```

1.  创建两个测试类，它们之间分布着各种测试方法：

```py
import unittest 
class RomanNumeralConverterTest(unittest.TestCase): 
    def setUp(self): 
        self.cvt = RomanNumeralConverter()
    def test_parsing_millenia(self): 
        self.assertEquals(1000, \ 
                    self.cvt.convert_to_decimal("M")) 

    def test_parsing_century(self): 
        self.assertEquals(100, \ 
                    self.cvt.convert_to_decimal("C")) 

class RomanNumeralComboTest(unittest.TestCase):
    def setUp(self):
        self.cvt=RomanNumeralConverter()
    def test_multi_millenia(self):
        self.assertEquals(4000,\
    def test_multi_add_up(self): 
        self.assertEquals(2010, \ 
        self.cvt.convert_to_decimal("MMX"))
```

1.  在一个名为`recipe5_runner.py`的单独文件中创建一个测试运行器，它引入了两个测试用例：

```py
if __name__ == "__main__": 
    import unittest 
    from recipe5 import * 
    suite1 = unittest.TestLoader().loadTestsFromTestCase( \  
                RomanNumeralConverterTest) 
    suite2 = unittest.TestLoader().loadTestsFromTestCase( \ 
                RomanNumeralComboTest) 
    suite = unittest.TestSuite([suite1, suite2])     
    unittest.TextTestRunner(verbosity=2).run(suite)
```

1.  执行测试运行器，并从这个截图中观察到测试是如何从两个测试用例中提取出来的。

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00011.jpeg)

# 工作原理...

unittest 模块提供了一种方便的方法，可以找到`TestClass`中的所有测试方法，并使用其`loadTestsFromTestCase`将它们捆绑在一起作为一个套件。为了进一步使用测试套件，我们能够将这两个套件组合成一个单一的套件，使用`unittest.TestSuite([list...])`。`TestSuite`类被设计为像`TestCase`类一样运行，尽管它不是`TestClass`的子类，但允许我们使用`TextTestRunner`来运行它。这个配方显示了详细程度的提高，让我们能够看到确切运行了哪些测试方法，以及它们来自哪个测试用例。

# 还有更多...

在这个配方中，我们从一个不同的文件中运行了测试，而不是测试用例被定义的文件。这与以前的配方不同，以前的配方中可运行的代码和测试用例都包含在同一个文件中。由于运行器定义了我们要运行的测试，我们可以轻松地创建更多的运行器，结合不同的测试套件。

# 测试用例的名称应该有意义

在以前的配方中，建议将测试用例命名为`[要测试的类]Test`。这是为了让读者明白，被测试的类和相关的测试之间有重要的关系。现在我们引入了另一个测试用例，我们需要选择一个不同的名称。名称应该清楚地解释为什么这些特定的测试方法被拆分到一个单独的类中。对于这个配方，这些方法被拆分出来以展示更复杂的罗马数字组合。

# 在测试模块内定义测试套件

每个测试模块可以提供一个或多个方法，定义不同的测试套件。一个方法可以在给定模块中执行所有测试，另一个方法可以定义一个特定的子集。

# 如何做...

通过以下步骤，我们将创建一些方法，使用不同的方式定义测试套件：

1.  创建一个名为`recipe6.py`的新文件，以放置我们这个配方的代码。

1.  选择一个要测试的类。在这种情况下，我们将使用我们的罗马数字转换器：

```py
class RomanNumeralConverter(object): 
    def __init__(self): 
        self.digit_map = {"M":1000, "D":500, "C":100, "L":50, "X":10, "V":5, "I":1} 

    def convert_to_decimal(self, roman_numeral): 
    val = 0 
    for char in roman_numeral: 
        val += self.digit_map[char] 
    return val 
```

1.  使用与要测试的类相同的名称创建一个测试类，并在末尾添加`Test`：

```py
import unittest 
class RomanNumeralConverterTest(unittest.TestCase): 
```

1.  编写一系列测试方法，包括一个`setUp`方法，为每个测试方法创建一个`RomanNumeralConverter`的新实例：

```py
import unittest 

class RomanNumeralConverterTest(unittest.TestCase): 
    def setUp(self): 
        self.cvt = RomanNumeralConverter() 

    def test_parsing_millenia(self): 
        self.assertEquals(1000, \ 
             self.cvt.convert_to_decimal("M")) 

    def test_parsing_century(self): 
        self.assertEquals(100, \ 
            self.cvt.convert_to_decimal("C")) 

    def test_parsing_half_century(self): 
        self.assertEquals(50, \ 
            self.cvt.convert_to_decimal("L")) 

    def test_parsing_decade(self): 
        self.assertEquals(10, \ 
            self.cvt.convert_to_decimal("X")) 

    def test_parsing_half_decade(self): 
        self.assertEquals(5, self.cvt.convert_to_decimal("V")) 

    def test_parsing_one(self): 
        self.assertEquals(1, self.cvt.convert_to_decimal("I")) 

    def test_empty_roman_numeral(self):     
        self.assertTrue(self.cvt.convert_to_decimal("") == 0) 
        self.assertFalse(self.cvt.convert_to_decimal("") > 0) 

    def test_no_roman_numeral(self): 
        self.assertRaises(TypeError, \ 
            self.cvt.convert_to_decimal, None) 

    def test_combo1(self): 
        self.assertEquals(4000, \ 
            self.cvt.convert_to_decimal("MMMM")) 

    def test_combo2(self): 
        self.assertEquals(2010, \ 
            self.cvt.convert_to_decimal("MMX")) 

    def test_combo3(self): 
        self.assertEquals(4668, \ 
            self.cvt.convert_to_decimal("MMMMDCLXVIII")) 
```

1.  在配方模块中创建一些方法（但不在测试用例中），定义不同的测试套件：

```py
def high_and_low(): 
    suite = unittest.TestSuite() 
    suite.addTest(\ 
        RomanNumeralConverterTest("test_parsing_millenia"))    
    suite.addTest(\ 
        RomanNumeralConverterTest("test_parsing_one")) return suite 
def combos(): 
    return unittest.TestSuite(map(RomanNumeralConverterTest,\    
        ["test_combo1", "test_combo2", "test_combo3"])) 
def all(): 
    return unittest.TestLoader().loadTestsFromTestCase(\   
            RomanNumeralConverterTest) 
```

1.  创建一个运行器，它将遍历每个测试套件并通过 unittest 的`TextTestRunner`运行它们：

```py
if __name__ == "__main__": 
    for suite_func in [high_and_low, combos, all]: 
        print ("Running test suite '%s'" % suite_func.__name__)  
        suite = suite_func()    
        unittest.TextTestRunner(verbosity=2).run(suite)
```

1.  运行测试套件的组合，并查看结果。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00012.jpeg)

# 它是如何工作的...

我们选择一个要测试的类，并定义一些测试方法来检查事情。然后我们定义一些模块级别的方法，比如`high_and_low`，`combos`和`all`，来定义测试套件。其中两个包含固定的方法子集，而`all`动态加载类中的`test*`方法。最后，我们的模块的主要部分遍历所有这些生成套件的函数的列表，以顺利地创建和运行它们。

# 还有更多...

我们所有的测试套件都是从配方的主运行器中运行的。但这可能不适用于一个真正的项目。相反，想法是定义不同的套件，并编写一个机制来选择要运行的套件。每个套件都针对不同的目的，有必要允许开发人员选择要运行的套件。这可以通过使用 Python 的 optparse 模块编写一个命令行脚本来完成，以定义命令行标志来选择其中一个套件。

# 测试套件方法必须在测试类之外

如果我们将这些定义套件的方法作为测试类的成员，我们将不得不实例化测试类。扩展`unittest.TestCase`的类具有一个专门的`init`方法，它与仅用于调用非测试方法的实例不兼容。这就是为什么这些方法在测试类之外的原因。虽然这些方法可以在其他模块中，但在包含测试代码的模块内定义它们非常方便，以保持它们的接近性。

# 为什么有不同的测试套件？

如果我们一开始就运行所有测试项目会怎样？听起来是个好主意，对吧？但是如果运行整个测试套件的时间增长到一个小时以上怎么办？在一定的阈值之后，开发人员往往会停止运行测试，*没有比未运行的测试套件更糟糕的了*。通过定义测试的子集，可以轻松地在白天运行备用套件，然后也许每天运行一次全面的测试套件。请记住以下几点：

+   `all`是全面的测试套件

+   `high_and_low`是测试边缘情况的一个例子

+   `combos`是用于显示事物通常工作的值的随机抽样

定义我们的测试套件是一个判断。每隔一段时间重新评估每个测试套件也是值得的。如果一个测试套件运行成本太高，考虑将一些更昂贵的测试移到另一个套件中。

# optparse 正在被淘汰，并被 argparse 替代

虽然`optparse`是向 Python 脚本添加命令行标志的一种方便方式，但它不会永远可用。Python 2.7 已经弃用了这个模块，并在`argparse`中继续开发。

# 重新调整旧的测试代码以在 unittest 中运行

有时，我们可能已经开发了演示代码来测试我们的系统。我们不必重写它以在 unittest 中运行。相反，将它连接到测试框架并进行一些小的更改即可轻松运行。

# 如何做...

通过这些步骤，我们将深入捕获那些没有使用 unittest 编写的测试代码，并以最小的努力重新用途化它们以在 unittest 中运行：

1.  创建一个名为`recipe7.py`的文件，用于放置我们将要测试的应用程序代码。

1.  选择一个要测试的类。在这种情况下，我们将使用我们的罗马数字转换器：

```py
class RomanNumeralConverter(object): 
    def __init__(self): 
        self.digit_map = {"M":1000, "D":500, "C":100, "L":50, "X":10, "V":5, "I":1} 

    def convert_to_decimal(self, roman_numeral): 
        val = 0 
        for char in roman_numeral: 
            val += self.digit_map[char] 
        return val 
```

1.  创建一个名为`recipe7_legacy.py`的新文件，其中包含不使用 unittest 模块的测试代码。

1.  创建一组遗留测试，根据 Python 的`assert`函数编码，而不是使用 unittest，以及一个运行器：

```py
from recipe7 import * 
class RomanNumeralTester(object): 
  def   init  (self): 
    self.cvt = RomanNumeralConverter() 
  def simple_test(self):
    print ("+++ Converting M to 1000")
    assert self.cvt.convert_to_decimal("M") == 1000
  def combo_test1(self): 
    print ("+++ Converting MMX to 2010") 
    assert self.cvt.convert_to_decimal("MMXX") == 2010 
  def combo_test2(self): 
    print ("+++ Converting MMMMDCLXVIII to 4668") 
    val = self.cvt.convert_to_decimal("MMMMDCLXVII")         
    self.check(val, 4668) 
  def other_test(self): 
    print ("+++ Converting MMMM to 4000") 
    val = self.cvt.convert_to_decimal("MMMM") 
    self.check(val, 4000) 
  def check(self, actual, expected): 
    if (actual != expected): 
      raise AssertionError("%s doesn't equal %s" % \ 
            (actual,  expected)) 
  def test_the_system(self): 
    self.simple_test() 
    self.combo_test1() 
    self.combo_test2() 
    self.other_test() 
if __name == "__main__": 
  tester = RomanNumeralTester() 
  tester.test_the_system()
```

这组遗留测试旨在代表我们团队在 unittest 成为一个选择之前开发的遗留测试代码。

1.  运行遗留测试。这种情况有什么问题？所有测试方法都运行了吗？我们有没有捕捉到所有的 bug？看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00013.jpeg)

1.  创建一个名为`recipe7_pyunit.py`的新文件。

1.  创建一个 unittest 测试集，将每个遗留测试方法包装在 unittest 的`FunctionTestCase`中：

```py
from recipe7 import * 
from recipe7_legacy import * import unittest 

if __name__ == "__main__":  
    tester = RomanNumeralTester() 
    suite = unittest.TestSuite() 
    for test in [tester.simple_test, tester.combo_test1, \ 
            tester.combo_test2, tester.other_test]: 
        testcase = unittest.FunctionTestCase(test)   
        suite.addTest(testcase) 
    unittest.TextTestRunner(verbosity=2).run(suite)
```

1.  运行 unittest 测试。这次所有测试都运行了吗？哪个测试失败了？bug 在哪里？看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00014.jpeg)

# 它是如何工作的...

Python 提供了一个方便的断言语句来测试条件。当条件为真时，代码继续执行。当条件为假时，它会引发`AssertionError`。在第一个测试运行器中，我们有几个测试，使用`assert`语句或引发`AssertionError`来检查结果。

unittest 提供了一个方便的类，`unittest.FunctionTestCase`，它将绑定的函数包装为 unittest 测试用例。如果抛出`AssertionError`，`FunctionTestCase`会捕获它，将其标记为测试*失败*，然后继续下一个测试用例。如果抛出任何其他类型的异常，它将被标记为测试错误。在第二个测试运行器中，我们使用`FunctionTestCase`包装每个这些遗留测试方法，并将它们链接在一起，以便 unittest 运行。

通过运行第二个测试运行，可以看到第三个测试方法中隐藏着一个 bug。我们之前并不知道这个 bug，因为测试套件被过早中断了。

Python 的`assert`语句的另一个不足之处可以从前面的截图中的第一个失败中看出。当断言失败时，几乎没有关于被比较的值的信息。我们只有它失败的代码行。截图中的第二个断言更有用，因为我们编写了一个自定义检查器，它抛出了一个自定义的`AssertionError`。

# 还有更多...

Unittest 不仅仅是运行测试。它有一个内置的机制来捕获错误和失败，然后尽可能多地继续运行我们的测试套件。这有助于我们在给定的测试运行中摆脱更多的错误并修复更多的问题。当测试套件增长到需要花费几分钟甚至几小时才能运行时，这一点尤为重要。

# 错误在哪里？

它们存在于测试方法中，并且基本上是通过对被转换的罗马数字进行轻微修改而产生的，如代码所示：

```py
def combo_test1(self): 
    print ("+++ Converting MMX to 2010") 
    assert self.cvt.convert_to_decimal("MMXX") == 2010 
def combo_test2(self): 
    print ("+++ Converting MMMMDCLXVIII to 4668")
    val = self.cvt.convert_to_decimal("MMMMDCLXVII") 
    self.check(val, 4668) 
```

`combo_test1`测试方法打印出正在转换`MMX`，但实际上尝试转换`MMXX`。`combo_test2`测试方法打印出正在转换`MMMMDCLXVIII`，但实际上尝试转换`MMMMDCLXVII`。

这是一个刻意的例子，但你是否曾经遇到过同样小的错误，让你疯狂地试图追踪它们？关键是，显示追踪它们有多容易或多困难取决于如何检查值。Python 的`assert`语句在告诉我们在哪里比较值方面并不是很有效。自定义的`check`方法在指出`combo_test2`的问题方面要好得多。

这突显了使用注释或打印语句来反映断言所做的事情的问题。它们很容易失去同步，开发人员可能会在追踪错误时遇到一些问题。避免这种情况被称为**DRY**原则（**不要重复自己**）。

# FunctionTestCase 是一个临时措施

`FunctionTestCase`是一个测试用例，它提供了一种快速迁移基于 Python 的`assert`语句的测试的简单方法，因此它们可以与 unittest 一起运行。但事情不应该止步于此。如果我们花时间将`RomanNumeralTester`转换为 unittest 的`TestCase`，那么我们就可以使用`TestCase`提供的其他有用功能，比如各种`assert*`方法。这是一个很好的投资。`FunctionTestCase`只是降低了迁移到 unittest 的门槛。

# 将模糊测试拆分为简单测试

Unittest 提供了通过一系列断言来测试代码的手段。我经常感到诱惑，想在单个测试方法中测试代码的许多方面。如果任何部分失败，哪一部分失败就变得模糊了。最好将事情分解成几个较小的测试方法，这样当被测试的代码的某些部分失败时，就很明显了。

# 如何做到...

通过这些步骤，我们将调查将太多内容放入单个测试方法时会发生什么：

1.  创建一个名为`recipe8.py`的新文件，用于放置此配方的应用代码。

1.  选择一个要测试的类。在这种情况下，我们将使用罗马数字转换器的另一种版本，它可以双向转换：

```py
class RomanNumeralConverter(object): 
    def __init__(self): 
        self.digit_map = {"M":1000, "D":500, "C":100, "L":50, "X":10, "V":5, "I":1} 

    def convert_to_decimal(self, roman_numeral): 
        val = 0 
        for char in roman_numeral: 
        val += self.digit_map[char] 
    return val 

    def convert_to_roman(self, decimal): 
        val = "" 
    while decimal > 1000: 
        val += "M" 
        decimal -= 1000 
    while decimal > 500: 
        val += "D"
        decimal -= 500 
    while decimal > 100: 
        val += "C" 
        decimal -= 100 
    while decimal > 50: 
        val += "L" 
        decimal -= 50 
    while decimal > 10: 
        val += "X" 
        decimal -= 10 
    while decimal > 5: 
        val += "V" 
        decimal -= 5 
    while decimal > 1: 
        val += "I" 
        decimal -= 1 
    return val 
```

1.  创建一个名为`recipe8_obscure.py`的新文件，以放置一些更长的测试方法。

1.  创建一些结合了几个测试断言的测试方法：

```py
import unittest 
from recipe8 import * 

class RomanNumeralTest(unittest.TestCase): 
    def setUp(self): 
        self.cvt = RomanNumeralConverter() 

    def test_convert_to_decimal(self): 
        self.assertEquals(0, self.cvt.convert_to_decimal(""))     
        self.assertEquals(1, self.cvt.convert_to_decimal("I"))    
        self.assertEquals(2010, \ 
            self.cvt.convert_to_decimal("MMX")) 
        self.assertEquals(4000, \ 
            self.cvt.convert_to_decimal("MMMM")) 
    def test_convert_to_roman(self): 
        self.assertEquals("", self.cvt.convert_to_roman(0)) 
        self.assertEquals("II", self.cvt.convert_to_roman(2))     
        self.assertEquals("V", self.cvt.convert_to_roman(5))    
        self.assertEquals("XII", \ 
            self.cvt.convert_to_roman(12)) 
        self.assertEquals("MMX", \ 
            self.cvt.convert_to_roman(2010)) 
        self.assertEquals("MMMM", \ 
            self.cvt.convert_to_roman(4000))

if __name__ == "__main__":  
    unittest.main()
```

1.  运行模糊测试。为什么会失败？错误在哪里？报告说`II`不等于`I`，所以似乎有些问题。这是唯一的错误吗？创建另一个名为`recipe8_clear.py`的文件，以创建一组更精细的测试方法。看一下这个截图：![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00015.jpeg)

1.  将断言拆分为单独的测试方法，以提供更高的输出保真度：

```py
import unittest 
from recipe8 import * 

class RomanNumeralTest(unittest.TestCase): 
    def setUp(self): 
        self.cvt = RomanNumeralConverter() 

    def test_to_decimal1(self): 
        self.assertEquals(0, self.cvt.convert_to_decimal("")) 

    def test_to_decimal2(self): 
        self.assertEquals(1, self.cvt.convert_to_decimal("I")) 

    def test_to_decimal3(self): 
        self.assertEquals(2010, \ 
            self.cvt.convert_to_decimal("MMX")) 

    def test_to_decimal4(self): 
        self.assertEquals(4000, \ 
            self.cvt.convert_to_decimal("MMMM")) 

    def test_convert_to_roman1(self): 
        self.assertEquals("", self.cvt.convert_to_roman(0)) 

    def test_convert_to_roman2(self): 
        self.assertEquals("II", self.cvt.convert_to_roman(2)) 

    def test_convert_to_roman3(self): 
        self.assertEquals("V", self.cvt.convert_to_roman(5)) 

    def test_convert_to_roman4(self): 
        self.assertEquals("XII", \ 
                    self.cvt.convert_to_roman(12)) 

    def test_convert_to_roman5(self): 
        self.assertEquals("MMX", \ 
                    self.cvt.convert_to_roman(2010)) 

    def test_convert_to_roman6(self): 
        self.assertEquals("MMMM", \ 
                    self.cvt.convert_to_roman(4000)) 

if __name__ == "__main__": 
unittest.main() 
```

1.  运行更清晰的测试套件。现在错误的位置更清晰了吗？为了获得更高程度的测试失败，我们做出了什么样的交易？这样做值得吗？参考这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00016.jpeg)

# 它是如何工作的...

在这种情况下，我们创建了一个修改后的罗马数字转换器，可以双向转换。然后我们开始创建测试方法来练习这些事情。由于这些测试都是简单的一行断言，将它们放在同一个测试方法中非常方便。

在第二个测试用例中，我们将每个断言放入一个单独的测试方法中。运行它会暴露出这个罗马数字转换器中存在多个错误。

# 还有更多...

当我们开始编写测试时，将所有这些断言捆绑到一个测试方法中非常方便。毕竟，如果一切正常，那就没有坏处，对吧？但是如果一切都*不*正常呢；我们要如何处理？一个晦涩的错误报告！

# 错误在哪里？

晦涩的测试运行器可能不够清晰。我们只能依靠`II != I`这并不多。线索是它只差一个。清晰的测试运行器提供更多线索。我们看到`V != IIII, XII != XI`，还有更多。这些失败显示了每个都差一个。

错误涉及 while 检查中的各种布尔条件：

```py
while decimal > 1000: 
while decimal > 500: 
while decimal > 100: 
while decimal > 50: 
while decimal > 10: 
while decimal > 5: 
while decimal > 1:
```

它应该测试*大于*或*等于*，而不是测试大于。这会导致它在计算最后一个罗马数字之前跳出。

# 测试方法的合适大小是多少？

在这个示例中，我们将事物分解为每个测试一个断言。但我不建议沿着这样的思路思考。

如果我们再仔细看一些，每个测试方法还涉及对罗马数字 API 的单一使用。对于转换器，在练习代码时只有一个结果需要检查。对于其他系统，输出可能更复杂。在同一个测试方法中使用多个断言来检查通过进行单次调用的结果是完全合理的。

当我们继续对罗马数字 API 进行更多调用时，它应该提示我们考虑将其拆分为一个新的测试方法。

这引发了一个问题：*什么是代码单元？*关于代码单元的定义以及什么样的单元测试才算是好的，一直存在着很多争论。有很多不同的观点。希望阅读本章并将其与本书中涵盖的其他测试策略进行权衡，将有助于您加强自己的观点，最终提高自己的测试技能。

# 单元测试与集成测试

Unittest 可以轻松帮助我们编写单元测试和集成测试。单元测试可以测试较小的代码块。在编写单元测试时，最好将测试保持尽可能小和细粒度。将测试分解为许多较小的测试通常是检测和定位错误的更好方法。

当我们提升到更高级别（如集成测试）时，有意义的是在一个测试方法中测试多个步骤。但只有在有足够的低级单元测试时才建议这样做。这将为我们提供一些线索，表明它是在单元级别出现了问题，还是存在一系列步骤导致了错误。

集成测试通常扩展到诸如外部系统之类的事物。例如，许多人认为单元测试不应该连接到数据库，与 LDAP 服务器通信或与其他系统交互。

仅仅因为我们使用了 unittest 并不意味着我们正在编写的测试就是单元测试。在本书的后面，我们将讨论 unittest 可以用来编写许多类型的测试，包括集成测试、冒烟测试以及其他类型的测试。

# 测试边缘情况

当我们编写自动化测试时，我们选择输入并断言预期的输出。测试输入的极限是很重要的，以确保我们的代码可以处理好和坏的输入。这也被称为**测试边界情况**。

# 如何做...

当我们深入研究这个示例时，我们将寻找好的边界进行测试：

1.  为这个示例创建一个名为`recipe9.py`的新文件。

1.  选择一个要测试的类。在这个示例中，我们将使用我们的罗马数字转换器的另一个变体。这个变体不处理大于`4000`的值：

```py
class RomanNumeralConverter(object): 
    def __init__(self): 
      self.digit_map = {"M":1000, "D":500, "C":100, "L":50, "X":10, "V":5, "I":1} 
    def convert_to_decimal(self, roman_numeral): 
        val = 0 
        for char in roman_numeral: 
            val += self.digit_map[char] 
        if val > 4000: 
        raise Exception("We don't handle values over 4000") 
    return val

    def convert_to_roman(self, decimal): 
        if decimal > 4000: 
            raise Exception("We don't handle values over 4000") 
        val = "" 
        mappers = [(1000,"M"), (500,"D"), (100,"C"), (50,"L"), 
(10,"X"), (5,"V"), (1,"I")] 
        for (mapper_dec, mapper_rom) in mappers: 
            while decimal >= mapper_dec: 
                val += mapper_rom 
                decimal -= mapper_dec 
        return val 
```

1.  创建一个测试用例，设置罗马数字转换器的实例：

```py
import unittest 

class RomanNumeralTest(unittest.TestCase): 
    def setUp(self): 
      self.cvt = RomanNumeralConverter() 
```

1.  添加几个测试方法，以测试转换为罗马数字表示法的边缘情况：

```py
def test_to_roman_bottom(self): 
    self.assertEquals("I", self.cvt.convert_to_roman(1))  

def test_to_roman_below_bottom(self): 
    self.assertEquals("", self.cvt.convert_to_roman(0)) 

def test_to_roman_negative_value(self): 
    self.assertEquals("", self.cvt.convert_to_roman(-1)) 

def test_to_roman_top(self): 
    self.assertEquals("MMMM", \ 
                self.cvt.convert_to_roman(4000)) 

def test_to_roman_above_top(self): 
    self.assertRaises(Exception, \ 
                self.cvt.convert_to_roman, 4001) 
```

1.  添加几个测试方法，以便测试转换为十进制表示法的边缘情况：

```py
def test_to_decimal_bottom(self): 
    self.assertEquals(1, self.cvt.convert_to_decimal("I")) 

def test_to_decimal_below_bottom(self): 
    self.assertEquals(0, self.cvt.convert_to_decimal("")) 

def test_to_decimal_top(self):  
    self.assertEquals(4000, \ 
                self.cvt.convert_to_decimal("MMMM")) 

def test_to_decimal_above_top(self):      
    self.assertRaises(Exception, \ 
                self.cvt.convert_to_decimal, "MMMMI")
```

1.  添加一些测试，以测试将十进制数转换为罗马数字的层次：

```py
def test_to_roman_tier1(self): 
    self.assertEquals("V", self.cvt.convert_to_roman(5)) 

def test_to_roman_tier2(self): 
    self.assertEquals("X", self.cvt.convert_to_roman(10)) 

def test_to_roman_tier3(self): 
    self.assertEquals("L", self.cvt.convert_to_roman(50)) 

def test_to_roman_tier4(self): 
    self.assertEquals("C", self.cvt.convert_to_roman(100)) 

def test_to_roman_tier5(self): 
    self.assertEquals("D", self.cvt.convert_to_roman(500)) 

def test_to_roman_tier6(self): 
    self.assertEquals("M", \ 
                self.cvt.convert_to_roman(1000)) 
```

1.  添加一些测试，输入意外值到罗马数字转换器：

```py
def test_to_roman_bad_inputs(self): 
    self.assertEquals("", self.cvt.convert_to_roman(None))     
    self.assertEquals("I", self.cvt.convert_to_roman(1.2)) 

def test_to_decimal_bad_inputs(self):   
    self.assertRaises(TypeError, \ 
                self.cvt.convert_to_decimal, None) 
    self.assertRaises(TypeError, \ 
                self.cvt.convert_to_decimal, 1.2) 
```

1.  添加一个单元测试运行器：

```py
if __name__ == "__main__": 
  unittest.main() 
```

1.  运行测试用例。看一下这个屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00017.jpeg)

# 工作原理...

我们有一个专门的罗马数字转换器，只能转换到`MMMM`或`4000`的值。我们编写了几个测试方法来测试它。我们立即测试的边缘是`1`和`4000`。我们还为这之后的一步编写了一些测试：`0`和`4001`。为了使事情完整，我们还测试了`-1`。

# 还有更多...

算法的一个关键部分涉及处理各种层次的罗马数字（5、10、50、100、500 和 1000）。这些可以被认为是*微边缘*，所以我们编写了测试来检查代码是否也处理了这些情况。你认为我们应该测试一下微边缘之外的情况吗？

建议我们应该。许多错误是由于编码*大于*而不是*大于或等于*（或反之）等等而引发的。在边界之外进行测试，向两个方向进行测试，是确保事情正如预期的完美方式。我们还需要检查错误的输入，所以我们尝试转换`None`和`float`。

上面的陈述提出了一个重要的问题：*我们应该测试多少种无效类型*？因为 Python 是动态的，我们可以期望许多输入类型。那么，什么是合理的呢？如果我们的代码依赖于字典查找，比如我们的罗马数字 API 的某些部分，那么确认我们正确处理`KeyError`可能就足够了。如果所有不同类型的输入都导致`KeyError`，那么我们就不需要输入很多不同类型。

# 识别边缘很重要

识别系统的边缘很重要，因为我们需要知道我们的软件能够处理这些边界。我们还需要知道它能够处理这些边界的两侧，即好值和坏值。这就是为什么我们需要检查`4000`和`4001`以及`0`和`1`。这是软件经常出错的地方。

# 测试意外条件

这听起来有点别扭吗？预料之外的情况？我们的代码涉及将整数和字符串来回转换。所谓的意外情况，是指当有人使用我们的库时传递了我们没有预料到的边界或将其连接到接收比我们预期的更广泛类型的输入时传递的输入类型。

一个常见的误用情况是当我们的 API 的用户针对一个集合（如列表）进行操作，并意外地传递整个列表，而不是通过迭代传递单个值。另一个经常出现的情况是当我们的 API 的用户由于其代码中的某些其他错误而传递`None`。知道我们的 API 足够强大，能够处理这些情况是很好的。

# 通过迭代测试边界情况

在开发代码时，通常会发现新的边界情况输入。能够将这些输入捕获在可迭代的数组中，使得添加相关的测试方法变得容易。

# 如何做...

在这个示例中，我们将看一种不同的测试边界情况的方法：

1.  为我们在这个示例中的代码创建一个名为`recipe10.py`的新文件。

1.  选择一个类进行测试。在这个示例中，我们将使用我们的罗马数字转换器的另一个变体。这个变体不处理大于`4000`的值：

```py
class RomanNumeralConverter(object): 
    def __init__(self): 
        self.digit_map = {"M":1000, "D":500, "C":100, "L":50, "X":10, "V":5, "I":1} 

    def convert_to_decimal(self, roman_numeral): 
        val = 0 
        for char in roman_numeral: 
            val += self.digit_map[char] 
        if val > 4000: 
            raise Exception(\ 
                "We don't handle values over 4000") 
        return val 

    def convert_to_roman(self, decimal): 
        if decimal > 4000: 
            raise Exception(\ 
                "We don't handle values over 4000") 
        val = ""  
        mappers = [(1000,"M"), (500,"D"), (100,"C"), (50,"L"), 
(10,"X"), (5,"V"), (1,"I")] 
        for (mapper_dec, mapper_rom) in mappers: 
            while decimal >= mapper_dec: 
                val += mapper_rom 
                decimal -= mapper_dec 
        return val 
```

1.  创建一个测试类来测试罗马数字转换器：

```py
import unittest 

class RomanNumeralTest(unittest.TestCase): 
    def setUp(self): 
        self.cvt = RomanNumeralConverter()
```

1.  编写一个测试方法，测试罗马数字转换器的边缘情况：

```py
def test_edges(self): 
    r = self.cvt.convert_to_roman 
    d = self.cvt.convert_to_decimal 
    edges = [("equals", r, "I", 1),\ 
          ("equals", r, "", 0),\ 
          ("equals", r, "", -1),\ 
          ("equals", r, "MMMM", 4000),\ 
          ("raises", r, Exception, 4001),\ 
          ("equals", d, 1, "I"),\ 
          ("equals", d, 0, ""),\ 
          ("equals", d, 4000, "MMMM"),\
          ("raises", d, Exception, "MMMMI") 
         ] 
    [self.checkout_edge(edge) for edge in edges
```

1.  创建一个测试方法，测试从十进制到罗马数字的转换层次：

```py
def test_tiers(self):
    r = self.cvt.convert_to_roman
    edges = [("equals", r, "V", 5),\
         ("equals", r, "VIIII", 9),\
         ("equals", r, "X", 10),\
         ("equals", r, "XI", 11),\
         ("equals", r, "XXXXVIIII", 49),\
         ("equals", r, "L", 50),\
         ("equals", r, "LI", 51),\
         ("equals", r, "LXXXXVIIII", 99),\
         ("equals", r, "C", 100),\
         ("equals", r, "CI", 101),\
         ("equals", r, "CCCCLXXXXVIIII", 499),\
         ("equals", r, "D", 500),\
         ("equals", r, "DI", 501),\
         ("equals", r, "M", 1000)\
        ]
    [self.checkout_edge(edge) for edge in edges]
```

1.  创建一个测试方法，测试一组无效输入：

```py
def test_bad_inputs(self): 
    r = self.cvt.convert_to_roman 
    d = self.cvt.convert_to_decimal 
    edges = [("equals", r, "", None),\ 
        ("equals", r, "I", 1.2),\ 
        ("raises", d, TypeError, None),\ 
        ("raises", d, TypeError, 1.2)\ 
       ] 
    [self.checkout_edge(edge) for edge in edges]
```

1.  编写一个实用方法，迭代边缘情况并根据每个边缘运行不同的断言：

```py
def checkout_edge(self, edge): 
    if edge[0] == "equals": 
      f, output, input = edge[1], edge[2], edge[3]    
      print("Converting %s to %s..." % (input, output))    
      self.assertEquals(output, f(input)) 
    elif edge[0] == "raises": 
      f, exception, args = edge[1], edge[2], edge[3:]    
      print("Converting %s, expecting %s" % \ 
                      (args, exception)) 
      self.assertRaises(exception, f, *args)
```

1.  通过将测试用例加载到`TextTestRunner`中使脚本可运行。

```py
  if __name__ == "__main__": 
    suite = unittest.TestLoader().loadTestsFromTestCase( \    
                RomanNumeralTest) 
    unittest.TextTestRunner(verbosity=2).run(suite)
```

1.  运行测试用例，如此截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00018.jpeg)

# 它是如何工作的...

我们有一个专门的罗马数字转换器，只能转换值到`MMMM`或`4000`。我们写测试的即时边缘是`1`和`4000`。我们还为这之后的一步写了一些测试：`0`和`4001`。为了使事情完整，我们还对`-1`进行了测试。

但我们以稍有不同的方式编写了测试。我们不是将每个测试输入/输出组合作为单独的测试方法来编写，而是将输入和输出值捕捉在嵌入列表中的元组中。然后我们将其提供给我们的测试迭代器`checkout_edge`。因为我们需要`assertEqual`和`assertRaise`调用，所以元组还包括等于或引发以标记使用哪种断言。

最后，为了灵活处理罗马数字和十进制的转换，我们还将我们的罗马数字 API 的`convert_to_roman`和`convert_to_decimal`函数的句柄嵌入到每个元组中。

如下所示，我们抓住了`convert_to_roman`并将其存储在`r`中。然后我们将其嵌入到突出显示的元组的第三个元素中，允许`checkout_edge`函数在需要时调用它：

```py
def test_bad_inputs(self): 
    r = self.cvt.convert_to_roman 
    d = self.cvt.convert_to_decimal 
    edges = [("equals", r, "", None),\ 
         ("equals", r, "I", 1.2),\ 
         ("raises", d, TypeError, None),\ 
         ("raises", d, TypeError, 1.2)\ 
        ] 

    [self.checkout_edge(edge) for edge in edges] 
```

# 还有更多...

算法的一个关键部分涉及处理罗马数字的各个层次（5、10、50、100、500 和 1000）。这些可以被视为*迷你边缘*，因此我们编写了一个单独的测试方法，其中包含要检查的输入/输出值的列表。在*测试边缘*配方中，我们没有包括这些迷你边缘之前和之后的测试，例如`5`的`4`和`6`。现在只需要一行数据来捕捉这个测试，我们在这个配方中有了它。其他所有的都是这样做的（除了 1000）。

最后，我们需要检查错误的输入，因此我们创建了另一种测试方法，尝试将`None`和`float`转换为罗马数字并从中转换。

# 这是否违背了配方-将模糊测试分解为简单测试？

在某种程度上是这样的。如果测试数据条目中的某个地方出现问题，那么整个测试方法将失败。这就是为什么这个配方将事物分解成了三个测试方法而不是一个大的测试方法来覆盖它们所有的原因之一。这是一个关于何时将输入和输出视为更多数据而不是测试方法的判断。如果你发现相同的测试步骤序列重复出现，考虑一下是否有意义将这些值捕捉在某种表结构中，比如在这个配方中使用的列表中。

# 这与配方相比如何-测试边缘？

如果不明显的话，这些是在*测试边缘*配方中使用的完全相同的测试。问题是，你觉得哪个版本更可读？两者都是完全可以接受的。将事物分解为单独的方法使其更精细化，更容易发现问题。将事物收集到数据结构中，就像我们在这个配方中所做的那样，使其更简洁，并可能会激励我们编写更多的测试组合，就像我们为转换层所做的那样。

在我自己的观点中，当测试具有简单输入和输出的算法函数时，更适合使用这种方法来以简洁的格式编写整个测试输入的电池。例如，数学函数，排序算法或者转换函数。

当测试更逻辑和命令式的函数时，另一种方法可能更有用。例如，与数据库交互，导致系统状态发生变化或其他类型的副作用的函数，这些副作用没有封装在返回值中，将很难使用这种方法捕捉。

# 另请参阅

+   *将模糊测试分解为简单测试*

+   *测试边缘*


# 第二章：使用 Nose 运行自动化测试套件

在本章中，我们将涵盖以下示例：

+   用测试变得多管闲事

+   将鼻子嵌入 Python 中

+   编写一个 nose 扩展来基于正则表达式选择测试

+   编写一个 nose 扩展来生成 CSV 报告

+   编写一个项目级脚本，让您运行不同的测试套件

# 介绍

在上一章中，我们看了几种利用 unittest 创建自动化测试的方法。现在，我们将看看不同的方法来收集测试并运行它们。Nose 是一个有用的实用程序，用于发现测试并运行它们。它灵活，可以从命令行或嵌入式脚本运行，并且可以通过插件进行扩展。由于其可嵌入性和高级工具（如项目脚本），可以构建具有测试选项的工具。

nose 提供了 unittest 没有的东西吗？关键的东西包括自动测试发现和有用的插件 API。有许多 nose 插件，提供从特殊格式的测试报告到与其他工具集成的一切。我们将在本章和本书的后面部分更详细地探讨这一点。

有关 nose 的更多信息，请参阅：[`somethingaboutorange.com/mrl/projects/nose`](http://somethingaboutorange.com/mrl/projects/nose)。

我们需要激活我们的虚拟环境，然后为本章的示例安装 nose。

创建一个虚拟环境，激活它，并验证工具是否正常工作：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00019.jpeg)

接下来，使用`pip install nose`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00020.jpeg)

# 用测试变得多管闲事

当提供一个包、一个模块或一个文件时，nose 会自动发现测试。

# 如何做...

通过以下步骤，我们将探讨 nose 如何自动发现测试用例并运行它们：

1.  创建一个名为`recipe11.py`的新文件，用于存储此示例的所有代码。

1.  创建一个用于测试的类。对于这个示例，我们将使用一个购物车应用程序，让我们加载物品，然后计算账单：

```py
class ShoppingCart(object):
      def __init__(self):
          self.items = []
      def add(self, item, price):
          self.items.append(Item(item, price))
          return self
     def item(self, index):
          return self.items[index-1].item
     def price(self, index):
          return self.items[index-1].price
     def total(self, sales_tax):
          sum_price = sum([item.price for item in self.items])
          return sum_price*(1.0 + sales_tax/100.0)
     def __len__(self):
          return len(self.items)
class Item(object):
     def __init__(self, item, price):
          self.item = item
          self.price = price
```

1.  创建一个测试用例，练习购物车应用程序的各个部分：

```py
import unittest
class ShoppingCartTest(unittest.TestCase):
     def setUp(self):
        self.cart = ShoppingCart().add("tuna sandwich", 15.00)
     def test_length(self):
        self.assertEquals(1, len(self.cart))
     def test_item(self):
        self.assertEquals("tuna sandwich", self.cart.item(1))
     def test_price(self):
        self.assertEquals(15.00, self.cart.price(1))
     def test_total_with_sales_tax(self):
        self.assertAlmostEquals(16.39,
        self.cart.total(9.25), 2)
```

1.  使用命令行`nosetests`工具按文件名和模块运行此示例：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00021.jpeg)

# 工作原理...

我们首先创建了一个简单的应用程序，让我们用`Items`加载`ShoppingCart`。这个应用程序让我们查找每个物品及其价格。最后，我们可以计算包括销售税在内的总账单金额。

接下来，我们编写了一些测试方法，以使用 unittest 来练习所有这些功能。

最后，我们使用了命令行`nosetests`工具，它发现测试用例并自动运行它们。这样可以避免手动编写测试运行器来加载测试套件。

# 还有更多...

为什么不编写测试运行器如此重要？使用`nosetests`我们能获得什么？毕竟，unittest 给了我们嵌入自动发现测试运行器的能力，就像这样：

```py
if __name__ == "__main__": 
    unittest.main()
```

如果测试分布在多个模块中，同一段代码块是否能够工作？不行，因为`unittest.main()`只查找当前模块。要扩展到多个模块，我们需要开始使用 unittest 的`loadTestsFromTestCase`方法或其他自定义套件来加载测试。我们如何组装套件并不重要。当我们有遗漏测试用例的风险时，`nosetests`方便地让我们搜索所有测试，或者根据需要搜索一部分测试。

在项目中常见的情况是将测试用例分布在许多模块之间。我们通常不会编写一个大的测试用例，而是根据各种设置、场景和其他逻辑分组将其分解为较小的测试用例。根据正在测试的模块拆分测试用例是一种常见做法。关键是，手动加载真实世界测试套件的所有测试用例可能会变得费力。

# Nose 是可扩展的

自动发现测试并不是使用 nose 的唯一原因。在本章的后面，我们将探讨如何编写插件来自定义它发现的内容以及测试运行的输出。

# Nose 是可嵌入的

nose 提供的所有功能都可以通过命令行或 Python 脚本来使用。我们还将在本章中进一步探讨这一点。

# 另请参阅

第一章中的*断言基础*食谱，*使用 Unittest 开发基本测试*。

# 将 nose 嵌入 Python 中

将 nose 嵌入 Python 脚本中非常方便。这不仅让我们创建更高级的测试工具，还允许开发人员将测试添加到现有工具中。

# 如何做...

通过这些步骤，我们将探索在 Python 脚本中使用 nose 的 API 来运行一些测试：

1.  创建一个名为`recipe12.py`的新文件，以包含此示例中的代码。

1.  创建一个要测试的类。对于这个示例，我们将使用一个购物车应用程序，它让我们加载物品然后计算账单：

```py
class ShoppingCart(object):
   def __init__(self):
      self.items = []
   def add(self, item, price):
      self.items.append(Item(item, price))
      return self
   def item(self, index):
      return self.items[index-1].item
   def price(self, index):
      return self.items[index-1].price
   def total(self, sales_tax):
      sum_price = sum([item.price for item in self.items])
      return sum_price*(1.0 + sales_tax/100.0)
   def __len__(self):
      return len(self.items)
class Item(object):
   def __init__(self, item, price):
      self.item = item
      self.price = price
```

1.  创建一个包含多个测试方法的测试用例：

```py
import unittest
class ShoppingCartTest(unittest.TestCase):
   def setUp(self): 
      self.cart = ShoppingCart().add("tuna sandwich", 15.00)
   def test_length(self):
      self.assertEquals(1, len(self.cart))
   def test_item(self):
      self.assertEquals("tuna sandwich", self.cart.item(1))
   def test_price(self):
      self.assertEquals(15.00, self.cart.price(1))
   def test_total_with_sales_tax(self):
      self.assertAlmostEquals(16.39,
      self.cart.total(9.25), 2)
```

1.  创建一个名为`recipe12_nose.py`的脚本，以使用 nose 的 API 来运行测试。

1.  使脚本可运行，并使用 nose 的`run()`方法来运行选定的参数：

```py
if __name__ == "__main__":
    import nose
    nose.run(argv=["", "recipe12", "--verbosity=2"])
```

1.  从命令行运行测试脚本并查看详细输出：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00022.jpeg)

# 它是如何工作的...

在测试运行代码中，我们使用了`nose.run()`。没有参数时，它简单地依赖于`sys.argv`并像命令行`nosetests`一样运行。但在这个示例中，我们插入了当前模块的名称以及增加的详细信息。

# 还有更多...

Unittest 有`unittest.main()`，它也发现并运行测试用例。这有什么不同？`unittest.main()`旨在在运行它的同一模块中发现测试用例。`nose.run()`函数旨在让我们传入命令行参数或以编程方式加载它们。

例如，看看以下步骤；我们必须完成它们以提高 unittest 的详细程度：

```py
if __name__ == "__main__": 
    import unittest 
    from recipe12 import * 
    suite = unittest.TestLoader().loadTestsFromTestCase( 
                                        ShoppingCartTest) 
    unittest.TextTestRunner(verbosity=2).run(suite) 
```

我们必须导入测试用例，使用测试加载器创建测试套件，然后通过`TextTestRunner`运行它。

要使用 nose 做同样的事情，我们只需要这些：

```py
if __name__ == "__main__": 
    import nose 
    nose.run(argv=["", "recipe12", "--verbosity=2"]) 
```

这更加简洁。我们可以在这里使用`nosetests`的任何命令行选项。当我们使用 nose 插件时，这将非常方便，我们将在本章和本书的其余部分中更详细地探讨。

# 编写一个 nose 扩展来基于正则表达式选择测试

像 nose 这样的开箱即用的测试工具非常有用。但最终，我们会达到一个选项不符合我们需求的地步。Nose 具有编写自定义插件的强大能力，这使我们能够微调 nose 以满足我们的需求。这个示例将帮助我们编写一个插件，允许我们通过匹配测试方法的方法名使用正则表达式来选择性地选择测试方法，当我们运行`nosetests`时。

# 准备工作

我们需要加载`easy_install`以安装即将创建的 nose 插件。如果您还没有它，请访问[`pypi.python.org/pypi/setuptools`](http://pypi.python.org/pypi/setuptools)下载并按照网站上的指示安装该软件包。

如果您刚刚安装了它，那么您将需要执行以下操作：

+   重新构建用于运行本书中代码示例的`virtualenv`

+   使用`pip`重新安装`nose`

# 如何做...

通过以下步骤，我们将编写一个 nose 插件，通过正则表达式选择要运行的测试方法：

1.  创建一个名为`recipe13.py`的新文件，以存储此示例的代码。

1.  创建一个购物车应用程序，我们可以围绕它构建一些测试：

```py
class ShoppingCart(object):
   def __init__(self):
     self.items = []
   def add(self, item, price):
     self.items.append(Item(item, price))
     return self
   def item(self, index):
     return self.items[index-1].item
   def price(self, index):
     return self.items[index-1].price
   def total(self, sales_tax):
     sum_price = sum([item.price for item in self.items])
     return sum_price*(1.0 + sales_tax/100.0)
   def __len__(self):
     return len(self.items)
class Item(object):
   def __init__(self, item, price):
     self.item = item
     self.price = price
```

1.  创建一个包含多个测试方法的测试用例，包括一个不以单词`test`开头的方法：

```py
import unittest
class ShoppingCartTest(unittest.TestCase):
   def setUp(self):
     self.cart = ShoppingCart().add("tuna sandwich", 15.00)
   def length(self):
     self.assertEquals(1, len(self.cart))
   def test_item(self):
     self.assertEquals("tuna sandwich", self.cart.item(1))
   def test_price(self):
     self.assertEquals(15.00, self.cart.price(1))
   def test_total_with_sales_tax(self):
     self.assertAlmostEquals(16.39,
     self.cart.total(9.25), 2)
```

1.  使用命令行中的`nosetests`运行模块，并打开`verbosity`。有多少个测试方法被运行？我们定义了多少个测试方法？

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00023.jpeg)

1.  创建一个名为`recipe13_plugin.py`的新文件，为此配方编写一个鼻子插件。

1.  捕获`sys.stderr`的句柄以支持调试和详细输出：

```py
import sys 
err = sys.stderr 
```

1.  通过子类化`nose.plugins.Plugin`创建一个名为`RegexPicker`的鼻子插件：

```py
import nose
import re
from nose.plugins import Plugin
class RegexPicker(Plugin):
   name = "regexpicker"
   def __init__(self):
      Plugin.__init__(self)
      self.verbose = False
```

我们的鼻子插件需要一个类级别的名称。这用于定义`with-<name>`命令行选项。

1.  覆盖`Plugin.options`并添加一个选项，在命令行上提供模式：

```py
def options(self, parser, env):
    Plugin.options(self, parser, env)
    parser.add_option("--re-pattern",
       dest="pattern", action="store",
       default=env.get("NOSE_REGEX_PATTERN", "test.*"),
       help=("Run test methods that have a method name matching this regular expression"))
```

1.  覆盖`Plugin.configuration`，使其获取模式和详细信息：

```py
def configure(self, options, conf):
     Plugin.configure(self, options, conf)
     self.pattern = options.pattern
     if options.verbosity >= 2:
        self.verbose = True
        if self.enabled:
           err.write("Pattern for matching test methods is %sn" % self.pattern)
```

当我们扩展`Plugin`时，我们继承了一些其他功能，例如`self.enabled`，当使用鼻子的`-with-<name>`时会打开。

1.  覆盖`Plugin.wantedMethod`，使其接受与我们的正则表达式匹配的测试方法：

```py
def wantMethod(self, method):
   wanted =
     re.match(self.pattern, method.func_name) is not None
   if self.verbose and wanted:
      err.write("nose will run %sn" % method.func_name)
   return wanted
```

编写一个测试运行器，通过运行与我们之前运行的相同的测试用例来以编程方式测试我们的插件：

```py
if __name__ == "__main__":
     args = ["", "recipe13", "--with-regexpicker", "--re-pattern=test.*|length", "--verbosity=2"]
     print "With verbosity..."
     print "===================="
     nose.run(argv=args, plugins=[RegexPicker()])
     print "Without verbosity..."
     print "===================="
     args = args[:-1]
     nose.run(argv=args, plugins=[RegexPicker()])
```

1.  执行测试运行器。查看以下截图中的结果，这次运行了多少个测试方法？

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00024.jpeg)

1.  创建一个`setup.py`脚本，允许我们安装并注册我们的插件到`nosetests`：

```py
import sys
try:
        import ez_setup
        ez_setup.use_setuptools()
except ImportError:
        pass
from setuptools import setup
setup(
        name="RegexPicker plugin",
        version="0.1",
        author="Greg L. Turnquist",
        author_email="Greg.L.Turnquist@gmail.com",
        description="Pick test methods based on a regular expression",
        license="Apache Server License 2.0",
        py_modules=["recipe13_plugin"],
        entry_points = {
            'nose.plugins': [
                'recipe13_plugin = recipe13_plugin:RegexPicker'
               ]
        }
)
```

1.  安装我们的新插件：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00025.jpeg)

1.  从命令行使用`--with-regexpicker`运行`nosetests`：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00026.jpeg)

# 它是如何工作的...

编写鼻子插件有一些要求。首先，我们需要类级别的`name`属性。它在几个地方使用，包括定义用于调用我们的插件的命令行开关`--with-<name>`。

接下来，我们编写`options`。没有要求覆盖`Plugin.options`，但在这种情况下，我们需要一种方法来为我们的插件提供正则表达式。为了避免破坏`Plugin.options`的有用机制，我们首先调用它，然后使用`parser.add_option`为我们的额外参数添加一行：

+   第一个未命名的参数是参数的字符串版本，我们可以指定多个参数。如果我们想要的话，我们可以有`-rp`和`-re-pattern`。

+   `Dest`：这是存储结果的属性的名称（请参阅 configure）。

+   `Action`：这指定参数值的操作（存储，追加等）。

+   `Default`：这指定在未提供值时存储的值（请注意，我们使用`test.*`来匹配标准的 unittest 行为）。

+   `Help`：这提供了在命令行上打印的帮助信息。

鼻子使用 Python 的`optparse.OptionParser`库来定义选项。

要了解有关 Python 的`optparse.OptionParser`的更多信息，请参阅[`docs.python.org/library/optparse.html`](http://docs.python.org/library/optparse.html)。

然后，我们编写`configure`。没有要求覆盖`Plugin.configure`。因为我们有一个额外的选项`--pattern`，我们需要收集它。我们还想通过`verbosity`（一个标准的鼻子选项）来打开一个标志。

在编写鼻子插件时，我们可以做很多事情。在我们的情况下，我们想要聚焦于**测试选择**。有几种加载测试的方法，包括按模块和文件名。加载后，它们通过一个方法运行，该方法会投票赞成或反对它们。这些投票者被称为`want*`方法，它们包括`wantModule`，`wantName`，`wantFunction`和`wantMethod`，还有一些其他方法。我们实现了`wantMethod`，在这里我们使用 Python 的`re`模块测试`method.func_name`是否与我们的模式匹配。`want*`方法有三种返回值类型：

+   `True`：这个测试是需要的。

+   `False`：此测试不需要（并且不会被另一个插件考虑）。

+   `None`：插件不关心另一个插件（或鼻子）是否选择。

通过不从`want*`方法返回任何内容来简洁地实现这一点。

`wantMethod`只查看在类内定义的函数。`nosetests`旨在通过许多不同的方法查找测试，并不仅限于搜索`unittest.TestCase`的子类。如果在模块中找到了测试，但不是作为类方法，那么这种模式匹配就不会被使用。为了使这个插件更加健壮，我们需要很多不同的测试，并且可能需要覆盖其他`want*`测试选择器。

# 还有更多...

这个食谱只是浅尝插件功能。它侧重于测试选择过程。

在本章后面，我们将探讨生成专门报告的方法。这涉及使用其他插件钩子，在每次测试运行后收集信息以及在测试套件耗尽后生成报告。Nose 提供了一组强大的钩子，允许详细定制以满足我们不断变化的需求。

插件应该是`nose.plugins.Plugin`的子类。

`Plugin`中内置了很多有价值的机制。子类化是开发插件的推荐方法。如果不这样做，您可能需要添加您没有意识到 nose 需要的方法和属性（当您子类化时会自动获得）。

一个很好的经验法则是子类化 nose API 的部分，而不是覆盖它。

nose API 的在线文档有点不完整。它倾向于假设太多的知识。如果我们覆盖了，但我们的插件没有正确工作，可能很难调试发生了什么。

不要子类化`nose.plugins.IPluginInterface`。

这个类仅用于文档目的。它提供了关于我们的插件可以访问的每个钩子的信息。但它不是为了子类化真正的插件而设计的。

# 编写一个 nose 扩展来生成 CSV 报告

这个食谱将帮助我们编写一个生成自定义报告的插件，列出 CSV 文件中的成功和失败。它用于演示如何在每个测试方法完成后收集信息。

# 准备工作

我们需要加载`easy_install`以安装我们即将创建的 nose 插件。如果您还没有它，请访问[`pypi.python.org/pypi/setuptools`](http://pypi.python.org/pypi/setuptools)下载并按照网站上的指示安装该软件包。

如果您刚刚安装了它，那么您将不得不执行以下操作：

+   重新构建您用于运行本书中代码示例的`virtualenv`

+   使用`easy_install`重新安装 nose

# 如何做...

1.  创建一个名为`recipe14.py`的新文件，用于存储此食谱的代码。

1.  创建一个购物车应用程序，我们可以围绕它构建一些测试：

```py
class ShoppingCart(object):
   def __init__(self):
     self.items = [] 
   def add(self, item, price):
     self.items.append(Item(item, price))
     return self
   def item(self, index):
     return self.items[index-1].item
   def price(self, index):
     return self.items[index-1].price
   def total(self, sales_tax):
     sum_price = sum([item.price for item in self.items])
     return sum_price*(1.0 + sales_tax/100.0)
   def __len__(self):
     return len(self.items)
class Item(object):
   def __init__(self, item, price):
     self.item = item
     self.price = price
```

1.  创建一个包含多个测试方法的测试用例，包括一个故意设置为失败的测试方法：

```py
import unittest
class ShoppingCartTest(unittest.TestCase):
    def setUp(self):
      self.cart = ShoppingCart().add("tuna sandwich", 15.00)
    def test_length(self):
      self.assertEquals(1, len(self.cart))
    def test_item(self):
      self.assertEquals("tuna sandwich", self.cart.item(1))
    def test_price(self):
      self.assertEquals(15.00, self.cart.price(1))
    def test_total_with_sales_tax(self):
      self.assertAlmostEquals(16.39,
      self.cart.total(9.25), 2)
    def test_assert_failure(self):
      self.fail("You should see this failure message in the report.")
```

1.  从命令行使用`nosetests`运行模块。查看下面的截图输出，是否存在 CSV 报告？

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00027.jpeg)

1.  创建一个名为`recipe14_plugin.py`的新文件，用于存储我们的新 nose 插件。

1.  通过子类化`nose.plugins.Plugin`创建一个名为`CsvReport`的 nose 插件：

```py
import nose
import re
from nose.plugins import Plugin
class CsvReport(Plugin):
    name = "csv-report"
    def __init__(self):
      Plugin.__init__(self)
      self.results = []
```

我们的 nose 插件需要一个类级别的`name`。这用于定义`-with-<name>`命令行选项。

1.  覆盖`Plugin.options`并添加一个选项，在命令行上提供报告的文件名：

```py
def options(self, parser, env):
  Plugin.options(self, parser, env)
  parser.add_option("--csv-file",
    dest="filename", action="store",
    default=env.get("NOSE_CSV_FILE", "log.csv"),
    help=("Name of the report"))
```

1.  通过让它从选项中获取文件名来覆盖`Plugin.configuration`：

```py
def configure(self, options, conf):
  Plugin.configure(self, options, conf)
  self.filename = options.filename
```

当我们扩展`Plugin`时，我们会继承一些其他功能，比如`self.enabled`，当使用 nose 的`-with-<name>`时会打开。

1.  覆盖`addSuccess`，`addFailure`和`addError`以在内部列表中收集结果：

```py
def addSuccess(self, *args, **kwargs):
  test = args[0]
  self.results.append((test, "Success"))
def addError(self, *args, **kwargs):
  test, error = args[0], args[1]
  self.results.append((test, "Error", error))
def addFailure(self, *args, **kwargs):
  test, error = args[0], args[1]
  self.results.append((test, "Failure", error))
```

1.  覆盖`finalize`以生成 CSV 报告：

```py
def finalize(self, result):
   report = open(self.filename, "w")
   report.write("Test,Success/Failure,Detailsn")
   for item in self.results:
       if item[1] == "Success":
           report.write("%s,%sn" % (item[0], item[1]))
       else:
           report.write("%s,%s,%sn" % (item[0],item[1], item[2][1]))
    report.close()
```

1.  编写一个测试运行器，通过运行与我们之前运行的相同的测试用例来以编程方式测试我们的插件：

```py
if __name__ == "__main__":
   args = ["", "recipe14", "--with-csv-report", "--csv-file=recipe14.csv"]
nose.run(argv=args, plugin=[CsvReport()])
```

1.  执行测试运行器。查看下一个截图输出，现在是否有测试报告？

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00028.jpeg)

1.  使用您喜欢的电子表格打开并查看报告：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00029.jpeg)

1.  创建一个`setup.py`脚本，允许我们安装并注册我们的插件到`nosetests`：

```py
import sys
try:
   import ez_setup
   ez_setup.use_setuptools()
except ImportError:
   pass
from setuptools import setup
setup(
   name="CSV report plugin",
   version="0.1",
   author="Greg L. Turnquist",
   author_email="Greg.L.Turnquist@gmail.com",
   description="Generate CSV report",
   license="Apache Server License 2.0",
   py_modules=["recipe14_plugin"],
   entry_points = {
       'nose.plugins': [
           'recipe14_plugin = recipe14_plugin:CsvReport'
         ]
   }
)
```

1.  安装我们的新插件：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00030.jpeg)

1.  从命令行运行`nosetests`，使用`--with-csv-report`：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00031.jpeg)

在上一个截图中，注意我们有先前的日志文件`recipe14.csv`和新的日志文件`log.csv`。

# 它是如何工作的...

编写 nose 插件有一些要求。首先，我们需要类级别的`name`属性。它在几个地方使用，包括定义用于调用我们的插件的命令行开关，`--with-<name>`。

接下来，我们编写`options`。没有必要覆盖`Plugin.options`。但在这种情况下，我们需要一种方法来提供我们的插件将写入的 CSV 报告的名称。为了避免破坏`Plugin.options`的有用机制，我们首先调用它，然后使用`parser.add_option`添加我们额外参数的行：

+   未命名的参数是参数的字符串版本

+   `dest`：这是存储结果的属性的名称（参见 configure）

+   `action`：这告诉参数值要执行的操作（存储、追加等）

+   `default`：这告诉了当没有提供值时要存储什么值

+   `help`：这提供了在命令行上打印的帮助信息

Nose 使用 Python 的`optparse.OptionParser`库来定义选项。

要了解更多关于`optparse.OptionParser`的信息，请访问[`docs.python.org/optparse.html`](http://docs.python.org/optparse.html)。

然后，我们编写`configure`。同样，没有必要覆盖`Plugin.configure`。因为我们有一个额外的选项`--csv-file`，我们需要收集它。

在这个配方中，我们希望在测试方法完成时捕获测试用例和错误报告。为此，我们实现`addSuccess`、`addFailure`和`addError`，因为 nose 在以编程方式调用或通过命令行调用这些方法时发送的参数不同，所以我们必须使用 Python 的`*args`：

+   这个元组的第一个槽包含`test`，一个`nose.case.Test`的实例。简单地打印它对我们的需求就足够了。

+   这个元组的第二个槽包含`error`，是`sys.exc_info()`的 3 元组实例。它仅包括在`addFailure`和`addError`中。

+   nose 网站上没有更多关于这个元组的槽的文档。我们通常忽略它们。

# 还有更多...

这个配方深入探讨了插件功能。它侧重于在测试方法成功、失败或导致错误后进行的处理。在我们的情况下，我们只是收集结果以放入报告中。我们还可以做其他事情，比如捕获堆栈跟踪，将失败的邮件发送给开发团队，或者向 QA 团队发送页面，让他们知道测试套件已经完成。

有关编写 nose 插件的更多详细信息，请阅读*编写**nose**扩展*的配方，以根据正则表达式选择测试。

# 编写一个项目级别的脚本，让您运行不同的测试套件

Python 以其多范式的特性，使得构建应用程序并提供脚本支持变得容易。

这个配方将帮助我们探索构建一个项目级别的脚本，允许我们运行不同的测试套件。我们还将展示一些额外的命令行选项，以创建用于打包、发布、注册和编写自动文档的钩子。

# 如何做...

1.  创建一个名为`recipe15.py`的脚本，使用 Python 的`getopt`库解析一组选项：

```py
import getopt
import glob
import logging
import nose
import os
import os.path
import pydoc
import re
import sys
def usage():
    print
    print "Usage: python recipe15.py [command]"
    print
    print "t--help"
    print "t--test"
    print "t--suite [suite]"
    print "t--debug-level [info|debug]"
    print "t--package"
    print "t--publish"
    print "t--register"
    print "t--pydoc"
    print
try:
    optlist, args = getopt.getopt(sys.argv[1:],
                    "ht", 
                    ["help", "test", "suite=",
                    "debug-level=", "package",
                    "publish", "register", "pydoc"])
except getopt.GetoptError:
    # print help information and exit:
    print "Invalid command found in %s" % sys.argvusage()
    sys.exit(2)
```

1.  创建一个映射到`-test`的函数：

```py
def test(test_suite, debug_level):
    logger = logging.getLogger("recipe15")
    loggingLevel = debug_level
    logger.setLevel(loggingLevel)
    ch = logging.StreamHandler()
    ch.setLevel(loggingLevel)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s -
%(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    nose.run(argv=["", test_suite, "--verbosity=2"])
```

1.  创建支持`package`、`publish`和`register`的存根函数：

```py
def package():
    print "This is where we can plug in code to run " +
    "setup.py to generate a bundle."
def publish():
    print "This is where we can plug in code to upload " +
          "our tarball to S3 or some other download site."
def register():
    print "setup.py has a built in function to " +
          "'register' a release to PyPI. It's " +
          "convenient to put a hook in here."
    # os.system("%s setup.py register" % sys.executable)
```

1.  创建一个函数，使用 Python 的`pydoc`模块自动生成文档：

```py
def create_pydocs():
    print "It's useful to use pydoc to generate docs."
    pydoc_dir = "pydoc"
    module = "recipe15_all"
    __import__(module)
    if not os.path.exists(pydoc_dir):
        os.mkdir(pydoc_dir)
    cur = os.getcwd()
    os.chdir(pydoc_dir)
    pydoc.writedoc("recipe15_all")
    os.chdir(cur)
```

1.  添加一些代码，定义调试级别，然后解析选项以允许用户进行覆盖：

```py
debug_levels = {"info":logging.INFO, "debug":logging.DEBUG}
# Default debug level is INFO
debug_level = debug_levels["info"]
for option in optlist:
    if option[0] in ("--debug-level"):
        # Override with a user-supplied debug level
        debug_level = debug_levels[option[1]]
```

1.  添加一些代码，扫描命令行选项以查找`-help`，如果找到，则退出脚本：

```py
# Check for help requests, which cause all other
# options to be ignored.
for option in optlist:
if option[0] in ("--help", "-h"):
   usage()
   sys.exit(1)
```

1.  通过迭代每个命令行选项并根据选择了哪些选项来调用其他函数来完成它：

```py
# Parse the arguments, in order
for option in optlist:
    if option[0] in ("--test"):
       print "Running recipe15_checkin tests..."
       test("recipe15_checkin", debug_level)
    if option[0] in ("--suite"):
       print "Running test suite %s..." % option[1]
       test(option[1], debug_level)
    if option[0] in ("--package"):
       package()
    if option[0] in ("--publish"):
       publish()
    if option[0] in ("--register"):
       register()
    if option[0] in ("--pydoc"):
       create_pydocs()
```

1.  使用`-help`运行`recipe15.py`脚本：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00032.jpeg)

1.  创建一个名为`recipe15_checkin.py`的新文件来创建一个新的测试套件。

1.  重用*获取**nosy**with**testing*食谱中的测试用例来定义一个`check``in`测试套件：

```py
import recipe11 

class Recipe11Test(recipe11.ShoppingCartTest): 
    pass 
```

1.  使用`-test -package -publish -register -pydoc`运行`recipe15.py`脚本。在下面的屏幕截图中，您是否注意到它如何按照在命令行上提供的相同顺序来执行每个选项？

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00033.jpeg)

1.  检查在`pydoc`目录中生成的报告：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00034.jpeg)

1.  创建一个名为`recipe15_all.py`的新文件来定义另一个新的测试套件。

1.  重用本章早期食谱的测试代码来定义一个`all`测试套件：

```py
import recipe11
import recipe12
import recipe13
import recipe14
class Recipe11Test(recipe11.ShoppingCartTest):
    pass
class Recipe12Test(recipe12.ShoppingCartTest):
    pass
class Recipe13Test(recipe13.ShoppingCartTest):
    pass
class Recipe14Test(recipe14.ShoppingCartTest):
    pass
```

1.  使用`-suite=recipe15_all`运行`recipe15.py`脚本：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00035.jpeg)

# 它是如何工作的...

该脚本使用 Python 的`getopt`库，该库是模仿 C 编程语言的`getopt()`函数而建立的。这意味着我们使用 API 来定义一组命令，然后迭代选项，调用相应的函数：

访问[`docs.python.org/library/getopt.html`](http://docs.python.org/library/getopt.html)了解更多关于`getopt`库的详细信息。

+   `usage`：这是一个为用户提供帮助的函数。

+   `键`：选项定义包含在以下块中：

```py
optlist, args = getopt.getopt(sys.argv[1:],
                "ht",
                ["help", "test", "suite=",
                "debug-level=", "package",
                "publish", "register", "pydoc"])
```

我们解析除第一个参数之外的所有参数，因为这是可执行文件本身：

+   `"ht"`定义了短选项：`-h`和`-t`。

+   该列表定义了长选项。带有`"="`的选项接受参数。没有`"="`的选项是标志。

+   如果收到不在列表中的选项，就会抛出异常；我们打印出`usage()`，然后退出。

+   `测试`：这激活了记录器，如果我们的应用程序使用 Python 的`logging`库，这将非常有用。

+   `包`：这生成 tarballs。我们创建了一个存根，但通过运行`setup.py sdist|bdist`提供一个快捷方式会很方便。

+   `发布`：它的功能是将 tarballs 推送到部署站点。我们创建了一个存根，但将其部署到 S3 站点或其他地方是有用的。

+   `注册`：这是与 PyPI 注册。我们创建了一个存根，但提供一个快捷方式运行`setup.py register`会很方便。

+   `create_pydocs`：这些是自动生成的文档。基于代码生成 HTML 文件非常方便。

定义了这些功能后，我们可以迭代解析的选项。对于这个脚本，有一个如下的顺序：

1.  检查是否有调试覆盖。我们默认为`logging.INFO`，但提供切换到`logging.DEBUG`的能力。

1.  检查是否调用了`-h`或`-help`。如果是，打印出`usage()`信息，然后退出，不再解析。

1.  最后，迭代选项并调用它们对应的函数。

为了练习，我们首先使用`-help`选项调用了这个脚本。这打印出了我们的命令选择。

然后我们使用所有选项调用它来演示功能。当我们使用`-test`时，脚本被编码为执行`check in`套件。这个简短的测试套件模拟了运行一个更快的测试，旨在查看事情是否正常。

最后，我们使用`-suite=recipe15_all`调用了脚本。这个测试套件模拟了运行一个更完整的测试套件，通常需要更长时间。

# 还有更多...

该脚本提供的功能可以很容易地通过已经构建的命令来处理。我们在本章前面看过`nosetests`，并且知道它可以灵活地接受参数来选择测试。

使用`setup.py`生成 tarballs 并注册发布也是 Python 社区中常用的功能。

那么，为什么要写这个脚本呢？因为我们可以通过一个单一的命令脚本利用所有这些功能，`setup.py`包含了一组预先构建的命令，涉及打包和上传到 Python 项目索引。执行其他任务，比如生成**pydocs**，部署到像 Amazon S3 桶这样的位置，或者任何其他系统级任务，都不包括在内。这个脚本演示了如何轻松地引入其他命令行选项，并将它们与项目管理功能链接起来。

我们还可以方便地嵌入`pydoc`的使用。基本上，任何满足项目管理需求的 Python 库也可以被嵌入。

在一个现有的项目中，我开发了一个脚本，以统一的方式将版本信息嵌入到一个模板化的`setup.py`以及由`pydoc`、`sphinx`和`DocBook`生成的文档中。这个脚本让我不必记住管理项目所需的所有命令。

为什么我不扩展`distutils`来创建自己的命令？这是一个品味的问题。我更喜欢使用`getopt`，并在`distutils`框架之外工作，而不是创建和注册新的子命令。

# 为什么使用`getopt`而不是`optparse`？

Python 有几种处理命令行选项解析的选项。`getopt`可能是最简单的。它旨在快速定义短选项和长选项，但它有限制。它需要自定义编码帮助输出，就像我们在使用函数中所做的那样。

它还需要对参数进行自定义处理。`optparse`提供了更复杂的选项，比如更好地处理参数和自动构建帮助。但它也需要更多的代码来实现功能。`optparse`也计划在未来被`argparse`取代。

你可以尝试用`optparse`写一个这个脚本的替代版本，来评估哪一个是更好的解决方案。
