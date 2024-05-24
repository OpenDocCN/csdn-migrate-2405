# Python 学徒（五）

> 原文：[`zh.annas-archive.org/md5/4702C628AD6B03CA92F1B4B8E471BB27`](https://zh.annas-archive.org/md5/4702C628AD6B03CA92F1B4B8E471BB27)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 后记：只是个开始。

正如我们在开头所说，Python 是一门庞大的语言。我们的目标是通过本书让您朝着正确的方向开始，为您提供不仅能有效地编写 Python 程序，而且能够引导自己的语言成长所需的基础。希望我们做到了！

我们鼓励您尽可能多地运用在这里学到的知识。实践这些技能确实是掌握它们的唯一途径，我们相信，随着您运用这门语言，您对 Python 的欣赏会不断加深。也许您可以立即在工作或学校中使用 Python，但如果不行，还有无数的开源项目希望得到您的帮助。或者您可以开始自己的项目！有很多方式可以获得 Python 的经验，真正的问题可能是找到最适合您的那一种。

当然，Python 还有很多内容没有在本书中涉及。我们的书籍《Python 初学者》和《Python 大师》涵盖了许多这里没有涉及的更高级的主题，所以当您准备学习更多时，可以看一看它们。或者，如果您有兴趣以其他形式学习 Python，请务必查看 PluralSight 上的 Python 课程，《Python 基础》、《Python：进阶》和《高级 Python》。我们还提供公司 Sixty North 的内部 Python 培训和咨询，如果您有更多实质性的需求。

无论您的 Python 之旅如何，我们真诚地希望您喜欢这本书。Python 是一门很棒的语言，拥有一个伟大的社区，我们希望您能像我们一样从中获得快乐。编程愉快！


## 附录 A：虚拟环境

*虚拟环境*是一个轻量级的、独立的 Python 安装。虚拟环境的主要动机是允许不同的项目控制安装的 Python 包的版本，而不会干扰同一主机上安装的其他 Python 项目。虚拟环境包括一个目录，其中包含对现有 Python 安装的符号链接（Unix），或者是一个副本（Windows），以及一个空的`site-packages`目录，用于安装特定于该虚拟环境的 Python 包。虚拟环境的第二个动机是，用户可以在不需要系统管理员权限的情况下创建虚拟环境，这样他们可以轻松地在本地安装软件包。第三个动机是，不同的虚拟环境可以基于不同版本的 Python，这样可以更容易地在同一台计算机上测试代码，比如在 Python 3.4 和 Python 3.5 上。

如果你使用的是 Python 3.3 或更高版本，那么你的系统上应该已经安装了一个叫做`venv`的模块。你可以通过在命令行上运行它来验证：

```py
$ python3 -m venv
usage: venv [-h] [--system-site-packages] [--symlinks | --copies] [--clear]
            [--upgrade] [--without-pip]
            ENV_DIR [ENV_DIR ...]
venv: error: the following arguments are required: ENV_DIR

```

如果你没有安装`venv`，还有另一个工具叫做`virtualenv`，它的工作方式非常类似。你可以从[Python Package Index (PyPI)](https://pypi.python.org/pypi/virtualenv)获取它。我们将在附录 C 中解释如何从 PyPI 安装软件包。你可以使用`venv`或`virtualenv`，不过我们将在这里使用`venv`，因为它已经内置在最新版本的 Python 中。

### 创建虚拟环境

使用`venv`非常简单：你指定一个目录的路径，该目录将包含新的虚拟环境。该工具会创建新目录并填充它的安装内容：

```py
$ python3 -m venv my_python_3_5_project_env

```

### 激活虚拟环境

创建环境后，你可以通过在环境的`bin`目录中使用`activate`脚本来*激活*它。在 Linux 或 macOS 上，你需要`source`该脚本：

```py
$ source my_python_3_5_project_env/bin/activate

```

在 Windows 上运行它：

```py
> my_python_3_5_project_env\bin\activate

```

一旦你这样做，你的提示符将会改变，提醒你当前处于虚拟环境中：

```py
(my_python_3_5_project_env) $

```

运行`python`时执行的 Python 来自虚拟环境。实际上，使用虚拟环境是获得可预测的 Python 版本的最佳方式，而不是记住要使用`python`来运行 Python 2，`python3`来运行 Python 3。

一旦进入虚拟环境，你可以像平常一样工作，放心地知道包安装与系统 Python 和其他虚拟环境是隔离的。

### 退出虚拟环境

要离开虚拟环境，请使用`deactivate`命令，这将使你返回到激活虚拟环境的父 shell：

```py
(my_python_3_5_project_env) $ deactivate
$

```

### 其他用于虚拟环境的工具

如果你经常使用虚拟环境——我们建议你几乎总是在其中工作——管理大量的环境本身可能会变得有些繁琐。集成开发环境，比如*JetBrains’ PyCharm*，提供了出色的支持来创建和使用虚拟环境。在命令行上，我们推荐一个叫做[virtualenv wrapper](https://virtualenvwrapper.readthedocs.io/en/latest/)的工具，它可以使在依赖不同虚拟环境的项目之间切换几乎变得轻而易举，一旦你做了一些初始配置。


## 附录 B：打包和分发

打包和分发你的 Python 代码可能是一个复杂的，有时令人困惑的任务，特别是如果你的项目有很多依赖项或涉及比纯 Python 代码更奇特的组件。然而，对于许多情况来说，以标准方式使你的代码对他人可访问是非常直接的，我们将在本节中看到如何使用标准的`distutils`模块来做到这一点。`distutils`的主要优势是它包含在 Python 标准库中。对于远非最简单的打包要求，你可能会想要使用`setuptools`，它具有超出`distutils`的功能，但相应地更加令人困惑。

`distutils`模块允许你编写一个简单的 Python 脚本，它知道如何将你的 Python 模块安装到任何 Python 安装中，包括托管在虚拟环境中的安装。按照惯例，这个脚本被称为`setup.py`，并且存在于项目结构的顶层。然后可以执行此脚本来执行实际安装。

### 使用`distutils`配置包

让我们看一个`distutils`的简单例子。我们将为我们在第十一章中编写的`palindrome`模块创建一个基本的`setup.py`安装脚本。

我们想要做的第一件事是创建一个目录来保存我们的项目。让我们称之为`palindrome`：

```py
$ mkdir palindrome
$ cd palindrome

```

让我们把我们的`palindrome.py`复制到这个目录中：

```py
"""palindrome.py - Detect palindromic integers"""

import unittest

def digits(x):
    """Convert an integer into a list of digits.

 Args:
 x: The number whose digits we want.

 Returns: A list of the digits, in order, of ``x``.

 >>> digits(4586378)
 [4, 5, 8, 6, 3, 7, 8]
 """

    digs = []
    while x != 0:
        div, mod = divmod(x, 10)
        digs.append(mod)
        x = div
    digs.reverse()
    return digs

def is_palindrome(x):
    """Determine if an integer is a palindrome.

 Args:
 x: The number to check for palindromicity.

 Returns: True if the digits of ``x`` are a palindrome,
 False otherwise.

 >>> is_palindrome(1234)
 False
 >>> is_palindrome(2468642)
 True
 """
    digs = digits(x)
    for f, r in zip(digs, reversed(digs)):
        if f != r:
            return False
    return True

class Tests(unittest.TestCase):
    "Tests for the ``is_palindrome()`` function."
    def test_negative(self):
        "Check that it returns False correctly."
        self.assertFalse(is_palindrome(1234))

    def test_positive(self):
        "Check that it returns True correctly."
        self.assertTrue(is_palindrome(1234321))

    def test_single_digit(self):
        "Check that it works for single digit numbers."
        for i in range(10):
            self.assertTrue(is_palindrome(i))

if __name__ == '__main__':
    unittest.main()

```

最后让我们创建`setup.py`脚本：

```py
from distutils.core import setup

setup(
    name = 'palindrome',
    version = '1.0',
    py_modules  = ['palindrome'],

    # metadata
    author = 'Austin Bingham',
    author_email = 'austin@sixty-north.com',
    description = 'A module for finding palindromic integers.',
    license = 'Public domain',
    keywords = 'palindrome',
    )

```

文件中的第一行从`distutils.core`模块导入我们需要的功能，即`setup()`函数。这个函数完成了安装我们代码的所有工作，所以我们需要告诉它我们正在安装的代码。当然，我们通过传递给函数的参数来做到这一点。

我们告诉`setup()`的第一件事是这个项目的名称。在这种情况下，我们选择了`palindrome`，但你可以选择任何你喜欢的名称。不过，一般来说，最简单的方法是将名称与项目名称保持一致。

我们传递给`setup()`的下一个参数是版本。同样，这可以是任何你想要的字符串。Python 不依赖于版本遵循任何规则。

下一个参数`py_modules`可能是最有趣的。我们使用它来指定我们想要安装的 Python 模块。列表中的每个条目都是模块的名称，不包括`.py`扩展名。`setup()`将查找匹配的`.py`文件并安装它。所以，在我们的例子中，我们要求`setup()`安装`palindrome.py`，当然，这是我们项目中的一个文件。

我们在这里使用的其余参数都相当不言自明，主要是为了帮助人们正确使用你的模块，并知道如果他们遇到问题应该联系谁。

在我们开始使用我们的`setup.py`之前，我们首先需要创建一个虚拟环境，我们将在其中安装我们的模块。在你的`palindrome`目录中，创建一个名为`palindrome_env`的虚拟环境：

```py
$ python3 -m venv palindrome_env

```

当这完成后，激活新的环境。在 Linux 或 macOS 上，执行激活脚本：

```py
$ source palindrome_env/bin/activate

```

或者在 Windows 上直接调用脚本：

```py
> palindrome_env\bin\activate

```

### 使用`distutils`安装

现在我们有了`setup.py`，我们可以用它来做一些有趣的事情。我们可以做的第一件事，也许是最明显的，就是将我们的模块安装到我们的虚拟环境中！我们通过向`setup.py`传递`install`参数来实现这一点：

```py
(palindrome_env)$ python setup.py install
running install
running build
running build_py
copying palindrome.py -> build/lib
running install_lib
copying build/lib/palindrome.py -> /Users/sixty_north/examples/palindrome/palindrome_\
env/lib/python3.5/site-packages
byte-compiling /Users/sixty_north/examples/palindrome/palindrome_env/lib/python3.5/si\
te-packages/palindrome.py to palindrome.cpython-35.pyc
running install_egg_info
Writing /Users/sixty_north/examples/palindrome/palindrome_env/lib/python3.5/site-pack\
ages/palindrome-1.0-py3.5.egg-info

```

当调用`setup()`时，它会打印出几行来告诉你它的进度。对我们来说最重要的一行是它实际将`palindrome.py`复制到安装文件夹的地方：

```py
copying build/lib/palindrome.py -> /Users/sixty_north/examples/palindrome/palindrome_\
env/lib/python3.5/site-packages

```

Python 安装的`site-packages`目录是第三方包通常安装的地方，就像我们的包看起来安装成功了一样。

让我们通过运行 Python 来验证这一点，并看到我们的模块可以被导入。请注意，在我们这样做之前，我们要改变目录，否则当我们导入`palindrome`时，Python 会加载我们当前目录中的源文件：

```py
(palindrome_env)$ cd ..
(palindrome_env)$ python
Python 3.5.2 (v3.5.2:4def2a2901a5, Jun 26 2016, 10:47:25)
[GCC 4.2.1 (Apple Inc. build 5666) (dot 3)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> import palindrome
>>> palindrome.__file__
'/Users/sixty_north/examples/palindrome/palindrome_env/lib/python3.5/site-packages/pa\
lindrome.py'

```

在这里，我们使用模块的`__file__`属性来查看它是从哪里导入的，我们看到我们是从我们的虚拟环境的`site-packages`中导入的，这正是我们想要的。

退出 Python REPL 后，不要忘记切换回你的源目录：

```py
(palindrome_env)$ cd palindrome

```

### 使用`distutils`进行打包

`setup()`的另一个有用的特性是它可以创建各种类型的“分发”格式。它将把你指定的所有模块打包成易于分发给他人的包。你可以使用`sdist`命令来实现这一点（这是“源分发”的缩写）：

```py
(palindrome_env)$ python setup.py sdist --format zip
running sdist
running check
warning: check: missing required meta-data: url

warning: sdist: manifest template 'MANIFEST.in' does not exist (using default file li\
st)

warning: sdist: standard file not found: should have one of README, README.txt

writing manifest file 'MANIFEST'
creating palindrome-1.0
making hard links in palindrome-1.0...
hard linking palindrome.py -> palindrome-1.0
hard linking setup.py -> palindrome-1.0
creating dist
creating 'dist/palindrome-1.0.zip' and adding 'palindrome-1.0' to it
adding 'palindrome-1.0/palindrome.py'
adding 'palindrome-1.0/PKG-INFO'
adding 'palindrome-1.0/setup.py'
removing 'palindrome-1.0' (and everything under it)

```

如果我们查看，我们会发现这个命令创建了一个新的目录`dist`，其中包含了新生成的分发文件：

```py
(palindrome_env) $ ls dist
palindrome-1.0.zip

```

如果我们解压缩该文件，我们会看到它包含了我们项目的源代码，包括`setup.py`：

```py
(palindrome_env)$ cd dist
(palindrome_env)$ unzip palindrome-1.0.zip
Archive:  palindrome-1.0.zip
  inflating: palindrome-1.0/palindrome.py
  inflating: palindrome-1.0/PKG-INFO
  inflating: palindrome-1.0/setup.py

```

现在你可以把这个 zip 文件发送给任何想要使用你的代码的人，他们可以使用`setup.py`将其安装到他们的系统中。非常方便！

请注意，`sdist`命令可以生成各种类型的分发。要查看可用的选项，可以使用`--help-formats`选项：

```py
(palindrome_env) $ python setup.py sdist --help-formats
List of available source distribution formats:
  --formats=bztar  bzip2'ed tar-file
  --formats=gztar  gzip'ed tar-file
  --formats=tar    uncompressed tar file
  --formats=zip    ZIP file
  --formats=ztar   compressed tar file

```

这一部分只是简单地介绍了`distutils`的基础知识。你可以通过向`setup.py`传递`--help`来了解更多关于如何使用`distutils`的信息：

```py
(palindrome_env) $ python setup.py --help
Common commands: (see '--help-commands' for more)

  setup.py build      will build the package underneath 'build/'
  setup.py install    will install the package

Global options:
  --verbose (-v)      run verbosely (default)
  --quiet (-q)        run quietly (turns verbosity off)
  --dry-run (-n)      don't actually do anything
  --help (-h)         show detailed help message
  --command-packages  list of packages that provide distutils commands

Information display options (just display information, ignore any commands)
  --help-commands     list all available commands
  --name              print package name
  --version (-V)      print package version
  --fullname          print <package name>-<version>
  --author            print the author's name
  --author-email      print the author's email address
  --maintainer        print the maintainer's name
  --maintainer-email  print the maintainer's email address
  --contact           print the maintainer's name if known, else the author's
  --contact-email     print the maintainer's email address if known, else the
                      author's
  --url               print the URL for this package
  --license           print the license of the package
  --licence           alias for --license
  --description       print the package description
  --long-description  print the long package description
  --platforms         print the list of platforms
  --classifiers       print the list of classifiers
  --keywords          print the list of keywords
  --provides          print the list of packages/modules provided
  --requires          print the list of packages/modules required
  --obsoletes         print the list of packages/modules made obsolete

usage: setup.py [global_opts] cmd1 [cmd1_opts] [cmd2 [cmd2_opts] ...]
   or: setup.py --help [cmd1 cmd2 ...]
   or: setup.py --help-commands
   or: setup.py cmd --help

```

对于许多简单的项目，你会发现我们刚刚介绍的几乎就是你需要了解的全部内容。


## 附录 C：安装第三方软件包

Python 的打包历史曾经饱受困扰和混乱。幸运的是，情况已经稳定下来，一个名为`pip`的工具已经成为通用 Python 使用中包安装工具的明确领先者。对于依赖*Numpy*或*Scipy*软件包的数值或科学计算等更专业的用途，您应该考虑*Anaconda*作为`pip`的一个强大替代品。

### 介绍`pip`

在本附录中，我们将专注于`pip`，因为它是由核心 Python 开发人员正式认可的，并且具有开箱即用的支持。`pip`工具已包含在 Python 3.4 及以上版本中。对于较旧版本的 Python 3，您需要查找有关如何为您的平台安装`pip`的具体说明，因为您可能需要使用操作系统的软件包管理器，这取决于您最初安装 Python 的方式。开始的最佳地方是[Python 包装用户指南](https://packaging.python.org/tutorials/installing-packages/#install-pip-setuptools-and-wheel)。

`venv`模块还将确保`pip`安装到新创建的环境中。

`pip`工具是独立于标准库的其余部分开发的，因此通常有比随附 Python 分发的版本更近的版本可用。您可以使用`pip`来升级自身：

```py
$ pip install --upgrade pip

```

这是有用的，可以避免`pip`重复警告您不是最新版本。但请记住，这只会在当前 Python 环境中生效，这可能是一个虚拟环境。

### Python 包索引

`pip`工具可以在中央存储库（*Python 包索引*或*PyPI*，也被昵称为“奶酪店”）中搜索软件包，然后下载和安装它们以及它们的依赖项。您可以在[`pypi.python.org/pypi`](https://pypi.python.org/pypi)上浏览 PyPI。这是一种非常方便的安装 Python 软件的方式，因此了解如何使用它是很好的。

#### 使用`pip`安装

我们将演示如何使用`pip`来安装`nose`测试工具。`nose`是一种用于运行基于`unittest`的测试的强大工具，例如我们在第十章中开发的测试。它可以做的一个非常有用的事情是*发现*所有的测试并运行它们。这意味着您不需要将`unittest.main()`添加到您的代码中；您可以使用 nose 来查找和运行您的测试。

不过，首先我们需要做一些准备工作。让我们创建一个虚拟环境（参见附录 B），这样我们就不会意外地安装到系统 Python 安装中。使用`pyenv`创建一个虚拟环境，并激活它：

```py
$ python3 -m venv test_env
$ source activate test_env/bin/activate
(test_env) $

```

由于`pip`的更新频率远远超过 Python 本身，因此在任何新的虚拟环境中升级`pip`是一个良好的做法，所以让我们这样做。幸运的是，`pip`能够更新自身：

```py
(test_env) $ pip install --upgrade pip
Collecting pip
  Using cached pip-8.1.2-py2.py3-none-any.whl
Installing collected packages: pip
  Found existing installation: pip 8.1.1
    Uninstalling pip-8.1.1:
      Successfully uninstalled pip-8.1.1
Successfully installed pip-8.1.2

```

如果您不升级`pip`，每次使用它时都会收到警告，如果自上次升级以来已有新版本可用。

现在让我们使用`pip`来安装`nose`。`pip`使用子命令来决定要执行的操作，并且要安装模块，您可以使用`pip install package-name`：

```py
(test_env) $ pip install nose
Collecting nose
  Downloading nose-1.3.7-py3-none-any.whl (154kB)
    100% |████████████████████████████████| 163kB 2.1MB/s
Installing collected packages: nose
Successfully installed nose-1.3.7

```

如果成功，`nose`已准备好在我们的虚拟环境中使用。让我们通过尝试在 REPL 中导入它并检查安装路径来确认它是否可用：

```py
(test_env) $ python
Python 3.5.2 (v3.5.2:4def2a2901a5, Jun 26 2016, 10:47:25)
[GCC 4.2.1 (Apple Inc. build 5666) (dot 3)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> import nose
>>> nose.__file__
'/Users/sixty_north/.virtualenvs/test_env/lib/python3.5/site-packages/nose/__init__.p\
y'

```

除了安装模块外，`nose`还会在虚拟环境的`bin`目录中安装`nosetests`程序。为了真正锦上添花，让我们使用`nosetests`来运行第十一章中的`palindrome.py`中的测试：

```py
(test_env) $ cd palindrome
(test_env) $ nosetests palindrome.py
...
----------------------------------------------------------------------
Ran 3 tests in 0.001s

OK

```

### 使用`pip`安装本地软件包

您还可以使用`pip`从文件中安装本地软件包，而不是从 Python 包索引中安装。要做到这一点，请将打包分发的文件名传递给`pip install`。例如，在附录 B 中，我们展示了如何使用`distutils`构建所谓的源分发。要使用`pip`安装这个，做：

```py
(test_env) $ palindrome/dist
(test_env) $ pip install palindrome-1.0.zip

```

### 卸载软件包

使用`pip`安装软件包而不是直接调用源分发的`setup.py`的一个关键优势是，`pip`知道如何卸载软件包。要这样做，使用`uninstall`子命令：

```py
(test_env) $ pip uninstall palindrome-1.0.zip
Uninstalling palindrome-1.0:
Proceed (y/n)? y
  Successfully uninstalled palindrome-1.0

```


## 注释


1 尽管越来越多的项目开始“主要是 Python 3”甚至“仅限 Python 3”。↩

2 我们不在本书中涵盖*正则表达式*，也称为*regexes*。有关更多信息，请参阅 Python 标准库`re`模块的文档。[`docs.python.org/3/library/re.html`](https://docs.python.org/3/library/re.html)↩

3 从技术上讲，模块不一定是简单的源代码文件，但对于本书的目的，这是一个足够的定义。↩

4 从技术上讲，一些编译语言确实提供了在运行时动态定义函数的机制。然而，在几乎所有情况下，这些方法都是例外而不是规则。↩

5Python 代码实际上是编译成字节码的，因此从这个意义上说，Python 有一个编译器。但是编译器所做的工作与您从流行的编译、静态类型语言中所熟悉的工作大不相同。↩

6 您会注意到，这里我们用名称`x`来引用*对象引用*，并将其表示为`x`。这有点懒散，因为当然，`x`通常意味着*由名称`x`的对象引用引用的对象*。但这有点啰嗦和过于迂腐。一般来说，引用名称的使用上下文足以告诉您我们是指对象还是引用。↩

7 垃圾回收是一个我们在本书中不会涵盖的高级主题。简而言之，这是 Python 用来释放和回收它确定不再使用的资源（即对象）的系统。↩

8 由于将列表引用分配给另一个名称不会复制列表，您可能想知道如果需要的话*如何*进行复制。这需要其他技术，我们稍后在更详细地讨论列表时会看到。↩

9 然而，请注意，Python 不强制执行此行为。完全有可能创建一个对象，该对象报告它与自身不是值相同。我们将在后面的章节中看看如何做到这一点 - 如果您因某种原因感到有冲动的话。↩

10 虽然没有普遍接受的术语，但您经常会看到术语*参数*或*形式参数*用来表示在函数定义中声明的名称。同样，术语*参数*经常用来表示传递给函数的实际对象（因此，绑定到参数）。我们将根据需要在本书中使用这些术语。↩

11 这种行为是语法实现的一部分，而不是类型系统的一部分。↩

12 在 Python 2 时代，`range()`是一个返回列表的函数。Python 3 版本的`range`更加高效、有用和强大。↩

13 当然，这让人想起了一个经典笑话：编程中最困难的两个问题是命名、缓存一致性和一次性错误。↩

14 可以说，一个包含相同名称函数的模块设计不好，因为会出现这个问题。↩

15 我们稍后在本章中详细介绍可迭代协议。↩

16 嗯，它们可以，但请记住，遍历字典只会产生键！↩

17 我们经常只使用术语*生成器*来指代生成器函数，尽管有时可能需要区分生成器*函数*和生成器*表达式*，我们稍后会涵盖这一点。↩

18 作者们发誓永远不会在演示或练习中使用斐波那契或快速排序的实现。

19 这与您应该观看 Star Wars 剧集的顺序无关。如果您正在寻找这方面的建议，我们可以建议[Machete Order](http://www.nomachetejuggling.com/2011/11/11/the-star-wars-saga-suggested-viewing-order/)。

20 实际上，可以在运行时更改对象的类，尽管这是一个高级话题，而且这种技术很少被使用。

21 在 Python 中，考虑对象的*销毁*通常是没有帮助的。最好考虑对象变得不可访问。

22 函数的*形式*参数是函数*定义*中列出的参数。

23 函数的*实际*参数是函数*调用*中列出的参数。

24 或者任何语言。 

25 您可以在[PEP 343](https://www.python.org/dev/peps/pep-0343/)中找到关于 with 语句的语法等价的完整细节。

26 您可以在[这里](https://en.wikipedia.org/wiki/BMP_file_format)了解有关 BMP 格式的所有细节。

27 比如，*sequence*协议是用于类似元组的对象。

28**E**asier to **A**sk **F**orgiveness Than **P**ermission

29 测试驱动开发，或 TDD，是一种软件开发形式，其中测试是首先编写的，即在编写要测试的实际功能之前。这乍看起来可能有些反常，但它实际上是一种非常强大的技术。您可以在[这里](https://en.wikipedia.org/wiki/Test-driven_development)了解更多关于 TDD 的信息。

30 请注意，我们实际上并没有尝试测试任何功能。这只是我们测试套件的初始框架，让我们验证测试方法是否执行。

31TDD 的原则是，您的测试应该在通过之前失败，并且您只能编写足够的实现代码来使测试通过。通过这种方式，您的测试就是对代码应该如何行为的完整描述。

32 您可能已经注意到，`setUp()`和`tearDown()`方法的名称与 PEP 8 规定的不一致。这是因为`unittest`模块早于 PEP 8 规定的函数名称应为小写并带下划线的部分。Python 标准库中有几种这样的情况，但大多数新的 Python 代码都遵循 PEP 8 风格。

33 如果我们在这里严格解释 TDD，这种实现量就太多了。为了使现有的测试通过，我们不需要实际实现行计数；我们只需要返回值 4。随后的测试将不断强迫我们“更新”我们的实现，因为它们描述了更完整的分析算法版本。我们认为您会同意，在这里以及实际开发中，这种教条主义的方法都是不合适的。

34 请注意，我们可以使用`print`，无论是否带括号。不要惊慌——我们没有退回到 Python 2。在这种情况下，`print`是 PDB 的*命令*，而不是 Python 3 的*函数*。
