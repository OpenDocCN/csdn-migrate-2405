# 现代 Python 标准库秘籍（二）

> 原文：[`zh.annas-archive.org/md5/3fab99a8deba9438823e5414cd05b6e8`](https://zh.annas-archive.org/md5/3fab99a8deba9438823e5414cd05b6e8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：文件系统和目录

在本章中，我们将涵盖以下食谱：

+   遍历文件夹-递归遍历文件系统中的路径并检查其内容

+   处理路径-以系统独立的方式构建路径

+   扩展文件名-查找与特定模式匹配的所有文件

+   获取文件信息-检测文件或目录的属性

+   命名临时文件-使用需要从其他进程访问的临时文件

+   内存和磁盘缓冲区-如果临时缓冲区大于阈值，则将其暂存到磁盘上

+   管理文件名编码-处理文件名的编码

+   复制目录-复制整个目录的内容

+   安全地替换文件内容-在发生故障时如何安全地替换文件的内容

# 介绍

使用文件和目录是大多数软件自然而然的，也是我们作为用户每天都在做的事情，但作为开发人员，您很快会发现它可能比预期的要复杂得多，特别是当需要支持多个平台或涉及编码时。

Python 标准库有许多强大的工具可用于处理文件和目录。起初，可能很难在`os`、`shutil`、`stat`和`glob`函数中找到这些工具，但一旦您了解了所有这些工具，就会清楚地知道标准库提供了一套很好的工具来处理文件和目录。

# 遍历文件夹

在文件系统中使用路径时，通常需要查找直接或子文件夹中包含的所有文件。想想复制一个目录或计算其大小；在这两种情况下，您都需要获取要复制的目录中包含的所有文件的完整列表，或者要计算大小的目录中包含的所有文件的完整列表。

# 如何做...

这个食谱的步骤如下：

1.  `os`模块中的`os.walk`函数用于递归遍历目录，其使用方法并不直接，但稍加努力，我们可以将其包装成一个方便的生成器，列出所有包含的文件：

```py
import os

def traverse(path):
    for basepath, directories, files in os.walk(path):
        for f in files:
            yield os.path.join(basepath, f)
```

1.  然后，我们可以遍历`traverse`并对其进行任何操作：

```py
for f in traverse('.'):
    print(f)
```

# 它是如何工作的...

`os.walk`函数遍历目录及其所有子文件夹。对于它找到的每个目录，它返回三个值：目录本身、它包含的子目录和它包含的文件。然后，它将进入所提供的目录的子目录，并为子目录返回相同的三个值。

这意味着在我们的食谱中，`basepath`始终是正在检查的当前目录，`directories`是其子目录，`files`是它包含的文件。

通过迭代当前目录中包含的文件列表，并将它们的名称与目录路径本身连接起来，我们可以获取目录中包含的所有文件的路径。由于`os.walk`将进入所有子目录，因此我们将能够返回直接或间接位于所需路径内的所有文件。

# 处理路径

Python 最初是作为系统管理语言创建的。最初是为 Unix 系统编写脚本，因此在语言的核心部分之一始终是浏览磁盘，但在 Python 的最新版本中，这进一步扩展到了`pathlib`模块，它使得非常方便和容易地构建引用文件或目录的路径，而无需关心我们正在运行的系统。

由于编写多平台软件可能很麻烦，因此非常重要的是有中间层来抽象底层系统的约定，并允许我们编写可以在任何地方运行的代码。

特别是在处理路径时，Unix 和 Windows 系统处理路径的方式之间的差异可能会有问题。一个系统使用`/`，另一个使用`\`来分隔路径的部分本身就很麻烦，但 Windows 还有驱动器的概念，而 Unix 系统没有，因此我们需要一些东西来抽象这些差异并轻松管理路径。

# 如何做...

执行此食谱的以下步骤：

1.  `pathlib`库允许我们根据构成它的部分构建路径，根据您所在的系统正确地执行正确的操作：

```py
>>> import pathlib
>>> 
>>> path = pathlib.Path('somefile.txt')
>>> path.write_text('Hello World')  # Write some text into file.
11
>>> print(path.resolve())  # Print absolute path
/Users/amol/wrk/pythonstlcookbook/somefile.txt
>>> path.read_text()  # Check the file content
'Hello World'
>>> path.unlink()  # Destroy the file
```

1.  有趣的是，即使在 Windows 上进行相同的操作，也会得到完全相同的结果，即使`path.resolve()`会打印出稍微不同的结果：

```py
>>> print(path.resolve())  # Print absolute path
C:\\wrk\\pythonstlcookbook\\somefile.txt
```

1.  一旦我们有了`pathlib.Path`实例，甚至可以使用`/`运算符在文件系统中移动：

```py
>>> path = pathlib.Path('.')
>>> path = path.resolve()
>>> path
PosixPath('/Users/amol/wrk/pythonstlcookbook')
>>> path = path / '..'
>>> path.resolve()
PosixPath('/Users/amol/wrk')
```

即使我是在类 Unix 系统上编写的，上述代码在 Windows 和 Linux/macOS 上都能正常工作并产生预期的结果。

# 还有更多...

`pathlib.Path`实际上会根据我们所在的系统构建不同的对象。在 POSIX 系统上，它将导致一个`pathlib.PosixPath`对象，而在 Windows 系统上，它将导致一个`pathlib.WindowsPath`对象。

在 POSIX 系统上无法构建`pathlib.WindowsPath`，因为它是基于 Windows 系统调用实现的，而这些调用在 Unix 系统上不可用。如果您需要在 POSIX 系统上使用 Windows 路径（或在 Windows 系统上使用 POSIX 路径），可以依赖于`pathlib.PureWindowsPath`和`pathlib.PurePosixPath`。

这两个对象不会实现实际访问文件的功能（读取、写入、链接、解析绝对路径等），但它们将允许您执行与操作路径本身相关的简单操作。

# 扩展文件名

在我们系统的日常使用中，我们习惯于提供路径，例如`*.py`，以识别所有的 Python 文件，因此当我们的用户提供一个或多个文件给我们的软件时，他们能够做同样的事情并不奇怪。

通常，通配符是由 shell 本身扩展的，但假设您从配置文件中读取它们，或者您想编写一个工具来清除当前项目中的`.pyc`文件（编译的 Python 字节码缓存），那么 Python 标准库中有您需要的内容。

# 如何做...

此食谱的步骤是：

1.  `pathlib`能够对您提供的路径执行许多操作。其中之一是解析通配符：

```py
>>> list(pathlib.Path('.').glob('*.py'))
[PosixPath('conf.py')]
```

1.  它还支持递归解析通配符：

```py
>>> list(pathlib.Path('.').glob('**/*.py'))
[PosixPath('conf.py'), PosixPath('venv/bin/cmark.py'), 
 PosixPath('venv/bin/rst2html.py'), ...]
```

# 获取文件信息

当用户提供路径时，您真的不知道路径指的是什么。它是一个文件吗？是一个目录吗？它甚至存在吗？

检索文件信息允许我们获取有关提供的路径的详细信息，例如它是否指向文件以及该文件的大小。

# 如何做...

执行此食谱的以下步骤：

1.  对任何`pathlib.Path`使用`.stat()`将提供有关路径的大部分详细信息：

```py
>>> pathlib.Path('conf.py').stat()
os.stat_result(st_mode=33188, 
               st_ino=116956459, 
               st_dev=16777220, 
               st_nlink=1, 
               st_uid=501, 
               st_gid=20, 
               st_size=9306, 
               st_atime=1519162544, 
               st_mtime=1510786258, 
               st_ctime=1510786258)
```

返回的详细信息是指：

+   +   `st_mode`: 文件类型、标志和权限

+   `st_ino`: 存储文件的文件系统节点

+   `st_dev`: 存储文件的设备

+   `st_nlink`: 对此文件的引用（超链接）的数量

+   `st_uid`: 拥有文件的用户

+   `st_gid`: 拥有文件的组

+   `st_size`: 文件的大小（以字节为单位）

+   `st_atime`: 文件上次访问的时间

+   `st_mtime`: 文件上次修改的时间

+   `st_ctime`: 文件在 Windows 上创建的时间，Unix 上修改元数据的时间

1.  如果我们想要查看其他详细信息，例如路径是否存在或者它是否是一个目录，我们可以依赖于这些特定的方法：

```py
>>> pathlib.Path('conf.py').exists()
True
>>> pathlib.Path('conf.py').is_dir()
False
>>> pathlib.Path('_build').is_dir()
True
```

# 命名临时文件

通常在处理临时文件时，我们不关心它们存储在哪里。我们需要创建它们，在那里存储一些内容，并在完成后摆脱它们。大多数情况下，我们在想要存储一些太大而无法放入内存的东西时使用临时文件，但有时你需要能够提供一个文件给另一个工具或软件，临时文件是避免需要知道在哪里存储这样的文件的好方法。

在这种情况下，我们需要知道通往临时文件的路径，以便我们可以将其提供给其他工具。

这就是`tempfile.NamedTemporaryFile`可以帮助的地方。与所有其他`tempfile`形式的临时文件一样，它将为我们创建，并且在我们完成工作后会自动删除，但与其他类型的临时文件不同，它将有一个已知的路径，我们可以提供给其他程序，这些程序将能够从该文件中读取和写入。

# 如何做...

`tempfile.NamedTemporaryFile`将创建临时文件：

```py
>>> from tempfile import NamedTemporaryFile
>>>
>>> with tempfile.NamedTemporaryFile() as f:
...   print(f.name)
... 
/var/folders/js/ykgc_8hj10n1fmh3pzdkw2w40000gn/T/tmponbsaf34
```

`.name`属性导致完整的文件路径在磁盘上，这使我们能够将其提供给其他外部程序：

```py
>>> with tempfile.NamedTemporaryFile() as f:
...   os.system('echo "Hello World" > %s' % f.name)
...   f.seek(0)
...   print(f.read())
... 
0
0
b'Hello World\n'
```

# 内存和磁盘缓冲

有时，我们需要将某些数据保留在缓冲区中，比如我们从互联网上下载的文件，或者我们动态生成的一些数据。

由于这种数据的大小通常是不可预测的，通常不明智将其全部保存在内存中。

如果你从互联网上下载一个 32GB 的大文件，需要处理它（如解压缩或解析），如果你在处理之前尝试将其存储到字符串中，它可能会耗尽你所有的内存。

这就是为什么通常依赖`tempfile.SpooledTemporaryFile`通常是一个好主意，它将保留内容在内存中，直到达到最大大小，然后如果它比允许的最大大小更大，就将其移动到临时文件中。

这样，我们可以享受保留数据的内存缓冲区的好处，而不会因为内容太大而耗尽所有内存，因为一旦内容太大，它将被移动到磁盘上。

# 如何做...

像其他`tempfile`对象一样，创建`SpooledTemporaryFile`就足以使临时文件可用。唯一的额外部分是提供允许的最大大小，`max_size=`，在此之后内容将被移动到磁盘上：

```py
>>> with tempfile.SpooledTemporaryFile(max_size=30) as temp:
...     for i in range(3):
...         temp.write(b'Line of text\n')
...     
...     temp.seek(0)
...     print(temp.read())
... 
b'Line of text\nLine of text\nLine of text\n'
```

# 它是如何工作的...

`tempfile.SpooledTemporaryFile`有一个`内部 _file`属性，它将真实数据存储在`BytesIO`存储中，直到它可以适应内存，然后一旦它比`max_size`更大，就将其移动到真实文件中。

在写入数据时，你可以通过打印`_file`的值来轻松看到这种行为：

```py
>>> with tempfile.SpooledTemporaryFile(max_size=30) as temp:
...     for i in range(3):
...         temp.write(b'Line of text\n')
...         print(temp._file)
... 
<_io.BytesIO object at 0x10d539ca8>
<_io.BytesIO object at 0x10d539ca8>
<_io.BufferedRandom name=4>
```

# 管理文件名编码

以可靠的方式使用文件系统并不像看起来那么容易。我们的系统必须有特定的编码来表示文本，通常这意味着我们创建的所有内容都是以该编码处理的，包括文件名。

问题在于文件名的编码没有强有力的保证。假设你连接了一个外部硬盘，那个硬盘上的文件名的编码是什么？嗯，这将取决于文件创建时系统的编码。

通常，为了解决这个问题，软件会尝试系统编码，如果失败，它会打印一些占位符（你是否曾经看到过一个充满`?`的文件名，只是因为你的系统无法理解文件的名称？），这通常允许我们看到有一个文件，并且在许多情况下甚至打开它，尽管我们可能不知道它的实际名称。

为了使一切更加复杂，Windows 和 Unix 系统在处理文件名时存在很大的差异。在 Unix 系统上，路径基本上只是字节；你不需要真正关心它们的编码，因为你只是读取和写入一堆字节。而在 Windows 上，文件名实际上是文本。

在 Python 中，文件名通常存储为`str`。它们是需要以某种方式进行编码/解码的文本。

# 如何做...

每当我们处理文件名时，我们应该根据预期的文件系统编码对其进行解码。如果失败（因为它不是以预期的编码存储的），我们仍然必须能够将其放入`str`而不使其损坏，以便我们可以打开该文件，即使我们无法读取其名称：

```py
def decode_filename(fname):
    fse = sys.getfilesystemencoding()
    return fname.decode(fse, "surrogateescape")
```

# 它是如何工作的...

`decode_filename`试图做两件事：首先，它询问 Python 根据操作系统预期的文件系统编码是什么。一旦知道了这一点，它就会尝试使用该编码解码提供的文件名。如果失败，它将使用`surrogateescape`进行解码。

这实际上意味着*如果你无法解码它，就将其解码为假字符，我们将使用它来表示文本*。

这真的很方便，因为这样我们能够将文件名作为文本进行管理，即使我们不知道它的编码，当它使用`surrogateescape`编码回字节时，它将导致回到其原始字节序列。

当文件名以与我们的系统相同的编码进行编码时，很容易看出我们如何能够将其解码为`str`并打印它以读取其内容：

```py
>>> utf8_filename_bytes = 'ùtf8.txt'.encode('utf8')
>>> utf8_filename = decode_filename(utf8_filename_bytes)
>>> type(utf8_filename)
<class 'str'>
>>> print(utf8_filename)
ùtf8.txt
```

如果编码实际上不是我们的系统编码（也就是说，文件来自一个非常古老的外部驱动器），我们实际上无法读取里面写的内容，但我们仍然能够将其解码为字符串，以便我们可以将其保存在一个变量中，并将其提供给任何可能需要处理该文件的函数：

```py
>>> latin1_filename_bytes = 'làtìn1.txt'.encode('latin1')
>>> latin1_filename = decode_filename(latin1_filename_bytes)
>>> type(latin1_filename)
<class 'str'>
>>> latin1_filename
'l\udce0t\udcecn1.txt'
```

`surrogateescape`意味着能够告诉 Python*我不在乎数据是否是垃圾，只需原样传递未知的字节*。

# 复制目录

复制目录的内容是我们可以轻松做到的事情，但是如果我告诉你，像`cp`（在 GNU 系统上复制文件的命令）这样的工具大约有 1200 行代码呢？

显然，`cp`的实现不是基于 Python 的，它已经发展了几十年，它照顾的远远超出了你可能需要的，但是自己编写递归复制目录的代码所需的工作远远超出你的预期。

幸运的是，Python 标准库提供了实用程序，可以直接执行最常见的操作之一。

# 如何做...

此处的步骤如下：

1.  `copydir`函数可以依赖于`shutil.copytree`来完成大部分工作：

```py
import shutil

def copydir(source, dest, ignore=None):
    """Copy source to dest and ignore any file matching ignore 
       pattern."""
    shutil.copytree(source, dest, ignore_dangling_symlinks=True,
                    ignore=shutil.ignore_patterns(*ignore) if 
                    ignore else None)
```

1.  然后，我们可以轻松地使用它来复制任何目录的内容，甚至将其限制为只复制相关部分。我们将复制一个包含三个文件的目录，其中我们实际上只想复制`.pdf`文件：

```py
>>> import glob
>>> print(glob.glob('_build/pdf/*'))
['_build/pdf/PySTLCookbook.pdf', '_build/pdf/PySTLCookbook.rtc', '_build/pdf/PySTLCookbook.stylelog']
```

1.  我们的目标目录目前不存在，因此它不包含任何内容：

```py
>>> print(glob.glob('/tmp/buildcopy/*'))
[]
```

1.  一旦我们执行`copydir`，它将被创建并包含我们期望的内容：

```py
>>> copydir('_build/pdf', '/tmp/buildcopy', ignore=('*.rtc', '*.stylelog'))
```

1.  现在，目标目录存在并包含我们期望的内容：

```py
>>> print(glob.glob('/tmp/buildcopy/*'))
['/tmp/buildcopy/PySTLCookbook.pdf']
```

# 它是如何工作的...

`shutil.copytree`将通过`os.listdir`检索提供的目录的内容。对于`listdir`返回的每个条目，它将检查它是文件还是目录。

如果是文件，它将通过`shutil.copy2`函数进行复制（实际上可以通过提供`copy_function`参数来替换使用的函数），如果是目录，`copytree`本身将被递归调用。

然后使用`ignore`参数构建一个函数，一旦调用，将返回所有需要忽略的文件，给定一个提供的模式：

```py
>>> f = shutil.ignore_patterns('*.rtc', '*.stylelog')
>>> f('_build', ['_build/pdf/PySTLCookbook.pdf', 
                 '_build/pdf/PySTLCookbook.rtc', 
                 '_build/pdf/PySTLCookbook.stylelog'])
{'_build/pdf/PySTLCookbook.stylelog', '_build/pdf/PySTLCookbook.rtc'}
```

因此，`shutil.copytree`将复制除`ignore_patterns`之外的所有文件，这将使其跳过。

最后的`ignore_dangling_symlinks=True`参数确保在`symlinks`损坏的情况下，我们只是跳过文件而不是崩溃。

# 安全地替换文件内容

替换文件的内容是一个非常缓慢的操作。与替换变量的内容相比，通常慢几倍；当我们将某些东西写入磁盘时，需要一些时间才能真正刷新，以及在内容实际写入磁盘之前需要一些时间。这不是一个原子操作，因此如果我们的软件在保存文件时遇到任何问题，文件可能会被写入一半，我们的用户无法恢复其数据的一致状态。

通常有一种常用模式来解决这种问题，该模式基于写入文件是一个缓慢、昂贵、易出错的操作，但重命名文件是一个原子、快速、廉价的操作。

# 如何做...

您需要执行以下操作：

1.  就像`open`可以用作上下文管理器一样，我们可以轻松地推出一个`safe_open`函数，以安全的方式打开文件进行写入：

```py
import tempfile, os

class safe_open:
    def __init__(self, path, mode='w+b'):
        self._target = path
        self._mode = mode

    def __enter__(self):
        self._file = tempfile.NamedTemporaryFile(self._mode, delete=False)
        return self._file

    def __exit__(self, exc_type, exc_value, traceback):
        self._file.close()
        if exc_type is None:
            os.rename(self._file.name, self._target)
        else:
            os.unlink(self._file.name)
```

1.  使用`safe_open`作为上下文管理器允许我们写入文件，就像我们通常会做的那样。

```py
with safe_open('/tmp/myfile') as f:
    f.write(b'Hello World')
```

1.  内容将在退出上下文时正确保存：

```py
>>> print(open('/tmp/myfile').read())
Hello World
```

1.  主要区别在于，如果我们的软件崩溃或在写入时发生系统故障，我们不会得到一个写入一半的文件，而是会保留文件的任何先前状态。在这个例子中，我们在尝试写入`替换 hello world，期望写入更多`时中途崩溃：

```py
with open('/tmp/myfile', 'wb+') as f:
    f.write(b'Replace the hello world, ')
    raise Exception('but crash meanwhile!')
    f.write(b'expect to write some more')
```

1.  使用普通的`open`，结果将只是`"替换 hello world，"`：

```py
>>> print(open('/tmp/myfile').read())
Replace the hello world,
```

1.  在使用`safe_open`时，只有在整个写入过程成功时，文件才会包含新数据：

```py
with safe_open('/tmp/myfile') as f:
    f.write(b'Replace the hello world, ')
    raise Exception('but crash meanwhile!')
    f.write(b'expect to write some more')
```

1.  在所有其他情况下，文件仍将保留其先前的状态：

```py
>>> print(open('/tmp/myfile').read())
Hello World
```

# 工作原理...

`safe_open`依赖于`tempfile`来创建一个新文件，其中实际发生写操作。每当我们在上下文中写入`f`时，实际上是在临时文件中写入。

然后，只有当上下文存在时（`safe_open.__exit__`中的`exc_type`为 none），我们才会使用`os.rename`将旧文件与我们刚刚写入的新文件进行交换。

如果一切如预期般运行，我们应该有新文件，并且所有内容都已更新。

如果任何步骤失败，我们只需向临时文件写入一些或没有数据，并通过`os.unlink`将其丢弃。

在这种情况下，我们以前的文件从未被触及，因此仍保留其先前的状态。


# 第五章：日期和时间

在本章中，我们将涵盖以下技巧：

+   时区感知的 datetime-检索当前 datetime 的可靠值

+   解析日期-如何根据 ISO 8601 格式解析日期

+   保存日期-如何存储 datetime

+   从时间戳到 datetime-转换为时间戳和从时间戳转换为 datetime

+   以用户格式显示日期-根据用户语言格式化日期

+   去明天-如何计算指向明天的 datetime

+   去下个月-如何计算指向下个月的 datetime

+   工作日-如何构建一个指向本月第*n*个星期一/星期五的日期

+   工作日-如何在时间范围内获取工作日

+   组合日期和时间-从日期和时间创建一个 datetime

# 介绍

日期是我们生活的一部分，我们习惯于处理时间和日期作为一个基本的过程。即使是一个小孩也知道现在是什么时间或者*明天*是什么意思。但是，试着和世界另一端的人交谈，突然之间*明天*、*午夜*等概念开始变得非常复杂。

当你说明天时，你是在说你的明天还是我的明天？如果你安排一个应该在午夜运行的进程，那么是哪一个午夜？

为了让一切变得更加困难，我们有闰秒，奇怪的时区，夏令时等等。当你尝试在软件中处理日期时，特别是在可能被世界各地的人使用的软件中，突然之间就会明白日期是一个复杂的事务。

本章包括一些短小的技巧，可以在处理用户提供的日期时避免头痛和错误。

# 时区感知的 datetime

Python datetimes 通常是*naive*，这意味着它们不知道它们所指的时区。这可能是一个主要问题，因为给定一个 datetime，我们无法知道它实际指的是什么时候。

在 Python 中处理日期最常见的错误是尝试通过`datetime.datetime.now()`获取当前 datetime，因为所有`datetime`方法都使用 naive 日期，所以无法知道该值代表的时间。

# 如何做到这一点...

执行以下步骤来完成这个技巧：

1.  检索当前 datetime 的唯一可靠方法是使用`datetime.datetime.utcnow()`。无论用户在哪里，系统如何配置，它都将始终返回 UTC 时间。因此，我们需要使其具有时区感知能力，以便能够将其拒绝到世界上的任何时区：

```py
import datetime

def now():
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
```

1.  一旦我们有了一个具有时区感知能力的当前时间，就可以将其转换为任何其他时区，这样我们就可以向我们的用户显示他们自己时区的值：

```py
def astimezone(d, offset):
    return d.astimezone(datetime.timezone(datetime.timedelta(hours=offset)))
```

1.  现在，假设我目前在 UTC+01:00 时区，我可以获取 UTC 的具有时区感知能力的当前时间，然后在我的时区中显示它：

```py
>>> d = now()
>>> print(d)
2018-03-19 21:35:43.251685+00:00

>>> d = astimezone(d, 1)
>>> print(d)
2018-03-19 22:35:43.251685+01:00
```

# 它是如何工作的...

所有 Python datetimes，默认情况下都没有指定任何时区，但通过设置`tzinfo`，我们可以使它们意识到它们所指的时区。

如果我们只是获取当前时间（`datetime.datetime.now()`），我们无法轻松地从软件内部知道我们正在获取时间的时区。因此，我们唯一可以依赖的时区是 UTC。每当检索当前时间时，最好始终依赖于`datetime.datetime.utcnow()`。

一旦我们有了 UTC 的日期，因为我们知道它实际上是 UTC 时区的日期，我们可以轻松地附加`datetime.timezone.utc`时区（Python 提供的唯一时区）并使其具有时区感知能力。

`now`函数可以做到这一点：它获取 datetime 并使其具有时区感知能力。

由于我们的 datetime 现在具有时区感知能力，从那一刻起，我们可以依赖于`datetime.datetime.astimezone`方法将其转换为任何我们想要的时区。因此，如果我们知道我们的用户在 UTC+01:00，我们可以显示 datetime 的用户本地值，而不是显示 UTC 值。

这正是`astimezone`函数所做的。一旦提供了日期时间和与 UTC 的偏移量，它将返回一个日期，该日期是基于该偏移量的本地时区。

# 还有更多...

您可能已经注意到，虽然这个解决方案有效，但缺乏更高级的功能。例如，我目前在 UTC+01:00，但根据我的国家的夏令时政策，我可能在 UTC+02:00。此外，我们只支持基于整数小时的偏移量，虽然这是最常见的情况，但有一些时区，如印度或伊朗，有半小时的偏移量。

虽然我们可以扩展我们对时区的支持以包括这些奇怪的情况，但对于更复杂的情况，您可能应该依赖于`pytz`软件包，该软件包为完整的 IANA 时区数据库提供了时区。

# 解析日期

从另一个软件或用户那里接收日期时间时，它可能是以字符串格式。例如 JSON 等格式甚至不定义日期应该如何表示，但通常最好的做法是以 ISO 8601 格式提供这些日期。

ISO 8601 格式通常定义为`[YYYY]-[MM]-[DD]T[hh]:[mm]:[ss]+-[TZ]`，例如`2018-03-19T22:00+0100`将指的是 UTC+01:00 时区的 3 月 19 日晚上 10 点。

ISO 8601 传达了表示日期和时间所需的所有信息，因此这是一种将日期时间编组并通过网络发送的好方法。

遗憾的是，它有许多奇怪之处（例如，`+00`时区也可以写为`Z`，或者您可以省略小时、分钟和秒之间的`:`），因此解析它有时可能会引起麻烦。

# 如何做...

以下是要遵循的步骤：

1.  由于 ISO 8601 允许所有这些变体，没有简单的方法将其传递给`datetime.datetime.strptime`，并为所有情况返回一个日期时间；我们必须将所有可能的格式合并为一个格式，然后解析该格式：

```py
import datetime

def parse_iso8601(strdate):
    date, time = strdate.split('T', 1)
    if '-' in time:
        time, tz = time.split('-')
        tz = '-' + tz
    elif '+' in time:
        time, tz = time.split('+')
        tz = '+' + tz
    elif 'Z' in time:
        time = time[:-1]
        tz = '+0000'
    date = date.replace('-', '')
    time = time.replace(':', '')
    tz = tz.replace(':', '')
    return datetime.datetime.strptime('{}T{}{}'.format(date, time, tz), 
                                      "%Y%m%dT%H%M%S%z")
```

1.  `parse_iso8601`的先前实现处理了大多数可能的 ISO 8601 表示：

```py
>>> parse_iso8601('2018-03-19T22:00Z')
datetime.datetime(2018, 3, 19, 22, 0, tzinfo=datetime.timezone.utc)
>>> parse_iso8601('2018-03-19T2200Z')
datetime.datetime(2018, 3, 19, 22, 0, tzinfo=datetime.timezone.utc)
>>> parse_iso8601('2018-03-19T22:00:03Z')
datetime.datetime(2018, 3, 19, 22, 0, 3, tzinfo=datetime.timezone.utc)
>>> parse_iso8601('20180319T22:00:03Z')
datetime.datetime(2018, 3, 19, 22, 0, 3, tzinfo=datetime.timezone.utc)
>>> parse_iso8601('20180319T22:00:03+05:00')
datetime.datetime(2018, 3, 19, 22, 0, 3, tzinfo=datetime.timezone(datetime.timedelta(0, 18000)))
>>> parse_iso8601('20180319T22:00:03+0500')
datetime.datetime(2018, 3, 19, 22, 0, 3, tzinfo=datetime.timezone(datetime.timedelta(0, 18000)))
```

# 它是如何工作的...

`parse_iso8601`的基本思想是，无论在解析之前收到 ISO 8601 的方言是什么，我们都将其转换为`[YYYY][MM][DD]T[hh][mm][ss]+-[TZ]`的形式。

最难的部分是检测时区，因为它可以由`+`、`-`分隔，甚至可以是`Z`。一旦提取了时区，我们可以摆脱日期中所有`-`的示例和时间中所有`:`的实例。

请注意，在提取时区之前，我们将时间与日期分开，因为日期和时区都可能包含`-`字符，我们不希望我们的解析器感到困惑。

# 还有更多...

解析日期可能变得非常复杂。虽然我们的`parse_iso8601`在与大多数以字符串格式提供日期的系统（如 JSON）交互时可以工作，但您很快就会面临它因日期时间可以表示的所有方式而不足的情况。

例如，我们可能会收到一个值，例如`2 周前`或`2013 年 7 月 4 日 PST`。尝试解析所有这些情况并不是很方便，而且可能很快变得复杂。如果您必须处理这些特殊情况，您可能应该依赖于外部软件包，如`dateparser`、`dateutil`或`moment`。

# 保存日期

迟早，我们都必须在某个地方保存一个日期，将其发送到数据库或将其保存到文件中。也许我们将其转换为 JSON 以将其发送到另一个软件。

许多数据库系统不跟踪时区。其中一些具有配置选项，指定它们应该使用的时区，但在大多数情况下，您提供的日期将按原样保存。

这会导致许多情况下出现意外的错误或行为。假设您是一个好童子军，并且正确地完成了接收保留其时区的日期时间所需的所有工作。现在您有一个`2018-01-15 15:30:00 UTC+01:00`的日期时间，一旦将其存储在数据库中，`UTC+01:00`将很容易丢失，即使您自己将其存储在文件中，存储和恢复时区通常是一项麻烦的工作。

因此，您应该始终确保在将日期时间存储在某个地方之前将其转换为 UTC，这将始终保证，无论日期时间来自哪个时区，当您将其加载回来时，它将始终表示正确的时间。

# 如何做到...

此食谱的步骤如下：

1.  要保存日期时间，我们希望有一个函数，确保日期时间在实际存储之前始终指的是 UTC：

```py
import datetime

def asutc(d):
    return d.astimezone(datetime.timezone.utc)
```

1.  `asutc`函数可用于任何日期时间，以确保在实际存储之前将其移至 UTC：

```py
>>> now = datetime.datetime.now().replace(
...    tzinfo=datetime.timezone(datetime.timedelta(hours=1))
... )
>>> now
datetime.datetime(2018, 3, 22, 0, 49, 45, 198483, 
                  tzinfo=datetime.timezone(datetime.timedelta(0, 3600)))
>>> asutc(now)
datetime.datetime(2018, 3, 21, 23, 49, 49, 742126, tzinfo=datetime.timezone.utc)
```

# 它是如何工作的...

此食谱的功能非常简单，通过`datetime.datetime.astimezone`方法，日期始终转换为其 UTC 表示。

这确保它将适用于存储跟踪时区的地方（因为日期仍将是时区感知的，但时区将是 UTC），以及当存储不保留时区时（因为没有时区的 UTC 日期仍然表示与零增量相同的 UTC 日期）。

# 从时间戳到日期时间

时间戳是从特定时刻开始的秒数的表示。通常，由于计算机可以表示的值在大小上是有限的，通常从 1970 年 1 月 1 日开始。

如果您收到一个值，例如`1521588268`作为日期时间表示，您可能想知道如何将其转换为实际的日期时间。

# 如何做到...

最近的 Python 版本引入了一种快速将日期时间与时间戳相互转换的方法：

```py
>>> import datetime
>>> ts = 1521588268

>>> d = datetime.datetime.utcfromtimestamp(ts)
>>> print(repr(d))
datetime.datetime(2018, 3, 20, 23, 24, 28)

>>> newts = d.timestamp()
>>> print(newts)
1521584668.0
```

# 还有更多...

正如食谱介绍中指出的，计算机可以表示的数字有一个限制。因此，重要的是要注意，虽然`datetime.datetime`可以表示几乎任何日期，但时间戳却不能。

例如，尝试表示来自`1300`的日期时间将成功，但将无法将其转换为时间戳：

```py
>>> datetime.datetime(1300, 1, 1)
datetime.datetime(1300, 1, 1, 0, 0)
>>> datetime.datetime(1300, 1, 1).timestamp()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
OverflowError: timestamp out of range
```

时间戳只能表示从 1970 年 1 月 1 日开始的日期。

对于遥远的日期，反向方向也是如此，而`253402214400`表示 9999 年 12 月 31 日的时间戳，尝试从该值之后的日期创建日期时间将失败：

```py
>>> datetime.datetime.utcfromtimestamp(253402214400)
datetime.datetime(9999, 12, 31, 0, 0)
>>> datetime.datetime.utcfromtimestamp(253402214400+(3600*24))
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ValueError: year is out of range
```

日期时间只能表示从公元 1 年到 9999 年的日期。

# 以用户格式显示日期

在软件中显示日期时，如果用户不知道您将依赖的格式，很容易使用户感到困惑。

我们已经知道时区起着重要作用，并且在显示时间时我们总是希望将其显示为时区感知，但是日期也可能存在歧义。如果您写 3/4/2018，它是 4 月 3 日还是 3 月 4 日？

因此，通常有两种选择：

+   采用国际格式（2018-04-03）

+   本地化日期（2018 年 4 月 3 日）

可能的话，最好能够本地化日期格式，这样我们的用户将看到一个他们可以轻松识别的值。

# 如何做到...

此食谱需要以下步骤：

1.  Python 标准库中的`locale`模块提供了一种获取系统支持的本地化格式的方法。通过使用它，我们可以以目标系统允许的任何方式格式化日期：

```py
import locale
import contextlib

@contextlib.contextmanager
def switchlocale(name):
    prev = locale.getlocale()
    locale.setlocale(locale.LC_ALL, name)
    yield
    locale.setlocale(locale.LC_ALL, prev)

def format_date(loc, d):
    with switchlocale(loc):
        fmt = locale.nl_langinfo(locale.D_T_FMT)
        return d.strftime(fmt)
```

1.  调用`format_date`将正确地给出预期`locale`模块中日期的字符串表示：

```py
>>> format_date('de_DE', datetime.datetime.utcnow())
'Mi 21 Mär 00:08:59 2018'
>>> format_date('en_GB', datetime.datetime.utcnow())
'Wed 21 Mar 00:09:11 2018'
```

# 它是如何工作的...

`format_date`函数分为两个主要部分。

第一个由`switchlocale`上下文管理器提供，它负责启用请求的`locale`（locale 是整个进程范围的），并在包装的代码块中返回控制，然后恢复原始`locale`。这样，我们可以仅在上下文管理器中使用请求的`locale`，而不影响软件的任何其他部分。

第二个是上下文管理器内部发生的事情。使用`locale.nl_langinfo`，请求当前启用的`locale`的日期时间格式字符串（`locale.D_T_FMT`）。这会返回一个字符串，告诉我们如何在当前活动的`locale`中格式化日期时间。返回的字符串将类似于`'%a %e %b %X %Y'`。

然后日期本身根据通过`datetime.strftime`检索到的格式字符串进行格式化。

请注意，返回的字符串通常会包含`%a`和`%b`格式化符号，它们代表*当前星期*和*当前月份*的名称。由于星期几或月份的名称对每种语言都是不同的，Python 解释器将以当前启用的`locale`发出星期几或月份的名称。

因此，我们不仅按照用户的期望格式化了日期，而且结果输出也将是用户的语言。

# 还有更多...

虽然这个解决方案看起来非常方便，但重要的是要注意它依赖于动态切换`locale`。

切换`locale`是一个非常昂贵的操作，所以如果你有很多值需要格式化（比如`for`循环或成千上万的日期），这可能会太慢。

另外，切换`locale`也不是线程安全的，所以除非所有的`locale`切换发生在其他线程启动之前，否则你将无法在多线程软件中应用这个食谱。

如果你想以一种健壮且线程安全的方式处理本地化，你可能想要检查 babel 包。Babel 支持日期和数字的本地化，并且以一种不需要设置全局状态的方式工作，因此即使在多线程环境中也能正确运行。

# 前往明天

当你有一个日期时，通常需要对该日期进行数学运算。例如，也许你想要移动到明天或昨天。

日期时间支持数学运算，比如对它们进行加减，但涉及时间时，很难得到你需要添加或减去的确切秒数，以便移动到下一天或前一天。

因此，这个食谱将展示一种从任意给定日期轻松移动到下一个或上一个日期的方法。

# 如何做...

对于这个食谱，以下是步骤：

1.  `shiftdate`函数将允许我们按任意天数移动到一个日期：

```py
import datetime

def shiftdate(d, days):
    return (
        d.replace(hour=0, minute=0, second=0, microsecond=0) + 
        datetime.timedelta(days=days)
    )
```

1.  使用它就像简单地提供你想要添加或移除的天数一样简单：

```py
>>> now = datetime.datetime.utcnow()
>>> now
datetime.datetime(2018, 3, 21, 21, 55, 5, 699400)
```

1.  我们可以用它去到明天：

```py
>>> shiftdate(now, 1)
datetime.datetime(2018, 3, 22, 0, 0)
```

1.  或者前往昨天：

```py
>>> shiftdate(now, -1)
datetime.datetime(2018, 3, 20, 0, 0)
```

1.  甚至前往下个月：

```py
>>> shiftdate(now, 11)
datetime.datetime(2018, 4, 1, 0, 0)
```

# 它是如何工作的...

通常在移动日期时间时，我们想要去到一天的开始。假设你想要在事件列表中找到明天发生的所有事件，你真的想要搜索`day_after_tomorrow > event_time >= tomorrow`，因为你想要找到从明天午夜开始到后天午夜结束的所有事件。

因此，简单地改变日期本身是行不通的，因为我们的日期时间也与时间相关联。如果我们只是在日期上加一天，实际上我们会在明天包含的小时范围内结束。

这就是为什么`shiftdate`函数总是用午夜替换提供的日期时间的原因。

一旦日期被移动到午夜，我们只需添加一个等于指定天数的`timedelta`。如果这个数字是负数，我们将会向后移动时间，因为`D + -1 == D -1`。

# 前往下个月

在移动日期时，另一个经常需要的需求是能够将日期移动到下个月或上个月。

如果你阅读了*前往明天*的食谱，你会发现与这个食谱有很多相似之处，尽管在处理月份时需要一些额外的变化，而在处理天数时是不需要的，因为月份的持续时间是可变的。

# 如何做...

按照这个食谱执行以下步骤：

1.  `shiftmonth`函数将允许我们按任意月数前后移动我们的日期：

```py
import datetime

def shiftmonth(d, months):
    for _ in range(abs(months)):
        if months > 0:
            d = d.replace(day=5) + datetime.timedelta(days=28)
        else:
            d = d.replace(day=1) - datetime.timedelta(days=1)
    d = d.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return d
```

1.  使用它就像简单地提供你想要添加或移除的月份一样简单：

```py
>>> now = datetime.datetime.utcnow()
>>> now
datetime.datetime(2018, 3, 21, 21, 55, 5, 699400)
```

1.  我们可以用它去到下个月：

```py
>>> shiftmonth(now, 1)
datetime.datetime(2018, 4, 1, 0, 0)
```

1.  或者回到上个月：

```py
>>> shiftmonth(now, -1)
datetime.datetime(2018, 2, 1, 0, 0)
```

1.  甚至可以按月份移动：

```py
>>> shiftmonth(now, 10)
datetime.datetime(2019, 1, 1, 0, 0)
```

# 它是如何工作的...

如果您尝试将此配方与*前往明天*进行比较，您会注意到，尽管其目的非常相似，但这个配方要复杂得多。

就像在移动天数时，我们有兴趣在一天中的特定时间点移动一样（通常是开始时），当移动月份时，我们不希望最终处于新月份的随机日期和时间。

这解释了我们配方的最后一部分，对于我们数学表达式产生的任何日期时间，我们将时间重置为该月的第一天的午夜：

```py
d = d.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
```

就像对于天数配方一样，这使我们能够检查条件，例如`two_month_from_now > event_date >= next_month`，因为我们将捕捉从该月的第一天午夜到上个月的最后一天 23:59 的所有事件。

您可能想知道的部分是`for`循环。

与我们必须按天数移动（所有天数的持续时间相等为 24 小时）不同，当按月份移动时，我们需要考虑到每个月的持续时间不同的事实。

这就是为什么在向前移动时，我们将当前日期设置为月份的第 5 天，然后添加 28 天。仅仅添加 28 天是不够的，因为它只适用于 2 月，如果您在想，添加 31 天也不起作用，因为在 2 月的情况下，您将移动两个月而不是一个月。

这就是为什么我们将当前日期设置为月份的第 5 天，因为我们想要选择一个日期，我们确切地知道向其添加 28 天将使我们进入下一个月。

例如，选择月份的第一天将有效，因为 3 月 1 日+28 天=3 月 29 日，所以我们仍然在 3 月。而 3 月 5 日+28 天=4 月 2 日，4 月 5 日+28 天=5 月 3 日，2 月 5 日+28 天=3 月 5 日。因此，对于任何给定的月份，我们在将 5 日加 28 天时总是进入下一个月。

我们总是移动到不同的日期并不重要，因为该日期总是会被替换为该月的第一天。

由于我们无法移动确保我们总是准确地移动到下一个月的固定天数，所以我们不能仅通过添加`天数*月份`来移动，因此我们必须在`for`循环中执行此操作，并连续移动`月份`次数。

当向后移动时，事情变得容易得多。由于所有月份都从月份的第一天开始，我们只需移动到那里，然后减去一天。我们总是会在上个月的最后一天。

# 工作日

为月份的第 20 天或第 3 周构建日期非常简单，但如果您必须为月份的第 3 个星期一构建日期呢？

# 如何做...

按照以下步骤进行：

1.  为了解决这个问题，我们将实际生成所有与请求的工作日匹配的月份日期：

```py
import datetime

def monthweekdays(month, weekday):
    now = datetime.datetime.utcnow()
    d = now.replace(day=1, month=month, hour=0, minute=0, second=0, 
                    microsecond=0)
    days = []
    while d.month == month:
        if d.isoweekday() == weekday:
            days.append(d)
        d += datetime.timedelta(days=1)
    return days
```

1.  然后，一旦我们有了这些列表，抓取*第 n 个*日期只是简单地索引结果列表。例如，要抓取 3 月的星期一：

```py
>>> monthweekdays(3, 1)
[datetime.datetime(2018, 3, 5, 0, 0), 
 datetime.datetime(2018, 3, 12, 0, 0), 
 datetime.datetime(2018, 3, 19, 0, 0), 
 datetime.datetime(2018, 3, 26, 0, 0)]
```

1.  所以抓取三月的第三个星期一将是：

```py
>>> monthweekdays(3, 1)[2]
datetime.datetime(2018, 3, 19, 0, 0)
```

# 它是如何工作的...

在配方的开始，我们为所请求的月份的第一天创建一个日期。然后我们每次向前移动一天，直到月份结束，并将所有与请求的工作日匹配的日期放在一边。

星期从星期一到星期日分别为 1 到 7。

一旦我们有了所有星期一、星期五或者月份的其他日期，我们只需索引结果列表，抓取我们真正感兴趣的日期。

# 工作日

在许多管理应用程序中，您只需要考虑工作日，星期六和星期日并不重要。在这些日子里，您不工作，所以从工作的角度来看，它们不存在。

因此，在计算项目管理或与工作相关的应用程序的给定时间跨度内包含的日期时，您可以忽略这些日期。

# 如何做...

我们想要获取两个日期之间的工作日列表：

```py
def workdays(d, end, excluded=(6, 7)):
    days = []
    while d.date() < end.date():
        if d.isoweekday() not in excluded:
            days.append(d)
        d += datetime.timedelta(days=1)
    return days
```

例如，如果是 2018 年 3 月 22 日，这是一个星期四，我想知道工作日直到下一个星期一（即 3 月 26 日），我可以轻松地要求`workdays`：

```py
>>> workdays(datetime.datetime(2018, 3, 22), datetime.datetime(2018, 3, 26))
[datetime.datetime(2018, 3, 22, 0, 0), 
 datetime.datetime(2018, 3, 23, 0, 0)]
```

因此我们知道还剩下两天：星期四本身和星期五。

如果您在世界的某个地方工作日是星期日，可能不是星期五，`excluded`参数可以用来指示哪些日期应该从工作日中排除。

# 它是如何工作的...

这个方法非常简单，我们只是从提供的日期（`d`）开始，每次加一天，直到达到`end`。

我们认为提供的参数是日期时间，因此我们循环比较只有日期，因为我们不希望根据`d`和`end`中提供的时间随机包括和排除最后一天。

这允许`datetime.datetime.utcnow()`为我们提供第一个参数，而不必关心函数何时被调用。只有日期本身将被比较，而不包括它们的时间。

# 组合日期和时间

有时您会有分开的日期和时间。当它们由用户输入时，这种情况特别频繁。从交互的角度来看，通常更容易选择一个日期然后选择一个时间，而不是一起选择日期和时间。或者您可能正在组合来自两个不同来源的输入。

在所有这些情况下，您最终会得到一个日期和时间，您希望将它们组合成一个单独的`datetime.datetime`实例。

# 如何做到...

Python 标准库提供了对这些操作的支持，因此拥有其中的任何两个：

```py
>>> t = datetime.time(13, 30)
>>> d = datetime.date(2018, 1, 11)
```

我们可以轻松地将它们组合成一个单一的实体：

```py
>>> datetime.datetime.combine(d, t)
datetime.datetime(2018, 1, 11, 13, 30)
```

# 还有更多...

如果您的`time`实例有一个时区（`tzinfo`），将日期与时间组合也会保留它：

```py
>>> t = datetime.time(13, 30, tzinfo=datetime.timezone.utc)
>>> datetime.datetime.combine(d, t)
datetime.datetime(2018, 1, 11, 13, 30, tzinfo=datetime.timezone.utc)
```

如果您的时间没有时区，您仍然可以在组合这两个值时指定一个时区：

```py
>>> t = datetime.time(13, 30)
>>> datetime.datetime.combine(d, t, tzinfo=datetime.timezone.utc)
```

在组合时提供时区仅支持 Python 3.6+。如果您使用之前的 Python 版本，您将不得不将时区设置为时间值。


# 第六章：读/写数据

在本章中，我们将涵盖以下配方：

+   读取和写入文本数据——从文件中读取任何编码的文本

+   读取文本行——逐行读取文本文件

+   读取和写入二进制数据——从文件中读取二进制结构化数据

+   压缩目录——读取和写入压缩的 ZIP 存档

+   Pickling 和 shelving——如何将 Python 对象保存在磁盘上

+   读取配置文件——如何读取`.ini`格式的配置文件

+   写入 XML/HTML 内容——生成 XML/HTML 内容

+   读取 XML/HTML 内容——从文件或字符串解析 XML/HTML 内容

+   读取和写入 CSV——读取和写入类似电子表格的 CSV 文件

+   读取和写入关系数据库——将数据加载到`SQLite`数据库中

# 介绍

您的软件的输入将来自各种来源：命令行选项，标准输入，网络，以及经常是文件。从输入中读取本身很少是处理外部数据源时的问题；一些输入可能需要更多的设置，有些更直接，但通常只是打开它然后从中读取。

问题出在我们读取的数据该如何处理。有成千上万种格式，每种格式都有其自己的复杂性，有些是基于文本的，有些是二进制的。在本章中，我们将设置处理您作为开发人员在生活中可能会遇到的最常见格式的配方。

# 读取和写入文本数据

当读取文本文件时，我们已经知道应该以文本模式打开它，这是 Python 的默认模式。在这种模式下，Python 将尝试根据`locale.getpreferredencoding`返回的作为我们系统首选编码的编码来解码文件的内容。

遗憾的是，任何类型的编码都是我们系统的首选编码与文件内容保存时使用的编码无关。因为它可能是别人写的文件，甚至是我们自己写的，编辑器可能以任何编码保存它。

因此，唯一的解决方案是指定应该用于解码文件的编码。

# 如何做...

Python 提供的`open`函数接受一个`encoding`参数，可以用于正确地编码/解码文件的内容：

```py
# Write a file with latin-1 encoding
with open('/tmp/somefile.txt', mode='w', encoding='latin-1') as f:
    f.write('This is some latin1 text: "è già ora"')

# Read back file with latin-1 encoding.
with open('/tmp/somefile.txt', encoding='latin-1') as f:
    txt = f.read()
    print(txt)
```

# 它是如何工作的...

一旦`encoding`选项传递给`open`，生成的文件对象将知道任何提供给`file.write`的字符串必须在将实际字节存储到文件之前编码为指定的编码。对于`file.read()`也是如此，它将从文件中获取字节，并在将它们返回给您之前使用指定的编码对其进行解码。

这允许您独立于系统声明的首选编码，读/写文件中的内容。

# 还有更多...

如果您想知道如何可能读取编码未知的文件，那么这是一个更加复杂的问题。

事实是，除非文件在头部提供一些指导，或者等效物，可以告诉您内容的编码类型，否则没有可靠的方法可以知道文件可能被编码的方式。

您可以尝试多种不同类型的编码，并检查哪种编码能够解码内容（不会抛出`UnicodeDecodeError`），但是一组字节解码为一种编码并不保证它解码为正确的结果。例如，编码为`utf-8`的`'ì'`字符在`latin-1`中完美解码，但结果完全不同：

```py
>>> 'ì'.encode('utf-8').decode('latin-1')
'Ã¬'
```

如果您真的想尝试猜测内容的类型编码，您可能想尝试一个库，比如`chardet`，它能够检测到大多数常见类型的编码。如果要解码的数据长度足够长且足够多样化，它通常会成功地检测到正确的编码。

# 读取文本行

在处理文本文件时，通常最容易的方法是按行处理；每行文本是一个单独的实体，我们可以通过`'\n'`或`'\r\n'`连接所有行，因此在列表中有文本文件的所有行将非常方便。

有一种非常方便的方法可以立即从文本文件中提取行，Python 可以立即使用。

# 如何做...

由于`file`对象本身是可迭代的，我们可以直接构建一个列表：

```py
with open('/var/log/install.log') as f:
    lines = list(f)
```

# 工作原理...

`open`充当上下文管理器，返回结果对象`file`。依赖上下文管理器非常方便，因为当我们完成文件操作时，我们需要关闭它，使用`open`作为上下文管理器将在我们退出`with`的主体时为我们关闭文件。

有趣的是`file`实际上是一个可迭代对象。当你迭代一个文件时，你会得到其中包含的行。因此，将`list`应用于它将构建所有行的列表，然后我们可以按照我们的意愿导航到结果列表。

# 字符

读取文本数据已经相当复杂，因为它需要解码文件的内容，但读取二进制数据可能会更加复杂，因为它需要解析字节及其内容以重建保存在文件中的原始数据。

在某些情况下，甚至可能需要处理字节顺序，因为当将数字保存到文本文件时，字节的写入顺序实际上取决于写入该文件的系统。

假设我们想要读取 TCP 头的开头，特定的源和目标端口、序列号和确认号，表示如下：

```py
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

# 如何做...

此食谱的步骤如下：

1.  假设有一个包含 TCP 数据包转储的文件（在我的计算机上，我将其保存为`/tmp/packet.dump`），我们可以尝试将其读取为二进制数据并解析其内容。

Python 的`struct`模块是读取二进制结构化数据的完美工具，我们可以使用它来解析我们的 TCP 数据包，因为我们知道每个部分的大小：

```py
>>> import struct
>>> with open('/tmp/packet.dump', 'rb') as f:
...     data = struct.unpack_from('>HHLL', f.read())
>>> data
(50291, 80, 2778997212, 644363807)
```

作为 HTTP 连接，结果是我们所期望的：`源端口：50291，目标端口：80，序列号：2778997212`和`确认号：644363807`。

1.  可以使用`struct.pack`将二进制数据写回：

```py
>>> with open('/tmp/packet.dump', 'wb') as f:
...     data = struct.pack('>HHLL', 50291, 80, 2778997212, 644363807)
...     f.write(data)
>>> data
b'\xc4s\x00P\xa5\xa4!\xdc&h6\x1f'
```

# 工作原理...

首先，我们以*二进制模式*（`rb`参数）打开文件。这告诉 Python 避免尝试解码文件的内容，就像它是文本一样；内容以`bytes`对象的形式返回。

然后，我们使用`f.read()`读取的数据传递给`struct.unpack_from`，它能够解码二进制数据作为一组数字、字符串等。在我们的例子中，我们使用`>`指定我们正在读取的数据是大端排序的（就像所有与网络相关的数据一样），然后使用`HHLL`来说明我们要读取两个无符号 16 位数字和两个无符号 32 位数字（端口和序列/确认号）。

由于我们使用了`unpack_from`，在消耗了指定的四个数字后，任何其他剩余的数据都会被忽略。

写入二进制数据也是一样的。我们以二进制模式打开文件，通过`struct.pack`将四个数字打包成一个字节对象，并将它们写入文件。

# 还有更多...

`struct.pack`和`struct.unpack`函数支持许多选项和格式化程序，以定义应该写入/读取的数据以及应该如何写入/读取。

字节顺序的最常见格式化程序如下：

| 字节顺序 |
| --- |
| 读取和写入二进制数据 |
| 本地 |
| 小端 |
| 大端 |

如果没有指定这些选项中的任何一个，数据将以您系统的本机字节顺序进行编码，并且将按照在系统内存中的自然对齐方式进行对齐。强烈不建议以这种方式保存数据，因为能够读取它的唯一系统是保存它的系统。

对于数据本身，每种数据类型由一个单个字符表示，每个字符定义数据的类型（整数、浮点数、字符串）和其大小：

| 格式 | C 类型 | Python 类型 | 大小（字节） |
| --- | --- | --- | --- |
| `x` | 填充字节 | 无值 |  |
| `c` | `char` | 长度为 1 的字节 | 1 |
| `b` | 有符号`char` | 整数 | 1 |
| `B` | 无符号`char` | 整数 | 1 |
| `?` | `_Bool` | 布尔值 | 1 |
| `h` | `short` | 整数 | 2 |
| `H` | 无符号`short` | 整数 | 2 |
| `i` | `int` | 整数 | 4 |
| `I` | 无符号`int` | 整数 | 4 |
| `l` | `long` | 整数 | 4 |
| `L` | 无符号`long` | 整数 | 4 |
| `q` | `long long` | 整数 | 8 |
| `Q` | 无符号`long long` | 整数 | 8 |
| `n` | `ssize_t` | 整数 |  |
| `N` | `size_t` | 整数 |  |
| `e` | 半精度`float` | 浮点数 | 2 |
| `f` | `float` | 浮点数 | 4 |
| `d` | `double` | 浮点数 | 8 |
| `s` | `char[]` | 字节 |  |
| `p` | `char[]` | 字节 |  |
| `P` | `void *` | 整数 |  |

# 压缩目录

存档文件是以一种好的方式来分发整个目录，就好像它们是单个文件，并且可以减小分发文件的大小。

Python 内置支持创建 ZIP 存档文件，可以利用它来压缩整个目录。

# 如何实现...

这个食谱的步骤如下：

1.  `zipfile`模块允许我们创建由多个文件组成的压缩 ZIP 存档：

```py
import zipfile
import os

def zipdir(archive_name, directory):
    with zipfile.ZipFile(
        archive_name, 'w', compression=zipfile.ZIP_DEFLATED
    ) as archive:
        for root, dirs, files in os.walk(directory):
            for filename in files:
                abspath = os.path.join(root, filename)
                relpath = os.path.relpath(abspath, directory)
                archive.write(abspath, relpath)        
```

1.  使用`zipdir`就像提供应该创建的`.zip`文件的名称和应该存档的目录的路径一样简单：

```py
zipdir('/tmp/test.zip', '_build/doctrees')
```

1.  在这种情况下，我压缩了包含本书文档树的目录。存档准备好后，我们可以通过再次使用`zipfile`打开它并列出包含的条目来验证其内容：

```py
>>> with zipfile.ZipFile('/tmp/test.zip') as archive:
...     for n in archive.namelist():
...         print(n)
algorithms.doctree
concurrency.doctree
crypto.doctree
datastructures.doctree
datetimes.doctree
devtools.doctree
environment.pickle
filesdirs.doctree
gui.doctree
index.doctree
io.doctree
multimedia.doctree
```

# 如何实现...

`zipfile.ZipFile`首先以`ZIP_DEFLATED`压缩（这意味着用标准 ZIP 格式压缩数据）的写模式打开。这允许我们对存档进行更改，然后在退出上下文管理器的主体时自动刷新并关闭存档。

在上下文中，我们依靠`os.walk`来遍历整个目录及其所有子目录，并找到所有包含的文件。

对于在每个目录中找到的每个文件，我们构建两个路径：绝对路径和相对路径。

绝对路径是必需的，以告诉`ZipFile`从哪里读取需要添加到存档中的数据，相对路径用于为写入存档的数据提供适当的名称。这样，我们写入存档的每个文件都将以磁盘上的名称命名，但是不会存储其完整路径（`/home/amol/pystlcookbook/_build/doctrees/io.doctree`），而是以相对路径（`_build/doctrees/io.doctree`）存储，因此，如果存档被解压缩，文件将相对于我们正在解压缩的目录创建，而不是以长而无意义的路径结束，这个路径类似于文件在我的计算机上的路径。

一旦文件的路径和应该用来存储它的名称准备好，它们就被提供给`ZipFile.write`来实际将文件写入存档。

一旦所有文件都被写入，我们退出上下文管理器，存档最终被刷新。

# Pickling and shelving

如果您的软件需要大量信息，或者如果您希望在不同运行之间保留历史记录，除了将其保存在某个地方并在下次运行时加载它之外，几乎没有其他选择。

手动保存和加载数据可能会很繁琐且容易出错，特别是如果数据结构很复杂。

因此，Python 提供了一个非常方便的模块`shelve`，允许我们保存和恢复任何类型的 Python 对象，只要可以对它们进行`pickle`。

# 如何实现...

执行以下步骤以完成此食谱：

1.  `shelve`，由`shelve`实现，可以像 Python 中的任何其他文件一样打开。一旦打开，就可以像字典一样将键读入其中：

```py
>>> with shelve.open('/tmp/shelf.db') as shelf:
...   shelf['value'] = 5
... 
```

1.  存储到`shelf`中的值也可以作为字典读回：

```py
>>> with shelve.open('/tmp/shelf.db') as shelf:
...   print(shelf['value'])
... 
5
```

1.  复杂的值，甚至自定义类，都可以存储在`shelve`中：

```py
>>> class MyClass(object):
...   def __init__(self, value):
...     self.value = value
... 
>>> with shelve.open('/tmp/shelf.db') as shelf:
...   shelf['value'] = MyClass(5)
... 
>>> with shelve.open('/tmp/shelf.db') as shelf:
...   print(shelf['value'])
... 
<__main__.MyClass object at 0x101e90d30>
>>> with shelve.open('/tmp/shelf.db') as shelf:
...   print(shelf['value'].value)
... 
5
```

# 它的工作原理...

`shelve` 模块被实现为管理`dbm`数据库的上下文管理器。

当上下文进入时，数据库被打开，并且因为`shelf`是一个字典，所以包含的对象变得可访问。

每个对象都作为一个 pickled 对象存储在数据库中。这意味着在存储之前，每个对象都使用`pickle`进行编码，并产生一个序列化字符串：

```py
>>> import pickle
>>> pickle.dumps(MyClass(5))
b'\x80\x03c__main__\nMyClass\nq\x00)\x81q\x01}'
b'q\x02X\x05\x00\x00\x00valueq\x03K\x05sb.'
```

这允许`shelve`存储任何类型的 Python 对象，甚至自定义类，只要它们在读取对象时再次可用。

然后，当上下文退出时，所有已更改的`shelf`键都将通过在关闭`shelf`时调用`shelf.sync`写回磁盘。

# 还有更多...

在使用`shelve`时需要注意一些事项。

首先，`shelve`不跟踪突变。如果您将可变对象（如`dict`或`list`）存储在`shelf`中，则对其进行的任何更改都不会被保存。只有对`shelf`本身的根键的更改才会被跟踪：

```py
>>> with shelve.open('/tmp/shelf.db') as shelf:
...   shelf['value'].value = 10
... 
>>> with shelve.open('/tmp/shelf.db') as shelf:
...   print(shelf['value'].value)
... 
5
```

这只是意味着您需要重新分配您想要改变的任何值：

```py
>>> with shelve.open('/tmp/shelf.db') as shelf:
...   myvalue = shelf['value']
...   myvalue.value = 10
...   shelf['value'] = myvalue
... 
>>> with shelve.open('/tmp/shelf.db') as shelf:
...   print(shelf['value'].value)
... 
10
```

`shelve` 不允许多个进程或线程同时进行并发读/写。如果要从多个进程访问相同的`shelf`，则必须使用锁（例如使用`fcntl.flock`）来包装`shelf`访问。

# 读取配置文件

当您的软件有太多的选项无法通过命令行简单地传递它们，或者当您希望确保用户不必每次启动应用程序时手动提供它们时，从配置文件加载这些选项是最常见的解决方案之一。

配置文件应该易于人类阅读和编写，因为他们经常会与它们一起工作，而最常见的要求之一是允许注释，以便用户可以在配置中写下为什么设置某些选项或如何计算某些值的原因。这样，当用户在六个月后回到配置文件时，他们仍然会知道这些选项的原因。

因此，通常依赖于 JSON 或机器-机器格式来配置选项并不是很好，因此最好使用特定于配置的格式。

最长寿的配置格式之一是`.ini`文件，它允许我们使用`[section]`语法声明多个部分，并使用`name = value`语法设置选项。

生成的配置文件将如下所示：

```py
[main]
debug = true
path = /tmp
frequency = 30
```

另一个很大的优势是我们可以轻松地从 Python 中读取`.ini`文件。

# 如何做到这一点...

本教程的步骤是：

1.  大多数加载和解析`.ini`的工作可以由`configparser`模块本身完成，但我们将扩展它以实现每个部分的默认值和转换器：

```py
import configparser

def read_config(config_text, schema=None):
    """Read options from ``config_text`` applying given ``schema``"""
    schema = schema or {}

    cfg = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation()
    )
    try:
        cfg.read_string(config_text)
    except configparser.MissingSectionHeaderError:
        config_text = '[main]\n' + config_text
        cfg.read_string(config_text)

    config = {}
    for section in schema:
        options = config.setdefault(section, {})
        for option, option_schema in schema[section].items():
            options[option] = option_schema.get('default')
    for section in cfg.sections():
        options = config.setdefault(section, {})
        section_schema = schema.get(section, {})
        for option in cfg.options(section):
            option_schema = section_schema.get(option, {})
            getter = 'get' + option_schema.get('type', '')
            options[option] = getattr(cfg, getter)(section, option)
    return config
```

1.  使用提供的函数就像提供一个应该用于解析它的配置和模式一样容易：

```py
config_text = '''
debug = true

[registry]
name = Alessandro
surname = Molina

[extra]
likes = spicy food
countrycode = 39
'''

config = read_config(config_text, {
    'main': {
        'debug': {'type': 'boolean'}
    },
    'registry': {
        'name': {'default': 'unknown'},
        'surname': {'default': 'unknown'},
        'middlename': {'default': ''},
    },
    'extra': {
        'countrycode': {'type': 'int'},
        'age': {'type': 'int', 'default': 0}
    },
    'more': {
        'verbose': {'type': 'int', 'default': 0}
    }
})
```

生成的配置字典`config`将包含配置中提供的所有选项或在模式中声明的选项，转换为模式中指定的类型：

```py
>>> import pprint
>>> pprint.pprint(config)
{'extra': {'age': 0, 'countrycode': 39, 'likes': 'spicy food'},
 'main': {'debug': True},
 'more': {'verbose': 0},
 'registry': {'middlename': 'unknown',
              'name': 'Alessandro',
              'surname': 'Molina'}}
```

# 它的工作原理...

`read_config`函数执行三件主要事情：

+   允许我们解析没有部分的简单`config`文件的纯列表选项：

```py
option1 = value1
option2 = value2
```

+   为配置的`default`模式中声明的所有选项应用默认值。

+   将所有值转换为模式中提供的`type`。

第一个特性是通过捕获解析过程中引发的任何`MissingSectionHeaderError`异常来提供的，并在缺少时自动添加`[main]`部分。所有未在任何部分中提供的选项都将记录在`main`部分下。

提供默认值是通过首先遍历模式中声明的所有部分和选项，并将它们设置为其`default`中提供的值或者如果没有提供默认值，则设置为`None`来完成的。

在第二次遍历中，所有默认值都将被实际存储在配置中的值所覆盖。

在第二次遍历期间，对于每个被设置的值，该选项的`type`在模式中被查找。通过在类型前加上`get`单词来构建诸如`getboolean`或`getint`的字符串。这导致成为需要用于将配置选项解析为请求的类型的`configparser`方法的名称。

如果没有提供`type`，则使用空字符串。这导致使用普通的`.get`方法，该方法将值读取为文本。因此，不提供`type`意味着将选项视为普通字符串。

然后，所有获取和转换的选项都存储在字典中，这样就可以通过`config[section][name]`的表示法更容易地访问转换后的值，而无需总是调用访问器，例如`.getboolean`。

# 还有更多...

提供给`ConfigParser`对象的`interpolation=configparser.ExtendedInterpolation()`参数还启用了一种插值模式，允许我们引用配置文件中其他部分的值。

这很方便，可以避免一遍又一遍地重复相同的值，例如，当提供应该都从同一个根开始的多个路径时：

```py
[paths]
root = /tmp/test01
images = ${root}/images
sounds = ${root}/sounds
```

此外，该语法允许我们引用其他部分中的选项：

```py
[main]
root = /tmp/test01

[paths]
images = ${main:root}/images
sounds = ${main:root}/sounds
```

`ConfigParser`的另一个便利功能是，如果要使一个选项在所有部分中都可用，只需在特殊的`[DEFAULT]`部分中指定它。

这将使该选项在所有其他部分中都可用，除非在该部分本身中明确覆盖它：

```py
>>> config = read_config('''
... [DEFAULT]
... option = 1
... 
... [section1]
... 
... [section2]
... option = 5
... ''')
>>> config
{'section1': {'option': '1'}, 
 'section2': {'option': '5'}}
```

# 编写 XML/HTML 内容

编写基于 SGML 的语言通常并不是很困难，大多数语言都提供了用于处理它们的实用程序，但是如果文档变得太大，那么在尝试以编程方式构建元素树时很容易迷失。

最终会有数百个`.addChild`或类似的调用，这些调用都是连续的，这样很难理解我们在文档中的位置以及我们当前正在编辑的部分是什么。

幸运的是，通过将 Python 的`ElementTree`模块与上下文管理器结合起来，我们可以拥有一个解决方案，使我们的代码结构能够与我们试图生成的 XML/HTML 的结构相匹配。

# 如何做...

对于这个配方，执行以下步骤：

1.  我们可以创建一个代表 XML/HTML 文档树的`XMLDocument`类，并且通过允许我们插入标签和文本的`XMLDocumentBuilder`来辅助实际构建文档。

```py
import xml.etree.ElementTree as ET
from contextlib import contextmanager

class XMLDocument:
    def __init__(self, root='document', mode='xml'):
        self._root = ET.Element(root)
        self._mode = mode

    def __str__(self):
        return ET.tostring(self._root, encoding='unicode', method=self._mode)

    def write(self, fobj):
        ET.ElementTree(self._root).write(fobj)

    def __enter__(self):
        return XMLDocumentBuilder(self._root)

    def __exit__(self, exc_type, value, traceback):
        return

class XMLDocumentBuilder:
    def __init__(self, root):
        self._current = [root]

    def tag(self, *args, **kwargs):
        el = ET.Element(*args, **kwargs)
        self._current[-1].append(el)
        @contextmanager
        def _context():
            self._current.append(el)
            try:
                yield el
            finally:
                self._current.pop()
        return _context()

    def text(self, text):
        if self._current[-1].text is None:
            self._current[-1].text = ''
        self._current[-1].text += text
```

1.  然后，我们可以使用我们的`XMLDocument`来构建我们想要的文档。例如，我们可以在 HTML 模式下构建网页：

```py
doc = XMLDocument('html', mode='html')

with doc as _:
    with _.tag('head'):
        with _.tag('title'): _.text('This is the title')
    with _.tag('body'):
        with _.tag('div', id='main-div'):
            with _.tag('h1'): _.text('My Document')
            with _.tag('strong'): _.text('Hello World')
            _.tag('img', src='http://via.placeholder.com/150x150')
```

1.  `XMLDocument`支持转换为字符串，因此要查看生成的 XML，我们只需打印它：

```py
>>> print(doc)
<html>
    <head>
        <title>This is the title</title>
    </head>
    <body>
        <div id="main-div">
            <h1>My Document</h1>
            <strong>Hello World</strong>
            <img src="http://via.placeholder.com/150x150">
        </div>
    </body>
</html>
```

正如您所看到的，我们的代码结构与实际 XML 文档的嵌套相匹配，因此很容易看到`_.tag('body')`中的任何内容都是我们 body 标签的内容。

将生成的文档写入实际文件可以依赖于`XMLDocument.write`方法来完成：

```py
doc.write('/tmp/test.html')
```

# 它是如何工作的...

实际的文档生成是由`xml.etree.ElementTree`执行的，但是如果我们必须使用普通的`xml.etree.ElementTree`生成相同的文档，那么将会导致一堆`el.append`调用：

```py
root = ET.Element('html')
head = ET.Element('head')
root.append(head)
title = ET.Element('title')
title.text = 'This is the title'
head.append(title)
```

这使得我们很难理解我们所在的位置。在这个例子中，我们只是构建一个结构，`<html><head><title>This is the title</title></head></html>`，但是已经很难跟踪`title`在 head 中，依此类推。对于更复杂的文档，这将变得不可能。

因此，虽然我们的`XMLDocument`保留了文档树的`root`并支持将其转换为字符串并将其写入文件，但实际工作是由`XMLDocumentBuilder`完成的。

`XMLDocumentBuilder`保持节点堆栈以跟踪我们在树中的位置（`XMLDocumentBuilder._current`）。该列表的尾部将始终告诉我们当前在哪个标签内。

调用`XMLDocumentBuilder.text`将向当前活动标签添加文本：

```py
doc = XMLDocument('html', mode='html')
with doc as _:
    _.text('Some text, ')
    _.text('and even more')
```

上述代码将生成`<html>Some text, and even more</html>`。

`XMLDocumentBuilder.tag`方法将在当前活动标签中添加一个新标签：

```py
doc = XMLDocument('html', mode='html')
with doc as _:
    _.tag('input', type='text', placeholder='Name?')
    _.tag('input', type='text', placeholder='Surname?')
```

这导致以下结果：

```py
<html>
    <input placeholder="Name?" type="text">
    <input placeholder="Surname?" type="text">
</html>
```

有趣的是，`XMLDocumentBuilder.tag`方法还返回一个上下文管理器。进入时，它将设置输入的标签为当前活动标签，退出时，它将恢复先前的活动节点。

这使我们能够嵌套`XMLDocumentBuilder.tag`调用并生成标签树：

```py
doc = XMLDocument('html', mode='html')
with doc as _:
    with _.tag('head'):
        with _.tag('title') as title: title.text = 'This is a title'
```

这导致以下结果：

```py
<html>
    <head>
        <title>This is a title</title>
    </head>
</html>
```

实际文档节点可以通过`as`获取，因此在先前的示例中，我们能够获取刚刚创建的`title`节点并为其设置文本，但`XMLDocumentBuilder.text`也可以工作，因为`title`节点现在是活动元素，一旦我们进入其上下文。

# 还有更多...

在使用此方法时，我经常应用一个技巧。这使得在 Python 端更难理解发生了什么，这就是我在解释配方本身时避免这样做的原因，但通过消除大部分 Python *噪音*，它使 HTML/XML 结构更加可读。

如果您将`XMLDocumentBuilder.tag`和`XMLDocumentBuilder.text`方法分配给一些简短的名称，您几乎可以忽略调用 Python 函数的事实，并使 XML 结构更相关：

```py
doc = XMLDocument('html', mode='html')
with doc as builder:
    _ = builder.tag
    _t = builder.text

    with _('head'):
        with _('title'): _t('This is the title')
    with _('body'):
        with _('div', id='main-div'):
            with _('h1'): _t('My Document')
            with _('strong'): _t('Hello World')
            _('img', src='http://via.placeholder.com/150x150')
```

以这种方式编写，您实际上只能看到 HTML 标签及其内容，这使得文档结构更加明显。

# 阅读 XML/HTML 内容

阅读 HTML 或 XML 文件使我们能够解析网页内容，并阅读 XML 中描述的文档或配置。

Python 有一个内置的 XML 解析器，`ElementTree`模块非常适合解析 XML 文件，但涉及 HTML 时，由于 HTML 的各种怪癖，它很快就会出现问题。

考虑尝试解析以下 HTML：

```py
<html>
    <body class="main-body">
        <p>hi</p>
        <img><br>
        <input type="text" />
    </body>
</html>
```

您将很快遇到错误：

```py
xml.etree.ElementTree.ParseError: mismatched tag: line 7, column 6
```

幸运的是，调整解析器以处理至少最常见的 HTML 文件并不太难，例如自闭合/空标签。

# 如何做...

对于此配方，您需要执行以下步骤：

1.  `ElementTree`默认使用`expat`解析文档，然后依赖于`xml.etree.ElementTree.TreeBuilder`构建文档的 DOM。

我们可以用基于`HTMLParser`的自己的解析器替换基于`expat`的`XMLParser`，并让`TreeBuilder`依赖于它：

```py
import xml.etree.ElementTree as ET
from html.parser import HTMLParser

class ETHTMLParser(HTMLParser):
    SELF_CLOSING = {'br', 'img', 'area', 'base', 'col', 'command',    
                    'embed', 'hr', 'input', 'keygen', 'link', 
                    'menuitem', 'meta', 'param',
                    'source', 'track', 'wbr'}

    def __init__(self, *args, **kwargs):
        super(ETHTMLParser, self).__init__(*args, **kwargs)
        self._builder = ET.TreeBuilder()
        self._stack = []

    @property
    def _last_tag(self):
        return self._stack[-1] if self._stack else None

    def _handle_selfclosing(self):
        last_tag = self._last_tag
        if last_tag in self.SELF_CLOSING:
            self.handle_endtag(last_tag)

    def handle_starttag(self, tag, attrs):
        self._handle_selfclosing()
        self._stack.append(tag)
        self._builder.start(tag, dict(attrs))

    def handle_endtag(self, tag):
        if tag != self._last_tag:
            self._handle_selfclosing()
        self._stack.pop()
        self._builder.end(tag)

    def handle_data(self, data):
        self._handle_selfclosing()
        self._builder.data(data)

    def close(self):
        return self._builder.close()
```

1.  使用此解析器，我们最终可以成功处理我们的 HTML 文档：

```py
text = '''
<html>
    <body class="main-body">
        <p>hi</p>
        <img><br>
        <input type="text" />
    </body>
</html>
'''

parser = ETHTMLParser()
parser.feed(text)
root = parser.close()
```

1.  我们可以验证我们的`root`节点实际上包含我们原始的 HTML 文档，通过将其打印回来：

```py
>>> print(ET.tostring(root, encoding='unicode'))
<html>
    <body class="main-body">
        <p>hi</p>
        <img /><br />
        <input type="text" />
    </body>
</html>
```

1.  然后，生成的`root`文档可以像任何其他`ElementTree.Element`树一样进行导航：

```py
def print_node(el, depth=0):
    print(' '*depth, el)
    for child in el:
        print_node(child, depth + 1)

>>> print_node(root)
 <Element 'html' at 0x102799a48>
  <Element 'body' at 0x102799ae8>
   <Element 'p' at 0x102799a98>
   <Element 'img' at 0x102799b38>
   <Element 'br' at 0x102799b88>
   <Element 'input' at 0x102799bd8>
```

# 它是如何工作的...

为了构建表示 HTML 文档的`ElementTree.Element`对象树，我们一起使用了两个类：`HTMLParser`读取 HTML 文本，`TreeBuilder`构建`ElementTree.Element`对象树。

每次`HTMLParser`遇到打开或关闭标签时，它将调用`handle_starttag`和`handle_endtag`。当我们遇到这些时，我们通知`TreeBuilder`必须启动一个新元素，然后关闭该元素。

同时，我们在`self._stack`中跟踪上次启动的标签（因此我们当前所在的标签）。这样，我们可以知道当前打开的标签尚未关闭。每次遇到新的打开标签或关闭标签时，我们都会检查上次打开的标签是否是自闭合标签；如果是，我们会在打开或关闭新标签之前关闭它。

这将自动转换代码。考虑以下内容：

```py
<br><p></p>
```

它将被转换为以下内容：

```py
In::
<br></br><p></p>
```

在遇到一个新的开放标签后，当遇到一个自关闭标签（`<br>`）时，`<br>`标签会自动关闭。

它还处理以下代码：

```py
<body><br></body>
```

前面的代码转换为以下内容：

```py
<body><br></br></body>
```

当面对`<br>`自关闭标签后，遇到不同的关闭标签（`</body>`），`<br>`会自动关闭。

即使在处理标签内文本时调用`handle_data`，如果最后一个开放标签是自关闭标签，自关闭标签也会自动关闭：

```py
<p><br>Hello World</p>
```

`Hello World`文本被认为是`<p>`的内容，而不是`<br>`的内容，因为代码被转换为以下内容：

```py
<p><br></br>Hello World</p>
```

最后，一旦完整的文档被解析，调用`ETHTMLParser.close()`将终止`TreeBuilder`构建的树，并返回生成的根`Element`。

# 还有更多...

提出的食谱展示了如何使用`HTMLParser`来适应 XML 解析工具以处理 HTML，与 XML 相比，HTML 的规则更加灵活。

虽然这个解决方案主要处理常见的 HTML 写法，但它不会涵盖所有可能的情况。HTML 支持一些奇怪的情况，有时会使用一些没有值的属性：

```py
<input disabled>
```

或者没有引号的属性：

```py
<input type=text>
```

甚至一些带内容但没有任何关闭标签的属性：

```py
<li>Item 1
<li>Item 2
```

尽管大多数这些格式都得到支持，但它们很少被使用（也许除了没有任何值的属性，我们的解析器会报告其值为`None`之外），所以在大多数情况下，它们不会引起麻烦。但是，如果您真的需要解析支持所有可能的奇怪情况的 HTML，那么最好使用外部库，比如`lxml`或`html5lib`，它们在面对奇怪情况时会尽可能地像浏览器一样行为。

# 读写 CSV

CSV 被认为是表格数据的最佳交换格式之一；几乎所有的电子表格工具都支持读写 CSV，并且可以使用任何纯文本编辑器轻松编辑，因为它对人类来说很容易理解。

只需拆分并用逗号设置值，您几乎已经写了一个 CSV 文档。

Python 对于读取 CSV 文件有非常好的内置支持，我们可以通过`csv`模块轻松地写入或读取 CSV 数据。

我们将看到如何读写表格：

```py
"ID","Name","Surname","Language"
1,"Alessandro","Molina","Italian"
2,"Mika","Häkkinen","Suomi"
3,"Sebastian","Vettel","Deutsch"
```

# 如何做...

让我们看看这个食谱的步骤：

1.  首先，我们将看到如何写指定的表：

```py
import csv

with open('/tmp/table.csv', 'w', encoding='utf-8') as f:
    writer = csv.writer(f, quoting=csv.QUOTE_NONNUMERIC)
    writer.writerow(("ID","Name","Surname","Language"))
    writer.writerow((1,"Alessandro","Molina","Italian"))
    writer.writerow((2,"Mika","Häkkinen","Suomi"))
    writer.writerow((3,"Sebastian","Vettel","Deutsch"))
```

1.  `table.csv`文件将包含我们之前看到的相同的表，我们可以使用任何`csv`读取器将其读回。当您的 CSV 文件有标题时，最方便的是`DictReader`，它将使用标题作为键读取每一行到一个字典中：

```py
with open('/tmp/table.csv', 'r', encoding='utf-8', newline='') as f:
    reader = csv.DictReader(f)
    for row in reader:
        print(row)
```

1.  迭代`DictReader`将消耗行，应该打印我们写的相同数据：

```py
{'Surname': 'Molina', 'Language': 'Italian', 'ID': '1', 'Name': 'Alessandro'}
{'Surname': 'Häkkinen', 'Language': 'Suomi', 'ID': '2', 'Name': 'Mika'}
{'Surname': 'Vettel', 'Language': 'Deutsch', 'ID': '3', 'Name': 'Sebastian'}
```

# 还有更多...

CSV 文件是纯文本文件，有一些限制。例如，没有任何东西告诉我们如何编码换行符（`\r\n`或`\n`），也没有告诉我们应该使用哪种编码，`utf-8`还是`ucs-2`。理论上，CSV 甚至没有规定必须是逗号分隔的；很多软件会用`:`或`;`来分隔。

这就是为什么在读取 CSV 文件时，您应该注意提供给`open`函数的`encoding`。在我们的例子中，我们确定使用了`utf8`，因为我们自己写了文件，但在其他情况下，不能保证使用了任何特定的编码。

如果您不确定 CSV 文件的格式，可以尝试使用`csv.Sniffer`对象，当应用于 CSV 文件中包含的文本时，它将尝试检测使用的方言。

一旦方言被确定，您可以将其传递给`csv.reader`，告诉读取器使用该方言解析文件。

# 读写数据库

Python 通常被称为一个*内置电池*的语言，这要归功于它非常完整的标准库，它提供的最好的功能之一就是从一个功能齐全的关系型数据库中读取和写入。

Python 内置了`SQLite`库，这意味着我们可以保存和读取由`SQLite`存储的数据库文件。

使用起来非常简单，实际上大部分只涉及发送 SQL 进行执行。

# 如何做到...

对于这些食谱，步骤如下：

1.  使用`sqlite3`模块，可以创建一个新的数据库文件，创建一个表，并向其中插入条目：

```py
import sqlite3

with sqlite3.connect('/tmp/test.db') as db:
    try:
        db.execute('''CREATE TABLE people (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
            name TEXT, 
            surname TEXT, 
            language TEXT
        )''')
    except sqlite3.OperationalError:
        # Table already exists
        pass

    sql = 'INSERT INTO people (name, surname, language) VALUES (?, ?, ?)'
    db.execute(sql, ("Alessandro", "Molina", "Italian"))
    db.execute(sql, ("Mika", "Häkkinen", "Suomi"))
    db.execute(sql, ("Sebastian", "Vettel", "Deutsch"))
```

1.  `sqlite3`模块还提供了对`cursors`的支持，它允许我们将查询的结果从数据库流式传输到你自己的代码：

```py
with sqlite3.connect('/tmp/test.db') as db:
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    for row in cursor.execute('SELECT * FROM people WHERE language 
                              != :language', 
                              {'language': 'Italian'}):
        print(dict(row))
```

1.  前面的片段将打印存储在我们的数据库中的所有行作为`dict`，键与列名匹配，值与行中每个列的值匹配。

```py
{'name': 'Mika', 'language': 'Suomi', 'surname': 'Häkkinen', 'id': 2}
{'name': 'Sebastian', 'language': 'Deutsch', 'surname': 'Vettel', 'id': 3}
```

# 它是如何工作的...

`sqlite3.connect`用于打开数据库文件；返回的对象可以用于对其执行任何查询，无论是插入还是选择。

然后使用`.execute`方法来运行任何 SQL 代码。要运行的 SQL 以纯字符串的形式提供。

在执行查询时，通常不应直接在 SQL 中提供值，特别是如果这些值是由用户提供的。

想象我们写了以下内容：

```py
cursor.execute('SELECT * FROM people WHERE language != %s' % ('Italian',)):
```

如果用户提供的字符串是`Italian" OR 1=1 OR "`，而不是`Italian`，会发生什么？用户不会过滤结果，而是可以访问表的全部内容。很容易看出，如果查询是通过用户 ID 进行过滤，而表中包含来自多个用户的数据，这可能会成为安全问题。

此外，在`executescript`命令的情况下，用户将能够依赖相同的行为来实际执行任何 SQL 代码，从而将代码注入到我们自己的应用程序中。

因此，`sqlite3`提供了一种方法来传递参数到 SQL 查询并转义它们的内容，这样即使用户提供了恶意输入，也不会发生任何不好的事情。

我们的`INSERT`语句中的`?`占位符和我们的`SELECT`语句中的`:language`占位符正是为了这个目的：依赖于`sqlite`的转义行为。

这两者是等价的，你可以选择使用哪一个。一个适用于元组，而另一个适用于字典。

在从数据库中获取结果时，它们是通过`Cursor`提供的。你可以将光标视为从数据库流式传输数据的东西。每当你需要访问它时，才会读取每一行，从而避免将所有行加载到内存中并一次性传输它们的需要。

虽然这对于常见情况不是一个主要问题，但当读取大量数据时可能会出现问题，直到系统可能会因为消耗太多内存而终止你的 Python 脚本。

默认情况下，从光标读取行会返回元组，其中值的顺序与列的声明顺序相同。通过使用`db.row_factory = sqlite3.Row`，我们确保光标返回`sqlite3.Row`对象作为行。

它们比元组更方便，因为它们可以像元组一样进行索引（你仍然可以写`row[0]`），而且还支持通过列名进行访问（`row['name']`）。我们的片段依赖于`sqlite3.Row`对象可以转换为字典，以打印所有带有列名的行值。

# 还有更多...

`sqlite3`模块支持许多其他功能，例如事务、自定义类型和内存数据库。

自定义类型允许我们将结构化数据读取为 Python 对象，但我最喜欢的功能是支持内存数据库。

在编写软件的测试套件时，使用内存数据库非常方便。如果你编写依赖于`sqlite3`模块的软件，请确保编写连接到`":memory:"`数据库的测试。这将使你的测试更快，并且将避免在每次运行测试时在磁盘上堆积测试数据库文件。
