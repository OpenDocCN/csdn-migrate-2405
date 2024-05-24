# 现代 Python 标准库秘籍（五）

> 原文：[`zh.annas-archive.org/md5/3fab99a8deba9438823e5414cd05b6e8`](https://zh.annas-archive.org/md5/3fab99a8deba9438823e5414cd05b6e8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：多媒体

在本章中，我们将涵盖以下配方：

+   确定文件类型——如何猜测文件类型

+   检测图像类型——检查图像以了解其类型

+   检测图像大小——检查图像以检索其大小

+   播放音频/视频/图像——在桌面系统上播放音频、视频或显示图像

# 介绍

多媒体应用程序，如视频、声音和游戏通常需要依赖非常特定的库来管理用于存储数据和播放内容所需的硬件。

由于数据存储格式的多样性，视频和音频存储领域的不断改进导致新格式的出现，以及与本地操作系统功能和特定硬件编程语言的深度集成，多媒体相关功能很少集成在标准库中。

当每隔几个月就会创建一个新的图像格式时，需要维护对所有已知图像格式的支持，这需要全职的工作，而专门的库可以比维护编程语言本身的团队更好地处理这个问题。

因此，Python 几乎没有与多媒体相关的函数，但一些核心函数是可用的，它们可以在多媒体不是主要关注点的应用程序中非常有帮助，但也许它们需要处理多媒体文件以正确工作；例如，一个可能需要检查用户上传的文件是否是浏览器支持的有效格式的 Web 应用程序。

# 确定文件类型

当我们从用户那里收到文件时，通常需要检测其类型。通过文件名而无需实际读取数据就可以实现这一点，这可以通过`mimetypes`模块来实现。

# 如何做...

对于这个配方，需要执行以下步骤：

1.  虽然`mimetypes`模块并不是绝对可靠的，因为它依赖于文件名来检测预期的类型，但它通常足以处理大多数常见情况。

1.  用户通常会为了自己的利益（特别是 Windows 用户，其中扩展名对文件的正确工作至关重要）为其文件分配适当的名称，使用`mimetypes.guess_type`猜测类型通常就足够了：

```py
import mimetypes

def guess_file_type(filename):
    if not getattr(guess_file_type, 'initialised', False):
        mimetypes.init()
        guess_file_type.initialised = True
    file_type, encoding = mimetypes.guess_type(filename)
    return file_type
```

1.  我们可以对任何文件调用`guess_file_type`来获取其类型：

```py
>>> print(guess_file_type('~/Pictures/5565_1680x1050.jpg'))
'image/jpeg'
>>> print(guess_file_type('~/Pictures/5565_1680x1050.jpeg'))
'image/jpeg'
>>> print(guess_file_type('~/Pictures/avatar.png'))
'image/png' 
```

1.  如果类型未知，则返回`None`：

```py
>>> print(guess_file_type('/tmp/unable_to_guess.blob'))
None
```

1.  另外，请注意文件本身并不一定真的存在。您关心的只是它的文件名：

```py
>>> print(guess_file_type('/this/does/not/exists.txt'))
'text/plain'
```

# 它是如何工作的...

`mimetypes`模块保留了与每个文件扩展名关联的 MIME 类型列表。

提供文件名时，只分析扩展名。

如果扩展名在已知 MIME 类型列表中，则返回关联的类型。否则返回`None`。

调用`mimetypes.init()`还会加载系统配置中注册的任何 MIME 类型，通常是从 Linux 系统的`/etc/mime.types`和 Windows 系统的注册表中加载。

这使我们能够涵盖更多可能不为 Python 所知的扩展名，并且还可以轻松支持自定义扩展名，如果您的系统配置支持它们的话。

# 检测图像类型

当您知道正在处理图像文件时，通常需要验证它们的类型，以确保它们是您的软件能够处理的格式。

一个可能的用例是确保它们是浏览器可能能够在网站上上传时显示的格式的图像。

通常可以通过检查文件头部来检测多媒体文件的类型，文件头部是文件的初始部分，存储有关文件内容的详细信息。

标头通常包含有关文件类型、包含图像的大小、每种颜色的位数等的详细信息。所有这些细节都是重现文件内存储的内容所必需的。

通过检查头部，可以确认存储数据的格式。这需要支持特定的头部格式，Python 标准库支持大多数常见的图像格式。

# 如何做...

`imghdr` 模块可以帮助我们了解我们面对的是什么类型的图像文件：

```py
import imghdr

def detect_image_format(filename):
    return imghdr.what(filename)
```

这使我们能够检测磁盘上任何图像的格式或提供的字节流的格式：

```py
>>> print(detect_image_format('~/Pictures/avatar.jpg'))
'jpeg'
>>> with open('~/Pictures/avatar.png', 'rb') as f:
...     print(detect_image_format(f))
'png'
```

# 它是如何工作的...

当提供的文件名是包含文件路径的字符串时，直接在其上调用 `imghdr.what`。

这只是返回文件的类型，如果不支持则返回 `None`。

相反，如果提供了类似文件的对象（例如文件本身或 `io.BytesIO`），则它将查看其前 32 个字节并根据这些字节检测头部。

鉴于大多数图像类型的头部大小在 10 多个字节左右，读取 32 个字节可以确保我们应该有足够的内容来检测任何图像。

读取字节后，它将返回到文件的开头，以便任何后续调用仍能读取文件（否则，前 32 个字节将被消耗并永远丢失）。

# 还有更多...

Python 标准库还提供了一个 `sndhdr` 模块，它的行为很像音频文件的 `imghdr`。

`sndhdr` 识别的格式通常是非常基本的格式，因此当涉及到 `wave` 或 `aiff` 文件时，它通常是非常有帮助的。

# 检测图像大小

如果我们知道我们面对的是什么类型的图像，检测分辨率通常只是从图像头部读取它。

对于大多数图像类型，这相对简单，因为我们可以使用 `imghdr` 来猜测正确的图像类型，然后根据检测到的类型读取头部的正确部分，以提取大小部分。

# 如何做...

一旦 `imghdr` 检测到图像类型，我们就可以使用 `struct` 模块读取头部的内容：

```py
import imghdr
import struct
import os
from pathlib import Path

class ImageReader:
    @classmethod
    def get_size(cls, f):    
        requires_close = False
        if isinstance(f, (str, getattr(os, 'PathLike', str))):
            f = open(f, 'rb')
            requires_close = True
        elif isinstance(f, Path):
            f = f.expanduser().open('rb')
            requires_close = True

        try:
            image_type = imghdr.what(f)
            if image_type not in ('jpeg', 'png', 'gif'):
                raise ValueError('Unsupported image format')

            f.seek(0)
            size_reader = getattr(cls, '_size_{}'.format(image_type))
            return size_reader(f)
        finally:
            if requires_close: f.close()

    @classmethod
    def _size_gif(cls, f):
        f.read(6)  # Skip the Magick Numbers
        w, h = struct.unpack('<HH', f.read(4))
        return w, h

    @classmethod
    def _size_png(cls, f):
        f.read(8)  # Skip Magic Number
        clen, ctype = struct.unpack('>I4s', f.read(8))
        if ctype != b'IHDR':
            raise ValueError('Unsupported PNG format')
        w, h = struct.unpack('>II', f.read(8))
        return w, h

    @classmethod
    def _size_jpeg(cls, f):
        start_of_image = f.read(2)
        if start_of_image != b'\xff\xd8':
            raise ValueError('Unsupported JPEG format')
        while True:
            marker, segment_size = struct.unpack('>2sH', f.read(4))
            if marker[0] != 0xff:
                raise ValueError('Unsupported JPEG format')
            data = f.read(segment_size - 2)
            if not 0xc0 <= marker[1] <= 0xcf:
                continue
            _, h, w = struct.unpack('>cHH', data[:5])
            break
        return w, h
```

然后我们可以使用 `ImageReader.get_size` 类方法来检测任何支持的图像的大小：

```py
>>> print(ImageReader.get_size('~/Pictures/avatar.png'))
(300, 300)
>>> print(ImageReader.get_size('~/Pictures/avatar.jpg'))
(300, 300)
```

# 它是如何工作的...

`ImageReader` 类的四个核心部分共同工作，以提供对读取图像大小的支持。

首先，`ImageReader.get_size` 方法本身负责打开图像文件并检测图像类型。

第一部分与打开文件有关，如果它以字符串形式提供为路径，作为 `Path` 对象，或者如果它已经是文件对象：

```py
requires_close = False
if isinstance(f, (str, getattr(os, 'PathLike', str))):
    f = open(f, 'rb')
    requires_close = True
elif isinstance(f, Path):
    f = f.expanduser().open('rb')
    requires_close = True
```

如果它是一个字符串或路径对象（`os.PathLike` 仅支持 Python 3.6+），则打开文件并将 `requires_close` 变量设置为 `True`，这样一旦完成，我们将关闭文件。

如果它是一个 `Path` 对象，并且我们使用的 Python 版本不支持 `os.PathLike`，那么文件将通过路径本身打开。

如果提供的对象已经是一个打开的文件，则我们什么也不做，`requires_close` 保持 `False`，这样我们就不会关闭提供的文件。

一旦文件被打开，它被传递给 `imghdr.what` 来猜测文件类型，如果它不是受支持的类型之一，它就会被拒绝：

```py
image_type = imghdr.what(f)
if image_type not in ('jpeg', 'png', 'gif'):
    raise ValueError('Unsupported image format')
```

最后，我们回到文件的开头，这样我们就可以读取头部，并调用相关的 `cls._size_png`、`cls._size_jpeg` 或 `cls._size_gif` 方法：

```py
f.seek(0)
size_reader = getattr(cls, '_size_{}'.format(image_type))
return size_reader(f)
```

每种方法都专门用于了解特定文件格式的大小，从最简单的（GIF）到最复杂的（JPEG）。

对于 GIF 本身，我们所要做的就是跳过魔术数字（只有 `imghdr.what` 关心；我们已经知道它是 GIF），并将随后的四个字节读取为无符号短整数（16 位数字），采用小端字节顺序：

```py
@classmethod
def _size_gif(cls, f):
    f.read(6)  # Skip the Magick Numbers
    w, h = struct.unpack('<HH', f.read(4))
    return w, h
```

`png` 几乎和 GIF 一样复杂。我们跳过魔术数字，并将随后的字节作为大端顺序的 `unsigned int`（32 位数字）读取，然后是四字节字符串：

```py
@classmethod
def _size_png(cls, f):
    f.read(8)  # Skip Magic Number
    clen, ctype = struct.unpack('>I4s', f.read(8))
```

这给我们返回了图像头部的大小，后面跟着图像部分的名称，必须是 `IHDR`，以确认我们正在读取图像头部：

```py
if ctype != b'IHDR':
    raise ValueError('Unsupported PNG format')
```

一旦我们知道我们在图像头部内，我们只需读取前两个`unsigned int`数字（仍然是大端）来提取图像的宽度和高度：

```py
w, h = struct.unpack('>II', f.read(8))
return w, h
```

最后一种方法是最复杂的，因为 JPEG 的结构比 GIF 或 PNG 复杂得多。JPEG 头由多个部分组成。每个部分由`0xff`标识，后跟部分标识符和部分长度。

一开始，我们只读取前两个字节并确认我们面对**图像的开始**（**SOI**）部分：

```py
@classmethod
def _size_jpeg(cls, f):
    start_of_image = f.read(2)
    if start_of_image != b'\xff\xd8':
        raise ValueError('Unsupported JPEG format')
```

然后我们寻找一个声明 JPEG 为基线 DCT、渐进 DCT 或无损帧的部分。

这是通过读取每个部分的前两个字节及其大小来完成的：

```py
while True:
    marker, segment_size = struct.unpack('>2sH', f.read(4))
```

由于我们知道每个部分都以`0xff`开头，如果我们遇到以不同字节开头的部分，这意味着图像无效：

```py
if marker[0] != 0xff:
    raise ValueError('Unsupported JPEG format')
```

如果部分有效，我们可以读取它的内容。我们知道大小，因为它是在两个字节的无符号短整数中以大端记法指定的：

```py
data = f.read(segment_size - 2)
```

现在，在能够从我们刚刚读取的数据中读取宽度和高度之前，我们需要检查我们正在查看的部分是否实际上是基线、渐进或无损的帧的开始。这意味着它必须是从`0xc0`到`0xcf`的部分之一。

否则，我们只是跳过这个部分并移动到下一个：

```py
if not 0xc0 <= marker[1] <= 0xcf:
    continue
```

一旦我们找到一个有效的部分（取决于图像的编码方式），我们可以通过查看前五个字节来读取大小。

第一个字节是样本精度。我们真的不关心它，所以我们可以忽略它。然后，剩下的四个字节是图像的高度和宽度，以大端记法的两个无符号短整数：

```py
_, h, w = struct.unpack('>cHH', data[:5])
```

# 播放音频/视频/图像

Python 标准库没有提供打开图像的实用程序，并且对播放音频文件的支持有限。

虽然可以通过结合`wave`和`ossaudiodev`或`winsound`模块以某种格式在一些格式中播放音频文件，但是 OSS 音频系统在 Linux 系统上已经被弃用，而且这两者都不适用于 Mac 系统。

对于图像，可以使用`tkinter`模块显示图像，但我们将受到非常简单的图像格式的限制，因为解码图像将由我们自己完成。

但是有一个小技巧，我们可以用来实际显示大多数图像文件和播放大多数音频文件。

在大多数系统上，尝试使用默认的网络浏览器打开文件将播放文件，我们可以依靠这个技巧和`webbrowser`模块通过 Python 播放大多数文件类型。

# 如何做...

此食谱的步骤如下：

1.  给定一个指向支持的文件的路径，我们可以构建一个`file:// url`，然后使用`webbrowser`模块打开它：

```py
import pathlib
import webbrowser

def playfile(fpath):
    fpath = pathlib.Path(fpath).expanduser().resolve()
    webbrowser.open('file://{}'.format(fpath))
```

1.  打开图像应该会显示它：

```py
>>> playfile('~/Pictures/avatar.jpg')
```

1.  此外，打开音频文件应该会播放它：

```py
>>> playfile('~/Music/FLY_ME_TO_THE_MOON.mp3')
```

因此，我们可以在大多数系统上使用这种方法来向用户显示文件的内容。

# 它是如何工作的...

`webbrowser.open`函数实际上在 Linux 系统上启动浏览器，但在 macOS 和 Windows 系统上，它的工作方式有所不同。

在 Windows 和 macOS 系统上，它将要求系统使用最合适的应用程序打开指定的路径。

如果路径是 HTTP URL，则最合适的应用程序当然是`webbrowser`，但如果路径是本地`file://` URL，则系统将寻找能够处理该文件类型并将文件打开的软件。

这是通过在 Windows 系统上使用`os.startfile`，并通过`osascript`命令在 macOS 上运行一个小的 Apple 脚本片段来实现的。

这使我们能够打开图像和音频文件，由于大多数图像和音频文件格式也受到浏览器支持，因此它也可以在 Linux 系统上运行。


# 第十三章：图形用户界面

在本章中，我们将涵盖以下配方：

+   警报-在图形系统上显示警报对话框

+   对话框-如何使用对话框询问简单问题

+   ProgressBar 对话框-如何提供图形进度对话框

+   列表-如何实现可滚动的元素列表以供选择

+   菜单-如何在 GUI 应用程序中创建菜单以允许多个操作

# 介绍

Python 带有一个编程语言很少提供的功能：内置的**图形用户界面**（**GUI**）库。

Python 附带了一个可通过标准库提供的`tkinter`模块控制的`Tk`小部件工具包的工作版本。

`Tk`工具包实际上是通过一种称为`Tcl`的简单语言使用的。所有`Tk`小部件都可以通过`Tcl`命令进行控制。

大多数这些命令都非常简单，采用以下形式：

```py
classname widgetid options
```

例如，以下内容会导致一个按钮（标识为`mybutton`）上有红色的“点击这里”文本：

```py
button .mybutton -fg red  -text "click here"
```

由于这些命令通常相对简单，Python 附带了一个内置的`Tcl`解释器，并使用它来驱动`Tk`小部件。

如今，几乎每个人，甚至更加专注的计算机用户，都习惯于依赖 GUI 来完成他们的许多任务，特别是对于需要基本交互的简单应用程序，例如选择选项，确认输入或显示一些进度。因此，使用 GUI 可能非常方便。

对于图形应用程序，用户通常无需查看应用程序的帮助页面，阅读文档并浏览应用程序提供的选项以了解其特定的语法。 GUI 已经提供了几十年的一致交互语言，如果正确使用，是保持软件入门门槛低的好方法。

由于 Python 提供了创建强大的控制台应用程序和良好的 GUI 所需的一切，因此下次您需要创建新工具时，如果您选择图形应用程序，也许停下来考虑一下您的用户会发现什么更方便，前往`tkinter`可能是一个不错的选择。

虽然`tkinter`与强大的工具包（如 Qt 或 GTK）相比可能有限，但它确实是一个完全独立于平台的解决方案，对于大多数应用程序来说已经足够好了。

# 警报

最简单的 GUI 类型是警报。只需在图形框中打印一些内容以通知用户结果或事件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/mod-py-stlib-cb/img/ca5ecdd4-5d78-49d5-a9d8-50c84ff5b921.png)

# 如何做...

`tkinter`中的警报由`messagebox`对象管理，我们可以通过要求`messagebox`为我们显示一个来创建一个：

```py
from tkinter import messagebox

def alert(title, message, kind='info', hidemain=True):
    if kind not in ('error', 'warning', 'info'):
        raise ValueError('Unsupported alert kind.')

    show_method = getattr(messagebox, 'show{}'.format(kind))
    show_method(title, message)
```

一旦我们有了`alert`助手，我们可以初始化`Tk`解释器并显示我们想要的多个警报：

```py
from tkinter import Tk

Tk().withdraw()
alert('Hello', 'Hello World')
alert('Hello Again', 'Hello World 2', kind='warning')
```

如果一切按预期工作，我们应该看到一个弹出对话框，一旦解除，新的对话框应该出现“再见”。

# 工作原理...

`alert`函数本身只是`tkinter.messagebox`提供的一个薄包装。

我们可以显示三种类型的消息框：`error`，`warning`和`info`。如果请求了不支持的对话框类型，我们会拒绝它：

```py
if kind not in ('error', 'warning', 'info'):
    raise ValueError('Unsupported alert kind.')
```

每种对话框都是通过依赖`messagebox`的不同方法来显示的。信息框使用`messagebox.showinfo`显示，而错误使用`messagebox.showerror`显示，依此类推。

因此，我们获取`messagebox`的相关方法：

```py
show_method = getattr(messagebox, 'show{}'.format(kind))
```

然后，我们调用它来显示我们的框：

```py
show_method(title, message)
```

`alert`函数非常简单，但还有一件事情我们需要记住。

`tkinter`库通过与`Tk`的解释器和环境交互来工作，必须创建和启动它。

如果我们自己不开始，`tkinter`需要在需要发送一些命令时立即为我们启动一个。但是，这会导致始终创建一个空的主窗口。

因此，如果您像这样使用`alert`，您将收到警报，但您也会在屏幕角落看到空窗口。

为了避免这种情况，我们需要自己初始化`Tk`环境并禁用主窗口，因为我们对它没有任何用处：

```py
from tkinter import Tk
Tk().withdraw()
```

然后我们可以显示任意数量的警报，而不会出现在屏幕周围泄漏空的不需要的窗口的风险。

# 对话框

对话框是用户界面可以提供的最简单和最常见的交互。询问一个简单的输入，比如数字、文本或是是/否，可以满足简单应用程序与用户交互的许多需求。

`tkinter`提供了大多数情况下的对话框，但如果你不知道这个库，可能很难找到它们。作为一个指针，`tkinter`提供的所有对话框都有非常相似的签名，因此很容易创建一个`dialog`函数来显示它们：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/mod-py-stlib-cb/img/f0d43442-8643-4db8-a0bc-86a03b14bcdf.png)

对话框将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/mod-py-stlib-cb/img/28197129-73c7-41d8-ab0b-85af9edb584b.png)

打开文件的窗口如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/mod-py-stlib-cb/img/04fb7778-7b6f-42c7-8c77-b323c93b81e0.png)

# 如何做...

我们可以创建一个`dialog`函数来隐藏对话框类型之间的细微差异，并根据请求的类型调用适当的对话框：

```py
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import filedialog

def dialog(ask, title, message=None, **kwargs):
    for widget in (messagebox, simpledialog, filedialog):
        show = getattr(widget, 'ask{}'.format(ask), None)
        if show:
            break
    else:
        raise ValueError('Unsupported type of dialog: {}'.format(ask))

    options = dict(kwargs, title=title)
    for arg, replacement in dialog._argsmap.get(widget, {}).items():
        options[replacement] = locals()[arg]
    return show(**options)
dialog._argsmap = {
    messagebox: {'message': 'message'},
    simpledialog: {'message': 'prompt'}
}
```

然后我们可以测试我们的`dialog`方法来显示所有可能的对话框类型，并显示用户的选择：

```py
>>> from tkinter import Tk

>>> Tk().withdraw()
>>> for ask in ('okcancel', 'retrycancel', 'yesno', 'yesnocancel',
...             'string', 'integer', 'float', 'directory', 'openfilename'):
...     choice = dialog(ask, 'This is title', 'What?')
...     print('{}: {}'.format(ask, choice))
okcancel: True
retrycancel: False
yesno: True
yesnocancel: None
string: Hello World
integer: 5
float: 1.3
directory: /Users/amol/Documents
openfilename: /Users/amol/Documents/FileZilla_3.27.1_macosx-x86.app.tar.bz2
```

# 它是如何工作的...

`tkinter`提供的对话框类型分为`messagebox`、`simpledialog`和`filedialog`模块（你可能也考虑`colorchooser`，但它很少需要）。

因此，根据用户想要的对话框类型，我们需要选择正确的模块并调用所需的函数来显示它：

```py
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import filedialog

def dialog(ask, title, message=None, **kwargs):
    for widget in (messagebox, simpledialog, filedialog):
        show = getattr(widget, 'ask{}'.format(ask), None)
        if show:
            break
    else:
        raise ValueError('Unsupported type of dialog: {}'.format(ask))
```

如果没有模块公开函数来显示请求的对话框类型（所有函数都以`ask*`命名），循环将在没有打破的情况下结束，因此将进入`else`子句，引发异常以通知调用者请求的类型不可用。

如果循环以`break`退出，`widget`变量将指向能够显示请求的对话框的模块，而`show`变量将导致实际能够显示它的函数。

一旦我们有了正确的函数，我们需要考虑各种对话框函数之间的细微差异。

主要的问题与`messagebox`对话框有一个`message`参数有关，而`simpledialog`对话框有一个提示参数来显示用户的消息。`filedialog`根本不需要任何消息。

这是通过创建一个基本的选项字典和自定义提供的选项以及`title`选项来完成的，因为在所有类型的对话框中始终可用：

```py
options = dict(kwargs, title=title)
```

然后，通过查找`dialog._argsmap`字典中从`dialog`参数的名称到预期参数的映射，将`message`选项替换为正确的名称（或跳过）。

例如，在`simpledialog`的情况下，使用`{'message': 'prompt'}`映射。`message`变量在函数局部变量中查找（`locals()[arg]`），然后将其分配给选项字典，`prompt`名称由`replacement`指定。然后，最终调用分配给`show`的函数来显示对话框：

```py
for arg, replacement in dialog._argsmap.get(widget, {}).items():
    options[replacement] = locals()[arg]
return show(**options)

dialog._argsmap = {
    messagebox: {'message': 'message'}, 
    simpledialog: {'message': 'prompt'}
}
```

# 进度条对话框

在进行长时间运行的操作时，向用户显示进度的最常见方式是通过进度条。

在线程中运行操作时，我们可以更新进度条以显示操作正在向前推进，并向用户提示可能需要完成工作的时间：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/mod-py-stlib-cb/img/e0ec92d1-34a2-46f5-92e1-6616f7d96c3f.png)

# 如何做...

`simpledialog.SimpleDialog`小部件用于创建带有一些文本和按钮的简单对话框。我们将利用它来显示进度条而不是按钮：

```py
import tkinter
from tkinter import simpledialog
from tkinter import ttk

from queue import Queue

class ProgressDialog(simpledialog.SimpleDialog):
    def __init__(self, master, text='', title=None, class_=None):
        super().__init__(master=master, text=text, title=title, 
                         class_=class_)
        self.default = None
        self.cancel = None

        self._bar = ttk.Progressbar(self.root, orient="horizontal", 
                                    length=200, mode="determinate")
        self._bar.pack(expand=True, fill=tkinter.X, side=tkinter.BOTTOM)
        self.root.attributes("-topmost", True)

        self._queue = Queue()
        self.root.after(200, self._update)

    def set_progress(self, value):
        self._queue.put(value)

    def _update(self):
        while self._queue.qsize():
            try:
                self._bar['value'] = self._queue.get(0)
            except Queue.Empty:
                pass
        self.root.after(200, self._update)
```

然后可以创建`ProgressDialog`，并使用后台线程让操作进展（比如下载），然后在我们的操作向前推进时更新进度条：

```py
if __name__ == '__main__':
    root = tkinter.Tk()
    root.withdraw()

    # Prepare the progress dialog
    p = ProgressDialog(master=root, text='Downloading Something...',
                    title='Download')

    # Simulate a download running for 5 seconds in background
    import threading
    def _do_progress():
        import time
        for i in range(1, 11):
            time.sleep(0.5)
            p.set_progress(i*10)
        p.done(0)
    t = threading.Thread(target=_do_progress)
    t.start()

    # Display the dialog and wait for the download to finish.
    p.go()
    print('Download Completed!')
```

# 它是如何工作的...

我们的对话框本身主要基于`simpledialog.SimpleDialog`小部件。我们创建它，然后设置`self.default = None`以防止用户能够通过按`<Return>`键关闭对话框，并且我们还设置`self.default = None`以防止用户通过按窗口上的按钮关闭对话框。我们希望对话框保持打开状态，直到完成为止：

```py
class ProgressDialog(simpledialog.SimpleDialog):
    def __init__(self, master, text='', title=None, class_=None):
        super().__init__(master=master, text=text, title=title, class_=class_)
        self.default = None
        self.cancel = None
```

然后我们实际上需要进度条本身，它将显示在文本消息下方，并且我们还将对话框移到前面，因为我们希望用户意识到正在发生某事：

```py
self._bar = ttk.Progressbar(self.root, orient="horizontal", 
                            length=200, mode="determinate")
self._bar.pack(expand=True, fill=tkinter.X, side=tkinter.BOTTOM)
self.root.attributes("-topmost", True)
```

在最后一部分，我们需要安排`self._update`，它将继续循环，直到对话框停止更新进度条，如果`self._queue`中有新的进度值可用。进度值可以通过`self._queue`提供，我们将在通过`set_progress`方法提供新的进度值时插入新的进度值：

```py
self._queue = Queue()
self.root.after(200, self._update)
```

我们需要通过`Queue`进行，因为具有进度条更新的对话框会阻塞整个程序。

当`Tkinter mainloop`函数运行时（由`simpledialog.SimpleDialog.go()`调用），没有其他东西可以继续进行。

因此，UI 和下载必须在两个不同的线程中进行，并且由于我们无法从不同的线程更新 UI，因此必须从生成它们的线程将进度值发送到将其消耗以更新进度条的 UI 线程。

执行操作并生成进度更新的线程可以通过`set_progress`方法将这些进度更新发送到 UI 线程：

```py
def set_progress(self, value):
    self._queue.put(value)
```

另一方面，UI 线程将不断调用`self._update`方法（每 200 毫秒一次），以检查`self._queue`中是否有更新请求，然后应用它：

```py
def _update(self):
    while self._queue.qsize():
        try:
            self._bar['value'] = self._queue.get(0)
        except Queue.Empty:
            pass
    self.root.after(200, self._update)
```

在更新结束时，该方法将重新安排自己：

```py
self.root.after(200, self._update)
```

这样，我们将永远继续每 200 毫秒检查进度条是否有更新，直到`self.root mainloop`退出。

为了使用`ProgressDialog`，我们模拟了一个需要 5 秒钟的下载。这是通过创建对话框本身完成的：

```py
if __name__ == '__main__':
    root = tkinter.Tk()
    root.withdraw()

    # Prepare the progress dialog
    p = ProgressDialog(master=root, text='Downloading Something...',
                    title='Download')
```

然后我们启动了一个后台线程，持续 5 秒，每隔半秒更新一次进度：

```py
# Simulate a download running for 5 seconds in background
import threading

def _do_progress():
    import time
    for i in range(1, 11):
        time.sleep(0.5)
        p.set_progress(i*10)
    p.done(0)

t = threading.Thread(target=_do_progress)
t.start()
```

更新发生是因为线程调用`p.set_progress`，它将在队列中设置一个新的进度值，向 UI 线程发出新的进度值设置信号。

一旦下载完成，进度对话框将通过`p.done(0)`退出。

一旦我们的下载线程就位，我们就可以显示进度对话框并等待其退出：

```py
# Display the dialog and wait for the download to finish.
p.go()
print('Download Completed!')
```

# 列表

当用户有两个以上的选择时，最好的列出它们的方式是通过列表。`tkinter`模块提供了一个`ListBox`，允许我们在可滚动的小部件中显示一组条目供用户选择。

我们可以使用它来实现一个对话框，用户可以从中选择许多选项并抓取所选项：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/mod-py-stlib-cb/img/3d954334-8b5f-4610-b619-ac1f212250db.png)

# 如何做...

`simpledialog.Dialog`类可用于实现简单的确定/取消对话框，并允许我们提供具有自定义内容的对话框主体。

我们可以使用它向对话框添加消息和列表，并让用户进行选择：

```py
import tkinter
from tkinter import simpledialog

class ChoiceDialog(simpledialog.Dialog):
    def __init__(self, parent, title, text, items):
        self.selection = None
        self._items = items
        self._text = text
        super().__init__(parent, title=title)

    def body(self, parent):
        self._message = tkinter.Message(parent, text=self._text, aspect=400)
        self._message.pack(expand=1, fill=tkinter.BOTH)
        self._list = tkinter.Listbox(parent)
        self._list.pack(expand=1, fill=tkinter.BOTH, side=tkinter.TOP)
        for item in self._items:
            self._list.insert(tkinter.END, item)
        return self._list

    def validate(self):
        if not self._list.curselection():
            return 0
        return 1

    def apply(self):
        self.selection = self._items[self._list.curselection()[0]]
```

一旦有了`ChoiceDialog`，我们可以显示它并提供一个项目列表，让用户选择一个或取消对话框：

```py
if __name__ == '__main__':
    tk = tkinter.Tk()
    tk.withdraw()

    dialog = ChoiceDialog(tk, 'Pick one',
                        text='Please, pick a choice?',
                        items=['first', 'second', 'third'])
    print('Selected "{}"'.format(dialog.selection))
```

`ChoiceDialog.selection`属性将始终包含所选项目，如果对话框被取消，则为`None`。

# 它是如何工作的...

`simpledialog.Dialog`默认创建一个带有`确定`和`取消`按钮的对话框，并且只提供一个标题。

在我们的情况下，除了创建对话框本身之外，我们还希望保留对话框的消息和可供选择的项目，以便我们可以向用户显示它们。此外，默认情况下，我们希望设置尚未选择任何项目。最后，我们可以调用`simpledialog.Dialog.__init__`，一旦调用它，主线程将阻塞，直到对话框被解除：

```py
import tkinter
from tkinter import simpledialog

class ChoiceDialog(simpledialog.Dialog):
    def __init__(self, parent, title, text, items):
        self.selection = None
        self._items = items
        self._text = text
        super().__init__(parent, title=title)
```

我们可以通过重写`simpledialog.Dialog.body`方法来添加任何其他内容。这个方法可以将更多的小部件添加为对话框主体的子级，并且可以返回应该具有焦点的特定小部件：

```py
def body(self, parent):
    self._message = tkinter.Message(parent, text=self._text, aspect=400)
    self._message.pack(expand=1, fill=tkinter.BOTH)
    self._list = tkinter.Listbox(parent)
    self._list.pack(expand=1, fill=tkinter.BOTH, side=tkinter.TOP)
    for item in self._items:
        self._list.insert(tkinter.END, item)
    return self._list
```

`body`方法是在`simpledialog.Dialog.__init__`中创建的，因此在阻塞主线程之前调用它。

对话框的内容放置好后，对话框将阻塞等待用户点击按钮。

如果点击`cancel`按钮，则对话框将自动关闭，`ChoiceDialog.selection`将保持为`None`。

如果点击`Ok`，则调用`ChoiceDialog.validate`方法来检查选择是否有效。我们的`validate`实现将检查用户在点击`Ok`之前是否实际选择了条目，并且只有在有选定项目时才允许用户关闭对话框：

```py
def validate(self):
    if not self._list.curselection():
        return 0
    return 1
```

如果验证通过，将调用`ChoiceDialog.apply`方法来确认选择，然后我们只需在`self.selection`中设置所选项目的名称，这样一旦对话框不再可见，调用者就可以访问它了：

```py
def apply(self):
    self.selection = self._items[self._list.curselection()[0]]
```

这使得可以显示对话框并在其关闭后从`selection`属性中读取所选值成为可能：

```py
dialog = ChoiceDialog(tk, 'Pick one',
                    text='Please, pick a choice?',
                    items=['first', 'second', 'third'])
print('Selected "{}"'.format(dialog.selection))
```

# 菜单

当应用程序允许执行多个操作时，菜单通常是允许访问这些操作的最常见方式：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/mod-py-stlib-cb/img/ca3d5d42-6626-40f4-925f-c9ef2ff3a557.png)

# 如何做...

`tkinter.Menu`类允许我们创建菜单、子菜单、操作和分隔符。因此，它提供了我们在基于 GUI 的应用程序中创建基本菜单所需的一切：

```py
import tkinter

def set_menu(window, choices):
    menubar = tkinter.Menu(root)
    window.config(menu=menubar)

    def _set_choices(menu, choices):
        for label, command in choices.items():
            if isinstance(command, dict):
                # Submenu
                submenu = tkinter.Menu(menu)
                menu.add_cascade(label=label, menu=submenu)
                _set_choices(submenu, command)
            elif label == '-' and command == '-':
                # Separator
                menu.add_separator()
            else:
                # Simple choice
                menu.add_command(label=label, command=command)

    _set_choices(menubar, choices)
```

`set_menu`函数允许我们轻松地从嵌套的操作和子菜单的字典中创建整个菜单层次结构：

```py
import sys
root = tkinter.Tk()

from collections import OrderedDict
set_menu(root, {
    'File': OrderedDict([
        ('Open', lambda: print('Open!')),
        ('Save', lambda: print('Save')),
        ('-', '-'),
        ('Quit', lambda: sys.exit(0))
    ])
})
root.mainloop()
```

如果您使用的是 Python 3.6+，还可以避免使用`OrderedDict`，而是使用普通字典，因为字典已经是有序的。

# 它是如何工作的...

提供一个窗口，`set_menu`函数创建一个`Menu`对象并将其设置为窗口菜单：

```py
def set_menu(window, choices):
    menubar = tkinter.Menu(root)
    window.config(menu=menubar)
```

然后，它使用通过`choices`参数提供的选择填充菜单。这个参数预期是一个字典，其中键是菜单条目的名称，值是在选择时应调用的可调用对象，或者如果选择应导致子菜单，则是另一个字典。最后，当标签和选择都设置为`-`时，它支持分隔符。

菜单通过递归函数遍历选项树来填充，该函数调用`Menu.add_command`、`Menu.add_cascade`和`Menu.add_separator`，具体取决于遇到的条目：

```py
def _set_choices(menu, choices):
    for label, command in choices.items():
        if isinstance(command, dict):
            # Submenu
            submenu = tkinter.Menu(menu)
            menu.add_cascade(label=label, menu=submenu)
            _set_choices(submenu, command)
        elif label == '-' and command == '-':
            # Separator
            menu.add_separator()
        else:
            # Simple choice
            menu.add_command(label=label, command=command)

_set_choices(menubar, choices)
```


# 第十四章：开发工具

在本章中，我们将介绍以下内容：

+   调试-如何利用 Python 内置调试器

+   测试-使用 Python 标准库测试框架编写测试套件

+   模拟-在测试中修补对象以模拟虚假行为

+   在生产中报告错误-通过电子邮件报告崩溃

+   基准测试-如何使用标准库对函数进行基准测试

+   检查-检查对象提供的类型、属性和方法

+   代码评估-在 Python 代码中运行 Python 代码

+   跟踪-如何跟踪执行了哪些代码行

+   性能分析-如何跟踪代码中的瓶颈

# 介绍

在编写软件时，您需要工具来更轻松地实现目标，以及帮助您管理代码库的复杂性，代码库可能包含数百万行代码，并且可能涉及您不熟悉的其他人的代码。

即使是对于小型项目，如果涉及第三方库、框架和工具，实际上是将其他人的代码引入到自己的代码中，您将需要一套工具来理解在依赖于此代码时发生了什么，并且保持自己的代码受控并且没有错误。

在这里，诸如测试、调试、性能分析和跟踪等技术可以派上用场，以验证代码库，了解发生了什么，发现瓶颈，并查看执行了什么以及何时执行。

Python 标准库提供了许多您在日常开发中需要实现大多数最佳实践和软件开发技术的工具。

# 调试

在开发过程中，您可能会遇到代码的意外行为或崩溃，并且希望深入了解，查看变量的状态，并检查发生了什么，以了解如何处理意外情况，以便软件能够正常运行。

这通常是调试的一部分，通常需要专用工具、调试器，以使您的生活更轻松（是否曾经发现自己在代码中到处添加`print`语句，只是为了查看某个变量的值？）。

Python 标准库提供了一个非常强大的调试器，虽然存在其他第三方解决方案，但内部的`pdb`调试器非常强大，并且能够在几乎所有情况下帮助您。

# 如何做...

如果您想在特定点停止代码执行，并在交互式地向前移动，同时检查变量如何变化以及执行的流程，您只需设置一个跟踪点，然后您将进入一个交互式会话，在那里您的代码正在运行：

```py
def divide(x, y):
    print('Going to divide {} / {}'.format(x, y))

    # Stop execution here and enter the debugger
    import pdb; pdb.set_trace()

    return x / y
```

现在，如果我们调用`divide`函数，我们将进入一个交互式调试器，让我们看到`x`和`y`的值，并继续执行：

```py
>>> print(divide(3, 2))
Going to divide 3 / 2
> ../sources/devtools/devtools_01.py(4)divide()
-> return x / y
(Pdb) x
3
(Pdb) y
2
(Pdb) continue
1.5
```

# 它是如何工作的...

`pdb`模块公开了一个`set_trace`函数，当调用时，会停止执行并进入交互式调试器。

从这里开始，您的提示将更改（为`Pdb`），您可以向调试器发送命令，或者只需写出变量名称即可打印变量值。

`pdb`调试器有许多命令；最有用的命令如下：

+   `next`：逐行执行代码

+   `continue`：继续执行代码，直到达到下一个断点

+   `list`：打印当前正在执行的代码

要查看完整的命令列表，您可以使用`help`命令，它将列出所有可用的命令。您还可以使用`help`命令获取有关特定命令的帮助。

# 还有更多...

自 Python 3.7 版本以来，不再需要进行奇怪的`import pdb`；`pdb.set_trace()`操作。您只需编写`breakpoint()`，就会进入`pdb`。

更好的是，如果您的系统配置了更高级的调试器，您将依赖于这些调试器，因为`breakpoint()`使用当前配置的调试器，而不仅仅依赖于`pdb`。

# 测试

为了确保您的代码正确，并且不会在将来的更改中出现问题，编写测试通常是您可以做的最好的事情之一。

在 Python 中，有一些框架可以实现自动验证代码可靠性的测试套件，实现不同的模式，比如**行为驱动开发**（**BDD**），甚至可以自动为您找到边界情况。

但是，只需依赖标准库本身就可以编写简单的自动测试，因此只有在需要特定插件或模式时才需要第三方测试框架。

标准库有`unittest`模块，它允许我们为我们的软件编写测试，运行它们，并报告测试套件的状态。

# 如何做...

对于这个配方，需要执行以下步骤：

1.  假设我们有一个`divide`函数，我们想为它编写测试：

```py
def divide(x, y):
    return x / y
```

1.  我们需要创建一个名为`test_divide.py`的文件（包含测试的文件必须命名为`test_*.py`，否则测试将无法运行）。在`test_divide.py`文件中，我们可以放置所有的测试：

```py
from divide import divide
import unittest

class TestDivision(unittest.TestCase):
    def setUp(self):
        self.num = 6

    def test_int_division(self):
        res = divide(self.num, 3)
        self.assertEqual(res, 2)

    def test_float_division(self):
        res = divide(self.num, 4)
        self.assertEqual(res, 1.5)

    def test_divide_zero(self):
        with self.assertRaises(ZeroDivisionError) as err:
            res = divide(self.num, 0)
        self.assertEqual(str(err.exception), 'division by zero')
```

1.  然后，假设`test_divide.py`模块在同一个目录中，我们可以用`python -m unittest`来运行我们的测试：

```py
$ python -m unittest
...
------------------------------------------------------------------
Ran 3 tests in 0.000s

OK
```

1.  如果我们还想看到哪些测试正在运行，我们也可以提供`-v`选项：

```py
$ python -m unittest -v
test_divide_zero (test_devtools_02.TestDivision) ... ok
test_float_division (test_devtools_02.TestDivision) ... ok
test_int_division (test_devtools_02.TestDivision) ... ok

----------------------------------------------------------------------
Ran 3 tests in 0.000s

OK
```

# 它是如何工作的...

`unittest`模块提供了两个主要功能：

+   `unittest.TestCase`类提供了编写测试和固定的基础

+   `unittest.TestLoader`类提供了从多个来源找到并运行多个测试的基础，一次运行；然后可以将结果提供给运行器来运行它们所有并报告它们的进度。

通过创建一个`unittest.TestCase`类，我们可以在相同的固定集下收集多个测试，这些固定集由类作为`setUp`和`setUpClass`方法提供。`setUpClass`方法对整个类执行一次，而`setUp`方法对每个测试执行一次。测试是所有名称以`test*`开头的类方法。

一旦测试完成，`tearDown`和`tearDownClass`方法可以用来清理状态。

因此，我们的`TestDivision`类将为其中声明的每个测试提供一个`self.num`属性：

```py
class TestDivision(unittest.TestCase):
    def setUp(self):
        self.num = 6
```

然后将有三个测试，其中两个（`test_int_division`和`test_float_division`）断言除法的结果是预期的（通过`self.assertEqual`）：

```py
def test_int_division(self):
    res = divide(self.num, 3)
    self.assertEqual(res, 2)

def test_float_division(self):
    res = divide(self.num, 4)
    self.assertEqual(res, 1.5)
```

然后，第三个测试（`test_divide_zero`）检查我们的`divide`函数在提供`0`作为除数时是否实际引发了预期的异常：

```py
def test_divide_zero(self):
    with self.assertRaises(ZeroDivisionError) as err:
        res = divide(self.num, 0)
    self.assertEqual(str(err.exception), 'division by zero')
```

然后检查异常消息是否也是预期的。

然后将这些测试保存在一个名为`test_divide.py`的文件中，以便`TestLoader`能够找到它们。

当执行`python -m unittest`时，实际发生的是调用了`TestLoader.discover`。这将查找本地目录中命名为`test*`的所有模块和包，并运行这些模块中声明的所有测试。

# 还有更多...

标准库`unittest`模块几乎提供了您为库或应用程序编写测试所需的一切。

但是，如果您发现需要更多功能，比如重试不稳定的测试、以更多格式报告和支持驱动浏览器，您可能想尝试像`pytest`这样的测试框架。这些通常提供了一个插件基础架构，允许您通过附加功能扩展它们的行为。

# Mocking

在测试代码时，您可能会面临替换现有函数或类的行为并跟踪函数是否被调用以及是否使用了正确的参数的需求。

例如，假设你有一个如下的函数：

```py
def print_division(x, y):
    print(x / y)
```

为了测试它，我们不想去屏幕上检查输出，但我们仍然想知道打印的值是否是预期的。

因此，一个可能的方法是用不打印任何东西的东西来替换`print`，但允许我们跟踪提供的参数（这是将要打印的值）。

这正是 mocking 的意思：用一个什么都不做但允许我们检查调用的对象或函数替换代码库中的对象或函数。

# 它是如何工作的...

您需要执行以下步骤来完成此操作：

1.  `unittest`包提供了一个`mock`模块，允许我们创建`Mock`对象和`patch`现有对象，因此我们可以依赖它来替换`print`的行为：

```py
from unittest import mock

with mock.patch('builtins.print') as mprint:
    print_division(4, 2)

mprint.assert_called_with(2)
```

1.  一旦我们知道模拟的`print`实际上是用`2`调用的，这是我们预期的值，我们甚至可以进一步打印它接收到的所有参数：

```py
mock_args, mock_kwargs = mprint.call_args
>>> print(mock_args)
(2, )
```

在这种情况下，这并不是很有帮助，因为只有一个参数，但在只想检查部分参数而不是整个调用的情况下，能够访问其中一些参数可能会很方便。

# 工作原理...

`mock.patch`在上下文中用`Mock`实例替换指定的对象或类。

`Mock`在被调用时不会执行任何操作，但会跟踪它们的参数，并允许您检查它们是否按预期被调用。

因此，通过`mock.patch`，我们用`Mock`替换`print`，并将`Mock`的引用保留为`mprint`：

```py
with mock.patch('builtins.print') as mprint:
    print_division(4, 2)
```

这使我们能够检查`print`是否通过`Mock`以预期的参数被调用：

```py
mprint.assert_called_with(2)
```

# 还有更多...

`Mock`对象实际上并不受限于什么都不做。

通过为`mock.patch`提供`side_effect`参数，您可以在调用时引发异常。这对于模拟代码中的故障非常有帮助。

或者，您甚至可以通过为`mock.patch`提供`new`来将它们的行为替换为完全不同的对象，这对于在实现的位置注入伪造对象非常有用。

因此，通常情况下，`unittest.mock`可以用来替换现有类和对象的行为，从模拟对象到伪造对象，再到不同的实现，都可以。

但是在使用它们时要注意，因为如果调用者保存了对原始对象的引用，`mock.patch`可能无法为其替换函数，因为它仍然受到 Python 是基于引用的语言这一事实的限制，如果您有一个对象的引用，第三方代码就无法轻松地劫持该引用。

因此，请务必在使用要打补丁的对象之前应用`mock.patch`，以减少对原始对象的引用风险。

# 在生产中报告错误

生产软件中最重要的一个方面是在发生错误时得到通知。由于我们不是软件本身的用户，所以只有在软件通知我们时（或者当为时已晚并且用户在抱怨时）才能知道出了什么问题。

基于 Python 标准库，我们可以轻松构建一个解决方案，以便在发生崩溃时通过电子邮件通知开发人员。

# 如何做...

`logging`模块有一种通过电子邮件报告异常的方法，因此我们可以设置一个记录器，并捕获异常以通过电子邮件记录它们：

```py
import logging
import logging.handlers
import functools

crashlogger = logging.getLogger('__crashes__')

def configure_crashreport(mailhost, fromaddr, toaddrs, subject, 
                        credentials, tls=False):
    if configure_crashreport._configured:
        return

    crashlogger.addHandler(
        logging.handlers.SMTPHandler(
            mailhost=mailhost,
            fromaddr=fromaddr,
            toaddrs=toaddrs,
            subject=subject,
            credentials=credentials,
            secure=tuple() if tls else None
        )
    )
    configure_crashreport._configured = True
configure_crashreport._configured = False

def crashreport(f):
    @functools.wraps(f)
    def _crashreport(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            crashlogger.exception(
                '{} crashed\n'.format(f.__name__)
            )
            raise
    return _crashreport
```

一旦这两个函数就位，我们可以配置`logging`，然后装饰我们的主代码入口点，以便代码库中的所有异常都通过电子邮件报告：

```py
@crashreport
def main():
    3 / 0

configure_crashreport(
    'your-smtp-host.com',
    'no-reply@your-smtp-host.com',
    'crashes_receiver@another-smtp-host.com',
    'Automatic Crash Report from TestApp',
    ('smtpserver_username', 'smtpserver_password'),
    tls=True
)

main()
```

# 工作原理...

`logging`模块能够向附加到记录器的任何处理程序发送消息，并且具有通过`.exception`显式记录崩溃的功能。

因此，我们解决方案的根本是用装饰器包装代码库的主函数，以捕获所有异常并调用记录器：

```py
def crashreport(f):
    @functools.wraps(f)
    def _crashreport(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            crashlogger.exception(
                '{} crashed\n'.format(f.__name__)
            )
            raise
    return _crashreport
```

`crashlogger.exception`方法将构建一个包含我们自定义文本的消息（报告装饰函数的名称）以及崩溃的回溯，并将其发送到关联的处理程序。

通过`configure_crashreport`方法，我们为`crashlogger`提供了自定义处理程序。然后处理程序通过电子邮件发送消息：

```py
def configure_crashreport(mailhost, fromaddr, toaddrs, subject, 
                        credentials, tls=False):
    if configure_crashreport._configured:
        return

    crashlogger.addHandler(
        logging.handlers.SMTPHandler(
            mailhost=mailhost,
            fromaddr=fromaddr,
            toaddrs=toaddrs,
            subject=subject,
            credentials=credentials,
            secure=tuple() if tls else None
        )
    )
    configure_crashreport._configured = True
configure_crashreport._configured = False
```

额外的`_configured`标志用作保护，以防止处理程序被添加两次。

然后我们只需调用`configure_crashreport`来提供电子邮件服务的凭据：

```py
configure_crashreport(
    'your-smtp-host.com',
    'no-reply@your-smtp-host.com',
    'crashes_receiver@another-smtp-host.com',
    'Automatic Crash Report from TestApp',
    ('smtpserver_username', 'smtpserver_password'),
    tls=True
)
```

并且函数中的所有异常都将在`crashlogger`中记录，并通过关联的处理程序发送电子邮件。

# 基准测试

在编写软件时，通常需要确保某些性能约束得到保证。标准库中有大部分我们编写的函数的时间和资源消耗的工具。

假设我们有两个函数，我们想知道哪一个更快：

```py
def function1():
    l = []
    for i in range(100):
        l.append(i)
    return l

def function2():
    return [i for i in range(100)]
```

# 如何做...

`timeit`模块提供了一堆实用程序来计时函数或整个脚本：

```py
>>> import timeit

>>> print(
...     timeit.timeit(function1)
... )
10.132873182068579

>>> print(
...     timeit.timeit(function2)
... )
5.13165780401323
```

从报告的时间中，我们知道`function2`比`function1`快两倍。

# 还有更多...

通常，这样的函数会在几毫秒内运行，但报告的时间是以秒为单位的。

这是因为，默认情况下，`timeit.timeit`将运行被基准测试的代码 100 万次，以提供一个结果，其中执行速度的任何临时变化都不会对最终结果产生太大影响。

# 检查

作为一种强大的动态语言，Python 允许我们根据它正在处理的对象的状态来改变其运行时行为。

检查对象的状态是每种动态语言的基础，标准库`inspect`模块具有大部分这种情况所需的功能。

# 如何做...

对于这个示例，需要执行以下步骤：

1.  基于`inspect`模块，我们可以快速创建一个辅助函数，它将告诉我们大多数对象的主要属性和类型：

```py
import inspect

def inspect_object(o):
    if inspect.isfunction(o) or inspect.ismethod(o):
        print('FUNCTION, arguments:', inspect.signature(o))
    elif inspect.isclass(o):
        print('CLASS, methods:', 
              inspect.getmembers(o, inspect.isfunction))
    else:
        print('OBJECT ({}): {}'.format(
            o.__class__, 
            [(n, v) for n, v in inspect.getmembers(o) 
                if not n.startswith('__')]
        ))
```

1.  然后，如果我们将其应用于任何对象，我们将获得有关其类型、属性、方法的详细信息，如果它是一个函数，还有关其参数。我们甚至可以创建一个自定义类型：

```py
class MyClass:
    def __init__(self):
        self.value = 5

    def sum_to_value(self, other):
        return self.value + other
```

1.  我们检查它的方法：

```py
>>> inspect_object(MyClass.sum_to_value)
FUNCTION, arguments: (self, other)
```

该类型的一个实例：

```py
>>> o = MyClass()
>>> inspect_object(o)
OBJECT (<class '__main__.MyClass'>): [
    ('sum_to_value', <bound method MyClass.sum_to_value of ...>), 
    ('value', 5)
]
```

或者类本身：

```py
>>> inspect_object(MyClass)
CLASS, methods: [
    ('__init__', <function MyClass.__init__ at 0x107bd0400>), 
    ('sum_to_value', <function MyClass.sum_to_value at 0x107bd0488>)
]
```

# 它是如何工作的...

`inspect_object`依赖于`inspect.isfunction`、`inspect.ismethod`和`inspect.isclass`来决定提供的参数的类型。

一旦清楚提供的对象适合其中一种类型，它就会为该类型的对象提供更合理的信息。

对于函数和方法，它查看函数的签名：

```py
if inspect.isfunction(o) or inspect.ismethod(o):
    print('FUNCTION, arguments:', inspect.signature(o))
```

`inspect.signature`函数返回一个包含给定方法接受的所有参数详细信息的`Signature`对象。

当打印时，这些参数会显示在屏幕上，这正是我们所期望的：

```py
FUNCTION, arguments: (self, other)
```

对于类，我们主要关注类公开的方法。因此，我们将使用`inspect.getmembers`来获取类的所有属性，然后使用`inspect.isfunction`来仅过滤函数：

```py
elif inspect.isclass(o):
    print('CLASS, methods:', inspect.getmembers(o, inspect.isfunction))
```

`inspect.getmembers`的第二个参数可以是任何谓词，用于过滤成员。

对于对象，我们想要显示对象的属性和方法。

对象通常有数十种方法，这些方法在 Python 中默认提供，以支持标准操作符和行为。这些就是所谓的魔术方法，我们通常不关心。因此，我们只需要列出公共方法和属性：

```py
else:
    print('OBJECT ({}): {}'.format(
        o.__class__, 
        [(n, v) for n, v in inspect.getmembers(o) 
            if not n.startswith('__')]
    ))
```

正如我们所知，`inspect.getmembers`接受一个谓词来过滤要返回的成员。但是谓词只能作用于成员本身；它无法知道它的名称。因此，我们必须使用列表推导来过滤`inspect.getmembers`的结果，删除任何名称以`dunder（__）`开头的属性。

结果是提供的对象的公共属性和方法：

```py
OBJECT (<class '__main__.MyClass'>): [
    ('sum_to_value', <bound method MyClass.sum_to_value of ...>), 
    ('value', 5)
]
```

我们还打印了对象本身的`__class__`，以提供关于我们正在查看的对象类型的提示。

# 还有更多...

`inspect`模块有数十个函数，可以用来深入了解 Python 对象。

在调查第三方代码或实现必须处理未知形状和类型的对象的高度动态代码时，它可以是一个非常强大的工具。

# 代码评估

Python 是一种解释性语言，解释器的功能也暴露在标准库中。

这意味着我们可以评估来自文件或文本源的表达式和语句，并让它们作为 Python 代码在 Python 代码本身中运行。

还可以以相当安全的方式评估代码，允许我们从表达式中创建对象，但阻止执行任何函数。

# 如何做...

本教程的步骤如下：

1.  `eval`、`exec` 和 `ast` 函数和模块提供了执行字符串代码所需的大部分机制：

```py
import ast

def run_python(code, mode='evalsafe'):
    if mode == 'evalsafe':
        return ast.literal_eval(code)
    elif mode == 'eval':
        return eval(compile(code, '', mode='eval'))
    elif mode == 'exec':
        return exec(compile(code, '', mode='exec'))
    else:
        raise ValueError('Unsupported execution model 
                         {}'.format(mode))
```

1.  `evalsafe` 模式中的 `run_python` 函数允许我们以安全的方式运行基本的 Python 表达式。这意味着我们可以根据它们的文字表示创建 Python 对象：

```py
>>> print(run_python('[1, 2, 3]'))
[1, 2, 3]
```

1.  我们不能运行函数或执行更高级的命令，比如索引：

```py
>>> print(run_python('[1, 2, 3][0]'))
[ ... ]
malformed node or string: <_ast.Subscript object at 0x10ee57ba8>
```

1.  如果我们想要运行这些，我们需要以不安全的方式 `eval`：

```py
>>> print(run_python('[1, 2, 3][0]', 'eval'))
1
```

1.  这是不鼓励的，因为它允许在当前解释器会话中执行恶意代码。但即使它允许更广泛的执行，它仍然不允许更复杂的语句，比如函数的定义：

```py
>>> print(run_python('''
... def x(): 
...     print("printing hello")
... x()
... ''', 'eval'))
[ ... ]
invalid syntax (, line 2)
```

1.  为了允许完整的 Python 支持，我们需要使用 `exec` 模式，这将允许执行所有 Python 代码，但不再返回表达式的结果（因为提供的代码可能根本不是表达式）：

```py
>>> print(run_python('''
... def x(): 
...     print("printing hello")
... x()
... ''', 'exec'))
printing hello
None
```

# 跟踪代码

`trace` 模块提供了一个强大且易于使用的工具，可以跟踪运行过程中执行了哪些代码行。

跟踪可以用于确保测试覆盖率，并查看我们的软件或第三方函数的行为。

# 如何做...

您需要执行以下步骤来完成此教程：

1.  我们可以实现一个函数，跟踪提供的函数的执行并返回执行的模块以及每个模块的行：

```py
import trace
import collections

def report_tracing(func, *args, **kwargs):
    outputs = collections.defaultdict(list)

    tracing = trace.Trace(trace=False)
    tracing.runfunc(func, *args, **kwargs)

    traced = collections.defaultdict(set)
    for filename, line in tracing.results().counts:
        traced[filename].add(line)

    for filename, tracedlines in traced.items():
        with open(filename) as f:
            for idx, fileline in enumerate(f, start=1):
                outputs[filename].append(
                  (idx, idx in tracedlines, fileline))
                )  
    return outputs
```

1.  然后，一旦我们有了跟踪，我们需要实际打印它，以便人类能够阅读。为此，我们将阅读每个被跟踪模块的源代码，并使用 `+` 标记打印它，该标记将指示哪些行被执行或未执行：

```py
def print_traced_execution(tracings):
    for filename, tracing in tracings.items():
        print(filename)
        for idx, executed, content in tracing:
            print('{:04d}{}  {}'.format(idx, 
                                        '+' if executed else ' ', 
                                        content),
                end='')
        print()
```

1.  给定任何函数，我们都可以看到在各种条件下执行的代码行：

```py
def function(should_print=False):
    a = 1
    b = 2
    if should_print:
        print('Usually does not execute!')
    return a + b
```

1.  首先，我们可以使用 `should_print=False` 打印函数的跟踪：

```py
>>> print_traced_execution(
...     report_tracing(function)
... )
devtools_08.py
0001   def function(should_print=False):
0002+      a = 1
0003+      b = 2
0004+      if should_print:
0005           print('Usually does not execute!')
0006+      return a + b
```

1.  然后我们可以检查 `should_print=True` 时会发生什么：

```py
>>> print_traced_execution(
...     report_tracing(function, True)
... )
Usually does not execute!
devtools_08.py
0001   def function(should_print=False):
0002+      a = 1
0003+      b = 2
0004+      if should_print:
0005+          print('Usually does not execute!')
0006+      return a + b
```

您可以看到行 `0005` 现在标记为 `+`，因为它被执行了。

# 工作原理...

`report_tracing` 函数实际上负责跟踪另一个函数的执行。

首先，由于执行是按模块进行的，它创建了 `defaultdict`，用于存储跟踪。键将是模块，值将是包含该模块每行信息的列表：

```py
def report_tracing(func, *args, **kwargs):
    outputs = collections.defaultdict(list)
```

然后，它创建了实际的跟踪机制。`trace=False` 选项特别重要，以避免在屏幕上打印跟踪。现在，我们希望将其保存在一边，而不是打印出来。

```py
tracing = trace.Trace(trace=False)
```

一旦跟踪器可用，我们就可以使用它来运行提供的函数并提供任何给定的参数：

```py
tracing.runfunc(func, *args, **kwargs)
```

跟踪的结果保存在跟踪器本身中，因此我们可以使用 `tracing.results()` 访问它。我们感兴趣的是代码行是否至少执行了一次，因此我们将寻找计数，并将每个执行的代码行添加到给定模块的执行代码行集合中：

```py
traced = collections.defaultdict(set)
for filename, line in tracing.results().counts:
    traced[filename].add(line)
```

`traced` 字典包含了给定模块实际执行的所有代码行。顺便说一句，它不包含任何关于未执行的代码行的详细信息。

到目前为止，我们只有行号，没有关于执行的代码行的其他细节。当然，我们也希望有代码行本身，并且希望有所有代码行，而不仅仅是执行的代码行，这样我们就可以打印出没有间隙的源代码。

这就是为什么 `report_tracing` 打开每个执行模块的源代码并读取其内容。对于每一行，它检查它是否在该模块的执行集合中，并存储一对元组，其中包含行号、一个布尔值，指示它是否被执行，以及行内容本身：

```py
for filename, tracedlines in traced.items():
    with open(filename) as f:
        for idx, fileline in enumerate(f, start=1):
            outputs[filename].append((idx, idx in tracedlines, fileline))
```

最后，结果字典包含了所有被执行的模块，以及它们的源代码，注释了关于行号和是否执行的详细信息：

```py
return outputs
```

`print_traced_execution`则更容易：它的唯一目的是获取我们收集的数据并将其打印到屏幕上，以便人类可以看到源代码和执行的内容。

该函数会迭代每个被跟踪的模块并打印`filename`模块：

```py
def print_traced_execution(tracings):
    for filename, tracing in tracings.items():
        print(filename)
```

然后，对于每个模块，它会迭代跟踪详细信息并打印行号（作为四位数，以便对任何行号最多到 9999 进行正确缩进），如果执行了该行，则打印一个`+`号，以及行内容本身：

```py
for idx, executed, content in tracing:
    print('{:04d}{}  {}'.format(idx, 
                                '+' if executed else ' ', 
                                content),
        end='')
print()
```

# 还有更多...

使用跟踪，您可以轻松地检查您编写的代码是否被测试执行。您只需将跟踪限制在您编写并感兴趣的模块上即可。

有一些第三方模块专门用于测试覆盖率报告；最广泛使用的可能是`coverage`模块，它支持最常见的测试框架，如`pytest`和`nose`。

# 性能分析

当您需要加快代码速度或了解瓶颈所在时，性能分析是最有效的技术之一。

Python 标准库提供了一个内置的分析器，用于跟踪每个函数的执行和时间，并允许您找出更昂贵或运行次数过多的函数，消耗了大部分执行时间。

# 如何做...

对于这个示例，需要执行以下步骤：

1.  我们可以选择任何要进行性能分析的函数（甚至可以是程序的主入口点）：

```py
import time

def slowfunc(goslow=False):
    l = []
    for i in range(100):
        l.append(i)
        if goslow:
            time.sleep(0.01)
    return l
```

1.  我们可以使用`cProfile`模块对其进行性能分析。

```py
from cProfile import Profile

profiler = Profile()
profiler.runcall(slowfunc, True)
profiler.print_stats()
```

1.  这将打印函数的时间以及分析函数调用的最慢函数：

```py
202 function calls in 1.183 seconds

Ordered by: standard name

ncalls  tottime  percall  cumtime  percall filename:lineno(function)
    1    0.002    0.002    1.183    1.183 devtools_09.py:3(slowfunc)
  100    1.181    0.012    1.181    0.012 {built-in method time.sleep}
  100    0.000    0.000    0.000    0.000 {method 'append' of 'list' objects}
```

# 它是如何工作的...

`cProfile.Profile`对象能够使用少量负载运行任何函数并收集执行统计信息。

`runcall`函数是实际运行函数并提供传递的参数的函数（在本例中，`True`作为第一个函数参数提供，这意味着`goslow=True`）：

```py
profiler = Profile()
profiler.runcall(slowfunc, True)
```

一旦收集到了性能分析数据，我们可以将其打印到屏幕上，以提供关于执行的详细信息：

```py
profiler.print_stats()
```

打印输出包括在调用期间执行的函数列表，每个函数所花费的总时间，每个调用中每个函数所花费的时间，以及调用的总次数：

```py
ncalls  tottime  percall  cumtime  percall filename:lineno(function)
    1    0.002    0.002    1.183    1.183 devtools_09.py:3(slowfunc)
  100    1.181    0.012    1.181    0.012 {built-in method time.sleep}
  ...
```

我们可以看到，`slowfunc`的主要瓶颈是`time.sleep`调用：它占用了总共`1.183`时间中的`1.181`。

我们可以尝试使用`goslow=False`调用`slowfunc`，并查看时间的变化：

```py
profiler.runcall(slowfunc, False)
profiler.print_stats()
```

而且，在这种情况下，我们看到整个函数运行时间为`0.000`而不是`1.183`，并且不再提到`time.sleep`：

```py
102 function calls in 0.000 seconds

Ordered by: standard name

ncalls  tottime  percall  cumtime  percall filename:lineno(function)
    1    0.000    0.000    0.000    0.000 devtools_09.py:3(slowfunc)
  100    0.000    0.000    0.000    0.000 {method 'append' of 'list' objects}
```
