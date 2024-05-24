# Python GUI 编程秘籍（三）

> 原文：[`zh.annas-archive.org/md5/de38d8b70825b858336fa5194110e245`](https://zh.annas-archive.org/md5/de38d8b70825b858336fa5194110e245)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：准备工作

注意

+   在 Python 中国际化文本字符串的最简单方法是将它们移动到一个单独的 Python 模块中，然后通过向该模块传递参数来选择在我们的 GUI 中显示的语言。

+   在本章中，我们将通过在标签、按钮、选项卡和其他小部件上显示文本来国际化我们的 GUI，使用不同的语言。

+   在不同语言中显示小部件文本

+   为国际化准备 GUI

+   如何以敏捷方式设计 GUI

+   在本章中，我们将国际化和测试我们的 Python GUI，包括以下配方：

+   设置调试监视

+   配置不同的调试输出级别

+   如何使用 Eclipse PyDev IDE 编写单元测试

+   如何做...

+   我们需要测试 GUI 代码吗？

# 介绍

注意

第八章。国际化和测试

我们正在将 GUI 与其显示的语言分开，这是一个面向对象的设计原则。

### 让我们改变我们以前的一行代码：

注意

使用单元测试创建健壮的 GUI

我们将这个新的 Python 模块导入到我们的主要 Python GUI 代码中，然后使用它。

# 我们将从简单开始，然后探讨如何在设计级别准备我们的 GUI 进行国际化。

让我们创建一个新的 Python 模块，并将其命名为`Resources.py`。接下来，让我们将我们的 GUI 标题的英文字符串移到这个模块中，然后将此模块导入到我们的 GUI 代码中。

将字符串硬编码到代码中从来都不是一个好主意，所以我们可以改进我们的代码的第一步是将所有在我们的 GUI 中可见的字符串分离到它们自己的 Python 模块中。这是国际化我们的 GUI 可见方面的开始。

## 一次性更改整个 GUI 语言

本地化 GUI

## 它是如何工作的...

在这个配方中，我们将开始通过将 Windows 标题从英语更改为另一种语言来国际化我们的 GUI。

由于“GUI”在其他语言中是相同的，我们将首先扩展该名称，以便我们可以看到我们更改的视觉效果。

根据我们传递给 I18N 类的语言，我们的 GUI 将显示为该语言。

```py
self.win.title("Python GUI")
```

虽然这种方法并不是高度推荐的，但根据在线搜索结果，根据您正在开发的应用程序的具体要求，这种方法可能仍然是最实用和最快速实现的。

```py
self.win.title("Python Graphical User Interface")
```

上述代码更改导致我们的 GUI 程序的以下标题：

运行上述代码会给我们带来以下国际化的结果：

### 这有效。

我们还将测试我们的 GUI 代码并编写单元测试，并探索单元测试在我们的开发工作中可以提供的价值，这将使我们达到*重构*我们的代码的最佳实践。

在本章中，我们将使用英语和德语来举例说明国际化我们的 Python GUI 的原则。

### 我们的新 Python 模块，包含国际化的字符串，现在看起来像这样：

由于这些单词很长，它们已经被缩写为使用单词的第一个字符，后面跟着第一个和最后一个字符之间的总字符数，然后是单词的最后一个字符。

如何做...

### 注意

因此，国际化变成了 I18N，本地化变成了 L10N。

我们还将本地化 GUI，这与国际化略有不同。

```py
Class I18N():
'''Internationalization'''
    def __init__(self, language):
        if    language == 'en': self.resourceLanguageEnglish()
        elif  language == 'de': self.resourceLanguageGerman()
        else: raise NotImplementedError('Unsupported language.')

    def resourceLanguageEnglish(self):
        self.title = "Python Graphical User Interface"

    def resourceLanguageGerman(self):
        self.title = 'Python Grafische Benutzeroberflaeche'
```

使用 Python 的 __main__ 部分创建自测试代码

```py
from B04829_Ch08_Resources import I18N
class OOP():
    def __init__(self): 
        self.win = tk.Tk()                # Create instance
        self.i18n = I18N('de')            # Select language
        self.win.title(self.i18n.title)   # Add a title
```

在不同语言中显示小部件文本

到：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_02.jpg)

## 我们将重用之前创建的 Python GUI。我们已经注释掉了一个创建 MySQL 选项卡的 Python 代码行，因为在本章中我们不与 MySQL 数据库交谈。

我们将 GUI 中的硬编码字符串分解为它们自己的单独模块。我们通过创建一个类来实现这一点，并在类的`__init__()`方法中，根据传入的语言参数选择我们的 GUI 将显示哪种语言。

当我们进行国际化时，我们将在一个步骤中进行这种积极的重构和语言翻译。

我们可以通过将国际化字符串分离到单独的文件中，可能是 XML 或其他格式，进一步模块化我们的代码。我们还可以从 MySQL 数据库中读取它们。

### 注意

这是一种“关注点分离”的编码方法，是面向对象编程的核心。

# 一次性更改整个 GUI 语言

在这个示例中，我们将通过将以前硬编码的英文字符串重构到一个单独的 Python 模块中，然后国际化这些字符串，一次性更改整个 GUI 显示名称。

这个示例表明，避免硬编码 GUI 显示的任何字符串，而是将 GUI 代码与 GUI 显示的文本分开，是一个很好的设计原则。

### 注意

以模块化的方式设计我们的 GUI 使得国际化变得更加容易。

## 准备工作

我们将继续使用上一个示例中开发的 GUI。在那个示例中，我们已经国际化了 GUI 的标题。

## 如何做...

为了国际化在我们的 GUI 小部件中显示的文本，我们必须将所有硬编码的字符串移到一个单独的 Python 模块中，这就是我们接下来要做的。

以前，我们的 GUI 显示的单词字符串分散在我们的 Python 代码中。

这是我们的 GUI 在没有 I18N 的情况下的样子。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_03.jpg)

每个小部件的每个字符串，包括我们的 GUI 的标题，选项卡控件名称等，都是硬编码的，并与创建 GUI 的代码混在一起。

### 注意

在 GUI 软件开发过程的设计阶段考虑如何最好地国际化我们的 GUI 是一个好主意。

以下是我们代码的摘录。

```py
WIDGET_LABEL = ' Widgets Frame '
class OOP():
    def __init__(self): 
        self.win = tk.Tk()              # Create instance
        self.win.title("Python GUI")    # Add a title

    # Radiobutton callback function
    def radCall(self):
        radSel=self.radVar.get()
        if   radSel == 0: self.monty2.configure(text='Blue')
        elif radSel == 1: self.monty2.configure(text='Gold')
        elif radSel == 2: self.monty2.configure(text='Red')
```

在这个示例中，我们正在国际化我们的 GUI 小部件中显示的所有字符串。我们不会国际化*输入*到我们的 GUI 中的文本，因为这取决于您 PC 上的本地设置。

以下是英文国际化字符串的代码：

```py
classI18N():
'''Internationalization'''

    def __init__(self, language):
        if   language == 'en': self.resourceLanguageEnglish()
        elif language == 'de': self.resourceLanguageGerman()
        else: raiseNotImplementedError('Unsupported language.')

    def resourceLanguageEnglish(self):
        self.title = "Python Graphical User Interface"

        self.file  = "File"
        self.new   = "New"
        self.exit  = "Exit"
        self.help  = "Help"
        self.about = "About"

        self.WIDGET_LABEL = ' Widgets Frame '

        self.disabled  = "Disabled"
        self.unChecked = "UnChecked"
        self.toggle    = "Toggle"

        # Radiobutton list
        self.colors   = ["Blue", "Gold", "Red"]
        self.colorsIn = ["in Blue", "in Gold", "in Red"]

        self.labelsFrame  = ' Labels within a Frame '
        self.chooseNumber = "Choose a number:"
        self.label2       = "Label 2"

        self.mgrFiles = ' Manage Files '

        self.browseTo = "Browse to File..."
        self.copyTo   = "Copy File To :   "
```

在我们的 Python GUI 模块中，所有以前硬编码的字符串现在都被我们新的 I18N 类的实例所取代，该类位于`Resources.py`模块中。

以下是我们重构后的`GUI.py`模块的示例：

```py
from B04829_Ch08_Resources import I18N

class OOP():
    def __init__(self): 
        self.win = tk.Tk()              # Create instance
        self.i18n = I18N('de')          # Select language
        self.win.title(self.i18n.title) # Add a title

    # Radiobutton callback function
    def radCall(self):
          radSel = self.radVar.get()
        if   radSel == 0: self.widgetFrame.configure(text=self.i18n.WIDGET_LABEL + self.i18n.colorsIn[0])
        elif radSel == 1: self.widgetFrame.configure(text=self.i18n.WIDGET_LABEL + self.i18n.colorsIn[1])
        elif radSel == 2: self.widgetFrame.configure(text=self.i18n.WIDGET_LABEL + self.i18n.colorsIn[2])
```

请注意，以前所有的硬编码的英文字符串都已被我们新的 I18N 类的实例调用所取代。

一个例子是`self.win.title(self.i18n.title)`。

这给了我们国际化 GUI 的能力。我们只需要使用相同的变量名，并通过传递参数来选择我们希望显示的语言。

我们也可以在 GUI 的一部分中实时更改语言，或者我们可以读取本地 PC 设置，并根据这些设置决定我们的 GUI 文本应该显示哪种语言。

现在，我们可以通过简单地填写相应的单词来实现对德语的翻译。

```py

class I18N():
    '''Internationalization'''
    def __init__(self, language):      
        if   language == 'en': self.resourceLanguageEnglish()
        elif language == 'de': self.resourceLanguageGerman()
        else: raise NotImplementedError('Unsupported language.')

def resourceLanguageGerman(self):
        self.file  = "Datei"
        self.new   = "Neu"
        self.exit  = "Schliessen"
        self.help  = "Hilfe"
        self.about = "Ueber"

        self.WIDGET_LABEL = ' Widgets Rahmen '

        self.disabled  = "Deaktiviert"
        self.unChecked = "NichtMarkiert"
        self.toggle    = "Markieren"

        # Radiobutton list
        self.colors   = ["Blau", "Gold", "Rot"]    
        self.colorsIn = ["in Blau", "in Gold", "in Rot"]  

        self.labelsFrame  = ' EtikettenimRahmen '
        self.chooseNumber = "WaehleeineNummer:"
        self.label2       = "Etikette 2"

        self.mgrFiles = ' DateienOrganisieren '

        self.browseTo = "WaehleeineDatei... "
        self.copyTo   = "KopiereDateizu :     "
```

在我们的 GUI 代码中，我们现在可以通过一行 Python 代码更改整个 GUI 显示语言。

```py
class OOP():
    def __init__(self): 
        self.win = tk.Tk()        # Create instance
        self.i18n = I18N('de')    # Pass in language
```

运行上述代码会创建以下国际化 GUI：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_04.jpg)

## 工作原理...

为了国际化我们的 GUI，我们将硬编码的字符串重构到一个单独的模块中，然后通过将字符串作为我们的 I18N 类的初始化器的参数来使用相同的类成员来国际化我们的 GUI，从而有效地控制我们的 GUI 显示的语言。

# 本地化 GUI

在国际化我们的 GUI 的第一步之后，下一步是本地化。我们为什么要这样做呢？

嗯，在美利坚合众国，我们都是牛仔，我们生活在不同的时区。

因此，虽然我们在美国“国际化”，但我们的马在不同的时区醒来（并且期望根据它们自己的内部马时区时间表被喂食）。

这就是本地化的作用。

## 准备工作

我们正在通过本地化扩展我们在上一个示例中开发的 GUI。

## 如何做...

我们首先通过 pip 安装 Python pytz 时区模块。我们在命令处理器提示中输入以下命令：

```py
**pip install pytz**

```

### 注意

在本书中，我们使用的是 Python 3.4，其中内置了`pip`模块。如果您使用的是较旧版本的 Python，则可能需要先安装`pip`模块。

成功时，我们会得到以下结果。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_05.jpg)

### 注意

屏幕截图显示该命令下载了`.whl`格式。如果您还没有这样做，您可能需要先安装 Python 的`wheel`模块。

这将 Python 的`pytz`模块安装到`site-packages`文件夹中，现在我们可以从 Python GUI 代码中导入这个模块。

我们可以通过运行以下代码列出所有现有的时区，在我们的`ScrolledText`小部件中显示时区。首先，我们向 GUI 添加一个新的`Button`小部件。

```py
import pytz
class OOP():

    # TZ Button callback
    def allTimeZones(self):
        for tz in all_timezones:
            self.scr.insert(tk.INSERT, tz + '\n')

    def createWidgets(self):
        # Adding a TZ Button
        self.allTZs = ttk.Button(self.widgetFrame, 
                                 text=self.i18n.timeZones, 
                                 command=self.allTimeZones)
        self.allTZs.grid(column=0, row=9, sticky='WE')
```

点击我们的新`Button`小部件会产生以下输出：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_06.jpg)

安装了 tzlocal Python 模块后，我们可以通过运行以下代码打印我们当前的区域设置：

```py
    # TZ Local Button callback
    def localZone(self):   
        from tzlocal import get_localzone
        self.scr.insert(tk.INSERT, get_localzone())

    def createWidgets(self):
        # Adding local TZ Button
        self.localTZ = ttk.Button(self.widgetFrame, 
                                  text=self.i18n.localZone, 
                                  command=self.localZone
        self.localTZ.grid(column=1, row=9, sticky='WE')
```

我们已经在`Resources.py`中国际化了我们两个新动作`Button`的字符串。

英文版本：

```py
        self.timeZones = "All Time Zones"
        self.localZone = "Local Zone"
```

德语版本：

```py
        self.timeZones = "Alle Zeitzonen"
        self.localZone = "Lokale Zone"
```

现在点击我们的新按钮会告诉我们我们在哪个时区（嘿，我们不知道这个，是吧…）。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_07.jpg)

我们现在可以将我们的本地时间转换为不同的时区。让我们以美国东部标准时间为例。

通过改进我们现有的代码，我们在未使用的标签 2 中显示我们当前的本地时间。

```py
import pytz
from datetime import datetime
class OOP():
    # Format local US time
    def getDateTime(self):
        fmtStrZone = ""%Y-%m-%d %H:%M:%S""
        self.lbl2.set(datetime.now().strftime(fmtStrZone))

        # Place labels into the container element
        ttk.Label(labelsFrame, text=self.i18n.chooseNumber).grid(column=0, row=0)
        self.lbl2 = tk.StringVar()
        self.lbl2.set(self.i18n.label2)
        ttk.Label(labelsFrame, textvariable=self.lbl2).grid(column=0, row=1)

        # Adding getTimeTZ Button
        self.dt = ttk.Button(self.widgetFrame, text=self.i18n.getTime, command=self.getDateTime)
        self.dt.grid(column=2, row=9, sticky='WE')
```

当我们运行代码时，我们国际化的标签 2（在德语中显示为`Etikette 2`）将显示当前的本地时间。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_08.jpg)

我们现在可以通过首先将本地时间转换为**协调世界时**（**UTC**），然后应用从导入的`pytz`模块中的`timezone`函数来将本地时间更改为美国东部标准时间。

```py
import pytz
class OOP():
    # Format local US time with TimeZone info
    def getDateTime(self):
        fmtStrZone = "%Y-%m-%d %H:%M:%S %Z%z"
        # Get Coordinated Universal Time
        utc = datetime.now(timezone('UTC'))
        print(utc.strftime(fmtStrZone))

        # Convert UTC datetime object to Los Angeles TimeZone
        la = utc.astimezone(timezone('America/Los_Angeles'))
        print(la.strftime(fmtStrZone))

        # Convert UTC datetime object to New York TimeZone
        ny = utc.astimezone(timezone('America/New_York'))
        print(ny.strftime(fmtStrZone))

        # update GUI label with NY Time and Zone
        self.lbl2.set(ny.strftime(fmtStrZone))
```

现在点击重命名为纽约的按钮会产生以下输出：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_09.jpg)

我们的标签 2 已更新为纽约的当前时间，并且我们正在使用美国日期格式字符串将洛杉矶和纽约的 UTC 时间及其相应的时区转换打印到 Eclipse 控制台。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_10.jpg)

### 注意

UTC 从不观察夏令时。在**东部夏令时**（**EDT**）期间，UTC 比本地时间提前四个小时，在**标准时间**（**EST**）期间，UTC 比本地时间提前五个小时。

## 工作原理

为了本地化日期和时间信息，我们首先需要将我们的本地时间转换为 UTC 时间。然后，我们应用`时区`信息，并使用`pytz` Python 时区模块中的`astimezone`函数将时间转换为世界上任何时区的时间！

在这个示例中，我们已经将美国西海岸的本地时间转换为 UTC，然后在我们的 GUI 的标签 2 中显示了美国东海岸的时间。

# 为国际化准备 GUI

在这个示例中，我们将通过意识到将英语翻译成外语并不像预期的那样容易，来为我们的 GUI 准备国际化。

我们还有一个问题要解决，那就是如何正确显示来自外语的非英语 Unicode 字符。

人们可能期望 Python 3 会自动处理德语ä、ö和ü的 Unicode 变音字符，但事实并非如此。

## 准备工作

我们将继续使用我们在最近章节中开发的 Python GUI。首先，我们将在`GUI.py`的初始化代码中将默认语言更改为德语。

我们通过取消注释`self.i18n = I18N('de')`这一行来实现这一点。

## 如何做...

当我们使用变音字符将单词`Ueber`更改为正确的德语`Űber`时，Eclipse PyDev 插件并不太开心。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_11.jpg)

我们收到了一个错误消息，有点令人困惑，因为当我们在 Eclipse PyDev 控制台中运行相同的代码行时，我们得到了预期的结果。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_12.jpg)

当我们询问 Python 的默认编码时，我们得到了预期的结果，即 UTF-8。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_13.jpg)

### 注意

当然，我们总是可以直接表示 Unicode。

使用 Windows 内置的字符映射，我们可以找到 umlaut 字符的 Unicode 表示，大写 U 带有 umlaut 的 Unicode 是 U+00DC。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_14.jpg)

虽然这种解决方法确实很丑陋，但它起到了作用。我们可以通过传递 Unicode 的\u00DC 来正确显示这个字符，而不是输入文字字符Ü。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_15.jpg)

我们也可以接受从 Cp1252 到 UTF-8 的默认编码更改，使用 PyDev 与 Eclipse，但我们可能并不总是会得到提示去这样做。

相反，我们可能会看到显示以下错误消息：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_16.jpg)

解决这个问题的方法是将 PyDev 项目的**文本文件编码**属性更改为 UTF-8。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_17.jpg)

更改 PyDev 默认编码后，我们现在可以显示那些德语 umlaut 字符。我们还更新了标题，使用了正确的德语ä字符。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_18.jpg)

## 工作原理...

国际化和处理外语 Unicode 字符通常并不像我们希望的那样直接。有时，我们不得不找到解决方法，并通过在 Python 中使用直接表示的方式来表示 Unicode 字符，可以解决问题。

在其他时候，我们只需找到我们开发环境的设置进行调整。

# 如何以敏捷方式设计 GUI

现代敏捷软件开发方法的设计和编码是由软件专业人员的经验教训总结而来的。这种方法适用于 GUI 和其他任何代码。敏捷软件开发的主要关键之一是持续应用的重构过程。

重构我们的代码可以通过首先使用函数实现一些简单功能来帮助我们进行软件开发工作的一个实际例子。

随着我们的代码复杂性的增加，我们可能希望将我们的函数重构为类的方法。这种方法可以让我们删除全局变量，并且更灵活地确定在类的哪个位置放置方法。

虽然我们的代码的功能没有改变，但结构已经改变了。

在这个过程中，我们编写、测试、重构，然后再次测试。我们会在短周期内进行这些操作，通常从需要一些功能的最小代码开始。

### 注意

测试驱动的软件开发是敏捷开发方法论的一种特定风格。

虽然我们的 GUI 运行得很好，但我们的主要`GUI.py`代码的复杂性不断增加，开始变得有点难以维护。

这意味着我们需要重构我们的代码。

## 准备工作

我们将重构之前章节中创建的 GUI。我们将使用 GUI 的英文版本。

## 如何做...

在之前的配方中，我们已经将 GUI 显示的所有名称都国际化了。这是重构我们的代码的一个很好的开始。

### 注意

重构是改进现有代码的结构、可读性和可维护性的过程。我们不会添加新功能。

在之前的章节和配方中，我们一直在以“自上而下”的瀑布式开发方法扩展我们的 GUI，向现有代码的顶部添加`import`，并向底部添加代码。

虽然在查看代码时这很有用，但现在看起来有点凌乱，我们可以改进这一点，以帮助我们未来的开发。

让我们首先清理我们的`import`语句部分，目前看起来是这样的：

```py
#======================
# imports
#======================
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import Menu
from tkinter import Spinbox
import B04829_Ch08_ToolTip as tt
from threading import Thread
from time import sleep
from queue import Queue
from tkinter import filedialog as fd
from os import path 
from tkinter import messagebox as mBox
from B04829_Ch08_MySQL import MySQL
from B04829_Ch08_Resources import I18N
from datetime import datetime
from pytz import all_timezones, timezone

# Module level GLOBALS
GLOBAL_CONST = 42
```

通过简单地分组相关的导入，我们可以减少代码行数，从而提高导入的可读性，使其看起来不那么令人生畏。

```py
#======================
# imports
#======================
import tkinter as tk
from tkinter import ttk, scrolledtext, Menu, Spinbox, filedialog as fd, messagebox as mBox
from queue import Queue
from os import path 
import B04829_Ch08_ToolTip as tt
from B04829_Ch08_MySQL import MySQL
from B04829_Ch08_Resources import I18N
from B04829_Ch08_Callbacks_Refactored import Callbacks
from B04829_Ch08_Logger import Logger, LogLevel

# Module level GLOBALS
GLOBAL_CONST = 42
```

我们可以通过将回调方法分解成它们自己的模块来进一步重构我们的代码。这通过将不同的导入语句分离到它们所需的模块中来提高可读性。

让我们将我们的`GUI.py`重命名为`GUI_Refactored.py`，并创建一个新的模块，我们将其命名为`Callbacks_Refactored.py`。

这给了我们这种新的架构。

```py
#======================
# imports
#======================
import tkinter as tk
from tkinter import ttk, scrolledtext, Menu, Spinbox, \
                    filedialog as fd, messagebox as mBox
from queue import Queue
from os import path 
import B04829_Ch08_ToolTip as tt
from B04829_Ch08_MySQL import MySQL
from B04829_Ch08_Resources import I18N
from B04829_Ch08_Callbacks_Refactored import Callbacks

# Module level GLOBALS
GLOBAL_CONST = 42

class OOP():
    def __init__(self): 

        # Callback methods now in different module
        self.callBacks = Callbacks(self)
```

注意我们在调用`Callbacks`初始化程序时是如何传入我们自己的 GUI 类实例（`self`）的。

我们的新`Callbacks`类如下：

```py
#======================
# imports
#======================
import tkinter as tk
from time import sleep
from threading import Thread
from pytz import all_timezones, timezone
from datetime import datetime

class Callbacks():
    def __init__(self, oop):
        self.oop = oop

    def defaultFileEntries(self): 
        self.oop.fileEntry.delete(0, tk.END)
        self.oop.fileEntry.insert(0, 'Z:\\')        # bogus path
        self.oop.fileEntry.config(state='readonly')         
        self.oop.netwEntry.delete(0, tk.END)
        self.oop.netwEntry.insert(0, 'Z:\\Backup')  # bogus path

    # Combobox callback 
    def _combo(self, val=0):
        value = self.oop.combo.get()
        self.oop.scr.insert(tk.INSERT, value + '\n')
```

在我们新类的初始化程序中，传入的 GUI 实例被保存在名为`self.oop`的名称下，并在这个新的 Python 类模块中使用。

运行重构后的 GUI 代码仍然有效。我们只是增加了代码的可读性，并减少了代码的复杂性，为进一步的开发工作做准备。

## 它是如何工作的...

我们首先通过分组相关的导入语句来提高代码的可读性。接下来，我们将回调方法分解成它们自己的类和模块，以进一步减少代码的复杂性。

我们已经采用了相同的面向对象编程方法，通过将`ToolTip`类驻留在自己的模块中，并在先前的示例中国际化了所有 GUI 字符串。

在这个示例中，我们通过将我们自己的实例传递给 GUI 依赖的回调方法类，进一步进行了重构。

### 注意

现在我们更好地理解了模块化软件开发的价值，我们很可能会在未来的软件设计中采用这种方法。

# 我们需要测试 GUI 代码吗？

在编码阶段以及发布服务包或修复错误时，测试我们的软件是一项重要的活动。

有不同级别的测试。第一级是开发人员测试，通常从编译器或解释器不让我们运行有错误的代码开始，迫使我们在单个方法的级别上测试我们的代码的小部分。

这是第一层防御。

第二层防御性编码是当我们的源代码控制系统告诉我们有一些冲突需要解决，并且不让我们提交修改后的代码。

当我们在开发团队中进行专业工作时，这是非常有用且绝对必要的。源代码控制系统是我们的朋友，它指出了已经提交到特定分支或最新版本的更改，无论是我们自己提交的还是其他开发人员提交的，并告诉我们我们的本地代码版本已经过时，并且存在一些需要在提交代码到存储库之前解决的冲突。

这部分假设您使用源代码控制系统来管理和存储您的代码。示例包括 git、mercurial、svn 和其他几种。Git 是一个非常流行的源代码控制系统，对于单个用户是免费的。

第三级是 API 级别，我们通过只允许通过已发布的接口与我们的代码进行交互来封装对我们代码的潜在未来更改。

### 注意

请参考《面向接口编程，而不是实现》，*设计模式*，第 17 页。

另一种测试级别是集成测试，当我们最终构建的一半桥梁与其他开发团队创建的另一半桥梁相遇时，两者高度不一致（比如，一半比另一半高出两米或码...）。

然后，有最终用户测试。虽然我们构建了他们指定的内容，但实际上并不是他们想要的。

噢，好吧...我想所有前面的例子都是我们需要在设计和实施阶段都测试我们的代码的有效原因。

## 准备工作

我们将测试我们在最近的示例和章节中创建的 GUI。我们还将展示一些简单的例子，说明可能出现的问题以及为什么我们需要不断测试我们的代码和通过 API 调用的代码。

## 如何做...

虽然许多经验丰富的开发人员在调试时会在他们的代码中撒上`printf()`语句，但 21 世纪的许多开发人员习惯于现代 IDE 开发环境，这些环境可以有效地加快开发时间。

在本书中，我们使用 Eclipse IDE 的 PyDev Python 插件。

如果您刚开始使用像 Eclipse 这样的 IDE，并安装了 PyDev 插件，一开始可能会有点不知所措。Python 3 附带的 Python IDLE 工具也有一个更简单的调试器，您可能希望先探索一下。

每当我们的代码出现问题时，我们都必须进行调试。这样做的第一步是设置断点，然后逐行或逐个方法地执行我们的代码。

在我们的代码中进出是日常活动，直到代码顺利运行。

在 Python GUI 编程中，出错的第一件事可能是遗漏导入所需的模块或导入现有模块。

这里有一个简单的例子：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_19.jpg)

我们试图创建一个 tkinter 类的实例，但事情并不如预期那样运行。

好吧，我们只是忘记导入模块，我们可以通过在我们的类创建之前添加一行 Python 代码来修复这个问题，导入语句就在那里。

```py
#======================
# imports
#======================
import tkinter as tk
```

这是一个例子，我们的开发环境为我们进行测试。我们只需要进行调试和修复代码。

另一个与开发人员测试更相关的例子是，当我们编写条件语句时，在常规开发过程中没有执行所有逻辑分支。

使用上一章的一个例子，假设我们点击**获取报价**按钮，这个操作成功了，但我们从未点击**修改报价**按钮。第一次按钮点击会创建期望的结果，但第二次会抛出异常（因为我们尚未实现此代码，可能已经完全忘记了）。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_20.jpg)

单击**修改报价**按钮会创建以下结果：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_21.jpg)

另一个潜在的错误区域是当函数或方法突然不再返回预期的结果。假设我们正在调用以下函数，它返回了预期的结果。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_22.jpg)

然后，有人犯了一个错误，我们不再得到以前的结果。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_23.jpg)

我们不是在进行乘法，而是以传入数字的幂进行计算，结果不再是以前的样子了。

### 注意

在软件测试中，这种错误被称为回归。

## 它是如何工作的...

在这个示例中，我们强调了在软件开发生命周期的几个阶段进行软件测试的重要性，通过展示代码可能出错并引入软件缺陷（也称为错误）的几个例子。

# 设置调试监视

在现代的集成开发环境（IDE）中，如 Eclipse 中的 PyDev 插件或其他 IDE（如 NetBeans），我们可以设置调试监视来监视我们的 GUI 在代码执行过程中的状态。

这与 Visual Studio 和更近期的 Visual Studio.NET 的 Microsoft IDE 非常相似。

### 注意

设置调试监视是帮助我们开发工作的一种非常方便的方式。

## 准备工作

在这个示例中，我们将重用之前开发的 Python GUI。我们正在逐步执行我们之前开发的代码并设置调试监视。

## 如何做...

### 注意

虽然这个示例适用于基于 Java 的 Eclipse IDE 中的 PyDev 插件，但其原则也适用于许多现代 IDE。

我们可能希望设置断点的第一个位置是在我们通过调用 tkinter 主事件循环使我们的 GUI 可见的地方。

PyDev/Eclipse 中左侧的绿色气球符号是一个断点。当我们以调试模式执行我们的代码时，一旦执行到达断点，代码的执行将停止。此时，我们可以看到当前作用域内的所有变量的值。我们还可以在调试器窗口中输入表达式，执行它们，显示结果。如果结果是我们想要的，我们可能决定使用我们刚学到的知识更改我们的代码。

我们通常通过单击 IDE 工具栏中的图标或使用键盘快捷键（例如按下*F5*进入代码，*F6*跳过，*F7*跳出当前方法）来逐步执行代码。

![如何操作...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_24.jpg)

在我们放置断点并进入此代码时，出现了问题，因为我们最终进入了一些我们现在不希望调试的低级 tkinter 代码。我们通过单击 Step-Out 工具栏图标（该图标位于项目菜单下方的第三个黄色箭头）或按下*F7*（假设我们在 Eclipse 中使用 PyDev）来退出低级 tkinter 代码。

我们通过单击截图右侧的 bug 工具栏图标开始调试会话。如果我们在不调试的情况下执行，我们会单击绿色圆圈内部有白色三角形的图标，该图标位于 bug 图标右侧。

![如何操作...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_25.jpg)

更好的做法是将断点放置在我们自己的代码附近，以便观察一些我们自己的 Python 变量的值。

在现代 GUI 的事件驱动世界中，我们必须将断点放置在在事件期间被调用的代码上，例如按钮单击。

目前，我们的一个主要功能位于按钮单击事件中。当我们单击标记为**New York**的按钮时，我们创建一个事件，然后在我们的 GUI 中发生某些事情。

让我们在**New York**按钮回调方法上放置一个断点，我们将其命名为`getDateTime()`。

当我们现在运行调试会话时，我们将在断点处停止，然后我们可以启用作用域内的变量观察。

在 Eclipse 中使用 PyDev，我们可以右键单击一个变量，然后从弹出菜单中选择观察命令。变量的名称、类型和当前值将显示在下一个截图中显示的表达式调试窗口中。我们也可以直接在表达式窗口中输入。

我们观察的变量不仅限于简单的数据类型。我们可以观察类实例、列表、字典等。

在观察这些更复杂的对象时，我们可以在表达式窗口中展开它们，并深入了解类实例、字典等所有值。

我们通过点击出现在每个变量**名称**列最左边的观察变量左侧的三角形来实现这一点。

![如何操作...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_26.jpg)

虽然我们正在打印出不同时区位置的值，但从长远来看，设置调试观察更方便、更高效。我们不必用老式的 C 风格的`printf()`语句来使我们的代码混乱。

### 注意

如果您有兴趣学习如何为 Python 安装 Eclipse 和 PyDev 插件，有一个很好的教程可以帮助您开始安装所有必要的免费软件，然后通过创建一个简单的、可工作的 Python 程序来介绍您 PyDev 在 Eclipse 中的使用。[`www.vogella.com/tutorials/Python/article.html`](http://www.vogella.com/tutorials/Python/article.html)

## 工作原理...

我们在 21 世纪使用现代集成开发环境（IDE），这些 IDE 是免费提供的，可以帮助我们创建稳健的代码。

本文介绍了如何设置调试观察，这是每个开发人员技能中的基本工具。即使在不追踪错误时，逐步执行我们自己的代码可以确保我们理解我们的代码，并可能通过重构改进我们的代码。

以下是我读过的第一本编程书籍《Java 编程思想》中的一句话，作者是 Bruce Eckel。

|   | *"抵制急躁的冲动，它只会减慢你的速度。"* |   |
| --- | --- | --- |
|   | --*Bruce Eckel* |

将近 20 年后，这些建议经受住了时间的考验。

### 注意

调试观察有助于我们创建可靠的代码，不是浪费时间。

# 配置不同的调试输出级别

在本示例中，我们将配置不同的调试级别，可以在运行时选择和更改。这使我们能够控制在调试代码时要深入到代码中的程度。

我们将创建两个新的 Python 类，并将它们放入同一个模块中。

我们将使用四种不同的日志级别，并将我们的调试输出写入我们将创建的日志文件中。如果日志文件夹不存在，我们也将自动创建它。

日志文件的名称是执行脚本的名称，即我们重构的`GUI.py`。我们还可以通过将完整路径传递给我们的记录器类的初始化程序来选择其他日志文件的名称。

## 准备工作

我们将继续使用上一个示例中的重构的`GUI.py`代码。

## 如何做...

首先，我们创建一个新的 Python 模块，将两个新的`类`放入其中。第一个`类`非常简单，定义了日志级别。这基本上是一个`枚举`。

```py
class LogLevel:
'''Define logging levels.'''
    OFF     = 0
    MINIMUM = 1
    NORMAL  = 2
    DEBUG   = 3
```

第二个`类`通过使用传入的文件名的完整路径创建一个日志文件，并将其放入`logs`文件夹中。在第一次运行时，`logs`文件夹可能不存在，因此代码会自动创建该文件夹。

```py
class Logger:   
    ''' Create a test log and write to it. '''     
    #-------------------------------------------------------
    def __init__(self, fullTestName, loglevel=LogLevel.DEBUG):
        testName = os.path.splitext(os.path.basename(fullTestName))[0]
        logName  = testName  + '.log'    

        logsFolder = 'logs'          
        if not os.path.exists(logsFolder):                     
            os.makedirs(logsFolder, exist_ok = True)

        self.log = os.path.join(logsFolder, logName)           
        self.createLog()

        self.loggingLevel = loglevel
        self.startTime    = time.perf_counter()

    #------------------------------------------------------
    def createLog(self):    
        with open(self.log, mode='w', encoding='utf-8') as logFile:
            logFile.write(self.getDateTime() + 
                          '\t\t*** Starting Test ***\n')
        logFile.close()
```

为了写入我们的日志文件，我们使用`writeToLog()`方法。在方法内部，我们首先检查消息是否具有高于我们设置的期望日志输出的限制级别。如果消息级别较低，我们将丢弃它并立即从方法中返回。

如果消息具有我们想要显示的日志级别，那么我们检查它是否以换行符开头，如果是，我们通过使用 Python 的切片运算符（`msg = msg[1:]`）来丢弃换行符。

然后，我们将一行写入我们的日志文件，其中包括当前日期时间戳、两个制表符、我们的消息，并以换行符结尾。

```py
    def writeToLog(self, msg='', loglevel=LogLevel.DEBUG): 
        # control how much gets logged
        if loglevel > self.loggingLevel:
            return

        # open log file in append mode 
        with open(self.log, mode='a', encoding='utf-8') as logFile:
            msg = str(msg)
            if msg.startswith('\n'):
                msg = msg[1:]
            logFile.write(self.getDateTime() + '\t\t' + msg + '\n')

        logFile.close()
```

现在我们可以导入我们的新 Python 模块，并在 GUI 代码的`__init__`部分中创建`Logger`类的实例。

```py
from os import path 
from B04829_Ch08_Logger import Logger
class OOP():
    def __init__(self): 
        # create Logger instance
        fullPath = path.realpath(__file__)
        self.log = Logger(fullPath)
        print(self.log)
```

我们通过`path.realpath(__file__)`获取正在运行的 GUI 脚本的完整路径，并将其传递给`Logger`类的初始化程序。如果`logs`文件夹不存在，我们的 Python 代码将自动创建它。

这会产生以下结果：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_27.jpg)

上述截图显示我们创建了一个新的`Logger`类的实例，下面的截图显示`logs`文件夹和日志都已创建。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_28.jpg)

当我们打开日志时，我们可以看到当前日期和时间以及默认字符串已被写入日志。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_29.jpg)

## 它是如何工作的...

在本示例中，我们创建了自己的日志记录类。虽然 Python 附带了一个日志记录模块，但很容易创建我们自己的日志记录类，这使我们对日志格式有绝对控制。当我们将自己的日志输出与我们在上一章中探索的 MS Excel 或 Matplotlib 结合使用时，这非常有用。

在下一个示例中，我们将使用 Python 内置的`__main__`功能来使用我们刚刚创建的四个不同的日志级别。

# 使用 Python 的 __main__ 部分创建自测试代码

Python 具有一个非常好的功能，可以使每个模块进行自我测试。利用这个功能是确保我们的代码更改不会破坏现有代码的一个很好的方法，此外，`__main__`自测试部分还可以作为每个模块工作方式的文档。

### 注意

几个月或几年后，我们有时会忘记我们的代码在做什么，因此在代码本身中写下解释确实是一个很大的帮助。

在可能的情况下，为每个 Python 模块始终添加一个自测试部分是一个好主意。有时不可能，但在大多数模块中是可能的。

## 准备工作

我们将扩展上一个配方，因此，为了理解本配方中的代码在做什么，我们必须先阅读并理解上一个配方中的代码。

## 如何做...

首先，我们将通过向我们的`Resources.py`模块添加这个自测试部分来探索 Python`__main__`自测试部分的功能。每当我们运行一个具有此自测试部分位于模块底部的模块时，当模块单独执行时，此代码将运行。

当模块被导入并从其他模块中使用时，`__main__`自测试部分中的代码将不会被执行。

这是在随后的屏幕截图中显示的代码：

```py
if __name__ == '__main__':
    language = 'en'
    inst = I18N(language)
    print(inst.title)

    language = 'de'
    inst = I18N(language)
    print(inst.title)
```

添加了自测试部分后，我们现在可以单独运行此模块，并且它会创建有用的输出，同时还会显示我们的代码按预期工作。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_30.jpg)

我们首先传入英语作为要在我们的 GUI 中显示的语言，然后传入德语作为我们的 GUI 将显示的语言。

我们打印出我们的 GUI 的标题，以显示我们的 Python 模块按我们的意图工作。

### 注意

下一步是使用我们在上一个配方中创建的日志功能。

我们首先通过向我们重构的`GUI.py`模块添加一个`__main__`自测试部分，然后验证我们创建了`Logger`类的实例。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_31.jpg)

接下来，我们使用所示的命令写入我们的日志文件。我们已经设计了我们的日志级别默认记录每条消息，这是 DEBUG 级别，因此我们不必更改任何内容。我们只需将要记录到`writeToLog`方法的消息传入。

```py
if __name__ == '__main__':
#======================
# Start GUI
#======================
oop = OOP()
    print(oop.log)
    oop.log.writeToLog('Test message')
    oop.win.mainloop()
```

这被写入我们的日志文件，如下面日志的屏幕截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_32.jpg)

现在我们可以通过向我们的日志语句添加日志级别并设置我们希望输出的级别来控制日志记录。让我们将这种能力添加到`Callbacks.py`模块中的`getDateTime`方法，这是`New York`按钮回调方法。

我们使用不同的调试级别将先前的`print`语句更改为`log`语句。

在`GUI.py`中，我们从我们的日志模块导入了两个新类。

```py
from B04829_Ch08_Logger import Logger, LogLevel
```

接下来，我们创建这些类的本地实例。

```py
# create Logger instance
fullPath = path.realpath(__file__)
self.log = Logger(fullPath)

# create Log Level instance
self.level = LogLevel()
```

由于我们将 GUI 类的一个实例传递给`Callbacks.py`初始化程序，因此我们可以根据我们创建的`LogLevel`类对日志级别进行约束。

```py
    # Format local US time with TimeZone info
    def getDateTime(self):
        fmtStrZone = "%Y-%m-%d %H:%M:%S %Z%z"
        # Get Coordinated Universal Time
        utc = datetime.now(timezone('UTC'))
        self.oop.log.writeToLog(utc.strftime(fmtStrZone), 
                                self.oop.level.MINIMUM)

        # Convert UTC datetime object to Los Angeles TimeZone
        la = utc.astimezone(timezone('America/Los_Angeles'))
        self.oop.log.writeToLog(la.strftime(fmtStrZone), 
                                self.oop.level.NORMAL)

        # Convert UTC datetime object to New York TimeZone
        ny = utc.astimezone(timezone('America/New_York'))
        self.oop.log.writeToLog(ny.strftime(fmtStrZone), 
                                self.oop.level.DEBUG)

        # update GUI label with NY Time and Zone
        self.oop.lbl2.set(ny.strftime(fmtStrZone))
```

当我们现在点击我们的纽约按钮时，根据所选的日志级别，我们会得到不同的输出写入我们的日志文件。默认的日志级别是`DEBUG`，这意味着一切都会被写入我们的日志。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_33.jpg)

当我们更改日志级别时，我们控制写入我们的日志的内容。我们通过调用`Logger`类的`setLoggingLevel`方法来实现这一点。

```py
    #----------------------------------------------------------------
    def setLoggingLevel(self, level):  
        '''change logging level in the middle of a test.''' 
        self.loggingLevel = level
```

在我们的 GUI 的`__main__`部分中，我们将日志级别更改为`MINIMUM`，这将导致减少写入我们的日志文件的输出。

```py
if __name__ == '__main__':
#======================
# Start GUI
#======================
oop = OOP()
    oop.log.setLoggingLevel(oop.level.MINIMUM)
    oop.log.writeToLog('Test message')
    oop.win.mainloop()
```

现在，我们的日志文件不再显示`Test Message`，只显示符合设置的日志级别的消息。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_34.jpg)

## 工作原理...

在这个配方中，我们充分利用了 Python 内置的`__main__`自测试部分。我们引入了自己的日志文件，同时也介绍了如何创建不同的日志级别。

通过这样做，我们可以完全控制写入日志文件的内容。

# 使用单元测试创建健壮的 GUI

Python 自带了一个内置的单元测试框架，在这个示例中，我们将开始使用这个框架来测试我们的 Python GUI 代码。

在我们开始编写单元测试之前，我们想要设计我们的测试策略。我们可以很容易地将单元测试与它们测试的代码混合在一起，但更好的策略是将应用程序代码与单元测试代码分开。

### 注意

PyUnit 是根据所有其他 xUnit 测试框架的原则设计的。

## 准备工作

我们将测试本章前面创建的国际化 GUI。

## 如何做...

为了使用 Python 的内置单元测试框架，我们必须导入 Python 的`unittest`模块。让我们创建一个新模块，命名为`UnitTests.py`。

我们首先导入`unittest`模块，然后创建我们自己的类，在这个类中，我们继承并扩展`unittest.TestCase`类。

做到这一点的最简单的代码如下：

```py
import unittest

class GuiUnitTests(unittest.TestCase):
    pass

if __name__ == '__main__':
    unittest.main()
```

这段代码还没有做太多事情，但当我们运行它时，我们没有得到任何错误，这是一个好迹象。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_35.jpg)

实际上，我们确实会在控制台上得到一个输出，说明我们成功地运行了零个测试...

嗯，这个输出有点误导，因为到目前为止我们只是创建了一个不包含任何实际测试方法的类。

我们添加了实际进行单元测试的测试方法，按照所有测试方法的默认命名以“test”开头。这是一个可以更改的选项，但坚持这种命名约定似乎更容易和更清晰。

让我们添加一个测试方法，测试我们的 GUI 的标题。这将验证通过传入预期的参数，我们得到了预期的结果。

```py
import unittest
from B04829_Ch08_Resources import I18N

class GuiUnitTests(unittest.TestCase):

    def test_TitleIsEnglish(self):
        i18n = I18N('en')
        self.assertEqual(i18n.title, 
                       "Python Graphical User Interface")
```

我们从我们的`Resources.py`模块中导入我们的`I18N`类，将英语作为要在我们的 GUI 中显示的语言传入。由于这是我们的第一个单元测试，我们也打印出了标题的结果，只是为了确保我们知道我们得到了什么。接下来，我们使用`unittest assertEqual`方法来验证我们的标题是否正确。

运行这段代码会得到一个**OK**，这意味着单元测试通过了。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_36.jpg)

单元测试运行并成功，这由一个点和单词“OK”表示。如果它失败或出现错误，我们将不会得到点，而是得到“F”或“E”作为输出。

现在我们可以通过验证 GUI 的德语版本的标题来进行相同的自动化单元测试检查。

我们只需复制，粘贴和修改我们的代码。

```py
import unittest
from B04829_Ch08_Resources import I18N

class GuiUnitTests(unittest.TestCase):

    def test_TitleIsEnglish(self):
        i18n = I18N('en')
        self.assertEqual(i18n.title, 
                         "Python Graphical User Interface")

    def test_TitleIsGerman(self):
        i18n = I18N('en')           
        self.assertEqual(i18n.title, 
                         'Python Grafische Benutzeroberfl' 
                       + "\u00E4" + 'che')
```

现在我们正在测试我们国际化的 GUI 标题，使用两种语言，并在运行代码时得到以下结果：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_37.jpg)

我们运行了两个单元测试，但是，我们没有得到一个 OK，而是得到了一个失败。发生了什么？

我们的德语版本 GUI 的`assertion`失败了...

在调试我们的代码时，结果表明在复制，粘贴和修改我们的单元测试代码时，我们忘记了将德语作为语言传入。我们可以很容易地修复这个问题。

```py
    def test_TitleIsGerman(self):
        # i18n = I18N('en')           # <= Bug in Unit Test
        i18n = I18N('de') 
        self.assertEqual(i18n.title, 
                         'Python Grafische Benutzeroberfl' 
                         + "\u00E4" + 'che')
```

当我们重新运行我们的单元测试时，我们再次得到了所有测试都通过的预期结果。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_38.jpg)

### 注意

单元测试代码也是代码，也可能存在 bug。

虽然编写单元测试的目的是真正测试我们的应用程序代码，但我们必须确保我们的测试写得正确。来自**测试驱动开发**（TDD）方法论的一种方法可能会帮助我们。

### 注意

在 TDD 中，我们在实际编写应用程序代码之前先编写单元测试。现在，如果一个方法甚至不存在的测试通过了，那就有问题。下一步是创建不存在的方法，并确保它会失败。之后，我们可以编写最少量的代码来使单元测试通过。

## 工作原理...

在本篇中，我们已经开始测试我们的 Python GUI，编写 Python 单元测试。我们已经看到 Python 单元测试代码只是代码，可能包含需要纠正的错误。在下一篇中，我们将扩展本篇的代码，并使用随 Eclipse IDE 附带的 PyDev 插件的图形单元测试运行器。

# 如何使用 Eclipse PyDev IDE 编写单元测试

在上一篇中，我们开始使用 Python 的单元测试功能，而在本篇中，我们将进一步使用这一功能来确保我们的 GUI 代码的质量。

我们将对我们的 GUI 进行单元测试，以确保我们的 GUI 显示的国际化字符串符合预期。

在上一篇中，我们在单元测试代码中遇到了一些错误，但通常，我们的单元测试将发现由修改现有应用程序代码而引起的回归错误，而不是单元测试代码。一旦我们验证了我们的单元测试代码是正确的，通常不会再更改它。

### 注意

我们的单元测试也作为我们期望代码执行的文档。

默认情况下，Python 的单元测试是使用文本单元测试运行器执行的，我们可以在 Eclipse IDE 的 PyDev 插件中运行它。我们也可以从控制台窗口运行完全相同的单元测试。

除了本篇中的文本运行器，我们还将探讨 PyDev 的图形单元测试功能，该功能可以从 Eclipse IDE 内部使用。

## 准备就绪

我们正在扩展之前的配方，其中我们开始使用 Python 单元测试。

## 操作步骤...

Python 单元测试框架配备了所谓的装置。

请参考以下网址了解测试装置的描述：

+   [`docs.python.org/3.4/library/unittest.html`](https://docs.python.org/3.4/library/unittest.html)

+   [`en.wikipedia.org/wiki/Test_fixture`](https://en.wikipedia.org/wiki/Test_fixture)

+   [`www.boost.org/doc/libs/1_51_0/libs/test/doc/html/utf/user-guide/fixture.html`](http://www.boost.org/doc/libs/1_51_0/libs/test/doc/html/utf/user-guide/fixture.html)

这意味着我们可以创建`setup()`和`teardown()`单元测试方法，以便在执行任何单个测试之前调用`setup()`方法，并且在每个单元测试结束时调用`teardown()`方法。

### 注意

这种装置功能为我们提供了一个非常受控的环境，我们可以在其中运行我们的单元测试。这类似于使用前置条件和后置条件。

让我们设置我们的单元测试环境。我们将创建一个新的测试类，重点关注前面提到的代码正确性。

### 注意

`unittest.main()`运行任何以前缀"test"开头的方法，无论我们在给定的 Python 模块中创建了多少个类。

```py
import unittest
from B04829_Ch08_Resources import I18N
from B04829_Ch08_GUI_Refactored import OOP as GUI

class GuiUnitTests(unittest.TestCase):

    def test_TitleIsEnglish(self):
        i18n = I18N('en')
        self.assertEqual(i18n.title, 
                         "Python Graphical User Interface")

    def test_TitleIsGerman(self):
        # i18n = I18N('en')           # <= Bug in Unit Test
        i18n = I18N('de') 
        self.assertEqual(i18n.title, 
                         'Python Grafische Benutzeroberfl' 
                         + "\u00E4" + 'che')

class WidgetsTestsEnglish(unittest.TestCase):

    def setUp(self):
        self.gui = GUI('en')

    def tearDown(self):
        self.gui = None

    def test_WidgetLabels(self):
        self.assertEqual(self.gui.i18n.file, "File")
        self.assertEqual(self.gui.i18n.mgrFiles, ' Manage Files ')
        self.assertEqual(self.gui.i18n.browseTo, 
                                            "Browse to File...")
if __name__ == '__main__':
    unittest.main()
```

这将产生以下输出：

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_39.jpg)

前面的单元测试代码表明，我们可以创建几个单元测试类，并且可以通过调用`unittest.main`在同一个模块中运行它们。

它还显示`setup()`方法在单元测试报告的输出中不算作测试（测试数量为 3），同时，它也完成了其预期的工作，因为我们现在可以从单元测试方法内部访问我们的类实例变量`self.gui`。

我们有兴趣测试所有标签的正确性，特别是在我们更改代码时捕捉错误。

如果我们从应用程序代码复制并粘贴字符串到测试代码中，它将在单元测试框架按钮的点击下捕捉到任何意外更改。

我们还希望测试在任何语言中调用任何`Radiobutton`小部件都会导致`labelframe`小部件的`text`被更新。为了自动测试这一点，我们必须做两件事。

首先，我们必须检索`labelframe text`小部件的值，并将该值分配给一个名为`labelFrameText`的变量。我们必须使用以下语法，因为该小部件的属性是通过字典数据类型传递和检索的：

```py
self.gui.widgetFrame['text']
```

现在我们可以验证默认文本，然后在以编程方式单击一个 Radiobutton 小部件后，验证国际化版本。

```py
class WidgetsTestsGerman(unittest.TestCase):

    def setUp(self):
        self.gui = GUI('de')

    def test_WidgetLabels(self):
        self.assertEqual(self.gui.i18n.file, "Datei")
        self.assertEqual(self.gui.i18n.mgrFiles, 
                                        ' Dateien Organisieren ')
        self.assertEqual(self.gui.i18n.browseTo, 
                                        "Waehle eine Datei... ")

    def test_LabelFrameText(self):
        labelFrameText = self.gui.widgetFrame['text']
        self.assertEqual(labelFrameText, " Widgets Rahmen ")
        self.gui.radVar.set(1)
        self.gui.callBacks.radCall()
        labelFrameText = self.gui.widgetFrame['text']
        self.assertEqual(labelFrameText, 
                                    " Widgets Rahmen in Gold")
```

在验证默认的`labelFrameText`之后，我们以编程方式将单选按钮设置为索引 1，然后以编程方式调用单选按钮的回调方法。

```py
        self.gui.radVar.set(1)
        self.gui.callBacks.radCall()
```

### 注意

这基本上与在 GUI 中单击单选按钮相同，但我们是通过代码在单元测试中进行按钮单击事件。

然后，我们验证`labelframe`小部件中的文本是否按预期更改了。

当我们在 Eclipse 中使用 Python PyDev 插件运行单元测试时，我们会得到以下输出写入 Eclipse 控制台。

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_40.jpg)

从命令提示符运行时，一旦我们导航到当前代码所在的文件夹，我们会得到类似的输出。

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_41.jpg)

使用 Eclipse，我们还可以选择运行我们的单元测试，不是作为简单的 Python 脚本，而是作为 Python 单元测试脚本，这样我们就可以得到一些丰富多彩的输出，而不是旧的 DOS 提示符的黑白世界。

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_08_42.jpg)

单元测试结果栏是绿色的，这意味着我们所有的单元测试都通过了。前面的截图还显示，GUI 测试运行器比文本测试运行器慢得多：在 Eclipse 中为 1.01 秒，而文本测试运行器为 0.466 秒。

## 工作原理...

我们通过测试`labels`来扩展我们的单元测试代码，通过编程调用`Radiobutton`，然后在单元测试中验证`labelframe`小部件的相应`text`属性是否按预期更改。我们已经测试了两种不同的语言。

然后，我们开始使用内置的 Eclipse/PyDev 图形化单元测试运行器。


# 第九章：使用 wxPython 库扩展我们的 GUI

在本章中，我们将使用 wxPython 库增强我们的 Python GUI。

+   如何安装 wxPython 库

+   如何在 wxPython 中创建我们的 GUI

+   使用 wxPython 快速添加控件

+   尝试在主 tkinter 应用程序中嵌入主 wxPython 应用程序

+   尝试将我们的 tkinter GUI 代码嵌入到 wxPython 中

+   如何使用 Python 控制两个不同的 GUI 框架

+   如何在两个连接的 GUI 之间通信

# 介绍

在本章中，我们将介绍另一个 Python GUI 工具包，它目前不随 Python 一起发布。它被称为 wxPython。

这个库有两个版本。原始版本称为 Classic，而最新版本称为开发项目的代号 Phoenix。

在本书中，我们仅使用 Python 3 进行编程，因为新的 Phoenix 项目旨在支持 Python 3，这就是我们在本章中使用的 wxPython 版本。

首先，我们将创建一个简单的 wxPython GUI，然后我们将尝试将我们在本书中开发的基于 tkinter 的 GUI 与新的 wxPython 库连接起来。

### 注意

wxPython 是 Python 绑定到 wxWidgets 的库。

wxPython 中的 w 代表 Windows 操作系统，x 代表 Unix 操作系统，如 Linux 和 OS X。

如果同时使用这两个 GUI 工具包出现问题，我们将尝试使用 Python 解决任何问题，然后我们将使用 Python 内的**进程间通信**（**IPC**）来确保我们的 Python 代码按我们希望的方式工作。

# 如何安装 wxPython 库

wxPython 库不随 Python 一起发布，因此，为了使用它，我们首先必须安装它。

这个步骤将向我们展示在哪里以及如何找到正确的版本来安装，以匹配已安装的 Python 版本和正在运行的操作系统。

### 注意

wxPython 第三方库已经存在了 17 年多，这表明它是一个强大的库。

## 准备工作

为了在 Python 3 中使用 wxPython，我们必须安装 wxPython Phoenix 版本。

## 如何做...

在网上搜索 wxPython 时，我们可能会在[www.wxpython.org](http://www.wxpython.org)找到官方网站。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_01.jpg)

如果我们点击 MS Windows 的下载链接，我们可以看到几个 Windows 安装程序，所有这些安装程序都仅适用于 Python 2.x。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_02.jpg)

使用 Python 3 和 wxPython，我们必须安装 wxPython/Phoenix 库。我们可以在快照构建链接中找到安装程序：

[`wxpython.org/Phoenix/snapshot-builds/`](http://wxpython.org/Phoenix/snapshot-builds/)

从这里，我们可以选择与我们的 Python 版本和操作系统版本匹配的 wxPython/Phoenix 版本。我正在使用运行在 64 位 Windows 7 操作系统上的 Python 3.4。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_03.jpg)

Python wheel（.whl）安装程序包有一个编号方案。

对我们来说，这个方案最重要的部分是我们正在安装的 wxPython/Phoenix 版本是为 Python 3.4（安装程序名称中的 cp34）和 Windows 64 位操作系统（安装程序名称中的 win_amd64）。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_04.jpg)

成功下载 wxPython/Phoenix 包后，我们现在可以转到该包所在的目录，并使用 pip 安装此包。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_05.jpg)

我们的 Python`site-packages`文件夹中有一个名为`wx`的新文件夹。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_06.jpg)

### 注意

`wx`是 wxPython/Phoenix 库安装的文件夹名称。我们将在 Python 代码中导入此模块。

我们可以通过执行来自官方 wxPython/Phoenix 网站的简单演示脚本来验证我们的安装是否成功。官方网站的链接是[`wxpython.org/Phoenix/docs/html/`](http://wxpython.org/Phoenix/docs/html/)。

```py
import wx
app = wx.App()
frame = wx.Frame(None, -1, "Hello World")
frame.Show()
app.MainLoop()
```

运行上述 Python 3 脚本将使用 wxPython/Phoenix 创建以下 GUI。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_07.jpg)

## 工作原理...

在这个食谱中，我们成功安装了与 Python 3 兼容的正确版本的 wxPython 工具包。我们找到了这个 GUI 工具包的 Phoenix 项目，这是当前和活跃的开发线。Phoenix 将在未来取代 Classic wxPython 工具包，特别适用于与 Python 3 良好地配合使用。

成功安装了 wxPython/Phoenix 工具包后，我们只用了五行代码就创建了一个 GUI。

### 注意

我们之前使用 tkinter 实现了相同的结果。

# 如何在 wxPython 中创建我们的 GUI

在这个食谱中，我们将开始使用 wxPython GUI 工具包创建我们的 Python GUI。

我们将首先使用随 Python 一起提供的 tkinter 重新创建我们之前创建的几个小部件。

然后，我们将探索一些使用 tkinter 更难创建的 wxPython GUI 工具包提供的小部件。

## 准备工作

前面的食谱向您展示了如何安装与您的 Python 版本和操作系统匹配的正确版本的 wxPython。

## 如何做...

开始探索 wxPython GUI 工具包的一个好地方是访问以下网址：[`wxpython.org/Phoenix/docs/html/gallery.html`](http://wxpython.org/Phoenix/docs/html/gallery.html)

这个网页显示了许多 wxPython 小部件。点击任何一个小部件，我们会进入它们的文档，这是一个非常好的和有用的功能，可以快速了解 wxPython 控件。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_08.jpg)

以下屏幕截图显示了 wxPython 按钮小部件的文档。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_09.jpg)

我们可以非常快速地创建一个带有标题、菜单栏和状态栏的工作窗口。当鼠标悬停在菜单项上时，状态栏会显示菜单项的文本。这可以通过编写以下代码来实现：

```py
# Import wxPython GUI toolkit
import wx

# Subclass wxPython frame
class GUI(wx.Frame):
    def __init__(self, parent, title, size=(200,100)):
        # Initialize super class
        wx.Frame.__init__(self, parent, title=title, size=size)

        # Change the frame background color 
        self.SetBackgroundColour('white')

        # Create Status Bar
        self.CreateStatusBar() 

        # Create the Menu
        menu= wx.Menu()

        # Add Menu Items to the Menu
        menu.Append(wx.ID_ABOUT, "About", "wxPython GUI")
        menu.AppendSeparator()
        menu.Append(wx.ID_EXIT,"Exit"," Exit the GUI")

        # Create the MenuBar
        menuBar = wx.MenuBar()

        # Give the MenuBar a Title
        menuBar.Append(menu,"File") 

        # Connect the MenuBar to the frame
        self.SetMenuBar(menuBar)  

        # Display the frame
        self.Show()

# Create instance of wxPython application
app = wx.App()

# Call sub-classed wxPython GUI increasing default Window size
GUI(None, "Python GUI using wxPython", (300,150))

# Run the main GUI event loop
app.MainLoop()
```

这创建了以下使用 wxPython 库编写的 Python GUI。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_10.jpg)

在前面的代码中，我们继承自`wx.Frame`。在下面的代码中，我们继承自`wx.Panel`，并将`wx.Frame`传递给我们的类的`__init__()`方法。

### 注意

在 wxPython 中，顶级 GUI 窗口称为框架。没有框架就不能有 wxPython GUI，框架必须作为 wxPython 应用程序的一部分创建。

我们在代码底部同时创建应用程序和框架。

为了向我们的 GUI 添加小部件，我们必须将它们附加到一个面板上。面板的父级是框架（我们的顶级窗口），我们放置在面板中的小部件的父级是面板。

以下代码向一个面板小部件添加了一个多行文本框小部件。我们还向面板小部件添加了一个按钮小部件，当点击时，会向文本框打印一些文本。

以下是完整的代码：

```py
import wx               # Import wxPython GUI toolkit
class GUI(wx.Panel):    # Subclass wxPython Panel
    def __init__(self, parent):

        # Initialize super class
        wx.Panel.__init__(self, parent)

        # Create Status Bar
        parent.CreateStatusBar() 

        # Create the Menu
        menu= wx.Menu()

        # Add Menu Items to the Menu
        menu.Append(wx.ID_ABOUT, "About", "wxPython GUI")
        menu.AppendSeparator()
        menu.Append(wx.ID_EXIT,"Exit"," Exit the GUI")

        # Create the MenuBar
        menuBar = wx.MenuBar()

        # Give the Menu a Title
        menuBar.Append(menu,"File") 

        # Connect the MenuBar to the frame
        parent.SetMenuBar(menuBar)  

        # Create a Print Button
        button = wx.Button(self, label="Print", pos=(0,60))

        # Connect Button to Click Event method 
        self.Bind(wx.EVT_BUTTON, self.printButton, button)

        # Create a Text Control widget 
        self.textBox = wx.TextCtrl(
self, size=(280,50), style=wx.TE_MULTILINE)

    def printButton(self, event):
        self.textBox.AppendText(
"The Print Button has been clicked!") 

app = wx.App()      # Create instance of wxPython application
frame = wx.Frame(None, title="Python GUI using wxPython", size=(300,180))     # Create frame
GUI(frame)          # Pass frame into GUI
frame.Show()        # Display the frame
app.MainLoop()      # Run the main GUI event loop
```

运行前面的代码并点击我们的 wxPython 按钮小部件会产生以下 GUI 输出：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_11.jpg)

## 工作原理...

在这个食谱中，我们使用成熟的 wxPython GUI 工具包创建了自己的 GUI。只需几行 Python 代码，我们就能创建一个带有“最小化”、“最大化”和“退出”按钮的完全功能的 GUI。我们添加了一个菜单栏，一个多行文本控件和一个按钮。我们还创建了一个状态栏，当我们选择菜单项时会显示文本。我们将所有这些小部件放入了一个面板容器小部件中。

我们将按钮连接到文本控件以打印文本。

当鼠标悬停在菜单项上时，状态栏会显示一些文本。

# 使用 wxPython 快速添加控件

在这个食谱中，我们将重新创建我们在本书中早期使用 tkinter 创建的 GUI，但这次，我们将使用 wxPython 库。我们将看到使用 wxPython GUI 工具包创建我们自己的 Python GUI 是多么简单和快速。

我们不会重新创建我们在之前章节中创建的整个功能。例如，我们不会国际化我们的 wxPython GUI，也不会将其连接到 MySQL 数据库。我们将重新创建 GUI 的视觉方面并添加一些功能。

### 注意

比较不同的库可以让我们选择使用哪些工具包来开发我们自己的 Python GUI，并且我们可以在我们自己的 Python 代码中结合几个工具包。

## 准备工作

确保你已经安装了 wxPython 模块以便按照这个步骤进行。

## 如何做...

首先，我们像以前在 tkinter 中那样创建我们的 Python`OOP`类，但这次我们继承并扩展了`wx.Frame`类。出于清晰的原因，我们不再将我们的类称为`OOP`，而是将其重命名为`MainFrame`。

### 注意

在 wxPython 中，主 GUI 窗口被称为 Frame。

我们还创建了一个回调方法，当我们单击“退出”菜单项时关闭 GUI，并将浅灰色的“元组”声明为我们 GUI 的背景颜色。

```py
import wx
BACKGROUNDCOLOR = (240, 240, 240, 255)

class MainFrame(wx.Frame):
    def __init__(self, *args, **kwargs):
        wx.Frame.__init__(self, *args, **kwargs)

        self.createWidgets()
        self.Show()

    def exitGUI(self, event):     # callback
        self.Destroy()

    def createWidgets(self):   
        self.CreateStatusBar()      # wxPython built-in method
        self.createMenu()
       self.createNotebook()
```

接下来，我们通过创建 wxPython`Notebook`类的实例并将其分配为我们自己的名为`Widgets`的自定义类的父类，向我们的 GUI 添加一个选项卡控件。

`notebook`类实例变量的父类是`wx.Panel`。

```py
    def createNotebook(self):
        panel = wx.Panel(self)
        notebook = wx.Notebook(panel)
        widgets = Widgets(notebook) # Custom class explained below
        notebook.AddPage(widgets, "Widgets")
        notebook.SetBackgroundColour(BACKGROUNDCOLOR) 
        # layout
        boxSizer = wx.BoxSizer()
        boxSizer.Add(notebook, 1, wx.EXPAND)
        panel.SetSizerAndFit(boxSizer)  
```

### 注意

在 wxPython 中，选项卡小部件被命名为`Notebook`，就像在 tkinter 中一样。

每个`Notebook`小部件都需要一个父类，并且为了在 wxPython 中布局`Notebook`中的小部件，我们使用不同类型的 sizers。

### 注意

wxPython sizers 是类似于 tkinter 的网格布局管理器的布局管理器。

接下来，我们向我们的 Notebook 页面添加控件。我们通过创建一个从`wx.Panel`继承的单独类来实现这一点。

```py
class Widgets(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.createWidgetsFrame()
        self.addWidgets()
        self.layoutWidgets()
```

我们通过将 GUI 代码模块化为小方法来遵循 Python OOP 编程最佳实践，这样可以使我们的代码易于管理和理解。

```py
    #------------------------------------------------------
    def createWidgetsFrame(self):
        self.panel = wx.Panel(self)
        staticBox = wx.StaticBox( self.panel, -1, "Widgets Frame" )    
        self.statBoxSizerV = wx.StaticBoxSizer(staticBox, 
                                               wx.VERTICAL)
    #-----------------------------------------------------
    def layoutWidgets(self):         
        boxSizerV = wx.BoxSizer( wx.VERTICAL )
        boxSizerV.Add( self.statBoxSizerV, 1, wx.ALL )
        self.panel.SetSizer( boxSizerV )
        boxSizerV.SetSizeHints( self.panel )

    #------------------------------------------------------
    def addWidgets(self):
        self.addCheckBoxes()        
        self.addRadioButtons()
        self.addStaticBoxWithLabels()
```

### 注意

在使用 wxPython StaticBox 小部件时，为了成功地对其进行布局，我们使用了`StaticBoxSizer`和常规的`BoxSizer`的组合。wxPython StaticBox 与 tkinter 的 LabelFrame 小部件非常相似。

在 tkinter 中，将一个`StaticBox`嵌入另一个`StaticBox`很简单，但在 wxPython 中使用起来有点不直观。使其工作的一种方法如下所示：

```py
    def addStaticBoxWithLabels(self):
        boxSizerH = wx.BoxSizer(wx.HORIZONTAL)
        staticBox = wx.StaticBox( self.panel, -1, 
"Labels within a Frame" )
        staticBoxSizerV = wx.StaticBoxSizer( staticBox, wx.VERTICAL )
        boxSizerV = wx.BoxSizer( wx.VERTICAL )
        staticText1 = wx.StaticText( self.panel, -1,
"Choose a number:" )
        boxSizerV.Add( staticText1, 0, wx.ALL)
        staticText2 = wx.StaticText( self.panel, -1,"Label 2")
        boxSizerV.Add( staticText2, 0, wx.ALL )
        #------------------------------------------------------
        staticBoxSizerV.Add( boxSizerV, 0, wx.ALL )
        boxSizerH.Add(staticBoxSizerV)
        #------------------------------------------------------
        boxSizerH.Add(wx.TextCtrl(self.panel))
        # Add local boxSizer to main frame
        self.statBoxSizerV.Add( boxSizerH, 1, wx.ALL )
```

首先，我们创建一个水平的`BoxSizer`。接下来，我们创建一个垂直的`StaticBoxSizer`，因为我们想在这个框架中以垂直布局排列两个标签。

为了将另一个小部件排列到嵌入的`StaticBox`的右侧，我们必须将嵌入的`StaticBox`及其子控件和下一个小部件都分配给水平的`BoxSizer`，然后将这个`BoxSizer`（现在包含了我们的嵌入的`StaticBox`和其他小部件）分配给主`StaticBox`。

这听起来令人困惑吗？

你只需要尝试使用这些 sizers 来感受如何使用它们。从这个步骤的代码开始，注释掉一些代码，或者修改一些 x 和 y 坐标来看看效果。

阅读官方的 wxPython 文档也是很有帮助的。

### 注意

重要的是要知道在代码中的哪里添加不同的 sizers 以实现我们希望的布局。

为了在第一个下面创建第二个`StaticBox`，我们创建单独的`StaticBoxSizers`并将它们分配给同一个面板。

```py
class Widgets(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.panel = wx.Panel(self)
        self.createWidgetsFrame()
        self.createManageFilesFrame()
        self.addWidgets()
        self.addFileWidgets()
        self.layoutWidgets()

    #----------------------------------------------------------
    def createWidgetsFrame(self):
        staticBox = wx.StaticBox( 
self.panel, -1, "Widgets Frame", size=(285, -1) )   
        self.statBoxSizerV = wx.StaticBoxSizer(
staticBox, wx.VERTICAL)   

    #----------------------------------------------------------
    def createManageFilesFrame(self):
        staticBox = wx.StaticBox( 
self.panel, -1, "Manage Files", size=(285, -1) )   
        self.statBoxSizerMgrV = wx.StaticBoxSizer(
staticBox, wx.VERTICAL)

    #----------------------------------------------------------
    def layoutWidgets(self):         
        boxSizerV = wx.BoxSizer( wx.VERTICAL )
        boxSizerV.Add( self.statBoxSizerV, 1, wx.ALL )
        boxSizerV.Add( self.statBoxSizerMgrV, 1, wx.ALL )

        self.panel.SetSizer( boxSizerV )
        boxSizerV.SetSizeHints( self.panel )

    #----------------------------------------------------------
    def addFileWidgets(self):   
        boxSizerH = wx.BoxSizer(wx.HORIZONTAL)
        boxSizerH.Add(wx.Button(
self.panel, label='Browse to File...'))   
        boxSizerH.Add(wx.TextCtrl(
self.panel, size=(174, -1), value= "Z:\\" ))

        boxSizerH1 = wx.BoxSizer(wx.HORIZONTAL)
        boxSizerH1.Add(wx.Button(
self.panel, label='Copy File To:    ')) 
        boxSizerH1.Add(wx.TextCtrl(
self.panel, size=(174, -1), value= "Z:\\Backup" ))    

        boxSizerV = wx.BoxSizer(wx.VERTICAL)
        boxSizerV.Add(boxSizerH)
        boxSizerV.Add(boxSizerH1)        

        self.statBoxSizerMgrV.Add( boxSizerV, 1, wx.ALL )
```

以下代码实例化了主事件循环，运行我们的 wxPython GUI 程序。

```py
#======================
# Start GUI
#======================
app = wx.App()
MainFrame(None, title="Python GUI using wxPython", size=(350,450))
app.MainLoop()
```

我们的 wxPython GUI 的最终结果如下：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_12.jpg)

## 工作原理...

我们在几个类中设计和布局我们的 wxPython GUI。

在我们的 Python 模块的底部部分完成这些操作后，我们创建了一个 wxPython 应用程序的实例。接下来，我们实例化我们的 wxPython GUI 代码。

之后，我们调用主 GUI 事件循环，该循环执行在此应用程序进程中运行的所有 Python 代码。这将显示我们的 wxPython GUI。

### 注意

我们放置在创建应用程序和调用其主事件循环之间的任何代码都成为我们的 wxPython GUI。

可能需要一些时间来真正熟悉 wxPython 库及其 API，但一旦我们了解如何使用它，这个库就真的很有趣，是构建自己的 Python GUI 的强大工具。还有一个可与 wxPython 一起使用的可视化设计工具：[`www.cae.tntech.edu/help/programming/wxdesigner-getting-started/view`](http://www.cae.tntech.edu/help/programming/wxdesigner-getting-started/view)

这个示例使用面向对象编程来学习如何使用 wxPython GUI 工具包。

# 尝试将主要的 wxPython 应用程序嵌入到主要的 tkinter 应用程序中

现在，我们已经使用 Python 内置的 tkinter 库以及 wxWidgets 库的 wxPython 包装器创建了相同的 GUI，我们确实需要结合使用这些技术创建的 GUI。

### 注意

wxPython 和 tkinter 库都有各自的优势。在诸如[`stackoverflow.com/`](http://stackoverflow.com/)的在线论坛上，我们经常看到诸如哪个更好？应该使用哪个 GUI 工具包？这表明我们必须做出“二选一”的决定。我们不必做出这样的决定。

这样做的主要挑战之一是每个 GUI 工具包都必须有自己的事件循环。

在这个示例中，我们将尝试通过从我们的 tkinter GUI 中调用它来嵌入一个简单的 wxPython GUI。

## 准备工作

我们将重用在第一章中构建的 tkinter GUI。

## 如何做...

我们从一个简单的 tkinter GUI 开始，看起来像这样：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_13.jpg)

接下来，我们将尝试调用在本章前一篇示例中创建的简单 wxPython GUI。

这是以简单的非面向对象编程方式完成此操作的整个代码：

```py
#===========================================================
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext

win = tk.Tk()    

win.title("Python GUI")
aLabel = ttk.Label(win, text="A Label")
aLabel.grid(column=0, row=0)    
ttk.Label(win, text="Enter a name:").grid(column=0, row=0)
name = tk.StringVar()
nameEntered = ttk.Entry(win, width=12, textvariable=name)
nameEntered.grid(column=0, row=1)
ttk.Label(win, text="Choose a number:").grid(column=1, row=0)
number = tk.StringVar()
numberChosen = ttk.Combobox(win, width=12, textvariable=number)
numberChosen['values'] = (1, 2, 4, 42, 100)
numberChosen.grid(column=1, row=1)
numberChosen.current(0)
scrolW  = 30
scrolH  =  3
scr = scrolledtext.ScrolledText(win, width=scrolW, height=scrolH, wrap=tk.WORD)
scr.grid(column=0, sticky='WE', columnspan=3)
nameEntered.focus()  

#===========================================================
def wxPythonApp():
    import wx
    app = wx.App()
    frame = wx.Frame(None, -1, "wxPython GUI", size=(200,150))
    frame.SetBackgroundColour('white')
    frame.CreateStatusBar()
    menu= wx.Menu()
    menu.Append(wx.ID_ABOUT, "About", "wxPython GUI")
    menuBar = wx.MenuBar()
    menuBar.Append(menu,"File") 
    frame.SetMenuBar(menuBar)     
    frame.Show()
    app.MainLoop()

action = ttk.Button(win, text="Call wxPython GUI", command= wxPythonApp ) 
action.grid(column=2, row=1)

#======================
# Start GUI
#======================
win.mainloop()
```

运行上述代码后，单击 tkinter `Button`控件后，从我们的 tkinter GUI 启动了一个 wxPython GUI。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_14.jpg)

## 它是如何工作的...

重要的是，我们将整个 wxPython 代码放入了自己的函数中，我们将其命名为`def wxPythonApp()`。

在按钮单击事件的回调函数中，我们只需调用此代码。

### 注意

需要注意的一点是，在继续使用 tkinter GUI 之前，我们必须关闭 wxPython GUI。

# 尝试将我们的 tkinter GUI 代码嵌入到 wxPython 中

在这个示例中，我们将与上一个示例相反，尝试从 wxPython GUI 中调用我们的 tkinter GUI 代码。

## 准备工作

我们将重用在本章前一篇示例中创建的一些 wxPython GUI 代码。

## 如何做...

我们将从一个简单的 wxPython GUI 开始，看起来像这样：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_15.jpg)

接下来，我们将尝试调用一个简单的 tkinter GUI。

这是以简单的非面向对象编程方式完成此操作的整个代码：

```py
#=============================================================
def tkinterApp():
    import tkinter as tk
    from tkinter import ttk
    win = tk.Tk()    
    win.title("Python GUI")
    aLabel = ttk.Label(win, text="A Label")
    aLabel.grid(column=0, row=0)    
    ttk.Label(win, text="Enter a name:").grid(column=0, row=0)
    name = tk.StringVar()
    nameEntered = ttk.Entry(win, width=12, textvariable=name)
    nameEntered.grid(column=0, row=1)
    nameEntered.focus()  
    def buttonCallback():
        action.configure(text='Hello ' + name.get())
    action = ttk.Button(win, text="Print", command=buttonCallback)
    action.grid(column=2, row=1)
    win.mainloop()

#=============================================================
import wx
app = wx.App()
frame = wx.Frame(None, -1, "wxPython GUI", size=(200,180))
frame.SetBackgroundColour('white')
frame.CreateStatusBar()
menu= wx.Menu()
menu.Append(wx.ID_ABOUT, "About", "wxPython GUI")
menuBar = wx.MenuBar()
menuBar.Append(menu,"File") 
frame.SetMenuBar(menuBar) 
textBox = wx.TextCtrl(frame, size=(180,50), style=wx.TE_MULTILINE)

def tkinterEmbed(event):
    tkinterApp()

button = wx.Button(frame, label="Call tkinter GUI", pos=(0,60)) 
frame.Bind(wx.EVT_BUTTON, tkinterEmbed, button)
frame.Show()

#======================
# Start wxPython GUI
#======================
app.MainLoop()
```

运行上述代码后，单击 wxPython `Button`小部件后，从我们的 wxPython GUI 启动了一个 tkinter GUI。然后我们可以在 tkinter 文本框中输入文本。通过单击其按钮，按钮文本将更新为该名称。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_16.jpg)

在启动 tkinter 事件循环后，wxPython GUI 仍然可以响应，因为我们可以在 tkinter GUI 运行时输入`TextCtrl`小部件。

### 注意

在上一个示例中，我们在关闭 wxPython GUI 之前无法使用我们的 tkinter GUI。意识到这种差异可以帮助我们的设计决策，如果我们想要结合这两种 Python GUI 技术。

通过多次单击 wxPython GUI 按钮，我们还可以创建几个 tkinter GUI 实例。但是，只要有任何 tkinter GUI 仍在运行，我们就不能关闭 wxPython GUI。我们必须先关闭它们。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_17.jpg)

## 它是如何工作的...

在这个示例中，我们与上一个示例相反，首先使用 wxPython 创建 GUI，然后在其中使用 tkinter 创建了几个 GUI 实例。

当一个或多个 tkinter GUI 正在运行时，wxPython GUI 仍然保持响应。但是，单击 tkinter 按钮只会更新第一个实例中的按钮文本。

# 如何使用 Python 来控制两种不同的 GUI 框架

在这个配方中，我们将探讨如何从 Python 控制 tkinter 和 wxPython GUI 框架。在上一章中，我们已经使用 Python 的线程模块来保持我们的 GUI 响应，所以在这里我们将尝试使用相同的方法。

我们将看到事情并不总是按照直觉的方式工作。

然而，我们将改进我们的 tkinter GUI，使其在我们从中调用 wxPython GUI 的实例时不再无响应。

## 准备工作

这个配方将扩展本章的一个先前配方，我们试图将一个主要的 wxPython GUI 嵌入到我们的 tkinter GUI 中。

## 如何做...

当我们从 tkinter GUI 创建了一个 wxPython GUI 的实例时，我们就不能再使用 tkinter GUI 控件，直到关闭了 wxPython GUI 的一个实例。让我们现在改进一下。

我们的第一次尝试可能是在 tkinter 按钮回调函数中使用线程。

例如，我们的代码可能是这样的：

```py
def wxPythonApp():
    import wx
    app = wx.App()
    frame = wx.Frame(None, -1, "wxPython GUI", size=(200,150))
    frame.SetBackgroundColour('white')
    frame.CreateStatusBar()
    menu= wx.Menu()
    menu.Append(wx.ID_ABOUT, "About", "wxPython GUI")
    menuBar = wx.MenuBar()
    menuBar.Append(menu,"File") 
    frame.SetMenuBar(menuBar)     
    frame.Show()
    app.MainLoop()

def tryRunInThread():
    runT = Thread(target=wxPythonApp)
    runT.setDaemon(True)    
    runT.start()
    print(runT)
    print('createThread():', runT.isAlive())    

action = ttk.Button(win, text="Call wxPython GUI", command=tryRunInThread)
```

起初，这似乎是有效的，这是直观的，因为 tkinter 控件不再被禁用，我们可以通过单击按钮创建几个 wxPython GUI 的实例。我们还可以在其他 tkinter 小部件中输入和选择。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_18.jpg)

然而，一旦我们试图关闭 GUI，我们会从 wxWidgets 得到一个错误，我们的 Python 可执行文件会崩溃。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_19.jpg)

为了避免这种情况，我们可以改变代码，只让 wxPython 的`app.MainLoop`在一个线程中运行，而不是尝试在一个线程中运行整个 wxPython 应用程序。

```py
def wxPythonApp():
    import wx
    app = wx.App()
    frame = wx.Frame(None, -1, "wxPython GUI", size=(200,150))
    frame.SetBackgroundColour('white')
    frame.CreateStatusBar()
    menu= wx.Menu()
    menu.Append(wx.ID_ABOUT, "About", "wxPython GUI")
    menuBar = wx.MenuBar()
    menuBar.Append(menu,"File") 
    frame.SetMenuBar(menuBar)     
    frame.Show()

    runT = Thread(target=app.MainLoop)
    runT.setDaemon(True)    
    runT.start()
    print(runT)
    print('createThread():', runT.isAlive())

action = ttk.Button(win, text="Call wxPython GUI", command=wxPythonApp) 
action.grid(column=2, row=1)
```

## 它是如何工作的...

我们最初尝试在一个线程中运行整个 wxPython GUI 应用程序，但这并不起作用，因为 wxPython 的主事件循环期望成为应用程序的主线程。

我们找到了一个解决方法，只在一个线程中运行 wxPython 的`app.MainLoop`，这样就可以欺骗它认为它是主线程。

这种方法的一个副作用是，我们不能再单独关闭所有的 wxPython GUI 实例。至少其中一个只有在我们关闭创建线程为守护进程的 wxPython GUI 时才关闭。

我不太确定为什么会这样。直觉上，人们可能期望能够关闭所有守护线程，而不必等待创建它们的主线程先关闭。

这可能与引用计数器没有被设置为零，而我们的主线程仍在运行有关。

在实际层面上，这是当前的工作方式。

# 如何在两个连接的 GUI 之间进行通信

在之前的配方中，我们找到了连接 wxPython GUI 和 tkinter GUI 的方法，相互调用彼此。

虽然两个 GUI 成功同时运行，但它们实际上并没有真正相互通信，因为它们只是互相启动。

在这个配方中，我们将探讨使这两个 GUI 相互通信的方法。

## 准备工作

阅读之前的一些配方可能是为这个配方做好准备的好方法。

在这个配方中，我们将使用与之前配方相比略有修改的 GUI 代码，但大部分基本的 GUI 构建代码是相同的。

## 如何做...

在之前的配方中，我们的主要挑战之一是如何将两个设计为应用程序的唯一 GUI 工具包的 GUI 技术结合起来。我们找到了各种简单的方法来将它们结合起来。

我们将再次从 tkinter GUI 的主事件循环中启动 wxPython GUI，并在 tkinter 进程中启动 wxPython GUI 的自己的线程。

为了做到这一点，我们将使用一个共享的全局多进程 Python 队列。

### 注意

虽然在这个配方中最好避免全局数据，但它们是一个实际的解决方案，Python 全局变量实际上只在它们被声明的模块中是全局的。

这是使两个 GUI 在一定程度上相互通信的 Python 代码。为了节省空间，这不是纯粹的面向对象编程代码。

我们也没有展示所有部件的创建代码。该代码与之前的示例中相同。

```py
# Ch09_Communicate.py
import tkinter as tk
from tkinter import ttk
from threading import Thread

win = tk.Tk()       
win.title("Python GUI")   

from multiprocessing import Queue
sharedQueue = Queue()
dataInQueue = False

def putDataIntoQueue(data):
    global dataInQueue
    dataInQueue =  True
    sharedQueue.put(data)

def readDataFromQueue():
    global dataInQueue
    dataInQueue = False
    return sharedQueue.get() 
#===========================================================
import wx               
class GUI(wx.Panel):    
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        parent.CreateStatusBar() 
        button = wx.Button(self, label="Print", pos=(0,60))
        self.Bind(wx.EVT_BUTTON, self.writeToSharedQueue, button)

    #--------------------------------------------------------
    def writeToSharedQueue(self, event):
        self.textBox.AppendText(
                        "The Print Button has been clicked!\n") 
        putDataIntoQueue('Hi from wxPython via Shared Queue.\n')
        if dataInQueue: 
            data = readDataFromQueue()
            self.textBox.AppendText(data)

            text.insert('0.0', data) # insert data into GUI

#============================================================
def wxPythonApp():
        app = wx.App()
        frame = wx.Frame(
            None, title="Python GUI using wxPython", size=(300,180))
        GUI(frame)          
        frame.Show()        
        runT = Thread(target=app.MainLoop)
        runT.setDaemon(True)    
        runT.start()
        print(runT)
        print('createThread():', runT.isAlive())
#============================================================
action = ttk.Button(win, text="Call wxPython GUI", command=wxPythonApp) 
action.grid(column=2, row=1)

#======================
# Start GUI
#======================
win.mainloop()
```

首先运行上述代码会创建程序的 tkinter 部分，当我们在这个 GUI 中点击按钮时，它会运行 wxPython GUI。与之前一样，两者同时运行，但这次，两个 GUI 之间有了额外的通信层级。

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_09_20.jpg)

在上述截图的左侧显示了 tkinter GUI，通过点击**Call wxPython GUI**按钮，我们调用了一个 wxPython GUI 的实例。我们可以通过多次点击按钮来创建多个实例。

### 注意

所有创建的 GUI 都保持响应。它们不会崩溃或冻结。

在任何一个 wxPython GUI 实例上点击**Print**按钮会向其自己的`TextCtrl`部件写入一句话，然后也会向自己以及 tkinter GUI 写入另一行。您需要向上滚动以在 wxPython GUI 中看到第一句话。

### 注意

这种工作方式是通过使用模块级队列和 tkinter 的`Text`部件来实现的。

重要的一点是，我们创建一个线程来运行 wxPython 的`app.MainLoop`，就像我们在之前的示例中所做的那样。

```py
def wxPythonApp():
        app = wx.App()
        frame = wx.Frame(
None, title="Python GUI using wxPython", size=(300,180))
        GUI(frame)          
        frame.Show()        
        runT = Thread(target=app.MainLoop)
        runT.setDaemon(True)    
        runT.start()
```

我们创建了一个从`wx.Panel`继承并命名为`GUI`的类。然后我们在上述代码中实例化了这个类。

我们在这个类中创建了一个按钮点击事件回调方法，然后调用了上面编写的过程代码。因此，该类可以访问这些函数并将数据写入共享队列。

```py
    #------------------------------------------------------
    def writeToSharedQueue(self, event):
        self.textBox.AppendText(
"The Print Button has been clicked!\n") 
        putDataIntoQueue('Hi from wxPython via Shared Queue.\n')
        if dataInQueue: 
            data = readDataFromQueue()
            self.textBox.AppendText(data)
            text.insert('0.0', data) # insert data into tkinter
```

我们首先检查在上述方法中是否已将数据放入共享队列，如果是这样，我们就将公共数据打印到两个 GUI 中。

### 注意

`putDataIntoQueue()`将数据放入队列，`readDataFromQueue()`将其读取出来并保存在`data`变量中。

`text.insert('0.0', data)`是将这些数据从**Print**按钮的 wxPython 回调方法写入到 tkinter GUI 中的代码行。

以下是在代码中被调用并使其工作的过程函数（不是方法，因为它们没有绑定）。

```py
from multiprocessing import Queue
sharedQueue = Queue()
dataInQueue = False

def putDataIntoQueue(data):
    global dataInQueue
    dataInQueue =  True
    sharedQueue.put(data)

def readDataFromQueue():
    global dataInQueue
    dataInQueue = False
    return sharedQueue.get()
```

我们使用一个名为`dataInQueue`的简单布尔标志来通知数据何时可用于队列中。

## 工作原理

在这个示例中，我们成功地以类似的方式将我们之前独立的两个 GUI 结合在一起，但彼此之间没有交流。然而，在这个示例中，我们通过使一个 GUI 启动另一个 GUI，并通过一个简单的多进程 Python 队列机制，进一步连接它们，我们能够使它们相互通信，将数据从共享队列写入到两个 GUI 中。

有许多非常先进和复杂的技术可用于连接不同的进程、线程、池、锁、管道、TCP/IP 连接等。

在 Python 精神中，我们找到了一个对我们有效的简单解决方案。一旦我们的代码变得更加复杂，我们可能需要重构它，但这是一个很好的开始。
